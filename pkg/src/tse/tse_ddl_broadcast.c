/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
 *
 * Cantian is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * tse_ddl_broadcast.c
 *
 *
 * IDENTIFICATION
 * src/tse/tse_ddl_broadcast.c
 *
 * -------------------------------------------------------------------------
 */
#include "mes_func.h"
#include "dtc_ddl.h"
#include "tse_ddl.h"
#include "dtc_dls.h"
#include "knl_context.h"
#include "tse_inst.h"

void tse_process_broadcast_ack_ex(void *session, mes_message_t *msg)
{
    if (msg->head->dst_sid >= GS_MAX_MES_ROOMS) {
        GS_LOG_RUN_ERR("[TSE_MES]:invalid msg dst_sid %u.", msg->head->dst_sid);
        return;
    }
    mes_instance_t *mes_inst = get_g_mes();
    mes_waiting_room_t *room = &mes_inst->mes_ctx.waiting_rooms[msg->head->dst_sid];
    cm_spin_lock(&room->lock, NULL);
    if (room->rsn == msg->head->rsn) {
        MES_LOG_HEAD(msg->head);
        room->err_code = ((msg_ddl_rsp_t *)msg->buffer)->err_code;
        room->msg_buf = msg->buffer;
        mes_mutex_unlock(&room->mutex);
        cm_spin_unlock(&room->lock);
    } else {
        cm_spin_unlock(&room->lock);
        MES_LOG_WAR_HEAD_EX(msg->head, "receive unmatch msg");
        mes_release_message_buf(msg->buffer);
    }
    return;
}

int tse_broadcast_and_recv(knl_session_t *knl_session, uint64 target_bits, const void *req_data)
{
    uint32 sid = knl_session->id;
    uint64 start_stat_time = 0;
    mes_check_sid(sid);
    mes_instance_t *mes_inst = get_g_mes();
    mes_message_head_t *head = (mes_message_head_t *)req_data;
    mes_waiting_room_t *room = &mes_inst->mes_ctx.waiting_rooms[sid];
    mes_get_consume_time_start(&start_stat_time);
    thread_lock_t *tse_mes_lock = get_g_tse_mes_lock();

    cm_thread_lock(tse_mes_lock);

    uint32_t target_inst = 0;
    while (target_inst < mes_inst->profile.inst_count) {
        if (SECUREC_UNLIKELY(target_inst == mes_inst->profile.inst_id) ||
            (!MES_IS_INST_SEND(target_bits, target_inst))) {
            target_inst++;
            continue;
        }
        
        // 发送消息, 重发依赖集群位图的可靠
        head->dst_inst = target_inst;
        status_t status = tse_send_data_retry(req_data, head->dst_inst);
        if (status != GS_SUCCESS) {
            target_inst++;
            continue;
        }

        // 接受消息
        mes_message_t recv_msg = {0};
        SYNC_POINT_GLOBAL_START(TSE_MES_OVERVIEW_RECV_FAIL, &status, GS_ERROR);
        status = mes_recv(sid, &recv_msg, GS_FALSE, head->rsn, TSE_BROADCAST_WAIT_TIMEOUT);
        SYNC_POINT_GLOBAL_END;
        if (status != GS_SUCCESS) {
            // recv失败重发
            head->rsn = mes_get_rsn(sid);  // the rsn is filled by upper-layer services for the first time.
                                           // In other cases, the rsn needs to be updated
            GS_LOG_RUN_ERR("[TSE_MES]:recv msg fail. going to resend. cmd%d, rsn:%d.", head->cmd, head->rsn);
            cm_reset_error();
            continue;
        }

        // 接受消息成功, 某个参天执行失败继续广播其它参天
        if (room->err_code != GS_SUCCESS) {
            // lock远端执行失败需要反错，触发mysql下发unlock命令.
            if (recv_msg.head->cmd == MES_CMD_PREPARE_DDL_RSP || recv_msg.head->cmd == MES_CMD_REWRITE_OPEN_CONN_RSP ||
                ((msg_ddl_rsp_t *)recv_msg.buffer)->allow_fail == true) {
                GS_LOG_RUN_ERR("[TSE_MES]:remote node exec failed. inst_id:%d, error_code:%d, cmd:%d",
                    target_inst, room->err_code, recv_msg.head->cmd);
                cm_thread_unlock(tse_mes_lock);
                mes_release_message_buf(recv_msg.buffer);
                return room->err_code;
            }
            GS_LOG_RUN_ERR("[TSE_MES]:recv error from other node. inst_id:%d, error_code:%d, cmd:%d",
                target_inst, room->err_code, recv_msg.head->cmd);
        }

        mes_release_message_buf(recv_msg.buffer);
        target_inst++;
    }

    cm_thread_unlock(tse_mes_lock);
    mes_consume_with_time(head->cmd, MES_TIME_TEST_MULTICAST, start_stat_time);
    return GS_SUCCESS;
}
