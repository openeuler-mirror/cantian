/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
#include "tse_module.h"
#include "mes_func.h"
#include "dtc_ddl.h"
#include "tse_ddl.h"
#include "dtc_dls.h"
#include "knl_context.h"
#include "tse_ddl_broadcast.h"

void tse_process_broadcast_ack_ex(void *session, mes_message_t *msg)
{
    if (msg->head->dst_sid >= CT_MAX_MES_ROOMS) {
        CT_LOG_RUN_ERR("[TSE_MES]:invalid msg dst_sid %u.", msg->head->dst_sid);
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

bool ctc_handle_recv_error(mes_message_t *recv_msg, char *err_msg)
{
    uint8_t cmd = recv_msg->head->cmd;
    bool allow_fail = ((msg_ddl_rsp_t *)recv_msg->buffer)->allow_fail;
    char *carry_err_msg = ((msg_ddl_rsp_t *)recv_msg->buffer)->err_msg;

    if (cmd == MES_CMD_PREPARE_DDL_RSP ||  cmd == MES_CMD_REWRITE_OPEN_CONN_RSP || allow_fail == true) {
        if (err_msg != NULL && carry_err_msg != NULL) {
            int ret = strncpy_s(err_msg, ERROR_MESSAGE_LEN, carry_err_msg, strlen(carry_err_msg));
            knl_securec_check(ret);
        }

        CT_LOG_RUN_ERR("[TSE_MES]:remote node exec failed. cmd:%d", cmd);
        return true;
    }
    return false;
}

int tse_broadcast_and_recv(knl_session_t *knl_session, uint64 target_bits, const void *req_data, char *err_msg)
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
        if (status != CT_SUCCESS) {
            target_inst++;
            continue;
        }

        // 接受消息
        mes_message_t recv_msg = {0};
        SYNC_POINT_GLOBAL_START(TSE_MES_OVERVIEW_RECV_FAIL, &status, CT_ERROR);
        CT_LOG_DEBUG_INF("[Disaster Recovery] wait for recv rsp. target_inst:%d, total: %d",
                         target_inst, mes_inst->profile.inst_count);
        status = mes_recv(sid, &recv_msg, CT_FALSE, head->rsn, TSE_BROADCAST_WAIT_TIMEOUT);
        CT_LOG_DEBUG_INF("[Disaster Recovery] after recv rsp. status: %d, arget_inst:%d, total: %d",
                         status, target_inst, mes_inst->profile.inst_count);
        SYNC_POINT_GLOBAL_END;
        if (status != CT_SUCCESS) {
            // recv失败重发
            head->rsn = mes_get_rsn(sid);  // the rsn is filled by upper-layer services for the first time.
                                           // In other cases, the rsn needs to be updated
            CT_LOG_RUN_ERR("[TSE_MES]:recv msg fail. going to resend. cmd%d, rsn:%d.", head->cmd, head->rsn);
            cm_reset_error();
            continue;
        }

        // 接受消息成功, 某个参天执行失败继续广播其它参天
        if (room->err_code != CT_SUCCESS) {
            // lock远端执行失败需要反错，触发mysql下发unlock命令.
            if (ctc_handle_recv_error(&recv_msg, err_msg)) {
                mes_release_message_buf(recv_msg.buffer);
                cm_thread_unlock(tse_mes_lock);
                return room->err_code;
            }

            CT_LOG_RUN_ERR("[TSE_MES]:recv error from other node. inst_id:%d, error_code:%d, cmd:%d",
                target_inst, room->err_code, recv_msg.head->cmd);
        }

        mes_release_message_buf(recv_msg.buffer);
        target_inst++;
    }

    cm_thread_unlock(tse_mes_lock);
    mes_consume_with_time(head->cmd, MES_TIME_TEST_MULTICAST, start_stat_time);
    return CT_SUCCESS;
}

static void ctc_copy_lock_info_from_rd(rd_lock_info_4mysql_ddl *rd_lock_info, tse_lock_table_info *lock_info)
{
    lock_info->sql_type = rd_lock_info->sql_type;
    lock_info->mdl_namespace = rd_lock_info->mdl_namespace;
    memcpy_sp(lock_info->db_name, rd_lock_info->db_name_len, rd_lock_info->buff, rd_lock_info->db_name_len);
    memcpy_sp(lock_info->table_name, rd_lock_info->table_name_len, rd_lock_info->buff + rd_lock_info->db_name_len, rd_lock_info->table_name_len);
    lock_info->db_name[rd_lock_info->db_name_len] = '\0';
    lock_info->table_name[rd_lock_info->table_name_len] = '\0';
    lock_info->user_name[0] = '\0';
    lock_info->user_ip[0] = '\0';
}

status_t ctc_lock_table_in_slave_node(knl_handle_t session, void *buff)
{
    rd_lock_info_4mysql_ddl *rd_lock_info = (rd_lock_info_4mysql_ddl *)buff;
    tianchi_handler_t tch;
    memset_s(&tch, sizeof(tianchi_handler_t), 0, sizeof(tianchi_handler_t));
    tch.thd_id = CT_INVALID_ID32 - 1;
    tch.inst_id = CT_INVALID_ID32 - 1;
    tch.sess_addr = (uint64_t)session;
    const char *db_name = NULL;
    tse_lock_table_info lock_info;
    ctc_copy_lock_info_from_rd(rd_lock_info, &lock_info);
    CT_LOG_DEBUG_INF("[ctc_lock_table_in_slave_node] redo op_type = %d, db_name = %s, db_name_len = %d, "
                     "table_name = %s, table_name_len = %d, mdl_namespace = %d, sql_type = %d",
                     rd_lock_info->op_type, lock_info.db_name, rd_lock_info->db_name_len, lock_info.table_name,
                     rd_lock_info->table_name_len, rd_lock_info->mdl_namespace, rd_lock_info->sql_type);
    int error_code = 0;

    int ret = tse_lock_table_impl(&tch, session, db_name, &lock_info, &error_code);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ctc_lock_table_in_slave_node] ret: %d, error_code: %d", ret, error_code);
    }
    return CT_SUCCESS;
}

status_t ctc_unlock_table_in_slave_node(knl_handle_t session, void *buff)
{
    rd_lock_info_4mysql_ddl *rd_lock_info = (rd_lock_info_4mysql_ddl *)buff;
    tianchi_handler_t tch;
    memset_s(&tch, sizeof(tianchi_handler_t), 0, sizeof(tianchi_handler_t));
    tch.thd_id = CT_INVALID_ID32 - 1;
    tch.inst_id = CT_INVALID_ID32 - 1;
    tch.sess_addr = (uint64_t)session;
    uint32_t mysql_inst_id = CT_INVALID_ID32 - 1;
    tse_lock_table_info lock_info;
    ctc_copy_lock_info_from_rd(rd_lock_info, &lock_info);
    CT_LOG_DEBUG_INF("[ctc_unlock_table_in_slave_node] redo op_type = %d, db_name = %s, db_name_len = %d, "
                     "table_name = %s, table_name_len = %d, mdl_namespace = %d, sql_type = %d",
                     rd_lock_info->op_type, lock_info.db_name, rd_lock_info->db_name_len, lock_info.table_name,
                     rd_lock_info->table_name_len, rd_lock_info->mdl_namespace, rd_lock_info->sql_type);

    int ret = tse_unlock_table_impl(&tch, session, mysql_inst_id, &lock_info);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ctc_unlock_table_in_slave_node] ret: %d", ret);
    }
    return CT_SUCCESS;
}

status_t ctc_invalid_dd_in_slave_node(knl_handle_t session, void *buff)
{
    rd_invalid_dd_4mysql_ddl *invalid_info = (rd_invalid_dd_4mysql_ddl *)buff;
    tianchi_handler_t tch;
    memset_s(&tch, sizeof(tianchi_handler_t), 0, sizeof(tianchi_handler_t));
    // Do not use 0 or 0xFFFFFFFF, or mysql will close all the connections.
    tch.thd_id = CT_INVALID_ID32 - 1;
    tch.inst_id = CT_INVALID_ID32 - 1;
    tch.sess_addr = (uint64_t)session;

    tse_invalidate_broadcast_request broadcast_req;
    memcpy_sp(broadcast_req.buff, invalid_info->buff_len, invalid_info->buff, invalid_info->buff_len);
    broadcast_req.buff[invalid_info->buff_len] = '\0';
    broadcast_req.buff_len = invalid_info->buff_len;
    broadcast_req.is_dcl = invalid_info->is_dcl;
    broadcast_req.mysql_inst_id = CT_INVALID_ID32 - 1;
    broadcast_req.err_code = 0;
    CT_LOG_DEBUG_INF("[ctc_invalid_dd_in_slave_node] redo op_type = %d, buff = %s, buff_len = %d, is_dcl = %u",
                     invalid_info->op_type, broadcast_req.buff, broadcast_req.buff_len, broadcast_req.is_dcl);

    int ret = tse_broadcast_mysql_dd_invalidate_impl(&tch, session, &broadcast_req);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ctc_invalid_dd_in_slave_node] ret: %d", ret);
    }
    return CT_SUCCESS;
}

status_t ctc_execute_ddl_in_slave_node(knl_handle_t session, char *sql_text, uint32 sql_len)
{
    tianchi_handler_t tch;
    memset_s(&tch, sizeof(tianchi_handler_t), 0, sizeof(tianchi_handler_t));
    // Do not use 0 or 0xFFFFFFFF, or mysql will close all the connections.
    tch.thd_id = CT_INVALID_ID32 - 1;
    tch.inst_id = CT_INVALID_ID32 - 1;
    tch.sess_addr = (uint64_t)session;

    tse_ddl_broadcast_request broadcast_req;
    memset_s(&broadcast_req, sizeof(tse_ddl_broadcast_request), 0, sizeof(tse_ddl_broadcast_request));
    memcpy_s(broadcast_req.sql_str, sql_len, sql_text, sql_len);
    broadcast_req.sql_str[sql_len] = '\0';
    broadcast_req.mysql_inst_id = CT_INVALID_ID32 - 1;

    int ret = tse_ddl_execute_and_broadcast(&tch, &broadcast_req, false, (knl_session_t *)session); 
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[TSE_DDL]:tse_ddl_execute_and_broadcast failed in disaster-recovery. sql_str:%s",
        broadcast_req.sql_str);
        return ret;
    }

    return CT_SUCCESS;
}