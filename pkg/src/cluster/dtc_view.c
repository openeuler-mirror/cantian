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
 * dtc_view.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_view.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_cluster_module.h"
#include "cm_base.h"
#include "cm_log.h"
#include "cm_system.h"
#include "knl_log.h"
#include "knl_context.h"
#include "knl_interface.h"
#include "knl_session.h"
#include "dtc_context.h"
#include "srv_view.h"
#include "mes_func.h"
#include "dtc_drc.h"
#include "dtc_view.h"
#include "knl_common.h"

dtc_view_mes_stat_t     g_mes_stat_array[CT_MAX_INSTANCES];
dtc_view_mes_elapsed_t  g_mes_elapsed_array[CT_MAX_INSTANCES];
dtc_view_mes_queue_t g_mes_queue_array[CT_MAX_INSTANCES];
dtc_view_node_info_t    g_node_info_array[CT_MAX_INSTANCES];
dtc_view_mes_task_queue_t g_mes_task_queue_array;
dtc_view_mes_channel_stat_t g_mes_channel_stat_array;

#define CMS_MAX_NODES_FOR_TEST 4
#define DTC_VIEW_GET_REMOTE_INFO_TIMEOUT 1000
#define ADDR_LEN 15
int g_node_list_for_test[CMS_MAX_NODES_FOR_TEST] = { 1, 1, 0, 0 };  // Max node number is 4;0,1 is online. Later will
                                                                    // call CMS interface to get info.
dtc_view_buffer_pos_t g_buffer_pos;
dtc_view_buffer_ctrls_t g_buffer_ctrls;

status_t dtc_view_open(knl_handle_t session, knl_cursor_t *cursor)
{
    cursor->rowid.vmid = 0;
    cursor->rowid.vm_slot = 0;
    cursor->rowid.vm_tag = 0;
    return CT_SUCCESS;
}
status_t dtc_view_buffer_ctrl_open(knl_handle_t session, knl_cursor_t *cursor)
{
    cursor->rowid.vmid = 0;
    cursor->rowid.vm_slot = 0;
    cursor->rowid.vm_tag = 0;
    cm_spin_lock(&g_buffer_pos.lock, NULL);
    //get first active inst
    g_buffer_pos.current_peer_inst_id = 0;
    while ((g_buffer_pos.current_peer_inst_id < CMS_MAX_NODES_FOR_TEST) && (g_node_list_for_test[g_buffer_pos.current_peer_inst_id] != 1)) {
        g_buffer_pos.current_peer_inst_id++;
    }
    g_buffer_pos.next_inst_id = g_buffer_pos.current_peer_inst_id;
    g_buffer_pos.buf_set_id = 0;
    g_buffer_pos.ctrl_id = 0;

    g_buffer_pos.is_next_inst = CT_FALSE;
    g_buffer_ctrls.buffer_ctrl_cnt = 0;
    return CT_SUCCESS;
}
//Colums defination of View
knl_column_t g_converting_page_cnt_cols[] = {
    { 0, "ID", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "CONVERTING_PAGE_COUNT", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "INST_ID", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
};

knl_column_t g_buffer_ctrl_cols[] = {
    { 0, "ID", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "ADDR", 0, 0, CT_TYPE_VARCHAR, ADDR_LEN, 0, 0, CT_FALSE, 0, { 0 } },           // Buffer ctrl address
    { 2, "TS#", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },      // tablespace number
    { 3, "FILE#", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },    // file id
    { 4, "DBABLK#", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },  // Page id
    { 5, "BA", 0, 0, CT_TYPE_VARCHAR, ADDR_LEN, 0, 0, CT_FALSE, 0, { 0 } },             // page address
    { 6, "INST_ID", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    // need to add other  information of buffer ctrl;
};
#define MAX_MES_TYPE_LEN 5
#define MAX_MES_GROUP_ID 4

knl_column_t g_mes_stat_cols[] = {
    { 0, "INST_ID", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "MES_TYPE", 0, 0, CT_TYPE_CHAR, MAX_MES_TYPE_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "DESCRIPTION", 0, 0, CT_TYPE_CHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 3, "SEND", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 4, "SEND_FAIL", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 5, "LOCAL_COUNT", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 6, "RECV_PROCESS", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 7, "DEALING_COUNT", 0, 0, CT_TYPE_INTEGER, sizeof(int32), 0, 0, CT_FALSE, 0, { 0 } },
};

#define MAX_MES_QUEUE_LEN 10
knl_column_t g_mes_queue_cols[] = {
    { 0, "INST_ID", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "GROUP_ID", 0, 0, CT_TYPE_CHAR, MAX_MES_GROUP_ID, 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "QUEUE_LENGTH", 0, 0, CT_TYPE_CHAR, MAX_MES_QUEUE_LEN, 0, 0, CT_FALSE, 0, { 0 } },
};

#define MAX_MES_TASK_ID 4
knl_column_t g_mes_task_queue_cols[] = {
    { 0, "TASK_INDEX", 0, 0, CT_TYPE_INTEGER, MAX_MES_TASK_ID, 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "QUEUE_LENGTH", 0, 0, CT_TYPE_INTEGER, MAX_MES_QUEUE_LEN, 0, 0, CT_FALSE, 0, { 0 } },
};

#define IP_TYPE_LEN 32
#define MAX_MES_LSID_LEN 12
#define PIPE_TYPE_LEN 10
#define CHANNEL_STATE_LEN 20
knl_column_t g_mes_channel_stat_cols[] = {
    { 0, "PIPE_TYPE", 0, 0, CT_TYPE_CHAR, PIPE_TYPE_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "LOCAL_INST_ID", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "LOCAL_IP", 0, 0, CT_TYPE_CHAR, IP_TYPE_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 3, "LOCAL_LSID", 0, 0, CT_TYPE_CHAR, MAX_MES_LSID_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 4, "REMOTE_INST_ID", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 5, "REMOTE_IP", 0, 0, CT_TYPE_CHAR, IP_TYPE_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 6, "REMOTE_PORT", 0, 0, CT_TYPE_INTEGER, sizeof(uint16), 0, 0, CT_FALSE, 0, { 0 } },
    { 7, "REMOTE_LSID", 0, 0, CT_TYPE_CHAR, MAX_MES_LSID_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 8, "CHANNEL_NUM", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 9, "REACTOR_THREAD_NUM", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 10, "CHANNEL_STATE", 0, 0, CT_TYPE_CHAR, CHANNEL_STATE_LEN, 0, 0, CT_FALSE, 0, { 0 } },
};

#define MAX_MES_TIME_LEN 35
knl_column_t g_mes_elapsed_cols[] = {
    { 0, "INST_ID", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "MES_TYPE", 0, 0, CT_TYPE_CHAR, MAX_MES_TYPE_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "GROUP_ID", 0, 0, CT_TYPE_CHAR, MAX_MES_GROUP_ID, 0, 0, CT_FALSE, 0, { 0 } },
    { 3, "DESCRIPTION", 0, 0, CT_TYPE_CHAR, 50, 0, 0, CT_FALSE, 0, { 0 } },
    { 4, "SEND", 0, 0, CT_TYPE_CHAR, MAX_MES_TIME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 5, "SEND_IO", 0, 0, CT_TYPE_CHAR, MAX_MES_TIME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 6, "SEND_ACK", 0, 0, CT_TYPE_CHAR, MAX_MES_TIME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 7, "RECV", 0, 0, CT_TYPE_CHAR, MAX_MES_TIME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 8, "GET_BUF", 0, 0, CT_TYPE_CHAR, MAX_MES_TIME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 9, "READ_MESSAGE", 0, 0, CT_TYPE_CHAR, MAX_MES_TIME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 10, "PUT_QUEUE", 0, 0, CT_TYPE_CHAR, MAX_MES_TIME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 11, "GET_QUEUE", 0, 0, CT_TYPE_CHAR, MAX_MES_TIME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 12, "PROCESS_FUNC", 0, 0, CT_TYPE_CHAR, MAX_MES_TIME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 13, "BROADCAST", 0, 0, CT_TYPE_CHAR, MAX_MES_TIME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 14, "BROADCAST_AND_WAIT", 0, 0, CT_TYPE_CHAR, MAX_MES_TIME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 15, "MULTICAST", 0, 0, CT_TYPE_CHAR, MAX_MES_TIME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 16, "MULTICAST_AND_WAIT", 0, 0, CT_TYPE_CHAR, MAX_MES_TIME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
};

knl_column_t g_node_info_cols[] = {
    { 0, "INST_ID", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "ADDRESS", 0, 0, CT_TYPE_VARCHAR, IP_TYPE_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "INTERCONNECT_PORT", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 3, "TYPE", 0, 0, CT_TYPE_CHAR, PIPE_TYPE_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 4, "CHANNEL_NUM", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 5, "POOL_SIZE", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
};
//COL_CNT of View
#define CONVERTING_PAGE_CNT_COLS            (ELEMENT_COUNT(g_converting_page_cnt_cols))
#define BUFFER_CTRL_COLS                    (ELEMENT_COUNT(g_buffer_ctrl_cols))
#define MES_STAT_COLS                       (ELEMENT_COUNT(g_mes_stat_cols))
#define MES_ELAPSED_COLS                    (ELEMENT_COUNT(g_mes_elapsed_cols))
#define MES_QUEUE_COLS                      (ELEMENT_COUNT(g_mes_queue_cols))
#define NODE_INFO_COLS                      (ELEMENT_COUNT(g_node_info_cols))
#define MES_TASK_QUEUE_COLS                 (ELEMENT_COUNT(g_mes_task_queue_cols))
#define MES_CHANNEL_STAT_COLS               (ELEMENT_COUNT(g_mes_channel_stat_cols))

bool8 dtc_view_elapsed_is_empty(mes_command_t cmd)
{
    for (int i = 0; i < MES_TIME_CEIL; i++) {
        if (mes_get_elapsed_count(cmd, i)) {
            return CT_FALSE;
        }
    }
    return CT_TRUE;
}

void dtc_view_get_time_stat(mes_time_consume_t * mes_elapsed_items)
{
    if (!mes_get_elapsed_switch()) {
        return;
    }

    uint32 loop;
    uint64 all_times[MES_TIME_CEIL] = {0};
    int64 all_counts[MES_TIME_CEIL] = {0};

    mes_elapsed_items[0].cmd = 0;
    uint64 time = 0;
    int64 count = 0;
    uint64 last_time = 0;

    for (loop = 1; loop < MES_CMD_CEIL; loop++) {
        if (!dtc_view_elapsed_is_empty(loop)) {
            mes_elapsed_items[loop].cmd = loop;
            mes_elapsed_items[loop].group_id = mes_get_cmd_group(loop);

            for (int i = MES_TIME_TEST_SEND; i <= MES_TIME_GET_BUF; i++) {
                time = mes_get_elapsed_time(loop, i);
                count = mes_get_elapsed_count(loop, i);

                mes_elapsed_items[loop].time[i] = (count == 0) ? 0 : time / count;
                mes_elapsed_items[loop].count[i] =  count;
                all_times[i] += (count == 0) ? 0 : time ;
                all_counts[i] += count;
            }

            for (int j = MES_TIME_READ_MES; j <= MES_TIME_QUEUE_PROC; j++) {
                time = mes_get_elapsed_time(loop, j);
                last_time = mes_get_elapsed_time(loop, j - 1);
                count = mes_get_elapsed_count(loop, j);
                mes_elapsed_items[loop].time[j] = (count == 0) ? 0 : (time - last_time) / count;
                mes_elapsed_items[loop].count[j] = count;
                all_times[j] += (count == 0) ? 0 : (time - last_time);
                all_counts[j] +=  count;
            }
            time = mes_get_elapsed_time(loop, MES_TIME_PROC_FUN);
            last_time = mes_get_elapsed_time(loop, MES_TIME_READ_MES);
            count = mes_get_elapsed_count(loop, MES_TIME_PROC_FUN);
            mes_elapsed_items[loop].time[MES_TIME_PROC_FUN] = (count == 0) ? 0 : (time - last_time) / count;
            mes_elapsed_items[loop].count[MES_TIME_PROC_FUN] = count;

            all_times[MES_TIME_PROC_FUN] += (count == 0) ? 0 : (time - last_time);
            all_counts[MES_TIME_PROC_FUN] += count;

            mes_elapsed_items[loop].non_empty = CT_TRUE;
        }
    }
    for (loop = 0; loop < MES_TIME_CEIL; loop++) {
        mes_elapsed_items[0].time[loop] = (all_counts[loop] == 0) ? 0 : all_times[loop] / all_counts[loop];
        mes_elapsed_items[0].count[loop] = all_counts[loop];
    }
    mes_elapsed_items[0].non_empty = CT_TRUE;
}

void dtc_view_get_mes_stat(mes_stat_t* mes_stat_items)
{
    mes_stat_items[0].cmd = 0;
    uint32 loop;
    for (loop = 1; loop < MES_CMD_CEIL; loop++) {
        if (mes_get_stat_send_count(loop) || mes_get_stat_recv_count(loop)) {
            mes_stat_items[loop].cmd = loop;
            mes_stat_items[loop].send_count = mes_get_stat_send_count(loop);
            mes_stat_items[loop].send_fail_count = mes_get_stat_send_fail_count(loop);
            mes_stat_items[loop].recv_count = mes_get_stat_recv_count(loop);
            mes_stat_items[loop].local_count = mes_get_stat_local_count(loop);
            mes_stat_items[loop].dealing_count = mes_get_stat_dealing_count(loop);
            mes_stat_items[loop].non_empty = CT_TRUE;
            mes_stat_items[0].send_count += mes_stat_items[loop].send_count;
            mes_stat_items[0].recv_count += mes_stat_items[loop].recv_count;
            mes_stat_items[0].dealing_count += mes_stat_items[loop].dealing_count;
            mes_stat_items[0].local_count += mes_stat_items[loop].local_count;
            mes_stat_items[0].send_fail_count += mes_stat_items[loop].send_fail_count;
        }
    }
    mes_stat_items[0].non_empty = CT_TRUE;
}

void dtc_view_get_mes_queue(mes_queue_t *mes_queue_items)
{
    for (uint8 loop = 0; loop < MES_TASK_GROUP_ALL; loop++) {
        mes_queue_items[loop].group_id = loop;
        mes_queue_items[loop].queue_len = mes_get_msg_queue_length(loop);
        mes_queue_items[loop].non_empty = CT_TRUE;
    }
}

void dtc_view_get_mes_task_queue(mes_task_queue_t *mes_queue_items)
{
    mes_instance_t *mes_inst = get_g_mes();
    for (uint32_t loop = 0; loop < mes_inst->profile.work_thread_num; loop++) {
        mes_queue_items[loop].task_index = loop;
        mes_queue_items[loop].queue_len = mes_get_msg_task_queue_length(loop);
        mes_queue_items[loop].non_empty = CT_TRUE;
    }
}

void dtc_view_get_mes_channel_stat(mes_channel_view_t *mes_buffer_items)
{
    uint8 src_inst = g_dtc->profile.inst_id;
    for (uint32_t loop = 0; loop < g_dtc->profile.node_count; loop++) {
        if (loop == src_inst) {
            continue;
        }
        mes_buffer_items[loop].channel_state = mes_get_channel_state(loop);
        mes_buffer_items[loop].non_empty = CT_TRUE;
    }
}

static status_t dtc_view_req_view(knl_session_t *knl_session, uint8 src_id, uint8 dest_id, mes_message_t *msg,
                                  uint32 view_id)
{
    dtc_view_req_t req;
    mes_init_send_head(&req.head, MES_CMD_GET_VIEW_INFO_REQ, sizeof(dtc_view_req_t), CT_INVALID_ID32, src_id, dest_id,
                       knl_session->id, CT_INVALID_ID16);
    req.view_id = view_id;
    status_t send_ret = mes_send_data((void *)&req);
    if (send_ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("send get_view_info_req failed, src_id %d dest_id %d view_id %d \n", src_id, dest_id, view_id);
        return send_ret;
    }
    status_t recv_ret = mes_recv(knl_session->id, msg, CT_FALSE, CT_INVALID_ID32, DTC_VIEW_GET_REMOTE_INFO_TIMEOUT);
    if (recv_ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("recv get_view_info_ack failed, src_id %d dest_id %d view_id %d \n", src_id, dest_id, view_id);
        return recv_ret;
    }

    if (msg->head->cmd == MES_CMD_GET_VIEW_INFO_ERROR_ACK) {
        CT_LOG_RUN_ERR("recv get view info error ack, src_id %d dest_id %d view_id %d \n", src_id, dest_id, view_id);
        mes_release_message_buf(msg->buffer);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t dtc_view_mes_stat_req(knl_session_t *knl_session, dtc_view_mes_stat_t *mes_stat, uint8 src_id,
                                      uint8 dest_id)
{
    mes_message_t msg;
    dtc_view_mes_stat_ack_t *mes_stat_ack;
    if (src_id == dest_id) {
        memset_s(mes_stat->mes_stat, sizeof(mes_stat->mes_stat), 0, sizeof(mes_stat->mes_stat));
        dtc_view_get_mes_stat(mes_stat->mes_stat);
        mes_stat->inst_id  = src_id;
        return CT_SUCCESS;
    }
    status_t ret = dtc_view_req_view(knl_session, src_id, dest_id, &msg, DYN_VIEW_DTC_MES_STAT);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("get mes stat view req failed\n");
        return ret;
    }
    mes_stat_ack = (dtc_view_mes_stat_ack_t *)msg.buffer;
    mes_stat->inst_id  = mes_stat_ack->mes_stat.inst_id;
    memcpy_s(mes_stat->mes_stat, sizeof(mes_stat->mes_stat), mes_stat_ack->mes_stat.mes_stat,
             sizeof(mes_stat->mes_stat));
    mes_release_message_buf(msg.buffer);
    return CT_SUCCESS;
}


static void  dtc_view_mes_stat_ack(knl_session_t *session, mes_message_t * receive_msg)
{
    dtc_view_mes_stat_ack_t view_ack;
    view_ack.mes_stat.inst_id = receive_msg->head->dst_inst;
    mes_init_ack_head(receive_msg->head, &view_ack.head, MES_CMD_DTC_VIEW_INFO_ACK, sizeof(dtc_view_mes_stat_ack_t), CT_INVALID_ID16);
    mes_release_message_buf(receive_msg->buffer);
    memset_s(view_ack.mes_stat.mes_stat, sizeof(view_ack.mes_stat.mes_stat), 0, sizeof(view_ack.mes_stat.mes_stat));
    dtc_view_get_mes_stat(view_ack.mes_stat.mes_stat);
    if (mes_send_data((void*)&view_ack) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("mes_send_dtc_view_mes_stat_ack fail\n");
        return;
    }
    CT_LOG_RUN_INF("mes_send_dtc_view_mes_stat_ack success\n");
}

static status_t dtc_view_mes_queue_req(knl_session_t *knl_session, dtc_view_mes_queue_t *mes_queue_view, uint8 src_id,
                                       uint8 dest_id)
{
    errno_t res;
    if (src_id == dest_id) {
        res = memset_s(mes_queue_view->mes_queue, sizeof(mes_queue_view->mes_queue), 0,
                       sizeof(mes_queue_view->mes_queue));
        knl_securec_check(res);
        dtc_view_get_mes_queue(mes_queue_view->mes_queue);
        mes_queue_view->inst_id = src_id;
        return CT_SUCCESS;
    }
    mes_message_t msg;
    status_t ret = dtc_view_req_view(knl_session, src_id, dest_id, &msg, DYN_VIEW_DTC_MES_QUEUE);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("get mes queue view req failed");
        return ret;
    }
    dtc_view_mes_queue_ack_t *mes_queue_ack = (dtc_view_mes_queue_ack_t *)msg.buffer;
    mes_queue_view->inst_id = mes_queue_ack->mes_queue_view.inst_id;
    res = memcpy_s(mes_queue_view->mes_queue, sizeof(mes_queue_view->mes_queue),
                   mes_queue_ack->mes_queue_view.mes_queue, sizeof(mes_queue_view->mes_queue));
    knl_securec_check(res);
    mes_release_message_buf(msg.buffer);
    return CT_SUCCESS;
}

static void dtc_view_mes_queue_ack(knl_session_t *session, mes_message_t *receive_msg)
{
    dtc_view_mes_queue_ack_t queue_view_ack;
    queue_view_ack.mes_queue_view.inst_id = receive_msg->head->dst_inst;
    mes_init_ack_head(receive_msg->head, &queue_view_ack.head, MES_CMD_DTC_VIEW_INFO_ACK,
                      sizeof(dtc_view_mes_queue_ack_t), CT_INVALID_ID16);
    mes_release_message_buf(receive_msg->buffer);
    errno_t res = memset_s(queue_view_ack.mes_queue_view.mes_queue, sizeof(queue_view_ack.mes_queue_view.mes_queue), 0,
                           sizeof(queue_view_ack.mes_queue_view.mes_queue));
    knl_securec_check(res);
    dtc_view_get_mes_queue(queue_view_ack.mes_queue_view.mes_queue);
    if (mes_send_data((void *)&queue_view_ack) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("mes_send_dtc_view_mes_queue_ack fail");
        return;
    }
    CT_LOG_RUN_INF("mes_send_dtc_view_mes_queue_ack success");
}

static void dtc_view_mes_task_queue_req(knl_session_t *knl_session,
    dtc_view_mes_task_queue_t *mes_task_queue_view)
{
    memset_s(mes_task_queue_view->mes_task_queue, sizeof(mes_task_queue_view->mes_task_queue),
        0, sizeof(mes_task_queue_view->mes_task_queue));
    dtc_view_get_mes_task_queue(mes_task_queue_view->mes_task_queue);
    return;
}

static void dtc_view_mes_channel_stat_req(knl_session_t *knl_session,
    dtc_view_mes_channel_stat_t *mes_channel_stat_view)
{
    (void)memset_s(mes_channel_stat_view->mes_channel, sizeof(mes_channel_stat_view->mes_channel),
        0, sizeof(mes_channel_stat_view->mes_channel));
    dtc_view_get_mes_channel_stat(mes_channel_stat_view->mes_channel);
    return;
}

static status_t dtc_view_mes_elapsed_req(knl_session_t *knl_session, dtc_view_mes_elapsed_t *mes_elapsed, uint8 src_id,
                                         uint8 dest_id)
{
    if (src_id == dest_id) {
        memset_s(mes_elapsed->func_time, sizeof(mes_elapsed->func_time), 0, sizeof(mes_elapsed->func_time));
        dtc_view_get_time_stat(mes_elapsed->func_time);
        mes_elapsed->inst_id  = src_id;
        return CT_SUCCESS;
    }
    mes_message_t   msg;
    dtc_view_mes_elapsed_ack_t *mes_elapsed_ack;
    status_t ret = dtc_view_req_view(knl_session, src_id, dest_id, &msg, DYN_VIEW_DTC_MES_ELAPSED);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("get mes elapsed view req failed\n");
        return ret;
    }
    mes_elapsed_ack = (dtc_view_mes_elapsed_ack_t *)msg.buffer;
    mes_elapsed->inst_id  = mes_elapsed_ack->mes_elapsed.inst_id;

    memcpy_s(mes_elapsed->func_time, sizeof(mes_elapsed->func_time), mes_elapsed_ack->mes_elapsed.func_time,
             sizeof(mes_elapsed->func_time));

    mes_release_message_buf(msg.buffer);
    return CT_SUCCESS;
}

static void dtc_view_mes_elapsed_ack(knl_session_t *session, mes_message_t * receive_msg)
{
    dtc_view_mes_elapsed_ack_t view_ack;
    view_ack.mes_elapsed.inst_id = receive_msg->head->dst_inst;
    memset_s(view_ack.mes_elapsed.func_time, sizeof(view_ack.mes_elapsed.func_time), 0,
             sizeof(view_ack.mes_elapsed.func_time));
    dtc_view_get_time_stat(view_ack.mes_elapsed.func_time);
    mes_init_ack_head(receive_msg->head, &view_ack.head, MES_CMD_DTC_VIEW_INFO_ACK, sizeof(view_ack), CT_INVALID_ID16);
    mes_release_message_buf(receive_msg->buffer);
    if (mes_send_data((void*)&view_ack) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("mes_send_dtc_view_mes_elapsed_ack fail\n");
        return;
    }
    CT_LOG_RUN_INF("mes_send_dtc_view_mes_elapsed_ack success\n");
}

static status_t dtc_view_node_info_req(knl_session_t *knl_session, dtc_view_node_info_t *node_info, uint8 src_id,
                                       uint8 dest_id)
{
    if (src_id == dest_id) {
        node_info->inst_id  = src_id;
        node_info->channel_num = g_dtc->profile.channel_num;
        node_info->pipe_type = g_dtc->profile.pipe_type;
        node_info->mes_pool_size = g_dtc->profile.mes_pool_size;
        node_info->non_empty = CT_TRUE;
        return CT_SUCCESS;
    }

    mes_message_t   msg;
    dtc_view_node_info_ack_t *node_info_ack;
    status_t ret = dtc_view_req_view(knl_session, src_id, dest_id, &msg, DYN_VIEW_DTC_NODE_INFO);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("get node info view req failed\n");
        return ret;
    }
    node_info_ack = (dtc_view_node_info_ack_t *)msg.buffer;
    node_info->inst_id = node_info_ack->node_info.inst_id;
    node_info->channel_num = node_info_ack->node_info.channel_num;
    node_info->pipe_type = node_info_ack->node_info.pipe_type;
    node_info->mes_pool_size = node_info_ack->node_info.mes_pool_size;
    node_info->non_empty = CT_TRUE;
    mes_release_message_buf(msg.buffer);
    return CT_SUCCESS;
}

static void dtc_view_node_info_ack(knl_session_t *session, mes_message_t * receive_msg)
{
    dtc_view_node_info_ack_t view_ack;
    view_ack.node_info.inst_id = g_dtc->profile.inst_id;
    view_ack.node_info.channel_num = g_dtc->profile.channel_num;
    view_ack.node_info.pipe_type = g_dtc->profile.pipe_type;
    view_ack.node_info.mes_pool_size = g_dtc->profile.mes_pool_size;
    mes_init_ack_head(receive_msg->head, &view_ack.head, MES_CMD_DTC_VIEW_INFO_ACK, sizeof(view_ack), CT_INVALID_ID16);
    mes_release_message_buf(receive_msg->buffer);
    if (mes_send_data((void*)&view_ack) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("mes_send_dtc_view_node_info_ack fail\n");
        return;
    }
    CT_LOG_RUN_INF("mes_send_dtc_view_node_info_ack success\n");
}

static status_t dtc_view_get_converting_page_cnt_req(knl_session_t *knl_session,
                                                     dtc_view_converting_page_cnt_t *page_count, uint8 src_id,
                                                     uint8 dest_id)
{
    dtc_view_req_t req;
    mes_message_t   msg;
    dtc_view_converting_page_cnt_t *converting_page_cnt = NULL;

    if (src_id == dest_id) {
        drc_stat_converting_page_count(&(page_count->converting_cnt));
        page_count->converting_cnt = 100;//need to get real info.
        page_count->inst_id = src_id;
        return CT_SUCCESS;
    }
    //remote info
    mes_init_send_head(&req.head, MES_CMD_DTC_VIEW_INFO_REQ, sizeof(dtc_view_req_t), CT_INVALID_ID32, src_id, dest_id,
                       knl_session->id, CT_INVALID_ID16);
    req.view_id = DYN_VIEW_DTC_CONVERTING_PAGE_CNT;

    if (mes_send_data((void *)&req) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (mes_recv(knl_session->id, &msg, CT_FALSE, CT_INVALID_ID32, DTC_VIEW_GET_REMOTE_INFO_TIMEOUT) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (msg.head->cmd == MES_CMD_GET_VIEW_INFO_ERROR_ACK) {
        mes_release_message_buf(msg.buffer);
        return CT_ERROR;
    }
    converting_page_cnt = (dtc_view_converting_page_cnt_t *)MES_MESSAGE_BODY(&msg);
    page_count->converting_cnt = converting_page_cnt->converting_cnt;
    page_count->inst_id = converting_page_cnt->inst_id;

    mes_release_message_buf(msg.buffer);

    return CT_SUCCESS;
}


status_t dtc_view_mes_stat_open(knl_handle_t session, knl_cursor_t *cursor)
{
    status_t ret = dtc_view_open(session, cursor);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("mes stat view open failed\n");
        return ret;
    }
    memset_s(g_mes_stat_array, sizeof(g_mes_stat_array), 0, sizeof(g_mes_stat_array));
    uint8 src_inst = g_dtc->profile.inst_id;
    for (int loop = 0; loop < g_dtc->profile.node_count; loop++) {
        if (loop == src_inst || mes_is_inst_connect(loop)) {
            dtc_view_mes_stat_req(session, &g_mes_stat_array[loop], src_inst, loop);
        }
    }
    return CT_SUCCESS;
}

status_t dtc_view_mes_queue_open(knl_handle_t session, knl_cursor_t *cursor)
{
    status_t ret = dtc_view_open(session, cursor);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("mes queue view open failed");
        return ret;
    }
    errno_t res = memset_s(g_mes_queue_array, sizeof(g_mes_queue_array), 0, sizeof(g_mes_queue_array));
    knl_securec_check(res);
    uint8 src_inst = g_dtc->profile.inst_id;
    for (int loop = 0; loop < g_dtc->profile.node_count; loop++) {
        if (loop == src_inst || mes_is_inst_connect(loop)) {
            dtc_view_mes_queue_req(session, &g_mes_queue_array[loop], src_inst, loop);
        }
    }
    return CT_SUCCESS;
}

status_t dtc_view_mes_task_queue_open(knl_handle_t session, knl_cursor_t *cursor)
{
    (void)dtc_view_open(session, cursor);
    memset_s(&g_mes_task_queue_array, sizeof(g_mes_task_queue_array), 0, sizeof(g_mes_task_queue_array));
    dtc_view_mes_task_queue_req(session, &g_mes_task_queue_array);
    return CT_SUCCESS;
}

status_t dtc_view_mes_channel_stat_open(knl_handle_t session, knl_cursor_t *cursor)
{
    (void)dtc_view_open(session, cursor);
    (void)memset_s(&g_mes_channel_stat_array, sizeof(dtc_view_mes_channel_stat_t), 0,
        sizeof(dtc_view_mes_channel_stat_t));
    dtc_view_mes_channel_stat_req(session, &g_mes_channel_stat_array);
    return CT_SUCCESS;
}

status_t dtc_view_mes_elapsed_open(knl_handle_t session, knl_cursor_t *cursor)
{
    status_t ret = dtc_view_open(session, cursor);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("mes elapsed view open failed\n");
        return ret;
    }
    memset_s(g_mes_elapsed_array, sizeof(g_mes_elapsed_array), 0, sizeof(g_mes_elapsed_array));
    uint8 src_inst = g_dtc->profile.inst_id;

    if (!mes_get_elapsed_switch()) {
        return CT_SUCCESS;
    }
    for (int loop = 0; loop < g_dtc->profile.node_count; loop++) {
        if (loop == src_inst || mes_is_inst_connect(loop)) {
            dtc_view_mes_elapsed_req(session, &g_mes_elapsed_array[loop], src_inst, loop);
        }
    }
    return CT_SUCCESS;
}

status_t dtc_view_node_info_open(knl_handle_t session, knl_cursor_t *cursor)
{
    status_t ret = dtc_view_open(session, cursor);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("node info view open failed\n");
        return ret;
    }
    memset_s(g_node_info_array, sizeof(g_node_info_array), 0, sizeof(g_node_info_array));
    uint8 src_inst = g_dtc->profile.inst_id;
    for (int loop = 0; loop < g_dtc->profile.node_count; loop++) {
        if (loop == src_inst || mes_is_inst_connect(loop)) {
            dtc_view_node_info_req(session, &g_node_info_array[loop], src_inst, loop);
        }
    }
    return CT_SUCCESS;
}


static status_t dtc_view_mes_stat_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    row_assist_t ra;
    uint32 id = cursor->rowid.vmid;

    uint32 node = id / MES_CMD_CEIL;
    if (node >= CT_MAX_INSTANCES) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }
    int32 key = id % MES_CMD_CEIL;
    while (!g_mes_stat_array[node].mes_stat[key].non_empty) {
        id++;
        key = id % MES_CMD_CEIL;
        node = id / MES_CMD_CEIL;
        if (node >= CT_MAX_INSTANCES) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }
    }
    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, MES_STAT_COLS);
    CT_RETURN_IFERR(row_put_uint32(&ra, (uint32)g_mes_stat_array[node].inst_id));
    if (g_mes_stat_array[node].mes_stat[key].cmd == 0) {
        CT_RETURN_IFERR(row_put_str(&ra, "all"));
        CT_RETURN_IFERR(row_put_str(&ra, "all"));
    } else {
        char cmd[MAX_MES_TYPE_LEN];
        PRTS_RETURN_IFERR(sprintf_s(cmd, MAX_MES_TYPE_LEN, "%u", g_mes_stat_array[node].mes_stat[key].cmd));
        CT_RETURN_IFERR(row_put_str(&ra, cmd));
        char description[CT_MAX_NAME_LEN];
        PRTS_RETURN_IFERR(
            sprintf_s(description, CT_MAX_NAME_LEN, "%s", g_processors[g_mes_stat_array[node].mes_stat[key].cmd].name));
        CT_RETURN_IFERR(row_put_str(&ra, description));
    }

    CT_RETURN_IFERR(row_put_int64(&ra, (int64)g_mes_stat_array[node].mes_stat[key].send_count));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)g_mes_stat_array[node].mes_stat[key].send_fail_count));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)g_mes_stat_array[node].mes_stat[key].local_count));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)g_mes_stat_array[node].mes_stat[key].recv_count));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)g_mes_stat_array[node].mes_stat[key].dealing_count));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    id++;
    cursor->rowid.vmid = id;
    return CT_SUCCESS;
}

static status_t dtc_view_mes_queue_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    row_assist_t ra;
    uint32 id = cursor->rowid.vmid;
    uint32 node = id / MES_TASK_GROUP_ALL;
    if (node >= CT_MAX_INSTANCES) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }
    int32 key = id % MES_TASK_GROUP_ALL;
    while (!g_mes_queue_array[node].mes_queue[key].non_empty) {
        id++;
        key = id % MES_TASK_GROUP_ALL;
        node = id / MES_TASK_GROUP_ALL;
        if (node >= CT_MAX_INSTANCES) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }
    }
    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, MES_QUEUE_COLS);
    CT_RETURN_IFERR(row_put_uint32(&ra, (uint32)g_mes_queue_array[node].inst_id));

    // use row_put_uint32 is not right
    char group_id[MAX_MES_GROUP_ID];
    PRTS_RETURN_IFERR(sprintf_s(group_id, MAX_MES_GROUP_ID, "%u", g_mes_queue_array[node].mes_queue[key].group_id));
    CT_RETURN_IFERR(row_put_str(&ra, group_id));

    char queue_len[MAX_MES_QUEUE_LEN];
    PRTS_RETURN_IFERR(sprintf_s(queue_len, MAX_MES_QUEUE_LEN, "%u", g_mes_queue_array[node].mes_queue[key].queue_len));
    CT_RETURN_IFERR(row_put_str(&ra, queue_len));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    id++;
    cursor->rowid.vmid = id;
    return CT_SUCCESS;
}

static void dtc_view_get_pipe_type(cs_pipe_type_t type, char *ret)
{
    switch (type) {
        case CS_TYPE_TCP:
            PRTS_RETVOID_IFERR(sprintf_s(ret, PIPE_TYPE_LEN, "%s", "TCP"));
            break;
        case CS_TYPE_UC:
            PRTS_RETVOID_IFERR(sprintf_s(ret, PIPE_TYPE_LEN, "%s", "UC"));
            break;
        case CS_TYPE_UC_RDMA:
            PRTS_RETVOID_IFERR(sprintf_s(ret, PIPE_TYPE_LEN, "%s", "UC_RDMA"));
            break;
        default:
            CT_LOG_RUN_ERR("dtc view get pipe type failed, type invalid.");
            return;
    }
}

static void dtc_view_get_channel_state(mes_channel_stat_t state, char *ret)
{
    switch (state) {
        case MES_CHANNEL_UNCONNECTED:
            PRTS_RETVOID_IFERR(sprintf_s(ret, CHANNEL_STATE_LEN, "%s", "UNCONNECTED"));
            break;
        case MES_CHANNEL_CONNECTED:
            PRTS_RETVOID_IFERR(sprintf_s(ret, CHANNEL_STATE_LEN, "%s", "CONNECTED"));
            break;
        case MES_CHANNEL_SUBHEALTH:
            PRTS_RETVOID_IFERR(sprintf_s(ret, CHANNEL_STATE_LEN, "%s", "SUBHEALTH"));
            break;
        default:
            CT_LOG_RUN_ERR("dtc view get channel state failed, state invalid.");
            return;
    }
}

static status_t dtc_view_mes_get_channel_stat(knl_cursor_t *cursor, int32 key)
{
    row_assist_t ra;
    mes_instance_t *mes_inst = get_g_mes();
    uint32 local_inst_id = mes_inst->profile.inst_id;

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, MES_CHANNEL_STAT_COLS);
    char type[PIPE_TYPE_LEN];
    dtc_view_get_pipe_type(mes_inst->profile.pipe_type, type);
    CT_RETURN_IFERR(row_put_str(&ra, type)); // pipe type

    CT_RETURN_IFERR(row_put_uint32(&ra, local_inst_id)); // local inst id
    CT_RETURN_IFERR(row_put_str(&ra, mes_inst->profile.inst_arr[local_inst_id].ip)); // local ip
    if (mes_inst->profile.pipe_type == CS_TYPE_UC || mes_inst->profile.pipe_type == CS_TYPE_UC_RDMA) {
        char local_inst_lsid[MAX_MES_LSID_LEN];
        PRTS_RETURN_IFERR(sprintf_s(local_inst_lsid, MAX_MES_LSID_LEN, "0x%x", mes_inst->profile.inst_lsid[local_inst_id]));
        CT_RETURN_IFERR(row_put_str(&ra, local_inst_lsid)); // local lsid
    } else {
        CT_RETURN_IFERR(row_put_str(&ra, "")); // TCP not need lsid
    }
    CT_RETURN_IFERR(row_put_uint32(&ra, key)); // remote inst id
    CT_RETURN_IFERR(row_put_str(&ra, mes_inst->profile.inst_arr[key].ip)); // remote ip
    CT_RETURN_IFERR(row_put_uint32(&ra, mes_inst->profile.inst_arr[key].port)); // remote port
    if (mes_inst->profile.pipe_type == CS_TYPE_UC || mes_inst->profile.pipe_type == CS_TYPE_UC_RDMA) {
        char remote_inst_lsid[MAX_MES_LSID_LEN];
        PRTS_RETURN_IFERR(sprintf_s(remote_inst_lsid, MAX_MES_LSID_LEN, "0x%x", mes_inst->profile.inst_lsid[key]));
        CT_RETURN_IFERR(row_put_str(&ra, remote_inst_lsid)); // local lsid
    } else {
        CT_RETURN_IFERR(row_put_str(&ra, "")); // TCP not need lsid
    }
    CT_RETURN_IFERR(row_put_uint32(&ra, mes_inst->profile.channel_num)); // channel num
    if (mes_inst->profile.pipe_type == CS_TYPE_UC || mes_inst->profile.pipe_type == CS_TYPE_UC_RDMA) {
        CT_RETURN_IFERR(row_put_uint32(&ra, mes_inst->profile.reactor_thread_num)); // reactor thread num
    } else {
        CT_RETURN_IFERR(row_put_uint32(&ra, 0)); // TCP not need reactor thread
    }
    char channel_state[CHANNEL_STATE_LEN];
    dtc_view_get_channel_state(g_mes_channel_stat_array.mes_channel[key].channel_state, channel_state);
    CT_RETURN_IFERR(row_put_str(&ra, channel_state)); // channel state

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    return CT_SUCCESS;
}

static status_t dtc_view_mes_channel_stat_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    uint32 id = cursor->rowid.vmid;
    int node = id / CT_MES_MAX_INSTANCE_ID;
    if (node > 0) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }
    int32 key = id % CT_MES_MAX_INSTANCE_ID;
    while (!g_mes_channel_stat_array.mes_channel[key].non_empty) {
        id++;
        key = id % CT_MES_MAX_INSTANCE_ID;
        node = id / CT_MES_MAX_INSTANCE_ID;
        if (node > 0) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }
    }

    CT_RETURN_IFERR(dtc_view_mes_get_channel_stat(cursor, key));
    id++;
    cursor->rowid.vmid = id;
    return CT_SUCCESS;
}

static status_t dtc_view_mes_task_queue_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    row_assist_t ra;
    uint32 id = cursor->rowid.vmid;
    mes_instance_t *mes_inst = get_g_mes();
    uint32 task_num = mes_inst->profile.work_thread_num;
    int node = id / task_num;
    if (node > 0) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }
    int32 key = id % task_num;
    while (!g_mes_task_queue_array.mes_task_queue[key].non_empty) {
        id++;
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }
    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, MES_TASK_QUEUE_COLS);

    CT_RETURN_IFERR(row_put_uint32(&ra, g_mes_task_queue_array.mes_task_queue[key].task_index));

    CT_RETURN_IFERR(row_put_uint32(&ra, g_mes_task_queue_array.mes_task_queue[key].queue_len));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    id++;
    cursor->rowid.vmid = id;
    return CT_SUCCESS;
}

static status_t dtc_view_get_elapsed_item(row_assist_t *ra, char *item, int len, int node, int key, int cmd)
{
    PRTS_RETURN_IFERR(sprintf_s(item, len, "%lluus(%lld)", g_mes_elapsed_array[node].func_time[key].time[cmd],
                                g_mes_elapsed_array[node].func_time[key].count[cmd]));
    CT_RETURN_IFERR(row_put_str(ra, item));
    return CT_SUCCESS;
}

static status_t dtc_view_mes_elapsed_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    if (!mes_get_elapsed_switch()) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }
    row_assist_t ra;
    uint32 id = cursor->rowid.vmid;
    uint32 node = id / MES_CMD_CEIL;
    if (node >= CT_MAX_INSTANCES) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }
    int32 key = id % MES_CMD_CEIL;
    while (!g_mes_elapsed_array[node].func_time[key].non_empty) {
        id++;
        key = id % MES_CMD_CEIL;
        node = id / MES_CMD_CEIL;
        if (node >= CT_MAX_INSTANCES) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }
    }
    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, MES_ELAPSED_COLS);
    CT_RETURN_IFERR(row_put_uint32(&ra, (uint32)g_mes_elapsed_array[node].inst_id));
    if (g_mes_elapsed_array[node].func_time[key].cmd == 0) {
        CT_RETURN_IFERR(row_put_str(&ra, "all"));
        CT_RETURN_IFERR(row_put_str(&ra, "all"));
        CT_RETURN_IFERR(row_put_str(&ra, "all"));
    } else {
        char cmd[MAX_MES_TYPE_LEN];
        PRTS_RETURN_IFERR(sprintf_s(cmd, MAX_MES_TYPE_LEN, "%u", g_mes_elapsed_array[node].func_time[key].cmd));
        CT_RETURN_IFERR(row_put_str(&ra, cmd));
        char group_id[MAX_MES_GROUP_ID];
        PRTS_RETURN_IFERR(
            sprintf_s(group_id, MAX_MES_GROUP_ID, "%u", g_mes_elapsed_array[node].func_time[key].group_id));
        CT_RETURN_IFERR(row_put_str(&ra, group_id));
        char description[CT_MAX_NAME_LEN];
        PRTS_RETURN_IFERR(sprintf_s(description, CT_MAX_NAME_LEN, "%s",
                                    g_processors[g_mes_elapsed_array[node].func_time[key].cmd].name));
        CT_RETURN_IFERR(row_put_str(&ra, description));
    }

    char item[MAX_MES_TIME_LEN];
    dtc_view_get_elapsed_item(&ra, item, MAX_MES_TIME_LEN, node, key, MES_TIME_TEST_SEND);
    dtc_view_get_elapsed_item(&ra, item, MAX_MES_TIME_LEN, node, key, MES_TIME_SEND_IO);
    dtc_view_get_elapsed_item(&ra, item, MAX_MES_TIME_LEN, node, key, MES_TIME_TEST_SEND_ACK);
    dtc_view_get_elapsed_item(&ra, item, MAX_MES_TIME_LEN, node, key, MES_TIME_TEST_RECV);
    dtc_view_get_elapsed_item(&ra, item, MAX_MES_TIME_LEN, node, key, MES_TIME_GET_BUF);
    dtc_view_get_elapsed_item(&ra, item, MAX_MES_TIME_LEN, node, key, MES_TIME_READ_MES);
    dtc_view_get_elapsed_item(&ra, item, MAX_MES_TIME_LEN, node, key, MES_TIME_PUT_QUEUE);
    dtc_view_get_elapsed_item(&ra, item, MAX_MES_TIME_LEN, node, key, MES_TIME_GET_QUEUE);
    if (mes_get_msg_enqueue(key)) {
        dtc_view_get_elapsed_item(&ra, item, MAX_MES_TIME_LEN, node, key, MES_TIME_QUEUE_PROC);
    } else {
        dtc_view_get_elapsed_item(&ra, item, MAX_MES_TIME_LEN, node, key, MES_TIME_PROC_FUN);
    }
    dtc_view_get_elapsed_item(&ra, item, MAX_MES_TIME_LEN, node, key, MES_TIME_TEST_BROADCAST);
    dtc_view_get_elapsed_item(&ra, item, MAX_MES_TIME_LEN, node, key, MES_TIME_TEST_BROADCAST_AND_WAIT);
    dtc_view_get_elapsed_item(&ra, item, MAX_MES_TIME_LEN, node, key, MES_TIME_TEST_MULTICAST);
    dtc_view_get_elapsed_item(&ra, item, MAX_MES_TIME_LEN, node, key, MES_TIME_TEST_MULTICAST_AND_WAIT);
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    id++;
    cursor->rowid.vmid = id;
    return CT_SUCCESS;
}

static status_t dtc_view_node_info_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    row_assist_t ra;
    uint32 id = cursor->rowid.vmid;
    if (id >= CT_MAX_INSTANCES) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }
    while (!g_node_info_array[id].non_empty) {
        id++;
        if (id >= CT_MAX_INSTANCES) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }
    }
    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, NODE_INFO_COLS);
    CT_RETURN_IFERR(row_put_uint32(&ra, (uint32)g_node_info_array[id].inst_id));
    CT_RETURN_IFERR(row_put_str(&ra, g_dtc->profile.nodes[id]));
    CT_RETURN_IFERR(row_put_uint32(&ra, g_dtc->profile.ports[id]));
    char type[PIPE_TYPE_LEN];
    dtc_view_get_pipe_type(g_node_info_array[id].pipe_type, type);
    CT_RETURN_IFERR(row_put_str(&ra, type));
    CT_RETURN_IFERR(row_put_uint32(&ra, (uint32)g_node_info_array[id].channel_num));
    CT_RETURN_IFERR(row_put_uint32(&ra, (uint32)g_node_info_array[id].mes_pool_size));
    id++;
    cursor->rowid.vmid = id;
    return CT_SUCCESS;
}

static status_t dtc_view_converting_page_cnt_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    int32 id;
    uint8 inst_sequence;
    status_t ret;
    uint8 src_inst;
    row_assist_t ra;
    dtc_view_converting_page_cnt_t converting_page_cnt;

    inst_sequence = (uint8)cursor->rowid.vm_slot;
    id = (int32)cursor->rowid.vmid;
    src_inst = g_dtc->profile.inst_id;
    while ((inst_sequence < CMS_MAX_NODES_FOR_TEST) && (g_node_list_for_test[inst_sequence] != 1)) {
        inst_sequence++;
    }
    if (inst_sequence >= CMS_MAX_NODES_FOR_TEST) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    ret = dtc_view_get_converting_page_cnt_req(se, &converting_page_cnt, src_inst, inst_sequence);
    if (ret != CT_SUCCESS) {  //if get converting page count error, skip it.
        inst_sequence++;
        cursor->rowid.vm_slot = inst_sequence;
        cursor->rowid.vmid++;
        return CT_SUCCESS;
    }

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, CONVERTING_PAGE_CNT_COLS);
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)id));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)converting_page_cnt.converting_cnt));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)converting_page_cnt.inst_id));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    inst_sequence++;
    cursor->rowid.vm_slot = inst_sequence;
    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

static void dtc_view_get_buffer_ctrl(knl_session_t *session, dtc_view_buffer_ctrls_t *buffer_ctrls)
{
    buf_set_t *set = NULL;
    uint32 i;
    uint32 count;
    buf_ctrl_t *ctrl = NULL;
    page_head_t *page = NULL;
    knl_instance_t *kernel = session->kernel;
    buf_context_t *ctx = &kernel->buf_ctx;

    buffer_ctrls->buffer_ctrl_cnt = 0;
    buffer_ctrls->is_next_inst = CT_FALSE;
    count = 0;
    CT_LOG_RUN_INF("dtc_view_get_buffer_ctrl: buf set id = %d\n,ctrl id = %d.\n", buffer_ctrls->buf_set_id,
                   buffer_ctrls->ctrl_id);
    if (buffer_ctrls->buf_set_id >= ctx->buf_set_count) {
        buffer_ctrls->is_next_inst = CT_TRUE;
        buffer_ctrls->buf_set_id = 0;
        buffer_ctrls->ctrl_id = 0;
        CT_LOG_RUN_INF("get max set id in current insatnce, switch to next instance.\n");
        return;
    }

    set = &ctx->buf_set[buffer_ctrls->buf_set_id];
    for (i = buffer_ctrls->ctrl_id; i < set->hwm; i++) {
        if (count == MAX_BUFFER_CTRL_PER_BUCKET) {
            buffer_ctrls->ctrl_id = i;
            CT_LOG_RUN_INF("fill one package, next ctrl id is %d.\n", i);
            return;
        }
        ctrl = &set->ctrls[i];
        page = ctrl->page;
        if (page == NULL || ctrl->load_status != (uint8)BUF_IS_LOADED) {
            continue;
        }
        buffer_ctrls->buffer_ctrl[count].addr = (uint64)ctrl;
        buffer_ctrls->buffer_ctrl[count].ts_num = session->kernel->db.datafiles[ctrl->page_id.file].space_id;
        buffer_ctrls->buffer_ctrl[count].file_num = ctrl->page_id.file;
        buffer_ctrls->buffer_ctrl[count].dbablk_num = ctrl->page_id.page;
        buffer_ctrls->buffer_ctrl[count].ba = (uint64)page;
        buffer_ctrls->buffer_ctrl_cnt++;
        count++;
    }
    if (i == set->hwm) {
        if (buffer_ctrls->buf_set_id == ctx->buf_set_count - 1) {
            buffer_ctrls->buf_set_id = 0;
            buffer_ctrls->ctrl_id = 0;
            buffer_ctrls->is_next_inst = CT_TRUE;
            CT_LOG_RUN_INF("buffer set %d reach to set->hwm, switch to next instance.\n", buffer_ctrls->buf_set_id);
        } else {
            buffer_ctrls->buf_set_id++;
            buffer_ctrls->ctrl_id = 0;
            CT_LOG_RUN_INF("switch to next buffer set %d.\n", buffer_ctrls->buf_set_id);
        }
    }

    return;
}

status_t dtc_view_get_buffer_ctrl_req(knl_session_t *knl_session, uint8 src_id)
{
    dtc_view_buffer_ctrl_req_t req;
    mes_message_t msg;
    dtc_view_buffer_ctrls_t *ctrls = NULL;
    dtc_view_buffer_ctrls_t buffer_ctrls;
    uint32 i;

    g_buffer_ctrls.buffer_ctrl_cnt = 0;
    if (src_id == g_buffer_pos.current_peer_inst_id) {
        buffer_ctrls.buf_set_id = g_buffer_pos.buf_set_id;
        buffer_ctrls.ctrl_id = g_buffer_pos.ctrl_id;
        dtc_view_get_buffer_ctrl(knl_session, &buffer_ctrls);
        for (i = 0; i < buffer_ctrls.buffer_ctrl_cnt; i++) {
            g_buffer_ctrls.buffer_ctrl[i] = buffer_ctrls.buffer_ctrl[i];
        }
        g_buffer_ctrls.buffer_ctrl_cnt = buffer_ctrls.buffer_ctrl_cnt;

        g_buffer_pos.buf_set_id = buffer_ctrls.buf_set_id;
        g_buffer_pos.ctrl_id = buffer_ctrls.ctrl_id;
        g_buffer_pos.is_next_inst = buffer_ctrls.is_next_inst;
        if (buffer_ctrls.is_next_inst) {
            g_buffer_pos.next_inst_id++;
        }
        return CT_SUCCESS;
    }

    //remote info
    CT_LOG_RUN_INF("get infro: %d--->%d,bufset = %d,ctrl_id = %d.\n", src_id, g_buffer_pos.current_peer_inst_id, g_buffer_pos.buf_set_id, g_buffer_pos.ctrl_id);
    cm_sleep(100);

    mes_init_send_head(&req.head, MES_CMD_DTC_VIEW_BUFFER_CTRL_REQ, sizeof(dtc_view_buffer_ctrl_req_t), CT_INVALID_ID32,
                       src_id, g_buffer_pos.current_peer_inst_id, knl_session->id, CT_INVALID_ID16);
    req.buf_set_id = g_buffer_pos.buf_set_id;
    req.ctrl_id = g_buffer_pos.ctrl_id;

    if (mes_send_data((void *)&req) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (mes_recv(knl_session->id, &msg, CT_FALSE, CT_INVALID_ID32, DTC_VIEW_GET_REMOTE_INFO_TIMEOUT) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (msg.head->cmd == MES_CMD_DTC_VIEW_INFO_ERROR_ACK) {
        mes_release_message_buf(msg.buffer);
        return CT_ERROR;
    }
    ctrls = (dtc_view_buffer_ctrls_t *)MES_MESSAGE_BODY(&msg);
    for (i = 0; i < ctrls->buffer_ctrl_cnt;i++) {
        g_buffer_ctrls.buffer_ctrl[i] = ctrls->buffer_ctrl[i];
    }
    g_buffer_ctrls.buffer_ctrl_cnt = ctrls->buffer_ctrl_cnt;

    g_buffer_pos.buf_set_id = ctrls->buf_set_id;
    g_buffer_pos.ctrl_id = ctrls->ctrl_id;
    g_buffer_pos.is_next_inst = ctrls->is_next_inst;
    if (ctrls->is_next_inst) {
        g_buffer_pos.next_inst_id++;
    }
    mes_release_message_buf(msg.buffer);

    return CT_SUCCESS;
}
static status_t dtc_view_buffer_ctrl_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    uint32 id;
    uint16 read_pos;
    status_t ret;
    uint8 src_inst;
    row_assist_t ra;

    id = (uint32)cursor->rowid.vmid;  //for each row.
    read_pos = (uint16)cursor->rowid.vm_slot;
    src_inst = g_dtc->profile.inst_id;

    if (g_buffer_pos.is_next_inst == CT_FALSE) {
        if (g_buffer_ctrls.buffer_ctrl_cnt == 0 || read_pos == g_buffer_ctrls.buffer_ctrl_cnt) {
            cursor->rowid.vm_slot = 0;
            read_pos = (uint8)cursor->rowid.vm_slot;
            ret = dtc_view_get_buffer_ctrl_req(se, src_inst);
            if (ret == CT_ERROR) { // send or receive error, go to next inst;
                g_buffer_pos.is_next_inst = CT_TRUE;
                return CT_SUCCESS;
            }
        }
    } else if (g_buffer_pos.is_next_inst == CT_TRUE && read_pos < g_buffer_ctrls.buffer_ctrl_cnt) {
    } else {
        while ((g_buffer_pos.next_inst_id < CMS_MAX_NODES_FOR_TEST) && (g_node_list_for_test[g_buffer_pos.next_inst_id] != 1)) {
            g_buffer_pos.next_inst_id++;
        }
        if (g_buffer_pos.next_inst_id >= CMS_MAX_NODES_FOR_TEST) {
            cursor->eof = CT_TRUE;
            cm_spin_unlock(&g_buffer_pos.lock);
            return CT_SUCCESS;
        }
        g_buffer_pos.current_peer_inst_id = g_buffer_pos.next_inst_id;
        g_buffer_pos.buf_set_id = 0;
        g_buffer_pos.ctrl_id = 0;
        g_buffer_pos.is_next_inst = CT_FALSE;
        cursor->rowid.vm_slot = 0;
        read_pos = (uint8)cursor->rowid.vm_slot;
        ret = dtc_view_get_buffer_ctrl_req(se, src_inst);
        if (ret == CT_ERROR) {
            g_buffer_pos.next_inst_id++;
            g_buffer_pos.is_next_inst = CT_TRUE;
            return CT_SUCCESS;
        }
    }

    if (read_pos < g_buffer_ctrls.buffer_ctrl_cnt) {
        char addr[ADDR_LEN];
        row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, BUFFER_CTRL_COLS);
        sprintf_s(addr, ADDR_LEN, "%llx", g_buffer_ctrls.buffer_ctrl[read_pos].addr);
        CT_RETURN_IFERR(row_put_int32(&ra, (uint32)id));
        CT_RETURN_IFERR(row_put_str(&ra, addr));
        CT_RETURN_IFERR(row_put_int32(&ra, (uint32)g_buffer_ctrls.buffer_ctrl[read_pos].ts_num));
        CT_RETURN_IFERR(row_put_int32(&ra, (uint32)g_buffer_ctrls.buffer_ctrl[read_pos].file_num));
        CT_RETURN_IFERR(row_put_int32(&ra, (uint32)g_buffer_ctrls.buffer_ctrl[read_pos].dbablk_num));
        sprintf_s(addr, ADDR_LEN, "%llx", g_buffer_ctrls.buffer_ctrl[read_pos].ba);
        CT_RETURN_IFERR(row_put_str(&ra, addr));
        CT_RETURN_IFERR(row_put_int32(&ra, (int32)g_buffer_pos.current_peer_inst_id));
        cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
        cursor->rowid.vm_slot++;
        cursor->rowid.vmid++;
    }

    return CT_SUCCESS;
}
/*
Describtion of DTC view structure
*/

VW_DECL dtc_view_converting_page_cnt = { "SYS", "DV_DTC_CONVERTING_PAGE_CNT",   CONVERTING_PAGE_CNT_COLS,           g_converting_page_cnt_cols,           dtc_view_open, dtc_view_converting_page_cnt_fetch };
VW_DECL dtc_view_buffer_ctrl = { "SYS",
                                 "DV_DTC_BUFFER_CTRL",
                                 BUFFER_CTRL_COLS,
                                 g_buffer_ctrl_cols,
                                 dtc_view_buffer_ctrl_open,
                                 dtc_view_buffer_ctrl_fetch };
VW_DECL dtc_view_mes_stat = {
    "SYS", "MES_STAT", MES_STAT_COLS, g_mes_stat_cols, dtc_view_mes_stat_open, dtc_view_mes_stat_fetch
};
VW_DECL dtc_view_mes_elapsed = {
    "SYS", "MES_ELAPSED", MES_ELAPSED_COLS, g_mes_elapsed_cols, dtc_view_mes_elapsed_open, dtc_view_mes_elapsed_fetch
};
VW_DECL dtc_view_mes_queue = {
    "SYS", "MES_QUEUE", MES_QUEUE_COLS, g_mes_queue_cols, dtc_view_mes_queue_open, dtc_view_mes_queue_fetch
};
VW_DECL dtc_view_mes_channel_stat = {
    "SYS", "MES_CHANNEL_STAT", MES_CHANNEL_STAT_COLS, g_mes_channel_stat_cols, dtc_view_mes_channel_stat_open,
    dtc_view_mes_channel_stat_fetch };
VW_DECL dtc_view_node_info = {
    "SYS", "NODE_INFO", NODE_INFO_COLS, g_node_info_cols, dtc_view_node_info_open, dtc_view_node_info_fetch
};
VW_DECL dtc_view_mes_task_queue = { "SYS", "MES_TASK_QUEUE", MES_TASK_QUEUE_COLS, g_mes_task_queue_cols,
    dtc_view_mes_task_queue_open, dtc_view_mes_task_queue_fetch };

dynview_desc_t *vw_describe_dtc(uint32 id)
{
    switch ((dynview_id_t)id) {
        case DYN_VIEW_DTC_CONVERTING_PAGE_CNT:
            return &dtc_view_converting_page_cnt;
        case DYN_VIEW_DTC_BUFFER_CTRL:
            return &dtc_view_buffer_ctrl;
        case DYN_VIEW_DTC_MES_STAT:
            return &dtc_view_mes_stat;
        case DYN_VIEW_DTC_MES_ELAPSED:
            return &dtc_view_mes_elapsed;
        case DYN_VIEW_DTC_MES_QUEUE:
            return &dtc_view_mes_queue;
        case DYN_VIEW_DTC_MES_CHANNEL_STAT:
            return &dtc_view_mes_channel_stat;
        case DYN_VIEW_DTC_NODE_INFO:
            return &dtc_view_node_info;
        case DYN_VIEW_DTC_MES_TASK_QUEUE:
            return &dtc_view_mes_task_queue;
        default:
            return NULL;
    }
}

static void dtc_view_get_converting_page_cnt_ack(knl_session_t *session, mes_message_t * receive_msg)
{
    dtc_view_converting_page_cnt_ack_t view_ack;
    view_ack.converting_page_cnt.inst_id = receive_msg->head->dst_inst;
    drc_stat_converting_page_count(&(view_ack.converting_page_cnt.converting_cnt));
    view_ack.converting_page_cnt.converting_cnt = 11;//number fo test.need get real number;
    mes_init_ack_head(receive_msg->head, &view_ack.head, MES_CMD_DTC_VIEW_CONVERTING_PAGE_CNT_ACK,
                      sizeof(dtc_view_converting_page_cnt_ack_t), CT_INVALID_ID16);
    uint8 src_id = receive_msg->head->dst_inst;
    CT_LOG_RUN_INF("src_inst = %d,converting_page_num =%d.", view_ack.converting_page_cnt.inst_id, view_ack.converting_page_cnt.converting_cnt);
    mes_release_message_buf(receive_msg->buffer);
    if (mes_send_data((void*)&view_ack) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[GDV]: fail to send converting page cnt ack to %d.", src_id);
        return;
    }
    CT_LOG_RUN_INF("mes_send_data success.");
}
static void dtc_view_wrong_id_ack(knl_session_t *session, mes_message_t * receive_msg)
{
    dtc_view_wrong_id_ack_t  view_ack;
    view_ack.view_id = *((uint32 *)(receive_msg->buffer + sizeof(mes_message_head_t)));
    mes_init_ack_head(receive_msg->head, &view_ack.head, MES_CMD_GET_VIEW_INFO_ERROR_ACK,
                      sizeof(dtc_view_wrong_id_ack_t), CT_INVALID_ID16);
    uint8 src_id = receive_msg->head->dst_inst;
    mes_release_message_buf(receive_msg->buffer);
    if (mes_send_data((void*)&view_ack) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[GDV]: fail to send wrong view id err ack to %d.", src_id);
        return;
    }
    CT_LOG_RUN_INF("mes_send_data success.");
}

void dtc_view_process_get_buffer_ctrl_info(void *sess, mes_message_t * receive_msg)
{
    dtc_view_buffer_ctrl_ack_t view_ack;
    dtc_view_buffer_ctrl_req_t *req = NULL;
    knl_session_t *session = (knl_session_t *)sess;
    //fill ack
    if (sizeof(dtc_view_buffer_ctrl_req_t) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("msg is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    req = (dtc_view_buffer_ctrl_req_t *)(receive_msg->buffer);
    if (req->buf_set_id >= CT_MAX_BUF_POOL_NUM) {
        CT_LOG_RUN_ERR("[GDV]: invalid buf_set_id: %d.", req->buf_set_id);
        return;
    }
    view_ack.buffer_ctrls.buf_set_id = req->buf_set_id;
    view_ack.buffer_ctrls.ctrl_id = req->ctrl_id;
    uint8 src_id = receive_msg->head->dst_inst;
    mes_init_ack_head(receive_msg->head, &view_ack.head, MES_CMD_DTC_VIEW_BUFFER_CTRL_ACK,
                      sizeof(dtc_view_buffer_ctrl_ack_t), CT_INVALID_ID16);
    dtc_view_get_buffer_ctrl(session, &view_ack.buffer_ctrls);
    mes_release_message_buf(receive_msg->buffer);
    if (mes_send_data((void *)&view_ack) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[GDV]: fail to send buffer ctrl data to %d.", src_id);
        return;
    }
    CT_LOG_RUN_INF("mes_send_data success.");
    return;
}

void dtc_view_process_get_view_info(void *sess, mes_message_t *receive_msg)
{
    knl_session_t *session = (knl_session_t *)sess;
    if (sizeof(dtc_view_req_t) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("msg is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    dynview_id_t view_id = *((uint32 *)(receive_msg->buffer + sizeof(mes_message_head_t)));
    CT_LOG_RUN_INF("Get DTC view request %d.", view_id);

    switch (view_id) {
        case DYN_VIEW_DTC_CONVERTING_PAGE_CNT:
            dtc_view_get_converting_page_cnt_ack(session, receive_msg);
            break;
        case DYN_VIEW_DTC_MES_STAT:
            dtc_view_mes_stat_ack(session, receive_msg);
            break;
        case DYN_VIEW_DTC_MES_ELAPSED:
            dtc_view_mes_elapsed_ack(session, receive_msg);
            break;
        case DYN_VIEW_DTC_MES_QUEUE:
            dtc_view_mes_queue_ack(session, receive_msg);
            break;
        case DYN_VIEW_DTC_NODE_INFO:
            dtc_view_node_info_ack(session, receive_msg);
            break;
        default:
            dtc_view_wrong_id_ack(session, receive_msg);
    }
}
