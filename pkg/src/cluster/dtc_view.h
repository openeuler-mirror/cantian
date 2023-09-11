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
 * dtc_view.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_view.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef DTC_VIEW_H
#define DTC_VIEW_H

#include "cm_types.h"
#include "srv_view.h"
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 */
#include "knl_session.h"
#include "mes_func.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_BUFFER_CTRL_PER_BUCKET 100
//

typedef struct st_dtc_view_buffer_pos {
    uint8 current_peer_inst_id;
    uint8 next_inst_id;
    uint8 reserved[2];
    uint32 buf_set_id;
    uint32 ctrl_id;
    bool32 is_next_inst;  // false--keep ;true--need to switch to next inst
    uint32 lock;
} dtc_view_buffer_pos_t;
typedef struct st_dtc_view_buffer_ctrl {
    uint64 addr;
    uint64 ba;
    uint32 ts_num;
    uint32 file_num;
    uint32 dbablk_num;
} dtc_view_buffer_ctrl_t;
typedef struct st_dtc_view_buffer_ctrls {
    dtc_view_buffer_ctrl_t buffer_ctrl[MAX_BUFFER_CTRL_PER_BUCKET];
    uint32 buffer_ctrl_cnt; //actural count.
    uint32 buf_set_id;
    uint32 ctrl_id;
    bool32 is_next_inst;
} dtc_view_buffer_ctrls_t;

typedef struct st_dtc_view_buffer_ctrl_req {
    mes_message_head_t head;
    uint8 inst_id;
    uint8 reserved[3];
    uint32 buf_set_id;
    uint32 ctrl_id;
} dtc_view_buffer_ctrl_req_t;

typedef struct st_dtc_view_buffer_ctrl_ack {
    mes_message_head_t head;
    dtc_view_buffer_ctrls_t buffer_ctrls;
} dtc_view_buffer_ctrl_ack_t;

//view request head
typedef struct st_dtc_view_req {
    mes_message_head_t head;
    uint32             view_id;
} dtc_view_req_t;

//struct for converting page count
typedef struct st_dtc_view_converting_page_cnt {
    uint8 inst_id;
    uint8 reserve[3];
    dynview_id_t view_id;
    uint32 converting_cnt;
} dtc_view_converting_page_cnt_t;

//for converting page count ack
typedef struct st_dtc_view_converting_page_cnt_ack {
    mes_message_head_t head;
    dtc_view_converting_page_cnt_t  converting_page_cnt;
} dtc_view_converting_page_cnt_ack_t;

//for error view id
typedef struct st_dtc_view_wrong_id_ack {
    mes_message_head_t head;
    dynview_id_t view_id;
} dtc_view_wrong_id_ack_t;

typedef struct st_dtc_view_mes_stat {
    uint8 inst_id;
    mes_stat_t mes_stat[MES_CMD_CEIL];
} dtc_view_mes_stat_t;

typedef struct st_dtc_view_mes_stat_ack {
    mes_message_head_t   head;
    dynview_id_t         view_id;
    dtc_view_mes_stat_t  mes_stat;
} dtc_view_mes_stat_ack_t;

typedef struct st_dtc_view_mes_elapsed {
    uint8 inst_id;
    mes_time_consume_t func_time[MES_CMD_CEIL];
} dtc_view_mes_elapsed_t;

typedef struct st_dtc_view_mes_elapsed_ack {
    mes_message_head_t     head;
    dynview_id_t           view_id;
    dtc_view_mes_elapsed_t mes_elapsed;
} dtc_view_mes_elapsed_ack_t;

typedef struct st_dtc_view_mes_queue {
    uint8 inst_id;
    mes_queue_t mes_queue[MES_TASK_GROUP_ALL];
} dtc_view_mes_queue_t;

typedef struct st_dtc_view_mes_queue_ack {
    mes_message_head_t head;
    dynview_id_t view_id;
    dtc_view_mes_queue_t mes_queue_view;
} dtc_view_mes_queue_ack_t;

typedef struct st_dtc_view_node_info {
    uint8          inst_id;
    uint32         channel_num;
    cs_pipe_type_t pipe_type;
    uint32         mes_pool_size;
    bool8          non_empty;
} dtc_view_node_info_t;

typedef struct st_dtc_view_node_info_ack {
    mes_message_head_t   head;
    dynview_id_t         view_id;
    dtc_view_node_info_t node_info;
} dtc_view_node_info_ack_t;

typedef struct st_dtc_view_mes_task_queue {
    mes_task_queue_t mes_task_queue[GS_DTC_MAX_TASK_NUM];
} dtc_view_mes_task_queue_t;

dynview_desc_t *vw_describe_dtc(uint32 id);
void dtc_view_process_get_view_info(void *sess, mes_message_t *receive_msg);

void dtc_view_process_get_buffer_ctrl_info(void *sess, mes_message_t *receive_msg);

#ifdef __cplusplus
}
#endif

#endif
