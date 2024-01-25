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
 * dtc_ckpt.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_ckpt.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef DTC_CKPT_H
#define DTC_CKPT_H

#include "cm_types.h"
#include "knl_session.h"
#include "knl_ckpt.h"
#include "mes_func.h"
#include "dtc_database.h"
#include "dtc_buffer.h"
#include "rc_reform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CKPT_TRY_ADD_TO_GROUP_TIMES     3
#define CKPT_CLOSED(session)            ((session)->kernel->ckpt_ctx.thread.closed == CT_TRUE)
#define CKPT_CAL_REDO_TIMES             50
typedef struct st_msg_ckpt_trigger {
    bool32 wait;
    bool32 update;
    bool32 force_switch;
    ckpt_mode_t trigger;
    uint64 lsn;
} msg_ckpt_trigger_t;

typedef struct st_msg_ckpt_trigger_point {
    uint32 result;
    log_point_t rcy_point;
    log_point_t lrp_point;
    uint64 lsn;
} msg_ckpt_trigger_point_t;

typedef struct st_msg_ckpt_edp_request {
    mes_message_head_t head;
    uint32 count;
    edp_page_info_t edp_pages[0]; // edp_pages count is CT_CKPT_GROUP_SIZE/3
} msg_ckpt_edp_request_t;

typedef struct st_msg_ckpt_request {
    mes_message_head_t head;
    bool32 wait;
    ckpt_mode_t trigger;
} msg_ckpt_request_t;

status_t dtc_ckpt_flushing_prepare(knl_session_t *session, ckpt_context_t *ctx);
status_t dtc_ckpt_trigger(knl_session_t *session, msg_ckpt_trigger_point_t *point, bool32 wait, ckpt_mode_t trigger,
    uint32 target_id, bool32 update, bool32 force_switch);
EXTER_ATTACK void dtc_process_ckpt_trigger(void *sess, mes_message_t *receive_msg);
void dtc_pop_dirty_queue(knl_session_t *session, buf_ctrl_t *ctrl);
status_t dcs_notify_owner_for_ckpt(knl_session_t *session, ckpt_context_t *ctx);
void dcs_process_ckpt_req(void *sess, mes_message_t *msg);
void dcs_process_master_ckpt_req(void *sess, mes_message_t *msg);
EXTER_ATTACK void dcs_process_ckpt_edp_broadcast_to_master_req(void *sess, mes_message_t *msg);
EXTER_ATTACK status_t dcs_master_process_ckpt_request(knl_session_t *session, edp_page_info_t *pages, uint32 count,
                                                      bool32 broadcast_to_others);
EXTER_ATTACK void dcs_process_ckpt_edp_broadcast_to_owner_req(void *sess, mes_message_t *msg);
EXTER_ATTACK void dcs_process_ckpt_request(void *sess, mes_message_t *msg);
status_t dcs_ckpt_remote_edp_prepare(knl_session_t *session, ckpt_context_t *ctx);
status_t dcs_ckpt_clean_local_edp(knl_session_t *session, ckpt_context_t *ctx);
void dcs_ckpt_trigger(knl_session_t *session, bool32 wait, ckpt_mode_t trigger);
void dcs_ckpt_trigger4drop(knl_session_t *session, bool32 wait, ckpt_mode_t trigger);
bool32 dtc_add_to_edp_group(knl_session_t *session, ckpt_edp_group_t *dst, uint32 count, page_id_t page, uint64 lsn);
bool32 dtc_need_empty_ckpt(knl_session_t* session);
void ckpt_sort_page_id_array(edp_page_info_t *pages, uint32 count);
uint32 ckpt_merge_to_array(edp_page_info_t *src_pages, uint32 start, uint32 src_count, edp_page_info_t *dst_pages,
                           uint32 *dst_count, uint32 dst_capacity);
EXTER_ATTACK void dcs_process_ckpt_edp_local(knl_session_t *session, edp_page_info_t *pages, uint32 page_count,
                                             bool32 wait);
void dtc_calculate_rcy_redo_size(knl_session_t *session, buf_ctrl_t *ckpt_first_ctrl);
status_t dtc_cal_redo_size(knl_session_t *session, log_point_t pre_lrp_point, log_point_t pre_rcy_point,
                           rc_redo_stat_list_t *redo_stat_list);
status_t dcs_notify_owner_for_ckpt_l(knl_session_t *session, edp_page_info_t *pages, uint32 start, uint32 end);

#ifdef __cplusplus
}
#endif

#endif
