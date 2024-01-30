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
 * dtc_dcs.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_dcs.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DTC_DCS_H__
#define __DTC_DCS_H__

//DCS = Distributed Cache service
#include "cm_defs.h"
#include "knl_session.h"
#include "knl_buffer.h"
#include "knl_tran.h"
#include "mes_func.h"
#include "dtc_drc.h"
#include "cm_config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_mes_flags {
    MES_FLAG_DIRTY_PAGE = 0x01,         // sent local dirty page, owner has edp
    MES_FLAG_REMOTE_DIRTY_PAGE = 0x02,  // sent remote dirty page, owner has edp
    MES_FLAG_NEED_LOAD = 0x04,          // need load page from disk
    MES_FLAG_READONLY2X = 0x8,          // readonly to x
    MES_FLAG_OWNER = 0x10,              // invalidate page owner
    MES_FLAG_CEIL = 0x20
} en_mes_flags;

typedef struct st_msg_page_req {
    mes_message_head_t head;
    page_id_t page_id;
    drc_lock_mode_e req_mode;
    drc_lock_mode_e curr_mode;
    uint64 req_version;
    uint64 lsn;
    uint8 action;
    bool8 is_retry;
} msg_page_req_t;

typedef struct st_msg_page_req_batch {
    mes_message_head_t head;
    uint32 count;
    page_id_t page_ids[BUF_MAX_PREFETCH_NUM];
    uint64 req_version;
} msg_page_req_batch_t;

typedef struct st_msg_owner_req {
    mes_message_head_t head;
    uint16 count;
    drc_req_owner_result_t result[BUF_MAX_PREFETCH_NUM];
} msg_owner_req_t;

typedef enum en_cr_type {
    CR_TYPE_HEAP,
    CR_TYPE_BTREE,
} cr_type_t;

typedef struct st_msg_pcr_request {
    mes_message_head_t head;
    page_id_t page_id;
    uint8 cr_type;
    bool8 ssi_conflict;
    bool8 cleanout;
    bool8 local_cr;
    bool8 force_cvt;
    uint8 reserved[3];
    uint32 ssn;
    xid_t xid;
    knl_scn_t query_scn;
} msg_pcr_request_t;

typedef struct st_msg_btree_request {
    msg_pcr_request_t pcr_request;
    page_id_t entry;
    index_profile_t profile;
} msg_btree_request_t;

typedef struct st_msg_pcr_ack {
    mes_message_head_t head;
    bool8 ssi_conflict;
    bool8 cleanout;
    bool8 force_cvt;
    bool8 reserved;
} msg_pcr_ack_t;

typedef struct st_msg_cr_check {
    mes_message_head_t head;
    rowid_t rowid;
    xid_t xid;
    knl_scn_t query_scn;
    uint32 ssn;
    bool8 local_cr;
    uint8 reserved[3];
} msg_cr_check_t;

typedef struct st_msg_cr_check_ack {
    mes_message_head_t head;
    bool32 is_found;
} msg_cr_check_ack_t;

typedef struct st_msg_recycle_owner_req_t {
    mes_message_head_t head;
    page_id_t pageids[RECYCLE_PAGE_NUM];
    atomic_t owner_lsn;
    knl_scn_t owner_scn;
    date_t req_start_times[RECYCLE_PAGE_NUM];
    uint64 req_version;
} msg_recycle_owner_req_t;

typedef struct st_msg_rls_owner_req {
    mes_message_head_t head;
    page_id_t pageid;
    atomic_t owner_lsn;
    knl_scn_t owner_scn;
} msg_rls_owner_req_t;

typedef struct st_msg_rls_owner_ack {
    mes_message_head_t head;
    bool32 released;
} msg_rls_owner_ack_t;

typedef struct st_msg_claim_owner {
    mes_message_head_t head;
    page_id_t page_id;
    bool32 has_edp;  // previous owner has earlier dirty page
    drc_lock_mode_e mode;  // lock mode
    uint64 lsn;
    uint64 req_version;
} msg_claim_owner_t;

typedef struct st_msg_claim_owner_batch {
    mes_message_head_t head;
    uint32 count;
    page_id_t page_ids[BUF_MAX_PREFETCH_NUM];
    uint64 req_version;
} msg_claim_owner_batch_t;

typedef struct st_msg_ack_owner {
    mes_message_head_t head;
    uint32 owner_id;
    uint64 req_version;
    uint64 lsn;
    uint8 action;
    uint8 req_mode;
} msg_ack_owner_t;

// msg for notifying instance load page from disk
typedef struct st_msg_pg_ack_ld {
    mes_message_head_t head;
    atomic_t master_lsn;
    knl_scn_t scn;
    uint64 req_version;
} msg_pg_ack_ld_t;

typedef struct st_msg_ask_page_ack {
    mes_message_head_t head;
    uint64 lsn;
    knl_scn_t scn;
    drc_lock_mode_e mode;
    uint64 req_version;
} msg_ask_page_ack_t;

typedef struct st_msg_edpinfo_req {
    mes_message_head_t head;
    page_id_t page_id;
} msg_edpinfo_req_t;

typedef struct st_msg_edpinfo_ack {
    mes_message_head_t head;
    drc_edp_info_t edp_info;
} msg_edpinfo_ack_t;

typedef struct st_msg_lock_chg_req {
    mes_message_head_t head;
    page_id_t page_id;
    drc_lock_mode_e before;
    drc_lock_mode_e after;
} msg_lock_chg_req_t;

typedef enum en_pcr_status {
    PCR_TRY_READ = 0,
    PCR_LOCAL_READ,
    PCR_READ_PAGE,
    PCR_CONSTRUCT,
    PCR_PAGE_VISIBLE,
    PCR_CHECK_MASTER,
    PCR_REQUEST_MASTER,
    PCR_REQUEST_OWNER,
} pcr_status_t;

typedef struct st_dtc_page_req {
    mes_message_head_t head;
    page_id_t          pagid;
    uint64             req_version;
} dtc_page_req_t;

/*
typedef struct st_page_map {
    page_id_t pages[CT_MAX_INSTANCES][DCS_RLS_OWNER_BATCH_SIZE];
    uint32 count[CT_MAX_INSTANCES];
    uint32 max_count;
} dcs_page_map_t;
*/

typedef struct st_msg_page_batch_op {
    mes_message_head_t head;
    uint32 count;
    atomic_t lsn;
    knl_scn_t scn;
} msg_page_batch_op_t;

typedef struct st_msg_arch_set_request {
    mes_message_head_t head;
    uint32 scope;
    char value[CT_PARAM_BUFFER_SIZE];
} msg_arch_set_request_t;

#define DCS_RESEND_MSG_INTERVAL (5)  //unit: ms
#define DCS_WAIT_MSG_TIMEOUT (3600000)   //unit: ms
#define DCS_CR_REQ_TIMEOUT (10000) //ms
#define DCS_RESEND_MSG_TIMES (200) // resend times in 1s
#define DCS_GET_BITMAP_TIME_INTERVAL (1000)

#define DCS_INSTID_VALID(instid) ((instid) != CT_INVALID_ID8)
#define DCS_SELF_INSTID(session) ((session)->kernel->id)
#define DCS_SELF_SID(session) ((session)->id)

#define DCS_ACK_PG_IS_DIRTY(msg)        (((msg)->head->flags & MES_FLAG_DIRTY_PAGE) ? CT_TRUE : CT_FALSE)
#define DCS_ACK_PG_IS_REMOTE_DIRTY(msg) (((msg)->head->flags & MES_FLAG_REMOTE_DIRTY_PAGE) ? CT_TRUE : CT_FALSE)
#define DCS_BUF_CTRL_NOT_OWNER(session, ctrl) \
    (((ctrl)->lock_mode == DRC_LOCK_NULL) || ((ctrl)->lock_mode == DRC_LOCK_SHARE))
#define DCS_BUF_CTRL_IS_OWNER(session, ctrl) \
    ((((ctrl)->lock_mode == DRC_LOCK_EXCLUSIVE) || ((ctrl)->lock_mode == DRC_LOCK_SHARE)) && (!(ctrl)->is_edp))
#define DCS_IS_EDP(edp_map, inst_id) (((edp_map) >> (inst_id)) & 0x1)
#define DCS_MAX_RETRY_TIEMS (0xFFFFFFFF)

// this function check if local page can be reused for request or not, try to avoid communicating to master/coordinator if possible
bool32 dcs_local_page_usable(knl_session_t *session, buf_ctrl_t *ctrl, latch_mode_t mode);

status_t dcs_request_page(knl_session_t *session, buf_ctrl_t *ctrl, page_id_t page_id, drc_lock_mode_e mode);

status_t dcs_request_edpinfo(knl_session_t *session, page_id_t page_id, drc_edp_info_t *edp_info);

// after checkpoint, notify all old version in other instance to be released
status_t dcs_clean_edp(knl_session_t *session, ckpt_context_t *ctx);
status_t dcs_invalidate_readonly_copy(knl_session_t *session, page_id_t page_id, uint64 readonly_copies,
                                      uint8 exception, uint64 req_version);
status_t dcs_invalidate_page_owner(knl_session_t *session, page_id_t page_id, uint8 owner_id, uint64 req_version);

EXTER_ATTACK void dcs_process_ask_master_for_page(void *sess, mes_message_t *receive_msg);
void dcs_process_try_ask_master_for_page(void *sess, mes_message_t *receive_msg);
EXTER_ATTACK void dcs_process_ask_owner_for_page(void *sess, mes_message_t *receive_msg);
EXTER_ATTACK void dcs_process_claim_ownership_req(void *sess, mes_message_t *receive_msg);
EXTER_ATTACK void dcs_process_claim_ownership_req_batch(void *sess, mes_message_t *receive_msg);
void dcs_process_release_owner(void *sess, mes_message_t *receive_msg);
EXTER_ATTACK void dcs_process_recycle_owner(void *sess, mes_message_t *receive_msg);
void dcs_process_notify_change_lock(void *sess, mes_message_t *receive_msg);

EXTER_ATTACK void dcs_process_notify_master_clean_edp_req(void *sess, mes_message_t *receive_msg);
EXTER_ATTACK void dcs_process_clean_edp_req(void *sess, mes_message_t *receive_msg);
EXTER_ATTACK void dcs_process_edpinfo_req(void *sess, mes_message_t *receive_msg);
EXTER_ATTACK status_t dcs_master_clean_edp(knl_session_t *session, edp_page_info_t *pages, uint32 start, uint32 end,
    uint32 length);
EXTER_ATTACK void dcs_process_page_req(void *sess, mes_message_t *msg);
EXTER_ATTACK void dcs_process_invld_req(void *sess, mes_message_t *msg);
status_t dcs_try_get_page_share_owner(knl_session_t *session, buf_ctrl_t **ctrl_array, page_id_t *page_ids,
                                      uint32 count, uint8 master_id, uint32 *valid_count);
EXTER_ATTACK void dcs_process_ddl_broadcast(void *sess, mes_message_t *msg);
status_t dcs_claim_page_share_owners(knl_session_t *session, page_id_t *page_ids, uint32 count, uint8 master_id);

status_t dcs_heap_request_cr_page(knl_session_t *session, cr_cursor_t *cursor, char *page, uint8 dst_id);
status_t dcs_btree_request_cr_page(knl_session_t *session, cr_cursor_t *cursor, char *page, uint8 dst_id);
EXTER_ATTACK void dcs_process_pcr_req_master(void *sess, mes_message_t *msg);
EXTER_ATTACK void dcs_process_pcr_req_owner(void *sess, mes_message_t *msg);
EXTER_ATTACK void dcs_process_pcr_request(void *sess, mes_message_t *msg);
EXTER_ATTACK void dcs_process_check_visible(void *sess, mes_message_t *msg);
EXTER_ATTACK void dcs_clean_edp_pages_local(knl_session_t *session, edp_page_info_t *pages, uint32 page_count);
void dcs_process_invld_batch_req(void *sess, mes_message_t *msg);
void dcs_process_release_owner_batch(void *sess, mes_message_t *msg);

status_t dcs_pcr_request_master(knl_session_t *session, cr_cursor_t *cursor, char *page_buf, uint8 master_id,
                                cr_type_t type, pcr_status_t *status);
status_t dcs_pcr_request_owner(knl_session_t *session, cr_cursor_t *cursor, char *page_buf, uint8 owner_id,
                               cr_type_t type, pcr_status_t *status);
status_t dcs_pcr_check_master(knl_session_t *session, page_id_t page_id, cr_type_t type,
                              uint8 *dst_id, pcr_status_t *status);
status_t dcs_check_current_visible(knl_session_t *session, cr_cursor_t *cursor, char *page,
                                   uint8 dst_id, bool32 *is_found);
status_t dcs_send_check_visible_ack(knl_session_t *session, msg_cr_check_t *check, bool32 is_found);

status_t dcs_shutdown(knl_session_t *session);
void dcs_buf_clean_ctrl_edp(knl_session_t *session, buf_ctrl_t *ctrl, bool32 need_lock);

status_t dcs_handle_inst_abort(knl_session_t *session, uint8 instid);

status_t dcs_send_data_retry(void *msg);

status_t dcs_send_data3_retry(mes_message_head_t *head, uint32 head_size, const void *body);

void dcs_clean_local_ctrl(knl_session_t *session, buf_ctrl_t *ctrl, drc_res_action_e action, uint64 clean_lsn);
status_t dcs_send_txn_wait(knl_session_t *session, msg_pcr_request_t *request, xid_t wxid);
status_t dcs_alter_set_param(knl_session_t *session, const char *value, config_scope_t scope);
EXTER_ATTACK void dcs_process_arch_set_request(void *sess, mes_message_t *msg);
#ifdef __cplusplus
}
#endif


#endif
