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
 * dtc_drc.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_drc.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef DTC_DRC_H
#define DTC_DRC_H

#include "cm_defs.h"
#include "dtc_drc_util.h"
#include "knl_session.h"
#include "knl_context.h"
#include "srv_instance.h"
#include "dtc_reform.h"
#include "mes_func.h"
#include "dtc_drc_stat.h"
#include "dtc_buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DRC_DEFAULT_BUF_RES_NUM \
    (MAX(((g_instance->kernel.attr.data_buf_size / g_instance->kernel.attr.page_size) * 2), SIZE_M(4)))
#define DRC_DEFAULT_LOCK_RES_NUM (SIZE_M(1))
#define DRC_FILE_EXTENT_SIZE    (8 * 1024 * 1024)    //8M one extent to manage the page resource
#define DRC_FILE_EXTENT_PAGE_NUM(ctx)  (DRC_FILE_EXTENT_SIZE / (ctx)->kernel->attr.page_size)

//lock item structures
typedef enum en_drc_lock_mode {
    DRC_LOCK_NULL = 0,
    DRC_LOCK_SHARE = 1,
    DRC_LOCK_EXCLUSIVE = 2,
    DRC_LOCK_MODE_MAX = 3,
} drc_lock_mode_e;

typedef struct st_drc_req_info {
    uint8 inst_id;
    uint8 req_mode;
    uint8 curr_mode;
    uint8 req_owner_result;
    uint16 inst_sid;
    uint32 rsn;
    date_t req_time;
    uint64 req_version;
    uint64 lsn;
    uint32 release_timeout_ticks;
} drc_req_info_t;

typedef struct st_drc_lock_item {
    uint32 next;
    drc_req_info_t req_info;
} drc_lock_item_t;

static inline void DRC_LE_SET(drc_lock_item_t *le, uint8 inst_id, uint8 mode, uint16 inst_sid, uint32 next)
{
    le->req_info.inst_id = inst_id;
    le->req_info.req_mode = mode;
    le->req_info.inst_sid = inst_sid;
    le->next = next;
}

extern const drc_req_info_t g_invalid_req_info;

typedef struct st_drc_list drc_lock_q_t ;

/* these structures are for non-page buffer resource usage */
typedef struct st_drc_master_res {
    uint32     next;  //should be the first field
    spinlock_t lock;
    uint32     idx;
    drid_t     res_id;

    uint8 mode;
    uint16 part_id;
    uint64 granted_map;
    drc_lock_item_t converting;
    drc_lock_q_t convert_q;
    drc_list_node_t node;
} drc_master_res_t;

typedef struct st_drc_local_latch_stat {
    volatile uint16 shared_count;
    volatile uint16 stat;
    volatile uint16 sid;

    uint8 lock_mode;
    uint8 unused;
}drc_local_latch;

typedef struct st_drc_local_lock_res {
    uint32  next;
    uint32  idx;
    drid_t  res_id;

    bool8   is_owner;
    bool8   is_locked;
    uint16  count;   //only for dls tablelock

    spinlock_t lock;
    spinlock_t lockc;  // lock for count

    //latch
    drc_local_latch latch_stat;
} drc_local_lock_res_t;

typedef struct st_drc_txn_res {
    uint32 next;  // should be the first field
    uint32 idx;
    xid_t res_id;
    uint64 ins_map;         // instance id map
    cm_thread_cond_t cond;  // wait sem/cond
    bool8 is_cond_inited;
    uint8 reserve[3];
} drc_txn_res_t;

typedef uint64 drc_edp_map_t;

typedef enum en_drc_res_action {
    DRC_RES_INVALID_ACTION = 0,
    DRC_RES_PENDING_ACTION,   /* the claimed owner is being recycled */
    DRC_RES_SHARE_ACTION,     /* the claimed owner need to grant shared-owner after recovery */
    DRC_RES_EXCLUSIVE_ACTION, /* the claimed owner need to grant exclusive-owner after recovery */
    DRC_RES_CLEAN_EDP_ACTION, /* clean edp */
    DRC_RES_MAX_ACTION,
} drc_res_action_e;

/* page buffer resource management structure */
typedef struct st_drc_buf_res {
    uint32           next;  // should be the first field
    spinlock_t       lock;
    uint32           idx;
    uint8            claimed_owner;
    uint8            latest_edp;  // the id of the latest edp
    uint8 pending;                // this buf res is not accessible
    uint64 latest_edp_lsn;
    uint8            mode;
    page_id_t        page_id;
    drc_lock_item_t  converting;
    drc_lock_q_t     convert_q;
    uint16           part_id;
    uint8            is_used;
    drc_edp_map_t    edp_map;  //history dirty page map, dcs use it to recovery or CR read
    drc_list_node_t  node;
    uint64           lsn;
    uint64 readonly_copies;
} drc_buf_res_t;

typedef struct st_drc_edp_info {
    drc_edp_map_t    edp_map;
    uint64 lsn;
    uint64 readonly_copies;
    uint8            latest_edp;
} drc_edp_info_t;

typedef enum en_drc_res_type {
    DRC_RES_INVALID_TYPE,
    DRC_RES_PAGE_TYPE,
    DRC_RES_LOCK_TYPE,
    DRC_RES_LOCAL_LOCK_TYPE,
    DRC_RES_TXN_TYPE,
    DRC_RES_LOCAL_TXN_TYPE,
    DRC_RES_LOCK_ITEM_TYPE,
} drc_res_type_e;

typedef enum en_drc_global_res_type {
    DRC_GLOBAL_BUF_RES_TYPE,
    DRC_GLOBAL_LOCK_RES_TYPE,
    DRC_GLOBAL_RES_INVALID_TYPE,
} drc_global_res_type_e;

typedef enum en_drc_res_map_type {
    DRC_LOCAL_LOCK_MAP_TYPE,
    DRC_TXN_RES_MAP_TYPE,
    DRC_LOCAL_TXN_MAP,
    DRC_RES_MAP_INVALID_TYPE,
} drc_res_map_type_e;

typedef enum en_drc_mgrt_res_type {
    DRC_MGRT_RES_PAGE_TYPE,
    DRC_MGRT_RES_LOCK_TYPE,
    DRC_MGRT_RES_INVALID_TYPE,
} drc_mgrt_res_type_e;

typedef enum st_drc_part_status {
    PART_INIT,
    PART_NORMAL,
    PART_WAIT_MIGRATE,
    PART_MIGRATING,
    PART_WAIT_RECOVERY,
    PART_RECOVERING,
    PART_MIGRATE_COMPLETE,
    PART_MIGRATE_FAIL,
}drc_part_status_e;

#define DRC_REMASTER_MIGRATE_RES_MAX_THREAD_NUM (8)
#define REMASTER_SEND_MSG_RETRY_TIMES (3)
#define REMASTER_WAIT_ALL_NODE_READY_TIMEOUT (5 * 1000)
#define REMASTER_ASSIGN_TASK_TIMEOUT (5 * 1000)
#define DRC_CHECK_FULL_CONNECT_SLEEP_INTERVAL (1000)
#define DRC_CHECK_FULL_CONNECT_RETRY_TIMEOUT (5 * 1000)

#ifdef DB_DEBUG_VERSION
    #define REMASTER_WAIT_MIGRATE_FINISH_TIMEOUT         (10 * 60 * 1000)
    #define REMASTER_RECOVER_TIMEOUT                     (10 * 60 * 1000)
    #define REMASTER_WAIT_ALL_NODE_READY_PUBLISH_TIMEOUT (10 * 60 * 1000)
#else
    #define REMASTER_WAIT_MIGRATE_FINISH_TIMEOUT         (20 * 1000)
    #define REMASTER_RECOVER_TIMEOUT                     (20 * 1000)
    #define REMASTER_WAIT_ALL_NODE_READY_PUBLISH_TIMEOUT (20 * 1000)
#endif

#define REMASTER_BROADCAST_TARGET_PART_TIMEOUT (5 * 1000)
#define REMASTER_BROADCAST_DONE_TIMEOUT (5 * 1000)
#define REMASTER_SLEEP_INTERVAL (5)
#define REMASTER_FAIL_SLEEP_INTERVAL (5 * 1000)

typedef enum st_drc_remaster_status {
    REMASTER_PREPARE,
    REMASTER_ASSIGN_TASK,
    REMASTER_MIGRATE,
    REMASTER_RECOVERY,
    REMASTER_PUBLISH,
    REMASTER_DONE,
    REMASTER_FAIL,
} drc_remaster_status_e;

typedef struct st_drc_part {
    uint8 inst_id;
    uint8 status;
    uint16 next;
} drc_part_t;

typedef struct st_drc_inst_part {
    uint16 first;
    uint16 last;
    uint16 count;
    uint16 expected_num;
    bool8  is_used;
    uint8  reserve[3];
}drc_inst_part_t;

typedef struct st_drc_remaster_task {
    uint8 export_inst;
    uint8 import_inst;
    uint16 part_id;
    uint8 status;
    uint8 reserve[3];
} drc_remaster_task_t;

typedef struct st_inst_drm_info {
    uint8 remaster_status;
    uint8 reserve;
    uint16 task_num;
} inst_drm_info_t;

typedef struct st_drc_mgrt_res_cnt {
    atomic32_t res_cnt[DRC_MGRT_RES_INVALID_TYPE];
} drc_mgrt_res_cnt_t;

typedef struct st_rc_part_info {
    uint32 res_cnt[DRC_MGRT_RES_INVALID_TYPE];
    uint8 src_inst;
}rc_part_info_t;

typedef struct st_drc_remaster_mngr {
    uint32 lock;
    drc_part_t target_part_map[DRC_MAX_PART_NUM];
    drc_inst_part_t target_inst_part_tbl[CT_MAX_INSTANCES];

    inst_drm_info_t inst_drm_info[CT_MAX_INSTANCES];
    drc_remaster_task_t remaster_task_set[DRC_MAX_PART_NUM];
    uint32 task_num;
    bool32 is_master;
    atomic_t complete_num;

    drc_remaster_task_t local_task_set[DRC_MAX_PART_NUM];
    uint32 local_task_num;
    atomic_t local_task_complete_num;

    drc_part_t tmp_part_map[DRC_MAX_PART_NUM]; // remaster reentrant
    drc_inst_part_t tmp_inst_part_tbl[CT_MAX_INSTANCES]; // remaster reentrant
    uint64 tmp_part_map_reform_version; //record g_rc_ctx->info.version during reform

    thread_t   remaster_thread;
    reform_info_t reform_info;

    drc_mgrt_res_cnt_t mgrt_part_res_cnt[DRC_MAX_PART_NUM];
    // for remaster_recovery when abort
    atomic_t recovery_task_num;
    atomic_t recovery_complete_task_num;
    bool32 stopped;
    thread_t           mgrt_part_thread;
    rc_part_info_t     mgrt_part_info[DRC_MAX_PART_NUM];
} drc_remaster_mngr_t;

typedef struct st_drc_part_mngr {
    uint32 lock;
    uint32 version;
    bool8  inited;
    uint8  inst_num;
    uint8  remaster_status;
    bool8  is_reentrant;
    uint8 remaster_inst;
    uint8 remaster_finish_step;
    uint16 reversed;

    drc_part_t part_map[DRC_MAX_PART_NUM];
    drc_inst_part_t inst_part_tbl[CT_MAX_INSTANCES];  // reverse table, find part map of a specific instantance

    drc_remaster_mngr_t remaster_mngr;
} drc_part_mngr_t;


typedef struct st_drc_stat {
    spinlock_t lock;
    uint32 master_info_row_cnt ; // record row count
    drc_master_info_row *stat_info; // point to stat info
    uint32 converting_page_cnt;     // for old code only

    // for remaster
    atomic_t clean_page_cnt;
    atomic_t clean_lock_cnt;
    atomic_t clean_convert_cnt;
    atomic_t rcy_page_cnt;
    atomic_t rcy_lock_cnt;
    atomic_t mig_buf_cnt;
    atomic_t mig_lock_cnt;
    atomic_t mig_buf_msg_sent_cnt;
    atomic_t mig_lock_msg_sent_cnt;
}drc_stat_t;

typedef struct st_drc_deposit_map {
    spinlock_t lock;
    uint32 deposit_id; // return self as default, return deposit instance id if error
} drc_deposit_map_t;

typedef struct st_drc_res_ctx {
    spinlock_t     lock;
    knl_instance_t *kernel;
    uint8          instance_num;
    uint8          reserve[3];
    drc_mpool_t    mpool;

    drc_res_pool_t lock_item_pool;
    drc_global_res_t  global_buf_res;
    drc_global_res_t  global_lock_res;
    drc_res_map_t  local_lock_map;
    drc_res_map_t  txn_res_map;
    drc_res_map_t  local_txn_map;
    drc_res_map_t  local_io_map;
    drc_part_mngr_t part_mngr;
    drc_stat_t stat;
    thread_t gc_thread;

    drc_deposit_map_t drc_deposit_map[CT_MAX_INSTANCES];
} drc_res_ctx_t;

typedef struct st_cvt_info {
    uint8 owner_id;
    uint8 req_id;
    uint16 req_sid;
    uint32 req_rsn;
    page_id_t pageid;
    drc_lock_mode_e req_mode;
    drc_lock_mode_e curr_mode;
    uint64 readonly_copies;
    uint64 req_version;
    uint64 lsn;
} cvt_info_t;

typedef struct st_claim_info {
    uint8 new_id;
    uint8 pad[5];
    uint16 inst_sid;
    page_id_t page_id;
    uint64 lsn;
    bool32 has_edp;
    drc_lock_mode_e mode;
} claim_info_t;

typedef struct st_lock_claim_info {
    uint8 new_id;
    uint8 mode;
    uint16 inst_sid;
} lock_claim_info_t;

typedef struct st_col_edp_page_info {
    page_id_t page_id;
    uint64 lsn;
} col_edp_page_info_t;

#define DRC_SET_CLAIM_INFO(claim_info, v_id, v_sid, v_page_id, v_has_edp, v_readonly, v_page_lsn) \
    do {                                                                                          \
        (claim_info)->new_id = (v_id);                                                            \
        (claim_info)->inst_sid = (v_sid);                                                         \
        (claim_info)->page_id = (v_page_id);                                                      \
        (claim_info)->has_edp = (v_has_edp);                                                      \
        (claim_info)->mode = (v_readonly);                                                        \
        (claim_info)->lsn = (v_page_lsn);                                                         \
    } while (0)

#define DRC_MGRT_MSG_SET_RES_CNT(message, msg_offset, buf_res_count, lock_res_count) \
    do {                                                                             \
        *(uint32 *)((uint8 *)(message) + (msg_offset)) = (buf_res_count);            \
        (msg_offset) += sizeof(uint32);                                              \
        *(uint32 *)((uint8 *)(message) + (msg_offset)) = (lock_res_count);           \
        (msg_offset) += sizeof(uint32);                                              \
    } while (0)

#define DRC_MGRT_MSG_GET_RES_CNT(message, msg_offset, buf_res_count, lock_res_count) \
    do {                                                                             \
        buf_res_count = *(uint32 *)((uint8 *)(message) + (msg_offset));              \
        (msg_offset) += sizeof(uint32);                                              \
        lock_res_count = *(uint32 *)((uint8 *)(message) + (msg_offset));             \
        (msg_offset) += sizeof(uint32);                                              \
    } while (0)

typedef enum en_drc_req_owner_result_type {
    DRC_REQ_OWNER_INVALID = 0,
    DRC_REQ_OWNER_GRANTED = 1,
    DRC_REQ_OWNER_ALREADY_OWNER = 2,
    DRC_REQ_OWNER_CONVERTING = 3,
    DRC_REQ_OWNER_WAITING = 4,
    DRC_REQ_OWNER_TRANSFERRED = 5
} drc_req_owner_result_type;

typedef struct st_drc_req_owner_result {
    drc_req_owner_result_type type;
    drc_res_action_e action;
    uint8 curr_owner_id;
    uint8 is_retry;
    uint8 req_mode;
    uint64 readonly_copies;
} drc_req_owner_result_t;

typedef struct st_drc_remaster_task_msg {
    mes_message_head_t head;
    uint32 task_num;
    uint32 task_buffer_len;
    uint64 reform_trigger_version;
}drc_remaster_task_msg_t;

typedef struct st_drc_remaster_task_ack {
    mes_message_head_t head;
    status_t task_status;
    uint64 reform_trigger_version;
}drc_remaster_task_ack_t;

typedef struct st_drc_remaster_status_notify {
    mes_message_head_t head;
    uint32 remaster_status;
    uint64 reform_trigger_version;
}drc_remaster_status_notify_t;

typedef struct st_drc_res_master_msg {
    mes_message_head_t head;
    uint32 part_id;
    uint32 res_num;
    bool8  is_part_end;
    uint8  res_type;
    uint64 reform_trigger_version;
    uint8  reserve[2];
    uint8  block[0];
}drc_res_master_msg_t;

typedef struct st_drc_res_master_msg_ack {
    mes_message_head_t head;
    status_t status;
} drc_res_master_msg_ack_t;

typedef struct st_drc_buf_res_msg {
    uint8 mode;
    uint8 claimed_owner;
    uint8 latest_edp;  // the id of the latest edp
    uint64 latest_edp_lsn;
    uint8 le_num;     //lock item num
    page_id_t page_id;
    uint64 lsn;
    drc_edp_map_t edp_map;
    uint64 readonly_copies;
} drc_buf_res_msg_t;

typedef struct st_drc_lock_res_msg {
    drid_t    res_id;
    uint8     mode;
    uint8 reserve[3];
    uint32 le_num;
    uint64    granted_map;
}drc_lock_res_msg_t;

typedef struct st_drc_le_msg {
    uint8    inst_id;
    uint8    mode;
    uint16   inst_sid;  // some space can be saved if needed later.
}drc_le_msg_t;

// recovery for abort instance
typedef struct st_drc_recovery_lock_res {
    drid_t res_id;
    uint8 lock_mode;  // drc_lock_mode_e
} drc_recovery_lock_res_t;

typedef struct st_drc_recovery_lock_res_msg {
    mes_message_head_t head;
    uint32 count;
    uint32 buffer_len;
} drc_recovery_lock_res_msg_t;

#define DRC_BATCH_BUF_SIZE (30000)
typedef struct st_drc_lock_batch_buf {
    char buffers[CT_MAX_INSTANCES][DRC_BATCH_BUF_SIZE];
    uint32 count[CT_MAX_INSTANCES];
    uint32 max_count;
} drc_lock_batch_buf_t;

typedef struct st_page_info {
    page_id_t page_id;
    uint8 lock_mode;  // drc_lock_mode_e
    bool8 is_edp;
    uint64_t lsn;
} page_info_t;

typedef struct st_msg_page_info {
    mes_message_head_t head;
    uint32 count;
    uint32 buffer_len;
} msg_page_info_t;

typedef struct st_dls_recycle_msg {
    mes_message_head_t head;
    drid_t lock_id;
} dls_recycle_msg_t;

typedef struct st_drc_remaster_migrate_param {
    uint32 start;
    uint32 count_per_thread;
    atomic_t *job_num;
    knl_session_t *session;
} drc_remaster_migrate_param_t;

typedef struct st_drc_remaster_target_part_msg {
    mes_message_head_t head;
    int32 status;
    uint64 reform_trigger_version;
    uint32 buffer_len;
    drc_part_t target_part_map[DRC_MAX_PART_NUM];
    drc_inst_part_t target_inst_part_tbl[CT_MAX_INSTANCES];
} drc_remaster_target_part_msg_t;

extern drc_res_ctx_t g_drc_res_ctx;
#define DRC_RES_CTX  (&g_drc_res_ctx)
extern int32 page_req_count;
static inline bool32 stop_dcs_io(knl_session_t *session)
{
    return !dtc_dcs_readable(session);
}

static inline bool32 stop_dls_req(knl_session_t *session)
{
    return !dtc_dcs_readable(session);
}

#define DRC_GET_CURR_REFORM_VERSION (g_rc_ctx->info.trigger_version)

#define DRC_STOP_DCS_IO_FOR_REFORMING(req_version, session) \
    ((stop_dcs_io(session)) || (req_version) < (DRC_GET_CURR_REFORM_VERSION))

#define DRC_STOP_DLS_REQ_FOR_REFORMING(req_version, session) \
    ((stop_dls_req(session)) || (req_version) < (DRC_GET_CURR_REFORM_VERSION))

#define DRC_PAGE_BATCH_BUF_SIZE (30000)
#define DRC_PAGE_RLS_OWNER_BATCH_SIZE (DRC_PAGE_BATCH_BUF_SIZE / sizeof(page_id_t))
#define DRC_PAGE_CACHE_INFO_BATCH_CNT (DRC_PAGE_BATCH_BUF_SIZE / sizeof(page_info_t))

#define REMASTER_MIG_MAX_BUF_RES_NUM ((MES_MESSAGE_BUFFER_SIZE - sizeof(drc_res_master_msg_t)) / sizeof(drc_buf_res_msg_t))
#define REMASTER_MIG_MAX_LOCK_RES_NUM ((MES_MESSAGE_BUFFER_SIZE - sizeof(drc_res_master_msg_t)) / sizeof(drc_lock_res_msg_t))

typedef struct st_drc_page_batch_buf {
    char buffers[CT_MAX_INSTANCES][DRC_PAGE_BATCH_BUF_SIZE];
    uint32 count[CT_MAX_INSTANCES];
    uint32 max_count;

    uint32 idx[DRC_PAGE_CACHE_INFO_BATCH_CNT];
} drc_page_batch_buf_t;

// DRC init and exit APIs
status_t drc_init(void);
void drc_start_one_master(void);
void drc_destroy(void);

//DRC page master APIs
status_t drc_get_page_master_id(page_id_t pagid, uint8 *id);
status_t drc_get_page_owner_id(knl_session_t *session, page_id_t pagid, uint8 *id, drc_res_action_e *action);
void drc_get_page_owner_id_for_rcy(knl_session_t *session, page_id_t pagid, uint8 *id);

uint32 drc_recycle_items(knl_session_t *session, bool32 is_batch);
EXTER_ATTACK void drc_buf_res_recycle(knl_session_t *session, uint32 inst_id, date_t time, page_id_t page_id, uint64 req_version);
void drc_buf_res_try_recycle(knl_session_t *session, page_id_t page_id);
EXTER_ATTACK status_t drc_get_edp_info(page_id_t pagid, drc_edp_info_t *edp_info);
status_t drc_clean_edp_info(edp_page_info_t page);
EXTER_ATTACK status_t drc_request_page_owner(knl_session_t *session, page_id_t pagid, drc_req_info_t *req_info,
    bool32 is_try, drc_req_owner_result_t *result);
EXTER_ATTACK void drc_claim_page_owner(knl_session_t *session, claim_info_t *claim_info, cvt_info_t *cvt_info,
    uint64 req_version);
status_t drc_release_page_owner(uint8 old_id, page_id_t pagid, bool32 *released);
EXTER_ATTACK void drc_process_send_page_info(void *sess, mes_message_t *msg);
drc_buf_res_t *drc_get_buf_res_by_pageid(knl_session_t *session, page_id_t pagid);
status_t drc_process_buf_master_blk(mes_message_t *msg);
status_t drc_process_lock_master_blk(uint32 id, mes_message_t *msg);
void drc_update_remaster_local_status(drc_remaster_status_e status);
void drc_accept_remaster_done(void *sess, mes_message_t *receive_msg);
void drc_prepare_remaster(knl_session_t *session, reform_info_t *reform_info);
status_t drc_remaster_step_assign_task(knl_session_t *session, reform_info_t *reform_info);
status_t drc_execute_remaster(knl_session_t *session, reform_info_t *reform_info);
void drc_remaster_fail(knl_session_t   *session, status_t ret);
status_t drc_notify_remaster_status(knl_session_t *session, drc_remaster_status_e remaster_status);
status_t drc_mes_send_data_with_retry(const char *msg, uint64 interval, uint64 retry_time);
status_t drc_send_remaster_task_msg(knl_session_t *session, void* body, uint32 task_num,
                                    uint8 src_inst, uint8 dest_inst);
status_t drc_remaster_step_recover(knl_session_t *session, reform_info_t *reform_info);
void drc_remaster_proc(thread_t *thread);
status_t drc_migrate_master_blk(knl_session_t *session, drc_remaster_task_t *remaster_task);
void drc_update_remaster_task_status(uint32 part_id, uint8 status, uint8 export_inst);
status_t drc_send_buf_master_blk(knl_session_t *session, drc_remaster_task_t *remaster_task, uint32 *res_count);
status_t drc_send_lock_master_blk(knl_session_t *session, drc_remaster_task_t *remaster_task, uint32 buf_res_cnt,
                                  uint32 *lock_res_cnt);
void drc_remaster_migrate_res(thread_t *thread);

//lock resource APIs
void drc_get_lock_master_id(drid_t *lock_id, uint8 *master_id);
status_t drc_request_lock_owner(knl_session_t *session, drid_t *lock_id, drc_req_info_t *req_info, bool32 *is_granted,
                                uint64 *old_owner_map, uint64 req_version);
status_t drc_try_request_lock_owner(knl_session_t *session, drid_t *lock_id, drc_req_info_t *req_info,
                                    bool32 *is_granted, uint64 *old_owner_map, uint64 req_version);
status_t drc_cancel_lock_owner_request(uint8 inst_id, drid_t *lock_id);
status_t drc_claim_lock_owner(knl_session_t *session, drid_t *lock_id, lock_claim_info_t *claim_info,
                              uint64 req_version, bool32 is_remaster);
status_t drc_release_lock_owner(uint8 old_id, drid_t *lock_id);
void dls_clear_granted_map_for_inst(drid_t *lock_id, int32 inst_id);
status_t drc_recycle_lock_res(knl_session_t *session, drid_t *lock_id, uint64 req_version);
void dtc_init_lock_res(drc_master_res_t *lock_res, drc_lock_res_msg_t *res_msg, uint32 id);

//lock local resource by yourself
/*
void drc_lock_local_res(drid_t *lock_id);
bool32 drc_try_lock_local_res(drid_t *lock_id);
void drc_unlock_local_res(drid_t *lock_id);
void drc_get_local_lock_stat(drid_t *lock_id, bool8* is_locked, bool8* is_owner);
void drc_set_local_lock_stat(drid_t *lock_id, bool8 is_locked, bool8 is_owner);
void drc_get_local_latch_stat(drid_t *lock_id, drc_local_latch** latch_stat);
*/
//for performace, these interfaces avoid multiple calls to the hash algorithm
drc_local_lock_res_t* drc_get_local_resx(drid_t* lock_id);
drc_local_lock_res_t* drc_get_local_resx_without_create(drid_t* lock_id);
bool32 drc_try_lock_local_resx(drc_local_lock_res_t* lock_res);
void drc_lock_local_resx(drc_local_lock_res_t* lock_res);
void drc_unlock_local_resx(drc_local_lock_res_t* lock_res);
void drc_lock_local_res_count(drc_local_lock_res_t* lock_res);
void drc_unlock_local_res_count(drc_local_lock_res_t* lock_res);
void drc_get_local_lock_statx(drc_local_lock_res_t* lock_res, bool8* is_locked, bool8* is_owner);
void drc_set_local_lock_statx(drc_local_lock_res_t* lock_res, bool8 is_locked, bool8 is_owner);
void drc_get_local_latch_statx(drc_local_lock_res_t* lock_res, drc_local_latch** latch_stat);
void drc_get_global_lock_res_parts(uint16 part_id, drc_list_t **part_list);
drc_master_res_t *drc_get_global_lock_resx_by_id(uint32 lock_idx);
char *drc_get_lock_mode_str(drc_master_res_t *lock_res);
//buf_lock_mode to string
char *drc_get_buf_lock_mode_str(uint8 lock_mode);

//drc part_mngr APIs
void drc_lock_remaster_mngr(void);
void drc_unlock_remaster_mngr(void);

void drc_lock_remaster_part(uint16 part_id);
void drc_unlock_remaster_part(uint16 part_id);
//txn resource APIs
typedef void(*drc_send_txn_msg)(knl_session_t *session, xid_t *xid, knl_scn_t scn, uint32 dst_inst, uint32 cmd);
void drc_enqueue_txn(xid_t *xid, uint8 ins_id);
void drc_release_txn(knl_session_t *session, xid_t *xid, knl_scn_t scn, drc_send_txn_msg func);
bool32 drc_local_txn_wait(xid_t *xid);
void drc_local_txn_awake(xid_t *xid);
void drc_local_txn_recyle(xid_t *xid);

//drc remaster APIs
void dtc_remaster_init(reform_info_t *reform_info);
void drc_start_remaster(reform_info_t *reform_info);
status_t drc_stop_remaster(void);
bool32 drc_remaster_in_progress(void);
bool32 drc_remaster_need_stop(void);
void drc_clean_remaster_res(void);
uint8 drc_get_remaster_status(void);
EXTER_ATTACK void drc_process_remaster_status_notify(void *sess, mes_message_t *receive_msg);
EXTER_ATTACK void drc_accept_remaster_task(void *sess, mes_message_t *msg);
EXTER_ATTACK void drc_process_mgrt_data(void *sess, mes_message_t *receive_msg);
EXTER_ATTACK void drc_accept_target_part(void *sess, mes_message_t *receive_msg);
EXTER_ATTACK void drc_accept_remaster_done(void *sess, mes_message_t *receive_msg);
EXTER_ATTACK void drc_process_remaster_task_ack(void *sess, mes_message_t *receive_msg);
void drc_rcy_page_info(void* page_info, uint8 inst_id, uint32 item_idx, uint32 *alloc_index);
void drc_get_page_remaster_id(page_id_t pagid, uint8 *id);
bool32 drc_page_need_recver(knl_session_t *, page_id_t *pagid);
status_t drc_rcy_lock_res_info(knl_session_t *session, drc_recovery_lock_res_t* lock_res_info, uint8 inst_id);
EXTER_ATTACK void drc_process_recovery_lock_res(void *sess, mes_message_t *msg);
EXTER_ATTACK void drc_process_remaster_recovery_task_ack(void *sess, mes_message_t *receive_msg);
void drc_remaster_inst_list(reform_info_t *reform_info);
status_t drc_remaster_wait_all_node_ready(reform_info_t *reform_info, uint64 timeout,
                                          drc_remaster_status_e status);
status_t drc_reset_target_part(void);
void drc_free_immigrated_res(void);
status_t drc_remaster_task_ack(uint32 id, status_t task_status);
bool32 drc_remaster_recovery_is_complete(drc_remaster_mngr_t *remaster_mngr);
status_t drc_remaster_recovery(knl_session_t *session, reform_info_t *reform_info);
status_t drc_remaster_step_migrate(knl_session_t *session, reform_info_t *reform_info);
void drc_remaster_migrate_clean_res_owner(knl_session_t *session, reform_info_t *reform_info);
status_t drc_remaster_wait_migrate_finish(uint64 timeout);
status_t drc_remaster_migrate(knl_session_t *session);

//return statistics info for drc
void drc_stat_converting_page_count(uint32 *cnt);
uint8 drc_get_deposit_id(uint8 inst_id);
void drc_get_res_num(drc_res_type_e type, uint32 *used_num, uint32 *item_num);
bool32 dtc_is_in_rcy(void);

void drc_destroy_edp_pages_list(ptlist_t* list);
bool32 drc_page_need_recover(knl_session_t *session, page_id_t *pagid);
status_t drc_mes_check_full_connection(uint8 instId);
status_t drc_mes_send_connect_ready_msg(knl_session_t *session, uint8 dst_id);
status_t drc_lock_bucket_and_stat_with_version_check(knl_session_t *session, drid_t *lock_id, drc_res_bucket_t **bucket,
    spinlock_t **res_part_stat_lock, uint64 req_version, bool32 is_remaster);
void drc_unlock_bucket_and_stat(drc_res_bucket_t *bucket, spinlock_t *res_part_stat_lock);
EXTER_ATTACK void drc_process_recycle_lock_master(void *sess, mes_message_t *receive_msg);
status_t drc_check_migrate_buf_res_info(drc_buf_res_t *buf_res, drc_buf_res_msg_t *res_msg);
bool32 drc_claim_info_is_invalid(claim_info_t *claim_info, drc_buf_res_t *buf_res);
status_t drc_lock_local_lock_res_by_id_for_recycle(knl_session_t *session, drid_t *lock_id, uint64 req_version, bool8 *is_found);
void drc_release_local_lock_res_by_id(knl_session_t *session, drid_t *lock_id);
#ifdef __cplusplus
}
#endif

#endif
