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
 * dtc_recovery.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_recovery.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DTC_RECOVERY_H__
#define __DTC_RECOVERY_H__

#include "cm_defs.h"
#include "cm_utils.h"
#include "knl_archive.h"
#include "knl_log.h"
#include "knl_session.h"
#include "mes_func.h"
#include "dtc_reform.h"
#include "knl_recovery.h"
#include "cm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CT_RCY_SET_SIZE                 SIZE_M(64)
#define CT_RCY_SET_BUCKET               1048573
#define RCY_SET_BUCKET_TIMES            3 // the times of buckets against buffer ctrl
#define DTC_RCY_PARAL_BUF_LIST_SIZE     256 // must is power of 2
#define DTC_RCY_PARAL_BUF_LIST_MASK     (DTC_RCY_PARAL_BUF_LIST_SIZE - 1)
#define PARAL_ANALYZE_THREAD_NUM        8
#define DTC_RCY_GROUP_NUM_BASE          SIZE_M(1)
// wait alive nodes send collected page info of rcy_set back to reformer timeout (seconds)
#ifdef DB_DEBUG_VERSION
    #define DTC_RCY_RECV_RCY_SET_ACK_TIMEOUT         (1000 * 1000)
#else
    #define DTC_RCY_RECV_RCY_SET_ACK_TIMEOUT         (500 * 1000)
#endif
#define DTC_RCY_WAIT_STOP_SLEEP_TIME    100
#define DTC_RCY_WAIT_REF_NUM_CLEAN_SLEEP_TIME 10
#define DTC_RCY_SET_SEND_MSG_MAX_PAGE_NUM ((MES_MESSAGE_BUFFER_SIZE - sizeof(dtc_rcy_set_msg_t)) / sizeof(page_id_t))

typedef struct st_dtc_rcy_atomic_list_node {
    uint32 array[DTC_RCY_PARAL_BUF_LIST_SIZE];
    atomic_t begin;
    atomic_t end;
    atomic_t writed_end;
    spinlock_t lock;
} dtc_rcy_atomic_list;

typedef struct st_dtc_rcy_analyze_paral_node {
    aligned_buf_t buf_list[DTC_RCY_PARAL_BUF_LIST_SIZE];
    thread_t thread[PARAL_ANALYZE_THREAD_NUM];
    dtc_rcy_atomic_list free_list;
    dtc_rcy_atomic_list used_list;
    atomic32_t running_thread_num;
    bool8 read_log_end_flag;
    bool8 killed_flag;
} dtc_rcy_analyze_paral_node_t;

typedef struct st_dtc_rcy_replay_paral_node {
    aligned_buf_t buf_list[DTC_RCY_PARAL_BUF_LIST_SIZE];
    aligned_buf_t group_list[DTC_RCY_PARAL_BUF_LIST_SIZE];
    atomic32_t group_num[DTC_RCY_PARAL_BUF_LIST_SIZE];
    dtc_rcy_atomic_list free_list;
} dtc_rcy_replay_paral_node_t;

typedef struct st_dtc_rcy_set_req {
    mes_message_head_t head;
    uint32 count;
    bool32 finished;
    uint32 buffer_len;
    uint64 reform_trigger_version;
} dtc_rcy_set_msg_t;

typedef struct st_rcy_set_item {
    page_id_t page_id;
    uint64 first_dirty_lsn;
    uint64 last_dirty_lsn;
    uint32 pcn;
    uint8 master_id;
    volatile bool8 need_replay;
    bool8 need_check_leave_changed;
    struct st_rcy_set_item *next_item;
} rcy_set_item_t;

typedef struct st_rcy_set_bucket {
    spinlock_t lock;
    uint32 count;
    rcy_set_item_t *first;
} rcy_set_bucket_t;

typedef struct st_rcy_set_item_pool {
    int64  hwm;
    rcy_set_item_t *items;
    struct st_rcy_set_item_pool *next;
} rcy_set_item_pool_t;

typedef struct st_rcy_set {
    spinlock_t lock;
    uint64 size;
    int64  capacity;
    uint32 bucket_num;
    rcy_set_bucket_t *buckets;
    rcy_set_item_pool_t *item_pools;
    rcy_set_item_pool_t *curr_item_pools;
    page_id_t *pages[CT_MAX_INSTANCES];
    uint32 page_count[CT_MAX_INSTANCES];
} rcy_set_t;

typedef enum en_dtc_rcy_phase {
    PHASE_ANALYSIS = 0,
    PHASE_HANDLE_RCYSET = 1,
    PHASE_HANDLE_RCYSET_DONE = 2,
    PHASE_RECOVERY = 3,
} dtc_rcy_phase_e;

typedef struct st_dtc_rcy_node {
    uint8 node_id;
    uint8 unused;
    uint16 blk_size;
    aligned_buf_t read_buf;
    bool32 recover_done;
    bool32 ulog_exist_data;
    uint64 pitr_lfn;  // pitr use
    uint64 ddl_lsn_pitr;  // pitr use
    uint32 read_pos;
    uint32 write_pos;
    uint64 curr_file_length;
    arch_file_t arch_file; // archive logfile
    int32 handle[CT_MAX_LOG_FILES];  // online logfile handle
    log_point_t analysis_read_end_point;
    log_point_t recovery_read_end_point;
} dtc_rcy_node_t;

typedef struct st_rcy_node_stat {
    uint8 node_id;                    // rcy node id
    log_point_t rcy_point;            // rcy node rcy point
    log_point_t lrp_point;            // rcy node lrp point
    log_point_t curr_read_rcy_point;  // rcy node current read redo log point
} rcy_node_stat_t;

typedef struct st_dtc_rcy_stat {
    // last recovery stat
    uint64 last_rcy_log_size;           // redo log size
    uint64 last_rcy_set_num;            // recovery-set before revise
    uint64 last_rcy_analyze_elapsed;    // create recovery-set time consuming
    uint64 last_rcy_set_revise_elapsed; // revise recovery-set by other masters time consuming
    uint64 last_rcy_replay_elapsed;     // replay redo log time consuming
    uint64 last_rcy_elapsed;            // total recovery time consuming
    bool32 last_rcy_is_full_recovery;   // full recovery or partial recovery
    uint64 last_rcy_logic_log_group_count;  // replay logic group count
    uint64 last_rcy_logic_log_elapsed;      // replay logic log time consuming
    uint64 latc_rcy_logic_log_wait_time;    // wait time before replay logic log group
    instance_list_t last_rcy_inst_list;     // recovery instance list
    rcy_node_stat_t rcy_log_points[CT_MAX_INSTANCES];  // rcy&lrp point of each recovery inst

    // accumulate recovery stat
    uint64 accum_rcy_log_size;              // accumulate redo log size
    uint64 accum_rcy_set_num;               // accumulate recovery-set
    uint64 accum_rcy_set_create_elapsed;    // accumulate recovery-set create time consuming
    uint64 accum_rcy_set_revise_elapsed;    // accumulate recovery-set revise time consuming
    uint64 accum_rcy_replay_elapsed;        // accumulate redo log replay time consuming
    uint64 accum_rcy_elapsed;               // accumulate total recovery time consuming
    uint64 accum_rcy_times;                 // accumulate recovery times
} dtc_rcy_stat_t;

typedef enum st_dtc_recovery_status {
    RECOVERY_INIT,
    RECOVERY_ANALYSIS,
    RECOVERY_REPLAY,
    RECOVERY_FINISH,
} dtc_recovery_status_e;

typedef struct st_dtc_rcy_context {
    rcy_bucket_t bucket[CT_MAX_PARAL_RCY];
    spinlock_t lock;
    thread_t thread;
    bool32 full_recovery;
    bool32 paral_rcy;
    volatile bool32 in_progress;
    volatile bool32 canceled;
    volatile bool32 failed;
    bool8 is_end_restore_recover;
    uint32 node_count;
    uint32 finished_count;
    dtc_rcy_phase_e phase;
    rcy_set_t rcy_set;
    dtc_rcy_node_t *rcy_nodes;
    reform_rcy_node_t rcy_log_points[CT_MAX_INSTANCES];
    uint8 curr_node_idx;
    uint8 curr_node;
    uint8 replay_thread_num;
    uint16 curr_blk_size;
    uint64 curr_batch_lsn;
    uint64 end_lsn_restore_recovery;
    knl_session_t *ss;
    uint32 msg_sent;
    uint32 msg_recv;
    date_t rcy_set_send_time;
    dtc_rcy_stat_t rcy_stat;
    uint32 paral_rcy_size;
    uint16 rcy_set_ref_num;
    uint8 recovery_status;
    uint32 pcn_is_equal_num;
    int32 need_analysis_leave_page_cnt;
} dtc_rcy_context_t;

status_t dtc_recover(knl_session_t *session);
status_t dtc_recover_crashed_nodes(knl_session_t *session, instance_list_t *recover_list, bool32 full_recovery);

status_t dtc_start_recovery(knl_session_t *session, instance_list_t *recover_list, bool32 full_recovery);
void dtc_recovery_close(knl_session_t *session);
void dtc_stop_recovery(void);
bool32 dtc_recovery_need_stop(void);
bool32 dtc_recovery_in_progress(void);
bool32 dtc_recovery_failed(void);
void dtc_rcy_atomic_dec_group_num(uint32 idx, int32 val);
bool8 dtc_rcy_page_in_rcyset(page_id_t page_id);
void dtc_rcy_page_update_need_replay(page_id_t page_id);
rcy_set_item_t *dtc_rcy_get_item_internal(page_id_t page_id);
EXTER_ATTACK void dtc_process_rcy_set_ack(void *sess, mes_message_t *msg);
EXTER_ATTACK void dtc_process_rcy_set_err_ack(void *sess, mes_message_t *msg);
EXTER_ATTACK void dtc_process_rcy_set(void *sess, mes_message_t *receive_msg);
EXTER_ATTACK status_t dtc_send_page_back_to_node(knl_session_t *session, page_id_t *pages,
    uint32 count, bool32 finished, uint8 node_id, uint8 cmd);
status_t dtc_send_page_to_node(knl_session_t *session, page_id_t *pages, uint32 count, bool32 finished,
    uint8 node_id, uint8 cmd);
bool32 dtc_prcy_ckpt_in_progress(knl_session_t *session);
dtc_rcy_phase_e dtc_rcy_get_recover_phase(knl_session_t *session, bool32 full_recovery);
bool8 dtc_rcy_set_pitr_end_analysis(bool32 recover_flag);
bool8 dtc_rcy_set_pitr_end_replay(bool32 recover_flag, uint64 lsn);
status_t dtc_rcy_find_batch_by_lsn(char *buf, dtc_rcy_node_t *rcy_node, log_point_t *point,
                                   int32 size_read, bool8 *is_find_start);
status_t dtc_rcy_read_archived_log(knl_session_t *session, uint32 idx, uint32 *size_read);
status_t dtc_rcy_read_log(knl_session_t *session, int32 *handle, const char *name, int64 offset,
                          void *buf, int64 buf_size, int64 size_need_read, uint32 *size_read);
bool8 dtc_get_page_id_by_redo(log_entry_t *log, page_id_t *page_id_value);
bool8 dtc_rcy_check_recovery_is_done(knl_session_t *session, uint32 idx);
status_t dtc_rcy_set_batch_invalidate(knl_session_t *session, log_batch_t *batch);
status_t dtc_rcy_analyze_group(knl_session_t *session, log_group_t *group);
status_t dtc_rcy_process_batch(knl_session_t *session, log_batch_t *batch);
bool32 dtc_rcy_validate_batch(log_batch_t *batch);
status_t dtc_add_dirtypage_for_recovery(knl_session_t *session, page_id_t page_id);
status_t dtc_update_ckpt_log_point(void);
EXTER_ATTACK status_t dtc_rcy_set_update_no_need_replay_batch(rcy_set_t *rcy_set,
    page_id_t *no_rcy_pages, uint32 count);
status_t dtc_rcy_set_item_update_need_replay(rcy_set_bucket_t *bucket, page_id_t page_id, bool8 need_replay);
status_t dtc_rcy_verify_analysis_and_recovery_log_point(log_point_t analysis_read_end_point,
    log_point_t recovery_read_end_point);
void dtc_rcy_try_set_pitr_end_analysis(bool32 recover_flag, page_id_t *page_id, rcy_set_item_t *item, bool32 changed);
void dtc_rcy_init_page_id_stack(bool32 recover_flag);
void dtc_rcy_push_page_id(bool32 recover_flag, page_id_t page_id);
void dtc_rcy_pop_page_id(bool32 recover_flag, page_id_t *page_id);
void dtc_rcy_inc_need_analysis_leave_page_cnt(bool32 recover_flag);
void dtc_rcy_dec_need_analysis_leave_page_cnt(bool32 recover_flag);
void dtc_rcy_reset_need_analysis_leave_page_cnt(bool32 recover_flag);
bool8 dtc_rcy_is_need_analysis_leave_page(bool32 recover_flag);
status_t dtc_update_batch(knl_session_t *session, uint32 node_id);
status_t dtc_skip_damage_batch(knl_session_t *session, log_batch_t **batch, uint32 node_id);
status_t dtc_skip_batch(knl_session_t *session, log_batch_t **batch, uint32 node_id);
status_t dtc_find_next_batch(knl_session_t *session, log_batch_t **batch, uint32 cur_block_id, uint64 cur_lsn, uint32 node_id);
void dtc_rcy_next_file(knl_session_t *session, uint32 idx, bool32 *need_more_log);
status_t dtc_rcy_read_node_log(knl_session_t *session, uint32 idx, uint32 *size_read);

#define DTC_RCY_CONTEXT                         (&g_dtc->dtc_rcy_ctx)
#define DTC_RCY_GET_CURR_BATCH(dtc_rcy, idx) \
    ((log_batch_t *)((dtc_rcy)->rcy_nodes[(idx)].read_buf.aligned_buf + (dtc_rcy)->rcy_nodes[(idx)].read_pos))

#define DAAC_FULL_RECOVERY(session)             ((DTC_RCY_CONTEXT)->in_progress && (DTC_RCY_CONTEXT->full_recovery))
#define DAAC_PART_RECOVERY(session)             ((DTC_RCY_CONTEXT)->in_progress && !(DTC_RCY_CONTEXT->full_recovery))
#define DAAC_FULL_RECOVER_SESSION(session)      ((session)->dtc_session_type == DTC_FULL_RCY || (session)->dtc_session_type == DTC_FULL_RCY_PARAL)
#define DAAC_PARTIAL_RECOVER_SESSION(session) \
    ((session)->dtc_session_type == DTC_PART_RCY || (session)->dtc_session_type == DTC_PART_RCY_PARAL)
#define DAAC_SESSION_IN_RECOVERY(session)       (DAAC_FULL_RECOVER_SESSION(session) || DAAC_PARTIAL_RECOVER_SESSION(session))

#ifdef __cplusplus
}
#endif
#endif
