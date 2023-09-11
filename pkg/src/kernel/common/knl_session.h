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
 * knl_session.h
 *
 *
 * IDENTIFICATION
 * src/kernel/common/knl_session.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_SESSION_H__
#define __KNL_SESSION_H__

#include "cm_defs.h"
#include "cm_latch.h"
#include "cm_charset.h"
#include "cm_atomic.h"
#include "cm_thread.h"
#include "knl_interface.h"
#include "mtrl_defs.h"
#ifdef DB_DEBUG_VERSION
#include "knl_syncpoint.h"
#endif /* DB_DEBUG_VERSION */

#ifdef __cplusplus
extern "C" {
#endif

#define KNL_MAX_PAGE_STACK_DEPTH 6
#define KNL_MAX_ATOMIC_PAGES     145
#define KNL_LOGIC_LOG_BUF_SIZE 800
#define KNL_LOGIC_LOG_FLUSH_SIZE ((KNL_LOGIC_LOG_BUF_SIZE) / 2)
#define KNL_INVALID_SERIAL_ID    0

#define KNL_TEMP_MORE_MTRL_SEG_SIZE (sizeof(mtrl_segment_t) * (GS_MAX_TEMP_MTRL_SEGMENTS - GS_MAX_MATERIALS))

typedef struct st_page_stack {
    uint32 depth;
    struct st_buf_ctrl *pages[KNL_MAX_PAGE_STACK_DEPTH];
    latch_mode_t latch_modes[KNL_MAX_PAGE_STACK_DEPTH];
    bool32 is_skip[KNL_MAX_PAGE_STACK_DEPTH];
    uint32 log_begin[KNL_MAX_ATOMIC_PAGES];
    page_id_t gbp_aly_page_id[KNL_MAX_PAGE_STACK_DEPTH];
} page_stack_t;

typedef struct st_temp_page_stack {
    uint32 depth;
    vm_page_t *pages[KNL_MAX_PAGE_STACK_DEPTH];
} temp_page_stack_t;

#pragma pack(4)
typedef union st_xmap {
    uint32 value;
    struct {
        uint16 seg_id;
        uint16 slot;
    };
} xmap_t;
#pragma pack()

typedef union un_xid {
    uint64 value;
    struct {
        xmap_t xmap;
        uint32 xnum;
    };
} xid_t;

/* transaction item id */
typedef union un_tx_id {
    uint64 value;
    struct {
        uint32 seg_id;
        uint32 item_id;
    };
} tx_id_t;

typedef enum en_knl_session_status {
    SESSION_INACTIVE = 0,
    SESSION_SUSPENSION = 1,
    SESSION_ACTIVE = 2,
} knl_session_status_t;

typedef enum en_knl_session_qos_mode {
    QOS_NORMAL = 0,
    QOS_NOWAIT = 1,
    QOS_WAIT = 2,
} knl_session_qos_mode_t;

typedef struct st_knl_spin_stat_t {
    spin_statis_t stat_txn;
    spin_statis_t stat_txn_list;
    spin_statis_t stat_inc_scn;
    spin_statis_t stat_seri_commit;
    spin_statis_t stat_redo_buf;
    spin_statis_t stat_commit_queue;
    spin_statis_t stat_ckpt_queue;
    spin_statis_t stat_buffer;
    spin_statis_t stat_bucket;
    spin_statis_t stat_space;
    spin_statis_t stat_dc_entry;
    spin_statis_t stat_log_flush;
    spin_statis_t stat_sch_lock;
    spin_statis_t stat_ckpt;
    spin_statis_t stat_pcr_pool;
    spin_statis_t stat_pcr_bucket;
    spin_statis_t stat_gbp_queue;
} knl_spin_stat_t;

typedef struct st_knl_stat {
    uint16 id;
    uint16 next;

    uint64 disk_reads;
    uint64 disk_read_time;
    uint64 disk_writes;
    uint64 disk_write_time;
    uint64 temp_allocs;
    uint64 aio_reads;
    uint64 buffer_gets;
    uint64 buffer_recycle_cnt;
    uint64 buffer_recycle_wait;
    uint64 buffer_recycle_step;
    uint64 cr_reads;
    uint64 cr_gets;             // cr hits
    uint64 dcs_cr_reads;
    uint64 dcs_buffer_gets;
    uint64 dcs_buffer_sends;
    uint64 dcs_cr_gets;         // cr hits
    uint64 dcs_cr_sends;
    uint64 dcs_net_time;
    uint64 wait_time[WAIT_EVENT_COUNT];
    uint64 wait_count[WAIT_EVENT_COUNT];
    uint64 con_wait_time;
    uint64 atomic_opers;  // written by current session
    uint64 redo_bytes;    // written by current session
    uint64 commits;
    uint64 nowait_commits;
    uint64 rollbacks;
    uint64 local_txn_times;

    uint64 xa_commits;
    uint64 xa_rollbacks;
    uint64 xa_txn_times;

    uint64 processed_rows;
    uint64 sorts;
    uint64 disk_sorts;
    uint64 db_block_changes;
    uint64 pcr_construct_count;
    uint64 bcr_construct_count;
    uint64 cr_pool_capacity;
    uint64 cr_pool_used;

#ifdef Z_SHARDING
    uint64 dis_commits_single_shard;
    uint64 dis_rollbacks_single_shard;
    uint64 dis_commits_multi_shard;
    uint64 dis_rollbacks_multi_shard;
    uint64 dis_commit_time_single_shard;
    uint64 dis_rollback_time_single_shard;
    uint64 dis_commit_time_multi_shard;
    uint64 dis_rollback_time_multi_shard;
#endif
    /* GBP */
    uint64 gbp_page_write;
    uint64 gbp_page_write_time;
    uint64 gbp_write_wait;
    uint64 gbp_bg_read;
    uint64 gbp_bg_read_time;  /* us */
    uint64 gbp_knl_read;
    uint64 gbp_miss;
    uint64 gbp_hit;
    uint64 gbp_ahead;
    uint64 gbp_usable;
    uint64 gbp_old;

    uint64 table_creates;
    uint64 table_drops;
    uint64 table_alters;

    uint64 hists_inserts;
    uint64 hists_updates;
    uint64 hists_deletes;

    uint64 table_part_drops;
    uint64 table_subpart_drops;

    uint64 spc_free_exts;
    uint64 spc_shrink_times;
    uint64 undo_free_pages;
    uint64 undo_shrink_times;
    uint64 auto_txn_alloc_times;
    uint64 auto_txn_page_waits;
    uint64 auto_txn_page_end_waits;
    uint64 txn_alloc_times;
    uint64 txn_page_waits;
    uint64 txn_page_end_waits;
    knl_spin_stat_t spin_stat;
    uint64 undo_disk_reads;
    uint64 undo_buf_reads;
    uint64 btree_leaf_recycled;
} knl_stat_t;

typedef enum en_waitstat_id {
    DATA_BLOCK = 0,
    SEGMENT_HEADER,
    UNDO_BLOCK,
    UNDO_HEADER,
    FREE_LIST,
    WAITSTAT_COUNT,
} waitstat_id_t;

typedef struct st_knl_buf_wait {
    uint32 wait_count;
    uint64 wait_time;
} knl_buf_wait_t;

typedef struct st_knl_fsm_cache {
    page_id_t page_id;
    page_id_t entry;
    knl_scn_t seg_scn;
    uint32 page_count;
} knl_fsm_cache_t;

#define KNL_FSM_CACHE_COUNT (uint8)4

#define KNL_TX_FPL_COUNT (uint8)4

typedef struct st_knl_tx_fpl_node {
    page_id_t page_id;
    xid_t xid;
    uint8 itl_id;
    page_id_t entry;
    knl_scn_t seg_scn;
} knl_tx_fpl_node_t;

typedef struct st_knl_tx_fpl {
    uint8 count;
    uint8 index;
    knl_tx_fpl_node_t pages[KNL_TX_FPL_COUNT];
} knl_tx_fpl_t; // transaction free page list

typedef struct st_knl_session_wait {
    wait_event_t event;
    bool32 immediate;       // stats time spent on event execution or lock wating

    date_t begin_time;
    uint64 usecs;
    uint64 pre_spin_usecs;  // total spin sleep usecs
    timeval_t begin_tv;
} knl_session_wait_t;

typedef enum st_log_progress {
    LOG_COMPLETED = 0,
    LOG_PENDING = 1,
    LOG_WAITING = 2,
} log_progress_t;

typedef enum en_xa_status {
    XA_INVALID = 0,
    XA_START = 1,
    XA_SUSPEND = 2,
    XA_PHASE1 = 3,
    XA_PENDING = 4,
    XA_PHASE2 = 5
} xa_status_t;

typedef enum st_dtc_session_type {
    DTC_TYPE_NONE = 0,
    DTC_WORKER = 1,
    DTC_FULL_RCY = 2,
    DTC_FULL_RCY_PARAL = 3,
    DTC_PART_RCY = 4,
    DTC_PART_RCY_PARAL = 5,
} dtc_session_type_e;

typedef struct st_knl_rm {
    spinlock_t lock; // xa_status lock
    uint32 uid;
    uint16 id;
    uint16 sid;
    tx_id_t tx_id; // undo transaction area item id
    xid_t xid; // transaction id
    struct st_txn *txn; // transaction pointer

    uint16 prev;
    uint16 next;

    uint64 xa_flags;
    date_t suspend_time;
    uint64 suspend_timeout;
    knl_xa_xid_t xa_xid;
    uint16 xa_prev;
    uint16 xa_next;
    rowid_t xa_rowid;
    volatile uint8 xa_status;
    uint8 isolevel; // transaction isolation level
    bool8 is_ddl_op;
    uint8 aligned;

    knl_scn_t query_scn; // transaction query scn used for transaction level consistent read
    uint64 begin_lsn; // transaction begin lsn used for invalidate cursor
    uint32 undo_segid; // undo segment id for alloc undo pages
    uint32 ssn; // sql sequence number used for inside transaction visibility

    undo_page_info_t undo_page_info; // last undo page info
    undo_page_info_t noredo_undo_page_info; // last no-redo undo page info
    undo_page_list_t noredo_undo_pages; // nologging table's undo page list held by current txn

    lock_group_t row_lock_group;
    lock_group_t key_lock_group;
    lock_group_t sch_lock_group;
    lock_group_t direct_lock_group;
    lock_group_t alck_lock_group;

    cm_thread_cond_t cond;  // wait sem/cond, for false-sharing, do not put it in same cache-line with commit_cond

    lob_item_list_t lob_items;
    knl_savepoint_t save_points[GS_MAX_SAVEPOINTS];

    uint8 svpt_count;  // save point count for current transaction
    bool8 logging; // statement is doing logging insert nor not
    bool8 need_copy_logic_log;
    bool8 temp_has_undo; // temp table has undo

    char logic_log_buf[KNL_LOGIC_LOG_BUF_SIZE];
    uint32 logic_log_size;
    uint32 large_page_id;
    uint64 idx_conflicts; // current statement index conflicts
    bool8 txn_alarm_enable;
    bool8 nolog_insert;  // current rm has done nologging insert
    nologing_type_t nolog_type;
} knl_rm_t;

typedef struct st_advlck_wait {
    uint32 serial;
    uint32 lock_id;
}alck_wait_t;

#define RECYCLE_PAGE_NUM (100)

typedef struct {
    spinlock_t lock;
    uint32 count;
    page_id_t pages[RECYCLE_PAGE_NUM];
    date_t req_start_times[RECYCLE_PAGE_NUM];
} recycle_pages;

typedef struct st_knl_session {
    struct st_knl_instance *kernel;
    uint32 id;
    uint32 rmid;
    // the operating system's thread id by whom the current session is carried.
    // 0 means no thread is carrying this session
    uint32 spid;
    uint32 serial_id;  // used to identify a session's object uniquely, when we reuse a session with the same id
    uint32 uid;        // user id
    uint32 drop_uid;   // user id dropping now
    uint32 inst_id;    // instance id, for cluster
    uint16 stat_id;
    uint8 reverse;
    bool8 has_migr;
    bool8 bootstrap;  // if this session is doing database bootstrap
    bool8 autotrace;
    bool8 interactive_altpwd;
    bool8 delete_ptrans;

    knl_rm_t *rm;

    page_stack_t page_stack;
    temp_page_stack_t temp_page_stack;
    char *curr_page;
    struct st_buf_ctrl *curr_page_ctrl;
    char *curr_cr_page;
    struct st_pcrp_ctrl *curr_pcrp_ctrl;
    cm_stack_t *stack;
    knl_match_cond_t match_cond;
    int32 datafiles[GS_MAX_DATA_FILES];  // data file handles
    knl_stat_t *stat;
    knl_session_wait_t wait;
    knl_buf_wait_t buf_wait[WAITSTAT_COUNT];

    uint64 ssn; // sql sequence number used for temporary table visibility judgment
    knl_scn_t query_scn; // statement query scn

    bool8 trace_on;
    bool8 commit_batch;
    bool8 commit_nowait;
    bool8 is_waiting;

    void *log_entry;
    char *log_buf;
    struct st_knl_session *log_next;
    volatile log_progress_t log_progress;
    cm_thread_cond_t commit_cond;

    volatile uint64 curr_lsn;   // latest lsn generated by current session
    uint64 ddl_lsn_pitr;
    uint64 curr_lfn;     // expected batch lfn for session current log
    bool8 log_encrypt; // private log need encrypt
    bool8 thread_shared; // if curr session will be thread shared
    bool8 atomic_op;
    bool8 log_diag;
#ifdef LOG_DIAG
    char *log_diag_page[KNL_MAX_ATOMIC_PAGES];
#endif

    uint32 dirty_count;
    uint32 changed_count;
    struct st_buf_ctrl *dirty_pages[KNL_MAX_ATOMIC_PAGES];
    struct st_buf_ctrl *changed_pages[KNL_MAX_ATOMIC_PAGES];  // all dirty pages affected by atomic operation

    uint8 gbp_queue_index; // which gbp queue to push gbp_dirty_pages, only gbp bg session's gbp_queue_index > 0
    uint32 gbp_dirty_count;
    struct st_buf_ctrl *gbp_dirty_pages[KNL_MAX_ATOMIC_PAGES];  // dirty pages that not flush to GBP if use gbp

    uint32 lock_wait_timeout;  // lock wait timeout(ms)
    uint8 itl_id;   // current itl id
    bool8 compacting;
    int8 change_list;  // the change num of map list
    bool8 bg_rollback;
    uint8 curr_fsm;    // current insert FSM
    knl_fsm_cache_t cached_fsms[KNL_FSM_CACHE_COUNT];

    knl_tx_fpl_t tx_fpl; // transaction free page list

    volatile xid_t wxid; // wait node id in transaction table
    volatile rowid_t wrid;
    volatile lock_twait_t wtid;  // wait on this table
    volatile page_id_t wpid;     // wait on page itls
    volatile alck_wait_t walck_se; // wait on session level advisory lock
    volatile alck_wait_t walck_tx; // wait on transaction level advisory lock
    volatile uint16 wrmid;        // wait session id
    volatile bool8 dead_locked;
    volatile bool8 itl_dead_locked;
    volatile bool8 lock_dead_locked;
    volatile bool8 alck_se_dead_locked;
    volatile bool8 alck_tx_dead_locked;
    // caution !! do not assign killed to true directly, use g_knl_callback.kill_session instead
    volatile bool8 killed;
    volatile bool8 canceled;
    volatile bool8 force_kill;
    bool8 stat_sample;
    bool8 skip_update_mk;

    vm_pool_t *temp_pool;
    uint32 temp_table_count;
    uint32 temp_table_capacity;
    knl_temp_cache_t *temp_table_cache;  // temp table is created on mtrl segment, refer to GS_MAX_MATERIALS
    mtrl_context_t *temp_mtrl;
    knl_temp_dc_t *temp_dc;
    void *temp_dc_entries;
    latch_t ltt_latch;

    // dblink table
    knl_lnk_tab_dc_t *lnk_tab_dc;
    uint32 lnk_tab_count;
    uint32 lnk_tab_capacity;
    void *lnk_tab_entries;

    volatile char *index_root;

    knl_session_qos_mode_t qos_mode;
    knl_session_status_t status;

    latch_statis_t stat_heap;
    latch_statis_t stat_btree;
    latch_statis_t stat_page;
    latch_statis_t stat_lob;
    latch_statis_t stat_interval;

#ifdef DB_DEBUG_VERSION
    syncpoint_action_t syncpoint_action;
#endif /* DB_DEBUG_VERSION */
    knl_update_info_t update_info;  // for update info, will be used by kernel cursor when open cursor
    knl_update_info_t *trig_ui;
    uint64 idx_conflicts;
    uint32 logic_log_size;
    int32 logic_log_num;
    dtc_session_type_e dtc_session_type;
    text_t *dist_ddl_id;

    lock_group_t alck_lock_group;
    knl_scn_t xa_scn;
    uint64 temp_version;
    uint32 stats_parall;
    bool32 user_locked_ddl;
} knl_session_t;

#define KNL_SESSION_SET_CURR_THREADID(session, tid) \
    do {                                            \
        (session)->spid = (tid);                    \
    } while (0)

#define KNL_SESSION_CLEAR_THREADID(session) \
    do {                                    \
        (session)->spid = 0;                \
    } while (0)

static inline void knl_wait_for_tick(knl_session_t *session)
{
    timeval_t tv_begin, tv_end;
    if (session->wait.usecs == 0) {
        session->wait.begin_time = cm_now();
    }

    (void)cm_gettimeofday(&tv_begin);
    cm_spin_sleep();
    (void)cm_gettimeofday(&tv_end);
    session->wait.usecs += (uint64)TIMEVAL_DIFF_US(&tv_begin, &tv_end);
}

static inline status_t knl_check_session_status(knl_session_t *session)
{
    if (session->canceled) {
        GS_THROW_ERROR(ERR_OPERATION_CANCELED);
        return GS_ERROR;
    }

    if (session->killed) {
        GS_THROW_ERROR(ERR_OPERATION_KILLED);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

extern uint32 g_local_inst_id;

static inline uint32 knl_db_node_id(knl_session_t *session)
{
    CM_ASSERT(g_local_inst_id < GS_MAX_INSTANCES);  //
    return g_local_inst_id;
}

#define KNL_NOW(session) ((session)->kernel->attr.timer->now)
#define KNL_IS_AUTON_SE(session) (((session)->rm != NULL) && ((session)->rm->prev != GS_INVALID_ID16))
#define KNL_GBP_ENABLE(kernel)        ((kernel)->gbp_attr.use_gbp)
#define KNL_GBP_OFF_TRIGGERED(kernel) ((kernel)->gbp_attr.gbp_off_triggered)
#define KNL_GBP_FOR_RECOVERY(kernel)  ((kernel)->gbp_attr.gbp_for_recovery)
#define KNL_GBP_SAFE(kernel)          ((kernel)->gbp_attr.use_gbp && !((kernel)->redo_ctx.gbp_aly_result.gbp_unsafe))
#define KNL_RECOVERY_WITH_GBP(kernel) ((kernel)->redo_ctx.rcy_with_gbp)
#define KNL_GBP_READ_VER(kernel)      ((kernel)->gbp_context.gbp_read_version)

#define MY_LOGFILE_SET(session) (&(session)->kernel->db.logfile_sets[(session)->kernel->id])
#define MY_UNDO_SET(session) (&(session)->kernel->undo_ctx.undo_sets[(session)->kernel->id])

#define UNDO_SET(session, id) (&(session)->kernel->undo_ctx.undo_sets[(id)])
#define LOGFILE_SET(session, id) (&(session)->kernel->db.logfile_sets[(id)])

#define DAAC_REPLAY_NODE(session)               (DB_IS_CLUSTER(session) && ((session)->dtc_session_type == DTC_WORKER))
#define DAAC_CKPT_SESSION(session)              ((session)->id == SESSION_ID_DBWR)
#define DAAC_NEED_FLUSH_LOG(session, ctrl)      ((session)->kernel->redo_ctx.flushed_lfn < (ctrl)->lastest_lfn)

#ifdef __cplusplus
}
#endif

#endif
