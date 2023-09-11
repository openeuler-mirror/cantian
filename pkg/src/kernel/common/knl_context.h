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
 * knl_context.h
 *
 *
 * IDENTIFICATION
 * src/kernel/common/knl_context.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_CONTEXT_H__
#define __KNL_CONTEXT_H__

#include "cm_defs.h"
#include "cm_timer.h"
#include "repl_raft.h"
#include "cm_kmc.h"
#include "knl_database.h"
#include "repl_log_send.h"
#include "repl_log_replay.h"
#include "repl_arch_fetch.h"
#include "knl_smon.h"
#include "knl_rmon.h"
#include "knl_ashrink.h"
#include "repl_log_recv.h"
#include "knl_recovery.h"
#include "bak_build.h"
#include "knl_extern_table_defs.h"
#include "pcr_pool.h"
#include "knl_rstat.h"
#include "knl_alck.h"
#include "knl_gbp.h"
#include "knl_ctlg.h"
#ifdef DB_DEBUG_VERSION
#include "knl_syncpoint.h"
#endif /* DB_DEBUG_VERSION */
#ifndef WIN32
#include <sys/epoll.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_knl_attr {
    bool32 commit_batch;
    bool32 commit_nowait;

    uint32 page_size;
    uint32 max_row_size;
    uint32 plog_buf_size;
    uint32 cursor_size;
    uint32 max_map_nodes;  // max node count in map page
    uint32 max_sessions;
    uint32 db_block_checksum;

    uint32 default_extents;
    uint32 buf_pool_num;
    uint64 data_buf_size;
    uint64 data_buf_part_size;
    uint64 data_buf_part_align_size;
    uint64 vma_size;
    uint64 large_vma_size;
    uint64 pma_size;
    uint64 buddy_init_size;
    uint64 buddy_max_size;
    uint64 shared_area_size;
    double sql_pool_factor;
    uint64 large_pool_size;
    uint64 log_buf_size;
    uint64 dbwr_buf_size;
    uint64 lgwr_buf_size;
    uint64 lgwr_cipher_buf_size;
    uint64 lgwr_async_buf_size;
    uint64 lgwr_head_buf_size;
    uint64 tran_buf_size;
    uint32 temp_pool_num;
    uint64 temp_buf_size;
    uint64 temp_buf_inst_size;
    uint64 temp_buf_inst_align_size;
    uint64 index_buf_size;
    uint64 thread_stack_size;
    uint64 reactor_thread_stack_size;
    uint64 buf_iocbs_size;
    uint64 cr_pool_size;
    uint64 cr_pool_part_size;
    uint64 cr_pool_part_align_size;
    uint32 cr_pool_count;

    bool32 enable_multi_stmt;

    uint32 log_buf_count;
    uint32 dbwr_processes;
    uint32 log_replay_processes;
    uint32 rcy_preload_processes;
    uint32 rcy_sleep_interval;

    uint32 cpu_count;
    uint32 spin_count;
    uint32 cpu_bind_lo;
    uint32 cpu_bind_hi;

    bool32 enable_qos;
    bool32 recyclebin;
    bool32 drop_nologging;
    uint32 qos_threshold;
    double qos_factor;
    uint32 qos_sleep_time;
    uint32 qos_random_range;
    bool32 disable_soft_parse;
    bool32 enable_timed_stat;
    bool32 enable_table_stat;
    bool32 enable_double_write;
    bool32 enable_directIO;
    bool32 enable_logdirectIO;
    bool32 enable_asynch;
    bool32 enable_dsync;
    bool32 enable_fdatasync;
    bool32 enable_OSYNC;
    bool32 enable_ltt; /* LTT = LOCAL TEMPORARY TABLE */
    bool32 enable_upper_case_names;
    bool32 enable_cbo;
    bool32 rcy_check_pcn;
    uint32 repl_wait_timeout;
    uint32 build_keep_alive_timeout;
    uint16 repl_port;
    char repl_trust_host[GS_HOST_NAME_BUFFER_SIZE * GS_MAX_LSNR_HOST_COUNT];
    bool32 repl_auth; // default false, if true, check user and passwd in replication
    bool32 repl_scram_auth; // default false, if true, force user and passwd using complete rfc5802
    atomic_t repl_pkg_size;

    uint32 undo_reserve_size;
    uint32 undo_retention_time;
    uint32 undo_segments;
    uint32 undo_active_segments;
    uint32 undo_auton_trans_segments;
    bool32 undo_auton_bind_own;
    bool32 undo_auto_shrink;
    bool32 undo_auto_shrink_inactive;
    uint32 undo_prefetch_page_num;
    uint32 tx_rollback_proc_num;
    bool32 serialized_commit;
    uint32 lock_wait_timeout;
    bool32 enable_tx_free_page_list;

    bool32 enable_raft;
    uint32 raft_start_mode;
    uint32 raft_node_id;
    uint32 raft_log_level;
    uint32 raft_log_async_buffer_num;
    uint32 raft_failover_lib_timeout;
    char raft_peer_ids[GS_HOST_NAME_BUFFER_SIZE];
    char raft_local_addr[GS_HOST_NAME_BUFFER_SIZE];
    char raft_peer_addrs[GS_RAFT_PEERS_BUFFER_SIZE];
    char raft_kudu_dir[GS_FILE_NAME_BUFFER_SIZE];
    char raft_priority_type[GS_FILE_NAME_BUFFER_SIZE];
    char raft_priority_level[GS_FILE_NAME_BUFFER_SIZE];
    char raft_layout_info[GS_FILE_NAME_BUFFER_SIZE];
    char raft_pending_cmds_buffer_size[GS_MAX_NAME_LEN];
    char raft_send_buffer_size[GS_MAX_NAME_LEN];
    char raft_receive_buffer_size[GS_MAX_NAME_LEN];
    char raft_tls_dir[GS_FILE_NAME_BUFFER_SIZE];
    char raft_token_verify[GS_FILE_NAME_BUFFER_SIZE];
    char raft_max_size_per_msg[GS_MAX_NAME_LEN];
    char raft_entry_cache_memory_size[GS_MAX_NAME_LEN];
    char raft_mem_threshold[GS_MAX_NAME_LEN];
    char raft_election_timeout[GS_MAX_NAME_LEN];

    uint32 ckpt_interval;
    uint32 ckpt_timeout;
    uint32 ckpt_io_capacity;
    bool32 ckpt_flush_neighbors;

    uint64 backup_buf_size;
    uint64 max_arch_files_size;
    bool32 arch_log_check;
    uint32 arch_upper_limit;
    uint32 arch_lower_limit;
    bool32 arch_ignore_backup;
    bool32 arch_ignore_standby;
    char *data_buf;
    char *temp_buf;  // buffer of temp_pool, user for materialize
    char *log_buf;
    char *ckpt_buf;
    char *lgwr_buf;
    char *lgwr_cipher_buf;
    char *lgwr_async_buf;
    char *lgwr_head_buf;
    char *tran_buf;
    char *index_buf;
    char *cr_buf;
    char *xpurpose_buf;  // used for file-write and other operation need a short temp-memory buffer
    char *buf_iocbs;

    memory_area_t *shared_area;
    memory_pool_t *large_pool;
    config_t *config;
    gs_timer_t *timer;
    log_sync_param_t sync_mode;
    arch_attr_t arch_attr[GS_MAX_ARCH_DEST];
    char pwd_alg[GS_NAME_BUFFER_SIZE];
    char sys_pwd[GS_PASSWORD_BUFFER_SIZE];
    file_convert_t data_file_convert;
    file_convert_t log_file_convert;
    bool32 enable_resource_limit;
    uint32 alg_iter;
    uint32 max_temp_tables;
    uint32 max_link_tables;
    uint32 column_count;  // 1024 2048 3072 4096
    bool32 enable_idx_key_len_check;
    uint32 tc_level;
    uint32 max_column_count;  // 1024 2048 3072 4096
    uint32 vmp_cache_pages;
    uint64 stats_sample_size;
    bool32 idx_auto_recycle;
    bool32 idx_auto_rebuild;
    uint32 idx_auto_rebuild_start_date; // total seconds from 00:00:00, invalid GS_INVALID_ID32
    uint32 idx_recycle_percent;
    uint64 idx_recycle_size;
    uint32 idx_force_recycle_time;
    uint32 idx_recycle_reuse_time;
    uint32 idx_rebuild_keep_storage_time;
    uint32 lsnd_wait_time;
    uint32 initrans;
    uint8 cr_mode;
    uint8 row_format;
    uint8 db_isolevel;
    uint8 private_row_locks;
    uint8 private_key_locks;
    uint32 ddl_lock_timeout;
    uint32 max_rms;
    uint32 xa_suspend_timeout;
    uint32 spc_usage_alarm_threshold;
    uint32 undo_usage_alarm_threshold;
    uint32 txn_undo_usage_alarm_threshold;
    bool32 temptable_support_batch;
    bool32 enable_abr;
    uint32 abr_timeout;
    uint32 stats_cost_limit;
    uint32 stats_cost_delay;
    uint32 quorum_any;
    bool32 enable_sample_limit;
    bool32 enable_degrade_search;
    uint32 small_table_sampling_threshold;
    uint32 ashrink_wait_time;
    uint32 shrink_wait_recycled_pages;
    uint16 stats_max_buckets;
    bool32 delay_cleanout;          // delay_cleanout
    int64 systime_inc_threshold;   // max seconds of system time inscreased
    uint8 default_space_type;
    uint8 ctrllog_backup_level;
    uint8 default_compress_algo;
    keyfile_item_t kmc_key_files[GS_KMC_MAX_KEYFILE_NUM];
    uint64 lob_reuse_threshold;
    uint32 index_defer_recycle_time;
    uint32 page_clean_period;
    bool32 restore_keep_arch_compressed;
    bool32 enable_arch_compress;
    uint32 page_clean_wait_timeout;
    uint32 ckpt_timed_task_delay;
    bool32 restore_check_version;
    uint32 nbu_backup_timeout;
    char db_version[GS_DB_NAME_LEN];
    bool32 check_sysdata_version;
    uint32 shrink_percent;
    uint32 stats_paraller_threads;
    uint32 stats_enable_parall;
    bool32 build_datafile_parallel;
    uint32 init_lockpool_pages;
    bool32 enable_temp_bitmap;
    bool32 tab_compress_enable_buf;
    uint64 tab_compress_buf_size;
    double normal_emerge_sess_factor;
    bool32 build_datafile_prealloc;
    bool32 enable_auto_inherit;
    bool32 backup_log_prealloc;
    bool32 password_verify;
    bool32 clustered;
    uint32 deadlock_detect_interval;
    uint32 auto_undo_retention;
    uint32 lru_search_threshold;
    double page_clean_ratio;
    uint32 compatible_mysql;
    uint32 page_clean_mode;
    bool32 backup_retry;
    uint32 batch_flush_capacity;
    bool32 enable_hwm_change;
} knl_attr_t;

typedef struct st_sys_name_context {  // for system name
    spinlock_t lock;
    uint32 sequence;
} sys_name_context_t;

typedef struct st_job {
    thread_t thread;
} job_t;

typedef struct st_synctimer {
    thread_t *thread;
} synctimer_t;

typedef struct st_encrypt_context {
    bool8 swap_encrypt_flg;
    uint8 swap_encrypt_version;
    uint8 swap_cipher_reserve_size;
    spinlock_t lock;
} encrypt_context_t;

typedef struct st_dtc_attr {
    uint32    inst_id;
    char gss_inst_path[GS_UNIX_PATH_MAX];
}dtc_attr_t;

typedef struct st_knl_instance {
    knl_handle_t server;
    atomic_t scn;
    atomic_t commit_scn;
    uint32 atomic_align1[32];
    atomic_t lsn;
    uint32 atomic_align2[32];
    atomic_t lfn;
    knl_attr_t attr;
    dtc_attr_t dtc_attr;
    char *home;
    atomic_t undo_segid;
    database_t db;
    atomic_t min_scn;  // min query scn of all active sessions
    atomic_t local_min_scn; // min query scn of all local node sessions
#ifdef Z_SHARDING
    atomic_t min_gts_scn; // min GTS query scn of all active sessions in current CN
    bool32 is_coordinator;
#endif
    atomic32_t seq_name;
    raft_context_t raft_ctx;
    spinlock_t lock;
    log_context_t redo_ctx;
    dc_context_t dc_ctx;
    ckpt_context_t ckpt_ctx;
    undo_context_t undo_ctx;
    tx_area_t tran_ctx;
    lock_area_t lock_ctx;
    lob_area_t lob_ctx;
    smon_t smon_ctx;    // system monitor
    rmon_t rmon_ctx;    // resource monitor
    stats_t stats_ctx;
    job_t job_ctx;
    synctimer_t synctimer_ctx;
    arch_context_t arch_ctx;
    bak_context_t backup_ctx;
    aligned_buf_t ddl_file_mgr;
    index_area_t index_ctx;
    lsnd_context_t lsnd_ctx;
    lrpl_context_t lrpl_ctx;
    gbp_aly_ctx_t gbp_aly_ctx;
    lftc_clt_ctx_t lftc_client_ctx;
    lrcv_context_t lrcv_ctx;
    rcy_context_t rcy_ctx;
    buf_context_t buf_ctx;
    pcrp_context_t pcrp_ctx;
    encrypt_context_t encrypt_ctx;
    ashrink_ctx_t ashrink_ctx;
    auto_rebuild_ctx_t auto_rebuild_ctx;
    knl_stat_t stat;
    atomic_t total_io_read;

    knl_dynview_t *dyn_views;
    uint32 dyn_view_count;
    knl_dynview_t *dyn_views_nomount;
    uint32 dyn_view_nomount_count;
    knl_dynview_t *dyn_views_mount;
    uint32 dyn_view_mount_count;

    knl_dynview_t *global_dyn_views;
    uint32 global_dyn_view_count;
#ifdef Z_SHARDING
    knl_dynview_t *shd_dyn_views;
    uint32 shd_dyn_view_count;
#endif

    uint32 temp_ctx_count;
    vm_pool_t temp_pool[GS_MAX_BUF_POOL_NUM];

    switch_ctrl_t switch_ctrl;
    volatile bool32 record_backup_trigger[GS_MAX_PHYSICAL_STANDBY];

    uint32 reserved_sessions;
    atomic32_t running_sessions;
    atomic32_t assigned_sessions;
    knl_session_t *sessions[GS_MAX_SESSIONS];
    knl_rm_t *rms[GS_MAX_RMS];
    uint32 rm_count;
    char instance_name[GS_NAME_BUFFER_SIZE];
    char alarm_log_dir[GS_MAX_PATH_BUFFER_SIZE];

    date_t db_startup_time;  // the time db startup
    gbp_attr_t gbp_attr;        // gbp config params
    gbp_context_t gbp_context;  // gbp context
    pcb_context_t compress_buf_ctx; // page compress buf context for page compress
#ifdef DB_DEBUG_VERSION
    syncpoint_t syncpoint;
#endif /* DB_DEBUG_VERSION */

    cm_aio_lib_t aio_lib;
    buf_aio_ctx_t buf_aio_ctx;
    alck_ctx_t alck_ctx;
    bool32 is_ssl_initialized; // if ssl is enabled, indicate whether ssl has been initialized
    ddl_exec_status_t set_dc_complete_status;
    uint32        id;   //instance id, id = 0 if under non-clustered mode
    thread_t file_iof_thd;
} knl_instance_t;

#define KNL_MAX_ROW_SIZE(session)     ((session)->kernel->attr.max_row_size)

#define KNL_IDX_RECYCLE_ENABLED(kernel) ((kernel)->attr.idx_auto_recycle)

#define SEG_STATS_INIT(session, temp_stat)             \
    do {                                               \
        if (STATS_ENABLE_MONITOR_TABLE(session)) {     \
            db_segment_stats_init(session, temp_stat); \
        }                                              \
    } while (0)

#define SEG_STATS_RECORD(session, temp_stat, seg_stat)              \
    do {                                                            \
        if (STATS_ENABLE_MONITOR_TABLE(session)) {                  \
            db_segments_stats_record(session, temp_stat, seg_stat); \
        }                                                           \
    } while (0)

static inline bool32 page_compress(knl_session_t *session, page_id_t page_id)
{
    datafile_t *df = DATAFILE_GET(session, page_id.file);

    if (!DATAFILE_IS_COMPRESS(df)) {
        return GS_FALSE;
    }

    /* compress datafile can be only added in bitmap tablespace */
    return (page_id.page >= DF_MAP_HWM_START);
}

uint32 knl_io_flag(knl_session_t *session);
uint32 knl_redo_io_flag(knl_session_t *session);
uint32 knl_arch_io_flag(knl_session_t *session, bool32 arch_compressed);

status_t db_fdatasync_file(knl_session_t *session, int32 file);
status_t db_fsync_file(knl_session_t *session, int32 file);
status_t db_load_lib(knl_session_t *session);

#ifdef __cplusplus
}
#endif

#endif
