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
 * srv_instance.h
 *
 *
 * IDENTIFICATION
 * src/server/srv_instance.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SRV_INSTANCE_H__
#define __SRV_INSTANCE_H__

#include "cm_defs.h"
#include "cm_config.h"
#include "cm_timer.h"
#include "cs_listener.h"
#include "srv_lsnr.h"
#include "srv_rm.h"
#include "srv_param.h"
#include "srv_sga.h"
#include "srv_agent.h"
#include "knl_context.h"
#include "knl_interface.h"
#include "ctsql_context.h"
#include "ctsql_service.h"
#include "srv_reactor.h"
#include "srv_job.h"
#include "srv_emerg.h"
#include "ctsql_resource.h"
#include "srv_sess_security.h"
#include "cse_stats.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum os_run_info_types {
    /* cpu numbers */
    NUM_CPUS = 0,
    NUM_CPU_CORES,
    NUM_CPU_SOCKETS,

    /* cpu times */
    IDLE_TIME,
    BUSY_TIME,
    USER_TIME,
    SYS_TIME,
    IOWAIT_TIME,
    NICE_TIME,

    /* avg cpu times */
    AVG_IDLE_TIME,
    AVG_BUSY_TIME,
    AVG_USER_TIME,
    AVG_SYS_TIME,
    AVG_IOWAIT_TIME,
    AVG_NICE_TIME,

    /* virtual memory page in/out data */
    VM_PAGE_IN_BYTES,
    VM_PAGE_OUT_BYTES,

    /* os run load */
    RUNLOAD,

    /* physical memory size */
    PHYSICAL_MEMORY_BYTES,

    TOTAL_OS_RUN_INFO_TYPES
} os_run_info_types;

typedef enum en_shutdown_mode {
    SHUTDOWN_MODE_NORMAL = 0,
    SHUTDOWN_MODE_IMMEDIATE,
    SHUTDOWN_MODE_SIGNAL,
    SHUTDOWN_MODE_ABORT,
    SHUTDOWN_MODE_END,
} shutdown_mode_t;

typedef enum en_shutdown_phase {
    SHUTDOWN_PHASE_NOT_BEGIN = 0,
    SHUTDOWN_PHASE_INPROGRESS,
    SHUTDOWN_PHASE_DONE
} shutdown_phase_t;

typedef enum en_promote_columns {
    PRMOTE_COL_TIME = 0,
    PRMOTE_COL_TYPE = 1,
    PRMOTE_COL_LOCAL_HOST = 2,
    PRMOTE_COL_PEER_HOST = 3
} promote_columns_t;

typedef struct st_shutdown_context {
    spinlock_t lock;
    session_t *session;
    shutdown_mode_t mode;
    shutdown_phase_t phase;
    bool32 enabled;
    drlatch_t shutdown_latch; // keep shutdown in order
} shutdown_context_t;

typedef struct st_instance_attr {
    uint32 stack_size;
    uint32 init_cursors;
    uint32 black_box_depth;
    uint32 core_dump_config;

    uint32 optimized_worker_count;
    uint32 max_worker_count;
    uint32 merge_sort_batch_size;
    uint32 max_allowed_packet;
    uint32 lob_max_exec_size;

    uint32 hint_force;
    uint32 sql_cursors_each_sess;
    uint32 reserved_sql_cursors;
    uint32 sql_map_buckets;

    bool8 mem_alloc_from_large_page;
    bool8 using_naive_datatype;
    bool8 enable_sql_map;
    uint8 unused;

    uint32 pl_cursor_slots;
    uint32 max_remote_params;
    uint32 open_cursors;
    uint64 master_slave_difftime;
    bool32 access_dc_enable;
    bool32 enable_local_infile;
    bool32 view_access_dc;
    // for CN only
    uint64 xa_fmt_id;
#ifdef Z_SHARDING
    uint32 sequence_cache_size;
    bool32 shard_restricted_feature;
    bool32 shard_error_force_rollback;
#endif
    bool32 enable_permissive_unicode;
    uint32 priv_connection;
    uint32 priv_session;
    uint32 priv_agent;
    bool32 disable_var_peek;
    bool32 enable_cursor_sharing;
    bool32 enable_use_spm;
} instance_attr_t;

typedef struct st_os_run_desc {
    char *name;
    char *comments;
    bool32 comulative;
    bool32 got;
} os_run_desc_t;

typedef struct st_os_run_info {
    os_run_desc_t *desc;
    union {
        uint64 int64_val;  /* cpu times,vm pgin/pgout size,total memory etc. */
        double float8_val; /* load */
        uint32 int32_val;  /* cpu numbers */
    };
} os_run_info_t;

typedef struct st_library_cache_t {
    uint32 lang_type;
    char lib_namespace[CT_MAX_NAME_LEN];
    atomic_t hits;
    atomic_t gethits;
    atomic_t pins;
    atomic_t pinhits;
    atomic_t reloads;
    atomic_t invlidations;
} st_library_cache_t;

typedef struct uuid_info {
    spinlock_t lock;
    uint32 self_increase_seq;
    char mac_address[CT_MAC_ADDRESS_LEN + 1];
} st_uuid_info_t;

typedef struct st_rebalance_ctrl {
    thread_lock_t res_lock;
    pointer_t rblc_tbls;
} rebalance_ctrl_t;

typedef struct st_instance {
    uint32 id;
    int32 lock_fd;
    lsnr_t lsnr;
    char home[CT_MAX_PATH_BUFFER_SIZE];
    char rand_for_md5[CT_KDF2SALTSIZE];

    knl_instance_t kernel;

    sql_style_t sql_style;
    sql_instance_t sql;

    sga_t sga;
    rm_pool_t rm_pool;
    stat_pool_t stat_pool;
    session_pool_t session_pool; /* session map */
    reactor_pool_t reactor_pool;
    sql_par_pool_t sql_par_pool;
    sql_emerg_pool_t sql_emerg_pool;
    sql_cur_pool_t sql_cur_pool; /* global sql cursor pool */
    st_uuid_info_t g_uuid_info;
    char xpurpose_buf[CT_XPURPOSE_BUFFER_SIZE + CT_MAX_ALIGN_SIZE_4K];

    instance_attr_t attr;
    config_t config;
    shutdown_context_t shutdown_ctx;
    os_run_info_t os_rinfo[TOTAL_OS_RUN_INFO_TYPES];

    ssl_ctx_t *ssl_acceptor_fd;
    drlock_t dblink_lock;
    spinlock_t stat_lock;
    job_mgr_t job_mgr; /* job manager */
    st_library_cache_t library_cache_info[10];
    rsrc_mgr_t rsrc_mgr;
    atomic_t logined_count;      // the account of current external user connected from client
    atomic_t logined_cumu_count; // the cumulative account of external user connected from client
    atomic32_t seq_xid; // for xid generating
    bool32 sync_doing;
    bool32 is_ztrst_instance;
    bool8 lsnr_abort_status : 1;
    bool8 is_setlocale_success : 1;
    bool8 gts_started : 1;
    bool8 cn_alter_pwd : 1;
    bool8 audit_log_warning : 1;
    bool8 inc_rebalance : 1;
    bool8 unused : 2;
    date_t frozen_starttime;
    uint32 frozen_waittime;
} instance_t;

typedef struct st_promote_record {
    date_t time;
    char type[CT_MAX_PROMOTE_TYPE_LEN];
    char local_url[CT_HOST_NAME_BUFFER_SIZE + CT_TCP_PORT_MAX_LENGTH + 1];
    char peer_url[CT_HOST_NAME_BUFFER_SIZE + CT_TCP_PORT_MAX_LENGTH + 1];
} promote_record_t;

#define IS_GTS CT_FALSE
#define IS_COORDINATOR CT_FALSE
#define IS_DATANODE CT_FALSE
#define IS_SHARD CT_FALSE
#define IS_CONSOLE_APP CT_FALSE
#define IS_APP_CONN(session) CT_TRUE
#define IS_COORD_CONN(session) CT_FALSE

#define GET_PWD_BLACK_CTX (&g_instance->session_pool.pwd_black_ctx)
#define GET_WHITE_CTX (&g_instance->session_pool.white_ctx)
#define GET_MAL_IP_CTX (&g_instance->session_pool.malicious_ip_ctx)
#define GET_SYSDBA_PRIVILEGE (g_instance->session_pool.sysdba_privilege)
#define GET_ENABLE_SYSDBA_LOGIN (g_instance->session_pool.enable_sysdba_login)
#define GET_ENABLE_SYS_REMOTE_LOGIN (g_instance->session_pool.enable_sys_remote_login)
#define GET_ENABLE_SYSDBA_REMOTE_LOGIN (g_instance->session_pool.enable_sysdba_remote_login)
#define GET_SHARED_LOCKS_MGR (&g_instance->slk_mgr)
#define GET_ADVISORY_LOCKS_MGR (&g_instance->alk_mgr)                 /* for advisory lock */
#define GET_SESSION_SLOCKS_MGR (&g_instance->session_slk_mgr)         /* for session shared lock */
#define GET_SESSION_WAIT_LOCK_MGR (&g_instance->session_waitlock_mgr) /* for session waitlock lock */
#define GET_TRANS_SLOCKS_MGR (&g_instance->trans_slk_mgr)             /* for transaction shared lock */
#define GET_TRANS_WAIT_LOCK_MGR (&g_instance->trans_waitlock_mgr)     /* for transaction waitlock */
#define IS_SSL_ENABLED (g_instance->ssl_acceptor_fd != NULL)
#define AGENT_STACK_SIZE (g_instance->attr.stack_size)
#define USE_NATIVE_DATATYPE (g_instance->attr.using_naive_datatype)
#define IS_CASE_INSENSITIVE (g_instance->kernel.attr.enable_upper_case_names)
#define GET_HBA_CTX (&g_instance->session_pool.hba_ctx)
#define SHUTDOWN_WAIT_INTERVAL 1000
#define GET_CONFIG (&g_instance->config)
#define IS_ZTRST_INSTANCE (g_instance->is_ztrst_instance)
#define GET_CHARSET_ID (g_instance->kernel.db.ctrl.core.charset_id)
#define GET_DATABASE_CHARSET (&(CM_CHARSET_FUNC(GET_CHARSET_ID)))
#define GET_RSRC_MGR (&g_instance->rsrc_mgr)
#define GET_PL_MGR (&g_instance->sql.pl_mngr)
#define IS_LOG_OUT(session)                                                                          \
    ((session)->knl_session.killed || (g_instance->shutdown_ctx.phase != SHUTDOWN_PHASE_NOT_BEGIN && \
        g_instance->shutdown_ctx.mode != SHUTDOWN_MODE_NORMAL))
#define MIN_NODE_POOL_SIZE (g_instance->conn_pool_info.min_pool_size + g_instance->attr.priv_connection)
#define MAX_NODE_POOL_SIZE (g_instance->conn_pool_info.max_pool_size + g_instance->attr.priv_connection)
#define DISABLE_VPEEK (g_instance->attr.disable_var_peek)
#define PMA_POOL (&g_instance->sga.pma)
#define HASH_PAGES_HOLD (g_instance->sql.hash_pages_hold)
#define HASH_AREA_SIZE (g_instance->sql.hash_area_size)
#define sql_pool (g_instance->sql.pool)
#define buddy_mem_pool (&g_instance->sga.buddy_pool)
#define IS_COMPATIBLE_MYSQL_INST (g_instance->kernel.attr.compatible_mysql == 1)
#define IS_SQL_SERVER_INITIALIZING (g_instance->kernel.is_sql_server_initializing == 1)

extern instance_t *g_instance;
extern char *g_database_home;
status_t srv_instance_startup(db_startup_phase_t phase, bool32 is_coordinator, bool32 is_datanode, bool32 is_gts);
status_t srv_stop_all_session(shutdown_context_t *ctx);
status_t srv_shutdown(session_t *session, shutdown_mode_t mode);
status_t srv_instance_loop(void);
bool32 srv_is_kernel_reserve_session(session_type_e type);
void srv_instance_destroy(void);
void srv_instance_abort(void);
status_t srv_sysdba_privilege(void);
status_t srv_backup_keyfile(char *event);
status_t srv_update_server_masterkey(void);
void srv_shutdown_dn_sockets(session_t *sess);
bool32 is_instance_startuped(void);
#define MAX_KERNEL_ROW_SIZE (g_instance->kernel.attr.max_row_size)
void srv_destory_session(void);
atomic32_t rsrc_active_sess_inc(session_t *session);
atomic32_t rsrc_active_sess_dec(session_t *session);
void rsrc_cpu_time_add(session_t *session, uint64 value);
void rsrc_queue_length_inc(session_t *session);
void rsrc_queue_length_dec(session_t *session);
void rsrc_queue_total_inc(session_t *session);
void srv_thread_exit(thread_t *thread, session_t *session);
status_t srv_shutdown_wait(session_t *session, shutdown_mode_t mode, shutdown_context_t *ctx);
void srv_unlock_db(void);
#ifdef __cplusplus
}
#endif

#endif
