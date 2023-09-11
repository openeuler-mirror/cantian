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
 * srv_session.h
 *
 *
 * IDENTIFICATION
 * src/server/srv_session.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SRV_SESSION_H__
#define __SRV_SESSION_H__

#include "cm_defs.h"
#include "cs_pipe.h"
#include "cs_protocol.h"
#include "cs_packet.h"
#include "cm_atomic.h"
#include "cm_spinlock.h"
#include "cm_list.h"
#include "cm_stack.h"
#include "cm_lex.h"
#include "knl_interface.h"
#include "knl_session.h"
#include "cm_queue.h"
#include "repl_arch_fetch.h"
#include "cm_encrypt.h"
#include "cm_nls.h"
#include "cm_hba.h"
#include "cm_pbl.h"
#include "cm_vma.h"
#include "cms_interface.h"
#include "cm_hash.h"
#include "cm_hashmap.h"
#include "tse_list.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SESSION_TIME_ZONE(sess) (((int64)((sess)->nls_params.client_timezone)) * 60 * 1000000)
#define EXTEND_SQL_CURS_EACH_TIME (g_instance->attr.sql_cursors_each_sess * 10)
#define SESSION_STMT_EXT_STEP 4
#define SESSION_STMT_EXT_MAX (uint32)(16384 / 4)

typedef struct st_object_stack {
    uint32 depth;
    pointer_t items[GS_MAX_OBJECT_STACK_DEPTH];
} object_stack_t;

#define OBJ_STACK_RESET(stack) \
    {                          \
        (stack)->depth = 0;    \
    }
#define OBJ_STACK_CURR(stack) (stack)->items[(stack)->depth - 1]

static inline status_t obj_stack_push(object_stack_t *stack, pointer_t obj)
{
    if (stack->depth < GS_MAX_OBJECT_STACK_DEPTH) {
        stack->items[stack->depth] = obj;
        stack->depth++;
        return GS_SUCCESS;
    }

    GS_THROW_ERROR(ERR_OBJECT_STACK_OVERDEPTH);
    return GS_ERROR;
}

static inline void obj_stack_pop(object_stack_t *stack)
{
    if (stack->depth > 0) {
        stack->depth--;
    }
}

typedef enum en_session_type {
    SESSION_TYPE_BACKGROUND = 1,
    SESSION_TYPE_USER = 2,
    SESSION_TYPE_AUTONOMOUS = 3,
    SESSION_TYPE_REPLICA = 4,
    SESSION_TYPE_SQL_PAR = 5,
    SESSION_TYPE_JOB = 6,
    SESSION_TYPE_EMERG = 7,
    SESSION_TYPE_KERNEL_PAR = 8,
    SESSION_TYPE_DTC = 9,
    SESSION_TYPE_KERNEL_RESERVE = 10,
} session_type_e;

struct st_sql_stmt;
struct st_session;

typedef enum en_session_status {
    SESSION_STATUS_OK = 0,
    SESSION_STATUS_LOGOUT = 1,
    SESSION_STATUS_CANCELED = 2,
    SESSION_STATUS_AUTH_FAILED = 3,
} session_status_t;

/*
 * store the base the stack this thread.
 */
typedef char *stack_base_t;

typedef enum {
    AUTH_STATUS_NONE,
    AUTH_STATUS_PROTO, // proto code checked
    AUTH_STATUS_CONN,  // handshake done
    AUTH_STATUS_INIT,  // auth init done
    AUTH_STATUS_LOGON  // logon done
} auth_status_t;

typedef enum {
    REMOTE_CONN_APP = 0,
    REMOTE_CONN_COORD = 1
} remote_conn_type_t;

typedef struct st_interactive_info {
    bool32 is_on;
    bool32 is_timeout;
    date_t response_time;
} interactive_info_t;

typedef struct st_saved_schema {
    char user[GS_NAME_BUFFER_SIZE];
    uint32 user_id;
    bool32 switched_flag;
} saved_schema_t;

typedef struct st_saved_tenant {
    char name[GS_TENANT_BUFFER_SIZE];
    uint32 id;
} saved_tenant_t;

typedef enum {
    CUR_RES_FREE = 0,
    CUR_RES_INUSE = 1,
} cur_res_type_t;

typedef struct st_pl_cursor_slot {
    uint8 state; // dedicate cursor state , free or inuse, cur_res_type_t
    uint8 unused;
    uint16 stmt_id;   // state is inuse and except 0xFFFF, it carry the alloc stmt id.
    uint32 ref_count; // dedicate the cursor slot is ref by how many variant cursor
} pl_cursor_slot_t;

typedef enum en_param_status {
    PARAM_INIT = 0,
    PARAM_OFF = 1,
    PARAM_ON = 2,
} param_status_t;

/* DON'T change the following value */
typedef enum en_withas_mode {
    WITHAS_OPTIMIZER = 0,
    WITHAS_MATERIALIZE = 1,
    WITHAS_INLINE = 2,
    WITHAS_UNSET = 3,
} withas_mode_t;

typedef struct st_load_data_def {
    int32 load_data_tmp_file_fp;
    char *full_file_name;
    char *sql_load_seq_suffix;
    char *table_name;
} load_data_info_t;

// cbo parameter of session
typedef struct st_cbo_param {
    uint32 cbo_index_caching;
    uint32 cbo_index_cost_adj;
} cbo_param_t;

typedef struct st_tse_context {
    tse_list_node_t node; // 该成员必须放在第一个位置
    uint32_t tse_magic_num;
    text_t user;
    text_t table;
    knl_dictionary_t *dc;
    uint8 dup_key_slot;   // for on duplicate key update
    rowid_t conflict_rid; // for on duplicate key update
    uint32_t tse_inst_id;
    rowid_t row_id;
} tse_context_t;
typedef struct st_session {
    knl_session_t knl_session; // need to be first!
    spinlock_t kill_lock;
    uint8 type;        // session_type_e
    uint8 client_kind; // client_kind_t
    uint8 proto_type;  // cantian or mysql (not realized) protocol_type_t
    uint8 auth_status; // auth_status_t
    bool8 priv;
    bool8 priv_upgrade; // if set this to true, when return the session, should set the priv to false and this too
    uint16 reserved;

    cs_pipe_t pipe_entity; // if pipe info specified when create a session, pointer pipe will point to
    // if pipe info specified when create a session, it will point to pipe_entity, otherwise null assigned
    cs_pipe_t *pipe;
    char os_prog[GS_FILE_NAME_BUFFER_SIZE];
    char os_host[GS_HOST_NAME_BUFFER_SIZE];
    char os_user[GS_NAME_BUFFER_SIZE];
    char db_user[GS_NAME_BUFFER_SIZE];
    char curr_schema[GS_NAME_BUFFER_SIZE];   // set by 'ALTER SESSION set current_schema=schema'. default : curr_user
    char curr_tenant[GS_TENANT_BUFFER_SIZE]; // set by 'ALTER SESSION set tenant=tenant_name'. default : TENANT$ROOT
    char curr_user2[GS_NAME_BUFFER_SIZE];
    uint32 curr_schema_id;
    uint32 curr_user2_id;
    uint32 curr_tenant_id;
    date_t logon_time;
    date_t interval_time;
    ack_sender_t *sender; // execution result sender
    text_t curr_user;     // point to db_user
    uint32 stmts_cnt;
    cm_stack_t *stack; // Memory recycled when a execution is end
    list_t stmts;
    uint32 active_stmts_cnt;
    spinlock_t sess_lock; // for modify stmts/current_sql
    text_t current_sql;
    uint32 sql_id;
    uint32 prev_sql_id;

    lex_t *lex;
    vmp_t vmp;
    vmp_t vms; // for cursor sharing memory manage
    object_pool_t sql_cur_pool;
    object_pool_t knl_cur_pool;
    nlsparams_t nls_params;

    struct st_sql_stmt *unnamed_stmt;
    struct st_sql_stmt *current_stmt;
    cs_packet_t *recv_pack;
    cs_packet_t *send_pack;
    struct st_agent *agent;
    struct st_reactor *reactor;
    // the order defined prev and next should not be changed,
    // so pointer of a session can be assigned to pointer of a biqueue_node_t as
    struct st_session *prev;   // for shared thread mode
    struct st_session *next;   // for shared thread mode
    struct st_session *parent; // for auton session
    void *pl_cursors;

    int32 rsrc_attr_id;
    date_t queued_time;       /* if queued, the start time the session has been queued,
                                if not queued, the value is 0. */
    interactive_info_t interactive_info;
    uint64 recent_foundrows; /* for the built-in function "FOUND_ROWS()" */

    uint32 client_version; /* client version */
    uint32 call_version;   /* client and server negotiated version */
    uchar challenge[GS_MAX_CHALLENGE_LEN * 2];
    uchar server_key[GS_HMAC256MAXSIZE];
    int64 last_insert_id;
    spinlock_t dbg_ctl_lock; // for write and read dbg_ctl
    uint64 rrs_sn; // for clean returned resultset when anonymous block broken by error occuring
    date_t optinfo_start;
    bool8 is_free;
    bool8 optinfo_enable;
    bool8 auto_commit;
    bool8 is_active;
    bool8 is_log_out;
    bool8 remote_as_sysdba;
    bool8 disable_soft_parse;
    bool8 prefix_tenant_flag;
    bool8 is_auth;
    bool8 triggers_disable;
    bool8 nologging_enable;
    bool8 switched_schema;
    bool8 is_reg; // hit sBit field thread insecure
                  // hit concurrency scenario:when session register the epool, set is_reg = true
                  // reactor receive first proto message, and set is_auth = false.
    bool8 unused[3];
    struct {
        param_status_t outer_join_optimization : 2;
        withas_mode_t withas_subquery : 2;
        param_status_t cursor_sharing : 2;
        param_status_t unused2 : 26;
    };
    uint32 plan_display_format;
    load_data_info_t load_data_info;
    cbo_param_t cbo_param;            // cbo parameter of session
    uint32 stmt_id;                   // for gdv
    uint32 stmt_session_id;           // for gdv
    bool32 stmt_valid;                // for gdv
    date_t gdv_last_time;             // for gdv
    cms_res_status_list_t res_status; // for gdv
    bool32 is_tse;
    uint32_t tse_inst_id;
    uint32_t tse_thd_id;
    uint32_t tse_magic_num;
    int64_t query_id;
    uint16_t total_cursor_num;
    spinlock_t map_lock;
    cm_oamap_t cursor_map;
} session_t;

typedef status_t (*proc_msg_t)(session_t *sess);
typedef void (*proc_msg2_t)(session_t *sess);

typedef struct st_cmd_handler {
    proc_msg_t func;
    proc_msg2_t func2;
} cmd_handler_t;

typedef struct st_session_set {
    uint32 count;
    session_t *first;
} session_set_t;

typedef struct st_session_pool {
    spinlock_t lock;
    biqueue_t idle_sessions;
    biqueue_t priv_idle_sessions;
    uint32 hwm; /* high water mark */
    uint32 max_sessions;
    uint32 expanded_max_sessions; /* up to max_sessions * 1.5 */
    session_t *sessions[GS_MAX_SESSIONS];
    atomic_t service_count;
    black_context_t pwd_black_ctx;
    white_context_t white_ctx;
    char sysdba_privilege[GS_SCRAM256MAXSTRSIZE + 4];
    bool32 enable_sysdba_login;
    bool32 enable_sys_remote_login;
    bool32 enable_sysdba_remote_login; // local connect without pw,remote connect use file pw
    uint32 unauth_session_expire_time;
    bool32 is_log;
    int epollfd; // process hang session
    mal_ip_context_t malicious_ip_ctx;
} session_pool_t;

typedef struct st_sql_par_stat {
    atomic_t parallel_executions;
    atomic_t under_trans_cnt;
    atomic_t res_limited_cnt;
    atomic_t break_proc_cnt;
} sql_par_stat_t;

typedef struct st_sql_par_pool {
    spinlock_t lock;
    uint32 max_sessions;
    uint32 used_sessions;
    session_t *sessions[GS_PARALLEL_MAX_THREADS];
    sql_par_stat_t par_stat;
} sql_par_pool_t;

typedef struct st_sql_cur_pool {
    spinlock_t lock;
    uint32 cnt;
    object_pool_t pool;
} sql_cur_pool_t;

/* * ALTSES_SET: alter session set type */
typedef enum en_altses_set_type {
    SET_COMMIT = 0,
    SET_LOCKWAIT_TIMEOUT,
    SET_NLS_PARAMS,
    SET_SCHEMA,
    SET_SESSION_TIMEZONE,
    SET_SHOW_EXPLAIN_PREDICATE,
    SET_SHD_SOCKET_TIMEOUT,
    SET_TENANT,
    SET_OUTER_JOIN_OPT,
    SET_CBO_INDEX_CACHING,
    SET_CBO_INDEX_COST_ADJ,
    SET_WITHAS_SUBQUERY,
    SET_CURSOR_SHARING,
    SET_PLAN_DISPLAY_FORMAT,
} altset_type_t;

/* * ALTSES_SET: SET parameter_name = parameter_value */
typedef struct st_altset_def {
    altset_type_t set_type;
    text_t pkey;                 /* parameter key */
    union {                      /* parameter value */
        knl_commit_def_t commit; /* *< for set commit */
        knl_lockwait_def_t lock_wait_timeout;
        nls_setting_def_t nls_seting; /* *< for setting NLS parameters */
        text_t curr_schema;           /* *< for current schema */
        text_t timezone_offset_name;  /* for time_zone */
        uint32 shd_socket_timeout;
        text_t tenant;             /* for tenant */
        bool32 on_off;             /* GS_TRUE:ON   GS_FALSE:OFF */
        uint32 cbo_index_caching;  /* for cbo_index_caching */
        uint32 cbo_index_cost_adj; /* for cbo_index_cost_adj */
        uint32 withas_subquery;    /* for _WITHAS_SUBQUERY */
        uint32 plan_display_format;
    };
} altset_def_t;

/* * ALTSES_ABLE: DISABLE | ENABLE parameter_name */
typedef enum en_altses_able_type {
    ABLE_TRIGGERS = 0,
    ABLE_INAV_TO = 1,
    ABLE_NOLOGGING = 2,
    ABLE_OPTINFO = 3,
} altable_type_t;

typedef struct st_altable_def {
    altable_type_t able_type;
    bool32 enable;
} altable_def_t;

/* * alter session type enumeration */
typedef enum en_altses_action {
    ALTSES_SET = 0,
    ALTSES_ADVISE = 1,
    ALTSES_CLOSE = 2,
    ALTSES_ENABLE = 3,
    ALTSES_DISABLE = 4,
    ALTSES_FORCE = 5,
} altses_action_t;

/* * alter session */
typedef struct st_altses_def {
    altses_action_t action;
    union {
        altset_def_t setting;
        altable_def_t setable;
    };
} alter_session_def_t;

typedef struct st_stat_list {
    uint32 count;
    uint16 first;
    uint16 last;
} stat_list_t;

typedef struct st_stat_pool {
    spinlock_t lock;
    uint32 hwm;
    uint32 capacity;
    uint32 page_count;
    char *pages[GS_MAX_STAT_PAGES];
    knl_stat_t *stats[GS_MAX_STATS];
    stat_list_t free_list;
} stat_pool_t;

#define SESSION_CLIENT_KIND(session) ((session)->client_kind)

#define SESSION_PIPE(sess) (&(sess)->pipe_entity)

#define SESSION_TCP_REMOTE(sess) (&(sess)->pipe_entity.link.tcp.remote)
#define SESSION_TCP_LOCAL(sess) (&(sess)->pipe_entity.link.tcp.local)

#define SESSION_UDS_REMOTE(sess) (&(sess)->pipe_entity.link.uds.remote)
#define SESSION_UDS_LOCAL(sess) (&(sess)->pipe_entity.link.uds.local)

/* the short-cut macros to access foundrows_info in session_t */
#define SESSION_GET_FOUND_COUNT(session) ((session)->recent_foundrows)

typedef struct st_sql_cursor sql_cursor_t;

status_t server_alloc_session(session_t **session, cs_pipe_t *pipe, session_type_e type);
status_t server_alloc_reserved_session(uint32 *sid);
status_t server_alloc_knl_session(bool32 knl_reserved, knl_handle_t *knl_session);
void server_release_knl_session(knl_handle_t sess);
status_t server_create_session(cs_pipe_t *pipe);
void server_release_session(session_t *session);
void server_deinit_session(session_t *session);
void server_return_session(session_t *session);
status_t server_new_session(cs_pipe_t *pipe, session_t **session);
void server_reset_session(session_t *session, cs_pipe_t *pipe);
status_t server_process_command(session_t *session);
status_t server_return_success(session_t *session);
status_t server_return_error(session_t *session);
bool32 server_whether_login_with_user(text_t *username);
bool32 server_session_in_trans(session_t *session);
status_t server_wait_all_session_be_killed(session_t *session);
void server_wait_all_session_free(void);
void server_kill_all_session(session_t *session, bool32 is_force);
status_t srv_reset_statistic(session_t *session);
void clean_open_curs(void *session_handle, uint64 lsn);
void clean_open_temp_curs(void *session_handle, void *temp_cache);
void invalidate_tablespaces(uint32 space_id);
void get_sess_min_local_scn(knl_session_t *knl_sess, knl_scn_t *local_scn);
void server_init_ip_white(void);
void server_init_pwd_black(void);
void server_init_ip_login_addr(void);
status_t server_read_packet(session_t *session);

status_t server_check_challenge(session_t *session, const char *rsp_str, uchar *pwd_cipher, uint32 *cipher_len);

status_t server_init_sql_cur_pools(void);
void server_mark_user_sess_killed(session_t *session, bool32 force, uint32 serial_id);
void server_expire_unauth_timeout_session(void);

status_t server_get_sql_text(uint32 sessionid, text_t *sql);
void srv_free_dbg_ctl(session_t *session);
status_t server_register_zombie_epoll(session_t *session);

void server_set_min_scn(knl_handle_t sess);

/* interface for resource group control */
void srv_detach_ctrl_group(session_t *session);
status_t srv_attach_ctrl_group(session_t *session);
void free_trans_table_resource(session_t *session);

void release_load_local_resource(session_t *session);
status_t sql_load_reset_fp_and_del_file(load_data_info_t *info);
void sql_load_free_data_info(session_t *session);
static inline void srv_mark_sess_killed(knl_handle_t knl_session, bool32 force, uint32 serial_id)
{
    session_t *session = (session_t *)knl_session;

    if (session->type == SESSION_TYPE_USER) {
        server_mark_user_sess_killed(session, force, serial_id);
    } else {
        session->knl_session.killed = GS_TRUE;
        session->knl_session.force_kill = force;
        GS_LOG_DEBUG_INF("mark session %d killed", session->knl_session.id);
    }
}

#define JOB_CHECK_SESSION_RETURN_ERROR(sess)                                               \
    do {                                                                                   \
        if ((sess)->type == SESSION_TYPE_JOB) {                                            \
            GS_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "Job not support interact whit client."); \
            return GS_ERROR;                                                               \
        }                                                                                  \
    } while (0)

status_t server_init_drbg(void);

#ifdef __cplusplus
}
#endif

#endif
