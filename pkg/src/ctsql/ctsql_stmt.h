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
 * ctsql_stmt.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/ctsql_stmt.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_STMT_H__
#define __SQL_STMT_H__
#include "cm_base.h"
#include "cm_defs.h"
#include "cm_stack.h"
#include "cm_date.h"
#include "cm_vma.h"
#include "cm_spinlock.h"
#include "cm_list.h"
#include "var_inc.h"
#include "cs_protocol.h"
#include "srv_session.h"
#include "srv_agent.h"
#include "cm_lex.h"
#include "ctsql_context.h"
#include "knl_interface.h"
#include "cm_partkey.h"
#include "cm_log.h"
#include "cm_error.h"

#ifdef Z_SHARDING
// for online update
typedef enum en_stmt_check_status {
    STMT_CHECK_STATUS_ERR = 0,
    STMT_CHECK_STATUS_PASS = 1,
    STMT_CHECK_STATUS_NOT_PASS = 2,
} stmt_check_status;

typedef enum en_shd_exec_type {
    SHD_EXEC_FOR_VALUE,
    SHD_EXEC_FOR_COND,
    SHD_EXEC_INTERNAL,
} shd_exec_type_e;

typedef struct st_shd_exec_info {
    void *columns_src; // columns value source when exec COLUMN type of node.
    shd_exec_type_e exec_type;
    galist_t *succ_node_ids;
} shd_exec_info_t;

#define MAX_FROZEN_TIME_US (60 * 1000 * 1000)
#define TIME_US (1000 * 1000)

#endif

#ifdef __cplusplus
extern "C" {
#endif

status_t do_commit(session_t *session);
void do_rollback(session_t *session, knl_savepoint_t *savepoint);

typedef enum en_stmt_status {
    STMT_STATUS_FREE = 0,
    STMT_STATUS_IDLE,
    STMT_STATUS_PREPARED,
    STMT_STATUS_EXECUTING,
    STMT_STATUS_EXECUTED,
    STMT_STATUS_FETCHING,
    STMT_STATUS_FETCHED,
#ifdef Z_SHARDING
    STMT_STATUS_PRE_PARAMS, // preprocessed params in CN
#endif
} stmt_status_t;

typedef enum en_lang_type {
    LANG_INVALID = 0,
    LANG_DML = 1,
    LANG_DCL = 2,
    LANG_DDL = 3,
    LANG_PL = 4,
    LANG_EXPLAIN = 5,
} lang_type_t;

typedef struct st_sql_lob_info {
    id_list_t list;     // virtual memory page list for lob
    uint32 inuse_count; // only lob_inuse_count is 0 can do free lob_list when
                        // sql_release_resource with force(false)
} sql_lob_info_t;

typedef struct st_sql_lob_info1 {
    id_list_t pre_list;  // virtual memory page list for prepare lob this time in lob write
    id_list_t exec_list; // virtual memory page list for execute lob this time in sql process
    bool8 pre_expired;   // pre_list of lob is used in sql process and then it is expired
    uint8 reversed[3];
} sql_lob_info_ex_t;

#ifdef Z_SHARDING
typedef struct st_shd_lob_info {
    uint32 size;
    uint32 offset;
    char *buf; // for bind lob
} shd_lob_info_t;

typedef struct st_shd_stmt_data {
    object_list_t remote_curs;
    bool32 is_multi_shard;

    bool32 exec_expr;
    knl_dictionary_t *curr_dc;
    sql_table_t *sql_table;
    shd_exec_info_t exec_info;
    node_slot_stmt_t *slot_stmt_list[M_NODE_POOL_COUNT]; // for lob read&write
    shd_lob_info_t lob_info;
    char *dist_ddl_sql;
    bool32 is_random_cal;
} shd_stmt_data_t;

typedef struct st_shd_retry_assist {
    bool8 in_trans;
    uint32 retry_times;
    uint32 recv_pack_offset;
    uint32 send_head_size;
} shd_retry_assist_t;
#endif

typedef struct st_sql_param {
    uint8 direction;
    uint8 unused[3];
    variant_t *out_value;
    variant_t value;
} sql_param_t;

typedef struct st_sql_seq {
    var_seq_t seq;
    uint32 flags;
    bool32 processed;
    int64 value;
} sql_seq_t;


typedef struct st_cursor_attr {
    uint64 rrs_sn; // dedicate a return cursor unique
    bool8 is_returned;
    bool8 is_forcur;
    uint8 type;
    bool8 sql_executed;
    bool8 has_fetched;
    bool8 reverify_in_fetch; // true in fetch sys_refcursor(DBE_SQL.RETURN_CURSOR), it's important
                             // to send a parsed stmt that UNKNOWN TYPE-PARAMs have been specified.
    uint16 unused2;
    char *param_types; // points to param types of cursor's pl-variant in vmc
    char *param_buf;   // points to param data of cursor's pl-variant in vmc
} cursor_info_t;

typedef struct st_default_info {
    bool32 default_on;
    variant_t *default_values;
} default_info_t;

typedef struct st_param_info {
    sql_param_t *params;    // stmt params from cm_push and points to received packet or kept vmc memory
    char *param_types;      // points to param types of received packet or kept vmc memory
    char *param_buf;        // points to param data of received packet or kept vmc memory
    uint32 outparam_cnt;    // count of outparams
    uint16 paramset_size;   // count of batch
    uint16 paramset_offset; // offset of row in batch
    uint32 param_offset;    // record offset to decode params data of param_buf
    uint32 param_strsize;   // record total size of string type in params for read kept params
} param_info_t;

typedef struct st_first_exec_info {
    char *first_exec_buf;
    variant_t *first_exec_vars;  // count of first execution vars depends on context->fexec_vars_cnt
    uint32 fexec_buff_offset;    // used to alloca memory for var-length datatypes
    variant_t **first_exec_subs; // record first execution subquery results for multiple executions
} first_exec_info_t;

#define GET_VM_CTX(stmt) ((stmt)->vm_ctx)
#define F_EXEC_VARS(stmt) ((stmt)->fexec_info.first_exec_vars)
#define F_EXEC_VALUE(stmt, node) (&(stmt)->fexec_info.first_exec_vars[NODE_OPTMZ_IDX(node)])

typedef struct st_sql_stmt {
    session_t *session;     // owner session
    spinlock_t stmt_lock;   // for modify context
    uint8 rs_type;          // rs_type_t
    uint8 plsql_mode;       // PLSQL_NONE
    uint8 lang_type;        // lang_type_t
    uint8 merge_type;       // merge_type_t
    sql_context_t *context; // current sql memory
    void *pl_context;       // only for pl create
    vmc_t vmc;
    struct st_plan_node *rs_plan;
    cs_execute_ack_t *exec_ack;
    uint32 exec_ack_offset;
    uint32 fetch_ack_offset;

    date_t last_sql_active_time; // last execute sql return result time of stmt
    knl_scn_t query_scn;         // query scn for current stmt
    uint64 ssn;                  // sql sequence number in session used for temporary table visibility judgment.
    uint32 xact_ssn;             // sql sequence number in transaction, in sub-stmt we force increase this whether
    knl_scn_t gts_scn;
    knl_scn_t sync_scn;

    // we are in transaction or not in order to distinguish stmt and its sub-stmt.
    object_list_t sql_curs;
    object_list_t knl_curs;

    char *in_param_buf; // refer to in subquery bind parameters in variant area
    variant_t *unsinkable_params;

    /* object_stack */
    object_stack_t cursor_stack; // for executing
    object_stack_t ssa_stack;    // for parsing, sub-select array
    object_stack_t node_stack;

    galist_t vmc_list; // record all vmc allocated for query
    uint16 status;     // stmt status(free/idle/prepared/executed/fetch/pre_params)
    uint16 id;         // stmt id

    mtrl_context_t mtrl;
    row_assist_t ra;
    uint64 serial_value; // for CT_TYPE_SERIAL
    uint32 batch_rows;  // number of rows in a batch
    uint32 total_rows;
    uint32 prefetch_rows;
    uint32 allowed_batch_errs;
    uint32 actual_batch_errs;
    union {
        sql_lob_info_t lob_info;
        sql_lob_info_ex_t lob_info_ex;
    };
    knl_column_t *default_column; // for default key word, insert into values(default), update set = default
    uint32 gts_offset;
    uint32 pairs_pos; // for insert some values or update pairs(0)

    /* for procedure */
    void *pl_compiler;
    void *pl_exec;
    galist_t *pl_ref_entry;                  // dependent PL objects dc during actual execution
    galist_t *trigger_list;                  // check trigger if has been checked privilege before
    void *parent_stmt;                       // parent stmt of current stmt in pl
    char pl_set_schema[CT_NAME_BUFFER_SIZE]; // saved schema value that set in procedure.

    /* flags */
    bool32 eof : 1; // query result fetch over or dml execute over
    bool32 return_generated_key : 1;
    bool32 is_sub_stmt : 1;
    bool32 in_parse_query : 1;
    bool32 chk_priv : 1;
    bool32 mark_pending_done : 1;
    bool32 is_check : 1;
    bool32 resource_inuse : 1;
    bool32 need_send_ddm : 1;
    bool32 is_success : 1; // stmt execute result
    bool32 is_batch_insert : 1;
    bool32 is_explain : 1;
    bool32 auto_commit : 1;
    bool32 is_srvoutput_on : 1;
    bool32 pl_failed : 1;
    bool32 params_ready : 1; // flags whether stmt->param_info.params is ready, for print
    bool32 dc_invalid : 1;   // flags whether dc is invalid when execute
    bool32 is_reform_call : 1;
    bool32 is_verifying : 1;
    bool32 is_temp_alloc : 1;
    bool32 trace_disabled : 1; // when exists serveroutput/returnresult, don't support autotrace
    bool32 context_refered : 1;
    bool32 is_var_peek : 1;
    bool32 has_pl_ref_dc : 1;
    bool32 hide_plan_extras : 1; // if hide plan extra information for printing, such as cost/rows/pridicate/outline
    bool32 reversed : 7;

    /* record sysdate/systimestamp/sequence of stmt */
    date_t v_sysdate;
    date_t v_systimestamp;
    int32 tz_offset_utc;
    sql_seq_t *v_sequences;

    cursor_info_t cursor_info;

    default_info_t default_info;
    first_exec_info_t fexec_info; // for first execution optimized
    param_info_t param_info;
    vm_stat_t vm_stat;               // vm pages statistical info
    void *hash_views;                // for in condition optimized by hash table
    void *withass;                   // list of materialized withas context (withas_mtrl_ctx_t)
    void *vm_view_ctx_array;         // array of materialized vm view context
    knl_cursor_t *direct_knl_cursor; // kernel cursor to calculate function index column and check
    int32 text_shift; // if is_reform_call is true, param offset need text_shift
    void *sort_par;
    date_t *plan_time; // record execution time of each plan
    uint32 plan_cnt;
    ctx_stat_t *stat;
    void *into;
    vm_lob_id_t *vm_lob_ids;
    galist_t *outlines; // record applied outlines
    pvm_context_t vm_ctx;
    vm_context_data_t vm_ctx_data;
    struct st_hash_mtrl_ctx **hash_mtrl_ctx_list;
    uint16 gdv_mode;   // for gdv: in sql_execute_select, do not return the ruslt set.
    uint16 gdv_unused; // for gdv
    bilist_t ddl_def_list;
} sql_stmt_t;

typedef enum en_cursor_type {
    USER_CURSOR = 0,
    PL_FORK_CURSOR = 1,
    PL_EXPLICIT_CURSOR = 2,
    PL_IMPLICIT_CURSOR = 3,
} cursor_type_t;

#define SQL_UNINITIALIZED_DATE CT_INVALID_INT64
#define SQL_UNINITIALIZED_TSTAMP CT_INVALID_INT64

#define SQL_CURSOR_STACK_DEPTH(stmt) ((stmt)->cursor_stack.depth)

#define CTSQL_ROOT_CURSOR(stmt) ((struct st_sql_cursor *)(stmt)->cursor_stack.items[0])
#define CTSQL_CURR_CURSOR(stmt)                                                                                 \
    (((struct st_sql_cursor *)OBJ_STACK_CURR(&(stmt)->cursor_stack))->connect_data.cur_level_cursor == NULL ? \
        (struct st_sql_cursor *)OBJ_STACK_CURR(&(stmt)->cursor_stack) :                                       \
        ((struct st_sql_cursor *)OBJ_STACK_CURR(&(stmt)->cursor_stack))->connect_data.cur_level_cursor)
#define SQL_CURSOR_PUSH(stmt, cursor) obj_stack_push(&(stmt)->cursor_stack, cursor)
#define SQL_CURSOR_POP(stmt) (void)obj_stack_pop(&(stmt)->cursor_stack)

// SSA subselect array
#define CTSQL_CURR_SSA(stmt) ((sql_array_t *)OBJ_STACK_CURR(&(stmt)->ssa_stack))
#define SQL_SSA_PUSH(stmt, ar) obj_stack_push(&(stmt)->ssa_stack, ar)
#define SQL_SSA_POP(stmt) (void)obj_stack_pop(&(stmt)->ssa_stack)

// parent query
#define CTSQL_CURR_NODE(stmt) (stmt)->node_stack.depth > 0 ? ((sql_query_t *)OBJ_STACK_CURR(&(stmt)->node_stack)) : NULL
#define SQL_NODE_PUSH(stmt, node) obj_stack_push(&(stmt)->node_stack, (node))
#define SQL_NODE_POP(stmt) (void)obj_stack_pop(&(stmt)->node_stack)

#define SET_NODE_STACK_CURR_QUERY(stmt, query)                                                  \
    sql_query_t *__save_query__ = (stmt)->node_stack.depth == 0 ? NULL : CTSQL_CURR_NODE((stmt)); \
    do {                                                                                        \
        if ((stmt)->node_stack.depth == 0) {                                                    \
            CT_RETURN_IFERR(SQL_NODE_PUSH((stmt), (query)));                                    \
        } else {                                                                                \
            (stmt)->node_stack.items[(stmt)->node_stack.depth - 1] = (query);                   \
        }                                                                                       \
    } while (0)
#define SQL_RESTORE_NODE_STACK(stmt)                      \
    do {                                                  \
        if (__save_query__ == NULL) {                     \
            (stmt)->node_stack.depth = 0;                 \
        } else {                                          \
            (stmt)->node_stack.items[0] = __save_query__; \
            (stmt)->node_stack.depth = 1;                 \
        }                                                 \
    } while (0)

#define SAVE_AND_RESET_NODE_STACK(stmt)                                                         \
    sql_query_t *__save_query__ = (stmt)->node_stack.depth == 0 ? NULL : CTSQL_CURR_NODE((stmt)); \
    do {                                                                                        \
        (stmt)->node_stack.depth = 0;                                                           \
    } while (0)

#define SRV_SESSION(stmt) ((stmt)->session)
#define KNL_SESSION(stmt) (&(stmt)->session->knl_session)
#define LEX(stmt) ((stmt)->session->lex)

#define AUTOTRACE_ON(stmt) ((stmt)->session->knl_session.autotrace)
#define NEED_TRACE(stmt)                                                                              \
    (AUTOTRACE_ON(stmt) && (stmt)->plsql_mode == PLSQL_NONE && (stmt)->context->type < CTSQL_TYPE_DML_CEIL && \
        !(stmt)->is_explain)
#ifndef TEST_MEM

static inline uint32 sql_stack_remain_size(sql_stmt_t *stmt)
{
    uint32 remain_size = stmt->session->stack->push_offset - stmt->session->stack->heap_offset;
    return remain_size > CT_MIN_KERNEL_RESERVE_SIZE ? (remain_size - CT_MIN_KERNEL_RESERVE_SIZE) : 0;
}

static inline status_t sql_push(sql_stmt_t *stmt, uint32 size, void **ptr)
{
    uint32 actual_size, last_offset;
    cm_stack_t *stack = stmt->session->stack;

    actual_size = CM_ALIGN8(size) + CT_PUSH_RESERVE_SIZE;
    *ptr = stack->buf + stack->push_offset - actual_size + CT_PUSH_RESERVE_SIZE;

    if (stack->push_offset < (uint64)stack->heap_offset + CT_MIN_KERNEL_RESERVE_SIZE + actual_size) {
        *ptr = NULL;
        CT_THROW_ERROR(ERR_STACK_OVERFLOW);
        return CT_ERROR;
    }
    last_offset = stack->push_offset;
    stack->push_offset -= actual_size;
    *(uint32 *)(stack->buf + stack->push_offset + CT_PUSH_OFFSET_POS) = last_offset;

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    /* set magic number */
    *(uint32 *)(stack->buf + stack->push_offset) = STACK_MAGIC_NUM;
#endif

    return CT_SUCCESS;
}
#else
static inline status_t sql_push(sql_stmt_t *stmt, uint32 size, void **ptr)
{
    *ptr = cm_push(stmt->session->stack, size);

    if (*ptr == NULL) {
        CT_THROW_ERROR(ERR_STACK_OVERFLOW);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}
#endif // TEST_MEM

static inline status_t sql_push_textbuf(sql_stmt_t *stmt, uint32 size, text_buf_t *txtbuf)
{
    if (sql_push(stmt, size, (void **)&txtbuf->str) != CT_SUCCESS) {
        return CT_ERROR;
    }

    txtbuf->len = 0;
    txtbuf->max_size = size;

    return CT_SUCCESS;
}

static inline const nlsparams_t *sql_get_session_nlsparams(const sql_stmt_t *stmt)
{
    return &(stmt->session->nls_params);
}

#define SESSION_NLS(stmt) sql_get_session_nlsparams(stmt)

static inline const timezone_info_t sql_get_session_timezone(const sql_stmt_t *stmt)
{
    return cm_get_session_time_zone(SESSION_NLS(stmt));
}

static inline void sql_session_nlsparam_geter(const sql_stmt_t *stmt, nlsparam_id_t id, text_t *text)
{
    const nlsparams_t *nls = SESSION_NLS(stmt);
    nls->param_geter(nls, id, text);
}

status_t sql_stack_alloc(void *sql_stmt, uint32 size, void **ptr); // with memset_s
status_t sql_get_serial_cached_value(sql_stmt_t *stmt, text_t *username, text_t *tbl_name, int64 *val);

#define CTSQL_SAVE_STACK(stmt) CM_SAVE_STACK((stmt)->session->stack)
#define CTSQL_RESTORE_STACK(stmt) CM_RESTORE_STACK((stmt)->session->stack)
#define CTSQL_POP(stmt) cm_pop((stmt)->session->stack)

static inline void sql_keep_stack_variant(sql_stmt_t *stmt, variant_t *var)
{
    cm_keep_stack_variant(stmt->session->stack, var_get_buf(var));
}

/* * To keep  a variant with STRING or BINARY type into stack for later using */
#ifndef TEST_MEM
static inline bool8 sql_var_cankeep(sql_stmt_t *stmt, variant_t *var)
{
    cm_stack_t *stack = NULL;
    char *buf = NULL;
    uint32 len;

    if (var->is_null) {
        return CT_TRUE;
    }

    if (CT_IS_VARLEN_TYPE(var->type)) {
        buf = var->v_text.str;
        len = var->v_text.len;
    } else if (CT_IS_LOB_TYPE(var->type)) {
        if (var->v_lob.type == CT_LOB_FROM_KERNEL) {
            buf = (char *)var->v_lob.knl_lob.bytes;
            len = var->v_lob.knl_lob.size;
        } else if (var->v_lob.type == CT_LOB_FROM_NORMAL) {
            buf = var->v_lob.normal_lob.value.str;
            len = var->v_lob.normal_lob.value.len;
        } else {
            return CT_TRUE;
        }
    } else {
        return CT_TRUE;
    }

    if (len == 0) {
        return CT_FALSE;
    }

    stack = stmt->session->stack;
    return buf > (char *)stack->buf && buf <= (char *)stack->buf + stack->size;
}

#else
static inline bool8 sql_var_cankeep(sql_stmt_t *stmt, variant_t *var)
{
    cm_stack_t *stack = NULL;
    char *buf = NULL;
    uint32 len;

    if (var->is_null) {
        return CT_TRUE;
    }

    if (CT_IS_VARLEN_TYPE(var->type)) {
        buf = var->v_text.str;
        len = var->v_text.len;
    } else if (CT_IS_LOB_TYPE(var->type)) {
        if (var->v_lob.type == CT_LOB_FROM_KERNEL) {
            buf = (char *)var->v_lob.knl_lob.bytes;
            len = var->v_lob.knl_lob.size;
        } else if (var->v_lob.type == CT_LOB_FROM_NORMAL) {
            buf = var->v_lob.normal_lob.value.str;
            len = var->v_lob.normal_lob.value.len;
        } else {
            return CT_TRUE;
        }
    } else {
        return CT_TRUE;
    }

    if (len == 0) {
        return CT_FALSE;
    }

    stack = stmt->session->stack;
    for (uint32 i = 0; i < CT_MAX_TEST_STACK_DEPTH && stack->stack_addr[i] != NULL; i++) {
        if (buf == stack->stack_addr[i]) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

#endif // TEST_MEM

static inline void sql_keep_stack_var(void *stmt, variant_t *var)
{
    sql_keep_stack_variant((sql_stmt_t *)stmt, var);
}

void sql_init_stmt(session_t *session, sql_stmt_t *stmt, uint32 stmt_id);
status_t sql_alloc_stmt(session_t *session, sql_stmt_t **statement);
void sql_free_stmt(sql_stmt_t *stmt);
void sql_set_scn(sql_stmt_t *stmt);
void sql_set_ssn(sql_stmt_t *stmt); // SSN = SQL SEQUENCE NUMBER
status_t sql_parse_job(sql_stmt_t *stmt, text_t *sql, source_location_t *loc);
status_t sql_reparse(sql_stmt_t *stmt);
status_t sql_prepare(sql_stmt_t *stmt);
status_t sql_init_pl_ref_dc(sql_stmt_t *stmt);
status_t sql_init_trigger_list(sql_stmt_t *stmt);
status_t sql_execute(sql_stmt_t *stmt);
status_t sql_execute_directly(session_t *session, text_t *sql, sql_type_t *type, bool32 check_priv);
status_t sql_execute_directly2(session_t *session, text_t *sql);
void sql_release_context(sql_stmt_t *stmt);
status_t sql_get_table_value(sql_stmt_t *stmt, var_column_t *v_col, variant_t *value);
status_t sql_check_ltt_dc(sql_stmt_t *stmt);
void sql_free_vmemory(sql_stmt_t *stmt);
void sql_log_param_change(sql_stmt_t *stmt, text_t sql);
void sql_unlock_lnk_tabs(sql_stmt_t *stmt);

status_t sql_prepare_for_multi_sql(sql_stmt_t *stmt, text_t *sql);
status_t sql_convert_data2variant(sql_stmt_t *stmt, char *ptr, uint32 len, uint32 is_null, variant_t *value);

static inline bool32 sql_is_invalid_rowid(const rowid_t *rid, knl_dict_type_t dc_type)
{
    if (dc_type == DICT_TYPE_TABLE || dc_type == DICT_TYPE_TABLE_NOLOGGING) {
        return IS_INVALID_ROWID(*rid);
    }

    return IS_INVALID_TEMP_TABLE_ROWID(rid);
}
status_t sql_init_sequence(sql_stmt_t *stmt);
void *sql_get_plan(sql_stmt_t *stmt);
status_t sql_get_rowid(sql_stmt_t *stmt, var_rowid_t *rowid, variant_t *value);
status_t sql_get_rownodeid(sql_stmt_t *stmt, var_rowid_t *rowid, variant_t *value);
status_t sql_get_rowscn(sql_stmt_t *stmt, var_rowid_t *rowid, variant_t *value);
status_t sql_get_rownum(sql_stmt_t *stmt, variant_t *value);
void sql_release_resource(sql_stmt_t *stmt, bool32 is_force);
void sql_release_lob_info(sql_stmt_t *stmt);
void sql_mark_lob_info(sql_stmt_t *stmt);
void sql_prewrite_lob_info(sql_stmt_t *stmt);
void sql_preread_lob_info(sql_stmt_t *stmt);
void sql_convert_column_t(knl_column_t *column, knl_column_def_t *col_def);
id_list_t *sql_get_exec_lob_list(sql_stmt_t *stmt);
id_list_t *sql_get_pre_lob_list(sql_stmt_t *stmt);
status_t sql_keep_params(sql_stmt_t *stmt);
status_t sql_read_kept_params(sql_stmt_t *stmt);
status_t sql_read_dynblk_params(sql_stmt_t *stmt);
status_t sql_keep_first_exec_vars(sql_stmt_t *stmt);
status_t sql_load_first_exec_vars(sql_stmt_t *stmt);
status_t sql_read_params(sql_stmt_t *stmt);
status_t sql_fill_null_params(sql_stmt_t *stmt);
status_t sql_prepare_params(sql_stmt_t *stmt);
status_t sql_load_scripts(knl_handle_t handle, const char *file_name, bool8 is_necessary);
void sql_init_session(session_t *sess);
status_t sql_write_lob(sql_stmt_t *stmt, lob_write_req_t *req);
status_t sql_read_lob(sql_stmt_t *stmt, void *locator, uint32 offset, void *buf, uint32 size, uint32 *read_size);
status_t sql_check_lob_vmid(id_list_t *vm_list, vm_pool_t *vm_pool, uint32 vmid);
status_t sql_alloc_object_id(sql_stmt_t *stmt, int64 *id);
status_t sql_extend_lob_vmem(sql_stmt_t *stmt, id_list_t *list, vm_lob_t *vlob);
status_t sql_row_put_lob(sql_stmt_t *stmt, row_assist_t *ra, uint32 lob_locator_size, var_lob_t *v_lob);
status_t sql_row_set_lob(sql_stmt_t *stmt, row_assist_t *ra, uint32 lob_locator_size, var_lob_t *lob, uint32 col_id);
status_t sql_row_set_array(sql_stmt_t *stmt, row_assist_t *ra, variant_t *val, uint16 col_id);
bool32 sql_send_check_is_full(sql_stmt_t *stmt);
void sql_init_sender(session_t *session);
status_t sql_send_result_success(session_t *session);
status_t sql_send_result_error(session_t *session);
void sql_init_sender_row(sql_stmt_t *stmt, char *buf, uint32 size, uint32 column_count); // for materialize
status_t sql_send_parsed_stmt(sql_stmt_t *stmt);
status_t sql_send_exec_begin(sql_stmt_t *stmt);
void sql_send_exec_end(sql_stmt_t *stmt);
status_t sql_send_import_rows(sql_stmt_t *stmt);
status_t sql_send_fetch_begin(sql_stmt_t *stmt);
void sql_send_fetch_end(sql_stmt_t *stmt);
status_t sql_send_row_entire(sql_stmt_t *stmt, char *row, bool32 *is_full);
status_t sql_send_row_begin(sql_stmt_t *stmt, uint32 column_count);
status_t sql_send_row_end(sql_stmt_t *stmt, bool32 *is_full);
status_t sql_send_column_null(sql_stmt_t *stmt, uint32 type);
status_t sql_send_column_uint32(sql_stmt_t *stmt, uint32 val);
status_t sql_send_column_int32(sql_stmt_t *stmt, int32 val);
status_t sql_send_column_int64(sql_stmt_t *stmt, int64 val);
status_t sql_send_column_real(sql_stmt_t *stmt, double val);
status_t sql_send_column_date(sql_stmt_t *stmt, date_t val);
status_t sql_send_column_ts(sql_stmt_t *stmt, date_t val);
status_t sql_send_column_tstz(sql_stmt_t *stmt, timestamp_tz_t *val);
status_t sql_send_column_tsltz(sql_stmt_t *stmt, timestamp_ltz_t val);
status_t sql_send_column_str(sql_stmt_t *stmt, char *str);
status_t sql_send_column_text(sql_stmt_t *stmt, text_t *text);
status_t sql_send_column_bin(sql_stmt_t *stmt, binary_t *binary);
status_t sql_send_column_decimal(sql_stmt_t *stmt, dec8_t *dec);
status_t sql_send_column_decimal2(sql_stmt_t *stmt, dec8_t *dec);
status_t sql_send_column_array(sql_stmt_t *stmt, var_array_t *val);
status_t sql_send_column_lob(sql_stmt_t *stmt, var_lob_t *val);
#define sql_send_column_ysintvl sql_send_column_int32
#define sql_send_column_dsintvl sql_send_column_int64
status_t sql_send_serveroutput(sql_stmt_t *stmt, text_t *output);
status_t sql_send_outparams(sql_stmt_t *stmt);
status_t sql_send_return_result(sql_stmt_t *stmt, uint32 stmt_id);
status_t sql_send_column_cursor(sql_stmt_t *stmt, cursor_t *cur);
status_t sql_send_return_values(sql_stmt_t *stmt, ct_type_t type, typmode_t *typmod, variant_t *val);
void sql_send_column_def(sql_stmt_t *stmt, void *sql_cursor);
status_t sql_remap(sql_stmt_t *stmt, text_t *sql);
void sql_release_sql_map(sql_stmt_t *stmt);

status_t sql_send_nls_feedback(sql_stmt_t *stmt, nlsparam_id_t id, text_t *value);
status_t sql_send_session_tz_feedback(sql_stmt_t *stmt, timezone_info_t client_timezone);

status_t sql_stack_safe(sql_stmt_t *stmt);
status_t sql_execute_check(knl_handle_t handle, text_t *sql, bool32 *exist);
status_t sql_check_exist_cols_type(sql_stmt_t *stmt, uint32 col_type, bool32 *exist);
status_t sql_get_array_from_knl_lob(sql_stmt_t *stmt, knl_handle_t locator, vm_lob_t *v_lob);
status_t sql_get_array_vm_lob(sql_stmt_t *stmt, var_lob_t *var_lob, vm_lob_t *vm_lob);
void sql_free_array_vm(sql_stmt_t *stmt, uint32 entry_vmid, uint32 last_vmid);
status_t sql_row_put_inline_array(sql_stmt_t *stmt, row_assist_t *ra, var_array_t *v, uint32 real_size);
status_t sql_convert_to_array(sql_stmt_t *stmt, variant_t *v, typmode_t *mode, bool32 apply_mode);
status_t sql_convert_to_collection(sql_stmt_t *stmt, variant_t *v, void *pl_coll);
status_t sql_compare_array(sql_stmt_t *stmt, variant_t *v1, variant_t *v2, int32 *result);
status_t sql_row_put_array(sql_stmt_t *stmt, row_assist_t *ra, var_array_t *v);
status_t sql_var_as_array(sql_stmt_t *stmt, variant_t *v, typmode_t *mode);
status_t var_get_value_in_row(variant_t *var, char *buf, uint32 size, uint16 *len);
status_t add_to_trans_table_list(sql_stmt_t *stmt);
status_t sql_parse_check_from_text(knl_handle_t handle, text_t *cond_text, knl_handle_t entity,
    memory_context_t *memory, void **cond_tree);
status_t sql_parse_default_from_text(knl_handle_t handle, knl_handle_t dc_entity, knl_handle_t column,
    memory_context_t *memory, void **expr_tree, void **expr_update_tree, text_t parse_text);
status_t sql_verify_default_from_text(knl_handle_t handle, knl_handle_t column_handle, text_t parse_text);
status_t sql_alloc_mem_from_dc(void *mem, uint32 size, void **buf);
status_t sql_trace_dml_and_send(sql_stmt_t *stmt);
status_t sql_init_stmt_plan_time(sql_stmt_t *stmt);
void srv_increase_session_shard_dml_id(sql_stmt_t *stmt);
void srv_unlock_session_shard_dml_id(sql_stmt_t *stmt);
status_t sql_alloc_for_longsql_stat(sql_stmt_t *stmt);
status_t sql_alloc_context(sql_stmt_t *stmt);
status_t sql_send_parsed_stmt_normal(sql_stmt_t *stmt, uint16 columnCount);

#define my_sender(stmt) ((stmt)->session->sender)
#define SET_STMT_CONTEXT(stmt, ctx)             \
    do {                                        \
        cm_spin_lock(&(stmt)->stmt_lock, NULL); \
        (stmt)->context = (ctx);                \
        cm_spin_unlock(&(stmt)->stmt_lock);     \
    } while (0)

#define SET_STMT_PL_CONTEXT(stmt, pl_ctx)       \
    do {                                        \
        cm_spin_lock(&(stmt)->stmt_lock, NULL); \
        (stmt)->pl_context = (void *)(pl_ctx);  \
        cm_spin_unlock(&(stmt)->stmt_lock);     \
    } while (0)

static inline void sql_reset_sequence(sql_stmt_t *stmt)
{
    if (stmt->v_sequences == NULL) {
        return;
    }
    for (uint32 i = 0; i < stmt->context->sequences->count; ++i) {
        stmt->v_sequences[i].processed = CT_FALSE;
    }
}

static inline status_t sql_compare_diff_variant(sql_stmt_t *stmt, variant_t *left, variant_t *right, cmp_rule_t *rule,
    char *buf, int32 *result)
{
    text_buf_t buffer;
    CM_INIT_TEXTBUF(&buffer, CT_CONVERT_BUFFER_SIZE, buf);
    CT_RETURN_IFERR(var_convert(SESSION_NLS(stmt), left, rule->cmp_type, &buffer));
    CT_RETURN_IFERR(var_convert(SESSION_NLS(stmt), right, rule->cmp_type, &buffer));
    return var_compare_same_type(left, right, result);
}

static inline status_t sql_compare_variant(sql_stmt_t *stmt, variant_t *v1, variant_t *v2, int32 *result)
{
    char *buf = NULL;
    variant_t *left = NULL;
    variant_t *right = NULL;

    if (v1->is_null) {
        *result = 1;
        return CT_SUCCESS;
    } else if (v2->is_null) {
        *result = -1;
        return CT_SUCCESS;
    }

    if (v1->type == v2->type) {
        return var_compare_same_type(v1, v2, result);
    }

    if (v1->type == CT_TYPE_ARRAY || v2->type == CT_TYPE_ARRAY) {
        return sql_compare_array(stmt, v1, v1, result);
    }

    cmp_rule_t *rule = get_cmp_rule((ct_type_t)v1->type, (ct_type_t)v2->type);
    if (rule->cmp_type == INVALID_CMP_DATATYPE) {
        CT_SET_ERROR_MISMATCH(v1->type, v2->type);
        return CT_ERROR;
    }

    if (rule->same_type) {
        return var_compare_same_type(v1, v2, result);
    }

    CTSQL_SAVE_STACK(stmt);
    sql_keep_stack_variant(stmt, v1);
    sql_keep_stack_variant(stmt, v2);

    if (sql_push(stmt, sizeof(variant_t), (void **)&left) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    if (sql_push(stmt, sizeof(variant_t), (void **)&right) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    *left = *v1;
    *right = *v2;

    if (sql_push(stmt, CT_CONVERT_BUFFER_SIZE, (void **)&buf) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    status_t status = sql_compare_diff_variant(stmt, left, right, rule, buf, result);
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

static inline status_t sql_convert_variant(sql_stmt_t *stmt, variant_t *v, ct_type_t type)
{
    if (v->is_null) {
        v->type = type;
        return CT_SUCCESS;
    }

    CT_RETVALUE_IFTRUE((v->type == type), CT_SUCCESS);

    if (!CT_IS_BUFF_CONSUMING_TYPE(type) || CT_IS_BINSTR_TYPE2(v->type, type)) {
        return var_convert(SESSION_NLS(stmt), v, type, NULL);
    }

    // only buffer consuming datatype needs to alloc memory
    text_buf_t buffer;

    CTSQL_SAVE_STACK(stmt);

    sql_keep_stack_variant(stmt, v);
    if (sql_push_textbuf(stmt, CT_CONVERT_BUFFER_SIZE, &buffer) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    if (var_convert(SESSION_NLS(stmt), v, type, &buffer) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    CTSQL_RESTORE_STACK(stmt);
    return CT_SUCCESS;
}

static inline status_t sql_convert_variant2(sql_stmt_t *stmt, variant_t *v1, variant_t *v2)
{
    if (v1->is_null) {
        v1->type = v2->type;
        return CT_SUCCESS;
    }

    CT_RETVALUE_IFTRUE((v1->type == v2->type), CT_SUCCESS);

    if (!CT_IS_BUFF_CONSUMING_TYPE(v2->type) || CT_IS_BINSTR_TYPE2(v1->type, v2->type)) {
        return var_convert(SESSION_NLS(stmt), v1, v2->type, NULL);
    }

    // only buffer consuming datatype needs to alloc memory
    text_buf_t buffer;

    CTSQL_SAVE_STACK(stmt);

    sql_keep_stack_variant(stmt, v1);
    sql_keep_stack_variant(stmt, v2);
    if (sql_push_textbuf(stmt, CT_CONVERT_BUFFER_SIZE, &buffer) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    if (var_convert(SESSION_NLS(stmt), v1, v2->type, &buffer) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    CTSQL_RESTORE_STACK(stmt);
    return CT_SUCCESS;
}

static inline status_t sql_get_unnamed_stmt(session_t *session, sql_stmt_t **stmt)
{
    if (session->unnamed_stmt == NULL) {
        if (sql_alloc_stmt(session, &session->unnamed_stmt) != CT_SUCCESS) {
            return CT_ERROR;
        }
        session->unnamed_stmt->sync_scn = (*stmt)->sync_scn;
        session->unnamed_stmt->pl_exec = (*stmt)->pl_exec;
    }

    *stmt = session->unnamed_stmt;
    return CT_SUCCESS;
}
status_t sql_apply_typmode(variant_t *var, const typmode_t *type_mod, char *buf, bool32 is_truc);
// this function like sql_apply_typmode_bin(), can merge to one function ?
status_t sql_convert_bin(sql_stmt_t *stmt, variant_t *v, uint32 def_size);
status_t sql_convert_char(knl_session_t *session, variant_t *v, uint32 def_size, bool32 is_character);
status_t sql_part_put_number_key(variant_t *value, ct_type_t data_type, part_key_t *partkey, uint32 precision);
status_t sql_part_put_scan_key(sql_stmt_t *stmt, variant_t *value, ct_type_t data_type, part_key_t *partkey);
status_t sql_part_put_key(sql_stmt_t *stmt, variant_t *value, ct_type_t data_type, uint32 def_size, bool32 is_character,
    uint32 precision, int32 scale, part_key_t *partkey);
status_t sql_get_char_length(text_t *text, uint32 *characters, uint32 def_size);

// callback func for convert char
status_t sql_convert_char_cb(knl_handle_t session, text_t *text, uint32 def_size, bool32 is_char);

static inline void sql_rowid2str(const rowid_t *rowid, variant_t *result, knl_dict_type_t dc_type)
{
    uint32 offset;
    char *buf = result->v_text.str;

    if (dc_type == DICT_TYPE_TABLE || dc_type == DICT_TYPE_TABLE_NOLOGGING) {
        PRTS_RETVOID_IFERR(snprintf_s(buf, CT_MAX_ROWID_BUFLEN, CT_MAX_ROWID_STRLEN, "%04u", (uint32)rowid->file));
        offset = 4;

        PRTS_RETVOID_IFERR(
            snprintf_s(buf + offset, CT_MAX_ROWID_BUFLEN - offset, CT_MAX_ROWID_STRLEN, "%010u", (uint32)rowid->page));
        offset += 10;

        PRTS_RETVOID_IFERR(
            snprintf_s(buf + offset, CT_MAX_ROWID_BUFLEN - offset, CT_MAX_ROWID_STRLEN, "%04u", (uint32)rowid->slot));
        offset += 4;
        result->v_text.len = offset;
    } else {
        result->v_text.len = 0;
        cm_concat_fmt(&result->v_text, CT_MAX_ROWID_BUFLEN, "%010u", (uint32)rowid->vmid);
        cm_concat_fmt(&result->v_text, CT_MAX_ROWID_BUFLEN - result->v_text.len, "%08u", (uint32)rowid->vm_slot);
    }
}

static inline void sql_str2rowid(const char *str, rowid_t *rowid)
{
    errno_t ret;
    int32 fileid, pageid, slotid;

    ret = sscanf_s(str, "%04d%10d%04d", &fileid, &pageid, &slotid);
    if (ret == -1) {
        rowid->value = 0;
        return;
    }
    rowid->file = fileid;
    rowid->page = pageid;
    rowid->slot = slotid;
}

#define SQL_TYPE(stmt) (stmt)->context->type
#define IS_DDL(stmt) (SQL_TYPE(stmt) > CTSQL_TYPE_DCL_CEIL && SQL_TYPE(stmt) < CTSQL_TYPE_DDL_CEIL)
#define IS_DCL(stmt) (SQL_TYPE(stmt) > CTSQL_TYPE_DML_CEIL && SQL_TYPE(stmt) < CTSQL_TYPE_DCL_CEIL)

static inline status_t sql_text_concat_n_str(text_t *text, uint32 max_size, const char *str, uint32 size)
{
    if (size + text->len > max_size) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "extend star expr exceed buf size %d", max_size);
        return CT_ERROR;
    }
    cm_concat_n_string(text, max_size, str, size);
    return CT_SUCCESS;
}

status_t sql_check_trig_commit(sql_stmt_t *stmt);
status_t shd_check_route_flag(sql_stmt_t *stmt);
status_t sql_check_tables(sql_stmt_t *stmt, sql_context_t *ctx);
status_t check_table_in_trans(session_t *session);
bool32 shd_find_table_in_trans(session_t *session);
static inline void sql_inc_active_stmts(sql_stmt_t *stmt)
{
    if (stmt->cursor_info.type != PL_FORK_CURSOR) {
        stmt->session->active_stmts_cnt++;
    }
}

static inline void sql_dec_active_stmts(sql_stmt_t *stmt)
{
    if (stmt->cursor_info.type != PL_FORK_CURSOR) {
#if defined(DEBUG)
        CM_ASSERT(stmt->session->active_stmts_cnt > 0);
#endif
        stmt->query_scn = CT_INVALID_ID64;
        stmt->gts_scn = CT_INVALID_ID64;
        stmt->session->active_stmts_cnt--;
    }
}

static inline void sql_reset_first_exec_vars(sql_stmt_t *stmt)
{
    uint32 cnt = stmt->context->fexec_vars_cnt;

    stmt->fexec_info.fexec_buff_offset = 0;

    if (cnt == 0 || stmt->fexec_info.first_exec_vars == NULL) {
        return;
    }

    while (cnt-- > 0) {
        stmt->fexec_info.first_exec_vars[cnt].type = CT_TYPE_UNINITIALIZED;
        stmt->fexec_info.first_exec_vars[cnt].is_null = CT_TRUE;
    }
}

static inline void sql_set_stmt_check(void *stmt, knl_cursor_t *cursor, bool32 is_check)
{
    ((sql_stmt_t *)stmt)->is_check = (bool8)is_check;
    ((sql_stmt_t *)stmt)->direct_knl_cursor = cursor;
}

static inline void sql_init_mtrl_vmc(handle_t *mtrl)
{
    mtrl_context_t *ctx = (mtrl_context_t *)mtrl;
    session_t *session = (session_t *)ctx->session;
    vmc_init(&session->vmp, &ctx->vmc);
}

status_t sql_init_first_exec_info(sql_stmt_t *stmt);
status_t sql_stmt_clone(sql_stmt_t *src, sql_stmt_t *sql_dest);

// 120000000us = 120s * 1000 * 1000, OPTINFO log only valid for 120s, in case some user forgets to turn it off.
#define LOG_OPTINFO_ON(stmt) \
    ((stmt)->session->optinfo_enable && LOG_ON && (cm_monotonic_now() - (stmt)->session->optinfo_start < 120000000))

#define SQL_LOG_OPTINFO(stmt, format, ...)     \
    if (LOG_OPTINFO_ON(stmt)) {                \
        CT_LOG_OPTINFO(format, ##__VA_ARGS__); \
    }

static inline status_t sql_switch_schema_by_name(sql_stmt_t *stmt, text_t *new_user, saved_schema_t *schema)
{
    uint32 new_user_id;

    schema->switched_flag = stmt->session->switched_schema;
    stmt->session->switched_schema = CT_TRUE;
    schema->user_id = CT_INVALID_ID32;
    if (CM_IS_EMPTY(new_user) || cm_text_str_equal_ins(new_user, stmt->session->curr_schema)) {
        return CT_SUCCESS;
    }

    if (!knl_get_user_id(KNL_SESSION(stmt), new_user, &new_user_id)) {
        CT_SRC_THROW_ERROR(stmt->session->lex->loc, ERR_USER_NOT_EXIST, T2S(new_user));
        return CT_ERROR;
    }

    uint32 len = (uint32)strlen(stmt->session->curr_schema);
    MEMS_RETURN_IFERR(strncpy_s(schema->user, CT_NAME_BUFFER_SIZE, stmt->session->curr_schema, len));
    schema->user_id = stmt->session->curr_schema_id;

    CT_RETURN_IFERR(cm_text2str(new_user, stmt->session->curr_schema, CT_NAME_BUFFER_SIZE));
    stmt->session->curr_schema_id = new_user_id;
    return CT_SUCCESS;
}

static inline status_t sql_switch_schema_by_uid(sql_stmt_t *stmt, uint32 switch_uid, saved_schema_t *schema)
{
    uint32 curr_schema_id = stmt->session->curr_schema_id;
    text_t name;

    schema->switched_flag = stmt->session->switched_schema;
    stmt->session->switched_schema = CT_TRUE;
    schema->user_id = CT_INVALID_ID32;
    if (curr_schema_id == switch_uid) {
        return CT_SUCCESS;
    }
    if (knl_get_user_name(KNL_SESSION(stmt), switch_uid, &name) != CT_SUCCESS) {
        return CT_ERROR;
    }
    MEMS_RETURN_IFERR(
        strncpy_s(schema->user, CT_NAME_BUFFER_SIZE, stmt->session->curr_schema, strlen(stmt->session->curr_schema)));
    schema->user_id = stmt->session->curr_schema_id;

    CT_RETURN_IFERR(cm_text2str(&name, stmt->session->curr_schema, CT_NAME_BUFFER_SIZE));
    stmt->session->curr_schema_id = switch_uid;

    return CT_SUCCESS;
}

static inline void sql_restore_schema(sql_stmt_t *stmt, saved_schema_t *schema)
{
    stmt->session->switched_schema = schema->switched_flag;
    if (schema->user_id == CT_INVALID_ID32) {
        return;
    }

    errno_t errcode = strncpy_s(stmt->session->curr_schema, CT_NAME_BUFFER_SIZE, schema->user, strlen(schema->user));
    MEMS_RETVOID_IFERR(errcode);

    stmt->session->curr_schema_id = schema->user_id;
    return;
}

#define SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt)                          \
    do {                                                                  \
        sql_stmt_t *root_stmt = (stmt);                                   \
        while (root_stmt->parent_stmt != NULL) {                          \
            root_stmt = root_stmt->parent_stmt;                           \
        }                                                                 \
        CHECK_SESSION_VALID_FOR_RETURN(&root_stmt->session->knl_session); \
    } while (0)

static inline status_t sql_alloc_params_buf(sql_stmt_t *stmt)
{
    uint32 max_params = stmt->context->params->count;

    if (stmt->context->in_params != NULL) {
        max_params += stmt->context->in_params->count;
    }

    if (max_params == 0) {
        stmt->param_info.params = NULL;
        return CT_SUCCESS;
    }

    return sql_push(stmt, max_params * sizeof(sql_param_t), (void **)&stmt->param_info.params);
}

static inline status_t sql_clear_origin_sql(sql_stmt_t *stmt)
{
    return CT_SUCCESS;
}

static inline status_t sql_clear_origin_sql_if_error(sql_stmt_t *stmt, status_t status)
{
    if (status != CT_SUCCESS) {
        CT_RETURN_IFERR(sql_clear_origin_sql(stmt));
    }
    return CT_SUCCESS;
}

static inline bool32 sql_table_in_list(sql_array_t *table_list, uint32 table_id)
{
    sql_table_t *table = NULL;
    for (uint32 i = 0; i < table_list->count; ++i) {
        table = (sql_table_t *)sql_array_get(table_list, i);
        if (table->id == table_id) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

static inline void sql_inc_ctx_ref(sql_stmt_t *stmt, sql_context_t *context)
{
    if (context == NULL || stmt->context_refered) {
        return;
    }
    sql_context_inc_exec(context);
    stmt->context_refered = CT_TRUE;
}

static inline void sql_dec_ctx_ref(sql_stmt_t *stmt, sql_context_t *context)
{
    if (!stmt->context_refered) {
        return;
    }
    sql_context_dec_exec(context);
    stmt->context_refered = CT_FALSE;
}
typedef enum en_mutate_table_type {
    SINGLE_TABLE,
    ALL_TABLES,
    UPD_TABLES,
    DEL_TABLES
} mutate_table_type_t;

typedef struct st_mutate_table_assist {
    mutate_table_type_t type;
    uint32 table_count;
    union {
        sql_table_t *table;
        galist_t *tables;
    };
} mutate_table_assist_t;
void sql_reset_plsql_resource(sql_stmt_t *stmt);
#ifdef __cplusplus
}
#endif

#endif
