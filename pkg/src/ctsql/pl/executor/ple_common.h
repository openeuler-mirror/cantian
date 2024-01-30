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
 * ple_common.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/executor/ple_common.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __PLE_COMMON_H__
#define __PLE_COMMON_H__

#include "ast.h"
#include "pl_dc_util.h"
#include "ple_coverage.h"
#include "srv_instance.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_ple_var {
    plv_decl_t *decl;
    variant_t value;
    typmode_t exec_type; // exec_type of value is used when pl is executing
    variant_t temp;      // for storing temporary data
} ple_var_t;

typedef struct st_ple_variant_array {
    uint32 count;
    ple_var_t **items;
} ple_varmap_t;

typedef struct ple_stack_anchor {
#ifdef TEST_MEM
    uint32 stack_depth;
#endif
    uint32 heap_offset;
    uint32 push_offset;
} ple_stack_anchor_t;

typedef struct st_ple_block {
    pl_line_ctrl_t *entry;
    ple_varmap_t var_map;
    ple_stack_anchor_t anchor;
    pl_exec_exception_t *curr_except;
} ple_block_t;

#define PLE_MAX_BLOCK_DEPTH (PL_MAX_BLOCK_DEPTH * 2)

typedef struct st_ple_block_stack {
    ple_block_t *items[PLE_MAX_BLOCK_DEPTH];
    uint16 depth;
} ple_block_stack_t;

// if insert then sql_cursor_t, if update then upd_object_t, if delete then null
// ":OLD.F1", update: knl_cursor_t, insert: NULL, delete: knl_cursor_t;
// ":NEW.F1", update: knl_update_info_t, insert: knl_cursor_t, delete: NULL
typedef struct st_trig_executor {
    uint32 trig_event;
    void *data;
    knl_cursor_t *knl_cur;
} trig_executor_t;

typedef struct st_cond_exec_stack {
    uint32 depth;
    uint32 items[PLE_MAX_BLOCK_DEPTH];
} cond_exec_stack_t;

#define COND_TRUE 1
#define COND_FALSE 0

#define CURR_COND_EXEC_DEPTH(exec) ((exec)->cond_exec.depth)
#define CURR_COND_EXEC(exec) \
    (((exec)->cond_exec.depth == 0) ? CT_INVALID_ID32 : (exec)->cond_exec.items[(exec)->cond_exec.depth - 1])
#define PUSH_COND_EXEC(cond, exec)                                    \
    do {                                                              \
        (exec)->cond_exec.items[(exec)->cond_exec.depth] = (cond);    \
        (exec)->cond_exec.depth++;                                    \
    } while (0)
#define POP_COND_EXEC(exec)                      \
    do {                                         \
        if ((exec)->cond_exec.depth > 0) {       \
            (exec)->cond_exec.depth--;           \
        }                                        \
    } while (0)
#define UPDATE_COND_EXEC(cond, exec)                                         \
    do {                                                                     \
        if ((exec)->cond_exec.depth > 0) {                                   \
            (exec)->cond_exec.items[(exec)->cond_exec.depth - 1] = (cond);   \
        }                                                                    \
    } while (0)

typedef struct st_selector_exec_stack {
    uint32 depth;
    variant_t *items[PLE_MAX_BLOCK_DEPTH];
} selector_exec_stack_t;

#define CURR_SELECTOR_EXEC_DEPTH(exec) ((exec)->selector_exec.depth)
#define CURR_SELECTOR_EXEC(exec) \
    (((exec)->selector_exec.depth == 0) ? NULL : (exec)->selector_exec.items[(exec)->selector_exec.depth - 1])
#define PUSH_SELECTOR_EXEC(var, exec)                                       \
    do {                                                                    \
        (exec)->selector_exec.items[(exec)->selector_exec.depth] = (var);   \
        (exec)->selector_exec.depth++;                                      \
    } while (0)
#define POP_SELECTOR_EXEC(exec)                     \
    do {                                            \
        if ((exec)->selector_exec.depth > 0) {      \
            (exec)->selector_exec.depth--;          \
        }                                           \
    } while (0)
#define UPDATE_SELECTOR_EXEC(var)                                             \
    do {                                                                      \
        if (exec->selector_exec.depth > 0) {                                  \
            exec->selector_exec.items[exec->selector_exec.depth - 1] = (var); \
        }                                                                     \
    } while (0)

/* NOTICE: add member should init it in function ple_init_executor() */
typedef struct st_pl_executor {
    ple_block_stack_t block_stack;
    uint32 stack_base; // current stack base
    pl_entity_t *entity;
    pl_line_ctrl_t *curr_line;
    pl_line_ctrl_t *start_line;
    trig_executor_t *trig_exec;
    cond_exec_stack_t cond_exec;         // when if/elsif/when_case it dedicate the last-calc result.
    selector_exec_stack_t selector_exec; // when switch case, to save the selector value
    source_location_t sql_loc;
    union {
        uint64 combine64;
        struct {
            uint32 is_raised : 1;    /* default 0 */
            uint32 sql_executed : 1; // when exec a sql, it's true
            uint32 err_buf_full : 1;
            uint32 err_stack_full : 1;
            uint32 err_except_acc : 1;
            uint32 is_dyncur : 1;
            uint32 error_tracked : 1;
            uint32 unused : 25;
            uint16 err_buf_pos;
            uint16 err_stack_pos;
        };
    };

    uint32 recent_rows; // the recent sql returned rows
    char err_buf[CT_MESSAGE_BUFFER_SIZE];
    char err_stack[CT_MESSAGE_BUFFER_SIZE];
    pl_exec_exception_t exec_except;
    uint32 return_cursor_stmt; // returned cursor stmt id, default:CT_INVALID_ID32
    ple_coverage_t *coverage;
    sql_stmt_t *dynamic_parent; // null unless execute in execute immediate, record stmt who execute dynamic sql
    union {
        galist_t *curr_input;   // null unless in plsql_cursor mode, record explicit/implicit/sysref cursor input
        galist_t *using_values; // null unless in plsql_cursor mode, record dynamic sysref cursor bound value
    };
    sql_array_t svpts;
    pl_line_begin_t *body;
    var_udo_t *obj;
} pl_executor_t;

typedef struct st_vbuf_assist {
    sql_stmt_t *stmt;
    uint32 id;
    uint32 *total_len;
    uint32 type;
} vbuf_assist_t;

ple_var_t *ple_get_plvar(pl_executor_t *executor, plv_id_t vid);
variant_t *ple_get_value(sql_stmt_t *stmt, plv_id_t vid);
status_t ple_get_output_plvar(pl_executor_t *exec, pl_into_t *into, ple_var_t **left, uint32 index);
status_t ple_get_dynsql_parent(sql_stmt_t *stmt, sql_stmt_t **parent);

status_t pl_init_sequence(sql_stmt_t *stmt);
status_t ple_init_executor(pl_executor_t *executor, sql_stmt_t *stmt);
status_t ple_prepare_pl_cursors(sql_stmt_t *stmt, bool8 *is_curs_prepare);

status_t ple_begin_auton_rm(session_t *session);
status_t ple_end_auton_rm(session_t *session);

void ple_send_error(sql_stmt_t *stmt);
void ple_set_error(sql_stmt_t *stmt, text_t *user, text_t *name, source_location_t *err_loc);
void ple_update_error_stack(sql_stmt_t *stmt, text_t *user, text_t *name, source_location_t *err_location);
void ple_check_error(sql_stmt_t *stmt);
void ple_update_exec_error(sql_stmt_t *stmt, source_location_t *err_location);
void ple_check_exec_error(sql_stmt_t *stmt, source_location_t *err_location);
void ple_update_func_error(sql_stmt_t *stmt, expr_node_t *node);

#define PLE_RESET_EXEC_ERR(exec)           \
    do {                                   \
        (exec)->err_stack_pos = 0;         \
        (exec)->err_buf_pos = 0;           \
        (exec)->err_buf_full = CT_FALSE;   \
        (exec)->err_stack_full = CT_FALSE; \
        (exec)->err_stack[0] = '\0';       \
        (exec)->err_buf[0] = '\0';         \
    } while (0)

#define PLE_MAX_CURSORS (g_instance->attr.open_cursors)

sql_stmt_t *ple_ref_cursor_get(sql_stmt_t *stmt, pl_cursor_slot_t *ref_cursor);
bool32 sql_is_pl_exec(sql_stmt_t *stmt);

#define PLE_DEFAULT_EXPR(v) (v)->decl->default_expr
#define PLE_CURR_BLOCK(exec) ((exec)->block_stack.items[(exec)->block_stack.depth - 1])

#define PLE_CHECK_NONE 0x0
#define PLE_CHECK_OUT 0x1
#define PLE_CHECK_IN 0x2

#define PLE_SAVE_STMT(stmt)                               \
    ack_sender_t *__sender__ = (stmt)->session->sender;   \
    sql_audit_t __audit__ = (stmt)->session->sql_audit;   \
    sql_stmt_t *__stmt__ = (stmt)->session->current_stmt; \
    CTSQL_SAVE_STACK(stmt);

#define PLE_RESTORE_STMT(stmt)                    \
    do {                                          \
        (stmt)->session->sender = __sender__;     \
        (stmt)->session->sql_audit = __audit__;   \
        (stmt)->session->current_stmt = __stmt__; \
        CTSQL_RESTORE_STACK(stmt);                  \
    } while (0)

#define PLE_CURSOR_SLOT_GET(v) ((pl_cursor_slot_t *)((v)->value.v_cursor.ref_cursor))
#define PLV_IS_COMPLEX_TYPE(type) \
    ((type) == PLV_RECORD || (type) == PLV_COLLECTION || (type) == PLV_OBJECT || (type) == PLV_ARRAY)

status_t pl_check_trig_and_udf(sql_stmt_t *stmt);
status_t ple_copy_variant(sql_stmt_t *stmt, variant_t *src, variant_t *dst, typmode_t type);
status_t ple_move_value(sql_stmt_t *stmt, variant_t *right, ple_var_t *left);
void ple_cursor_dec_refcount(sql_stmt_t *stmt, variant_t *dst, bool32 is_free);
status_t ple_calc_object_dft(sql_stmt_t *stmt, plv_object_t *plv_obj, variant_t *value);
status_t ple_calc_record_dft(sql_stmt_t *stmt, plv_record_t *plv_record, variant_t *value);
status_t ple_calc_dft(sql_stmt_t *stmt, ple_var_t *var);
status_t ple_calc_param_dft(sql_stmt_t *stmt, ple_var_t *var);
status_t ple_push_decl_element(sql_stmt_t *stmt, galist_t *decl_list, ple_varmap_t *var_map, bool32 calc_dft);
status_t ple_get_dynsql_using_expr(sql_stmt_t *stmt, uint32 pnid, pl_using_expr_t **using_expr);
status_t ple_get_using_expr_var(sql_stmt_t *stmt, pl_using_expr_t *using_expr, ple_var_t **var, uint32 flag);
status_t ple_get_using_expr_value(sql_stmt_t *stmt, pl_using_expr_t *using_expr, variant_t *res, uint32 flag);
status_t ple_get_dynsql_param_dir(sql_stmt_t *stmt, uint32 id, uint32 *dir);
bool32 ple_get_curr_except(pl_executor_t *exec, pl_exec_exception_t **curr_except);
void ple_save_stack_anchor(sql_stmt_t *stmt, ple_stack_anchor_t *anchor);
status_t ple_push_block(sql_stmt_t *stmt, pl_line_ctrl_t *entry, ple_varmap_t *var_map, ple_stack_anchor_t anchor);
void ple_close_cursor(sql_stmt_t *stmt, pl_cursor_slot_t *ref_cursor);
status_t ple_check_rollback(pl_executor_t *exec, text_t *svpt, source_location_t *loc);
status_t ple_store_savepoint(sql_stmt_t *stmt, pl_executor_t *exec, text_t *svpt);
status_t ple_fork_stmt(sql_stmt_t *stmt, sql_stmt_t **sub_stmt);
status_t ple_fork_executor_core(sql_stmt_t *stmt, sql_stmt_t *sub_stmt);
void ple_pop_block(sql_stmt_t *stmt, pl_executor_t *exec);
void ple_inherit_substmt_error(sql_stmt_t *stmt, sql_stmt_t *sub_stmt);

#ifdef __cplusplus
}
#endif

#endif