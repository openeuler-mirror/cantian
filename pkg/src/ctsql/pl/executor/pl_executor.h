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
 * pl_executor.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/executor/pl_executor.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_EXECUTOR_H__
#define __PL_EXECUTOR_H__

#include "ple_common.h"
#include "pl_dc_util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_ple_call_assist {
    uint32 type;
    uint32 arg_count;
    pl_dc_t *dc;
    pl_dc_t *body_dc;
    pl_entity_t *sub_pl_context;
    sql_stmt_t *stmt;
    sql_stmt_t *sub_stmt;
    galist_t *params;
    galist_t *decls;
    ple_varmap_t var_map;
    expr_tree_t *args;
    expr_node_t *node;
    pl_line_begin_t *begin_ln;
    variant_t *result;
    bool8 is_recursive;
    bool8 is_over_return;
    bool8 is_pending;
    bool8 is_top_exec;
    bool8 is_curs_prepare;
    bool8 is_exec_open;
    bool8 is_sub_error; // if sub exec has error info or not
    bool8 is_pkg;
    status_t status;
    bool32 new_page;
    saved_schema_t saved_schema;
    ple_stack_anchor_t anchor;
    sql_context_t *dyn_proc; // if is ltt proc, need alloc a new context when execute
    pl_source_pages_t source_pages;
} ple_call_assist_t;

status_t ple_exec_call(sql_stmt_t *stmt, expr_node_t *node, variant_t *res);
status_t ple_exec_anonymous_block(sql_stmt_t *stmt);
status_t ple_get_pl_attr(sql_stmt_t *stmt, expr_node_t *node, variant_t *res);
status_t ple_get_param_value(sql_stmt_t *stmt, uint32 param_id, uint32 pnid, variant_t *result);
status_t ple_keep_input(sql_stmt_t *stmt, pl_executor_t *exec, void *input, bool8 is_dyncur);
bool32 sql_send_get_node_function(sql_stmt_t *stmt, function_t **func);
#ifdef __cplusplus
}
#endif

#endif
