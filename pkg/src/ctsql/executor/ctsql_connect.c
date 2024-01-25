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
 * ctsql_connect.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_connect.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_connect.h"
#include "ctsql_select.h"
#include "ctsql_scan.h"
#include "srv_instance.h"
#include "ctsql_concate.h"
#include "ctsql_connect_mtrl.h"

static status_t sql_push_connect_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    if (cursor->connect_data.level > 1) {
        CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor->connect_data.last_level_cursor));
    }

    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));

    return CT_SUCCESS;
}

static void sql_pop_connect_cursor(sql_stmt_t *ctsql_stmt, sql_cursor_t *cursor)
{
    SQL_CURSOR_POP(ctsql_stmt);

    if (cursor->connect_data.level > 1) {
        SQL_CURSOR_POP(ctsql_stmt);
    }
}

/* only root cursor need init */
static status_t sql_init_connect_by_path(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    uint32 path_count;
    void *buf = NULL;
    cm_stack_t *path_stack = NULL;
    cursor->connect_data.path_func_nodes = plan->connect.path_func_nodes;

    path_count = cursor->connect_data.path_func_nodes->count;
    if (path_count > 0) {
        CT_RETURN_IFERR(
            vmc_alloc(&cursor->vmc, path_count * sizeof(cm_stack_t), (void **)&cursor->connect_data.path_stack));
    }

    for (uint32 i = 0; i < path_count; i++) {
        CT_RETURN_IFERR(vmc_alloc(&cursor->vmc, CT_MAX_ROW_SIZE, (void **)&buf));
        path_stack = cursor->connect_data.path_stack + i;
        cm_stack_init(path_stack, buf, CT_MAX_ROW_SIZE);
    }

    return CT_SUCCESS;
}

status_t sql_execute_connect(sql_stmt_t *stmt, sql_cursor_t *ctsql_cursor, plan_node_t *plan)
{
    if (ctsql_cursor->connect_data.level <= 1) {
        ctsql_cursor->connect_data.level = 1;
        ctsql_cursor->connect_data.first_level_rownum = 0;
        ctsql_cursor->connect_data.cur_level_cursor = NULL;
        ctsql_cursor->connect_data.first_level_cursor = ctsql_cursor;
        ctsql_cursor->connect_data.first_level_cursor->connect_data.prior_exprs = plan->connect.prior_exprs;
        CT_RETURN_IFERR(sql_init_connect_by_path(stmt, ctsql_cursor, plan));
    }

    if (ctsql_cursor->connect_data.next_level_cursor == NULL) {
        CT_RETURN_IFERR(sql_alloc_cursor(stmt, &ctsql_cursor->connect_data.next_level_cursor));
    }

    ctsql_cursor->connect_data.next_level_cursor->eof = CT_TRUE;
    ctsql_cursor->connect_data.next_level_cursor->scn = ctsql_cursor->scn;
    ctsql_cursor->connect_data.next_level_cursor->ancestor_ref = ctsql_cursor->ancestor_ref;
    ctsql_cursor->connect_data.next_level_cursor->connect_data.last_level_cursor = ctsql_cursor;
    ctsql_cursor->connect_data.next_level_cursor->connect_data.first_level_cursor =
        ctsql_cursor->connect_data.first_level_cursor;
    ctsql_cursor->connect_data.next_level_cursor->connect_data.level = ctsql_cursor->connect_data.level + 1;

    CT_RETURN_IFERR(sql_push_connect_cursor(stmt, ctsql_cursor));

    if (ctsql_cursor->connect_data.level == 1) {
        if (sql_execute_query_plan(stmt, ctsql_cursor, plan->connect.next_start_with) != CT_SUCCESS) {
            sql_pop_connect_cursor(stmt, ctsql_cursor);
            return CT_ERROR;
        }
    } else {
        if (sql_execute_query_plan(stmt, ctsql_cursor, plan->connect.next_connect_by) != CT_SUCCESS) {
            sql_pop_connect_cursor(stmt, ctsql_cursor);
            return CT_ERROR;
        }
    }

    sql_pop_connect_cursor(stmt, ctsql_cursor);

    return CT_SUCCESS;
}

static status_t sql_compare_prior_exprs(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_cursor_t *prev_cursor,
    bool32 *is_cycle)
{
    galist_t *prior_exprs = cursor->connect_data.first_level_cursor->connect_data.prior_exprs;
    expr_node_t *node = NULL;
    variant_t curr_value, prev_value;
    int32 cmp_result;
    sql_cursor_t *curr_cursor = NULL;
    CTSQL_SAVE_STACK(stmt);
    for (uint32 i = 0; i < prior_exprs->count; i++) {
        node = (expr_node_t *)cm_galist_get(prior_exprs, i);
        CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, prev_cursor));
        curr_cursor = prev_cursor->connect_data.cur_level_cursor;
        prev_cursor->connect_data.cur_level_cursor = prev_cursor;
        if (sql_exec_expr_node(stmt, node, &prev_value) != CT_SUCCESS) {
            SQL_CURSOR_POP(stmt);
            return CT_ERROR;
        }
        prev_cursor->connect_data.cur_level_cursor = curr_cursor;
        sql_keep_stack_variant(stmt, &prev_value);
        SQL_CURSOR_POP(stmt);
        CT_RETURN_IFERR(sql_exec_expr_node(stmt, node, &curr_value));
        if (prev_value.is_null && curr_value.is_null) {
            continue;
        }
        if (sql_compare_variant(stmt, &curr_value, &prev_value, &cmp_result) != CT_SUCCESS) {
            return CT_ERROR;
        }
        CTSQL_RESTORE_STACK(stmt);
        if (cmp_result != 0) {
            *is_cycle = CT_FALSE;
            return CT_SUCCESS;
        }
    }
    *is_cycle = prior_exprs->count == 0 ? CT_FALSE : CT_TRUE;
    CTSQL_RESTORE_STACK(stmt);
    return CT_SUCCESS;
}

static status_t sql_check_connect_by_iscycle(sql_stmt_t *stmt, sql_cursor_t *cursor, bool32 *is_cycle)
{
    sql_cursor_t *last_cursor = NULL;
    status_t status = CT_SUCCESS;
    *is_cycle = CT_FALSE;
    if (cursor->connect_data.level == 1) {
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));
    for (last_cursor = cursor; last_cursor->connect_data.last_level_cursor != NULL;
        last_cursor = last_cursor->connect_data.last_level_cursor) {
        if (sql_compare_prior_exprs(stmt, cursor, last_cursor->connect_data.last_level_cursor, is_cycle) !=
            CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }
        if (!(*is_cycle)) {
            continue;
        }
        if (!cursor->query->connect_by_nocycle) {
            CT_THROW_ERROR(ERR_CONNECT_BY_LOOP);
            status = CT_ERROR;
        }
        break;
    }
    SQL_CURSOR_POP(stmt);
    return status;
}

static status_t sql_fetch_connect_join_plan(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan,
    cond_tree_t *cond, bool32 *eof)
{
    bool32 is_found = CT_TRUE;

    for (;;) {
        SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt);

        CT_RETURN_IFERR(sql_fetch_join(stmt, cursor, plan, eof));

        if (*eof) {
            return CT_SUCCESS;
        }

        if (cond != NULL) {
            CT_RETURN_IFERR(sql_match_cond_node(stmt, cond->root, &is_found));
        }

        if (is_found) {
            return CT_SUCCESS;
        }
    }
}

static inline status_t sql_fetch_connect_plan_core(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan,
    cond_tree_t *cond, bool32 *eof)
{
    switch (plan->type) {
        case PLAN_NODE_SCAN:
            return sql_fetch_scan(stmt, cursor, plan, eof);

        case PLAN_NODE_JOIN:
            return sql_fetch_connect_join_plan(stmt, cursor, plan, cond, eof);

        case PLAN_NODE_CONCATE:
            return sql_fetch_concate(stmt, cursor, plan, eof);

        case PLAN_NODE_CONNECT_MTRL:
            return sql_fetch_connect_mtrl(stmt, cursor, plan, eof);

        default:
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Don't support plan, plan type = %u", (uint32)plan->type);
            return CT_ERROR;
    }
}

static inline status_t sql_fetch_connect_plan(sql_stmt_t *ctsql_stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    if (cursor->eof) {
        *eof = CT_TRUE;
        return CT_SUCCESS;
    }
    SQL_CHECK_SESSION_VALID_FOR_RETURN(ctsql_stmt);

    if (cursor->connect_data.level == 1) {
        return sql_fetch_connect_plan_core(ctsql_stmt, cursor, plan->connect.next_start_with, NULL, eof);
    } else {
        cond_tree_t *cond = plan->connect.connect_by_cond;
        return sql_fetch_connect_plan_core(ctsql_stmt, cursor, plan->connect.next_connect_by, cond, eof);
    }
}

static status_t sql_set_connect_by_iscycle(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    bool32 is_cycle = CT_FALSE;
    bool32 eof = CT_FALSE;
    sql_cursor_t *next_cursor = cursor->connect_data.next_level_cursor;

    CT_RETURN_IFERR(sql_open_query_cursor(stmt, next_cursor, cursor->query));

    CT_RETURN_IFERR(sql_execute_connect(stmt, next_cursor, plan));

    cursor->connect_data.connect_by_iscycle = CT_FALSE;

    for (;;) {
        CT_RETURN_IFERR(sql_push_connect_cursor(stmt, next_cursor));
        if (sql_fetch_connect_plan(stmt, next_cursor, plan, &eof) != CT_SUCCESS) {
            sql_pop_connect_cursor(stmt, next_cursor);
            return CT_ERROR;
        }
        sql_pop_connect_cursor(stmt, next_cursor);

        if (eof) {
            next_cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }

        CT_RETURN_IFERR(sql_check_connect_by_iscycle(stmt, next_cursor, &is_cycle));

        if (is_cycle) {
            cursor->connect_data.connect_by_iscycle = CT_TRUE;
            next_cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }
    }
}

static status_t sql_fetch_connect_one_record(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    bool32 is_cycle = CT_FALSE;
    uint32 rownum = cursor->connect_data.first_level_cursor->rownum;
    cursor->connect_data.connect_by_isleaf = CT_FALSE;
    cursor->connect_data.connect_by_iscycle = CT_FALSE;
    do {
        // set rownum for connect by cond match
        if (cursor->connect_data.level == 1) {
            cursor->rownum = cursor->connect_data.first_level_rownum;
        } else {
            cursor->rownum = cursor->connect_data.first_level_cursor->rownum + 1;
        }

        CT_RETURN_IFERR(sql_push_connect_cursor(stmt, cursor));
        if (sql_fetch_connect_plan(stmt, cursor, plan, &cursor->eof) != CT_SUCCESS) {
            sql_pop_connect_cursor(stmt, cursor);
            return CT_ERROR;
        }
        sql_pop_connect_cursor(stmt, cursor);

        // reset rownum for rs fetch
        cursor->rownum = rownum;

        if (cursor->eof) {
            return CT_SUCCESS;
        }

        if (!cursor->query->connect_by_prior) {
            break;
        }

        CT_RETURN_IFERR(sql_check_connect_by_iscycle(stmt, cursor, &is_cycle));
    } while (is_cycle);

    if (cursor->query->connect_by_iscycle && cursor->query->connect_by_prior &&
        sql_set_connect_by_iscycle(stmt, cursor, plan) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void sql_reset_connect_path(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    cm_stack_t *path_stack = NULL;
    sql_cursor_t *first_level_cursor = cursor->connect_data.first_level_cursor;
    uint32 path_cnt = first_level_cursor->connect_data.path_func_nodes->count;

    for (uint32 i = 0; i < path_cnt; i++) {
        path_stack = first_level_cursor->connect_data.path_stack + i;
        cm_pop(path_stack);
    }
}

static status_t sql_get_connect_path_args_value(sql_stmt_t *stmt, expr_node_t *func, variant_t *arg_var,
    variant_t *separator_var)
{
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    bool32 charset_type = CT_FALSE;
    int32 index = 0;

    arg1 = func->argument;
    arg2 = arg1->next;

    CT_RETURN_IFERR(sql_exec_expr_node(stmt, arg1->root, arg_var));
    CT_RETURN_IFERR(sql_convert_variant(stmt, arg_var, CT_TYPE_STRING));
    sql_keep_stack_var(stmt, arg_var);

    CT_RETURN_IFERR(sql_exec_expr_node(stmt, arg2->root, separator_var));
    CT_RETURN_IFERR(sql_convert_variant(stmt, separator_var, CT_TYPE_STRING));
    sql_keep_stack_var(stmt, separator_var);

    if (separator_var->is_null || separator_var->v_text.len == 0) {
        CT_SRC_THROW_ERROR_EX(arg2->root->loc, ERR_INVALID_SEPARATOR, T2S(&func->word.func.name));
        return CT_ERROR;
    }

    /* separator_var cannot be a substring of arg_var */
    if (!arg_var->is_null && arg_var->v_text.len != 0) {
        index = GET_DATABASE_CHARSET->instr(&arg_var->v_text, &separator_var->v_text, 1, 1, &charset_type);
        if (index > 0) {
            CT_THROW_ERROR_EX(ERR_INVALID_SEPARATOR, T2S(&func->word.func.name));
            return CT_ERROR;
        }
    }
    if (arg_var->is_null) {
        arg_var->v_text.len = 0;
    }
    return CT_SUCCESS;
}

static status_t sql_set_connect_path(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    status_t status = CT_SUCCESS;
    int32 ret;
    variant_t arg_var;
    variant_t separator_var;
    expr_node_t *func = NULL;
    text_t *buffer = NULL;
    cm_stack_t *path_stack = NULL;
    sql_cursor_t *first_level_cursor = cursor->connect_data.first_level_cursor;
    galist_t *path_func_nodes = first_level_cursor->connect_data.path_func_nodes;

    CTSQL_SAVE_STACK(stmt);
    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, first_level_cursor));
    for (uint32 i = 0; i < path_func_nodes->count; i++) {
        func = (expr_node_t *)cm_galist_get(path_func_nodes, i);
        status = sql_get_connect_path_args_value(stmt, func, &arg_var, &separator_var);
        CT_BREAK_IF_ERROR(status);

        path_stack = first_level_cursor->connect_data.path_stack + i;
        /* push separator & current path to stack. will be popped when the current node is leaf node */
        buffer = cm_push(path_stack, sizeof(text_t) + separator_var.v_text.len + arg_var.v_text.len);
        if (buffer == NULL) {
            CT_THROW_ERROR(ERR_VALUE_ERROR, "result string length is too long, beyond the max");
            status = CT_ERROR;
            break;
        }
        buffer->str = (char *)buffer + sizeof(text_t);
        buffer->len = separator_var.v_text.len + arg_var.v_text.len;
        ret = memcpy_s(buffer->str, buffer->len, separator_var.v_text.str, separator_var.v_text.len);
        if (ret != EOK) {
            status = CT_ERROR;
            CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
            break;
        }
        if (arg_var.v_text.len > 0) {
            ret = memcpy_s(buffer->str + separator_var.v_text.len, arg_var.v_text.len, arg_var.v_text.str,
                arg_var.v_text.len);
            if (ret != EOK) {
                status = CT_ERROR;
                CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
                break;
            }
        }
    }

    SQL_CURSOR_POP(stmt);
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

static status_t sql_fetch_connect_next_level(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    sql_cursor_t *next_cursor = cursor->connect_data.next_level_cursor;

    if (next_cursor->eof) {
        if (sql_open_query_cursor(stmt, next_cursor, cursor->query) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (sql_execute_connect(stmt, next_cursor, plan) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (sql_fetch_connect_one_record(stmt, next_cursor, plan) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (next_cursor->eof) {
        cursor->connect_data.connect_by_isleaf = CT_TRUE;
    }

    return CT_SUCCESS;
}

static status_t sql_fetch_connect_record(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    sql_cursor_t *next_cursor = cursor->connect_data.next_level_cursor;
    status_t status;

    if (sql_stack_safe(stmt) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!next_cursor->eof) {
        cursor->connect_data.first_level_cursor->connect_data.cur_level_cursor = next_cursor;
        if (sql_fetch_connect_next_level(stmt, next_cursor, plan) != CT_SUCCESS) {
            return CT_ERROR;
        }

        return sql_set_connect_path(stmt, next_cursor);
    }

    if (cursor->connect_data.connect_by_isleaf) {
        sql_reset_connect_path(stmt, cursor);
    }

    if (sql_fetch_connect_one_record(stmt, cursor, plan) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cursor->eof) {
        if (cursor->connect_data.last_level_cursor == NULL) {
            cursor->eof = (bool32)CT_FALSE;
            *eof = CT_TRUE;
            return CT_SUCCESS;
        }
        sql_reset_connect_path(stmt, cursor);
        return sql_fetch_connect_record(stmt, cursor->connect_data.last_level_cursor, plan, eof);
    }

    status = sql_fetch_connect_next_level(stmt, cursor, plan);
    cursor->connect_data.first_level_cursor->connect_data.cur_level_cursor = cursor;
    if (sql_set_connect_path(stmt, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return status;
}

status_t sql_fetch_connect(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    sql_cursor_t *first_level_cur = cursor->connect_data.first_level_cursor;
    sql_cursor_t *current_level_cur = first_level_cur->connect_data.cur_level_cursor;
    first_level_cur->connect_data.cur_level_cursor = NULL;
    if (current_level_cur == NULL) {
        current_level_cur = first_level_cur;
    }

    if (sql_fetch_connect_record(stmt, current_level_cur, plan, eof) != CT_SUCCESS) {
        return CT_ERROR;
    }

    current_level_cur = first_level_cur->connect_data.cur_level_cursor;
    if (current_level_cur != NULL) {
        current_level_cur->rownum = first_level_cur->rownum;
    }

    if (!*eof) {
        if (first_level_cur->connect_data.cur_level_cursor == NULL ||
            first_level_cur->connect_data.cur_level_cursor->connect_data.level >
            g_instance->sql.max_connect_by_level) {
            CT_THROW_ERROR(ERR_CONNECT_BY_LEVEL_MAX, g_instance->sql.max_connect_by_level);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t sql_execute_connect_hash(sql_stmt_t *stmt, sql_cursor_t *ctsql_cursor, plan_node_t *plan)
{
    ctsql_cursor->connect_data.level = 1;
    ctsql_cursor->connect_data.first_level_rownum = 0;
    ctsql_cursor->connect_data.cur_level_cursor = NULL;
    ctsql_cursor->connect_data.next_level_cursor = NULL;
    ctsql_cursor->connect_data.first_level_cursor = ctsql_cursor;
    ctsql_cursor->connect_data.prior_exprs = plan->connect.prior_exprs;
    CT_RETURN_IFERR(sql_init_connect_by_path(stmt, ctsql_cursor, plan));

    CT_RETURN_IFERR(sql_push_connect_cursor(stmt, ctsql_cursor));
    CT_RETURN_IFERR(sql_execute_query_plan(stmt, ctsql_cursor, plan->connect.next_start_with));
    sql_pop_connect_cursor(stmt, ctsql_cursor);
    return CT_SUCCESS;
}

static status_t sql_fetch_connect_hash_first(sql_stmt_t *stmt, sql_cursor_t *ctsql_cursor, plan_node_t *plan,
                                             bool32 *eof)
{
    uint32 rownum = ctsql_cursor->rownum;
    ctsql_cursor->connect_data.first_level_rownum++;
    ctsql_cursor->rownum = ctsql_cursor->connect_data.first_level_rownum;
    CT_RETURN_IFERR(sql_fetch_connect_plan_core(stmt, ctsql_cursor, plan->connect.next_start_with, NULL, eof));
    ctsql_cursor->rownum = rownum;
    if (!*eof) {
        ctsql_cursor->connect_data.cur_level_cursor = ctsql_cursor;
        return sql_execute_query_plan(stmt, ctsql_cursor, plan->connect.next_connect_by);
    }
    return CT_SUCCESS;
}

static status_t sql_fetch_connect_hash_plan(sql_stmt_t *stmt, sql_cursor_t *ctsql_cursor, plan_node_t *plan,
                                            bool32 *eof)
{
    bool32 level2_eof = CT_FALSE;

    if (ctsql_cursor->connect_data.next_level_cursor == NULL) {
        return sql_fetch_connect_hash_first(stmt, ctsql_cursor, plan, eof);
    } else {
        cond_tree_t *cond = plan->connect.connect_by_cond;
        CT_RETURN_IFERR(sql_fetch_connect_plan_core(stmt, ctsql_cursor, plan->connect.next_connect_by, cond, &level2_eof));
        if (level2_eof) {
            ctsql_cursor->connect_data.cur_level_cursor = NULL;
            ctsql_cursor->connect_data.next_level_cursor = NULL;
            CT_RETURN_IFERR(sql_fetch_connect_hash_first(stmt, ctsql_cursor, plan, eof));
        }
    }
    return CT_SUCCESS;
}

status_t sql_fetch_connect_hash(sql_stmt_t *stmt, sql_cursor_t *ctsql_cursor, plan_node_t *plan, bool32 *eof)
{
    SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt);
    if (ctsql_cursor->connect_data.cur_level_cursor != NULL &&
        ctsql_cursor->connect_data.cur_level_cursor->connect_data.connect_by_isleaf) {
        sql_reset_connect_path(stmt, ctsql_cursor);
    }
    CT_RETURN_IFERR(sql_fetch_connect_hash_plan(stmt, ctsql_cursor, plan, eof));

    if (!*eof) {
        if (ctsql_cursor->connect_data.cur_level_cursor == NULL ||
            ctsql_cursor->connect_data.cur_level_cursor->connect_data.level > g_instance->sql.max_connect_by_level) {
            CT_THROW_ERROR(ERR_CONNECT_BY_LEVEL_MAX, g_instance->sql.max_connect_by_level);
            return CT_ERROR;
        }
        CT_RETURN_IFERR(sql_set_connect_path(stmt, ctsql_cursor));
    }
    return CT_SUCCESS;
}
