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
 * func_group.c
 *
 *
 * IDENTIFICATION
 * src/cmd/function/func_group.c
 *
 * -------------------------------------------------------------------------
 */
#include "func_group.h"
#include "srv_query.h"

status_t sql_func_grouping(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    expr_tree_t *arg = func->argument;
    sql_cursor_t *cursor = SQL_CURR_CURSOR(stmt);
    cursor = sql_get_group_cursor(cursor);
    group_set_t *group_set = NULL;
    expr_tree_t *group_expr = NULL;
    group_data_t *group_data = NULL;
    CM_POINTER3(stmt, func, result);

    GS_RETURN_IFERR(sql_get_ancestor_cursor(cursor, NODE_VM_ANCESTOR(arg->root), &cursor));
    group_data = cursor->exec_data.group;

    if (group_data == NULL) {
        GS_SRC_THROW_ERROR(func->loc, ERR_GROUPING_NOT_ALLOWED);
        return GS_ERROR;
    }

    group_set = (group_set_t *)cm_galist_get(group_data->group_p->sets, group_data->curr_group);
    group_expr = (expr_tree_t *)cm_galist_get(group_set->items, NODE_VM_ID(arg->root));
    if (SECUREC_UNLIKELY(group_expr == NULL)) {
        GS_THROW_ERROR(ERR_ASSERT_ERROR, "group_expr is not null");
        return GS_ERROR;
    }

    if (NODE_IS_RES_DUMMY(group_expr->root)) {
        result->v_int = 1;
    } else {
        result->v_int = 0;
    }
    result->type = GS_TYPE_INTEGER;
    result->is_null = GS_FALSE;

    return GS_SUCCESS;
}

status_t sql_verify_grouping(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (verf->excl_flags & SQL_EXCL_GROUPING) {
        GS_SRC_THROW_ERROR(func->loc, ERR_GROUPING_NOT_ALLOWED);
        return GS_ERROR;
    }

    if (verf->curr_query == NULL || verf->curr_query->group_sets->count == 0) {
        GS_THROW_ERROR(ERR_GROUPING_NO_GROUPBY);
        return GS_ERROR;
    }

    verf->incl_flags |= SQL_INCL_GROUPING;

    GS_RETURN_IFERR(sql_verify_func_node(verf, func, 1, 1, GS_INVALID_ID32));

    func->datatype = GS_TYPE_INTEGER;
    func->size = GS_INTEGER_SIZE;
    return GS_SUCCESS;
}

status_t sql_func_grouping_id(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    expr_tree_t *arg = func->argument;
    sql_cursor_t *cursor = SQL_CURR_CURSOR(stmt);
    cursor = sql_get_group_cursor(cursor);
    group_set_t *group_set = NULL;
    expr_tree_t *group_expr = NULL;
    group_data_t *group_data = NULL;
    CM_POINTER3(stmt, func, result);

    GS_RETURN_IFERR(sql_get_ancestor_cursor(cursor, NODE_VM_ANCESTOR(arg->root), &cursor));
    group_data = cursor->exec_data.group;

    if (group_data == NULL) {
        GS_SRC_THROW_ERROR(func->loc, ERR_GROUPING_NOT_ALLOWED);
        return GS_ERROR;
    }

    group_set = (group_set_t *)cm_galist_get(group_data->group_p->sets, group_data->curr_group);
    uint64 group_value = 0;

    while (arg != NULL) {
        group_value <<= 1;
        group_expr = (expr_tree_t *)cm_galist_get(group_set->items, NODE_VM_ID(arg->root));
        if (SECUREC_UNLIKELY(group_expr == NULL)) {
            GS_THROW_ERROR(ERR_ASSERT_ERROR, "group_expr is not null");
            return GS_ERROR;
        }
        if (NODE_IS_RES_DUMMY(group_expr->root)) {
            group_value += 1;
        }
        arg = arg->next;
    }

    result->v_bigint = (int64)group_value;
    result->type = GS_TYPE_BIGINT;
    result->is_null = GS_FALSE;

    return GS_SUCCESS;
}

status_t sql_verify_grouping_id(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (verf->curr_query == NULL || verf->curr_query->group_sets->count == 0) {
        GS_THROW_ERROR(ERR_GROUPING_NO_GROUPBY);
        return GS_ERROR;
    }

    if (verf->excl_flags & SQL_EXCL_GROUPING) {
        GS_SRC_THROW_ERROR(func->loc, ERR_GROUPING_NOT_ALLOWED);
        return GS_ERROR;
    }
    verf->incl_flags |= SQL_INCL_GROUPING;

    // 63 bits is the maximum value of bigint
    GS_RETURN_IFERR(sql_verify_func_node(verf, func, 1, GS_MAX_FUNC_ARGUMENTS - 1, GS_INVALID_ID32));

    func->datatype = GS_TYPE_BIGINT;
    func->size = GS_BIGINT_SIZE;
    return GS_SUCCESS;
}

status_t sql_verify_group_concat(sql_verifier_t *verf, expr_node_t *func)
{
    // The first argument is separator, the 2nd arg is the 1st func argument
    if (func->argument == NULL || func->argument->next == NULL) {
        GS_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), 1,
            GS_MAX_FUNC_ARGUMENTS);
        return GS_ERROR;
    }

    if (sql_is_single_const_or_param(func->argument->root) != GS_TRUE) {
        GS_SRC_THROW_ERROR_EX(func->argument->loc, ERR_SQL_SYNTAX_ERROR,
            "separator specified in %s must be a const or a binding paramter", T2S(&func->word.func.name));
        return GS_ERROR;
    }

    GS_RETURN_IFERR(sql_verify_func_node(verf, func, 1, GS_MAX_FUNC_ARGUMENTS, GS_INVALID_ID32));

    if (func->sort_items != NULL) {
        GS_RETURN_IFERR(sql_verify_group_concat_order(verf, func, func->sort_items));
    }

    func->datatype = GS_TYPE_STRING;
    func->size = GS_MAX_ROW_SIZE;
    return GS_SUCCESS;
}

status_t sql_func_group_concat(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    uint32 row_len, remain_len;
    variant_t arg_var;
    char *buf = NULL;
    CM_POINTER3(stmt, func, result);

    result->type = GS_TYPE_STRING;
    GS_RETURN_IFERR(sql_push(stmt, GS_MAX_ROW_SIZE, (void **)&buf));
    result->v_text.str = buf;
    result->v_text.len = row_len = 0;
    remain_len = GS_MAX_ROW_SIZE;

    SQL_SAVE_STACK(stmt);

    expr_tree_t *arg = func->argument->next;
    while (arg != NULL) {
        SQL_EXEC_FUNC_ARG_EX(arg, &arg_var, result);

        if (!GS_IS_STRING_TYPE(arg_var.type)) {
            if (sql_var_as_string(stmt, &arg_var) != GS_SUCCESS) {
                SQL_RESTORE_STACK(stmt);
                return GS_ERROR;
            }
        }

        if ((row_len + arg_var.v_text.len) > GS_MAX_ROW_SIZE) {
            SQL_RESTORE_STACK(stmt);
            GS_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, (row_len + arg_var.v_text.len), GS_MAX_ROW_SIZE);
            return GS_ERROR;
        }

        if (arg_var.v_text.len > 0) {
            errno_t errcode =
                memcpy_s(result->v_text.str + row_len, remain_len, arg_var.v_text.str, arg_var.v_text.len);
            if (errcode != EOK) {
                SQL_RESTORE_STACK(stmt);
                GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
                return GS_ERROR;
            }

            row_len += arg_var.v_text.len;
            remain_len -= arg_var.v_text.len;
        }
        arg = arg->next;
        SQL_RESTORE_STACK(stmt);
    }

    result->is_null = GS_FALSE;
    result->v_text.len = row_len;
    return GS_SUCCESS;
}
