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
 * func_group.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/function/func_group.c
 *
 * -------------------------------------------------------------------------
 */
#include "func_group.h"
#include "dml_executor.h"

status_t sql_func_grouping(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    expr_tree_t *arg = func->argument;
    sql_cursor_t *cur = CTSQL_CURR_CURSOR(stmt);
    cur = sql_get_group_cursor(cur);
    group_set_t *group_set = NULL;
    expr_tree_t *group_expr = NULL;
    group_data_t *group_data = NULL;
    CM_POINTER3(stmt, func, res);

    CT_RETURN_IFERR(sql_get_ancestor_cursor(cur, NODE_VM_ANCESTOR(arg->root), &cur));
    group_data = cur->exec_data.group;

    if (group_data == NULL) {
        CT_SRC_THROW_ERROR(func->loc, ERR_GROUPING_NOT_ALLOWED);
        return CT_ERROR;
    }

    group_set = (group_set_t *)cm_galist_get(group_data->group_p->sets, group_data->curr_group);
    group_expr = (expr_tree_t *)cm_galist_get(group_set->items, NODE_VM_ID(arg->root));
    if (SECUREC_UNLIKELY(group_expr == NULL)) {
        CT_THROW_ERROR(ERR_ASSERT_ERROR, "group_expr is not null");
        return CT_ERROR;
    }

    if (NODE_IS_RES_DUMMY(group_expr->root)) {
        res->v_int = 1;
    } else {
        res->v_int = 0;
    }
    res->type = CT_TYPE_INTEGER;
    res->is_null = CT_FALSE;

    return CT_SUCCESS;
}

status_t sql_verify_grouping(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (verf->excl_flags & SQL_EXCL_GROUPING) {
        CT_SRC_THROW_ERROR(func->loc, ERR_GROUPING_NOT_ALLOWED);
        return CT_ERROR;
    }

    if (verf->curr_query == NULL || verf->curr_query->group_sets->count == 0) {
        CT_THROW_ERROR(ERR_GROUPING_NO_GROUPBY);
        return CT_ERROR;
    }

    verf->incl_flags |= SQL_INCL_GROUPING;

    CT_RETURN_IFERR(sql_verify_func_node(verf, func, 1, 1, CT_INVALID_ID32));

    func->datatype = CT_TYPE_INTEGER;
    func->size = CT_INTEGER_SIZE;
    return CT_SUCCESS;
}

status_t sql_func_grouping_id(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    expr_tree_t *arg = func->argument;
    sql_cursor_t *cur = CTSQL_CURR_CURSOR(stmt);
    cur = sql_get_group_cursor(cur);
    group_set_t *group_set = NULL;
    expr_tree_t *group_expr = NULL;
    group_data_t *group_data = NULL;
    CM_POINTER3(stmt, func, res);

    CT_RETURN_IFERR(sql_get_ancestor_cursor(cur, NODE_VM_ANCESTOR(arg->root), &cur));
    group_data = cur->exec_data.group;

    if (group_data == NULL) {
        CT_SRC_THROW_ERROR(func->loc, ERR_GROUPING_NOT_ALLOWED);
        return CT_ERROR;
    }

    group_set = (group_set_t *)cm_galist_get(group_data->group_p->sets, group_data->curr_group);
    uint64 group_val = 0;

    while (arg != NULL) {
        group_val <<= 1;
        group_expr = (expr_tree_t *)cm_galist_get(group_set->items, NODE_VM_ID(arg->root));
        if (SECUREC_UNLIKELY(group_expr == NULL)) {
            CT_THROW_ERROR(ERR_ASSERT_ERROR, "group_expr is not null");
            return CT_ERROR;
        }
        if (NODE_IS_RES_DUMMY(group_expr->root)) {
            group_val += 1;
        }
        arg = arg->next;
    }

    res->v_bigint = (int64)group_val;
    res->type = CT_TYPE_BIGINT;
    res->is_null = CT_FALSE;

    return CT_SUCCESS;
}

status_t sql_verify_grouping_id(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (verf->curr_query == NULL || verf->curr_query->group_sets->count == 0) {
        CT_THROW_ERROR(ERR_GROUPING_NO_GROUPBY);
        return CT_ERROR;
    }

    if (verf->excl_flags & SQL_EXCL_GROUPING) {
        CT_SRC_THROW_ERROR(func->loc, ERR_GROUPING_NOT_ALLOWED);
        return CT_ERROR;
    }
    verf->incl_flags |= SQL_INCL_GROUPING;

    // 63 bits is the maximum value of bigint
    CT_RETURN_IFERR(sql_verify_func_node(verf, func, 1, CT_MAX_FUNC_ARGUMENTS - 1, CT_INVALID_ID32));

    func->datatype = CT_TYPE_BIGINT;
    func->size = CT_BIGINT_SIZE;
    return CT_SUCCESS;
}

status_t sql_verify_group_concat(sql_verifier_t *verf, expr_node_t *func)
{
    // The first argument is separator, the 2nd arg is the 1st func argument
    if (func->argument == NULL || func->argument->next == NULL) {
        CT_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), 1,
            CT_MAX_FUNC_ARGUMENTS);
        return CT_ERROR;
    }

    if (sql_is_single_const_or_param(func->argument->root) != CT_TRUE) {
        CT_SRC_THROW_ERROR_EX(func->argument->loc, ERR_SQL_SYNTAX_ERROR,
            "separator specified in %s must be a const or a binding paramter", T2S(&func->word.func.name));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_verify_func_node(verf, func, 1, CT_MAX_FUNC_ARGUMENTS, CT_INVALID_ID32));

    if (func->sort_items != NULL) {
        CT_RETURN_IFERR(sql_verify_group_concat_order(verf, func, func->sort_items));
    }

    func->datatype = CT_TYPE_STRING;
    func->size = CT_MAX_ROW_SIZE;
    return CT_SUCCESS;
}

status_t sql_func_group_concat(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    uint32 row_len, remain_len;
    variant_t arg_var;
    char *buf = NULL;
    CM_POINTER3(stmt, func, res);

    res->type = CT_TYPE_STRING;
    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buf));
    res->v_text.str = buf;
    res->v_text.len = row_len = 0;
    remain_len = CT_MAX_ROW_SIZE;

    CTSQL_SAVE_STACK(stmt);

    expr_tree_t *arg = func->argument->next;
    while (arg != NULL) {
        SQL_EXEC_FUNC_ARG_EX(arg, &arg_var, res);

        if (!CT_IS_STRING_TYPE(arg_var.type)) {
            if (sql_var_as_string(stmt, &arg_var) != CT_SUCCESS) {
                CTSQL_RESTORE_STACK(stmt);
                return CT_ERROR;
            }
        }

        if ((row_len + arg_var.v_text.len) > CT_MAX_ROW_SIZE) {
            CTSQL_RESTORE_STACK(stmt);
            CT_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, (row_len + arg_var.v_text.len), CT_MAX_ROW_SIZE);
            return CT_ERROR;
        }

        if (arg_var.v_text.len > 0) {
            errno_t errcode =
                memcpy_s(res->v_text.str + row_len, remain_len, arg_var.v_text.str, arg_var.v_text.len);
            if (errcode != EOK) {
                CTSQL_RESTORE_STACK(stmt);
                CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
                return CT_ERROR;
            }

            row_len += arg_var.v_text.len;
            remain_len -= arg_var.v_text.len;
        }
        arg = arg->next;
        CTSQL_RESTORE_STACK(stmt);
    }

    res->is_null = CT_FALSE;
    res->v_text.len = row_len;
    return CT_SUCCESS;
}
