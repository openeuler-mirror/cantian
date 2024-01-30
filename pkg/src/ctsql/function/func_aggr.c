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
 * func_aggr.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/function/func_aggr.c
 *
 * -------------------------------------------------------------------------
 */
#include "func_aggr.h"
#include "ctsql_table_func.h"
#include "srv_instance.h"
#include "ctsql_cond_rewrite.h"
#include "func_parser.h"
#include "ctsql_mtrl.h"

/* ******************************************************************************
Function       : count aggregate function
Output         : None
Return         : CT_SUCCESS or CT_ERROR
Modification   : Create function
****************************************************************************** */
status_t sql_func_array_agg(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    return sql_exec_expr_node(stmt, func->argument->root, res);
}

status_t sql_verify_array_agg(sql_verifier_t *verif, expr_node_t *func)
{
    expr_tree_t *arg = NULL;

    if (sql_verify_func_node(verif, func, 1, 1, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    arg = func->argument;
    if (arg->root->typmod.is_array == CT_TRUE ||
        (arg->root->type == EXPR_NODE_COLUMN && !cm_datatype_arrayable(arg->root->value.v_col.datatype))) {
        CT_SRC_THROW_ERROR(arg->root->loc, ERR_INVALID_ARG_TYPE);
        return CT_ERROR;
    }

    verif->incl_flags |= SQL_INCL_ARRAY;

    /* elements' datatype */
    func->typmod = func->argument->root->typmod;
    func->typmod.is_array = CT_TRUE;
    return CT_SUCCESS;
}

static status_t sql_verify_avg_median_core(expr_node_t *func, bool32 is_avg)
{
    ct_type_t arg_type = func->argument->root->datatype;
    switch (arg_type) {
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_BIGINT:
        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
            func->datatype = CT_TYPE_NUMBER;
            func->size = CT_MAX_DEC_OUTPUT_ALL_PREC;
            return CT_SUCCESS;
        case CT_TYPE_NUMBER2:
            func->datatype = CT_TYPE_NUMBER2;
            func->size = CT_MAX_DEC_OUTPUT_ALL_PREC;
            return CT_SUCCESS;

        case CT_TYPE_REAL:
            func->datatype = CT_TYPE_REAL;
            func->size = CT_REAL_SIZE;
            return CT_SUCCESS;

        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
            if (is_avg) {
                func->datatype = CT_TYPE_NUMBER;
                func->size = CT_MAX_DEC_OUTPUT_ALL_PREC;
                return CT_SUCCESS;
            }
            break;

        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ:
        case CT_TYPE_TIMESTAMP_LTZ:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
            if (!is_avg) {
                func->datatype = arg_type;
                func->typmod = func->argument->root->typmod;
                return CT_SUCCESS;
            }
            break;

        case CT_TYPE_UNKNOWN:
            func->datatype = CT_TYPE_UNKNOWN;
            func->size = CT_MAX_DEC_OUTPUT_ALL_PREC;
            return CT_SUCCESS;

        default:
            break;
    }

    CT_THROW_ERROR(ERR_TYPE_MISMATCH, "NUMERIC", get_datatype_name_str(arg_type));
    return CT_ERROR;
}

static status_t sql_verify_avg_median(sql_verifier_t *verif, expr_node_t *func, bool32 is_avg)
{
    CM_POINTER2(verif, func);

    uint32 excl_flags = verif->excl_flags | SQL_EXCL_STAR;
    verif->excl_flags = excl_flags | SQL_EXCL_PARENT;
    CT_RETURN_IFERR(sql_verify_func_node(verif, func, 1, 1, CT_INVALID_ID32));
    verif->excl_flags = excl_flags;
    return sql_verify_avg_median_core(func, is_avg);
}

status_t sql_verify_avg(sql_verifier_t *verif, expr_node_t *func)
{
    return sql_verify_avg_median(verif, func, CT_TRUE);
}

status_t sql_verify_covar_or_corr(sql_verifier_t *verif, expr_node_t *func)
{
    uint32 excl_flags;
    CM_POINTER2(verif, func);
    excl_flags = verif->excl_flags;
    verif->excl_flags = excl_flags | SQL_EXCL_STAR | SQL_EXCL_AGGR;

    CT_RETURN_IFERR(sql_verify_func_node(verif, func, 2, 2, CT_INVALID_ID32));
    if (func->dis_info.need_distinct) {
        CT_SRC_THROW_ERROR_EX(func->argument->loc, ERR_SQL_SYNTAX_ERROR,
            "DISTINCT option not allowed for this function");
        return CT_ERROR;
    }

    expr_tree_t *arg = func->argument;
    if (!sql_match_numeric_type(TREE_DATATYPE(arg))) {
        CT_SRC_ERROR_REQUIRE_NUMERIC(arg->loc, TREE_DATATYPE(arg));
        return CT_ERROR;
    }

    arg = arg->next;
    if (!sql_match_numeric_type(TREE_DATATYPE(arg))) {
        CT_SRC_ERROR_REQUIRE_NUMERIC(arg->loc, TREE_DATATYPE(arg));
        return CT_ERROR;
    }

    verif->excl_flags = excl_flags;
    func->datatype = CT_TYPE_NUMBER;
    func->size = CT_MAX_DEC_OUTPUT_ALL_PREC;
    if (verif->curr_query != NULL) {
        verif->curr_query->exists_covar = CT_TRUE;
    }
    return CT_SUCCESS;
}

status_t sql_func_covar_or_corr(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    CM_POINTER3(stmt, func, result);
    if (sql_exec_expr_node(stmt, func->argument->root, &result[0]) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_exec_expr_node(stmt, func->argument->next->root, &result[1]) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_func_count(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t value;

    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;
    res->is_null = CT_FALSE;
    res->type = CT_TYPE_BIGINT;

    if (arg->root->type == EXPR_NODE_STAR) {
        res->v_bigint = 1;
    } else {
        CT_RETURN_IFERR(sql_exec_expr(stmt, arg, &value));
        res->v_bigint = value.is_null ? 0 : 1;
    }

    return CT_SUCCESS;
}

status_t sql_verify_count(sql_verifier_t *verif, expr_node_t *func)
{
    CM_POINTER2(verif, func);

    if (func->argument == NULL || func->argument->next != NULL) {
        CT_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), 1, 1);
        return CT_ERROR;
    }

    expr_node_t *node = func->argument->root;

    if (node->type == EXPR_NODE_STAR) {
        if (node->word.column.table.len != 0) {
            CT_SRC_THROW_ERROR(node->word.column.table.loc, ERR_INVALID_FUNC_PARAMS,
                "user.table.column or table.column or column is invalid");
            return CT_ERROR;
        }

        if (func->dis_info.need_distinct) {
            CT_SRC_THROW_ERROR(node->word.column.table.loc, ERR_INVALID_FUNC_PARAMS, "missing expression");
            return CT_ERROR;
        }
    } else {
        CT_RETURN_IFERR(sql_verify_expr(verif, func->argument));
    }

    if ((verif->incl_flags & SQL_INCL_WINSORT) && (node->type == EXPR_NODE_STAR)) {
        node->type = EXPR_NODE_CONST;
        node->value.v_bigint = 1;
        node->value.type = CT_TYPE_BIGINT;
        node->value.is_null = CT_FALSE;
    }

    func->datatype = CT_TYPE_BIGINT;
    func->size = CT_BIGINT_SIZE;
    return CT_SUCCESS;
}

static status_t sql_calc_cume_dist_satisfy(sql_stmt_t *stmt, expr_tree_t *arg_expr, sort_item_t *item, bool32 *satisfy,
    bool32 *continus)
{
    variant_t constant;
    variant_t val_order;
    int32 result = 0;

    CM_POINTER3(stmt, arg_expr, item);

    // if the position of contant is behind of val_order, it will be true. as if all data has been sorted
    *satisfy = CT_FALSE;
    *continus = CT_FALSE;

    CT_RETURN_IFERR(sql_exec_expr(stmt, arg_expr, &constant));
    CT_RETURN_IFERR(sql_exec_expr(stmt, item->expr, &val_order));
    if (!(CT_IS_NUMERIC_TYPE(val_order.type))) {
        CT_RETURN_IFERR(sql_convert_variant2(stmt, &constant, &val_order));
    }

    if (constant.is_null && val_order.is_null) {
        *satisfy = CT_TRUE;
        *continus = CT_TRUE;
    } else if (constant.is_null) {
        if (item->nulls_pos == SORT_NULLS_LAST) {
            *satisfy = CT_TRUE;
        }
    } else if (val_order.is_null) {
        if (item->nulls_pos == SORT_NULLS_FIRST || item->nulls_pos == SORT_NULLS_DEFAULT) {
            *satisfy = CT_TRUE;
        }
    } else {
        CT_RETURN_IFERR(var_compare(SESSION_NLS(stmt), &constant, &val_order, &result));
        if (item->direction == SORT_MODE_ASC || item->direction == SORT_MODE_NONE) {
            if (result >= 0) {
                *satisfy = CT_TRUE;
                *continus = (result == 0) ? CT_TRUE : CT_FALSE;
            }
        } else {
            if (result <= 0) {
                *satisfy = CT_TRUE;
                *continus = (result == 0) ? CT_TRUE : CT_FALSE;
            }
        }
        return CT_SUCCESS;
    }

    return CT_SUCCESS;
}

status_t sql_func_cume_dist(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    CM_POINTER3(stmt, func, res);
    uint32 i = 0;
    sort_item_t *item = NULL;
    expr_tree_t *arg = NULL;
    bool32 satisfy = CT_FALSE;
    bool32 continus = CT_FALSE;

    res->type = CT_TYPE_BIGINT;
    res->is_null = CT_FALSE;
    res->v_bigint = 0;

    /*
     * actually , there is no need to do sort, you could only fetch all the data,
     * and just compare according to the sort_item's order mode
     */
    arg = func->argument;
    for (; i < func->sort_items->count; i++) {
        item = (sort_item_t *)cm_galist_get(func->sort_items, i);
        CT_RETURN_IFERR(sql_calc_cume_dist_satisfy(stmt, arg, item, &satisfy, &continus));

        if (!satisfy) {
            return CT_SUCCESS;
        }
        if (!continus) {
            break;
        }

        arg = arg->next;
    }

    res->v_bigint = 1;
    return CT_SUCCESS;
}

static status_t sql_verify_order_by_expr(sql_verifier_t *verf, expr_tree_t *arg_expr, sort_item_t *item, ct_type_t type)
{
    variant_t *pvar;
    variant_t constant;

    constant = arg_expr->root->value;
    pvar = &constant;

    CT_RETURN_IFERR(sql_convert_variant(verf->stmt, pvar, type));
    if (CT_IS_LOB_TYPE(pvar->type)) {
        CT_SRC_THROW_ERROR_EX(item->expr->loc, ERR_SQL_SYNTAX_ERROR, "unexpected LOB datatype occurs");
        return CT_ERROR;
    }

    // copy string, binary, and raw datatype into SQL context
    if ((!pvar->is_null) && CT_IS_VARLEN_TYPE(pvar->type)) {
        text_t text_bak = pvar->v_text;
        CT_RETURN_IFERR(sql_copy_text(verf->stmt->context, &text_bak, &pvar->v_text));
    }

    return CT_SUCCESS;
}

static status_t sql_verify_sort_param(sql_verifier_t *verif, expr_node_t *func)
{
    uint32 i;
    sort_item_t *item = NULL;
    expr_tree_t *arg = NULL;
    CM_POINTER2(verif, func);

    uint32 ori_excl_flags = verif->excl_flags;
    verif->excl_flags = verif->excl_flags | SQL_EXCL_WIN_SORT | SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_SEQUENCE |
        SQL_EXCL_ROWID | SQL_EXCL_LOB_COL | SQL_EXCL_ARRAY | SQL_EXCL_UNNEST;
    if (sql_verify_func_node(verif, func, 1, CT_MAX_FUNC_ARGUMENTS, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (func->value.v_func.arg_cnt != func->sort_items->count) {
        CT_SRC_THROW_ERROR_EX(func->argument->loc, ERR_SQL_SYNTAX_ERROR, "invalid number of arguments");
        return CT_ERROR;
    }

    arg = func->argument;
    for (i = 0; i < func->sort_items->count; i++) {
        // param must be constant, include null
        if (!NODE_IS_OPTMZ_CONST(arg->root) && TREE_DATATYPE(arg) != CT_TYPE_UNKNOWN && !NODE_IS_RES_NULL(arg->root) &&
            !NODE_IS_RES_TRUE(arg->root) && !NODE_IS_RES_FALSE(arg->root)) {
            if (arg->root->argument != NULL) {
                if (!NODE_IS_OPTMZ_CONST(arg->root->argument->root)) {
                    CT_SRC_THROW_ERROR_EX(arg->root->argument->loc, ERR_SQL_SYNTAX_ERROR,
                        "Argument should be a constant");
                    return CT_ERROR;
                }
            } else {
                CT_SRC_THROW_ERROR_EX(arg->loc, ERR_SQL_SYNTAX_ERROR, "Argument should be a constant");
                return CT_ERROR;
            }
        }

        if (CT_IS_LOB_TYPE(TREE_DATATYPE(arg))) {
            CT_SRC_THROW_ERROR_EX(arg->loc, ERR_SQL_SYNTAX_ERROR, "unexpected LOB datatype occurs");
            return CT_ERROR;
        }

        // verify the sort expr tree
        item = (sort_item_t *)cm_galist_get(func->sort_items, i);
        CT_RETURN_IFERR(sql_verify_expr_node(verif, item->expr->root));

        if (arg->root->type == EXPR_NODE_CONST && TREE_DATATYPE(item->expr) != CT_TYPE_UNKNOWN) {
            // param must can be convert to the sort item type
            CT_RETURN_IFERR(sql_verify_order_by_expr(verif, arg, item, item->expr->root->datatype));
        }

        arg = arg->next;
    }
    verif->excl_flags = ori_excl_flags;
    return CT_SUCCESS;
}

status_t sql_verify_cume_dist(sql_verifier_t *verif, expr_node_t *func)
{
    CM_POINTER2(verif, func);
    CT_RETURN_IFERR(sql_verify_sort_param(verif, func));
    func->datatype = CT_TYPE_REAL;
    func->size = CT_REAL_SIZE;
    return CT_SUCCESS;
}

status_t sql_func_dense_rank(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    result->type = CT_TYPE_UNKNOWN;
    result->is_null = CT_TRUE;
    return CT_SUCCESS;
}

status_t sql_verify_dense_rank(sql_verifier_t *verif, expr_node_t *func)
{
    CM_POINTER2(verif, func);
    CT_RETURN_IFERR(sql_verify_sort_param(verif, func));
    func->datatype = CT_TYPE_INTEGER;
    func->size = CT_INTEGER_SIZE;
    return CT_SUCCESS;
}

// swap the position of the first and second parameters
static status_t sql_adjust_args_pos(sql_stmt_t *stmt, expr_node_t *func)
{
    expr_tree_t *sep = NULL;
    expr_tree_t *arg = NULL;

    arg = func->argument;
    if (arg->next == NULL) {
        CT_RETURN_IFERR(sql_create_const_string_expr(stmt, &sep, ""));
    } else {
        sep = arg->next;
        arg->next = sep->next;
    }
    sep->next = arg;
    func->argument = sep;
    return CT_SUCCESS;
}

status_t sql_verify_listagg(sql_verifier_t *verif, expr_node_t *func)
{
    if (sql_verify_func_node(verif, func, 1, 2, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // the first arg is delimiter, the second arg is column
    CT_RETURN_IFERR(sql_adjust_args_pos(verif->stmt, func));

    // verify within group(order by expr)
    CT_RETURN_IFERR(sql_verify_listagg_order(verif, func->sort_items));

    func->datatype = CT_TYPE_STRING;
    func->size = CT_MAX_ROW_SIZE;
    return CT_SUCCESS;
}

status_t sql_verify_min_max(sql_verifier_t *verif, expr_node_t *func)
{
    uint32 excl_flags;

    CM_POINTER2(verif, func);

    excl_flags = verif->excl_flags;
    verif->excl_flags = excl_flags | SQL_EXCL_STAR | SQL_EXCL_AGGR;

    if (sql_verify_func_node(verif, func, 1, 1, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }
    verif->excl_flags = excl_flags;
    func->typmod = TREE_TYPMODE(func->argument);
    sql_convert_lob_type(func, TREE_DATATYPE(func->argument));
    // min/max do not need distinct
    func->dis_info.need_distinct = CT_FALSE;
    return CT_SUCCESS;
}

status_t sql_verify_median(sql_verifier_t *verif, expr_node_t *func)
{
    expr_node_t *node = NULL;
    sort_item_t *sort_item = NULL;
    galist_t *cmp_list = NULL;
    sql_context_t *ctx = verif->stmt->context;
    CT_RETURN_IFERR(sql_verify_avg_median(verif, func, CT_FALSE));

    CT_RETURN_IFERR(sql_alloc_mem(ctx, sizeof(galist_t), (void **)&cmp_list));
    cm_galist_init(cmp_list, ctx, sql_alloc_mem);
    CT_RETURN_IFERR(cm_galist_new(cmp_list, sizeof(sort_item_t), (void **)&sort_item));
    CT_RETURN_IFERR(sql_clone_expr_node(ctx, func->argument->root, &node, sql_alloc_mem));
    CT_RETURN_IFERR(sql_alloc_mem(ctx, sizeof(expr_tree_t), (void **)&sort_item->expr));
    sort_item->expr->owner = ctx;
    sort_item->expr->root = node;
    sort_item->sort_mode.direction = SORT_MODE_ASC;
    sort_item->sort_mode.nulls_pos = SORT_NULLS_LAST;
    func->sort_items = cmp_list;
    return CT_SUCCESS;
}

status_t sql_verify_stddev_intern(sql_verifier_t *verif, expr_node_t *func)
{
    uint32 excl_flags;
    CM_POINTER2(verif, func);
    excl_flags = verif->excl_flags;
    verif->excl_flags = excl_flags | SQL_EXCL_STAR | SQL_EXCL_AGGR;

    CT_RETURN_IFERR(sql_verify_func_node(verif, func, 1, 1, CT_INVALID_ID32));

    if (!sql_match_numeric_type(TREE_DATATYPE(func->argument))) {
        CT_SRC_ERROR_REQUIRE_NUMERIC(func->argument->loc, TREE_DATATYPE(func->argument));
        return CT_ERROR;
    }

    verif->excl_flags = excl_flags;
    func->datatype = CT_TYPE_NUMBER;
    func->size = CT_MAX_DEC_OUTPUT_ALL_PREC;
    return CT_SUCCESS;
}

status_t sql_verify_sum(sql_verifier_t *verif, expr_node_t *func)
{
    CM_POINTER2(verif, func);

    verif->excl_flags = verif->excl_flags | SQL_EXCL_STAR;

    if (sql_verify_func_node(verif, func, 1, 1, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return opr_infer_type_sum(func->argument->root->datatype, &func->typmod);
}

status_t sql_verify_approx_count_distinct(sql_verifier_t *verif, expr_node_t *func)
{
    uint32 excl_flags = verif->excl_flags;
    verif->excl_flags = excl_flags | SQL_EXCL_STAR | SQL_EXCL_AGGR;

    if (sql_verify_func_node(verif, func, 1, 1, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    verif->excl_flags = excl_flags;

    func->size = CT_BIGINT_SIZE;
    func->datatype = CT_TYPE_BIGINT;
    func->dis_info.need_distinct = CT_FALSE;
    return CT_SUCCESS;
}

status_t sql_func_approx_count_distinct(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t var;
    char *buf = NULL;
    row_assist_t row_ass;

    result->type = CT_TYPE_BIGINT;
    result->is_null = CT_FALSE;

    CM_POINTER3(stmt, func, result);
    SQL_EXEC_FUNC_ARG_EX(func->argument, &var, result);

    CTSQL_SAVE_STACK(stmt);
    sql_keep_stack_variant(stmt, &var);

    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buf));
    row_init(&row_ass, buf, CT_MAX_ROW_SIZE, 1);
    CT_RETURN_IFERR(sql_put_row_value(stmt, NULL, &row_ass, var.type, &var));
    result->v_bigint = sql_hash_func(buf);
    CTSQL_RESTORE_STACK(stmt);
    return CT_SUCCESS;
}

status_t sql_func_normal_aggr(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    CM_POINTER3(stmt, func, res);
    expr_node_t *arg_node = func->argument->root;
    return sql_exec_expr_node(stmt, arg_node, res);
}
