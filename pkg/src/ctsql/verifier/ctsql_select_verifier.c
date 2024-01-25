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
 * ctsql_select_verifier.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/verifier/ctsql_select_verifier.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_select_verifier.h"
#include "ctsql_table_verifier.h"
#include "ctsql_func.h"
#include "srv_instance.h"
#include "ctsql_select_parser.h"
#include "base_compiler.h"
#include "expr_parser.h"
#include "ctsql_limit.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline status_t sql_try_match_distinct_node(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node);
static void sql_try_delete_parent_ref(sql_query_t *query, expr_node_t *expr)
{
    if (expr->type == EXPR_NODE_COLUMN && NODE_ANCESTOR(expr) > 0) {
        query = sql_get_ancestor_query(query, NODE_ANCESTOR(expr) - 1);
        if (query != NULL && query->owner != NULL) {
            sql_del_parent_refs(query->owner->parent_refs, NODE_TAB(expr), expr);
        }
    }
}

static status_t sql_try_match_distinct_node_full(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node,
    bool32 *result)
{
    rs_column_t *rs_col = NULL;
    *result = CT_FALSE;
    expr_node_t *origin_ref = sql_get_origin_ref(node);
    for (uint32 i = 0; i < query->rs_columns->count; i++) {
        rs_col = (rs_column_t *)cm_galist_get(query->rs_columns, i);
        // all members in rs_columns are of the RS_COL_CALC type.
        if (rs_col->type == RS_COL_CALC) {
            if (sql_expr_node_equal(stmt, origin_ref, rs_col->expr->root, NULL)) {
                *result = CT_TRUE;
                sql_try_delete_parent_ref(query, node);
                return sql_set_group_expr_node(stmt, node, i, 0, 0, sql_get_origin_ref(rs_col->expr->root));
            }
        }
    }

    return CT_SUCCESS;
}

static inline status_t sql_match_distinct_cond_node(sql_stmt_t *stmt, sql_query_t *query, cond_node_t *cond)
{
    if (sql_stack_safe(stmt) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cond == NULL) {
        return CT_SUCCESS;
    }

    switch (cond->type) {
        case COND_NODE_COMPARE:
            CT_RETURN_IFERR(sql_match_distinct_expr(stmt, query, &cond->cmp->left, CT_FALSE));
            CT_RETURN_IFERR(sql_match_distinct_expr(stmt, query, &cond->cmp->right, CT_FALSE));
            break;
        case COND_NODE_TRUE:
        case COND_NODE_FALSE:
            break;
        default:
            CT_RETURN_IFERR(sql_match_distinct_cond_node(stmt, query, cond->left));
            CT_RETURN_IFERR(sql_match_distinct_cond_node(stmt, query, cond->right));
            break;
    }

    return CT_SUCCESS;
}

static status_t sql_try_match_distinct_func(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node)
{
    expr_tree_t *arg = NULL;
    sql_func_t *func = sql_get_func(&node->value.v_func);
    if ((func->builtin_func_id == ID_FUNC_ITEM_IF || func->builtin_func_id == ID_FUNC_ITEM_LNNVL) &&
        node->cond_arg != NULL) {
        CT_RETURN_IFERR(sql_match_distinct_cond_node(stmt, query, node->cond_arg->root));
    }
    arg = node->argument;
    while (arg != NULL) {
        CT_RETURN_IFERR(sql_try_match_distinct_node(stmt, query, arg->root));
        arg = arg->next;
    }
    return CT_SUCCESS;
}

static inline status_t sql_try_match_distinct_node(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node)
{
    if (sql_stack_safe(stmt) != CT_SUCCESS) {
        return CT_ERROR;
    }
    bool32 result = CT_FALSE;

    CT_RETURN_IFERR(sql_try_match_distinct_node_full(stmt, query, node, &result));
    if (result) {
        return CT_SUCCESS;
    }

    switch (node->type) {
        case EXPR_NODE_ADD:
        case EXPR_NODE_SUB:
        case EXPR_NODE_MUL:
        case EXPR_NODE_DIV:
        case EXPR_NODE_BITAND:
        case EXPR_NODE_BITOR:
        case EXPR_NODE_BITXOR:
        case EXPR_NODE_CAT:
        case EXPR_NODE_MOD:
        case EXPR_NODE_LSHIFT:
        case EXPR_NODE_RSHIFT:
        case EXPR_NODE_OPCEIL:
            CT_RETURN_IFERR(sql_try_match_distinct_node(stmt, query, node->left));
            return sql_try_match_distinct_node(stmt, query, node->right);
        case EXPR_NODE_FUNC:
            return sql_try_match_distinct_func(stmt, query, node);
        case EXPR_NODE_NEGATIVE:
            return sql_try_match_distinct_node(stmt, query, node->right);
        case EXPR_NODE_CONST:
        case EXPR_NODE_SELECT:
            return CT_SUCCESS;
        default:
            return CT_ERROR;
    }
}

status_t sql_match_distinct_expr(sql_stmt_t *stmt, sql_query_t *query, expr_tree_t **expr, bool32 need_clone)
{
    expr_tree_t *clone_expr = NULL;

    if (need_clone) {
        CT_RETURN_IFERR(sql_clone_expr_tree((*expr)->owner, *expr, &clone_expr, sql_alloc_mem));
        *expr = clone_expr;
    }

    if (sql_try_match_distinct_node(stmt, query, (*expr)->root) != CT_SUCCESS) {
        CT_SRC_THROW_ERROR((*expr)->loc, ERR_SQL_SYNTAX_ERROR, "expression not in distinct list");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

bool32 sql_rs_column_is_array(rs_column_t *rs_col)
{
    if (rs_col->datatype == CT_TYPE_ARRAY) {
        return CT_TRUE;
    }

    if (rs_col->type == RS_COL_COLUMN) {
        return (bool32)rs_col->v_col.is_array;
    } else if (rs_col->type == RS_COL_CALC) {
        return (bool32)rs_col->expr->root->typmod.is_array;
    } else {
        return CT_FALSE;
    }
}

status_t sql_verify_query_distinct(sql_verifier_t *verif, sql_query_t *query)
{
    uint32 i;
    expr_tree_t *expr = NULL;
    rs_column_t *rs_cols = NULL;
    rs_column_t *rs_col = NULL;
    expr_node_t *node = NULL;
    expr_node_t *origin_ref = NULL;

    if (!query->has_distinct) {
        return CT_SUCCESS;
    }

    if (if_query_distinct_can_eliminate(verif, query)) {
        query->has_distinct = CT_FALSE;
        return CT_SUCCESS;
    }

    galist_t *emp_rs_columns = query->distinct_columns;
    query->distinct_columns = query->rs_columns;
    query->rs_columns = emp_rs_columns;
    for (i = 0; i < query->distinct_columns->count; i++) {
        rs_cols = (rs_column_t *)cm_galist_get(query->distinct_columns, i);
        if (sql_rs_column_is_array(rs_cols)) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "unexpected array expression");
            return CT_ERROR;
        }
        CT_RETURN_IFERR(cm_galist_new(query->rs_columns, sizeof(rs_column_t), (pointer_t *)&rs_col));
        CT_RETURN_IFERR(sql_alloc_mem(verif->context, sizeof(expr_tree_t), (void **)&expr));
        CT_RETURN_IFERR(sql_alloc_mem(verif->context, sizeof(expr_node_t), (void **)&node));
        node->owner = expr;
        node->unary = expr->unary;
        node->typmod = rs_cols->typmod;
        CT_RETURN_IFERR(sql_generate_origin_ref(verif->stmt, rs_cols, &origin_ref));
        CT_RETURN_IFERR(sql_set_group_expr_node(verif->stmt, node, i, 0, 0, origin_ref));

        expr->root = node;
        expr->owner = verif->context;

        rs_col->type = RS_COL_CALC;
        rs_col->name = rs_cols->name;
        rs_col->z_alias = rs_cols->z_alias;
        rs_col->typmod = rs_cols->typmod;
        rs_col->expr = expr;
        rs_col->rs_flag = rs_cols->rs_flag;
    }

    return CT_SUCCESS;
}

static void sql_verify_select_rs_column_precision(rs_column_t *select_rs_col, rs_column_t *query_rs_col)
{
    if (CT_IS_NUMBER_TYPE(select_rs_col->datatype)) {
        if (select_rs_col->size != query_rs_col->size || select_rs_col->precision != query_rs_col->precision ||
            select_rs_col->scale != query_rs_col->scale) {
            if (CT_IS_NUMBER2_TYPE(select_rs_col->datatype)) {
                select_rs_col->size = MAX_DEC2_BYTE_SZ;
            } else {
                select_rs_col->size = MAX_DEC_BYTE_SZ;
            }
            select_rs_col->precision = CT_UNSPECIFIED_NUM_PREC;
            select_rs_col->scale = CT_UNSPECIFIED_NUM_SCALE;
        }
    } else if (CT_IS_DOUBLE_TYPE(select_rs_col->datatype)) {
        select_rs_col->size = sizeof(double);
        select_rs_col->precision = CT_UNSPECIFIED_NUM_PREC;
        select_rs_col->scale = CT_UNSPECIFIED_NUM_SCALE;
    } else if (CT_IS_DATETIME_TYPE(select_rs_col->datatype)) {
        select_rs_col->typmod.precision = MAX(select_rs_col->typmod.precision, query_rs_col->typmod.precision);
    } else if (CT_IS_YMITVL_TYPE2(select_rs_col->datatype, query_rs_col->datatype)) {
        select_rs_col->typmod.year_prec = MAX(select_rs_col->typmod.year_prec, query_rs_col->typmod.year_prec);
    } else if (CT_IS_DSITVL_TYPE2(select_rs_col->datatype, query_rs_col->datatype)) {
        select_rs_col->typmod.day_prec = MAX(select_rs_col->typmod.day_prec, query_rs_col->typmod.day_prec);
        select_rs_col->typmod.frac_prec = MAX(select_rs_col->typmod.frac_prec, query_rs_col->typmod.frac_prec);
    }
}

// NUMBER/DECIMAL and NUMBER2 -> NUMBER/DECIMAL
// UINT32 and NUMBER2 -> NUMBER2
// Other cases are consistent with NUMBER
static void sql_combine_number2_typmod(rs_column_t *select_rs_col, rs_column_t *query_rs_col)
{
    if (CT_IS_NUMBER2_TYPE(query_rs_col->datatype)) {
        if (CT_IS_DECIMAL_TYPE(select_rs_col->datatype) ||
            (select_rs_col->datatype > CT_TYPE_NUMBER && select_rs_col->datatype != CT_TYPE_UINT32)) {
            return;
        }
    } else { // CT_IS_NUMBER2_TYPE(select_rs_col->datatype)
        if (query_rs_col->datatype < CT_TYPE_NUMBER ||
            (query_rs_col->datatype > CT_TYPE_NUMBER && query_rs_col->datatype == CT_TYPE_UINT32)) {
            return;
        }
    }

    select_rs_col->datatype = query_rs_col->datatype;
    if (select_rs_col->size < query_rs_col->size) {
        select_rs_col->size = query_rs_col->size;
    }
}

static void sql_combine_string_typmod(rs_column_t *select_rs_col, rs_column_t *query_rs_col)
{
    if (select_rs_col->datatype != query_rs_col->datatype) {
        select_rs_col->datatype = CT_TYPE_STRING;
    }
    if (!select_rs_col->typmod.is_char && query_rs_col->typmod.is_char) {
        uint32 byte_size = MIN(query_rs_col->size * CT_CHAR_TO_BYTES_RATIO, CT_MAX_COLUMN_SIZE);
        select_rs_col->size = MAX(select_rs_col->size, byte_size);
    } else {
        select_rs_col->size = MAX(select_rs_col->size, query_rs_col->size);
    }
}

static void sql_verify_select_rs_datatype(rs_column_t *select_rs_col, rs_column_t *query_rs_col)
{
    uint16 size = 0;
    uint16 size2 = 0;

    if ((CT_IS_STRING_TYPE(select_rs_col->datatype) && CT_IS_CLOB_TYPE(query_rs_col->datatype)) ||
        (CT_IS_STRING_TYPE(query_rs_col->datatype) && CT_IS_CLOB_TYPE(select_rs_col->datatype))) {
        select_rs_col->datatype = CT_TYPE_CLOB;
    } else if (CT_IS_STRING_TYPE2(select_rs_col->datatype, query_rs_col->datatype)) {
        sql_combine_string_typmod(select_rs_col, query_rs_col);
        return;
    } else if (CT_IS_STRING_TYPE(select_rs_col->datatype) || CT_IS_STRING_TYPE(query_rs_col->datatype)) {
        size = (uint16)cm_get_datatype_strlen(query_rs_col->datatype, query_rs_col->size);
        size2 = (uint16)cm_get_datatype_strlen(select_rs_col->datatype, select_rs_col->size);
        size = MAX(size, size2);
        if (select_rs_col->datatype != query_rs_col->datatype) {
            select_rs_col->datatype = CT_TYPE_STRING;
        }
    } else if ((select_rs_col->datatype == CT_TYPE_UINT32 && query_rs_col->datatype == CT_TYPE_INTEGER) ||
        (select_rs_col->datatype == CT_TYPE_INTEGER && query_rs_col->datatype == CT_TYPE_UINT32)) {
        select_rs_col->datatype = CT_TYPE_BIGINT;
        select_rs_col->size = CT_BIGINT_SIZE;
    } else if (CT_IS_NUMBER2_TYPE(select_rs_col->datatype) || CT_IS_NUMBER2_TYPE(query_rs_col->datatype)) {
        sql_combine_number2_typmod(select_rs_col, query_rs_col);
        return;
    } else if ((select_rs_col->datatype <= query_rs_col->datatype && query_rs_col->datatype != CT_TYPE_UINT32) ||
        select_rs_col->datatype == CT_TYPE_UINT32) {
        select_rs_col->datatype = query_rs_col->datatype;
        size = query_rs_col->size;
    }

    if (select_rs_col->size < size) {
        select_rs_col->size = size;
    }
}

static status_t sql_verify_select_rs_column(sql_verifier_t *verif, sql_query_t *query, uint32 i)
{
    rs_column_t *select_rs_col = (rs_column_t *)cm_galist_get(query->owner->rs_columns, i);
    rs_column_t *query_rs_col = (rs_column_t *)cm_galist_get(query->rs_columns, i);

    if (select_rs_col->typmod.is_array != query_rs_col->typmod.is_array ||
        !var_datatype_matched(query_rs_col->datatype, select_rs_col->datatype)) {
        CT_SRC_THROW_ERROR(query->loc, ERR_SQL_SYNTAX_ERROR,
            "expression must have same datatype as corresponding expression");
        return CT_ERROR;
    }

    if ((verif->has_union || verif->has_minus || verif->has_except_intersect) && (select_rs_col->typmod.is_array)) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "unexpected array expression");
        return CT_ERROR;
    }

    sql_verify_select_rs_datatype(select_rs_col, query_rs_col);

    /* the precision and scale of NUMBER/DECIMAL/NUMERIC should be zero,
       the precision of TIMESTAMP WITH TIME ZONE/TIMESTAMP WITH LOCAL TIME ZONE/TIMESTAMP/DATE should be the
       bigger one */
    sql_verify_select_rs_column_precision(select_rs_col, query_rs_col);
    return CT_SUCCESS;
}

static status_t sql_verify_select_rs_columns(sql_verifier_t *verif, sql_query_t *query)
{
    if (query->owner->type == SELECT_AS_RESULT) {
        if (verif->context->rs_columns == NULL) {
            verif->context->rs_columns = query->rs_columns;
        }
    }

    if (query->owner->rs_columns == NULL) {
        query->owner->rs_columns = query->rs_columns;
        return CT_SUCCESS;
    }

    if (query->owner->rs_columns->count != query->rs_columns->count) {
        CT_SRC_THROW_ERROR(query->loc, ERR_SQL_SYNTAX_ERROR, "query block has incorrect number of result columns");
        return CT_ERROR;
    }

    for (uint32 i = 0; i < query->owner->rs_columns->count; ++i) {
        CT_RETURN_IFERR(sql_verify_select_rs_column(verif, query, i));
    }

    if (query->owner->type == SELECT_AS_RESULT) {
        verif->context->rs_columns = query->owner->rs_columns;
    }

    return CT_SUCCESS;
}

status_t sql_verify_query_limit(sql_verifier_t *verif, sql_query_t *query)
{
    variant_t limit_offset_var, limit_count_var;
    CT_RETURN_IFERR(sql_verify_limit_offset(verif->stmt, &query->limit));

    if (query->limit.offset != NULL && ((expr_tree_t *)(query->limit.offset))->root->type == EXPR_NODE_CONST) {
        CT_RETURN_IFERR(sql_exec_expr(verif->stmt, (expr_tree_t *)query->limit.offset, &limit_offset_var));
        if (limit_offset_var.is_null) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "offset must not be null");
            return CT_ERROR;
        }

        CT_RETURN_IFERR(sql_convert_limit_num(&limit_offset_var));
        if (limit_offset_var.v_bigint < 0) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "offset must not be negative");
            return CT_ERROR;
        }
    }

    if (query->limit.count != NULL && ((expr_tree_t *)(query->limit.count))->root->type == EXPR_NODE_CONST) {
        CT_RETURN_IFERR(sql_exec_expr(verif->stmt, (expr_tree_t *)query->limit.count, &limit_count_var));
        if (limit_count_var.is_null) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "limit must not be null");
            return CT_ERROR;
        }

        CT_RETURN_IFERR(sql_convert_limit_num(&limit_count_var));

        if (limit_count_var.v_bigint < 0) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "limit must not be negative");
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static inline status_t sql_set_cbo_flag_4_subselect(sql_query_t *query)
{
    sql_table_t *table = NULL;
    sql_select_t *select_ctx = query->owner;

    if (select_ctx == NULL) {
        return CT_SUCCESS;
    }

    if (!select_ctx->is_update_value || (select_ctx->parent_refs->count == 0 && select_ctx->has_ancestor == 0)) {
        return CT_SUCCESS;
    }
    select_ctx->can_sub_opt = CT_FALSE;

    for (uint32 i = 0; i < query->tables.count; ++i) {
        table = (sql_table_t *)sql_array_get(&query->tables, i);
        TABLE_CBO_SET_FLAG(table, SELTION_NO_HASH_JOIN);
    }
    return CT_SUCCESS;
}

static status_t sql_add_table_for_update_cols(sql_stmt_t *stmt, sql_table_t *table, uint32 col)
{
    uint32 *new_col = NULL;
    if (col == CT_INVALID_ID32) {
        return CT_SUCCESS;
    }
    if (table->for_update_cols == NULL) {
        CT_RETURN_IFERR(sql_create_list(stmt, &table->for_update_cols));
    }
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(uint32), (void **)&new_col));
    *new_col = col;
    CT_RETURN_IFERR(cm_galist_insert(table->for_update_cols, new_col));
    return CT_SUCCESS;
}

static inline status_t sql_verify_for_update_rs_col(sql_query_t *query, uint32 col, sql_table_t **sub_table,
    uint32 *sub_col)
{
    rs_column_t *rs_col = (rs_column_t *)cm_galist_get(query->rs_columns, col);

    if (rs_col->type == RS_COL_COLUMN) {
        *sub_col = rs_col->v_col.col;
        *sub_table = (sql_table_t *)sql_array_get(&query->tables, rs_col->v_col.tab);
    } else if (rs_col->expr->next == NULL && NODE_IS_RES_ROWID(rs_col->expr->root)) {
        *sub_col = CT_INVALID_ID32;
        *sub_table = (sql_table_t *)sql_array_get(&query->tables, ROWID_NODE_TAB(rs_col->expr->root));
    } else {
        CT_SRC_THROW_ERROR(rs_col->expr->loc, ERR_CALC_COLUMN_NOT_ALLOWED);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_verify_table_for_update(sql_stmt_t *stmt, sql_table_t *table, uint32 col)
{
    CT_RETURN_IFERR(sql_stack_safe(stmt));

    if (table->type == NORMAL_TABLE) {
        table->for_update = CT_TRUE;
        if (table->entry->dc.type == DICT_TYPE_DYNAMIC_VIEW) {
            CT_THROW_ERROR(ERR_FOR_UPDATE_NOT_ALLOWED);
            return CT_ERROR;
        }
        CT_RETURN_IFERR(sql_add_table_for_update_cols(stmt, table, col));
        return CT_SUCCESS;
    }

    if (!CT_IS_SUBSELECT_TABLE(table->type)) {
        CT_THROW_ERROR(ERR_FOR_UPDATE_NOT_ALLOWED);
        return CT_ERROR;
    }

    uint32 sub_col;
    sql_table_t *sub_table = NULL;
    sql_select_t *select_ctx = table->select_ctx;
    sql_query_t *query = select_ctx->first_query;

    // not support for update from view or sub-select with DISTINCT, GROUP BY, etc
    if (select_ctx->root->type != SELECT_NODE_QUERY || query->distinct_columns->count != 0 ||
        query->group_sets->count != 0 || query->aggrs->count != 0 || query->cntdis_columns->count != 0 ||
        query->connect_by_cond != NULL || query->winsort_list->count != 0 || ROWNUM_COND_OCCUR(query->cond) ||
        LIMIT_CLAUSE_OCCUR(&query->limit)) {
        CT_THROW_ERROR(ERR_FOR_UPDATE_FROM_VIEW);
        return CT_ERROR;
    }

    if (col == CT_INVALID_ID32) {
        for (uint32 i = 0; i < query->tables.count; i++) {
            sub_table = (sql_table_t *)sql_array_get(&query->tables, i);
            CT_RETURN_IFERR(sql_verify_table_for_update(stmt, sub_table, CT_INVALID_ID32));
        }
        table->for_update = CT_TRUE;
        select_ctx->for_update = CT_TRUE;
        return CT_SUCCESS;
    }

    // only accept normal column or rowid here
    CT_RETURN_IFERR(sql_verify_for_update_rs_col(query, col, &sub_table, &sub_col));
    CT_RETURN_IFERR(sql_verify_table_for_update(stmt, sub_table, sub_col));
    table->for_update = CT_TRUE;
    select_ctx->for_update = CT_TRUE;

    return CT_SUCCESS;
}

static status_t sql_verify_for_update_columns(sql_verifier_t *verif, sql_query_t *query)
{
    expr_tree_t *expr = NULL;
    sql_table_t *table = NULL;
    galist_t *for_update_cols = verif->select_ctx->for_update_cols;

    if (!query->for_update) {
        return CT_SUCCESS;
    }

    verif->excl_flags = SQL_FOR_UPDATE_EXCL;

    if (for_update_cols == NULL) {
        for (uint32 i = 0; i < query->tables.count; i++) {
            table = (sql_table_t *)sql_array_get(&query->tables, i);
            CT_RETURN_IFERR(sql_verify_table_for_update(verif->stmt, table, CT_INVALID_ID32));
        }
        return CT_SUCCESS;
    }

    for (uint32 i = 0; i < for_update_cols->count; i++) {
        expr = (expr_tree_t *)cm_galist_get(for_update_cols, i);
        if (sql_verify_expr(verif, expr) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (expr->root->type != EXPR_NODE_COLUMN) {
            CT_SRC_THROW_ERROR(expr->loc, ERR_EXPECT_COLUMN_HERE);
            return CT_ERROR;
        }
        if (NODE_ANCESTOR(expr->root) != 0) {
            CT_SRC_THROW_ERROR(expr->loc, ERR_FOR_UPDATE_NOT_ALLOWED);
            return CT_ERROR;
        }
        table = (sql_table_t *)sql_array_get(&query->tables, NODE_TAB(expr->root));
        CT_RETURN_IFERR(sql_verify_table_for_update(verif->stmt, table, NODE_COL(expr->root)));
    }
    return CT_SUCCESS;
}

static inline void sql_organize_group_sets(sql_query_t *query)
{
    group_set_t *group_set = NULL;
    for (uint32 i = 0; i < query->group_sets->count; i++) {
        group_set = (group_set_t *)cm_galist_get(query->group_sets, i);
        group_set->group_id = i;
    }
}

static status_t sql_create_specified_expr(sql_stmt_t *stmt, expr_tree_t **expr, expr_node_type_t type,
    ct_type_t datatype, variant_t value)
{
    expr_node_t *node = NULL;
    CT_RETURN_IFERR(sql_create_expr(stmt, expr));
    CT_RETURN_IFERR(sql_alloc_mem((void *)stmt->context, sizeof(expr_node_t), (void **)&node));
    node->type = type;
    node->datatype = datatype;
    node->value = value;
    (*expr)->root = node;
    return CT_SUCCESS;
}

static status_t sql_create_null_expr(sql_stmt_t *stmt, expr_tree_t **expr)
{
    variant_t value;
    value.is_null = CT_FALSE;
    value.type = CT_TYPE_INTEGER;
    value.v_int = RES_WORD_NULL;
    return sql_create_specified_expr(stmt, expr, EXPR_NODE_RESERVED, CT_TYPE_VARCHAR, value);
}

static status_t sql_create_const_number_expr(sql_stmt_t *stmt, expr_tree_t **expr, int val)
{
    variant_t value;
    value.v_int = val;
    value.is_null = CT_FALSE;
    value.type = CT_TYPE_INTEGER;
    return sql_create_specified_expr(stmt, expr, EXPR_NODE_CONST, CT_TYPE_INTEGER, value);
}

static status_t sql_build_decode_4_count(sql_stmt_t *stmt, expr_node_t *node)
{
    node->type = EXPR_NODE_FUNC;
    node->value.v_func.func_id = ID_FUNC_ITEM_DECODE;
    node->value.v_func.pack_id = CT_INVALID_ID32;
    node->typmod.datatype = CT_TYPE_INTEGER;
    CT_RETURN_IFERR(sql_create_null_expr(stmt, &node->argument->next));
    CT_RETURN_IFERR(sql_create_const_number_expr(stmt, &node->argument->next->next, 0));
    CT_RETURN_IFERR(sql_create_const_number_expr(stmt, &node->argument->next->next->next, 1));
    return CT_SUCCESS;
}

static status_t sql_build_decode_4_stddev(sql_stmt_t *stmt, expr_node_t *node)
{
    node->type = EXPR_NODE_FUNC;
    node->value.v_func.func_id = ID_FUNC_ITEM_DECODE;
    node->value.v_func.pack_id = CT_INVALID_ID32;
    node->typmod.datatype = CT_TYPE_INTEGER;
    CT_RETURN_IFERR(sql_create_null_expr(stmt, &node->argument->next));
    CT_RETURN_IFERR(sql_create_null_expr(stmt, &node->argument->next->next));
    CT_RETURN_IFERR(sql_create_const_number_expr(stmt, &node->argument->next->next->next, 0));
    return CT_SUCCESS;
}

static status_t sql_build_decode_4_covar_pop(sql_stmt_t *stmt, expr_node_t *node)
{
    expr_node_t *arg_node = NULL;
    node->type = EXPR_NODE_FUNC;
    node->value.v_func.func_id = ID_FUNC_ITEM_DECODE;
    node->value.v_func.pack_id = CT_INVALID_ID32;
    node->typmod.datatype = CT_TYPE_INTEGER;
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&arg_node));
    arg_node->argument = node->argument->next;
    CT_RETURN_IFERR(sql_create_null_expr(stmt, &node->argument->next));
    CT_RETURN_IFERR(sql_create_null_expr(stmt, &node->argument->next->next));
    CT_RETURN_IFERR(sql_create_expr(stmt, &node->argument->next->next->next));
    arg_node->type = EXPR_NODE_FUNC;
    arg_node->value.v_func.func_id = ID_FUNC_ITEM_DECODE;
    arg_node->value.v_func.pack_id = CT_INVALID_ID32;
    arg_node->typmod.datatype = CT_TYPE_INTEGER;
    CT_RETURN_IFERR(sql_create_null_expr(stmt, &arg_node->argument->next));
    CT_RETURN_IFERR(sql_create_null_expr(stmt, &arg_node->argument->next->next));
    CT_RETURN_IFERR(sql_create_const_number_expr(stmt, &arg_node->argument->next->next->next, 0));
    node->argument->next->next->next->root = arg_node;
    return CT_SUCCESS;
}

static status_t sql_rewrite_aggr_node(sql_stmt_t *stmt, sql_func_t *func, expr_node_t *node)
{
    switch (func->builtin_func_id) {
        case ID_FUNC_ITEM_AVG:
        case ID_FUNC_ITEM_SUM:
        case ID_FUNC_ITEM_MIN:
        case ID_FUNC_ITEM_MAX:
        case ID_FUNC_ITEM_MEDIAN:
            // sum(expr) ==> expr
            *node = *node->argument->root;
            break;
        case ID_FUNC_ITEM_COUNT:
            // count(*) or count(1) ==> 1
            if (node->argument->root->type == EXPR_NODE_STAR || node->argument->root->type == EXPR_NODE_CONST) {
                node->type = EXPR_NODE_CONST;
                node->value.type = CT_TYPE_INTEGER;
                node->value.v_int = 1;
                node->value.is_null = CT_FALSE;
                break;
            } else {
                // count(expr) ==> decode(expr,null,0,1)
                return sql_build_decode_4_count(stmt, node);
            }
        case ID_FUNC_ITEM_STDDEV:
        case ID_FUNC_ITEM_STDDEV_POP:
        case ID_FUNC_ITEM_VAR_POP:
        case ID_FUNC_ITEM_VARIANCE:
            // stddev(expr) ==>  decode(expr,null,null,0)
            return sql_build_decode_4_stddev(stmt, node);
        case ID_FUNC_ITEM_COVAR_POP:
            // covar_pop(expr1, expr2) ==> decode(expr1,null,null,decode(expr2,null,null,0))
            return sql_build_decode_4_covar_pop(stmt, node);
        case ID_FUNC_ITEM_STDDEV_SAMP:
        case ID_FUNC_ITEM_CORR:
        case ID_FUNC_ITEM_COVAR_SAMP:
        case ID_FUNC_ITEM_VAR_SAMP:
            // stddev(expr) ==> null
            node->type = EXPR_NODE_RESERVED;
            node->value.type = CT_TYPE_VARCHAR;
            node->value.v_int = RES_WORD_NULL;
            node->value.is_null = CT_FALSE;
            break;
        case ID_FUNC_ITEM_LISTAGG:
            // listagg(expr,separator) wihtin group(order by expr1) ==> expr
            *node = *node->argument->next->root;
            break;
        default:
            break;
    }
    return CT_SUCCESS;
}

static status_t modify_aggr_node_4_eliminate(visit_assist_t *va, expr_node_t **node)
{
    expr_node_t *aggr_node = NULL;
    sql_func_t *func = NULL;
    // rewrite expr_node_aggr
    if ((*node)->type == EXPR_NODE_AGGR) {
        aggr_node = (expr_node_t *)cm_galist_get(va->query->aggrs, (*node)->value.v_int);
        func = sql_get_func(&aggr_node->value.v_func);
        CT_RETURN_IFERR(sql_rewrite_aggr_node(va->stmt, func, *node));
    }
    // revert expr_node_group
    if ((*node)->type == EXPR_NODE_GROUP) {
        expr_node_t *origin_ref = sql_get_origin_ref(*node);
        **node = *origin_ref;
    }
    return CT_SUCCESS;
}

static status_t sql_regen_rs_column(sql_stmt_t *stmt, expr_tree_t *expr, rs_column_t *rs_col)
{
    // sum(a)==>a, use a regenerate rs_col
    if (expr->root->type == EXPR_NODE_COLUMN) {
        rs_col->type = RS_COL_COLUMN;
        rs_col->v_col = *VALUE_PTR(var_column_t, &expr->root->value);
    } else {
        // corr()==>NULL, use null regenerate rs_col
        rs_col->expr = expr;
    }
    return CT_SUCCESS;
}

static inline void sql_reset_rs_col_flags(rs_column_t *rs_col)
{
    cols_used_t cols_used;

    if (rs_col->type == RS_COL_COLUMN) {
        CT_BIT_RESET(rs_col->rs_flag, RS_COND_UNABLE);
        return;
    }
    if (rs_col->type == RS_COL_CALC && rs_col->expr->root->type == EXPR_NODE_AGGR) {
        return;
    }
    init_cols_used(&cols_used);
    sql_collect_cols_in_expr_node(rs_col->expr->root, &cols_used);
    if (!HAS_ROWNUM(&cols_used)) {
        CT_BIT_RESET(rs_col->rs_flag, RS_COND_UNABLE);
    }
}

static status_t sql_eliminate_group_set(sql_stmt_t *stmt, sql_query_t *query)
{
    uint32 i;
    bool32 need_reset_flag = CT_FALSE;
    rs_column_t *rs_col = NULL;
    sort_item_t *item = NULL;
    visit_assist_t va;

    sql_init_visit_assist(&va, stmt, query);
    // example : select a,sum(c) from t where c < 10 and b > 1 group by a having min(a) > 1 order by sum(a);
    // modify column expr
    // sum(a)==> a, abs(sum(a)) ==> abs(a), count(a) ==> decode(a, null, 0, 1)
    for (i = 0; i < query->rs_columns->count; i++) {
        rs_col = (rs_column_t *)cm_galist_get(query->rs_columns, i);
        need_reset_flag = (rs_col->type == RS_COL_CALC && rs_col->expr->root->type == EXPR_NODE_AGGR);
        CT_RETURN_IFERR(visit_expr_tree(&va, rs_col->expr, modify_aggr_node_4_eliminate));
        CT_RETURN_IFERR(sql_regen_rs_column(stmt, rs_col->expr, rs_col));
        if (need_reset_flag) {
            sql_reset_rs_col_flags(rs_col);
        }
    }

    // modify haing condition
    // where c < 10 and b > 1 group by a having min(a) > 1 ==> where c < 10 and b > 1 and a > 1
    if (query->having_cond != NULL) {
        CT_RETURN_IFERR(visit_cond_node(&va, query->having_cond->root, modify_aggr_node_4_eliminate));
        if (query->cond != NULL) {
            CT_RETURN_IFERR(sql_add_cond_node(query->cond, query->having_cond->root));
        } else {
            query->cond = query->having_cond;
        }
        query->having_cond = NULL;
    }
    // modify order by expr
    // order by sum(a) ==> order by a
    for (i = 0; i < query->sort_items->count; i++) {
        item = (sort_item_t *)cm_galist_get(query->sort_items, i);
        CT_RETURN_IFERR(visit_expr_tree(&va, item->expr, modify_aggr_node_4_eliminate));
    }

    // remove all aggregate function
    cm_galist_reset(query->aggrs);
    // remove group by a
    cm_galist_reset(query->group_sets);
    return CT_SUCCESS;
}

static bool32 chk_aggr_node_name(uint32 builtin_func_id)
{
    switch (builtin_func_id) {
        case ID_FUNC_ITEM_AVG:
        case ID_FUNC_ITEM_MIN:
        case ID_FUNC_ITEM_SUM:
        case ID_FUNC_ITEM_MAX:
        case ID_FUNC_ITEM_MEDIAN:
        case ID_FUNC_ITEM_COUNT:
        case ID_FUNC_ITEM_STDDEV:
        case ID_FUNC_ITEM_STDDEV_POP:
        case ID_FUNC_ITEM_COVAR_POP:
        case ID_FUNC_ITEM_VAR_POP:
        case ID_FUNC_ITEM_VARIANCE:
        case ID_FUNC_ITEM_STDDEV_SAMP:
        case ID_FUNC_ITEM_CORR:
        case ID_FUNC_ITEM_COVAR_SAMP:
        case ID_FUNC_ITEM_VAR_SAMP:
        case ID_FUNC_ITEM_LISTAGG:
            return CT_TRUE;

        default:
            break;
    }
    return CT_FALSE;
}

static bool32 chk_aggr_node_args(sql_stmt_t *stmt, expr_node_t *node)
{
    if (sql_stack_safe(stmt) != CT_SUCCESS) {
        return CT_FALSE;
    }
    expr_tree_t *arg = NULL;
    switch (node->type) {
        case EXPR_NODE_COLUMN:
        case EXPR_NODE_CONST:
        case EXPR_NODE_STAR:
        case EXPR_NODE_GROUP:
            return CT_TRUE;

        case EXPR_NODE_ADD:
        case EXPR_NODE_SUB:
        case EXPR_NODE_MOD:
        case EXPR_NODE_DIV:
        case EXPR_NODE_MUL:
        case EXPR_NODE_BITAND:
        case EXPR_NODE_BITOR:
        case EXPR_NODE_BITXOR:
        case EXPR_NODE_LSHIFT:
        case EXPR_NODE_RSHIFT:
        case EXPR_NODE_NEGATIVE:
            if (node->left != NULL && !chk_aggr_node_args(stmt, node->left)) {
                return CT_FALSE;
            }
            if (node->right != NULL && !chk_aggr_node_args(stmt, node->right)) {
                return CT_FALSE;
            }
            return CT_TRUE;

        case EXPR_NODE_FUNC:
            if (node->value.v_func.func_id == ID_FUNC_ITEM_LNNVL || node->value.v_func.func_id == ID_FUNC_ITEM_IF) {
                return CT_FALSE;
            }
            arg = node->argument;
            while (arg != NULL) {
                if (!chk_aggr_node_args(stmt, arg->root)) {
                    return CT_FALSE;
                }
                arg = arg->next;
            }
            return CT_TRUE;

        default:
            return CT_FALSE;
    }
}

static bool32 chk_aggr_node_can_rewrite(sql_stmt_t *stmt, expr_node_t *aggr_node)
{
    sql_func_t *func = NULL;
    expr_tree_t *args = aggr_node->argument;
    // check parameters of aggregate function
    while (args != NULL) {
        // not support stddev(((select min(length(A)) + sum(length(A)) + STDDEV_SAMP(length(A)) from sys_dummy)) + A) c1
        if (!chk_aggr_node_args(stmt, args->root)) {
            return CT_FALSE;
        }
        args = args->next;
    }
    // check name of aggregate function
    func = sql_get_func(&aggr_node->value.v_func);
    return chk_aggr_node_name(func->builtin_func_id);
}

static bool32 chk_aggrs_can_rewrite(sql_stmt_t *stmt, sql_query_t *query)
{
    uint32 i;
    expr_node_t *aggr_node = NULL;
    for (i = 0; i < query->aggrs->count; i++) {
        aggr_node = (expr_node_t *)cm_galist_get(query->aggrs, i);
        if (!chk_aggr_node_can_rewrite(stmt, aggr_node)) {
            return CT_FALSE;
        }
    }
    return CT_TRUE;
}

static bool32 chk_having_cond_has_subslct(sql_stmt_t *stmt, sql_query_t *query)
{
    if (query->having_cond != NULL) {
        cols_used_t cols_used;
        init_cols_used(&cols_used);
        sql_collect_cols_in_cond(query->having_cond->root, &cols_used);
        return HAS_SUBSLCT(&cols_used);
    }
    return CT_FALSE;
}

static bool32 chk_rs_cols_has_subslect(sql_stmt_t *stmt, sql_query_t *query)
{
    cols_used_t cols_used;
    init_cols_used(&cols_used);
    for (uint32 i = 0; i < query->rs_columns->count; i++) {
        rs_column_t *rs_col = (rs_column_t *)cm_galist_get(query->rs_columns, i);
        sql_collect_cols_in_expr_node(rs_col->expr->root, &cols_used);
        if (HAS_DYNAMIC_SUBSLCT(&cols_used)) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

static bool32 if_eliminate_group_set(sql_stmt_t *stmt, sql_query_t *query)
{
    uint32 i;
    expr_tree_t *group_expr = NULL;
    if(query->group_sets->count != 1 || query->tables.count > 1 || query->winsort_list->count > 0 ||
        query->has_distinct || query->connect_by_cond != NULL) {
        return CT_FALSE;
    }

    sql_array_t *tables = &query->tables;
    sql_table_t *table = (sql_table_t *)sql_array_get(tables, 0);
    if (table->type != NORMAL_TABLE) {
        return CT_FALSE;
    }

    group_set_t *group_set = (group_set_t *)cm_galist_get(query->group_sets, 0);
    // not support select ... from t1 where a in (select a from t2 group by a, t1.b)
    for (i = 0; i < group_set->items->count; i++) {
        group_expr = (expr_tree_t *)cm_galist_get(group_set->items, i);
        if (group_expr->root->type != EXPR_NODE_COLUMN || EXPR_ANCESTOR(group_expr) > 0) {
            return CT_FALSE;
        }
    }

    if (!chk_rs_cols_has_subslect(stmt, query) && chk_aggrs_can_rewrite(stmt, query) &&
        !chk_having_cond_has_subslct(stmt, query) && if_unqiue_idx_in_list(query, table, group_set->items)) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

// rewrite : select a, b ,sum(c) from t1 group by a, b having min(a) > 1 order by sum(a) > 1
// ==>
// select a, b, c from t1 where a > 1 order by a > 1
static status_t sql_try_eliminate_group_set(sql_stmt_t *stmt, sql_query_t *query)
{
    if (if_eliminate_group_set(stmt, query)) {
        CT_RETURN_IFERR(sql_eliminate_group_set(stmt, query));
    }
    return CT_SUCCESS;
}

static status_t sql_verify_query(sql_verifier_t *verif, sql_query_t *query)
{
    CM_POINTER2(verif, query);

    query->for_update = verif->for_update;
    query->owner = verif->select_ctx;
    SET_NODE_STACK_CURR_QUERY(verif->stmt, query);

    CT_RETURN_IFERR(sql_verify_tables(verif, query));

    CT_RETURN_IFERR(sql_verify_query_group(verif, query));

    CT_RETURN_IFERR(sql_verify_query_columns(verif, query));

    CT_RETURN_IFERR(sql_verify_query_pivot(verif, query));

    CT_RETURN_IFERR(sql_verify_query_unpivot(verif, query));

    CT_RETURN_IFERR(sql_verify_query_distinct(verif, query));

    CT_RETURN_IFERR(sql_verify_query_where(verif, query));

    CT_RETURN_IFERR(sql_set_cbo_flag_4_subselect(query));

    CT_RETURN_IFERR(sql_verify_query_joins(verif, query));

    CT_RETURN_IFERR(sql_verify_query_connect(verif, query));

    CT_RETURN_IFERR(sql_verify_query_having(verif, query));

    CT_RETURN_IFERR(sql_verify_query_order(verif, query, query->sort_items, CT_TRUE));

    CT_RETURN_IFERR(sql_verify_select_rs_columns(verif, query));

    CT_RETURN_IFERR(sql_verify_query_limit(verif, query));

    CT_RETURN_IFERR(sql_verify_for_update_columns(verif, query));

    CT_RETURN_IFERR(sql_try_eliminate_group_set(verif->stmt, query));

    sql_organize_group_sets(query);

    SQL_RESTORE_NODE_STACK(verif->stmt);
    return CT_SUCCESS;
}

static status_t sql_verify_select_node(sql_verifier_t *verif, select_node_t *node)
{
    CT_RETURN_IFERR(sql_stack_safe(verif->stmt));

    switch (node->type) {
        case SELECT_NODE_QUERY:
            return sql_verify_query(verif, node->query);

        case SELECT_NODE_UNION:
            if (verif->has_union) {
                node->type = SELECT_NODE_UNION_ALL;
            } else {
                verif->has_union = CT_TRUE;
            }

            CT_RETURN_IFERR(sql_verify_select_node(verif, node->left));
            CT_RETURN_IFERR(sql_verify_select_node(verif, node->right));

            if (node->type == SELECT_NODE_UNION) {
                verif->has_union = CT_FALSE;
            }

            return CT_SUCCESS;

        case SELECT_NODE_UNION_ALL:
            CT_RETURN_IFERR(sql_verify_select_node(verif, node->left));
            return sql_verify_select_node(verif, node->right);

        case SELECT_NODE_MINUS:
        case SELECT_NODE_EXCEPT:
            verif->has_minus = CT_TRUE;
            CT_RETURN_IFERR(sql_verify_select_node(verif, node->left));
            CT_RETURN_IFERR(sql_verify_select_node(verif, node->right));
            verif->has_minus = CT_FALSE;
            return CT_SUCCESS;
        case SELECT_NODE_INTERSECT:
        case SELECT_NODE_INTERSECT_ALL:
        case SELECT_NODE_EXCEPT_ALL:
            verif->has_except_intersect = CT_TRUE;
            CT_RETURN_IFERR(sql_verify_select_node(verif, node->left));
            CT_RETURN_IFERR(sql_verify_select_node(verif, node->right));
            verif->has_except_intersect = CT_FALSE;
            return CT_SUCCESS;
        default:
            CT_THROW_ERROR(ERR_UNSUPPORT_OPER_TYPE, "set", node->type);
            return CT_ERROR;
    }
}

static bool32 sql_rs_col_equal_sort_col(sql_stmt_t *stmt, rs_column_t *rs_col, sort_item_t *sort_item)
{
    expr_node_t *sort_expr_node = NULL;

    if (rs_col->type == RS_COL_COLUMN) {
        sort_expr_node = sort_item->expr->root;
        if (sort_expr_node->type == EXPR_NODE_COLUMN && rs_col->v_col.tab == VAR_TAB(&sort_expr_node->value) &&
            rs_col->v_col.col == VAR_COL(&sort_expr_node->value)) {
            return CT_TRUE;
        }
    } else if (rs_col->type == RS_COL_CALC) {
        if (sql_expr_node_equal(stmt, rs_col->expr->root, sort_item->expr->root, NULL)) {
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

static status_t sql_create_select_sort_items(sql_verifier_t *verif, sql_select_t *select_ctx)
{
    galist_t *rs_columns = select_ctx->first_query->rs_columns;
    galist_t *sort_items = select_ctx->sort_items;
    uint32 i, j;
    rs_column_t *rs_col = NULL;
    sort_item_t *sort_item = NULL;
    select_sort_item_t *select_sort_item = NULL;
    bool32 is_found = CT_FALSE;

    if (sql_create_list(verif->stmt, &select_ctx->select_sort_items) != CT_SUCCESS) {
        return CT_ERROR;
    }

    for (i = 0; i < sort_items->count; ++i) {
        sort_item = (sort_item_t *)cm_galist_get(sort_items, i);
        is_found = CT_FALSE;
        if (cm_galist_new(select_ctx->select_sort_items, sizeof(select_sort_item_t), (void **)&select_sort_item) !=
            CT_SUCCESS) {
            return CT_ERROR;
        }

        for (j = 0; j < rs_columns->count; ++j) {
            rs_col = (rs_column_t *)cm_galist_get(rs_columns, j);
            if (sql_rs_col_equal_sort_col(verif->stmt, rs_col, sort_item)) {
                select_sort_item->rs_columns_id = j;
                select_sort_item->datatype = rs_col->datatype;
                select_sort_item->sort_mode = sort_item->sort_mode;
                is_found = CT_TRUE;
                break;
            }
        }

        if (!is_found) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "ORDER BY item must be the number of a SELECT-list expression");
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_verify_select_order(sql_verifier_t *verif, sql_select_t *select_ctx)
{
    SET_NODE_STACK_CURR_QUERY(verif->stmt, select_ctx->first_query);
    if (sql_verify_query_order(verif, select_ctx->first_query, select_ctx->sort_items, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    SQL_RESTORE_NODE_STACK(verif->stmt);
    return sql_create_select_sort_items(verif, select_ctx);
}

static void sql_set_query_rs_datatype(galist_t *select_rs_cols, select_node_t *node)
{
    uint32 i;
    rs_column_t *select_col = NULL;
    rs_column_t *query_rs_col = NULL;

    switch (node->type) {
        case SELECT_NODE_QUERY: {
            if (select_rs_cols == node->query->rs_columns) {
                return;
            }
            for (i = 0; i < select_rs_cols->count; ++i) {
                select_col = (rs_column_t *)cm_galist_get(select_rs_cols, i);
                query_rs_col = (rs_column_t *)cm_galist_get(node->query->rs_columns, i);
                query_rs_col->typmod = select_col->typmod;
                if (select_col->type == RS_COL_CALC && select_col->expr != NULL &&
                    select_col->expr->root->type == EXPR_NODE_ARRAY) {
                    select_col->expr->root->datatype = select_col->datatype;
                    query_rs_col->expr->root->datatype = select_col->datatype;
                }
            }
            return;
        }

        default:
            sql_set_query_rs_datatype(select_rs_cols, node->left);
            sql_set_query_rs_datatype(select_rs_cols, node->right);
            return;
    }
}

static void sql_record_pending_column(sql_select_t *select_ctx)
{
    rs_column_t *rs_column = NULL;
    uint32 i;

    select_ctx->pending_col_count = 0;

    for (i = 0; i < select_ctx->rs_columns->count; ++i) {
        rs_column = (rs_column_t *)cm_galist_get(select_ctx->rs_columns, i);
        if (rs_column->datatype == CT_TYPE_UNKNOWN) {
            select_ctx->pending_col_count++;
        }
    }
}

static inline void sql_try_optmz_select_type(sql_verifier_t *verif, sql_select_t *select_ctx)
{
    sql_query_t *query = NULL;
    if (select_ctx->type != SELECT_AS_LIST) {
        return;
    }
    if (select_ctx->root->type != SELECT_NODE_QUERY) {
        return;
    }
    query = select_ctx->first_query;
    // ignore group or winsort
    if (query->group_sets->count != 0 || query->winsort_list->count != 0) {
        return;
    }
    // make sure the result is only one
    if (query->aggrs->count == 1 && query->rs_columns->count == 1) {
        select_ctx->type = SELECT_AS_VARIANT;
    }
}

status_t sql_verify_withas_ctx(sql_stmt_t *stmt, galist_t *withas_ctx)
{
    sql_verifier_t verif = { 0 };
    sql_select_t *select_ctx = NULL;
    uint32 i;

    verif.stmt = stmt;
    verif.context = stmt->context;

    for (i = 0; i < withas_ctx->count; i++) {
        select_ctx = (sql_select_t *)cm_galist_get(withas_ctx, i);
        verif.select_ctx = select_ctx;
        verif.for_update = select_ctx->for_update;
        verif.excl_flags = SQL_EXCL_DEFAULT;
        verif.do_expr_optmz = CT_TRUE;
        verif.parent = NULL;

        CT_RETURN_IFERR(sql_verify_select_context(&verif, select_ctx));
    }

    return CT_SUCCESS;
}

status_t sql_verify_select_context(sql_verifier_t *verif, sql_select_t *select_ctx)
{
    verif->select_ctx = select_ctx;

    if (select_ctx->withass != NULL) {
        CT_RETURN_IFERR(sql_verify_withas_ctx(verif->stmt, select_ctx->withass));
    }

    CT_RETURN_IFERR(sql_verify_select_node(verif, select_ctx->root));

    sql_set_query_rs_datatype(select_ctx->rs_columns, select_ctx->root);
    sql_record_pending_column(select_ctx);
    CT_RETURN_IFERR(sql_verify_select_order(verif, select_ctx));
    sql_try_optmz_select_type(verif, select_ctx);

    return CT_SUCCESS;
}

status_t sql_verify_sub_select(sql_stmt_t *stmt, sql_select_t *select_ctx, sql_verifier_t *parent)
{
    sql_verifier_t verif = { 0 };

    verif.stmt = stmt;
    verif.context = stmt->context;
    verif.select_ctx = select_ctx;
    verif.pl_dc_lst = select_ctx->pl_dc_lst;
    verif.for_update = select_ctx->for_update;
    verif.excl_flags = SQL_EXCL_DEFAULT;
    verif.do_expr_optmz = CT_TRUE;
    verif.parent = parent;
#ifdef Z_SHARDING
    CT_RETURN_IFERR(shd_verfity_excl_user_function(&verif, stmt));
#endif

    return sql_verify_select_context(&verif, select_ctx);
}

status_t sql_verify_select(sql_stmt_t *stmt, sql_select_t *select_ctx)
{
    sql_verifier_t verif = { 0 };

    verif.stmt = stmt;
    verif.context = stmt->context;
    verif.select_ctx = select_ctx;
    verif.pl_dc_lst = select_ctx->pl_dc_lst;
    verif.for_update = select_ctx->for_update;
    verif.excl_flags = SQL_EXCL_DEFAULT;
    verif.do_expr_optmz = CT_TRUE;
    verif.parent = NULL;
    plc_get_verify_obj(stmt, &verif);
#ifdef Z_SHARDING
    CT_RETURN_IFERR(shd_verfity_excl_user_function(&verif, stmt));
#endif

    CT_RETURN_IFERR(sql_verify_select_context(&verif, select_ctx));
    if ((verif.has_ddm_col == CT_TRUE) && (stmt->context->type == CTSQL_TYPE_CREATE_TABLE)) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", the command references a redacted object");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
