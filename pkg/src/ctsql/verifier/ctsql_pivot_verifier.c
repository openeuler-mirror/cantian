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
 * ctsql_pivot_verifier.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/verifier/ctsql_pivot_verifier.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_select_verifier.h"
#include "ctsql_func.h"

#ifdef __cplusplus
extern "C" {
#endif


static inline void sql_delete_rs_by_name(galist_t *rs_cols, text_t *name)
{
    rs_column_t *rs_col = NULL;

    for (int32 i = rs_cols->count - 1; i >= 0; i--) {
        rs_col = cm_galist_get(rs_cols, (uint32)i);
        if (cm_text_equal(&rs_col->name, name)) {
            cm_galist_delete(rs_cols, (uint32)i);
            break;
        }
    }
}

static status_t sql_pivot_gen_group_expr(sql_verifier_t *verif, rs_column_t *rs)
{
    expr_tree_t *expr = NULL;
    CT_RETURN_IFERR(sql_alloc_mem(verif->context, sizeof(expr_tree_t), (void **)&rs->expr));
    expr = rs->expr;
    expr->owner = verif->context;
    CT_RETURN_IFERR(sql_alloc_mem(verif->context, sizeof(expr_node_t), (void **)&expr->root));
    expr->root->owner = expr;
    expr->root->type = EXPR_NODE_COLUMN;
    expr->root->dis_info.need_distinct = CT_FALSE;
    expr->root->format_json = CT_FALSE;
    expr->root->word.column.name.value = rs->name;
    expr->root->word.column.ss_start = CT_INVALID_ID32;
    expr->root->typmod = rs->typmod;
    return CT_SUCCESS;
}

static status_t sql_pivot_gen_aggr_rs_name(sql_context_t *sql_ctx, pivot_items_t *pivot_items, uint32 pos, text_t **name)
{
    uint32 aggr_index = pos % pivot_items->aggr_count;
    uint32 alias_index = pos / pivot_items->aggr_count;
    text_t *aggr_alias = cm_galist_get(pivot_items->aggr_alias, aggr_index);
    text_t *alias = cm_galist_get(pivot_items->alias, alias_index);
    char *char_pos = NULL;

    if (aggr_alias->len == 0) {
        *name = alias;
    } else {
        CT_RETURN_IFERR(sql_alloc_mem(sql_ctx, sizeof(text_t), (void **)name));
        (*name)->len = MIN(CT_MAX_NAME_LEN, aggr_alias->len + alias->len + 1);
        CT_RETURN_IFERR(sql_alloc_mem(sql_ctx, (*name)->len, (void **)&(*name)->str));
        char_pos = (*name)->str;
        MEMS_RETURN_IFERR(memcpy_sp(char_pos, (*name)->len, alias->str, alias->len));
        char_pos += alias->len;
        *char_pos = '_';
        char_pos++;
        MEMS_RETURN_IFERR(memcpy_sp(char_pos, aggr_alias->len, aggr_alias->str, aggr_alias->len));
    }

    return CT_SUCCESS;
}

static status_t sql_pivot_gen_aggr_rs(sql_context_t *sql_ctx, pivot_items_t *pivot_items)
{
    rs_column_t *pivot_rs = NULL;
    text_t *rs_name = NULL;
    expr_tree_t *expr = NULL;

    for (uint32 i = 0; i < pivot_items->aggrs->count; i++) {
        if (i % pivot_items->aggr_count == 0) {
            expr = pivot_items->aggr_expr;
        }
        CM_ASSERT(expr != NULL);
        CT_RETURN_IFERR(cm_galist_new(pivot_items->pivot_rs_columns, sizeof(rs_column_t), (pointer_t *)&pivot_rs));
        CT_RETURN_IFERR(sql_alloc_mem(sql_ctx, sizeof(expr_tree_t), (void **)&pivot_rs->expr));
        *pivot_rs->expr = *expr;
        CT_RETURN_IFERR(sql_alloc_mem(sql_ctx, sizeof(expr_node_t), (void **)&pivot_rs->expr->root));
        *pivot_rs->expr->root = *expr->root;
        pivot_rs->expr->root->value.v_int = i;
        pivot_rs->type = RS_COL_CALC;
        CT_BIT_SET(pivot_rs->rs_flag, RS_NULLABLE);
        pivot_rs->typmod = expr->root->typmod;
        CT_RETURN_IFERR(sql_pivot_gen_aggr_rs_name(sql_ctx, pivot_items, i, &rs_name));
        pivot_rs->name = *rs_name;
        expr = expr->next;
    }
    return CT_SUCCESS;
}

static void sql_pivot_remove_rs_by_expr(expr_tree_t *expr, galist_t *rs)
{
    cols_used_t cols_used;
    biqueue_t *cols_que = NULL;
    biqueue_node_t *curr_node = NULL;
    biqueue_node_t *end_node = NULL;
    expr_node_t *col = NULL;
    expr_node_t *node = NULL;

    while (expr != NULL) {
        node = expr->root;
        init_cols_used(&cols_used);
        cols_used.collect_sub_select = CT_FALSE;
        sql_collect_cols_in_expr_node(node, &cols_used);
        cols_que = &cols_used.cols_que[SELF_IDX];
        curr_node = biqueue_first(cols_que);
        end_node = biqueue_end(cols_que);
        while (curr_node != end_node) {
            col = OBJECT_OF(expr_node_t, curr_node);
            sql_delete_rs_by_name(rs, &col->word.column.name.value);
            curr_node = curr_node->next;
        }
        expr = expr->next;
    }
}

static status_t sql_pivot_remove_rs(sql_stmt_t *stmt, pivot_items_t *pivot_items)
{
    expr_node_t *aggr = NULL;
    expr_tree_t *pivot_tree = pivot_items->for_expr;
    sort_item_t *sort_item = NULL;

    for (uint32 i = 0; i < pivot_items->aggr_count; i++) {
        aggr = cm_galist_get(pivot_items->aggrs, i);
        sql_pivot_remove_rs_by_expr(aggr->argument, pivot_items->pivot_rs_columns);

        if (aggr->sort_items != NULL && aggr->sort_items->count > 0) {
            for (uint32 j = 0; j < aggr->sort_items->count; j++) {
                sort_item = cm_galist_get(aggr->sort_items, j);
                sql_pivot_remove_rs_by_expr(sort_item->expr, pivot_items->pivot_rs_columns);
            }
        }
    }

    while (pivot_tree != NULL) {
        sql_delete_rs_by_name(pivot_items->pivot_rs_columns, &pivot_tree->root->word.column.name.value);
        pivot_tree = pivot_tree->next;
    }
    return CT_SUCCESS;
}

static status_t sql_pivot_gen_group_set(sql_verifier_t *verif, pivot_items_t *pivot_items, group_set_t *group_set)
{
    rs_column_t *pivot_rs = NULL;
    expr_tree_t *expr = NULL;
    expr_node_t *node = NULL;
    uint32 ori_excl_flags = verif->excl_flags;

    verif->excl_flags = SQL_GROUP_BY_EXCL;
    for (uint32 i = 0; i < pivot_items->pivot_rs_columns->count; i++) {
        pivot_rs = (rs_column_t *)cm_galist_get(pivot_items->pivot_rs_columns, i);
        CT_RETURN_IFERR(sql_pivot_gen_group_expr(verif, pivot_rs));
        pivot_rs->type = RS_COL_CALC;
        CT_RETURN_IFERR(sql_verify_expr(verif, pivot_rs->expr));
        CT_RETURN_IFERR(sql_alloc_mem(verif->context, sizeof(expr_tree_t), (void **)&expr));
        CT_RETURN_IFERR(sql_alloc_mem(verif->context, sizeof(expr_node_t), (void **)&node));
        *expr = *pivot_rs->expr;
        *node = *pivot_rs->expr->root;
        expr->root = node;
        CT_RETURN_IFERR(sql_set_group_expr_node(verif->stmt, pivot_rs->expr->root, i, 0, 0, expr->root));
        CT_RETURN_IFERR(cm_galist_insert(group_set->items, expr));
    }
    verif->excl_flags = ori_excl_flags;
    return CT_SUCCESS;
}

static status_t sql_gen_pivot_items(sql_verifier_t *verif, sql_query_t *query)
{
    galist_t *query_rs_columns = query->rs_columns;
    galist_t *query_group_sets = query->group_sets;
    pivot_items_t *pivot_items = query->pivot_items;
    group_set_t *group_set = NULL;

    CT_RETURN_IFERR(sql_alloc_mem(verif->context, sizeof(galist_t), (void **)&pivot_items->group_sets));
    cm_galist_init(pivot_items->group_sets, verif->context, sql_alloc_mem);
    CT_RETURN_IFERR(cm_galist_new(pivot_items->group_sets, sizeof(group_set_t), (void **)&group_set));
    group_set->group_id = 0;
    CT_RETURN_IFERR(sql_alloc_mem(verif->context, sizeof(galist_t), (void **)&group_set->items));
    cm_galist_init(group_set->items, verif->context, sql_alloc_mem);

    pivot_items->pivot_rs_columns = query->rs_columns;
    CT_RETURN_IFERR(sql_pivot_remove_rs(verif->stmt, pivot_items));
    CT_RETURN_IFERR(sql_pivot_gen_group_set(verif, pivot_items, group_set));
    query->group_sets = pivot_items->group_sets;
    CT_RETURN_IFERR(sql_normalize_group_sets(verif->stmt, query));
    CT_RETURN_IFERR(sql_pivot_gen_aggr_rs(verif->context, pivot_items));

    query->group_sets = query_group_sets;
    query->rs_columns = query_rs_columns;

    return CT_SUCCESS;
}

static status_t sql_gen_pivot_aggrs(sql_verifier_t *verif, sql_query_t *query)
{
    expr_node_t *aggr_origin = NULL;
    pivot_items_t *pivot_item = query->pivot_items;
    uint32 group_count, aggr_count, i, j;

    aggr_count = query->pivot_items->aggr_count;
    group_count = sql_expr_list_len(pivot_item->in_expr) / sql_expr_list_len(pivot_item->for_expr);
    for (i = 0; i < group_count; i++) {
        if (aggr_count == query->aggrs->count) {
            for (j = 0; j < aggr_count; j++) {
                aggr_origin = (expr_node_t *)cm_galist_get(query->aggrs, j);
                CT_RETURN_IFERR(cm_galist_insert(pivot_item->aggrs, aggr_origin));
            }
        } else {
            expr_tree_t *aggr_expr = pivot_item->aggr_expr;
            uint32 aggr_id;
            while (aggr_expr != NULL) {
                aggr_id = aggr_expr->root->value.v_uint32;
                aggr_origin = (expr_node_t *)cm_galist_get(query->aggrs, aggr_id);
                CT_RETURN_IFERR(cm_galist_insert(pivot_item->aggrs, aggr_origin));
                aggr_expr = aggr_expr->next;
            }
        }
    }
    return CT_SUCCESS;
}

static status_t sql_verify_pivot_aggr_type(expr_node_t *node)
{
    sql_aggr_type_t aggr_type = g_func_tab[node->value.v_func.func_id].aggr_type;
    switch (aggr_type) {
        case AGGR_TYPE_AVG:
        case AGGR_TYPE_ARRAY_AGG:
        case AGGR_TYPE_CUME_DIST:
        case AGGR_TYPE_COUNT:
        case AGGR_TYPE_COVAR_POP:
        case AGGR_TYPE_COVAR_SAMP:
        case AGGR_TYPE_CORR:
        case AGGR_TYPE_DENSE_RANK:
        case AGGR_TYPE_SUM:
        case AGGR_TYPE_MIN:
        case AGGR_TYPE_MAX:
        case AGGR_TYPE_GROUP_CONCAT:
        case AGGR_TYPE_STDDEV:
        case AGGR_TYPE_STDDEV_POP:
        case AGGR_TYPE_STDDEV_SAMP:
        case AGGR_TYPE_MEDIAN:
        case AGGR_TYPE_VARIANCE:
        case AGGR_TYPE_VAR_POP:
        case AGGR_TYPE_VAR_SAMP:
        case AGGR_TYPE_RANK:
            return CT_SUCCESS;
        default:
            CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unsupported aggr type in pivot");
            return CT_ERROR;
    }
}

static status_t sql_verify_pivot_aggrs_type(galist_t *aggrs)
{
    expr_node_t *aggr_node = NULL;
    for (uint32 i = 0; i < aggrs->count; i++) {
        aggr_node = (expr_node_t *)cm_galist_get(aggrs, i);
        CT_RETURN_IFERR(sql_verify_pivot_aggr_type(aggr_node));
    }
    return CT_SUCCESS;
}

status_t sql_verify_query_pivot(sql_verifier_t *verif, sql_query_t *query)
{
    if (query->pivot_items == NULL || query->pivot_items->type != PIVOT_TYPE) {
        return CT_SUCCESS;
    }

    pivot_items_t *pivot_items = query->pivot_items;
    expr_tree_t *aggr_expr = pivot_items->aggr_expr;
    expr_tree_t *for_expr = pivot_items->for_expr;
    expr_tree_t *in_expr = pivot_items->in_expr;
    uint32 aggr_flags = verif->aggr_flags;

    verif->aggr_flags = SQL_GEN_AGGR_FROM_COLUMN;

    CT_RETURN_IFERR(sql_verify_expr(verif, aggr_expr));
    pivot_items->aggr_count = 0;
    while (aggr_expr != NULL) {
        pivot_items->aggr_count++;
        if (aggr_expr->root->type != EXPR_NODE_AGGR) {
            CT_THROW_ERROR(ERR_EXPECTED_AGGR_FUNTION, T2S(&aggr_expr->root->word.column.name.value));
            return CT_ERROR;
        }
        aggr_expr = aggr_expr->next;
    }
    CT_RETURN_IFERR(sql_verify_pivot_aggrs_type(query->aggrs));

    verif->aggr_flags = aggr_flags;
    CT_RETURN_IFERR(sql_verify_expr(verif, pivot_items->for_expr));

    while (for_expr != NULL) {
        if (for_expr->root->type != EXPR_NODE_COLUMN) {
            CT_SRC_THROW_ERROR(for_expr->loc, ERR_SQL_SYNTAX_ERROR, "expect simple column specification here");
            return CT_ERROR;
        } else if (for_expr->root->word.column.table.len > 0) {
            CT_SRC_THROW_ERROR(for_expr->loc, ERR_SQL_SYNTAX_ERROR, "simple column name only");
            return CT_ERROR;
        }
        for_expr = for_expr->next;
    }

    CT_RETURN_IFERR(sql_gen_pivot_aggrs(verif, query));
    CT_RETURN_IFERR(sql_gen_pivot_items(verif, query));

    CT_RETURN_IFERR(sql_verify_expr(verif, pivot_items->in_expr));
    while (in_expr != NULL) {
        if (in_expr->root->type != EXPR_NODE_CONST && in_expr->root->datatype != CT_TYPE_BOOLEAN) {
            CT_SRC_THROW_ERROR(in_expr->loc, ERR_SQL_SYNTAX_ERROR, "pivot expr only allow const");
            return CT_ERROR;
        }
        in_expr = in_expr->next;
    }

    return CT_SUCCESS;
}

static status_t sql_unpivot_rebuild_data_rs(sql_verifier_t *verif, sql_query_t *query)
{
    expr_tree_t *expr = NULL;
    rs_column_t *rs_col = NULL;
    pivot_items_t *pivot_item = query->pivot_items;
    galist_t *group_exprs = NULL;
    text_t *name = NULL;

    group_exprs = cm_galist_get(pivot_item->group_sets, 0);
    for (uint32 i = 0; i < group_exprs->count; i++) {
        expr = cm_galist_get(group_exprs, i);
        if (i < pivot_item->unpivot_alias_rs->count) {
            name = cm_galist_get(pivot_item->unpivot_alias_rs, i);
        } else {
            name = cm_galist_get(pivot_item->unpivot_data_rs, i - pivot_item->unpivot_alias_rs->count);
        }

        CT_RETURN_IFERR(sql_alloc_mem(verif->context, sizeof(rs_column_t), (void **)&rs_col));
        CT_RETURN_IFERR(sql_alloc_mem(verif->context, sizeof(expr_tree_t), (void **)&rs_col->expr));
        CT_RETURN_IFERR(sql_alloc_mem(verif->context, sizeof(expr_node_t), (void **)&rs_col->expr->root));
        rs_col->typmod = expr->root->typmod;
        rs_col->expr->root->typmod = rs_col->typmod;
        rs_col->type = RS_COL_CALC;
        rs_col->name = *name;
        CT_BIT_SET(rs_col->rs_flag, RS_NULLABLE);

        CT_RETURN_IFERR(sql_set_group_expr_node(verif->stmt, rs_col->expr->root, i, 0, 0, expr->root));
        CT_RETURN_IFERR(cm_galist_insert(query->rs_columns, rs_col));
    }

    return CT_SUCCESS;
}

static status_t sql_unpivot_verify_rs_col(sql_verifier_t *verif, sql_query_t *query, galist_t *group_exprs,
    uint32 row_id)
{
    pivot_items_t *pivot_item = query->pivot_items;
    text_t *name = NULL;
    rs_column_t *rs_col = NULL;
    bool32 column_exist = CT_FALSE;

    for (uint32 j = 0; j < pivot_item->unpivot_data_rs->count; j++) {
        name = cm_galist_get(pivot_item->column_name, pivot_item->unpivot_data_rs->count * row_id + j);
        column_exist = CT_FALSE;
        for (uint32 k = 0; k < query->rs_columns->count; k++) {
            rs_col = cm_galist_get(query->rs_columns, k);
            if (cm_text_equal(&rs_col->name, name)) {
                column_exist = CT_TRUE;
                CT_RETURN_IFERR(sql_pivot_gen_group_expr(verif, rs_col));
                CT_RETURN_IFERR(sql_verify_expr(verif, rs_col->expr));
                CT_RETURN_IFERR(cm_galist_insert(group_exprs, rs_col->expr));
                break;
            }
        }

        if (!column_exist) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "invalid column name %s", T2S(name));
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_unpivot_rebuild_rs(sql_verifier_t *verif, sql_query_t *query)
{
    pivot_items_t *pivot_items = query->pivot_items;
    text_t *name = NULL;
    expr_tree_t *alias_expr = NULL;
    rs_column_t *rs_col = NULL;
    galist_t *group_exprs = NULL;
    uint32 i;
    uint32 rows = pivot_items->column_name->count / pivot_items->unpivot_data_rs->count;

    for (i = 0; i < rows; i++) {
        CT_RETURN_IFERR(cm_galist_new(pivot_items->group_sets, sizeof(galist_t), (void **)&group_exprs));
        cm_galist_init(group_exprs, verif->context, sql_alloc_mem);
        for (uint32 j = 0; j < pivot_items->unpivot_alias_rs->count; j++) {
            alias_expr = cm_galist_get(pivot_items->alias, pivot_items->unpivot_alias_rs->count * i + j);
            CT_RETURN_IFERR(sql_verify_expr(verif, alias_expr));
            if (alias_expr->root->type != EXPR_NODE_CONST && alias_expr->root->datatype != CT_TYPE_BOOLEAN) {
                CT_SRC_THROW_ERROR(alias_expr->loc, ERR_SQL_SYNTAX_ERROR, "unpivot expr only allow const");
                return CT_ERROR;
            }
            CT_RETURN_IFERR(cm_galist_insert(group_exprs, alias_expr));
        }

        CT_RETURN_IFERR(sql_unpivot_verify_rs_col(verif, query, group_exprs, i));
    }

    for (i = 0; i < pivot_items->column_name->count; i++) {
        name = cm_galist_get(pivot_items->column_name, i);
        for (uint32 j = 0; j < query->rs_columns->count; j++) {
            rs_col = cm_galist_get(query->rs_columns, j);
            if (cm_text_equal(&rs_col->name, name)) {
                cm_galist_delete(query->rs_columns, j);
                break;
            }
        }
    }

    CT_RETURN_IFERR(sql_unpivot_rebuild_data_rs(verif, query));
    return CT_SUCCESS;
}

static status_t sql_verify_unpivot_columns_datatype(sql_query_t *query)
{
    pivot_items_t *pivot_item = query->pivot_items;
    galist_t *group_exprs = NULL;
    expr_tree_t *expr = NULL;
    typmode_t *type = NULL;
    uint32 new_rs_cnt = pivot_item->unpivot_data_rs->count + pivot_item->unpivot_alias_rs->count;
    uint32 rows = pivot_item->group_sets->count;
    uint32 rs_pos = query->rs_columns->count - new_rs_cnt;
    uint32 i;

    for (i = 0; i < new_rs_cnt; i++) {
        type = &((rs_column_t *)cm_galist_get(query->rs_columns, rs_pos + i))->typmod;
        for (uint32 j = 1; j < rows; j++) {
            group_exprs = cm_galist_get(pivot_item->group_sets, j);
            expr = cm_galist_get(group_exprs, group_exprs->count - new_rs_cnt + i);
            if (type->datatype != expr->root->typmod.datatype) {
                CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "datatype different");
                return CT_ERROR;
            }
            if (type->size < expr->root->typmod.size) {
                type->size = expr->root->typmod.size;
            }
            if (type->precision < expr->root->typmod.precision) {
                type->precision = expr->root->typmod.precision;
            }
            if (type->scale < expr->root->typmod.scale) {
                type->scale = expr->root->typmod.scale;
            }
        }
    }

    return CT_SUCCESS;
}

status_t sql_verify_query_unpivot(sql_verifier_t *verif, sql_query_t *query)
{
    if (query->pivot_items == NULL || query->pivot_items->type != UNPIVOT_TYPE) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_unpivot_rebuild_rs(verif, query));
    CT_RETURN_IFERR(sql_verify_unpivot_columns_datatype(query));
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif