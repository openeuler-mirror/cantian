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
 * ctsql_order_verifier.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/verifier/ctsql_order_verifier.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_func.h"
#include "srv_instance.h"
#include "dml_parser.h"
#include "ctsql_cond_rewrite.h"

#ifdef __cplusplus
extern "C" {
#endif


static inline status_t add_query_field_for_order(visit_assist_t *visit_ass, expr_node_t **node)
{
    sql_query_t *query = NULL;
    sql_select_t *subslct = NULL;

    if ((*node)->type == EXPR_NODE_COLUMN) {
        sql_table_t *table = NULL;
        query_field_t query_field;
        var_column_t *v_col = &(*node)->value.v_col;

        if (!get_specified_level_query(visit_ass->query, v_col->ancestor, &query, &subslct)) {
            CT_THROW_ERROR(ERR_ANCESTOR_LEVEL_MISMATCH);
            return CT_ERROR;
        }

        table = (sql_table_t *)sql_array_get(&query->tables, v_col->tab);
        SQL_SET_QUERY_FIELD_INFO(&query_field, v_col->datatype, v_col->col, v_col->is_array, v_col->ss_start,
            v_col->ss_end);
        return sql_table_cache_query_field(visit_ass->stmt, table, &query_field);
    } else if ((*node)->type == EXPR_NODE_GROUP) {
        // in verify stage, origin_ref should be stable
        expr_node_t *origin_ref = sql_get_origin_ref(*node);
        return visit_expr_node(visit_ass, &origin_ref, add_query_field_for_order);
    }

    if (NODE_IS_RES_ROWID(*node) && ROWID_NODE_ANCESTOR(*node) > 0) {
        var_rowid_t *v_rid = &(*node)->value.v_rid;
        if (!get_specified_level_query(visit_ass->query, v_rid->ancestor, &query, &subslct)) {
            CT_THROW_ERROR(ERR_ANCESTOR_LEVEL_MISMATCH);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

static inline status_t sql_set_expr_from_rs_col(sql_stmt_t *stmt, sql_query_t *query, rs_column_t *rs_col,
    expr_node_t **node, bool32 is_aggr)
{
    source_location_t loc = NODE_LOC(*node);
    if (rs_col->type == RS_COL_COLUMN) {
        (*node)->type = EXPR_NODE_COLUMN;
        (*node)->value.type = CT_TYPE_COLUMN;

        var_column_t *v_col = VALUE_PTR(var_column_t, &(*node)->value);
        v_col->tab = rs_col->v_col.tab;
        v_col->col = rs_col->v_col.col;
        v_col->ancestor = rs_col->v_col.ancestor;
        v_col->datatype = rs_col->datatype;
        v_col->is_jsonb = rs_col->v_col.is_jsonb;
        (*node)->size = rs_col->size;
        (*node)->datatype = rs_col->datatype;
        if ((*node)->word.column.ss_start > 0 && (*node)->word.column.ss_end == CT_INVALID_ID32) {
            (*node)->typmod.is_array = CT_FALSE;
            v_col->is_array = CT_FALSE;
            v_col->ss_start = (*node)->word.column.ss_start;
            v_col->ss_end = (*node)->word.column.ss_end;
        } else {
            (*node)->typmod.is_array = rs_col->v_col.is_array;
            v_col->is_array = rs_col->v_col.is_array;
            v_col->ss_start = rs_col->v_col.ss_start;
            v_col->ss_end = rs_col->v_col.ss_end;
        }
    } else {
        if (IS_APP_CONN(stmt->session) && stmt->context->has_sharding_tab && !is_aggr) {
            (*node) = rs_col->expr->root;
        } else {
            CT_RETURN_IFERR(sql_clone_expr_node(stmt->context, rs_col->expr->root, node, sql_alloc_mem));
            NODE_LOC(*node) = loc;
        }
        if (is_aggr) {
            CT_RETURN_IFERR(replace_group_expr_node(stmt, node));
        }
    }
    (*node)->has_verified = CT_TRUE;
    if (!IS_APP_CONN(stmt->session) || !stmt->context->has_sharding_tab) {
        visit_assist_t visit_ass;
        sql_init_visit_assist(&visit_ass, stmt, query);
        CT_RETURN_IFERR(visit_expr_node(&visit_ass, node, add_query_field_for_order));
    }
    return CT_SUCCESS;
}

static status_t add_expr_func_node(visit_assist_t *visit_ass, expr_node_t **node)
{
    CT_RETURN_IFERR(sql_add_ref_func_node((sql_verifier_t *)(visit_ass->param0), *node));
    if ((*node)->type == EXPR_NODE_FUNC) {
        return visit_func_node(visit_ass, *node, add_expr_func_node);
    } else if ((*node)->type == EXPR_NODE_GROUP) {
        expr_node_t *origin_ref = sql_get_origin_ref(*node);
        return visit_expr_node(visit_ass, &origin_ref, add_expr_func_node);
    }
    return CT_SUCCESS;
}

static status_t sql_add_func_node_in_expr(sql_verifier_t *verif, sql_query_t *query, expr_tree_t *expr)
{
    visit_assist_t visit_ass;
    sql_init_visit_assist(&visit_ass, verif->stmt, query);
    visit_ass.param0 = (void *)verif;
    visit_ass.excl_flags = VA_EXCL_FUNC;
    return visit_expr_tree(&visit_ass, expr, add_expr_func_node);
}

static status_t sql_add_func_node_in_expr_node(sql_verifier_t *verif, sql_query_t *query, expr_node_t **node)
{
    visit_assist_t visit_ass;
    sql_init_visit_assist(&visit_ass, verif->stmt, query);
    visit_ass.param0 = (void *)verif;
    visit_ass.excl_flags = VA_EXCL_FUNC;
    return visit_expr_node(&visit_ass, node, add_expr_func_node);
}

static status_t sql_check_const_sort(sql_verifier_t *verif, sql_query_t *query, sort_item_t *sort_item, bool32 *is_found)
{
    bool32 is_array = CT_FALSE;
    rs_column_t *rs_col = NULL;
    expr_node_t *node = sort_item->expr->root;

    *is_found = CT_FALSE;
    if (!NODE_IS_CONST(node) || !CT_IS_NUMERIC_TYPE(node->value.type)) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(var_as_floor_integer(&node->value));

    if (node->value.v_int > (int32)query->rs_columns->count || node->value.v_int < 1) {
        CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR,
            "ORDER BY item must be the number of a SELECT-list expression");
        return CT_ERROR;
    }

    rs_col = (rs_column_t *)cm_galist_get(query->rs_columns, node->value.v_int - 1);
    if (rs_col->type == RS_COL_CALC && rs_col->expr->root->type == EXPR_NODE_PRIOR) {
        is_array = rs_col->expr->root->right->typmod.is_array;
    } else {
        is_array = rs_col->typmod.is_array;
    }

    /* not support now: order by array */
    if ((verif->excl_flags & SQL_EXCL_ARRAY) && is_array == CT_TRUE) {
        CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected array expression");
        return CT_ERROR;
    }
    CT_RETURN_IFERR(sql_set_expr_from_rs_col(verif->stmt, query, rs_col, &sort_item->expr->root, CT_FALSE));
    CT_RETURN_IFERR(sql_add_func_node_in_expr(verif, query, sort_item->expr));
    *is_found = CT_TRUE;
    return CT_SUCCESS;
}

static bool32 sql_match_sort_columns(rs_column_t *rs_col, column_word_t *sort_col)
{
    int32 ss_start = CT_INVALID_ID32;
    int32 ss_end = CT_INVALID_ID32;
    expr_node_t *expr = NULL;

    if (!cm_text_equal(&rs_col->name, &sort_col->name.value)) {
        return CT_FALSE;
    }

    if (CT_BIT_TEST(rs_col->rs_flag, RS_EXIST_ALIAS)) {
        return CT_TRUE;
    }

    /* compare array subscript */
    if (rs_col->type == RS_COL_COLUMN) {
        ss_start = rs_col->v_col.ss_start;
        ss_end = rs_col->v_col.ss_end;
    } else if (rs_col->expr->root->type == EXPR_NODE_GROUP) {
        expr = sql_get_origin_ref(rs_col->expr->root);
        if (expr->type == EXPR_NODE_COLUMN) {
            ss_start = expr->value.v_col.ss_start;
            ss_end = expr->value.v_col.ss_end;
        }
    }

    return (bool32)(ss_start == sort_col->ss_start && ss_end == sort_col->ss_end);
}

static bool32 sql_match_sort_column_in_rs_column(sql_query_t *query, column_word_t *sort_col, rs_column_t *rs_col)
{
    rs_column_t *dis_col = NULL;
    expr_tree_t *group_expr = NULL;
    group_set_t *group_set = NULL;

    if (!CT_BIT_TEST(rs_col->rs_flag, RS_EXIST_ALIAS) && rs_col->type != RS_COL_COLUMN) {
        // If the column in group by list, the column type will be
        // converted to RS_COL_CALC, and its root node type is EXPR_NODE_GROUP
        if (rs_col->expr->root->type != EXPR_NODE_GROUP) {
            return CT_FALSE;
        }
        // If distinct exists, the column may not in group_exprs
        // e.g. select distinct f1, avg(f2) from t1 group by f1 order by f1
        uint32 id = NODE_VM_ID(rs_col->expr->root);
        uint32 group_id = NODE_VM_GROUP(rs_col->expr->root);
        if (query->has_distinct && id < query->distinct_columns->count && group_id == 0) {
            dis_col = (rs_column_t *)cm_galist_get(query->distinct_columns, id);
            CT_RETVALUE_IFTRUE(dis_col->type != RS_COL_COLUMN, CT_FALSE);
        } else if (group_id < query->group_sets->count) {
            group_set = (group_set_t *)cm_galist_get(query->group_sets, group_id);
            if (id < group_set->items->count) {
                group_expr = (expr_tree_t *)cm_galist_get(group_set->items, id);
                CT_RETVALUE_IFTRUE(group_expr->root->type != EXPR_NODE_COLUMN, CT_FALSE);
            }
        } else {
            return CT_FALSE;
        }
    }
    return sql_match_sort_columns(rs_col, sort_col);
}

static status_t sql_search_expr_in_rs_col_alias(sql_verifier_t *verif, sql_query_t *query, expr_node_t **node,
    bool32 *is_aggr, bool32 *is_found, bool32 *exist_alias);
static status_t sql_search_cond_in_rs_col_alias(sql_verifier_t *verif, sql_query_t *query, cond_node_t *cond,
    bool32 *is_aggr, bool32 *is_found, bool32 *exist_alias)
{
    CT_RETURN_IFERR(sql_stack_safe(verif->stmt));
    if (cond == NULL) {
        return CT_SUCCESS;
    }
    switch (cond->type) {
        case COND_NODE_COMPARE:
            if (cond->cmp->left != NULL) {
                CT_RETURN_IFERR(sql_search_expr_in_rs_col_alias(verif, query, &cond->cmp->left->root, is_aggr, is_found,
                    exist_alias));
            }
            if (cond->cmp->right != NULL) {
                CT_RETURN_IFERR(sql_search_expr_in_rs_col_alias(verif, query, &cond->cmp->right->root, is_aggr, is_found,
                    exist_alias));
            }
            break;
        case COND_NODE_OR:
        case COND_NODE_AND:
            CT_RETURN_IFERR(sql_search_cond_in_rs_col_alias(verif, query, cond->left, is_aggr, is_found, exist_alias));
            CT_RETURN_IFERR(sql_search_cond_in_rs_col_alias(verif, query, cond->right, is_aggr, is_found, exist_alias));
            break;
        default:
            break;
    }
    return CT_SUCCESS;
}

static status_t sql_search_node_in_rs_col_alias(sql_verifier_t *verif, sql_query_t *query, expr_node_t **expr,
    bool32 *is_aggr, bool32 *is_found, bool32 *exist_alias)
{
    galist_t *rs_columns = query->rs_columns;
    rs_column_t *rs_col = NULL;
    column_word_t sort_col;
    *is_found = CT_FALSE;

    if ((*expr)->type == EXPR_NODE_COLUMN && (*expr)->word.table.name.len == 0) {
        sort_col = (*expr)->word.column;
    } else if (NODE_IS_CONST((*expr)) && CT_IS_STRING_TYPE((*expr)->value.type)) {
        sort_col.name.value = (*expr)->value.v_text;
        sort_col.ss_start = CT_INVALID_ID32;
        sort_col.ss_end = CT_INVALID_ID32;
    } else {
        return CT_SUCCESS;
    }
    for (uint32 i = 0; i < rs_columns->count; ++i) {
        rs_col = (rs_column_t *)cm_galist_get(rs_columns, i);
        if (sql_match_sort_column_in_rs_column(query, &sort_col, rs_col)) {
            if (*is_found) {
                CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "ambiguous column naming in select list");
                return CT_ERROR;
            }
            CT_RETURN_IFERR(sql_set_expr_from_rs_col(verif->stmt, query, rs_col, expr, *is_aggr));
            CT_RETURN_IFERR(sql_add_func_node_in_expr_node(verif, query, expr));
            *is_found = CT_TRUE;
            *exist_alias = CT_TRUE;
        }
    }
    return CT_SUCCESS;
}

static status_t sql_search_arg_list_in_rs_col_alias(sql_verifier_t *verif, sql_query_t *query, expr_tree_t *arg,
    bool32 *is_aggr, bool32 *is_found, bool32 *exist_alias)
{
    expr_tree_t *match_arg = arg;
    while (match_arg != NULL) {
        CT_RETURN_IFERR(sql_search_expr_in_rs_col_alias(verif, query, &match_arg->root, is_aggr, is_found, exist_alias));
        match_arg = match_arg->next;
    }
    return CT_SUCCESS;
}

static status_t sql_search_case_expr_in_rs_col_alias(sql_verifier_t *verif, sql_query_t *query, expr_node_t **node,
    bool32 *is_aggr, bool32 *is_found, bool32 *exist_alias)
{
    case_pair_t *pair = NULL;

    case_expr_t *case_expr = (case_expr_t *)VALUE(pointer_t, &(*node)->value);
    if (!case_expr->is_cond) {
        CT_RETURN_IFERR(
            sql_search_expr_in_rs_col_alias(verif, query, &case_expr->expr->root, is_aggr, is_found, exist_alias));
        for (uint32 i = 0; i < case_expr->pairs.count; i++) {
            pair = (case_pair_t *)cm_galist_get(&case_expr->pairs, i);
            CT_RETURN_IFERR(
                sql_search_expr_in_rs_col_alias(verif, query, &pair->when_expr->root, is_aggr, is_found, exist_alias));
            CT_RETURN_IFERR(
                sql_search_expr_in_rs_col_alias(verif, query, &pair->value->root, is_aggr, is_found, exist_alias));
        }
    } else {
        for (uint32 i = 0; i < case_expr->pairs.count; i++) {
            pair = (case_pair_t *)cm_galist_get(&case_expr->pairs, i);
            CT_RETURN_IFERR(
                sql_search_cond_in_rs_col_alias(verif, query, pair->when_cond->root, is_aggr, is_found, exist_alias));
            CT_RETURN_IFERR(
                sql_search_expr_in_rs_col_alias(verif, query, &pair->value->root, is_aggr, is_found, exist_alias));
        }
    }
    if (case_expr->default_expr != NULL) {
        CT_RETURN_IFERR(sql_search_expr_in_rs_col_alias(verif, query, &case_expr->default_expr->root, is_aggr, is_found,
            exist_alias));
    }
    return CT_SUCCESS;
}

static inline status_t sql_search_func_expr_in_rs_col_alias(sql_verifier_t *verif, sql_query_t *query,
    expr_node_t **node, bool32 *is_aggr, bool32 *is_found, bool32 *exist_alias)
{
    uint32 func_id = sql_get_func_id((text_t *)&(*node)->word.func.name);
    if (func_id != CT_INVALID_ID32 && g_func_tab[func_id].aggr_type != AGGR_TYPE_NONE) {
        *is_aggr = CT_TRUE;
    } else if ((func_id == ID_FUNC_ITEM_IF || func_id == ID_FUNC_ITEM_LNNVL) && (*node)->cond_arg != NULL) {
        CT_RETURN_IFERR(
            sql_search_cond_in_rs_col_alias(verif, query, (*node)->cond_arg->root, is_aggr, is_found, exist_alias));
    }
    CT_RETURN_IFERR(
        sql_search_arg_list_in_rs_col_alias(verif, query, (*node)->argument, is_aggr, is_found, exist_alias));
    *is_aggr = CT_FALSE;
    return CT_SUCCESS;
}

static status_t sql_search_expr_in_rs_col_alias(sql_verifier_t *verif, sql_query_t *query, expr_node_t **node,
    bool32 *is_aggr, bool32 *is_found, bool32 *exist_alias) // search alias
{
    CT_RETURN_IFERR(sql_stack_safe(verif->stmt));
    switch ((*node)->type) {
        case EXPR_NODE_COLUMN:
        case EXPR_NODE_CONST:
            return sql_search_node_in_rs_col_alias(verif, query, node, is_aggr, is_found, exist_alias);
        case EXPR_NODE_ADD:
        case EXPR_NODE_SUB:
        case EXPR_NODE_MUL:
        case EXPR_NODE_DIV:
        case EXPR_NODE_MOD:
        case EXPR_NODE_BITAND:
        case EXPR_NODE_BITOR:
        case EXPR_NODE_BITXOR:
        case EXPR_NODE_CAT:
        case EXPR_NODE_LSHIFT:
        case EXPR_NODE_RSHIFT:
        case EXPR_NODE_OPCEIL:
            CT_RETURN_IFERR(
                sql_search_expr_in_rs_col_alias(verif, query, &(*node)->left, is_aggr, is_found, exist_alias));
            CT_RETURN_IFERR(
                sql_search_expr_in_rs_col_alias(verif, query, &(*node)->right, is_aggr, is_found, exist_alias));
            break;
        case EXPR_NODE_NEGATIVE:
            if ((*node)->right == NULL) {
                CT_SRC_THROW_ERROR((*node)->loc, ERR_SQL_SYNTAX_ERROR, "missing expression");
                return CT_ERROR;
            }
            CT_RETURN_IFERR(
                sql_search_expr_in_rs_col_alias(verif, query, &(*node)->right, is_aggr, is_found, exist_alias));
            break;
        case EXPR_NODE_CASE:
            CT_RETURN_IFERR(sql_search_case_expr_in_rs_col_alias(verif, query, node, is_aggr, is_found, exist_alias));
            break;
        case EXPR_NODE_FUNC:
            CT_RETURN_IFERR(sql_search_func_expr_in_rs_col_alias(verif, query, node, is_aggr, is_found, exist_alias));
            break;
        case EXPR_NODE_USER_FUNC:
            CT_RETURN_IFERR(
                sql_search_arg_list_in_rs_col_alias(verif, query, (*node)->argument, is_aggr, is_found, exist_alias));
            break;
        default:
            break;
    }
    *is_found = CT_FALSE;
    return CT_SUCCESS;
}

static status_t sql_verify_replaced_sort_expr(visit_assist_t *visit_ass, expr_node_t **node)
{
    sql_verifier_t *verif = (sql_verifier_t *)visit_ass->param0;

    if ((*node)->type == EXPR_NODE_AGGR) {
        uint32 aggr_id = (*node)->value.v_uint32;
        expr_node_t *aggr_node = (expr_node_t *)cm_galist_get(visit_ass->query->aggrs, aggr_id);
        if (verif->excl_flags & SQL_EXCL_AGGR) {
            CT_SRC_THROW_ERROR((*node)->loc, ERR_UNEXPECTED_ARRG, T2S(&aggr_node->word.func.name));
            return CT_ERROR;
        }

        uint32 saved_excl_flags = verif->excl_flags;
        verif->excl_flags |= SQL_AGGR_EXCL;
        CT_RETURN_IFERR(visit_expr_tree(visit_ass, aggr_node->argument, sql_verify_replaced_sort_expr));
        verif->excl_flags = saved_excl_flags;
        return CT_SUCCESS;
    }

    return CT_SUCCESS;
}

static status_t sql_verify_replaced_sort_item(sql_verifier_t *verif, sql_query_t *query, sort_item_t *sort_item)
{
    visit_assist_t visit_ass;
    sql_init_visit_assist(&visit_ass, verif->stmt, query);
    visit_ass.excl_flags = VA_EXCL_PRIOR;
    visit_ass.param0 = (void *)verif;

    uint32 saved_excl_flags = verif->excl_flags;

    verif->excl_flags = SQL_ORDER_EXCL | SQL_EXCL_COLL;
    if (query->order_siblings) {
        verif->excl_flags |= (SQL_EXCL_PATH_FUNC | SQL_EXCL_ROWNUM);
    }

    CT_RETURN_IFERR(visit_expr_node(&visit_ass, &sort_item->expr->root, sql_verify_replaced_sort_expr));

    verif->excl_flags = saved_excl_flags;

    return CT_SUCCESS;
}

static status_t sql_verify_sort_item(sql_verifier_t *verif, sql_query_t *query, sort_item_t *item, uint32 old_aggr_count)
{
    bool32 is_found = CT_FALSE;
    bool32 is_aggr = CT_FALSE;
    bool32 exist_alias = CT_FALSE;

    CT_RETURN_IFERR(sql_check_const_sort(verif, query, item, &is_found));

    if (is_found) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_search_expr_in_rs_col_alias(verif, query, &item->expr->root, &is_aggr, &is_found, &exist_alias));
    if (is_found) {
        if ((verif->excl_flags & SQL_EXCL_ARRAY) && item->expr->root->typmod.is_array == CT_TRUE) {
            CT_SRC_THROW_ERROR(item->expr->root->loc, ERR_SQL_SYNTAX_ERROR, "unexpected array expression");
            return CT_ERROR;
        }
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_verify_expr(verif, item->expr));

    if (exist_alias) {
        CT_RETURN_IFERR(sql_verify_replaced_sort_item(verif, query, item));
    }

    if (query->group_sets->count > 0) {
        CT_RETURN_IFERR(sql_match_group_expr(verif->stmt, query, item->expr));
    } else {
        if ((verif->incl_flags & SQL_INCL_AGGR) && old_aggr_count == 0) {
            CT_SRC_THROW_ERROR(item->expr->loc, ERR_UNEXPECTED_ARRG, T2S(&item->expr->root->word.func.name));
            return CT_ERROR;
        }
    }

    if (query->winsort_list->count > 0) {
        CT_RETURN_IFERR(sql_gen_winsort_rs_col_by_expr_tree(verif->stmt, query, item->expr));
    }

    if (query->has_distinct) {
        CT_RETURN_IFERR(sql_match_distinct_expr(verif->stmt, query, &item->expr, CT_FALSE));
    }

#ifdef Z_SHARDING
    if (IS_COORDINATOR) {
        if (item->expr->root->type == EXPR_NODE_SELECT) {
            CT_SRC_THROW_ERROR(item->expr->root->loc, ERR_SQL_SYNTAX_ERROR, "unexpected select expression");
            return CT_ERROR;
        }
    }
#endif

    return CT_SUCCESS;
}

status_t sql_verify_query_order(sql_verifier_t *verif, sql_query_t *query, galist_t *sort_items, bool32 is_query)
{
    uint32 i, old_aggr_count;
    sort_item_t *item = NULL;

    if (sort_items->count == 0) {
        return CT_SUCCESS;
    }

    if (query->order_siblings && query->winsort_list->count > 0) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "ORDER SIBLINGS BY can't exists with winsort functions");
        return CT_ERROR;
    }

    verif->tables = &query->tables;
    verif->aggrs = query->aggrs;
    verif->cntdis_columns = query->cntdis_columns;
    verif->curr_query = query;
    verif->incl_flags = 0;
    verif->excl_flags = SQL_ORDER_EXCL | SQL_EXCL_COLL;
    if (query->order_siblings) {
        verif->excl_flags |= (SQL_EXCL_PATH_FUNC | SQL_EXCL_ROWNUM);
    }
    if (query->aggrs->count > 0 || query->group_sets->count > 0) {
        verif->aggr_flags = SQL_GEN_AGGR_FROM_ORDER;
    }

    old_aggr_count = query->aggrs->count;
    for (i = 0; i < sort_items->count; i++) {
        item = (sort_item_t *)cm_galist_get(sort_items, i);
        CT_RETURN_IFERR(sql_verify_sort_item(verif, query, item, old_aggr_count));
    }

    verif->aggr_flags = 0;

    bool32 has_limit = LIMIT_CLAUSE_OCCUR(&query->limit);
    if (is_query && ((old_aggr_count > 0 && query->group_sets->count == 0) ||
        (query->owner != NULL && query->owner->root->type != SELECT_NODE_QUERY && !has_limit))) {
        cm_galist_reset(sort_items);
    }
    return CT_SUCCESS;
}

static status_t sql_check_const_concat_sort(sql_stmt_t *stmt, expr_tree_t *arg, sort_item_t *sort_item,
    bool32 *is_found)
{
    uint32 idx = 1;
    expr_node_t *node = sort_item->expr->root;
    *is_found = CT_FALSE;

    if (!NODE_IS_CONST(node) || !CT_IS_NUMERIC_TYPE(node->value.type)) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(var_as_floor_integer(&node->value));

    if (node->value.v_int < 1) {
        CT_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "unknown column '%d' in order clause",
            node->value.v_int);
        return CT_ERROR;
    }

    while (arg != NULL) {
        if (idx == (uint32)node->value.v_int) {
            CT_RETURN_IFERR(sql_clone_expr_node(stmt->context, arg->root, &sort_item->expr->root, sql_alloc_mem));
            *is_found = CT_TRUE;
            break;
        }
        arg = arg->next;
        idx++;
    }

    if (!(*is_found)) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "unknown column '%d' in order clause", node->value.v_int);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_listagg_order(sql_verifier_t *verif, galist_t *sort_items)
{
    uint32 i, excl_flags;
    sort_item_t *item = NULL;

    excl_flags = verif->excl_flags;
    verif->excl_flags = SQL_ORDER_EXCL | SQL_GROUP_BY_EXCL;

    for (i = sort_items->count; i > 0; i--) {
        item = (sort_item_t *)cm_galist_get(sort_items, i - 1);
        if (TREE_IS_CONST(item->expr)) {
            cm_galist_delete(sort_items, i - 1);
            continue;
        }

        CT_RETURN_IFERR(sql_verify_expr(verif, item->expr));
    }

    verif->excl_flags = excl_flags;
    return CT_SUCCESS;
}

status_t sql_verify_group_concat_order(sql_verifier_t *verif, expr_node_t *func, galist_t *sort_items)
{
    uint32 i, excl_flags;
    sort_item_t *item = NULL;
    bool32 is_found = CT_FALSE;
    expr_tree_t *arg = func->argument->next; // the first argument is separator

    if (sort_items->count == 0) {
        return CT_SUCCESS;
    }

    excl_flags = verif->excl_flags;
    verif->excl_flags = SQL_ORDER_EXCL | SQL_GROUP_BY_EXCL;

    for (i = sort_items->count; i > 0; i--) {
        item = (sort_item_t *)cm_galist_get(sort_items, i - 1);
        if (TREE_IS_BINDING_PARAM(item->expr)) {
            cm_galist_delete(sort_items, i - 1);
            continue;
        }
        CT_RETURN_IFERR(sql_check_const_concat_sort(verif->stmt, arg, item, &is_found));

        if (is_found) {
            continue;
        }

        CT_RETURN_IFERR(sql_verify_expr(verif, item->expr));
    }
    verif->excl_flags = excl_flags;
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif