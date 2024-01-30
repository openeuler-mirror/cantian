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
 * ctsql_group_verifier.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/verifier/ctsql_group_verifier.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_select_verifier.h"
#include "srv_instance.h"
#include "ctsql_func.h"
#include "expr_parser.h"
#include "dml_parser.h"


#ifdef __cplusplus
extern "C" {
#endif


static status_t sql_match_group_node(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node);

status_t sql_match_group_expr(sql_stmt_t *stmt, sql_query_t *query, expr_tree_t *expr)
{
    while (expr != NULL) {
        if (sql_match_group_node(stmt, query, expr->root) != CT_SUCCESS) {
            return CT_ERROR;
        }
        expr = expr->next;
    }

    return CT_SUCCESS;
}

static inline status_t sql_match_group_cond_node(sql_stmt_t *stmt, sql_query_t *query, cond_node_t *cond)
{
    if (sql_stack_safe(stmt) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cond == NULL) {
        return CT_SUCCESS;
    }

    switch (cond->type) {
        case COND_NODE_COMPARE:
            CT_RETURN_IFERR(sql_match_group_expr(stmt, query, cond->cmp->left));
            CT_RETURN_IFERR(sql_match_group_expr(stmt, query, cond->cmp->right));
            break;
        case COND_NODE_TRUE:
        case COND_NODE_FALSE:
            break;
        default:
            CT_RETURN_IFERR(sql_match_group_cond_node(stmt, query, cond->left));
            CT_RETURN_IFERR(sql_match_group_cond_node(stmt, query, cond->right));
            break;
    }

    return CT_SUCCESS;
}

static status_t sql_match_group_node_by_winsort(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *winsort)
{
    sort_item_t *item = NULL;
    expr_tree_t *expr = NULL;
    expr_node_t *func_node = winsort->argument->root;

    if (winsort->win_args->group_exprs != NULL) {
        for (uint32 i = 0; i < winsort->win_args->group_exprs->count; i++) {
            expr = (expr_tree_t *)cm_galist_get(winsort->win_args->group_exprs, i);
            CT_RETURN_IFERR(sql_match_group_expr(stmt, query, expr));
        }
    }
    if (winsort->win_args->sort_items != NULL) {
        for (uint32 i = 0; i < winsort->win_args->sort_items->count; i++) {
            item = (sort_item_t *)cm_galist_get(winsort->win_args->sort_items, i);
            CT_RETURN_IFERR(sql_match_group_expr(stmt, query, item->expr));
        }
        if (winsort->win_args->windowing != NULL) {
            CT_RETURN_IFERR(sql_match_group_expr(stmt, query, winsort->win_args->windowing->l_expr));
            CT_RETURN_IFERR(sql_match_group_expr(stmt, query, winsort->win_args->windowing->r_expr));
        }
    }

    return sql_match_group_expr(stmt, query, func_node->argument);
}

static inline bool32 sql_group_expr_node_equal(sql_stmt_t *stmt, expr_node_t *node, expr_node_t *group_node)
{
    if (group_node->type != node->type) {
        return CT_FALSE;
    }

    switch (group_node->type) {
        case EXPR_NODE_COLUMN:
            if (VAR_ANCESTOR(&group_node->value) > 0) {
                return CT_FALSE;
            }
            return (bool32)(VAR_TAB(&group_node->value) == VAR_TAB(&node->value) &&
                VAR_COL(&group_node->value) == VAR_COL(&node->value));

        case EXPR_NODE_RESERVED:
            if (VALUE(uint32, &group_node->value) != RES_WORD_ROWID || ROWID_NODE_ANCESTOR(group_node) > 0 ||
                VALUE(uint32, &group_node->value) != VALUE(uint32, &node->value)) {
                return CT_FALSE;
            }
            return (bool32)(ROWID_NODE_TAB(group_node) == ROWID_NODE_TAB(node));

        default:
            return CT_FALSE;
    }
}

static inline status_t sql_find_in_parent_group_exprs(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node)
{
    uint32 i, j;
    expr_tree_t *group_expr = NULL;
    group_set_t *group_set = NULL;

    for (i = 0; i < query->group_sets->count; i++) {
        group_set = (group_set_t *)cm_galist_get(query->group_sets, i);
        for (j = 0; j < group_set->items->count; j++) {
            group_expr = (expr_tree_t *)cm_galist_get(group_set->items, j);
            if (sql_group_expr_node_equal(stmt, node, group_expr->root)) {
                return sql_set_group_expr_node(stmt, node, j, i, ANCESTOR_OF_NODE(node), NULL);
            }
        }
    }
    CT_SRC_THROW_ERROR(node->loc, ERR_EXPR_NOT_IN_GROUP_LIST);
    return CT_ERROR;
}

static inline status_t sql_match_group_parent_ref_columns(sql_stmt_t *stmt, sql_query_t *query, galist_t *ref_columns)
{
    expr_node_t *col = NULL;
    uint32 ref_count = ref_columns->count;

    for (uint32 i = 0; i < ref_count; i++) {
        col = (expr_node_t *)cm_galist_get(ref_columns, i);
        if (col->type == EXPR_NODE_GROUP) {
            continue;
        }
        CT_RETURN_IFERR(sql_find_in_parent_group_exprs(stmt, query, col));
    }
    return CT_SUCCESS;
}

static inline status_t sql_match_group_subselect(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node)
{
    parent_ref_t *parent_ref = NULL;
    sql_select_t *select_ctx = NULL;
    select_ctx = (sql_select_t *)node->value.v_obj.ptr;

#ifdef Z_SHARDING
    if (IS_SHARD && stmt->context->has_sharding_tab) {
        if (select_ctx->has_ancestor > 0) {
            CT_SRC_THROW_ERROR(node->loc, ERR_CAPABILITY_NOT_SUPPORT, "subquery contain group by column");
            return CT_ERROR;
        }
        return CT_SUCCESS;
    }
#endif

    SET_NODE_STACK_CURR_QUERY(stmt, select_ctx->first_query);
    for (uint32 i = 0; i < select_ctx->parent_refs->count; i++) {
        parent_ref = (parent_ref_t *)cm_galist_get(select_ctx->parent_refs, i);
        CT_RETURN_IFERR(sql_match_group_parent_ref_columns(stmt, query, parent_ref->ref_columns));
    }
    SQL_RESTORE_NODE_STACK(stmt);
    return CT_SUCCESS;
}

static status_t sql_match_node_in_group_sets(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node, bool32 *matched)
{
    uint32 i, j;
    group_set_t *group_set = NULL;
    expr_tree_t *group_expr = NULL;

    for (i = 0; i < query->group_sets->count; i++) {
        group_set = (group_set_t *)cm_galist_get(query->group_sets, i);
        for (j = 0; j < group_set->items->count; j++) {
            group_expr = (expr_tree_t *)cm_galist_get(group_set->items, j);
            if (NODE_IS_RES_DUMMY(group_expr->root)) {
                continue;
            }
            if (sql_expr_node_equal(stmt, node, group_expr->root, NULL)) {
                *matched = CT_TRUE;
                return sql_set_group_expr_node(stmt, node, j, i, 0, group_expr->root);
            }
        }
    }
    *matched = CT_FALSE;
    return CT_SUCCESS;
}

static status_t sql_match_group_grouping(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node)
{
    bool32 matched = CT_FALSE;
    expr_tree_t *arg = node->argument;

    while (arg != NULL) {
        if (sql_match_node_in_group_sets(stmt, query, arg->root, &matched) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (!matched) {
            CT_SRC_THROW_ERROR(arg->loc, ERR_EXPR_NOT_IN_GROUP_LIST);
            return CT_ERROR;
        }
        arg = arg->next;
        matched = CT_FALSE;
    }
    return CT_SUCCESS;
}

static status_t sql_match_group_func(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node)
{
    sql_func_t *func = sql_get_func(&node->value.v_func);
    if (func->aggr_type != AGGR_TYPE_NONE) {
        return CT_SUCCESS;
    }

    switch (func->builtin_func_id) {
        case ID_FUNC_ITEM_GROUPING:
        case ID_FUNC_ITEM_GROUPING_ID:
            return sql_match_group_grouping(stmt, query, node);
        case ID_FUNC_ITEM_SYS_CONNECT_BY_PATH:
            CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR,
                "sys_connect_by_path was not allowed in query containing group by clause");
            return CT_ERROR;
        case ID_FUNC_ITEM_IF:
        case ID_FUNC_ITEM_LNNVL:
            if (node->cond_arg != NULL) {
                CT_RETURN_IFERR(sql_match_group_cond_node(stmt, query, node->cond_arg->root));
            }
            // fall through
        default:
            break;
    }

    return sql_match_group_expr(stmt, query, node->argument);
}

static status_t sql_match_group_case(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node)
{
    case_expr_t *case_expr = NULL;
    case_pair_t *pair = NULL;
    case_expr = (case_expr_t *)VALUE(pointer_t, &node->value);
    if (!case_expr->is_cond) {
        CT_RETURN_IFERR(sql_match_group_expr(stmt, query, case_expr->expr));
        for (uint32 i = 0; i < case_expr->pairs.count; i++) {
            pair = (case_pair_t *)cm_galist_get(&case_expr->pairs, i);
            CT_RETURN_IFERR(sql_match_group_expr(stmt, query, pair->when_expr));
            CT_RETURN_IFERR(sql_match_group_expr(stmt, query, pair->value));
        }
    } else {
        for (uint32 i = 0; i < case_expr->pairs.count; i++) {
            pair = (case_pair_t *)cm_galist_get(&case_expr->pairs, i);
            CT_RETURN_IFERR(sql_match_group_cond_node(stmt, query, pair->when_cond->root));
            CT_RETURN_IFERR(sql_match_group_expr(stmt, query, pair->value));
        }
    }
    return sql_match_group_expr(stmt, query, case_expr->default_expr);
}

bool32 sql_check_reserved_is_const(expr_node_t *node)
{
    switch (VALUE(uint32, &node->value)) {
        case RES_WORD_ROWNUM:
        case RES_WORD_ROWID:
        case RES_WORD_ROWSCN:
        case RES_WORD_LEVEL:
        case RES_WORD_CONNECT_BY_ISCYCLE:
        case RES_WORD_CONNECT_BY_ISLEAF:
        case RES_WORD_ROWNODEID:
            return CT_FALSE;
        default:
            return CT_TRUE;
    }
}

static status_t sql_match_group_reserved(expr_node_t *node)
{
    if (!sql_check_reserved_is_const(node)) {
        CT_SRC_THROW_ERROR(node->loc, ERR_EXPR_NOT_IN_GROUP_LIST);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_match_group_column(expr_node_t *node)
{
    if (VAR_ANCESTOR(&node->value) > 0) {
        return CT_SUCCESS;
    }
    CT_SRC_THROW_ERROR(node->loc, ERR_EXPR_NOT_IN_GROUP_LIST);
    return CT_ERROR;
}

static status_t sql_match_group_node_by_node_type(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node)
{
    // if modify this function, do modify sql_check_table_column_exists at the same time
    switch (node->type) {
        case EXPR_NODE_FUNC:
            return sql_match_group_func(stmt, query, node);
        case EXPR_NODE_USER_FUNC:
            return sql_match_group_expr(stmt, query, node->argument);
        case EXPR_NODE_SELECT:
            return sql_match_group_subselect(stmt, query, node);
        case EXPR_NODE_PARAM:
        case EXPR_NODE_CONST:
        case EXPR_NODE_V_ADDR: // deal same as pl-variant
        case EXPR_NODE_USER_PROC:
        case EXPR_NODE_PROC:
        case EXPR_NODE_NEW_COL:
        case EXPR_NODE_OLD_COL:
        case EXPR_NODE_PL_ATTR:
            return CT_SUCCESS;
        case EXPR_NODE_RESERVED:
            return sql_match_group_reserved(node);
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
            CT_RETURN_IFERR(sql_match_group_node(stmt, query, node->left));
            return sql_match_group_node(stmt, query, node->right);
        case EXPR_NODE_NEGATIVE:
            return sql_match_group_node(stmt, query, node->right);
        case EXPR_NODE_CASE:
            return sql_match_group_case(stmt, query, node);
        case EXPR_NODE_OVER:
            return sql_match_group_node_by_winsort(stmt, query, node);
        case EXPR_NODE_COLUMN:
            return sql_match_group_column(node);
        case EXPR_NODE_ARRAY:
            return sql_match_group_expr(stmt, query, node->argument);
        default:
            break;
    }

    CT_SRC_THROW_ERROR(node->loc, ERR_EXPR_NOT_IN_GROUP_LIST);
    return CT_ERROR;
}

static inline status_t sql_match_group_node(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node)
{
    bool32 matched = CT_FALSE;
    if (node->type == EXPR_NODE_AGGR || NODE_IS_CONST(node) || node->type == EXPR_NODE_GROUP) {
        return CT_SUCCESS;
    }
    if (node->type == EXPR_NODE_COLUMN && NODE_ANCESTOR(node) > 0) {
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(sql_match_node_in_group_sets(stmt, query, node, &matched));
    if (!matched) {
        return sql_match_group_node_by_node_type(stmt, query, node);
    }
    return CT_SUCCESS;
}

static status_t sql_group_set_cmp_func(const void *str1, const void *str2, int32 *result)
{
    expr_tree_t *expr1 = NULL;
    expr_tree_t *expr2 = NULL;
    group_set_t *group_set1 = (group_set_t *)str1;
    group_set_t *group_set2 = (group_set_t *)str2;

    if (group_set1->count != group_set2->count) {
        *result = (group_set1->count < group_set2->count) ? 1 : -1;
        return CT_SUCCESS;
    }
    for (uint32 i = 0; i < group_set1->items->count; i++) {
        expr1 = (expr_tree_t *)cm_galist_get(group_set1->items, i);
        expr2 = (expr_tree_t *)cm_galist_get(group_set2->items, i);
        // keep the dummy expr to the last
        if (NODE_IS_RES_DUMMY(expr1->root) && !NODE_IS_RES_DUMMY(expr2->root)) {
            *result = 1;
            return CT_SUCCESS;
        }
        if (!NODE_IS_RES_DUMMY(expr1->root) && NODE_IS_RES_DUMMY(expr2->root)) {
            *result = -1;
            return CT_SUCCESS;
        }
    }
    *result = 0;
    return CT_SUCCESS;
}

static inline bool32 sql_list_has_expr(sql_stmt_t *stmt, galist_t *items, expr_tree_t *expr)
{
    expr_tree_t *item = NULL;

    for (uint32 i = 0; i < items->count; i++) {
        item = (expr_tree_t *)cm_galist_get(items, i);
        if (sql_expr_node_equal(stmt, item->root, expr->root, NULL)) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

static inline status_t sql_create_dummy_expr(sql_stmt_t *stmt, expr_tree_t **null_expr)
{
    expr_node_t *node = NULL;
    CT_RETURN_IFERR(sql_create_expr(stmt, null_expr));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&node));
    node->owner = (*null_expr);
    node->type = EXPR_NODE_RESERVED;
    node->datatype = CT_DATATYPE_OF_NULL;
    node->value.v_res.res_id = RES_WORD_DUMMY;
    (*null_expr)->root = node;
    return CT_SUCCESS;
}

static status_t sql_normalize_group_set(sql_stmt_t *stmt, galist_t *s_items, expr_tree_t *dummy_expr,
    group_set_t *group_set)
{
    uint32 i;
    galist_t *group_exprs = NULL;
    expr_tree_t *expr = NULL;

    CT_RETURN_IFERR(sql_create_list(stmt, &group_exprs));
    group_set->count = 0;

    for (i = 0; i < s_items->count; i++) {
        expr = (expr_tree_t *)cm_galist_get(s_items, i);
        if (sql_list_has_expr(stmt, group_set->items, expr)) {
            CT_RETURN_IFERR(cm_galist_insert(group_exprs, expr));
            group_set->count++;
        } else {
            CT_RETURN_IFERR(cm_galist_insert(group_exprs, dummy_expr));
        }
    }
    group_set->items = group_exprs;
    return CT_SUCCESS;
}

status_t sql_normalize_group_sets(sql_stmt_t *stmt, sql_query_t *query)
{
    uint32 i, j;
    expr_tree_t *expr = NULL;
    expr_tree_t *dummy = NULL;
    group_set_t *group_set = NULL;
    galist_t *full_items = NULL;

    CT_RETURN_IFERR(sql_create_dummy_expr(stmt, &dummy));

    CTSQL_SAVE_STACK(stmt);
    if (sql_push(stmt, sizeof(galist_t), (void **)&full_items) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    cm_galist_init(full_items, stmt, sql_stack_alloc);

    // gather full group exprs
    for (i = 0; i < query->group_sets->count; i++) {
        group_set = (group_set_t *)cm_galist_get(query->group_sets, i);
        for (j = 0; j < group_set->items->count; j++) {
            expr = (expr_tree_t *)cm_galist_get(group_set->items, j);
            // skip bind parameter
            if (expr->root->type == EXPR_NODE_PARAM) {
                continue;
            }
            if (sql_list_has_expr(stmt, full_items, expr)) {
                continue;
            }
            if (cm_galist_insert(full_items, expr) != CT_SUCCESS) {
                CTSQL_RESTORE_STACK(stmt);
                return CT_ERROR;
            }
        }
    }

    // insert dummy expr
    if (full_items->count == 0 && cm_galist_insert(full_items, dummy) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    // normalize all group sets
    for (i = 0; i < query->group_sets->count; i++) {
        group_set = (group_set_t *)cm_galist_get(query->group_sets, i);
        if (sql_normalize_group_set(stmt, full_items, dummy, group_set) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }
    }

    CTSQL_RESTORE_STACK(stmt);
    (void)cm_galist_sort(query->group_sets, sql_group_set_cmp_func);
    return CT_SUCCESS;
}

status_t sql_verify_query_group(sql_verifier_t *verif, sql_query_t *query)
{
    uint32 i, j;
    expr_tree_t *expr = NULL;
    group_set_t *group_set = NULL;

    if (query->group_sets->count == 0) {
        return CT_SUCCESS;
    }

    verif->excl_flags = SQL_GROUP_BY_EXCL;
    verif->tables = &query->tables;
    verif->aggrs = query->aggrs;
    verif->cntdis_columns = query->cntdis_columns;
    verif->incl_flags = 0;
    verif->curr_query = query;

    for (i = 0; i < query->group_sets->count; i++) {
        group_set = (group_set_t *)cm_galist_get(query->group_sets, i);

        for (j = 0; j < group_set->items->count; j++) {
            expr = (expr_tree_t *)cm_galist_get(group_set->items, j);
            verif->has_ddm_col = CT_FALSE;
            if (sql_verify_expr(verif, expr) != CT_SUCCESS) {
                return CT_ERROR;
            }
            if (verif->has_ddm_col == CT_TRUE) {
                if (expr->root->type != EXPR_NODE_COLUMN) {
                    CT_THROW_ERROR(ERR_INVALID_OPERATION,
                        ", ddm col expr is not allowed in group clause, only support single col");
                    return CT_ERROR;
                }
                verif->has_ddm_col = CT_FALSE;
            }
            expr->root->has_verified = CT_TRUE;
        }
    }

    if (query->group_sets->count > 1) {
#ifdef Z_SHARDING
        // not support multiple grouping sets in Z_SHARDING
        if (IS_COORDINATOR) {
            CT_THROW_ERROR(ERR_COORD_NOT_SUPPORT, "GROUPING SETS/CUBE/ROLLUP");
            return CT_ERROR;
        }
#endif // Z_SHARDING
    }
    return sql_normalize_group_sets(verif->stmt, query);
}

static status_t sql_check_having_compare(sql_stmt_t *stmt, sql_query_t *query, cmp_node_t *node)
{
    if (node->left != NULL) {
        CT_RETURN_IFERR(sql_match_group_expr(stmt, query, node->left));
    }

    if (node->right != NULL) {
        CT_RETURN_IFERR(sql_match_group_expr(stmt, query, node->right));
    }

    return CT_SUCCESS;
}

static status_t sql_check_having_cond_node(sql_stmt_t *stmt, sql_query_t *query, cond_node_t *node)
{
    if (sql_stack_safe(stmt) != CT_SUCCESS) {
        return CT_ERROR;
    }
    switch (node->type) {
        case COND_NODE_TRUE:
        case COND_NODE_FALSE:
            break;
        case COND_NODE_COMPARE:
            CT_RETURN_IFERR(sql_check_having_compare(stmt, query, node->cmp));
            break;
        default:
            CT_RETURN_IFERR(sql_check_having_cond_node(stmt, query, node->left));
            CT_RETURN_IFERR(sql_check_having_cond_node(stmt, query, node->right));
            break;
    }

    return CT_SUCCESS;
}

status_t sql_verify_query_having(sql_verifier_t *verif, sql_query_t *query)
{
    bool32 allowed_aggr = CT_FALSE;

    if (query->having_cond == NULL) {
        return CT_SUCCESS;
    }

    verif->tables = &query->tables;
    verif->aggrs = query->aggrs;
    verif->cntdis_columns = query->cntdis_columns;
    verif->curr_query = query;
    verif->excl_flags = SQL_HAVING_EXCL;
    verif->incl_flags = 0;
    verif->aggr_flags = SQL_GEN_AGGR_FROM_HAVING;

    /* ok:  select count(f1) from t1 having max(f1)=1
           ok:  select f1 from t1 group by f1 having max(f1)=1
           nok: select f1 from t1 having max(f1)=1
           ok:  select 1  from t1 having max(f1)=1
        */
    allowed_aggr = ((query->aggrs->count > 0 || query->group_sets->count > 0) || !verif->has_excl_const);
    if (!allowed_aggr) {
        verif->excl_flags |= SQL_EXCL_AGGR;
    }

    CT_RETURN_IFERR(sql_verify_cond(verif, query->having_cond));
    CT_RETURN_IFERR(sql_check_having_cond_node(verif->stmt, query, query->having_cond->root));

    verif->aggr_flags = 0;
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif