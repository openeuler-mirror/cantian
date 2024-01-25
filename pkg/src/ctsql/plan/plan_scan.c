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
 * plan_scan.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/plan/plan_scan.c
 *
 * -------------------------------------------------------------------------
 */
#include "plan_scan.h"
#include "plan_query.h"
#include "cbo_join.h"
#include "srv_instance.h"
#include "table_parser.h"
#include "ctsql_table_func.h"
#include "plan_rbo.h"
#include "plan_range.h"

#ifdef __cplusplus
extern "C" {
#endif


static inline status_t sql_set_mapped_table_cost(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table)
{
    CT_RETURN_IFERR(sql_stack_safe(stmt));

    if (table->type == FUNC_AS_TABLE) {
        table->cost = FUNC_TABLE_COST;
        return CT_SUCCESS;
    }

    if (table->subslct_tab_usage == SUBSELECT_4_ANTI_JOIN || table->subslct_tab_usage == SUBSELECT_4_ANTI_JOIN_NA) {
        table->cost = RBO_COST_FULL_TABLE_SCAN;
        return CT_SUCCESS;
    }

    table->cost = RBO_COST_SUB_QUERY_SCAN;
    return CT_SUCCESS;
}

static inline status_t sql_add_sub_table(sql_stmt_t *stmt, galist_t *sub_tables, sql_table_t *table, cond_node_t *cond)
{
    sql_table_t *element = NULL;

    CT_RETURN_IFERR(cm_galist_new(sub_tables, sizeof(sql_table_t), (void **)&element));
    *element = *table;
    element->is_sub_table = CT_TRUE;

    if (INDEX_ONLY_SCAN(element->scan_flag)) {
        CT_RETURN_IFERR(sql_make_index_col_map(NULL, stmt, element));
    }
    return sql_union_cond_node(stmt->context, (cond_tree_t **)&element->cond, cond);
}

static inline status_t sql_try_add_sub_table(sql_stmt_t *stmt, sql_table_t *parent, sql_table_t *sub_table,
    cond_node_t *cond)
{
    if (sub_table->index->id == parent->index->id) {
        return sql_union_cond_node(stmt->context, (cond_tree_t **)&parent->cond, cond);
    }

    if (parent->sub_tables == NULL) {
        CT_RETURN_IFERR(sql_create_list(stmt, &parent->sub_tables));
        return sql_add_sub_table(stmt, parent->sub_tables, sub_table, cond);
    }

    for (uint32 i = 0; i < parent->sub_tables->count; i++) {
        sql_table_t *element = (sql_table_t *)cm_galist_get(parent->sub_tables, i);
        if (element->index->id == sub_table->index->id) {
            return sql_union_cond_node(stmt->context, (cond_tree_t **)&element->cond, cond);
        }
    }
    return sql_add_sub_table(stmt, parent->sub_tables, sub_table, cond);
}

static inline status_t sql_get_index_cond(sql_stmt_t *stmt, cond_tree_t *and_cond, cond_node_t *cond_node,
    cond_node_t **index_cond)
{
    if (and_cond == NULL) {
        *index_cond = cond_node;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(cm_stack_alloc(stmt->session->stack, sizeof(cond_node_t), (void **)index_cond));
    MEMS_RETURN_IFERR(memset_sp(*index_cond, sizeof(cond_node_t), 0, sizeof(cond_node_t)));

    (*index_cond)->type = COND_NODE_AND;
    (*index_cond)->left = and_cond->root;
    (*index_cond)->right = cond_node;
    return CT_SUCCESS;
}

static inline status_t sql_collect_or_cond(sql_stmt_t *stmt, cond_node_t *src_cond, cond_tree_t **and_cond,
    galist_t *or_list)
{
    CT_RETURN_IFERR(sql_stack_safe(stmt));
    switch (src_cond->type) {
        case COND_NODE_AND:
            CT_RETURN_IFERR(sql_collect_or_cond(stmt, src_cond->left, and_cond, or_list));
            return sql_collect_or_cond(stmt, src_cond->right, and_cond, or_list);

        case COND_NODE_OR:
            return cm_galist_insert(or_list, src_cond);

        case COND_NODE_COMPARE:
            if (*and_cond == NULL) {
                CT_RETURN_IFERR(sql_stack_alloc(stmt, sizeof(cond_tree_t), (void **)and_cond));
                sql_init_cond_tree(stmt, *and_cond, sql_stack_alloc);
            }
            return sql_merge_cond_tree_shallow(*and_cond, src_cond);

        default:
            return CT_SUCCESS;
    }
}

static inline bool32 judge_sort_items(plan_assist_t *pa)
{
    if (pa->query->sort_items->count == 0) {
        return CT_TRUE;
    }

    sort_item_t *sort_item = NULL;
    uint32 i = 0;
    sort_direction_t direction;
    sort_item = (sort_item_t *)cm_galist_get(pa->query->sort_items, 0);
    direction = sort_item->direction;
    for (i = 1; i < pa->query->sort_items->count; i++) {
        sort_item = (sort_item_t *)cm_galist_get(pa->query->sort_items, i);
        if (direction != sort_item->direction) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

static inline bool32 if_need_get_sort_index(plan_assist_t *pa, sql_table_t *table)
{
    if (!LIMIT_CLAUSE_OCCUR(&pa->query->limit) || table->equal_cols > 0 || INDEX_SORT_SCAN(table->scan_flag) ||
        judge_sort_items(pa) || table->cost <= RBO_COST_INDEX_LIST_SCAN ||
        table->opt_match_mode <= COLUMN_MATCH_2_BORDER_RANGE) {
        return CT_FALSE;
    }
    return CT_TRUE;
}

status_t sql_check_table_indexable(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, cond_tree_t *cond)
{
    if (pa->top_pa != NULL) {
        pa = pa->top_pa;
    }

    if (table->type != NORMAL_TABLE) {
        return sql_set_mapped_table_cost(stmt, pa, table);
    }

    CT_RETSUC_IFTRUE(table->remote_type != REMOTE_TYPE_LOCAL);

    sql_init_table_indexable(table, NULL);
    return CT_SUCCESS;
}

static status_t sql_create_scan_plan(sql_stmt_t *stmt, plan_assist_t *pa, cond_tree_t *cond, sql_table_t *table,
    plan_node_t **plan)
{
    plan_node_t *scan_plan = NULL;

    if (sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)&scan_plan) != CT_SUCCESS) {
        return CT_ERROR;
    }

    *plan = scan_plan;
    pa->cond = cond;
    scan_plan->type = PLAN_NODE_SCAN;
    scan_plan->plan_id = stmt->context->plan_count++;
    scan_plan->scan_p.table = table;
    scan_plan->scan_p.par_exec = CT_FALSE;
    scan_plan->scan_p.sort_items = pa->sort_items;
    scan_plan->cost = table->cost;
    scan_plan->rows = table->card;

    return sql_create_scan_ranges(stmt, pa, table, &scan_plan->scan_p);
}

static bool32 check_expr_datatype_for_pruning(expr_node_t *col_node, expr_node_t *val_node)
{
    if (CT_IS_UNKNOWN_TYPE(val_node->datatype)) {
        return CT_FALSE;
    }
    if (NODE_DATATYPE(col_node) == NODE_DATATYPE(val_node)) {
        return CT_TRUE;
    }
    if (CT_IS_NUMERIC_TYPE2(col_node->datatype, val_node->datatype)) {
        if (CT_IS_INTEGER_TYPE(col_node->datatype)) {
            if (val_node->scale != 0 || col_node->size < val_node->size) {
                return CT_FALSE;
            }
            // "int32 = uint32" needs to return false, such as "where 1 = 2147483648"
            if (col_node->size == val_node->size &&
                ((CT_IS_UNSIGNED_INTEGER_TYPE(col_node->datatype) && CT_IS_SIGNED_INTEGER_TYPE(val_node->datatype)) ||
                (CT_IS_SIGNED_INTEGER_TYPE(col_node->datatype) && CT_IS_UNSIGNED_INTEGER_TYPE(val_node->datatype)))) {
                return CT_FALSE;
            }
            return CT_TRUE;
        }
        return CT_TRUE;
    }
    if (CT_IS_DATETIME_TYPE2(col_node->datatype, val_node->datatype)) {
        if (NODE_DATATYPE(col_node) == CT_TYPE_TIMESTAMP_TZ || NODE_DATATYPE(col_node) == CT_TYPE_TIMESTAMP_LTZ ||
            NODE_DATATYPE(col_node) == CT_TYPE_TIMESTAMP_TZ_FAKE) {
            return CT_FALSE;
        }
        return (bool32)(col_node->size >= val_node->size && col_node->precision >= val_node->precision);
    }
    if (CT_IS_VARLEN_TYPE(col_node->datatype)) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

static bool32 sql_expr_in_index_range(sql_stmt_t *stmt, cmp_node_t *cmp_node, sql_array_t *index_array)
{
    plan_range_list_t *range_list = NULL;
    plan_range_t *plan_range = NULL;

    for (uint32 i = 0; i < index_array->count; i++) {
        range_list = (plan_range_list_t *)sql_array_get(index_array, i);
        if (range_list->type == RANGE_LIST_FULL) {
            continue;
        }
        for (uint32 j = 0; j < range_list->items->count; j++) {
            plan_range = (plan_range_t *)cm_galist_get(range_list->items, j);
            if (cmp_node->right == plan_range->left.expr) {
                return check_expr_datatype_for_pruning(cmp_node->left->root, cmp_node->right->root);
            }
            if (cmp_node->left == plan_range->left.expr) {
                return check_expr_datatype_for_pruning(cmp_node->right->root, cmp_node->left->root);
            }
        }
    }

    return CT_FALSE;
}

static bool32 is_equal_index_leading_column(sql_stmt_t *stmt, sql_table_t *table, cmp_node_t *cmp_node)
{
    uint32 col_id;
    expr_node_t *node = NULL;
    expr_node_t col_node;
    knl_column_t *knl_col = NULL;
    bool32 result = CT_FALSE;
    CTSQL_SAVE_STACK(stmt);
    for (uint16 i = 0; i < table->idx_equal_to; i++) {
        col_id = table->index->columns[i];
        knl_col = knl_get_column(table->entry->dc.handle, col_id);
        if (sql_get_index_col_node(stmt, knl_col, &col_node, &node, table->id, col_id) != CT_SUCCESS) {
            break;
        }
        if (sql_expr_node_equal(stmt, node, cmp_node->left->root, NULL) ||
            sql_expr_node_equal(stmt, node, cmp_node->right->root, NULL)) {
            result = CT_TRUE;
            break;
        }
    }
    CTSQL_RESTORE_STACK(stmt);
    return result;
}

static status_t sql_pruning_index_cond(sql_stmt_t *stmt, sql_table_t *table, cond_node_t *cond_node,
    cond_tree_t **index_cond, sql_array_t *index_array)
{
    switch (cond_node->type) {
        case COND_NODE_AND:
            CT_RETURN_IFERR(sql_pruning_index_cond(stmt, table, cond_node->left, index_cond, index_array));
            CT_RETURN_IFERR(sql_pruning_index_cond(stmt, table, cond_node->right, index_cond, index_array));
            break;
        case COND_NODE_COMPARE:
            if (cond_node->cmp->type != CMP_TYPE_EQUAL || !sql_expr_in_index_range(stmt, cond_node->cmp, index_array)) {
                return CT_SUCCESS;
            }
            // index on (c1,c2,c3), c1 = ? and c2 = ? and c3 = ?, optimize all
            // index on (c1,c2,c3), c1 = ? and c2 > ? and c3 = ?, only optimize c1 = ?
            if (table->idx_equal_to != table->index->column_count &&
                !is_equal_index_leading_column(stmt, table, cond_node->cmp)) {
                return CT_SUCCESS;
            }
            if (*index_cond == NULL) {
                CT_RETURN_IFERR(sql_create_cond_tree(stmt->context, index_cond));
            }
            CT_RETURN_IFERR(sql_merge_cond_tree_shallow(*index_cond, cond_node));
            cond_node->type = COND_NODE_TRUE;
            // fall through
        case COND_NODE_OR:
        default:
            break;
    }
    return CT_SUCCESS;
}

static bool32 cmp_node_in_cond(sql_stmt_t *stmt, cmp_node_t *cmp_node, cond_node_t *cond)
{
    switch (cond->type) {
        case COND_NODE_AND:
            return (bool32)(cmp_node_in_cond(stmt, cmp_node, cond->left) ||
                cmp_node_in_cond(stmt, cmp_node, cond->right));
        case COND_NODE_COMPARE:
            return sql_cmp_node_equal(stmt, cmp_node, cond->cmp, NULL);
        case COND_NODE_OR:
        default:
            return CT_FALSE;
    }
}

static void eliminate_index_cond_in_query_cond(sql_stmt_t *stmt, cond_node_t *query_node, cond_node_t *index_cond)
{
    switch (query_node->type) {
        case COND_NODE_AND:
            eliminate_index_cond_in_query_cond(stmt, query_node->left, index_cond);
            eliminate_index_cond_in_query_cond(stmt, query_node->right, index_cond);
            break;
        case COND_NODE_COMPARE:
            if (cmp_node_in_cond(stmt, query_node->cmp, index_cond)) {
                query_node->type = COND_NODE_TRUE;
            }
            break;
        case COND_NODE_OR:
        default:
            break;
    }
}

static status_t sql_pruning_single_index_cond(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table,
    plan_node_t *plan)
{
    sql_array_t *index_array = &plan->scan_p.index_array;
    cond_tree_t *index_cond = NULL;

    CT_RETURN_IFERR(sql_pruning_index_cond(stmt, table, table->cond->root, &index_cond, index_array));
    if (index_cond == NULL) {
        return CT_SUCCESS;
    }
    // CBO outer join optimize, pa->cond may be cloned from original cond
    if (table->cond->root != pa->cond->root) {
        table->cond = index_cond;
        eliminate_index_cond_in_query_cond(stmt, pa->cond->root, table->cond->root);
        CT_RETURN_IFERR(try_eval_logic_cond(stmt, pa->cond->root));
    } else {
        CT_RETURN_IFERR(try_eval_logic_cond(stmt, table->cond->root));
        table->cond = index_cond;
    }
    table->index_cond_pruning = CT_TRUE;
    return CT_SUCCESS;
}

static status_t sql_try_pruning_single_index_cond(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table,
    plan_node_t *plan)
{
    if (table->scan_mode != SCAN_MODE_INDEX || table->cond == NULL || pa->cond == NULL ||
        stmt->context->parallel != 0 || !g_instance->sql.enable_index_cond_pruning ||
        stmt->context->type != CTSQL_TYPE_SELECT || pa->query->for_update) {
        return CT_SUCCESS;
    }

    if (table->idx_equal_to == 0) {
        return CT_SUCCESS;
    }

    return sql_pruning_single_index_cond(stmt, pa, table, plan);
}

status_t sql_create_table_scan_plan(sql_stmt_t *stmt, plan_assist_t *pa, cond_tree_t *cond, sql_table_t *table,
    plan_node_t **plan)
{
    sql_table_t *sub_table = NULL;
    plan_node_t *scan_plan = NULL;

    CT_RETURN_IFERR(sql_create_scan_plan(stmt, pa, cond, table, &scan_plan));
    if (table->sub_tables == NULL) {
        *plan = scan_plan;
        return sql_try_pruning_single_index_cond(stmt, pa, table, scan_plan);
    }

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)plan));
    (*plan)->type = PLAN_NODE_CONCATE;
    (*plan)->plan_id = stmt->context->plan_count++;

    CT_RETURN_IFERR(sql_create_list(stmt, &(*plan)->cnct_p.keys));
    CT_RETURN_IFERR(sql_create_concate_key(stmt, (*plan)->cnct_p.keys, table));

    CT_RETURN_IFERR(sql_create_list(stmt, &(*plan)->cnct_p.plans));
    CT_RETURN_IFERR(cm_galist_insert((*plan)->cnct_p.plans, scan_plan));

    for (uint32 i = 0; i < table->sub_tables->count; i++) {
        sub_table = (sql_table_t *)cm_galist_get(table->sub_tables, i);
        CT_RETURN_IFERR(sql_create_scan_plan(stmt, pa, cond, sub_table, &scan_plan));
        CT_RETURN_IFERR(cm_galist_insert((*plan)->cnct_p.plans, scan_plan));
    }
    return CT_SUCCESS;
}

static inline bool32 sql_chk_need_remove(cols_used_t *cols_used, uint32 ancestor, uint32 tab)
{
    biqueue_t *cols_que = NULL;
    biqueue_node_t *curr_node = NULL;
    biqueue_node_t *end_node = NULL;
    expr_node_t *node = NULL;
    uint32 id = (ancestor == 1) ? PARENT_IDX : ANCESTOR_IDX;

    cols_que = &cols_used->cols_que[id];
    curr_node = biqueue_first(cols_que);
    end_node = biqueue_end(cols_que);

    while (curr_node != end_node) {
        node = OBJECT_OF(expr_node_t, curr_node);
        if (tab == TAB_OF_NODE(node) && ancestor == ANCESTOR_OF_NODE(node)) {
            return CT_TRUE;
        }
        curr_node = curr_node->next;
    }
    return CT_FALSE;
}

static inline bool32 if_need_remove(cmp_node_t *cmp_node, uint32 ancestor, uint32 tab)
{
    cols_used_t left_cols_used;
    cols_used_t right_cols_used;

    init_cols_used(&left_cols_used);
    init_cols_used(&right_cols_used);
    sql_collect_cols_in_expr_tree(cmp_node->left, &left_cols_used);
    sql_collect_cols_in_expr_tree(cmp_node->right, &right_cols_used);

    return (bool32)(sql_chk_need_remove(&left_cols_used, ancestor, tab) ||
        sql_chk_need_remove(&right_cols_used, ancestor, tab));
}

static inline status_t sql_remove_join_cond_node(sql_stmt_t *stmt, cond_node_t *cond_node, uint32 ancestor, uint32 tab)
{
    CT_RETURN_IFERR(sql_stack_safe(stmt));

    switch (cond_node->type) {
        case COND_NODE_AND:
            CT_RETURN_IFERR(sql_remove_join_cond_node(stmt, cond_node->left, ancestor, tab));
            CT_RETURN_IFERR(sql_remove_join_cond_node(stmt, cond_node->right, ancestor, tab));
            try_eval_logic_and(cond_node);
            break;

        case COND_NODE_OR:
            CT_RETURN_IFERR(sql_remove_join_cond_node(stmt, cond_node->left, ancestor, tab));
            CT_RETURN_IFERR(sql_remove_join_cond_node(stmt, cond_node->right, ancestor, tab));
            try_eval_logic_or(cond_node);
            break;

        case COND_NODE_COMPARE:
            if (if_need_remove(cond_node->cmp, ancestor, tab)) {
                cond_node->type = COND_NODE_TRUE;
            }
            break;
        default:
            break;
    }

    return CT_SUCCESS;
}

static inline status_t sql_remove_join_cond(sql_stmt_t *stmt, cond_tree_t **cond_tree, uint32 ancestor, uint32 tab)
{
    if (*cond_tree == NULL) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_remove_join_cond_node(stmt, (*cond_tree)->root, ancestor, tab));

    return CT_SUCCESS;
}

static inline status_t remove_join_cond_4_join_node(sql_stmt_t *stmt, sql_join_node_t *join_node, uint32 ancestor,
    uint32 tab)
{
    if (join_node->type == JOIN_TYPE_NONE) {
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(remove_join_cond_4_join_node(stmt, join_node->left, ancestor, tab));
    CT_RETURN_IFERR(remove_join_cond_4_join_node(stmt, join_node->right, ancestor, tab));

    CT_RETURN_IFERR(sql_remove_join_cond(stmt, &join_node->filter, ancestor, tab));

    if (IS_INNER_JOIN(join_node)) {
        return CT_SUCCESS;
    }
    return sql_remove_join_cond(stmt, &join_node->join_cond, ancestor, tab);
}

static inline bool32 chk_remove_table_push_down_join(select_node_t *node)
{
    if (node->type == SELECT_NODE_QUERY) {
        return (node->query->cond_has_acstor_col ? CT_FALSE : CT_TRUE);
    }
    if (chk_remove_table_push_down_join(node->left)) {
        return CT_TRUE;
    }
    return chk_remove_table_push_down_join(node->right);
}

static inline status_t remove_join_cond_4_slct_node(sql_stmt_t *stmt, select_node_t *select_node,
                                                    uint32 ancestor, uint32 tab);
static inline status_t remove_join_cond_4_query(sql_stmt_t *stmt, sql_query_t *sub_query, uint32 ancestor, uint32 tab)
{
    CT_RETURN_IFERR(sql_remove_join_cond(stmt, &sub_query->cond, ancestor, tab));

    if (sub_query->join_assist.outer_node_count > 0) {
        CT_RETURN_IFERR(remove_join_cond_4_join_node(stmt, sub_query->join_assist.join_node, ancestor, tab));
        CT_RETURN_IFERR(sql_remove_join_cond(stmt, &sub_query->filter_cond, ancestor, tab));
    }

    // pushed-down column can not be pushed down to sub select in ssa again
    for (uint32 loop = 0; loop < sub_query->tables.count; ++loop) {
        sql_table_t *table = (sql_table_t *)sql_array_get(&sub_query->tables, loop);
        if (table->type != SUBSELECT_AS_TABLE && table->type != VIEW_AS_TABLE) {
            continue;
        }
        CT_RETURN_IFERR(remove_join_cond_4_slct_node(stmt, table->select_ctx->root, ancestor + 1, tab));
        if (chk_remove_table_push_down_join(table->select_ctx->root)) {
            TABLE_CBO_UNSET_FLAG(table, SELTION_PUSH_DOWN_JOIN);
            cbo_unset_select_node_table_flag(table->select_ctx->root, SELTION_PUSH_DOWN_TABLE, CT_FALSE);
        }
    }

    // check if query cond still has ancstor col
    if (sub_query->cond_has_acstor_col) {
        if (sub_query->cond != NULL) {
            cols_used_t cols_used;
            init_cols_used(&cols_used);
            sql_collect_cols_in_cond(sub_query->cond->root, &cols_used);
            if (!(HAS_PRNT_OR_ANCSTR_COLS(cols_used.flags) || HAS_DYNAMIC_SUBSLCT(&cols_used))) {
                sub_query->cond_has_acstor_col = CT_FALSE;
            }
        } else {
            sub_query->cond_has_acstor_col = CT_FALSE;
        }
    }
    return CT_SUCCESS;
}

static inline status_t remove_join_cond_4_slct_node(sql_stmt_t *stmt, select_node_t *select_node,
                                                    uint32 ancestor, uint32 tab)
{
    // The query node is processed separately to avoid the scenario where the node is already in queue.
    if (select_node->type == SELECT_NODE_QUERY) {
        return remove_join_cond_4_query(stmt, select_node->query, ancestor, tab);
    }
    biqueue_t que;
    biqueue_init(&que);
    sql_collect_select_nodes(&que, select_node);

    select_node_t *obj = NULL;
    biqueue_node_t *curr_node = biqueue_first(&que);
    biqueue_node_t *end_node = biqueue_end(&que);

    while (curr_node != end_node) {
        obj = OBJECT_OF(select_node_t, curr_node);
        if (obj != NULL && obj->query != NULL) {
            CT_RETURN_IFERR(remove_join_cond_4_query(stmt, obj->query, ancestor, tab));
        }
        curr_node = BINODE_NEXT(curr_node);
    }
    return CT_SUCCESS;
}

void reset_select_node_cbo_status(select_node_t *node);
void cbo_unset_select_node_table_flag(select_node_t *select_node, uint32 cbo_flag, bool32 recurs);

static inline status_t replace_table_in_array(sql_array_t *tables, sql_table_t *old_table, sql_table_t *new_table)
{
    for (uint32 i = 0; i < tables->count; i++) {
        sql_table_t *table = (sql_table_t *)sql_array_get(tables, i);
        if (table->id == old_table->id) {
            return sql_array_set(tables, i, new_table);
        }
    }
    return CT_SUCCESS;
}

static inline status_t replace_table_id_4_split_nl(visit_assist_t *va, expr_node_t **node)
{
    if ((*node)->type != EXPR_NODE_COLUMN || NODE_ANCESTOR(*node) > 0 || va->result1 != NODE_TAB(*node)) {
        return CT_SUCCESS;
    }
    (*node)->value.v_col.tab = va->result0;
    return CT_SUCCESS;
}

static inline status_t convert_node_to_nl_batch(sql_stmt_t *stmt, sql_join_node_t *join_node, sql_table_t *old_table,
    sql_table_t *new_table)
{
    visit_assist_t visit_ass;
    sql_init_visit_assist(&visit_ass, stmt, NULL);
    visit_ass.result0 = new_table->id;
    visit_ass.result1 = old_table->id;
    visit_ass.excl_flags = SQL_EXCL_NONE;
    join_node->oper = JOIN_OPER_NL_BATCH;
    CT_RETURN_IFERR(replace_table_in_array(&join_node->tables, old_table, new_table));
    CT_RETURN_IFERR(replace_table_in_array(&join_node->right->tables, old_table, new_table));
    return visit_cond_node(&visit_ass, join_node->filter->root, replace_table_id_4_split_nl);
}

static inline status_t gen_rowid_scan_nl_node(sql_stmt_t *stmt, sql_join_node_t *sub_node, sql_table_t *table,
    sql_join_node_t **join_node)
{
    sql_join_node_t *tab_node = NULL;
    CT_RETURN_IFERR(sql_create_join_node(stmt, JOIN_TYPE_NONE, table, NULL, NULL, NULL, &tab_node));
    CT_RETURN_IFERR(sql_create_join_node(stmt, JOIN_TYPE_INNER, NULL, NULL, sub_node, tab_node, join_node));
    (*join_node)->oper = JOIN_OPER_NL;
    (*join_node)->cost = sub_node->cost;
    return CT_SUCCESS;
}

static bool32 if_subslct_has_drive(visit_assist_t *va, expr_node_t *node)
{
    sql_select_t *select_ctx = (sql_select_t *)node->value.v_obj.ptr;
    if (select_ctx->parent_refs->count == 0) {
        return CT_FALSE;
    }

    for (uint32 i = 0; i < select_ctx->parent_refs->count; i++) {
        parent_ref_t *parent_ref = (parent_ref_t *)cm_galist_get(select_ctx->parent_refs, i);
        if (parent_ref->tab == va->result1) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

static status_t chk_drive_in_expr_node(visit_assist_t *va, expr_node_t **node)
{
    if ((*node)->type == EXPR_NODE_COLUMN || (*node)->type == EXPR_NODE_TRANS_COLUMN) {
        if (NODE_ANCESTOR(*node) == 0 && va->result1 == NODE_TAB(*node)) {
            va->result0 = CT_TRUE;
        }
        return CT_SUCCESS;
    }

    if (NODE_IS_RES_ROWID(*node)) {
        if (ROWID_NODE_ANCESTOR(*node) == 0 && va->result1 == ROWID_NODE_TAB(*node)) {
            va->result0 = CT_TRUE;
        }
        return CT_SUCCESS;
    }

    if ((*node)->type == EXPR_NODE_SELECT && if_subslct_has_drive(va, *node)) {
        va->result0 = CT_TRUE;
    }
    return CT_SUCCESS;
}

static inline bool32 if_expr_has_drive(visit_assist_t *visit_ass, expr_tree_t *expr)
{
    (void)visit_expr_tree(visit_ass, expr, chk_drive_in_expr_node);
    return (bool32)visit_ass->result0;
}

static inline bool32 if_aggr_node_has_drive(visit_assist_t *visit_ass, galist_t *aggrs)
{
    expr_node_t *func_node = NULL;
    for (uint32 i = 0; i < aggrs->count; i++) {
        func_node = (expr_node_t *)cm_galist_get(aggrs, i);
        CT_RETVALUE_IFTRUE(if_expr_has_drive(visit_ass, func_node->argument), CT_TRUE);
    }
    return CT_FALSE;
}

static inline bool32 if_group_exprs_has_drive(visit_assist_t *visit_ass, galist_t *group_exprs)
{
    expr_tree_t *expr = NULL;
    for (uint32 i = 0; i < group_exprs->count; i++) {
        expr = (expr_tree_t *)cm_galist_get(group_exprs, i);
        CT_RETVALUE_IFTRUE(if_expr_has_drive(visit_ass, expr), CT_TRUE);
    }
    return CT_FALSE;
}

static inline bool32 if_groupby_has_drive(visit_assist_t *visit_ass, galist_t *group_sets)
{
    group_set_t *group_set = NULL;
    for (uint32 i = 0; i < group_sets->count; i++) {
        group_set = (group_set_t *)cm_galist_get(group_sets, i);
        CT_RETVALUE_IFTRUE(if_group_exprs_has_drive(visit_ass, group_set->items), CT_TRUE);
    }
    return CT_FALSE;
}

static inline bool32 if_sort_items_has_drive(visit_assist_t *visit_ass, galist_t *sort_items)
{
    sort_item_t *item = NULL;
    for (uint32 i = 0; i < sort_items->count; i++) {
        item = (sort_item_t *)cm_galist_get(sort_items, i);
        CT_RETVALUE_IFTRUE(if_expr_has_drive(visit_ass, item->expr), CT_TRUE);
    }
    return CT_FALSE;
}

static inline bool32 if_orderby_has_drive(visit_assist_t *visit_ass)
{
    sql_query_t *query = visit_ass->query;
    if (query->has_distinct || query->group_sets->count > 0 || query->winsort_list->count > 0) {
        return CT_FALSE;
    }
    return if_sort_items_has_drive(visit_ass, query->sort_items);
}


#define SPLIT_TABLE_COUNT 2
static status_t try_split_nl_node(sql_stmt_t *stmt, plan_assist_t *pa, sql_join_node_t **join_root)
{
    return CT_SUCCESS;
}

bool32 sql_has_hash_join_oper(sql_join_node_t *join_node)
{
    if (join_node->type == JOIN_TYPE_NONE) {
        return CT_FALSE;
    }
    if (join_node->oper >= JOIN_OPER_HASH) {
        return CT_TRUE;
    }
    if (sql_has_hash_join_oper(join_node->left)) {
        return CT_TRUE;
    }
    return sql_has_hash_join_oper(join_node->right);
}

static status_t sql_finalize_join_tree(sql_stmt_t *stmt, plan_assist_t *pa, sql_join_node_t **join_root)
{
    uint32 step = pa->query->tables.count;
    pa->is_final_plan = CT_TRUE;

    CT_RETURN_IFERR(sql_build_join_tree(stmt, pa, join_root));

    CT_RETURN_IFERR(try_split_nl_node(stmt, pa, join_root));

    pa->query->join_root = *join_root;

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, step * step * sizeof(uint8), (void **)&pa->join_oper_map));

    CT_RETURN_IFERR(perfect_tree_and_gen_oper_map(pa, step, *join_root));

    return CT_SUCCESS;
}

static status_t optimized_with_join_tree(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_join_node_t **join_root)
{
    CT_RETURN_IFERR(sql_finalize_join_tree(stmt, plan_ass, join_root));
    return CT_SUCCESS;
}

status_t sql_create_query_scan_plan(sql_stmt_t *stmt, plan_assist_t *plan_ass, plan_node_t **plan)
{
    if (plan_ass->table_count > 1) {
        sql_join_node_t *join_root = NULL;
        CT_RETURN_IFERR(optimized_with_join_tree(stmt, plan_ass, &join_root));
        plan_ass->query->cost = join_root->cost;
        plan_ass->cbo_flags = CBO_NONE_FLAG;
        return sql_create_join_plan(stmt, plan_ass, join_root, join_root->filter, plan);
    }

    plan_ass->has_parent_join = (bool8)plan_ass->query->cond_has_acstor_col;
    CBO_SET_FLAGS(plan_ass, CBO_CHECK_FILTER_IDX | CBO_CHECK_JOIN_IDX);
    CT_RETURN_IFERR(sql_check_table_indexable(stmt, plan_ass, plan_ass->tables[0], plan_ass->cond));
    plan_ass->query->cost.card = plan_ass->tables[0]->card;
    plan_ass->query->cost.cost = plan_ass->tables[0]->cost;
    if (plan_ass->query->join_card == CT_INVALID_INT64) {
        plan_ass->query->join_card = TABLE_CBO_FILTER_ROWS(plan_ass->tables[0]);
    }

    plan_ass->cbo_flags = CBO_NONE_FLAG;
    return sql_create_table_scan_plan(stmt, plan_ass, plan_ass->cond, plan_ass->tables[0], plan);
}

#ifdef __cplusplus
}
#endif
