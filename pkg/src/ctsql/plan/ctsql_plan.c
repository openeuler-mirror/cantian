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
 * ctsql_plan.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/plan/ctsql_plan.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_plan.h"
#include "plan_dml.h"
#include "plan_query.h"
#include "plan_rbo.h"
#include "plan_range.h"
#include "dml_parser.h"
#include "ctsql_func.h"
#include "ctsql_table_func.h"
#include "expr_parser.h"
#include "srv_instance.h"
#include "dml_executor.h"

#ifdef __cplusplus
extern "C" {
#endif

plan_assist_t *sql_get_ancestor_pa(plan_assist_t *curr_pa, uint32 temp_ancestor)
{
    uint32 anc = temp_ancestor;
    while (anc > 0 && curr_pa != NULL) {
        curr_pa = curr_pa->parent;
        anc--;
    }
    return curr_pa;
}

sql_query_t *sql_get_ancestor_query(sql_query_t *query, uint32 anc)
{
    uint32 depth = 0;
    while (depth < anc) {
        if (query == NULL || query->owner == NULL) {
            return NULL;
        }
        query = query->owner->parent;
        depth++;
    }
    return query;
}

void sql_collect_select_nodes(biqueue_t *queue, select_node_t *node)
{
    if (node->type == SELECT_NODE_QUERY) {
        biqueue_add_tail(queue, QUEUE_NODE_OF(node));
    } else {
        sql_collect_select_nodes(queue, node->left);
        sql_collect_select_nodes(queue, node->right);
    }
}

status_t visit_select_node(sql_stmt_t *stmt, select_node_t *node, query_visit_func_t visit_func)
{
    // The query node is processed separately to avoid the scenario where the node is already in queue.
    if (node->type == SELECT_NODE_QUERY) {
        return visit_func(stmt, node->query);
    }
    biqueue_t queue;
    biqueue_init(&queue);
    sql_collect_select_nodes(&queue, node);

    select_node_t *obj = NULL;
    biqueue_node_t *cur = biqueue_first(&queue);
    biqueue_node_t *end = biqueue_end(&queue);

    while (cur != end) {
        obj = OBJECT_OF(select_node_t, cur);
        if (obj != NULL && obj->query != NULL) {
            CT_RETURN_IFERR(visit_func(stmt, obj->query));
        }
        cur = BINODE_NEXT(cur);
    }
    return CT_SUCCESS;
}

static inline bool32 is_analyzed_table(sql_stmt_t *stmt, sql_table_t *table)
{
    if (CT_IS_SUBSELECT_TABLE(table->type)) {
        return CT_FALSE;
    }
    return IS_ANALYZED_TABLE(table);
}

#define MIN_PARAM_ROWNUM (uint32)1
#define MAX_PARAM_ROWNUM (uint32)1000

static uint32 sql_calc_param_rownum(sql_stmt_t *stmt, cmp_node_t *cmp, expr_node_t *left_node, expr_node_t *right_node)
{
    switch (cmp->type) {
        case CMP_TYPE_EQUAL:
        case CMP_TYPE_EQUAL_ANY:
            return MIN_PARAM_ROWNUM;
        case CMP_TYPE_LESS:
        case CMP_TYPE_LESS_EQUAL:
        case CMP_TYPE_LESS_ALL:
        case CMP_TYPE_LESS_ANY:
        case CMP_TYPE_LESS_EQUAL_ALL:
            if (NODE_IS_RES_ROWNUM(left_node) && NODE_IS_PARAM(right_node)) {
                return MAX_PARAM_ROWNUM;
            }
            break;
        case CMP_TYPE_GREAT:
        case CMP_TYPE_GREAT_ALL:
        case CMP_TYPE_GREAT_ANY:
        case CMP_TYPE_GREAT_EQUAL:
        case CMP_TYPE_GREAT_EQUAL_ALL:
            if (NODE_IS_RES_ROWNUM(right_node) && NODE_IS_PARAM(left_node)) {
                return MAX_PARAM_ROWNUM;
            }
            break;
        default:
            break;
    }
    return CT_INFINITE32;
}

uint32 sql_calc_rownum(sql_stmt_t *stmt, sql_query_t *query)
{
    if ((query->join_assist.outer_node_count == 0 && query->cond == NULL) ||
        (query->join_assist.outer_node_count > 0 && query->filter_cond == NULL)) {
        return CT_INFINITE32;
    }
    cond_tree_t *cond = sql_get_rownum_cond(stmt, query);
    uint32 row_num_upper = GET_MAX_ROWNUM(cond);
    if (row_num_upper != CT_INFINITE32 || cond == NULL) {
        return row_num_upper;
    }
    // handle rownum param
    cond_node_t *node = cond->root;
    if (node->type != COND_NODE_COMPARE) {
        return CT_INFINITE32;
    }
    expr_tree_t *left = node->cmp->left;
    expr_tree_t *right = node->cmp->right;
    if (left != NULL && right != NULL) {
        if ((NODE_IS_RES_ROWNUM(left->root) && NODE_IS_PARAM(right->root)) ||
            (NODE_IS_RES_ROWNUM(right->root) && NODE_IS_PARAM(left->root))) {
            return sql_calc_param_rownum(stmt, node->cmp, left->root, right->root);
        }
    }
    return CT_INFINITE32;
}

static inline uint32 get_query_cond_max_ancestor(sql_query_t *query)
{
    if (!query->cond_has_acstor_col || query->cond == NULL) {
        return 0;
    }
    cols_used_t cols_used;
    init_cols_used(&cols_used);
    sql_collect_cols_in_cond(query->cond->root, &cols_used);
    return cols_used.ancestor;
}

void sql_init_plan_assist_impl(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_query_t *query, sql_node_type_t type,
    plan_assist_t *parent)
{
    plan_ass->stmt = stmt;
    {
        plan_ass->cond = query->cond;
    }
    plan_ass->type = type;
    plan_ass->query = query;
    plan_ass->top_pa = NULL;
    plan_ass->cbo_flags = CBO_NONE_FLAG;
    plan_ass->cbo_index_ast = NONE_INDEX;
    plan_ass->col_use_flag = USE_NONE_FLAG;
    plan_ass->spec_drive_flag = DRIVE_FOR_NONE;
    plan_ass->has_parent_join = query->cond_has_acstor_col;
    plan_ass->max_ancestor = 0;
    plan_ass->no_nl_batch = CT_FALSE;
    plan_ass->resv_outer_join = CT_FALSE;
    plan_ass->hj_pos = 0;
    plan_ass->sort_items = NULL;
    plan_ass->list_expr_count = 0;
    plan_ass->plan_count = 0;
    plan_ass->table_count = query->tables.count;
    plan_ass->join_assist = &query->join_assist;
    plan_ass->join_assist->has_hash_oper = CT_FALSE;
    plan_ass->join_oper_map = NULL;
    plan_ass->parent = parent;
    plan_ass->scan_part_cnt = 1;
    plan_ass->is_final_plan = (parent == NULL) ? CT_FALSE : parent->is_final_plan;
    plan_ass->ignore_hj = (parent == NULL) ? CT_FALSE : parent->ignore_hj;
    plan_ass->is_subqry_cost = CT_FALSE;
    plan_ass->join_card_map = NULL;
    plan_ass->nlf_mtrl_cnt = 0;
    plan_ass->nlf_dupl_plan_cnt = 0;
    plan_ass->is_nl_full_opt = CT_FALSE;
    plan_ass->save_plcnt = 0;
    plan_ass->filter_node_pptr = NULL;
    plan_ass->vpeek_flag = CT_FALSE;
}

static inline void set_query_sort_plan_flag(sql_query_t *query, uint32 *flag)
{
    if (query->sort_items->count > 0) {
        if (query->order_siblings && !query->has_distinct) {
            (*flag) |= EX_QUERY_SIBL_SORT;
        } else {
            (*flag) |= EX_QUERY_SORT;
        }
    }
}

static inline void set_query_pivot_plan_flag(sql_query_t *query, uint32 *flag)
{
    if (query->pivot_items != NULL) {
        if (query->pivot_items->type == PIVOT_TYPE) {
            (*flag) |= EX_QUERY_PIVOT;
        } else if (query->pivot_items->type == UNPIVOT_TYPE) {
            (*flag) |= EX_QUERY_UNPIVOT;
        }
    }
}

uint32 get_query_plan_flag(sql_query_t *query)
{
    bool32 flag = 0;
    if (query->for_update != CT_FALSE) {
        flag |= EX_QUERY_FOR_UPDATE;
    }

    if (query->has_distinct != CT_FALSE) {
        flag |= EX_QUERY_DISTINCT;
    }

    if (query->having_cond != NULL) {
        flag |= EX_QUERY_HAVING;
    }

    set_query_sort_plan_flag(query, &flag);

    if (query->group_cubes != NULL) {
        flag |= EX_QUERY_CUBE;
    }

    if (query->aggrs->count > 0 || query->group_sets->count > 0) {
        flag |= EX_QUERY_AGGR;
    }

    if (LIMIT_CLAUSE_OCCUR(&query->limit)) {
        flag |= EX_QUERY_LIMIT;
    }

    if (query->connect_by_cond != NULL) {
        flag |= EX_QUERY_CONNECT;
    }
    if (query->filter_cond != NULL) {
        flag |= EX_QUERY_FILTER;
    }

    if (query->winsort_list->count > 0) {
        flag |= EX_QUERY_WINSORT;
    }

    set_query_pivot_plan_flag(query, &flag);

    // (query->cond != NULL && query->cond->rownum_upper == 0) == > rownum count
    if (QUERY_HAS_ROWNUM(query) || (query->cond != NULL && query->cond->rownum_upper == 0)) {
        flag |= EX_QUERY_ROWNUM;
    }
    return flag;
}

void sql_init_plan_assist(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_query_t *query, sql_node_type_t type,
    plan_assist_t *parent)
{
    sql_init_plan_assist_impl(stmt, plan_ass, query, type, parent);
    for (uint32 i = 0; i < plan_ass->table_count; i++) {
        plan_ass->tables[i] = (sql_table_t *)sql_array_get(&query->tables, i);
        plan_ass->plan_tables[i] = plan_ass->tables[i];
        plan_ass->plan_tables[i]->scan_mode = SCAN_MODE_TABLE_FULL;
        plan_ass->plan_tables[i]->scan_flag = 0;
        plan_ass->plan_tables[i]->index = NULL;
        plan_ass->plan_tables[i]->plan_id = (plan_ass->table_count > 1) ? CT_INVALID_ID32 : 0;
        plan_ass->query->filter_infos = NULL;
        /* set table extra attr memory allocator */
        TABLE_CBO_ATTR_OWNER(plan_ass->tables[i]) = query->vmc;
    }
    plan_ass->max_ancestor = get_query_cond_max_ancestor(query);
}

static void build_join_oper_map(sql_array_t *l_tables, sql_join_node_t *join_node, uint8 operator_flag, uint32 step,
    uint8 *join_oper_map)
{
    sql_table_t *r_tab = TABLE_OF_JOIN_LEAF(join_node);
    for (uint32 i = 0; i < l_tables->count; i++) {
        sql_table_t *l_tab = (sql_table_t *)sql_array_get(l_tables, i);
        join_oper_map[step * l_tab->id + r_tab->id] = operator_flag;
        join_oper_map[step * r_tab->id + l_tab->id] = operator_flag;
    }
}

static void generate_join_oper_map(sql_join_node_t *join_node, sql_array_t *l_tables, uint8 operator_flag, uint32 step,
    uint8 *join_oper_map)
{
    switch (join_node->oper) {
        case JOIN_OPER_NONE:
            build_join_oper_map(l_tables, join_node, operator_flag, step, join_oper_map);
            break;
        case JOIN_OPER_HASH:
        case JOIN_OPER_HASH_LEFT:
        case JOIN_OPER_HASH_FULL:
        case JOIN_OPER_HASH_SEMI:
        case JOIN_OPER_HASH_ANTI:
        case JOIN_OPER_HASH_ANTI_NA: {
            sql_join_node_t *hash_node = join_node->hash_left ? join_node->left : join_node->right;
            sql_join_node_t *drive_node = join_node->hash_left ? join_node->right : join_node->left;
            generate_join_oper_map(hash_node, l_tables, operator_flag | (uint8)join_node->oper, step, join_oper_map);
            generate_join_oper_map(drive_node, l_tables, operator_flag, step, join_oper_map);
            break;
        }
        default:
            generate_join_oper_map(join_node->left, l_tables, operator_flag | (uint8)join_node->oper, step, join_oper_map);
            generate_join_oper_map(join_node->right, l_tables, operator_flag | (uint8)join_node->oper, step, join_oper_map);
            break;
    }
}

static inline void set_table_global_cached(sql_array_t *r_tables)
{
    for (uint32 i = 0; i < r_tables->count; i++) {
        sql_table_t *r_tab = (sql_table_t *)sql_array_get(r_tables, i);
        r_tab->global_cached = CT_TRUE;
    }
}

status_t perfect_tree_and_gen_oper_map(plan_assist_t *pa, uint32 step, sql_join_node_t *join_node)
{
    if (join_node->type == JOIN_TYPE_NONE) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(perfect_tree_and_gen_oper_map(pa, step, join_node->left));
    CT_RETURN_IFERR(perfect_tree_and_gen_oper_map(pa, step, join_node->right));

    if (join_node->oper == JOIN_OPER_NL || join_node->oper == JOIN_OPER_NL_LEFT ||
        join_node->oper == JOIN_OPER_NL_BATCH) {
        set_table_global_cached(&join_node->right->tables);
    }
    generate_join_oper_map(join_node->right, &join_node->left->tables, (uint8)join_node->oper, step, pa->join_oper_map);
    return CT_SUCCESS;
}


status_t sql_make_index_col_map(plan_assist_t *pa, sql_stmt_t *stmt, sql_table_t *table)
{
    if (pa != NULL && pa->vpeek_flag) {
        return CT_SUCCESS;
    }
    uint32 index_col = 0;
    uint32 col_count = knl_get_column_count(table->entry->dc.handle);
    uint32 vcol_count = knl_get_index_vcol_count(table->index);
    uint32 alloc_size = (col_count + vcol_count) * sizeof(uint16);

    if (table->idx_col_map == NULL) {
        CT_RETURN_IFERR(sql_alloc_mem(stmt->context, alloc_size, (void **)&table->idx_col_map));
    }
    if (alloc_size > 0) {
        MEMS_RETURN_IFERR(memset_sp(table->idx_col_map, alloc_size, 0xFF, alloc_size));
    }

    for (uint32 i = 0; i < table->index->column_count; i++) {
        uint16 col_id = table->index->columns[i];
        if (col_id >= DC_VIRTUAL_COL_START) {
            uint32 vcol_id = col_count + index_col++;
            table->idx_col_map[vcol_id] = i;
        } else {
            table->idx_col_map[col_id] = i;
        }
    }
    return CT_SUCCESS;
}

uint32 sql_get_plan_hash_rows(sql_stmt_t *stmt, plan_node_t *plan)
{
    uint32 card = (uint32)plan->rows * CT_HASH_FACTOR;
    if (!stmt->context->opt_by_rbo) {
        card = MIN(card, CT_CBO_MAX_HASH_COUNT);
    } else {
        card = MIN(card, CT_RBO_MAX_HASH_COUNT);
    }
    return card;
}

static inline bool32 select_node_has_hash_join(select_node_t *slct_node)
{
    if (slct_node->type == SELECT_NODE_QUERY) {
        return sql_query_has_hash_join(slct_node->query);
    }
    if (select_node_has_hash_join(slct_node->left)) {
        return CT_TRUE;
    }
    return select_node_has_hash_join(slct_node->right);
}

bool32 sql_query_has_hash_join(sql_query_t *query)
{
    if (query->join_assist.has_hash_oper) {
        return CT_TRUE;
    }
    for (uint32 i = 0; i < query->tables.count; ++i) {
        sql_table_t *table = (sql_table_t *)sql_array_get(&query->tables, i);
        if (CT_IS_SUBSELECT_TABLE(table->type)) {
            if (select_node_has_hash_join(table->select_ctx->root)) {
                return CT_TRUE;
            }
        }
    }
    return CT_FALSE;
}

sql_table_t *sql_get_driver_table(plan_assist_t *plan_ass)
{
    if (plan_ass->top_pa != NULL) {
        plan_ass = plan_ass->top_pa;
    }
    if (plan_ass->plan_count > 0) {
        return plan_ass->plan_tables[0];
    }
    for (uint32 i = 0; i < plan_ass->table_count; ++i) {
        if (plan_ass->tables[i]->is_join_driver) {
            return plan_ass->tables[i];
        }
    }
    return plan_ass->plan_tables[0];
}

#ifdef __cplusplus
}
#endif
