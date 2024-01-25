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
 * plan_query.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/plan/plan_query.c
 *
 * -------------------------------------------------------------------------
 */
#include "plan_scan.h"
#include "plan_query.h"
#include "plan_dml.h"
#include "plan_rbo.h"
#include "dml_parser.h"
#include "ctsql_func.h"
#include "ctsql_aggr.h"
#include "srv_instance.h"
#include "ctsql_cond_rewrite.h"
#include "ctsql_connect_rewrite.h"
#include "ctsql_limit.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline void set_filter_plan_pptr(plan_assist_t *plan_ass, plan_node_t **pred_plan, plan_node_t *next_plan)
{
    if (next_plan->type == PLAN_NODE_FILTER) {
        plan_ass->filter_node_pptr = pred_plan;
    }
}

static status_t sql_create_winsort_plan(sql_stmt_t *stmt, sql_query_t *query, plan_assist_t *plan_ass,
    plan_node_t **winsort_plan)
{
    plan_node_t *plan = NULL;
    expr_node_t *over_node = NULL;
    plan_node_t *post_plan = NULL;
    plan_node_t *pre_plan = NULL;
    uint32 plan_id = stmt->context->plan_count++;

    if (sql_create_query_plan_ex(stmt, query, plan_ass, &plan) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (query->winsort_list->count == 0) {
        return CT_SUCCESS;
    }
    for (uint32 i = 0; i < query->winsort_list->count; i++) {
        if (sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)&post_plan) != CT_SUCCESS) {
            return CT_ERROR;
        }

        post_plan->type = PLAN_NODE_WINDOW_SORT;
        post_plan->plan_id = plan_id;
        over_node = (expr_node_t *)cm_galist_get(query->winsort_list, i);

        post_plan->winsort_p.winsort = over_node;

        if (pre_plan != NULL) {
            pre_plan->winsort_p.next = post_plan;
        } else {
            *winsort_plan = post_plan;
        }
        pre_plan = post_plan;
        post_plan->winsort_p.rs_columns = query->winsort_rs_columns;
    }
    post_plan->winsort_p.next = plan;
    set_filter_plan_pptr(plan_ass, &post_plan->winsort_p.next, plan);
    return CT_SUCCESS;
}

static status_t sql_create_query_limit_plan(sql_stmt_t *stmt, sql_query_t *query, plan_assist_t *plan_ass,
    plan_node_t **limit_plan)
{
    plan_node_t *plan = NULL;
    uint32 plan_id = stmt->context->plan_count++;

    if (sql_create_query_plan_ex(stmt, query, plan_ass, &plan) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)limit_plan) != CT_SUCCESS) {
        return CT_ERROR;
    }

    (*limit_plan)->type = PLAN_NODE_QUERY_LIMIT;
    (*limit_plan)->plan_id = plan_id;
    (*limit_plan)->limit.item = query->limit;
    (*limit_plan)->limit.next = plan;
    (*limit_plan)->limit.calc_found_rows = query->calc_found_rows;
    set_filter_plan_pptr(plan_ass, &(*limit_plan)->limit.next, plan);
    return CT_SUCCESS;
}

static status_t sql_create_having_plan(sql_stmt_t *stmt, sql_query_t *query, plan_assist_t *plan_ass,
    plan_node_t **having_plan)
{
    plan_node_t *plan = NULL;
    uint32 plan_id = stmt->context->plan_count++;

    if (sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)having_plan) != CT_SUCCESS) {
        return CT_ERROR;
    }

    plan = *having_plan;
    plan->type = PLAN_NODE_HAVING;
    plan->plan_id = plan_id;
    plan->having.cond = query->having_cond;
    return sql_create_query_plan_ex(stmt, query, plan_ass, &plan->having.next);
}

static uint16 sql_get_index_col_table_id(expr_tree_t *expr)
{
    uint16 tab_id;
    expr_node_t *arg_col = NULL;

    if (TREE_EXPR_TYPE(expr) == EXPR_NODE_COLUMN) {
        if (NODE_ANCESTOR(expr->root) != 0) {
            return CT_INVALID_ID16;
        }
    } else {
        arg_col = sql_find_column_in_func(expr->root);
        if (arg_col == NULL || NODE_ANCESTOR(arg_col) != 0) {
            return CT_INVALID_ID16;
        }
    }

    tab_id = (arg_col == NULL) ? EXPR_TAB(expr) : NODE_TAB(arg_col);
    return tab_id;
}

static bool32 sql_group_index_matched(sql_query_t *query, galist_t *group_exprs)
{
    // if group with multiple table columns, the index group cannot be set, so only check one item
    expr_tree_t *expr = (expr_tree_t *)cm_galist_get(group_exprs, 0);
    uint16 table_id = sql_get_index_col_table_id(expr);
    if (table_id == CT_INVALID_ID16) {
        return CT_FALSE;
    }
    sql_table_t *table = (sql_table_t *)(query->tables.items[table_id]);
    if (query->tables.count > 1) {
        return if_is_drive_table(query->join_root, table_id) && CAN_INDEX_GROUP(table->scan_flag);
    }
    return CAN_INDEX_GROUP(table->scan_flag);
}

bool32 sql_can_hash_mtrl_support_aggtype(sql_stmt_t *stmt, sql_query_t *query)
{
    const sql_func_t *func = NULL;
    expr_node_t *aggr_node = NULL;

    for (uint32 i = 0; i < query->aggrs->count; i++) {
        aggr_node = (expr_node_t *)cm_galist_get(query->aggrs, i);
        func = GET_AGGR_FUNC(aggr_node);
        if (func->aggr_type != AGGR_TYPE_AVG && func->aggr_type != AGGR_TYPE_SUM && func->aggr_type != AGGR_TYPE_MIN &&
            func->aggr_type != AGGR_TYPE_MAX && func->aggr_type != AGGR_TYPE_COUNT) {
            return CT_FALSE;
        }
    }
    return CT_TRUE;
}

plan_node_type_t sql_get_group_plan_type(sql_stmt_t *stmt, sql_query_t *query)
{
    expr_node_t *aggr_node = NULL;
    const sql_func_t *func = NULL;

    sql_table_t *table = (sql_table_t *)sql_array_get(&query->tables, 0);
    if (table->fetch_type == REMOTE_FETCHER_GROUP) {
        return PLAN_NODE_GROUP_MERGE;
    }
    if (query->sort_groups != NULL) {
        return PLAN_NODE_SORT_GROUP;
    }

    if (query->group_sets->count == 1) {
        for (uint32 i = 0; i < query->aggrs->count; i++) {
            aggr_node = (expr_node_t *)cm_galist_get(query->aggrs, i);
            func = GET_AGGR_FUNC(aggr_node);
            if (func->aggr_type == AGGR_TYPE_AVG_COLLECT || func->aggr_type == AGGR_TYPE_APPX_CNTDIS ||
                (func->aggr_type == AGGR_TYPE_GROUP_CONCAT && aggr_node->sort_items != NULL)) {
                return PLAN_NODE_MERGE_SORT_GROUP;
            }
        }
    }
    return PLAN_NODE_HASH_GROUP;
}

static status_t sql_generate_group_sets(sql_stmt_t *stmt, sql_query_t *query, group_plan_t *group_p)
{
    cube_node_t *cube_node = NULL;
    if (query->group_cubes == NULL) {
        group_p->sets = query->group_sets;
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(sql_create_list(stmt, &group_p->sets));
    for (uint32 i = 0; i < query->group_cubes->count; ++i) {
        cube_node = (cube_node_t *)cm_galist_get(query->group_cubes, i);
        CT_RETURN_IFERR(cm_galist_insert(group_p->sets, cube_node->group_set));
    }
    return CT_SUCCESS;
}

static status_t sql_create_aggr_sort_items(sql_stmt_t *stmt, expr_node_t *aggr_node, uint32 aggr_cid,
    galist_t *sort_items)
{
    uint32 vm_col;
    SAVE_AND_RESET_NODE_STACK(stmt);
    expr_node_t *node = NULL;
    for (uint32 i = 0; i < aggr_node->sort_items->count; ++i) {
        sort_item_t *sort_item = (sort_item_t *)cm_galist_get(aggr_node->sort_items, i);
        CT_RETURN_IFERR(sql_clone_expr_node(stmt->context, sort_item->expr->root, &node, sql_alloc_mem));
        CT_RETURN_IFERR(cm_galist_insert(sort_items, node));
        vm_col = aggr_cid + sort_items->count - 1;
        CT_RETURN_IFERR(sql_set_group_expr_node(stmt, sort_item->expr->root, vm_col, 0, 0, node));
    }
    SQL_RESTORE_NODE_STACK(stmt);
    return CT_SUCCESS;
}

static status_t sql_generate_merge_group_items(plan_assist_t *plan_ass, group_plan_t *group_p)
{
    uint32 aggr_cid = group_p->exprs->count + group_p->cntdis_columns->count + group_p->aggrs_args;
    CT_RETURN_IFERR(sql_create_list(plan_ass->stmt, &group_p->sort_items));

    for (uint32 i = 0; i < plan_ass->query->aggrs->count; ++i) {
        expr_node_t *aggr_node = (expr_node_t *)cm_galist_get(plan_ass->query->aggrs, i);
        const sql_func_t *func = sql_get_func(&aggr_node->value.v_func);
        CT_CONTINUE_IFTRUE(func->aggr_type != AGGR_TYPE_GROUP_CONCAT || aggr_node->sort_items == NULL);
        CT_RETURN_IFERR(sql_create_aggr_sort_items(plan_ass->stmt, aggr_node, aggr_cid, group_p->sort_items));
        group_p->aggrs_sorts += aggr_node->sort_items->count;
    }
    return CT_SUCCESS;
}

static bool32 sql_par_can_multi_prod(sql_query_t *query, plan_node_t *plan)
{
    return CT_FALSE;
}

static status_t sql_create_group_plan(sql_stmt_t *stmt, sql_query_t *query, plan_assist_t *plan_ass, 
                                      plan_node_t **group_plan)
{
    uint32 i;
    plan_node_t *next_plan = NULL;
    plan_node_t *plan_node = NULL;
    group_set_t *group_set = NULL;
    expr_node_t *expr_node = NULL;
    const sql_func_t *func = NULL;
    uint32 plan_id = stmt->context->plan_count++;

    CT_RETURN_IFERR(sql_create_query_plan_ex(stmt, query, plan_ass, &next_plan));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)group_plan));
    plan_node = *group_plan;
    plan_node->plan_id = plan_id;
    plan_node->type = sql_get_group_plan_type(stmt, query);
    CT_RETURN_IFERR(sql_generate_group_sets(stmt, query, &plan_node->group));
    group_set = (group_set_t *)cm_galist_get(plan_node->group.sets, 0);
    plan_node->group.exprs = group_set->items;
    plan_node->group.aggrs = query->aggrs;
    plan_node->group.cntdis_columns = query->cntdis_columns;
    plan_node->group.sort_groups = query->sort_groups;
    plan_node->group.aggrs_sorts = 0;
    plan_node->group.sort_items = NULL;
    plan_node->group.next = next_plan;
    plan_node->group.multi_prod = sql_par_can_multi_prod(query, plan_node);
    set_filter_plan_pptr(plan_ass, &plan_node->group.next, next_plan);

    plan_node->group.aggrs_args = plan_node->group.aggrs->count;
    /* calculate the number of parameter used by all the aggrs */
    if (query->exists_covar) {
        for (i = 0; i < plan_node->group.aggrs->count; i++) {
            expr_node = (expr_node_t *)cm_galist_get(plan_node->group.aggrs, i);
            func = GET_AGGR_FUNC(expr_node);
            if (func->value_cnt > FO_USUAL) {
                plan_node->group.aggrs_args += (func->value_cnt - FO_USUAL); // covar_pop and covar_samp return two
                                                                        // paremeter
            }
        }
    }
    if (sql_group_index_matched(query, group_set->items)) {
        plan_node->type = PLAN_NODE_INDEX_GROUP;
    }

    if (query->has_aggr_sort) {
        return sql_generate_merge_group_items(plan_ass, &plan_node->group);
    }
    return CT_SUCCESS;
}

static status_t sql_make_cube_sub_plan_aggrs(sql_stmt_t *stmt, sql_query_t *query, galist_t **aggrs)
{
    expr_node_t *aggr_node = NULL;
    expr_node_t *node = NULL;
    sql_func_t *func = NULL;
    CT_RETURN_IFERR(sql_create_list(stmt, aggrs));

    for (uint32 i = 0; i < query->aggrs->count; i++) {
        aggr_node = (expr_node_t *)cm_galist_get(query->aggrs, i);
        func = sql_get_func(&aggr_node->value.v_func);
        CT_RETURN_IFERR(sql_clone_expr_node(stmt->context, aggr_node, &node, sql_alloc_mem));
        if (func->aggr_type == AGGR_TYPE_COUNT) {
            node->value.v_func.func_id = ID_FUNC_ITEM_SUM;
        }
        node->argument->root->type = EXPR_NODE_AGGR;
        node->argument->root->value.v_int = i;
        node->argument->root->value.type = CT_TYPE_INTEGER;
        NODE_OPTIMIZE_MODE(node->argument->root) = OPTIMIZE_NONE;
        CT_RETURN_IFERR(cm_galist_insert(*aggrs, node));
    }
    return CT_SUCCESS;
}

static status_t sql_create_cube_sub_plan(sql_stmt_t *stmt, sql_query_t *query, cube_node_t *cube_node, galist_t *plans,
    galist_t *aggrs)
{
    plan_node_t *plan_node = NULL;
    cube_node_t *sub_node = NULL;
    if (cube_node->leafs == 0) {
        cube_node->plan_id = CT_INVALID_ID32;
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(sql_stack_safe(stmt));

    CT_RETURN_IFERR(cm_galist_new(plans, sizeof(plan_node_t), (void **)&plan_node));
    cube_node->plan_id = plans->count - 1;

    plan_node->type = PLAN_NODE_HASH_GROUP;
    plan_node->plan_id = stmt->context->plan_count++;
    plan_node->group.aggrs = aggrs;
    plan_node->group.cntdis_columns = query->cntdis_columns;
    plan_node->group.sort_groups = NULL;
    plan_node->group.next = NULL;

    CT_RETURN_IFERR(sql_create_list(stmt, &plan_node->group.sets));

    for (uint32 i = 0; i < cube_node->leafs->count; i++) {
        sub_node = (cube_node_t *)cm_galist_get(cube_node->leafs, i);
        if (i == 0) {
            plan_node->group.exprs = sub_node->group_set->items;
        }
        CT_RETURN_IFERR(cm_galist_insert(plan_node->group.sets, sub_node->group_set));
        CT_RETURN_IFERR(sql_create_cube_sub_plan(stmt, query, sub_node, plans, aggrs));
    }
    return CT_SUCCESS;
}

static status_t sql_create_cube_plan(sql_stmt_t *stmt, sql_query_t *query, plan_assist_t *plan_ass, 
                                     plan_node_t **cube_plan)
{
    cube_node_t *cube_node = NULL;
    plan_node_t *next_plan = NULL;
    plan_node_t *plan_node = NULL;
    galist_t *aggrs = NULL;
    uint32 plan_id = stmt->context->plan_count++;

    plan_ass->no_nl_batch = CT_TRUE;
    CT_RETURN_IFERR(sql_create_query_plan_ex(stmt, query, plan_ass, &next_plan));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)cube_plan));
    plan_node = *cube_plan;
    plan_node->type = PLAN_NODE_GROUP_CUBE;
    plan_node->plan_id = plan_id;
    plan_node->cube.sets = query->group_sets;
    plan_node->cube.nodes = query->group_cubes;
    plan_node->cube.next = next_plan;
    set_filter_plan_pptr(plan_ass, &plan_node->cube.next, next_plan);

    CT_RETURN_IFERR(sql_create_list(stmt, &plan_node->cube.plans));
    CT_RETURN_IFERR(sql_make_cube_sub_plan_aggrs(stmt, query, &aggrs));

    for (uint32 i = 0; i < query->group_cubes->count; i++) {
        cube_node = (cube_node_t *)cm_galist_get(query->group_cubes, i);
        CT_RETURN_IFERR(sql_create_cube_sub_plan(stmt, query, cube_node, plan_node->cube.plans, aggrs));
    }
    return CT_SUCCESS;
}

static status_t sql_create_pivot_plan(sql_stmt_t *stmt, sql_query_t *query, plan_assist_t *plan_ass, plan_node_t **plan)
{
    plan_node_t *next_plan = NULL;
    plan_node_t *pivot_plan = NULL;
    group_set_t *group_set = NULL;
    uint32 plan_id = stmt->context->plan_count++;

    plan_ass->no_nl_batch = CT_TRUE;
    CT_RETURN_IFERR(sql_create_query_plan_ex(stmt, query, plan_ass, &next_plan));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)plan));
    pivot_plan = *plan;
    pivot_plan->type = PLAN_NODE_HASH_GROUP_PIVOT;
    pivot_plan->plan_id = plan_id;
    pivot_plan->group.next = next_plan;
    set_filter_plan_pptr(plan_ass, &pivot_plan->group.next, next_plan);

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(pivot_assist_t), (void **)&pivot_plan->group.pivot_assist));
    pivot_plan->group.pivot_assist->for_expr = query->pivot_items->for_expr;
    pivot_plan->group.pivot_assist->in_expr = query->pivot_items->in_expr;
    pivot_plan->group.pivot_assist->aggr_count = query->pivot_items->aggr_count;
    pivot_plan->group.sets = query->pivot_items->group_sets;
    group_set = (group_set_t *)cm_galist_get(query->pivot_items->group_sets, 0);
    pivot_plan->group.exprs = group_set->items;
    pivot_plan->group.cntdis_columns = query->cntdis_columns;
    pivot_plan->group.aggrs = query->pivot_items->aggrs;

    return CT_SUCCESS;
}

static status_t sql_create_unpivot_plan(sql_stmt_t *stmt, sql_query_t *query, 
                                        plan_assist_t *plan_ass, plan_node_t **plan)
{
    plan_node_t *next_plan = NULL;
    plan_node_t *unpivot_plan = NULL;
    pivot_items_t *pivot_items = query->pivot_items;
    uint32 plan_id = stmt->context->plan_count++;

    plan_ass->no_nl_batch = CT_TRUE;
    CT_RETURN_IFERR(sql_create_query_plan_ex(stmt, query, plan_ass, &next_plan));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)plan));
    unpivot_plan = *plan;
    unpivot_plan->type = PLAN_NODE_UNPIVOT;
    unpivot_plan->plan_id = plan_id;
    unpivot_plan->unpivot_p.group_sets = pivot_items->group_sets;
    unpivot_plan->unpivot_p.rows = pivot_items->column_name->count / pivot_items->unpivot_data_rs->count;
    unpivot_plan->unpivot_p.include_nulls = pivot_items->include_nulls;
    unpivot_plan->unpivot_p.alias_rs_count = pivot_items->unpivot_alias_rs->count;
    unpivot_plan->unpivot_p.next = next_plan;
    set_filter_plan_pptr(plan_ass, &unpivot_plan->group.next, next_plan);

    return CT_SUCCESS;
}

static status_t sql_create_hash_mtrl_plan(sql_stmt_t *stmt, sql_query_t *query, plan_assist_t *plan_ass,
    plan_node_t **mtrl_plan)
{
    plan_node_t *next_plan = NULL;
    plan_node_t *plan_node = NULL;
    group_set_t *group_set = NULL;
    uint32 plan_id = stmt->context->plan_count++;

    CT_RETURN_IFERR(sql_create_query_plan_ex(stmt, query, plan_ass, &next_plan));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)mtrl_plan));
    group_set = (group_set_t *)cm_galist_get(query->group_sets, 0);
    plan_node = *mtrl_plan;
    plan_node->type = PLAN_NODE_HASH_MTRL;
    plan_node->plan_id = plan_id;
    plan_node->hash_mtrl.group.sets = query->group_sets;
    plan_node->hash_mtrl.group.exprs = group_set->items;
    plan_node->hash_mtrl.group.aggrs = query->aggrs;
    plan_node->hash_mtrl.remote_keys = query->remote_keys;
    plan_node->hash_mtrl.group.cntdis_columns = query->cntdis_columns;
    plan_node->hash_mtrl.group.next = next_plan;
    plan_node->hash_mtrl.hash_mtrl_id = stmt->context->hash_mtrl_count++;
    set_filter_plan_pptr(plan_ass, &plan_node->hash_mtrl.group.next, next_plan);

    return CT_SUCCESS;
}

static inline uint16 sql_get_index_match_flag(plan_assist_t *plan_ass)
{
    sql_table_t *table = sql_get_driver_table(plan_ass);
    return table->scan_flag;
}

static status_t generate_btree_sort_keys(sql_query_t *query, btree_sort_t *btree_sort, bool8 *sort_key_map,
    bool32 *eliminate_sort)
{
    sort_item_t *item = NULL;
    btree_sort_key_t *btree_sort_key = NULL;

    for (uint32 i = 0; i < query->sort_items->count; ++i) {
        item = (sort_item_t *)cm_galist_get(query->sort_items, i);
        if (item->expr->root->type != EXPR_NODE_GROUP) {
            *eliminate_sort = CT_FALSE;
            continue;
        }

        CT_RETURN_IFERR(cm_galist_new(&btree_sort->sort_key, sizeof(btree_sort_key_t), (void **)&btree_sort_key));
        btree_sort_key->group_id = VALUE_PTR(var_vm_col_t, &item->expr->root->value)->id;
        btree_sort_key->sort_mode = item->sort_mode;
        sort_key_map[btree_sort_key->group_id] = CT_TRUE;
    }
    return CT_SUCCESS;
}

static status_t generate_btree_cmp_keys(btree_sort_t *btree_sort, bool8 *sort_key_map, uint32 total_keys)
{
    btree_cmp_key_t *btree_cmp_key = NULL;

    for (uint32 i = 0; i < total_keys; i++) {
        if (sort_key_map[i]) {
            continue;
        }
        CT_RETURN_IFERR(cm_galist_new(&btree_sort->cmp_key, sizeof(btree_cmp_key_t), (void **)&btree_cmp_key));
        btree_cmp_key->group_id = i;
    }
    return CT_SUCCESS;
}

static status_t sql_generate_btree_sort(sql_stmt_t *stmt, sql_query_t *query, uint32 total_keys,
    btree_sort_t **btree_sort, bool32 *eliminate_sort)
{
    bool8 *sort_key_map = NULL;

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(btree_sort_t), (void **)btree_sort));
    cm_galist_init(&(*btree_sort)->cmp_key, stmt->context, sql_alloc_mem);
    cm_galist_init(&(*btree_sort)->sort_key, stmt->context, sql_alloc_mem);

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, total_keys * sizeof(bool8), (void **)&sort_key_map));
    CT_RETURN_IFERR(generate_btree_sort_keys(query, *btree_sort, sort_key_map, eliminate_sort));
    return generate_btree_cmp_keys(*btree_sort, sort_key_map, total_keys);
}

static status_t sql_get_distinct_plan_type(sql_stmt_t *stmt, sql_query_t *query, plan_assist_t *plan_ass, 
                                           plan_node_t *plan,
    plan_node_type_t *plan_type)
{
    bool32 eliminate_sort = CT_TRUE;

    if (query->connect_by_cond != NULL) {
        CT_RETURN_IFERR(sql_generate_btree_sort(stmt, query, plan->distinct.columns->count, &plan->distinct.btree_sort,
            &eliminate_sort));
        if (eliminate_sort) {
            cm_galist_reset(query->sort_items);
        }
        *plan_type = PLAN_NODE_SORT_DISTINCT;
        return CT_SUCCESS;
    }

    uint16 scan_flag = sql_get_index_match_flag(plan_ass);
    if (CAN_INDEX_DISTINCT(scan_flag) && CAN_INDEX_SORT(scan_flag)) {
        cm_galist_reset(query->sort_items);
        *plan_type = PLAN_NODE_INDEX_DISTINCT;
        return CT_SUCCESS;
    }

    if (query->sort_items->count >= plan->distinct.columns->count * SORT_DISTINCT_FACTOR) {
        CT_RETURN_IFERR(sql_generate_btree_sort(stmt, query, plan->distinct.columns->count, &plan->distinct.btree_sort,
            &eliminate_sort));
        if (eliminate_sort) {
            cm_galist_reset(query->sort_items);
            *plan_type = PLAN_NODE_SORT_DISTINCT;
            return CT_SUCCESS;
        }
    }

    *plan_type = CAN_INDEX_DISTINCT(scan_flag) ? PLAN_NODE_INDEX_DISTINCT : PLAN_NODE_HASH_DISTINCT;
    return CT_SUCCESS;
}

#define DISTINCT_PRUNING_ENABLED g_instance->sql.enable_distinct_pruning
static status_t sql_eliminate_distinct_const_col(sql_stmt_t *stmt, sql_query_t *query, plan_node_type_t plan_type)
{
    if (!DISTINCT_PRUNING_ENABLED || plan_type != PLAN_NODE_HASH_DISTINCT || query->sort_items->count > 0 ||
        query->group_sets->count > 0 || query->connect_by_cond != NULL || query->pivot_items != NULL) {
        return CT_SUCCESS;
    }
    rs_column_t *rs_col = NULL;
    rs_column_t *del_col = NULL;
    uint32 del_count = 0;

    for (uint32 i = 0; i < query->distinct_columns->count;) {
        del_col = (rs_column_t *)cm_galist_get(query->distinct_columns, i);
        rs_col = (rs_column_t *)cm_galist_get(query->rs_columns, i + del_count);

        // Last distinct column must be left.
        if (query->distinct_columns->count > 1 && del_col->type == RS_COL_CALC &&
            sql_can_expr_node_optm_by_hash(del_col->expr->root)) {
            cm_galist_delete(query->distinct_columns, i); // Should not i++ after delete list item.
            rs_col->expr->root = del_col->expr->root;
            del_count++;
        } else {
            rs_col->expr->root->value.v_vm_col.id -= del_count;
            i++;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_create_distinct_plan(sql_stmt_t *stmt, sql_query_t *query, plan_assist_t *plan_ass,
    plan_node_t **distinct_plan)
{
    plan_node_t *plan = NULL;
    plan_node_t *next_plan = NULL;
    uint32 plan_id = stmt->context->plan_count++;

    CT_RETURN_IFERR(sql_create_query_plan_ex(stmt, query, plan_ass, &next_plan));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)distinct_plan));
    plan = *distinct_plan;
    plan->plan_id = plan_id;
    plan->distinct.next = next_plan;
    plan->distinct.columns = query->distinct_columns;
    set_filter_plan_pptr(plan_ass, &plan->distinct.next, next_plan);
    CT_RETURN_IFERR(sql_get_distinct_plan_type(stmt, query, plan_ass, plan, &plan->type));
    return sql_eliminate_distinct_const_col(stmt, query, plan->type);
}

status_t sql_create_aggr_plan_no_optimize(sql_stmt_t *stmt, sql_query_t *query, plan_assist_t *plan_ass,
    plan_node_t **group_plan)
{
    plan_node_t *plan = NULL;
    status_t ret;
    uint32 plan_id = stmt->context->plan_count++;

    ret = sql_create_query_plan_ex(stmt, query, plan_ass, &plan);
    CT_RETURN_IFERR(ret);
    ret = sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)group_plan);
    CT_RETURN_IFERR(ret);

    (*group_plan)->plan_id = plan_id;
    (*group_plan)->type = PLAN_NODE_AGGR;
    (*group_plan)->aggr.items = query->aggrs;
    (*group_plan)->aggr.cntdis_columns = query->cntdis_columns;
    (*group_plan)->aggr.next = plan;
    set_filter_plan_pptr(plan_ass, &(*group_plan)->aggr.next, plan);
    return CT_SUCCESS;
}

static inline status_t sql_generate_optimize_aggr_cond(sql_stmt_t *stmt, sql_query_t *query, expr_tree_t *aggrarg)
{
    uint32 rownum_upper;
    cond_node_t *cond_node = NULL;

    if (query->cond == NULL) {
        CT_RETURN_IFERR(sql_create_cond_tree(stmt->context, &query->cond));
    }
    rownum_upper = MIN(query->cond->rownum_upper, 1);

    // build condition: xxx IS NOT NULL
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&cond_node));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&cond_node->cmp));
    cond_node->type = COND_NODE_COMPARE;
    cond_node->cmp->type = CMP_TYPE_IS_NOT_NULL;
    cond_node->cmp->left = aggrarg;
    CT_RETURN_IFERR(sql_add_cond_node(query->cond, cond_node));
    query->cond->rownum_upper = rownum_upper;
    return CT_SUCCESS;
}

static inline void set_aggr_sort_item_info(expr_node_t *aggr_node, sort_item_t *item, bool32 only_max)
{
    unary_oper_t unary;
    item->expr = aggr_node->argument;
    unary = item->expr->root->unary;
    if (only_max) {
        item->direction = unary == UNARY_OPER_NEGATIVE ? SORT_MODE_ASC : SORT_MODE_DESC;
    } else {
        item->direction = unary == UNARY_OPER_NEGATIVE ? SORT_MODE_DESC : SORT_MODE_ASC;
    }
    item->nulls_pos = DEFAULT_NULLS_SORTING_POSITION(item->direction);
}

static status_t sql_create_aggr_plan(sql_stmt_t *stmt, sql_query_t *query, plan_assist_t *plan_ass, plan_node_t **plan)
{
    plan_node_t *next_plan = NULL;
    expr_node_t *aggrnode = NULL;
    bool32 onlymin = CT_FALSE;
    bool32 onlymax = CT_FALSE;
    galist_t *sort_items = NULL;
    sort_item_t *item = NULL;
    const sql_func_t *func = NULL;

    // must be the nearest one to filter plan
    // like select max(c) from t where a = ? and b = ?; (a,b,c) is index
    // descend scan can be used according to index (a,b,c), use the first record matched
    aggrnode = (expr_node_t *)cm_galist_get(query->aggrs, 0);
    if (query->aggrs->count == 1) {
        func = GET_AGGR_FUNC(aggrnode);
        onlymin = (func->aggr_type == AGGR_TYPE_MIN);
        onlymax = (func->aggr_type == AGGR_TYPE_MAX);
    }
    if (!onlymax && !onlymin) {
        return sql_create_aggr_plan_no_optimize(stmt, query, plan_ass, plan);
    }

    CTSQL_SAVE_STACK(stmt);
    CT_RETURN_IFERR(cm_stack_alloc(stmt->session->stack, sizeof(galist_t), (void **)&sort_items));
    cm_galist_init(sort_items, stmt->session->stack, cm_stack_alloc);

    CT_RETURN_IFERR(cm_galist_new(sort_items, sizeof(sort_item_t), (void **)&item));
    set_aggr_sort_item_info(aggrnode, item, onlymax);

    uint32 plan_id = stmt->context->plan_count++;
    plan_ass->sort_items = sort_items;
    CT_RETURN_IFERR(sql_create_query_plan_ex(stmt, query, plan_ass, &next_plan));
    plan_ass->sort_items = NULL;

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)plan));
    (*plan)->type = PLAN_NODE_AGGR;
    (*plan)->plan_id = plan_id;
    (*plan)->aggr.items = query->aggrs;
    (*plan)->aggr.cntdis_columns = query->cntdis_columns;
    (*plan)->aggr.next = next_plan;
    set_filter_plan_pptr(plan_ass, &(*plan)->aggr.next, next_plan);

    if (next_plan->type != PLAN_NODE_SCAN || !sql_sort_index_matched(query, sort_items, next_plan)) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_SUCCESS;
    }
    CTSQL_RESTORE_STACK(stmt);
    (*plan)->type = PLAN_NODE_INDEX_AGGR;
    return sql_generate_optimize_aggr_cond(stmt, query, aggrnode->argument);
}

static status_t sql_create_for_update_plan(sql_stmt_t *stmt, sql_query_t *query, plan_assist_t *plan_ass, 
                                           plan_node_t **plan)
{
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)plan));
    (*plan)->type = PLAN_NODE_FOR_UPDATE;
    (*plan)->plan_id = stmt->context->plan_count++;

    plan_ass->no_nl_batch = CT_TRUE;
    CT_RETURN_IFERR(sql_create_query_plan_ex(stmt, query, plan_ass, &(*plan)->for_update.next));
    if (IF_LOCK_IN_FETCH(query)) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_create_list(stmt, &(*plan)->for_update.rowids));

    for (uint32 i = 0; i < query->tables.count; i++) {
        sql_table_t *table = (sql_table_t *)sql_array_get(&query->tables, i);
        if (table->type == NORMAL_TABLE && table->for_update) {
            expr_tree_t *rowid = NULL;
            CT_RETURN_IFERR(sql_create_rowid_expr(stmt, table->id, &rowid));
            CT_RETURN_IFERR(cm_galist_insert((*plan)->for_update.rowids, rowid));
        }
    }
    return CT_SUCCESS;
}

cond_tree_t *sql_get_rownum_cond(sql_stmt_t *stmt, sql_query_t *query)
{
    if (IS_COORDINATOR && IS_APP_CONN(stmt->session)) {
        return query->filter_cond;
    }
    if (query->join_assist.outer_node_count > 0) {
        return query->filter_cond;
    }
    return query->cond;
}

static status_t sql_create_rownum_plan(sql_stmt_t *stmt, sql_query_t *query, plan_assist_t *plan_ass,
    plan_node_t **row_num_plan)
{
    plan_node_t *plan = NULL;
    uint32 plan_id = stmt->context->plan_count++;
    if (QUERY_HAS_ROWNUM(query)) {
        plan_ass->no_nl_batch = CT_TRUE;
    }
    if (sql_create_query_plan_ex(stmt, query, plan_ass, &plan) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)row_num_plan) != CT_SUCCESS) {
        return CT_ERROR;
    }

    (*row_num_plan)->type = PLAN_NODE_ROWNUM;
    (*row_num_plan)->plan_id = plan_id;
    (*row_num_plan)->rownum_p.next = plan;
    (*row_num_plan)->rows = GET_MAX_ROWNUM(sql_get_rownum_cond(stmt, query));
    set_filter_plan_pptr(plan_ass, &(*row_num_plan)->rownum_p.next, plan);

    return CT_SUCCESS;
}

static status_t sql_create_filter_plan(sql_stmt_t *stmt, sql_query_t *query, plan_assist_t *plan_ass,
    plan_node_t **filter_plan)
{
    plan_node_t *plan = NULL;

    plan_ass->filter_node_pptr = filter_plan;
    if (sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)filter_plan) != CT_SUCCESS) {
        return CT_ERROR;
    }

    plan = *filter_plan;
    plan->type = PLAN_NODE_FILTER;
    plan->filter.cond = query->filter_cond;
    plan->plan_id = stmt->context->plan_count++;
    return sql_create_query_plan_ex(stmt, query, plan_ass, &plan->filter.next);
}

static bool32 sql_sort_scan_index_matched(sql_query_t *query, galist_t *sort_items)
{
    // if sort with multi table columns, then sortable can not be set, so only check one item
    sort_item_t *sort_item = (sort_item_t *)cm_galist_get(sort_items, 0);
    expr_tree_t *expr = sort_item->expr;
    uint16 tab = sql_get_index_col_table_id(expr);
    if (tab == CT_INVALID_ID16) {
        return CT_FALSE;
    }
    sql_table_t *table = (sql_table_t *)query->tables.items[tab];
    if (query->tables.count > 1) {
        return if_is_drive_table(query->join_root, tab) && CAN_INDEX_SORT(table->scan_flag);
    }
    return CAN_INDEX_SORT(table->scan_flag);
}

static bool32 sql_match_sort_items(galist_t *sort_items, galist_t *checkitems)
{
    return CT_FALSE;
}

bool32 if_is_drive_table(sql_join_node_t *join_node, uint16 table)
{
    switch (join_node->oper) {
        case JOIN_OPER_HASH:
        case JOIN_OPER_HASH_LEFT:
        case JOIN_OPER_HASH_SEMI:
        case JOIN_OPER_HASH_ANTI:
        case JOIN_OPER_HASH_ANTI_NA:
            if (join_node->hash_left) {
                return (bool32)(!sql_table_in_list(&join_node->left->tables, table) &&
                    if_is_drive_table(join_node->right, table));
            }
            return (bool32)(!sql_table_in_list(&join_node->right->tables, table) &&
                if_is_drive_table(join_node->left, table));

        case JOIN_OPER_NL:
        case JOIN_OPER_NL_LEFT:
        case JOIN_OPER_NL_BATCH:
            return (bool32)(!sql_table_in_list(&join_node->right->tables, table) &&
                if_is_drive_table(join_node->left, table));

        case JOIN_OPER_NONE:
            return (table == TABLE_OF_JOIN_LEAF(join_node)->id);

        default:
            return CT_FALSE;
    }
}

bool32 sql_sort_index_matched(sql_query_t *query, galist_t *sort_items, plan_node_t *next_plan)
{
    sql_query_t *nextqry = NULL;

    switch (next_plan->type) {
        case PLAN_NODE_AGGR:
        case PLAN_NODE_SORT_DISTINCT:
            return sql_match_sort_items(sort_items, next_plan->aggr.items);

        case PLAN_NODE_HAVING:
            return sql_sort_index_matched(query, sort_items, next_plan->having.next);
        case PLAN_NODE_UNION:
        case PLAN_NODE_MINUS:
        case PLAN_NODE_HASH_MINUS:
            nextqry = next_plan->set_p.left->query.ref;
            return sql_match_sort_items(sort_items, nextqry->rs_columns);

        case PLAN_NODE_SCAN:
        case PLAN_NODE_JOIN:
            break;
        case PLAN_NODE_CONNECT:
        case PLAN_NODE_CONNECT_HASH:
            if (query->order_siblings) {
                if (next_plan->connect.next_start_with == next_plan->connect.next_connect_by) {
                    return sql_sort_index_matched(query, sort_items, next_plan->connect.next_start_with);
                } else {
                    return (bool32)(sql_sort_index_matched(query, sort_items, next_plan->connect.next_start_with) &&
                        sql_sort_index_matched(query, sort_items, next_plan->connect.next_connect_by));
                }
            }
            return CT_FALSE;
        case PLAN_NODE_ROWNUM:
            return sql_sort_index_matched(query, sort_items, next_plan->rownum_p.next);
        case PLAN_NODE_FILTER:
            return sql_sort_index_matched(query, sort_items, next_plan->filter.next);
        default:
            return CT_FALSE;
    }

    return sql_sort_scan_index_matched(query, sort_items);
}

status_t sql_create_group_rs_from_column(sql_stmt_t *stmt, rs_column_t *column, rs_column_t *rs_col, uint32 index)
{
    expr_node_t *origin_ref = NULL;

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(expr_tree_t), (void **)&rs_col->expr));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&rs_col->expr->root));
    rs_col->expr->root->typmod.is_array = column->typmod.is_array;
    rs_col->type = RS_COL_CALC;
    rs_col->expr->owner = stmt->context;
    rs_col->expr->root->datatype = column->datatype;

    CT_RETURN_IFERR(sql_generate_origin_ref(stmt, column, &origin_ref));
    return sql_set_group_expr_node(stmt, rs_col->expr->root, index, 0, 0, origin_ref);
}

status_t sql_create_mtrl_plan_rs_columns(sql_stmt_t *stmt, sql_query_t *query, galist_t **plan_rs_columns)
{
    uint32 i;
    rs_column_t *plan_rs_col = NULL;
    rs_column_t *query_rs_col = NULL;
    galist_t *query_rs_columns = query->rs_columns;
    if (sql_create_list(stmt, plan_rs_columns) != CT_SUCCESS) {
        return CT_ERROR;
    }

    for (i = 0; i < query_rs_columns->count; i++) {
        if (cm_galist_new(*plan_rs_columns, sizeof(rs_column_t), (pointer_t *)&plan_rs_col) != CT_SUCCESS) {
            return CT_ERROR;
        }

        query_rs_col = (rs_column_t *)cm_galist_get(query_rs_columns, i);
        *plan_rs_col = *query_rs_col;
        SET_NODE_STACK_CURR_QUERY(stmt, query);
        CT_RETURN_IFERR(sql_create_group_rs_from_column(stmt, query_rs_col, plan_rs_col, i));
        SQL_RESTORE_NODE_STACK(stmt);
    }

    return CT_SUCCESS;
}

static inline bool32 check_subselect_rs_in_order(expr_node_t *select_rs, galist_t *sort_items)
{
    sort_item_t *item = NULL;
    for (uint32 i = 0; i < sort_items->count; i++) {
        item = (sort_item_t *)cm_galist_get(sort_items, i);
        if (select_rs->value.v_obj.id == item->expr->root->value.v_obj.id &&
            select_rs->value.v_obj.ptr == item->expr->root->value.v_obj.ptr) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

static inline bool32 check_rs_has_pending_rownum(plan_node_t *sort_plan, rs_column_t *rs_col)
{
    return sort_plan->type == PLAN_NODE_QUERY_SIBL_SORT && CT_BIT_TEST(rs_col->rs_flag, RS_HAS_ROWNUM);
}

static inline bool32 check_dyna_subselect_can_mtrl_opt(rs_column_t *query_rs_col, galist_t *sort_items)
{
    return (!IS_COORDINATOR) && query_rs_col->type == RS_COL_CALC &&
        query_rs_col->expr->root->type == EXPR_NODE_SELECT &&
        ((sql_select_t *)query_rs_col->expr->root->value.v_obj.ptr)->parent_refs->count != 0 &&
        !check_subselect_rs_in_order(query_rs_col->expr->root, sort_items);
}

status_t gen_group_expr_except_rownum(visit_assist_t *va, expr_node_t **node)
{
    if (NODE_IS_RES_ROWNUM(*node) || NODE_IS_CONST(*node)) {
        return CT_SUCCESS;
    }

    return sql_gen_group_rs_by_expr(va->stmt, (galist_t *)va->param0, *node);
}

status_t gen_mtrl_expr_by_pending_rownum(sql_stmt_t *stmt, galist_t *columns, expr_tree_t *expr)
{
    visit_assist_t visit_as;
    sql_init_visit_assist(&visit_as, stmt, NULL);
    visit_as.param0 = columns;
    return visit_expr_tree(&visit_as, expr, gen_group_expr_except_rownum);
}

static status_t sql_create_sort_plan_mtrl_columns(sql_stmt_t *stmt, galist_t *query_rs_columns, plan_node_t *plan,
    galist_t *sort_items)
{
    rs_column_t *query_rs_col = NULL;
    rs_column_t *plan_rs_col = NULL;
    query_sort_plan_t *sort_plan = &plan->query_sort;

    CT_RETURN_IFERR(sql_create_list(stmt, &sort_plan->select_columns));
    for (uint32 i = 0; i < query_rs_columns->count; i++) {
        query_rs_col = (rs_column_t *)cm_galist_get(query_rs_columns, i);
        if (check_rs_has_pending_rownum(plan, query_rs_col)) {
            sort_plan->has_pending_rs = CT_TRUE;
            CT_RETURN_IFERR(gen_mtrl_expr_by_pending_rownum(stmt, sort_plan->select_columns, query_rs_col->expr));
        } else if (check_dyna_subselect_can_mtrl_opt(query_rs_col, sort_items)) {
            sort_plan->has_pending_rs = CT_TRUE;
            CT_RETURN_IFERR(
                sql_gen_group_rs_col_by_subselect(stmt, sort_plan->select_columns, query_rs_col->expr->root));
        } else {
            CT_RETURN_IFERR(
                cm_galist_new(sort_plan->select_columns, sizeof(rs_column_t), (pointer_t *)&plan_rs_col));
            *plan_rs_col = *query_rs_col;
            CT_RETURN_IFERR(sql_create_group_rs_from_column(stmt, plan_rs_col, query_rs_col,
                sort_plan->select_columns->count - 1));
        }
    }
    return CT_SUCCESS;
}

static status_t sql_create_rowid_rs_columns(sql_stmt_t *stmt, sql_query_t *query)
{
    for (uint32 i = 0; i < query->tables.count; i++) {
        sql_table_t *table = (sql_table_t *)sql_array_get(&query->tables, i);
        CT_RETURN_IFERR(sql_create_rowid_rs_column(stmt, i, table->type, query->rs_columns));
    }
    return CT_SUCCESS;
}

#define IS_SIBLINGS_SORT(query) (query)->order_siblings && !(query)->has_distinct

static status_t check_expr_contains_rownum_or_const_only(visit_assist_t *va, expr_node_t **node)
{
    if (va->result0 == CT_TRUE && !NODE_IS_RES_ROWNUM(*node) && !NODE_IS_CONST(*node)) {
        va->result0 = CT_FALSE;
    }
    return CT_SUCCESS;
}

static bool32 check_siblings_order_can_eliminated(sql_stmt_t *stmt, sql_query_t *query)
{
    // if siblings order query's rs contain rownum or const only, then eliminate siblings order by
    visit_assist_t visit_as;
    uint32 i;
    sql_init_visit_assist(&visit_as, stmt, query);
    for (i = 0; i < query->rs_columns->count; ++i) {
        rs_column_t *rs = (rs_column_t *)cm_galist_get(query->rs_columns, i);
        if (rs->type == RS_COL_COLUMN) {
            break;
        }
        visit_as.result0 = CT_TRUE;
        CT_BREAK_IF_ERROR(visit_expr_tree(&visit_as, rs->expr, check_expr_contains_rownum_or_const_only));
        if (visit_as.result0 == CT_FALSE) {
            break;
        }
    }
    return (i == query->rs_columns->count);
}

static bool32 if_sort_can_eliminated(sql_stmt_t *stmt, sql_query_t *query, galist_t *sort_items, plan_node_t *next_plan)
{
    if (sort_items->count == 0) {
        return CT_TRUE;
    }

    if (IS_SIBLINGS_SORT(query) && check_siblings_order_can_eliminated(stmt, query)) {
        return CT_TRUE;
    }

    for (uint32 i = 0; i < sort_items->count; ++i) {
        sort_item_t *sort_item = (sort_item_t *)cm_galist_get(sort_items, i);

        /* If the nulls position of an sort items is not equal to the default position of its direction,
         * then the index can not eliminate the sort operation. Since our indexes are built by using
         * default NULLS position, @see DEFAULT_NULLS_SORTING_POSITION */
        if (!sql_nulls_pos_is_default(&sort_item->sort_mode)) {
            return CT_FALSE;
        }
    }

    return sql_sort_index_matched(query, sort_items, next_plan);
}

status_t get_limit_total_value(sql_stmt_t *stmt, sql_query_t *query, uint32 *rownum_upper)
{
    variant_t limit_offset_var, limit_count_var;
    uint32 row_count = 0;

    if (query->limit.count == NULL) {
        return CT_SUCCESS;
    }
    if (query->limit.offset != NULL) {
        expr_tree_t *limit_offset = (expr_tree_t *)query->limit.offset;
        if (!sql_is_const_expr_tree(limit_offset)) {
            return CT_SUCCESS;
        }

        CT_RETURN_IFERR(sql_exec_expr(stmt, limit_offset, &limit_offset_var));
        if (limit_offset_var.is_null) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "offset must not be null");
            return CT_ERROR;
        }

        CT_RETURN_IFERR(sql_convert_limit_num(&limit_offset_var));
        if (limit_offset_var.v_bigint < 0) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "offset must not be negative");
            return CT_ERROR;
        }
        if (limit_offset_var.v_bigint > CT_MAX_TOPN_THRESHOLD) {
            return CT_SUCCESS;
        }
        row_count += (uint32)limit_offset_var.v_bigint;
    }

    if (query->limit.count != NULL) {
        expr_tree_t *limit_count = (expr_tree_t *)query->limit.count;
        if (!sql_is_const_expr_tree(limit_count)) {
            return CT_SUCCESS;
        }
        CT_RETURN_IFERR(sql_exec_expr(stmt, limit_count, &limit_count_var));
        if (limit_count_var.is_null) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "limit must not be null");
            return CT_ERROR;
        }

        CT_RETURN_IFERR(sql_convert_limit_num(&limit_count_var));
        if (limit_count_var.v_bigint < 0) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "limit must not be negative");
            return CT_ERROR;
        }
        if (limit_count_var.v_bigint > CT_MAX_TOPN_THRESHOLD) {
            return CT_SUCCESS;
        }
        row_count += (uint32)limit_count_var.v_bigint;
    }
    *rownum_upper = row_count;
    return CT_SUCCESS;
}

bool32 if_parent_changes_rows_count(sql_query_t *query, uint32 *rownum_upper)
{
    if (query->tables.count != 1 || query->group_sets->count > 0 || query->connect_by_cond != NULL ||
        query->filter_cond != NULL || query->has_distinct || query->winsort_list->count > 0 ||
        query->aggrs->count > 0 || query->pivot_items != NULL || LIMIT_CLAUSE_OCCUR(&query->limit)) {
        return CT_TRUE;
    }

    if (query->cond == NULL || query->cond->root->type == COND_NODE_TRUE) {
        return CT_FALSE;
    }

    if (query->cond->root->type == COND_NODE_COMPARE && GET_MAX_ROWNUM(query->cond) != CT_INFINITE32) {
        *rownum_upper = query->cond->rownum_upper;
        return CT_FALSE;
    }
    return CT_TRUE;
}

static status_t calc_query_sort_rownum_upper(sql_stmt_t *stmt, sql_query_t *query, plan_node_t *sort_plan,
    uint32 *rownum_upper)
{
    *rownum_upper = CT_INFINITE32;
    if (query->calc_found_rows) {
        return CT_SUCCESS;
    }

    if (sort_plan->type != PLAN_NODE_QUERY_SORT) {
        return CT_SUCCESS;
    }

    if (LIMIT_CLAUSE_OCCUR(&query->limit)) {
        return get_limit_total_value(stmt, query, rownum_upper);
    }

    sql_query_t *parent = query->owner != NULL ? query->owner->parent : NULL;
    uint32 max_row = CT_INFINITE32;
    while (parent != NULL && !if_parent_changes_rows_count(parent, &max_row)) {
        if (max_row != CT_INFINITE32) {
            *rownum_upper = max_row;
            return CT_SUCCESS;
        }
        if (parent->owner == NULL) {
            break;
        }
        parent = parent->owner->parent;
    }
    return CT_SUCCESS;
}

/* First create the next plan. Then check whether need to create the sort plan, or use the index directly. */
static status_t sql_create_query_sort_plan(sql_stmt_t *stmt, sql_query_t *query, plan_assist_t *plan_ass,
    plan_node_t **sort_plan)
{
    plan_node_t *next_plan = NULL;
    uint32 plan_id = stmt->context->plan_count++;
    plan_ass->sort_items = query->sort_items;
    if (sql_create_query_plan_ex(stmt, query, plan_ass, &next_plan) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (if_sort_can_eliminated(stmt, query, query->sort_items, next_plan)) {
        *sort_plan = next_plan;
        return CT_SUCCESS;
    }

    if (sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)sort_plan) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (IS_SIBLINGS_SORT(query)) {
        (*sort_plan)->type = PLAN_NODE_QUERY_SIBL_SORT;
    } else {
        (*sort_plan)->type = PLAN_NODE_QUERY_SORT;
    }
    CT_RETURN_IFERR(calc_query_sort_rownum_upper(stmt, query, *sort_plan, &(*sort_plan)->query_sort.rownum_upper));
    (*sort_plan)->plan_id = plan_id;
    (*sort_plan)->query_sort.items = query->sort_items;
    (*sort_plan)->query_sort.select_columns = query->rs_columns;
    (*sort_plan)->query_sort.next = next_plan;
    set_filter_plan_pptr(plan_ass, &(*sort_plan)->query_sort.next, next_plan);

    // delete from order by
    if (query->rs_columns->count == 0) {
        CT_RETURN_IFERR(sql_create_rowid_rs_columns(stmt, query));
    }
    return sql_create_sort_plan_mtrl_columns(stmt, query->rs_columns, *sort_plan, query->sort_items);
}

status_t sql_clone_join_root_table(void *ctx, sql_stmt_t *stmt, sql_join_node_t *src_join_root, sql_array_t **tables,
    ga_alloc_func_t alloc_mem_func)
{
    sql_table_t *table = NULL;
    sql_table_t *new_table = NULL;

    CT_RETURN_IFERR(sql_push(stmt, sizeof(sql_array_t), (void **)tables));
    CT_RETURN_IFERR(sql_array_init(*tables, CT_MAX_JOIN_TABLES, stmt, sql_stack_alloc));
    (*tables)->count = CT_MAX_JOIN_TABLES;
    for (uint32 i = 0; i < src_join_root->tables.count; i++) {
        table = (sql_table_t *)sql_array_get(&src_join_root->tables, i);
        CT_RETURN_IFERR(alloc_mem_func(ctx, sizeof(sql_table_t), (void **)&new_table));
        *new_table = *table;
        CT_RETURN_IFERR(sql_array_set(*tables, new_table->id, new_table));
    }
    return CT_SUCCESS;
}

status_t sql_clone_nl_full_opt_info(sql_stmt_t *stmt, void *ctx, sql_join_node_t *src_root,
    sql_join_node_t *dst_root, ga_alloc_func_t alloc_mem_func)
{
    if (src_root->oper == JOIN_OPER_NL_FULL) {
        dst_root->nl_full_opt_info.opt_type = src_root->nl_full_opt_info.opt_type;
        if (src_root->nl_full_opt_info.opt_type == NL_FULL_DUPL_DRIVE) {
            CT_RETURN_IFERR(sql_clone_join_root(stmt, ctx, src_root->nl_full_opt_info.r_drive_tree,
                &dst_root->nl_full_opt_info.r_drive_tree, NULL, alloc_mem_func));
        } else if (src_root->nl_full_opt_info.opt_type == NL_FULL_ROWID_MTRL) {
            CT_RETURN_IFERR(
                alloc_mem_func(ctx, sizeof(sql_table_t), (void **)&dst_root->nl_full_opt_info.r_drive_table));
            *dst_root->nl_full_opt_info.r_drive_table = *src_root->nl_full_opt_info.r_drive_table;
        }
    }
    return CT_SUCCESS;
}

status_t sql_clone_join_root(sql_stmt_t *stmt, void *ctx, sql_join_node_t *src_join_root,
    sql_join_node_t **dst_root, sql_array_t *tables, ga_alloc_func_t alloc_mem_func)
{
    CT_RETURN_IFERR(alloc_mem_func(ctx, sizeof(sql_join_node_t), (void **)dst_root));
    CT_RETURN_IFERR(sql_array_init(&(*dst_root)->tables, CT_MAX_JOIN_TABLES, ctx, alloc_mem_func));
    (*dst_root)->type = src_join_root->type;
    (*dst_root)->oper = src_join_root->oper;
    (*dst_root)->cost = src_join_root->cost;
    (*dst_root)->is_cartesian_join = src_join_root->is_cartesian_join;

    if (tables == NULL) {
        CT_RETURN_IFERR(sql_clone_join_root_table(ctx, stmt, src_join_root, &tables, alloc_mem_func));
    }

    for (uint32 i = 0; i < src_join_root->tables.count; ++i) {
        sql_table_t *table = (sql_table_t *)sql_array_get(&src_join_root->tables, i);
        CT_RETURN_IFERR(sql_array_put(&(*dst_root)->tables, sql_array_get(tables, table->id)));
    }

    if (src_join_root->type == JOIN_TYPE_NONE) {
        return CT_SUCCESS;
    }

    if (src_join_root->join_cond != NULL) {
        CT_RETURN_IFERR(
            sql_clone_cond_tree(ctx, src_join_root->join_cond, &(*dst_root)->join_cond, alloc_mem_func));
    }
    if (src_join_root->filter != NULL) {
        CT_RETURN_IFERR(sql_clone_cond_tree(ctx, src_join_root->filter, &(*dst_root)->filter, alloc_mem_func));
    }

    CT_RETURN_IFERR(sql_clone_nl_full_opt_info(stmt, ctx, src_join_root, *dst_root, alloc_mem_func));
    CT_RETURN_IFERR(
        sql_clone_join_root(stmt, ctx, src_join_root->left, &(*dst_root)->left, tables, alloc_mem_func));
    return sql_clone_join_root(stmt, ctx, src_join_root->right, &(*dst_root)->right, tables, alloc_mem_func);
}

static status_t sql_extract_prior_cmp_node(sql_stmt_t *stmt, cond_node_t *cond_node, cond_tree_t **dst_tree)
{
    if (!sql_cond_node_has_prior(cond_node)) {
        return CT_SUCCESS;
    }

    /* NULL means erase the prior cond */
    if (dst_tree == NULL) {
        cond_node->type = COND_NODE_TRUE;
        return CT_SUCCESS;
    }

    if (*dst_tree == NULL) {
        CT_RETURN_IFERR(sql_create_cond_tree(stmt->context, dst_tree));
    }
    cond_node_t *copy_cond = NULL;
    CT_RETURN_IFERR(sql_clone_cond_node(stmt->context, cond_node, &copy_cond, sql_alloc_mem));
    CT_RETURN_IFERR(sql_add_cond_node(*dst_tree, copy_cond));
    return CT_SUCCESS;
}

status_t sql_extract_prior_cond_node(sql_stmt_t *stmt, cond_node_t *cond_node, cond_tree_t **dst_tree)
{
    switch (cond_node->type) {
        case COND_NODE_AND:
            CT_RETURN_IFERR(sql_extract_prior_cond_node(stmt, cond_node->left, dst_tree));
            CT_RETURN_IFERR(sql_extract_prior_cond_node(stmt, cond_node->right, dst_tree));
            try_eval_logic_and(cond_node);
            break;

        case COND_NODE_COMPARE:
            CT_RETURN_IFERR(sql_extract_prior_cmp_node(stmt, cond_node, dst_tree));
            break;

        case COND_NODE_OR:
        default:
            break;
    }
    return CT_SUCCESS;
}

static status_t sql_extract_prior_expr(visit_assist_t *va, expr_node_t **node)
{
    if ((*node)->type == EXPR_NODE_PRIOR) {
        expr_node_t *dst_node = NULL;
        CT_RETURN_IFERR(sql_clone_expr_node(va->stmt->context, (*node)->right, &dst_node, sql_alloc_mem));
        CT_RETURN_IFERR(cm_galist_insert((galist_t *)va->param0, dst_node));
    }
    return CT_SUCCESS;
}

static status_t sql_create_connect_mtrl_plan(sql_stmt_t *stmt, sql_query_t *query, plan_assist_t *plan_ass,
    connect_plan_t *conn_plan)
{
    plan_node_t *plan = NULL;
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)&plan));

    plan->type = PLAN_NODE_CONNECT_MTRL;
    plan->plan_id = stmt->context->plan_count++;
    plan->cb_mtrl.start_with_cond = query->start_with_cond;
    plan->cb_mtrl.connect_by_cond = query->connect_by_cond;
    plan->cb_mtrl.rs_tables = &query->tables;
    plan->cb_mtrl.prior_exprs = query->cb_mtrl_info->prior_exprs;
    plan->cb_mtrl.key_exprs = query->cb_mtrl_info->key_exprs;

    visit_assist_t visit_ass;
    sql_init_visit_assist(&visit_ass, stmt, NULL);
    visit_ass.excl_flags = VA_EXCL_PRIOR;
    visit_ass.param0 = conn_plan->prior_exprs;
    for (uint32 i = 0; i < query->cb_mtrl_info->prior_exprs->count; ++i) {
        expr_tree_t *prior_expr = (expr_tree_t *)cm_galist_get(query->cb_mtrl_info->prior_exprs, i);
        CT_RETURN_IFERR(visit_expr_tree(&visit_ass, prior_expr, sql_extract_prior_expr));
    }

    if (!query->cb_mtrl_info->combine_sw) {
        plan_assist_t pa_bak;
        sql_init_plan_assist(stmt, &pa_bak, query->s_query, SQL_QUERY_NODE, plan_ass->parent);
        pa_bak.no_nl_batch = CT_TRUE;
        CT_RETURN_IFERR(sql_create_query_plan_ex(stmt, pa_bak.query, &pa_bak, &conn_plan->next_start_with));
        plan->cb_mtrl.start_with_cond = NULL;
    } else {
        conn_plan->next_start_with = plan;
    }
    conn_plan->next_connect_by = plan;
    conn_plan->s_query = query->s_query;
    plan_ass->no_nl_batch = CT_TRUE;
    return sql_create_query_plan_ex(stmt, query, plan_ass, &plan->cb_mtrl.next);
}

static status_t sql_create_connect_plan(sql_stmt_t *stmt, sql_query_t *query, plan_assist_t *plan_ass,
    plan_node_t **connect_plan)
{
    plan_node_t *plan = NULL;
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)connect_plan));

    plan = *connect_plan;
    plan->type = PLAN_NODE_CONNECT;
    plan->plan_id = stmt->context->plan_count++;
    plan->connect.start_with_cond = query->start_with_cond;
    plan->connect.connect_by_cond = query->connect_by_cond;
    plan->connect.path_func_nodes = query->path_func_nodes;

    CT_RETURN_IFERR(sql_create_list(stmt, &plan->connect.prior_exprs));

    // extract prior exprs for cycle checking
    visit_assist_t visit_ass;
    sql_init_visit_assist(&visit_ass, stmt, NULL);
    visit_ass.excl_flags = VA_EXCL_PRIOR;
    visit_ass.param0 = (void *)plan->connect.prior_exprs;
    CT_RETURN_IFERR(visit_cond_node(&visit_ass, query->connect_by_cond->root, sql_extract_prior_expr));

    // create connect by mtrl plan
    if (query->cb_mtrl_info != NULL) {
        plan->type = PLAN_NODE_CONNECT_HASH;
        return sql_create_connect_mtrl_plan(stmt, query, plan_ass, &plan->connect);
    }

    // generate sub-query for start with
    if (query->s_query == NULL) {
        CT_RETURN_IFERR(sql_generate_start_query(stmt, query));
    }
    plan->connect.s_query = query->s_query;

    // start with condition contains query->cond
    plan_assist_t pa_bak;
    sql_init_plan_assist(stmt, &pa_bak, query->s_query, SQL_QUERY_NODE, NULL);

    plan_ass->no_nl_batch = CT_TRUE;
    pa_bak.no_nl_batch = CT_TRUE;

    CT_RETURN_IFERR(sql_create_query_plan_ex(stmt, pa_bak.query, &pa_bak, &plan->connect.next_start_with));

    cond_tree_t *prior_cond = NULL;
    CT_RETURN_IFERR(sql_extract_prior_cond_node(plan_ass->stmt, query->connect_by_cond->root, &prior_cond));
    query->cond_has_acstor_col = sql_cond_has_acstor_col(stmt, plan_ass->cond, query);
    plan_ass->resv_outer_join = CT_TRUE;
    CT_RETURN_IFERR(sql_create_query_plan_ex(stmt, query, plan_ass, &plan->connect.next_connect_by));
    if (prior_cond != NULL && query->join_root != NULL && sql_has_hash_join_oper(query->join_root)) {
        CT_RETURN_IFERR(sql_add_cond_node(query->connect_by_cond, prior_cond->root));
    }
    return CT_SUCCESS;
}

status_t sql_create_query_plan_ex(sql_stmt_t *stmt, sql_query_t *query, plan_assist_t *plan_ass, plan_node_t **plan)
{
    CT_RETURN_IFERR(sql_stack_safe(stmt));
    if (query->extra_flags & EX_QUERY_LIMIT) {
        CM_CLEAN_FLAG(query->extra_flags, EX_QUERY_LIMIT);
        return sql_create_query_limit_plan(stmt, query, plan_ass, plan);
    }

    if (query->extra_flags & EX_QUERY_SORT) {
        CM_CLEAN_FLAG(query->extra_flags, EX_QUERY_SORT);
        return sql_create_query_sort_plan(stmt, query, plan_ass, plan);
    }

    if (query->extra_flags & EX_QUERY_DISTINCT) {
        CM_CLEAN_FLAG(query->extra_flags, EX_QUERY_DISTINCT);
        return sql_create_distinct_plan(stmt, query, plan_ass, plan);
    }

    if (query->extra_flags & EX_QUERY_WINSORT) {
        CM_CLEAN_FLAG(query->extra_flags, EX_QUERY_WINSORT);
        return sql_create_winsort_plan(stmt, query, plan_ass, plan);
    }

    if (query->extra_flags & EX_QUERY_HAVING) {
        CM_CLEAN_FLAG(query->extra_flags, EX_QUERY_HAVING);
        return sql_create_having_plan(stmt, query, plan_ass, plan);
    }

    if (query->extra_flags & EX_QUERY_CUBE) {
        CM_CLEAN_FLAG(query->extra_flags, EX_QUERY_CUBE);
        return sql_create_cube_plan(stmt, query, plan_ass, plan);
    }

    if (query->extra_flags & EX_QUERY_PIVOT) {
        CM_CLEAN_FLAG(query->extra_flags, EX_QUERY_AGGR);
        CM_CLEAN_FLAG(query->extra_flags, EX_QUERY_PIVOT);
        return sql_create_pivot_plan(stmt, query, plan_ass, plan);
    }

    if (query->extra_flags & EX_QUERY_UNPIVOT) {
        CM_CLEAN_FLAG(query->extra_flags, EX_QUERY_UNPIVOT);
        return sql_create_unpivot_plan(stmt, query, plan_ass, plan);
    }

    if (query->extra_flags & EX_QUERY_AGGR) {
        CM_CLEAN_FLAG(query->extra_flags, EX_QUERY_AGGR);
        if (query->remote_keys != NULL) {
            return sql_create_hash_mtrl_plan(stmt, query, plan_ass, plan);
        } else if (query->group_sets->count != 0) {
            return sql_create_group_plan(stmt, query, plan_ass, plan);
        } else {
            return sql_create_aggr_plan(stmt, query, plan_ass, plan);
        }
    }

    if (query->extra_flags & EX_QUERY_FOR_UPDATE) {
        CM_CLEAN_FLAG(query->extra_flags, EX_QUERY_FOR_UPDATE);
        return sql_create_for_update_plan(stmt, query, plan_ass, plan);
    }

    if (query->extra_flags & EX_QUERY_ROWNUM) {
        CM_CLEAN_FLAG(query->extra_flags, EX_QUERY_ROWNUM);
        return sql_create_rownum_plan(stmt, query, plan_ass, plan);
    }

    if (query->extra_flags & EX_QUERY_FILTER) {
        CM_CLEAN_FLAG(query->extra_flags, EX_QUERY_FILTER);
        return sql_create_filter_plan(stmt, query, plan_ass, plan);
    }
    if (query->extra_flags & EX_QUERY_SIBL_SORT) {
        CM_CLEAN_FLAG(query->extra_flags, EX_QUERY_SIBL_SORT);
        return sql_create_query_sort_plan(stmt, query, plan_ass, plan);
    }
    if (query->extra_flags & EX_QUERY_CONNECT) {
        CM_CLEAN_FLAG(query->extra_flags, EX_QUERY_CONNECT);
        return sql_create_connect_plan(stmt, query, plan_ass, plan);
    }

    return sql_create_query_scan_plan(stmt, plan_ass, plan);
}

void sql_prepare_query_plan(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_query_t *query, sql_node_type_t type,
    plan_assist_t *parent)
{
    sql_init_plan_assist(stmt, plan_ass, query, type, parent);

    query->has_filter_opt = CT_FALSE;
    query->extra_flags = 0;
    query->extra_flags = get_query_plan_flag(query);
}

status_t sql_create_query_plan(sql_stmt_t *stmt, sql_query_t *query, sql_node_type_t type, plan_node_t **query_plan,
    plan_assist_t *parent)
{
    plan_node_t *plan = NULL;
    plan_assist_t plan_ass;

    SET_NODE_STACK_CURR_QUERY(stmt, query);
    if (sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)query_plan) != CT_SUCCESS) {
        return CT_ERROR;
    }

    plan = *query_plan;
    plan->type = PLAN_NODE_QUERY;
    plan->plan_id = stmt->context->plan_count++;
    plan->query.ref = query;

    sql_prepare_query_plan(stmt, &plan_ass, query, type, parent);

    if (query->extra_flags != 0) {
        bool32 has_filter_plan = (bool32)(query->extra_flags & EX_QUERY_FILTER);
        CT_RETURN_IFERR(sql_create_query_plan_ex(stmt, query, &plan_ass, &plan->query.next));
        if (has_filter_plan && query->has_filter_opt) {
            plan_node_t *filter_plan = *plan_ass.filter_node_pptr;
            *plan_ass.filter_node_pptr = filter_plan->filter.next;
        }
    } else {
        CT_RETURN_IFERR(sql_create_query_scan_plan(stmt, &plan_ass, &plan->query.next));
    }

    CT_RETURN_IFERR(sql_create_subselect_plan(stmt, query, &plan_ass));
    if (query->s_query != NULL) {
        CT_RETURN_IFERR(sql_create_subselect_plan(stmt, query->s_query, &plan_ass));
    }
    SQL_RESTORE_NODE_STACK(stmt);
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
