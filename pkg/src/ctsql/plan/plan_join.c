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
 * plan_join.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/plan/plan_join.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_instance.h"
#include "table_parser.h"
#include "ctsql_transform.h"
#include "ctsql_plan_defs.h"
#include "plan_join.h"
#include "plan_rbo.h"

#ifdef __cplusplus
extern "C" {
#endif

void sql_generate_join_assist(plan_assist_t *pa, sql_join_node_t *join_node, join_assist_t *join_ass)
{
    join_node->plan_id_start = CT_INVALID_ID32;
    if (join_node->type != JOIN_TYPE_NONE) {
        sql_generate_join_assist(pa, join_node->left, join_ass);
        sql_generate_join_assist(pa, join_node->right, join_ass);
        return;
    }
    sql_table_t *table = TABLE_OF_JOIN_LEAF(join_node);
    join_ass->maps[table->id] = join_node;
    join_ass->nodes[join_ass->total++] = join_node;
}

static inline bool32 is_table_certain(join_assist_t *join_ass, uint32 tab_id)
{
    for (uint32 i = 0; i < join_ass->count; i++) {
        sql_join_node_t *join_node = join_ass->selected_nodes[i];
        for (uint32 j = 0; j < join_node->tables.count; j++) {
            sql_table_t *table = (sql_table_t *)sql_array_get(&join_node->tables, j);
            if (table->id == tab_id) {
                return CT_TRUE;
            }
        }
    }
    return CT_FALSE;
}

static inline bool32 is_subslct_certain(sql_select_t *subslct, plan_assist_t *parent_pa, join_assist_t *join_ass)
{
    for (uint32 i = 0; i < subslct->parent_refs->count; i++) {
        parent_ref_t *parent_ref = (parent_ref_t *)cm_galist_get(subslct->parent_refs, i);
        uint32 tab_id = parent_ref->tab;
        if (parent_pa->tables[tab_id]->plan_id == CT_INVALID_ID32 && (!is_table_certain(join_ass, tab_id))) {
            return CT_FALSE;
        }
    }
    return CT_TRUE;
}

bool32 json_table_available(plan_assist_t *pa, sql_table_t *json_table);
static inline bool32 is_mapped_table_certain(sql_table_t *table, plan_assist_t *parent_pa, join_assist_t *join_ass)
{
    if (table->type == JSON_TABLE) {
        return json_table_available(parent_pa, table);
    } else if (!CT_IS_SUBSELECT_TABLE(table->type) || table->subslct_tab_usage == SUBSELECT_4_NORMAL_JOIN) {
        return CT_TRUE;
    }
    return is_subslct_certain(table->select_ctx, parent_pa, join_ass);
}

static inline bool32 is_node_join_cond(sql_join_node_t *join_node, join_cond_t *join_cond)
{
    if (sql_table_in_list(&join_node->tables, join_cond->table1)) {
        return CT_TRUE;
    }

    if (sql_table_in_list(&join_node->tables, join_cond->table2)) {
        SWAP(uint32, join_cond->table1, join_cond->table2);
        return CT_TRUE;
    }
    return CT_FALSE;
}

static inline bool32 sql_check_join_cond2(plan_assist_t *pa, join_assist_t *join_ass, join_cond_t *join_cond)
{
    for (uint32 i = 0; i < join_ass->count; i++) {
        if (!is_node_join_cond(join_ass->selected_nodes[i], join_cond)) {
            continue;
        }

        if (join_ass->maps[join_cond->table2]->plan_id_start != CT_INVALID_ID32) {
            continue;
        }

        sql_table_t *rtable = pa->tables[join_cond->table2];
        if (rtable->type == NORMAL_TABLE || is_mapped_table_certain(rtable, pa, join_ass)) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

static status_t sql_get_join_cond(sql_stmt_t *stmt, plan_assist_t *pa, join_assist_t *join_ass, join_cond_t **join_cond,
    sql_table_t *rtable)
{
    double cost = RBO_COST_INFINITE;
    double cur_cost;
    bilist_node_t *node = cm_bilist_head(&pa->join_conds);

    *join_cond = NULL;
    for (; node != NULL; node = BINODE_NEXT(node)) {
        join_cond_t *tmp_cond = BILIST_NODE_OF(join_cond_t, node, bilist_node);
        if (!sql_check_join_cond2(pa, join_ass, tmp_cond)) {
            continue;
        }

        if (join_ass->maps[tmp_cond->table2]->type == JOIN_TYPE_NONE) {
            CT_RETURN_IFERR(sql_check_table_indexable(stmt, pa, pa->tables[tmp_cond->table2], pa->cond));

            // For hint specified leading table
            if (rtable != NULL) {
                if (tmp_cond->table2 == rtable->id) {
                    *join_cond = tmp_cond;
                    break;
                } else {
                    continue;
                }
            }

            cur_cost = pa->tables[tmp_cond->table2]->cost;
        } else {
            cur_cost = RBO_COST_FULL_TABLE_SCAN;
        }

        if (cost > cur_cost) {
            cost = cur_cost;
            *join_cond = tmp_cond;
        }
    }
    return CT_SUCCESS;
}

static inline void hint_remove_leading_head(hint_info_t *hint_info)
{
    galist_t *l = (galist_t *)(hint_info->args[ID_HINT_LEADING]);

    cm_galist_delete(l, 0);
    if (l->count == 0) {
        HINT_JOIN_ORDER_CLEAR(hint_info);
    }
}

static status_t sql_get_join_cond_by_join_node(sql_stmt_t *stmt, plan_assist_t *pa, join_assist_t *join_ass,
    join_cond_t **join_cond, sql_join_node_t *join_node)
{
    bool32 join_cond_found = CT_FALSE;
    bilist_node_t *node = cm_bilist_head(&pa->join_conds);
    sql_table_t *table = NULL;

    for (; node != NULL; node = BINODE_NEXT(node)) {
        join_cond_t *tmp_cond = BILIST_NODE_OF(join_cond_t, node, bilist_node);

        if (sql_table_in_list(&join_node->tables, tmp_cond->table1) &&
            join_ass->maps[tmp_cond->table2]->plan_id_start == CT_INVALID_ID32) {
            join_cond_found = CT_TRUE;
        } else if (sql_table_in_list(&join_node->tables, tmp_cond->table2) &&
            join_ass->maps[tmp_cond->table1]->plan_id_start == CT_INVALID_ID32) {
            join_cond_found = CT_TRUE;
            SWAP(uint32, tmp_cond->table1, tmp_cond->table2);
        }
        if (join_cond_found) {
            table = pa->tables[tmp_cond->table2];
            if ((table->type == JSON_TABLE) && !json_table_available(pa, table)) {
                join_cond_found = CT_FALSE;
                continue;
            }
            *join_cond = tmp_cond;
            break;
        }
    }
    return CT_SUCCESS;
}

// choose the join node from subselect parent table with the least cost
static status_t sql_get_subselect_parent_node(sql_stmt_t *stmt, plan_assist_t *pa, join_assist_t *join_ass,
    sql_select_t *select_ctx, sql_join_node_t **join_node)
{
    double cost = RBO_COST_INFINITE;

    for (uint32 i = 0; i < select_ctx->parent_refs->count; ++i) {
        parent_ref_t *parent_ref = (parent_ref_t *)cm_galist_get(select_ctx->parent_refs, i);
        sql_table_t *table = TABLE_OF_JOIN_LEAF(join_ass->maps[parent_ref->tab]);

        if (table->plan_id != CT_INVALID_ID32 || is_table_certain(join_ass, table->id)) {
            continue;
        }

        CT_RETURN_IFERR(sql_check_table_indexable(stmt, pa, table, pa->cond));
        if (cost > table->cost) {
            cost = table->cost;
            *join_node = join_ass->maps[table->id];
        }
    }
    return CT_SUCCESS;
}

/* try to find a join_cond with tables already in the join plan list
 * if any join_cond exists, choose the cond associated parent table node as the next join node
 */
static status_t sql_get_next_node_by_table(sql_stmt_t *stmt, plan_assist_t *pa, join_assist_t *join_ass,
    sql_join_node_t **join_node)
{
    join_cond_t *join_cond = NULL;

    for (uint32 i = 0; i < join_ass->total; ++i) {
        if (join_ass->nodes[i]->plan_id_start == CT_INVALID_ID32) {
            continue;
        }

        CT_RETURN_IFERR(sql_get_join_cond_by_join_node(stmt, pa, join_ass, &join_cond, join_ass->nodes[i]));
        if (join_cond != NULL) {
            break;
        }
    }

    if (join_cond == NULL) {
        return CT_SUCCESS;
    }

    if (join_ass->maps[join_cond->table2]->type != JOIN_TYPE_NONE) {
        return CT_SUCCESS;
    }

    // choose the subselect parent node as next node
    sql_table_t *rtable = TABLE_OF_JOIN_LEAF(join_ass->maps[join_cond->table2]);
    if (rtable->type != SUBSELECT_AS_TABLE && rtable->type != WITH_AS_TABLE) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "rtable->type(%u) == SUBSELECT_AS_TABLE(%u)", (uint32)rtable->type,
            (uint32)SUBSELECT_AS_TABLE);
        return CT_ERROR;
    }

    return sql_get_subselect_parent_node(stmt, pa, join_ass, rtable->select_ctx, join_node);
}

static void sql_set_join_node(plan_assist_t *pa, join_assist_t *join_ass, sql_join_node_t *join_node)
{
    join_ass->selected_nodes[join_ass->count++] = join_node;
    join_node->plan_id_start = pa->plan_count;
    if (join_node->type == JOIN_TYPE_NONE) {
        sql_plan_assist_set_table(pa, TABLE_OF_JOIN_LEAF(join_node));
    } else {
        pa->plan_count += join_node->tables.count;
        for (uint32 i = 0; i < join_node->tables.count; ++i) {
            sql_table_t *table = (sql_table_t *)sql_array_get(&join_node->tables, i);

            // If the table field appears in the association condition and table plan id is not CT_INVALID_ID32,
            // then assumes that the table field already has a value
            table->plan_id = join_node->plan_id_start;
        }
    }
}

static inline bool32 can_use_leading_hint_4_outer_join(join_assist_t *join_ass, sql_table_t *leading_table)
{
    sql_join_node_t *node = NULL;
    for (uint32 i = 0; i < join_ass->total; i++) {
        node = join_ass->nodes[i];
        if (node->type == JOIN_TYPE_NONE && TABLE_OF_JOIN_LEAF(node) == leading_table) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

static inline bool32 leading_tables_in_sub_node(join_assist_t *join_ass, galist_t *l)
{
    if (l->count > join_ass->total) {
        return CT_FALSE;
    }
    for (uint32 i = 0; i < l->count; i++) {
        sql_table_t *leading_table = (sql_table_t *)(((sql_table_hint_t *)cm_galist_get(l, i))->table);
        if (!can_use_leading_hint_4_outer_join(join_ass, leading_table)) {
            return CT_FALSE;
        }
    }
    return CT_TRUE;
}

static inline sql_table_t *get_leading_table_4_hint(plan_assist_t *pa, join_assist_t *join_ass)
{
    if (!HAS_SPEC_TYPE_HINT(pa->query->hint_info, JOIN_HINT, HINT_KEY_WORD_LEADING)) {
        return NULL;
    }
    galist_t *l = (galist_t *)(pa->query->hint_info->args[ID_HINT_LEADING]);
    if (pa->query->join_assist.outer_node_count == 0 || leading_tables_in_sub_node(join_ass, l)) {
        sql_table_t *lead_table = (sql_table_t *)(((sql_table_hint_t *)cm_galist_get(l, 0))->table);
        if (lead_table->type != JSON_TABLE || json_table_available(pa, lead_table)) {
            return lead_table;
        }
        HINT_JOIN_ORDER_CLEAR(pa->query->hint_info);
    }
    return NULL;
}

static status_t sql_get_next_node(sql_stmt_t *stmt, plan_assist_t *pa, join_assist_t *join_ass,
                                  sql_join_node_t **join_node, join_cond_t **join_cond)
{
    sql_table_t *leading_table = get_leading_table_4_hint(pa, join_ass);
    *join_node = NULL;

    CT_RETURN_IFERR(sql_get_join_cond(stmt, pa, join_ass, join_cond, leading_table));
    if (*join_cond == NULL) {
        if (leading_table != NULL) {
            *join_node = join_ass->maps[leading_table->id];
            sql_set_join_node(pa, join_ass, *join_node);

            hint_remove_leading_head(pa->query->hint_info);

            return sql_check_table_indexable(stmt, pa, leading_table, pa->cond);
        }

        CT_RETURN_IFERR(sql_get_next_node_by_table(stmt, pa, join_ass, join_node));
        if (*join_node != NULL) {
            join_ass->selected_nodes[join_ass->count++] = *join_node;
            (*join_node)->plan_id_start = pa->plan_count;
            if ((*join_node)->type == JOIN_TYPE_NONE) {
                sql_plan_assist_set_table(pa, TABLE_OF_JOIN_LEAF(*join_node));
            } else {
                pa->plan_count += (*join_node)->tables.count;
            }
        }
        return CT_SUCCESS;
    }

    *join_node = join_ass->maps[(*join_cond)->table2];
    sql_set_join_node(pa, join_ass, *join_node);

    if (leading_table != NULL) {
        hint_remove_leading_head(pa->query->hint_info);
    }
    return CT_SUCCESS;
}

bool32 json_table_available(plan_assist_t *pa, sql_table_t *json_table)
{
    for (uint32 i = 0; i < json_table->json_table_info->depend_table_count; i++) {
        if (pa->tables[json_table->json_table_info->depend_tables[i]]->plan_id == CT_INVALID_ID32) {
            return CT_FALSE;
        }
    }
    return CT_TRUE;
}

static status_t get_filter_driver_node(sql_stmt_t *stmt, plan_assist_t *pa, join_assist_t *join_ass,
    sql_join_node_t **opt_node, bool32 *is_leading)
{
    double cost = RBO_COST_INFINITE;
    sql_join_node_t *join_node_i = NULL;
    uint32 node_idx = CT_INVALID_ID32;
    *opt_node = NULL;
    sql_table_t *leading_table = get_leading_table_4_hint(pa, join_ass);

    for (uint32 i = 0; i < join_ass->total; i++) {
        join_node_i = join_ass->nodes[i];

        if (join_node_i->plan_id_start != CT_INVALID_ID32) {
            continue;
        } else if ((TABLE_OF_JOIN_LEAF(join_ass->nodes[i])->type == JSON_TABLE) &&
            !json_table_available(pa, TABLE_OF_JOIN_LEAF(join_ass->nodes[i]))) {
            continue;
        }

        if (join_node_i->type != JOIN_TYPE_NONE) { // The outer join node is not recommended as the driver node
            if (node_idx == CT_INVALID_ID32) {
                cost = RBO_COST_FULL_TABLE_SCAN;
                node_idx = i; // if not find driver node, outer join node will be as the driver node
            }
            continue;
        }

        if (TABLE_OF_JOIN_LEAF(join_node_i)->subslct_tab_usage >= SUBSELECT_4_SEMI_JOIN &&
            TABLE_OF_JOIN_LEAF(join_node_i)->select_ctx->parent_refs->count > 1) {
            // sub-select table(semi/anti) with ancestors can never be a driver table
            continue;
        }

        CT_RETURN_IFERR(sql_check_table_indexable(stmt, pa, TABLE_OF_JOIN_LEAF(join_ass->nodes[i]), pa->cond));
        if (leading_table != NULL) {
            if (leading_table == TABLE_OF_JOIN_LEAF(join_ass->nodes[i])) {
                node_idx = i;
                *is_leading = CT_TRUE;
                hint_remove_leading_head(pa->query->hint_info);
                break;
            }
        } else {
            if (cost > TABLE_OF_JOIN_LEAF(join_ass->nodes[i])->cost) {
                node_idx = i;
                cost = TABLE_OF_JOIN_LEAF(join_ass->nodes[i])->cost;
            }
        }
    }

    if (node_idx != CT_INVALID_ID32) {
        *opt_node = join_ass->nodes[node_idx];
    }
    return CT_SUCCESS;
}

static status_t chk_mapped_table_indexable(sql_stmt_t *stmt, sql_table_t *table, plan_assist_t *parent, bool32 *result)
{
    plan_assist_t pa;
    sql_query_t *subqry = NULL;

    *result = CT_FALSE;

    // ignore WITH_AS_TABLE
    if (table->type != SUBSELECT_AS_TABLE && table->type != VIEW_AS_TABLE) {
        return CT_SUCCESS;
    }

    if (table->select_ctx->root->type != SELECT_NODE_QUERY) {
        return CT_SUCCESS;
    }

    subqry = table->select_ctx->root->query;
    if (HAS_SPEC_TYPE_HINT(subqry->hint_info, JOIN_HINT, HINT_KEY_WORD_LEADING) ||
        subqry->join_assist.outer_node_count > 0 || subqry->group_sets->count > 0) {
        return CT_SUCCESS;
    }

    sql_init_plan_assist(stmt, &pa, subqry, SQL_QUERY_NODE, parent);
    if (pa.table_count > 1) {
        sql_join_node_t *join_root = NULL;
        CT_RETURN_IFERR(sql_build_join_tree(stmt, &pa, &join_root));
    } else {
        CT_RETURN_IFERR(sql_check_table_indexable(stmt, &pa, pa.tables[0], pa.cond));
    }

    for (uint32 i = 0; i < subqry->tables.count; i++) {
        sql_table_t *s_table = (sql_table_t *)sql_array_get(&subqry->tables, i);
        if (s_table->type != NORMAL_TABLE) {
            CT_RETURN_IFERR(chk_mapped_table_indexable(stmt, s_table, &pa, result));
            if (!(*result)) {
                return CT_SUCCESS;
            }
            continue;
        }

        if (s_table->index == NULL || s_table->index_full_scan ||
            (s_table->index->column_count != s_table->idx_equal_to)) {
            return CT_SUCCESS;
        }

        if (s_table->plan_id == 0) {
            if (!(s_table->col_use_flag & USE_ANCESTOR_COL)) {
                return CT_SUCCESS;
            }
            continue;
        }

        if (!(s_table->col_use_flag & (USE_SELF_JOIN_COL | USE_ANCESTOR_COL))) {
            return CT_SUCCESS;
        }
    }
    *result = CT_TRUE;
    return CT_SUCCESS;
}

static inline status_t can_used_by_other_table(sql_stmt_t *stmt, plan_assist_t *pa, join_assist_t *join_ass,
    sql_join_node_t *join_node, bool32 *result)
{
    bilist_node_t *node = cm_bilist_head(&pa->join_conds);

    *result = CT_FALSE;
    TABLE_OF_JOIN_LEAF(join_node)->plan_id = pa->plan_count;
    for (; node != NULL; node = BINODE_NEXT(node)) {
        join_cond_t *join_cond = BILIST_NODE_OF(join_cond_t, node, bilist_node);
        if (!is_node_join_cond(join_node, join_cond)) {
            continue;
        }

        if (join_ass->maps[join_cond->table2]->type != JOIN_TYPE_NONE ||
            TABLE_OF_JOIN_LEAF(join_ass->maps[join_cond->table2])->type != NORMAL_TABLE ||
            TABLE_OF_JOIN_LEAF(join_ass->maps[join_cond->table2])->plan_id != CT_INVALID_ID32) {
            continue;
        }

        CT_RETURN_IFERR(sql_check_table_indexable(stmt, pa, pa->tables[join_cond->table2], pa->cond));
        if (pa->tables[join_cond->table2]->cost < RBO_COST_FULL_INDEX_SCAN) {
            *result = CT_TRUE;
            sql_init_table_indexable(pa->tables[join_cond->table2], NULL);
            break;
        }
    }

    TABLE_OF_JOIN_LEAF(join_node)->plan_id = CT_INVALID_ID32;
    return CT_SUCCESS;
}

static status_t try_get_join_driver_node(sql_stmt_t *stmt, plan_assist_t *pa, join_assist_t *join_ass,
    sql_join_node_t **opt_node)
{
    bool32 result = CT_FALSE;
    sql_join_node_t *join_node = NULL;

    for (uint32 i = 0; i < join_ass->total; i++) {
        join_node = join_ass->nodes[i];
        if (join_node->type != JOIN_TYPE_NONE || join_node->plan_id_start != CT_INVALID_ID32 ||
            TABLE_OF_JOIN_LEAF(join_node)->type != NORMAL_TABLE) {
            continue;
        }

        CT_RETURN_IFERR(can_used_by_other_table(stmt, pa, join_ass, join_node, &result));
        if (result) {
            *opt_node = join_node;
            return CT_SUCCESS;
        }
    }
    return CT_SUCCESS;
}

static inline bool32 is_driver_node(sql_join_node_t *node, plan_assist_t *top_pa)
{
    if (node->type != JOIN_TYPE_NONE) {
        return CT_FALSE;
    }

    sql_table_t *table = TABLE_OF_JOIN_LEAF(node);
    if (table->type != NORMAL_TABLE || IS_DYNAMIC_VIEW(table) || IS_TEMP_TABLE(table) ||
        (table->index != NULL && !table->index_full_scan)) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

static inline status_t sql_get_driver_node(sql_stmt_t *stmt, plan_assist_t *pa, join_assist_t *join_ass,
    sql_join_node_t **drv_node)
{
    bool32 is_leading = CT_FALSE;

    CT_RETURN_IFERR(get_filter_driver_node(stmt, pa, join_ass, drv_node, &is_leading));
    if (*drv_node == NULL) {
        return CT_SUCCESS;
    }

    if (is_leading || is_driver_node(*drv_node, pa)) {
        sql_set_join_node(pa, join_ass, *drv_node);
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(try_get_join_driver_node(stmt, pa, join_ass, drv_node));

    sql_set_join_node(pa, join_ass, *drv_node);
    return CT_SUCCESS;
}

static inline status_t sql_check_indexable_4_hint(sql_stmt_t *stmt, plan_assist_t *pa, join_oper_t join_oper,
    sql_join_node_t *join_node)
{
    if (join_node->type != JOIN_TYPE_NONE || join_oper == JOIN_OPER_NL || join_oper == JOIN_OPER_NL_LEFT ||
        join_oper == JOIN_OPER_NL_FULL) {
        return CT_SUCCESS;
    }
    CBO_SET_FLAGS(pa, CBO_CHECK_FILTER_IDX);
    CT_RETURN_IFERR(sql_check_table_indexable(stmt, pa, TABLE_OF_JOIN_LEAF(join_node), pa->cond));
    CBO_UNSET_FLAGS(pa, CBO_CHECK_FILTER_IDX);
    return CT_SUCCESS;
}

static inline bool32 check_hash_join_ability(sql_join_node_t *join_node)
{
    if (join_node->type == JOIN_TYPE_NONE) {
        if (TABLE_CBO_HAS_FLAG(TABLE_OF_JOIN_LEAF(join_node), SELTION_NO_HASH_JOIN)) {
            return CT_FALSE;
        }
        return CT_TRUE;
    }
    if (!check_hash_join_ability(join_node->left)) {
        return CT_FALSE;
    }
    return check_hash_join_ability(join_node->right);
}

#define TRY_SET_SEMI_JOIN_OPER_BY_CHILD(child, table, join_node)        \
    do {                                                                \
        (table) = TABLE_OF_JOIN_LEAF(child);                            \
        if ((table)->subslct_tab_usage == SUBSELECT_4_SEMI_JOIN) {      \
            (join_node)->oper = JOIN_OPER_HASH_SEMI;                    \
            return CT_TRUE;                                             \
        }                                                               \
        if ((table)->subslct_tab_usage == SUBSELECT_4_ANTI_JOIN) {      \
            (join_node)->oper = JOIN_OPER_HASH_ANTI;                    \
            return CT_TRUE;                                             \
        }                                                               \
        if ((table)->subslct_tab_usage == SUBSELECT_4_ANTI_JOIN_NA) {   \
            (join_node)->oper = JOIN_OPER_HASH_ANTI_NA;                 \
            return CT_TRUE;                                             \
        }                                                               \
    } while (0)

static bool32 check_and_get_join_column(cmp_node_t *cmp_node, cols_used_t *l_cols_used, cols_used_t *r_cols_used)
{
    expr_tree_t *left = cmp_node->left;
    expr_tree_t *right = cmp_node->right;

    if (left == NULL || right == NULL) {
        return CT_FALSE;
    }

    init_cols_used(l_cols_used);
    init_cols_used(r_cols_used);
    sql_collect_cols_in_expr_tree(left, l_cols_used);
    sql_collect_cols_in_expr_tree(right, r_cols_used);

    return sql_can_equal_used_by_hash(l_cols_used, r_cols_used, NULL, NULL);
}

bool32 sql_get_cmp_join_column(cmp_node_t *cmp_node, expr_node_t **left_column, expr_node_t **right_column)
{
    cols_used_t l_cols_used, r_cols_used;

    if (!check_and_get_join_column(cmp_node, &l_cols_used, &r_cols_used)) {
        return CT_FALSE;
    }

    *left_column = (expr_node_t *)sql_any_self_col_node(&l_cols_used);
    *right_column = (expr_node_t *)sql_any_self_col_node(&r_cols_used);
    return CT_TRUE;
}

bool32 sql_cmp_can_used_by_hash(cmp_node_t *cmp_node)
{
    cols_used_t l_cols_used, r_cols_used;

    if (cmp_node->type != CMP_TYPE_EQUAL) {
        return CT_FALSE;
    }
    return check_and_get_join_column(cmp_node, &l_cols_used, &r_cols_used);
}

bool32 sql_check_hash_join(cmp_node_t *cmp_node, double base, double *rate)
{
    cols_used_t l_cols_used, r_cols_used;

    if (cmp_node->type != CMP_TYPE_EQUAL) {
        return CT_FALSE;
    }

    if (check_and_get_join_column(cmp_node, &l_cols_used, &r_cols_used)) {
        uint8 max_lev = l_cols_used.func_maxlev + r_cols_used.func_maxlev;
        *rate = pow(base, max_lev);
        return CT_TRUE;
    }
    return CT_FALSE;
}

bool32 sql_get_cmp_join_tab_id(cmp_node_t *cmp_node, uint16 *l_tab_id, uint16 *r_tab_id, join_oper_t oper)
{
    cols_used_t l_cols_used, r_cols_used;

    if (cmp_node->type != CMP_TYPE_EQUAL) {
        if (oper != JOIN_OPER_MERGE) {
            return CT_FALSE;
        }
        if (cmp_node->type != CMP_TYPE_GREAT && cmp_node->type != CMP_TYPE_LESS &&
            cmp_node->type != CMP_TYPE_GREAT_EQUAL && cmp_node->type != CMP_TYPE_LESS_EQUAL) {
            return CT_FALSE;
        }
    }

    if (!check_and_get_join_column(cmp_node, &l_cols_used, &r_cols_used)) {
        return CT_FALSE;
    }

    expr_node_t *l_col = (expr_node_t *)sql_any_self_col_node(&l_cols_used);
    expr_node_t *r_col = (expr_node_t *)sql_any_self_col_node(&r_cols_used);
    *l_tab_id = TAB_OF_NODE(l_col);
    *r_tab_id = TAB_OF_NODE(r_col);
    return CT_TRUE;
}

static inline bool32 try_choose_semi_join_oper(sql_join_node_t *join_node)
{
    sql_join_node_t *left = NULL;
    sql_join_node_t *right = NULL;
    sql_table_t *table = NULL;

    left = join_node->left;
    right = join_node->right;

    // left and right can't be all sub-select, meanwhile usage are all SUBSELECT_4_SEMI_JOIN or SUBSELECT_4_ANTI_JOIN
    if (left->type == JOIN_TYPE_NONE) {
        TRY_SET_SEMI_JOIN_OPER_BY_CHILD(left, table, join_node);
    }
    if (right->type == JOIN_TYPE_NONE) {
        TRY_SET_SEMI_JOIN_OPER_BY_CHILD(right, table, join_node);
    }
    return CT_FALSE;
}

static inline void try_choose_better_join_oper(sql_stmt_t *stmt, sql_join_node_t *join_node, join_cond_t *join_cond)
{
    join_node->oper = JOIN_OPER_NL;
    return;
}

static inline status_t sql_check_nl_join_ability(sql_stmt_t *stmt, sql_table_t *table, plan_assist_t *pa,
    bool32 *result)
{
    *result = CT_FALSE;

    if (table->type != NORMAL_TABLE) {
        return chk_mapped_table_indexable(stmt, table, pa, result);
    }

    if (table->scan_mode == SCAN_MODE_ROWID || (table->index != NULL && (table->col_use_flag & USE_SELF_JOIN_COL))) {
        *result = CT_TRUE;
    }
    return CT_SUCCESS;
}

// all join in query are inner, when build join tree, this function will be invoked
static status_t sql_set_join_oper(sql_stmt_t *stmt, plan_assist_t *pa, sql_join_node_t *join_node,
    join_cond_t *join_cond, bool32 is_select)
{
    try_choose_better_join_oper(stmt, join_node, join_cond);
    return CT_SUCCESS;
}

static status_t sql_create_sub_join_tree(sql_stmt_t *stmt, plan_assist_t *pa, join_assist_t *join_ass,
    sql_join_node_t **sub_tree)
{
    join_cond_t *join_cond = NULL;
    sql_join_node_t *right = NULL;
    sql_join_node_t *temp_tree = NULL;

    CT_RETURN_IFERR(sql_get_driver_node(stmt, pa, join_ass, sub_tree));
    if (*sub_tree == NULL) {
        return CT_SUCCESS;
    }

    while (join_ass->count < join_ass->total) {
        CT_RETURN_IFERR(sql_get_next_node(stmt, pa, join_ass, &right, &join_cond));
        if (right == NULL) {
            break;
        }
        CT_RETURN_IFERR(sql_create_join_node(stmt, JOIN_TYPE_INNER, NULL, NULL, *sub_tree, right, &temp_tree));
        CT_RETURN_IFERR(sql_set_join_oper(stmt, pa, temp_tree, join_cond, pa->query->owner != NULL));
        temp_tree->filter = pa->cond;
        *sub_tree = temp_tree;
    }
    return CT_SUCCESS;
}

static status_t sql_create_join_tree(sql_stmt_t *stmt, plan_assist_t *pa, join_assist_t *join_ass,
    sql_join_node_t **join_root)
{
    sql_join_node_t *right = NULL;
    sql_join_node_t *temp_tree = NULL;

    CT_RETURN_IFERR(sql_create_sub_join_tree(stmt, pa, join_ass, join_root));

    while (join_ass->count < join_ass->total) {
        CT_RETURN_IFERR(sql_create_sub_join_tree(stmt, pa, join_ass, &right));
        if (right == NULL) {
            break;
        }
        CT_RETURN_IFERR(sql_create_join_node(stmt, JOIN_TYPE_INNER, NULL, NULL, *join_root, right, &temp_tree));
        temp_tree->oper = JOIN_OPER_NL;
        temp_tree->filter = pa->cond;
        *join_root = temp_tree;
    }
    return CT_SUCCESS;
}

static inline cond_tree_t *sql_get_right_table_cond(sql_join_node_t *join_node)
{
    if (join_node->type <= JOIN_TYPE_INNER) {
        return join_node->filter;
    }
    if (join_node->type <= JOIN_TYPE_RIGHT) {
        return join_node->join_cond;
    }
    return NULL;
}

static bool32 reserved_node_contains_table(visit_assist_t *visit_ass, expr_node_t *node, bool32 *exist_col)
{
    if ((VAR_RES_ID(&node->value) == RES_WORD_SYSDATE || VAR_RES_ID(&node->value) == RES_WORD_SYSTIMESTAMP ||
        VAR_RES_ID(&node->value) == RES_WORD_NULL || VAR_RES_ID(&node->value) == RES_WORD_TRUE ||
        VAR_RES_ID(&node->value) == RES_WORD_FALSE)) {
        return CT_TRUE;
    }

    if (VAR_RES_ID(&node->value) == RES_WORD_ROWID) {
        if (ROWID_NODE_ANCESTOR(node) > 0) {
            return CT_TRUE;
        }

        *exist_col = CT_TRUE;

        return (bool32)(ROWID_NODE_TAB(node) == visit_ass->result1);
    }

    return CT_FALSE;
}

static status_t expr_node_contains_table(visit_assist_t *visit_ass, expr_node_t **node)
{
    if (!visit_ass->result0) {
        return CT_SUCCESS;
    }
    bool32 *exist_col = (bool32 *)visit_ass->param0;

    switch ((*node)->type) {
        case EXPR_NODE_CONST:
        case EXPR_NODE_PARAM:
            break;

        case EXPR_NODE_COLUMN:
        case EXPR_NODE_TRANS_COLUMN:
            if (NODE_ANCESTOR(*node) > 0) {
                return CT_SUCCESS;
            }

            *exist_col = CT_TRUE;
            visit_ass->result0 = NODE_TAB(*node) == visit_ass->result1;
            break;

        case EXPR_NODE_RESERVED:
            visit_ass->result0 = reserved_node_contains_table(visit_ass, *node, exist_col);
            break;

        case EXPR_NODE_SELECT:
        default:
            visit_ass->result0 = CT_FALSE;
            break;
    }
    return CT_SUCCESS;
}

static bool32 table_in_expr_node(uint32 tab_id, expr_node_t *expr_node, bool32 *exist_col)
{
    visit_assist_t visit_ass;
    sql_init_visit_assist(&visit_ass, NULL, NULL);
    visit_ass.excl_flags = VA_EXCL_PRIOR | VA_EXCL_WIN_SORT;
    visit_ass.result0 = CT_TRUE;
    visit_ass.result1 = tab_id;
    visit_ass.param0 = (void *)exist_col;

    if (visit_expr_node(&visit_ass, &expr_node, expr_node_contains_table) != CT_SUCCESS) {
        return CT_FALSE;
    }
    return visit_ass.result0;
}

static inline bool32 table_in_cmp_node(uint32 tab_id, expr_node_t *cmp_node1, expr_node_t *cmp_node2,
    sql_array_t *tables)
{
    bool32 exist_col = CT_FALSE;
    sql_table_t *table = NULL;

    bool32 ret = table_in_expr_node(tab_id, cmp_node1, &exist_col);
    if (ret && exist_col) {
        for (uint32 i = 0; i < tables->count; i++) {
            exist_col = CT_FALSE;
            table = (sql_table_t *)sql_array_get(tables, i);
            if (table->id == tab_id) {
                continue;
            }
            ret = table_in_expr_node(table->id, cmp_node2, &exist_col);
            if (ret && exist_col) {
                return CT_TRUE;
            }
        }
    }
    return CT_FALSE;
}

static inline bool32 table_in_cmp_cond(uint32 tab_id, cmp_node_t *cmp_node, sql_array_t *tables)
{
    if (cmp_node->left != NULL && cmp_node->left->root != NULL && cmp_node->right != NULL &&
        cmp_node->right->root != NULL) {
        return (bool32)(table_in_cmp_node(tab_id, cmp_node->left->root, cmp_node->right->root, tables) ||
            table_in_cmp_node(tab_id, cmp_node->right->root, cmp_node->left->root, tables));
    }

    return CT_FALSE;
}

static inline status_t can_find_hash_join_cond(uint32 tab_id, cond_node_t *cond, sql_stmt_t *stmt, bool32 *result,
    sql_array_t *tables)
{
    CT_RETURN_IFERR(sql_stack_safe(stmt));
    bool32 ret = CT_FALSE;
    bool32 find_ret = CT_FALSE;
    switch (cond->type) {
        case COND_NODE_COMPARE: {
            cmp_node_t *cmp_node = cond->cmp;
            if (table_in_cmp_cond(tab_id, cmp_node, tables) && sql_cmp_can_used_by_hash(cmp_node)) {
                ret = CT_TRUE;
            }
        } break;
        case COND_NODE_OR:
        case COND_NODE_TRUE:
        case COND_NODE_FALSE:
            break;
        default:
            CT_RETURN_IFERR(can_find_hash_join_cond(tab_id, cond->left, stmt, &ret, tables));
            CT_RETURN_IFERR(can_find_hash_join_cond(tab_id, cond->right, stmt, &find_ret, tables));
            ret |= find_ret;
            break;
    }
    *result = ret;
    return CT_SUCCESS;
}

static inline status_t can_find_table_hash_join_cond(uint32 tab_id, cond_tree_t *join_node, sql_stmt_t *stmt,
    bool32 *result, sql_array_t *tables)
{
    if (join_node == NULL) {
        *result = CT_FALSE;
        return CT_SUCCESS;
    }
    return can_find_hash_join_cond(tab_id, join_node->root, stmt, result, tables);
}

static status_t sql_adjust_mix_join_plan(plan_assist_t *plan_ass, sql_join_node_t *join_node);
static status_t choose_full_join_drive_table_index(plan_assist_t *pa, sql_table_t *drive_table,
    sql_join_node_t *drive_node, sql_join_node_t *parent_node)
{
    cond_tree_t *cond = NULL;
    sql_init_table_indexable(drive_table, TABLE_OF_JOIN_LEAF(drive_node));
    return sql_check_table_indexable(pa->stmt, pa, drive_table, cond);
}

static inline uint32 get_first_plan_id(sql_join_node_t *join_node)
{
    sql_table_t *table = (sql_table_t *)sql_array_get(&join_node->tables, 0);
    uint32 plan_id = table->plan_id;
    for (uint32 i = 1; i < join_node->tables.count; i++) {
        table = (sql_table_t *)sql_array_get(&join_node->tables, i);
        plan_id = MIN(plan_id, table->plan_id);
    }
    return plan_id;
}

static inline status_t sql_build_mix_join_tree(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_join_node_t **join_node,
    cond_tree_t *join_cond);
static inline status_t create_nl_full_rowid_mtrl_join_node(plan_assist_t *pa, sql_join_node_t *join_node)
{
    uint32 plan_count = pa->plan_count;
    CT_RETURN_IFERR(
        sql_alloc_mem(pa->stmt->context, sizeof(sql_table_t), (void **)&join_node->nl_full_opt_info.r_drive_table));
    CT_RETURN_IFERR(
        choose_full_join_drive_table_index(pa, join_node->nl_full_opt_info.r_drive_table, join_node->right, join_node));
    pa->plan_count = get_first_plan_id(join_node->right);
    CT_RETURN_IFERR(sql_build_mix_join_tree(pa->stmt, pa, &join_node->right, join_node->join_cond));
    pa->plan_count = plan_count;
    return CT_SUCCESS;
}

void swap_join_tree_child_node(plan_assist_t *plan_ass, sql_join_node_t *join_root)
{
    sql_table_t *table = NULL;
    sql_table_t *sub_table = NULL;
    for (uint32 i = 0; i < join_root->left->tables.count; i++) {
        table = (sql_table_t *)sql_array_get(&join_root->left->tables, i);
        table->plan_id += join_root->right->tables.count;
    }
    for (uint32 i = 0; i < join_root->right->tables.count; i++) {
        table = (sql_table_t *)sql_array_get(&join_root->right->tables, i);
        table->plan_id -= join_root->left->tables.count;
    }
    for (uint32 i = 0; i < join_root->tables.count; i++) {
        table = (sql_table_t *)sql_array_get(&join_root->tables, i);
        if (plan_ass != NULL) {
            plan_ass->plan_tables[table->plan_id] = table;
        }
        if (table->sub_tables == NULL) {
            continue;
        }
        for (uint32 j = 0; j < table->sub_tables->count; j++) {
            sub_table = (sql_table_t *)cm_galist_get(table->sub_tables, j);
            sub_table->plan_id = table->plan_id;
        }
    }
    SWAP(sql_join_node_t *, join_root->left, join_root->right);
}

static inline status_t sql_reorganise_join_tree(sql_stmt_t *stmt, sql_join_node_t *join_node);

static status_t check_expr_node_4_nl_full_opt(visit_assist_t *visit_ass, expr_node_t **node);
static status_t check_expr_node_4_nl_full_opt(visit_assist_t *visit_ass, expr_node_t **node)
{
    if (visit_ass->result0 == CT_FALSE) {
        return CT_SUCCESS;
    }
    expr_node_t *ori_node = NULL;
    reserved_wid_t res_type;

    switch ((*node)->type) {
        case EXPR_NODE_FUNC:
            if ((*node)->value.v_func.pack_id != CT_INVALID_ID32) {
                visit_ass->result0 = CT_FALSE;
                return CT_SUCCESS;
            }
            return visit_func_node(visit_ass, *node, check_expr_node_4_nl_full_opt);
        case EXPR_NODE_RESERVED:
            res_type = VALUE(uint32, &(*node)->value);
            visit_ass->result0 = (res_type == RES_WORD_NULL || res_type == RES_WORD_TRUE || res_type == RES_WORD_FALSE ||
                res_type == RES_WORD_ROWID);
            // fall through
        case EXPR_NODE_COLUMN:
        case EXPR_NODE_PARAM:
        case EXPR_NODE_CONST:
            return CT_SUCCESS;
        case EXPR_NODE_GROUP:
            ori_node = sql_get_origin_ref(*node);
            return visit_expr_node(visit_ass, &ori_node, check_expr_node_4_nl_full_opt);
        default:
            visit_ass->result0 = NODE_IS_FIRST_EXECUTABLE(*node) || NODE_IS_OPTMZ_CONST(*node);
            return CT_SUCCESS;
    }
}

bool32 check_nl_full_rowid_mtrl_available(cond_tree_t *join_cond)
{
    visit_assist_t visit_ass;
    sql_init_visit_assist(&visit_ass, NULL, NULL);
    visit_ass.excl_flags = VA_EXCL_FUNC;
    visit_ass.result0 = CT_TRUE;
    if (visit_cond_node(&visit_ass, join_cond->root, check_expr_node_4_nl_full_opt) != CT_SUCCESS) {
        cm_reset_error();
        return CT_FALSE;
    }
    return visit_ass.result0;
}

static status_t sql_adjust_mix_join_plan(plan_assist_t *plan_ass, sql_join_node_t *join_node)
{
    return CT_SUCCESS;
}

typedef struct st_sql_join_node_queue {
    sql_join_node_t *head; // head is inner join root node
    sql_join_node_t *tail;
} sql_join_node_queue_t;

static inline void sql_add_inner_join_node_tail(sql_join_node_queue_t *queue_node, sql_join_node_t *join_node)
{
    if (queue_node->tail == queue_node->head) {
        queue_node->head->next = join_node;
        join_node->prev = queue_node->head;
        join_node->next = NULL;
        queue_node->tail = join_node;
        return;
    }

    join_node->next = NULL;
    join_node->prev = queue_node->tail;
    queue_node->tail->next = join_node;
    queue_node->tail = join_node;
}

static inline status_t sql_reorganise_innerjoin_tree_node(sql_stmt_t *stmt, sql_join_node_queue_t *queue_node,
    sql_join_node_t *join_node)
{
    switch (join_node->type) {
        case JOIN_TYPE_COMMA:
        case JOIN_TYPE_CROSS:
        case JOIN_TYPE_INNER:
            if (join_node->filter != NULL) {
                if (queue_node->head->filter == NULL) {
                    CT_RETURN_IFERR(sql_create_cond_tree(stmt->context, &queue_node->head->filter));
                }
                CT_RETURN_IFERR(sql_add_cond_node(queue_node->head->filter, join_node->filter->root));
            }
            CT_RETURN_IFERR(sql_reorganise_innerjoin_tree_node(stmt, queue_node, join_node->left));
            CT_RETURN_IFERR(sql_reorganise_innerjoin_tree_node(stmt, queue_node, join_node->right));
            break;
        case JOIN_TYPE_LEFT:
        case JOIN_TYPE_FULL:
        case JOIN_TYPE_RIGHT:
            sql_add_inner_join_node_tail(queue_node, join_node);
            CT_RETURN_IFERR(sql_reorganise_join_tree(stmt, join_node->left));
            CT_RETURN_IFERR(sql_reorganise_join_tree(stmt, join_node->right));
            break;
        default: // JOIN_TYPE_NODE
            sql_add_inner_join_node_tail(queue_node, join_node);
            break;
    }

    return CT_SUCCESS;
}

static inline status_t sql_reorganise_innerjoin_tree(sql_stmt_t *stmt, sql_join_node_t *inner_join_root)
{
    sql_join_node_queue_t queue_node;

    inner_join_root->prev = NULL;
    inner_join_root->next = NULL;
    queue_node.head = inner_join_root;
    queue_node.tail = inner_join_root;
    CT_RETURN_IFERR(sql_reorganise_innerjoin_tree_node(stmt, &queue_node, inner_join_root->left));
    CT_RETURN_IFERR(sql_reorganise_innerjoin_tree_node(stmt, &queue_node, inner_join_root->right));
    return CT_SUCCESS;
}

static inline status_t sql_reorganise_join_tree(sql_stmt_t *stmt, sql_join_node_t *join_node)
{
    switch (join_node->type) {
        case JOIN_TYPE_COMMA:
        case JOIN_TYPE_CROSS:
        case JOIN_TYPE_INNER:
            CT_RETURN_IFERR(sql_reorganise_innerjoin_tree(stmt, join_node));
            break;

        case JOIN_TYPE_LEFT:
        case JOIN_TYPE_RIGHT:
        case JOIN_TYPE_FULL:
            CT_RETURN_IFERR(sql_reorganise_join_tree(stmt, join_node->left));
            CT_RETURN_IFERR(sql_reorganise_join_tree(stmt, join_node->right));
            break;

        default: // JOIN_TYPE_NONE
            break;
    }

    return CT_SUCCESS;
}

static inline status_t sql_build_mix_join_tree(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_join_node_t **join_node,
    cond_tree_t *join_cond);
static inline status_t sql_build_outer_join_tree(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_join_node_t *join_node)
{
    if (join_node->type == JOIN_TYPE_FULL) {
        CT_RETURN_IFERR(sql_build_mix_join_tree(stmt, plan_ass, &join_node->left, NULL));
        CT_RETURN_IFERR(sql_build_mix_join_tree(stmt, plan_ass, &join_node->right, NULL));
    } else {
        CT_RETURN_IFERR(sql_build_mix_join_tree(stmt, plan_ass, &join_node->left, join_node->filter));
        CT_RETURN_IFERR(sql_build_mix_join_tree(stmt, plan_ass, &join_node->right, join_node->join_cond));
    }

    return CT_SUCCESS;
}

static void sql_reset_join_node_plan_id(sql_join_node_t *join_node)
{
    join_node->plan_id_start = CT_INVALID_ID32;
    for (uint32 i = 0; i < join_node->tables.count; ++i) {
        sql_table_t *table = (sql_table_t *)sql_array_get(&join_node->tables, i);
        table->plan_id = CT_INVALID_ID32;
    }
}

static status_t sql_build_inner_join_tree(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_join_node_t **inner_join_root)
{
    sql_table_t *table = NULL;
    join_assist_t join_ass = { 0 };
    sql_join_node_t *join_node = (*inner_join_root)->next;
    sql_join_node_t *new_join_root = NULL;
    while (join_node != NULL) {
        for (uint32 i = 0; i < join_node->tables.count; ++i) {
            table = (sql_table_t *)sql_array_get(&join_node->tables, i);
            join_ass.maps[table->id] = join_node;
        }

        join_node->plan_id_start = CT_INVALID_ID32;
        join_ass.nodes[join_ass.total++] = join_node;
        join_node = join_node->next;
    }

    plan_ass->cond = (*inner_join_root)->filter;
    if (IS_COORDINATOR && plan_ass->cond == NULL) {
        plan_ass->cond = (*inner_join_root)->join_cond;
    }
    CT_RETURN_IFERR(
        sql_get_table_join_cond(plan_ass->stmt, &plan_ass->query->tables, &plan_ass->query->tables,
                                plan_ass->cond, &plan_ass->join_conds));
    CT_RETURN_IFERR(sql_create_join_tree(stmt, plan_ass, &join_ass, &new_join_root));

    join_node = (*inner_join_root)->next;
    uint32 old_plan_count = plan_ass->plan_count;
    while (join_node != NULL) {
        if (join_node->type == JOIN_TYPE_NONE) {
            join_node = join_node->next;
            continue;
        }

        // Plan id not equal to CT_INVALID_ID32 indicates that the node has been selected,
        // but when creating a join tree within the node, it needs to be reset to CT_INVALID_ID32
        // Prevents all tables in a node from being considered selected
        plan_ass->plan_count = join_node->plan_id_start;
        sql_reset_join_node_plan_id(join_node);
        CT_RETURN_IFERR(sql_build_outer_join_tree(stmt, plan_ass, join_node));
        join_node = join_node->next;
    }
    plan_ass->plan_count = old_plan_count;
    *inner_join_root = new_join_root;
    return CT_SUCCESS;
}

static inline status_t sql_build_mix_join_tree(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_join_node_t **join_node,
    cond_tree_t *join_cond)
{
    switch ((*join_node)->type) {
        case JOIN_TYPE_COMMA:
        case JOIN_TYPE_CROSS:
        case JOIN_TYPE_INNER:
            return sql_build_inner_join_tree(stmt, plan_ass, join_node);

        case JOIN_TYPE_LEFT:
        case JOIN_TYPE_RIGHT:
        case JOIN_TYPE_FULL:
            return sql_build_outer_join_tree(stmt, plan_ass, *join_node);

        default: // JOIN_TYPE_NONE
            CT_RETURN_IFERR(sql_check_table_indexable(stmt, plan_ass, TABLE_OF_JOIN_LEAF(*join_node), join_cond));
            sql_plan_assist_set_table(plan_ass, TABLE_OF_JOIN_LEAF(*join_node));
            return CT_SUCCESS;
    }
}

static status_t sql_adjust_query_filter_cond(plan_assist_t *plan_ass, sql_join_node_t *join_node)
{
    sql_stmt_t *stmt = plan_ass->stmt;
    sql_query_t *query = plan_ass->query;

    if (!plan_ass->is_final_plan || plan_ass->is_subqry_cost || query->filter_cond == NULL) {
        return CT_SUCCESS;
    }

    // s_query: must push filter_cond down to join_node->filter
    // query:  when connect by exists, it cannot be put on join_node->filter
    //         when rownum exists, it is necessary to use rownum to adjust the cost,so it cannot be put on
    //         join_node->filter
    if (!query->is_s_query && (!IS_INNER_JOIN(join_node) || IS_COND_FALSE(query->filter_cond) ||
        query->connect_by_cond != NULL || query->filter_cond->rownum_upper != CT_INFINITE32)) {
        return CT_SUCCESS;
    }

    if (join_node->filter == NULL) {
        join_node->filter = query->filter_cond;
    } else {
        cond_tree_t *new_cond = NULL;
        CT_RETURN_IFERR(sql_create_cond_tree(stmt->context, &new_cond));
        CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&new_cond->root));
        new_cond->root->type = COND_NODE_AND;
        new_cond->root->left = join_node->filter->root;
        new_cond->root->right = query->filter_cond->root;
        join_node->filter = new_cond;
    }
    query->filter_cond = NULL;
    query->has_filter_opt = CT_TRUE;
    return CT_SUCCESS;
}

status_t sql_build_join_tree(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_join_node_t **join_root)
{
    CTSQL_SAVE_STACK(stmt);
    SET_NODE_STACK_CURR_QUERY(stmt, plan_ass->query);
    if (plan_ass->join_assist->outer_node_count > 0) {
        {
            CT_RETURN_IFERR(sql_reorganise_join_tree(stmt, plan_ass->join_assist->join_node));
            CT_RETURN_IFERR(sql_build_mix_join_tree(stmt, plan_ass, &plan_ass->join_assist->join_node, NULL));
            CT_RETURN_IFERR(sql_adjust_mix_join_plan(plan_ass, plan_ass->join_assist->join_node));
            *join_root = plan_ass->join_assist->join_node;
        }
        CT_RETURN_IFERR(sql_adjust_query_filter_cond(plan_ass, *join_root));
    } else {
        join_assist_t join_ass = { 0 };
        sql_generate_join_assist(plan_ass, plan_ass->join_assist->join_node, &join_ass);
        CT_RETURN_IFERR(
            sql_get_table_join_cond(plan_ass->stmt, &plan_ass->query->tables, &plan_ass->query->tables,
                                    plan_ass->cond, &plan_ass->join_conds));
        {
            CT_RETURN_IFERR(sql_create_join_tree(stmt, plan_ass, &join_ass, join_root));
        }
    }
    SQL_RESTORE_NODE_STACK(stmt);
    CTSQL_RESTORE_STACK(stmt);
    return CT_SUCCESS;
}

static status_t sql_create_base_join_plan(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_join_node_t *join_node,
    plan_node_t **l_plan, plan_node_t **r_plan)
{
    cond_tree_t *temp_cond = NULL;

    CT_RETURN_IFERR(sql_create_join_plan(stmt, plan_ass, join_node->left, join_node->filter, l_plan));

    temp_cond = sql_get_right_table_cond(join_node);
    return sql_create_join_plan(stmt, plan_ass, join_node->right, temp_cond, r_plan);
}

static inline bool32 sql_cond_node_exist_tables(cond_node_t *cond, sql_array_t *tables)
{
    cols_used_t cols_used;
    biqueue_t *cols_que = NULL;
    biqueue_node_t *curr_que = NULL;
    biqueue_node_t *end_que = NULL;
    expr_node_t *col = NULL;
    sql_table_t *table = NULL;
    init_cols_used(&cols_used);
    sql_collect_cols_in_cond(cond, &cols_used);

    // returns TRUE means no optimize
    if (HAS_DYNAMIC_SUBSLCT(&cols_used) || HAS_ROWNUM(&cols_used)) {
        return CT_TRUE;
    }

    cols_que = &cols_used.cols_que[SELF_IDX];
    curr_que = biqueue_first(cols_que);
    end_que = biqueue_end(cols_que);

    while (curr_que != end_que) {
        col = OBJECT_OF(expr_node_t, curr_que);
        for (uint32 i = 0; i < tables->count; i++) {
            table = (sql_table_t *)sql_array_get(tables, i);
            if (table->id == TAB_OF_NODE(col)) {
                return CT_TRUE;
            }
        }
        curr_que = curr_que->next;
    }
    return CT_FALSE;
}

static inline bool32 sql_check_json_table_variable(sql_stmt_t *stmt, sql_array_t *tables)
{
    sql_table_t *table = NULL;

    for (uint32 i = 0; i < tables->count; i++) {
        table = (sql_table_t *)sql_array_get(tables, i);
        if ((table->type == JSON_TABLE) && table->json_table_info->depend_table_count > 0) {
            return CT_FALSE;
        }
    }
    return CT_TRUE;
}

static bool32 sql_table_cond_exists_tables(sql_array_t *right_tables, sql_array_t *left_tables)
{
    sql_table_t *table = NULL;
    for (uint32 i = 0; i < right_tables->count; i++) {
        table = (sql_table_t *)sql_array_get(right_tables, i);
        if (table->index_cond_pruning && sql_cond_node_exist_tables(table->cond->root, left_tables)) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

static bool32 sql_judge_cmp_cartesian(cmp_node_t *cmp, uint32 l_tab_id, uint32 r_tab_id)
{
    expr_node_t *col_node = NULL;
    bool32 has_l_tab = CT_FALSE;
    bool32 has_r_tab = CT_FALSE;
    cols_used_t cols_used;
    init_cols_used(&cols_used);

    sql_collect_cols_in_expr_tree(cmp->left, &cols_used);
    sql_collect_cols_in_expr_tree(cmp->right, &cols_used);

    biqueue_t *cols_que = &cols_used.cols_que[SELF_IDX];
    biqueue_node_t *curr_que = biqueue_first(cols_que);
    biqueue_node_t *end_que = biqueue_end(cols_que);

    while (curr_que != end_que) {
        col_node = OBJECT_OF(expr_node_t, curr_que);
        if (TAB_OF_NODE(col_node) == l_tab_id) {
            has_l_tab = CT_TRUE;
        } else if (TAB_OF_NODE(col_node) == r_tab_id) {
            has_r_tab = CT_TRUE;
        }
        if (has_l_tab && has_r_tab) {
            return CT_FALSE;
        }
        curr_que = curr_que->next;
    }

    return CT_TRUE;
}

static bool32 sql_judge_join_cond_cartesian(cond_node_t *cond_node, uint32 l_tab_id, uint32 r_tab_id)
{
    switch (cond_node->type) {
        case COND_NODE_AND:
        case COND_NODE_OR:
            return (bool32)(sql_judge_join_cond_cartesian(cond_node->left, l_tab_id, r_tab_id) &&
                sql_judge_join_cond_cartesian(cond_node->right, l_tab_id, r_tab_id));
        case COND_NODE_COMPARE:
            return sql_judge_cmp_cartesian(cond_node->cmp, l_tab_id, r_tab_id);
        default:
            return CT_TRUE;
    }
}

#define GET_JOIN_NODE_COND(join_root) (IS_INNER_JOIN(join_root) ? (join_root)->filter : (join_root)->join_cond);
static bool32 sql_judge_cartesian_join(sql_join_node_t *join_root)
{
    cond_tree_t *join_cond = GET_JOIN_NODE_COND(join_root);
    if (join_cond == NULL) {
        return CT_TRUE;
    }

    sql_array_t *l_tables = &join_root->left->tables;
    sql_table_t *right_table = TABLE_OF_JOIN_LEAF(join_root->right);
    sql_table_t *left_table = NULL;

    for (uint32 i = 0; i < l_tables->count; i++) {
        left_table = (sql_table_t *)sql_array_get(l_tables, i);
        if (!sql_judge_join_cond_cartesian(join_cond->root, left_table->id, right_table->id)) {
            return CT_FALSE;
        }
    }

    return CT_TRUE;
}

static status_t sql_create_nl_join_plan(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_join_node_t *join_node,
    plan_node_t *plan)
{
    plan->join_p.exec_data_index = plan_ass->join_assist->inner_plan_count++;
    CT_RETURN_IFERR(sql_create_base_join_plan(stmt, plan_ass, join_node, &plan->join_p.left, &plan->join_p.right));

    cond_node_t *cond = NULL;
    if (plan_ass->query->connect_by_cond == NULL && !plan_ass->query->is_s_query) {
        if (plan->join_p.filter != NULL) {
            cond = plan->join_p.filter->root;
        } else if (plan_ass->cond != NULL) {
            cond = plan_ass->cond->root;
        }
        plan->join_p.r_eof_flag = !sql_table_cond_exists_tables(&join_node->right->tables, &join_node->left->tables);
    }
    if (cond != NULL) {
        plan->join_p.r_eof_flag =
            plan->join_p.r_eof_flag && !sql_cond_node_exist_tables(cond, &join_node->left->tables);
    }
    plan->join_p.r_eof_flag = plan->join_p.r_eof_flag && sql_check_json_table_variable(stmt, &join_node->right->tables);

    if (plan->join_p.right->type == PLAN_NODE_SCAN && sql_judge_cartesian_join(join_node)) {
        plan->join_p.right->scan_p.table->is_descartes = CT_TRUE;
    }

    return CT_SUCCESS;
}

static status_t sql_create_nl_batch_join_plan(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_join_node_t *join_node,
    plan_node_t *plan)
{
    plan->join_p.filter = join_node->filter;
    plan->join_p.nl_pos = stmt->context->nl_batch_cnt++;
    plan->join_p.cache_tab = TABLE_OF_JOIN_LEAF(join_node->right);
    return sql_create_base_join_plan(stmt, plan_ass, join_node, &plan->join_p.left, &plan->join_p.right);
}

static status_t sql_create_nl_outer_join_plan(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_join_node_t *join_node,
    plan_node_t *plan)
{
    plan->join_p.exec_data_index = plan_ass->join_assist->outer_plan_count++;
    return sql_create_base_join_plan(stmt, plan_ass, join_node, &plan->join_p.left, &plan->join_p.right);
}

static status_t sql_create_nl_full_join_plan(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_join_node_t *join_node,
    plan_node_t *plan)
{
    plan->join_p.nl_full_opt_type = join_node->nl_full_opt_info.opt_type;
    if (join_node->nl_full_opt_info.opt_type == NL_FULL_OPT_NONE) {
        return sql_create_nl_outer_join_plan(stmt, plan_ass, join_node, plan);
    }

    plan->join_p.exec_data_index = plan_ass->join_assist->outer_plan_count++;
    join_node->type = JOIN_TYPE_LEFT;
    join_node->oper = JOIN_OPER_NL_LEFT;
    CT_RETURN_IFERR(perfect_tree_and_gen_oper_map(plan_ass, plan_ass->query->tables.count, join_node));
    CT_RETURN_IFERR(sql_create_base_join_plan(stmt, plan_ass, join_node, &plan->join_p.left, &plan->join_p.right));

    {
        plan->join_p.nl_full_mtrl_pos = plan_ass->nlf_mtrl_cnt++;
        CT_RETURN_IFERR(sql_create_table_scan_plan(stmt, plan_ass, NULL, join_node->nl_full_opt_info.r_drive_table,
            &plan->join_p.r_drive_plan));
    }

    join_node->type = JOIN_TYPE_FULL;
    join_node->oper = JOIN_OPER_NL_FULL;
    return perfect_tree_and_gen_oper_map(plan_ass, plan_ass->query->tables.count, join_node);
}

static inline void sql_reset_join_table_scan_flag(sql_join_node_t *join_node);
static inline void sql_reset_table_scan_flag(sql_join_node_t *join_node)
{
    if (join_node->type == JOIN_TYPE_NONE) {
    } else {
        sql_reset_join_table_scan_flag(join_node);
    }
}

static inline void sql_reset_join_table_scan_flag(sql_join_node_t *join_node)
{
    sql_reset_table_scan_flag(join_node->left);
    sql_reset_table_scan_flag(join_node->right);
}

#define HASH_MIN_BUCKETS_LIMIT (int64)10000
static inline join_oper_t get_hash_right_join_oper(join_oper_t oper)
{
    switch (oper) {
        case JOIN_OPER_HASH_SEMI:
            return JOIN_OPER_HASH_RIGHT_SEMI;
        case JOIN_OPER_HASH_ANTI:
            return JOIN_OPER_HASH_RIGHT_ANTI;
        case JOIN_OPER_HASH_ANTI_NA:
            return JOIN_OPER_HASH_RIGHT_ANTI_NA;
        case JOIN_OPER_HASH_LEFT:
            return JOIN_OPER_HASH_RIGHT_LEFT;
        default:
            return oper;
    }
}

static inline void clear_hash_table_conflict(sql_table_t *l_table, sql_table_t *r_table)
{
    bool32 l_hash_table = HAS_SPEC_TYPE_HINT(l_table->hint_info, JOIN_HINT, HINT_KEY_WORD_HASH_TABLE);
    bool32 r_hash_table = HAS_SPEC_TYPE_HINT(r_table->hint_info, JOIN_HINT, HINT_KEY_WORD_HASH_TABLE);
    bool32 l_no_hash_table = HAS_SPEC_TYPE_HINT(l_table->hint_info, JOIN_HINT, HINT_KEY_WORD_NO_HASH_TABLE);
    bool32 r_no_hash_table = HAS_SPEC_TYPE_HINT(r_table->hint_info, JOIN_HINT, HINT_KEY_WORD_NO_HASH_TABLE);
    if ((l_hash_table && r_hash_table) || (l_no_hash_table && r_no_hash_table)) {
        l_table->hint_info->mask[JOIN_HINT] &= ~(HINT_KEY_WORD_HASH_TABLE | HINT_KEY_WORD_NO_HASH_TABLE);
        r_table->hint_info->mask[JOIN_HINT] &= ~(HINT_KEY_WORD_HASH_TABLE | HINT_KEY_WORD_NO_HASH_TABLE);
    }
}

static inline void hint_get_hash_table(sql_table_t *table, bool32 l_table, bool32 *hash_left)
{
    if (HAS_SPEC_TYPE_HINT(table->hint_info, JOIN_HINT, HINT_KEY_WORD_HASH_TABLE)) {
        *hash_left = l_table;
    }
    if (HAS_SPEC_TYPE_HINT(table->hint_info, JOIN_HINT, HINT_KEY_WORD_NO_HASH_TABLE)) {
        *hash_left = !l_table;
    }
}

static inline status_t check_hash_keys_count_valid(join_plan_t *join_p)
{
    galist_t *l_keys = join_p->left_hash.key_items;
    galist_t *r_keys = join_p->right_hash.key_items;

    if (l_keys->count != r_keys->count || l_keys->count == 0) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "l_keys->count(%u) == r_keys->count(%u)", (uint32)l_keys->count,
            (uint32)r_keys->count);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static inline status_t sql_join_create_concate_keys(sql_stmt_t *stmt, galist_t *keys, plan_node_t *plan,
    bool32 *has_subselect)
{
    if (plan->type == PLAN_NODE_JOIN) {
        CT_RETURN_IFERR(sql_join_create_concate_keys(stmt, keys, plan->join_p.left, has_subselect));
        if (*has_subselect) {
            return CT_SUCCESS;
        }
        return sql_join_create_concate_keys(stmt, keys, plan->join_p.right, has_subselect);
    }
    if (plan->scan_p.table->type != NORMAL_TABLE) {
        *has_subselect = CT_TRUE;
        return CT_SUCCESS;
    }
    return sql_create_concate_key(stmt, keys, plan->scan_p.table);
}

static inline status_t sql_adjust_join_plan_with_1_cnct(plan_assist_t *plan_ass, concate_plan_t *cnct_p,
    plan_node_t *sub_plan, bool32 is_left, plan_node_t **plan)
{
    bool32 has_subselect = CT_FALSE;
    plan_node_t *concate_plan = NULL;
    plan_node_t *child_plan = NULL;
    plan_node_t *join_plan = NULL;
    uint32 ori_keys_count = cnct_p->keys->count;
    sql_stmt_t *stmt = plan_ass->stmt;

    CT_RETURN_IFERR(sql_join_create_concate_keys(stmt, cnct_p->keys, sub_plan, &has_subselect));
    if (has_subselect) {
        cnct_p->keys->count = ori_keys_count;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)&concate_plan));
    CT_RETURN_IFERR(sql_create_list(stmt, &concate_plan->cnct_p.plans));
    concate_plan->type = PLAN_NODE_CONCATE;
    concate_plan->cnct_p.keys = cnct_p->keys;

    for (uint32 i = 0; i < cnct_p->plans->count; i++) {
        child_plan = (plan_node_t *)cm_galist_get(cnct_p->plans, i);
        CT_RETURN_IFERR(cm_galist_new(concate_plan->cnct_p.plans, sizeof(plan_node_t), (void **)&join_plan));
        join_plan->type = PLAN_NODE_JOIN;
        join_plan->join_p.oper = (*plan)->join_p.oper;
        join_plan->join_p.cond = (*plan)->join_p.cond;
        join_plan->join_p.filter = (*plan)->join_p.filter;
        join_plan->join_p.left = is_left ? child_plan : sub_plan;
        join_plan->join_p.right = is_left ? sub_plan : child_plan;
        join_plan->join_p.exec_data_index = plan_ass->join_assist->inner_plan_count++;
    }
    *plan = concate_plan;
    return CT_SUCCESS;
}

static inline status_t sql_adjust_join_plan_with_2_cnct(plan_assist_t *plan_ass, concate_plan_t *l_cnct,
    concate_plan_t *r_cnct, plan_node_t **plan)
{
    expr_tree_t *rowid = NULL;
    plan_node_t *concate_plan = NULL;
    plan_node_t *l_plan = NULL;
    plan_node_t *r_plan = NULL;
    plan_node_t *join_plan = NULL;
    sql_stmt_t *stmt = plan_ass->stmt;

    for (uint32 i = 0; i < r_cnct->keys->count; i++) {
        rowid = (expr_tree_t *)cm_galist_get(r_cnct->keys, i);
        CT_RETURN_IFERR(cm_galist_insert(l_cnct->keys, rowid));
    }

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)&concate_plan));
    CT_RETURN_IFERR(sql_create_list(stmt, &concate_plan->cnct_p.plans));
    concate_plan->type = PLAN_NODE_CONCATE;
    concate_plan->cnct_p.keys = l_cnct->keys;

    for (uint32 i = 0; i < l_cnct->plans->count; i++) {
        l_plan = (plan_node_t *)cm_galist_get(l_cnct->plans, i);
        for (uint32 j = 0; j < r_cnct->plans->count; j++) {
            r_plan = (plan_node_t *)cm_galist_get(r_cnct->plans, j);
            CT_RETURN_IFERR(cm_galist_new(concate_plan->cnct_p.plans, sizeof(plan_node_t), (void **)&join_plan));
            join_plan->type = PLAN_NODE_JOIN;
            join_plan->join_p.oper = (*plan)->join_p.oper;
            join_plan->join_p.cond = (*plan)->join_p.cond;
            join_plan->join_p.filter = (*plan)->join_p.filter;
            join_plan->join_p.left = l_plan;
            join_plan->join_p.right = r_plan;
            join_plan->join_p.exec_data_index = plan_ass->join_assist->inner_plan_count++;
        }
    }
    *plan = concate_plan;
    return CT_SUCCESS;
}

static inline status_t sql_adjust_join_plan_with_cnct(plan_assist_t *pa, plan_node_t **plan)
{
    if ((*plan)->join_p.oper != JOIN_OPER_NL ||
        ((*plan)->join_p.left->type != PLAN_NODE_CONCATE && (*plan)->join_p.right->type != PLAN_NODE_CONCATE)) {
        return CT_SUCCESS;
    }

    if ((*plan)->join_p.left->type == PLAN_NODE_CONCATE && (*plan)->join_p.right->type != PLAN_NODE_CONCATE) {
        return sql_adjust_join_plan_with_1_cnct(pa, &(*plan)->join_p.left->cnct_p, (*plan)->join_p.right, CT_TRUE,
            plan);
    }

    if ((*plan)->join_p.right->type == PLAN_NODE_CONCATE && (*plan)->join_p.left->type != PLAN_NODE_CONCATE) {
        return sql_adjust_join_plan_with_1_cnct(pa, &(*plan)->join_p.right->cnct_p, (*plan)->join_p.left, CT_FALSE,
            plan);
    }

    return sql_adjust_join_plan_with_2_cnct(pa, &(*plan)->join_p.left->cnct_p, &(*plan)->join_p.right->cnct_p, plan);
}

static inline void sql_init_join_plan(sql_stmt_t *stmt, plan_assist_t *pa, sql_join_node_t *join_node,
                                      plan_node_t *plan_node)
{
    plan_node->type = PLAN_NODE_JOIN;
    plan_node->plan_id = stmt->context->plan_count++;
    plan_node->join_p.cond = join_node->join_cond;
    plan_node->join_p.filter = (pa->join_assist->outer_node_count > 0) ? join_node->filter : NULL;
    plan_node->join_p.oper = join_node->oper;
    plan_node->join_p.nl_full_opt_type = NL_FULL_OPT_NONE;
    plan_node->join_p.nl_full_r_drive = CT_FALSE;
}

static bool32 if_optimize_nl_full(sql_stmt_t *stmt, plan_assist_t *pa, sql_join_node_t *join_node)
{
        return CT_FALSE;
}

status_t sql_create_full_join_plan(sql_stmt_t *stmt, plan_assist_t *pa, sql_join_node_t *join_node, plan_node_t *plan)
{
    if (if_optimize_nl_full(stmt, pa, join_node)) {
        sql_init_join_plan(stmt, pa, join_node, plan);
    }
    return sql_create_nl_full_join_plan(stmt, pa, join_node, plan);
}

status_t sql_create_join_plan(sql_stmt_t *stmt, plan_assist_t *pa, sql_join_node_t *join_node, cond_tree_t *cond,
    plan_node_t **plan)
{
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)plan));
    plan_node_t *plan_node = *plan;
    (*plan)->cost = join_node->cost.cost;
    (*plan)->rows = (CBO_ON && !stmt->context->opt_by_rbo) ? join_node->cost.card : 0;

    if (join_node->type != JOIN_TYPE_NONE) {
        sql_init_join_plan(stmt, pa, join_node, plan_node);

        switch (join_node->oper) {
            case JOIN_OPER_NL:
                CT_RETURN_IFERR(sql_create_nl_join_plan(stmt, pa, join_node, plan_node));
                break;

            case JOIN_OPER_NL_BATCH:
                CT_RETURN_IFERR(sql_create_nl_batch_join_plan(stmt, pa, join_node, plan_node));
                break;

            case JOIN_OPER_MERGE:
            case JOIN_OPER_HASH:
            case JOIN_OPER_HASH_LEFT:
            case JOIN_OPER_HASH_SEMI:
            case JOIN_OPER_HASH_ANTI:
            case JOIN_OPER_HASH_ANTI_NA:
            case JOIN_OPER_HASH_FULL:
		knl_panic(0);
                break;

            case JOIN_OPER_NL_FULL:
                CT_RETURN_IFERR(sql_create_full_join_plan(stmt, pa, join_node, plan_node));
                break;

            case JOIN_OPER_NL_LEFT:
                CT_RETURN_IFERR(sql_create_nl_outer_join_plan(stmt, pa, join_node, plan_node));
                break;

            default:
                CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "merge left or merge full");
                return CT_ERROR;
        }
        return sql_adjust_join_plan_with_cnct(pa, plan);
    }

    return sql_create_table_scan_plan(stmt, pa, cond, TABLE_OF_JOIN_LEAF(join_node), plan);
}

#ifdef __cplusplus
}
#endif
