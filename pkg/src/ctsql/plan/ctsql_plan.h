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
 * ctsql_plan.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/plan/ctsql_plan.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __SQL_PLAN_H__
#define __SQL_PLAN_H__

#include "ctsql_plan_defs.h"
#include "ctsql_func.h"


#ifdef __cplusplus
extern "C" {
#endif

static inline expr_node_t *get_like_first_node(expr_node_t *node)
{
    if (node->type == EXPR_NODE_FUNC) {
        sql_func_t *func = sql_get_func(&node->value.v_func);
        if (func->builtin_func_id == ID_FUNC_ITEM_CONCAT || func->builtin_func_id == ID_FUNC_ITEM_CONCAT_WS) {
            return node->argument->root;
        }
    } else {
        while (node->type == EXPR_NODE_CAT) {
            node = node->left;
        }
    }
    return node;
}

static inline bool32 sql_expr_column_matched(expr_tree_t *expr, var_column_t *column)
{
    expr_node_t *node = expr->root;

    // (a, b) in ((a1, b1), (a2, b2), ...) not support index scaning now ; minus not support index scaning now
    if (node->type != EXPR_NODE_COLUMN || expr->next != NULL) {
        return CT_FALSE;
    }

    var_column_t *expr_column = VALUE_PTR(var_column_t, &node->value);

    return (expr_column->ancestor == 0) && (expr_column->tab == column->tab) && (expr_column->col == column->col);
}

static inline bool32 sql_expr_node_matched(sql_stmt_t *stmt, expr_tree_t *expr, expr_node_t *r_node)
{
    expr_node_t *l_node = expr->root;

    // (a, b) in ((a1, b1), (a2, b2), ...) not support index scaning now
    if (l_node->type != r_node->type || expr->next != NULL) {
        return CT_FALSE;
    }
    return sql_expr_node_equal(stmt, l_node, r_node, NULL);
}

static inline cmp_type_t sql_reverse_cmp(cmp_type_t cmp_type)
{
    switch (cmp_type) {
        case CMP_TYPE_LESS:
            return CMP_TYPE_GREAT;
        case CMP_TYPE_LESS_EQUAL:
            return CMP_TYPE_GREAT_EQUAL;
        case CMP_TYPE_GREAT:
            return CMP_TYPE_LESS;
        case CMP_TYPE_GREAT_EQUAL:
            return CMP_TYPE_LESS_EQUAL;
        case CMP_TYPE_EQUAL:
        default:
            return CMP_TYPE_EQUAL;
    }
}

#define HAS_ONLY_NL_OPER(flag) \
    (((flag) == JOIN_OPER_NL) || ((flag) == JOIN_OPER_NL_LEFT) || ((flag) == JOIN_OPER_NL_BATCH))

static inline bool32 chk_tab_with_oper_map(plan_assist_t *pa, uint16 tab1, uint16 tab2)
{
    if (pa->join_oper_map == NULL) {
        return CT_TRUE;
    }
    uint32 step = pa->table_count;
    uint8 oper_flag = pa->join_oper_map[step * tab1 + tab2];
    return HAS_ONLY_NL_OPER(oper_flag);
}

static inline bool32 sql_reserved_word_indexable(plan_assist_t *pa, expr_node_t *node, uint32 tab_id)
{
    uint32 tab;

    switch (VALUE(uint32, &node->value)) {
        case RES_WORD_SYSDATE:
        case RES_WORD_SYSTIMESTAMP:
        case RES_WORD_CURDATE:
        case RES_WORD_CURTIMESTAMP:
        case RES_WORD_LOCALTIMESTAMP:
        case RES_WORD_UTCTIMESTAMP:
        case RES_WORD_NULL:
        case RES_WORD_TRUE:
        case RES_WORD_FALSE:
            return CT_TRUE;

        case RES_WORD_ROWID:
            if (pa == NULL) {
                return CT_FALSE;
            }
            if (node->value.v_rid.ancestor > 0) {
                pa->col_use_flag |= USE_ANCESTOR_COL;
                pa->max_ancestor = MAX(node->value.v_rid.ancestor, pa->max_ancestor);
                return CT_TRUE;
            }
            tab = node->value.v_rid.tab_id;
            if (pa->tables[tab]->plan_id < pa->tables[tab_id]->plan_id) {
                if (!chk_tab_with_oper_map(pa, tab, tab_id)) {
                    return CT_FALSE;
                }
                pa->col_use_flag |= USE_SELF_JOIN_COL;
                return CT_TRUE;
            }
            return CT_FALSE;

        default:
            return CT_FALSE;
    }
}

status_t sql_create_dml_plan(sql_stmt_t *stmt);
status_t sql_check_table_indexable(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, cond_tree_t *cond);
status_t sql_create_table_scan_plan(sql_stmt_t *stmt, plan_assist_t *pa, cond_tree_t *cond, sql_table_t *table,
    plan_node_t **plan);
status_t sql_get_rowid_cost(sql_stmt_t *stmt, plan_assist_t *pa, cond_node_t *cond, sql_table_t *table, bool32 is_temp);
status_t sql_make_index_col_map(plan_assist_t *pa, sql_stmt_t *stmt, sql_table_t *table);

status_t sql_generate_insert_plan(sql_stmt_t *stmt, sql_insert_t *insert_ctx, plan_assist_t *parent);
status_t sql_generate_merge_into_plan(sql_stmt_t *stmt, sql_merge_t *merge_ctx, plan_assist_t *parent);
status_t sql_generate_delete_plan(sql_stmt_t *stmt, sql_delete_t *delete_ctx, plan_assist_t *plan_ass);
status_t sql_generate_select_plan(sql_stmt_t *stmt, sql_select_t *select_ctx, plan_assist_t *plan_ass);
status_t sql_generate_update_plan(sql_stmt_t *stmt, sql_update_t *update_ctx, plan_assist_t *parent);
status_t sql_create_subselect_plan(sql_stmt_t *stmt, sql_query_t *query, plan_assist_t *plan_ass);
void check_table_stats(sql_stmt_t *stmt);
void cbo_unset_select_node_table_flag(select_node_t *select_node, uint32 cbo_flag, bool32 recurs);
void cbo_set_select_node_table_flag(select_node_t *select_node, uint32 cbo_flag, bool32 recurs);

// RBO|CBO interface declare
status_t rbo_table_indexable(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, cond_node_t *cond,
    bool32 *result);
status_t rbo_choose_full_scan_index(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, bool32 chk_sort);

void sql_prepare_query_plan(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_query_t *query, sql_node_type_t type,
                            plan_assist_t *parent);

void reset_select_node_cbo_status(select_node_t *node);
void sql_collect_select_nodes(biqueue_t *queue, select_node_t *node);
typedef status_t (*query_visit_func_t)(sql_stmt_t *stmt, sql_query_t *query);
status_t visit_select_node(sql_stmt_t *stmt, select_node_t *node, query_visit_func_t visit_func);
bool32 sql_expr_is_certain(plan_assist_t *pa, expr_tree_t *expr, var_column_t *v_col);
void sql_init_plan_assist(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_query_t *query, sql_node_type_t type,
                          plan_assist_t *parent);
uint32 get_query_plan_flag(sql_query_t *query);
plan_assist_t *sql_get_ancestor_pa(plan_assist_t *curr_pa, uint32 temp_ancestor);
sql_query_t *sql_get_ancestor_query(sql_query_t *query, uint32 anc);
status_t can_rewrite_by_check_index(sql_stmt_t *stmt, sql_query_t *query, ck_type_t cktype, bool32 *result);
status_t rbo_check_index_4_rewrite(sql_stmt_t *stmt, sql_query_t *query, bool32 *result);
plan_node_type_t sql_get_group_plan_type(sql_stmt_t *stmt, sql_query_t *query);
status_t add_cbo_depend_tab(sql_stmt_t *stmt, sql_table_t *table, uint32 tab_no);
uint32 sql_get_plan_hash_rows(sql_stmt_t *stmt, plan_node_t *plan);
status_t sql_create_query_plan_ex(sql_stmt_t *stmt, sql_query_t *query, plan_assist_t *plan_ass, plan_node_t **plan);
bool32 sql_can_hash_mtrl_support_aggtype(sql_stmt_t *stmt, sql_query_t *query);
status_t sql_clone_join_root(sql_stmt_t *stmt, void *ctx, sql_join_node_t *src_join_root,
                             sql_join_node_t **dst_root, sql_array_t *tables, ga_alloc_func_t alloc_mem_func);
void swap_join_tree_child_node(plan_assist_t *plan_ass, sql_join_node_t *join_root);
bool32 if_is_drive_table(sql_join_node_t *join_node, uint16 table);
void clear_query_cbo_status(sql_query_t *query);
status_t build_query_join_tree(sql_stmt_t *stmt, sql_query_t *query, plan_assist_t *parent, sql_join_node_t **ret_root,
    uint32 driver_table_count);
uint32 sql_calc_rownum(sql_stmt_t *stmt, sql_query_t *query);
status_t perfect_tree_and_gen_oper_map(plan_assist_t *pa, uint32 step, sql_join_node_t *join_node);
status_t sql_dynamic_sampling_table_stats(sql_stmt_t *stmt, plan_assist_t *pa);
bool32 sql_query_has_hash_join(sql_query_t *query);
status_t clone_tables_4_subqry(sql_stmt_t *stmt, sql_query_t *query, sql_query_t *sub_query);
void sql_init_plan_assist_impl(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_query_t *query, sql_node_type_t type,
                               plan_assist_t *parent);
sql_table_t *sql_get_driver_table(plan_assist_t *plan_ass);
status_t remove_pushed_down_join_cond(sql_stmt_t *stmt, plan_assist_t *pa, sql_array_t *tables);

#define IS_REVERSE_INDEX_AVAILABLE(match_mode, idx_col_id) \
    ((match_mode) == COLUMN_MATCH_POINT || ((match_mode) == COLUMN_MATCH_LIST && (idx_col_id) == 0))
#define SCALE_BY_LIMIT_EXCL                                                                                           \
    (EX_QUERY_WINSORT | EX_QUERY_HAVING | EX_QUERY_CUBE | EX_QUERY_PIVOT | EX_QUERY_FOR_UPDATE | EX_QUERY_SIBL_SORT | \
        EX_QUERY_CONNECT)

#define SCALE_BY_ROWNUM_EXCL (EX_QUERY_SIBL_SORT | EX_QUERY_CONNECT)
#define MAX_NL_FULL_DUPL_PLAN_COUNT 4
#define IS_EQUAL_TYPE(join_type)                                                                           \
    ((join_type) == JOIN_TYPE_INNER || (join_type) == JOIN_TYPE_COMMA || (join_type) == JOIN_TYPE_CROSS || \
        (join_type) == JOIN_TYPE_FULL)
#define IS_INNER_TYPE(join_type) \
    ((join_type) == JOIN_TYPE_INNER || (join_type) == JOIN_TYPE_COMMA || (join_type) == JOIN_TYPE_CROSS)
#define IS_INNER_JOIN(join_root) IS_INNER_TYPE((join_root)->type)
#define IS_LEFT_JOIN(join_root) ((join_root)->type == JOIN_TYPE_LEFT)
#define IS_FULL_JOIN(join_root) ((join_root)->type == JOIN_TYPE_FULL)
#define IS_SEMI_JOIN(join_root)                                                                 \
    ((join_root)->oper == JOIN_OPER_HASH_ANTI || (join_root)->oper == JOIN_OPER_HASH_ANTI_NA || \
        (join_root)->oper == JOIN_OPER_HASH_SEMI)
static inline void sql_plan_assist_set_table(plan_assist_t *pa, sql_table_t *table)
{
    table->plan_id = pa->plan_count;
    pa->plan_tables[pa->plan_count++] = table;

    if (table->sub_tables != NULL) {
        for (uint32 i = 0; i < table->sub_tables->count; i++) {
            sql_table_t *sub_table = (sql_table_t *)cm_galist_get(table->sub_tables, i);
            sub_table->plan_id = table->plan_id;
        }
    }
}

static inline status_t sql_create_concate_key(sql_stmt_t *stmt, galist_t *keys, sql_table_t *table)
{
    expr_tree_t *rowid = NULL;

    CT_RETURN_IFERR(cm_galist_new(keys, sizeof(expr_tree_t), (pointer_t *)&rowid));
    rowid->owner = stmt->context;
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&rowid->root));
    rowid->root->size = ROWID_LENGTH;
    rowid->root->type = EXPR_NODE_RESERVED;
    rowid->root->datatype = CT_TYPE_STRING;
    rowid->root->value.type = CT_TYPE_INTEGER;
    rowid->root->value.v_rid.res_id = RES_WORD_ROWID;
    rowid->root->value.v_rid.tab_id = table->id;
    rowid->root->value.v_rid.ancestor = 0;
    return CT_SUCCESS;
}

static inline void sql_convert_to_left_join(sql_join_node_t *join_node)
{
    if (join_node->type <= JOIN_TYPE_LEFT) {
        return;
    }
    join_node->type = JOIN_TYPE_LEFT;
    join_node->oper = join_node->oper == JOIN_OPER_HASH_FULL ? JOIN_OPER_HASH_LEFT : JOIN_OPER_NL_LEFT;
}

static inline void sql_convert_to_left_or_inner_join(sql_join_node_t *join_node, sql_join_assist_t *join_assist)
{
    if (join_node->type < JOIN_TYPE_LEFT) {
        return;
    }
    if (join_node->type == JOIN_TYPE_LEFT) {
        join_node->type = JOIN_TYPE_INNER;
        join_assist->outer_node_count--;
        join_node->oper = join_node->oper == JOIN_OPER_HASH_LEFT ? JOIN_OPER_HASH : JOIN_OPER_NL;
        return;
    }
    join_node->type = JOIN_TYPE_LEFT;
    join_node->oper = join_node->oper == JOIN_OPER_HASH_FULL ? JOIN_OPER_HASH_LEFT : JOIN_OPER_NL_LEFT;
    SWAP(sql_join_node_t *, join_node->left, join_node->right);
}

#define IF_LOCK_IN_FETCH(query) \
    ((query)->tables.count == 1 || (query)->connect_by_cond != NULL || (query)->incl_flags & (EXPR_INCL_ROWNUM))

#ifdef __cplusplus
}
#endif

#endif
