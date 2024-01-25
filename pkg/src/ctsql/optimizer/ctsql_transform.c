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
 * ctsql_transform.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/optimizer/ctsql_transform.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_transform.h"
#include "ctsql_verifier.h"
#include "table_parser.h"
#include "ctsql_select_parser.h"
#include "ctsql_table_func.h"
#include "ctsql_func.h"
#include "srv_instance.h"
#include "ctsql_cond_rewrite.h"
#include "plan_rbo.h"
#include "plan_join.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef status_t (*sql_optimizer_func_t)(sql_stmt_t *stmt, sql_query_t *query);

typedef struct st_sql_optimizer {
    text_t name;
    sql_optimizer_func_t optimizer;
} sql_optimizer_t;

status_t create_new_table_4_rewrite(sql_stmt_t *stmt, sql_query_t *query, sql_select_t *subslct)
{
    sql_table_t *table = NULL;

    CT_RETURN_IFERR(sql_init_join_assist(stmt, &query->join_assist));
    CT_RETURN_IFERR(sql_create_array(stmt->context, &query->tables, "JOINS TABLES", CT_MAX_JOIN_TABLES));
    CT_RETURN_IFERR(sql_array_new(&query->tables, sizeof(sql_table_t), (void **)&table));
    table->id = 0;
    table->type = SUBSELECT_AS_TABLE;
    table->select_ctx = subslct;
    CT_RETURN_IFERR(sql_copy_text(stmt->context, &query->block_info->origin_name, &table->qb_name));
    TABLE_CBO_ATTR_OWNER(table) = query->vmc;
    cm_bilist_init(&table->func_expr);
    return CT_SUCCESS;
}

static inline status_t sql_add_sort_group(sql_query_t *query, sort_item_t *item)
{
    btree_sort_key_t *btree_sort_key = NULL;
    CT_RETURN_IFERR(cm_galist_new(query->sort_groups, sizeof(btree_sort_key_t), (void **)&btree_sort_key));
    btree_sort_key->group_id = VALUE_PTR(var_vm_col_t, &item->expr->root->value)->id;
    btree_sort_key->sort_mode = item->sort_mode;
    return CT_SUCCESS;
}

static inline bool32 chk_aggr_4_sort_group(sql_aggr_type_t aggr_type)
{
    const sql_aggr_type_t sg_aggrs[] = {
        AGGR_TYPE_AVG, AGGR_TYPE_SUM, AGGR_TYPE_MIN, AGGR_TYPE_MAX,
        AGGR_TYPE_COUNT, AGGR_TYPE_MEDIAN, AGGR_TYPE_DENSE_RANK
    };
    for (uint32 i = 0; i < ARRAY_NUM(sg_aggrs); ++i) {
        if (aggr_type == sg_aggrs[i]) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

static inline bool32 sql_is_grouping_func(expr_node_t *node)
{
    sql_func_t *func = NULL;
    if (node->type != EXPR_NODE_FUNC) {
        return CT_FALSE;
    }
    func = sql_get_func(&node->value.v_func);
    if (func->builtin_func_id == ID_FUNC_ITEM_GROUPING) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

bool32 check_query_has_json_table(sql_query_t *query)
{
    sql_table_t *table = NULL;

    for (uint32 i = 0; i < query->tables.count; i++) {
        table = (sql_table_t *)sql_array_get(&query->tables, i);
        if (table->type == JSON_TABLE) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

status_t sql_get_table_join_cond(sql_stmt_t *stmt, sql_array_t *l_tables, sql_array_t *r_tables, cond_tree_t *cond,
    bilist_t *join_conds)
{
    bool32 has_join_cond = CT_FALSE;
    join_cond_t *join_cond = NULL;
    sql_table_t *left_table = NULL;
    sql_table_t *right_table = NULL;
    cm_bilist_init(join_conds);

    if (cond == NULL) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_stack_alloc(stmt, sizeof(join_cond_t), (void **)&join_cond));
    cm_galist_init(&join_cond->cmp_nodes, stmt, sql_stack_alloc);

    for (uint32 i = 0; i < l_tables->count; i++) {
        for (uint32 j = 0; j < r_tables->count; j++) {
            left_table = (sql_table_t *)sql_array_get(l_tables, i);
            right_table = (sql_table_t *)sql_array_get(r_tables, j);
            if (l_tables == r_tables && left_table->id <= right_table->id) {
                continue;
            }
            has_join_cond = CT_FALSE;
            CT_RETURN_IFERR(sql_extract_join_from_cond(cond->root,
                                                       left_table->id, right_table->id, &join_cond->cmp_nodes,
                &has_join_cond));
            if (has_join_cond) {
                join_cond->table1 = left_table->id;
                join_cond->table2 = right_table->id;
                cm_bilist_add_tail(&join_cond->bilist_node, join_conds);
                CT_RETURN_IFERR(sql_stack_alloc(stmt, sizeof(join_cond_t), (void **)&join_cond));
                cm_galist_init(&join_cond->cmp_nodes, stmt, sql_stack_alloc);
            }
        }
    }
    return CT_SUCCESS;
}

static status_t sql_get_join_filter_cond(sql_stmt_t *stmt, cond_node_t *cond, sql_join_node_t *join_node,
    bool32 is_right_node, bool32 *not_null, bool32 is_outer_right)
{
    bool32 l_not_null = CT_FALSE;
    bool32 r_not_null = CT_FALSE;
    CT_RETURN_IFERR(sql_stack_safe(stmt));
    switch (cond->type) {
        case COND_NODE_AND:
            CT_RETURN_IFERR(
                sql_get_join_filter_cond(stmt, cond->left, join_node, is_right_node, &l_not_null, is_outer_right));
            CT_RETURN_IFERR(
                sql_get_join_filter_cond(stmt, cond->right, join_node, is_right_node, &r_not_null, is_outer_right));
            *not_null = (bool32)(l_not_null || r_not_null);
            try_eval_logic_and(cond);
            break;

        case COND_NODE_OR:
        case COND_NODE_COMPARE:
            if (!sql_chk_cond_degrade_join(cond, join_node, is_right_node, is_outer_right, not_null)) {
                return CT_SUCCESS;
            }

            *not_null = CT_TRUE;

            if (join_node->filter == NULL) {
                CT_RETURN_IFERR(sql_create_cond_tree(stmt->context, &join_node->filter));
            }
            CT_RETURN_IFERR(sql_merge_cond_tree_shallow(join_node->filter, cond));
            cond->type = COND_NODE_TRUE;
            break;

        default:
            break;
    }
    return CT_SUCCESS;
}

static status_t sql_process_mix_join_filter(sql_stmt_t *stmt, cond_tree_t *src, sql_join_node_t *join_node,
    sql_join_assist_t *join_ass, bool32 is_out_right)
{
    if (join_node->type == JOIN_TYPE_NONE) {
        return CT_SUCCESS;
    }

    bool32 l_not_null = CT_FALSE;
    bool32 r_not_null = CT_FALSE;
    bool32 l_is_out_right = join_node->type == JOIN_TYPE_FULL ? CT_TRUE : is_out_right;
    bool32 r_is_out_right = join_node->type >= JOIN_TYPE_LEFT ? CT_TRUE : is_out_right;

    if (src != NULL) {
        CT_RETURN_IFERR(sql_get_join_filter_cond(stmt, src->root, join_node, CT_FALSE, &l_not_null, l_is_out_right));

        CT_RETURN_IFERR(sql_get_join_filter_cond(stmt, src->root, join_node, CT_TRUE, &r_not_null, r_is_out_right));
    }

    if (l_not_null) {
        sql_convert_to_left_join(join_node);
    }

    if (r_not_null) {
        sql_convert_to_left_or_inner_join(join_node, join_ass);
    }

    if (join_node->type >= JOIN_TYPE_LEFT || join_node->join_cond == NULL) {
        return CT_SUCCESS;
    }

    if (join_node->filter == NULL) {
        CT_RETURN_IFERR(sql_create_cond_tree(stmt->context, &join_node->filter));
    }

    CT_RETURN_IFERR(sql_add_cond_node(join_node->filter, join_node->join_cond->root));
    join_node->join_cond = NULL;
    return CT_SUCCESS;
}

static status_t sql_preprocess_mix_join_cond(sql_stmt_t *stmt, galist_t *conds_list, sql_join_node_t *join_node,
    sql_join_assist_t *join_ass, bool32 is_out_right)
{
    if (join_node->type == JOIN_TYPE_NONE) {
        return CT_SUCCESS;
    }

    uint32 filter_pos = CT_INVALID_ID32;

    for (uint32 i = 0; i < conds_list->count; i++) {
        cond_tree_t *filter = (cond_tree_t *)cm_galist_get(conds_list, i);
        CT_RETURN_IFERR(sql_process_mix_join_filter(stmt, filter, join_node, join_ass, is_out_right));
    }

    if (join_node->type < JOIN_TYPE_LEFT && join_node->join_cond != NULL) {
        if (join_node->filter == NULL) {
            CT_RETURN_IFERR(sql_create_cond_tree(stmt->context, &join_node->filter));
        }
        CT_RETURN_IFERR(sql_add_cond_node(join_node->filter, join_node->join_cond->root));
        join_node->join_cond = NULL;
    }

    if (join_node->filter != NULL) {
        filter_pos = conds_list->count;
        CT_RETURN_IFERR(cm_galist_insert(conds_list, join_node->filter));
    }

    bool32 l_is_out_right = join_node->type == JOIN_TYPE_FULL ? CT_TRUE : is_out_right;
    bool32 r_is_out_right = join_node->type >= JOIN_TYPE_LEFT ? CT_TRUE : is_out_right;

    CT_RETURN_IFERR(sql_preprocess_mix_join_cond(stmt, conds_list, join_node->left, join_ass, l_is_out_right));
    CT_RETURN_IFERR(sql_preprocess_mix_join_cond(stmt, conds_list, join_node->right, join_ass, r_is_out_right));
    if (filter_pos != CT_INVALID_ID32) {
        cm_galist_delete(conds_list, filter_pos);
    }
    return CT_SUCCESS;
}

status_t sql_preprocess_mix_join(sql_stmt_t *stmt, cond_tree_t *cond, sql_join_node_t *join_node,
    sql_join_assist_t *join_ass)
{
    galist_t conds_list;
    cm_galist_init(&conds_list, stmt->session->stack, cm_stack_alloc);
    CTSQL_SAVE_STACK(stmt);
    if (cond != NULL && cond->root->type != COND_NODE_TRUE) {
        cm_galist_insert(&conds_list, cond);
    }
    if (sql_preprocess_mix_join_cond(stmt, &conds_list, join_node, join_ass, CT_FALSE) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    CTSQL_RESTORE_STACK(stmt);
    return CT_SUCCESS;
}

void sql_reset_ancestor_level(sql_select_t *select_ctx, uint32 temp_level)
{
    uint32 level = temp_level;
    sql_select_t *curr_ctx = select_ctx;

    while (level > 0 && curr_ctx != NULL) {
        RESET_ANCESTOR_LEVEL(curr_ctx, level);
        curr_ctx = (curr_ctx->parent != NULL) ? curr_ctx->parent->owner : NULL;
        level--;
    }
}

static new_qb_info_t g_qb_info_tab[] = {
    { QUERY_TYPE_OR_EXPAND, { (char *)"_ORE", 4 } },
    { QUERY_TYPE_SUBQRY_TO_TAB, { (char *)"_SQ", 3 } },
    { QUERY_TYPE_WINMAGIC, { (char *)"_WMR", 4 } },
    { QUERY_TYPE_UPDATE_SET, { (char *)"_UUS", 4 } },
    { QUERY_TYPE_SEMI_TO_INNER, { (char *)"_STI", 4 } },
};

status_t sql_set_new_query_block_name(sql_stmt_t *stmt, sql_query_t *query, new_query_type_t type)
{
    text_t suffix = g_qb_info_tab[type].suffix;
    char id_str[CT_MAX_INT32_STRLEN + 1] = { 0 };
    int32 len = snprintf_s(id_str, CT_MAX_INT32_STRLEN + 1, CT_MAX_INT32_STRLEN, PRINT_FMT_UINT32,
        query->block_info->origin_id);
    PRTS_RETURN_IFERR(len);
    text_t origin_id_text = {
        .str = id_str,
        .len = len
    };
    uint32 qb_name_buf = origin_id_text.len + suffix.len + SEL_QUERY_BLOCK_PREFIX_LEN;

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, qb_name_buf, (void **)&query->block_info->changed_name.str));
    CT_RETURN_IFERR(cm_concat_string(&query->block_info->changed_name, qb_name_buf, SEL_QUERY_BLOCK_PREFIX));
    cm_concat_text(&query->block_info->changed_name, qb_name_buf, &origin_id_text);
    cm_concat_text(&query->block_info->changed_name, qb_name_buf, &suffix);
    return CT_SUCCESS;
}

status_t sql_set_old_query_block_name(sql_stmt_t *stmt, sql_query_t *query, new_query_type_t query_type)
{
    text_t suffix = g_qb_info_tab[query_type].suffix;
    text_t changed_name = { 0 };
    uint32 qb_name_len;

    if (query->block_info->transformed) {
        qb_name_len = query->block_info->changed_name.len + suffix.len;
        CT_RETURN_IFERR(sql_push(stmt, qb_name_len, (void **)&changed_name.str));
        cm_concat_text(&changed_name, qb_name_len, &query->block_info->changed_name);
        cm_concat_text(&changed_name, qb_name_len, &suffix);
        CT_RETURN_IFERR(sql_copy_text(stmt->context, &changed_name, &query->block_info->changed_name));
        CTSQL_POP(stmt);
    } else {
        qb_name_len = query->block_info->origin_name.len + suffix.len;
        CT_RETURN_IFERR(sql_alloc_mem(stmt->context, qb_name_len, (void **)&query->block_info->changed_name.str));
        cm_concat_text(&query->block_info->changed_name, qb_name_len, &query->block_info->origin_name);
        cm_concat_text(&query->block_info->changed_name, qb_name_len, &suffix);
        query->block_info->transformed = CT_TRUE;
    }

    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
