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
 * ctsql_join_verifier.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/verifier/ctsql_join_verifier.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_select_verifier.h"
#include "table_parser.h"

#ifdef __cplusplus
extern "C" {
#endif


void sql_join_set_default_oper(sql_join_node_t *node)
{
    if (node->oper != JOIN_OPER_NONE) {
        return;
    }

    switch (node->type) {
        case JOIN_TYPE_LEFT:
            node->oper = JOIN_OPER_NL_LEFT;
            break;
        case JOIN_TYPE_FULL:
            node->oper = JOIN_OPER_NL_FULL;
            break;
        default:
            node->oper = JOIN_OPER_NL;
            break;
    }
}

static status_t sql_verify_joins_cond(sql_verifier_t *verif, sql_join_node_t *node)
{
    sql_query_t *query = verif->curr_query;
    sql_join_node_t *tmp_node = NULL;
    sql_array_t *save_tables = verif->tables;
    uint32 save_flags = verif->excl_flags;
    CT_BIT_SET(verif->excl_flags, SQL_EXCL_JOIN);
    if (node->type == JOIN_TYPE_FULL && verif->select_ctx == NULL) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "multi delete/update not support full join");
        return CT_ERROR;
    }

    if (node->type == JOIN_TYPE_RIGHT) {
        tmp_node = node->left;
        node->left = node->right;
        node->right = tmp_node;
        node->type = JOIN_TYPE_LEFT;
    }

    if (node->type != JOIN_TYPE_NONE) {
        CT_RETURN_IFERR(sql_verify_joins_cond(verif, node->left));
        CT_RETURN_IFERR(sql_verify_joins_cond(verif, node->right));

        if (node->type != JOIN_TYPE_COMMA && node->type != JOIN_TYPE_CROSS) {
            verif->tables = &node->tables;
            CT_RETURN_IFERR(sql_verify_cond(verif, node->join_cond));
        }

        sql_join_set_default_oper(node);

        // all inner join, join cond add to where cond in verify stage
        // parent may use sub_select's cond when they have not transformed yet.
        if (query->join_assist.outer_node_count == 0) {
            if (node->join_cond == NULL) {
                verif->tables = save_tables;
                return CT_SUCCESS;
            }
            if (query->cond == NULL) {
                CT_RETURN_IFERR(sql_create_cond_tree(verif->context, &query->cond));
            }
            CT_RETURN_IFERR(sql_add_cond_node(query->cond, node->join_cond->root));
            if (node->join_cond->incl_flags & SQL_INCL_ROWNUM) {
                query->cond->incl_flags |= SQL_INCL_ROWNUM;
            }
            node->join_cond = NULL;
        }
    }
    verif->tables = save_tables;
    verif->excl_flags = save_flags;
    return CT_SUCCESS;
}

static void sql_remove_join_node(sql_join_node_t *join_node)
{
    join_node->prev->next = join_node->next;
    if (join_node->next != NULL) {
        join_node->next->prev = join_node->prev;
    }
}

static inline void sql_add_join_node(sql_join_node_t *node_comma, sql_join_node_t *join_node)
{
    join_node->next = node_comma->next;
    if (node_comma->next != NULL) {
        node_comma->next->prev = join_node;
    }
    node_comma->next = join_node;
    join_node->prev = node_comma;
}

static status_t sql_verify_join_comma(sql_join_node_t *join_node_root, sql_join_node_t *join_node)
{
    if (join_node->type == JOIN_TYPE_NONE) {
        return CT_SUCCESS;
    }

    if (join_node->type != JOIN_TYPE_COMMA) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "the 'join' keyword is not allowed when exist '(+)'");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_verify_join_comma(join_node_root, join_node->left));
    CT_RETURN_IFERR(sql_verify_join_comma(join_node_root, join_node->right));
    join_node->left = NULL;
    join_node->right = NULL;

    return CT_SUCCESS;
}

static status_t sql_add_cmp_to_join_node(sql_stmt_t *stmt, sql_join_node_t *join_node,
    join_symbol_cmp_t *join_symbol_cmp)
{
    cond_node_t *cond_node = NULL;

    join_node->type = JOIN_TYPE_LEFT;

    if (join_node->join_cond == NULL) {
        CT_RETURN_IFERR(sql_create_cond_tree(stmt->context, &join_node->join_cond));
    }

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&cond_node));
    cond_node->cmp = join_symbol_cmp->cmp_node;
    cond_node->type = COND_NODE_COMPARE;
    return sql_add_cond_node(join_node->join_cond, cond_node);
}

static sql_table_t *sql_find_table(sql_array_t *tables, uint32 table_id)
{
    for (uint32 i = 0; i < tables->count; ++i) {
        sql_table_t *table = (sql_table_t *)sql_array_get(tables, i);
        if (table->id == table_id) {
            return table;
        }
    }

    return NULL;
}

static status_t sql_generate_outerjoin_node(sql_stmt_t *stmt, sql_array_t *tables, sql_join_node_t *node_root,
    join_symbol_cmp_t *join_symbol_cmp)
{
    uint32 left_table = join_symbol_cmp->left_tab;
    uint32 right_table = join_symbol_cmp->right_tab;
    sql_join_node_t *join_node = node_root->next;
    sql_join_node_t *join_node_pre = node_root;
    sql_join_node_t *left_tab_join_node = NULL;
    sql_join_node_t *right_tab_join_node = NULL;
    sql_table_t *table = NULL;

    while (join_node != NULL) {
        table = TABLE_OF_JOIN_LEAF(join_node);
        if (table->id == right_table) {
            right_tab_join_node = join_node;
            join_node = join_node->next;
            break;
        } else if (table->id == left_table) {
            left_tab_join_node = join_node;
        }
        join_node_pre = join_node;
        join_node = join_node->next;
    }

    if (right_tab_join_node == NULL) {
        table = sql_find_table(tables, right_table);
        CT_RETURN_IFERR(sql_create_join_node(stmt, JOIN_TYPE_LEFT, table, NULL, NULL, NULL, &right_tab_join_node));
        sql_add_join_node(join_node_pre, right_tab_join_node);
    }

    CT_RETURN_IFERR(sql_add_cmp_to_join_node(stmt, right_tab_join_node, join_symbol_cmp));

    CT_RETSUC_IFTRUE(left_tab_join_node != NULL);

    while (join_node != NULL) {
        table = TABLE_OF_JOIN_LEAF(join_node);
        if (table->id == left_table) {
            left_tab_join_node = join_node;
            break;
        }
        join_node = join_node->next;
    }

    if (left_tab_join_node == NULL) {
        table = sql_find_table(tables, left_table);
        CT_RETURN_IFERR(sql_create_join_node(stmt, JOIN_TYPE_NONE, table, NULL, NULL, NULL, &left_tab_join_node));
    } else {
        if (left_tab_join_node->type != JOIN_TYPE_NONE) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "failed to generate join tree when using '(+)'");
            return CT_ERROR;
        }
        sql_remove_join_node(left_tab_join_node);
    }

    // Add left_tab_join_node before right_tab_join_node
    sql_add_join_node(right_tab_join_node->prev, left_tab_join_node);

    return CT_SUCCESS;
}

static status_t sql_generate_join_tree_by_remain_tab(sql_stmt_t *stmt, sql_array_t *tables,
    sql_join_node_t *join_node_root, sql_join_node_t **res_join_node_root)
{
    sql_join_node_t *join_node = NULL;
    sql_join_node_t *right_join_node = NULL;
    bool32 is_found = CT_FALSE;

    *res_join_node_root = NULL;
    for (uint32 i = 0; i < tables->count; ++i) {
        sql_table_t *table1 = (sql_table_t *)sql_array_get(tables, i);

        is_found = CT_FALSE;
        join_node = join_node_root->next;
        while (join_node != NULL) {
            sql_table_t *table2 = TABLE_OF_JOIN_LEAF(join_node);
            if (table1->id == table2->id) {
                is_found = CT_TRUE;
                break;
            }
            join_node = join_node->next;
        }

        if (is_found) {
            continue;
        }

        CT_RETURN_IFERR(sql_create_join_node(stmt, JOIN_TYPE_NONE, table1, NULL, NULL, NULL, &right_join_node));

        if (*res_join_node_root == NULL) {
            *res_join_node_root = right_join_node;
        } else {
            CT_RETURN_IFERR(sql_create_join_node(stmt, JOIN_TYPE_COMMA, NULL, NULL, *res_join_node_root,
                right_join_node, res_join_node_root));
            (*res_join_node_root)->oper = JOIN_OPER_NL;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_rebuild_join_tree(sql_stmt_t *stmt, sql_array_t *tables, sql_join_node_t *join_node_root,
    sql_join_node_t **res_join_node_root, uint32 *left_join_count)
{
    sql_join_node_t *new_join_node = NULL;
    sql_join_node_t *join_node = NULL;
    sql_join_type_t join_type;
    cond_tree_t *cond = NULL;

    CT_RETURN_IFERR(sql_generate_join_tree_by_remain_tab(stmt, tables, join_node_root, &new_join_node));

    if (new_join_node == NULL) {
        new_join_node = join_node_root->next;
        if (new_join_node->type == JOIN_TYPE_LEFT) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "failed to generate join tree when using '(+)'");
            return CT_ERROR;
        }
        join_node = new_join_node->next;
    } else {
        join_node = join_node_root->next;
    }

    while (join_node != NULL) {
        join_type = join_node->type;
        cond = join_node->join_cond;
        join_node->type = JOIN_TYPE_NONE;
        join_node->join_cond = NULL;

        if (join_type == JOIN_TYPE_LEFT) {
            (*left_join_count)++;
        } else {
            join_type = JOIN_TYPE_COMMA;
        }

        CT_RETURN_IFERR(sql_create_join_node(stmt, join_type, NULL, cond, new_join_node, join_node, &new_join_node));
        sql_join_set_default_oper(new_join_node);

        join_node = join_node->next;
    }

    *res_join_node_root = new_join_node;
    return CT_SUCCESS;
}

static status_t sql_add_cmp_to_cond_tree(sql_stmt_t *stmt, sql_query_t *query, cmp_node_t *cmp_node)
{
    cond_node_t *cond_node = NULL;
    cond_tree_t **dst_tree = (query->connect_by_cond != NULL) ? &query->filter_cond : &query->cond;

    if (*dst_tree == NULL) {
        CT_RETURN_IFERR(sql_create_cond_tree(stmt->context, dst_tree));
    }
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&cond_node));
    cond_node->type = COND_NODE_COMPARE;
    cond_node->cmp = cmp_node;
    cmp_node->join_type = JOIN_TYPE_NONE;
    return sql_add_cond_node(*dst_tree, cond_node);
}

static status_t sql_join_symbol_cmp_sort(const void *str1, const void *str2, int32 *result)
{
    join_symbol_cmp_t *join_symbol_cmp1 = (join_symbol_cmp_t *)str1;
    join_symbol_cmp_t *join_symbol_cmp2 = (join_symbol_cmp_t *)str2;
    cmp_node_t *cmp_node1 = join_symbol_cmp1->cmp_node;
    cmp_node_t *cmp_node2 = join_symbol_cmp2->cmp_node;
    cols_used_t used_col1, used_col2;

    init_cols_used(&used_col1);
    init_cols_used(&used_col2);
    sql_collect_cols_in_expr_tree(cmp_node1->left, &used_col1);
    sql_collect_cols_in_expr_tree(cmp_node1->right, &used_col1);
    sql_collect_cols_in_expr_tree(cmp_node2->left, &used_col2);
    sql_collect_cols_in_expr_tree(cmp_node2->right, &used_col2);

    if (!HAS_DIFF_TABS(&used_col1, SELF_IDX) && HAS_DIFF_TABS(&used_col2, SELF_IDX)) {
        *result = 1;
    } else {
        *result = 0;
    }

    return CT_SUCCESS;
}

static status_t sql_add_join_symbol_cmp_to_cond(sql_stmt_t *stmt, sql_query_t *query, sql_join_node_t *join_node_root,
    join_symbol_cmp_t *join_symbol_cmp)
{
    sql_join_node_t *join_node = join_node_root->next;
    sql_table_t *table = NULL;
    uint32 right_table = join_symbol_cmp->right_tab;
    bool32 json_table_drive = CT_FALSE;

    if (join_symbol_cmp->left_tab != CT_INVALID_ID32) {
        sql_table_t *l_table = (sql_table_t *)sql_array_get(&query->tables, join_symbol_cmp->left_tab);
        if ((l_table->type == JSON_TABLE) && l_table->json_table_info->depend_table_count > 0) {
            json_table_drive = CT_TRUE;
        }
    }

    if (join_node == NULL || right_table == CT_INVALID_ID32 || json_table_drive) {
        return sql_add_cmp_to_cond_tree(stmt, query, join_symbol_cmp->cmp_node);
    }

    while (join_node != NULL) {
        table = TABLE_OF_JOIN_LEAF(join_node);
        if (table->id == right_table && join_node->type == JOIN_TYPE_LEFT) {
            return sql_add_cmp_to_join_node(stmt, join_node, join_symbol_cmp);
        }
        join_node = join_node->next;
    }

    return sql_add_cmp_to_cond_tree(stmt, query, join_symbol_cmp->cmp_node);
}

static status_t sql_generate_join_relation(sql_stmt_t *stmt, sql_query_t *query)
{
    sql_table_t *left_table = NULL;
    galist_t *join_symbol_cmps = query->join_symbol_cmps;
    sql_join_assist_t *join_assist = &query->join_assist;
    sql_join_node_t join_node_root;
    join_node_root.next = NULL;

    CT_RETURN_IFERR(sql_verify_join_comma(join_assist->join_node, join_assist->join_node));
    CT_RETURN_IFERR(cm_galist_sort(join_symbol_cmps, sql_join_symbol_cmp_sort));
    for (uint32 i = 0; i < join_symbol_cmps->count; ++i) {
        join_symbol_cmp_t *join_symbol_cmp = (join_symbol_cmp_t *)cm_galist_get(join_symbol_cmps, i);
        if (join_symbol_cmp->left_tab != CT_INVALID_ID32 && join_symbol_cmp->right_tab != CT_INVALID_ID32) {
            left_table = (sql_table_t *)sql_array_get(&query->tables, join_symbol_cmp->left_tab);
            if ((left_table->type != JSON_TABLE) || left_table->json_table_info->depend_table_count == 0) {
                CT_RETURN_IFERR(sql_generate_outerjoin_node(stmt, &query->tables, &join_node_root, join_symbol_cmp));
                continue;
            }
        }
        CT_RETURN_IFERR(sql_add_join_symbol_cmp_to_cond(stmt, query, &join_node_root, join_symbol_cmp));
    }

    return sql_rebuild_join_tree(stmt, &query->tables, &join_node_root, &join_assist->join_node,
        &join_assist->outer_node_count);
}

static status_t sql_verify_joins(sql_verifier_t *verif, sql_query_t *query)
{
    sql_join_assist_t *join_assist = &query->join_assist;

    if (join_assist->join_node == NULL) {
        return CT_SUCCESS;
    }

    if (query->join_symbol_cmps->count > 0) {
        return sql_generate_join_relation(verif->stmt, query);
    }

    return sql_verify_joins_cond(verif, join_assist->join_node);
}

status_t sql_verify_query_joins(sql_verifier_t *verif, sql_query_t *query)
{
    verif->curr_query = query;
    verif->excl_flags = SQL_WHERE_EXCL | SQL_EXCL_CONNECTBY_ATTR | SQL_EXCL_LEVEL;

    return sql_verify_joins(verif, query);
}

#ifdef __cplusplus
}
#endif