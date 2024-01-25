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
 * ctsql_connect_rewrite.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/optimizer/ctsql_connect_rewrite.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_connect_rewrite.h"
#include "ctsql_transform.h"
#include "ctsql_plan.h"
#include "ctsql_select_parser.h"
#include "srv_instance.h"

status_t sql_generate_start_query(sql_stmt_t *stmt, sql_query_t *query)
{
    sql_query_t *s_query = NULL;
    sql_table_t *table = NULL;

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(sql_query_t), (void **)&s_query));
    CT_RETURN_IFERR(sql_init_query(stmt, query->owner, query->loc, s_query));

    /* clone join tables */
    CT_RETURN_IFERR(clone_tables_4_subqry(stmt, query, s_query));
    for (uint32 i = 0; i < s_query->tables.count; ++i) {
        table = (sql_table_t *)sql_array_get(&s_query->tables, i);
        table->plan_id = (query->tables.count > 1) ? CT_INVALID_ID32 : 0;
    }

    /* clone join assist */
    if (query->join_assist.join_node != NULL) {
        CT_RETURN_IFERR(sql_clone_join_root(stmt, stmt->context, query->join_assist.join_node,
            &s_query->join_assist.join_node, &s_query->tables, sql_alloc_mem));
    }
    s_query->join_assist.outer_node_count = query->join_assist.outer_node_count;
    s_query->cond = query->start_with_cond;
    s_query->is_s_query = CT_TRUE;
    s_query->cond_has_acstor_col = sql_cond_has_acstor_col(stmt, s_query->cond, s_query);
    query->s_query = s_query;
    return CT_SUCCESS;
}

static inline bool32 if_cmp_used_by_connect_mtrl(cols_used_t *l_cols_used, cols_used_t *r_cols_used)
{
    // make sure each side has not sub-query use parent and ancestor columns
    // this constraint can be broken when sub-query use only ancestor columns
    // or use the columns of same table that other columns used in the expr
    if (HAS_DYNAMIC_SUBSLCT(l_cols_used) || HAS_DYNAMIC_SUBSLCT(r_cols_used)) {
        return CT_FALSE;
    }

    // make sure left side has no cols and right side have only self columns, and belong to one table
    if (!HAS_NO_COLS(l_cols_used->flags) || !HAS_ONLY_SELF_COLS(r_cols_used->flags) ||
        HAS_DIFF_TABS(l_cols_used, SELF_IDX) || HAS_DIFF_TABS(r_cols_used, SELF_IDX)) {
        return CT_FALSE;
    }

    // make sure no ROWNUM expr node
    if (HAS_ROWNUM(l_cols_used) || HAS_ROWNUM(r_cols_used)) {
        return CT_FALSE;
    }
    return CT_TRUE;
}

static inline void clear_table_cbo_filter(sql_query_t *query)
{
    sql_table_t *table = NULL;
    query->join_root = NULL;
    for (uint32 i = 0; i < query->tables.count; ++i) {
        table = (sql_table_t *)sql_array_get(&query->tables, i);
        TABLE_CBO_FILTER(table) = NULL;
        TABLE_CBO_SAVE_TABLES(table) = NULL;
        TABLE_CBO_SUBGRP_TABLES(table) = NULL;
        TABLE_CBO_IDX_REF_COLS(table) = NULL;
        TABLE_CBO_FILTER_COLS(table) = NULL;
        TABLE_CBO_DRV_INFOS(table) = NULL;
        TABLE_CBO_IS_DEAL(table) = CT_FALSE;
        table->cost = (double)0;
    }
    query->filter_infos = NULL;
    vmc_free(query->vmc);
}

