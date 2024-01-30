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
 * ctsql_transform.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/optimizer/ctsql_transform.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_TRANSFORM_H__
#define __SQL_TRANSFORM_H__

#include "ctsql_stmt.h"
#include "ctsql_expr.h"
#include "ctsql_cond.h"

/*
The Oracle optimizer is divided into three parts:
1, transformer
2, estimator
3, plan generator

This module implement the oracle-like transformer.

For some statements, the query transformer determines
whether it is advantageous to rewrite the original SQL statement
into a semantically equivalent SQL statement with a lower cost.

The query transformation includes:
1, OR Expansion
2, View Merging
3, Predicate Pushing
4, Subquery Unnesting
5, Query Rewrite with Materialized Views
6, Star Transformation
7, In-Memory Aggregation
8, Table Expansion
9, Join Factorization

Similar concept is implemented in PostgreSql. For example, in PG,
pulling up sub-link is equivalent to sub-query unnesting in Oracle.
*/
#ifdef __cplusplus
extern "C" {
#endif

// sql_select_t::parent_refs is initialized when select-context is created, it can not be null.
// parent_refs collect all columns that belong to parent (caution!! just parent's, no ancestor's)
#define IF_USE_PARENT_COLS(select_ctx) ((select_ctx)->parent_refs->count > 0)
#define SQL_IS_DUAL_TABLE(table) \
    ((table)->type == NORMAL_TABLE && (table)->entry->dc.oid == 10 && (table)->entry->dc.uid == 0)

typedef enum en_new_query_type {
    QUERY_TYPE_OR_EXPAND = 0,
    QUERY_TYPE_SUBQRY_TO_TAB,
    QUERY_TYPE_WINMAGIC,
    QUERY_TYPE_UPDATE_SET,
    QUERY_TYPE_SEMI_TO_INNER,
} new_query_type_t;

typedef struct st_new_qb_info {
    new_query_type_t type;
    text_t suffix;
} new_qb_info_t;

status_t sql_transform(sql_stmt_t *stmt);
status_t sql_transform_select(sql_stmt_t *stmt, select_node_t *node);
status_t phase_1_transform_query(sql_stmt_t *stmt, sql_query_t *query);
status_t phase_2_transform_query(sql_stmt_t *stmt, sql_query_t *query);
status_t try_chged_2_nest_loop(sql_stmt_t *stmt, sql_join_node_t *join_node);
status_t sql_retry_verify_subselect_table(sql_stmt_t *stmt, sql_select_t *sub_slct_ctx, sql_select_t **select_ctx);
status_t sql_get_table_join_cond(sql_stmt_t *stmt, sql_array_t *l_tables, sql_array_t *r_tables, cond_tree_t *cond,
    bilist_t *join_conds);
status_t sql_eliminate_outer_join(sql_stmt_t *stmt, sql_query_t *query);
void sql_erase_select_table_sorts(sql_stmt_t *stmt, sql_query_t *query);
status_t sql_preprocess_mix_join(sql_stmt_t *stmt, cond_tree_t *cond, sql_join_node_t *join_node,
    sql_join_assist_t *join_ass);
bool32 check_query_has_json_table(sql_query_t *query);

static inline bool32 if_query_has_mapped_table(sql_query_t *query)
{
    for (uint32 i = 0; i < query->tables.count; i++) {
        sql_table_t *table = (sql_table_t *)sql_array_get(&query->tables, i);
        if (table->type != NORMAL_TABLE) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

status_t create_new_table_4_rewrite(sql_stmt_t *stmt, sql_query_t *query, sql_select_t *subslct);
status_t generate_project_columns_shard(sql_stmt_t *stmt, sql_query_t *subqry, sql_table_t *table);
void sql_reset_ancestor_level(sql_select_t *select_ctx, uint32 temp_level);
status_t sql_set_new_query_block_name(sql_stmt_t *stmt, sql_query_t *query, new_query_type_t type);
status_t sql_set_old_query_block_name(sql_stmt_t *stmt, sql_query_t *query, new_query_type_t query_type);

#ifdef __cplusplus
}
#endif

#endif