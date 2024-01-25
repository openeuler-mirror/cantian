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
 * ctsql_cond_rewrite.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/optimizer/ctsql_cond_rewrite.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_COND_REWRITE_H__
#define __SQL_COND_REWRITE_H__

#include "ctsql_stmt.h"
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

typedef enum en_collect_mode {
    DLVR_COLLECT_FV,
    DLVR_COLLECT_FF,
    DLVR_COLLECT_ALL,
} collect_mode_t;

typedef struct st_dlvr_pair {
    uint32 *col_map[CT_MAX_JOIN_TABLES];
    galist_t cols;
    galist_t values;
} dlvr_pair_t;

typedef struct st_push_assist {
    sql_query_t *p_query;
    uint32 ssa_count;
    select_node_type_t subslct_type;
    expr_node_t *ssa_nodes[CT_MAX_SUBSELECT_EXPRS];
    bool8 is_del[CT_MAX_SUBSELECT_EXPRS];
} push_assist_t;

#define DLVR_MAX_IN_COUNT 5
status_t sql_predicate_push_down(sql_stmt_t *stmt, sql_query_t *query);
status_t sql_process_predicate_dlvr(sql_stmt_t *stmt, sql_query_t *query, cond_tree_t *cond);
status_t sql_process_dlvr_join_tree_on(sql_stmt_t *stmt, sql_query_t *query, sql_join_node_t *join_tree);
status_t sql_process_oper_or_sink(sql_stmt_t *stmt, cond_node_t **cond);
status_t push_down_predicate(sql_stmt_t *stmt, cond_tree_t *cond, sql_table_t *table, select_node_t *slct,
    push_assist_t *push_assist);
status_t cond_rewrite_4_chg_order(sql_stmt_t *stmt, sql_query_t *query);
status_t replace_group_expr_node(sql_stmt_t *stmt, expr_node_t **node);
bool32 get_specified_level_query(sql_query_t *curr_query, uint32 level, sql_query_t **query, sql_select_t **subslct);
status_t sql_update_query_ssa(sql_query_t *query);
bool32 sql_can_expr_node_optm_by_hash(expr_node_t *node);
#ifdef __cplusplus
}
#endif

#endif