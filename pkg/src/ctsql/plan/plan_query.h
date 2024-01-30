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
 * plan_query.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/plan/plan_query.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PLAN_QUERY_H__
#define __PLAN_QUERY_H__

#include "ctsql_plan.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_extract_prior_cond_node(sql_stmt_t *stmt, cond_node_t *cond_node, cond_tree_t **dst_tree);
bool32 sql_sort_index_matched(sql_query_t *query, galist_t *sort_items, plan_node_t *next_plan);
bool32 if_parent_changes_rows_count(sql_query_t *query, uint32 *rownum_upper);
status_t get_limit_total_value(sql_stmt_t *stmt, sql_query_t *query, uint32 *rownum_upper);
status_t sql_create_mtrl_plan_rs_columns(sql_stmt_t *stmt, sql_query_t *query, galist_t **plan_rs_columns);
status_t sql_create_query_plan(sql_stmt_t *stmt, sql_query_t *query, sql_node_type_t type, plan_node_t **query_plan,
    plan_assist_t *parent);
cond_tree_t *sql_get_rownum_cond(sql_stmt_t *stmt, sql_query_t *query);

#ifdef __cplusplus
}
#endif

#endif