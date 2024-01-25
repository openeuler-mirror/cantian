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
 * ctsql_sort.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_sort.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_SORT_H__
#define __SQL_SORT_H__

#include "dml_executor.h"

status_t sql_execute_query_sort(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan);
status_t sql_execute_select_sort(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan);
status_t sql_fetch_sort(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);
status_t sql_put_sort_row(sql_stmt_t *stmt, sql_cursor_t *cursor, bool32 *is_full);
status_t sql_sort_mtrl_open_segment(sql_stmt_t *stmt, sql_cursor_t *cursor, mtrl_segment_type_t sort_type,
    galist_t *cmp_items);
void sql_sort_mtrl_close_segment(sql_stmt_t *stmt, sql_cursor_t *cursor);
void sql_sort_mtrl_release_segment(sql_stmt_t *stmt, sql_cursor_t *cursor);
status_t sql_sort_mtrl_record_types(vmc_t *vmc, mtrl_segment_type_t sort_type, galist_t *cmp_items, char **buf);
status_t sql_mtrl_query_sort(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan);
status_t sql_execute_query_sibl_sort(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan);
status_t sql_fetch_sibl_sort(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);
status_t sql_fetch_sort_for_minus(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);
#endif