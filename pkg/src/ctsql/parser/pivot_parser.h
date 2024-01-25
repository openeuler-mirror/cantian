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
 * pivot_parser.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser/pivot_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PIVOT_PARSER_H__
#define __PIVOT_PARSER_H__

#include "ctsql_expr.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_create_pivot(sql_stmt_t *stmt, sql_query_t *query, word_t *word);
status_t sql_create_unpivot(sql_stmt_t *stmt, sql_query_t *query, word_t *word);
status_t sql_try_create_pivot_unpivot_table(sql_stmt_t *stmt, sql_table_t *query_table, word_t *word, bool32 *is_pivot);

#endif
