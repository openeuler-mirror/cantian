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
 * ctsql_select_parser.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser/ctsql_select_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_SELECT_PARSER_H__
#define __SQL_SELECT_PARSER_H__

#include "dml_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_try_parse_alias(sql_stmt_t *stmt, text_t *alias, word_t *word);
status_t sql_init_query(sql_stmt_t *stmt, sql_select_t *select_ctx, source_location_t loc, sql_query_t *sql_query);
status_t sql_parse_column(sql_stmt_t *stmt, galist_t *columns, word_t *word);
status_t sql_parse_order_by_items(sql_stmt_t *stmt, galist_t *sort_items, word_t *word);
status_t sql_parse_order_by(sql_stmt_t *stmt, sql_query_t *query, word_t *word);
status_t sql_verify_limit_offset(sql_stmt_t *stmt, limit_item_t *limit_item);
status_t sql_parse_limit_offset(sql_stmt_t *stmt, limit_item_t *limit_item, word_t *word);
status_t sql_init_join_assist(sql_stmt_t *stmt, sql_join_assist_t *join_ass);
status_t sql_parse_select_context(sql_stmt_t *stmt, select_type_t type, word_t *word, sql_select_t **select_ctx);
status_t sql_create_select_context(sql_stmt_t *stmt, sql_text_t *sql, select_type_t type, sql_select_t **select_ctx);
status_t sql_alloc_select_context(sql_stmt_t *stmt, select_type_t type, sql_select_t **select_ctx);
status_t sql_set_origin_query_block_name(sql_stmt_t *stmt, sql_query_t *query);

#endif