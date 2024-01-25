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
 * ctsql_insert_parser.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser/ctsql_insert_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_INSERT_PARSER_H__
#define __SQL_INSERT_PARSER_H__

#include "dml_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_create_insert_context(sql_stmt_t *stmt, sql_text_t *sql, sql_insert_t **insert_context);
status_t sql_init_insert(sql_stmt_t *stmt, sql_insert_t *insert_context);
status_t sql_try_parse_insert_columns(sql_stmt_t *stmt, sql_insert_t *insert_context, word_t *word);
status_t sql_parse_insert_column_quote_info(word_t *word, column_value_pair_t *pair);
status_t sql_convert_insert_column(sql_stmt_t *stmt, sql_insert_t *insert_context, word_t *word, sql_text_t *column);
status_t sql_try_parse_insert_select(sql_stmt_t *stmt, sql_insert_t *insert_context, word_t *word, bool32 *result);
status_t sql_parse_insert_values(sql_stmt_t *stmt, sql_insert_t *insert_context, word_t *word);

#endif