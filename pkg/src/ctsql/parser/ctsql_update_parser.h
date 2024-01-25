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
 * ctsql_update_parser.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser/ctsql_update_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_UPDATE_PARSER_H__
#define __SQL_UPDATE_PARSER_H__

#include "dml_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_create_update_context(sql_stmt_t *stmt, sql_text_t *sql, sql_update_t **update_ctx);
status_t sql_init_update(sql_stmt_t *stmt, sql_update_t *update_ctx);
status_t sql_parse_update_pairs(sql_stmt_t *stmt, sql_update_t *update_ctx, word_t *word);
status_t sql_parse_return_columns(sql_stmt_t *stmt, galist_t **ret_columns, word_t *word);
status_t sql_parse_update_set(sql_stmt_t *stmt, sql_update_t *update_ctx, word_t *word);

#endif