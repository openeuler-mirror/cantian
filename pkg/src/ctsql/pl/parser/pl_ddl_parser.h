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
 * pl_ddl_parser.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/parser/pl_ddl_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_DDL_PARSER_H__
#define __PL_DDL_PARSER_H__

#include "ctsql_stmt.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t pl_parse_name(sql_stmt_t *stmt, word_t *word, var_udo_t *obj, bool32 need_single);
status_t pl_parse_create_trigger(sql_stmt_t *stmt, bool32 replace, word_t *word);
status_t pl_parse_create(sql_stmt_t *stmt, bool32 replace, word_t *word);
status_t pl_parse_drop_procedure(sql_stmt_t *stmt, word_t *word);
status_t pl_parse_drop_trigger(sql_stmt_t *stmt, word_t *word);
status_t pl_parse_drop_type(sql_stmt_t *stmt, word_t *word);
status_t pl_parse_drop_package(sql_stmt_t *stmt, word_t *word);
status_t plc_parse_trigger_desc_core(sql_stmt_t *stmt, word_t *word, bool32 is_upgrade);
status_t pl_parse_trigger_desc(sql_stmt_t *stmt, var_udo_t *obj, word_t *word);

#ifdef __cplusplus
}
#endif

#endif