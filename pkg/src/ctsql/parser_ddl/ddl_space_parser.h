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
 * ddl_space_parser.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser_ddl/ddl_space_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DDL_SPACE_PARSER_H__
#define __DDL_SPACE_PARSER_H__

#include "cm_defs.h"
#include "ctsql_stmt.h"
#include "cm_lex.h"
#include "ddl_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_parse_datafile(sql_stmt_t *stmt, knl_device_def_t *dev_def, word_t *word, bool32 *isRelative);
status_t sql_parse_autoextend_clause_core(device_type_t type, sql_stmt_t *stmt, knl_autoextend_def_t *autoextend_def,
    word_t *next_word);

status_t sql_parse_create_space(sql_stmt_t *stmt, bool32 is_temp, bool32 is_undo);
status_t sql_parse_create_undo_space(sql_stmt_t *stmt);
status_t sql_parse_alter_space(sql_stmt_t *stmt);
status_t sql_parse_drop_tablespace(sql_stmt_t *stmt);
status_t sql_parse_purge_tablespace(sql_stmt_t *stmt, knl_purge_def_t *def);
status_t sql_parse_create_ctrlfiles(sql_stmt_t *stmt);
#ifdef __cplusplus
}
#endif

#endif
