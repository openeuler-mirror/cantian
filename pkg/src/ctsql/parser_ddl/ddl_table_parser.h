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
 * ddl_table_parser.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser_ddl/ddl_table_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DDL_TABLE_PARSER_H__
#define __DDL_TABLE_PARSER_H__

#include "ctsql_stmt.h"
#include "cm_lex.h"
#include "ddl_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_SAMPLE_RATIO 100

status_t sql_parse_space(sql_stmt_t *stmt, lex_t *lex, word_t *word, text_t *space);
status_t sql_verify_check_constraint(sql_stmt_t *stmt, knl_table_def_t *def);
status_t sql_regist_ddl_table(sql_stmt_t *stmt, text_t *user, text_t *name);

status_t sql_parse_create_table(sql_stmt_t *stmt, bool32 is_temp, bool32 has_global);
status_t sql_parse_drop_table(sql_stmt_t *stmt, bool32 is_temp);
status_t sql_parse_alter_table(sql_stmt_t *stmt);
status_t sql_verify_alter_table(sql_stmt_t *stmt);
status_t sql_parse_analyze_table(sql_stmt_t *stmt);
status_t sql_parse_truncate_table(sql_stmt_t *stmt);
status_t sql_parse_flashback_table(sql_stmt_t *stmt);
status_t sql_parse_purge_table(sql_stmt_t *stmt, knl_purge_def_t *def);
status_t sql_parse_comment_table(sql_stmt_t *stmt, key_wid_t wid);
status_t sql_create_temporary_lead(sql_stmt_t *stmt);
status_t sql_parse_drop_temporary_lead(sql_stmt_t *stmt);
status_t sql_create_global_lead(sql_stmt_t *stmt);

#ifdef __cplusplus
}
#endif

#endif
