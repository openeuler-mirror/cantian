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
 * ddl_database_parser.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser_ddl/ddl_database_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DDL_DATABASE_PARSER_H__
#define __DDL_DATABASE_PARSER_H__

#include "ctsql_stmt.h"
#include "cm_lex.h"
#include "ddl_parser.h"
#include "ddl_space_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_CTRL_FILE_COUNT 3
#define DEFAULT_SYSTEM_SPACE_SIZE ((int64)(128 * 1048576))
#define DEFAULT_UNDO_SPACE_SIZE ((int64)(128 * 1048576))
#define DEFAULT_TEMP_SPACE_SIZE ((int64)(128 * 1048576))
#define DEFAULT_USER_SPACE_SIZE ((int64)(128 * 1048576))
#define DEFAULT_SYSAUX_SPACE_SIZE ((int64)(128 * 1048576))
#define DEFAULT_LOGFILE_SIZE ((int64)(64 * 1048576))
#define DEFAULT_AUTOEXTEND_SIZE ((int64)(16 * 1048576))

#define DB_MAX_NAME_LEN 32
#define SYSTEM_FILE_MIN_SIZE SIZE_M(80)

status_t sql_parse_create_database(sql_stmt_t *stmt, bool32 clustered);
status_t sql_create_database_lead(sql_stmt_t *stmt);
status_t sql_parse_alter_database_lead(sql_stmt_t *stmt);
status_t sql_parse_drop_tablespace(sql_stmt_t *stmt);
status_t sql_drop_database_lead(sql_stmt_t *stmt);
status_t sql_parse_password(sql_stmt_t *stmt, char *password, word_t *word);

status_t sql_parse_dbca_datafile_spec(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_space_def_t *space_def);
status_t sql_parse_dbca_logfiles(sql_stmt_t *stmt, galist_t *logfiles, word_t *word);

#ifdef __cplusplus
}
#endif

#endif
