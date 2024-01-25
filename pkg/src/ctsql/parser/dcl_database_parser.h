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
 * dcl_database_parser.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser/dcl_database_parser.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DCL_DB_PARSER_H__
#define __DCL_DB_PARSER_H__

#include "ctsql_stmt.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_parse_backup(sql_stmt_t *stmt);
status_t sql_parse_restore(sql_stmt_t *stmt);
status_t sql_parse_recover(sql_stmt_t *stmt);
status_t sql_parse_shutdown(sql_stmt_t *stmt);
status_t sql_parse_backup_tag(sql_stmt_t *stmt, word_t *word, char *tag);
status_t sql_parse_daac(sql_stmt_t *stmt);
#ifdef __cplusplus
}
#endif

#endif