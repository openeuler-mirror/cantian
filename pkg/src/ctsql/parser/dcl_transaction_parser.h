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
 * dcl_transaction_parser.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser/dcl_transaction_parser.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DCL_TRANS_PARSER_H__
#define __DCL_TRANS_PARSER_H__

#include "ctsql_stmt.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_parse_commit_phase1(sql_stmt_t *stmt);
status_t sql_parse_commit_phase2(sql_stmt_t *stmt, word_t *word);
status_t sql_parse_set(sql_stmt_t *stmt);
status_t sql_parse_commit(sql_stmt_t *stmt);
status_t sql_parse_rollback(sql_stmt_t *stmt);
status_t sql_parse_release_savepoint(sql_stmt_t *stmt);
status_t sql_parse_savepoint(sql_stmt_t *stmt);

#ifdef __cplusplus
}
#endif

#endif