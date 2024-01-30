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
 * ctsql_delete_parser.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser/ctsql_delete_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_DELETE_PARSER_H__
#define __SQL_DELETE_PARSER_H__

#include "dml_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_create_delete_context(sql_stmt_t *stmt, sql_text_t *sql, sql_delete_t **delete_ctx);

#endif