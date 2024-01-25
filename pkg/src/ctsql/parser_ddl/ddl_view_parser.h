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
 * ddl_view_parser.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser_ddl/ddl_view_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DDL_VIEW_PARSER_H__
#define __DDL_VIEW_PARSER_H__

#include "cm_defs.h"
#include "ctsql_stmt.h"
#include "cm_lex.h"
#include "ddl_parser.h"
#include "dml_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_parse_create_view(sql_stmt_t *stmt, bool32 is_replace, bool32 is_force);

status_t sql_parse_drop_view(sql_stmt_t *stmt);
#ifdef __cplusplus
}
#endif

#endif