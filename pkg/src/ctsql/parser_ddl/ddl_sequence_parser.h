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
 * ddl_sequence_parser.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser_ddl/ddl_sequence_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DDL_SEQUENCE_PARSER_H__
#define __DDL_SEQUENCE_PARSER_H__

#include "cm_defs.h"
#include "srv_instance.h"
#include "ctsql_stmt.h"
#include "cm_lex.h"

#ifdef __cplusplus
extern "C" {
#endif
/* default values for sequence parameters */
#define DDL_SEQUENCE_DEFAULT_INCREMENT 1
#define DDL_SEQUENCE_DEFAULT_CACHE 20
#define DDL_ASC_SEQUENCE_DEFAULT_MIN_VALUE 1
#define DDL_DESC_SEQUENCE_DEFAULT_MAX_VALUE ((int64)(-1))

#define DDL_ASC_SEQUENCE_DEFAULT_MAX_VALUE ((int64)CT_MAX_INT64)
#define DDL_DESC_SEQUENCE_DEFAULT_MIN_VALUE ((int64)CT_MIN_INT64)
#define DDL_SEQUENCE_MAX_CACHE ((int64)CT_MAX_INT64)

status_t sql_parse_create_sequence(sql_stmt_t *stmt);
status_t sql_parse_alter_sequence(sql_stmt_t *stmt);
status_t sql_parse_drop_sequence(sql_stmt_t *stmt);
status_t sql_parse_create_synonym(sql_stmt_t *stmt, uint32 flags);
status_t sql_parse_drop_synonym(sql_stmt_t *stmt, uint32 flags);
#ifdef __cplusplus
}
#endif

#endif