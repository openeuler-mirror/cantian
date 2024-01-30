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
 * ddl_user_parser.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser_ddl/ddl_user_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DDL_USER_PARSER_H__
#define __DDL_USER_PARSER_H__

#include "cm_defs.h"
#include "ctsql_stmt.h"
#include "cm_lex.h"
#include "ddl_parser.h"

#ifdef __cplusplus
extern "C" {
#endif
/* user update types */
#define DDL_USER_NULL 0
#define DDL_USER_PWD 1
#define DDL_USER_AUDIT 2
#define DDL_USER_READONLY 4
#define DDL_USER_STATUS 8
#define DDL_USER_FAILCOUNT 16
#define DDL_USER_PWD_EXPIRE 32
#define DDL_USER_ACCOUNT_LOCK 64
#define DDL_USER_PROFILE 128
#define DDL_USER_DEFALT_SPACE 256
#define DDL_USER_TMP_SPACE 512
#define DDL_USER_PERMANENT 1024

typedef status_t (*func_check_profile)(knl_profile_def_t *def, variant_t *value, lex_t *lex, uint32 id,
    dec8_t *unlimit);

typedef struct st_check_profile {
    func_check_profile func;
} check_profile_t;

status_t sql_parse_create_user(sql_stmt_t *stmt);
status_t sql_parse_drop_user(sql_stmt_t *stmt);
status_t sql_parse_alter_user(sql_stmt_t *stmt);
status_t sql_parse_create_role(sql_stmt_t *stmt);
status_t sql_parse_drop_role(sql_stmt_t *stmt);
status_t sql_parse_create_tenant(sql_stmt_t *stmt);
status_t sql_parse_create_profile(sql_stmt_t *stmt, bool32 is_replace);
status_t sql_parse_alter_profile(sql_stmt_t *stmt);
status_t sql_parse_drop_profile(sql_stmt_t *stmt);
status_t sql_parse_alter_tenant(sql_stmt_t *stmt);
status_t sql_parse_drop_tenant(sql_stmt_t *stmt);
#ifdef __cplusplus
}
#endif

#endif
