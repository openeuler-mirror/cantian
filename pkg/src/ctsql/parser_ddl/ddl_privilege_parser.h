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
 * ddl_privilege_parser.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser_ddl/ddl_privilege_parser.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DDL_PRIV_PARSER_H__
#define __DDL_PRIV_PARSER_H__

#include "cm_defs.h"
#include "ctsql_stmt.h"
#include "cm_lex.h"
#include "ddl_parser.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_program_type_def {
    PROGRAM_TYPE_FUNCTION,
    PROGRAM_TYPE_PROCEDURE,
    PROGRAM_TYPE_PACKAGE
} program_type_def;

typedef struct st_knl_program_unit_def {
    program_type_def prog_type; /* 0: function, 1: procedure, 2: package */
    text_t schema;              /* the program's owner */
    text_t prog_name;           /* the program's name */
} knl_program_unit_def;

/* check object type */
#define OBJ_IS_TABLE_TYPE(objtype) ((objtype) == OBJ_TYPE_TABLE)
#define OBJ_IS_VIEW_TYPE(objtype) ((objtype) == OBJ_TYPE_VIEW)
#define OBJ_IS_SEQUENCE_TYPE(objtype) ((objtype) == OBJ_TYPE_SEQUENCE)
#define OBJ_IS_PACKAGE_TYPE(objtype) ((objtype) == OBJ_TYPE_PACKAGE_SPEC)
#define OBJ_IS_TYPE_TYPE(objtype) ((objtype) == OBJ_TYPE_TYPE_SPEC)
#define OBJ_IS_PROCEDURE_TYPE(objtype) ((objtype) == OBJ_TYPE_PROCEDURE)
#define OBJ_IS_FUNCTION_TYPE(objtype) ((objtype) == OBJ_TYPE_FUNCTION)
#define OBJ_IS_DIRECTORY_TYPE(objtype) ((objtype) == OBJ_TYPE_DIRECTORY)
#define OBJ_IS_LIBRARY_TYPE(objtype) ((objtype) == OBJ_TYPE_LIBRARY)
#define OBJ_IS_TRIGGER_TYPE(objtype) ((objtype) == OBJ_TYPE_TRIGGER)
#define OBJ_IS_INVALID_TYPE(objtype) ((objtype) == OBJ_TYPE_INVALID)
#define OBJ_IS_USER_TYPE(objtype) ((objtype) == OBJ_TYPE_USER)

typedef struct st_priv_info {
    text_t priv_name;
    source_location_t start_loc;
} priv_info;

status_t sql_parse_grant_objprivs_def(sql_stmt_t *stmt, lex_t *lex, knl_grant_def_t *def);
status_t sql_parse_revoke_objprivs_def(sql_stmt_t *stmt, lex_t *lex, knl_revoke_def_t *def);
status_t sql_check_dir_priv(galist_t *privs, bool32 *dire_priv);
status_t sql_check_user_privileges(galist_t *privs);
status_t sql_parse_grant_privs(sql_stmt_t *stmt, knl_grant_def_t *def);
status_t sql_parse_revokee_def(sql_stmt_t *stmt, lex_t *lex, knl_revoke_def_t *revoke_def);
status_t sql_parse_grantee_def(sql_stmt_t *stmt, lex_t *lex, knl_grant_def_t *grant_def);
status_t sql_check_obj_owner(lex_t *lex, const text_t *curr_user, galist_t *holders);
status_t sql_check_obj_schema(lex_t *lex, text_t *schema, galist_t *holders);
status_t sql_check_privs_type(sql_stmt_t *stmt, galist_t *privs, priv_type_def priv_type, object_type_t obj_type,
                              text_t *type_name);
status_t sql_parse_revoke_privs(sql_stmt_t *stmt, knl_revoke_def_t *revoke_def);
#ifdef __cplusplus
}
#endif

#endif
