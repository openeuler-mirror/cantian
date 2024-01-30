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
 * ddl_parser.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser_ddl/ddl_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DDL_PARSER_H__
#define __DDL_PARSER_H__

#include "cm_defs.h"
#include "ctsql_stmt.h"
#include "ddl_sequence_parser.h"
#ifdef __cplusplus
extern "C" {
#endif


#define KNL_MAX_DEF_LEN 64
#define DDL_MIN_PWD_LEN 6
#define DDL_MIN_SYS_PWD_LEN 8
#define DDL_MAX_PWD_LEN 32
#define DDL_MAX_INT32_LEN 10 /* do not include sign */
#define DDL_MAX_INT64_LEN 19 /* do not include sign */
#define DDL_MAX_REAL_LEN 40
#define DDL_MAX_NUMERIC_LEN 38

#define DDL_USER_TABLE (DDL_USER_PWD | DDL_USER_AUDIT | DDL_USER_READONLY | DDL_USER_STATUS)

typedef struct st_seqence_info {
    bool32 start_flag;
    bool32 cache_flag;
    bool32 inc_flag;
    bool32 cyc_flag;
    bool32 nomin_flag;
    bool32 nomax_flag;
    bool32 nocache_flag;
    bool32 nocyc_flag;
} sql_seqence_info_t;

status_t sql_parse_ddl(sql_stmt_t *stmt, key_wid_t wid);
status_t sql_parse_drop(sql_stmt_t *sql_stmt);
status_t sql_parse_truncate(sql_stmt_t *stmt);
status_t sql_parse_flashback(sql_stmt_t *stmt);
status_t sql_parse_create(sql_stmt_t *stmt);
status_t sql_parse_create_directory(sql_stmt_t *stmt, bool32 is_replace);
status_t sql_parse_create_library(sql_stmt_t *stmt, bool32 is_replace);
status_t sql_parse_drop_library(sql_stmt_t *stmt);
status_t sql_parse_drop_table(sql_stmt_t *stmt, bool32 is_temp);
status_t sql_parse_drop_tablespace(sql_stmt_t *stmt);
status_t sql_parse_truncate_table(sql_stmt_t *stmt);
status_t sql_parse_flashback_table(sql_stmt_t *stmt);
status_t sql_parse_create_unique_lead(sql_stmt_t *stmt);
status_t sql_check_duplicate_column(galist_t *columns, const text_t *name);
status_t sql_verify_view_def(sql_stmt_t *stmt, knl_view_def_t *def, lex_t *lex, bool32 is_force);
status_t sql_verify_default_column(sql_stmt_t *stmt, knl_table_def_t *def);
status_t sql_verify_check_constraint(sql_stmt_t *stmt, knl_table_def_t *def);
status_t sql_verify_table_storage(sql_stmt_t *stmt, knl_table_def_t *def);
status_t sql_parse_column_defs(sql_stmt_t *stmt, lex_t *lex, knl_table_def_t *def, bool32 *expect_as);
status_t sql_convert_object_name(sql_stmt_t *stmt, word_t *word, text_t *owner, bool32 *owner_explict, text_t *name);
status_t sql_parse_drop_object(sql_stmt_t *stmt, knl_drop_def_t *def);
status_t sql_verify_array_columns(table_type_t type, galist_t *columns);
status_t sql_verify_auto_increment(sql_stmt_t *stmt, knl_table_def_t *def);
status_t sql_part_verify_key_type(typmode_t *typmod);
status_t sql_list_store_define_key(part_key_t *curr_key, knl_part_def_t *parent_part_def, knl_part_obj_def_t *obj_def,
    const text_t *part_name);
void sql_unregist_ddl_table(sql_stmt_t *stmt, const text_t *user, const text_t *name);
status_t sql_parse_scope_clause_inner(knl_alter_sys_def_t *def, lex_t *lex, bool32 force);
status_t sql_parse_expected_scope_clause(knl_alter_sys_def_t *def, lex_t *lex);
status_t sql_parse_scope_clause(knl_alter_sys_def_t *def, lex_t *lex);
status_t sql_parse_dc_info(sql_stmt_t *stmt, text_t *schema, text_t *objname, bool32 owner_explict,
                           object_type_t *obj_type, text_t *typename);
status_t sql_parse_sequence_info(sql_stmt_t *stmt, text_t *schema, text_t *objname, object_type_t *obj_type,
                                 text_t *typename);
status_t sql_parse_pl_info(sql_stmt_t *stmt, text_t *schema, text_t *objname, bool32 owner_explict,
                           object_type_t *obj_type, text_t *type_name);
status_t sql_parse_directory_info(sql_stmt_t *stmt, text_t *schema, object_type_t *obj_type, text_t *type_name);
status_t sql_parse_lib_info(sql_stmt_t *stmt, text_t *schema, text_t *objname, object_type_t *obj_type, text_t *typename);
status_t sql_check_object_type(sql_stmt_t *stmt, object_type_t *expected_objtype, text_t *type_name, text_t *schema,
                               text_t *objname);
status_t sql_parse_auto_primary_key_constr_name(sql_stmt_t *stmt, text_t *constr_name, text_t *sch_name,
    text_t *tab_name);
static inline status_t sql_replace_password(sql_stmt_t *stmt, text_t *password)
{
    if (stmt->pl_exec == NULL && stmt->pl_compiler == NULL) { // can't modify sql in pl
        if (password->len != 0) {
            MEMS_RETURN_IFERR(memset_s(password->str, password->len, '*', password->len));
        }
    }
    return CT_SUCCESS;
}

#define CHECK_CONS_TZ_TYPE_RETURN(col_type)                                                       \
    do {                                                                                          \
        if ((col_type) == CT_TYPE_TIMESTAMP_TZ) {                                                 \
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR,                                                  \
                "column of datatype TIMESTAMP WITH TIME ZONE cannot be unique or a primary key"); \
            return CT_ERROR;                                                                      \
        }                                                                                         \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif
