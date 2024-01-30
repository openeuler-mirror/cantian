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
 * ddl_constraint_parser.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser_ddl/ddl_constraint_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DDL_CONSTRAINT_PARSER_H__
#define __DDL_CONSTRAINT_PARSER_H__

#include "cm_defs.h"
#include "ctsql_stmt.h"
#include "cm_lex.h"
#include "ddl_column_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DDL_MAX_CONSTR_NAME_LEN 128

status_t sql_try_parse_if_not_exists(lex_t *lex, uint32 *options);

status_t sql_parse_references_clause(sql_stmt_t *stmt, lex_t *lex, text_t *ref_user, text_t *ref_table,
    knl_refactor_t *refactor, galist_t *ref_columns);
status_t sql_parse_primary_unique_cons(sql_stmt_t *stmt, lex_t *lex, constraint_type_t type,
                                       knl_constraint_def_t *cons_def);
status_t sql_parse_foreign_key(sql_stmt_t *stmt, lex_t *lex, knl_constraint_def_t *cons_def);
status_t sql_parse_add_check(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def, knl_constraint_def_t *cons_def);
status_t sql_parse_constraint(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def);
status_t sql_try_parse_cons(sql_stmt_t *stmt, lex_t *lex, knl_table_def_t *def, word_t *word, bool32 *result);
status_t sql_create_altable_inline_cons(sql_stmt_t *stmt, knl_column_def_t *column, knl_alt_column_prop_t *column_def);
status_t sql_parse_auto_primary_key_constr_name(sql_stmt_t *stmt, text_t *constr_name, text_t *sch_name,
    text_t *tab_name);
status_t sql_parse_inline_constraint(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word,
    uint32 *ex_flags);
status_t sql_parse_inline_constraint_elemt(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word,
    uint32 *ex_flags, text_t *cons_name);
status_t sql_parse_altable_constraint_rename(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def);
#ifdef __cplusplus
}
#endif

#endif
