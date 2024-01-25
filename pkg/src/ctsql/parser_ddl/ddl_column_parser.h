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
 * ddl_column_parser.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser_ddl/ddl_column_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DDL_COLUMN_PARSER_H__
#define __DDL_COLUMN_PARSER_H__

#include "cm_defs.h"
#include "ctsql_stmt.h"
#include "cm_lex.h"
#include "ddl_parser.h"

#ifdef __cplusplus
extern "C" {
#endif
#define COLUMN_EX_NULLABLE 0x00000001
#define COLUMN_EX_KEY 0x00000002
#define COLUMN_EX_DEFAULT 0x00000004
#define COLUMN_EX_REF 0x00000008
#define COLUMN_EX_INL_CONSTR 0x00000010
#define COLUMN_EX_CHECK 0x00000020
#define COLUMN_EX_COMMENT 0x00000040
#define COLUMN_EX_UPDATE_DEFAULT 0x00000080
#define COLUMN_EX_AUTO_INCREMENT 0x00000100
#define COLUMN_EX_COLLATE 0x00000200
#define ALTAB_AUTO_INCREMENT_COLUMN 0x00000001

#define IS_CONSTRAINT_KEYWORD(id)                                                                                      \
    ((id) == KEY_WORD_CONSTRAINT || (id) == KEY_WORD_PRIMARY || (id) == KEY_WORD_UNIQUE || (id) == KEY_WORD_FOREIGN || \
        (id) == KEY_WORD_CHECK || (id) == KEY_WORD_PARTITION || (id) == KEY_WORD_LOGICAL)

#ifdef Z_SHARDING
#define SHARDING_NOT_SUPPORT_ERROR(loc, error_no, err_msg)       \
    do {                                                         \
        if (IS_COORDINATOR) {                                    \
            CT_SRC_THROW_ERROR_EX((loc), (error_no), (err_msg)); \
            return CT_ERROR;                                     \
        }                                                        \
    } while (0)
#endif

#ifdef Z_SHARDING
#define SHARDING_NOT_SUPPORT_ERROR_EX(loc, error_no, err_msg, text)      \
    do {                                                                 \
        if (IS_COORDINATOR) {                                            \
            CT_SRC_THROW_ERROR_EX((loc), (error_no), (err_msg), (text)); \
            return CT_ERROR;                                             \
        }                                                                \
    } while (0)
#endif

typedef enum en_add_column_type {
    CREATE_TABLE_ADD_COLUMN = 0,
    ALTER_TABLE_ADD_COLUMN = 1,
} def_column_action_t;

status_t sql_parse_lob_store(sql_stmt_t *stmt, lex_t *lex, word_t *word, galist_t *defs);
status_t sql_parse_modify_lob(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *tab_def);
status_t sql_parse_charset(sql_stmt_t *stmt, lex_t *lex, uint8 *charset);
status_t sql_parse_collate(sql_stmt_t *stmt, lex_t *lex, uint8 *collate);

status_t sql_verify_columns(sql_stmt_t *stmt, knl_table_def_t *def);
status_t sql_verify_column_default_expr(sql_verifier_t *verf, expr_tree_t *cast_expr, knl_column_def_t *def);
status_t sql_verify_auto_increment(sql_stmt_t *stmt, knl_table_def_t *def);
status_t sql_verify_array_columns(table_type_t type, galist_t *columns);
status_t sql_verify_cons_def(knl_table_def_t *def);
status_t sql_check_duplicate_column(galist_t *columns, const text_t *name);
status_t sql_create_inline_cons(sql_stmt_t *stmt, knl_table_def_t *def);
status_t sql_parse_column_property(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_altable_def_t *def, uint32 *flags);
status_t sql_delay_verify_default(sql_stmt_t *stmt, knl_table_def_t *def);
status_t sql_parse_altable_add_brackets_recurse(sql_stmt_t *stmt, lex_t *lex, bool32 enclosed, knl_altable_def_t *def);
status_t sql_parse_altable_modify_brackets_recurse(sql_stmt_t *stmt, lex_t *lex, bool32 enclosed,
    knl_altable_def_t *def);
status_t sql_parse_altable_column_rename(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def);
status_t sql_parse_column_defs(sql_stmt_t *stmt, lex_t *lex, knl_table_def_t *def, bool32 *expect_as);
status_t sql_check_duplicate_column_name(galist_t *columns, const text_t *name);

#ifdef __cplusplus
}
#endif

#endif