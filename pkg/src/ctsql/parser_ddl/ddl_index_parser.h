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
 * ddl_index_parser.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser_ddl/ddl_index_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DDL_INDEX_PARSER_H__
#define __DDL_INDEX_PARSER_H__

#include "cm_defs.h"
#include "srv_instance.h"
#include "ctsql_stmt.h"
#include "cm_lex.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_index_column_def {
    text_t index_column_name;
    bool32 is_in_function_mode;
    bool32 is_in_expression_mode;
    char expression_operator;
    char *function_name;
} index_knl_column_def_t;

status_t sql_parse_using_index(sql_stmt_t *stmt, lex_t *lex, knl_constraint_def_t *cons_def);
status_t sql_parse_column_list(sql_stmt_t *stmt, lex_t *lex, galist_t *column_list, bool32 have_sort,
    bool32 *have_func);
status_t sql_parse_index_attrs(sql_stmt_t *stmt, lex_t *lex, knl_index_def_t *index_def);

status_t sql_parse_create_index(sql_stmt_t *stmt, bool32 is_unique);
status_t sql_parse_alter_index(sql_stmt_t *stmt);
status_t sql_parse_drop_index(sql_stmt_t *stmt);
status_t sql_parse_analyze_index(sql_stmt_t *stmt);
status_t sql_parse_purge_index(sql_stmt_t *stmt, knl_purge_def_t *def);
status_t sql_parse_create_indexes(sql_stmt_t *stmt);

#ifdef __cplusplus
}
#endif

#endif
