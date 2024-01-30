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
 * ddl_partition_parser.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser_ddl/ddl_partition_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DDL_PARTITION_PARSER_H__
#define __DDL_PARTITION_PARSER_H__

#include "cm_defs.h"
#include "ctsql_stmt.h"
#include "cm_lex.h"
#include "ddl_parser.h"


#ifdef __cplusplus
extern "C" {
#endif
status_t sql_parse_partition_attrs(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_part_def_t *def);
status_t sql_delay_verify_part_attrs(sql_stmt_t *stmt, knl_table_def_t *def, bool32 *expect_as, word_t *word);
status_t sql_parse_altable_set_clause(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_altable_def_t *def);

status_t sql_parse_add_partition(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def);
status_t sql_parse_modify_partition(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *tab_def);
status_t sql_part_parse_table(sql_stmt_t *stmt, word_t *word, bool32 *expect_as, knl_table_def_t *table_def);
status_t sql_parse_altable_partition(sql_stmt_t *stmt, word_t *word, knl_altable_def_t *def);
status_t sql_parse_split_partition(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def);
status_t sql_parse_purge_partition(sql_stmt_t *stmt, knl_purge_def_t *def);
status_t sql_parse_subpartition_attrs(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_part_def_t *part_def);

#ifdef __cplusplus
}
#endif

#endif