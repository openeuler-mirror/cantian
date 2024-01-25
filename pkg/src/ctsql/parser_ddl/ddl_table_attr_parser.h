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
 * ddl_table_attr_parser.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser_ddl/ddl_table_attr_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DDL_TABLE_ATTR_PARSER_H__
#define __DDL_TABLE_ATTR_PARSER_H__

#include "ctsql_stmt.h"
#include "cm_lex.h"

#ifdef __cplusplus
extern "C" {
#endif
#define TEMP_TBL_ATTR_PARSED 0x00000002
#define TBLOPTS_EX_AUTO_INCREMENT 0x00000001
#define DDL_MAX_COMMENT_LEN 4000

status_t sql_parse_init_auto_increment(sql_stmt_t *stmt, lex_t *lex, int64 *serial_start);
status_t sql_check_organization_column(knl_table_def_t *def);
status_t sql_parse_coalesce_partition(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def);
status_t sql_parse_check_auto_increment(sql_stmt_t *stmt, word_t *word, knl_altable_def_t *def);
status_t sql_parse_appendonly(lex_t *lex, word_t *word, bool32 *appendonly);
status_t sql_parse_organization(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_ext_def_t *def);
status_t sql_parse_table_attrs(sql_stmt_t *stmt, lex_t *lex, knl_table_def_t *table_def,
                               bool32 *expect_as, word_t *word);
status_t sql_parse_row_format(lex_t *lex, word_t *word, bool8 *csf);
status_t sql_parse_table_compress(sql_stmt_t *stmt, lex_t *lex, uint8 *type, uint8 *algo);

#ifdef __cplusplus
}
#endif

#endif
