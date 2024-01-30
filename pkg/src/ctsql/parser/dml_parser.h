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
 * dml_parser.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser/dml_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_DML_PARSER_H__
#define __SQL_DML_PARSER_H__

#include "cm_defs.h"
#include "ctsql_stmt.h"
#include "cm_lex.h"
#include "ctsql_expr.h"
#include "ctsql_cond.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SEL_QUERY_BLOCK_PREFIX "SEL$"
#define SEL_QUERY_BLOCK_PREFIX_LEN (uint32)4

/* by Liu Liang on XXXX.XX.XX */
#ifndef LIMIT_CLAUSE_OCCUR
#define LIMIT_CLAUSE_OCCUR(limit) ((limit)->count != NULL || (limit)->offset != NULL)
#endif

typedef enum en_sql_special_word {
    SQL_HAS_NONE = 0,
    SQL_HAS_LTT = 0x00000001,
    SQL_HAS_DBLINK = 0x00000002
} sql_special_word_t;

status_t sql_create_list(sql_stmt_t *stmt, galist_t **list);
status_t sql_parse_dml(sql_stmt_t *stmt, key_wid_t key_wid);
status_t sql_parse_view_subselect(sql_stmt_t *stmt, text_t *sql, sql_select_t **select_ctx, source_location_t *loc);
bool32 sql_has_ltt(sql_stmt_t *stmt, text_t *sql_text);
bool32 sql_check_ctx(sql_stmt_t *stmt, sql_context_t *ctx);
bool32 sql_check_procedures(sql_stmt_t *stmt, galist_t *dc_lst);
status_t sql_compile_synonym_by_user(sql_stmt_t *stmt, text_t *schema_name, bool32 compile_all);
status_t sql_compile_view_by_user(sql_stmt_t *stmt, text_t *schema_name, bool32 compile_all);
status_t sql_parse_dml_directly(sql_stmt_t *stmt, key_wid_t key_wid, sql_text_t *sql_text);
bool32 sql_compile_view_sql(sql_stmt_t *stmt, knl_dictionary_t *view_dc, text_t *owner);
bool32 sql_check_equal_join_cond(join_cond_t *join_cond);

#define CTSQL_SAVE_PARSER(stmt)                     \
    CTSQL_SAVE_STACK(stmt);                         \
    sql_context_t *__context__ = (stmt)->context; \
    void *__pl_context__ = (stmt)->pl_context;    \
    lang_type_t __lang_type__ = (stmt)->lang_type;

#define SQL_RESTORE_PARSER(stmt)                   \
    do {                                           \
        SET_STMT_CONTEXT(stmt, __context__);       \
        SET_STMT_PL_CONTEXT(stmt, __pl_context__); \
        (stmt)->lang_type = __lang_type__;         \
        CTSQL_RESTORE_STACK(stmt);                   \
    } while (0)

#ifdef Z_SHARDING
status_t shd_duplicate_origin_sql(sql_stmt_t *stmt, const text_t *origin_sql);
#endif

status_t sql_create_rowid_rs_column(sql_stmt_t *stmt, uint32 id, sql_table_type_t type, galist_t *list);

status_t sql_cache_context(sql_stmt_t *stmt, context_bucket_t *bucket, sql_text_t *sql, uint32 hash_value);
status_t sql_create_dml_currently(sql_stmt_t *stmt, sql_text_t *sql_text, key_wid_t key_wid);
void sql_prepare_context_ctrl(sql_stmt_t *stmt, uint32 hash_value, context_bucket_t *bucket);
void sql_parse_set_context_procinfo(sql_stmt_t *stmt);
uint32 sql_has_special_word(sql_stmt_t *stmt, text_t *sql_text);
#ifdef __cplusplus
}
#endif

#endif
