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
 * ctsql_replace_parser.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser/ctsql_replace_parser.c
 *
 * -------------------------------------------------------------------------
 */

#include "ctsql_replace_parser.h"
#include "ctsql_insert_parser.h"
#include "hint_parser.h"
#include "expr_parser.h"
#include "table_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t sql_init_replace(sql_stmt_t *stmt, sql_replace_t *replace_context)
{
    if (sql_create_list(stmt, &replace_context->insert_ctx.pairs) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_create_list(stmt, &replace_context->insert_ctx.pl_dc_lst) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_create_array(stmt->context, &replace_context->insert_ctx.ssa, "SUB-SELECT", CT_MAX_SUBSELECT_EXPRS) !=
        CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_alloc_mem(stmt->context, sizeof(sql_table_t), (void **)&replace_context->insert_ctx.table) != CT_SUCCESS) {
        return CT_ERROR;
    }

    replace_context->insert_ctx.flags = INSERT_SET_NONE;
    replace_context->insert_ctx.select_ctx = NULL;
    replace_context->insert_ctx.plan = NULL;
    replace_context->insert_ctx.pairs_count = 0;
    replace_context->insert_ctx.hint_info = NULL;
    return CT_SUCCESS;
}

static status_t sql_parse_replace_set(sql_stmt_t *stmt, sql_replace_t *replace_context, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    column_value_pair_t *pair = NULL;
    expr_tree_t *expr = NULL;
    sql_insert_t *insert_ctx = &replace_context->insert_ctx;

    for (;;) {
        CT_RETURN_IFERR(lex_expected_fetch_variant(lex, word));
        CT_RETURN_IFERR(cm_galist_new(insert_ctx->pairs, sizeof(column_value_pair_t), (pointer_t *)&pair));
        CT_RETURN_IFERR(sql_create_list(stmt, &pair->exprs));

        CT_RETURN_IFERR(sql_parse_insert_column_quote_info(word, pair));
        CT_RETURN_IFERR(sql_convert_insert_column(stmt, insert_ctx, word, &pair->column_name));
        CT_RETURN_IFERR(lex_expected_fetch_word(lex, "="));

        CT_RETURN_IFERR(sql_create_expr_until(stmt, &expr, word));
        CT_RETURN_IFERR(cm_galist_insert(pair->exprs, expr));

        if (word->type == WORD_TYPE_EOF) {
            break;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            break;
        }
    }

    insert_ctx->pairs_count++;
    insert_ctx->flags |= INSERT_COLS_SPECIFIED;
    return CT_SUCCESS;
}

static status_t sql_parse_replace_clause(sql_stmt_t *stmt, sql_replace_t *replace_context, sql_insert_t *insert_ctx)
{
    word_t word;
    bool32 result = CT_FALSE;
    lex_t *lex = stmt->session->lex;

    CT_RETURN_IFERR(sql_parse_table(stmt, insert_ctx->table, &word));

    CT_RETURN_IFERR(sql_try_parse_insert_columns(stmt, insert_ctx, &word));

    CT_RETURN_IFERR(sql_try_parse_insert_select(stmt, insert_ctx, &word, &result));

    if (!result) {
        if (word.id == KEY_WORD_SET) {
            if (insert_ctx->pairs->count != 0) {
                CT_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "not supported to specify column in replace set");
                return CT_ERROR;
            }
            CT_RETURN_IFERR(sql_parse_replace_set(stmt, replace_context, &word));
        } else {
            CT_RETURN_IFERR(sql_parse_insert_values(stmt, insert_ctx, &word));
        }
    }

    if (word.type != WORD_TYPE_EOF) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "text end expected but %s found", W2S(&word));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_parse_replace(sql_stmt_t *stmt, sql_replace_t *replace_context)
{
    lex_t *lex = stmt->session->lex;
    bool32 result = CT_FALSE;
    status_t status;
    sql_insert_t *insert_ctx = &(replace_context->insert_ctx);
    CT_RETURN_IFERR(sql_init_replace(stmt, replace_context));

    CT_RETURN_IFERR(lex_try_fetch(lex, "INTO", &result));

    CT_RETURN_IFERR(SQL_SSA_PUSH(stmt, &insert_ctx->ssa));
    status = sql_parse_replace_clause(stmt, replace_context, insert_ctx);
    SQL_SSA_POP(stmt);
    return status;
}


status_t sql_create_replace_context(sql_stmt_t *stmt, sql_text_t *sql, sql_replace_t **replace_context)
{
    lex_t *lex = stmt->session->lex;

    if (sql_alloc_mem(stmt->context, sizeof(sql_replace_t), (void **)replace_context) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_push(lex, sql) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_word(lex, "REPLACE") != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    if (sql_parse_replace(stmt, *replace_context) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    lex_pop(lex);
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
