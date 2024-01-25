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
 * ctsql_merge_parser.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser/ctsql_merge_parser.c
 *
 * -------------------------------------------------------------------------
 */

#include "ctsql_merge_parser.h"
#include "ctsql_insert_parser.h"
#include "ctsql_update_parser.h"
#include "table_parser.h"
#include "ctsql_select_parser.h"
#include "cond_parser.h"
#include "hint_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t sql_init_merge(sql_stmt_t *stmt, sql_merge_t *merge_ctx)
{
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(sql_query_t), (void **)&merge_ctx->query));
    CT_RETURN_IFERR(sql_init_query(stmt, NULL, stmt->session->lex->loc, merge_ctx->query));
    CT_RETURN_IFERR(sql_copy_str(stmt->context, "MRG$1", &merge_ctx->query->block_info->origin_name));
    CT_RETURN_IFERR(sql_create_list(stmt, &merge_ctx->pl_dc_lst));

    merge_ctx->update_ctx = NULL;
    merge_ctx->insert_ctx = NULL;
    merge_ctx->plan = NULL;
    merge_ctx->hint_info = NULL;
    return CT_SUCCESS;
}

static status_t sql_parse_merge_update(sql_stmt_t *stmt, sql_merge_t *merge_ctx, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    if (lex_expected_fetch_word(lex, "UPDATE") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (merge_ctx->update_ctx != NULL) {
        CT_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "already have word 'UPDATE'");
        return CT_ERROR;
    }

    if (sql_alloc_mem(stmt->context, sizeof(sql_update_t), (void **)&merge_ctx->update_ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_init_update(stmt, merge_ctx->update_ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_array_put(&merge_ctx->update_ctx->query->tables, sql_array_get(&merge_ctx->query->tables, 0)) !=
        CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_fetch(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_parse_update_set(stmt, merge_ctx->update_ctx, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word->id == KEY_WORD_WHERE) {
        if (sql_create_cond_until(stmt, &merge_ctx->update_filter_cond, word) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_parse_merge_insert(sql_stmt_t *stmt, sql_merge_t *merge_ctx, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    bool32 result;

    if (lex_expected_fetch_word(lex, "INSERT") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (merge_ctx->insert_ctx != NULL) {
        CT_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "already have word 'INSERT'");
        return CT_ERROR;
    }

    if (sql_alloc_mem(stmt->context, sizeof(sql_insert_t), (void **)&merge_ctx->insert_ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_init_insert(stmt, merge_ctx->insert_ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }

    merge_ctx->insert_ctx->table = (sql_table_t *)sql_array_get(&merge_ctx->query->tables, 0);
    if (lex_try_fetch(lex, "VALUES", &result) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (result) {
        word->id = KEY_WORD_VALUES;
    } else {
        if (lex_fetch(lex, word) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (sql_try_parse_insert_columns(stmt, merge_ctx->insert_ctx, word) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (sql_parse_insert_values(stmt, merge_ctx->insert_ctx, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word->id == KEY_WORD_WHERE) {
        if (sql_create_cond_until(stmt, &merge_ctx->insert_filter_cond, word) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_parse_merge_when(sql_stmt_t *stmt, sql_merge_t *merge_ctx, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    bool32 result = CT_FALSE;

    if (word->id != KEY_WORD_WHEN) {
        CT_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "expect word 'WHEN'");
        return CT_ERROR;
    }

    if (lex_try_fetch(lex, "NOT", &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_word(lex, "MATCHED") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_word(lex, "THEN") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (result) {
        return sql_parse_merge_insert(stmt, merge_ctx, word);
    } else {
        return sql_parse_merge_update(stmt, merge_ctx, word);
    }
}

static status_t sql_parse_merge_on(sql_stmt_t *stmt, sql_merge_t *merge_ctx, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    bool32 is_expr = CT_FALSE;
    if (word->id != KEY_WORD_ON) {
        CT_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "expect word 'ON'");
        return CT_ERROR;
    }

    if (lex_expected_fetch_bracket(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    CT_RETURN_IFERR(SQL_SSA_PUSH(stmt, &merge_ctx->query->ssa));
    if (sql_create_cond_from_text(stmt, &word->text, &merge_ctx->query->cond, &is_expr) != CT_SUCCESS) {
        SQL_SSA_POP(stmt);
        return CT_ERROR;
    }
    SQL_SSA_POP(stmt);

    if (is_expr) {
        CT_SRC_THROW_ERROR(merge_ctx->query->cond->loc, ERR_SQL_SYNTAX_ERROR, "expect condition text");
        return CT_ERROR;
    }
    return lex_fetch(lex, word);
}

static status_t sql_parse_merge_using(sql_stmt_t *stmt, sql_merge_t *merge_ctx, word_t *word)
{
    sql_join_chain_t join_chain = { 0 };
    sql_table_t *merge_into_table = (sql_table_t *)sql_array_get(&merge_ctx->query->tables, 0);
    source_location_t loc = word->loc;

    if (word->id != KEY_WORD_USING) {
        CT_SRC_THROW_ERROR(loc, ERR_SQL_SYNTAX_ERROR, "expect word 'USING'");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_parse_comma_join(stmt, &merge_ctx->query->tables, &merge_ctx->query->join_assist, &join_chain,
        &merge_into_table, word));
    // using must be followed by a table or subquery, not a join. Therefore, the count of the table in merge_ctx->query
    // cannot be greater than 2.
    if (merge_ctx->query->tables.count > 2) {
        CT_SRC_THROW_ERROR(loc, ERR_SQL_SYNTAX_ERROR, "expect select query after 'USING'");
        return CT_ERROR;
    }
    CT_RETURN_IFERR(sql_form_table_join_with_opers(&join_chain, JOIN_TYPE_COMMA));
    merge_ctx->query->join_assist.join_node = join_chain.first;

    return CT_SUCCESS;
}

static status_t sql_parse_merge(sql_stmt_t *stmt, sql_merge_t *merge_ctx)
{
    word_t word;
    status_t status = CT_ERROR;
    sql_table_t *merge_into_table = NULL;
    lex_t *lex = stmt->session->lex;

    CT_RETURN_IFERR(sql_init_merge(stmt, merge_ctx));

    CT_RETURN_IFERR(SQL_NODE_PUSH(stmt, merge_ctx->query));

    CT_RETURN_IFERR(SQL_SSA_PUSH(stmt, &merge_ctx->query->ssa));

    do {
        CT_BREAK_IF_ERROR(lex_expected_fetch_word(lex, "INTO"));

        CT_BREAK_IF_ERROR(sql_array_new(&merge_ctx->query->tables, sizeof(sql_table_t), (void **)&merge_into_table));
        merge_into_table->id = merge_ctx->query->tables.count - 1;

        CT_BREAK_IF_ERROR(sql_parse_table(stmt, merge_into_table, &word));

        CT_BREAK_IF_ERROR(sql_parse_merge_using(stmt, merge_ctx, &word));

        CT_BREAK_IF_ERROR(sql_parse_merge_on(stmt, merge_ctx, &word));

        CT_BREAK_IF_ERROR(sql_parse_merge_when(stmt, merge_ctx, &word));

        if (word.type != WORD_TYPE_EOF) {
            CT_BREAK_IF_ERROR(sql_parse_merge_when(stmt, merge_ctx, &word));
        }
        if (word.type != WORD_TYPE_EOF) {
            CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "text end expected but %s found", W2S(&word));
            break;
        }
        status = CT_SUCCESS;
    } while (0);

    CT_RETURN_IFERR(sql_set_table_qb_name(stmt, merge_ctx->query));

    SQL_SSA_POP(stmt);
    SQL_NODE_POP(stmt);
    return status;
}

status_t sql_create_merge_context(sql_stmt_t *stmt, sql_text_t *sql, sql_merge_t **merge_ctx)
{
    /*
            MERGE INTO table
            USING{ table | (select query) }[alias]
            ON(condition)
            WHEN MATCHED THEN UPDATE SET col = expression[, ...]
            WHEN NOT MATCHED THEN INSERT(column[, ...]) VALUES(expression[, ...])
        */
    lex_t *lex = stmt->session->lex;

    if (sql_alloc_mem(stmt->context, sizeof(sql_merge_t), (void **)merge_ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_push(lex, sql) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_word(lex, "MERGE") != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    if (sql_parse_merge(stmt, *merge_ctx) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    lex_pop(lex);
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
