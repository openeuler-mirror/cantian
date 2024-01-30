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
 * ctsql_delete_parser.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser/ctsql_delete_parser.c
 *
 * -------------------------------------------------------------------------
 */

#include "ctsql_delete_parser.h"
#include "srv_instance.h"
#include "table_parser.h"
#include "ctsql_select_parser.h"
#include "hint_parser.h"
#include "cond_parser.h"
#include "ctsql_update_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t sql_init_delete(sql_stmt_t *stmt, sql_delete_t *delete_ctx)
{
    CT_RETURN_IFERR(sql_create_list(stmt, &delete_ctx->objects));
    CT_RETURN_IFERR(sql_create_list(stmt, &delete_ctx->pl_dc_lst));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(sql_query_t), (void **)&delete_ctx->query));
    CT_RETURN_IFERR(sql_init_query(stmt, NULL, stmt->session->lex->loc, delete_ctx->query));
    CT_RETURN_IFERR(sql_copy_str(stmt->context, "DEL$1", &delete_ctx->query->block_info->origin_name));
    delete_ctx->plan = NULL;
    delete_ctx->ret_columns = NULL;
    delete_ctx->hint_info = NULL;
    return CT_SUCCESS;
}

static status_t sql_parse_del_object(sql_stmt_t *stmt, sql_delete_t *delete_ctx, word_t *word)
{
    del_object_t *curr_obj = NULL;
    del_object_t *prev_obj = NULL;
    lex_t *lex = stmt->session->lex;
    uint32 save_flags = lex->flags;
    key_word_t *save_key_words = lex->key_words;
    uint32 save_key_word_count = lex->key_word_count;
    key_word_t key_words[] = { { (uint32)KEY_WORD_RETURNING, CT_FALSE, { (char *)"returning", 9 } } };

    CT_RETURN_IFERR(lex_expected_fetch_variant(lex, word));
    CT_RETURN_IFERR(cm_galist_new(delete_ctx->objects, sizeof(del_object_t), (void **)&curr_obj));
    CT_RETURN_IFERR(sql_decode_object_name(stmt, word, &curr_obj->user, &curr_obj->name));

    lex->flags = LEX_SINGLE_WORD;
    lex->key_words = key_words;
    lex->key_word_count = ELEMENT_COUNT(key_words);

    if (lex_fetch(lex, word) != CT_SUCCESS) {
        lex->key_words = save_key_words;
        lex->key_word_count = save_key_word_count;
        return CT_ERROR;
    }

    if (sql_try_parse_table_alias(stmt, &curr_obj->alias, word) != CT_SUCCESS) {
        lex->key_words = save_key_words;
        lex->key_word_count = save_key_word_count;
        return CT_ERROR;
    }

    for (uint32 i = 0; i < delete_ctx->objects->count - 1; i++) {
        prev_obj = (del_object_t *)cm_galist_get(delete_ctx->objects, i);
        if (cm_text_equal((text_t *)&prev_obj->user, (text_t *)&curr_obj->user) &&
            cm_text_equal((text_t *)&prev_obj->name, (text_t *)&curr_obj->name)) {
            CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicated object %s found", W2S(word));
            lex->key_words = save_key_words;
            lex->key_word_count = save_key_word_count;
            return CT_ERROR;
        }
    }
    lex->flags = save_flags;
    lex->key_words = save_key_words;
    lex->key_word_count = save_key_word_count;

    return CT_SUCCESS;
}

static status_t sql_parse_del_objects(sql_stmt_t *stmt, sql_delete_t *delete_ctx, word_t *word)
{
    for (;;) {
        CT_RETURN_IFERR(sql_parse_del_object(stmt, delete_ctx, word));

        if (!IS_SPEC_CHAR(word, ',')) {
            break;
        }
    }
    return CT_SUCCESS;
}

static status_t sql_parse_convert_del_table(sql_stmt_t *stmt, sql_delete_t *delete_ctx)
{
    sql_table_t *table = NULL;
    del_object_t *del_obj = (del_object_t *)cm_galist_get(delete_ctx->objects, 0);

    CT_RETURN_IFERR(sql_array_new(&delete_ctx->query->tables, sizeof(sql_table_t), (void **)&table));
    table->user = del_obj->user;
    table->name = del_obj->name;

    if (del_obj->alias.len > 0) {
        table->alias = del_obj->alias;
        del_obj->name = del_obj->alias;
    }

    if (sql_regist_table(stmt, table) != CT_SUCCESS) {
        cm_set_error_loc(table->name.loc);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_parse_delete_tables(sql_stmt_t *stmt, sql_delete_t *delete_ctx, word_t *word)
{
    bool32 result = CT_FALSE;
    lex_t *lex = stmt->session->lex;

    do {
        CT_RETURN_IFERR(lex_try_fetch(lex, "FROM", &result));

        CT_RETURN_IFERR(sql_parse_del_objects(stmt, delete_ctx, word));

#ifdef Z_SHARDING
        if (IS_COORDINATOR) {
            if (delete_ctx->objects->count > 1) {
                CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "multi delete");
                return CT_ERROR;
            }
            CT_RETURN_IFERR(sql_parse_convert_del_table(stmt, delete_ctx));
            break;
        }
#endif
        if (result) {
            if (word->id == KEY_WORD_USING) {
                CT_RETURN_IFERR(sql_parse_join_entry(stmt, delete_ctx->query, word));
                break;
            }
            if (delete_ctx->objects->count > 1) {
                CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, " USING expected but %s found", W2S(word));
                return CT_ERROR;
            }
            CT_RETURN_IFERR(sql_parse_convert_del_table(stmt, delete_ctx));
            break;
        }
        if (word->id == KEY_WORD_FROM) {
            CT_RETURN_IFERR(sql_parse_join_entry(stmt, delete_ctx->query, word));
            break;
        }
        if (delete_ctx->objects->count > 1) {
            CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, " FROM expected but %s found", W2S(word));
            return CT_ERROR;
        }
        CT_RETURN_IFERR(sql_parse_convert_del_table(stmt, delete_ctx));
    } while (CT_FALSE);

    lex->flags = LEX_WITH_OWNER | LEX_WITH_ARG;
    return CT_SUCCESS;
}

static status_t sql_parse_delete(sql_stmt_t *stmt, sql_delete_t *delete_ctx)
{
    word_t word;
    status_t status = CT_ERROR;

    CT_RETURN_IFERR(sql_init_delete(stmt, delete_ctx));

    CT_RETURN_IFERR(SQL_NODE_PUSH(stmt, delete_ctx->query));
    CT_RETURN_IFERR(SQL_SSA_PUSH(stmt, &delete_ctx->query->ssa));

    do {
        CT_BREAK_IF_ERROR(sql_parse_delete_tables(stmt, delete_ctx, &word));

        if (word.id == KEY_WORD_WHERE) {
            CT_BREAK_IF_ERROR(sql_create_cond_until(stmt, &delete_ctx->query->cond, &word));
        }

        if (word.id == KEY_WORD_ORDER) {
            if (delete_ctx->query->tables.count > 1) {
                CT_SRC_THROW_ERROR(word.text.loc, ERR_SQL_SYNTAX_ERROR, "multi delete do not support order by");
                return CT_ERROR;
            }
            CT_BREAK_IF_ERROR(sql_parse_order_by(stmt, delete_ctx->query, &word));
        }

        if (word.id == KEY_WORD_LIMIT || word.id == KEY_WORD_OFFSET) {
            if (delete_ctx->query->tables.count > 1) {
                CT_SRC_THROW_ERROR(word.text.loc, ERR_SQL_SYNTAX_ERROR, "multi delete do not support limit");
                return CT_ERROR;
            }
            CT_BREAK_IF_ERROR(sql_parse_limit_offset(stmt, &delete_ctx->query->limit, &word));
        }

        if (word.id == KEY_WORD_RETURN || word.id == KEY_WORD_RETURNING) {
            CT_BREAK_IF_ERROR(sql_parse_return_columns(stmt, &delete_ctx->ret_columns, &word));
        }

        if (word.type != WORD_TYPE_EOF) {
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "text end expected but %s found", W2S(&word));
            break;
        }
        status = CT_SUCCESS;
    } while (0);

    CT_RETURN_IFERR(sql_set_table_qb_name(stmt, delete_ctx->query));

    SQL_SSA_POP(stmt);
    SQL_NODE_POP(stmt);
    return status;
}

status_t sql_create_delete_context(sql_stmt_t *stmt, sql_text_t *sql, sql_delete_t **delete_ctx)
{
    lex_t *lex = stmt->session->lex;

    if (sql_alloc_mem(stmt->context, sizeof(sql_delete_t), (void **)delete_ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_push(lex, sql) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_word(lex, "DELETE") != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    if (sql_parse_delete(stmt, *delete_ctx) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    lex_pop(lex);
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
