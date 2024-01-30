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
 * table_parser.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser/table_parser.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_instance.h"
#include "cbo_base.h"
#include "ctsql_json_table.h"
#include "ctsql_select_parser.h"
#include "pivot_parser.h"
#include "cond_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t sql_try_parse_table_alias_word(sql_stmt_t *stmt, sql_text_t *alias, word_t *word,
    const char *expect_alias)
{
    bool32 result = CT_FALSE;
    lex_t *lex = stmt->session->lex;

    if (lex_try_fetch(lex, expect_alias, &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!result) {
        return CT_SUCCESS;
    }

    return sql_copy_object_name_loc(stmt->context, word->type, &word->text, alias);
}

static status_t sql_try_parse_table_alias_limit(sql_stmt_t *stmt, sql_text_t *alias, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    word_t tmp_word;

    LEX_SAVE(lex);

    if (lex_fetch(lex, &tmp_word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (tmp_word.type == WORD_TYPE_NUMBER || tmp_word.type == WORD_TYPE_PARAM || tmp_word.type == WORD_TYPE_RESERVED ||
        tmp_word.type == WORD_TYPE_STRING || tmp_word.type == WORD_TYPE_BRACKET ||
        tmp_word.type == WORD_TYPE_HEXADECIMAL) {
        LEX_RESTORE(lex);
        return CT_SUCCESS;
    }
    LEX_RESTORE(lex);

    if (sql_copy_object_name_loc(stmt->context, word->type, &word->text, alias) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return lex_fetch(lex, word);
}

static status_t sql_try_parse_table_alias_using(sql_stmt_t *stmt, sql_text_t *alias, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    if (stmt->context->type == CTSQL_TYPE_MERGE || stmt->context->type == CTSQL_TYPE_DELETE) {
        return sql_try_parse_table_alias_word(stmt, alias, word, "USING");
    } else {
        if (sql_copy_object_name_loc(stmt->context, word->type, &word->text, alias) != CT_SUCCESS) {
            return CT_ERROR;
        }

        return lex_fetch(lex, word);
    }
}

static status_t sql_try_parse_table_alias_inner(sql_stmt_t *stmt, sql_text_t *alias, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    word_t tmp_word;

    LEX_SAVE(lex);

    if (lex_fetch(lex, &tmp_word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (tmp_word.id == KEY_WORD_JOIN) {
        LEX_RESTORE(lex);
        return CT_SUCCESS;
    }
    LEX_RESTORE(lex);

    if (sql_copy_object_name_loc(stmt->context, word->type, &word->text, alias) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return lex_fetch(lex, word);
}

static status_t sql_try_parse_table_alias_outer(sql_stmt_t *stmt, sql_text_t *alias, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    word_t tmp_word;

    LEX_SAVE(lex);

    if (lex_fetch(lex, &tmp_word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (tmp_word.id == KEY_WORD_JOIN || tmp_word.id == KEY_WORD_OUTER) {
        LEX_RESTORE(lex);
        return CT_SUCCESS;
    }
    LEX_RESTORE(lex);

    if (sql_copy_object_name_loc(stmt->context, word->type, &word->text, alias) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return lex_fetch(lex, word);
}

status_t sql_try_parse_table_alias(sql_stmt_t *stmt, sql_text_t *table_alias, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    if (word->id == KEY_WORD_AS) {
        CT_RETURN_IFERR(lex_expected_fetch_variant(lex, word));
        CT_RETURN_IFERR(sql_copy_object_name_loc(stmt->context, word->type, &word->text, table_alias));
        return lex_fetch(lex, word);
    }

    if (word->type == WORD_TYPE_EOF || !IS_VARIANT(word)) {
        return CT_SUCCESS;
    }

    switch (word->id) {
        case KEY_WORD_LIMIT:
            return sql_try_parse_table_alias_limit(stmt, table_alias, word);
        case KEY_WORD_USING:
            return sql_try_parse_table_alias_using(stmt, table_alias, word);
        case KEY_WORD_INNER:
        case KEY_WORD_CROSS:
            return sql_try_parse_table_alias_inner(stmt, table_alias, word);
        case KEY_WORD_RIGHT:
        case KEY_WORD_LEFT:
        case KEY_WORD_FULL:
            return sql_try_parse_table_alias_outer(stmt, table_alias, word);
        case KEY_WORD_JOIN:
            return sql_try_parse_table_alias_word(stmt, table_alias, word, "JOIN");
        case KEY_WORD_OFFSET:
            return sql_try_parse_table_alias_word(stmt, table_alias, word, "OFFSET");
        default:
            if (sql_copy_object_name_loc(stmt->context, word->type, &word->text, table_alias) != CT_SUCCESS) {
                return CT_ERROR;
            }

            return lex_fetch(lex, word);
    }
}

static status_t sql_try_parse_column_alias(sql_stmt_t *stmt, sql_table_t *table, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    uint32 i;
    query_column_t *query_col = NULL;
    bool32 result = CT_FALSE;

    CT_RETSUC_IFTRUE(word->type != WORD_TYPE_BRACKET ||
        !(table->type == SUBSELECT_AS_TABLE || table->type == WITH_AS_TABLE));

    lex_remove_brackets(&word->text);

    CT_RETURN_IFERR(lex_push(lex, &word->text));

    for (i = 0; i < table->select_ctx->first_query->columns->count; ++i) {
        if (lex_fetch(lex, word) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }

        query_col = (query_column_t *)cm_galist_get(table->select_ctx->first_query->columns, i);
        if (query_col->exist_alias) {
            lex_pop(lex);
            CT_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "cloumn already have alias");
            return CT_ERROR;
        }

        if (IS_VARIANT(word) || word->type == WORD_TYPE_STRING) {
            if (sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &query_col->alias) != CT_SUCCESS) {
                lex_pop(lex);
                return CT_ERROR;
            }
        } else {
            lex_pop(lex);
            CT_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "invalid cloumn alias");
            return CT_ERROR;
        }

        if (i < table->select_ctx->first_query->columns->count - 1) {
            if (lex_try_fetch_char(lex, ',', &result) != CT_SUCCESS) {
                lex_pop(lex);
                return CT_ERROR;
            }
            if (!result) {
                lex_pop(lex);
                CT_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "expect ','");
                return CT_ERROR;
            }
        }
    }

    if (lex_expected_end(lex) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    lex_pop(lex);

    return lex_fetch(lex, word);
}

status_t sql_decode_object_name(sql_stmt_t *stmt, word_t *word, sql_text_t *user, sql_text_t *name)
{
    var_word_t var_word;

    if (sql_word_as_table(stmt, word, &var_word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    *user = var_word.table.user;
    *name = var_word.table.name;

    return CT_SUCCESS;
}

static status_t sql_try_match_withas_table(sql_stmt_t *stmt, sql_table_t *query_table, bool32 *is_withas_table)
{
    sql_withas_t *sql_withas = NULL;
    sql_withas_factor_t *factor = NULL;
    uint32 i, tmp_delta;
    uint32 match_idx = CT_INVALID_ID32;
    uint32 delta = CT_INVALID_INT32;
    uint32 level = CT_INVALID_INT32;

    *is_withas_table = CT_FALSE;

    sql_withas = (sql_withas_t *)stmt->context->withas_entry;
    if (sql_withas == NULL) {
        return CT_SUCCESS;
    }
    /* if found table in with as list, can't use with as list to check tables in sub query sql
    in some case and throws error in lex_push:
    nok: with A as (select * from t1), B as (select * from B) select * from A,B
    nok: with A as (select * from B), B as (select * from t1) select * from A,B
    ok:  with A as (select * from t1), B as (select * from A) select * from A,B */
    for (i = 0; i < sql_withas->withas_factors->count; i++) {
        factor = (sql_withas_factor_t *)cm_galist_get(sql_withas->withas_factors, i);
        if (cm_text_equal(&query_table->user.value, &factor->user.value) &&
            cm_text_equal(&query_table->name.value, &factor->name.value)) {
            if (sql_withas->cur_match_idx == i) {
                CT_SRC_THROW_ERROR(factor->name.loc, ERR_SQL_SYNTAX_ERROR,
                    "recursive WITH clause must have column alias list");
                return CT_ERROR;
            }

            /* match the nearest and firstly withas table in select level */
            tmp_delta = CM_DELTA(stmt->node_stack.depth, factor->depth);
            if (tmp_delta < delta || (tmp_delta == delta && level < factor->level)) {
                match_idx = i;
                delta = tmp_delta;
                level = factor->level;
            }
        }
    }

    if (match_idx != CT_INVALID_ID32) {
        factor = (sql_withas_factor_t *)cm_galist_get(sql_withas->withas_factors, match_idx);
        *is_withas_table = CT_TRUE;
        query_table->type = WITH_AS_TABLE;
        query_table->select_ctx = (sql_select_t *)factor->subquery_ctx;
        query_table->select_ctx->is_withas = CT_TRUE;
        query_table->entry = NULL;
        factor->refs++;
    }

    return CT_SUCCESS;
}

static status_t sql_parse_dblink(sql_stmt_t *stmt, word_t *word, sql_text_t *dblink, sql_text_t *tab_user)
{
    lex_t *lex = stmt->session->lex;
    bool32 result;

    CT_RETURN_IFERR(lex_try_fetch_database_link(lex, word, &result));

    if (!result) {
        return CT_SUCCESS;
    }

    if (stmt->context->type != CTSQL_TYPE_SELECT) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "dml", "dblink table");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_copy_name_loc(stmt->context, &word->text, dblink));

    return CT_SUCCESS;
}

#ifdef Z_SHARDING
static status_t sql_regist_distribute_rule(sql_stmt_t *stmt, sql_text_t *name, sql_table_entry_t **rule)
{
    text_t curr_user = stmt->session->curr_user;

    uint32 i;
    knl_handle_t knl = &stmt->session->knl_session;
    sql_context_t *ctx = stmt->context;

    for (i = 0; i < ctx->rules->count; i++) {
        *rule = (sql_table_entry_t *)cm_galist_get(ctx->rules, i);

        if (cm_text_equal(&(*rule)->name, &name->value)) {
            return CT_SUCCESS;
        }
    }

    if (cm_galist_new(ctx->rules, sizeof(sql_table_entry_t), (pointer_t *)rule) != CT_SUCCESS) {
        return CT_ERROR;
    }

    (*rule)->name = name->value;
    (*rule)->user = curr_user;
    ((*rule)->dc).type = DICT_TYPE_DISTRIBUTE_RULE;

    if (knl_open_dc_with_public(knl, &curr_user, CT_TRUE, &name->value, &(*rule)->dc) != CT_SUCCESS) {
        int32 code;
        const char *message = NULL;
        cm_get_error(&code, &message, NULL);
        if (code == ERR_TABLE_OR_VIEW_NOT_EXIST) {
            cm_reset_error();
            CT_THROW_ERROR(ERR_DISTRIBUTE_RULE_NOT_EXIST, T2S(&name->value));
        }
        return CT_ERROR;
    }

    return CT_SUCCESS;
}
#endif

status_t sql_regist_table(sql_stmt_t *stmt, sql_table_t *table)
{
    uint32 i;
    sql_context_t *ctx = stmt->context;
    sql_table_entry_t *entry = NULL;

    for (i = 0; i < ctx->tables->count; i++) {
        entry = (sql_table_entry_t *)cm_galist_get(ctx->tables, i);
        if (cm_text_equal(&entry->name, &table->name.value) &&
            cm_text_equal(&entry->user, &table->user.value) &&
            cm_text_equal(&entry->dblink, &table->dblink.value)) {
            table->entry = entry;
            return CT_SUCCESS;
        }
    }

    CT_RETURN_IFERR(cm_galist_new(ctx->tables, sizeof(sql_table_entry_t), (pointer_t *)&entry));

    entry->name = table->name.value;
    entry->user = table->user.value;
    entry->dblink = table->dblink.value;
    entry->dc.type = DICT_TYPE_UNKNOWN;

    entry->tab_hash_val = cm_hash_text(&entry->name, CT_TRANS_TAB_HASH_BUCKET);

    table->entry = entry;
    return CT_SUCCESS;
}

static status_t sql_convert_normal_table(sql_stmt_t *stmt, word_t *word, sql_table_t *table)
{
    bool32 is_withas_table = CT_FALSE;

    if (word->ex_count == 1) {
        if (word->type == WORD_TYPE_DQ_STRING) {
            table->user_has_quote = CT_TRUE;
        }
        table->tab_name_has_quote = (word->ex_words[0].type == WORD_TYPE_DQ_STRING) ? CT_TRUE : CT_FALSE;
    } else {
        if (word->type == WORD_TYPE_DQ_STRING) {
            table->tab_name_has_quote = CT_TRUE;
        }
    }

    if (sql_decode_object_name(stmt, word, &table->user, &table->name) != CT_SUCCESS) {
        cm_set_error_loc(word->loc);
        return CT_ERROR;
    }

    // table can be with as or normal
    if (sql_try_match_withas_table(stmt, table, &is_withas_table) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (is_withas_table) {
        return CT_SUCCESS;
    }

#ifdef Z_SHARDING
    if (table->is_distribute_rule) {
        if (sql_regist_distribute_rule(stmt, &table->name, &table->entry) != CT_SUCCESS) {
            cm_set_error_loc(word->loc);
            return CT_ERROR;
        }

        return CT_SUCCESS;
    }
#endif

    if (sql_parse_dblink(stmt, word, &table->dblink, &table->user) != CT_SUCCESS) {
        cm_set_error_loc(word->loc);
        return CT_ERROR;
    }

    if (sql_regist_table(stmt, table) != CT_SUCCESS) {
        cm_set_error_loc(word->loc);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_parse_table_part_name(sql_stmt_t *stmt, word_t *word, sql_table_t *query_table, lex_t *lex)
{
    if (lex_expected_fetch(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (!IS_VARIANT(word)) {
        CT_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "illegal partition-extended table name syntax");
        return CT_ERROR;
    }
    if (sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &query_table->part_info.part_name) !=
        CT_SUCCESS) {
        return CT_ERROR;
    }
    if (lex_expected_end(lex) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_parse_table_part_value(sql_stmt_t *stmt, word_t *word, sql_table_t *query_table)
{
    expr_tree_t *value_expr = NULL;

    if (sql_create_list(stmt, &query_table->part_info.values) != CT_SUCCESS) {
        return CT_ERROR;
    }
    while (CT_TRUE) {
        if (sql_create_expr_until(stmt, &value_expr, word) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (cm_galist_insert(query_table->part_info.values, value_expr) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (word->type == WORD_TYPE_EOF) {
            break;
        }
        if (!IS_SPEC_CHAR(word, ',')) {
            CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(word));
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

static status_t sql_try_parse_table_partition(sql_stmt_t *stmt, word_t *word, sql_table_t *query_table)
{
    bool32 result = CT_FALSE;
    lex_t *lex = stmt->session->lex;
    status_t status;

    CT_RETURN_IFERR(lex_try_fetch(lex, "FOR", &result));
    query_table->part_info.type = result ? SPECIFY_PART_VALUE : SPECIFY_PART_NAME;

#ifdef Z_SHARDING
    if (IS_COORDINATOR && IS_APP_CONN(stmt->session) && query_table->part_info.type == SPECIFY_PART_VALUE) {
        CT_SRC_THROW_ERROR(word->text.loc, ERR_CAPABILITY_NOT_SUPPORT, "select from partition for");
        return CT_ERROR;
    }
#endif
    if (!result) {
        CT_RETURN_IFERR(lex_try_fetch_bracket(lex, word, &result));
        if (!result) {
            query_table->part_info.type = SPECIFY_PART_NONE;
            CT_RETURN_IFERR(sql_copy_str(stmt->context, "PARTITION", &query_table->alias.value));
            query_table->alias.loc = word->loc;
            return lex_fetch(lex, word);
        }
    } else {
        CT_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    }

    if (word->text.len == 0) {
        CT_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "partition name or key value expected");
        return CT_ERROR;
    }
    CT_RETURN_IFERR(lex_push(lex, &word->text));
    uint32 flags = lex->flags;
    lex->flags |= LEX_WITH_ARG;
    if (query_table->part_info.type == SPECIFY_PART_NAME) {
        status = sql_parse_table_part_name(stmt, word, query_table, lex);
    } else {
        status = sql_parse_table_part_value(stmt, word, query_table);
    }
    lex->flags = flags;
    lex_pop(lex);
    CT_RETURN_IFERR(status);

    if (IS_DBLINK_TABLE(query_table)) {
        CT_SRC_THROW_ERROR(word->loc, ERR_CAPABILITY_NOT_SUPPORT, "partition on dblink table");
        return CT_ERROR;
    }

    return lex_fetch(lex, word);
}

static status_t sql_try_parse_table_version(sql_stmt_t *stmt, sql_table_snapshot_t *version, word_t *word);

static status_t sql_try_parse_table_attribute(sql_stmt_t *stmt, word_t *word, sql_table_t *query_table,
    bool32 *pivot_table)
{
    CT_RETURN_IFERR(sql_parse_dblink(stmt, word, &query_table->dblink, &query_table->user));

    uint32 flags = stmt->session->lex->flags;
    stmt->session->lex->flags = LEX_SINGLE_WORD;
    CT_RETURN_IFERR(sql_try_parse_table_version(stmt, &query_table->version, word));
    if (query_table->version.type != CURR_VERSION && IS_DBLINK_TABLE(query_table)) {
        CT_SRC_THROW_ERROR(word->loc, ERR_CAPABILITY_NOT_SUPPORT, "pivot or unpivot on dblink table");
        return CT_ERROR;
    }

    if (word->id == KEY_WORD_PARTITION || word->id == KEY_WORD_SUBPARTITION) {
        if (word->id == KEY_WORD_PARTITION) {
            query_table->part_info.is_subpart = CT_FALSE;
        } else {
            query_table->part_info.is_subpart = CT_TRUE;
        }

        CT_RETURN_IFERR(sql_try_parse_table_partition(stmt, word, query_table));
    }

    stmt->session->lex->flags = flags;
    CT_RETURN_IFERR(sql_try_create_pivot_unpivot_table(stmt, query_table, word, pivot_table));
    stmt->session->lex->flags = LEX_SINGLE_WORD;
    if (query_table->alias.len == 0) {
        CT_RETURN_IFERR(sql_try_parse_table_alias(stmt, &query_table->alias, word));
    }

    if (query_table->alias.len > 0) {
        if (query_table->type == JOIN_AS_TABLE) {
            CT_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "table join does not support aliases");
            return CT_ERROR;
        }
        CT_RETURN_IFERR(sql_try_parse_column_alias(stmt, query_table, word));
    }

    stmt->session->lex->flags = flags;

    return CT_SUCCESS;
}

static status_t sql_create_query_table(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_ass,
                                       sql_table_t *query_table, word_t *word);

#define IS_INCLUDE_SPEC_WORD(word)                                                                             \
    (((*(word)).id == KEY_WORD_LEFT) || ((*(word)).id == KEY_WORD_RIGHT) || ((*(word)).id == KEY_WORD_FULL) || \
        ((*(word)).id == KEY_WORD_JOIN) || ((*(word)).id == KEY_WORD_INNER) || (IS_SPEC_CHAR((word), ',')))

static status_t sql_try_parse_join_in_bracket(sql_stmt_t *stmt, sql_table_t *query_table, word_t *word, bool32 *result)
{
    lex_t *lex = stmt->session->lex;
    if (query_table->alias.len == 0) {
        *result = IS_INCLUDE_SPEC_WORD(word);
        if (!(*result)) {
            CT_RETURN_IFERR(lex_fetch(lex, word));
            *result = IS_INCLUDE_SPEC_WORD(word);
        }
    } else {
        *result = IS_INCLUDE_SPEC_WORD(word);
    }
    return CT_SUCCESS;
}

static status_t sql_try_parse_partition_table_outside_alias(sql_stmt_t *stmt, sql_table_t *query_table, lex_t *lex,
    word_t *word, sql_array_t *tables)
{
    sql_text_t table_alias;
    // select * from ((tableA) partition(p2)) aliasA
    if (query_table->alias.len == 0) {
        CT_RETURN_IFERR(sql_try_parse_table_attribute(stmt, word, query_table, NULL));
    } else {
        uint32 old_flags = lex->flags;
        CT_BIT_RESET(lex->flags, LEX_WITH_ARG);
        CT_RETURN_IFERR(lex_fetch(lex, word));
        lex->flags = old_flags;
        // select * from ((tableA) partition(p2) aliasA) aliasB --expected error
        table_alias.len = 0;
        CT_RETURN_IFERR(sql_try_parse_table_alias(stmt, &table_alias, word));
        if (table_alias.len != 0) {
            CT_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "invalid table alias");
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

static status_t sql_create_query_table_in_bracket(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_assist,
    sql_table_t *query_table, word_t *word);
static status_t sql_parse_table_in_nested_brackets(sql_stmt_t *stmt, sql_array_t *tables,
    sql_join_assist_t *join_assist, sql_table_t *query_table, word_t *word, bool32 *eof)
{
    lex_t *lex = stmt->session->lex;
    word_t sub_select_word;
    bool32 result = CT_FALSE;
    bool32 pivot_table = CT_FALSE;
    sql_table_t *table = NULL;
    const char *words[] = { "UNION", "MINUS", "EXCEPT", "INTERSECT" };
    const uint32 words_count = sizeof(words) / sizeof(char *);
    status_t status = CT_ERROR;

    CT_RETURN_IFERR(lex_push(lex, &word->text));
    LEX_SAVE(lex);
    if (lex_fetch(lex, &sub_select_word) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }
    if (lex_try_fetch_anyone(lex, words_count, words, &result) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    if (result) {
        // this branch handle one case. case1: select * from ((select * from t1) union all (select * from t2))
        lex_pop(lex);
        return CT_SUCCESS;
    }
    CT_RETSUC_IFTRUE(sub_select_word.type != WORD_TYPE_BRACKET);
    *eof = CT_TRUE;
    do {
        word_t temp_word = *word;
        CT_BREAK_IF_ERROR(sql_try_parse_table_attribute(stmt, &temp_word, query_table, &pivot_table));

        CT_BREAK_IF_ERROR(sql_try_parse_join_in_bracket(stmt, query_table, &temp_word, &result));

        LEX_RESTORE(lex);
        if (result) {
            /* this branch handle two cases:
             * case2: select * from ((select * from t1) aliasA left join (select * from t2) aliasB
             * on aliasA.a = aliasB.a);
             * case3: select * from ((t1) left join (t2) on t1.a = t2.a)
             */
            status = sql_create_query_table_in_bracket(stmt, tables, join_assist, query_table, word);
            break;
        }
        if ((&temp_word)->type != WORD_TYPE_EOF) {
            CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "expected end in bracket but %s found",
                W2S(&temp_word));
            break;
        }

        // this branch handle one case: case4: select * from((select * from t1) aliasA)
        table = pivot_table ? (sql_table_t *)query_table->select_ctx->first_query->tables.items[0] : query_table;
        status = sql_create_query_table(stmt, tables, join_assist, table, &sub_select_word);
    } while (0);

    lex_pop(lex);
    CT_RETURN_IFERR(status);
    return sql_try_parse_partition_table_outside_alias(stmt, query_table, lex, word, tables);
}

static status_t sql_try_parse_table_wrapped(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_assist,
    sql_table_t *query_table, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    bool32 eof = CT_FALSE;
    CT_RETURN_IFERR(lex_expected_fetch(lex, word));
    if (word->type != WORD_TYPE_DQ_STRING) {
        cm_trim_text(&word->text.value);
        cm_remove_brackets(&word->text.value);
    }

    if (word->text.len > 0 && word->text.str[0] == '(' && word->type == WORD_TYPE_BRACKET) {
        CT_RETURN_IFERR(sql_parse_table_in_nested_brackets(stmt, tables, join_assist, query_table, word, &eof));
        if (eof) {
            return CT_SUCCESS;
        }
    }

    CT_RETURN_IFERR(sql_create_query_table(stmt, tables, join_assist, query_table, word));
    return sql_try_parse_partition_table_outside_alias(stmt, query_table, lex, word, tables);
}

static status_t sql_parse_query_table(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_assist,
    sql_table_t **query_table, word_t *word)
{
    if (sql_array_new(tables, sizeof(sql_table_t), (void **)query_table) != CT_SUCCESS) {
        return CT_ERROR;
    }
    (*query_table)->id = tables->count - 1;
    (*query_table)->rs_nullable = CT_FALSE;

    return sql_try_parse_table_wrapped(stmt, tables, join_assist, *query_table, word);
}

static status_t sql_create_normal_query_table(sql_stmt_t *stmt, word_t *word, sql_table_t *query_table)
{
    return sql_convert_normal_table(stmt, word, query_table);
}

static status_t sql_bracket_as_query_table(sql_stmt_t *stmt, word_t *word, sql_table_t *query_table)
{
    text_t curr_schema;
    cm_str2text(stmt->session->curr_schema, &curr_schema);
    query_table->user.value = curr_schema;
    query_table->user.loc = word->text.loc;
    query_table->type = SUBSELECT_AS_TABLE;
    CT_RETURN_IFERR(sql_create_select_context(stmt, &word->text, SELECT_AS_TABLE, &query_table->select_ctx));
    query_table->select_ctx->parent = CTSQL_CURR_NODE(stmt);
    return CT_SUCCESS;
}

static inline status_t sql_word_as_table_func(sql_stmt_t *stmt, word_t *word, table_func_t *func)
{
    text_t schema;
    func->loc = word->text.loc;
    sql_copy_func_t sql_copy_func;
    if (IS_COMPATIBLE_MYSQL_INST) {
        sql_copy_func = sql_copy_name_cs;
    } else {
        sql_copy_func = sql_copy_name;
    }

    if (word->ex_count == 0) {
        CT_RETURN_IFERR(sql_copy_func(stmt->context, (text_t *)&word->text, &func->name));
        cm_str2text(stmt->session->curr_schema, &schema);
        func->user = schema;
        func->package = CM_NULL_TEXT;
    } else if (word->ex_count == 1) {
        CT_RETURN_IFERR(sql_copy_prefix_tenant(stmt, (text_t *)&word->text, &func->user, sql_copy_func));
        CT_RETURN_IFERR(sql_copy_func(stmt->context, (text_t *)&word->ex_words[0].text, &func->name));

        func->package = CM_NULL_TEXT;
    } else if (word->ex_count == 2) {
        CT_RETURN_IFERR(sql_copy_func(stmt->context, (text_t *)&word->ex_words[1].text, &func->name));
        CT_RETURN_IFERR(sql_copy_func(stmt->context, (text_t *)&word->ex_words[0].text, &func->package));
        CT_RETURN_IFERR(sql_copy_prefix_tenant(stmt, (text_t *)&word->text, &func->user, sql_copy_func));
    } else {
        CT_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid function or procedure name is found");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_parse_table_cast_type(sql_stmt_t *stmt, expr_tree_t **arg2, word_t *word)
{
    expr_tree_t *arg = NULL;
    lex_t *lex = stmt->session->lex;
    if (sql_create_expr(stmt, arg2) != CT_SUCCESS) {
        return CT_ERROR;
    }
    arg = *arg2;
    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&arg->root) != CT_SUCCESS) {
        return CT_ERROR;
    }

    CT_RETURN_IFERR(lex_fetch(lex, word));

    arg->root->value.type = CT_TYPE_TYPMODE;
    arg->root->type = EXPR_NODE_CONST;
    arg->loc = word->loc;
    arg->root->exec_default = CT_TRUE;
    CT_RETURN_IFERR(sql_word_as_func(stmt, word, &arg->root->word));
    return CT_SUCCESS;
}

static status_t sql_parse_table_cast_arg(sql_stmt_t *stmt, word_t *word, expr_tree_t **expr)
{
    lex_t *lex = stmt->session->lex;
    expr_tree_t *arg = NULL;

    if (lex_push(lex, &word->text) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_create_expr_until(stmt, &arg, word) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    if (word->id != KEY_WORD_AS) {
        lex_pop(lex);
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "key word AS expected but %s found", W2S(word));
        return CT_ERROR;
    }

    if (sql_parse_table_cast_type(stmt, &arg->next, word) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    if (lex_expected_end(lex) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    *expr = arg;

    lex_pop(lex);
    return CT_SUCCESS;
}

static status_t sql_func_as_query_table(sql_stmt_t *stmt, word_t *word, sql_table_t *query_table)
{
    lex_t *lex = stmt->session->lex;
    uint32 prev_flags = lex->flags;
    bool32 result = CT_FALSE;
    text_t cast = { "CAST", 4 };
    stmt->context->has_func_tab = CT_TRUE;
    CT_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    CT_RETURN_IFERR(lex_push(lex, &word->text));

    lex->flags = LEX_WITH_OWNER;
    if (lex_expected_fetch_variant(lex, word) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }
    lex->flags = prev_flags;

    if (sql_word_as_table_func(stmt, word, &query_table->func) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    if (lex_try_fetch_bracket(lex, word, &result) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    if (result) {
        if (word->text.len == 0) {
            query_table->func.args = NULL;
        } else if (cm_compare_text_ins(&query_table->func.name, &cast) == 0) {
            if (sql_parse_table_cast_arg(stmt, word, &query_table->func.args) != CT_SUCCESS) {
                lex_pop(lex);
                return CT_ERROR;
            }
        } else if (sql_create_expr_list(stmt, &word->text, &query_table->func.args) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }
    }

    query_table->user.value.str = stmt->session->curr_schema;
    query_table->user.value.len = (uint32)strlen(stmt->session->curr_schema);
    query_table->user.loc = word->text.loc;
    query_table->type = FUNC_AS_TABLE;
    lex_pop(lex);
    return CT_SUCCESS;
}

static status_t sql_parse_join(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_ass, word_t *word);

static status_t sql_is_subquery_table(sql_stmt_t *stmt, word_t *word, bool32 *result)
{
    lex_t *lex = stmt->session->lex;
    word_t sub_select_word;
    const char *words[] = { "UNION", "MINUS", "EXCEPT", "INTERSECT" };
    const uint32 words_count = sizeof(words) / sizeof(char *);
    *result = CT_FALSE;
    if (word->text.len > 0 && word->text.str[0] == '(') {
        CT_RETURN_IFERR(lex_push(lex, &word->text));
        if (lex_fetch(lex, &sub_select_word) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }
        CT_RETURN_IFERR(lex_try_fetch_anyone(lex, words_count, words, result));
        lex_pop(lex);
    }

    return CT_SUCCESS;
}

static status_t sql_create_json_table(sql_stmt_t *stmt, sql_table_t *table, word_t *word, bool32 is_jsonb_table);
static status_t sql_parse_table_without_join(sql_stmt_t *stmt, sql_table_t *query_table, lex_t *lex, word_t *first_word,
    word_t *second_word)
{
    bool32 pivot_table = CT_FALSE;
    CT_RETURN_IFERR(sql_try_parse_table_attribute(stmt, second_word, query_table, &pivot_table));
    if (second_word->type == WORD_TYPE_EOF) {
        if (first_word->id == KEY_WORD_JSON_TABLE && first_word->ex_count > 0) {
            CT_RETURN_IFERR(sql_create_json_table(stmt, query_table, first_word, CT_FALSE));
        } else if (first_word->id == KEY_WORD_JSONB_TABLE && first_word->ex_count > 0) {
            CT_RETURN_IFERR(sql_create_json_table(stmt, query_table, first_word, CT_TRUE));
        } else if (!pivot_table) {
            CT_RETURN_IFERR(sql_create_normal_query_table(stmt, first_word, query_table));
        } else {
            CT_RETURN_IFERR(
                sql_create_normal_query_table(stmt, first_word, query_table->select_ctx->first_query->tables.items[0]));
        }
    }
    return CT_SUCCESS;
}

static status_t sql_parse_table_with_join(sql_stmt_t *stmt, sql_array_t *tables, sql_table_t *query_table, word_t *word,
    sql_join_assist_t *join_assist)
{
    lex_t *lex = stmt->session->lex;
    sql_join_assist_t join_assist_tmp;
    CT_RETURN_IFERR(lex_push(lex, &word->text));
    join_assist_tmp.join_node = query_table->join_node;
    join_assist_tmp.outer_node_count = 0;
    if (sql_parse_join(stmt, tables, &join_assist_tmp, word) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }
    join_assist->outer_node_count += join_assist_tmp.outer_node_count;
    query_table->join_node = join_assist_tmp.join_node;
    if (word->type != WORD_TYPE_EOF) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "expected end but %s found", W2S(word));
        lex_pop(lex);
        return CT_ERROR;
    }
    lex_pop(lex);

    query_table->type = JOIN_AS_TABLE;
    if (query_table->join_node == NULL) {
        CT_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "Don't support the sql");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_create_query_table_in_bracket(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_assist,
    sql_table_t *query_table, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    word_t first_word, second_word;
    CT_RETURN_IFERR(lex_push(lex, &word->text));
    CT_RETURN_IFERR(lex_fetch(lex, &first_word));
    bool32 result = (first_word.id == KEY_WORD_SELECT || first_word.id == KEY_WORD_WITH);
    if (!result && sql_is_subquery_table(stmt, word, &result) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    if (result) {
        lex_pop(lex);
        return sql_bracket_as_query_table(stmt, word, query_table);
    } else {
        if (IS_VARIANT(&first_word) || first_word.id == KEY_WORD_JSON_TABLE) {
            if (sql_parse_table_without_join(stmt, query_table, lex, &first_word, &second_word) != CT_SUCCESS) {
                lex_pop(lex);
                return CT_ERROR;
            }
            if (second_word.type == WORD_TYPE_EOF) {
                lex_pop(lex);
                return CT_SUCCESS;
            }
        }
        lex_pop(lex);
        return sql_parse_table_with_join(stmt, tables, query_table, word, join_assist);
    }
}

static void sql_init_json_table_info(sql_stmt_t *stmt, json_table_info_t *json_info)
{
    json_info->data_expr = NULL;
    json_info->json_error_info.default_value = NULL;
    json_info->json_error_info.type = JSON_RETURN_NULL;
    json_info->depend_table_count = 0;
    json_info->depend_tables = NULL;
    cm_galist_init(&json_info->columns, stmt->context, sql_alloc_mem);
}

static status_t sql_create_json_table(sql_stmt_t *stmt, sql_table_t *table, word_t *word, bool32 is_jsonb_table)
{
    lex_t *lex = stmt->session->lex;

    table->type = JSON_TABLE;
    table->is_jsonb_table = is_jsonb_table;
    CT_RETURN_IFERR(lex_push(lex, &word->ex_words[0].text));
    word->ex_count = 0;
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(json_table_info_t), (void **)&table->json_table_info));
    sql_init_json_table_info(stmt, table->json_table_info);
    CT_RETURN_IFERR(sql_parse_json_table(stmt, table, word));
    lex_pop(lex);
    return CT_SUCCESS;
}

static status_t sql_create_query_table(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_ass,
    sql_table_t *query_table, word_t *word)
{
    if (IS_VARIANT(word)) {
        return sql_create_normal_query_table(stmt, word, query_table);
    } else if (word->type == WORD_TYPE_BRACKET) {
        return sql_create_query_table_in_bracket(stmt, tables, join_ass, query_table, word);
    } else if (word->id == KEY_WORD_TABLE) {
        return sql_func_as_query_table(stmt, word, query_table);
    } else if (word->id == KEY_WORD_JSON_TABLE) {
        return sql_create_json_table(stmt, query_table, word, CT_FALSE);
    } else if (word->id == KEY_WORD_JSONB_TABLE) {
        return sql_create_json_table(stmt, query_table, word, CT_TRUE);
    } else {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "table name or subselect expected but %s found.",
            W2S(word));
        return CT_ERROR;
    }
}

static status_t sql_verify_table_version(sql_stmt_t *stmt, sql_table_snapshot_t *version, word_t *word)
{
    sql_verifier_t verf = { 0 };
    ct_type_t expr_type;
    expr_node_type_t node_type;

    verf.context = stmt->context;
    verf.stmt = stmt;
    verf.excl_flags = SQL_EXCL_AGGR | SQL_EXCL_COLUMN | SQL_EXCL_STAR | SQL_EXCL_SEQUENCE | SQL_EXCL_SUBSELECT |
        SQL_EXCL_JOIN | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_DEFAULT | SQL_EXCL_ROWSCN | SQL_EXCL_WIN_SORT |
        SQL_EXCL_GROUPING | SQL_EXCL_ROWNODEID;

    if (sql_verify_expr(&verf, (expr_tree_t *)version->expr) != CT_SUCCESS) {
        return CT_ERROR;
    }

    expr_type = TREE_DATATYPE((expr_tree_t *)version->expr);
    node_type = TREE_EXPR_TYPE((expr_tree_t *)version->expr);
    if (version->type == SCN_VERSION) {
        if (!CT_IS_WEAK_NUMERIC_TYPE(expr_type) && node_type != EXPR_NODE_PARAM) {
            cm_try_set_error_loc(word->text.loc);
            CT_SET_ERROR_MISMATCH(CT_TYPE_BIGINT, expr_type);
            return CT_ERROR;
        }
    } else {
        if (!CT_IS_DATETIME_TYPE(expr_type)) {
            cm_try_set_error_loc(word->text.loc);
            CT_SET_ERROR_MISMATCH(CT_TYPE_TIMESTAMP, expr_type);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_try_parse_table_version(sql_stmt_t *stmt, sql_table_snapshot_t *version, word_t *word)
{
    bool32 result = CT_FALSE;
    lex_t *lex = stmt->session->lex;
    uint32 matched_id;
    uint32 flags = lex->flags;

    if (lex_fetch(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word->id != KEY_WORD_AS) {
        version->type = CURR_VERSION;
        return CT_SUCCESS;
    }

    if (lex_try_fetch(lex, "OF", &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!result) {
        version->type = CURR_VERSION;
        return CT_SUCCESS;
    }

#ifdef Z_SHARDING
    if (IS_COORDINATOR && IS_APP_CONN(stmt->session)) {
        CT_SRC_THROW_ERROR(word->text.loc, ERR_CAPABILITY_NOT_SUPPORT, "AS OF");
        return CT_ERROR;
    }
#endif

    if (lex_expected_fetch_1of2(lex, "SCN", "TIMESTAMP", &matched_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    version->type = (matched_id == 0) ? SCN_VERSION : TIMESTAMP_VERSION;

    lex->flags = LEX_WITH_ARG;
    if (sql_create_expr_until(stmt, (expr_tree_t **)&version->expr, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_verify_table_version(stmt, version, word));

    lex->flags = flags;
    return CT_SUCCESS;
}

status_t sql_create_join_node(sql_stmt_t *stmt, sql_join_type_t join_type, sql_table_t *table, cond_tree_t *cond,
    sql_join_node_t *left, sql_join_node_t *right, sql_join_node_t **join_node)
{
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(sql_join_node_t), (void **)join_node));
    CT_RETURN_IFERR(sql_create_array(stmt->context, &(*join_node)->tables, "JOINS TABLES", CT_MAX_JOIN_TABLES));
    (*join_node)->type = join_type;
    (*join_node)->cost.cost = CBO_MIN_COST;
    (*join_node)->cost.card = CBO_MAX_ROWS;
    (*join_node)->join_cond = cond;
    (*join_node)->left = left;
    (*join_node)->right = right;
    (*join_node)->is_cartesian_join = CT_FALSE;
    // table is not NULL only when dml parse
    if (table != NULL) {
        CT_RETURN_IFERR(sql_array_put(&(*join_node)->tables, table));
    }
    // adjust join tree, left and right node is not NULL
    if (left != NULL) {
        CT_RETURN_IFERR(sql_array_concat(&(*join_node)->tables, &left->tables));
    }
    if (right != NULL) {
        CT_RETURN_IFERR(sql_array_concat(&(*join_node)->tables, &right->tables));
    }
    return CT_SUCCESS;
}

static void sql_add_join_node(sql_join_chain_t *chain_node, sql_join_node_t *join_node)
{
    if (chain_node->count == 0) {
        chain_node->first = join_node;
    } else {
        chain_node->last->next = join_node;
        join_node->prev = chain_node->last;
    }

    chain_node->last = join_node;
    chain_node->count++;
}

status_t sql_generate_join_node(sql_stmt_t *stmt, sql_join_chain_t *join_chain, sql_join_type_t join_type,
    sql_table_t *table, cond_tree_t *cond)
{
    sql_join_node_t *join_node = NULL;

    if (table != NULL && table->type == JOIN_AS_TABLE) {
        join_node = table->join_node;
    } else {
        CT_RETURN_IFERR(sql_create_join_node(stmt, join_type, table, cond, NULL, NULL, &join_node));
    }

    sql_add_join_node(join_chain, join_node);
    return CT_SUCCESS;
}

static inline status_t sql_parse_comma_cross_join(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_ass,
    sql_join_chain_t *join_chain, sql_table_t **table, word_t *word, sql_join_type_t join_type)
{
    if (join_chain->count == 0) {
        CT_RETURN_IFERR(sql_generate_join_node(stmt, join_chain, JOIN_TYPE_NONE, *table, NULL));
    }
    CT_RETURN_IFERR(sql_generate_join_node(stmt, join_chain, join_type, NULL, NULL));
    CT_RETURN_IFERR(sql_parse_query_table(stmt, tables, join_ass, table, word));

    return sql_generate_join_node(stmt, join_chain, JOIN_TYPE_NONE, *table, NULL);
}

status_t sql_parse_comma_join(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_ass,
    sql_join_chain_t *join_chain, sql_table_t **table, word_t *word)
{
    return sql_parse_comma_cross_join(stmt, tables, join_ass, join_chain, table, word, JOIN_TYPE_COMMA);
}

static inline status_t sql_parse_cross_join(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_ass,
    sql_join_chain_t *join_chain, sql_table_t **table, word_t *word)
{
    CT_RETURN_IFERR(lex_expected_fetch_word(stmt->session->lex, "JOIN"));
    return sql_parse_comma_cross_join(stmt, tables, join_ass, join_chain, table, word, JOIN_TYPE_CROSS);
}

static status_t sql_parse_explicit_join(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_ass,
    sql_join_chain_t *join_chain, sql_table_t **table, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    bool32 result = CT_FALSE;
    sql_join_type_t join_type;
    cond_tree_t *join_cond = NULL;

    if (join_chain->count == 0) {
        CT_RETURN_IFERR(sql_generate_join_node(stmt, join_chain, JOIN_TYPE_NONE, *table, NULL));
    }

    for (;;) {
        join_cond = NULL;
        if (word->id == KEY_WORD_LEFT || word->id == KEY_WORD_RIGHT || word->id == KEY_WORD_FULL) {
            join_type = (word->id == KEY_WORD_LEFT) ? JOIN_TYPE_LEFT :
                                                      ((word->id == KEY_WORD_RIGHT) ? JOIN_TYPE_RIGHT : JOIN_TYPE_FULL);
            join_ass->outer_node_count++;
            CT_RETURN_IFERR(lex_try_fetch(lex, "OUTER", &result));
        } else {
            join_type = JOIN_TYPE_INNER;
        }
        if (word->id != KEY_WORD_JOIN) {
            CT_RETURN_IFERR(lex_expected_fetch_word(lex, "JOIN"));
        }

        CT_RETURN_IFERR(sql_parse_query_table(stmt, tables, join_ass, table, word));
        if ((*table)->type == JSON_TABLE) {
            if (join_type == JOIN_TYPE_RIGHT) {
                join_type = JOIN_TYPE_INNER;
                join_ass->outer_node_count--;
            } else if (join_type == JOIN_TYPE_FULL) {
                join_type = JOIN_TYPE_LEFT;
            }
        }

        if ((word->id != KEY_WORD_ON) && (join_type != JOIN_TYPE_INNER)) {
            CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "ON expected but '%s' found", W2S(word));
            return CT_ERROR;
        }

        if (word->id == KEY_WORD_ON) {
            CT_RETURN_IFERR(sql_create_cond_until(stmt, &join_cond, word));
        }
        CT_RETURN_IFERR(sql_generate_join_node(stmt, join_chain, join_type, NULL, join_cond));
        CT_RETURN_IFERR(sql_generate_join_node(stmt, join_chain, JOIN_TYPE_NONE, *table, NULL));

        CT_BREAK_IF_TRUE(!(word->id == KEY_WORD_JOIN || word->id == KEY_WORD_INNER || word->id == KEY_WORD_LEFT ||
            word->id == KEY_WORD_RIGHT || word->id == KEY_WORD_FULL));
    }

    return CT_SUCCESS;
}

static void sql_down_table_join_node(sql_join_chain_t *chain, sql_join_node_t *join_node)
{
    join_node->left = join_node->prev;
    join_node->right = join_node->next;

    join_node->next = join_node->next->next;
    join_node->prev = join_node->prev->prev;

    if (join_node->prev != NULL) {
        join_node->prev->next = join_node;
    } else {
        chain->first = join_node;
    }

    if (join_node->next != NULL) {
        join_node->next->prev = join_node;
    } else {
        chain->last = join_node;
    }

    join_node->left->prev = NULL;
    join_node->left->next = NULL;
    join_node->right->prev = NULL;
    join_node->right->next = NULL;

    chain->count -= 2;
}

status_t sql_form_table_join_with_opers(sql_join_chain_t *join_chain, uint32 opers)
{
    sql_join_node_t *node = join_chain->first;

    /* get next cond node, merge node is needed at least two nodes */
    while (node != NULL) {
        if (((uint32)node->type & opers) == 0 || node->left != NULL) {
            node = node->next;
            continue;
        }

        sql_down_table_join_node(join_chain, node);

        if (node->left->type == JOIN_TYPE_NONE) {
            CT_RETURN_IFERR(sql_array_put(&node->tables, TABLE_OF_JOIN_LEAF(node->left)));
        } else {
            CT_RETURN_IFERR(sql_array_concat(&node->tables, &node->left->tables));
        }

        if (node->right->type == JOIN_TYPE_NONE) {
            CT_RETURN_IFERR(sql_array_put(&node->tables, TABLE_OF_JOIN_LEAF(node->right)));
        } else {
            CT_RETURN_IFERR(sql_array_concat(&node->tables, &node->right->tables));
        }

        node = node->next;
    }

    return CT_SUCCESS;
}

static status_t sql_parse_join(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_ass, word_t *word)
{
    sql_join_chain_t join_chain = { 0 };
    sql_table_t *table = NULL;
    join_ass->join_node = NULL;

    CT_RETURN_IFERR(sql_stack_safe(stmt));

    CT_RETURN_IFERR(sql_parse_query_table(stmt, tables, join_ass, &table, word));

    for (;;) {
        CT_BREAK_IF_TRUE(word->type == WORD_TYPE_EOF);

        if (word->id == KEY_WORD_JOIN || word->id == KEY_WORD_INNER || word->id == KEY_WORD_LEFT ||
            word->id == KEY_WORD_RIGHT || word->id == KEY_WORD_FULL) {
            CT_RETURN_IFERR(sql_parse_explicit_join(stmt, tables, join_ass, &join_chain, &table, word));
        }

        if (IS_SPEC_CHAR(word, ',')) {
            CT_RETURN_IFERR(sql_parse_comma_join(stmt, tables, join_ass, &join_chain, &table, word));
        } else if (word->id == KEY_WORD_CROSS) {
            CT_RETURN_IFERR(sql_parse_cross_join(stmt, tables, join_ass, &join_chain, &table, word));
        } else {
            break;
        }
    }

    if (join_chain.count > 0) {
        CT_RETURN_IFERR(sql_form_table_join_with_opers(&join_chain,
            JOIN_TYPE_INNER | JOIN_TYPE_LEFT | JOIN_TYPE_RIGHT | JOIN_TYPE_FULL | JOIN_TYPE_CROSS));
        CT_RETURN_IFERR(sql_form_table_join_with_opers(&join_chain, JOIN_TYPE_COMMA));
        join_ass->join_node = join_chain.first;
    } else {
        join_ass->join_node = table->join_node;
    }

    return CT_SUCCESS;
}

static status_t sql_remove_join_table(sql_stmt_t *stmt, sql_query_t *query)
{
    sql_array_t new_tables;

    CT_RETURN_IFERR(sql_create_array(stmt->context, &new_tables, "QUERY TABLES", CT_MAX_JOIN_TABLES));

    for (uint32 i = 0; i < query->tables.count; ++i) {
        sql_table_t *table = (sql_table_t *)sql_array_get(&query->tables, i);
        if (table->type == JOIN_AS_TABLE) {
            continue;
        }
        table->id = new_tables.count;
        CT_RETURN_IFERR(sql_array_put(&new_tables, table));
    }

    query->tables = new_tables;

    return CT_SUCCESS;
}

static void sql_traverse_join_tree_set_nullable(sql_join_node_t *node)
{
    sql_table_t *table = NULL;
    for (uint32 i = 0; i < node->tables.count; i++) {
        table = (sql_table_t *)sql_array_get(&(node->tables), i);
        table->rs_nullable = CT_TRUE;
    }
    return;
}

static void sql_parse_join_set_table_nullable(sql_join_node_t *node)
{
    if (node->type == JOIN_TYPE_NONE) {
        return;
    }
    /* if parent node is left join, so right tree should be null */
    if (node->type == JOIN_TYPE_LEFT) {
        sql_traverse_join_tree_set_nullable(node->right);
    } else if (node->type == JOIN_TYPE_RIGHT) {
        /* if parent node is right join, so left tree should be null */
        sql_traverse_join_tree_set_nullable(node->left);
    } else if (node->type == JOIN_TYPE_FULL) {
        /* if parent node is full join, so left tree and right tree should be null */
        sql_traverse_join_tree_set_nullable(node->right);
        sql_traverse_join_tree_set_nullable(node->left);
    }

    sql_parse_join_set_table_nullable(node->left);
    sql_parse_join_set_table_nullable(node->right);
}

status_t sql_parse_join_entry(sql_stmt_t *stmt, sql_query_t *query, word_t *word)
{
    CT_RETURN_IFERR(sql_parse_join(stmt, &query->tables, &query->join_assist, word));
    if (query->join_assist.outer_node_count > 0) {
        sql_parse_join_set_table_nullable(query->join_assist.join_node);
    }
    return sql_remove_join_table(stmt, query);
}

status_t sql_parse_query_tables(sql_stmt_t *stmt, sql_query_t *sql_query, word_t *word)
{
    sql_table_t *table = NULL;
    lex_t *lex = NULL;

    CM_POINTER3(stmt, sql_query, word);
    lex = stmt->session->lex;

    if (word->type == WORD_TYPE_EOF) {
        word->ex_count = 0;
        word->type = WORD_TYPE_VARIANT;
        word->text.str = "SYS_DUMMY";
        word->text.len = (uint32)strlen(word->text.str);
        word->text.loc = LEX_LOC;

        CT_RETURN_IFERR(sql_array_new(&sql_query->tables, sizeof(sql_table_t), (void **)&table));
        table->id = sql_query->tables.count - 1;
        table->rs_nullable = CT_FALSE;
        table->ineliminable = CT_FALSE;
#ifdef Z_SHARDING
        table->is_ancestor = 0;
#endif

        CT_RETURN_IFERR(sql_create_query_table(stmt, &sql_query->tables, &sql_query->join_assist, table, word));
        word->type = WORD_TYPE_EOF;

        return CT_SUCCESS;
    }

    if (word->id != KEY_WORD_FROM) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "FROM expected but %s found", W2S(word));
        return CT_ERROR;
    }

    return sql_parse_join_entry(stmt, sql_query, word);
}

status_t sql_parse_table(sql_stmt_t *stmt, sql_table_t *table, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    lex->flags = LEX_WITH_OWNER;

    if (lex_expected_fetch(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!IS_VARIANT(word)) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "table name expected but %s found", W2S(word));
        return CT_ERROR;
    }

    if (word->type == WORD_TYPE_DQ_STRING) {
        table->tab_name_has_quote = CT_TRUE;
    }

    if (sql_convert_normal_table(stmt, word, table) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (table->type == SUBSELECT_AS_TABLE || table->type == WITH_AS_TABLE) {
        return CT_SUCCESS;
    }

    if (lex_fetch(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!table->is_distribute_rule) {
        if (sql_try_parse_table_alias(stmt, &table->alias, word) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    lex->flags = LEX_WITH_OWNER | LEX_WITH_ARG;
    return CT_SUCCESS;
}

status_t sql_set_table_qb_name(sql_stmt_t *stmt, sql_query_t *query)
{
    sql_table_t *table = NULL;
    for (uint32 i = 0; i < query->tables.count; i++) {
        table = (sql_table_t *)sql_array_get(&query->tables, i);
        CT_RETURN_IFERR(sql_copy_text(stmt->context, &query->block_info->origin_name, &table->qb_name));
    }
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif