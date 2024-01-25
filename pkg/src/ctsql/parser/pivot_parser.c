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
 * pivot_parser.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser/pivot_parser.c
 *
 * -------------------------------------------------------------------------
 */
#include "pivot_parser.h"
#include "srv_instance.h"
#include "ctsql_select_parser.h"
#include "expr_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

static expr_tree_t *sql_get_last_expr_tree(expr_tree_t *expr)
{
    expr_tree_t *temp = expr;
    while (temp != NULL && temp->next != NULL) {
        temp = temp->next;
    }
    return temp;
}

static inline status_t sql_pivot_add_alias(sql_stmt_t *stmt, galist_t *aliases, word_t *word, text_t *tmp_alias,
    bool32 need_filling)
{
    text_t *alias = NULL;
    lex_t *lex = stmt->session->lex;

    if (word->id == KEY_WORD_AS) {
        CT_RETURN_IFERR(lex_expected_fetch_variant(lex, word));
        CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(text_t), (void **)(&alias)));
        CT_RETURN_IFERR(sql_copy_text(stmt->context, &word->text.value, alias));
        CT_RETURN_IFERR(lex_fetch(lex, word));
    } else if (word->id != KEY_WORD_FROM) {
        CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(text_t), (void **)(&alias)));
        CT_RETURN_IFERR(sql_try_parse_alias(stmt, alias, word));
    }

    if (alias != NULL && alias->str != NULL) {
        cm_text_upper(alias);
        return cm_galist_insert(aliases, alias);
    } else if (need_filling) {
        CT_RETURN_IFERR(cm_galist_new(aliases, sizeof(text_t), (void **)&alias));
        cm_text_upper(tmp_alias);
        return sql_copy_text(stmt->context, tmp_alias, alias);
    } else {
        CT_RETURN_IFERR(cm_galist_new(aliases, sizeof(text_t), (void **)&alias));
        alias->str = NULL;
        alias->len = 0;
    }

    return CT_SUCCESS;
}

static inline status_t sql_create_new_query_columns(sql_stmt_t *stmt, sql_query_t *new_query)
{
    query_column_t *column = NULL;

    CT_RETURN_IFERR(cm_galist_new(new_query->columns, sizeof(query_column_t), (void **)&column));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(expr_tree_t), (void **)&column->expr));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&column->expr->root));

    column->expr->root->type = EXPR_NODE_STAR;
    column->expr->root->loc = stmt->session->lex->loc;
    return CT_SUCCESS;
}

static status_t sql_create_pivot_sub_select(sql_stmt_t *stmt, sql_table_t *query_table, sql_query_t *query,
    pivot_items_t *pivot_items)
{
    text_t curr_schema;
    sql_query_t *new_query = NULL;
    sql_table_t *new_table = NULL;
    sql_array_t *tables = NULL;
    sql_join_assist_t *join_ass = NULL;
    sql_table_t *sub_table = NULL;
    select_node_t *select_node = NULL;

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(sql_table_t), (void **)&new_table));
    cm_str2text(stmt->session->curr_schema, &curr_schema);
    if (query != NULL) {
        tables = &query->tables;
        join_ass = &query->join_assist;
        sub_table = new_table;
        CT_RETURN_IFERR(sql_copy_text(stmt->context, &query->block_info->origin_name, &sub_table->qb_name));
    } else {
        *new_table = *query_table;
        MEMS_RETURN_IFERR(memset_s(query_table, sizeof(sql_table_t), 0, sizeof(sql_table_t)));
        sub_table = query_table;
        query_table->part_info.type = SPECIFY_PART_NONE;
    }
    sub_table->user.value = curr_schema;
    sub_table->type = SUBSELECT_AS_TABLE;

    CT_RETURN_IFERR(sql_alloc_select_context(stmt, SELECT_AS_TABLE, &sub_table->select_ctx));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(select_node_t), (void **)&select_node));
    APPEND_CHAIN(&sub_table->select_ctx->chain, select_node);
    select_node->type = SELECT_NODE_QUERY;
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(sql_query_t), (void **)&new_query));
    CT_RETURN_IFERR(sql_init_query(stmt, sub_table->select_ctx, pivot_items->loc, new_query));
    new_query->block_info->origin_id = ++stmt->context->query_count;
    CT_RETURN_IFERR(sql_set_origin_query_block_name(stmt, new_query));
    if (tables != NULL) {
        sub_table->id = 0;
        new_query->tables = *tables;
        new_query->join_assist = *join_ass;
        sql_init_join_assist(stmt, join_ass);
        CT_RETURN_IFERR(sql_create_array(stmt->context, &query->tables, "QUERY TABLES", CT_MAX_JOIN_TABLES));
        CT_RETURN_IFERR(sql_array_put(&query->tables, sub_table));
    } else {
        sub_table->id = new_table->id;
        CT_RETURN_IFERR(sql_create_array(stmt->context, &new_query->tables, "QUERY TABLES", CT_MAX_JOIN_TABLES));
        new_table->id = 0;
        CT_RETURN_IFERR(sql_copy_text(stmt->context, &new_query->block_info->origin_name, &new_table->qb_name));
        CT_RETURN_IFERR(sql_array_put(&new_query->tables, new_table));
    }

    CT_RETURN_IFERR(sql_create_new_query_columns(stmt, new_query));
    sub_table->select_ctx->root = sub_table->select_ctx->chain.first;
    sub_table->select_ctx->root->query = new_query;
    sub_table->select_ctx->first_query = new_query;
    new_query->pivot_items = pivot_items;

    return CT_SUCCESS;
}

static status_t sql_create_pivot_items(sql_stmt_t *stmt, pivot_items_t **pivot_items, word_t *word, pivot_type_t type)
{
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(pivot_items_t), (void **)pivot_items));
    (*pivot_items)->loc = word->loc;
    (*pivot_items)->type = type;
    if (type == PIVOT_TYPE) {
        CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(galist_t), (void **)&(*pivot_items)->alias));
        cm_galist_init((*pivot_items)->alias, stmt->context, sql_alloc_mem);
        CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(galist_t), (void **)&(*pivot_items)->aggr_alias));
        cm_galist_init((*pivot_items)->aggr_alias, stmt->context, sql_alloc_mem);
        CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(galist_t), (void **)&(*pivot_items)->aggrs));
        cm_galist_init((*pivot_items)->aggrs, stmt->context, sql_alloc_mem);
        (*pivot_items)->group_sets = NULL;
        (*pivot_items)->pivot_rs_columns = NULL;
        cm_galist_init((*pivot_items)->alias, stmt->context, sql_alloc_mem);
    } else {
        CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(galist_t), (void **)&(*pivot_items)->column_name));
        cm_galist_init((*pivot_items)->column_name, stmt->context, sql_alloc_mem);
        CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(galist_t), (void **)&(*pivot_items)->unpivot_data_rs));
        cm_galist_init((*pivot_items)->unpivot_data_rs, stmt->context, sql_alloc_mem);
        CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(galist_t), (void **)&(*pivot_items)->unpivot_alias_rs));
        cm_galist_init((*pivot_items)->unpivot_alias_rs, stmt->context, sql_alloc_mem);
        CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(galist_t), (void **)&(*pivot_items)->alias));
        cm_galist_init((*pivot_items)->alias, stmt->context, sql_alloc_mem);
        CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(galist_t), (void **)&(*pivot_items)->group_sets));
        cm_galist_init((*pivot_items)->group_sets, stmt->context, sql_alloc_mem);
        (*pivot_items)->include_nulls = CT_FALSE;
    }
    return CT_SUCCESS;
}

static inline status_t sql_continue_create_pivot(sql_stmt_t *stmt, sql_query_t *sql_query, word_t *word)
{
    uint32 ori_flags = stmt->session->lex->flags;

    stmt->session->lex->flags = LEX_SINGLE_WORD;
    CT_RETURN_IFERR(lex_fetch(stmt->session->lex, word));
    stmt->session->lex->flags = ori_flags;

    if (word->id == KEY_WORD_PIVOT) {
        return sql_create_pivot(stmt, sql_query, word);
    } else if (word->id == KEY_WORD_UNPIVOT) {
        return sql_create_unpivot(stmt, sql_query, word);
    } else {
        return CT_SUCCESS;
    }
}

static status_t sql_parse_pivot_alias_set(sql_stmt_t *stmt, expr_tree_t **expr, word_t *word, text_t *set_alias,
    uint32 list_len)
{
    lex_t *lex = stmt->session->lex;
    expr_tree_t *last_expr = (*expr == NULL) ? NULL : sql_get_last_expr_tree(*expr);
    expr_tree_t *curr_expr = NULL;
    text_t tmp_alias;
    char *pos = set_alias->str;

    CT_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    CT_RETURN_IFERR(lex_push(lex, &word->text));

    for (uint32 count = 0; count < list_len; count++) {
        tmp_alias.str = lex->curr_text->str;
        if (sql_create_expr_until(stmt, &curr_expr, word) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }
        tmp_alias.len = (uint32)(word->text.str - tmp_alias.str);
        cm_trim_text(&tmp_alias);

        if (set_alias->len != 0 && set_alias->len < CT_MAX_NAME_LEN) {
            *pos++ = '_';
            set_alias->len++;
        }
        tmp_alias.len = MIN(CT_MAX_NAME_LEN - set_alias->len, tmp_alias.len);
        if (tmp_alias.len > 0) {
            errno_t ret = memcpy_sp(pos, CT_MAX_NAME_LEN - set_alias->len, tmp_alias.str, tmp_alias.len);
            if (ret != EOK) {
                lex_pop(lex);
                CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
                return CT_ERROR;
            }
        }
        pos += tmp_alias.len;
        set_alias->len = MIN(set_alias->len + tmp_alias.len, CT_MAX_NAME_LEN);

        if (*expr == NULL) {
            *expr = curr_expr;
        } else {
            last_expr->next = curr_expr;
        }
        last_expr = curr_expr;
        if (!IS_SPEC_CHAR(word, ',') && count != list_len - 1) {
            lex_pop(lex);
            CT_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "',' expected");
            return CT_ERROR;
        }
    }

    if (lex_expected_end(lex) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }
    lex_pop(lex);
    return lex_fetch(lex, word);
}

static status_t sql_pivot_parse_single_expr_until(sql_stmt_t *stmt, expr_tree_t **expr, galist_t *expr_alias,
    word_t *word, bool32 need_filling)
{
    lex_t *lex = stmt->session->lex;
    text_t tmp_alias;
    expr_tree_t *curr_expr = NULL;
    expr_tree_t *last_expr = sql_get_last_expr_tree(*expr);

    for (;;) {
        tmp_alias.str = lex->curr_text->str;
        if (sql_create_expr_until(stmt, &curr_expr, word) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }

        if (last_expr == NULL) {
            *expr = curr_expr;
        } else {
            last_expr->next = curr_expr;
        }
        last_expr = curr_expr;

        tmp_alias.len = (uint32)(word->text.str - tmp_alias.str);
        cm_trim_text(&tmp_alias);
        CT_RETURN_IFERR(sql_pivot_add_alias(stmt, expr_alias, word, &tmp_alias, need_filling));

        if (IS_SPEC_CHAR(word, ',')) {
            continue;
        }
        break;
    }
    return CT_SUCCESS;
}

static status_t sql_create_pivot_in(sql_stmt_t *stmt, pivot_items_t *pivot_items, word_t *word)
{
    text_t tmp_alias;
    lex_t *lex = stmt->session->lex;
    uint32 list_len = sql_expr_list_len(pivot_items->for_expr);

    CT_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    if (word->text.len == 0) {
        CT_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "expression expected");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(lex_push(lex, &word->text));

    if (list_len > 1) {
        char temp_str[CT_MAX_NAME_LEN] = { 0 };
        tmp_alias.str = temp_str;

        for (;;) {
            tmp_alias.len = 0;
            CT_RETURN_IFERR(sql_parse_pivot_alias_set(stmt, &pivot_items->in_expr, word, &tmp_alias, list_len));
            CT_RETURN_IFERR(sql_pivot_add_alias(stmt, pivot_items->alias, word, &tmp_alias, CT_TRUE));

            if (IS_SPEC_CHAR(word, ',')) {
                continue;
            }
            break;
        }
    } else {
        CT_RETURN_IFERR(
            sql_pivot_parse_single_expr_until(stmt, &pivot_items->in_expr, pivot_items->alias, word, CT_TRUE));
    }

    if (word->type != WORD_TYPE_EOF) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "expected end but %s found", W2S(word));
        lex_pop(lex);
        return CT_ERROR;
    }

    lex_pop(lex);
    return CT_SUCCESS;
}

static status_t sql_create_pivot_bracket_list(sql_stmt_t *stmt, lex_t *lex, word_t *word, expr_tree_t **expr)
{
    bool32 result = CT_FALSE;

    CT_RETURN_IFERR(lex_try_fetch_bracket(lex, word, &result));
    if (result) {
        CT_RETURN_IFERR(sql_create_expr_list(stmt, &word->text, expr));
        return lex_fetch(lex, word);
    } else {
        return sql_create_expr_until(stmt, expr, word);
    }
}

static status_t sql_create_pivot_core(sql_stmt_t *stmt, word_t *word, pivot_items_t *pivot_items,
    sql_table_t *query_table)
{
    lex_t *lex = stmt->session->lex;

    CT_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    CT_RETURN_IFERR(lex_push(lex, &word->text));
    CT_RETURN_IFERR(SQL_NODE_PUSH(stmt, query_table->select_ctx->first_query));
    CT_RETURN_IFERR(SQL_SSA_PUSH(stmt, &query_table->select_ctx->first_query->ssa));

    CT_RETURN_IFERR(
        sql_pivot_parse_single_expr_until(stmt, &pivot_items->aggr_expr, pivot_items->aggr_alias, word, CT_FALSE));

    if (word->id != KEY_WORD_FOR) {
        CT_SRC_THROW_ERROR(stmt->session->lex->loc, ERR_SQL_SYNTAX_ERROR, "for expected");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_create_pivot_bracket_list(stmt, lex, word, &pivot_items->for_expr));

    if (word->id != KEY_WORD_IN) {
        CT_SRC_THROW_ERROR(stmt->session->lex->loc, ERR_SQL_SYNTAX_ERROR, "in expected");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_create_pivot_in(stmt, pivot_items, word));

    CT_RETURN_IFERR(lex_expected_end(lex));

    SQL_SSA_POP(stmt);
    SQL_NODE_POP(stmt);
    lex_pop(lex);

    return CT_SUCCESS;
}

status_t sql_create_pivot(sql_stmt_t *stmt, sql_query_t *query, word_t *word)
{
    pivot_items_t *pivot_items = NULL;
    sql_table_t *query_table = NULL;

#ifdef Z_SHARDING
    if (IS_COORDINATOR) {
        CT_SRC_THROW_ERROR(word->loc, ERR_CAPABILITY_NOT_SUPPORT, "pivot at CN");
        return CT_ERROR;
    }
#endif

    CT_RETURN_IFERR(sql_stack_safe(stmt));
    CT_RETURN_IFERR(sql_create_pivot_items(stmt, &pivot_items, word, PIVOT_TYPE));
    CT_RETURN_IFERR(sql_create_pivot_sub_select(stmt, NULL, query, pivot_items));

    query_table = (sql_table_t *)query->tables.items[0];
    CT_RETURN_IFERR(sql_create_pivot_core(stmt, word, pivot_items, query_table));

    return sql_continue_create_pivot(stmt, query, word);
}

static inline status_t sql_unpivot_alias_if_repeat(galist_t *rs_name, expr_tree_t *expr)
{
    text_t *tmp_alias = NULL;
    text_t *name = &expr->root->word.column.name.value;
    for (uint32 i = 0; i < rs_name->count; i++) {
        tmp_alias = cm_galist_get(rs_name, i);
        if (cm_text_equal(tmp_alias, name)) {
            CT_SRC_THROW_ERROR(expr->loc, ERR_SQL_SYNTAX_ERROR, "column alias can not be the same");
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

static status_t sql_create_unpivot_data_rs(sql_stmt_t *stmt, lex_t *lex, word_t *word, pivot_items_t *pivot_items,
    galist_t *unpivot_data_rs)
{
    expr_tree_t *expr = NULL;

    CT_RETURN_IFERR(sql_create_pivot_bracket_list(stmt, lex, word, &expr));
    while (expr != NULL) {
        CT_RETURN_IFERR(sql_unpivot_alias_if_repeat(pivot_items->unpivot_alias_rs, expr));
        CT_RETURN_IFERR(sql_unpivot_alias_if_repeat(pivot_items->unpivot_data_rs, expr));
        CT_RETURN_IFERR(cm_galist_insert(unpivot_data_rs, &expr->root->word.column.name.value));
        expr = expr->next;
    }

    if (unpivot_data_rs->count == 0) {
        CT_SRC_THROW_ERROR(lex->loc, ERR_SQL_SYNTAX_ERROR, "column expected");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static inline status_t sql_parse_unpivot_in_core(sql_stmt_t *stmt, word_t *word, galist_t *rs_alias, expr_tree_t **expr,
    text_t *group_alias, text_t *alias, uint32 len, expr_node_type_t type)
{
    if (len > 1) {
        CT_RETURN_IFERR(sql_parse_pivot_alias_set(stmt, expr, word, alias, len));
        *group_alias = *alias;
    } else {
        CT_RETURN_IFERR(sql_create_expr_until(stmt, expr, word));
        *group_alias = (*expr)->root->word.column.name.value;
    }

    while (*expr != NULL) {
        if (type == EXPR_NODE_COLUMN) {
            if ((*expr)->root->type != type) {
                CT_SRC_THROW_ERROR((*expr)->loc, ERR_SQL_SYNTAX_ERROR, "column only");
                return CT_ERROR;
            }
            if ((*expr)->root->word.column.table.len != 0) {
                CT_SRC_THROW_ERROR((*expr)->loc, ERR_SQL_SYNTAX_ERROR, "simple column name only");
                return CT_ERROR;
            }

            CT_RETURN_IFERR(cm_galist_insert(rs_alias, (void *)&(*expr)->root->word.column.name.value));
        } else {
            (*expr)->root->datatype = (*expr)->root->value.type;
            CT_RETURN_IFERR(cm_galist_insert(rs_alias, (void *)*expr));
        }

        *expr = (*expr)->next;
    }

    return CT_SUCCESS;
}

static status_t sql_parse_unpivot_in(sql_stmt_t *stmt, word_t *word, pivot_items_t *pivot_items)
{
    lex_t *lex = stmt->session->lex;
    text_t tmp_alias, group_alias;
    expr_tree_t *expr = NULL;
    expr_tree_t *alias_expr = NULL;
    uint32 data_count = pivot_items->unpivot_data_rs->count;
    uint32 alias_count = pivot_items->unpivot_alias_rs->count;
    char temp_alias_str[CT_MAX_NAME_LEN] = { 0 };
    tmp_alias.str = temp_alias_str;

    CT_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    if (word->text.len == 0) {
        CT_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "expression expected");
        return CT_ERROR;
    }
    CT_RETURN_IFERR(lex_push(lex, &word->text));

    for (;;) {
        tmp_alias.len = 0;
        CT_RETURN_IFERR(sql_parse_unpivot_in_core(stmt, word, pivot_items->column_name, &expr, &group_alias,
            &tmp_alias, data_count, EXPR_NODE_COLUMN));
        if (word->id == KEY_WORD_AS) {
            CT_RETURN_IFERR(sql_parse_unpivot_in_core(stmt, word, pivot_items->alias, &expr, &group_alias, &tmp_alias,
                alias_count, EXPR_NODE_CONST));
        } else {
            CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(expr_tree_t), (void **)&alias_expr));
            CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&alias_expr->root));
            CT_RETURN_IFERR(sql_copy_text(stmt->context, &group_alias, &alias_expr->root->value.v_text));
            alias_expr->root->value.v_text.len = group_alias.len;
            cm_text_upper(&alias_expr->root->value.v_text);
            alias_expr->root->type = EXPR_NODE_CONST;
            alias_expr->root->value.is_null = CT_FALSE;
            alias_expr->root->value.type = CT_TYPE_CHAR;
            alias_expr->root->datatype = CT_TYPE_CHAR;

            for (uint32 i = 0; i < alias_count; i++) {
                CT_RETURN_IFERR(cm_galist_insert(pivot_items->alias, alias_expr));
            }
        }

        if (IS_SPEC_CHAR(word, ',')) {
            continue;
        }
        break;
    }

    CT_RETURN_IFERR(lex_expected_end(lex));
    lex_pop(lex);
    return CT_SUCCESS;
}

static status_t sql_create_unpivot_core(sql_stmt_t *stmt, word_t *word, pivot_items_t *pivot_items)
{
    lex_t *lex = stmt->session->lex;

    CT_RETURN_IFERR(lex_fetch(lex, word));
    if (word->type == WORD_TYPE_BRACKET) {
        lex_back(lex, word);
    } else {
        if (word->id == KEY_WORD_INCLUDE) {
            pivot_items->include_nulls = CT_TRUE;
        } else if (word->id != KEY_WORD_EXCLUDE) {
            CT_SRC_THROW_ERROR(stmt->session->lex->loc, ERR_SQL_SYNTAX_ERROR, "exclude or include expected");
            return CT_ERROR;
        }
        CT_RETURN_IFERR(lex_expected_fetch_word(lex, "nulls"));
    }

    CT_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    CT_RETURN_IFERR(lex_push(lex, &word->text));
    CT_RETURN_IFERR(sql_create_unpivot_data_rs(stmt, lex, word, pivot_items, pivot_items->unpivot_data_rs));

    if (word->id != KEY_WORD_FOR) {
        CT_SRC_THROW_ERROR(stmt->session->lex->loc, ERR_SQL_SYNTAX_ERROR, "for expected");
        return CT_ERROR;
    }
    CT_RETURN_IFERR(sql_create_unpivot_data_rs(stmt, lex, word, pivot_items, pivot_items->unpivot_alias_rs));

    if (word->id != KEY_WORD_IN) {
        CT_SRC_THROW_ERROR(stmt->session->lex->loc, ERR_SQL_SYNTAX_ERROR, "in expected");
        return CT_ERROR;
    }
    CT_RETURN_IFERR(sql_parse_unpivot_in(stmt, word, pivot_items));

    CT_RETURN_IFERR(lex_expected_end(lex));
    lex_pop(lex);

    return CT_SUCCESS;
}

status_t sql_create_unpivot(sql_stmt_t *stmt, sql_query_t *query, word_t *word)
{
    pivot_items_t *pivot_items = NULL;

#ifdef Z_SHARDING
    if (IS_COORDINATOR) {
        CT_SRC_THROW_ERROR(word->loc, ERR_CAPABILITY_NOT_SUPPORT, "unpivot at CN");
        return CT_ERROR;
    }
#endif

    CT_RETURN_IFERR(sql_stack_safe(stmt));
    CT_RETURN_IFERR(sql_create_pivot_items(stmt, &pivot_items, word, UNPIVOT_TYPE));
    CT_RETURN_IFERR(sql_create_pivot_sub_select(stmt, NULL, query, pivot_items));
    CT_RETURN_IFERR(sql_create_unpivot_core(stmt, word, pivot_items));

    return sql_continue_create_pivot(stmt, query, word);
}

static status_t sql_create_pivot_for_table(sql_stmt_t *stmt, sql_table_t *query_table, word_t *word, pivot_type_t type)
{
    pivot_items_t *pivot_items = NULL;

    CT_RETURN_IFERR(sql_create_pivot_items(stmt, &pivot_items, word, type));
    CT_RETURN_IFERR(sql_create_pivot_sub_select(stmt, query_table, NULL, pivot_items));
    if (type == PIVOT_TYPE) {
        return sql_create_pivot_core(stmt, word, pivot_items, query_table);
    } else {
        return sql_create_unpivot_core(stmt, word, pivot_items);
    }
}

status_t sql_try_create_pivot_unpivot_table(sql_stmt_t *stmt, sql_table_t *query_table, word_t *word, bool32 *is_pivot)
{
    lex_t *lex = stmt->session->lex;
    pivot_type_t type = NOPIVOT_TYPE;
    bool32 result = CT_FALSE;
    uint32 match_id;
    uint32 ori_flags = lex->flags;

    CT_RETURN_IFERR(sql_stack_safe(stmt));
    // table partition(p1) pivot() alias is OK
    if (query_table->alias.len > 0) {
        return CT_SUCCESS;
    }

    LEX_SAVE(lex);
    if (word->id == KEY_WORD_PIVOT) {
        CT_RETURN_IFERR(lex_try_fetch(lex, "(", &result));
        if (result) {
            type = PIVOT_TYPE;
        }
    } else if (word->id == KEY_WORD_UNPIVOT) {
        CT_RETURN_IFERR(lex_try_fetch_1of3(lex, "(", "exclude", "include", &match_id));
        if (match_id != CT_INVALID_ID32) {
            type = UNPIVOT_TYPE;
        }
    }
    LEX_RESTORE(lex);

    if (type == NOPIVOT_TYPE) {
        return CT_SUCCESS;
    }

    if (IS_DBLINK_TABLE(query_table)) {
        CT_SRC_THROW_ERROR(word->loc, ERR_CAPABILITY_NOT_SUPPORT, "pivot or unpivot on dblink table");
        return CT_ERROR;
    }

#ifdef Z_SHARDING
    if (IS_COORDINATOR) {
        CT_SRC_THROW_ERROR(word->loc, ERR_CAPABILITY_NOT_SUPPORT, "pivot or unpivot at CN");
        return CT_ERROR;
    }
#endif
    if (is_pivot != NULL) {
        *is_pivot = CT_TRUE;
    }
    CT_RETURN_IFERR(sql_create_pivot_for_table(stmt, query_table, word, type));

    lex->flags = LEX_SINGLE_WORD;
    CT_RETURN_IFERR(lex_fetch(lex, word));
    lex->flags = ori_flags;
    return sql_try_create_pivot_unpivot_table(stmt, query_table, word, is_pivot);
}

#ifdef __cplusplus
}
#endif