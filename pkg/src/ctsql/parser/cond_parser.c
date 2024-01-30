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
 * cond_parser.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser/cond_parser.c
 *
 * -------------------------------------------------------------------------
 */
#include "cond_parser.h"
#include "srv_instance.h"
#ifdef __cplusplus
extern "C" {
#endif

static status_t sql_generate_cond(sql_stmt_t *stmt, cond_tree_t *cond, bool32 *is_expr);
status_t sql_parse_in(sql_stmt_t *stmt, cmp_node_t *cmp_node, word_t *word);

static status_t sql_create_cond_node(sql_stmt_t *stmt, cond_tree_t *cond, cond_node_type_t cond_type)
{
    cond_node_t *node = NULL;

    if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != CT_SUCCESS) {
        return CT_ERROR;
    }

    node->type = cond_type;
    APPEND_CHAIN(&cond->chain, node);
    return CT_SUCCESS;
}

static status_t sql_parse_logic_node(sql_stmt_t *stmt, cond_tree_t *cond, word_t *word)
{
    uint32 node_type;
    cond_node_t *last = NULL;

    if (word->id == KEY_WORD_AND) {
        node_type = COND_NODE_AND;
    }
    if (word->id == KEY_WORD_OR) {
        node_type = COND_NODE_OR;
    }
    if (cond->chain.count == 0) {
        CT_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "expression expected but and/or is found");
        return CT_ERROR;
    }
    last = cond->chain.last;
    /* ******************************************************************
       |  and/or->and/or |             |                |
       |   /  \          |=>is ok, but | and/or->and/or | is invaid
       | cmp1 cmp2       |             |                |
     ******************************************************************* */
    if (IS_LOGICAL_NODE(last) && last->left == NULL) {
        CT_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "expression expected, but and/or is found");
        return CT_ERROR;
    }

    return sql_create_cond_node(stmt, cond, node_type);
}

static status_t sql_create_cmp_node(sql_stmt_t *stmt, cond_tree_t *cond)
{
    cond_node_t *node = NULL;

    if (sql_create_cond_node(stmt, cond, COND_NODE_COMPARE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    node = cond->chain.last;

    if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != CT_SUCCESS) {
        return CT_ERROR;
    }

    node->cmp->rnum_pending = CT_FALSE;
    node->cmp->has_conflict_chain = CT_FALSE;
    node->cmp->anti_join_cond = CT_FALSE;
    return CT_SUCCESS;
}

status_t sql_parse_exists(sql_stmt_t *stmt, cmp_node_t *cmp_node, word_t *word)
{
    expr_tree_t *expr = NULL;
    lex_t *lex = stmt->session->lex;
    sql_select_t *select_ctx = NULL;

    if (lex_expected_fetch_bracket(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_create_expr_from_text(stmt, &word->text, &expr, WORD_FLAG_NONE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (expr->root->type != EXPR_NODE_SELECT) {
        CT_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "SELECT expected");
        return CT_ERROR;
    }

    select_ctx = (sql_select_t *)expr->root->value.v_obj.ptr;
    select_ctx->type = SELECT_AS_LIST;
    sql_set_exists_query_flag(stmt, select_ctx->root);

    cmp_node->right = expr;

    return CT_SUCCESS;
}

// only for CMP_TYPE_REGEXP_LIKE/CMP_TYPE_NOT_REGEXP_LIKE = true/ = false/ != true / != false / <> true / <> false
static status_t sql_parse_regexp_like_right(sql_stmt_t *stmt, cmp_node_t *cmp_node, word_t *word)
{
    cmp_type_t cmp_type = cmp_node->type;
    uint32 match_id;

    if (word->type != WORD_TYPE_COMPARE) {
        return CT_SUCCESS;
    }

    if ((cmp_type != CMP_TYPE_REGEXP_LIKE) && (cmp_type != CMP_TYPE_NOT_REGEXP_LIKE)) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(lex_try_fetch_1of2(stmt->session->lex, "true", "false", &match_id));
    if (match_id >= 2) {
        return CT_SUCCESS;
    }

    switch (word->id) {
        case CMP_TYPE_EQUAL:
            if (match_id == 1) {
                cmp_type = (cmp_type == CMP_TYPE_REGEXP_LIKE) ? CMP_TYPE_NOT_REGEXP_LIKE : CMP_TYPE_REGEXP_LIKE;
            }
            break;
        case CMP_TYPE_NOT_EQUAL:
            if (match_id == 0) {
                cmp_type = (cmp_type == CMP_TYPE_REGEXP_LIKE) ? CMP_TYPE_NOT_REGEXP_LIKE : CMP_TYPE_REGEXP_LIKE;
            }
            break;
        default:
            return CT_SUCCESS;
    }
    cmp_node->type = cmp_type;
    return CT_SUCCESS;
}

status_t sql_parse_between(sql_stmt_t *stmt, cmp_node_t *cmp_node, word_t *word)
{
    expr_tree_t *expr1 = NULL;
    expr_tree_t *expr2 = NULL;

    if (sql_create_expr_until(stmt, &expr1, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word->id != KEY_WORD_AND) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "AND expected but %s found ", W2S(word));
        return CT_ERROR;
    }

    if (sql_create_expr_until(stmt, &expr2, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cmp_node->right = expr1;
    expr1->next = expr2;

    return CT_SUCCESS;
}

status_t sql_parse_like(sql_stmt_t *stmt, cmp_node_t *cmp_node, word_t *word)
{
    expr_tree_t *escape_expr = NULL;
    variant_t *escape_var = NULL;
    char escape_char;

    CT_RETURN_IFERR(sql_create_expr_until(stmt, &cmp_node->right, word));

    if (word->id != KEY_WORD_ESCAPE) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_create_expr_until(stmt, &cmp_node->right->next, word));

    do {
        escape_expr = cmp_node->right->next;

        if (escape_expr->root->type == EXPR_NODE_CONST) {
            escape_var = &escape_expr->root->value;
            if (escape_var->is_null || !CT_IS_STRING_TYPE(escape_var->type)) {
                break;
            }
            CT_BREAK_IF_ERROR(lex_check_asciichar(&escape_var->v_text, &escape_expr->loc, &escape_char, CT_FALSE));
            escape_var->v_text.str[0] = escape_char;
            escape_var->v_text.len = 1;
            return CT_SUCCESS;
        }

        if (NODE_IS_RES_NULL(escape_expr->root)) {
            break;
        }

        if (escape_expr->root->type == EXPR_NODE_PARAM) {
            return CT_SUCCESS;
        }
    } while (0);

    CT_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "invalid escape character");
    return CT_ERROR;
}

status_t sql_parse_regexp(sql_stmt_t *stmt, cmp_node_t *cmp_node, word_t *word)
{
    return sql_create_expr_until(stmt, &cmp_node->right, word);
}

status_t sql_parse_in_expr_list(sql_stmt_t *stmt, cmp_node_t *cmp_node, sql_text_t *text, expr_tree_t **expr)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    expr_tree_t *last = NULL;
    expr_tree_t *curr = NULL;
    uint32 list_len = sql_expr_list_len(cmp_node->left);

    CT_RETURN_IFERR(lex_push(lex, text));
    *expr = NULL;

    for (;;) {
        if (lex_expected_fetch_bracket(lex, &word) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }

        if (sql_create_expr_list(stmt, &word.text, &curr) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }

        if (list_len != sql_expr_list_len(curr)) {
            lex_pop(lex);
            CT_SRC_THROW_ERROR(word.text.loc, ERR_SQL_SYNTAX_ERROR, "not enough values");
            return CT_ERROR;
        }

        if (last == NULL) {
            *expr = curr;
        } else {
            last->next = curr;
        }

        last = sql_expr_list_last(curr);

        if (lex_fetch(lex, &word) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }

        if (word.type == WORD_TYPE_EOF) {
            break;
        }

        if (!IS_SPEC_CHAR(&word, ',')) {
            lex_pop(lex);
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(&word));
            return CT_ERROR;
        }
    }

    lex_pop(lex);
    return CT_SUCCESS;
}

static status_t chk_in_expr_is_single_select(sql_stmt_t *stmt, cmp_node_t *cmp_node, word_t *word, bool32 *is_single_select)
{
    lex_t *lex = stmt->session->lex;
    word_t tmp_word;
    const char *words[] = { "UNION", "MINUS", "EXCEPT", "INTERSECT" };
    const uint32 words_count = sizeof(words) / sizeof(char *);
    bool32 has_union = CT_FALSE;
    *is_single_select = CT_TRUE;
    CT_RETURN_IFERR(sql_stack_safe(stmt));
    // select 1 from sys_dummy where 1 in ((select 1 from sys_dummy),(select 1 from sys_dummy))
    CT_RETURN_IFERR(lex_push(lex, &word->text));
    if (lex_fetch(lex, &tmp_word) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }
    LEX_SAVE(lex);
    if (lex_try_fetch_anyone(lex, words_count, words, &has_union) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }
    LEX_RESTORE(lex);
    if (tmp_word.type == WORD_TYPE_BRACKET && !has_union) {
        CT_RETURN_IFERR(chk_in_expr_is_single_select(stmt, cmp_node, &tmp_word, is_single_select));
        if (lex_fetch(lex, &tmp_word) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }
        *is_single_select = (*is_single_select && tmp_word.type == WORD_TYPE_EOF);
        lex_pop(lex);
        return CT_SUCCESS;
    }
    if (!has_union && tmp_word.id != KEY_WORD_SELECT && tmp_word.id != KEY_WORD_WITH) {
        *is_single_select = CT_FALSE;
    }
    lex_pop(lex);
    return CT_SUCCESS;
}

status_t sql_parse_in(sql_stmt_t *stmt, cmp_node_t *cmp_node, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    status_t status;
    bool32 is_single_select = CT_FALSE;
    CT_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));

    if (word->text.len == 0) {
        CT_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "expression expected");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(chk_in_expr_is_single_select(stmt, cmp_node, word, &is_single_select));

    if (is_single_select) {
        expr_tree_t *cur_expr = NULL;
        status = sql_parse_in_subselect(stmt, &cur_expr, word);
        cmp_node->right = cur_expr;
    } else if (cmp_node->left->next != NULL) { // left is an expr list
        status = sql_parse_in_expr_list(stmt, cmp_node, &word->text, &cmp_node->right);
    } else {
        status = sql_create_expr_list(stmt, &word->text, &cmp_node->right);
    }

    if (status != CT_SUCCESS) {
        return CT_ERROR;
    }

    return lex_fetch(lex, word);
}

status_t sql_create_const_expr_false(sql_stmt_t *stmt, expr_tree_t **expr, word_t *word, int32 val)
{
    expr_node_t *expr_node = NULL;
    CT_RETURN_IFERR(sql_create_expr(stmt, expr));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&expr_node));

    expr_node->owner = (*expr);
    expr_node->argument = NULL;
    expr_node->type = EXPR_NODE_CONST;
    expr_node->unary = UNARY_OPER_NONE;
    expr_node->value.type = CT_TYPE_BOOLEAN;
    expr_node->value.v_int = val;
    if (word != NULL) {
        expr_node->loc = word->text.loc;
        (*expr)->loc = word->text.loc;
    }
    expr_node->left = NULL;
    expr_node->right = NULL;
    (*expr)->owner = stmt->context;
    (*expr)->root = expr_node;
    (*expr)->next = NULL;
    (*expr)->unary = UNARY_OPER_NONE;
    return CT_SUCCESS;
}

static status_t sql_parse_group_compare_right(sql_stmt_t *stmt, cmp_node_t *cmp_node, word_t *word)
{
    switch (cmp_node->type) {
        case CMP_TYPE_EQUAL_ANY:
        case CMP_TYPE_NOT_EQUAL_ANY:
        case CMP_TYPE_GREAT_EQUAL_ANY:
        case CMP_TYPE_GREAT_ANY:
        case CMP_TYPE_LESS_ANY:
        case CMP_TYPE_LESS_EQUAL_ANY:
        case CMP_TYPE_EQUAL_ALL:
        case CMP_TYPE_NOT_EQUAL_ALL:
        case CMP_TYPE_GREAT_EQUAL_ALL:
        case CMP_TYPE_GREAT_ALL:
        case CMP_TYPE_LESS_ALL:
        case CMP_TYPE_LESS_EQUAL_ALL:
            if (cmp_node->left->next != NULL) {
                CT_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                    "the left expr count of 'any/all' compare must be 1");
                return CT_ERROR;
            }
            return sql_parse_in(stmt, cmp_node, word);
        default:
            return sql_create_expr_until(stmt, &cmp_node->right, word);
    }
}

cmp_node_t *sql_get_last_comp_node(sql_stmt_t *stmt, cond_tree_t *cond, word_t *word)
{
    cond_node_t *last_cond_node = NULL;
    CM_POINTER(word);

    if (cond->chain.count == 0) {
        if (sql_create_cmp_node(stmt, cond) != CT_SUCCESS) {
            return NULL;
        }

        last_cond_node = cond->chain.last;
    } else {
        last_cond_node = cond->chain.last;
        CM_POINTER(last_cond_node);

        if (IS_LOGICAL_NODE(last_cond_node)) {
            if (sql_create_cmp_node(stmt, cond) != CT_SUCCESS) {
                return NULL;
            }
            last_cond_node = cond->chain.last;
        }
    }
    return last_cond_node->cmp;
}

status_t sql_set_node_type_by_keyword(sql_stmt_t *stmt, word_t *word, cmp_type_t *type)
{
    uint32 match_id;
    lex_t *lex = stmt->session->lex;
    CM_POINTER3(stmt, word, type);

    switch (word->id) {
        case (uint32)KEY_WORD_NOT:
            CT_RETURN_IFERR(lex_expected_fetch_1ofn(lex, &match_id, 4, "IN", "BETWEEN", "LIKE", "REGEXP"));
            if (0 == match_id) {
                *type = CMP_TYPE_NOT_IN;
            } else if (1 == match_id) {
                *type = CMP_TYPE_NOT_BETWEEN;
            } else if (2 == match_id) {
                *type = CMP_TYPE_NOT_LIKE;
            } else if (3 == match_id) {
                *type = CMP_TYPE_NOT_REGEXP;
            }
            break;
        case (uint32)KEY_WORD_IN:
            *type = CMP_TYPE_IN;
            break;

        case (uint32)KEY_WORD_BETWEEN:
            *type = CMP_TYPE_BETWEEN;
            break;

        case (uint32)KEY_WORD_IS: {
            bool32 match_not = CT_FALSE;
            CT_RETURN_IFERR(lex_try_fetch(lex, "NOT", &match_not));

            CT_RETURN_IFERR(lex_expected_fetch_1of2(lex, "NULL", "JSON", &match_id));
            if (0 == match_id) {
                *type = match_not ? CMP_TYPE_IS_NOT_NULL : CMP_TYPE_IS_NULL;
                break;
            }

            *type = match_not ? CMP_TYPE_IS_NOT_JSON : CMP_TYPE_IS_JSON;
            break;
        }
        case (uint32)KEY_WORD_LIKE:
            *type = CMP_TYPE_LIKE;
            break;

        case (uint32)KEY_WORD_REGEXP:
            *type = CMP_TYPE_REGEXP;
            // fall through

        default:
            break;
    }

    return CT_SUCCESS;
}

status_t sql_set_comp_nodetype(sql_stmt_t *stmt, word_t *word, cmp_type_t *cmp_type)
{
    CM_POINTER3(stmt, word, cmp_type);

    switch (word->type) {
        case WORD_TYPE_COMPARE:
            *cmp_type = word->id;
            break;
        case WORD_TYPE_KEYWORD:
            if (!word->namable || word->id == KEY_WORD_REGEXP) {
                return sql_set_node_type_by_keyword(stmt, word, cmp_type);
            }
            break;
        default:
            return CT_SUCCESS;
    }

    return CT_SUCCESS;
}

status_t sql_identify_comp_node_type(sql_stmt_t *stmt, word_t *word, cmp_node_t *cmp_node)
{
    lex_t *lex = stmt->session->lex;

    bool32 is_true1 = (cmp_node->left == NULL) &&
        ((IS_UNNAMABLE_KEYWORD(word) && word->id != KEY_WORD_CASE) || word->id == KEY_WORD_REGEXP_LIKE);
    bool32 is_true2 = (cmp_node->left == NULL) && (((uint32)word->type & (uint32)EXPR_VAR_WORDS) ||
        (word->type == WORD_TYPE_OPERATOR));
    /* if first word is key word, only hit regexp_like  or exist cond, so it can identified the cmp ype */
    if (is_true1) {
        switch (word->id) {
            case KEY_WORD_EXISTS:
                cmp_node->type = CMP_TYPE_EXISTS;
                return sql_parse_exists(stmt, cmp_node, word);
            case KEY_WORD_REGEXP_LIKE:
                cmp_node->type = CMP_TYPE_REGEXP_LIKE;
                if (word->ex_count != 1) {
                    CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "(...) expected but %s found", W2S(word));
                    return CT_ERROR;
                }
                CT_RETURN_IFERR(sql_create_expr_list(stmt, &word->ex_words[0].text, &cmp_node->right));
                // PL CONTEXT, we need to support like 'regexp_like(...) = true'
                if (stmt->pl_compiler) {
                    LEX_SAVE(lex);
                    CT_RETURN_IFERR(lex_fetch(lex, word));
                    CT_RETURN_IFERR(sql_parse_regexp_like_right(stmt, cmp_node, word));
                    if (word->id != CMP_TYPE_EQUAL && word->id != CMP_TYPE_NOT_EQUAL) {
                        LEX_RESTORE(lex);
                    }
                }
                return CT_SUCCESS;
            default: {
                CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "the \"%s\" is not a correct keyword",
                    T2S(&word->text));
                return CT_ERROR;
            }
        }
    }
    /* if the first word is variant, it must be expr or expr list */
    if (is_true2) {
        lex_back(lex, word);
        CT_RETURN_IFERR(sql_create_expr_until(stmt, &cmp_node->left, word));
    }

    /* if cond->left have been resolved, so cmp type is decided the next word */
    is_true1 = word->type == WORD_TYPE_COMPARE || word->type == WORD_TYPE_KEYWORD;
    if (is_true1) {
        if (cmp_node->left == NULL || cmp_node->left->root == NULL || cmp_node->type != CMP_TYPE_UNKNOWN) {
            CT_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "expect expression but comparison is found");
            return CT_ERROR;
        }

        return sql_set_comp_nodetype(stmt, word, &cmp_node->type);
    }

    return CT_SUCCESS;
}

static inline status_t sql_create_cmp_false(cmp_node_t *cmp_node, word_t *word)
{
    if (cmp_node->left == NULL && cmp_node->right == NULL) {
        CT_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "failed to create compare node");
        return CT_ERROR;
    }
    cmp_node->right = cmp_node->left;
    cmp_node->type = CMP_TYPE_NOT_EQUAL;
    return CT_SUCCESS;
}

static status_t sql_parse_compare_right(sql_stmt_t *stmt, cmp_node_t *cmp_node, word_t *word)
{
    switch (cmp_node->type) {
        case CMP_TYPE_EQUAL_ANY:
        case CMP_TYPE_NOT_EQUAL_ANY:
        case CMP_TYPE_GREAT_EQUAL_ANY:
        case CMP_TYPE_GREAT_ANY:
        case CMP_TYPE_LESS_ANY:
        case CMP_TYPE_LESS_EQUAL_ANY:
        case CMP_TYPE_EQUAL:
        case CMP_TYPE_GREAT_EQUAL:
        case CMP_TYPE_GREAT:
        case CMP_TYPE_LESS:
        case CMP_TYPE_LESS_EQUAL:
        case CMP_TYPE_NOT_EQUAL:
        case CMP_TYPE_EQUAL_ALL:
        case CMP_TYPE_NOT_EQUAL_ALL:
        case CMP_TYPE_GREAT_EQUAL_ALL:
        case CMP_TYPE_GREAT_ALL:
        case CMP_TYPE_LESS_ALL:
        case CMP_TYPE_LESS_EQUAL_ALL:

            return sql_parse_group_compare_right(stmt, cmp_node, word);
        case CMP_TYPE_LIKE:
        case CMP_TYPE_NOT_LIKE:
            return sql_parse_like(stmt, cmp_node, word);

        case CMP_TYPE_IN:
        case CMP_TYPE_NOT_IN:
            return sql_parse_in(stmt, cmp_node, word);

        case CMP_TYPE_BETWEEN:
        case CMP_TYPE_NOT_BETWEEN:
            return sql_parse_between(stmt, cmp_node, word);

        case CMP_TYPE_REGEXP:
        case CMP_TYPE_NOT_REGEXP:
            return sql_parse_regexp(stmt, cmp_node, word);
        /* is [not] null/[not] exist/[not] regexp_like/ cond no need to process again */
        case CMP_TYPE_IS_NULL:
        case CMP_TYPE_IS_NOT_NULL:
        case CMP_TYPE_IS_JSON:
        case CMP_TYPE_IS_NOT_JSON:
        case CMP_TYPE_EXISTS:
        case CMP_TYPE_NOT_EXISTS:
        case CMP_TYPE_REGEXP_LIKE:
        case CMP_TYPE_NOT_REGEXP_LIKE:
            return lex_fetch(stmt->session->lex, word);
        default:
            CT_RETURN_IFERR(sql_create_cmp_false(cmp_node, word));
            return sql_create_const_expr_false(stmt, &cmp_node->left, word, 0);
    }
}

static status_t sql_parse_compare(sql_stmt_t *stmt, cond_tree_t *cond, word_t *word)
{
    cond_node_t *last_cond_node = cond->chain.last;
    cmp_node_t *cmp_node = sql_get_last_comp_node(stmt, cond, word);
    if (cmp_node == NULL) {
        return CT_ERROR;
    }

    /* logical node must appear between two cmp node
       cmp --> cmp is invalid */
    if (last_cond_node == cond->chain.last) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid word '%s' found", W2S(word));
        return CT_ERROR;
    }

    if (cmp_node->type == CMP_TYPE_UNKNOWN) {
        CT_RETURN_IFERR(sql_identify_comp_node_type(stmt, word, cmp_node));
    }

    return sql_parse_compare_right(stmt, cmp_node, word);
}

status_t sql_check_select_expr(sql_stmt_t *stmt, sql_text_t *text, bool32 *is_select)
{
    lex_t *lex = stmt->session->lex;
    word_t word;

    if (text->len == 0) {
        CT_SRC_THROW_ERROR(text->loc, ERR_SQL_SYNTAX_ERROR, "expression expected");
        return CT_ERROR;
    }
    // FALSE:  ((select 1 from sys_dummy)) in (1,2)
    // FALSE   ((select 1 from sys_dummy), (select 2 from sys_dummy)) in ((1,1), (1,2))
    // TRUE:   (select 1 from sys_dummy) in (1,2)
    CT_RETURN_IFERR(lex_push(lex, text));
    CT_RETURN_IFERR(lex_fetch(lex, &word));

    if (word.id == KEY_WORD_SELECT || word.id == KEY_WORD_WITH) {
        *is_select = CT_TRUE;
    }
    lex_pop(lex);

    return CT_SUCCESS;
}

status_t sql_parse_in_subselect(sql_stmt_t *stmt, expr_tree_t **expr, word_t *word)
{
    if (sql_create_expr_from_text(stmt, &word->text, expr, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    sql_select_t *select_ctx = (sql_select_t *)(*expr)->root->value.v_obj.ptr;
    select_ctx->type = SELECT_AS_LIST;
    return CT_SUCCESS;
}

static status_t sql_try_parse_bracket(sql_stmt_t *stmt, cond_tree_t *cond, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    word_t next_word;
    cond_tree_t *sub_tree = NULL;
    bool32 is_expr = CT_FALSE;
    cmp_type_t type = CMP_TYPE_UNKNOWN;
    cmp_node_t *cmp_node = NULL;

    LEX_SAVE(lex);
    CT_RETURN_IFERR(lex_fetch(lex, &next_word));
    /* hit select * from sys_dummy where (102+108+102+108+102+108)/6.0 = (105+105)/2.0; */
    if (next_word.type == WORD_TYPE_OPERATOR) {
        LEX_RESTORE(lex);
        return sql_parse_compare(stmt, cond, word);
    }

    /* according the next word to judge is bracket is expr or cond */
    if (next_word.type == WORD_TYPE_COMPARE || next_word.type == WORD_TYPE_KEYWORD) {
        CT_RETURN_IFERR(sql_set_comp_nodetype(stmt, &next_word, &type));
    }

    if (type == CMP_TYPE_UNKNOWN) {
        LEX_RESTORE(lex);
        CT_RETURN_IFERR(sql_create_cond_from_text(stmt, &word->text, &sub_tree, &is_expr));

        if (!is_expr) {
            CT_LOG_DEBUG_INF("condition tree m_chain appends sub-CondTree");
            APPEND_CHAIN(&cond->chain, sub_tree->root);
            return lex_fetch(stmt->session->lex, word);
        } else {
            CT_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "invalid condition expr");
            return CT_ERROR;
        }
    } else {
        cmp_node = sql_get_last_comp_node(stmt, cond, word);
        CT_RETVALUE_IFTRUE(cmp_node == NULL, CT_ERROR);
        cmp_node->type = type;

        if (IS_MEMBERSHIP_COND_TYPE(type)) {
            bool32 select_expr = CT_FALSE;
            CT_RETURN_IFERR(sql_check_select_expr(stmt, &word->text, &select_expr));
            if (select_expr) {
                word_t left_word;
                left_word.text = word->text;
                expr_tree_t *cur_expr = NULL;
                CT_RETURN_IFERR(sql_parse_in_subselect(stmt, &cur_expr, &left_word));
                cmp_node->left = cur_expr;
            } else {
                CT_RETURN_IFERR(sql_create_expr_list(stmt, &word->text, &cmp_node->left));
            }
        } else {
            CT_RETURN_IFERR(sql_create_expr_from_text(stmt, &word->text, &cmp_node->left, WORD_FLAG_NONE));
        }

        return sql_parse_compare_right(stmt, cmp_node, word);
    }
}

static key_word_t g_cause_key_words[] = {
    { (uint32)KEY_WORD_FULL,    CT_TRUE, { (char *)"full", 4 } },
    { (uint32)KEY_WORD_INNER,   CT_TRUE, { (char *)"inner", 5 } },
    { (uint32)KEY_WORD_JOIN,    CT_TRUE, { (char *)"join", 4 } },
    { (uint32)KEY_WORD_LIMIT,   CT_TRUE, { (char *)"limit", 5 } },
    { (uint32)KEY_WORD_LOOP,    CT_TRUE, { (char *)"loop", 4 } },
    { (uint32)KEY_WORD_PIVOT,   CT_TRUE, { (char *)"pivot", 5 } },
    { (uint32)KEY_WORD_UNPIVOT, CT_TRUE, { (char *)"unpivot", 7} },
    { (uint32)KEY_WORD_WHEN,    CT_TRUE, { (char *)"when", 4 } }
};

static status_t sql_add_cond_words(sql_stmt_t *stmt, word_t *word, cond_tree_t *cond, bool32 *is_expr)
{
    bool32 is_logical;

    if (word->type == WORD_TYPE_BRACKET) {
        return sql_try_parse_bracket(stmt, cond, word);
    }

    is_logical = (word->id == KEY_WORD_NOT) && (cond->chain.count == 0 || IS_LOGICAL_NODE(cond->chain.last));
    if (is_logical) {
        if (sql_create_cond_node(stmt, cond, COND_NODE_NOT) != CT_SUCCESS) {
            return CT_ERROR;
        }
        return lex_fetch(stmt->session->lex, word);
    }

    is_logical = (word->id == KEY_WORD_AND) || (word->id == KEY_WORD_OR);
    if (is_logical) {
        if (sql_parse_logic_node(stmt, cond, word) != CT_SUCCESS) {
            return CT_ERROR;
        }
        return lex_fetch(stmt->session->lex, word);
    }

    return sql_parse_compare(stmt, cond, word);
}

status_t sql_create_cond_from_text(sql_stmt_t *stmt, sql_text_t *text, cond_tree_t **cond, bool32 *is_expr)
{
    lex_t *lex = NULL;
    word_t word;
    bool32 has_in_cond;

    CM_POINTER4(stmt, text, cond, is_expr);
    CT_RETURN_IFERR(sql_stack_safe(stmt));

    word.id = KEY_WORD_0_UNKNOWN;
    lex = stmt->session->lex;
    has_in_cond = (lex->flags & LEX_IN_COND);
    lex->flags |= LEX_IN_COND;
    cm_trim_text((text_t *)text);
    if (text->len == 0) {
        CT_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "more comparision expected");
        return CT_ERROR;
    }

    if (lex_push(lex, text) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    if (sql_create_cond_tree(stmt->context, cond) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    (*cond)->loc = text->loc;
    if (lex_fetch(lex, &word) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    for (;;) {
        if (sql_add_cond_words(stmt, &word, *cond, is_expr) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }
        CT_BREAK_IF_TRUE(word.type == WORD_TYPE_EOF);
    }

    lex_pop(lex);
    if (!has_in_cond) {
        lex->flags &= ~LEX_IN_COND;
    }

    if (sql_generate_cond(stmt, *cond, is_expr) != CT_SUCCESS) {
        cm_try_set_error_loc(word.text.loc);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static bool32 check_clause_word_is_in_condition(sql_stmt_t *stmt, lex_t *lex)
{
    cmp_type_t cmp_type = CMP_TYPE_UNKNOWN;
    word_t tmp_word;

    LEX_SAVE(lex);
    do {
        CT_BREAK_IF_ERROR(lex_fetch(lex, &tmp_word));
        CT_BREAK_IF_ERROR(sql_set_comp_nodetype(stmt, &tmp_word, &cmp_type));
    } while (0);
    LEX_RESTORE(lex);
    cm_reset_error();
    return (cmp_type != CMP_TYPE_UNKNOWN);
}

status_t sql_create_cond_until(sql_stmt_t *stmt, cond_tree_t **cond, word_t *word)
{
    sql_text_t cond_text;
    lex_t *lex = stmt->session->lex;
    bool32 is_expr = CT_FALSE;
    key_word_t *save_key_words = lex->key_words;
    uint32 save_key_word_count = lex->key_word_count;

    /* arranged lexicographically */
    lex->flags |= LEX_IN_COND;
    CT_RETURN_IFERR(sql_create_cond_tree(stmt->context, cond));
    (*cond)->loc = word->text.loc;
    cond_text = *lex->curr_text;
    CT_RETURN_IFERR(lex_fetch(lex, word));

    if (word->type == WORD_TYPE_EOF) {
        CT_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "more text expected but terminated");
        return CT_ERROR;
    }

    lex->key_words = g_cause_key_words;
    lex->key_word_count = ELEMENT_COUNT(g_cause_key_words);

    for (;;) {
        if (sql_add_cond_words(stmt, word, *cond, &is_expr) != CT_SUCCESS) {
            lex->key_words = save_key_words;
            lex->key_word_count = save_key_word_count;
            return CT_ERROR;
        }
        /* If the conditional split keyword can be named and used as function, it should separate judement, othewise
           should be fill in g_cause_key_words array */
        if (word->type == WORD_TYPE_EOF || IS_SPEC_CHAR(word, ';') || IS_KEY_WORD(word, KEY_WORD_LEFT) ||
            IS_KEY_WORD(word, KEY_WORD_RIGHT) || IS_KEY_WORD(word, KEY_WORD_CROSS) || IS_SPEC_CHAR(word, ',') ||
            (IS_CLAUSE_WORD(word->id) && (!word->namable || !check_clause_word_is_in_condition(stmt, lex)))) {
            break;
        }
    }

    lex->flags &= ~LEX_IN_COND;
    if (sql_generate_cond(stmt, *cond, &is_expr) != CT_SUCCESS) {
        lex->key_words = save_key_words;
        lex->key_word_count = save_key_word_count;
        cm_try_set_error_loc(word->text.loc);
        return CT_ERROR;
    }

    lex->key_words = save_key_words;
    lex->key_word_count = save_key_word_count;
    if (is_expr) {
        CT_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "expect condition text");
        return CT_ERROR;
    }
    cond_text.len = (uint32)(word->text.str - cond_text.str);
    CT_LOG_DEBUG_INF("parse condition text\"%s\" sucessfully", T2S((text_t *)&cond_text));

    return CT_SUCCESS;
}

static inline void sql_down_cond_node(cond_tree_t *cond, cond_node_t *down_node)
{
    down_node->left = down_node->prev;
    down_node->right = down_node->next;

    down_node->next = down_node->next->next;
    down_node->prev = down_node->prev->prev;

    if (down_node->prev != NULL) {
        down_node->prev->next = down_node;
    } else {
        cond->chain.first = down_node;
    }

    if (down_node->next != NULL) {
        down_node->next->prev = down_node;
    } else {
        cond->chain.last = down_node;
    }

    down_node->left->prev = NULL;
    down_node->left->next = NULL;
    down_node->right->prev = NULL;
    down_node->right->next = NULL;

    cond->chain.count -= 2;
}

/* !
 * \brief
 *
 * Adding some comments and optimizing the codes
 */
static status_t sql_form_cond_with_logic(cond_tree_t *cond, cond_node_type_t type)
{
    cond_node_t *prev = NULL;
    cond_node_t *next = NULL;
    cond_node_t *node = NULL;

    /* node->left != NULL states node is a cond tree
     * chain  AND   AND  cmp_expr OR cmp_expr
     * /   \
     * left  right
     * get next cond node ,merge node is needed at least two node */
    node = cond->chain.first->next;
    while (node != NULL) {
        if (node->type != type || node->left != NULL) {
            node = node->next;
            continue;
        }

        prev = node->prev;
        next = node->next;

        /* if is not a correct condition */
        if (prev == NULL || next == NULL) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "condition parsing error");
            return CT_ERROR;
        }

        sql_down_cond_node(cond, node);
        node = node->next;
    }

    return CT_SUCCESS;
}

#define CMP_TYPE_IDX(type) ((type) - CMP_TYPE_EQUAL)
#define GET_CMP_NODE_CVT_TYPE(type) (g_cmp_node_cvt_rule[CMP_TYPE_IDX(type)])

static cmp_type_t g_cmp_node_cvt_rule[] =
{
    [CMP_TYPE_IDX(CMP_TYPE_EQUAL)] = CMP_TYPE_NOT_EQUAL,
    [CMP_TYPE_IDX(CMP_TYPE_GREAT_EQUAL)] = CMP_TYPE_LESS,
    [CMP_TYPE_IDX(CMP_TYPE_GREAT)] = CMP_TYPE_LESS_EQUAL,
    [CMP_TYPE_IDX(CMP_TYPE_LESS)] = CMP_TYPE_GREAT_EQUAL,
    [CMP_TYPE_IDX(CMP_TYPE_LESS_EQUAL)] = CMP_TYPE_GREAT,
    [CMP_TYPE_IDX(CMP_TYPE_NOT_EQUAL)] = CMP_TYPE_EQUAL,
    [CMP_TYPE_IDX(CMP_TYPE_EQUAL_ANY)] = CMP_TYPE_NOT_IN, // NOT IN <=> <> ALL
    [CMP_TYPE_IDX(CMP_TYPE_NOT_EQUAL_ANY)] = CMP_TYPE_EQUAL_ALL,
    [CMP_TYPE_IDX(CMP_TYPE_GREAT_ANY)] = CMP_TYPE_LESS_EQUAL_ALL,
    [CMP_TYPE_IDX(CMP_TYPE_GREAT_EQUAL_ANY)] = CMP_TYPE_LESS_ALL,
    [CMP_TYPE_IDX(CMP_TYPE_LESS_EQUAL_ANY)] = CMP_TYPE_GREAT_ALL,
    [CMP_TYPE_IDX(CMP_TYPE_LESS_ANY)] = CMP_TYPE_GREAT_EQUAL_ALL,
    [CMP_TYPE_IDX(CMP_TYPE_EQUAL_ALL)] = CMP_TYPE_NOT_EQUAL_ANY,
    [CMP_TYPE_IDX(CMP_TYPE_NOT_EQUAL_ALL)] = CMP_TYPE_IN, // IN <=> =ANY
    [CMP_TYPE_IDX(CMP_TYPE_GREAT_ALL)] = CMP_TYPE_LESS_EQUAL_ANY,
    [CMP_TYPE_IDX(CMP_TYPE_GREAT_EQUAL_ALL)] = CMP_TYPE_LESS_ANY,
    [CMP_TYPE_IDX(CMP_TYPE_LESS_EQUAL_ALL)] = CMP_TYPE_GREAT_ANY,
    [CMP_TYPE_IDX(CMP_TYPE_LESS_ALL)] = CMP_TYPE_GREAT_EQUAL_ANY,
    [CMP_TYPE_IDX(CMP_TYPE_IS_NULL)] = CMP_TYPE_IS_NOT_NULL,
    [CMP_TYPE_IDX(CMP_TYPE_IS_NOT_NULL)] = CMP_TYPE_IS_NULL,
    [CMP_TYPE_IDX(CMP_TYPE_IS_JSON)] = CMP_TYPE_IS_NOT_JSON,
    [CMP_TYPE_IDX(CMP_TYPE_IS_NOT_JSON)] = CMP_TYPE_IS_JSON,
    [CMP_TYPE_IDX(CMP_TYPE_IN)] = CMP_TYPE_NOT_IN,
    [CMP_TYPE_IDX(CMP_TYPE_NOT_IN)] = CMP_TYPE_IN,
    [CMP_TYPE_IDX(CMP_TYPE_LIKE)] = CMP_TYPE_NOT_LIKE,
    [CMP_TYPE_IDX(CMP_TYPE_NOT_LIKE)] = CMP_TYPE_LIKE,
    [CMP_TYPE_IDX(CMP_TYPE_REGEXP)] = CMP_TYPE_NOT_REGEXP,
    [CMP_TYPE_IDX(CMP_TYPE_NOT_REGEXP)] = CMP_TYPE_REGEXP,
    [CMP_TYPE_IDX(CMP_TYPE_BETWEEN)] = CMP_TYPE_NOT_BETWEEN,
    [CMP_TYPE_IDX(CMP_TYPE_NOT_BETWEEN)] = CMP_TYPE_BETWEEN,
    [CMP_TYPE_IDX(CMP_TYPE_EXISTS)] = CMP_TYPE_NOT_EXISTS,
    [CMP_TYPE_IDX(CMP_TYPE_NOT_EXISTS)] = CMP_TYPE_EXISTS,
    [CMP_TYPE_IDX(CMP_TYPE_REGEXP_LIKE)] = CMP_TYPE_NOT_REGEXP_LIKE,
    [CMP_TYPE_IDX(CMP_TYPE_NOT_REGEXP_LIKE)] = CMP_TYPE_REGEXP_LIKE,
};

static status_t sql_convert_cmp_node(cmp_node_t *cmp)
{
    cmp->type = GET_CMP_NODE_CVT_TYPE(cmp->type);
    return CT_SUCCESS;
}

static status_t sql_conver_not_node(sql_stmt_t *stmt, cond_node_t *node)
{
    CT_RETURN_IFERR(sql_stack_safe(stmt));
    switch (node->type) {
        case COND_NODE_TRUE:
            node->type = COND_NODE_FALSE;
            break;

        case COND_NODE_FALSE:
            node->type = COND_NODE_TRUE;
            break;

        case COND_NODE_COMPARE:
            CT_RETURN_IFERR(sql_convert_cmp_node(node->cmp));
            break;

        case COND_NODE_OR:
            node->type = COND_NODE_AND;
            CT_RETURN_IFERR(sql_conver_not_node(stmt, node->left));
            CT_RETURN_IFERR(sql_conver_not_node(stmt, node->right));
            break;

        case COND_NODE_AND:
            node->type = COND_NODE_OR;
            CT_RETURN_IFERR(sql_conver_not_node(stmt, node->left));
            CT_RETURN_IFERR(sql_conver_not_node(stmt, node->right));
            break;
        /* not not expr equal expr */
        case COND_NODE_NOT:
            if (node->next == NULL) {
                CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "condition parsing error, 'not' condition convert failed");
                return CT_ERROR;
            }
            break;
        case COND_NODE_UNKNOWN:
        default:
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "condition parsing error, 'not' condition convert failed");
            return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_form_cond_with_not(sql_stmt_t *stmt, cond_tree_t *cond_tree)
{
    cond_node_t *node = cond_tree->chain.first;

    do {
        if (node->type != COND_NODE_NOT) {
            node = node->next;
            continue;
        }
        /* if is not a correct condition */
        if (node->next == NULL) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "condition parsing error");
            return CT_ERROR;
        }
        if (sql_conver_not_node(stmt, node->next) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (node->next->type == COND_NODE_NOT) {
            if (node->prev != NULL) {
                node->prev->next = node->next->next;
            } else {
                cond_tree->chain.first = node->next->next;
            }
            node->next->next->prev = node->prev;
            node->left = NULL;
            node->right = NULL;
            node->next->left = NULL;
            node->next->right = NULL;
            cond_tree->chain.count -= 2;
            node = node->next->next;
        } else {
            if (node->prev != NULL) {
                node->prev->next = node->next;
            } else {
                cond_tree->chain.first = node->next;
            }
            node->next->prev = node->prev;
            node->left = NULL;
            node->right = NULL;
            cond_tree->chain.count -= 1;
            node = node->next;
        }
    } while (node != NULL);
    return CT_SUCCESS;
}

static status_t sql_generate_cond(sql_stmt_t *stmt, cond_tree_t *cond, bool32 *is_expr)
{
    cond_node_t *node = NULL;
    cmp_node_t *cmp_node = NULL;

    if (cond->chain.count == 0) {
        CT_SRC_THROW_ERROR(cond->loc, ERR_SQL_SYNTAX_ERROR, "condition error");
        return CT_ERROR;
    }
    node = cond->chain.first;

    if (node->next == NULL && node->type == COND_NODE_COMPARE) {
        cmp_node = node->cmp;
        if (cmp_node->type == CMP_TYPE_UNKNOWN) {
            *is_expr = CT_TRUE;
            return CT_SUCCESS;
        }
    }
    *is_expr = CT_FALSE;
    if (sql_form_cond_with_not(stmt, cond) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_form_cond_with_logic(cond, COND_NODE_AND) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_form_cond_with_logic(cond, COND_NODE_OR) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cond->chain.count != 1) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "condition error");
        return CT_ERROR;
    }

    cond->root = cond->chain.first;
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
