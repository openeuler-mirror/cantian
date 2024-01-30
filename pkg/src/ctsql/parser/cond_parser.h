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
 * cond_parser.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser/cond_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __COND_EXPR_H__
#define __COND_EXPR_H__

#include "ctsql_cond.h"
#include "expr_parser.h"


#define IS_COMPARE_COND_TYPE(type) ((type) <= CMP_TYPE_NOT_EQUAL_ANY || (type) >= CMP_TYPE_GREAT_EQUAL_ANY)

#define IS_MEMBERSHIP_COND_TYPE(type) ((type) == CMP_TYPE_IN || (type) == CMP_TYPE_NOT_IN)

#define IS_LOGICAL_NODE(node) \
    ((node)->type == COND_NODE_OR || (node)->type == COND_NODE_NOT || (node)->type == COND_NODE_AND)

#define IS_LOGICAL_WORD(word) ((word)->id == KEY_WORD_OR || (word)->id == KEY_WORD_NOT || (word)->id == KEY_WORD_AND)

#define IS_OBVIOUS_CMP(word)                                                                                   \
    (word)->type == WORD_TYPE_COMPARE &&                                                                       \
        ((word)->id == CMP_TYPE_EQUAL || (word)->id == CMP_TYPE_GREAT_EQUAL || (word)->id == CMP_TYPE_GREAT || \
        (word)->id == CMP_TYPE_LESS || (word)->id == CMP_TYPE_LESS_EQUAL || (word)->id == CMP_TYPE_NOT_EQUAL)

#define IS_CSR_WHERE_END_WORD(id)                                                                                      \
    ((id) == KEY_WORD_FOR || (id) == KEY_WORD_GROUP || (id) == KEY_WORD_ORDER || (id) == KEY_WORD_WHERE ||             \
        (id) == KEY_WORD_HAVING || (id) == KEY_WORD_UNION || (id) == KEY_WORD_MINUS || (id) == KEY_WORD_LIMIT ||       \
        (id) == KEY_WORD_FULL || (id) == KEY_WORD_INNER || (id) == KEY_WORD_JOIN || (id) == KEY_WORD_START ||          \
        (id) == KEY_WORD_CONNECT || (id) == KEY_WORD_LOOP || (id) == KEY_WORD_SET || (id) == KEY_WORD_ON ||            \
        (id) == KEY_WORD_OFFSET || (id) == KEY_WORD_EXCEPT || (id) == KEY_WORD_RETURN || (id) == KEY_WORD_RETURNING || \
        (id) == KEY_WORD_INTERSECT || (id) == KEY_WORD_PIVOT || (id) == KEY_WORD_UNPIVOT)

#define IS_CLAUSE_WORD(id) (IS_CSR_WHERE_END_WORD(id) || (id) == KEY_WORD_WHEN || (id) == KEY_WORD_THEN)

#define MAX_COND_TREE_DEPTH 16

status_t sql_create_cond_until(sql_stmt_t *stmt, cond_tree_t **cond, word_t *word);
status_t sql_create_cond_from_text(sql_stmt_t *stmt, sql_text_t *text, cond_tree_t **cond, bool32 *is_expr);
status_t sql_create_const_expr_false(sql_stmt_t *stmt, expr_tree_t **expr, word_t *word, int32 val);
status_t sql_check_select_expr(sql_stmt_t *stmt, sql_text_t *text, bool32 *is_select);
status_t sql_parse_in_subselect(sql_stmt_t *stmt, expr_tree_t **expr, word_t *word);
cmp_node_t *sql_get_last_comp_node(sql_stmt_t *stmt, cond_tree_t *cond, word_t *word);

#endif
