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
 * expr_parser.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser/expr_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __EXPR_PARSER_H__
#define __EXPR_PARSER_H__

#include "ctsql_expr.h"
#include "knl_database.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IS_DUAL_TABLE_NAME(tab_name) \
    (cm_text_str_equal_ins(tab_name, "DUAL") || cm_text_str_equal(tab_name, "SYS_DUMMY"))

static inline status_t sql_word_as_table(sql_stmt_t *stmt, word_t *word, var_word_t *var)
{
    if (word->ex_count == 0) {
        if (sql_copy_object_name_loc(stmt->context, word->type, &word->text, &var->table.name) != CT_SUCCESS) {
            return CT_ERROR;
        }
        var->table.user.loc = word->text.loc;
        var->table.user.implicit = CT_TRUE;
        text_t user_name = { stmt->session->curr_schema, (uint32)strlen(stmt->session->curr_schema) };
        if (IS_DUAL_TABLE_NAME(&var->table.name.value)) {
            cm_text_upper(&var->table.name.value);
        }

        if (sql_copy_name(stmt->context, &user_name, (text_t *)&var->table.user) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else if (word->ex_count == 1) {
        if (sql_copy_object_name_loc(stmt->context, word->ex_words[0].type, &word->ex_words[0].text,
            &var->table.name) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (sql_copy_name_prefix_tenant_loc(stmt, &word->text, &var->table.user) != CT_SUCCESS) {
            return CT_ERROR;
        }
        var->table.user.implicit = CT_FALSE;
        if (cm_text_str_equal_ins(&var->table.user.value, "SYS") && IS_DUAL_TABLE_NAME(&var->table.name.value)) {
            cm_text_upper(&var->table.name.value);
        }
    } else {
        CT_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid table name");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static inline status_t sql_word_as_column(sql_stmt_t *stmt, word_t *word, var_word_t *var)
{
    if (word->ex_count == 0) {
        CT_RETURN_IFERR(sql_copy_object_name_loc(stmt->context, word->type, &word->text, &var->column.name));

        var->column.table.value = CM_NULL_TEXT;
        var->column.table.loc = word->text.loc;

        var->column.user.value = CM_NULL_TEXT;
        var->column.user.loc = word->text.loc;
    } else if (word->ex_count == 1) {
        CT_RETURN_IFERR(sql_copy_object_name_loc(stmt->context, word->ex_words[0].type, &word->ex_words[0].text,
            &var->column.name));

        CT_RETURN_IFERR(
            sql_copy_object_name_loc(stmt->context, word->type | word->ori_type, &word->text, &var->column.table));

        CT_RETURN_IFERR(sql_copy_name_prefix_tenant_loc(stmt, &word->text, &var->column.user_ex));

        var->column.user.value = CM_NULL_TEXT;
        var->column.user.loc = word->text.loc;
    } else if (word->ex_count == 2) {
        CT_RETURN_IFERR(sql_copy_object_name_loc(stmt->context, word->ex_words[1].type, &word->ex_words[1].text,
            &var->column.name));

        CT_RETURN_IFERR(sql_copy_object_name_loc(stmt->context, word->ex_words[0].type, &word->ex_words[0].text,
            &var->column.table));

        CT_RETURN_IFERR(sql_copy_name_prefix_tenant_loc(stmt, &word->text, &var->column.user));
    } else {
        CT_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid column name is found");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static inline status_t sql_word_as_func(sql_stmt_t *stmt, word_t *word, var_word_t *var_word)
{
    if (word->ex_count == 0) {
        CT_RETURN_IFERR(
            sql_copy_object_name_loc(stmt->context, word->type | word->ori_type, &word->text, &var_word->func.name));

        var_word->func.args.value = CM_NULL_TEXT;
        var_word->func.args.loc = word->text.loc;
        var_word->func.pack.value = CM_NULL_TEXT;
        var_word->func.pack.loc = word->text.loc;
        var_word->func.user.value = CM_NULL_TEXT;
        var_word->func.user.loc = word->text.loc;
    } else if (word->ex_count == 1) {
        CT_RETURN_IFERR(
            sql_copy_object_name_loc(stmt->context, word->type | word->ori_type, &word->text, &var_word->func.name));

        var_word->func.args = word->ex_words[0].text;
        var_word->func.pack.value = CM_NULL_TEXT;
        var_word->func.pack.loc = word->text.loc;
        var_word->func.user.value = CM_NULL_TEXT;
        var_word->func.user.loc = word->text.loc;
    } else if (word->ex_count == 2) {
        CT_RETURN_IFERR(sql_copy_object_name_loc(stmt->context, word->ori_type,
                                                 &word->text, &var_word->func.org_user));
        CT_RETURN_IFERR(sql_copy_object_name_prefix_tenant_loc(stmt, word->ori_type,
                                                               &word->text, &var_word->func.user));
        CT_RETURN_IFERR(
            sql_copy_object_name_loc(stmt->context, word->ex_words[0].type,
                                     &word->ex_words[0].text, &var_word->func.name));

        var_word->func.args = word->ex_words[1].text;
        var_word->func.pack.value = CM_NULL_TEXT;
        var_word->func.pack.loc = word->text.loc;
    } else if (word->ex_count == 3) {
        CT_RETURN_IFERR(
            sql_copy_object_name_loc(stmt->context, word->ex_words[1].type,
                                     &word->ex_words[1].text, &var_word->func.name));

        CT_RETURN_IFERR(
            sql_copy_object_name_loc(stmt->context, word->ex_words[0].type,
                                     &word->ex_words[0].text, &var_word->func.pack));

        CT_RETURN_IFERR(sql_copy_name_prefix_tenant_loc(stmt, &word->text, &var_word->func.user));

        var_word->func.args = word->ex_words[2].text;
    } else {
        CT_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid function or procedure name is found");
        return CT_ERROR;
    }

    var_word->func.count = word->ex_count;

    return CT_SUCCESS;
}


#define EXPR_EXPECT_NONE 0x00000000
#define EXPR_EXPECT_UNARY_OP 0x00000001
#define EXPR_EXPECT_OPER 0x00000002
#define EXPR_EXPECT_VAR 0x00000004
#define EXPR_EXPECT_UNARY 0x00000008
#define EXPR_EXPECT_STAR 0x00000010
#define EXPR_EXPECT_ALPHA 0x00000020

/* The modes of datatype parsing */
typedef enum en_parsing_mode {
    PM_NORMAL, /* parsing SQL column datatype or cast function  */
    PM_PL_VAR, /* parsing for procedure variables */
    PM_PL_ARG, /* parsing for procedure argument, no type attr is allowed */
} pmode_t;

status_t sql_create_expr_until(sql_stmt_t *stmt, expr_tree_t **expr, word_t *word);
status_t sql_create_expr_from_text(sql_stmt_t *stmt, sql_text_t *text, expr_tree_t **expr, word_flag_t word_flag);
status_t sql_create_expr_list(sql_stmt_t *stmt, sql_text_t *text, expr_tree_t **expr);
status_t sql_create_expr(sql_stmt_t *stmt, expr_tree_t **expr);
status_t sql_add_expr_word(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word);
status_t sql_create_expr_from_word(sql_stmt_t *stmt, word_t *word, expr_tree_t **expr);
status_t sql_generate_expr(expr_tree_t *expr);
status_t sql_parse_typmode(lex_t *lex, pmode_t pmod, typmode_t *typmod, word_t *typword);
status_t sql_parse_datatype(lex_t *lex, pmode_t pmod, typmode_t *typmod, word_t *typword);
status_t sql_parse_datatype_typemode(lex_t *lex, pmode_t pmod, typmode_t *typmod, word_t *typword, word_t *tword);
status_t sql_parse_case_expr(sql_stmt_t *stmt, word_t *word, expr_node_t *node);
status_t sql_build_default_reserved_expr(sql_stmt_t *stmt, expr_tree_t **r_result);
status_t sql_build_column_expr(sql_stmt_t *stmt, knl_column_t *column, expr_tree_t **r_result);
status_t sql_copy_text_remove_quotes(sql_context_t *context, text_t *src, text_t *dst);
status_t sql_word2text(sql_stmt_t *stmt, word_t *word, expr_node_t *node);
status_t sql_word2number(word_t *word, expr_node_t *node);

#define EXPR_VAR_WORDS                                                                                        \
    (WORD_TYPE_VARIANT | WORD_TYPE_FUNCTION | WORD_TYPE_STRING | WORD_TYPE_PARAM | WORD_TYPE_NUMBER |         \
        WORD_TYPE_RESERVED | WORD_TYPE_DATATYPE | WORD_TYPE_BRACKET | WORD_TYPE_KEYWORD | WORD_TYPE_PL_ATTR | \
        WORD_TYPE_PL_NEW_COL | WORD_TYPE_PL_OLD_COL | WORD_TYPE_DQ_STRING | WORD_TYPE_HEXADECIMAL |           \
        WORD_TYPE_JOIN_COL | WORD_TYPE_ARRAY)

#define EXPR_IS_UNARY_OP(word)                                                             \
    ((word)->type == (uint32)WORD_TYPE_OPERATOR && ((word)->id == (uint32)OPER_TYPE_SUB || \
        (word)->id == (uint32)OPER_TYPE_ADD || (word)->id == (uint32)OPER_TYPE_PRIOR))

#define EXPR_IS_UNARY_OP_ROOT(word) \
    ((word)->type == (uint32)WORD_TYPE_OPERATOR && ((word)->id == (uint32)OPER_TYPE_ROOT))

#define EXPR_IS_OPER(word) ((word)->type == (uint32)WORD_TYPE_OPERATOR)

#define EXPR_IS_STAR(word)                                        \
    ((word)->text.len > 0 && CM_TEXT_END(&(word)->text) == '*' && \
        (word)->type != WORD_TYPE_DQ_STRING) /* the last char of word is * */
status_t sql_add_param_mark(sql_stmt_t *stmt, word_t *word, bool32 *is_repeated, uint32 *pnid);

#ifdef __cplusplus
}
#endif

#endif
