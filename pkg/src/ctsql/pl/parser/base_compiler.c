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
 * base_compiler.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/parser/base_compiler.c
 *
 * -------------------------------------------------------------------------
 */
#include "base_compiler.h"
#include "pl_memory.h"

void pl_check_and_set_loc(source_location_t source_loc)
{
    int32 l_code;
    const char *l_message = NULL;
    source_location_t l_loc;
    cm_get_error(&l_code, &l_message, &l_loc);
    if (l_loc.line == 0) {
        cm_set_error_loc(source_loc);
        l_loc = source_loc;
    }
    if (g_tls_plc_error.plc_flag) {
        cm_set_superposed_plc_loc(l_loc, l_code, l_message);
    }
}

status_t plc_stack_safe(pl_compiler_t *compiler)
{
    if (sql_stack_safe(compiler->stmt) != CT_SUCCESS) {
        pl_check_and_set_loc(compiler->line_loc);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t plc_verify_expr_node(pl_compiler_t *compiler, expr_node_t *node, void *line, uint32 excl_flags)
{
    sql_verifier_t verif = { 0 };
    verif.context = compiler->stmt->context;
    verif.stmt = compiler->stmt;
    verif.line = line;
    verif.excl_flags = excl_flags;

    if (compiler->root_type == PL_PACKAGE_BODY) {
        verif.obj = compiler->obj;
    }

    if (sql_verify_expr_node(&verif, node) != CT_SUCCESS) {
        pl_check_and_set_loc(node->loc);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t plc_clone_expr_node(pl_compiler_t *compiler, expr_node_t **src_node)
{
    expr_node_t *dst_node = NULL;

    CT_RETURN_IFERR(sql_clone_expr_node(compiler->entity, *src_node, &dst_node, pl_alloc_mem));
    *src_node = dst_node;
    return CT_SUCCESS;
}

status_t plc_clone_cond_tree(pl_compiler_t *compiler, cond_tree_t **src_cond)
{
    cond_tree_t *dst_cond = NULL;

    CT_RETURN_IFERR(sql_clone_cond_tree(compiler->entity, *src_cond, &dst_cond, pl_alloc_mem));
    *src_cond = dst_cond;
    return CT_SUCCESS;
}

status_t plc_clone_expr_tree(pl_compiler_t *compiler, expr_tree_t **src_expr)
{
    expr_tree_t *dst_expr = NULL;

    CT_RETURN_IFERR(sql_clone_expr_tree(compiler->entity, *src_expr, &dst_expr, pl_alloc_mem));
    *src_expr = dst_expr;
    return CT_SUCCESS;
}

status_t plc_verify_limit_expr(pl_compiler_t *compiler, expr_tree_t *expr)
{
    uint32 excl_flags = SQL_LIMIT_EXCL;

    return plc_verify_expr_node(compiler, expr->root, NULL, excl_flags);
}

status_t plc_verify_cond(pl_compiler_t *compiler, cond_tree_t *cond)
{
    sql_verifier_t verif = { 0 };
    verif.stmt = compiler->stmt;
    verif.context = compiler->stmt->context;
    if (compiler->root_type == PL_PACKAGE_BODY) {
        verif.obj = compiler->obj;
    }
    verif.excl_flags = SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_JOIN | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID |
        SQL_EXCL_DEFAULT | SQL_EXCL_SUBSELECT | SQL_EXCL_COLUMN | SQL_EXCL_ROWSCN | SQL_EXCL_WIN_SORT |
        SQL_EXCL_GROUPING | SQL_EXCL_ROWNODEID | SQL_EXCL_METH_PROC | SQL_EXCL_PL_PROC;

    if (sql_verify_cond(&verif, cond) != CT_SUCCESS) {
        pl_check_and_set_loc(cond->loc);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static void plc_concat_join_col_word(text_t *text, uint32 max_len, word_t *word)
{
    int32 i;
    cm_concat_text(text, max_len, (text_t *)&word->text);
    for (i = 0; i < (int32)word->ex_count; i++) { // not overflow
        (void)cm_concat_string(text, max_len, ".");
        PLC_CONCAT_QUOTATION(text, word->ex_words[i].type);
        cm_concat_text(text, max_len, &word->ex_words[i].text.value);
        PLC_CONCAT_QUOTATION(text, word->ex_words[i].type);
    }
    (void)cm_concat_string(text, max_len, "(+)");
}

static void plc_concat_func_word(text_t *text, uint32 max_len, word_t *word)
{
    int32 i;
    cm_concat_text(text, max_len, (text_t *)&word->text);
    for (i = 0; i < (int32)word->ex_count - 1; i++) { // not overflow
        (void)cm_concat_string(text, max_len, ".");
        PLC_CONCAT_QUOTATION(text, word->ex_words[i].type);
        cm_concat_text(text, max_len, &word->ex_words[i].text.value);
        PLC_CONCAT_QUOTATION(text, word->ex_words[i].type);
    }
    (void)cm_concat_string(text, max_len, "(");
    PLC_CONCAT_QUOTATION(text, word->ex_words[i].type);
    cm_concat_text(text, max_len, &word->ex_words[i].text.value);
    PLC_CONCAT_QUOTATION(text, word->ex_words[i].type);
    (void)cm_concat_string(text, max_len, ")");
}

void plc_concat_word_ex(text_t *text, uint32 max_len, word_t *word)
{
    PLC_CONCAT_QUOTATION(text, word->type);
    cm_concat_text(text, max_len, (text_t *)&word->text);
    PLC_CONCAT_QUOTATION(text, word->type);

    for (uint32 i = 0; i < word->ex_count; i++) {
        (void)cm_concat_string(text, max_len, ".");
        PLC_CONCAT_QUOTATION(text, word->ex_words[i].type);
        cm_concat_text(text, max_len, &word->ex_words[i].text.value);
        PLC_CONCAT_QUOTATION(text, word->ex_words[i].type);
    }
}

void plc_concat_word(text_t *text, uint32 max_len, word_t *word)
{
    if (word->type == WORD_TYPE_FUNCTION) {
        plc_concat_func_word(text, max_len, word);
    } else if (word->type == WORD_TYPE_ARRAY) {
        cm_concat_text(text, max_len, &word->text.value);
    } else if (word->type == WORD_TYPE_JOIN_COL) {
        plc_concat_join_col_word(text, max_len, word);
    } else {
        plc_concat_word_ex(text, max_len, word);
    }
}

status_t plc_verify_word_as_var(pl_compiler_t *compiler, word_t *word)
{
    if (word->text.len > CT_MAX_NAME_LEN) {
        CT_SRC_THROW_ERROR(word->loc, ERR_NAME_TOO_LONG, "variant", word->text.len, CT_MAX_NAME_LEN);
        return CT_ERROR;
    }

    for (uint32 i = 0; i < word->ex_count; i++) {
        if (word->ex_words[i].text.len > CT_MAX_NAME_LEN) {
            CT_SRC_THROW_ERROR(word->loc, ERR_NAME_TOO_LONG, "variant", (int32)word->ex_words[i].text.len,
                (int32)CT_MAX_NAME_LEN);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

void plc_try_verify_word_as_var(word_t *word, bool32 *result)
{
    *result = CT_TRUE;
    if (word->text.len > CT_MAX_NAME_LEN) {
        *result = CT_FALSE;
        return;
    }

    for (uint32 i = 0; i < word->ex_count; i++) {
        if (word->ex_words[i].text.len > CT_MAX_NAME_LEN) {
            *result = CT_FALSE;
            return;
        }
    }
}

status_t pl_save_lex(sql_stmt_t *stmt, lex_t **bak)
{
    uint32 lex_size = LEX_HEAD_SIZE + sizeof(uint32);
    lex_size = lex_size + (stmt->session->lex->stack.depth) * sizeof(lex_stack_item_t);

    if (sql_push(stmt, lex_size, (void **)bak) != CT_SUCCESS) {
        return CT_ERROR;
    }
    // memcpy by lex_stack.depth avoid alloc huge stack in thread.
    errno_t ret = memcpy_s((*bak), lex_size, stmt->session->lex, lex_size);
    if (ret != EOK) {
        CTSQL_POP(stmt);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void pl_restore_lex(sql_stmt_t *stmt, lex_t *bak)
{
    // lex bak memory will reset by macro CTSQL_RESTORE_STACK
    uint32 lex_size = LEX_HEAD_SIZE + sizeof(uint32);
    lex_size = lex_size + (bak->stack.depth) * sizeof(lex_stack_item_t);

    errno_t ret = memcpy_s(stmt->session->lex, lex_size, bak, lex_size);
    if (ret != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
    }
    return;
}