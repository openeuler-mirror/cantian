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
 * base_compiler.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/parser/base_compiler.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __BASE_COMPILER_H__
#define __BASE_COMPILER_H__

#include "ast.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PLC_CONCAT_QUOTATION(text, type) \
    if (WORD_TYPE_DQ_STRING == (type)) { \
        CM_TEXT_APPEND((text), '\"');    \
    }

#define PLC_UDT_IS_ARRAY(type_mode, word)                                     \
    do {                                                                      \
        if ((type_mode).is_array) {                                           \
            CT_SRC_THROW_ERROR((word)->loc, ERR_UNSUPPORT_DATATYPE, "ARRAY"); \
            return CT_ERROR;                                                  \
        }                                                                     \
    } while (0)

#define PLC_RESET_WORD_LOC(lex, word)  \
    do {                               \
        (word)->text.loc = (lex)->loc; \
    } while (0)

status_t plc_clone_expr_node(pl_compiler_t *compiler, expr_node_t **src_node);
status_t plc_clone_cond_tree(pl_compiler_t *compiler, cond_tree_t **src_cond);
status_t plc_clone_expr_tree(pl_compiler_t *compiler, expr_tree_t **src_expr);
status_t plc_verify_expr_node(pl_compiler_t *compiler, expr_node_t *node, void *line, uint32 excl_flags);
status_t plc_verify_cond(pl_compiler_t *compiler, cond_tree_t *cond);
void plc_concat_word_ex(text_t *text, uint32 max_len, word_t *word);
void plc_concat_word(text_t *text, uint32 max_len, word_t *word);
status_t plc_verify_limit_expr(pl_compiler_t *compiler, expr_tree_t *expr);
void pl_check_and_set_loc(source_location_t source_loc);
status_t plc_stack_safe(pl_compiler_t *compiler);

static inline void plc_get_verify_obj(sql_stmt_t *stmt, sql_verifier_t *verf)
{
    pl_compiler_t *pl_compiler = NULL;
    if (stmt->pl_compiler != NULL) {
        pl_compiler = (pl_compiler_t *)stmt->pl_compiler;
        if (pl_compiler->root_type == PL_PACKAGE_BODY) {
            verf->obj = pl_compiler->obj;
        }
    }
}

static inline status_t plc_concat_str(text_t *text, uint32 maxsize, const char *part)
{
    if ((text->len + strlen(part)) > maxsize) {                                 // not overflow
        CT_THROW_ERROR(ERR_BUFFER_OVERFLOW, text->len + strlen(part), maxsize); // not overflow
        return CT_ERROR;
    }
    if (cm_concat_string(text, maxsize, part) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static inline void plc_concat_text_upper_by_type(text_t *text, uint32 len, const text_t *part, word_type_t type)
{
    if ((type & WORD_TYPE_DQ_STRING) == 0) {
        cm_concat_text_upper_with_cut(text, len, part);
    } else {
        cm_concat_text_with_cut(text, len, part);
    }
}

status_t plc_verify_word_as_var(pl_compiler_t *compiler, word_t *word);
void plc_try_verify_word_as_var(word_t *word, bool32 *result);

/*
 * @brief    pl verify expr enter. ATTENTION: if create expr in pl, must call it
 */
static inline status_t plc_verify_expr(pl_compiler_t *compiler, expr_tree_t *expr)
{
    uint32 excl_flags = PL_EXPR_EXCL;
    return plc_verify_expr_node(compiler, expr->root, NULL, excl_flags);
}

/*
 * @brief    pl verify expr after using. ATTENTION: bind param can not be used after using.
 */
static inline status_t plc_verify_address_expr(pl_compiler_t *compiler, expr_node_t *node)
{
    uint32 excl_flags;

    excl_flags = SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_JOIN | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_DEFAULT |
        SQL_EXCL_SUBSELECT | SQL_EXCL_COLUMN | SQL_EXCL_ROWSCN | SQL_EXCL_ROWNODEID | SQL_EXCL_METH_PROC |
        SQL_EXCL_METH_FUNC | SQL_EXCL_PL_PROC;
    return plc_verify_expr_node(compiler, node, NULL, excl_flags);
}

#define SET_FUNC_RETURN_TYPE(ret, node)                                              \
    do {                                                                             \
        switch ((ret)->type) {                                                       \
            case PLV_VAR:                                                            \
                (node)->typmod = (ret)->variant.type;                                \
                break;                                                               \
            case PLV_ARRAY:                                                          \
                (node)->typmod = (ret)->array.type;                                  \
                break;                                                               \
            case PLV_RECORD:                                                         \
                (node)->datatype = CT_TYPE_RECORD;                                   \
                (node)->udt_type = (ret)->record;                                    \
                break;                                                               \
            case PLV_OBJECT:                                                         \
                (node)->datatype = CT_TYPE_OBJECT;                                   \
                (node)->udt_type = (ret)->object;                                    \
                break;                                                               \
            case PLV_COLLECTION:                                                     \
                (node)->datatype = CT_TYPE_COLLECTION;                               \
                (node)->udt_type = (ret)->collection;                                \
                break;                                                               \
            case PLV_CUR:                                                            \
                (node)->datatype = CT_TYPE_CURSOR;                                   \
                break;                                                               \
            default:                                                                 \
                CT_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "unexpect pl-variant type"); \
                return CT_ERROR;                                                     \
        }                                                                            \
    } while (0)

void pl_restore_lex(sql_stmt_t *stmt, lex_t *bak);
status_t pl_save_lex(sql_stmt_t *stmt, lex_t **bak);

#ifdef __cplusplus
}
#endif

#endif