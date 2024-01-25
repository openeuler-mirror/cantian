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
 * dml_cl.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/parser/dml_cl.c
 *
 * -------------------------------------------------------------------------
 */
#include "dml_cl.h"
#include "dml.h"
#include "base_compiler.h"
#include "ast_cl.h"
#include "srv_instance.h"
#include "pl_compiler.h"
#include "dml_parser.h"
#include "func_parser.h"
#include "trigger_decl_cl.h"
#include "decl_cl.h"
#include "pl_udt.h"
#include "ctsql_parser.h"
#include "ctsql_dependency.h"
#include "param_decl_cl.h"
#include "ctsql_package.h"
#include "lines_cl.h"
#include "ctsql_privilege.h"

static status_t plc_compile_select_into(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    CT_RETURN_IFERR(plc_compile_select(compiler, sql, word, CT_TRUE));
    if (word->type != WORD_TYPE_PL_TERM) {
        pl_line_sql_t *line = (pl_line_sql_t *)compiler->last_line;
        CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

/*
 * If the input word is head with hint, then add hint info to sql.
 */
static status_t plc_compile_hint(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    bool32 result = CT_FALSE;
    lex_t *lex = compiler->stmt->session->lex;
    if (lex_try_fetch_hint_comment(lex, word, &result) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (result) {
        CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "/*+"));
        cm_concat_text(sql, compiler->convert_buf_size, &word->text.value);
        CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "*/ "));
    }

    return CT_SUCCESS;
}

static status_t plc_compile_dml_org(pl_compiler_t *compiler, text_t *sql, word_t *word, bool32 is_skip_bracket)
{
    source_location_t loc;
    lex_t *lex = compiler->stmt->session->lex;
    CT_RETURN_IFERR(plc_stack_safe(compiler));
    lex->flags = LEX_WITH_OWNER;
    while (CT_TRUE) {
        loc = word->text.loc;
        CT_RETURN_IFERR(lex_fetch(lex, word));
        if (loc.line != 0 && loc.line != word->text.loc.line) {
            CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "\n"));
        }

        switch (word->type) {
            case WORD_TYPE_EOF:
            case WORD_TYPE_PL_TERM:
                return CT_SUCCESS;

            case WORD_TYPE_BRACKET:
                if (!is_skip_bracket) {
                    return CT_SUCCESS;
                }
                CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "("));
                PLC_SAVE_KW_HOOK(compiler);
                compiler->keyword_hook = plc_dmlhook_none;
                CT_RETURN_IFERR(lex_push(lex, &word->text));
                if (plc_compile_dml_org(compiler, sql, word, is_skip_bracket) != CT_SUCCESS) {
                    lex_pop(lex);
                    return CT_ERROR;
                }
                lex_pop(lex);
                PLC_RESTORE_KW_HOOK(compiler);
                CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, ")"));
                break;

            case WORD_TYPE_KEYWORD:
                if (compiler->keyword_hook(word) == CT_TRUE) {
                    return CT_SUCCESS;
                }
                /* fall-through */
            default:
                plc_concat_word(sql, compiler->convert_buf_size, word);
                break;
        }
        CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, " "));
    }
}

static inline status_t plc_try_compile_select_dml(pl_compiler_t *compiler, text_t *sql, word_t *word, bool32 result)
{
    if (!result) {
        CT_RETURN_IFERR(plc_compile_dml_org(compiler, sql, word, CT_TRUE));
    } else {
        CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "select "));
        CT_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));
    }
    return CT_SUCCESS;
}

static status_t plc_compile_returning(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    pl_line_sql_t *line = (pl_line_sql_t *)compiler->last_line;
    // syntax: insert/delete/update return|returning f1, f2 into var1, var2
    if (word->id == KEY_WORD_RETURN || word->id == KEY_WORD_RETURNING) {
        CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "returning "));

        compiler->keyword_hook = plc_dmlhook_return_into;
        CT_RETURN_IFERR(plc_compile_dml(compiler, sql, word, 0, NULL));

        if (word->id != KEY_WORD_INTO && word->id != KEY_WORD_BULK) {
            CT_SRC_THROW_ERROR(word->text.loc, ERR_PL_EXPECTED_FAIL_FMT, "returning clause",
                "missing INTO or BULK keyword");
            return CT_ERROR;
        }
#ifdef Z_SHARDING
        if (IS_COORDINATOR && word->id == KEY_WORD_BULK) {
            CT_SRC_THROW_ERROR(word->loc, ERR_CAPABILITY_NOT_SUPPORT, "'bulk collect' on coordinator is");
            return CT_ERROR;
        }
#endif
    }

    // deal with into variable-list
    if (word->id == KEY_WORD_INTO) {
        CT_RETURN_IFERR(plc_compile_into_clause(compiler, &line->into, word));
    } else {
        CT_RETURN_IFERR(plc_compile_bulk_into_clause(compiler, &line->into, word));
    }

    return CT_SUCCESS;
}

static status_t plc_compile_insert_head(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    lex_t *lex = compiler->stmt->session->lex;
    bool32 result = CT_FALSE;

    compiler->keyword_hook = plc_dmlhook_insert_head;
    CT_RETURN_IFERR(plc_compile_dml_org(compiler, sql, word, CT_FALSE));
    if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_PL_TERM) {
        CT_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, "insert values or select clause", "EOF or ';'");
        return CT_ERROR;
    }
    if (word->type == WORD_TYPE_BRACKET) {
        CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "("));
        CT_RETURN_IFERR(lex_push(lex, &word->text));
        if (lex_try_fetch(lex, "SELECT", &result) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }
        PLC_SAVE_KW_HOOK(compiler);
        compiler->keyword_hook = plc_dmlhook_none;
        if (plc_try_compile_select_dml(compiler, sql, word, result) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }
        lex_pop(lex);
        PLC_RESTORE_KW_HOOK(compiler);
        CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, ") "));
    } else {
        if (word->id == KEY_WORD_VALUES) {
            CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "values "));
        }
        if (word->id == KEY_WORD_SELECT) {
            CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "select "));
        }
    }

    return CT_SUCCESS;
}

static status_t plc_compile_insert_all(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "all "));

    while (CT_TRUE) {
        CT_RETURN_IFERR(plc_compile_insert_head(compiler, sql, word));
        compiler->keyword_hook = plc_dmlhook_all_into;
        CT_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));

        if (PLC_IS_ALL_INTO_WORD(word)) {
            CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "into "));
            continue;
        }

        if (word->type != WORD_TYPE_PL_TERM) {
            CT_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
            return CT_ERROR;
        }

        break;
    }

    return CT_SUCCESS;
}

static status_t plc_compile_insert(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    pl_line_sql_t *line = (pl_line_sql_t *)compiler->last_line;
    lex_t *lex = compiler->stmt->session->lex;
    bool32 isall;

    CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "insert "));
    CT_RETURN_IFERR(plc_compile_hint(compiler, sql, word));

    if (lex_try_fetch(lex, "ALL", &isall) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (isall) {
        return plc_compile_insert_all(compiler, sql, word);
    }

    CT_RETURN_IFERR(plc_compile_insert_head(compiler, sql, word));
    compiler->keyword_hook = plc_dmlhook_return_returning;
    CT_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));

    if (PLC_IS_RETURNING_WORD(word)) {
        CT_RETURN_IFERR(plc_compile_returning(compiler, sql, word));
    }

    if (word->type != WORD_TYPE_PL_TERM) {
        CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t plc_compile_currowid_variant(void *anchor)
{
    plv_decl_t *decl = NULL;
    char name_buf[CT_MAX_NAME_LEN];
    text_t name = {
        .str = NULL,
        .len = 0
    };

    variant_complier_t *def = (variant_complier_t *)anchor;
    pl_compiler_t *compiler = def->compiler;
    text_t *sql_text = def->sql;
    word_t *word = def->word;
    galist_t *input = compiler->current_input;

    if (word->type == WORD_TYPE_PL_NEW_COL || word->type == WORD_TYPE_PL_OLD_COL) {
        return plc_compile_trigger_variant(compiler, sql_text, word);
    }

    CT_RETURN_IFERR(plc_verify_word_as_var(compiler, word));
    plc_find_decl_ex(compiler, word, PLV_CUR, NULL, &decl);
    if (decl == NULL) {
        plc_concat_word(sql_text, compiler->convert_buf_size, word);
        return CT_SUCCESS;
    }
    // here only allow cursor-variant, so it must be a single vid
    CT_RETURN_IFERR(udt_build_list_address_single(compiler->stmt, input, decl, UDT_STACK_ADDR));
    decl->vid.is_rowid = CT_TRUE;

    CT_RETURN_IFERR(plc_make_input_name(input, name_buf, CT_MAX_NAME_LEN, &name));
    cm_concat_text(sql_text, compiler->convert_buf_size, &name);
    return CT_SUCCESS;
}

static status_t pl_compile_current_of(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    bool32 is_of = CT_FALSE;
    lex_t *lex = compiler->stmt->session->lex;

#ifdef Z_SHARDING
    if (IS_COORDINATOR && IS_APP_CONN(compiler->stmt->session)) {
        CT_SRC_THROW_ERROR(word->loc, ERR_PL_SYNTAX_ERROR_FMT, "CURRENT OF is not supported at CN.");
        return CT_ERROR;
    }
#endif

    CT_RETURN_IFERR(lex_try_fetch(lex, "OF", &is_of));
    if (is_of) {
        CT_RETURN_IFERR(lex_fetch(lex, word));

        if (IS_VARIANT(word) && word->ex_count <= 1) {
            CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, " rowid = "));
            variant_complier_t def;
            def.compiler = compiler;
            def.sql = sql;
            def.word = word;
            def.types = PLV_CUR;
            def.usrdef = NULL;
            CT_RETURN_IFERR(plc_compile_currowid_variant(&def));
        } else {
            CT_SRC_THROW_ERROR(word->loc, ERR_PL_SYNTAX_ERROR_FMT, "'current of' should follow a update cursor.");
            return CT_ERROR;
        }
    } else {
        CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, " CURRENT "));
    }
    return CT_SUCCESS;
}

static status_t plc_compile_update(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    bool32 result = CT_FALSE;
    lex_t *lex = compiler->stmt->session->lex;
    pl_line_sql_t *line = (pl_line_sql_t *)compiler->last_line;

    CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "update "));
    CT_RETURN_IFERR(plc_compile_hint(compiler, sql, word));

    compiler->keyword_hook = plc_dmlhook_update_head;
    CT_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));
    if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_PL_TERM) {
        CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "update set clause", "EOF or ';'");
        return CT_ERROR;
    }
    CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "set "));

    CT_RETURN_IFERR(lex_try_fetch_bracket(lex, word, &result));
    if (result) {
        CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "("));
        plc_concat_word(sql, compiler->convert_buf_size, word);
        CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, ")"));
    } else {
        CT_RETURN_IFERR(lex_fetch(lex, word));
        plc_concat_word(sql, compiler->convert_buf_size, word);
    }

    compiler->keyword_hook = plc_dmlhook_current;
    CT_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));
    if (word->type == WORD_TYPE_EOF) {
        CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
        return CT_ERROR;
    }
    if (word->type == WORD_TYPE_PL_TERM) {
        return CT_SUCCESS;
    }

    // translate current of cursor into rowid = rowid_variant
    if (word->id == KEY_WORD_CURRENT) {
        CT_RETURN_IFERR(pl_compile_current_of(compiler, sql, word));
        if (word->type == WORD_TYPE_PL_TERM) {
            return CT_SUCCESS;
        }

        compiler->keyword_hook = plc_dmlhook_return_returning;
        CT_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));
        if (PLC_IS_RETURNING_WORD(word)) {
            CT_RETURN_IFERR(plc_compile_returning(compiler, sql, word));
        }
    } else if (PLC_IS_RETURNING_WORD(word)) {
        CT_RETURN_IFERR(plc_compile_returning(compiler, sql, word));
    }

    if (word->type != WORD_TYPE_PL_TERM) {
        CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t plc_compile_delete(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    pl_line_sql_t *line = NULL;

    line = (pl_line_sql_t *)compiler->last_line;
    CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "delete "));
    CT_RETURN_IFERR(plc_compile_hint(compiler, sql, word));

    compiler->keyword_hook = plc_dmlhook_current;
    CT_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));
    if (word->type == WORD_TYPE_EOF) {
        CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
        return CT_ERROR;
    }
    if (word->type == WORD_TYPE_PL_TERM) {
        return CT_SUCCESS;
    }

    if (word->id == KEY_WORD_CURRENT) {
        CT_RETURN_IFERR(pl_compile_current_of(compiler, sql, word));
        if (word->type == WORD_TYPE_PL_TERM) {
            return CT_SUCCESS;
        }

        compiler->keyword_hook = plc_dmlhook_return_returning;
        CT_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));
        if (PLC_IS_RETURNING_WORD(word)) {
            CT_RETURN_IFERR(plc_compile_returning(compiler, sql, word));
        }
    } else if (PLC_IS_RETURNING_WORD(word)) {
        CT_RETURN_IFERR(plc_compile_returning(compiler, sql, word));
    }

    if (word->type != WORD_TYPE_PL_TERM) {
        CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t plc_compile_set_clause(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    bool32 result = CT_FALSE;
    lex_t *lex = compiler->stmt->session->lex;
    while (CT_TRUE) {
        // column
        lex->flags = LEX_WITH_OWNER;
        CT_RETURN_IFERR(lex_fetch(lex, word));
        plc_concat_word(sql, compiler->convert_buf_size, word);
        CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, " "));

        lex->flags = LEX_SINGLE_WORD;
        CT_RETURN_IFERR(lex_expected_fetch_word(lex, "="));
        CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "= "));

        CT_RETURN_IFERR(lex_try_fetch(lex, "case", &result));
        if (result) {
            CT_RETURN_IFERR(lex_expected_fetch_word(lex, "when"));
            CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "case when "));
            compiler->keyword_hook = plc_dmlhook_end;
            CT_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));
            if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_PL_TERM) {
                CT_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, "end", "EOF or ';'");
                return CT_ERROR;
            }
            CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "end "));
            lex->flags = LEX_SINGLE_WORD;
            CT_RETURN_IFERR(lex_fetch(lex, word));
        } else {
            lex->flags = LEX_WITH_ARG | LEX_WITH_OWNER;
            compiler->keyword_hook = plc_dmlhook_spec_char;
            CT_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));
        }

        if (IS_SPEC_CHAR(word, ',')) {
            CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, ", "));
            continue;
        }
        break;
    }

    return CT_SUCCESS;
}

static status_t plc_compile_merge(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    pl_line_sql_t *line = NULL;
    bool32 result = CT_FALSE;
    bool32 loop_flag;
    lex_t *lex = compiler->stmt->session->lex;

    line = (pl_line_sql_t *)compiler->last_line;
    CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "merge "));

    if (plc_compile_hint(compiler, sql, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    compiler->keyword_hook = plc_dmlhook_merge_head;
    CT_RETURN_IFERR(plc_compile_dml_org(compiler, sql, word, CT_TRUE));
    if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_PL_TERM) {
        CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "merge using clause", "EOF or ';'");
        return CT_ERROR;
    }
    CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "using "));

    compiler->keyword_hook = plc_dmlhook_merge_when;
    CT_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));
    if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_PL_TERM) {
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "when "));

    do {
        loop_flag = CT_FALSE;
        CT_RETURN_IFERR(lex_try_fetch(lex, "not", &result));
        if (result) {
            CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "not "));
            compiler->keyword_hook = plc_dmlhook_merge_insert;
            CT_RETURN_IFERR(plc_compile_dml_org(compiler, sql, word, CT_TRUE));
            if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_PL_TERM) {
                CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "insert values clause", "EOF or ';'");
                return CT_ERROR;
            }
            CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "values "));
        } else {
            compiler->keyword_hook = plc_dmlhook_update_head;
            CT_RETURN_IFERR(plc_compile_dml_org(compiler, sql, word, CT_TRUE));
            if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_PL_TERM) {
                CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "update set clause", "EOF or ';'");
                return CT_ERROR;
            }
            CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "set "));
            CT_RETURN_IFERR(lex_try_fetch_bracket(lex, word, &result));
            if (result) {
                CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "("));
                plc_concat_word(sql, compiler->convert_buf_size, word);
                CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, ")"));
            } else {
                uint32 flags = lex->flags;
                if (plc_compile_set_clause(compiler, sql, word) != CT_SUCCESS) {
                    lex->flags = flags;
                    return CT_ERROR;
                }
                lex->flags = flags;

                if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_PL_TERM) {
                    break;
                }
                plc_concat_word(sql, compiler->convert_buf_size, word);
                CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, " "));
            }
        }

        compiler->keyword_hook = plc_dmlhook_merge_when;
        CT_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));

        if (word->id == KEY_WORD_WHEN) {
            CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "when "));
            loop_flag = CT_TRUE;
        }
    } while (loop_flag);

    if (word->type != WORD_TYPE_PL_TERM) {
        CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t plc_compile_dml_end(pl_compiler_t *compiler, text_t *sql, word_t *word, pl_line_sql_t *line)
{
    compiler->keyword_hook = plc_dmlhook_none;
    CT_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));
    if (word->type != WORD_TYPE_PL_TERM) {
        CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t plc_compile_replace(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    bool32 result = CT_FALSE;
    lex_t *lex = compiler->stmt->session->lex;
    pl_line_sql_t *line = (pl_line_sql_t *)compiler->last_line;
    CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "replace "));

    if (plc_compile_hint(compiler, sql, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    compiler->keyword_hook = plc_dmlhook_replace_head;
    CT_RETURN_IFERR(plc_compile_dml_org(compiler, sql, word, CT_FALSE));
    if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_PL_TERM) {
        CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "replace values or select or set clause",
            "EOF or ';'");
        return CT_ERROR;
    }

    if (word->type == WORD_TYPE_BRACKET) {
        CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "("));
        CT_RETURN_IFERR(lex_push(lex, &word->text));
        if (lex_try_fetch(lex, "SELECT", &result) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }
        PLC_SAVE_KW_HOOK(compiler);
        compiler->keyword_hook = plc_dmlhook_none;
        if (plc_try_compile_select_dml(compiler, sql, word, result) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }
        lex_pop(lex);
        PLC_RESTORE_KW_HOOK(compiler);
        CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, ")"));
    } else {
        switch (word->id) {
            case KEY_WORD_VALUES:
                CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "values "));
                break;
            case KEY_WORD_SELECT:
                CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "select "));
                break;
            case KEY_WORD_SET:
                CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "set "));
                break;
            default:
                CT_SRC_THROW_ERROR(word->loc, ERR_PL_UNEXPECTED_FMT, W2S(word));
                return CT_ERROR;
        }
    }

    return plc_compile_dml_end(compiler, sql, word, line);
}

static status_t plc_create_dynamic_sql_expr(sql_stmt_t *stmt, expr_tree_t **expr, text_t *sql, source_location_t loc)
{
    expr_node_t *node = NULL;
    text_t *value_text = NULL;
    char *str = NULL;

    CT_RETURN_IFERR(sql_create_expr(stmt, expr));
    (*expr)->loc = loc;

    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&node) != CT_SUCCESS) {
        return CT_ERROR;
    }

    node->owner = (*expr);
    node->type = EXPR_NODE_CONST;
    node->unary = (*expr)->unary;
    node->loc = loc;
    node->dis_info.need_distinct = CT_FALSE;
    node->dis_info.idx = CT_INVALID_ID32;

    if (sql_alloc_mem(stmt->context, sql->len + 1, (void **)&str) != CT_SUCCESS) {
        return CT_ERROR;
    }

    value_text = VALUE_PTR(text_t, &node->value);
    value_text->str = str;
    value_text->len = sql->len;
    if (sql->len != 0) {
        MEMS_RETURN_IFERR(memcpy_s(str, sql->len + 1, sql->str, sql->len));
    }
    node->value.ctrl = 0;
    node->value.type = CT_TYPE_STRING;
    APPEND_CHAIN(&(*expr)->chain, node);
    (*expr)->unary = UNARY_OPER_NONE;
    (*expr)->generated = CT_TRUE;
    (*expr)->root = (*expr)->chain.first;

    return CT_SUCCESS;
}

static status_t plc_check_column_match(pl_compiler_t *compiler, sql_type_t type, pl_line_sql_t *line)
{
    if (!IS_DML_INTO_PL_VAR(type) || line->context->rs_columns == NULL) {
        return CT_SUCCESS;
    }

    return plc_verify_into_clause(line->context, &line->into, line->ctrl.loc);
}

status_t pl_compile_parse_sql(sql_stmt_t *stmt, sql_context_t **ctx, text_t *sql, source_location_t *loc,
    galist_t *sql_list)
{
    sql_stmt_t *sub_stmt = NULL;
    lex_t *lex_bak = NULL;
    status_t status = CT_ERROR;
    sql_stmt_t *save_curr_stmt = stmt->session->current_stmt;
    CT_RETURN_IFERR(sql_push(stmt, sizeof(sql_stmt_t), (void **)&sub_stmt));
    CT_RETURN_IFERR(pl_save_lex(stmt, &lex_bak));

    sql_init_stmt(stmt->session, sub_stmt, stmt->id);
    sub_stmt->pl_compiler = stmt->pl_compiler;
    sub_stmt->context = NULL;
    sub_stmt->session->current_stmt = sub_stmt;
    do {
        if (sql_parse(sub_stmt, sql, loc) != CT_SUCCESS) {
            pl_check_and_set_loc(*loc);
            break;
        }

        if (sql_check_dml_privs(sub_stmt, CT_TRUE) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            pl_check_and_set_loc(*loc);
            sql_release_context(sub_stmt);
            break;
        }

        if (cm_galist_insert(sql_list, sub_stmt->context) != CT_SUCCESS) {
            sql_release_context(sub_stmt);
            break;
        }
        status = CT_SUCCESS;
    } while (0);
    stmt->session->current_stmt = save_curr_stmt;
    *ctx = sub_stmt->context;
    pl_restore_lex(stmt, lex_bak);
    sql_release_lob_info(sub_stmt);
    sql_release_resource(sub_stmt, CT_TRUE);
    return status;
}

status_t plc_compile_sql(pl_compiler_t *compiler, word_t *word)
{
    text_t sql;
    pl_line_sql_t *sql_line = NULL;
    source_location_t loc;
    sql_stmt_t *stmt = compiler->stmt;
    pl_entity_t *entity = (pl_entity_t *)compiler->entity;

    CT_RETURN_IFERR(plc_stack_safe(compiler));
    // convert statement to large page addr
    CT_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_sql_t), LINE_SQL, (pl_line_ctrl_t **)&sql_line));
    CT_RETURN_IFERR(plc_init_galist(compiler, &sql_line->input));
    sql.len = 0;
    // reserve a quato for dynamic sql.
    sql.str = compiler->convert_buf;

    compiler->keyword_hook = plc_dmlhook_none;
    compiler->current_input = sql_line->input;
    loc = word->loc;
    switch (word->id) {
        case KEY_WORD_SELECT:
            CT_RETURN_IFERR(plc_compile_select_into(compiler, &sql, word));
            break;

        case KEY_WORD_INSERT:
            CT_RETURN_IFERR(plc_compile_insert(compiler, &sql, word));
            break;

        case KEY_WORD_UPDATE:
            CT_RETURN_IFERR(plc_compile_update(compiler, &sql, word));
            break;

        case KEY_WORD_DELETE:
            CT_RETURN_IFERR(plc_compile_delete(compiler, &sql, word));
            break;

        case KEY_WORD_MERGE:
            CT_RETURN_IFERR(plc_compile_merge(compiler, &sql, word));
            break;

        case KEY_WORD_REPLACE:
            CT_RETURN_IFERR(plc_compile_replace(compiler, &sql, word));
            break;

        default:
            CT_SRC_THROW_ERROR(word->loc, ERR_PL_UNEXPECTED_FMT, W2S(word));
            return CT_ERROR;
    }

    cm_trim_text(&sql);

    /* sql has local temp table will be treated as dynamic sql */
    if (sql_has_ltt(compiler->stmt, &sql)) {
        CT_RETURN_IFERR(plc_create_dynamic_sql_expr(compiler->stmt, &sql_line->dynamic_sql, &sql, loc));
        CT_RETURN_IFERR(plc_verify_expr(compiler, sql_line->dynamic_sql));
        CT_RETURN_IFERR(plc_clone_expr_tree(compiler, &sql_line->dynamic_sql));
        sql_line->is_dynamic_sql = CT_TRUE;
        return CT_SUCCESS;
    } else {
        sql_line->is_dynamic_sql = CT_FALSE;
    }

    CTSQL_SAVE_STACK(stmt);
    if (pl_compile_parse_sql(stmt, &sql_line->context, &sql, &loc, &entity->sqls) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    CTSQL_RESTORE_STACK(stmt);

    if (plc_check_column_match(compiler, sql_line->context->type, sql_line) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_append_references(&entity->ref_list, sql_line->context);
}

static status_t plc_compile_sql_try_complex(pl_compiler_t *compiler, text_t *sql, word_t *word, bool32 *result)
{
    plc_var_type_t var_type;
    plv_decl_t *decl = NULL;
    expr_node_t *node = NULL;
    char name_buf[CT_MAX_NAME_LEN];
    text_t name = {
        .str = NULL,
        .len = 0
    };
    galist_t *input = compiler->current_input;

    plc_try_verify_word_as_var(word, result);
    if (!(*result)) {
        return CT_SUCCESS;
    }
    plc_find_decl_ex(compiler, word, PLV_COMPLEX_VARIANT, &var_type, &decl);
    if (decl == NULL || !PLC_IS_MULTIEX_VARIANT(var_type)) {
        *result = CT_FALSE;
        return CT_SUCCESS;
    }
    *result = CT_TRUE;
    CT_RETURN_IFERR(cm_galist_new(input, sizeof(expr_node_t), (void **)&node));
    if (plc_try_obj_access_bracket(compiler->stmt, word, node) != CT_SUCCESS) {
        pl_check_and_set_loc(word->loc);
        return CT_ERROR;
    }
    if (NODE_EXPR_TYPE(node) != EXPR_NODE_V_ADDR && NODE_EXPR_TYPE(node) != EXPR_NODE_V_METHOD) {
        CT_SRC_THROW_ERROR_EX(word->loc, ERR_PL_SYNTAX_ERROR_FMT, "identifier \'%s\' must be declared", W2S(word));
        return CT_ERROR;
    }
    CT_RETURN_IFERR(plc_verify_address_expr(compiler, node));
    CT_RETURN_IFERR(plc_make_input_name(input, name_buf, CT_MAX_NAME_LEN, &name));
    cm_concat_text(sql, compiler->convert_buf_size, &name);
    return CT_SUCCESS;
}

static inline void plc_concat_pack_word_core(pl_compiler_t *compiler, text_t *sql, word_t *word, bool32 has_bracket)
{
    if (has_bracket) {
        plc_concat_word_ex(sql, compiler->convert_buf_size, word);
    } else {
        plc_concat_word(sql, compiler->convert_buf_size, word);
    }
}

static status_t plc_concat_pack_word(pl_compiler_t *compiler, text_t *sql, word_t *word, bool32 has_bracket)
{
    plv_decl_t *spec_obj = NULL;
    function_t *func = NULL;
    galist_t *spec_objs = NULL;
    pl_dc_t *spec_dc = compiler->spec_dc;

    if (word->ex_count > 0) {
        plc_concat_pack_word_core(compiler, sql, word, has_bracket);
        return CT_SUCCESS;
    }

    if (spec_dc != NULL) {
        spec_objs = spec_dc->entity->package_spec->defs;
        for (uint32 i = 0; i < spec_objs->count; i++) {
            spec_obj = (plv_decl_t *)cm_galist_get(spec_objs, i);
            func = spec_obj->func;
            if (func->desc.pl_type != PL_FUNCTION) {
                continue;
            }
            if (cm_text_str_equal_ins(&word->text.value, func->desc.name)) {
                cm_concat_string(sql, compiler->convert_buf_size, spec_dc->entry->desc.name);
                CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "."));
                plc_concat_pack_word_core(compiler, sql, word, has_bracket);
                return CT_SUCCESS;
            }
        }
    }

    plc_concat_pack_word_core(compiler, sql, word, has_bracket);
    return CT_SUCCESS;
}

static status_t plc_compile_sql_func(pl_compiler_t *compiler, text_t *sql, word_t *word, uint32 types, void *usrdef)
{
    word_t func_name;
    bool32 result = CT_FALSE;
    lex_t *lex = compiler->stmt->session->lex;

    CT_RETURN_IFERR(plc_compile_sql_try_complex(compiler, sql, word, &result));
    if (result) {
        return CT_SUCCESS;
    }

    sql_text_t *args = &word->ex_words[word->ex_count - 1].text; // not overflow

    func_name = *word;
    func_name.ex_count--;
    CT_RETURN_IFERR(plc_concat_pack_word(compiler, sql, &func_name, CT_TRUE));

    if (args->len == 0) {
        CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "("));
        return plc_concat_str(sql, compiler->convert_buf_size, ")");
    }

    PLC_SAVE_KW_HOOK(compiler);
    compiler->keyword_hook = plc_dmlhook_none;
    CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "("));
    CT_RETURN_IFERR(lex_push(lex, args));
    if (plc_compile_dml(compiler, sql, word, types, usrdef) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }
    lex_pop(lex);
    CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, ")"));
    PLC_RESTORE_KW_HOOK(compiler);
    return CT_SUCCESS;
}

static status_t plc_compile_array_var(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    int32 start;
    int32 end;
    text_t text;
    lex_t *lex = compiler->stmt->session->lex;

    text.str = lex->curr_text->value.str;
    CT_RETURN_IFERR(lex_try_fetch_subscript(lex, &start, &end));

    text.len = (uint32)(lex->curr_text->value.str - text.str);
    cm_concat_text(sql, compiler->convert_buf_size, &text);
    return CT_SUCCESS;
}

static status_t plc_concat_variant(pl_compiler_t *compiler, text_t *sql, word_t *word, uint32 types, void *usrdef)
{
    if (IS_VARIANT(word)) {
        variant_complier_t complier_def;
        complier_def.compiler = compiler;
        complier_def.sql = sql;
        complier_def.word = word;
        complier_def.types = types;
        complier_def.usrdef = usrdef;
        CT_RETURN_IFERR(plc_compile_sql_variant(&complier_def));
        CT_RETURN_IFERR(plc_compile_array_var(compiler, sql, word));
    } else {
        plc_concat_word(sql, compiler->convert_buf_size, word);
    }

    return CT_SUCCESS;
}

static status_t plc_compile_sql_verify_next_space(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    bool32 current_flag = PLC_NOT_NEED_NEXT_SPACE(word);
    lex_t *lex = compiler->stmt->session->lex;
    CT_RETURN_IFERR(lex_fetch(lex, word));
    if (current_flag || PLC_NOT_NEED_NEXT_SPACE(word) || word->type == WORD_TYPE_EOF ||
        word->type == WORD_TYPE_PL_TERM) {
        return CT_SUCCESS;
    }
    return plc_concat_str(sql, compiler->convert_buf_size, " ");
}

static status_t plc_compile_as_or_from(pl_compiler_t *compiler, text_t *sql, lex_t *lex, word_t *word, uint32 types,
    void *usrdef)
{
    CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, (word->id == KEY_WORD_AS) ? "as " : "from "));
    // don't care the word follow key_word_as
    CT_RETURN_IFERR(lex_fetch(lex, word));
    if (word->type == WORD_TYPE_BRACKET) {
        CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "("));
        PLC_SAVE_KW_HOOK(compiler);
        compiler->keyword_hook = plc_dmlhook_none;
        CT_RETURN_IFERR(lex_push(lex, &word->text));
        if (plc_compile_dml(compiler, sql, word, types, usrdef) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }
        lex_pop(lex);
        PLC_RESTORE_KW_HOOK(compiler);
        CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, ")"));
    } else {
        plc_concat_word(sql, compiler->convert_buf_size, word);
    }
    return CT_SUCCESS;
}

// reform DML parser in PL/SQL.
status_t plc_compile_dml(pl_compiler_t *compiler, text_t *sql, word_t *word, uint32 types, void *usrdef)
{
    source_location_t loc;
    lex_t *lex = compiler->stmt->session->lex;
    CT_RETURN_IFERR(plc_stack_safe(compiler));

    lex->flags = LEX_WITH_OWNER | LEX_WITH_ARG;

    if (plc_compile_hint(compiler, sql, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    loc = word->text.loc;
    CT_RETURN_IFERR(lex_fetch(lex, word));

    while (CT_TRUE) {
        if (loc.line != 0 && loc.line != word->text.loc.line) {
            CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "\n"));
            loc = word->text.loc;
        }

        switch (word->type) {
            case WORD_TYPE_EOF:
            case WORD_TYPE_PL_TERM:
                return CT_SUCCESS;

            case WORD_TYPE_FUNCTION:
                CT_RETURN_IFERR(plc_compile_sql_func(compiler, sql, word, types, usrdef));
                break;

            case WORD_TYPE_PARAM:
                CT_RETURN_IFERR(plc_compile_sql_param(compiler, sql, word));
                break;

            case WORD_TYPE_BRACKET:
                CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "("));
                PLC_SAVE_KW_HOOK(compiler);
                compiler->keyword_hook = plc_dmlhook_none;
                CT_RETURN_IFERR(lex_push(lex, &word->text));
                if (plc_compile_dml(compiler, sql, word, types, usrdef) != CT_SUCCESS) {
                    lex_pop(lex);
                    return CT_ERROR;
                }
                lex_pop(lex);
                PLC_RESTORE_KW_HOOK(compiler);
                if (word->type == WORD_TYPE_PL_TERM) {
                    CT_RETURN_IFERR(lex_fetch(lex, word));
                    CT_SRC_THROW_ERROR(loc, ERR_SQL_SYNTAX_ERROR, "unexpected word ';' found");
                    return CT_ERROR;
                }
                CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, ")"));
                break;
            case WORD_TYPE_COMPARE:
                plc_concat_word(sql, compiler->convert_buf_size, word);
                if (word->id == CMP_TYPE_EQUAL_ANY || word->id == CMP_TYPE_NOT_EQUAL_ANY ||
                    word->id == CMP_TYPE_GREAT_EQUAL_ANY || word->id == CMP_TYPE_GREAT_ANY ||
                    word->id == CMP_TYPE_LESS_ANY || word->id == CMP_TYPE_LESS_EQUAL_ANY) {
                    CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, " any "));
                } else if (word->id == CMP_TYPE_EQUAL_ALL || word->id == CMP_TYPE_NOT_EQUAL_ALL ||
                    word->id == CMP_TYPE_GREAT_EQUAL_ALL || word->id == CMP_TYPE_GREAT_ALL ||
                    word->id == CMP_TYPE_LESS_ALL || word->id == CMP_TYPE_LESS_EQUAL_ALL) {
                    CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, " all "));
                }
                break;
            case WORD_TYPE_KEYWORD:
                if (compiler->keyword_hook(word) == CT_TRUE) {
                    return CT_SUCCESS;
                }
                // else do as variant check.
                if (word->id == KEY_WORD_AS || word->id == KEY_WORD_FROM) {
                    CT_RETURN_IFERR(plc_compile_as_or_from(compiler, sql, lex, word, types, usrdef));
                    break;
                }

                CT_RETURN_IFERR(plc_concat_variant(compiler, sql, word, types, usrdef));
                if (PLC_IS_DML_WORD(word)) {
                    CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, " "));
                    CT_RETURN_IFERR(plc_compile_hint(compiler, sql, word));
                }
                break;

            case WORD_TYPE_ARRAY:
                CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "array["));
                CT_RETURN_IFERR(lex_fetch_array(lex, word));
                CT_RETURN_IFERR(plc_concat_variant(compiler, sql, word, types, usrdef));
                CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "]"));
                break;
            case WORD_TYPE_SPEC_CHAR:
                if (compiler->keyword_hook(word) == CT_TRUE) {
                    return CT_SUCCESS;
                }
                /* fall-through */
            default:
                CT_RETURN_IFERR(plc_concat_variant(compiler, sql, word, types, usrdef));
                break;
        }
        CT_RETURN_IFERR(plc_compile_sql_verify_next_space(compiler, sql, word));
    }
}

static status_t plc_compile_select_columns(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    compiler->keyword_hook = plc_dmlhook_qrylist;
    CT_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));

    if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_PL_TERM) {
        CT_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, "more clause", "EOF or ';'");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t plc_compile_select(pl_compiler_t *compiler, text_t *sql, word_t *word, bool32 is_select_into)
{
    pl_line_sql_t *line = NULL;
    line = (pl_line_sql_t *)compiler->last_line;

    CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "select "));

    if (plc_compile_hint(compiler, sql, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // column name
    CT_RETURN_IFERR(plc_compile_select_columns(compiler, sql, word));

    if (is_select_into) {
        if (word->id != KEY_WORD_INTO && word->id != KEY_WORD_BULK) {
            CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_SYNTAX_ERROR_FMT,
                "an INTO clause is expected in this SELECT statement");
            return CT_ERROR;
        }
        if (word->id == KEY_WORD_INTO) {
            CT_RETURN_IFERR(plc_compile_into_clause(compiler, &line->into, word));
            line->into.prefetch_rows = INTO_VALUES_PREFETCH_COUNT;
        } else {
            CT_RETURN_IFERR(plc_compile_bulk_into_clause(compiler, &line->into, word));
        }
    }

    // deal with others
    if (word->id != KEY_WORD_FROM) {
        CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_SYNTAX_ERROR_FMT,
            "an FROM clause is expected in this SELECT statement");
        return CT_ERROR;
    }
    CT_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "from "));

    compiler->keyword_hook = plc_dmlhook_none;
    return plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL);
}

static status_t plc_try_compile_cursor_arg(pl_compiler_t *compiler, text_t *sql, word_t *word, variant_complier_t *def,
    plv_decl_t **decl)
{
    plv_decl_t *input = def->usrdef;
    if ((input == NULL) || (input->type != PLV_CUR) || (input->cursor.ctx == NULL)) {
        return plc_concat_pack_word(compiler, sql, word, CT_FALSE);
    }

    plv_decl_t *select = NULL;
    plc_find_in_decls(input->cursor.ctx->args, (text_t *)&word->text, IS_DQ_STRING(word->type), &select);
    if ((select == NULL) || (select->type & def->types) == 0) {
        plc_concat_word(sql, compiler->convert_buf_size, word);
        return CT_SUCCESS;
    }

    *decl = select;
    return CT_ERROR;
}

// it's the time replace variant name in dml's sql
status_t plc_compile_sql_variant(void *anchor)
{
    plv_decl_t *decl = NULL;
    char name_buf[CT_MAX_NAME_LEN];
    text_t name = {
        .str = NULL,
        .len = 0
    };
    plc_var_type_t var_type;

    variant_complier_t *def = (variant_complier_t *)anchor;
    pl_compiler_t *compiler = def->compiler;
    text_t *sql_text = def->sql;
    word_t *word = def->word;
    galist_t *input = compiler->current_input;
    expr_node_t *node = NULL;
    if (IS_TRIGGER_WORD_TYPE(word)) {
        return plc_compile_trigger_variant(compiler, sql_text, word);
    }

    CT_RETURN_IFERR(plc_verify_word_as_var(compiler, word));
    plc_find_decl_ex(compiler, word, def->types, &var_type, &decl);
    if (decl == NULL || (PLC_IS_MULTIEX_VARIANT(var_type) && decl->type == PLV_VAR)) {
        if (plc_try_compile_cursor_arg(compiler, sql_text, word, def, &decl) != CT_ERROR) {
            return CT_SUCCESS;
        }
    }

    CT_RETURN_IFERR(cm_galist_new(input, sizeof(expr_node_t), (void **)&node));
    if (PLC_IS_MULTIEX_VARIANT(var_type)) {
        if (plc_try_obj_access_bracket(compiler->stmt, word, node) != CT_SUCCESS) {
            pl_check_and_set_loc(word->loc);
            return CT_ERROR;
        }

        if (NODE_EXPR_TYPE(node) != EXPR_NODE_V_ADDR) {
            CT_SRC_THROW_ERROR_EX(word->loc, ERR_PL_SYNTAX_ERROR_FMT, "identifier \'%s\' must be declared", W2S(word));
            return CT_ERROR;
        }

        CT_RETURN_IFERR(plc_verify_address_expr(compiler, node));
    } else {
        CT_RETURN_IFERR(plc_build_var_address(compiler->stmt, decl, node, UDT_STACK_ADDR));
        SET_FUNC_RETURN_TYPE(decl, node);
    }
    CT_RETURN_IFERR(plc_make_input_name(input, name_buf, CT_MAX_NAME_LEN, &name));
    cm_concat_text(sql_text, compiler->convert_buf_size, &name);
    return CT_SUCCESS;
}

static status_t plc_word2var_column(sql_stmt_t *stmt, word_t *word, expr_node_t *node, var_func_t *v, bool32 *result)
{
    if (node->type != EXPR_NODE_COLUMN) {
        return CT_SUCCESS;
    }

    bool32 flag = CT_FALSE;
    text_t *package = NULL;
    text_t *name = NULL;

    /* deal with the case of dbms const, such as:DBE_STATS.AUTO_SAMPLE_SIZE */
    if (word->ex_count == 1) {
        package = &word->text.value;
        name = &word->ex_words[0].text.value;
        flag = CT_TRUE;
    } else if (word->ex_count == 2) { // number 2 ex_count, such as: user.package.function
        if (cm_text_str_equal_ins(&word->text.value, SYS_USER_NAME)) {
            package = &word->ex_words[0].text.value;
            name = &word->ex_words[1].text.value;
            flag = CT_TRUE;
        }
    }

    if (!flag) {
        return CT_SUCCESS;
    }

    sql_convert_pack_func(package, name, v);
    if (v->pack_id != CT_INVALID_ID32 && v->func_id != CT_INVALID_ID32) {
        *result = CT_TRUE;
        node->value.type = CT_TYPE_COLUMN;
        return sql_word_as_column(stmt, word, &node->word);
    }
    return CT_SUCCESS;
}

/*
 * @brief    an important expression's node convert function, search block decls'
 * variants then record the vid in node's pair->stack
 */
status_t plc_word2var(sql_stmt_t *stmt, word_t *word, expr_node_t *node)
{
    var_func_t v;
    bool32 result = CT_FALSE;
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;

    if (compiler == NULL) {
        // If not in compiler-phase, do as column.
        node->value.type = CT_TYPE_COLUMN;
        return sql_word_as_column(stmt, word, &node->word);
    }

    CT_RETURN_IFERR(plc_word2var_column(stmt, word, node, &v, &result));
    if (result) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(plc_verify_word_as_var(compiler, word));
    CT_RETURN_IFERR(plc_try_obj_access_single(stmt, word, node));
    if (IS_UDT_EXPR(node->type)) {
        return CT_SUCCESS;
    }

    /* deal with the case of dbe_std function without parameters, such as:sqlcode, sqlerrm and so on. */
    if (node->type == EXPR_NODE_COLUMN && word->ex_count == 0) {
        text_t standard_pack_name = {
            .str = STANDARD_PACK_NAME,
            .len = (uint32)strlen(STANDARD_PACK_NAME)
        };
        sql_convert_pack_func(&standard_pack_name, &word->text.value, &v);
        if (v.pack_id != CT_INVALID_ID32 && v.func_id != CT_INVALID_ID32) {
            node->type = EXPR_NODE_FUNC;
            return sql_build_func_node(stmt, word, node);
        }
    }

    // can't find in pl, need to check if column indeed.
    node->value.type = CT_TYPE_COLUMN;
    return sql_word_as_column(stmt, word, &node->word);
}