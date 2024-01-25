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
 * cursor_cl.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/parser/cursor_cl.c
 *
 * -------------------------------------------------------------------------
 */

#include "cursor_cl.h"
#include "base_compiler.h"
#include "decl_cl.h"
#include "pl_memory.h"
#include "pl_common.h"
#include "ctsql_parser.h"
#include "dml.h"
#include "ctsql_dependency.h"
#include "typedef_cl.h"
#include "ast_cl.h"
#include "pl_udt.h"
#include "dml_cl.h"
#include "pl_dc.h"
#include "func_parser.h"

static status_t plc_compile_cursor_select(pl_compiler_t *compiler, plv_decl_t *decl, word_t *word, text_t *sql_text)
{
    sql_text->len = 0;
    sql_text->str = compiler->convert_buf;

    CT_RETURN_IFERR(plc_concat_str(sql_text, compiler->convert_buf_size, "select "));
    compiler->current_input = decl->cursor.input;
    compiler->keyword_hook = plc_dmlhook_none;
    // column name
    CT_RETURN_IFERR(plc_compile_dml(compiler, sql_text, word, PLV_VARIANT_ALL | PLV_CUR, (void *)decl));

    if (word->type != WORD_TYPE_PL_TERM && word->type != WORD_TYPE_EOF) {
        CT_SRC_THROW_ERROR(decl->loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t plc_expanse_cursor_def(pl_compiler_t *compiler, plv_decl_t *decl, pl_line_open_t *line,
    bool32 dynamic_check)
{
    word_t word;
    text_t sql_text;
    source_location_t loc;
    sql_context_t *cursor_ctx = NULL;
    lex_t *lex = compiler->stmt->session->lex;
    sql_stmt_t *stmt = compiler->stmt;
    pl_entity_t *entity = (pl_entity_t *)compiler->entity;

    loc = lex->loc;
    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "SELECT"));

    PLC_RESET_WORD_LOC(lex, &word);
    CT_RETURN_IFERR(plc_compile_cursor_select(compiler, decl, &word, &sql_text));
    cm_trim_text(&sql_text);

    CM_ASSERT(decl->cursor.ctx->context == NULL);
    CTSQL_SAVE_STACK(stmt);
    if (pl_compile_parse_sql(stmt, &cursor_ctx, &sql_text, &loc, &entity->sqls) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    CTSQL_RESTORE_STACK(stmt);

    if (decl->cursor.ctx->is_sysref == CT_FALSE) {
        decl->cursor.ctx->context = cursor_ctx;
    } else {
        ((pl_line_open_t *)line)->context = cursor_ctx;
    }

    if (!cursor_ctx->cacheable) {
        // if not cached, need inherit for reparse next time.
        pl_entity_uncacheable(compiler->entity);
    }

    /* add referenced object info to current compiler statement */
    CT_RETURN_IFERR(sql_append_references(&entity->ref_list, cursor_ctx));

    return CT_SUCCESS;
}

static status_t plc_copy_context_rscols(pl_compiler_t *compiler, sql_context_t *sql_ctx, plv_record_t *record)
{
    uint32 col_id;
    plv_record_attr_t *attr = NULL;
    lex_t *lex = compiler->stmt->session->lex;
    pl_entity_t *pl_entity = compiler->entity;

    for (col_id = 0; col_id < sql_ctx->rs_columns->count; col_id++) {
        rs_column_t *col = cm_galist_get(sql_ctx->rs_columns, col_id);
        /* column type do not support the array type */
        if (col->typmod.is_array) {
            CT_SRC_THROW_ERROR(lex->loc, ERR_PL_UNSUPPORT);
            return CT_ERROR;
        }
        attr = udt_record_alloc_attr(pl_entity, record);
        if (attr == NULL) {
            pl_check_and_set_loc(lex->loc);
            return CT_ERROR;
        }
        CT_RETURN_IFERR(pl_copy_name_cs(pl_entity, &col->name, &attr->name, CT_FALSE));
        attr->type = UDT_SCALAR;
        CT_RETURN_IFERR(pl_alloc_mem(pl_entity, sizeof(field_scalar_info_t), (void **)&attr->scalar_field));
        attr->scalar_field->type_mode = col->typmod;
        attr->default_expr = NULL;
        attr->nullable = CT_FALSE;
        if (attr->scalar_field->type_mode.datatype != CT_TYPE_UNKNOWN) {
            CT_RETURN_IFERR(plc_check_datatype(compiler, &attr->scalar_field->type_mode, CT_FALSE));
        }
    }
    return CT_SUCCESS;
}

static status_t plc_expanse_cursor_defs_core(pl_compiler_t *compiler, plv_decl_t *decl, lex_t *lex)
{
    if (decl->cursor.sql.len != 0) {
        CT_RETURN_IFERR(lex_push(lex, &decl->cursor.sql));
        if (plc_expanse_cursor_def(compiler, decl, NULL, CT_FALSE) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }
        if (decl->cursor.record != NULL) {
            if (plc_copy_context_rscols(compiler, decl->cursor.ctx->context, decl->cursor.record) != CT_SUCCESS) {
                lex_pop(lex);
                return CT_ERROR;
            }
        }
        lex_pop(lex);
    }
    return CT_SUCCESS;
}


static status_t plc_compile_static_refcur(pl_compiler_t *compiler, bool32 bracketed, sql_text_t *sql, word_t *word,
    plv_decl_t *decl, pl_line_open_t *line)
{
    lex_t *lex = compiler->stmt->session->lex;
    if (bracketed) {
        CT_RETURN_IFERR(lex_push(lex, sql));
        if (plc_expanse_cursor_def(compiler, decl, line, CT_TRUE) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }
        lex_pop(lex);
        CT_RETURN_IFERR(lex_fetch(lex, word));
        if (IS_SPEC_CHAR(word, ';')) {
            return CT_SUCCESS;
        }
        CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
        return CT_ERROR;
    }

    return plc_expanse_cursor_def(compiler, decl, line, CT_TRUE);
}

static status_t plc_compile_refcur_using(pl_compiler_t *compiler, word_t *word, pl_line_open_t *line)
{
    expr_tree_t *expr = NULL;
    bool32 result = CT_FALSE;
    lex_t *lex = compiler->stmt->session->lex;

    CT_RETURN_IFERR(plc_init_galist(compiler, &line->using_exprs));

    while (CT_TRUE) {
        CT_RETURN_IFERR(lex_try_fetch(lex, "IN", &result));
        // allow 'IN', except 'OUT' OR 'IN OUT'
        CT_RETURN_IFERR(lex_try_fetch(lex, "OUT", &result));
        if (result) {
            CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_PLSQL_ILLEGAL_LINE_FMT,
                "OUT and IN/OUT modes cannot be opened in refcursor");
            return CT_ERROR;
        }
        CT_RETURN_IFERR(sql_create_expr_until(compiler->stmt, &expr, word));
        CT_RETURN_IFERR(plc_verify_expr(compiler, expr));
        CT_RETURN_IFERR(plc_clone_expr_tree(compiler, &expr));
        CT_RETURN_IFERR(cm_galist_insert(line->using_exprs, expr));
        if (word->text.len != 1 || word->text.str[0] != ',') {
            break;
        }
    }

    return CT_SUCCESS;
}

static status_t plc_compile_dynamic_refcur(pl_compiler_t *compiler, word_t *word, pl_line_open_t *line)
{
    CT_RETURN_IFERR(sql_create_expr_until(compiler->stmt, &line->dynamic_sql, word));
    CT_RETURN_IFERR(plc_verify_expr(compiler, line->dynamic_sql));
    CT_RETURN_IFERR(plc_clone_expr_tree(compiler, &line->dynamic_sql));

    if (IS_SPEC_CHAR(word, ';')) {
        return CT_SUCCESS;
    }

    if (word->id != KEY_WORD_USING) {
        CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_SQL_SYNTAX_ERROR, "USING expected");
        return CT_ERROR;
    }

    return plc_compile_refcur_using(compiler, word, line);
}

static status_t plc_check_same_cursor_args_name(pl_compiler_t *compiler, galist_t *args)
{
    uint32 i;
    uint32 j;
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;

    for (i = 0; i < args->count; i++) {
        arg1 = (expr_tree_t *)cm_galist_get(args, i);
        CT_CONTINUE_IFTRUE(arg1->arg_name.len == 0);

        for (j = i + 1; j < args->count; j++) { // not overflow
            arg2 = (expr_tree_t *)cm_galist_get(args, j);
            CT_CONTINUE_IFTRUE(arg2->arg_name.len == 0);

            if (cm_compare_text_ins(&arg1->arg_name, &arg2->arg_name) == 0) {
                CT_SRC_THROW_ERROR(arg1->loc, ERR_PL_DUP_ARG_FMT, T2S(&arg1->arg_name), "cursor");
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

status_t plc_build_open_cursor_args(pl_compiler_t *compiler, word_t *word, galist_t *expr_list)
{
    expr_tree_t *arg_expr = NULL;
    sql_text_t *arg_text = NULL;
    sql_stmt_t *stmt = compiler->stmt;
    lex_t *lex = stmt->session->lex;
    bool32 assign_arg = CT_FALSE;
    text_t arg_name;
    text_t pl_arg_name;

    arg_text = &word->text;
    lex_remove_brackets(arg_text);

    CT_RETURN_IFERR(lex_push(lex, arg_text));
    while (CT_TRUE) {
        arg_name.len = 0;
        if (sql_try_fetch_func_arg(stmt, &arg_name) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }

        if (pl_copy_text(compiler->entity, &arg_name, &pl_arg_name) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }

        if (arg_name.len == 0 && assign_arg) {
            lex_pop(lex);
            CT_SRC_THROW_ERROR(word->text.loc, ERR_PL_EXPECTED_FAIL_FMT, "'=>'", "NULL");
            return CT_ERROR;
        }

        PLC_RESET_WORD_LOC(lex, word);
        if (sql_create_expr_until(stmt, &arg_expr, word) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }
        if (plc_verify_expr(compiler, arg_expr) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }
        if (plc_clone_expr_tree(compiler, &arg_expr) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }
        if (arg_name.len > 0) {
            assign_arg = CT_TRUE;
            arg_expr->arg_name = pl_arg_name;
        }

        if (cm_galist_insert(expr_list, arg_expr) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }

        if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_OPERATOR) {
            break;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            lex_pop(lex);
            CT_SRC_THROW_ERROR(word->text.loc, ERR_PL_EXPECTED_FAIL_FMT, "','", W2S(word));
            return CT_ERROR;
        }
    }
    lex_pop(lex);

    return plc_check_same_cursor_args_name(compiler, expr_list);
}

/*
 * @brief    implicit cursor's attribiute must equal 'SQL'
 */
static status_t plc_check_cursor_name(pl_compiler_t *compiler, source_location_t loc, text_t *name)
{
    if (cm_text_str_equal_ins(name, "SQL")) {
        CT_SRC_THROW_ERROR(loc, ERR_PL_SYNTAX_ERROR_FMT,
            "Encountered the symbol 'SQL' when expecting one of the following:"
            "<an identifier> <a double-quoted delimited-identifier>");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t plc_compile_cursor_arg(pl_compiler_t *compiler, plv_decl_t *cur, galist_t *decls, word_t *word)
{
    bool32 result = CT_FALSE;
    plv_decl_t *decl = NULL;
    lex_t *lex = compiler->stmt->session->lex;
    pl_entity_t *pl_entity = compiler->entity;
    CT_RETURN_IFERR(cm_galist_new(decls, sizeof(plv_decl_t), (void **)&decl));
    decl->vid.block = (int16)compiler->stack.depth;
    decl->vid.id = decls->count - 1; // not overflow

    CT_RETURN_IFERR(lex_fetch(lex, word));
    if (!IS_VARIANT(word)) {
        CT_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, "VARIANT", W2S(word));
        return CT_ERROR;
    }
    CT_RETURN_IFERR(pl_copy_object_name_ci(pl_entity, word->type, (text_t *)&word->text, &decl->name));
    CT_RETURN_IFERR(lex_try_fetch(lex, "in", &result));

    decl->drct = PLV_DIR_IN;
    CT_RETURN_IFERR(plc_compile_variant_def(compiler, word, decl, CT_TRUE, decls, CT_TRUE));
    CT_RETURN_IFERR(plc_compile_default_def(compiler, word, decl, CT_TRUE));

    // add args check here to avoid generate error.
    if ((word->type != WORD_TYPE_EOF) && !(IS_SPEC_CHAR(word, ','))) {
        if (word->type == WORD_TYPE_BRACKET) {
            CT_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, ":= or default or another arg or end of args",
                "BRACKET symbol '('");
        } else {
            CT_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, ":= or default or another arg or end of args",
                W2S(word));
        }
        return CT_ERROR;
    }

    if ((decl->type & PLV_VAR) == 0) {
        CT_SRC_THROW_ERROR(word->loc, ERR_PLSQL_ILLEGAL_LINE_FMT, "cursor arg should be variant.");
        return CT_ERROR;
    }
    // give a tag for cursor arg, actual only PLV_VAR.
    decl->type = PLV_VAR;
    decl->arg_type = PLV_CURSOR_ARG;
    // temp support curr size.
    if (CT_IS_VARLEN_TYPE(decl->variant.type.datatype)) {
        decl->variant.type.size = CT_STRING_BUFFER_SIZE;
    }
    return cm_galist_insert(cur->cursor.ctx->args, decl);
}

static status_t plc_compile_cursor_args(pl_compiler_t *compiler, plv_decl_t *decl, galist_t *decls, word_t *word)
{
    lex_t *lex = compiler->stmt->session->lex;
    cm_trim_text((text_t *)&word->text);
    if (((text_t *)&word->text)->len == 0) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(plc_init_galist(compiler, &decl->cursor.ctx->args));

    CT_RETURN_IFERR(lex_push(lex, &word->text));
    while (CT_TRUE) {
        if (plc_compile_cursor_arg(compiler, decl, decls, word) != CT_SUCCESS) {
            decl->cursor.ctx->is_err = (bool8)CT_TRUE;
            lex_pop(lex);
            return CT_ERROR;
        }
        if ((word->type == WORD_TYPE_EOF) || !(IS_SPEC_CHAR(word, ','))) {
            break;
        }
    }
    lex_pop(lex);

    return CT_SUCCESS;
}

status_t plc_compile_cursor_def(pl_compiler_t *compiler, galist_t *decls, word_t *word)
{
    bool32 result = CT_FALSE;
    plv_decl_t *decl = NULL;
    lex_t *lex = compiler->stmt->session->lex;
    pl_entity_t *pl_entity = compiler->entity;

    CT_RETURN_IFERR(lex_fetch(lex, word));
    CT_RETURN_IFERR(plc_check_cursor_name(compiler, word->loc, (text_t *)&word->text));

    CT_RETURN_IFERR(plc_verify_word_as_var(compiler, word));
    plc_find_decl_ex(compiler, word, PLV_CUR, NULL, &decl);
    if (decl != NULL && decl->cursor.ctx->is_sysref) {
        CT_SRC_THROW_ERROR_EX(word->loc, ERR_PLSQL_ILLEGAL_LINE_FMT, "%s is sys_refcursor conflict with cursor def.",
            W2S(word));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(cm_galist_new(decls, sizeof(plv_decl_t), (void **)&decl));
    CT_RETURN_IFERR(pl_alloc_mem(pl_entity, sizeof(plv_cursor_context_t), (void **)&decl->cursor.ctx));
    CT_RETURN_IFERR(pl_copy_object_name_ci(pl_entity, word->type, (text_t *)&word->text, &decl->name));
    decl->vid.block = (int16)compiler->stack.depth;
    decl->vid.id = decls->count - 1; // not overflow
    decl->type = PLV_CUR;
    decl->cursor.ctx->is_sysref = (bool8)CT_FALSE;
    decl->loc = word->text.loc;
    decl->cursor.ctx->is_err = (bool8)CT_FALSE;
    CT_RETURN_IFERR(lex_try_fetch_bracket(lex, word, &result));
    if (result) {
        CT_RETURN_IFERR(plc_compile_cursor_args(compiler, decl, decls, word));
    }

    CT_RETURN_IFERR(lex_try_fetch(lex, "RETURN", &result));
    if (result) {
        CT_SRC_THROW_ERROR(lex->loc, ERR_PL_UNSUPPORT); // don't return CT_ERROR
    }

    CT_RETURN_IFERR(lex_try_fetch(lex, "IS", &result));
    if (result) {
        CT_RETURN_IFERR(lex_try_fetch_bracket(lex, word, &result));
        if (!result) {
            decl->cursor.sql = *(lex->curr_text);
        } else {
            decl->cursor.sql = word->text;
        }
        CT_RETURN_IFERR(lex_fetch_to_char(lex, word, ';'));
    } else {
        decl->cursor.sql.value = CM_NULL_TEXT;
        CT_RETURN_IFERR(lex_expected_fetch_word(lex, ";"));
        word->type = WORD_TYPE_PL_TERM;
    }

    return plc_init_galist(compiler, &decl->cursor.input);
}

static status_t plc_compile_for_impcur(pl_compiler_t *compiler, pl_line_for_t *line, word_t *word)
{
    text_t sql;
    plv_decl_t *id = line->id;
    plv_decl_t *imp_cur = NULL;
    source_location_t loc;
    lex_t *lex = compiler->stmt->session->lex;
    sql_stmt_t *stmt = compiler->stmt;
    pl_entity_t *entity = (pl_entity_t *)compiler->entity;

    sql.str = compiler->convert_buf;
    sql.len = 0;
    CT_RETURN_IFERR(cm_galist_new(line->decls, sizeof(plv_decl_t), (void **)&imp_cur));
    CT_RETURN_IFERR(pl_alloc_mem(entity, sizeof(plv_cursor_context_t), (void **)&imp_cur->cursor.ctx));
    CT_RETURN_IFERR(plc_init_galist(compiler, &imp_cur->cursor.input));
    compiler->current_input = imp_cur->cursor.input;
    imp_cur->vid.block = id->vid.block;
    imp_cur->vid.id = line->decls->count - 1; // not overflow
    imp_cur->type = PLV_IMPCUR;
    line->cursor_id = imp_cur->vid;

    loc = word->loc;
    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "SELECT"));
    CT_RETURN_IFERR(plc_compile_select(compiler, &sql, word, CT_FALSE));

    cm_trim_text(&sql);

    CTSQL_SAVE_STACK(stmt);
    if (pl_compile_parse_sql(stmt, &line->context, &sql, &loc, &entity->sqls) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    CTSQL_RESTORE_STACK(stmt);

    if (!line->context->cacheable) {
        // if not cached, need inherit for reparse next time.
        pl_entity_uncacheable(entity);
    }

    /* add referenced object info to entity's ref_list */
    CT_RETURN_IFERR(sql_append_references(&entity->ref_list, line->context));
    CT_RETURN_IFERR(plc_copy_context_rscols(compiler, line->context, line->id->record));
    CT_RETURN_IFERR(plc_init_galist(compiler, &line->into.output));
    CT_RETURN_IFERR(udt_build_list_address_single(compiler->stmt, line->into.output, line->id, UDT_STACK_ADDR));

    line->into.prefetch_rows = INTO_COMMON_PREFETCH_COUNT;
    line->into.into_type = (uint8)INTO_AS_REC;
    line->into.is_bulk = CT_FALSE;

    // UNAME.IMPILICT CURSOR.
    imp_cur->cursor.sql.value = CM_NULL_TEXT;
    imp_cur->drct = PLV_DIR_NONE;
    imp_cur->cursor.ctx->context = line->context;
    return CT_SUCCESS;
}

status_t plc_compile_for_cursor(pl_compiler_t *compiler, pl_line_for_t *line, word_t *word)
{
    plv_decl_t *decl = NULL;
    bool32 result = CT_FALSE;
    uint32 save_flags;
    plv_decl_t *id = line->id;
    plv_decl_t *type_record = NULL;
    lex_t *lex = compiler->stmt->session->lex;
    pl_entity_t *pl_entity = compiler->entity;
    id->type = PLV_RECORD;
    CT_RETURN_IFERR(pl_copy_name(pl_entity, (text_t *)&word->text, &id->name));
    /* alloc anonymous record type */
    CT_RETURN_IFERR(cm_galist_new(line->decls, sizeof(plv_decl_t), (void **)&type_record));
    type_record->type = PLV_TYPE;
    type_record->typdef.type = PLV_RECORD;
    type_record->typdef.record.root = type_record;
    type_record->typdef.record.is_anonymous = CT_TRUE;
    id->record = &type_record->typdef.record;

    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "in"));
    // (1) for variant in (...)
    CT_RETURN_IFERR(lex_try_fetch_bracket(lex, word, &result));
    if (result) {
        line->is_impcur = CT_TRUE;
        CT_RETURN_IFERR(lex_push(lex, &word->text));
        status_t status = plc_compile_for_impcur(compiler, line, word);
        lex_pop(lex);
        return status;
    }

    // (2) for variant in  Explicit cursor loop
    save_flags = lex->flags;
    lex->flags = LEX_WITH_OWNER;
    CT_RETURN_IFERR(lex_fetch(lex, word));

    if (word->type != WORD_TYPE_PARAM) {
        CT_RETURN_IFERR(plc_find_decl(compiler, word, PLV_CUR, NULL, &decl));
        if (cm_text_equal(&id->name, &decl->name)) {
            CT_SRC_THROW_ERROR(word->loc, ERR_PL_INVALID_LOOP_INDEX, T2S(&line->id->name));
            return CT_ERROR;
        }
    } else {
        CT_SRC_THROW_ERROR(word->loc, ERR_PLSQL_ILLEGAL_LINE_FMT,
            "the declaration of the cursor of this expression is incomplete or malformed");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(lex_try_fetch_bracket(lex, word, &result));
    if (result) {
        lex_trim(&word->text);
        if (word->text.len == 0) {
            result = CT_FALSE;
        }
    }

    if (result) {
        CT_RETURN_IFERR(plc_init_galist(compiler, &line->exprs));
        CT_RETURN_IFERR(plc_build_open_cursor_args(compiler, word, line->exprs));
        CT_RETURN_IFERR(plc_verify_cursor_args(compiler, line->exprs, decl->cursor.ctx->args, line->ctrl.loc));
    } else {
        line->exprs = NULL;
    }
    lex->flags = save_flags;

    if (decl->cursor.ctx->is_sysref) {
        CT_SRC_THROW_ERROR(word->loc, ERR_INVALID_CURSOR);
        return CT_ERROR;
    }
    line->is_impcur = CT_FALSE;
    line->cursor_id = decl->vid;

    if (decl->cursor.ctx->context == NULL) {
        CT_SRC_THROW_ERROR(word->loc, ERR_UNDEFINED_SYMBOL_FMT, W2S(word));
        return CT_ERROR;
    }
    CT_RETURN_IFERR(plc_copy_context_rscols(compiler, decl->cursor.ctx->context, line->id->record));
    CT_RETURN_IFERR(plc_init_galist(compiler, &line->into.output));
    CT_RETURN_IFERR(udt_build_list_address_single(compiler->stmt, line->into.output, id, UDT_STACK_ADDR));

    line->into.prefetch_rows = INTO_COMMON_PREFETCH_COUNT;
    line->into.into_type = (uint8)INTO_AS_REC;
    line->into.is_bulk = CT_FALSE;
    return CT_SUCCESS;
}

status_t plc_compile_refcur(pl_compiler_t *compiler, word_t *word, plv_decl_t *decl, pl_line_open_t *line)
{
    lex_t *lex = compiler->stmt->session->lex;
    bool32 bracketed = CT_FALSE;
    sql_text_t sql;

    /* open cursor FOR {select_statement | dynamic_string} [USING_CLAUSE]
    hit cursors variables scenario */
    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "FOR"));
    CT_RETURN_IFERR(lex_try_fetch_bracket(lex, word, &bracketed));

    if (bracketed) {
        sql = word->text;
        CT_RETURN_IFERR(lex_extract_first(&word->text, word));
    } else {
        CT_RETURN_IFERR(lex_extract_first(lex->curr_text, word));
    }

    if (word->id == KEY_WORD_SELECT) {
        line->is_dynamic_sql = CT_FALSE;
        CT_RETURN_IFERR(plc_init_galist(compiler, &line->input));
        decl->cursor.input = line->input;
        CT_RETURN_IFERR(plc_compile_static_refcur(compiler, bracketed, &sql, word, decl, line));
        decl->cursor.input = NULL;
    } else {
        lex_back(lex, word);
        line->is_dynamic_sql = CT_TRUE;
        CT_RETURN_IFERR(plc_compile_dynamic_refcur(compiler, word, line));
    }

    return CT_SUCCESS;
}

status_t plc_diagnose_for_is_cursor(pl_compiler_t *compiler, bool8 *is_cur)
{
    bool32 result = CT_FALSE;
    word_t word;
    lex_t *lex = compiler->stmt->session->lex;

    LEX_SAVE(lex);
    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "in"));
    // (1) for variant in (...)
    CT_RETURN_IFERR(lex_try_fetch_bracket(lex, &word, &result));
    CT_RETURN_IFERR(lex_fetch(lex, &word));
    if (result) {
        if (word.type == WORD_TYPE_PL_RANGE) {
            result = CT_FALSE;
        }
    }
    if (!result) {
        // (2) for variant in cur loop
        CT_RETURN_IFERR(lex_try_fetch(lex, "loop", &result));
    }
    LEX_RESTORE(lex);

    *is_cur = (bool8)result;
    return CT_SUCCESS;
}

status_t plc_expanse_cursor_defs(pl_compiler_t *compiler, galist_t *decls)
{
    lex_t *lex = compiler->stmt->session->lex;
    plv_decl_t *decl = NULL;
    uint32 i;
    uint32 count = decls->count;
    for (i = 0; i < count; i++) {
        decl = (plv_decl_t *)cm_galist_get(decls, i);
        if (decl->type == PLV_CUR) {
            CT_RETURN_IFERR(plc_expanse_cursor_defs_core(compiler, decl, lex));
        }
    }

    return CT_SUCCESS;
}

status_t plc_verify_cursor_args(pl_compiler_t *compiler, galist_t *expr_list, galist_t *args, source_location_t loc)
{
    if (args == NULL) {
        CT_SRC_THROW_ERROR(loc, ERR_PL_SYNTAX_ERROR_FMT, "open cursor have no args definition");
        return CT_ERROR;
    }

    if (expr_list->count > args->count) {
        CT_SRC_THROW_ERROR(loc, ERR_PL_SYNTAX_ERROR_FMT, "open cursor args no match definition");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

/*
 * @brief    compile sys_refcursor define
 */
status_t plc_compile_syscursor_def(pl_compiler_t *compiler, word_t *word, plv_decl_t *decl)
{
    pl_entity_t *pl_entity = compiler->entity;
    CT_RETURN_IFERR(pl_copy_object_name_ci(pl_entity, word->type, (text_t *)&word->text, &decl->name));
    CT_RETURN_IFERR(pl_alloc_mem(pl_entity, sizeof(plv_cursor_context_t), (void **)&decl->cursor.ctx));
    decl->cursor.ctx->is_sysref = (bool8)CT_TRUE;
    decl->cursor.input = NULL;
    return CT_SUCCESS;
}

status_t plc_compile_type_refcur_def(pl_compiler_t *compiler, plv_decl_t *decl, galist_t *decls, word_t *word)
{
    lex_t *lex = compiler->stmt->session->lex;
    bool32 result = CT_FALSE;
    decl->typdef.type = PLV_CUR;
    CT_RETURN_IFERR(lex_try_fetch(lex, "RETURN", &result));
    if (result) {
        CT_SRC_THROW_ERROR(lex->loc, ERR_PL_UNSUPPORT);
        return CT_ERROR;
    }
    return lex_expected_fetch_word(lex, ";");
}

status_t plc_verify_cursor_setval(pl_compiler_t *compiler, expr_tree_t *expr)
{
    if (expr->root->datatype != CT_TYPE_CURSOR) {
        CT_SRC_THROW_ERROR(expr->loc, ERR_PL_EXPR_WRONG_TYPE);
        return CT_ERROR;
    }
    if (expr->root->type == EXPR_NODE_USER_FUNC) {
        return CT_SUCCESS;
    }
    if (expr->root->type != EXPR_NODE_V_ADDR || compiler->stack.depth == 0) {
        CT_SRC_THROW_ERROR(expr->loc, ERR_PL_EXPR_WRONG_TYPE);
        return CT_ERROR;
    }
    var_address_pair_t *pair = sql_get_last_addr_pair(expr->root);
    if (pair == NULL || pair->type != UDT_STACK_ADDR) {
        CT_SRC_THROW_ERROR(expr->loc, ERR_PL_EXPR_WRONG_TYPE);
        return CT_ERROR;
    }

    plv_decl_t *decl = pair->stack->decl;
    if (decl->cursor.ctx != NULL && (decl->cursor.ctx->is_sysref == CT_FALSE ||
        (decl->cursor.ctx->args != NULL && decl->cursor.ctx->args->count != 0))) {
        CT_SRC_THROW_ERROR(expr->loc, ERR_PL_EXPR_WRONG_TYPE);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t plc_verify_using_out_cursor(pl_compiler_t *compiler, expr_tree_t *expr)
{
    expr_node_t *node = expr->root;
    if (node->type == EXPR_NODE_V_ADDR) {
        if (compiler == NULL) {
            return CT_SUCCESS;
        }
        var_address_pair_t *pair = sql_get_last_addr_pair(node);
        if (pair == NULL || pair->type != UDT_STACK_ADDR) {
            return CT_SUCCESS;
        }
        if (pair->stack->decl != NULL && pair->stack->decl->type == PLV_CUR) {
            CT_SRC_THROW_ERROR(expr->loc, ERR_PL_SYNTAX_ERROR_FMT,
                "out param of using clause only support normal variable, not cursor");
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}
