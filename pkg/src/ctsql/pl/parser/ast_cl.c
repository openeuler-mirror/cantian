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
 * ast_cl.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/parser/ast_cl.c
 *
 * -------------------------------------------------------------------------
 */

#include "ast_cl.h"
#include "decl_cl.h"
#include "srv_instance.h"
#include "pl_memory.h"
#include "base_compiler.h"
#include "cursor_cl.h"
#include "trigger_decl_cl.h"
#include "pl_executor.h"
#include "typedef_cl.h"
#include "pragma_cl.h"
#include "lines_cl.h"

#define PLC_ENDLN_TEXT_EQUAL(dest, src, type)                                                                          \
    (((IS_DQ_STRING(type) || !IS_CASE_INSENSITIVE) && cm_text_equal((const text_t *)(dest), (const text_t *)(src))) || \
        (!IS_DQ_STRING(type) && cm_text_equal_ins2((const text_t *)(dest), (const text_t *)(src))))

pl_line_ctrl_t *plc_get_current_beginln(pl_compiler_t *compiler)
{
    uint16 i = compiler->stack.depth - 1; // not overflow

    pl_line_type_t type = compiler->stack.items[i].entry->type;
    if (type == LINE_BEGIN) {
        return compiler->stack.items[i].entry;
    }

    return NULL;
}

status_t plc_expected_end_ln(pl_compiler_t *compiler, bool32 *res, var_udo_t *obj, word_t *word)
{
    pl_line_begin_t *begin_line = NULL;
    lex_t *lex = compiler->stmt->session->lex;

    if (word->id != KEY_WORD_END) {
        *res = CT_FALSE;
        return CT_SUCCESS;
    }

    compiler->line_loc = word->loc;
    begin_line = (pl_line_begin_t *)plc_get_current_beginln(compiler);
    if (begin_line == NULL) {
        return CT_ERROR;
    }

    /* make sure the block is end with obj_name or block name */
    lex->flags = LEX_WITH_OWNER;

    CT_RETURN_IFERR(lex_try_fetch_variant(lex, word, res));
    if (*res) {
        if (obj != NULL && plc_expected_end_value_equal(compiler, obj, word)) {
            *res = CT_TRUE;
        } else if (begin_line->name != NULL && word->ex_count == 0 &&
            PLC_ENDLN_TEXT_EQUAL(begin_line->name, &word->text.value, word->type)) {
            *res = CT_TRUE;
        } else {
            CT_SRC_THROW_ERROR(word->loc, ERR_UNDEFINED_SYMBOL_FMT, W2S_EX(word));
            return CT_ERROR;
        }
    }

    /* expected to find ';' */
    if (lex_eof(lex)) {
        *res = CT_TRUE;
    } else {
        CT_RETURN_IFERR(lex_try_fetch_char(lex, ';', res));
    }

    if (!(*res)) {
        CT_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static void plc_pop_block(plc_block_stack_t *stack)
{
    if (stack->depth > 0) {
        stack->depth--;
    }
}

status_t plc_pop(pl_compiler_t *compiler, source_location_t loc, pl_block_end_t pbe, pl_line_ctrl_t **res)
{
    pl_line_ctrl_t *line = NULL;
    pl_line_type_t type;
    plc_block_stack_t *stack = NULL;

    switch (pbe) {
        case PBE_END:
            line = CURR_BLOCK_BEGIN(compiler);
            type = (line == NULL) ? LINE_UNKNOWN : line->type;
            if (!(type == LINE_BEGIN || type == LINE_EXCEPTION)) {
                CT_SRC_THROW_ERROR(loc, ERR_PL_UNEXPECTED_FMT, "END");
                return CT_ERROR;
            }
            stack = &compiler->stack;
            break;

        case PBE_END_IF:
            line = CURR_CTL_BLOCK_BEGIN(compiler);
            type = (line == NULL) ? LINE_UNKNOWN : line->type;
            if (!(type == LINE_IF || type == LINE_ELIF || type == LINE_ELSE)) {
                CT_SRC_THROW_ERROR(loc, ERR_PL_UNEXPECTED_FMT, "END IF");
                return CT_ERROR;
            }
            stack = &compiler->control_stack;
            break;

        case PBE_ELIF:
            line = CURR_CTL_BLOCK_BEGIN(compiler);
            type = (line == NULL) ? LINE_UNKNOWN : line->type;
            if (!(type == LINE_IF || type == LINE_ELIF)) {
                CT_SRC_THROW_ERROR(loc, ERR_PL_UNEXPECTED_FMT, "ELIF");
                return CT_ERROR;
            }
            stack = &compiler->control_stack;
            break;

        case PBE_ELSE:
            line = CURR_CTL_BLOCK_BEGIN(compiler);
            type = (line == NULL) ? LINE_UNKNOWN : line->type;
            if (!(type == LINE_IF || type == LINE_ELIF || type == LINE_WHEN_CASE)) {
                CT_SRC_THROW_ERROR(loc, ERR_PL_UNEXPECTED_FMT, "ELSE");
                return CT_ERROR;
            }
            stack = &compiler->control_stack;
            break;

        case PBE_END_LOOP:
            line = CURR_CTL_BLOCK_BEGIN(compiler);
            type = (line == NULL) ? LINE_UNKNOWN : line->type;
            if (!(type == LINE_LOOP || type == LINE_FOR || type == LINE_WHILE)) {
                CT_SRC_THROW_ERROR(loc, ERR_PL_UNEXPECTED_FMT, "END LOOP");
                return CT_ERROR;
            }
            if (type == LINE_FOR) {
                pl_line_ctrl_t *line_for = CURR_BLOCK_BEGIN(compiler);
                pl_line_type_t type_for = (line_for == NULL) ? LINE_UNKNOWN : line_for->type;
                if (type != type_for) {
                    CT_SRC_THROW_ERROR(loc, ERR_PL_UNEXPECTED_FMT, "END LOOP");
                    return CT_ERROR;
                }
                stack = &compiler->stack;
                plc_pop_block(stack);
            }
            stack = &compiler->control_stack;
            break;

        case PBE_WHEN_CASE:
            line = CURR_CTL_BLOCK_BEGIN(compiler);
            type = (line == NULL) ? LINE_UNKNOWN : line->type;
            if (!(type == LINE_CASE || type == LINE_WHEN_CASE)) {
                CT_SRC_THROW_ERROR(loc, ERR_PL_UNEXPECTED_FMT, "CASE WHEN");
                return CT_ERROR;
            }
            stack = &compiler->control_stack;
            break;

        case PBE_END_CASE:
            line = CURR_CTL_BLOCK_BEGIN(compiler);
            type = (line == NULL) ? LINE_UNKNOWN : line->type;
            if (!(type == LINE_ELSE || type == LINE_WHEN_CASE)) {
                CT_SRC_THROW_ERROR(loc, ERR_PL_UNEXPECTED_FMT, "END CASE");
                return CT_ERROR;
            }
            stack = &compiler->control_stack;
            break;

        case PBE_END_EXCEPTION:
            line = CURR_BLOCK_BEGIN(compiler);
            type = (line == NULL) ? LINE_UNKNOWN : line->type;
            if (!(type == LINE_EXCEPTION)) {
                CT_SRC_THROW_ERROR(loc, ERR_PL_UNEXPECTED_FMT, "END EXCEPTION");
                return CT_ERROR;
            }
            stack = &compiler->stack;
            break;

        default:
            CT_SRC_THROW_ERROR_EX(loc, ERR_PL_UNEXPECTED_FMT, "PBE(%u)", pbe);
            return CT_ERROR;
    }

    plc_pop_block(stack);

    if (res != NULL) {
        *res = line;
    }
    return CT_SUCCESS;
}

status_t plc_try_compile_end_ln(pl_compiler_t *compiler, bool32 *res, var_udo_t *obj, word_t *word)
{
    pl_line_ctrl_t *line = NULL;
    pl_line_begin_t *begin_line = NULL;

    compiler->line_loc = word->loc;

    CT_RETURN_IFERR(plc_expected_end_ln(compiler, res, obj, word));
    if (*res) {
        begin_line = (pl_line_begin_t *)plc_get_current_beginln(compiler);
        if (begin_line == NULL) {
            return CT_ERROR;
        }

        CT_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_ctrl_t), LINE_END, (pl_line_ctrl_t **)&line));
        begin_line->end = line;
        CT_RETURN_IFERR(plc_pop(compiler, compiler->line_loc, PBE_END, NULL));
    }

    return CT_SUCCESS;
}

status_t plc_skip_error_line(pl_compiler_t *compiler, word_t *word)
{
    if (word->type != WORD_TYPE_PL_TERM) {
        CT_RETURN_IFERR(lex_fetch_to_char(compiler->stmt->session->lex, word, ';'));
    }
    return CT_SUCCESS;
}

static void plc_push_block(plc_block_stack_t *stack, pl_line_ctrl_t *line, const text_t *name)
{
    stack->items[stack->depth].entry = line;
    stack->items[stack->depth].name = *name;
    stack->depth++;
}

status_t plc_push_ctl(pl_compiler_t *compiler, pl_line_ctrl_t *line, const text_t *block_name)
{
    if (compiler->control_stack.depth >= PL_MAX_BLOCK_DEPTH) {
        CT_SRC_THROW_ERROR(line->loc, ERR_PL_BLOCK_TOO_DEEP_FMT, PL_MAX_BLOCK_DEPTH);
        return CT_ERROR;
    }

    plc_push_block(&compiler->control_stack, line, block_name);
    return CT_SUCCESS;
}

static void plc_error_wrong_type_as_left(pl_compiler_t *compiler, source_location_t loc, pl_arg_info_t *arg_info)
{
    if (arg_info == NULL) {
        CT_SRC_THROW_ERROR(loc, ERR_PL_EXPR_WRONG_TYPE);
    } else {
        CT_SRC_THROW_ERROR(arg_info->func->loc, ERR_PL_ARG_FMT, arg_info->pos, T2S(&arg_info->func->word.func.name),
            "wrong type bound to an OUT position");
    }
}

static void plc_error_not_refcursor_as_left(pl_compiler_t *compiler, plv_decl_t *decl, source_location_t loc,
    pl_arg_info_t *arg_info)
{
    if (compiler == NULL) {
        if (arg_info == NULL) {
            CT_SRC_THROW_ERROR(loc, ERR_PL_EXPR_AS_LEFT_FMT, T2S(&(decl)->name));
        } else {
            CT_SRC_THROW_ERROR(arg_info->func->loc, ERR_PL_ARG_FMT, arg_info->pos, T2S(&arg_info->func->word.func.name),
                "not sysref cursor bound to an OUT position");
        }
    } else {
        if (arg_info == NULL) {
            CT_SRC_THROW_ERROR(loc, ERR_PL_EXPR_AS_LEFT_FMT, T2S(&(decl)->name));
        } else {
            CT_SRC_THROW_ERROR(arg_info->func->loc, ERR_PL_ARG_FMT, arg_info->pos, T2S(&arg_info->func->word.func.name),
                "not sysref cursor bound to an OUT position");
        }
    }
}

static void plc_error_in_dir_as_left(pl_compiler_t *compiler, plv_decl_t *decl, source_location_t loc,
    pl_arg_info_t *arg_info)
{
    if (compiler == NULL) {
        if (arg_info == NULL) {
            CT_SRC_THROW_ERROR(loc, ERR_PL_EXPR_AS_LEFT_FMT, T2S(&decl->name));
        } else {
            CT_SRC_THROW_ERROR(arg_info->func->loc, ERR_PL_ARG_FMT, arg_info->pos, T2S(&arg_info->func->word.func.name),
                "IN bind variable bound to an OUT position");
        }
    } else {
        if (arg_info == NULL) {
            CT_SRC_THROW_ERROR(loc, ERR_PL_EXPR_AS_LEFT_FMT, T2S(&decl->name));
        } else {
            CT_SRC_THROW_ERROR(arg_info->func->loc, ERR_PL_ARG_FMT, arg_info->pos, T2S(&arg_info->func->word.func.name),
                "IN bind variable bound to an OUT position");
        }
    }
}

static status_t plc_check_variant_left(pl_compiler_t *compiler, plv_decl_t *decl, source_location_t loc)
{
    CT_RETURN_IFERR(plc_verify_trigger_modified_var(compiler, decl));
    /*
     * Check the variant's validity. Variant of for-loop can not be used as left value.
     * Does not search variant at current stack, because it has not be pushed into the stack.
     */
    if ((int16)compiler->stack.depth > decl->vid.block && decl->vid.block >= 0 &&
        compiler->stack.items[decl->vid.block].entry->type == LINE_FOR) {
        CT_SRC_THROW_ERROR(loc, ERR_PL_EXPR_AS_LEFT_FMT, T2S(&decl->name));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t plc_check_param_left(pl_compiler_t *compiler, plv_decl_t *decl, source_location_t loc)
{
    sql_stmt_t *stmt = (sql_stmt_t *)compiler->stmt;
    if (stmt == NULL || ((pl_executor_t *)stmt->pl_exec) == NULL ||
        ((pl_executor_t *)stmt->pl_exec)->dynamic_parent == NULL) {
        return CT_SUCCESS;
    }

    pl_using_expr_t *using_expr = NULL;
    ple_var_t *pl_var = NULL;
    uint32 pnid = decl->pnid;

    sql_stmt_t *parent = NULL;
    CT_RETURN_IFERR(ple_get_dynsql_parent(stmt, &parent));
    if (ple_get_dynsql_using_expr(parent, pnid, &using_expr) != CT_SUCCESS) {
        cm_set_error_loc(loc);
        return CT_ERROR;
    }

    if (using_expr->dir == PLV_DIR_IN) {
        if (ple_get_using_expr_var(parent, using_expr, &pl_var, PLE_CHECK_NONE) != CT_SUCCESS) {
            pl_check_and_set_loc(loc);
            return CT_ERROR;
        }
        CT_SRC_THROW_ERROR(loc, ERR_PL_EXPR_AS_LEFT_FMT, T2S(&pl_var->decl->name));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t plc_check_decl_as_left(pl_compiler_t *compiler, plv_decl_t *decl, source_location_t loc,
    pl_arg_info_t *arg_info)
{
    if (decl->drct == PLV_DIR_IN) {
        plc_error_in_dir_as_left(compiler, decl, loc, arg_info);
        return CT_ERROR;
    }
    switch (decl->type) {
        case PLV_PARAM:
            if (compiler == NULL) {
                break;
            }
            CT_RETURN_IFERR(plc_check_param_left(compiler, decl, loc));
            break;
        case PLV_CUR:
            if (!decl->cursor.ctx->is_sysref) {
                plc_error_not_refcursor_as_left(compiler, decl, loc, arg_info);
                return CT_ERROR;
            }
            break;
        case PLV_VAR:
        case PLV_ARRAY:
            if (compiler == NULL) {
                break;
            }
            CT_RETURN_IFERR(plc_check_variant_left(compiler, decl, loc));
            break;
        case PLV_RECORD:
        case PLV_COLLECTION:
        case PLV_OBJECT:
            break;
        case PLV_EXCPT:
        case PLV_TYPE:
        default:
            plc_error_wrong_type_as_left(compiler, loc, arg_info);
            return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t plc_check_var_as_left(pl_compiler_t *compiler, expr_node_t *node, source_location_t source_loc,
    pl_arg_info_t *arg_info)
{
    plv_decl_t *decl = NULL;
    if (node->type != EXPR_NODE_V_ADDR) {
        CT_SRC_THROW_ERROR(source_loc, ERR_PL_SYNTAX_ERROR_FMT, "unexpected pl-variant occurs");
        return CT_ERROR;
    }
    var_address_t *var_addr = NODE_VALUE_PTR(var_address_t, node);
    var_address_pair_t *pair = (var_address_pair_t *)cm_galist_get(var_addr->pairs, (uint32)0);
    CM_ASSERT(pair->type == UDT_STACK_ADDR);
    decl = pair->stack->decl;
    return plc_check_decl_as_left(compiler, decl, source_loc, arg_info);
}

status_t plc_verify_out_expr(pl_compiler_t *compiler, expr_tree_t *expr, pl_arg_info_t *arg_info)
{
    expr_node_t *node = expr->root;
    if (node->type == EXPR_NODE_PARAM) {
        return CT_SUCCESS;
    } else if (node->type != EXPR_NODE_V_ADDR) {
        plc_error_wrong_type_as_left(compiler, expr->loc, arg_info);
        return CT_ERROR;
    }

    return plc_check_var_as_left(compiler, node, expr->loc, arg_info);
}

static status_t plc_compile_block_body(pl_compiler_t *compiler, text_t *block_name, var_udo_t *obj, galist_t *decls)
{
    word_t word;
    pl_line_begin_t *line = NULL;
    bool32 res = CT_FALSE;
    bool32 body_empty = CT_TRUE;
    status_t status = CT_SUCCESS;
    pl_line_label_t *label = (pl_line_label_t *)compiler->last_line;
    lex_t *lex = compiler->stmt->session->lex;

    CT_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_begin_t), LINE_BEGIN, (pl_line_ctrl_t **)&line));
    CT_RETURN_IFERR(plc_push(compiler, (pl_line_ctrl_t *)line, block_name));
    CT_RETURN_IFERR(plc_convert_typedecl(compiler, decls));
    line->decls = decls;
    line->type_decls = compiler->type_decls;
    line->name = ((label != NULL) && (label->ctrl.type == LINE_LABEL)) ? &label->name : NULL;

    if (compiler->body == NULL) {
        compiler->body = line;
    }

    lex->flags = LEX_WITH_OWNER | LEX_WITH_ARG;
    CT_RETURN_IFERR(plc_expanse_cursor_defs(compiler, decls));

    while (CT_TRUE) {
        lex->flags = LEX_SINGLE_WORD;
        CT_RETURN_IFERR(lex_fetch(lex, &word));
        plc_check_end_symbol(&word);
        CT_RETURN_IFERR(plc_check_word_eof(word.type, word.loc));

        CT_RETURN_IFERR(plc_try_compile_end_ln(compiler, &res, obj, &word));
        if (res) {
            if (body_empty) {
                CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "lines", "END");
                return CT_ERROR;
            }
            break;
        }

        if (plc_compile_lines(compiler, &word) != CT_SUCCESS) {
            status = CT_ERROR;
            CT_RETURN_IFERR(plc_skip_error_line(compiler, &word));
            if (g_tls_error.is_full) {
                return CT_ERROR;
            }
            if (word.type == WORD_TYPE_EOF) {
                break;
            }
        }
        body_empty = CT_FALSE;
    }

    return status;
}

static status_t plc_compile_block_decls(pl_compiler_t *compiler, text_t *block_name, galist_t *decls)
{
    word_t word;
    uint32 flag;
    lex_t *lex = compiler->stmt->session->lex;
    if ((compiler->last_line != NULL) && (compiler->last_line->type == LINE_LABEL)) {
        // It means the name of loop statement.
        *block_name = ((pl_line_label_t *)compiler->last_line)->name;
    }

    compiler->decls = decls;
    flag = lex->flags;
    lex->flags = LEX_SINGLE_WORD;
    CT_RETURN_IFERR(lex_expected_fetch(lex, &word));

    // LOOK AHEAD TO DISTINCED CURSOR/TYPE
    while (CT_TRUE) {
        switch (word.id) {
            case KEY_WORD_TYPE:
                // type definition clause
                CT_RETURN_IFERR(plc_compile_type_def(compiler, decls, &word));
                break;
            case KEY_WORD_PRAGMA:
                CT_RETURN_IFERR(plc_compile_pragma(compiler, decls, &word));
                break;
            case KEY_WORD_CURSOR:
                CT_RETURN_IFERR(plc_compile_cursor_def(compiler, decls, &word));
                break;

            case KEY_WORD_BEGIN:
                lex->flags = flag;
                compiler->line_loc = word.loc;
                return CT_SUCCESS;

            case KEY_WORD_FUNCTION:
            case KEY_WORD_PROCEDURE:
                CT_SRC_THROW_ERROR(lex->loc, ERR_PL_UNSUPPORT);
                return CT_ERROR;
            default:
                CT_RETURN_IFERR(plc_compile_decl(compiler, decls, &word));
                break;
        }
        CT_RETURN_IFERR(plc_check_auton_output_valid(compiler, decls));
        lex->flags = LEX_SINGLE_WORD;
        CT_RETURN_IFERR(lex_expected_fetch(lex, &word));
    }
}

status_t plc_compile_block(pl_compiler_t *compiler, galist_t *decls, var_udo_t *obj, word_t *leader)
{
    word_t word;
    key_wid_t wid = leader->id;
    text_t block_name = CM_NULL_TEXT;
    lex_t *lex = compiler->stmt->session->lex;

    CT_RETURN_IFERR(plc_stack_safe(compiler));
    if (IS_PL_LABEL(leader)) {
        CT_RETURN_IFERR(lex_fetch_pl_label(lex, &word));
        CT_RETURN_IFERR(plc_label_name_verify(compiler, &word));
        CT_RETURN_IFERR(plc_compile_label(compiler, &word, &block_name));
        CT_RETURN_IFERR(lex_expected_fetch(lex, &word));
        wid = word.id;
    }

    if (wid == KEY_WORD_DECLARE || wid == KEY_WORD_AS || wid == KEY_WORD_IS) { //  anonymous block
        if (plc_compile_block_decls(compiler, &block_name, decls)) {
            g_tls_error.is_full = CT_TRUE; // do not continue compiling
            return CT_ERROR;
        }
        CT_RETURN_IFERR(plc_compile_block_body(compiler, &block_name, obj, decls));
        // clear decls when pop block
        compiler->decls = NULL;
        compiler->type_decls = NULL;
    } else if (wid == KEY_WORD_BEGIN) {
        // BEGIN without declare vars or excpts
        compiler->line_loc = leader->loc;
        CT_RETURN_IFERR(plc_compile_block_body(compiler, &block_name, obj, decls));
    } else {
        CT_SRC_THROW_ERROR(compiler->line_loc, ERR_PL_SYNTAX_ERROR_FMT,
            "block statement should start with declare or begin or label");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t plc_alloc_line(pl_compiler_t *compiler, uint32 size, pl_line_type_t type, pl_line_ctrl_t **line)
{
    CT_RETURN_IFERR(pl_alloc_mem(compiler->entity, size, (void **)line));

    (*line)->type = type;
    (*line)->loc = compiler->line_loc;
    if (compiler->last_line != NULL) {
        compiler->last_line->next = *line;
    }

    compiler->last_line = *line;
    return CT_SUCCESS;
}

status_t plc_verify_into_record(galist_t *rs_columns, plv_record_t *record, source_location_t loc)
{
    uint32 col_id;
    rs_column_t *col = NULL;
    plv_record_attr_t *attr = NULL;

    if (rs_columns->count != record->count) {
        CT_SRC_THROW_ERROR(loc, ERR_RESULT_NOT_MATCH);
        return CT_ERROR;
    }

    for (col_id = 0; col_id < rs_columns->count; col_id++) {
        col = cm_galist_get(rs_columns, col_id);
        attr = udt_seek_field_by_id(record, col_id);
        CT_RETURN_IFERR(plc_verify_record_field_assign(attr, col, loc));
    }
    return CT_SUCCESS;
}

status_t plc_verify_rscolumn_datatype(galist_t *rs_columns, source_location_t loc)
{
    uint32 col_id;
    rs_column_t *col = NULL;
    for (col_id = 0; col_id < rs_columns->count; col_id++) {
        col = cm_galist_get(rs_columns, col_id);
        if (CM_IS_COMPOUND_DATATYPE(col->datatype)) {
            CT_SRC_THROW_ERROR_EX(loc, ERR_UNSUPPORT_DATATYPE, get_datatype_name_str(col->datatype));
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t plc_verify_into_clause(sql_context_t *context, pl_into_t *into, source_location_t loc)
{
    if (context->rs_columns == NULL) {
        return CT_SUCCESS;
    }
    uint32 col_cnt = context->rs_columns->count;
    expr_node_t *node = NULL;
    plv_record_t *record = NULL;
    var_address_pair_t *pair = NULL;
    CT_RETURN_IFERR(plc_verify_rscolumn_datatype(context->rs_columns, loc));
    switch (into->into_type) {
        case INTO_AS_VALUE:
            if (col_cnt != into->output->count) {
                CT_SRC_THROW_ERROR(loc, ERR_RESULT_NOT_MATCH);
                return CT_ERROR;
            }
            break;

        case INTO_AS_REC:
            node = (expr_node_t *)cm_galist_get(into->output, 0);
            record = (plv_record_t *)node->udt_type;
            CT_RETURN_IFERR(plc_verify_into_record(context->rs_columns, record, loc));
            break;

        case INTO_AS_COLL:
            if (col_cnt != into->output->count) {
                CT_SRC_THROW_ERROR(loc, ERR_RESULT_NOT_MATCH);
                return CT_ERROR;
            }
            break;

        case INTO_AS_COLL_REC:
            node = (expr_node_t *)cm_galist_get(into->output, 0);
            if (node == NULL || node->type != EXPR_NODE_V_ADDR || !sql_pair_type_is_plvar(node)) {
                CT_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "unexpected pl-variant occurs");
                return CT_ERROR;
            }
            pair = sql_get_last_addr_pair(node);
            if (pair == NULL) {
                CT_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "pair is null");
                return CT_ERROR;
            }
            record = UDT_GET_TYPE_DEF_RECORD(pair->stack->decl->collection->elmt_type);
            CT_RETURN_IFERR(plc_verify_into_record(context->rs_columns, record, loc));
            break;

        default:
            CT_SRC_THROW_ERROR(loc, ERR_PL_WRONG_TYPE_VALUE, "INTO type", into->into_type);
            return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t plc_push(pl_compiler_t *compiler, pl_line_ctrl_t *line, const text_t *block_name)
{
    if (compiler->stack.depth >= PL_MAX_BLOCK_DEPTH) {
        CT_SRC_THROW_ERROR(line->loc, ERR_PL_BLOCK_TOO_DEEP_FMT, PL_MAX_BLOCK_DEPTH);
        return CT_ERROR;
    }

    plc_push_block(&compiler->stack, line, block_name);
    return CT_SUCCESS;
}

status_t plc_verify_label(pl_compiler_t *compiler)
{
    pl_line_ctrl_t *line = (pl_line_ctrl_t *)compiler->body;
    pl_line_goto_t *goto_line = NULL;
    uint32 block_depth = 0;
    uint32 block_count[PL_MAX_BLOCK_DEPTH] = { 0 };
    sql_stmt_t *plc_stmt = compiler->stmt;
    pl_line_ctl_block_t *ctl_block_lines = NULL;
    pl_line_ctl_block_t *curr_ctl_block_line = NULL;
    pl_ctl_block_id_t goto_ctl_block_id;
    pl_ctl_block_id_t label_ctl_block_id;
    errno_t rc_memzero;
    status_t rc_verifylabel = CT_SUCCESS;
    pl_line_ctrl_t *before_line = NULL;
    pl_line_label_t *label_line = NULL;
    bool32 flag = CT_FALSE;
    CTSQL_SAVE_STACK(plc_stmt);
    CT_RETURN_IFERR(sql_push(plc_stmt, sizeof(pl_line_ctl_block_t), (void **)&ctl_block_lines));
    rc_memzero = memset_s(ctl_block_lines, sizeof(pl_line_ctl_block_t), 0, sizeof(pl_line_ctl_block_t));
    if (rc_memzero != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, rc_memzero);
        CTSQL_RESTORE_STACK(plc_stmt);
        return CT_ERROR;
    }

    curr_ctl_block_line = ctl_block_lines;
    while (line != NULL) {
        if (plc_ctl_block_count_change(line->type, &block_depth, block_count, PL_MAX_BLOCK_DEPTH) != CT_SUCCESS) {
            CT_SRC_THROW_ERROR(line->loc, ERR_PL_BLOCK_TOO_DEEP_FMT, PL_MAX_BLOCK_DEPTH);
            CTSQL_RESTORE_STACK(plc_stmt);
            return CT_ERROR;
        }

        if ((line->type == LINE_LABEL) || (line->type == LINE_GOTO)) {
            if (plc_verify_label_next(plc_stmt, &curr_ctl_block_line) != CT_SUCCESS) {
                CTSQL_RESTORE_STACK(plc_stmt);
                return CT_ERROR;
            }
            curr_ctl_block_line->line = line;
            plc_copy_ctl_block_id(&curr_ctl_block_line->ctl_block_id, block_depth, block_count, PL_MAX_BLOCK_DEPTH);
        }
        before_line = line;
        line = line->next;
        if (before_line->type == LINE_LABEL && IS_END_LINE_TYPE(line->type)) {
            label_line = (pl_line_label_t *)before_line;
            CT_SRC_THROW_ERROR_EX(before_line->loc, ERR_PL_SYNTAX_ERROR_FMT, "%s is an invalid label",
                T2S(&label_line->name));
            CTSQL_RESTORE_STACK(plc_stmt);
            return CT_ERROR;
        }
    }

    curr_ctl_block_line = ctl_block_lines;
    while ((curr_ctl_block_line != NULL) && (curr_ctl_block_line->line != NULL)) {
        line = curr_ctl_block_line->line;
        if (line->type == LINE_GOTO) {
            // compile labels of goto to line;
            goto_line = (pl_line_goto_t *)line;
            plc_find_label(compiler, (text_t *)&goto_line->label, &goto_line->next, &flag);
            if (!flag) {
                CT_SRC_THROW_ERROR_EX(line->loc, ERR_PL_SYNTAX_ERROR_FMT, "%s is an invalid label",
                    T2S(&goto_line->label));
                rc_verifylabel = CT_ERROR;
                break;
            }

            goto_ctl_block_id = curr_ctl_block_line->ctl_block_id;
            if (plc_find_ctl_block_id(ctl_block_lines, goto_line->next, &label_ctl_block_id) != CT_SUCCESS) {
                CT_SRC_THROW_ERROR_EX(line->loc, ERR_PL_SYNTAX_ERROR_FMT, "%s label can not find label line",
                    T2S(&goto_line->label));
                rc_verifylabel = CT_ERROR;
                break;
            }

            if (!plc_ctl_block_equal(&goto_ctl_block_id, &label_ctl_block_id)) {
                CT_SRC_THROW_ERROR_EX(line->loc, ERR_PL_SYNTAX_ERROR_FMT,
                    "%s is an invalid label(not in equal ctl_block)", T2S(&goto_line->label));
                rc_verifylabel = CT_ERROR;
                break;
            }
            if (goto_ctl_block_id.depth < label_ctl_block_id.depth) {
                CT_SRC_THROW_ERROR_EX(line->loc, ERR_PL_SYNTAX_ERROR_FMT,
                    "%s is an invalid label(ctl_block depth more than goto)", T2S(&goto_line->label));
                rc_verifylabel = CT_ERROR;
                break;
            }
        }

        curr_ctl_block_line = curr_ctl_block_line->next;
    }

    CTSQL_RESTORE_STACK(plc_stmt);
    return rc_verifylabel;
}

bool32 plc_expected_end_value_equal(pl_compiler_t *compiler, var_udo_t *obj, word_t *word)
{
    if (word->ex_count > 1) {
        CT_SRC_THROW_ERROR(compiler->line_loc, ERR_PL_UNSUPPORT);
        return CT_FALSE;
    } else if (word->ex_count == 1) {
        return cm_text_equal_ins(&obj->user, &word->text.value) &&
            PLC_ENDLN_TEXT_EQUAL(&obj->name, &(word->ex_words[0].text.value), word->type);
    } else {
        return PLC_ENDLN_TEXT_EQUAL(&obj->name, &word->text.value, word->type);
    }
}

status_t plc_init_galist(pl_compiler_t *compiler, galist_t **decls)
{
    CT_RETURN_IFERR(pl_alloc_mem(compiler->entity, sizeof(galist_t), (void **)decls));
    cm_galist_init(*decls, compiler->entity, pl_alloc_mem);
    return CT_SUCCESS;
}
