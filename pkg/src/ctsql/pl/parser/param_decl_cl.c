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
 * param_decl_cl.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/parser/param_decl_cl.c
 *
 * -------------------------------------------------------------------------
 */
#include "param_decl_cl.h"
#include "pl_dc_util.h"
#include "pl_udt.h"
#include "pl_memory.h"

void plc_find_param_decl(pl_compiler_t *compiler, uint32 p_nid, plv_decl_t **decl)
{
    uint32 i;
    pl_line_begin_t *begin_ln = (pl_line_begin_t *)compiler->stack.items[0].entry;
    plv_decl_t *item = NULL;

    for (i = 0; i < begin_ln->decls->count; i++) {
        item = cm_galist_get(begin_ln->decls, i);
        if (item->pnid == p_nid) {
            break;
        }
    }

    *decl = item;
}

status_t plc_add_param_decl(pl_compiler_t *compiler, uint32 p_nid, uint32 param_id, plv_decl_t **decl)
{
    pl_line_begin_t *begin_ln = (pl_line_begin_t *)compiler->stack.items[0].entry;
    pl_entity_t *pl_entity = compiler->entity;
    if (begin_ln->decls == NULL) {
        CT_RETURN_IFERR(pl_alloc_mem(pl_entity, sizeof(galist_t), (void **)&begin_ln->decls));
        cm_galist_init(begin_ln->decls, pl_entity, pl_alloc_mem);
    }
    if (cm_galist_new(begin_ln->decls, sizeof(plv_decl_t), (void **)decl) != CT_SUCCESS) {
        return CT_ERROR;
    }

    (*decl)->type = PLV_PARAM;
    (*decl)->pnid = p_nid;
    (*decl)->param.param_id = param_id;
    (*decl)->param.type.datatype = CT_TYPE_UNKNOWN;
    (*decl)->vid.block = 0;
    (*decl)->vid.id = begin_ln->decls->count - 1;
    return CT_SUCCESS;
}

status_t plc_convert_sql_param(sql_stmt_t *stmt, text_t *sql, bool32 is_repeated, uint32 p_nid, uint32 param_id)
{
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;
    pl_line_ctrl_t *line = CURR_BLOCK_BASE(compiler);
    pl_line_begin_t *begin_ln = (pl_line_begin_t *)line;
    plv_decl_t *decl = NULL;
    char buf[INPUT_NAME_BUFFER_SIZE];
    text_t name = {
        .str = NULL,
        .len = 0
    };

    if ((line == NULL) || (line->type != LINE_BEGIN)) {
        CT_THROW_ERROR(ERR_PLSQL_ILLEGAL_LINE_FMT, "begin line must be required");
        return CT_ERROR;
    }

    if (begin_ln->decls == NULL) {
        CT_SRC_THROW_ERROR(line->loc, ERR_ACCESS_INTO_NULL);
        return CT_ERROR;
    }

    if (is_repeated) {
        plc_find_param_decl(compiler, p_nid, &decl);
    } else {
        CT_RETURN_IFERR(plc_add_param_decl(compiler, p_nid, param_id, &decl));
    }
    CT_RETURN_IFERR(udt_build_list_address_single(compiler->stmt, compiler->current_input, decl, UDT_STACK_ADDR));
    CT_RETURN_IFERR(plc_make_input_name(compiler->current_input, buf, INPUT_NAME_BUFFER_SIZE, &name));
    cm_concat_text(sql, compiler->convert_buf_size, &name);
    return CT_SUCCESS;
}

status_t plc_compile_sql_param(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    uint32 p_nid, param_id;
    bool32 is_repeated;
    sql_stmt_t *stmt = compiler->stmt;
    lex_t *lex = compiler->stmt->session->lex;

    if (stmt->context->type != CTSQL_TYPE_ANONYMOUS_BLOCK) {
        CT_SRC_THROW_ERROR(lex->loc, ERR_PL_PARAM_USE);
        return CT_ERROR;
    }
    param_id = stmt->context->params->count;
    CT_RETURN_IFERR(sql_add_param_mark(stmt, word, &is_repeated, &p_nid));
    return plc_convert_sql_param(stmt, sql, is_repeated, p_nid, param_id);
}

// convert expr_node to pair->stack
status_t plc_convert_param_node(sql_stmt_t *stmt, expr_node_t *node, bool32 is_repeated, uint32 p_nid)
{
    plv_decl_t *decl = NULL;
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;
    lex_t *lex = compiler->stmt->session->lex;

    if (is_repeated) {
        plc_find_param_decl(compiler, p_nid, &decl);
    } else {
        // if begin line is null,it means it ocurrs in declare block, it's forbidden to use param in plv's default value
        if ((pl_line_begin_t *)compiler->stack.items[0].entry == NULL) {
            CT_SRC_THROW_ERROR(lex->loc, ERR_PL_PARAM_USE);
            return CT_ERROR;
        }
        CT_RETURN_IFERR(plc_add_param_decl(compiler, p_nid, (uint32)node->value.v_int, &decl));
    }

    node->typmod = decl->variant.type;
    node->value.type = CT_TYPE_INTEGER;
    node->value.is_null = CT_FALSE;
    return plc_build_var_address(stmt, decl, node, UDT_STACK_ADDR);
}

status_t plc_find_param_as_expr_left(pl_compiler_t *compiler, word_t *word, plv_decl_t **decl)
{
    uint32 p_nid;
    uint32 param_id;
    bool32 is_repeated;

    if (compiler->stmt->context->type != CTSQL_TYPE_ANONYMOUS_BLOCK) {
        CT_SRC_THROW_ERROR(word->loc, ERR_PL_PARAM_USE);
        return CT_ERROR;
    }
    CT_RETURN_IFERR(sql_add_param_mark(compiler->stmt, word, &is_repeated, &p_nid));
    if (is_repeated) {
        plc_find_param_decl(compiler, p_nid, decl);
    } else {
        param_id = compiler->stmt->context->params->count - 1;
        CT_RETURN_IFERR(plc_add_param_decl(compiler, p_nid, param_id, decl));
    }

    return CT_SUCCESS;
}
