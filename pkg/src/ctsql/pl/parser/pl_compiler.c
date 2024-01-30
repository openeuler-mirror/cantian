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
 * pl_compiler.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/parser/pl_compiler.c
 *
 * -------------------------------------------------------------------------
 */
#include "pl_compiler.h"
#include "srv_instance.h"
#include "pl_ddl_parser.h"
#include "ctsql_dependency.h"
#include "pl_memory.h"
#include "pl_common.h"
#include "base_compiler.h"
#include "typedef_cl.h"
#include "decl_cl.h"
#include "cursor_cl.h"
#include "ast_cl.h"
#include "call_cl.h"
#include "trigger_decl_cl.h"


static status_t plc_compile_match_drct(pl_compiler_t *compiler, galist_t *decls, word_t *word, plv_decl_t *decl)
{
    CT_RETURN_IFERR(plc_compile_variant_def(compiler, word, decl, CT_TRUE, decls, CT_TRUE));
    return plc_compile_default_def(compiler, word, decl, CT_TRUE);
}

static status_t plc_compile_end(pl_compiler_t *compiler)
{
    word_t word;
    lex_t *lex = compiler->stmt->session->lex;
    lex_trim(lex->curr_text);
    if (lex->curr_text->len == 0) {
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(lex_fetch(lex, &word));
    if (word.type != WORD_TYPE_EOF) {
        if (!(word.text.len == 1 && word.text.str[0] == '/')) {
            CT_SRC_THROW_ERROR(lex->loc, ERR_PL_EXPECTED_FAIL_FMT, "'/'", W2S(&word));
            return CT_ERROR;
        }
        lex_trim(lex->curr_text); // There should be only line break, TAB and spaces.
        if (lex->curr_text->value.len != 0) {
            CT_SRC_THROW_ERROR(lex->loc, ERR_PL_EXPECTED_FAIL_FMT, "EOF", "more text");
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}


static status_t plc_compile_args_core(pl_compiler_t *compiler, galist_t *params, word_t *word, lex_t *lex,
    uint32 *outparam_count)
{
    bool32 result = CT_FALSE;
    uint32 dir;
    plv_decl_t *decl = NULL;
    uint32 match = CT_INVALID_ID32;
    for (;;) {
        CT_RETURN_IFERR(cm_galist_new(params, sizeof(plv_decl_t), (void **)&decl));
        decl->arg_type = PLV_NORMAL_ARG;
        decl->vid.block = (int16)compiler->stack.depth;
        decl->vid.id = params->count - 1;
        CT_RETURN_IFERR(lex_expected_fetch_variant(lex, word));
        plc_check_duplicate(params, (text_t *)&word->text, IS_DQ_STRING(word->type), &result);
        if (result) {
            CT_SRC_THROW_ERROR(word->loc, ERR_DUPLICATE_NAME, "argument", T2S((text_t *)&word->text));
            return CT_ERROR;
        }
        decl->loc = word->loc;
        CT_RETURN_IFERR(pl_copy_object_name_ci(compiler->entity, word->type, (text_t *)&word->text, &decl->name));
        CT_RETURN_IFERR(lex_try_fetch_1of2(lex, "IN", "OUT", &match));
        dir = ((match == CT_INVALID_ID32) ? PLV_DIR_IN : (match + 1));
        if (match == 0) {
            CT_RETURN_IFERR(lex_try_fetch(lex, "OUT", &match));
            dir = match ? PLV_DIR_INOUT : dir;
        }
        decl->drct = dir;
        CT_RETURN_IFERR(lex_try_fetch(lex, "SYS_REFCURSOR", &result));
        if (result) {
            decl->type = PLV_CUR;
            decl->cursor.sql.value = CM_NULL_TEXT;
            CT_RETURN_IFERR(plc_compile_syscursor_def(compiler, word, decl));
            CT_RETURN_IFERR(lex_fetch(lex, word));
        } else {
            CT_RETURN_IFERR(plc_compile_match_drct(compiler, params, word, decl)); // OUT or INOUT matched
        }
        if (decl->drct == PLV_DIR_OUT || decl->drct == PLV_DIR_INOUT) {
            (*outparam_count)++;
        }

        CT_BREAK_IF_TRUE(word->type == WORD_TYPE_EOF);
        if (!IS_SPEC_CHAR(word, ',')) {
            CT_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, "','", W2S(word));
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

/*
 * @brief    compile arguments
 */
static status_t plc_compile_args(pl_compiler_t *compiler, function_t *func, word_t *word)
{
    galist_t *params = func->desc.params;
    bool32 result = CT_FALSE;
    uint32 outparam_count = 0;
    lex_t *lex = compiler->stmt->session->lex;
    lex->flags = LEX_SINGLE_WORD;

    CT_RETURN_IFERR(lex_try_fetch_bracket(lex, word, &result));

    if (!result || word->text.len == 0) {
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(lex_push(lex, &word->text));
    if (plc_compile_args_core(compiler, params, word, lex, &outparam_count) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    func->desc.outparam_count = outparam_count;

    lex_pop(lex);
    return CT_SUCCESS;
}

plv_decl_t *plc_get_last_addr_decl(sql_stmt_t *stmt, var_address_pair_t *addr_pair)
{
    plv_collection_t *coll = NULL;
    plv_record_t *rec = NULL;
    plv_record_attr_t *rec_attr = NULL;
    plv_object_t *obj = NULL;
    plv_object_attr_t *obj_attr = NULL;
    if (addr_pair == NULL) {
        return NULL;
    }

    switch (addr_pair->type) {
        case UDT_COLL_ELEMT_ADDR:
            coll = (plv_collection_t *)addr_pair->coll_elemt->parent;
            switch (coll->attr_type) {
                case UDT_SCALAR:
                    return NULL;
                default:
                    return coll->elmt_type;
            }
            break;
        case UDT_REC_FIELD_ADDR:
            rec = (plv_record_t *)addr_pair->rec_field->parent;
            rec_attr = udt_seek_field_by_id(rec, addr_pair->rec_field->id);
            switch (rec_attr->type) {
                case UDT_SCALAR:
                    return NULL;
                default:
                    return rec_attr->udt_field;
            }
            break;
        case UDT_OBJ_FIELD_ADDR:
            obj = (plv_object_t *)addr_pair->obj_field->parent;
            obj_attr = udt_seek_obj_field_byid(obj, addr_pair->obj_field->id);
            switch (obj_attr->type) {
                case UDT_SCALAR:
                    return NULL;
                default:
                    return obj_attr->udt_field;
            }
            break;
        case UDT_STACK_ADDR:
            return addr_pair->stack->decl;
        case UDT_ARRAY_ADDR:
        default:
            return NULL;
    }
}

void plc_diag_ctx_type(sql_context_t *context, uint32 type)
{
    switch (type) {
        case PL_TRIGGER:
            context->type = CTSQL_TYPE_CREATE_TRIG;
            break;

        case PL_FUNCTION:
            context->type = CTSQL_TYPE_CREATE_FUNC;
            break;

        case PL_ANONYMOUS_BLOCK:
            context->type = CTSQL_TYPE_ANONYMOUS_BLOCK;
            break;

        case PL_PROCEDURE:
            context->type = CTSQL_TYPE_CREATE_PROC;
            break;

        case PL_PACKAGE_SPEC:
            context->type = CTSQL_TYPE_CREATE_PACK_SPEC;
            break;

        case PL_PACKAGE_BODY:
            context->type = CTSQL_TYPE_CREATE_PACK_BODY;
            break;

        case PL_TYPE_SPEC:
            context->type = CTSQL_TYPE_CREATE_TYPE_SPEC;
            break;

        case PL_TYPE_BODY:
            context->type = CTSQL_TYPE_CREATE_TYPE_BODY;
            break;

        default:
            break;
    }
}

#define PLC_REFORM_SQL_RESERVERD_ALIGN 1024

status_t plc_prepare(sql_stmt_t *stmt, pl_compiler_t *compile, plc_desc_t *desc)
{
    pl_entity_t *entity = (pl_entity_t *)desc->entity;
    entity->pl_type = desc->type;
    stmt->pl_compiler = compile;
    MEMS_RETURN_IFERR(memset_s(compile, sizeof(pl_compiler_t), 0, sizeof(pl_compiler_t)));
    compile->pages = desc->source_pages;
    compile->type = desc->type;
    compile->root_type = desc->type;
    compile->stmt = stmt;

    compile->large_page_id = CT_INVALID_ID32;
    compile->type_decls = NULL;
    compile->proc_oid = desc->proc_oid;
    compile->entity = desc->entity;
    compile->push_stack = CT_FALSE;
    compile->proc_id = 1;
    compile->step = PL_COMPILE_INIT;
    compile->proc = NULL;

    lex_t *lex = compile->stmt->session->lex;

    entity->context = stmt->context;
    plc_diag_ctx_type(entity->context, desc->type);

    // init direct ref_object of context here
    if (entity->context->ref_objects == NULL) {
        CT_RETURN_IFERR(sql_alloc_mem(entity->context, sizeof(galist_t), (void **)&entity->context->ref_objects));
        cm_galist_init(entity->context->ref_objects, entity->context, sql_alloc_mem);
    }

    uint32 len = MAX(lex->text.len / 10, PLC_REFORM_SQL_RESERVERD_ALIGN);
    compile->convert_buf_size = len + lex->text.len;

    return buddy_alloc_mem(buddy_mem_pool, compile->convert_buf_size, (void **)&compile->convert_buf);
}

static status_t plc_compile_anonymous_block(pl_compiler_t *compiler, word_t *leader)
{
    galist_t *decls = NULL;
    galist_t *type_decls = NULL;
    pl_entity_t *entity = (pl_entity_t *)compiler->entity;
    anonymous_t *anony = entity->anonymous;

    CT_RETURN_IFERR(plc_init_galist(compiler, &decls));
    CT_RETURN_IFERR(plc_init_galist(compiler, &type_decls));

    compiler->decls = decls;
    compiler->type_decls = type_decls;
    compiler->params = NULL;

    CT_RETURN_IFERR(plc_compile_block(compiler, decls, NULL, leader));
    anony->body = compiler->body;

    CT_RETURN_IFERR(plc_verify_label(compiler));

    return plc_compile_end(compiler);
}

static status_t plc_decl_insert_params(pl_compiler_t *compiler, galist_t *decls, galist_t *params)
{
    plv_decl_t *decl = NULL;
    for (uint32 i = 0; i < params->count; i++) {
        decl = cm_galist_get(params, i);
        CT_RETURN_IFERR(cm_galist_insert(decls, decl));
    }
    return CT_SUCCESS;
}


status_t plc_compile_proc_desc(pl_compiler_t *compiler, word_t *word, text_t *name, void *proc_in)
{
    procedure_t *proc = (procedure_t *)proc_in;
    bool32 result = CT_FALSE;
    lex_t *lex = compiler->stmt->session->lex;
    // init procedure
    CT_RETURN_IFERR(plc_init_galist(compiler, &proc->desc.params));
    CT_RETURN_IFERR(cm_text2str(name, proc->desc.name, CT_NAME_BUFFER_SIZE));
    if (!dc_get_user_id(&compiler->stmt->session->knl_session, &compiler->obj->user, &proc->desc.uid)) {
        return CT_ERROR;
    }

    proc->desc.lang_type = LANG_PLSQL;
    proc->desc.pl_type = PL_PROCEDURE;
    proc->desc.proc_id = compiler->proc_id;
    proc->desc.is_function = CT_FALSE;
    proc->desc.loc = word->loc;

    // compile argument
    CT_RETURN_IFERR(plc_compile_args(compiler, proc, word));
    proc->desc.arg_count = proc->desc.params->count;
    CT_RETURN_IFERR(lex_try_fetch(lex, "AUTHID", &result));
    if (result) {
        CT_RETURN_IFERR(lex_expected_fetch_word(lex, "CURRENT_USER"));
    }

    return CT_SUCCESS;
}

static status_t plc_compile_pack_proc_spec(pl_compiler_t *compiler, word_t *word, text_t *name, procedure_t **proc_out)
{
    galist_t *decls = NULL;
    galist_t *type_decls = NULL;
    procedure_t *proc = NULL;

    CT_RETURN_IFERR(pl_alloc_mem(compiler->entity, sizeof(procedure_t), (void **)&proc));
    *proc_out = proc;
    CT_RETURN_IFERR(plc_init_galist(compiler, &decls));
    CT_RETURN_IFERR(plc_init_galist(compiler, &type_decls));
    compiler->type_decls = type_decls;
    compiler->decls = decls;
    CT_RETURN_IFERR(plc_compile_proc_desc(compiler, word, name, proc));
    compiler->body = NULL;
    compiler->last_line = NULL;

    return CT_SUCCESS;
}


static status_t plc_compile_procedure_core(pl_compiler_t *compiler, word_t *word, text_t *name, procedure_t **proc_out)
{
    uint32 id;
    bool32 result = CT_FALSE;
    procedure_t *proc = NULL;
    lex_t *lex = compiler->stmt->session->lex;
    galist_t *decls = NULL;
    galist_t *type_decls = NULL;
    status_t status;

    CT_RETURN_IFERR(pl_alloc_mem(compiler->entity, sizeof(procedure_t), (void **)&proc));
    *proc_out = proc;
    CT_RETURN_IFERR(plc_init_galist(compiler, &decls));
    CT_RETURN_IFERR(plc_init_galist(compiler, &type_decls));
    compiler->type_decls = type_decls;
    compiler->decls = decls;
    CT_RETURN_IFERR(plc_compile_proc_desc(compiler, word, name, proc));
    compiler->params = proc->desc.params;
    CT_RETURN_IFERR(plc_decl_insert_params(compiler, decls, proc->desc.params));

    compiler->type = PL_PROCEDURE;
    CT_RETURN_IFERR(lex_expected_fetch_1of2(lex, "IS", "AS", &id));

    word->id = (id == 0) ? KEY_WORD_IS : KEY_WORD_AS;
    CT_RETURN_IFERR(lex_try_fetch(lex, "language", &result));
    if (result) {
        return plc_compile_language(compiler, proc);
    }
    if (compiler->root_type == PL_PROCEDURE) {
        compiler->step = PL_COMPILE_AFTER_DECL;
        compiler->proc = proc;
    }

    status = plc_compile_block(compiler, decls, compiler->obj, word);
    proc->body = (void *)compiler->body;
    CT_RETURN_IFERR(status);
    CT_RETURN_IFERR(plc_verify_label(compiler));
    compiler->body = NULL;
    compiler->last_line = NULL;

    return CT_SUCCESS;
}


static status_t plc_compile_procedure(pl_compiler_t *compiler, word_t *word)
{
    procedure_t *proc = NULL;
    pl_entity_t *entity = compiler->entity;

    status_t status = plc_compile_procedure_core(compiler, word, &compiler->obj->name, &proc);
    entity->procedure = proc;
    CT_RETURN_IFERR(status);
    return plc_compile_end(compiler);
}


status_t pl_compile_func_desc(pl_compiler_t *compiler, word_t *word, text_t *name, void *func_in)
{
    function_t *func = (function_t *)func_in;
    plv_decl_t *ret = NULL;
    uint32 matched_id = CT_INVALID_ID32;
    lex_t *lex = compiler->stmt->session->lex;

    CT_RETURN_IFERR(plc_init_galist(compiler, &func->desc.params));
    if (!dc_get_user_id(&compiler->stmt->session->knl_session, &compiler->obj->user, &func->desc.uid)) {
        CT_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&compiler->obj->user));
        return CT_ERROR;
    }
    CT_RETURN_IFERR(cm_text2str(name, func->desc.name, CT_NAME_BUFFER_SIZE));
    func->desc.lang_type = LANG_PLSQL;
    func->desc.pl_type = PL_FUNCTION;
    func->desc.proc_id = compiler->proc_id;
    func->desc.is_function = CT_TRUE;
    func->desc.loc = word->loc;

    // insert return values declaration
    CT_RETURN_IFERR(cm_galist_new(func->desc.params, sizeof(plv_decl_t), (void **)&ret));
    ret->drct = PLV_DIR_OUT;

    // compile argument
    CT_RETURN_IFERR(plc_compile_args(compiler, func, word));
    func->desc.arg_count = func->desc.params->count;
    // compile returning
    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "RETURN"));
    CT_RETURN_IFERR(lex_try_fetch_1of2(lex, "SYS_REFCURSOR", "SELF", &matched_id));

    if (matched_id == CT_INVALID_ID32) {
        CT_RETURN_IFERR(plc_compile_variant_def(compiler, word, ret, CT_TRUE, compiler->decls, CT_FALSE));
    } else if (matched_id == 0) {
        CT_RETURN_IFERR(pl_alloc_mem(compiler->entity, sizeof(plv_cursor_context_t), (void **)&ret->cursor.ctx));
        ret->type = PLV_CUR;
        ret->cursor.ctx->is_sysref = (bool8)CT_TRUE;
        ret->cursor.input = NULL;
    } else {
        CT_SRC_THROW_ERROR(compiler->line_loc, ERR_PL_UNSUPPORT);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t plc_compile_pack_func_spec(pl_compiler_t *compiler, word_t *word, text_t *name, function_t **func_out)
{
    function_t *func = NULL;
    galist_t *decls = NULL;
    galist_t *type_decls = NULL;

    CT_RETURN_IFERR(pl_alloc_mem(compiler->entity, sizeof(function_t), (void **)&func));
    *func_out = func;
    CT_RETURN_IFERR(plc_init_galist(compiler, &decls));
    CT_RETURN_IFERR(plc_init_galist(compiler, &type_decls));
    compiler->type_decls = type_decls;
    compiler->decls = decls;
    CT_RETURN_IFERR(pl_compile_func_desc(compiler, word, name, func));
    compiler->body = NULL;
    compiler->last_line = NULL;

    return CT_SUCCESS;
}


static status_t plc_compile_function_core(pl_compiler_t *compiler, word_t *word, text_t *name, function_t **func_out)
{
    function_t *func = NULL;
    uint32 id;
    bool32 is_exist = CT_FALSE;
    lex_t *lex = compiler->stmt->session->lex;
    compiler->type = PL_FUNCTION;
    galist_t *decls = NULL;
    galist_t *type_decls = NULL;
    status_t status;

    // init function
    CT_RETURN_IFERR(pl_alloc_mem(compiler->entity, sizeof(function_t), (void **)&func));
    *func_out = func;
    CT_RETURN_IFERR(plc_init_galist(compiler, &decls));
    CT_RETURN_IFERR(plc_init_galist(compiler, &type_decls));
    compiler->type_decls = type_decls;
    compiler->decls = decls;

    CT_RETURN_IFERR(pl_compile_func_desc(compiler, word, name, func));
    compiler->params = func->desc.params;

    CT_RETURN_IFERR(plc_decl_insert_params(compiler, decls, func->desc.params));

    CT_RETURN_IFERR(lex_expected_fetch_1of2(lex, "IS", "AS", &id));
    word->id = (id == 1) ? KEY_WORD_IS : KEY_WORD_AS;

    CT_RETURN_IFERR(lex_try_fetch(lex, "language", &is_exist));
    if (is_exist) {
        return plc_compile_language(compiler, func);
    }

    if (compiler->root_type == PL_FUNCTION) {
        compiler->step = PL_COMPILE_AFTER_DECL;
        compiler->proc = func;
    }
    status = plc_compile_block(compiler, decls, compiler->obj, word);
    func->body = (void *)compiler->body;
    CT_RETURN_IFERR(status);
    CT_RETURN_IFERR(plc_verify_label(compiler));
    compiler->body = NULL;
    compiler->last_line = NULL;

    return CT_SUCCESS;
}

static status_t plc_compile_function(pl_compiler_t *compiler, word_t *word)
{
    function_t *func = NULL;
    pl_entity_t *entity = compiler->entity;

    status_t status = plc_compile_function_core(compiler, word, &compiler->obj->name, &func);
    entity->function = func;
    CT_RETURN_IFERR(status);
    return plc_compile_end(compiler);
}

static status_t plc_compile_pack_end(pl_compiler_t *compiler, var_udo_t *obj, word_t *word)
{
    bool32 result = CT_FALSE;
    lex_t *lex = compiler->stmt->session->lex;
    /* make sure the block is end with obj_name or block name */
    lex->flags = LEX_WITH_OWNER;

    CT_RETURN_IFERR(lex_try_fetch_variant(lex, word, &result));
    if (result) {
        if (obj != NULL && plc_expected_end_value_equal(compiler, obj, word)) {
            result = CT_TRUE;
        } else {
            CT_SRC_THROW_ERROR(word->loc, ERR_UNDEFINED_SYMBOL_FMT, W2S_EX(word));
            return CT_ERROR;
        }
    }

    /* expected to find ';' */
    if (lex_eof(lex)) {
        result = CT_TRUE;
    } else {
        CT_RETURN_IFERR(lex_try_fetch_char(lex, ';', &result));
    }

    if (!result) {
        CT_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static bool32 plc_check_defs_duplicate(galist_t *defs, var_udo_t *obj)
{
    plv_decl_t *decl = NULL;

    for (uint32 i = 0; i < defs->count; i++) {
        decl = (plv_decl_t *)cm_galist_get(defs, i);
        if (cm_text_equal(&obj->name, &decl->name)) {
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

void plc_set_func_decl(plv_decl_t *decl, plv_type_t type, text_t *name, function_t *func)
{
    decl->type = type;
    decl->func = func;
    cm_str2text(func->desc.name, &decl->name);
}

static status_t plc_compile_package_spec_object(pl_compiler_t *compiler, word_t *word)
{
    lex_t *lex = compiler->stmt->session->lex;
    pl_entity_t *entity = compiler->entity;
    function_t *func = NULL;
    procedure_t *proc = NULL;
    plv_decl_t *decl = NULL;
    var_udo_t obj;
    uint32 type = word->id;

    CT_RETURN_IFERR(pl_parse_name(compiler->stmt, word, &obj, CT_TRUE));

    /* check this object has existed in this package or not */
    if (plc_check_defs_duplicate(entity->package_spec->defs, &obj)) {
        CT_SRC_THROW_ERROR(word->loc, ERR_OBJECT_EXISTS, "function or procedure", T2S(&obj.name));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(cm_galist_new(entity->package_spec->defs, sizeof(plv_decl_t), (pointer_t *)&decl));
    switch (type) {
        case KEY_WORD_FUNCTION:
            CT_RETURN_IFERR(plc_compile_pack_func_spec(compiler, word, &obj.name, &func));
            plc_set_func_decl(decl, PLV_FUNCTION, &obj.name, func);
            break;
        case KEY_WORD_PROCEDURE:
            CT_RETURN_IFERR(plc_compile_pack_proc_spec(compiler, word, &obj.name, &proc));
            plc_set_func_decl(decl, PLV_FUNCTION, &obj.name, proc);
            break;
        default:
            break;
    }

    return lex_expected_fetch_word(lex, ";");
}

status_t plc_compile_package_spec(pl_compiler_t *compiler, word_t *word)
{
    uint32 flags, id;
    lex_t *lex = compiler->stmt->session->lex;
    pl_entity_t *entity = compiler->entity;
    bool32 pack_end = CT_FALSE;

    CT_RETURN_IFERR(lex_expected_fetch_1of2(lex, "IS", "AS", &id));
    word->id = (id == 0) ? KEY_WORD_IS : KEY_WORD_AS;
    CT_RETURN_IFERR(pl_alloc_mem(entity, sizeof(package_spec_t), (void **)&entity->package_spec));
    CT_RETURN_IFERR(plc_init_galist(compiler, &entity->package_spec->defs));

    flags = lex->flags;
    for (;;) {
        CT_RETURN_IFERR(plc_stack_safe(compiler));

        lex->flags = LEX_SINGLE_WORD;
        CT_RETURN_IFERR(lex_expected_fetch(lex, word));

        switch (word->id) {
            case KEY_WORD_TYPE:
            case KEY_WORD_CURSOR:
                CT_SRC_THROW_ERROR(word->loc, ERR_PL_UNSUPPORT);
                return CT_ERROR;

            case KEY_WORD_FUNCTION:
            case KEY_WORD_PROCEDURE:
                if (plc_compile_package_spec_object(compiler, word) != CT_SUCCESS) {
                    pl_check_and_set_loc(word->loc);
                    return CT_ERROR;
                }
                compiler->proc_id++;
                break;

            case KEY_WORD_END:
                lex->flags = flags;
                compiler->line_loc = word->loc;
                pack_end = CT_TRUE;
                CT_RETURN_IFERR(plc_compile_pack_end(compiler, compiler->obj, word));
                break;

            default:
                CT_SRC_THROW_ERROR_EX(word->loc, ERR_PL_SYNTAX_ERROR_FMT, "can not recognize the symbol: %s",
                    W2S(word));
                return CT_ERROR;
        }

        if (pack_end) {
            break;
        }
    }

    return plc_compile_end(compiler);
}

static bool32 plc_function_equal(sql_stmt_t *stmt, function_t *func1, function_t *func2)
{
    procedure_desc_t *desc1 = &func1->desc;
    procedure_desc_t *desc2 = &func2->desc;

    if (desc1->pl_type != desc2->pl_type || desc1->arg_count != desc2->arg_count ||
        desc1->outparam_count != desc2->outparam_count) {
        CT_SRC_THROW_ERROR(desc1->loc, ERR_PKG_OBJECT_NOMATCH_FMT, desc1->name);
        return CT_FALSE;
    }

    galist_t *param1 = func1->desc.params;
    galist_t *param2 = func2->desc.params;
    plv_decl_t *decl1 = NULL;
    plv_decl_t *decl2 = NULL;

    if (param1->count != param2->count) {
        CT_SRC_THROW_ERROR(desc1->loc, ERR_PKG_OBJECT_NOMATCH_FMT, desc1->name);
        return CT_FALSE;
    }

    for (uint32 i = 0; i < param1->count; i++) {
        decl1 = (plv_decl_t *)cm_galist_get(param1, i);
        decl2 = (plv_decl_t *)cm_galist_get(param2, i);
        if (plc_decl_equal(stmt, decl1, decl2) != CT_SUCCESS) {
            CT_SRC_THROW_ERROR(decl1->loc, ERR_PKG_OBJECT_NOMATCH_FMT, desc1->name);
            return CT_FALSE;
        }
    }

    return CT_TRUE;
}

status_t plc_compile_package_set_meth_map(pl_compiler_t *compile, function_t *func)
{
    pl_entity_t *entity = compile->entity;
    pl_entity_t *spec_entity = ((pl_dc_t *)compile->spec_dc)->entity;
    galist_t *spec_defs = spec_entity->package_spec->defs;
    plv_decl_t *decl = NULL;
    function_t *spec_func = NULL;
    uint32 body_func_id = entity->package_body->defs->count - 1;

    for (uint32 i = 0; i < spec_defs->count; i++) {
        decl = (plv_decl_t *)cm_galist_get(spec_defs, i);
        if (decl->type != PLV_FUNCTION) {
            continue;
        }
        spec_func = decl->func;
        if (!cm_str_equal(func->desc.name, spec_func->desc.name)) {
            continue;
        }
        if (!plc_function_equal(compile->stmt, func, spec_func)) {
            return CT_ERROR;
        }
        entity->package_body->meth_map[i] = body_func_id;
        return CT_SUCCESS;
    }

    return CT_SUCCESS;
}

static status_t plc_parse_pack_object_name(pl_compiler_t *compiler, word_t *word, var_udo_t *obj, var_udo_t *pack_obj)
{
    CT_RETURN_IFERR(pl_parse_name(compiler->stmt, word, obj, CT_TRUE));
    obj->user = pack_obj->user;
    obj->pack = pack_obj->name;
    obj->pack_sensitive = pack_obj->name_sensitive;
    return CT_SUCCESS;
}

static status_t plc_compile_package_body_object(pl_compiler_t *compile, word_t *word)
{
    status_t status = CT_ERROR;
    pl_entity_t *entity = compile->entity;
    function_t *func = NULL;
    plv_decl_t *decl = NULL;
    var_udo_t *pack_obj = compile->obj;
    var_udo_t obj;
    uint32 type = word->id;

    CT_RETURN_IFERR(plc_parse_pack_object_name(compile, word, &obj, pack_obj));

    set_inter_plc_cnt();
    plc_set_tls_plc_error();
    do {
        /* check this object has existed in this package or not */
        if (plc_check_defs_duplicate(entity->package_body->defs, &obj)) {
            CT_SRC_THROW_ERROR(word->loc, ERR_OBJECT_EXISTS, "function or procedure", T2S(&obj.name));
            status = CT_ERROR;
            break;
        }

        compile->obj = &obj;
        CT_BREAK_IF_ERROR(cm_galist_new(entity->package_body->defs, sizeof(plv_decl_t), (pointer_t *)&decl));
        if (type == KEY_WORD_FUNCTION) {
            CT_BREAK_IF_ERROR(plc_compile_function_core(compile, word, &obj.name, &func));
        } else {
            CT_BREAK_IF_ERROR(plc_compile_procedure_core(compile, word, &obj.name, &func));
        }

        plc_set_func_decl(decl, PLV_FUNCTION, &obj.name, func);
        status = CT_SUCCESS;
    } while (0);

    if (status == CT_ERROR) {
        plc_set_compiling_errors(compile->stmt, compile->obj);
        pl_check_and_set_loc(word->loc);
    } else {
        status = plc_compile_package_set_meth_map(compile, func);
    }
    reset_inter_plc_cnt();
    compile->obj = pack_obj;
    return status;
}

status_t plc_check_meth_map(pl_compiler_t *compile)
{
    pl_entity_t *spec_entity = ((pl_dc_t *)compile->spec_dc)->entity;
    pl_entity_t *body_entity = compile->entity;
    plv_decl_t *decl = NULL;
    function_t *func = NULL;
    source_location_t loc = { 0 };

    for (uint32 i = 0; i < spec_entity->package_spec->defs->count; i++) {
        if (body_entity->package_body->meth_map[i] == CT_INVALID_ID32) {
            decl = (plv_decl_t *)cm_galist_get(spec_entity->package_spec->defs, i);
            func = decl->func;
            CT_SRC_THROW_ERROR(loc, ERR_PKG_OBJECT_NODEFINED_FMT, func->desc.name);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t plc_compile_package_body_prepare(pl_compiler_t *compiler, word_t *word)
{
    pl_dc_t *spec_dc = compiler->spec_dc;
    pl_entity_t *entity = compiler->entity;
    lex_t *lex = compiler->stmt->session->lex;
    uint32 id;

    CT_RETURN_IFERR(lex_expected_fetch_1of2(lex, "IS", "AS", &id));
    word->id = (id == 0) ? KEY_WORD_IS : KEY_WORD_AS;
    CT_RETURN_IFERR(pl_alloc_mem(entity, sizeof(package_body_t), (void **)&entity->package_body));
    CT_RETURN_IFERR(plc_init_galist(compiler, &entity->package_body->defs));
    uint32 func_num = spec_dc->entity->package_spec->defs->count;
    uint32 size = func_num * sizeof(uint32);
    CT_RETURN_IFERR(pl_alloc_mem(entity, size, (void **)&entity->package_body->meth_map));
    MEMS_RETURN_IFERR(memset_s(entity->package_body->meth_map, size, -1, size));

    return CT_SUCCESS;
}

static status_t plc_compile_package_body_core(pl_compiler_t *compiler, word_t *word)
{
    lex_t *lex = compiler->stmt->session->lex;
    uint32 flags = lex->flags;

    for (;;) {
        CT_RETURN_IFERR(plc_stack_safe(compiler));

        lex->flags = LEX_SINGLE_WORD;
        CT_RETURN_IFERR(lex_expected_fetch(lex, word));

        switch (word->id) {
            case KEY_WORD_TYPE:
            case KEY_WORD_CURSOR:
                CT_SRC_THROW_ERROR(word->loc, ERR_PL_UNSUPPORT);
                return CT_ERROR;

            case KEY_WORD_FUNCTION:
            case KEY_WORD_PROCEDURE:
                CT_RETURN_IFERR(plc_compile_package_body_object(compiler, word));
                compiler->proc_id++;
                break;

            case KEY_WORD_END:
                lex->flags = flags;
                compiler->line_loc = word->loc;
                CT_RETURN_IFERR(plc_compile_pack_end(compiler, compiler->obj, word));
                return plc_check_meth_map(compiler);

            default:
                CT_SRC_THROW_ERROR_EX(word->loc, ERR_PL_SYNTAX_ERROR_FMT, "can not recognize the symbol: %s",
                    W2S(word));
                return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}


static status_t plc_compile_package_body(pl_compiler_t *compiler, word_t *word)
{
    sql_stmt_t *stmt = compiler->stmt;
    var_udo_t *obj = compiler->obj;
    pl_dc_t spec_dc = { 0 };
    bool32 exist = CT_FALSE;
    pl_dc_assist_t assist = { 0 };
    pl_entity_t *entity = (pl_entity_t *)compiler->entity;

    pl_dc_open_prepare(&assist, stmt, &obj->user, &obj->name, PL_PACKAGE_SPEC);
    if (pl_dc_open(&assist, &spec_dc, &exist) != CT_SUCCESS) {
        cm_revert_pl_last_error();
        CT_SRC_THROW_ERROR(word->loc, ERR_OBJECT_INVALID, "package specification", T2S(&obj->user), T2S_EX(&obj->name));
        return CT_ERROR;
    }
    if (!exist) {
        CT_SRC_THROW_ERROR(word->loc, ERR_USER_OBJECT_NOT_EXISTS, "package", T2S(&obj->user), T2S_EX(&obj->name));
        return CT_ERROR;
    }
    CT_RETURN_IFERR(pl_regist_reference(&entity->ref_list, &spec_dc));
    compiler->spec_dc = &spec_dc;
    if (plc_compile_package_body_prepare(compiler, word) != CT_SUCCESS) {
        pl_dc_close(&spec_dc);
        return CT_ERROR;
    }
    if (plc_compile_package_body_core(compiler, word) != CT_SUCCESS) {
        pl_dc_close(&spec_dc);
        return CT_ERROR;
    }

    pl_dc_close(&spec_dc);
    return plc_compile_end(compiler);
}

static status_t plc_check_inherit_clauses(pl_compiler_t *compiler, bool32 *has_found, source_location_t loc)
{
    if (*has_found) {
        CT_SRC_THROW_ERROR(loc, ERR_PL_SYNTAX_ERROR_FMT, "key word of inherit is found repeatedly");
        return CT_ERROR;
    }
    *has_found = CT_TRUE;
    return CT_SUCCESS;
}

static status_t plc_compile_inherit_clauses(pl_compiler_t *compiler, word_t *word, uint16 *inherit_flag,
    bool32 *is_find_clause)
{
    bool32 found_final = CT_FALSE;
    bool32 found_instantiable = CT_FALSE;
    uint32 id;
    lex_t *lex = compiler->stmt->session->lex;

    for (;;) {
        CT_RETURN_IFERR(lex_fetch(lex, word));
        if (word->id == KEY_WORD_FINAL) {
            CT_RETURN_IFERR(plc_check_inherit_clauses(compiler, &found_final, word->loc));
            *inherit_flag |= TYPE_INHERIT_FINAL;
        } else if (word->id == KEY_WORD_INSTANTIABLE) {
            CT_RETURN_IFERR(plc_check_inherit_clauses(compiler, &found_instantiable, word->loc));
            *inherit_flag |= TYPE_INHERIT_INSTANTIABLE;
        } else if (word->id == KEY_WORD_NOT) {
            CT_RETURN_IFERR(lex_expected_fetch_1of2(lex, "FINAL", "INSTANTIABLE", &id));
            if (id == 0) {
                CT_RETURN_IFERR(plc_check_inherit_clauses(compiler, &found_final, word->loc));
                *inherit_flag &= ~TYPE_INHERIT_FINAL;
            } else {
                CT_RETURN_IFERR(plc_check_inherit_clauses(compiler, &found_instantiable, word->loc));
                *inherit_flag &= ~TYPE_INHERIT_INSTANTIABLE;
            }
        } else {
            if (*inherit_flag == TYPE_INHERIT_FINAL) {
                CT_SRC_THROW_ERROR(word->loc, ERR_PL_SYNTAX_ERROR_FMT, "can not be final and not instantiable");
                return CT_ERROR;
            }
            return CT_SUCCESS;
        }
        if (is_find_clause != NULL) {
            *is_find_clause = CT_TRUE;
        }
    }
}

static status_t plc_compile_subproc_inherit_clauses(pl_compiler_t *compiler)
{
    uint32 matched_id = CT_INVALID_ID32;
    lex_t *lex = compiler->stmt->session->lex;
    if (lex_try_fetch_1ofn(lex, &matched_id, OBJ_SUBPROC_WORD_NUM, "NOT", "OVERRIDING", "FINAL", "INSTANTIABLE",
        "MEMBER", "STATIC") != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (matched_id != CT_INVALID_ID32) {
        CT_SRC_THROW_ERROR(lex->loc, ERR_PL_UNSUPPORT);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t plc_compile_object_scalar_attr(pl_compiler_t *compiler, word_t *word, plv_object_attr_t *attr)
{
    attr->type = UDT_SCALAR;
    lex_t *lex = compiler->stmt->session->lex;
    CT_RETURN_IFERR(pl_alloc_mem(compiler->entity, sizeof(field_scalar_info_t), (void **)&attr->scalar_field));
    CT_RETURN_IFERR(sql_parse_datatype_typemode(lex, PM_NORMAL, &attr->scalar_field->type_mode, NULL, word));
    return plc_compile_attr_options(compiler, word, &attr->default_expr, &attr->nullable);
}

static status_t plc_check_object_attr_duplicate(pl_compiler_t *compiler, plv_object_t *object, word_t *word)
{
    plv_object_attr_t *attr = udt_seek_obj_field_byname(compiler->stmt, object, &word->text,
        IS_DQ_STRING(word->type) || !IS_CASE_INSENSITIVE);
    if (attr != NULL) {
        CT_SRC_THROW_ERROR(word->loc, ERR_DUPLICATE_NAME, "attribute", T2S((text_t *)&word->text));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t plc_compile_type_bracket_def(pl_compiler_t *compiler, word_t *word)
{
    pl_entity_t *entity = compiler->entity;
    type_spec_t *type_spec = entity->type_spec;
    plv_decl_t *decl = type_spec->decl;
    bool32 result = CT_FALSE;
    plv_object_attr_t *attr = NULL;
    lex_t *lex = compiler->stmt->session->lex;
    lex->flags = LEX_WITH_OWNER;
    for (;;) {
        CT_RETURN_IFERR(plc_compile_subproc_inherit_clauses(compiler));
        CT_RETURN_IFERR(lex_expected_fetch(lex, word));
        CT_RETURN_IFERR(plc_check_object_attr_duplicate(compiler, &decl->typdef.object, word));
        if (!IS_VARIANT(word)) {
            CT_SRC_THROW_ERROR_EX(word->loc, ERR_PL_SYNTAX_ERROR_FMT, "%s: invalid identifier", T2S(&word->text));
            return CT_ERROR;
        }

        attr = udt_object_alloc_attr(entity, &decl->typdef.object);
        if (attr == NULL) {
            pl_check_and_set_loc(word->loc);
            return CT_ERROR;
        }
        CT_RETURN_IFERR(pl_copy_object_name_ci(entity, word->type, (text_t *)&word->text, &attr->name));
        CT_RETURN_IFERR(lex_expected_fetch(lex, word));

        if (word->type == WORD_TYPE_DATATYPE) {
            CT_RETURN_IFERR(plc_compile_object_scalar_attr(compiler, word, attr));
            PLC_UDT_IS_ARRAY(attr->scalar_field->type_mode, word);
            CT_RETURN_IFERR(plc_check_datatype(compiler, &attr->scalar_field->type_mode, CT_FALSE));
        } else if (word->type == WORD_TYPE_VARIANT) {
            CT_RETURN_IFERR(plc_compile_global_udt_attr(compiler, word, &attr->udt_field, &attr->type));
        } else {
            CT_SRC_THROW_ERROR(word->loc, ERR_INVALID_DATA_TYPE, "type defining");
            return CT_ERROR;
        }

        CT_RETURN_IFERR(lex_try_fetch(lex, ",", &result));
        if (!result) {
            break;
        }
    }

    return lex_expected_end(lex);
}
static status_t plc_compile_type_inherit_clauses(pl_compiler_t *compiler, word_t *word)
{
    pl_entity_t *entity = compiler->entity;
    type_spec_t *type_spec = entity->type_spec;

    CT_RETURN_IFERR(plc_compile_inherit_clauses(compiler, word, &type_spec->desc.inherit_flag, NULL));
    if (word->type != WORD_TYPE_PL_TERM && word->type != WORD_TYPE_EOF) {
        CT_SRC_THROW_ERROR_EX(word->loc, ERR_PL_SYNTAX_ERROR_FMT, "%s: invalid identifier", T2S(&word->text));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t plc_expected_type_declare(pl_compiler_t *compiler, word_t *word)
{
    bool32 result = CT_FALSE;
    lex_t *lex = compiler->stmt->session->lex;
    CT_RETURN_IFERR(lex_try_fetch_bracket(lex, word, &result));
    if (!result) {
        CT_SRC_THROW_ERROR(word->loc, ERR_PL_SYNTAX_ERROR_FMT, "type need declare element");
        return CT_ERROR;
    }
    lex_trim(&word->text);
    if (word->text.len == 0) {
        CT_SRC_THROW_ERROR(word->loc, ERR_PL_SYNTAX_ERROR_FMT, "type need declare element");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t plc_object_decl_init(pl_compiler_t *compiler)
{
    pl_entity_t *entity = compiler->entity;
    type_spec_t *type_spec = entity->type_spec;
    plv_decl_t *decl = type_spec->decl;

    type_spec->desc.inherit_flag = TYPE_INHERIT_FINAL | TYPE_INHERIT_INSTANTIABLE;
    type_spec->super_type = NULL;
    decl->type = PLV_TYPE;
    decl->vid.block = CT_INVALID_ID16;
    decl->vid.id = CT_INVALID_ID16;
    decl->vid.input_id = CT_INVALID_ID32;
    decl->loc.line = 1;
    decl->loc.column = 1;
    decl->name = compiler->obj->name;
    decl->typdef.type = PLV_OBJECT;
    decl->typdef.object.root = (void *)entity;
    return CT_SUCCESS;
}

static status_t plc_compile_object_type(pl_compiler_t *compiler, word_t *word)
{
    lex_t *lex = compiler->stmt->session->lex;
    uint32 flags;

    CT_RETURN_IFERR(plc_object_decl_init(compiler));
    CT_RETURN_IFERR(plc_expected_type_declare(compiler, word));
    CT_RETURN_IFERR(lex_push(lex, &word->text));
    flags = lex->flags;
    if (plc_compile_type_bracket_def(compiler, word) != CT_SUCCESS) {
        lex->flags = flags;
        lex_pop(lex);
        return CT_ERROR;
    }
    lex->flags = flags;
    lex_pop(lex);
    return plc_compile_type_inherit_clauses(compiler, word);
}

static status_t plc_global_collection_decl_init(pl_compiler_t *compiler, collection_type_t type)
{
    pl_entity_t *entity = compiler->entity;
    type_spec_t *type_spec = entity->type_spec;
    plv_decl_t *dec = type_spec->decl;

    type_spec->super_type = NULL;
    type_spec->desc.inherit_flag = TYPE_INHERIT_FINAL | TYPE_INHERIT_INSTANTIABLE;
    dec->type = PLV_TYPE;
    dec->vid.block = CT_INVALID_ID16;
    dec->vid.id = CT_INVALID_ID16;
    dec->loc.line = 1;
    dec->loc.column = 1;
    dec->name = compiler->obj->name;
    dec->typdef.type = PLV_COLLECTION;
    dec->typdef.collection.root = (void *)entity;
    dec->typdef.collection.is_global = CT_TRUE;
    dec->typdef.collection.type = type;
    return CT_SUCCESS;
}

static status_t plc_compile_global_varray_type(pl_compiler_t *compiler, word_t *word)
{
    lex_t *lex = compiler->stmt->session->lex;
    pl_entity_t *entity = compiler->entity;
    type_spec_t *type_spec = entity->type_spec;

    CT_RETURN_IFERR(plc_global_collection_decl_init(compiler, UDT_VARRAY));
    CT_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    CT_RETURN_IFERR(cm_text2uint32(&word->text.value, &type_spec->decl->typdef.collection.limit));
    CT_RETURN_IFERR(plc_check_array_element_size(compiler, type_spec->decl));
    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "OF"));
    CT_RETURN_IFERR(plc_compile_global_type_member(compiler, type_spec->decl, word));
    return lex_expected_fetch_word(lex, ";");
}

static status_t plc_compile_global_table_type(pl_compiler_t *compiler, word_t *word)
{
    lex_t *lex = compiler->stmt->session->lex;
    pl_entity_t *entity = compiler->entity;
    type_spec_t *type_spec = entity->type_spec;

    CT_RETURN_IFERR(plc_global_collection_decl_init(compiler, UDT_NESTED_TABLE));
    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "OF"));
    CT_RETURN_IFERR(plc_compile_global_type_member(compiler, type_spec->decl, word));
    return lex_expected_fetch_word(lex, ";");
}

static status_t plc_compile_direct_type(pl_compiler_t *compiler, word_t *word)
{
    uint32 id;
    lex_t *lex = compiler->stmt->session->lex;
    CT_RETURN_IFERR(lex_expected_fetch_1of3(lex, "OBJECT", "VARRAY", "TABLE", &id));
    if (id == 0) {
        CT_RETURN_IFERR(plc_compile_object_type(compiler, word));
    } else if (id == 1) {
        CT_RETURN_IFERR(plc_compile_global_varray_type(compiler, word));
    } else {
        CT_RETURN_IFERR(plc_compile_global_table_type(compiler, word));
    }
    return CT_SUCCESS;
}

static status_t plc_inherit_type_update(pl_compiler_t *compiler, pl_dc_t *type_dc, source_location_t loc)
{
    pl_entity_t *super_entity = type_dc->entity;
    type_spec_t *super_type = super_entity->type_spec;

    if ((super_type->desc.inherit_flag & TYPE_INHERIT_FINAL) != 0) {
        CT_SRC_THROW_ERROR(loc, ERR_PL_SYNTAX_ERROR_FMT, "final type can not be inherited");
        return CT_ERROR;
    }

    pl_entity_t *curr_entity = compiler->entity;
    type_spec_t *curr_type = curr_entity->type_spec;
    curr_type->super_type = super_type;
    plv_object_t *super_object = &super_type->decl->typdef.object;
    plv_object_t *curr_object = &curr_type->decl->typdef.object;
    if (udt_object_inherit_super_attr(compiler->entity, curr_object, super_object) != CT_SUCCESS) {
        pl_check_and_set_loc(loc);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t plc_compile_inherit_type(pl_compiler_t *compiler, word_t *word)
{
    uint32 flags;
    var_udo_t obj;
    lex_t *lex = compiler->stmt->session->lex;
    pl_dc_t type_dc = { 0 };
    bool32 found = CT_FALSE;

    CT_RETURN_IFERR(plc_object_decl_init(compiler));

    flags = lex->flags;
    CT_RETURN_IFERR(pl_parse_name(compiler->stmt, word, &obj, CT_FALSE));
    lex->flags = flags;

    if (!cm_text_equal_ins(&compiler->obj->user, &obj.user)) {
        CT_SRC_THROW_ERROR(word->loc, ERR_PL_SYNTAX_ERROR_FMT, "supertype and subtype are not in same schema");
        return CT_ERROR;
    }
    if (cm_text_equal_ins(&compiler->obj->name, &obj.name)) {
        CT_SRC_THROW_ERROR(word->loc, ERR_DUPLICATE_NAME, "object", T2S(&obj.name));
        return CT_ERROR;
    }

    status_t status = pl_try_find_type_dc(compiler->stmt, &obj, &type_dc, &found);
    if (!found) {
        pl_revert_last_error(status);
        return pl_unfound_error(compiler->stmt, &obj, NULL, PL_TYPE_SPEC);
    }
    if (status == CT_ERROR) {
        pl_check_and_set_loc(word->loc);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(plc_inherit_type_update(compiler, &type_dc, word->loc));
    CT_RETURN_IFERR(plc_expected_type_declare(compiler, word));
    CT_RETURN_IFERR(lex_push(lex, &word->text));
    flags = lex->flags;
    if (plc_compile_type_bracket_def(compiler, word) != CT_SUCCESS) {
        lex->flags = flags;
        lex_pop(lex);
        return CT_ERROR;
    }
    lex->flags = flags;
    lex_pop(lex);
    return plc_compile_type_inherit_clauses(compiler, word);
}

/*
 * This function is used to compile the type specification.
 */
static status_t plc_compile_type_spec(pl_compiler_t *compiler, word_t *word)
{
    galist_t *decls = NULL;
    lex_t *lex = compiler->stmt->session->lex;
    pl_entity_t *entity = compiler->entity;
    var_udo_t *obj = compiler->obj;
    type_spec_t *type_spec = NULL;
    status_t status;
    uint32 id;

    CT_RETURN_IFERR(pl_alloc_mem(entity, sizeof(type_spec_t), (void **)&entity->type_spec));
    CT_RETURN_IFERR(plc_init_galist(compiler, &decls));
    CT_RETURN_IFERR(plc_init_galist(compiler, &compiler->type_decls));
    CT_RETURN_IFERR(pl_alloc_mem(entity, sizeof(plv_decl_t), (void **)&entity->type_spec->decl));
    CT_RETURN_IFERR(lex_expected_fetch_1of3(lex, "IS", "AS", "UNDER", &id));
    compiler->decls = decls;
    type_spec = entity->type_spec;
    CT_RETURN_IFERR(cm_text2str(&obj->name, type_spec->desc.name, CT_NAME_BUFFER_SIZE));

    if (id != 2) { // id = 2 means type is inherited
        status = plc_compile_direct_type(compiler, word);
    } else {
        status = plc_compile_inherit_type(compiler, word);
    }

    type_spec->desc.type_code = type_spec->decl->typdef.type;
    if (type_spec->decl->typdef.type == PLV_OBJECT) {
        type_spec->desc.attributes = type_spec->decl->typdef.object.count;
    }
    CT_RETURN_IFERR(status);

    return plc_compile_end(compiler);
}

static status_t plc_compile_type_body(pl_compiler_t *compiler, word_t *word)
{
    CT_SRC_THROW_ERROR(word->loc, ERR_PL_UNSUPPORT);
    return CT_ERROR;
}

static status_t plc_compile_trigger(pl_compiler_t *compiler, word_t *word)
{
    galist_t *decls = NULL;
    galist_t *type_decls = NULL;
    pl_entity_t *pl_entity = (pl_entity_t *)compiler->entity;
    trigger_t *trigger = pl_entity->trigger;
    lex_t *lex = compiler->stmt->session->lex;

    CT_RETURN_IFERR(plc_init_galist(compiler, &decls));
    CT_RETURN_IFERR(plc_init_galist(compiler, &type_decls));
    compiler->type_decls = type_decls;
    // trigger begin
    lex_fetch(lex, word);
    compiler->line_loc = word->loc;
    CT_RETURN_IFERR(plc_init_trigger_decls(compiler));
    CT_RETURN_IFERR(plc_compile_block(compiler, decls, compiler->obj, word));
    trigger->body = compiler->body;
    CT_RETURN_IFERR(plc_verify_label(compiler));

    CT_RETURN_IFERR(plc_add_modified_new_cols(compiler));

    return plc_compile_end(compiler);
}


#define PLC_SAVE_STMT(stmt)                             \
    sql_audit_t __audit__ = (stmt)->session->sql_audit; \
    CTSQL_SAVE_STACK(stmt);

#define PLC_RESTORE_STMT(stmt)                    \
    do {                                          \
        (stmt)->session->sql_audit = __audit__;   \
        (stmt)->pl_compiler = NULL;               \
        CTSQL_RESTORE_STACK(stmt);                \
    } while (0)

status_t plc_do_compile_core(pl_compiler_t *compile, word_t *word, uint32 type)
{
    switch (type) {
        case PL_ANONYMOUS_BLOCK:
            return plc_compile_anonymous_block(compile, word);

        case PL_TRIGGER:
            return plc_compile_trigger(compile, word);

        case PL_FUNCTION:
            return plc_compile_function(compile, word);

        case PL_PROCEDURE:
            return plc_compile_procedure(compile, word);

        case PL_PACKAGE_SPEC:
            return plc_compile_package_spec(compile, word);

        case PL_PACKAGE_BODY:
            return plc_compile_package_body(compile, word);

        case PL_TYPE_SPEC:
            return plc_compile_type_spec(compile, word);

        case PL_TYPE_BODY:
            return plc_compile_type_body(compile, word);

        default:
            CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "compile", "unknown PLSQL type");
            return CT_ERROR;
    }
}

void plc_set_tls_plc_error(void)
{
    if (g_tls_plc_error.plc_cnt == 1) {
        set_tls_plc_error();
    }

    if (g_tls_plc_error.plc_cnt <= CT_MAX_PLC_CNT) {
        g_tls_plc_error.start_pos[g_tls_plc_error.plc_cnt - 1] = (uint16)strlen(g_tls_error.message);
    }
}

void plc_reset_tls_plc_error(void)
{
    if (g_tls_plc_error.plc_cnt == 0) {
        g_tls_plc_error.plc_flag = CT_FALSE;
    }
}

void plc_set_compiling_errors(sql_stmt_t *stmt, var_udo_t *obj)
{
    if (g_tls_plc_error.plc_flag && g_tls_plc_error.plc_cnt == 1) {
        reset_tls_plc_error();
    }
    cm_reset_error_loc();

    if (g_tls_plc_error.plc_cnt > CT_MAX_PLC_CNT) {
        return;
    }
    if (obj != NULL) {
        CT_THROW_ERROR(ERR_PL_COMP_FMT, CC_T2S(&obj->user, &obj->pack, '.'), T2S_EX(&obj->name),
            g_tls_error.message + g_tls_plc_error.start_pos[g_tls_plc_error.plc_cnt - 1]);
    } else {
        CT_THROW_ERROR(ERR_PL_COMP_FMT, stmt->session->curr_schema, "ANONYMOUS BLOCK",
            g_tls_error.message + g_tls_plc_error.start_pos[g_tls_plc_error.plc_cnt - 1]);
    }

    g_tls_plc_error.start_pos[g_tls_plc_error.plc_cnt - 1] = 0;
}

status_t plc_do_compile(sql_stmt_t *stmt, plc_desc_t *desc, word_t *word)
{
    status_t status;
    pl_compiler_t compiler;
    uint32 type = desc->type;
    var_udo_t *obj = desc->obj;
    saved_schema_t schema;
    pl_entity_t *entity = desc->entity;

    PLC_SAVE_STMT(stmt);
    if (plc_prepare(stmt, &compiler, desc) != CT_SUCCESS) { // large page allocated
        PLC_RESTORE_STMT(stmt);
        return CT_ERROR;
    }
    compiler.obj = obj;
    if (compiler.obj != NULL) {
        if (sql_switch_schema_by_name(stmt, &obj->user, &schema) != CT_SUCCESS) {
            PLC_RESTORE_STMT(stmt);
            gfree(compiler.convert_buf);
            return CT_ERROR;
        }
    }

    set_inter_plc_cnt();
    plc_set_tls_plc_error();
    status = plc_do_compile_core(&compiler, word, type);
    if (status != CT_SUCCESS) {
        plc_set_compiling_errors(stmt, obj);
    } else {
        status = sql_append_references(&entity->ref_list, stmt->context);
    }
    if (compiler.obj != NULL) {
        sql_restore_schema(stmt, &schema);
    }
    reset_inter_plc_cnt();
    plc_reset_tls_plc_error();
    gfree(compiler.convert_buf);
    PLC_RESTORE_STMT(stmt);

    return status;
}

status_t plc_compile(sql_stmt_t *stmt, plc_desc_t *desc, word_t *word)
{
    bool32 save_disable_soft_parse = stmt->session->disable_soft_parse;
    // PLSQL need soft parse
    stmt->session->disable_soft_parse = CT_FALSE;
    status_t status = plc_do_compile(stmt, desc, word);
    stmt->session->disable_soft_parse = save_disable_soft_parse;
    return status;
}

static status_t pl_get_uid(knl_session_t *knl_session, text_t *user, uint32 *uid)
{
    if (!knl_get_user_id(knl_session, user, uid)) {
        CT_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(user));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t pl_recompile_object(sql_stmt_t *stmt, var_udo_t *obj, uint32 type)
{
    pl_entry_info_t entry_info;
    pl_entity_t *entity = NULL;
    dc_user_t *dc_user = NULL;
    bool32 found = CT_FALSE;

    CT_RETURN_IFERR(dc_open_user(KNL_SESSION(stmt), &obj->user, &dc_user));
    pl_find_entry_for_desc(dc_user, &obj->name, type, &entry_info, &found);

    if (!found) {
        return CT_SUCCESS;
    }

    if (pl_lock_entry_shared(KNL_SESSION(stmt), &entry_info) != CT_SUCCESS) {
        return CT_ERROR;
    }

    status_t status = pl_load_entity(stmt, entry_info.entry, &entity);
    if (status == CT_SUCCESS && entity != NULL) {
        pl_set_entity_for_recompile(entry_info.entry, entity);
    }

    pl_unlock_shared(KNL_SESSION(stmt), entry_info.entry);
    return status;
}

status_t pl_compile_by_user(sql_stmt_t *stmt, text_t *schema_name, bool32 compile_all)
{
    knl_cursor_t *cursor = NULL;
    uint32 obj_status, uid;
    knl_session_t *session = KNL_SESSION(stmt);
    var_udo_t obj;
    obj.name_sensitive = CT_TRUE;
    obj.pack = CM_NULL_TEXT;

    CT_RETURN_IFERR(pl_get_uid(KNL_SESSION(stmt), schema_name, &uid));
    obj.user = *schema_name;
    knl_set_session_scn(session, CT_INVALID_ID64);

    CTSQL_SAVE_STACK(stmt);
    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_PROC_ID, IX_PROC_003_ID);
    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&uid, sizeof(int32),
        IX_PROC_003_ID_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, (void *)&uid, sizeof(int32),
        IX_PROC_003_ID_USER);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_PROC_003_ID_OBJ);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_PROC_003_ID_OBJ);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    while (!cursor->eof) {
        obj_status = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PROC_STATUS_COL);
        if ((compile_all == CT_FALSE && obj_status != OBJ_STATUS_VALID) || compile_all == CT_TRUE) {
            // ignore current compile error
            cm_reset_error();
            char pl_type = *(char *)CURSOR_COLUMN_DATA(cursor, SYS_PROC_TYPE_COL);
            uint32 type = plm_get_pl_type(pl_type);
            obj.name.str = CURSOR_COLUMN_DATA(cursor, SYS_PROC_NAME_COL);
            obj.name.len = CURSOR_COLUMN_SIZE(cursor, SYS_PROC_NAME_COL);

            if (pl_recompile_object(stmt, &obj, type) != CT_SUCCESS) {
                CTSQL_RESTORE_STACK(stmt);
                return CT_ERROR;
            }
        }

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }
    }
    CTSQL_RESTORE_STACK(stmt);
    cm_reset_error();
    return CT_SUCCESS;
}
