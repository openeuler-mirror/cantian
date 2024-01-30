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
 * decl_cl.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/parser/decl_cl.c
 *
 * -------------------------------------------------------------------------
 */
#include "decl_cl.h"
#include "base_compiler.h"
#include "srv_instance.h"
#include "pl_memory.h"
#include "trigger_decl_cl.h"
#include "pragma_cl.h"
#include "cursor_cl.h"
#include "typedef_cl.h"

plv_decl_t *plc_find_param_by_id(pl_compiler_t *compiler, plv_id_t plv_id)
{
    return (plv_decl_t *)cm_galist_get(compiler->params, plv_id.id);
}

plv_decl_t *plc_find_decl_by_id(pl_compiler_t *compiler, plv_id_t plv_id)
{
    if (plv_id.block >= (int16)compiler->stack.depth) {
        if (plv_id.block != 0 || compiler->decls == NULL || plv_id.id >= compiler->decls->count) {
            return NULL;
        }

        return (plv_decl_t *)cm_galist_get(compiler->decls, plv_id.id);
    }

    uint16 depth = (uint16)plv_id.block;
    plc_block_t *block = &compiler->stack.items[depth];
    pl_line_ctrl_t *line = block->entry;
    galist_t *decls = NULL;

    if (line->type == LINE_BEGIN) {
        decls = ((pl_line_begin_t *)line)->decls;
    } else if (line->type == LINE_FOR) {
        decls = ((pl_line_for_t *)line)->decls;
    } else {
        return NULL;
    }

    if (decls == NULL || plv_id.id >= decls->count) {
        return NULL;
    }

    return (plv_decl_t *)cm_galist_get(decls, plv_id.id);
}

/*
 * @brief   seek label if exists, and avoid duplicate label
 */
void plc_find_label(pl_compiler_t *compiler, text_t *label, pl_line_ctrl_t **line, bool32 *result)
{
    uint32 i;
    pl_line_label_t *cmp_line = NULL;
    uint32 label_num = 0;

    for (i = 0; i < compiler->labels.count; i++) {
        cmp_line = (pl_line_label_t *)compiler->labels.lines[i];
        if (cm_text_equal(&cmp_line->name, label)) {
            *line = compiler->labels.lines[i];
            label_num++;
        }
    }

    *result = (label_num == 1);
}

/*
 * @brief    search variant decl by block name and variant own name in BEGIN line
 */
void plc_find_in_begin_block(pl_compiler_t *compiler, uint32 stack_id, plc_variant_name_t *var, uint32 types,
    plv_decl_t **decl)
{
    plc_block_t *block = &compiler->stack.items[stack_id];
    pl_line_begin_t *begin_line = (pl_line_begin_t *)block->entry;
    plv_decl_t *select = NULL;

    if ((var->block_name.len != 0) && !cm_text_equal_ins(&var->block_name, &block->name)) {
        return;
    }

    if (begin_line->decls == NULL) {
        return;
    }

    plc_find_in_decls(begin_line->decls, &var->name, var->case_sensitive, &select);
    if (select && (select->type & types) == 0) {
        return;
    }
    *decl = select;
}

/*
 * @brief    search variant decl by block name and variant own name in FOR line
 */
static void plc_find_in_for_block(pl_compiler_t *compiler, uint32 stack_id, plc_variant_name_t *var, uint32 types,
    plv_decl_t **decl)
{
    plc_block_t *block = &compiler->stack.items[stack_id];
    pl_line_for_t *line = (pl_line_for_t *)block->entry;
    bool32 result = CT_FALSE;

    if ((var->block_name.len != 0) && !cm_text_equal(&var->block_name, &block->name)) {
        return;
    }

    plc_cmp_name(&line->id->name, &var->name, var->case_sensitive, &result);
    if (!result || (line->id->type & types) == 0) {
        return;
    }

    *decl = line->id;
}

/*
 * @brief   search variant decl by block name and variant own name in compiler's block
 */
void plc_find_block_decl(pl_compiler_t *compiler, plc_variant_name_t *variant_name, plv_decl_t **decl)
{
    plc_block_t *block = NULL;
    plv_decl_t *item = NULL;

    /* Name is occured at begin block. */
    for (int32 i = (int32)compiler->stack.depth - 1; i >= 0; i--) {
        block = &compiler->stack.items[i];
        switch (block->entry->type) {
            case LINE_FOR:
                plc_find_in_for_block(compiler, (uint32)i, variant_name, variant_name->types, &item);
                break;
            case LINE_BEGIN:
                plc_find_in_begin_block(compiler, (uint32)i, variant_name, variant_name->types, &item);
                break;
            default:
                break;
        }

        if (item != NULL && item->arg_type != PLV_CURSOR_ARG) {
            // has found decl but we not return cursor_arg decl
            *decl = item;
            return;
        }
    }
    item = NULL;

    /* Name is occured at declare block. */
    if (compiler->decls != NULL) {
        plc_find_in_decls(compiler->decls, &variant_name->name, variant_name->case_sensitive, &item);
        if (item == NULL || (item->type & variant_name->types) == 0 || item->arg_type == PLV_CURSOR_ARG) {
            return;
        }

        *decl = item;
        return;
    }
}

/*
 * @brief    change the variant name to block name and variant own name
 */
void plc_translate_variant(pl_compiler_t *compiler, word_t *word, plc_variant_name_t *variant_name,
                           plc_var_type_t *var_type)
{
    pl_line_ctrl_t *line = NULL;
    bool32 is_label = CT_FALSE;
    bool32 is_upper_case = CT_TRUE;

    variant_name->case_sensitive = IS_DQ_STRING(word->type);
    if (word->ex_count == 0) {
        *var_type = PLC_NORMAL_VAR;
        variant_name->block_name.len = 0;
        plc_concat_text_upper_by_type(&variant_name->name, CT_MAX_NAME_LEN, &word->text.value, word->type);
        return;
    }

    if (IS_TRIGGER_WORD_TYPE(word)) {
        *var_type = PLC_TRIGGER_VAR;
        variant_name->block_name.len = 0;
        plc_get_trig_decl_name(compiler, &variant_name->name, word, &is_upper_case);
        variant_name->case_sensitive = CT_TRUE;
        return;
    }

    if (word->ex_count >= 1) {
        plc_concat_text_upper_by_type(&variant_name->block_name, CT_MAX_NAME_LEN, &word->text.value, word->type);
        plc_find_label(compiler, &variant_name->block_name, &line, &is_label);
        if (is_label) {
            *var_type = PLC_BLOCK_VAR;
            plc_concat_text_upper_by_type(&variant_name->name, CT_MAX_NAME_LEN, &word->ex_words[0].text.value,
                word->ex_words[0].type);
            return;
        } else {
            variant_name->block_name.len = 0;
            plc_concat_text_upper_by_type(&variant_name->name, CT_MAX_NAME_LEN, &word->text.value, word->type);
        }
    }
    *var_type = PLC_MULTIEX_VAR;
}

/*
 * @brief    search decl by name and type, before using plc_find_decl_ex, check len of word
 */
void plc_find_decl_ex(pl_compiler_t *compiler, word_t *word, uint32 types, plc_var_type_t *var_type, plv_decl_t **decl)
{
    plc_var_type_t type;
    char block_name_buf[CT_NAME_BUFFER_SIZE];
    char name_buf[CT_NAME_BUFFER_SIZE];
    plc_variant_name_t variant_name;
    *decl = NULL;
    PLC_INIT_VARIANT_NAME(&variant_name, block_name_buf, name_buf, CT_FALSE, types);
    plc_translate_variant(compiler, word, &variant_name, &type);

    if (var_type != NULL) {
        *var_type = type;
    }
    if (type == PLC_NORMAL_VAR || type == PLC_TRIGGER_VAR) {
        plc_find_block_decl(compiler, &variant_name, decl);
        return;
    }
    if (type == PLC_BLOCK_VAR) {
        plc_find_block_decl(compiler, &variant_name, decl);
        if (*decl == NULL) {
            type = PLC_MULTIEX_VAR;
            variant_name.block_name.len = 0;
            variant_name.name.len = 0;
            plc_concat_text_upper_by_type(&variant_name.name, CT_MAX_NAME_LEN, &word->text.value, word->type);
        } else {
            if (word->ex_count == 1) {
                return;
            }
            if (var_type != NULL) {
                *var_type = PLC_BLOCK_MULTIEX_VAR;
            }
            return;
        }
    }

    if (var_type != NULL) {
        *var_type = type;
    }
    plc_find_block_decl(compiler, &variant_name, decl);
}

status_t plc_find_decl(pl_compiler_t *compiler, word_t *word, uint32 types, plc_var_type_t *var_type, plv_decl_t **decl)
{
    size_t witer_pos;
    CT_RETURN_IFERR(plc_verify_word_as_var(compiler, word));
    plc_find_decl_ex(compiler, word, types, var_type, decl);

    if (*decl != NULL) {
        return CT_SUCCESS;
    }

    witer_pos = strlen(g_tls_error.message);
    if (IS_TRIGGER_WORD_TYPE(word)) {
        CT_RETURN_IFERR(plc_add_trigger_decl(compiler, 0, word, PLV_VAR, decl));
        if (*decl != NULL) {
            return CT_SUCCESS;
        }
    }

    if (strlen(g_tls_error.message) == witer_pos) {
        CT_SRC_THROW_ERROR(word->loc, ERR_UNDEFINED_SYMBOL_FMT, W2S(word));
    }

    return CT_ERROR;
}

/*
 * @brief    pl's check datatype, it's important to support blob/clob/image in pl
 */
status_t plc_check_datatype(pl_compiler_t *compiler, typmode_t *type, bool32 is_arg)
{
    lex_t *lex = compiler->stmt->session->lex;
    switch (type->datatype) {
        case CT_TYPE_CHAR:
            if (is_arg) {
                type->size = (uint16)CT_MAX_COLUMN_SIZE;
                return CT_SUCCESS;
            }
            if (type->size > CT_MAX_COLUMN_SIZE) {
                CT_SRC_THROW_ERROR_EX(lex->loc, ERR_PL_SYNTAX_ERROR_FMT, "size of CHAR must less than %d",
                    CT_MAX_COLUMN_SIZE);
                return CT_ERROR;
            }
            return CT_SUCCESS;

        case CT_TYPE_STRING:
        case CT_TYPE_VARCHAR:
            if (is_arg) {
                type->size = (uint16)CT_MAX_STRING_LEN;
                return CT_SUCCESS;
            }
            if (type->size > CT_MAX_STRING_LEN) {
                CT_SRC_THROW_ERROR_EX(lex->loc, ERR_PL_SYNTAX_ERROR_FMT, "size of VARCHAR must less than %d",
                    CT_MAX_STRING_LEN);
                return CT_ERROR;
            }
            return CT_SUCCESS;

        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
        case CT_TYPE_INTEGER:
        case CT_TYPE_BOOLEAN:
        case CT_TYPE_BIGINT:
        case CT_TYPE_REAL:
        case CT_TYPE_NUMBER:
        case CT_TYPE_NUMBER2:
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_TZ:
        case CT_TYPE_TIMESTAMP_LTZ:
        case CT_TYPE_INTERVAL_DS:
        case CT_TYPE_INTERVAL_YM:
        case CT_TYPE_CURSOR:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_UINT32:
        case CT_TYPE_UINT64:
        case CT_TYPE_SMALLINT:
        case CT_TYPE_USMALLINT:
        case CT_TYPE_TINYINT:
        case CT_TYPE_UTINYINT:
            return CT_SUCCESS;

        case CT_TYPE_BLOB:
            type->datatype = CT_TYPE_RAW;
            type->size = CT_MAX_COLUMN_SIZE;
            return CT_SUCCESS;

        case CT_TYPE_CLOB:
        case CT_TYPE_IMAGE:
            type->datatype = CT_TYPE_STRING;
            type->size = CT_MAX_STRING_LEN;
            return CT_SUCCESS;

        default:
            CT_SRC_THROW_ERROR(lex->loc, ERR_INVALID_DATA_TYPE, "unknown");
            return CT_ERROR;
    }
}

status_t plc_check_record_datatype(pl_compiler_t *compiler, plv_decl_t *decl, bool32 is_arg)
{
    uint32 i;
    for (i = 0; i < decl->record->count; i++) {
        plv_record_attr_t *attr = udt_seek_field_by_id(decl->record, i);
        if (attr->type != UDT_SCALAR) {
            continue;
        }

        CT_RETURN_IFERR(plc_check_datatype(compiler, &attr->scalar_field->type_mode, is_arg));
    }
    return CT_SUCCESS;
}

/*
 * @brief    compile variant's default expr define
 */
status_t plc_compile_default_def(pl_compiler_t *compiler, word_t *word, plv_decl_t *decl, bool32 is_arg)
{
    bool32 result = CT_FALSE;
    lex_t *lex = compiler->stmt->session->lex;
    CT_RETURN_IFERR(lex_try_fetch(lex, ":=", &result));
    if (!result) {
        CT_RETURN_IFERR(lex_try_fetch(lex, "DEFAULT", &result));
    }

    if (!result) {
        if (is_arg) {
            CT_RETURN_IFERR(lex_fetch(lex, word));
        } else {
            CT_RETURN_IFERR(lex_expected_fetch_word(lex, ";"));
        }

        return CT_SUCCESS;
    }

    if (decl->drct == PLV_DIR_OUT || decl->drct == PLV_DIR_INOUT) {
        CT_SRC_THROW_ERROR(word->loc, ERR_PL_OUT_PARAM_WITH_DFT);
        return CT_ERROR;
    }

    lex->flags = LEX_WITH_OWNER | LEX_WITH_ARG;

    PLC_RESET_WORD_LOC(lex, word);
    CT_RETURN_IFERR(lex_try_fetch(lex, "PRIOR", &result));
    if (result) {
        CT_SRC_THROW_ERROR(word->loc, ERR_PL_ENCOUNT_PRIOR);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_create_expr_until(compiler->stmt, &decl->default_expr, word));
    CT_RETURN_IFERR(plc_verify_expr(compiler, decl->default_expr));
    CT_RETURN_IFERR(plc_clone_expr_tree(compiler, &decl->default_expr));

    if (is_arg) {
        return CT_SUCCESS;
    }
    if (!IS_SPEC_CHAR(word, ';')) {
        CT_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", "OTHERS");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t plc_extract_table_column(pl_compiler_t *compiler, word_t *word, var_udo_t *obj, text_t *column)
{
    session_t *cmpl_session = compiler->stmt->session;
    if ((word->ex_count == 0) || (word->ex_count >= MAX_EXTRA_TEXTS)) {
        CT_SRC_THROW_ERROR(word->loc, ERR_PL_ATTR_TYPE_FMT, cmpl_session->curr_schema, W2S(word));
        return CT_ERROR;
    }

    if (word->ex_count == 1) {
        CT_RETURN_IFERR(cm_text_copy_from_str(&obj->user, cmpl_session->curr_schema, CT_NAME_BUFFER_SIZE));
        CT_RETURN_IFERR(cm_text_copy(&obj->name, CT_NAME_BUFFER_SIZE, &word->text.value));
        obj->user_explicit = CT_FALSE;
        *column = word->ex_words[0].text.value;
    } else {
        text_t user;
        CT_RETURN_IFERR(sql_copy_prefix_tenant(compiler->stmt, &word->text.value, &user, sql_copy_text));
        cm_text_copy_upper(&obj->user, &user);
        CT_RETURN_IFERR(cm_text_copy(&obj->name, CT_NAME_BUFFER_SIZE, &word->ex_words[0].text.value));
        *column = word->ex_words[1].text.value;
        obj->user_explicit = CT_TRUE;
    }

    if (IS_CASE_INSENSITIVE) {
        cm_text_upper(&obj->name);
        cm_text_upper(column);
    }
    return CT_SUCCESS;
}

expr_node_t *plc_get_param_vid(pl_compiler_t *compiler, uint32 p_nid)
{
    galist_t *input = NULL;
    plv_decl_t *decl = NULL;
    pl_line_ctrl_t *line_ctrl = compiler->last_line;

    switch (line_ctrl->type) {
        case LINE_SQL:
            input = ((pl_line_sql_t *)line_ctrl)->input;
            break;
        case LINE_OPEN:
            decl = plc_find_decl_by_id(compiler, ((pl_line_open_t *)line_ctrl)->vid);
            if (decl == NULL) {
                return NULL;
            }
            input = (decl->cursor.ctx->is_sysref) ? ((pl_line_open_t *)line_ctrl)->input : decl->cursor.input;
            break;
        case LINE_FOR:
            if (!((pl_line_for_t *)line_ctrl)->is_cur) {
                return NULL;
            }
            decl = plc_find_decl_by_id(compiler, ((pl_line_for_t *)line_ctrl)->cursor_id);
            if (decl == NULL) {
                return NULL;
            }
            input = decl->cursor.input;
            break;
        default:
            return NULL;
    }

    return (expr_node_t *)cm_galist_get(input, p_nid);
}

status_t plc_compile_decl(pl_compiler_t *compiler, galist_t *decls, word_t *word)
{
    uint32 matched_id;
    plv_decl_t *decl = NULL;
    bool32 result = CT_FALSE;
    lex_t *lex = compiler->stmt->session->lex;
    plc_check_duplicate(decls, (text_t *)&word->text, IS_DQ_STRING(word->type), &result);

    if (result) {
        CT_SRC_THROW_ERROR(word->loc, ERR_DUPLICATE_NAME, "declaration", T2S((text_t *)&word->text));
        return CT_ERROR;
    }
    CT_RETURN_IFERR(cm_galist_new(decls, sizeof(plv_decl_t), (void **)&decl));
    decl->vid.block = (int16)compiler->stack.depth;
    decl->vid.id = (uint16)(decls->count - 1); // not overflow
    decl->loc = word->loc;

    CT_RETURN_IFERR(lex_try_fetch_1of2(lex, "EXCEPTION", "SYS_REFCURSOR", &matched_id));

    if (matched_id == 0) {
        decl->type = PLV_EXCPT;
        CT_RETURN_IFERR(plc_compile_excpt_def(compiler, word, decl));
        CT_RETURN_IFERR(lex_expected_fetch_word(lex, ";"));
    } else if (matched_id == 1) {
        decl->type = PLV_CUR;
        CT_RETURN_IFERR(plc_compile_syscursor_def(compiler, word, decl));
        CT_RETURN_IFERR(lex_expected_fetch_word(lex, ";"));
    } else {
        CT_RETURN_IFERR(plc_compile_variant_def(compiler, word, decl, CT_FALSE, decls, CT_TRUE));
        CT_RETURN_IFERR(plc_compile_default_def(compiler, word, decl, CT_FALSE));
    }
    return CT_SUCCESS;
}

/*
 * @brief    complex type compile, only support record and cursor
 */
status_t plc_compile_complex_type(pl_compiler_t *compiler, plv_decl_t *decl, plv_decl_t *type_recur)
{
    plv_typdef_t *type = &type_recur->typdef;
    pl_entity_t *pl_entity = compiler->entity;
    switch (decl->type) {
        case PLV_RECORD:
            decl->record = &type->record;
            return plc_check_record_datatype(compiler, decl, CT_FALSE);
        case PLV_OBJECT:
            decl->object = &type->object;
            return plc_check_object_datatype(compiler, decl, CT_FALSE);
        case PLV_CUR:
            CT_RETURN_IFERR(pl_alloc_mem(pl_entity, sizeof(plv_cursor_context_t), (void **)&decl->cursor.ctx));
            decl->cursor.ctx->is_sysref = (bool8)CT_TRUE;
            break;
        case PLV_COLLECTION:
            decl->collection = &type->collection;
            break;
        default:
            break;
    }
    return CT_SUCCESS;
}
