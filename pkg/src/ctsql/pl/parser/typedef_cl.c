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
 * typedef_cl.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/parser/typedef_cl.c
 *
 * -------------------------------------------------------------------------
 */
#include "typedef_cl.h"
#include "pl_dc.h"
#include "srv_instance.h"
#include "base_compiler.h"
#include "decl_cl.h"
#include "cursor_cl.h"
#include "pl_common.h"
#include "pl_memory.h"
#include "ctsql_dependency.h"

status_t plc_convert_typedecl(pl_compiler_t *compiler, galist_t *decls)
{
    plv_decl_t *decl = NULL;
    plv_decl_t *type_decl = NULL;
    for (uint32 i = 0; i < compiler->type_decls->count; i++) {
        decl = NULL;
        CT_RETURN_IFERR(cm_galist_new(decls, sizeof(plv_decl_t), (void **)&decl));
        type_decl = cm_galist_get(compiler->type_decls, i);
        *decl = *type_decl;
        decl->vid.id = decls->count - 1;
    }
    return CT_SUCCESS;
}

/*
 * @brief PLC_PMODE dedicate for the datatype belong to PLSQL object like procedure, user define function or trigger
 */
#define PLC_PMODE(direction) \
    (((direction) == PLV_DIR_IN || (direction) == PLV_DIR_OUT || (direction) == PLV_DIR_INOUT) ? PM_PL_ARG : PM_PL_VAR)

void plm_parse_name_by_copy(sql_stmt_t *stmt, word_t *word, var_udo_t *obj)
{
    if (word->ex_count == 1) {
        text_t user;
        char buf[CT_NAME_BUFFER_SIZE];

        (void)cm_text2str(&word->text.value, buf, CT_NAME_BUFFER_SIZE);
        (void)sql_user_prefix_tenant(stmt->session, buf);
        cm_str2text(buf, &user);
        cm_concat_text(&obj->user, CT_NAME_BUFFER_SIZE, &user);
        cm_text_upper_self_name(&obj->user);

        cm_concat_text(&obj->name, CT_NAME_BUFFER_SIZE, &word->ex_words[0].text.value);
        if (IS_DQ_STRING(word->ex_words[0].type) || !IS_CASE_INSENSITIVE) {
            obj->name_sensitive = CT_TRUE;
        } else {
            obj->name_sensitive = CT_FALSE;
            cm_text_upper_self_name(&obj->name);
        }
        obj->user_explicit = CT_TRUE;
    } else {
        text_t user = {
            .str = stmt->session->curr_schema,
            .len = (uint32)strlen(stmt->session->curr_schema)
        };
        cm_concat_text(&obj->user, CT_NAME_BUFFER_SIZE, &user);

        cm_concat_text(&obj->name, CT_NAME_BUFFER_SIZE, &word->text.value);
        if (IS_DQ_STRING(word->type | word->ori_type) || !IS_CASE_INSENSITIVE) {
            obj->name_sensitive = CT_TRUE;
        } else {
            obj->name_sensitive = CT_FALSE;
            cm_text_upper_self_name(&obj->name);
        }
        obj->user_explicit = CT_FALSE;
    }
}

status_t plc_try_find_global_type(pl_compiler_t *compiler, word_t *word, plv_decl_t **decl, bool32 *found)
{
    var_udo_t obj;
    char user[CT_NAME_BUFFER_SIZE] = { 0 };
    char pack[CT_NAME_BUFFER_SIZE] = { 0 };
    char name[CT_NAME_BUFFER_SIZE] = { 0 };
    pl_dc_t type_dc = { 0 };
    uint32 ex_count_bak;
    bool32 result;

    ex_count_bak = word->ex_count;
    if (word->ex_count > 0 && (word->ex_words[word->ex_count - 1].type & WORD_TYPE_BRACKET) != 0) {
        word->ex_count--;
    }
    // parse name need XXX or XXX.XXX
    if (word->ex_count > 1) {
        word->ex_count = ex_count_bak;
        *decl = NULL;
        *found = CT_FALSE;
        return CT_SUCCESS;
    }
    plc_try_verify_word_as_var(word, &result);
    if (!result) {
        word->ex_count = ex_count_bak;
        *decl = NULL;
        *found = CT_FALSE;
        return CT_SUCCESS;
    }
    sql_init_udo_with_str(&obj, user, pack, name);
    plm_parse_name_by_copy(compiler->stmt, word, &obj);
    word->ex_count = ex_count_bak;

    if (pl_try_find_type_dc(compiler->stmt, &obj, &type_dc, found) != CT_SUCCESS) {
        pl_check_and_set_loc(word->loc);
        return CT_ERROR;
    }
    if (!*found) {
        *decl = NULL;
    } else {
        *decl = type_dc.entity->type_spec->decl;
    }
    return CT_SUCCESS;
}

status_t plc_check_object_datatype(pl_compiler_t *compiler, plv_decl_t *decl, bool32 is_arg)
{
    for (uint32 i = 0; i < decl->object->count; i++) {
        plv_object_attr_t *attr = udt_seek_obj_field_byid(decl->object, i);
        if (attr->type != UDT_SCALAR) {
            continue;
        }

        CT_RETURN_IFERR(plc_check_datatype(compiler, &attr->scalar_field->type_mode, is_arg));
    }
    return CT_SUCCESS;
}

static status_t plc_check_decl_datatype(pl_compiler_t *compiler, plv_decl_t *decl, bool32 is_arg)
{
    if (decl->type & PLV_VAR) {
        return plc_check_datatype(compiler, &decl->variant.type, is_arg);
    } else if (decl->type & PLV_ARRAY) {
        return plc_check_datatype(compiler, &decl->array.type, CT_FALSE);
    } else if (decl->type & PLV_RECORD) {
        return plc_check_record_datatype(compiler, decl, CT_FALSE);
    } else if (decl->type & PLV_OBJECT) {
        return plc_check_object_datatype(compiler, decl, CT_FALSE);
    }

    // do nothing
    return CT_SUCCESS;
}

static status_t plc_extract_table(pl_compiler_t *compiler, word_t *word, var_udo_t *obj)
{
    session_t *cmpl_session = compiler->stmt->session;
    if (word->ex_count >= 2) {
        CT_SRC_THROW_ERROR(word->loc, ERR_PL_ATTR_ROWTYPE_FMT, W2S(word));
        return CT_ERROR;
    }

    if (word->ex_count == 0) {
        CT_RETURN_IFERR(cm_text_copy_from_str(&obj->user, cmpl_session->curr_schema, CT_NAME_BUFFER_SIZE));
        CT_RETURN_IFERR(cm_text_copy(&obj->name, CT_NAME_BUFFER_SIZE, &word->text.value));
        obj->user_explicit = CT_FALSE;
    } else {
        text_t user;
        CT_RETURN_IFERR(sql_copy_prefix_tenant(compiler->stmt, &word->text.value, &user, sql_copy_text));
        cm_text_copy_upper(&obj->user, &user);
        CT_RETURN_IFERR(cm_text_copy(&obj->name, CT_NAME_BUFFER_SIZE, &word->ex_words[0].text.value));
        obj->user_explicit = CT_TRUE;
    }

    if (IS_CASE_INSENSITIVE) {
        cm_text_upper(&obj->name);
    }
    return CT_SUCCESS;
}

static inline void plc_copy_table_set_attr(plv_record_attr_t *record_attr, knl_column_t *col)
{
    record_attr->type = UDT_SCALAR;
    record_attr->scalar_field->type_mode.datatype = col->datatype;
    record_attr->scalar_field->type_mode.size = (uint16)col->size;
    record_attr->scalar_field->type_mode.precision = (uint8)col->precision;
    record_attr->scalar_field->type_mode.scale = (uint8)col->scale;
    record_attr->default_expr = NULL;
    record_attr->nullable = CT_FALSE;
}

static status_t plc_open_knl_dc(pl_compiler_t *compiler, word_t *word, var_udo_t *obj, text_t *column,
    knl_dictionary_t *dc)
{
    knl_session_t *knl_sess = KNL_SESSION(compiler->stmt);
    pl_entity_t *entity = (pl_entity_t *)compiler->entity;
    knl_dictionary_t *ref_dc = NULL;

    ref_dc = pl_get_regist_knl_dc(compiler->stmt, obj);
    if (ref_dc != NULL) {
        *dc = *ref_dc;
        return CT_SUCCESS;
    }

    if (knl_open_dc_with_public_ex(knl_sess, &obj->user, !obj->user_explicit, &obj->name, dc) != CT_SUCCESS) {
        if (column == NULL) {
            CT_SRC_THROW_ERROR(word->loc, ERR_PL_ATTR_ROWTYPE_FMT, T2S_EX(&obj->name));
        } else {
            CT_SRC_THROW_ERROR(word->loc, ERR_PL_ATTR_TYPE_FMT, T2S(&obj->name), T2S_EX(column));
        }
        return CT_ERROR;
    }

    // if table is ltt, no need to add dc into entity->knl_list
    if (IS_LTT_BY_NAME(obj->name.str)) {
        dc_close(dc);
        pl_entity_uncacheable(entity);
        return CT_SUCCESS;
    }

    // if table is gtt, should add dc into entity->knl_list and set entity uncacheable
    if (dc->type == DICT_TYPE_TEMP_TABLE_TRANS || dc->type == DICT_TYPE_TEMP_TABLE_SESSION) {
        pl_entity_uncacheable(entity);
    }

    if (pl_regist_knl_dc(compiler->stmt, dc) != CT_SUCCESS) {
        dc_close(dc);
        return CT_ERROR;
    }

    // if table is gtt, no need to add dc into ref_list
    if (dc->type == DICT_TYPE_TEMP_TABLE_TRANS || dc->type == DICT_TYPE_TEMP_TABLE_SESSION) {
        return CT_SUCCESS;
    }

    if (sql_append_reference_knl_dc(&entity->ref_list, dc) != CT_SUCCESS) {
        dc_close(dc);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t plc_copy_table_core(pl_compiler_t *compiler, word_t *word, plv_decl_t *decl, var_udo_t *obj)
{
    knl_dictionary_t dc;
    text_t col_name;
    knl_column_t *column = NULL;
    pl_entity_t *pl_entity = compiler->entity;

    CT_RETURN_IFERR(plc_open_knl_dc(compiler, word, obj, NULL, &dc));
    uint32 col_cnt = knl_get_column_count(dc.handle);
    for (uint32 col_id = 0; col_id < col_cnt; col_id++) {
        column = knl_get_column(dc.handle, col_id);
        if (KNL_COLUMN_INVISIBLE(column)) {
            continue;
        }
        plv_record_attr_t *attr = udt_record_alloc_attr((void *)pl_entity, &decl->typdef.record);
        if (attr == NULL) {
            pl_check_and_set_loc(word->loc);
            return CT_ERROR;
        }

        cm_str2text(column->name, &col_name);
        if (pl_copy_name_cs(pl_entity, &col_name, &attr->name, CT_FALSE) != CT_SUCCESS) {
            cm_reset_error();
            CT_SRC_THROW_ERROR(word->loc, ERR_PL_ATTR_ROWTYPE_FMT, W2S(word));
            return CT_ERROR;
        }
        if (pl_alloc_mem(pl_entity, sizeof(field_scalar_info_t), (void **)&attr->scalar_field) != CT_SUCCESS) {
            return CT_ERROR;
        }
        plc_copy_table_set_attr(attr, column);
        if (KNL_COLUMN_IS_ARRAY(column)) {
            CT_SRC_THROW_ERROR(word->loc, ERR_UNSUPPORT_DATATYPE, "ARRAY");
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}


/*
 * @brief    inherit table's define, support for table%rowtype
 */
static status_t plc_copy_table(pl_compiler_t *compiler, word_t *word, plattr_assist_t *plattr_ass)
{
    plv_decl_t *decl = NULL;
    pl_entity_t *pl_entity = compiler->entity;
    text_t type_name;
    var_udo_t obj;
    char buf[CT_VALUE_BUFFER_SIZE];
    char user_buf[CT_NAME_BUFFER_SIZE];
    char name_buf[CT_NAME_BUFFER_SIZE];

    type_name.len = 0;
    type_name.str = buf;
    sql_init_udo_with_str(&obj, user_buf, NULL, name_buf);
    CT_RETURN_IFERR(plc_extract_table(compiler, word, &obj));
    cm_concat_text(&type_name, CT_VALUE_BUFFER_SIZE, &obj.user);
    CM_TEXT_APPEND(&type_name, '@');
    cm_concat_text(&type_name, CT_VALUE_BUFFER_SIZE, &obj.name);

    galist_t *decls = plattr_ass->is_args ? compiler->type_decls : compiler->decls;

    plc_find_in_decls(decls, &type_name, CT_FALSE, &decl);
    if (decl == NULL) {
        CT_RETURN_IFERR(cm_galist_new(decls, sizeof(plv_decl_t), (pointer_t *)&decl));
        CT_RETURN_IFERR(pl_copy_text(pl_entity, &type_name, &decl->name));
        // In fact, this decl won't be retrieved by the following vid. A plv_record_t's root pointer will point at it.
        decl->vid.block = (int16)compiler->stack.depth;
        decl->vid.id = decls->count - 1;
        decl->type = PLV_TYPE;
        decl->typdef.type = PLV_RECORD;
        decl->typdef.record.is_anonymous = CT_TRUE;
        decl->typdef.record.root = decl;
        CT_RETURN_IFERR(plc_copy_table_core(compiler, word, decl, &obj));
    }

    switch (plattr_ass->type) {
        case REC_FIELD_INHERIT:
            plattr_ass->attr->type = UDT_RECORD;
            plattr_ass->attr->udt_field = decl;
            break;
        case DECL_INHERIT:
            plattr_ass->decl->type = PLV_RECORD;
            plattr_ass->decl->record = &decl->typdef.record;
            break;
        case COLL_ATTR_INHERIT:
            plattr_ass->coll->attr_type = UDT_RECORD;
            plattr_ass->coll->elmt_type = decl;
            break;
        default:
            CT_THROW_ERROR(ERR_PL_WRONG_TYPE_VALUE, "inherit type", plattr_ass->type);
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

/*
 * @brief    inherit the column of table define, support for table.column%type
 */
static status_t plc_copy_table_column(pl_compiler_t *compiler, word_t *word, plattr_assist_t *plattr_ass)
{
    text_t column;
    status_t status = CT_ERROR;
    knl_dictionary_t dc;
    knl_column_t *knl_col = NULL;
    pl_entity_t *pl_entity = compiler->entity;
    var_udo_t obj;
    char user_buf[CT_NAME_BUFFER_SIZE];
    char name_buf[CT_NAME_BUFFER_SIZE];

    sql_init_udo_with_str(&obj, user_buf, NULL, name_buf);
    CT_RETURN_IFERR(plc_extract_table_column(compiler, word, &obj, &column));
    CT_RETURN_IFERR(plc_open_knl_dc(compiler, word, &obj, &column, &dc));

    do {
        uint16 col_id = knl_get_column_id(&dc, &column);
        CT_BREAK_IF_TRUE(col_id == CT_INVALID_ID16);
        knl_col = knl_get_column(dc.handle, col_id);
        CT_BREAK_IF_TRUE(KNL_COLUMN_INVISIBLE(knl_col));
        status = CT_SUCCESS;
    } while (0);

    if (status == CT_ERROR) {
        cm_reset_error();
        CT_SRC_THROW_ERROR(word->loc, ERR_PL_ATTR_TYPE_FMT, T2S(&obj.name), T2S_EX(&column));
        return CT_ERROR;
    }
    typmode_t *pmode = NULL;
    switch (plattr_ass->type) {
        case REC_FIELD_INHERIT:
            if (pl_alloc_mem(pl_entity, sizeof(field_scalar_info_t), (void **)&plattr_ass->attr->scalar_field) !=
                CT_SUCCESS) {
                return CT_ERROR;
            }
            plattr_ass->attr->nullable = (bool8)knl_col->nullable;
            plattr_ass->attr->type = UDT_SCALAR;
            pmode = &plattr_ass->attr->scalar_field->type_mode;
            break;
        case DECL_INHERIT:
            plattr_ass->decl->type = PLV_VAR;
            plattr_ass->decl->default_expr = NULL;
            pmode = &plattr_ass->decl->variant.type;
            break;
        case COLL_ATTR_INHERIT:
            plattr_ass->coll->attr_type = UDT_SCALAR;
            pmode = &plattr_ass->coll->type_mode;
            break;
        default:
            CT_THROW_ERROR(ERR_PL_WRONG_TYPE_VALUE, "inherit type", plattr_ass->type);
            return CT_ERROR;
    }

    pmode->datatype = knl_col->datatype;
    pmode->precision = (uint8)knl_col->precision;
    pmode->scale = (uint8)knl_col->scale;
    pmode->size = (uint16)knl_col->size;
    pmode->is_array = KNL_COLUMN_IS_ARRAY(knl_col) ? 1 : 0;
    status = plc_check_datatype(compiler, pmode, CT_FALSE);
    return status;
}

static status_t plc_copy_simple_attr_type(pl_compiler_t *compiler, plv_decl_t *src, plv_record_attr_t *attr,
    word_t *word)
{
    session_t *cmpl_session = compiler->stmt->session;
    pl_entity_t *pl_entity = compiler->entity;
    switch (src->type) {
        case PLV_VAR:
            attr->type = UDT_SCALAR;
            CT_RETURN_IFERR(pl_alloc_mem(pl_entity, sizeof(field_scalar_info_t), (void **)&attr->scalar_field));
            attr->default_expr = src->default_expr;
            attr->scalar_field->type_mode = src->variant.type;
            return CT_SUCCESS;
        case PLV_RECORD:
            attr->type = UDT_RECORD;
            attr->udt_field = src;
            // notice: return the record's vid instead of type's vid
            return CT_SUCCESS;
        case PLV_OBJECT:
            attr->type = UDT_OBJECT;
            attr->udt_field = src;
            return CT_SUCCESS;
        case PLV_COLLECTION:
            attr->type = UDT_COLLECTION;
            attr->udt_field = src;
            // notice: return the record's vid instead of type's vid
            return CT_SUCCESS;
        case PLV_ARRAY:
            CT_SRC_THROW_ERROR((word)->loc, ERR_UNSUPPORT_DATATYPE, "ARRAY");
            return CT_ERROR;
        default: // PLV_CUR PLV_TYPE
            CT_SRC_THROW_ERROR(word->loc, ERR_PL_ATTR_TYPE_FMT, cmpl_session->curr_schema, W2S(word));
            return CT_ERROR;
    }
    return CT_ERROR;
}

static status_t plc_copy_attr_type(pl_compiler_t *compiler, plv_decl_t *src, plc_var_type_t var_type,
    plv_record_attr_t *attr, word_t *word)
{
    plv_record_attr_t *src_attr = NULL;
    plv_object_attr_t *obj_attr = NULL;
    pl_entity_t *pl_entity = compiler->entity;
    if (PLV_REC_EXIST_FIELD(src, var_type)) {
        uint16 id = 0;
        src_attr = udt_record_recurse_find_attr(compiler->stmt, &id, src->record, word);
        if (src_attr == NULL) {
            CT_SRC_THROW_ERROR(word->ex_words[id].text.loc, ERR_PL_REF_VARIABLE_FAILED,
                T2S(&word->ex_words[id].text.value));
            return CT_ERROR;
        }
        if (src_attr->type == UDT_SCALAR) {
            CT_RETURN_IFERR(pl_alloc_mem(pl_entity, sizeof(field_scalar_info_t), (void **)&attr->scalar_field));
            attr->type = UDT_SCALAR;
            attr->default_expr = src_attr->default_expr;
            attr->scalar_field->type_mode = src_attr->scalar_field->type_mode;
        } else {
            CT_RETURN_IFERR(plc_copy_simple_attr_type(compiler, src_attr->udt_field, attr, word));
        }
    } else if (PLV_OBJ_EXIST_FIELD(src, var_type)) {
        uint16 id = 0;
        obj_attr = udt_object_recurse_find_attr(compiler->stmt, &id, src->object, word);
        if (obj_attr == NULL) {
            CT_SRC_THROW_ERROR(word->ex_words[id].text.loc, ERR_PL_REF_VARIABLE_FAILED,
                T2S(&word->ex_words[id].text.value));
            return CT_ERROR;
        }

        if (obj_attr->type == UDT_SCALAR) {
            CT_RETURN_IFERR(pl_alloc_mem(pl_entity, sizeof(field_scalar_info_t), (void **)&attr->scalar_field));
            attr->type = UDT_SCALAR;
            attr->default_expr = obj_attr->default_expr;
            attr->scalar_field->type_mode = obj_attr->scalar_field->type_mode;
        } else {
            CT_RETURN_IFERR(plc_copy_simple_attr_type(compiler, obj_attr->udt_field, attr, word));
        }
    } else {
        CT_RETURN_IFERR(plc_copy_simple_attr_type(compiler, src, attr, word));
    }

    return CT_SUCCESS;
}

static status_t plc_copy_simple_decl_type(pl_compiler_t *compiler, plv_decl_t *src, plv_decl_t *dst, word_t *word)
{
    session_t *cmpl_session = compiler->stmt->session;
    switch (src->type) {
        case PLV_VAR:
            dst->type = PLV_VAR;
            dst->default_expr = src->default_expr;
            dst->variant.type = src->variant.type;
            return CT_SUCCESS;
        case PLV_ARRAY:
            CT_SRC_THROW_ERROR((word)->loc, ERR_UNSUPPORT_DATATYPE, "ARRAY");
            return CT_ERROR;
        case PLV_RECORD:
            dst->type = PLV_RECORD;
            dst->record = src->record;
            return CT_SUCCESS;
        case PLV_OBJECT:
            dst->type = PLV_OBJECT;
            dst->object = src->object;
            return CT_SUCCESS;
        case PLV_COLLECTION:
            dst->type = PLV_COLLECTION;
            dst->collection = src->collection;
            return CT_SUCCESS;
            /* fall-through */
        default: // PLV_CUR PLV_TYPE
            CT_SRC_THROW_ERROR(word->loc, ERR_PL_ATTR_TYPE_FMT, cmpl_session->curr_schema, W2S(word));
            return CT_ERROR;
    }
}

static status_t plc_copy_decl_type(pl_compiler_t *compiler, plv_decl_t *src, plc_var_type_t var_type, plv_decl_t *dst,
    word_t *word)
{
    plv_record_attr_t *src_attr = NULL;
    plv_object_attr_t *obj_attr = NULL;
    if (PLV_REC_EXIST_FIELD(src, var_type)) {
        uint16 id = 0;
        src_attr = udt_record_recurse_find_attr(compiler->stmt, &id, src->record, word);
        if (src_attr == NULL) {
            CT_SRC_THROW_ERROR(word->ex_words[id].text.loc, ERR_PL_REF_VARIABLE_FAILED,
                T2S(&word->ex_words[id].text.value));
            return CT_ERROR;
        }
        if (src_attr->type == UDT_SCALAR) {
            dst->type = PLV_VAR;
            dst->default_expr = src_attr->default_expr;
            dst->variant.type = src_attr->scalar_field->type_mode;
        } else {
            CT_RETURN_IFERR(plc_copy_simple_decl_type(compiler, src_attr->udt_field, dst, word));
        }
    } else if (PLV_OBJ_EXIST_FIELD(src, var_type)) {
        uint16 id = 0;
        obj_attr = udt_object_recurse_find_attr(compiler->stmt, &id, src->object, word);
        if (obj_attr == NULL) {
            CT_SRC_THROW_ERROR(word->ex_words[id].text.loc, ERR_PL_REF_VARIABLE_FAILED,
                T2S(&word->ex_words[id].text.value));
            return CT_ERROR;
        }

        if (obj_attr->type == UDT_SCALAR) {
            dst->type = PLV_VAR;
            dst->default_expr = obj_attr->default_expr;
            dst->variant.type = obj_attr->scalar_field->type_mode;
        } else {
            CT_RETURN_IFERR(plc_copy_simple_decl_type(compiler, obj_attr->udt_field, dst, word));
        }
    } else {
        CT_RETURN_IFERR(plc_copy_simple_decl_type(compiler, src, dst, word));
    }

    return CT_SUCCESS;
}

static status_t plc_copy_simple_coll_type(pl_compiler_t *compiler, plv_decl_t *src, plv_collection_t *coll,
    word_t *word)
{
    session_t *cmpl_session = compiler->stmt->session;
    switch (src->type) {
        case PLV_VAR:
            coll->attr_type = UDT_SCALAR;
            coll->type_mode = src->variant.type;
            return CT_SUCCESS;
        case PLV_RECORD:
            coll->attr_type = UDT_RECORD;
            coll->elmt_type = src;
            // notice: return the record's vid instead of type's vid
            return CT_SUCCESS;
        case PLV_OBJECT:
            coll->attr_type = UDT_OBJECT;
            coll->elmt_type = src;
            return CT_SUCCESS;
        case PLV_COLLECTION:
            coll->attr_type = UDT_COLLECTION;
            coll->elmt_type = src;
            return CT_SUCCESS;
        case PLV_ARRAY:
            CT_SRC_THROW_ERROR(word->loc, ERR_UNSUPPORT_DATATYPE, "ARRAY");
            return CT_ERROR;
        default: // PLV_CUR PLV_TYPE
            CT_SRC_THROW_ERROR(word->loc, ERR_PL_ATTR_TYPE_FMT, cmpl_session->curr_schema, W2S(word));
            return CT_ERROR;
    }
    return CT_ERROR;
}

static status_t plc_copy_coll_attr_type(pl_compiler_t *compiler, plv_decl_t *src, plc_var_type_t var_type,
    plv_collection_t *coll, word_t *word)
{
    plv_record_attr_t *src_attr = NULL;
    plv_object_attr_t *obj_attr = NULL;
    if (PLV_REC_EXIST_FIELD(src, var_type)) {
        uint16 id = 0;
        src_attr = udt_record_recurse_find_attr(compiler->stmt, &id, src->record, word);
        if (src_attr == NULL) {
            CT_SRC_THROW_ERROR(word->ex_words[id].text.loc, ERR_PL_REF_VARIABLE_FAILED,
                T2S(&word->ex_words[id].text.value));
            return CT_ERROR;
        }
        if (src_attr->type == UDT_SCALAR) {
            coll->attr_type = UDT_SCALAR;
            coll->type_mode = src_attr->scalar_field->type_mode;
        } else {
            CT_RETURN_IFERR(plc_copy_simple_coll_type(compiler, src_attr->udt_field, coll, word));
        }
    } else if (PLV_OBJ_EXIST_FIELD(src, var_type)) {
        uint16 id = 0;
        obj_attr = udt_object_recurse_find_attr(compiler->stmt, &id, src->object, word);
        if (obj_attr == NULL) {
            CT_SRC_THROW_ERROR(word->ex_words[id].text.loc, ERR_PL_REF_VARIABLE_FAILED,
                T2S(&word->ex_words[id].text.value));
            return CT_ERROR;
        }
        if (obj_attr->type == UDT_SCALAR) {
            coll->attr_type = UDT_SCALAR;
            coll->type_mode = obj_attr->scalar_field->type_mode;
        } else {
            CT_RETURN_IFERR(plc_copy_simple_coll_type(compiler, obj_attr->udt_field, coll, word));
        }
    } else {
        CT_RETURN_IFERR(plc_copy_simple_coll_type(compiler, src, coll, word));
    }

    return CT_SUCCESS;
}

static status_t plc_copy_variant_type(pl_compiler_t *compiler, plv_decl_t *src, plc_var_type_t var_type,
    plattr_assist_t *plattr_ass, word_t *word)
{
    // only db_table_or_view.column.
    if (src == NULL) {
        return plc_copy_table_column(compiler, word, plattr_ass);
    }

    switch (plattr_ass->type) {
        case REC_FIELD_INHERIT:
            return plc_copy_attr_type(compiler, src, var_type, plattr_ass->attr, word);

        case DECL_INHERIT:
            return plc_copy_decl_type(compiler, src, var_type, plattr_ass->decl, word);

        case COLL_ATTR_INHERIT:
            return plc_copy_coll_attr_type(compiler, src, var_type, plattr_ass->coll, word);
        default:
            CT_THROW_ERROR(ERR_PL_WRONG_TYPE_VALUE, "inherit type", plattr_ass->type);
            return CT_ERROR;
    }
}

status_t plc_copy_variant_rowtype(pl_compiler_t *compiler, plv_decl_t *src, plc_var_type_t var_type,
    plattr_assist_t *plattr_ass, word_t *word)
{
    plv_decl_t *rec_type = NULL;
    // only db_table_or_view.column.
    if (src == NULL) {
        return plc_copy_table(compiler, word, plattr_ass);
    }

    /* { explicit_cursor | db_table_or_view } %rowtype */
    switch (src->type) {
        case PLV_CUR:
            if (src->cursor.ctx != NULL && src->cursor.ctx->is_sysref) {
                CT_SRC_THROW_ERROR(word->loc, ERR_PL_SYNTAX_ERROR_FMT,
                    "the declaration of the type of this expression is incomplete or malformed");
                return CT_ERROR;
            }
            if (src->cursor.record == NULL) {
                galist_t *decls = plattr_ass->is_args ? compiler->type_decls : plattr_ass->decls;
                CT_RETURN_IFERR(cm_galist_new(decls, sizeof(plv_decl_t), (void **)&rec_type));
                rec_type->type = PLV_TYPE;
                rec_type->typdef.type = PLV_RECORD;
                rec_type->typdef.record.root = (void *)rec_type;
                rec_type->typdef.record.is_anonymous = CT_TRUE;
                src->cursor.record = &rec_type->typdef.record;
                rec_type->vid.block = (int16)compiler->stack.depth;
                rec_type->vid.id = decls->count - 1;
            }
            switch (plattr_ass->type) {
                case REC_FIELD_INHERIT:
                    plattr_ass->attr->type = (int8)UDT_RECORD;
                    plattr_ass->attr->udt_field = src->cursor.record->root;
                    break;
                case DECL_INHERIT:
                    plattr_ass->decl->type = PLV_RECORD;
                    plattr_ass->decl->record = src->cursor.record;
                    break;
                case COLL_ATTR_INHERIT:
                    plattr_ass->coll->attr_type = (uint8)UDT_RECORD;
                    plattr_ass->coll->elmt_type = src->cursor.record->root;
                    break;
                default:
                    CT_THROW_ERROR(ERR_PL_WRONG_TYPE_VALUE, "inherit type", plattr_ass->type);
                    return CT_ERROR;
            }

            return CT_SUCCESS;

        default: // PLV_RECORD PLV_VAR PLV_TYPE
            CT_SRC_THROW_ERROR(word->loc, ERR_PL_ATTR_ROWTYPE_FMT, W2S(word));
            return CT_ERROR;
    }
}

static status_t plc_parse_copy_type(pl_compiler_t *compiler, word_t *word, plv_cur_rowtype_t *type)
{
    text_t type_word;

    if ((word->ex_count == 0) || word->ex_count > MAX_EXTRA_TEXTS) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "word->ex_count(%u) > 0 && word->ex_count <= MAX_EXTRA_TEXTS(%u)",
            word->ex_count, (uint32)MAX_EXTRA_TEXTS);
        return CT_ERROR;
    }

    type_word = word->ex_words[word->ex_count - 1].text.value; // not overflow
    if (word->id == PL_ATTR_WORD_TYPE) {
        *type = PLV_CUR_TYPE;
    } else if (word->id == PL_ATTR_WORD_ROWTYPE) {
        *type = PLV_CUR_ROWTYPE;
    } else {
        *type = PLV_CUR_UNKNOWN;
        CT_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, "TYPE or ROWTYPE", T2S(&type_word));
        return CT_ERROR;
    }

    word->ex_count--;
    return CT_SUCCESS;
}

/*
 * @brief    enter for support %type or %rowtype
 */
static status_t plc_copy_variant_attr(pl_compiler_t *compiler, word_t *word, plattr_assist_t *plattr_ass)
{
    plv_cur_rowtype_t r_type;
    plv_decl_t *decl = NULL;
    plc_var_type_t var_type;
    CT_RETURN_IFERR(plc_parse_copy_type(compiler, word, &r_type));
    // search and then return db_table_or_view.column.
    CT_RETURN_IFERR(plc_verify_word_as_var(compiler, word));
    plc_find_decl_ex(compiler, word, PLV_VARIANT_AND_CUR, &var_type, &decl);

    if (r_type == PLV_CUR_TYPE) {
        // support COLLECTION VARIABLE OR CURSOR VARIABLE OR DB_TABLE_OR_VIEW.COLUMN OR RECORD VARIABLE [. FIELD] or
        // OR OBJECT VARIABLE [. FIELD] OR SCALAR, but coll(index)%type is prohibit.
        return plc_copy_variant_type(compiler, decl, var_type, plattr_ass, word);
    } else {
        // support EXPLICIT CURSOR or DB_TABLE_OR_VIEW
        return plc_copy_variant_rowtype(compiler, decl, var_type, plattr_ass, word);
    }
}

/*
 * @brief search variant in the block and top decls(not push in block yet), if it's a user define type then compile it
 */
static status_t plc_try_compile_local_type(pl_compiler_t *compiler, word_t *word, plv_decl_t *decl, bool32 *result)
{
    plv_decl_t *type_recur = NULL;

    CT_RETURN_IFERR(plc_verify_word_as_var(compiler, word));
    plc_find_decl_ex(compiler, word, PLV_TYPE, NULL, &type_recur);
    if (type_recur != NULL) {
        decl->type = type_recur->typdef.type;
        CT_RETURN_IFERR(plc_compile_complex_type(compiler, decl, type_recur));
        *result = CT_TRUE;
    } else {
        *result = CT_FALSE;
    }
    return CT_SUCCESS;
}

static inline plv_object_t *plc_get_object_def(pl_dc_t *type_dc)
{
    return &type_dc->entity->type_spec->decl->typdef.object;
}

static inline plv_collection_t *plc_get_global_collection_def(pl_dc_t *type_dc)
{
    return &type_dc->entity->type_spec->decl->typdef.collection;
}

status_t plc_try_compile_global_type(pl_compiler_t *compiler, word_t *word, plv_decl_t *decl, bool32 *result)
{
    var_udo_t obj;
    char user[CT_NAME_BUFFER_SIZE] = { 0 };
    char pack[CT_NAME_BUFFER_SIZE] = { 0 };
    char name[CT_NAME_BUFFER_SIZE] = { 0 };
    pl_dc_t type_dc = { 0 };
    bool32 found = CT_FALSE;

    plc_try_verify_word_as_var(word, result);
    if (!(*result)) {
        return CT_SUCCESS;
    }
    sql_init_udo_with_str(&obj, user, pack, name);
    plm_parse_name_by_copy(compiler->stmt, word, &obj);

    if (pl_try_find_type_dc(compiler->stmt, &obj, &type_dc, &found) != CT_SUCCESS) {
        pl_check_and_set_loc(word->loc);
        return CT_ERROR;
    }
    if (!found) {
        *result = CT_FALSE;
        return CT_SUCCESS;
    }

    decl->type = type_dc.entity->type_spec->decl->typdef.type;
    if (decl->type == PLV_OBJECT) {
        decl->object = plc_get_object_def(&type_dc);
    } else {
        decl->collection = plc_get_global_collection_def(&type_dc);
    }
    *result = CT_TRUE;
    return CT_SUCCESS;
}

/*
 * @brief    compile variant define
 */
status_t plc_compile_variant_def(pl_compiler_t *compiler, word_t *word, plv_decl_t *decl, bool32 is_arg,
    galist_t *decls, bool32 need_check)
{
    pl_entity_t *pl_entity = compiler->entity;
    lex_t *lex = compiler->stmt->session->lex;
    uint32 save_flags = lex->flags;
    bool32 result = CT_FALSE;

    if (!is_arg) {
        /*
         * If the text is dq_string, the dest string should the same with the source.
         * Otherwise, the dest string in upper mode.
         */
        if (!IS_VARIANT(word)) {
            CT_SRC_THROW_ERROR(word->text.loc, ERR_PL_EXPECTED_FAIL_FMT, "variant name", W2S(word));
            return CT_ERROR;
        }
        CT_RETURN_IFERR(pl_copy_object_name_ci(pl_entity, word->type, (text_t *)&word->text, &decl->name));
    }

    LEX_SAVE(lex);
    lex->flags = LEX_WITH_OWNER;
    CT_RETURN_IFERR(lex_fetch(lex, word));
    lex->flags = save_flags;

    // 1) check if %type or %rowtype
    if (word->type == WORD_TYPE_PL_ATTR) {
        plattr_assist_t plattr_ass;
        plattr_ass.type = DECL_INHERIT;
        plattr_ass.decl = decl;
        plattr_ass.decls = decls;
        plattr_ass.is_args = CT_TRUE;
        CT_RETURN_IFERR(plc_copy_variant_attr(compiler, word, &plattr_ass));
        return plc_check_decl_datatype(compiler, decl, is_arg);
    }

    // 2) check userdef type in block
    CT_RETURN_IFERR(plc_try_compile_local_type(compiler, word, decl, &result));
    if (result) {
        return CT_SUCCESS;
    }

    // 3) check userdef global type
    CT_RETURN_IFERR(plc_try_compile_global_type(compiler, word, decl, &result));
    if (result) {
        return CT_SUCCESS;
    }

    // 4) check if datatype
    decl->type = PLV_VAR;
    lex->flags = LEX_WITH_ARG;
    LEX_RESTORE(lex);

    if (plc_parse_datatype(lex, PLC_PMODE(decl->drct), &decl->variant.type, NULL) != CT_SUCCESS) {
        lex->flags = save_flags;
        return CT_ERROR;
    }

    if (need_check) {
        CT_RETURN_IFERR(plc_check_datatype(compiler, &decl->variant.type, is_arg));
    }
    if (decl->variant.type.is_array) {
        decl->type = PLV_ARRAY;
    }
    lex->flags = save_flags;

    return CT_SUCCESS;
}

static status_t plc_compile_record_def_datatype(pl_compiler_t *compiler, lex_t *lex, word_t *word)
{
    bool32 is_found = CT_FALSE;
    key_word_t *save_key_words = lex->key_words;
    uint32 save_key_word_count = lex->key_word_count;
    key_word_t key_words[] = {
        { (uint32)DTYP_PLS_INTEGER, CT_FALSE, { (char *)"pls_integer", 11 } },
        { (uint32)DTYP_STRING, CT_FALSE, { (char *)"string", 6 } }
    };

    lex->key_words = key_words;
    lex->key_word_count = ELEMENT_COUNT(key_words);

    LEX_SAVE(lex);
    if (lex_try_fetch_datatype(lex, word, &is_found) != CT_SUCCESS || !is_found) {
        LEX_RESTORE(lex);
        if (lex_expected_fetch(lex, word) != CT_SUCCESS) {
            lex->key_words = save_key_words;
            lex->key_word_count = save_key_word_count;
            return CT_ERROR;
        }
    }
    lex->key_words = save_key_words;
    lex->key_word_count = save_key_word_count;
    return CT_SUCCESS;
}

status_t plc_check_attr_duplicate(pl_compiler_t *compiler, plv_record_t *record, word_t *word)
{
    plv_record_attr_t *attr =
        udt_seek_field_by_name(compiler->stmt, record, &word->text, IS_DQ_STRING(word->type) || !IS_CASE_INSENSITIVE);
    if (attr != NULL) {
        CT_SRC_THROW_ERROR(word->loc, ERR_DUPLICATE_NAME, "attribute", T2S((text_t *)&word->text));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t plc_compile_attr_options(pl_compiler_t *compiler, word_t *word, expr_tree_t **def_expr, bool8 *null)
{
    bool32 result, id, nullable;
    expr_tree_t *default_expr = NULL;
    lex_t *lex = compiler->stmt->session->lex;
    CT_RETURN_IFERR(lex_try_fetch(lex, "NOT", &result));

    if (result) {
        CT_RETURN_IFERR(lex_expected_fetch_word(lex, "NULL"));
        nullable = CT_FALSE;
    } else {
        nullable = CT_TRUE;
    }

    CT_RETURN_IFERR(lex_try_fetch_1of2(lex, ":=", "DEFAULT", &id));
    if (id == CT_INVALID_ID32) {
        if (!nullable) {
            CT_SRC_THROW_ERROR(word->loc, ERR_INVALID_DATA_TYPE,
                "type defining, not null declaration must have default value");
            return CT_ERROR;
        }
        return CT_SUCCESS;
    } else if (compiler->type == PL_TYPE_SPEC) {
        CT_SRC_THROW_ERROR(word->loc, ERR_INVALID_DATA_TYPE,
            "type defining, object attribute must not have default value");
        return CT_ERROR;
    }

    PLC_RESET_WORD_LOC(lex, word);
    CT_RETURN_IFERR(lex_try_fetch(lex, "PRIOR", &result));
    if (result) {
        CT_SRC_THROW_ERROR(word->loc, ERR_PLSQL_ILLEGAL_LINE_FMT,
            "function or pseudo-column 'PRIOR' may be used inside a SQL statement");
        return CT_ERROR;
    }

    if (sql_create_expr_until(compiler->stmt, &default_expr, word) != CT_SUCCESS) {
        pl_check_and_set_loc(word->loc);
        return CT_ERROR;
    }
    CT_RETURN_IFERR(plc_verify_expr(compiler, default_expr));
    CT_RETURN_IFERR(plc_clone_expr_tree(compiler, &default_expr));
    if (word->type == WORD_TYPE_SPEC_CHAR) {
        lex_back(lex, word);
    }

    *def_expr = default_expr;
    *null = nullable;
    return CT_SUCCESS;
}

status_t plc_compile_scalar_attr(pl_compiler_t *compiler, word_t *word, plv_record_attr_t *attr)
{
    attr->type = UDT_SCALAR;
    lex_t *lex = compiler->stmt->session->lex;
    pl_entity_t *pl_entity = compiler->entity;
    CT_RETURN_IFERR(pl_alloc_mem(pl_entity, sizeof(field_scalar_info_t), (void **)&attr->scalar_field));
    CT_RETURN_IFERR(sql_parse_datatype_typemode(lex, PM_NORMAL, &attr->scalar_field->type_mode, NULL, word));
    return plc_compile_attr_options(compiler, word, &attr->default_expr, &attr->nullable);
}

status_t plc_compile_global_udt_attr(pl_compiler_t *compiler, word_t *word, plv_decl_t **udt_fld, int8 *type)
{
    var_udo_t obj;
    char user[CT_NAME_BUFFER_SIZE] = { 0 };
    char pack[CT_NAME_BUFFER_SIZE] = { 0 };
    char name[CT_NAME_BUFFER_SIZE] = { 0 };
    pl_dc_t dc = { 0 };
    bool32 found = CT_FALSE;

    CT_RETURN_IFERR(plc_verify_word_as_var(compiler, word));
    sql_init_udo_with_str(&obj, user, pack, name);
    plm_parse_name_by_copy(compiler->stmt, word, &obj);

    if (pl_try_find_type_dc(compiler->stmt, &obj, &dc, &found) != CT_SUCCESS) {
        pl_check_and_set_loc(word->loc);
        return CT_ERROR;
    }

    if (!found) {
        if (pl_unfound_error(compiler->stmt, &obj, NULL, PL_TYPE_SPEC) != CT_SUCCESS) {
            pl_check_and_set_loc(word->loc);
            return CT_ERROR;
        }
        return CT_SUCCESS;
    }

    *udt_fld = dc.entity->type_spec->decl;
    switch (dc.entity->type_spec->decl->typdef.type) {
        case PLV_OBJECT:
            *type = UDT_OBJECT;
            break;
        case PLV_COLLECTION:
            *type = UDT_COLLECTION;
            break;
        default:
            break;
    }
    return CT_SUCCESS;
}

static status_t plc_try_compile_local_udt_attr(pl_compiler_t *compiler, word_t *word, plv_record_attr_t *attr,
    bool32 *result)
{
    plv_decl_t *decl = NULL;

    plc_find_decl_ex(compiler, word, PLV_TYPE, NULL, &decl);
    if (decl == NULL) {
        *result = CT_FALSE;
        return CT_SUCCESS;
    }

    *result = CT_TRUE;
    attr->udt_field = decl;
    if (decl->typdef.type == PLV_RECORD) {
        attr->type = UDT_RECORD;
        return CT_SUCCESS;
    } else if (decl->typdef.type == PLV_COLLECTION) {
        attr->type = UDT_COLLECTION;
        return CT_SUCCESS;
    }

    CT_SRC_THROW_ERROR(word->loc, ERR_UNEXPECTED_PL_VARIANT);
    return CT_ERROR;
}

/*
 * @brief  compiler phase to find decl which type is PLV_TYPE
 */
static status_t plc_compile_udt_type_attr(pl_compiler_t *compiler, word_t *word, plv_record_attr_t *attr)
{
    bool32 result = CT_FALSE;
    CT_RETURN_IFERR(plc_try_compile_local_udt_attr(compiler, word, attr, &result));
    if (result) {
        return CT_SUCCESS;
    }

    return plc_compile_global_udt_attr(compiler, word, &attr->udt_field, &attr->type);
}

static status_t plc_compile_record_def(pl_compiler_t *compiler, galist_t *decls, plv_decl_t *decl, word_t *word)
{
    plattr_assist_t plattr_ass;
    plv_record_attr_t *attr = NULL;
    lex_t *lex = compiler->stmt->session->lex;
    pl_entity_t *pl_entity = compiler->entity;
    bool32 result = CT_FALSE;

    for (;;) {
        CT_RETURN_IFERR(lex_fetch(lex, word));
        CT_RETURN_IFERR(plc_check_attr_duplicate(compiler, &decl->typdef.record, word));

        attr = udt_record_alloc_attr((void *)pl_entity, &decl->typdef.record);
        if (attr == NULL) {
            pl_check_and_set_loc(word->loc);
            return CT_ERROR;
        }
        CT_RETURN_IFERR(pl_copy_object_name_ci(pl_entity, word->type, (text_t *)&word->text, &attr->name));

        lex->flags = LEX_WITH_OWNER | LEX_WITH_ARG;
        if (plc_compile_record_def_datatype(compiler, lex, word) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (word->type == WORD_TYPE_DATATYPE) {
            CT_RETURN_IFERR(plc_compile_scalar_attr(compiler, word, attr));
            PLC_UDT_IS_ARRAY(attr->scalar_field->type_mode, word);
            CT_RETURN_IFERR(plc_check_datatype(compiler, &attr->scalar_field->type_mode, CT_FALSE));
        } else if (word->type == WORD_TYPE_VARIANT) {
            CT_RETURN_IFERR(plc_compile_udt_type_attr(compiler, word, attr));
            CT_RETURN_IFERR(plc_compile_attr_options(compiler, word, &attr->default_expr, &attr->nullable));
        } else if (word->type == WORD_TYPE_PL_ATTR) {
            plattr_ass.type = REC_FIELD_INHERIT;
            plattr_ass.attr = attr;
            plattr_ass.decls = decls;
            plattr_ass.is_args = CT_FALSE;
            CT_RETURN_IFERR(plc_copy_variant_attr(compiler, word, &plattr_ass));
            PLC_UDT_IS_ARRAY(attr->scalar_field->type_mode, word);
            CT_RETURN_IFERR(plc_compile_attr_options(compiler, word, &attr->default_expr, &attr->nullable));
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

static status_t plc_compile_type_record_def(pl_compiler_t *compiler, plv_decl_t *decl, galist_t *decls, word_t *word)
{
    lex_t *lex = compiler->stmt->session->lex;
    bool32 result = CT_FALSE;
    decl->typdef.type = PLV_RECORD;
    decl->typdef.record.root = decl;
    decl->typdef.record.is_anonymous = CT_FALSE;
    CT_RETURN_IFERR(lex_try_fetch_bracket(lex, word, &result));
    if (!result) {
        CT_SRC_THROW_ERROR(lex->loc, ERR_PL_SYNTAX_ERROR_FMT, "record need declare element");
        return CT_ERROR;
    }
    lex_trim(&word->text);
    if (word->text.len == 0) {
        CT_SRC_THROW_ERROR(lex->loc, ERR_PL_SYNTAX_ERROR_FMT, "record need declare element");
        return CT_ERROR;
    }
    CT_RETURN_IFERR(lex_push(lex, &word->text));
    if (plc_compile_record_def(compiler, decls, decl, word) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }
    lex_pop(lex);

    return lex_expected_fetch_word(lex, ";");
}

static status_t plc_try_compile_local_collection(pl_compiler_t *compiler, word_t *word, plv_decl_t *decl,
    bool32 *res)
{
    plv_decl_t *type_recur = NULL;
    plc_find_decl_ex(compiler, word, PLV_TYPE, NULL, &type_recur);

    if (type_recur != NULL) {
        if (type_recur->typdef.type == PLV_COLLECTION) {
            decl->typdef.collection.attr_type = UDT_COLLECTION;
        } else if (type_recur->typdef.type == PLV_RECORD) {
            decl->typdef.collection.attr_type = UDT_RECORD;
        } else {
            CT_SRC_THROW_ERROR(word->loc, ERR_UNEXPECTED_PL_VARIANT);
            return CT_ERROR;
        }

        decl->typdef.collection.elmt_type = type_recur;
        *res = CT_TRUE;
    } else {
        *res = CT_FALSE;
    }
    return CT_SUCCESS;
}

static status_t plc_try_compile_global_collection(pl_compiler_t *compiler, word_t *word, plv_decl_t *decl,
    bool32 *res)
{
    var_udo_t obj;
    char user[CT_NAME_BUFFER_SIZE] = { 0 };
    char pack[CT_NAME_BUFFER_SIZE] = { 0 };
    char name[CT_NAME_BUFFER_SIZE] = { 0 };
    pl_dc_t type_dc = { 0 };
    bool32 found = CT_FALSE;
    plv_decl_t *type_recur = NULL;

    plc_try_verify_word_as_var(word, res);
    if (!(*res)) {
        return CT_SUCCESS;
    }
    sql_init_udo_with_str(&obj, user, pack, name);
    plm_parse_name_by_copy(compiler->stmt, word, &obj);

    if (pl_try_find_type_dc(compiler->stmt, &obj, &type_dc, &found) != CT_SUCCESS) {
        pl_check_and_set_loc(word->loc);
        return CT_ERROR;
    }
    if (!found) {
        *res = CT_FALSE;
        return CT_SUCCESS;
    }
    type_recur = type_dc.entity->type_spec->decl;
    if (type_recur->typdef.type == PLV_COLLECTION) {
        decl->typdef.collection.attr_type = UDT_COLLECTION;
    } else {
        decl->typdef.collection.attr_type = UDT_OBJECT;
    }
    decl->typdef.collection.elmt_type = type_recur;
    *res = CT_TRUE;
    return CT_SUCCESS;
}

static status_t plc_compile_type_member(pl_compiler_t *compiler, galist_t *decls, plv_decl_t *decl, word_t *word)
{
    lex_t *lex = compiler->stmt->session->lex;
    uint32 save_flags = lex->flags;
    bool32 res = CT_FALSE;

    LEX_SAVE(lex);
    lex->flags = LEX_WITH_OWNER;
    CT_RETURN_IFERR(lex_fetch(lex, word));
    lex->flags = save_flags;

    // 1) check if %type or %rowtype
    if (word->type == WORD_TYPE_PL_ATTR) {
        plattr_assist_t plattr_ass;
        plattr_ass.type = COLL_ATTR_INHERIT;
        plattr_ass.decls = decls;
        plattr_ass.coll = &decl->typdef.collection;
        plattr_ass.is_args = CT_FALSE;
        CT_RETURN_IFERR(plc_copy_variant_attr(compiler, word, &plattr_ass));
        PLC_UDT_IS_ARRAY(decl->typdef.collection.type_mode, word);
        return plc_check_decl_datatype(compiler, decl, CT_FALSE);
    }

    if (word->type != WORD_TYPE_DATATYPE) {
        // 2) check userdef type in block
        CT_RETURN_IFERR(plc_try_compile_local_collection(compiler, word, decl, &res));
        if (res) {
            return CT_SUCCESS;
        }

        // 3) check userdef global type
        CT_RETURN_IFERR(plc_try_compile_global_collection(compiler, word, decl, &res));
        if (res) {
            return CT_SUCCESS;
        }
    }

    // 4) check if datatype
    decl->typdef.collection.attr_type = UDT_SCALAR;
    lex->flags = LEX_WITH_ARG;
    LEX_RESTORE(lex);
    if (plc_parse_datatype(lex, PM_PL_VAR, &decl->typdef.collection.type_mode, NULL) != CT_SUCCESS) {
        lex->flags = save_flags;
        return CT_ERROR;
    }
    PLC_UDT_IS_ARRAY(decl->typdef.collection.type_mode, word);
    CT_RETURN_IFERR(plc_check_datatype(compiler, &decl->typdef.collection.type_mode, CT_FALSE));
    lex->flags = save_flags;
    return CT_SUCCESS;
}

static status_t plc_compile_type_collection(pl_compiler_t *compiler, plv_decl_t *decl, galist_t *decls, word_t *word)
{
    decl->typdef.type = PLV_COLLECTION;
    decl->typdef.collection.type = UDT_NESTED_TABLE;
    decl->typdef.collection.limit = 0;
    decl->typdef.collection.root = decl;

    return plc_compile_type_member(compiler, decls, decl, word);
}

static status_t plc_copy_index_attr(pl_compiler_t *compiler, word_t *word, plattr_assist_t *plattr_ass)
{
    lex_t *lex = compiler->stmt->session->lex;
    plv_cur_rowtype_t r_type;
    plv_decl_t *decl = NULL;
    plc_var_type_t var_type;
    CT_RETURN_IFERR(plc_parse_copy_type(compiler, word, &r_type));
    // search and then return db_table_or_view.column.
    CT_RETURN_IFERR(plc_verify_word_as_var(compiler, word));
    plc_find_decl_ex(compiler, word, PLV_VARIANT_AND_CUR, &var_type, &decl);

    if (r_type == PLV_CUR_TYPE) {
        // support COLLECTION VARIABLE OR CURSOR VARIABLE OR DB_TABLE_OR_VIEW.COLUMN OR RECORD VARIABLE [. FIELD] or
        // SCALAR, coll(0)%type is prohibit
        return plc_copy_variant_type(compiler, decl, var_type, plattr_ass, word);
    } else {
        CT_SRC_THROW_ERROR(lex->loc, ERR_PL_HSTB_INDEX_TYPE);
        return CT_ERROR;
    }
}

static status_t plc_try_compile_index_datatype(pl_compiler_t *compiler, plv_decl_t *decl, galist_t *decls, word_t *word)
{
    lex_t *lex = compiler->stmt->session->lex;
    uint32 save_flags = lex->flags;
    bool32 res = CT_FALSE;

    LEX_SAVE(lex);
    lex->flags = LEX_WITH_OWNER;
    CT_RETURN_IFERR(lex_fetch(lex, word));
    lex->flags = save_flags;

    // index supports %type
    if (word->type == WORD_TYPE_PL_ATTR) {
        plv_collection_t collection;
        plattr_assist_t plattr_ass;
        plattr_ass.type = COLL_ATTR_INHERIT;
        plattr_ass.decls = decls;
        plattr_ass.coll = &collection;
        plattr_ass.is_args = CT_FALSE;
        CT_RETURN_IFERR(plc_copy_index_attr(compiler, word, &plattr_ass));
        decl->typdef.collection.index_typmod = plattr_ass.coll->type_mode;
    } else {
        // 2) check userdef type in block
        CT_RETURN_IFERR(plc_try_compile_local_collection(compiler, word, decl, &res));
        if (res) {
            CT_SRC_THROW_ERROR(lex->loc, ERR_PL_HSTB_INDEX_TYPE);
            return CT_ERROR;
        }

        // 3) check userdef global type
        CT_RETURN_IFERR(plc_try_compile_global_collection(compiler, word, decl, &res));
        if (res) {
            CT_SRC_THROW_ERROR(lex->loc, ERR_PL_HSTB_INDEX_TYPE);
            return CT_ERROR;
        }

        // 4) check if datatype
        lex->flags = LEX_WITH_ARG;
        LEX_RESTORE(lex);
        if (plc_parse_datatype(lex, PM_PL_VAR, &decl->typdef.collection.index_typmod, NULL) != CT_SUCCESS) {
            lex->flags = save_flags;
            return CT_ERROR;
        }

        CT_RETURN_IFERR(plc_check_datatype(compiler, &decl->typdef.collection.index_typmod, CT_FALSE));
        lex->flags = save_flags;
    }

    if (decl->typdef.collection.index_typmod.datatype != CT_TYPE_INTEGER &&
        decl->typdef.collection.index_typmod.datatype != CT_TYPE_VARCHAR) {
        CT_SRC_THROW_ERROR(lex->loc, ERR_PL_HSTB_INDEX_TYPE);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t plc_try_compile_type_index(pl_compiler_t *compiler, plv_decl_t *decl, galist_t *decls, word_t *word)
{
    bool32 res = CT_FALSE;
    lex_t *lex = compiler->stmt->session->lex;
    CT_RETURN_IFERR(lex_try_fetch(lex, "INDEX", &res));
    if (!res) {
        return lex_expected_fetch_word(lex, ";");
    }

    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "BY"));
    decl->typdef.collection.type = UDT_HASH_TABLE;
    CT_RETURN_IFERR(plc_try_compile_index_datatype(compiler, decl, decls, word));
    return lex_expected_fetch_word(lex, ";");
}

status_t plc_check_array_element_size(pl_compiler_t *compiler, plv_decl_t *decl)
{
    lex_t *lex = compiler->stmt->session->lex;
    if (decl->typdef.collection.limit > MAX_ARRAY_ELEMENT_SIZE) {
        CT_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "The number %u reached the upper limit of %s %u.",
            decl->typdef.collection.limit, "max varray element size", MAX_ARRAY_ELEMENT_SIZE);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t plc_compile_type_varray(pl_compiler_t *compiler, plv_decl_t *decl, galist_t *decls, word_t *word)
{
    lex_t *lex = compiler->stmt->session->lex;
    decl->typdef.type = PLV_COLLECTION;
    decl->typdef.collection.root = decl;
    decl->typdef.collection.type = UDT_VARRAY;
    CT_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    CT_RETURN_IFERR(cm_text2uint32(&word->text.value, &decl->typdef.collection.limit));
    CT_RETURN_IFERR(plc_check_array_element_size(compiler, decl));
    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "OF"));

    CT_RETURN_IFERR(plc_compile_type_member(compiler, decls, decl, word));
    return lex_expected_fetch_word(lex, ";");
}

static status_t plc_check_type_name(pl_compiler_t *compiler, galist_t *decls, word_t *word)
{
    bool32 res = CT_FALSE;
    lex_t *lex = compiler->stmt->session->lex;
    plc_check_duplicate(decls, (text_t *)&word->text, IS_DQ_STRING(word->type), &res);

    if (res) {
        CT_SRC_THROW_ERROR(word->loc, ERR_DUPLICATE_NAME, "type", T2S((text_t *)&word->text));
        return CT_ERROR;
    }

    if (lex_check_datatype(lex, word)) {
        CT_SRC_THROW_ERROR(word->loc, ERR_PL_SYNTAX_ERROR_FMT, "illegal use of a type before its declaration");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t plc_compile_type_def(pl_compiler_t *compiler, galist_t *decls, word_t *word)
{
    uint32 matched_id;
    plv_decl_t *decl = NULL;
    lex_t *lex = compiler->stmt->session->lex;
    pl_entity_t *pl_entity = compiler->entity;

    CT_RETURN_IFERR(lex_fetch(lex, word));
    CT_RETURN_IFERR(plc_check_type_name(compiler, decls, word));
    CT_RETURN_IFERR(cm_galist_new(decls, sizeof(plv_decl_t), (void **)&decl));
    CT_RETURN_IFERR(pl_copy_object_name_ci(pl_entity, word->type, (text_t *)&word->text, &decl->name));
    decl->vid.block = (int16)compiler->stack.depth;
    decl->vid.id = decls->count - 1; // not overflow
    decl->type = PLV_TYPE;
    decl->loc = word->loc;

    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "IS"));
    CT_RETURN_IFERR(lex_try_fetch_1ofn(lex, &matched_id, 4, "RECORD", "REF", "VARRAY", "TABLE"));

    switch (matched_id) {
        case MATCH_RECORD:
            return plc_compile_type_record_def(compiler, decl, decls, word);
        case MATCH_REF:
            CT_RETURN_IFERR(lex_expected_fetch_word(lex, "CURSOR"));
            return plc_compile_type_refcur_def(compiler, decl, decls, word);
        case MATCH_VARRAY:
            return plc_compile_type_varray(compiler, decl, decls, word);
        case MATCH_TABLE:
            CT_RETURN_IFERR(lex_expected_fetch_word(lex, "OF"));
            CT_RETURN_IFERR(plc_compile_type_collection(compiler, decl, decls, word));
            return plc_try_compile_type_index(compiler, decl, decls, word);
        default:
            CT_SRC_THROW_ERROR(lex->loc, ERR_PL_UNSUPPORT);
            return CT_ERROR;
    }
}

status_t plc_compile_global_type_member(pl_compiler_t *compiler, plv_decl_t *decl, word_t *word)
{
    lex_t *lex = compiler->stmt->session->lex;
    uint32 save_flags = lex->flags;
    bool32 res = CT_FALSE;

    LEX_SAVE(lex);
    lex->flags = LEX_WITH_OWNER;
    CT_RETURN_IFERR(lex_fetch(lex, word));
    lex->flags = save_flags;

    // 1) check if %type or %rowtype
    if (word->type == WORD_TYPE_PL_ATTR) {
        plattr_assist_t plattr_ass;
        plattr_ass.type = COLL_ATTR_INHERIT;
        plattr_ass.coll = &decl->typdef.collection;
        plattr_ass.decls = NULL;
        plattr_ass.is_args = CT_TRUE;
        CT_RETURN_IFERR(plc_copy_variant_attr(compiler, word, &plattr_ass));
        PLC_UDT_IS_ARRAY(decl->typdef.collection.type_mode, word);
        return plc_check_decl_datatype(compiler, decl, CT_FALSE);
    }

    // 2) check userdef global type
    CT_RETURN_IFERR(plc_try_compile_global_collection(compiler, word, decl, &res));
    if (res) {
        return CT_SUCCESS;
    }

    // 3) check if datatype
    decl->typdef.collection.attr_type = UDT_SCALAR;
    lex->flags = LEX_WITH_ARG;
    LEX_RESTORE(lex);
    CT_RETURN_IFERR(sql_parse_datatype(lex, PM_PL_VAR, &decl->typdef.collection.type_mode, NULL));
    PLC_UDT_IS_ARRAY(decl->typdef.collection.type_mode, word);
    CT_RETURN_IFERR(plc_check_datatype(compiler, &decl->typdef.collection.type_mode, CT_FALSE));
    lex->flags = save_flags;
    return CT_SUCCESS;
}
