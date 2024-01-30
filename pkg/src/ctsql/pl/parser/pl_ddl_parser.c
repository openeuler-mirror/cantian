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
 * pl_ddl_parser.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/parser/pl_ddl_parser.c
 *
 * -------------------------------------------------------------------------
 */
#include "pl_ddl_parser.h"
#include "pl_compiler.h"
#include "srv_instance.h"
#include "ctsql_privilege.h"
#include "pl_meta_common.h"
#include "base_compiler.h"
#include "pl_memory.h"
#include "pl_common.h"
#include "dml_parser.h"


static status_t pl_try_parse_if_not_exists(sql_stmt_t *stmt, uint32 *matched)
{
    bool32 result = CT_FALSE;

    *matched = CT_FALSE;

    CT_RETURN_IFERR(lex_try_fetch(stmt->session->lex, "IF", &result));
    CT_RETSUC_IFTRUE(!result);

    CT_RETURN_IFERR(lex_expected_fetch_word(stmt->session->lex, "NOT"));
    CT_RETURN_IFERR(lex_expected_fetch_word(stmt->session->lex, "EXISTS"));

    *matched = CT_TRUE;
    return CT_SUCCESS;
}

static status_t pl_try_parse_if_exists(sql_stmt_t *stmt, uint32 *option)
{
    bool32 result = CT_FALSE;

    CT_RETURN_IFERR(lex_try_fetch(stmt->session->lex, "IF", &result));
    CT_RETSUC_IFTRUE(!result);

    CT_RETURN_IFERR(lex_expected_fetch_word(stmt->session->lex, "EXISTS"));

    *option |= DROP_IF_EXISTS;
    return CT_SUCCESS;
}

static status_t pl_record_source(sql_stmt_t *stmt, pl_entity_t *pl_ctx, text_t *source)
{
    knl_session_t *session = KNL_SESSION(stmt);

    knl_begin_session_wait(session, LARGE_POOL_ALLOC, CT_FALSE);
    if (mpool_alloc_page_wait(&g_instance->sga.large_pool, &pl_ctx->create_def->large_page_id,
        CM_MPOOL_ALLOC_WAIT_TIME) != CT_SUCCESS) {
        knl_end_session_wait(session, LARGE_POOL_ALLOC);
        return CT_ERROR;
    }
    knl_end_session_wait(session, LARGE_POOL_ALLOC);

    pl_ctx->create_def->source.len = 0;
    pl_ctx->create_def->source.str =
        mpool_page_addr(KNL_SESSION(stmt)->kernel->attr.large_pool, pl_ctx->create_def->large_page_id);
    CT_RETURN_IFERR(sql_text_concat_n_str(&pl_ctx->create_def->source, CT_LARGE_PAGE_SIZE, source->str, source->len));

    return CT_SUCCESS;
}

static status_t pl_diag_pacakge_type(sql_stmt_t *stmt, word_t *word, uint32 *type)
{
    bool32 is_body = CT_FALSE;

#ifdef Z_SHARDING
    if (IS_COORDINATOR && IS_APP_CONN(stmt->session)) {
        CT_THROW_ERROR(ERR_COORD_NOT_SUPPORT, "create package");
        return CT_ERROR;
    }
#endif
    if (lex_try_fetch(LEX(stmt), "body", &is_body) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (is_body) {
        stmt->context->type = CTSQL_TYPE_CREATE_PACK_BODY;
        *type = PL_PACKAGE_BODY;
    } else {
        stmt->context->type = CTSQL_TYPE_CREATE_PACK_SPEC;
        *type = PL_PACKAGE_SPEC;
    }

    return CT_SUCCESS;
}

static status_t pl_diag_udt_type(sql_stmt_t *stmt, word_t *word, uint32 *type)
{
    bool32 is_body = CT_FALSE;
#ifdef Z_SHARDING
    if (IS_COORDINATOR && IS_APP_CONN(stmt->session)) {
        CT_THROW_ERROR(ERR_COORD_NOT_SUPPORT, "create type");
        return CT_ERROR;
    }
#endif
    if (lex_try_fetch(LEX(stmt), "body", &is_body) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (is_body) {
        stmt->context->type = CTSQL_TYPE_CREATE_TYPE_BODY;
        *type = PL_TYPE_BODY;
        CT_SRC_THROW_ERROR(LEX(stmt)->loc, ERR_PL_UNSUPPORT);
        return CT_ERROR;
    } else {
        stmt->context->type = CTSQL_TYPE_CREATE_TYPE_SPEC;
        *type = PL_TYPE_SPEC;
    }

    return CT_SUCCESS;
}


status_t pl_diag_create_type(sql_stmt_t *stmt, word_t *word, uint32 *type)
{
    switch (word->id) {
        case KEY_WORD_PROCEDURE:
            stmt->context->type = CTSQL_TYPE_CREATE_PROC;
            *type = PL_PROCEDURE;
            break;

        case KEY_WORD_FUNCTION:
            stmt->context->type = CTSQL_TYPE_CREATE_FUNC;
            *type = PL_FUNCTION;
            break;

        case KEY_WORD_PACKAGE:
            CT_RETURN_IFERR(pl_diag_pacakge_type(stmt, word, type));
            break;
        case KEY_WORD_TYPE:
            CT_RETURN_IFERR(pl_diag_udt_type(stmt, word, type));
            break;

        default:
            CT_SRC_THROW_ERROR(word->loc, ERR_OPERATIONS_NOT_SUPPORT, "create", "unknown PLSQL type");
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t pl_verify_object_name(lex_t *lex)
{
    text_t *value = &lex->curr_text->value;

    for (uint32 loop = 0; loop < lex->curr_text->len; loop++) {
        if (value->str[loop] <= ' ' || value->str[loop] == '(' || value->str[loop] == ';' || value->str[loop] == ',') {
            return CT_SUCCESS;
        }
        if (CM_IS_QUOTE_CHAR(value->str[loop]) || value->str[loop] == '$') {
            continue;
        }

        if (is_nonnaming_char(value->str[loop])) {
            CT_SRC_THROW_ERROR_EX(lex->loc, ERR_PL_SYNTAX_ERROR_FMT,
                "Can not using this sepecial char '%c' as object name", value->str[loop]);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t pl_parse_name_direct(sql_stmt_t *stmt, word_t *word, var_udo_t *obj)
{
    sql_init_udo(obj);

    if (word->ex_count == 1) {
        CT_RETURN_IFERR(sql_copy_prefix_tenant(stmt, &word->text.value, &obj->user, sql_copy_name));
        CT_RETURN_IFERR(
            sql_copy_object_name(stmt->context, word->ex_words[0].type, &word->ex_words[0].text.value, &obj->name));
        if (IS_DQ_STRING(word->ex_words[0].type) || !IS_CASE_INSENSITIVE) {
            obj->name_sensitive = CT_TRUE;
        } else {
            obj->name_sensitive = CT_FALSE;
        }
        obj->user_explicit = CT_TRUE;
    } else {
        obj->user.str = stmt->session->curr_schema;
        obj->user.len = (uint32)strlen(stmt->session->curr_schema);
        CT_RETURN_IFERR(
            sql_copy_object_name(stmt->context, word->type | word->ori_type, &word->text.value, &obj->name));
        if (IS_DQ_STRING((uint32)(word->type) | (uint32)(word->ori_type)) || !IS_CASE_INSENSITIVE) {
            obj->name_sensitive = CT_TRUE;
        } else {
            obj->name_sensitive = CT_FALSE;
        }
        obj->user_explicit = CT_FALSE;
    }

    return CT_SUCCESS;
}

status_t pl_parse_name(sql_stmt_t *stmt, word_t *word, var_udo_t *obj, bool32 need_single)
{
    stmt->session->lex->flags = LEX_WITH_OWNER;
    CT_RETURN_IFERR(pl_verify_object_name(stmt->session->lex));
    CT_RETURN_IFERR(lex_expected_fetch_variant(stmt->session->lex, word));
    if (need_single && word->ex_count > 0) {
        CT_SRC_THROW_ERROR(word->loc, ERR_PL_SYNTAX_ERROR_FMT, "Unexpected the symbol '.' here");
        return CT_ERROR;
    }

    return pl_parse_name_direct(stmt, word, obj);
}

status_t pl_parse_drop_procedure(sql_stmt_t *stmt, word_t *word)
{
    pl_drop_def_t *drop_def = NULL;

    if (sql_alloc_mem(stmt->context, sizeof(pl_drop_def_t), (void **)&drop_def)) {
        return CT_ERROR;
    }

    if (word->id == KEY_WORD_FUNCTION) {
        stmt->context->type = CTSQL_TYPE_DROP_FUNC;
        drop_def->type = PL_FUNCTION;
    } else {
        stmt->context->type = CTSQL_TYPE_DROP_PROC;
        drop_def->type = PL_PROCEDURE;
    }

    CT_RETURN_IFERR(pl_try_parse_if_exists(stmt, &drop_def->option));
    CT_RETURN_IFERR(pl_parse_name(stmt, word, &drop_def->obj, CT_FALSE));
    CT_RETURN_IFERR(lex_expected_end(stmt->session->lex));

    stmt->context->entry = drop_def;
    return CT_SUCCESS;
}

status_t pl_parse_drop_trigger(sql_stmt_t *stmt, word_t *word)
{
    pl_drop_def_t *drop_def = NULL;

    if (sql_alloc_mem(stmt->context, sizeof(pl_drop_def_t), (void **)&drop_def)) {
        return CT_ERROR;
    }
    stmt->context->type = CTSQL_TYPE_DROP_TRIG;
    drop_def->type = PL_TRIGGER;
    CT_RETURN_IFERR(pl_try_parse_if_exists(stmt, &drop_def->option));
    CT_RETURN_IFERR(pl_parse_name(stmt, word, &drop_def->obj, CT_FALSE));
    CT_RETURN_IFERR(lex_expected_end(stmt->session->lex));

    stmt->context->entry = drop_def;
    return CT_SUCCESS;
}

static void pl_prepare_compile_desc(plc_desc_t *desc, sql_stmt_t *stmt, var_udo_t *obj, pl_type_t type)
{
    desc->proc_oid = CT_INVALID_INT64;
    desc->type = type;
    desc->obj = obj;
    desc->source_pages.curr_page_id = CT_INVALID_ID32;
    desc->source_pages.curr_page_pos = 0;
    desc->is_synonym = CT_FALSE;
    desc->entity = (pl_entity_t *)stmt->pl_context;
}

status_t pl_parse_create_core(sql_stmt_t *stmt, word_t *word, var_udo_t *obj, uint32 type)
{
    plc_desc_t desc = { 0 };
    status_t compl_ret;
    pl_entity_t *pl_ctx = stmt->pl_context;

    text_t source = stmt->session->lex->curr_text->value;

    pl_prepare_compile_desc(&desc, stmt, obj, type);
    compl_ret = plc_compile(stmt, &desc, word);
    if (compl_ret != CT_SUCCESS) {
        stmt->pl_failed = CT_TRUE;
        pl_ctx->create_def->compl_result = CT_FALSE;
    } else {
        cm_reset_error();
        pl_ctx->create_def->compl_result = CT_TRUE;
    }

    return pl_record_source(stmt, pl_ctx, &source);
}

static status_t pl_check_packname_validity(var_udo_t *obj, uint32 type)
{
    if ((type == PL_PACKAGE_SPEC || type == PL_PACKAGE_BODY) && cm_text_equal_ins(&obj->user, &obj->name)) {
        CT_THROW_ERROR(ERR_OBJECT_EXISTS, "creating a package with the same name under the user is not supported, user",
            T2S(&obj->user));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t pl_parse_create(sql_stmt_t *stmt, bool32 replace, word_t *word)
{
    bool32 clause_matched = CT_FALSE;
    uint16 create_option = 0;
    uint32 type;
    pl_entity_t *pl_ctx = NULL;

    CM_ASSERT(stmt->pl_context == NULL);
    CT_RETURN_IFERR(pl_alloc_context(&pl_ctx, stmt->context));
    SET_STMT_PL_CONTEXT(stmt, pl_ctx);

    SQL_SET_IGNORE_PWD(stmt->session);
    SQL_SET_COPY_LOG(stmt->session, CT_TRUE);

    CT_RETURN_IFERR(pl_diag_create_type(stmt, word, &type));
    CT_RETURN_IFERR(pl_try_parse_if_not_exists(stmt, &clause_matched));
    CT_RETURN_IFERR(pl_parse_name(stmt, word, &pl_ctx->def, CT_FALSE));
    CT_RETURN_IFERR(pl_check_packname_validity(&pl_ctx->def, type));

    if (clause_matched) {
        create_option |= CREATE_IF_NOT_EXISTS;
    }

    if (replace) {
        create_option |= CREATE_OR_REPLACE;
    }

    if (type == PL_TYPE_SPEC) {
        bool32 is_found = CT_FALSE;
        CT_RETURN_IFERR(lex_try_fetch(stmt->session->lex, "FORCE", &is_found));
        if (is_found) {
            create_option |= CREATE_TYPE_FORCE;
        }
    }

    pl_ctx->create_def->create_option = create_option;
    pl_ctx->pl_type = type;

    return pl_parse_create_core(stmt, word, &pl_ctx->def, type);
}

static status_t pl_check_trigger_create_priv(sql_stmt_t *stmt, var_udo_t *obj)
{
    pl_entity_t *pl_ctx = stmt->pl_context;

    if (pl_ctx->trigger == NULL) {
        return CT_SUCCESS;
    }

    if (sql_check_create_trig_priv(stmt, &obj->user, &pl_ctx->trigger->desc.real_user) != CT_SUCCESS) {
        cm_reset_error();
        CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return CT_ERROR;
    }

    /* check if the current user has privilege to create the trigger */
    if (cm_text_str_equal_ins(&pl_ctx->trigger->desc.real_user, SYS_USER_NAME) &&
        !cm_text_str_equal_ins(&obj->user, SYS_USER_NAME)) {
        cm_reset_error();
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "cannot create triggers on objects owned by sys");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}


static status_t plc_add_trig_tab_ref(sql_stmt_t *stmt, knl_dictionary_t *dc, sql_text_t *trig_tab)
{
    object_address_t *new_obj = NULL;
    dc_entity_t *entity = NULL;
    errno_t errcode;
    pl_entity_t *pl_entity = (pl_entity_t *)stmt->pl_context;
    galist_t *ref_list = &pl_entity->ref_list;

    CT_RETURN_IFERR(ref_list->alloc_func(ref_list->owner, sizeof(object_address_t), (void **)&new_obj));
    new_obj->uid = dc->uid;
    new_obj->oid = dc->oid;
    new_obj->tid = OBJ_TYPE_TABLE;
    new_obj->scn = dc->chg_scn;
    entity = (dc_entity_t *)dc->handle;
    errcode = strcpy_s(new_obj->name, CT_NAME_BUFFER_SIZE, entity->entry->name);
    if (errcode != EOK) {
        CT_SRC_THROW_ERROR(trig_tab->loc, ERR_SYSTEM_CALL, errcode);
        return CT_ERROR;
    }
    return cm_galist_insert(ref_list, new_obj);
}
static status_t plc_get_trig_tab_info(sql_stmt_t *stmt, trig_desc_t *trigger, knl_dictionary_t *dc)
{
    text_t user_name;
    text_t obj_name;
    dc_entity_t *dc_entity = NULL;
    dc_entry_t *dc_entry = NULL;
    pl_entity_t *pl_entity = (pl_entity_t *)stmt->pl_context;

    if (SYNONYM_EXIST(dc)) {
        dc_entry = (dc_entry_t *)dc->syn_handle;
        knl_get_link_name(dc, &user_name, &obj_name);
    } else {
        dc_entity = (dc_entity_t *)dc->handle;
        dc_entry = dc_entity->entry;
        cm_str2text(dc_entry->user->desc.name, &user_name);
        cm_str2text(dc_entry->name, &obj_name);
    }

    trigger->obj_uid = dc->uid;
    trigger->base_obj = dc->oid;

    if (pl_copy_text(pl_entity, &user_name, &trigger->real_user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (pl_copy_text(pl_entity, &obj_name, &trigger->real_table) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t plc_verify_trigger_view(sql_stmt_t *stmt, trig_desc_t *trig, knl_dictionary_t *dc, sql_text_t *tab_name)
{
    status_t status;
    lex_t *lex_bak = NULL;

    CTSQL_SAVE_PARSER(stmt);
    if (pl_save_lex(stmt, &lex_bak) != CT_SUCCESS) {
        return CT_ERROR;
    }

    bool8 disable_soft_parse = stmt->session->disable_soft_parse;
    stmt->is_explain = CT_FALSE;
    stmt->context = NULL;
    stmt->pl_context = NULL;
    stmt->session->disable_soft_parse = CT_TRUE;
    status = sql_compile_view_sql(stmt, dc, &trig->real_user) ? CT_SUCCESS : CT_ERROR;
    if (status != CT_SUCCESS) {
        CT_SRC_THROW_ERROR(tab_name->loc, ERR_OBJECT_INVALID, "view", T2S(&trig->real_user), T2S_EX(&trig->real_table));
    }
    sql_release_context(stmt);
    pl_restore_lex(stmt, lex_bak);
    SQL_RESTORE_PARSER(stmt);
    stmt->session->disable_soft_parse = disable_soft_parse;
    return status;
}

static status_t plc_verify_trigger_table(sql_stmt_t *stmt, trig_desc_t *trig, knl_dictionary_t *dc,
    sql_text_t *tab_user, sql_text_t *tab_name)
{
    if (!IS_TRIGGER_SUPPROT_OBJECT(dc->type)) {
        CT_SRC_THROW_ERROR_EX(tab_name->loc, ERR_PL_SYNTAX_ERROR_FMT,
            "%s.%s is neither a normal table or a temporary table", T2S(&tab_user->value), T2S_EX(&tab_name->value));
        return CT_ERROR;
    }
    if (dc->type == DICT_TYPE_VIEW && trig->type != TRIG_INSTEAD_OF) {
        CT_SRC_THROW_ERROR_EX(tab_name->loc, ERR_PL_SYNTAX_ERROR_FMT, "view %s.%s only support instead of trigger",
            T2S(&tab_user->value), T2S_EX(&tab_name->value));
        return CT_ERROR;
    }
    if ((dc->type == DICT_TYPE_TABLE || dc->type == DICT_TYPE_TEMP_TABLE_TRANS ||
        dc->type == DICT_TYPE_TEMP_TABLE_SESSION) &&
        trig->type == TRIG_INSTEAD_OF) {
        CT_SRC_THROW_ERROR_EX(tab_name->loc, ERR_PL_SYNTAX_ERROR_FMT,
            "instead of trigger cannont created on table %s.%s", T2S(&tab_user->value), T2S_EX(&tab_name->value));
        return CT_ERROR;
    }
    if (dc->type == DICT_TYPE_VIEW) {
        if (IS_COORDINATOR && IS_APP_CONN(stmt->session)) {
            CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "CREATE OR REPLACE TRIGGER INSTEAD OF on coordinator is");
            return CT_ERROR;
        }
        CT_RETURN_IFERR(plc_verify_trigger_view(stmt, trig, dc, tab_name));
    }
    return CT_SUCCESS;
}

static status_t plc_verify_trigger_tab_columns(sql_stmt_t *stmt, trig_desc_t *trig, sql_text_t *tab_user,
    sql_text_t *tab_name)
{
    knl_dictionary_t dc;

    if (knl_open_dc_with_public(KNL_SESSION(stmt), &tab_user->value, CT_TRUE, &tab_name->value, &dc) != CT_SUCCESS) {
        sql_check_user_priv(stmt, &tab_user->value);
        return CT_ERROR;
    }

    if (plc_get_trig_tab_info(stmt, trig, &dc) != CT_SUCCESS) {
        knl_close_dc(&dc);
        return CT_ERROR;
    }
    if (plc_add_trig_tab_ref(stmt, &dc, tab_name) != CT_SUCCESS) {
        knl_close_dc(&dc);
        return CT_ERROR;
    }
    if (plc_verify_trigger_table(stmt, trig, &dc, tab_user, tab_name) != CT_SUCCESS) {
        knl_close_dc(&dc);
        return CT_ERROR;
    }

    trig->col_count = knl_get_column_count(dc.handle);
    knl_close_dc(&dc);

    return CT_SUCCESS;
}

static status_t plc_verify_trigger_update_cols(sql_stmt_t *stmt, trig_desc_t *trig)
{
    uint32 i;
    status_t status = CT_SUCCESS;
    knl_column_t *knl_col = NULL;
    trigger_column_t *column = NULL;
    text_t col_name;
    knl_dictionary_t dc;

    if (knl_open_dc_with_public(KNL_SESSION(stmt), &trig->real_user, CT_TRUE, &trig->real_table, &dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    for (i = 0; i < trig->columns.count; ++i) {
        column = (trigger_column_t *)cm_galist_get(&trig->columns, i);
        cm_str2text(column->col_name, &col_name);
        column->id = knl_get_column_id(&dc, &col_name);
        column->type = PLV_TRIG_NONE;

        if (CT_INVALID_ID16 == column->id) {
            CT_SRC_THROW_ERROR(column->loc, ERR_UNDEFINED_SYMBOL_FMT, column->col_name);
            status = CT_ERROR;
            break;
        }

        knl_col = knl_get_column(dc.handle, column->id);
        if (KNL_COLUMN_INVISIBLE(knl_col)) {
            CT_SRC_THROW_ERROR(column->loc, ERR_UNDEFINED_SYMBOL_FMT, column->col_name);
            status = CT_ERROR;
            break;
        }
        if (CT_IS_LOB_TYPE(knl_col->datatype)) {
            CT_SRC_THROW_ERROR(column->loc, ERR_PL_UNSUPPORT);
            status = CT_ERROR;
            break;
        }
    }

    knl_close_dc(&dc);
    return status;
}

static status_t plc_exist_duplicate_update_columns(galist_t *columns, word_type_t type, sql_text_t *col_name)
{
    bool32 is_found = CT_FALSE;

    for (uint32 i = 0; i < columns->count; ++i) {
        trigger_column_t *column = (trigger_column_t *)cm_galist_get(columns, i);

        if (IS_DQ_STRING(type) || !IS_CASE_INSENSITIVE) {
            is_found = cm_text_str_equal(&col_name->value, column->col_name);
        } else {
            is_found = cm_text_str_equal_ins(&col_name->value, column->col_name);
        }

        if (is_found) {
            return CT_SUCCESS;
        }
    }

    return CT_ERROR;
}

static status_t plc_compile_update_trigger(sql_stmt_t *stmt, word_t *word, trig_desc_t *trig)
{
    bool32 result = CT_FALSE;
    text_t column_name;
    trigger_column_t *column = NULL;
    lex_t *lex = stmt->session->lex;
    pl_entity_t *entity = (pl_entity_t *)stmt->pl_context;
    trig->events |= TRIG_EVENT_UPDATE;

    CT_RETURN_IFERR(lex_try_fetch(lex, "OF", &result));
    if (!result) {
        return CT_SUCCESS;
    }
    for (;;) {
        CT_RETURN_IFERR(lex_expected_fetch_variant(lex, word));

        if (plc_exist_duplicate_update_columns(&trig->columns, word->type, &word->text) == CT_SUCCESS) {
            CT_SRC_THROW_ERROR(word->text.loc, ERR_PL_DUP_OBJ_FMT, T2S(&word->text.value));
            return CT_ERROR;
        }

        CT_RETURN_IFERR(cm_galist_new(&trig->columns, sizeof(trigger_column_t), (void **)&column));
        column->loc = word->text.loc;
        CT_RETURN_IFERR(pl_copy_object_name(entity, word->type, &word->text.value, &column_name));
        cm_text2str(&column_name, column->col_name, CT_NAME_BUFFER_SIZE);

        CT_RETURN_IFERR(lex_try_fetch_char(lex, ',', &result));
        if (!result) {
            break;
        }
    }

    return CT_SUCCESS;
}

static inline status_t plc_parse_trigger_table(sql_stmt_t *stmt, word_t *word, sql_text_t *trig_user,
    sql_text_t *trig_tab)
{
    return pl_decode_object_name(stmt, word, trig_user, trig_tab);
}

static status_t plc_get_trigger_event(sql_stmt_t *stmt, lex_t *lex, word_t *word, trig_desc_t *trig)
{
    CT_RETURN_IFERR(lex_expected_fetch(lex, word));

    switch (word->id) {
        case KEY_WORD_INSERT:
            trig->events |= TRIG_EVENT_INSERT;
            break;
        case KEY_WORD_UPDATE:
            CT_RETURN_IFERR(plc_compile_update_trigger(stmt, word, trig));
            break;
        case KEY_WORD_DELETE:
            trig->events |= TRIG_EVENT_DELETE;
            break;
        default:
            CT_SRC_THROW_ERROR(word->loc, ERR_PL_SYNTAX_ERROR_FMT, "only support 'insert' or 'update' or 'delete'");
            return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t plc_parse_trigger_event(sql_stmt_t *stmt, word_t *word, trig_desc_t *trig)
{
    lex_t *lex = stmt->session->lex;
    lex->flags = LEX_SINGLE_WORD;
    trig->events = 0;
    sql_text_t tab_user;
    sql_text_t tab_name;

    for (;;) {
        CT_RETURN_IFERR(plc_get_trigger_event(stmt, lex, word, trig));
        CT_RETURN_IFERR(lex_fetch(lex, word));

        if (word->id == KEY_WORD_ON) {
            break;
        }
        if (word->id == KEY_WORD_OR) {
            continue;
        }

        CT_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, "'ON' or 'OR'", W2S(word));
        return CT_ERROR;
    }

    // table name
    lex->flags = LEX_WITH_OWNER;
    CT_RETURN_IFERR(lex_expected_fetch(lex, word));

    if (!IS_VARIANT(word)) {
        CT_SRC_THROW_ERROR(word->text.loc, ERR_PL_EXPECTED_FAIL_FMT, "table name", W2S(word));
        return CT_ERROR;
    }
    CT_RETURN_IFERR(plc_parse_trigger_table(stmt, word, &tab_user, &tab_name));

    /* unsupport create trigger on local temp table */
    if (g_instance->kernel.attr.enable_ltt && tab_name.len > 0 && knl_is_llt_by_name(tab_name.str[0])) {
        CT_SRC_THROW_ERROR(word->text.loc, ERR_PL_SYNTAX_ERROR_FMT, "unsupport create trigger on local temp table");
        return CT_ERROR;
    }

    if (trig->events == TRIG_INSTEAD_OF) {
        bool32 result = CT_FALSE;
        CT_RETURN_IFERR(lex_try_fetch(lex, "REFERENCING ", &result));
        if (result) {
            CT_SRC_THROW_ERROR(word->text.loc, ERR_PL_SYNTAX_ERROR_FMT,
                "unsupport instead of trigger REFERENCING syntax");
            return CT_ERROR;
        }
    }

    return plc_verify_trigger_tab_columns(stmt, trig, &tab_user, &tab_name);
}

static status_t plc_parse_for_each_row(sql_stmt_t *stmt, word_t *word, trig_desc_t *trigger)
{
    bool32 result = CT_FALSE;
    lex_t *lex = stmt->session->lex;
    lex->flags = LEX_SINGLE_WORD;
    // FOR EACH ROW
    CT_RETURN_IFERR(lex_try_fetch(lex, "FOR", &result));
    if (!result) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "EACH"));
    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "ROW"));

    switch ((uint32)trigger->type) {
        case TRIG_AFTER_STATEMENT:
            trigger->type = TRIG_AFTER_EACH_ROW;
            break;
        case TRIG_BEFORE_STATEMENT:
            trigger->type = TRIG_BEFORE_EACH_ROW;
            break;
        case TRIG_INSTEAD_OF:
            break;
        default:
            CT_SRC_THROW_ERROR(word->loc, ERR_PL_SYNTAX_ERROR_FMT, "'FOR EACH ROW' only support 'AFTER' or 'BEFOR'");
            return CT_ERROR;
    }

#ifdef Z_SHARDING
    if (IS_COORDINATOR) {
        CT_SRC_THROW_ERROR(word->loc, ERR_CAPABILITY_NOT_SUPPORT, "'FOR EACH ROW' on coordinator is");
        return CT_ERROR;
    }
#endif

    return CT_SUCCESS;
}

static inline void pl_set_trigger_action_line(lex_t *lex, trig_desc_t *trig, source_location_t *start_loc)
{
    // trigger action begin
    trig->action_line = lex->curr_text->loc.line - start_loc->line + 1;
    if (start_loc->line != lex->curr_text->loc.line) {
        trig->action_col = lex->curr_text->loc.column;
    } else {
        trig->action_col = lex->curr_text->loc.column - start_loc->column + 1;
    }
}

status_t plc_parse_trigger_desc_core(sql_stmt_t *stmt, word_t *word, bool32 is_upgrade)
{
    trig_desc_t *trig = &((pl_entity_t *)stmt->pl_context)->trigger->desc;
    lex_t *lex = stmt->session->lex;
    lex->flags = LEX_SINGLE_WORD;
    source_location_t start_loc = lex->curr_text->loc;
    CT_RETURN_IFERR(lex_fetch(lex, word));

    switch ((uint32)word->id) {
        case KEY_WORD_AFTER:
            trig->type = TRIG_AFTER_STATEMENT;
            break;
        case KEY_WORD_BEFORE:
            trig->type = TRIG_BEFORE_STATEMENT;
            break;
        case KEY_WORD_INSTEAD:
            CT_RETURN_IFERR(lex_expected_fetch_word(lex, "of"));
            trig->type = TRIG_INSTEAD_OF;
            break;
        default:
            CT_SRC_THROW_ERROR(word->loc, ERR_PL_SYNTAX_ERROR_FMT, "only support 'after' or 'before' or 'instead'");
            return CT_ERROR;
    }
    cm_galist_init(&trig->columns, stmt->pl_context, pl_alloc_mem);
    CT_RETURN_IFERR(plc_parse_trigger_event(stmt, word, trig));
    CT_RETURN_IFERR(plc_parse_for_each_row(stmt, word, trig));

    if (trig->events == TRIG_INSTEAD_OF) {
        bool32 result = CT_FALSE;
        CT_RETURN_IFERR(lex_try_fetch(lex, "WHEN", &result));
        if (result) {
            CT_SRC_THROW_ERROR(word->text.loc, ERR_PL_SYNTAX_ERROR_FMT,
                "unsupport instead of trigger WHEN condition syntax");
            return CT_ERROR;
        }
    }
    pl_set_trigger_action_line(lex, trig, &start_loc);

    if (!is_upgrade) {
        CT_RETURN_IFERR(plc_verify_trigger_update_cols(stmt, trig));
    }

    return CT_SUCCESS;
}


status_t pl_parse_trigger_desc(sql_stmt_t *stmt, var_udo_t *obj, word_t *word)
{
    pl_entity_t *pl_ctx = stmt->pl_context;
    saved_schema_t save_schema;

    CT_RETURN_IFERR(pl_alloc_mem(stmt->pl_context, sizeof(trigger_t), (void **)&pl_ctx->trigger));
    CT_RETURN_IFERR(sql_switch_schema_by_name(stmt, &obj->user, &save_schema));
    if (plc_parse_trigger_desc_core(stmt, word, CT_FALSE) != CT_SUCCESS) {
        sql_restore_schema(stmt, &save_schema);
        return CT_ERROR;
    }
    sql_restore_schema(stmt, &save_schema);

    return CT_SUCCESS;
}

static status_t pl_parse_trigger_core(sql_stmt_t *stmt, word_t *word, var_udo_t *obj, uint32 type)
{
    plc_desc_t desc;
    status_t compl_ret;
    pl_entity_t *pl_ctx = stmt->pl_context;
    text_t source = stmt->session->lex->curr_text->value;

    CT_RETURN_IFERR(pl_parse_trigger_desc(stmt, obj, word));

    pl_prepare_compile_desc(&desc, stmt, obj, type);
    compl_ret = plc_compile(stmt, &desc, word);
    if (compl_ret != CT_SUCCESS) {
        stmt->pl_failed = CT_TRUE;
        pl_ctx->create_def->compl_result = CT_FALSE;
    } else {
        reset_tls_plc_error();
        cm_reset_error();
        pl_ctx->create_def->compl_result = CT_TRUE;
    }

    CT_RETURN_IFERR(pl_check_trigger_create_priv(stmt, obj));

    if (pl_record_source(stmt, pl_ctx, &source) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t pl_parse_create_trigger(sql_stmt_t *stmt, bool32 replace, word_t *word)
{
    bool32 clause_matched = CT_FALSE;
    uint16 create_option = 0;
    uint32 type;
    pl_entity_t *pl_ctx = NULL;

    CT_RETURN_IFERR(pl_alloc_context(&pl_ctx, stmt->context));
    SET_STMT_PL_CONTEXT(stmt, pl_ctx);

    SQL_SET_IGNORE_PWD(stmt->session);
    SQL_SET_COPY_LOG(stmt->session, CT_TRUE);
    type = PL_TRIGGER;
    stmt->context->type = CTSQL_TYPE_CREATE_TRIG;
    CT_RETURN_IFERR(pl_try_parse_if_not_exists(stmt, &clause_matched));
    CT_RETURN_IFERR(pl_parse_name(stmt, word, &pl_ctx->def, CT_FALSE));

    if (clause_matched) {
        create_option |= CREATE_IF_NOT_EXISTS;
    }

    if (replace) {
        create_option |= CREATE_OR_REPLACE;
    }

    pl_ctx->create_def->create_option = create_option;
    pl_ctx->pl_type = type;

    if (pl_parse_trigger_core(stmt, word, &pl_ctx->def, type) != CT_SUCCESS) {
        sql_check_user_priv(stmt, &pl_ctx->def.user);
        CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t pl_parse_drop_package(sql_stmt_t *stmt, word_t *word)
{
    pl_drop_def_t *drop_def = NULL;
    bool32 is_body = CT_FALSE;

    if (sql_alloc_mem(stmt->context, sizeof(pl_drop_def_t), (void **)&drop_def)) {
        return CT_ERROR;
    }

    if (lex_try_fetch(LEX(stmt), "body", &is_body) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (is_body) {
        stmt->context->type = CTSQL_TYPE_DROP_PACK_BODY;
        drop_def->type = PL_PACKAGE_BODY;
    } else {
        stmt->context->type = CTSQL_TYPE_DROP_PACK_SPEC;
        drop_def->type = PL_PACKAGE_SPEC;
    }

    CT_RETURN_IFERR(pl_try_parse_if_exists(stmt, &drop_def->option));
    CT_RETURN_IFERR(pl_parse_name(stmt, word, &drop_def->obj, CT_FALSE));
    CT_RETURN_IFERR(lex_expected_end(stmt->session->lex));
    stmt->context->entry = drop_def;
    return CT_SUCCESS;
}

status_t pl_try_parse_force(sql_stmt_t *stmt, uint32 *option)
{
    bool32 result = CT_FALSE;
    CT_RETURN_IFERR(lex_try_fetch(stmt->session->lex, "FORCE", &result));
    if (result) {
        *option |= DROP_TYPE_FORCE;
    }

    return CT_SUCCESS;
}

status_t pl_parse_drop_type(sql_stmt_t *stmt, word_t *word)
{
    pl_drop_def_t *drop_def = NULL;
    bool32 is_body = CT_FALSE;

    if (sql_alloc_mem(stmt->context, sizeof(pl_drop_def_t), (void **)&drop_def)) {
        return CT_ERROR;
    }

    if (lex_try_fetch(LEX(stmt), "body", &is_body) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (is_body) {
        stmt->context->type = CTSQL_TYPE_DROP_TYPE_BODY;
        drop_def->type = PL_TYPE_BODY;
    } else {
        stmt->context->type = CTSQL_TYPE_DROP_TYPE_SPEC;
        drop_def->type = PL_TYPE_SPEC;
    }

    CT_RETURN_IFERR(pl_try_parse_if_exists(stmt, &drop_def->option));
    CT_RETURN_IFERR(pl_parse_name(stmt, word, &drop_def->obj, CT_FALSE));
    CT_RETURN_IFERR(pl_try_parse_force(stmt, &drop_def->option));
    CT_RETURN_IFERR(lex_expected_end(stmt->session->lex));
    stmt->context->entry = drop_def;
    return CT_SUCCESS;
}
