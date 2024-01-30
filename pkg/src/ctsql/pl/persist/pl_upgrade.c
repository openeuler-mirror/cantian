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
 * pl_upgrade.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/persist/pl_upgrade.c
 *
 * -------------------------------------------------------------------------
 */
#include "pl_upgrade.h"
#include "pl_memory.h"
#include "srv_instance.h"
#include "base_compiler.h"
#include "pl_ddl_parser.h"


static void pl_upgrade_set_trig_def(pl_entry_t *entry, trig_desc_t *trigger_desc)
{
    entry->desc.trig_def.obj_oid = trigger_desc->base_obj;
    entry->desc.trig_def.obj_uid = trigger_desc->obj_uid;
}

static status_t pl_upgrade_write_trig_table(sql_stmt_t *stmt, pl_entry_t *entry, knl_dictionary_t *dc)
{
    knl_session_t *session = KNL_SESSION(stmt);
    pl_entity_t *pl_ctx = (pl_entity_t *)stmt->pl_context;
    trig_desc_t *trigger_desc = &pl_ctx->trigger->desc;
    dc_entity_t *dc_entity = (dc_entity_t *)dc->handle;

    trigger_desc->enable = CT_TRUE;
    CT_RETURN_IFERR(pl_delete_systriger(session, entry->desc.oid));
    CT_RETURN_IFERR(pl_write_systrigger(session, entry->desc.oid, trigger_desc));
    if (dc->type != DICT_TYPE_VIEW) {
        CT_RETURN_IFERR(knl_update_trig_table_flag(session, &dc_entity->table.desc, CT_TRUE));
    }
    pl_upgrade_set_trig_def(entry, trigger_desc);
    dc_invalidate(session, (dc_entity_t *)dc->handle);
    return CT_SUCCESS;
}

static status_t pl_upgrade_write_trigger_table(sql_stmt_t *stmt, pl_desc_t *desc)
{
    knl_dictionary_t dc;
    bool32 entry_exists;
    pl_entry_t *entry = NULL;
    dc_user_t *dc_user = NULL;
    pl_entity_t *pl_ctx = (pl_entity_t *)stmt->pl_context;
    trig_desc_t *trigger_desc = &pl_ctx->trigger->desc;
    knl_session_t *session = KNL_SESSION(stmt);
    text_t user_name;
    text_t obj_name;
    status_t status = CT_ERROR;

    CT_RETURN_IFERR(dc_open_user_by_id(session, desc->uid, &dc_user));
    CT_RETURN_IFERR(knl_open_dc_by_id(session, trigger_desc->obj_uid, (uint32)trigger_desc->base_obj, &dc, CT_FALSE));
    if (lock_table_directly(session, &dc, session->kernel->attr.ddl_lock_timeout) != CT_SUCCESS) {
        dc_close(&dc);
        return CT_ERROR;
    }

    cm_str2text(dc_user->desc.name, &user_name);
    cm_str2text(desc->name, &obj_name);
    do {
        CT_BREAK_IF_ERROR(pl_find_entry(session, &user_name, &obj_name, PL_TRIGGER, &entry, &entry_exists));
        if (!entry_exists) {
            CT_LOG_RUN_ERR("trigger not found while upgrade, user: %s, trigger: %s", dc_user->desc.name, desc->name);
            break;
        }
        CT_BREAK_IF_ERROR(pl_upgrade_write_trig_table(stmt, entry, &dc));
        status = CT_SUCCESS;
    } while (0);

    unlock_tables_directly(KNL_SESSION(stmt));
    dc_close(&dc);

    return status;
}

status_t pl_upgrade_parse_trigger_desc(sql_stmt_t *stmt, var_udo_t *udo_obj)
{
    pl_entity_t *pl_ctx = stmt->pl_context;
    saved_schema_t save_schema;
    word_t word;

    word.type = WORD_TYPE_VARIANT;
    word.text.value = udo_obj->name;
    CT_RETURN_IFERR(pl_alloc_mem(stmt->pl_context, sizeof(trigger_t), (void **)&pl_ctx->trigger));
    CT_RETURN_IFERR(sql_switch_schema_by_name(stmt, &udo_obj->user, &save_schema));
    if (plc_parse_trigger_desc_core(stmt, &word, CT_TRUE) != CT_SUCCESS) {
        sql_restore_schema(stmt, &save_schema);
        return CT_ERROR;
    }
    sql_restore_schema(stmt, &save_schema);

    return CT_SUCCESS;
}

static status_t pl_upgrade_compile_trigger(knl_session_t *session, pl_desc_t *desc, text_t *source)
{
    pl_entity_t *entity = NULL;
    sql_stmt_t *stmt = ((session_t *)session)->current_stmt;
    sql_stmt_t *sub_stmt = NULL;
    lex_t *lex_bak = NULL;
    status_t status = CT_ERROR;
    sql_stmt_t *save_curr_stmt = stmt->session->current_stmt;
    CT_RETURN_IFERR(pl_alloc_context(&entity, NULL));

    if (pl_init_obj(session, desc, entity) != CT_SUCCESS) {
        pl_free_entity(entity);
        return CT_ERROR;
    }
    CTSQL_SAVE_STACK(stmt);
    if (pl_save_lex(stmt, &lex_bak) != CT_SUCCESS) {
        pl_free_entity(entity);
        return CT_ERROR;
    }

    if (sql_push(stmt, sizeof(sql_stmt_t), (void **)&sub_stmt) != CT_SUCCESS) {
        pl_restore_lex(stmt, lex_bak);
        pl_free_entity(entity);
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    do {
        sql_init_stmt(stmt->session, sub_stmt, stmt->id);
        sub_stmt->context = NULL;
        sub_stmt->pl_context = entity;
        CT_BREAK_IF_ERROR(sql_alloc_context(sub_stmt));
        sub_stmt->context->type = CTSQL_TYPE_CREATE_TRIG;
        pl_init_lex(sub_stmt->session->lex, *source);
        sub_stmt->session->current_stmt = sub_stmt;
        if (pl_upgrade_parse_trigger_desc(sub_stmt, &entity->def) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("trigger %s.%s is invalid", T2S(&entity->def.user), T2S(&entity->def.name));
            status = CT_SUCCESS;
            break;
        }
        // if parse not success, do not write table
        status = pl_upgrade_write_trigger_table(sub_stmt, desc);
    } while (0);

    sql_release_lob_info(sub_stmt);
    sql_release_resource(sub_stmt, CT_TRUE);
    pl_free_entity(sub_stmt->pl_context);
    sql_free_context(sub_stmt->context);
    sub_stmt->context = NULL;
    sub_stmt->pl_context = NULL;
    stmt->session->current_stmt = save_curr_stmt;
    pl_restore_lex(stmt, lex_bak);
    CTSQL_RESTORE_STACK(stmt);

    return status;
}

static int pl_get_pl_type(char type)
{
    switch (type) {
        case 'T':
            return PL_TRIGGER;
        case 'F':
            return PL_FUNCTION;
        case 'P':
            return PL_PROCEDURE;
        case 'S':
            return PL_PACKAGE_SPEC;
        case 'B':
            return PL_PACKAGE_BODY;
        case 'Y':
            return PL_TYPE_SPEC;
        case 'O':
            return PL_TYPE_BODY;
        default:
            return PL_ANONYMOUS_BLOCK;
    }
}

static status_t pl_upgrade_compile_trig(knl_session_t *session, knl_cursor_t *cursor, pl_desc_t *desc)
{
    text_t source;
    bool32 new_page;
    char *locator = NULL;
    uint32 source_len;
    pl_source_pages_t source_page = { CT_INVALID_ID32, 0 };

    locator = CURSOR_COLUMN_DATA(cursor, SYS_PROC_SOURCE_COL);
    source_len = knl_lob_size(locator);

    CT_RETURN_IFERR(pl_alloc_source_page(session, &source_page, source_len, &source.str, &new_page));

    if (knl_read_lob(session, locator, 0, source.str, CT_LARGE_PAGE_SIZE, &source.len, NULL) != CT_SUCCESS) {
        pl_free_source_page(&source_page, CT_TRUE);
        return CT_ERROR;
    }

    if (pl_upgrade_compile_trigger(session, desc, &source) != CT_SUCCESS) {
        pl_free_source_page(&source_page, CT_TRUE);
        return CT_ERROR;
    }

    pl_free_source_page(&source_page, CT_TRUE);
    return CT_SUCCESS;
}

status_t pl_upgrade_build_sys_procs(knl_session_t *se)
{
    pl_desc_t desc;
    knl_cursor_t *cur = NULL;
    knl_session_t *session = (knl_session_t *)se;
    text_t obj_name;
    char obj_type;

    if (sql_push_knl_cursor(session, &cur) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_STACK_OVERFLOW);
        return CT_ERROR;
    }
    if (cur == NULL) {
        CT_THROW_ERROR(ERR_STACK_OVERFLOW);
        return CT_ERROR;
    }

    knl_set_session_scn(session, CT_INVALID_ID64);
    knl_open_sys_cursor(session, cur, CURSOR_ACTION_SELECT, SYS_PROC_ID, CT_INVALID_ID32);

    for (;;) {
        if (knl_fetch(session, cur) != CT_SUCCESS) {
            return CT_ERROR;
        }

        CT_BREAK_IF_TRUE(cur->eof);
        desc.uid = *(uint32 *)CURSOR_COLUMN_DATA(cur, SYS_PROC_USER_COL);
        desc.oid = *(int64 *)CURSOR_COLUMN_DATA(cur, SYS_PROC_OBJ_ID_COL);
        obj_name.str = (char *)CURSOR_COLUMN_DATA(cur, SYS_PROC_NAME_COL);
        obj_name.len = (uint32)CURSOR_COLUMN_SIZE(cur, SYS_PROC_NAME_COL);
        obj_type = *(char *)CURSOR_COLUMN_DATA(cur, SYS_PROC_TYPE_COL);
        desc.org_scn = *(int64 *)CURSOR_COLUMN_DATA(cur, SYS_PROC_ORG_SCN_COL);
        desc.chg_scn = *(int64 *)CURSOR_COLUMN_DATA(cur, SYS_PROC_CHG_SCN_COL);
        desc.status = *(int32 *)CURSOR_COLUMN_DATA(cur, SYS_PROC_STATUS_COL);
        desc.type = pl_get_pl_type(obj_type);
        desc.flags = 0;
        cm_text2str(&obj_name, desc.name, CT_NAME_BUFFER_SIZE);
        if (desc.type == PL_TRIGGER) {
            CT_RETURN_IFERR(pl_upgrade_compile_trig(session, cur, &desc));
        }
    }

    return CT_SUCCESS;
}

status_t pl_upgrade_build_object(knl_session_t *session)
{
    if (!DB_IS_UPGRADE(session)) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in UPGRADE mode");
        return CT_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    if (pl_upgrade_build_sys_procs(session) != CT_SUCCESS) {
        knl_rollback(session, NULL);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_commit(session);
    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}