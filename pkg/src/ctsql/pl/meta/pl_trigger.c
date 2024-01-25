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
 * pl_trigger.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/meta/pl_trigger.c
 *
 * -------------------------------------------------------------------------
 */
#include "pl_trigger.h"
#include "base_compiler.h"
#include "pl_compiler.h"
#include "srv_instance.h"
#include "pl_meta_common.h"
#include "pl_logic.h"
#include "trigger_decl_cl.h"

#ifdef Z_SHARDING
status_t shd_pre_execute_ddl(sql_stmt_t *stmt, bool32 multi_ddl, bool32 need_encrypt);
status_t shd_trigger_check_for_rebalance(sql_stmt_t *stmt, text_t *user, text_t *tab);
#endif

trig_pseudo_column_t g_trig_pseudo_col[] = {
    {TRIG_RES_WORD_ROWID, {"rowid", 5}},
    {TRIG_RES_WORD_ROWSCN, {"rowscn", 6}}
};

#define TRIG_PSEUDO_COL_NUM ELEMENT_COUNT(g_trig_pseudo_col)

bool32 plc_trigger_verify_row_pesudo(const text_t *name, uint16 *col, text_t *decl_name)
{
    for (uint32 loop = 0; loop < TRIG_PSEUDO_COL_NUM; loop++) {
        if (cm_compare_text_ins(&g_trig_pseudo_col[loop].name, name) == 0) {
            *col = g_trig_pseudo_col[loop].col_id;
            cm_text_upper(decl_name);
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

status_t plm_update_source_fetch_on(lex_t *lex, word_t *word)
{
    for (;;) {
        CT_RETURN_IFERR(lex_fetch(lex, word));

        if (word->type == WORD_TYPE_EOF) {
            CT_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "'on' expected");
            return CT_ERROR;
        }
        CT_BREAK_IF_TRUE(word->id == KEY_WORD_ON);
    }
    return CT_SUCCESS;
}

status_t plm_update_source_trig_tab(knl_session_t *session, knl_cursor_t *cursor, knl_column_t *column, text_t *locator,
    text_t *old_source, text_t *old_tab, text_t *new_tab)
{
    lex_t lex;
    sql_text_t sql_text;
    text_t write_data;
    word_t word, tab_word;
    status_t status = CT_ERROR;
    uint32 need_size = old_source->len - old_tab->len + new_tab->len; // not overflow

    if (CT_LARGE_PAGE_SIZE < need_size) {
        CT_THROW_ERROR(ERR_SOURCE_SIZE_TOO_LARGE_FMT, need_size, CT_LARGE_PAGE_SIZE);
        return CT_ERROR;
    }

    sql_text.value = *old_source;
    lex_init(&lex, &sql_text);
    lex.call_version = CS_LOCAL_VERSION;

    if (plm_update_source_fetch_on(&lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    lex.flags = LEX_WITH_OWNER;

    do {
        CT_BREAK_IF_ERROR(lex_fetch(&lex, &tab_word));

        if (tab_word.ex_count > 0) {
            tab_word.text = tab_word.ex_words[0].text;
        }

        if (!cm_text_equal_ins(&tab_word.text.value, old_tab)) {
            CT_THROW_ERROR(ERR_UNDEFINED_SYMBOL_FMT, T2S(old_tab));
            break;
        }

        MEMS_RETURN_IFERR(memset_s(locator->str, locator->len, 0xFF, KNL_LOB_LOCATOR_SIZE));
        write_data.str = old_source->str;
        write_data.len = (uint32)(tab_word.text.str - old_source->str); // not overflow
        CT_BREAK_IF_ERROR(knl_write_lob(session, cursor, locator->str, column, CT_TRUE, &write_data));
        CT_BREAK_IF_ERROR(knl_write_lob(session, cursor, locator->str, column, CT_TRUE, new_tab));

        write_data.str = tab_word.text.str + tab_word.text.len;                        // not overflow
        write_data.len = old_source->len - (uint32)(write_data.str - old_source->str); // not overflow
        CT_BREAK_IF_ERROR(knl_write_lob(session, cursor, locator->str, column, CT_TRUE, &write_data));
        status = CT_SUCCESS;
    } while (0);

    return status;
}

// the function only for : alter table ... rename to ...
status_t plm_update_tab_from_sysproc(knl_handle_t knl_session, pl_desc_t *desc, text_t *name, text_t *new_name)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t row_ass;
    knl_update_info_t *update_info = NULL;
    char *locator = NULL;
    uint32 large_page_id;
    knl_session_t *session = (knl_session_t *)knl_session;
    text_t source = { 0 };
    knl_column_t *column = NULL;
    char locator_buf[KNL_LOB_LOCATOR_SIZE] = { 0 };
    binary_t loc_upt;
    text_t locator_text;
    status_t status = CT_SUCCESS;

    loc_upt.bytes = (uint8 *)locator_buf;
    loc_upt.size = KNL_LOB_LOCATOR_SIZE;
    locator_text.str = locator_buf;
    locator_text.len = KNL_LOB_LOCATOR_SIZE;

    CM_SAVE_STACK(session->stack);

    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_STACK_OVERFLOW);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_PROC_ID, IX_PROC_003_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &desc->uid, sizeof(int32),
        0);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, &desc->oid,
        sizeof(desc->oid), 1);

    column = knl_get_column(cursor->dc_entity, SYS_PROC_SOURCE_COL);

    knl_begin_session_wait(knl_session, LARGE_POOL_ALLOC, CT_FALSE);
    if (mpool_alloc_page_wait(&g_instance->sga.large_pool, &large_page_id, CM_MPOOL_ALLOC_WAIT_TIME) != CT_SUCCESS) {
        knl_end_session_wait(knl_session, LARGE_POOL_ALLOC);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    knl_end_session_wait(knl_session, LARGE_POOL_ALLOC);
    source.str = mpool_page_addr(&g_instance->sga.large_pool, large_page_id);

    for (;;) {
        if (CT_SUCCESS != knl_fetch(session, cursor)) {
            status = CT_ERROR;
            break;
        }

        if (cursor->eof) {
            break;
        }

        locator = CURSOR_COLUMN_DATA(cursor, SYS_PROC_SOURCE_COL);
        if (knl_read_lob(session, locator, 0, source.str, CT_LARGE_PAGE_SIZE, &source.len, NULL) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        if (plm_update_source_trig_tab(session, cursor, column, &locator_text, &source, name, new_name) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        update_info = &cursor->update_info;
        row_init(&row_ass, update_info->data, CT_MAX_ROW_SIZE, 2);
        // The current application scenario will not return a failure
        (void)row_put_bin(&row_ass, &loc_upt);
        (void)row_put_text(&row_ass, new_name);
        update_info->count = 2;
        update_info->columns[0] = SYS_PROC_SOURCE_COL;
        update_info->columns[1] = SYS_PROC_TRIG_TABLE_COL;
        cm_decode_row(update_info->data, update_info->offsets, update_info->lens, NULL);

        if (CT_SUCCESS != knl_internal_update(session, cursor)) {
            status = CT_ERROR;
            break;
        }
    }

    mpool_free_page(&g_instance->sga.large_pool, large_page_id);
    CM_RESTORE_STACK(session->stack);
    return status;
}

// callback function, already get table lock
status_t pl_update_source_for_trigs(knl_handle_t knl_session, knl_dictionary_t *dc, text_t *name, text_t *new_name)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    trig_set_t *trig_set = &entity->trig_set;
    pl_entry_t *entry = NULL;
    pl_entry_info_t entry_info;
    trig_item_t *trig_item = NULL;
    knl_session_t *session = (knl_session_t *)knl_session;

    for (uint32 i = 0; i < trig_set->trig_count; i++) {
        trig_item = &trig_set->items[i];
        pl_find_entry_by_oid(trig_item->oid, PL_TRIGGER, &entry_info);
        entry = entry_info.entry;
        CM_ASSERT(entry != NULL);

        if (pl_lock_entry_exclusive(knl_session, &entry_info) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (plm_update_tab_from_sysproc(session, &entry->desc, name, new_name) != CT_SUCCESS) {
            pl_unlock_exclusive(knl_session, entry);
            return CT_ERROR;
        }

        pl_entity_invalidate_by_entry(entry);
        pl_unlock_exclusive(knl_session, entry);
    }

    return CT_SUCCESS;
}

// callback function, already get table lock
void pl_free_trig_entity_by_tab(knl_handle_t knl_session, knl_dictionary_t *dc)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    pl_entry_t *entry = NULL;
    trig_item_t *trig_item = NULL;
    trig_set_t trig_set = entity->trig_set;
    pl_entry_info_t entry_info;
    for (uint32 i = 0; i < trig_set.trig_count; i++) {
        trig_item = &trig_set.items[i];
        pl_find_entry_by_oid(trig_item->oid, PL_TRIGGER, &entry_info);
        entry = entry_info.entry;
        CM_ASSERT(entry != NULL);

        if (pl_lock_entry_exclusive(knl_session, &entry_info) != CT_SUCCESS) {
            CT_LOG_RUN_WAR("Don't find the trigger %s, user id = %u", entry->desc.name, entry->desc.uid);
            continue;
        }
        pl_entity_invalidate_by_entry(entry);
        pl_logic_log_put(knl_session, RD_PLM_FREE_TRIG_ENTITY, entry->desc.uid, entry->desc.oid, entry->desc.type);
        pl_unlock_exclusive(knl_session, entry);
    }

    return;
}

status_t pl_write_systrigger(knl_session_t *session, uint64 oid, trig_desc_t *trig_desc)
{
    uint32 max_size;
    row_assist_t row_ass;
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);

    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_STACK_OVERFLOW);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    max_size = session->kernel->attr.max_row_size;
    row_init(&row_ass, cursor->buf, max_size, SYS_TRIGGER_COLUMN_COUNT);
    (void)row_put_int64(&row_ass, oid);                     // OBJ#
    (void)row_put_uint32(&row_ass, trig_desc->type);        // TYPE#
    (void)row_put_uint32(&row_ass, trig_desc->events);      // EVENT#
    (void)row_put_uint32(&row_ass, trig_desc->obj_uid);     // OBJ_UID
    (void)row_put_int64(&row_ass, trig_desc->base_obj);     // BASEOBJECT
    (void)row_put_null(&row_ass);                           // WHENCLAUSSE
    (void)row_put_int32(&row_ass, trig_desc->enable);       // ENABLE
    (void)row_put_uint32(&row_ass, trig_desc->flags);       // FLAGS
    (void)row_put_uint32(&row_ass, trig_desc->action_line); // ACTIONLINENO
    (void)row_put_uint32(&row_ass, trig_desc->action_col);  // ACTIONCOLNO
    (void)row_put_null(&row_ass);                           // SPARE1
    (void)row_put_null(&row_ass);                           // SPARE2
    (void)row_put_null(&row_ass);                           // SPARE3
    (void)row_put_null(&row_ass);                           // SPARE4

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_TRIGGER_ID, CT_INVALID_ID32);

    if (knl_internal_insert(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

status_t pl_delete_systriger(knl_session_t *session, uint64 oid)
{
    knl_cursor_t *cursor = NULL;
    CM_SAVE_STACK(session->stack);

    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_TRIGGER_ID, IX_SYS_TRIGGER_001_ID);

    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, (void *)&oid, sizeof(oid),
        IX_SYS_TRIGGER_001_ID_OBJ);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    while (!cursor->eof) {
        if (knl_internal_delete(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (CT_SUCCESS != knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t pl_load_sys_trigger(knl_session_t *session, uint64 oid, trig_desc_t *trig)
{
    knl_cursor_t *cursor = NULL;
    CM_SAVE_STACK(session->stack);

    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    knl_set_session_scn(session, CT_INVALID_ID64);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TRIGGER_ID, IX_SYS_TRIGGER_001_ID);
    knl_init_index_scan(cursor, CT_TRUE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, (void *)&oid, sizeof(oid),
        IX_SYS_TRIGGER_001_ID_OBJ);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CT_THROW_ERROR(ERR_OBJECT_ID_NOT_EXIST, "trigger", oid);
        CT_LOG_RUN_ERR("load trigger failed, oid = %lld", (int64)oid);
        CM_RESTORE_STACK(session->stack);
        return CT_SUCCESS;
    }

    trig->events = (uint16)(*(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TRIGGER_COL_EVENT));
    trig->type = (uint16)(*(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TRIGGER_COL_TYPE));
    trig->enable = (uint16)(*(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TRIGGER_COL_ENABLE));
    trig->flags = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TRIGGER_COL_FALGS);
    trig->obj_uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TRIGGER_COL_OBJECTUID);
    trig->base_obj = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_TRIGGER_COL_BASEOBJECT);
    trig->action_line = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TRIGGER_COL_ACTIONLINENO);
    trig->action_col = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TRIGGER_COL_ACTIONCOLNO);

    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

status_t pl_update_trigger_enable_status(knl_session_t *session, uint64 oid, bool32 enable)
{
    status_t status = CT_ERROR;
    knl_cursor_t *cursor = NULL;
    knl_update_info_t *update_info = NULL;
    row_assist_t row_ass;
    CM_SAVE_STACK(session->stack);

    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    knl_set_session_scn(session, CT_INVALID_ID64);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TRIGGER_ID, IX_SYS_TRIGGER_001_ID);
    knl_init_index_scan(cursor, CT_TRUE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, (void *)&oid, sizeof(oid),
        IX_SYS_TRIGGER_001_ID_OBJ);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    do {
        CT_BREAK_IF_ERROR(knl_fetch(session, cursor));

        if (!cursor->eof) {
            CT_THROW_ERROR(ERR_OBJECT_ID_NOT_EXIST, "trigger", oid);
            break;
        }

        update_info = &cursor->update_info;
        update_info->count = 1;
        row_init(&row_ass, update_info->data, CT_MAX_ROW_SIZE, update_info->count);
        (void)row_put_int32(&row_ass, enable);
        update_info->columns[0] = SYS_TRIGGER_COL_ENABLE;
        cm_decode_row(update_info->data, update_info->offsets, update_info->lens, NULL);
        CT_BREAK_IF_ERROR(knl_internal_update(session, cursor));
        status = CT_SUCCESS;
    } while (0);

    CM_RESTORE_STACK(session->stack);

    return status;
}

status_t pl_get_table_trigger_count(knl_session_t *session, void *trig_def, uint32 *trig_count)
{
    knl_session_t *sess = (knl_session_t *)session;
    knl_cursor_t *cursor = NULL;
    status_t status = CT_SUCCESS;
    trig_def_t *trig = (trig_def_t *)trig_def;

    CM_SAVE_STACK(sess->stack);

    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_set_session_scn(session, CT_INVALID_ID64);
    knl_open_sys_cursor(sess, cursor, CURSOR_ACTION_SELECT, SYS_TRIGGER_ID, IX_SYS_TRIGGERS_002_ID);
    knl_init_index_scan(cursor, CT_FALSE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&trig->obj_uid,
        sizeof(uint32), IX_SYS_TRIGGERS_002_ID_OBJUID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, (void *)&trig->obj_uid,
        sizeof(uint32), IX_SYS_TRIGGERS_002_ID_OBJUID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, (void *)&trig->obj_oid,
        sizeof(uint64), IX_SYS_TRIGGERS_002_ID_BASEOBJ);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_BIGINT, (void *)&trig->obj_oid,
        sizeof(uint64), IX_SYS_TRIGGERS_002_ID_BASEOBJ);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_SYS_TRIGGER_002_ID_OBJ);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_SYS_TRIGGER_002_ID_OBJ);
    *trig_count = 0;
    for (;;) {
        if (CT_SUCCESS != knl_fetch(session, cursor)) {
            status = CT_ERROR;
            break;
        }
        if (cursor->eof) {
            break;
        }
        (*trig_count)++;
    }

    return status;
}


status_t pl_load_entity_update_trigger_table(knl_session_t *session, void *desc_in, void *entity_in)
{
    pl_desc_t *desc = (pl_desc_t *)desc_in;
    pl_entity_t *entity = (pl_entity_t *)entity_in;
    object_address_t obj_addr;
    pl_entry_t *entry = entity->entry;

    CT_RETURN_IFERR(pl_get_desc_objaddr(&obj_addr, desc));
    CT_RETURN_IFERR(pl_update_sysproc_status(session, desc));
    CT_RETURN_IFERR(pl_delete_dependency(session, &obj_addr));

    if (desc->status == OBJ_STATUS_VALID) {
        CT_RETURN_IFERR(pl_insert_dependency_list(session, &obj_addr, &entity->ref_list));
    }

    if (entry->desc.status == OBJ_STATUS_VALID && desc->status != OBJ_STATUS_VALID) {
        CT_RETURN_IFERR(pl_update_depender_status(session, &obj_addr));
    }

    return CT_SUCCESS;
}

status_t pl_update_sysproc_trigger_enable(knl_session_t *knl_session, void *desc_in, bool32 enable)
{
    pl_desc_t *desc = (pl_desc_t *)desc_in;
    knl_cursor_t *cursor = NULL;
    row_assist_t row_ass;
    knl_update_info_t *update_info = NULL;
    status_t status = CT_ERROR;

    CM_SAVE_STACK(knl_session->stack);

    if (sql_push_knl_cursor(knl_session, &cursor) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_STACK_OVERFLOW);
        CM_RESTORE_STACK(knl_session->stack);
        return CT_ERROR;
    }

    do {
        knl_set_session_scn(knl_session, CT_INVALID_ID64);

        knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_UPDATE, SYS_PROC_ID, IX_PROC_003_ID);

        knl_init_index_scan(cursor, CT_TRUE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &desc->uid,
            sizeof(int32), 0);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, &desc->oid,
            sizeof(desc->oid), 1);

        CT_BREAK_IF_ERROR(knl_fetch(knl_session, cursor));

        if (cursor->eof) {
            break;
        }

        update_info = &cursor->update_info;
        update_info->count = 1;
        row_init(&row_ass, update_info->data, CT_MAX_ROW_SIZE, update_info->count);
        if (enable) {
            (void)row_put_str(&row_ass, "ENABLED");
        } else {
            (void)row_put_str(&row_ass, "DISABLED");
        }
        update_info->columns[0] = SYS_PROC_TRIG_STATUS_COL;
        cm_decode_row(update_info->data, update_info->offsets, update_info->lens, NULL);
        CT_BREAK_IF_ERROR(knl_internal_update(knl_session, cursor));

        status = CT_SUCCESS;
    } while (0);

    CM_RESTORE_STACK(knl_session->stack);
    return status;
}
