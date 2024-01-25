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
 * pl_meta_common.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/meta/pl_meta_common.c
 *
 * -------------------------------------------------------------------------
 */
#include "pl_meta_common.h"
#include "srv_instance.h"
#include "ctsql_dependency.h"
#include "pl_common.h"
#include "pl_defs.h"

status_t pl_fetch_obj_by_uid(knl_session_t *session, uint32 uid, pl_desc_t *desc, bool32 *found)
{
    knl_cursor_t *cursor = NULL;
    text_t obj_name;
    char pl_type;

    CM_SAVE_STACK(session->stack);
    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_STACK_OVERFLOW);
        CM_RESTORE_STACK(session->stack);
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
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (!cursor->eof) {
        desc->oid = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_PROC_OBJ_ID_COL);
        desc->uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PROC_USER_COL);
        obj_name.str = (char *)CURSOR_COLUMN_DATA(cursor, SYS_PROC_NAME_COL);
        obj_name.len = (uint32)CURSOR_COLUMN_SIZE(cursor, SYS_PROC_NAME_COL);
        pl_type = *(char *)CURSOR_COLUMN_DATA(cursor, SYS_PROC_TYPE_COL);
        desc->type = plm_get_pl_type(pl_type);
        cm_text2str(&obj_name, desc->name, CT_NAME_BUFFER_SIZE);
        *found = CT_TRUE;
    } else {
        *found = CT_FALSE;
    }

    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

status_t pl_load_sys_proc_desc(knl_session_t *session, pl_desc_t *desc)
{
    text_t obj_name;
    char pl_type;
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);
    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_PROC_ID, IX_PROC_003_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->uid,
        sizeof(int32), IX_PROC_003_ID_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->oid,
        sizeof(int64), IX_PROC_003_ID_OBJ);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CT_THROW_ERROR(ERR_OBJECT_ID_NOT_EXIST, "object", desc->oid);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    obj_name.str = (char *)CURSOR_COLUMN_DATA(cursor, SYS_PROC_NAME_COL);
    obj_name.len = (uint32)CURSOR_COLUMN_SIZE(cursor, SYS_PROC_NAME_COL);
    pl_type = *(char *)CURSOR_COLUMN_DATA(cursor, SYS_PROC_TYPE_COL);
    desc->type = plm_get_pl_type(pl_type);
    desc->status = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PROC_STATUS_COL);
    desc->flags = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PROC_FLAGS_COL);
    desc->org_scn = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_PROC_ORG_SCN_COL);
    desc->chg_scn = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_PROC_CHG_SCN_COL);
    cm_text2str(&obj_name, desc->name, CT_NAME_BUFFER_SIZE);

    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}


static int32 pl_get_pl_class(uint32 type)
{
    pl_class_type_t class_type;
    switch (type) {
        case PL_TRIGGER:
            class_type = PL_CLASS_TRIGGER;
            break;
        case PL_PACKAGE_BODY:
            class_type = PL_CLASS_PACK_BODY;
            break;
        case PL_TYPE_BODY:
            class_type = PL_CLASS_TYPE_BODY;
            break;
        default:
            class_type = PL_CLASS_PROC_FUNC_PACK_TYPE;
            break;
    }

    return class_type;
}

static status_t pl_process_lib_column(row_assist_t *ra, pl_desc_t *desc, pl_entity_t *entity)
{
    function_t *func = entity->function;
    pl_line_begin_t *begin_line = NULL;

    if (entity->pl_type == PL_FUNCTION && func->desc.lang_type == LANG_C) {
        begin_line = (pl_line_begin_t *)func->body;
        desc->lang_type = LANG_C;
        CT_RETURN_IFERR(row_put_int32(ra, desc->flags));        // FLAGS
        CT_RETURN_IFERR(row_put_text(ra, &begin_line->lib_name)); // LIB_NAME
        CT_RETURN_IFERR(row_put_text(ra, &begin_line->lib_user)); // LIB_USER
    } else {
        CT_RETURN_IFERR(row_put_int32(ra, desc->flags)); // FLAGS
        CT_RETURN_IFERR(row_put_null(ra));               // LIB_NAME
        CT_RETURN_IFERR(row_put_null(ra));               // LIB_USER
    }

    return CT_SUCCESS;
}


status_t pl_write_sys_proc(knl_session_t *knl_session, pl_desc_t *desc, pl_entity_t *entity)
{
    row_assist_t ra;
    knl_column_t *column = NULL;
    knl_cursor_t *cursor = NULL;
    lob_locator_t lob_loc;
    char *locator_buf = (char *)&lob_loc;
    binary_t locator_bin = { 0 };
    status_t status = CT_ERROR;

    locator_bin.bytes = (uint8 *)locator_buf;
    locator_bin.size = KNL_LOB_LOCATOR_SIZE;
    CM_SAVE_STACK(knl_session->stack);
    if (sql_push_knl_cursor(knl_session, &cursor) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_STACK_OVERFLOW);
        CM_RESTORE_STACK(knl_session->stack);
        return CT_ERROR;
    }

    knl_set_session_scn(knl_session, CT_INVALID_ID64);
    do {
        knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_INSERT, SYS_PROC_ID, CT_INVALID_ID32);

        errno_t errcode = memset_s(locator_buf, KNL_LOB_LOCATOR_SIZE, 0xFF, KNL_LOB_LOCATOR_SIZE);
        if (errcode != EOK) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            CM_RESTORE_STACK(knl_session->stack);
            return CT_ERROR;
        }

        column = knl_get_column(cursor->dc_entity, SYS_PROC_SOURCE_COL);
        CT_BREAK_IF_ERROR(
            knl_write_lob(knl_session, cursor, locator_buf, column, CT_TRUE, &entity->create_def->source));

        uint32 column_count = knl_get_column_count(cursor->dc_entity);
        desc->chg_scn = db_inc_scn(knl_session);
        row_init(&ra, (char *)cursor->row, g_instance->kernel.attr.max_row_size, column_count);
        // The current application scenario will not return a failure
        CT_BREAK_IF_ERROR(row_put_int32(&ra, (int32)desc->uid)); // user#
        CT_BREAK_IF_ERROR(row_put_int64(&ra, desc->oid));        // obj#
        CT_BREAK_IF_ERROR(row_put_str(&ra, desc->name));         // name
        int32 pl_class = pl_get_pl_class(desc->type);
        CT_BREAK_IF_ERROR(row_put_int32(&ra, pl_class)); // class
        char *obj_type = pl_get_char_type(desc->type);
        CT_BREAK_IF_ERROR(row_put_str(&ra, obj_type));                           // type
        CT_BREAK_IF_ERROR(row_put_bin(&ra, &locator_bin));                       // source
        CT_BREAK_IF_ERROR(row_put_int32(&ra, 0));                                // AGGREGATE
        CT_BREAK_IF_ERROR(row_put_int32(&ra, 0));                                // PIPELINED
        CT_BREAK_IF_ERROR(row_put_null(&ra));                                    // TRIG_TABLE_USER
        CT_BREAK_IF_ERROR(row_put_null(&ra));                                    // TRIG_TABLE
        CT_BREAK_IF_ERROR(row_put_int64(&ra, (int64)desc->org_scn));             // ORG_SCN
        CT_BREAK_IF_ERROR(row_put_int64(&ra, (int64)desc->chg_scn));             // CHG_SCN
        CT_BREAK_IF_ERROR(row_put_null(&ra));                                    // TRIG_STATUS
        CT_BREAK_IF_ERROR(row_put_int32(&ra, entity->create_def->compl_result)); // STATUS
        CT_BREAK_IF_ERROR(pl_process_lib_column(&ra, desc, entity));
        CT_BREAK_IF_ERROR(knl_internal_insert(knl_session, cursor));
        status = CT_SUCCESS;
    } while (0);

    CM_RESTORE_STACK(knl_session->stack);
    return status;
}

status_t pl_delete_sysproc_by_trig(knl_session_t *session, text_t *tab_user, text_t *tab_name, uint64 target_oid,
    uint32 *uid, bool32 *exists)
{
    uint64 obj;
    knl_cursor_t *cursor = NULL;
    knl_set_session_scn(session, CT_INVALID_ID64);
    CM_SAVE_STACK(session->stack);

    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_PROC_ID, IX_PROC_002_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    // table name len is not greater 68
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, tab_name->str,
        (uint16)tab_name->len, IX_COL_PROC_002_TRIG_TABLE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, tab_user->str,
        (uint16)tab_user->len, IX_COL_PROC_002_TRIG_TABLE_USER);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    *exists = CT_FALSE;
    while (!cursor->eof) {
        obj = *(int64 *)CURSOR_COLUMN_DATA(cursor, SYS_PROC_OBJ_ID_COL);
        if (target_oid == obj) {
            if (knl_internal_delete(session, cursor) != CT_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return CT_ERROR;
            }
            *uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PROC_USER_COL);
            *exists = CT_TRUE;
            return CT_SUCCESS;
        }

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

status_t pl_delete_sys_proc(knl_session_t *session, uint64 oid, uint32 uid)
{
    knl_cursor_t *cursor = NULL;

    knl_set_session_scn(session, CT_INVALID_ID64);

    CM_SAVE_STACK(session->stack);

    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_PROC_ID, IX_PROC_003_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &uid, sizeof(int32), 0);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, &oid, sizeof(oid), 1);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CT_THROW_ERROR(ERR_OBJECT_ID_NOT_EXIST, "object", oid);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (knl_internal_delete(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

status_t pl_update_language(knl_session_t *session, pl_desc_t *desc, pl_entity_t *entity)
{
    status_t status = CT_ERROR;
    knl_cursor_t *cursor = NULL;
    knl_update_info_t *update_info = NULL;
    row_assist_t ra;

    knl_set_session_scn(session, CT_INVALID_ID64);

    CM_SAVE_STACK(session->stack);

    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_PROC_ID, IX_PROC_003_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &desc->uid,
        sizeof(desc->uid), IX_PROC_003_ID_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, &desc->oid,
        sizeof(desc->oid), IX_PROC_003_ID_OBJ);

    do {
        CT_BREAK_IF_ERROR(knl_fetch(session, cursor));
        if (cursor->eof) {
            CT_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "object", desc->name);
            break;
        }

        update_info = &cursor->update_info;
        row_init(&ra, update_info->data, CT_MAX_ROW_SIZE, 3);
        CT_BREAK_IF_ERROR(pl_process_lib_column(&ra, desc, entity));
        update_info->count = 3;
        update_info->columns[0] = SYS_PROC_FLAGS_COL;
        update_info->columns[1] = SYS_PROC_LIB_NAME_COL;
        update_info->columns[2] = SYS_PROC_LIB_USER_COL;
        cm_decode_row(update_info->data, update_info->offsets, update_info->lens, NULL);
        CT_BREAK_IF_ERROR(knl_internal_update(session, cursor));
        status = CT_SUCCESS;
    } while (0);

    CM_RESTORE_STACK(session->stack);

    return status;
}

status_t pl_update_sys_proc_source(knl_session_t *session, pl_desc_t *desc, pl_entity_t *entity)
{
    status_t status = CT_ERROR;
    knl_cursor_t *cursor = NULL;
    knl_column_t *column = NULL;
    knl_update_info_t *update_info = NULL;
    row_assist_t ra;

    knl_set_session_scn(session, CT_INVALID_ID64);

    CM_SAVE_STACK(session->stack);

    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_PROC_ID, IX_PROC_003_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &desc->uid, sizeof(int32),
        0);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, &desc->oid,
        sizeof(desc->oid), 1);

    do {
        CT_BREAK_IF_ERROR(knl_fetch(session, cursor));
        if (cursor->eof) {
            CT_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "object", desc->name);
            break;
        }

        column = knl_get_column(cursor->dc_entity, SYS_PROC_SOURCE_COL);
        update_info = &cursor->update_info;
        row_init(&ra, update_info->data, CT_MAX_ROW_SIZE, 4);
        CT_BREAK_IF_ERROR(knl_row_put_lob(session, cursor, column, &entity->create_def->source, &ra));
        // The current application scenario will not return a failure
        CT_BREAK_IF_ERROR(row_put_int64(&ra, (int64)desc->chg_scn));
        CT_BREAK_IF_ERROR(row_put_int32(&ra, (int32)entity->create_def->compl_result));
        CT_BREAK_IF_ERROR(row_put_int32(&ra, (int32)entity->is_auton_trans));
        update_info->count = 4;
        update_info->columns[0] = SYS_PROC_SOURCE_COL;
        update_info->columns[1] = SYS_PROC_CHG_SCN_COL;
        update_info->columns[2] = SYS_PROC_STATUS_COL;
        update_info->columns[3] = SYS_PROC_AGGREGATE_COL;
        cm_decode_row(update_info->data, update_info->offsets, update_info->lens, NULL);
        CT_BREAK_IF_ERROR(knl_internal_update(session, cursor));
        status = CT_SUCCESS;
    } while (0);

    CM_RESTORE_STACK(session->stack);

    return status;
}

status_t pl_check_update_sysproc(knl_session_t *session, pl_desc_t *desc)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    knl_update_info_t *update_info = NULL;
    knl_set_session_scn(session, CT_INVALID_ID64);

    CM_SAVE_STACK(session->stack);

    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_STACK_OVERFLOW);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_PROC_ID, IX_PROC_003_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &desc->uid, sizeof(int32),
        IX_PROC_003_ID_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, &desc->oid,
        sizeof(desc->oid), IX_PROC_003_ID_OBJ);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        return CT_SUCCESS;
    }

    update_info = &cursor->update_info;
    row_init(&ra, update_info->data, CT_MAX_ROW_SIZE, 1);
    // The current application scenario will not return a failure
    (void)row_put_int32(&ra, (int32)desc->status);
    update_info->count = 1;
    update_info->columns[0] = SYS_PROC_STATUS_COL;
    cm_decode_row(update_info->data, update_info->offsets, update_info->lens, NULL);

    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t pl_update_sysproc_status(knl_session_t *session, pl_desc_t *desc)
{
    knl_cursor_t *cursor = NULL;
    status_t status = CT_ERROR;
    row_assist_t ra;
    knl_update_info_t *update_info = NULL;
    knl_set_session_scn(session, CT_INVALID_ID64);

    CM_SAVE_STACK(session->stack);

    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_STACK_OVERFLOW);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    do {
        knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_PROC_ID, IX_PROC_003_ID);
        knl_init_index_scan(cursor, CT_TRUE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &desc->uid,
            sizeof(int32), IX_PROC_003_ID_USER);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, &desc->oid,
            sizeof(desc->oid), IX_PROC_003_ID_OBJ);

        CT_BREAK_IF_ERROR(knl_fetch(session, cursor));

        if (cursor->eof) {
            CT_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "object", desc->name);
            break;
        }

        update_info = &cursor->update_info;
        row_init(&ra, update_info->data, CT_MAX_ROW_SIZE, 1);
        // The current application scenario will not return a failure
        (void)row_put_int32(&ra, (int32)desc->status);
        update_info->count = 1;
        update_info->columns[0] = SYS_PROC_STATUS_COL;
        cm_decode_row(update_info->data, update_info->offsets, update_info->lens, NULL);
        CT_BREAK_IF_ERROR(knl_internal_update(session, cursor));
        status = CT_SUCCESS;
    } while (0);

    CM_RESTORE_STACK(session->stack);
    return status;
}

status_t pl_load_sysproc_source(knl_session_t *session, pl_desc_t *desc, pl_source_pages_t *source_page, text_t *source,
    bool32 *new_page)
{
    uint32 source_len;
    char *locator = NULL;
    knl_cursor_t *cursor = NULL;
    status_t status = CT_ERROR;

    knl_set_session_scn(session, CT_INVALID_ID64);

    CM_SAVE_STACK(session->stack);

    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_STACK_OVERFLOW);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    *new_page = CT_FALSE;
    do {
        knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_PROC_ID, IX_PROC_003_ID);
        knl_init_index_scan(cursor, CT_TRUE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &desc->uid,
            sizeof(int32), 0);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, &desc->oid,
            sizeof(desc->oid), 1);

        CT_BREAK_IF_ERROR(knl_fetch(session, cursor));

        if (cursor->eof) {
            CT_THROW_ERROR(ERR_OBJECT_ID_NOT_EXIST, "object", desc->oid);
            status = CT_ERROR;
            break;
        }
        desc->status = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PROC_STATUS_COL);
        locator = CURSOR_COLUMN_DATA(cursor, SYS_PROC_SOURCE_COL);
        source_len = knl_lob_size(locator);
        if (pl_alloc_source_page(session, source_page, source_len, &source->str, new_page) != CT_SUCCESS) {
            break;
        }

        if (knl_read_lob(session, locator, 0, source->str, CT_LARGE_PAGE_SIZE, &source->len, NULL) != CT_SUCCESS) {
            pl_free_source_page(source_page, *new_page);
            break;
        }

        status = CT_SUCCESS;
    } while (0);

    CM_RESTORE_STACK(session->stack);

    return status;
}


status_t pl_delete_obj_priv(knl_session_t *session, pl_entry_t *entry, object_type_t type)
{
    if (db_drop_object_privs(session, entry->desc.uid, entry->desc.name, type)) {
        return CT_ERROR;
    }

    dc_drop_object_privs(&session->kernel->dc_ctx, entry->desc.uid, entry->desc.name, type);
    return CT_SUCCESS;
}

status_t pl_get_desc_objaddr(object_address_t *obj_addr, pl_desc_t *desc)
{
    obj_addr->uid = desc->uid;
    obj_addr->oid = (uint64)desc->oid;
    obj_addr->tid = pltype_to_objtype(desc->type);
    obj_addr->scn = desc->chg_scn;
    MEMS_RETURN_IFERR(strcpy_s(obj_addr->name, CT_NAME_BUFFER_SIZE, desc->name));
    return CT_SUCCESS;
}

status_t pl_delete_dependency(knl_session_t *session, object_address_t *obj_addr)
{
    return knl_delete_dependency(session, obj_addr->uid, obj_addr->oid, obj_addr->tid);
}

status_t pl_insert_dependency_list(knl_session_t *session, object_address_t *obj_addr, galist_t *ref_list)
{
    return knl_insert_dependency_list(session, obj_addr, ref_list);
}

status_t pl_update_depender_status(knl_session_t *session, object_address_t *obj_addr)
{
    obj_info_t *curr_obj = (obj_info_t *)obj_addr;
    return sql_update_depender_status(session, curr_obj);
}