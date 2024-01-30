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
 * rb_purge.c
 *
 *
 * IDENTIFICATION
 * src/kernel/flashback/rb_purge.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_flash_module.h"
#include "rb_purge.h"
#include "index_common.h"
#include "knl_context.h"
#include "knl_table.h"
#include "knl_ctlg.h"
#include "dc_log.h"

/*
 * fetch a recycle bin object by origin name
 * @param kernel session, purge object, object type, object description(output)
 * @note if there are two object whose origin name are same, we fetch the oldest object
 * to purge.
 */
status_t rb_purge_fetch_name(knl_session_t *session, knl_purge_def_t *def, rb_object_type_t type, knl_rb_desc_t *desc)
{
    char part_name[CT_NAME_BUFFER_SIZE];
    knl_cursor_t *cursor = NULL;
    uint32 uid;

    if (!dc_get_user_id(session, &def->owner, &uid)) {
        CT_THROW_ERROR(ERR_RECYCLE_OBJ_NOT_EXIST, T2S(&def->owner), T2S_EX(&def->name));
        return CT_ERROR;
    }

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_RB_ID, 0);
    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, 0);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, 0);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    while (!cursor->eof) {
        rb_convert_desc(cursor, desc);

        if (desc->type == type && desc->uid == uid &&
            cm_text_str_equal(&def->name, desc->org_name) &&
            (def->part_name.str == NULL || cm_text_str_equal(&def->part_name, desc->part_name))) {
            CM_RESTORE_STACK(session->stack);
            return CT_SUCCESS;
        }

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    if (def->part_name.str == NULL) {
        CT_THROW_ERROR(ERR_RECYCLE_OBJ_NOT_EXIST, T2S(&def->owner), T2S_EX(&def->name));
    } else {
        (void)cm_text2str(&def->part_name, part_name, CT_NAME_BUFFER_SIZE);
        CT_THROW_ERROR(ERR_RECYCLE_PARTITION_NOT_EXIST, T2S(&def->owner), T2S_EX(&def->name), part_name);
    }

    return CT_ERROR;
}

/*
 * fetch a recycle bin object by object name
 * @param kernel session, purge object, object type, object description(output)
 */
status_t rb_purge_fetch_object(knl_session_t *session, knl_purge_def_t *def,
                               rb_object_type_t type, knl_rb_desc_t *desc)
{
    char buf[CT_NAME_BUFFER_SIZE];
    knl_cursor_t *cursor = NULL;
    errno_t ret;

    desc->id = CT_INVALID_ID64;
    (void)cm_text2str(&def->name, buf, CT_NAME_BUFFER_SIZE);
    ret = sscanf_s(buf, "BIN$%u$%llX", &desc->table_id, &desc->id);
    knl_securec_check_ss(ret);

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_RB_ID, IX_SYS_RB001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key,
                     CT_TYPE_BIGINT, &desc->id, sizeof(uint64), IX_COL_SYS_RB001_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_RECYCLE_OBJ_NOT_EXIST, T2S(&def->owner), T2S_EX(&def->name));
        return CT_ERROR;
    }

    rb_convert_desc(cursor, desc);
    CM_RESTORE_STACK(session->stack);

    if (desc->type != type) {
        CT_THROW_ERROR_EX(ERR_RECYCLEBIN_MISMATCH, "%s type does not match expected type", T2S(&def->name));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/*
 * fetch a recycle bin drop table
 * @param kernel session, user, table name, object description(output)
 * @note if there are two object whose origin names are same, we fetch the newest table
 * to flashback.
 */
status_t rb_fetch_drop_table(knl_session_t *session, text_t *user, text_t *name, knl_rb_desc_t *desc)
{
    knl_cursor_t *cursor = NULL;
    uint32 uid;

    if (!dc_get_user_id(session, user, &uid)) {
        CT_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(user));
        return CT_ERROR;
    }

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_RB_ID, 0);
    cursor->index_dsc = CT_TRUE;

    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, 0);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, 0);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    while (!cursor->eof) {
        rb_convert_desc(cursor, desc);

        if (desc->type == RB_TABLE_OBJECT && desc->oper == RB_OPER_DROP &&
            desc->uid == uid && cm_text_str_equal(name, desc->org_name)) {
            CM_RESTORE_STACK(session->stack);
            return CT_SUCCESS;
        }

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    CT_THROW_ERROR(ERR_RECYCLE_OBJ_NOT_EXIST, T2S(user), T2S_EX(name));
    return CT_ERROR;
}

/*
 * fetch a recycle bin truncate table
 * @param kernel session, kernel dictionary, object description(output)
 * @note if there are two object whose origin names are same, we fetch the newest table
 * to flashback.
 */
status_t rb_fetch_truncate_table(knl_session_t *session, knl_dictionary_t *dc, knl_rb_desc_t *desc)
{
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_RB_ID, IX_SYS_RB001_ID);
    cursor->index_dsc = CT_TRUE;

    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_RB001_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_RB001_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    while (!cursor->eof) {
        rb_convert_desc(cursor, desc);

        if (desc->type == RB_TABLE_OBJECT && desc->oper == RB_OPER_TRUNCATE &&
            desc->uid == dc->uid && desc->table_id == dc->oid) {
            CM_RESTORE_STACK(session->stack);
            return CT_SUCCESS;
        }

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    CT_THROW_ERROR(ERR_RECYCLE_OBJ_NOT_EXIST, DC_ENTRY_USER_NAME(dc), DC_ENTRY_NAME(dc));
    return CT_ERROR;
}

/*
 * fetch a recycle bin truncate table part
 * @param kernel session, kernel dictionary, object description(output)
 * @note if there are two object whose origin names are same, we fetch the newest table part
 * to flashback.
 */
status_t rb_fetch_truncate_tabpart(knl_session_t *session, knl_dictionary_t *dc,
                                   table_part_t *table_part, knl_rb_desc_t *desc)
{
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_RB_ID, IX_SYS_RB001_ID);
    cursor->index_dsc = CT_TRUE;

    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_RB001_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_RB001_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    while (!cursor->eof) {
        rb_convert_desc(cursor, desc);

        if (desc->type == RB_TABLE_PART_OBJECT && desc->oper == RB_OPER_TRUNCATE &&
            desc->uid == dc->uid && desc->table_id == dc->oid &&
            desc->id == desc->base_id && desc->org_scn == table_part->desc.org_scn &&
            cm_str_equal_ins(desc->part_name, table_part->desc.name)) {
            CM_RESTORE_STACK(session->stack);
            return CT_SUCCESS;
        }

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    CT_THROW_ERROR(ERR_RECYCLE_PARTITION_NOT_EXIST, DC_ENTRY_USER_NAME(dc), DC_ENTRY_NAME(dc), table_part->desc.name);
    return CT_ERROR;
}

/*
 * fetch the base object of current object
 * We can use table_id decoded from current object and base_id to construct the
 * base object name, so that we can use the index on obj_name column to scan
 * the related object quickly.
 * @param kernel session, object description(input with output)
 * @notes this may cause recursive function call.
 */
static status_t rb_fetch_base_object(knl_session_t *session, knl_rb_desc_t *desc)
{
    knl_cursor_t *cursor = NULL;

    if (desc->id == desc->base_id) {
        return CT_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_RB_ID, IX_SYS_RB001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key,
                     CT_TYPE_BIGINT, &desc->base_id, sizeof(uint64), IX_COL_SYS_RB001_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_OBJECT_ID_NOT_EXIST, "recyclebin base object", desc->base_id);
        return CT_ERROR;
    }

    rb_convert_desc(cursor, desc);
    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

/*
 * fetch the base object of current object
 * We can use table_id decoded from current object and base_id to construct the
 * base object name, so that we can use the index on obj_name column to scan
 * the related object quickly.
 * @param kernel session, object description(input with output)
 * @notes this may cause recursive function call.
 */
static status_t rb_fetch_purge_object(knl_session_t *session, knl_rb_desc_t *desc)
{
    knl_cursor_t *cursor = NULL;

    if (desc->id == desc->purge_id) {
        if (!desc->can_purge || desc->is_cons) {
            if (rb_fetch_base_object(session, desc) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
        return CT_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_RB_ID, IX_SYS_RB001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT,
                     &desc->purge_id, sizeof(uint64), IX_COL_SYS_RB001_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_OBJECT_ID_NOT_EXIST, "recyclebin purge object", desc->purge_id);
        return CT_ERROR;
    }

    rb_convert_desc(cursor, desc);
    CM_RESTORE_STACK(session->stack);

    if (!desc->can_purge || desc->is_cons) {
        if (rb_fetch_base_object(session, desc) != CT_SUCCESS) {
            return CT_SUCCESS;
        }
    }

    return CT_SUCCESS;
}

/*
 * fetch a recycle bin object
 * Fetch a recycle bin object to purge, so we should fetch the base object.
 * @param kernel session, object description(output), found(output)
 */
status_t rb_purge_fetch(knl_session_t *session, knl_rb_desc_t *desc, bool32 *found)
{
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_RB_ID, CT_INVALID_ID32);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        *found = CT_FALSE;
        CM_RESTORE_STACK(session->stack);
        return CT_SUCCESS;
    }

    *found = CT_TRUE;
    rb_convert_desc(cursor, desc);
    CM_RESTORE_STACK(session->stack);

    if (rb_fetch_base_object(session, desc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/*
 * fetch a space recycle bin object
 * In fetch space, we use current scn instead of session query scn as cursor query scn
 * 'causing in space auto purging, we want to check if there is any objects in recycle bin
 * now, but we should not change the current session query scn which is being used for
 * visibility judgment.
 * @param kernel session, space id, object description(output), found(output)
 * @note if there are two object whose origin names are same, we fetch the oldest table
 * to purge.
 */
status_t rb_purge_fetch_space(knl_session_t *session, uint32 space_id, knl_rb_desc_t *desc, bool32 *found)
{
    knl_cursor_t *cursor = NULL;
    knl_rb_desc_t temp;
    errno_t ret;

    *found = CT_FALSE;
    desc->rec_scn = CT_INVALID_ID64;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_RB_ID, IX_SYS_RB003_ID);
    cursor->query_scn = DB_CURR_SCN(session);
    cursor->query_lsn = DB_CURR_LSN(session);

    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key,
                     CT_TYPE_INTEGER, &space_id, sizeof(uint32), IX_COL_SYS_RB003_SPACE_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    while (!cursor->eof) {
        rb_convert_desc(cursor, &temp);

        if (temp.rec_scn < desc->rec_scn) {
            ret = memcpy_sp(desc, sizeof(knl_rb_desc_t), &temp, sizeof(knl_rb_desc_t));
            knl_securec_check(ret);
            *found = CT_TRUE;
        }

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    if (*found) {
        if (rb_fetch_purge_object(session, desc) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

/*
 * delete the specified recycle bin object and its related objects
 * @param kernel session, object description
 */
static status_t rb_purge_delete(knl_session_t *session, knl_rb_desc_t *desc)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    knl_rb_desc_t temp;
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_RB_ID, IX_SYS_RB002_ID);

    if (desc->purge_id == desc->base_id) {
        knl_init_index_scan(cursor, CT_FALSE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, &desc->base_id,
                         sizeof(uint64), IX_COL_SYS_RB002_BASE_ID);
        knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_RB002_PURGE_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_BIGINT, &desc->base_id,
                         sizeof(uint64), IX_COL_SYS_RB002_BASE_ID);
        knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_RB002_PURGE_ID);
    } else {
        knl_init_index_scan(cursor, CT_TRUE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, &desc->base_id,
                         sizeof(uint64), IX_COL_SYS_RB002_BASE_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, &desc->purge_id,
                         sizeof(uint64), IX_COL_SYS_RB002_PURGE_ID);
    }

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_RECYCLE_OBJ_NOT_EXIST, ctx->users[desc->uid]->desc.name, desc->org_name);
        return CT_ERROR;
    }

    while (!cursor->eof) {
        rb_convert_desc(cursor, &temp);

        if (knl_internal_delete(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

/*
 * fetch truncate recycle bin object
 * @param kernel session, user id, table id, object description, found(output)
 */
static status_t rb_fetch_truncate(knl_session_t *session, uint32 uid, uint32 oid, knl_rb_desc_t *desc, bool32 *found)
{
    knl_cursor_t *cursor = NULL;

    *found = CT_FALSE;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_RB_ID, CT_INVALID_ID32);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    while (!cursor->eof) {
        rb_convert_desc(cursor, desc);

        if (desc->oper == RB_OPER_TRUNCATE &&
            desc->uid == uid && desc->table_id == oid &&
            desc->id == desc->base_id) {
            *found = CT_TRUE;
            break;
        }

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

/*
 * fetch a recycle bin truncate table subpart
 * @param kernel session, kernel dictionary, object description(output)
 * @note if there are two object whose origin names are same, we fetch the newest table part
 * to flashback.
 */
static status_t rb_fetch_truncate_subtabpart(knl_session_t *session, knl_dictionary_t *dc, table_part_t *subpart,
    knl_rb_desc_t *desc)
{
    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_RB_ID, IX_SYS_RB001_ID);
    cursor->index_dsc = CT_TRUE;

    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_RB001_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_RB001_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    while (!cursor->eof) {
        rb_convert_desc(cursor, desc);

        if (desc->type == RB_TABLE_SUBPART_OBJECT && desc->oper == RB_OPER_TRUNCATE &&
            desc->uid == dc->uid && desc->table_id == dc->oid &&
            desc->id == desc->base_id && desc->org_scn == subpart->desc.org_scn &&
            cm_str_equal_ins(desc->part_name, subpart->desc.name)) {
            CM_RESTORE_STACK(session->stack);
            return CT_SUCCESS;
        }

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    CT_THROW_ERROR(ERR_RECYCLE_PARTITION_NOT_EXIST, DC_ENTRY_USER_NAME(dc), DC_ENTRY_NAME(dc), subpart->desc.name);
    return CT_ERROR;
}

/*
 * purge truncate object and related objects
 */
static status_t rb_purge_truncate(knl_session_t *session, knl_rb_desc_t *desc)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    knl_cursor_t *cursor = NULL;
    status_t status = CT_ERROR;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_RB_ID, IX_SYS_RB002_ID);
    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key,
                     CT_TYPE_BIGINT, &desc->base_id, sizeof(uint64), IX_COL_SYS_RB002_BASE_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_RB002_PURGE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key,
                     CT_TYPE_BIGINT, &desc->base_id, sizeof(uint64), IX_COL_SYS_RB002_BASE_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_RB002_PURGE_ID);
    
    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_RECYCLE_OBJ_NOT_EXIST, ctx->users[desc->uid]->desc.name, desc->org_name);
        return CT_ERROR;
    }

    while (!cursor->eof) {
        rb_convert_desc(cursor, desc);

        switch (desc->type) {
            case RB_TABLE_OBJECT:
            case RB_TABLE_PART_OBJECT:
            case RB_TABLE_SUBPART_OBJECT:
                status = heap_purge_prepare(session, desc);
                break;

            case RB_INDEX_OBJECT:
            case RB_INDEX_PART_OBJECT:
            case RB_INDEX_SUBPART_OBJECT:
                status = btree_purge_prepare(session, desc);
                break;

            case RB_LOB_OBJECT:
            case RB_LOB_PART_OBJECT:
            case RB_LOB_SUBPART_OBJECT:
                status = lob_purge_prepare(session, desc);
                break;

            default:
                CM_RESTORE_STACK(session->stack);
                CT_THROW_ERROR(ERR_INVALID_PURGE_TYPE, desc->type);
                return CT_ERROR;
        }

        if (status != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (knl_internal_delete(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    knl_commit(session);

    if (db_garbage_segment_handle(session, desc->uid, desc->table_id, CT_TRUE) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("failed to handle garbage segment");
        cm_spin_lock(&session->kernel->rmon_ctx.mark_mutex, NULL);
        session->kernel->rmon_ctx.delay_clean_segments = CT_TRUE;
        cm_spin_unlock(&session->kernel->rmon_ctx.mark_mutex);
    }

    return CT_SUCCESS;
}

/*
 * purge drop related
 * Truncated objects in recycle bin should be purged when drop table
 * or purge drop table
 * @param kernel session, user id, table id
 */
status_t rb_purge_drop_related(knl_session_t *session, uint32 uid, uint32 oid)
{
    knl_rb_desc_t desc;
    bool32 found = CT_FALSE;

    knl_set_session_scn(session, CT_INVALID_ID64);

    if (rb_fetch_truncate(session, uid, oid, &desc, &found) != CT_SUCCESS) {
        return CT_ERROR;
    }

    while (found) {
        if (rb_purge_truncate(session, &desc) != CT_SUCCESS) {
            return CT_ERROR;
        }

        knl_set_session_scn(session, CT_INVALID_ID64);

        if (rb_fetch_truncate(session, uid, oid, &desc, &found) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

/*
 * purge drop table from recycle bin
 * Causing we are still holding the dc entry, so we can use the db drop table
 * interface directly.
 * @param kernel session, kernel dictionary, object description
 * @note when purge drop table, we should purge truncate object related to current table
 */
static status_t rb_purge_drop_table(knl_session_t *session, knl_rb_desc_t *desc)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    knl_dictionary_t dc;

    if (knl_open_dc_by_id(session, desc->uid, desc->table_id, &dc, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (desc->org_scn != dc.org_scn) {
        CT_THROW_ERROR(ERR_RECYCLE_OBJ_NOT_EXIST, ctx->users[desc->uid]->desc.name, desc->org_name);
        dc_close(&dc);
        return CT_ERROR;
    }

    uint32 timeout = session->kernel->attr.ddl_lock_timeout;
    if (lock_table_directly(session, &dc, timeout) != CT_SUCCESS) {
        dc_close(&dc);
        return CT_ERROR;
    }

    if (rb_purge_drop_related(session, dc.uid, dc.oid) != CT_SUCCESS) {
        unlock_tables_directly(session);
        dc_close(&dc);
        return CT_ERROR;
    }

    if (rb_purge_delete(session, desc) != CT_SUCCESS) {
        unlock_tables_directly(session);
        dc_close(&dc);
        return CT_ERROR;
    }

    if (db_drop_table(session, NULL, &dc, CT_TRUE) != CT_SUCCESS) {
        unlock_tables_directly(session);
        dc_close(&dc);
        return CT_ERROR;
    }

    unlock_tables_directly(session);
    dc_free_entry(session, DC_ENTRY(&dc));
    dc_close(&dc);
    return CT_SUCCESS;
}

/*
 * purge drop index from recycle bin
 * @param kernel session, kernel dictionary, object description
 */
static status_t rb_purge_drop_index(knl_session_t *session, knl_rb_desc_t *desc)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    knl_rb_desc_t bo_desc;
    knl_dictionary_t dc;
    knl_index_desc_t index_desc;
    text_t index_name;
    rd_table_t redo;
    index_t *index = NULL;
    errno_t ret;

    ret = memcpy_sp(&bo_desc, sizeof(knl_rb_desc_t), desc, sizeof(knl_rb_desc_t));
    knl_securec_check(ret);
    if (rb_fetch_base_object(session, &bo_desc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_open_dc_by_id(session, desc->uid, desc->table_id, &dc, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (bo_desc.org_scn != dc.org_scn) {
        CT_THROW_ERROR(ERR_RECYCLE_OBJ_NOT_EXIST, ctx->users[desc->uid]->desc.name, desc->org_name);
        dc_close(&dc);
        return CT_ERROR;
    }

    uint32 timeout = session->kernel->attr.ddl_lock_timeout;
    if (lock_table_directly(session, &dc, timeout) != CT_SUCCESS) {
        dc_close(&dc);
        return CT_ERROR;
    }

    cm_str2text(desc->name, &index_name);
    if (db_fetch_index_desc(session, desc->uid, desc->table_id, &index_name, &index_desc) != CT_SUCCESS) {
        unlock_tables_directly(session);
        dc_close(&dc);
        return CT_ERROR;
    }

    if (rb_purge_delete(session, desc) != CT_SUCCESS) {
        unlock_tables_directly(session);
        dc_close(&dc);
        return CT_ERROR;
    }

    index = dc_find_index_by_id((dc_entity_t *)dc.handle, index_desc.id);
    if (index == NULL) {
        unlock_tables_directly(session);
        dc_close(&dc);
        CT_THROW_ERROR(ERR_OBJECT_ID_NOT_EXIST, "index", index_desc.id);
        return CT_ERROR;
    }
    if (index->desc.is_enforced) {
        unlock_tables_directly(session);
        dc_close(&dc);
        CT_THROW_ERROR(ERR_INDEX_ENFORCEMENT);
        return CT_ERROR;
    }

    if (db_drop_index(session, index, &dc) != CT_SUCCESS) {
        unlock_tables_directly(session);
        dc_close(&dc);
        return CT_ERROR;
    }

    redo.op_type = RD_ALTER_TABLE;
    redo.uid = dc.uid;
    redo.oid = dc.oid;
    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_table_t), LOG_ENTRY_FLAG_NONE);

    SYNC_POINT(session, "SP_B1_PURGE_INDEX");
    knl_commit(session);

    if (db_garbage_segment_handle(session, dc.uid, dc.oid, CT_FALSE) != CT_SUCCESS) {
        cm_spin_lock(&session->kernel->rmon_ctx.mark_mutex, NULL);
        session->kernel->rmon_ctx.delay_clean_segments = CT_TRUE;
        cm_spin_unlock(&session->kernel->rmon_ctx.mark_mutex);
        CT_LOG_RUN_ERR("failed to handle garbage segment");
    }

    dc_invalidate(session, (dc_entity_t *)dc.handle);
    unlock_tables_directly(session);
    dc_close(&dc);
    return CT_SUCCESS;
}

/*
 * purge table object from recycle bin
 * The table object may be a truncated table or a dropped table
 * @param kernel session, object description
 * @note we should check the origin scn before we lock the table,
 * maybe someone has just purged the table we fetched and then creates
 * a new table which reuses the same table id.
 */
status_t rb_purge_table(knl_session_t *session, knl_rb_desc_t *desc)
{
    switch (desc->oper) {
        case RB_OPER_DROP:
            return rb_purge_drop_table(session, desc);

        case RB_OPER_TRUNCATE:
            return rb_purge_truncate(session, desc);

        default:
            CT_THROW_ERROR(ERR_INVALID_PURGE_OPER, "invalid purge table operation");
            return CT_ERROR;
    }
}

/*
 * purge index object from recycle bin
 * The index object may be a truncated index or a dropped index
 * @param kernel session, object description
 * @note if the index object is a truncated index, it should be truncated
 * with table to recycle bin at the same time. we must fetch the base truncate
 * table object, and purge the table with its related object.
 */
status_t rb_purge_index(knl_session_t *session, knl_rb_desc_t *desc)
{
    switch (desc->oper) {
        case RB_OPER_DROP:
            return rb_purge_drop_index(session, desc);

        case RB_OPER_TRUNCATE:
            CT_THROW_ERROR(ERR_INVALID_PURGE_OPER, "cannot purge index");
            return CT_ERROR;

        default:
            CT_THROW_ERROR(ERR_INVALID_PURGE_OPER, "invalid purge index operation");
            return CT_ERROR;
    }
}

status_t rb_purge_table_part(knl_session_t *session, knl_rb_desc_t *desc)
{
    if (desc->id != desc->purge_id) {
        CT_THROW_ERROR(ERR_INVALID_PURGE_OPER, "cannot purge table or partition");
        return CT_ERROR;
    }

    return rb_purge_truncate(session, desc);
}

/*
 * purge a recycle bin object
 * Using an autonomous session to purge the object, to avoid the
 * purging process effect current process of the session.
 * @param kernel session, origin description
 */
status_t rb_purge(knl_session_t *session, knl_rb_desc_t *desc)
{
    status_t status;

    if (knl_begin_auton_rm(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    switch (desc->type) {
        case RB_TABLE_OBJECT:
            status = rb_purge_table(session, desc);
            break;

        case RB_INDEX_OBJECT:
            status = rb_purge_index(session, desc);
            break;

        case RB_TABLE_PART_OBJECT:
        case RB_TABLE_SUBPART_OBJECT:
            status = rb_purge_table_part(session, desc);
            break;

        default:
            CT_THROW_ERROR(ERR_INVALID_PURGE_TYPE, desc->type);
            status = CT_ERROR;
            break;
    }

    knl_end_auton_rm(session, status);

    return status;
}

/*
 * purge all objects in recycle bin
 */
status_t rb_purge_recyclebin(knl_session_t *session)
{
    knl_rb_desc_t desc;
    bool32 found = CT_FALSE;

    knl_set_session_scn(session, CT_INVALID_ID64);

    if (rb_purge_fetch(session, &desc, &found) != CT_SUCCESS) {
        return CT_ERROR;
    }

    while (found) {
        if (rb_purge(session, &desc) != CT_SUCCESS) {
            return CT_ERROR;
        }

        knl_set_session_scn(session, CT_INVALID_ID64);

        if (rb_purge_fetch(session, &desc, &found) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

/*
 * purge all objects of the specified space in recycle bin
 */
status_t rb_purge_space(knl_session_t *session, uint32 space_id)
{
    knl_rb_desc_t desc;
    bool32 found = CT_FALSE;

    knl_set_session_scn(session, CT_INVALID_ID64);

    if (rb_purge_fetch_space(session, space_id, &desc, &found) != CT_SUCCESS) {
        return CT_ERROR;
    }

    while (found) {
        if (rb_purge(session, &desc) != CT_SUCCESS) {
            return CT_ERROR;
        }

        knl_set_session_scn(session, CT_INVALID_ID64);

        if (rb_purge_fetch_space(session, space_id, &desc, &found) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t rb_fetch_uid(knl_session_t *session, uint32 uid, knl_rb_desc_t *desc, bool32 *found)
{
    knl_cursor_t *cursor = NULL;
    knl_rb_desc_t temp;
    errno_t ret;

    *found = CT_FALSE;
    desc->rec_scn = CT_INVALID_ID64;

    CM_SAVE_STACK(session->stack)

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_RB_ID, IX_SYS_RB004_ID);
    cursor->query_scn = DB_CURR_SCN(session);
    cursor->query_lsn = DB_CURR_LSN(session);

    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key,
                     CT_TYPE_INTEGER, &uid, sizeof(uint32), IX_COL_SYS_RB004_USER_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    while (!cursor->eof) {
        rb_convert_desc(cursor, &temp);

        if (temp.rec_scn < desc->rec_scn) {
            ret = memcpy_sp(desc, sizeof(knl_rb_desc_t), &temp, sizeof(knl_rb_desc_t));
            knl_securec_check(ret);
            *found = CT_TRUE;
        }

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    if (*found) {
        if (rb_fetch_purge_object(session, desc) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

/*
 * purge all objects of the specified user id in recycle bin
 */
status_t rb_purge_user(knl_session_t *session, uint32 uid)
{
    knl_rb_desc_t desc;
    bool32 found = CT_FALSE;

    knl_set_session_scn(session, CT_INVALID_ID64);

    if (rb_fetch_uid(session, uid, &desc, &found) != CT_SUCCESS) {
        return CT_ERROR;
    }

    while (found) {
        if (rb_purge(session, &desc) != CT_SUCCESS) {
            return CT_ERROR;
        }

        knl_set_session_scn(session, CT_INVALID_ID64);

        if (rb_fetch_uid(session, uid, &desc, &found) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

/*
 * restore drop table from recycle bin
 * @param kernel session, object description, new name
 * @note if we specified a new name, we should rename the index either
 */
static status_t rb_restore_drop(knl_session_t *session, knl_rb_desc_t *desc, text_t *new_name)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    knl_rb_desc_t temp;
    text_t temp_name;
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_RB_ID, IX_SYS_RB002_ID);
    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key,
                     CT_TYPE_BIGINT, &desc->base_id, sizeof(uint64), IX_COL_SYS_RB002_BASE_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_RB002_PURGE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key,
                     CT_TYPE_BIGINT, &desc->base_id, sizeof(uint64), IX_COL_SYS_RB002_BASE_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_RB002_PURGE_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_RECYCLE_OBJ_NOT_EXIST, ctx->users[desc->uid]->desc.name, desc->org_name);
        return CT_ERROR;
    }

    while (!cursor->eof) {
        rb_convert_desc(cursor, &temp);

        switch (temp.type) {
            case RB_TABLE_OBJECT:
                if (new_name->str == NULL) {
                    cm_str2text(temp.org_name, &temp_name);
                } else {
                    temp_name = *new_name;
                }

                if (db_update_table_name(session, temp.uid, temp.name, &temp_name, CT_FALSE) != CT_SUCCESS) {
                    CM_RESTORE_STACK(session->stack);
                    CT_THROW_ERROR(ERR_OBJECT_EXISTS, "table", T2S(&temp_name));
                    return CT_ERROR;
                }
                break;

            case RB_INDEX_OBJECT:
                if (new_name->str == NULL) {
                    cm_str2text(temp.org_name, &temp_name);
                    if (db_update_index_name(session, temp.uid, temp.table_id, temp.name, &temp_name) != CT_SUCCESS) {
                        CM_RESTORE_STACK(session->stack);
                        CT_THROW_ERROR(ERR_OBJECT_EXISTS, "index", T2S(&temp_name));
                        return CT_ERROR;
                    }
                }
                break;

            default:
                CT_THROW_ERROR(ERR_INVALID_FLASHBACK_TYPE, temp.type);
                CM_RESTORE_STACK(session->stack);
                return CT_ERROR;
        }

        if (knl_internal_delete(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

/*
 * flashback drop table from recycle bin
 * Restore table and all its related drop object from recycle bin, restore
 * the dc entry, so user can see it from dc interface.
 * @param kernel session, flashback option
 * @note we should check the origin scn before we lock the table,
 * maybe someone has just purged the table we fetched and then creates
 * a new table which reuses the same table id.
 */
status_t rb_flashback_drop_table(knl_session_t *session, knl_flashback_def_t *def)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    knl_rb_desc_t desc;
    knl_dictionary_t dc;
    rd_flashback_drop_t rd;

    if (rb_fetch_drop_table(session, &def->owner, &def->name, &desc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_open_dc_by_id(session, desc.uid, desc.table_id, &dc, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc.type == DICT_TYPE_TABLE_EXTERNAL) {
        dc_close(&dc);
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "flashback table", "external organized table");
        return CT_ERROR;
    }
    
    if (desc.org_scn != dc.org_scn) {
        dc_close(&dc);
        CT_THROW_ERROR(ERR_RECYCLE_OBJ_NOT_EXIST, ctx->users[desc.uid]->desc.name, desc.org_name);
        return CT_ERROR;
    }

    uint32 timeout = session->kernel->attr.ddl_lock_timeout;
    if (lock_table_directly(session, &dc, timeout) != CT_SUCCESS) {
        dc_close(&dc);
        return CT_ERROR;
    }

    if (rb_restore_drop(session, &desc, &def->ext_name) != CT_SUCCESS) {
        unlock_tables_directly(session);
        dc_close(&dc);
        return CT_ERROR;
    }

    if (def->ext_name.str == NULL) {
        cm_str2text(desc.org_name, &def->ext_name);
    }

    dc_entity_t *entity = DC_ENTITY(&dc);
    if (!dc_restore(session, entity, &def->ext_name)) {
        unlock_tables_directly(session);
        dc_close(&dc);
        CT_THROW_ERROR(ERR_DUPLICATE_TABLE, T2S(&def->owner), T2S_EX(&def->ext_name));
        return CT_ERROR;
    }

    rd.op_type = RD_FLASHBACK_DROP;
    rd.uid = desc.uid;
    rd.table_id = desc.table_id;
    (void)cm_text2str(&def->ext_name, rd.new_name, CT_NAME_BUFFER_SIZE);
    log_put(session, RD_LOGIC_OPERATION, &rd, sizeof(rd_flashback_drop_t), LOG_ENTRY_FLAG_NONE);

    knl_commit(session);
    dc_invalidate(session, entity);
    unlock_tables_directly(session);
    dc_close(&dc);

    return CT_SUCCESS;
}

void rd_flashback_drop_table(knl_session_t *session, log_entry_t *log)
{
    if (log->size != CM_ALIGN4(sizeof(rd_flashback_drop_t)) + LOG_ENTRY_SIZE) {
        CT_LOG_RUN_ERR("[DC] no need to replay drop table, log size %u is wrong", log->size);
        return;
    }
    rd_flashback_drop_t *rd = (rd_flashback_drop_t *)log->data;
    rd->new_name[CT_NAME_BUFFER_SIZE - 1] = 0;
    knl_dictionary_t dc;
    text_t new_name;

    if (rd->table_id >= DC_GROUP_SIZE * DC_GROUP_COUNT) {
        CT_LOG_RUN_ERR("[RB] no need to replay drop table, invalid table id %u", rd->table_id);
        return;
    }
    if (knl_open_dc_by_id(session, rd->uid, rd->table_id, &dc, CT_FALSE) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RB] failed to replay flashback drop table id %u", rd->table_id);
        rd_check_dc_replay_err(session);
        return;
    }

    cm_str2text(rd->new_name, &new_name);
    (void)dc_restore(session, DC_ENTITY(&dc), &new_name);
    dc_invalidate(session, DC_ENTITY(&dc));
    dc_close(&dc);
}

void print_flashback_drop_table(log_entry_t *log)
{
    rd_flashback_drop_t *rd = (rd_flashback_drop_t *)log->data;
    printf("flashback drop uid:%u,oid:%u,name:%s\n", rd->uid, rd->table_id, rd->new_name);
}
/*
 * restore truncate table segment from recycle bin
 * This interface is simple, but reserved for future design
 * @param kernel session, kernel dictionary, object description
 */
static inline status_t rb_restore_table_segment(knl_session_t *session, knl_dictionary_t *dc, knl_rb_desc_t *desc)
{
    table_t *table = DC_TABLE(dc);

    if (db_update_table_entry(session, &table->desc, desc->entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/*
 * restore truncate table part segment from recycle bin
 * This interface is simple, but reserved for future design
 * @param kernel session, kernel dictionary, object description
 */
static status_t rb_restore_table_part_segment(knl_session_t *session, knl_dictionary_t *dc, knl_rb_desc_t *desc)
{
    table_t *table;
    table_part_t *table_part = NULL;
    text_t name;

    table = DC_TABLE(dc);
    knl_panic_log(IS_PART_TABLE(table), "current table is not part table, panic info: table %s rb_table %s",
                  table->desc.name, desc->name);
    cm_str2text(desc->part_name, &name);

    if (!part_table_find_by_name(table->part_table, &name, &table_part)) {
        CT_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", desc->part_name);
        return CT_ERROR;
    }

    /* for parent part, there is not need to update entry */
    if (IS_PARENT_TABPART(&table_part->desc)) {
        return CT_SUCCESS;
    }

    if (db_update_table_part_entry(session, &table_part->desc, desc->entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/*
 * restore truncate table subpart segment from recycle bin
 * @param kernel session, kernel dictionary, object description
 */
static status_t rb_restore_tabsubpart_segment(knl_session_t *session, knl_dictionary_t *dc, knl_rb_desc_t *desc)
{
    table_t *table = DC_TABLE(dc);
    text_t name;

    knl_panic_log(IS_PART_TABLE(table) && IS_COMPART_TABLE(table->part_table), "current table is not part table or "
        "the part_table is not compart_table, panic info: table %s rb_table %s", table->desc.name, desc->name);
    cm_str2text(desc->part_name, &name);

    table_part_t *compart = NULL;
    table_part_t *subpart = NULL;
    if (!subpart_table_find_by_name(table->part_table, &name, &compart, &subpart)) {
        CT_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", desc->part_name);
        return CT_ERROR;
    }

    if (db_update_subtabpart_entry(session, &subpart->desc, desc->entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/*
 * restore truncate index segment from recycle bin
 * The index id can be decoded from origin name in recycle bin.
 * So we can find the index we need to restore directly.
 * @param kernel session, kernel dictionary, object description
 */
static status_t rb_restore_index_segment(knl_session_t *session, knl_dictionary_t *dc, knl_rb_desc_t *desc)
{
    table_t *table = NULL;
    index_t *index;
    bool32 is_changed = CT_FALSE;
    errno_t ret;
    knl_index_desc_t index_desc;

    index = dc_find_index_by_scn((dc_entity_t *)dc->handle, desc->org_scn);
    if (index == NULL) {
        CT_THROW_ERROR_EX(ERR_RECYCLEBIN_MISMATCH, "index %s does not match flashback table %s.%s index",
                          desc->org_name, DC_ENTRY_USER_NAME(dc), DC_ENTRY_NAME(dc));
        return CT_ERROR;
    }

    table = DC_TABLE(dc);

    /*
     * global_index_invalid is for compatible with old version in these cases:
     * case 1 : index must was invalid if table can be truncated into recyclebin
     *     but recyclebin index entry is invalid
     * case 2 : global index is invalid after truncate partition,
     *     flashback to before truncate table should reset index to valid
     */
    bool32 global_index_invalid = (IS_PART_TABLE(table) && !IS_PART_INDEX(index) && IS_INVALID_PAGID(desc->entry));
    if (desc->is_invalid || global_index_invalid) {
        if (db_update_index_status(session, index, CT_TRUE, &is_changed) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (db_update_index_status(session, index, CT_FALSE, &is_changed) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    /*
     * since rebuild index may change the index space id, when restore,we have to set the space id to the
     * original one. Could not update the desc->space_id directly since it will change dictionary cache
     */
    ret = memcpy_sp(&index_desc, sizeof(knl_index_desc_t), &index->desc, sizeof(knl_index_desc_t));
    knl_securec_check(ret);
    index_desc.space_id = desc->space_id;
    if (db_update_index_entry(session, &index_desc, desc->entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/*
 * restore truncate index part segment from recycle bin
 * The index id can be decoded from origin name in recycle bin.
 * So we can find the index we need to restore directly.
 * @param kernel session, kernel dictionary, object description
 */
static status_t rb_restore_index_part_segment(knl_session_t *session, knl_dictionary_t *dc, knl_rb_desc_t *desc)
{
    table_t *table;
    index_t *index = NULL;
    index_part_t *index_part = NULL;
    uint32 index_id;
    uint32 part_no;
    bool32 is_changed = CT_FALSE;

    table = DC_TABLE(dc);
    knl_panic_log(IS_PART_TABLE(table), "current table is not part table, panic info: table %s rb_table %s",
                  table->desc.name, desc->name);
    errno_t ret = sscanf_s(desc->part_name, "INDEX%uP%u", &index_id, &part_no);
    knl_securec_check_ss(ret);
    knl_panic_log(part_no < table->part_table->desc.partcnt + CT_SPLIT_PART_COUNT,
                  "current part_no is abnormal, panic info: table %s rb_table %s part_no %u partcnt %u",
                  table->desc.name, desc->name, part_no, table->part_table->desc.partcnt);

    index = dc_find_index_by_id((dc_entity_t *)dc->handle, index_id);
    if (index == NULL) {
        CT_THROW_ERROR_EX(ERR_RECYCLEBIN_MISMATCH, "index %s part_no %u does not match flashback table %s.%s index",
                          desc->org_name, part_no, DC_ENTRY_USER_NAME(dc), DC_ENTRY_NAME(dc));
        return CT_ERROR;
    }

    knl_panic_log(IS_PART_INDEX(index), "current index is not part index, panic info: table %s rb_table %s index %s",
                  table->desc.name, desc->name, index->desc.name);

    index_part = INDEX_GET_PART(index, part_no);
    if (desc->is_invalid) {
        if (db_update_idxpart_status(session, index_part, CT_TRUE, &is_changed) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    /* for parent part, there is not need to update entry */
    if (IS_PARENT_IDXPART(&index_part->desc)) {
        return CT_SUCCESS;
    }
    index_part->desc.space_id = desc->space_id;
    if (db_upd_idx_part_entry(session, &index_part->desc, desc->entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/*
* restore truncate index subpart segment from recycle bin
* The index id, compart_no and subpart_no can be decoded from origin name in recycle bin.
* So we can find the index we need to restore directly.
* @param kernel session, kernel dictionary, object description
*/
static status_t rb_restore_idxsubpart_segment(knl_session_t *session, knl_dictionary_t *dc, knl_rb_desc_t *desc)
{
    uint32 idx_id, compart_no, part_no;
    table_t *table = DC_TABLE(dc);
    dc_entity_t *entity = DC_ENTITY(dc);

    knl_panic_log(IS_PART_TABLE(table) && IS_COMPART_TABLE(table->part_table), "current table is not part table or "
        "the part_table is not compart_table, panic info: table %s rb_table %s", entity->table.desc.name, desc->name);
    errno_t ret = sscanf_s(desc->part_name, "INDEX%uP%uSUBP%u", &idx_id, &compart_no, &part_no);
    knl_securec_check_ss(ret);
    
    index_t *index = dc_find_index_by_id(entity, idx_id);
    if (index == NULL) {
        CT_THROW_ERROR_EX(ERR_RECYCLEBIN_MISMATCH, "index %s does not match flashback table %s.%s index",
            desc->org_name, DC_ENTRY_USER_NAME(dc), DC_ENTRY_NAME(dc));
        return CT_ERROR;
    }

    knl_panic_log(IS_PART_INDEX(index) && IS_COMPART_INDEX(index->part_index), "current index is not part index or "
                  "the part_index is not compart_index, panic info: table %s rb_table %s index %s",
                  entity->table.desc.name, desc->name, index->desc.name);
    index_part_t *index_compart = INDEX_GET_PART(index, compart_no);
    index_part_t *index_subpart = PART_GET_SUBENTITY(index->part_index, index_compart->subparts[part_no]);
    if (desc->is_invalid) {
        bool32 is_changed = CT_FALSE;
        if (db_update_sub_idxpart_status(session, index_subpart, CT_TRUE, &is_changed) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    index_subpart->desc.space_id = desc->space_id;
    if (db_upd_sub_idx_part_entry(session, &index_subpart->desc, desc->entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/*
 * restore a truncate lob segment from recycle bin
 * The lob column id can be decoded from origin name in recycle bin.
 * So we can find the lob we need to restore directly.
 * @param kernel session, kernel dictionary, object description
 */
static status_t rb_restore_lob_segment(knl_session_t *session, knl_dictionary_t *dc, knl_rb_desc_t *desc)
{
    dc_entity_t *entity;
    lob_t *lob = NULL;
    knl_column_t *column = NULL;
    uint32 table_id, col_id;
    errno_t ret;

    entity = DC_ENTITY(dc);
    ret = sscanf_s(desc->org_name, "LOB%uC%u", &table_id, &col_id);
    knl_securec_check_ss(ret);
    knl_panic_log(desc->table_id == table_id, "rb's table_id is not equal table_id, panic info: table %s table_id %u "
                  "rb_table %s rb_table_id %u", entity->table.desc.name, table_id, desc->name, desc->table_id);

    column = dc_get_column(entity, col_id);
    if (!COLUMN_IS_LOB(column)) {
        CT_THROW_ERROR_EX(ERR_RECYCLEBIN_MISMATCH, "lob column id %u does not match table %s.%s column id",
                          col_id, DC_ENTRY_USER_NAME(dc), DC_ENTRY_NAME(dc));
        return CT_ERROR;
    }

    lob = (lob_t *)column->lob;
    if (db_update_lob_entry(session, &lob->desc, desc->entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/*
 * restore a truncate lob part segment from recycle bin
 * The lob column id can be decoded from origin name in recycle bin.
 * So we can find the lob we need to restore directly.
 * @param kernel session, kernel dictionary, object description
 */
static status_t rb_restore_lob_part_segment(knl_session_t *session, knl_dictionary_t *dc, knl_rb_desc_t *desc)
{
    dc_entity_t *entity;
    table_t *table;
    lob_t *lob = NULL;
    lob_part_t *lob_part = NULL;
    knl_column_t *column = NULL;
    uint32 table_id, col_id;
    uint32 part_no;
    errno_t ret;

    entity = DC_ENTITY(dc);
    table = &entity->table;
    knl_panic_log(IS_PART_TABLE(table), "current table is not part_table, panic info: table %s rb_table %s",
                  table->desc.name, desc->name);
    ret = sscanf_s(desc->part_name, "LOB%uC%uP%u", &table_id, &col_id, &part_no);
    knl_securec_check_ss(ret);
    knl_panic_log(desc->table_id == table_id, "rb's table_id is not equal table_id, panic info: table %s table_id %u "
                  "rb_table %s rb_table_id %u", entity->table.desc.name, table_id, desc->name, desc->table_id);
    knl_panic_log(part_no < table->part_table->desc.partcnt + CT_SPLIT_PART_COUNT,
                  "current part_no is abnormal, panic info: table %s rb_table %s part_no %u partcnt %u",
                  table->desc.name, desc->name, part_no, table->part_table->desc.partcnt);

    column = dc_get_column(entity, col_id);
    if (!COLUMN_IS_LOB(column)) {
        CT_THROW_ERROR_EX(ERR_RECYCLEBIN_MISMATCH, "lob id %u partition no %u does not match table %s.%s column id",
                          col_id, part_no, DC_ENTRY_USER_NAME(dc), DC_ENTRY_NAME(dc));
        return CT_ERROR;
    }

    lob = (lob_t *)column->lob;
    lob_part = LOB_GET_PART(lob, part_no);
    /* for parent part, there is not need to update entry */
    if (IS_PARENT_LOBPART(&lob_part->desc)) {
        return CT_SUCCESS;
    }

    if (db_update_lob_part_entry(session, &lob_part->desc, desc->entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/*
* restore a truncate sublob part segment from recycle bin
* The lob column id, compart_no and subpart_no can be decoded from origin name in recycle bin.
* So we can find the lob we need to restore directly.
* @param kernel session, kernel dictionary, object description
*/
static status_t rb_restore_lobsubpart_segment(knl_session_t *session, knl_dictionary_t *dc, knl_rb_desc_t *desc)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;
    uint32 table_id, col_id, compart_no, part_no;

    knl_panic_log(IS_PART_TABLE(table) && IS_COMPART_TABLE(table->part_table), "current table is not part table or "
        "the part_table is not compart table, panic info: table %s rb_table %s", table->desc.name, desc->name);
    errno_t ret = sscanf_s(desc->part_name, "LOB%uC%uP%uSUBP%u", &table_id, &col_id, &compart_no, &part_no);
    knl_securec_check_ss(ret);
    knl_panic_log(desc->table_id == table_id, "rb's table_id is not equal table_id, panic info: table %s table_id %u "
                  "rb_table %s rb_table_id %u", entity->table.desc.name, table_id, desc->name, desc->table_id);
    knl_panic_log(compart_no < table->part_table->desc.partcnt + CT_SPLIT_PART_COUNT,
                  "current compart_no is abnormal, panic info: table %s rb_table %s compart_no %u partcnt %u",
                  table->desc.name, desc->name, compart_no, table->part_table->desc.partcnt);

    knl_column_t *column = dc_get_column(entity, col_id);
    if (!COLUMN_IS_LOB(column)) {
        CT_THROW_ERROR_EX(ERR_RECYCLEBIN_MISMATCH, "lob id %u does not match table %s.%s column id",
            col_id, DC_ENTRY_USER_NAME(dc), DC_ENTRY_NAME(dc));
        return CT_ERROR;
    }

    lob_t *lob = column->lob;
    lob_part_t *lob_compart = LOB_GET_PART(lob, compart_no);
    lob_part_t *lob_subpart = PART_GET_SUBENTITY(lob->part_lob, lob_compart->subparts[part_no]);
    if (db_update_sublobpart_entry(session, &lob_subpart->desc, desc->entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t rb_restore_object_segment(knl_session_t *session, knl_dictionary_t *dc, knl_rb_desc_t *desc)
{
    status_t status = CT_SUCCESS;
    
    switch (desc->type) {
        case RB_TABLE_OBJECT:
            status = rb_restore_table_segment(session, dc, desc);
            break;

        case RB_INDEX_OBJECT:
            status = rb_restore_index_segment(session, dc, desc);
            break;

        case RB_LOB_OBJECT:
            status = rb_restore_lob_segment(session, dc, desc);
            break;

        case RB_TABLE_PART_OBJECT:
            status = rb_restore_table_part_segment(session, dc, desc);
            break;

        case RB_INDEX_PART_OBJECT:
            status = rb_restore_index_part_segment(session, dc, desc);
            break;

        case RB_LOB_PART_OBJECT:
            status = rb_restore_lob_part_segment(session, dc, desc);
            break;

        case RB_TABLE_SUBPART_OBJECT:
            status = rb_restore_tabsubpart_segment(session, dc, desc);
            break;

        case RB_INDEX_SUBPART_OBJECT:
            status = rb_restore_idxsubpart_segment(session, dc, desc);
            break;

        case RB_LOB_SUBPART_OBJECT:
            status = rb_restore_lobsubpart_segment(session, dc, desc);
            break;

        default:
            CT_THROW_ERROR(ERR_INVALID_FLASHBACK_TYPE, desc->type);
            return CT_ERROR;
    }
    
    return status;
}

/*
 * restore truncate table and its related object from recycle bin
 * @param kernel session, kernel dictionary, object description
 * @note here we use db drop table segments interface to release segments we
 * are holding. In case we are releasing segments, crash happens, the transaction
 * roll backed, we have released some segments, we can use flashback table to
 * before truncate again to recover, the segments we released would not be released
 * again.
 */
static status_t rb_restore_truncate(knl_session_t *session, knl_dictionary_t *dc, knl_rb_desc_t *desc)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_RB_ID, IX_SYS_RB002_ID);
    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT,
                     &desc->base_id, sizeof(uint64), IX_COL_SYS_RB002_BASE_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_RB002_PURGE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_BIGINT,
                     &desc->base_id, sizeof(uint64), IX_COL_SYS_RB002_BASE_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_RB002_PURGE_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CT_THROW_ERROR(ERR_RECYCLE_OBJ_NOT_EXIST, ctx->users[desc->uid]->desc.name, desc->org_name);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    do {
        rb_convert_desc(cursor, desc);

        if (rb_restore_object_segment(session, dc, desc) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (knl_internal_delete(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    } while (!cursor->eof);

    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

/*
 * flashback truncate table interface
 * flashback table to before truncate, before flashback, we should
 * check the table change scn, if table definition has changed, we are
 * not allowed to do flashback truncate.
 * @param kernel session, dictionary, force mode
 * @note force mode is that, maybe there are data in current table, it's
 * necessary to notice user to decide whether to do flashback truncate 'causing
 * once we flashback table to before truncate, current segments would converted
 * by segments in recycle bin.
 */
status_t rb_flashback_truncate_table(knl_session_t *session, knl_dictionary_t *dc, bool32 is_force)
{
    knl_rb_desc_t desc;
    rd_table_t redo;

    if (rb_fetch_truncate_table(session, dc, &desc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (desc.tchg_scn != dc->chg_scn) {
        CT_THROW_ERROR(ERR_DEF_CHANGED, DC_ENTRY_USER_NAME(dc), DC_ENTRY_NAME(dc));
        return CT_ERROR;
    }

    if (db_table_has_segment(session, dc)) {
        if (!is_force) {
            CT_THROW_ERROR(ERR_TABLE_NOT_EMPTY, DC_ENTRY_USER_NAME(dc), DC_ENTRY_NAME(dc));
            return CT_ERROR;
        }

        if (rb_truncate_table(session, dc) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (rb_restore_truncate(session, dc, &desc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    redo.op_type = RD_ALTER_TABLE;
    redo.uid = dc->uid;
    redo.oid = dc->oid;
    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_table_t), LOG_ENTRY_FLAG_NONE);
    knl_commit(session);
    dc_invalidate(session, DC_ENTITY(dc));
    return CT_SUCCESS;
}

static status_t rb_prepare_invalid_indexes(knl_session_t *session, table_t *table)
{
    index_t *index = NULL;
    bool32 is_changed = CT_FALSE;

    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];

        if (!IS_PART_INDEX(index)) {
            if (db_update_index_status(session, index, CT_TRUE, &is_changed) != CT_SUCCESS) {
                return CT_ERROR;
            }
            if (btree_segment_prepare(session, index, CT_FALSE, BTREE_DROP_SEGMENT) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }
    return CT_SUCCESS;
}

static status_t rb_flashback_idx_chk(table_t *table)
{
    uint32 valid_count = table->index_set.total_count;

    for (uint32 i = 0; i < valid_count; i++) {
        index_t *index = table->index_set.items[i];
        if (index == NULL) {
            continue;
        }

        if (IS_PART_INDEX(index)) {
            continue;
        }

        if (IS_UNIQUE_PRIMARY_INDEX(index)) {
            CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "flashback force when there is unique index");
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t rb_flashback_partition_check(table_t *table, knl_dictionary_t *dc, text_t *partition_name,
                                        table_part_t **table_part)
{
    if (!IS_PART_TABLE(table)) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "flashback table partition", DC_ENTRY_NAME(dc));
        return CT_ERROR;
    }

    if (!part_table_find_by_name(table->part_table, partition_name, table_part)) {
        CT_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(partition_name));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/*
 * flashback table part interface
 * flashback table part to before truncate, before flashback, we should
 * check the table change scn, if table definition has changed, we are
 * not allowed to do flashback truncate.
 * @param kernel session, dictionary, part name, force mode
 */
status_t rb_flashback_truncate_tabpart(knl_session_t *session, knl_dictionary_t *dc,
                                       text_t *part_name, bool32 is_force)
{
    knl_rb_desc_t desc;
    table_t *table = DC_TABLE(dc);
    table_part_t *table_part = NULL;
    rd_table_t redo;

    if (rb_flashback_partition_check(table, dc, part_name, &table_part) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (rb_fetch_truncate_tabpart(session, dc, table_part, &desc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (desc.tchg_scn != dc->chg_scn) {
        CT_THROW_ERROR(ERR_DEF_CHANGED, DC_ENTRY_USER_NAME(dc), DC_ENTRY_NAME(dc));
        return CT_ERROR;
    }

    if (db_tabpart_has_segment(table->part_table, table_part)) {
        if (!is_force) {
            CT_THROW_ERROR(ERR_TABLE_NOT_EMPTY, DC_ENTRY_USER_NAME(dc), DC_ENTRY_NAME(dc));
            return CT_ERROR;
        }

        if (rb_flashback_idx_chk(table) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (rb_truncate_table_part(session, dc, table_part) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (rb_restore_truncate(session, dc, &desc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (rb_prepare_invalid_indexes(session, table) != CT_SUCCESS) {
        return CT_ERROR;
    }

    redo.op_type = RD_ALTER_TABLE;
    redo.uid = dc->uid;
    redo.oid = dc->oid;
    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_table_t), LOG_ENTRY_FLAG_NONE);
    knl_commit(session);
    if (db_garbage_segment_handle(session, dc->uid, dc->oid, CT_FALSE) != CT_SUCCESS) {
        cm_spin_lock(&session->kernel->rmon_ctx.mark_mutex, NULL);
        session->kernel->rmon_ctx.delay_clean_segments = CT_TRUE;
        cm_spin_unlock(&session->kernel->rmon_ctx.mark_mutex);
        CT_LOG_RUN_ERR("failed to handle garbage segment");
    }
    dc_invalidate(session, DC_ENTITY(dc));
    return CT_SUCCESS;
}

/*
* flashback table subpart interface
* flashback table subpart to before truncate. before flashback, we should
* check the table change scn, if table definition has changed, we are
* not allowed to do flashback truncate.
* @param kernel session, dictionary, part name, force mode
*/
status_t rb_flashback_truncate_tabsubpart(knl_session_t *session, knl_dictionary_t *dc, text_t *part_name,
    bool32 is_force)
{
    table_t *table = DC_TABLE(dc);

    table_part_t *compart = NULL;
    table_part_t *subpart = NULL;
    if (!subpart_table_find_by_name(table->part_table, part_name, &compart, &subpart)) {
        CT_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(part_name));
        return CT_ERROR;
    }

    knl_rb_desc_t desc = { 0 };
    if (rb_fetch_truncate_subtabpart(session, dc, subpart, &desc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (desc.tchg_scn != dc->chg_scn) {
        CT_THROW_ERROR(ERR_DEF_CHANGED, DC_ENTRY_USER_NAME(dc), DC_ENTRY_NAME(dc));
        return CT_ERROR;
    }

    if (subpart->heap.segment != NULL) {
        if (!is_force) {
            CT_THROW_ERROR(ERR_TABLE_NOT_EMPTY, DC_ENTRY_USER_NAME(dc), DC_ENTRY_NAME(dc));
            return CT_ERROR;
        }

        if (rb_flashback_idx_chk(table) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (rb_truncate_table_subpart(session, dc, subpart, compart->part_no) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (rb_restore_truncate(session, dc, &desc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    rd_table_t redo;
    if (rb_prepare_invalid_indexes(session, table) != CT_SUCCESS) {
        return CT_ERROR;
    }

    redo.op_type = RD_ALTER_TABLE;
    redo.uid = dc->uid;
    redo.oid = dc->oid;
    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_table_t), LOG_ENTRY_FLAG_NONE);
    knl_commit(session);
    if (db_garbage_segment_handle(session, dc->uid, dc->oid, CT_FALSE) != CT_SUCCESS) {
        cm_spin_lock(&session->kernel->rmon_ctx.mark_mutex, NULL);
        session->kernel->rmon_ctx.delay_clean_segments = CT_TRUE;
        cm_spin_unlock(&session->kernel->rmon_ctx.mark_mutex);
        CT_LOG_RUN_ERR("failed to handle garbage segment");
    }
    dc_invalidate(session, DC_ENTITY(dc));
    return CT_SUCCESS;
}

static status_t rb_fetch_index_by_name(knl_session_t *session, knl_purge_def_t *def, knl_rb_desc_t *desc)
{
    uint32 table_id = CT_INVALID_ID32;
    
    if (!CM_IS_EMPTY(&def->ext_name)) {
        text_t name = def->name;
        def->name = def->ext_name;
        if (rb_purge_fetch_name(session, def, RB_TABLE_OBJECT, desc) != CT_SUCCESS) {
            return CT_ERROR;
        }
        def->name = name;
        table_id = desc->table_id;
    }

    if (rb_purge_fetch_name(session, def, RB_INDEX_OBJECT, desc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if ((table_id != CT_INVALID_ID32) && (table_id != desc->table_id)) {
        CT_THROW_ERROR(ERR_RECYCLE_OBJ_NOT_EXIST, T2S(&def->owner), T2S_EX(&def->name));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t db_purge(knl_session_t *session, knl_purge_def_t *def)
{
    knl_rb_desc_t desc;
    uint32 space_id;

    switch (def->type) {
        case PURGE_TABLE:
            if (rb_purge_fetch_name(session, def, RB_TABLE_OBJECT, &desc) != CT_SUCCESS) {
                return CT_ERROR;
            }
            return rb_purge_table(session, &desc);

        case PURGE_TABLE_OBJECT:
            if (rb_purge_fetch_object(session, def, RB_TABLE_OBJECT, &desc) != CT_SUCCESS) {
                return CT_ERROR;
            }
            return rb_purge_table(session, &desc);

        case PURGE_INDEX:
            if (rb_fetch_index_by_name(session, def, &desc) != CT_SUCCESS) {
                return CT_ERROR;
            }
            return rb_purge_index(session, &desc);

        case PURGE_INDEX_OBJECT:
            if (rb_purge_fetch_object(session, def, RB_INDEX_OBJECT, &desc) != CT_SUCCESS) {
                return CT_ERROR;
            }
            return rb_purge_index(session, &desc);

        case PURGE_PART:
            if (rb_purge_fetch_name(session, def, RB_TABLE_PART_OBJECT, &desc) != CT_SUCCESS) {
                return CT_ERROR;
            }
            return rb_purge_table_part(session, &desc);

        case PURGE_PART_OBJECT:
            if (rb_purge_fetch_object(session, def, RB_TABLE_PART_OBJECT, &desc) != CT_SUCCESS) {
                return CT_ERROR;
            }
            return rb_purge_table_part(session, &desc);

        case PURGE_TABLESPACE:
            if (spc_get_space_id(session, &def->name, CT_FALSE, &space_id) != CT_SUCCESS) {
                return CT_ERROR;
            }
            if (spc_check_by_uid(session, &def->name, space_id, session->uid) != CT_SUCCESS) {
                return CT_ERROR;
            }
            return rb_purge_space(session, space_id);

        case PURGE_RECYCLEBIN:
            return rb_purge_recyclebin(session);

        default:
            CT_THROW_ERROR(ERR_INVALID_PURGE_TYPE, def->type);
            return CT_ERROR;
    }
}
                                       
