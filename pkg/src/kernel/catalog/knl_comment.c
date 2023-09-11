/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * knl_comment.c
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/knl_comment.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_comment.h"
#include "knl_context.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t db_insert_syscomment(knl_session_t *session, knl_cursor_t *cursor,
    knl_comment_def_t *def)
{
    uint32 max_size;
    row_assist_t ra;
    table_t *table = NULL;

    max_size = session->kernel->attr.max_row_size;
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_COMMENT_ID, GS_INVALID_ID32);
    table = (table_t *)cursor->table;

    row_init(&ra, (char *)cursor->row, max_size, table->desc.column_count);
    (void)row_put_int32(&ra, def->uid);
    (void)row_put_int32(&ra, def->id);

    switch (def->type) {
        case COMMENT_ON_COLUMN:
            (void)row_put_int32(&ra, def->column_id);
            break;

        case COMMENT_ON_TABLE:
            row_put_null(&ra);
            break;
        default:
            GS_THROW_ERROR(ERR_INVALID_OPERATION, "");
            return GS_ERROR;
    }

    if (def->comment.str != NULL) {
        (void)row_put_text(&ra, &def->comment);
    } else {
        row_put_null(&ra);
    }

    return knl_internal_insert(session, cursor);
}

static status_t db_update_syscomment(knl_session_t *session, knl_cursor_t *cursor, knl_comment_def_t *def)
{
    row_assist_t ra;
    knl_update_info_t *ua = &cursor->update_info;

    row_init(&ra, ua->data, HEAP_MAX_ROW_SIZE(session), 1);
    if (def->comment.str != NULL) {
        (void)row_put_text(&ra, &def->comment);
    } else {
        row_put_null(&ra);
    }
    ua->count = 1;
    ua->columns[0] = COMMENT_TEXT_COLUMN_ID;
    cm_decode_row(ua->data, ua->offsets, ua->lens, NULL);

    return knl_internal_update(session, cursor);
}

status_t db_delete_comment(knl_session_t *session, knl_comment_def_t *def)
{
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_COMMENT_ID, IX_SYS_COMMENT001_ID);

    switch (def->type) {
        case COMMENT_ON_TABLE:
            knl_init_index_scan(cursor, GS_FALSE);
            knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                             &def->uid, sizeof(uint32), COMMENT_USER_COLUMN_ID);
            knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                             &def->id, sizeof(uint32), COMMENT_TABLE_COLUMN_ID);
            knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, COMMENT_COLUMN_COLUMN_ID);

            knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                             &def->uid, sizeof(uint32), COMMENT_USER_COLUMN_ID);
            knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                             &def->id, sizeof(uint32), COMMENT_TABLE_COLUMN_ID);
            knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, COMMENT_COLUMN_COLUMN_ID);
            break;
        case COMMENT_ON_COLUMN:
            knl_init_index_scan(cursor, GS_TRUE);
            knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                             &def->uid, sizeof(uint32), COMMENT_USER_COLUMN_ID);
            knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                             &def->id, sizeof(uint32), COMMENT_TABLE_COLUMN_ID);
            knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                             &def->column_id, sizeof(uint32), COMMENT_COLUMN_COLUMN_ID);
            break;
        default:
            CM_RESTORE_STACK(session->stack);
            GS_THROW_ERROR(ERR_INVALID_OPERATION, "");
            return GS_ERROR;
    }

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }

    while (!cursor->eof) {
        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_comment_on(knl_session_t *session, knl_comment_def_t *def)
{
    knl_cursor_t *cursor = NULL;
    status_t status;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_COMMENT_ID, IX_SYS_COMMENT001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &def->uid, sizeof(uint32),
                     COMMENT_USER_COLUMN_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &def->id, sizeof(uint32),
                     COMMENT_TABLE_COLUMN_ID);

    switch (def->type) {
        case COMMENT_ON_TABLE:
            knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_IS_NULL, COMMENT_COLUMN_COLUMN_ID);
            break;
        case COMMENT_ON_COLUMN:
            knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &def->column_id,
                             sizeof(uint32),
                             COMMENT_COLUMN_COLUMN_ID);
            break;
        default:
            CM_RESTORE_STACK(session->stack);
            GS_THROW_ERROR(ERR_INVALID_OPERATION, "");
            return GS_ERROR;
    }

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (cursor->eof) {
        status = db_insert_syscomment(session, cursor, def);
    } else {
        status = db_update_syscomment(session, cursor, def);
    }

    CM_RESTORE_STACK(session->stack);
    return status;
}

#ifdef __cplusplus
}
#endif
