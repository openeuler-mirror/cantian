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
 * pl_library.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/meta/pl_library.c
 *
 * -------------------------------------------------------------------------
 */

#include "pl_library.h"
#include "knl_session.h"
#include "knl_interface.h"
#include "knl_database.h"
#include "knl_context.h"
#include "knl_dc.h"
#include "pl_ext_proc.h"
#include "dtc_dls.h"

status_t pl_find_library(knl_handle_t se, uint32 uid, text_t *name, pl_library_t *library, bool32 *exists)
{
    knl_session_t *session = (knl_session_t *)se;
    knl_cursor_t *cur = NULL;
    text_t path_text, agent_text, leaf_text;
    *exists = CT_FALSE;

    CM_SAVE_STACK(session->stack);

    cur = knl_push_cursor(session);

    knl_open_sys_cursor(session, cur, CURSOR_ACTION_SELECT, SYS_LIBRARY_ID, IDX_LIBRARY_001_ID);
    knl_init_index_scan(cur, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cur->index), &cur->scan_range.l_key, CT_TYPE_INTEGER, (void *)&uid,
        sizeof(uint32), IX_COL_SYS_LIBRARY001_OWNER);
    knl_set_scan_key(INDEX_DESC(cur->index), &cur->scan_range.l_key, CT_TYPE_STRING, name->str, name->len,
        IX_COL_SYS_LIBRARY001_NAME);

    if (knl_fetch(session, cur) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cur->eof) {
        CM_RESTORE_STACK(session->stack);
        return CT_SUCCESS;
    }
    *exists = CT_TRUE;
    if (library != NULL) {
        // get library uid and name
        library->uid = uid;
        cm_text2str(name, library->name, CT_NAME_BUFFER_SIZE);

        // get library info
        path_text.len = (uint32)CURSOR_COLUMN_SIZE(cur, SYS_LIBRARY_FILE_PATH);
        path_text.str = (char *)CURSOR_COLUMN_DATA(cur, SYS_LIBRARY_FILE_PATH);

        library->status = *(uint32 *)CURSOR_COLUMN_DATA(cur, SYS_LIBRARY_STATUS);
        library->flags = *(uint32 *)CURSOR_COLUMN_DATA(cur, SYS_LIBRARY_FLAGS);

        agent_text.len = (uint32)CURSOR_COLUMN_SIZE(cur, SYS_LIBRARY_AGENT_DBLINK);
        agent_text.str = (char *)CURSOR_COLUMN_DATA(cur, SYS_LIBRARY_AGENT_DBLINK);

        leaf_text.len = (uint32)CURSOR_COLUMN_SIZE(cur, SYS_LIBRARY_LEAF_FILENAME);
        leaf_text.str = (char *)CURSOR_COLUMN_DATA(cur, SYS_LIBRARY_LEAF_FILENAME);

        library->chg_scn = *(int64 *)CURSOR_COLUMN_DATA(cur, SYS_LIBRARY_ORG_SCN);
        library->org_scn = *(int64 *)CURSOR_COLUMN_DATA(cur, SYS_LIBRARY_CHG_SCN);

        cm_text2str(&path_text, library->path, CT_FILE_NAME_BUFFER_SIZE);
        cm_text2str(&agent_text, library->agent_name, CT_FILE_NAME_BUFFER_SIZE);
        cm_text2str(&leaf_text, library->leaf_name, CT_NAME_BUFFER_SIZE);
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

static inline status_t pl_init_library_desc(knl_session_t *session, pl_library_t *library, pl_library_def_t *def)
{
    library->org_scn = db_inc_scn(session);
    library->chg_scn = library->org_scn;
    library->flags = 0;
    library->is_dll = CT_TRUE;
    CT_RETURN_IFERR(cm_text2str(&def->name, library->name, CT_NAME_BUFFER_SIZE));
    CT_RETURN_IFERR(cm_text2str(&def->leaf_name, library->leaf_name, CT_NAME_BUFFER_SIZE));
    CT_RETURN_IFERR(cm_text2str(&def->path, library->path, CT_FILE_NAME_BUFFER_SIZE));
    CT_RETURN_IFERR(cm_text2str(&def->agent, library->agent_name, CT_FILE_NAME_BUFFER_SIZE));
    library->status = OBJ_STATUS_VALID;

    return CT_SUCCESS;
}


static status_t pl_write_syslibrary(knl_session_t *session, knl_cursor_t *cursor, pl_library_t *library)
{
    uint32 max_size;
    row_assist_t ra;
    table_t *table = NULL;

    max_size = session->kernel->attr.max_row_size;
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_LIBRARY_ID, CT_INVALID_ID32);
    table = (table_t *)cursor->table;
    row_init(&ra, cursor->buf, max_size, table->desc.column_count);

    CT_RETURN_IFERR(row_put_uint32(&ra, library->uid));

    CT_RETURN_IFERR(row_put_str(&ra, library->name));

    CT_RETURN_IFERR(row_put_str(&ra, library->path));

    CT_RETURN_IFERR(row_put_int32(&ra, library->flags));

    CT_RETURN_IFERR(row_put_int32(&ra, library->status));

    CT_RETURN_IFERR(row_put_str(&ra, library->agent_name));

    CT_RETURN_IFERR(row_put_str(&ra, library->leaf_name));

    CT_RETURN_IFERR(row_put_int64(&ra, library->org_scn));

    CT_RETURN_IFERR(row_put_int64(&ra, library->chg_scn));

    return knl_internal_insert(session, cursor);
}

static status_t pl_delete_from_syslibrary(knl_session_t *session, knl_cursor_t *cursor, text_t *owner,
    pl_library_t *library)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_LIBRARY_ID, IDX_LIBRARY_001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&library->uid,
        sizeof(uint32), IX_COL_SYS_LIBRARY001_OWNER);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, (void *)library->name,
        (uint16)strlen(library->name), IX_COL_SYS_LIBRARY001_NAME);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cursor->eof) {
        CT_THROW_ERROR(ERR_LIBRARY_NOT_EXIST, T2S(owner), library->name);
        return CT_ERROR;
    }

    return knl_internal_delete(session, cursor);
}

static status_t pl_drop_library_internal(knl_session_t *session, text_t *owner, pl_library_t *library)
{
    knl_cursor_t *cursor = NULL;
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    cursor->row = (row_head_t *)cursor->buf;

    // todo: re-compile pl_clear_sym_cache
    /*    if (pl_clear_sym_cache((knl_handle_t)session, library->uid, library->name, library->path) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    */

    if (db_drop_object_privs(session, library->uid, library->name, OBJ_TYPE_LIBRARY) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (pl_delete_from_syslibrary(session, cursor, owner, library) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    knl_commit(session);
    dc_drop_object_privs(&session->kernel->dc_ctx, library->uid, library->name, OBJ_TYPE_LIBRARY);
    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

status_t pl_create_library(knl_handle_t se, pl_library_def_t *def)
{
    knl_session_t *session = (knl_session_t *)se;
    pl_library_t library;
    knl_cursor_t *cursor = NULL;
    dc_user_t *user = NULL;
    drlatch_t *ddl_latch = &session->kernel->db.ddl_latch;
    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_open_user(session, &def->owner, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }
    dls_latch_x(session, &user->user_latch, session->id, NULL);
    dls_latch_s(session, ddl_latch, session->id, CT_FALSE, NULL);

    bool32 exists = CT_FALSE;
    library.uid = user->desc.id;
    if (pl_find_library(se, library.uid, &def->name, &library, &exists) != CT_SUCCESS) {
        dls_unlatch(session, ddl_latch, NULL);
        dls_unlatch(session, &user->user_latch, NULL);
        return CT_ERROR;
    }

    if (exists) {
        if (!def->is_replace) {
            dls_unlatch(session, ddl_latch, NULL);
            dls_unlatch(session, &user->user_latch, NULL);

            CT_THROW_ERROR(ERR_OBJECT_EXISTS, T2S(&def->owner), T2S_EX(&def->name));
            return CT_ERROR;
        }

        if (pl_drop_library_internal(session, &def->owner, &library) != CT_SUCCESS) {
            dls_unlatch(session, ddl_latch, NULL);
            dls_unlatch(session, &user->user_latch, NULL);

            return CT_ERROR;
        }
    }

    if (pl_init_library_desc(session, &library, def) != CT_SUCCESS) {
        dls_unlatch(session, ddl_latch, NULL);
        dls_unlatch(session, &user->user_latch, NULL);

        return CT_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    cursor->row = (row_head_t *)cursor->buf;
    cursor->is_valid = CT_TRUE;

    if (pl_write_syslibrary(session, cursor, &library) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        dls_unlatch(session, ddl_latch, NULL);
        dls_unlatch(session, &user->user_latch, NULL);
        return CT_ERROR;
    }

    knl_commit(session);
    CM_RESTORE_STACK(session->stack);
    dls_unlatch(session, ddl_latch, NULL);
    dls_unlatch(session, &user->user_latch, NULL);

    return CT_SUCCESS;
}

status_t pl_drop_library(knl_handle_t se, knl_drop_def_t *def)
{
    knl_session_t *session = (knl_session_t *)se;
    pl_library_t library;
    dc_user_t *user = NULL;
    status_t status;

    if (knl_ddl_enabled(session, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_open_user(session, &def->owner, &user) != CT_SUCCESS) {
        cm_reset_error_user(ERR_USER_OBJECT_NOT_EXISTS, T2S(&def->owner), T2S_EX(&def->name), ERR_TYPE_LIBRARY);
        return CT_ERROR;
    }

    bool32 exists = CT_FALSE;
    dls_latch_x(session, &user->lib_latch, session->id, NULL);
    if (pl_find_library(se, user->desc.id, &def->name, &library, &exists) != CT_SUCCESS) {
        dls_unlatch(session, &user->lib_latch, NULL);
        return CT_ERROR;
    }

    if (!exists) {
        dls_unlatch(session, &user->lib_latch, NULL);
        if ((def->options & DROP_IF_EXISTS)) {
            return CT_SUCCESS;
        }

        CT_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "library", T2S(&def->owner), T2S_EX(&def->name));
        return CT_ERROR;
    }

    status = pl_drop_library_internal(session, &def->name, &library);
    knl_commit(session);
    dls_unlatch(session, &user->lib_latch, NULL);

    return status;
}
