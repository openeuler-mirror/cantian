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
 * pl_synonym.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/meta/pl_synonym.c
 *
 * -------------------------------------------------------------------------
 */
#include "pl_synonym.h"
#include "pl_lock.h"
#include "ctsql_dependency.h"
#include "pl_logic.h"
#include "pl_common.h"
#include "knl_table.h"

static status_t pl_init_sync_def(knl_synonym_t *synonym, knl_synonym_def_t *def, pl_desc_t *desc)
{
    synonym->uid = desc->uid;
    synonym->id = (uint32)desc->oid;
    synonym->org_scn = desc->org_scn;
    synonym->chg_scn = desc->chg_scn;
    CT_RETURN_IFERR(cm_text2str(&def->name, synonym->name, CT_NAME_BUFFER_SIZE));
    CT_RETURN_IFERR(cm_text2str(&def->table_owner, synonym->table_owner, CT_NAME_BUFFER_SIZE));
    CT_RETURN_IFERR(cm_text2str(&def->table_name, synonym->table_name, CT_NAME_BUFFER_SIZE));
    synonym->flags = OBJ_STATUS_VALID;
    synonym->type = pltype_to_objtype(def->ref_dc_type);
    return CT_SUCCESS;
}

status_t pl_write_pl_synonym(knl_session_t *session, knl_synonym_def_t *def, pl_desc_t *desc)
{
    knl_synonym_t synonym;
    knl_cursor_t *cursor = NULL;

    if (pl_init_sync_def(&synonym, def, desc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    CM_SAVE_STACK(session->stack);

    knl_set_session_scn(session, CT_INVALID_ID64);
    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_STACK_OVERFLOW);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (db_write_syssyn(session, cursor, &synonym) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t pl_write_syn_dep(knl_session_t *session, knl_synonym_def_t *def, pl_desc_t *desc)
{
    knl_cursor_t *cursor = NULL;
    object_address_t obj_addr, ref;

    obj_addr.uid = desc->uid;
    obj_addr.oid = desc->oid;
    obj_addr.tid = OBJ_TYPE_PL_SYNONYM;
    obj_addr.scn = desc->chg_scn;
    MEMS_RETURN_IFERR(strcpy_s(obj_addr.name, CT_NAME_BUFFER_SIZE, desc->name));

    ref.uid = def->ref_uid;
    ref.oid = def->ref_oid;
    ref.tid = pltype_to_objtype(def->ref_dc_type);
    ref.scn = def->ref_chg_scn;
    MEMS_RETURN_IFERR(strncpy_s(ref.name, CT_NAME_BUFFER_SIZE, def->table_name.str, def->table_name.len));

    CM_SAVE_STACK(session->stack);

    knl_set_session_scn(session, CT_INVALID_ID64);
    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_STACK_OVERFLOW);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (db_write_sysdep(session, cursor, &obj_addr, &ref, 0) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

status_t pl_process_drop_synonym(knl_session_t *session, pl_entry_info_t *entry_info)
{
    bool32 ret_ok = CT_FALSE;
    pl_entry_t *entry = entry_info->entry;

    if (pl_lock_entry_exclusive(session, entry_info) != CT_SUCCESS) {
        return CT_ERROR;
    }

    obj_info_t obj_addr = { OBJ_TYPE_PL_SYNONYM, entry->desc.uid, entry->desc.oid };
    do {
        CT_BREAK_IF_ERROR(knl_delete_syssyn_by_name(session, entry->desc.uid, entry->desc.name));
        CT_BREAK_IF_ERROR(knl_delete_dependency(session, entry->desc.uid, entry->desc.oid, OBJ_TYPE_PL_SYNONYM));
        CT_BREAK_IF_ERROR(sql_update_depender_status(session, &obj_addr));
        pl_logic_log_put(session, RD_PLM_DROP, entry->desc.uid, entry->desc.oid, entry->desc.type);
        ret_ok = CT_TRUE;
    } while (CT_FALSE);

    if (!ret_ok) {
        knl_rollback(session, NULL);
        pl_unlock_exclusive(session, entry);
        return CT_ERROR;
    }

    knl_commit(session);
    pl_entity_invalidate_by_entry(entry);
    pl_entry_drop(entry);
    pl_unlock_exclusive(session, entry);
    pl_free_entry(entry);
    return CT_SUCCESS;
}

status_t pl_execute_drop_synonym_core(sql_stmt_t *stmt, dc_user_t *dc_user)
{
    knl_drop_def_t *drop_def = (knl_drop_def_t *)stmt->context->entry;
    pl_entry_info_t entry_info;
    bool32 found = CT_FALSE;
    status_t status;

    pl_find_entry_for_desc(dc_user, &drop_def->name, PL_SYNONYM, &entry_info, &found);
    if (found) {
        status = pl_process_drop_synonym(KNL_SESSION(stmt), &entry_info);
    } else {
        if (drop_def->options & DROP_IF_EXISTS) {
            status = CT_SUCCESS;
        } else {
            CT_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "synonym", T2S(&drop_def->owner), T2S_EX(&drop_def->name));
            status = CT_ERROR;
        }
    }

    return status;
}

status_t pl_drop_synonym_by_user(knl_handle_t sess, uint32 uid, text_t *syn_name)
{
    knl_session_t *session = (knl_session_t *)sess;
    dc_user_t *dc_user = NULL;
    pl_entry_info_t entry_info;
    bool32 found = CT_FALSE;

    CT_RETURN_IFERR(dc_open_user_by_id(session, uid, &dc_user));
    pl_find_entry_for_desc(dc_user, syn_name, PL_SYNONYM, &entry_info, &found);
    if (found) {
        return pl_process_drop_synonym(session, &entry_info);
    }

    CT_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "synonym", dc_user->desc.name, T2S(syn_name));
    return CT_ERROR;
}

status_t pl_load_synonym(knl_handle_t sess, void *desc_in)
{
    knl_session_t *session = (knl_session_t *)sess;
    pl_desc_t *desc = (pl_desc_t *)desc_in;
    knl_cursor_t *cursor = NULL;
    text_t obj_name;

    CM_SAVE_STACK(session->stack);
    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SYN_ID, IX_SYS_SYNONYM002_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->uid,
        sizeof(int32), IX_COL_SYS_SYNONYM002_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->oid,
        sizeof(int64), IX_COL_SYS_SYNONYM002_OBJID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    desc->org_scn = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_ORG_SCN);
    desc->chg_scn = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_CHG_SCN);

    obj_name.str = (char *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_SYNONYM_NAME);
    obj_name.len = (uint32)CURSOR_COLUMN_SIZE(cursor, SYS_SYN_SYNONYM_NAME);
    if (cm_text2str(&obj_name, desc->name, CT_NAME_BUFFER_SIZE) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    obj_name.str = (char *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_TABLE_OWNER);
    obj_name.len = (uint32)CURSOR_COLUMN_SIZE(cursor, SYS_SYN_TABLE_OWNER);
    if (cm_text2str(&obj_name, desc->link_user, CT_NAME_BUFFER_SIZE) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    obj_name.str = (char *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_TABLE_NAME);
    obj_name.len = (uint32)CURSOR_COLUMN_SIZE(cursor, SYS_SYN_TABLE_NAME);
    if (cm_text2str(&obj_name, desc->link_name, CT_NAME_BUFFER_SIZE) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    desc->status = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_FLAG);
    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}