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
 * pl_manager.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/pl_manager.c
 *
 * -------------------------------------------------------------------------
 */

#include "pl_manager.h"
#include "ctsql_package.h"
#include "srv_instance.h"
#include "pl_memory.h"


#ifdef Z_SHARDING
status_t shd_pre_execute_ddl(sql_stmt_t *stmt, bool32 multi_ddl, bool32 need_encrypt);
status_t shd_trigger_check_for_rebalance(sql_stmt_t *stmt, text_t *user, text_t *tab);
#endif

status_t pl_entry_insert_into_bucket(pl_entry_t *entry)
{
    pl_manager_t *mngr = GET_PL_MGR;
    char *name = entry->desc.name;
    uint32 bucket_id = cm_hash_string(name, PL_ENTRY_NAME_BUCKET_SIZE);
    pl_list_t *entry_lst = &mngr->entry_name_buckets[bucket_id];

    entry->bucket_id = bucket_id;
    pl_list_insert_head(entry_lst, &entry->bucket_link, CT_TRUE);
    pl_entry_insert_into_oid_bucket(entry);

    return CT_SUCCESS;
}

status_t pl_load_entry(pl_desc_t *desc)
{
    pl_entry_t *entry = NULL;

    if (pl_alloc_entry(&entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    entry->desc = *desc;
    if (pl_entry_insert_into_bucket(entry) != CT_SUCCESS) {
        pl_free_broken_entry(entry);
        return CT_ERROR;
    }

    pl_set_entry_status(entry, CT_TRUE);
    return CT_SUCCESS;
}

status_t pl_load_sys_packages(void)
{
    uint32 pkg_count = sql_get_pack_num();
    sql_package_t *pack = NULL;
    pl_desc_t desc = { 0 };

    for (uint32 i = 0; i < pkg_count; i++) {
        pack = sql_get_pack(i);
        CT_RETURN_IFERR(cm_text2str(&pack->name, desc.name, CT_NAME_BUFFER_SIZE));
        desc.uid = DB_SYS_USER_ID;
        desc.oid = pack->pack_id;
        desc.type = PL_SYS_PACKAGE;
        desc.status = OBJ_STATUS_VALID;
        CT_RETURN_IFERR(pl_load_entry(&desc));
    }

    return CT_SUCCESS;
}

status_t pl_load_entries(knl_session_t *session)
{
    status_t status = CT_SUCCESS;
    knl_cursor_t *cursor = NULL;
    text_t obj_name;
    char pl_type;
    pl_desc_t desc;
    trig_desc_t trig_desc;
    CM_SAVE_STACK(session->stack);

    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_STACK_OVERFLOW);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_set_session_scn(session, CT_INVALID_ID64);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_PROC_ID, CT_INVALID_ID32);
    for (;;) {
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        if (cursor->eof) {
            break;
        }

        desc.oid = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_PROC_OBJ_ID_COL);
        desc.uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PROC_USER_COL);
        obj_name.str = (char *)CURSOR_COLUMN_DATA(cursor, SYS_PROC_NAME_COL);
        obj_name.len = (uint32)CURSOR_COLUMN_SIZE(cursor, SYS_PROC_NAME_COL);
        pl_type = *(char *)CURSOR_COLUMN_DATA(cursor, SYS_PROC_TYPE_COL);
        desc.type = plm_get_pl_type(pl_type);
        desc.status = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PROC_STATUS_COL);
        desc.flags = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PROC_FLAGS_COL);
        desc.org_scn = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_PROC_ORG_SCN_COL);
        desc.chg_scn = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_PROC_CHG_SCN_COL);
        cm_text2str(&obj_name, desc.name, CT_NAME_BUFFER_SIZE);

        if (desc.type == PL_TRIGGER) {
            if (pl_load_sys_trigger(session, desc.oid, &trig_desc) != CT_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return CT_ERROR;
            }

            desc.trig_def.obj_uid = trig_desc.obj_uid;
            desc.trig_def.obj_oid = trig_desc.base_obj;
        }

        if (pl_load_entry(&desc) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }
    }
    CM_RESTORE_STACK(session->stack);

    return status;
}

status_t pl_load_synonym_entries(knl_session_t *session)
{
    knl_cursor_t *cur = NULL;
    pl_desc_t desc;
    status_t status;
    object_type_t syn_type;
    text_t name;

    CM_SAVE_STACK(session->stack);

    if (sql_push_knl_cursor(session, &cur) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_STACK_OVERFLOW);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    if (cur == NULL) {
        CT_THROW_ERROR(ERR_STACK_OVERFLOW);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_set_session_scn(session, CT_INVALID_ID64);

    knl_open_sys_cursor(session, cur, CURSOR_ACTION_SELECT, SYS_SYN_ID, CT_INVALID_ID32);

    status = CT_SUCCESS;
    desc.type = PL_SYNONYM;
    for (;;) {
        if (knl_fetch(session, cur) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        CT_BREAK_IF_TRUE(cur->eof);

        syn_type = *(uint32 *)CURSOR_COLUMN_DATA(cur, SYS_SYN_TYPE);
        if (IS_PL_SYN(syn_type)) {
            desc.uid = *(uint32 *)CURSOR_COLUMN_DATA(cur, SYS_SYN_USER);
            desc.oid = *(uint32 *)CURSOR_COLUMN_DATA(cur, SYS_SYN_OBJID);
            desc.chg_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cur, SYS_SYN_CHG_SCN);

            name.len = (uint32)CURSOR_COLUMN_SIZE(cur, SYS_SYN_SYNONYM_NAME);
            name.str = (char *)CURSOR_COLUMN_DATA(cur, SYS_SYN_SYNONYM_NAME);
            cm_text2str(&name, desc.name, CT_NAME_BUFFER_SIZE);
            name.len = (uint32)CURSOR_COLUMN_SIZE(cur, SYS_SYN_TABLE_OWNER);
            name.str = (char *)CURSOR_COLUMN_DATA(cur, SYS_SYN_TABLE_OWNER);
            cm_text2str(&name, desc.link_user, CT_NAME_BUFFER_SIZE);
            name.len = (uint32)CURSOR_COLUMN_SIZE(cur, SYS_SYN_TABLE_NAME);
            name.str = (char *)CURSOR_COLUMN_DATA(cur, SYS_SYN_TABLE_NAME);
            cm_text2str(&name, desc.link_name, CT_NAME_BUFFER_SIZE);

            if (pl_load_entry(&desc) != CT_SUCCESS) {
                status = CT_ERROR;
                break;
            }
        }
    }

    CM_RESTORE_STACK(session->stack);
    return status;
}

status_t pl_init(knl_handle_t sess)
{
    pl_manager_t *mngr = GET_PL_MGR;
    context_pool_t *pool = sql_pool;
    knl_session_t *session = (knl_session_t *)sess;

    CT_RETSUC_IFTRUE(mngr->initialized);

    if (ctx_create_mctx(pool, &mngr->memory) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // init data structure
    pl_init_lock_map_pool(&mngr->lock_map_pool);

    // load sys packages
    CT_RETURN_IFERR(pl_load_sys_packages());

    // load stored procedure/function/trigger/library entry
    CT_RETURN_IFERR(pl_load_entries(session));

    // load stored synonym of procedure/function
    CT_RETURN_IFERR(pl_load_synonym_entries(session));
    pool->external_recycle = pl_recycle_internal;
    mngr->external_recycle = ctx_recycle_internal;
    mngr->initialized = CT_TRUE;
    return CT_SUCCESS;
}

void pl_release_anony_context(sql_stmt_t *stmt)
{
    pl_entity_t *pl_context = (pl_entity_t *)stmt->pl_context;

    if (pl_context == NULL) {
        return;
    }

    SET_STMT_PL_CONTEXT(stmt, NULL);
    if (!pl_context->cached) {
        CM_ASSERT(stmt->context == pl_context->context);
        pl_free_entity(pl_context);
        return;
    }

    pl_entity_lock(pl_context);
    if (pl_context->ref_count > 1 || pl_context->valid) {
        pl_context->ref_count--;
        pl_entity_unlock(pl_context);
        return;
    }
    pl_entity_unlock(pl_context);

    pl_manager_t *mngr = GET_PL_MGR;
    pl_list_t *find_list = &mngr->anony_buckets[pl_context->find_hash];
    pl_list_t *lru_list = &mngr->anony_lru[pl_context->lru_hash];

    pl_list_del(find_list, &pl_context->bucket_link, CT_TRUE);
    pl_list_del(lru_list, &pl_context->lru_link, CT_TRUE);
    pl_entity_ref_dec(pl_context);
    pl_free_entity(pl_context);
}

// free pl_entity
void pl_free_context_direct(sql_stmt_t *stmt)
{
    pl_entity_t *pl_context = (pl_entity_t *)stmt->pl_context;

    if (pl_context == NULL) {
        return;
    }

    SET_STMT_PL_CONTEXT(stmt, NULL);
    if (pl_context->create_def != NULL && pl_context->create_def->large_page_id != CT_INVALID_ID32) {
        mpool_free_page(&g_instance->sga.large_pool, pl_context->create_def->large_page_id);
        pl_context->create_def->large_page_id = CT_INVALID_ID32;
    }

    pl_free_entity(pl_context);
}

void pl_release_context(sql_stmt_t *stmt)
{
    pl_entity_t *pl_context = (pl_entity_t *)stmt->pl_context;
    if (pl_context == NULL) {
        return;
    }

    if (pl_context->pl_type == PL_ANONYMOUS_BLOCK) {
        pl_release_anony_context(stmt);
    } else {
        pl_free_context_direct(stmt);
    }
}
