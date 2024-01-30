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
 * pl_logic.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/persist/pl_logic.c
 *
 * -------------------------------------------------------------------------
 */
#include "pl_logic.h"
#include "dc_log.h"
#include "dc_tbl.h"
#include "pl_manager.h"
#include "pl_meta_common.h"
#include "pl_synonym.h"

void pl_logic_log_put(knl_session_t *session, uint32 type, uint32 uid, uint64 oid, uint32 tid)
{
    logic_log_plm_ddl_t logic_log_plm;
    errno_t ret = memset_sp(&logic_log_plm, sizeof(logic_log_plm_ddl_t), 0, sizeof(logic_log_plm_ddl_t));
    knl_securec_check(ret);

    logic_log_plm.uid = uid;
    logic_log_plm.oid = oid;
    logic_log_plm.type = (uint32)tid;

    knl_logic_log_put(session, type, &logic_log_plm, sizeof(logic_log_plm_ddl_t));
    knl_commit(session);
}

void pl_logic_invalidate_trig_tab(knl_session_t *session, uint32 uid, uint32 oid)
{
    dc_user_t *user = NULL;
    dc_entry_t *entry = NULL;

    if (dc_open_user_by_id(session, uid, &user) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DC] failed to find trigger table id %u,user id %u doesn't exists\n", oid, uid);
        rd_check_dc_replay_err(session);
        return;
    }

    if (!dc_find_by_id(session, user, oid, CT_FALSE)) {
        return;
    }

    /* seem like dc_open and dc_invalidate */
    entry = DC_GET_ENTRY(user, oid);
    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    dc_entity_t *entity = rd_invalid_entity(session, entry);

    if (IS_CORE_SYS_TABLE(uid, oid)) {
        if (dc_load_core_table(session, oid) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DC] failed to reload sys core table id %u\n", oid);
            rd_check_dc_replay_err(session);
        }
    } else {
        if (dc_is_reserved_entry(uid, oid)) {
            if (dc_load_entity(session, user, oid, entry, NULL) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[DC] failed to reload sys table id %u\n", oid);
                rd_check_dc_replay_err(session);
            }
        }
    }

    cm_spin_unlock(&entry->lock);

    if (entity != NULL) {
        dc_close_entity(session->kernel, entity, CT_TRUE);
    }
}

static status_t pl_logic_log_replay_invalidate_trig(knl_session_t *session, pl_desc_t *desc)
{
    trig_def_t trig_def;
    pl_entry_info_t entry_info;
    pl_find_entry_by_oid(desc->oid, desc->type, &entry_info);
    pl_entry_t *entry = entry_info.entry;

    if (entry == NULL) {
        CT_LOG_RUN_ERR("failed to find trigger, [uid] %d, [oid] %lld ", desc->uid, desc->oid);
        return CT_ERROR;
    }

    if (pl_lock_entry_exclusive(session, &entry_info) != CT_SUCCESS) {
        return CT_ERROR;
    }

    trig_def = entry->desc.trig_def;
    pl_entity_invalidate_by_entry(entry);
    pl_logic_invalidate_trig_tab(session, trig_def.obj_uid, (uint32)trig_def.obj_oid);
    pl_unlock_exclusive(session, entry);

    return CT_SUCCESS;
}

void pl_logic_log_prepare_desc(logic_log_plm_ddl_t *logic_log_plm, pl_desc_t *desc)
{
    desc->uid = logic_log_plm->uid;
    desc->oid = logic_log_plm->oid;
    desc->type = logic_log_plm->type;
}

static status_t pl_logic_log_replay_create(knl_session_t *session, pl_desc_t *desc)
{
    trig_desc_t trig_desc;
    CT_LOG_DEBUG_INF("logic log replay create, object_id = %d.%lld", desc->uid, desc->oid);

    switch (desc->type) {
        case PL_TRIGGER:
            CT_RETURN_IFERR(pl_load_sys_proc_desc(session, desc));
            CT_RETURN_IFERR(pl_load_sys_trigger(session, desc->oid, &trig_desc));
            desc->trig_def.obj_uid = trig_desc.obj_uid;
            desc->trig_def.obj_oid = trig_desc.base_obj;
            CT_RETURN_IFERR(pl_load_entry(desc));
            // like dc_invalidate
            pl_logic_invalidate_trig_tab(session, trig_desc.obj_uid, (uint32)trig_desc.base_obj);
            break;

        case PL_SYNONYM:
            CT_RETURN_IFERR(pl_load_synonym(session, desc));
            CT_RETURN_IFERR(pl_load_entry(desc));
            break;

        default:
            CT_RETURN_IFERR(pl_load_sys_proc_desc(session, desc));
            CT_RETURN_IFERR(pl_load_entry(desc));
            break;
    }

    return CT_SUCCESS;
}

static status_t pl_logic_log_replay_replace(knl_session_t *session, pl_desc_t *desc)
{
    trig_desc_t trig_desc;
    pl_entry_info_t entry_info;
    pl_find_entry_by_oid(desc->oid, desc->type, &entry_info);
    pl_entry_t *entry = entry_info.entry;
    if (entry == NULL) {
        CT_LOG_RUN_ERR("failed to find object, [uid] %d [oid] %lld [type] %d", desc->uid, desc->oid, desc->type);
        return CT_ERROR;
    }

    if (pl_lock_entry_exclusive(session, &entry_info) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (desc->type == PL_SYNONYM) {
        if (pl_load_synonym(session, desc) != CT_SUCCESS) {
            pl_unlock_exclusive(session, entry);
            return CT_ERROR;
        }
    } else {
        if (pl_load_sys_proc_desc(session, desc) != CT_SUCCESS) {
            pl_unlock_exclusive(session, entry);
            return CT_ERROR;
        }
    }

    if (desc->type == PL_TRIGGER) {
        if (pl_load_sys_trigger(session, desc->oid, &trig_desc) != CT_SUCCESS) {
            pl_unlock_exclusive(session, entry);
            return CT_ERROR;
        }

        pl_desc_set_trig_def(desc, &trig_desc);
        pl_logic_invalidate_trig_tab(session, trig_desc.obj_uid, (uint32)trig_desc.base_obj);
    }

    pl_entity_invalidate_by_entry(entry);
    pl_update_entry_desc(entry, desc);
    pl_unlock_exclusive(session, entry);

    return CT_SUCCESS;
}

static status_t pl_logic_log_replay_drop(knl_session_t *session, pl_desc_t *desc)
{
    trig_def_t trigger_def;
    pl_entry_info_t entry_info;
    pl_find_entry_by_oid(desc->oid, desc->type, &entry_info);
    pl_entry_t *entry = entry_info.entry;

    if (entry == NULL) {
        CT_LOG_RUN_ERR("Object [uid] %d [oid]%lld [type]%d not exists", desc->uid, desc->oid, desc->type);
        return CT_ERROR;
    }

    if (pl_lock_entry_exclusive(session, &entry_info) != CT_SUCCESS) {
        return CT_ERROR;
    }

    pl_entity_invalidate_by_entry(entry);

    if (desc->type == PL_TRIGGER) {
        trigger_def = entry->desc.trig_def;
        pl_logic_invalidate_trig_tab(session, trigger_def.obj_uid, (uint32)trigger_def.obj_oid);
    }

    pl_entry_drop(entry);
    pl_unlock_exclusive(session, entry);
    pl_free_entry(entry);
    return CT_SUCCESS;
}

static status_t pl_logic_log_replay_free_trig_entity(knl_session_t *session, pl_desc_t *desc)
{
    pl_entry_info_t entry_info;
    pl_find_entry_by_oid(desc->oid, desc->type, &entry_info);
    pl_entry_t *entry = entry_info.entry;

    if (entry == NULL) {
        CT_LOG_RUN_ERR("failed to find trigger, [uid] %d, [oid] %lld ", desc->uid, desc->oid);
        return CT_ERROR;
    }

    if (pl_lock_entry_exclusive(session, &entry_info) != CT_SUCCESS) {
        return CT_ERROR;
    }

    pl_entity_invalidate_by_entry(entry);
    pl_unlock_exclusive(session, entry);

    return CT_SUCCESS;
}

status_t pl_logic_log_replay(knl_handle_t session, uint32 type, void *data)
{
    logic_log_plm_ddl_t *logic_log_plm = (logic_log_plm_ddl_t *)data;
    pl_desc_t desc;

    pl_logic_log_prepare_desc(logic_log_plm, &desc);

    switch (type) {
        case RD_PLM_CREATE:
            return pl_logic_log_replay_create(session, &desc);
        case RD_PLM_REPLACE:
            return pl_logic_log_replay_replace(session, &desc);
        case RD_PLM_DROP:
            return pl_logic_log_replay_drop(session, &desc);
        case RD_PLM_UPDATE_TRIG_STATUS:
            return pl_logic_log_replay_invalidate_trig(session, &desc);
        case RD_PLM_UPDATE_TRIG_TAB:
        case RD_PLM_FREE_TRIG_ENTITY:
            return pl_logic_log_replay_free_trig_entity(session, &desc);
        default:
            CT_THROW_ERROR(ERR_PL_REPLAY_UNKNOWN_FMT, type);
            return CT_ERROR;
    }
    return CT_SUCCESS;
}
