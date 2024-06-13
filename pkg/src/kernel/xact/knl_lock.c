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
 * knl_lock.c
 *
 *
 * IDENTIFICATION
 * src/kernel/xact/knl_lock.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_xact_module.h"
#include "knl_lock.h"
#include "knl_heap.h"
#include "pcr_heap.h"
#include "pcr_btree.h"
#include "knl_context.h"
#include "knl_alck.h"
#include "dc_part.h"
#include "dtc_dls.h"
#include "dtc_dc.h"
#include "dtc_drc.h"

status_t lock_area_init(knl_session_t *session)
{
    memory_area_t *shared_pool = session->kernel->attr.shared_area;
    lock_area_t *area = &session->kernel->lock_ctx;
    char *buf = NULL;
    uint32 i;
    uint32 init_lockpool_pages = session->kernel->attr.init_lockpool_pages;

    if (mpool_create(shared_pool, "lock pool", init_lockpool_pages, CT_MAX_LOCK_PAGES, &area->pool) != CT_SUCCESS) {
        return CT_ERROR;
    }
    buf = marea_page_addr(shared_pool, area->pool.free_pages.first);

    area->lock = 0;
    area->capacity = init_lockpool_pages * LOCK_PAGE_CAPACITY;  // fixed value, won't overflow
    area->hwm = 0;
    area->free_items.count = 0;
    area->free_items.first = CT_INVALID_ID32;
    area->free_items.last = CT_INVALID_ID32;
    area->page_count = init_lockpool_pages;

    for (i = 0; i < init_lockpool_pages; i++) {
        area->pages[i] = buf + i * shared_pool->page_size;
    }
    return CT_SUCCESS;
}

static status_t lock_area_extend(knl_session_t *session)
{
    mem_extent_t extent;
    memory_area_t *shared_pool = session->kernel->attr.shared_area;
    lock_area_t *area = &session->kernel->lock_ctx;
    uint32 i, page_count;

    if (area->page_count == CT_MAX_LOCK_PAGES) {
        CT_THROW_ERROR(ERR_NO_MORE_LOCKS);
        return CT_ERROR;
    }

    page_count = mpool_get_extend_page_count(CT_MAX_LOCK_PAGES, area->page_count);
    if (mpool_extend(&area->pool, page_count, &extent) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // alloc  CT_MAX_LOCK_PAGES - area->page_count extent count, the array won't overrun
    for (i = 0; i < extent.count; i++) {
        area->pages[area->page_count + i] = marea_page_addr(shared_pool, extent.pages[i]);
    }

    area->page_count += extent.count;
    area->capacity += LOCK_PAGE_CAPACITY * extent.count;
    return CT_SUCCESS;
}

static status_t lock_area_alloc(knl_session_t *session, uint32 *lockid)
{
    lock_area_t *area = &session->kernel->lock_ctx;
    lock_item_t *item = NULL;
    uint32 item_size;
    int32 ret;

    cm_spin_lock(&area->lock, NULL);

    // no more free locks, try to extend from shared pool
    if (area->hwm == area->capacity && area->free_items.count == 0) {
        if (lock_area_extend(session) != CT_SUCCESS) {
            cm_spin_unlock(&area->lock);
            return CT_ERROR;
        }
    }

    if (area->free_items.count == 0) {
        *lockid = area->hwm;
        item = lock_addr(area, *lockid);
        item_size = sizeof(lock_item_t);
        ret = memset_sp(item, item_size, 0, item_size);
        knl_securec_check(ret);
        area->hwm++;
    } else {
        *lockid = area->free_items.first;
        item = lock_addr(area, *lockid);
        area->free_items.first = item->next;
        area->free_items.count--;

        if (area->free_items.count == 0) {
            area->free_items.first = CT_INVALID_ID32;
            area->free_items.last = CT_INVALID_ID32;
        }
    }

    cm_spin_unlock(&area->lock);
    return CT_SUCCESS;
}

static status_t lock_alloc_item(knl_session_t *session, lock_group_t *group, uint32 private_locks,
    lock_item_t **lock)
{
    lock_area_t *area = &session->kernel->lock_ctx;
    id_list_t *list = NULL;
    uint32 id;

    if (group->plock_id != CT_INVALID_ID32) {
        *lock = lock_addr(area, group->plock_id);
        group->plock_id = (*lock)->next;
        return CT_SUCCESS;
    }

    if (lock_area_alloc(session, &id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    *lock = lock_addr(area, id);
    (*lock)->next = CT_INVALID_ID32;
    (*lock)->rmid = session->rmid;

    list = (group->plocks.count < private_locks) ? &group->plocks : &group->glocks;
    if (list->count == 0) {
        list->first = id;
    } else {
        lock_addr(area, list->last)->next = id;
    }
    list->last = id;
    list->count++;

    return CT_SUCCESS;
}

status_t lock_alloc(knl_session_t *session, lock_type_t type, lock_item_t **lock)
{
    knl_rm_t *rm = session->rm;

    if (rm->txn == NULL && !IS_SESSION_OR_PL_LOCK(type)) {
        if (tx_begin(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (type == LOCK_TYPE_TS || type == LOCK_TYPE_TX) {
        return lock_alloc_item(session, &rm->sch_lock_group, CT_MAX_PRIVATE_LOCKS, lock);
    } else if (type == LOCK_TYPE_RCR_RX || type == LOCK_TYPE_PCR_RX) {
        return lock_alloc_item(session, &rm->row_lock_group, session->kernel->attr.private_row_locks, lock);
    } else if (type == LOCK_TYPE_ALCK_SS || type == LOCK_TYPE_ALCK_SX) {
        return lock_alloc_item(session, &session->alck_lock_group, CT_MAX_PRIVATE_LOCKS, lock);
    } else if (type == LOCK_TYPE_ALCK_TS || type == LOCK_TYPE_ALCK_TX) {
        return lock_alloc_item(session, &rm->alck_lock_group, CT_MAX_PRIVATE_LOCKS, lock);
    } else {
        return lock_alloc_item(session, &rm->key_lock_group, session->kernel->attr.private_key_locks, lock);
    }
}

status_t lock_itl(knl_session_t *session, page_id_t page_id, uint8 itl_id, knl_part_locate_t part_loc,
    page_id_t next_pagid, lock_type_t type)
{
    lock_item_t *item = NULL;

    knl_panic_log(session->rm->txn != NULL, "rm's txn is NULL, panic info: page %u-%u", page_id.file, page_id.page);

    if (lock_alloc(session, type, &item) != CT_SUCCESS) {
        return CT_ERROR;
    }

    item->page = (uint32)page_id.page;
    item->file = (uint16)page_id.file;
    item->itl = itl_id;
    item->part_no = part_loc.part_no;
    item->subpart_no = part_loc.subpart_no;
    item->type = (uint8)type;
    TO_PAGID_DATA(next_pagid, item->next_pagid);

    return CT_SUCCESS;
}

status_t lock_try_lock_table_shared_local(knl_session_t *session, knl_handle_t dc_entity, uint32 timeout_s,
                                          lock_item_t *item)
{
    schema_lock_t *lock;
    dc_entity_t *entity;
    date_t begin_time;
    int64 timeout_us;
    dc_entry_t *entry;

    entity = (dc_entity_t *)dc_entity;
    entry = entity->entry;
    lock = entry->sch_lock;
    item->dc_entry = entry;
    item->type = (uint8)LOCK_TYPE_TS;
    timeout_us = (int64)LOCK_TIMEOUT(timeout_s) * MICROSECS_PER_SECOND;
    begin_time = KNL_NOW(session);

    for (;;) {
        if (session->canceled) {
            CT_THROW_ERROR(ERR_OPERATION_CANCELED);
            break;
        }

        if (session->killed) {
            CT_THROW_ERROR(ERR_OPERATION_KILLED);
            break;
        }

        if (timeout_us != 0 && (KNL_NOW(session) - begin_time) > timeout_us) {
            CT_THROW_ERROR(ERR_RESOURCE_BUSY);
            break;
        }

        cm_spin_lock(&entry->sch_lock_mutex, &session->stat->spin_stat.stat_sch_lock);
        if (!entity->valid) {
            cm_spin_unlock(&entry->sch_lock_mutex);
            CT_THROW_ERROR(ERR_DC_INVALIDATED);
            break;
        }

        session->wtid.oid = entity->entry->id;
        session->wtid.uid = entity->entry->uid;
        if (lock->mode == LOCK_MODE_IX || lock->mode == LOCK_MODE_X) {
            session->wtid.is_locking = CT_TRUE;
            if (timeout_us != 0) {
                knl_begin_session_wait(session, ENQ_TX_TABLE_S, CT_FALSE);
                if (session->lock_dead_locked) {
                    cm_spin_unlock(&entry->sch_lock_mutex);
                    CT_THROW_ERROR(ERR_DEAD_LOCK, "table", session->id);
                    break;
                }
                cm_spin_unlock(&entry->sch_lock_mutex);
                cm_spin_sleep_and_stat2(1);
                knl_end_session_wait(session, ENQ_TX_TABLE_S);
                continue;
            } else {
                cm_spin_unlock(&entry->sch_lock_mutex);
                CT_THROW_ERROR(ERR_RESOURCE_BUSY);
                break;
            }
        }
        /*
         * current session has checked if entity is valid, however it may be invalidated by others
         * between last check and lock table by current session. recheck is necessary here.
         */
        if (!entity->valid) {
            cm_spin_unlock(&entry->sch_lock_mutex);
            CT_THROW_ERROR(ERR_DC_INVALIDATED);
            break;
        }

        lock->mode = LOCK_MODE_S;
        knl_panic(lock->shared_count != CT_INVALID_ID32);
        lock->shared_count++;
        SCH_LOCK_SET(session, lock);
        SCH_LOCK_INST_SET(session->kernel->dtc_attr.inst_id, lock);
        cm_spin_unlock(&entry->sch_lock_mutex);
        knl_end_session_wait(session, ENQ_TX_TABLE_S);
        session->wtid.is_locking = CT_FALSE;
        CT_LOG_DEBUG_INF("[DLS] add table shared lock table name %s", entry->name);
        return CT_SUCCESS;
    }
    item->dc_entry = NULL;
    session->lock_dead_locked = CT_FALSE;
    session->wtid.is_locking = CT_FALSE;
    knl_end_session_wait(session, ENQ_TX_TABLE_S);
    return CT_ERROR;
}

static status_t lock_try_lock_table_shared(knl_session_t *session, knl_handle_t dc_entity, uint32 timeout_s,
                                           lock_item_t *item)
{
    SYNC_POINT_GLOBAL_START(CANTIAN_LOCK_TABLE_S_LOCAL_BEFORE_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    status_t ret = lock_try_lock_table_shared_local(session, dc_entity, timeout_s, item);
    if (ret != CT_SUCCESS) {
        return ret;
    }

    SYNC_POINT_GLOBAL_START(CANTIAN_LOCK_TABLE_S_LOCAL_AFTER_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    if (!DB_ATTR_CLUSTER(session)) {
        return CT_SUCCESS;
    }

    knl_panic(session->kernel->db.status >= DB_STATUS_MOUNT);
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    dc_entry_t *entry = entity->entry;
    drc_local_latch *latch_stat = NULL;
    bool32 locked = CT_FALSE;
    bool32 local_lock_released = CT_FALSE;

    drc_local_lock_res_t *lock_res = drc_get_local_resx(&entry->ddl_latch.drid);
    drc_lock_local_resx(lock_res);
    drc_get_local_latch_statx(lock_res, &latch_stat);
    if (latch_stat->lock_mode == DRC_LOCK_NULL) {
        locked = dls_request_latch_s(session, &entry->ddl_latch.drid, CT_TRUE, timeout_s, CT_INVALID_ID32);
        cm_spin_lock(&entry->sch_lock_mutex, &session->stat->spin_stat.stat_sch_lock);
        if (locked && !entity->valid) {
            dls_request_clean_granted_map(session, &entry->ddl_latch.drid);
            locked = CT_FALSE;
            local_lock_released = CT_TRUE;
            // request master to unlock dls
        }
        cm_spin_unlock(&entry->sch_lock_mutex);
        if (!locked) {
            drc_unlock_local_resx(lock_res);
            unlock_table_local(session, entry, session->kernel->dtc_attr.inst_id, local_lock_released); /* the table may be dropped and invalidated from other nodes.*/
            return CT_ERROR;
        }
        latch_stat->lock_mode = DRC_LOCK_SHARE;
    }
    drc_unlock_local_resx(lock_res);
    SYNC_POINT_GLOBAL_START(CANTIAN_LOCK_TABLE_S_DLS_AFTER_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    return CT_SUCCESS;
}

status_t lock_table_shared_directly(knl_session_t *session, knl_handle_t dc)
{
    lock_item_t *item = NULL;
    dc_entity_t *entity = NULL;
    int32 code;
    knl_dictionary_t *pdc = (knl_dictionary_t *)dc;
    knl_dictionary_t reopen_dc;
    int32 ret;
    table_t *table = NULL;
    dc_user_t *user;
    dc_context_t *ctx = &session->kernel->dc_ctx;

    user = ctx->users[pdc->uid];

    if (DB_IS_READONLY(session)) {
        CT_THROW_ERROR(ERR_DATABASE_ROLE, "locking table shared", "in read only mode");
        return CT_ERROR;
    }

    if (DB_NOT_READY(session) || pdc->handle == NULL) {
        return CT_SUCCESS;
    }

    if (session->rm->txn == NULL) {
        if (tx_begin(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    entity = (dc_entity_t *)(pdc->handle);
    table = &entity->table;

    if (dc_locked_by_self(session, entity->entry) && !DB_IS_BG_ROLLBACK_SE(session)) {
        return CT_SUCCESS;
    }

    if (lock_alloc_item(session, &session->rm->direct_lock_group, CT_MAX_PRIVATE_LOCKS, &item) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lock_try_lock_table_shared(session, pdc->handle, LOCK_INF_WAIT, item) == CT_SUCCESS) {
        dc_load_all_part_segments(session, pdc->handle);
        return CT_SUCCESS;
    }

    for (;;) {
        code = cm_get_error_code();
        if (code != ERR_DC_INVALIDATED) {
            return CT_ERROR;
        }
        cm_reset_error();
        if (knl_open_dc_by_id(session, pdc->uid, pdc->oid, &reopen_dc, CT_TRUE) != CT_SUCCESS) {
            code = cm_get_error_code();
            /*
             * if table was dropped, table name described by error message is recycle table name.
             * We should reset it , and throw an error with table name which we want to lock.
             */
            if (code == ERR_TABLE_OR_VIEW_NOT_EXIST) {
                cm_reset_error();
                CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, user->desc.name, table->desc.name);
            }
            return CT_ERROR;
        }

        if (pdc->org_scn != reopen_dc.org_scn) {
            dc_close(&reopen_dc);
            CT_THROW_ERROR(ERR_TABLE_ID_NOT_EXIST, pdc->uid, pdc->oid);
            return CT_ERROR;
        }
        dc_close(pdc);
        ret = memcpy_sp(pdc, sizeof(knl_dictionary_t), &reopen_dc, sizeof(knl_dictionary_t));
        knl_securec_check(ret);

        if (lock_try_lock_table_shared(session, pdc->handle, LOCK_INF_WAIT, item) == CT_SUCCESS) {
            dc_load_all_part_segments(session, pdc->handle);
            return CT_SUCCESS;
        }
    }
}

static status_t lock_local_temp_table(knl_session_t *session, lock_group_t *group, knl_handle_t dc_entity,
    lock_mode_t mode)
{
    lock_item_t *item = NULL;
    dc_entity_t *entity = (dc_entity_t *)dc_entity;

    CT_LOG_DEBUG_INF("[lock_local_temp_table] start to lock temp table %s in mode %u", entity->entry->name, mode);

    if (entity->entry->ltt_lock_mode != LOCK_MODE_IDLE) {
        entity->entry->ltt_lock_mode = (entity->entry->ltt_lock_mode == LOCK_MODE_X) ? LOCK_MODE_X : mode;
        return CT_SUCCESS;
    }

    if (session->rm->txn == NULL) {
        if (tx_begin(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (DB_ATTR_COMPATIBLE_MYSQL(session)) {
        CT_LOG_DEBUG_INF("[lock_local_temp_table] Finish to lock temp table %s in mode %u for mysql, not alloc item",
                       entity->entry->name, mode);
        return CT_SUCCESS;
    }

    if (lock_alloc_item(session, group, CT_PRIVATE_TABLE_LOCKS, &item) != CT_SUCCESS) {
        return CT_ERROR;
    }

    item->type = (uint8)((mode == LOCK_MODE_S) ? LOCK_TYPE_TS : LOCK_TYPE_TX);
    item->dc_entry = entity->entry;
    entity->entry->ltt_lock_mode = mode;

    CT_LOG_DEBUG_INF("[lock_local_temp_table] Finish to lock temp table %s in mode %u", entity->entry->name, mode);

    return CT_SUCCESS;
}

status_t lock_table_shared(knl_session_t *session, knl_handle_t dc_entity, uint32 timeout_s)
{
    lock_item_t *item = NULL;
    dc_entity_t *entity = NULL;

    if (!DB_IS_PRIMARY(&session->kernel->db) &&
        (((dc_entity_t *)dc_entity)->type == DICT_TYPE_TEMP_TABLE_SESSION ||
        ((dc_entity_t *)dc_entity)->type == DICT_TYPE_TEMP_TABLE_TRANS)) {
        CT_LOG_RUN_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_20, "Do not lock temp table in slave mode");
        return CT_SUCCESS;
    }

    if (DB_IS_READONLY(session)) {
        CT_THROW_ERROR(ERR_DATABASE_ROLE, "locking table shared", "in read only mode");
        return CT_ERROR;
    }

    if (DB_NOT_READY(session) || dc_entity == NULL) {
        return CT_SUCCESS;
    }

    if (session->rm->txn == NULL) {
        if (tx_begin(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    entity = (dc_entity_t *)dc_entity;

    if (IS_LTT_BY_ID((entity->entry->id))) {
        return lock_local_temp_table(session, &session->rm->sch_lock_group, dc_entity, LOCK_MODE_S);
    }

    if (dc_locked_by_self(session, entity->entry) && !DB_IS_BG_ROLLBACK_SE(session)) {
        return CT_SUCCESS;
    }

    if (lock_alloc(session, LOCK_TYPE_TS, &item) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return lock_try_lock_table_shared(session, dc_entity, timeout_s, item);
}

status_t lock_table_exclusive_mode(knl_session_t *session, knl_handle_t dc_entity, knl_handle_t dc_entry,
                                   uint32 timeout_s, uint8 inst_id)
{
    time_t begin_time;
    bool32 lock_ix = CT_FALSE;
    bool32 is_locked = CT_FALSE;
    schema_lock_t *lock;
    dc_entry_t *entry;
    int64 timeout_us;
    dc_entity_t *entity;

    entity = (dc_entity_t *)dc_entity;
    entry = (dc_entry_t *)dc_entry;
    lock = entry->sch_lock;
    timeout_us = (int64)LOCK_TIMEOUT(timeout_s) * MICROSECS_PER_SECOND;
    begin_time = KNL_NOW(session);

    // autonomous sessions should not wait for exclusive lock
    if (KNL_IS_AUTON_SE(session)) {
        timeout_us = 0;
    }

    for (;;) {
        if (session->canceled) {
            CT_THROW_ERROR(ERR_OPERATION_CANCELED);
            break;
        }

        if (session->killed) {
            CT_THROW_ERROR(ERR_OPERATION_KILLED);
            break;
        }

        if (timeout_us != 0 && (KNL_NOW(session) - begin_time) > timeout_us) {
            CT_THROW_ERROR(ERR_RESOURCE_BUSY);
            break;
        }

        cm_spin_lock(&entry->sch_lock_mutex, &session->stat->spin_stat.stat_sch_lock);
        if (SECUREC_UNLIKELY(entity != NULL && !entity->valid)) {
            cm_spin_unlock(&entry->sch_lock_mutex);
            CT_THROW_ERROR(ERR_DC_INVALIDATED);
            break;
        }

        session->wtid.oid = entry->id;
        session->wtid.uid = entry->uid;
        if (lock->mode == LOCK_MODE_X) {
            knl_begin_session_wait(session, ENQ_TX_TABLE_X, CT_FALSE);
            if (session->lock_dead_locked) {
                cm_spin_unlock(&entry->sch_lock_mutex);
                CT_THROW_ERROR(ERR_DEAD_LOCK, "table", session->id);
                break;
            }

            if (dc_locked_by_self(session, entry)) {
                cm_spin_unlock(&entry->sch_lock_mutex);
                knl_end_session_wait(session, ENQ_TX_TABLE_X);
                session->wtid.is_locking = CT_FALSE;
                return CT_SUCCESS;
            }

            cm_spin_unlock(&entry->sch_lock_mutex);
            if (timeout_us == 0) {
                CT_THROW_ERROR(ERR_RESOURCE_BUSY);
                break;
            }
            cm_spin_sleep_and_stat2(1);
            continue;
        }

        // locked by self in shared mode
        if (dc_locked_by_self(session, entry) && lock->shared_count == 1) {
            lock->shared_count--;
            lock->mode = LOCK_MODE_X;
            cm_spin_unlock(&entry->sch_lock_mutex);
            return CT_SUCCESS;
        }

        // if entry is locked by others or not
        if (dc_locked_by_self(session, entry)) {
            is_locked = (lock->shared_count > 1);
        } else {
            is_locked = (lock->shared_count > 0);
        }

        if (is_locked) {
            knl_begin_session_wait(session, ENQ_TX_TABLE_X, CT_FALSE);
            if (session->lock_dead_locked) {
                cm_spin_unlock(&entry->sch_lock_mutex);
                CT_THROW_ERROR(ERR_DEAD_LOCK, "table", session->id);
                break;
            }
            if (timeout_us == 0) {
                cm_spin_unlock(&entry->sch_lock_mutex);
                CT_THROW_ERROR(ERR_RESOURCE_BUSY);
                break;
            }

            if (lock->mode == LOCK_MODE_S) {
                lock->mode = LOCK_MODE_IX;
                lock_ix = CT_TRUE;
            }

            cm_spin_unlock(&entry->sch_lock_mutex);
            cm_spin_sleep();
            continue;
        }

        if (lock->mode == LOCK_MODE_IX && !lock_ix) {
            knl_begin_session_wait(session, ENQ_TX_TABLE_X, CT_FALSE);
            if (session->lock_dead_locked) {
                cm_spin_unlock(&entry->sch_lock_mutex);
                CT_THROW_ERROR(ERR_DEAD_LOCK, "table", session->id);
                break;
            }
            cm_spin_unlock(&entry->sch_lock_mutex);
            cm_spin_sleep();
            continue;
        }

        if (SECUREC_UNLIKELY(entity != NULL && !entity->valid)) {
            /* there is no other sessions hold lock on this table */
            lock->mode = LOCK_MODE_IDLE;
            cm_spin_unlock(&entry->sch_lock_mutex);
            CT_THROW_ERROR(ERR_DC_INVALIDATED);
            break;
        }

        // locked by self before and X now
        if (dc_locked_by_self(session, entry)) {
            lock->shared_count--;
            knl_panic(lock->shared_count == 0);
        }

        lock->mode = LOCK_MODE_X;
        SCH_LOCK_SET(session, lock);
        SCH_LOCK_INST_SET(inst_id, lock);
        cm_spin_unlock(&entry->sch_lock_mutex);
        knl_end_session_wait(session, ENQ_TX_TABLE_X);
        session->wtid.is_locking = CT_FALSE;
        return CT_SUCCESS;
    }

    knl_end_session_wait(session, ENQ_TX_TABLE_X);
    cm_spin_lock(&entry->sch_lock_mutex, &session->stat->spin_stat.stat_sch_lock);
    /* 1 lock_upgrade_table_lock has the highest priority, as a result, if session has lock table in IX mode,
     * session which is upgrading table lock may lock table in X mode.
     * 2 lock is null in case table has been dropped, we should check lock_ix first, because if lock_ix is true,
     * lock is ofcause not null.
     */
    if (lock_ix && lock->mode == LOCK_MODE_IX) {
        lock->mode = (lock->shared_count > 0 ? LOCK_MODE_S : LOCK_MODE_IDLE);
    }
    cm_spin_unlock(&entry->sch_lock_mutex);
    session->lock_dead_locked = CT_FALSE;
    session->wtid.is_locking = CT_FALSE;
    return CT_ERROR;
}

status_t lock_table_in_exclusive_mode(knl_session_t *session, knl_handle_t dc_entity, knl_handle_t dc_entry,
                                      uint32 timeout_s)
{
    status_t ret = CT_SUCCESS;
    database_t *db = &session->kernel->db;

    SYNC_POINT_GLOBAL_START(CANTIAN_LOCK_TABLE_X_LOCAL_BEFORE_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    ret = lock_table_exclusive_mode(session, dc_entity, dc_entry, timeout_s, session->kernel->dtc_attr.inst_id);
    if (ret != CT_SUCCESS) {
        CT_LOG_DEBUG_ERR("[DLS] local lock table exclusive failed, table name %s errcode %u",
                         ((dc_entry_t *)dc_entry)->name, ret);
        return ret;
    }
    SYNC_POINT_GLOBAL_START(CANTIAN_LOCK_TABLE_X_LOCAL_AFTER_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    if (!DB_ATTR_CLUSTER(session)) {
        return CT_SUCCESS;
    }

    knl_panic(db->status >= DB_STATUS_MOUNT);
    drc_local_latch *latch_stat = NULL;
    bool32 locked = CT_FALSE;
    bool32 local_lock_released = CT_FALSE;
    dc_entry_t *entry = (dc_entry_t *)dc_entry;

    drc_local_lock_res_t *lock_res = drc_get_local_resx(&entry->ddl_latch.drid);
    drc_lock_local_resx(lock_res);
    drc_get_local_latch_statx(lock_res, &latch_stat);
    if (latch_stat->lock_mode != DRC_LOCK_EXCLUSIVE) {
        locked = dls_request_latch_x(session, &entry->ddl_latch.drid, CT_TRUE, timeout_s, CT_INVALID_ID32);
        dc_entity_t *entity = (dc_entity_t *)dc_entity;
        cm_spin_lock(&entry->sch_lock_mutex, &session->stat->spin_stat.stat_sch_lock);
        if (locked && entity != NULL && !entity->valid) {
            dls_request_clean_granted_map(session, &entry->ddl_latch.drid);
            locked = CT_FALSE;
            local_lock_released = CT_TRUE;
            // request master to unlock dls
        }
        cm_spin_unlock(&entry->sch_lock_mutex);
        if (!locked) {
            drc_unlock_local_resx(lock_res);
            unlock_table_local(session, entry, session->kernel->dtc_attr.inst_id, local_lock_released); /* the table may be dropped and invalidated from other nodes.*/
            return CT_ERROR;
        }
        latch_stat->lock_mode = DRC_LOCK_EXCLUSIVE;
    }
    drc_unlock_local_resx(lock_res);
    SYNC_POINT_GLOBAL_START(CANTIAN_LOCK_TABLE_X_DLS_AFTER_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    CT_LOG_DEBUG_INF("end lock table in exclusive mode");
    return CT_SUCCESS;
}

static status_t lock_try_lock_table_exclusive(knl_session_t *session, knl_handle_t dc_entity, uint32 timeout_s,
    lock_item_t *item)
{
    dc_entity_t *entity;
    dc_entry_t *entry;

    entity = (dc_entity_t *)dc_entity;
    entry = entity->entry;
    item->dc_entry = entry;
    item->type = (uint8)LOCK_TYPE_TX;

    if (lock_table_in_exclusive_mode(session, entity, entry, timeout_s) != CT_SUCCESS) {
        item->dc_entry = NULL;
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t lock_table_exclusive(knl_session_t *session, knl_handle_t dc_entity, uint32 wait_time)
{
    lock_item_t *item = NULL;

    if (DB_IS_READONLY(session)) {
        CT_THROW_ERROR(ERR_DATABASE_ROLE, "locking table exclusively", "in read only mode");
        return CT_ERROR;
    }

    if (!DB_IS_MAINTENANCE(session) && DB_IN_BG_ROLLBACK(session) && !DB_IS_BG_ROLLBACK_SE(session)) {
        CT_THROW_ERROR_EX(ERR_INVALID_OPERATION, ",txn area is rollbacking,can't lock table exclusive,db_status[%u]",
            (uint32)(session->kernel->db.status));
        knl_panic_log(0, "txn area is rollbacking,can't lock table exclusive");
        return CT_ERROR;
    }

    if (IS_LTT_BY_ID(((dc_entity_t *)dc_entity)->entry->id)) {
        return lock_local_temp_table(session, &session->rm->sch_lock_group, dc_entity, LOCK_MODE_X);
    }

    if (lock_alloc(session, LOCK_TYPE_TX, &item) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return lock_try_lock_table_exclusive(session, dc_entity, wait_time, item);
}

#define LOCK_UPGRADE_WAIT_TIMES 1000

status_t lock_upgrade_table_lock(knl_session_t *session, knl_handle_t dc_entity, uint32 timeout_s)
{
    lock_area_t *ctx = &session->kernel->lock_ctx;
    schema_lock_t *lock;
    dc_entity_t *entity;
    bool32 lock_ix = CT_FALSE;
    dc_entry_t *entry;
    uint32 wait_times = 0;
    time_t begin_time;

    entity = (dc_entity_t *)dc_entity;
    entry = entity->entry;
    lock = entry->sch_lock;
    session->wtid.oid = entry->id;
    session->wtid.uid = entry->uid;

    begin_time = KNL_NOW(session);
    cm_spin_lock(&ctx->upgrade_lock, NULL);

    for (;;) {
        if (session->canceled) {
            CT_THROW_ERROR(ERR_OPERATION_CANCELED);
            break;
        }

        if (session->killed) {
            CT_THROW_ERROR(ERR_OPERATION_KILLED);
            break;
        }

        if (timeout_s != LOCK_INF_WAIT &&
            (KNL_NOW(session) - begin_time) > (int64)LOCK_TIMEOUT(timeout_s) * MICROSECS_PER_SECOND) {
            CT_THROW_ERROR(ERR_RESOURCE_BUSY);
            break;
        }
        cm_spin_lock(&entry->sch_lock_mutex, &session->stat->spin_stat.stat_sch_lock);
        knl_panic_log(entity->valid, "current entity is invalid, panic info: table %s", entity->table.desc.name);
        knl_panic_log(dc_locked_by_self(session, entry), "table was not locked by self, panic info: table %s",
                      entity->table.desc.name);
        if (lock->mode == LOCK_MODE_X) {
            session->wtid.is_locking = CT_FALSE;
            session->lock_dead_locked = CT_FALSE;
            knl_end_session_wait(session, ENQ_TX_TABLE_X);
            cm_spin_unlock(&entry->sch_lock_mutex);
            cm_spin_unlock(&ctx->upgrade_lock);
            return CT_SUCCESS;
        }

        if (lock->shared_count > 1) {
            /* if locked in S mode, change to IX mode */
            if (lock->mode == LOCK_MODE_S) {
                lock_ix = CT_TRUE;
                lock->mode = LOCK_MODE_IX;
            }

            if (wait_times == LOCK_UPGRADE_WAIT_TIMES) {
                session->wtid.is_locking = CT_FALSE;
                knl_end_session_wait(session, ENQ_TX_TABLE_X);
                lock->mode = LOCK_MODE_S;
                cm_spin_unlock(&entry->sch_lock_mutex);
                cm_spin_unlock(&ctx->upgrade_lock);

                /*
                 * unlock upgrade lock, and sleep 100ms waiting for DML commit or concurrent
                 * upgrading lock finished.
                 */
                lock_ix = CT_FALSE;
                wait_times = 0;
                cm_sleep(100);
                cm_spin_lock(&ctx->upgrade_lock, NULL);
                continue;
            }
            cm_spin_unlock(&entry->sch_lock_mutex);

            if (session->lock_dead_locked) {
                CT_THROW_ERROR(ERR_DEAD_LOCK, "table", session->id);
                break;
            }

            knl_begin_session_wait(session, ENQ_TX_TABLE_X, CT_FALSE);
            session->wtid.is_locking = CT_TRUE;
            cm_spin_sleep();
            wait_times++;
            continue;
        }
        session->lock_dead_locked = CT_FALSE;
        session->wtid.is_locking = CT_FALSE;
        knl_end_session_wait(session, ENQ_TX_TABLE_X);
        lock->shared_count--;
        knl_panic(lock->shared_count == 0);
        lock->mode = LOCK_MODE_X;
        cm_spin_unlock(&entry->sch_lock_mutex);
        cm_spin_unlock(&ctx->upgrade_lock);
        //must get table lock x, then can degrade and upgrade
        if (DB_ATTR_CLUSTER(session)) {
            knl_panic(session->kernel->db.status >= DB_STATUS_MOUNT);
            drc_local_latch *latch_stat = NULL;
            bool32 locked = CT_FALSE;

            CT_LOG_DEBUG_INF("[DLS] upgrade table lock(%u/%u/%u/%u/%u), table name %s", entry->ddl_latch.drid.type,
                             entry->ddl_latch.drid.uid, entry->ddl_latch.drid.id, entry->ddl_latch.drid.idx,
                             entry->ddl_latch.drid.part, entry->name);

            drc_local_lock_res_t *lock_res = drc_get_local_resx(&entry->ddl_latch.drid);
            drc_lock_local_resx(lock_res);
            drc_get_local_latch_statx(lock_res, &latch_stat);
            if (latch_stat->lock_mode != DRC_LOCK_EXCLUSIVE) {
                knl_panic(latch_stat->lock_mode == DRC_LOCK_SHARE);
                locked = dls_request_latch_x(session, &entry->ddl_latch.drid, CT_TRUE, timeout_s, CT_INVALID_ID32);
                if (!locked) {
                    drc_unlock_local_resx(lock_res);
                    cm_sleep(DLS_TABLE_WAIT_TIMEOUT);
                    CT_LOG_DEBUG_INF(
                        "[DLS] upgrade table lock(%u/%u/%u/%u/%u), try dls failed, will restart, table name %s",
                        entry->ddl_latch.drid.type, entry->ddl_latch.drid.uid, entry->ddl_latch.drid.id,
                        entry->ddl_latch.drid.idx, entry->ddl_latch.drid.part, entry->name);

                    continue;
                }
                latch_stat->lock_mode = DRC_LOCK_EXCLUSIVE;
            }
            drc_unlock_local_resx(lock_res);
        }
        return CT_SUCCESS;
    }
    session->wtid.is_locking = CT_FALSE;
    session->lock_dead_locked = CT_FALSE;
    knl_end_session_wait(session, ENQ_TX_TABLE_X);
    cm_spin_lock(&entry->sch_lock_mutex, &session->stat->spin_stat.stat_sch_lock);
    if (lock->mode == LOCK_MODE_IX && lock_ix) {
        lock->mode = LOCK_MODE_S;
    }
    cm_spin_unlock(&entry->sch_lock_mutex);
    cm_spin_unlock(&ctx->upgrade_lock);

    return CT_ERROR;
}

void lock_degrade_table_lock(knl_session_t *session, knl_handle_t dc_entity)
{
    schema_lock_t *lock;
    dc_entity_t *entity;
    dc_entry_t *entry;

    entity = (dc_entity_t *)dc_entity;
    entry = entity->entry;
    lock = entry->sch_lock;

    knl_panic_log(lock->mode == LOCK_MODE_X, "lock's mode is abnormal, panic info: table %s", entity->table.desc.name);
    knl_panic_log(dc_locked_by_self(session, entry), "table was not locked by self, panic info: table %s",
                  entity->table.desc.name);

    cm_spin_lock(&entry->sch_lock_mutex, &session->stat->spin_stat.stat_sch_lock);
    lock->mode = LOCK_MODE_S;
    knl_panic(lock->shared_count == 0);
    lock->shared_count = 1;
    cm_spin_unlock(&entry->sch_lock_mutex);
}

void unlock_table_local(knl_session_t *session, knl_handle_t dc_entry, uint32 inst_id, bool32 is_clean)
{
    dc_entry_t *entry = (dc_entry_t *)dc_entry;
    if (entry == NULL) {
        return;
    }

    if (IS_LTT_BY_ID(entry->id)) {
        entry->ltt_lock_mode = LOCK_MODE_IDLE;
        return;
    }

    knl_panic(session->kernel->db.status >= DB_STATUS_MOUNT);
    schema_lock_t *lock = entry->sch_lock;

    cm_spin_lock(&entry->sch_lock_mutex, &session->stat->spin_stat.stat_sch_lock);
    if (lock == NULL) {
        knl_panic(is_clean);
        cm_spin_unlock(&entry->sch_lock_mutex);
        return;
    }

    knl_panic(lock->inst_id == CT_INVALID_ID8 || lock->inst_id == inst_id);

    if (lock->mode == LOCK_MODE_S || lock->mode == LOCK_MODE_IX) {
        knl_panic_log(lock->shared_count > 0, "lock's shared_count is abnormal, panic info: shared_count %u",
                      lock->shared_count);
        lock->shared_count--;
        if (lock->shared_count == 0 && lock->mode == LOCK_MODE_S) {
            lock->mode = LOCK_MODE_IDLE;
            SCH_LOCK_INST_CLEAN(lock);
        }
    } else if (lock->mode == LOCK_MODE_X) {
        lock->mode = LOCK_MODE_IDLE;
        knl_panic(lock->shared_count == 0);
        SCH_LOCK_INST_CLEAN(lock);
        SCH_LOCK_DLSTBL_CLEAN(lock);
    } else {
        // LOCK_MODE_IDLE, do nothing
    }

    SCH_LOCK_CLEAN(session, lock);
    cm_spin_unlock(&entry->sch_lock_mutex);
}

void unlock_table(knl_session_t *session, lock_item_t *item)
{
    unlock_table_local(session, item->dc_entry, session->kernel->dtc_attr.inst_id, CT_FALSE);
}

/*
 * api for DDL X_lock, default wait time is set by DDL_LOCK_TIMEOUT
 * otherwise, some DDL need wait infinite time like rebuild online
 */
status_t lock_table_directly(knl_session_t *session, knl_handle_t dc, uint32 timeout)
{
    lock_item_t *item = NULL;
    knl_dictionary_t *pdc = (knl_dictionary_t *)dc;
    knl_dictionary_t reopen_dc;
    int32 ret;
    dc_entity_t *entity;
    table_t *table;
    dc_user_t *user;
    dc_context_t *ctx = &session->kernel->dc_ctx;
    knl_rm_t *rm = session->rm;
    int32 code;

    user = ctx->users[pdc->uid];
    entity = DC_ENTITY(pdc);
    table = &entity->table;

    if (DB_IS_READONLY(session)) {
        CT_THROW_ERROR(ERR_DATABASE_ROLE, "locking table directly", "in read only mode");
        return CT_ERROR;
    }

    if (!DB_IS_MAINTENANCE(session) && DB_IN_BG_ROLLBACK(session) && !DB_IS_BG_ROLLBACK_SE(session)) {
        CT_THROW_ERROR_EX(ERR_INVALID_OPERATION, ",txn area is rollbacking,can't lock table exclusive,db_status[%u]",
            (uint32)(session->kernel->db.status));
        return CT_ERROR;
    }

    if (rm->txn == NULL) {
        if (tx_begin(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (timeout > DEADLOCK_DETECT_TIME) {
        session->wtid.is_locking = CT_TRUE;
    }

    if (IS_LTT_BY_ID(((knl_dictionary_t *)dc)->oid)) {
        return lock_local_temp_table(session, &rm->direct_lock_group, pdc->handle, LOCK_MODE_X);
    }

    if (lock_alloc_item(session, &rm->direct_lock_group, CT_PRIVATE_TABLE_LOCKS, &item) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lock_try_lock_table_exclusive(session, pdc->handle, timeout, item) == CT_SUCCESS) {
        knl_set_session_scn(session, CT_INVALID_ID64);
        dc_load_all_part_segments(session, pdc->handle);
        return CT_SUCCESS;
    }

    for (;;) {
        code = cm_get_error_code();
        if (code != ERR_DC_INVALIDATED) {
            return CT_ERROR;
        }
        cm_reset_error();
        if (knl_open_dc_by_id(session, pdc->uid, pdc->oid, &reopen_dc, CT_TRUE) != CT_SUCCESS) {
            code = cm_get_error_code();
            /*
             * if table was dropped, table name described by error message is recycle table name.
             * We should reset it , and throw an error with table name which we want to lock.
             */
            if (code == ERR_TABLE_OR_VIEW_NOT_EXIST) {
                cm_reset_error();
                CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, user->desc.name, table->desc.name);
            }
            return CT_ERROR;
        }

        if (pdc->org_scn != reopen_dc.org_scn) {
            dc_close(&reopen_dc);
            CT_THROW_ERROR(ERR_TABLE_ID_NOT_EXIST, pdc->uid, pdc->oid);
            return CT_ERROR;
        }
        dc_close(pdc);
        ret = memcpy_sp(pdc, sizeof(knl_dictionary_t), &reopen_dc, sizeof(knl_dictionary_t));
        knl_securec_check(ret);

        if (timeout > DEADLOCK_DETECT_TIME) {
            session->wtid.is_locking = CT_TRUE;
        }

        if (lock_try_lock_table_exclusive(session, pdc->handle, timeout, item) == CT_SUCCESS) {
            knl_set_session_scn(session, CT_INVALID_ID64);
            dc_load_all_part_segments(session, pdc->handle);
            return CT_SUCCESS;
        }
    }
}

status_t lock_table_ux(knl_session_t *session, knl_handle_t dc_entry)
{
    lock_item_t *item = NULL;

    if (!DB_IS_MAINTENANCE(session) && DB_IN_BG_ROLLBACK(session) && !DB_IS_BG_ROLLBACK_SE(session)) {
        CT_THROW_ERROR_EX(ERR_INVALID_OPERATION, ",txn area is rollbacking,can't lock table exclusive,db_status[%u]",
            (uint32)(session->kernel->db.status));
        knl_panic_log(0, "txn area is rollbacking,can't lock table exclusive");
        return CT_ERROR;
    }

    if (session->rm->txn == NULL) {
        if (tx_begin(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (lock_alloc_item(session, &session->rm->direct_lock_group, CT_PRIVATE_TABLE_LOCKS, &item) != CT_SUCCESS) {
        return CT_ERROR;
    }

    item->dc_entry = (dc_entry_t *)dc_entry;
    item->type = (uint8)LOCK_TYPE_TX;

    uint32 timeout = session->kernel->attr.ddl_lock_timeout;
    if (timeout > DEADLOCK_DETECT_TIME) {
        session->wtid.is_locking = CT_TRUE;
    }

    if (lock_table_in_exclusive_mode(session, NULL, dc_entry, timeout) != CT_SUCCESS) {
        item->dc_entry = NULL;
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static void unlock_heap_list(knl_session_t *session, uint32 start_id_input, uint32 end_id, bool32 delay_cleanout)
{
    uint32 start_id = start_id_input;
    lock_area_t *area = &session->kernel->lock_ctx;
    lock_item_t *item = NULL;
    lock_type_t type;

    while (start_id != end_id) {
        item = lock_addr(area, start_id);

        type = item->type;
        if (type == LOCK_TYPE_FREE) {
            break;
        }

        item->type = LOCK_TYPE_FREE;

        if (delay_cleanout) {
            start_id = item->next;
            continue;
        }

        if (type == LOCK_TYPE_RCR_RX) {
            heap_clean_lock(session, item);
        } else {
            pcrh_clean_lock(session, item);
        }

        start_id = item->next;
    }
}

static void unlock_key_list(knl_session_t *session, uint32 start_id_input, uint32 end_id, bool32 delay_cleanout)
{
    uint32 start_id = start_id_input;
    lock_area_t *area = &session->kernel->lock_ctx;
    lock_item_t *item = NULL;
    lock_type_t type;

    while (start_id != end_id) {
        item = lock_addr(area, start_id);

        type = item->type;
        if (type == LOCK_TYPE_FREE) {
            break;
        }

        item->type = LOCK_TYPE_FREE;

        if (delay_cleanout) {
            start_id = item->next;
            continue;
        }

        if (type == LOCK_TYPE_RCR_KX) {
            btree_clean_lock(session, item);
        } else {
            pcrb_clean_lock(session, item);
        }

        start_id = item->next;
    }
}

static void unlock_table_list(knl_session_t *session, uint32 start_id_input, uint32 end_id)
{
    uint32 start_id = start_id_input;
    lock_area_t *area = &session->kernel->lock_ctx;
    lock_item_t *item = NULL;

    while (start_id != end_id) {
        item = lock_addr(area, start_id);
        if (item->type == LOCK_TYPE_FREE) { // for private locks
            break;
        }

        item->type = LOCK_TYPE_FREE;
        unlock_table(session, item);
        start_id = item->next;
    }
}

static void lock_release_lock_list(lock_area_t *area, id_list_t *list)
{
    lock_item_t *last = NULL;

    if (list->count == 0) {
        return;
    }

    cm_spin_lock(&area->lock, NULL);
    if (area->free_items.count == 0) {
        area->free_items = *list;
    } else {
        last = lock_addr(area, list->last);
        last->next = area->free_items.first;
        area->free_items.first = list->first;
        area->free_items.count += list->count;
    }
    cm_spin_unlock(&area->lock);
}

static inline void lock_release_glocks(knl_session_t *session, lock_group_t *group)
{
    lock_area_t *area = &session->kernel->lock_ctx;
    lock_release_lock_list(area, &group->glocks);
}

static inline void lock_release_plocks(knl_session_t *session, lock_group_t *group)
{
    lock_area_t *area = &session->kernel->lock_ctx;
    lock_release_lock_list(area, &group->plocks);
}

void lock_free_sch_group(knl_session_t *session)
{
    lock_group_t *group = &session->rm->sch_lock_group;

    if (group->plocks.count != 0) {
        unlock_table_list(session, group->plocks.first, group->plock_id);
    }

    if (group->glocks.count != 0) {
        unlock_table_list(session, group->glocks.first, CT_INVALID_ID32);
    }
    lock_release_glocks(session, group);
}

static inline void lock_free_row_group(knl_session_t *session, knl_rm_t *rm, bool32 delay_cleanout)
{
    lock_group_t *group = &rm->row_lock_group;

    if (group->plocks.count != 0) {
        unlock_heap_list(session, group->plocks.first, group->plock_id, delay_cleanout);
    }

    if (group->glocks.count != 0) {
        unlock_heap_list(session, group->glocks.first, CT_INVALID_ID32, delay_cleanout);
    }
    lock_release_glocks(session, group);
}

static inline void lock_free_key_group(knl_session_t *session, knl_rm_t *rm, bool32 delay_cleanout)
{
    lock_group_t *group = &rm->key_lock_group;

    if (group->plocks.count != 0) {
        unlock_key_list(session, group->plocks.first, group->plock_id, delay_cleanout);
    }

    if (group->glocks.count != 0) {
        unlock_key_list(session, group->glocks.first, CT_INVALID_ID32, delay_cleanout);
    }
    lock_release_glocks(session, group);
}

static void unlock_tx_alck_list(knl_session_t *session, uint32 start_id_input, uint32 end_id)
{
    uint32 start_id = start_id_input;
    lock_area_t *area = &session->kernel->lock_ctx;
    lock_item_t *item = NULL;

    while (start_id != end_id) {
        item = lock_addr(area, start_id);
        if (item->type == LOCK_TYPE_ALCK_TS) {
            alck_tx_unlock_sh(session, item->alck_id);
        } else {
            cm_assert(item->type == LOCK_TYPE_ALCK_TX);
            alck_tx_unlock_ex(session, item->alck_id);
        }
        item->type = LOCK_TYPE_FREE;
        start_id = item->next;
    }
}

static inline void lock_free_alck_group(knl_session_t *session)
{
    lock_group_t *group = &session->rm->alck_lock_group;
    if (group->plocks.count != 0) {
        unlock_tx_alck_list(session, group->plocks.first, group->plock_id);
    }

    if (group->glocks.count != 0) {
        unlock_tx_alck_list(session, group->glocks.first, CT_INVALID_ID32);
    }
    lock_release_glocks(session, group);
}

static inline void unlock_se_alck_list(knl_session_t *session, uint32 start_id_input, uint32 end_id)
{
    uint32 start_id = start_id_input;
    lock_area_t *area = &session->kernel->lock_ctx;
    lock_item_t *item = NULL;

    while (start_id != end_id) {
        item = lock_addr(area, start_id);
        alck_se_unlock_all(session, item->alck_id);
        start_id = item->next;
    }
}

void lock_destroy_se_alcks(knl_session_t *session)
{
    lock_group_t *group = &session->alck_lock_group;
    if (group->plocks.count != 0) {
        unlock_se_alck_list(session, group->plocks.first, group->plock_id);
    }

    if (group->glocks.count != 0) {
        unlock_se_alck_list(session, group->glocks.first, CT_INVALID_ID32);
    }

    lock_release_plocks(session, group);
    lock_release_glocks(session, group);
    lock_init_group(group);
}

static inline void lock_reset_group(lock_group_t *group)
{
    group->plock_id = (group->plocks.count > 0) ? group->plocks.first : CT_INVALID_ID32;
    cm_reset_id_list(&group->glocks);
}

void lock_reset(knl_rm_t *rm)
{
    lock_reset_group(&rm->sch_lock_group);
    lock_reset_group(&rm->row_lock_group);
    lock_reset_group(&rm->key_lock_group);
    lock_reset_group(&rm->alck_lock_group);
}

void lock_free(knl_session_t *session, knl_rm_t *rm)
{
    lock_group_t *row = &rm->row_lock_group;
    lock_group_t *key = &rm->key_lock_group;
    bool32 delay_cleanout = CT_FALSE;

    if (row->glocks.count + key->glocks.count > LOCKS_THRESHOLD(session)
        && session->kernel->attr.delay_cleanout) {
        delay_cleanout = CT_TRUE;
    }

    lock_free_key_group(session, rm, delay_cleanout);
    lock_free_row_group(session, rm, delay_cleanout);
    lock_free_sch_group(session);
    lock_free_alck_group(session);
}

static inline void lock_reset_svpt_group(knl_session_t *session, lock_group_t *group, lock_group_t *svpt_group)
{
    lock_area_t *area = &session->kernel->lock_ctx;
    lock_item_t *item = NULL;

    if (svpt_group->plock_id == CT_INVALID_ID32) {
        group->plock_id = (svpt_group->plocks.count == 0) ?
            group->plocks.first : LOCK_NEXT(area, svpt_group->plocks.last);
    } else {
        group->plock_id = svpt_group->plock_id;
    }

    group->glocks = svpt_group->glocks;
    if (group->glocks.last != CT_INVALID_ID32) {
        item = lock_addr(area, group->glocks.last);
        item->next = CT_INVALID_ID32;
    }
}

static void lock_release_to_svpt(knl_session_t *session, lock_group_t *group, lock_group_t *svpt_group,
    uint32 start_gid)
{
    lock_area_t *area = &session->kernel->lock_ctx;
    lock_item_t *last = NULL;

    if (group->glocks.count == svpt_group->glocks.count) {
        return;
    }

    cm_spin_lock(&area->lock, NULL);
    if (area->free_items.count == 0) {
        area->free_items.first = start_gid;
        area->free_items.last = group->glocks.last;
        area->free_items.count = group->glocks.count - svpt_group->glocks.count;
        cm_spin_unlock(&area->lock);
        return;
    }

    last = lock_addr(area, group->glocks.last);
    last->next = area->free_items.first;
    area->free_items.first = start_gid;
    area->free_items.count += (group->glocks.count - svpt_group->glocks.count);
    cm_spin_unlock(&area->lock);
}

static void lock_free_sch_svpt(knl_session_t *session, lock_group_t *svpt_group)
{
    lock_group_t *group = &session->rm->sch_lock_group;
    lock_area_t *area = &session->kernel->lock_ctx;
    lock_item_t *item = NULL;
    uint32 start_pid;
    uint32 start_gid;

    if (group->plocks.count != 0) {
        if (svpt_group->plocks.count != 0) {
            start_pid = (svpt_group->plock_id == CT_INVALID_ID32) ?
                LOCK_NEXT(area, svpt_group->plocks.last) : svpt_group->plock_id;
        } else {
            start_pid = group->plocks.first;
        }
        unlock_table_list(session, start_pid, group->plock_id);
    }

    if (group->glocks.count != 0) {
        if (svpt_group->glocks.count != 0) {
            item = lock_addr(area, svpt_group->glocks.last);
            start_gid = item->next;
        } else {
            start_gid = group->glocks.first;
        }
        unlock_table_list(session, start_gid, CT_INVALID_ID32);
        lock_release_to_svpt(session, group, svpt_group, start_gid);
    }
}

static void lock_free_key_svpt(knl_session_t *session, lock_group_t *svpt_group)
{
    lock_group_t *group = &session->rm->key_lock_group;
    lock_area_t *area = &session->kernel->lock_ctx;
    lock_item_t *item = NULL;
    uint32 start_pid;
    uint32 start_gid;

    if (group->plocks.count != 0) {
        if (svpt_group->plocks.count != 0) {
            start_pid = (svpt_group->plock_id == CT_INVALID_ID32) ?
                LOCK_NEXT(area, svpt_group->plocks.last) : svpt_group->plock_id;
        } else {
            start_pid = group->plocks.first;
        }
        unlock_key_list(session, start_pid, group->plock_id, CT_FALSE);
    }

    if (group->glocks.count != 0) {
        if (svpt_group->glocks.count != 0) {
            item = lock_addr(area, svpt_group->glocks.last);
            start_gid = item->next;
        } else {
            start_gid = group->glocks.first;
        }
        unlock_key_list(session, start_gid, CT_INVALID_ID32, CT_FALSE);
        lock_release_to_svpt(session, group, svpt_group, start_gid);
    }
}

static void lock_free_row_svpt(knl_session_t *session, lock_group_t *svpt_group)
{
    lock_group_t *group = &session->rm->row_lock_group;
    lock_area_t *area = &session->kernel->lock_ctx;
    lock_item_t *item = NULL;
    uint32 start_pid;
    uint32 start_gid;

    if (group->plocks.count != 0) {
        if (svpt_group->plocks.count != 0) {
            start_pid = (svpt_group->plock_id == CT_INVALID_ID32) ?
                LOCK_NEXT(area, svpt_group->plocks.last) : svpt_group->plock_id;
        } else {
            start_pid = group->plocks.first;
        }
        unlock_heap_list(session, start_pid, group->plock_id, CT_FALSE);
    }

    if (group->glocks.count != 0) {
        if (svpt_group->glocks.count != 0) {
            item = lock_addr(area, svpt_group->glocks.last);
            start_gid = item->next;
        } else {
            start_gid = group->glocks.first;
        }
        unlock_heap_list(session, start_gid, CT_INVALID_ID32, CT_FALSE);
        lock_release_to_svpt(session, group, svpt_group, start_gid);
    }
}

static void lock_free_alck_svpt(knl_session_t *session, lock_group_t *svpt_group)
{
    lock_group_t *group = &session->rm->alck_lock_group;
    lock_area_t *area = &session->kernel->lock_ctx;
    lock_item_t *item = NULL;
    uint32 start_pid;
    uint32 start_gid;

    if (group->plocks.count != 0) {
        if (svpt_group->plocks.count != 0) {
            start_pid = (svpt_group->plock_id == CT_INVALID_ID32) ?
                LOCK_NEXT(area, svpt_group->plocks.last) : svpt_group->plock_id;
        } else {
            start_pid = group->plocks.first;
        }
        unlock_tx_alck_list(session, start_pid, group->plock_id);
    }

    if (group->glocks.count != 0) {
        if (svpt_group->glocks.count != 0) {
            item = lock_addr(area, svpt_group->glocks.last);
            start_gid = item->next;
        } else {
            start_gid = group->glocks.first;
        }
        unlock_tx_alck_list(session, start_gid, CT_INVALID_ID32);
        lock_release_to_svpt(session, group, svpt_group, start_gid);
    }
}

void lock_reset_to_svpt(knl_session_t *session, knl_savepoint_t *savepoint)
{
    knl_rm_t *rm = session->rm;

    lock_reset_svpt_group(session, &rm->row_lock_group, &savepoint->row_lock);
    lock_reset_svpt_group(session, &rm->key_lock_group, &savepoint->key_lock);
    lock_reset_svpt_group(session, &rm->sch_lock_group, &savepoint->sch_lock);
    lock_reset_svpt_group(session, &rm->alck_lock_group, &savepoint->alck_lock);
}

void lock_free_to_svpt(knl_session_t *session, knl_savepoint_t *savepoint)
{
    lock_free_key_svpt(session, &savepoint->key_lock);
    lock_free_row_svpt(session, &savepoint->row_lock);
    lock_free_sch_svpt(session, &savepoint->sch_lock);
    lock_free_alck_svpt(session, &savepoint->alck_lock);
}

void unlock_tables_directly(knl_session_t *session)
{
    lock_group_t *group = &session->rm->direct_lock_group;

    if (group->plocks.count != 0) {
        unlock_table_list(session, group->plocks.first, group->plock_id);
    }

    if (group->glocks.count != 0) {
        unlock_table_list(session, group->glocks.first, CT_INVALID_ID32);
    }
    lock_release_glocks(session, group);
    lock_reset_group(&session->rm->direct_lock_group);
}

void lock_init(knl_rm_t *rm)
{
    lock_init_group(&rm->sch_lock_group);
    lock_init_group(&rm->row_lock_group);
    lock_init_group(&rm->key_lock_group);
    lock_init_group(&rm->direct_lock_group);
    lock_init_group(&rm->alck_lock_group);
}

char *g_lock_type_str[] = { "FREE", "TS", "TX", "RX", "KX", "RX", "KX", "ALK_TS", "ALK_TX", "ALK_SS", "ALK_SX",
    "ALK_PS", "ALK_PX"};

char *g_lock_mode_str[] = { "IDLE", "S", "IX", "X" };

// for delay cleaning page, test the table is locked or not, and try to locking
// if table is locked by ddl/dcl(include truncate table) or dc invalidated, return FALSE immediate
bool32 lock_table_without_xact_local(knl_session_t *session, knl_handle_t dc_entity, bool32 *inuse)  // test and lock
{
    schema_lock_t *lock = NULL;
    dc_entity_t *entity = NULL;

    if (DB_NOT_READY(session) || dc_entity == NULL) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "lock table without transaction when database is not ready");
        return CT_FALSE;
    }

    if (DB_IS_READONLY(session)) {
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "operation on read only mode");
        return CT_FALSE;
    }

    entity = (dc_entity_t *)dc_entity;
    lock = entity->entry->sch_lock;

    if (dc_locked_by_self(session, entity->entry)) {
        *inuse = CT_TRUE;
        return CT_TRUE;
    }

    *inuse = CT_FALSE;

    cm_spin_lock(&entity->entry->sch_lock_mutex, &session->stat->spin_stat.stat_sch_lock);
    if (!entity->valid) {
        cm_spin_unlock(&entity->entry->sch_lock_mutex);
        CT_THROW_ERROR(ERR_DC_INVALIDATED);
        return CT_FALSE;
    }

    if (lock->mode == LOCK_MODE_IX || lock->mode == LOCK_MODE_X) {
        cm_spin_unlock(&entity->entry->sch_lock_mutex);
        CT_THROW_ERROR(ERR_RESOURCE_BUSY);
        return CT_FALSE;
    }

    knl_panic(lock->shared_count != CT_INVALID_ID32);
    lock->shared_count++;
    SCH_LOCK_SET(session, lock);
    SCH_LOCK_INST_SET(session->kernel->dtc_attr.inst_id, lock);
    cm_spin_unlock(&entity->entry->sch_lock_mutex);
    return CT_TRUE;
}

void unlock_table_without_xact(knl_session_t *session, knl_handle_t dc_entity, bool32 inuse)
{
    schema_lock_t *lock = NULL;
    dc_entity_t *entity = NULL;

    if (inuse) {
        return;
    }

    entity = (dc_entity_t *)dc_entity;
    lock = entity->entry->sch_lock;

    cm_spin_lock(&entity->entry->sch_lock_mutex, &session->stat->spin_stat.stat_sch_lock);
    knl_panic(lock->shared_count > 0);
    lock->shared_count--;
    SCH_LOCK_CLEAN(session, lock);
    if (lock->shared_count == 0) {
        SCH_LOCK_INST_CLEAN(lock);
    }
    cm_spin_unlock(&entity->entry->sch_lock_mutex);
}

bool32 lock_table_without_xact(knl_session_t *session, knl_handle_t dc_entity, bool32 *inuse)  // test and lock
{
    SYNC_POINT_GLOBAL_START(CANTIAN_LOCK_TABLE_S_LOCAL_BEFORE_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    bool32 ret = lock_table_without_xact_local(session, dc_entity, inuse);
    if (!ret) {
        return ret;
    }

    SYNC_POINT_GLOBAL_START(CANTIAN_LOCK_TABLE_S_LOCAL_AFTER_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    if (!DB_ATTR_CLUSTER(session)) {
        return CT_TRUE;
    }

    knl_panic(session->kernel->db.status >= DB_STATUS_MOUNT);
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    dc_entry_t *entry = entity->entry;
    drc_local_latch *latch_stat = NULL;
    bool32 locked = CT_FALSE;

    drc_local_lock_res_t *lock_res = drc_get_local_resx(&entry->ddl_latch.drid);
    drc_lock_local_resx(lock_res);
    drc_get_local_latch_statx(lock_res, &latch_stat);
    if (latch_stat->lock_mode == DRC_LOCK_NULL) {
        locked = dls_request_latch_s(session, &entry->ddl_latch.drid, CT_TRUE, LOCK_INF_WAIT, CT_INVALID_ID32);
        if (!locked) {
            drc_unlock_local_resx(lock_res);
            unlock_table_without_xact(session, entry, *inuse);
            return CT_FALSE;
        }
        latch_stat->lock_mode = DRC_LOCK_SHARE;
    }
    drc_unlock_local_resx(lock_res);
    SYNC_POINT_GLOBAL_START(CANTIAN_LOCK_TABLE_S_DLS_AFTER_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    return CT_TRUE;
}

status_t lock_parent_table_directly(knl_session_t *session, knl_handle_t entity, bool32 is_default)
{
    table_t *table;
    ref_cons_t *ref = NULL;
    knl_dictionary_t ref_dc;
    uint32 i;
    dc_entity_t *dc_entity;
    uint32 timeout = is_default ? session->kernel->attr.ddl_lock_timeout : LOCK_INF_WAIT;
    dc_entity = (dc_entity_t *)entity;
    table = &dc_entity->table;
    // ref_count won't exceed 32
    for (i = 0; i < table->cons_set.ref_count; i++) {
        ref = table->cons_set.ref_cons[i];
        if (ref->ref_oid == CT_INVALID_ID32) {
            continue;
        }
        if (knl_open_dc_by_id(session, ref->ref_uid, ref->ref_oid, &ref_dc, CT_TRUE) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (lock_table_directly(session, &ref_dc, timeout) != CT_SUCCESS) {
            dc_close(&ref_dc);
            return CT_ERROR;
        }

        dc_close(&ref_dc);
    }
    return CT_SUCCESS;
}

status_t lock_child_table_directly(knl_session_t *session, knl_handle_t entity, bool32 is_default)
{
    uint32 i;
    table_t *table;
    index_t *index = NULL;
    cons_dep_t *dep = NULL;
    knl_dictionary_t dep_dc;
    dc_entity_t *dc_entity;

    dc_entity = (dc_entity_t *)entity;
    table = &dc_entity->table;

    if (table->index_set.count == 0) {
        return CT_SUCCESS;
    }

    uint32 timeout = is_default ? session->kernel->attr.ddl_lock_timeout : LOCK_INF_WAIT;

    for (i = 0; i < table->index_set.count; i++) {
        index = table->index_set.items[i];
        if (index->dep_set.count == 0) {
            continue;
        }

        /* if table is referenced by another table */
        dep = index->dep_set.first;
        while (dep != NULL) {
            if (dep->uid == table->desc.uid && dep->oid == table->desc.id) {
                dep = dep->next;
                continue;
            }

            if (knl_open_dc_by_id(session, dep->uid, dep->oid, &dep_dc, CT_TRUE) != CT_SUCCESS) {
                return CT_ERROR;
            }

            if (lock_table_directly(session, &dep_dc, timeout) != CT_SUCCESS) {
                dc_close(&dep_dc);
                return CT_ERROR;
            }

            dc_close(&dep_dc);
            dep = dep->next;
        }
    }

    return CT_SUCCESS;
}

char *lock_mode_string(knl_handle_t dc_entry)
{
    dc_entry_t *entry = (dc_entry_t *)dc_entry;
    schema_lock_t *lock = NULL;

    if (IS_LTT_BY_ID(entry->id)) {
        return g_lock_mode_str[entry->ltt_lock_mode - LOCK_MODE_IDLE];
    }

    lock = entry->sch_lock;
    if (lock == NULL) {
        return g_lock_mode_str[LOCK_MODE_IDLE];
    }

    return g_lock_mode_str[lock->mode - LOCK_MODE_IDLE];
}

static inline uint32 lock_search_alck(knl_session_t *session, uint32 beg, uint32 end, uint32 alck_id)
{
    lock_area_t *area = &session->kernel->lock_ctx;
    lock_item_t *item = NULL;
    uint32 curr = beg;
    uint32 prev = CT_INVALID_ID32;

    while (curr != end) {
        item = lock_addr(area, curr);
        item->prev = prev;
        if (item->alck_id == alck_id) {
            return curr;
        }
        prev = curr;
        curr = item->next;
    }
    return CT_INVALID_ID32;
}

static inline lock_group_t *lock_get_alck_group(knl_session_t *session, int32 lock_set)
{
    if (lock_set == TX_LOCK) {
        return &session->rm->alck_lock_group;
    } else {
        return &session->alck_lock_group;
    }
}

void lock_add_alck_times(knl_session_t *session, uint32 alck_id, int32 lock_set)
{
    lock_group_t *group = NULL;
    lock_item_t *item = NULL;
    uint32 lock_id = CT_INVALID_ID32;

    group = lock_get_alck_group(session, lock_set);
    if (group->plocks.count) {
        lock_id = lock_search_alck(session, group->plocks.first, group->plock_id, alck_id);
    }
    if (lock_id == CT_INVALID_ID32 && group->glocks.count) {
        lock_id = lock_search_alck(session, group->glocks.first, CT_INVALID_ID32, alck_id);
    }
    if (lock_id != CT_INVALID_ID32) {
        lock_area_t *area = &session->kernel->lock_ctx;
        item = lock_addr(area, lock_id);
        ++item->alck_times;
    }
}

void lock_del_alck_times(knl_session_t *session, uint32 alck_id, int32 lock_set)
{
    lock_group_t *group = NULL;
    lock_item_t *item = NULL;
    id_list_t *list = NULL;
    uint32 lock_id = CT_INVALID_ID32;

    group = lock_get_alck_group(session, lock_set);
    if (group->plocks.count) {
        list = &group->plocks;
        lock_id = lock_search_alck(session, group->plocks.first, group->plock_id, alck_id);
    }
    if (lock_id == CT_INVALID_ID32 && group->glocks.count) {
        list = &group->glocks;
        lock_id = lock_search_alck(session, group->glocks.first, CT_INVALID_ID32, alck_id);
    }

    if (lock_id == CT_INVALID_ID32) { return; }

    lock_area_t *area = &session->kernel->lock_ctx;
    item = lock_addr(area, lock_id);
    --item->alck_times;

    if (item->alck_times) { return; }

    // delete item from group
    if (lock_id == list->last) {
        list->last = item->prev;
    }
    if (item->prev == CT_INVALID_ID32) {
        list->first = item->next;
    } else {
        lock_item_t *prev_item = lock_addr(area, item->prev);
        prev_item->next = item->next;
    }

    if (list == &group->plocks) {
        item->next = CT_INVALID_ID32;
        if (list->last == CT_INVALID_ID32) {
            list->first = lock_id;
            list->last = lock_id;
            group->plock_id = lock_id;
            return;
        }
        lock_item_t *last_item = lock_addr(area,  list->last);
        last_item->next = lock_id;
        list->last = lock_id;
        if (group->plock_id == CT_INVALID_ID32) {
            group->plock_id = lock_id;
        }
        return;
    }

    --list->count;
    // return item to area
    cm_spin_lock(&area->lock, NULL);
    if (area->free_items.count == 0) {
        item->next = CT_INVALID_ID32;
        area->free_items.first = lock_id;
        area->free_items.last = lock_id;
        area->free_items.count = 1;
    } else {
        item->next = area->free_items.first;
        area->free_items.first = lock_id;
        ++area->free_items.count;
    }
    cm_spin_unlock(&area->lock);
}

bool32 lock_table_is_shared_mode(knl_session_t *session, uint64 table_id)
{
    lock_twait_t wtid;
    schema_lock_t *lock = NULL;
    dc_entry_t *entry = NULL;
    dc_user_t *user = NULL;

    wtid.value = table_id;
    if (dc_open_user_by_id(session, wtid.uid, &user) != CT_SUCCESS) {
        return CT_FALSE;
    }

    entry = DC_GET_ENTRY(user, wtid.oid);
    if (entry == NULL) {
        return CT_FALSE;
    }

    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    if ((!entry->ready) || (entry->recycled)) {
        cm_spin_unlock(&entry->lock);
        return CT_FALSE;
    }
    lock = entry->sch_lock;
    if (lock == NULL) {
        cm_spin_unlock(&entry->lock);
        return CT_FALSE;
    }
    cm_spin_unlock(&entry->lock);

    cm_spin_lock(&entry->sch_lock_mutex, &session->stat->spin_stat.stat_sch_lock);
    if (lock->mode == LOCK_MODE_S || lock->shared_count > 0) {
        cm_spin_unlock(&entry->sch_lock_mutex);
        return CT_TRUE;
    }
    cm_spin_unlock(&entry->sch_lock_mutex);
    return CT_FALSE;
}
