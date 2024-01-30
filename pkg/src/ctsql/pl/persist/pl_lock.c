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
 * pl_lock.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/persist/pl_lock.c
 *
 * -------------------------------------------------------------------------
 */
#include "pl_lock.h"
#include "srv_instance.h"
#include "pl_memory.h"

void ple_restore_lock_entries(sql_stmt_t *stmt, const uint32 entry_cnt)
{
    uint32 i;
    pl_entry_t *entry = NULL;

    if (stmt->pl_ref_entry == NULL) {
        return;
    }
    for (i = stmt->pl_ref_entry->count; i > entry_cnt; i--) {
        entry = (pl_entry_t *)cm_galist_get(stmt->pl_ref_entry, i - 1);

        pl_unlock_shared(&stmt->session->knl_session, entry);
        cm_galist_delete(stmt->pl_ref_entry, i - 1);
    }
}

status_t pl_lock_check_entity_valid(pl_lock_ast_t *lock_ass, pl_lock_item_t *lock_item)
{
    pl_entry_t *entry = lock_ass->entry;
    pl_dc_t *dc = lock_ass->dc;
    pl_entity_t *entity = lock_ass->entity;
    status_t status = CT_ERROR;
    do {
        if (dc != NULL && dc->entity != NULL && !pl_check_dc(dc)) {
            break;
        }
        if (entity != NULL && !entity->valid) {
            break;
        }
        if (dc != NULL && !dc->is_recursive && entity->cached && entity != entry->entity) {
            break;
        }
        if (lock_ass->chg_scn != entry->desc.chg_scn) {
            break;
        }
        status = CT_SUCCESS;
    } while (0);

    if (status != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_DC_INVALIDATED);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t pl_lock_wait_sess_responds(pl_lock_ast_t *lock_ass, date_t time_beg, date_t to_us)
{
    status_t ret = CT_SUCCESS;
    do {
        if (lock_ass->se->canceled) {
            CT_THROW_ERROR(ERR_OPERATION_CANCELED);
            ret = CT_ERROR;
            break;
        }

        if (lock_ass->se->killed) {
            CT_THROW_ERROR(ERR_OPERATION_KILLED);
            ret = CT_ERROR;
            break;
        }

        if (lock_ass->timeout != 0 && (KNL_NOW(lock_ass->se) - time_beg) > to_us) {
            CT_THROW_ERROR(ERR_RESOURCE_BUSY);
            ret = CT_TIMEDOUT;
            break;
        }
    } while (0);

    return ret;
}

#define PL_LOCK_INIT_ASSIST(sess, dc, chg_scn, entity, entry, to, lock_set, nowait, lock_ass) \
    do {                                                                                      \
        (lock_ass).se = (knl_session_t *)(sess);                                              \
        (lock_ass).dc = dc;                                                                   \
        (lock_ass).chg_scn = chg_scn;                                                         \
        (lock_ass).entity = entity;                                                           \
        (lock_ass).entry = entry;                                                             \
        (lock_ass).timeout = to;                                                              \
        (lock_ass).lock_mode = lock_set;                                                      \
        (lock_ass).no_wait = nowait;                                                          \
        (lock_ass).map_id = (lock_ass).se->id;                                                \
    } while (0)

pl_lock_map_t *pl_lock_get_map(pl_lock_pool_t *lock_pool, pl_lock_item_t *lock_item, uint32 idx)
{
    uint32 map_id = lock_item->first_map;
    pl_lock_map_t *lock_map = NULL;

    while (map_id != CT_INVALID_ID32) {
        lock_map = PL_LOCK_MAP_PTR(lock_pool, map_id);
        if (lock_map->idx == idx) {
            return lock_map;
        }
        map_id = lock_map->next;
    }
    return NULL;
}

status_t pl_alloc_lock_map(pl_lock_ast_t *lock_ass, pl_lock_map_t **lock_map)
{
    pl_lock_pool_t *pool = &GET_PL_MGR->lock_map_pool;
    for (;;) {
        if (knl_check_session_status(lock_ass->se) != CT_SUCCESS) {
            return CT_ERROR;
        }

        cm_spin_lock(&pool->lock, NULL);

        if (pool->free_first != CT_INVALID_ID32) {
            *lock_map = PL_LOCK_MAP_PTR(pool, pool->free_first);
            pool->free_first = (*lock_map)->next;
            pool->free_count--;
            cm_spin_unlock(&pool->lock);
            return CT_SUCCESS;
        }

        if (pool->count < pool->capacity) {
            *lock_map = PL_LOCK_MAP_PTR(pool, pool->count);

            (*lock_map)->id = pool->count;
            ++pool->count;
            cm_spin_unlock(&pool->lock);
            return CT_SUCCESS;
        }

        if (pool->extending) {
            cm_spin_unlock(&pool->lock);
            cm_sleep(1);
            continue;
        }

        pool->extending = CT_TRUE;
        cm_spin_unlock(&pool->lock);

        if (pool->capacity == CT_PL_LOCK_MAX_MAPS) {
            pool->extending = CT_FALSE;
            CT_THROW_ERROR(ERR_ALCK_LOCK_THRESHOLD, CT_PL_LOCK_MAX_MAPS);
            return CT_ERROR;
        }
        uint32 alloc_size = sizeof(pl_lock_map_t) * CT_PL_LOCK_EXTENT;

        if (pl_alloc_mem_in_mngr(alloc_size, (void **)&pool->extents[pool->ext_cnt]) != CT_SUCCESS) {
            return CT_ERROR;
        }

        errno_t ret = memset_sp(pool->extents[pool->ext_cnt], alloc_size, 0, alloc_size);
        knl_securec_check(ret);

        pool->capacity += CT_PL_LOCK_EXTENT;
        ++pool->ext_cnt;
        CM_MFENCE;
        pool->extending = CT_FALSE;
    }
    return CT_SUCCESS;
}

static status_t pl_set_lock_map(pl_lock_ast_t *lock_ass, pl_lock_map_t **lock_map)
{
    pl_entry_t *entry = lock_ass->entry;
    pl_lock_item_t *lock_item = entry->meta_lock;
    pl_lock_pool_t *pool = &GET_PL_MGR->lock_map_pool;

    if (*lock_map != NULL) {
        (*lock_map)->count++;
        return CT_SUCCESS;
    }

    if (pl_alloc_lock_map(lock_ass, lock_map)) {
        return CT_ERROR;
    }
    (*lock_map)->count = 1;
    (*lock_map)->idx = lock_ass->map_id;
    (*lock_map)->next = lock_item->first_map;
    if (lock_item->first_map != CT_INVALID_ID32) {
        PL_LOCK_MAP_PTR(pool, lock_item->first_map)->prev = (*lock_map)->id;
    }
    (*lock_map)->prev = CT_INVALID_ID32;
    lock_item->first_map = (*lock_map)->id;

    return CT_SUCCESS;
}

status_t pl_lock_add(pl_lock_ast_t *lock_ass, pl_lock_item_t *lock_item, pl_lock_map_t *map, bool32 *locked,
    pl_lock_mode_t lock_mode)
{
    if (pl_set_lock_map(lock_ass, &map) != CT_SUCCESS) {
        return CT_ERROR;
    }

    ++lock_item->lock_times;
    if (lock_mode == PL_MODE_X) {
        lock_item->lock_mode = PL_MODE_X;
        lock_item->x_times = 1;
        lock_item->x_map_id = lock_ass->map_id;
        lock_item->ix_map_id = CT_INVALID_ID32;
    } else {
        lock_item->lock_mode = PL_MODE_S;
    }
    *locked = CT_TRUE;
    return CT_SUCCESS;
}

static void pl_shared_lock_set_wsid(pl_lock_ast_t *lock_ass, pl_lock_item_t *lock_item)
{
    uint32 sid = (lock_item->lock_mode == PL_MODE_IX) ? lock_item->ix_map_id : lock_item->x_map_id;
    if (lock_ass->se->wrmid != sid) {
        lock_ass->se->wrmid = sid;
    }
    return;
}

status_t pl_lock_wait_sh(pl_lock_ast_t *lock_ass, pl_lock_item_t *lock_item, bool32 *locked)
{
    pl_lock_pool_t *map_pool = &GET_PL_MGR->lock_map_pool;
    cm_spin_unlock(&lock_item->lock);
    date_t time_beg = KNL_NOW(lock_ass->se);
    date_t to_us = lock_ass->timeout * MICROSECS_PER_SECOND;
    status_t ret = CT_ERROR;
    knl_begin_session_wait(lock_ass->se, ENQ_PLSQL_LOCK, CT_FALSE);
    for (;;) {
        CT_BREAK_IF_ERROR(pl_lock_wait_sess_responds(lock_ass, time_beg, to_us));
        cm_spin_sleep_and_stat2(1);

        CT_BREAK_IF_ERROR(pl_lock_check_entity_valid(lock_ass, lock_item));

        cm_spin_lock(&lock_item->lock, NULL);

        if (pl_lock_check_entity_valid(lock_ass, lock_item) != CT_SUCCESS) {
            cm_spin_unlock(&lock_item->lock);
            break;
        }

        if (lock_item->lock_mode == PL_MODE_IX || lock_item->lock_mode == PL_MODE_X) {
            pl_shared_lock_set_wsid(lock_ass, lock_item);
            cm_spin_unlock(&lock_item->lock);
            continue;
        }

        pl_lock_map_t *map = pl_lock_get_map(map_pool, lock_item, lock_ass->map_id);
        CM_ASSERT(map == NULL);

        ret = pl_lock_add(lock_ass, lock_item, map, locked, PL_MODE_S);
        cm_spin_unlock(&lock_item->lock);
        break;
    }
    knl_end_session_wait(lock_ass->se, ENQ_PLSQL_LOCK);
    lock_ass->se->wrmid = CT_INVALID_ID16;
    return ret;
}

static status_t pl_lock_or_wait_sh(pl_lock_ast_t *lock_ass, pl_lock_item_t *lock_item, bool32 *locked)
{
    pl_lock_pool_t *map_pool = &GET_PL_MGR->lock_map_pool;
    pl_lock_map_t *map = pl_lock_get_map(map_pool, lock_item, lock_ass->map_id);
    /*
     * scene1.lock is locked by current session, lock mode may be PL_MODE_S or PL_MODE_IX. lock it immediate.
     * scene2.lock mode is PL_MODE_S locked by another session or lock is just idle. get a map and lock it immediate.
     * scene3.lock is locked by another session, lock mode is PL_MODE_X or PL_MODE_IX. wait until current lock free.
     */
    if (map != NULL && map->count > 0) {
        if (map->count == CT_PL_LOCK_MAX_RECUR_LVL) {
            CT_THROW_ERROR(ERR_PL_ENTRY_LOCK, "exceed max shared lock times");
            cm_spin_unlock(&lock_item->lock);
            return CT_ERROR;
        }
        ++lock_item->lock_times;
        ++map->count;
        CM_ASSERT(lock_item->lock_mode == PL_MODE_S || lock_item->lock_mode == PL_MODE_IX);
        cm_spin_unlock(&lock_item->lock);
        *locked = CT_TRUE;
        return CT_SUCCESS;
    } else if (lock_item->lock_mode != PL_MODE_X && lock_item->lock_mode != PL_MODE_IX) {
        if (pl_set_lock_map(lock_ass, &map) != CT_SUCCESS) {
            cm_spin_unlock(&lock_item->lock);
            return CT_ERROR;
        }
        ++lock_item->lock_times;
        if (lock_item->lock_mode == PL_MODE_IDLE) {
            lock_item->lock_mode = PL_MODE_S;
        }
        cm_spin_unlock(&lock_item->lock);
        *locked = CT_TRUE;
        return CT_SUCCESS;
    } else {
        *locked = CT_FALSE;
        if (lock_ass->no_wait) {
            cm_spin_unlock(&lock_item->lock);
            return CT_SUCCESS;
        } else {
            return pl_lock_wait_sh(lock_ass, lock_item, locked);
        }
    }
}

static status_t pl_deal_self_locked_ex(pl_lock_ast_t *lock_ass, pl_lock_item_t *lock_item, pl_lock_map_t *map,
    bool32 *locked)
{
    if (map->count == CT_PL_LOCK_MAX_RECUR_LVL) {
        CT_THROW_ERROR(ERR_PL_ENTRY_LOCK, "exceed max exclusive lock times");
        cm_spin_unlock(&lock_item->lock);
        return CT_ERROR;
    }

    ++lock_item->lock_times;
    ++map->count;

    if (lock_item->lock_mode == PL_MODE_S || lock_item->lock_mode == ALCK_MODE_IX) {
        lock_item->x_map_id = lock_ass->map_id;
        lock_item->x_times = 1;
        lock_item->ix_map_id = CT_INVALID_ID32;
    } else {
        ++lock_item->x_times;
    }
    lock_item->lock_mode = PL_MODE_X;

    cm_spin_unlock(&lock_item->lock);

    *locked = CT_TRUE;
    return CT_SUCCESS;
}

static bool32 pl_locked_by_others(pl_lock_ast_t *lock_ass, pl_lock_item_t *lock_item, pl_lock_map_t *map)
{
    pl_lock_pool_t *map_pool = &GET_PL_MGR->lock_map_pool;
    bool32 is_locked;
    if (map != NULL && map->count > 0) {
        is_locked = (lock_item->lock_times > map->count);
    } else {
        is_locked = (lock_item->lock_times > 0);
    }

    if (is_locked) {
        if (lock_item->lock_mode == PL_MODE_S) {
            lock_item->lock_mode = PL_MODE_IX;
            lock_item->ix_map_id = lock_ass->map_id;
        }
        if (lock_item->first_map != CT_INVALID_ID32) {
            pl_lock_map_t *lock_map = PL_LOCK_MAP_PTR(map_pool, lock_item->first_map);
            if (lock_map != NULL && lock_map->idx != lock_ass->se->wrmid) {
                lock_ass->se->wrmid = lock_map->idx;
            }
        }
        return CT_TRUE;
    }
    return CT_FALSE;
}

static inline void pl_lock_downgrade(pl_lock_ast_t *lock_ass, pl_lock_item_t *lock_item)
{
    cm_spin_lock(&lock_item->lock, NULL);
    if (lock_item->lock_mode == PL_MODE_IX && lock_item->ix_map_id == lock_ass->map_id) {
        lock_item->lock_mode = (lock_item->lock_times == 0) ? PL_MODE_IDLE : PL_MODE_S;
    }
    cm_spin_unlock(&lock_item->lock);
}

static inline void pl_exlock_set_wsid(pl_lock_ast_t *lock_ass, pl_lock_item_t *lock_item)
{
    if (lock_item->lock_mode == PL_MODE_X) {
        if (lock_item->x_map_id != lock_ass->se->wrmid) {
            lock_ass->se->wrmid = lock_item->x_map_id;
        }
    } else {
        if (lock_item->ix_map_id != lock_ass->se->wrmid) {
            lock_ass->se->wrmid = lock_item->ix_map_id;
        }
    }
}

status_t pl_lock_wait_ex(pl_lock_ast_t *lock_ass, pl_lock_item_t *lock_item, bool32 *locked)
{
    pl_lock_pool_t *map_pool = &GET_PL_MGR->lock_map_pool;
    cm_spin_unlock(&lock_item->lock);
    date_t time_beg = KNL_NOW(lock_ass->se);
    date_t to_us = lock_ass->timeout * MICROSECS_PER_SECOND;
    status_t ret = CT_ERROR;
    knl_begin_session_wait(lock_ass->se, ENQ_PLSQL_LOCK, CT_FALSE);
    for (;;) {
        CT_BREAK_IF_ERROR(pl_lock_wait_sess_responds(lock_ass, time_beg, to_us));
        cm_spin_sleep_and_stat2(1);

        CT_BREAK_IF_ERROR(pl_lock_check_entity_valid(lock_ass, lock_item));

        cm_spin_lock(&lock_item->lock, NULL);

        if (pl_lock_check_entity_valid(lock_ass, lock_item) != CT_SUCCESS) {
            cm_spin_unlock(&lock_item->lock);
            break;
        }

        if (lock_item->lock_mode == PL_MODE_X) {
            pl_exlock_set_wsid(lock_ass, lock_item);
            cm_spin_unlock(&lock_item->lock);
            continue;
        }

        pl_lock_map_t *map = pl_lock_get_map(map_pool, lock_item, lock_ass->map_id);
        if (map != NULL && lock_item->lock_times == map->count) {
            ret = pl_lock_add(lock_ass, lock_item, map, locked, PL_MODE_X);
            cm_spin_unlock(&lock_item->lock);
            break;
        }

        if (pl_locked_by_others(lock_ass, lock_item, map)) {
            cm_spin_unlock(&lock_item->lock);
            continue;
        }

        if (lock_item->lock_mode == PL_MODE_IX && lock_item->ix_map_id != lock_ass->map_id) {
            pl_exlock_set_wsid(lock_ass, lock_item);
            cm_spin_unlock(&lock_item->lock);
            continue;
        }

        ret = pl_lock_add(lock_ass, lock_item, map, locked, PL_MODE_X);
        cm_spin_unlock(&lock_item->lock);
        break;
    }
    knl_end_session_wait(lock_ass->se, ENQ_PLSQL_LOCK);
    lock_ass->se->wrmid = CT_INVALID_ID16;
    if (ret != CT_SUCCESS) {
        pl_lock_downgrade(lock_ass, lock_item);
    }
    return ret;
}

static status_t pl_lock_or_wait_ex(pl_lock_ast_t *lock_ass, pl_lock_item_t *lock_item, bool32 *locked)
{
    pl_lock_pool_t *map_pool = &GET_PL_MGR->lock_map_pool;
    pl_lock_map_t *map = pl_lock_get_map(map_pool, lock_item, lock_ass->map_id);
    if (map != NULL && map->count == lock_item->lock_times) {
        return pl_deal_self_locked_ex(lock_ass, lock_item, map, locked);
    } else if (!lock_item->lock_times) {
        if (pl_set_lock_map(lock_ass, &map) != CT_SUCCESS) {
            cm_spin_unlock(&lock_item->lock);
            return CT_ERROR;
        }
        ++lock_item->lock_times;
        lock_item->lock_mode = PL_MODE_X;
        lock_item->x_map_id = lock_ass->map_id;
        lock_item->x_times = 1;
        cm_spin_unlock(&lock_item->lock);
        *locked = CT_TRUE;
        return CT_SUCCESS;
    } else {
        *locked = CT_FALSE;
        if (lock_ass->no_wait) {
            cm_spin_unlock(&lock_item->lock);
            return CT_SUCCESS;
        } else {
            return pl_lock_wait_ex(lock_ass, lock_item, locked);
        }
    }
}

static status_t pl_lock_or_wait(pl_lock_ast_t *lock_ass, pl_lock_item_t *lock_item, bool32 *locked)
{
    if (lock_ass->lock_mode == PL_MODE_S) {
        return pl_lock_or_wait_sh(lock_ass, lock_item, locked);
    } else {
        return pl_lock_or_wait_ex(lock_ass, lock_item, locked);
    }
}

status_t pl_lock(pl_lock_ast_t *lock_ass, bool32 *locked)
{
    pl_entry_t *entry = lock_ass->entry;
    pl_lock_item_t *lock_item = entry->meta_lock;
    *locked = CT_FALSE;
    cm_spin_lock(&lock_item->lock, NULL);

    if (pl_lock_check_entity_valid(lock_ass, lock_item) != CT_SUCCESS) {
        cm_spin_unlock(&lock_item->lock);
        return CT_ERROR;
    }

    return pl_lock_or_wait(lock_ass, lock_item, locked);
}

static void pl_lock_free_map_node(pl_lock_pool_t *pool, pl_lock_item_t *lock_item, pl_lock_map_t *map)
{
    if (map->prev != CT_INVALID_ID32) {
        PL_LOCK_MAP_PTR(pool, map->prev)->next = map->next;
    }
    if (map->next != CT_INVALID_ID32) {
        PL_LOCK_MAP_PTR(pool, map->next)->prev = map->prev;
    }
    if (lock_item->first_map == map->id) {
        lock_item->first_map = map->next;
    }
    map->next = CT_INVALID_ID32;
    map->prev = CT_INVALID_ID32;

    cm_spin_lock(&pool->lock, NULL);
    map->next = pool->free_first;
    pool->free_first = map->id;
    pool->free_count++;
    cm_spin_unlock(&pool->lock);
}


static bool32 pl_unlock_sh(pl_lock_ast_t *lock_ass)
{
    pl_lock_item_t *lock_item = lock_ass->entry->meta_lock;
    cm_spin_lock(&lock_item->lock, NULL);
    pl_lock_pool_t *map_pool = &GET_PL_MGR->lock_map_pool;
    pl_lock_map_t *map = pl_lock_get_map(map_pool, lock_item, lock_ass->map_id);
    CM_ASSERT(map != NULL);
    CM_ASSERT(map->count > 0);
    if (lock_item->lock_times == lock_item->x_times) {
        cm_spin_unlock(&lock_item->lock);
        return CT_FALSE;
    }

    if (lock_item->lock_times > 1) {
        --lock_item->lock_times;
        --map->count;
        if (map->count == 0) {
            pl_lock_free_map_node(map_pool, lock_item, map);
        }
        cm_spin_unlock(&lock_item->lock);
        return CT_TRUE;
    }

    lock_item->lock_times = 0;
    pl_lock_free_map_node(map_pool, lock_item, map);

    if (lock_item->lock_mode == PL_MODE_IX) {
        cm_spin_unlock(&lock_item->lock);
        return CT_TRUE;
    }

    lock_item->lock_mode = PL_MODE_IDLE;
    cm_spin_unlock(&lock_item->lock);

    return CT_TRUE;
}

static bool32 pl_unlock_ex(pl_lock_ast_t *lock_ass)
{
    pl_lock_item_t *lock_item = lock_ass->entry->meta_lock;
    cm_spin_lock(&lock_item->lock, NULL);

    if (lock_item->lock_mode != PL_MODE_X) {
        cm_spin_unlock(&lock_item->lock);
        return CT_FALSE;
    }

    pl_lock_pool_t *map_pool = &GET_PL_MGR->lock_map_pool;
    pl_lock_map_t *map = pl_lock_get_map(map_pool, lock_item, lock_ass->map_id);
    if (map == NULL) {
        cm_spin_unlock(&lock_item->lock);
        return CT_FALSE;
    }
    CM_ASSERT(map->count > 0);
    if (lock_item->x_map_id != lock_ass->map_id) {
        cm_spin_unlock(&lock_item->lock);
        return CT_FALSE;
    }

    if (lock_item->lock_times > 1) {
        --lock_item->lock_times;
        --map->count;
        --lock_item->x_times;
        if (lock_item->x_times == 0) {
            lock_item->lock_mode = PL_MODE_S;
            lock_item->x_map_id = CT_INVALID_ID16;
        }
        CM_ASSERT(map->count > 0);
        cm_spin_unlock(&lock_item->lock);
        return CT_TRUE;
    }

    lock_item->lock_mode = PL_MODE_IDLE;
    lock_item->lock_times = 0;
    lock_item->x_map_id = CT_INVALID_ID16;
    lock_item->x_times = 0;
    pl_lock_free_map_node(map_pool, lock_item, map);
    cm_spin_unlock(&lock_item->lock);

    return CT_TRUE;
}

status_t pl_lock_dc_shared(knl_handle_t sess, pl_dc_t *dc)
{
    bool32 locked;
    pl_entry_t *entry = dc->entry;
    pl_entity_t *entity = dc->entity;
    pl_lock_ast_t lock_ass;
    knl_scn_t chg_scn = dc->chg_scn;
    PL_LOCK_INIT_ASSIST(sess, dc, chg_scn, entity, entry, 0, PL_MODE_S, CT_FALSE, lock_ass);

    if (pl_lock(&lock_ass, &locked) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!locked) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t pl_lock_entry_shared(knl_handle_t sess, pl_entry_info_t *entry_info)
{
    bool32 locked;
    uint32 timeout = 0;
    pl_entry_t *entry = entry_info->entry;
    pl_entity_t *entity = entry->entity;
    pl_lock_ast_t lock_ass;
    pl_dc_t *dc = NULL;
    knl_scn_t chg_scn = entry_info->scn;

    PL_LOCK_INIT_ASSIST(sess, dc, chg_scn, entity, entry, timeout, PL_MODE_S, CT_FALSE, lock_ass);

    if (pl_lock(&lock_ass, &locked) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!locked) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t pl_lock_entry_exclusive(knl_handle_t sess, pl_entry_info_t *entry_info)
{
    bool32 locked;
    pl_dc_t *dc = NULL;
    pl_entry_t *entry = entry_info->entry;
    pl_entity_t *entity = entry->entity;
    pl_lock_ast_t lock_ass;
    knl_scn_t chg_scn = entry_info->scn;
    PL_LOCK_INIT_ASSIST(sess, dc, chg_scn, entity, entry, 0, PL_MODE_X, CT_FALSE, lock_ass);

    if (pl_lock(&lock_ass, &locked) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!locked) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void pl_unlock_shared(knl_handle_t sess, pl_entry_t *entry)
{
    pl_lock_ast_t lock_ass;
    pl_entity_t *entity = NULL;
    pl_dc_t *dc = NULL;
    knl_scn_t chg_scn = entry->desc.chg_scn;
    PL_LOCK_INIT_ASSIST(sess, dc, chg_scn, entity, entry, 0, PL_MODE_S, CT_FALSE, lock_ass);

    if (!pl_unlock_sh(&lock_ass)) {
        CT_LOG_RUN_ERR("pl unlock shared object failed, uid %u, name %s, type %s.", entry->desc.uid, entry->desc.name,
            pl_get_char_type(entry->desc.type));
        CM_NEVER;
    }
}

void pl_unlock_exclusive(knl_handle_t sess, pl_entry_t *entry)
{
    pl_lock_ast_t lock_ass;
    pl_entity_t *entity = NULL;
    pl_dc_t *dc = NULL;
    knl_scn_t chg_scn = entry->desc.chg_scn;
    PL_LOCK_INIT_ASSIST(sess, dc, chg_scn, entity, entry, 0, PL_MODE_X, CT_FALSE, lock_ass);

    if (!pl_unlock_ex(&lock_ass)) {
        CT_LOG_RUN_ERR("pl unlock exclusive object failed, uid %u, name %s, type %s.", entry->desc.uid,
            entry->desc.name, pl_get_char_type(entry->desc.type));
        CM_NEVER;
    }
}

void pl_init_lock_map_pool(pl_lock_pool_t *pool)
{
    pool->capacity = 0;
    pool->count = 0;
    pool->lock = 0;
    pool->ext_cnt = 0;
    pool->free_first = CT_INVALID_ID32;
    pool->free_count = 0;
    pool->extending = CT_FALSE;
}
