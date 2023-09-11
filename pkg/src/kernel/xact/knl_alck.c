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
 * knl_alck.c
 *
 *
 * IDENTIFICATION
 * src/kernel/xact/knl_alck.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_interface.h"
#include "knl_session.h"
#include "knl_context.h"
#include "knl_alck.h"
#include "knl_lock.h"

typedef struct st_alck_assit {
    /* in params */
    knl_session_t *se;
    text_t *name;
    uint32 timeout;
    alck_mode_t lock_mode;
    alck_lock_set_t lock_set;
    bool32 no_wait;
    uint32 map_id;
    alck_ctx_spec_t *spec_ctx;

    /* out params */
    bool32 new_locked;  // whether first locked by current session
    uint32 lock_id;
}alck_assist_t;

#define ALCK_SESS(assist) ((assist)->se)
#define ALCK_TIMEOUT(assist) ((assist)->timeout)
#define ALCK_NAME(assist) ((assist)->name)
#define ALCK_LOCK_MODE(assist) ((assist)->lock_mode)
#define ALCK_LOCK_SET(assist) ((assist)->lock_set)
#define ALCK_NO_WAIT(assist) ((assist)->no_wait)
#define ALCK_CTX(assist) ((assist)->spec_ctx)
#define ALCK_MAP_ID(assist) ((assist)->map_id)
#define ALCK_ID(assist) ((assist)->lock_id)
#define ALCK_NEW_LOCKED(assist) ((assist)->new_locked)

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
void knl_check_alck_item(alck_item_pool_t *pool, uint32 p_first, uint32 target)
{
    uint32 first = p_first;
    while (first != GS_INVALID_ID32) {
        cm_assert(target != first);
        first = ALCK_ITEM_PTR(pool, first)->next;
    }
}
#endif

status_t alck_check_db_status(knl_session_t *session)
{
    return knl_ddl_enabled(session, GS_FALSE);
}

#define INIT_POOL(pool)                   \
do {                                      \
    (pool)->capacity = 0;                 \
    (pool)->count = 0;                    \
    (pool)->lock = 0;                     \
    (pool)->ext_cnt = 0;                  \
    (pool)->free_first = GS_INVALID_ID32; \
    (pool)->free_count = 0;               \
    (pool)->extending = GS_FALSE;         \
} while (0)


static void alck_free_map_node(alck_map_pool_t *pool, alck_item_t *alck_item, alck_map_t *map)
{
    if (map->prev != GS_INVALID_ID32) {
        ALCK_MAP_PTR(pool, map->prev)->next = map->next;
    }
    if (map->next != GS_INVALID_ID32) {
        ALCK_MAP_PTR(pool, map->next)->prev = map->prev;
    }
    if (alck_item->first_map == map->id) {
        alck_item->first_map = map->next;
    }
    map->next = GS_INVALID_ID32;
    map->prev = GS_INVALID_ID32;

    cm_spin_lock(&pool->lock, NULL);
    map->next = pool->free_first;
    pool->free_first = map->id;
    pool->free_count++;
    cm_spin_unlock(&pool->lock);
}


alck_map_t *alck_get_map(alck_map_pool_t *map_pool, alck_item_t *alck_item, uint32 idx)
{
    uint32 map_id = alck_item->first_map;
    alck_map_t *alck_map = NULL;

    while (map_id != GS_INVALID_ID32) {
        alck_map = ALCK_MAP_PTR(map_pool, map_id);
        if (alck_map->idx == idx) {
            return alck_map;
        }
        map_id = alck_map->next;
    }
    return NULL;
}

status_t alck_alloc_item(alck_assist_t *assist, alck_item_t **alck_item)
{
    alck_item_pool_t *pool = &ALCK_CTX(assist)->item_pool;
    for (;;) {
        if (knl_check_session_status(ALCK_SESS(assist)) != GS_SUCCESS) {
            return GS_ERROR;
        }
        
        cm_spin_lock(&pool->lock, NULL);

        if (pool->free_first != GS_INVALID_ID32) {
            *alck_item = ALCK_ITEM_PTR(pool, pool->free_first);
            pool->free_first = (*alck_item)->next;
            pool->free_count--;
            cm_spin_unlock(&pool->lock);
            ALCK_ITEM_INIT(*alck_item);
            return GS_SUCCESS;
        }

        if (pool->count < pool->capacity) {
            *alck_item = ALCK_ITEM_PTR(pool, pool->count);
            (*alck_item)->id = pool->count;
            ++pool->count;
            cm_spin_unlock(&pool->lock);
            ALCK_ITEM_INIT(*alck_item);
            return GS_SUCCESS;
        }

        if (pool->extending) {
            cm_spin_unlock(&pool->lock);
            cm_sleep(1);
            continue;
        }

        pool->extending = GS_TRUE;
        cm_spin_unlock(&pool->lock);

        if (pool->capacity == GS_ALCK_MAX_ITEMS) {
            pool->extending = GS_FALSE;
            GS_THROW_ERROR(ERR_ALCK_LOCK_THRESHOLD, GS_ALCK_MAX_ITEMS);
            return GS_ERROR;
        }
        uint32 alloc_size = sizeof(alck_item_t) * GS_ALCK_EXTENT;
        pool->extents[pool->ext_cnt] = malloc(alloc_size);
        if (pool->extents[pool->ext_cnt] == NULL) {
            pool->extending = GS_FALSE;
            GS_THROW_ERROR(ERR_ALLOC_MEMORY, alloc_size, "advisory lock");
            return GS_ERROR;
        }

        errno_t ret = memset_sp(pool->extents[pool->ext_cnt], alloc_size, 0, alloc_size);
        knl_securec_check(ret);

        pool->capacity += GS_ALCK_EXTENT;
        ++pool->ext_cnt;
        CM_MFENCE;
        pool->extending = GS_FALSE;
    }
    return GS_SUCCESS;
}

void alck_free_item(alck_item_pool_t *pool, alck_item_t *alck_item)
{
    cm_spin_lock(&pool->lock, NULL);
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    CM_ASSERT(alck_item->first_map == GS_INVALID_ID32);
    knl_check_alck_item(pool, pool->free_first, alck_item->id);
#endif
    alck_item->next = pool->free_first;
    pool->free_first = alck_item->id;
    pool->free_count++;
    cm_spin_unlock(&pool->lock);
}

static inline status_t alck_init_spec_ctx(alck_ctx_spec_t *ctx)
{
    INIT_POOL(&ctx->item_pool);
    INIT_POOL(&ctx->map_pool);
    
    for (uint32 lp = 0; lp < GS_ALCK_MAX_BUCKETS; ++lp) {
        ctx->buckets[lp].latch.lock = 0;
        ctx->buckets[lp].latch.shared_count = 0;
        ctx->buckets[lp].latch.stat = LATCH_STATUS_IDLE;
        ctx->buckets[lp].id = lp;
        ctx->buckets[lp].first = GS_INVALID_ID32;
    }
    return GS_SUCCESS;
}

status_t alck_init_ctx(struct st_knl_instance *kernel)
{
    kernel->alck_ctx.se_ctx.lock_set = SE_LOCK;
    if (alck_init_spec_ctx(&kernel->alck_ctx.se_ctx) != GS_SUCCESS) {
        return GS_ERROR;
    }
    kernel->alck_ctx.tx_ctx.lock_set = TX_LOCK;
    if (alck_init_spec_ctx(&kernel->alck_ctx.tx_ctx) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

#define RESET_POOL(pool)                       \
    do {                                       \
        (pool)->capacity = 0;                  \
        (pool)->count = 0;                     \
        (pool)->ext_cnt = 0;                   \
        (pool)->free_first = GS_INVALID_ID32;  \
        (pool)->free_count = 0;                \
        (pool)->extending = GS_FALSE;          \
    } while (0)
    
static inline void alck_deinit_spec_ctx(alck_ctx_spec_t *ctx)
{
    alck_item_pool_t *pool = &ctx->item_pool;
    alck_map_pool_t *map_pool = &ctx->map_pool;
    for (uint32 i = 0; i < pool->ext_cnt; i++) {
        CM_FREE_PTR(pool->extents[i]);
    }
    for (uint32 i = 0; i < map_pool->ext_cnt; i++) {
        CM_FREE_PTR(map_pool->extents[i]);
    }
    
    RESET_POOL(pool);
    RESET_POOL(map_pool);
    
    for (uint32 lp = 0; lp < GS_ALCK_MAX_BUCKETS; ++lp) {
        ctx->buckets[lp].latch.lock = 0;
        ctx->buckets[lp].latch.shared_count = 0;
        ctx->buckets[lp].latch.stat = LATCH_STATUS_IDLE;
        ctx->buckets[lp].id = lp;
        ctx->buckets[lp].first = GS_INVALID_ID32;
    }
    return;
}

void alck_deinit_ctx(struct st_knl_instance *kernel)
{
    alck_deinit_spec_ctx(&kernel->alck_ctx.se_ctx);
    alck_deinit_spec_ctx(&kernel->alck_ctx.tx_ctx);
    return;
}

void alck_bucket_delete(alck_ctx_spec_t *ctx, alck_bucket_t *bucket, alck_item_t *alck_item)
{
    if (alck_item->id == bucket->first) {
        bucket->first = alck_item->next;
    }
    if (alck_item->prev != GS_INVALID_ID32) {
        ALCK_ITEM_PTR(&ctx->item_pool, alck_item->prev)->next = alck_item->next;
    }
    if (alck_item->next != GS_INVALID_ID32) {
        ALCK_ITEM_PTR(&ctx->item_pool, alck_item->next)->prev = alck_item->prev;
    }
}

void alck_bucket_insert(alck_ctx_spec_t *ctx, alck_bucket_t *bucket, alck_item_t *alck_item)
{
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    knl_check_alck_item(&ctx->item_pool, bucket->first, alck_item->id);
#endif
    alck_item->next = bucket->first;
    if (bucket->first != GS_INVALID_ID32) {
        ALCK_ITEM_PTR(&ctx->item_pool, bucket->first)->prev = alck_item->id;
    }
    alck_item->prev = GS_INVALID_ID32;
    bucket->first = alck_item->id;
    alck_item->bucket_id = bucket->id;
}

alck_item_t *alck_bucket_match(alck_ctx_spec_t *ctx, alck_bucket_t *bucket, text_t *name)
{
    uint32 lock_id = bucket->first;
    alck_item_t *alck_item = NULL;

    while (lock_id != GS_INVALID_ID32) {
        alck_item = ALCK_ITEM_PTR(&ctx->item_pool, lock_id);
        if (!cm_compare_text_str(name, alck_item->name)) {
            return alck_item;
        }
        lock_id = alck_item->next;
    }
    return NULL;
}

// when a item found, it's spin-lock was locked
static inline alck_item_t *alck_find_item(alck_assist_t *assist, alck_bucket_t *bucket, text_t *name)
{
    cm_latch_s(&bucket->latch, 0, GS_FALSE, NULL);

    alck_item_t *alck_item = alck_bucket_match(ALCK_CTX(assist), bucket, name);
    if (alck_item != NULL) {
        cm_spin_lock(&alck_item->lock, NULL);
        cm_unlatch(&bucket->latch, NULL);
        return alck_item;
    }

    cm_unlatch(&bucket->latch, NULL);

    return NULL;
}

status_t alck_alloc_map(alck_assist_t *assist, alck_map_t **alck_map)
{
    alck_map_pool_t *pool = &ALCK_CTX(assist)->map_pool;
    for (;;) {
        if (knl_check_session_status(ALCK_SESS(assist)) != GS_SUCCESS) {
            return GS_ERROR;
        }

        cm_spin_lock(&pool->lock, NULL);

        if (pool->free_first != GS_INVALID_ID32) {
            *alck_map = ALCK_MAP_PTR(pool, pool->free_first);
            pool->free_first = (*alck_map)->next;
            pool->free_count--;
            cm_spin_unlock(&pool->lock);
            return GS_SUCCESS;
        }

        if (pool->count < pool->capacity) {
            *alck_map = ALCK_MAP_PTR(pool, pool->count);

            (*alck_map)->id = pool->count;
            ++pool->count;
            cm_spin_unlock(&pool->lock);
            return GS_SUCCESS;
        }

        if (pool->extending) {
            cm_spin_unlock(&pool->lock);
            cm_sleep(1);
            continue;
        }

        pool->extending = GS_TRUE;
        cm_spin_unlock(&pool->lock);

        if (pool->capacity == GS_ALCK_MAX_MAPS) {
            pool->extending = GS_FALSE;
            GS_THROW_ERROR(ERR_ALCK_MAP_THRESHOLD, GS_ALCK_MAX_MAPS);
            return GS_ERROR;
        }
        uint32 alloc_size = sizeof(alck_map_t) * GS_ALCK_EXTENT;
        pool->extents[pool->ext_cnt] = malloc(alloc_size);
        if (pool->extents[pool->ext_cnt] == NULL) {
            pool->extending = GS_FALSE;
            GS_THROW_ERROR(ERR_ALLOC_MEMORY, alloc_size, "advisory lock map");
            return GS_ERROR;
        }

        errno_t ret = memset_sp(pool->extents[pool->ext_cnt], alloc_size, 0, alloc_size);
        knl_securec_check(ret);

        pool->capacity += GS_ALCK_EXTENT;
        ++pool->ext_cnt;
        CM_MFENCE;
        pool->extending = GS_FALSE;
    }
    return GS_SUCCESS;
}


status_t alck_map_add_idx(alck_assist_t *assist, alck_item_t *alck_item, alck_map_t **map, uint32 idx)
{
    if (*map != NULL) {
        (*map)->count++;
        return GS_SUCCESS;
    }
    alck_map_pool_t *pool = &ALCK_CTX(assist)->map_pool;
    if (alck_alloc_map(assist, map) != GS_SUCCESS) {
        return GS_ERROR;
    }
    (*map)->count = 1;
    (*map)->idx = idx;
    (*map)->next = alck_item->first_map;
    if (alck_item->first_map != GS_INVALID_ID32) {
        ALCK_MAP_PTR(pool, alck_item->first_map)->prev = (*map)->id;
    }
    (*map)->prev = GS_INVALID_ID32;
    alck_item->first_map = (*map)->id;
 
    return GS_SUCCESS;
}


void alck_free_map(alck_map_pool_t *pool, alck_map_t *alck_map)
{
    cm_spin_lock(&pool->lock, NULL);
    alck_map->next = pool->free_first;
    pool->free_first = alck_map->id;
    pool->free_count++;
    cm_spin_unlock(&pool->lock);
}
static inline status_t alck_insert_item(alck_assist_t *assist, alck_bucket_t *bucket, alck_item_t **alck_item)
{
    errno_t ret;
    alck_map_t *map = NULL;
    alck_item_t *input_item = *alck_item;
    cm_latch_x(&bucket->latch, 0, NULL);

    // in case a lock with the same name was already inserted
    // if happened, the lock item was returned
    alck_item_t *locked = alck_bucket_match(ALCK_CTX(assist), bucket, assist->name);
    if (locked != NULL) {
        cm_spin_lock(&locked->lock, NULL);
        cm_unlatch(&bucket->latch, NULL);
        alck_free_item(&ALCK_CTX(assist)->item_pool, input_item);
        *alck_item = locked;
        return GS_SUCCESS;
    }
    if (alck_map_add_idx(assist, input_item, &map, ALCK_MAP_ID(assist)) != GS_SUCCESS) {
        cm_unlatch(&bucket->latch, NULL);
        return GS_ERROR;
    }
    alck_bucket_insert(ALCK_CTX(assist), bucket, input_item);
    input_item->lock_mode = ALCK_LOCK_MODE(assist);
    input_item->lock_times = 1;

    if (ALCK_LOCK_MODE(assist) == ALCK_MODE_X) {
        input_item->x_map_id = ALCK_MAP_ID(assist);
        input_item->x_times = 1;
    } else {
        input_item->x_map_id = GS_INVALID_ID32;
        input_item->x_times = 0;
    }

    ret = strncpy_s(input_item->name, GS_ALCK_NAME_BUFFER_SIZE, ALCK_NAME(assist)->str, ALCK_NAME(assist)->len);
    knl_securec_check(ret);

    cm_unlatch(&bucket->latch, NULL);

    ALCK_ID(assist) = input_item->id;
    ALCK_NEW_LOCKED(assist) = GS_TRUE;
    *alck_item = NULL;
    return GS_SUCCESS;
}

static inline void alck_try_delete_item(alck_assist_t *assist, alck_bucket_t *bucket, alck_item_t *alck_item,
    uint32 del_sn)
{
    cm_latch_x(&bucket->latch, 0, NULL);
    cm_spin_lock(&alck_item->lock, NULL);

    // may be locked again after spin_lock unlocked
    if (alck_item->lock_times > 0 || alck_item->sn != del_sn) {
        cm_spin_unlock(&alck_item->lock);
        cm_unlatch(&bucket->latch, NULL);
        return;
    }

    ++alck_item->sn;

    alck_bucket_delete(ALCK_CTX(assist), bucket, alck_item);

    cm_spin_unlock(&alck_item->lock);
    cm_unlatch(&bucket->latch, NULL);

    alck_free_item(&ALCK_CTX(assist)->item_pool, alck_item);
}

status_t alck_wait_sess_responds(alck_assist_t *assist, alck_item_t *alck_item, date_t time_beg, date_t to_us)
{
    status_t ret = GS_SUCCESS;
    do {
        if (ALCK_SESS(assist)->alck_se_dead_locked) {
            GS_THROW_ERROR(ERR_DEAD_LOCK, "advisory lock", ALCK_SESS(assist)->id);
            ret = GS_ERROR;
            break;
        }

        if (ALCK_SESS(assist)->canceled) {
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            ret = GS_ERROR;
            break;
        }

        if (ALCK_SESS(assist)->killed) {
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            ret = GS_ERROR;
            break;
        }

        if (ALCK_TIMEOUT(assist) != 0 && (KNL_NOW(ALCK_SESS(assist)) - time_beg) > to_us) {
            GS_THROW_ERROR(ERR_RESOURCE_BUSY);
            ret = GS_TIMEDOUT;
            break;
        }
    } while (0);

    return ret;
}

static bool32 alck_locked_by_others(alck_assist_t *assist, alck_item_t *alck_item, alck_map_t *map)
{
    bool32 is_locked;
    if (map != NULL && map->count > 0) {
        is_locked = (alck_item->lock_times > map->count);
    } else {
        is_locked = (alck_item->lock_times > 0);
    }

    if (is_locked) {
        if (alck_item->lock_mode == ALCK_MODE_S) {
            alck_item->ix_map_id = ALCK_MAP_ID(assist);
            alck_item->lock_mode = ALCK_MODE_IX;
        }
        return GS_TRUE;
    }
    return GS_FALSE;
}

status_t alck_add(alck_assist_t *assist, alck_item_t *alck_item, alck_map_t *map, bool32 *locked,
    alck_mode_t lock_mode)
{
    if (alck_map_add_idx(assist, alck_item, &map, ALCK_MAP_ID(assist)) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    ++alck_item->lock_times;
    if (lock_mode == ALCK_MODE_X) {
        alck_item->lock_mode = ALCK_MODE_X;
        alck_item->x_times = 1;
        alck_item->x_map_id = ALCK_MAP_ID(assist);
        alck_item->ix_map_id = GS_INVALID_ID32;
    } else {
        alck_item->lock_mode = ALCK_MODE_S;
    }
    ALCK_NEW_LOCKED(assist) = (map->count == 1);

    ALCK_ID(assist) = alck_item->id;
    *locked = GS_TRUE;
    return GS_SUCCESS;
}

static inline void alck_lock_downgrade(alck_assist_t *assist, alck_item_t *alck_item)
{
    cm_spin_lock(&alck_item->lock, NULL);
    if (alck_item->lock_mode == ALCK_MODE_IX && alck_item->ix_map_id == ALCK_MAP_ID(assist)) {
        alck_item->ix_map_id = GS_INVALID_ID32;
        alck_item->lock_mode = (alck_item->lock_times == 0) ? ALCK_MODE_IDLE : ALCK_MODE_S;
    }
    cm_spin_unlock(&alck_item->lock);
}

#define ALCK_SET_WAIT_LOCK(walck, assist)               \
    do {                                                 \
        if (ALCK_LOCK_SET(assist) == TX_LOCK) {        \
            walck = &ALCK_SESS(assist)->walck_tx;             \
        } else {                                        \
            walck = &ALCK_SESS(assist)->walck_se;             \
        }                                               \
    } while (0)

status_t alck_wait_ex(alck_assist_t *assist, alck_item_t *alck_item, bool32 *locked)
{
    volatile alck_wait_t *walck = NULL;
    ALCK_SET_WAIT_LOCK(walck, assist);
    alck_map_pool_t *map_pool = &ALCK_CTX(assist)->map_pool;
    walck->lock_id = alck_item->id;
    walck->serial = alck_item->sn;

    cm_spin_unlock(&alck_item->lock);

    date_t time_beg = KNL_NOW(ALCK_SESS(assist));
    date_t to_us = ALCK_TIMEOUT(assist) * MICROSECS_PER_SECOND;
    status_t ret;

    knl_begin_session_wait(ALCK_SESS(assist), ENQ_ADVISORY_LOCK, GS_FALSE);
    while (GS_TRUE) {
        ret = alck_wait_sess_responds(assist, alck_item, time_beg, to_us);
        GS_BREAK_IF_ERROR(ret);
        cm_spin_sleep_and_stat2(1);

        // when the lock is released, it will be removed from hash bucket
        // and the sn number will be increased
        GS_BREAK_IF_TRUE(walck->serial != alck_item->sn);

        cm_spin_lock(&alck_item->lock, NULL);
        if (walck->serial != alck_item->sn) {
            cm_spin_unlock(&alck_item->lock);
            break;
        }

        if (alck_item->lock_mode == ALCK_MODE_X) {
            cm_spin_unlock(&alck_item->lock);
            continue;
        }
        /* locked by self in shared mode */
        alck_map_t *map = alck_get_map(map_pool, alck_item, ALCK_MAP_ID(assist));
        if (map != NULL && alck_item->lock_times == map->count) {
            ret = alck_add(assist, alck_item, map, locked, ALCK_MODE_X);
            cm_spin_unlock(&alck_item->lock);
            break;
        }

        // if lock is locked by others or not
        if (alck_locked_by_others(assist, alck_item, map) == GS_TRUE) {
            cm_spin_unlock(&alck_item->lock);
            continue;
        }

        if (alck_item->lock_mode == ALCK_MODE_IX && alck_item->ix_map_id != ALCK_MAP_ID(assist)) {
            cm_spin_unlock(&alck_item->lock);
            continue;
        }

        ret = alck_add(assist, alck_item, map, locked, ALCK_MODE_X);
        cm_spin_unlock(&alck_item->lock);
        break;
    }
    knl_end_session_wait(ALCK_SESS(assist));
    if (ret != GS_SUCCESS) {
        alck_lock_downgrade(assist, alck_item);
    }
    return ret;
}

status_t alck_wait_sh(alck_assist_t *assist, alck_item_t *alck_item, bool32 *locked)
{
    volatile alck_wait_t *walck = NULL;
    ALCK_SET_WAIT_LOCK(walck, assist);
    alck_map_pool_t *map_pool = &ALCK_CTX(assist)->map_pool;
    walck->lock_id = alck_item->id;
    walck->serial = alck_item->sn;

    cm_spin_unlock(&alck_item->lock);
    date_t time_beg = KNL_NOW(ALCK_SESS(assist));
    date_t to_us = ALCK_TIMEOUT(assist) * MICROSECS_PER_SECOND;
    status_t ret;

    knl_begin_session_wait(ALCK_SESS(assist), ENQ_ADVISORY_LOCK, GS_FALSE);
    for (;;) {
        ret = alck_wait_sess_responds(assist, alck_item, time_beg, to_us);
        GS_BREAK_IF_ERROR(ret);
        cm_spin_sleep_and_stat2(1);

        // when the lock is released, it will be removed from hash bucket
        // and the sn number will be increased
        if (walck->serial != alck_item->sn) {
            break;
        }

        cm_spin_lock(&alck_item->lock, NULL);
        if (walck->serial != alck_item->sn) {
            cm_spin_unlock(&alck_item->lock);
            break;
        }

        if (alck_item->lock_mode == ALCK_MODE_IX || alck_item->lock_mode == ALCK_MODE_X) {
            cm_spin_unlock(&alck_item->lock);
            continue;
        }

        alck_map_t *map = alck_get_map(map_pool, alck_item, ALCK_MAP_ID(assist));
        CM_ASSERT(map == NULL);

        ret = alck_add(assist, alck_item, map, locked, ALCK_MODE_S);
        cm_spin_unlock(&alck_item->lock);
        break;
    }
    knl_end_session_wait(ALCK_SESS(assist));
    return ret;
}

static inline status_t alck_deal_self_locked_ex(alck_assist_t *assist, alck_item_t *alck_item, alck_map_t *map,
    bool32 *locked)
{
    if (map->count == GS_ALCK_MAX_RECUR_LVL) {
        GS_THROW_ERROR(ERR_ALCK_RECURSIVE_LEVEL, GS_ALCK_MAX_RECUR_LVL);
        cm_spin_unlock(&alck_item->lock);
        return GS_ERROR;
    }
    ++alck_item->lock_times;
    ++map->count;

    // already locked by current session
    // lock mode can only be ALCK_MODE_S or ALCK_MODE_X
    if (alck_item->lock_mode == ALCK_MODE_S || alck_item->lock_mode == ALCK_MODE_IX) {
        alck_item->lock_mode = ALCK_MODE_X;
        alck_item->x_map_id = ALCK_MAP_ID(assist);
        alck_item->x_times = 1;
        alck_item->ix_map_id = GS_INVALID_ID32;
    } else {
        ++alck_item->x_times;
    }

    cm_spin_unlock(&alck_item->lock);

    ALCK_ID(assist) = alck_item->id;
    ALCK_NEW_LOCKED(assist) = GS_FALSE;
    *locked = GS_TRUE;
    return GS_SUCCESS;
}

status_t alck_lock_or_wait_ex(alck_assist_t *assist, alck_item_t *alck_item, bool32 *locked)
{
    alck_map_pool_t *map_pool = &ALCK_CTX(assist)->map_pool;
    alck_map_t *map = alck_get_map(map_pool, alck_item, ALCK_MAP_ID(assist));
    if (map != NULL && map->count == alck_item->lock_times) { // locked by self
        return alck_deal_self_locked_ex(assist, alck_item, map, locked);
    } else if (!alck_item->lock_times) { // just unlocked, not deleted from hash map
        if (alck_map_add_idx(assist, alck_item, &map, ALCK_MAP_ID(assist)) != GS_SUCCESS) {
            cm_spin_unlock(&alck_item->lock);
            return GS_ERROR;
        }
        alck_item->lock_mode = ALCK_MODE_X;
        ++alck_item->lock_times;
        alck_item->x_map_id = ALCK_MAP_ID(assist);
        alck_item->x_times = 1;
        cm_spin_unlock(&alck_item->lock);
        ALCK_ID(assist) = alck_item->id;
        ALCK_NEW_LOCKED(assist) = GS_TRUE;
        *locked = GS_TRUE;
        return GS_SUCCESS;
    } else { // locked by other
        *locked = GS_FALSE;
        if (ALCK_NO_WAIT(assist)) {
            cm_spin_unlock(&alck_item->lock);
            return GS_SUCCESS;
        } else {
            return alck_wait_ex(assist, alck_item, locked);
        }
    }
}

uint32 alck_get_locks(alck_map_pool_t *map_pool, alck_item_t *alck_item, uint32 idx)
{
    alck_map_t *map = alck_get_map(map_pool, alck_item, idx);
    
    return map == NULL ? 0 : map->count;
}

status_t alck_lock_or_wait_sh(alck_assist_t *assist, alck_item_t *alck_item, bool32 *locked)
{
    alck_map_pool_t *map_pool = &ALCK_CTX(assist)->map_pool;
    alck_map_t *map = alck_get_map(map_pool, alck_item, ALCK_MAP_ID(assist));

    if (map != NULL && map->count > 0) {
        if (map->count == GS_ALCK_MAX_RECUR_LVL) {
            GS_THROW_ERROR(ERR_ALCK_RECURSIVE_LEVEL, GS_ALCK_MAX_RECUR_LVL);
            cm_spin_unlock(&alck_item->lock);
            return GS_ERROR;
        }
        ++alck_item->lock_times;
        ++map->count;
        cm_spin_unlock(&alck_item->lock);

        ALCK_ID(assist) = alck_item->id;
        ALCK_NEW_LOCKED(assist) = GS_FALSE;
        *locked = GS_TRUE;
        return GS_SUCCESS;
    } else if (alck_item->lock_mode != ALCK_MODE_X && alck_item->lock_mode != ALCK_MODE_IX) {
        if (alck_map_add_idx(assist, alck_item, &map, ALCK_MAP_ID(assist)) != GS_SUCCESS) {
            cm_spin_unlock(&alck_item->lock);
            return GS_ERROR;
        }
        ++alck_item->lock_times;
        cm_spin_unlock(&alck_item->lock);

        ALCK_ID(assist) = alck_item->id;
        ALCK_NEW_LOCKED(assist) = GS_TRUE;
        *locked = GS_TRUE;
        return GS_SUCCESS;
    } else {
        *locked = GS_FALSE;
        if (ALCK_NO_WAIT(assist)) {
            cm_spin_unlock(&alck_item->lock);
            return GS_SUCCESS;
        } else {
            return alck_wait_sh(assist, alck_item, locked);
        }
    }
}

status_t alck_lock_or_wait(alck_assist_t *assist, alck_item_t *alck_item, bool32 *locked)
{
    if (ALCK_LOCK_MODE(assist) == ALCK_MODE_S) {
        return alck_lock_or_wait_sh(assist, alck_item, locked);
    } else {
        return alck_lock_or_wait_ex(assist, alck_item, locked);
    }
}

status_t alck_lock(alck_assist_t *assist, bool32 *locked)
{
    uint32 bucket_id = cm_hash_text(ALCK_NAME(assist), GS_ALCK_MAX_BUCKETS);
    alck_bucket_t *bucket = &ALCK_CTX(assist)->buckets[bucket_id];

    alck_item_t *alck_item = alck_find_item(assist, bucket, ALCK_NAME(assist));
    do {
        if (alck_item != NULL) {
            status_t ret = alck_lock_or_wait(assist, alck_item, locked);
            if (SECUREC_UNLIKELY(ret != GS_SUCCESS)) {
                if (ret == GS_TIMEDOUT) {
                    return GS_SUCCESS;
                } else {
                    return GS_ERROR;
                }
            }
            if (*locked) {
                return GS_SUCCESS;
            }
            // alck_item already released
            // refer to branch: if (walck->serial != alck_item->sn) in alck_wait
        }

        if (alck_alloc_item(assist, &alck_item) != GS_SUCCESS) {
            return GS_ERROR;
        }

        // when the lock with same name is locked by other session
        // adv_ctx_lock will return the locked item, and free the item just allocated.
        if (alck_insert_item(assist, bucket, &alck_item) != GS_SUCCESS) {
            alck_free_item(&ALCK_CTX(assist)->item_pool, alck_item);
            return GS_ERROR;
        }

        if (!alck_item) {
            *locked = GS_TRUE;
            return GS_SUCCESS;
        }
    } while (1);

    return GS_SUCCESS;
}

status_t alck_try_lock(alck_assist_t *assist, bool32 *locked)
{
    uint32 bucket_id = cm_hash_text(ALCK_NAME(assist), GS_ALCK_MAX_BUCKETS);
    alck_bucket_t *bucket = &ALCK_CTX(assist)->buckets[bucket_id];

    alck_item_t *alck_item = alck_find_item(assist, bucket, ALCK_NAME(assist));
    do {
        if (alck_item != NULL) {
            return alck_lock_or_wait(assist, alck_item, locked);
        }

        if (alck_alloc_item(assist, &alck_item) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (alck_insert_item(assist, bucket, &alck_item) != GS_SUCCESS) {
            alck_free_item(&ALCK_CTX(assist)->item_pool, alck_item);
            return GS_ERROR;
        }

        if (alck_item == NULL) {
            *locked = GS_TRUE;
            return GS_SUCCESS;
        }
    } while (1);

    return GS_SUCCESS;
}

static inline bool32 alck_unlock_ex(alck_assist_t *assist, alck_bucket_t *bucket, alck_item_t *alck_item)
{
    uint32 curr_sn;
    if (alck_item == NULL) {
        return GS_FALSE;
    }

    if (alck_item->lock_mode != ALCK_MODE_X) {
        cm_spin_unlock(&alck_item->lock);
        return GS_FALSE;
    }
    alck_map_pool_t *map_pool = &ALCK_CTX(assist)->map_pool;
    alck_map_t *map = alck_get_map(map_pool, alck_item, ALCK_MAP_ID(assist));
    if (map == NULL) {
        cm_spin_unlock(&alck_item->lock);
        return GS_FALSE;
    }
    CM_ASSERT(map->count > 0);
    if (alck_item->x_map_id != ALCK_MAP_ID(assist)) {
        cm_spin_unlock(&alck_item->lock);
        return GS_FALSE;
    }

    if (alck_item->lock_times > 1) {
        --alck_item->lock_times;
        --map->count;
        --alck_item->x_times;
        if (alck_item->x_times == 0) {
            alck_item->lock_mode = ALCK_MODE_S;
            alck_item->x_map_id = GS_INVALID_ID32;
        }
        CM_ASSERT(map->count > 0);
        cm_spin_unlock(&alck_item->lock);

        ALCK_ID(assist) = alck_item->id;
        return GS_TRUE;
    }

    alck_item->lock_mode = ALCK_MODE_IDLE;
    alck_item->lock_times = 0;
    alck_item->x_map_id = GS_INVALID_ID32;
    alck_item->x_times = 0;
    curr_sn = alck_item->sn;
    alck_free_map_node(map_pool, alck_item, map);
    cm_spin_unlock(&alck_item->lock);

    ALCK_ID(assist) = alck_item->id;
    alck_try_delete_item(assist, bucket, alck_item, curr_sn);
    return GS_TRUE;
}

bool32 alck_unlock_ex_by_id(alck_assist_t *assist, uint32 alck_id)
{
    alck_item_t *alck_item = ALCK_ITEM_PTR(&ALCK_CTX(assist)->item_pool, alck_id);
    alck_bucket_t *bucket = &ALCK_CTX(assist)->buckets[alck_item->bucket_id];
    cm_spin_lock(&alck_item->lock, NULL);
    return alck_unlock_ex(assist, bucket, alck_item);
}

bool32 alck_unlock_ex_by_name(alck_assist_t *assist, text_t *name)
{
    uint32 bucket_id = cm_hash_text(name, GS_ALCK_MAX_BUCKETS);
    alck_bucket_t *bucket = &ALCK_CTX(assist)->buckets[bucket_id];
    alck_item_t *alck_item = alck_find_item(assist, bucket, name);
    return alck_unlock_ex(assist, bucket, alck_item);
}

static inline bool32 alck_unlock_sh(alck_assist_t *assist, alck_bucket_t *bucket, alck_item_t *alck_item)
{
    uint32 curr_sn;
    if (alck_item == NULL) {
        return GS_FALSE;
    }
    alck_map_pool_t *map_pool = &ALCK_CTX(assist)->map_pool;
    alck_map_t *map = alck_get_map(map_pool, alck_item, ALCK_MAP_ID(assist));
    if (map == NULL) {
        cm_spin_unlock(&alck_item->lock);
        return GS_FALSE;
    }
    CM_ASSERT(map->count > 0);
    if (alck_item->lock_times == alck_item->x_times) {
        cm_spin_unlock(&alck_item->lock);
        return GS_FALSE;
    }

    if (alck_item->lock_times > 1) {
        --alck_item->lock_times;
        --map->count;
        if (map->count == 0) {
            alck_free_map_node(map_pool, alck_item, map);
        }
        cm_spin_unlock(&alck_item->lock);

        ALCK_ID(assist) = alck_item->id;
        return GS_TRUE;
    }

    alck_item->lock_times = 0;
    alck_free_map_node(map_pool, alck_item, map);
    curr_sn = alck_item->sn;
    if (alck_item->lock_mode == ALCK_MODE_IX) {
        cm_spin_unlock(&alck_item->lock);
        ALCK_ID(assist) = alck_item->id;
        return GS_TRUE;
    }
    
    alck_item->lock_mode = ALCK_MODE_IDLE;
    cm_spin_unlock(&alck_item->lock);

    ALCK_ID(assist) = alck_item->id;

    alck_try_delete_item(assist, bucket, alck_item, curr_sn);
    return GS_TRUE;
}

bool32 alck_unlock_sh_by_id(alck_assist_t *assist, uint32 alck_id)
{
    alck_item_t *alck_item = ALCK_ITEM_PTR(&ALCK_CTX(assist)->item_pool, alck_id);
    alck_bucket_t *bucket = &ALCK_CTX(assist)->buckets[alck_item->bucket_id];
    cm_spin_lock(&alck_item->lock, NULL);
    return alck_unlock_sh(assist, bucket, alck_item);
}

bool32 alck_unlock_sh_by_name(alck_assist_t *assist, text_t *name)
{
    uint32 bucket_id = cm_hash_text(name, GS_ALCK_MAX_BUCKETS);
    alck_bucket_t *bucket = &ALCK_CTX(assist)->buckets[bucket_id];
    alck_item_t *alck_item = alck_find_item(assist, bucket, name);
    return alck_unlock_sh(assist, bucket, alck_item);
}

static inline void alck_unlock_all(alck_assist_t *assist, uint32 alck_id)
{
    alck_item_t *alck_item = ALCK_ITEM_PTR(&ALCK_CTX(assist)->item_pool, alck_id);
    alck_map_t *map = NULL;
    uint16 bucket_id;
    uint32 curr_sn;
    cm_spin_lock(&alck_item->lock, NULL);
    map = alck_get_map(&ALCK_CTX(assist)->map_pool, alck_item, ALCK_MAP_ID(assist));
    if (map == NULL || map->count == 0) {
        cm_spin_unlock(&alck_item->lock);
        return;
    }
    alck_item->lock_times -= map->count;
    alck_free_map_node(&ALCK_CTX(assist)->map_pool, alck_item, map);
    if (alck_item->x_map_id == ALCK_MAP_ID(assist)) {
        alck_item->x_times = 0;
        alck_item->lock_mode = ALCK_MODE_S;
        alck_item->x_map_id = GS_INVALID_ID32;
    }
    if (alck_item->lock_times > 0) {
        cm_spin_unlock(&alck_item->lock);
        return;
    }
    alck_item->lock_mode = ALCK_MODE_IDLE;
    bucket_id = alck_item->bucket_id;
    curr_sn = alck_item->sn;
    cm_spin_unlock(&alck_item->lock);

    alck_bucket_t *bucket = &ALCK_CTX(assist)->buckets[bucket_id];
    alck_try_delete_item(assist, bucket, alck_item, curr_sn);
}

static inline status_t alck_check_name_db(knl_handle_t session, text_t *name)
{
    if (name->len > GS_MAX_ALCK_USER_NAME_LEN) {
        GS_THROW_ERROR(ERR_NAME_TOO_LONG, "advisory lock", name->len, GS_MAX_NAME_LEN);
        return GS_ERROR;
    }
    return alck_check_db_status(session);
}

static inline alck_ctx_spec_t *alck_get_spec_ctx(knl_session_t *session, alck_lock_set_t lock_set)
{
    if (lock_set == TX_LOCK) {
        return &((knl_instance_t *)session->kernel)->alck_ctx.tx_ctx;
    } else {
        return &((knl_instance_t *)session->kernel)->alck_ctx.se_ctx;
    }
}

#define ALCK_INIT_ASSIST(sess, nm, to, lockmode, lockset, nowait, assist)                   \
    do {                                                                            \
        (assist).se = (knl_session_t *)(sess);                                        \
        (assist).name = nm;                                                           \
        (assist).timeout = to;                                                        \
        (assist).lock_mode = lockmode;                                                \
        (assist).lock_set = lockset;                                                  \
        (assist).no_wait = nowait;                                                    \
        (assist).spec_ctx = alck_get_spec_ctx((assist).se, lockset);                    \
        (assist).map_id = ((lockset) == TX_LOCK) ? (assist).se->rm->id : (assist).se->id; \
    } while (0)

static inline status_t alck_register(alck_assist_t *assist, lock_type_t lock_type)
{
    lock_item_t *lock_item = NULL;

    // first locked
    if (!ALCK_NEW_LOCKED(assist) && (ALCK_LOCK_SET(assist) != TX_LOCK)) {
        lock_add_alck_times(ALCK_SESS(assist), ALCK_ID(assist), ALCK_LOCK_SET(assist));
        return GS_SUCCESS;
    }

    if (SECUREC_UNLIKELY(lock_alloc(ALCK_SESS(assist), lock_type, &lock_item) != GS_SUCCESS)) {
        switch (lock_type) {
            case LOCK_TYPE_ALCK_SS:
            case LOCK_TYPE_ALCK_TS:
                alck_unlock_sh_by_id(assist, ALCK_ID(assist));
                break;
            case LOCK_TYPE_ALCK_SX:
            case LOCK_TYPE_ALCK_TX:
                alck_unlock_ex_by_id(assist, ALCK_ID(assist));
                break;
            default:
                break;
        }
        return GS_ERROR;
    }

    lock_item->alck_id = ALCK_ID(assist);
    lock_item->alck_times = 1;
    lock_item->type = lock_type;
    return GS_SUCCESS;
}

bool32 knl_alck_have_se_lock(knl_handle_t sess)
{
    knl_session_t *se = (knl_session_t *)sess;
    return (se->alck_lock_group.plocks.count > 0 &&
        se->alck_lock_group.plock_id != se->alck_lock_group.plocks.first) ||
        se->alck_lock_group.glocks.count > 0;
}

status_t knl_alck_se_lock_ex(knl_handle_t sess, text_t *name, uint32 timeout, bool32 *locked)
{
    if (alck_check_name_db(sess, name) != GS_SUCCESS) {
        return GS_ERROR;
    }
    alck_assist_t assist;
    ALCK_INIT_ASSIST(sess, name, timeout, ALCK_MODE_X, SE_LOCK, GS_FALSE, assist);

    if (alck_lock(&assist, locked) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!*locked) {
        return GS_SUCCESS;
    }

    return alck_register(&assist, LOCK_TYPE_ALCK_SX);
}

status_t knl_alck_se_try_lock_ex(knl_handle_t sess, text_t *name, bool32 *locked)
{
    if (alck_check_name_db(sess, name) != GS_SUCCESS) {
        return GS_ERROR;
    }
    alck_assist_t assist;
    ALCK_INIT_ASSIST(sess, name, 0, ALCK_MODE_X, SE_LOCK, GS_TRUE, assist);

    if (alck_try_lock(&assist, locked) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!*locked) {
        return GS_SUCCESS;
    }

    return alck_register(&assist, LOCK_TYPE_ALCK_SX);
}

status_t knl_alck_se_lock_sh(knl_handle_t sess, text_t *name, uint32 timeout, bool32 *locked)
{
    if (alck_check_name_db(sess, name) != GS_SUCCESS) {
        return GS_ERROR;
    }
    alck_assist_t assist;
    ALCK_INIT_ASSIST(sess, name, timeout, ALCK_MODE_S, SE_LOCK, GS_FALSE, assist);

    if (alck_lock(&assist, locked) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!*locked) {
        return GS_SUCCESS;
    }

    return alck_register(&assist, LOCK_TYPE_ALCK_SS);
}

status_t knl_alck_se_try_lock_sh(knl_handle_t sess, text_t *name, bool32 *locked)
{
    if (alck_check_name_db(sess, name) != GS_SUCCESS) {
        return GS_ERROR;
    }
    alck_assist_t assist;
    ALCK_INIT_ASSIST(sess, name, 0, ALCK_MODE_S, SE_LOCK, GS_TRUE, assist);

    if (alck_try_lock(&assist, locked) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!*locked) {
        return GS_SUCCESS;
    }

    return alck_register(&assist, LOCK_TYPE_ALCK_SS);
}

status_t knl_alck_se_unlock_ex(knl_handle_t sess, text_t *name, bool32 *unlocked)
{
    if (alck_check_name_db(sess, name) != GS_SUCCESS) {
        return GS_ERROR;
    }
    alck_assist_t assist;
    ALCK_INIT_ASSIST(sess, name, 0, ALCK_MODE_X, SE_LOCK, GS_FALSE, assist);

    if (alck_unlock_ex_by_name(&assist, name)) {
        lock_del_alck_times(assist.se, assist.lock_id, SE_LOCK);
        *unlocked = GS_TRUE;
    } else {
        *unlocked = GS_FALSE;
    }
    return GS_SUCCESS;
}

status_t knl_alck_se_unlock_sh(knl_handle_t sess, text_t *name, bool32 *unlocked)
{
    if (alck_check_name_db(sess, name) != GS_SUCCESS) {
        return GS_ERROR;
    }
    alck_assist_t assist;
    ALCK_INIT_ASSIST(sess, name, 0, ALCK_MODE_S, SE_LOCK, GS_FALSE, assist);

    if (alck_unlock_sh_by_name(&assist, name)) {
        lock_del_alck_times(assist.se, assist.lock_id, SE_LOCK);
        *unlocked = GS_TRUE;
    } else {
        *unlocked = GS_FALSE;
    }
    return GS_SUCCESS;
}

void alck_se_unlock_all(knl_handle_t sess, uint32 alck_id)
{
    alck_assist_t assist;
    ALCK_INIT_ASSIST(sess, NULL, 0, ALCK_MODE_IDLE, SE_LOCK, GS_FALSE, assist);
    alck_unlock_all(&assist, alck_id);
}

status_t knl_alck_tx_lock_ex(knl_handle_t sess, text_t *name, uint32 timeout, bool32 *locked)
{
    if (alck_check_name_db(sess, name) != GS_SUCCESS) {
        return GS_ERROR;
    }
    alck_assist_t assist;
    ALCK_INIT_ASSIST(sess, name, timeout, ALCK_MODE_X, TX_LOCK, GS_FALSE, assist);

    if (alck_lock(&assist, locked) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!*locked) {
        return GS_SUCCESS;
    }

    return alck_register(&assist, LOCK_TYPE_ALCK_TX);
}

status_t knl_alck_tx_try_lock_ex(knl_handle_t sess, text_t *name, bool32 *locked)
{
    if (alck_check_name_db(sess, name) != GS_SUCCESS) {
        return GS_ERROR;
    }
    alck_assist_t assist;
    ALCK_INIT_ASSIST(sess, name, 0, ALCK_MODE_X, TX_LOCK, GS_TRUE, assist);

    if (alck_try_lock(&assist, locked) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!*locked) {
        return GS_SUCCESS;
    }

    return alck_register(&assist, LOCK_TYPE_ALCK_TX);
}

status_t knl_alck_tx_lock_sh(knl_handle_t sess, text_t *name, uint32 timeout, bool32 *locked)
{
    if (alck_check_name_db(sess, name) != GS_SUCCESS) {
        return GS_ERROR;
    }
    alck_assist_t assist;
    ALCK_INIT_ASSIST(sess, name, timeout, ALCK_MODE_S, TX_LOCK, GS_FALSE, assist);

    if (alck_lock(&assist, locked) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!*locked) {
        return GS_SUCCESS;
    }

    return alck_register(&assist, LOCK_TYPE_ALCK_TS);
}

status_t knl_alck_tx_try_lock_sh(knl_handle_t sess, text_t *name, bool32 *locked)
{
    if (alck_check_name_db(sess, name) != GS_SUCCESS) {
        return GS_ERROR;
    }
    alck_assist_t assist;
    ALCK_INIT_ASSIST(sess, name, 0, ALCK_MODE_S, TX_LOCK, GS_TRUE, assist);

    if (alck_try_lock(&assist, locked) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!*locked) {
        return GS_SUCCESS;
    }

    return alck_register(&assist, LOCK_TYPE_ALCK_TS);
}

void alck_tx_unlock_sh(knl_handle_t sess, uint32 alck_id)
{
    alck_assist_t assist;
    ALCK_INIT_ASSIST(sess, NULL, 0, ALCK_MODE_S, TX_LOCK, GS_FALSE, assist);
    alck_unlock_sh_by_id(&assist, alck_id);
}

void alck_tx_unlock_ex(knl_handle_t sess, uint32 alck_id)
{
    alck_assist_t assist;
    ALCK_INIT_ASSIST(sess, NULL, 0, ALCK_MODE_X, TX_LOCK, GS_FALSE, assist);
    alck_unlock_ex_by_id(&assist, alck_id);
}
