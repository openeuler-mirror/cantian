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
 * srv_stat.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_stat.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "srv_stat.h"
#include "srv_instance.h"

void stat_pool_init(stat_pool_t *pool)
{
    pool->lock = 0;
    pool->hwm = 0;
    pool->capacity = 0;
    pool->page_count = 0;

    pool->free_list.count = 0;
    pool->free_list.first = CT_INVALID_ID16;
    pool->free_list.last = CT_INVALID_ID16;
}

static inline knl_stat_t *stat_addr(stat_pool_t *pool, uint32 id)
{
    uint32 page_id = id / CT_EXTEND_STATS;
    uint32 slot_id = id % CT_EXTEND_STATS;
    return (knl_stat_t *)(pool->pages[page_id] + slot_id * sizeof(knl_stat_t));
}

static status_t stat_pool_extend(stat_pool_t *pool)
{
    if (pool->capacity >= CT_MAX_STATS) {
        CT_THROW_ERROR(ERR_TOO_MANY_STAT_OBJECTS, CT_MAX_STATS);
        CT_LOG_RUN_WAR("too many stat objects");
        return CT_ERROR;
    }

    CM_ASSERT(pool->page_count < CT_MAX_STAT_PAGES);

    size_t alloc_size = sizeof(knl_stat_t) * CT_EXTEND_STATS;
    char *buf = (char *)malloc(alloc_size);
    if (buf == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)alloc_size, "alloc kernel session stat");
        CT_LOG_RUN_WAR("alloc kernel session stat failed");
        return CT_ERROR;
    }

    errno_t ret = memset_sp(buf, alloc_size, 0, alloc_size);
    knl_securec_check(ret);

    pool->capacity += CT_EXTEND_STATS;
    pool->pages[pool->page_count++] = buf;

    return CT_SUCCESS;
}

static status_t stat_alloc(stat_pool_t *stat_pool, uint16 *stat_id)
{
    knl_stat_t *stat = NULL;

    if (stat_pool->free_list.count == 0 && stat_pool->hwm == stat_pool->capacity) {
        if (stat_pool_extend(stat_pool) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (stat_pool->free_list.count == 0) {
        *stat_id = stat_pool->hwm;
        stat = stat_addr(stat_pool, *stat_id);
        stat->id = *stat_id;

        stat_pool->stats[stat_pool->hwm] = stat;
        stat_pool->hwm++;
    } else {
        *stat_id = stat_pool->free_list.first;
        stat = stat_pool->stats[*stat_id];
        CM_ASSERT(stat->id == *stat_id);

        stat_pool->free_list.first = stat->next;
        stat_pool->free_list.count--;
        if (stat_pool->free_list.count == 0) {
            stat_pool->free_list.first = CT_INVALID_ID16;
            stat_pool->free_list.last = CT_INVALID_ID16;
        }
    }

    stat->next = CT_INVALID_ID16;
    return CT_SUCCESS;
}

static void stat_release(stat_pool_t *stat_pool, uint16 stat_id)
{
    knl_stat_t *stat = stat_pool->stats[stat_id];

    CM_ASSERT(stat_id != CT_INVALID_ID16 && stat->id == stat_id);

    if (stat_pool->free_list.count == 0) {
        stat_pool->free_list.first = stat_id;
        stat_pool->free_list.last = stat_id;
    } else {
        stat_pool->stats[stat_pool->free_list.last]->next = stat_id;
        stat_pool->free_list.last = stat_id;
    }

    stat->next = CT_INVALID_ID16;
    stat_pool->free_list.count++;
}

status_t srv_alloc_stat(uint16 *stat_id)
{
    stat_pool_t *stat_pool = &g_instance->stat_pool;

    cm_spin_lock(&stat_pool->lock, NULL);
    if (stat_alloc(stat_pool, stat_id) != CT_SUCCESS) {
        cm_spin_unlock(&stat_pool->lock);
        return CT_ERROR;
    }
    cm_spin_unlock(&stat_pool->lock);
    return CT_SUCCESS;
}

void srv_release_stat(uint16 *stat_id)
{
    stat_pool_t *stat_pool = &g_instance->stat_pool;

    cm_spin_lock(&stat_pool->lock, NULL);
    stat_release(stat_pool, *stat_id);
    *stat_id = CT_INVALID_ID16;
    cm_spin_unlock(&stat_pool->lock);
}
