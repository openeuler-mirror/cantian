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
 * cm_ga.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_ga.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_common_module.h"
#include <string.h>
#include "cm_ga.h"
#include "cm_spinlock.h"
#include "cm_shm.h"
#include "cm_log.h"
#include "cm_error.h"
#include "cm_defs.h"
#include "cm_debug.h"
char *g_app_area_addr;

int32 g_sys_shm_id = -1;
int32 g_app_shm_id = -1;

spinlock_t g_ga_attach_mutex = 0;

ga_pool_t g_app_pools[GA_APP_POOL_COUNT] = {
    { "ctrl", NULL, NULL, NULL, NULL, { NULL }, { 1, GA_INSTANCE_POOL_SIZE, 0 }, 0, 0 }, /* ctrl pool */
    { "sesseion", NULL, NULL, NULL, NULL, { NULL }, { 0, 0, 0 }, 0, 0 },                 /* inst pool */
    { "meta 8k", NULL, NULL, NULL, NULL, { NULL }, { 0, 0, 0 }, 0, 0 },                  /* 8k pool */
    { "meta 16k", NULL, NULL, NULL, NULL, { NULL }, { 0, 0, 0 }, 0, 0 },                 /* 16k pool */
};

static __inline ga_pool_t *ga_get_pool(uint32 id)
{
    return &g_app_pools[GA_POOL_IDX(id)];
}

void ga_set_pool_def(ga_pool_id_e pool_id, ga_pool_def_t *def)
{
    ga_pool_t *pool;
    CM_POINTER(def);
    pool = ga_get_pool((uint32)pool_id);
    pool->def = *def;
    pool->capacity = CM_ALIGN_512(sizeof(ga_pool_ctrl_t));
    pool->capacity += CM_ALIGN_512(((ulong)def->object_size + sizeof(ga_object_map_t)) * def->object_count);
}

static __inline ga_object_map_t *ga_object_map(ga_pool_t *pool, uint32 object_id)
{
    uint32 ex_pool_id;
    ga_object_map_t *ex_object_map;

    CM_POINTER(pool);

    if (pool->ctrl->ex_count == 0 || object_id < pool->def.object_count) {
        return &pool->object_map[object_id];
    } else {
        ex_pool_id = (object_id / pool->def.object_count) - 1;
        ex_object_map = (ga_object_map_t *)pool->ex_pool_addr[ex_pool_id];
        return &ex_object_map[object_id % pool->def.object_count];
    }
}

static void ga_append_into_queue(ga_pool_t *pool, ga_queue_t *queue, uint32 object_id)
{
    ga_object_map_t *obj_map = ga_object_map(pool, object_id);

    CM_POINTER2(pool, queue);

    if (queue->count == 0) {
        queue->count = 1;
        queue->first = object_id;
        queue->last = object_id;
        obj_map->next = CT_INVALID_ID32;
        obj_map->prior = CT_INVALID_ID32;
        return;
    }

    ga_object_map(pool, queue->last)->next = object_id;
    obj_map->prior = queue->last;
    obj_map->next = CT_INVALID_ID32;
    queue->last = object_id;
    queue->count++;
}

static uint32 ga_remove_from_queue(ga_pool_t *pool, ga_queue_t *queue)
{
    uint32 object_id;

    CM_POINTER2(pool, queue);

    if (queue->count == 0) {
        return CT_INVALID_ID32;
    }

    object_id = queue->first;
    queue->first = ga_object_map(pool, object_id)->next;
    queue->count--;
    if (queue->count > 0) {
        ga_object_map(pool, queue->first)->prior = CT_INVALID_ID32;
    }

    return object_id;
}

static void ga_concat_queue(ga_pool_t *pool, ga_queue_t *queue1, ga_queue_t *queue2)
{
    CM_POINTER3(pool, queue1, queue2);

    if (queue1->count == 0) {
        *queue1 = *queue2;
    } else {
        ga_object_map(pool, queue1->last)->next = queue2->first;
        ga_object_map(pool, queue2->first)->prior = queue1->last;
        queue1->count += queue2->count;
        queue1->last = queue2->last;
    }
}

static void ga_init_pool(uint32 area_type, ga_offset_t offset, ga_pool_t *pool)
{
    uint32 i, object_offset;
    CM_POINTER(pool);

    pool->addr = g_app_area_addr + offset;

    object_offset = sizeof(ga_pool_ctrl_t) + pool->def.object_count * sizeof(ga_object_map_t);
    pool->object_addr = pool->addr + object_offset;

    pool->ctrl = (ga_pool_ctrl_t *)pool->addr;
    pool->object_map = (ga_object_map_t *)(pool->addr + sizeof(ga_pool_ctrl_t));

    pool->object_map[0].prior = CT_INVALID_ID32;

    for (i = 0; i < pool->def.object_count - 1; i++) {
        pool->object_map[i].next = i + 1;
        pool->object_map[(uint32)(i + 1)].prior = i;
    }

    pool->object_map[pool->def.object_count - 1].next = CT_INVALID_ID32;

    CT_INIT_SPIN_LOCK(pool->ctrl->mutex);
    pool->ctrl->def = pool->def;
    pool->ctrl->offset = offset;
    pool->ctrl->ex_count = 0;

    pool->ctrl->free_objects.count = pool->def.object_count;
    pool->ctrl->free_objects.first = 0;
    pool->ctrl->free_objects.last = pool->def.object_count - 1;
}

status_t ga_create_global_area(void)
{
    uint64 app_area_size, offset;
    uint32 i;
    uint64 *pool_offsets;

    app_area_size = CM_ALIGN_512(GA_APP_POOL_COUNT * sizeof(ulong));
    for (i = 0; i < GA_APP_POOL_COUNT; i++) {
        if (g_app_pools[i].capacity == 0) {
            CT_LOG_RUN_ERR("The application pool %d is not defined.", i);
            CT_THROW_ERROR(ERR_CTSTORE_GA_INIT, "The application pool is not defined.");
            return CT_ERROR;
        }

        app_area_size += g_app_pools[i].capacity;
    }

    g_app_area_addr = (char *)cm_get_shm(SHM_TYPE_FIXED, (uint32)SHM_ID_APP_GA, app_area_size, CM_SHM_ATTACH_RW,
                                         PERM_GRPRW);
    if (NULL == g_app_area_addr) {
        CT_LOG_RUN_ERR("Can't create the application area because of failed to get shm, area size = %llu.",
                       app_area_size);
        CT_THROW_ERROR(ERR_CTSTORE_GA_INIT, "Can't create the application area because of failed to get shm.");
        return CT_ERROR;
    }

    offset = CM_ALIGN_512(GA_APP_POOL_COUNT * sizeof(ulong));
    pool_offsets = (uint64 *)g_app_area_addr;

    for (i = 0; i < GA_APP_POOL_COUNT; i++) {
        pool_offsets[i] = offset;
        ga_init_pool(GA_APP_AREA, offset, &g_app_pools[i]);
        offset += g_app_pools[i].capacity;
    }
    CT_LOG_RUN_INF("Create global area successfully.");
    return CT_SUCCESS;
}

void ga_destroy_global_area(void)
{
    uint32 i;

    for (i = 0; i < CM_GA_SHM_MAX_ID; i++) {
        (void)cm_del_shm(SHM_TYPE_GA, i);
    }

    (void)cm_del_shm(SHM_TYPE_FIXED, (uint32)SHM_ID_APP_GA);
}

static void ga_attach_pool(uint32 area_type, ga_pool_id_e id, uint32 attach_perm)
{
    uint32 i, object_offset;
    char *area_addr;
    ga_pool_t *pool = &g_app_pools[id];
    ulong *pool_offsets;

    area_addr = g_app_area_addr;
    pool_offsets = (ulong *)area_addr;

    pool->addr = area_addr + pool_offsets[id];
    pool->ctrl = (ga_pool_ctrl_t *)(pool->addr);
    pool->object_map = (ga_object_map_t *)(pool->addr + sizeof(ga_pool_ctrl_t));
    pool->def = pool->ctrl->def;

    object_offset = sizeof(ga_pool_ctrl_t) + pool->def.object_count * sizeof(ga_object_map_t);
    pool->object_addr = pool->addr + object_offset;

    for (i = 0; i < GA_MAX_EXTENDED_POOLS; i++) {
        pool->ex_pool_addr[i] = NULL;
    }

    for (i = 0; i < pool->ctrl->ex_count; i++) {
        pool->ex_pool_addr[i] = (char *)cm_attach_shm(SHM_TYPE_GA, (uint32)pool->ctrl->ex_shm_id[i], 0, attach_perm);
    }
}

int32 ga_attach_area(uint32 attach_perm)
{
    uint32 i = 0;

    if (cm_get_shm_ctrl_flag() != CM_SHM_CTRL_FLAG_TRUE) {
        CT_LOG_RUN_ERR("Can not attach the global area because the server is not ready yet.");
        return CT_ERROR;
    }

    g_app_area_addr = (char *)cm_attach_shm(SHM_TYPE_FIXED, (uint32)SHM_ID_APP_GA, 0, attach_perm);
    if (NULL == g_app_area_addr) {
        CT_LOG_RUN_ERR("can't attach the application area.");
        return CT_ERROR;
    }

    for (i = 0; i < GA_APP_POOL_COUNT; i++) {
        ga_attach_pool(GA_APP_AREA, (ga_pool_id_e)i, attach_perm);
    }

    return CT_SUCCESS;
}

static void ga_detach_pool(uint32 area_type, ga_pool_id_e id)
{
    ga_pool_t *pool = &g_app_pools[id];
    uint32 i;

    if (!pool->ctrl) {
        return;
    }

    for (i = 0; i < pool->ctrl->ex_count; i++) {
        if (pool->ex_pool_addr[i] != NULL) {
            (void)cm_detach_shm(SHM_TYPE_GA, (uint32)pool->ctrl->ex_shm_id[i]);
        }
    }
}

void ga_detach_area(void)
{
    uint32 i = 0;

    for (i = 0; i < GA_APP_POOL_COUNT; i++) {
        ga_detach_pool(GA_APP_AREA, (ga_pool_id_e)i);
    }

    (void)cm_detach_shm(SHM_TYPE_FIXED, (uint32)SHM_ID_APP_GA);
}

static status_t ga_extend_pool(ga_pool_id_e pool_id)
{
    ulong ex_pool_size;
    uint32 ex_start_id, object_id, object_cost, i;
    char *ex_addr;
    ga_queue_t ex_objects;
    ga_pool_t *pool = ga_get_pool((uint32)pool_id);
    ga_object_map_t *object_map;
    uint32 pool_shm_id = GA_EXT_SHM_POOLID(pool_id) * GA_MAX_EXTENDED_POOLS + pool->ctrl->ex_count;

    if (pool->def.ex_max <= pool->ctrl->ex_count) {
        CT_LOG_RUN_ERR("the extended number of %s pool reach to limitation.", pool->pool_name);
        return CT_ERROR;
    }

    object_cost = pool->def.object_size + sizeof(ga_object_map_t);
    ex_pool_size = (ulong)object_cost * pool->def.object_count;

    ex_addr = (char *)cm_get_shm(SHM_TYPE_GA, pool_shm_id, ex_pool_size, CM_SHM_ATTACH_RW, PERM_GRPRW);
    if (ex_addr == NULL) {
        CT_LOG_RUN_ERR("get shared memory in failure when extending the %s pool.", pool->pool_name);
        return CT_ERROR;
    }

    pool->ctrl->ex_shm_id[pool->ctrl->ex_count] = pool_shm_id;
    pool->ex_pool_addr[pool->ctrl->ex_count] = ex_addr;
    ex_start_id = (pool->ctrl->ex_count + 1) * pool->def.object_count;

    pool->ctrl->ex_count++;

    object_map = (ga_object_map_t *)ex_addr;

    object_map[0].prior = CT_INVALID_ID32;

    for (i = 0; i < pool->def.object_count - 1; i++) {
        object_id = ex_start_id + i;
        object_map[i].next = object_id + 1;
        object_map[(uint32)(i + 1)].prior = object_id;
    }

    object_map[(uint32)(pool->def.object_count - 1)].next = CT_INVALID_ID32;

    ex_objects.first = ex_start_id;
    ex_objects.last = ex_start_id + pool->def.object_count - 1;
    ex_objects.count = pool->def.object_count;

    ga_concat_queue(pool, &pool->ctrl->free_objects, &ex_objects);

    return CT_SUCCESS;
}

void ga_pool_stat(ga_pool_id_e pool_id, uint32 *obj_sum, uint32 *free_count)
{
    ga_pool_t *pool = ga_get_pool((uint32)pool_id);
    CM_POINTER2(obj_sum, free_count);

    cm_spin_lock(&pool->ctrl->mutex, NULL);

    *obj_sum = (pool->def.object_count * (pool->def.ex_max + 1));
    *free_count = (pool->def.object_count * (pool->def.ex_max - pool->ctrl->ex_count)) + pool->ctrl->free_objects.count;

    cm_spin_unlock(&pool->ctrl->mutex);

    return;
}

uint32 ga_alloc_object(ga_pool_id_e pool_id, uint32 specific_id)
{
    uint32 object_id, next_id, prior_id;
    ga_pool_t *pool = ga_get_pool((uint32)pool_id);

    cm_spin_lock(&pool->ctrl->mutex, NULL);

    if (pool->ctrl->free_objects.count == 0) {
        if (pool->def.ex_max == 0) {
            cm_spin_unlock(&pool->ctrl->mutex);
            return CT_INVALID_ID32;
        }

        if (ga_extend_pool(pool_id) != CT_SUCCESS) {
            cm_spin_unlock(&pool->ctrl->mutex);
            return CT_INVALID_ID32;
        }
    }

    if (specific_id != CT_INVALID_ID32) {
        next_id = pool->object_map[specific_id].next;
        prior_id = pool->object_map[specific_id].prior;

        if (next_id != CT_INVALID_ID32) {
            pool->object_map[next_id].prior = prior_id;
        }

        if (prior_id != CT_INVALID_ID32) {
            pool->object_map[prior_id].next = next_id;
        }

        if (pool->ctrl->free_objects.first == specific_id) {
            pool->ctrl->free_objects.first = next_id;
        }

        if (pool->ctrl->free_objects.last == specific_id) {
            pool->ctrl->free_objects.last = prior_id;
        }

        pool->ctrl->free_objects.count--;
        object_id = specific_id;
    } else {
        object_id = ga_remove_from_queue(pool, &pool->ctrl->free_objects);
    }

    cm_spin_unlock(&pool->ctrl->mutex);

    return object_id;
}

uint32 ga_alloc_object_append(ga_pool_id_e pool_id, uint32 specific_id, ga_queue_t *list)
{
    uint32 object_id;
    CM_POINTER(list);
    object_id = ga_alloc_object(pool_id, specific_id);
    if (object_id != CT_INVALID_ID32) {
        ga_append_into_queue(ga_get_pool((uint32)pool_id), list, object_id);
    }

    return object_id;
}

int32 ga_alloc_object_list(ga_pool_id_e pool_id, uint32 count, ga_queue_t *list)
{
    uint32 last_id, i;
    status_t status;
    ga_pool_t *pool = ga_get_pool((uint32)pool_id);

    CM_POINTER(list);
    GA_INIT_QUEUE(list);

    if (count == 0) {
        return CT_SUCCESS;
    }

    cm_spin_lock(&pool->ctrl->mutex, NULL);

    if (pool->ctrl->free_objects.count < count) {
        status = ga_extend_pool(pool_id);
        if (status != CT_SUCCESS) {
            cm_spin_unlock(&pool->ctrl->mutex);
            CT_LOG_DEBUG_ERR("Failed to extend pool:%u.", pool_id);
            return status;
        }
        CT_LOG_DEBUG_INF("Extend pool:%d, count:%u.", pool_id, pool->ctrl->free_objects.count);
    }

    if (pool->ctrl->free_objects.count == count) {
        *list = pool->ctrl->free_objects;
        GA_INIT_QUEUE(&pool->ctrl->free_objects);
    } else {
        list->first = pool->ctrl->free_objects.first;
        list->count = count;

        last_id = list->first;
        for (i = 1; i < count; i++) {
            last_id = ga_object_map(pool, last_id)->next;
        }
        list->last = last_id;

        pool->ctrl->free_objects.first = ga_object_map(pool, last_id)->next;

        ga_object_map(pool, list->last)->next = CT_INVALID_ID32;
        ga_object_map(pool, pool->ctrl->free_objects.first)->prior = CT_INVALID_ID32;

        pool->ctrl->free_objects.count -= count;
    }

    cm_spin_unlock(&pool->ctrl->mutex);

    return CT_SUCCESS;
}
uint32 ga_next_object(ga_pool_id_e pool_id, uint32 object_id)
{
    ga_pool_t *pool = ga_get_pool((uint32)pool_id);
    return ga_object_map(pool, object_id)->next;
}

uint32 ga_prior_object(ga_pool_id_e pool_id, uint32 object_id)
{
    ga_pool_t *pool = ga_get_pool((uint32)pool_id);
    return ga_object_map(pool, object_id)->prior;
}

void ga_free_object(ga_pool_id_e pool_id, uint32 object_id)
{
    ga_pool_t *pool = ga_get_pool((uint32)pool_id);

    // For test cursor free mutiply times
    CM_ASSERT(CT_INVALID_ID32 != object_id);

    cm_spin_lock(&pool->ctrl->mutex, NULL);
    ga_append_into_queue(pool, &pool->ctrl->free_objects, object_id);
    cm_spin_unlock(&pool->ctrl->mutex);
}

void ga_free_object_list(ga_pool_id_e pool_id, ga_queue_t *list)
{
    ga_pool_t *pool = ga_get_pool((uint32)pool_id);
    CM_POINTER(list);

    if (list->count == 0) {
        return;
    }
    cm_spin_lock(&pool->ctrl->mutex, NULL);
    ga_concat_queue(pool, &pool->ctrl->free_objects, list);
    cm_spin_unlock(&pool->ctrl->mutex);
}

#define GA_MAIN_POOL_OBJECT_OFFSET(pool, object_id)                                                            \
    (ga_offset_t)(CM_ALIGN_512(sizeof(ga_pool_ctrl_t) +                                                        \
                               (ga_offset_t)(pool)->def.object_count * (ga_offset_t)sizeof(ga_object_map_t)) + \
                  (ga_offset_t)(object_id) * (ga_offset_t)(pool)->def.object_size)

char *ga_object_addr(ga_pool_id_e pool_id, uint32 object_id)
{
    ulong offset;
    uint32 ex_pool_id;
    ga_pool_t *pool = ga_get_pool((uint32)pool_id);

    if (object_id < pool->def.object_count) {
        return pool->addr + GA_MAIN_POOL_OBJECT_OFFSET(pool, object_id);
    }

    if (pool->ctrl->ex_count == 0) {
        return NULL;
    } else {
        offset = CM_ALIGN_512((ga_offset_t)pool->def.object_count * (ga_offset_t)sizeof(ga_object_map_t));
        offset += (ga_offset_t)(object_id % pool->def.object_count) * (ga_offset_t)pool->def.object_size;
        ex_pool_id = object_id / pool->def.object_count - 1;

        if (pool->ex_pool_addr[ex_pool_id] == NULL) {
            cm_spin_lock(&g_ga_attach_mutex, NULL);
            if (pool->ex_pool_addr[ex_pool_id] == NULL) {
                pool->ex_pool_addr[ex_pool_id] =
                    (char *)cm_attach_shm(SHM_TYPE_GA, (uint32)pool->ctrl->ex_shm_id[ex_pool_id], 0, CM_SHM_ATTACH_RW);
            }

            cm_spin_unlock(&g_ga_attach_mutex);
        }

        if (pool->ex_pool_addr[ex_pool_id] == NULL) {
            return NULL;
        }

        return pool->ex_pool_addr[ex_pool_id] + offset;
    }
}
