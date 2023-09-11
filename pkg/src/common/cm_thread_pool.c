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
 * cm_thread_pool.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_thread_pool.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_thread_pool.h"
#include "cm_log.h"
#include "cm_error.h"

#ifdef __cplusplus
extern "C" {
#endif

static void cm_pooling_thread_entry(thread_t *obj)
{
    pooling_thread_t *pooling_thread = (pooling_thread_t*)obj->argument;
    status_t ret;

    cm_set_thread_name("pooling_thread");

    pooling_thread->spid = cm_get_current_thread_id();

    while (!obj->closed) {
        // wait 50ms
        ret = cm_event_timedwait(&pooling_thread->event, 50);

        if (pooling_thread->status == THREAD_STATUS_ENDING) {
            pooling_thread->status = THREAD_STATUS_ENDED;
        }

        if (ret == GS_SUCCESS && pooling_thread->task != NULL) {
            cm_reset_error();
            pooling_thread->task->action(pooling_thread->task->param);
            pooling_thread->task = NULL;
            cm_set_thread_name("pooling_thread");
        }
    }
}

void cm_init_thread_pool(cm_thread_pool_t *pool)
{
    pool->total = 0;
    pool->starts = 0;
    cm_init_thread_lock(&pool->lock);
    pool->threads = NULL;
}

static inline status_t cm_start_pooling_thread(pooling_thread_t *obj, uint32 thread_stack_size)
{
    return cm_create_thread(cm_pooling_thread_entry, thread_stack_size, obj, &obj->thread);
}

status_t cm_create_thread_pool(cm_thread_pool_t *pool, uint32 thread_stack_size, uint32 count)
{
    pooling_thread_t *threads = NULL;
    uint32 size, i;
    status_t ret = GS_SUCCESS;
    errno_t err;

    if (pool->starts > 0) {
        return GS_SUCCESS;
    }

    cm_thread_lock(&pool->lock);

    do {
        /* double check */
        if (pool->starts > 0) {
            break;
        }

        /* create parallel threads */
        size = count * sizeof(pooling_thread_t);
        threads = (pooling_thread_t *)malloc(size);
        if (threads == NULL) {
            GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, "threads pool");
            ret = GS_ERROR;
            break;
        }
        err = memset_s(threads, size, 0, size);
        if (err != EOK) {
            GS_THROW_ERROR(ERR_SYSTEM_CALL, err);
            ret = GS_ERROR;
            break;
        }
        pool->threads = threads;
        pool->total = count;

        for (i = 0; i < count; ++i) {
            ret = cm_event_init(&threads[i].event);
            GS_BREAK_IF_ERROR(ret);

            ret = cm_start_pooling_thread(&threads[i], thread_stack_size);
            GS_BREAK_IF_ERROR(ret);
        }
        
        pool->starts = i;
    } while (0);

    cm_thread_unlock(&pool->lock);

    if (ret != GS_SUCCESS) {
        CM_FREE_PTR(threads);
        pool->threads = NULL;
    }

    return ret;
}

void cm_destroy_thread_pool(cm_thread_pool_t *pool)
{
    uint32 i = 0;
    pooling_thread_t *obj = NULL;

    CM_POINTER(pool);
    if (pool->starts == 0) {
        CM_FREE_PTR(pool->threads);
        return;
    }

    cm_thread_lock(&pool->lock);
    for (i = 0; i < pool->starts; ++i) {
        obj = &pool->threads[i];
        cm_close_thread(&obj->thread);
    }
    cm_thread_unlock(&pool->lock);

    CM_FREE_PTR(pool->threads);

    return;
}

status_t cm_get_idle_pooling_thread(cm_thread_pool_t *pool, pooling_thread_t **obj)
{
    uint32 i = 0;
    pooling_thread_t *thrd = NULL;

    CM_POINTER(pool);
    *obj = NULL;

    if (pool->starts > 0) {
        cm_thread_lock(&pool->lock);
        for (i = 0; i < pool->starts; i++) {
            thrd = &pool->threads[i];
            if (thrd->status == THREAD_STATUS_IDLE) {
                *obj = thrd;
                thrd->status = THREAD_STATUS_PROCESSSING;
                break;
            }
        }
        cm_thread_unlock(&pool->lock);
    }

    return (*obj == NULL) ?  GS_ERROR : GS_SUCCESS;
}

void cm_dispatch_pooling_thread(pooling_thread_t *thread, void* task)
{
    CM_POINTER(thread);
    /* no task doing */
    CM_ASSERT(thread->task == NULL);

    thread->task = task;
    cm_event_notify(&thread->event);
}

void cm_release_pooling_thread(pooling_thread_t *thread)
{
    thread->status = THREAD_STATUS_ENDING;
    cm_event_notify(&thread->event);
    while (thread->status != THREAD_STATUS_ENDED) {
        cm_sleep(1);
    }

    thread->status = THREAD_STATUS_IDLE;
}

#ifdef __cplusplus
}
#endif
