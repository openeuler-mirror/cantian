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
 * cm_thread_pool.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_thread_pool.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __SRV_PAR_TREADS__
#define __SRV_PAR_TREADS__

#include "cm_defs.h"
#include "cm_thread.h"
#include "cm_sync.h"
#include "cm_spinlock.h"

#ifdef __cplusplus
extern "C" {
#endif
    
typedef void(*run_task_action)(void* param);
typedef struct st_thread_task {
    run_task_action action;
    void *param;
} thread_task_t;

typedef enum en_thread_stat {
    THREAD_STATUS_IDLE = 0,
    THREAD_STATUS_PROCESSSING = 1,
    THREAD_STATUS_ENDING = 2,
    THREAD_STATUS_ENDED = 3
} thread_stat_t;

typedef struct st_pooling_thread {
    thread_t thread;
    uint32 spid;
    cm_event_t event;
    thread_task_t *task;
    thread_stat_t status;
}pooling_thread_t;

typedef struct st_cm_thread_pool {
    uint32 total;
    uint32 starts;
    thread_lock_t lock;
    pooling_thread_t *threads;
}cm_thread_pool_t;

void cm_init_thread_pool(cm_thread_pool_t *pool);
status_t cm_create_thread_pool(cm_thread_pool_t *pool, uint32 thread_stack_size, uint32 count);
void cm_destroy_thread_pool(cm_thread_pool_t *pool);

status_t cm_get_idle_pooling_thread(cm_thread_pool_t *pool, pooling_thread_t **obj);
void cm_dispatch_pooling_thread(pooling_thread_t *thread, void* task);
void cm_release_pooling_thread(pooling_thread_t *thread);

#ifdef __cplusplus
}
#endif

#endif //__SRV_PAR_TREADS__
