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
 * shm_thread_pool.h
 *
 *
 * IDENTIFICATION
 * src/tse/message_queue/shm_thread_pool.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __shm_thread_pool_h__
#define __shm_thread_pool_h__

#include "pthread.h"
#include "semaphore.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

typedef enum SHM_STATUS_E {
    SHM_STATUS_DOWN = 0,
    SHM_STATUS_INIT,
    SHM_STATUS_RUNNING,
    SHM_STATUS_RELEASING,
    SHM_STATUS_SLEEPING
} SHM_STATUS_S;

typedef struct SHM_THREAD_JOB_S {
    void (*handler)(void*);
    void *args;
} SHM_THREAD_JOB_T;

typedef struct SHM_THREAD_S {
    pthread_t thd;
    sem_t sem;
    SHM_STATUS_S status;
    SHM_THREAD_JOB_T current_job;
    struct SHM_THREAD_S *next;
} SHM_THREAD_T;

typedef struct SHM_THREAD_POOL_QUEUE {
    pthread_mutex_t lock;
    SHM_THREAD_T *front;
    SHM_THREAD_T *tail;
    int free_thread_num;
} SHM_THREAD_POOL_QUEUE_T;

typedef struct SHM_THREAD_POOL_ARRAY {
    SHM_THREAD_T *shm_threads;
    int max_thread_num;
    SHM_STATUS_S status;
} SHM_THREAD_POOL_ARRAY_T;

typedef struct SHM_THREAD_POOL_S {
    int max_thread_num;
    int running_thread_num;
    SHM_STATUS_S status;
    SHM_THREAD_POOL_ARRAY_T thread_array;
    SHM_THREAD_POOL_QUEUE_T free_thread_queue;
    pthread_mutex_t lock;
} SHM_THREAD_POOL_T;

typedef struct SHM_THREAD_POOL_ARGS {
    SHM_THREAD_T *thread;
    SHM_THREAD_POOL_T *thread_pool;
    int idx;
} SHM_THREAD_POOL_ARGS_T;

typedef struct CREATE_SHM_THREAD_POOL_PARAMS_S {
    int max_thread_num;
} CREATE_SHM_THREAD_POOL_PARAMS_T;

int shm_create_thread_pool(CREATE_SHM_THREAD_POOL_PARAMS_T *params, SHM_THREAD_POOL_T **thread_pool);
void shm_destroy_thread_pool(SHM_THREAD_POOL_T **thread_pool);
int shm_add_job_to_thread_pool(SHM_THREAD_POOL_T *thread_pool, SHM_THREAD_JOB_T* job);

#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif /* __shm_thread_pool_h__ */
