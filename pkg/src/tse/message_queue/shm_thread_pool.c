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
 * shm_thread_pool.c
 *
 *
 * IDENTIFICATION
 * src/tse/message_queue/shm_thread_pool.c
 *
 * -------------------------------------------------------------------------
 */

#include "pthread.h"
#include "shm_thread_pool.h"
#include "dsw_shm_pri.h"

#define SHM_TPOOL_CHECK_INTERVAL (100000) // 100ms

void *_tpool_malloc(size_t len)
{
    return malloc(len);
}

void shm_thread_queue_push(SHM_THREAD_POOL_QUEUE_T *free_thd_queue, SHM_THREAD_T *thd) // add thread to the queue end
{
    pthread_mutex_lock(&(free_thd_queue->lock));
    free_thd_queue->tail->next = thd;
    free_thd_queue->tail = free_thd_queue->tail->next;
    free_thd_queue->free_thread_num++;
    pthread_mutex_unlock(&(free_thd_queue->lock));
}

SHM_THREAD_T *shm_thread_queue_pop(SHM_THREAD_POOL_QUEUE_T *free_thd_queue) // get thread from the queue start
{
    pthread_mutex_lock(&(free_thd_queue->lock));
    if (free_thd_queue->front == free_thd_queue->tail) {
        pthread_mutex_unlock(&(free_thd_queue->lock));
        LOG_SHM_ERROR("[tpool] queue pop failed, queue is empty");
        return NULL;
    }
    SHM_THREAD_T *temp = free_thd_queue->front->next;
    free_thd_queue->front->next = free_thd_queue->front->next->next;
    free_thd_queue->free_thread_num--;
    if (free_thd_queue->free_thread_num == 0) {
        free_thd_queue->tail = free_thd_queue->front;
    }
    pthread_mutex_unlock(&(free_thd_queue->lock));
    return temp;
}

SHM_THREAD_POOL_ARGS_T *thread_args_init(SHM_THREAD_POOL_T *thd_pool, SHM_THREAD_T *thd, int idx)
{
    SHM_THREAD_POOL_ARGS_T *thd_do_job_args = (SHM_THREAD_POOL_ARGS_T *)malloc(sizeof(SHM_THREAD_POOL_ARGS_T));
    if (thd_do_job_args == NULL) {
        LOG_SHM_ERROR("[tpool] thread args init failed, malloc error");
        return NULL;
    }
    thd_do_job_args->thread = thd;
    thd_do_job_args->thread_pool = thd_pool;
    thd_do_job_args->idx = idx;
    return thd_do_job_args;
}

void thread_args_destory(SHM_THREAD_POOL_ARGS_T *thd_args)
{
    free(thd_args);
}

void thd_do_job(void* arg)
{
    SHM_THREAD_POOL_ARGS_T *thd_args = (SHM_THREAD_POOL_ARGS_T *)arg;
    SHM_THREAD_T *cur_thread = thd_args->thread;
    // important, ensure thread->status = sleeping. At ling 98, status is init not sleeping
    while (thd_args->thread_pool->thread_array.status != SHM_STATUS_RUNNING) {
        usleep(SHM_TPOOL_CHECK_INTERVAL);
    }
    while (cur_thread->status == SHM_STATUS_SLEEPING) {
        sem_wait(&(cur_thread->sem));
        if (cur_thread->current_job.handler == NULL) {
            continue;
        }
        cur_thread->status = SHM_STATUS_RUNNING;
        cur_thread->current_job.handler(cur_thread->current_job.args); // do job
        cur_thread->status = SHM_STATUS_SLEEPING;
        shm_thread_queue_push(&(thd_args->thread_pool->free_thread_queue), cur_thread);
        cur_thread->current_job.handler = NULL;
    }
    if (cur_thread->status == SHM_STATUS_RELEASING) { // judge the status
        cur_thread->status = SHM_STATUS_DOWN;
        thread_args_destory(thd_args);
        pthread_exit(NULL);
    }
}

int shm_thread_init(SHM_THREAD_POOL_T *thd_pool, SHM_THREAD_T *thread, int idx)
{
    thread->status = SHM_STATUS_INIT;
    sem_init(&(thread->sem), 0, 0);
    thread->current_job.handler = NULL;
    shm_thread_queue_push(&(thd_pool->free_thread_queue), thread);
    SHM_THREAD_POOL_ARGS_T *thd_args = thread_args_init(thd_pool, thread, idx);
    if (thd_args == NULL) {
        sem_destroy(&(thread->sem));
        LOG_SHM_ERROR("[tpool] thread init failed, thd_args init error");
        return -1;
    }
    int ret = pthread_create(&(thread->thd), NULL, (void*)thd_do_job, (void*)thd_args);
    if (ret != 0) {
        sem_destroy(&(thread->sem));
        thread_args_destory(thd_args);
        LOG_SHM_ERROR("[tpool] thread init failed, pthread_create error");
        return ret;
    }
    thread->status = SHM_STATUS_SLEEPING;
    return ret;
}

void shm_thread_destory(SHM_THREAD_T *thread)
{
    if (thread->status == SHM_STATUS_DOWN || thread->status == SHM_STATUS_INIT) { // thread is not init or init failed
        return;
    }
    while (thread->status != SHM_STATUS_SLEEPING) { // waiting for thread to complete the job
        usleep(SHM_TPOOL_CHECK_INTERVAL);
    }
    thread->status = SHM_STATUS_RELEASING;
    sem_post(&(thread->sem));
    while (thread->status != SHM_STATUS_DOWN) { // waiting for thread to exit
        usleep(SHM_TPOOL_CHECK_INTERVAL);
    }
    sem_destroy(&(thread->sem));
    pthread_join(thread->thd, NULL);
}

SHM_THREAD_T *get_shm_thread(SHM_THREAD_POOL_ARRAY_T *thd_array, int idx) // idx is not used，temporarily reserved
{
    if (idx >= thd_array->max_thread_num) {
        return NULL;
    }
    return &(thd_array->shm_threads[idx]);
}

int shm_thread_array_init(SHM_THREAD_POOL_T *thread_pool) // malloc is complete here
{
    uint32_t max_thread_num = (uint32_t)thread_pool->max_thread_num;
    thread_pool->thread_array.status = SHM_STATUS_INIT;
    thread_pool->thread_array.shm_threads = (SHM_THREAD_T *)malloc(max_thread_num * sizeof(SHM_THREAD_T));
    if (thread_pool->thread_array.shm_threads == NULL) {
        LOG_SHM_ERROR("[tpool] array init failed, thread init error");
        return -1;
    }
    thread_pool->thread_array.max_thread_num = thread_pool->max_thread_num;
    int ret = 0;
    for (int i = 0; i < thread_pool->max_thread_num; i++) {
        ret = shm_thread_init(thread_pool, &(thread_pool->thread_array.shm_threads[i]), i);
        if (ret != 0) {
            LOG_SHM_ERROR("[tpool] array init failed, thread init error");
            return -1;
        }
    }
    thread_pool->thread_array.status = SHM_STATUS_RUNNING;
    LOG_SHM_INFO("[tpool] array init success");
    return ret;
}

void shm_thread_array_destory(SHM_THREAD_POOL_ARRAY_T *thd_array)
{
    if (thd_array->shm_threads == NULL) {
        LOG_SHM_ERROR("[tpool] array destory failed, array is null");
        return;
    }
    for (size_t i = 0; i < thd_array->max_thread_num; i++) {
        shm_thread_destory(&(thd_array->shm_threads[i]));
    }
    free(thd_array->shm_threads);
    thd_array->shm_threads = NULL;
}

int shm_thread_queue_init(SHM_THREAD_POOL_QUEUE_T *free_thd_queue)
{
    pthread_mutex_init(&(free_thd_queue->lock), NULL);
    free_thd_queue->free_thread_num = 0;
    free_thd_queue->front = (SHM_THREAD_T *)malloc(sizeof(SHM_THREAD_T));
    if (free_thd_queue->front == NULL) {
        LOG_SHM_ERROR("[tpool] queue init failed, queue_front malloc error");
        return -1;
    }
    free_thd_queue->front->status = SHM_STATUS_SLEEPING; // front is as a guard node
    free_thd_queue->tail = free_thd_queue->front;
    LOG_SHM_INFO("[tpool] queue init success");
    return 0;
}

void shm_thread_queue_destory(SHM_THREAD_POOL_QUEUE_T *free_thd_queue) // do after array destory, ensure all thread down
{
    pthread_mutex_destroy(&(free_thd_queue->lock));
    free(free_thd_queue->front);
    free_thd_queue->front = NULL;
}

int shm_create_thread_pool(CREATE_SHM_THREAD_POOL_PARAMS_T *params, SHM_THREAD_POOL_T **thread_pool)
{
    if (params->max_thread_num <= 0) {
        LOG_SHM_ERROR("[tpool] create tpool failed, params error");
        return -1;
    }
    int thread_num = params->max_thread_num;
    SHM_THREAD_POOL_T *thread_pool_temp = (SHM_THREAD_POOL_T *)_tpool_malloc(sizeof(SHM_THREAD_POOL_T));
    if (thread_pool_temp == NULL) {
        LOG_SHM_ERROR("[tpool] create tpool failed, tpool malloc error");
        return -1;
    }
    memset(thread_pool_temp, 0, sizeof(SHM_THREAD_POOL_T));
    thread_pool_temp->max_thread_num = thread_num;
    thread_pool_temp->running_thread_num = 0;
    thread_pool_temp->status = SHM_STATUS_INIT;
    
    int ret = shm_thread_queue_init(&(thread_pool_temp->free_thread_queue));
    if (ret != 0) {
        LOG_SHM_ERROR("[tpool] create tpool failed, queue init error");
        free(thread_pool_temp);
        thread_pool_temp = NULL;
        return -1;
    }
    ret = shm_thread_array_init(thread_pool_temp);
    if (ret != 0) {
        LOG_SHM_ERROR("[tpool] create tpool failed, array init error");
        shm_thread_array_destory(&(thread_pool_temp->thread_array));
        shm_thread_queue_destory(&(thread_pool_temp->free_thread_queue));
        free(thread_pool_temp);
        thread_pool_temp = NULL;
        return -1;
    }
    thread_pool_temp->status = SHM_STATUS_RUNNING;

    *thread_pool = thread_pool_temp;
    LOG_SHM_INFO("[tpool] tpool init success");
    return 0;
}

void shm_destroy_thread_pool(SHM_THREAD_POOL_T **thread_pool)
{
    shm_assert(((*thread_pool) != NULL) && ((*thread_pool)->status == SHM_STATUS_RUNNING));
    shm_thread_array_destory(&((*thread_pool)->thread_array)); // destory the array first, ensure all threads done jobs
    shm_thread_queue_destory(&((*thread_pool)->free_thread_queue));
    free(*thread_pool);
    (*thread_pool) = NULL;
    LOG_SHM_INFO("[tpool] tpool destory success");
}

void thd_curent_job_prepare(SHM_THREAD_T *job_thread, SHM_THREAD_JOB_T* job)
{
    job_thread->current_job.handler = job->handler;
    job_thread->current_job.args = job->args;
}

int shm_add_job_to_thread_pool(SHM_THREAD_POOL_T *thread_pool, SHM_THREAD_JOB_T* job)
{
    if (job == NULL || job->handler == NULL) {
        LOG_SHM_ERROR("[tpool] add job failed, job_params error");
        return -1;
    }
    if (thread_pool == NULL) {
        LOG_SHM_ERROR("[tpool] add job failed, tpool is null");
        return -1;
    }
    while (thread_pool->thread_array.status != SHM_STATUS_RUNNING) { // waiting for the array has been inited
        usleep(SHM_TPOOL_CHECK_INTERVAL);
    }
    SHM_THREAD_T *job_thread = shm_thread_queue_pop(&(thread_pool->free_thread_queue));
    if (job_thread == NULL || job_thread->status != SHM_STATUS_SLEEPING) {
        LOG_SHM_ERROR("[tpool] add job failed, job_thread error");
        return -1;
    }
    thd_curent_job_prepare(job_thread, job);
    sem_post(&(job_thread->sem));
    return 0;
}
