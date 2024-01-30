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
 * cms_sync.c
 *
 *
 * IDENTIFICATION
 * src/cms/interface/cms_sync.c
 *
 * -------------------------------------------------------------------------
 */
#include "cms_log_module.h"
#include "cms_sync.h"

#ifndef WIN32
#include <sys/time.h>
#endif

status_t cms_sync_init(cms_sync_t* sync)
{
    cm_init_thread_lock(&sync->lock);
#ifdef WIN32
    sync->cond = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (sync->cond == NULL) {
        return CT_ERROR;
    }
#else
    pthread_condattr_t attr;
    int32 ret = pthread_condattr_init(&attr);
    if (ret != 0) {
        CT_LOG_RUN_ERR("pthread condattr init failed, ret %d", ret);
        return CT_ERROR;
    }

    ret = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    if (ret != 0) {
        CT_LOG_RUN_ERR("pthread condattr setclock failed, ret %d", ret);
        (void)pthread_condattr_destroy(&attr);
        return CT_ERROR;
    }

    ret = pthread_cond_init(&sync->cond, &attr);
    if (ret != 0) {
        CT_LOG_RUN_ERR("pthread cond init failed, ret %d", ret);
        (void)pthread_condattr_destroy(&attr);
        return CT_ERROR;
    }
#endif
    return CT_SUCCESS;
}

void cms_sync_deinit(cms_sync_t* sync)
{
    cm_destroy_thread_lock(&sync->lock);
#ifdef WIN32
    (void)CloseHandle(&sync->cond);
#else
    (void)pthread_cond_destroy(&sync->cond);
#endif
}

#ifndef WIN32
static void cms_get_timespec(struct timespec* tim, uint32 timeout)
{
    struct timespec tv;
    (void)clock_gettime(CLOCK_MONOTONIC, &tv);

    tim->tv_sec = tv.tv_sec + timeout / CMS_SYNC_MILLISEC_PER_SEC;
    tim->tv_nsec = tv.tv_nsec + ((long)timeout % CMS_SYNC_MILLISEC_PER_SEC) * CMS_SYNC_NANOSEC_PER_MILLISEC;
    if (tim->tv_nsec >= CMS_SYNC_NANOSEC_PER_SEC) {
        tim->tv_sec++;
        tim->tv_nsec -= CMS_SYNC_NANOSEC_PER_SEC;
    }
}
#endif

status_t cms_sync_wait(cms_sync_t* sync, uint32 timeout /* milliseconds */)
{
#ifdef WIN32
    cm_thread_unlock(&sync->lock);
    int32 ret = WaitForSingleObject(sync->cond, timeout);
    cm_thread_lock(&sync->lock);
    switch (ret) {
        case WAIT_OBJECT_0:
            return CT_SUCCESS;
        case WAIT_TIMEOUT:
            return CT_TIMEDOUT;
        default:
            return CT_ERROR;
    }
#else
    struct timespec tim;
    cms_get_timespec(&tim, timeout);
    int32 ret = pthread_cond_timedwait(&sync->cond, &sync->lock, &tim);
    switch (ret) {
        case 0:
            return CT_SUCCESS;
        case ETIMEDOUT:
            return CT_TIMEDOUT;
        default:
            return CT_ERROR;
    }
#endif
    return CT_SUCCESS;
}

void cms_sync_notify(cms_sync_t* sync)
{
#ifdef WIN32
    (void)SetEvent(sync->cond);
#else
    (void)pthread_cond_signal(&sync->cond);
#endif
}
