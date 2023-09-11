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
 * cm_sync.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_sync.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_sync.h"

#ifndef WIN32
#include <sys/time.h>
#endif

int32 cm_event_init(cm_event_t *evnt)
{
#ifdef WIN32
    evnt->evnt = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (evnt->evnt == NULL) {
        return GS_ERROR;
    }
#else
    evnt->status = GS_FALSE;
    if (pthread_condattr_init(&evnt->attr) != 0) {
        (void)pthread_cond_destroy(&evnt->cond);
        return GS_ERROR;
    }

    if (pthread_mutex_init(&evnt->lock, 0) != 0) {
        (void)pthread_cond_destroy(&evnt->cond);
        return GS_ERROR;
    }

    if (pthread_condattr_setclock(&evnt->attr, CLOCK_MONOTONIC) != 0) {
        (void)pthread_cond_destroy(&evnt->cond);
        return GS_ERROR;
    }

    if (pthread_cond_init(&evnt->cond, &evnt->attr) != 0) {
        (void)pthread_cond_destroy(&evnt->cond);
        return GS_ERROR;
    }
#endif
    return GS_SUCCESS;
}

void cm_event_destory(cm_event_t *evnt)
{
#ifdef WIN32
    (void)CloseHandle(evnt->evnt);
#else
    (void)pthread_mutex_destroy(&evnt->lock);
    (void)pthread_cond_destroy(&evnt->cond);
    (void)pthread_condattr_destroy(&evnt->attr);
#endif
}

#ifndef WIN32
void cm_get_timespec(struct timespec *tim, uint32 timeout)
{
    struct timespec tv;
    (void)clock_gettime(CLOCK_MONOTONIC, &tv);

    tim->tv_sec = tv.tv_sec + timeout / 1000;
    tim->tv_nsec = tv.tv_nsec + ((long)timeout % 1000) * 1000000;
    if (tim->tv_nsec >= 1000000000) {
        tim->tv_sec++;
        tim->tv_nsec -= 1000000000;
    }
}
#endif

int32 cm_event_timedwait(cm_event_t *evnt, uint32 timeout /* milliseconds */)
{
#ifdef WIN32
    int ret;
    ret = WaitForSingleObject(evnt->evnt, timeout);
    switch (ret) {
        case WAIT_OBJECT_0:
            return GS_SUCCESS;
        case WAIT_TIMEOUT:
            return GS_TIMEDOUT;
        default:
            return GS_ERROR;
    }
#else
    struct timespec tim;

    (void)pthread_mutex_lock(&evnt->lock);
    if (evnt->status) {
        evnt->status = GS_FALSE;
        (void)pthread_mutex_unlock(&(evnt->lock));
        return GS_SUCCESS;
    }

    if (timeout == 0xFFFFFFFF) {
        while (!evnt->status) {
            (void)pthread_cond_wait(&evnt->cond, &evnt->lock);
        }
        evnt->status = GS_FALSE;
        (void)pthread_mutex_unlock(&evnt->lock);
        return GS_SUCCESS;
    }

    cm_get_timespec(&tim, timeout);
    (void)pthread_cond_timedwait(&evnt->cond, &evnt->lock, &tim);
    if (evnt->status) {
        evnt->status = GS_FALSE;
        (void)pthread_mutex_unlock(&evnt->lock);
        return GS_SUCCESS;
    }
    (void)pthread_mutex_unlock(&evnt->lock);
    return GS_TIMEDOUT;
#endif
}

void cm_event_wait(cm_event_t *evnt)
{
    (void)cm_event_timedwait(evnt, 50);  // 50ms
}

void cm_event_notify(cm_event_t *evnt)
{
#ifdef WIN32
    (void)SetEvent(evnt->evnt);
#else
    (void)pthread_mutex_lock(&evnt->lock);
    if (!evnt->status) {
        evnt->status = GS_TRUE;
        (void)pthread_cond_signal(&evnt->cond);
    }
    (void)pthread_mutex_unlock(&evnt->lock);
#endif
}
