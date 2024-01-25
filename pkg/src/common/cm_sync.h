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
 * cm_sync.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_sync.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_SYNC_H__
#define __CM_SYNC_H__

#include "cm_defs.h"

#ifdef WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

typedef struct st_event {
#ifdef WIN32
    HANDLE evnt;
#else
    volatile bool32 status;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    pthread_condattr_t attr;
#endif
} cm_event_t;

int32 cm_event_init(cm_event_t *evnt);
void cm_event_destory(cm_event_t *evnt);
void cm_event_notify(cm_event_t *evnt);
int32 cm_event_timedwait(cm_event_t *evnt, uint32 timeout /* milliseconds */);
void cm_event_wait(cm_event_t *evnt);

#ifndef WIN32
void cm_get_timespec(struct timespec *tim, uint32 timeout);
#endif

#endif
