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
 * cms_sync.h
 *
 *
 * IDENTIFICATION
 * src/cms/interface/cms_sync.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMS_SYNC_H
#define CMS_SYNC_H

#include "cm_defs.h"
#include "cm_thread.h"
#ifdef WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define CMS_SYNC_MICROSECS_PER_MILLISEC   1000
#define CMS_SYNC_MILLISEC_PER_SEC         1000
#define CMS_SYNC_NANOSEC_PER_MILLISEC     1000000
#define CMS_SYNC_NANOSEC_PER_SEC          1000000000

typedef struct st_cms_sync {
#ifdef WIN32
    HANDLE              cond;
#else
    pthread_cond_t      cond;
#endif
    thread_lock_t       lock;
} cms_sync_t;

status_t cms_sync_init(cms_sync_t* sync);
void cms_sync_deinit(cms_sync_t* sync);
static inline void cms_sync_lock(cms_sync_t* sync)
{
    cm_thread_lock(&sync->lock);
}
static inline void cms_sync_unlock(cms_sync_t* sync)
{
    cm_thread_unlock(&sync->lock);
}

void cms_sync_notify(cms_sync_t* sync);
status_t cms_sync_wait(cms_sync_t* sync, uint32 timeout /* milliseconds */);

#ifdef __cplusplus
}
#endif
#endif
