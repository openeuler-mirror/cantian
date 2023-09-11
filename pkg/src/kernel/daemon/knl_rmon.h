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
 * knl_rmon.h
 *
 *
 * IDENTIFICATION
 * src/kernel/daemon/knl_rmon.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __KNL_RMON_H__
#define __KNL_RMON_H__

#include "cm_defs.h"
#include "cm_thread.h"
#include "knl_session.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RMON_MONITOR_BUFFER_CLOCK  20

typedef struct st_rmon {
    thread_t thread;
    knl_session_t *session;
    int32 watch_fd;
    int32 epoll_fd;
    spinlock_t mark_mutex;
    bool32 delay_clean_segments;
    bool32 working;
} rmon_t;

void rmon_proc(thread_t *thread);
void rmon_close(knl_session_t *session);
void rmon_clean_alarm(knl_session_t *session);
void rmon_load(knl_session_t *session);
status_t rmon_start(knl_session_t *session);

void job_close(knl_session_t *session);
void synctimer_close(knl_session_t *session);

#ifdef __cplusplus
}
#endif

#endif

