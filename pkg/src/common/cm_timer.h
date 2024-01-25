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
 * cm_timer.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_timer.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_TIMER_H__
#define __CM_TIMER_H__

#include "cm_defs.h"
#include "cm_thread.h"
#include "cm_date.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CM_HOST_TIMEZONE (g_timer()->host_tz_offset)

typedef enum en_timer_status {
    TIMER_STATUS_RUNNING,
    TIMER_STATUS_PAUSING,
    TIMER_STATUS_PAUSED,
} timer_status_t;

typedef struct st_ct_timer {
    volatile date_detail_t detail;  // detail of date, yyyy-mm-dd hh24:mi:ss
    volatile date_t now;
    volatile date_t monotonic_now;  // not affected by user change
    volatile date_t today;          // the day with time 00:00:00
    volatile uint32 systime;        // seconds between timer started and now
    volatile int32 tz;              // time zone (min)
    volatile int64 host_tz_offset;  // host timezone offset (us)
    atomic_t now_scn;
    atomic_t sys_scn_valid;
    atomic_t *system_scn;
    time_t db_init_time;
    thread_t thread;
    timer_status_t status;
} ct_timer_t;

status_t cm_start_timer(ct_timer_t *input_timer);
void cm_close_timer(ct_timer_t *input_timer);
ct_timer_t *g_timer(void);
date_t cm_get_sync_time(void);
void cm_set_sync_time(date_t time);
void cm_pause_timer(ct_timer_t *input_timer);
void cm_resume_timer(ct_timer_t *input_timer);

#ifdef __cplusplus
}
#endif
#endif
