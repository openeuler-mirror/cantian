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
 * cm_timer.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_timer.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_common_module.h"
#include "cm_timer.h"
#include "cm_log.h"

#define DAY_USECS (uint64)86400000000
#define TIMER_INTERVAL  2  // ms
#define MAX_INTERVAL    60 // sec
static ct_timer_t timer;
static date_t sync_time;

ct_timer_t *g_timer(void)
{
    return &timer;
}

date_t cm_get_sync_time(void)
{
    return sync_time;
}

void cm_set_sync_time(date_t time)
{
    sync_time = time;
}

static void timer_set_now_scn(ct_timer_t *timer_temp, date_t interval_us)
{
    if (!cm_atomic_get(&timer_temp->sys_scn_valid)) {
        return;
    }

    if (timer_temp->system_scn == NULL) {
        return;
    }

    atomic_t sys_scn = cm_atomic_get(timer_temp->system_scn);
    if (CT_INVALID_SCN(sys_scn)) {
        return;
    }

    atomic_t *now_scn = &timer_temp->now_scn;
    if ((*now_scn) < sys_scn) {
        cm_atomic_set(now_scn, sys_scn);
        return;
    }

    timeval_t old_time;
    timeval_t new_time;
    CT_SCN_TO_TIME(*now_scn, &old_time, timer_temp->db_init_time);
    cm_date2timeval(timer_temp->now, &new_time);

    // set scn by current timestamp
    int64 diff_sec = (int64)new_time.tv_sec - (int64)old_time.tv_sec;
    int64 diff_usec = (int64)new_time.tv_usec - (int64)old_time.tv_usec;
    if (diff_sec >= 0 && diff_usec >= 0) {
        diff_sec += diff_usec / MICROSECS_PER_SECOND;
    }
    if (diff_sec >= 0 && diff_sec < MAX_INTERVAL) {
        uint64 time_scn = CT_TIME_TO_SCN(&new_time, timer_temp->db_init_time);
        cm_atomic_set(now_scn, time_scn);
        return;
    }
    date_t interval = interval_us;
    if (interval < 0 || interval / MICROSECS_PER_SECOND >= MAX_INTERVAL) {
        interval = TIMER_INTERVAL * MICROSECS_PER_MILLISEC;
    }

    uint64 usec = (uint64)old_time.tv_usec + interval;
    old_time.tv_sec += usec / MICROSECS_PER_SECOND;
    old_time.tv_usec = usec % MICROSECS_PER_SECOND;
    uint64 interval_scn = CT_TIME_TO_SCN(&old_time, timer_temp->db_init_time);
    cm_atomic_set(now_scn, interval_scn);
}

static void timer_proc(thread_t *thread)
{
    date_t start_time;
    ct_timer_t *timer_temp = (ct_timer_t *)thread->argument;
    int16 tz_min;

    start_time = cm_now();
    sync_time = start_time;
    timer_temp->status = TIMER_STATUS_RUNNING;
    cm_set_thread_name("timer");

    while (!thread->closed) {
        // In order to solve the thread deadlock problem caused by local_time_r function when fork child process.
        if (timer_temp->status == TIMER_STATUS_PAUSING) {
            timer_temp->status = TIMER_STATUS_PAUSED;
        }
        if (timer_temp->status == TIMER_STATUS_PAUSED) {
            cm_sleep(1);
            sync_time += MICROSECS_PER_MILLISEC;
            continue;
        }

        date_t old_time = timer_temp->now;
        cm_now_detail((date_detail_t *)&timer_temp->detail);
        timer_temp->now = cm_encode_date((const date_detail_t *)&timer_temp->detail);
        timer_temp->monotonic_now = cm_monotonic_now();
        timer_temp->today = (timer_temp->now / DAY_USECS) * DAY_USECS;
        timer_temp->systime = (uint32)((timer_temp->now - start_time) / MICROSECS_PER_SECOND);

        // flush timezone
        tz_min = cm_get_local_tzoffset();
        timer_temp->tz = tz_min;
        timer_temp->host_tz_offset = tz_min * (int)SECONDS_PER_MIN * MICROSECS_PER_SECOND_LL;

        timer_set_now_scn(timer_temp, timer_temp->now - old_time);
        cm_sleep(TIMER_INTERVAL);

        // update sync_time
        if (sync_time <= timer_temp->now) {
            sync_time = timer_temp->now;
        } else {
            sync_time += TIMER_INTERVAL * MICROSECS_PER_MILLISEC;
        }
    }

    CT_LOG_RUN_INF("timer thread closed");
}

status_t cm_start_timer(ct_timer_t *input_timer)
{
    cm_now_detail((date_detail_t *)&input_timer->detail);
    input_timer->now = cm_encode_date((const date_detail_t *)&input_timer->detail);
    input_timer->monotonic_now = cm_monotonic_now();
    input_timer->today = (input_timer->now / DAY_USECS) * DAY_USECS;
    input_timer->systime = 0;
    int16 tz_min = cm_get_local_tzoffset();
    input_timer->tz = tz_min;
    input_timer->host_tz_offset = tz_min * (int)SECONDS_PER_MIN * MICROSECS_PER_SECOND_LL;
    input_timer->now_scn = 0;
    input_timer->sys_scn_valid = 0;
    input_timer->system_scn = NULL;
    input_timer->db_init_time = 0;
    return cm_create_thread(timer_proc, 0, input_timer, &input_timer->thread);
}

void cm_close_timer(ct_timer_t *input_timer)
{
    cm_close_thread(&input_timer->thread);
}

void cm_pause_timer(ct_timer_t *input_timer)
{
    input_timer->status = TIMER_STATUS_PAUSING;
    while (input_timer->status != TIMER_STATUS_PAUSED && !input_timer->thread.closed) {
        cm_sleep(3); // waitting 3s for changing status
    }
}

void cm_resume_timer(ct_timer_t *input_timer)
{
    input_timer->status = TIMER_STATUS_RUNNING;
}
