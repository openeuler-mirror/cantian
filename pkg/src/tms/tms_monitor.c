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
 * tms_monitor.c
 *
 *
 * IDENTIFICATION
 * src/tms/tms_monitor.c
 *
 * -------------------------------------------------------------------------
 */
#include <unistd.h>
#include <stdlib.h>
#include "tms_module.h"
#include "cm_timer.h"
#include "cm_spinlock.h"
#include "cm_thread.h"
#include "cm_defs.h"
#include "cm_error.h"
#include "tms_monitor.h"

#define TMS_MONITOR_CHECK_TIME 500
#define TMS_MONITOR_PRINT_POW 1
#define TMS_NULL_DWORD 0
#define TMS_MONITOR_HZ 1000000

tms_param_t g_tms_param;
tms_param_t *g_tms = &g_tms_param;

void tms_date2str(date_t date, char* str, uint32 max_size)
{
    text_t date_text = {str, 0};
    text_t format = {"YYYY-MM-DD HH24:MI:SS.FF", 24};
    uint32 precision = 3;
    cm_date2text_ex(date, &format, precision, &date_text, max_size - 1);
    str[max_size - 1] = 0;
}

tms_monitor_handle tms_reg_monitor_event(const char *monitor_event_name, tms_monitor_cb_fn_t monitor_cb,
    uint32 monitor_step)
{
    uint32 index;
    tms_monitor_t *monitor = (tms_monitor_t *)malloc(sizeof(tms_monitor_t));
    if (monitor == NULL) {
        CT_LOG_RUN_ERR("Monitor event mem alloc failed (%s).", monitor_event_name);
        return NULL;
    }

    cm_spin_lock(&g_tms->monitor_lock, NULL);
    int32 ret = strcpy_sp(monitor->monitor_name, sizeof(monitor->monitor_name), monitor_event_name);
    if ((g_tms->monitor_event_num >= TMS_MONITOR_EVENT_NUM) || (ret != EOK)) {
        CT_LOG_RUN_ERR("Params Err monitor_event_num(%u), monitor_event_name(%s), ret(%d).", g_tms->monitor_event_num,
            monitor_event_name, ret);
        cm_spin_unlock(&g_tms->monitor_lock);
        CM_FREE_PTR(monitor);
        return NULL;
    }

    index = g_tms->monitor_event_num;
    g_tms->monitor_event[index] = monitor;
    cm_spin_unlock(&g_tms->monitor_lock);

    monitor->monitor_enable_flag = CT_TRUE;
    monitor->thread_tid = TMS_NULL_DWORD;
    monitor->monitor_start_time = cm_now();
    monitor->monitor_end_time = cm_now();
    monitor->monitor_thread_run_nums = 0;
    monitor->last_run_j = cm_now();
    monitor->last_trig_j = cm_now();
    monitor->monitor_print_num = monitor_step;
    monitor->monitor_step = monitor_step;
    monitor->monitor_cb = monitor_cb;
    g_tms->monitor_event_num++;
    CT_LOG_RUN_INF("Reg mon(%p) name(%s)", monitor, monitor->monitor_name);

    return monitor;
}

void tms_unreg_monitor_event(tms_monitor_handle monitor_handler)
{
    cm_spin_lock(&g_tms->monitor_lock, NULL);
    tms_monitor_t *monitor_event = (tms_monitor_t *)monitor_handler;
    if (monitor_handler != NULL) {
        monitor_event->monitor_enable_flag = CT_FALSE;
        CT_LOG_RUN_INF("Unreg mon(%p) name(%s)", monitor_event, monitor_event->monitor_name);
    }
    cm_spin_unlock(&g_tms->monitor_lock);
    return;
}

void tms_del_disable_monitor_event(void)
{
    uint32 index = 0;
    uint32 left = 0;

    cm_spin_lock(&g_tms->monitor_lock, NULL);
    uint32 event_num = g_tms->monitor_event_num;

    while (index < event_num) {
        if (!g_tms->monitor_event[index]->monitor_enable_flag) {
            CT_LOG_RUN_INF("Del mon(%p) name(%s)", g_tms->monitor_event[index],
                g_tms->monitor_event[index]->monitor_name);
            CM_FREE_PTR(g_tms->monitor_event[index]);
            g_tms->monitor_event[index] = NULL;
            g_tms->monitor_event_num--;
        } else {
            if (left < index) {
                g_tms->monitor_event[left] = g_tms->monitor_event[index];
                g_tms->monitor_event[index] = NULL;
            }
            left++;
        }
        index++;
    }

    cm_spin_unlock(&g_tms->monitor_lock);

    return;
}

bool32 tms_monitor_dump_stack_limit(uint64 limit_seconds, uint32 limit_count)
{
    static uint64 last_jiffies = 0;
    static uint32 call_count = 0;
    
    uint64 now_jiffies = cm_now();
    if ((last_jiffies == 0) || now_jiffies > last_jiffies + limit_seconds * TMS_MONITOR_HZ) {
        last_jiffies = now_jiffies;
        call_count = 0;
    }

    return (++call_count) > limit_count ? CT_TRUE : CT_FALSE;
}

void tms_monitor_dump_thread_stack(tms_monitor_t *monitor)
{
    if (tms_monitor_dump_stack_limit(60, 3)) { // 避免冲日志，60秒内最多可以打印3次
        return;
    }

    if (tms_dump_thread_stack_sig(getpid(), monitor->thread_tid) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Monitor event(%s) pid(%u) tid(%u), dump kernel stack failed.",
            monitor->monitor_name, getpid(), monitor->thread_tid);
    }
}

void tms_monitor_cb(tms_monitor_handle monitor_handler)
{
    char now_str[32], start_str[32], end_str[32];
    tms_monitor_t *monitor_event = (tms_monitor_t *)monitor_handler;

    if (monitor_event->thread_tid == TMS_NULL_DWORD) {
        return;
    }

    tms_monitor_dump_thread_stack(monitor_event);

    tms_date2str(cm_now(), now_str, sizeof(now_str));
    tms_date2str(monitor_event->monitor_start_time, start_str, sizeof(start_str));
    tms_date2str(monitor_event->monitor_end_time, end_str, sizeof(end_str));
    CT_LOG_RUN_ERR(
        "Monitor event(%s) pid(%u), tid(%u) running too long "
        "jiffies(%s - %s = %llu), end_time is %s.",
        monitor_event->monitor_name, getpid(), monitor_event->thread_tid, now_str,
        start_str, cm_now() - monitor_event->monitor_start_time, end_str);
}

void tms_update_monitor_start_time(tms_monitor_handle monitor_handler)
{
    tms_monitor_t *monitor_event = (tms_monitor_t *)monitor_handler;
    if (monitor_handler != NULL) {
        monitor_event->monitor_start_time = cm_now();
        monitor_event->monitor_thread_run_nums++;

        if (monitor_event->thread_tid == TMS_NULL_DWORD) {
            monitor_event->thread_tid = cm_get_current_thread_id();
        }
    }

    return;
}

void tms_update_monitor_end_time(tms_monitor_handle monitor_handler)
{
    tms_monitor_t *monitor_event = (tms_monitor_t *)monitor_handler;
    if (monitor_handler != NULL) {
        monitor_event->monitor_end_time = cm_now();
    }

    return;
}

void tms_monitor_trig_calltrace(tms_monitor_t *monitor)
{
    if (monitor->monitor_cb == NULL) {
        return;
    }

    if (cm_now() > monitor->last_trig_j + 7 * TMS_MONITOR_HZ) { // 7s内不触发两次信号
        monitor->monitor_cb(monitor);
        monitor->last_trig_j = cm_now();
    }
}

void tms_check_monitor_time_result(void)
{
    uint32 index;
    bool32 monitor_disable = CT_FALSE;

    cm_spin_lock(&g_tms->monitor_lock, NULL);
    uint32 event_num = g_tms->monitor_event_num;

    for (index = 0; index < event_num; index++) {
        tms_monitor_t *monitor = g_tms->monitor_event[index];
        if (monitor == NULL) {
            break;
        }

        if (monitor->monitor_enable_flag == CT_FALSE) {
            monitor_disable = CT_TRUE;
            continue;
        }

        if (monitor->monitor_start_time != monitor->last_run_j) {
            monitor->last_run_j = monitor->monitor_start_time;
            monitor->monitor_print_num =
                (monitor->monitor_step == 0) ? TMS_MONITOR_DEFAULT_STEP : monitor->monitor_step;
            continue;
        }

        uint64 time_step = (uint64)monitor->monitor_print_num * TMS_MONITOR_HZ;
        if (monitor->monitor_is_running && cm_now() > monitor->monitor_start_time + time_step) {
            tms_monitor_trig_calltrace(monitor);
            monitor->monitor_print_num = monitor->monitor_print_num << TMS_MONITOR_PRINT_POW;
        }
    }
    cm_spin_unlock(&g_tms->monitor_lock);

    if (monitor_disable) {
        tms_del_disable_monitor_event();
    }

    return;
}

void tms_check_monitor_result(thread_t* thread)
{
    uint64 start_time = cm_now();
    while (!thread->closed) {
        if (cm_now()> start_time + 2 * TMS_MONITOR_HZ) { // warning if time out 2s
            CT_LOG_RUN_WAR("Monitor event thread running too long jiffies(%llu - %llu = %llu).",
                cm_now(), start_time, cm_now() - start_time);
        }
        start_time = cm_now();

        tms_check_monitor_time_result();
        cm_sleep(g_tms->monitor_check_ms); // sleep 500ms
    }
}

tms_monitor_handle tms_sig_event_reg(const char *monitor_event_name, tms_monitor_cb_fn_t monitor_cb,
    uint32 monitor_step)
{
    if (tms_sigcap_reg_proc(SIGTASKTRACK) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[tms]: Failed to reg sigcap.");
        return NULL;
    }

    tms_monitor_handle monitor_handler =
        tms_reg_monitor_event(monitor_event_name, monitor_cb, monitor_step);

    return monitor_handler;
}

status_t tms_monitor_init(void)
{
    CT_INIT_SPIN_LOCK(g_tms->monitor_lock);
    if (cm_create_thread(tms_check_monitor_result, CT_DFLT_THREAD_STACK_SIZE, NULL,
        &g_tms->monitor_thread) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("create tms monitor thread failed.");
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("create tms monitor thread succeed.");

    return CT_SUCCESS;
}
