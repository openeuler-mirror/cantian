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
 * tms_monitor.h
 *
 *
 * IDENTIFICATION
 * src/tms/tms_monitor.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef TMS_MONITOR_H
#define TMS_MONITOR_H

#include <stdint.h>
#include "cm_defs.h"
#include "tms_sig_calltrace.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TMS_MONITOR_DEFAULT_STEP 30
#define TMS_MONITOR_DEFAULT_STEP_DOUBLE (2 * TMS_MONITOR_DEFAULT_STEP)
#define TMS_MONITOR_NAME_MAX_LEN 64
#define TMS_MONITOR_EVENT_NUM 1024

typedef void *tms_monitor_handle;

typedef void (*tms_monitor_cb_fn_t)(tms_monitor_handle monitor);
typedef struct st_tms_monitor {
    char monitor_name[TMS_MONITOR_NAME_MAX_LEN];
    bool32 monitor_enable_flag;
    bool32 monitor_is_running;
    uint32 thread_tid;
    uint64 monitor_start_time;
    uint64 monitor_end_time;
    uint64 monitor_thread_run_nums;
    uint64 last_run_j;
    uint64 last_trig_j;
    uint32 monitor_print_num;
    uint32 monitor_step;
    tms_monitor_cb_fn_t monitor_cb;
} tms_monitor_t;

typedef struct st_tms_param {
    uint32 monitor_event_num;
    uint32 monitor_check_ms;
    thread_t monitor_thread;
    spinlock_t monitor_lock;
    tms_monitor_t *monitor_event[TMS_MONITOR_EVENT_NUM];
} tms_param_t;

void tms_unreg_monitor_event(tms_monitor_handle monitor_handler);

void tms_monitor_cb(tms_monitor_handle monitor_handler);

void tms_update_monitor_start_time(tms_monitor_handle monitor_handler);

void tms_update_monitor_end_time(tms_monitor_handle monitor_handler);

tms_monitor_handle tms_sig_event_reg(const char *monitor_event_name, tms_monitor_cb_fn_t monitor_cb,
    uint32 monitor_step);

status_t tms_monitor_init(void);

#ifdef __cplusplus
}
#endif

#endif