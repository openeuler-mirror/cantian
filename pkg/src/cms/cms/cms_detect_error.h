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
 * cms_detect_error.h
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_detect_error.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMS_DETECT_DISK_ERROR
#define CMS_DETECT_DISK_ERROR

#include "cm_disk.h"
#include "cm_date.h"
#include "cm_debug.h"
#include "cm_thread.h"
#include "cm_malloc.h"
#include "cm_error.h"
#include "cms_gcc.h"
#include "cms_param.h"
#include "cms_syncpoint_inject.h"
#include "cm_file.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CMS_SECOND_TRANS_MICROSECOND 1000000U // The time obtained by calling the cm_now interface is in microseconds.
#define CMS_DETECT_DISK_INTERVAL 1000        // The input parameter to cm_sleep is in milliseconds.
#define CMS_RETRY_DISK_DETECT 200
#define CMS_READ_DISK_TIMEOUT_WAIT 60000 // 60s Read timed out, waiting for CMS itself abort.
#define CMS_STOP_RERUN_SCRIPT_TIMEOUT 5000
#define CMS_WAIT_STOP_RERUN_ENABLE 2000 // It takes 2 seconds for the stop pull command to take effect.
#define CMS_DETECT_DISK_ERR_TIMEOUT 10000000
#define CMS_DISK_IO_CHECK_PERIOD (1 * MICROSECS_PER_MIN) // The period of slow disk IO checking.
#define CMS_DISK_IO_SLOW_THRESHOLD 0.5  // Be regared as slow if the slow I/O exceeds 50 percent of the overall I/O in one period.

void cms_judge_disk_error_entry(thread_t *thread);
void cms_detect_disk_error_entry(thread_t *thread);
void cms_kill_all_res(void);
void cms_kill_self(void);
status_t cms_daemon_stop_pull(void);
status_t cms_judge_disk_error(void);
status_t cms_detect_disk(void);
status_t cms_detect_file_stat(const char *read_file, disk_handle_t* gcc_handle);
status_t cms_exec_stop_rerun_script(const char *script, const char *arg, uint32 timeout_ms, status_t *result);
status_t cms_exec_script_inner(cms_res_t res, char *type);
status_t cms_get_script_from_memory(cms_res_t *res);
void cms_try_init_exit_num(void);
void cms_refresh_last_check_time(date_t start_time);
void cms_judge_disk_io_stat(void);
status_t cms_open_detect_file(void);

typedef struct st_cms_disk_check_t {
    date_t last_check_time;
    bool32 read_timeout;
} cms_disk_check_t;

extern cms_disk_check_t g_check_disk;

typedef struct st_cms_disk_check_stat_t {
    date_t period_start_time;
    uint64 total_count;
    uint64 slow_count;
    date_t last_check_time;
    bool32 disk_io_slow;
    uint64 total_slow_io_time_ms;
    uint64 avg_ms;
    uint64 max_ms;
} cms_disk_check_stat_t;

extern cms_disk_check_stat_t g_local_disk_stat;

#ifdef __cplusplus
}
#endif
// CMS_DETECT_DISK_ERROR
#endif