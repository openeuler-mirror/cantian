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
 * cms_log.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_log.c
 *
 * -------------------------------------------------------------------------
 */
#include "cms_log.h"
#include "cms_detect_error.h"

void cms_log_io_time_check(date_t log_inner_start_time)
{
    date_t io_time = cm_now() - log_inner_start_time;
    g_local_disk_stat.total_count++;
    if (io_time >= CSM_DETECT_LOG_IO_SLOW_TIMEOUT) {
        g_local_disk_stat.slow_count++;
        g_local_disk_stat.total_slow_io_time_ms += io_time / MICROSECS_PER_MILLISEC;
        g_local_disk_stat.max_ms = MAX(g_local_disk_stat.max_ms, io_time / MICROSECS_PER_MILLISEC);
    }
}