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
 * cms_detect_error.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_detect_error.c
 *
 * -------------------------------------------------------------------------
 */
#include "cms_detect_error.h"
#include "cms_stat.h"
#include "cms_log.h"

cms_disk_check_t g_check_disk = { 0 };

cms_disk_check_stat_t g_local_disk_stat = { 0 };

status_t cms_detect_disk(void)
{
    if (g_cms_param->gcc_type == CMS_DEV_TYPE_FILE) {
        for (int i = 0; i < g_cms_param->wait_detect_file_num; i++) {
            if (cms_detect_file_stat(g_cms_param->wait_detect_file[i]) != GS_SUCCESS) {
                CMS_LOG_ERR("cms detect file %s failed.", g_cms_param->wait_detect_file[i]);
                return GS_ERROR;
            }
        }
    } else if (g_cms_param->gcc_type == CMS_DEV_TYPE_SD) {
        if (cms_detect_file_stat(g_cms_param->gcc_home) != GS_SUCCESS) {
            CMS_LOG_ERR("cms detect file failed, file is %s.", g_cms_param->gcc_home);
            return GS_ERROR;
        }
    } else {
        CMS_LOG_ERR("invalid device type:%d", g_cms_param->gcc_type);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t cms_get_script_from_memory(cms_res_t *res)
{
    uint32 res_id = 0;
    GS_RETURN_IFERR(cms_get_res_id_by_name("db", &res_id));
    GS_RETURN_IFERR(cms_get_res_by_id(res_id, res));
    return GS_SUCCESS;
}

status_t cms_exec_script_inner(cms_res_t res, char *type)
{
    status_t result = GS_ERROR;
    status_t ret = cms_exec_res_script(res.script, type, res.check_timeout, &result);
    if (ret == GS_SUCCESS) {
        if (result == GS_SUCCESS) {
            CMS_LOG_DEBUG_INF("script executed successfully, script=%s, type=%s", res.script, type);
            return GS_SUCCESS;
        } else {
            CMS_LOG_DEBUG_ERR("script executed failed, script=%s, type=%s", res.script, type);
            return GS_ERROR;
        }
    } else {
        CMS_LOG_ERR("exec cms_exec_res_script func failed.");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

void cms_try_init_exit_num(void)
{
    cms_res_t res = { 0 };
    if (cms_get_script_from_memory(&res) != GS_SUCCESS) {
        CMS_LOG_ERR("cms get script from memory failed.");
    } else {
        if (cm_file_exist(g_cms_param->exit_num_file) == GS_TRUE) {
            if (cms_exec_script_inner(res, "-init_exit_file") != GS_SUCCESS) {
                CMS_LOG_DEBUG_ERR("cms init exit file failed.");
            }
        }
    }
}

void cms_refresh_last_check_time(date_t start_time)
{
    date_t end_time = cm_now();
    g_check_disk.last_check_time = end_time;
    if (end_time - start_time > CMS_DETECT_DISK_ERR_TIMEOUT) {
        CMS_LOG_WAR("cms read disk spend %lld(ms)", (end_time - start_time) / CMS_DETECT_DISK_INTERVAL);
    }
}

status_t cms_detect_file_stat(const char *read_file)
{
    disk_handle_t gcc_handle = -1;
    cms_gcc_t *new_gcc = (cms_gcc_t *)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_gcc_t));
    if (new_gcc == NULL) {
        CMS_LOG_ERR("cms allocate memory failed.");
        return GS_ERROR;
    }
    date_t start_time = cm_now();
    CMS_LOG_DEBUG_INF("cms detect file name is %s", read_file);
    if (cm_open_disk(read_file, &gcc_handle) != GS_SUCCESS) {
        CMS_LOG_ERR("cms open disk failed.");
        CM_FREE_PTR(new_gcc);
        return GS_ERROR;
    }
    if (cm_read_disk(gcc_handle, 0, (char *)new_gcc, sizeof(cms_gcc_t)) != GS_SUCCESS) {
        CMS_LOG_ERR("cms read disk failed.");
        cm_close_disk(gcc_handle);
        CM_FREE_PTR(new_gcc);
        return GS_ERROR;
    }
    date_t end_time = cm_now();
    cm_close_disk(gcc_handle);
    CM_FREE_PTR(new_gcc);
    CMS_SYNC_POINT_GLOBAL_START(CMS_MEMORY_LEAK, NULL, 0);
    CMS_SYNC_POINT_GLOBAL_END;
    cms_refresh_last_check_time(start_time);
    if (end_time - start_time > (int64)g_cms_param->detect_disk_timeout * CMS_SECOND_TRANS_MICROSECOND) {
        CMS_LOG_ERR("cms read disk timeout, spend time is %lld.", (end_time - start_time));
        g_check_disk.read_timeout = GS_TRUE;
        return GS_ERROR;
    }
    // Synchronously update the heartbeat to ensure that the process exits when the disk heartbeat expires.
    if (cms_update_disk_hb() == GS_SUCCESS) {
        cms_refresh_last_check_time(start_time);
    }
    cms_try_init_exit_num();
    return GS_SUCCESS;
}

void cms_kill_all_res(void)
{
    for (uint32 res_id = 0; res_id < CMS_MAX_RESOURCE_COUNT; res_id++) {
        if (cms_res_is_invalid(res_id)) {
            continue;
        }
        status_t ret = cms_res_stop(res_id, GS_FALSE);
        if (ret == GS_SUCCESS) {
            CMS_LOG_INF("cms kill res %u succeed.", res_id);
        } else if (ret == GS_TIMEDOUT) {
            CMS_LOG_ERR("cms kill res %u timeout, check the process status.", res_id);
        } else {
            CMS_LOG_ERR("cms kill res %u failed, check the process status.", res_id);
        }
    }
}

status_t cms_judge_disk_error(void)
{
    date_t time_now = cm_now();
    if ((time_now - g_check_disk.last_check_time) >
        ((int64)g_cms_param->detect_disk_timeout * CMS_SECOND_TRANS_MICROSECOND) ||
        g_check_disk.read_timeout == GS_TRUE) {
        CMS_LOG_ERR("cms detect disk problem, latest check time is %lld, time now is %lld, read timeout stat is %u.",
            g_check_disk.last_check_time, time_now, g_check_disk.read_timeout);
        if (cms_daemon_stop_pull() != GS_SUCCESS) {
            CMS_LOG_ERR("stop cms daemon process failed.");
        }
        cms_kill_all_res();
        cms_kill_self();
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

void cms_kill_self(void)
{
    CM_ABORT_REASONABLE(0, "[CMS] ABORT INFO: cms check disk error.");
}

status_t cms_daemon_stop_pull(void)
{
    status_t result = GS_ERROR;
    status_t ret = GS_ERROR;
    CMS_LOG_INF("start exec stop rerun script, script=%s", g_cms_param->stop_rerun_script);
    ret = cms_exec_res_script(g_cms_param->stop_rerun_script, "disable", CMS_STOP_RERUN_SCRIPT_TIMEOUT, &result);
    if (ret == GS_SUCCESS) {
        if (result == GS_SUCCESS) {
            CMS_LOG_INF("exec stop rerun script succeed, script=%s", g_cms_param->stop_rerun_script);
        } else {
            CMS_LOG_ERR("exec stop rerun script succeed, but result is failed, script=%s",
                g_cms_param->stop_rerun_script);
            return GS_ERROR;
        }
    } else {
        CMS_LOG_ERR("exec stop rerun script failed, script=%s", g_cms_param->stop_rerun_script);
    }
    CMS_LOG_INF("end exec stop rerun script, script=%s, ret=%d, result=%d", g_cms_param->stop_rerun_script, ret,
        result);
    return ret;
}

void cms_detect_disk_error_entry(thread_t *thread)
{
    while (!thread->closed) {
        timeval_t tv_begin;
        cantian_record_io_stat_begin(CMS_IO_RECORD_DETECT_DISK, &tv_begin);
        if (cms_detect_disk() != GS_SUCCESS) {
            CMS_LOG_ERR("cms detect disk failed, retry after one second.");
            cantian_record_io_stat_end(CMS_IO_RECORD_DETECT_DISK, &tv_begin, IO_STAT_FAILED);
        } else {
            cantian_record_io_stat_end(CMS_IO_RECORD_DETECT_DISK, &tv_begin, IO_STAT_SUCCESS);
        }
        cm_sleep(CMS_DETECT_DISK_INTERVAL);
    }
}

void cms_judge_disk_error_entry(thread_t *thread)
{
    g_check_disk.last_check_time = cm_now();
    g_check_disk.read_timeout = GS_FALSE;
    while (!thread->closed) {
        if (cms_judge_disk_error() != GS_SUCCESS) {
            CMS_LOG_ERR("cms detect disk failed, all res on the node are about to be offline.");
        }
        cms_judge_disk_io_stat();
        cm_sleep(CMS_DETECT_DISK_INTERVAL);
    }
}

void cms_judge_disk_io_stat(void)
{
    // check the start time, init or reset if last period ended
    date_t now = cm_now();
    if (g_local_disk_stat.period_start_time == 0 ||
        now - g_local_disk_stat.period_start_time > CMS_DISK_IO_CHECK_PERIOD) {
        g_local_disk_stat.period_start_time = now;
        g_local_disk_stat.slow_count = 0;
        g_local_disk_stat.disk_io_slow = GS_FALSE;
        g_local_disk_stat.total_slow_io_time_ms = 0;
        g_local_disk_stat.avg_ms = 0;
        g_local_disk_stat.max_ms = 0;
        g_local_disk_stat.total_count = 0;
    }
    g_check_disk.last_check_time = now;
    // skip if it has been slow in current period
    if (g_local_disk_stat.disk_io_slow) {
        return;
    }
    // check if disk io is regarded as being slow
    if (g_local_disk_stat.slow_count > g_local_disk_stat.total_count * CMS_DISK_IO_SLOW_THRESHOLD) {
        g_local_disk_stat.disk_io_slow = GS_TRUE;
        g_local_disk_stat.avg_ms = g_local_disk_stat.total_slow_io_time_ms / g_local_disk_stat.slow_count;
        CMS_LOG_ERR("cms disk io slow. slow_count %llu, total_count %llu, avg_ms %llu, max_ms %llu", g_local_disk_stat.slow_count, g_local_disk_stat.total_count, g_local_disk_stat.avg_ms, g_local_disk_stat.max_ms);
    }
}