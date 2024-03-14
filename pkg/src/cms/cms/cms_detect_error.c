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
 * cms_detect_error.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_detect_error.c
 *
 * -------------------------------------------------------------------------
 */
#include "cms_log_module.h"
#include "cms_detect_error.h"
#include "cms_stat.h"
#include "cms_log.h"

cms_disk_check_t g_check_disk = { 0 };

cms_disk_check_stat_t g_local_disk_stat = { 0 };
disk_handle_t g_detect_file_fd[CMS_MAX_DISK_DETECT_FILE];
object_id_t g_detect_dbs_file; // only used in dbs type

status_t cms_detect_disk(void)
{
    if ((g_cms_param->gcc_type == CMS_DEV_TYPE_FILE) || (g_cms_param->gcc_type == CMS_DEV_TYPE_NFS)) {
        for (int i = 0; i < g_cms_param->wait_detect_file_num; i++) {
            if (cms_detect_file_stat(g_cms_param->wait_detect_file[i], &g_detect_file_fd[i]) != CT_SUCCESS) {
                CMS_LOG_ERR("cms detect file %s failed.", g_cms_param->wait_detect_file[i]);
                return CT_ERROR;
            }
        }
    } else if (g_cms_param->gcc_type == CMS_DEV_TYPE_SD) {
        if (cms_detect_file_stat(g_cms_param->gcc_home, &g_detect_file_fd[0]) != CT_SUCCESS) {
            CMS_LOG_ERR("cms detect file failed, file is %s.", g_cms_param->gcc_home);
            return CT_ERROR;
        }
    } else if (g_cms_param->gcc_type == CMS_DEV_TYPE_DBS) {
        char file_name[CMS_MAX_NAME_LEN] = {0};
        for (int i = 0; i < g_cms_param->wait_detect_file_num; i++) {
            if (cm_get_path_file_name(g_cms_param->wait_detect_file[i], file_name, CMS_MAX_NAME_LEN) != CT_SUCCESS) {
                CMS_LOG_ERR("get path last file name failed, file %s.", g_cms_param->wait_detect_file[i]);
                return CT_ERROR;
            }
            if (cms_detect_dbs_file_stat(file_name, &g_detect_dbs_file) != CT_SUCCESS) {
                CMS_LOG_ERR("cms detect file %s failed.", g_cms_param->wait_detect_file[i]);
                return CT_ERROR;
            }
        }
    } else {
        CMS_LOG_ERR("invalid device type:%d", g_cms_param->gcc_type);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cms_get_script_from_memory(cms_res_t *res)
{
    uint32 res_id = 0;
    CT_RETURN_IFERR(cms_get_res_id_by_name("db", &res_id));
    CT_RETURN_IFERR(cms_get_res_by_id(res_id, res));
    return CT_SUCCESS;
}

status_t cms_exec_script_inner(cms_res_t res, char *type)
{
    status_t result = CT_ERROR;
    status_t ret = cms_exec_res_script(res.script, type, res.check_timeout, &result);
    if (ret == CT_SUCCESS) {
        if (result == CT_SUCCESS) {
            CMS_LOG_DEBUG_INF("script executed successfully, script=%s, type=%s", res.script, type);
            return CT_SUCCESS;
        } else {
            CMS_LOG_DEBUG_ERR("script executed failed, script=%s, type=%s", res.script, type);
            return CT_ERROR;
        }
    } else {
        CMS_LOG_ERR("exec cms_exec_res_script func failed.");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void cms_try_init_exit_num(void)
{
    cms_res_t res = { 0 };
    if (cms_get_script_from_memory(&res) != CT_SUCCESS) {
        CMS_LOG_ERR("cms get script from memory failed.");
    } else {
        if (cm_file_exist(g_cms_param->exit_num_file) == CT_TRUE) {
            if (cms_exec_script_inner(res, "-init_exit_file") != CT_SUCCESS) {
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

status_t cms_detect_file_stat(const char *read_file, disk_handle_t* gcc_handle)
{
    status_t ret = CT_SUCCESS;
    cms_gcc_t *new_gcc = (cms_gcc_t *)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_gcc_t));
    if (new_gcc == NULL) {
        CMS_LOG_ERR("cms allocate memory failed.");
        return CT_ERROR;
    }
    date_t start_time = cm_now();
    CMS_LOG_DEBUG_INF("cms detect file name is %s", read_file);
    // only first time check should be write.
    int64 file_size = cm_seek_file(*gcc_handle, 0, SEEK_END);
    if (file_size == 0) {
        ret = cm_write_file(*gcc_handle, new_gcc, sizeof(cms_gcc_t));
        if (ret != CT_SUCCESS) {
            CMS_LOG_ERR("write file failed, file %s, ret %d", read_file, ret);
            CM_FREE_PTR(new_gcc);
            return ret;
        }
        CMS_LOG_INF("cms detect file %s fd %d content fill.", read_file, *gcc_handle);
    }

    int64 seek_offset = cm_seek_file(*gcc_handle, CMS_ERROR_DETECT_START, SEEK_SET);
    if (seek_offset != CMS_ERROR_DETECT_START) {
        CMS_LOG_ERR("file seek failed:%s:%d,%d:%s", read_file, CMS_ERROR_DETECT_START, errno,
            strerror(errno));
        CM_FREE_PTR(new_gcc);
        return CT_ERROR;
    }

    ret = cm_read_file_try_timeout(read_file, gcc_handle, new_gcc, sizeof(cms_gcc_t), CMS_READ_DISK_TIMEOUT_WAIT);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("cms read file %s failed.", read_file);
        CM_FREE_PTR(new_gcc);
        return CT_ERROR;
    }
    
    date_t end_time = cm_now();
    CM_FREE_PTR(new_gcc);
    CMS_SYNC_POINT_GLOBAL_START(CMS_MEMORY_LEAK, NULL, 0);
    CMS_SYNC_POINT_GLOBAL_END;
    cms_refresh_last_check_time(start_time);
    if (end_time - start_time > (int64)g_cms_param->detect_disk_timeout * CMS_SECOND_TRANS_MICROSECOND) {
        CMS_LOG_ERR("cms read file %s timeout, spend time is %lld.", read_file, (end_time - start_time));
        g_check_disk.read_timeout = CT_TRUE;
        return CT_ERROR;
    }
    // Synchronously update the heartbeat to ensure that the process exits when the disk heartbeat expires.
    if (cms_update_disk_hb() == CT_SUCCESS) {
        cms_refresh_last_check_time(start_time);
    }
    cms_try_init_exit_num();
    return CT_SUCCESS;
}

status_t cms_detect_dbs_file_stat(const char *read_file, object_id_t* handle)
{
    int32 ret = CT_SUCCESS;
    cms_gcc_t *new_gcc = (cms_gcc_t *)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_gcc_t));
    if (new_gcc == NULL) {
        CMS_LOG_ERR("cms allocate memory failed.");
        return CT_ERROR;
    }
    date_t start_time = cm_now();
    CMS_LOG_DEBUG_INF("cms detect dbs file name is %s", read_file);
    // TODO：if this file new create，but file size is zero
    ret = cm_read_dbs_file(handle, (char *)read_file, CMS_ERROR_DETECT_START, new_gcc, sizeof(cms_gcc_t));
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("cms read dbs file %s failed.", read_file);
        CM_FREE_PTR(new_gcc);
        return CT_ERROR;
    }

    date_t end_time = cm_now();
    CM_FREE_PTR(new_gcc);
    CMS_SYNC_POINT_GLOBAL_START(CMS_MEMORY_LEAK, NULL, 0);
    CMS_SYNC_POINT_GLOBAL_END;
    cms_refresh_last_check_time(start_time);
    if (end_time - start_time > (int64)g_cms_param->detect_disk_timeout * CMS_SECOND_TRANS_MICROSECOND) {
        CMS_LOG_ERR("cms read dbs file %s timeout, spend time is %lld.", read_file, (end_time - start_time));
        g_check_disk.read_timeout = CT_TRUE;
        return CT_ERROR;
    }
    // Synchronously update the heartbeat to ensure that the process exits when the disk heartbeat expires.
    if (cms_update_disk_hb() == CT_SUCCESS) {
        cms_refresh_last_check_time(start_time);
    }
    cms_try_init_exit_num();
    return CT_SUCCESS;
}

void cms_kill_all_res(void)
{
    for (uint32 res_id = 0; res_id < CMS_MAX_RESOURCE_COUNT; res_id++) {
        if (cms_res_is_invalid(res_id)) {
            continue;
        }
        status_t ret = cms_res_stop(res_id, CT_FALSE);
        if (ret == CT_SUCCESS) {
            CMS_LOG_INF("cms kill res %u succeed.", res_id);
        } else if (ret == CT_TIMEDOUT) {
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
        (int64)(g_cms_param->detect_disk_timeout * CMS_SECOND_TRANS_MICROSECOND) ||
        g_check_disk.read_timeout == CT_TRUE) {
        CMS_LOG_ERR("cms detect disk problem, latest check time is %lld, time now is %lld, read timeout stat is %u.",
            g_check_disk.last_check_time, time_now, g_check_disk.read_timeout);
        if (cms_daemon_stop_pull() != CT_SUCCESS) {
            CMS_LOG_ERR("stop cms daemon process failed.");
        }
        cms_kill_all_res();
        cms_kill_self();
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void cms_kill_self(void)
{
    CM_ABORT_REASONABLE(0, "[CMS] ABORT INFO: cms check disk error.");
}

status_t cms_daemon_stop_pull(void)
{
    status_t result = CT_ERROR;
    status_t ret = CT_ERROR;
    CMS_LOG_INF("start exec stop rerun script, script=%s", g_cms_param->stop_rerun_script);
    ret = cms_exec_res_script(g_cms_param->stop_rerun_script, "disable", CMS_STOP_RERUN_SCRIPT_TIMEOUT, &result);
    if (ret == CT_SUCCESS) {
        if (result == CT_SUCCESS) {
            CMS_LOG_INF("exec stop rerun script succeed, script=%s", g_cms_param->stop_rerun_script);
        } else {
            CMS_LOG_ERR("exec stop rerun script succeed, but result is failed, script=%s",
                g_cms_param->stop_rerun_script);
            return CT_ERROR;
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
        if (cms_detect_disk() != CT_SUCCESS) {
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
    g_check_disk.read_timeout = CT_FALSE;
    while (!thread->closed) {
        if (cms_judge_disk_error() != CT_SUCCESS) {
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
        g_local_disk_stat.disk_io_slow = CT_FALSE;
        g_local_disk_stat.total_slow_io_time_ms = 0;
        g_local_disk_stat.avg_ms = 0;
        g_local_disk_stat.max_ms = 0;
        g_local_disk_stat.total_count = 0;
    }
    // skip if it has been slow in current period
    if (g_local_disk_stat.disk_io_slow) {
        return;
    }
    // check if disk io is regarded as being slow
    if (g_local_disk_stat.slow_count > g_local_disk_stat.total_count * CMS_DISK_IO_SLOW_THRESHOLD) {
        g_local_disk_stat.disk_io_slow = CT_TRUE;
        g_local_disk_stat.avg_ms = g_local_disk_stat.total_slow_io_time_ms / g_local_disk_stat.slow_count;
        CMS_LOG_ERR("cms disk io slow. slow_count %llu, total_count %llu, avg_ms %llu, max_ms %llu", g_local_disk_stat.slow_count, g_local_disk_stat.total_count, g_local_disk_stat.avg_ms, g_local_disk_stat.max_ms);
    }
}

status_t cms_open_detect_file(void)
{
    status_t ret;
    if ((g_cms_param->gcc_type == CMS_DEV_TYPE_FILE) || (g_cms_param->gcc_type == CMS_DEV_TYPE_NFS)) {
        for (int i = 0; i < g_cms_param->wait_detect_file_num; i++) {
            ret = cm_open_file(g_cms_param->wait_detect_file[i],
                               O_CREAT | O_RDWR | O_NONBLOCK | O_NDELAY | O_BINARY | O_CLOEXEC | O_SYNC | O_DIRECT,
                               &g_detect_file_fd[i]);
            if (ret != CT_SUCCESS) {
                CMS_LOG_ERR("open file failed, file %s, ret %d", g_cms_param->wait_detect_file[i], ret);
                return ret;
            }
        }
    } else if (g_cms_param->gcc_type == CMS_DEV_TYPE_SD) {
        ret = cm_open_file(g_cms_param->gcc_home, O_RDWR | O_BINARY | O_CLOEXEC | O_SYNC | O_DIRECT, &g_detect_file_fd[0]);
        if (ret != CT_SUCCESS) {
            CMS_LOG_ERR("open file failed, file %s, ret %d", g_cms_param->gcc_home, ret);
            return ret;
        }
    } else if (g_cms_param->gcc_type == CMS_DEV_TYPE_DBS) {
        char file_name[CMS_MAX_NAME_LEN] = {0};
        object_id_t file_handle = {0};
        ret = cm_get_dbs_last_dir_handle(g_cms_param->gcc_dir, &g_detect_dbs_file);
        if (ret != CT_SUCCESS) {
            CMS_LOG_ERR("open dbs gcc dir failed, path %s, ret %d", g_cms_param->gcc_dir, ret);
            return ret;
        }
        for (int i = 0; i < g_cms_param->wait_detect_file_num; i++) {
            ret = cm_get_path_file_name(g_cms_param->wait_detect_file[i], file_name, CMS_MAX_NAME_LEN);
            if (ret != CT_SUCCESS) {
                CMS_LOG_ERR("get path last file name failed, file %s, ret %d", g_cms_param->wait_detect_file[i], ret);
                return ret;
            }
            ret = cm_get_dbs_file_handle(&g_detect_dbs_file, file_name, &file_handle);
            if (ret != CT_SUCCESS) {
                CMS_LOG_ERR("open dbs file %s failed %d", file_name, ret);
                return ret;
            }
        }
    } else {
        CMS_LOG_ERR("invalid device type:%d", g_cms_param->gcc_type);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}
