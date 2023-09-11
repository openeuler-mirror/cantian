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
 * cms_disk_lock.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_disk_lock.c
 *
 * -------------------------------------------------------------------------
 */
#include <time.h>
#include "cm_file.h"
#include "cm_date.h"
#include "cm_malloc.h"
#include "cms_disk_lock.h"
#include "cm_disk.h"
#include "cms_param.h"
#include "cms_detect_error.h"
#include "cms_stat.h"
#include "cm_utils.h"
#include "cms_log.h"


#ifdef WIN32
#define cm_strdup _strdup
#else
#define cm_strdup strdup
#endif

static active_func_t   g_active_func = NULL;
cms_flock_t* g_invalid_lock = NULL;
spinlock_t g_exit_num_lock = 0;

status_t cms_disk_lock_init(cms_dev_type_t type, const char* dev, uint64 offset, int64 inst_id,
                            cms_disk_lock_t* lock, active_func_t active_func, uint32 flag)
{
    cm_init_thread_lock(&lock->tlock);
    cm_init_thread_lock(&lock->slock);
    lock->type = type;
    lock->offset = offset;
    lock->inst_id = inst_id;
    lock->flag = flag;
    lock->active_func = active_func;
    lock->int64_param1 = GS_INVALID_ID64;
    errno_t ret = snprintf_s(lock->dev_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN,
                             "%s", dev);
    PRTS_RETURN_IFERR(ret);

    if (type == CMS_DEV_TYPE_FILE) {
        if (lock->flock == NULL) {
            lock->flock = (cms_flock_t*)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_flock_t));
            GS_RETVALUE_IFTRUE((lock->flock == NULL), GS_ERROR);
        }
        ret = memset_sp(lock->flock->file_name, CMS_FILE_NAME_BUFFER_SIZE, 0, CMS_FILE_NAME_BUFFER_SIZE);
        MEMS_RETURN_IFERR(ret);
        ret = snprintf_s(lock->flock->file_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN,
            "%s_%lld.lock", dev, (int64)offset);
        PRTS_RETURN_IFERR(ret);
        GS_RETURN_IFERR(cm_open_file(lock->flock->file_name,
            O_CREAT | O_RDWR | O_BINARY | O_CLOEXEC | O_SYNC | O_DIRECT, &lock->fd));
        lock->flock->magic = CMS_STAT_LOCK_MAGIC;
        lock->flock->node_id = inst_id;
        lock->flock->lock_time = time(NULL);
    } else if (type == CMS_DEV_TYPE_SD) {
        char file_name[CMS_FILE_NAME_BUFFER_SIZE] = {0};
        if (flag & CMS_DLOCK_PROCESS) {
            char* dev_name = cm_strdup(dev);
            if (dev_name == NULL) {
                CMS_LOG_ERR("alloc memory failed");
                return GS_ERROR;
            }
            ret = snprintf_s(file_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN,
                "%s/%s_%lld.lock", g_cms_param->cms_home, dev_name, (int64)offset);
            CM_FREE_PTR(dev_name);
            PRTS_RETURN_IFERR(ret);
            GS_RETURN_IFERR(cm_open_file(file_name, O_CREAT | O_RDWR | O_BINARY | O_CLOEXEC, &lock->fd));
        }
        GS_RETURN_IFERR(cm_open_disk(dev, &lock->disk_handle));
        GS_RETURN_IFERR(cm_alloc_dlock(&lock->dlock, offset, inst_id));
    } else {
        CMS_LOG_ERR("invalid device type:%d", type);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void cms_disk_lock_set_active_func(active_func_t func)
{
    g_active_func = func;
}

static status_t cms_disk_lock_try_lock_sd(cms_disk_lock_t* lock)
{
#ifndef _WIN32
    int32 ret;
    
    //reset the read area,set self to write area
    cm_init_dlock_header(&lock->dlock, lock->offset, lock->inst_id);
    ret = cm_disk_lock(&lock->dlock, lock->disk_handle);
    if (ret == GS_SUCCESS) {
        return GS_SUCCESS;
    }
    
    if (ret != CM_DLOCK_ERR_LOCK_OCCUPIED) {
        CMS_LOG_ERR("%lld try lock dlock [%d,%llu] failed", lock->inst_id, lock->disk_handle, lock->offset);
        return GS_ERROR;
    }

    //read current lock info to read area
    status_t status = cm_get_dlock_info(&lock->dlock, lock->disk_handle);
    if (GS_SUCCESS != status) {
        GS_LOG_DEBUG_ERR("Get lock info from dev failed.");
        return status;
    }
    uint64 old_inst_id = LOCKR_ORG_INST_ID(lock->dlock);
    
    time_t lock_time = LOCKR_LOCK_TIME(lock->dlock);
    time_t now_time = time(NULL);
    time_t diff_time = now_time - lock_time;
    if (diff_time <= CMS_DISK_LOCK_TIMEOUT) {
        return CM_DLOCK_ERR_LOCK_OCCUPIED;
    }
        
    if (lock->active_func != NULL && lock->active_func(lock, old_inst_id)) {
        return CM_DLOCK_ERR_LOCK_OCCUPIED;
    }

    CMS_LOG_INF("dlock [%d,%lld] holded by %lld timeout(holded time = %lu),will be released and try lock by %lld",
        lock->disk_handle, lock->offset, old_inst_id, diff_time, lock->inst_id);

    return cm_preempt_dlock(&lock->dlock, lock->disk_handle);
#else
    return GS_SUCCESS;
#endif
}

status_t cms_get_exit_num(uint32 *exit_num)
{
    char buf[CMS_EXIT_NUM] = {0};
    char *endptr = NULL;
    bool32 is_exist_special;
    bool32 is_file_exist;
    char real_path[CMS_FILE_NAME_BUFFER_SIZE];

    is_exist_special = cm_check_exist_special_char(g_cms_param->exit_num_file,
        (uint32)strlen(g_cms_param->exit_num_file));
    if (is_exist_special == GS_TRUE) {
        CMS_LOG_ERR("the cms exit num file path(name:%s) has special char.", g_cms_param->exit_num_file);
        return GS_ERROR;
    }
    GS_RETURN_IFERR(realpath_file(g_cms_param->exit_num_file, real_path, CMS_FILE_NAME_BUFFER_SIZE));
    is_file_exist = cm_file_exist(real_path);
    if (is_file_exist == GS_FALSE) {
        CMS_LOG_ERR("the cms exit num file path(name:%s) does not exist. ", real_path);
        return GS_ERROR;
    }
    int exit_num_fd = open(real_path, O_CREAT | O_RDWR | O_SYNC, S_IRUSR | S_IWUSR);
    if (exit_num_fd == -1) {
        CMS_LOG_ERR("cm open exit_num_file failed.");
        return GS_ERROR;
    }
    int curr_size = read(exit_num_fd, buf, CMS_EXIT_NUM);
    if (curr_size <= 0) {
        CMS_LOG_ERR("read file failed, read size=%d.", curr_size);
        close(exit_num_fd);
        return GS_ERROR;
    }
    int64 val_int64 = strtoll(buf, &endptr, CM_DEFAULT_DIGIT_RADIX);
    if (val_int64 <= 0) {
        CMS_LOG_ERR("cm str trans uint failed.");
        close(exit_num_fd);
        return GS_ERROR;
    }
    *exit_num = (uint32)val_int64;
    close(exit_num_fd);
    return GS_SUCCESS;
}

void cms_kill_self_by_exit(void)
{
    CM_ABORT_REASONABLE(0, "cms exits due to an exception.");
}

void cms_inc_exit_num(cms_res_t res)
{
    uint32 exit_num = 0;
    if (cms_exec_script_inner(res, "-inc_exit_num") == GS_SUCCESS) {
        status_t ret = cms_get_exit_num(&exit_num);
        if (ret == GS_SUCCESS && exit_num >= CMS_EXIT_COUNT_MAX) {
            if (cms_daemon_stop_pull() != GS_SUCCESS) {
                CMS_LOG_ERR("stop cms daemon process failed.");
            }
            cms_kill_all_res();
        }
    }
    cm_spin_unlock(&g_exit_num_lock);
    cms_kill_self_by_exit();
}

void cms_exec_exit_proc(void)
{
    cms_res_t res = { 0 };
    status_t result = GS_ERROR;
    cm_spin_lock(&g_exit_num_lock, NULL);
    if (cms_get_script_from_memory(&res) != GS_SUCCESS) {
        CMS_LOG_ERR("cms get script from memory failed.");
    }
    uint8 ret = cm_file_exist(g_cms_param->exit_num_file);
    if (ret == GS_TRUE) {
        CMS_LOG_INF("exit_num file exist");
        cms_inc_exit_num(res);
    } else {
        CMS_LOG_INF("exit_num file does not exist");
        cms_exec_res_script(res.script, "-inc_exit_num", res.check_timeout, &result);
        cm_spin_unlock(&g_exit_num_lock);
        cms_kill_self_by_exit();
    }
}

status_t cms_reopen_lock_file(cms_disk_lock_t* lock)
{
    int32 old_fd = lock->fd;
    status_t ret = cm_open_file(lock->flock->file_name,
        O_CREAT | O_RDWR | O_BINARY | O_CLOEXEC | O_SYNC | O_DIRECT, &lock->fd);
    if (ret != GS_SUCCESS) {
        CMS_LOG_ERR("cms open file failed:%s:%d", lock->dev_name, (int32)lock->offset);
        return ret;
    }
    CMS_SYNC_POINT_GLOBAL_START(CMS_DISK_REOPEN_SLEEP, NULL, 0);
    CMS_SYNC_POINT_GLOBAL_END;
    cm_close_file(old_fd);
    CMS_LOG_INF("cms reopen file finished, file lock:%s:%d, old fd:%d, new fd:%d", lock->dev_name,
        (int32)lock->offset, old_fd, lock->fd);
    return GS_SUCCESS;
}

status_t cms_seek_write_file(cms_disk_lock_t* lock, cms_flock_t* lock_info)
{
    status_t ret;
    int64 seek_offset;
    seek_offset = cm_seek_file(lock->fd, 0, SEEK_SET);
    if (seek_offset != 0) {
        CMS_LOG_ERR("file seek failed:%s:%d,%d:%s", lock->dev_name, (int32)lock->offset, errno,
            strerror(errno));
        if (cm_unlock_file_fd(lock->fd) != GS_SUCCESS) {
            CMS_LOG_ERR("cms unlock file failed:%s:%d", lock->dev_name, (int32)lock->offset);
        }
        return GS_ERROR;
    }
    ret = cm_write_file(lock->fd, lock_info, sizeof(cms_flock_t));
    CMS_SYNC_POINT_GLOBAL_START(CMS_DISK_UNLOCK_FILE_WRITE_FAIL, &ret, GS_ERROR);
    CMS_SYNC_POINT_GLOBAL_END;
    if (ret != GS_SUCCESS) {
        CMS_LOG_ERR("file write failed:%s:%d,%d:%s", lock->dev_name, (int32)lock->offset, errno,
            strerror(errno));
        if (cm_unlock_file_fd(lock->fd) != GS_SUCCESS) {
            CMS_LOG_ERR("cms unlock file failed:%s:%d", lock->dev_name, (int32)lock->offset);
        }
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t cms_disk_lock_try_lock_file(cms_disk_lock_t* lock, uint8 lock_type)
{
    status_t ret = GS_ERROR;
    int cnt = 0;
    cm_thread_lock(&lock->slock);
    do {
        ++cnt;
        if (lock_type == DISK_LOCK_WRITE) {
            ret = cm_lockw_file_fd(lock->fd);
        } else if (lock_type == DISK_LOCK_READ) {
            ret = cm_lockr_file_fd(lock->fd);
        } else {
            CMS_LOG_ERR("invalid lock type(%u), file lock failed:%s:%d", lock_type, lock->dev_name,
                (int32)lock->offset);
            cms_exec_exit_proc();
            break;
        }

        CMS_SYNC_POINT_GLOBAL_START(CMS_DISK_LOCK_FILE_LOCK_FAIL, &ret, GS_ERROR);
        CMS_SYNC_POINT_GLOBAL_END;
        if (ret != GS_SUCCESS) {
            if (errno == EAGAIN) {
                cm_thread_unlock(&lock->slock);
                return CM_DLOCK_ERR_LOCK_OCCUPIED;
            }
            CMS_LOG_ERR("file lock(lock type(%u)) failed:%s:%d,%d:%s", lock_type, lock->dev_name,
                (int32)lock->offset, errno, strerror(errno));
            cms_reopen_lock_file(lock);
            continue;
        }

        if (lock_type == DISK_LOCK_WRITE) {
            lock->flock->lock_time = time(NULL);
            date_t start_time = cm_now();
            ret = cms_seek_write_file(lock, lock->flock);
            cms_refresh_last_check_time(start_time);
            if (ret != GS_SUCCESS) {
                cms_reopen_lock_file(lock);
                continue;
            }
        }
        cm_thread_unlock(&lock->slock);
        return GS_SUCCESS;
    } while (cnt <= 1);
    cm_thread_unlock(&lock->slock);
    cms_exec_exit_proc();
    return ret;
}

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
status_t _cms_disk_try_lock(cms_disk_lock_t* lock, uint8 lock_type, const char* file, int32 line)
{
    CMS_LOG_DEBUG_INF("cms_disk_try_lock:%s:%d", file, line);
    date_t start = cm_now();
#else
status_t cms_disk_try_lock(cms_disk_lock_t* lock, uint8 lock_type)
{
#endif
    status_t ret;
    if (lock->flag & CMS_DLOCK_THREAD) {
        cm_thread_lock(&lock->tlock);
    }

    if (lock->type == CMS_DEV_TYPE_SD) {
        if (lock->flag & CMS_DLOCK_PROCESS) {
            if (cm_lockw_file_fd(lock->fd) != GS_SUCCESS) {
                cm_thread_unlock(&lock->tlock);
                return GS_ERROR;
            }
        }
        ret = cms_disk_lock_try_lock_sd(lock);
        if (ret != GS_SUCCESS) {
            if (lock->flag & CMS_DLOCK_PROCESS) {
                cm_unlock_file_fd(lock->fd);
            }
        }
    } else {
        ret = cms_disk_lock_try_lock_file(lock, lock_type);
    }

    if (ret != GS_SUCCESS) {
        if (lock->flag & CMS_DLOCK_THREAD) {
            cm_thread_unlock(&lock->tlock);
        }
    }

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    date_t end = cm_now();
    CMS_LOG_DEBUG_INF("cms_disk_lock offset:%lld elapsed:%lld(ms) at %s:%d", lock->offset, (end - start) / MICROSECS_PER_MILLISEC, file, line);
#endif
    return ret;
}

status_t cms_disk_lock(cms_disk_lock_t* lock, uint32 timeout_ms, uint8 lock_type)
{
    status_t ret;

    if (timeout_ms == 0) {
        while (1) {
            ret = cms_disk_try_lock(lock, lock_type);
            if (ret == CM_DLOCK_ERR_LOCK_OCCUPIED) {
                cm_sleep(CMS_LOCK_TRY_INTERVAL);
            } else {
                return ret;
            }
        }
    } else {
        date_t start_time = cm_monotonic_now();
        while (1) {
            ret = cms_disk_try_lock(lock, lock_type);
            if (ret == GS_SUCCESS) {
                return ret;
            } else if (ret == CM_DLOCK_ERR_LOCK_OCCUPIED) {
                date_t end_time = cm_monotonic_now();
                if (end_time > start_time + timeout_ms * MICROSECS_PER_MILLISEC) {
                    CMS_LOG_DEBUG_ERR("cms_disk_lock timeout:%s:%lld.", lock->dev_name, lock->offset);
                    return GS_ERROR;
                }
                cm_sleep(CMS_LOCK_TRY_INTERVAL);
            } else {
                CMS_LOG_DEBUG_ERR("cms_disk_lock failed:%s:%lld.", lock->dev_name, lock->offset);
                return ret;
            }
        }
    }

    return GS_ERROR;
}

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
status_t _cms_disk_unlock(cms_disk_lock_t* lock, const char* file, int32 line)
{
    CMS_LOG_DEBUG_INF("cms_disk_unlock:%s:%d", file, line);
#else
status_t cms_disk_unlock(cms_disk_lock_t* lock)
{
#endif
    status_t ret;
    if (lock->type == CMS_DEV_TYPE_SD) {
        ret = cm_disk_unlock_ex(&lock->dlock, lock->fd);
        if (lock->flag & CMS_DLOCK_PROCESS) {
            cm_unlock_file_fd(lock->fd);
        }
    } else {
        ret = cms_disk_unlock_file(lock);
    }

    if (lock->flag & CMS_DLOCK_THREAD) {
        cm_thread_unlock(&lock->tlock);
    }

    return ret;
}

status_t cms_disk_unlock_file(cms_disk_lock_t* lock)
{
    int32 cnt = 0;
    status_t ret;
    cm_thread_lock(&lock->slock);
    do {
        ++cnt;
        if (cm_lockw_file_fd(lock->fd) == GS_SUCCESS) {
            date_t start_time = cm_now();
            ret = cms_seek_write_file(lock, g_invalid_lock);
            if (ret != GS_SUCCESS) {
                cms_reopen_lock_file(lock);
                continue;
            }
            cms_refresh_last_check_time(start_time);
        }
        ret = cm_unlock_file_fd(lock->fd);
        CMS_SYNC_POINT_GLOBAL_START(CMS_DISK_UNLOCK_FILE_UNLOCK_FAIL, &ret, GS_ERROR);
        CMS_SYNC_POINT_GLOBAL_END;
        if (ret != GS_SUCCESS) {
            CMS_LOG_ERR("file unlock failed:%s:%d,%d:%s", lock->dev_name, (int32)lock->offset, errno,
                strerror(errno));
            cms_reopen_lock_file(lock);
            continue;
        }
        cm_thread_unlock(&lock->slock);
        return GS_SUCCESS;
    } while (cnt <= 1);
    cm_thread_unlock(&lock->slock);
    cms_exec_exit_proc();
    return GS_ERROR;
}

void cms_disk_lock_destroy(cms_disk_lock_t* lock)
{
    cms_disk_unlock(lock);
    cm_destroy_thread_lock(&lock->tlock);
    if (lock->type == CMS_DEV_TYPE_SD) {
        cm_destory_dlock(&lock->dlock);
        cm_close_disk(lock->disk_handle);
        if (lock->flag & CMS_DLOCK_PROCESS) {
            cm_close_file(lock->fd);
        }
    } else {
        cm_close_file(lock->fd);
        CM_FREE_PTR(lock->flock);
    }
}

status_t cms_disk_lock_get_inst_sd(cms_disk_lock_t* lock, uint64* inst_id)
{
#ifndef _WIN32
    dlock_t         dlock;
    GS_RETURN_IFERR(cm_alloc_dlock(&dlock, lock->offset, lock->inst_id));
    if (cm_init_dlock(&dlock, lock->offset, lock->inst_id) != GS_SUCCESS) {
        cm_destory_dlock(&dlock);
        return GS_ERROR;
    }
    status_t status = cm_get_dlock_info(&dlock, lock->disk_handle);
    if (GS_SUCCESS != status) {
        cm_destory_dlock(&dlock);
        GS_LOG_DEBUG_ERR("Get lock info from dev failed.");
        return status;
    }

    if (LOCKW_LOCK_MAGICNUM(dlock) == DISK_LOCK_HEADER_MAGIC) {
        time_t lock_time = LOCKR_LOCK_TIME(dlock);
        time_t now_time = time(NULL);
        time_t diff_time = now_time - lock_time;
        if (diff_time <= CMS_DISK_LOCK_TIMEOUT) {
	        *inst_id = LOCKR_ORG_INST_ID(dlock);
        } else if (lock->active_func != NULL && lock->active_func(lock, LOCKR_ORG_INST_ID(dlock))) {
            *inst_id = LOCKR_ORG_INST_ID(dlock);
        } else {
            *inst_id = GS_INVALID_ID64;
        }
    } else {
        *inst_id = GS_INVALID_ID64;
    }
    cm_destory_dlock(&dlock);
#endif
    return GS_SUCCESS;
}

static status_t cms_disk_lock_get_data_sd(cms_disk_lock_t* lock, char* data, uint32 size)
{
#ifndef _WIN32
    dlock_t         dlock;
    GS_RETURN_IFERR(cm_alloc_dlock(&dlock, lock->offset, lock->inst_id));
    if (cm_init_dlock(&dlock, lock->offset, lock->inst_id) != GS_SUCCESS) {
        cm_destory_dlock(&dlock);
        return GS_ERROR;
    }
    status_t status = cm_get_dlock_info(&dlock, lock->disk_handle);
    if (GS_SUCCESS != status) {
        cm_destory_dlock(&dlock);
        GS_LOG_DEBUG_ERR("Get lock info from dev failed.");
        return status;
    }

    if (LOCKR_LOCK_MAGICNUM(dlock) == DISK_LOCK_HEADER_MAGIC) {
        errno_t ret = memcpy_s(data, size, LOCKR_LOCK_BODY(dlock), MIN(size, DISK_LOCK_BODY_LEN));
        MEMS_RETURN_IFERR(ret);
    } else {
        errno_t ret = memset_s(data, size, 0, size);
        MEMS_RETURN_IFERR(ret);
    }

    cm_destory_dlock(&dlock);
#endif
    return GS_SUCCESS;
}

static status_t cms_disk_lock_set_data_sd(cms_disk_lock_t* lock, char* data, uint32 size)
{
#ifndef _WIN32
    errno_t ret = memcpy_s(LOCKW_LOCK_BODY(lock->dlock), DISK_LOCK_BODY_LEN, data, size);
    MEMS_RETURN_IFERR(ret);
#endif
    return GS_SUCCESS;
}

static status_t cms_seek_read_file(cms_disk_lock_t* lock, cms_flock_t* lock_info)
{
    status_t ret = GS_ERROR;
    int32 cnt = 0;
    do {
        ++cnt;
        int64 seek_offset = cm_seek_file(lock->fd, 0, SEEK_SET);
        if (seek_offset != 0) {
            CMS_LOG_ERR("cm seek file failed, %s %llu", lock->dev_name, lock->offset);
            cms_reopen_lock_file(lock);
            continue;
        }
        ret = cm_read_file(lock->fd, lock_info, sizeof(cms_flock_t), NULL);
        CMS_SYNC_POINT_GLOBAL_START(CMS_DISK_GET_INST_FILE_READ_FAIL, &ret, GS_ERROR);
        CMS_SYNC_POINT_GLOBAL_END;
        if (ret != GS_SUCCESS) {
            CMS_LOG_ERR("cm read file failed, %s %llu", lock->dev_name, lock->offset);
            cms_reopen_lock_file(lock);
            continue;
        }
        return GS_SUCCESS;
    } while (cnt <= 1);
    cms_exec_exit_proc();
    return ret;
}

static status_t cms_disk_lock_get_inst_file(cms_disk_lock_t* lock, uint64* inst_id)
{
    cms_flock_t* lock_info = cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_flock_t));
    date_t start_time = cm_now();
    status_t ret;
    if (lock_info == NULL) {
        CMS_LOG_ERR("cms malloc lock_info failed, %s %llu", lock->dev_name, lock->offset);
        return GS_ERROR;
    }
    cm_thread_lock(&lock->slock);
    ret = cms_seek_read_file(lock, lock_info);
    cm_thread_unlock(&lock->slock);
    if (ret != GS_SUCCESS) {
        CM_FREE_PTR(lock_info);
        return ret;
    }
    if (lock_info->magic == CMS_STAT_LOCK_MAGIC) {
        time_t lock_time = lock_info->lock_time;
        time_t now_time = time(NULL);
        time_t diff_time = now_time - lock_time;
        if (diff_time <= CMS_DISK_LOCK_TIMEOUT) {
            *inst_id = lock_info->node_id;
        } else if (lock->active_func != NULL && lock->active_func(lock, lock_info->node_id)) {
            CMS_LOG_WAR("lock[%s,%llu] hold by %d time out, diff_time %lu", lock->dev_name, lock->offset,
                lock_info->node_id, diff_time);
            *inst_id = GS_INVALID_ID64;
        }
    } else {
        CMS_LOG_WAR("lock info is invalid, lock_info magic is %llu", lock_info->magic);
        *inst_id = GS_INVALID_ID64;
    }
    cms_refresh_last_check_time(start_time);
    CM_FREE_PTR(lock_info);
    return GS_SUCCESS;
}

static status_t cms_disk_lock_get_data_file(cms_disk_lock_t* lock, char* data, uint32 size)
{
    cms_flock_t* lock_info = cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_flock_t));
    if (lock_info == NULL) {
        CMS_LOG_ERR("cms malloc lock_info failed, %s %llu", lock->dev_name, lock->offset);
        return GS_ERROR;
    }
    status_t ret = GS_SUCCESS;
    cm_thread_lock(&lock->slock);
    date_t start_time = cm_now();
    ret = cms_seek_read_file(lock, lock_info);
    cm_thread_unlock(&lock->slock);
    if (ret != GS_SUCCESS) {
        CM_FREE_PTR(lock_info);
        return GS_ERROR;
    }
    do {
        if (lock_info->magic != CMS_STAT_LOCK_MAGIC) {
            CMS_LOG_WAR("cms lock_info magic is invalid");
            ret = memset_s(data, size, 0, size);
            break;
        }
        cms_refresh_last_check_time(start_time);
        if (memcpy_s(data, size, lock_info->data, MIN(size, DISK_LOCK_BODY_LEN)) != GS_SUCCESS) {
            CMS_LOG_ERR("cms lock get data memcpy failed, %s %llu", lock->dev_name, lock->offset);
            ret = GS_ERROR;
            break;
        }
    } while (0);
    CM_FREE_PTR(lock_info);
    return ret;
}

static status_t cms_disk_lock_set_data_file(cms_disk_lock_t* lock, char* data, uint32 size)
{
    errno_t ret = memcpy_s(lock->flock->data, DISK_LOCK_BODY_LEN, data, MIN(size, DISK_LOCK_BODY_LEN));
    MEMS_RETURN_IFERR(ret);

    return GS_SUCCESS;
}

status_t cms_disk_lock_get_data(cms_disk_lock_t* lock, char* data, uint32 size)
{
    if (lock->type == CMS_DEV_TYPE_SD) {
        return cms_disk_lock_get_data_sd(lock, data, size);
    }

    return cms_disk_lock_get_data_file(lock, data, size);
}

status_t cms_disk_lock_set_data(cms_disk_lock_t* lock, char* data, uint32 size)
{
    if (lock->type == CMS_DEV_TYPE_SD) {
        return cms_disk_lock_set_data_sd(lock, data, size);
    }

    return cms_disk_lock_set_data_file(lock, data, size);
}

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
status_t _cms_disk_lock_get_inst(cms_disk_lock_t* lock, uint64* inst_id, const char* file, int32 line)
{
    CMS_LOG_DEBUG_INF("cms_disk_lock_get_inst:%s:%d", file, line);
#else
status_t cms_disk_lock_get_inst(cms_disk_lock_t* lock, uint64* inst_id)
{
#endif
    if (lock->type == CMS_DEV_TYPE_SD) {
        return cms_disk_lock_get_inst_sd(lock, inst_id);
    }

    return cms_disk_lock_get_inst_file(lock, inst_id);
}
