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
 * cms_disk_lock.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_disk_lock.c
 *
 * -------------------------------------------------------------------------
 */
#include "cms_log_module.h"
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
#include "cm_disklock.h"

static active_func_t  g_active_func = NULL;
cms_flock_t* g_invalid_lock = NULL;
cms_master_info_t* g_master_info = NULL;
spinlock_t g_exit_num_lock = 0;

status_t cms_disk_lock_init_sd(cms_disk_lock_t* lock, const char* dev, uint64 offset, int64 inst_id, uint32 flag)
{
    status_t ret = CT_SUCCESS;
    errno_t err = EOK;
    char file_name[CMS_FILE_NAME_BUFFER_SIZE] = {0};
    if (flag & CMS_DLOCK_PROCESS) {
        err = snprintf_s(file_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN,
            "%s/%s_%lld.lock", g_cms_param->cms_home, dev, (int64)offset);
        if (err != EOK) {
            CMS_LOG_ERR("snprintf_s failed, err %d, errno %d[%s]", err, errno, strerror(errno));
            return CT_ERROR;
        }
        ret = cm_open_file(file_name, O_CREAT | O_RDWR | O_BINARY | O_CLOEXEC, &lock->fd);
        if (ret != CT_SUCCESS) {
            CMS_LOG_ERR("open file failed, ret %d, file %s", ret, file_name);
            return ret;
        }
    }
    CT_RETURN_IFERR(cm_open_disk(dev, &lock->disk_handle));
    CT_RETURN_IFERR(cm_alloc_dlock(&lock->dlock, offset, inst_id));
    return CT_SUCCESS;
}

status_t cms_disk_lock_init_file(cms_disk_lock_t* lock, const char* dev, uint64 offset, int64 inst_id, bool32 is_write)
{
    status_t ret = CT_SUCCESS;
    errno_t err = EOK;
    if (lock->flock == NULL) {
        lock->flock = (cms_flock_t*)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_flock_t));
        CT_RETVALUE_IFTRUE((lock->flock == NULL), CT_ERROR);
    }
    err = memset_sp(lock->flock->file_name, CMS_FILE_NAME_BUFFER_SIZE, 0, CMS_FILE_NAME_BUFFER_SIZE);
    if (err != EOK) {
        CMS_LOG_ERR("memset_sp failed, err %d, errno %d[%s].", err, errno, strerror(errno));
        CM_FREE_PTR(lock->flock);
        return CT_ERROR;
    }
    err = snprintf_s(lock->flock->file_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN,
        "%s_%lld.lock", dev, (int64)offset);
    if (err == -1) {
        CMS_LOG_ERR("snprintf_s failed, err %d, errno %d[%s]", err, errno, strerror(errno));
        CM_FREE_PTR(lock->flock);
        return CT_ERROR;
    }
    ret = cm_open_file(lock->flock->file_name, O_CREAT | O_RDWR | O_BINARY | O_CLOEXEC | O_SYNC | O_DIRECT,
        &lock->fd);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("open file failed, file %s, ret %d", lock->flock->file_name, ret);
        CM_FREE_PTR(lock->flock);
        return ret;
    }
    lock->flock->magic = CMS_STAT_LOCK_MAGIC;
    lock->flock->node_id = inst_id;
    lock->flock->is_write = is_write;
    lock->flock->lock_time = time(NULL);
    return CT_SUCCESS;
}

status_t cms_disk_lock_init_nfs(cms_disk_lock_t* lock, const char* dev, const char* file, uint64 l_start,
    uint64 l_len, int64 inst_id, bool32 is_write)
{
    status_t ret = CT_SUCCESS;
    errno_t err = EOK;
    if (lock->flock == NULL) {
        lock->flock = (cms_flock_t*)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_flock_t));
        CT_RETVALUE_IFTRUE((lock->flock == NULL), CT_ERROR);
    }
    err = memset_sp(lock->flock->file_name, CMS_FILE_NAME_BUFFER_SIZE, 0, CMS_FILE_NAME_BUFFER_SIZE);
    if (err != EOK) {
        CMS_LOG_ERR("memset_sp failed, err %d, errno %d[%s].", err, errno, strerror(errno));
        CM_FREE_PTR(lock->flock);
        return CT_ERROR;
    }
    err = snprintf_s(lock->flock->file_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN,
        "%s%s", dev, file);
    if (err == -1) {
        CMS_LOG_ERR("snprintf_s failed, err %d, errno %d[%s]", err, errno, strerror(errno));
        CM_FREE_PTR(lock->flock);
        return CT_ERROR;
    }

    ret = cm_open_file(lock->flock->file_name, O_CREAT | O_RDWR | O_BINARY | O_CLOEXEC | O_SYNC | O_DIRECT, &lock->fd);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("open file failed, file %s, ret %d", lock->flock->file_name, ret);
        CM_FREE_PTR(lock->flock);
        return ret;
    }
    lock->flock->magic = CMS_STAT_LOCK_MAGIC;
    lock->flock->node_id = inst_id;
    lock->flock->lock_time = time(NULL);
    lock->flock->is_write = is_write;
    lock->flock->l_start = l_start;
    lock->flock->l_len = l_len;
    return CT_SUCCESS;
}

status_t cms_dbstore_lock_init(cms_disk_lock_t* lock, uint64 l_start, uint64 l_len)
{
    status_t ret = CT_SUCCESS;
    char file_name[CMS_MAX_NAME_LEN] = {0};
    if (lock->flock == NULL) {
        CMS_LOG_ERR("get file name from path(%s), invalid para.", lock->dev_name);
        return CT_ERROR;
    }
    ret = cm_get_path_file_name(lock->flock->file_name, file_name, CMS_MAX_NAME_LEN);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("get file name from path(%s) failed,", lock->flock->file_name);
        return CT_ERROR;
    }
    errno_t err = snprintf_s(lock->file_name, CMS_MAX_NAME_LEN, CMS_MAX_NAME_LEN - 1, "%s", file_name);
    if (err == -1) {
        CMS_LOG_ERR("snprintf_s file name failed, err %d, errno %d[%s]", err, errno, strerror(errno));
        return CT_ERROR;
    }
    if (cm_dbs_lock_init(file_name, l_start, l_len, &lock->fd) != CT_SUCCESS) {
        CMS_LOG_ERR("init dbstore lock(%s) start(%llu) len(%llu) failed.", file_name, l_start, l_len);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}
 
/* 生成当前加锁路径文件的dbstore lock锁句柄 */
status_t cms_gen_dbstore_lock_obj(cms_disk_lock_t* lock, uint64 l_start, uint64 l_len)
{
    int path_depth = 0;
    status_t ret = cm_get_file_path_depth(lock->flock->file_name, "/", &path_depth);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("get file path depth failed, file %s, ret %d", lock->flock->file_name, ret);
        return ret;
    }
    if (lock->dbs_fd == NULL) {
        lock->dbs_fd = (object_id_t *)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(object_id_t) * (path_depth + 1));
        CT_RETVALUE_IFTRUE((lock->dbs_fd == NULL), CT_ERROR);
        lock->fd_len = path_depth;
    }
    
    ret = cm_get_dbs_file_path_handle(lock->flock->file_name, "/", lock->dbs_fd, path_depth);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("get dbstore file path fd failed, file %s, ret %d", lock->flock->file_name, ret);
        CM_FREE_PTR(lock->dbs_fd);
        return ret;
    }
    ret = cms_dbstore_lock_init(lock, l_start, l_len);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("dbstore lock init name:%s offset:%lld len:%lld failed.", lock->flock->file_name, l_start, l_len);
        CM_FREE_PTR(lock->dbs_fd);
        return ret;
    }
    return CT_SUCCESS;
}
 
status_t cms_disk_lock_init_dbs(cms_disk_lock_t* lock, const char* dev, const char* file, uint64 l_start,
    uint64 l_len, int64 inst_id, bool32 is_write)
{
    status_t ret = CT_SUCCESS;
    errno_t err = EOK;
    if (lock->flock == NULL) {
        lock->flock = (cms_flock_t*)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_flock_t));
        CT_RETVALUE_IFTRUE((lock->flock == NULL), CT_ERROR);
    }
    err = memset_sp(lock->flock->file_name, CMS_FILE_NAME_BUFFER_SIZE, 0, CMS_FILE_NAME_BUFFER_SIZE);
    if (err != EOK) {
        CMS_LOG_ERR("memset_sp failed, err %d, errno %d[%s].", err, errno, strerror(errno));
        CM_FREE_PTR(lock->flock);
        return CT_ERROR;
    }
    err = snprintf_s(lock->flock->file_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN,
        "%s%s", dev, file);
    if (err == -1) {
        CMS_LOG_ERR("snprintf_s failed, err %d, errno %d[%s]", err, errno, strerror(errno));
        CM_FREE_PTR(lock->flock);
        return CT_ERROR;
    }
    ret = cms_gen_dbstore_lock_obj(lock, l_start, l_len);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("gen dbstore lock obj failed, file %s, ret %d", lock->flock->file_name, ret);
        CM_FREE_PTR(lock->flock);
        return ret;
    }
    
    lock->flock->magic = CMS_STAT_LOCK_MAGIC;
    lock->flock->node_id = inst_id;
    lock->flock->lock_time = time(NULL);
    lock->flock->is_write = is_write;
    lock->flock->l_start = l_start;
    lock->flock->l_len = l_len;
    return CT_SUCCESS;
}

status_t cms_disk_lock_init(cms_dev_type_t type, const char* dev, const char* file, uint64 offset,
    uint64 l_start, uint64 l_len, int64 inst_id, cms_disk_lock_t* lock, active_func_t active_func,
    uint32 flag, bool32 is_write)
{
    status_t ret = CT_SUCCESS;
    errno_t err = EOK;
    cm_init_thread_lock(&lock->tlock);
    cm_init_thread_lock(&lock->slock);
    lock->type = type;
    lock->offset = offset;
    lock->inst_id = inst_id;
    lock->flag = flag;
    lock->active_func = active_func;
    lock->int64_param1 = CT_INVALID_ID64;
    err = snprintf_s(lock->dev_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN, "%s", dev);
    PRTS_RETURN_IFERR(err);

    if (type == CMS_DEV_TYPE_FILE) {
        ret = cms_disk_lock_init_file(lock, dev, offset, inst_id, is_write);
        if (ret != CT_SUCCESS) {
            CMS_LOG_ERR("cms disk lock init file failed, ret %d, dev %s, offset %llu, inst_id %lld",
                ret, dev, offset, inst_id);
            return ret;
        }
    } else if (type == CMS_DEV_TYPE_NFS) {
        ret = cms_disk_lock_init_nfs(lock, dev, file, l_start, l_len, inst_id, is_write);
        if (ret != CT_SUCCESS) {
            CMS_LOG_ERR("cms disk lock init nas failed, ret %d, dev %s, file %s, l_start %llu, l_len %llu, "
                " inst_id %lld", ret, dev, file, l_start, l_len, inst_id);
            return ret;
        }
    } else if (type == CMS_DEV_TYPE_SD) {
        ret = cms_disk_lock_init_sd(lock, dev, offset, inst_id, flag);
        if (ret != CT_SUCCESS) {
            CMS_LOG_ERR("cms disk lock init sd failed, ret %d, dev %s, offset %llu, inst_id %lld, flag %u",
                ret, dev, offset, inst_id, flag);
            return ret;
        }
    } else if (type == CMS_DEV_TYPE_DBS) {
        ret = cms_disk_lock_init_dbs(lock, dev, file, l_start, l_len, inst_id, is_write);
        if (ret != CT_SUCCESS) {
            CMS_LOG_ERR("cms disk lock init dbstore failed, ret %d, dev %s, file %s, l_start %llu, l_len %llu, "
                " inst_id %lld", ret, dev, file, l_start, l_len, inst_id);
            return ret;
        }
    } else {
        CMS_LOG_ERR("invalid device type, type %d", type);
        return CT_ERROR;
    }
    return CT_SUCCESS;
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
    if (ret == CT_SUCCESS) {
        return CT_SUCCESS;
    }
    
    if (ret != CM_DLOCK_ERR_LOCK_OCCUPIED) {
        CMS_LOG_ERR("%lld try lock dlock [%d,%llu] failed", lock->inst_id, lock->disk_handle, lock->offset);
        return CT_ERROR;
    }

    //read current lock info to read area
    status_t status = cm_get_dlock_info(&lock->dlock, lock->disk_handle);
    if (CT_SUCCESS != status) {
        CT_LOG_DEBUG_ERR("Get lock info from dev failed.");
        return status;
    }
    uint64 old_inst_id = LOCKR_ORG_INST_ID(lock->dlock);
    
    time_t lock_time = LOCKR_LOCK_TIME(lock->dlock);
    time_t now_time = time(NULL);
    time_t diff_time = now_time - lock_time;
    if (diff_time <= CMS_DISK_LOCK_TIMEOUT) {
        return CT_EAGAIN;
    }
        
    if (lock->active_func != NULL && lock->active_func(lock, old_inst_id)) {
        return CT_EAGAIN;
    }

    CMS_LOG_INF("dlock [%d,%lld] holded by %lld timeout(holded time = %lu),will be released and try lock by %lld",
        lock->disk_handle, lock->offset, old_inst_id, diff_time, lock->inst_id);

    return cm_preempt_dlock(&lock->dlock, lock->disk_handle);
#else
    return CT_SUCCESS;
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
    if (is_exist_special == CT_TRUE) {
        CMS_LOG_ERR("the cms exit num file path(name:%s) has special char.", g_cms_param->exit_num_file);
        return CT_ERROR;
    }
    CT_RETURN_IFERR(realpath_file(g_cms_param->exit_num_file, real_path, CMS_FILE_NAME_BUFFER_SIZE));
    is_file_exist = cm_file_exist(real_path);
    if (is_file_exist == CT_FALSE) {
        CMS_LOG_ERR("the cms exit num file path(name:%s) does not exist. ", real_path);
        return CT_ERROR;
    }
    int exit_num_fd = open(real_path, O_CREAT | O_RDWR | O_SYNC, S_IRUSR | S_IWUSR);
    if (exit_num_fd == -1) {
        CMS_LOG_ERR("cm open exit_num_file failed.");
        return CT_ERROR;
    }
    int curr_size = read(exit_num_fd, buf, CMS_EXIT_NUM);
    if (curr_size <= 0) {
        CMS_LOG_ERR("read file failed, read size=%d.", curr_size);
        close(exit_num_fd);
        return CT_ERROR;
    }
    int64 val_int64 = strtoll(buf, &endptr, CM_DEFAULT_DIGIT_RADIX);
    if (val_int64 <= 0) {
        CMS_LOG_ERR("cm str trans uint failed.");
        close(exit_num_fd);
        return CT_ERROR;
    }
    *exit_num = (uint32)val_int64;
    close(exit_num_fd);
    return CT_SUCCESS;
}

void cms_kill_self_by_exit(void)
{
    CM_ABORT_REASONABLE(0, "cms exits due to an exception.");
}

void cms_inc_exit_num(cms_res_t res)
{
    uint32 exit_num = 0;
    if (cms_exec_script_inner(res, "-inc_exit_num") == CT_SUCCESS) {
        status_t ret = cms_get_exit_num(&exit_num);
        if (ret == CT_SUCCESS && exit_num >= CMS_EXIT_COUNT_MAX) {
            if (cms_daemon_stop_pull() != CT_SUCCESS) {
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
    status_t result = CT_ERROR;
    cm_spin_lock(&g_exit_num_lock, NULL);
    if (cms_get_script_from_memory(&res) != CT_SUCCESS) {
        CMS_LOG_ERR("cms get script from memory failed.");
    }
    uint8 ret = cm_file_exist(g_cms_param->exit_num_file);
    if (ret == CT_TRUE) {
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
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("cms open file failed:%s:%d", lock->dev_name, (int32)lock->offset);
        return ret;
    }
    CMS_SYNC_POINT_GLOBAL_START(CMS_DISK_REOPEN_SLEEP, NULL, 0);
    CMS_SYNC_POINT_GLOBAL_END;
    cm_close_file(old_fd);
    CMS_LOG_INF("cms reopen file finished, file lock:%s:%d, old fd:%d, new fd:%d", lock->dev_name,
        (int32)lock->offset, old_fd, lock->fd);
    return CT_SUCCESS;
}

status_t cms_seek_write_file(cms_disk_lock_t* lock, cms_flock_t* lock_info)
{
    status_t ret;
    int64 seek_offset;
    seek_offset = cm_seek_file(lock->fd, 0, SEEK_SET);
    if (seek_offset != 0) {
        CMS_LOG_ERR("file seek failed:%s:%d,%d:%s", lock->dev_name, (int32)lock->offset, errno,
            strerror(errno));
        if (cm_unlock_file_fd(lock->fd) != CT_SUCCESS) {
            CMS_LOG_ERR("cms unlock file failed:%s:%d", lock->dev_name, (int32)lock->offset);
        }
        return CT_ERROR;
    }
    ret = cm_write_file(lock->fd, lock_info, sizeof(cms_flock_t));
    CMS_SYNC_POINT_GLOBAL_START(CMS_DISK_UNLOCK_FILE_WRITE_FAIL, &ret, CT_ERROR);
    CMS_SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("file write failed:%s:%d,%d:%s", lock->dev_name, (int32)lock->offset, errno,
            strerror(errno));
        if (cm_unlock_file_fd(lock->fd) != CT_SUCCESS) {
            CMS_LOG_ERR("cms unlock file failed:%s:%d", lock->dev_name, (int32)lock->offset);
        }
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t cms_disk_lock_try_lock_file(cms_disk_lock_t* lock, uint8 lock_type)
{
    status_t ret = CT_ERROR;
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

        CMS_SYNC_POINT_GLOBAL_START(CMS_DISK_LOCK_FILE_LOCK_FAIL, &ret, CT_ERROR);
        CMS_SYNC_POINT_GLOBAL_END;
        if (ret != CT_SUCCESS) {
            if (errno == EAGAIN) {
                cm_thread_unlock(&lock->slock);
                return CT_EAGAIN;
            }
            CMS_LOG_ERR("file lock(lock type(%u)) failed:%s:%d,%d:%s", lock_type, lock->dev_name,
                (int32)lock->offset, errno, strerror(errno));
            cms_reopen_lock_file(lock);
            continue;
        }

        if (lock->flock->is_write == CT_TRUE && lock_type == DISK_LOCK_WRITE) {
            lock->flock->lock_time = time(NULL);
            date_t start_time = cm_now();
            ret = cms_seek_write_file(lock, lock->flock);
            cms_refresh_last_check_time(start_time);
            if (ret != CT_SUCCESS) {
                cms_reopen_lock_file(lock);
                continue;
            }
        }
        cm_thread_unlock(&lock->slock);
        return CT_SUCCESS;
    } while (cnt <= 1);
    cm_thread_unlock(&lock->slock);
    cms_exec_exit_proc();
    return ret;
}

status_t cms_seek_write_master_lock(cms_disk_lock_t* lock, cms_flock_t* lock_info)
{
    status_t ret;
    int64 seek_offset = cm_seek_file(lock->fd, lock->flock->l_start, SEEK_SET);
    if (seek_offset != lock->flock->l_start) {
        CMS_LOG_ERR("file seek failed:%s:%llu,%d:%s",
            lock->flock->file_name, lock->flock->l_start, errno, strerror(errno));
        if (cm_unlock_range_fd(lock->fd, lock->flock->l_start, lock->flock->l_len) != CT_SUCCESS) {
            CMS_LOG_ERR("cms unlock file failed:%s:%llu-%llu", lock->flock->file_name, lock->flock->l_start,
                lock->flock->l_len);
        }
        return CT_ERROR;
    }
    ret = cm_write_file(lock->fd, lock_info, sizeof(cms_flock_t));
    CMS_SYNC_POINT_GLOBAL_START(CMS_DISK_UNLOCK_FILE_WRITE_FAIL, &ret, CT_ERROR);
    CMS_SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("file write failed:%s:%llu,%d:%s",
            lock->flock->file_name, lock->flock->l_start, errno, strerror(errno));
        if (cm_unlock_range_fd(lock->fd, lock->flock->l_start, lock->flock->l_len) != CT_SUCCESS) {
            CMS_LOG_ERR("cms unlock file failed:%s:%llu-%llu", lock->flock->file_name, lock->flock->l_start,
                lock->flock->l_len);
        }
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cms_write_master_lock_with_dbs(cms_disk_lock_t* lock, cms_flock_t* lock_info, uint8 lock_type)
{
    if (lock->fd_len < CMS_DBS_LAST_DIR_HANDLE_IDX) {
        CMS_LOG_ERR("cms write master info dbs fd len(%d) invalid.", lock->fd_len);
        return CT_ERROR;
    }
    uint64 offset = lock->flock->l_start;
    object_id_t* dbs_fd = &lock->dbs_fd[lock->fd_len - CMS_DBS_LAST_DIR_HANDLE_IDX];
    status_t ret = cm_write_dbs_file(dbs_fd, lock->file_name, offset, lock_info, sizeof(cms_flock_t));
    CMS_SYNC_POINT_GLOBAL_START(CMS_DISK_UNLOCK_FILE_WRITE_FAIL, &ret, CT_ERROR);
    CMS_SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("dbs write failed:%s:%llu,%d:%s",
            lock->flock->file_name, lock->flock->l_start, errno, strerror(errno));
        if (cm_unlock_range_dbs(lock->fd, lock_type) != 0) {
            CMS_LOG_ERR("cms unlock(%s) type(%d) start(%llu) len(%llu) failed.",
                lock->file_name, lock_type, lock->flock->l_start, lock->flock->l_len);
        }
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cms_seek_write_master_info(cms_disk_lock_t* lock, cms_master_info_t* data_info, uint64 offset)
{
    status_t ret;
    int64 seek_offset = cm_seek_file(lock->fd, offset, SEEK_SET);
    if (seek_offset != offset) {
        CMS_LOG_ERR("file seek failed:%s:%llu,%d:%s", lock->flock->file_name, offset, errno, strerror(errno));
        if (cm_unlock_range_fd(lock->fd, lock->flock->l_start, lock->flock->l_len) != CT_SUCCESS) {
            CMS_LOG_ERR("cms unlock file failed:%s:%llu-%llu", lock->flock->file_name, lock->flock->l_start,
                lock->flock->l_len);
        }
        return CT_ERROR;
    }
    ret = cm_write_file(lock->fd, data_info, sizeof(cms_master_info_t));
    CMS_SYNC_POINT_GLOBAL_START(CMS_DISK_UNLOCK_FILE_WRITE_FAIL, &ret, CT_ERROR);
    CMS_SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("file write failed:%s:%llu,%d:%s", lock->flock->file_name, offset, errno, strerror(errno));
        if (cm_unlock_range_fd(lock->fd, lock->flock->l_start, lock->flock->l_len) != CT_SUCCESS) {
            CMS_LOG_ERR("cms unlock file failed:%s:%llu-%llu", lock->flock->file_name, lock->flock->l_start,
                lock->flock->l_len);
        }
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cms_write_master_info_with_dbs(cms_disk_lock_t* lock, cms_master_info_t* data_info, uint64 offset, uint8 type)
{
    if (lock->fd_len < CMS_DBS_LAST_DIR_HANDLE_IDX) {
        CMS_LOG_ERR("cms write master info dbs fd len(%d) invalid.", lock->fd_len);
        return CT_ERROR;
    }
    object_id_t* dbs_fd = &lock->dbs_fd[lock->fd_len - CMS_DBS_LAST_DIR_HANDLE_IDX];
    status_t ret = cm_write_dbs_file(dbs_fd, lock->file_name, offset, data_info, sizeof(cms_master_info_t));
    CMS_SYNC_POINT_GLOBAL_START(CMS_DISK_UNLOCK_FILE_WRITE_FAIL, &ret, CT_ERROR);
    CMS_SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("file write failed:%s: %llu", lock->flock->file_name, offset);
        if (cm_unlock_range_dbs(lock->fd, type) != 0) {
            CMS_LOG_ERR("cms unlock(%s) type(%d) start(%llu) len(%llu) failed.",
                lock->file_name, type, lock->flock->l_start, lock->flock->l_len);
        }
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t cms_lock_range_fd(cms_disk_lock_t* lock, uint8 lock_type)
{
    status_t ret = CT_ERROR;
    if (lock_type == DISK_LOCK_WRITE) {
        ret = cm_lockw_range_fd(lock->fd, lock->flock->l_start, lock->flock->l_len);
    } else if (lock_type == DISK_LOCK_READ) {
        ret = cm_lockr_range_fd(lock->fd, lock->flock->l_start, lock->flock->l_len);
    }
    return ret;
}

static status_t cms_disk_lock_try_lock_nfs(cms_disk_lock_t* lock, uint8 lock_type)
{
    status_t ret = CT_ERROR;
    int cnt = 0;
    cm_thread_lock(&lock->slock);
    do {
        ++cnt;
        if (lock_type != DISK_LOCK_WRITE && lock_type != DISK_LOCK_READ) {
            CMS_LOG_ERR("invalid lock type(%u), file lock failed:%s:%llu-%llu", lock_type, lock->flock->file_name,
                lock->flock->l_start, lock->flock->l_len);
            break;
        }

        ret = cms_lock_range_fd(lock, lock_type);
        CMS_SYNC_POINT_GLOBAL_START(CMS_DISK_LOCK_FILE_LOCK_FAIL, &ret, CT_ERROR);
        CMS_SYNC_POINT_GLOBAL_END;
        if (ret != CT_SUCCESS) {
            if (errno == EAGAIN) {
                cm_thread_unlock(&lock->slock);
                return CT_EAGAIN;
            }
            CMS_LOG_ERR("file lock(lock type(%u)) failed:%s:%llu-%llu,%d:%s", lock_type, lock->flock->file_name,
                lock->flock->l_start, lock->flock->l_len, errno, strerror(errno));
            cms_reopen_lock_file(lock);
            continue;
        }
        if (lock->flock->is_write == CT_TRUE && lock_type == DISK_LOCK_WRITE) {
            lock->flock->lock_time = time(NULL);
            date_t start_time = cm_now();
            ret = cms_seek_write_master_lock(lock, lock->flock);
            if (ret != CT_SUCCESS) {
                cms_reopen_lock_file(lock);
                continue;
            }
            g_master_info->magic = CMS_MASTER_INFO_MAGIC;
            g_master_info->node_id = lock->flock->node_id;
            g_master_info->lock_time = lock->flock->lock_time;
            ret = cms_seek_write_master_info(lock, g_master_info, CMS_BLOCK_SIZE);
            if (ret != CT_SUCCESS) {
                cms_reopen_lock_file(lock);
                continue;
            }
            cms_refresh_last_check_time(start_time);
        }
        cm_thread_unlock(&lock->slock);
        return CT_SUCCESS;
    } while (cnt <= 1);
    cm_thread_unlock(&lock->slock);
    cms_exec_exit_proc();
    return ret;
}

static status_t cms_disk_lock_try_lock_dbs(cms_disk_lock_t* lock, uint8 lock_type)
{
    if (lock_type != DISK_LOCK_WRITE && lock_type != DISK_LOCK_READ) {
        CMS_LOG_ERR("invalid lock type(%u),dbs lock file name:%s", lock_type, lock->file_name);
        return CT_ERROR;
    }
    status_t ret = CT_ERROR;
    int cnt = 0;
    cm_thread_lock(&lock->slock);
    do {
        ++cnt;
        ret = cm_lock_range_dbs(lock->fd, lock_type);
        CMS_SYNC_POINT_GLOBAL_START(CMS_DISK_LOCK_FILE_LOCK_FAIL, &ret, CT_ERROR);
        CMS_SYNC_POINT_GLOBAL_END;
        if (ret != CT_SUCCESS) {
            if (ret == CT_EAGAIN) {
                cm_thread_unlock(&lock->slock);
                return CT_EAGAIN;
            }
            CMS_LOG_ERR("cms dbs lock(lock type(%u)) name(%s) start(%llu) len(%llu) failed(%d).",
                        lock_type, lock->file_name, lock->flock->l_start, lock->flock->l_len, ret);
            cm_sleep(CM_LOCK_DBS_TRY_INTERVAL);
            continue;
        }
        // 只有master锁的is_write为true，表示是否需要将master锁信息落盘
        if (lock->flock->is_write == CT_TRUE && lock_type == DISK_LOCK_WRITE) {
            lock->flock->lock_time = time(NULL);
            date_t start_time = cm_now();
            // 写lock信息，失败会解锁
            ret = cms_write_master_lock_with_dbs(lock, lock->flock, lock_type);
            if (ret != CT_SUCCESS) {
                cm_sleep(CM_LOCK_DBS_TRY_INTERVAL);
                continue;
            }
            g_master_info->magic = CMS_MASTER_INFO_MAGIC;
            g_master_info->node_id = lock->flock->node_id;
            g_master_info->lock_time = lock->flock->lock_time;
            // 写master信息，失败会解锁
            ret = cms_write_master_info_with_dbs(lock, g_master_info, CMS_BLOCK_SIZE, lock_type);
            if (ret != CT_SUCCESS) {
                cm_sleep(CM_LOCK_DBS_TRY_INTERVAL);
                continue;
            }
            cms_refresh_last_check_time(start_time);
        }
        cm_thread_unlock(&lock->slock);
        return CT_SUCCESS;
    } while (cnt <= 1);
    cm_thread_unlock(&lock->slock);
    cms_exec_exit_proc();
    return ret;
}

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
status_t _cms_disk_try_lock(cms_disk_lock_t* lock, uint8 lock_type, const char* file, int32 line)
{
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
            if (cm_lockw_file_fd(lock->fd) != CT_SUCCESS) {
                cm_thread_unlock(&lock->tlock);
                return CT_ERROR;
            }
        }
        ret = cms_disk_lock_try_lock_sd(lock);
        if (ret != CT_SUCCESS) {
            if (lock->flag & CMS_DLOCK_PROCESS) {
                cm_unlock_file_fd(lock->fd);
            }
        }
    } else if (lock->type == CMS_DEV_TYPE_NFS) {
        ret = cms_disk_lock_try_lock_nfs(lock, lock_type);
    } else if (lock->type == CMS_DEV_TYPE_FILE) {
        ret = cms_disk_lock_try_lock_file(lock, lock_type);
    } else if (lock->type == CMS_DEV_TYPE_DBS) {
        ret = cms_disk_lock_try_lock_dbs(lock, lock_type);
    } else {
        CMS_LOG_ERR("invalid device type, type %d", lock->type);
        ret = CT_ERROR;
    }

    if (ret != CT_SUCCESS) {
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

status_t cms_disk_try_lock_timeout(cms_disk_lock_t* lock, uint32 timeout_ms, uint8 lock_type)
{
    status_t ret = CT_ERROR;
    date_t start_time = cm_monotonic_now();
    while (1) {
        ret = cms_disk_try_lock(lock, lock_type);
        CMS_SYNC_POINT_GLOBAL_START(CMS_DISK_LOCK_FILE_RANGE_LOCK_FAIL, &ret, CT_ERROR);
        CMS_SYNC_POINT_GLOBAL_END;
        if (ret == CT_SUCCESS) {
            date_t end_time = cm_monotonic_now();
            date_t cost_time = end_time - start_time;
            if (cost_time > timeout_ms * MICROSECS_PER_MILLISEC) {
                CMS_LOG_WAR("cms_disk_lock timeout:%s:%lld:%lld us.", lock->dev_name, lock->offset, cost_time);
            }
            return ret;
        } else if (ret == CT_EAGAIN) {
            date_t end_time = cm_monotonic_now();
            if (end_time > start_time + timeout_ms * MICROSECS_PER_MILLISEC) {
                CMS_LOG_DEBUG_ERR("cms_disk_lock timeout:%s:%lld.", lock->dev_name, lock->offset);
                return CT_ERROR;
            }
            cm_sleep(CMS_LOCK_TRY_INTERVAL);
        } else {
            CMS_LOG_DEBUG_ERR("cms_disk_lock failed:%s:%lld.", lock->dev_name, lock->offset);
            return ret;
        }
    }
    return CT_ERROR;
}

status_t cms_disk_lock(cms_disk_lock_t* lock, uint32 timeout_ms, uint8 lock_type)
{
    status_t ret = CT_ERROR;

    if (timeout_ms == 0) {
        while (1) {
            ret = cms_disk_try_lock(lock, lock_type);
            if (ret == CT_EAGAIN) {
                cm_sleep(CMS_LOCK_TRY_INTERVAL);
            } else {
                return ret;
            }
        }
    } else {
        return cms_disk_try_lock_timeout(lock, timeout_ms, lock_type);
    }
    return CT_ERROR;
}

status_t cms_disk_unlock_file(cms_disk_lock_t* lock)
{
    int32 cnt = 0;
    status_t ret;
    cm_thread_lock(&lock->slock);
    do {
        ++cnt;
        if (lock->flock->is_write == CT_TRUE && cm_lockw_file_fd(lock->fd) == CT_SUCCESS) {
            date_t start_time = cm_now();
            ret = cms_seek_write_file(lock, g_invalid_lock);
            if (ret != CT_SUCCESS) {
                cms_reopen_lock_file(lock);
                continue;
            }
            cms_refresh_last_check_time(start_time);
        }
        ret = cm_unlock_file_fd(lock->fd);
        CMS_SYNC_POINT_GLOBAL_START(CMS_DISK_UNLOCK_FILE_UNLOCK_FAIL, &ret, CT_ERROR);
        CMS_SYNC_POINT_GLOBAL_END;
        if (ret != CT_SUCCESS) {
            CMS_LOG_ERR("file unlock failed:%s:%d,%d:%s", lock->dev_name, (int32)lock->offset, errno,
                strerror(errno));
            cms_reopen_lock_file(lock);
            continue;
        }
        cm_thread_unlock(&lock->slock);
        return CT_SUCCESS;
    } while (cnt <= 1);
    cm_thread_unlock(&lock->slock);
    cms_exec_exit_proc();
    return CT_ERROR;
}

status_t cms_disk_unlock_nfs(cms_disk_lock_t* lock)
{
    int32 cnt = 0;
    status_t ret;
    cm_thread_lock(&lock->slock);
    do {
        ++cnt;
        if (lock->flock->is_write == CT_TRUE &&
            cm_lockw_range_fd(lock->fd, lock->flock->l_start, lock->flock->l_len) == CT_SUCCESS) {
            date_t start_time = cm_now();
            ret = cms_seek_write_master_lock(lock, g_invalid_lock);
            if (ret != CT_SUCCESS) {
                cms_reopen_lock_file(lock);
                continue;
            }
            g_master_info->magic = CMS_MASTER_INFO_MAGIC;
            g_master_info->node_id = g_invalid_lock->node_id;
            g_master_info->lock_time = g_invalid_lock->lock_time;
            ret = cms_seek_write_master_info(lock, g_master_info, CMS_BLOCK_SIZE);
            if (ret != CT_SUCCESS) {
                cms_reopen_lock_file(lock);
                continue;
            }
            cms_refresh_last_check_time(start_time);
        }
        ret = cm_unlock_range_fd(lock->fd, lock->flock->l_start, lock->flock->l_len);
        CMS_SYNC_POINT_GLOBAL_START(CMS_DISK_UNLOCK_FILE_UNLOCK_FAIL, &ret, CT_ERROR);
        CMS_SYNC_POINT_GLOBAL_END;
        if (ret != CT_SUCCESS) {
            CMS_LOG_ERR("file unlock failed:%s:%llu-%llu,%d:%s", lock->flock->file_name, lock->flock->l_start,
                lock->flock->l_len, errno, strerror(errno));
            cms_reopen_lock_file(lock);
            continue;
        }
        cm_thread_unlock(&lock->slock);
        return CT_SUCCESS;
    } while (cnt <= 1);
    cm_thread_unlock(&lock->slock);
    cms_exec_exit_proc();
    return CT_ERROR;
}

status_t cms_disk_unlock_dbs(cms_disk_lock_t* lock, uint8_t lock_type)
{
    int32 cnt = 0;
    status_t ret;
    bool32 is_force = CT_FALSE;
    cm_thread_lock(&lock->slock);
    do {
        ++cnt;
        // 只有master锁的is_write才会为true
        if (lock->flock->is_write == CT_TRUE && cm_lock_range_dbs(lock->fd, DISK_LOCK_WRITE) == CT_SUCCESS) {
            date_t start_time = cm_now();
            is_force = CT_TRUE;
            ret = cms_write_master_lock_with_dbs(lock, g_invalid_lock, lock_type);
            if (ret != CT_SUCCESS) {
                continue;
            }
            g_master_info->magic = CMS_MASTER_INFO_MAGIC;
            g_master_info->node_id = g_invalid_lock->node_id;
            g_master_info->lock_time = g_invalid_lock->lock_time;
            ret = cms_write_master_info_with_dbs(lock, g_master_info, CMS_BLOCK_SIZE, lock_type);
            if (ret != CT_SUCCESS) {
                continue;
            }
            cms_refresh_last_check_time(start_time);
        }
        if (is_force == CT_FALSE) {
            ret = cm_unlock_range_dbs(lock->fd, lock_type);
        } else {
            ret = cm_unlock_range_dbs_force(lock->fd, lock_type);
        }
        CMS_SYNC_POINT_GLOBAL_START(CMS_DISK_UNLOCK_FILE_UNLOCK_FAIL, &ret, CT_ERROR);
        CMS_SYNC_POINT_GLOBAL_END;
        if (ret != CT_SUCCESS) {
            CMS_LOG_ERR("dbs unlock failed(%d) file name:%s start:%llu, len:%llu lock type:%d is_force:%d.",
                ret, lock->file_name, lock->flock->l_start, lock->flock->l_len, lock_type, is_force);
            cm_sleep(CMS_LOCK_TRY_INTERVAL);
            continue;
        }
        cm_thread_unlock(&lock->slock);
        return CT_SUCCESS;
    } while (cnt <= 1);
    cm_thread_unlock(&lock->slock);
    cms_exec_exit_proc();
    return CT_ERROR;
}

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
status_t _cms_disk_unlock(cms_disk_lock_t* lock, uint8 lock_type, const char* file, int32 line)
{
    CMS_LOG_DEBUG_INF("cms_disk_unlock:%s:%d", file, line);
#else
status_t cms_disk_unlock(cms_disk_lock_t* lock, uint8_t lock_type)
{
#endif
    status_t ret = CT_ERROR;
    if (lock->type == CMS_DEV_TYPE_SD) {
        ret = cm_disk_unlock_ex(&lock->dlock, lock->fd);
        if (lock->flag & CMS_DLOCK_PROCESS) {
            cm_unlock_file_fd(lock->fd);
        }
    } else if (lock->type == CMS_DEV_TYPE_NFS) {
        ret = cms_disk_unlock_nfs(lock);
    } else if (lock->type == CMS_DEV_TYPE_FILE) {
        ret = cms_disk_unlock_file(lock);
    } else if (lock->type == CMS_DEV_TYPE_DBS) {
        ret = cms_disk_unlock_dbs(lock, lock_type);
    } else {
        CMS_LOG_ERR("invalid device type, type %d", lock->type);
        return CT_ERROR;
    }

    if (lock->flag & CMS_DLOCK_THREAD) {
        cm_thread_unlock(&lock->tlock);
    }

    return ret;
}

void cms_disk_lock_destroy(cms_disk_lock_t* lock)
{
    if (lock->type == CMS_DEV_TYPE_DBS) {
        return;
    }
    cms_disk_unlock(lock, DISK_LOCK_READ);
    cm_destroy_thread_lock(&lock->tlock);
    if (lock->type == CMS_DEV_TYPE_SD) {
        cm_destory_dlock(&lock->dlock);
        cm_close_disk(lock->disk_handle);
        if (lock->flag & CMS_DLOCK_PROCESS) {
            cm_close_file(lock->fd);
        }
    } else if (lock->type == CMS_DEV_TYPE_FILE || lock->type == CMS_DEV_TYPE_NFS) {
        cm_close_file(lock->fd);
        CM_FREE_PTR(lock->flock);
    } else {
        CMS_LOG_ERR("lock destory invalid device type %d", lock->type);
    }
}

static status_t cms_seek_read_file(cms_disk_lock_t* lock, cms_flock_t* lock_info)
{
    status_t ret = CT_ERROR;
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
        CMS_SYNC_POINT_GLOBAL_START(CMS_DISK_GET_INST_FILE_READ_FAIL, &ret, CT_ERROR);
        CMS_SYNC_POINT_GLOBAL_END;
        if (ret != CT_SUCCESS) {
            CMS_LOG_ERR("cm read file failed, %s %llu", lock->dev_name, lock->offset);
            cms_reopen_lock_file(lock);
            continue;
        }
        return CT_SUCCESS;
    } while (cnt <= 1);
    cms_exec_exit_proc();
    return ret;
}

static status_t cms_seek_read_master_info(cms_disk_lock_t* lock, cms_master_info_t* master_info, uint64 offset)
{
    status_t ret = CT_ERROR;
    int32 cnt = 0;
    do {
        ++cnt;
        int64 seek_offset = cm_seek_file(lock->fd, offset, SEEK_SET);
        if (seek_offset != offset) {
            CMS_LOG_ERR("cm seek file failed, %s %llu", lock->dev_name, offset);
            cms_reopen_lock_file(lock);
            continue;
        }
        ret = cm_read_file(lock->fd, master_info, sizeof(cms_master_info_t), NULL);
        CMS_SYNC_POINT_GLOBAL_START(CMS_DISK_GET_INST_FILE_READ_FAIL, &ret, CT_ERROR);
        CMS_SYNC_POINT_GLOBAL_END;
        if (ret != CT_SUCCESS) {
            CMS_LOG_ERR("cm read file failed, %s %llu", lock->dev_name, offset);
            cms_reopen_lock_file(lock);
            continue;
        }
        return CT_SUCCESS;
    } while (cnt <= 1);
    cms_exec_exit_proc();
    return ret;
}

static status_t cms_read_dbs_master_info(cms_disk_lock_t* lock, cms_master_info_t* master_info, uint64 offset)
{
    status_t ret = CT_ERROR;
    int32 cnt = 0;
    object_id_t* dbs_dir_handle = NULL;
    object_id_t* dbs_file_handle = NULL;
    do {
        ++cnt;
        int fd_len = lock->fd_len;
        if (fd_len <= CMS_DBS_LAST_DIR_HANDLE_IDX || lock->dbs_fd == NULL || lock->flock == NULL) {
            CMS_LOG_ERR("cms read dbs master file error, file(%s) not open.", lock->dev_name);
            break;
        }
        dbs_dir_handle = &lock->dbs_fd[fd_len - CMS_DBS_LAST_DIR_HANDLE_IDX];
        ret = cm_read_dbs_file(dbs_dir_handle, lock->file_name, offset, master_info, sizeof(cms_master_info_t));
        CMS_SYNC_POINT_GLOBAL_START(CMS_DISK_GET_INST_FILE_READ_FAIL, &ret, CT_ERROR);
        CMS_SYNC_POINT_GLOBAL_END;
        if (ret != CT_SUCCESS) {
            CMS_LOG_ERR("cm read dbs file %s offset %llu failed", lock->file_name, offset);
            dbs_file_handle = &lock->dbs_fd[fd_len - CMS_DBS_LAST_FILE_HANDLE_IDX];
            cm_open_dbs_file(dbs_dir_handle, lock->file_name, dbs_file_handle);
            continue;
        }
        return CT_SUCCESS;
    } while (cnt <= 1);
    cms_exec_exit_proc();
    return ret;
}

static status_t cms_disk_lock_get_data_sd(cms_disk_lock_t* lock, char* data, uint32 size)
{
#ifndef _WIN32
    dlock_t dlock;
    CT_RETURN_IFERR(cm_alloc_dlock(&dlock, lock->offset, lock->inst_id));
    if (cm_init_dlock(&dlock, lock->offset, lock->inst_id) != CT_SUCCESS) {
        cm_destory_dlock(&dlock);
        return CT_ERROR;
    }
    status_t status = cm_get_dlock_info(&dlock, lock->disk_handle);
    if (CT_SUCCESS != status) {
        cm_destory_dlock(&dlock);
        CT_LOG_DEBUG_ERR("Get lock info from dev failed.");
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
    return CT_SUCCESS;
}

static status_t cms_copy_master_data(uint64 magic, uint64 magic_check, char* out_buf, uint32 size, char* in_buf)
{
    errno_t err = EOK;
    date_t start_time = cm_now();
    if (out_buf == NULL || in_buf == NULL || size == 0) {
        CMS_LOG_ERR("cms lock get data param invalid.");
        return CT_ERROR;
    }
    if (magic != magic_check) {
        CMS_LOG_WAR("cms lock_info magic is invalid");
        err = memset_s(out_buf, size, 0, size);
        MEMS_RETURN_IFERR(err);
    }
    cms_refresh_last_check_time(start_time);
    if (memcpy_s(out_buf, size, in_buf, MIN(size, DISK_LOCK_BODY_LEN)) != EOK) {
        CMS_LOG_ERR("cms lock get data memcpy failed.");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t cms_disk_lock_get_data_file(cms_disk_lock_t* lock, char* data, uint32 size)
{
    cms_flock_t* lock_info = cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_flock_t));
    if (lock_info == NULL) {
        CMS_LOG_ERR("cms malloc lock_info failed, %s %llu", lock->dev_name, lock->offset);
        return CT_ERROR;
    }
    status_t ret = CT_SUCCESS;
    cm_thread_lock(&lock->slock);
    date_t start_time = cm_now();
    ret = cms_seek_read_file(lock, lock_info);
    cm_thread_unlock(&lock->slock);
    if (ret != CT_SUCCESS) {
        CM_FREE_PTR(lock_info);
        return CT_ERROR;
    }
    do {
        if (lock_info->magic != CMS_STAT_LOCK_MAGIC) {
            CMS_LOG_WAR("cms lock_info magic is invalid");
            ret = memset_s(data, size, 0, size);
            break;
        }
        cms_refresh_last_check_time(start_time);
        if (memcpy_s(data, size, lock_info->data, MIN(size, DISK_LOCK_BODY_LEN)) != CT_SUCCESS) {
            CMS_LOG_ERR("cms lock get data memcpy failed, %s %llu", lock->dev_name, lock->offset);
            ret = CT_ERROR;
            break;
        }
    } while (0);
    CM_FREE_PTR(lock_info);
    return ret;
}

static status_t cms_disk_lock_get_data_nfs(cms_disk_lock_t* lock, char* data, uint32 size)
{
    cms_master_info_t* master_info = cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_master_info_t));
    if (master_info == NULL) {
        CMS_LOG_ERR("cms malloc master_info failed, %s %llu", lock->dev_name, lock->offset);
        return CT_ERROR;
    }
    status_t ret = CT_SUCCESS;
    cm_thread_lock(&lock->slock);
    date_t start_time = cm_now();
    ret = cms_seek_read_master_info(lock, master_info, CMS_BLOCK_SIZE);
    cm_thread_unlock(&lock->slock);
    if (ret != CT_SUCCESS) {
        CM_FREE_PTR(master_info);
        return CT_ERROR;
    }
    do {
        if (master_info->magic != CMS_MASTER_INFO_MAGIC) {
            CMS_LOG_WAR("cms master_info magic is invalid");
            ret = memset_s(data, size, 0, size);
            break;
        }
        cms_refresh_last_check_time(start_time);
        if (memcpy_s(data, size, master_info->data, MIN(size, DISK_LOCK_BODY_LEN)) != CT_SUCCESS) {
            CMS_LOG_ERR("cms lock get data memcpy failed, %s %llu", lock->dev_name, lock->offset);
            ret = CT_ERROR;
            break;
        }
    } while (0);
    CM_FREE_PTR(master_info);
    return ret;
}

static status_t cms_disk_lock_get_data_dbs(cms_disk_lock_t* lock, char* data, uint32 size)
{
    cms_master_info_t* master_info = cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_master_info_t));
    if (master_info == NULL) {
        CMS_LOG_ERR("cms malloc master_info failed, %s %llu", lock->dev_name, lock->offset);
        return CT_ERROR;
    }
    status_t ret = CT_SUCCESS;
    do {
        cm_thread_lock(&lock->slock);
        ret = cms_read_dbs_master_info(lock, master_info, CMS_BLOCK_SIZE);
        cm_thread_unlock(&lock->slock);
        if (ret != CT_SUCCESS) {
            CMS_LOG_ERR("cms read dbs file failed, %s %llu", lock->dev_name, lock->offset);
            break;
        }
        ret = cms_copy_master_data(master_info->magic, CMS_MASTER_INFO_MAGIC, data, size, master_info->data);
        if (ret != CT_SUCCESS) {
            CMS_LOG_ERR("cms lock get data failed, %s %llu", lock->dev_name, lock->offset);
            break;
        }
    } while (0);
    CM_FREE_PTR(master_info);
    return ret;
}

status_t cms_disk_lock_get_data(cms_disk_lock_t* lock, char* data, uint32 size)
{
    if (lock->type == CMS_DEV_TYPE_SD) {
        return cms_disk_lock_get_data_sd(lock, data, size);
    } else if (lock->type == CMS_DEV_TYPE_FILE) {
        return cms_disk_lock_get_data_file(lock, data, size);
    } else if (lock->type == CMS_DEV_TYPE_NFS) {
        return cms_disk_lock_get_data_nfs(lock, data, size);
    } else if (lock->type == CMS_DEV_TYPE_DBS) {
        return cms_disk_lock_get_data_dbs(lock, data, size);
    } else {
        CMS_LOG_ERR("invalid device type, type %d", lock->type);
        return CT_ERROR;
    }
}

status_t cms_disk_lock_get_inst_sd(cms_disk_lock_t* lock, uint64* inst_id)
{
#ifndef _WIN32
    dlock_t dlock;
    CT_RETURN_IFERR(cm_alloc_dlock(&dlock, lock->offset, lock->inst_id));
    if (cm_init_dlock(&dlock, lock->offset, lock->inst_id) != CT_SUCCESS) {
        cm_destory_dlock(&dlock);
        return CT_ERROR;
    }
    status_t status = cm_get_dlock_info(&dlock, lock->disk_handle);
    if (CT_SUCCESS != status) {
        cm_destory_dlock(&dlock);
        CT_LOG_DEBUG_ERR("Get lock info from dev failed.");
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
            *inst_id = CT_INVALID_ID64;
        }
    } else {
        *inst_id = CT_INVALID_ID64;
    }
    cm_destory_dlock(&dlock);
#endif
    return CT_SUCCESS;
}

static status_t cms_disk_lock_get_inst_file(cms_disk_lock_t* lock, uint64* inst_id)
{
    cms_flock_t* lock_info = cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_flock_t));
    date_t start_time = cm_now();
    status_t ret;
    if (lock_info == NULL) {
        CMS_LOG_ERR("cms malloc lock_info failed, %s %llu", lock->dev_name, lock->offset);
        return CT_ERROR;
    }
    cm_thread_lock(&lock->slock);
    ret = cms_seek_read_file(lock, lock_info);
    cm_thread_unlock(&lock->slock);
    if (ret != CT_SUCCESS) {
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
            *inst_id = CT_INVALID_ID64;
        } else {
            *inst_id = CT_INVALID_ID64;
        }
    } else {
        CMS_LOG_WAR("lock info is invalid, lock_info magic is %llu", lock_info->magic);
        *inst_id = CT_INVALID_ID64;
    }
    cms_refresh_last_check_time(start_time);
    CM_FREE_PTR(lock_info);
    return CT_SUCCESS;
}

static void cms_get_inst_id_from_master_info(cms_disk_lock_t* lock, cms_master_info_t* master_info, uint64* inst_id)
{
    if (master_info->magic == CMS_MASTER_INFO_MAGIC) {
        time_t lock_time = master_info->lock_time;
        time_t now_time = time(NULL);
        time_t diff_time = now_time - lock_time;
        if (diff_time <= CMS_DISK_LOCK_TIMEOUT) {
            *inst_id = master_info->node_id;
        } else if (lock->active_func != NULL && lock->active_func(lock, master_info->node_id)) {
            CMS_LOG_WAR("lock[%s,%llu] hold by %d time out, diff_time %lu", lock->dev_name, lock->offset,
                master_info->node_id, diff_time);
            *inst_id = CT_INVALID_ID64;
        }
    } else {
        CMS_LOG_WAR("lock info is invalid, lock_info magic is %llu", master_info->magic);
        *inst_id = CT_INVALID_ID64;
    }
    return;
}

static status_t cms_disk_lock_get_inst_nfs(cms_disk_lock_t* lock, uint64* inst_id)
{
    cms_master_info_t* master_info = cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_master_info_t));
    date_t start_time = cm_now();
    status_t ret;
    if (master_info == NULL) {
        CMS_LOG_ERR("cms malloc master_info failed, %s %llu", lock->dev_name, lock->offset);
        return CT_ERROR;
    }
    cm_thread_lock(&lock->slock);
    ret = cms_seek_read_master_info(lock, master_info, CMS_BLOCK_SIZE);
    cm_thread_unlock(&lock->slock);
    if (ret != CT_SUCCESS) {
        CM_FREE_PTR(master_info);
        return ret;
    }
    cms_get_inst_id_from_master_info(lock, master_info, inst_id);
    cms_refresh_last_check_time(start_time);
    CM_FREE_PTR(master_info);
    return CT_SUCCESS;
}

static status_t cms_disk_lock_get_inst_dbs(cms_disk_lock_t* lock, uint64* inst_id)
{
    cms_master_info_t* master_info = cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_master_info_t));
    date_t start_time = cm_now();
    status_t ret;
    if (master_info == NULL) {
        CMS_LOG_ERR("cms malloc master_info failed, %s %llu", lock->dev_name, lock->offset);
        return CT_ERROR;
    }
    cm_thread_lock(&lock->slock);
    ret = cms_read_dbs_master_info(lock, master_info, CMS_BLOCK_SIZE);
    cm_thread_unlock(&lock->slock);
    if (ret != CT_SUCCESS) {
        CM_FREE_PTR(master_info);
        return ret;
    }
    cms_get_inst_id_from_master_info(lock, master_info, inst_id);
    cms_refresh_last_check_time(start_time);
    CM_FREE_PTR(master_info);
    return CT_SUCCESS;
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
    } else if (lock->type == CMS_DEV_TYPE_FILE) {
        return cms_disk_lock_get_inst_file(lock, inst_id);
    } else if (lock->type == CMS_DEV_TYPE_NFS) {
        return cms_disk_lock_get_inst_nfs(lock, inst_id);
    } else if (lock->type == CMS_DEV_TYPE_DBS) {
        return cms_disk_lock_get_inst_dbs(lock, inst_id);
    } else {
        CMS_LOG_ERR("invalid device type, type %d", lock->type);
        return CT_ERROR;
    }
}

static status_t cms_disk_lock_set_data_sd(cms_disk_lock_t* lock, char* data, uint32 size)
{
#ifndef _WIN32
    errno_t ret = memcpy_s(LOCKW_LOCK_BODY(lock->dlock), DISK_LOCK_BODY_LEN, data, size);
    MEMS_RETURN_IFERR(ret);
#endif
    return CT_SUCCESS;
}

static status_t cms_disk_lock_set_data_file(cms_disk_lock_t* lock, char* data, uint32 size)
{
    errno_t ret = memcpy_s(lock->flock->data, DISK_LOCK_BODY_LEN, data, MIN(size, DISK_LOCK_BODY_LEN));
    MEMS_RETURN_IFERR(ret);

    return CT_SUCCESS;
}

static status_t cms_disk_lock_set_data_nfs(cms_disk_lock_t* lock, char* data, uint32 size)
{
    errno_t ret = memcpy_s(g_master_info->data, DISK_LOCK_BODY_LEN, data, MIN(size, DISK_LOCK_BODY_LEN));
    MEMS_RETURN_IFERR(ret);

    return CT_SUCCESS;
}

status_t cms_disk_lock_set_data(cms_disk_lock_t* lock, char* data, uint32 size)
{
    if (lock->type == CMS_DEV_TYPE_SD) {
        return cms_disk_lock_set_data_sd(lock, data, size);
    } else if (lock->type == CMS_DEV_TYPE_FILE) {
        return cms_disk_lock_set_data_file(lock, data, size);
    } else if (lock->type == CMS_DEV_TYPE_NFS) {
        return cms_disk_lock_set_data_nfs(lock, data, size);
    } else if (lock->type == CMS_DEV_TYPE_DBS) {
        return cms_disk_lock_set_data_nfs(lock, data, size);
    } else {
        CMS_LOG_ERR("invalid device type, type %d", lock->type);
        return CT_ERROR;
    }
}
