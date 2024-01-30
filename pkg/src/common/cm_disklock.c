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
 * cm_disklock.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_disklock.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_common_module.h"
#include "cm_disklock.h"
#include <time.h>
#include "cm_file.h"
#include "cm_date.h"
#include "cm_disk.h"

#define CM_LOCK_MAGIC (*((uint64 *)"CM_LOCK"))
#define CM_FILE_LOCK_CNT 11
#define CM_ENV_DISKLOCK_HOME (char *)"CTDB_HOME"

status_t cm_disk_lock_init(cm_disk_lock_t *lock, uint32 inst_id, uint32 uid)
{
    CT_LOG_DEBUG_INF("cm disk lock init, inst_id:%d", inst_id);
    uint32 temp_id = uid % CM_FILE_LOCK_CNT;
    const char *file_dev = "cm_disk";
    char file_name[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    cm_init_thread_lock(&lock->tlock);
    lock->flock.lock_time = time(NULL);
    lock->flock.magic = CM_LOCK_MAGIC;
    lock->id = uid;
    lock->inst_id = inst_id;
    lock->lh_lock.lock = 0;
    lock->lh_lock.shared_count = 0;
    lock->lh_lock.unused = 0;
    lock->lh_lock.stat = 0;
    lock->lh_lock.sid = 0;

    char *dlock_home = getenv(CM_ENV_DISKLOCK_HOME);
    if (dlock_home == NULL) {
        CT_LOG_RUN_ERR("env $CTDB_HOME not exists.");
        return CT_ERROR;
    }
    errno_t ret = snprintf_s(file_name, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s/cm_disklock/", dlock_home);
    PRTS_RETURN_IFERR(ret);
    if (!cm_dir_exist(file_name)) {
        CT_RETURN_IFERR(cm_create_dir(file_name));
    }
    ret = snprintf_s(file_name, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s/cm_disklock/%s_%u.lock", dlock_home,
                     file_dev, temp_id);
    PRTS_RETURN_IFERR(ret);

    ret = snprintf_s(lock->dev_name, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s_%u.lock", file_dev, temp_id);
    PRTS_RETURN_IFERR(ret);

    CT_RETURN_IFERR(cm_open_file(file_name, O_CREAT | O_RDWR | O_BINARY | O_CLOEXEC, &lock->fd));

    return CT_SUCCESS;
}

void cm_destory_lock(cm_disk_lock_t *lock)
{
    if (cm_record_disk_unlock(lock) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cm_destory_lock failed");
    }
    cm_close_file(lock->fd);
}

status_t cm_disk_save_lockinfo(cm_disk_lock_t *lock)
{
    if (cm_seek_file(lock->fd, 0, SEEK_SET) != 0) {
        (void)cm_unlock_record_fd(lock->fd, lock->id);
        CT_LOG_RUN_ERR("file lock failed:%s,%d:%s", lock->dev_name, errno, strerror(errno));
        return CT_ERROR;
    }

    if (cm_write_file(lock->fd, &lock->flock, sizeof(cm_flock_t)) != CT_SUCCESS) {
        (void)cm_unlock_record_fd(lock->fd, lock->id);
        CT_LOG_RUN_ERR("file lock failed:%s,%d:%s", lock->dev_name, errno, strerror(errno));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cm_disk_mutex_try_lock(cm_disk_lock_t *lock)
{
    if (lock->lh_lock.stat == LATCH_STATUS_X) {
        return CT_TIMEDOUT;
    }
    status_t ret;
    cm_latch_x(&lock->lh_lock, 0, NULL);

    if (cm_lockw_record_fd(lock->fd, lock->id) != CT_SUCCESS) {
        if (errno == EAGAIN) {
            cm_unlatch(&lock->lh_lock, NULL);
            return CT_TIMEDOUT;
        } else {
            cm_unlatch(&lock->lh_lock, NULL);
            CT_LOG_RUN_ERR("mutex record lock failed:%s,%d:%s", lock->dev_name, errno, strerror(errno));
            return CT_ERROR;
        }
    }
    lock->flock.lock_time = time(NULL);

    ret = cm_disk_save_lockinfo(lock);
    if (ret != CT_SUCCESS) {
        cm_unlatch(&lock->lh_lock, NULL);
        CT_LOG_DEBUG_ERR("try lock file failed:%s", lock->dev_name);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cm_disk_latchs_try_lock(cm_disk_lock_t *lock)
{
    status_t ret;
    cm_latch_s(&lock->lh_lock, 0, CT_FALSE, NULL);
    if (cm_lockr_record_fd(lock->fd, lock->id) != CT_SUCCESS) {
        if (errno == EAGAIN) {
            cm_unlatch(&lock->lh_lock, NULL);
            return CT_TIMEDOUT;
        } else {
            cm_unlatch(&lock->lh_lock, NULL);
            CT_LOG_RUN_ERR("read record lock failed:%s,%d:%s", lock->dev_name, errno, strerror(errno));
            return CT_ERROR;
        }
    }
    lock->flock.lock_time = time(NULL);

    ret = cm_disk_save_lockinfo(lock);
    if (ret != CT_SUCCESS) {
        cm_unlatch(&lock->lh_lock, NULL);
        CT_LOG_DEBUG_ERR("try lock file failed:%s", lock->dev_name);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cm_disk_file_lock(cm_disk_lock_t *lock, uint8 lock_type)
{
    status_t ret;
    while (1) {
        switch (lock_type) {
            case DISK_LOCK_MUTEX:
                ret = cm_disk_mutex_try_lock(lock);
                break;
            case DISK_LOCK_LATCHX:
                ret = cm_disk_mutex_try_lock(lock);
                break;
            case DISK_LOCK_LATCHS:
                ret = cm_disk_latchs_try_lock(lock);
                break;
            default:
                ret = CT_ERROR;
                break;
        }
        if (ret == CT_TIMEDOUT) {
            cm_sleep(CM_LOCK_TRY_INTERVAL);
        } else {
            return ret;
        }
    }
    return CT_ERROR;
}

status_t cm_disk_timed_file_lock(cm_disk_lock_t *lock, uint32 timeout_ms, uint8 lock_type)
{
    status_t ret;
    date_t start_time;
    date_t end_time;

    if (timeout_ms == 0) {
        ret = cm_disk_file_lock(lock, lock_type);
        return ret;
    }
    start_time = cm_monotonic_now();
    while (1) {
        switch (lock_type) {
            case DISK_LOCK_MUTEX:
                ret = cm_disk_mutex_try_lock(lock);
                break;
            case DISK_LOCK_LATCHX:
                ret = cm_disk_mutex_try_lock(lock);
                break;
            case DISK_LOCK_LATCHS:
                ret = cm_disk_latchs_try_lock(lock);
                break;
            default:
                ret = CT_ERROR;
                break;
        }
        if (ret == CT_SUCCESS) {
            return ret;
        } else if (ret == CT_TIMEDOUT) {
            end_time = cm_monotonic_now();
            if (end_time > start_time + timeout_ms * MICROSECS_PER_MILLISEC) {
                CT_LOG_DEBUG_ERR("cm_disk_timed_file_lock timeout:%s.", lock->dev_name);
                return CT_ERROR;
            }
            cm_sleep(CM_LOCK_TRY_INTERVAL);
        } else {
            CT_LOG_DEBUG_ERR("cm_disk_timed_file_lock failed:%s.", lock->dev_name);
            return ret;
        }
    }

    return CT_ERROR;
}

status_t cm_disk_mutex_lock(cm_disk_lock_t *lock, uint32 timeout_ms)
{
    status_t ret = cm_disk_timed_file_lock(lock, timeout_ms, DISK_LOCK_MUTEX);
    if (ret != CT_SUCCESS) {
        CT_LOG_DEBUG_ERR("cm_disk_mutex_lock failed");
        return ret;
    }
    return ret;
}

status_t cm_disk_latchx_lock(cm_disk_lock_t *lock, uint32 timeout_ms)
{
    status_t ret = cm_disk_timed_file_lock(lock, timeout_ms, DISK_LOCK_LATCHX);
    if (ret != CT_SUCCESS) {
        CT_LOG_DEBUG_ERR("cm_disk_latchx_lock failed");
        return ret;
    }
    return ret;
}

status_t cm_disk_latchs_lock(cm_disk_lock_t *lock, uint32 timeout_ms)
{
    status_t ret = cm_disk_timed_file_lock(lock, timeout_ms, DISK_LOCK_LATCHS);
    if (ret != CT_SUCCESS) {
        CT_LOG_DEBUG_ERR("cm_disk_latchs_lock failed");
        return ret;
    }
    return ret;
}

status_t cm_record_disk_unlock(cm_disk_lock_t *lock)
{
    status_t ret;
    ret = cm_unlock_record_fd(lock->fd, lock->id);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cm_record_disk_unlock failed:%s,%d:%s", lock->dev_name, errno, strerror(errno));
    }
    cm_unlatch(&lock->lh_lock, NULL);
    return ret;
}

status_t cm_disk_mutex_unlock(cm_disk_lock_t *lock)
{
    return cm_record_disk_unlock(lock);
}

status_t cm_disk_latch_unlock(cm_disk_lock_t *lock)
{
    return cm_record_disk_unlock(lock);
}
