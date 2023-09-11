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
 * cm_dlock.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_dlock.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_dlock.h"
#include "cm_log.h"
#include "cm_date.h"
#include "cm_utils.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

status_t cm_alloc_dlock(dlock_t *lock, uint64 lock_addr, int64 inst_id)
{
#ifdef WIN32
#else
    errno_t rc_memzero = EOK;
    uint64 buff_size = 3 * CM_DEF_BLOCK_SIZE + DISK_LOCK_ALIGN_SIZE_512;
    uint64 offset;

    if (lock_addr % CM_DEF_BLOCK_SIZE != 0) {
        GS_LOG_DEBUG_ERR("Invalid lock addr %llu, the addr value must be an integer multiple of the block size.",
                         lock_addr);
        return GS_ERROR;
    }

    if (NULL != lock) {
        rc_memzero = memset_sp(lock, sizeof(dlock_t), 0, sizeof(dlock_t));
        MEMS_RETURN_IFERR(rc_memzero);

        lock->buff = malloc(buff_size);
        if (lock->buff == NULL) {
            cm_reset_error();
            GS_THROW_ERROR(ERR_ALLOC_MEMORY, buff_size, "cm disk lock");
            return GS_ERROR;
        }

        rc_memzero = memset_sp(lock->buff, buff_size, 0, buff_size);
        if (rc_memzero != EOK) {
            CM_FREE_PTR(lock->buff);
            GS_THROW_ERROR(ERR_SYSTEM_CALL, rc_memzero);
            return GS_ERROR;
        }

        // three buff area, lockr buff|lockw buff|tmp buff
        offset = (DISK_LOCK_ALIGN_SIZE_512 - ((uint64)lock->buff) % DISK_LOCK_ALIGN_SIZE_512);
        lock->lockr = lock->buff + offset;
        lock->lockw = lock->lockr + CM_DEF_BLOCK_SIZE;
        lock->tmp = lock->lockw + CM_DEF_BLOCK_SIZE;

        rc_memzero = memset_sp(lock->lockw, CM_DEF_BLOCK_SIZE, 1, CM_DEF_BLOCK_SIZE);
        if (rc_memzero != EOK) {
            CM_FREE_PTR(lock->buff);
            GS_THROW_ERROR(ERR_SYSTEM_CALL, rc_memzero);
            return GS_ERROR;
        }

        cm_init_dlock_header(lock, lock_addr, inst_id);
    }

#endif
    return GS_SUCCESS;
}

status_t cm_init_dlock(dlock_t *lock, uint64 lock_addr, int64 inst_id)
{
#ifdef WIN32
#else
    errno_t rc_memzero = EOK;
    uint64 buff_size = 3 * CM_DEF_BLOCK_SIZE + DISK_LOCK_ALIGN_SIZE_512;

    if (NULL != lock) {
        rc_memzero = memset_sp(lock->buff, buff_size, 0, buff_size);
        MEMS_RETURN_IFERR(rc_memzero);

        rc_memzero = memset_sp(lock->lockw, CM_DEF_BLOCK_SIZE, 1, CM_DEF_BLOCK_SIZE);
        MEMS_RETURN_IFERR(rc_memzero);

        cm_init_dlock_header(lock, lock_addr, inst_id);
    }
#endif
    return GS_SUCCESS;
}

void cm_init_dlock_header(dlock_t *lock, uint64 lock_addr, int64 inst_id)
{
#ifdef WIN32
#else
    errno_t rc_memzero = EOK;

    if (NULL != lock) {
        // clear lockr header
        rc_memzero = memset_sp(lock->lockr, DISK_LOCK_HEADER_LEN, 0, DISK_LOCK_HEADER_LEN);
        MEMS_RETVOID_IFERR(rc_memzero);

        // set lockw members
        // header magic num
        LOCKW_LOCK_MAGICNUM(*lock) = DISK_LOCK_HEADER_MAGIC;
        // tail magic num
        int64 *tail_magic = (int64 *)(lock->lockw + CM_DEF_BLOCK_SIZE - sizeof(int64));
        *tail_magic = DISK_LOCK_HEADER_MAGIC;
        // LOCKW_INST_ID_P(lock) = inst_id + 1;
        LOCKW_INST_ID(*lock) = inst_id + 1;
        LOCKW_LOCK_VERSION(*lock) = DISK_LOCK_VERSION;
        lock->lock_addr = lock_addr;
    }
#endif
}

void cm_destory_dlock(dlock_t *lock)
{
#ifdef WIN32
#else
    CM_FREE_PTR(lock->buff);
#endif
    lock->buff = NULL;
}

int32 cm_disk_lock_s(dlock_t *lock, const char *scsi_dev)
{
#ifdef WIN32
#else
    int32 fd = 0;
    int32 ret;

    if (NULL == lock || NULL == scsi_dev) {
        return GS_ERROR;
    }

    fd = open(scsi_dev, O_RDWR | O_DIRECT | O_SYNC);
    if (fd < 0) {
        GS_LOG_DEBUG_ERR("Open dev %s failed, errno %d.", scsi_dev, errno);
        return GS_ERROR;
    }

    ret = cm_disk_lock(lock, fd);
    if (GS_SUCCESS != ret) {
        close(fd);
        return ret;
    }

    close(fd);
#endif
    return GS_SUCCESS;
}

status_t cm_disk_timed_lock_s(dlock_t *lock, const char *scsi_dev, uint64 wait_usecs, int32 lock_interval,
                              uint32 dlock_retry_count)
{
#ifdef WIN32
#else
    // GS_LOG_DEBUG_INF("begin lock timeouts, %s.", scsi_dev);

    int32 fd = 0;
    status_t status = GS_SUCCESS;

    if (NULL == lock || NULL == scsi_dev) {
        return GS_ERROR;
    }

    fd = open(scsi_dev, O_RDWR | O_DIRECT | O_SYNC);
    if (fd < 0) {
        GS_LOG_DEBUG_ERR("Open dev %s failed, errno %d.", scsi_dev, errno);
        return GS_ERROR;
    }

    status = cm_disk_timed_lock(lock, fd, wait_usecs, lock_interval, dlock_retry_count);
    if (GS_SUCCESS != status) {
        close(fd);
        return status;
    }

    close(fd);
    // GS_LOG_DEBUG_INF("end lock timeouts");
#endif
    return GS_SUCCESS;
}

int32 cm_disk_lockf_s(dlock_t *lock, const char *scsi_dev)
{
#ifdef WIN32
#else
    int32 fd = 0;
    int32 ret = GS_SUCCESS;

    if (NULL == lock || NULL == scsi_dev) {
        return GS_ERROR;
    }

    fd = open(scsi_dev, O_RDWR | O_DIRECT | O_SYNC);
    if (fd < 0) {
        GS_LOG_DEBUG_ERR("Open dev %s failed, errno %d.", scsi_dev, errno);
        return GS_ERROR;
    }

    ret = cm_disk_lockf(lock, fd);
    if (ret != GS_SUCCESS) {
        close(fd);
        return ret;
    }

    close(fd);
#endif
    return GS_SUCCESS;
}

status_t cm_disk_unlock_s(dlock_t *lock, const char *scsi_dev)
{
#ifdef WIN32
#else
    int32 fd = 0;
    status_t status = GS_SUCCESS;

    if (NULL == lock || NULL == scsi_dev) {
        return GS_ERROR;
    }

    fd = open(scsi_dev, O_RDWR | O_DIRECT | O_SYNC);
    if (fd < 0) {
        GS_LOG_DEBUG_ERR("Open dev %s failed, errno %d.", scsi_dev, errno);
        return GS_ERROR;
    }

    status = cm_disk_unlock(lock, fd);
    if (GS_SUCCESS != status) {
        close(fd);
        return status;
    }

    close(fd);
#endif
    return GS_SUCCESS;
}

status_t cm_disk_unlockf_s(dlock_t *lock, const char *scsi_dev, int64 old_inst_id)
{
#ifdef WIN32
#else
#endif
    return GS_SUCCESS;
}

int32 cm_preempt_dlock_s(dlock_t *lock, const char *scsi_dev)
{
#ifdef WIN32
#else
    int32 ret = 0;
    int32 fd = 0;

    if (NULL == lock || NULL == scsi_dev) {
        return GS_ERROR;
    }

    fd = open(scsi_dev, O_RDWR | O_DIRECT | O_SYNC);
    if (fd < 0) {
        GS_LOG_DEBUG_ERR("Open dev %s failed, errno %d.", scsi_dev, errno);
        return GS_ERROR;
    }

    ret = cm_preempt_dlock(lock, fd);
    if (GS_SUCCESS != ret) {
        close(fd);
        return ret;
    }
    close(fd);
#endif
    return GS_SUCCESS;
}

status_t cm_erase_dlock_s(dlock_t *lock, const char *scsi_dev)
{
#ifdef WIN32
#else
    int32 fd = 0;
    status_t status = GS_SUCCESS;

    if (NULL == lock || NULL == scsi_dev) {
        return GS_ERROR;
    }

    fd = open(scsi_dev, O_RDWR | O_DIRECT | O_SYNC);
    if (fd < 0) {
        GS_LOG_DEBUG_ERR("Open dev %s failed, errno %d.", scsi_dev, errno);
        return GS_ERROR;
    }

    status = cm_erase_dlock(lock, fd);
    if (GS_SUCCESS != status) {
        close(fd);
        return status;
    }

    close(fd);
#endif
    return GS_SUCCESS;
}

status_t cm_get_dlock_info_s(dlock_t *lock, const char *scsi_dev)
{
#ifdef WIN32
#else
    int32 status = 0;
    int32 fd = 0;

    if (NULL == lock || NULL == scsi_dev) {
        return GS_ERROR;
    }

    fd = open(scsi_dev, O_RDWR | O_DIRECT | O_SYNC);
    if (fd < 0) {
        GS_LOG_DEBUG_ERR("Open dev %s failed, errno %d.", scsi_dev, errno);
        return GS_ERROR;
    }

    status = cm_get_dlock_info(lock, fd);
    if (GS_SUCCESS != status) {
        GS_LOG_DEBUG_ERR("Get lock info from dev %s failed.", scsi_dev);
        close(fd);
        return status;
    }

    close(fd);
#endif
    return GS_SUCCESS;
}

int32 cm_disk_lock(dlock_t *lock, int32 fd)
{
    int32 buff_len = 2 * CM_DEF_BLOCK_SIZE;
    int32 ret;
    status_t status = GS_SUCCESS;

    if (NULL == lock || fd < 0) {
        return GS_ERROR;
    }

#ifdef WIN32
#else
    GS_LOG_DEBUG_INF("begin lock.");
    time_t t = time(NULL);
    LOCKW_LOCK_TIME(*lock) = t;
    LOCKW_LOCK_CREATE_TIME(*lock) = t;
    ret = cm_scsi3_caw(fd, lock->lock_addr / CM_DEF_BLOCK_SIZE, lock->lockr, buff_len);
    if (GS_SUCCESS != ret) {
        if (CM_SCSI_ERR_MISCOMPARE != ret) {
            GS_LOG_DEBUG_ERR("Scsi3 caw failed, addr %llu.", lock->lock_addr);
            return GS_ERROR;
        }
    } else {
        GS_LOG_DEBUG_INF("lock succ.");
        return GS_SUCCESS;
    }

    // there is a lock on disk, get lock info
    status = cm_get_dlock_info(lock, fd);
    if (GS_SUCCESS != status) {
        GS_LOG_DEBUG_ERR("Get lock info from dev failed.");
        return GS_ERROR;
    }

    // if the owner of the lock on the disk is the current instance, we can lock succ
    LOCKR_INST_ID(*lock) = LOCKW_INST_ID(*lock);
    LOCKW_LOCK_CREATE_TIME(*lock) = LOCKR_LOCK_CREATE_TIME(*lock);
    ret = cm_scsi3_caw(fd, lock->lock_addr / CM_DEF_BLOCK_SIZE, lock->lockr, buff_len);
    if (GS_SUCCESS != ret) {
        if (CM_SCSI_ERR_MISCOMPARE == ret) {
            // the lock is hold by another instance
            return CM_DLOCK_ERR_LOCK_OCCUPIED;
        } else {
            GS_LOG_DEBUG_ERR("Scsi3 caw failed, addr %llu.", lock->lock_addr);
            return GS_ERROR;
        }
    }
#endif
    GS_LOG_DEBUG_INF("lock succ.");
    return GS_SUCCESS;
}

status_t cm_disk_timed_lock(dlock_t *lock, int32 fd, uint64 wait_usecs, int32 lock_interval, uint32 dlock_retry_count)
{
#ifdef WIN32
    return GS_SUCCESS;
#else
    // GS_LOG_DEBUG_INF("Begin lock with time, fd %d.", fd);
    int32 ret = 0;
    uint64 usecs = 0;
    timeval_t tv_begin, tv_end;
    uint32 disk_lock_interval = DISK_DEFAULT_LOCK_INTERVAL;
    uint32 times = 0;

    if (NULL == lock || fd < 0) {
        return GS_ERROR;
    }

    if (lock_interval > 0) {
        disk_lock_interval = lock_interval;
    }

    (void)cm_gettimeofday(&tv_begin);
    for (;;) {
        ret = cm_disk_lock(lock, fd);
        if (ret == GS_SUCCESS) {
            // GS_LOG_DEBUG_INF("Lock with time succ.");
            return GS_SUCCESS;
        } else {
            // cm_get_error(&code, &msg, NULL);
            if (ret == CM_DLOCK_ERR_LOCK_OCCUPIED) {
                GS_LOG_DEBUG_INF("Lock occupied, try to lock again, fd %d.", fd);
            } else {
                GS_LOG_DEBUG_ERR("Scsi3 caw failed, addr %llu.", lock->lock_addr);
                return GS_ERROR;
            }
        }

        (void)cm_gettimeofday(&tv_end);
        usecs = TIMEVAL_DIFF_US(&tv_begin, &tv_end);
        if (usecs >= wait_usecs) {
            GS_LOG_DEBUG_INF("Lock with time timeout.");
            return GS_TIMEDOUT;
        }

        times++;
        if (times == dlock_retry_count) {
            cm_usleep(disk_lock_interval);
            times = 0;
        }
    }
#endif
}

int32 cm_disk_lockf(dlock_t *lock, int32 fd)
{
#ifdef WIN32
#else
    status_t status = GS_SUCCESS;
    int32 ret = 0;

    if (NULL == lock || fd < 0) {
        return GS_ERROR;
    }

    status = cm_get_dlock_info(lock, fd);
    if (GS_SUCCESS != status) {
        GS_LOG_DEBUG_ERR("Get lock info from dev failed, fd %d.", fd);
        return GS_ERROR;
    }

    ret = cm_disk_lock(lock, fd);
    if (GS_SUCCESS != ret) {
        return ret;
    }
#endif
    return GS_SUCCESS;
}

status_t cm_disk_unlock_interal(dlock_t *lock, int32 fd, bool32 clean_body)
{
#ifdef WIN32
#else
    errno_t rc_memzero = EOK;
    status_t status = GS_SUCCESS;
    int32 ret = 0;
    int32 buff_len = 2 * CM_DEF_BLOCK_SIZE;

    if (NULL == lock || fd < 0) {
        return GS_ERROR;
    }

    status = cm_get_dlock_info(lock, fd);
    if (GS_SUCCESS != status) {
        GS_LOG_DEBUG_ERR("Get lock info from dev failed, fd %d.", fd);
        return status;
    }

    if (LOCKR_INST_ID(*lock) == 0) {
        GS_LOG_DEBUG_INF("Unlock succ, ther is no lock on disk.");
        return GS_SUCCESS;
    }

    if (LOCKR_INST_ID(*lock) != LOCKW_INST_ID(*lock)) {
        GS_LOG_DEBUG_ERR(
            "Unlock failed, this lock is held by another instance, another inst_id(disk) %lld, curr inst_id(lock) %lld.",
            LOCKR_INST_ID(*lock), LOCKW_INST_ID(*lock));
        cm_reset_error();
        GS_THROW_ERROR(ERR_SCSI_LOCK_OCCUPIED);
        return GS_ERROR;
    }

    if (clean_body) {
        // clear write area for caw
        rc_memzero = memset_sp(lock->lockw, CM_DEF_BLOCK_SIZE, 0, CM_DEF_BLOCK_SIZE);
        MEMS_RETURN_IFERR(rc_memzero);
    } else {
        // just clean lock header
        rc_memzero = memcpy_s(lock->lockw, CM_DEF_BLOCK_SIZE, lock->lockr, CM_DEF_BLOCK_SIZE);
        MEMS_RETURN_IFERR(rc_memzero);
        rc_memzero = memset_sp(lock->lockw, DISK_LOCK_HEADER_LEN, 0, DISK_LOCK_HEADER_LEN);
        MEMS_RETURN_IFERR(rc_memzero);
    }
    ret = cm_scsi3_caw(fd, lock->lock_addr / CM_DEF_BLOCK_SIZE, lock->lockr, buff_len);
    if (GS_SUCCESS != ret) {
        GS_LOG_DEBUG_ERR("Scsi3 caw failed, addr %llu, ret %d.", lock->lock_addr, ret);
        return GS_ERROR;
    }
#endif
    return GS_SUCCESS;
}

status_t cm_disk_unlock(dlock_t *lock, int32 fd)
{
#ifdef WIN32
#else
    status_t status = GS_SUCCESS;

    status = cm_disk_unlock_interal(lock, fd, GS_TRUE);
    if (GS_SUCCESS != status) {
        return status;
    }
#endif
    return GS_SUCCESS;
}

status_t cm_disk_unlock_ex(dlock_t *lock, int32 fd)
{
#ifdef WIN32
#else
    status_t status = GS_SUCCESS;

    status = cm_disk_unlock_interal(lock, fd, GS_FALSE);
    if (GS_SUCCESS != status) {
        return status;
    }
#endif
    return GS_SUCCESS;
}

status_t cm_disk_unlockf(dlock_t *lock, int32 fd, int64 old_inst_id)
{
#ifdef WIN32
#else
#endif
    return GS_SUCCESS;
}

status_t cm_erase_dlock(dlock_t *lock, int32 fd)
{
#ifdef WIN32
#else
    int32 size = 0;

    if (NULL == lock || fd < 0) {
        return GS_ERROR;
    }

    if (lseek64(fd, (off64_t)lock->lock_addr, SEEK_SET) == -1) {
        GS_LOG_DEBUG_ERR("Seek failed, addr %llu, errno %d.", lock->lock_addr, errno);
        return GS_ERROR;
    }

    size = write(fd, lock->lockr, CM_DEF_BLOCK_SIZE);
    if (size == -1) {
        GS_LOG_DEBUG_ERR("Write failed, ret %d, errno %d.", size, errno);
        return GS_ERROR;
    }
#endif
    return GS_SUCCESS;
}

int32 cm_preempt_dlock(dlock_t *lock, int32 fd)
{
#ifdef WIN32
#else
    int32 ret = 0;
    int32 buff_len = 2 * CM_DEF_BLOCK_SIZE;

    if (NULL == lock) {
        return GS_ERROR;
    }

    time_t t = time(NULL);
    LOCKW_LOCK_TIME(*lock) = t;
    LOCKW_LOCK_CREATE_TIME(*lock) = t;
    ret = cm_scsi3_caw(fd, lock->lock_addr / CM_DEF_BLOCK_SIZE, lock->lockr, buff_len);
    if (GS_SUCCESS != ret) {
        if (CM_SCSI_ERR_MISCOMPARE == ret) {
            return CM_DLOCK_ERR_LOCK_OCCUPIED;
        } else {
            GS_LOG_DEBUG_ERR("Scsi3 caw failed, addr %llu.", lock->lock_addr);
            return GS_ERROR;
        }
    }
#endif
    return GS_SUCCESS;
}

status_t cm_get_dlock_info(dlock_t *lock, int32 fd)
{
#ifdef WIN32
#else
    int32 size = 0;

    if (NULL == lock || fd < 0) {
        return GS_ERROR;
    }

    if (lseek64(fd, (off64_t)lock->lock_addr, SEEK_SET) == -1) {
        GS_LOG_DEBUG_ERR("Seek failed, addr %llu, errno %d.", lock->lock_addr, errno);
        return GS_ERROR;
    }

    size = read(fd, lock->lockr, CM_DEF_BLOCK_SIZE);
    if (size == -1) {
        GS_LOG_DEBUG_ERR("Read lockr info failed, ret %d, errno %d.", size, errno);
        return GS_ERROR;
    }
#endif
    return GS_SUCCESS;
}
