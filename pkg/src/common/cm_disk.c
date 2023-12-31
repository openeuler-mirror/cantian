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
 * cm_disk.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_disk.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_disk.h"
#ifndef WIN32
#include <pthread.h>
#endif
#include "cm_date.h"
#include "cm_date.h"
#include "cm_error.h"

#define CM_FILE_BLOCK_SIZE 8192
#define CM_DISK_PART_COUNT 16
#define CM_FILE_PART_BLOCK_SIZE 512
#define CM_OPERATE_FILE_INTERVAL 50

#ifdef WIN32
status_t cm_open_disk(const char *name, disk_handle_t *handle)
{
    *handle = CreateFile(name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0,
                         NULL);

    if (*handle == INVALID_HANDLE_VALUE) {
        DWORD code = GetLastError();
        GS_LOG_RUN_ERR("CreateFile failed");
        GS_THROW_ERROR(ERR_CM_OPEN_DISK, "open disk %s failed, errno %d", name, GS_ERRNO);
        return GS_ERROR;
    }

    GS_LOG_RUN_INF("CreateFile succeed\n");

    return GS_SUCCESS;
}

void cm_close_disk(disk_handle_t handle)
{
    (void)CloseHandle(handle);
}

uint64 cm_get_disk_size(disk_handle_t handle)
{
    DWORD low32, high32;
    uint64 size;

    low32 = GetFileSize(handle, &high32);
    if (low32 == INVALID_FILE_SIZE) {
        return 0;
    }

    size = (uint64)high32;
    size <<= 32;
    size += low32;
    return size;
}

status_t cm_seek_disk(disk_handle_t handle, uint64 offset)
{
    LONG low32, high32;

    low32 = (LONG)(offset & 0xFFFFFFFF);
    high32 = (LONG)(offset >> 32);
    if (SetFilePointer(handle, low32, &high32, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        GS_THROW_ERROR(ERR_CM_SEEK_DISK, GS_ERRNO);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t cm_try_read_disk(disk_handle_t handle, char *buffer, int32 size, int32 *read_size)
{
    CM_POINTER3(disk, buffer, read_size);

    if (ReadFile(handle, buffer, (DWORD)size, (LPDWORD)read_size, NULL) == FALSE) {
        DWORD code = GetLastError();
        GS_THROW_ERROR(ERR_CM_READ_DISK, GS_ERRNO);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t cm_try_write_disk(disk_handle_t handle, char *buffer, int32 size, int32 *written_size)
{
    if (!WriteFile(handle, buffer, (DWORD)size, (LPDWORD)written_size, NULL)) {
        DWORD code = GetLastError();
        GS_THROW_ERROR(ERR_CM_WRITE_DISK, GS_ERRNO);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
status_t _cm_lock_disk(disk_handle_t handle, uint64 offset, int32 size, const char *file, int line)
#else
status_t cm_lock_disk(disk_handle_t handle, uint64 offset, int32 size)
#endif
{
    if (cm_seek_disk(handle, offset) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, size, 0, NULL)) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

#else
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

status_t cm_open_disk(const char *name, disk_handle_t *handle)
{
    *handle = open(name, O_RDWR | O_DIRECT | O_SYNC | O_CLOEXEC, 0);
    if (*handle == -1) {
        GS_THROW_ERROR(ERR_CM_OPEN_DISK, GS_ERRNO);
        GS_LOG_RUN_ERR("open %s failed:error code:%d,%s", name, errno, strerror(errno));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void cm_close_disk(disk_handle_t handle)
{
    int code;
    code = close(handle);
    if (code != 0) {
        // CMS_LOGGING("failed to close file with handle, error code %d", GS_ERRNO);
    }
}

status_t cm_seek_disk(disk_handle_t handle, uint64 offset)
{
    if (lseek64(handle, (off64_t)offset, SEEK_SET) == -1) {
        GS_THROW_ERROR(ERR_CM_SEEK_DISK, GS_ERRNO);
        GS_LOG_RUN_ERR("seek failed:error code:%d,%s", errno, strerror(errno));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

uint64 cm_get_disk_size(disk_handle_t handle)
{
    return (uint64)lseek64(handle, 0, SEEK_END);
}

status_t cm_try_read_disk(disk_handle_t handle, char *buffer, int32 size, int32 *read_size)
{
    *read_size = read(handle, buffer, size);
    if (*read_size == -1) {
        GS_THROW_ERROR(ERR_CM_READ_DISK, GS_ERRNO);
        GS_LOG_RUN_ERR("read failed:error code:%d,%s", errno, strerror(errno));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t cm_try_write_disk(disk_handle_t handle, char *buffer, int32 size, int32 *written_size)
{
    *written_size = write(handle, buffer, size);

    if (*written_size == -1) {
        GS_THROW_ERROR(ERR_CM_WRITE_DISK, GS_ERRNO);
        GS_LOG_RUN_ERR("write failed:error code:%d,%s", errno, strerror(errno));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
status_t _cm_lock_disk(disk_handle_t handle, uint64 offset, int32 size, const char *file, int line)
{
    GS_LOG_DEBUG_INF("cm_disk_lock:%s:%d", file, line);
#else
status_t cm_lock_disk(disk_handle_t handle, uint64 offset, int32 size)
{
#endif
    if (cm_seek_disk(handle, offset) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lockf(handle, F_TLOCK, size) != 0) {
        if (errno == EACCES || errno == EAGAIN) {
            return GS_ERROR;
        }

        GS_LOG_RUN_ERR("lockf failed:error code:%d,%s", errno, strerror(errno));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

#endif

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
status_t _cm_read_disk(disk_handle_t handle, uint64 offset, void *buf, int32 size, const char *file, int line)
{
#else
status_t cm_read_disk(disk_handle_t handle, uint64 offset, void *buf, int32 size)
{
#endif
    int32 curr_size, total_size;
    date_t start = cm_now();
    if (cm_seek_disk(handle, offset) != GS_SUCCESS) {
        return GS_ERROR;
    }

    total_size = 0;

    do {
        if (cm_try_read_disk(handle, (char *)buf + total_size, size - total_size, &curr_size) != GS_SUCCESS) {
            return GS_ERROR;
        }

        total_size += curr_size;
    } while (total_size < size);

    date_t end = cm_now();
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    GS_LOG_DEBUG_INF("cm_disk_read %d elapsed:%lld(ms) at %s:%d", size, (end - start) / MICROSECS_PER_MILLISEC, file,
                     line);
#else
    if (end - start > 50 * MICROSECS_PER_MILLISEC) {
        GS_LOG_RUN_WAR("cm_disk_read %d elapsed:%lld(ms)", size, (end - start) / MICROSECS_PER_MILLISEC);
    }
#endif
    return GS_SUCCESS;
}

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
status_t _cm_write_disk(disk_handle_t handle, uint64 offset, void *buf, int32 size, const char *file, int line)
{
#else
status_t cm_write_disk(disk_handle_t handle, uint64 offset, void *buf, int32 size)
{
#endif
    int32 curr_size, total_size;

    date_t start = cm_now();
    if (cm_seek_disk(handle, offset) != GS_SUCCESS) {
        return GS_ERROR;
    }

    total_size = 0;

    do {
        if (cm_try_write_disk(handle, (char *)buf + total_size, size - total_size, &curr_size) != GS_SUCCESS) {
            return GS_ERROR;
        }

        total_size += curr_size;
    } while (total_size < size);

    date_t end = cm_now();
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    GS_LOG_DEBUG_INF("cm_disk_write %d elapsed:%lld(ms) at %s:%d", size, (end - start) / MICROSECS_PER_MILLISEC, file,
                     line);
#else
    if (end - start > 50 * MICROSECS_PER_MILLISEC) {
        GS_LOG_RUN_WAR("cm_disk_write %d elapsed:%lld(ms)", size, (end - start) / MICROSECS_PER_MILLISEC);
    }
#endif
    return GS_SUCCESS;
}

status_t cm_lock_file_fd(int32 fd, uint8 type)
{
#ifndef _WIN32
    struct flock lk;
    if (type == DISK_LOCK_READ) {
        lk.l_type = F_RDLCK;
    } else if (type == DISK_LOCK_WRITE) {
        lk.l_type = F_WRLCK;
    } else {
        GS_LOG_DEBUG_ERR("incorrect type,type =%d.", type);
        return GS_ERROR;
    }
    lk.l_whence = SEEK_SET;
    lk.l_start = lk.l_len = 0;

    if (fcntl(fd, F_SETLK, &lk) != 0) {
        GS_LOG_DEBUG_ERR("cm_lock_file_fd failed, fd %d, errno %d, err info %s.",
            fd, errno, strerror(errno));
        return GS_ERROR;
    }
#endif
    return GS_SUCCESS;
}

status_t cm_lockw_file_fd(int32 fd)
{
    uint8 type = DISK_LOCK_WRITE;
    if (cm_lock_file_fd(fd, type) != GS_SUCCESS) {
        GS_LOG_DEBUG_ERR("cm_lockw_file_fd failed, fd %d.", fd);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t cm_lockr_file_fd(int32 fd)
{
    uint8 type = DISK_LOCK_READ;
    if (cm_lock_file_fd(fd, type) != GS_SUCCESS) {
        GS_LOG_DEBUG_ERR("cm_lockr_file_fd failed, fd %d.", fd);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t cm_lock_record_fd(int32 fd, uint32 id, uint8 type)
{
#ifndef _WIN32
    struct flock lk;

    uint32 part_id = id % CM_DISK_PART_COUNT;
    if (type == DISK_LOCK_READ) {
        lk.l_type = F_RDLCK;
    } else if (type == DISK_LOCK_WRITE) {
        lk.l_type = F_WRLCK;
    } else {
        GS_LOG_DEBUG_ERR("incorrect type,type =%d.", type);
        return GS_ERROR;
    }
    lk.l_whence = SEEK_SET;
    lk.l_start = (part_id - 1) * CM_FILE_PART_BLOCK_SIZE;
    lk.l_len = CM_FILE_PART_BLOCK_SIZE;

    if (fcntl(fd, F_SETLK, &lk) != 0) {
        GS_LOG_DEBUG_ERR("cm_lock_record_fd failed, fd %d.", fd);
        return GS_ERROR;
    }
#endif
    return GS_SUCCESS;
}

status_t cm_lockw_record_fd(int32 fd, uint32 id)
{
    uint8 type = DISK_LOCK_WRITE;
    if (cm_lock_record_fd(fd, id, type) != GS_SUCCESS) {
        GS_LOG_DEBUG_ERR("cm_lockw_record_fd failed, fd %d.", fd);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t cm_lockr_record_fd(int32 fd, uint32 id)
{
    uint8 type = DISK_LOCK_READ;
    if (cm_lock_record_fd(fd, id, type) != GS_SUCCESS) {
        GS_LOG_DEBUG_ERR("cm_lockr_record_fd failed, fd %d.", fd);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t cm_unlock_file_fd(int32 fd)
{
#ifndef _WIN32
    struct flock lk;

    lk.l_type = F_UNLCK;
    lk.l_whence = SEEK_SET;
    lk.l_start = lk.l_len = 0;

    if (fcntl(fd, F_SETLK, &lk) != 0) {
        GS_LOG_DEBUG_ERR("cm_unlock_file_fd failed, fd= %d.", fd);
        return GS_ERROR;
    }
#endif
    return GS_SUCCESS;
}

status_t cm_unlock_record_fd(int32 fd, uint32 id)
{
#ifndef _WIN32
    struct flock lk;

    uint32 part_id = id % CM_DISK_PART_COUNT;
    lk.l_type = F_UNLCK;
    lk.l_whence = SEEK_SET;
    lk.l_start = (part_id - 1) * CM_FILE_PART_BLOCK_SIZE;
    lk.l_len = CM_FILE_PART_BLOCK_SIZE;

    if (fcntl(fd, F_SETLK, &lk) != 0) {
        GS_LOG_DEBUG_ERR("cm_unlock_record_fd, fd = %d.", fd);
        return GS_ERROR;
    }
#endif
    return GS_SUCCESS;
}
