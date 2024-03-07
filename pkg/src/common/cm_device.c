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
 * cm_device.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_device.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_device_module.h"
#include "cm_device.h"
#include "cm_file.h"
#include "cm_dbs_ulog.h"
#include "cm_dbs_pgpool.h"
#include "cm_dbs_map.h"
#include "cm_io_record.h"
#ifdef WIN32
#else
#include <string.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif
// interface for register raw device callback function
raw_device_op_t g_raw_device_op;

cm_check_file_error_t g_check_file_error = NULL;

void cm_raw_device_register(raw_device_op_t *device_op)
{
    g_raw_device_op = *device_op;
}

device_type_t cm_device_type(const char *name)
{
    switch (name[0]) {
        case '+':
            return DEV_TYPE_RAW;
        case '-':
            return DEV_TYPE_PGPOOL;
        case '*':
            return DEV_TYPE_ULOG;
        default:
            return DEV_TYPE_FILE;
    }
}

static inline void cm_check_file_error(void)
{
    if (g_check_file_error != NULL) {
        g_check_file_error();
    }
}

status_t cm_access_device(device_type_t type, const char *file_name, uint32 mode)
{
    if (type == DEV_TYPE_FILE) {
        return cm_access_file(file_name, mode);
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_exist == NULL) {
            CT_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
            return CT_ERROR;
        }

        bool32 result = CT_FALSE;
        if (g_raw_device_op.raw_exist(file_name, &result) != CT_SUCCESS || !result) {
            return CT_ERROR;
        }
        return CT_SUCCESS;
    } else if (type == DEV_TYPE_ULOG) {
        return cm_dbs_map_exist(file_name) == CT_TRUE ? CT_SUCCESS : CT_ERROR;
    } else if (type == DEV_TYPE_PGPOOL) {
        return cm_dbs_pg_exist(file_name) == CT_TRUE ? CT_SUCCESS : CT_ERROR;
    } else {
        CT_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}
status_t cm_create_device_dir(device_type_t type, const char *name)
{
    if (type == DEV_TYPE_FILE) {
        return cm_create_dir(name);
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_create_dir == NULL) {
            CT_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
            return CT_ERROR;
        }

        return g_raw_device_op.raw_create_dir(name);
    } else {
        CT_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_create_device(const char *name, device_type_t type, uint32 flags, int32 *handle)
{
    timeval_t tv_begin;
    status_t ret = CT_SUCCESS;
    io_record_stat_t io_stat = IO_STAT_SUCCESS;
    if (type == DEV_TYPE_FILE) {
        if (cm_create_file(name, O_BINARY | O_SYNC | O_RDWR | O_EXCL | flags, handle) != CT_SUCCESS) {
            cm_check_file_error();
            return CT_ERROR;
        }
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_create == NULL || g_raw_device_op.raw_open == NULL) {
            CT_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
            return CT_ERROR;
        }

        if (g_raw_device_op.raw_create(name, O_BINARY | O_SYNC | O_RDWR | O_EXCL | flags) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (g_raw_device_op.raw_open(name, flags, handle) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else if (type == DEV_TYPE_ULOG) {
        cantian_record_io_stat_begin(IO_RECORD_EVENT_NS_CREATE_ULOG, &tv_begin);
        ret = cm_dbs_ulog_create(name, 0, flags, handle);
        io_stat = (ret == CT_SUCCESS ? IO_STAT_SUCCESS : IO_STAT_FAILED);
        cantian_record_io_stat_end(IO_RECORD_EVENT_NS_CREATE_ULOG, &tv_begin, io_stat);
        return ret;
    } else if (type == DEV_TYPE_PGPOOL) {
        cantian_record_io_stat_begin(IO_RECORD_EVENT_NS_CREATE_PG_POOL, &tv_begin);
        ret = cm_dbs_pg_create(name, 0, flags, handle);
        io_stat = (ret == CT_SUCCESS ? IO_STAT_SUCCESS : IO_STAT_FAILED);
        cantian_record_io_stat_end(IO_RECORD_EVENT_NS_CREATE_PG_POOL, &tv_begin, io_stat);
        return ret;
    } else {
        CT_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

// 当阵列故障时, create可能失败. 现象:create成功但返回eexist
status_t cm_create_device_retry_when_eexist(const char *name, device_type_t type, uint32 flags, int32 *handle)
{
    if (cm_create_device(name, type, flags, handle) == CT_SUCCESS) {
        return CT_SUCCESS;
    }
    CT_LOG_RUN_WAR("failed to create device %s the first time, errno %d", name, errno);
    if (errno == EEXIST) {
        if (cm_remove_device(type, name) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("failed to remove device %s, errno %d", name, errno);
            return CT_ERROR;
        }
        if (cm_create_device(name, type, flags, handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("failed to create device %s the second time, errno %d", name, errno);
            return CT_ERROR;
        }
        CT_LOG_RUN_WAR("succ to create device %s the second time", name);
        return CT_SUCCESS;
    }
    return CT_ERROR;
}

status_t cm_rename_device(device_type_t type, const char *src, const char *dst)
{
    if (type == DEV_TYPE_FILE) {
        return cm_rename_file(src, dst);
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_rename == NULL) {
            CT_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
            return CT_ERROR;
        }
        return g_raw_device_op.raw_rename(src, dst);
    } else if (type == DEV_TYPE_PGPOOL) {
        return cm_dbs_pg_rename(src, dst);
    } else {
        CT_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return CT_ERROR;
    }
}

// 当阵列故障时, rename可能失败. 现象:rename成功但返回enoent
status_t cm_rename_device_when_enoent(device_type_t type, const char *src, const char *dst)
{
    if (cm_rename_device(type, src, dst) == CT_SUCCESS) {
        return CT_SUCCESS;
    }
    if (errno == ENOENT) {
        if (cm_exist_device(type, dst)) {
            CT_LOG_RUN_WAR(" file %s is exist, errno %d", src, errno);
            return CT_SUCCESS;
        }
    }
    CT_LOG_RUN_ERR("failed to rename file %s to %s, errno %d", src, dst, errno);
    return CT_ERROR;
}

status_t cm_remove_device(device_type_t type, const char *name)
{
    if (type == DEV_TYPE_FILE) {
        return cm_remove_file(name);
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_remove == NULL) {
            CT_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
            return CT_ERROR;
        }

        return g_raw_device_op.raw_remove(name);
    } else if (type == DEV_TYPE_ULOG) {
        return cm_dbs_ulog_destroy(name);
    } else if (type == DEV_TYPE_PGPOOL) {
        return cm_dbs_pg_destroy(name);
    } else {
        CT_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return CT_ERROR;
    }
}

// 当阵列故障时, remove可能失败. 现象:remove成功但返回enoent
status_t cm_remove_device_when_enoent(device_type_t type, const char *name)
{
    if (cm_remove_device(type, name) == CT_SUCCESS) {
        return CT_SUCCESS;
    }
    if (errno == ENOENT) {
        CT_LOG_RUN_WAR("device %s is not exist, errno %d", name, errno);
        return CT_SUCCESS;
    }
    CT_LOG_RUN_ERR("failed to remove device %s, errno %d", name, errno);
    return CT_ERROR;
}

status_t cm_open_device_common(const char *name, device_type_t type, uint32 flags, int32 *handle, uint8 is_retry)
{
    timeval_t tv_begin;
    if (type == DEV_TYPE_FILE) {
        if (*handle != -1) {
            // device already opened, nothing to do.
            return CT_SUCCESS;
        }

        uint32 mode = O_BINARY | O_RDWR | flags;

        if (cm_open_file(name, mode, handle) != CT_SUCCESS) {
            cm_check_file_error();
            return CT_ERROR;
        }
    } else if (type == DEV_TYPE_RAW) {
        if (*handle != -1) {
            // device already opened, nothing to do.
            return CT_SUCCESS;
        }
        if (g_raw_device_op.raw_open == NULL) {
            CT_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
            return CT_ERROR;
        }
        return g_raw_device_op.raw_open(name, O_BINARY | O_RDWR | flags, handle);
    } else if (type == DEV_TYPE_ULOG) {
        if (*handle != -1) {
            return CT_SUCCESS;
        }
        cantian_record_io_stat_begin(IO_RECORD_EVENT_NS_OPEN_ULOG, &tv_begin);
        if (cm_dbs_ulog_open(name, handle, is_retry) == CT_ERROR) {
            cantian_record_io_stat_end(IO_RECORD_EVENT_NS_OPEN_ULOG, &tv_begin, IO_STAT_FAILED);
            return CT_ERROR;
        }
        cantian_record_io_stat_end(IO_RECORD_EVENT_NS_OPEN_ULOG, &tv_begin, IO_STAT_SUCCESS);
    } else if (type == DEV_TYPE_PGPOOL) {
        if (*handle != -1) {
            return CT_SUCCESS;
        }
        cantian_record_io_stat_begin(IO_RECORD_EVENT_NS_OPEN_PG_POOL, &tv_begin);
        if (cm_dbs_pg_open(name, handle) == CT_ERROR) {
            cantian_record_io_stat_end(IO_RECORD_EVENT_NS_OPEN_PG_POOL, &tv_begin, IO_STAT_FAILED);
            return CT_ERROR;
        }
        cantian_record_io_stat_end(IO_RECORD_EVENT_NS_OPEN_PG_POOL, &tv_begin, IO_STAT_SUCCESS);
    } else {
        CT_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_open_device(const char *name, device_type_t type, uint32 flags, int32 *handle){
    return cm_open_device_common(name, type ,flags, handle, CT_TRUE);
}

status_t cm_open_device_no_retry(const char *name, device_type_t type, uint32 flags, int32 *handle){
    return cm_open_device_common(name, type ,flags, handle, CT_FALSE);
}

void cm_close_device(device_type_t type, int32 *handle)
{
    timeval_t tv_begin;
    if (type == DEV_TYPE_FILE) {
        cm_close_file(*handle);
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_close != NULL) {
            g_raw_device_op.raw_close(handle);
        }
    } else if (type == DEV_TYPE_ULOG) {
        cantian_record_io_stat_begin(IO_RECORD_EVENT_NS_CLOSE_ULOG, &tv_begin);
        cm_dbs_ulog_close(*handle);
        cantian_record_io_stat_end(IO_RECORD_EVENT_NS_CLOSE_ULOG, &tv_begin, IO_STAT_SUCCESS);
    } else if (type == DEV_TYPE_PGPOOL) {
        cantian_record_io_stat_begin(IO_RECORD_EVENT_NS_CLOSE_PG_POOL, &tv_begin);
        cm_dbs_pg_close(*handle);
        cantian_record_io_stat_end(IO_RECORD_EVENT_NS_CLOSE_PG_POOL, &tv_begin, IO_STAT_SUCCESS);
    }
    *handle = -1;  // reset handle
}

status_t cm_read_device(device_type_t type, int32 handle, int64 offset, void *buf, int32 size)
{
    int32 read_size;
    timeval_t tv_begin;
    if (type == DEV_TYPE_FILE) {
        if (cm_pread_file(handle, buf, size, offset, &read_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_seek == NULL || g_raw_device_op.raw_read == NULL) {
            CT_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
            return CT_ERROR;
        }

        if (g_raw_device_op.raw_seek(handle, offset, SEEK_SET) != offset) {
            return CT_ERROR;
        }
        if (g_raw_device_op.raw_read(handle, offset, buf, size, &read_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else if (type == DEV_TYPE_ULOG) {
        cantian_record_io_stat_begin(IO_RECORD_EVENT_NS_READ_ULOG, &tv_begin);
        if (cm_dbs_ulog_read(handle, offset, buf, size, &read_size) != CT_SUCCESS) {
            cantian_record_io_stat_end(IO_RECORD_EVENT_NS_READ_ULOG, &tv_begin, IO_STAT_FAILED);
            return CT_ERROR;
        }
        cantian_record_io_stat_end(IO_RECORD_EVENT_NS_READ_ULOG, &tv_begin, IO_STAT_SUCCESS);
    } else if (type == DEV_TYPE_PGPOOL) {
        cantian_record_io_stat_begin(IO_RECORD_EVENT_NS_READ_PG_POOL, &tv_begin);
        if (cm_dbs_pg_read(handle, offset, buf, size, &read_size) != CT_SUCCESS) {
            cantian_record_io_stat_end(IO_RECORD_EVENT_NS_READ_PG_POOL, &tv_begin, IO_STAT_FAILED);
            return CT_ERROR;
        }
        cantian_record_io_stat_end(IO_RECORD_EVENT_NS_READ_PG_POOL, &tv_begin, IO_STAT_SUCCESS);
    } else {
        CT_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return CT_ERROR;
    }

    if (type != DEV_TYPE_ULOG && read_size != size) {
        CT_THROW_ERROR(ERR_READ_DEVICE_INCOMPLETE, read_size, size);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cm_read_device_nocheck(device_type_t type, int32 handle, int64 offset, void *buf, int32 size,
                                int32 *return_size)
{
    int32 read_size;

    if (type == DEV_TYPE_FILE) {
        if (cm_pread_file(handle, buf, size, offset, &read_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_seek == NULL || g_raw_device_op.raw_read == NULL) {
            CT_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
            return CT_ERROR;
        }

        if (g_raw_device_op.raw_seek(handle, offset, SEEK_SET) != offset) {
            CT_LOG_RUN_ERR("[cm_read_device] raw_seek handle %d offset %lld size %d.", handle, offset, size);
            return CT_ERROR;
        }
        if (g_raw_device_op.raw_read(handle, offset, buf, size, &read_size) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[cm_read_device] raw_read handle %d offset %lld size %d.", handle, offset, size);
            return CT_ERROR;
        }
    } else if (type == DEV_TYPE_ULOG) {
        if (cm_dbs_ulog_read(handle, offset, buf, size, &read_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else if (type == DEV_TYPE_PGPOOL) {
        if (cm_dbs_pg_read(handle, offset, buf, size, &read_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        CT_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return CT_ERROR;
    }

    if (return_size != NULL) {
        *return_size = read_size;
        return CT_SUCCESS;
    }
    if (type != DEV_TYPE_ULOG && read_size != size) {
        CT_THROW_ERROR(ERR_READ_DEVICE_INCOMPLETE, read_size, size);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cm_device_read_batch(device_type_t type, int32 handle, uint64 startLsn, uint64 endLsn,
                              void *buf, int32 size, int32 *r_size, uint64 *outLsn)
{
    if (type == DEV_TYPE_ULOG) {
        return cm_dbs_ulog_batch_read(handle, startLsn, endLsn, buf, size, r_size, outLsn);
    }
    CT_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
    return CT_ERROR;
}
 
status_t cm_device_get_used_cap_common(device_type_t type, int32 handle, uint64_t startLsn, uint32_t *sizeKb, uint8 is_retry)
{
    if (type == DEV_TYPE_ULOG) {
        return cm_dbs_get_used_cap(handle, startLsn, sizeKb, is_retry);
    }
    CT_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
    return CT_ERROR;
}

status_t cm_device_get_used_cap(device_type_t type, int32 handle, uint64_t startLsn, uint32_t *sizeKb)
{
    return cm_device_get_used_cap_common(type, handle, startLsn, sizeKb, CT_TRUE);
}

status_t cm_device_get_used_cap_no_retry(device_type_t type, int32 handle, uint64_t startLsn, uint32_t *sizeKb)
{
    return cm_device_get_used_cap_common(type, handle, startLsn, sizeKb, CT_FALSE);
}

status_t cm_device_capacity(device_type_t type, int64 *capacity)
{
    if (capacity == NULL) {
        CT_LOG_RUN_ERR("The input capacity addr is NULL pointer.");
        return CT_ERROR;
    }
    if (type == DEV_TYPE_ULOG) {
        return cm_dbs_ulog_capacity(capacity);
    }
    CT_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
    return CT_ERROR;
}

status_t cm_write_device(device_type_t type, int32 handle, int64 offset, const void *buf, int32 size)
{
    timeval_t tv_begin;
    if (type == DEV_TYPE_FILE) {
        if (cm_pwrite_file(handle, buf, size, offset) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_seek == NULL || g_raw_device_op.raw_write == NULL) {
            CT_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
            return CT_ERROR;
        }

        if (g_raw_device_op.raw_seek(handle, offset, SEEK_SET) != offset) {
            return CT_ERROR;
        }
        if (g_raw_device_op.raw_write(handle, offset, buf, size) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else if (type == DEV_TYPE_ULOG) {
        cantian_record_io_stat_begin(IO_RECORD_EVENT_NS_WRITE_ULOG, &tv_begin);
        if (cm_dbs_ulog_write(handle, offset, buf, size, NULL) != CT_SUCCESS) {
            cantian_record_io_stat_end(IO_RECORD_EVENT_NS_WRITE_ULOG, &tv_begin, IO_STAT_FAILED);
            return CT_ERROR;
        }
        cantian_record_io_stat_end(IO_RECORD_EVENT_NS_WRITE_ULOG, &tv_begin, IO_STAT_SUCCESS);
    } else if (type == DEV_TYPE_PGPOOL) {
        cantian_record_io_stat_begin(IO_RECORD_EVENT_NS_WRITE_PG_POOL, &tv_begin);
        if (cm_dbs_pg_write(handle, offset, buf, size) != CT_SUCCESS) {
            cantian_record_io_stat_end(IO_RECORD_EVENT_NS_WRITE_PG_POOL, &tv_begin, IO_STAT_FAILED);
            return CT_ERROR;
        }
        cantian_record_io_stat_end(IO_RECORD_EVENT_NS_WRITE_PG_POOL, &tv_begin, IO_STAT_SUCCESS);
    } else {
        CT_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

int64 cm_seek_device(device_type_t type, int32 handle, int64 offset, int32 origin)
{
    if (type == DEV_TYPE_FILE) {
        return cm_seek_file(handle, offset, origin);
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_seek == NULL) {
            return (int64)0;
        }

        return g_raw_device_op.raw_seek(handle, offset, origin);
    } else if (type == DEV_TYPE_ULOG) {
        return cm_dbs_ulog_seek(handle, offset, origin);
    } else if (type == DEV_TYPE_PGPOOL) {
        return cm_dbs_pg_seek(handle, offset, origin);
    } else {
        return (int64)0;
    }
}

bool32 cm_exist_device_dir(device_type_t type, const char *name)
{
    if (type == DEV_TYPE_FILE) {
        return cm_dir_exist(name);
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_exist_dir == NULL) {
            return CT_FALSE;
        }

        bool32 result = CT_FALSE;
        if (g_raw_device_op.raw_exist_dir(name, &result) != CT_SUCCESS) {
            return CT_FALSE;
        }
        return result;
    } else {
        return CT_FALSE;
    }
}

status_t cm_create_device_dir_ex2(const char *dir_name)
{
    char dir[CT_MAX_FILE_NAME_LEN + 1];
    size_t dir_len = strlen(dir_name);
    uint32 i;

    errno_t errcode = strncpy_s(dir, (size_t)CT_MAX_FILE_NAME_LEN, dir_name, (size_t)dir_len);
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CT_ERROR;
    }
    if (dir[dir_len - 1] != '\\' && dir[dir_len - 1] != '/') {
        dir[dir_len] = '/';
        dir_len++;
        dir[dir_len] = '\0';
    }

    for (i = 0; i < dir_len; i++) {
        if (dir[i] == '\\' || dir[i] == '/') {
            if (i == 0) {
                continue;
            }

            dir[i] = '\0';
            if (cm_exist_device_dir(DEV_TYPE_RAW, dir)) {
                dir[i] = '/';
                continue;
            }

            if (cm_create_device_dir(DEV_TYPE_RAW, dir) != CT_SUCCESS) {
                return CT_ERROR;
            }
            dir[i] = '/';
        }
    }

    return CT_SUCCESS;
}

bool32 cm_create_device_dir_ex(device_type_t type, const char *name)
{
    if (type == DEV_TYPE_FILE) {
        return cm_create_dir_ex(name);
    } else if (type == DEV_TYPE_RAW) {
        return cm_create_device_dir_ex2(name);
    } else {
        CT_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

bool32 cm_exist_device(device_type_t type, const char *name)
{
    if (type == DEV_TYPE_FILE) {
        return cm_file_exist(name);
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_exist == NULL) {
            return CT_FALSE;
        }

        bool32 result = CT_FALSE;
        if (g_raw_device_op.raw_exist(name, &result) != CT_SUCCESS) {
            return CT_FALSE;
        }
        return result;
    } else if (type == DEV_TYPE_ULOG) {
        return cm_dbs_map_exist(name);
    } else if (type == DEV_TYPE_PGPOOL) {
        return cm_dbs_pg_exist(name);
    } else {
        return CT_FALSE;
    }
}

// prealloc file by fallocate
status_t cm_prealloc_device(int32 handle, int64 offset, int64 size)
{
    return cm_fallocate_file(handle, 0, offset, size);
}

status_t cm_write_device_by_zero(int32 handle, device_type_t type, char *buf, uint32 buf_size,
    int64 offset, int64 size)
{
    int64 offset_tmp = offset;
    if (type == DEV_TYPE_PGPOOL || type == DEV_TYPE_ULOG) {
        return CT_SUCCESS;
    }
    errno_t err = memset_sp(buf, (size_t)buf_size, 0, (size_t)buf_size);
    if (err != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (err));
        return CT_ERROR;
    }

    int64 remain_size = size;
    int32 curr_size;
    while (remain_size > 0) {
        curr_size = (remain_size > buf_size) ? (int32)buf_size : (int32)remain_size;
        if (cm_write_device(type, handle, offset_tmp, buf, curr_size) != CT_SUCCESS) {
            return CT_ERROR;
        }

        offset_tmp += curr_size;
        remain_size -= curr_size;
    }

    return CT_SUCCESS;
}

status_t cm_extend_device(device_type_t type, int32 handle, char *buf, uint32 buf_size, int64 size,
    bool32 prealloc)
{
    int64 offset = cm_device_size(type, handle);
    if (offset == -1) {
        CT_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_END, errno);
        return CT_ERROR;
    }
    if (type == DEV_TYPE_PGPOOL) {
        timeval_t tv_begin;
        cantian_record_io_stat_begin(IO_RECORD_EVENT_NS_EXTENT_PG_POOL, &tv_begin);
        status_t ret = cm_dbs_pg_extend(handle, offset, size);
        io_record_stat_t io_stat = (ret == CT_SUCCESS ? IO_STAT_SUCCESS : IO_STAT_FAILED);
        cantian_record_io_stat_end(IO_RECORD_EVENT_NS_EXTENT_PG_POOL, &tv_begin, io_stat);
        return ret;
    }
    if (prealloc) {
        // use falloc to fast build device
        return cm_prealloc_device(handle, offset, size);
    }

    return cm_write_device_by_zero(handle, type, buf, buf_size, offset, size);
}

status_t cm_try_prealloc_extend_device(device_type_t type, int32 handle, char *buf, uint32 buf_size, int64 size,
    bool32 prealloc)
{
    int64 offset = cm_device_size(type, handle);
    if (offset == -1) {
        CT_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_END, errno);
        return CT_ERROR;
    }

    if (prealloc) {
        // use falloc to fast build device
        if (cm_prealloc_device(handle, offset, size) == CT_SUCCESS) {
            return CT_SUCCESS;
        }

        // if there is no space lefe on disk, return error
        if (errno == ENOSPC) {
            return CT_ERROR;
        }
        cm_reset_error();
        CT_LOG_RUN_WAR("extent device by prealloc failed error code %u, will try extent device by write 0", errno);
    }

    return cm_write_device_by_zero(handle, type, buf, buf_size, offset, size);
}


status_t cm_truncate_device(device_type_t type, int32 handle, int64 keep_size)
{
    if (type == DEV_TYPE_FILE) {
        if (cm_truncate_file(handle, keep_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_truncate == NULL) {
            CT_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
            return CT_ERROR;
        }

        return g_raw_device_op.raw_truncate(handle, keep_size);
    } else if (type == DEV_TYPE_PGPOOL) {
        return cm_dbs_pg_truncate(handle, keep_size);
    } else {
        CT_LOG_RUN_ERR("Unsupported operation(truncate) for device(%u).", type);
        CT_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_check_device_size(device_type_t type, int32 size)
{
    if (type == DEV_TYPE_FILE) {
        return CT_SUCCESS;
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_check_size == NULL) {
            CT_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
            return CT_ERROR;
        }

        return g_raw_device_op.raw_check_size(size);
    } else if (type == DEV_TYPE_ULOG || type == DEV_TYPE_PGPOOL) {
        return CT_SUCCESS;
    } else {
        CT_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return CT_ERROR;
    }
}

int32 cm_align_device_size(device_type_t type, int32 size)
{
    if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_align_size == NULL) {
            return size;
        }

        return g_raw_device_op.raw_align_size(size);
    } else if (type == DEV_TYPE_ULOG) {
        return cm_dbs_ulog_align_size(size);
    } else {
        return size;
    }
}

bool32 cm_check_device_offset_valid(device_type_t type, int32 handle, int64 offset)
{
    if (type == DEV_TYPE_ULOG) {
        if (offset <= 0) {
            CT_LOG_RUN_ERR("Invalid offset(%lld).", offset);
            return CT_FALSE;
        }
        return cm_dbs_ulog_is_lsn_valid(handle, (uint64)offset);
    }
    CT_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
    return CT_FALSE;
}

status_t cm_build_device(const char *name, device_type_t type, char *buf, uint32 buf_size, int64 size,
    uint32 flags, bool32 prealloc, int32 *handle)
{
    *handle = -1;
    if (type == DEV_TYPE_PGPOOL) {
        status_t ret = cm_dbs_pg_create(name, size, flags, handle);
        cm_close_device(type, handle);
        return ret;
    }
    if (cm_create_device(name, type, flags, handle) != CT_SUCCESS) {
        cm_close_device(type, handle);
        return CT_ERROR;
    }
    status_t status;
    if (prealloc) {
        status = cm_prealloc_device(*handle, 0, size);
    } else {
        status = cm_write_device_by_zero(*handle, type, buf, buf_size, 0, size);
    }

    if (status != CT_SUCCESS) {
        cm_close_device(type, handle);
        return CT_ERROR;
    }

    if (type == DEV_TYPE_FILE) {
        if (cm_fsync_file(*handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("failed to fsync datafile %s", name);
            cm_close_device(type, handle);
            return CT_ERROR;
        }
    }

    cm_close_device(type, handle);
    return CT_SUCCESS;
}

status_t cm_aio_setup(cm_aio_lib_t *lib_ctx, int maxevents, cm_io_context_t *io_ctx)
{
    int32 aio_ret;

    aio_ret = lib_ctx->io_setup(maxevents, io_ctx);
    if (aio_ret < 0) {
        CT_LOG_RUN_ERR("failed to io_setup by async io: aio_ret: %d, error code: %d", aio_ret, errno);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cm_aio_destroy(cm_aio_lib_t *lib_ctx, cm_io_context_t io_ctx)
{
    if (lib_ctx->io_destroy(io_ctx) < 0) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cm_aio_getevents(cm_aio_lib_t *lib_ctx, cm_io_context_t io_ctx, long min_nr, long nr,
                          cm_io_event_t *events, int32 *aio_ret)
{
    struct timespec timeout  = { 0, 200 };
    *aio_ret = lib_ctx->io_getevents(io_ctx, min_nr, nr, events, &timeout);
    if (*aio_ret < 0) {
        if (*aio_ret != -EINTR) {
            CT_LOG_RUN_ERR("failed to io_getevents by async io: error code: %d, aio_ret: %d", errno, *aio_ret);
        }
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_aio_submit(cm_aio_lib_t *lib_ctx, cm_io_context_t io_ctx, long nr, cm_iocb_t *ios[])
{
    if (lib_ctx->io_submit(io_ctx, nr, ios) != nr) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void cm_aio_prep_read(cm_iocb_t *iocb, int fd, void *buf, size_t count, long long offset)
{
#ifndef WIN32
    io_prep_pread(iocb, fd, buf, count, offset);
#endif
}

void cm_aio_prep_write(cm_iocb_t *iocb, int fd, void *buf, size_t count, long long offset)
{
#ifndef WIN32
    io_prep_pwrite(iocb, fd, buf, count, offset);
#endif
}

void cm_aio_set_callback(cm_iocb_t *iocb, cm_io_callback_t cb)
{
#ifndef WIN32
    io_set_callback(iocb, cb);
#endif
}

status_t cm_aio_prep_write_by_part(int32 handle, int64 offset, void *buf, int32 size, int32 part_id)
{
    timeval_t tv_begin;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_NS_PUT_PAGE, &tv_begin);

    status_t ret = cm_dbs_pg_asyn_write(handle, offset, buf, size, part_id);
    io_record_stat_t io_stat = (ret == CT_SUCCESS ? IO_STAT_SUCCESS : IO_STAT_FAILED);
    cantian_record_io_stat_end(IO_RECORD_EVENT_NS_PUT_PAGE, &tv_begin, io_stat);
    return ret;
}

status_t cm_sync_device_by_part(int32 handle, int32 part_id)
{
    timeval_t tv_begin;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_NS_SYNC_PAGE, &tv_begin);

    status_t ret = cm_dbs_sync_page(handle, part_id);
    io_record_stat_t io_stat = (ret == CT_SUCCESS ? IO_STAT_SUCCESS : IO_STAT_FAILED);
    cantian_record_io_stat_end(IO_RECORD_EVENT_NS_SYNC_PAGE, &tv_begin, io_stat);
    return ret;
}

status_t cm_cal_partid_by_pageid(uint64 page_id, uint32 page_size, uint32 *part_id)
{
    return cm_dbs_pg_cal_part_id(page_id, page_size, part_id);
}

#ifdef __cplusplus
}
#endif

