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
 * cm_disk.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_disk.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef _CM_DISK_H_
#define _CM_DISK_H_

#ifdef WIN32
#include <windows.h>
#endif
#include "cm_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
typedef HANDLE disk_handle_t;
#else
typedef int32 disk_handle_t;
#endif

typedef enum en_cm_lock_type {
    DISK_LOCK_WRITE = 0,
    DISK_LOCK_READ = 1,
} cm_lock_type;

status_t cm_open_disk(const char *name, disk_handle_t *handle);
void cm_close_disk(disk_handle_t handle);
uint64 cm_get_disk_size(disk_handle_t handle);
status_t cm_seek_disk(disk_handle_t handle, uint64 offset);
status_t cm_try_read_disk(disk_handle_t handle, char *buffer, int32 size, int32 *read_size);
status_t cm_try_write_disk(disk_handle_t handle, char *buffer, int32 size, int32 *written_size);

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
status_t _cm_write_disk(disk_handle_t handle, uint64 offset, void *buf, int32 size, const char *file, int line);
status_t _cm_read_disk(disk_handle_t handle, uint64 offset, void *buf, int32 size, const char *file, int line);
status_t _cm_lock_disk(disk_handle_t handle, uint64 offset, int32 size, const char *file, int line);

#define cm_write_disk(handle, offset, buf, size) _cm_write_disk((handle), (offset), (buf), (size), __FILE__, __LINE__)
#define cm_read_disk(handle, offset, buf, size) _cm_read_disk((handle), (offset), (buf), (size), __FILE__, __LINE__)
#define cm_lock_disk(handle, offset, size) _cm_lock_disk((handle), (offset), (size), __FILE__, __LINE__)
#else
status_t cm_write_disk(disk_handle_t handle, uint64 offset, void *buf, int32 size);
status_t cm_read_disk(disk_handle_t handle, uint64 offset, void *buf, int32 size);
status_t cm_lock_disk(disk_handle_t handle, uint64 offset, int32 size);
#endif

status_t cm_lock_file_fd(int32 fd, uint8 type);
status_t cm_lockw_file_fd(int32 fd);
status_t cm_lockr_file_fd(int32 fd);
status_t cm_lock_record_fd(int32 fd, uint32 id, uint8 type);
status_t cm_lockw_record_fd(int32 fd, uint32 id);
status_t cm_lockr_record_fd(int32 fd, uint32 id);
status_t cm_unlock_file_fd(int32 fd);
status_t cm_unlock_record_fd(int32 fd, uint32 id);

#ifdef __cplusplus
}
#endif

#endif