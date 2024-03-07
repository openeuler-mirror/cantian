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
 * cm_device.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_device.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_DEVICE_H__
#define __CM_DEVICE_H__

#include "cm_defs.h"
#include <time.h>

#ifndef WIN32
#include "libaio.h"
#endif


typedef enum en_device_type {
    DEV_TYPE_FILE = 1,
    DEV_TYPE_RAW = 2,
    DEV_TYPE_CFS = 3,
    DEV_TYPE_ULOG = 4,
    DEV_TYPE_PGPOOL = 5,
} device_type_t;

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*cm_check_file_error_t)(void);
extern cm_check_file_error_t g_check_file_error;

#ifdef WIN32
typedef uint64 cm_io_context_t;
typedef uint64 cm_iocb_t;
typedef void (*cm_io_callback_t)(cm_io_context_t ctx, cm_iocb_t *iocb, long res, long res2);
typedef struct st_aio_event {
    void *data;
    cm_iocb_t *obj;
    long res;
    long res2;
} cm_io_event_t;
#else
typedef struct iocb cm_iocb_t;
typedef struct io_event cm_io_event_t;
typedef io_callback_t cm_io_callback_t;
typedef io_context_t cm_io_context_t;
#endif

#define CM_IOCB_LENTH (sizeof(cm_iocb_t) + sizeof(cm_iocb_t*) + sizeof(cm_io_event_t))

typedef int (*cm_io_setup)(int maxevents, cm_io_context_t *io_ctx);
typedef int (*cm_io_destroy)(cm_io_context_t ctx);
typedef int (*cm_io_submit)(cm_io_context_t ctx, long nr, cm_iocb_t *ios[]);
typedef int (*cm_io_cancel)(cm_io_context_t ctx, cm_iocb_t *iocb, cm_io_event_t *evt);
typedef int (*cm_io_getevents)(cm_io_context_t ctx_id, long min_nr, long nr, cm_io_event_t *events,
                               struct timespec *timeout);

typedef struct st_aio_cbs {
    cm_iocb_t **iocb_ptrs;
    cm_iocb_t *iocbs;
    cm_io_event_t *events;
}cm_aio_iocbs_t;

typedef struct st_aio_lib {
    void *lib_handle;
    cm_io_setup io_setup;
    cm_io_destroy io_destroy;
    cm_io_submit io_submit;
    cm_io_cancel io_cancel;
    cm_io_getevents io_getevents;
}cm_aio_lib_t;

#define cm_device_size(type, handle) cm_seek_device((type), (handle), 0, SEEK_END)

status_t cm_aio_setup(cm_aio_lib_t *lib_ctx, int maxevents, cm_io_context_t *io_ctx);
status_t cm_aio_destroy(cm_aio_lib_t *lib_ctx, cm_io_context_t io_ctx);
status_t cm_aio_submit(cm_aio_lib_t *lib_ctx, cm_io_context_t io_ctx, long nr, cm_iocb_t *ios[]);
status_t cm_aio_getevents(cm_aio_lib_t *lib_ctx, cm_io_context_t io_ctx, long min_nr, long nr,
                          cm_io_event_t *events, int32 *aio_ret);
void cm_aio_prep_read(cm_iocb_t *iocb, int fd, void *buf, size_t count, long long offset);
void cm_aio_prep_write(cm_iocb_t *iocb, int fd, void *buf, size_t count, long long offset);
void cm_aio_set_callback(cm_iocb_t *iocb, cm_io_callback_t cb);

device_type_t cm_device_type(const char *name);
status_t cm_remove_device(device_type_t type, const char *name);
status_t cm_remove_device_when_enoent(device_type_t type, const char *name);
status_t cm_open_device(const char *name, device_type_t type, uint32 flags, int32 *handle);
status_t cm_open_device_no_retry(const char *name, device_type_t type, uint32 flags, int32 *handle);
void cm_close_device(device_type_t type, int32 *handle);
status_t cm_rename_device(device_type_t type, const char *src, const char *dst);
status_t cm_rename_device_when_enoent(device_type_t type, const char *src, const char *dst);
status_t cm_read_device(device_type_t type, int32 handle, int64 offset, void *buf, int32 size);
status_t cm_read_device_nocheck(device_type_t type, int32 handle, int64 offset, void *buf, int32 size,
                                int32 *return_size);
status_t cm_write_device(device_type_t type, int32 handle, int64 offset, const void *buf, int32 size);
int64 cm_seek_device(device_type_t type, int32 handle, int64 offset, int32 origin);
bool32 cm_exist_device(device_type_t type, const char *name);
status_t cm_extend_device(device_type_t type, int32 handle, char *buf, uint32 buf_size, int64 size,
    bool32 prealloc);
status_t cm_try_prealloc_extend_device(device_type_t type, int32 handle, char *buf, uint32 buf_size, int64 size,
    bool32 prealloc);
status_t cm_truncate_device(device_type_t type, int32 handle, int64 keep_size);
status_t cm_build_device(const char *name, device_type_t type, char *buf, uint32 buf_size, int64 size,
    uint32 flags, bool32 prealloc, int32 *handle);
status_t cm_create_device(const char *name, device_type_t type, uint32 flags, int32 *handle);
status_t cm_create_device_retry_when_eexist(const char *name, device_type_t type, uint32 flags, int32 *handle);
status_t cm_write_zero_to_device(device_type_t type, char *buf, uint32 buf_size, int64 size, int32 *handle);
status_t cm_access_device(device_type_t type, const char *file_name, uint32 mode);
status_t cm_create_device_dir(device_type_t type, const char *name);
bool32 cm_exist_device_dir(device_type_t type, const char *name);
bool32 cm_create_device_dir_ex(device_type_t type, const char *name);
status_t cm_check_device_size(device_type_t type, int32 size);
int32 cm_align_device_size(device_type_t type, int32 size);
status_t cm_device_get_used_cap(device_type_t type, int32 handle, uint64_t startLsn, uint32_t *sizeKb);
status_t cm_device_get_used_cap_no_retry(device_type_t type, int32 handle, uint64_t startLsn, uint32_t *sizeKb);
status_t cm_device_capacity(device_type_t type, int64 *capacity);
status_t cm_device_read_batch(device_type_t type, int32 handle, uint64 startLsn, uint64 endLsn,
                              void *buf, int32 size, int32 *r_size, uint64 *outLsn);
bool32 cm_check_device_offset_valid(device_type_t type, int32 handle, int64 offset);

status_t cm_aio_prep_write_by_part(int32 handle, int64 offset, void* buf, int32 size, int32 part_id);
status_t cm_sync_device_by_part(int32 handle, int32 part_id);
status_t cm_cal_partid_by_pageid(uint64 page_id, uint32 page_size, uint32 *part_id);

// callback for register raw device
typedef status_t (*raw_open_device)(const char *name, uint32 flags, int32 *handle);
typedef status_t (*raw_read_device)(int32 handle, int64 offset, void *buf, int32 size, int32 *read_size);
typedef status_t (*raw_write_device)(int32 handle, int64 offset, const void *buf, int32 size);
typedef int64 (*raw_seek_device)(int32 handle, int64 offset, int32 origin);
typedef status_t (*raw_trucate_device)(int32 handle, int64 keep_size);
typedef status_t (*raw_create_device)(const char *name, uint32 flags);
typedef status_t (*raw_remove_device)(const char *name);
typedef void (*raw_close_device)(int32 *handle);
typedef status_t (*raw_exist_device)(const char *name, bool32 *result);
typedef status_t (*raw_create_device_dir)(const char *name);
typedef status_t (*raw_exist_device_dir)(const char *name, bool32 *result);
typedef status_t (*raw_rename_device)(const char *src, const char *dst);
typedef status_t (*raw_check_device_size)(int32 size);
typedef status_t (*raw_align_device_size)(int32 size);

typedef struct st_raw_device_op {
    raw_create_device raw_create;
    raw_remove_device raw_remove;
    raw_open_device raw_open;
    raw_read_device raw_read;
    raw_write_device raw_write;
    raw_seek_device raw_seek;
    raw_trucate_device raw_truncate;
    raw_close_device raw_close;
    raw_exist_device raw_exist;
    raw_create_device_dir raw_create_dir;
    raw_exist_device_dir raw_exist_dir;
    raw_rename_device raw_rename;
    raw_check_device_size raw_check_size;
    raw_align_device_size raw_align_size;
} raw_device_op_t;

// interface for register raw device callback function
void cm_raw_device_register(raw_device_op_t *device_op);

#define CM_CTSTORE_ALIGN_SIZE 512

#ifdef __cplusplus
}
#endif

#endif
