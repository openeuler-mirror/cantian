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
 * cm_disklock.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_disklock.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef _CM_DISKLOCK_
#define _CM_DISKLOCK_

#include "cm_defs.h"
#include "cm_disk.h"
#include "cm_thread.h"
#include "cm_latch.h"

#define CM_LOCK_TRY_INTERVAL 200

typedef enum en_cm_disklock_mode {
    DISK_LOCK_MUTEX = 0,
    DISK_LOCK_LATCHX = 1,
    DISK_LOCK_LATCHS = 2,
} cm_disklock_mode_e;

typedef struct u_cm_file_lock_t {
    short l_type;
    short l_whence;
    off_t l_start;
    off_t l_len;
    pid_t l_pid;
    uint64 magic;
    time_t lock_time;
} cm_flock_t;

typedef struct _st_cm_disk_lock_t {
    int fd;
    cm_flock_t flock;
    thread_lock_t tlock;
    latch_t lh_lock;
    uint32 id;
    uint32 inst_id;
    char dev_name[GS_FILE_NAME_BUFFER_SIZE];
} cm_disk_lock_t;

status_t cm_disk_lock_init(cm_disk_lock_t *lock, uint32 inst_id, uint32 uid);
void cm_destory_lock(cm_disk_lock_t *lock);
status_t cm_disk_save_lockinfo(cm_disk_lock_t *lock);
status_t cm_disk_mutex_try_lock(cm_disk_lock_t *lock);
status_t cm_disk_latchs_try_lock(cm_disk_lock_t *lock);
status_t cm_disk_file_lock(cm_disk_lock_t *lock, uint8 lock_type);
status_t cm_disk_timed_file_lock(cm_disk_lock_t *lock, uint32 timeout_ms, uint8 lock_type);
status_t cm_disk_mutex_lock(cm_disk_lock_t *lock, uint32 timeout_ms);
status_t cm_disk_latchx_lock(cm_disk_lock_t *lock, uint32 timeout_ms);
status_t cm_disk_latchs_lock(cm_disk_lock_t *lock, uint32 timeout_ms);
status_t cm_record_disk_unlock(cm_disk_lock_t *lock);
status_t cm_disk_mutex_unlock(cm_disk_lock_t *lock);
status_t cm_disk_latch_unlock(cm_disk_lock_t *lock);

#endif
