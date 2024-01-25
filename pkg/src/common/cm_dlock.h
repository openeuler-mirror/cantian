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
 * cm_dlock.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_dlock.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_DLOCK_H__
#define __CM_DLOCK_H__

#include "cm_scsi.h"

#define DISK_LOCK_HEADER_MAGIC      0x9527EEFFFFEE9527
#define DISK_DEFAULT_LOCK_INTERVAL  100    // μs
#define DISK_LOCK_ALIGN_SIZE_512    512
#define DISK_LOCK_BODY_LEN          128
#define DISK_LOCK_HEADER_LEN        (CM_DEF_BLOCK_SIZE - DISK_LOCK_BODY_LEN)
#define DISK_LOCK_VERSION           1

#define CM_DLOCK_ERR_RETRY_INTERVAL  500    // ms
#define CM_DLOCK_ERR_RETRY_COUNT     3
#define CM_DLOCK_ERR_LOCK_OCCUPIED  (-2)

typedef struct st_dlock_header {
    union {
        struct {
            int64 magic_num;
            int64 inst_id;
            time_t lock_time;
            time_t create_time;
            int32 version;
        };
        char data[DISK_LOCK_HEADER_LEN];
    };
} dlock_header;

typedef struct st_dlock_body {
    char data[DISK_LOCK_BODY_LEN];
} dlock_body;

typedef struct st_dlock_info {
    dlock_header header;
    dlock_body body;
} dlock_info;

typedef struct st_dlock_area {
    union {
        dlock_info lock_info;
        char lock[CM_DEF_BLOCK_SIZE];
    };
} dlock_area;

typedef struct st_dlock {
    uint64 lock_addr;
    char *buff;  // malloc buff
    char *lockr;
    char *lockw;
    char *tmp;
} dlock_t;

#define LOCKR_INFO(lock) ((dlock_area *)(lock).lockr)
#define LOCKR_INST_ID(lock) (LOCKR_INFO(lock)->lock_info.header.inst_id)
#define LOCKR_SET_INST_ID(lock, org_inst_id) (LOCKR_INFO(lock)->lock_info.header.inst_id = (org_inst_id) + 1)
#define LOCKR_ORG_INST_ID(lock) (LOCKR_INFO(lock)->lock_info.header.inst_id - 1)
#define LOCKR_LOCK_TIME(lock) (LOCKR_INFO(lock)->lock_info.header.lock_time)
#define LOCKR_LOCK_CREATE_TIME(lock) (LOCKR_INFO(lock)->lock_info.header.create_time)
#define LOCKR_LOCK_MAGICNUM(lock) (LOCKR_INFO(lock)->lock_info.header.magic_num)
#define LOCKR_LOCK_VERSION(lock) (LOCKR_INFO(lock)->lock_info.header.version)
#define LOCKR_LOCK_BODY(lock) (LOCKR_INFO(lock)->lock_info.body.data)
#define LOCKW_INFO(lock) ((dlock_area *)(lock).lockw)
#define LOCKW_INST_ID(lock) (LOCKW_INFO(lock)->lock_info.header.inst_id)
#define LOCKW_ORG_INST_ID(lock) (LOCKW_INFO(lock)->lock_info.header.inst_id - 1)
#define LOCKW_LOCK_TIME(lock) (LOCKW_INFO(lock)->lock_info.header.lock_time)
#define LOCKW_LOCK_CREATE_TIME(lock) (LOCKW_INFO(lock)->lock_info.header.create_time)
#define LOCKW_LOCK_MAGICNUM(lock) (LOCKW_INFO(lock)->lock_info.header.magic_num)
#define LOCKW_LOCK_VERSION(lock) (LOCKW_INFO(lock)->lock_info.header.version)
#define LOCKW_LOCK_BODY(lock) (LOCKW_INFO(lock)->lock_info.body.data)

status_t cm_alloc_dlock(dlock_t *lock, uint64 lock_addr, int64 inst_id);
status_t cm_init_dlock(dlock_t *lock, uint64 lock_addr, int64 inst_id);     // init lockw header and body
void cm_init_dlock_header(dlock_t *lock, uint64 lock_addr, int64 inst_id);  // init lockw and lockr header
void cm_destory_dlock(dlock_t *lock);
int32 cm_disk_lock_s(dlock_t *lock, const char *scsi_dev);
status_t cm_disk_timed_lock_s(dlock_t *lock, const char *scsi_dev, uint64 wait_usecs, int32 lock_interval,
                              uint32 dlock_retry_count);
status_t cm_disk_lockf_s(dlock_t *lock, const char *scsi_dev);
status_t cm_disk_unlock_s(dlock_t *lock, const char *scsi_dev);
status_t cm_disk_unlockf_s(dlock_t *lock, const char *scsi_dev, int64 old_inst_id);
int32 cm_preempt_dlock_s(dlock_t *lock, const char *scsi_dev);
status_t cm_erase_dlock_s(dlock_t *lock, const char *scsi_dev);
status_t cm_get_dlock_info_s(dlock_t *lock, const char *scsi_dev);

int32 cm_disk_lock(dlock_t *lock, int32 fd);
status_t cm_disk_timed_lock(dlock_t *lock, int32 fd, uint64 wait_usecs, int32 lock_interval, uint32 dlock_retry_count);
int32 cm_disk_lockf(dlock_t *lock, int32 fd);
status_t cm_disk_unlock(dlock_t *lock, int32 fd);     // clean lock header and body
status_t cm_disk_unlock_ex(dlock_t *lock, int32 fd);  // keep lock body
status_t cm_disk_unlockf(dlock_t *lock, int32 fd, int64 old_inst_id);
int32 cm_preempt_dlock(dlock_t *lock, int32 fd);
status_t cm_erase_dlock(dlock_t *lock, int32 fd);
status_t cm_get_dlock_info(dlock_t *lock, int32 fd);
#endif
