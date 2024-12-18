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
 * cms_cbb.h
 *
 *
 * IDENTIFICATION
 * src/cms/cbb/cbb_disklock.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CBB_DISKLOCK_H__
#define __CBB_DISKLOCK_H__

#define CM_MAX_DISKLOCK_COUNT (16)
#define CM_MAX_PATH_SIZE (256)
#define CM_MAX_INST_COUNT (15)

#define CM_DL_ERR_IO (1)
#define CM_DL_ERR_OCCUPIED (2)
#define CM_DL_ERR_INVALID_LOCK_ID (3)
#define CM_DL_ERR_TIMEOUT (4)
#define CM_DL_ERR_INVALID_PARAM (5)
#define CM_DL_ERR_INVALID_LOCKSTAT (6)

#define CM_INVALID_LOCK_ID ((unsigned int)-1)
#define CM_INVALID_INST_ID ((unsigned long long)-1)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Allocate a disk lock: reserve CM_MAX_INST_COUNT*(BLOCK_SIZE + 1) for the disk lock area.
 * @param [in] path: disk path
 * @param [in] offset: start position of the lock located, 8K aligned.
 * @param [in] inst_id: base on 0, less than CM_MAX_INST_COUNT.
 * @return >= 0 lock_id
 * @return CM_INVALID_LOCK_ID fail
 */
unsigned int cm_dl_alloc(const char *path, unsigned long long offset, unsigned long long inst_id);

/**
 * Allocate a lease disk lock: reserve CM_MAX_INST_COUNT*(BLOCK_SIZE + 1) for the disk lock area.
 * @param [in] path: disk path
 * @param [in] offset: start position of the lock located, 8K aligned.
 * @param [in] inst_id: base on 0, less than CM_MAX_INST_COUNT.
 * @param [in] lease_sec: lease duration, unit second
 * @return >= 0 lock_id
 * @return CM_INVALID_LOCK_ID fail
 */
unsigned int cm_dl_alloc_lease(
    const char *path, unsigned long long offset, unsigned long long inst_id, unsigned int lease_sec);

/**
 * Deallocate a disk lock.
 * @param [in] lock_id: lock_id
 * @return 0 success
 * @return != 0 fail
 */
int cm_dl_dealloc(unsigned int lock_id);

/**
 * Try lock.
 * @param [in] lock_id: lock_id
 * @param [in] timeout_ms: wait time, unit: ms. If timeout_ms is greater than 0, wait for the specified time.
 *                         If timeout_ms is equal to 0, do not wait. If timeout_ms is less than 0, wait forever.
 * @return 0 success
 * @return != 0 fail
 */
int cm_dl_lock(unsigned int lock_id, int timeout_ms);

/**
 * Unlock.
 * @param [in] lock_id: lock_id
 * @return 0 success
 * @return != 0 fail
 */
int cm_dl_unlock(unsigned int lock_id);

/**
 * Clean the lock of other instance.
 * @param [in] lock_id: lock_id
 * @param [in] inst_id: target inst_id
 * @return 0 success
 * @return != 0 fail
 */
int cm_dl_clean(unsigned int lock_id, unsigned long long inst_id);

/**
 * Get the lock's owner.
 * @param [in] lock_id: lock_id
 * @param [out] inst_id: owner's inst_id. If the lock does not have an owner, CM_INVALID_INST_ID will be returned.
 * @return 0 success
 * @return != 0 fail
 */
int cm_dl_getowner(unsigned int lock_id, unsigned long long *inst_id);

/**
 * Get the lock's time.
 * @param [in] lock_id: lock_id
 * @param [out] locktime: locktime of the lock. If the lock does not have an owner, 0 will be returned. 
 * @return 0 success
 * @return != 0 fail
 */
int cm_dl_getlocktime(unsigned int lock_id, unsigned long long *locktime);

#ifdef __cplusplus
}
#endif

#endif