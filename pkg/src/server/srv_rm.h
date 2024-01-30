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
 * srv_rm.h
 *
 *
 * IDENTIFICATION
 * src/server/srv_rm.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SRV_RM_H__
#define __SRV_RM_H__

#include "cm_defs.h"
#include "cm_spinlock.h"
#include "srv_session.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_rm_list {
    uint32 count;
    uint16 first;
    uint16 last;
} rm_list_t;

typedef struct st_rm_bucket {
    spinlock_t lock;
    uint16 count;
    uint16 first;
} rm_bucket_t;

typedef struct st_rm_pool {
    spinlock_t lock;
    uint32 hwm;
    uint32 capacity;
    uint32 page_count;
    char *pages[CT_MAX_RM_PAGES];
    knl_rm_t *rms[CT_MAX_RMS];
    rm_bucket_t buckets[CT_MAX_RM_BUCKETS];
    rm_list_t free_list;
} rm_pool_t;

void rm_pool_init(rm_pool_t *pool);
status_t srv_alloc_rm(uint16 *rmid);
void srv_release_rm(uint16 rmid);
status_t srv_alloc_auton_rm(knl_handle_t handle);
status_t srv_release_auton_rm(knl_handle_t handle);
void srv_detach_suspend_rm(knl_handle_t handle, uint16 new_rmid);
bool32 srv_attach_suspend_rm(knl_handle_t handle, knl_xa_xid_t *xa_xid, uint8 status, bool8 release);
void srv_detach_pending_rm(knl_handle_t handle, uint16 new_rmid);
bool32 srv_attach_pending_rm(knl_handle_t handle, knl_xa_xid_t *xa_xid);
uint16 srv_get_xa_xid(knl_xa_xid_t *xa_xid);
bool32 srv_add_xa_xid(knl_xa_xid_t *xa_xid, uint16 rmid, uint8 status);
void srv_delete_xa_xid(knl_xa_xid_t *xa_xid);
void srv_shrink_xa_rms(knl_handle_t handle, bool32 force);

#ifdef __cplusplus
}
#endif

#endif
