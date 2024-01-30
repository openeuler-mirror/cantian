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
 * srv_rm.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_rm.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "srv_rm.h"
#include "srv_agent.h"
#include "srv_instance.h"
#include "dml_executor.h"
#include "cm_log.h"
#include "cm_ip.h"
#include "knl_xact_log.h"

void rm_pool_init(rm_pool_t *pool)
{
    uint32 i;

    pool->lock = 0;
    pool->hwm = 0;
    pool->capacity = 0;
    pool->page_count = 0;

    pool->free_list.count = 0;
    pool->free_list.first = CT_INVALID_ID16;
    pool->free_list.last = CT_INVALID_ID16;

    for (i = 0; i < CT_MAX_RM_BUCKETS; i++) {
        pool->buckets[i].lock = 0;
        pool->buckets[i].count = 0;
        pool->buckets[i].first = CT_INVALID_ID16;
    }
}

static inline knl_rm_t *rm_addr(rm_pool_t *pool, uint32 id)
{
    uint32 page_id = id / CT_EXTEND_RMS;
    uint32 slot_id = id % CT_EXTEND_RMS;
    return (knl_rm_t *)(pool->pages[page_id] + slot_id * sizeof(knl_rm_t));
}

static status_t rm_pool_extend(rm_pool_t *pool)
{
    char *buf = NULL;
    size_t alloc_size;
    errno_t ret;

    if (pool->capacity >= g_instance->kernel.attr.max_rms) {
        CT_THROW_ERROR(ERR_TOO_MANY_RM_OBJECTS, g_instance->kernel.attr.max_rms);
        CT_LOG_RUN_WAR("too many rm objects");
        return CT_ERROR;
    }

    CM_ASSERT(pool->page_count < CT_MAX_RM_PAGES);

    alloc_size = sizeof(knl_rm_t) * CT_EXTEND_RMS;
    buf = (char *)malloc(alloc_size);
    if (buf == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)alloc_size, "alloc rm");
        CT_LOG_RUN_WAR("alloc rm failed");
        return CT_ERROR;
    }

    ret = memset_sp(buf, alloc_size, 0, alloc_size);
    knl_securec_check(ret);

    pool->capacity += CT_EXTEND_RMS;
    pool->pages[pool->page_count++] = buf;

    return CT_SUCCESS;
}

static status_t rm_alloc(rm_pool_t *rm_pool, uint16 *rmid)
{
    knl_rm_t *rm = NULL;

    if (rm_pool->free_list.count == 0 && rm_pool->hwm == rm_pool->capacity) {
        if (rm_pool_extend(rm_pool) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (rm_pool->free_list.count == 0) {
        *rmid = rm_pool->hwm;
        rm = rm_addr(rm_pool, *rmid);
        knl_init_rm(rm, *rmid);

        rm_pool->rms[rm_pool->hwm] = rm;
        g_instance->kernel.rms[rm_pool->hwm] = rm;
        rm_pool->hwm++;
        g_instance->kernel.rm_count++;
    } else {
        *rmid = rm_pool->free_list.first;
        rm = rm_addr(rm_pool, *rmid);
        CM_ASSERT(rm->id == *rmid);

        rm_pool->free_list.first = rm->next;
        rm_pool->free_list.count--;
        if (rm_pool->free_list.count == 0) {
            rm_pool->free_list.first = CT_INVALID_ID16;
            rm_pool->free_list.last = CT_INVALID_ID16;
        }
    }

    return CT_SUCCESS;
}

static inline void rm_release(rm_pool_t *rm_pool, uint16 rmid)
{
    knl_rm_t *rm = rm_pool->rms[rmid];

    CM_ASSERT(rmid != CT_INVALID_ID16 && rm->id == rmid);
    rm->sid = CT_INVALID_ID16;
    rm->uid = CT_INVALID_ID32;
    rm->next = CT_INVALID_ID16;
    rm->nolog_type = LOGGING_LEVEL;
    rm->nolog_insert = CT_FALSE;
    rm->logging = CT_TRUE;

    if (rm_pool->free_list.count == 0) {
        rm->prev = CT_INVALID_ID16;
        rm_pool->free_list.first = rmid;
        rm_pool->free_list.last = rmid;
    } else {
        rm->prev = rm_pool->free_list.last;
        rm_pool->rms[rm_pool->free_list.last]->next = rmid;
        rm_pool->free_list.last = rmid;
    }

    lob_items_reset(rm);
    rm_pool->free_list.count++;
}

static inline void rm_add_to_bucket(rm_pool_t *rm_pool, rm_bucket_t *bucket, uint16 rmid, uint8 status)
{
    knl_rm_t *rm = NULL;

    if (bucket->first != CT_INVALID_ID16) {
        rm = rm_pool->rms[bucket->first];
        rm->xa_prev = rmid;
    }

    rm = rm_pool->rms[rmid];
    rm->xa_status = status;
    rm->xa_next = bucket->first;

    bucket->first = rmid;
    bucket->count++;
}

static inline uint16 rm_find_from_bucket(rm_pool_t *rm_pool, rm_bucket_t *bucket, knl_xa_xid_t *xa_xid)
{
    uint16 rmid = bucket->first;
    knl_rm_t *rm = NULL;

    while (rmid != CT_INVALID_ID16) {
        rm = rm_pool->rms[rmid];

        if (knl_xa_xid_equal(xa_xid, &rm->xa_xid)) {
            return rmid;
        }

        rmid = rm->xa_next;
    }

    return rmid;
}

static inline void rm_remove_from_bucket(rm_pool_t *rm_pool, rm_bucket_t *bucket, uint16 rmid)
{
    knl_rm_t *rm = NULL;

    CM_ASSERT(bucket->count > 0);

    rm = rm_pool->rms[rmid];
    if (rm->xa_prev != CT_INVALID_ID16) {
        rm_pool->rms[rm->xa_prev]->xa_next = rm->xa_next;
    }

    if (rm->xa_next != CT_INVALID_ID16) {
        rm_pool->rms[rm->xa_next]->xa_prev = rm->xa_prev;
    }

    if (rmid == bucket->first) {
        bucket->first = rm->xa_next;
    }

    bucket->count--;
    knl_xa_reset_rm(rm);
}

status_t srv_alloc_rm(uint16 *rmid)
{
    rm_pool_t *rm_pool = &g_instance->rm_pool;
    knl_rm_t *rm = NULL;

    cm_spin_lock(&rm_pool->lock, NULL);
    if (rm_alloc(rm_pool, rmid) != CT_SUCCESS) {
        cm_spin_unlock(&rm_pool->lock);
        return CT_ERROR;
    }
    cm_spin_unlock(&rm_pool->lock);

    rm = rm_pool->rms[*rmid];
    rm->prev = CT_INVALID_ID16;
    rm->next = CT_INVALID_ID16;
    return CT_SUCCESS;
}

void srv_release_rm(uint16 rmid)
{
    rm_pool_t *rm_pool = &g_instance->rm_pool;

    cm_spin_lock(&rm_pool->lock, NULL);
    rm_release(rm_pool, rmid);
    cm_spin_unlock(&rm_pool->lock);
}

status_t srv_alloc_auton_rm(knl_handle_t handle)
{
    session_t *session = (session_t *)handle;
    rm_pool_t *rm_pool = &g_instance->rm_pool;
    knl_rm_t *rm = NULL;
    uint16 rmid;

    cm_spin_lock(&rm_pool->lock, NULL);
    if (rm_alloc(rm_pool, &rmid) != CT_SUCCESS) {
        cm_spin_unlock(&rm_pool->lock);
        return CT_ERROR;
    }
    cm_spin_unlock(&rm_pool->lock);

    rm = rm_pool->rms[rmid];
    rm->prev = session->knl_session.rmid;
    rm->next = CT_INVALID_ID16;

    session->knl_session.rm->next = rmid;
    knl_set_session_rm(session, rmid);
    return CT_SUCCESS;
}

status_t srv_release_auton_rm(knl_handle_t handle)
{
    session_t *session = (session_t *)handle;
    rm_pool_t *rm_pool = &g_instance->rm_pool;
    knl_rm_t *rm = NULL;
    uint16 curr, prev;
    status_t status = CT_SUCCESS;

    curr = session->knl_session.rmid;
    rm = session->knl_session.rm;

    prev = rm->prev;
    if (prev == CT_INVALID_ID16) {
        return CT_SUCCESS;
    }

    if (knl_xact_status(&session->knl_session) != XACT_END) {
        do_rollback(session, NULL);
        CT_THROW_ERROR(ERR_TXN_IN_PROGRESS, "detect active transaction at the end of autonomous session");
        status = CT_ERROR;
    }

    rm = rm_pool->rms[prev];
    rm->next = CT_INVALID_ID16;

    session->knl_session.rmid = prev;
    session->knl_session.rm = rm;

    cm_spin_lock(&rm_pool->lock, NULL);
    rm_release(rm_pool, curr);
    cm_spin_unlock(&rm_pool->lock);

    return status;
}

uint16 srv_get_xa_xid(knl_xa_xid_t *xa_xid)
{
    rm_pool_t *rm_pool = &g_instance->rm_pool;
    rm_bucket_t *bucket = NULL;
    uint16 rmid;
    uint32 hash;

    hash = knl_xa_xid_hash(xa_xid);
    bucket = &rm_pool->buckets[hash];

    cm_spin_lock(&bucket->lock, NULL);
    rmid = rm_find_from_bucket(rm_pool, bucket, xa_xid);
    cm_spin_unlock(&bucket->lock);

    return rmid;
}

bool32 srv_add_xa_xid(knl_xa_xid_t *xa_xid, uint16 rmid, uint8 status)
{
    rm_pool_t *rm_pool = &g_instance->rm_pool;
    rm_bucket_t *bucket = NULL;
    uint16 temp;
    uint32 hash;

    hash = knl_xa_xid_hash(xa_xid);
    bucket = &rm_pool->buckets[hash];

    cm_spin_lock(&bucket->lock, NULL);
    temp = rm_find_from_bucket(rm_pool, bucket, xa_xid);
    if (temp != CT_INVALID_ID16) {
        cm_spin_unlock(&bucket->lock);
        return CT_FALSE;
    }

    rm_add_to_bucket(rm_pool, bucket, rmid, status);
    cm_spin_unlock(&bucket->lock);
    return CT_TRUE;
}

void srv_delete_xa_xid(knl_xa_xid_t *xa_xid)
{
    rm_pool_t *rm_pool = &g_instance->rm_pool;
    rm_bucket_t *bucket = NULL;
    uint16 rmid;
    uint32 hash;

    hash = knl_xa_xid_hash(xa_xid);
    bucket = &rm_pool->buckets[hash];

    cm_spin_lock(&bucket->lock, NULL);
    rmid = rm_find_from_bucket(rm_pool, bucket, xa_xid);
    if (rmid == CT_INVALID_ID16) {
        cm_spin_unlock(&bucket->lock);
        return;
    }

    rm_remove_from_bucket(rm_pool, bucket, rmid);
    cm_spin_unlock(&bucket->lock);
}

static inline void assign_trans_to_bg_rollback(knl_rm_t *rm)
{
    undo_t *undo = &g_instance->kernel.undo_ctx.undos[rm->tx_id.seg_id];
    g_instance->kernel.tran_ctx.rollback_num = g_instance->kernel.attr.tx_rollback_proc_num;
    undo->items[rm->tx_id.item_id].rmid = g_instance->kernel.sessions[SESSION_ID_ROLLBACK]->rmid;
    CM_ASSERT(XID_INST_ID(rm->xid) == g_instance->id);

    undo_context_t *ctx = &g_instance->kernel.undo_ctx;
    undo_set_t *undo_set = &ctx->undo_sets[XID_INST_ID(rm->xid)];
    CT_LOG_RUN_INF("[assign_trans_to_bg_rollback] update undo_ctx active_workers");
    update_undo_ctx_active_workers(ctx, undo_set);
}

void srv_shrink_xa_rms(knl_handle_t handle, bool32 force)
{
    session_t *session = (session_t *)handle;
    uint16 org_rmid = session->knl_session.rmid;
    knl_rm_t *org_rm = session->knl_session.rm;
    rm_pool_t *rm_pool = &g_instance->rm_pool;
    bool32 release_rm = CT_FALSE;
    knl_rm_t *rm = NULL;
    uint64 timeout;

    for (uint16 i = 0; i < rm_pool->hwm; i++) {
        CT_BREAK_IF_TRUE(session->knl_session.canceled);
        CT_BREAK_IF_TRUE(session->knl_session.killed);

        rm = rm_pool->rms[i];
        CT_CONTINUE_IFTRUE(!knl_xa_xid_valid(&rm->xa_xid));

        session->knl_session.rmid = i;
        session->knl_session.rm = rm;

        cm_spin_lock(&rm->lock, NULL);
        if (rm->xa_status == XA_PENDING) {
            if (force) {
                lock_free_sch_group(&session->knl_session);
                // used for rollback procs to recover table locks of current residual xa transaction
                assign_trans_to_bg_rollback(rm);
                knl_tx_reset_rm(rm);
                CT_LOG_DEBUG_INF("lock free sch group of pending rm.rmid %u", i);
                release_rm = CT_TRUE;
            }
        }

        if (rm->xa_status == XA_SUSPEND) {
            timeout = (uint64)(KNL_NOW(&session->knl_session) - rm->suspend_time);
            if (force || timeout / MICROSECS_PER_SECOND > rm->suspend_timeout) {
                do_rollback(session, NULL);
                CT_LOG_DEBUG_INF("rollback timeout suspend rm.rmid %u", i);
                release_rm = CT_TRUE;
            }
        }

        if (release_rm) {
            rm->xa_status = XA_INVALID;
        }
        cm_spin_unlock(&rm->lock);

        if (release_rm) {
            srv_delete_xa_xid(&rm->xa_xid);
            cm_spin_lock(&rm_pool->lock, NULL);
            rm_release(rm_pool, i);
            cm_spin_unlock(&rm_pool->lock);
        }
        release_rm = CT_FALSE;
    }

    session->knl_session.rmid = org_rmid;
    session->knl_session.rm = org_rm;
}

static bool32 srv_attach_rm(session_t *session, knl_xa_xid_t *xa_xid, uint8 exp_status, uint8 status, bool8 release)
{
    rm_pool_t *rm_pool = &g_instance->rm_pool;
    knl_rm_t *rm = NULL;
    uint16 rmid, curr;

    rmid = srv_get_xa_xid(xa_xid);
    if (rmid == CT_INVALID_ID16) {
        return CT_FALSE;
    }

    rm = rm_pool->rms[rmid];

    if (rm->xa_status != exp_status) {
        return CT_FALSE;
    }

    cm_spin_lock(&rm->lock, NULL);
    if (rm->xa_status != exp_status || !knl_xa_xid_equal(xa_xid, &rm->xa_xid)) {
        cm_spin_unlock(&rm->lock);
        return CT_FALSE;
    }

    /* the transaction branch can not be ended in one session, but resumed in another one */
    if ((rm->xa_flags & KNL_XA_NOMIGRATE) && exp_status == XA_SUSPEND && status == XA_START &&
        rm->sid != session->knl_session.id) {
        cm_spin_unlock(&rm->lock);
        return CT_FALSE;
    }

    rm->xa_status = status;
    cm_spin_unlock(&rm->lock);

    curr = session->knl_session.rmid;

    session->knl_session.rmid = rmid;
    session->knl_session.rm = rm;
    rm->sid = session->knl_session.id;

    if (release) {
        CM_ASSERT(curr != CT_INVALID_ID16);
        cm_spin_lock(&rm_pool->lock, NULL);
        rm_release(rm_pool, curr);
        cm_spin_unlock(&rm_pool->lock);
    }

    return CT_TRUE;
}

void srv_detach_suspend_rm(knl_handle_t handle, uint16 new_rmid)
{
    session_t *session = (session_t *)handle;
    knl_rm_t *rm = session->knl_session.rm;

    CM_ASSERT(rm != NULL);
    rm->xa_status = XA_SUSPEND;
    rm->suspend_time = KNL_NOW(&session->knl_session);
    if (!(rm->xa_flags & KNL_XA_NOMIGRATE)) {
        rm->sid = CT_INVALID_ID16;
    }

    knl_set_session_rm(session, new_rmid);
}

bool32 srv_attach_suspend_rm(knl_handle_t handle, knl_xa_xid_t *xa_xid, uint8 status, bool8 release)
{
    return srv_attach_rm((session_t *)handle, xa_xid, XA_SUSPEND, status, release);
}

void srv_detach_pending_rm(knl_handle_t handle, uint16 new_rmid)
{
    session_t *session = (session_t *)handle;
    knl_rm_t *rm = session->knl_session.rm;

    CM_ASSERT(rm != NULL);
    rm->xa_status = XA_PENDING;
    rm->sid = CT_INVALID_ID16;

    knl_set_session_rm(session, new_rmid);
}

bool32 srv_attach_pending_rm(knl_handle_t handle, knl_xa_xid_t *xa_xid)
{
    return srv_attach_rm((session_t *)handle, xa_xid, XA_PENDING, XA_PHASE2, CT_FALSE);
}
