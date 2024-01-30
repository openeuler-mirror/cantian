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
 * knl_buflatch.h
 *
 *
 * IDENTIFICATION
 * src/kernel/buffer/knl_buflatch.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_BUFLATCH_H__
#define __KNL_BUFLATCH_H__

#include "cm_types.h"
#include "cm_spinlock.h"
#include "knl_buffer.h"
#include "knl_context.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline void buf_stat_page_inc(knl_session_t *session, uint32 count)
{
    if (STATS_ENABLE_PAGE(session)) {
        session->stat_page.hits++;
        session->stat_page.spin_gets = (count == 0) ? 0 : session->stat_page.spin_gets + 1;
    }
}

/* buffer latch interface */
static inline void buf_latch_ix2x(knl_session_t *session, buf_latch_t *latch, spinlock_t *lock, wait_event_t event)
{
    uint32 count = 0;

    do {
        session->stat_page.misses++;
        while (latch->shared_count > 0) {
            knl_begin_session_wait(session, event, CT_TRUE);
            count++;
            if (count >= CT_SPIN_COUNT) {
                SPIN_STAT_INC(&session->stat_page, ix_sleeps);
                cm_spin_sleep();
                count = 0;
            }
        }

        cm_spin_lock(lock, &session->stat->spin_stat.stat_bucket);
        if (latch->shared_count == 0) {
            latch->sid = session->id;
            latch->stat = LATCH_STATUS_X;
            cm_spin_unlock(lock);
            buf_stat_page_inc(session, count);
            knl_end_session_wait(session, event);
            return;
        }
        cm_spin_unlock(lock);
    } while (1);
}

static inline void buf_latch_x(knl_session_t *session, buf_ctrl_t *ctrl, bool32 lock_needed)
{
    uint32 count = 0;
    buf_set_t *set = &session->kernel->buf_ctx.buf_set[ctrl->buf_pool_id];
    buf_bucket_t *bucket = BUF_GET_BUCKET(set, ctrl->bucket_id);
    buf_latch_t *latch = &ctrl->latch;

    if (lock_needed) {
        cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
    }

    wait_event_t event = ctrl->transfer_status == BUF_TRANS_TRY_REMOTE ? GC_BUFFER_BUSY : BUFFER_BUSY_WAIT;

    do {
        if (latch->stat == LATCH_STATUS_IDLE) {
            latch->sid = session->id;
            latch->stat = LATCH_STATUS_X;
            cm_spin_unlock(&bucket->lock);
            buf_stat_page_inc(session, count);
            knl_end_session_wait(session, event);
            return;
        } else if (latch->stat == LATCH_STATUS_S) {
            latch->stat = LATCH_STATUS_IX;
            cm_spin_unlock(&bucket->lock);
            buf_latch_ix2x(session, latch, &bucket->lock, event);
            return;
        } else {
            cm_spin_unlock(&bucket->lock);
            session->stat_page.misses++;
            while (latch->stat != LATCH_STATUS_IDLE && latch->stat != LATCH_STATUS_S) {
                knl_begin_session_wait(session, event, CT_TRUE);
                count++;
                if (count >= CT_SPIN_COUNT) {
                    SPIN_STAT_INC(&session->stat_page, x_sleeps);
                    cm_spin_sleep();
                    count = 0;
                }
            }
            cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
        }
    } while (1);
}

static inline void buf_latch_s(knl_session_t *session, buf_ctrl_t *ctrl, bool32 is_force, bool32 lock_needed)
{
    uint32 count = 0;
    buf_set_t *set = &session->kernel->buf_ctx.buf_set[ctrl->buf_pool_id];
    buf_bucket_t *bucket = BUF_GET_BUCKET(set, ctrl->bucket_id);
    buf_latch_t *latch = &ctrl->latch;

    if (lock_needed) {
        cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
    }

    wait_event_t event = ctrl->transfer_status == BUF_TRANS_TRY_REMOTE ? GC_BUFFER_BUSY : BUFFER_BUSY_WAIT;

    do {
        if (latch->stat == LATCH_STATUS_IDLE) {
            latch->stat = LATCH_STATUS_S;
            latch->shared_count = 1;
            latch->sid = session->id;
            cm_spin_unlock(&bucket->lock);
            buf_stat_page_inc(session, count);
            knl_end_session_wait(session, event);
            return;
        } else if ((latch->stat == LATCH_STATUS_S) || (latch->stat == LATCH_STATUS_IX && is_force)) {
            latch->shared_count++;
            cm_spin_unlock(&bucket->lock);
            buf_stat_page_inc(session, count);
            knl_end_session_wait(session, event);
            return;
        } else {
            cm_spin_unlock(&bucket->lock);
            session->stat_page.misses++;
            while (latch->stat != LATCH_STATUS_IDLE && latch->stat != LATCH_STATUS_S) {
                knl_begin_session_wait(session, event, CT_TRUE);
                count++;
                if (count >= CT_SPIN_COUNT) {
                    SPIN_STAT_INC(&session->stat_page, s_sleeps);
                    cm_spin_sleep();
                    count = 0;
                }
            }
            cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
        }
    } while (1);
}

static inline bool32 buf_latch_timed_s(knl_session_t *session, buf_ctrl_t *ctrl, uint32 wait_ticks,
    bool32 is_force, bool32 lock_needed)
{
    buf_set_t *set;
    buf_bucket_t *bucket;
    buf_latch_t *latch;
    uint32 count, ticks;

    count = 0;
    ticks = 0;
    set = &session->kernel->buf_ctx.buf_set[ctrl->buf_pool_id];
    bucket = BUF_GET_BUCKET(set, ctrl->bucket_id);
    latch = &ctrl->latch;

    if (lock_needed) {
        cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
    }

    do {
        if (latch->stat == LATCH_STATUS_IDLE) {
            latch->stat = LATCH_STATUS_S;
            latch->shared_count = 1;
            latch->sid = session->id;
            cm_spin_unlock(&bucket->lock);
            return CT_TRUE;
        } else if ((latch->stat == LATCH_STATUS_S) || (latch->stat == LATCH_STATUS_IX && is_force)) {
            latch->shared_count++;
            cm_spin_unlock(&bucket->lock);
            return CT_TRUE;
        } else {
            cm_spin_unlock(&bucket->lock);
            while (latch->stat != LATCH_STATUS_IDLE && latch->stat != LATCH_STATUS_S) {
                if (ticks >= wait_ticks) {
                    return CT_FALSE;
                }

                count++;
                if (count >= CT_SPIN_COUNT) {
                    SPIN_STAT_INC(&session->stat_page, s_sleeps);
                    cm_spin_sleep();
                    count = 0;
                    ticks++;
                }
            }
            cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
        }
    } while (1);
}

static inline void buf_unlatch(knl_session_t *session, buf_ctrl_t *ctrl, bool32 release)
{
    buf_set_t *set;
    buf_bucket_t *bucket;
    buf_latch_t *latch;

    set = &session->kernel->buf_ctx.buf_set[ctrl->buf_pool_id];
    bucket = BUF_GET_BUCKET(set, ctrl->bucket_id);
    latch = &ctrl->latch;

    cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);

    if (latch->shared_count > 0) {
        latch->shared_count--;
    }

    if (release) {
        knl_panic_log(ctrl->ref_num > 0, "ctrl's ref_num is invalid, panic info: page %u-%u type %u ref_num %u",
                      ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type, ctrl->ref_num);
        ctrl->ref_num--;
    }

    if ((latch->stat == LATCH_STATUS_S || latch->stat == LATCH_STATUS_X) && (latch->shared_count == 0)) {
        latch->stat = LATCH_STATUS_IDLE;
    }

    cm_spin_unlock(&bucket->lock);
}

#ifdef __cplusplus
}
#endif

#endif
