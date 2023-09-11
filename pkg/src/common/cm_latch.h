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
 * cm_latch.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_latch.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_LATCH_H_
#define __CM_LATCH_H_

#include "cm_types.h"
#include "cm_spinlock.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_latch_mode {
    LATCH_MODE_S = 1,
    LATCH_MODE_X = 2,
    LATCH_MODE_FORCE_S = 3,
} latch_mode_t;

typedef enum en_latch_status {
    LATCH_STATUS_IDLE = 0,
    LATCH_STATUS_S = 1,
    LATCH_STATUS_IX = 2,
    LATCH_STATUS_X = 3,
} latch_stat_e;

typedef struct st_latch {
    spinlock_t lock;
    volatile uint16 shared_count;
    volatile uint16 stat;
    volatile uint16 sid;
    uint16 unused;
} latch_t;

typedef struct st_latch_statis {
    uint64 r_sleeps;
    uint64 x_sleeps;
    uint64 s_sleeps;
    uint64 ix_sleeps;

    spin_statis_t x_spin;
    spin_statis_t s_spin;
    spin_statis_t ix_spin;

    uint32 hits;
    uint32 misses;
    uint32 spin_gets;
    bool32 enable;
} latch_statis_t;

//distributed resource latch
typedef struct st_dr_latch {
    latch_t latch;
    drid_t  drid;
}drlatch_t;

static inline void cm_latch_stat_inc(latch_statis_t *stat, uint32 count)
{
    if (stat != NULL && stat->enable) {
        stat->hits++;
        stat->spin_gets = (count == 0) ? 0 : stat->spin_gets + 1;
    }
}

static inline void cm_latch_ix2x(latch_t *latch, uint32 sid, latch_statis_t *stat)
{
    uint32 count = 0;

    do {
        if (stat != NULL) {
            stat->misses++;
        }
        while (latch->shared_count > 0) {
            count++;
            if (count >= GS_SPIN_COUNT) {
                SPIN_STAT_INC(stat, ix_sleeps);
                cm_spin_sleep();
                count = 0;
            }
        }

        cm_spin_lock(&latch->lock, (stat != NULL) ? &stat->ix_spin : NULL);
        if (latch->shared_count == 0) {
            latch->sid = sid;
            latch->stat = LATCH_STATUS_X;
            cm_spin_unlock(&latch->lock);
            cm_latch_stat_inc(stat, count);
            return;
        }
        cm_spin_unlock(&latch->lock);
    } while (1);
}

static inline bool32 cm_latch_timed_ix2x(latch_t *latch, uint32 sid, uint32 wait_ticks, latch_statis_t *stat)
{
    uint32 count = 0;
    uint32 ticks = 0;

    do {
        if (stat != NULL) {
            stat->misses++;
        }
        while (latch->shared_count > 0) {
            if (ticks >= wait_ticks) {
                return GS_FALSE;
            }

            count++;
            if (count >= GS_SPIN_COUNT) {
                SPIN_STAT_INC(stat, ix_sleeps);
                cm_spin_sleep();
                count = 0;
                ticks++;
            }
        }

        cm_spin_lock(&latch->lock, (stat != NULL) ? &stat->ix_spin : NULL);
        if (latch->shared_count == 0) {
            latch->sid = sid;
            latch->stat = LATCH_STATUS_X;
            cm_spin_unlock(&latch->lock);
            cm_latch_stat_inc(stat, count);
            return GS_TRUE;
        }

        cm_spin_unlock(&latch->lock);
    } while (1);
}

static inline void cm_latch_x(latch_t *latch, uint32 sid, latch_statis_t *stat)
{
    uint32 count = 0;

    do {
        cm_spin_lock(&latch->lock, (stat != NULL) ? &stat->x_spin : NULL);

        if (latch->stat == LATCH_STATUS_IDLE) {
            latch->sid = sid;
            latch->stat = LATCH_STATUS_X;
            cm_spin_unlock(&latch->lock);
            cm_latch_stat_inc(stat, count);
            return;
        } else if (latch->stat == LATCH_STATUS_S) {
            latch->stat = LATCH_STATUS_IX;
            cm_spin_unlock(&latch->lock);
            cm_latch_ix2x(latch, sid, stat);
            return;
        } else {
            cm_spin_unlock(&latch->lock);
            if (stat != NULL) {
                stat->misses++;
            }
            while (latch->stat != LATCH_STATUS_IDLE && latch->stat != LATCH_STATUS_S) {
                count++;
                if (count >= GS_SPIN_COUNT) {
                    SPIN_STAT_INC(stat, x_sleeps);
                    cm_spin_sleep();
                    count = 0;
                }
            }
        }
    } while (1);
}

static inline bool32 cm_latch_timed_x(latch_t *latch, uint32 sid, uint32 wait_ticks, latch_statis_t *stat)
{
    uint32 count = 0;
    uint32 ticks = 0;

    do {
        cm_spin_lock(&latch->lock, (stat != NULL) ? &stat->x_spin : NULL);

        if (latch->stat == LATCH_STATUS_IDLE) {
            latch->sid = sid;
            latch->stat = LATCH_STATUS_X;
            cm_spin_unlock(&latch->lock);
            cm_latch_stat_inc(stat, count);
            return GS_TRUE;
        } else if (latch->stat == LATCH_STATUS_S) {
            latch->stat = LATCH_STATUS_IX;
            cm_spin_unlock(&latch->lock);
            if (!cm_latch_timed_ix2x(latch, sid, wait_ticks, stat)) {
                cm_spin_lock(&latch->lock, (stat != NULL) ? &stat->x_spin : NULL);
                latch->stat = latch->shared_count > 0 ? LATCH_STATUS_S : LATCH_STATUS_IDLE;
                cm_spin_unlock(&latch->lock);
                return GS_FALSE;
            }
            return GS_TRUE;
        } else {
            cm_spin_unlock(&latch->lock);
            if (stat != NULL) {
                stat->misses++;
            }
            while (latch->stat != LATCH_STATUS_IDLE && latch->stat != LATCH_STATUS_S) {
                if (ticks >= wait_ticks) {
                    return GS_FALSE;
                }

                count++;
                if (count >= GS_SPIN_COUNT) {
                    SPIN_STAT_INC(stat, x_sleeps);
                    cm_spin_sleep();
                    count = 0;
                    ticks++;
                }
            }
        }
    } while (1);
}

static inline void cm_latch_s(latch_t *latch, uint32 sid, bool32 is_force, latch_statis_t *stat)
{
    uint32 count = 0;

    do {
        cm_spin_lock(&latch->lock, (stat != NULL) ? &stat->s_spin : NULL);

        if (latch->stat == LATCH_STATUS_IDLE) {
            latch->stat = LATCH_STATUS_S;
            latch->shared_count = 1;
            latch->sid = sid;
            cm_spin_unlock(&latch->lock);
            cm_latch_stat_inc(stat, count);
            return;
        } else if ((latch->stat == LATCH_STATUS_S) || (latch->stat == LATCH_STATUS_IX && is_force)) {
            latch->shared_count++;
            cm_spin_unlock(&latch->lock);
            cm_latch_stat_inc(stat, count);
            return;
        } else {
            cm_spin_unlock(&latch->lock);
            if (stat != NULL) {
                stat->misses++;
            }
            while (latch->stat != LATCH_STATUS_IDLE && latch->stat != LATCH_STATUS_S) {
                count++;
                if (count >= GS_SPIN_COUNT) {
                    SPIN_STAT_INC(stat, s_sleeps);
                    cm_spin_sleep();
                    count = 0;
                }
            }
        }
    } while (1);
}

static inline bool32 cm_latch_timed_s(latch_t *latch, uint32 wait_ticks, bool32 is_force, latch_statis_t *stat)
{
    uint32 count = 0;
    uint32 ticks = 0;

    do {
        cm_spin_lock(&latch->lock, (stat != NULL) ? &stat->s_spin : NULL);

        if (latch->stat == LATCH_STATUS_IDLE) {
            latch->stat = LATCH_STATUS_S;
            latch->shared_count = 1;
            cm_spin_unlock(&latch->lock);
            return GS_TRUE;
        } else if ((latch->stat == LATCH_STATUS_S) || (latch->stat == LATCH_STATUS_IX && is_force)) {
            latch->shared_count++;
            cm_spin_unlock(&latch->lock);
            return GS_TRUE;
        } else {
            cm_spin_unlock(&latch->lock);
            while (latch->stat != LATCH_STATUS_IDLE && latch->stat != LATCH_STATUS_S) {
                if (ticks >= wait_ticks) {
                    return GS_FALSE;
                }

                count++;
                if (count >= GS_SPIN_COUNT) {
                    SPIN_STAT_INC(stat, s_sleeps);
                    cm_spin_sleep();
                    count = 0;
                    ticks++;
                }
            }
        }
    } while (1);
}

static inline void cm_unlatch(latch_t *latch, latch_statis_t *stat)
{
    spin_statis_t *stat_spin = NULL;

    if (stat != NULL) {
        stat_spin = (LATCH_STATUS_S == latch->stat) ? &stat->s_spin : &stat->x_spin;
    }

    cm_spin_lock(&latch->lock, stat_spin);

    if (latch->shared_count > 0) {
        latch->shared_count--;
    }

    if ((latch->stat == LATCH_STATUS_S || latch->stat == LATCH_STATUS_X) && (latch->shared_count == 0)) {
        latch->stat = LATCH_STATUS_IDLE;
    }

    cm_spin_unlock(&latch->lock);
}

static inline const char *cm_latch_stat(uint16 stat)
{
    switch (stat) {
        case LATCH_STATUS_IDLE:
            return "idle";
        case LATCH_STATUS_S:
            return "s";
        case LATCH_STATUS_IX:
            return "ix";
        case LATCH_STATUS_X:
            return "x";
        default:
            return "invalid";
    }
}

static inline void cm_latch_init(latch_t *latch)
{
    latch->shared_count = 0;
    latch->sid = 0;
    latch->stat = 0;
    GS_INIT_SPIN_LOCK(latch->lock);
}

#ifdef __cplusplus
}

#endif

#endif
