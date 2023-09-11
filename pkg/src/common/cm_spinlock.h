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
 * cm_spinlock.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_spinlock.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_SPINLOCK_H_
#define __CM_SPINLOCK_H_

#include "cm_defs.h"

#ifndef WIN32
#include <time.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef volatile uint32 spinlock_t;
typedef volatile uint32 ip_spinlock_t;
#if defined(__arm__) || defined(__aarch64__)
#define GS_INIT_SPIN_LOCK(lock)                       \
    {                                                 \
        __atomic_store_n(&lock, 0, __ATOMIC_SEQ_CST); \
    }
#else
#define GS_INIT_SPIN_LOCK(lock) \
    {                           \
        (lock) = 0;               \
    }
#endif

#define GS_SPIN_COUNT             1000
#define SPIN_STAT_INC(stat, item) \
    {                             \
        if ((stat) != NULL) {     \
            ((stat)->item)++;     \
        }                         \
    }

typedef struct st_spin_statis {
    uint64 spins;
    uint64 wait_usecs;
    uint64 fails;
} spin_statis_t;

// caution!! can not use by session 0
typedef struct st_recursive_lock {
    spinlock_t mutex;
    uint16 sid;
    uint16 r_cnt;
} recursive_lock_t;


//all kind of distributed resource
typedef enum en_dr_type {
    DR_TYPE_INVALID = 0,
    DR_TYPE_DATABASE = 1,
    DR_TYPE_SPACE = 2,
    DR_TYPE_TABLE = 3,
    DR_TYPE_DDL = 4,
    DR_TYPE_SEQENCE = 5,
    DR_TYPE_SERIAL = 6,
    DR_TYPE_ROLE = 7,
    DR_TYPE_USER = 8,
    DR_TYPE_DC = 9,
    DR_TYPE_INDEX = 10,
    DR_TYPE_TRIGGER = 11,
    DR_TYPE_HEAP = 12,
    DR_TYPE_HEAP_PART = 13,
    DR_TYPE_HEAP_LATCH = 14,
    DR_TYPE_HEAP_PART_LATCH = 15,
    DR_TYPE_BTREE_LATCH = 16,
    DR_TYPE_BRTEE_PART_LATCH = 17,
    DR_TYPE_INTERVAL_PART_LATCH = 18,
    DR_TYPE_LOB_LATCH = 19,
    DR_TYPE_LOB_PART_LATCH = 20,
    DR_TYPE_PROFILE = 21,
    DR_TYPE_UNDO = 22,
    DR_TYPE_PROC = 23,
    DR_TYPE_GDV = 24,
    DR_TYPE_SHUTDOWN = 25,
}dr_type_t;

//persistent distributed resource id
typedef enum en_dr_persistent_id {
    DR_ID_DATABASE_CTRL = 0,
    DR_ID_DATABASE_SWITCH_CTRL = 1,
    DR_ID_DATABASE_BAKUP = 2,
    DR_ID_DATABASE_LINK = 3,
    DR_ID_SPACE_OP = 10,
    DR_ID_SPACE_BLOCK = 11,
    DR_ID_DDL_OP = 20,
    DR_ID_DC_CTX = 30,
    DR_ID_INDEX_RECYLE = 40,
    DR_ID_UNDO_SET = 50,
}dr_pst_id_t;


//for DTC
//distributed resource lock id
#pragma pack(4)
typedef struct st_dr_id {
    union {
        struct {
            uint64 key1;
            uint64 key2; // index partition
            uint32 key3;
        };
        struct {
            uint16    type;  //lock type
            uint16    uid; //user id, for table lock resource
            uint32    id; //lock id

            uint32    idx; // index id
            uint32    part; // partition id

            uint32 subpart;  // sub partition id
        };
    };
} drid_t;
#pragma pack()

//distributed resource lock
typedef struct st_dr_lock {
    spinlock_t lock;
    drid_t  drid;
}drlock_t;

#if defined(__arm__) || defined(__aarch64__)
#define fas_cpu_pause()          \
    {                            \
        __asm__ volatile("nop"); \
    }
#else
#define fas_cpu_pause()            \
    {                              \
        __asm__ volatile("pause"); \
    }
#endif

void cm_spin_sleep_and_stat(spin_statis_t *stat);
void cm_spin_sleep_and_stat2(uint32 ms);
uint64 cm_total_spin_usecs(void);

#ifdef WIN32

static inline uint32 cm_spin_set(spinlock_t *ptr, uint32 value)
{
    return (uint32)InterlockedExchange(ptr, value);
}

static inline void cm_spin_sleep()
{
    Sleep(1);
}

static inline void cm_spin_sleep_ex(uint32 tick)
{
    Sleep(tick);
}

#else

#if defined(__arm__) || defined(__aarch64__)
static inline uint32 cm_spin_set(spinlock_t *ptr, uint32 value)
{
    uint32 oldvalue = 0;
    return !__atomic_compare_exchange_n(ptr, &oldvalue, value, GS_FALSE, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}
static inline void cm_spin_unlock(spinlock_t *lock)
{
    __atomic_store_n(lock, 0, __ATOMIC_SEQ_CST);
}

#else
static inline uint32 cm_spin_set(spinlock_t *ptr, uint32 value)
{
    uint32 oldvalue = 0;
    return (uint32)__sync_val_compare_and_swap(ptr, oldvalue, value);
}
#endif

static inline void cm_spin_sleep(void)
{
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 100;
    nanosleep(&ts, NULL);
}

static inline void cm_spin_sleep_ex(uint32 tick)
{
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = tick;
    nanosleep(&ts, NULL);
}

#endif

static inline void cm_spin_lock(spinlock_t *lock, spin_statis_t *stat)
{
    uint32 spin_times = 0;
    uint32 sleep_times = 0;

    if (SECUREC_UNLIKELY(lock == NULL)) {
        return;
    }

    for (;;) {
#if defined(__arm__) || defined(__aarch64__)
        while (__atomic_load_n(lock, __ATOMIC_SEQ_CST) != 0) {
#else
        while (*lock != 0) {
#endif
            SPIN_STAT_INC(stat, spins);
            spin_times++;
            if (SECUREC_UNLIKELY(spin_times == GS_SPIN_COUNT)) {
                cm_spin_sleep_and_stat(stat);
                spin_times = 0;
            }
        }

        if (SECUREC_LIKELY(cm_spin_set(lock, 1) == 0)) {
            break;
        }

        SPIN_STAT_INC(stat, fails);
        sleep_times++;
#ifndef WIN32
        for (uint32 i = 0; i < sleep_times; i++) {
            fas_cpu_pause();
        }
#endif
    }
}

static inline void cm_spin_lock_ex(spinlock_t *lock, spin_statis_t *stat, uint32 spin_count)
{
    uint32 spin_times = 0;
    uint32 sleep_times = 0;
    if (SECUREC_UNLIKELY(lock == NULL)) {
        return;
    }

    for (;;) {
#if defined(__arm__) || defined(__aarch64__)
        while (__atomic_load_n(lock, __ATOMIC_SEQ_CST) != 0) {
#else
        while (*lock != 0) {
#endif
            SPIN_STAT_INC(stat, spins);
            spin_times++;
#ifndef WIN32
            fas_cpu_pause();
#endif  // !WIN32

            if (SECUREC_UNLIKELY(spin_times == spin_count)) {
                cm_spin_sleep_and_stat(stat);
                spin_times = 0;
            }
        }

        if (cm_spin_set(lock, 1) != 0) {
            SPIN_STAT_INC(stat, fails);
            sleep_times++;
#ifndef WIN32
            for (uint32 i = 0; i < sleep_times; i++) {
                fas_cpu_pause();
            }
#endif
            continue;
        }
        break;
    }
}

static inline void cm_spin_lock_by_sid(uint32 sid, spinlock_t *lock, spin_statis_t *stat)
{
    uint32 spin_times = 0;
    uint32 sleep_times = 0;
    if (SECUREC_UNLIKELY(lock == NULL)) {
        return;
    }

    for (;;) {
#if defined(__arm__) || defined(__aarch64__)
        while (__atomic_load_n(lock, __ATOMIC_SEQ_CST) != 0) {
#else
        while (*lock != 0) {
#endif
            SPIN_STAT_INC(stat, spins);
            spin_times++;
            if (SECUREC_UNLIKELY(spin_times == GS_SPIN_COUNT)) {
                cm_spin_sleep_and_stat(stat);
                spin_times = 0;
            }
        }

        if (SECUREC_LIKELY(cm_spin_set(lock, sid) == 0)) {
            break;
        }

        SPIN_STAT_INC(stat, fails);
        sleep_times++;
#ifndef WIN32
        for (uint32 i = 0; i < sleep_times; i++) {
            fas_cpu_pause();
        }
#endif
    }
}

#if !defined(__arm__) && !defined(__aarch64__)
static inline void cm_spin_unlock(spinlock_t *lock)
{
    if (SECUREC_UNLIKELY(lock == NULL)) {
        return;
    }

    *lock = 0;
}
#endif

static inline bool32 cm_spin_try_lock(spinlock_t *lock)
{
#if defined(__arm__) || defined(__aarch64__)
    if (__atomic_load_n(lock, __ATOMIC_SEQ_CST) != 0) {
#else
    if (*lock != 0) {
#endif
        return GS_FALSE;
    }

    return (cm_spin_set(lock, 1) == 0);
}

static inline bool32 cm_spin_timed_lock(spinlock_t *lock, uint32 timeout_ticks)
{
    uint32 spin_times = 0, wait_ticks = 0;
    uint32 sleep_times = 0;

    for (;;) {
#if defined(__arm__) || defined(__aarch64__)
        while (__atomic_load_n(lock, __ATOMIC_SEQ_CST) != 0) {
#else
        while (*lock != 0) {
#endif
            if (SECUREC_UNLIKELY(wait_ticks >= timeout_ticks)) {
                return GS_FALSE;
            }

#ifndef WIN32
            fas_cpu_pause();
#endif  // !WIN32

            spin_times++;
            if (SECUREC_UNLIKELY(spin_times == GS_SPIN_COUNT)) {
                cm_spin_sleep();
                spin_times = 0;
                wait_ticks++;
            }
        }

        if (cm_spin_set(lock, 1) != 0) {
            sleep_times++;
#ifndef WIN32
            for (uint32 i = 0; i < sleep_times; i++) {
                fas_cpu_pause();
            }
#endif
            continue;
        }
        break;
    }

    return GS_TRUE;
}

// caution!! can not use by session 0
static inline void cm_recursive_lock(uint16 sid, recursive_lock_t *lock, spin_statis_t *stat)
{
    if (lock->sid == sid) {
        lock->r_cnt++;
        return;
    }

    cm_spin_lock(&lock->mutex, stat);

    lock->sid = sid;
    lock->r_cnt = 1;
}

// caution!! can not use by session 0
static inline void cm_recursive_unlock(recursive_lock_t *lock)
{
    if (lock->r_cnt > 1) {
        lock->r_cnt--;
        return;
    }
    lock->r_cnt = 0;
    lock->sid = 0;
    cm_spin_unlock(&lock->mutex);
}

static inline void cm_spin_lock_if_exists(spinlock_t *lock, spin_statis_t *stat)
{
    if (lock == NULL) {
        return;
    }
    cm_spin_lock(lock, stat);
}

static inline void cm_spin_unlock_if_exists(spinlock_t *lock)
{
    if (lock == NULL) {
        return;
    }
    cm_spin_unlock(lock);
}

#ifdef __cplusplus
}
#endif

#endif
