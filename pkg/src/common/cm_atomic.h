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
 * cm_atomic.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_atomic.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_ATOMIC_H__
#define __CM_ATOMIC_H__

#include <stdlib.h>
#include "cm_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32

typedef volatile long atomic32_t;
typedef volatile int64 atomic_t;

static inline atomic_t cm_atomic_add(atomic_t *val, int64 count)
{
    return InterlockedAdd64(val, count);
}

static inline atomic_t cm_atomic_get(atomic_t *val)
{
    return InterlockedAdd64(val, 0);
}

static inline atomic_t cm_atomic_set(atomic_t *val, int64 value)
{
    return InterlockedExchange64(val, value);
}

static inline atomic_t cm_atomic_inc(atomic_t *val)
{
    return InterlockedIncrement64(val);
}

static inline atomic_t cm_atomic_dec(atomic_t *val)
{
    return InterlockedDecrement64(val);
}

static inline atomic32_t cm_atomic32_inc(atomic32_t *val)
{
    return InterlockedIncrement(val);
}

static inline atomic32_t cm_atomic32_dec(atomic32_t *val)
{
    return InterlockedDecrement(val);
}


static inline atomic32_t cm_atomic32_add(atomic32_t *val, int32 count)
{
    return InterlockedExchangeAdd(val, count);
}

static inline atomic32_t cm_atomic32_get(atomic32_t *val)
{
    return InterlockedCompareExchange(val, 0, 0);
}

static inline bool32 cm_atomic_cas(atomic_t *val, int64 oldval, int64 newval)
{
    return (InterlockedCompareExchange64(val, newval, oldval) == oldval) ? GS_TRUE : GS_FALSE;
}

static inline bool32 cm_atomic32_cas(atomic32_t *val, int32 oldval, int32 newval)
{
    return (InterlockedCompareExchange(val, newval, oldval) == oldval) ? GS_TRUE : GS_FALSE;
}

#else

typedef volatile int32 atomic32_t;
typedef volatile int64 atomic_t;
#if defined(__arm__) || defined(__aarch64__)
static inline int64 cm_atomic_get(atomic_t *val)
{
    return __atomic_load_n(val, __ATOMIC_SEQ_CST);
}

static inline int64 cm_atomic_set(atomic_t *val, int64 value)
{
    __atomic_store_n(val, value, __ATOMIC_SEQ_CST);
    return value;
}

static inline int64 cm_atomic_inc(atomic_t *val)
{
    return __atomic_add_fetch(val, 1, __ATOMIC_SEQ_CST);
}

static inline int64 cm_atomic_dec(atomic_t *val)
{
    return __atomic_add_fetch(val, -1, __ATOMIC_SEQ_CST);
}

static inline int32 cm_atomic32_inc(atomic32_t *val)
{
    return __atomic_add_fetch(val, 1, __ATOMIC_SEQ_CST);
}

static inline int32 cm_atomic32_dec(atomic32_t *val)
{
    return __atomic_add_fetch(val, -1, __ATOMIC_SEQ_CST);
}

static inline int32 cm_atomic32_add(atomic32_t *val, int32 count)
{
    return __atomic_add_fetch(val, count, __ATOMIC_SEQ_CST);
}

static inline int32 cm_atomic32_get(atomic32_t *val)
{
    return __atomic_load_n(val, __ATOMIC_SEQ_CST);
}

static inline int64 cm_atomic_add(atomic_t *val, int64 count)
{
    return __atomic_add_fetch(val, count, __ATOMIC_SEQ_CST);
}

static inline bool32 cm_atomic_cas(atomic_t *val, int64 oldval, int64 newval)
{
    return __atomic_compare_exchange(val, &oldval, &newval, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}

static inline bool32 cm_atomic32_cas(atomic32_t *val, int32 oldval, int32 newval)
{
    return __atomic_compare_exchange(val, &oldval, &newval, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}

#else
static inline int64 cm_atomic_get(atomic_t *val)
{
    return *val;
}

static inline int64 cm_atomic_set(atomic_t *val, int64 value)
{
    return *val = value;
}

static inline int64 cm_atomic_inc(atomic_t *val)
{
    return __sync_add_and_fetch(val, 1);
}

static inline int64 cm_atomic_dec(atomic_t *val)
{
    return __sync_add_and_fetch(val, -1);
}

static inline int32 cm_atomic32_inc(atomic32_t *val)
{
    return __sync_add_and_fetch(val, 1);
}

static inline int32 cm_atomic32_dec(atomic32_t *val)
{
    return __sync_add_and_fetch(val, -1);
}

static inline int32 cm_atomic32_add(atomic32_t *val, int32 count)
{
    return __sync_add_and_fetch(val, count);
}

static inline int32 cm_atomic32_get(atomic32_t *val)
{
    return __atomic_load_n(val, __ATOMIC_SEQ_CST);
}

static inline int64 cm_atomic_add(atomic_t *val, int64 count)
{
    return __sync_add_and_fetch(val, count);
}

static inline bool32 cm_atomic_cas(atomic_t *val, int64 oldval, int64 newval)
{
    return __sync_bool_compare_and_swap(val, oldval, newval);
}

static inline bool32 cm_atomic32_cas(atomic32_t *val, int32 oldval, int32 newval)
{
    return __sync_bool_compare_and_swap(val, oldval, newval);
}

#endif

#endif

#ifdef __cplusplus
}
#endif

#endif
