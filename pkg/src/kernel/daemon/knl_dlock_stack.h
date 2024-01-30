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
 * knl_dlock_stack.h
 *
 *
 * IDENTIFICATION
 * src/kernel/daemon/knl_dlock_stack.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_DLOCK_STACK_H__
#define __KNL_DLOCK_STACK_H__

#include "cm_defs.h"

#define NUM CT_MAX_SESSIONS
typedef struct st_knl_dlock_stack {
    void *values[NUM];
    int32 top;
} knl_dlock_stack_t;

static inline bool32 dlock_is_empty(knl_dlock_stack_t *s)
{
    return s->top == 0;
}

static inline bool32 dlock_is_full(knl_dlock_stack_t *s)
{
    return s->top >= (int32)NUM;
}

static inline void dlock_push(knl_dlock_stack_t *s, void *ptr)
{
    s->values[s->top++] = ptr;
}

static inline bool32 dlock_push_with_check(knl_dlock_stack_t *s, void *ptr)
{
    if (dlock_is_full(s)) {
        CT_THROW_ERROR(ERR_STACK_OVERSPACE);
        return CT_FALSE;
    }
    dlock_push(s, ptr);
    return CT_TRUE;
}

static inline void *dlock_top(knl_dlock_stack_t *s)
{
    return s->values[s->top - 1];
}

static inline void dlock_pop(knl_dlock_stack_t *s)
{
    s->top--;
}

typedef struct st_dtc_dlock_stack {
    void *values;
    int32 top;
    int32 count;
    int32 size;
} dtc_dlock_stack_t;

static inline bool32 dtc_dlock_is_empty(dtc_dlock_stack_t *s)
{
    return s->top == 0;
}

static inline bool32 dtc_dlock_is_full(dtc_dlock_stack_t *s)
{
    return s->top >= (int32)s->count;
}

static inline status_t dtc_dlock_push(dtc_dlock_stack_t *s, void *ptr, uint32 size)
{
    errno_t ret = memcpy_s(((char*)s->values + s->top * s->size), s->size, (char*)ptr, size);
    MEMS_RETURN_IFERR(ret);
    s->top++;
    return CT_SUCCESS;
}

static inline bool32 dtc_dlock_push_with_check(dtc_dlock_stack_t *s, void *ptr, uint32 size)
{
    if (dtc_dlock_is_full(s)) {
        CT_THROW_ERROR(ERR_STACK_OVERSPACE);
        return CT_FALSE;
    }
    dtc_dlock_push(s, ptr, size);
    return CT_TRUE;
}

static inline void *dtc_dlock_top(dtc_dlock_stack_t *s)
{
    return (char*)s->values + (s->top - 1) * s->size;
}

static inline void dtc_dlock_pop(dtc_dlock_stack_t *s)
{
    s->top--;
}

static inline void dtc_dlock_reset(dtc_dlock_stack_t *s)
{
    s->top = 0;
}


#endif

