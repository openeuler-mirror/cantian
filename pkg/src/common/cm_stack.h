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
 * cm_stack.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_stack.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_STACK_H__
#define __CM_STACK_H__
#include "cm_base.h"
#include "cm_defs.h"
#include "cm_debug.h"
#include "cm_error.h"
#include "cm_log.h"
#include <string.h>

#ifndef TEST_MEM

// reserved size to save the last push_offset
// 8 bytes align
#define GS_PUSH_RESERVE_SIZE 8
#define GS_PUSH_OFFSET_POS 4
#define STACK_MAGIC_NUM (uint32)0x12345678

typedef struct st_stack {
    uint8 *buf;
    uint32 size;
    uint32 push_offset; /* top postion of the stack, begin from max_stack_size to 0  */
    uint32 heap_offset; /* bottom postion of the stack, begin from 0 to max_stack_size */
} cm_stack_t;

static inline void cm_stack_reset(cm_stack_t *stack)
{
    stack->push_offset = stack->size;
    stack->heap_offset = 0;
}

static inline void *cm_push(cm_stack_t *stack, uint32 size)
{
    uint32 last_offset;
    uint32 actual_size = CM_ALIGN8(size) + GS_PUSH_RESERVE_SIZE;
    uint8 *ptr = stack->buf + stack->push_offset - actual_size + GS_PUSH_RESERVE_SIZE;

    if (stack->push_offset < (uint64)stack->heap_offset + actual_size) {
        return NULL;
    }

    last_offset = stack->push_offset;
    stack->push_offset -= actual_size;
    *(uint32 *)(stack->buf + stack->push_offset + GS_PUSH_OFFSET_POS) = last_offset;

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    /* set magic number */
    *(uint32 *)(stack->buf + stack->push_offset) = STACK_MAGIC_NUM;
#endif

    return ptr;
}

static inline void cm_pop(cm_stack_t *stack)
{
    if (stack->push_offset == stack->size) {
        return;
    }

    stack->push_offset = *(uint32 *)(stack->buf + stack->push_offset + GS_PUSH_OFFSET_POS);

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    /* check magic number */
    if (stack->push_offset != stack->size) {
        CM_ASSERT(*(uint32 *)(stack->buf + stack->push_offset) == STACK_MAGIC_NUM);
    }
#endif
}

static inline void cm_pop_to(cm_stack_t *stack, uint32 push_offset)
{
    if (stack->push_offset >= push_offset) {
        return;
    }

    stack->push_offset = push_offset;

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    /* check magic number */
    if (stack->push_offset != stack->size) {
        CM_ASSERT(*(uint32 *)(stack->buf + stack->push_offset) == STACK_MAGIC_NUM);
    }
#endif
}

#define STACK_ALLOC_ADDR(stack) ((stack)->buf + (stack)->heap_offset)

static inline status_t cm_stack_alloc(void *owner, uint32 size, void **ptr)
{
    uint32 actual_size;
    cm_stack_t *stack;

    stack = (cm_stack_t *)owner;
    actual_size = CM_ALIGN8(size);
    if ((uint64)stack->heap_offset + actual_size + GS_MIN_KERNEL_RESERVE_SIZE >= stack->push_offset) {
        GS_THROW_ERROR(ERR_STACK_OVERFLOW);
        return GS_ERROR;
    }

    *ptr = STACK_ALLOC_ADDR(stack);
    stack->heap_offset += actual_size;
    return GS_SUCCESS;
}

static inline void *cm_stack_heap_head(cm_stack_t *stack)
{
    return STACK_ALLOC_ADDR(stack);
}

static inline void cm_stack_heap_reset(cm_stack_t *stack, void *to)
{
    stack->heap_offset = (uint32)((uint8 *)to - stack->buf);
}

static inline void cm_stack_init(cm_stack_t *stack, char *buf, uint32 buf_size)
{
    CM_ASSERT(stack != NULL);
    MEMS_RETVOID_IFERR(memset_sp(stack, sizeof(cm_stack_t), 0, sizeof(cm_stack_t)));

    stack->buf = (uint8 *)buf;
    stack->size = buf_size;
    cm_stack_reset(stack);
}

#define CM_SAVE_STACK(stack)                       \
    uint32 __heap_offset__ = (stack)->heap_offset; \
    uint32 __push_offset__ = (stack)->push_offset;

#define CM_RESTORE_STACK(stack)                 \
    do {                                        \
        cm_pop_to(stack, __push_offset__);      \
        (stack)->heap_offset = __heap_offset__; \
    } while (0)

static inline void cm_keep_stack_variant(cm_stack_t *stack, char *buf)
{
    if (buf == NULL) {
        return;
    }
    if (buf < (char *)(stack->buf + stack->heap_offset) ||
        buf >= (char *)stack->buf + stack->push_offset + GS_PUSH_RESERVE_SIZE) {
        return;
    }

    stack->push_offset = (uint32)(buf - (char *)stack->buf - GS_PUSH_RESERVE_SIZE);

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    /* check magic number when keep variant, because the buff must be pushed */
    if (stack->push_offset != stack->size) {
        CM_ASSERT(*(uint32 *)(stack->buf + stack->push_offset) == STACK_MAGIC_NUM);
    }
#endif
}

#else

#define GS_MAX_TEST_HEAP_DEPTH  (uint32)256
#define GS_MAX_TEST_STACK_DEPTH (uint32)1024

typedef struct st_stack {
    uint8 *buf;
    uint32 push_offset;
    uint32 heap_offset;
    void *heap_addr[GS_MAX_TEST_HEAP_DEPTH];
    uint32 push_depth;
    void *stack_addr[GS_MAX_TEST_STACK_DEPTH];
} cm_stack_t;

static inline void cm_stack_reset(cm_stack_t *stack)
{
    uint32 i;
    for (i = 0; i < GS_MAX_TEST_STACK_DEPTH && stack->stack_addr[i] != NULL; ++i) {
        CM_FREE_PTR(stack->stack_addr[i]);
    }
    stack->push_depth = 0;

    for (i = 0; i < stack->heap_offset; ++i) {
        CM_FREE_PTR(stack->heap_addr[i]);
    }
    stack->heap_offset = 0;
}

static inline void *cm_push(cm_stack_t *stack, uint32 size)
{
    errno_t rc_memzero;

    if (stack->push_depth + 1 > GS_MAX_TEST_STACK_DEPTH) {
        return NULL;
    }
    if (size == 0) {
        return NULL;
    }
    void *ptr = malloc(size);
    if (ptr == NULL) {
        return NULL;
    }

    if (stack->stack_addr[stack->push_depth] != NULL) {
        CM_FREE_PTR(stack->stack_addr[stack->push_depth]);
    }

    stack->stack_addr[stack->push_depth] = ptr;
    stack->push_depth++;

    rc_memzero = memset_sp(ptr, size, 0, size);
    if (rc_memzero != EOK) {
        CM_FREE_PTR(ptr);
        GS_THROW_ERROR(ERR_SYSTEM_CALL, rc_memzero);
        return NULL;
    }
    return ptr;
}

static inline void cm_pop(cm_stack_t *stack)
{
    if (stack->push_depth == 0) {
        return;
    }

    stack->push_depth--;
}

static inline void cm_pop_to(cm_stack_t *stack, uint32 to, uint32 push_offset)
{
    if (stack->push_depth <= to) {
        return;
    }

    stack->push_depth = to;
}

#define STACK_ALLOC_ADDR(stack) ((stack)->heap_offset == 0 ? NULL : (stack)->heap_addr[(stack)->heap_offset - 1])

static inline status_t cm_stack_alloc(void *owner, uint32 size, void **ptr)
{
    cm_stack_t *stack;
    errno_t errcode;

    stack = (cm_stack_t *)owner;

    if (stack->heap_offset + 1 > GS_MAX_TEST_HEAP_DEPTH) {
        *ptr = NULL;
        return GS_ERROR;
    }
    if (size == 0) {
        *ptr = NULL;
        return GS_ERROR;
    }
    *ptr = malloc(size);
    if (*ptr == NULL) {
        return GS_ERROR;
    }

    stack->heap_addr[stack->heap_offset] = *ptr;
    stack->heap_offset++;

    errcode = memset_sp(*ptr, size, 0, size);
    if (errcode != EOK) {
        CM_FREE_PTR(*ptr);
        GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static inline void *cm_stack_heap_head(cm_stack_t *stack)
{
    return STACK_ALLOC_ADDR(stack);
}

static inline void cm_stack_heap_reset(cm_stack_t *stack, void *to)
{
    while (stack->heap_offset > 0 && stack->heap_addr[stack->heap_offset - 1] != to) {
        CM_FREE_PTR(stack->heap_addr[stack->heap_offset - 1]);
        stack->heap_addr[stack->heap_offset - 1] = NULL;
        stack->heap_offset--;
    }
}

static inline void cm_stack_init(cm_stack_t *stack, char *buf, uint32 buf_size)
{
    MEMS_RETVOID_IFERR(memset_sp(stack, sizeof(cm_stack_t), 0, sizeof(cm_stack_t)));
    stack->buf = (uint8 *)buf;
}

#define CM_SAVE_STACK(stack)                       \
    uint32 __stack_depth__ = (stack)->push_depth;  \
    uint32 __heap_offset__ = (stack)->heap_offset; \
    uint32 __push_offset__ = (stack)->push_offset;

#define CM_RESTORE_STACK(stack)                             \
    do {                                                    \
        cm_pop_to(stack, __stack_depth__, __push_offset__); \
        (stack)->heap_offset = __heap_offset__;             \
    } while (0)

static inline void cm_keep_stack_variant(cm_stack_t *stack, char *buf)
{
    if (buf == NULL) {
        return;
    }

    for (i = 0; stack->stack_addr[i] != NULL && i < GS_MAX_TEST_STACK_DEPTH; i++) {
        if (buf == stack->stack_addr[i]) {
            if (stack->push_depth < i + 1) {
                stack->push_depth = i + 1;
            }
        }
    }
}

#endif  // TEST_MEM

#define CM_PUSH_UPDATE_INFO(session, update_info)                                                                     \
    do {                                                                                                              \
        (update_info).columns = (uint16 *)cm_push((session)->stack,                                                   \
            (session)->kernel->attr.max_column_count * sizeof(uint16));                                               \
        (update_info).offsets = (uint16 *)cm_push((session)->stack,                                                   \
            (session)->kernel->attr.max_column_count * sizeof(uint16));                                               \
        (update_info).lens = (uint16 *)cm_push((session)->stack,                                                      \
            (session)->kernel->attr.max_column_count * sizeof(uint16));                                               \
        CM_ASSERT((update_info).columns != NULL);                                                                     \
        CM_ASSERT((update_info).offsets != NULL);                                                                     \
        CM_ASSERT((update_info).lens != NULL);                                                                        \
    } while (0)

#endif

