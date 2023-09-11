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
 * cm_queue.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_queue.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_QUEUE_H__
#define __CM_QUEUE_H__

#include "cm_defs.h"

#define OBJECT_OF(type, node) (type *)((char *)(node)-OFFSET_OF(type, prev))
#define QUEUE_NODE_OF(obj)    ((biqueue_node_t *)&(obj)->prev)

typedef struct st_biqueue_node {
    struct st_biqueue_node *prev;
    struct st_biqueue_node *next;
} biqueue_node_t;

typedef struct st_biqueue {
    biqueue_node_t dumb;
} biqueue_t;

static inline void biqueue_init(biqueue_t *que)
{
    que->dumb.next = que->dumb.prev = &que->dumb;
}

static inline void biqueue_add_tail(biqueue_t *que, biqueue_node_t *node)
{
    node->prev = que->dumb.prev;
    que->dumb.prev->next = node;
    node->next = &que->dumb;
    que->dumb.prev = node;
}

static inline void biqueue_add_head(biqueue_t *que, biqueue_node_t *node)
{
    node->next = que->dumb.next;
    que->dumb.next->prev = node;
    node->prev = &que->dumb;
    que->dumb.next = node;
}

static inline biqueue_node_t *biqueue_del_head(biqueue_t *que)
{
    biqueue_node_t *ret = NULL;
    if (que->dumb.next == &que->dumb) {
        return NULL;
    }
    ret = que->dumb.next;
    que->dumb.next = ret->next;
    ret->next->prev = &que->dumb;
    ret->prev = ret->next = NULL;
    return ret;
}

static inline void biqueue_del_node(biqueue_node_t *node)
{
    node->next->prev = node->prev;
    node->prev->next = node->next;
    node->prev = node->next = NULL;
}

static inline uint32 biqueue_empty(biqueue_t *que)
{
    return que->dumb.next == &que->dumb;
}

static inline biqueue_node_t *biqueue_first(biqueue_t *que)
{
    return que->dumb.next;
}

static inline biqueue_node_t *biqueue_last(biqueue_t *que)
{
    return que->dumb.prev;
}

static inline biqueue_node_t *biqueue_end(biqueue_t *que)
{
    return &que->dumb;
}

static inline void biqueue_move(biqueue_t *dst, biqueue_t *src)
{
    if (!biqueue_empty(src)) {
        src->dumb.prev->next = &dst->dumb;
        src->dumb.next->prev = &dst->dumb;
        dst->dumb.next = src->dumb.next;
        dst->dumb.prev = src->dumb.prev;
        biqueue_init(src);
        return;
    }
    biqueue_init(dst);
    return;
}

#endif