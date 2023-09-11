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
 * cm_list.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_list.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_LIST_H__
#define __CM_LIST_H__
#include "cm_defs.h"
#include "cm_debug.h"
#include "cm_log.h"
#include "cm_error.h"
#ifdef WIN32
#else
#include <string.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define LIST_EXTENT_SIZE 32

/* galist: groups(16k/8, step=4) * extents(16k/8, step=4) * items(32) limits to 2048*2048 */
#define LIST_EXTENT_STEP        4
#define LIST_EXTENT_CAPACITY    (GS_SHARED_PAGE_SIZE / sizeof(pointer_t))   // capacity < max(uint16)
#define LIST_GROUP_ITEMS        (LIST_EXTENT_CAPACITY * LIST_EXTENT_SIZE)
#define MAX_LIST_COUNT          (2048 * 2048)

typedef status_t (*ga_alloc_func_t)(void *owner, uint32 size, void **ptr);

typedef struct st_galist {
    void *owner;
    ga_alloc_func_t alloc_func;
    pointer_t *groups;
    pointer_t *first_extent;
    uint32 capacity;
    uint32 count;
    uint16 group_capacity;
    uint16 group_count;
    uint16 latest_ext_cap;  // last extent capacity
    uint16 latest_ext_cnt;  // last extent count, [0, LIST_EXTENT_CAPACITY-1]
} galist_t;

status_t cm_galist_insert(galist_t *list, pointer_t item);
status_t cm_galist_new(galist_t *list, uint32 item_size, pointer_t *new_item);

static inline void cm_galist_init(galist_t *list, void *owner, ga_alloc_func_t alloc_func)
{
    CM_ASSERT(list != NULL);
    list->groups = NULL;
    list->first_extent = NULL;
    list->capacity = 0;
    list->count = 0;
    list->group_capacity = 0;
    list->group_count = 0;
    list->latest_ext_cnt = 0;
    list->owner = owner;
    list->alloc_func = alloc_func;
}

static inline pointer_t* cm_galist_get_extent(galist_t *list, uint32 index)
{
    uint32 group_id = index / LIST_GROUP_ITEMS;
    uint32 ext_id = (index - group_id * LIST_GROUP_ITEMS) / LIST_EXTENT_SIZE;
    return ((pointer_t *)(((pointer_t *)list->groups[group_id])[ext_id]));
}

static inline pointer_t cm_galist_get(galist_t *list, uint32 index)
{
    /* get the item in the top 32 or 64 */
    if (index < LIST_EXTENT_SIZE) {
        return list->first_extent[index];
    } else if (index < LIST_EXTENT_SIZE * 2) {
        return ((pointer_t *)(((pointer_t *)list->groups[0])[1]))[index - LIST_EXTENT_SIZE];
    }

    pointer_t *extent = cm_galist_get_extent(list, index);
    return extent[index % LIST_EXTENT_SIZE];
}

static inline void cm_galist_set(galist_t *list, uint32 index, pointer_t item)
{
    /* set the item in the top 32 or 64 */
    if (index < LIST_EXTENT_SIZE) {
        list->first_extent[index] = item;
        return;
    } else if (index < LIST_EXTENT_SIZE * 2) {
        ((pointer_t *)(((pointer_t *)list->groups[0])[1]))[index - LIST_EXTENT_SIZE] = item;
        return;
    }

    pointer_t *extent = cm_galist_get_extent(list, index);
    extent[index % LIST_EXTENT_SIZE] = item;
}

static inline void cm_galist_reset(galist_t *list)
{
    list->count = 0;
}

static inline void cm_galist_delete(galist_t *list, uint32 index)
{
    if (list->count > 0) {
        for (uint32 i = index; i < list->count - 1; i++) {
            pointer_t temp_item = cm_galist_get(list, i + 1);
            cm_galist_set(list, i, temp_item);
        }

        list->count--;
    }
}
static inline void cm_galist_clean(galist_t *list)
{
    if (list != NULL && list->count > 0) {
        for (uint32 i = list->count; i > 0; i--) {
            cm_galist_delete(list, i - 1);
        }
    }
}
static inline status_t cm_galist_copy(galist_t *dst, galist_t *src)
{
    for (uint32 i = 0; i < src->count; i++) {
        if (cm_galist_insert(dst, cm_galist_get(src, i)) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

static inline status_t cm_galist_copy_append(galist_t *dst, size_t size, pointer_t p_src)
{
    CM_ASSERT(size > 0 && p_src != NULL);
    pointer_t ptr = NULL;
    if (cm_galist_new(dst, (uint32)size, &ptr) != GS_SUCCESS) {
        return GS_ERROR;
    }
    MEMS_RETURN_IFERR(memcpy_sp(ptr, size, p_src, size));
    return GS_SUCCESS;
}

typedef status_t (*galist_cmp_func_t)(const void *item1, const void *item2, int32 *result);

static inline status_t cm_galist_sort(galist_t *list, galist_cmp_func_t cmp_func)
{
    uint32 i, j;
    void *item1 = NULL;
    void *item2 = NULL;
    int32 result;

    if (list->count <= 1) {
        return GS_SUCCESS;
    }

    for (j = 0; j < list->count - 1; j++) {
        for (i = 0; i < list->count - 1 - j; i++) {
            item1 = cm_galist_get(list, i);
            item2 = cm_galist_get(list, i + 1);
            if (cmp_func(item1, item2, &result) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (result > 0) {
                cm_galist_set(list, i, item2);
                cm_galist_set(list, i + 1, item1);
            }
        }
    }

    return GS_SUCCESS;
}

/* pointer list */
typedef struct st_ptlist {
    pointer_t *items;
    uint32 capacity;
    uint32 count;
} ptlist_t;

static inline void cm_ptlist_init(ptlist_t *list)
{
    list->items = NULL;
    list->capacity = 0;
    list->count = 0;
}

static inline void cm_ptlist_reset(ptlist_t *list)
{
    list->count = 0;
}

static inline void cm_destroy_ptlist(ptlist_t *list)
{
    if (list->items != NULL) {
        CM_FREE_PTR(list->items);
    }

    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static inline pointer_t cm_ptlist_get(ptlist_t *list, uint32 index)
{
    return list->items[index];
}

static inline void cm_ptlist_set(ptlist_t *list, uint32 index, pointer_t item)
{
    list->items[index] = item;
}

static inline status_t cm_ptlist_add(ptlist_t *list, pointer_t item)
{
    pointer_t *new_items = NULL;
    uint32 buf_size;
    errno_t errcode;
    if (list->count >= list->capacity) { /* extend the list */
        buf_size = (list->capacity + LIST_EXTENT_SIZE) * sizeof(pointer_t);
        if (buf_size == 0 || (buf_size / sizeof(pointer_t) != list->capacity + LIST_EXTENT_SIZE)) {
            GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)buf_size, "extending list");
            return GS_ERROR;
        }
        new_items = (pointer_t *)malloc(buf_size);
        if (new_items == NULL) {
            GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)buf_size, "extending list");
            return GS_ERROR;
        }
        errcode = memset_sp(new_items, (size_t)buf_size, 0, (size_t)buf_size);
        if (errcode != EOK) {
            CM_FREE_PTR(new_items);
            GS_THROW_ERROR(ERR_RESET_MEMORY, "extending list");
            return GS_ERROR;
        }
        if (list->items != NULL) {
            if (list->capacity != 0) {
                errcode = memcpy_sp(new_items, (size_t)buf_size, list->items,
                    (size_t)(list->capacity * sizeof(pointer_t)));
                if (errcode != EOK) {
                    CM_FREE_PTR(new_items);
                    GS_THROW_ERROR(ERR_RESET_MEMORY, "extending list");
                    return GS_ERROR;
                }
            }

            CM_FREE_PTR(list->items);
        }

        list->items = new_items;
        list->capacity += LIST_EXTENT_SIZE;
    }

    list->items[list->count] = item;
    list->count++;
    return GS_SUCCESS;
}

/* normal list: LIST_EXTENT_SIZE * MAX_LIST_EXTENTS > 100w */
#define MAX_LIST_EXTENTS 32768

typedef struct st_list {
    uint32 item_size;
    uint32 extent_step;
    uint32 max_extents;
    uint32 extent_count;
    pointer_t *extents;
    uint32 capacity;
    uint32 count;
} list_t;

static inline void cm_create_list2(list_t *list, uint32 extent_step, uint32 max_extents, uint32 item_size)
{
    list->extent_step = extent_step;
    list->max_extents = max_extents;
    list->item_size = item_size;
    list->extent_count = 0;
    list->capacity = 0;
    list->count = 0;
    list->extents = NULL;
}

static inline void cm_create_list(list_t *list, uint32 item_size)
{
    cm_create_list2(list, LIST_EXTENT_SIZE, MAX_LIST_EXTENTS, item_size);
}

static inline void cm_reset_list(list_t *list)
{
    uint32 i;

    if (list->extent_count == 0) {
        CM_FREE_PTR(list->extents);
        return;
    }

    for (i = 0; i < list->extent_count; i++) {
        CM_FREE_PTR(list->extents[i]);
    }

    list->extent_count = 0;
    list->count = 0;
    list->capacity = 0;
    CM_FREE_PTR(list->extents);
}

static inline void cm_destroy_list(list_t *list)
{
    cm_reset_list(list);
}

static inline pointer_t cm_list_get(list_t *list, uint32 index)
{
    char *item_buf = (char *)list->extents[index / list->extent_step];
    return item_buf + (index % list->extent_step) * list->item_size;
}

static inline pointer_t cm_list_get_extent(list_t *list, uint32 idx)
{
    return list->extents[idx];
}

static inline uint32 cm_list_get_extent_cnt(list_t *list)
{
    return list->extent_count;
}

static inline status_t cm_list_set(list_t *list, uint32 index, pointer_t item)
{
    char *ptr = (char *)cm_list_get(list, index);
    if ((item != NULL) && (list->item_size != 0)) {
        MEMS_RETURN_IFERR(memcpy_sp(ptr, (size_t)list->item_size, item, (size_t)list->item_size));
    }
    return GS_SUCCESS;
}

static inline status_t cm_list_new(list_t *list, pointer_t *item)
{
    uint32 buf_size;
    errno_t rc_memzero;

    if (list->extents == NULL) {
        buf_size = sizeof(pointer_t) * list->max_extents;
        if (buf_size == 0 || buf_size / sizeof(pointer_t) != list->max_extents) {
            GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)buf_size, "initializing list");
            return GS_ERROR;
        }
        list->extents = (pointer_t *)malloc(buf_size);
        if (list->extents == NULL) {
            GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)buf_size, "initializing list");
            return GS_ERROR;
        }
        rc_memzero = memset_sp(list->extents, (size_t)buf_size, 0, (size_t)buf_size);
        if (rc_memzero != EOK) {
            CM_FREE_PTR(list->extents);
            GS_THROW_ERROR(ERR_RESET_MEMORY, "initializing list");
            return GS_ERROR;
        }
    }

    if (list->count >= list->capacity) { /* extend the list */
        if (list->capacity == list->extent_step * list->max_extents) {
            GS_THROW_ERROR(ERR_ALLOC_MEMORY_REACH_LIMIT, list->extent_step * list->max_extents);
            return GS_ERROR;
        }

        buf_size = list->extent_step * list->item_size;
        /* extending count: list->capacity - LIST_EXTENT_SIZE + LIST_EXTENT_SIZE => list->capacity */
        if (buf_size == 0 || buf_size / list->item_size != list->extent_step) {
            GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)buf_size, "extending list");
            return GS_ERROR;
        }
        char *item_buf = (char *)malloc(buf_size);
        if (item_buf == NULL) {
            GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)buf_size, "extending list");
            return GS_ERROR;
        }

        rc_memzero = memset_sp(item_buf, (size_t)buf_size, 0, (size_t)buf_size);
        if (rc_memzero != EOK) {
            CM_FREE_PTR(item_buf);
            GS_THROW_ERROR(ERR_RESET_MEMORY, "extending list");
            return GS_ERROR;
        }

        list->extents[list->extent_count] = item_buf;
        list->extent_count++;
        list->capacity += list->extent_step;
    }

    if (item != NULL) {
        *item = cm_list_get(list, list->count);
    }

    list->count++;
    return GS_SUCCESS;
}

/* bidirectional list */
typedef struct st_list_head {
    struct st_list_head *next;
    struct st_list_head *prev;
} cm_list_head;

#define cm_list_init(head)                    \
    do {                                      \
        (head)->next = (head)->prev = (head); \
    } while (0)

/* add a node to a list after a special location */
#define cm_list_add(item, where)      \
    do {                              \
        (item)->next = (where)->next; \
        (item)->prev = (where);       \
        (where)->next = (item);       \
        (item)->next->prev = (item);  \
    } while (0)

/* add a node to a list before a special location */
#define cm_list_add_before(item, where) cm_list_add(item, (where)->prev)

/* remove a node from a list */
#define cm_list_remove(item)               \
    do {                                   \
        (item)->prev->next = (item)->next; \
        (item)->next->prev = (item)->prev; \
        (item)->next = NULL; \
        (item)->prev = NULL; \
    } while (0)

/* check if a list is empty */
#define cm_list_is_empty(head) ((head)->next == (head))

/* Travel through a list */
#define cm_list_for_each(item, head) \
    for ((item) = (head)->next; (item) != (head); (item) = (item)->next)

/* Travel through a list in a safe way. item can be removed safely */
#define cm_list_for_each_safe(item, temp, head)        \
    for ((item) = (head)->next, (temp) = (item)->next; \
         (item) != (head);                             \
         (item) = (temp), (temp) = (item)->next)

/* find the entry of a data struct */
#define cm_list_entry(item, type, member) \
    ((type *)((char *)(item) - (char *)(&((type *)0)->member)))

static inline void cm_list_free(cm_list_head *list)
{
    cm_list_head *item = NULL;
    cm_list_head *temp = NULL;
    cm_list_for_each_safe(item, temp, list) {
        cm_list_remove(item);
        CM_FREE_PTR(item);
    }
}

#ifdef __cplusplus
}
#endif

#endif

