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
 * cm_list.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_list.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_list.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t cm_galist_ext_group(galist_t *list)
{
    pointer_t *groups = NULL;
    pointer_t *group = NULL;
    uint32 new_capacity;

    if (list->group_count >= list->group_capacity) {
        new_capacity = list->group_capacity + LIST_EXTENT_STEP;
        if (list->alloc_func(list->owner, new_capacity * sizeof(pointer_t), (void **)&groups) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (list->group_capacity != 0) {
            MEMS_RETURN_IFERR(memcpy_sp(groups, (size_t)(new_capacity * sizeof(pointer_t)), list->groups,
                                        (size_t)(list->group_capacity * sizeof(pointer_t))));
        }

        list->groups = groups;
        list->group_capacity = new_capacity;
    }

    if (list->alloc_func(list->owner, LIST_EXTENT_STEP * sizeof(pointer_t), (void **)&group) != CT_SUCCESS) {
        return CT_ERROR;
    }

    list->groups[list->group_count] = group;
    list->group_count++;
    list->latest_ext_cap = 0;
    list->latest_ext_cnt = 0;
    return CT_SUCCESS;
}

static status_t cm_galist_ext_list(galist_t *list)
{
    pointer_t *extents = NULL;
    pointer_t *group = NULL;
    pointer_t *extent = NULL;
    uint32 new_capacity;

    if (list->latest_ext_cnt >= list->latest_ext_cap) {
        new_capacity = list->latest_ext_cap + LIST_EXTENT_STEP;
        if (list->alloc_func(list->owner, new_capacity * sizeof(pointer_t), (void **)&extents) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (list->latest_ext_cap != 0) {
            MEMS_RETURN_IFERR(memcpy_sp(extents, (size_t)(new_capacity * sizeof(pointer_t)),
                                        (pointer_t *)list->groups[list->group_count - 1],
                                        (size_t)(list->latest_ext_cap * sizeof(pointer_t))));
        }

        list->groups[list->group_count - 1] = extents;
        list->latest_ext_cap = new_capacity;
    }

    if (list->alloc_func(list->owner, LIST_EXTENT_SIZE * sizeof(pointer_t), (void **)&extent) != CT_SUCCESS) {
        return CT_ERROR;
    }

    group = (pointer_t *)list->groups[list->group_count - 1];
    group[list->latest_ext_cnt] = extent;
    list->latest_ext_cnt++;
    if (list->group_count == 1 && list->latest_ext_cnt == 1) {
        list->first_extent = extent;
    }
    return CT_SUCCESS;
}

status_t cm_galist_insert(galist_t *list, pointer_t item)
{
    uint32 group_id, ext_id, item_id;
    pointer_t *group = NULL;
    pointer_t *extent = NULL;

    if (list->count > 0 && list->count < LIST_EXTENT_SIZE) {
        list->first_extent[list->count] = item;
        ++list->count;
        return CT_SUCCESS;
    }

    if (list->count >= MAX_LIST_COUNT) {
        CT_THROW_ERROR(ERR_OUT_OF_INDEX, "ga-list", MAX_LIST_COUNT);
        return CT_ERROR;
    }

    group_id = list->count / LIST_GROUP_ITEMS;
    ext_id = (list->count - group_id * LIST_GROUP_ITEMS) / LIST_EXTENT_SIZE;
    item_id = (list->count - group_id * LIST_GROUP_ITEMS) % LIST_EXTENT_SIZE;

    if (group_id >= list->group_count) { /* extend the group */
        if (cm_galist_ext_group(list) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (ext_id >= list->latest_ext_cnt) { /* extend the extent */
        if (cm_galist_ext_list(list) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    group = (pointer_t *)list->groups[group_id];
    extent = (pointer_t *)group[ext_id];
    extent[item_id] = item;

    list->count++;
    return CT_SUCCESS;
}

status_t cm_galist_new(galist_t *list, uint32 item_size, pointer_t *new_item)
{
    pointer_t item = NULL;

    if (list->alloc_func(list->owner, item_size, &item) != CT_SUCCESS) {
        return CT_ERROR;
    }

    *new_item = item;
    return cm_galist_insert(list, item);
}

#ifdef __cplusplus
}
#endif
