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
 * cm_dbs_map.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_dbs_map.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_dbs_module.h"
#include "cm_dbs_map.h"
#include "cm_hash.h"
#include "cm_list.h"
#include "cm_log.h"
#include "cm_malloc.h"
#include "securec.h"
#include "cm_latch.h"
#include "cm_spinlock.h"

#define CM_DBS_MAP_HASH_TABLE_SIZE 1024

typedef struct {
    cm_list_head node;
    int32 handle;
    char obj_name[CSS_MAX_NAME_LEN + 1];
    cm_dbs_map_item_s item;
} cm_dbs_map_value_s;

typedef struct {
    latch_t latch;
    cm_list_head hs_list;
} cm_dbs_map_hs_list;

static struct {
    spinlock_t hdl_seed_lock; // 仅用于分配handle时加锁
    int32 hdl_seed;
    cm_dbs_map_hs_list hs_cache[CM_DBS_MAP_HASH_TABLE_SIZE];
} g_cm_dbs_cache_mgr = { 0 };

typedef enum en_cm_dbs_latch_type {
    LATCH_TYPE_S,
    LATCH_TYPE_X,
} cm_dbs_latch_type_e;

void cm_dbs_map_latch(cm_dbs_latch_type_e latch_type, uint32 index)
{
    if (latch_type == LATCH_TYPE_S) {
        cm_latch_s(&g_cm_dbs_cache_mgr.hs_cache[index].latch, 0, CT_FALSE, NULL);
    } else {
        cm_latch_x(&g_cm_dbs_cache_mgr.hs_cache[index].latch, 0, NULL);
    }
}

void cm_dbs_map_unlatch(uint32 index)
{
    cm_unlatch(&g_cm_dbs_cache_mgr.hs_cache[index].latch, NULL);
}

void cm_dbs_map_init(void)
{
    g_cm_dbs_cache_mgr.hdl_seed = CM_DBS_INVALID_HANDLE;
    for (uint32 idx = 0; idx < CM_DBS_MAP_HASH_TABLE_SIZE; idx++) {
        cm_list_init(&g_cm_dbs_cache_mgr.hs_cache[idx].hs_list);
    }
}

void cm_dbs_map_deinit(void)
{
    cm_list_head *list = NULL;
    cm_list_head *node = NULL;
    cm_list_head *tmp = NULL;
    cm_dbs_map_value_s *entry = NULL;
    for (uint32 idx = 0; idx < CM_DBS_MAP_HASH_TABLE_SIZE; idx++) {
        cm_dbs_map_latch(LATCH_MODE_X, idx);
        list = &(g_cm_dbs_cache_mgr.hs_cache[idx].hs_list);
        cm_list_for_each_safe(node, tmp, list) {
            cm_list_remove(node);
            entry = cm_list_entry(node, cm_dbs_map_value_s, node);
            cm_free(entry);
        }
        cm_dbs_map_unlatch(idx);
    }
    g_cm_dbs_cache_mgr.hdl_seed = CM_DBS_INVALID_HANDLE;
}

static int32 cm_dbs_cache_gen_handle(void)
{
    if (g_cm_dbs_cache_mgr.hdl_seed == INT32_MAX) {
        g_cm_dbs_cache_mgr.hdl_seed = 0;
    } else {
        g_cm_dbs_cache_mgr.hdl_seed++;
    }
    return g_cm_dbs_cache_mgr.hdl_seed;
}

static uint32 cm_dbs_cache_calc_index_by_handle(int32 handle)
{
    return cm_hash_uint32((uint32)handle, CM_DBS_MAP_HASH_TABLE_SIZE);
}

status_t cm_dbs_map_set(const char *name, cm_dbs_map_item_s *item, int32 *handle)
{
    cm_dbs_map_value_s *value = (cm_dbs_map_value_s *)cm_malloc(sizeof(cm_dbs_map_value_s));
    if (value == NULL) {
        CT_LOG_RUN_ERR("Out of memory(%lu).", sizeof(cm_dbs_map_value_s));
        return CT_ERROR;
    }
    errno_t err = strcpy_s(value->obj_name, sizeof(value->obj_name), name);
    if (err != EOK) {
        cm_free(value);
        CT_LOG_RUN_ERR("Failed(%d) to copy the object name(%s).", err, name);
        return CT_ERROR;
    }
    err = memcpy_s(&value->item, sizeof(value->item), item, sizeof(cm_dbs_map_item_s));
    if (err != EOK) {
        cm_free(value);
        CT_LOG_RUN_ERR("Failed(%d) to copy the object item.", err);
        return CT_ERROR;
    }
    cm_list_init(&(value->node));
    cm_spin_lock(&g_cm_dbs_cache_mgr.hdl_seed_lock, NULL);
    value->handle = cm_dbs_cache_gen_handle();
    cm_spin_unlock(&g_cm_dbs_cache_mgr.hdl_seed_lock);

    uint32 index = cm_dbs_cache_calc_index_by_handle(value->handle);
    cm_dbs_map_latch(LATCH_TYPE_X, index);
    cm_list_add(&(value->node), &(g_cm_dbs_cache_mgr.hs_cache[index].hs_list));
    *handle = value->handle;
    cm_dbs_map_unlatch(index);
    return CT_SUCCESS;
}

static cm_dbs_map_value_s *cm_dbs_cache_get_by_index(uint32 index, int32 handle)
{
    cm_list_head *list = &(g_cm_dbs_cache_mgr.hs_cache[index].hs_list);
    cm_list_head *node = NULL;
    cm_dbs_map_value_s *entry = NULL;
    cm_list_for_each(node, list) {
        entry = cm_list_entry(node, cm_dbs_map_value_s, node);
        if (entry->handle == handle) {
            return entry;
        }
    }
    return NULL;
}

status_t cm_dbs_map_get(int32 handle, cm_dbs_map_item_s *item)
{
    uint32 index = cm_dbs_cache_calc_index_by_handle(handle);
    cm_dbs_map_latch(LATCH_TYPE_S, index);
    cm_dbs_map_value_s *value = cm_dbs_cache_get_by_index(index, handle);
    if (value == NULL) {
        cm_dbs_map_unlatch(index);
        CT_LOG_RUN_ERR("The cache at handle(%d) is invalid.", handle);
        return CT_ERROR;
    }
    errno_t err = memcpy_s(item, sizeof(cm_dbs_map_item_s), &value->item, sizeof(value->item));
    cm_dbs_map_unlatch(index);
    if (err != EOK) {
        CT_LOG_RUN_ERR("Failed(%d) to copy the object item.", err);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void cm_dbs_map_remove(int32 handle)
{
    uint32 index = cm_dbs_cache_calc_index_by_handle(handle);
    cm_dbs_map_latch(LATCH_TYPE_X, index);
    cm_dbs_map_value_s *value = cm_dbs_cache_get_by_index(index, handle);
    if (value == NULL) {
        cm_dbs_map_unlatch(index);
        CT_LOG_RUN_WAR("The cache at handle(%d) is invalid.", handle);
        return;
    }
    cm_list_remove(&(value->node));
    cm_free(value);
    cm_dbs_map_unlatch(index);
}

bool32 cm_dbs_map_exist(const char *name)
{
    cm_list_head *list = NULL;
    cm_list_head *node = NULL;
    cm_dbs_map_value_s *entry = NULL;
    for (uint32 idx = 0; idx < CM_DBS_MAP_HASH_TABLE_SIZE; idx++) {
        cm_dbs_map_latch(LATCH_TYPE_S, idx);
        list = &(g_cm_dbs_cache_mgr.hs_cache[idx].hs_list);
        cm_list_for_each(node, list)
        {
            entry = cm_list_entry(node, cm_dbs_map_value_s, node);
            if (strcmp(name, entry->obj_name) == 0) {
                cm_dbs_map_unlatch(idx);
                return CT_TRUE;
            }
        }
        cm_dbs_map_unlatch(idx);
    }
    return CT_FALSE;
}

void cm_dbs_map_update(int32 handle, cm_dbs_map_item_s *item)
{
    uint32 index = cm_dbs_cache_calc_index_by_handle(handle);
    cm_dbs_map_latch(LATCH_TYPE_X, index);
    cm_dbs_map_value_s *value = cm_dbs_cache_get_by_index(index, handle);
    if (value == NULL) {
        cm_dbs_map_unlatch(index);
        CT_LOG_RUN_WAR("The cache at handle(%d) is invalid.", handle);
        return;
    }
    errno_t err = memcpy_s(&value->item, sizeof(value->item), item, sizeof(cm_dbs_map_item_s));
    cm_dbs_map_unlatch(index);
    if (err != EOK) {
        CT_LOG_RUN_WAR("Failed(%d) to update cache at handle(%d).", err, handle);
        return;
    }
}

void cm_dbs_map_get_name(int32 handle, char *name, int32 size)
{
    uint32 index = cm_dbs_cache_calc_index_by_handle(handle);
    cm_dbs_map_latch(LATCH_TYPE_S, index);
    cm_dbs_map_value_s *value = cm_dbs_cache_get_by_index(index, handle);
    if (value == NULL) {
        cm_dbs_map_unlatch(index);
        CT_LOG_RUN_WAR("The cache at handle(%d) is invalid.", handle);
        return;
    }
    errno_t err = strcpy_s(name, size, value->obj_name);
    cm_dbs_map_unlatch(index);
    if (err != EOK) {
        CT_LOG_RUN_ERR("Failed(%d) to copy the object name(%s).", err, name);
        return;
    }
}