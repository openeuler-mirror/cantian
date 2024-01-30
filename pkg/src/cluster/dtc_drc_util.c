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
 * dtc_drc_util.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_drc_util.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_cluster_module.h"
#include "dtc_drc.h"
#include "dtc_drc_util.h"

static inline void  drc_memset_more2g(void* dest, int c, size_t dest_size)
{
    status_t ret;
    size_t remain_size = dest_size;
    void* cur_addr = dest;

    while (CT_TRUE) {
        if (remain_size <= SECUREC_MEM_MAX_LEN) {
            ret = memset_s(cur_addr, remain_size, c, remain_size);
            knl_securec_check(ret);
            return;
        }
        ret = memset_s(cur_addr, SECUREC_MEM_MAX_LEN, c, SECUREC_MEM_MAX_LEN);
        knl_securec_check(ret);
        
        cur_addr = (uchar*)cur_addr + SECUREC_MEM_MAX_LEN;
        remain_size -= SECUREC_MEM_MAX_LEN;
    }
}

status_t drc_mpool_init(drc_mpool_t *pool, uint32 block_size, uint32 block_num)
{
    if (block_size < sizeof(pool_area_header_t)) {
        return CT_ERROR;
    }
    pool->lock = 0;
    pool->area_list = NULL;
    pool->free_list = NULL;
    pool->block_size = block_size;
    pool->block_num = 0;
    pool->inited = CT_TRUE;
    pool->block_used = 0;

    return drc_mpool_extend(pool, block_num);
}

status_t drc_mpool_extend(drc_mpool_t *pool, uint32 block_num)
{
    uint64  size;
    pool_area_header_t  *area;
    area_block_header_t *block;
    area_block_header_t *first;
    uint32 i;

    if (pool->inited != CT_TRUE) {
        return CT_ERROR;
    }

    if (0 == block_num) {
        return CT_ERROR;
    }

    size = block_num * pool->block_size + sizeof(pool_area_header_t);

    area = (pool_area_header_t*)malloc((size_t)size);
    if (NULL == area) {
        return CT_ERROR;
    }

    block = (area_block_header_t*)((uint8*)area + sizeof(pool_area_header_t));
    for (i = 0; i < (block_num - 1); i++) {
        block->next = (area_block_header_t*)((uint8*)block + pool->block_size);
        block = block->next;
    }
    block->next = NULL;

    cm_spin_lock(&pool->lock, NULL);
    area->next = pool->area_list;
    pool->area_list = area;

    first = (area_block_header_t*)((uint8*)area + sizeof(pool_area_header_t));
    block->next = pool->free_list;
    pool->free_list = first;

    pool->block_num += block_num;

    cm_spin_unlock(&pool->lock);

    return CT_SUCCESS;
}

void drc_mpool_destroy(drc_mpool_t *pool)
{
    pool_area_header_t *cur_area;

    if (pool->inited != CT_TRUE) {
        return;
    }

    cm_spin_lock(&pool->lock, NULL);

    while (pool->area_list != NULL) {
        cur_area = pool->area_list;
        pool->area_list = pool->area_list->next;
        free(cur_area);
    }

    pool->area_list = NULL;
    pool->free_list = NULL;
    pool->block_num = 0;
    pool->block_size = 0;
    pool->block_used = 0;
    pool->inited = CT_FALSE;

    cm_spin_unlock(&pool->lock);
}

uint8 *drc_mpool_alloc_block(drc_mpool_t *pool)
{
    area_block_header_t *block;

    if (pool->inited != CT_TRUE) {
        return NULL;
    }

    cm_spin_lock(&pool->lock, NULL);
    if (NULL == pool->free_list) {
        cm_spin_unlock(&pool->lock);
        return NULL;
    }
    block = pool->free_list;
    pool->free_list = block->next;

    pool->block_used++;

    cm_spin_unlock(&pool->lock);

    return (uint8*)block;
}

void drc_mpool_free_block(drc_mpool_t *pool, uint8 *block)
{
    area_block_header_t *free_block = (area_block_header_t*)block;

    if (pool->inited != CT_TRUE) {
        return;
    }

    cm_spin_lock(&pool->lock, NULL);

    free_block->next = pool->free_list;
    pool->free_list = free_block;
    pool->block_used--;

    cm_spin_unlock(&pool->lock);
}

status_t drc_res_pool_init(drc_res_pool_t *pool, uint64 item_size, uint32 item_num)
{
    uint64 size;
    uint32 i;
    drc_res_block_header_t *block = NULL;

    if (CT_TRUE == pool->inited) {
        return CT_ERROR;
    }

    if (item_size < sizeof(drc_res_block_header_t)) {
        return CT_ERROR;
    }

    size = item_size * item_num;
    pool->addr = (uint8*)malloc((size_t)size);
    if (NULL == pool->addr) {
        return CT_ERROR;
    }

    drc_memset_more2g((void *)pool->addr, 0, (size_t)size);

    pool->item_size = item_size;
    pool->item_num = item_num;
    pool->lock = 0;
    pool->used_num = 0;
    pool->free_list = 0;
    pool->recycle_pos = 0;
    pool->inited = CT_TRUE;

    block = (drc_res_block_header_t*)pool->addr;
    for (i = 0; i < (item_num - 1); i++) {
        block->next = i + 1;
        block = (drc_res_block_header_t*)(pool->addr + block->next * item_size);
    }
    block->next = CT_INVALID_ID32;

    return CT_SUCCESS;
}

void drc_res_pool_destroy(drc_res_pool_t *pool)
{
    cm_spin_lock(&pool->lock, NULL);
    if (CT_FALSE == pool->inited) {
        cm_spin_unlock(&pool->lock);
        return;
    }

    if (pool->addr != NULL) {
        free(pool->addr);
    }
    pool->addr = NULL;
    pool->free_list = 0;
    pool->item_num = 0;
    pool->item_size = 0;
    pool->lock = 0;
    pool->used_num = 0;
    pool->inited = CT_FALSE;

    cm_spin_unlock(&pool->lock);
}

uint32 drc_res_pool_alloc_item(drc_res_pool_t *pool)
{
    uint32  id;
    drc_res_block_header_t *block = NULL;

    if (CT_FALSE == pool->inited) {
        CT_LOG_RUN_ERR("[DRC]Pool was not been inited!");
        return CT_INVALID_ID32;
    }

    cm_spin_lock(&pool->lock, NULL);
    id = pool->free_list;
    if (CT_INVALID_ID32 == id) {
        CT_LOG_RUN_ERR_LIMIT(LOG_PRINT_INTERVAL_SECOND_20,
                             "[DRC]Alloc item failed! item_num(%u),used_num(%u).", pool->item_num, pool->used_num);
        cm_spin_unlock(&pool->lock);
        return CT_INVALID_ID32;
    }
    block = (drc_res_block_header_t*)(pool->addr + pool->free_list * pool->item_size);
    pool->free_list = block->next;
    pool->used_num++;
    cm_spin_unlock(&pool->lock);

    return id;
}

status_t drc_res_pool_alloc_batch_item(drc_res_pool_t *pool, uint32 *idx, uint32 num)
{
    uint32  id;
    drc_res_block_header_t *block = NULL;
    if (CT_FALSE == pool->inited) {
        return CT_ERROR;
    }
    cm_spin_lock(&pool->lock, NULL);
    if ((num > pool->item_num) || (pool->used_num + num > pool->item_num)) {
        CT_LOG_RUN_ERR("[DRC]Alloc batch item failed! item_num(%u),alloc_num(%u),used_num(%u).",
                       pool->item_num, num, pool->used_num);
        cm_spin_unlock(&pool->lock);
        return CT_ERROR;
    }
    id = pool->free_list;
    if (CT_INVALID_ID32 == id) {
        cm_spin_unlock(&pool->lock);
        return CT_ERROR;
    }
    for (uint32 i = 0; i < num; i++) {
        idx[i] = id;
        block = (drc_res_block_header_t*)(pool->addr + pool->free_list * pool->item_size);
        pool->free_list = block->next;
        id = pool->free_list;
        pool->used_num++;
    }
    cm_spin_unlock(&pool->lock);
    return CT_SUCCESS;
}
void drc_res_pool_free_item(drc_res_pool_t *pool, uint32 id)
{
    drc_res_block_header_t *block = NULL;

    if (CT_FALSE == pool->inited) {
        CT_LOG_RUN_ERR("[DRC]Pool was not been inited!");
        return;
    }
    cm_spin_lock(&pool->lock, NULL);
    block = (drc_res_block_header_t*)(pool->addr + id * pool->item_size);
    block->next = pool->free_list;
    pool->free_list = id;
    pool->used_num--;
    cm_spin_unlock(&pool->lock);
}
void drc_res_pool_free_batch_item(drc_res_pool_t *pool, uint32* id, uint32 num)
{
    drc_res_block_header_t *block = NULL;
    if (CT_FALSE == pool->inited) {
        CT_LOG_RUN_ERR("[DRC]Pool was not been inited!");
        return;
    }
    cm_spin_lock(&pool->lock, NULL);
    if (num > pool->used_num) {
        CT_LOG_RUN_ERR("[DRC]Free batch item failed! item_num(%u),free_num(%u),used_num(%u).",
                       pool->item_num, num, pool->used_num);
        cm_spin_unlock(&pool->lock);
        return;
    }
    for (uint32 i = 0; i < num; i++) {
        if (id[i] > pool->item_num) {
            CT_LOG_RUN_ERR("[DRC]Free batch item failed! id(%u),item_num(%u),used_num(%u).",
                           id[i], pool->item_num, pool->used_num);
            break;
        }
        block = (drc_res_block_header_t*)(pool->addr + id[i] * pool->item_size);
        block->next = pool->free_list;
        pool->free_list = id[i];
        pool->used_num--;
    }
    cm_spin_unlock(&pool->lock);
}

void drc_add_list_node(drc_list_t *list, drc_list_node_t *node, drc_list_node_t *head)
{
    if (0 == list->count) {
        node->next = CT_INVALID_ID32;
        node->prev = CT_INVALID_ID32;
        list->first = node->idx;
        list->last = node->idx;
    } else {
        node->prev = CT_INVALID_ID32;
        node->next = list->first;
        head->prev = node->idx;
        list->first = node->idx;
    }
    list->count++;
}

void drc_delete_list_node(drc_list_t *list, drc_list_node_t *del_node, drc_list_node_t *prev_node, drc_list_node_t *next_node)
{
    if (prev_node != NULL) {
        if (next_node != NULL) {
            prev_node->next = del_node->next;
            next_node->prev = del_node->prev;
        } else {
            prev_node->next = CT_INVALID_ID32;
            list->last = prev_node->idx;
        }
    } else {
        if (next_node != NULL) {
            next_node->prev = CT_INVALID_ID32;
            list->first = del_node->next;
        } else {
            list->first = CT_INVALID_ID32;
            list->last = CT_INVALID_ID32;
        }
    }
    list->count--;
}

status_t drc_res_map_init(drc_res_map_t* res_map, uint32 pool_size, uint64 item_size, is_same_res res_cmp_func)
{
    uint64   bucket_size;
    status_t ret;

    if (CT_TRUE == res_map->inited) {
        return CT_ERROR;
    }

    res_map->bucket_num = pool_size * 2 + 1;
    bucket_size = res_map->bucket_num * sizeof(drc_res_bucket_t);

    res_map->buckets = (drc_res_bucket_t*)malloc((size_t)bucket_size);
    if (NULL == res_map->buckets) {
        return CT_ERROR;
    }

    drc_memset_more2g((void*)res_map->buckets, 0, bucket_size);

    ret = drc_res_pool_init(&res_map->res_pool, item_size, pool_size);
    if (ret != CT_SUCCESS) {
        free(res_map->buckets);
        return CT_ERROR;
    }

    res_map->res_cmp_func = res_cmp_func;
    res_map->inited = CT_TRUE;

    return CT_SUCCESS;
}

void drc_res_map_destroy(drc_res_map_t* res_map)
{
    if (CT_FALSE == res_map->inited) {
        return;
    }

    drc_res_pool_destroy(&res_map->res_pool);
    if (res_map->buckets != NULL) {
        free(res_map->buckets);
    }

    res_map->buckets = NULL;
    res_map->bucket_num = 0;
    res_map->res_cmp_func = NULL;
    res_map->inited = CT_FALSE;
}

drc_res_bucket_t *drc_get_buf_map_bucket(drc_res_map_t *res_map, uint16 file, uint32 page)
{
    uint32 hash_id = drc_page_id_hash(file, page, res_map->bucket_num);
    return (&res_map->buckets[hash_id]);
}

drc_res_bucket_t *drc_get_res_map_bucket(drc_res_map_t *res_map, char *id, uint32 len)
{
    uint32 hash_id = drc_resource_id_hash(id, len, res_map->bucket_num);

    return (&res_map->buckets[hash_id]);
}

void drc_res_map_add(drc_res_bucket_t *bucket, uint32 add_idx, uint32 *next)
{
    *next = (bucket->count == 0) ? CT_INVALID_ID32 : bucket->first;
    bucket->first = add_idx;
    bucket->count++;
}

void *drc_res_map_lookup(drc_res_map_t *res_map, drc_res_bucket_t *bucket, char *res_id)
{
    uint32 i;
    void  *res = NULL;
    uint32 idx;

    if (0 == bucket->count) {
        return NULL;
    }

    idx = bucket->first;
    for (i = 0; i < bucket->count; i++) {
        res = DRC_GET_RES_ADDR_BY_ID(&res_map->res_pool, idx);
        if (CT_TRUE == res_map->res_cmp_func(res_id, res)) {
            return res;
        }

        idx = *(uint32*)res;
    }

    return NULL;
}

void drc_res_map_remove(drc_res_map_t *res_map, drc_res_bucket_t *bucket, char *res_id)
{
    uint32 i;
    void *res = NULL;
    void *pre_res = NULL;
    uint32 idx;

    if (0 == bucket->count) {
        return;
    }

    idx = bucket->first;
    for (i = 0; i < bucket->count; i++) {
        res = DRC_GET_RES_ADDR_BY_ID(&res_map->res_pool, idx);
        if (CT_TRUE == res_map->res_cmp_func(res_id, res)) {
            if (NULL == pre_res) {
                bucket->first = *(uint32*)res;
            } else {
                *(uint32*)pre_res = *(uint32*)res;
            }
            bucket->count--;
            break;
        }
        pre_res = res;
        idx = *(uint32*)res;
    }
}

status_t drc_global_res_init(drc_global_res_t * global_res, uint32 pool_size, uint64 item_size, is_same_res res_cmp_func)
{
    uint32 i;

    for (i = 0; i < DRC_MAX_PART_NUM; i++) {
        DRC_LIST_INIT(&global_res->res_parts[i]);
        CT_INIT_SPIN_LOCK(global_res->res_part_lock[i]);
        CT_INIT_SPIN_LOCK(global_res->res_part_stat_lock[i]);
    }

    return drc_res_map_init(&global_res->res_map, pool_size, item_size, res_cmp_func);
}

void drc_global_res_destroy(drc_global_res_t * global_res)
{
    uint32 i;

    for (i = 0; i < DRC_MAX_PART_NUM; i++) {
        DRC_LIST_INIT(&global_res->res_parts[i]);
        CT_INIT_SPIN_LOCK(global_res->res_part_lock[i]);
        CT_INIT_SPIN_LOCK(global_res->res_part_stat_lock[i]);
    }

    drc_res_map_destroy(&global_res->res_map);
}

