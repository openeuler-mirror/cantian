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
 * dtc_drc_util.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_drc_util.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef DTC_DRC_UTIL_H
#define DTC_DRC_UTIL_H

#include "knl_context.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DRC_MAX_PART_NUM 1024

//drc resource list structures
typedef struct st_drc_list {
    uint32 first;
    uint32 last;
    uint32 count;
}drc_list_t;

typedef struct st_drc_list_node {
    uint32 prev;
    uint32 next;
    uint32 idx;
}drc_list_node_t;

#define DRC_LIST_INIT(list)              \
    do {                                 \
        (list)->count = 0;               \
        (list)->first = GS_INVALID_ID32; \
        (list)->last = GS_INVALID_ID32;  \
    } while (0)

/* mempool structure for DRC resource management */
typedef struct st_area_block_header {
    struct  st_area_block_header *next;
} area_block_header_t;

typedef struct st_pool_area_header {
    struct st_pool_area_header *next;
}pool_area_header_t;

typedef struct st_drc_mpool {
    spinlock_t lock;
    area_block_header_t *free_list;
    pool_area_header_t *area_list;
    uint32 block_num;
    uint32 block_used;
    uint32 block_size;
    bool32 inited;
}drc_mpool_t;

#define DRC_GET_RES_ADDR_BY_ID(pool, id)  (void*)((pool)->addr + (id) * (pool)->item_size)

//resource item pool structures
typedef struct st_drc_res_block_header {
    uint32 next;
}drc_res_block_header_t;

typedef struct st_drc_res_pool {
    spinlock_t    lock;
    bool32        inited;
    uint32        free_list;
    uint32        item_num;
    uint32        used_num;
    uint64        item_size;
    uint8         *addr;
    uint32 recycle_pos;
}drc_res_pool_t;

typedef bool32 (*is_same_res) (char *res_id, void *res);
//resource hash map structures
typedef struct st_drc_res_bucket {
    spinlock_t lock;
    uint32 count;
    uint32 first;
} drc_res_bucket_t;

typedef struct st_drc_res_map {
    bool32 inited;
    drc_res_pool_t res_pool;
    uint32 bucket_num;
    drc_res_bucket_t *buckets;
    is_same_res res_cmp_func;
} drc_res_map_t;

typedef struct st_drc_global_res {
    drc_res_map_t res_map;
    drc_list_t    res_parts[DRC_MAX_PART_NUM];
    spinlock_t    res_part_lock[DRC_MAX_PART_NUM];
    spinlock_t    res_part_stat_lock[DRC_MAX_PART_NUM];
}drc_global_res_t;

static inline void drc_bitmap64_set(uint64 *bitmap, uint8 num)
{
    uint64 position;
    CM_ASSERT(num < GS_MAX_INSTANCES);

    position = (uint64)1 << num;

    *bitmap |= position;
}

static inline void drc_bitmap64_clear(uint64 *bitmap, uint8 num)
{
    uint64 position;
    CM_ASSERT(num < GS_MAX_INSTANCES);

    position = ~((uint64)1 << num);

    *bitmap &= position;
}

static inline bool32 drc_bitmap64_exist(uint64 *bitmap, uint8 num)
{
    uint64 position;
    bool32 is_exist = GS_FALSE;
    CM_ASSERT(num < GS_MAX_INSTANCES);

    position = (uint64)1 << num;

    position = *bitmap & position;

    is_exist = (0 == position) ? GS_FALSE : GS_TRUE;

    return is_exist;
}

static inline uint32 drc_page_id_hash(uint16 file, uint32 page, uint32 range)
{
    return (HASH_SEED * (uint32)file + HASH_SEED * page) % range;
}

//use BKDR hash algrithm, get the hash id
static inline uint32 drc_resource_id_hash(char *id, uint32 len, uint32 range)
{
    uint32 seed = 131;  // this is BKDR hash seed: 31 131 1313 13131 131313 etc..
    uint32 hash = 0;
    uint32 i;

    for (i = 0; i < len; i++) {
        hash = hash * seed + (*id++);
    }

    return(hash % range);
}

// memory pool APIS for drc resource map
status_t drc_mpool_init(drc_mpool_t *pool, uint32 block_size, uint32 block_num);
status_t drc_mpool_extend(drc_mpool_t *pool, uint32 block_num);
void drc_mpool_destroy(drc_mpool_t *pool);
uint8 *drc_mpool_alloc_block(drc_mpool_t *pool);
void drc_mpool_free_block(drc_mpool_t *pool, uint8 *block);

//resource pool APIs
status_t drc_res_pool_init(drc_res_pool_t *pool, uint64 item_size, uint32 item_num);
void drc_res_pool_destroy(drc_res_pool_t *pool);
uint32 drc_res_pool_alloc_item(drc_res_pool_t *pool);
void drc_res_pool_free_item(drc_res_pool_t *pool, uint32 id);
status_t drc_res_pool_alloc_batch_item(drc_res_pool_t *pool, uint32 *idx, uint32 num);
void drc_res_pool_free_batch_item(drc_res_pool_t *pool, uint32 *id, uint32 num);

//drc list APIs
void drc_add_list_node(drc_list_t *list, drc_list_node_t *node, drc_list_node_t *head);
void drc_delete_list_node(drc_list_t *list, drc_list_node_t *del_node, drc_list_node_t *prev_node, drc_list_node_t *next_node);

//drc resource map APIs
status_t drc_res_map_init(drc_res_map_t* res_map, uint32 pool_size, uint64 item_size, is_same_res res_cmp_func);
void drc_res_map_destroy(drc_res_map_t* res_map);
drc_res_bucket_t *drc_get_buf_map_bucket(drc_res_map_t *res_map, uint16 file, uint32 page);
drc_res_bucket_t *drc_get_res_map_bucket(drc_res_map_t *res_map, char *id, uint32 len);
void drc_res_map_add(drc_res_bucket_t *bucket, uint32 add_idx, uint32 *next);
void *drc_res_map_lookup(drc_res_map_t *res_map, drc_res_bucket_t *bucket, char *res_id);
void drc_res_map_remove(drc_res_map_t *res_map, drc_res_bucket_t *bucket, char *res_id);

//drc global resource map management APIs
status_t drc_global_res_init(drc_global_res_t *global_res, uint32 pool_size, uint64 item_size,
                             is_same_res res_cmp_func);
void drc_global_res_destroy(drc_global_res_t *global_res);

#ifdef __cplusplus
}
#endif

#endif
