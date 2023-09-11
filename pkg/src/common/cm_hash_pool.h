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
 * cm_hash_pool.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_hash_pool.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CM_HASH_POOL_H__
#define __CM_HASH_POOL_H__

#include "cm_defs.h"
#include "cm_memory.h"
#include "cm_hash.h"
#include "cm_spinlock.h"

#ifdef __cplusplus
extern "C" {
#endif
#define HASH_MEM_EXTENT_SIZE 4

#define HASH_NODE_OF(node) ((cm_hash_item_t *)((char *)(node) - OFFSET_OF(cm_hash_item_t, data)))

#define ENTRY_SIZE(pool)         (pool)->profile.entry_size
#define HASH_MAX_SIZE(pool)      (pool)->profile.max_num
#define HASH_NAME(pool)          (pool)->profile.name


#define HASH_BUCKETS(pool)       (pool)->buckets
#define HASH_FREE_LIST(pool)   &((pool)->free_list)

#define HASH_ITEM_SIZE       sizeof(cm_hash_item_t)
typedef struct st_cm_hash_item_t {
    spinlock_t lock;
    struct st_cm_hash_item_t *prev;
    struct st_cm_hash_item_t *next;
    char data[0];
} cm_hash_item_t;

typedef struct st_cm_hash_bucket_t {
    spinlock_t lock;
    uint32 count;
    cm_hash_item_t *first;
} cm_hash_bucket_t;

typedef bool32(*cm_hp_match_data)(void *data, void *entry);
typedef uint32(*cm_hp_hash_data)(void *data);

typedef struct st_cm_hash_profile_t {
    char name[GS_NAME_BUFFER_SIZE];
    cm_hp_match_data cb_match_data;
    cm_hp_hash_data cb_hash_data;
    uint32 bucket_num;
    uint32 entry_size;
    uint32 max_num;
} cm_hash_profile_t;

typedef struct st_cm_hash_pool_t {
    cm_hash_profile_t profile;
    cm_hash_bucket_t  free_list;
    cm_hash_bucket_t *buckets;
    uint32 hwm;
    uint32 count;
    char **pages;
} cm_hash_pool_t;

static inline void init_hash_bucket(cm_hash_bucket_t *bucket)
{
    bucket->count = 0;
    bucket->lock = 0;
    bucket->first = NULL;
}

void cm_hash_pool_destory(cm_hash_pool_t *pool);

status_t cm_hash_pool_create(cm_hash_profile_t *profile, cm_hash_pool_t *pool);

/*
 * find the hash entry
 * caution:
 * The api internally locks the hash entry, The invoke should actively release the lock
 * void *hash_data = hash_pool_match_lock(pool, data)
 * cm_hash_item_t *entry = HASH_NODE_OF(hash_data);
 * cm_spin_unlock(&entry->lock);
 *
 * @param hp, hash key, hash data
 */
void *cm_hash_pool_match_lock(cm_hash_pool_t *pool, void *data);

status_t cm_hash_pool_add(cm_hash_pool_t *pool, void *data);

void cm_hash_pool_del(cm_hash_pool_t *pool, void *data);

#ifdef __cplusplus
}
#endif

#endif //__CM_HASH_POOL_H__

