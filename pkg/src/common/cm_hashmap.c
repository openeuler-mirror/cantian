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
 * cm_hashmap.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_hashmap.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_hashmap.h"
//#include "cm_utils.h"
//#include "cm_string.h"
//#include "cm_memory.h"
#include "cm_log.h"
#include "cm_error.h"
#include "cm_malloc.h"
#include "cm_debug.h"
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define HASH_MASK 0x3fffffff;
static uint32 const primes[] = { 7,        13,        31,        61,        127,        251,        509,       1021,
                                 1297,     2039,      4093,      8191,      16381,      32749,      65521,     131071,
                                 262139,   524287,    1048573,   2097143,   4194301,    8388593,    16777213,  33554393,
                                 67108859, 134217689, 268435399, 536870909, 1073741789, 2147483647, 0xfffffffb };

bool32 cm_oamap_ptr_compare(void *key1, void *key2)
{
    CM_POINTER2(key1, key2);
    return (key1 == key2);
}

bool32 cm_oamap_uint64_compare(void *key1, void *key2)
{
    CM_POINTER2(key1, key2);
    return (*(uint64 *)key1 == *(uint64 *)key2);
}

bool32 cm_oamap_uint32_compare(void *key1, void *key2)
{
    CM_POINTER2(key1, key2);
    return (*(uint32 *)key1 == *(uint32 *)key2);
}

bool32 cm_oamap_string_compare(void *key1, void *key2)
{
    CM_POINTER2(key1, key2);
    return (strcmp((char *)key1, (char *)key2) == 0);
}

static inline uint32 oamap_get_near_prime(unsigned long n)
{
    uint32 low = 0;
    uint32 cnt = sizeof(primes) / sizeof(uint32);
    uint32 high = cnt;

    while (low != high) {
        unsigned int mid = low + (high - low) / 2;
        if (n > primes[mid]) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    if (low < cnt) {
        return primes[low];
    } else {
        return (uint32)n;
    }
}

int32 oamap_rehash(cm_oamap_t *map, uint32 new_capacity)
{
    CM_POINTER(map);
    cm_oamap_bucket_t *new_buckets;
    cm_oamap_bucket_t *src_bucket;
    cm_oamap_bucket_t *dst_bucket;
    void **new_key;
    void **new_value;
    uint64 size;
    uint32 i, j, start, used;
    bool32 found;

    if (0 == new_capacity) {
        return ERR_GSS_INVALID_PARAM;
    }

    size = new_capacity * (sizeof(cm_oamap_bucket_t) + sizeof(void *) + sizeof(void *));
    if (size >= GS_INVALID_ID32) {
        GS_LOG_DEBUG_ERR("Invalid capacity value specified for rehashing map.");
        return ERR_GSS_INVALID_PARAM;
    }
    // if (map->mem_ctx != NULL)
    //{
    //     //new_buckets = (cm_oamap_bucket_t *)memctx_alloc(map->mem_ctx, (uint32)size);
    //     return ERR_GSS_INVALID_PARAM;
    // }
    // else
    {
        new_buckets = (cm_oamap_bucket_t *)cm_malloc((uint32)size);
    }
    if (new_buckets == NULL) {
        GS_LOG_DEBUG_ERR("Malloc failed");
        return ERR_ALLOC_MEMORY;
    }
    /*lint -save -e740 */
    new_key = (void **)(new_buckets + new_capacity);
    new_value = (void **)(new_key + new_capacity);
    /*lint -restore */

    for (i = 0; i < new_capacity; i++) {
        new_buckets[i].state = (uint32)FREE;
        new_key[i] = NULL;
        new_value[i] = NULL;
    }
    used = 0;
    for (i = 0; i < map->num; i++) {
        src_bucket = &(map->buckets[i]);
        if (src_bucket->state != (uint32)USED) {
            continue;
        }
        // TODO:PERF
        start = src_bucket->hash % new_capacity;
        found = GS_FALSE;
        for (j = start; j < new_capacity; j++) {
            dst_bucket = &new_buckets[j];
            if (dst_bucket->state != (uint32)USED) {
                *dst_bucket = *src_bucket;
                new_key[j] = map->key[i];
                new_value[j] = map->value[i];
                found = GS_TRUE;
                used++;
                break;
            }
        }
        if (!found) {
            while (start > 0) {
                start--;
                dst_bucket = &new_buckets[start];
                if (dst_bucket->state != (uint32)USED) {
                    *dst_bucket = *src_bucket;
                    new_key[start] = map->key[i];
                    new_value[start] = map->value[i];
                    found = GS_TRUE;
                    used++;
                    break;
                }
            }
        }
    }
    // if (map->mem_ctx == NULL)
    {
        cm_free(map->buckets);
    }
    map->buckets = new_buckets;
    map->key = new_key;
    map->value = new_value;
    map->num = new_capacity;
    map->deleted = 0;
    map->used = used;
    return GS_SUCCESS;
}

void cm_oamap_init_mem(cm_oamap_t *map)
{
    if (NULL == map) {
        GS_LOG_DEBUG_ERR("Null pointer specified");
        return;
    }

    map->buckets = NULL;
    map->key = NULL;
    map->value = NULL;
    map->num = 0;
    map->used = 0;
    map->deleted = 0;
    // map->mem_ctx = NULL;
    map->compare_func = NULL;
}

int32 cm_oamap_init(cm_oamap_t *map, uint32 init_capacity,
                    cm_oamap_compare_t compare_func /*, memory_context_t *mem_ctx*/)
{
    uint64 size;
    uint32 i;
    if (map == NULL || compare_func == NULL) {
        GS_LOG_DEBUG_ERR("Null pointer specified");
        return ERR_GSS_INVALID_PARAM;
    }
    // The max oamap
    map->num = oamap_get_near_prime(init_capacity);
    if (map->num >= MAX_OAMAP_BUCKET_NUM) {
        GS_LOG_DEBUG_ERR("Invalid bucket num specified");
        return ERR_GSS_INVALID_PARAM;
    }
    map->used = 0;
    size = map->num * (sizeof(cm_oamap_bucket_t) + sizeof(void *) + sizeof(void *));
    if (size >= GS_INVALID_ID32) {
        GS_LOG_DEBUG_ERR("Invalid map size");
        return ERR_GSS_INVALID_PARAM;
    }
    map->compare_func = compare_func;
    // map->mem_ctx = mem_ctx;
    // if (mem_ctx != NULL)
    //{
    //     //map->buckets = (cm_oamap_bucket_t *)memctx_alloc(mem_ctx, (uint32)size);
    //     return ERR_GSS_INVALID_PARAM;
    // }
    // else
    {
        map->buckets = (cm_oamap_bucket_t *)cm_malloc((uint32)size);
    }
    if (map->buckets == NULL) {
        GS_LOG_DEBUG_ERR("Malloc failed");
        return ERR_ALLOC_MEMORY;
    }
    /*lint -save -e740 */
    map->key = (void **)(map->buckets + map->num);
    map->value = (void **)(map->key + map->num);
    /*lint -restore */

    for (i = 0; i < map->num; i++) {
        map->buckets[i].state = (uint32)FREE;
        map->key[i] = NULL;
        map->value[i] = NULL;
    }
    map->deleted = 0;
    return GS_SUCCESS;
}

void cm_oamap_destroy(cm_oamap_t *map)
{
    CM_POINTER(map);
    map->num = 0;
    map->deleted = 0;
    map->used = 0;
    // if (map->mem_ctx == NULL)
    {
        if (NULL != map->buckets) {
            cm_free(map->buckets);
            map->buckets = NULL;
        }
    }
    /*else
    {
        map->mem_ctx = NULL;
    }*/
    map->compare_func = NULL;
}

int32 cm_oamap_insert(cm_oamap_t *map, uint32 hash_input, void *key, void *value)
{
    uint32 ret;
    uint32 i, start;
    uint32 insert_pos = 0;
    uint32 new_size;
    bool32 found_free;
    bool32 found_pos;
    cm_oamap_bucket_t *bucket;
    uint32 hash = hash_input;
    if (NULL == map) {
        GS_LOG_DEBUG_ERR("Pointer to map is NULL");
        return ERR_GSS_INVALID_PARAM;
    }
    if ((map->used - map->deleted) * 3 > map->num * 2) {
        new_size = oamap_get_near_prime(map->num + 1);
        if (new_size > MAX_OAMAP_BUCKET_NUM) {
            GS_LOG_DEBUG_ERR("Invalid bucket num specified");
            return ERR_GSS_INVALID_PARAM;
        }
        ret = (uint32)oamap_rehash(map, new_size);
        if (ret != GS_SUCCESS) {
            GS_LOG_DEBUG_ERR("OAMAP rehash failed,%d.", ret);
            return ret;
        }
    }
    hash = hash & HASH_MASK;
    // TODO:PERF
    start = hash % map->num;
    found_free = GS_FALSE;
    found_pos = GS_FALSE;
    for (i = start; i < map->num; i++) {
        bucket = &(map->buckets[i]);
        if (bucket->state == (uint32)FREE) {
            found_free = GS_TRUE;
            if (found_pos != GS_TRUE) {
                // find a new free pos to insert. so need to update the used counter
                map->used++;
                found_pos = GS_TRUE;
                insert_pos = i;
            }
            break;
        } else if (bucket->state == (uint32)DELETED) {
            if (found_pos != GS_TRUE) {
                // find a deleted pos to reuse for insert. so need to udpate the deleted counter
                map->deleted--;
                found_pos = GS_TRUE;
                insert_pos = i;
            }
        } else {
            if (bucket->hash == hash && map->compare_func(map->key[i], key) == GS_TRUE) {
                GS_LOG_DEBUG_ERR("Duplicate key being inserted, i:%d, hash:%u", i, hash);
                return ERR_OAMAP_DUP_KEY_ERROR;
            }
        }
    }
    if (found_free != GS_TRUE) {
        while (start > 0) {
            start--;
            bucket = &(map->buckets[start]);
            if (bucket->state == (uint32)FREE) {
                if (found_pos != GS_TRUE) {
                    // find a new free pos to insert. so need to update the used counter
                    map->used++;
                    found_pos = GS_TRUE;
                    insert_pos = start;
                }
                break;
            } else if (bucket->state == (uint32)DELETED) {
                if (found_pos != GS_TRUE) {
                    // find a deleted pos to reuse for insert. so need to update the deleted counter
                    map->deleted--;
                    found_pos = GS_TRUE;
                    insert_pos = start;
                }
            } else {
                if (bucket->hash == hash && map->compare_func(map->key[start], key) == GS_TRUE) {
                    GS_LOG_DEBUG_ERR("Duplicate key being inserted");
                    return ERR_OAMAP_DUP_KEY_ERROR;
                }
            }
        }
    }
    if (found_pos == GS_TRUE) {
        bucket = &(map->buckets[insert_pos]);
        bucket->hash = hash;
        bucket->state = (uint32)USED;
        map->key[insert_pos] = key;
        map->value[insert_pos] = value;
        return GS_SUCCESS;
    } else {
        GS_LOG_DEBUG_ERR("Insertion failed");
        return ERR_OAMAP_INSERTION_FAILED;
    }
}

void *cm_oamap_lookup(cm_oamap_t *map, uint32 hash_input, void *key)
{
    uint32 i, start;
    cm_oamap_bucket_t *bucket;
    uint32 hash = hash_input;

    if (NULL == map) {
        GS_LOG_DEBUG_ERR("Pointer to map is NULL");
        return NULL;
    }

    if (0 == map->num) {
        GS_LOG_DEBUG_ERR("The map is not initialized.");
        return NULL;
    }

    hash = hash & HASH_MASK;
    // TODO:PERF
    start = hash % map->num;

    for (i = start; i < map->num; i++) {
        bucket = &(map->buckets[i]);
        if (bucket->state == (uint32)FREE) {
            GS_LOG_DEBUG_INF("Search key not found, i:%u, hash:%u", i, hash);
            return NULL;
        } else if (bucket->state == (uint32)USED) {
            if (bucket->hash == hash && map->compare_func(map->key[i], key) == GS_TRUE) {
                return map->value[i];
            }
            GS_LOG_DEBUG_INF("Search key not equal, i:%u, hash:%u, bucket hash:%u", i, hash, bucket->hash);
        } else {
            // for lint
        }
    }

    while (start > 0) {
        start--;
        bucket = &(map->buckets[start]);
        if (bucket->state == (uint32)FREE) {
            GS_LOG_DEBUG_INF("Search key not found, start:%u, hash:%u", start, hash);
            return NULL;
        } else if (bucket->state == (uint32)USED) {
            if (bucket->hash == hash && map->compare_func(map->key[start], key) == GS_TRUE) {
                return map->value[start];
            }
        } else {
            // for lint
        }
    }
    GS_LOG_DEBUG_INF("Search key not found");
    return NULL;
}

void *cm_oamap_remove(cm_oamap_t *map, uint32 hash_input, void *key)
{
    uint32 i, start;
    cm_oamap_bucket_t *bucket;
    uint32 hash = hash_input;
    void *value = NULL;
    if (NULL == map) {
        GS_LOG_DEBUG_ERR("Pointer to map is NULL");
        return NULL;
    }

    hash = hash & HASH_MASK;
    // TODO:PERF
    start = hash % map->num;
    for (i = start; i < map->num; i++) {
        bucket = &(map->buckets[i]);
        if (bucket->state == (uint32)FREE) {
            return NULL;
        } else if (bucket->state == (uint32)USED) {
            if (bucket->hash == hash && map->compare_func(map->key[i], key) == GS_TRUE) {
                bucket->hash = 0;
                bucket->state = (uint32)DELETED;
                map->deleted++;
                value = map->value[i];
                map->key[i] = NULL;
                map->value[i] = NULL;
                return value;
            }
        } else {
            // for lint
        }
    }

    while (start > 0) {
        start--;
        bucket = &(map->buckets[start]);
        if (bucket->state == (uint32)FREE) {
            return NULL;
        } else if (bucket->state == (uint32)USED) {
            if (bucket->hash == hash && map->compare_func(map->key[start], key) == GS_TRUE) {
                bucket->hash = 0;
                bucket->state = (uint32)DELETED;
                map->deleted++;
                value = map->value[start];
                map->key[start] = NULL;
                map->value[start] = NULL;
                return value;
            }
        } else {
            // for lint
        }
    }
    GS_LOG_DEBUG_ERR("Key to remove not found");
    return value;
}

void cm_oamap_reset_iterator(cm_oamap_iterator_t *iter)
{
    CM_POINTER(iter);
    *iter = 0;
}

int32 cm_oamap_fetch(cm_oamap_t *map, cm_oamap_iterator_t *iter, void **key, void **value)
{
    uint32 i;
    cm_oamap_bucket_t *bucket;
    CM_POINTER4(map, iter, key, value);

    for (i = *iter; i < map->num; i++) {
        bucket = &(map->buckets[i]);
        if (bucket->state == (uint32)USED) {
            *key = map->key[i];
            *value = map->value[i];
            *iter = i + 1;
            return GS_SUCCESS;
        }
    }

    *key = NULL;
    *value = NULL;
    *iter = map->num;
    return ERR_OAMAP_FETCH_FAILED;
}

uint32 cm_oamap_size(cm_oamap_t *map)
{
    CM_POINTER(map);
    return map->num;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
