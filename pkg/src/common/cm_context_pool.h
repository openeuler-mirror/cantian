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
 * cm_context_pool.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_context_pool.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_CONTEXT_POOL_H__
#define __CM_CONTEXT_POOL_H__

#include "cm_defs.h"
#include "cm_text.h"
#include "cm_memory.h"
#include "cm_spinlock.h"
#include "cm_list.h"

typedef struct st_context_ctrl {
    spinlock_t lock;
    uint32 uid;
    volatile uint32 ref_count;
    volatile int32 exec_count;

    struct st_context_pool *pool;
    memory_context_t *memory;
    char *text_addr;
    struct st_context_bucket *bucket;

    struct st_context_ctrl *lru_prev;  // LRU
    struct st_context_ctrl *lru_next;  // LRU

    struct st_context_ctrl *hash_prev;
    struct st_context_ctrl *hash_next;

    uint32 map_id;
    uint32 hash_value;
    uint32 text_size;
    uint32 remote_conn_type;

    bool32 valid : 1;
    bool32 cleaned : 1;
    bool32 is_free : 1;
    bool32 is_direct_route : 1;
    bool32 fixed : 1; // if true, context will not be automatically recycled
    uint32 unused : 27;
    struct st_context_pool *subpool;
    text_t signature; // actual plan text sign by MD5
    galist_t *pdown_sql_id;
    spinlock_t subpool_lock;
} context_ctrl_t;

typedef struct st_context_bucket {
    spinlock_t enque_lock;  // lock for enque into bucket
    context_ctrl_t *first;
    recursive_lock_t parsing_lock;  // lock for parsing
} context_bucket_t;

typedef void (*context_clean_t)(context_ctrl_t *ctrl);

typedef struct st_context_pool_profile {
    memory_area_t *area;
    char *name;
    uint32 init_pages;
    uint32 optimize_pages;
    uint32 context_size;
    uint32 bucket_count;
    context_clean_t clean;
} context_pool_profile_t;

typedef struct st_context_list {
    uint32 first;
    uint32 count;
} context_list_t;

typedef struct st_context_map {
    uint32         hwm;
    uint32         map_size;
    context_list_t free_items;
    uint32         items[1];  // first page id of context
} context_map_t;

typedef bool32 (*external_recycle_t)(void);

#define CT_LRU_LIST_CNT 10

typedef struct st_lru_list {
    spinlock_t lock;
    uint32 lru_count;
    context_ctrl_t *lru_head;
    context_ctrl_t *lru_tail;
} lru_list_t;

typedef struct st_context_pool {
    spinlock_t lock;
    uint32 context_size;
    uint32 bucket_count;
    memory_pool_t *memory;
    context_map_t *map;
    uint32 lru_list_idx;
    uint32 lru_list_cnt;
    lru_list_t *lru_list;
    context_clean_t clean;
    external_recycle_t external_recycle;
    context_bucket_t buckets[1];
} context_pool_t;

#define SPM_CONTEXT_FIXED(context) ((context)->ctrl.fixed)

status_t ctx_pool_create(context_pool_profile_t *profile, context_pool_t **pool);
void ctx_pool_destroy(context_pool_t *pool);
status_t ctx_create(context_pool_t *pool, context_ctrl_t **ctrl);
void ctx_reuse(context_pool_t *pool, context_ctrl_t *ctrl);
void ctx_insert(context_pool_t *pool, context_ctrl_t *ctrl);
void ctx_bucket_insert(context_bucket_t *bucket, context_ctrl_t *ctrl);
status_t ctx_write_text(context_ctrl_t *ctrl, text_t *text);
status_t ctx_read_text(context_pool_t *pool, context_ctrl_t *ctrl, text_t *text, bool32 is_cut);
void *ctx_pool_find(context_pool_t *pool, text_t *text, uint32 hash_value, uint32 uid, uint32 remote_conn_type,
                    bool32 is_direct_route);
void ctx_dec_ref(context_pool_t *pool, context_ctrl_t *ctrl);
void ctx_dec_exec(context_ctrl_t *ctrl);
void ctx_pool_lru_move_to_head(context_pool_t *pool, context_ctrl_t *ctrl);
static inline void ctx_inc_ref(context_ctrl_t *ctrl)
{
    cm_spin_lock(&ctrl->lock, NULL);
    ctrl->ref_count++;
    cm_spin_unlock(&ctrl->lock);
}
static inline void ctx_dec_ref2(context_ctrl_t *ctrl)
{
    cm_spin_lock(&ctrl->lock, NULL);
    ctrl->ref_count--;
    cm_spin_unlock(&ctrl->lock);
}
status_t sql_ctx_alloc_mem(context_pool_t *pool, memory_context_t *memory, uint32 size, void **buf);
bool32 ctx_recycle_internal_core(context_pool_t *pool);
void ctx_recycle_all_core(context_pool_t *pool);
context_ctrl_t *ctx_get(context_pool_t *pool, uint32 id);
void ctx_read_first_page_text(context_pool_t *pool, context_ctrl_t *ctrl, text_t *text);
void ctx_flush_shared_pool(context_pool_t *pool);
status_t ctx_alloc_exhausted(context_ctrl_t *ctrl, uint32 size, void **buf, uint32 *buf_size);
status_t ctx_create_mctx(context_pool_t *pool, memory_context_t **mctx);
uint32 ctx_pool_get_lru_cnt(context_pool_t *pool);

#endif

