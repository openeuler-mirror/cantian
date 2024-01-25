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
 * knl_alck.h
 *
 *
 * IDENTIFICATION
 * src/kernel/xact/knl_alck.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_alck_H__
#define __KNL_alck_H__

#include "cm_latch.h"

#define CT_ALCK_MAX_BUCKETS 4096
#define CT_ALCK_EXTENT      1024
#define CT_ALCK_MAX_EXTENTS 1024
#define CT_ALCK_MAX_ITEMS   (CT_ALCK_MAX_EXTENTS * CT_ALCK_EXTENT)
#define CT_ALCK_MAX_RECUR_LVL CT_INVALID_ID32
#define CT_ALCK_MAP_MAX_EXTENTS (3 * CT_ALCK_MAX_EXTENTS)
#define CT_ALCK_MAX_MAPS   (CT_ALCK_EXTENT * CT_ALCK_MAP_MAX_EXTENTS)

typedef enum en_alck_lock_set {
    SE_LOCK = 0,        // session level lock
    TX_LOCK,            // transaction level lock
} alck_lock_set_t;

typedef struct st_alck_bucket {
    latch_t latch;
    uint32  id;
    uint32  first;
}alck_bucket_t;

typedef struct st_alck_item_pool {
    spinlock_t lock;
    char *extents[CT_ALCK_MAX_EXTENTS];
    volatile uint32 capacity;
    uint32 count;
    uint32 ext_cnt;
    uint32 free_first;
    uint32 free_count;
    volatile bool32 extending;
}alck_item_pool_t;


typedef struct st_alck_map_pool {
    spinlock_t lock;
    char *extents[CT_ALCK_MAP_MAX_EXTENTS];
    volatile uint32 capacity;
    uint32 count;
    uint32 ext_cnt;
    uint32 free_first;
    uint32 free_count;
    volatile bool32 extending;
}alck_map_pool_t;

typedef struct st_alck_ctx_spec {
    alck_lock_set_t lock_set;
    alck_item_pool_t item_pool;
    alck_map_pool_t map_pool;
    alck_bucket_t buckets[CT_ALCK_MAX_BUCKETS];
}alck_ctx_spec_t;

typedef struct st_alck_ctx {
    alck_ctx_spec_t tx_ctx;
    alck_ctx_spec_t se_ctx;
}alck_ctx_t;


typedef enum en_alck_mode {
    ALCK_MODE_IDLE = 0,
    ALCK_MODE_S = 1,
    ALCK_MODE_IX = 2,
    ALCK_MODE_X = 3,
}alck_mode_t;


typedef struct st_alck_map {
    uint32 id;
    uint32 prev;
    uint32 next;
    uint32 idx;
    uint32 count;
} alck_map_t;

typedef struct st_alck_item {
    spinlock_t    lock;
    char          name[CT_ALCK_NAME_BUFFER_SIZE];
    uint32        lock_times; // locked times in shared mode or recursively locked by one session or rm
    uint32        sn;         // serial number, increased when unlocked
    uint32        x_map_id;   // locked exclusively by which session or rm
    uint32        x_times;    // recursively exclusively locked times
    uint32        ix_map_id;  // the session or rm who set ix has a higher priority
    uint32        id;
    uint32        prev;
    uint32        next;
    uint32        bucket_id : 16;
    uint32        lock_mode : 2;
    uint32        unused    : 14;
    uint32        first_map;     // record which session or rm locked the lock
}alck_item_t;

#define ALCK_ITEM_PTR(pool, id) ((alck_item_t *)((pool)->extents[(id) / CT_ALCK_EXTENT] + \
                                  sizeof(alck_item_t) * ((id) % CT_ALCK_EXTENT)))
#define ALCK_ITEM_INIT(alck_item)                         \
do {                                                      \
    (alck_item)->first_map = CT_INVALID_ID32;             \
    (alck_item)->x_map_id = CT_INVALID_ID32;              \
    (alck_item)->ix_map_id = CT_INVALID_ID32;             \
    (alck_item)->x_times = 0;                             \
    (alck_item)->lock_times = 0;                          \
    (alck_item)->lock_mode = ALCK_MODE_IDLE;              \
    (alck_item)->prev = CT_INVALID_ID32;                  \
    (alck_item)->next = CT_INVALID_ID32;                  \
} while (CT_FALSE)

#define ALCK_MAP_PTR(pool, id) ((alck_map_t *)((pool)->extents[(id) / CT_ALCK_EXTENT] + \
                                  sizeof(alck_map_t) * ((id) % CT_ALCK_EXTENT)))

status_t alck_init_ctx(struct st_knl_instance *kernel);
void alck_deinit_ctx(struct st_knl_instance *kernel);

void alck_se_unlock_all(knl_handle_t sess, uint32 alck_id);
void alck_tx_unlock_sh(knl_handle_t sess, uint32 alck_id);
void alck_tx_unlock_ex(knl_handle_t sess, uint32 alck_id);
status_t alck_check_db_status(knl_session_t *session);
uint32 alck_get_locks(alck_map_pool_t *map_pool, alck_item_t *alck_item, uint32 idx);
alck_map_t* alck_get_map(alck_map_pool_t *map_pool, alck_item_t *alck_item, uint32 idx);
#endif
