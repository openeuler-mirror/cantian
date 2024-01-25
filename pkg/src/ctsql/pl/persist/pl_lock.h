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
 * pl_lock.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/persist/pl_lock.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_LOCK_H__
#define __PL_LOCK_H__

#include "pl_dc.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_pl_lock_mode {
    PL_MODE_IDLE = 0,
    PL_MODE_S = 1,
    PL_MODE_IX = 2,
    PL_MODE_X = 3,
} pl_lock_mode_t;

#define CT_PL_LOCK_MAX_RECUR_LVL CT_INVALID_ID32
#define CT_PL_LOCK_MAX_EXTENTS 1024
#define CT_PL_LOCK_EXTENT 16
#define CT_PL_LOCK_MAX_MAPS (CT_PL_LOCK_EXTENT * CT_PL_LOCK_MAX_EXTENTS)

typedef struct st_pl_lock_ast {
    knl_session_t *se;
    pl_dc_t *dc;
    pl_entity_t *entity;
    pl_entry_t *entry;
    uint32 timeout;
    pl_lock_mode_t lock_mode;
    bool32 no_wait;
    uint32 map_id;
    knl_scn_t chg_scn;
} pl_lock_ast_t;

typedef struct st_pl_lock_item {
    spinlock_t lock;
    uint32 lock_times; // locked times in shared mode or recursively locked
    int64 id;
    uint32 first_map; // record which session or rm locked the lock
    uint32 x_map_id;  // locked exclusively by which session or rm
    uint32 x_times;   // recursively exclusively locked times
    uint32 ix_map_id;
    uint16 lock_mode;
    uint16 unused;
} pl_lock_item_t;

typedef struct st_pl_lock_map {
    uint32 id;
    uint32 idx;
    uint32 prev;
    uint32 next;
    uint32 count;
} pl_lock_map_t;

typedef struct st_pl_lock_pool {
    spinlock_t lock;
    char *extents[CT_PL_LOCK_MAX_EXTENTS];
    volatile uint32 capacity;
    uint32 count;
    uint32 ext_cnt;
    uint32 free_first;
    uint32 free_count;
    volatile bool32 extending;
} pl_lock_pool_t;


#define PL_LOCK_MAP_PTR(pool, id) \
    ((pl_lock_map_t *)((pool)->extents[(id) / CT_PL_LOCK_EXTENT] + sizeof(pl_lock_map_t) * ((id) % CT_PL_LOCK_EXTENT)))

void ple_restore_lock_entries(sql_stmt_t *stmt, const uint32 entry_cnt);

void pl_unlock_shared(knl_handle_t sess, pl_entry_t *entry);
void pl_unlock_exclusive(knl_handle_t sess, pl_entry_t *entry);

status_t pl_lock_entry_shared(knl_handle_t sess, pl_entry_info_t *entry_info);
status_t pl_lock_entry_exclusive(knl_handle_t sess, pl_entry_info_t *entry_info);

status_t pl_lock_dc_shared(knl_handle_t sess, pl_dc_t *dc);

void pl_init_lock_map_pool(pl_lock_pool_t *pool);

#ifdef __cplusplus
}
#endif

#endif