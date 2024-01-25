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
 * pl_manager.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/pl_manager.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_MANAGER_H__
#define __PL_MANAGER_H__

#include "pl_lock.h"
#include "mes_func.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PL_ENTITY_LRU_SIZE 8
#define PL_ENTRY_NAME_BUCKET_SIZE SIZE_K(128)
#define PL_ENTRY_OID_BUCKET_SIZE 10000
#define PL_ANONY_LRU_SIZE 8
#define PL_ANONY_BUCKET_SIZE SIZE_K(128)

typedef struct st_pl_manager pl_manager_t;
struct st_pl_manager {
    bool32 initialized;
    spinlock_t memory_lock;
    memory_context_t *memory;
    pl_list_t free_entry;
    pl_list_t pl_entity_lru[PL_ENTITY_LRU_SIZE];
    pl_list_t entry_name_buckets[PL_ENTRY_NAME_BUCKET_SIZE];
    pl_list_t entry_oid_buckets[PL_ENTRY_OID_BUCKET_SIZE];
    pl_list_t anony_lru[PL_ANONY_LRU_SIZE];
    pl_list_t anony_buckets[PL_ANONY_BUCKET_SIZE];
    mes_profile_t profile; /* ext proc profile */
    pl_lock_pool_t lock_map_pool;
    bool32 bootstrap; /* ext proc default startup */
    external_recycle_t external_recycle;
};

status_t pl_init(knl_handle_t sess);
status_t pl_load_entry(pl_desc_t *desc);
void pl_release_context(sql_stmt_t *stmt);
#ifdef __cplusplus
}
#endif

#endif
