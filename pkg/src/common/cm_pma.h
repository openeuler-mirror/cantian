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
 * cm_pma.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_pma.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_PMA_H__
#define __CM_PMA_H__

#include "cm_memory.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PMA_PAGE_SIZE            SIZE_M(1)
#define PMA_MAX_SIZE             SIZE_T(1)
#define VM_PAGES_PER_PPAGE       (uint32)(PMA_PAGE_SIZE / GS_VMEM_PAGE_SIZE)

typedef struct st_private_memory_pool {
    id_list_t pages;
    memory_pool_t mpool;
} pm_pool_t;

typedef struct st_private_memory_area {
    memory_area_t marea;
    pm_pool_t *pool;
    uint32 *maps;   // maps for vm pages
} pma_t;

static inline void pm_area_init(const char *name, char *pma_buf, uint64 pma_size, pma_t *pma)
{
    MEMS_RETVOID_IFERR(memset_sp(pma, sizeof(pma_t), 0, sizeof(pma_t)));
    uint32 page_size = PMA_PAGE_SIZE + sizeof(pm_pool_t) + sizeof(uint32) + VM_PAGES_PER_PPAGE * sizeof(uint32);
    uint32 page_count = (uint32)(pma_size / page_size);
    GS_RETVOID_IFTRUE(page_count == 0);

    uint64 pool_size = sizeof(pm_pool_t) * page_count;
    uint64 maps_size = sizeof(uint32) * VM_PAGES_PER_PPAGE * page_count;
    pma->pool = (pm_pool_t *)pma_buf;
    pma->maps = (uint32 *)(pma_buf + pool_size);
    marea_attach(name, pma_buf + pool_size + maps_size, (size_t)(pma_size - pool_size - maps_size),
                 PMA_PAGE_SIZE, &pma->marea);
}

static inline void pm_pool_add_page(pm_pool_t *pool, uint32 page_id)
{
    uint32 offset = page_id * VM_PAGES_PER_PPAGE;
    for (uint32 id = 0; id < VM_PAGES_PER_PPAGE; ++id) {
        cm_concat_page(pool->mpool.maps, &pool->mpool.free_pages, id + offset);
    }
    cm_concat_page(pool->mpool.area->maps, &pool->pages, page_id);
    pool->mpool.page_count += VM_PAGES_PER_PPAGE;
}

static inline bool32 pm_pool_extend(pm_pool_t *pool)
{
    uint32 page_id;

    if (pool->mpool.page_count >= pool->mpool.opt_count) {
        return GS_FALSE;
    }

    if (marea_alloc_page(pool->mpool.area, &page_id) != GS_SUCCESS) {
        cm_reset_error();
        return GS_FALSE;
    }

    pm_pool_add_page(pool, page_id);
    return GS_TRUE;
}

static inline void pm_pool_init(pma_t *pma, pm_pool_t *pool, uint32 page_id, uint64 max_size)
{
    MEMS_RETVOID_IFERR(memset_sp(pool, sizeof(pm_pool_t), 0, sizeof(pm_pool_t)));
    pool->mpool.area = &pma->marea;
    pool->mpool.buf = pma->marea.buf;
    pool->mpool.page_buf = pma->marea.page_buf;
    pool->mpool.page_size = GS_VMEM_PAGE_SIZE;
    pool->mpool.opt_count = (uint32)(max_size / GS_VMEM_PAGE_SIZE);
    pool->mpool.maps = pma->maps;
    pm_pool_add_page(pool, page_id);
}

static inline status_t pm_create_pool(pma_t *pma, uint64 max_size, pm_pool_t **pool)
{
    uint32 page_id = GS_INVALID_ID32;

    if (pma->marea.page_count == 0 || max_size == 0) {
        return GS_ERROR;
    }
    
    if (marea_alloc_page(&pma->marea, &page_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    pm_pool_init(pma, &pma->pool[page_id], page_id, max_size);

    (*pool) = &pma->pool[page_id];
    return GS_SUCCESS;
}

static inline void pm_release_pool(pm_pool_t *pool)
{
    if (pool != NULL && pool->pages.count > 0) {
        cm_spin_lock(&pool->mpool.area->lock, NULL);
        cm_concat_page_list(pool->mpool.area->maps, &pool->mpool.area->free_pages, &pool->pages);
        cm_reset_id_list(&pool->pages);
        cm_spin_unlock(&pool->mpool.area->lock);
    }
}

static inline status_t pm_alloc(pm_pool_t *pool, uint32 *id)
{
    if (pool->mpool.free_pages.count == 0 && !pm_pool_extend(pool)) {
        return GS_ERROR;
    }
    if (!mpool_try_alloc_page(&pool->mpool, id)) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static inline void pm_free(pm_pool_t *pool, uint32 id)
{
    mpool_free_page(&pool->mpool, id);
}

static inline status_t pm_open(pm_pool_t *pool, uint32 id, char **ptr)
{
    (*ptr) = mpool_page_addr(&pool->mpool, id);
    return GS_SUCCESS;
}

#ifdef __cplusplus
}
#endif
#endif
