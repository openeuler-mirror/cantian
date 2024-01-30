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
 * cm_vma.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_vma.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_VMA_H__
#define __CM_VMA_H__

#include "cm_memory.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_variant_memory_area {
    memory_area_t marea;
    memory_area_t large_marea;
}vma_t;

typedef struct st_variant_memory_pool {
    memory_pool_t mpool;
    memory_pool_t large_mpool;
}vmp_t;

typedef struct st_variant_mem {
    struct st_variant_mem *next;
    char   mem[0];
}variant_mem_t;

typedef struct st_variant_memory_context {
    memory_context_t mctx;
    memory_context_t large_mctx;
    variant_mem_t   *head;
    uint64 os_mem_size;
}vmc_t;

static inline void vmc_init(vmp_t *pool, vmc_t *context)
{
    mctx_init(&pool->mpool, &context->mctx);
    mctx_init(&pool->large_mpool, &context->large_mctx);
    context->head = NULL;
    context->os_mem_size = 0;
}

status_t vmc_alloc(void *owner, uint32 size, void **buf);

static inline status_t vmc_alloc_mem(void *owner, uint32 size, void **buf)
{
    CT_RETURN_IFERR(vmc_alloc(owner, size, buf));
    if (size != 0) {
        MEMS_RETURN_IFERR(memset_sp(*buf, (size_t)size, 0, (size_t)size));
    }
    return CT_SUCCESS;
}


static inline status_t vmc_reset_mem(memory_context_t *context)
{
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    if (CT_TRUE) {
#else
    if (g_vma_mem_check) {
#endif
        uint32 page_id;
        memory_pool_t *pool = context->pool;

        if (context->pages.count == 0) {
            return CT_SUCCESS;
        }

        for (page_id = context->pages.first; page_id != context->pages.last;) {
            MEMS_RETURN_IFERR(memset_s(mpool_page_addr(pool, page_id), pool->page_size, VMC_MAGIC, pool->page_size));
            page_id = pool->maps[page_id];
        }
        MEMS_RETURN_IFERR(memset_s(mpool_page_addr(pool, page_id), pool->page_size, VMC_MAGIC, pool->page_size));

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    }
#else
    }
#endif
    return CT_SUCCESS;
}

static inline void vmc_free(vmc_t *context)
{
    (void)vmc_reset_mem(&context->mctx);
    mctx_free(&context->mctx);
    (void)vmc_reset_mem(&context->large_mctx);
    mctx_free(&context->large_mctx);

    variant_mem_t *pmem = context->head;
    variant_mem_t *pmem_next = NULL;
    while (pmem != NULL) {
        pmem_next = pmem->next;
        free(pmem);
        pmem = pmem_next;
    }
    context->head = NULL;
    context->os_mem_size = 0;
}

static inline status_t vmp_create(vma_t *area, uint32 init_pages, vmp_t *pool)
{
    if (mpool_create(&area->marea, "variant memory pool", init_pages, area->marea.page_count, &pool->mpool) != CT_SUCCESS) {
        return CT_ERROR;
    }
    
    if (mpool_create(&area->large_marea, "large variant memory pool", 0,
                     area->large_marea.page_count, &pool->large_mpool) != CT_SUCCESS) {
        mpool_destory(&pool->mpool);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static inline void vmp_destory(vmp_t *pool)
{
    mpool_destory(&pool->mpool);
    mpool_destory(&pool->large_mpool);
}

static inline void vmp_free(vmp_t *pool, uint32 pool_caches)
{
    mpool_free(&pool->mpool, pool_caches);
    mpool_free(&pool->large_mpool, 0);
}

#ifdef __cplusplus
}
#endif

#endif
