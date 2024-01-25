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
 * cm_vma.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_vma.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_common_module.h"
#include "cm_vma.h"

static inline void vmc_check_mem(const void* buf, uint32 size)
{
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    if (CT_TRUE) {
#else
    if (g_vma_mem_check) {
#endif
        // memory value in vmc free pages should be 'V', set in:
        // 1. VMA create
        // 2. vmc_free
        for (uint32 i = 0; i < size; i++) {
            // may be write after vmc_free.
            CM_ASSERT(((char*)buf)[i] == VMC_MAGIC);
        }

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    }
#else
    }
#endif
}

status_t vmc_alloc(void *owner, uint32 size, void **buf)
{
    vmc_t *context = (vmc_t *)owner;
    if (mctx_try_alloc(&context->mctx, size, buf)) {
        vmc_check_mem(*buf, size);
        return CT_SUCCESS;
    }

    if (mctx_try_alloc(&context->large_mctx, size, buf)) {
        vmc_check_mem(*buf, size);
        return CT_SUCCESS;
    }

    CT_LOG_DEBUG_WAR("failed to malloc memory from VMA, only can malloc memroy from OS, memory size=%u", size);

    uint64 malloc_size = (uint64)size + sizeof(variant_mem_t);
    malloc_size = CM_ALIGN8(malloc_size);
    if (context->os_mem_size + malloc_size > CT_MAX_VMP_OS_MEM_SIZE) {
        CT_LOG_DEBUG_WAR("Too much OS memory has been allocated, memory size=%llu", context->os_mem_size);
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, malloc_size, "VMP(variant memory pool)");
        return CT_ERROR;
    }

    variant_mem_t *pmem = (variant_mem_t *)malloc(malloc_size);
    if (pmem == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, malloc_size, "VMA(variant memory area) from OS");
        return CT_ERROR;
    }
    context->os_mem_size += malloc_size;

    pmem->next = context->head;
    context->head = pmem;

    *buf = pmem->mem;
    return CT_SUCCESS;
}
