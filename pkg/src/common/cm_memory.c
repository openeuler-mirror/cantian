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
 * cm_memory.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_memory.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_common_module.h"
#include "cm_memory.h"
#include "cm_log.h"
#include "cm_atomic.h"

#ifndef WIN32
#include <execinfo.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif
uint32 g_vm_max_stack_count = 0;
bool32 g_vma_mem_check = CT_FALSE;
static const cpid_t g_invalid_cpid = { .pool_id = CT_INVALID_ID32, .cached_page_id = CT_INVALID_ID32 };
#define INVALID_CPID g_invalid_cpid
#define IS_INVALID_CPID(cpid) ((cpid).pool_id == CT_INVALID_ID32 || (cpid).cached_page_id == CT_INVALID_ID32)

#ifndef WIN32
static inline void vm_create_func_stack_core(vm_pool_t *pool, uint32 vmid)
{
    void *array[CT_MAX_BLACK_BOX_DEPTH] = { 0 };
    size_t size;
    char **stacks;
    size_t i;
    size = backtrace(array, CT_MAX_BLACK_BOX_DEPTH);
    stacks = backtrace_symbols(array, size);
    if (stacks == NULL) {
        return;
    }

    if (size <= CT_INIT_BLACK_BOX_DEPTH) {
        CM_FREE_PTR(stacks);
        return;
    }

    uint32 remain_size = CT_VM_FUNC_STACK_SIZE - 1;
    for (i = CT_INIT_BLACK_BOX_DEPTH; i < size; i++) {
        uint32 len = strlen(stacks[i]) + 2;
        if (len > remain_size) {
            break;
        }

        if (snprintf_s(pool->func_stacks[vmid]->stack + CT_VM_FUNC_STACK_SIZE - 1 - remain_size,
                       (size_t)(remain_size + 1), (size_t)len, "%s\r\n", stacks[i]) == -1) {
            break;
        }
        remain_size -= len;
    }

    CM_FREE_PTR(stacks);
}
#endif

static inline void vm_create_func_stack(vm_pool_t *pool, uint32 vmid)
{
    errno_t ret;

    if (g_vm_max_stack_count <= vmid) {
        return;
    }
    if (pool->func_stacks == NULL) {
        uint32 need_size = sizeof(vm_func_stack_t *) * g_vm_max_stack_count;
        if (need_size == 0 || need_size / g_vm_max_stack_count != sizeof(vm_func_stack_t *)) {
            CT_LOG_RUN_ERR("not enough memory");
            return;
        }
        pool->func_stacks = (vm_func_stack_t **)malloc(need_size);
        if (pool->func_stacks == NULL) {
            CT_LOG_RUN_ERR("not enough memory");
            return;
        }
        ret = memset_sp(pool->func_stacks, (size_t)need_size, 0, (size_t)need_size);
        if (ret != EOK) {
            CM_FREE_PTR(pool->func_stacks);
            CT_LOG_RUN_ERR("Secure C lib has thrown an error %d", ret);
            return;
        }
    }

    if (pool->func_stacks[vmid] == NULL) {
        pool->func_stacks[vmid] = (vm_func_stack_t *)malloc(sizeof(vm_func_stack_t));
        if (pool->func_stacks[vmid] == NULL) {
            CT_LOG_RUN_ERR("not enough memory");
            return;
        }
        ret = memset_sp(pool->func_stacks[vmid], sizeof(vm_func_stack_t), 0, sizeof(vm_func_stack_t));
        if (ret != EOK) {
            CM_FREE_PTR(pool->func_stacks[vmid]);
            CT_LOG_RUN_ERR("Secure C lib has thrown an error %d", ret);
            return;
        }

        pool->func_stacks[vmid]->ref_count = 0;
    }
    pool->func_stacks[vmid]->stack[0] = '\0';

#ifndef WIN32

    vm_create_func_stack_core(pool, vmid);
#endif
}


static inline bool32 vm_chk_funcstack_and_lock_pool(vm_pool_t *pool, uint32 vmid)
{
    if (g_vm_max_stack_count <= vmid) {
        return CT_FALSE;
    }
    if (pool->func_stacks == NULL || pool->func_stacks[vmid] == NULL) {
        return CT_FALSE;
    }
    cm_spin_lock(&pool->lock, NULL);
    if (pool->func_stacks == NULL || pool->func_stacks[vmid] == NULL) {
        cm_spin_unlock(&pool->lock);
        return CT_FALSE;
    }
    return CT_TRUE;
}

static inline void vm_drop_func_stack(vm_pool_t *pool, uint32 vmid)
{
    if (!vm_chk_funcstack_and_lock_pool(pool, vmid)) {
        return;
    }
    pool->func_stacks[vmid]->stack[0] = '\0';
    pool->func_stacks[vmid]->ref_count = 0;
    cm_spin_unlock(&pool->lock);
}

static inline void vm_dec_func_stack_ref(vm_pool_t *pool, uint32 vmid)
{
    if (!vm_chk_funcstack_and_lock_pool(pool, vmid)) {
        return;
    }
    pool->func_stacks[vmid]->ref_count--;
    cm_spin_unlock(&pool->lock);
}

static inline void vm_inc_func_stack_ref(vm_pool_t *pool, uint32 vmid)
{
    if (!vm_chk_funcstack_and_lock_pool(pool, vmid)) {
        return;
    }
    pool->func_stacks[vmid]->ref_count++;
    cm_spin_unlock(&pool->lock);
}

void test_memory_pool_maps(memory_pool_t *pool)
{
    uint32 prev, next;
    uint32 i = 0;

    if (pool->free_pages.count == 0) {
        return;
    }

    cm_spin_lock(&pool->lock, NULL);
    if (pool->free_pages.count == 0) {
        cm_spin_unlock(&pool->lock);
        return;
    }

    prev = pool->free_pages.first;
    for (i = 0; i < pool->free_pages.count - 1; i++) {
        next = pool->maps[prev];
        CM_ASSERT(next != CT_INVALID_ID32);
        prev = next;
    }
    CM_ASSERT(prev == pool->free_pages.last);

    CM_ASSERT(pool->maps[prev] == CT_INVALID_ID32);
    cm_spin_unlock(&pool->lock);
}

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
static void test_memory_area_maps(memory_area_t *area)
{
    uint32 prev, next;
    uint32 i = 0;

    if (area == NULL || area->free_pages.count == 0) {
        return;
    }

    cm_spin_lock(&area->lock, NULL);
    if (area->free_pages.count == 0) {
        cm_spin_unlock(&area->lock);
        return;
    }

    prev = area->free_pages.first;
    for (i = 0; i < area->free_pages.count - 1; i++) {
        next = area->maps[prev];
        CM_ASSERT(next != CT_INVALID_ID32);
        prev = next;
    }
    CM_ASSERT(prev == area->free_pages.last);

    CM_ASSERT(area->maps[prev] == CT_INVALID_ID32);
    cm_spin_unlock(&area->lock);
}
#endif  // DEBUG

void marea_attach(const char *name, char *buf, size_t size, uint32 page_size, memory_area_t *area)
{
    uint32 page_count = (uint32)(size / (page_size + sizeof(uint32)));
    uint32 len;

    CM_ASSERT(area != NULL);
    MEMS_RETVOID_IFERR(memset_sp(area, sizeof(memory_area_t), 0, sizeof(memory_area_t)));

    CT_INIT_SPIN_LOCK(area->lock);
    area->buf = buf;
    len = (uint32)strlen(name);
    CM_ASSERT(len < CT_NAME_BUFFER_SIZE);
    PRTS_RETVOID_IFERR(snprintf_s(area->name, CT_NAME_BUFFER_SIZE, (size_t)len, "%s", name));

    CT_RETVOID_IFTRUE(page_count == 0);

    area->offset = page_count * sizeof(uint32);
    area->maps = (uint32 *)area->buf;
    area->page_buf = buf + area->offset;
    area->size = (uint64)size;
    area->page_hwm = (uint32)0;
    area->page_size = page_size;
    area->page_count = page_count;

    area->free_pages.count = 0;
    area->free_pages.first = CT_INVALID_ID32;
    area->free_pages.last = CT_INVALID_ID32;

    for (uint32 i = 0; i < area->page_count - 1; i++) {
        area->maps[i] = i + 1;
    }

    area->maps[area->page_count - 1] = CT_INVALID_ID32;
}

status_t marea_create(const char *name, size_t size, uint32 page_size, memory_area_t *area)
{
    uint32 page_count = (uint32)(size / (page_size + sizeof(uint32)));
    size_t area_size = (size_t)page_count * (size_t)page_size;
    errno_t errcode;

    if (area_size == 0 || area_size / (size_t)page_size != page_count) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)0, name);
        return CT_ERROR;
    }

    char *buf = (char *)malloc(area_size);
    if (buf == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)area_size, name);
        return CT_ERROR;
    }

    errcode = memset_sp(buf, area_size, 0, area_size);
    if (errcode != EOK) {
        CM_FREE_PTR(buf);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CT_ERROR;
    }
    marea_attach(name, buf, area_size, page_size, area);
    area->is_alone = CT_TRUE;
    return CT_SUCCESS;
}

void marea_destroy(memory_area_t *area)
{
    if (area->is_alone) {
        CM_FREE_PTR(area->buf);
        area->is_alone = CT_FALSE;
    }

    MEMS_RETVOID_IFERR(memset_sp(area, sizeof(memory_area_t), 0, sizeof(memory_area_t)));
}

status_t marea_alloc_buf(memory_area_t *area, uint32 page_count, char **buf)
{
    uint64 size = (uint64)page_count * (uint64)area->page_size;

    if (area->offset + size > area->size) {
        CT_THROW_ERROR(ERR_ALLOC_GA_MEMORY, area->name);
        return CT_ERROR;
    }

    if (buf != NULL) {
        *buf = area->buf + area->offset;
    }

    area->offset += size;
    area->page_hwm += page_count;
    return CT_SUCCESS;
}

static bool32 marea_try_alloc_page(memory_area_t *area, uint32 *page_id)
{
    if (area->free_pages.count == 0 && area->page_hwm == area->page_count) {
        return CT_FALSE;
    }

    if (area->free_pages.count == 0) {
        *page_id = area->page_hwm;
        area->page_hwm++;
        return CT_TRUE;
    }

    *page_id = area->free_pages.first;
    area->free_pages.count--;
    area->free_pages.first = area->maps[*page_id];

    if (area->free_pages.count == 0) {
        area->free_pages.first = CT_INVALID_ID32;
        area->free_pages.last = CT_INVALID_ID32;
    }

    return CT_TRUE;
}

status_t marea_alloc_page(memory_area_t *area, uint32 *page_id)
{
    cm_spin_lock(&area->lock, NULL);

    if (!marea_try_alloc_page(area, page_id)) {
        cm_spin_unlock(&area->lock);
        CT_THROW_ERROR(ERR_ALLOC_GA_MEMORY, area->name);
        return CT_ERROR;
    }

    cm_spin_unlock(&area->lock);
    return CT_SUCCESS;
}

bool32 mpool_try_extend(memory_pool_t *pool, uint32 count, mem_extent_t *extent)
{
    uint32 i, page_id;
    memory_area_t *area = pool->area;

    extent->count = 0;
    if (area == NULL) {
        return CT_FALSE;
    }

    cm_spin_lock(&area->lock, NULL);

    for (i = 0; i < count; i++) {
        if (!marea_try_alloc_page(area, &page_id)) {
            break;
        }

        cm_concat_page(pool->maps, &pool->free_pages, page_id);
        extent->pages[i] = page_id;
        pool->page_count++;
    }

    extent->count = i;
    cm_spin_unlock(&area->lock);

    return (extent->count > 0);
}

status_t mpool_extend(memory_pool_t *pool, uint32 count, mem_extent_t *extent)
{
    if (!mpool_try_extend(pool, count, extent)) {
        CT_THROW_ERROR(ERR_ALLOC_GA_MEMORY, pool->name);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t mpool_create(memory_area_t *area, const char *name, uint32 page_count, uint32 opt_count,
                      memory_pool_t *pool)
{
    size_t len;

    CT_INIT_SPIN_LOCK(pool->lock);
    pool->area = area;
    pool->buf = area->buf;
    pool->page_buf = area->page_buf;

    len = (uint32)strlen(name);
    if (len >= CT_NAME_BUFFER_SIZE) {
        CT_THROW_ERROR(ERR_BUFFER_OVERFLOW, len, CT_NAME_BUFFER_SIZE - 1);
        return CT_ERROR;
    }
    PRTS_RETURN_IFERR(snprintf_s(pool->name, CT_NAME_BUFFER_SIZE, (size_t)len, "%s", name));

    pool->free_pages.count = page_count;
    pool->maps = area->maps;
    pool->page_count = page_count;
    pool->page_size = (uint32)area->page_size;
    pool->opt_count = opt_count;

    if (page_count == 0) {
        pool->free_pages.first = CT_INVALID_ID32;
        pool->free_pages.last = CT_INVALID_ID32;
    } else {
        cm_spin_lock(&area->lock, NULL);
        pool->free_pages.first = area->page_hwm;
        pool->free_pages.last = area->page_hwm + page_count - 1;
        area->maps[pool->free_pages.last] = CT_INVALID_ID32;
        if (marea_alloc_buf(area, page_count, NULL) != CT_SUCCESS) {
            cm_spin_unlock(&area->lock);
            return CT_ERROR;
        }
        cm_spin_unlock(&area->lock);
    }

    return CT_SUCCESS;
}

void mpool_attach(const char *name, char *buf, int64 buf_size, uint32 page_size, memory_pool_t *pool)
{
    uint32 i;
    size_t len;

    CM_ASSERT(pool != NULL);
    MEMS_RETVOID_IFERR(memset_sp(pool, sizeof(memory_pool_t), 0, sizeof(memory_pool_t)));
    len = (uint32)strlen(name);
    CM_ASSERT(len < CT_NAME_BUFFER_SIZE);
    PRTS_RETVOID_IFERR(snprintf_s(pool->name, CT_NAME_BUFFER_SIZE, (size_t)len, "%s", name));

    pool->area = NULL;
    pool->buf = buf;
    pool->maps = (uint32 *)buf;
    pool->page_size = page_size;
    pool->page_count = (uint32)((buf_size - CT_MAX_ALIGN_SIZE_4K) / (page_size + sizeof(uint32)));
    pool->page_buf = buf + CM_CALC_ALIGN((uint64)pool->page_count * (uint64)sizeof(uint32), CT_MAX_ALIGN_SIZE_4K);
    pool->free_pages.count = pool->page_count;
    pool->free_pages.first = 0;
    pool->free_pages.last = pool->page_count - 1;

    for (i = 0; i < pool->page_count - 1; i++) {
        pool->maps[i] = i + 1;
    }

    pool->maps[pool->page_count - 1] = CT_INVALID_ID32;
}

uint32 mpool_get_extend_page_count(uint32 opt_count, uint32 page_count)
{
    uint32 count;
    count = opt_count - page_count;
    count = (count > MEM_EXTENT_SIZE) ? MEM_EXTENT_SIZE : count;
    return count;
}

bool32 mpool_try_alloc_page(memory_pool_t *pool, uint32 *id)
{
    uint32 page_id;
    mem_extent_t extent;
    uint32 extend_page_count;

    cm_spin_lock(&pool->lock, NULL);
    if (pool->free_pages.count == 0) {
        if (pool->page_count >= pool->opt_count) {
            cm_spin_unlock(&pool->lock);
            return CT_FALSE;
        }

        extend_page_count = mpool_get_extend_page_count(pool->opt_count, pool->page_count);
        if (!mpool_try_extend(pool, extend_page_count, &extent)) {
            cm_spin_unlock(&pool->lock);
            return CT_FALSE;
        }
    }

    page_id = pool->free_pages.first;
    pool->free_pages.first = pool->maps[page_id];
    pool->free_pages.count--;

    if (pool->free_pages.count == 0) {
        pool->free_pages.first = CT_INVALID_ID32;
        pool->free_pages.last = CT_INVALID_ID32;
    }
    cm_spin_unlock(&pool->lock);

    *id = page_id;
    return CT_TRUE;
}

status_t mpool_alloc_page(memory_pool_t *pool, uint32 *id)
{
    if (!mpool_try_alloc_page(pool, id)) {
        CT_THROW_ERROR(ERR_ALLOC_GA_MEMORY, pool->name);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

// Attention: inout wait_ms should > 0, otherwise mpool_alloc_page is ok
status_t mpool_alloc_page_wait(memory_pool_t *pool, uint32 *page_id, uint32 wait_ms)
{
    uint32 remain_time = wait_ms;
    uint32 sleep_time = remain_time > CM_MPOOL_ALLOC_SLEEP_TIME ? CM_MPOOL_ALLOC_SLEEP_TIME : remain_time;
    while (!mpool_try_alloc_page(pool, page_id)) {
        cm_spin_sleep_and_stat2(sleep_time);
        if (wait_ms == CT_INVALID_ID32) {
            continue;
        }
        remain_time = remain_time > CM_MPOOL_ALLOC_SLEEP_TIME ? remain_time - CM_MPOOL_ALLOC_SLEEP_TIME : 0;
        if (remain_time == 0) {
            CT_LOG_RUN_WAR("[BUFFER] no large pool page available");
            CT_THROW_ERROR(ERR_ALLOC_GA_MEMORY, pool->name);
            return CT_ERROR;
        }
        sleep_time = remain_time > CM_MPOOL_ALLOC_SLEEP_TIME ? CM_MPOOL_ALLOC_SLEEP_TIME : remain_time;
    }
    return CT_SUCCESS;
}


void mpool_free_page(memory_pool_t *pool, uint32 id)
{
    cm_spin_lock(&pool->lock, NULL);
    cm_concat_page(pool->maps, &pool->free_pages, id);
    cm_spin_unlock(&pool->lock);
}

void mpool_free(memory_pool_t *pool, uint32 pool_caches)
{
    memory_area_t *area = pool->area;
    id_list_t extra_pages;

    if (pool->free_pages.count == 0) {
        return;
    }

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    test_memory_area_maps(area);
#endif  // DEBUG

    int64 area_free_pages = (int64)area->page_count + area->free_pages.count - area->page_hwm;
    if (pool_caches == 0 || area_free_pages < area->page_count * CT_VMA_LW_FACTOR) {
        pool->page_count -= pool->free_pages.count;
        cm_spin_lock(&area->lock, NULL);
        cm_concat_page_list(area->maps, &area->free_pages, &pool->free_pages);
        cm_spin_unlock(&area->lock);
        pool->free_pages.count = 0;
        pool->free_pages.first = CT_INVALID_ID32;
        pool->free_pages.last = CT_INVALID_ID32;
        return;
    }

    if (pool->free_pages.count <= pool_caches) {
        return;
    }

    extra_pages.count = pool->free_pages.count - pool_caches;
    extra_pages.first = pool->free_pages.first;
    for (uint32 i = 0; i < extra_pages.count; ++i) {
        extra_pages.last = pool->free_pages.first;
        pool->free_pages.first = area->maps[extra_pages.last];
    }
    pool->page_count -= extra_pages.count;
    pool->free_pages.count -= extra_pages.count;
    area->maps[extra_pages.last] = CT_INVALID_ID32;

    cm_spin_lock(&area->lock, NULL);
    cm_concat_page_list(area->maps, &area->free_pages, &extra_pages);
    cm_spin_unlock(&area->lock);

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    test_memory_area_maps(area);
#endif  // DEBUG
}

bool32 mctx_try_create(memory_pool_t *pool, memory_context_t **context)
{
    uint32 page_id;
    *context = NULL;

    if (!mpool_try_alloc_page(pool, &page_id)) {
        return CT_FALSE;
    }

    mctx_first_page(pool, context, page_id);

    return CT_TRUE;
}

status_t mctx_create(memory_pool_t *pool, memory_context_t **context)
{
    if (!mctx_try_create(pool, context)) {
        CT_THROW_ERROR(ERR_ALLOC_GA_MEMORY, pool->name);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void mctx_init(memory_pool_t *pool, memory_context_t *context)
{
    context->pool = pool;
    context->pages.count = 0;
    context->pages.first = CT_INVALID_ID32;
    context->pages.last = CT_INVALID_ID32;
    context->alloc_pos = pool->page_size;
    context->curr_page_addr = NULL;
    context->curr_page_id = CT_INVALID_ID32;
}

void mctx_destroy(memory_context_t *context)
{
    memory_pool_t *pool = context->pool;

    if (context->pages.count == 0) {
        return;
    }

    cm_spin_lock(&pool->lock, NULL);
    cm_concat_page_list(pool->maps, &pool->free_pages, &context->pages);
    context->pages.count = 0;
    cm_spin_unlock(&pool->lock);
}

bool32 mctx_try_extend(memory_context_t *context)
{
    uint32 page_id;

    if (!mpool_try_alloc_page(context->pool, &page_id)) {
        return CT_FALSE;
    }

    mctx_add_page(context, page_id);
    return CT_TRUE;
}

bool32 mctx_try_alloc_exhausted(memory_context_t *context, uint32 size, void **buf, uint32 *buf_size)
{
    uint32 align_size;
    memory_pool_t *pool = context->pool;

    if (context->alloc_pos == pool->page_size) {
        if (!mctx_try_extend(context)) {
            return CT_FALSE;
        }
    }

    align_size = CM_ALIGN8(size);
    if (context->alloc_pos + align_size > pool->page_size) {
        align_size = pool->page_size - context->alloc_pos;
    }

    *buf = context->curr_page_addr + context->alloc_pos;
    context->alloc_pos += align_size;
    *buf_size = align_size;
    return CT_TRUE;
}

status_t mctx_alloc_exhausted(memory_context_t *context, uint32 size, void **buf, uint32 *buf_size)
{
    if (!mctx_try_alloc_exhausted(context, size, buf, buf_size)) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, context->pool->name);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

bool32 mctx_try_alloc(memory_context_t *context, uint32 size, void **buf)
{
    uint32 align_size;
    memory_pool_t *pool = context->pool;

    align_size = CM_ALIGN8(size);
    if (align_size > pool->page_size) {
        return CT_FALSE;
    }

    if (context->alloc_pos + align_size > pool->page_size) {
        if (!mctx_try_extend(context)) {
            return CT_FALSE;
        }
    }

    *buf = context->curr_page_addr + context->alloc_pos;
    context->alloc_pos += align_size;
    return CT_TRUE;
}

status_t mctx_alloc(memory_context_t *context, uint32 size, void **buf)
{
    if (!mctx_try_alloc(context, size, buf)) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, context->pool->name);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t mctx_copy_text2str(memory_context_t *context, const text_t *src, char **dst)
{
    if (src->len == 0) {
        *dst = NULL;
        return CT_SUCCESS;
    }

    if (mctx_alloc(context, src->len + 1, (void **)dst) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return cm_text2str(src, *dst, src->len + 1);
}

status_t mctx_copy_text(memory_context_t *context, const text_t *src, text_t *dst)
{
    dst->len = src->len;
    if (dst->len == 0) {
        return CT_SUCCESS;
    }

    if (mctx_alloc(context, src->len, (void **)&dst->str) != CT_SUCCESS) {
        return CT_ERROR;
    }
    MEMS_RETURN_IFERR(memcpy_sp(dst->str, (size_t)dst->len, src->str, (size_t)src->len));

    return CT_SUCCESS;
}

status_t mctx_copy_name(memory_context_t *context, text_t *src, text_t *dst, bool32 upper_name)
{
    if (mctx_copy_text(context, (text_t *)src, (text_t *)dst) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (upper_name == CT_TRUE) {
        cm_text_upper(dst);
    }
    return CT_SUCCESS;
}

void vm_init_pool(vm_pool_t *pool, char *buf, int64 buf_size, const vm_swapper_t *swapper, vm_statis_t stat)
{
    vm_page_t *page = NULL;
    MEMS_RETVOID_IFERR(memset_sp(pool, sizeof(vm_pool_t), 0, sizeof(vm_pool_t)));

    pool->buffer = buf;
    pool->page_count = (uint32)((buf_size - CT_MAX_ALIGN_SIZE_4K) / (CT_VMEM_PAGE_SIZE + sizeof(vm_page_t)));
    /* page_buffer init must put above vm_get_page */
    pool->page_buffer = pool->buffer + CM_CALC_ALIGN(pool->page_count * (uint64)sizeof(vm_page_t),
                                                     CT_MAX_ALIGN_SIZE_4K);
    MEMS_RETVOID_IFERR(memset_sp(pool->map_pages, CT_MAX_VMEM_MAP_PAGES * sizeof(uint32), 0xFF,
                                 CT_MAX_VMEM_MAP_PAGES * sizeof(uint32)));
    pool->map_count = 1;
    pool->map_pages[0].pool_id = pool->pool_id;
    pool->map_pages[0].cached_page_id = 0;
    page = vm_get_page(pool, 0);
    MEMS_RETVOID_IFERR(memset_sp(page->data, CT_VMEM_PAGE_SIZE, 0, CT_VMEM_PAGE_SIZE));

    pool->ctrl_count = VM_CTRLS_PER_PAGE;
    pool->page_hwm = 1;
    pool->swapper = *swapper;
    pool->free_ctrls.first = CT_INVALID_ID32;
    pool->free_ctrls.last = CT_INVALID_ID32;
    pool->free_pages.first = CT_INVALID_ID32;
    pool->free_pages.last = CT_INVALID_ID32;
    pool->get_swap_extents = 0;
    pool->swap_count = 0;
    pool->max_swap_count = 0;
    pool->vm_stat = stat;
    pool->extending_ctrls = CT_FALSE;
}

void mctx_concat_page(memory_context_t *context, uint32 page_id, uint32 alloc_pos)
{
    mctx_add_page(context, page_id);
    context->alloc_pos = alloc_pos;
}

static inline void vm_init_ctrl(vm_ctrl_t *ctrl)
{
    ctrl->cpid = INVALID_CPID;
    ctrl->swid = CT_INVALID_ID64;
    ctrl->cipher_len = 0;
    ctrl->prev = CT_INVALID_ID32;
    ctrl->next = CT_INVALID_ID32;
    ctrl->sort_next = CT_INVALID_ID32;
    ctrl->free = CT_FALSE;
    ctrl->closed = CT_TRUE;
    ctrl->swapping = CT_FALSE;
    ctrl->lock = 0;
}

static inline void vm_remove_page_list_head(vm_pool_t *pool, id_list_t *list, vm_page_t *page)
{
    vm_page_t *next_page = NULL;
    list->first = page->next.cached_page_id;
    list->count--;

    if (list->count == 0) {
        list->first = CT_INVALID_ID32;
        list->last = CT_INVALID_ID32;
    } else {
        next_page = vm_get_page_head(pool, list->first);
        next_page->prev.cached_page_id = CT_INVALID_ID32;
    }

    page->next.cached_page_id = CT_INVALID_ID32;
    page->prev.cached_page_id = CT_INVALID_ID32;
}

static inline void vm_remove_page_from_list(vm_pool_t *pool, vm_list_t *list, vm_page_t *page)
{
    vm_page_t *next_page = NULL;
    vm_page_t *prev_page = NULL;
    list->count--;

    if (list->count == 0) {
        list->first = INVALID_CPID;
        list->last = INVALID_CPID;
    } else {
        if (page->next.cached_page_id != CT_INVALID_ID32) {
            next_page = vm_get_cpid_page_head(pool, page->next);
            next_page->prev = page->prev;
        } else {
            list->last = page->prev;
        }
        
        if (page->prev.cached_page_id != CT_INVALID_ID32) {
            prev_page = vm_get_cpid_page_head(pool, page->prev);
            prev_page->next = page->next;
        } else {
            list->first = page->next;
        }
    }

    page->next = INVALID_CPID;
    page->prev = INVALID_CPID;
}

static inline void vm_alloc_free_page(handle_t session, vm_pool_t *pool, uint32 *id)
{
    vm_page_t *page = NULL;
    id_list_t *list = &pool->free_pages;

    CM_ASSERT(list->count != 0);
    *id = list->first;
    page = vm_get_page_head(pool, *id);
    vm_remove_page_list_head(pool, list, page);
    UNPROTECT_PAGE(page);
}

static inline void vm_enque_closed_page(handle_t session, vm_pool_t *pool, cpid_t id, vm_enque_mode_t mode)
{
    vm_page_t *first = NULL;
    vm_page_t *last = NULL;

    vm_page_t *page = vm_get_cpid_page_head(pool, id);
    CM_ASSERT(page->next.cached_page_id == CT_INVALID_ID32 && page->prev.cached_page_id == CT_INVALID_ID32);
    vm_page_pool_t *page_pool = &pool->close_page_pools[id.cached_page_id % CT_VM_CLOSE_PAGE_LIST_CNT];

    cm_spin_lock(&page_pool->lock, NULL);
    if (page_pool->pages.count == 0) {
        page->prev = INVALID_CPID;
        page->next = INVALID_CPID;
        page_pool->pages.first = id;
        page_pool->pages.last = id;
        page_pool->pages.count = 1;
    } else {
        if (mode == VM_ENQUE_HEAD) {
            first = vm_get_cpid_page_head(pool, page_pool->pages.first);
            first->prev = id;
            page->next = page_pool->pages.first;
            page->prev = INVALID_CPID;
            page_pool->pages.first = id;
        } else {
            last = vm_get_cpid_page_head(pool, page_pool->pages.last);
            last->next = id;
            page->prev = page_pool->pages.last;
            page->next = INVALID_CPID;
            page_pool->pages.last = id;
        }

        page_pool->pages.count++;
    }
    PROTECT_PAGE(vm_get_act_pool(pool, id.pool_id), page, id.cached_page_id);
    cm_spin_unlock(&page_pool->lock);
}

static inline void vm_deque_closed_page(handle_t session, vm_pool_t *pool, cpid_t id)
{
    vm_page_t *next = NULL;
    vm_page_t *prev = NULL;

    vm_page_t *page = vm_get_cpid_page_head(pool, id);
    vm_page_pool_t *page_pool = &pool->close_page_pools[id.cached_page_id % CT_VM_CLOSE_PAGE_LIST_CNT];

    cm_spin_lock(&page_pool->lock, NULL);
    CM_ASSERT((page_pool->pages.count == 1) || !IS_INVALID_CPID(page->next) || !IS_INVALID_CPID(page->prev));
    if (page->next.cached_page_id != CT_INVALID_ID32) {
        next = vm_get_cpid_page_head(pool, page->next);
        next->prev = page->prev;
    } else {
        page_pool->pages.last = page->prev;
    }

    if (page->prev.cached_page_id != CT_INVALID_ID32) {
        prev = vm_get_cpid_page_head(pool, page->prev);
        prev->next = page->next;
    } else {
        page_pool->pages.first = page->next;
    }

    CM_ASSERT(page_pool->pages.count > 0);
    page_pool->pages.count--;
    if (page_pool->pages.count == 0) {
        page_pool->pages.first = INVALID_CPID;
        page_pool->pages.last = INVALID_CPID;
    }
    page->next.cached_page_id = CT_INVALID_ID32;
    page->prev.cached_page_id = CT_INVALID_ID32;
    cm_spin_unlock(&page_pool->lock);
}

static status_t vm_alloc_from_close_page_pool(handle_t session, vm_pool_t *pool, vm_page_pool_t *page_pool, cpid_t *id)
{
    vm_page_t *page = NULL;
    vm_ctrl_t *ctrl = NULL;
    cpid_t page_id;
    vm_list_t *list = &page_pool->pages;

    for (page_id = list->first;; page_id = page->next) {
        page = vm_get_cpid_page_head(pool, page_id);
        ctrl = vm_get_ctrl(pool, page->vmid);
        if (!cm_spin_try_lock(&ctrl->lock)) {
            // ctrl is opened by vm_open, so try next close-page.
            if (page_id.pool_id == list->last.pool_id && page_id.cached_page_id == list->last.cached_page_id) {
                return CT_ERROR;
            }
            continue;
        }
        // ctrl is closed.
        if (ctrl->ref_num == 0) {
            CM_ASSERT(ctrl->cpid.cached_page_id != CT_INVALID_ID32);
            CM_ASSERT(ctrl->swid == CT_INVALID_ID64);
            CM_ASSERT(ctrl->cipher_len == 0);

            // 1. remove close-page linked with ctrl from list.
            vm_remove_page_from_list(pool, list, page);
            ctrl->cpid = INVALID_CPID;

            // 2. set ctrl swapping.
            ctrl->swapping = CT_TRUE;
            cm_spin_unlock(&ctrl->lock);

            (void)cm_atomic32_inc((atomic32_t *)&pool->swap_count);
            pool->max_swap_count = MAX(pool->swap_count, pool->max_swap_count);

            *id = page_id;
            return CT_SUCCESS;
        }
        cm_spin_unlock(&ctrl->lock);

        if (page_id.pool_id == list->last.pool_id && page_id.cached_page_id == list->last.cached_page_id) {
            return CT_ERROR;
        }
    }
}

static status_t vm_alloc_close_page(handle_t session, vm_pool_t *pool, cpid_t *id)
{
    vm_page_t *page = NULL;
    vm_ctrl_t *ctrl = NULL;
    vm_page_pool_t *page_pool = NULL;
    uint32 pool_idx = pool->close_pool_idx;

    // loop all close page-pool, find closed ctrl to do close-page recycle
    for (uint32 i = 0; i < CT_VM_CLOSE_PAGE_LIST_CNT; i++) {
        page_pool = &pool->close_page_pools[(pool_idx + i) % CT_VM_CLOSE_PAGE_LIST_CNT];
        (void)cm_atomic32_inc((atomic32_t *)&pool->close_pool_idx);
        if (page_pool->pages.count > 0) {
            cm_spin_lock(&page_pool->lock, NULL);
            if (page_pool->pages.count > 0) {
                if (vm_alloc_from_close_page_pool(session, pool, page_pool, id) == CT_SUCCESS) {
                    cm_spin_unlock(&page_pool->lock);

                    // do ctrl linked close-page swap out
                    page = vm_get_cpid_page(pool, *id);
                    ctrl = vm_get_ctrl(pool, page->vmid);
                    UNPROTECT_PAGE(page);
                    if (pool->swapper.out(session, page, &ctrl->swid, &ctrl->cipher_len) != CT_SUCCESS) {
                        (void)cm_atomic32_dec((atomic32_t *)&pool->swap_count);
                        vm_enque_closed_page(session, pool, *id, VM_ENQUE_HEAD);
                        ctrl->cpid = *id;
                        ctrl->swapping = CT_FALSE;
                        return CT_ERROR;
                    }
                    ctrl->swapping = CT_FALSE;
                    pool->vm_stat(session, VM_STAT_SWAP_OUT);
                    return CT_SUCCESS;
                }
            }
            cm_spin_unlock(&page_pool->lock);
        }
    }

    return CT_ERROR;
}

static bool32 vm_find_free_pages(handle_t session, vm_pool_t *pool, cpid_t *id)
{
    vm_pool_t *other_pool = NULL;
    uint32 loop = pool->pool_id + 1;
    if (pool->pool_hwm == 1) {
        return CT_FALSE;
    }

    while ((loop % pool->pool_hwm) != pool->pool_id) {
        other_pool = &pool->temp_pools[loop % pool->pool_hwm];
        if (other_pool->free_pages.count < 1 && other_pool->page_hwm == other_pool->page_count) {
            loop++;
            continue;
        }
        cm_spin_lock(&other_pool->lock, NULL);
        if (other_pool->page_hwm < other_pool->page_count) {
            (*id).cached_page_id = other_pool->page_hwm;
            (*id).pool_id = other_pool->pool_id;
            other_pool->page_hwm++;
            cm_spin_unlock(&other_pool->lock);
            return CT_TRUE;
        }
        
        if (other_pool->free_pages.count > 0) {
            (*id).pool_id = other_pool->pool_id;
            vm_alloc_free_page(session, other_pool, &id->cached_page_id);
            cm_spin_unlock(&other_pool->lock);
            return CT_TRUE;
        }
        cm_spin_unlock(&other_pool->lock);
        loop++;
    }
    return CT_FALSE;
}

static status_t vm_alloc_page(handle_t session, vm_pool_t *pool, cpid_t *id)
{
    cm_spin_lock(&pool->lock, NULL);
    if (pool->page_hwm < pool->page_count) {
        (*id).pool_id = pool->pool_id;
        (*id).cached_page_id = pool->page_hwm;
        pool->page_hwm++;
        cm_spin_unlock(&pool->lock);
        return CT_SUCCESS;
    }

    if (pool->free_pages.count > 0) {
        (*id).pool_id = pool->pool_id;
        vm_alloc_free_page(session, pool, &id->cached_page_id);
        cm_spin_unlock(&pool->lock);
        return CT_SUCCESS;
    }
    cm_spin_unlock(&pool->lock);

    if (vm_find_free_pages(session, pool, id)) {
        return CT_SUCCESS;
    }

    if (vm_alloc_close_page(session, pool, id) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_NO_FREE_VMEM, "can not alloc page from close pages");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static inline status_t vm_extend_ctrls(handle_t session, vm_pool_t *pool)
{
    uint32     map_id;
    vm_page_t *page = NULL;

    cm_spin_lock(&pool->lock, NULL);
    if (pool->extending_ctrls) {
        cm_spin_unlock(&pool->lock);
        cm_sleep(1);
        return CT_SUCCESS;
    }
    if (pool->ctrl_hwm != pool->ctrl_count) {
        cm_spin_unlock(&pool->lock);
        return CT_SUCCESS;
    }
    if (pool->map_count + VM_MIN_CACHE_PAGES >= pool->page_count) {
        CT_THROW_ERROR(ERR_NO_FREE_VMEM, "no free buffer for materialized result set");
        cm_spin_unlock(&pool->lock);
        return CT_ERROR;
    }
    pool->extending_ctrls = CT_TRUE;
    cm_spin_unlock(&pool->lock);

    map_id = pool->ctrl_hwm / VM_CTRLS_PER_PAGE;
    if (vm_alloc_page(session, pool, &pool->map_pages[map_id]) != CT_SUCCESS) {
        return CT_ERROR;
    }
    page = vm_get_cpid_page(pool, pool->map_pages[map_id]);
    MEMS_RETURN_IFERR(memset_sp(page->data, CT_VMEM_PAGE_SIZE, 0, CT_VMEM_PAGE_SIZE));
    pool->ctrl_count += VM_CTRLS_PER_PAGE;
    pool->map_count++;
    CM_MFENCE;
    pool->extending_ctrls = CT_FALSE;
    return CT_SUCCESS;
}

uint32 vm_close_page_cnt(const vm_pool_t *pool)
{
    uint32 cnt = 0;
    for (uint32 i = 0; i < CT_VM_CLOSE_PAGE_LIST_CNT;i++) {
        cnt += pool->close_page_pools[i].pages.count;
    }
    return cnt;
}

static inline vm_ctrl_t *vm_alloc_from_free_ctrls(vm_pool_t *pool, uint32 *id)
{
    vm_ctrl_t *ctrl = NULL;

    *id = pool->free_ctrls.first;
    ctrl = vm_get_ctrl(pool, pool->free_ctrls.first);
    pool->free_ctrls.first = ctrl->next;
    pool->free_ctrls.count--;
    if (pool->free_ctrls.count == 0) {
        pool->free_ctrls.last = CT_INVALID_ID32;
    }
    
    vm_create_func_stack(pool, *id);
    return ctrl;
}

status_t vm_alloc(handle_t session, vm_pool_t *pool, uint32 *id)
{
    vm_ctrl_t *ctrl = NULL;

    if (pool->get_swap_extents == 0) {
        pool->get_swap_extents = pool->swapper.get_swap_extents(session);
    }

    cm_spin_lock(&pool->lock, NULL);
    if (pool->free_ctrls.count > 0) {
        ctrl = vm_alloc_from_free_ctrls(pool, id);
        cm_spin_unlock(&pool->lock);
        CM_ASSERT(ctrl->free);
        vm_init_ctrl(ctrl);
        pool->vm_stat(session, VM_STAT_ALLOC);
        return CT_SUCCESS;
    }

    if (pool->ctrl_hwm >= VM_MAX_CTRLS) {
        cm_spin_unlock(&pool->lock);
        CT_THROW_ERROR(ERR_NO_FREE_VMEM, "can't allocate page from virtual memory pool");
        return CT_ERROR;
    }

    if (pool->page_hwm == pool->page_count && pool->free_pages.count == 0 &&
        pool->get_swap_extents != CT_INVALID_ID32 &&
        pool->swap_count + RESERVED_SWAP_EXTENTS >= pool->get_swap_extents) {
        cm_spin_unlock(&pool->lock);
        CT_THROW_ERROR(ERR_NO_FREE_VMEM,
                       "no enough temporary tablespace, used + RESERVED >= temporary tablespace extents");
        return CT_ERROR;
    }

    if (pool->page_hwm == pool->page_count &&
        pool->free_pages.count + vm_close_page_cnt(pool) < RESERVED_SWAP_EXTENTS) {
        cm_spin_unlock(&pool->lock);
        CT_THROW_ERROR(ERR_NO_FREE_VMEM, "no available temporary buffer page");
        return CT_ERROR;
    }

    for (;;) {
        if (SECUREC_UNLIKELY(pool->ctrl_hwm == pool->ctrl_count)) {
            cm_spin_unlock(&pool->lock);
            if (vm_extend_ctrls(session, pool) != CT_SUCCESS) {
                return CT_ERROR;
            }
            cm_spin_lock(&pool->lock, NULL);
            continue;
        }
        break;
    }

    ctrl = vm_get_ctrl(pool, pool->ctrl_hwm);
    vm_init_ctrl(ctrl);
    *id = pool->ctrl_hwm;
    pool->ctrl_hwm++;
    vm_create_func_stack(pool, *id);
    cm_spin_unlock(&pool->lock);
    pool->vm_stat(session, VM_STAT_ALLOC);
    return CT_SUCCESS;
}

void vm_append(vm_pool_t *pool, id_list_t *list, uint32 id)
{
    vm_ctrl_t *last_ctrl = NULL;

    vm_ctrl_t *ctrl = vm_get_ctrl(pool, id);
    ctrl->prev = CT_INVALID_ID32;
    ctrl->next = CT_INVALID_ID32;

    if (list->count == 0) {
        list->first = id;
        list->last = id;
        list->count = 1;
    } else {
        ctrl->prev = list->last;
        last_ctrl = vm_get_ctrl(pool, list->last);
        last_ctrl->next = id;
        list->last = id;
        list->count++;
    }
}

void vm_append_list(vm_pool_t *pool, id_list_t *list, const id_list_t *src_list)
{
    vm_ctrl_t *ctrl = NULL;
    vm_ctrl_t *last_ctrl = NULL;

    if (list->count == 0) {
        *list = *src_list;
        return;
    }

    if (src_list->count == 0) {
        return;
    }

    last_ctrl = vm_get_ctrl(pool, list->last);
    ctrl = vm_get_ctrl(pool, src_list->first);

    ctrl->prev = list->last;
    last_ctrl->next = src_list->first;
    list->last = src_list->last;
    list->count += src_list->count;
}


void vm_remove(vm_pool_t *pool, id_list_t *list, uint32 id)
{
    vm_ctrl_t *prev_ctrl = NULL;
    vm_ctrl_t *next_ctrl = NULL;

    vm_ctrl_t *ctrl = vm_get_ctrl(pool, id);

    if (ctrl->prev != CT_INVALID_ID32) {
        prev_ctrl = vm_get_ctrl(pool, ctrl->prev);
        prev_ctrl->next = ctrl->next;
    } else {
        list->first = ctrl->next;
    }

    if (ctrl->next != CT_INVALID_ID32) {
        next_ctrl = vm_get_ctrl(pool, ctrl->next);
        next_ctrl->prev = ctrl->prev;
    } else {
        list->last = ctrl->prev;
    }

    list->count--;
}

status_t vm_alloc_and_append(handle_t session, vm_pool_t *pool, id_list_t *list)
{
    uint32 id = 0;

    if (vm_alloc(session, pool, &id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    vm_append(pool, list, id);

    return CT_SUCCESS;
}

static inline void vm_free_page(handle_t session, vm_pool_t *pool, uint32 id, vm_enque_mode_t mode)
{
    vm_page_t *first = NULL;
    vm_page_t *last = NULL;

    vm_page_t *page = vm_get_page_head(pool, id);
    if (pool->free_pages.count == 0) {
        page->prev = INVALID_CPID;
        page->next = INVALID_CPID;
        pool->free_pages.first = id;
        pool->free_pages.last = id;
        pool->free_pages.count = 1;
    } else {
        if (mode == VM_ENQUE_HEAD) {
            first = vm_get_page_head(pool, pool->free_pages.first);
            first->prev.cached_page_id = id;
            page->next.cached_page_id = pool->free_pages.first;
            page->prev.cached_page_id = CT_INVALID_ID32;
            pool->free_pages.first = id;
        } else {
            last = vm_get_page_head(pool, pool->free_pages.last);
            last->next.cached_page_id = id;
            page->prev.cached_page_id = pool->free_pages.last;
            page->next.cached_page_id = CT_INVALID_ID32;
            pool->free_pages.last = id;
        }
        pool->free_pages.count++;
        CM_ASSERT(pool->free_pages.last != pool->free_pages.first);
    }
    PROTECT_PAGE(pool, page, id);
}

static inline void vm_free_cpid_page(handle_t session, vm_pool_t *pool, vm_ctrl_t *ctrl, vm_enque_mode_t mode)
{
    vm_pool_t *act_pool = vm_get_act_pool(pool, ctrl->cpid.pool_id);
    cm_spin_lock(&act_pool->lock, NULL);
    vm_free_page(session, act_pool, ctrl->cpid.cached_page_id, mode);
    ctrl->cpid = INVALID_CPID;
    cm_spin_unlock(&act_pool->lock);
}

static inline void vm_free_ctrl(vm_pool_t *pool, uint32 id)
{
    vm_ctrl_t *ctrl = vm_get_ctrl(pool, id);

    cm_spin_lock(&pool->lock, NULL);
    ctrl->next = pool->free_ctrls.first;

    pool->free_ctrls.first = id;
    if (pool->free_ctrls.count == 0) {
        pool->free_ctrls.last = id;
    }

    pool->free_ctrls.count++;
    cm_spin_unlock(&pool->lock);
}

static inline void vm_lock_ctrl(vm_ctrl_t *ctrl)
{
    // when the assigned page is being swapping out
    // wait until it is swapped, in case loss the data in cache
    for (;;) {
        if (!ctrl->swapping) {
            cm_spin_lock(&ctrl->lock, NULL);
            if (!ctrl->swapping) {
                break;
            }
            cm_spin_unlock(&ctrl->lock);
        }
        cm_sleep(1);
    }
}

void vm_free(handle_t session, vm_pool_t *pool, uint32 id)
{
    vm_ctrl_t *ctrl = vm_get_ctrl(pool, id);
    CM_ASSERT(!ctrl->free);

    vm_drop_func_stack(pool, id);

    vm_lock_ctrl(ctrl);

    CM_ASSERT(!ctrl->free);
    ctrl->free = CT_TRUE;
    if (ctrl->swid != CT_INVALID_ID64) {
        CM_ASSERT(IS_INVALID_CPID(ctrl->cpid));
        cm_spin_unlock(&ctrl->lock);

        pool->swapper.clean(session, ctrl->swid);
        (void)cm_atomic32_dec((atomic32_t *)&pool->swap_count);
        vm_lock_ctrl(ctrl);
    } else if (!IS_INVALID_CPID(ctrl->cpid)) {
        if (ctrl->closed) {
            // set ctrl ref_num, vm_alloc_close_page can not deque linked close-page
            ctrl->ref_num = 1;
        }
        cm_spin_unlock(&ctrl->lock);
        // if ctrl is closed, do close-page deque.
        if (ctrl->closed) {
            vm_deque_closed_page(session, pool, ctrl->cpid);
        } else {
            pool->vm_stat(session, VM_STAT_CLOSE);
        }

        vm_free_cpid_page(session, pool, ctrl, VM_ENQUE_HEAD);
        vm_lock_ctrl(ctrl);
    }

    ctrl->cpid = INVALID_CPID;
    ctrl->swid = CT_INVALID_ID64;
    ctrl->cipher_len = 0;
    ctrl->ref_num = 0;
    cm_spin_unlock(&ctrl->lock);
    vm_free_ctrl(pool, id);
    pool->vm_stat(session, VM_STAT_FREE);
}

void vm_free_list(handle_t session, vm_pool_t *pool, id_list_t *list)
{
    uint32 id, next;
    vm_ctrl_t *ctrl = NULL;

    if (list->count == 0) {
        return;
    }

    id = list->first;
    while (id != CT_INVALID_ID32) {
        ctrl = vm_get_ctrl(pool, id);
        next = ctrl->next;
        vm_free(session, pool, id);
        id = next;
    }

    list->count = 0;
}

status_t vm_open(handle_t session, vm_pool_t *pool, uint32 id, vm_page_t **page)
{
    vm_ctrl_t *ctrl = vm_get_ctrl(pool, id);
    pool->vm_stat(session, VM_STAT_BEGIN);
    vm_lock_ctrl(ctrl);
    if (SECUREC_UNLIKELY(ctrl->free)) {
        cm_spin_unlock(&ctrl->lock);
        pool->vm_stat(session, VM_STAT_END);
        CT_THROW_ERROR_EX(ERR_VM, "vm page is already free, vmid: %u", id);
        return CT_ERROR;
    }

    vm_inc_func_stack_ref(pool, id);
    if (ctrl->ref_num != 0) {
        *page = vm_get_cpid_page(pool, ctrl->cpid);
        ctrl->ref_num++;
        CM_ASSERT(ctrl->ref_num > 0);
        CM_ASSERT((*page)->vmid == id);
        cm_spin_unlock(&ctrl->lock);
        pool->vm_stat(session, VM_STAT_END);
        return CT_SUCCESS;
    }

    if (!IS_INVALID_CPID(ctrl->cpid)) {
        CM_ASSERT(ctrl->swid == CT_INVALID_ID64);
        CM_ASSERT(ctrl->cipher_len == 0);
        CM_ASSERT(ctrl->closed);
        CM_ASSERT(ctrl->ref_num == 0);
        *page = vm_get_cpid_page(pool, ctrl->cpid);
        UNPROTECT_PAGE(*page);
        ctrl->ref_num = 1;
        ctrl->closed = CT_FALSE;
        cm_spin_unlock(&ctrl->lock);
        vm_deque_closed_page(session, pool, ctrl->cpid);
        CM_ASSERT((*page)->vmid == id);
        pool->vm_stat(session, VM_STAT_OPEN);
        pool->vm_stat(session, VM_STAT_END);
        return CT_SUCCESS;
    }

    // allocate one cached page
    if (vm_alloc_page(session, pool, &ctrl->cpid) != CT_SUCCESS) {
        ctrl->cpid = INVALID_CPID;
        cm_spin_unlock(&ctrl->lock);
        pool->vm_stat(session, VM_STAT_END);
        return CT_ERROR;
    }

    // now vm is opened
    *page = vm_get_cpid_page(pool, ctrl->cpid);
    // IF PAGE GET FAILED
    if (SECUREC_UNLIKELY(*page == NULL)) {
        cm_spin_unlock(&ctrl->lock);
        pool->vm_stat(session, VM_STAT_END);
        CT_THROW_ERROR(ERR_VM, "fail to get vm page.");
        return CT_ERROR;
    }

    (*page)->vmid = id;
    (*page)->next.cached_page_id = CT_INVALID_ID32;
    (*page)->prev.cached_page_id = CT_INVALID_ID32;
    if (ctrl->swid != CT_INVALID_ID64) {
        if (pool->swapper.in(session, ctrl->swid, ctrl->cipher_len, *page) != CT_SUCCESS) {
            cm_spin_unlock(&ctrl->lock);
            vm_free_cpid_page(session, pool, ctrl, VM_ENQUE_HEAD);
            pool->vm_stat(session, VM_STAT_END);
            return CT_ERROR;
        }
        (void)cm_atomic32_dec((atomic32_t *)&pool->swap_count);
        pool->vm_stat(session, VM_STAT_SWAP_IN);
    }

    ctrl->ref_num = 1;
    ctrl->closed = CT_FALSE;
    ctrl->swid = CT_INVALID_ID64;
    ctrl->cipher_len = 0;

    /*
     * ctrl unlock must be after swap in, in case of repeat swap the same swid which caused by some one wrongly
     * repeat vm free, causing one ctrl held by more one session!
     */
    cm_spin_unlock(&ctrl->lock);

    CM_ASSERT((*page)->vmid == id);
    pool->vm_stat(session, VM_STAT_OPEN);
    pool->vm_stat(session, VM_STAT_END);
    return CT_SUCCESS;
}

void vm_close_and_free(handle_t session, vm_pool_t *pool, uint32 id)
{
    vm_ctrl_t *ctrl = vm_get_ctrl(pool, id);
    /* make sure current ctrl is not closed */
    CM_ASSERT(ctrl->ref_num >= 1);

    vm_dec_func_stack_ref(pool, id);

    // an page can not owned by two different user, so race control not needed
    if (ctrl->ref_num > 1) {
        ctrl->ref_num--;
        return;
    }
    vm_drop_func_stack(pool, id);
    CM_ASSERT(ctrl->cpid.cached_page_id != CT_INVALID_ID32);
    vm_free_cpid_page(session, pool, ctrl, VM_ENQUE_HEAD);
    // ctrl data-page do not in close-pages, no need to do ctrl-lock.
    vm_lock_ctrl(ctrl);
    ctrl->ref_num = 0;
    ctrl->swid = CT_INVALID_ID64;
    ctrl->cipher_len = 0;
    ctrl->closed = CT_TRUE;
    ctrl->free = CT_TRUE;
    cm_spin_unlock(&ctrl->lock);
    vm_free_ctrl(pool, id);
    pool->vm_stat(session, VM_STAT_CLOSE);
    pool->vm_stat(session, VM_STAT_FREE);
}

void vm_close(handle_t session, vm_pool_t *pool, uint32 id, vm_enque_mode_t mode)
{
    vm_ctrl_t *ctrl = vm_get_ctrl(pool, id);
    
    vm_dec_func_stack_ref(pool, id);
    vm_lock_ctrl(ctrl);
    // an page can not owned by two different user, so race control not needed
    if (ctrl->ref_num > 1) {
        ctrl->ref_num--;
        cm_spin_unlock(&ctrl->lock);
        return;
    }

    CM_ASSERT(!ctrl->closed);
    CM_ASSERT(!IS_INVALID_CPID(ctrl->cpid));
    CM_ASSERT(ctrl->swid == CT_INVALID_ID64);
    CM_ASSERT(ctrl->cipher_len == 0);
    CM_ASSERT(ctrl->ref_num == 1);
    ctrl->ref_num--;
    vm_enque_closed_page(session, pool, ctrl->cpid, mode);
    ctrl->closed = CT_TRUE;
    cm_spin_unlock(&ctrl->lock);
    pool->vm_stat(session, VM_STAT_CLOSE);
}

void *cm_realloc(void *ptr, size_t old_len, size_t new_len)
{
    if (new_len == 0 || new_len <= old_len) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)new_len, "reallocating memory");
        return NULL;
    }
    if (ptr == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)new_len, "reallocating memory");
        return NULL;
    }
    void *new_ptr = (void *)malloc(new_len);
    if (new_ptr == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)new_len, "reallocating memory");
        return NULL;
    }
    errno_t errcode = memcpy_sp(new_ptr, new_len, ptr, old_len);
    if (errcode != EOK) {
        CM_FREE_PTR(new_ptr);
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)new_len, "reallocating memory");
        return NULL;
    }
    CM_FREE_PTR(ptr);
    return new_ptr;
}

#ifdef __PROTECT_VM__

#define MAX_STACK_COUNT 8

typedef struct st_pool_symbols_t {
    vm_pool_t*      pool;
    void**          page_stack;
}pool_symbols_t;

static pthread_once_t  g_protect_vm_once = PTHREAD_ONCE_INIT;
static pool_symbols_t* g_pools_symbols = NULL;
static uint32          g_pools_count = 0;
static spinlock_t      g_pools_symbols_lock = 0;

static void protect_vm_init(void)
{
    g_pools_symbols = (pool_symbols_t *)malloc(sizeof(pool_symbols_t) * CT_MAX_TEMP_POOL_NUM);
    if (g_pools_symbols == NULL) {
        return;
    }
    errno_t ret = memset_sp(g_pools_symbols, sizeof(pool_symbols_t) * CT_MAX_TEMP_POOL_NUM, 0,
                            sizeof(pool_symbols_t) * CT_MAX_TEMP_POOL_NUM);
    if (ret != EOK) {
        CM_FREE_PTR(g_pools_symbols);
        return;
    }
}

static pool_symbols_t* find_pool_symbols(const vm_pool_t*  pool)
{
    pool_symbols_t* pool_symbols = NULL;
    for (uint32 pool_id = 0; pool_id < g_pools_count; pool_id++) {
        if (g_pools_symbols[pool_id].pool == pool) {
            pool_symbols = &g_pools_symbols[pool_id];
            break;
        }
    }

    return pool_symbols;
}

static pool_symbols_t* get_idle_pool_symbols(void)
{
    pool_symbols_t* pool_symbols = NULL;
    for (uint32 pool_id = 0; pool_id < CT_MAX_TEMP_POOL_NUM; pool_id++) {
        if (g_pools_symbols[pool_id].pool == NULL) {
            pool_symbols = &g_pools_symbols[pool_id];
            g_pools_count = MAX(g_pools_count, pool_id + 1);
            break;
        }
    }

    return pool_symbols;
}


void _protect_vm_save_stack(vm_pool_t* pool, uint32 id)
{
    (void)pthread_once(&g_protect_vm_once, protect_vm_init);
    if (g_pools_symbols == NULL) {
        return;
    }

    pool_symbols_t* pool_symbols = find_pool_symbols(pool);
    if (pool_symbols == NULL) {
        cm_spin_lock(&g_pools_symbols_lock, NULL);
        pool_symbols = find_pool_symbols(pool); // check again
        if (pool_symbols == NULL) {
            pool_symbols = get_idle_pool_symbols();
            if (pool_symbols == NULL) {
                cm_spin_unlock(&g_pools_symbols_lock);
                return;
            }
            pool_symbols->page_stack = (void**)malloc(sizeof(void*) * pool->page_count);
            if (pool_symbols->page_stack == NULL) {
                cm_spin_unlock(&g_pools_symbols_lock);
                return;
            }
            if (memset_sp(pool_symbols->page_stack, sizeof(void *) * pool->page_count, 0,
                sizeof(void *) * pool->page_count) != EOK) {
                CM_FREE_PTR(pool_symbols->page_stack);
                cm_spin_unlock(&g_pools_symbols_lock);
                return;
            }
            pool_symbols->pool = pool;
        }
        cm_spin_unlock(&g_pools_symbols_lock);
    }

    if (pool_symbols->page_stack != NULL) {
        void **stacks = pool_symbols->page_stack[id];
        if (stacks == NULL) {
            stacks = (void **)malloc(sizeof(void *) * MAX_STACK_COUNT);
            if (stacks == NULL) {
                return;
            }
            if (memset_sp(stacks, sizeof(void *) * MAX_STACK_COUNT, 0, sizeof(void *) * MAX_STACK_COUNT) != EOK) {
                CM_FREE_PTR(stacks);
                return;
            }
            pool_symbols->page_stack[id] = stacks;
        }

        int nptrs = backtrace(stacks, MAX_STACK_COUNT);
        for (int i = nptrs; i < MAX_STACK_COUNT; i++) {
            stacks[i] = NULL;
        }
    }
}

void _protech_vm_print_page_stack(vm_pool_t*  pool, uint32 id, void** stacks)
{
    vm_page_t* page = vm_get_page(pool, id);
    if (page == NULL) {
        CT_LOG_BLACKBOX("get vmpage by page id[%u] is null\r\n", id);
        return;
    }
    CT_LOG_BLACKBOX("page(%u,%u,%u,%u)\r\n", id, page->vmid, page->next.cached_page_id,
                    page->prev.cached_page_id);

    vm_ctrl_t *ctrl = vm_get_ctrl(pool, page->vmid);
    if (ctrl == NULL) {
        CT_LOG_BLACKBOX("get ctrl by vmid[%u] is null\r\n", page->vmid);
        return;
    }

    CT_LOG_BLACKBOX("ctrl(%llu,%u,%u,%u,%u,%u,%u,%u,%u,%u)\r\n",
        ctrl->swid,
        ctrl->cipher_len,
        ctrl->cpid.pool_id,
        ctrl->cpid.cached_page_id,
        ctrl->prev,
        ctrl->next,
        ctrl->sort_next,
        (uint32)ctrl->free,
        (uint32)ctrl->closed,
        (uint32)ctrl->ref_num);

    if (ctrl->closed || ctrl->free) {
        CT_LOG_BLACKBOX("close or free stack is:\r\n");
        char** strings = backtrace_symbols(stacks, MAX_STACK_COUNT);
        if (strings == NULL) {
            return;
        }
        for (uint32 i = 0; i < MAX_STACK_COUNT; i++) {
            if (stacks[i] != NULL) {
                CT_LOG_BLACKBOX("%s\r\n", strings[i]);
            } else {
                break;
            }
        }

        CM_FREE_PTR(strings);
    }
}

void _protech_vm_print_pool_stack(pool_symbols_t* pool_symbols)
{
    if (pool_symbols == NULL ||
        pool_symbols->pool == NULL ||
        pool_symbols->page_stack == NULL) {
        return;
    }

    CT_LOG_BLACKBOX("VM POOL INFO:\r\n");
    CT_LOG_BLACKBOX("pool->map_count       = %u\r\n", pool_symbols->pool->map_count);
    CT_LOG_BLACKBOX("pool->ctrl_hwm        = %u\r\n", pool_symbols->pool->ctrl_hwm);
    CT_LOG_BLACKBOX("pool->ctrl_count      = %u\r\n", pool_symbols->pool->ctrl_count);
    CT_LOG_BLACKBOX("pool->page_hwm        = %u\r\n", pool_symbols->pool->page_hwm);
    CT_LOG_BLACKBOX("pool->page_count      = %u\r\n", pool_symbols->pool->page_count);
    CT_LOG_BLACKBOX("pool->get_swap_extents= %u\r\n", pool_symbols->pool->get_swap_extents);
    CT_LOG_BLACKBOX("pool->swap_count      = %u\r\n", pool_symbols->pool->swap_count);
    CT_LOG_BLACKBOX("pool->max_swap_count  = %u\r\n", pool_symbols->pool->max_swap_count);

    for (uint32 cpid = 0; cpid < pool_symbols->pool->page_count; cpid++) {
        void** stacks = pool_symbols->page_stack[cpid];
        if (stacks != NULL) {
            _protech_vm_print_page_stack(pool_symbols->pool, cpid, stacks);
        }
    }
}

void _protech_vm_print_stack(void)
{
    CT_LOG_BLACKBOX("PROTECT VM:enabled\r\n");
    for (uint32 pool_id = 0; pool_id < g_pools_count; pool_id++) {
        pool_symbols_t* pool_symbols = &g_pools_symbols[pool_id];
        _protech_vm_print_pool_stack(pool_symbols);
    }
}
#else
void _protech_vm_print_stack(void)
{
    CT_LOG_BLACKBOX("PROTECT VM:disabled\r\n");
}
#endif

#ifndef WIN32
#define MADVICE_ERROR (-1)

void mem_remove_from_coredump(void *begin, uint64 len)
{
    if (begin == NULL || len == 0) {
        return;
    }

#ifdef MADV_DONTDUMP // advice MADV_DONTDUMP will only effect since linux 3.4
    int rc;
    CT_LOG_RUN_ERR("Try remove mem from  coredump");
    rc = madvise(begin, len, MADV_DONTDUMP);
    if (rc == MADVICE_ERROR) {
        CT_LOG_RUN_ERR("Remove mem from coredump");
    }
#endif
}

#endif

/*
 * Table for AllocSetFreeIndex
 */
#define LT16(n) (n), (n), (n), (n), (n), (n), (n), (n), (n), (n), (n), (n), (n), (n), (n), (n)
const mtrl_rowid_t g_invalid_entry = { .vmid = CT_INVALID_ID32, .slot = CT_INVALID_ID32};
/* 2^g_log_table256[i] = i + 1, i = [0, 255]
 0            1            2           3           4              5             6            7
(0~8]       (8,16]      (16,32]     (32,64]     (64,128]       (128,256]     (256,512]    (512,1024]
 8            9           10           11          12             13            14
(1024,2048] (2048,4096] (4096,8192] (8192,16384] (16384,32768] (32768,65536] (65536,131072]
*/
static const unsigned char g_log_table256[256] = {
    0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4,
    LT16(5), LT16(6), LT16(6), LT16(7), LT16(7), LT16(7), LT16(7),
    LT16(8), LT16(8), LT16(8), LT16(8), LT16(8), LT16(8), LT16(8), LT16(8)
};


static inline unsigned int vmctx_get_free_index(uint32 size)
{
    unsigned int idx;
    unsigned int t, tsize;

    if (size > (1 << ALLOC_MINBITS)) {
        /* calc the ceil(log2 (size)) */
        tsize = (size - 1) >> ALLOC_MINBITS;
        /* M > 256 ? log2((M/256)*256) = log2((M/256)) + 8 : log2(M) */
        t = tsize >> 8;
        idx = t ? g_log_table256[t] + 8 : g_log_table256[tsize];
    } else {
        idx = 0;
    }

    return idx;
}

status_t vmctx_alloc(pvm_context_t vm_ctx, uint32 size, mtrl_rowid_t *row_id)
{
    uint32 vmid;
    uint32 idx;
    vm_page_head_t *page = NULL;
    vm_ctrl_t      *ctrl = NULL ;
    pvm_chunk_t chunk = NULL;
    uint32      chunk_size = CM_ALIGN4(size);
    bool32      need_close = CT_FALSE;

    VM_CTX_OPEN(vm_ctx);
    vmid = vm_ctx->vm_list.last;
    ctrl = vm_get_ctrl(VMCTX_POOL(vm_ctx), vmid);
    CM_ASSERT(ctrl->ref_num > 0);
    page = (vm_page_head_t *)VMCTX_CURR_PAGE(vm_ctx)->data;

    /* if requested size is exceeds max vm page size, return NULL */
    if ((size >= CT_VMEM_PAGE_SIZE) || (chunk_size > ALLOC_MAX_MEM_SIZE)) {
        CT_THROW_ERROR_EX(ERR_NO_FREE_VMEM, "alloc size (%u) exceed max page size %u, last id: %u", size,
                          CT_VMEM_PAGE_SIZE, vmid);
        return CT_ERROR;
    }

    idx = vmctx_get_free_index(size);
    CM_ASSERT(idx < ALLOCSET_NUM_FREELISTS);
    
    *row_id = vm_ctx->free_list[idx];
    if (ROWID_ID2_UINT64(*row_id) != ROWID_ID2_UINT64(g_invalid_entry)) {
        vm_page_t *free_page = VMCTX_CURR_PAGE(vm_ctx);
        if (row_id->vmid != vmid) {
            if (vm_open(VMCTX_SESSION(vm_ctx), VMCTX_POOL(vm_ctx), row_id->vmid, &free_page) != CT_SUCCESS) {
                return CT_ERROR;
            }
            need_close = CT_TRUE;
        }
        chunk = VM_GET_CHUNK(free_page, row_id->slot);
        chunk->requested_size = size;
        
        vm_ctx->free_list[idx] = chunk->next;
        if (need_close) {
            vm_close(VMCTX_SESSION(vm_ctx), VMCTX_POOL(vm_ctx), row_id->vmid, VM_ENQUE_TAIL);
        }
        return CT_SUCCESS;
    }
    
    chunk_size = (1 << ALLOC_MINBITS) << idx;
    CM_ASSERT(chunk_size >= size);
    if (chunk_size + VM_CHUNKHDRSZ + page->free_begin > CT_VMEM_PAGE_SIZE) {
        /* last page is not avail for current alloc, split the left room into free list */
        CM_ASSERT(page->free_begin <= CT_VMEM_PAGE_SIZE);
        uint32 avail_space = CT_VMEM_PAGE_SIZE - page->free_begin;
        while (avail_space >= ((1 << ALLOC_MINBITS) + VM_CHUNKHDRSZ)) {
            uint32 avail_chunk = avail_space - VM_CHUNKHDRSZ;
            uint32 a_idx = vmctx_get_free_index(avail_chunk);
            if (avail_chunk != (1 << (a_idx + ALLOC_MINBITS))) {
                a_idx--;
                CM_ASSERT(a_idx >= 0);
                avail_chunk = ((uint32)1 << (a_idx + ALLOC_MINBITS));
            }

            chunk = VM_GET_CHUNK(VMCTX_CURR_PAGE(vm_ctx), page->free_begin);
            chunk->size = avail_chunk;
            chunk->requested_size = 0;    /* mark it free */

            chunk->next = vm_ctx->free_list[a_idx];
            vm_ctx->free_list[a_idx].vmid = vmid;
            vm_ctx->free_list[a_idx].slot = page->free_begin;

            page->free_begin += (avail_chunk + VM_CHUNKHDRSZ);
            avail_space -= (avail_chunk + VM_CHUNKHDRSZ);
        }

        vm_close(VMCTX_SESSION(vm_ctx), VMCTX_POOL(vm_ctx), vmid, VM_ENQUE_TAIL);
        if (vm_alloc_and_append(VMCTX_SESSION(vm_ctx), VMCTX_POOL(vm_ctx), &vm_ctx->vm_list) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (vmctx_open_page(vm_ctx) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_VM, "fail to open the vm");
            return CT_ERROR;
        }
        page = (vm_page_head_t *)VMCTX_CURR_PAGE(vm_ctx)->data;
        vmid = vm_ctx->vm_list.last;
    }

    row_id->vmid = vmid;
    row_id->slot = page->free_begin;
    chunk = VM_GET_CHUNK(VMCTX_CURR_PAGE(vm_ctx), page->free_begin);

    chunk->next = g_invalid_entry;
    if (chunk_size == CT_VMEM_PAGE_SIZE) {
        chunk->size = ALLOC_MAX_MEM_SIZE;
        chunk->requested_size = size;
        page->free_begin = CT_VMEM_PAGE_SIZE;
    } else {
        chunk->size = chunk_size;
        chunk->requested_size = size;
        page->free_begin += chunk->size + VM_CHUNKHDRSZ;
    }

    return CT_SUCCESS;
}

status_t vmctx_insert(pvm_context_t vm_ctx, const char *row, uint32 size, mtrl_rowid_t *row_id)
{
    vm_page_head_t *page = NULL;
    uint32 vmid;
    uint32 idx;
    vm_ctrl_t *ctrl = NULL;
    pvm_chunk_t chunk = NULL;
    uint32 chunk_size = CM_ALIGN4(size);
    bool32 need_close = CT_FALSE;

    VM_CTX_OPEN(vm_ctx);
    vmid = vm_ctx->vm_list.last;
    ctrl = vm_get_ctrl(VMCTX_POOL(vm_ctx), vmid);
    CM_ASSERT(ctrl->ref_num > 0);
    page = (vm_page_head_t *)VMCTX_CURR_PAGE(vm_ctx)->data;

    /* if requested size is exceeds max vm page size, return NULL */
    if ((size >= CT_VMEM_PAGE_SIZE) || (chunk_size > ALLOC_MAX_MEM_SIZE)) {
        CT_THROW_ERROR_EX(ERR_NO_FREE_VMEM, "alloc size (%u) exceed max page size %u, last id: %u",
            size, CT_VMEM_PAGE_SIZE, vmid);
        return CT_ERROR;
    }

    idx = vmctx_get_free_index(size);
    CM_ASSERT(idx < ALLOCSET_NUM_FREELISTS);

    *row_id = vm_ctx->free_list[idx];
    if (ROWID_ID2_UINT64(*row_id) != ROWID_ID2_UINT64(g_invalid_entry)) {
        vm_page_t *free_page = VMCTX_CURR_PAGE(vm_ctx);
        if (row_id->vmid != vmid) {
            if (vm_open(VMCTX_SESSION(vm_ctx), VMCTX_POOL(vm_ctx), row_id->vmid, &free_page) != CT_SUCCESS) {
                return CT_ERROR;
            }
            need_close = CT_TRUE;
        }
        chunk = VM_GET_CHUNK(free_page, row_id->slot);
        chunk->requested_size = size;
        errno_t err = memcpy_sp(ALLOC_CHUNK_GET_POINTER(chunk), chunk->size, row, size);
        if (SECUREC_UNLIKELY(err != EOK)) {
            if (need_close) {
                vm_close(VMCTX_SESSION(vm_ctx), VMCTX_POOL(vm_ctx), row_id->vmid, VM_ENQUE_TAIL);
            }
            CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
            return CT_ERROR;
        }
        vm_ctx->free_list[idx] = chunk->next;
        chunk->next = g_invalid_entry;
        if (need_close) {
            vm_close(VMCTX_SESSION(vm_ctx), VMCTX_POOL(vm_ctx), row_id->vmid, VM_ENQUE_TAIL);
        }
        return CT_SUCCESS;
    }

    chunk_size = (1 << ALLOC_MINBITS) << idx;
    CM_ASSERT(chunk_size >= size);
    if (chunk_size + VM_CHUNKHDRSZ + page->free_begin > CT_VMEM_PAGE_SIZE) {
        /* last page is not avail for current alloc, split the left room into free list */
        CM_ASSERT(page->free_begin <= CT_VMEM_PAGE_SIZE);
        uint32 avail_space = CT_VMEM_PAGE_SIZE - page->free_begin;
        while (avail_space >= ((1 << ALLOC_MINBITS) + VM_CHUNKHDRSZ)) {
            uint32 avail_chunk = avail_space - VM_CHUNKHDRSZ;
            uint32 a_idx = vmctx_get_free_index(avail_chunk);
            if (avail_chunk != (1 << (a_idx + ALLOC_MINBITS))) {
                a_idx--;
                CM_ASSERT(a_idx >= 0);
                avail_chunk = ((uint32)1 << (a_idx + ALLOC_MINBITS));
            }

            chunk = VM_GET_CHUNK(VMCTX_CURR_PAGE(vm_ctx), page->free_begin);
            chunk->size = avail_chunk;
            chunk->requested_size = 0;    /* mark it free */

            chunk->next = vm_ctx->free_list[a_idx];
            vm_ctx->free_list[a_idx].vmid = vmid;
            vm_ctx->free_list[a_idx].slot = page->free_begin;

            page->free_begin += (avail_chunk + VM_CHUNKHDRSZ);
            avail_space -= (avail_chunk + VM_CHUNKHDRSZ);
        }

        vm_close(VMCTX_SESSION(vm_ctx), VMCTX_POOL(vm_ctx), vmid, VM_ENQUE_TAIL);
        if (vm_alloc_and_append(VMCTX_SESSION(vm_ctx), VMCTX_POOL(vm_ctx), &vm_ctx->vm_list) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (vmctx_open_page(vm_ctx) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_VM, "fail to open the vm");
            return CT_ERROR;
        }
        page = (vm_page_head_t *)VMCTX_CURR_PAGE(vm_ctx)->data;
        vmid = vm_ctx->vm_list.last;
    }

    row_id->vmid = vmid;
    row_id->slot = page->free_begin;

    chunk = VM_GET_CHUNK(VMCTX_CURR_PAGE(vm_ctx), page->free_begin);
    chunk->next = g_invalid_entry;
    if (chunk_size == CT_VMEM_PAGE_SIZE) {
        chunk->size = ALLOC_MAX_MEM_SIZE;
        chunk->requested_size = size;
        page->free_begin = CT_VMEM_PAGE_SIZE;
    } else {
        chunk->size = chunk_size;
        chunk->requested_size = size;
        page->free_begin += chunk->size + VM_CHUNKHDRSZ;
    }

    MEMS_RETURN_IFERR(memcpy_sp(ALLOC_CHUNK_GET_POINTER(chunk), chunk->size, row, size));
    return CT_SUCCESS;
}


status_t vmctx_free(pvm_context_t vm_ctx, mtrl_rowid_t *row_id)
{
    vm_page_t  *free_page = VMCTX_CURR_PAGE(vm_ctx);
    pvm_chunk_t chunk = NULL;
    uint32 idx;
    bool32      need_close = CT_FALSE;
    
    CM_ASSERT(vm_ctx->is_open);
    
    if (row_id->vmid != vm_ctx->vm_list.last) {
        if (vm_open(VMCTX_SESSION(vm_ctx), VMCTX_POOL(vm_ctx), row_id->vmid, &free_page) != CT_SUCCESS) {
            return CT_ERROR;
        }
        need_close = CT_TRUE;
    }

    chunk = VM_GET_CHUNK(free_page, row_id->slot);
    /* Normal case, put the chunk into appropriate freelist */
    idx = vmctx_get_free_index(chunk->size);
    chunk->next = vm_ctx->free_list[idx];

    /* Reset requested_size to 0 in chunks that are on freelist */
    chunk->requested_size = 0;

    vm_ctx->free_list[idx] = *row_id;
    if (need_close) {
        vm_close(VMCTX_SESSION(vm_ctx), VMCTX_POOL(vm_ctx), row_id->vmid, VM_ENQUE_TAIL);
    }
    return CT_SUCCESS;
}

status_t vmctx_realloc(pvm_context_t vm_ctx, mtrl_rowid_t *row_id, uint32 size)
{
    char *data = NULL;
    bool32 need_close = CT_FALSE;
    pvm_chunk_t chunk = NULL;
    vm_page_t *page = vm_ctx->curr_page;
    errno_t ret;
    CM_ASSERT(vm_ctx->is_open);
    
    if (vm_ctx->vm_list.last != row_id->vmid) {
        if (vm_open(VMCTX_SESSION(vm_ctx), VMCTX_POOL(vm_ctx), row_id->vmid, &page) != CT_SUCCESS) {
            return CT_ERROR;
        }
        need_close = CT_TRUE;
    }
    
    chunk = VM_GET_CHUNK(page, row_id->slot);
    if (chunk->requested_size >= size) {
        chunk->requested_size = size;
        if (need_close) {
            vm_close(VMCTX_SESSION(vm_ctx), VMCTX_POOL(vm_ctx), row_id->vmid, VM_ENQUE_TAIL);
        }
        return CT_SUCCESS;
    }
    
    data = cm_push(VMCTX_STACK(vm_ctx), size);
    ret = memcpy_sp(data, size, ALLOC_CHUNK_GET_POINTER(chunk), chunk->requested_size);
    if (need_close) {
        vm_close(VMCTX_SESSION(vm_ctx), VMCTX_POOL(vm_ctx), row_id->vmid, VM_ENQUE_TAIL);
    }
    if (ret != EOK) {
        cm_pop(VMCTX_STACK(vm_ctx));
        return CT_ERROR;
    }
    
    if (vmctx_free(vm_ctx, row_id) != CT_SUCCESS) {
        cm_pop(VMCTX_STACK(vm_ctx));
        return CT_ERROR;
    }
    
    if (vmctx_insert(vm_ctx, (const char *)data, size, row_id) != CT_SUCCESS) {
        cm_pop(VMCTX_STACK(vm_ctx));
        return CT_ERROR;
    }
    cm_pop(VMCTX_STACK(vm_ctx));

    return CT_SUCCESS;
}

void vmctx_reset(pvm_context_t vm_ctx)
{
    if (!vm_ctx->is_open) {
        return;
    }
    vm_free_list(VMCTX_SESSION(vm_ctx), VMCTX_POOL(vm_ctx), &vm_ctx->vm_list);
    MEMS_RETVOID_IFERR(memset_sp(vm_ctx->free_list, sizeof(vm_ctx->free_list), 0xFF, sizeof(vm_ctx->free_list)));
    vm_ctx->curr_page = NULL;
    vm_ctx->is_open = CT_FALSE; /* vm_ctx->session vm_ctx->stack vm_ctx->pool no need assign NULL */
}

status_t vmctx_open_page(pvm_context_t vm_ctx)
{
    uint32 vmid = vm_ctx->vm_list.last;
    vm_page_head_t *page_head = NULL;

    if (vm_open(VMCTX_SESSION(vm_ctx), VMCTX_POOL(vm_ctx), vmid, &vm_ctx->curr_page) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_VM, "fail to open the vm");
        return CT_ERROR;
    }
 
    page_head = (vm_page_head_t *)vm_ctx->curr_page->data;
    vm_init_page(page_head, vm_ctx->vm_list.last);
    return CT_SUCCESS;
}

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)

status_t  vmctx_check_memory(pvm_context_t vm_ctx)
{
    uint32 free_size = 0;
    uint32 alloc_size;
    uint32 vmid;
    mtrl_rowid_t curr, next;
    vm_ctrl_t *ctrl = NULL;
    if (!vm_ctx->is_open) {
        return CT_SUCCESS;
    }
    /* alloc memory must equal free memory */
    CM_ASSERT(vm_ctx->vm_list.count > 0);
    vmid = vm_ctx->vm_list.first;
    while (vmid != vm_ctx->vm_list.last) {
        ctrl = vm_get_ctrl(vm_ctx->pool, vmid);
        CM_ASSERT(ctrl->ref_num == 0);
        vmid = ctrl->next;
    }
    ctrl = vm_get_ctrl(vm_ctx->pool, vm_ctx->vm_list.last);
    CM_ASSERT(ctrl->ref_num == 1);
    
    for (uint32 i = 0; i < ALLOCSET_NUM_FREELISTS; i++) {
        curr = vm_ctx->free_list[i];
 
        while (!IS_INVALID_MTRL_ROWID(curr)) {
            OPEN_VM_PTR(&curr, vm_ctx);
            CM_ASSERT(d_ptr != NULL);
            free_size += d_chunk->size + VM_CHUNKHDRSZ;
            next = d_chunk->next;
            CLOSE_VM_PTR(&curr, vm_ctx);
            curr = next;
        }
    }
    vm_page_head_t *page_head = (vm_page_head_t *)VMCTX_CURR_PAGE(vm_ctx)->data;
    alloc_size = page_head->free_begin - VM_PAGEHDRSZ;
    if (vm_ctx->vm_list.count > 1) {
        uint32 id = vm_ctx->vm_list.first;
        while (id != vm_ctx->vm_list.last) {
            vm_page_t *page = NULL;
            vm_ctrl_t *tmp_ctrl = vm_get_ctrl(VMCTX_POOL(vm_ctx), id);
            CM_ASSERT(vm_open(VMCTX_SESSION(vm_ctx), VMCTX_POOL(vm_ctx), id, &page) == CT_SUCCESS);
            alloc_size += ((vm_page_head_t *)page->data)->free_begin - VM_PAGEHDRSZ;
            vm_close(VMCTX_SESSION(vm_ctx), VMCTX_POOL(vm_ctx), id, VM_ENQUE_TAIL);
            id = tmp_ctrl->next;
        }
    }
    
    if (free_size != alloc_size) {
        CT_LOG_RUN_WAR("[VMCTX] vmctx memory may leak, alloc size %u, free size %u", alloc_size, free_size);
    }
    return CT_SUCCESS;
}

#endif  // DEBUG

#ifdef __cplusplus
}
#endif

