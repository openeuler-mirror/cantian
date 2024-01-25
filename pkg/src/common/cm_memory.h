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
 * cm_memory.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_memory.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_MEMORY_H__
#define __CM_MEMORY_H__

#include "cm_defs.h"
#include "cm_text.h"
#include "cm_spinlock.h"
#ifndef WIN32
#include <sys/mman.h>
#include <execinfo.h>
#include <pthread.h>
#endif
#include "cm_stack.h"
#ifdef __cplusplus
extern "C" {
#endif

#define CM_MPOOL_ALLOC_TRY_TIME_MAX 10
#define CM_MPOOL_ALLOC_SLEEP_TIME 5
#define CM_MPOOL_ALLOC_WAIT_TIME 100  // 100ms
#define VMC_MAGIC 'V'

#ifdef WIN32
#ifdef _WIN64
#define CM_MFENCE        \
    {                    \
        _mm_mfence();    \
    }
#else
#define CM_MFENCE        \
    {                    \
        __asm {mfence }  \
    }
#endif
#elif defined(__arm__) || defined(__aarch64__)
#define CM_MFENCE                         \
    {                                     \
        __asm__ volatile("dmb ish" ::     \
                             : "memory"); \
    }
#else
#define CM_MFENCE                         \
    {                                     \
        __asm__ volatile("mfence" ::      \
                             : "memory"); \
    }
#endif

#define TEMP_POOL_SIZE_THRESHOLD (((uint64)SIZE_M(1024)) * 2)  // if totoal/buf_pool_num < 2G, then use one TEMP pool
extern uint32 g_vm_max_stack_count;
extern bool32 g_vma_mem_check;
typedef struct st_id_list {
    uint32 count;
    uint32 first;
    uint32 last;
} id_list_t;

static inline void cm_reset_id_list(id_list_t *list)
{
    list->count = 0;
    list->first = CT_INVALID_ID32;
    list->last = CT_INVALID_ID32;
}

typedef struct st_memory_area {
    spinlock_t lock;
    char name[CT_NAME_BUFFER_SIZE];
    char *buf;
    char *page_buf;
    uint32 *maps;
    bool32 is_alone;
    uint64 size;
    uint64 offset;

    uint32 page_hwm;  // high water mark of page id
    uint32 page_count;
    uint32 page_size;
    id_list_t free_pages;
} memory_area_t;

typedef status_t (*mem_func_t)(void *ctx, void *mem, uint32 size, void **buf);

typedef status_t (*mem_alloc_t)(void *ctx, uint32 size, void **buf);

typedef struct st_memory_alloc {
    void *ctx;
    mem_func_t mem_func;
} memory_alloc_t;

typedef struct st_memory_pool {
    spinlock_t lock;
    char name[CT_NAME_BUFFER_SIZE];
    memory_area_t *area;  // for creating from memory area
    char *buf;            // for attached memory pool
    char *page_buf;
    uint32 *maps;
    uint32 page_size;
    uint32 page_count;
    uint32 opt_count;
    id_list_t free_pages;
    memory_alloc_t mem_alloc;
} memory_pool_t;

typedef struct st_memory_context {
    memory_pool_t *pool;
    id_list_t pages;

    char *curr_page_addr;
    uint32 curr_page_id;
    uint32 alloc_pos;
} memory_context_t;

#define MEM_EXTENT_SIZE      4
#define MEM_NEXT_PAGE(m, id) ((m)->maps[id])

typedef struct st_mem_extent {
    uint32 count;
    uint32 pages[MEM_EXTENT_SIZE];
} mem_extent_t;

status_t marea_create(const char *name, size_t size, uint32 page_size, memory_area_t *area);
void marea_attach(const char *name, char *buf, size_t size, uint32 page_size, memory_area_t *area);
void marea_destroy(memory_area_t *area);
status_t marea_alloc_buf(memory_area_t *area, uint32 page_count, char **buf);
status_t marea_alloc_page(memory_area_t *area, uint32 *page_id);
static inline status_t marea_reset_page_buf(memory_area_t *area, int32 val)
{
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    // debug version
    MEMS_RETURN_IFERR(memset_s(area->page_buf, area->page_count * area->page_size,
        val, area->page_count * area->page_size));
#else
    // release version
    if (g_vma_mem_check) {
        MEMS_RETURN_IFERR(memset_s(area->page_buf, area->page_count * area->page_size,
            val, area->page_count * area->page_size));
    }
#endif
    return CT_SUCCESS;
}

status_t mpool_create(memory_area_t *area, const char *name, uint32 page_count, uint32 opt_count,
                      memory_pool_t *pool);
void mpool_attach(const char *name, char *buf, int64 buf_size, uint32 page_size, memory_pool_t *pool);
status_t mpool_extend(memory_pool_t *pool, uint32 count, mem_extent_t *extent);
bool32 mpool_try_extend(memory_pool_t *pool, uint32 count, mem_extent_t *extent);
status_t mpool_alloc_page(memory_pool_t *pool, uint32 *id);
status_t mpool_alloc_page_wait(memory_pool_t *pool, uint32 *page_id, uint32 wait_ms);
void mpool_free_page(memory_pool_t *pool, uint32 id);
uint32 mpool_get_extend_page_count(uint32 opt_count, uint32 page_count);
bool32 mpool_try_alloc_page(memory_pool_t *pool, uint32 *id);
void mpool_free(memory_pool_t *pool, uint32 pool_caches);

static inline bool32 mpool_has_remain_page(memory_pool_t *pool)
{
    return (pool->free_pages.count > 0 || pool->page_count < pool->opt_count);
}

void mctx_init(memory_pool_t *pool, memory_context_t *context);
status_t mctx_create(memory_pool_t *pool, memory_context_t **context);
bool32 mctx_try_create(memory_pool_t *pool, memory_context_t **context);
void mctx_destroy(memory_context_t *context); // put the pages back into the pool
status_t mctx_alloc(memory_context_t *context, uint32 size, void **buf);
bool32 mctx_try_alloc(memory_context_t *context, uint32 size, void **buf);
bool32 mctx_try_extend(memory_context_t *context);
status_t mctx_alloc_exhausted(memory_context_t *context, uint32 size, void **buf, uint32 *buf_size);
bool32 mctx_try_alloc_exhausted(memory_context_t *context, uint32 size, void **buf, uint32 *buf_size);
status_t mctx_copy_text2str(memory_context_t *context, const text_t *src, char **dst);
status_t mctx_copy_text(memory_context_t *context, const text_t *src, text_t *dst);
status_t mctx_copy_name(memory_context_t *context, text_t *src, text_t *dst, bool32 upper_name);
#define mctx_copy_bin(context, src, dst) mctx_copy_text((context), (text_t *)(src), (text_t *)(dst))

static inline void mctx_delete_page(memory_context_t *context, uint32 *page_id)
{
    *page_id = context->pages.first;
    context->pages.first = context->pool->maps[*page_id];
    context->pool->maps[*page_id] = CT_INVALID_ID32;
    --context->pages.count;
}

static inline char *mpool_page_addr(memory_pool_t *pool, uint32 id);
static inline void cm_concat_page(uint32 *maps, id_list_t *list, uint32 page_id);
static inline void mctx_add_page(memory_context_t *context, uint32 page_id)
{
    cm_concat_page(context->pool->maps, &context->pages, page_id);
    context->alloc_pos = 0;
    context->curr_page_addr = mpool_page_addr(context->pool, page_id);
    context->curr_page_id = page_id;
}

static inline void mctx_first_page(memory_pool_t *pool, memory_context_t **context, uint32 page_id)
{
    memory_context_t *ctx = NULL;

    char *page = mpool_page_addr(pool, page_id);
    ctx = (memory_context_t *)page;
    ctx->pool = pool;
    ctx->pages.count = 1;
    ctx->pages.first = page_id;
    ctx->pages.last = page_id;
    pool->maps[page_id] = CT_INVALID_ID32;
    ctx->alloc_pos = sizeof(memory_context_t);
    ctx->curr_page_addr = page;
    ctx->curr_page_id = page_id;
    *context = ctx;
}

static inline char *marea_page_addr(memory_area_t *area, uint32 id)
{
    return area->page_buf + (uint64)area->page_size * (uint64)id;
}

static inline char *mpool_page_addr(memory_pool_t *pool, uint32 id)
{
    return pool->page_buf + (uint64)pool->page_size * (uint64)id;
}

static inline void cm_concat_page(uint32 *maps, id_list_t *list, uint32 page_id)
{
    if (list->count == 0) {
        list->first = page_id;
        list->last = page_id;
        list->count = 1;
        maps[page_id] = CT_INVALID_ID32;
        return;
    }

    list->count++;
    maps[list->last] = page_id;
    maps[page_id] = CT_INVALID_ID32;
    list->last = page_id;
}

static inline void cm_concat_page_list(uint32 *maps, id_list_t *list1, id_list_t *list2)
{
    if (list1->count == 0) {
        *list1 = *list2;
        return;
    }

    list1->count += list2->count;
    maps[list1->last] = list2->first;
    list1->last = list2->last;
}

static inline void mpool_destory(memory_pool_t *pool)
{
    memory_area_t *area = pool->area;

    CM_ASSERT(pool->free_pages.count == pool->page_count);

    if (pool->free_pages.count == 0) {
        return;
    }

    cm_spin_lock(&area->lock, NULL);
    cm_concat_page_list(area->maps, &area->free_pages, &pool->free_pages);
    cm_spin_unlock(&area->lock);
    pool->free_pages.count = 0;
    pool->page_count = 0;
}

static inline void mctx_free(memory_context_t *context)
{
    memory_pool_t *pool = context->pool;

    if (context->pages.count == 0) {
        return;
    }
    cm_spin_lock(&pool->lock, NULL);
    cm_concat_page_list(pool->maps, &pool->free_pages, &context->pages);
    cm_spin_unlock(&pool->lock);
    mctx_init(pool, context);
}

typedef struct st_object {
    struct st_object *next;
    struct st_object *prev;
    char data[4];
} object_t;

#define OBJECT_HEAD_SIZE OFFSET_OF(object_t, data)

typedef struct st_object_list {
    uint32 count;
    object_t *first;
    object_t *last;
} object_list_t;

static inline void olist_concat_single(object_list_t *list, object_t *object)
{
    if (list->count == 0) {
        list->first = object;
        list->last = object;
        object->prev = NULL;
        object->next = NULL;
        list->count = 1;
        return;
    }

    CM_ASSERT(list->last != object);
    object->prev = list->last;
    object->next = NULL;
    list->last->next = object;
    list->last = object;
    list->count++;
}

static inline void olist_concat(object_list_t *list1, object_list_t *list2)
{
    if (list1->count == 0) {
        *list1 = *list2;
        return;
    }

    if (list2->count == 0) {
        return;
    }

    list2->first->prev = list1->last;
    list1->last->next = list2->first;
    list1->last = list2->last;
    list1->count += list2->count;
}

static inline void olist_init(object_list_t *list)
{
    list->count = 0;
    list->first = NULL;
    list->last = NULL;
}

static inline void olist_remove(object_list_t *list, object_t *object)
{
    if (object->prev != NULL) {
        object->prev->next = object->next;
    }

    if (object->next != NULL) {
        object->next->prev = object->prev;
    }

    if (list->first == object) {
        list->first = object->next;
    }

    if (list->last == object) {
        list->last = object->prev;
    }
    CM_ASSERT(list->count > 0);
    list->count--;
}

typedef struct st_object_pool {
    char *buf;
    uint32 buf_size;
    uint32 object_size;
    object_list_t free_objects;
} object_pool_t;

static inline void opool_attach(char *buf, uint32 buf_size, uint32 object_size, object_pool_t *pool)
{
    uint32 i;
    uint32 aligned_size = CM_ALIGN8(object_size);
    object_t *object = NULL;

    pool->buf = buf;
    pool->buf_size = buf_size;
    pool->object_size = aligned_size;
    olist_init(&pool->free_objects);

    object = (object_t *)pool->buf;
    for (i = 0; i < buf_size / aligned_size; i++) {
        olist_concat_single(&pool->free_objects, object);
        object = (object_t *)((char *)object + aligned_size);
    }
}

static inline object_t *opool_alloc(object_pool_t *pool)
{
    object_t *object = NULL;

    if (pool->free_objects.count == 0) {
        if (pool->object_size == 0) {
            CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)pool->object_size, "opool_alloc");
            return NULL;
        }
        object = (object_t *)malloc(pool->object_size);
        if (object == NULL) {
            CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)pool->object_size, "opool_alloc");
            return NULL;
        }

        return object;
    }

    object = pool->free_objects.first;
    olist_remove(&pool->free_objects, object);
    return object;
}

static inline void opool_free(object_pool_t *pool, object_t *object)
{
    if ((char *)object < pool->buf || (char *)object >= pool->buf + pool->buf_size) {
        CM_FREE_PTR(object);
        return;
    }

    olist_concat_single(&pool->free_objects, object);
}

static inline void opool_free_list(object_pool_t *pool, object_list_t *list)
{
    object_t *next = NULL;
    object_t *object = list->first;

    while (object != NULL) {
        next = object->next;
        opool_free(pool, object);
        object = next;
    }
}

typedef struct st_cpid {
    uint32 pool_id;
    uint32 cached_page_id;
} cpid_t;

    
typedef struct st_vm_ctrl {      // virtual memory ctrl
    uint64 swid;             // swap  page id
    uint32 cipher_len;
    cpid_t cpid;             // cache page id
    uint32 prev;             // only for btree vm list,  no maintenance in other scenarios
    uint32 next;
    uint32 sort_next;
    uint16  free : 1;
    uint16  closed : 1;
    uint16  swapping : 1;
    uint16 reserved : 13;
    uint16 ref_num;
    spinlock_t lock;
} vm_ctrl_t;

typedef struct st_vm_page {  // cache page
    uint32 vmid;
    cpid_t next;
    cpid_t prev;
    char *data;
} vm_page_t;

typedef enum en_vm_enque_mode {
    VM_ENQUE_HEAD = 1,
    VM_ENQUE_TAIL = 2,
} vm_enque_mode_t;

typedef enum en_vm_stat_mode {
    VM_STAT_OPEN,
    VM_STAT_CLOSE,
    VM_STAT_ALLOC,
    VM_STAT_FREE,
    VM_STAT_SWAP_IN,
    VM_STAT_SWAP_OUT,
    VM_STAT_BEGIN,
    VM_STAT_END,
} vm_stat_mode_t;

#define RESERVED_SWAP_EXTENTS 32
#define VM_MIN_CACHE_PAGES    16
#define VM_CTRLS_PER_PAGE     (uint32)(CT_VMEM_PAGE_SIZE / sizeof(vm_ctrl_t))
#define VM_MAX_CTRLS          (uint32)(CT_MAX_VMEM_MAP_PAGES * VM_CTRLS_PER_PAGE)

typedef status_t (*vm_swap_out_t)(handle_t session, vm_page_t *page, uint64 *swid, uint32 *cipher_len);
typedef status_t (*vm_swap_in_t)(handle_t session, uint64 swid, uint32 cipher_len, vm_page_t *page);
typedef void (*vm_swap_clean_t)(handle_t session, uint64 swid);
typedef uint32 (*vm_swap_extents_t)(handle_t session);

typedef void (*vm_statis_t)(handle_t session, vm_stat_mode_t mode);
typedef uint32 (*vm_session_hash_t)(handle_t session);

typedef struct st_vm_swapper {
    vm_swap_out_t out;
    vm_swap_in_t in;
    vm_swap_clean_t clean;
    vm_swap_extents_t get_swap_extents;
} vm_swapper_t;

#define CT_VM_FUNC_STACK_SIZE 2048
#define CT_VM_CLOSE_PAGE_LIST_CNT 10
typedef struct st_vm_func_stack {
    char stack[CT_VM_FUNC_STACK_SIZE];
    uint32 ref_count;
} vm_func_stack_t;

typedef struct st_vm_list {
    uint32 count;
    cpid_t first;
    cpid_t last;
}vm_list_t;

typedef struct st_vm_page_pool {
    spinlock_t lock;
    vm_list_t pages;
} vm_page_pool_t;

typedef struct st_vm_pool {
    spinlock_t lock;
    uint32 pool_id;
    uint32 pool_hwm;
    vm_swapper_t swapper;
    uint32 map_count;
    cpid_t map_pages[CT_MAX_VMEM_MAP_PAGES];
    uint32 ctrl_hwm;
    uint32 ctrl_count;
    id_list_t free_ctrls;

    uint32 page_hwm;
    uint32 page_count;
    uint32 get_swap_extents;
    uint32 swap_count;
    uint32 max_swap_count;
    id_list_t free_pages;
    uint32 close_pool_idx;
    vm_page_pool_t close_page_pools[CT_VM_CLOSE_PAGE_LIST_CNT]; // close page will be distribute by page-id.
    char *buffer;
    char *page_buffer;
    vm_func_stack_t **func_stacks;
    bool32 extending_ctrls : 1;
    vm_statis_t vm_stat;
    struct st_vm_pool *temp_pools;
} vm_pool_t;

static inline vm_page_t *vm_get_page_head(vm_pool_t *pool, uint32 id)
{
    CM_ASSERT(id < pool->page_count);
    vm_page_t *page = (vm_page_t *)((char *)pool->buffer + (uint64)id * (uint64)sizeof(vm_page_t));
    return page;
}

static inline vm_page_t *vm_get_page(vm_pool_t *pool, uint32 id)
{
    CM_ASSERT(id < pool->page_count);
    vm_page_t *page = (vm_page_t *)((char *)pool->buffer + (uint64)id * (uint64)sizeof(vm_page_t));
    page->data = ((char *)pool->page_buffer + (uint64)id * (uint64)CT_VMEM_PAGE_SIZE);
    return page;
}

static inline vm_page_t *vm_get_cpid_page_head(vm_pool_t *pool, cpid_t vmid)
{
    vm_pool_t *other_pool = NULL;

    if (pool->pool_id != vmid.pool_id) {
        other_pool = &pool->temp_pools[vmid.pool_id];
        return vm_get_page_head(other_pool, vmid.cached_page_id);
    }
    return vm_get_page_head(pool, vmid.cached_page_id);
}

static inline vm_pool_t *vm_get_act_pool(vm_pool_t *pool, uint32 pool_id)
{
    return (pool->pool_id == pool_id) ? (pool) : (&pool->temp_pools[pool_id]);
}

static inline vm_page_t *vm_get_cpid_page(vm_pool_t *pool, cpid_t vmid)
{
    vm_pool_t *act_pool = vm_get_act_pool(pool, vmid.pool_id);

    return vm_get_page(act_pool, vmid.cached_page_id);
}

static inline vm_ctrl_t *vm_get_ctrl(vm_pool_t *pool, uint32 id)
{
    uint32 map_id = id / VM_CTRLS_PER_PAGE;
    vm_page_t *page = vm_get_cpid_page_head(pool, pool->map_pages[map_id]);
    vm_ctrl_t *ctrls = (vm_ctrl_t *)page->data;

    return &ctrls[id % VM_CTRLS_PER_PAGE];
}
void vm_init_pool(vm_pool_t *pool, char *buf, int64 buf_size, const vm_swapper_t *swapper, vm_statis_t stat);
status_t vm_alloc(handle_t session, vm_pool_t *pool, uint32 *id);
void vm_append(vm_pool_t *pool, id_list_t *list, uint32 id);
void vm_append_list(vm_pool_t *pool, id_list_t *list, const id_list_t *src_list);
void vm_remove(vm_pool_t *pool, id_list_t *list, uint32 id);
status_t vm_alloc_and_append(handle_t session, vm_pool_t *pool, id_list_t *list);
void vm_free(handle_t session, vm_pool_t *pool, uint32 id);
void vm_free_list(handle_t session, vm_pool_t *pool, id_list_t *list);
status_t vm_open(handle_t session, vm_pool_t *pool, uint32 id, vm_page_t **page);
void vm_close(handle_t session, vm_pool_t *pool, uint32 id, vm_enque_mode_t mode);

void vm_close_and_free(handle_t session, vm_pool_t *pool, uint32 id);
uint32 vm_close_page_cnt(const vm_pool_t *pool);
void test_memory_pool_maps(memory_pool_t *pool);
void *cm_realloc(void *ptr, size_t old_len, size_t new_len);
void mctx_concat_page(memory_context_t *context, uint32 page_id, uint32 alloc_pos);
#define vm_reset_list(list)              \
    do {                                 \
        (list)->count = 0;               \
        (list)->first = CT_INVALID_ID32; \
        (list)->last = CT_INVALID_ID32;  \
    } while (0)

#ifdef __PROTECT_VM__
// large page mode in the Redhah system does not support mprotect
#if ((defined REDHAT) || (defined NEOKYLIN))
#define PROTECT_PAGE(pool, page, id)
#define UNPROTECT_PAGE(page)
#define UNPROTECT_PAGE2(page, size)

#else
void _protect_vm_save_stack(vm_pool_t *pool, uint32 id);

#define PROTECT_PAGE(pool, page, id)                                     \
    do {                                                                 \
        if (mprotect((page)->data, CT_VMEM_PAGE_SIZE, PROT_NONE) != 0) { \
            CM_ASSERT(0);                                                \
        }                                                                \
        _protect_vm_save_stack((pool), (id));                            \
    } while (0);

#define UNPROTECT_PAGE(page)                                                          \
    do {                                                                              \
        if (mprotect((page)->data, CT_VMEM_PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) { \
            CM_ASSERT(0);                                                             \
        }                                                                             \
    } while (0);
#define UNPROTECT_PAGE2(page, size)                              \
    do {                                                         \
        if (mprotect(page, size, PROT_READ | PROT_WRITE) != 0) { \
            CM_ASSERT(0);                                        \
        }                                                        \
    } while (0);

#endif
#else
#define PROTECT_PAGE(pool, page, id)
#define UNPROTECT_PAGE(page)
#define UNPROTECT_PAGE2(page, size)

#endif
void _protech_vm_print_stack(void);

#ifndef WIN32
void mem_remove_from_coredump(void *begin, uint64 len);
#endif

typedef struct st_mtrl_rowid {
    uint32 vmid;
    uint32 slot;
} mtrl_rowid_t;

typedef struct st_mtrl_rowid_list {
    uint32 row_cnt;
    uint32 max_row;
    mtrl_rowid_t rid[0];
} mtrl_rowid_list_t;

extern const mtrl_rowid_t g_invalid_entry;

#define ROWID_ID2_UINT64(vmid) (*(uint64 *)&(vmid))

#define IS_INVALID_MTRL_ROWID(entry) (ROWID_ID2_UINT64(entry) == ROWID_ID2_UINT64(g_invalid_entry))

#define IS_VALID_MTRL_ROWID(entry) (ROWID_ID2_UINT64(entry) != ROWID_ID2_UINT64(g_invalid_entry))

#define IS_SAME_MTRL_ROWID(entry1, entry2) (ROWID_ID2_UINT64(entry1) == ROWID_ID2_UINT64(entry2))

// pl mtrl context
#define ALLOC_MINBITS 3 /* smallest chunk size is 8 bytes */
/* 2^3, 2^4, 2^5, 2^6, 2^7, 2^8, 2^9, 2^10, 2^11, 2^12, 2^13, 2^14, 2^15, 2^16, 2^17 */
#define ALLOCSET_NUM_FREELISTS 15
#define ALLOC_MAX_MEM_SIZE (CT_VMEM_PAGE_SIZE - VM_CHUNKHDRSZ - sizeof(vm_page_head_t))  // 131052

typedef struct st_vm_context_data *pvm_context_t;
typedef struct st_vm_chunk_data *pvm_chunk_t;
#define VM_GET_CHUNK(page, offset) (pvm_chunk_t)((page)->data + (offset))

typedef struct st_vm_context_data {
    id_list_t vm_list;
    bool32 is_open;
    vm_page_t *curr_page;
    handle_t session;
    cm_stack_t **stack;  // point the session->stack address
    vm_pool_t *pool;
    mtrl_rowid_t free_list[ALLOCSET_NUM_FREELISTS]; /* free chunk lists */
} vm_context_data_t;

typedef struct st_vm_page_head {
    uint32 free_begin;
} vm_page_head_t;

typedef struct st_vm_chunk_data {
    /* aset is the owning aset if allocated, or the freelist link if free */
    mtrl_rowid_t next;
    /* size is always the size of the usable space in the chunk */
    uint32 size;
    uint32 requested_size;
} vm_chunk_data_t;

#define VMCTX_CURR_PAGE(vm_ctx) ((vm_ctx)->curr_page)
#define VMCTX_SESSION(vm_ctx) ((vm_ctx)->session)
#define VMCTX_POOL(vm_ctx) ((vm_ctx)->pool)
#define VMCTX_STACK(vm_ctx) (*((vm_ctx)->stack))

#define VM_CHUNKHDRSZ sizeof(vm_chunk_data_t)
#define VM_PAGEHDRSZ sizeof(vm_page_head_t)
#define VM_CONTEXTHDRSZ sizeof(vm_context_data_t)

#define VM_POINTER_GET_CHUNK(ptr) ((pvm_chunk_t)(((char *)(ptr)) - VM_CHUNKHDRSZ))
#define ALLOC_CHUNK_GET_POINTER(chk) ((void *)(((char *)(chk)) + VM_CHUNKHDRSZ))

static inline void vm_init_ctx(pvm_context_t vm_ctx, handle_t session, cm_stack_t **stack, vm_pool_t *pool)
{
    vm_ctx->vm_list.count = 0;
    vm_ctx->curr_page = NULL;
    vm_ctx->session = session;
    vm_ctx->stack = stack;
    vm_ctx->pool = pool;
    vm_ctx->is_open = CT_FALSE;
    for (uint32 i = 0; i < ALLOCSET_NUM_FREELISTS; i++) {
        vm_ctx->free_list[i] = g_invalid_entry;
    }
}

static inline void vm_init_page(vm_page_head_t *page, uint32 id)
{
    page->free_begin = VM_PAGEHDRSZ;
}

status_t vmctx_open_page(pvm_context_t vm_ctx);

#define VM_CTX_OPEN(vm_ctx)                                                                                         \
    do {                                                                                                            \
        if (!(vm_ctx)->is_open) {                                                                                   \
            if (vm_alloc_and_append(VMCTX_SESSION(vm_ctx), VMCTX_POOL(vm_ctx), &(vm_ctx)->vm_list) != CT_SUCCESS) { \
                return CT_ERROR;                                                                                    \
            }                                                                                                       \
            if (vmctx_open_page(vm_ctx) != CT_SUCCESS) {                                                            \
                CT_THROW_ERROR(ERR_VM, "fail to open the vm");                                                      \
                return CT_ERROR;                                                                                    \
            }                                                                                                       \
            (vm_ctx)->is_open = CT_TRUE;                                                                            \
        }                                                                                                           \
    } while (0)

#define OPEN_VM_PTR(entry, vm_ctx)                                                                      \
    do {                                                                                                \
        vm_page_t *d_page = VMCTX_CURR_PAGE(vm_ctx);                                                    \
        char *d_ptr = NULL;                                                                             \
        pvm_chunk_t d_chunk = NULL;                                                                     \
        if (vm_open(VMCTX_SESSION(vm_ctx), VMCTX_POOL(vm_ctx), (entry)->vmid, &d_page) != CT_SUCCESS) { \
            return CT_ERROR;                                                                            \
        }                                                                                               \
        d_chunk = VM_GET_CHUNK(d_page, (entry)->slot);                                                  \
        d_ptr = ALLOC_CHUNK_GET_POINTER(d_chunk);                                                       \
        {
#define CLOSE_VM_PTR(entry, vm_ctx)                                                    \
    }                                                                                  \
    vm_close(VMCTX_SESSION(vm_ctx), VMCTX_POOL(vm_ctx), (entry)->vmid, VM_ENQUE_TAIL); \
    d_ptr = NULL;                                                                      \
    d_chunk = NULL;                                                                    \
    d_page = NULL;                                                                     \
    }                                                                                  \
    while (0)

#define CLOSE_VM_PTR_EX(entry, vm_ctx)                                                     \
    do {                                                                                   \
        vm_close(VMCTX_SESSION(vm_ctx), VMCTX_POOL(vm_ctx), (entry)->vmid, VM_ENQUE_TAIL); \
        d_ptr = NULL;                                                                      \
        d_chunk = NULL;                                                                    \
        d_page = NULL;                                                                     \
    } while (0)

#define VMCTX_GET_DATA(page, row_id)      ALLOC_CHUNK_GET_POINTER((pvm_chunk_t)((page)->data + (row_id)->slot))

static inline status_t vmctx_open_row_id(pvm_context_t vm_ctx, mtrl_rowid_t *row_id, char **data)
{
    vm_page_t *page = NULL;
    if (vm_open(VMCTX_SESSION(vm_ctx), VMCTX_POOL(vm_ctx), row_id->vmid, &page) != CT_SUCCESS) {
        CT_THROW_ERROR_EX(ERR_VM, "failed to open row id vm id %u, vm slot %u", row_id->vmid, row_id->slot);
        return CT_ERROR;
    }

    *data = VMCTX_GET_DATA(page, row_id);
    return CT_SUCCESS;
}

static inline void vmctx_close_row_id(pvm_context_t vm_ctx, mtrl_rowid_t *row_id)
{
    vm_close(VMCTX_SESSION(vm_ctx), VMCTX_POOL(vm_ctx), row_id->vmid, VM_ENQUE_TAIL);
}

status_t vmctx_alloc(pvm_context_t vm_ctx, uint32 size, mtrl_rowid_t *row_id);
status_t vmctx_insert(pvm_context_t vm_ctx, const char *row, uint32 size, mtrl_rowid_t *row_id);
status_t vmctx_free(pvm_context_t vm_ctx, mtrl_rowid_t *row_id);
status_t vmctx_realloc(pvm_context_t vm_ctx, mtrl_rowid_t *row_id, uint32 size);
void     vmctx_reset(pvm_context_t vm_ctx);
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    status_t vmctx_check_memory(pvm_context_t vm_ctx);
#endif  // DEBUG

#ifdef __cplusplus
}
#endif

#endif

