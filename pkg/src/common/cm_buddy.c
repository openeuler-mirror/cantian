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
 * cm_buddy.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_buddy.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_common_module.h"
#include "cm_buddy.h"
#include "cm_error.h"
#include "cm_spinlock.h"
#include "cm_defs.h"
#include "cm_debug.h"

#ifdef __cplusplus
extern "C" {
#endif

// flag indicate block is left or right,0 represent left: 1 represent right
static mem_block_t *mem_block_init(mem_zone_t *mem_zone, void *p, uint64 size, uint32 flag, uint64 bitmap)
{
    mem_block_t *mem_block = (mem_block_t *)p;
    if (mem_block == NULL) {
        return NULL;
    }
    errno_t ret = memset_sp(mem_block, MEM_BLOCK_SIZE, 0, MEM_BLOCK_SIZE);
    if (ret != EOK) {
        return NULL;
    }
    mem_block->mem_zone = mem_zone;
    mem_block->size = size;
    mem_block->bitmap = bitmap;
    if (flag == MEM_BLOCK_LEFT) {
        mem_block->bitmap &= ~size;
    } else {
        mem_block->bitmap |= size;
    }
    CM_MAGIC_SET(mem_block, mem_block_t);
    return mem_block;
}

static bilist_t *mem_zone_get_list(mem_zone_t *mem_zone, uint64 size)
{
    bilist_t *mem_block_list = NULL;

    switch (size) { // The range of size is [64, 2G], and size musts be an integer power of 2.
        case 64:
            mem_block_list = &mem_zone->list_64;
            break;
        case 128:
            mem_block_list = &mem_zone->list_128;
            break;
        case 256:
            mem_block_list = &mem_zone->list_256;
            break;
        case 512:
            mem_block_list = &mem_zone->list_512;
            break;
        case SIZE_K(1):
            mem_block_list = &mem_zone->list_1k;
            break;
        case SIZE_K(2):
            mem_block_list = &mem_zone->list_2k;
            break;
        case SIZE_K(4):
            mem_block_list = &mem_zone->list_4k;
            break;
        case SIZE_K(8):
            mem_block_list = &mem_zone->list_8k;
            break;
        case SIZE_K(16):
            mem_block_list = &mem_zone->list_16k;
            break;
        case SIZE_K(32):
            mem_block_list = &mem_zone->list_32k;
            break;
        case SIZE_K(64):
            mem_block_list = &mem_zone->list_64k;
            break;
        case SIZE_K(128):
            mem_block_list = &mem_zone->list_128k;
            break;
        case SIZE_K(256):
            mem_block_list = &mem_zone->list_256k;
            break;
        case SIZE_K(512):
            mem_block_list = &mem_zone->list_512k;
            break;
        case SIZE_M(1):
            mem_block_list = &mem_zone->list_1m;
            break;
        case SIZE_M(2):
            mem_block_list = &mem_zone->list_2m;
            break;
        case SIZE_M(4):
            mem_block_list = &mem_zone->list_4m;
            break;
        case SIZE_M(8):
            mem_block_list = &mem_zone->list_8m;
            break;
        case SIZE_M(16):
            mem_block_list = &mem_zone->list_16m;
            break;
        case SIZE_M(32):
            mem_block_list = &mem_zone->list_32m;
            break;
        case SIZE_M(64):
            mem_block_list = &mem_zone->list_64m;
            break;
        case SIZE_M(128):
            mem_block_list = &mem_zone->list_128m;
            break;
        case SIZE_M(256):
            mem_block_list = &mem_zone->list_256m;
            break;
        case SIZE_M(512):
            mem_block_list = &mem_zone->list_512m;
            break;
        case SIZE_G(1):
            mem_block_list = &mem_zone->list_1g;
            break;
        case SIZE_G(2):
            mem_block_list = &mem_zone->list_2g;
            break;
        default:
            mem_block_list = &mem_zone->list_64;
            break;
    }

    return mem_block_list;
}

static inline void mem_block_add(mem_block_t *mem_block)
{
    CM_MAGIC_CHECK(mem_block, mem_block_t);
    bilist_t *mem_block_list = mem_zone_get_list(mem_block->mem_zone, mem_block->size);
    cm_bilist_add_tail(&mem_block->link, mem_block_list);
}

static mem_zone_t *mem_zone_init(mem_pool_t *mem, uint64 size)
{
    mem_block_t *mem_block = NULL;
    mem_zone_t *mem_zone = (mem_zone_t *)malloc(sizeof(mem_zone_t) + (size_t)size);
    if (mem_zone == NULL) {
        return NULL;
    }

    errno_t ret = memset_sp(mem_zone, sizeof(mem_zone_t), 0, sizeof(mem_zone_t));
    if (ret != EOK) {
        CM_FREE_PTR(mem_zone);
        return NULL;
    }
    mem_zone->mem = mem;
    mem_zone->total_size = size;
    mem_zone->used_size = 0;
    CM_MAGIC_SET(mem_zone, mem_zone_t);
    mem_block = mem_block_init(mem_zone, (void *)(mem_zone + 1), size, MEM_BLOCK_LEFT, 0);
    if (mem_block == NULL) {
        CM_FREE_PTR(mem_zone);
        return NULL;
    }
    mem_block_add(mem_block);

    mem->total_size += size;
    return mem_zone;
}

status_t mem_pool_init(mem_pool_t *mem, const char *pool_name, uint64 init_size_input, uint64 max_size_input)
{
    mem_zone_t *mem_zone = NULL;
    uint32 len = (uint32)strlen(pool_name);
    uint64 max_size = max_size_input;
    uint64 init_size = init_size_input;
    if (len > CT_MAX_NAME_LEN) {
        CT_THROW_ERROR(ERR_BUFFER_OVERFLOW, len, CT_MAX_NAME_LEN);
        return CT_ERROR;
    }
    init_size = cm_get_next_2power(init_size);
    // modify init size val
    if (init_size > BUDDY_MAX_BLOCK_SIZE) {
        init_size = BUDDY_MAX_BLOCK_SIZE;
    } else if (init_size < BUDDY_MIN_BLOCK_SIZE) {
        init_size = BUDDY_MIN_BLOCK_SIZE;
    }

    if (max_size > BUDDY_MEM_POOL_MAX_SIZE) {
        max_size = BUDDY_MEM_POOL_MAX_SIZE;
    } else if (max_size < init_size) {
        max_size = init_size;
    }

    errno_t ret = memset_sp(mem, sizeof(mem_pool_t), 0, sizeof(mem_pool_t));
    MEMS_RETURN_IFERR(ret);
    CM_MAGIC_SET(mem, mem_pool_t);
    MEMS_RETURN_IFERR(strncpy_sp(mem->name, CT_NAME_BUFFER_SIZE, pool_name, len));
    mem->max_size = max_size;
    CT_INIT_SPIN_LOCK(mem->lock);
    cm_bilist_init(&mem->mem_zone_lst);
    mem_zone = mem_zone_init(mem, init_size);
    if (mem_zone == NULL) {
        CT_THROW_ERROR(ERR_MEM_ZONE_INIT);
        return CT_ERROR;
    }

    cm_bilist_add_tail(&mem_zone->link, &mem->mem_zone_lst);

    return CT_SUCCESS;
}

static mem_block_t *mem_get_block_low(mem_zone_t *mem_zone, uint64 size)
{
    bilist_t *mem_block_list = NULL;
    mem_block_t *mem_block = NULL;
    bilist_node_t *head = NULL;
    CM_MAGIC_CHECK(mem_zone, mem_zone_t);
    if (size > mem_zone->total_size) {
        return NULL;
    }

    mem_block_list = mem_zone_get_list(mem_zone, size);
    if (mem_block_list != NULL && !cm_bilist_empty(mem_block_list)) {
        head = cm_bilist_head(mem_block_list);
        cm_bilist_del_head(mem_block_list);
        mem_block = BILIST_NODE_OF(mem_block_t, head, link);
        CM_MAGIC_CHECK(mem_block, mem_block_t);
        return mem_block;
    } else {
        mem_block = mem_get_block_low(mem_zone, size * 2);
        if (mem_block == NULL) {
            return NULL;
        } else {
            uint64 bitmap = mem_block->bitmap;
            mem_block_t *block_left = mem_block_init(mem_zone, mem_block, size, MEM_BLOCK_LEFT, bitmap);
            mem_block_t *block_right = mem_block_init(mem_zone, (char *)mem_block + size, size, MEM_BLOCK_RIGHT,
                bitmap);

            mem_block_add(block_left);
            return block_right;
        }
    }
}

// obtain a block from memory zone
static inline mem_block_t *mem_alloc_block(mem_zone_t *mem_zone, uint64 size)
{
    if (mem_zone->total_size - mem_zone->used_size < size) {
        return NULL;
    }

    return mem_get_block_low(mem_zone, size);
}

static status_t mem_extend(mem_pool_t *mem, uint64 align_size)
{
    mem_zone_t *mem_zone = NULL;
    uint64 extend_size;

    extend_size = cm_get_next_2power(mem->total_size);
    extend_size = MAX(extend_size, align_size);
    extend_size = MIN(extend_size, BUDDY_MAX_BLOCK_SIZE);
    while (extend_size + mem->total_size > mem->max_size) {
        extend_size /= 2;
    }

    if (extend_size < align_size) {
        CT_THROW_ERROR(ERR_MEM_OUT_OF_MEMORY, align_size);
        return CT_ERROR;
    }

    mem_zone = mem_zone_init(mem, extend_size);
    if (mem_zone == NULL) {
        CT_THROW_ERROR(ERR_MEM_ZONE_INIT);
        return CT_ERROR;
    }
    cm_bilist_add_head(&mem_zone->link, &mem->mem_zone_lst);

    return CT_SUCCESS;
}

static status_t mem_check_if_extend(mem_pool_t *mem, uint64 align_size)
{
    uint64 remain_size = cm_get_prev_2power(mem->max_size - mem->used_size);
    if (align_size > remain_size) {
        CT_THROW_ERROR(ERR_MEM_OUT_OF_MEMORY, align_size);
        return CT_ERROR;
    }

    if (align_size > mem->total_size - mem->used_size) {
        return mem_extend(mem, align_size);
    }

    return CT_SUCCESS;
}

void *galloc(mem_pool_t *mem, uint64 size)
{
    mem_zone_t *mem_zone = NULL;
    mem_block_t *mem_block = NULL;
    uint64 align_size;
    status_t status;
    CM_MAGIC_CHECK(mem, mem_pool_t);
    align_size = cm_get_next_2power(size + MEM_BLOCK_SIZE);
    if (SECUREC_UNLIKELY(align_size > BUDDY_MAX_BLOCK_SIZE)) {
        return NULL;
    }

    cm_spin_lock(&mem->lock, NULL);

    status = mem_check_if_extend(mem, align_size);
    if (status != CT_SUCCESS) {
        cm_spin_unlock(&mem->lock);
        return NULL;
    }

    bilist_node_t *node = cm_bilist_head(&mem->mem_zone_lst);
    for (; node != NULL; node = BINODE_NEXT(node)) {
        mem_zone = BILIST_NODE_OF(mem_zone_t, node, link);
        mem_block = mem_alloc_block(mem_zone, align_size);
        if (mem_block != NULL) {
            break;
        }
    }

    if (mem_block == NULL) {
        status = mem_extend(mem, align_size);
        if (status != CT_SUCCESS) {
            cm_spin_unlock(&mem->lock);
            return NULL;
        }
        // extend zone always add list head
        node = cm_bilist_head(&mem->mem_zone_lst);
        mem_zone = BILIST_NODE_OF(mem_zone_t, node, link);
        mem_block = mem_alloc_block(mem_zone, align_size);
    }

    CM_ASSERT(mem_block != NULL);
    mem_block->actual_size = size;
    CM_ASSERT(mem_block->actual_size < mem_block->size);
    mem_block->use_flag = CT_TRUE;
    mem_block->mem_zone->used_size += mem_block->size;
    mem_block->mem_zone->mem->used_size += mem_block->size;

    cm_spin_unlock(&mem->lock);

    return mem_block->data;
}

#ifdef DB_DEBUG_VERSION
static void check_zone_list(mem_zone_t *mem_zone)
{
    for (int i = 0; i < MEM_NUM_FREELISTS; i++) {
        CM_ASSERT(mem_zone->list[i].count == 0);
    }
}
static void check_mem_double_free(mem_block_t *mem_block, mem_zone_t *mem_zone)
{
    char *left = (char *)mem_block;
    char *right = (char *)mem_block + mem_block->size;

    for (int i = 0; i < MEM_NUM_FREELISTS; i++) {
        bilist_node_t *node = cm_bilist_head(&mem_zone->list[i]);
        while (node) {
            mem_block_t *block_left = BILIST_NODE_OF(mem_block_t, node, link);
            if ((char *)block_left >= left && (char *)block_left < right) {
                CM_ASSERT(0);
            }

            char *block_right = (char *)block_left + block_left->size;
            if (block_right > left && block_right <= right) {
                CM_ASSERT(0);
            }

            if (left >= (char *)block_left && left < (char *)block_right) {
                CM_ASSERT(0);
            }

            if (right > (char *)block_left && right <= (char *)block_right) {
                CM_ASSERT(0);
            }

            node = BINODE_NEXT(node);
        }
    }
}
#endif

static void mem_recycle_low(mem_pool_t *mem, mem_block_t *mem_block)
{
    bilist_t *mem_block_list = NULL;
    mem_block_t *mem_block_bro = NULL;
    mem_block_t *mem_block_merge = NULL;
    uint8 block_type;
    CM_MAGIC_CHECK(mem_block, mem_block_t);
    if (mem_block->size == mem_block->mem_zone->total_size) {
#ifdef DB_DEBUG_VERSION
        check_zone_list(mem_block->mem_zone);
#endif
        mem_block_list = mem_zone_get_list(mem_block->mem_zone, mem_block->size);
        cm_bilist_add_head(&mem_block->link, mem_block_list);
        return;
    }

    block_type = (mem_block->bitmap & mem_block->size) == 0 ? MEM_BLOCK_LEFT : MEM_BLOCK_RIGHT;
    if (block_type == MEM_BLOCK_LEFT) {
        mem_block_bro = (mem_block_t *)((char *)mem_block + mem_block->size);
        mem_block_merge = mem_block;
    } else {
        mem_block_bro = (mem_block_t *)((char *)mem_block - mem_block->size);
        mem_block_merge = mem_block_bro;
    }
    CM_MAGIC_CHECK(mem_block_bro, mem_block_t);

    if (mem_block_bro->use_flag == CT_TRUE || mem_block->size != mem_block_bro->size) {
        mem_block_list = mem_zone_get_list(mem_block->mem_zone, mem_block->size);
        cm_bilist_add_head(&mem_block->link, mem_block_list);
        return;
    }

    mem_block_list = mem_zone_get_list(mem_block_bro->mem_zone, mem_block_bro->size);

    cm_bilist_del(&mem_block_bro->link, mem_block_list);
    mem_block_merge->size *= 2;
    mem_recycle_low(mem, mem_block_merge);
}

void *grealloc(void *p, mem_pool_t *mem, uint64 size)
{
    CM_ASSERT(p != NULL);
    mem_block_t *mem_block = (mem_block_t *)((char *)p - MEM_BLOCK_SIZE);
    if (mem_block->size - MEM_BLOCK_SIZE >= size) {
        mem_block->actual_size = size;
        return p;
    }

    void *new_p = galloc(mem, size);
    if (new_p == NULL) {
        return NULL;
    }
    mem_block_t *new_block = (mem_block_t *)((char *)new_p - MEM_BLOCK_SIZE);
    if (memcpy_sp(new_p, (size_t)(new_block->size - MEM_BLOCK_SIZE), p, (size_t)mem_block->actual_size) != EOK) {
        gfree(new_p);
        return NULL;
    }
    gfree(p);

    return new_p;
}

void gfree(void *p)
{
    mem_block_t *mem_block = NULL;
    mem_pool_t *mem = NULL;
    CM_ASSERT(p != NULL);

    mem_block = (mem_block_t *)((char *)p - MEM_BLOCK_SIZE);
    mem = mem_block->mem_zone->mem;
    CM_ASSERT(mem_block->use_flag);
    CM_MAGIC_CHECK(mem_block, mem_block_t);
    CM_MAGIC_CHECK(mem, mem_pool_t);

    cm_spin_lock(&mem->lock, NULL);
    mem_block = (mem_block_t *)((char *)p - MEM_BLOCK_SIZE);
#ifdef DB_DEBUG_VERSION
    check_mem_double_free(mem_block, mem_block->mem_zone);
#endif
    mem_block->use_flag = CT_FALSE;
    mem_block->actual_size = 0;
    mem_block->mem_zone->used_size -= mem_block->size;
    mem_block->mem_zone->mem->used_size -= mem_block->size;
    mem_recycle_low(mem, mem_block);
    cm_spin_unlock(&mem->lock);
}

void mem_pool_deinit(mem_pool_t *mem)
{
    mem_zone_t *mem_zone = NULL;
    bilist_node_t *head = NULL;

    while (!cm_bilist_empty(&mem->mem_zone_lst)) {
        head = cm_bilist_head(&mem->mem_zone_lst);
        cm_bilist_del(head, &mem->mem_zone_lst);
        mem_zone = BILIST_NODE_OF(mem_zone_t, head, link);
        CM_FREE_PTR(mem_zone);
    }
}

status_t buddy_alloc_mem(mem_pool_t *mem_pool, uint32 size, void **ptr)
{
    *ptr = galloc(mem_pool, size);
    if (*ptr == NULL) {
        CT_THROW_ERROR(ERR_MEM_OUT_OF_MEMORY, size);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
