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
 * pl_memory.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/persist/pl_memory.c
 *
 * -------------------------------------------------------------------------
 */

#include "pl_memory.h"
#include "srv_instance.h"

status_t pl_alloc_mem_in_mngr(uint32 size, void **buffer)
{
    pl_manager_t *pl_manager = GET_PL_MGR;
    memory_context_t *context = pl_manager->memory;

    cm_spin_lock(&pl_manager->memory_lock, NULL);
    uint32 align_size = CM_ALIGN8(size);
    if (align_size > context->pool->page_size) {
        cm_spin_unlock(&pl_manager->memory_lock);
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, "context memory");
        return CT_ERROR;
    }

    // try alloc, if failed then recycle, try alloc again, if failed then return error
    while (!mctx_try_alloc(context, size, buffer)) {
        cm_spin_unlock(&pl_manager->memory_lock);
        if (!pl_recycle()) {
            return CT_ERROR;
        }
        cm_spin_lock(&pl_manager->memory_lock, NULL);
    }
    cm_spin_unlock(&pl_manager->memory_lock);

    if (size != 0) {
        MEMS_RETURN_IFERR(memset_sp(*buffer, (size_t)size, 0, (size_t)size));
    }

    return CT_SUCCESS;
}

status_t pl_alloc_mem(void *entity_in, uint32 size, void **buffer)
{
    pl_entity_t *entity = (pl_entity_t *)entity_in;
    memory_context_t *context = entity->memory;

    uint32 align_size = CM_ALIGN8(size);
    if (align_size > context->pool->page_size) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, "context memory");
        return CT_ERROR;
    }

    while (!mctx_try_alloc(context, size, buffer)) {
        if (!pl_recycle()) {
            return CT_ERROR;
        }
    }

    if (size != 0) {
        MEMS_RETURN_IFERR(memset_sp(*buffer, (size_t)size, 0, (size_t)size));
    }
    return CT_SUCCESS;
}

status_t pl_init_context(pl_entity_t *pl_ctx)
{
    if (pl_alloc_mem(pl_ctx, sizeof(pl_create_def_t), (void **)&pl_ctx->create_def) != CT_SUCCESS) {
        return CT_ERROR;
    }
    cm_galist_init(&pl_ctx->knl_list, pl_ctx, pl_alloc_mem);
    cm_galist_init(&pl_ctx->ref_list, pl_ctx, pl_alloc_mem);
    cm_galist_init(&pl_ctx->dc_lst, pl_ctx, pl_alloc_mem);
    cm_galist_init(&pl_ctx->sqls, pl_ctx, pl_alloc_mem);
    cm_galist_init(&pl_ctx->sequences, pl_ctx, pl_alloc_mem);
    pl_ctx->create_def->large_page_id = CT_INVALID_ID32;
    return CT_SUCCESS;
}

status_t pl_alloc_context(pl_entity_t **pl_ctx, sql_context_t *context)
{
    memory_context_t *memory = NULL;
    memory_pool_t *pool = sql_pool->memory;

    while (!mctx_try_create(pool, &memory)) {
        if (!pl_recycle()) {
            return CT_ERROR;
        }
    }

    if (mctx_alloc(memory, sizeof(pl_entity_t), (void **)pl_ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }

    MEMS_RETURN_IFERR(memset_sp(*pl_ctx, sizeof(pl_entity_t), 0, sizeof(pl_entity_t)));
    (*pl_ctx)->memory = memory;
    (*pl_ctx)->cached = CT_FALSE;
    (*pl_ctx)->cacheable = CT_TRUE;
    (*pl_ctx)->entry = NULL;
    (*pl_ctx)->context = context;

    return pl_init_context(*pl_ctx);
}

status_t pl_alloc_entity(pl_entry_t *entry, pl_entity_t **entity_out)
{
    pl_entity_t *entity = NULL;

    *entity_out = NULL;
    CT_RETURN_IFERR(pl_alloc_context(&entity, NULL));

    if (entry != NULL) {
        entity->pl_type = entry->desc.type;
        entity->lru_hash = cm_hash_string(entry->desc.name, PL_ENTITY_LRU_SIZE);
    }
    entity->entry = entry;

    *entity_out = entity;

    return CT_SUCCESS;
}

// alloc entry from free_entry_lst, otherwise from GET_PL_MGR->memory
status_t pl_alloc_entry(pl_entry_t **entry_out)
{
    pl_manager_t *pl_manager = GET_PL_MGR;
    pl_list_t *free_entry = &pl_manager->free_entry;
    pl_entry_t *entry = NULL;
    pl_lock_item_t *item = NULL;

    cm_latch_x(&free_entry->latch, CM_THREAD_ID, NULL);
    if (free_entry->lst.count > 0) {
        entry = BILIST_NODE_OF(pl_entry_t, free_entry->lst.head, free_link);
        cm_bilist_del_head(&free_entry->lst);
        cm_unlatch(&free_entry->latch, NULL);
    } else {
        cm_unlatch(&free_entry->latch, NULL);
        CT_RETURN_IFERR(pl_alloc_mem_in_mngr(sizeof(pl_entry_t) + sizeof(pl_lock_item_t), (void **)&entry));
    }
    item = (pl_lock_item_t *)((char *)entry + sizeof(pl_entry_t));
    MEMS_RETURN_IFERR(memset_s(item, sizeof(pl_lock_item_t), 0, sizeof(pl_lock_item_t)));
    entry->meta_lock = item;
    item->first_map = CT_INVALID_ID32;
    item->ix_map_id = CT_INVALID_ID32;
    entry->ready = CT_FALSE;
    *entry_out = entry;
    return CT_SUCCESS;
}

void pl_free_entity(pl_entity_t *entity)
{
    sql_context_t *ref_context = NULL;
    pl_dc_t *pl_dc = NULL;
    knl_dictionary_t *dc = NULL;

    if (entity == NULL) {
        return;
    }
    for (uint32 i = 0; i < entity->dc_lst.count; i++) {
        pl_dc = (pl_dc_t *)cm_galist_get(&entity->dc_lst, i);
        pl_dc_close(pl_dc);
    }
    for (uint32 i = 0; i < entity->knl_list.count; i++) {
        dc = (knl_dictionary_t *)cm_galist_get(&entity->knl_list, i);
        dc_close(dc);
    }

    // free sql_ctx in sql_list of pl_entity
    for (uint32 i = 0; i < entity->sqls.count; i++) {
        ref_context = (sql_context_t *)cm_galist_get(&entity->sqls, i);
        if (!ref_context->in_sql_pool && ref_context->ctrl.ref_count == 0) {
            sql_free_context(ref_context);
        } else {
            // 1.context in pool
            // 2.context not in pool but used as dbe_sql.return_cursor, it will be released when free next stmt
            CM_ASSERT(ref_context->ctrl.ref_count > 0);
            ctx_dec_ref2(&ref_context->ctrl);
        }
    }
    if (entity->context != NULL) {
        sql_free_context(entity->context);
    }
    CM_ASSERT(entity->ref_count == 0);
    CM_ASSERT(entity->bucket_link.next == NULL);
    CM_ASSERT(entity->bucket_link.prev == NULL);
    CM_ASSERT(entity->lru_link.next == NULL);
    CM_ASSERT(entity->lru_link.prev == NULL);
    mctx_destroy(entity->memory);
}

static pl_entity_t *pl_pool_get_free_anony(pl_list_t *lru_list)
{
    pl_manager_t *pl_manager = GET_PL_MGR;
    pl_list_t *find_list = NULL;
    bilist_node_t *node = NULL;
    bilist_node_t *head = NULL;
    pl_entity_t *entity = NULL;

    if (cm_bilist_empty(&lru_list->lst)) {
        return NULL;
    }

    cm_latch_x(&lru_list->latch, CM_THREAD_ID, NULL);
    if (cm_bilist_empty(&lru_list->lst)) {
        cm_unlatch(&lru_list->latch, NULL);
        return NULL;
    }

    node = lru_list->lst.tail;
    head = lru_list->lst.head;
    do {
        entity = BILIST_NODE_OF(pl_entity_t, node, lru_link);
        if (entity->ref_count != 0) {
            node = BINODE_PREV(node);
            pl_lru_shift(lru_list, &entity->lru_link, CT_FALSE);
            continue;
        }
        find_list = &pl_manager->anony_buckets[entity->find_hash];
        pl_list_del(find_list, &entity->bucket_link, CT_TRUE);
        pl_list_del(lru_list, &entity->lru_link, CT_FALSE);
        cm_unlatch(&lru_list->latch, NULL);
        return entity;
    } while (node != NULL && node != head);
    cm_unlatch(&lru_list->latch, NULL);
    return NULL;
}

static pl_entity_t *pl_pool_get_free_entity(pl_list_t *lru)
{
    bilist_node_t *node = NULL;
    bilist_node_t *head = NULL;
    pl_entity_t *entity = NULL;
    pl_entry_t *entry = NULL;

    if (cm_bilist_empty(&lru->lst)) {
        return NULL;
    }

    cm_latch_x(&lru->latch, CM_THREAD_ID, NULL);
    if (cm_bilist_empty(&lru->lst)) {
        cm_unlatch(&lru->latch, NULL);
        return NULL;
    }

    node = lru->lst.tail;
    head = lru->lst.head;
    do {
        entity = BILIST_NODE_OF(pl_entity_t, node, lru_link);
        if (entity->ref_count != 0) {
            node = BINODE_PREV(node);
            pl_lru_shift(lru, &entity->lru_link, CT_FALSE);
            continue;
        }

        entry = entity->entry;
        CM_ASSERT(entry != NULL);

        pl_entry_lock(entry);
        pl_entity_lock(entity);
        if (entity->ref_count != 0) {
            pl_entity_unlock(entity);
            pl_entry_unlock(entry);
            node = BINODE_PREV(node);
            pl_lru_shift(lru, &entity->lru_link, CT_FALSE);
            continue;
        } else {
            entity->valid = CT_FALSE;
            pl_entity_unlock(entity);
        }
        if (entry->entity == entity) {
            entry->entity = NULL;
        }
        pl_entry_unlock(entry);
        pl_list_del(lru, &entity->lru_link, CT_FALSE);
        cm_unlatch(&lru->latch, NULL);
        return entity;
    } while (node != NULL && node != head);
    cm_unlatch(&lru->latch, NULL);
    return NULL;
}

// first remove entity from lru_list, then free entity; otherwise there will be deadlock in pl_dc_close
static bool32 pl_recycle_anony_core(pl_list_t *lru_list)
{
    pl_entity_t *pl_context = pl_pool_get_free_anony(lru_list);

    if (pl_context == NULL) {
        return CT_FALSE;
    }

    pl_free_entity(pl_context);
    return CT_TRUE;
}

static bool32 pl_recycle_anony(void)
{
    pl_manager_t *pl_manager = GET_PL_MGR;
    date_t now = g_timer()->now;
    uint32 lru_hash = cm_hash_timestamp((uint64)now) % PL_ANONY_LRU_SIZE;
    pl_list_t *lru_list = NULL;

    for (uint32 i = lru_hash; i < lru_hash + PL_ANONY_LRU_SIZE; i++) {
        lru_list = &pl_manager->anony_lru[i % PL_ANONY_LRU_SIZE];
        if (pl_recycle_anony_core(lru_list)) {
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

// first remove entity from lru_list, then free entity; otherwise there will be deadlock in pl_dc_close
static bool32 pl_recycle_entity_core(pl_list_t *lru_list)
{
    pl_entity_t *entity = pl_pool_get_free_entity(lru_list);

    if (entity == NULL) {
        return CT_FALSE;
    }

    pl_free_entity(entity);
    return CT_TRUE;
}

static bool32 pl_recycle_entity(void)
{
    pl_manager_t *pl_manager = GET_PL_MGR;
    date_t now = g_timer()->now;
    uint32 lru_hash = cm_hash_timestamp((uint64)now) % PL_ENTITY_LRU_SIZE;
    pl_list_t *lru_list = NULL;

    for (uint32 i = lru_hash; i < lru_hash + PL_ENTITY_LRU_SIZE; i++) {
        lru_list = &pl_manager->pl_entity_lru[i % PL_ENTITY_LRU_SIZE];
        if (pl_recycle_entity_core(lru_list)) {
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

bool32 pl_recycle_internal(void)
{
    if (pl_recycle_entity()) {
        return CT_TRUE;
    }

    if (pl_recycle_anony()) {
        return CT_TRUE;
    }

    return CT_FALSE;
}

static bool32 pl_recycle_external(void)
{
    pl_manager_t *pl_manager = GET_PL_MGR;

    if (pl_manager->external_recycle == NULL) {
        return CT_FALSE;
    }

    return pl_manager->external_recycle();
}

bool32 pl_recycle(void)
{
    if (pl_recycle_internal()) {
        return CT_TRUE;
    }

    if (pl_recycle_external()) {
        return CT_TRUE;
    }

    CT_THROW_ERROR(ERR_ALLOC_GA_MEMORY, "sql pool");
    return CT_FALSE;
}

// first remove entity from lru_list, then free entity; otherwise there will be deadlock in pl_dc_close
static void pl_recycle_all_anony_core(pl_list_t *lru_list)
{
    pl_entity_t *pl_context = pl_pool_get_free_anony(lru_list);

    while (pl_context != NULL) {
        pl_free_entity(pl_context);
        pl_context = pl_pool_get_free_anony(lru_list);
    }
}

static void pl_recycle_all_anony(void)
{
    pl_manager_t *pl_manager = GET_PL_MGR;
    pl_list_t *lru_list = NULL;

    for (uint32 i = 0; i < PL_ANONY_LRU_SIZE; i++) {
        lru_list = &pl_manager->anony_lru[i];
        pl_recycle_all_anony_core(lru_list);
    }
}

// first remove entity from lru_list, then free entity; otherwise there will be deadlock in pl_dc_close
static void pl_recycle_all_entity_core(pl_list_t *lru_list)
{
    pl_entity_t *entity = pl_pool_get_free_entity(lru_list);

    while (entity != NULL) {
        pl_free_entity(entity);
        entity = pl_pool_get_free_entity(lru_list);
    }
}

static void pl_recycle_all_entity(void)
{
    pl_manager_t *pl_manager = GET_PL_MGR;
    pl_list_t *lru_list = NULL;

    for (uint32 i = 0; i < PL_ENTITY_LRU_SIZE; i++) {
        lru_list = &pl_manager->pl_entity_lru[i];
        pl_recycle_all_entity_core(lru_list);
    }
}

void pl_recycle_all(void)
{
    pl_recycle_all_anony();
    pl_recycle_all_entity();
}
