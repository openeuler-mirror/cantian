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
 * dc_util.c
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/dc_util.c
 *
 * -------------------------------------------------------------------------
 */
#include "dc_util.h"
#include "cm_log.h"
#include "knl_context.h"
#include "dc_tbl.h"

void dc_list_add(dc_list_t *list, dc_list_node_t *node)
{
    knl_panic(node != NULL);

    cm_spin_lock(&list->lock, NULL);
    node->next = list->first;
    list->first = (void *)node;
    list->count++;
    cm_spin_unlock(&list->lock);
}

void *dc_list_remove(dc_list_t *list)
{
    dc_list_node_t *node = NULL;

    if (list->count == 0) {
        return NULL;
    }

    cm_spin_lock(&list->lock, NULL);
    if (list->count == 0) {
        cm_spin_unlock(&list->lock);
        return NULL;
    }
    node = (dc_list_node_t *)list->first;
    list->first = node->next;
    list->count--;
    cm_spin_unlock(&list->lock);

    return (void *)node;
}

void dc_lru_add(dc_lru_queue_t *queue, dc_entity_t *entity)
{
    knl_panic_log(entity->lru_prev == NULL && entity->lru_next == NULL,
                  "current entity's lru_prev or lru_next is not NULL, panic info: table %s", entity->table.desc.name);

    if (queue->head == NULL) {
        queue->head = entity;
        queue->tail = entity;
        entity->lru_prev = NULL;
        entity->lru_next = NULL;
    } else {
        entity->lru_next = queue->head;
        entity->lru_prev = NULL;
        queue->head->lru_prev = entity;
        queue->head = entity;
    }

    queue->count++;
}

void dc_lru_remove(dc_lru_queue_t *queue, dc_entity_t *entity)
{
    if (dc_is_reserved_entry(entity->entry->uid, entity->entry->id)) {
        return;
    }

    if (queue->head == entity) {
        queue->head = entity->lru_next;
    }

    if (queue->tail == entity) {
        queue->tail = entity->lru_prev;
    }

    if (entity->lru_prev != NULL) {
        entity->lru_prev->lru_next = entity->lru_next;
    }

    if (entity->lru_next != NULL) {
        entity->lru_next->lru_prev = entity->lru_prev;
    }

    queue->count--;
    entity->lru_next = NULL;
    entity->lru_prev = NULL;
}

void dc_lru_shift(dc_lru_queue_t *dc_lru, dc_entity_t *entity)
{
    dc_lru_remove(dc_lru, entity);
    dc_lru_add(dc_lru, entity);
}

status_t dc_init_lru(dc_context_t *ctx)
{
    dc_lru_queue_t *dc_lru = NULL;
    errno_t err;

    if (dc_alloc_mem(ctx, ctx->memory, sizeof(dc_lru_queue_t), (void **)&ctx->lru_queue) != GS_SUCCESS) {
        return GS_ERROR;
    }

    dc_lru = ctx->lru_queue;
    err = memset_sp(dc_lru, sizeof(dc_lru_queue_t), 0, sizeof(dc_lru_queue_t));
    knl_securec_check(err);
    dc_lru->count = 0;
    dc_lru->lock = 0;
    dc_lru->head = NULL;
    dc_lru->tail = NULL;
    return GS_SUCCESS;
}

static void dc_free_entity(dc_context_t *ctx, dc_entry_t *entry)
{
    if (entry->sch_lock != NULL) {
        dc_list_add(&ctx->free_schema_locks, (dc_list_node_t *)entry->sch_lock);
        entry->sch_lock = NULL;
    }

    if (entry->entity != NULL) {
        mctx_destroy(entry->entity->memory);
        entry->entity = NULL;
    }
}

/* nologging table dc entity can only recyclable if its entry has been emptied */
#define DC_ENTITY_RECYCLABLE(entry, entity)                                 \
    ((entity)->ref_count == 0 && (entity)->valid &&                         \
    (entity) == (entry)->entity && ((entry)->need_empty_entry == GS_FALSE))

bool32 dc_try_recycle(dc_context_t *ctx, dc_lru_queue_t *queue, dc_entity_t *entity)
{
    dc_entry_t *entry = NULL;

    if (entity == NULL) {
        return GS_FALSE;
    }

    entry = entity->entry;

    if (!DC_ENTITY_RECYCLABLE(entry, entity)) {
        return GS_FALSE;
    }

    cm_spin_lock(&entry->lock, NULL);
    if (!DC_ENTITY_RECYCLABLE(entry, entity)) {
        cm_spin_unlock(&entry->lock);
        return GS_FALSE;
    }

    /*
    * entries with table lock should not be recycled.
    * because anonymous block of procedure may open dc then close it before transaction end,
    * in this case, if entity is recyled, empty entity may be got when transaction releasing itl locks.
    */
    if (dc_is_locked(entry)) {
        cm_spin_unlock(&entry->lock);
        return GS_FALSE;
    }

    dc_lru_remove(queue, entity);
    cm_spin_lock(&entry->ref_lock, NULL);
    if (entry->type == DICT_TYPE_TABLE) {
        if (entry->ref_count == 1) {
            dc_segment_recycle(ctx, entity);
        }
        entry->ref_count--;
        knl_panic_log(entry->ref_count >= 0, "the table's ref_count is abnormal, panic info: table %s ref_count %u",
                      entity->table.desc.name, entry->ref_count);
    }
    dc_free_entity(ctx, entry);
    cm_spin_unlock(&entry->ref_lock);
    cm_spin_unlock(&entry->lock);

    return GS_TRUE;
}

static status_t dc_lru_recycle(dc_context_t *ctx)
{
    dc_lru_queue_t *queue;
    dc_entity_t *curr = NULL;
    dc_entity_t *head = NULL;
    dc_entity_t *prev = NULL;

    queue = ctx->lru_queue;
    cm_spin_lock(&queue->lock, NULL);

    if (queue->count == 0) {
        cm_spin_unlock(&queue->lock);
        GS_THROW_ERROR(ERR_ALLOC_GA_MEMORY, ctx->pool.name);
        return GS_ERROR;
    }

    head = queue->head;
    curr = queue->tail;

    while (curr != NULL) {
        if (curr == head) {
            break;
        }

        prev = curr->lru_prev;

        if (dc_try_recycle(ctx, queue, curr)) {
            cm_spin_unlock(&queue->lock);
            return GS_SUCCESS;
        }

        dc_lru_shift(queue, curr);
        curr = prev;
    }

    cm_spin_unlock(&queue->lock);
    GS_THROW_ERROR(ERR_ALLOC_GA_MEMORY, ctx->pool.name);
    return GS_ERROR;
}

dc_entity_t *dc_get_entity_from_lru(knl_session_t *session, uint32 pos, bool32 *is_found)
{
    dc_lru_queue_t *queue;
    dc_entry_t *entry = NULL;
    dc_entity_t *entity = NULL;
    dc_entity_t *prev = NULL;
    uint32       i = 0;
    dc_context_t *ctx = &session->kernel->dc_ctx;

    queue = ctx->lru_queue;
    cm_spin_lock(&queue->lock, NULL);

    if (queue->count == 0 || pos > queue->count) {
        cm_spin_unlock(&queue->lock);
        return NULL;
    }

    entity = queue->tail;
    while (entity != NULL) {
        if (i == pos) {
            break;
        }
        prev = entity->lru_prev;
        entity = prev;
        i++;
    }

    if (entity != NULL && DC_ENTRY_IS_MONITORED(entity->entry)) {
        entry = entity->entry;
        if (!DC_ENTITY_RECYCLABLE(entry, entity)) {
            cm_spin_unlock(&queue->lock);
            return NULL;
        }

        if (!cm_spin_try_lock(&entry->lock)) {
            cm_spin_unlock(&queue->lock);
            return NULL;
        }

        if (!DC_ENTITY_RECYCLABLE(entry, entity)) {
            cm_spin_unlock(&entry->lock);
            cm_spin_unlock(&queue->lock);
            return NULL;
        }

        cm_spin_lock(&entity->ref_lock, NULL);
        entity->ref_count++;
        *is_found = GS_TRUE;
        cm_spin_unlock(&entity->ref_lock);
        cm_spin_unlock(&entry->lock);
    }

    cm_spin_unlock(&queue->lock);
    return entity;
}

status_t dc_recycle_ctx(dc_context_t *ctx)
{
    if (dc_lru_recycle(ctx) == GS_SUCCESS) {
        return GS_SUCCESS;
    }

    cm_reset_error();
    g_knl_callback.dc_recycle_external();

    return dc_lru_recycle(ctx);
}

status_t dc_alloc_mem(dc_context_t *ctx, memory_context_t *mem, uint32 size, void **buf)
{
    for (;;) {
        /* 1. try to alloc mem from dc pool */
        if (mctx_try_alloc(mem, size, buf)) {
            break;
        }

        /* 2. try to recycle from dc_lru queue */
        if (dc_recycle_ctx(ctx) == GS_SUCCESS) {
            continue;
        }

        /* 3. due to sql_area recycled, so make the last attempt to alloc mem from dc pool  */
        if (mctx_try_alloc(mem, size, buf)) {
            cm_reset_error();
            break;
        }

        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t dc_alloc_page(dc_context_t *ctx, char **page)
{
    uint32 page_id;
    errno_t err;

    for (;;) {
        if (mpool_try_alloc_page(&ctx->pool, &page_id)) {
            break;
        }

        if (dc_recycle_ctx(ctx) == GS_SUCCESS) {
            continue;
        }

        if (mpool_try_alloc_page(&ctx->pool, &page_id)) {
            cm_reset_error();
            break;
        }

        return GS_ERROR;
    }

    *page = mpool_page_addr(&ctx->pool, page_id);
    err = memset_sp(*page, GS_SHARED_PAGE_SIZE, 0, GS_SHARED_PAGE_SIZE);
    knl_securec_check(err);

    return GS_SUCCESS;
}

status_t dc_alloc_memory_page(dc_context_t *ctx, uint32 *page_id)
{
    for (;;) {
        if (mpool_try_alloc_page(&ctx->pool, page_id)) {
            break;
        }

        if (dc_recycle_ctx(ctx) == GS_SUCCESS) {
            continue;
        }

        if (mpool_try_alloc_page(&ctx->pool, page_id)) {
            cm_reset_error();
            break;
        }

        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t dc_create_memory_context(dc_context_t *ctx, memory_context_t **memory)
{
    for (;;) {
        if (mctx_try_create(&ctx->pool, memory)) {
            break;
        }

        if (dc_recycle_ctx(ctx) == GS_SUCCESS) {
            continue;
        }

        if (mctx_try_create(&ctx->pool, memory)) {
            cm_reset_error();
            break;
        }

        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t dc_alloc_from_ctx(knl_session_t *session, dc_list_t *list, uint32 size, void **buf)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    errno_t err;

    cm_spin_lock(&ctx->lock, NULL);

    *buf = dc_list_remove(list);

    if (*buf == NULL) {
        if (dc_alloc_mem(ctx, ctx->memory, size, buf) != GS_SUCCESS) {
            cm_spin_unlock(&ctx->lock);
            return GS_ERROR;
        }
    }

    cm_spin_unlock(&ctx->lock);

    err = memset_sp(*buf, size, 0, size);
    knl_securec_check(err);

    return GS_SUCCESS;
}

status_t dc_copy_text2str(knl_session_t *session, memory_context_t *context, text_t *src, char **dst)
{
    if (src->len == 0) {
        *dst = NULL;
        return GS_SUCCESS;
    }

    if (dc_alloc_mem(&session->kernel->dc_ctx, context, src->len + 1, (void **)dst) != GS_SUCCESS) {
        return GS_ERROR;
    }

    (void)cm_text2str(src, *dst, src->len + 1);

    return GS_SUCCESS;
}

status_t dc_alloc_appendix(knl_session_t *session, dc_entry_t *entry)
{
    return dc_alloc_from_ctx(session, &session->kernel->dc_ctx.free_appendixes, sizeof(dc_appendix_t),
        (void **)&entry->appendix);
}

status_t dc_alloc_synonym_link(knl_session_t *session, dc_entry_t *entry)
{
    return dc_alloc_from_ctx(session, &session->kernel->dc_ctx.free_synonym_links, sizeof(synonym_link_t),
        (void **)&entry->appendix->synonym_link);
}

status_t dc_alloc_schema_lock(knl_session_t *session, dc_entry_t *entry)
{
    status_t ret;
    ret = dc_alloc_from_ctx(session, &session->kernel->dc_ctx.free_schema_locks, (uint32)SCHEMA_LOCK_SIZE,
                            (void **)&entry->sch_lock);
    if (ret == GS_SUCCESS) {
        entry->sch_lock->inst_id = GS_INVALID_ID8;
    }
    return ret;
}

bool32 dc_try_reuse_entry(dc_user_t *user, dc_entry_t **entry)
{
    cm_spin_lock(&user->free_entries_lock, NULL);
    *entry = (dc_entry_t *)cm_bilist_remove_head(&user->free_entries);
    if (*entry == NULL) {
        cm_spin_unlock(&user->free_entries_lock);
        return GS_FALSE;
    }
    (*entry)->is_free = GS_FALSE;
    (*entry)->ready = GS_FALSE;
    (*entry)->used = GS_TRUE;
    cm_spin_unlock(&user->free_entries_lock);
    return GS_TRUE;
}

// if entry in free list, remove it
void dc_try_remove_entry(dc_user_t *user, dc_entry_t *entry)
{
    cm_spin_lock(&user->free_entries_lock, NULL);
    if (entry->is_free) {
        cm_bilist_del(&entry->node, &user->free_entries);
        entry->is_free = GS_FALSE;
    }
    cm_spin_unlock(&user->free_entries_lock);
}