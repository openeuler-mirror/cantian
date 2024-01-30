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
 * knl_ashrink.c
 *
 *
 * IDENTIFICATION
 * src/kernel/daemon/knl_ashrink.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_common_module.h"
#include "knl_ashrink.h"
#include "cm_file.h"
#include "knl_context.h"
#include "dtc_dls.h"

static inline void ashrink_init_item(ashrink_item_t *item)
{
    item->prev = CT_INVALID_ID32;
    item->next = CT_INVALID_ID32;
    item->uid = CT_INVALID_ID32;
    item->oid = CT_INVALID_ID32;
    item->begin_time = CT_INVALID_INT64;
    item->shrinkable_scn = CT_INVALID_ID64;
}

static void ashrink_add_list_item(knl_session_t *session, id_list_t *list, uint32 id)
{
    ashrink_ctx_t *ctx = &session->kernel->ashrink_ctx;

    if (list->count == 0) {
        list->first = id;
        list->last = id;
    } else {
        ctx->array[list->last].next = id;
        ctx->array[id].prev = list->last;
        list->last = id;
    }

    knl_panic(list->first != CT_INVALID_ID32);
    knl_panic(list->last != CT_INVALID_ID32);
    list->count++;
}

static void ashrink_remove_list_item(knl_session_t *session, id_list_t *list, uint32 id)
{
    ashrink_ctx_t *ctx = &session->kernel->ashrink_ctx;
    ashrink_item_t *item = &ctx->array[id];

    if (item->prev != CT_INVALID_ID32) {
        ctx->array[item->prev].next = item->next;
    }
    
    if (item->next != CT_INVALID_ID32) {
        ctx->array[item->next].prev = item->prev;
    }

    if (id == list->first) {
        list->first = item->next;
    }

    if (id == list->last) {
        list->last = item->prev;
    }
    list->count--;

    if (list->count == 0) {
        list->first = CT_INVALID_ID32;
        list->last = CT_INVALID_ID32;
    } else  {
        knl_panic(list->first != CT_INVALID_ID32);
        knl_panic(list->last != CT_INVALID_ID32);
    }

    item->prev = CT_INVALID_ID32;
    item->next = CT_INVALID_ID32;
}

static void ashrink_release_item(knl_session_t *session, uint32 id)
{
    ashrink_ctx_t *ctx = &session->kernel->ashrink_ctx;

    cm_spin_lock(&ctx->lock, NULL);
    ashrink_item_t *item = &ctx->array[id];

    ashrink_init_item(item);
    ashrink_add_list_item(session, &ctx->free_list, id);

    cm_spin_unlock(&ctx->lock);
}

static status_t ashrink_alloc_item(knl_session_t *session, uint32 *item_id)
{
    ashrink_ctx_t *ctx = &session->kernel->ashrink_ctx;
    ashrink_item_t *item = NULL;

    cm_spin_lock(&ctx->lock, NULL);
    if (ctx->free_list.count == 0 && ctx->hwm >= ctx->capacity) {
        cm_spin_unlock(&ctx->lock);
        CT_THROW_ERROR(ERR_TOO_MANY_OBJECTS, ctx->capacity, "asyn shrink table");
        return CT_ERROR;
    }

    if (ctx->free_list.count > 0) {
        *item_id = ctx->free_list.first;
        ctx->free_list.first = ctx->array[*item_id].next;
        ctx->free_list.count--;
    } else {
        *item_id = ctx->hwm;
        ctx->hwm++;
    }

    if (ctx->free_list.count == 0) {
        ctx->free_list.first = CT_INVALID_ID32;
        ctx->free_list.last = CT_INVALID_ID32;
    } else {
        ctx->array[ctx->free_list.first].prev = CT_INVALID_ID32;
        knl_panic(ctx->free_list.first != CT_INVALID_ID32);
        knl_panic(ctx->free_list.last != CT_INVALID_ID32);
    }

    item = &ctx->array[*item_id];
    ashrink_init_item(item);

    cm_spin_unlock(&ctx->lock);
    return CT_SUCCESS;
}

static bool32 ashrink_match_cond(knl_session_t *session, ashrink_item_t *item,
    knl_dictionary_t *dc, bool32 check_min_scn)
{
    knl_attr_t *attr = &session->kernel->attr;

    if (dc != NULL) {
        if (item->uid != dc->uid || item->oid != dc->oid) {
            return CT_FALSE;
        }
    }

    if (!check_min_scn) {
        return CT_TRUE;
    }

    if (KNL_NOW(session) - item->begin_time > (date_t)attr->ashrink_wait_time * MICROSECS_PER_SECOND) {
        return CT_TRUE;
    }

    if (KNL_GET_SCN(&session->kernel->min_scn) >= item->shrinkable_scn) {
        return CT_TRUE;
    }

    return CT_FALSE;
}

static uint32 ashrink_find_table(knl_session_t *session, knl_dictionary_t *dc, bool32 check_min_scn)
{
    ashrink_ctx_t *ctx = &session->kernel->ashrink_ctx;

    uint32 begin = ctx->ashrink_list.first;
    while (begin != CT_INVALID_ID32) {
        ashrink_item_t *item = &ctx->array[begin];

        if (ashrink_match_cond(session, item, dc, check_min_scn)) {
            return begin;
        }

        begin = item->next;
    }

    return CT_INVALID_ID32;
}

static void ashrink_add_table(knl_session_t *session, knl_dictionary_t *dc, knl_scn_t shrinkable_scn, uint32 id)
{
    ashrink_ctx_t *ctx = &session->kernel->ashrink_ctx;
    ashrink_item_t *item = NULL;

    cm_spin_lock(&ctx->lock, NULL);

    uint32 old_id = ashrink_find_table(session, dc, CT_FALSE);
    if (old_id != CT_INVALID_ID32) {
        item = &ctx->array[old_id];
    } else {
        item = &ctx->array[id];
        ashrink_init_item(item);
        ashrink_add_list_item(session, &ctx->ashrink_list, id);
    }

    item->uid = dc->uid;
    item->oid = dc->oid;
    item->shrinkable_scn = shrinkable_scn;
    item->begin_time = KNL_NOW(session);

    cm_spin_unlock(&ctx->lock);

    if (old_id != CT_INVALID_ID32) {
        ashrink_release_item(session, id);
    }
}

static uint32 ashrink_remove_table(knl_session_t *session, bool32 check_min_scn)
{
    ashrink_ctx_t *ctx = &session->kernel->ashrink_ctx;

    cm_spin_lock(&ctx->lock, NULL);

    uint32 id = ashrink_find_table(session, NULL, check_min_scn);
    if (id != CT_INVALID_ID32) {
        ashrink_remove_list_item(session, &ctx->ashrink_list, id);
    }

    cm_spin_unlock(&ctx->lock);

    return id;
}

static void ashrink_table_space(knl_session_t *session, ashrink_item_t *item, knl_dictionary_t *dc)
{
    knl_attr_t *attr = &session->kernel->attr;
    table_t *table = DC_TABLE(dc);

    dc_entity_t *entity = DC_ENTITY(dc);
    if (entity->corrupted || table == NULL) {
        CT_LOG_RUN_WAR("async shrink failed, dc corrupted.uid %u real oid %u", dc->uid, dc->oid);
        return;
    }

    if (table->ashrink_stat != ASHRINK_WAIT_SHRINK) {
        CT_LOG_RUN_INF("can't ashrink table. invalid stat %u. uid %u oid %u name %s",
            (uint32)table->ashrink_stat, dc->uid, dc->oid, table->desc.name);
        return;
    }

    bool32 async_shrink = CT_TRUE;
    if (KNL_NOW(session) - item->begin_time > (date_t)attr->ashrink_wait_time * MICROSECS_PER_SECOND) {
        async_shrink = CT_FALSE;
        CT_LOG_RUN_WAR("async shrink wait timeout, force shrink space.stat %u uid %u oid %u name %s",
            (uint32)table->ashrink_stat, dc->uid, dc->oid, table->desc.name);
    }

    if (heap_shrink_spaces(session, dc, async_shrink) != CT_SUCCESS) {
        CT_LOG_RUN_WAR("failed asyn shrink table.uid %u oid %u name %s", dc->uid, dc->oid, table->desc.name);
    } else {
        CT_LOG_DEBUG_INF("finish async shrink table.uid %u oid %u name %s", dc->uid, dc->oid, table->desc.name);
    }
}

static void ashrink_try_shrink_space(knl_session_t *session, uint32 id)
{
    ashrink_ctx_t *ctx = &session->kernel->ashrink_ctx;
    ashrink_item_t *item = &ctx->array[id];
    knl_dictionary_t dc;

    if (knl_open_dc_by_id(session, item->uid, item->oid, &dc, CT_TRUE) != CT_SUCCESS) {
        CT_LOG_RUN_WAR("async shrink open dc failed,skip ashrink.uid %u oid %u", dc.uid, dc.oid);
        ashrink_release_item(session, id);
        return;
    }
    
    if (knl_ddl_latch_s(&session->kernel->db.ddl_latch, session, NULL) != CT_SUCCESS) {
        CT_LOG_RUN_WAR("async shrink lock ddl failed,retry ashrink.uid %u oid %u", dc.uid, dc.oid);
        ashrink_add_table(session, &dc, DB_CURR_SCN(session), id);
        dc_close(&dc);
        return;
    }

    if (lock_table_directly(session, &dc, session->kernel->attr.ddl_lock_timeout) != CT_SUCCESS) {
        CT_LOG_RUN_WAR("async shrink lock table failed,retry ashrink.uid %u oid %u", dc.uid, dc.oid);
        ashrink_add_table(session, &dc, DB_CURR_SCN(session), id);
        dls_unlatch(session, &session->kernel->db.ddl_latch, NULL);
        dc_close(&dc);
        return;
    }

    // check if curr table item is repeated
    cm_spin_lock(&ctx->lock, NULL);
    uint32 repeat_id = ashrink_find_table(session, &dc, CT_FALSE);
    cm_spin_unlock(&ctx->lock);

    dc_entity_t *entity = DC_ENTITY(&dc);

    if (repeat_id != CT_INVALID_ID32) {
        CT_LOG_RUN_WAR("will ashrink table later. uid %u oid %u", dc.uid, dc.oid);
    } else {
        ashrink_table_space(session, item, &dc);
        dc_invalidate(session, entity);
    }

    unlock_tables_directly(session);
    dls_unlatch(session, &session->kernel->db.ddl_latch, NULL);
    dc_close(&dc);

    ashrink_release_item(session, id);
    knl_rollback(session, NULL);
}

void ashrink_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    ashrink_ctx_t *ctx = &session->kernel->ashrink_ctx;
    switch_ctrl_t *switch_ctrl = &session->kernel->switch_ctrl;

    cm_set_thread_name("ashrink");
    CT_LOG_RUN_INF("ashrink thread started");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());

    while (!thread->closed) {
        ctx->working = CT_FALSE;
        session->status = SESSION_INACTIVE;

        if (session->kernel->db.status != DB_STATUS_OPEN) {
            cm_sleep(MILLISECS_PER_SECOND);
            continue;
        }

        if (DB_IS_MAINTENANCE(session) || DB_IS_READONLY(session)
            || ctx->ashrink_list.count == 0 || switch_ctrl->request != SWITCH_REQ_NONE) {
            cm_sleep(MILLISECS_PER_SECOND);
            continue;
        }

        session->status = SESSION_ACTIVE;
        db_set_with_switchctrl_lock(switch_ctrl, &ctx->working);
        if (!ctx->working) {
            cm_sleep(MILLISECS_PER_SECOND);
            continue;
        }

        uint32 id = ashrink_remove_table(session, CT_TRUE);
        if (id == CT_INVALID_ID32) {
            cm_sleep(MILLISECS_PER_SECOND);
            continue;
        }

        ashrink_try_shrink_space(session, id);
    }

    ctx->working = CT_FALSE;
    CT_LOG_RUN_INF("ashrink thread closed");
    KNL_SESSION_CLEAR_THREADID(session);
}

status_t ashrink_init(knl_session_t *session)
{
    ashrink_ctx_t *ctx = &session->kernel->ashrink_ctx;
    if (!mpool_try_alloc_page(session->kernel->attr.large_pool, &ctx->large_pool_id)) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, CT_LARGE_PAGE_SIZE, "alloc asyn shrink buffer from large pool");
        return CT_ERROR;
    }

    ctx->array = (ashrink_item_t *)mpool_page_addr(session->kernel->attr.large_pool, ctx->large_pool_id);
    ctx->capacity = CT_LARGE_PAGE_SIZE / sizeof(ashrink_item_t);
    ctx->hwm = 0;
    ctx->free_list.count = 0;
    ctx->free_list.first = CT_INVALID_ID32;
    ctx->free_list.last = CT_INVALID_ID32;
    ctx->ashrink_list.count = 0;
    ctx->ashrink_list.first = CT_INVALID_ID32;
    ctx->ashrink_list.last = CT_INVALID_ID32;
    ctx->working = CT_FALSE;

    return CT_SUCCESS;
}

void ashrink_close(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    ashrink_ctx_t *ctx = &kernel->ashrink_ctx;
    cm_close_thread(&ctx->thread);
}

status_t ashrink_add(knl_session_t *session, knl_dictionary_t *dc, knl_scn_t shrinkable_scn)
{
    table_t *table = DC_TABLE(dc);
    uint32 item_id;

    if (ashrink_alloc_item(session, &item_id) != CT_SUCCESS) {
        CT_LOG_RUN_WAR("no ashrink item to push table.uid %u oid %u name %s",
            dc->uid, dc->oid, table->desc.name);
        return CT_ERROR;
    }
    knl_panic_log(item_id != CT_INVALID_ID32, "the item_id is invalid, panic info: table %s", table->desc.name);

    ashrink_add_table(session, dc, shrinkable_scn, item_id);
    return CT_SUCCESS;
}

static inline void ashrink_clean_table(knl_session_t *session, ashrink_item_t *item)
{
    knl_dictionary_t dc;

    if (knl_open_dc_by_id(session, item->uid, item->oid, &dc, CT_TRUE) == CT_SUCCESS) {
        table_t *table = DC_TABLE(&dc);
        if (table != NULL) {
            table->ashrink_stat = ASHRINK_END;
        }
        dc_close(&dc);
    }
}

void ashrink_clean(knl_session_t *session)
{
    uint32 id = ashrink_remove_table(session, CT_FALSE);
    ashrink_ctx_t *ctx = &session->kernel->ashrink_ctx;

    while (id != CT_INVALID_ID32) {
        ashrink_item_t *item = &ctx->array[id];
        ashrink_clean_table(session, item);
        ashrink_release_item(session, id);
        id = ashrink_remove_table(session, CT_FALSE);
    }
}
