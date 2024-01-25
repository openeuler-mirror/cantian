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
 * pl_dc_util.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/persist/pl_dc_util.c
 *
 * -------------------------------------------------------------------------
 */

#include "pl_dc_util.h"
#include "srv_instance.h"
#include "pl_memory.h"
#include "dtc_dls.h"

void pl_entry_lock(pl_entry_t *pl_entry)
{
    CM_ASSERT(pl_entry != NULL);
    cm_spin_lock(&pl_entry->lock, NULL);
}

void pl_entry_unlock(pl_entry_t *pl_entry)
{
    CM_ASSERT(pl_entry != NULL);
    cm_spin_unlock(&pl_entry->lock);
}

void pl_entity_lock(pl_entity_t *pl_entity)
{
    CM_ASSERT(pl_entity != NULL);
    cm_spin_lock(&pl_entity->lock, NULL);
}

void pl_entity_unlock(pl_entity_t *pl_entity)
{
    CM_ASSERT(pl_entity != NULL);
    cm_spin_unlock(&pl_entity->lock);
}

void pl_set_entity_valid(pl_entity_t *pl_entity, bool8 valid)
{
    if (pl_entity == NULL) {
        return;
    }

    pl_entity_lock(pl_entity);
    pl_entity->valid = valid;
    pl_entity_unlock(pl_entity);
}

void pl_entity_invalidate_by_entry(pl_entry_t *pl_entry)
{
    if (pl_entry == NULL) {
        return;
    }

    pl_entry_lock(pl_entry);
    if (pl_entry->entity != NULL) {
        pl_set_entity_valid(pl_entry->entity, CT_FALSE);
        pl_entry->entity = NULL;
    }
    pl_entry_unlock(pl_entry);
}

// it needs to be ensured that entity ref_count > 0, such as in pl execute
// if there is entry you can use, it is better call function pl_entity_invalidate_by_entry
void pl_entity_invalidate(pl_entity_t *pl_entity)
{
    if (pl_entity == NULL) {
        return;
    }

    pl_entry_t *entry = pl_entity->entry;
    if (entry != NULL) {
        pl_entry_lock(entry);
        if (entry->entity == pl_entity) {
            entry->entity = NULL;
        }
        pl_entry_unlock(entry);
    }

    pl_set_entity_valid(pl_entity, CT_FALSE);
}

void pl_update_entry_desc(pl_entry_t *entry, pl_desc_t *desc)
{
    pl_entry_lock(entry);
    entry->entity = NULL;
    if (entry->desc.type == PL_TRIGGER) {
        entry->desc.trig_def = desc->trig_def;
    }
    entry->desc.chg_scn = desc->chg_scn;
    entry->desc.status = desc->status;
    entry->desc.flags = desc->flags;
    pl_entry_unlock(entry);
}


void pl_list_insert_head(pl_list_t *list_node, bilist_node_t *node, bool32 need_lock)
{
    if (need_lock) {
        cm_latch_x(&list_node->latch, CM_THREAD_ID, NULL);
    }
    cm_bilist_add_head(node, &list_node->lst);
    if (need_lock) {
        cm_unlatch(&list_node->latch, NULL);
    }
}

void pl_list_del(pl_list_t *list_node, bilist_node_t *node, bool32 need_lock)
{
    if (need_lock) {
        cm_latch_x(&list_node->latch, CM_THREAD_ID, NULL);
    }
    cm_bilist_del(node, &list_node->lst);
    if (need_lock) {
        cm_unlatch(&list_node->latch, NULL);
    }
}

void pl_lru_shift(pl_list_t *list_node, bilist_node_t *node, bool32 need_lock)
{
    if (need_lock) {
        cm_latch_x(&list_node->latch, CM_THREAD_ID, NULL);
    }

    pl_lru_remove(list_node, node, CT_FALSE);
    pl_lru_insert(list_node, node, CT_FALSE);

    if (need_lock) {
        cm_unlatch(&list_node->latch, NULL);
    }
}

void pl_entry_delete_from_oid_bucket(pl_entry_t *entry)
{
    pl_manager_t *mngr = GET_PL_MGR;
    uint32 bucket_id = cm_hash_uint32((uint32)entry->desc.oid, PL_ENTRY_OID_BUCKET_SIZE);
    pl_list_t *pl_list = &mngr->entry_oid_buckets[bucket_id];

    pl_list_del(pl_list, &entry->oid_link, CT_TRUE);
}

void pl_entry_drop(pl_entry_t *pl_entry)
{
    pl_manager_t *mngr = GET_PL_MGR;
    uint32 uid = pl_entry->desc.uid;
    pl_list_t *entry_name_lst = &mngr->entry_name_buckets[pl_entry->bucket_id];

    CT_LOG_DEBUG_INF("FREE PL ENTRY, USER=%d, NAME=%s, type=%d", uid, pl_entry->desc.name, pl_entry->desc.type);

    pl_entry_lock(pl_entry);
    pl_entry->ready = CT_FALSE;
    pl_entry->entity = NULL;
    pl_entry->desc.chg_scn = 0;
    pl_entry->desc.org_scn = 0;
    pl_entry_unlock(pl_entry);

    pl_list_del(entry_name_lst, &pl_entry->bucket_link, CT_TRUE);
    pl_entry_delete_from_oid_bucket(pl_entry);
}

void pl_free_entry(pl_entry_t *entry)
{
    pl_manager_t *mngr = GET_PL_MGR;

    pl_list_insert_head(&mngr->free_entry, &entry->free_link, CT_TRUE);
}

void pl_set_entry_status(pl_entry_t *pl_entry, bool32 ready)
{
    pl_entry_lock(pl_entry);
    pl_entry->ready = ready;
    pl_entry_unlock(pl_entry);
}

void pl_desc_set_trig_def(pl_desc_t *desc, trig_desc_t *trig_desc)
{
    desc->trig_def.obj_oid = trig_desc->base_obj;
    desc->trig_def.obj_uid = trig_desc->obj_uid;
}

status_t pl_alloc_source_page(knl_session_t *sess, pl_source_pages_t *source_pages, uint32 source_len, char **ret_buf,
    bool32 *new_page)
{
    char *buf = NULL;
    if ((source_pages->curr_page_id != CT_INVALID_ID32) &&
        (source_pages->curr_page_pos + source_len < g_instance->sga.large_pool.page_size)) { // not overflow
        buf = mpool_page_addr(&g_instance->sga.large_pool, source_pages->curr_page_id);
        buf += source_pages->curr_page_pos;        // not overflow
        source_pages->curr_page_pos += source_len; // not overflow
        *new_page = CT_FALSE;
    } else {
        knl_begin_session_wait(sess, LARGE_POOL_ALLOC, CT_FALSE);
        if (mpool_alloc_page_wait(&g_instance->sga.large_pool, &source_pages->curr_page_id, CM_MPOOL_ALLOC_WAIT_TIME) !=
            CT_SUCCESS) {
            knl_end_session_wait(sess, LARGE_POOL_ALLOC);
            return CT_ERROR;
        }
        knl_end_session_wait(sess, LARGE_POOL_ALLOC);
        buf = mpool_page_addr(&g_instance->sga.large_pool, source_pages->curr_page_id);
        source_pages->curr_page_pos = source_len;
        *new_page = CT_TRUE;
    }
    *ret_buf = buf;
    return CT_SUCCESS;
}

void pl_free_source_page(pl_source_pages_t *src_page, bool32 new_page)
{
    if (new_page) {
        mpool_free_page(&g_instance->sga.large_pool, src_page->curr_page_id);
    }
}

void pl_entity_ref_inc(pl_entity_t *pl_entity)
{
    pl_entity_lock(pl_entity);
    pl_entity->ref_count++;
    pl_entity_unlock(pl_entity);
}

void pl_entity_ref_dec(pl_entity_t *pl_entity)
{
    pl_entity_lock(pl_entity);
    CM_ASSERT(pl_entity->ref_count > 0);
    pl_entity->ref_count--;
    pl_entity_unlock(pl_entity);
}

void pl_entity_uncacheable(pl_entity_t *pl_entity)
{
    if (pl_entity == NULL) {
        return;
    }

    pl_entity->cacheable = CT_FALSE;
}

bool32 pl_entry_check(pl_entry_t *entry, uint32 uid, const char *name, uint32 type)
{
    CM_ASSERT(type != 0);

    if (entry->desc.uid != uid || !cm_str_equal(name, entry->desc.name) || !(type & entry->desc.type)) {
        return CT_FALSE;
    }

    return CT_TRUE;
}

static void pl_find_entry_core(dc_user_t *dc_user, text_t *name, uint32 type, pl_entry_t **entry_out, bool32 *found,
    bool32 *ready)
{
    pl_manager_t *mngr = GET_PL_MGR;
    uint32 uid = dc_user->desc.id;

    *entry_out = NULL;
    *ready = CT_FALSE;
    *found = CT_FALSE;

    uint32 bucket_id = cm_hash_string(T2S(name), PL_ENTRY_NAME_BUCKET_SIZE);
    pl_list_t *bucket = &mngr->entry_name_buckets[bucket_id];
    pl_entry_t *entry = NULL;

    cm_latch_s(&bucket->latch, CM_THREAD_ID, CT_FALSE, NULL);
    BILIST_SEARCH(&bucket->lst, pl_entry_t, entry, bucket_link, pl_entry_check(entry, uid, T2S(name), type));
    if (entry == NULL) {
        cm_unlatch(&bucket->latch, NULL);
        return;
    }

    *found = CT_TRUE;
    *entry_out = entry;
    pl_entry_lock(entry);
    *ready = entry->ready;
    pl_entry_unlock(entry);
    cm_unlatch(&bucket->latch, NULL);
}

status_t pl_find_entry(knl_session_t *session, text_t *user, text_t *name, uint32 type, pl_entry_t **entry_out,
    bool32 *found)
{
    pl_entry_t *entry = NULL;
    dc_user_t *dc_user = NULL;
    bool32 ready = CT_FALSE;

    CT_RETURN_IFERR(dc_open_user(session, user, &dc_user));
    dls_latch_x(session, &dc_user->user_latch, session->id, NULL);
    while (CT_TRUE) {
        pl_find_entry_core(dc_user, name, type, &entry, found, &ready);
        if (!*found) {
            dls_unlatch(session, &dc_user->user_latch, NULL);
            return CT_SUCCESS;
        }
        if (ready) {
            break;
        }
        cm_sleep(1);
    }
    dls_unlatch(session, &dc_user->user_latch, NULL);
    if (entry_out != NULL) {
        *entry_out = entry;
    }
    return CT_SUCCESS;
}

status_t pl_find_entry_with_public(knl_session_t *session, text_t *user, text_t *name, bool32 explict, uint32 type,
    pl_entry_t **entry_out, bool32 *found)
{
    pl_entry_t *entry = NULL;
    bool32 exist = CT_FALSE;

    *found = CT_FALSE;
    // find entry user.name
    CT_RETURN_IFERR(pl_find_entry(session, user, name, type, &entry, &exist));
    if (!exist) {
        if (explict) {
            CT_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "object", T2S(user), T2S_EX(name));
            return CT_ERROR;
        }

        text_t pub_user;
        cm_str2text(PUBLIC_USER, &pub_user);
        // find entry public.name
        CT_RETURN_IFERR(pl_find_entry(session, &pub_user, name, type, &entry, &exist));
        if (!exist) {
            CT_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "object", T2S(user), T2S_EX(name));
            return CT_ERROR;
        }
    }

    if (entry->desc.type == PL_SYNONYM) {
        text_t link_owner;
        text_t link_name;

        cm_str2text(entry->desc.link_user, &link_owner);
        cm_str2text(entry->desc.link_name, &link_name);
        // find entry link_owner.link_name
        CT_RETURN_IFERR(pl_find_entry(session, &link_owner, &link_name, type, &entry, &exist));
        if (!exist) {
            CT_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "object", T2S(&link_owner), T2S_EX(&link_name));
            return CT_ERROR;
        }
    }

    *entry_out = entry;
    *found = CT_TRUE;
    return CT_SUCCESS;
}

static uint32 pl_get_find_type_for_create(uint32 type)
{
    switch (type) {
        case PL_PROCEDURE:
        case PL_FUNCTION:
        case PL_PACKAGE_SPEC:
        case PL_TYPE_SPEC:
        case PL_SYNONYM:
        case PL_PROCEDURE | PL_FUNCTION:
        case PL_PACKAGE_SPEC | PL_SYS_PACKAGE:
            return PL_OBJECTS;
        case PL_SYS_PACKAGE:
        case PL_TRIGGER:
        case PL_PACKAGE_BODY:
        case PL_TYPE_BODY:
            return type;
        default:
            return PL_UNKNOWN;
    }
}

static status_t pl_find_or_create_entry_core(sql_stmt_t *stmt, dc_user_t *dc_user, pl_desc_t *desc,
    pl_entry_info_t *entry_info, bool32 *found, bool32 *ready)
{
    pl_manager_t *pl_manager = GET_PL_MGR;
    uint32 type = desc->type;
    uint32 find_type = pl_get_find_type_for_create(type);
    char *name = desc->name;
    uint32 uid = dc_user->desc.id;
    uint32 bucket_id = cm_hash_string(name, PL_ENTRY_NAME_BUCKET_SIZE);
    pl_list_t *bucket = &pl_manager->entry_name_buckets[bucket_id];
    pl_entry_t *entry = NULL;

    *found = CT_FALSE;
    *ready = CT_FALSE;
    cm_latch_x(&bucket->latch, CM_THREAD_ID, NULL);
    BILIST_SEARCH(&bucket->lst, pl_entry_t, entry, bucket_link, pl_entry_check(entry, uid, name, find_type));
    if (entry != NULL) {
        if (entry->desc.type != type) {
            cm_unlatch(&bucket->latch, NULL);
            CT_THROW_ERROR(ERR_DUPLICATE_NAME, "object", name);
            return CT_ERROR;
        }
        *found = CT_TRUE;
        entry_info->entry = entry;
        pl_entry_lock(entry);
        entry_info->scn = entry->desc.chg_scn;
        *ready = entry->ready;
        pl_entry_unlock(entry);
        cm_unlatch(&bucket->latch, NULL);
        return CT_SUCCESS;
    }

    if (sql_alloc_object_id(stmt, (int64 *)&desc->oid) != CT_SUCCESS) {
        cm_unlatch(&bucket->latch, NULL);
        return CT_ERROR;
    }

    if (pl_alloc_entry(&entry) != CT_SUCCESS) {
        cm_unlatch(&bucket->latch, NULL);
        return CT_ERROR;
    }

    *ready = CT_TRUE;
    entry->desc = *desc;
    entry_info->entry = entry;
    entry_info->scn = entry->desc.chg_scn;
    pl_list_insert_head(bucket, &entry->bucket_link, CT_FALSE);
    pl_entry_insert_into_oid_bucket(entry);
    entry->bucket_id = bucket_id;
    cm_unlatch(&bucket->latch, NULL);
    return CT_SUCCESS;
}

status_t pl_find_or_create_entry(sql_stmt_t *stmt, dc_user_t *dc_user, pl_desc_t *desc, pl_entry_info_t *entry_info,
    bool32 *found)
{
    bool32 ready = CT_FALSE;

    while (CT_TRUE) {
        CT_RETURN_IFERR(pl_find_or_create_entry_core(stmt, dc_user, desc, entry_info, found, &ready));
        if (ready) {
            break;
        }
        cm_sleep(1);
    }

    return CT_SUCCESS;
}

static void pl_find_entry_for_desc_core(dc_user_t *dc_user, text_t *name, uint32 type, pl_entry_info_t *entry_info,
    bool32 *found, bool32 *ready)
{
    pl_manager_t *mngr = GET_PL_MGR;
    uint32 bucket_id = cm_hash_string(T2S(name), PL_ENTRY_NAME_BUCKET_SIZE);
    pl_list_t *bucket = &mngr->entry_name_buckets[bucket_id];
    pl_entry_t *entry = NULL;
    uint32 uid = dc_user->desc.id;

    *ready = CT_FALSE;
    *found = CT_FALSE;
    cm_latch_s(&bucket->latch, CM_THREAD_ID, CT_FALSE, NULL);
    BILIST_SEARCH(&bucket->lst, pl_entry_t, entry, bucket_link, pl_entry_check(entry, uid, T2S(name), type));
    if (entry == NULL) {
        cm_unlatch(&bucket->latch, NULL);
        return;
    }

    *found = CT_TRUE;
    pl_entry_lock(entry);
    entry_info->entry = entry;
    entry_info->scn = entry->desc.chg_scn;
    *ready = entry->ready;
    pl_entry_unlock(entry);
    cm_unlatch(&bucket->latch, NULL);
}

// already get user_latch
void pl_find_entry_for_desc(dc_user_t *dc_user, text_t *name, uint32 type, pl_entry_info_t *entry_info, bool32 *found)
{
    bool32 ready = CT_FALSE;
    entry_info->entry = NULL;
    while (CT_TRUE) {
        pl_find_entry_for_desc_core(dc_user, name, type, entry_info, found, &ready);
        if (!*found) {
            break;
        }
        if (ready) {
            break;
        }
        cm_sleep(1);
    }
}

void pl_free_broken_entry(pl_entry_t *entry)
{
    pl_manager_t *mngr = GET_PL_MGR;
    pl_list_t *entry_name_bucket = &mngr->entry_name_buckets[entry->bucket_id];

    pl_set_entry_status(entry, CT_FALSE);
    pl_list_del(entry_name_bucket, &entry->bucket_link, CT_TRUE);
    pl_entry_delete_from_oid_bucket(entry);
    pl_list_insert_head(&mngr->free_entry, &entry->free_link, CT_TRUE);
}

static bool32 pl_entry_check_by_oid(pl_entry_t *entry, uint64 oid, uint32 type)
{
    CM_ASSERT(type != 0);

    if (entry->desc.oid != oid) {
        return CT_FALSE;
    }

    if (type & entry->desc.type) {
        return CT_TRUE;
    }

    return CT_TRUE;
}

void pl_try_find_entry_by_oid_core(uint64 oid, uint32 type, pl_entry_info_t *entry_info, bool32 *ready)
{
    pl_manager_t *mngr = GET_PL_MGR;
    uint32 bucket_id = cm_hash_uint32((uint32)oid, PL_ENTRY_OID_BUCKET_SIZE);
    pl_list_t *bucket_lst = &mngr->entry_oid_buckets[bucket_id];
    pl_entry_t *entry = NULL;

    // try find entry in target lst
    cm_latch_s(&bucket_lst->latch, CM_THREAD_ID, CT_FALSE, NULL);
    BILIST_SEARCH(&bucket_lst->lst, pl_entry_t, entry, oid_link, pl_entry_check_by_oid(entry, oid, type));
    if (entry != NULL) {
        pl_entry_lock(entry);
        entry_info->entry = entry;
        entry_info->scn = entry->desc.chg_scn;
        *ready = entry->ready;
        pl_entry_unlock(entry);
    }
    cm_unlatch(&bucket_lst->latch, NULL);
}

void pl_find_entry_by_oid(uint64 oid, uint32 type, pl_entry_info_t *entry_info)
{
    bool32 ready = CT_FALSE;
    entry_info->entry = NULL;
    while (CT_TRUE) {
        pl_try_find_entry_by_oid_core(oid, type, entry_info, &ready);
        if (entry_info->entry == NULL || ready) {
            break;
        }
        cm_sleep(1);
    }
    return;
}

void pl_set_entity(pl_entry_t *entry, pl_entity_t **entity_out)
{
    pl_manager_t *mngr = GET_PL_MGR;
    pl_entity_t *entity = *entity_out;
    pl_list_t *lru_list = &mngr->pl_entity_lru[entity->lru_hash];

    if (!entity->cacheable) {
        entity->ref_count = 1;
        entity->valid = CT_TRUE;
        return;
    }

    cm_latch_x(&lru_list->latch, CM_THREAD_ID, NULL);
    pl_entry_lock(entry);
    if (entry->entity == NULL) {
        pl_entity_lock(entity);
        entity->valid = CT_TRUE;
        entity->cached = CT_TRUE;
        entity->ref_count++;
        pl_entity_unlock(entity);
        entry->entity = entity;
        pl_entry_unlock(entry);
        pl_lru_insert(lru_list, &entity->lru_link, CT_FALSE);
    } else {
        pl_free_entity(entity); // has not been used
        pl_entity_ref_inc(entry->entity);
        *entity_out = entry->entity;
        pl_entry_unlock(entry);
        pl_lru_shift(lru_list, &(*entity_out)->lru_link, CT_FALSE);
    }
    cm_unlatch(&lru_list->latch, NULL);
}

void pl_set_entity_for_recompile(pl_entry_t *entry, pl_entity_t *entity)
{
    pl_manager_t *mngr = GET_PL_MGR;
    pl_list_t *lru_list = &mngr->pl_entity_lru[entity->lru_hash];

    if (!entity->cacheable) {
        pl_free_entity(entity);
        return;
    }

    entity->valid = CT_TRUE;
    entity->cached = CT_TRUE;
    cm_latch_x(&lru_list->latch, CM_THREAD_ID, NULL);
    pl_entry_lock(entry);
    if (entry->entity != NULL) {
        pl_set_entity_valid(entry->entity, CT_FALSE);
    }
    entry->entity = entity;
    pl_entry_unlock(entry);
    pl_lru_insert(lru_list, &entity->lru_link, CT_FALSE);
    cm_unlatch(&lru_list->latch, NULL);
}

void pl_entry_insert_into_oid_bucket(pl_entry_t *entry)
{
    pl_manager_t *mngr = GET_PL_MGR;
    uint32 bucket_id = cm_hash_uint32((uint32)entry->desc.oid, PL_ENTRY_OID_BUCKET_SIZE);
    pl_list_t *pl_list = &mngr->entry_oid_buckets[bucket_id];

    pl_list_insert_head(pl_list, &entry->oid_link, CT_TRUE);
}
