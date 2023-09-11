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
 * dc_seq.c
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/dc_seq.c
 *
 * -------------------------------------------------------------------------
 */
#include "dc_seq.h"
#include "cm_log.h"
#include "knl_context.h"
#include "dc_util.h"
#include "dtc_dls.h"

/*
* Description     : Insert an dc entry of a sequence to user hash bucket
* Input           : user, sequence entry
* Output          : NA
* Return Value    : void
* History         : 1. 2017/4/26,  add description
*/
void dc_insert_into_seqindex(dc_user_t *user, sequence_entry_t *entry)
{
    sequence_entry_t *first_entry = NULL;
    dc_bucket_t *bucket = NULL;
    uint32 hash;
    text_t name;

    cm_str2text(entry->name, &name);
    hash = dc_hash(&name);
    bucket = &user->sequence_set.buckets[hash];
    cm_spin_lock(&bucket->lock, NULL);
    entry->bucket = bucket;
    entry->user = user;
    entry->next = bucket->first;
    entry->prev = GS_INVALID_ID32;
    entry->entity = NULL;

    if (bucket->first != GS_INVALID_ID32) {
        first_entry = DC_GET_SEQ_ENTRY(user, bucket->first);
        first_entry->prev = entry->id;
    }

    bucket->first = entry->id;
    cm_spin_unlock(&bucket->lock);
}

void dc_convert_seq_desc(knl_cursor_t *cursor, sequence_desc_t *desc)
{
    text_t text;

    desc->uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SEQUENCE_COL_UID);
    desc->id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SEQUENCE_COL_ID);

    text.str = CURSOR_COLUMN_DATA(cursor, SYS_SEQUENCE_COL_NAME);
    text.len = CURSOR_COLUMN_SIZE(cursor, SYS_SEQUENCE_COL_NAME);
    (void)cm_text2str(&text, desc->name, GS_MAX_NAME_LEN + 1);

    desc->minval = *(int64 *)CURSOR_COLUMN_DATA(cursor, SYS_SEQUENCE_COL_MINVAL);
    desc->maxval = *(int64 *)CURSOR_COLUMN_DATA(cursor, SYS_SEQUENCE_COL_MAXVAL);
    desc->step = *(int64 *)CURSOR_COLUMN_DATA(cursor, SYS_SEQUENCE_COL_STEP);
    desc->cache = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_SEQUENCE_COL_CACHESIZE);
    desc->is_cyclable = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SEQUENCE_COL_CYCLE_FLAG);
    desc->is_order = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SEQUENCE_COL_ORDER_FLAG);
    desc->is_cache = (desc->cache > 0);
    desc->org_scn = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_SEQUENCE_COL_ORG_SCN);
    desc->chg_scn = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_SEQUENCE_COL_CHG_SCN);
    desc->lastval = *(int64 *)CURSOR_COLUMN_DATA(cursor, SYS_SEQUENCE_COL_LAST_NUMBER);
#ifdef Z_SHARDING
    desc->dist_data.size = CURSOR_COLUMN_SIZE(cursor, SYS_SEQUENCE_COL_DIST_DATA);
    desc->dist_data.bytes = (uint8 *)CURSOR_COLUMN_DATA(cursor, SYS_SEQUENCE_COL_DIST_DATA);
#endif
}

static status_t dc_init_sequence_context(dc_context_t *ctx, sequence_set_t *sequence_set)
{
    uint32 i, page_id;
    errno_t err;

    if (dc_alloc_memory_page(ctx, &page_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    sequence_set->groups = (sequence_group_t **)mpool_page_addr(&ctx->pool, page_id);
    err = memset_sp(sequence_set->groups, GS_SHARED_PAGE_SIZE, 0, GS_SHARED_PAGE_SIZE);
    knl_securec_check(err);

    if (dc_alloc_memory_page(ctx, &page_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    sequence_set->buckets = (dc_bucket_t *)mpool_page_addr(&ctx->pool, page_id);
    for (i = 0; i < DC_HASH_SIZE; i++) {
        sequence_set->buckets[i].lock = 0;
        sequence_set->buckets[i].first = GS_INVALID_ID32;
    }

    return GS_SUCCESS;
}

static status_t dc_init_sequence_entries(knl_session_t *session, dc_context_t *ctx, uint32 uid)
{
    sequence_desc_t desc;
    dc_user_t *user = NULL;
    sequence_entry_t *entry = NULL;
    errno_t err;

    CM_SAVE_STACK(session->stack);

    if (dc_open_user_by_id(session, uid, &user) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_cursor_t *cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SEQ_ID, SYS_SEQ001_ID);
    knl_scan_key_t *l_border = &cursor->scan_range.l_key;
    knl_scan_key_t *r_border = &cursor->scan_range.r_key;
    knl_init_index_scan(cursor, GS_FALSE);

    knl_set_scan_key(INDEX_DESC(cursor->index), l_border, GS_TYPE_INTEGER, (void *)&uid, sizeof(uint32),
                     IX_COL_SYS_SEQ001_UID);
    knl_set_key_flag(l_border, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SEQ001_NAME);
    knl_set_scan_key(INDEX_DESC(cursor->index), r_border, GS_TYPE_INTEGER, (void *)&uid, sizeof(uint32),
                     IX_COL_SYS_SEQ001_UID);
    knl_set_key_flag(r_border, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SEQ001_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) { // assert?
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        dc_convert_seq_desc(cursor, &desc);
        if (dc_create_sequence_entry(session, user, desc.id, &entry) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        knl_panic(entry != NULL);
        entry->entity = NULL;
        entry->org_scn = desc.org_scn;
        entry->chg_scn = desc.chg_scn;
        err = memcpy_sp(entry->name, GS_NAME_BUFFER_SIZE, desc.name, GS_MAX_NAME_LEN + 1);
        knl_securec_check(err);

        dc_insert_into_seqindex(user, entry);

        if (desc.id >= user->sequence_set.sequence_hwm) {
            user->sequence_set.sequence_hwm = desc.id + 1;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) { // assert?
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

static status_t dc_load_sequence(knl_session_t *session, knl_cursor_t *cursor, dc_user_t *user, text_t *seq_name,
    dc_sequence_t *seq_entity)
{
    text_t text;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SEQ_ID, SYS_SEQ001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &user->desc.id,
                     sizeof(uint32), IX_COL_SYS_SEQ001_UID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, seq_name->str,
                     seq_name->len, IX_COL_SYS_SEQ001_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cursor->eof) {
        GS_THROW_ERROR(ERR_SEQ_NOT_EXIST, user->desc.name, T2S(seq_name));
        return GS_ERROR;
    }

    seq_entity->uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SEQUENCE_COL_UID);
    seq_entity->id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SEQUENCE_COL_ID);
    text.str = CURSOR_COLUMN_DATA(cursor, SYS_SEQUENCE_COL_NAME);
    text.len = CURSOR_COLUMN_SIZE(cursor, SYS_SEQUENCE_COL_NAME);
    (void)cm_text2str(&text, seq_entity->name, GS_MAX_NAME_LEN + 1);
    seq_entity->minval = *(int64 *)CURSOR_COLUMN_DATA(cursor, SYS_SEQUENCE_COL_MINVAL);
    seq_entity->maxval = *(int64 *)CURSOR_COLUMN_DATA(cursor, SYS_SEQUENCE_COL_MAXVAL);
    seq_entity->step = *(int64 *)CURSOR_COLUMN_DATA(cursor, SYS_SEQUENCE_COL_STEP);
    seq_entity->cache_size = *(int64 *)CURSOR_COLUMN_DATA(cursor, SYS_SEQUENCE_COL_CACHESIZE);
    seq_entity->is_cyclable = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SEQUENCE_COL_CYCLE_FLAG);
    seq_entity->is_order = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SEQUENCE_COL_ORDER_FLAG);
    seq_entity->entry->org_scn = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_SEQUENCE_COL_ORG_SCN);
    seq_entity->entry->chg_scn = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_SEQUENCE_COL_CHG_SCN);
    seq_entity->lastval = *(int64 *)CURSOR_COLUMN_DATA(cursor, SYS_SEQUENCE_COL_LAST_NUMBER);
    seq_entity->rsv_nextval = seq_entity->lastval;
    seq_entity->is_cache = (seq_entity->cache_size > 0);
    seq_entity->cache_pos = seq_entity->is_cache ? seq_entity->cache_size - 1 : 0;
    seq_entity->dist_data.size = CURSOR_COLUMN_SIZE(cursor, SYS_SEQUENCE_COL_DIST_DATA);
#ifdef Z_SHARDING
    if (seq_entity->dist_data.size > 0 && seq_entity->dist_data.size <= GS_DISTRIBUTE_BUFFER_SIZE) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, seq_entity->memory, seq_entity->dist_data.size,
            (void **)&seq_entity->dist_data.bytes) != GS_SUCCESS) {
            return GS_ERROR;
        }
        errno_t err = memcpy_sp(seq_entity->dist_data.bytes, seq_entity->dist_data.size,
            CURSOR_COLUMN_DATA(cursor, SYS_SEQUENCE_COL_DIST_DATA), seq_entity->dist_data.size);
        knl_securec_check(err);
    }
#endif

    return GS_SUCCESS;
}

static status_t dc_seq_load(knl_session_t *session, dc_user_t *user, text_t *name, sequence_entry_t *entry)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    memory_context_t *memory = NULL;
    knl_cursor_t *cursor = NULL;
    errno_t err;

    if (dc_create_memory_context(ctx, &memory) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dc_alloc_mem(&session->kernel->dc_ctx, memory, sizeof(dc_sequence_t), (void **)&entry->entity) != GS_SUCCESS) {
        return GS_ERROR;
    }

    err = memset_sp(entry->entity, sizeof(dc_sequence_t), 0, sizeof(dc_sequence_t));
    knl_securec_check(err);
    entry->entity->entry = entry;
    entry->entity->memory = memory;
    entry->entity->valid = GS_TRUE;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    if (dc_load_sequence(session, cursor, user, name, entry->entity) != GS_SUCCESS) {
        mctx_destroy(memory);
        entry->entity = NULL;
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t dc_init_sequence_set(knl_session_t *session, dc_user_t *user)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;

    if (DB_STATUS(session) != DB_STATUS_OPEN && !(session->bootstrap)) {
        GS_THROW_ERROR(ERR_DATABASE_NOT_AVAILABLE);
        return GS_ERROR;
    }

    if (!user->sequence_set.is_loaded) {
        if (user->sequence_set.buckets == NULL) {
            if (dc_init_sequence_context(ctx, &user->sequence_set) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (dc_init_sequence_entries(session, ctx, user->desc.id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        user->sequence_set.is_loaded = GS_TRUE;
    }

    return GS_SUCCESS;
}

bool32 dc_seq_find(knl_session_t *session, dc_user_t *user, text_t *obj_name, knl_dictionary_t *dc)
{
    uint32 hash, eid;
    dc_bucket_t *bucket = NULL;
    sequence_entry_t *entry = NULL;

    hash = dc_hash(obj_name);
    bucket = &user->sequence_set.buckets[hash];

    cm_spin_lock(&bucket->lock, NULL);
    eid = bucket->first;
    entry = NULL;

    while (eid != GS_INVALID_ID32) {
        entry = DC_GET_SEQ_ENTRY(user, eid);
        knl_panic(entry != NULL);
        if (!cm_compare_text_str(obj_name, entry->name)) {
            break;
        }

        eid = entry->next;
    }

    if (eid == GS_INVALID_ID32) {
        cm_spin_unlock(&bucket->lock);
        return GS_FALSE;
    }

    dc->uid = user->desc.id;
    dc->oid = eid;

    dls_spin_lock(session, &entry->lock, NULL);
    dc->org_scn = entry->org_scn;
    dc->chg_scn = entry->chg_scn;
    dc->handle = entry->entity;
    dls_spin_unlock(session, &entry->lock);

    cm_spin_unlock(&bucket->lock);

    return GS_TRUE;
}

static inline void dc_seq_close_entity(dc_sequence_t *entity)
{
    cm_spin_lock(&entity->ref_lock, NULL);
    (void)cm_atomic32_dec(&entity->ref_count);
    if (entity->ref_count == 0 && !entity->valid) {
        cm_spin_unlock(&entity->ref_lock);
        mctx_destroy(entity->memory);
        return;
    }
    cm_spin_unlock(&entity->ref_lock);
}

void dc_seq_close(knl_dictionary_t *dc)
{
    dc_sequence_t *entity = (dc_sequence_t *)dc->handle;

    dc_seq_close_entity(entity);
}

static status_t dc_seq_open_entry(knl_session_t *session, dc_user_t *user, text_t *user_name, text_t *seq_name,
    knl_dictionary_t *dc)
{
    sequence_entry_t *entry = NULL;
    dc_sequence_t *entity = NULL;

    entry = DC_GET_SEQ_ENTRY(user, dc->oid);

    dls_spin_lock(session, &entry->lock, NULL);

    // table is dropped after dc_find
    if (dc->org_scn != entry->org_scn) {
        dls_spin_unlock(session, &entry->lock);
        GS_THROW_ERROR(ERR_SEQ_NOT_EXIST, T2S(user_name), T2S_EX(seq_name));
        return GS_ERROR;
    }

    if ((entry->entity != NULL) && (entry->entity->version != session->kernel->dc_ctx.version)) {
        cm_spin_lock(&entry->entity->ref_lock, NULL);
        entry->entity->ref_count++;
        entity = entry->entity;
        cm_spin_unlock(&entry->entity->ref_lock);
        entry->entity->valid = GS_FALSE;
        entry->entity = NULL;
        dc_seq_close_entity(entity);
    }

    if (entry->entity == NULL) {
        session->query_scn = DB_CURR_SCN(session);

        if (dc_seq_load(session, user, seq_name, entry) != GS_SUCCESS) { // create new dc entity
            dls_spin_unlock(session, &entry->lock);
            return GS_ERROR;
        }
    }

    entry->entity->version = session->kernel->dc_ctx.version;

    cm_spin_lock(&entry->entity->ref_lock, NULL);
    entry->entity->ref_count++;
    cm_spin_unlock(&entry->entity->ref_lock);
    dc->type = entry->type;
    dc->handle = entry->entity;
    dls_spin_unlock(session, &entry->lock);

    return GS_SUCCESS;
}

status_t dc_seq_open(knl_session_t *session, text_t *user_name, text_t *seq_name, knl_dictionary_t *dc)
{
    dc_user_t *user = NULL;

    if (dc_open_user(session, user_name, &user) != GS_SUCCESS) {
        cm_reset_error_user(ERR_SEQ_NOT_EXIST, T2S(user_name), T2S_EX(seq_name), ERR_TYPE_SEQUENCE);
        return GS_ERROR;
    }

    if (SECUREC_UNLIKELY(!user->sequence_set.is_loaded)) {
        dls_spin_lock(session, &user->lock, NULL);
        if (dc_init_sequence_set(session, user) != GS_SUCCESS) {
            dls_spin_unlock(session, &user->lock);
            return GS_ERROR;
        }
        dls_spin_unlock(session, &user->lock);
    }

    if (!dc_seq_find(session, user, seq_name, dc)) {
        GS_THROW_ERROR(ERR_SEQ_NOT_EXIST, T2S(user_name), T2S_EX(seq_name));
        return GS_ERROR;
    }

    if (dc_seq_open_entry(session, user, user_name, seq_name, dc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static bool32 dc_try_reuse_sequence_entry(dc_user_t *user, sequence_entry_t **entry)
{
    do {
        *entry = (sequence_entry_t *)dc_list_remove(&user->sequence_set.free_entries);

        if (*entry == NULL) {
            return GS_FALSE;
        }
    } while ((*entry)->used);

    (*entry)->is_free = GS_FALSE;
    (*entry)->used = GS_TRUE;
    return GS_TRUE;
}

status_t dc_create_sequence_entry(knl_session_t *session, dc_user_t *user, uint32 oid, sequence_entry_t **entry)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    uint32 eid, gid;
    char *page = NULL;
    sequence_set_t *sequence_set = &user->sequence_set;
    errno_t ret;

    if (oid >= DC_GROUP_COUNT * DC_GROUP_SIZE) {
        GS_THROW_ERROR(ERR_TOO_MANY_OBJECTS, DC_GROUP_COUNT * DC_GROUP_SIZE, "sequence");
        return GS_ERROR;
    }

    eid = oid % DC_GROUP_SIZE;
    gid = oid / DC_GROUP_SIZE;

    if (sequence_set->groups[gid] == NULL) {
        if (dc_alloc_page(ctx, &page) != GS_SUCCESS) {
            return GS_ERROR;
        }

        sequence_set->groups[gid] = (sequence_group_t *)page;
    }

    if (sequence_set->groups[gid]->entries[eid] == NULL) {
        if (dc_alloc_mem(ctx, user->memory, sizeof(sequence_entry_t), (void **)entry) != GS_SUCCESS) {
            return GS_ERROR;
        }

        ret = memset_sp(*entry, sizeof(sequence_entry_t), 0, sizeof(sequence_entry_t));
        knl_securec_check(ret);

        sequence_set->groups[gid]->entries[eid] = *entry;
    } else {
        *entry = sequence_set->groups[gid]->entries[eid];
    }

    (*entry)->uid = user->desc.id;
    (*entry)->id = oid;
    (*entry)->used = GS_TRUE;
    (*entry)->user = user;
    (*entry)->type = DICT_TYPE_SEQUENCE;
    dls_init_spinlock(&((*entry)->lock), DR_TYPE_SEQENCE, oid, user->desc.id);

    return GS_SUCCESS;
}

status_t dc_alloc_seq_entry(knl_session_t *session, sequence_desc_t *desc)
{
    dc_user_t *user = NULL;
    sequence_entry_t *entry = NULL;
    text_t user_name, seq_name;
    knl_dictionary_t dc;
    errno_t err;

    if (dc_open_user_by_id(session, desc->uid, &user) != GS_SUCCESS) {
        return GS_ERROR;
    }

    cm_str2text(user->desc.name, &user_name);
    cm_str2text(desc->name, &seq_name);

    dls_spin_lock(session, &user->lock, NULL);

    if (user->status != USER_STATUS_NORMAL) {
        dls_spin_unlock(session, &user->lock);
        GS_THROW_ERROR(ERR_USER_NOT_EXIST, user->desc.name);
        return GS_ERROR;
    }

    if (dc_init_sequence_set(session, user) != GS_SUCCESS) {
        dls_spin_unlock(session, &user->lock);
        return GS_ERROR;
    }

    if (dc_seq_find(session, user, &seq_name, &dc)) {
        dls_spin_unlock(session, &user->lock);
        GS_THROW_ERROR(ERR_DUPLICATE_TABLE, T2S(&user_name), T2S_EX(&seq_name));
        return GS_ERROR;
    }

    if (!dc_try_reuse_sequence_entry(user, &entry)) {
        if (dc_create_sequence_entry(session, user, user->sequence_set.sequence_hwm, &entry) != GS_SUCCESS) {
            dls_spin_unlock(session, &user->lock);
            return GS_ERROR;
        }
        user->sequence_set.sequence_hwm++;
    }

    err = memcpy_sp(entry->name, GS_NAME_BUFFER_SIZE, desc->name, GS_MAX_NAME_LEN + 1);
    knl_securec_check(err);
    desc->id = entry->id;
    entry->org_scn = desc->org_scn;
    entry->chg_scn = desc->chg_scn;
    dc_insert_into_seqindex(user, entry);
    dls_spin_unlock(session, &user->lock);

    return GS_SUCCESS;
}

void dc_remove_from_seq_bucket(knl_session_t *session, sequence_entry_t *entry)
{
    sequence_entry_t *next = NULL;
    sequence_entry_t *prev = NULL;

    cm_spin_lock(&entry->bucket->lock, NULL);
    if (entry->next != GS_INVALID_ID32) {
        next = DC_GET_SEQ_ENTRY(entry->user, entry->next);
        next->prev = entry->prev;
    }

    if (entry->prev != GS_INVALID_ID32) {
        prev = DC_GET_SEQ_ENTRY(entry->user, entry->prev);
        prev->next = entry->next;
    }

    if (entry->bucket->first == entry->id) {
        entry->bucket->first = entry->next;
    }

    cm_spin_unlock(&entry->bucket->lock);
}

void dc_sequence_drop(knl_session_t *session, sequence_entry_t *entry)
{
    dc_remove_from_seq_bucket(session, entry);

    dls_spin_lock(session, &entry->lock, NULL);
    entry->used = GS_FALSE;
    entry->org_scn = 0;
    entry->chg_scn = !DB_IS_PRIMARY(&session->kernel->db) ? 0 : db_next_scn(session);
    if (entry->entity != NULL) {
        entry->entity->valid = GS_FALSE;
    }
    entry->entity = NULL;
    dls_spin_unlock(session, &entry->lock);

    if (!entry->is_free) {
        dc_list_add(&entry->user->sequence_set.free_entries, (dc_list_node_t *)entry);
        entry->is_free = GS_TRUE;
    }
}
