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
 * knl_dc.c
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/knl_dc.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_dc_module.h"
#include "knl_spm.h"
#include "cm_log.h"
#include "knl_table.h"
#include "knl_context.h"
#include "ostat_load.h"
#include "knl_sequence.h"
#include "knl_user.h"
#include "dc_priv.h"
#include "dc_tbl.h"
#include "dc_user.h"
#include "dc_util.h"
#include "knl_ctlg.h"
#include "dc_part.h"
#include "dc_log.h"
#include "dc_tenant.h"
#include "dtc_database.h"
#include "dtc_dls.h"
#include "dtc_dcs.h"
#include "dtc_dc.h"

status_t dc_load_global_dynamic_views(knl_session_t *session);

static const char *g_dict_type_names[] = { "TABLE", "TRANSACTION TEMP TABLE", "SESSION TEMP TABLE", "NOLOGGING TABLE",
                                           "EXTERNAL TABLE", "VIEW", "DYNAMIC_VIEW", "GLOBAL_DYNAMIC_VIEW",
                                           "SYNONYM", "DISTRIBUTED_RULE", "SEQUENCE" };

bool32 dc_locked_by_self(knl_session_t *session, dc_entry_t *entry)
{
    schema_lock_t *lock = entry->sch_lock;

    if (IS_LTT_BY_ID(entry->id)) {
        return (entry->ltt_lock_mode != LOCK_MODE_IDLE);
    } else {
        return (bool32)(lock != NULL && lock->map[(session)->rmid]);
    }
}

bool32 dc_is_locked(dc_entry_t *entry)
{
    schema_lock_t *lock = entry->sch_lock;

    if (IS_LTT_BY_ID(entry->id)) {
        return (entry->ltt_lock_mode != LOCK_MODE_IDLE);
    } else {
        return (bool32)(lock != NULL && lock->mode != LOCK_MODE_IDLE);
    }
}

bool32 dc_entry_visible(dc_entry_t *entry, knl_dictionary_t *dc)
{
    knl_scn_t org_scn;

    if (!entry->ready || !entry->used) {
        return CT_FALSE;
    }

    org_scn = (DICT_TYPE_SYNONYM == entry->type) ? dc->syn_org_scn : dc->org_scn;

    return (org_scn == entry->org_scn);
}

knl_column_t *dc_get_column(const dc_entity_t *entity, uint16 id)
{
    if (id < DC_COLUMN_GROUP_SIZE) {
        return entity->column_groups[0].columns[id];
    }

    return DC_GET_COLUMN_PTR(entity, id);
}

void dc_ready(knl_session_t *session, uint32 uid, uint32 oid)
{
    uint32 gid, eid;
    dc_context_t *ctx = &session->kernel->dc_ctx;
    dc_user_t *user = ctx->users[uid];
    dc_entry_t *entry;

    gid = oid / DC_GROUP_SIZE;
    eid = oid % DC_GROUP_SIZE;

    entry = user->groups[gid]->entries[eid];
    knl_panic_log(entry != NULL, "entry is NULL.");
    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    entry->ready = CT_TRUE;
    cm_spin_unlock(&entry->lock);
}

static inline void dc_init_knl_dictionary(knl_dictionary_t *dc, dc_entry_t *entry)
{
    if (entry->type == DICT_TYPE_SYNONYM) {
        dc->syn_org_scn = entry->org_scn;
        dc->syn_chg_scn = entry->chg_scn;
        dc->syn_handle = (knl_handle_t)entry;
        dc->is_sysnonym = CT_TRUE;
    } else {
        dc->org_scn = entry->org_scn;
        dc->chg_scn = entry->chg_scn;
        dc->is_sysnonym = CT_FALSE;
    }

    dc->type = entry->type;
}

status_t dc_try_lock_table_ux(knl_session_t *session, dc_entry_t *entry)
{
    cm_spin_lock(&entry->lock, NULL);
    if (!entry->used || entry->recycled) {
        cm_spin_unlock(&entry->lock);
        return CT_SUCCESS;
    }

    if (entry->sch_lock == NULL) {
        if (dc_alloc_schema_lock(session, entry) != CT_SUCCESS) {
            cm_spin_unlock(&entry->lock);
            return CT_ERROR;
        }
    }
    cm_spin_unlock(&entry->lock);

    if (lock_table_ux(session, entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t dc_alloc_entry(dc_context_t *ctx, dc_user_t *user, dc_entry_t **entry)
{
    errno_t ret;

    if (dc_alloc_mem(ctx, user->memory, sizeof(dc_entry_t), (void **)entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    ret = memset_sp(*entry, sizeof(dc_entry_t), 0, sizeof(dc_entry_t));
    knl_securec_check(ret);

    return CT_SUCCESS;
}

status_t dc_alloc_entity(dc_context_t *ctx, dc_entry_t *entry)
{
    dc_entity_t *entity = NULL;
    memory_context_t *memory = NULL;
    errno_t err;

    if (dc_create_memory_context(ctx, &memory) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // first memory page is enough to store dc_entity_t
    (void)mctx_alloc(memory, sizeof(dc_entity_t), (void **)&entry->entity);

    entity = entry->entity;
    err = memset_sp(entity, sizeof(dc_entity_t), 0, sizeof(dc_entity_t));
    knl_securec_check(err);
    entity->type = entry->type;
    entity->entry = entry;
    entity->memory = memory;
    entity->valid = CT_TRUE;

    return CT_SUCCESS;
}

void dc_free_entry_list_add(dc_user_t *user, dc_entry_t *entry)
{
    if (!dc_is_reserved_entry(entry->uid, entry->id)) {
        cm_spin_lock(&user->free_entries_lock, NULL);
        if (!entry->is_free) {
            cm_bilist_add_head(&entry->node, &user->free_entries);
            entry->is_free = CT_TRUE;
        }
        cm_spin_unlock(&user->free_entries_lock);
    }
}

void dc_free_entry(knl_session_t *session, dc_entry_t *entry)
{
    dc_user_t *user;
    dc_context_t *ctx = &session->kernel->dc_ctx;
    dc_appendix_t *appendix = NULL;
    schema_lock_t *sch_lock = NULL;

    user = ctx->users[entry->uid];
    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    appendix = entry->appendix;
    sch_lock = entry->sch_lock;
    entry->appendix = NULL;
    entry->sch_lock = NULL;
    cm_spin_unlock(&entry->lock);

    cm_spin_lock(&ctx->lock, NULL);
    if (appendix != NULL) {
        if (appendix->synonym_link != NULL) {
            dc_list_add(&ctx->free_synonym_links, (dc_list_node_t *)appendix->synonym_link);
        }

        dc_list_add(&ctx->free_appendixes, (dc_list_node_t *)appendix);
    }

    if (sch_lock != NULL) {
        dc_list_add(&ctx->free_schema_locks, (dc_list_node_t *)sch_lock);
    }
    dc_recycle_table_dls(session, entry);
    dc_free_entry_list_add(user, entry);
    cm_spin_unlock(&ctx->lock);
}

dc_entry_t *dc_get_entry(dc_user_t *user, uint32 id)
{
    dc_entry_t *entry = NULL;

    if (id < CT_LTT_ID_OFFSET) {
        if (id >= DC_GROUP_COUNT * DC_GROUP_SIZE) {
            return NULL;
        }
        dc_group_t *group = user->groups[id / DC_GROUP_SIZE];
        if (group != NULL) {
            entry = group->entries[id % DC_GROUP_SIZE];
        }
    } else {
        knl_session_t *sess = (knl_session_t *)knl_get_curr_sess();
        if (sess != NULL && sess->temp_dc != NULL) {
            if (id >= CT_LTT_ID_OFFSET + sess->temp_table_capacity) {
                return NULL;
            }
            entry = (dc_entry_t *)(sess->temp_dc->entries[id - CT_LTT_ID_OFFSET]);
        }
    }

    return entry;
}

uint32 dc_hash(text_t *name)
{
    uint32 val;
    val = cm_hash_text(name, INFINITE_HASH_RANGE);
    return val % DC_HASH_SIZE;
}

bool32 dc_into_lru_needed(dc_entry_t *entry, dc_context_t *ctx)
{
    dc_entity_t *entity = entry->entity;
    // system table is not allowed to add to entry lru queue
    if (dc_is_reserved_entry(entry->uid, entry->id)) {
        return CT_FALSE;
    }
    // temp table is not allowed to add to entry lru queue
    if (entry->id >= CT_LTT_ID_OFFSET) {
        return CT_FALSE;
    }
    if (ctx->lru_queue->head == entity && ctx->lru_queue->tail == entity) {
        return CT_FALSE;
    }

    if (entity->lru_next == NULL && entity->lru_prev == NULL) {
        return CT_TRUE;
    }

    return CT_FALSE;
}

void dc_insert_into_index(dc_user_t *user, dc_entry_t *entry, bool8 is_recycled)
{
    dc_entry_t *first_entry = NULL;
    dc_bucket_t *bucket = NULL;
    uint32 hash;
    text_t name;

    entry->user = user;

    if (is_recycled) {
        entry->bucket = NULL;
        entry->next = CT_INVALID_ID32;
        entry->prev = CT_INVALID_ID32;

        return;
    }

    cm_str2text(entry->name, &name);
    hash = dc_hash(&name);
    bucket = &user->buckets[hash];
    entry->bucket = bucket;

    cm_spin_lock(&bucket->lock, NULL);
    entry->next = bucket->first;
    entry->prev = CT_INVALID_ID32;

    if (bucket->first != CT_INVALID_ID32) {
        first_entry = DC_GET_ENTRY(user, bucket->first);
        first_entry->prev = entry->id;
    }

    bucket->first = entry->id;
    cm_spin_unlock(&bucket->lock);
}

void dc_set_index_profile(knl_session_t *session, dc_entity_t *entity, index_t *index)
{
    knl_column_t *column = NULL;
    table_t *table = &entity->table;
    knl_index_desc_t *desc = &index->desc;
    index_profile_t *profile = &desc->profile;
    uint16 collate_id;

    profile->primary = desc->primary;
    profile->unique = desc->unique;
    profile->column_count = desc->column_count;
    profile->uid = desc->uid;
    profile->table_id = desc->table_id;
    profile->index_id = desc->id;
    profile->global_idx_for_part_table = IS_PART_TABLE(table) && !IS_PART_INDEX(index);
    profile->is_compart_table = profile->global_idx_for_part_table ? IS_COMPART_TABLE(table->part_table) : CT_FALSE;
    profile->is_shadow = index->btree.is_shadow;
    profile->null_first = DB_ATTR_COMPATIBLE_MYSQL(session) == 1 ? CT_TRUE : CT_FALSE;

    for (uint32 id = 0; id < desc->column_count; id++) {
        column = dc_get_column(entity, desc->columns[id]);
        profile->types[id] = column->datatype;
        if (column->is_collate && DB_ATTR_COMPATIBLE_MYSQL(session)) {
            collate_id = column->collate_id;
        } else {
            collate_id = CT_INVALID_ID16;
        }
        profile->collate_id[id] = collate_id;
    }
}

static inline status_t dc_alloc_group(dc_context_t *ctx, dc_user_t *user, uint32 gid)
{
    char *page = NULL;

    if (dc_alloc_page(ctx, &page) != CT_SUCCESS) {
        return CT_ERROR;
    }

    user->groups[gid] = (dc_group_t *)page;

    return CT_SUCCESS;
}

static bool32 dc_find_entry(knl_session_t *session, dc_user_t *user, text_t *name, knl_dictionary_t *dc,
    bool32 *is_ready)
{
    uint32 hash;
    uint32 eid;
    dc_bucket_t *bucket;
    dc_entry_t *entry = NULL;

    hash = dc_hash(name);
    bucket = &user->buckets[hash];

    cm_spin_lock(&bucket->lock, NULL);
    eid = bucket->first;

    while (eid != CT_INVALID_ID32) {
        entry = DC_GET_ENTRY(user, eid);
        knl_panic_log(entry != NULL, "entry is NULL.");
        if (cm_text_str_equal(name, entry->name)) {
            break;
        }

        eid = entry->next;
    }

    if (eid == CT_INVALID_ID32) {
        cm_spin_unlock(&bucket->lock);
        return CT_FALSE;
    }

    if (dc == NULL) {
        cm_spin_unlock(&bucket->lock);
        return CT_TRUE;
    }

    dc->uid = user->desc.id;
    dc->oid = eid;

    // spin lock on entry is need here, because other thread may load entity(which may change scn and entry->entity)
    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);

    dc_init_knl_dictionary(dc, entry);

    *is_ready = entry->ready;

    cm_spin_unlock(&entry->lock);

    cm_spin_unlock(&bucket->lock);

    return CT_TRUE;
}

bool32 dc_find(knl_session_t *session, dc_user_t *user, text_t *name, knl_dictionary_t *dc)
{
    bool32 is_ready = CT_FALSE;
    for (;;) {
        if (!dc_find_entry(session, user, name, dc, &is_ready)) {
            return CT_FALSE;
        }

        if (dc == NULL || is_ready) {
            break;
        }

        cm_sleep(5);
    }
    
    return CT_TRUE;
}

status_t dc_create_entry_with_oid(knl_session_t *session, dc_user_t *user, text_t *name, uint32 oid,
                                  dc_entry_t **entry)
{
    uint32 gid, eid;
    dc_context_t *ctx = &session->kernel->dc_ctx;
    dc_group_t *group = NULL;
    errno_t err;

    gid = oid / DC_GROUP_SIZE;
    eid = oid % DC_GROUP_SIZE;

    if (user->groups[gid] == NULL) {
        if (dc_alloc_group(ctx, user, gid) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    group = user->groups[gid];
    if (group->entries[eid] != NULL && group->entries[eid]->used) {
        CT_THROW_ERROR(ERR_OBJECT_ID_EXISTS, "entry id", oid);
        return CT_ERROR;
    }

    if (group->entries[eid] == NULL) {
        ctx = &session->kernel->dc_ctx;

        if (dc_alloc_entry(ctx, user, entry) != CT_SUCCESS) {
            return CT_ERROR;
        }

        group->entries[eid] = *entry;
    } else {
        *entry = group->entries[eid];
        dc_try_remove_entry(user, *entry);

        err = memset_sp(*entry, sizeof(dc_entry_t), 0, sizeof(dc_entry_t));
        knl_securec_check(err);
    }

    (*entry)->uid = user->desc.id;
    (*entry)->id = oid;
    (*entry)->used = CT_TRUE;
    (*entry)->ready = CT_FALSE;
    (*entry)->need_empty_entry = CT_TRUE;
    (*entry)->is_loading = CT_FALSE;
    (void)cm_text2str(name, (*entry)->name, CT_NAME_BUFFER_SIZE);
    dls_init_spinlock(&((*entry)->serial_lock), DR_TYPE_SERIAL, oid, (uint16)user->desc.id);
    dls_init_latch(&((*entry)->ddl_latch), DR_TYPE_TABLE, (*entry)->id, (*entry)->uid);

    if (oid >= user->entry_hwm) {
        user->entry_hwm = oid + 1;
    }

    return CT_SUCCESS;
}

static status_t dc_create_entry_normally(knl_session_t *session, dc_user_t *user, text_t *name, dc_entry_t **entry)
{
    if (dc_try_reuse_entry(user, entry)) {
        (void)cm_text2str(name, (*entry)->name, CT_NAME_BUFFER_SIZE);
        return CT_SUCCESS;
    }

    for (;;) {
        if (user->entry_lwm >= user->entry_hwm) {
            break;
        }

        if (dc_get_entry(user, user->entry_lwm) != NULL ||
            dc_is_reserved_entry(user->desc.id, user->entry_lwm)) {
            user->entry_lwm++;
            continue;
        }

        if (dc_create_entry_with_oid(session, user, name, user->entry_lwm, entry) != CT_SUCCESS) {
            return CT_ERROR;
        }

        user->entry_lwm++;

        return CT_SUCCESS;
    }

    if (user->entry_hwm >= DC_GROUP_COUNT * DC_GROUP_SIZE) {
        CT_THROW_ERROR(ERR_TOO_MANY_TABLES, user->desc.name, DC_GROUP_COUNT * DC_GROUP_SIZE);
        return CT_ERROR;
    }

    if (dc_is_reserved_entry(user->desc.id, user->entry_hwm)) {
        user->entry_hwm = CT_EX_SYSID_END;
    }

    if (dc_create_entry_with_oid(session, user, name, user->entry_hwm, entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    user->entry_lwm++;

    return CT_SUCCESS;
}

status_t dc_find_ltt(knl_session_t *session, dc_user_t *user, text_t *table_name, knl_dictionary_t *dc,
                     bool32 *found)
{
    knl_temp_dc_t *temp_dc = session->temp_dc;
    if (temp_dc == NULL) {
        if (knl_init_temp_dc(session) != CT_SUCCESS) {
            return CT_ERROR;
        }

        temp_dc = session->temp_dc;
    }

    *found = CT_FALSE;

    for (uint32 i = 0; i < session->temp_table_capacity; i++) {
        dc_entry_t *entry = (dc_entry_t *)temp_dc->entries[i];
        if (entry == NULL) {
            continue;
        }

        if (cm_text_str_equal(table_name, entry->name) && (entry->uid == user->desc.id)) {
            dc->type = entry->type;
            dc->uid = user->desc.id;
            dc->oid = entry->id;
            dc->is_sysnonym = CT_FALSE;
            dc->org_scn = entry->org_scn;
            dc->chg_scn = entry->chg_scn;
            dc->handle = (knl_handle_t)entry->entity;
            dc->kernel = session->kernel;
            *found = CT_TRUE;
            break;
        }
    }

    return CT_SUCCESS;
}

status_t dc_create_ltt_entry(knl_session_t *session, memory_context_t *ctx, dc_user_t *user,
                             knl_table_desc_t *desc, uint32 slot_id, dc_entry_t **entry)
{
    dc_entry_t *ptr = NULL;
    errno_t err;

    if (dc_alloc_mem(&session->kernel->dc_ctx, ctx, sizeof(dc_entry_t), (void **)&ptr) != CT_SUCCESS) {
        return CT_ERROR;
    }

    err = memset_sp(ptr, sizeof(dc_entry_t), 0, sizeof(dc_entry_t));
    knl_securec_check(err);
    err = memcpy_sp(ptr->name, CT_NAME_BUFFER_SIZE, desc->name, CT_NAME_BUFFER_SIZE);
    knl_securec_check(err);

    if (dc_alloc_mem(&session->kernel->dc_ctx, ctx, sizeof(dc_appendix_t), (void **)&ptr->appendix) != CT_SUCCESS) {
        return CT_ERROR;
    }

    err = memset_sp(ptr->appendix, sizeof(dc_appendix_t), 0, sizeof(dc_appendix_t));
    knl_securec_check(err);
    ptr->user = user;
    ptr->org_scn = desc->org_scn;
    ptr->chg_scn = desc->chg_scn;
    ptr->type = DICT_TYPE_TEMP_TABLE_SESSION;
    ptr->uid = user->desc.id;
    ptr->id = CT_LTT_ID_OFFSET + slot_id;
    ptr->used = CT_TRUE;
    ptr->ready = CT_FALSE;
    desc->id = ptr->id;

    *entry = ptr;
    return CT_SUCCESS;
}

status_t dc_create_entry(knl_session_t *session, dc_user_t *user, text_t *name, uint32 oid,
                         bool8 is_recycled, dc_entry_t **entry)
{
    knl_dictionary_t dc;
    status_t status;

    dls_spin_lock(session, &user->lock, NULL);

    if (user->status != USER_STATUS_NORMAL) {
        dls_spin_unlock(session, &user->lock);
        CT_THROW_ERROR(ERR_USER_NOT_EXIST, user->desc.name);
        return CT_ERROR;
    }

    if (dc_find(session, user, name, &dc)) {
        dls_spin_unlock(session, &user->lock);
        CT_THROW_ERROR(ERR_DUPLICATE_TABLE, user->desc.name, T2S(name));
        return CT_ERROR;
    }

    if (oid != CT_INVALID_ID32) {
        status = dc_create_entry_with_oid(session, user, name, oid, entry);  // if dc_init or creating system table
    } else {
        status = dc_create_entry_normally(session, user, name, entry);
    }

    if (status != CT_SUCCESS) {
        dls_spin_unlock(session, &user->lock);
        return CT_ERROR;
    }

    (*entry)->version = session->kernel->dc_ctx.version;

    if (oid == CT_INVALID_ID32) {
        (*entry)->need_empty_entry = CT_FALSE;  // new create entry, do not need empty entry
    }

    dc_insert_into_index(user, *entry, is_recycled);

    dls_spin_unlock(session, &user->lock);

    return CT_SUCCESS;
}

/*
 * check nologging is ready for write
 */
static status_t dc_nologging_check(knl_session_t *session, dc_entity_t *entity)
{
    table_t *table = &entity->table;
    dc_entry_t *entry = entity->entry;

    if (!IS_NOLOGGING_BY_TABLE_TYPE(table->desc.type)) {
        return CT_SUCCESS;
    }

    if (entry == NULL) {
        return CT_SUCCESS;
    }

    if (entry->need_empty_entry && KNL_IS_DATABASE_OPEN(session)) {
        CT_THROW_ERROR(ERR_INVALID_DC, table->desc.name);
        CT_LOG_RUN_ERR("dc for nologging table %s is invalid ", table->desc.name);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t dc_reset_nologging_entry(knl_session_t *session, knl_handle_t desc, object_type_t type)
{
    status_t status = CT_ERROR;

    if (DB_IS_READONLY(session)) {
        return CT_SUCCESS;
    }

    if (knl_begin_auton_rm(session) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to begin auton transaction to reset nologging table entry");
        return CT_ERROR;
    }

    switch (type) {
        case OBJ_TYPE_TABLE:
            status = db_update_table_entry(session, (knl_table_desc_t *)desc, INVALID_PAGID);
            break;
        case OBJ_TYPE_INDEX:
            status = db_update_index_entry(session, (knl_index_desc_t *)desc, INVALID_PAGID);
            break;
        case OBJ_TYPE_LOB:
            status = db_update_lob_entry(session, (knl_lob_desc_t *)desc, INVALID_PAGID);
            break;
        case OBJ_TYPE_TABLE_PART:
            status = db_update_table_part_entry(session, (knl_table_part_desc_t *)desc, INVALID_PAGID);
            break;
        case OBJ_TYPE_INDEX_PART:
            status = db_upd_idx_part_entry(session, (knl_index_part_desc_t *)desc, INVALID_PAGID);
            break;
        case OBJ_TYPE_LOB_PART:
            status = db_update_lob_part_entry(session, (knl_lob_part_desc_t *)desc, INVALID_PAGID);
            break;
        case OBJ_TYPE_SHADOW_INDEX:
            status = db_update_shadow_index_entry(session, (knl_index_desc_t *)desc, INVALID_PAGID);
            break;
        case OBJ_TYPE_SHADOW_INDEX_PART:
            status = db_upd_shadow_idx_part_entry(session, (knl_index_part_desc_t *)desc, INVALID_PAGID, CT_FALSE);
            break;
        case OBJ_TYPE_GARBAGE_SEGMENT:
            status = db_update_garbage_segment_entry(session, (knl_table_desc_t *)desc, INVALID_PAGID);
            break;
        case OBJ_TYPE_TABLE_SUBPART:
            status = db_update_subtabpart_entry(session, (knl_table_part_desc_t *)desc, INVALID_PAGID);
            break;
        case OBJ_TYPE_INDEX_SUBPART:
            status = db_upd_sub_idx_part_entry(session, (knl_index_part_desc_t *)desc, INVALID_PAGID);
            break;
        case OBJ_TYPE_LOB_SUBPART:
            status = db_update_sublobpart_entry(session, (knl_lob_part_desc_t *)desc, INVALID_PAGID);
            break;
        case OBJ_TYPE_SHADOW_INDEX_SUBPART:
            status = db_upd_shadow_idx_part_entry(session, (knl_index_part_desc_t *)desc, INVALID_PAGID, CT_TRUE);
            break;
        default:
            knl_panic(CT_FALSE);
            break;
    }

    knl_end_auton_rm(session, status);

    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to reset nologging table entry");
    }

    return status;
}

void knl_open_core_cursor(knl_session_t *session, knl_cursor_t *cursor, knl_cursor_action_t action, uint32 id)
{
    knl_rm_t *rm = session->rm;
    table_t *table = db_sys_table(id);

    knl_inc_session_ssn(session);

    cursor->row = (row_head_t *)cursor->buf;
    cursor->is_valid = CT_TRUE;
    cursor->isolevel = ISOLATION_READ_COMMITTED;
    cursor->scn = DB_CURR_SCN(session);
    cursor->cc_cache_time = KNL_NOW(session);
    cursor->table = table;
    cursor->index = NULL;
    cursor->dc_type = DICT_TYPE_TABLE;
    cursor->dc_entity = NULL;
    cursor->action = action;
    cursor->ssn = rm->ssn;
    cursor->page_buf = cursor->buf + DEFAULT_PAGE_SIZE(session);
    cursor->query_scn = session->query_scn;
    cursor->query_lsn = DB_CURR_LSN(session);
    cursor->xid = rm->xid.value;
    cursor->cleanout = CT_FALSE;
    cursor->eof = CT_FALSE;
    cursor->is_valid = CT_TRUE;
    cursor->rowid.slot = INVALID_SLOT;
    cursor->decode_count = CT_INVALID_ID16;
    cursor->stmt = NULL;
    cursor->disable_pk_update = CT_TRUE;
    SET_ROWID_PAGE(&cursor->rowid, HEAP_SEGMENT(session, table->heap.entry, table->heap.segment)->data_first);
    cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor->fetch = TABLE_ACCESSOR(cursor)->do_fetch;
}

status_t knl_open_sys_temp_cursor(knl_session_t *session, knl_cursor_t *cursor, knl_cursor_action_t action,
                                  uint32 table_id, uint32 index_slot)
{
    knl_dictionary_t dc;

    db_get_sys_dc(session, table_id, &dc);

    knl_open_sys_cursor(session, cursor, action, table_id, index_slot);

    knl_panic_log(dc.type == DICT_TYPE_TEMP_TABLE_SESSION || dc.type == DICT_TYPE_TEMP_TABLE_TRANS,
                  "dc type is abnormal, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);
    cursor->ssn = session->ssn;

    return knl_open_temp_cursor(session, cursor, &dc);
}

void dc_invalidate_shadow_index(knl_handle_t dc_entity)
{
    table_t *table = &((dc_entity_t *)dc_entity)->table;

    if (table->shadow_index != NULL) {
        table->shadow_index->is_valid = CT_FALSE;
    }
}

bool32 dc_restore(knl_session_t *session, dc_entity_t *entity, text_t *name)
{
    uint32 hash;
    uint32 eid;
    dc_bucket_t *bucket;
    dc_entry_t *entry;
    dc_entry_t *temp = NULL;

    entry = entity->entry;
    hash = dc_hash(name);
    bucket = &entry->user->buckets[hash];

    cm_spin_lock(&bucket->lock, NULL);
    eid = bucket->first;

    while (eid != CT_INVALID_ID32) {
        temp = DC_GET_ENTRY(entry->user, eid);
        if (cm_text_str_equal(name, temp->name)) {
            break;
        }

        eid = temp->next;
    }

    if (eid != CT_INVALID_ID32) {
        cm_spin_unlock(&bucket->lock);
        return CT_FALSE;
    }

    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    entry->recycled = CT_FALSE;
    (void)cm_text2str(name, entry->name, CT_NAME_BUFFER_SIZE);
    entry->prev = CT_INVALID_ID32;
    entry->bucket = bucket;
    entry->next = bucket->first;
    cm_spin_unlock(&entry->lock);

    if (bucket->first != CT_INVALID_ID32) {
        temp = DC_GET_ENTRY(entry->user, bucket->first);
        temp->prev = entry->id;
    }

    bucket->first = entry->id;
    cm_spin_unlock(&bucket->lock);

    return CT_TRUE;
}

void dc_remove_from_bucket(knl_session_t *session, dc_entry_t *entry)
{
    dc_bucket_t *bucket = entry->bucket;
    dc_entry_t *next = NULL;
    dc_entry_t *prev = NULL;

    cm_spin_lock(&bucket->lock, NULL);

    if (entry->next != CT_INVALID_ID32) {
        next = DC_GET_ENTRY(entry->user, entry->next);
        next->prev = entry->prev;
    }

    if (entry->prev != CT_INVALID_ID32) {
        prev = DC_GET_ENTRY(entry->user, entry->prev);
        prev->next = entry->next;
    }

    if (bucket->first == entry->id) {
        bucket->first = entry->next;
    }

    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    entry->bucket = NULL;
    entry->prev = CT_INVALID_ID32;
    entry->next = CT_INVALID_ID32;
    cm_spin_unlock(&entry->lock);

    cm_spin_unlock(&bucket->lock);
}

void dc_remove(knl_session_t *session, dc_entity_t *entity, text_t *name)
{
    dc_entry_t *entry = entity->entry;

    if (entry->bucket != NULL) {
        dc_remove_from_bucket(session, entry);
    }

    dc_invalidate_parents(session, entity);

    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    dc_wait_till_load_finish(session, entry);
    entity->valid = CT_FALSE;
    entry->entity = NULL;
    entry->recycled = CT_TRUE;
    (void)cm_text2str(name, entry->name, CT_NAME_BUFFER_SIZE);
    dc_release_segment_dls(session, entity);
    cm_spin_unlock(&entry->lock);
}

/*
 * remove an dc entry from hash bucket and mark it invalid
 */
void dc_drop(knl_session_t *session, dc_entity_t *entity)
{
    dc_entry_t *entry = entity->entry;
    dc_context_t *ctx = &session->kernel->dc_ctx;
    synonym_link_t *synonym_link = NULL;

    if (entry->bucket != NULL) {
        dc_remove_from_bucket(session, entry);
    }

    dc_invalidate_parents(session, entity);

    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    dc_wait_till_load_finish(session, entry);
    entity->valid = CT_FALSE;
    entry->used = CT_FALSE;
    entry->org_scn = 0;
    entry->chg_scn = db_next_scn(session);
    entry->entity = NULL;
    entry->recycled = CT_FALSE;
    entry->serial_value = 0;
    entry->serial_lock.lock = 0;
    if (entry->appendix == NULL) {
        cm_spin_unlock(&entry->lock);
        return;
    }
    dc_release_segment_dls(session, entity);

    synonym_link = entry->appendix->synonym_link;
    entry->appendix->synonym_link = NULL;
    cm_spin_unlock(&entry->lock);

    cm_spin_lock(&ctx->lock, NULL);
    if (synonym_link != NULL) {
        dc_list_add(&ctx->free_synonym_links, (dc_list_node_t *)synonym_link);
    }
    cm_spin_unlock(&ctx->lock);

    return;
}

status_t dc_open_ltt_entity(knl_session_t *session, uint32 uid, uint32 oid, knl_dictionary_t *dc)
{
    dc_user_t *user = NULL;
    dc_entry_t *entry = NULL;

    if (dc_open_user_by_id(session, uid, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    entry = DC_GET_ENTRY(user, oid);
    if (entry == NULL) {
        CT_THROW_ERROR(ERR_TABLE_ID_NOT_EXIST, uid, oid);
        return CT_ERROR;
    }

    dc->uid = uid;
    dc->oid = oid;
    dc->kernel = session->kernel;
    dc->type = entry->type;
    dc->is_sysnonym = CT_FALSE;
    dc->syn_org_scn = 0;
    dc->syn_chg_scn = 0;
    dc->syn_handle = NULL;
    dc->handle = entry->entity;
    dc->org_scn = entry->org_scn;
    dc->chg_scn = entry->chg_scn;
    entry->entity->ref_count++;
    return CT_SUCCESS;
}

bool32 dc_open_ltt(knl_session_t *session, dc_user_t *user, text_t *obj_name, knl_dictionary_t *dc)
{
    bool32 found = CT_FALSE;
    knl_temp_cache_t *temp_cache = NULL;
    dc_entity_t *entity = NULL;

    if (dc_find_ltt(session, user, obj_name, dc, &found) != CT_SUCCESS || !found) {
        return CT_FALSE;
    }

    dc_entry_t *entry = DC_GET_ENTRY(user, dc->oid);
    if (dc->org_scn != entry->org_scn) {
        return CT_FALSE;
    }

    if ((!entry->ready) || (entry->recycled)) {
        return CT_FALSE;
    }

    entity = (dc_entity_t *)dc->handle;

    if (knl_ensure_temp_cache(session, entity, &temp_cache) != CT_SUCCESS) {
        return CT_FALSE;
    }

    if (entity->cbo_table_stats == NULL) {
        if (cbo_alloc_temp_table_stats(session, entity, temp_cache, CT_TRUE) == CT_SUCCESS) {
            entity->stat_exists = CT_TRUE;
        }
    }

    // there is no need to maintain ref_count for ltt dc
    entry->entity->valid = CT_TRUE;

    return CT_TRUE;
}

static status_t dc_open_synonym(knl_session_t *session, dc_entry_t *entry, knl_dictionary_t *dc)
{
    text_t link_user, link_name;
    synonym_link_t *syn_link = entry->appendix->synonym_link;
    dc_user_t *syn_user = NULL;
    dc_user_t *cur_user = NULL;

    dc->type = entry->type;
    dc->syn_chg_scn = entry->chg_scn;
    dc->syn_org_scn = entry->org_scn;
    dc->kernel = session->kernel;
    cm_str2text(syn_link->user, &link_user);
    cm_str2text(syn_link->name, &link_name);

    if (dc_open_user_by_id(session, session->uid, &cur_user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_open_user(session, &link_user, &syn_user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_open(session, &link_user, &link_name, dc) != CT_SUCCESS) {
        dc->is_sysnonym = CT_TRUE;
        dc->syn_handle = entry;
        return CT_ERROR;
    }

    dc->is_sysnonym = CT_TRUE;
    dc->syn_handle = entry;
    return CT_SUCCESS;
}

static status_t dc_open_entry(knl_session_t *session, dc_user_t *user, dc_entry_t *entry, knl_dictionary_t *dc,
                              bool32 excl_recycled)
{
    status_t status;
    dc_entity_t *entity = NULL;

    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);

    if (!dc_entry_visible(entry, dc)) {
        CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, user->desc.name, entry->name);
        cm_spin_unlock(&entry->lock);
        return CT_ERROR;
    }

    if (entry->type == DICT_TYPE_SYNONYM) {
        status = dc_open_synonym(session, entry, dc);
    } else {
        status = dc_open_table_or_view(session, user, entry, dc);
    }

    if (status != CT_SUCCESS) {
        cm_spin_unlock(&entry->lock);
        return CT_ERROR;
    }

    knl_panic_log(!(entry->type == DICT_TYPE_TABLE && entry->ref_count <= 0),
                  "current entry is abnormal, panic info: entry type %u ref_count %u", entry->type, entry->ref_count);

    if (entry->recycled && excl_recycled) {
        entity = (dc_entity_t *)dc->handle;
        if (entity != NULL) {
            cm_spin_lock(&entity->ref_lock, NULL);
            knl_panic_log(entity->ref_count > 0, "the ref_count is abnormal, panic info: ref_count %u",
                          entity->ref_count);
            entity->ref_count--;
            cm_spin_unlock(&entity->ref_lock);
            dc->handle = NULL;
        }

        cm_spin_unlock(&entry->lock);
        CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, user->desc.name, entry->name);
        return CT_ERROR;
    }

    cm_spin_unlock(&entry->lock);

    status = dc_nologging_check(session, (dc_entity_t *)dc->handle);

    return status;
}

/*
 * called when:
 * 1. db failover(HA)
 * 2. db failover(Raft)
 * 3. convert to readwrite
 *
 * Notes:
 *  we will drop nologging tables, so reset dc is not ready to prevent DC access(see `dc_is_ready_for_access').
 *  the call step is:
 *  1. dc_reset_not_ready_by_nlg
 *  2. db_clean_nologging_guts
 *  3. dc_set_ready
 *
 * when:
 *  1. db restart(ready=false -->clean_nologging -->ready=true)
 *  2. db switchover
 *      (on master: we will clean_nologging after all sessions are killed and before wait_log_sync, so
 *       if switchover successfully, new master will have no nologging tables)
 *  so, the above two scenario do not need reset/set dc_ready.
 */
void dc_reset_not_ready_by_nlg(knl_session_t *session)
{
    if (session->kernel->attr.drop_nologging) {
        session->kernel->dc_ctx.ready = CT_FALSE;
    }
}

void dc_set_ready(knl_session_t *session)
{
    session->kernel->dc_ctx.ready = CT_TRUE;
}

static inline bool32 dc_is_ready_for_access(knl_session_t *session)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;

    /* 1. dc is ready, all is OK */
    if (ctx->ready) {
        return CT_TRUE;
    }

    /* 2. dc is not ready */
    /* 2.1 bootstrap session is OK */
    if (session->bootstrap) {
        return CT_TRUE;
    }

    /* 2.2 upgrade mode is OK */
    if (DB_IS_UPGRADE(session)) {
        return CT_TRUE;
    }

    /* 2.3 tx_rollback session is OK, because it will access dc during undo */
    if (DB_IS_BG_ROLLBACK_SE(session)) {
        return CT_TRUE;
    }

    return CT_FALSE;
}

status_t dc_open(knl_session_t *session, text_t *user_name, text_t *obj_name, knl_dictionary_t *dc)
{
    dc_entry_t *entry = NULL;
    dc_user_t *user = NULL;

    KNL_RESET_DC(dc);
    if (!dc_is_ready_for_access(session)) {
        CT_THROW_ERROR(ERR_DATABASE_NOT_AVAILABLE);
        return CT_ERROR;
    }

    if (dc_open_user(session, user_name, &user) != CT_SUCCESS) {
        cm_reset_error();
        CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(user_name), T2S_EX(obj_name));
        return CT_ERROR;
    }

    if (IS_LTT_BY_NAME(obj_name->str)) {
        if (dc_open_ltt(session, user, obj_name, dc)) {
            return CT_SUCCESS;
        }
        // CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(user_name), T2S_EX(obj_name));
        // return CT_ERROR;
    }

    if (!dc_find(session, user, obj_name, dc)) {
        CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(user_name), T2S_EX(obj_name));
        return CT_ERROR;
    }

    entry = DC_GET_ENTRY(user, dc->oid);
    if (dc_open_entry(session, user, entry, dc, CT_FALSE) != CT_SUCCESS) {
        int32 code = cm_get_error_code();
        if (code == ERR_TABLE_OR_VIEW_NOT_EXIST) {
            cm_reset_error();
            CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(user_name), T2S_EX(obj_name));
        }
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/* only used for plm_init */
dc_entry_t *dc_get_entry_private(knl_session_t *session, text_t *username, text_t *name, knl_dictionary_t *dc)
{
    dc_user_t *user = NULL;
    dc_entry_t *entry = NULL;

    KNL_RESET_DC(dc);
    if (!dc_is_ready_for_access(session)) {
        CT_THROW_ERROR(ERR_DATABASE_NOT_AVAILABLE);
        return NULL;
    }

    if (dc_open_user(session, username, &user) != CT_SUCCESS) {
        return NULL;
    }

    if (!dc_find(session, user, name, dc)) {
        return NULL;
    }

    entry = DC_GET_ENTRY(user, dc->oid);
    if (entry->type == DICT_TYPE_SYNONYM) {
        if (dc_open_entry(session, user, entry, dc, CT_FALSE) != CT_SUCCESS) {
            int32 code = cm_get_error_code();
            if (code == ERR_TABLE_OR_VIEW_NOT_EXIST) {
                cm_reset_error();
                CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(username), T2S_EX(name));
            }
            return NULL;
        }
    }

    if (entry->appendix == NULL) {
        if (dc_alloc_appendix(session, entry) != CT_SUCCESS) {
            return NULL;
        }
    }

    if (entry->sch_lock == NULL) {
        if (dc_alloc_schema_lock(session, entry) != CT_SUCCESS) {
            return NULL;
        }
    }

    return entry;
}

bool32 dc_object_exists(knl_session_t *session, text_t *owner, text_t *name, knl_dict_type_t *type)
{
    dc_user_t *user = NULL;
    knl_dictionary_t dc;

    if (dc_open_user(session, owner, &user) != CT_SUCCESS) {
        return CT_FALSE;
    }

    if (!dc_find(session, user, name, &dc)) {
        return CT_FALSE;
    }

    *type = dc.type;

    return CT_TRUE;
}

bool32 dc_object_exists2(knl_handle_t session, text_t *owner, text_t *name, knl_dict_type_t *type)
{
    return dc_object_exists((knl_session_t *)session, owner, name, type);
}

/*
 * Description     : a wrapper function for dc_open() which can fill a knl_dictionary_t structure
 * according to the owner name and the object name,
 * without reporting an error even if the specified object not found
 * Input           : handle(de-facto type: knl_session_t *),
 * user(text_t *) and object_name(text_t *)
 * Output          : flag(type bool32) to show if the specified object found
 * and a pointer to an existing knl_dictionary_t variable
 * Return Value    : status_t
 * Remark          : the reason why we don't use dc_try_open() is that the dc_try_open will search the
 * database object with the owner "PUBLIC", too. however, when we specify "owner", we need
 * the function to search dc exactly according to what we specified.
 */
status_t knl_open_dc_if_exists(knl_handle_t handle, text_t *user_name, text_t *obj_name,
                               knl_dictionary_t *dc, bool32 *is_exists)
{
    knl_session_t *session = (knl_session_t *)handle;
    dc_entry_t *entry = NULL;
    dc_user_t *user = NULL;

    KNL_RESET_DC(dc);
    if (!dc_is_ready_for_access(session)) {
        CT_THROW_ERROR(ERR_DATABASE_NOT_AVAILABLE);
        return CT_ERROR;
    }

    if (dc_open_user(session, user_name, &user) != CT_SUCCESS) {
        *is_exists = CT_FALSE;
        return CT_SUCCESS;
    }

    if (IS_LTT_BY_NAME(obj_name->str)) {
        *is_exists = dc_open_ltt(session, user, obj_name, dc);
        if (*is_exists) {
            return CT_SUCCESS;
        }
    }
    if (!dc_find(session, user, obj_name, dc)) {
        *is_exists = CT_FALSE;
        return CT_SUCCESS;
    }

    entry = DC_GET_ENTRY(user, dc->oid);
    if (dc_open_entry(session, user, entry, dc, CT_FALSE) != CT_SUCCESS) {
        int32 code = cm_get_error_code();
        if (code == ERR_TABLE_OR_VIEW_NOT_EXIST) {
            cm_reset_error();
            *is_exists = CT_FALSE;
            return CT_SUCCESS;
        }
        return CT_ERROR;
    }

    *is_exists = CT_TRUE;
    return CT_SUCCESS;
}

// this function is similar to knl_open_dc_if_exists except for supporting temporary table
status_t knl_open_dc_not_ltt(knl_handle_t handle, text_t *user_name, text_t *obj_name,
                               knl_dictionary_t *dc, bool32 *is_exists)
{
    knl_session_t *session = (knl_session_t *)handle;
    dc_entry_t *entry = NULL;
    dc_user_t *user = NULL;

    KNL_RESET_DC(dc);
    if (!dc_is_ready_for_access(session)) {
        CT_THROW_ERROR(ERR_DATABASE_NOT_AVAILABLE);
        return CT_ERROR;
    }

    if (dc_open_user(session, user_name, &user) != CT_SUCCESS) {
        *is_exists = CT_FALSE;
        return CT_SUCCESS;
    }

    if (!dc_find(session, user, obj_name, dc)) {
        *is_exists = CT_FALSE;
        return CT_SUCCESS;
    }

    entry = DC_GET_ENTRY(user, dc->oid);
    if (dc_open_entry(session, user, entry, dc, CT_FALSE) != CT_SUCCESS) {
        int32 code = cm_get_error_code();
        if (code == ERR_TABLE_OR_VIEW_NOT_EXIST) {
            cm_reset_error();
            *is_exists = CT_FALSE;
            return CT_SUCCESS;
        }
        return CT_ERROR;
    }

    *is_exists = CT_TRUE;
    return CT_SUCCESS;
}

status_t knl_open_dc_by_id(knl_handle_t handle, uint32 uid, uint32 oid, knl_dictionary_t *dc, bool32 excl_recycled)
{
    knl_session_t *session;
    dc_entry_t *entry = NULL;
    dc_user_t *user = NULL;
    uint32 gid;

    session = (knl_session_t *)handle;
    KNL_RESET_DC(dc);

    if (IS_LTT_BY_ID(oid)) {
        return dc_open_ltt_entity(session, uid, oid, dc);
    }

    if (dc_open_user_by_id(session, uid, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    gid = oid / DC_GROUP_SIZE;
    entry = DC_GET_ENTRY(user, oid);
    if (gid >= DC_GROUP_COUNT || user->groups[gid] == NULL || entry == NULL) {
        CT_THROW_ERROR(ERR_TABLE_ID_NOT_EXIST, uid, oid);
        return CT_ERROR;
    }

    dc->uid = entry->uid;
    dc->oid = entry->id;

    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);

    dc_init_knl_dictionary(dc, entry);

    cm_spin_unlock(&entry->lock);

    if (dc_open_entry(session, user, entry, dc, excl_recycled) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dc->uid = uid;
    dc->oid = oid;

    return CT_SUCCESS;
}

status_t knl_try_open_dc_by_id(knl_handle_t handle, uint32 uid, uint32 oid, knl_dictionary_t *dc)
{
    knl_session_t *session;
    dc_user_t *user = NULL;

    session = (knl_session_t *)handle;
    KNL_RESET_DC(dc);

    if (IS_LTT_BY_ID(oid)) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "try open local temporary table");
        return CT_ERROR;
    }

    if (dc_open_user_by_id(session, uid, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!dc_find_by_id(session, user, oid, CT_FALSE)) {
        CT_THROW_ERROR(ERR_TABLE_ID_NOT_EXIST, uid, oid);
        return CT_ERROR;
    }

    dc_entry_t *entry = DC_GET_ENTRY(user, oid);
    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    dc_wait_till_load_finish(session, entry);
    dc_init_knl_dictionary(dc, entry);

    if (!entry->ready || !entry->used) {
        CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, user->desc.name, entry->name);
        cm_spin_unlock(&entry->lock);
        return CT_ERROR;
    }

    if (entry->entity == NULL) {
        cm_spin_unlock(&entry->lock);
        return CT_SUCCESS;
    }

    cm_spin_lock(&entry->entity->ref_lock, NULL);
    entry->entity->ref_count++;
    dc_entity_t *entity = entry->entity;
    cm_spin_unlock(&entry->entity->ref_lock);

    if (!entity->valid) {
        cm_spin_unlock(&entry->lock);
        dc_close_entity(session->kernel, entity, CT_TRUE);
        return CT_SUCCESS;
    }

    dc->type = entry->type;
    dc->org_scn = entry->org_scn;
    dc->chg_scn = entry->chg_scn;
    dc->kernel = session->kernel;
    dc->handle = entity;
    dc->uid = entry->uid;
    dc->oid = entry->id;

    cm_spin_unlock(&entry->lock);

    return CT_SUCCESS;
}

void dc_invalidate_internal(knl_session_t *session, dc_entity_t *entity)
{
    btree_flush_garbage_size(session, entity);

    if (!IS_LTT_BY_ID(entity->entry->id)) {
        table_t *table = &entity->table;

        if (TABLE_IS_TEMP(table->desc.type)) {
            knl_temp_cache_t *temp_cache = knl_get_temp_cache(session, table->desc.uid, table->desc.id);
            if (temp_cache != NULL) {
                knl_free_temp_cache_memory(temp_cache);
            }
        }

        cm_spin_lock(&entity->entry->lock, &session->stat->spin_stat.stat_dc_entry);
        if (entity->valid) {
            knl_panic_log(entity == entity->entry->entity, "current entity is abnormal, panic info: table %s",
                          table->desc.name);
            entity->valid = CT_FALSE;
            entity->entry->entity = NULL;
        }
        cm_spin_unlock(&entity->entry->lock);
    }
}

void dc_invalidate4mysql(knl_session_t *session, dc_entity_t *entity, bool32 flush_monitor)
{
    // to flush dml statistics using autonomous  transaction
    // for mysql, if the table has already be dropped by mysql copy, do not update sys table anymore
    if (flush_monitor) {
        if (stats_temp_insert(session, entity) != CT_SUCCESS) {
            CT_LOG_RUN_WAR("segment statistic failed, there might be some statitics loss.");
        }
        if (stats_flush_monitor_force(session, entity) != CT_SUCCESS) {
            CT_LOG_RUN_WAR("Flush %s.%s  monitor statistic failed force, please gather statistics manually",
                entity->entry->user->desc.name, entity->table.desc.name);
        }
    }

    dc_invalidate_internal(session, entity);
}

void dc_invalidate(knl_session_t *session, dc_entity_t *entity)
{
    if (stats_temp_insert(session, entity) != CT_SUCCESS) {
        CT_LOG_RUN_WAR("segment statistic failed, there might be some statitics loss.");
    }

    // to flush dml statistics using autonomous  transaction
    if (stats_flush_monitor_force(session, entity) != CT_SUCCESS) {
        CT_LOG_RUN_WAR("Flush %s.%s  monitor statistic failed force, please gather statistics manually",
            entity->entry->user->desc.name, entity->table.desc.name);
    }

    dc_invalidate_internal(session, entity);
}

void dc_invalidate_parents(knl_session_t *session, dc_entity_t *entity)
{
    table_t *table = &entity->table;
    ref_cons_t *ref = NULL;
    knl_dictionary_t ref_dc;
    uint32 i;

    for (i = 0; i < table->cons_set.ref_count; i++) {
        ref = table->cons_set.ref_cons[i];

        if (ref->ref_uid == table->desc.uid && ref->ref_oid == table->desc.id) {
            continue;
        }
        // it will not failed here
        if (dc_open_table_directly(session, ref->ref_uid, ref->ref_oid, &ref_dc) != CT_SUCCESS) {
            continue;
        }

        if (stats_temp_insert(session, DC_ENTITY(&ref_dc)) != CT_SUCCESS) {
            CT_LOG_RUN_WAR("segment statistic failed, there might be some statitics loss.");
        }

        dc_invalidate(session, DC_ENTITY(&ref_dc));
        dc_invalidate_remote(session, DC_ENTITY(&ref_dc));
        dc_close(&ref_dc);
    }
}

void dc_invalidate_children(knl_session_t *session, dc_entity_t *entity)
{
    table_t *table = &entity->table;
    index_t *index = NULL;
    cons_dep_t *dep = NULL;
    knl_dictionary_t dep_dc;
    uint32 i;

    if (table->index_set.count == 0) {
        return;
    }

    for (i = 0; i < table->index_set.count; i++) {
        index = table->index_set.items[i];
        if (index->dep_set.count == 0) {
            continue;
        }

        /* if table is referenced by another table */
        dep = index->dep_set.first;
        while (dep != NULL) {
            if (dep->uid == table->desc.uid && dep->oid == table->desc.id) {
                dep = dep->next;
                continue;
            }

            if (dc_open_table_directly(session, dep->uid, dep->oid, &dep_dc) != CT_SUCCESS) { // it will not failed here
                dep = dep->next;
                continue;
            }

            if (stats_temp_insert(session, DC_ENTITY(&dep_dc)) != CT_SUCCESS) {
                CT_LOG_RUN_WAR("segment statistic failed, there might be some statitics loss.");
            }

            dc_invalidate(session, DC_ENTITY(&dep_dc));
            dc_invalidate_remote(session, DC_ENTITY(&dep_dc));
            dc_close(&dep_dc);
            dep = dep->next;
        }
    }
}

void dc_invalidate_remote(knl_session_t *session, dc_entity_t *entity)
{
    if (!DB_IS_CLUSTER(session) || IS_LTT_BY_ID(entity->entry->id)) {
        return;
    }

    dtc_broadcast_invalidate_dc(session, entity->entry->uid, entity->entry->id);
}

static void dc_nologging_empty_user_entry(dc_user_t *user)
{
    uint32 eid = 0;

    dc_entry_t *entry = NULL;

    for (eid = 0; eid < user->entry_hwm; eid++) {
        entry = dc_get_entry(user, eid);
        if (entry == NULL) {
            continue;
        }
        
        if (entry->type != DICT_TYPE_TABLE_NOLOGGING) {
            continue;
        }

        CT_LOG_DEBUG_INF("empty_user_entry: uid: %u, tid: %u", (uint32)entry->uid, entry->id);
        entry->need_empty_entry = CT_TRUE;
    }
}

static void dc_nologging_empty_all_entry(knl_session_t *session)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    uint32 i;

    for (i = 0; i < ctx->user_hwm; i++) {
        if (!ctx->users[i]) {
            continue;
        }

        if (!ctx->users[i]->has_nologging) {
            continue;
        }

        if (ctx->users[i]->status == USER_STATUS_NORMAL) {
            dc_nologging_empty_user_entry(ctx->users[i]);
        }
    }
}

/*
 * make nologging dc entry as invalid_entry in order to clear nologging table data,
 * this is must be called when primary demote to standby, to make sure nologging table is empty on standby.
 */
void dc_invalidate_nologging(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    dc_context_t *ctx = &kernel->dc_ctx;
    dc_lru_queue_t *queue = NULL;
    dc_entity_t *curr = NULL;
    dc_entity_t *lru_next = NULL;

    /* 1. entry in LRU */
    queue = ctx->lru_queue;
    cm_spin_lock(&queue->lock, NULL);

    curr = queue->head;
    while (curr != NULL) {
        knl_panic_log(curr->entry != NULL, "current entry is NULL.");
        lru_next = curr->lru_next;
        if (curr->entry->type == DICT_TYPE_TABLE_NOLOGGING) {
            CT_LOG_DEBUG_INF("dc_invalidate_nologging: uid: %u, tid: %u, valid: %u",
                             (uint32)curr->entry->uid, curr->entry->id, curr->valid);

            /* 1. set need_empty_entry flag, so we can clear nologging table data */
            curr->entry->need_empty_entry = CT_TRUE;

            /* 2. invaliate dc */
            if (curr->valid) {
                cm_spin_lock(&curr->entry->lock, &session->stat->spin_stat.stat_dc_entry);
                dc_entity_t *entity = rd_invalid_entity(session, curr->entry);
                cm_spin_unlock(&curr->entry->lock);
                dc_close_entity(session->kernel, entity, CT_FALSE);
            }
        }

        curr = lru_next;
    }

    cm_spin_unlock(&queue->lock);

    /* 2. entry not in LRU */
    dc_nologging_empty_all_entry(session);
}

status_t dc_check_stats_version(knl_session_t *session, knl_dictionary_t *dc, dc_entity_t *entity)
{
    knl_instance_t *kernel = (knl_instance_t *)dc->kernel;
    if (kernel != NULL && !kernel->attr.enable_cbo) {
        return CT_SUCCESS;
    }
    knl_temp_cache_t *temp_cache = NULL;
    if (TABLE_IS_TEMP(entity->table.desc.type)) {
        temp_cache = knl_get_temp_cache((knl_handle_t)session, entity->table.desc.uid, entity->table.desc.id);
    }
    bool32 stat_exists = (temp_cache == NULL) ? entity->stat_exists : temp_cache->stat_exists;
    if (!stat_exists) {
        return CT_SUCCESS;
    }
    uint32 stats_version = (temp_cache == NULL) ? entity->stats_version : temp_cache->stats_version;
    if (dc->stats_version != stats_version) {
        CT_THROW_ERROR(ERR_DC_INVALIDATED);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

/*
 * Description     : close dc(decrease reference number and free memory if entity is invalid and unreferenced
 * Input           : dc
 * Output          : NA
 * Return Value    : void
 * History         : 1.2017/4/26,  add description
 */
static void dc_close_ref_entities(knl_handle_t *kernel, dc_entity_t *entity)
{
    ref_cons_t *ref = NULL;
    uint32 i;

    if (entity->type != DICT_TYPE_TABLE && entity->type != DICT_TYPE_TABLE_NOLOGGING &&
        entity->type != DICT_TYPE_TEMP_TABLE_TRANS && entity->type != DICT_TYPE_TEMP_TABLE_SESSION) {
        return;
    }

    for (i = 0; i < entity->table.cons_set.ref_count; i++) {
        ref = entity->table.cons_set.ref_cons[i];
        if (ref->ref_entity != NULL) {
            dc_close_entity(kernel, (dc_entity_t *)ref->ref_entity, CT_TRUE);
        }
    }
}

status_t dc_synctime_load_entity(knl_session_t *session)
{
    dc_user_t *sys_user = NULL;
    dc_entry_t *entry = NULL;

    if (dc_open_user_by_id(session, DB_SYS_USER_ID, &sys_user) != CT_SUCCESS) {
        return CT_ERROR;
    }
    
    entry = DC_GET_ENTRY(sys_user, SYS_SYNC_INFO_ID);
    if (entry == NULL) {
        return CT_ERROR;
    }
    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    status_t ret = dc_load_entity(session, sys_user, SYS_SYNC_INFO_ID, entry, NULL);
    cm_spin_unlock(&entry->lock);

    return ret;
}

void dc_close_entity(knl_handle_t kernel, dc_entity_t *entity, bool32 need_lru_lock)
{
    dc_lru_queue_t *dc_lru = ((knl_instance_t *)kernel)->dc_ctx.lru_queue;
    dc_entry_t *entry = entity->entry;
    table_t *table = NULL;

    cm_spin_lock(&entity->ref_lock, NULL);
    knl_panic_log(entity->ref_count > 0, "the ref_count is abnormal, panic info: ref_count %u", entity->ref_count);
    if (entity->ref_count == 1 && !entity->valid) {
        cm_spin_unlock(&entity->ref_lock);
        /* close entities of tables referenced by this entity */
        (void)dc_close_ref_entities(kernel, entity);
        if (!need_lru_lock) {
            (void)dc_lru_remove(dc_lru, entity);
        } else {
            cm_spin_lock(&dc_lru->lock, NULL);
            (void)dc_lru_remove(dc_lru, entity);
            cm_spin_unlock(&dc_lru->lock);
        }

        cm_spin_lock(&entry->ref_lock, NULL);
        if ((entry->type == (uint8)DICT_TYPE_TABLE) && !dc_is_reserved_entry(entry->uid, entry->id)) {
            table = &entity->table;
            if (table->desc.org_scn == entry->org_scn) {
                if (entry->ref_count == 1) {
                    dc_segment_recycle(&((knl_instance_t *)kernel)->dc_ctx, entity);
                }
                entry->ref_count--;
                knl_panic_log(entry->ref_count >= 0, "the ref_count is abnormal, panic info: ref_count %u table %s",
                              entry->ref_count, table->desc.name);
            }
        }
        mctx_destroy(entity->memory);
        cm_spin_unlock(&entry->ref_lock);
        return;
    }
    entity->ref_count--;
    cm_spin_unlock(&entity->ref_lock);
}

void dc_close(knl_dictionary_t *dc)
{
    knl_instance_t *kernel = (knl_instance_t *)dc->kernel;
    dc_entity_t *entity = DC_ENTITY(dc);

    if (entity != NULL) {
        if (DC_TABLE_IS_TEMP(entity->type)) {
            return;
        }

        if (entity->entry != NULL && IS_DBLINK_TABLE_BY_ID(entity->entry->id)) {
            return;
        }

        dc_close_entity(kernel, entity, CT_TRUE);
        dc->handle = NULL;
    }
}

void dc_close_table_private(knl_dictionary_t *dc)
{
    dc_entry_t *entry = NULL;
    table_t *table = NULL;

    if (IS_LTT_BY_ID(dc->oid)) {
        dc_close(dc);
    } else {
        dc_entity_t *entity = (dc_entity_t *)dc->handle;
        table = &entity->table;
        entry = entity->entry;
        cm_spin_lock(&entry->ref_lock, NULL);
        if ((entry->type == DICT_TYPE_TABLE) && !dc_is_reserved_entry(entry->uid, entry->id)) {
            if (table->desc.org_scn == entry->org_scn) {
                if (entry->ref_count == 1) {
                    dc_segment_recycle(&((knl_instance_t *)dc->kernel)->dc_ctx, entity);
                }
                entry->ref_count--;
                knl_panic_log(entry->ref_count >= 0, "the ref_count is abnormal, panic info: ref_count %u table %s",
                              entry->ref_count, table->desc.name);
            }
        }
        mctx_destroy(entity->memory);
        cm_spin_unlock(&entry->ref_lock);
    }
}

status_t dc_load_core_table(knl_session_t *session, uint32 oid)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    memory_context_t *memory = NULL;
    table_t *table = NULL;

    if (dc_create_memory_context(ctx, &memory) != CT_SUCCESS) {
        return CT_ERROR;
    }

    table = db_sys_table(oid);
    if (db_load_core_entity_by_id(session, memory, table) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

/*
 * Description     : get valid of  dc
 * Input           : entity
 * Output          : is_valid : judge is valid or not
 * Return Value    : void
 * History         : 1.2017/9/1,  add description
 */
void dc_get_entry_status(dc_entry_t *entry, text_t *status)
{
    if (!entry->used) {
        status->str = "unused";
    } else if (entry->recycled) {
        status->str = "recycled";
    } else {
        status->str = "used";
    }
}

/*
 * Description     : get type of  dc
 * Input           : entity
 * Output          : dictionary type : table ,dictionary view or view
 * Return Value    : void
 * History         : 1.2017/9/4,  add description
 */
const char *dc_type2name(knl_dict_type_t type)
{
    return g_dict_type_names[type - 1];
}

static status_t dc_convert_table_type(knl_session_t *session, knl_table_desc_t *desc, dc_entry_t *entry)
{
    switch (desc->type) {
        case TABLE_TYPE_HEAP:
            entry->type = DICT_TYPE_TABLE;
            break;
        case TABLE_TYPE_TRANS_TEMP:
            entry->type = DICT_TYPE_TEMP_TABLE_TRANS;
            break;
        case TABLE_TYPE_SESSION_TEMP:
            entry->type = DICT_TYPE_TEMP_TABLE_SESSION;
            break;
        case TABLE_TYPE_NOLOGGING:
            entry->type = DICT_TYPE_TABLE_NOLOGGING;
            break;
        case TABLE_TYPE_EXTERNAL:
            entry->type = DICT_TYPE_TABLE_EXTERNAL;
            break;
        default:
            CT_THROW_ERROR(ERR_NOT_SUPPORT_TYPE, desc->type);
            CT_LOG_RUN_ERR("invalid table type %d", desc->type);
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t dc_create_table_entry(knl_session_t *session, dc_user_t *user, knl_table_desc_t *desc)
{
    dc_entry_t *entry = NULL;
    text_t table_name;
    status_t status;

    cm_str2text(desc->name, &table_name);

    if (dc_create_entry(session, user, &table_name, desc->id, desc->recycled, &entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cm_spin_lock(&entry->lock, NULL);
    cm_spin_lock(&entry->ref_lock, NULL);
    entry->org_scn = desc->org_scn;
    entry->chg_scn = desc->chg_scn;
    entry->recycled = desc->recycled;
    entry->ref_count = 0;
    cm_spin_unlock(&entry->ref_lock);

    if (desc->id == CT_INVALID_ID32) {
        desc->id = entry->id;
    }

    status = dc_convert_table_type(session, desc, entry);

    cm_spin_unlock(&entry->lock);

    return status;
}

status_t dc_create_view_entry(knl_session_t *session, dc_user_t *user, knl_view_t *view)
{
    dc_entry_t *entry = NULL;
    text_t view_name;

    cm_str2text(view->name, &view_name);

    if (dc_create_entry(session, user, &view_name, view->id, CT_FALSE, &entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    entry->type = DICT_TYPE_VIEW;
    view->id = entry->id;
    entry->org_scn = view->org_scn;
    entry->chg_scn = view->chg_scn;
    return CT_SUCCESS;
}

void dc_free_broken_entry(knl_session_t *session, uint32 uid, uint32 eid)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    dc_appendix_t *appendix = NULL;
    dc_entry_t *entry = NULL;
    dc_user_t *user = NULL;

    if (dc_open_user_by_id(session, uid, &user) != CT_SUCCESS) {
        rd_check_dc_replay_err(session);
        return;
    }

    entry = DC_GET_ENTRY(user, eid);
    if (entry == NULL) {
        if (DB_IS_PRIMARY(&session->kernel->db) && !DAAC_REPLAY_NODE(session)) {
            knl_panic_log(0, "current DB is primary.");
        }
        CT_LOG_RUN_INF("[DC] no need to replay drop synonym, synonym %u doesn't exists\n", eid);
        return;
    }

    if (entry->bucket != NULL) {
        dc_remove_from_bucket(session, entry);
    }

    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    entry->used = CT_FALSE;
    entry->ready = CT_FALSE;
    entry->org_scn = 0;
    entry->chg_scn = DB_IS_PRIMARY(&session->kernel->db) ? db_next_scn(session) : 0;
    entry->entity = NULL;
    appendix = entry->appendix;
    entry->appendix = NULL;
    cm_spin_unlock(&entry->lock);

    cm_spin_lock(&ctx->lock, NULL);
    if (appendix != NULL) {
        if (appendix->synonym_link != NULL) {
            dc_list_add(&ctx->free_synonym_links, (dc_list_node_t *)appendix->synonym_link);
        }

        dc_list_add(&ctx->free_appendixes, (dc_list_node_t *)appendix);
    }
    cm_spin_unlock(&ctx->lock);

    dc_free_entry_list_add(user, entry);
}

bool32 dc_locked_by_xa(knl_session_t *session, dc_entry_t *entry)
{
    uint32 rm_count = session->kernel->rm_count;
    knl_rm_t *rm = NULL;
    uint32 i;

    if (entry->sch_lock == NULL) {
        return CT_FALSE;
    }

    for (i = 0; i < rm_count; i++) {
        rm = session->kernel->rms[i];

        if (!knl_xa_xid_valid(&rm->xa_xid)) {
            continue;
        }

        if (SCH_LOCKED_BY_RMID(i, entry->sch_lock)) {
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

status_t dc_create_synonym_entry(knl_session_t *session, dc_user_t *user, knl_synonym_t *synonym)
{
    text_t name;
    dc_entry_t *entry = NULL;
    synonym_link_t *synonym_link = NULL;
    uint32 name_len = CT_NAME_BUFFER_SIZE - 1;
    errno_t err;

    cm_str2text(synonym->name, &name);

    if (dc_create_entry(session, user, &name, synonym->id, CT_FALSE, &entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);

    if (dc_alloc_appendix(session, entry) != CT_SUCCESS) {
        cm_spin_unlock(&entry->lock);
        dc_free_broken_entry(session, synonym->uid, entry->id);
        return CT_ERROR;
    }

    if (dc_alloc_synonym_link(session, entry) != CT_SUCCESS) {
        cm_spin_unlock(&entry->lock);
        dc_free_broken_entry(session, synonym->uid, entry->id);
        return CT_ERROR;
    }

    entry->type = DICT_TYPE_SYNONYM;
    synonym->id = entry->id;
    entry->uid = synonym->uid;
    entry->org_scn = synonym->chg_scn;
    entry->chg_scn = synonym->org_scn;
    synonym_link = entry->appendix->synonym_link;
    err = strncpy_s(entry->name, CT_NAME_BUFFER_SIZE, synonym->name, name_len);
    knl_securec_check(err);
    err = strncpy_s(synonym_link->user, CT_NAME_BUFFER_SIZE, synonym->table_owner, name_len);
    knl_securec_check(err);
    err = strncpy_s(synonym_link->name, CT_NAME_BUFFER_SIZE, synonym->table_name, name_len);
    knl_securec_check(err);
    synonym_link->type = synonym->type;
    entry->entity = NULL;
    cm_spin_unlock(&entry->lock);

    return CT_SUCCESS;
}

static status_t dc_alloc_entry_from_group(knl_session_t *session, dc_user_t *user, uint32 gid, uint32 eid_start,
                                          dc_entry_t **entry)
{
    dc_group_t *group = user->groups[gid];
    uint32 eid = eid_start;

    while (eid < DC_GROUP_SIZE) {
        if (group->entries[eid] == NULL && !dc_is_reserved_entry(user->desc.id, eid)) {
            break;
        }
        eid++;
    }

    if (eid == DC_GROUP_SIZE) {
        *entry = NULL;
        return CT_SUCCESS;
    }

    if (dc_alloc_entry(&session->kernel->dc_ctx, user, entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    group->entries[eid] = *entry;
    (*entry)->id = eid + gid * DC_GROUP_SIZE;

    return CT_SUCCESS;
}

static status_t dc_create_dynamic_view_entry(knl_session_t *session, dc_user_t *user, text_t *view_name,
                                             uint32 *view_id, dc_entry_t **entry)
{
    uint32 gid;
    uint32 gid_start = *view_id / DC_GROUP_SIZE;
    uint32 eid_start = *view_id % DC_GROUP_SIZE;

    for (gid = gid_start; gid < DC_GROUP_COUNT; gid++) {
        if (user->groups[gid] == NULL) {
            if (dc_alloc_group(&session->kernel->dc_ctx, user, gid) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }

        if (dc_alloc_entry_from_group(session, user, gid, eid_start, entry) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (*entry != NULL) {
            break;
        }

        eid_start = 0;
    }

    (*entry)->user = user;
    (*entry)->uid = user->desc.id;
    (*entry)->used = CT_TRUE;
    (*entry)->ready = CT_FALSE;
    (void)cm_text2str(view_name, (*entry)->name, CT_NAME_BUFFER_SIZE);

    *view_id = (*entry)->id + 1;

    if ((*entry)->id >= user->entry_hwm) {
        user->entry_hwm = (*entry)->id + 1;
    }

    return CT_SUCCESS;
}

status_t dc_regist_dynamic_view(knl_session_t *session, knl_dynview_t *view, db_status_t db_status,
                                uint32 *view_id)
{
    uint32 i;
    dc_user_t *user = NULL;
    dc_entry_t *entry = NULL;
    dc_entity_t *entity = NULL;
    dc_context_t *ctx;
    dynview_desc_t *desc;
    text_t user_name, view_name;

    ctx = &session->kernel->dc_ctx;

    desc = view->describe(view->id);
    if (desc == NULL) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "register", "dynamic view");
        return CT_ERROR;
    }

    cm_str2text(desc->user, &user_name);
    cm_str2text(desc->name, &view_name);

    if (dc_open_user(session, &user_name, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    knl_panic_log(user->desc.id == 0, "current user is not sys user, panic info: uid %u", user->desc.id);

    if (dc_find(session, user, &view_name, NULL)) { // already registered
        return CT_SUCCESS;
    }

    if (db_status == DB_STATUS_OPEN) {
        if (dc_create_dynamic_view_entry(session, user, &view_name, view_id, &entry) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (dc_create_entry_normally(session, user, &view_name, &entry) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    entry->type = DICT_TYPE_DYNAMIC_VIEW;
    entry->lock = 0;
    entry->org_scn = 0;
    entry->chg_scn = 0;
    entry->ready = CT_TRUE;
    entry->ref_count = 0;
    dc_insert_into_index(user, entry, CT_FALSE);

    if (dc_alloc_entity(ctx, entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    entity = entry->entity;
    entity->dview = desc;
    entity->column_count = desc->column_count;
    entity->ref_count = 1;
    entry->ref_count = 1;

    if (dc_prepare_load_columns(session, entity) != CT_SUCCESS) {
        return CT_ERROR;
    }

    for (i = 0; i < desc->column_count; i++) {
        // dynamic view no need to copy column descriptions
        entity->column_groups[i / DC_COLUMN_GROUP_SIZE].columns[i % DC_COLUMN_GROUP_SIZE] = &desc->columns[i];
    }

    dc_create_column_index(entity);
    return CT_SUCCESS;
}

status_t dc_load_dynamic_views(knl_session_t *session, db_status_t status)
{
    uint32 i;
    uint32 count;
    knl_dynview_t *views = NULL;
    uint32 view_id = CT_RESERVED_SYSID;

    if (status == DB_STATUS_NOMOUNT) {
        count = session->kernel->dyn_view_nomount_count;
        views = session->kernel->dyn_views_nomount;
    } else if (status == DB_STATUS_MOUNT) {
        count = session->kernel->dyn_view_mount_count;
        views = session->kernel->dyn_views_mount;
    } else {
        knl_panic(status == DB_STATUS_OPEN);
        count = session->kernel->dyn_view_count;
        views = session->kernel->dyn_views;
    }

    for (i = 0; i < count; i++) {
        if (dc_regist_dynamic_view(session, &views[i], status, &view_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

#ifdef Z_SHARDING
status_t dc_load_shd_dynamic_views(knl_session_t *session, db_status_t status)
{
    uint32 i;
    uint32 count;
    knl_dynview_t *views = NULL;
    uint32 view_id = CT_RESERVED_SYSID;

    count = session->kernel->shd_dyn_view_count;
    views = session->kernel->shd_dyn_views;

    for (i = 0; i < count; i++) {
        if (dc_regist_dynamic_view(session, &views[i], status, &view_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}
#endif

status_t dc_build_ex_systables(knl_session_t *session)
{
    core_ctrl_t *core = &session->kernel->db.ctrl.core;

    if (!core->build_completed) {
        session->bootstrap = CT_TRUE;
        if (g_knl_callback.load_scripts(session, "initdb.sql", CT_TRUE) != CT_SUCCESS) {
            return CT_ERROR;
        }

        // pl_init_new must before initview.sql
        if (g_knl_callback.pl_init(session) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (g_knl_callback.load_scripts(session, "initview.sql", CT_TRUE) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (db_build_ex_systables(session) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (g_knl_callback.load_scripts(session, "initplsql.sql", CT_TRUE) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (g_knl_callback.load_scripts(session, "initwsr.sql", CT_TRUE) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (g_knl_callback.load_scripts(session, "initdb_customized.sql", CT_FALSE) != CT_SUCCESS) {
            return CT_ERROR;
        }

        knl_set_session_scn(session, CT_INVALID_ID64);

        if (session->kernel->attr.clustered) {
            if (dtc_build_completed(session) != CT_SUCCESS) {
                return CT_ERROR;
            }
        } else {
            if (db_build_completed(session) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }

        session->bootstrap = CT_FALSE;
    }

    return CT_SUCCESS;
}

static status_t dc_context_init(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    dc_context_t *ctx = &kernel->dc_ctx;
    uint32 page_id, i;
    uint32 opt_count = (uint32)DC_MAX_POOL_PAGES(kernel);
    if (opt_count < CT_MIN_DICT_PAGES) {
        opt_count = CT_MIN_DICT_PAGES;
    }

    ctx->kernel = (knl_instance_t *)kernel;

    if (SCHEMA_LOCK_SIZE > CT_SHARED_PAGE_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_MAX_RM_COUNT",
            (int64)CM_CALC_ALIGN_FLOOR(CT_MAX_RM_COUNT, CT_EXTEND_RMS));
        return CT_ERROR;
    }

    if (mpool_create(kernel->attr.shared_area, "dictionary pool", CT_MIN_DICT_PAGES, opt_count,
                     &ctx->pool) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_create_memory_context(ctx, &ctx->memory) != CT_SUCCESS) {
        return CT_ERROR;
    }

    ctx->pool.mem_alloc.ctx = ctx;
    ctx->pool.mem_alloc.mem_func = (mem_func_t)dc_alloc_mem;

    if (dc_alloc_memory_page(ctx, &page_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    ctx->user_buckets = (dc_bucket_t *)mpool_page_addr(&ctx->pool, page_id);

    for (i = 0; i < DC_HASH_SIZE; i++) {
        ctx->user_buckets[i].lock = 0;
        ctx->user_buckets[i].first = CT_INVALID_ID32;
    }

    if (dc_alloc_memory_page(ctx, &page_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    ctx->tenant_buckets = (dc_bucket_t *)mpool_page_addr(&ctx->pool, page_id);
    // CT_MAX_TENANTS must be equal or less than DC_HASH_SIZE
    for (i = 0; i < CT_MAX_TENANTS; i++) {
        ctx->tenant_buckets[i].lock = 0;
        ctx->tenant_buckets[i].first = CT_INVALID_ID32;
    }

    if (dc_init_lru(ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }
    dls_init_spinlock(&ctx->paral_lock, DR_TYPE_DC, DR_ID_DC_CTX, 0);
    CT_LOG_RUN_INF("[DC] context init finish.");

    return CT_SUCCESS;
}

static inline void dc_reserve_system_entries(dc_context_t *ctx)
{
    /* set entry hwm for sys user to reserve entries for system objects */
    dc_user_t *user = ctx->users[0];

    user->entry_hwm = MAX(user->entry_hwm, MAX_SYS_OBJECTS);
    user->entry_lwm = MAX_SYS_OBJECTS;
}

status_t dc_init_entries(knl_session_t *session, dc_context_t *ctx, uint32 uid)
{
    if (dc_init_table_entries(session, ctx, uid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_init_view_entries(session, ctx, uid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_init_synonym_entries(session, ctx, uid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t dc_init_extral_entries(knl_session_t *session, dc_context_t *ctx)
{
    if (dc_init_view_entries(session, ctx, DB_SYS_USER_ID) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_init_synonym_entries(session, ctx, DB_SYS_USER_ID) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_load_dynamic_views(session, DB_STATUS_OPEN) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_build_ex_systables(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!session->kernel->db.has_load_role) {
        if (dc_init_roles(session, ctx) != CT_SUCCESS) {
            return CT_ERROR;
        }
        session->kernel->db.has_load_role = CT_TRUE;
    }

    if (dc_load_privileges(session, ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (profile_load(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

#ifdef Z_SHARDING
    if (dc_load_distribute_rule(session, ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (dc_load_global_dynamic_views(session) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (dc_load_shd_dynamic_views(session, DB_STATUS_OPEN) != CT_SUCCESS) {
        return CT_ERROR;
    }
#endif

    if (dc_init_tenants(session, ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }

#ifdef Z_SHARDING
    if (knl_load_dblinks(session) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (dc_creat_spm_context(ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }
#endif
    CT_LOG_RUN_INF("[DC] init extral entries success.");
    return CT_SUCCESS;
}

status_t dc_init_all_entry_for_upgrade(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    dc_context_t *ctx = &kernel->dc_ctx;

    if (dc_init_extral_entries(session, ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dc_reserve_system_entries(ctx);
    ctx->users[DB_SYS_USER_ID]->is_loaded = CT_TRUE;

    return CT_SUCCESS;
}

static status_t dc_open_core_systbl(knl_session_t *session)
{
    uint32 i;
    dc_context_t *ctx = &session->kernel->dc_ctx;
    memory_context_t *memory = NULL;
    dc_user_t *user;
    dc_entry_t *entry = NULL;
    table_t *table = NULL;
    errno_t err;

    user = ctx->users[0];

    if (dc_create_memory_context(ctx, &memory) != CT_SUCCESS) {
        return CT_ERROR;
    }

    for (i = 0; i <= CORE_SYS_TABLE_CEIL; i++) {
        table = db_sys_table(i);
        if (dc_create_table_entry(session, user, &table->desc) != CT_SUCCESS) {
            return CT_ERROR;
        }

        dc_ready(session, table->desc.uid, table->desc.id);
        entry = user->groups[0]->entries[table->desc.id];

        if (dc_alloc_mem(ctx, ctx->memory, sizeof(dc_appendix_t), (void **)&entry->appendix) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (dc_alloc_mem(ctx, ctx->memory, SCHEMA_LOCK_SIZE, (void **)&entry->sch_lock) != CT_SUCCESS) {
            return CT_ERROR;
        }

        err = memset_sp(entry->appendix, sizeof(dc_appendix_t), 0, sizeof(dc_appendix_t));
        knl_securec_check(err);

        err = memset_sp(entry->sch_lock, SCHEMA_LOCK_SIZE, 0, SCHEMA_LOCK_SIZE);
        knl_securec_check(err);

        if (db_load_core_entity_by_id(session, memory, table) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (session->kernel->db.ctrl.core.open_count == 0) {
        knl_set_session_scn(session, DB_CURR_SCN(session));
        if (db_fill_builtin_indexes(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t dc_init(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    dc_context_t *ctx = &kernel->dc_ctx;

    ctx->ready = CT_FALSE;

    if (ctx->memory == NULL) {
        if (dc_context_init(session) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("failed to dc context init");
            return CT_ERROR;
        }
    }

    knl_set_session_scn(session, DB_CURR_SCN(session));

    if (dc_init_users(session, ctx) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("failed to dc init users");
        return CT_ERROR;
    }

    if (dc_open_core_systbl(session) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("failed to dc open core systbl");
        return CT_ERROR;
    }

    if (dc_init_table_entries(session, ctx, DB_SYS_USER_ID) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("failed to dc init table entries");
        return CT_ERROR;
    }

    if (dc_load_systables(session, ctx) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("failed to dc load systables");
        return CT_ERROR;
    }

    if (DB_IS_UPGRADE(session)) {
        ctx->ready = CT_TRUE;
        ctx->version = 1;
        session->kernel->dc_ctx.completed = CT_TRUE;
        return CT_SUCCESS;
    }

    if (dc_init_extral_entries(session, ctx) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("failed to dc init extral entries");
        return CT_ERROR;
    }

    /* set db_status to WAIT_CLEAN to make tx_rollback_proc works */
    kernel->db.status = DB_STATUS_WAIT_CLEAN;
    if (db_clean_nologging_all(session) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("failed to clean nologging tables");
        return CT_ERROR;
    }

    if (db_garbage_segment_clean(session) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("failed to clean garbage segment");
        return CT_ERROR;
    }

    dc_reserve_system_entries(ctx);

    ctx->ready = CT_TRUE;
    ctx->users[DB_SYS_USER_ID]->is_loaded = CT_TRUE;
    ctx->version = 1;

    if (DB_IS_RESTRICT(session)) {
        session->kernel->dc_ctx.completed = CT_TRUE;
    }

    return CT_SUCCESS;
}

static status_t profile_init_array(knl_session_t *session, dc_context_t *ctx)
{
    uint32 page_id;
    profile_array_t *profile_array = &ctx->profile_array;

    if (dc_alloc_memory_page(ctx, &page_id) != CT_SUCCESS) {
        return CT_SUCCESS;
    }

    profile_array->profiles = (profile_t **)mpool_page_addr(&ctx->pool, page_id);
    for (uint32 i = 0; i < MAX_PROFILE_SIZE; i++) {
        profile_array->profiles[i] = NULL;
    }

    if (dc_alloc_memory_page(ctx, &page_id) != CT_SUCCESS) {
        return CT_SUCCESS;
    }

    profile_array->buckets = (bucket_t *)mpool_page_addr(&ctx->pool, page_id);
    for (uint32 i = 0; i < PROFILE_HASH_SIZE; i++) {
        profile_array->buckets[i].latch.lock = 0;
        profile_array->buckets[i].latch.shared_count = 0;
        profile_array->buckets[i].latch.sid = 0;
        profile_array->buckets[i].latch.stat = 0;
        profile_array->buckets[i].count = 0;
        profile_array->buckets[i].first = CT_INVALID_ID32;
    }

    return CT_SUCCESS;
}

status_t dc_preload(knl_session_t *session, db_status_t status)
{
    knl_instance_t *kernel = session->kernel;
    dc_context_t *ctx = &kernel->dc_ctx;

    ctx->ready = CT_FALSE;

    if (ctx->memory == NULL) {
        if (dc_context_init(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (profile_init_array(session, ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[DC] profile init finish.");

    if (dc_init_root_tenant(session, ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_init_sys_user(session, ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[DC] root_tenant&sys_user init finish.");

    if (dc_load_dynamic_views(session, status) != CT_SUCCESS) {
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[DC] load dynamic views finish.");

    ctx->ready = CT_TRUE;

    return CT_SUCCESS;
}

heap_t *dc_get_heap_by_entity(knl_session_t *session, knl_part_locate_t part_loc, dc_entity_t *entity)
{
    if (dc_nologging_check(session, entity) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("nologging check is failed.");
        CM_ASSERT(0);
        return NULL;
    }

    table_t *table = &entity->table;
    if (!IS_PART_TABLE(table)) {
        return &table->heap;
    }

    if (DB_IS_CLUSTER(session) && part_loc.part_no == CT_INVALID_ID32) {
        knl_panic(DAAC_REPLAY_NODE(session));
        return &table->heap;  /* rd_heap_create_entry for serial, its value is stored in table->heap, not in table part. */
    }
    if (part_loc.part_no == CT_INVALID_ID32 || part_loc.part_no == CT_INVALID_ID24) {
        CT_LOG_RUN_ERR("part_no is invalid.");
        CM_ASSERT(0);
        return NULL;
    }
    table_part_t *table_part = TABLE_GET_PART(table, part_loc.part_no);
    if (table_part == NULL) {
        return NULL;
    }
    if (IS_PARENT_TABPART(&table_part->desc)) {
        if (part_loc.subpart_no == CT_INVALID_ID32) {
            CT_LOG_RUN_ERR("subpart no is invalid, subpart_no(%u).", part_loc.subpart_no);
            return NULL;
        }
        table_part = PART_GET_SUBENTITY(table->part_table, table_part->subparts[part_loc.subpart_no]);
        if (table_part == NULL) {
            CT_LOG_RUN_ERR("table partition is invalid, part_no(%u).", part_loc.part_no);
            return NULL;
        }
    }

    if (dc_load_table_part_segment(session, entity, table_part) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("load table part segment is failed.");
        return NULL;
    }
    return &table_part->heap;
}

heap_t *dc_get_heap(knl_session_t *session, uint32 uid, uint32 oid, knl_part_locate_t part_loc, knl_dictionary_t *dc)
{
    dc_user_t *user = NULL;

    if (dc_open_user_by_id(session, uid, &user) != CT_SUCCESS) {
        knl_panic_log(0, "[DC] ABORT INFO: dc open user failed while getting heap");
    }

    dc_entry_t *entry = DC_GET_ENTRY(user, oid);
    bool32 self_locked = dc_locked_by_self(session, entry);
    if (!self_locked) {
        knl_panic_log(dc != NULL, "dc is NULL.");
        if (dc_open_table_directly(session, uid, oid, dc) != CT_SUCCESS) {
            knl_panic_log(0, "[DC] ABORT INFO: dc get heap failed in rollback process while restarting");
        }
    }

    return dc_get_heap_by_entity(session, part_loc, entry->entity);
}

/*
 * Description     : get index handle
 * Input           : session
 * Input           : uid : table owner user id
 * Input           : oid : table id
 * Input           : iid : index id
 * Return Value    : index handle
 * History         : 1. 2017/4/26,  add description
 */
index_t *dc_find_index_by_id(dc_entity_t *dc_entity, uint32 index_id)
{
    table_t *table = &dc_entity->table;
    index_t *index = NULL;
    uint32 i;

    for (i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (index->desc.id == index_id) {
            return index;
        }
    }

    return NULL;
}

index_t *dc_find_index_by_name(dc_entity_t *dc_entity, text_t *index_name)
{
    table_t *table = &dc_entity->table;
    index_t *index = NULL;
    uint32 i;

    for (i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (cm_text_str_equal(index_name, index->desc.name)) {
            return index;
        }
    }

    return NULL;
}

index_t *dc_find_index_by_name_ins(dc_entity_t *dc_entity, text_t *index_name)
{
    table_t *table = &dc_entity->table;
    index_t *index = NULL;
    uint32 i;

    for (i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (cm_text_str_equal_ins(index_name, index->desc.name)) {
            return index;
        }
    }

    return NULL;
}

index_t *dc_find_index_by_scn(dc_entity_t *dc_entity, knl_scn_t scn)
{
    table_t *table = &dc_entity->table;
    index_t *index = NULL;
    uint32 i;

    for (i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (scn == index->desc.org_scn) {
            return index;
        }
    }

    return NULL;
}

index_t *dc_get_index(knl_session_t *session, uint32 uid, uint32 oid, uint32 idx_id, knl_dictionary_t *dc)
{
    dc_user_t *user = NULL;
    dc_entry_t *entry = NULL;
    bool32 self_locked;

    if (dc_open_user_by_id(session, uid, &user) != CT_SUCCESS) {
        if (!IS_LTT_BY_ID(oid)) {
            knl_panic_log(0, "[DC] ABORT INFO: dc open user failed while getting index");
        }
    }

    entry = DC_GET_ENTRY(user, oid);
    if (entry == NULL && oid >= CT_LTT_ID_OFFSET && oid < (CT_LTT_ID_OFFSET + session->temp_table_capacity) &&
        DB_ATTR_MYSQL_META_IN_DACC(session)) {
        // FOR MYSQL, TEMP TABLE NOT WRITE UNDO, SO MYSQL MAYBE DROP TMPE TABLE THEN ROLLBACK.
        CT_LOG_RUN_WAR("ltt table maybe has been dropped, not rollback");
        return NULL;
    }
    self_locked = dc_locked_by_self(session, entry);
    if (!self_locked) {
        knl_panic_log(dc != NULL, "dc is NULL.");
        if (dc_open_table_directly(session, uid, oid, dc) != CT_SUCCESS) {
            knl_panic_log(0, "[DC] ABORT INFO: dc get index failed in rollback process while restarting");
        }
    }

    return dc_find_index_by_id(entry->entity, idx_id);
}

static shadow_index_t *dc_get_shadow_index(knl_session_t *session, uint32 uid, uint32 oid, knl_dictionary_t *dc)
{
    dc_user_t *user = NULL;
    dc_entry_t *entry = NULL;
    bool32 self_locked;

    /* rollback thread does not rollback shadow index, because it has been dropped when dc_init */
    if (DB_IS_BG_ROLLBACK_SE(session)) {
        return NULL;
    }

    user = session->kernel->dc_ctx.users[uid];
    entry = DC_GET_ENTRY(user, oid);
    self_locked = dc_locked_by_self(session, entry);
    if (!self_locked) {
        knl_panic(dc != NULL);
        if (dc_open_table_directly(session, uid, oid, dc) != CT_SUCCESS) {
            knl_panic_log(0, "[DC] ABORT INFO: dc get shadow index failed in rollback process while restarting");
        }
    }

    return entry->entity->table.shadow_index;
}

btree_t *dc_get_btree(knl_session_t *session, page_id_t entry, knl_part_locate_t part_loc, bool32 is_shadow,
    knl_dictionary_t *dc)
{
    uint32 uid, table_id, index_id;
    btree_segment_t *segment = NULL;
    page_id_t page_id;
    index_t *index = NULL;
    index_part_t *index_part = NULL;
    shadow_index_t *shadow_index = NULL;
    page_id = entry;
    buf_enter_page(session, page_id, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
    segment = BTREE_GET_SEGMENT(session);
    uid = segment->uid;
    table_id = segment->table_id;
    index_id = segment->index_id;
    buf_leave_page(session, CT_FALSE);

    if (is_shadow) {
        shadow_index = dc_get_shadow_index(session, uid, table_id, dc);
        if (shadow_index == NULL) {
            return NULL;
        }

        if (shadow_index->part_loc.part_no != CT_INVALID_ID32) {
            knl_panic_log(shadow_index->part_loc.part_no == part_loc.part_no, "the shadow_index's part_no is abnormal,"
                          " panic info: page %u-%u shadow_index part_no %u part_no %u",
                          page_id.file, page_id.page, shadow_index->part_loc.part_no, part_loc.part_no);
            return &shadow_index->index_part.btree;
        }
        index = &shadow_index->index;
    } else {
        index = dc_get_index(session, uid, table_id, index_id, dc);
        knl_panic_log(index != NULL, "the index is NULL, panic info: page %u-%u", page_id.file, page_id.page);
    }

    if (!IS_PART_INDEX(index)) {  // todo: if global heap for partition table, such as serial?
        return &index->btree;
    } else {
        knl_panic_log(part_loc.part_no != CT_INVALID_ID32, "the part_no is invalid, panic info: page %u-%u index %s",
                      page_id.file, page_id.page, index->desc.name);
        index_part = INDEX_GET_PART(index, part_loc.part_no);
        if (IS_PARENT_IDXPART(&index_part->desc)) {
            index_part = PART_GET_SUBENTITY(index->part_index, index_part->subparts[part_loc.subpart_no]);
        }
        
        if (index_part->btree.segment == NULL && !IS_INVALID_PAGID(index_part->btree.entry)) {
            table_t *table = &index->entity->table;
            table_part_t *table_part = TABLE_GET_PART(table, part_loc.part_no);
            if (IS_PARENT_TABPART(&table_part->desc)) {
                table_part = PART_GET_SUBENTITY(table->part_table, table_part->subparts[part_loc.subpart_no]);
            }
            
            if (dc_load_table_part_segment(session, index->entity, table_part) != CT_SUCCESS) {
                knl_panic_log(0, "load table part segment is failed, panic info: page %u-%u table %s table_part %s "
                              "index %s index_part %s", page_id.file, page_id.page, table->desc.name,
                              table_part->desc.name, index->desc.name, index_part->desc.name);
            }
        }
        return &index_part->btree;
    }
}

btree_t *dc_get_btree_by_id(knl_session_t *session, dc_entity_t *entity, uint16 index_id, knl_part_locate_t part_loc,
                            bool32 is_shadow)
{
    btree_t *btree = NULL;

    if (is_shadow) {
        shadow_index_t *shadow_index = entity->table.shadow_index;
        if (shadow_index == NULL) {
            return NULL;
        }
        if (shadow_index->part_loc.part_no == CT_INVALID_ID32) {
            btree = &shadow_index->index.btree;
        } else {
            if (shadow_index->part_loc.part_no != part_loc.part_no) {
                CT_LOG_RUN_ERR("part_no(%u) is invalid.", part_loc.part_no);
                CM_ASSERT(0);
                return NULL;
            }
            btree = &shadow_index->index_part.btree;
            return btree;
        }
    } else {
        index_t *index = dc_find_index_by_id(entity, index_id);
        if (index == NULL) {
            return NULL;
        }
        if (!IS_PART_INDEX(index)) {
            btree = &index->btree;
        } else {
            if (part_loc.part_no == CT_INVALID_ID32) {
                CT_LOG_RUN_ERR("part_no(%u) is invalid.", part_loc.part_no);
                CM_ASSERT(0);
                return NULL;
            }
            index_part_t *index_part = INDEX_GET_PART(index, part_loc.part_no);
            if (index_part == NULL) {
                CT_LOG_RUN_ERR("index partition is invalid, part_no(%u).", part_loc.part_no);
                return NULL;
            }
            if (IS_PARENT_IDXPART(&index_part->desc)) {
                if (part_loc.subpart_no == CT_INVALID_ID32) {
                    CT_LOG_RUN_ERR("subpart no is invalid, subpart_no(%u).", part_loc.subpart_no);
                    return NULL;
                }
                index_part = PART_GET_SUBENTITY(index->part_index, index_part->subparts[part_loc.subpart_no]);
                if (index_part == NULL) {
                    CT_LOG_RUN_ERR("index sub partition is invalid, part_no(%u).", part_loc.part_no);
                    return NULL;
                }
            }
            if (index_part->btree.segment == NULL && !IS_INVALID_PAGID(index_part->btree.entry)) {
                table_t *table = &index->entity->table;
                table_part_t *table_part = TABLE_GET_PART(table, part_loc.part_no);
                if (table_part == NULL) {
                    return NULL;
                }
                if (IS_PARENT_TABPART(&table_part->desc)) {
                    if (part_loc.subpart_no == CT_INVALID_ID32) {
                        CT_LOG_RUN_ERR("subpart no is invalid, subpart_no(%u).", part_loc.subpart_no);
                        return NULL;
                    }
                    table_part = PART_GET_SUBENTITY(table->part_table, table_part->subparts[part_loc.subpart_no]);
                    if (table_part == NULL) {
                        CT_LOG_RUN_ERR("table partiton is invalid, subpart_no(%u).", part_loc.subpart_no);
                        return NULL;
                    }
                }
                if (dc_load_table_part_segment(session, index->entity, table_part) != CT_SUCCESS) {
                    CT_LOG_RUN_ERR("load table part segment is failed, panic info: page %u-%u table %s table_part %s "
                                   "index %s index_part %s",
                                   index_part->btree.entry.file, index_part->btree.entry.page, table->desc.name,
                                   table_part->desc.name, index->desc.name, index_part->desc.name);
                    CM_ASSERT(0);
                    return NULL;
                }
            }
            btree = &index_part->btree;
        }
    }
    return btree;
}

status_t dc_rename_table(knl_session_t *session, text_t *new_name, knl_dictionary_t *dc)
{
    dc_user_t *user = NULL;
    dc_entry_t *entry = NULL;
    dc_context_t *ctx = &session->kernel->dc_ctx;

    if (dc_open_user_by_id(session, dc->uid, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* to prevent deadlock with user_alter, we lock paral_lock first */
    dls_spin_lock(session, &ctx->paral_lock, NULL);
    dls_spin_lock(session, &user->lock, NULL);
    entry = DC_GET_ENTRY(user, dc->oid);
    dc_remove_from_bucket(session, entry);

    dc_update_objname_for_privs(session, dc->uid, entry->name, new_name, OBJ_TYPE_TABLE);

    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    (void)cm_text2str(new_name, entry->name, CT_NAME_BUFFER_SIZE);
    cm_spin_unlock(&entry->lock);

    dc_insert_into_index(user, entry, CT_FALSE);

    dls_spin_unlock(session, &user->lock);
    dls_spin_unlock(session, &ctx->paral_lock);

    return CT_SUCCESS;
}

bool32 dc_find_by_id(knl_session_t *session, dc_user_t *user, uint32 oid, bool32 ex_recycled)
{
    dc_entry_t *entry = NULL;
    uint32 gid;

    gid = oid / DC_GROUP_SIZE;
    entry = DC_GET_ENTRY(user, oid);
    if (gid >= DC_GROUP_COUNT || user->groups[gid] == NULL || entry == NULL) {
        return CT_FALSE;
    }
    if (!entry->ready || !entry->used || (ex_recycled && entry->recycled)) {
        return CT_FALSE;
    }
    return CT_TRUE;
}

void dc_load_child_entity(knl_session_t *session, cons_dep_t *dep, knl_dictionary_t *child_dc)
{
    cm_spin_lock(&dep->lock, NULL);
    if (dep->loaded && dep->chg_scn == child_dc->chg_scn) {
        cm_spin_unlock(&dep->lock);
        return;
    }

    dep->chg_scn = child_dc->chg_scn;
    dc_fk_indexable(session, DC_TABLE(child_dc), dep);
    dep->loaded = CT_TRUE;
    cm_spin_unlock(&dep->lock);
}


#ifdef Z_SHARDING

status_t dc_create_distribute_rule_entry(knl_session_t *session, knl_table_desc_t *desc)
{
    dc_user_t *user = NULL;
    dc_entry_t *entry = NULL;
    text_t rule_name;

    cm_str2text(desc->name, &rule_name);

    if (dc_open_user_by_id(session, desc->uid, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_create_entry(session, user, &rule_name, desc->id, CT_FALSE, &entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    entry->org_scn = desc->org_scn;
    entry->chg_scn = desc->chg_scn;
    if (desc->id == CT_INVALID_ID32) {
        desc->id = entry->id;
    }
    entry->type = DICT_TYPE_DISTRIBUTE_RULE;

    return CT_SUCCESS;
}
#endif

status_t dc_regist_global_dynamic_view(knl_session_t *session, knl_dynview_t *view)
{
    uint32 i;
    dc_user_t *user = NULL;
    dc_entry_t *entry = NULL;
    dc_entity_t *entity = NULL;
    dc_context_t *ctx;
    dynview_desc_t *desc;
    text_t user_name, view_name;

    ctx = &session->kernel->dc_ctx;

    desc = view->describe(view->id);
    if (desc == NULL) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "register", "global dynamic view");
        return CT_ERROR;
    }

    cm_str2text(desc->user, &user_name);
    cm_str2text(desc->name, &view_name);

    if (dc_open_user(session, &user_name, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_find(session, user, &view_name, NULL)) { // already registered
        return CT_SUCCESS;
    }

    if (dc_create_entry(session, user, &view_name, CT_INVALID_ID32, CT_FALSE, &entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    entry->type = DICT_TYPE_GLOBAL_DYNAMIC_VIEW;
    entry->lock = 0;
    entry->org_scn = 0;
    entry->chg_scn = 0;
    entry->ready = CT_TRUE;

    if (dc_alloc_entity(ctx, entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    entity = entry->entity;
    entity->dview = desc;
    entity->column_count = desc->column_count;

    if (dc_prepare_load_columns(session, entity) != CT_SUCCESS) {
        return CT_ERROR;
    }

    for (i = 0; i < desc->column_count; i++) {
        // dynamic view no need to copy column descriptions
        entity->column_groups[i / DC_COLUMN_GROUP_SIZE].columns[i % DC_COLUMN_GROUP_SIZE] = &desc->columns[i];
    }

    dc_create_column_index(entity);
    return CT_SUCCESS;
}

status_t dc_load_global_dynamic_views(knl_session_t *session)
{
    uint32 i;
    uint32 count;
    knl_dynview_t *views;

    count = session->kernel->global_dyn_view_count;
    views = session->kernel->global_dyn_views;

    for (i = 0; i < count; i++) {
        if (dc_regist_global_dynamic_view(session, &views[i]) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static bool32 dc_scan_user_tables(knl_session_t *session, dc_user_t *user, uint32 *table_id)
{
    dc_entry_t *entry = NULL;

    for (;;) {
        if (*table_id >= user->entry_hwm) {
            return CT_FALSE;
        }

        entry = dc_get_entry(user, *table_id);
        if (entry == NULL || !entry->used || entry->recycled) {
            (*table_id)++;
            continue;
        }

        if (entry->entity != NULL && DC_ENTRY_IS_MONITORED(entry)) {
            return CT_TRUE;
        }

        (*table_id)++;
    }
}

status_t dc_scan_all_tables(knl_session_t *session, uint32 *uid, uint32 *table_id, bool32 *eof)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    dc_user_t *user = NULL;

    if (*uid == CT_INVALID_ID32) {
        *uid = 0;
        *table_id = 0;
    } else {
        (*table_id)++;
    }

    for (;;) {
        if (*uid >= ctx->user_hwm) {
            *eof = CT_TRUE;
            return CT_SUCCESS;
        }

        user = ctx->users[*uid];

        if (user == NULL || user->status != USER_STATUS_NORMAL || !user->is_loaded) {
            (*uid)++;
            *table_id = 0;
            continue;
        }

        if (dc_open_user_by_id(session, *uid, &user) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (dc_scan_user_tables(session, user, table_id)) {
            return CT_SUCCESS;
        }

        (*uid)++;
        *table_id = 0;
    }
}

status_t dc_scan_tables_by_user(knl_session_t *session, uint32 uid, uint32 *table_id, bool32 *eof)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    dc_user_t *user = NULL;

    if ((*table_id) == CT_INVALID_ID32) {
        (*table_id) = 0;
    } else {
        (*table_id)++;
    }

    if (uid >= ctx->user_hwm) {
        *eof = CT_TRUE;
        return CT_SUCCESS;
    }

    user = ctx->users[uid];

    if (user == NULL || user->status != USER_STATUS_NORMAL || !user->is_loaded) {
        *eof = CT_TRUE;
        return CT_SUCCESS;
    }

    if (dc_open_user_by_id(session, uid, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_scan_user_tables(session, user, table_id)) {
        return CT_SUCCESS;
    }

    *eof = CT_TRUE;
    return CT_SUCCESS;
}

bool32 dc_replication_enabled(knl_session_t *session, dc_entity_t *entity, knl_part_locate_t part_loc)
{
    if (LOGIC_REP_TABLE_ENABLED(session, entity)) {
        return CT_TRUE;
    }

    if (IS_PART_TABLE(&entity->table) && part_loc.part_no != CT_INVALID_ID32) {
        table_t *table = &entity->table;
        table_part_t *table_part = TABLE_GET_PART(table, part_loc.part_no);
        if (IS_PARENT_TABPART(&table_part->desc) && part_loc.subpart_no != CT_INVALID_ID32) {
            table_part_t *subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[part_loc.subpart_no]);
            return LOGIC_REP_PART_ENABLED(subpart);
        } else {
            if (LOGIC_REP_PART_ENABLED(table_part)) {
                return CT_TRUE;
            }
        }
    }

    return CT_FALSE;
}

void dc_recycle_table_dls(knl_session_t *session, dc_entry_t *entry)
{
    if (!DB_IS_CLUSTER(session)) {
        return;
    }
    drc_recycle_lock_res(session, &entry->serial_lock.drid, DRC_GET_CURR_REFORM_VERSION);
    bool8 is_found = CT_TRUE;
    if (drc_lock_local_lock_res_by_id_for_recycle(session, &entry->ddl_latch.drid, DRC_GET_CURR_REFORM_VERSION, &is_found) == CT_ERROR) {
        return;
    }
    if (!is_found) {
        return;
    }
    drc_release_local_lock_res_by_id(session, &entry->ddl_latch.drid);
}
