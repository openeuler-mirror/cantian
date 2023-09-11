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
 * dc_log.c
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/dc_log.c
 *
 * -------------------------------------------------------------------------
 */
#include "dc_log.h"
#include "knl_context.h"
#include "knl_sequence.h"
#include "knl_database.h"
#include "knl_table.h"
#include "knl_user.h"
#include "knl_tenant.h"
#include "dc_priv.h"
#include "dc_part.h"
#include "dc_tbl.h"
#include "dc_seq.h"
#include "dc_user.h"
#include "dc_tenant.h"
#include "dc_util.h"
#include "cm_file.h"
#include "cm_text.h"
#include "dtc_dls.h"
#include "dtc_recovery.h"
#include "dtc_dc.h"
#include "srv_instance.h"

#ifdef WIN32
#else
#include <string.h>
#include <unistd.h>
#include<dirent.h>
#include <fcntl.h>
#endif

void rd_alter_sequence(knl_session_t *session, log_entry_t *log)
{
    rd_seq_t *rd = (rd_seq_t *)log->data;
    dc_user_t *user = NULL;
    sequence_entry_t *entry = NULL;

    if (dc_open_user_by_id(session, rd->uid, &user) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[SEQ] failed to replay alter sequence,user id %u doesn't exists", rd->uid);
        rd_check_dc_replay_err(session);
        knl_panic(!DB_IS_CLUSTER(session) || !DAAC_REPLAY_NODE(session));
        return;
    }

    if (dc_init_sequence_set(session, user) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[SEQ] failed to replay alter sequence");
        rd_check_dc_replay_err(session);
        knl_panic(!DB_IS_CLUSTER(session) || !DAAC_REPLAY_NODE(session));
        return;
    }

    entry = DC_GET_SEQ_ENTRY(user, rd->id);
    if (entry == NULL) {
        GS_LOG_RUN_ERR("[SEQ] failed to replay alter sequence,sequence doesn't exists");
        knl_panic(!DB_IS_CLUSTER(session) || !DAAC_REPLAY_NODE(session));
        return;
    }

    cm_spin_lock(&entry->lock.lock, NULL);
    if (entry->entity == NULL) {
        cm_spin_unlock(&entry->lock.lock);
        GS_LOG_RUN_INF("[SEQ] no need to replay alter sequence");
        return;
    }
    entry->entity->valid = GS_FALSE;
    entry->entity = NULL;
    cm_spin_unlock(&entry->lock.lock);
}

void print_alter_table(log_entry_t *log)
{
    rd_table_t *rd = (rd_table_t *)log->data;
    printf("alter table uid:%u,oid:%u\n", rd->uid, rd->oid);
}

void rd_invalidate_parents(knl_session_t *session, dc_entity_t *entity)
{
    table_t *table = &entity->table;
    ref_cons_t *ref = NULL;
    dc_user_t *user = NULL;
    dc_entry_t *entry = NULL;
    uint32 i;

    for (i = 0; i < table->cons_set.ref_count; i++) {
        ref = table->cons_set.ref_cons[i];

        if (ref->ref_uid == table->desc.uid && ref->ref_oid == table->desc.id) {
            continue;
        }

        if (dc_open_user_by_id(session, ref->ref_uid, &user) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DC] failed to replay alter table %u.%u doesn't exists\n", ref->ref_uid, ref->ref_oid);
            rd_check_dc_replay_err(session);
            continue;
        }

        if (!dc_find_by_id(session, user, ref->ref_oid, GS_FALSE)) {
            GS_LOG_RUN_ERR("[DC] failed to replay alter table,table id %u doesn't exists\n", ref->ref_oid);
            continue;
        }

        /* seem like dc_open and dc_invalidate */
        entry = DC_GET_ENTRY(user, ref->ref_oid);
        cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
        dc_entity_t *parent_entity = rd_invalid_entity(session, entry);
        cm_spin_unlock(&entry->lock);

        if (parent_entity != NULL) {
            dc_close_entity(session->kernel, parent_entity, GS_TRUE);
        }
    }
}

void rd_invalidate_children(knl_session_t *session, dc_entity_t *entity)
{
    table_t *table = &entity->table;
    index_t *index = NULL;
    cons_dep_t *dep = NULL;
    dc_user_t *user = NULL;
    dc_entry_t *entry = NULL;
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

            if (dc_open_user_by_id(session, dep->uid, &user) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[DC] failed to replay alter table %u.%u doesn't exists\n", dep->uid, dep->oid);
                rd_check_dc_replay_err(session);
                dep = dep->next;
                continue;
            }

            if (!dc_find_by_id(session, user, dep->oid, GS_FALSE)) {
                GS_LOG_RUN_ERR("[DC] failed to replay alter table,table id %u doesn't exists\n", dep->oid);
                dep = dep->next;
                continue;
            }

            /* seem like dc_open and dc_invalidate */
            entry = DC_GET_ENTRY(user, dep->oid);
            cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
            dc_entity_t *child_entity = rd_invalid_entity(session, entry);
            cm_spin_unlock(&entry->lock);

            if (child_entity != NULL) {
                dc_close_entity(session->kernel, child_entity, GS_TRUE);
            }

            dep = dep->next;
        }
    }
}


dc_entity_t *rd_invalid_entity(knl_session_t *session, dc_entry_t *entry)
{
    dc_entity_t *entity = NULL;

    if (entry->entity != NULL) {
        table_t *table = &entry->entity->table;

        if (TABLE_IS_TEMP(table->desc.type)) {
            knl_temp_cache_t *temp_cache = knl_get_temp_cache(session, table->desc.uid, table->desc.id);
            if (temp_cache != NULL) {
                knl_free_temp_cache_memory(temp_cache);
            }
        }

        cm_spin_lock(&entry->entity->ref_lock, NULL);
        entry->entity->ref_count++;
        entity = entry->entity;
        cm_spin_unlock(&entry->entity->ref_lock);

        if (entity->valid) {
            entry->entity->valid = GS_FALSE;
            entry->entity = NULL;
        }
    }

    return entity;
}

void rd_alter_table(knl_session_t *session, log_entry_t *log)
{
    rd_table_t *rd = (rd_table_t *)log->data;
    dc_user_t *user = NULL;
    dc_entry_t *entry = NULL;
    GS_LOG_RUN_INF("[DC] start to replay alter table id %u, user id %u", rd->oid, rd->uid);

    if (dc_open_user_by_id(session, rd->uid, &user) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DC] failed to replay alter table id %u, user id %u doesn't exists\n", rd->oid, rd->uid);
        rd_check_dc_replay_err(session);
        knl_panic(!DB_IS_CLUSTER(session) || !DAAC_REPLAY_NODE(session));
        return;
    }

    if (!dc_find_by_id(session, user, rd->oid, GS_FALSE)) {
        GS_LOG_RUN_ERR("[DC] failed to replay alter table,table id %u doesn't exists\n", rd->oid);
        knl_panic(!DB_IS_CLUSTER(session) || !DAAC_REPLAY_NODE(session));
        return;
    }

    /* seem like dc_open and dc_invalidate */
    entry = DC_GET_ENTRY(user, rd->oid);
    if (entry == NULL) {
        GS_LOG_RUN_ERR("[DC] failed to replay alter table,resource of table id %u doesn't exists\n", rd->oid);
        return;
    }
    cm_spin_lock(&entry->sch_lock_mutex, &session->stat->spin_stat.stat_sch_lock);
    if (DAAC_PARTIAL_RECOVER_SESSION(session) && dc_is_locked(entry)) {
        // in partial recoverey, dc resource is busy means this logic log is staled, and do not need to replay
        GS_LOG_RUN_WAR("[DC] no need to replay alter table,resource of table id %u is busy\n", rd->oid);
        cm_spin_unlock(&entry->sch_lock_mutex);
        return;
    }

    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    
    if (IS_COMPATIBLE_MYSQL_INST && rd->op_type == RD_TRUNCATE_TABLE) {
        entry->serial_value = 0;
    }

    if (entry->entity != NULL) {
        rd_invalidate_children(session, entry->entity);
        rd_invalidate_parents(session, entry->entity);
    }

    dc_entity_t *entity = rd_invalid_entity(session, entry);

    if (IS_CORE_SYS_TABLE(rd->uid, rd->oid)) {
        if (dc_load_core_table(session, rd->oid) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DC] failed to reload sys core table id %u\n", rd->oid);
            rd_check_dc_replay_err(session);
        }
    } else {
        if (dc_is_reserved_entry(rd->uid, rd->oid)) {
            if (dc_load_entity(session, user, rd->oid, entry) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[DC] failed to reload sys table id %u\n", rd->oid);
                rd_check_dc_replay_err(session);
            }

            knl_dictionary_t dc;
            db_get_sys_dc(session, rd->oid, &dc);
            db_update_seg_scn(session, &dc);
        }
    }

    cm_spin_unlock(&entry->lock);
    cm_spin_unlock(&entry->sch_lock_mutex);

    if (entity != NULL) {
        dc_close_entity(session->kernel, entity, GS_TRUE);
    }
    GS_LOG_DEBUG_INF("[DC] replay alter table id %u successfully", rd->oid);
}


/* only clear the privileges that granted to user */
void rd_clear_user_priv(dc_context_t *ctx, dc_user_t *user)
{
    errno_t err;
    dc_user_granted *child_user = NULL;
    dc_granted_role *parent = NULL;
    cm_list_head *item1 = NULL;
    cm_list_head *item2 = NULL;
    cm_list_head *temp1 = NULL;
    cm_list_head *temp2 = NULL;

    /* clear system privileges */
    err = memset_sp(user->sys_privs, sizeof(user->sys_privs), 0, sizeof(user->sys_privs));
    knl_securec_check(err);
    err = memset_sp(user->admin_opt, sizeof(user->admin_opt), 0, sizeof(user->admin_opt));
    knl_securec_check(err);
    err = memset_sp(user->all_sys_privs, sizeof(user->all_sys_privs), 0, sizeof(user->all_sys_privs));
    knl_securec_check(err);
    err = memset_sp(user->ter_admin_opt, sizeof(user->ter_admin_opt), 0, sizeof(user->ter_admin_opt));
    knl_securec_check(err);

    /* clear all object privileges */
    dc_clear_all_objprivs(&user->obj_privs);

    /* clear all user privileges */
    dc_clear_all_userprivs(&user->user_privs);

    /* clear all object privilege items saved by the grantor */
    dc_clear_grantor_objprivs(ctx, &user->obj_privs, user->desc.id, TYPE_USER);

    /* delete the parent nodes in list. the list will rebuild during replay period */
    cm_list_for_each_safe(item1, temp1, &user->parent)
    {
        parent = cm_list_entry(item1, dc_granted_role, node);
        cm_list_remove(item1);

        cm_list_for_each_safe(item2, temp2, &parent->granted_role->child_users)
        {
            child_user = cm_list_entry(item2, dc_user_granted, node);
            if (user == child_user->user_granted) {
                cm_list_remove(item2);
                break;
            }
        }
    }

    cm_list_init(&user->parent);
}

static status_t rd_create_table_set_type(knl_session_t *session, table_type_t type, dc_entry_t *entry)
{
    switch (type) {
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
        default:
            GS_LOG_RUN_ERR("invalid table type %d", type);
            return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t rd_create_table_entry(knl_session_t *session, dc_user_t *user, text_t *obj_name, bool32 *is_exists)
{
    dc_entry_t *entry = NULL;
    knl_table_desc_t desc;
    text_t name;

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TABLE_ID, IX_SYS_TABLE_001_ID);

    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&user->desc.id,
                     sizeof(uint32), IX_COL_SYS_TABLE_001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, (void *)obj_name->str,
                     obj_name->len, IX_COL_SYS_TABLE_001_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    *is_exists = !cursor->eof;
    if (!(*is_exists)) {
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }

    dc_convert_table_desc(cursor, &desc);
    cm_str2text(desc.name, &name);

    cm_spin_lock(&session->kernel->db.replay_logic_lock, NULL);

    if (dc_create_entry_with_oid(session, user, &name, desc.id, &entry) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        cm_spin_unlock(&session->kernel->db.replay_logic_lock);
        return GS_ERROR;
    }

    entry->org_scn = desc.org_scn;
    entry->chg_scn = desc.chg_scn;

    if (rd_create_table_set_type(session, desc.type, entry) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        cm_spin_unlock(&session->kernel->db.replay_logic_lock);
        return GS_ERROR;
    }

    entry->ready = GS_TRUE;
    dc_insert_into_index(user, entry, GS_FALSE);

    CM_RESTORE_STACK(session->stack);
    cm_spin_unlock(&session->kernel->db.replay_logic_lock);
    return GS_SUCCESS;
}

static status_t rd_create_view_entry(knl_session_t *session, dc_user_t *user, text_t *obj_name, bool32 *is_found)
{
    knl_cursor_t *cursor = NULL;
    dc_entry_t *entry = NULL;
    knl_view_t desc;
    text_t name;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_VIEW_ID, IX_SYS_VIEW001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&user->desc.id,
        sizeof(uint32), IX_COL_SYS_VIEW001_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, (void *)obj_name->str,
        obj_name->len, IX_COL_SYS_VIEW001_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    *is_found = !cursor->eof;
    if (!(*is_found)) {
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }

    if (dc_convert_view_desc(session, cursor, &desc, NULL) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    cm_str2text(desc.name, &name);
    if (dc_create_entry_with_oid(session, user, &name, desc.id, &entry) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    entry->type = DICT_TYPE_VIEW;
    entry->org_scn = desc.org_scn;
    entry->chg_scn = desc.chg_scn;
    entry = DC_GET_ENTRY(user, desc.id);
    entry->ready = GS_TRUE;
    dc_insert_into_index(user, entry, GS_FALSE);

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t rd_create_table_reform(knl_session_t *session, dc_user_t *user, rd_create_table_t *rd)
{
    dc_entry_t *entry = NULL;
    text_t name;
    GS_LOG_RUN_INF("[DC] Reforming: start replay create table %s,table id %u", rd->obj_name, rd->oid);

    cm_str2text(rd->obj_name, &name);

    cm_spin_lock(&session->kernel->db.replay_logic_lock, NULL);
    if (dc_create_entry_with_oid(session, user, &name, rd->oid, &entry) != GS_SUCCESS) {
        cm_spin_unlock(&session->kernel->db.replay_logic_lock);
        return GS_ERROR;
    }

    entry->org_scn = rd->org_scn;
    entry->chg_scn = rd->chg_scn;

    if (rd_create_table_set_type(session, rd->type, entry) != GS_SUCCESS) {
        cm_spin_unlock(&session->kernel->db.replay_logic_lock);
        return GS_ERROR;
    }

    entry->ready = GS_TRUE;
    dc_insert_into_index(user, entry, GS_FALSE);
    cm_spin_unlock(&session->kernel->db.replay_logic_lock);

    return GS_SUCCESS;
}

void rd_create_table(knl_session_t *session, log_entry_t *log)
{
    dc_user_t *user = NULL;
    text_t obj_name;
    bool32 is_found = GS_FALSE;
    rd_create_table_t *rd = (rd_create_table_t *)log->data;
    GS_LOG_RUN_INF("[DC] start to replay create table or view %s", rd->obj_name);

    if (dc_open_user_by_id(session, rd->uid, &user) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DC] failed to replay create table %s,user id %u doesn't exists", rd->obj_name, rd->uid);
        rd_check_dc_replay_err(session);
        knl_panic(!DB_IS_CLUSTER(session) || !DAAC_REPLAY_NODE(session));
        return;
    }

    // only one session process the same message from the same source.
    // two sessions (reform and sync_ddl) still may perform in parallel, as one session may come when the other session
    // has not finish create table.
    if (dc_find_by_id(session, user, rd->oid, GS_TRUE)) {
        GS_LOG_RUN_INF("[DC] no need to replay create table %s,table id %u already exists", rd->obj_name, rd->oid);
        return;
    }

    if (DAAC_PARTIAL_RECOVER_SESSION(session)) {
        if (rd_create_table_reform(session, user, rd) != GS_SUCCESS) {
            if (cm_get_error_code() == ERR_OBJECT_ID_EXISTS) {
                // for two sessions (reform and sync_ddl) perform in parallel, one session may just finish create table
                // when the other session arrives here
                GS_LOG_RUN_WAR("[DC] failed to replay create table %s, table is already exists", rd->obj_name);
                return;
            }
            GS_LOG_RUN_ERR("[DC] failed to replay create table %s", rd->obj_name);
            knl_panic(!DB_IS_CLUSTER(session));
            return;
        }
        GS_LOG_DEBUG_INF("[DC] replay create table %s successfully", rd->obj_name);
        return;
    }

    cm_str2text(rd->obj_name, &obj_name);
    if (rd_create_table_entry(session, user, &obj_name, &is_found) != GS_SUCCESS) {
        if (cm_get_error_code() == ERR_OBJECT_ID_EXISTS) {
            // for two sessions (reform and sync_ddl) perform in parallel, one session may just finish create table when
            // the other session arrives here
            GS_LOG_RUN_WAR("[DC] failed to replay create table %s, table is already exists", rd->obj_name);
            return;
        }
        GS_LOG_RUN_ERR("[DC] failed to replay create table %s", rd->obj_name);
        rd_check_dc_replay_err(session);
        knl_panic(!DB_IS_CLUSTER(session) || !DAAC_REPLAY_NODE(session));
        return;
    }

    if (is_found) {
        GS_LOG_DEBUG_INF("[DC] replay create table %s successfully", rd->obj_name);
        return;
    }

    if (rd_create_view_entry(session, user, &obj_name, &is_found) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DC] failed to replay create view %s\n", rd->obj_name);
        rd_check_dc_replay_err(session);
        knl_panic(!DB_IS_CLUSTER(session) || !DAAC_REPLAY_NODE(session));
        return;
    }
    GS_LOG_RUN_INF("[DC] replay create view %s successfully", rd->obj_name);
    knl_panic(!DB_IS_CLUSTER(session) || is_found || !DAAC_REPLAY_NODE(session));
}

void print_create_table(log_entry_t *log)
{
    rd_create_table_t *rd = (rd_create_table_t *)log->data;
    printf("create table uid:%u,oid:%u,table_name:%s\n", rd->uid, rd->oid, rd->obj_name);
}


void rd_drop_sequence(knl_session_t *session, log_entry_t *log)
{
    rd_seq_t *rd = (rd_seq_t *)log->data;
    dc_user_t *user = NULL;
    sequence_entry_t *entry = NULL;

    if (dc_open_user_by_id(session, rd->uid, &user) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[SEQ] failed to replay drop sequence,user id %u doesn't exists", rd->uid);
        rd_check_dc_replay_err(session);
        return;
    }

    if (dc_init_sequence_set(session, user) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[SEQ] failed to replay drop sequence");
        rd_check_dc_replay_err(session);
        return;
    }

    entry = DC_GET_SEQ_ENTRY(user, rd->id);
    if (entry != NULL) {
        dc_sequence_drop(session, entry);
    }
}

void rd_dc_drop(knl_session_t *session, dc_user_t *user, dc_entry_t *entry)
{
    synonym_link_t *synonym_link = NULL;
    dc_context_t *ctx = &session->kernel->dc_ctx;

    if (entry->bucket != NULL) {
        dc_remove_from_bucket(session, entry);
    }

    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    if (entry->entity != NULL) {
        dc_release_segment_dls(session, entry->entity);
        entry->entity->valid = GS_FALSE;
        entry->entity = NULL;
    }
    entry->used = GS_FALSE;
    entry->org_scn = 0;
    entry->chg_scn = 0;  // no need save chg_scn on standby
    entry->recycled = GS_FALSE;
    entry->serial_value = 0;
    entry->serial_lock.lock = 0;
    if (entry->appendix == NULL) {
        cm_spin_unlock(&entry->lock);
        return;
    }

    synonym_link = entry->appendix->synonym_link;
    entry->appendix->synonym_link = NULL;
    cm_spin_unlock(&entry->lock);

    cm_spin_lock(&ctx->lock, NULL);
    if (synonym_link != NULL) {
        dc_list_add(&ctx->free_synonym_links, (dc_list_node_t *)synonym_link);
    }
    dc_recycle_table_dls(session, entry);

    dc_free_entry_list_add(user, entry);
    cm_spin_unlock(&ctx->lock);
}

void rd_dc_remove(knl_session_t *session, dc_entry_t *entry, text_t *name)
{
    if (entry->recycled) {
        GS_LOG_RUN_INF("[DC] has recycled table,table %s has been recycled\n", entry->name);
        return;
    }

    if (entry->bucket != NULL) {
        dc_remove_from_bucket(session, entry);
    }

    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    if (entry->entity != NULL) {
        dc_release_segment_dls(session, entry->entity);
        entry->entity->valid = GS_FALSE;
        entry->entity = NULL;
    }
    entry->recycled = GS_TRUE;
    (void)cm_text2str(name, entry->name, GS_NAME_BUFFER_SIZE);
    cm_spin_unlock(&entry->lock);
}

void rd_drop_table(knl_session_t *session, log_entry_t *log)
{
    rd_drop_table_t *rd = (rd_drop_table_t *)log->data;
    dc_user_t *user = NULL;
    text_t name;
    dc_entry_t *entry = NULL;
    dc_entity_t *entity = NULL;
    GS_LOG_RUN_INF("[DC] start to replay drop table %s, user id %u", rd->name, rd->uid);

    if (dc_open_user_by_id(session, rd->uid, &user) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DC] failed to replay drop table %s,user id %u doesn't exists\n", rd->name, rd->uid);
        rd_check_dc_replay_err(session);
        return;
    }

    cm_str2text(rd->name, &name);

    entry = DC_GET_ENTRY(user, rd->oid);
    if (entry == NULL) {
        GS_LOG_RUN_INF("[DC] no need to replay drop table,table %s doesn't exists\n", rd->name);
        return;
    }

    cm_spin_lock(&session->kernel->db.replay_logic_lock, NULL);

    GS_LOG_RUN_INF("[DC] replay drop table,table %s, uid %u, tid %u \n", rd->name, rd->uid, rd->oid);
    // only one session process the same message from the same source.
    if (!dc_find(session, user, &name, NULL)) {
        GS_LOG_RUN_INF("[DC] no need to replay drop table,table %s doesn't exists\n", rd->name);
        cm_spin_unlock(&session->kernel->db.replay_logic_lock);
        return;
    }

    if (entry->org_scn != rd->org_scn) {
        GS_LOG_RUN_WAR("[DC] no need to replay drop table %s, logic log is stale\n", rd->name);
        cm_spin_unlock(&session->kernel->db.replay_logic_lock);
        return;
    }

    cm_spin_lock(&entry->sch_lock_mutex, &session->stat->spin_stat.stat_sch_lock);
    if (DAAC_PARTIAL_RECOVER_SESSION(session) && dc_is_locked(entry)) {
        // in partial recoverey, dc resource is busy means this logic log is staled, and do not need to replay
        GS_LOG_RUN_WAR("[DC] no need to replay drop table, resource of table id %u is busy\n", rd->oid);
        cm_spin_unlock(&entry->sch_lock_mutex);
        cm_spin_unlock(&session->kernel->db.replay_logic_lock);
        return;
    }

    /* seem like dc_open */
    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    if (entry->entity != NULL) {
        cm_spin_lock(&entry->entity->ref_lock, NULL);
        entry->entity->ref_count++;
        entity = entry->entity;
        cm_spin_unlock(&entry->entity->ref_lock);
    }
    cm_spin_unlock(&entry->lock);
    cm_spin_unlock(&entry->sch_lock_mutex);

    if (rd->purge) {
        rd_dc_drop(session, user, entry);
    } else {
        rd_dc_remove(session, entry, &name);
    }
    cm_spin_unlock(&session->kernel->db.replay_logic_lock);

    if (entity != NULL) {
        dc_close_entity(session->kernel, entity, GS_TRUE);
    }
    GS_LOG_DEBUG_INF("[DC] replay drop table %s successfully", rd->name);
}


void rd_drop_view(knl_session_t *session, log_entry_t *log)
{
    rd_view_t *rd = (rd_view_t *)log->data;
    dc_user_t *user = NULL;
    dc_entry_t *entry = NULL;
    dc_entity_t *entity = NULL;

    if (dc_open_user_by_id(session, rd->uid, &user) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DC] failed to replay drop view id %u,user id %u doesn't exists\n", rd->oid, rd->uid);
        rd_check_dc_replay_err(session);
        return;
    }

    if (!dc_find_by_id(session, user, rd->oid, GS_TRUE)) {
        GS_LOG_RUN_INF("[DC] no need to replay drop view,view id %u doesn't exists\n", rd->oid);
        return;
    }

    entry = DC_GET_ENTRY(user, rd->oid);
    if (entry == NULL) {
        GS_LOG_RUN_INF("[DC] no need to replay drop view,view id %u doesn't exists\n", rd->oid);
        return;
    }

    /* seem like dc_open */
    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    if (entry->entity != NULL) {
        cm_spin_lock(&entry->entity->ref_lock, NULL);
        entry->entity->ref_count++;
        entity = entry->entity;
        cm_spin_unlock(&entry->entity->ref_lock);
    }
    cm_spin_unlock(&entry->lock);

    rd_dc_drop(session, user, entry);

    if (entity != NULL) {
        dc_close_entity(session->kernel, entity, GS_TRUE);
    }
}

void rd_rename_table(knl_session_t *session, log_entry_t *log)
{
    rd_rename_table_t *rd = (rd_rename_table_t *)log->data;
    dc_user_t *user = NULL;
    dc_entry_t *entry = NULL;
    dc_entity_t *entity = NULL;
    errno_t err;
    GS_LOG_RUN_INF("[DC] start to replay rename table id %u, user id %u", rd->oid, rd->uid);

    if (dc_open_user_by_id(session, rd->uid, &user) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DC] failed to replay rename table id %u, user id %u doesn't exists\n", rd->oid, rd->uid);
        rd_check_dc_replay_err(session);
        return;
    }

    if (!dc_find_by_id(session, user, rd->oid, GS_FALSE)) {
        GS_LOG_RUN_ERR("[DC] failed to replay rename table,table id %u doesn't exists\n", rd->oid);
        return;
    }

    // only one session process the same message from the same source.
    entry = DC_GET_ENTRY(user, rd->oid);
    cm_spin_lock(&entry->sch_lock_mutex, &session->stat->spin_stat.stat_sch_lock);
    if (DAAC_PARTIAL_RECOVER_SESSION(session) && dc_is_locked(entry)) {
        // in partial recoverey, dc resource is busy means this logic log is staled, and do not need to replay
        GS_LOG_RUN_WAR("[DC] no need to replay alter table,resource of table id %u is busy\n", rd->oid);
        cm_spin_unlock(&entry->sch_lock_mutex);
        return;
    }
    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    if (strcmp(entry->name, rd->new_name) == 0) {
        cm_spin_unlock(&entry->lock);
        cm_spin_unlock(&entry->sch_lock_mutex);
        return;
    }
    cm_spin_unlock(&entry->lock);

    dc_remove_from_bucket(session, entry);
    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    err = memcpy_sp(entry->name, GS_NAME_BUFFER_SIZE, rd->new_name, GS_NAME_BUFFER_SIZE);
    knl_securec_check(err);

    /* if entity has loaded, we need to rename entity, otherwise entry->name
     * will be different from entity->table.desc.name
     */
    if (dc_is_reserved_entry(rd->uid, rd->oid)) {
        if (entry->entity != NULL) {
            err = memcpy_sp(entry->entity->table.desc.name, GS_NAME_BUFFER_SIZE, rd->new_name, GS_NAME_BUFFER_SIZE);
            knl_securec_check(err);
        }
    } else {
        entity = rd_invalid_entity(session, entry);
    }

    cm_spin_unlock(&entry->lock);
    cm_spin_unlock(&entry->sch_lock_mutex);
    dc_insert_into_index(user, entry, GS_FALSE);

    if (entity != NULL) {
        dc_close_entity(session->kernel, entity, GS_TRUE);
    }
    GS_LOG_RUN_INF("[DC] replay rename table id %u successfully", rd->oid);
}

void print_rename_table(log_entry_t *log)
{
    rd_rename_table_t *rd = (rd_rename_table_t *)log->data;
    printf("create table uid:%u,oid:%u,new_name:%s\n", rd->uid, rd->oid, rd->new_name);
}

void rd_create_synonym(knl_session_t *session, log_entry_t *log)
{
    text_t name;
    rd_synonym_t *rd = (rd_synonym_t *)log->data;
    knl_synonym_t synonym;
    dc_user_t *user = NULL;
    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SYN_ID, IX_SYS_SYNONYM002_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &rd->uid, sizeof(uint32),
        IX_COL_SYS_SYNONYM002_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &rd->id, sizeof(uint32),
        IX_COL_SYS_SYNONYM002_OBJID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return;
    }

    if (cursor->eof) {
        GS_LOG_RUN_ERR("rd_create_synonym expect synonym uid %u id %u, but not exist", rd->uid, rd->id);
        CM_RESTORE_STACK(session->stack);
        knl_panic(!DB_IS_CLUSTER(session));
        return;
    }
    synonym.uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_USER);
    synonym.id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_OBJID);
    synonym.org_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_ORG_SCN);
    synonym.chg_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_CHG_SCN);
    name.str = CURSOR_COLUMN_DATA(cursor, SYS_SYN_SYNONYM_NAME);
    name.len = CURSOR_COLUMN_SIZE(cursor, SYS_SYN_SYNONYM_NAME);
    (void)cm_text2str(&name, synonym.name, GS_NAME_BUFFER_SIZE);
    name.str = CURSOR_COLUMN_DATA(cursor, SYS_SYN_TABLE_OWNER);
    name.len = CURSOR_COLUMN_SIZE(cursor, SYS_SYN_TABLE_OWNER);
    (void)cm_text2str(&name, synonym.table_owner, GS_NAME_BUFFER_SIZE);
    name.str = CURSOR_COLUMN_DATA(cursor, SYS_SYN_TABLE_NAME);
    name.len = CURSOR_COLUMN_SIZE(cursor, SYS_SYN_TABLE_NAME);
    (void)cm_text2str(&name, synonym.table_name, GS_NAME_BUFFER_SIZE);
    synonym.type = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_TYPE);

    if (dc_open_user_by_id(session, synonym.uid, &user) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        rd_check_dc_replay_err(session);
        return;
    }

    if (dc_create_synonym_entry(session, user, &synonym) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("rd_create_synonym create synonym entry uid %u id %u failed", rd->uid, rd->id);
        rd_check_dc_replay_err(session);
        CM_RESTORE_STACK(session->stack);
        return;
    }
    CM_RESTORE_STACK(session->stack);
    dc_ready(session, rd->uid, rd->id);

    return;
}

void rd_drop_synonym(knl_session_t *session, log_entry_t *log)
{
    rd_synonym_t *rd = (rd_synonym_t *)log->data;
    dc_free_broken_entry(session, rd->uid, rd->id);
}

void print_create_synonym(log_entry_t *log)
{
    rd_synonym_t *rd = (rd_synonym_t *)log->data;
    printf("create synonym uid:%u,id:%u\n", rd->uid, rd->id);
}

void print_drop_synonym(log_entry_t *log)
{
    rd_synonym_t *rd = (rd_synonym_t *)log->data;
    printf("drop synonym uid:%u,id:%u\n", rd->uid, rd->id);
}

void print_drop_table(log_entry_t *log)
{
    rd_drop_table_t *rd = (rd_drop_table_t *)log->data;
    printf("drop table purge:%u,uid:%u,obj:%s,org_scn:%llu\n", rd->purge, rd->uid, rd->name, rd->org_scn);
}

bool32 is_drop_same_user(knl_session_t *session, uint32 uid, rd_user_t *rd)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;

    dc_user_t *dc_user = ctx->users[uid];
    text_t name;
    name.str = rd->name;
    name.len = strlen(rd->name);
    if (cm_text_str_equal(&name, dc_user->desc.name)) {
        return GS_TRUE;
    }

    return GS_FALSE;
}

static void dc_redo_info_to_user(rd_user_t *rd, dc_user_t *user)
{
    strcpy_sp(user->desc.name, GS_NAME_BUFFER_SIZE, rd->name);
    strcpy_sp(user->desc.password, GS_PASSWORD_BUFFER_SIZE, rd->password);
    user->desc.id = rd->uid;
    user->desc.ctime = rd->ctime;
    user->desc.ptime = rd->ptime;
    user->desc.exptime = rd->exptime;
    user->desc.ltime = rd->ltime;
    user->desc.profile_id = rd->profile_id;
    user->desc.astatus = rd->astatus;
    user->desc.lcount = rd->lcount;
    user->desc.data_space_id = rd->data_space_id;
    user->desc.temp_space_id = rd->temp_space_id;
    user->desc.tenant_id = rd->tenant_id;
}

/* based on:
 * 1.user created by creating database 2.create database would trigger full ckpt
 * the logic log would up to date
 */
status_t dc_create_user_reform(knl_session_t *session, rd_user_t *rd)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    dc_user_t *user = NULL;
    
    if (!ctx->users[rd->uid]) {
        if (dc_alloc_mem(ctx, ctx->memory, sizeof(dc_user_t), (void **)&user) != GS_SUCCESS) {
            return GS_ERROR;
        }
        memset_sp(user, sizeof(dc_user_t), 0, sizeof(dc_user_t));
        ctx->users[rd->uid] = user;

        if (dc_init_user(ctx, user) != GS_SUCCESS) {
            return GS_ERROR;
        }

        dls_init_spinlock(&user->lock, DR_TYPE_USER, DR_ID_DATABASE_CTRL, (uint16)rd->uid);
        dls_init_spinlock(&user->s_lock, DR_TYPE_USER, DR_ID_DATABASE_SWITCH_CTRL, (uint16)rd->uid);
        dls_init_latch(&user->user_latch, DR_TYPE_USER, DR_ID_DATABASE_BAKUP, (uint16)rd->uid);
        dls_init_latch(&user->lib_latch, DR_TYPE_USER, DR_ID_DATABASE_LINK, (uint16)rd->uid);

        if (dc_init_table_context(ctx, user) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        user = ctx->users[rd->uid];
    }

    user->status = USER_STATUS_NORMAL;
    dc_redo_info_to_user(rd, user);
    dc_insert_into_user_index(ctx, user);
    dc_set_user_hwm(ctx, rd->uid);
    GS_LOG_RUN_INF("[DB] Success to replay create user %s during reform", rd->name);
    return GS_SUCCESS;
}

void rd_create_user(knl_session_t *session, log_entry_t *log)
{
    rd_user_t *rd = (rd_user_t *)log->data;
    dc_user_t *user = NULL;
    GS_LOG_RUN_INF("[DB] Start to replay create user %s", rd->name);
    cm_spin_lock(&session->kernel->db.replay_logic_lock, NULL);
    // if user is not being dropped, clean the drop uid in session
    if (DAAC_PARTIAL_RECOVER_SESSION(session) || DAAC_REPLAY_NODE(session)) {
        dc_context_t *ctx = &session->kernel->dc_ctx;
        dc_user_t *dc_user = ctx->users[rd->uid];
        if (dc_user && dc_user->status != USER_STATUS_LOCKED) {
            GS_LOG_RUN_INF("[DB] clean drop uid in session, user id is %u \n", rd->uid);
            session->drop_uid = GS_INVALID_ID32;
        }
    }

    // only one session process the same message from the same source.
    status_t ret = DAAC_REPLAY_NODE(session) ?
        dc_open_user_by_id_for_replay(session, rd->uid, &user) : dc_open_user_by_id(session, rd->uid, &user);
    if (ret == GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DB] failed to replay create user %s,user id %u already occupied by %s", rd->name, rd->uid,
            user->desc.name);
        rd_check_dc_replay_err(session);
        cm_spin_unlock(&session->kernel->db.replay_logic_lock);
        return;
    }

    // clean the error code for ERR_USER_ID_NOT_EXIST when dc_open_user_by_id
    int32 err_code = cm_get_error_code();
    if (err_code == ERR_USER_ID_NOT_EXIST) {
        cm_reset_error();
    }

    if (dc_create_user_reform(session, rd) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DB] failed to replay create user %s", rd->name);
        rd_check_dc_replay_err(session);
    }
    GS_LOG_RUN_INF("[DB] Success to replay create user %s", rd->name);
    cm_spin_unlock(&session->kernel->db.replay_logic_lock);
}

void print_create_user(log_entry_t *log)
{
    rd_user_t *rd = (rd_user_t *)log->data;
    printf("create user uid:%u,name:%s\n", rd->uid, rd->name);
}

void rd_alter_user(knl_session_t *session, log_entry_t *log)
{
    bool32 is_found = GS_FALSE;
    rd_user_t *rd = (rd_user_t *)log->data;
    dc_user_t *user = NULL;
    text_t user_name;

    cm_str2text(rd->name, &user_name);
    if (dc_open_user(session, &user_name, &user) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DB] failed to replay alter user, user %s doesn't exist", rd->name);
        rd_check_dc_replay_err(session);
        return;
    }

    if (dc_update_user(session, rd->name, &is_found) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DB] failed to replay alter user %s", rd->name);
        rd_check_dc_replay_err(session);
    }
}

void print_alter_user(log_entry_t *log)
{
    rd_user_t *rd = (rd_user_t *)log->data;
    printf("alter user uid:%u,name:%s\n", rd->uid, rd->name);
}

void rd_drop_user(knl_session_t *session, log_entry_t *log)
{
    rd_user_t *rd = (rd_user_t *)log->data;
    dc_user_t *user = NULL;
    GS_LOG_RUN_INF("[DB] Start to replay drop user, user id %u", rd->uid);
    cm_spin_lock(&session->kernel->db.replay_logic_lock, NULL);

    if (DAAC_PARTIAL_RECOVER_SESSION(session) || DAAC_REPLAY_NODE(session)) {
        if (dtc_modify_drop_uid(session, rd->uid) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DB] failed to replay drop user, user id %u doesn't exist", rd->uid);
            rd_check_dc_replay_err(session);
            cm_spin_unlock(&session->kernel->db.replay_logic_lock);
            return;
        }
    }

    if (DAAC_PARTIAL_RECOVER_SESSION(session)) {
        if (is_drop_same_user(session, rd->uid, rd) != GS_TRUE) {
            GS_LOG_RUN_ERR("[DB] failed to replay drop user %u,user name different from current user", rd->uid);
            rd_check_dc_replay_err(session);
            cm_spin_unlock(&session->kernel->db.replay_logic_lock);
            return;
        }
        dc_context_t *ctx = &session->kernel->dc_ctx;
        dc_user_t *dc_user = ctx->users[rd->uid];
        if (dc_user->status != USER_STATUS_LOCKED) {
            GS_LOG_RUN_ERR("[DB] failed to replay drop user %u, user is not locked", rd->uid);
            cm_spin_unlock(&session->kernel->db.replay_logic_lock);
            return;
        }
        dtc_try_clean_user_lock(session, dc_user);
    }

    // only one session process the same message from the same source.
    if (dc_open_user_by_id_for_replay(session, rd->uid, &user) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DB] failed to replay drop user,user id %u doesn't exist", rd->uid);
        rd_check_dc_replay_err(session);
        cm_spin_unlock(&session->kernel->db.replay_logic_lock);
        return;
    }

    // check space org_scn to verify if it is dropping the exactly same user
    if (IS_COMPATIBLE_MYSQL_INST) {
        space_t *space = SPACE_GET(session, user->desc.data_space_id);
        if (rd->data_space_org_scn != space->ctrl->org_scn) {
            GS_LOG_RUN_WAR("[DB] failed to replay drop user %u, user is already dropped or recycled", rd->uid);
            rd_check_dc_replay_err(session);
            cm_spin_unlock(&session->kernel->db.replay_logic_lock);
            return;
        }
    }

    if (DAAC_PARTIAL_RECOVER_SESSION(session) || DAAC_REPLAY_NODE(session)) {
        session->drop_uid = GS_INVALID_ID32;
    }

    dc_drop_user(session, rd->uid);
    cm_spin_unlock(&session->kernel->db.replay_logic_lock);
    GS_LOG_RUN_INF("[DB] Success to replay drop user , user id %u", rd->uid);
}

void print_drop_user(log_entry_t *log)
{
    rd_user_t *rd = (rd_user_t *)log->data;
    printf("drop user uid:%u\n", rd->uid);
}

void rd_create_role(knl_session_t *session, log_entry_t *log)
{
    rd_role_t *rd = (rd_role_t *)log->data;
    dc_context_t *ctx;

    ctx = &session->kernel->dc_ctx;

    cm_spin_lock(&ctx->lock, NULL);
    if (ctx->roles[rd->rid] != NULL) {
        cm_spin_unlock(&ctx->lock);
        return;
    }
    cm_spin_unlock(&ctx->lock);

    if (dc_try_create_role(session, rd->rid, rd->name) != GS_SUCCESS) {
        GS_LOG_DEBUG_ERR("[DB] failed to replay create role");
        rd_check_dc_replay_err(session);
    }
}

void print_create_role(log_entry_t *log)
{
    rd_role_t *rd = (rd_role_t *)log->data;
    printf("create role rid:%u,name:%s\n", rd->rid, rd->name);
}

void rd_drop_role(knl_session_t *session, log_entry_t *log)
{
    rd_role_t *rd = (rd_role_t *)log->data;
    dc_context_t *ctx;

    ctx = &session->kernel->dc_ctx;
    cm_spin_lock(&ctx->lock, NULL);
    if (ctx->roles[rd->rid] == NULL) {
        cm_spin_unlock(&ctx->lock);
        return;
    }
    cm_spin_unlock(&ctx->lock);

    if (dc_drop_role(session, rd->rid) != GS_SUCCESS) {
        GS_LOG_DEBUG_ERR("[DB] failed to replay drop role");
        rd_check_dc_replay_err(session);
    }
}

void print_drop_role(log_entry_t *log)
{
    rd_role_t *rd = (rd_role_t *)log->data;
    printf("drop role rid:%u\n", rd->rid);
}

void rd_create_tenant(knl_session_t *session, log_entry_t *log)
{
    rd_tenant_t *rd = (rd_tenant_t *)log->data;
    dc_tenant_t* tenant = NULL;

    CM_MAGIC_CHECK(rd, rd_tenant_t);

    if (dc_open_tenant_by_id(session, rd->tid, &tenant) == GS_SUCCESS) {
        dc_close_tenant(session, tenant->desc.id);
        GS_LOG_RUN_ERR("[DB] failed to replay create tenant %s,tenant id %u already occupied by %s",
            rd->name, rd->tid, tenant->desc.name);
        return;
    }

    if (dc_try_create_tenant(session, rd->tid, rd->name) != GS_SUCCESS) {
        GS_LOG_DEBUG_ERR("[DB] failed to replay create tenant %s", rd->name);
    }
}

void print_create_tenant(log_entry_t *log)
{
    rd_tenant_t *rd = (rd_tenant_t *)log->data;

    CM_MAGIC_CHECK(rd, rd_tenant_t);

    printf("create tenant tid:%u,name:%s\n", rd->tid, rd->name);
}

void rd_alter_tenant(knl_session_t *session, log_entry_t *log)
{
    bool32 is_found = GS_FALSE;
    rd_tenant_t *rd = (rd_tenant_t *)log->data;
    dc_tenant_t *tenant = NULL;
    text_t tenant_name;

    CM_MAGIC_CHECK(rd, rd_tenant_t);

    cm_str2text(rd->name, &tenant_name);
    if (dc_open_tenant(session, &tenant_name, &tenant) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DB] failed to replay alter tenant, tenant %s doesn't exist", rd->name);
        return;
    }

    dc_close_tenant(session, tenant->desc.id);
    if (dc_update_tenant(session, rd->name, &is_found) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DB] failed to replay alter tenant %s", rd->name);
    }
}

void print_alter_tenant(log_entry_t *log)
{
    rd_tenant_t *rd = (rd_tenant_t *)log->data;

    CM_MAGIC_CHECK(rd, rd_tenant_t);

    printf("alter tenant tid:%u,name:%s\n", rd->tid, rd->name);
}

void rd_drop_tenant(knl_session_t *session, log_entry_t *log)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    rd_tenant_t *rd = (rd_tenant_t *)log->data;
    dc_tenant_t *tenant = NULL;

    CM_MAGIC_CHECK(rd, rd_tenant_t);

    if (dc_open_tenant_by_id(session, rd->tid, &tenant) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DB] failed to replay drop tenant,tenant id %u doesn't exist", rd->tid);
        return;
    }

    dc_close_tenant(session, tenant->desc.id);

    cm_latch_x(&ctx->tenant_latch, session->id, NULL);
    dc_drop_tenant(session, rd->tid);
    cm_unlatch(&ctx->tenant_latch, NULL);
}

void print_drop_tenant(log_entry_t *log)
{
    rd_tenant_t *rd = (rd_tenant_t *)log->data;

    CM_MAGIC_CHECK(rd, rd_tenant_t);

    printf("drop tenant tid:%u\n", rd->tid);
}

#ifdef Z_SHARDING
static status_t rd_create_rule_entry(knl_session_t *session, dc_user_t *user, text_t *name, bool32 *is_exists)
{
    knl_cursor_t *cursor = NULL;
    knl_table_desc_t desc;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_DISTRIBUTE_RULE_ID, IX_SYS_DISTRIBUTE_RULE001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, (void *)name->str,
        name->len, IX_COL_SYS_DISTRIBUTE_RULE001_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    (void)dc_convert_distribute_rule_desc(cursor, &desc, NULL, session);

    if (dc_create_distribute_rule_entry(session, &desc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    dc_ready(session, desc.uid, desc.id);
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

void rd_create_distribute_rule(knl_session_t *session, log_entry_t *log)
{
    dc_user_t *user = NULL;
    text_t obj_name;
    bool32 is_found = GS_FALSE;
    rd_distribute_rule_t *rd = (rd_distribute_rule_t *)log->data;

    if (dc_open_user_by_id(session, rd->uid, &user) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DC] failed to replay create rule %s,user id %u doesn't exists", rd->name, rd->uid);
        rd_check_dc_replay_err(session);
        return;
    }

    if (dc_find_by_id(session, user, rd->oid, GS_TRUE)) {
        GS_LOG_RUN_INF("[DC] no need to replay create rule %s,rule id %u already exists", rd->name, rd->oid);
        return;
    }

    cm_str2text(rd->name, &obj_name);
    if (rd_create_rule_entry(session, user, &obj_name, &is_found) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DC] failed to replay create rule %s", rd->name);
        return;
    }

    if (is_found) {
        GS_LOG_RUN_INF("[DC] no need to replay create rule %s,rule already exists", rd->name);
        return;
    }
}

void print_create_distribute_rule(log_entry_t *log)
{
    rd_distribute_rule_t *rd = (rd_distribute_rule_t *)log->data;
    printf("create rule uid:%u,oid:%u,rule_name:%s\n", rd->uid, rd->oid, rd->name);
}

void rd_drop_distribute_rule(knl_session_t *session, log_entry_t *log)
{
    rd_distribute_rule_t *rd = (rd_distribute_rule_t *)log->data;
    dc_user_t *user = NULL;
    text_t name;
    dc_entry_t *entry = NULL;
    dc_entity_t *entity = NULL;

    if (dc_open_user_by_id(session, rd->uid, &user) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DC] failed to replay drop rule %s,user id %u doesn't exists\n", rd->name, rd->uid);
        rd_check_dc_replay_err(session);
        return;
    }

    cm_str2text(rd->name, &name);

    entry = DC_GET_ENTRY(user, rd->oid);
    if (entry == NULL) {
        GS_LOG_RUN_INF("[DC] no need to replay drop rule,rule %s doesn't exists\n", rd->name);
        return;
    }

    /* seem like dc_open */
    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    if (entry->entity != NULL) {
        cm_spin_lock(&entry->entity->ref_lock, NULL);
        entry->entity->ref_count++;
        entity = entry->entity;
        cm_spin_unlock(&entry->entity->ref_lock);
    }
    cm_spin_unlock(&entry->lock);

    rd_dc_drop(session, user, entry);
    if (entity != NULL) {
        dc_close_entity(session->kernel, entity, GS_TRUE);
    }
}

void print_drop_distribute_rule(log_entry_t *log)
{
    rd_distribute_rule_t *rd = (rd_distribute_rule_t *)log->data;
    printf("drop rule:uid:%u,obj:%s\n", rd->uid, rd->name);
}
#endif

void rd_create_mk_begin(knl_session_t *session, log_entry_t *log)
{
    uint32 max_mkid = 0;
    int32 handle = INVALID_FILE_HANDLE;
    char keyfile_name[GS_FILE_NAME_BUFFER_SIZE];
    rd_create_mk_begin_t *rd = (rd_create_mk_begin_t *)log->data;

    errno_t ret = snprintf_s(keyfile_name, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s.update.import",
                             session->kernel->attr.kmc_key_files[0].name);
    knl_securec_check_ss(ret);

    if (cm_file_exist(keyfile_name)) {
        if (cm_remove_file(keyfile_name) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("failed to remove key file %s", keyfile_name);
            return;
        }
    }

    if (cm_kmc_get_max_mkid(GS_KMC_KERNEL_DOMAIN, &max_mkid) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("failed to get max mkid.");
        return;
    }

    if (rd->max_mkid < max_mkid) {
        GS_LOG_RUN_INF("begin skip redo create masterkey.rd max mkid %u, local max mkid %u", rd->max_mkid, max_mkid);
        session->skip_update_mk = GS_TRUE;
        return;
    }

    session->skip_update_mk = GS_FALSE;
    if (cm_open_file(keyfile_name, O_RDWR | O_CREAT | O_SYNC, &handle) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("failed to open key file %s", keyfile_name);
        return;
    }
    if (cm_chmod_file(S_IRUSR | S_IWUSR, handle) != GS_SUCCESS) {
        cm_close_file(handle);
        GS_LOG_RUN_ERR("failed to modify key file %s permissions", keyfile_name);
        return;
    }
    cm_close_file(handle);
    GS_LOG_RUN_INF("begin replay create masterkey,curr max mkid %u", max_mkid);
}

void rd_create_mk_data(knl_session_t *session, log_entry_t *log)
{
    int32 handle = INVALID_FILE_HANDLE;
    char keyfile_name[GS_FILE_NAME_BUFFER_SIZE];
    uint32 plain_len = GS_KMC_MAX_MK_SIZE;
    char plain_buf[GS_KMC_MAX_MK_SIZE];
    rd_mk_data_t *rd = (rd_mk_data_t *)log->data;

    if (session->skip_update_mk) {
        GS_LOG_DEBUG_INF("skip replay create master key data");
        return;
    }

    errno_t ret = snprintf_s(keyfile_name, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s.update.import",
                             session->kernel->attr.kmc_key_files[0].name);
    knl_securec_check_ss(ret);

    if (!cm_file_exist(keyfile_name)) {
        GS_LOG_RUN_ERR("keyfile %s is not exist", keyfile_name);
        return;
    }

    if (cm_kmc_decrypt(GS_KMC_KERNEL_DOMAIN, rd->data, rd->len, plain_buf, &plain_len) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("failed to decrypt rd masterkey,need rebuild kmc keyfile");
        return;
    }

    if (cm_open_file(keyfile_name, O_RDWR | O_EXCL | O_SYNC, &handle) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("failed to open key file %s", keyfile_name);
        return;
    }

    int64 file_size = cm_file_size(handle);
    if (file_size < 0 || file_size >= GS_KMC_MAX_KEY_SIZE) {
        cm_close_file(handle);
        GS_LOG_RUN_ERR("invalid file size:%lld %s.", file_size, keyfile_name);
        return;
    }

    if (cm_seek_file(handle, (int64)rd->offset, SEEK_SET) != file_size) {
        cm_close_file(handle);
        GS_LOG_RUN_ERR("seek file failed :%s.", keyfile_name);
        return;
    }

    if (cm_write_file(handle, plain_buf, (int32)plain_len) != GS_SUCCESS) {
        cm_close_file(handle);
        GS_LOG_RUN_ERR("fail to write file %s", keyfile_name);
        return;
    }
    cm_close_file(handle);
}

static status_t rd_replace_keyfile(knl_session_t *session, const char *keyfile)
{
    int32 handle = GS_INVALID_HANDLE;

    if (cm_copy_file(keyfile, session->kernel->attr.kmc_key_files[0].name, GS_TRUE) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("fail copy %s to %s", keyfile, session->kernel->attr.kmc_key_files[0].name);
        return GS_ERROR;
    }

    if (cm_copy_file(keyfile, session->kernel->attr.kmc_key_files[1].name, GS_TRUE) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("fail copy %s to %s", keyfile, session->kernel->attr.kmc_key_files[1].name);
        return GS_ERROR;
    }

    device_type_t type = cm_device_type((const char *)session->kernel->attr.kmc_key_files[0].name);
    if (cm_open_device((const char *)session->kernel->attr.kmc_key_files[0].name, type,
        O_SYNC, &handle) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (cm_chmod_file(S_IRUSR | S_IWUSR, handle) != GS_SUCCESS) {
        cm_close_device(type, &handle);
        GS_LOG_RUN_ERR("failed to modify key file %s permissions", session->kernel->attr.kmc_key_files[0].name);
        return GS_ERROR;
    }
    cm_close_device(type, &handle);

    if (cm_open_device((const char *)session->kernel->attr.kmc_key_files[1].name, type,
        O_SYNC, &handle) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (cm_chmod_file(S_IRUSR | S_IWUSR, handle) != GS_SUCCESS) {
        cm_close_device(type, &handle);
        GS_LOG_RUN_ERR("failed to modify key file %s permissions", session->kernel->attr.kmc_key_files[1].name);
        return GS_ERROR;
    }
    cm_close_device(type, &handle);

    GS_LOG_RUN_INF("finish replace %s to keyfile %s and %s", keyfile,
        session->kernel->attr.kmc_key_files[0].name,
        session->kernel->attr.kmc_key_files[1].name);

    if (cm_kmc_reset() != GS_SUCCESS) {
        GS_LOG_RUN_ERR("fail to reset kmc keyfile");
        return GS_ERROR;
    }

    if (g_knl_callback.sysdba_privilege() != GS_SUCCESS) {
        GS_LOG_RUN_ERR("fail to call sysdba privilege");
        return GS_ERROR;
    }

    GS_LOG_RUN_INF("finish reset keyfile");
    return GS_SUCCESS;
}

void rd_create_mk_end(knl_session_t *session, log_entry_t *log)
{
    rd_create_mk_end_t *rd = (rd_create_mk_end_t *)log->data;
    uint32 max_mkid = 0;
    uint32 org_key_len = GS_KMC_MAX_MK_SIZE;
    char org_key[GS_KMC_MAX_MK_SIZE];
    char keyfile_name[GS_FILE_NAME_BUFFER_SIZE];

    if (session->skip_update_mk) {
        GS_LOG_RUN_INF("finish skip redo create masterkey.");
        session->skip_update_mk = GS_FALSE;
        return;
    }

    errno_t ret = snprintf_s(keyfile_name, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s.update.import",
                             session->kernel->attr.kmc_key_files[0].name);
    knl_securec_check_ss(ret);

    if (!cm_file_exist(keyfile_name)) {
        GS_LOG_RUN_ERR("keyfile %s is not exist", keyfile_name);
        return;
    }

    if (cm_kmc_get_max_mkid(GS_KMC_KERNEL_DOMAIN, &max_mkid) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("get max key id failed");
        return;
    }

    knl_panic_log(rd->mk_id > max_mkid, "current keyfile alread has masterkey %u.max mkid %u", rd->mk_id, max_mkid);

    if (rd_replace_keyfile(session, keyfile_name) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("use %s to replace current keyfile failed.", keyfile_name);
        return;
    }

    if (cm_get_masterkey_byhash(rd->hash, rd->hash_len, org_key, &org_key_len) != GS_SUCCESS) {
        knl_panic_log(GS_FALSE, "replay create masterkey %u failed", rd->mk_id);
        return;
    }

    ret = memset_sp(org_key, org_key_len, 0, org_key_len);
    knl_securec_check(ret);

    if (cm_kmc_get_max_mkid(GS_KMC_KERNEL_DOMAIN, &max_mkid) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("get kernel domain max masterkey id failed");
        return;
    }

    (void)cm_kmc_active_masterkey(GS_KMC_KERNEL_DOMAIN, max_mkid);

    if (cm_file_exist(keyfile_name)) {
        if (cm_remove_file(keyfile_name) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("failed to remove key file %s", keyfile_name);
            return;
        }
    }
    GS_LOG_RUN_INF("finish replay create masterkey %u,curr max mkid %u", rd->mk_id, max_mkid);
}

void rd_alter_server_mk(knl_session_t *session, log_entry_t *log)
{
    rd_alter_server_mk_t *rd = (rd_alter_server_mk_t *)log->data;
    if (g_knl_callback.update_server_masterkey(session) != GS_SUCCESS) {
        GS_LOG_RUN_INF("rd type %u, refresh mk failed", rd->op_type);
        return;
    }
    GS_LOG_RUN_INF("finish refresh mk");
}

void print_alter_server_mk(log_entry_t *log)
{
    rd_alter_server_mk_t *rd = (rd_alter_server_mk_t *)log->data;
    printf("rd type %u, finish refresh mk", rd->op_type);
}

void print_create_mk_begin(log_entry_t *log)
{
    rd_create_mk_begin_t *rd = (rd_create_mk_begin_t *)log->data;
    printf("create mk begin: max_mkid %u\n", rd->max_mkid);
}
void print_create_mk_data(log_entry_t *log)
{
    rd_mk_data_t *rd = (rd_mk_data_t *)log->data;
    printf("create mk data: len %u, offset %llu\n", rd->len, rd->offset);
}
void print_create_mk_end(log_entry_t *log)
{
    rd_create_mk_end_t *rd = (rd_create_mk_end_t *)log->data;
    printf("create mk end: key_id %u, hash_len %u\n", rd->mk_id, rd->hash_len);
}

void rd_heap_create_entry(knl_session_t *session, log_entry_t *log)
{
    rd_create_heap_entry_t *rd = (rd_create_heap_entry_t *)log->data;

    if (!DAAC_REPLAY_NODE(session)) {
        rd_alter_table(session, log);
        return;
    }

    knl_dictionary_t dc;
    dc_entity_t *entity = NULL;
    dc_entry_t *dc_entry = NULL;
    heap_t *heap = NULL;

    if (knl_try_open_dc_by_id(session, rd->tab_op.uid, rd->tab_op.oid, &dc) != GS_SUCCESS) {
        cm_reset_error();
        GS_LOG_RUN_ERR("[DDL] process heap create entry, failed to open dc user id %u, table id %u", rd->tab_op.uid,
                       rd->tab_op.oid);
        knl_panic(0);
        return;
    }

    entity = DC_ENTITY(&dc);
    if (entity == NULL) {
        cm_reset_error();
        GS_LOG_DEBUG_WAR("[DDL] process heap create entry, dc not loaded, user id %u, table id %u", rd->tab_op.uid,
                         rd->tab_op.oid);
        return;
    }

    heap = dc_get_heap(session, rd->tab_op.uid, rd->tab_op.oid, rd->part_loc, &dc);
    dc_entry = entity->entry;

    cm_spin_lock(&dc_entry->lock, &session->stat->spin_stat.stat_dc_entry);
    if (heap->segment != NULL) {
        knl_panic(IS_SAME_PAGID(heap->entry, rd->entry));
        cm_spin_unlock(&dc_entry->lock);
        GS_LOG_RUN_WAR("[DDL] retry to create entry, entry page %u, redo page %u, table id %u", heap->entry.page,
                       rd->entry.page, rd->tab_op.oid);
        return;
    }
    knl_panic(IS_INVALID_PAGID(heap->entry));

    heap->entry = rd->entry;
    buf_enter_page(session, heap->entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
    heap->segment = HEAP_SEG_HEAD(session);
    if (rd->part_loc.part_no == GS_INVALID_ID32) {
        table_t *table = heap->table;
        table->desc.entry = rd->entry;
        table->desc.seg_scn = heap->segment->seg_scn;
    } else {
        table_part_t *table_part = TABLE_GET_PART(heap->table, rd->part_loc.part_no);
        if (!IS_PARENT_TABPART(&table_part->desc)) {
            table_part->desc.entry = rd->entry;
            table_part->desc.seg_scn = heap->segment->seg_scn;
        } else {
            table_part_t *table_subpart = PART_GET_SUBENTITY(heap->table->part_table,
                                                             table_part->subparts[rd->part_loc.subpart_no]);
            table_subpart->desc.entry = rd->entry;
            table_subpart->desc.seg_scn = heap->segment->seg_scn;
        }
    }
    buf_leave_page(session, GS_FALSE);
    cm_spin_unlock(&dc_entry->lock);

    dc_close(&dc);
}

void print_heap_create_entry(log_entry_t *log)
{
    rd_create_heap_entry_t *rd = (rd_create_heap_entry_t *)log->data;
    printf("create heap entry uid:%u,oid:%u, partno:%u\n", rd->tab_op.uid, rd->tab_op.oid, rd->part_loc.part_no);
}

static void rd_btree_set_index(knl_session_t *session, rd_create_btree_entry_t *rd, btree_t *btree)
{
    index_t *index = btree->index;
    space_t *space = NULL;
    space = SPACE_GET(session, index->desc.space_id);
    index->desc.entry = rd->entry;
    index->desc.seg_scn = btree->segment->seg_scn;
    btree->cipher_reserve_size = space->ctrl->cipher_reserve_size;
}

static void rd_btree_set_index_part(knl_session_t *session, rd_create_btree_entry_t *rd, btree_t *btree)
{
    space_t *space = NULL;
    index_part_t *index_part = INDEX_GET_PART(btree->index, rd->part_loc.part_no);
    if (IS_PARENT_IDXPART(&index_part->desc)) {
        index_part = PART_GET_SUBENTITY(btree->index->part_index, index_part->subparts[rd->part_loc.subpart_no]);
    }
    space = SPACE_GET(session, index_part->desc.space_id);
    index_part->desc.entry = rd->entry;
    index_part->desc.seg_scn = btree->segment->seg_scn;
    btree->cipher_reserve_size = space->ctrl->cipher_reserve_size;
}

void rd_btree_create_entry(knl_session_t *session, log_entry_t *log)
{
    rd_create_btree_entry_t *rd = (rd_create_btree_entry_t *)log->data;

    if (!DAAC_REPLAY_NODE(session)) {
        rd_alter_table(session, log);
        return;
    }

    knl_dictionary_t dc;
    dc_entity_t *entity = NULL;
    dc_entry_t *dc_entry = NULL;
    btree_t *btree = NULL;

    if (knl_try_open_dc_by_id(session, rd->tab_op.uid, rd->tab_op.oid, &dc) != GS_SUCCESS) {
        cm_reset_error();
        knl_panic_log(0, "[DDL] process btree create entry, failed to open dc user id %u, table id %u", rd->tab_op.uid,
                      rd->tab_op.oid);
        return;
    }

    entity = DC_ENTITY(&dc);
    if (entity == NULL) {
        cm_reset_error();
        GS_LOG_DEBUG_WAR("[DDL] process btree create entry, dc not loaded, dc user id %u, table id %u", rd->tab_op.uid,
                         rd->tab_op.oid);
        return;
    }

    btree = dc_get_btree_by_id(session, entity, rd->index_id, rd->part_loc, rd->is_shadow);
    dc_entry = entity->entry;
    cm_spin_lock(&dc_entry->lock, &session->stat->spin_stat.stat_dc_entry);
    if (btree->segment != NULL) {
        knl_panic(IS_SAME_PAGID(btree->entry, rd->entry));
        cm_spin_unlock(&dc_entry->lock);
        GS_LOG_RUN_WAR("[DDL] retry to create entry, entry page %u, redo page %u, table id %u", btree->entry.page,
                       rd->entry.page, rd->tab_op.oid);
        return;
    }
    knl_panic(IS_INVALID_PAGID(btree->entry));

    btree->entry = rd->entry;
    buf_enter_page(session, btree->entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
    btree->segment = BTREE_GET_SEGMENT(session);
    if (rd->part_loc.part_no == GS_INVALID_ID32) {
        rd_btree_set_index(session, rd, btree);
    } else {
        rd_btree_set_index_part(session, rd, btree);
    }

    buf_leave_page(session, GS_FALSE);
    cm_spin_unlock(&dc_entry->lock);

    dc_close(&dc);
}

void print_btree_create_entry(log_entry_t *log)
{
    rd_create_btree_entry_t *rd = (rd_create_btree_entry_t *)log->data;
    printf("create btree entry uid:%u,oid:%u, partno:%u, subpartno: %u\n", rd->tab_op.uid, rd->tab_op.oid,
           rd->part_loc.part_no, rd->part_loc.subpart_no);
}

void rd_lob_create_entry(knl_session_t *session, log_entry_t *log)
{
    rd_create_lob_entry_t *rd = (rd_create_lob_entry_t *)log->data;

    if (!DAAC_REPLAY_NODE(session)) {
        rd_alter_table(session, log);
        return;
    }

    knl_dictionary_t dc;
    dc_entity_t *entity = NULL;
    dc_entry_t *dc_entry = NULL;
    knl_column_t *column = NULL;
    lob_t *lob = NULL;
    lob_entity_t *lob_entity = NULL;

    if (knl_try_open_dc_by_id(session, rd->tab_op.uid, rd->tab_op.oid, &dc) != GS_SUCCESS) {
        cm_reset_error();
        GS_LOG_RUN_ERR("[DDL] process lob create entry, failed to open dc user id %u, table id %u", rd->tab_op.uid,
                       rd->tab_op.oid);
        knl_panic(0);
        return;
    }

    entity = DC_ENTITY(&dc);
    if (entity == NULL) {
        cm_reset_error();
        GS_LOG_RUN_WAR("[DDL] process lob create entry, dc not loaded, dc user id %u, table id %u", rd->tab_op.uid,
                       rd->tab_op.oid);
        return;
    }

    column = dc_get_column(entity, rd->column_id);
    lob = (lob_t *)column->lob;

    dc_entry = entity->entry;

    cm_spin_lock(&dc_entry->lock, &session->stat->spin_stat.stat_dc_entry);
    buf_enter_page(session, rd->entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
    if (rd->part_loc.part_no == GS_INVALID_ID32) {
        lob_entity = &lob->lob_entity;
        space_t *space = SPACE_GET(session, lob->desc.space_id);
        if (lob_entity->segment != NULL) {
            knl_panic(IS_SAME_PAGID(lob_entity->entry, rd->entry));
            cm_spin_unlock(&dc_entry->lock);
            GS_LOG_RUN_WAR("[DDL] retry to create entry, entry page %u, redo page %u, table id %u",
                lob_entity->entry.page,
                rd->entry.page,
                rd->tab_op.oid);
            return;
        }
        knl_panic(IS_INVALID_PAGID(lob_entity->entry));
        knl_panic(lob_entity->segment == NULL);
        lob_entity->entry = rd->entry;
        lob_entity->segment = LOB_SEG_HEAD(session);
        lob_entity->cipher_reserve_size = space->ctrl->cipher_reserve_size;
        lob->desc.entry = rd->entry;
        lob->desc.seg_scn = lob_entity->segment->seg_scn;
    } else {
        lob_part_t *lob_part = LOB_GET_PART(lob, rd->part_loc.part_no);
        if (IS_PARENT_LOBPART(&lob_part->desc)) {
            knl_panic(rd->part_loc.subpart_no != GS_INVALID_ID32);
            lob_part = PART_GET_SUBENTITY(lob->part_lob, lob_part->subparts[rd->part_loc.subpart_no]);
        }
        lob_entity = &lob_part->lob_entity;
        space_t *space = SPACE_GET(session, lob_part->desc.space_id);
        if (lob_entity->segment != NULL) {
            knl_panic(IS_SAME_PAGID(lob_entity->entry, rd->entry));
            cm_spin_unlock(&dc_entry->lock);
            GS_LOG_RUN_WAR("[DDL] retry to create entry, entry page %u, redo page %u, table id %u",
                lob_entity->entry.page,
                rd->entry.page,
                rd->tab_op.oid);
            return;
        }
        knl_panic(IS_INVALID_PAGID(lob_entity->entry));
        knl_panic(lob_entity->segment == NULL);
        lob_entity->entry = rd->entry;
        lob_entity->segment = LOB_SEG_HEAD(session);
        lob_entity->cipher_reserve_size = space->ctrl->cipher_reserve_size;
        lob_part->desc.entry = rd->entry;
        lob_part->desc.seg_scn = lob_entity->segment->seg_scn;
    }
    buf_leave_page(session, GS_FALSE);
    cm_spin_unlock(&dc_entry->lock);

    dc_close(&dc);
}

void print_lob_create_entry(log_entry_t *log)
{
    rd_create_lob_entry_t *rd = (rd_create_lob_entry_t *)log->data;
    printf("create lob entry uid:%u,oid:%u, partno:%u, subpartno:%u \n", rd->tab_op.uid, rd->tab_op.oid,
           rd->part_loc.part_no, rd->part_loc.subpart_no);
}

void rd_create_interval(knl_session_t *session, log_entry_t *log)
{
    rd_create_interval_t *rd = (rd_create_interval_t *)log->data;

    if (!DAAC_REPLAY_NODE(session)) {
        rd_alter_table(session, log);
        return;
    }

    knl_dictionary_t dc;
    dc_entity_t *entity = NULL;
    table_t *table = NULL;
    part_table_t *part_table = NULL;

    if (knl_try_open_dc_by_id(session, rd->tab_op.uid, rd->tab_op.oid, &dc) != GS_SUCCESS) {
        cm_reset_error();
        knl_panic_log(0, "[DDL] create interval, failed to open dc user id %u, table id %u, part_no %u, part cnt %u",
                      rd->tab_op.uid, rd->tab_op.oid, rd->part_no, rd->part_cnt);
        return;
    }

    entity = DC_ENTITY(&dc);
    if (entity == NULL) {
        cm_reset_error();
        GS_LOG_RUN_WAR("[DDL] create interval, dc not loaded, user id %u, table id %u, part_no %u, part cnt %u",
                       rd->tab_op.uid, rd->tab_op.oid, rd->part_no, rd->part_cnt);
        return;
    }

    table = DC_TABLE(&dc);
    part_table = table->part_table;

    knl_panic(!is_interval_part_created(session, &dc, rd->part_no));
    if (db_reserve_interval_dc_memory(session, &dc, rd->part_no) != GS_SUCCESS) {
        knl_panic_log(
            0, "[DDL] create interval, failed to reserve memory, user id %u, table id %u, part_no %u, part cnt %u",
            rd->tab_op.uid, rd->tab_op.oid, rd->part_no, rd->part_cnt);
        return;
    }

    if (dc_load_interval_part(session, &dc, rd->part_no) != GS_SUCCESS) {
        // set the dc as corrupted since the part count is not correct if fail here
        knl_panic_log(0, "[DDL] create interval, dc load failed, user id %u, table id %u, part_no %u, part cnt %u",
                      rd->tab_op.uid, rd->tab_op.oid, rd->part_no, rd->part_cnt);
        return;
    }

    db_create_interval_update_desc(table, rd->part_cnt);
    table_part_t *interval_part = PART_GET_ENTITY(part_table, rd->part_no);
    interval_part->is_ready = GS_TRUE;
    dls_init_spinlock2(&interval_part->heap.lock, DR_TYPE_HEAP_PART, interval_part->desc.table_id,
                       interval_part->desc.uid, interval_part->desc.part_id, interval_part->part_no,
                       interval_part->parent_partno);
    dls_init_latch2(&interval_part->heap.latch, DR_TYPE_HEAP_PART_LATCH, interval_part->desc.table_id,
                    interval_part->desc.uid, interval_part->desc.part_id, interval_part->part_no,
                    interval_part->parent_partno);

    dc_close(&dc);
}

void print_create_interval(log_entry_t *log)
{
    rd_create_interval_t *rd = (rd_create_interval_t *)log->data;
    printf("create interval uid:%u,oid:%u\n", rd->tab_op.uid, rd->tab_op.oid);
}
