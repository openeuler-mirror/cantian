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
 * knl_dblink.c
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/knl_dblink.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_db_module.h"
#include "knl_context.h"
#include "knl_interface.h"
#include "dtc_dls.h"
#include "srv_instance.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef Z_SHARDING
static inline void lnk_entry_inc_ref(dc_entry_t *entry)
{
    cm_spin_lock(&entry->ref_lock, NULL);
    entry->ref_count++;
    cm_spin_unlock(&entry->ref_lock);
}

static inline void lnk_entry_dec_ref(dc_entry_t *entry)
{
    cm_spin_lock(&entry->ref_lock, NULL);
    entry->ref_count--;
    knl_panic(entry->ref_count >= 0);
    cm_spin_unlock(&entry->ref_lock);
}

static status_t dc_get_dblink_def_id(knl_session_t *session, knl_dblink_def_t *def)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    dc_dblink_t *dblink = NULL;

    def->id = CT_INVALID_ID32;

    for (uint32 i = 0; i < CT_MAX_DBLINKS; i++) {
        dblink = ctx->dblinks[i];
        if (dblink == NULL || dblink->status == DBLINK_STATUS_DROPPED) {
            if (def->id == CT_INVALID_ID32) {
                def->id = i;
            }
            continue;
        }
        
        if (cm_text_str_equal(&def->name.value, dblink->desc.name) && def->owner_id == dblink->desc.owner_id) {
            CT_THROW_ERROR(ERR_DUPLICATE_NAME, "dblink", T2S(&def->name.value));
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t dc_insert_sys_links(knl_session_t *session, knl_dblink_def_t *def)
{
    knl_cursor_t *cursor = knl_push_cursor(session);
    table_t *table = NULL;
    row_assist_t ra;
    status_t ret;

    cursor->scn = DB_CURR_SCN(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_LINK_ID, CT_INVALID_ID32);
    table = (table_t *)cursor->table;

    row_init(&ra, (char *)cursor->row, session->kernel->attr.max_row_size, table->desc.column_count);
    (void)row_put_int32(&ra, def->owner_id);    // OWNER#
    (void)row_put_text(&ra, &def->name.value);  // NAME
    (void)row_put_date(&ra, g_timer()->now);    // CTIME
    (void)row_put_int32(&ra, def->node_id);     // NODE_ID
    (void)row_put_text(&ra, &def->url);         // HOST
    (void)row_put_text(&ra, &def->user);        // USERID
    (void)row_put_null(&ra);                    // PASSWORD
    ret = knl_internal_insert(session, cursor);

    knl_pop_cursor(session);
    return ret;
}

static status_t dc_drop_sys_links(knl_session_t *knl_session, uint32 uid, text_t *name)
{
    knl_cursor_t *cursor = NULL;
    status_t ret;

    CM_SAVE_STACK(knl_session->stack);

    do {
        cursor = knl_push_cursor(knl_session);
        knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_DELETE, SYS_LINK_ID, IX_SYS_LINKS_001_ID);
        knl_init_index_scan(cursor, CT_TRUE);

        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&uid,
                         sizeof(uid), IX_COL_SYS_LINKS_001_OWNER);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, (void *)name->str,
                         name->len, IX_COL_SYS_LINKS_001_NAME);

        ret = knl_fetch(knl_session, cursor);
        CT_BREAK_IF_ERROR(ret);

        if (cursor->eof) {
            CT_THROW_ERROR(ERR_DBLINK_NOT_EXIST, T2S(name));
            ret = CT_ERROR;
            break;
        }
        
        ret = knl_internal_delete(knl_session, cursor);
    } while (0);

    CM_RESTORE_STACK(knl_session->stack);
    return ret;
}

static inline void dc_generate_dblink_desc(knl_dblink_def_t *def, knl_dblink_desc_t *desc)
{
    errno_t err;
    err = memcpy_sp(desc->name, def->name.len, def->name.str, def->name.len);
    knl_securec_check(err);
    desc->name[def->name.len] = '\0';
    err = memcpy_sp(desc->user, def->user.len, def->user.str, def->user.len);
    knl_securec_check(err);
    desc->user[def->user.len] = '\0';

    desc->owner_id = def->owner_id;
    desc->id = def->id;
    desc->node_id = def->node_id;
}

static status_t dc_add_dblink(dc_context_t *ctx, knl_dblink_def_t *def)
{
    dc_dblink_t *dblink = NULL;
    errno_t err;

    if (mctx_alloc(ctx->memory, sizeof(dc_dblink_t), (void **)&dblink) != CT_SUCCESS) {
        return CT_ERROR;
    }

    err = memset_sp(&dblink->latch, sizeof(latch_t), 0, sizeof(latch_t));
    knl_securec_check(err);

    dc_generate_dblink_desc(def, &dblink->desc);
    dblink->status = DBLINK_STATUS_NORMAL;
    ctx->dblinks[def->id] = dblink;
    return CT_SUCCESS;
}

static void dc_reuse_dblink(knl_session_t *session, knl_dblink_def_t *def)
{
    dc_dblink_t *dblink;
    dc_context_t  *ctx = &session->kernel->dc_ctx;

    dblink = ctx->dblinks[def->id];
    cm_latch_x(&dblink->latch, session->id, NULL);
    dc_generate_dblink_desc(def, &dblink->desc);
    dblink->status = DBLINK_STATUS_NORMAL;
    cm_unlatch(&dblink->latch, NULL);
}

static void dc_drop_dblink(knl_session_t *session, uint32 uid, text_t *name)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;

    for (uint32 i = 0; i < CT_MAX_DBLINKS; i++) {
        if (ctx->dblinks[i] == NULL) {
            continue;
        }

        cm_latch_x(&ctx->dblinks[i]->latch, session->id, NULL);

        if (!cm_text_str_equal(name, ctx->dblinks[i]->desc.name) || uid != ctx->dblinks[i]->desc.owner_id) {
            cm_unlatch(&ctx->dblinks[i]->latch, NULL);
            continue;
        }

        ctx->dblinks[i]->status = DBLINK_STATUS_DROPPED;
        cm_unlatch(&ctx->dblinks[i]->latch, NULL);
        return;
    }
}

status_t knl_create_dblink(knl_handle_t session, knl_dblink_def_t *def)
{
    knl_session_t *knl_session = (knl_session_t *)session;
    dc_context_t *ctx = &knl_session->kernel->dc_ctx;

    if (DB_NOT_READY(knl_session)) {
        CT_THROW_ERROR(ERR_NO_DB_ACTIVE, "Database has not been created or is not open");
        return CT_ERROR;
    }

    dls_spin_lock(session, &ctx->paral_lock, NULL);

    if (dc_get_dblink_def_id(session, def) != CT_SUCCESS) {
        dls_spin_unlock(session, &ctx->paral_lock);
        return CT_ERROR;
    }

    /* add the new dblink to dc */
    if (ctx->dblinks[def->id] == NULL) {
        if (dc_add_dblink(ctx, def) != CT_SUCCESS) {
            dls_spin_unlock(session, &ctx->paral_lock);
            return CT_ERROR;
        }
    } else {
        dc_reuse_dblink(knl_session, def);
    }

    if (dc_insert_sys_links(knl_session, def) != CT_SUCCESS) {
        ctx->dblinks[def->id]->status = DBLINK_STATUS_DROPPED;
        dls_spin_unlock(session, &ctx->paral_lock);
        return CT_ERROR;
    }

    dls_spin_unlock(session, &ctx->paral_lock);
    return CT_SUCCESS;
}

status_t knl_drop_dblink(knl_handle_t session, knl_dblink_def_t *def)
{
    knl_session_t *knl_session = (knl_session_t *)session;
    dc_context_t *ctx = &knl_session->kernel->dc_ctx;
    status_t ret;

    if (DB_NOT_READY(knl_session)) {
        CT_THROW_ERROR(ERR_NO_DB_ACTIVE, "Database has not been created or is not open");
        return CT_ERROR;
    }

    dls_spin_lock(session, &ctx->paral_lock, NULL);

    do {
        ret = dc_drop_sys_links(knl_session, def->owner_id, &def->name.value);
        CT_BREAK_IF_ERROR(ret);

        dc_drop_dblink(knl_session, def->owner_id, &def->name.value);
    } while (0);

    dls_spin_unlock(session, &ctx->paral_lock);
    return ret;
}

status_t knl_drop_dblink_by_id(knl_handle_t session, uint32 id)
{
    knl_session_t *knl_session = (knl_session_t *)session;
    dc_context_t *ctx = &knl_session->kernel->dc_ctx;
    dc_dblink_t *dblink = ctx->dblinks[id];
    text_t name;

    dls_spin_lock(session, &ctx->paral_lock, NULL);
    name.str = dblink->desc.name;
    name.len = strlen(dblink->desc.name);
    if (dc_drop_sys_links(knl_session, dblink->desc.owner_id, &name) != CT_SUCCESS) {
        dls_spin_unlock(session, &ctx->paral_lock);
        return CT_ERROR;
    }
    cm_latch_x(&dblink->latch, knl_session->id, NULL);
    dblink->status = DBLINK_STATUS_DROPPED;
    cm_unlatch(&dblink->latch, NULL);
    dls_spin_unlock(session, &ctx->paral_lock);

    return CT_SUCCESS;
}

void knl_free_lnk_tab_dc(knl_handle_t session)
{
    knl_session_t *knl_session = (knl_session_t *)session;
    mctx_destroy(knl_session->lnk_tab_dc->ctx);
    knl_session->lnk_tab_dc = NULL;
    knl_session->lnk_tab_count = 0;
}

status_t knl_load_dblinks(knl_handle_t session)
{
    knl_session_t *knl_session = (knl_session_t *)session;
    dc_context_t *ctx = &knl_session->kernel->dc_ctx;
    knl_cursor_t *cursor = NULL;
    dc_dblink_t *dblink = NULL;
    text_t name;
    uint32 dblink_count = 0;
    status_t ret;
    errno_t err;

    cursor = knl_push_cursor(knl_session);
    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_SELECT, SYS_LINK_ID, CT_INVALID_ID32);

    for (;;) {
        ret = knl_fetch(session, cursor);
        CT_BREAK_IF_ERROR(ret);

        if (cursor->eof) {
            break;
        }

        ret = mctx_alloc(ctx->memory, sizeof(dc_dblink_t), (void **)&dblink);
        CT_BREAK_IF_ERROR(ret);
        err = memset_sp(&dblink->latch, sizeof(latch_t), 0, sizeof(latch_t));
        knl_securec_check(err);

        dblink->desc.id = dblink_count;
        dblink_count++;
        dblink->desc.owner_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_LINKS_COL_OWNER);
        dblink->desc.node_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_LINKS_COL_NODE_ID);

        name.str = CURSOR_COLUMN_DATA(cursor, SYS_LINKS_COL_NAME);
        name.len = CURSOR_COLUMN_SIZE(cursor, SYS_LINKS_COL_NAME);
        err = memcpy_sp(dblink->desc.name, name.len, name.str, name.len);
        knl_securec_check(err);
        dblink->desc.name[name.len] = '\0';

        name.str = CURSOR_COLUMN_DATA(cursor, SYS_LINKS_COL_USERID);
        name.len = CURSOR_COLUMN_SIZE(cursor, SYS_LINKS_COL_USERID);
        err = memcpy_sp(dblink->desc.user, name.len, name.str, name.len);
        knl_securec_check(err);
        dblink->desc.user[name.len] = '\0';

        dblink->status = DBLINK_STATUS_NORMAL;
        ctx->dblinks[dblink->desc.id] = dblink;
    }
    
    knl_pop_cursor(knl_session);
    return ret;
}

status_t dc_open_dblink(knl_session_t *session, text_t *name, dc_dblink_t **dblink)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;

    for (uint32 i = 0; i < CT_MAX_DBLINKS; i++) {
        if (!ctx->dblinks[i]) {
            continue;
        }

        cm_latch_s(&ctx->dblinks[i]->latch, session->id, CT_FALSE, NULL);

        if (ctx->dblinks[i]->status != DBLINK_STATUS_NORMAL ||
            !cm_text_str_equal(name, ctx->dblinks[i]->desc.name) ||
            session->uid != ctx->dblinks[i]->desc.owner_id) {
            cm_unlatch(&ctx->dblinks[i]->latch, NULL);
            continue;
        }

        *dblink = ctx->dblinks[i];
        return CT_SUCCESS;
    }

    CT_THROW_ERROR(ERR_DBLINK_NOT_EXIST, T2S(name));
    return CT_ERROR;
}

void dc_close_dblink(knl_session_t *session, dc_dblink_t *dblink)
{
    cm_unlatch(&dblink->latch, NULL);
}

void dc_init_lnk_tab_entry(knl_session_t *session, dc_dblink_t *dblink,
    text_t *tab_user, text_t *tab_name, dc_entry_t *entry)
{
    errno_t err;

    err = memcpy_sp(entry->name, CT_NAME_BUFFER_SIZE, tab_name->str, tab_name->len);
    knl_securec_check(err);
    entry->name[tab_name->len] = '\0';
    err = memcpy_sp(entry->user_name, CT_NAME_BUFFER_SIZE, tab_user->str, tab_user->len);
    knl_securec_check(err);
    entry->user_name[tab_user->len] = '\0';
    entry->dblink = dblink;
    entry->type = DICT_TYPE_TABLE;
    entry->uid = dblink->desc.id;
    entry->ready = CT_FALSE;
}

static status_t dc_create_lnk_tab_cols(const knl_lnk_dc_callback_t *callback_data,
    knl_session_t *session, dc_entity_t *entity)
{
    uint32 i, hash;
    knl_column_t *column = NULL;

    if (dc_prepare_load_columns(session, entity) != CT_SUCCESS) {
        return CT_ERROR;
    }

    for (i = 0; i < callback_data->col_cnt; i++) {
        column = callback_data->cols[i];
        entity->column_groups[i / DC_COLUMN_GROUP_SIZE].columns[i % DC_COLUMN_GROUP_SIZE] = column;
    }

    for (i = 0; i < callback_data->col_cnt; i++) {
        column = dc_get_column(entity, i);
        hash = cm_hash_column_name(column->name, strlen(column->name), entity->column_count, IS_COMPATIBLE_MYSQL_INST);
        column->next = DC_GET_COLUMN_INDEX(entity, hash);
        entity->column_groups[hash / DC_COLUMN_GROUP_SIZE].column_index[hash % DC_COLUMN_GROUP_SIZE] = (uint16)i;
    }

    return CT_SUCCESS;
}

static status_t dc_create_lnk_tab_routing(const knl_lnk_dc_callback_t *callback_data,
    knl_session_t *session, dc_entity_t *entity)
{
    dc_context_t *dc_ctx = &session->kernel->dc_ctx;
    routing_info_t *routing_info = knl_get_table_routing_info(entity);

    routing_info->type = distribute_replication;
    routing_info->expr_count = 0;
    routing_info->column_count = 0;
    routing_info->group_count = 1;

    if (dc_alloc_mem(dc_ctx, entity->memory, sizeof(routing_group_t) * routing_info->group_count,
        (void **)&routing_info->groups) != CT_SUCCESS) {
        return CT_ERROR;
    }

    routing_info->groups[0].value_count = 0;
    routing_info->groups[0].group_id = callback_data->group_id;

    return CT_SUCCESS;
}

static status_t dc_init_lnk_tab_def(const knl_lnk_dc_callback_t *callback_data,
    knl_session_t *session, dc_entity_t *entity)
{
    knl_table_desc_t *desc = &entity->table.desc;
    errno_t err;

    err = memcpy_sp(desc->name, CT_NAME_BUFFER_SIZE, entity->entry->name, CT_NAME_BUFFER_SIZE);
    knl_securec_check(err);

    desc->column_count = callback_data->col_cnt;
    desc->org_scn = entity->entry->org_scn;
    desc->chg_scn = entity->entry->chg_scn;
    desc->seg_scn = entity->entry->org_scn;

    return CT_SUCCESS;
}

static status_t dc_create_lnk_tab_entity(knl_session_t *session, memory_context_t *ctx, dc_dblink_t *dblink,
    dc_entry_t *entry)
{
    dc_context_t         *dc_ctx = &session->kernel->dc_ctx;
    knl_lnk_dc_callback_t callback_data;
    errno_t               errcode;

    callback_data.ctx = ctx;
    callback_data.node_id = dblink->desc.node_id;
    callback_data.tab_user = entry->user_name;
    callback_data.tab_name = entry->name;
    if (g_knl_callback.load_lnk_tab_dc(session, &callback_data) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_alloc_mem(dc_ctx, ctx, sizeof(dc_entity_t), (void **)&entry->entity) != CT_SUCCESS) {
        return CT_ERROR;
    }
    errcode = memset_s(entry->entity, sizeof(dc_entity_t), 0, sizeof(dc_entity_t));
    knl_securec_check(errcode);
    entry->entity->type = entry->type;
    entry->entity->entry = entry;
    entry->entity->memory = ctx;
    entry->entity->valid = CT_TRUE;
    entry->entity->column_count = callback_data.col_cnt;

    if (dc_create_lnk_tab_routing(&callback_data, session, entry->entity) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_create_lnk_tab_cols(&callback_data, session, entry->entity) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_init_lnk_tab_def(&callback_data, session, entry->entity) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t dc_create_lnk_tab_entry(knl_session_t *session, memory_context_t *ctx, dc_dblink_t *dblink,
    text_t *tab_user, text_t *tab_name, dc_entry_t **entry)
{
    dc_entry_t *ptr = NULL;
    errno_t err;
    dc_context_t *dc_ctx = &session->kernel->dc_ctx;

    if (dc_alloc_mem(dc_ctx, ctx, sizeof(dc_entry_t), (void **)&ptr) != CT_SUCCESS) {
        return CT_ERROR;
    }

    err = memset_sp(ptr, sizeof(dc_entry_t), 0, sizeof(dc_entry_t));
    knl_securec_check(err);
    err = memcpy_sp(ptr->name, CT_NAME_BUFFER_SIZE, tab_name->str, tab_name->len);
    knl_securec_check(err);
    ptr->name[tab_name->len] = '\0';

    err = memcpy_sp(ptr->user_name, CT_NAME_BUFFER_SIZE, tab_user->str, tab_user->len);
    knl_securec_check(err);
    ptr->user_name[tab_user->len] = '\0';

    if (dc_alloc_mem(dc_ctx, ctx, sizeof(dc_appendix_t), (void **)&ptr->appendix) != CT_SUCCESS) {
        return CT_ERROR;
    }

    err = memset_sp(ptr->appendix, sizeof(dc_appendix_t), 0, sizeof(dc_appendix_t));
    knl_securec_check(err);
    ptr->dblink = dblink;
    ptr->type = DICT_TYPE_TABLE;
    ptr->uid = dblink->desc.id;
    ptr->id = CT_DBLINK_ENTRY_START_ID + session->lnk_tab_count;
    ptr->used = CT_TRUE;
    ptr->ready = CT_FALSE;

    *entry = ptr;

    return CT_SUCCESS;
}

static status_t dc_create_lnk_tab(knl_session_t *session, dc_dblink_t *dblink,
    text_t *tab_user, text_t *tab_name, knl_dictionary_t *dc)
{
    memory_context_t *ctx = session->lnk_tab_dc->ctx;
    dc_entry_t *entry = NULL;

    if (session->lnk_tab_count >= session->lnk_tab_capacity) {
        CT_THROW_ERROR(ERR_TOO_MANY_OBJECTS, session->lnk_tab_capacity, "dblink tables");
        return CT_ERROR;
    }

    if (dc_create_lnk_tab_entry(session, ctx, dblink, tab_user, tab_name, &entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_create_lnk_tab_entity(session, ctx, dblink, entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    session->lnk_tab_dc->entries[session->lnk_tab_count] = entry;
    session->lnk_tab_count++;

    dc->type = entry->type;
    dc->uid = dblink->desc.id;
    dc->oid = entry->id;
    dc->org_scn = entry->org_scn;
    dc->chg_scn = entry->chg_scn;
    dc->handle = (knl_handle_t)entry->entity;
    dc->kernel = session->kernel;

    return CT_SUCCESS;
}

static status_t dc_init_lnk_tab(knl_handle_t session)
{
    knl_session_t *sess = (knl_session_t *)session;
    dc_context_t *dc_ctx = &sess->kernel->dc_ctx;
    memory_context_t *context = NULL;
    knl_lnk_tab_dc_t *lnk_tab_dc = NULL;
    errno_t ret;

    if (dc_create_memory_context(dc_ctx, &context) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_alloc_mem(dc_ctx, context, sizeof(knl_lnk_tab_dc_t), (void **)&lnk_tab_dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    ret = memset_sp(lnk_tab_dc, sizeof(knl_lnk_tab_dc_t), 0, sizeof(knl_lnk_tab_dc_t));
    knl_securec_check(ret);

    lnk_tab_dc->entries = sess->lnk_tab_entries;
    ret = memset_sp(lnk_tab_dc->entries, sizeof(void *) * sess->lnk_tab_capacity, 0,
        sizeof(void *) * sess->lnk_tab_capacity);
    knl_securec_check(ret);

    lnk_tab_dc->ctx = (void *)context;
    sess->lnk_tab_dc = lnk_tab_dc;

    return CT_SUCCESS;
}

static status_t dc_find_lnk_tab(knl_session_t *session, dc_dblink_t *dblink, text_t *tab_user, text_t *tab_name,
    knl_dictionary_t *dc, bool32 *found)
{
    knl_lnk_tab_dc_t *lnk_tab_dc = session->lnk_tab_dc;
    if (lnk_tab_dc == NULL) {
        if (dc_init_lnk_tab(session) != CT_SUCCESS) {
            return CT_ERROR;
        }

        lnk_tab_dc = session->lnk_tab_dc;
    }

    *found = CT_FALSE;

    for (uint32 i = 0; i < session->lnk_tab_count; i++) {
        dc_entry_t *entry = (dc_entry_t *)lnk_tab_dc->entries[i];

        if ((entry->uid == dblink->desc.id) &&
            cm_text_str_equal(tab_name, entry->name) &&
            cm_text_str_equal(tab_user, entry->user_name)) {
            dc->type = entry->type;
            dc->uid = dblink->desc.id;
            dc->oid = entry->id;
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

bool32 knl_find_lnk_tab_dc(knl_handle_t session, text_t *lnk_name, text_t *tab_name)
{
    dc_dblink_t   *dblink = NULL;
    dc_entry_t    *entry = NULL;
    knl_session_t *knl_session = session;

    // find dblink dc
    if (dc_open_dblink(knl_session, lnk_name, &dblink) != CT_SUCCESS) {
        return CT_FALSE;
    }

    for (uint32 i = 0; i < knl_session->lnk_tab_count; i++) {
        entry = (dc_entry_t *)knl_session->lnk_tab_dc->entries[i];

        if ((entry->uid == dblink->desc.id) && cm_text_str_equal(tab_name, entry->name)) {
            dc_close_dblink(session, dblink);
            return CT_TRUE;
        }
    }
    dc_close_dblink(session, dblink);
    return CT_FALSE;
}

status_t knl_check_dblink_exist(knl_handle_t session, text_t *name)
{
    dc_dblink_t   *dblink = NULL;
    knl_session_t *knl_session = session;
    status_t ret = dc_open_dblink(knl_session, name, &dblink);
    if (ret == CT_SUCCESS) {
        dc_close_dblink(knl_session, dblink);
    }

    return ret;
}

status_t knl_open_lnk_tab_dc(knl_handle_t session, text_t *lnk_name,
    sql_text_t *tab_user, text_t *tab_name, knl_dictionary_t *dc)
{
    dc_dblink_t   *dblink = NULL;
    knl_session_t *knl_session = session;
    dc_entity_t   *entity = NULL;
    bool32         found = CT_FALSE;
    KNL_RESET_DC(dc);

    // find dblink dc
    if (dc_open_dblink(knl_session, lnk_name, &dblink) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (tab_user->implicit) {
        tab_user->str = dblink->desc.user;
        tab_user->len = (uint32)strlen(dblink->desc.user);
    }

    // find dblink table dc
    if (dc_find_lnk_tab(knl_session, dblink, &tab_user->value, tab_name, dc, &found) != CT_SUCCESS) {
        dc_close_dblink(session, dblink);
        return CT_ERROR;
    }

    if (!found) {
        if (dc_create_lnk_tab(session, dblink, &tab_user->value, tab_name, dc) != CT_SUCCESS) {
            dc_close_dblink(session, dblink);
            return CT_ERROR;
        }
    }

    dc_close_dblink(session, dblink);
    entity = (dc_entity_t *)dc->handle;
    entity->ref_count++;
    return CT_SUCCESS;
}
#endif

#ifdef __cplusplus
}
#endif
