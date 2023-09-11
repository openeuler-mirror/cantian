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
 * dc_user.c
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/dc_user.c
 *
 * -------------------------------------------------------------------------
 */
#include "dc_user.h"
#include "cm_log.h"
#include "knl_context.h"
#include "knl_user.h"
#include "dc_priv.h"
#include "dtc_dc.h"
#include "dtc_dls.h"

void dc_insert_into_user_index(dc_context_t *ctx, dc_user_t *user)
{
    dc_bucket_t *user_bucket = NULL;
    dc_bucket_t *tenant_bucket = NULL;
    dc_user_t *first_user = NULL;
    text_t name;
    uint32 hash;

    cm_str2text(user->desc.name, &name);
    hash = dc_hash(&name);
    user_bucket = &ctx->user_buckets[hash];

    cm_spin_lock(&user_bucket->lock, NULL);
    user->user_bucket = user_bucket;
    user->next = user_bucket->first;
    user->prev = GS_INVALID_ID32;

    if (user_bucket->first != GS_INVALID_ID32) {
        first_user = ctx->users[user_bucket->first];
        first_user->prev = user->desc.id;
    }

    user_bucket->first = user->desc.id;
    cm_spin_unlock(&user_bucket->lock);

    CM_ASSERT(user->desc.tenant_id < GS_MAX_TENANTS);
    tenant_bucket = &ctx->tenant_buckets[user->desc.tenant_id];

    cm_spin_lock(&tenant_bucket->lock, NULL);
    user->tenant_bucket = tenant_bucket;
    user->next1 = tenant_bucket->first;
    user->prev1 = GS_INVALID_ID32;

    if (tenant_bucket->first != GS_INVALID_ID32) {
        first_user = ctx->users[tenant_bucket->first];
        first_user->prev1 = user->desc.id;
    }

    tenant_bucket->first = user->desc.id;
    cm_spin_unlock(&tenant_bucket->lock);
}

void dc_free_user_entry(knl_session_t *session, uint32 uid)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    dc_user_t *user = ctx->users[uid];
    dc_entry_t *entry = NULL;
    uint32 eid;

    for (eid = 0; eid < user->entry_hwm; eid++) {
        entry = DC_GET_ENTRY(user, eid);
        if (entry == NULL || entry->used) {
            continue;
        }

        dc_free_entry(session, entry);
    }
}

static status_t dc_init_obj_priv(dc_context_t *ctx, dc_user_t *user)
{
    uint32 i, page_id;
    errno_t err;

    // alloc priv buckets
    if (dc_alloc_memory_page(ctx, &page_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    user->obj_privs.buckets = (dc_bucket_t *)mpool_page_addr(&ctx->pool, page_id);
    for (i = 0; i < DC_HASH_SIZE; i++) {
        user->obj_privs.buckets[i].lock = 0;
        user->obj_privs.buckets[i].first = GS_INVALID_ID32;
    }

    // alloc priv entries
    if (dc_alloc_memory_page(ctx, &page_id) != GS_SUCCESS) {
        return GS_ERROR;
    }
    user->obj_privs.groups = (object_priv_group_t **)mpool_page_addr(&ctx->pool, page_id);
    err = memset_sp(user->obj_privs.groups, GS_SHARED_PAGE_SIZE, 0, GS_SHARED_PAGE_SIZE);
    knl_securec_check(err);
    user->obj_privs.lock = 0;
    cm_list_init(&user->parent);
    cm_list_init(&user->parent_free);
    cm_list_init(&user->grant_obj_privs);

    return GS_SUCCESS;
}

static status_t dc_init_user_privs(dc_context_t *ctx, dc_user_t *user)
{
    uint32 i, page_id;

    // alloc priv buckets
    if (dc_alloc_memory_page(ctx, &page_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    user->user_privs.buckets = (dc_bucket_t *)mpool_page_addr(&ctx->pool, page_id);
    for (i = 0; i < DC_HASH_SIZE; i++) {
        user->user_privs.buckets[i].lock = 0;
        user->user_privs.buckets[i].first = GS_INVALID_ID32;
    }

    for (int j = 0; j < USER_PRIV_GROUP_COUNT; j++) {
        user->user_privs.groups[j] = 0;
    }
    
    user->user_privs.lock = 0;
    user->user_privs.hwm = 0;
    return GS_SUCCESS;
}

/*
* Only memory and privs are essential for user.Table,sequence and comtype
* will be initialize dynamically.
*/
status_t dc_init_user(dc_context_t *ctx, dc_user_t *user)
{
    errno_t err;

    err = memset_sp(user, sizeof(dc_user_t), 0, sizeof(dc_user_t));
    knl_securec_check(err);

    if (dc_create_memory_context(ctx, &user->memory) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dc_init_obj_priv(ctx, user) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dc_init_user_privs(ctx, user) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/*
* Description     : Initialize dc user table context
* Input           : session
* Output          : user : user context
* Return Value    : status_t
* History         : 1.2018/11/26,  add description
*/
status_t dc_init_table_context(dc_context_t *ctx, dc_user_t *user)
{
    uint32 i, page_id;
    errno_t err;

    // alloc group array
    if (dc_alloc_memory_page(ctx, &page_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    user->groups = (dc_group_t **)mpool_page_addr(&ctx->pool, page_id);
    err = memset_sp(user->groups, GS_SHARED_PAGE_SIZE, 0, GS_SHARED_PAGE_SIZE);
    knl_securec_check(err);

    // alloc buckets
    if (dc_alloc_memory_page(ctx, &page_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    user->buckets = (dc_bucket_t *)mpool_page_addr(&ctx->pool, page_id);

    for (i = 0; i < DC_HASH_SIZE; i++) {
        user->buckets[i].lock = 0;
        user->buckets[i].first = GS_INVALID_ID32;
    }

    user->entry_hwm = (user->desc.id == 0) ? GS_EX_SYSID_END : 0;
    user->entry_lwm = user->entry_hwm;

    return GS_SUCCESS;
}

static status_t dc_init_user_context(knl_session_t *session, dc_context_t *ctx, dc_user_t *user, bool32 is_replay)
{
    if (!user->is_loaded) {
        cm_spin_lock(&user->load_lock, NULL);
        if (!user->is_loaded) {
            if (user->buckets == NULL) {
                if (dc_init_table_context(ctx, user) != GS_SUCCESS) {
                    cm_spin_unlock(&user->load_lock);
                    return GS_ERROR;
                }
            }

            if (!is_replay && dc_init_entries(session, ctx, user->desc.id) != GS_SUCCESS) {
                cm_spin_unlock(&user->load_lock);
                return GS_ERROR;
            }
            user->is_loaded = GS_TRUE;
        }

        cm_spin_unlock(&user->load_lock);
    }

    return GS_SUCCESS;
}

status_t dc_open_user(knl_session_t *session, text_t *username, dc_user_t **user)
{
    uint32 uid, hash;
    dc_context_t *ctx = &session->kernel->dc_ctx;
    dc_bucket_t *bucket;
    dc_user_t *user_entry = NULL;

    hash = dc_hash(username);
    bucket = &ctx->user_buckets[hash];

    cm_spin_lock(&bucket->lock, NULL);
    uid = bucket->first;

    while (uid != GS_INVALID_ID32) {
        user_entry = ctx->users[uid];
        if (cm_text_str_equal(username, user_entry->desc.name)) {
            break;
        }

        uid = user_entry->next;
    }

    if (uid == GS_INVALID_ID32) {
        GS_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(username));
        cm_spin_unlock(&bucket->lock);
        return GS_ERROR;
    }

    if (session->drop_uid == uid) {
        *user = ctx->users[uid];
        cm_spin_unlock(&bucket->lock);
        return GS_SUCCESS;
    }

    cm_spin_unlock(&bucket->lock);

    if (session->kernel->attr.clustered && ctx->users[uid]->status == USER_STATUS_LOCKED) {
        if (dtc_try_clean_user_lock(session, ctx->users[uid]) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (ctx->users[uid]->status == USER_STATUS_NORMAL) {
        *user = ctx->users[uid];

        if (uid > DB_PUB_USER_ID) {
            if (!ctx->ready && !session->bootstrap) {
                GS_THROW_ERROR(ERR_DATABASE_NOT_AVAILABLE);
                return GS_ERROR;
            }

            if (dc_init_user_context(session, ctx, *user, GS_FALSE) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        return GS_SUCCESS;
    }

    GS_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(username));
    return GS_ERROR;
}

status_t dc_open_user_direct(knl_session_t *session, text_t *username, dc_user_t **user)
{
    uint32 uid, hash;
    dc_context_t *ctx = &session->kernel->dc_ctx;
    dc_bucket_t *bucket;
    dc_user_t *user_entry = NULL;

    hash = dc_hash(username);
    bucket = &ctx->user_buckets[hash];

    cm_spin_lock(&bucket->lock, NULL);
    uid = bucket->first;

    while (uid != GS_INVALID_ID32) {
        user_entry = ctx->users[uid];
        if (cm_text_str_equal(username, user_entry->desc.name)) {
            break;
        }

        uid = user_entry->next;
    }

    if (uid == GS_INVALID_ID32) {
        GS_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(username));
        cm_spin_unlock(&bucket->lock);
        return GS_ERROR;
    }

    *user = ctx->users[uid];
    cm_spin_unlock(&bucket->lock);
    return GS_SUCCESS;
}

status_t dc_open_user_by_id(knl_session_t *session, uint32 uid, dc_user_t **user)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;

    if (uid >= GS_MAX_USERS) {
        GS_LOG_RUN_ERR("dc_open_user_by_id failed, invalid uid %u", uid);
        GS_THROW_ERROR(ERR_USER_ID_NOT_EXIST, uid);
        return GS_ERROR;
    }

    if (ctx->users[uid]) {
        if (session->drop_uid == uid) {
            *user = ctx->users[uid];
        } else {
            if (ctx->users[uid]->status != USER_STATUS_NORMAL) {
                GS_THROW_ERROR(ERR_USER_ID_NOT_EXIST, uid);
                return GS_ERROR;
            }
            *user = ctx->users[uid];
        }

        if (uid > DB_PUB_USER_ID) {
            if (dc_init_user_context(session, ctx, *user, GS_FALSE) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        return GS_SUCCESS;
    }

    GS_THROW_ERROR(ERR_USER_ID_NOT_EXIST, uid);
    return GS_ERROR;
}

status_t dc_open_user_by_id_for_replay(knl_session_t *session, uint32 uid, dc_user_t **user)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;

    if (uid >= GS_MAX_USERS) {
        GS_LOG_RUN_ERR("dc_open_user_by_id failed, invalid uid %u", uid);
        GS_THROW_ERROR(ERR_USER_ID_NOT_EXIST, uid);
        return GS_ERROR;
    }

    if (ctx->users[uid]) {
        if (session->drop_uid == uid) {
            *user = ctx->users[uid];
        } else {
            if (ctx->users[uid]->status != USER_STATUS_NORMAL) {
                GS_THROW_ERROR(ERR_USER_ID_NOT_EXIST, uid);
                return GS_ERROR;
            }
            *user = ctx->users[uid];
        }

        if (uid > DB_PUB_USER_ID) {
            if (dc_init_user_context(session, ctx, *user, GS_TRUE) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        return GS_SUCCESS;
    }

    GS_THROW_ERROR(ERR_USER_ID_NOT_EXIST, uid);
    return GS_ERROR;
}

bool32 dc_get_user_id(knl_session_t *session, const text_t *user, uint32 *uid)
{
    uint32 i;
    dc_context_t *ctx = &session->kernel->dc_ctx;

    for (i = 0; i < GS_MAX_USERS; i++) {
        if (!ctx->users[i]) {
            continue;
        }
        if (cm_text_str_equal(user, ctx->users[i]->desc.name)) {
            if (session->kernel->attr.clustered && ctx->users[i]->status == USER_STATUS_LOCKED) {
                dtc_try_clean_user_lock(session, ctx->users[i]);
            }
            if (ctx->users[i]->status == USER_STATUS_NORMAL) {
                *uid = i;
                return GS_TRUE;
            } else if (session->drop_uid == i) {
                *uid = i;
                return GS_TRUE;
            }
        }
    }

    return GS_FALSE;
}

bool32 dc_get_role_id(knl_session_t *session, const text_t *role, uint32 *rid)
{
    uint32 i;
    dc_context_t *ctx = &session->kernel->dc_ctx;

    if (role == NULL || role->len == 0) {
        return GS_FALSE;
    }

    cm_spin_lock(&ctx->lock, NULL);
    for (i = 0; i < GS_MAX_ROLES; i++) {
        if (ctx->roles[i] != NULL && cm_text_str_equal_ins(role, ctx->roles[i]->desc.name)) {
            *rid = i;
            cm_spin_unlock(&ctx->lock);
            return GS_TRUE;
        }
    }
    cm_spin_unlock(&ctx->lock);

    return GS_FALSE;
}

/*
* set an user status
* @param
* - session: kernel session
* - username: user name
* - status: user status to set
* @return
* - GS_SUCCESS
* - GS_ERROR
* @note null
* @see null
*/
status_t dc_set_user_status(knl_session_t *session, text_t *username, uint32 status)
{
    uint32 i;
    text_t dc_user;
    dc_context_t *ctx = &session->kernel->dc_ctx;
    dc_user_t *user = NULL;

    for (i = 0; i < GS_MAX_USERS; i++) {
        cm_spin_lock(&ctx->lock, NULL);
        user = ctx->users[i];

        if (user == NULL) {
            cm_spin_unlock(&ctx->lock);
            continue;
        }

        cm_str2text(user->desc.name, &dc_user);
        if (cm_text_equal(&dc_user, username)) {
            dls_spin_lock(session, &user->s_lock, NULL);
            user->status = status;
            if (status == USER_STATUS_LOCKED) {
                user->user_locked_owner = session->kernel->id;
            } else {
                user->user_locked_owner = GS_INVALID_ID32;
            }

            SYNC_POINT_GLOBAL_START(CANTIAN_DROP_USER_REVERT_NORMAL_BEFORE_BCAST_ABORT, NULL, 0);
            SYNC_POINT_GLOBAL_END;

            dtc_broadcast_user_status(session, user->desc.id, user->status);
            dls_spin_unlock(session, &user->s_lock);
            cm_spin_unlock(&ctx->lock);
            return GS_SUCCESS;
        }
        cm_spin_unlock(&ctx->lock);
    }

    GS_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(username));

    return GS_ERROR;
}

static status_t dc_init_role(dc_context_t *ctx, dc_role_t *role)
{
    uint32 i;
    uint32 page_id;
    errno_t err;

    err = memset_sp(role, sizeof(dc_role_t), 0, sizeof(dc_role_t));
    knl_securec_check(err);
    if (dc_create_memory_context(ctx, &role->memory) != GS_SUCCESS) {
        return GS_ERROR;
    }
    cm_list_init(&role->parent_free);
    cm_list_init(&role->child_roles_free);
    cm_list_init(&role->child_users_free);
    cm_list_init(&role->parent);
    cm_list_init(&role->child_roles);
    cm_list_init(&role->child_users);
    role->bucket_page_id = GS_INVALID_ID32;
    role->entry_page_id = GS_INVALID_ID32;

    if (dc_alloc_memory_page(ctx, &page_id) != GS_SUCCESS) {
        mctx_destroy(role->memory);
        return GS_ERROR;
    }

    role->bucket_page_id = page_id;
    role->obj_privs.buckets = (dc_bucket_t *)mpool_page_addr(&ctx->pool, page_id);
    for (i = 0; i < DC_HASH_SIZE; i++) {
        role->obj_privs.buckets[i].lock = 0;
        role->obj_privs.buckets[i].first = GS_INVALID_ID32;
    }

    if (dc_alloc_memory_page(ctx, &page_id) != GS_SUCCESS) {
        mpool_free_page(&ctx->pool, role->bucket_page_id);
        mctx_destroy(role->memory);
        return GS_ERROR;
    }

    role->entry_page_id = page_id;
    role->obj_privs.groups = (object_priv_group_t **)mpool_page_addr(&ctx->pool, page_id);
    err = memset_sp(role->obj_privs.groups, GS_SHARED_PAGE_SIZE, 0, GS_SHARED_PAGE_SIZE);
    knl_securec_check(err);

    return GS_SUCCESS;
}

void inline dc_set_user_hwm(dc_context_t *ctx, uint32 id)
{
    if (id >= ctx->user_hwm) {
        ctx->user_hwm = id + 1;
    }
}

void dc_convert_user_desc(knl_cursor_t *cursor, knl_user_desc_t *desc)
{
    text_t text;

    desc->id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_ID);
    text.str = CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_NAME);
    text.len = CURSOR_COLUMN_SIZE(cursor, SYS_USER_COL_NAME);
    (void)cm_text2str(&text, desc->name, GS_NAME_BUFFER_SIZE);

    text.str = CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_PASSWORD);
    text.len = CURSOR_COLUMN_SIZE(cursor, SYS_USER_COL_PASSWORD);
    (void)cm_text2str(&text, desc->password, GS_PASSWORD_BUFFER_SIZE);

    desc->data_space_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_DATA_SPACE_ID);
    desc->temp_space_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_TEMP_SPACE_ID);
    desc->ctime = *(date_t *)CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_CTIME);
    desc->ptime = *(date_t *)CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_PTIME);

    /* expire time possible null */
    if (COL_BITS_8 == row_get_column_bits2(cursor->row, SYS_USER_COL_EXPTIME)) {
        desc->exptime = *(date_t *)CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_EXPTIME);
    }

    /* lock time possible null */
    if (COL_BITS_8 == row_get_column_bits2(cursor->row, SYS_USER_COL_LTIME)) {
        desc->ltime = *(date_t *)CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_LTIME);
    }

    desc->profile_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_PROFILE_ID);
    desc->astatus = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_ASTATUS);
    desc->lcount = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_LCOUNT);

    /* user created before upgrade, tenant_id must be set as SYS_TENANTROOT_ID;
    1.user created before upgrade, has not been updated after upgrade:
        column_count < SYS_USER_COLUMN_COUNT;
    2.user created before upgrade, but has been updated after upgrade:
        tenant_id size = GS_NULL_VALUE_LEN;
    3.user created after upgrade:
        column_count = SYS_USER_COLUMN_COUNT && tenant_id size = 4;
    */
    uint16 column_count = ROW_COLUMN_COUNT((cursor)->row);
    uint32 column_size = CURSOR_COLUMN_SIZE(cursor, SYS_USER_COL_TENANT_ID);
    if (column_count < SYS_USER_COLUMN_COUNT || column_size == GS_NULL_VALUE_LEN) {
        desc->tenant_id = SYS_TENANTROOT_ID;
    } else {
        desc->tenant_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_TENANT_ID);
    }
}

status_t dc_init_users(knl_session_t *session, dc_context_t *ctx)
{
    uint32 uid;
    dc_user_t *user = NULL;
    errno_t err;

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_core_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_USER_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {  // assert?
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_ID);

        dc_set_user_hwm(ctx, uid);

        if (uid >= GS_MAX_USERS) { // invalid user id, assert?
            break;
        }

        if (uid != DB_SYS_USER_ID) {
            if (dc_alloc_mem(ctx, ctx->memory, sizeof(dc_user_t), (void **)&user) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }

            err = memset_sp(user, sizeof(dc_user_t), 0, sizeof(dc_user_t));
            knl_securec_check(err);
            ctx->users[uid] = user;

            if (dc_init_user(ctx, user) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }

            if (uid == DB_PUB_USER_ID) {
                if (dc_init_table_context(ctx, user) != GS_SUCCESS) {
                    CM_RESTORE_STACK(session->stack);
                    return GS_ERROR;
                }
            }

            dc_convert_user_desc(cursor, &user->desc);
            dls_init_spinlock(&user->lock, DR_TYPE_USER, 0, (uint16)user->desc.id);
            dls_init_spinlock(&user->s_lock, DR_TYPE_USER, 1, (uint16)user->desc.id);
            dls_init_latch(&user->user_latch, DR_TYPE_USER, 2, (uint16)user->desc.id);
            dls_init_latch(&user->lib_latch, DR_TYPE_USER, 3, (uint16)user->desc.id);
            user->status = USER_STATUS_NORMAL;
            dc_insert_into_user_index(ctx, user);
        } else {
            user = ctx->users[uid];
            dc_init_sys_user_privs(user);
            dc_convert_user_desc(cursor, &user->desc);
            user->status = USER_STATUS_NORMAL;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {  // assert?
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t dc_init_roles(knl_session_t *session, dc_context_t *ctx)
{
    knl_cursor_t *cursor = NULL;
    dc_role_t *role = NULL;
    text_t rolename;
    text_t password;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_ROLES_ID, GS_INVALID_ID32);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (dc_alloc_mem(ctx, ctx->memory, sizeof(dc_role_t), (void **)&role) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (dc_init_role(ctx, role) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        role->desc.id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_ROLES_COL_ID);
        role->desc.owner_uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_ROLES_COL_OWNER_UID);
        rolename.str = CURSOR_COLUMN_DATA(cursor, SYS_ROLES_COL_NAME);
        rolename.len = CURSOR_COLUMN_SIZE(cursor, SYS_ROLES_COL_NAME);
        password.str = CURSOR_COLUMN_DATA(cursor, SYS_ROLES_COL_PASSWORD);
        password.len = CURSOR_COLUMN_SIZE(cursor, SYS_ROLES_COL_PASSWORD);

        (void)cm_text2str(&rolename, role->desc.name, GS_NAME_BUFFER_SIZE);
        (void)cm_text2str(&password, role->desc.password, GS_NAME_BUFFER_SIZE);
        ctx->roles[role->desc.id] = role;
        dls_init_spinlock(&role->lock, DR_TYPE_ROLE, role->desc.id, (uint16)role->desc.owner_uid);

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

void dc_init_sys_user_privs(dc_user_t *user)
{
    uint32 priv_id;

    for (priv_id = 1; priv_id < GS_SYS_PRIVS_COUNT; priv_id++) {
        DC_SET_PRIV_INFO(user->sys_privs, user->admin_opt, priv_id, 1);
        DC_SET_PRIV_INFO(user->all_sys_privs, user->ter_admin_opt, priv_id, 1);
    }
}

status_t dc_init_sys_user(knl_session_t *session, dc_context_t *ctx)
{
    dc_user_t *user = NULL;
    date_t now = cm_now();
    uint32 password_len;
    errno_t err;

    if (ctx->users[DB_SYS_USER_ID] != NULL) {
        return GS_SUCCESS;
    }

    if (dc_alloc_mem(ctx, ctx->memory, sizeof(dc_user_t), (void **)&user) != GS_SUCCESS) {
        return GS_ERROR;
    }

    err = memset_sp(user, sizeof(dc_user_t), 0, sizeof(dc_user_t));
    knl_securec_check(err);
    ctx->users[DB_SYS_USER_ID] = user;

    if (dc_init_user(ctx, user) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dc_init_table_context(ctx, user) != GS_SUCCESS) {
        return GS_ERROR;
    }

    dc_init_sys_user_privs(user);

    err = strcpy_sp(user->desc.name, GS_NAME_BUFFER_SIZE, "SYS");
    knl_securec_check(err);
    user->desc.id = DB_SYS_USER_ID;
    password_len = GS_PASSWORD_BUFFER_SIZE - 1;
    err = strncpy_s(user->desc.password, GS_PASSWORD_BUFFER_SIZE, session->kernel->attr.sys_pwd,
        password_len);
    knl_securec_check(err);

    user->desc.ctime = now;
    user->desc.ptime = now;
    user->desc.astatus = ACCOUNT_STATUS_OPEN;
    user->status = USER_STATUS_NORMAL;
    user->entry_hwm = GS_RESERVED_SYSID;
    user->entry_lwm = GS_RESERVED_SYSID;
    dls_init_spinlock(&user->lock, DR_TYPE_USER, 0, (uint16)user->desc.id);
    dls_init_spinlock(&user->s_lock, DR_TYPE_USER, 1, (uint16)user->desc.id);
    dls_init_latch(&user->user_latch, DR_TYPE_USER, 2, (uint16)user->desc.id);
    dls_init_latch(&user->lib_latch, DR_TYPE_USER, 3, (uint16)user->desc.id);

    dc_insert_into_user_index(ctx, user);

    return GS_SUCCESS;
}
/*
* add new user to dc
* @param    dc context, user id, user description structure
* @return
* - GS_SUCCESS
* - GS_ERROR
* @note null
* @see null
*/
status_t dc_add_user(dc_context_t *ctx, knl_user_desc_t *desc)
{
    dc_user_t *user = NULL;

    cm_spin_lock(&ctx->lock, NULL);
    if (dc_alloc_mem(ctx, ctx->memory, sizeof(dc_user_t), (void **)&user) != GS_SUCCESS) {
        cm_spin_unlock(&ctx->lock);
        return GS_ERROR;
    }

    cm_spin_unlock(&ctx->lock);
    if (dc_init_user(ctx, user) != GS_SUCCESS) {
        return GS_ERROR;
    }

    user->desc = *desc;
    user->status = USER_STATUS_NORMAL;
    ctx->users[desc->id] = user;
    dls_init_spinlock(&user->lock, DR_TYPE_USER, 0, (uint16)user->desc.id);
    dls_init_spinlock(&user->s_lock, DR_TYPE_USER, 1, (uint16)user->desc.id);
    dls_init_latch(&user->user_latch, DR_TYPE_USER, 2, (uint16)user->desc.id);
    dls_init_latch(&user->lib_latch, DR_TYPE_USER, 3, (uint16)user->desc.id);

    dc_insert_into_user_index(ctx, user);

    dc_set_user_hwm(ctx, desc->id);

    return GS_SUCCESS;
}

void dc_reuse_user(knl_session_t *session, knl_user_desc_t *desc)
{
    dc_user_t *user;
    dc_context_t *ctx = &session->kernel->dc_ctx;

    user = ctx->users[desc->id];
    dls_spin_lock(session, &user->s_lock, NULL);
    user->has_nologging = 0;
    user->desc = *desc;
    user->status = USER_STATUS_NORMAL;
    dls_spin_unlock(session, &user->s_lock);

    dc_insert_into_user_index(ctx, user);
}

/*
* @Prerequisites: lock the user->s_lock before call this function
*/
static void dc_clear_user_buckets(dc_user_t *user)
{
    uint32 i;

    if (user->buckets == NULL) {
        return;
    }

    for (i = 0; i < DC_HASH_SIZE; i++) {
        if (user->buckets[i].first != GS_INVALID_ID32) {
            /*
            * this function is supposed to be called when the user->s_lock.
            * so there is no need to lock user->buckets[i].lock
            */
            user->buckets[i].first = GS_INVALID_ID32;
        }
    }
}

static void dc_remove_user_bucket(knl_session_t *session, dc_user_t *user)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    dc_bucket_t *bucket = user->user_bucket;
    dc_user_t *next = NULL;
    dc_user_t *prev = NULL;

    cm_spin_lock(&bucket->lock, NULL);

    if (user->next != GS_INVALID_ID32) {
        next = ctx->users[user->next];
        next->prev = user->prev;
    }

    if (user->prev != GS_INVALID_ID32) {
        prev = ctx->users[user->prev];
        prev->next = user->next;
    }

    if (bucket->first == user->desc.id) {
        bucket->first = user->next;
    }

    dls_spin_lock(session, &user->lock, NULL);
    user->user_bucket = NULL;
    user->prev = GS_INVALID_ID32;
    user->next = GS_INVALID_ID32;
    dls_spin_unlock(session, &user->lock);

    cm_spin_unlock(&bucket->lock);

    bucket = user->tenant_bucket;

    cm_spin_lock(&bucket->lock, NULL);

    if (user->next1 != GS_INVALID_ID32) {
        next = ctx->users[user->next1];
        next->prev1 = user->prev1;
    }

    if (user->prev1 != GS_INVALID_ID32) {
        prev = ctx->users[user->prev1];
        prev->next1 = user->next1;
    }

    if (bucket->first == user->desc.id) {
        bucket->first = user->next1;
    }

    dls_spin_lock(session, &user->lock, NULL);
    user->tenant_bucket = NULL;
    user->prev1 = GS_INVALID_ID32;
    user->next1 = GS_INVALID_ID32;
    dls_spin_unlock(session, &user->lock);

    cm_spin_unlock(&bucket->lock);
}

/*
* drop user from dc
* @param    dc context, user id
* @return
* - GS_SUCCESS
* - GS_ERROR
* @note null
* @see null
*/
void dc_drop_user(knl_session_t *session, uint32 uid)
{
    dc_user_t *user = NULL;
    dc_context_t *ctx = NULL;

    if (uid >= GS_MAX_USERS) {
        return;
    }

    ctx = &session->kernel->dc_ctx;
    user = ctx->users[uid];

    if (user->user_bucket != NULL) {
        dc_remove_user_bucket(session, user);
    }

    dls_spin_lock(session, &user->s_lock, NULL);
    user->status = USER_STATUS_DROPPED;
    /*
    * clear all the buckets attached to the dropped user
    * for the possible reuse of dc_user_t
    */
    dc_clear_user_buckets(user);
    dls_spin_unlock(session, &user->s_lock);
    dc_clear_user_priv(ctx, user);
}

status_t dc_check_user_lock(knl_session_t *session, text_t *username)
{
    dc_user_t *user = NULL;

    if (CM_IS_EMPTY(username)) {
        return GS_ERROR;
    }

    if (dc_open_user_direct(session, username, &user) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (GS_BIT_TEST(user->desc.astatus, ACCOUNT_STATUS_LOCK)) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t dc_check_user_lock_timed(knl_session_t *session, text_t *username, bool32 *p_lock_unlock)
{
    knl_user_def_t def;
    dc_user_t *user = NULL;
    uint64 limit;
    date_t now = cm_now();
    date_t unlock_dt = 0;
    errno_t err;

    if (CM_IS_EMPTY(username)) {
        return GS_ERROR;
    }

    if (dc_open_user_direct(session, username, &user) != GS_SUCCESS) {
        return GS_ERROR;
    }

    err = memset_sp(&def, sizeof(knl_user_def_t), 0, sizeof(knl_user_def_t));
    knl_securec_check(err);

    (void)cm_text2str(username, def.name, GS_NAME_BUFFER_SIZE);
    if (GS_BIT_TEST(user->desc.astatus, ACCOUNT_STATUS_LOCK_TIMED)) {
        /* if the time exceed the pwd lock time, unlock account */
        if (GS_SUCCESS != profile_get_param_limit(session, user->desc.profile_id, PASSWORD_LOCK_TIME, &limit)) {
            return GS_ERROR;
        }

        if (PARAM_UNLIMITED != limit) {
            if (GS_SUCCESS != cm_date_add_seconds(user->desc.ltime, limit, &unlock_dt)) {
                return GS_ERROR;
            }

            if (now > unlock_dt) {
                def.is_lock_timed = GS_FALSE;
                def.mask |= USER_LOCK_TIMED_MASK;
                *p_lock_unlock = GS_TRUE;
                return user_alter(session, &def);
            }
        }

        return GS_ERROR;
    } else if (user->desc.lcount > 0) {
        def.is_lcount_clear = GS_TRUE;
        def.mask |= USER_LCOUNT_MASK;
        return user_alter(session, &def);
    } else {
        return GS_SUCCESS;
    }
}

status_t dc_check_user_expire(knl_session_t *session, text_t *username, char *message, uint32 message_len)
{
    dc_user_t *user = NULL;
    uint64 limit1;
    uint64 limit2;
    int32 remain_days;
    date_t now = cm_now();
    date_t expire_dt = 0;
    knl_user_def_t def;
    errno_t err;

    err = memset_sp(&def, sizeof(knl_user_def_t), 0, sizeof(knl_user_def_t));
    knl_securec_check(err);

    if (CM_IS_EMPTY(username)) {
        return GS_ERROR;
    }

    if (dc_open_user_direct(session, username, &user) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (GS_BIT_TEST(user->desc.astatus, ACCOUNT_STATUS_EXPIRED)) {
        err = snprintf_s(message, message_len, message_len - 1, "The current user has be in the expired status.");
        knl_securec_check_ss(err);
        return GS_ERROR;
    }

    if (GS_SUCCESS != profile_get_param_limit(session, user->desc.profile_id, PASSWORD_LIFE_TIME, &limit1)) {
        return GS_ERROR;
    }

    if (GS_SUCCESS != profile_get_param_limit(session, user->desc.profile_id, PASSWORD_GRACE_TIME, &limit2)) {
        return GS_ERROR;
    }

    if (PARAM_UNLIMITED != limit1) {
        if (GS_SUCCESS != cm_date_add_seconds(user->desc.ptime, limit1, &expire_dt)) {
            return GS_ERROR;
        }
    }

    if (PARAM_UNLIMITED == limit1 || now < expire_dt) {
        return GS_SUCCESS;
    }

    if (PARAM_UNLIMITED != limit2) {
        if (GS_SUCCESS != cm_date_add_seconds(user->desc.ptime, limit1 + limit2, &expire_dt)) {
            return GS_ERROR;
        }

        if (now < expire_dt) {
            remain_days = cm_date_diff_days(expire_dt, now);
            err = snprintf_s(message, message_len, message_len - 1, "Warnning:password will expire within %d days",
                remain_days);
            knl_securec_check_ss(err);
            (void)cm_text2str(username, def.name, GS_NAME_BUFFER_SIZE);
            def.mask |= USER_EXPIRE_GRACE_MASK;
            def.is_expire_grace = GS_TRUE;
            return user_alter(session, &def);
        }
    } else {
        err = snprintf_s(message, message_len, message_len - 1,
            "Warnning:the account will expire soon; change your password now");
        knl_securec_check_ss(err);
        (void)cm_text2str(username, def.name, GS_NAME_BUFFER_SIZE);
        def.mask |= USER_EXPIRE_GRACE_MASK;
        def.is_expire_grace = GS_TRUE;
        return user_alter(session, &def);
    }
    (void)cm_text2str(username, def.name, GS_NAME_BUFFER_SIZE);
    def.mask |= USER_EXPIRE_MASK;
    def.is_expire = GS_TRUE;
    (void)user_alter(session, &def);

    return GS_ERROR;
}

status_t dc_process_failed_login(knl_session_t *session, text_t *username, uint32 *p_lock_unlock)
{
    dc_user_t *user = NULL;
    knl_user_desc_t *desc = NULL;
    uint64 limit;
    knl_user_def_t def;
    date_t now = cm_now();
    date_t unlock_dt = 0;
    errno_t err;

    err = memset_sp(&def, sizeof(knl_user_def_t), 0, sizeof(knl_user_def_t));
    knl_securec_check(err);

    if (dc_open_user_direct(session, username, &user) != GS_SUCCESS) {
        return GS_ERROR;
    }
    desc = &user->desc;
    if (GS_BIT_TEST(desc->astatus, ACCOUNT_STATUS_LOCK_TIMED)) {
        /* if the time exceed the pwd lock time, unlock account */
        if (GS_SUCCESS != profile_get_param_limit(session, desc->profile_id, PASSWORD_LOCK_TIME, &limit)) {
            return GS_ERROR;
        }

        if (PARAM_UNLIMITED != limit) {
            if (GS_SUCCESS != cm_date_add_seconds(desc->ltime, limit, &unlock_dt)) {
                return GS_ERROR;
            }

            if (now > unlock_dt) {
                knl_user_def_t defunlock;
                err = memset_sp(&defunlock, sizeof(knl_user_def_t), 0, sizeof(knl_user_def_t));
                knl_securec_check(err);
                (void)cm_text2str(username, defunlock.name, GS_NAME_BUFFER_SIZE);
                defunlock.is_lock_timed = GS_FALSE;
                defunlock.mask |= USER_LOCK_TIMED_MASK;
                *p_lock_unlock = USER_UNLOCK;
                if (GS_SUCCESS != user_alter(session, &defunlock)) {
                    return GS_ERROR;
                }
            }
        }
    }

    if (GS_SUCCESS != profile_get_param_limit(session, desc->profile_id, FAILED_LOGIN_ATTEMPTS, &limit)) {
        return GS_ERROR;
    }
    (void)cm_text2str(username, def.name, GS_NAME_BUFFER_SIZE);
    def.mask |= USER_LCOUNT_MASK;
    def.is_lcount_clear = GS_FALSE;
    if (PARAM_UNLIMITED != limit && desc->lcount >= (uint32)limit) {
        /* set account status */
        def.mask |= USER_LOCK_TIMED_MASK;
        def.is_lock_timed = GS_TRUE;
        desc->astatus |= ACCOUNT_STATUS_LOCK_TIMED;
        (void)user_alter(session, &def);
        if (desc->lcount == limit + 1) {
            *p_lock_unlock = USER_LOCKED;
        }
        return GS_ERROR;
    }

    return user_alter(session, &def);
}

static void dc_fill_user(knl_cursor_t *cursor, dc_user_t *user, uint32 uid)
{
    text_t text;

    text.str = CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_NAME);
    text.len = CURSOR_COLUMN_SIZE(cursor, SYS_USER_COL_NAME);
    (void)cm_text2str(&text, user->desc.name, GS_NAME_BUFFER_SIZE);

    text.str = CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_PASSWORD);
    text.len = CURSOR_COLUMN_SIZE(cursor, SYS_USER_COL_PASSWORD);
    (void)cm_text2str(&text, user->desc.password, GS_PASSWORD_BUFFER_SIZE);

    user->desc.id = uid;
    user->status = USER_STATUS_NORMAL;
    user->desc.data_space_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_DATA_SPACE_ID);
    user->desc.temp_space_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_TEMP_SPACE_ID);
    user->desc.ctime = *(date_t *)CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_CTIME);
    user->desc.ptime = *(date_t *)CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_PTIME);

    /* expire time possible null */
    if (COL_BITS_8 == row_get_column_bits2(cursor->row, SYS_USER_COL_EXPTIME)) {
        user->desc.exptime = *(date_t *)CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_EXPTIME);
    }

    /* lock time possible null */
    if (COL_BITS_8 == row_get_column_bits2(cursor->row, SYS_USER_COL_LTIME)) {
        user->desc.ltime = *(date_t *)CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_LTIME);
    }

    user->desc.profile_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_PROFILE_ID);
    user->desc.astatus = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_ASTATUS);
    user->desc.lcount = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_LCOUNT);

    /* user created before upgrade, tenant_id must be set as SYS_TENANTROOT_ID;
    1.user created before upgrade, has not been updated after upgrade:
        column_count < SYS_USER_COLUMN_COUNT;
    2.user created before upgrade, but has been updated after upgrade:
        tenant_id size = GS_NULL_VALUE_LEN;
    3.user created after upgrade:
        column_count = SYS_USER_COLUMN_COUNT && tenant_id size = 4;
    */
    uint16 column_count = ROW_COLUMN_COUNT((cursor)->row);
    uint32 column_size = CURSOR_COLUMN_SIZE(cursor, SYS_USER_COL_TENANT_ID);
    if (column_count < SYS_USER_COLUMN_COUNT || column_size == GS_NULL_VALUE_LEN) {
        user->desc.tenant_id = SYS_TENANTROOT_ID;
    } else {
        user->desc.tenant_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_TENANT_ID);
    }
}

status_t dc_try_create_user(knl_session_t *session, const char *user_name)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    knl_cursor_t *cursor = NULL;
    uint32 uid;
    dc_user_t *user = NULL;
    errno_t err;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_USER_ID, IX_SYS_USER_002_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, user_name,
        (uint16)strlen(user_name), IX_COL_SYS_USER_001_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (!cursor->eof) {
        uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_ID);
        if (!ctx->users[uid]) {
            if (dc_alloc_mem(ctx, ctx->memory, sizeof(dc_user_t), (void **)&user) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
            err = memset_sp(user, sizeof(dc_user_t), 0, sizeof(dc_user_t));
            knl_securec_check(err);
            ctx->users[uid] = user;

            if (dc_init_user(ctx, user) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }

            dls_init_spinlock(&user->lock, DR_TYPE_USER, 0, (uint16)uid);
            dls_init_spinlock(&user->s_lock, DR_TYPE_USER, 1, (uint16)uid);
            dls_init_latch(&user->user_latch, DR_TYPE_USER, 2, (uint16)uid);
            dls_init_latch(&user->lib_latch, DR_TYPE_USER, 3, (uint16)uid);

            if (dc_init_table_context(ctx, user) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
        } else {
            user = ctx->users[uid];
        }

        dc_fill_user(cursor, user, uid);
        dc_insert_into_user_index(ctx, user);
        dc_set_user_hwm(ctx, uid);
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t dc_update_user(knl_session_t *session, const char *user_name, bool32 *is_found)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    knl_cursor_t *cursor = NULL;
    uint32 uid;
    dc_user_t *user = NULL;

    *is_found = GS_FALSE;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_USER_ID, IX_SYS_USER_002_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, user_name,
        (uint16)strlen(user_name), IX_COL_SYS_USER_001_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (!cursor->eof) {
        uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_USER_COL_ID);
        if (ctx->users[uid] == NULL || ctx->users[uid]->status != USER_STATUS_NORMAL) {
            CM_RESTORE_STACK(session->stack);
            GS_LOG_RUN_ERR("[DC] failed to load uid:%u", uid);
            return GS_ERROR;
        }
        user = ctx->users[uid];

        dc_fill_user(cursor, user, uid);
        if (uid == 0) { // refresh sys pwd into param
            if (cm_alter_config(session->kernel->attr.config, "_SYS_PASSWORD",
                user->desc.password, CONFIG_SCOPE_DISK, GS_TRUE) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                GS_LOG_RUN_ERR("[DC] failed to refresh sys pwd param");
                return GS_ERROR;
            }
        }
        *is_found = GS_TRUE;
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }

    *is_found = GS_FALSE;
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t dc_try_lock_user_tables(knl_session_t *session, dc_user_t *user)
{
    uint32 eid = 0;
    dc_entry_t *entry = NULL;

    for (eid = 0; eid < user->entry_hwm; eid++) {
        entry = DC_GET_ENTRY(user, eid);
        if (entry == NULL) {
            continue;
        }

        if (entry->type < DICT_TYPE_TABLE || entry->type > DICT_TYPE_TABLE_EXTERNAL) {
            continue;
        }

        if (dc_try_lock_table_ux(session, entry) != GS_SUCCESS) {
            unlock_tables_directly(session);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t dc_lock_user(knl_session_t *session, dc_user_t *user)
{
    dls_spin_lock(session, &user->lock, NULL);

    if (dc_try_lock_user_tables(session, user) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_USER_IS_REFERENCED, "user", user->desc.name, "being used");
        dls_spin_unlock(session, &user->lock);
        return GS_ERROR;
    }

    dls_spin_lock(session, &user->s_lock, NULL);
    user->status = USER_STATUS_LOCKED;
    user->user_locked_owner =  session->kernel->id;
    dtc_broadcast_user_status(session, user->desc.id, user->status);
    dls_spin_unlock(session, &user->s_lock);

    dls_spin_unlock(session, &user->lock);

    SYNC_POINT_GLOBAL_START(CANTIAN_DROP_USER_LOCK_AFTER_BCAST_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    return GS_SUCCESS;
}

/*
* add new role to dc
* @param    dc context, role id, role description structure
* @return
* - GS_SUCCESS
* - GS_ERROR
* @note null
* @see null
*/
status_t dc_add_role(dc_context_t *ctx, knl_role_desc_t *desc)
{
    dc_role_t *role = NULL;
    errno_t ret;

    cm_spin_lock(&ctx->lock, NULL);
    if (dc_alloc_mem(ctx, ctx->memory, sizeof(dc_role_t), (void **)&role) != GS_SUCCESS) {
        cm_spin_unlock(&ctx->lock);
        return GS_ERROR;
    }

    cm_spin_unlock(&ctx->lock);
    ret = memset_sp(role, sizeof(dc_role_t), 0, sizeof(dc_role_t));
    knl_securec_check(ret);

    cm_spin_lock(&ctx->lock, NULL);

    if (ctx->roles[desc->id] != NULL) {
        cm_spin_unlock(&ctx->lock);
        return GS_ERROR;
    }

    if (dc_init_role(ctx, role) != GS_SUCCESS) {
        cm_spin_unlock(&ctx->lock);
        return GS_ERROR;
    }

    dls_init_spinlock(&role->lock, DR_TYPE_ROLE, desc->id, (uint16)desc->owner_uid);

    ctx->roles[desc->id] = role;
    role->desc = *desc;
    cm_spin_unlock(&ctx->lock);
    return GS_SUCCESS;
}

/*
* drop role from dc, and revoke the role from all the roles/users granted
* @param    dc context, role id
* @return
* - GS_SUCCESS
* - GS_ERROR
* @note null
* @see null
*/
status_t dc_drop_role(knl_session_t *session, uint32 rid)
{
    dc_role_t *role = NULL;
    dc_context_t *ctx = &session->kernel->dc_ctx;

    knl_panic(rid < GS_MAX_ROLES);

    cm_spin_lock(&ctx->lock, NULL);

    role = ctx->roles[rid];
    dc_clear_role_priv(session, role);

    /* free pages */
    if (role->bucket_page_id != GS_INVALID_ID32) {
        mpool_free_page(&ctx->pool, role->bucket_page_id);
    }

    if (role->entry_page_id != GS_INVALID_ID32) {
        mpool_free_page(&ctx->pool, role->entry_page_id);
    }

    mctx_destroy(role->memory);
    ctx->roles[rid] = NULL;
    cm_spin_unlock(&ctx->lock);

    return GS_SUCCESS;
}

status_t dc_try_create_role(knl_session_t *session, uint32 id, const char *user_name)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    knl_cursor_t *cursor = NULL;
    knl_role_desc_t desc;
    text_t text;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_ROLES_ID, IX_SYS_ROLES_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&id,
        sizeof(uint32), IX_COL_SYS_ROLES_001_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, (void *)user_name,
        (uint16)strlen(user_name), IX_COL_SYS_ROLES_001_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (!cursor->eof) {
        desc.id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_ROLES_COL_ID);
        desc.owner_uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_ROLES_COL_OWNER_UID);
        text.str = CURSOR_COLUMN_DATA(cursor, SYS_ROLES_COL_NAME);
        text.len = CURSOR_COLUMN_SIZE(cursor, SYS_ROLES_COL_NAME);
        (void)cm_text2str(&text, desc.name, GS_NAME_BUFFER_SIZE);

        text.str = CURSOR_COLUMN_DATA(cursor, SYS_ROLES_COL_PASSWORD);
        text.len = CURSOR_COLUMN_SIZE(cursor, SYS_ROLES_COL_PASSWORD);
        (void)cm_text2str(&text, desc.password, GS_NAME_BUFFER_SIZE);

        if (dc_add_role(ctx, &desc) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t dc_get_user_default_spc(knl_session_t *session, uint32 uid, uint32 *spc_id)
{
    dc_user_t *user = NULL;

    knl_panic(uid < GS_MAX_USERS);
    if (GS_SUCCESS != dc_open_user_by_id(session, uid, &user)) {
        return GS_ERROR;
    }

    *spc_id = user->desc.data_space_id;

    knl_panic(*spc_id != GS_INVALID_ID32);
    return GS_SUCCESS;
}

status_t dc_get_user_temp_spc(knl_session_t *session, uint32 uid, uint32 *spc_id)
{
    dc_user_t *user = NULL;

    knl_panic(uid < GS_MAX_USERS);
    if (dc_open_user_by_id(session, uid, &user) != GS_SUCCESS) {
        return GS_ERROR;
    }

    *spc_id = user->desc.temp_space_id;

    knl_panic(*spc_id != GS_INVALID_ID32);
    return GS_SUCCESS;
}

status_t knl_get_user_name(knl_handle_t session, uint32 id, text_t *name)
{
    knl_session_t *se = (knl_session_t *)session;
    dc_context_t *ctx = &se->kernel->dc_ctx;

    if (id >= GS_MAX_USERS ||
        ctx->users[id] == NULL ||
        (se->drop_uid != id && ctx->users[id]->status != USER_STATUS_NORMAL)) {
        GS_THROW_ERROR(ERR_USER_NOT_EXIST, "");
        return GS_ERROR;
    }

    cm_str2text(ctx->users[id]->desc.name, name);
    return GS_SUCCESS;
}

bool32 knl_chk_user_status(knl_handle_t session, uint32 id)
{
    knl_session_t *se = (knl_session_t *)session;
    dc_context_t *ctx = &se->kernel->dc_ctx;
    if (id >= GS_MAX_USERS || ctx->users[id] == NULL || ctx->users[id]->status != USER_STATUS_NORMAL) {
        return GS_FALSE;
    }
    return GS_TRUE;
}

bool32 knl_get_user_id(knl_handle_t session, text_t *name, uint32 *uid)
{
    return dc_get_user_id((knl_session_t *)session, name, uid);
}

bool32 knl_get_role_id(knl_handle_t session, text_t *name, uint32 *rid)
{
    return dc_get_role_id((knl_session_t *)session, name, rid);
}

status_t knl_check_user_tables(knl_handle_t session, uint32 uid, bool32 *isfound)
{
    knl_session_t *se = (knl_session_t *)session;
    dc_user_t *user = NULL;

    knl_panic(uid < GS_MAX_USERS);
    if (dc_open_user_by_id(se, uid, &user) != GS_SUCCESS) {
        return GS_ERROR;
    }

    uint32 eid = 0;
    dc_entry_t *entry = NULL;

    for (eid = 0; eid < user->entry_hwm; eid++) {
        entry = DC_GET_ENTRY(user, eid);
        if (entry != NULL) {
            *isfound = GS_TRUE;
            return GS_SUCCESS;
        }
    }

    *isfound = GS_FALSE;
    return GS_SUCCESS;
}
