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
 * knl_profile.c
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/knl_profile.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_profile.h"
#include "knl_context.h"
#include "knl_user.h"
#include "dc_log.h"
#include "dtc_dls.h"

#define KNL_GET_PROFILE(array, id)          ((array)->profiles[(id) % MAX_PROFILE_SIZE])
#define KNL_SET_PROFILE(array, id, profile) ((array)->profiles[(id) % MAX_PROFILE_SIZE] = (profile))

const status_desc_t g_user_astatus_map[ACCOUNT_STATUS_TOTAL] = {
    { 0,  "OPEN",                                       NULL },
    { 1,  "EXPIRED",                                    NULL },
    { 2,  "EXPIRED(GRACE)",                             NULL },
    { 4,  "LOCKED(TIMED)",                              NULL },
    { 8,  "LOCKED",                                     NULL },
    { 5,  "EXPIRED & LOCKED(TIMED)",                    NULL },
    { 6,  "EXPIRED(GRACE) & LOCKED(TIMED)",             NULL },
    { 9,  "EXPIRED & LOCKED",                           NULL },
    { 10, "EXPIRED(GRACE) & LOCKED",                    NULL },
    { 16, "PERMANENT",                                  NULL },
    { 17, "PERMANENT & EXPIRED",                        NULL },
    { 18, "PERMANENT & EXPIRED(GRACE)",                 NULL },
    { 20, "PERMANENT & LOCKED(TIMED)",                  NULL },
    { 21, "PERMANENT & EXPIRED & LOCKED(TIMED)",        NULL },
    { 22, "PERMANENT & EXPIRED(GRACE) & LOCKED(TIMED)", NULL },
    { 24, "PERMANENT & LOCKED",                         NULL },
    { 25, "PERMANENT & EXPIRED & LOCKED",               NULL },
    { 26, "PERMANENT & EXPIRED(GRACE) & LOCKED",        NULL }
};

#define FAILED_LOGIN_ATTEMPTS_DESC "Specify the number of failed attempts to log in to the user account before the account is locked"
#define PASSWORD_LIFE_TIME_DESC    "Specify the number of days the same password can be used for authentication"
#define PASSWORD_REUSE_TIME_DESC   "Specify the number of days before which a password cannot be reused"
#define PASSWORD_REUSE_MAX_DESC    "Specify the number of password changes required before the current password can be reused"
#define PASSWORD_LOCK_TIME_DESC    "Specify the number of days an account will be locked after the specified number of consecutive failed login attempts"
#define PASSWORD_GRACE_TIME_DESC   "Specify the number of days after the grace period begins during which a warning is issued and login is allowed"
#define SESSION_PER_USER_DESC      "Specify the number of days after the grace period begins during which a warning is issued and login is allowed"
#define PASSOWORD_MIN_LEN_DESC     "Specify the minimum length of the password "

const resource_item_t g_resource_map[RESOURCE_PARAM_END] = {
    { "FAILED_LOGIN_ATTEMPTS",       PASSWORD_RES, 10,                         FAILED_LOGIN_ATTEMPTS_DESC, NULL },
    { "PASSWORD_LIFE_TIME",          PASSWORD_RES, 15552000,                   PASSWORD_LIFE_TIME_DESC,    "unit is second" },
    { "PASSWORD_REUSE_TIME",         PASSWORD_RES, PARAM_UNLIMITED,            PASSWORD_REUSE_TIME_DESC,   "unit is second" },
    { "PASSWORD_REUSE_MAX",          PASSWORD_RES, PARAM_UNLIMITED,            PASSWORD_REUSE_MAX_DESC,    NULL },
    { "PASSWORD_LOCK_TIME",          PASSWORD_RES, 86400,                      PASSWORD_LOCK_TIME_DESC,    "unit is second" },
    { "PASSWORD_GRACE_TIME",         PASSWORD_RES, 604800,                     PASSWORD_GRACE_TIME_DESC,   "unit is second" },
    { "SESSIONS_PER_USER",           KERNEL_RES,   PARAM_UNLIMITED,            SESSION_PER_USER_DESC,      NULL },
    { "PASSWORD_MIN_LEN",            PASSWORD_RES, 8,                          PASSOWORD_MIN_LEN_DESC,     NULL},
};

static inline uint32 profile_hash(text_t *name)
{
    uint32 val;
    val = cm_hash_text(name, INFINITE_HASH_RANGE);
    return val % PROFILE_HASH_SIZE;
}

static void profile_insert_into_buckets(knl_session_t *session, profile_array_t *profile_array,
                                        bucket_t *bucket, profile_t *profile)
{
    profile_t *first = NULL;

    profile->bucket = bucket;
    profile->next = bucket->first;
    profile->prev = GS_INVALID_ID32;

    if (bucket->first != GS_INVALID_ID32) {
        first = KNL_GET_PROFILE(profile_array, bucket->first);
        dls_spin_lock(session, &first->lock, NULL);
        first->prev = profile->id;
        dls_spin_unlock(session, &first->lock);
    }

    bucket->first = profile->id;
    bucket->count++;
}

static void profile_fill_paramters(knl_profile_def_t *def, profile_t *profile)
{
    profile->mask |= def->mask;
    for (uint32 i = FAILED_LOGIN_ATTEMPTS; i < RESOURCE_PARAM_END; i++) {
        if (GS_BIT_TEST(def->mask, GS_GET_MASK(i))) {
            switch (def->limit[i].type) {
                case VALUE_DEFAULT:
                    profile->limit[i] = g_resource_map[i].default_value;
                    break;
                case VALUE_UNLIMITED:
                    profile->limit[i] = PARAM_UNLIMITED;
                    break;
                case VALUE_NORMAL:
                    profile->limit[i] = def->limit[i].value;
                    break;
            }
        }
    }
}

static status_t profile_alloc(knl_session_t *session, knl_profile_def_t *def, profile_t **r_profile)
{
    uint32 i = 0;
    dc_context_t *dc_ctx = &session->kernel->dc_ctx;
    profile_array_t *profile_array = &dc_ctx->profile_array;
    profile_t *profile = NULL;
    errno_t ret;

    for (i = 0; i < MAX_PROFILE_SIZE; i++) {
        profile = profile_array->profiles[i];
        if (profile == NULL) {
            if (dc_alloc_mem(dc_ctx, dc_ctx->memory, sizeof(profile_t), (void **)&profile) != GS_SUCCESS) {
                return GS_ERROR;
            }
            ret = memset_sp(profile, sizeof(profile_t), 0, sizeof(profile_t));
            knl_securec_check(ret);
            profile_array->profiles[i] = profile;
            dls_init_spinlock(&profile->lock, DR_TYPE_PROFILE, i, 0);

            dls_spin_lock(session, &profile->lock, NULL);
            profile->id = i;
            (void)cm_text2str(&def->name, profile->name, GS_NAME_BUFFER_SIZE);
            profile_fill_paramters(def, profile);
            profile->used = GS_TRUE;
            dls_spin_unlock(session, &profile->lock);
            break;
        } else if (!profile->used && !profile->valid) {
            dls_spin_lock(session, &profile->lock, NULL);
            (void)cm_text2str(&def->name, profile->name, GS_NAME_BUFFER_SIZE);
            profile_fill_paramters(def, profile);
            profile->used = GS_TRUE;
            dls_spin_unlock(session, &profile->lock);
            break;
        }
    }

    if (i == MAX_PROFILE_SIZE) {
        GS_THROW_ERROR(ERR_TOO_MANY_OBJECTS, MAX_PROFILE_SIZE, "profiles");
        return GS_ERROR;
    }
    *r_profile = profile;
    return GS_SUCCESS;
}

status_t profile_alloc_and_insert_bucket(knl_session_t *session, knl_profile_def_t *def, bucket_t *bucket,
                                         profile_t **r_profile)
{
    profile_array_t *profile_array = &session->kernel->dc_ctx.profile_array;
    if (profile_alloc(session, def, r_profile) != GS_SUCCESS) {
        return GS_ERROR;
    }

    profile_insert_into_buckets(session, profile_array, bucket, *r_profile);

    return GS_SUCCESS;
}

bucket_t *profile_get_bucket(knl_session_t *session, text_t *name)
{
    dc_context_t *dc_ctx = &session->kernel->dc_ctx;
    profile_array_t *profile_array = &dc_ctx->profile_array;
    uint32 hash = profile_hash(name);
    return &profile_array->buckets[hash];
}

bool32 profile_find_by_name(knl_session_t *session, text_t *name, bucket_t *bucket, profile_t **r_profile)
{
    uint32 eid;
    dc_context_t *dc_ctx = &session->kernel->dc_ctx;
    profile_array_t *profile_array = &dc_ctx->profile_array;
    profile_t *profile = NULL;
    bool32 bucket_used = GS_FALSE;

    // parallel operation may cause different bucket ??
    if (bucket == NULL) {
        bucket = profile_get_bucket(session, name);
        cm_latch_s(&bucket->latch, session->id, GS_FALSE, NULL);
        bucket_used = GS_TRUE;
    }
    eid = bucket->first;

    while (eid != GS_INVALID_ID32) {
        profile = KNL_GET_PROFILE(profile_array, eid);
        dls_spin_lock(session, &profile->lock, NULL);
        if (!cm_compare_text_str(name, profile->name) && profile->valid) {
            *r_profile = profile;
            dls_spin_unlock(session, &profile->lock);
            break;
        }
        eid = profile->next;
        dls_spin_unlock(session, &profile->lock);
    }

    if (bucket_used == GS_TRUE) {
        cm_unlatch(&bucket->latch, NULL);
    }

    return (eid != GS_INVALID_ID32);
}

bool32 profile_find_by_id(knl_session_t *session, uint32 id, profile_t **r_profile)
{
    dc_context_t *dc_ctx = &session->kernel->dc_ctx;
    profile_array_t *profile_array = &dc_ctx->profile_array;
    profile_t *profile = NULL;

    knl_panic(id < MAX_PROFILE_SIZE);
    *r_profile = NULL;
    profile = KNL_GET_PROFILE(profile_array, id);
    if (profile == NULL) {
        return GS_FALSE;
    }
    dls_spin_lock(session, &profile->lock, NULL);
    if (profile->used) {
        *r_profile = profile;
        dls_spin_unlock(session, &profile->lock);
        return GS_TRUE;
    }
    dls_spin_unlock(session, &profile->lock);
    return GS_FALSE;
}

status_t profile_get_param_limit(knl_session_t *session, uint32 profile_id, resource_param_t param_id,
                                 uint64 *limit)
{
    profile_t *profile = NULL;
    if ((session->kernel->db.status < DB_STATUS_OPEN) || (DB_IS_UPGRADE(session))) {
        *limit = g_resource_map[param_id].default_value;
        return GS_SUCCESS;
    }

    if (!profile_find_by_id(session, profile_id, &profile)) {
        if (profile_id == DEFAULT_PROFILE_ID) {
            *limit = g_resource_map[param_id].default_value;
            return GS_SUCCESS;
        }

        GS_THROW_ERROR(ERR_PROFILE_ID_NOT_EXIST, profile_id);
        return GS_ERROR;
    }

    dls_spin_lock(session, &profile->lock, NULL);
    *limit = profile->limit[param_id];
    dls_spin_unlock(session, &profile->lock);

    return GS_SUCCESS;
}

static status_t profile_write_sysprofiles(knl_session_t *session, knl_cursor_t *cursor, profile_t *profile)
{
    uint32 max_size;
    row_assist_t ra;
    table_t *table = NULL;

    max_size = session->kernel->attr.max_row_size;
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_PROFILE_ID, IX_SYS_PROFILE_001_ID);
    table = (table_t *)cursor->table;

    for (uint32 i = FAILED_LOGIN_ATTEMPTS; i < RESOURCE_PARAM_END; i++) {
        if (GS_BIT_TEST(profile->mask, (uint32)GS_GET_MASK(i))) {
            row_init(&ra, (char *)cursor->row, max_size, table->desc.column_count);

            if (row_put_str(&ra, profile->name) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (row_put_int32(&ra, profile->id) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (row_put_int32(&ra, i) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (row_put_int64(&ra, profile->limit[i]) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
                return GS_ERROR;
            }

            knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_PROFILE_ID, 0);
        }
    }

    return GS_SUCCESS;
}

static void profile_set_reuse(knl_session_t *session, profile_t *profile)
{
    profile_t *next = NULL;
    profile_t *prev = NULL;
    dc_context_t *dc_ctx = &session->kernel->dc_ctx;
    profile_array_t *profile_array = &dc_ctx->profile_array;

    if (profile == NULL) {
        GS_LOG_RUN_ERR("profile_set_reuse expect profile, but not exist");
        return;
    }

    dls_spin_lock(session, &profile->lock, NULL);

    if (profile->next != GS_INVALID_ID32) {
        next = KNL_GET_PROFILE(profile_array, profile->next);
        next->prev = profile->prev;
    }

    if (profile->prev != GS_INVALID_ID32) {
        prev = KNL_GET_PROFILE(profile_array, profile->prev);
        prev->next = profile->next;
    }

    if (profile->bucket->first == profile->id) {
        profile->bucket->first = profile->next;
    }

    profile->used = GS_FALSE;
    profile->valid = GS_FALSE;
    profile->prev = GS_INVALID_ID32;
    profile->next = GS_INVALID_ID32;

    profile->bucket->count--;
    dls_spin_unlock(session, &profile->lock);
}

status_t profile_create(knl_session_t *session, profile_t *profile)
{
    knl_cursor_t *cursor = NULL;
    rd_profile_t redo;
    int32 ret;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    cursor->row = (row_head_t *)cursor->buf;

    if (profile_write_sysprofiles(session, cursor, profile) != GS_SUCCESS) {
        profile_set_reuse(session, profile);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    redo.op_type = RD_CREATE_PROFILE;
    redo.id = profile->id;
    ret = strcpy_sp(redo.obj_name, GS_NAME_BUFFER_SIZE, profile->name);
    knl_securec_check(ret);
    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_profile_t), LOG_ENTRY_FLAG_NONE);

    knl_commit(session);
    CM_RESTORE_STACK(session->stack);

    dls_spin_lock(session, &profile->lock, NULL);
    profile->valid = GS_TRUE;
    dls_spin_unlock(session, &profile->lock);

    return GS_SUCCESS;
}

static bool32 profile_check_user(knl_session_t *session, uint32 profile_id)
{
    uint32 i = 0;
    dc_context_t *ctx = &session->kernel->dc_ctx;
    dc_user_t *user = NULL;

    for (i = 0; i < GS_MAX_USERS; i++) {
        if (!ctx->users[i]) {
            continue;
        }

        user = ctx->users[i];
        dls_spin_lock(session, &user->s_lock, NULL);
        if (user->status == USER_STATUS_NORMAL && profile_id == user->desc.profile_id) {
            dls_spin_unlock(session, &user->s_lock);
            return GS_TRUE;
        }
        dls_spin_unlock(session, &user->s_lock);
    }

    return GS_FALSE;
}

static status_t profile_reset_user(knl_session_t *session, uint32 profile_id)
{
    uint32 i = 0;
    dc_context_t *ctx = &session->kernel->dc_ctx;
    dc_user_t *user = NULL;
    uint32 name_len = GS_NAME_BUFFER_SIZE - 1;
    errno_t ret;

    for (i = 0; i < GS_MAX_USERS; i++) {
        if (!ctx->users[i]) {
            continue;
        }

        user = ctx->users[i];
        if (user->status == USER_STATUS_NORMAL && profile_id == user->desc.profile_id) {
            knl_user_def_t def;
            ret = memset_sp(&def, sizeof(knl_user_def_t), 0, sizeof(knl_user_def_t));
            knl_securec_check(ret);
            ret = strncpy_s(def.name, GS_NAME_BUFFER_SIZE, user->desc.name, name_len);
            knl_securec_check(ret);
            def.mask |= USER_PROFILE_MASK;

            if (user_alter(session, &def) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

status_t profile_drop(knl_session_t *session, knl_drop_def_t *def, profile_t *profile)
{
    rd_profile_t redo;
    knl_cursor_t *cursor = NULL;
    int32 ret;

    if (profile_check_user(session, profile->id)) {
        if (!(def->options & DROP_CASCADE_CONS)) {
            GS_THROW_ERROR(ERR_PROFILE_HAS_USED);
            return GS_ERROR;
        } else {
            if (GS_SUCCESS != profile_reset_user(session, profile->id)) {
                return GS_ERROR;
            }
        }
    }

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_PROFILE_ID, IX_SYS_PROFILE_001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &profile->id,
                     sizeof(uint32), 0);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, 1);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &profile->id,
                     sizeof(uint32), 0);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, 1);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }

    while (!cursor->eof) {
        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    redo.op_type = RD_DROP_PROFILE;
    redo.id = profile->id;
    ret = strcpy_sp(redo.obj_name, GS_NAME_BUFFER_SIZE, profile->name);
    knl_securec_check(ret);
    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_profile_t), LOG_ENTRY_FLAG_NONE);

    knl_commit(session);
    CM_RESTORE_STACK(session->stack);
    profile_set_reuse(session, profile);

    return GS_SUCCESS;
}

static status_t profile_update_sysprofile(knl_session_t *session, knl_cursor_t *cursor, resource_param_t id,
                                          profile_t *profile)
{
    row_assist_t ra;
    knl_update_info_t *ua = &cursor->update_info;

    row_init(&ra, ua->data, HEAP_MAX_ROW_SIZE(session), 1);

    if (row_put_int64(&ra, profile->limit[id]) != GS_SUCCESS) {
        return GS_ERROR;
    }

    ua->count = 1;
    ua->columns[0] = PROFILE_THRESHOLD_COLUMN_ID;
    cm_decode_row(ua->data, ua->offsets, ua->lens, NULL);

    return knl_internal_update(session, cursor);
}

status_t profile_alter(knl_session_t *session, knl_profile_def_t *def)
{
    rd_profile_t redo;
    profile_t *profile = NULL;

    bucket_t *bucket = profile_get_bucket(session, &def->name);
    cm_latch_x(&bucket->latch, session->id, NULL);
    bool32 is_exists = profile_find_by_name(session, &def->name, bucket, &profile);
    if (is_exists == GS_FALSE) {
        cm_unlatch(&bucket->latch, NULL);
        GS_THROW_ERROR(ERR_PROFILE_NOT_EXIST, T2S(&def->name));
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_PROFILE_ID, 0);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &profile->id,
                     sizeof(uint32), 0);

    dls_spin_lock(session, &profile->lock, NULL);
    profile_fill_paramters(def, profile);
    dls_spin_unlock(session, &profile->lock);
    for (uint32 i = FAILED_LOGIN_ATTEMPTS; i < RESOURCE_PARAM_END; i++) {
        if (GS_BIT_TEST(def->mask, GS_GET_MASK(i))) {
            knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key,
                             GS_TYPE_INTEGER, &i, sizeof(uint32), 1);
            if (GS_SUCCESS != knl_fetch(session, cursor)) {
                CM_RESTORE_STACK(session->stack);
                cm_unlatch(&bucket->latch, NULL);
                return GS_ERROR;
            }

            if (!cursor->eof) {
                if (GS_SUCCESS != profile_update_sysprofile(session, cursor, i, profile)) {
                    CM_RESTORE_STACK(session->stack);
                    cm_unlatch(&bucket->latch, NULL);
                    return GS_ERROR;
                }
            }
            knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_PROFILE_ID, IX_SYS_PROFILE_001_ID);
        }
    }

    redo.op_type = RD_ALTER_PROFILE;
    redo.id = profile->id;
    errno_t ret = strcpy_sp(redo.obj_name, GS_NAME_BUFFER_SIZE, profile->name);
    knl_securec_check(ret);
    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_profile_t), LOG_ENTRY_FLAG_NONE);

    knl_commit(session);
    CM_RESTORE_STACK(session->stack);
    cm_unlatch(&bucket->latch, NULL);

    return GS_SUCCESS;
}

status_t profile_load(knl_session_t *session)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    profile_array_t *profile_array = &ctx->profile_array;
    knl_cursor_t *cursor = NULL;
    profile_t *profile = NULL;
    uint32 profile_id;
    uint32 resource_id;
    uint64 threshold;
    text_t text;
    errno_t ret;
    uint32 hash;
    bucket_t *bucket = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_PROFILE_ID, GS_INVALID_ID32);

    if (knl_fetch(session, cursor) != GS_SUCCESS) { // assert?
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        text.str = CURSOR_COLUMN_DATA(cursor, SYS_PROFILE_COL_NAME);
        text.len = CURSOR_COLUMN_SIZE(cursor, SYS_PROFILE_COL_NAME);

        profile_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PROFILE_COL_PROFILE_ID);
        resource_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PROFILE_COL_RESOURCE_ID);
        threshold = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_PROFILE_COL_THRESHOLD);

        if (profile_id >= MAX_PROFILE_SIZE) {
            break;
        }

        if (resource_id >= RESOURCE_PARAM_END) {
            break;
        }

        profile = KNL_GET_PROFILE(profile_array, profile_id);
        if (profile == NULL) {
            if (dc_alloc_mem(ctx, ctx->memory, sizeof(profile_t), (void **)&profile) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
            ret = memset_sp(profile, sizeof(profile_t), 0, sizeof(profile_t));
            knl_securec_check(ret);
            profile->used = GS_TRUE;
            profile->valid = GS_TRUE;
            profile->id = profile_id;
            (void)cm_text2str(&text, profile->name, GS_NAME_BUFFER_SIZE);
            KNL_SET_PROFILE(profile_array, profile_id, profile);
            dls_init_spinlock(&profile->lock, DR_TYPE_PROFILE, profile_id, 0);

            hash = profile_hash(&text);
            bucket = &profile_array->buckets[hash];
            cm_latch_x(&bucket->latch, session->id, NULL);
            profile_insert_into_buckets(session, profile_array, bucket, profile);
            cm_unlatch(&bucket->latch, NULL);
        }

        GS_BIT_SET(profile->mask, GS_GET_MASK(resource_id));
        profile->limit[resource_id] = threshold;

        if (knl_fetch(session, cursor) != GS_SUCCESS) { // assert?
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t profile_build_sysprofile(knl_session_t *session, knl_cursor_t *cursor)
{
    uint32 i;
    uint32 max_size;
    row_assist_t ra;

    max_size = session->kernel->attr.max_row_size;
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_PROFILE_ID, GS_INVALID_ID32);

    for (i = FAILED_LOGIN_ATTEMPTS; i < RESOURCE_PARAM_END; i++) {
        row_init(&ra, cursor->buf, max_size, PROFILE_COLUMN_NUM);

        if (row_put_str(&ra, DEFAULT_PROFILE_NAME) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (row_put_int32(&ra, DEFAULT_PROFILE_ID) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (row_put_int32(&ra, i) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (row_put_int64(&ra, g_resource_map[i].default_value) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }

        knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_PROFILE_ID, GS_INVALID_ID32);
    }

    return GS_SUCCESS;
}

void profile_convert_def(knl_cursor_t *cursor, knl_profile_def_t *def)
{
    uint32 resource_id;
    uint64 threshold;
    def->name.str = CURSOR_COLUMN_DATA(cursor, SYS_PROFILE_COL_NAME);
    def->name.len = CURSOR_COLUMN_SIZE(cursor, SYS_PROFILE_COL_NAME);

    resource_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PROFILE_COL_RESOURCE_ID);
    threshold = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_PROFILE_COL_THRESHOLD);
    GS_BIT_SET(def->mask, GS_GET_MASK(resource_id));
    def->limit[resource_id].type = VALUE_NORMAL;
    def->limit[resource_id].value = threshold;
}

static status_t profile_try_create(knl_session_t *session, uint32 id)
{
    knl_profile_def_t def = {{ .str = "", .len = 0 }, .mask = 0, .is_replace = GS_FALSE, {{ .type = 0, .value = 0 }}};
    knl_cursor_t *cursor = NULL;
    profile_t *profile = NULL;
    bucket_t *bucket = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_PROFILE_ID, IX_SYS_PROFILE_001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &id, sizeof(uint32), 0);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, 1);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &id, sizeof(uint32), 0);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, 1);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (cursor->eof) {
        GS_LOG_RUN_ERR("[PROF] failed to find profile in PROFILE$");
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        profile_convert_def(cursor, &def);
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    bucket = profile_get_bucket(session, &def.name);
    cm_latch_x(&bucket->latch, session->id, NULL);
    bool32 is_exists = profile_find_by_name(session, &def.name, bucket, &profile);
    if (is_exists == GS_TRUE) {
        cm_unlatch(&bucket->latch, NULL);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (profile_alloc_and_insert_bucket(session, &def, bucket, &profile) != GS_SUCCESS) {
        cm_unlatch(&bucket->latch, NULL);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    cm_unlatch(&bucket->latch, NULL);
    profile->valid = GS_TRUE;
    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

void rd_create_profile(knl_session_t *session, log_entry_t *log)
{
    text_t name;
    rd_profile_t *rd = (rd_profile_t *)log->data;
    profile_t *profile = NULL;

    cm_str2text(rd->obj_name, &name);

    // find_by_name will do in profile_try_create, no need to check here ??
    if (profile_find_by_name(session, &name, NULL, &profile)) {
        GS_LOG_RUN_ERR("rd_create_profile failed: profile [%s] exist", name.str);
        rd_check_dc_replay_err(session);
        return;
    }

    if (profile_try_create(session, rd->id) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("rd_create_profile failed");
        rd_check_dc_replay_err(session);
    }
}

void rd_alter_profile(knl_session_t *session, log_entry_t *log)
{
    rd_profile_t *rd = (rd_profile_t *)log->data;
    knl_cursor_t *cursor = NULL;
    profile_t *profile = NULL;
    knl_profile_def_t def = {{ .str = "", .len = 0 }, .mask = 0, .is_replace = GS_FALSE, {{ .type = 0, .value = 0 }}};

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_PROFILE_ID, IX_SYS_PROFILE_001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &rd->id, sizeof(uint32),
                     0);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, 1);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &rd->id, sizeof(uint32),
                     0);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, 1);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return;
    }

    if (cursor->eof) {
        GS_LOG_RUN_ERR("rd_alter_profile expect profile %s, but not exist", rd->obj_name);
        CM_RESTORE_STACK(session->stack);
        return;
    }

    while (!cursor->eof) {
        profile_convert_def(cursor, &def);
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return;
        }
    }

    if (!profile_find_by_name(session, &def.name, NULL, &profile)) {
        CM_RESTORE_STACK(session->stack);
        GS_LOG_RUN_ERR("rd_alter_profile expect profile %s, but not exist", rd->obj_name);
        return;
    }

    dls_spin_lock(session, &profile->lock, NULL);
    profile_fill_paramters(&def, profile);
    dls_spin_unlock(session, &profile->lock);

    CM_RESTORE_STACK(session->stack);
    return;
}

void rd_drop_profile(knl_session_t *session, log_entry_t *log)
{
    rd_profile_t *rd = (rd_profile_t *)log->data;
    profile_t *profile = NULL;
    bucket_t *bucket = NULL;
    if (!profile_find_by_id(session, rd->id, &profile)) {
        GS_THROW_ERROR(ERR_PROFILE_ID_NOT_EXIST, rd->id);
        return;
    }
    bucket = profile->bucket;
    cm_latch_x(&bucket->latch, session->id, NULL);
    profile_set_reuse(session, profile);
    cm_unlatch(&bucket->latch, NULL);
}

void print_create_profile(log_entry_t *log)
{
    rd_profile_t *rd = (rd_profile_t *)log->data;
    printf("create profile id:%u,profile_name:%s\n", rd->id, rd->obj_name);
}

void print_alter_profile(log_entry_t *log)
{
    rd_profile_t *rd = (rd_profile_t *)log->data;
    printf("alter profile id:%u,profile_name:%s\n", rd->id, rd->obj_name);
}

void print_drop_profile(log_entry_t *log)
{
    rd_profile_t *rd = (rd_profile_t *)log->data;
    printf("drop profile id:%u,profile_name:%s\n", rd->id, rd->obj_name);
}