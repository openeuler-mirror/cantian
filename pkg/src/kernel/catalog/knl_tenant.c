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
 * knl_tenant.c
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/knl_tenant.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_tenant.h"
#include "knl_context.h"
#include "dc_tenant.h"
#include "knl_table.h"
#include "dc_user.h"
#include "knl_interface.h"
#include "dtc_dls.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t tenant_check_name_valid(knl_session_t *session, knl_tenant_def_t *def, knl_tenant_desc_t *desc)
{
    dc_tenant_t *tenant = NULL;
    dc_context_t *ctx = &session->kernel->dc_ctx;
    uint32 i;

    CM_MAGIC_CHECK(def, knl_tenant_def_t);
    CM_MAGIC_CHECK(desc, knl_tenant_desc_t);

    desc->id = GS_INVALID_ID32;

    for (i = 0; i < GS_MAX_TENANTS; i++) {
        tenant = ctx->tenants[i];
        if (tenant == NULL) {
            if (desc->id == GS_INVALID_ID32) {
                desc->id = i;
            }
            continue;
        }

        if (cm_str_equal(tenant->desc.name, def->name)) {
            GS_THROW_ERROR(ERR_OBJECT_EXISTS, "tenant", tenant->desc.name);
            return GS_ERROR;
        }
    }

    if (desc->id == GS_INVALID_ID32) {
        GS_THROW_ERROR(ERR_MAX_ROLE_COUNT, "tenants", GS_MAX_TENANTS);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t tenant_prepare_desc(knl_session_t *session, knl_tenant_def_t *def, knl_tenant_desc_t *desc)
{
    uint32 i;
    text_t* space_name = NULL;
    uint32 space_id;
    status_t status;
    space_t* space = NULL;
    text_t name;

    CM_MAGIC_CHECK(def, knl_tenant_def_t);
    CM_MAGIC_CHECK(desc, knl_tenant_desc_t);

    if (tenant_check_name_valid(session, def, desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    // check table space list
    for (i = 0; i < def->space_lst.count; i++) {
        space_name = (text_t*)cm_galist_get(&def->space_lst, i);

        status = spc_get_space_id(session, space_name, GS_FALSE, &space_id);
        if (status != GS_SUCCESS) {
            return GS_ERROR;
        }

        CM_ASSERT(space_id < GS_MAX_SPACES);

        space = SPACE_GET(session, space_id);
        if (!IS_USER_SPACE(space)) {
            GS_THROW_ERROR(ERR_SPACE_INVALID, space->ctrl->name);
            return GS_ERROR;
        }

        dc_set_tenant_tablespace_bitmap(desc, space_id);
    }
    desc->ts_num = def->space_lst.count;

    errno_t ret = strcpy_s(desc->name, GS_TENANT_BUFFER_SIZE, def->name);
    knl_securec_check(ret);

    cm_str2text(def->default_tablespace, &name);
    if (spc_get_space_id(session, &name, GS_FALSE, &space_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    desc->ts_id = space_id;
    desc->ctime = cm_now();
    return GS_SUCCESS;
}

status_t tenant_create(knl_session_t *session, knl_tenant_def_t *def)
{
    knl_cursor_t *cursor = NULL;
    knl_tenant_desc_t desc = { 0 };
    errno_t err;
    rd_tenant_t redo;
    status_t status;
    dc_context_t *ctx = &session->kernel->dc_ctx;

    CM_MAGIC_CHECK(def, knl_tenant_def_t);

    dls_spin_lock(session, &ctx->paral_lock, NULL);
    cm_latch_x(&ctx->tenant_latch, session->id, NULL);

    CM_MAGIC_SET(&desc, knl_tenant_desc_t);
    status = tenant_prepare_desc(session, def, &desc);
    if (status != GS_SUCCESS) {
        cm_unlatch(&ctx->tenant_latch, NULL);
        dls_spin_unlock(session, &ctx->paral_lock);
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_TENANTS_ID, GS_INVALID_ID32);

    status = db_insert_sys_tenants(session, cursor, &desc);
    if (status != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        cm_unlatch(&ctx->tenant_latch, NULL);
        dls_spin_unlock(session, &ctx->paral_lock);
        return GS_ERROR;
    }

    if (dc_add_tenant(ctx, &desc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        cm_unlatch(&ctx->tenant_latch, NULL);
        dls_spin_unlock(session, &ctx->paral_lock);
        return GS_ERROR;
    }

    CM_MAGIC_SET(&redo, rd_tenant_t);
    redo.op_type = RD_CREATE_TENANT;
    redo.tid = desc.id;
    err = strcpy_s(redo.name, GS_TENANT_BUFFER_SIZE, desc.name);
    knl_securec_check(err);
    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_tenant_t), LOG_ENTRY_FLAG_NONE);

    knl_commit(session);
    CM_RESTORE_STACK(session->stack);
    cm_unlatch(&ctx->tenant_latch, NULL);
    dls_spin_unlock(session, &ctx->paral_lock);

    return GS_SUCCESS;
}

status_t tenant_prepare_alter_add_space(knl_session_t *session, knl_tenant_def_t *def, knl_tenant_desc_t *desc)
{
    text_t* space_name = NULL;
    uint32 i;
    uint32 space_id;
    space_t* space = NULL;

    CM_MAGIC_CHECK(def, knl_tenant_def_t);
    CM_MAGIC_CHECK(desc, knl_tenant_desc_t);

    // check if table space already exist in tenant
    for (i = 0; i < def->space_lst.count; i++) {
        space_name = (text_t*)cm_galist_get(&def->space_lst, i);
        if (spc_get_space_id(session, space_name, GS_FALSE, &space_id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        CM_ASSERT(space_id < GS_MAX_SPACES);
        space = SPACE_GET(session, space_id);
        if (!IS_USER_SPACE(space)) {
            GS_THROW_ERROR(ERR_SPACE_INVALID, space->ctrl->name);
            return GS_ERROR;
        }
        if (dc_get_tenant_tablespace_bitmap(desc, space_id)) {
            GS_THROW_ERROR(ERR_SPACE_ALREADY_USABLE, space->ctrl->name);
            return GS_ERROR;
        }
    }

    // check table space list
    for (i = 0; i < def->space_lst.count; i++) {
        space_name = (text_t*)cm_galist_get(&def->space_lst, i);
        if (spc_get_space_id(session, space_name, GS_FALSE, &space_id) != GS_SUCCESS) {
            return GS_ERROR;
        }
        dc_set_tenant_tablespace_bitmap(desc, space_id);
    }

    desc->ts_num += def->space_lst.count;
    return GS_SUCCESS;
}

status_t tenant_prepare_alter_modify_default(knl_session_t *session, knl_tenant_def_t *def, knl_tenant_desc_t *desc)
{
    uint32 space_id;
    space_t* space = NULL;
    text_t name;

    CM_MAGIC_CHECK(def, knl_tenant_def_t);
    CM_MAGIC_CHECK(desc, knl_tenant_desc_t);
    CM_ASSERT(!CM_IS_EMPTY_STR(def->default_tablespace));

    cm_str2text(def->default_tablespace, &name);
    if (spc_get_space_id(session, &name, GS_FALSE, &space_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    CM_ASSERT(space_id < GS_MAX_SPACES);

    if (space_id == desc->ts_id) {
        return GS_SUCCESS;
    }

    space = SPACE_GET(session, space_id);
    if (!IS_USER_SPACE(space)) {
        GS_THROW_ERROR(ERR_SPACE_INVALID, space->ctrl->name);
        return GS_ERROR;
    }

    if (!dc_get_tenant_tablespace_bitmap(desc, space_id)) {
        GS_THROW_ERROR(ERR_SPACE_DISABLED, space->ctrl->name);
        return GS_ERROR;
    }

    desc->ts_id = space_id;
    return GS_SUCCESS;
}

status_t tenant_prepare_alter(knl_session_t *session, knl_tenant_def_t *def, knl_tenant_desc_t *desc)
{
    CM_MAGIC_CHECK(def, knl_tenant_def_t);
    CM_MAGIC_CHECK(desc, knl_tenant_desc_t);

    if (def->sub_type == ALTER_TENANT_TYPE_ADD_SPACE) {
        return tenant_prepare_alter_add_space(session, def, desc);
    } else {
        CM_ASSERT(def->sub_type == ALTER_TENANT_TYPE_MODEIFY_DEFAULT);
        return tenant_prepare_alter_modify_default(session, def, desc);
    }
}

status_t tenant_alter_core(knl_session_t *session, knl_tenant_def_t *def)
{
    knl_tenant_desc_t *desc = NULL;
    knl_tenant_desc_t save_desc;
    text_t tenant_name;
    dc_tenant_t* tenant = NULL;
    rd_tenant_t redo;

    CM_MAGIC_CHECK(def, knl_tenant_def_t);
    cm_str2text(def->name, &tenant_name);
    if (dc_open_tenant_core(session, &tenant_name, &tenant) != GS_SUCCESS) {
        return GS_ERROR;
    }

    cm_spin_lock(&tenant->lock, NULL);
    int32 ref_cnt = tenant->ref_cnt;
    cm_spin_unlock(&tenant->lock);
    if (ref_cnt > 0) {
        GS_THROW_ERROR(ERR_TENANT_IS_REFERENCED, T2S(&tenant_name), "can not alter");
        return GS_ERROR;
    }

    desc = &tenant->desc;
    save_desc = *desc;

    if (tenant_prepare_alter(session, def, desc) != GS_SUCCESS) {
        *desc = save_desc;
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    status_t status = db_alter_tenant_field(session, desc);
    CM_RESTORE_STACK(session->stack);
    if (status != GS_SUCCESS) {
        *desc = save_desc;
    } else {
        CM_MAGIC_SET(&redo, rd_tenant_t);
        redo.op_type = RD_ALTER_TENANT;
        errno_t err = strcpy_sp(redo.name, GS_TENANT_BUFFER_SIZE, def->name);
        knl_securec_check(err);
        log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_tenant_t), LOG_ENTRY_FLAG_NONE);
        knl_commit(session);
    }

    return status;
}

status_t tenant_alter(knl_session_t *session, knl_tenant_def_t *def)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;

    dls_spin_lock(session, &ctx->paral_lock, NULL);
    cm_latch_x(&ctx->tenant_latch, session->id, NULL);
    status_t status = tenant_alter_core(session, def);
    cm_unlatch(&ctx->tenant_latch, NULL);
    dls_spin_unlock(session, &ctx->paral_lock);
    return status;
}

status_t tenant_drop_user(knl_session_t *session, uint32 tid)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    dc_bucket_t *bucket = NULL;
    dc_user_t *user = NULL;
    text_t username;
    uint32 uid;

    bucket = &ctx->tenant_buckets[tid];
    while (bucket->first != GS_INVALID_ID32) {
        if (dc_open_user_by_id(session, bucket->first, &user) != GS_SUCCESS) {
            return GS_ERROR;
        }

        /* check if there has an online session with the user dropped now */
        cm_str2text(user->desc.name, &username);
        if (g_knl_callback.whether_login_with_user(&username)) {
            GS_THROW_ERROR(ERR_USER_HAS_LOGIN, user->desc.name);
            return GS_ERROR;
        }
        uid = user->next1;
        if (user_drop_core(session, user, GS_TRUE) != GS_SUCCESS) {
            session->drop_uid = GS_INVALID_ID32;
            return GS_ERROR;
        }
        CM_ASSERT(uid == bucket->first);
    }

    session->drop_uid = GS_INVALID_ID32;
    return GS_SUCCESS;
}

status_t tenant_drop(knl_session_t *session, knl_drop_tenant_t *def)
{
    uint32 tid = GS_INVALID_ID32;
    dc_context_t *ctx = &session->kernel->dc_ctx;
    rd_tenant_t redo;

    CM_MAGIC_CHECK(def, knl_drop_tenant_t);

    dls_spin_lock(session, &ctx->paral_lock, NULL);
    cm_latch_x(&ctx->tenant_latch, session->id, NULL);
    knl_set_session_scn(session, GS_INVALID_ID64);

    // check tenant if exists and lock users in this tenant
    if (dc_lock_tenant(session, def, &tid) != GS_SUCCESS) {
        cm_unlatch(&ctx->tenant_latch, NULL);
        dls_spin_unlock(session, &ctx->paral_lock);
        if (def->options & DROP_IF_EXISTS) {
            int32 code = cm_get_error_code();
            if (code == ERR_TENANT_NOT_EXIST) {
                cm_reset_error();
                return GS_SUCCESS;
            }
        }
        return GS_ERROR;
    }

    // drop users in this tenant
    if (tenant_drop_user(session, tid) != GS_SUCCESS) {
        cm_unlatch(&ctx->tenant_latch, NULL);
        dls_spin_unlock(session, &ctx->paral_lock);
        return GS_ERROR;
    }

    // delete from table SYS_TENANTS
    status_t status = db_delete_from_sys_tenant(session, tid);
    if (status == GS_SUCCESS) {
        // clear memory of this tenant
        dc_drop_tenant(session, tid);
        CM_MAGIC_SET(&redo, rd_tenant_t);
        redo.op_type = RD_DROP_TENANT;
        redo.tid = tid;
        errno_t err = strcpy_s(redo.name, GS_TENANT_BUFFER_SIZE, T2S(&def->name));
        knl_securec_check(err);
        log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_tenant_t), LOG_ENTRY_FLAG_NONE);
        knl_commit(session);
    }
    cm_unlatch(&ctx->tenant_latch, NULL);
    dls_spin_unlock(session, &ctx->paral_lock);
    return status;
}

status_t knl_get_tenant_id(knl_handle_t session, text_t *name, uint32 *tid)
{
    return dc_get_tenant_id((knl_session_t *)session, name, tid);
}

#ifdef __cplusplus
}
#endif
