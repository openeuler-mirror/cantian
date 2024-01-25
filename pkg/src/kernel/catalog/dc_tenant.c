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
 * dc_tenant.c
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/dc_tenant.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_dc_module.h"
#include "dc_tenant.h"
#include "cm_log.h"
#include "knl_context.h"
#include "dc_util.h"
#include "knl_database.h"

status_t dc_init_tenant(dc_context_t *ctx, dc_tenant_t **tenant_out)
{
    dc_tenant_t *tenant = NULL;

    tenant = (dc_tenant_t *)dc_list_remove(&ctx->free_tenants);
    if (tenant == NULL) {
        if (dc_alloc_mem(ctx, ctx->memory, sizeof(dc_tenant_t), (void **)&tenant) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    errno_t ret = memset_s(tenant, sizeof(dc_tenant_t), 0, sizeof(dc_tenant_t));
    knl_securec_check(ret);

    CM_MAGIC_SET(tenant, dc_tenant_t);
    CM_MAGIC_SET(&tenant->desc, knl_tenant_desc_t);
    *tenant_out = tenant;
    return CT_SUCCESS;
}

void dc_convert_tenant_desc(knl_cursor_t *cursor, knl_tenant_desc_t *desc)
{
    text_t text;

    CM_MAGIC_CHECK(desc, knl_tenant_desc_t);

    /* ID */
    desc->id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TENANTS_COL_ID);

    /* NAME */
    text.str = CURSOR_COLUMN_DATA(cursor, SYS_TENANTS_COL_NAME);
    text.len = CURSOR_COLUMN_SIZE(cursor, SYS_TENANTS_COL_NAME);
    (void)cm_text2str(&text, desc->name, CT_TENANT_BUFFER_SIZE);

    /* DEFAULT_TABLESPACE */
    desc->ts_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TENANTS_COL_TABLESPACE_ID);

    /* TABLESPACES_NUM */
    desc->ts_num = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TENANTS_COL_TABLESPACES_NUM);

    /* TABLESPACES_BITMAP */
    text.str = CURSOR_COLUMN_DATA(cursor, SYS_TENANTS_COL_TABLESPACES_BITMAP);
    text.len = CURSOR_COLUMN_SIZE(cursor, SYS_TENANTS_COL_TABLESPACES_BITMAP);
    errno_t err = memcpy_s(desc->ts_bitmap, CT_SPACES_BITMAP_SIZE, text.str, text.len);
    knl_securec_check(err);

    /* CREATE TIME */
    desc->ctime = *(date_t *)CURSOR_COLUMN_DATA(cursor, SYS_TENANTS_COL_CTIME);
}

status_t dc_init_tenants(knl_session_t *session, dc_context_t *ctx)
{
    uint32 tid;
    dc_tenant_t *tenant = NULL;

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TENANTS_ID, CT_INVALID_ID32);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    while (!cursor->eof) {
        tid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TENANTS_COL_ID);
        if (tid >= CT_MAX_TENANTS) {
            CM_NEVER;
            break;
        }

        if (tid == SYS_TENANTROOT_ID) {
            tenant = ctx->tenants[tid];
        } else {
            if (dc_init_tenant(ctx, &tenant) != CT_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return CT_ERROR;
            }
            ctx->tenants[tid] = tenant;
        }

        dc_convert_tenant_desc(cursor, &tenant->desc);
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t dc_add_tenant(dc_context_t *ctx, knl_tenant_desc_t *desc)
{
    dc_tenant_t *tenant = NULL;

    CM_MAGIC_CHECK(desc, knl_tenant_desc_t);
    if (dc_init_tenant(ctx, &tenant) != CT_SUCCESS) {
        return CT_ERROR;
    }

    tenant->desc = *desc;
    ctx->tenants[desc->id] = tenant;

    return CT_SUCCESS;
}

void dc_drop_tenant(knl_session_t *session, uint32 tid)
{
    dc_tenant_t *tenant = NULL;
    dc_context_t *ctx = &session->kernel->dc_ctx;

    CM_ASSERT(tid < CT_MAX_TENANTS);

    tenant = ctx->tenants[tid];
    ctx->tenants[tid] = NULL;
    CM_ASSERT(ctx->tenant_buckets[tid].first == CT_INVALID_ID32);

    dc_list_add(&ctx->free_tenants, (dc_list_node_t*)tenant);
}

static void dc_fill_tenant(knl_cursor_t *cursor, dc_tenant_t *tenant, uint32 tid)
{
    text_t text;

    CM_MAGIC_CHECK(tenant, dc_tenant_t);

    /* ID */
    tenant->desc.id = tid;

    /* NAME */
    text.str = CURSOR_COLUMN_DATA(cursor, SYS_TENANTS_COL_NAME);
    text.len = CURSOR_COLUMN_SIZE(cursor, SYS_TENANTS_COL_NAME);
    (void)cm_text2str(&text, tenant->desc.name, CT_TENANT_BUFFER_SIZE);

    /* DEFAULT_TABLESPACE */
    tenant->desc.ts_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TENANTS_COL_TABLESPACE_ID);

    /* TABLESPACES_NUM */
    tenant->desc.ts_num = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TENANTS_COL_TABLESPACES_NUM);

    /* TABLESPACES_BITMAP */
    text.str = CURSOR_COLUMN_DATA(cursor, SYS_TENANTS_COL_TABLESPACES_BITMAP);
    text.len = CURSOR_COLUMN_SIZE(cursor, SYS_TENANTS_COL_TABLESPACES_BITMAP);
    errno_t err = memcpy_s(tenant->desc.ts_bitmap, CT_SPACES_BITMAP_SIZE, text.str, text.len);
    knl_securec_check(err);

    /* CREATE TIME */
    tenant->desc.ctime = *(date_t *)CURSOR_COLUMN_DATA(cursor, SYS_TENANTS_COL_CTIME);
}

status_t dc_try_create_tenant(knl_session_t *session, uint32 id, const char *tenant_name)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    knl_cursor_t *cursor = NULL;
    uint32 tid;
    dc_tenant_t *tenant = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TENANTS_ID, IX_SYS_TENANTS_001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&id,
        sizeof(uint32), IX_COL_SYS_TENANTS_001_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (!cursor->eof) {
        tid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TENANTS_COL_ID);

        cm_latch_x(&ctx->tenant_latch, session->id, NULL);
        if (ctx->tenants[tid] == NULL) {
            if (dc_init_tenant(ctx, &tenant) != CT_SUCCESS) {
                cm_unlatch(&ctx->tenant_latch, NULL);
                CM_RESTORE_STACK(session->stack);
                return CT_ERROR;
            }
            ctx->tenants[tid] = tenant;
        } else {
            tenant = ctx->tenants[tid];
        }

        dc_fill_tenant(cursor, tenant, tid);
        cm_unlatch(&ctx->tenant_latch, NULL);
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t dc_open_tenant_by_id(knl_session_t *session, uint32 tid, dc_tenant_t **tenant)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;

    CM_ASSERT(tid < CT_MAX_TENANTS);
    cm_latch_s(&ctx->tenant_latch, session->id, CT_FALSE, NULL);
    if (ctx->tenants[tid] == NULL) {
        cm_unlatch(&ctx->tenant_latch, NULL);
        CT_THROW_ERROR(ERR_OBJECT_ID_NOT_EXIST, "tenant", tid);
        return CT_ERROR;
    }

    if (tid != SYS_TENANTROOT_ID) {
        cm_spin_lock(&ctx->tenants[tid]->lock, NULL);
        ctx->tenants[tid]->ref_cnt++;
        cm_spin_unlock(&ctx->tenants[tid]->lock);
    }
    *tenant = ctx->tenants[tid];
    cm_unlatch(&ctx->tenant_latch, NULL);
    return CT_SUCCESS;
}

void dc_set_tenant_tablespace_bitmap(knl_tenant_desc_t* desc, uint32 ts_id)
{
    uint32 bit, map;

    CM_ASSERT(ts_id <= CT_MAX_SPACES);
    CM_MAGIC_CHECK(desc, knl_tenant_desc_t);

    bit = ts_id / UINT8_BITS;
    map = ts_id % UINT8_BITS;
    desc->ts_bitmap[bit] |= (1 << map);
}

bool32 dc_get_tenant_tablespace_bitmap(knl_tenant_desc_t* desc, uint32 ts_id)
{
    uint32 bit, map;

    CM_ASSERT(ts_id <= CT_MAX_SPACES);
    CM_MAGIC_CHECK(desc, knl_tenant_desc_t);

    bit = ts_id / UINT8_BITS;
    map = ts_id % UINT8_BITS;

    if ((desc->ts_bitmap[bit] & (1 << map))) {
        return CT_TRUE;
    } else {
        return CT_FALSE;
    }
}

status_t dc_open_tenant_core(knl_session_t *session, const text_t *tenantname, dc_tenant_t **tenant_out)
{
    uint32 i;
    dc_context_t *ctx = &session->kernel->dc_ctx;
    dc_tenant_t *tenant = NULL;

    for (i = 0; i < CT_MAX_TENANTS; i++) {
        tenant = ctx->tenants[i];
        if (tenant == NULL || cm_text_str_equal_ins(tenantname, tenant->desc.name) == CT_FALSE) {
            continue;
        }
        *tenant_out = tenant;
        return CT_SUCCESS;
    }
    CT_THROW_ERROR(ERR_TENANT_NOT_EXIST, T2S(tenantname));
    return CT_ERROR;
}

status_t dc_open_tenant(knl_session_t *session, const text_t *tenantname, dc_tenant_t **tenant_out)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;

    cm_latch_s(&ctx->tenant_latch, session->id, CT_FALSE, NULL);
    if (dc_open_tenant_core(session, tenantname, tenant_out) != CT_SUCCESS) {
        cm_unlatch(&ctx->tenant_latch, NULL);
        return CT_ERROR;
    }

    if ((*tenant_out)->desc.id != SYS_TENANTROOT_ID) {
        cm_spin_lock(&(*tenant_out)->lock, NULL);
        (*tenant_out)->ref_cnt++;
        cm_spin_unlock(&(*tenant_out)->lock);
    }

    cm_unlatch(&ctx->tenant_latch, NULL);
    return CT_SUCCESS;
}

void dc_close_tenant(knl_session_t *session, uint32 tenant_id)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    dc_tenant_t *tenant = NULL;

    CM_ASSERT(tenant_id < CT_MAX_TENANTS);
    tenant = ctx->tenants[tenant_id];
    CM_MAGIC_CHECK(tenant, dc_tenant_t);

    if (tenant_id != SYS_TENANTROOT_ID) {
        cm_spin_lock(&tenant->lock, NULL);
        CM_ASSERT(tenant->ref_cnt > 0);
        tenant->ref_cnt--;
        cm_spin_unlock(&tenant->lock);
    }
}

status_t dc_update_tenant(knl_session_t *session, const char *tenant_name, bool32 *is_found)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    knl_cursor_t *cursor = NULL;
    uint32 tid;
    dc_tenant_t *tenant = NULL;

    *is_found = CT_FALSE;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TENANTS_ID, IX_SYS_TENANTS_002_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, tenant_name,
        (uint16)strlen(tenant_name), IX_COL_SYS_TENANTS_002_NAME);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (!cursor->eof) {
        tid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TENANTS_COL_ID);

        cm_latch_x(&ctx->tenant_latch, session->id, NULL);
        tenant = ctx->tenants[tid];
        if (tenant == NULL) {
            cm_unlatch(&ctx->tenant_latch, NULL);
            CM_RESTORE_STACK(session->stack);
            CT_LOG_RUN_ERR("[DC] failed to load tid:%u", tid);
            return CT_ERROR;
        }

        dc_fill_tenant(cursor, tenant, tid);
        *is_found = CT_TRUE;
        cm_unlatch(&ctx->tenant_latch, NULL);
        CM_RESTORE_STACK(session->stack);
        return CT_SUCCESS;
    }

    *is_found = CT_FALSE;
    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t dc_lock_tenant(knl_session_t *session, knl_drop_tenant_t *def, uint32 *tid)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    dc_tenant_t *tenant = NULL;
    dc_bucket_t *bucket = NULL;
    status_t status = CT_SUCCESS;

    if (dc_open_tenant_core(session, &def->name, &tenant) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cm_spin_lock(&tenant->lock, NULL);
    int32 ref_cnt = tenant->ref_cnt;
    cm_spin_unlock(&tenant->lock);
    if (ref_cnt > 0) {
        CT_THROW_ERROR(ERR_TENANT_IS_REFERENCED, T2S(&def->name), "can not drop");
        return CT_ERROR;
    }

    *tid = tenant->desc.id;
    bucket = &ctx->tenant_buckets[*tid];
    cm_spin_lock(&bucket->lock, NULL);
    if (bucket->first != CT_INVALID_ID32) {
        if (!(def->options & DROP_CASCADE_CONS)) {
            /* export error, need to specify the CASCADE option */
            CT_THROW_ERROR(ERR_TENANT_IS_REFERENCED, T2S(&def->name), "can not drop");
            status = CT_ERROR;
        }
    }
    cm_spin_unlock(&bucket->lock);
    return status;
}

status_t dc_init_root_tenant(knl_handle_t session, dc_context_t *ctx)
{
    dc_tenant_t *tenant = NULL;

    if (ctx->tenants[SYS_TENANTROOT_ID] != NULL) {
        return CT_SUCCESS;
    }

    if (dc_init_tenant(ctx, &tenant) != CT_SUCCESS) {
        return CT_ERROR;
    }

    tenant->desc.ctime = cm_now();
    tenant->desc.id = SYS_TENANTROOT_ID;
    tenant->desc.ts_id = FIXED_USER_SPACE_ID;
    tenant->desc.ts_num = 0;
    if (cm_text2str(&g_tenantroot, tenant->desc.name, CT_TENANT_NAME_LEN) != CT_SUCCESS) {
        return CT_ERROR;
    }
    errno_t ret = memset_s(tenant->desc.ts_bitmap, CT_SPACES_BITMAP_SIZE, -1, CT_SPACES_BITMAP_SIZE);
    knl_securec_check(ret);
    ctx->tenants[SYS_TENANTROOT_ID] = tenant;

    return CT_SUCCESS;
}

status_t dc_get_tenant_id(knl_session_t *session, const text_t *name, uint32 *tenant_id)
{
    dc_tenant_t *tenant = NULL;

    if (CM_IS_EMPTY(name) || cm_text_equal_ins(name, &g_tenantroot)) {
        *tenant_id = 0;
        return CT_SUCCESS;
    }

    if (dc_open_tenant(session, name, &tenant) != CT_SUCCESS) {
        return CT_ERROR;
    }
    CM_MAGIC_CHECK(tenant, dc_tenant_t);
    *tenant_id = tenant->desc.id;
    dc_close_tenant(session, tenant->desc.id);
    return CT_SUCCESS;
}