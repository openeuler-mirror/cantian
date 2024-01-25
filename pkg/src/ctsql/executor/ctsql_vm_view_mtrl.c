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
 * ctsql_vm_view_mtrl.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_vm_view_mtrl.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_vm_view_mtrl.h"
#include "ctsql_mtrl.h"
#include "ctsql_sort.h"
#include "ctsql_select.h"
#include "ctsql_stmt.h"

static inline vm_view_mtrl_ctx_t *sql_get_vm_view_mtrl_ctx(sql_stmt_t *stmt, uint32 id)
{
    vm_view_mtrl_ctx_t **mtrl_list = (vm_view_mtrl_ctx_t **)stmt->vm_view_ctx_array;
    if (mtrl_list != NULL) {
        return mtrl_list[id];
    }
    return NULL;
}

static status_t sql_vm_view_mtrl_open_cursor(sql_stmt_t *stmt, sql_cursor_t *cur, vm_view_mtrl_ctx_t *ctx)
{
    if (cur->mtrl.cursor.rs_vmid != CT_INVALID_ID32) {
        mtrl_close_cursor(&stmt->mtrl, &cur->mtrl.cursor);
    }
    if (mtrl_open_rs_cursor(&stmt->mtrl, ctx->rs.sid, &cur->mtrl.cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }
    cur->columns = ctx->vm_view_p->rs_columns;
    cur->mtrl.rs.buf = ctx->rs.buf;
    cur->mtrl.cursor.type = MTRL_CURSOR_OTHERS;
    cur->eof = CT_FALSE;
    return CT_SUCCESS;
}

static status_t sql_materialize_vm_view(sql_stmt_t *stmt, sql_cursor_t *cursor, vm_view_mtrl_ctx_t *ctx)
{
    sql_open_select_cursor(stmt, cursor, ctx->vm_view_p->rs_columns);

    CT_RETURN_IFERR(
        sql_sort_mtrl_record_types(&stmt->vmc, MTRL_SEGMENT_RS, ctx->vm_view_p->rs_columns, &cursor->mtrl.rs.buf));

    CT_RETURN_IFERR(mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_RS, NULL, &cursor->mtrl.rs.sid));

    if (mtrl_open_segment(&stmt->mtrl, cursor->mtrl.rs.sid) != CT_SUCCESS) {
        mtrl_release_segment(&stmt->mtrl, cursor->mtrl.rs.sid);
        cursor->mtrl.rs.sid = CT_INVALID_ID32;
        return CT_ERROR;
    }

    if (sql_materialize_base(stmt, cursor, ctx->vm_view_p->next) != CT_SUCCESS) {
        CTSQL_RELEASE_SEGMENT(stmt, cursor->mtrl.rs.sid);
        return CT_ERROR;
    }
    mtrl_close_segment(&stmt->mtrl, cursor->mtrl.rs.sid);
    ctx->rs = cursor->mtrl.rs;
    cursor->mtrl.rs.sid = CT_INVALID_ID32;
    ctx->is_ready = CT_TRUE;
    return CT_SUCCESS;
}

static status_t sql_alloc_vm_view_mtrl_ctx(sql_stmt_t *stmt, sql_cursor_t *cursor, vm_view_mtrl_plan_t *vm_view_p,
    vm_view_mtrl_ctx_t **mtrl_ctx)
{
    if (stmt->vm_view_ctx_array == NULL) {
        uint32 array_size = stmt->context->vm_view_count * sizeof(vm_view_mtrl_ctx_t *);
        CT_RETURN_IFERR(vmc_alloc_mem(&stmt->vmc, array_size, (void **)(&stmt->vm_view_ctx_array)));
    }

    if (*mtrl_ctx == NULL) {
        uint32 alloc_size = sizeof(vm_view_mtrl_ctx_t);
        CT_RETURN_IFERR(vmc_alloc_mem(&stmt->vmc, alloc_size, (void **)mtrl_ctx));
        vm_view_mtrl_ctx_t **list = (vm_view_mtrl_ctx_t **)stmt->vm_view_ctx_array;
        list[vm_view_p->id] = *mtrl_ctx;
    }
    (*mtrl_ctx)->is_ready = CT_FALSE;
    (*mtrl_ctx)->vm_view_p = vm_view_p;
    (*mtrl_ctx)->rs.sid = CT_INVALID_ID32;
    (*mtrl_ctx)->rs.buf = NULL;

    return CT_SUCCESS;
}

status_t sql_execute_vm_view_mtrl(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    vm_view_mtrl_plan_t *vm_view_p = &plan->vm_view_p;
    vm_view_mtrl_ctx_t *mtrl_ctx = sql_get_vm_view_mtrl_ctx(stmt, vm_view_p->id);

    if (mtrl_ctx == NULL || !mtrl_ctx->is_ready) {
        CT_RETURN_IFERR(sql_alloc_vm_view_mtrl_ctx(stmt, cursor, vm_view_p, &mtrl_ctx));

        CT_RETURN_IFERR(sql_materialize_vm_view(stmt, cursor, mtrl_ctx));
    }
    return sql_vm_view_mtrl_open_cursor(stmt, cursor, mtrl_ctx);
}

status_t sql_fetch_vm_view_mtrl(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    if (SECUREC_UNLIKELY(cursor->mtrl.cursor.rs_vmid == CT_INVALID_ID32)) {
        (*eof) = CT_TRUE;
        return CT_SUCCESS;
    }
    if (mtrl_fetch_rs(&stmt->mtrl, &cursor->mtrl.cursor, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    (*eof) = cursor->mtrl.cursor.eof;
    return CT_SUCCESS;
}