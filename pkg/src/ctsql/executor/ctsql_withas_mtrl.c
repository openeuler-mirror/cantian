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
 * ctsql_withas_mtrl.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_withas_mtrl.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_withas_mtrl.h"
#include "ctsql_mtrl.h"
#include "ctsql_sort.h"
#include "ctsql_select.h"

static inline withas_mtrl_ctx_t *sql_get_withas_mtrl_ctx(sql_stmt_t *stmt, withas_mtrl_plan_t *withas_plan)
{
    if (stmt->withass != NULL) {
        return &((withas_mtrl_ctx_t *)stmt->withass)[withas_plan->id];
    }
    return NULL;
}

static status_t sql_alloc_withas_mtrl_ctx(sql_stmt_t *stmt, withas_mtrl_plan_t *withas_plan, withas_mtrl_ctx_t **ctx)
{
    if (stmt->withass == NULL) {
        sql_withas_t *withas = (sql_withas_t *)stmt->context->withas_entry;
        uint32 alloc_size = sizeof(withas_mtrl_ctx_t) * withas->withas_factors->count;
        CT_RETURN_IFERR(vmc_alloc(&stmt->vmc, alloc_size, &stmt->withass));
        MEMS_RETURN_IFERR(memset_sp(stmt->withass, alloc_size, 0, alloc_size));
    }

    (*ctx) = &((withas_mtrl_ctx_t *)stmt->withass)[withas_plan->id];

    (*ctx)->is_ready = CT_FALSE;
    (*ctx)->withas_p = withas_plan;
    (*ctx)->rs.sid = CT_INVALID_ID32;
    (*ctx)->rs.buf = NULL;

    return CT_SUCCESS;
}

static status_t sql_materialize_withas(sql_stmt_t *stmt, sql_cursor_t *cursor, withas_mtrl_ctx_t *ctx)
{
    sql_open_select_cursor(stmt, cursor, ctx->withas_p->rs_columns);

    CT_RETURN_IFERR(
        sql_sort_mtrl_record_types(&stmt->vmc, MTRL_SEGMENT_RS, ctx->withas_p->rs_columns, &cursor->mtrl.rs.buf));

    CT_RETURN_IFERR(mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_RS, NULL, &cursor->mtrl.rs.sid));

    if (mtrl_open_segment(&stmt->mtrl, cursor->mtrl.rs.sid) != CT_SUCCESS) {
        mtrl_release_segment(&stmt->mtrl, cursor->mtrl.rs.sid);
        cursor->mtrl.rs.sid = CT_INVALID_ID32;
        return CT_ERROR;
    }

    if (sql_materialize_base(stmt, cursor, ctx->withas_p->next) != CT_SUCCESS) {
        CTSQL_RELEASE_SEGMENT(stmt, cursor->mtrl.rs.sid);
        return CT_ERROR;
    }
    mtrl_close_segment(&stmt->mtrl, cursor->mtrl.rs.sid);
    ctx->rs = cursor->mtrl.rs;
    cursor->mtrl.rs.sid = CT_INVALID_ID32;
    ctx->is_ready = CT_TRUE;
    return CT_SUCCESS;
}

static inline status_t sql_withas_mtrl_open_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, withas_mtrl_ctx_t *mtrl_ctx)
{
    if (cursor->mtrl.cursor.rs_vmid != CT_INVALID_ID32) {
        mtrl_close_cursor(&stmt->mtrl, &cursor->mtrl.cursor);
    }
    if (mtrl_open_rs_cursor(&stmt->mtrl, mtrl_ctx->rs.sid, &cursor->mtrl.cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }
    cursor->columns = mtrl_ctx->withas_p->rs_columns;
    cursor->mtrl.rs.buf = mtrl_ctx->rs.buf;
    cursor->mtrl.cursor.type = MTRL_CURSOR_OTHERS;
    cursor->eof = CT_FALSE;
    return CT_SUCCESS;
}

status_t sql_execute_withas_mtrl(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    withas_mtrl_plan_t *withas_plan = &plan->withas_p;
    withas_mtrl_ctx_t *ctx = sql_get_withas_mtrl_ctx(stmt, withas_plan);

    if (ctx == NULL || !ctx->is_ready) {
        CT_RETURN_IFERR(sql_alloc_withas_mtrl_ctx(stmt, withas_plan, &ctx));

        CT_RETURN_IFERR(sql_materialize_withas(stmt, cursor, ctx));
    }
    return sql_withas_mtrl_open_cursor(stmt, cursor, ctx);
}

status_t sql_fetch_withas_mtrl(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
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
