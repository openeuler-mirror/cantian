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
 * ctsql_concate.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_concate.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_concate.h"
#include "ctsql_select.h"
#include "ctsql_mtrl.h"
#include "ctsql_scan.h"
#include "srv_instance.h"

static inline status_t sql_alloc_concate_ctx(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    uint32 vmid;
    vm_page_t *vm_page = NULL;
    concate_ctx_t *concate_ctx = NULL;
    plan_node_t *sub_plan = NULL;
    uint32 bucket_num;

    CT_RETURN_IFERR(vm_alloc(KNL_SESSION(stmt), KNL_SESSION(stmt)->temp_pool, &vmid));

    if (vm_open(KNL_SESSION(stmt), KNL_SESSION(stmt)->temp_pool, vmid, &vm_page) != CT_SUCCESS) {
        vm_free(KNL_SESSION(stmt), KNL_SESSION(stmt)->temp_pool, vmid);
        return CT_ERROR;
    }

    concate_ctx = (concate_ctx_t *)vm_page->data;
    concate_ctx->id = 0;
    concate_ctx->vmid = vmid;
    concate_ctx->curr_plan = NULL;
    concate_ctx->keys = plan->cnct_p.keys;
    concate_ctx->sub_plans = plan->cnct_p.plans;
    concate_ctx->buf = (char *)vm_page->data + sizeof(concate_ctx_t);
    sql_init_hash_iter(&concate_ctx->iter, NULL);
    cursor->cnct_ctx = concate_ctx;

    bucket_num = 0;
    for (uint32 i = 0; i < concate_ctx->sub_plans->count; ++i) {
        sub_plan = (plan_node_t *)cm_galist_get(concate_ctx->sub_plans, i);
        bucket_num += sql_get_plan_hash_rows(stmt, sub_plan);
    }
    bucket_num = MIN(bucket_num, CT_HASH_JOIN_COUNT);

    vm_hash_segment_init(KNL_SESSION(stmt), stmt->mtrl.pool, &concate_ctx->hash_segment, PMA_POOL, HASH_PAGES_HOLD,
        HASH_AREA_SIZE);
    CT_RETURN_IFERR(vm_hash_table_alloc(&concate_ctx->hash_table, &concate_ctx->hash_segment, bucket_num));
    CT_RETURN_IFERR(vm_hash_table_init(&concate_ctx->hash_segment, &concate_ctx->hash_table, NULL, NULL, NULL));
    return CT_SUCCESS;
}

void sql_free_concate_ctx(sql_stmt_t *ctsql_stmt, concate_ctx_t *ctx)
{
    vm_hash_segment_deinit(&ctx->hash_segment);
    vm_free(KNL_SESSION(ctsql_stmt), KNL_SESSION(ctsql_stmt)->temp_pool, ctx->vmid);
}

static inline status_t sql_execute_child_plan(sql_stmt_t *ctsql_stmt, sql_cursor_t *cursor, plan_node_t *sub_plan,
    bool32 *eof)
{
    switch (sub_plan->type) {
        case PLAN_NODE_SCAN:
            return sql_execute_scan(ctsql_stmt, cursor, sub_plan);

        case PLAN_NODE_JOIN:
            return sql_execute_join(ctsql_stmt, cursor, sub_plan, eof);

        default:
            break;
    }

    CT_THROW_ERROR(ERR_SQL_PLAN_ERROR, "not support plan type for concate", sub_plan->type);
    return CT_ERROR;
}

static inline status_t sql_execute_for_concate(sql_stmt_t *ctsql_stmt, sql_cursor_t *cursor, concate_ctx_t *ctx,
    bool32 switch_plan, bool32 *eof)
{
    bool32 sub_eof = CT_FALSE;

    ctx->id = switch_plan ? ctx->id + 1 : ctx->id;

    while (ctx->id < ctx->sub_plans->count) {
        ctx->curr_plan = (plan_node_t *)cm_galist_get(ctx->sub_plans, ctx->id);
        CT_RETURN_IFERR(sql_execute_child_plan(ctsql_stmt, cursor, ctx->curr_plan, &sub_eof));
        if (!sub_eof) {
            return CT_SUCCESS;
        }
        ++ctx->id;
    }
    *eof = CT_TRUE;
    return CT_SUCCESS;
}

static inline status_t sql_fetch_sub_plan(sql_stmt_t *ctsql_stmt, sql_cursor_t *cursor, plan_node_t *sub_plan, bool32 *eof)
{
    switch (sub_plan->type) {
        case PLAN_NODE_JOIN:
            return sql_fetch_join(ctsql_stmt, cursor, sub_plan, eof);

        case PLAN_NODE_SCAN:
            cursor->last_table = sub_plan->scan_p.table->plan_id;
            return sql_fetch_scan(ctsql_stmt, cursor, sub_plan, eof);

        default:
            break;
    }
    CT_THROW_ERROR(ERR_SQL_PLAN_ERROR, "not support plan type for concate", sub_plan->type);
    return CT_ERROR;
}

static status_t sql_fetch_for_concate(sql_stmt_t *stmt, sql_cursor_t *cursor, concate_ctx_t *ctx, bool32 *eof)
{
    bool32 sub_eof = CT_FALSE;

    *eof = CT_FALSE;

    while (CT_TRUE) {
        CT_RETURN_IFERR(sql_fetch_sub_plan(stmt, cursor, ctx->curr_plan, &sub_eof));
        if (!sub_eof) {
            return CT_SUCCESS;
        }

        CT_RETURN_IFERR(sql_execute_for_concate(stmt, cursor, ctx, CT_TRUE, eof));
        if (*eof) {
            return CT_SUCCESS;
        }
        sub_eof = CT_FALSE;
    }
}

static inline status_t make_concate_hash_key(sql_stmt_t *stmt, galist_t *keys, char *buf)
{
    variant_t value;
    expr_tree_t *key = NULL;
    row_assist_t ra;

    row_init(&ra, buf, CT_MAX_ROW_SIZE, keys->count);
    for (uint32 i = 0; i < keys->count; i++) {
        key = (expr_tree_t *)cm_galist_get(keys, i);

        CT_RETURN_IFERR(sql_exec_expr(stmt, key, &value));
        CT_RETURN_IFERR(sql_put_row_value(stmt, NULL, &ra, key->root->datatype, &value));
    }
    return CT_SUCCESS;
}

status_t sql_execute_concate(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    CM_TRACE_BEGIN;
    if (cursor->cnct_ctx != NULL) {
        sql_free_concate_ctx(stmt, cursor->cnct_ctx);
        cursor->cnct_ctx = NULL;
    }

    CT_RETURN_IFERR(sql_alloc_concate_ctx(stmt, cursor, plan));
    CT_RETURN_IFERR(sql_execute_for_concate(stmt, cursor, cursor->cnct_ctx, CT_FALSE, &cursor->eof));
    CM_TRACE_END(stmt, plan->plan_id);
    return CT_SUCCESS;
}

status_t sql_fetch_concate(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    bool32 exist_row = CT_FALSE;
    concate_ctx_t *ctx = cursor->cnct_ctx;
    CM_TRACE_BEGIN;

    if (cursor->eof) {
        *eof = CT_TRUE;
        return CT_SUCCESS;
    }

    for (;;) {
        CTSQL_SAVE_STACK(stmt);
        CT_RETURN_IFERR(sql_fetch_for_concate(stmt, cursor, ctx, eof));

        if (*eof) {
            CTSQL_RESTORE_STACK(stmt);
            CM_TRACE_END(stmt, plan->plan_id);
            return CT_SUCCESS;
        }

        CT_RETURN_IFERR(make_concate_hash_key(stmt, ctx->keys, ctx->buf));
        CT_RETURN_IFERR(vm_hash_table_insert2(&exist_row, &ctx->hash_segment, &ctx->hash_table, ctx->buf,
            ((row_head_t *)ctx->buf)->size));
        CTSQL_RESTORE_STACK(stmt);

        if (!exist_row) {
            break;
        }
    }
    CM_TRACE_END(stmt, plan->plan_id);
    return CT_SUCCESS;
}