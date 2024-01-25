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
 * ctsql_hash_mtrl.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_hash_mtrl.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_mtrl.h"
#include "ctsql_aggr.h"
#include "ctsql_select.h"
#include "srv_instance.h"
#include "ctsql_hash_mtrl.h"

static inline status_t sql_make_hash_mtrl_row(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, char *buf,
    uint32 *size, bool32 *has_null)
{
    row_assist_t ra;
    galist_t *local_keys = plan->hash_mtrl.group.exprs;

    CT_RETURN_IFERR(sql_make_hash_key(stmt, &ra, buf, local_keys, HASH_MTRL_CONTEXT(cursor)->key_types, has_null));
    if (*has_null) {
        return CT_SUCCESS;
    }
    return sql_calc_aggr_reserve_size(&ra, HASH_MTRL_GROUP_CONTEXT, size);
}

static inline status_t sql_make_hash_mtrl_scan_key(sql_stmt_t *stmt, sql_cursor_t *cursor, hash_mtrl_plan_t *hash_mtrl,
    char *buf, bool32 *has_null)
{
    row_assist_t ra;
    galist_t *remote_keys = hash_mtrl->remote_keys;

    return sql_make_hash_key(stmt, &ra, buf, remote_keys, HASH_MTRL_CONTEXT(cursor)->key_types, has_null);
}

static status_t sql_hash_mtrl_build_hash_table(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    bool32 found = CT_FALSE;
    bool32 has_null = CT_FALSE;
    bool32 eof = CT_FALSE;
    char *buf = NULL;
    uint32 size;
    status_t status = CT_ERROR;
    bool32 exists_record = CT_FALSE;

    galist_t *remote_keys = plan->hash_mtrl.remote_keys;
    galist_t *local_keys = plan->hash_mtrl.group.exprs;

    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));

    CT_RETURN_IFERR(
        vmc_alloc(&stmt->vmc, sizeof(ct_type_t) * local_keys->count, (void **)&HASH_MTRL_CONTEXT(cursor)->key_types));
    CT_RETURN_IFERR(
        sql_get_hash_key_types(stmt, cursor->query, local_keys, remote_keys, HASH_MTRL_CONTEXT(cursor)->key_types));

    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buf));
    for (;;) {
        CTSQL_SAVE_STACK(stmt);
        CT_BREAK_IF_ERROR(sql_fetch_query(stmt, cursor, plan->hash_mtrl.group.next, &eof));
        if (eof) {
            CTSQL_RESTORE_STACK(stmt);
            status = CT_SUCCESS;
            break;
        }

        CT_BREAK_IF_ERROR(sql_make_hash_mtrl_row(stmt, cursor, plan, buf, &size, &has_null));
        if (has_null) {
            CTSQL_RESTORE_STACK(stmt);
            // when there is null in key, then all equal predicate will return false
            continue;
        }

        exists_record = CT_TRUE;
        CT_BREAK_IF_ERROR(vm_hash_table_insert2(&found, HASH_MTRL_SEGMENT, HASH_MTRL_TABLE_ENTRY, buf, size));

        CTSQL_RESTORE_STACK(stmt);
    }
    CTSQL_POP(stmt);
    SQL_CURSOR_POP(stmt);

    HASH_MTRL_GROUP_CONTEXT->empty = !exists_record;
    return status;
}

static inline void sql_hash_mtrl_set_aggr_default(sql_cursor_t *cursor, hash_mtrl_ctx_t *mtrl_ctx)
{
    mtrl_cursor_t *mtrl_cursor = &cursor->mtrl.cursor;
    mtrl_cursor->hash_group.aggrs = mtrl_ctx->aggrs;
}

static inline void sql_hash_mtrl_open_cursor(sql_cursor_t *cursor, hash_mtrl_ctx_t *mtrl_ctx)
{
    mtrl_ctx->fetched = CT_FALSE;
    mtrl_ctx->group_ctx.oper_type = OPER_TYPE_FETCH;
    cursor->mtrl.cursor.type = MTRL_CURSOR_HASH_GROUP;
    cursor->eof = CT_FALSE;
}

static inline status_t sql_hash_mtrl_fetch_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan,
    bool32 *eof)
{
    char *key_buf = NULL;
    bool32 found = CT_FALSE;
    bool32 has_null = CT_FALSE;
    hash_scan_assist_t scan_assist;

    if (HASH_MTRL_GROUP_CONTEXT->empty) {
        sql_hash_mtrl_set_aggr_default(cursor, HASH_MTRL_CONTEXT(cursor));
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&key_buf));
    CT_RETURN_IFERR(sql_make_hash_mtrl_scan_key(stmt, cursor, &plan->hash_mtrl, key_buf, &has_null));
    if (has_null) {
        CTSQL_POP(stmt);
        sql_hash_mtrl_set_aggr_default(cursor, HASH_MTRL_CONTEXT(cursor));
        return CT_SUCCESS;
    }

    scan_assist.scan_mode = HASH_KEY_SCAN;
    scan_assist.buf = key_buf;
    scan_assist.size = ((row_head_t *)key_buf)->size;
    CT_RETURN_IFERR(
        vm_hash_table_open(HASH_MTRL_SEGMENT, HASH_MTRL_TABLE_ENTRY, &scan_assist, &found, HASH_MTRL_TABLE_ITER));
    CTSQL_POP(stmt);

    if (!found) {
        sql_hash_mtrl_set_aggr_default(cursor, HASH_MTRL_CONTEXT(cursor));
        HASH_MTRL_TABLE_ITER->curr_match.vmid = CT_INVALID_ID32;
        return CT_SUCCESS;
    }

    return vm_hash_table_fetch(eof, HASH_MTRL_SEGMENT, HASH_MTRL_TABLE_ENTRY, HASH_MTRL_TABLE_ITER);
}

static inline status_t sql_hash_mtrl_init_aggr_default(sql_stmt_t *stmt, hash_mtrl_ctx_t *mtrl_ctx, plan_node_t *plan)
{
    const sql_func_t *func = NULL;
    vm_page_t *vm_page = NULL;
    aggr_var_t *aggr_v = NULL;
    galist_t *aggrs = plan->hash_mtrl.group.aggrs;
    char *extras = NULL;
    aggr_assist_t ass;
    SQL_INIT_AGGR_ASSIST(&ass, stmt, mtrl_ctx->group_ctx.cursor);

    CT_RETURN_IFERR(vm_alloc(KNL_SESSION(stmt), KNL_SESSION(stmt)->temp_pool, &mtrl_ctx->aggr_id));
    CT_RETURN_IFERR(vm_open(KNL_SESSION(stmt), KNL_SESSION(stmt)->temp_pool, mtrl_ctx->aggr_id, &vm_page));

    mtrl_ctx->aggrs = (char *)vm_page->data;
    if (aggrs->count * sizeof(aggr_var_t) > CT_VMEM_PAGE_SIZE) {
        CT_THROW_ERROR(ERR_TOO_MANY_ARRG);
        return CT_ERROR;
    }

    extras = mtrl_ctx->aggrs + aggrs->count * sizeof(aggr_var_t);

    MEMS_RETURN_IFERR(
        memset_s((void *)mtrl_ctx->aggrs, aggrs->count * sizeof(aggr_var_t), 0, aggrs->count * sizeof(aggr_var_t)));

    for (uint32 i = 0; i < aggrs->count; i++) {
        ass.aggr_node = (expr_node_t *)cm_galist_get(aggrs, i);
        aggr_v = (aggr_var_t *)(mtrl_ctx->aggrs + i * sizeof(aggr_var_t));
        func = GET_AGGR_FUNC(ass.aggr_node);
        aggr_v->aggr_type = func->aggr_type;
        switch (func->aggr_type) {
            case AGGR_TYPE_GROUP_CONCAT:
                aggr_v->extra_offset = (uint32)(extras - (char *)aggr_v);
                aggr_v->extra_size = sizeof(aggr_group_concat_t);
                extras += sizeof(aggr_group_concat_t);
                break;
            case AGGR_TYPE_DENSE_RANK:
                aggr_v->extra_offset = (uint32)(extras - (char *)aggr_v);
                aggr_v->extra_size = sizeof(aggr_dense_rank_t);
                extras += sizeof(aggr_dense_rank_t);
                /* fall-through */
            case AGGR_TYPE_RANK:
                aggr_v->var.is_null = CT_TRUE;
                aggr_v->var.type = CT_TYPE_INTEGER;
                VALUE(uint32, &aggr_v->var) = 1;
                break;
            case AGGR_TYPE_STDDEV:
            case AGGR_TYPE_STDDEV_POP:
            case AGGR_TYPE_STDDEV_SAMP:
            case AGGR_TYPE_VARIANCE:
            case AGGR_TYPE_VAR_POP:
            case AGGR_TYPE_VAR_SAMP:
                aggr_v->extra_offset = (uint32)(extras - (char *)aggr_v);
                aggr_v->extra_size = sizeof(aggr_stddev_t);
                extras += sizeof(aggr_stddev_t);
                break;
            case AGGR_TYPE_COVAR_POP:
            case AGGR_TYPE_COVAR_SAMP:
                aggr_v->extra_offset = (uint32)(extras - (char *)aggr_v);
                aggr_v->extra_size = sizeof(aggr_covar_t);
                extras += sizeof(aggr_covar_t);
                break;
            case AGGR_TYPE_CORR:
                aggr_v->extra_offset = (uint32)(extras - (char *)aggr_v);
                aggr_v->extra_size = sizeof(aggr_corr_t);
                extras += sizeof(aggr_corr_t);
                break;
            case AGGR_TYPE_AVG:
            case AGGR_TYPE_CUME_DIST:
            case AGGR_TYPE_AVG_COLLECT:
                aggr_v->extra_offset = (uint32)(extras - (char *)aggr_v);
                aggr_v->extra_size = sizeof(aggr_avg_t);
                extras += sizeof(aggr_avg_t);
                break;
            case AGGR_TYPE_MIN:
            case AGGR_TYPE_MAX:
                if (CT_IS_VARLEN_TYPE(ass.aggr_node->datatype)) {
                    aggr_v->extra_offset = (uint32)(extras - (char *)aggr_v);
                    aggr_v->extra_size = sizeof(aggr_str_t);
                    extras += sizeof(aggr_str_t);
                }
                break;
            case AGGR_TYPE_MEDIAN:
                aggr_v->extra_offset = (uint32)(extras - (char *)aggr_v);
                aggr_v->extra_size = sizeof(aggr_median_t);
                extras += sizeof(aggr_median_t);
                break;
            case AGGR_TYPE_NONE:
            case AGGR_TYPE_SUM:
            case AGGR_TYPE_COUNT:
                break;
            default:
                break;
        }

        if (extras - (char *)vm_page->data > CT_VMEM_PAGE_SIZE) {
            CT_THROW_ERROR(ERR_TOO_MANY_ARRG);
            return CT_ERROR;
        }

        ass.aggr_type = func->aggr_type;
        CT_RETURN_IFERR(sql_aggr_init_var(&ass, aggr_v));
    }
    return CT_SUCCESS;
}

static inline status_t sql_alloc_hash_mtrl_ctx(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    uint32 key_card = sql_get_plan_hash_rows(stmt, plan);

    CT_RETURN_IFERR(sql_alloc_hash_group_ctx(stmt, cursor, plan, HASH_GROUP_TYPE, key_card));
    cursor->hash_mtrl_ctx->aggr_id = CT_INVALID_ID32;
    cursor->hash_mtrl_ctx->key_types = NULL;
    stmt->hash_mtrl_ctx_list[plan->hash_mtrl.hash_mtrl_id] = cursor->hash_mtrl_ctx;
    return CT_SUCCESS;
}

status_t sql_execute_hash_mtrl(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    if (stmt->hash_mtrl_ctx_list == NULL) {
        CT_RETURN_IFERR(vmc_alloc_mem(&stmt->vmc, sizeof(hash_mtrl_ctx_t *) * stmt->context->hash_mtrl_count,
            (void **)&stmt->hash_mtrl_ctx_list));
    } else if (HASH_MTRL_CONTEXT(cursor) == NULL && stmt->hash_mtrl_ctx_list[plan->hash_mtrl.hash_mtrl_id]) {
        HASH_MTRL_CONTEXT(cursor) = stmt->hash_mtrl_ctx_list[plan->hash_mtrl.hash_mtrl_id];
        HASH_MTRL_CONTEXT(cursor)->group_ctx.cursor = cursor;
    }

    if (HASH_MTRL_CONTEXT(cursor) == NULL) {
        CT_RETURN_IFERR(sql_alloc_hash_mtrl_ctx(stmt, cursor, plan));

        CT_RETURN_IFERR(sql_execute_query_plan(stmt, cursor, plan->hash_mtrl.group.next));

        CT_RETURN_IFERR(sql_hash_mtrl_build_hash_table(stmt, cursor, plan));

        /* init aggr default value */
        CT_RETURN_IFERR(sql_hash_mtrl_init_aggr_default(stmt, HASH_MTRL_CONTEXT(cursor), plan));
    }
    sql_hash_mtrl_open_cursor(cursor, HASH_MTRL_CONTEXT(cursor));
    return CT_SUCCESS;
}

status_t sql_fetch_hash_mtrl(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    if (!HASH_MTRL_CONTEXT(cursor)->fetched) {
        HASH_MTRL_CONTEXT(cursor)->fetched = CT_TRUE;
        return sql_hash_mtrl_fetch_cursor(stmt, cursor, plan, eof);
    }

    *eof = CT_TRUE;
    HASH_MTRL_TABLE_ITER->curr_match.vmid = CT_INVALID_ID32;
    return CT_SUCCESS;
}

void sql_free_hash_mtrl(sql_stmt_t *stmt)
{
    if (stmt->hash_mtrl_ctx_list == NULL) {
        return;
    }
    hash_mtrl_ctx_t *mtrl_ctx = NULL;
    for (uint32 i = 0; i < stmt->context->hash_mtrl_count; i++) {
        mtrl_ctx = stmt->hash_mtrl_ctx_list[i];
        if (mtrl_ctx == NULL) {
            continue;
        }
        if (mtrl_ctx->aggr_id != CT_INVALID_ID32) {
            vm_free(KNL_SESSION(stmt), KNL_SESSION(stmt)->temp_pool, mtrl_ctx->aggr_id);
            mtrl_ctx->aggr_id = CT_INVALID_ID32;
        }
        mtrl_ctx->key_types = NULL;
        mtrl_ctx->group_ctx.cursor = NULL;
        sql_free_group_ctx(stmt, &mtrl_ctx->group_ctx);
    }
    stmt->hash_mtrl_ctx_list = NULL;
}
