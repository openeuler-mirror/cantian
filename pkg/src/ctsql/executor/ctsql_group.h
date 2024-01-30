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
 * ctsql_group.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_group.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_GROUP_H__
#define __SQL_GROUP_H__

#include "dml_executor.h"
#include "ctsql_mtrl.h"

typedef struct st_sql_hash_group_row_attr {
    mtrl_rowid_t next_rid;
    uint16 key_row_size;
} sql_hash_group_row_attr_t;

#define SQL_HASH_GROUP_ROW_ATTR(row_buf) \
    (sql_hash_group_row_attr_t *)((row_buf) + ((row_head_t *)(row_buf))->size - sizeof(sql_hash_group_row_attr_t))
#define SQL_HASH_GROUP_AGGR_REMAIN_SIZE(hash_group_aggr) ((hash_group_aggr)->size - sizeof(sql_hash_group_aggr_t))

// str is the offset of a string's memory address,
// The reason the address cannot be recorded is that the memory to open the page may change
#define SQL_HASH_GROUP_AGGR_STR_ADDR(str) ((char *)&(str) + (uint64)(str))

#define HASH_GROUP_COL_COUNT 3
#define AGGR_BUF_SIZE_FACTOR 2

status_t sql_aggregate_group(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan);
status_t group_hash_i_oper_func(void *callback_ctx, const char *new_buf, uint32 new_size, const char *old_buf,
    uint32 old_size, bool32 found);
status_t group_hash_q_oper_func(void *callback_ctx, const char *new_buf, uint32 new_size, const char *old_buf,
    uint32 old_size, bool32 found);
status_t sql_init_group_exec_data(sql_stmt_t *stmt, sql_cursor_t *cursor, group_plan_t *group_p);
status_t sql_fetch_having(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);

status_t sql_execute_hash_group_new(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan_node);
status_t sql_fetch_hash_group_new(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);

status_t sql_make_hash_group_row_new(sql_stmt_t *stmt, group_ctx_t *group_ctx, uint32 group_id, char *buf, uint32 *size,
    uint32 *key_size, char *pending_buffer);
status_t sql_alloc_hash_group_ctx(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, group_type_t type,
    uint32 key_card);
void sql_free_group_ctx(sql_stmt_t *stmt, group_ctx_t *group_ctx);
status_t sql_calc_aggr_reserve_size(row_assist_t *ra, group_ctx_t *group_ctx, uint32 *size);
status_t sql_hash_group_save_aggr_str_value(group_ctx_t *ctx, aggr_var_t *old_aggr_var, variant_t *value);
status_t sql_group_mtrl_record_types(sql_cursor_t *cursor, plan_node_t *plan, char **buf);
status_t sql_group_re_calu_aggr(group_ctx_t *group_ctx, galist_t *aggrs);
status_t sql_hash_group_convert_rowid_to_str_row(group_ctx_t *ctx, sql_stmt_t *stmt, sql_cursor_t *cursor,
    galist_t *aggrs);
status_t sql_hash_group_make_sort_row(sql_stmt_t *stmt, expr_node_t *aggr_node, row_assist_t *ra, variant_t *value);
status_t sql_hash_group_mtrl_insert_row(sql_stmt_t *stmt, uint32 sort_seg, expr_node_t *aggr_node, aggr_var_t *var,
    char *row);
status_t sql_hash_group_calc_listagg(sql_stmt_t *stmt, sql_cursor_t *cursor, expr_node_t *aggr_node,
    aggr_var_t *aggr_var, text_buf_t *sort_concat);
status_t sql_hash_group_open_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, group_ctx_t *ctx, uint32 group_id);
status_t sql_mtrl_hash_group_new(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan);
status_t sql_hash_group_calc_median(sql_stmt_t *stmt, sql_cursor_t *cursor, expr_node_t *aggr_node,
    aggr_var_t *aggr_var);

static inline ct_type_t sql_group_pending_type(sql_cursor_t *cursor, uint32 id)
{
    mtrl_cursor_t *mtrl_cursor = &cursor->mtrl.cursor;
    char *pending_buf = (mtrl_cursor->type == MTRL_CURSOR_HASH_GROUP || mtrl_cursor->type == MTRL_CURSOR_SORT_GROUP) ?
        cursor->mtrl.group.buf :
        cursor->mtrl.rs.buf;
    if (mtrl_cursor->sort.segment != NULL && mtrl_cursor->sort.segment->type == MTRL_SEGMENT_WINSORT) {
        pending_buf = cursor->mtrl.winsort_rs.buf;
    }
    if (pending_buf != NULL && id < cursor->columns->count) {
        return ((ct_type_t *)(pending_buf + PENDING_HEAD_SIZE))[id];
    }
    return CT_TYPE_VARCHAR;
}

static inline status_t sql_get_group_value(sql_stmt_t *stmt, var_vm_col_t *v_vm_col, ct_type_t temp_type,
                                           bool8 is_array, variant_t *value)
{
    ct_type_t type = temp_type;
    sql_cursor_t *cursor = CTSQL_CURR_CURSOR(stmt);
    cursor = sql_get_group_cursor(cursor);

    CT_RETURN_IFERR(sql_get_ancestor_cursor(cursor, v_vm_col->ancestor, &cursor));
    mtrl_cursor_t *mtrl_cursor = &cursor->mtrl.cursor;

    if (SECUREC_UNLIKELY(type == CT_TYPE_UNKNOWN)) {
        type = sql_group_pending_type(cursor, v_vm_col->id);
    }

    if (mtrl_cursor->type == MTRL_CURSOR_HASH_DISTINCT) {
        return mtrl_get_column_value(&mtrl_cursor->distinct.row, mtrl_cursor->distinct.eof, v_vm_col->id, type,
            is_array, value);
    }
    mtrl_row_assist_t row_assist;
    mtrl_row_init(&row_assist, &mtrl_cursor->row);
    return mtrl_get_column_value(&row_assist, mtrl_cursor->eof, v_vm_col->id, type, is_array, value);
}

static inline status_t sql_cache_aggr_node(vmc_t *vmc, group_ctx_t *ctx)
{
    if (ctx->group_p->aggrs->count == 0) {
        ctx->aggr_node = NULL;
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(vmc_alloc(vmc, sizeof(expr_node_t *) * ctx->group_p->aggrs->count, (void **)&ctx->aggr_node));
    for (uint32 i = 0; i < ctx->group_p->aggrs->count; i++) {
        ctx->aggr_node[i] = (expr_node_t *)cm_galist_get(ctx->group_p->aggrs, i);
    }

    return CT_SUCCESS;
}

#endif
