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
 * ctsql_sort_group.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_sort_group.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_sort_group.h"
#include "ctsql_btree.h"
#include "ctsql_group.h"
#include "ctsql_select.h"
#include "ctsql_aggr.h"

static inline ct_type_t sql_get_group_expr_datatype(sql_cursor_t *cursor, uint32 col_id)
{
    expr_tree_t *expr = (expr_tree_t *)cm_galist_get(cursor->group_ctx->group_p->exprs, col_id);

    if (expr->root->datatype != CT_TYPE_UNKNOWN) {
        return expr->root->datatype;
    } else {
        return sql_get_pending_type(cursor->mtrl.group.buf, col_id);
    }
}

static inline int32 sql_sort_group_cmp_g(sql_cursor_t *cursor, mtrl_row_t *row1, mtrl_row_t *row2, uint32 col_id,
    const order_mode_t *order_mode)
{
    ct_type_t datatype = sql_get_group_expr_datatype(cursor, col_id);
    return sql_sort_mtrl_rows(row1, row2, col_id, datatype, order_mode);
}

static inline int32 sql_sort_group_cmp_i(sql_cursor_t *cursor, mtrl_row_t *row1, mtrl_row_t *row2, uint32 col_id)
{
    ct_type_t datatype = sql_get_group_expr_datatype(cursor, col_id);

    return sql_compare_data_ex(MT_CDATA(row1, col_id), MT_CSIZE(row1, col_id), MT_CDATA(row2, col_id),
        MT_CSIZE(row2, col_id), datatype);
}

static status_t sql_sort_group_cmp(int32 *result, void *callback_ctx, char *l_buf, uint32 lsize, char *r_buf,
    uint32 rsize)
{
    sql_cursor_t *cur = (sql_cursor_t *)callback_ctx;
    mtrl_row_t row1, row2;
    btree_sort_key_t *btree_sort_key = NULL;
    galist_t *sort_groups = cur->group_ctx->group_p->sort_groups;
    galist_t *group_exprs = cur->group_ctx->group_p->exprs;
    bool8 *already_cmp = NULL;
    uint32 need_size;

    row1.data = l_buf;
    cm_decode_row(l_buf, row1.offsets, row1.lens, NULL);
    row2.data = r_buf;
    cm_decode_row(r_buf, row2.offsets, row2.lens, NULL);

    need_size = group_exprs->count * sizeof(bool8);
    CT_RETURN_IFERR(sql_push(cur->stmt, need_size, (void **)&already_cmp));

    MEMS_RETURN_IFERR(memset_s(already_cmp, need_size, CT_FALSE, need_size));

    for (uint32 i = 0; i < sort_groups->count; ++i) {
        btree_sort_key = (btree_sort_key_t *)cm_galist_get(sort_groups, i);

        already_cmp[btree_sort_key->group_id] = CT_TRUE;
        *result = sql_sort_group_cmp_g(cur, &row1, &row2, btree_sort_key->group_id, &btree_sort_key->sort_mode);
        if (*result != 0) {
            CTSQL_POP(cur->stmt);
            return CT_SUCCESS;
        }
    }

    for (uint32 i = 0; i < group_exprs->count; ++i) {
        if (already_cmp[i]) {
            continue;
        }

        *result = sql_sort_group_cmp_i(cur, &row1, &row2, i);
        if (*result != 0) {
            CTSQL_POP(cur->stmt);
            return CT_SUCCESS;
        }
    }

    CTSQL_POP(cur->stmt);
    return CT_SUCCESS;
}

static inline status_t sql_sort_group_calc(void *callback_ctx, const char *new_buf, uint32 new_size,
    const char *old_buf, uint32 old_size, bool32 found)
{
    sql_cursor_t *cur = (sql_cursor_t *)callback_ctx;
    return group_hash_i_oper_func(cur->group_ctx, new_buf, new_size, old_buf, old_size, found);
}

static status_t sql_alloc_sort_group_ctx(sql_stmt_t *stmt, sql_cursor_t *cursor, group_plan_t *group_p,
    group_ctx_t **group_ctx)
{
    uint32 vmid;
    uint32 offset;
    vm_page_t *vm_page = NULL;
    knl_session_t *knl_session = KNL_SESSION(stmt);

    CT_RETURN_IFERR(sql_init_group_exec_data(stmt, cursor, group_p));
    CT_RETURN_IFERR(vm_alloc(knl_session, knl_session->temp_pool, &vmid));

    if (vm_open(knl_session, knl_session->temp_pool, vmid, &vm_page) != CT_SUCCESS) {
        vm_free(knl_session, knl_session->temp_pool, vmid);
        return CT_ERROR;
    }

    *group_ctx = (group_ctx_t *)vm_page->data;
    (*group_ctx)->type = SORT_GROUP_TYPE;
    (*group_ctx)->vm_id = vmid;
    (*group_ctx)->cursor = cursor;
    (*group_ctx)->stmt = stmt;
    (*group_ctx)->group_p = group_p;
    (*group_ctx)->str_aggr_page_count = 0;
    (*group_ctx)->group_by_phase = GROUP_BY_INIT;
    (*group_ctx)->hash_tables = NULL;
    (*group_ctx)->iters = NULL;
    (*group_ctx)->hash_dist_tables = NULL;
    (*group_ctx)->listagg_page = CT_INVALID_ID32;
    CM_INIT_TEXTBUF(&(*group_ctx)->concat_data, 0, NULL);
    (*group_ctx)->concat_typebuf = NULL;

    offset = sizeof(group_ctx_t);

    // buf for aggr_pages
    (*group_ctx)->str_aggr_pages = (uint32 *)((char *)vm_page->data + offset);
    offset += sizeof(uint32) * group_p->aggrs->count;

    // buf for aggr_value
    (*group_ctx)->str_aggr_val = (variant_t *)(vm_page->data + offset);
    offset += sizeof(variant_t) * (FO_VAL_MAX - 1);

    // buf for row_buf
    (*group_ctx)->row_buf = (char *)vm_page->data + offset;
    (*group_ctx)->row_buf_len = 0;

    mtrl_init_segment(&(*group_ctx)->extra_data, MTRL_SEGMENT_EXTRA_DATA, NULL);

    if (CT_VMEM_PAGE_SIZE - CT_MAX_ROW_SIZE < offset) {
        CT_THROW_ERROR(ERR_TOO_MANY_ARRG);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_cache_aggr_node(&stmt->vmc, *group_ctx));
    return sql_btree_init(&(*group_ctx)->btree_seg, stmt->session, knl_session->temp_pool, cursor, sql_sort_group_cmp,
        sql_sort_group_calc);
}

static status_t sql_mtrl_sort_group(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    bool32 eof = CT_FALSE;
    char *buf = NULL;
    status_t status;
    uint32 size;
    uint32 key_size;

    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));

    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buf));

    CTSQL_SAVE_STACK(stmt);
    for (;;) {
        if (sql_fetch_query(stmt, cursor, plan->group.next, &eof) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        if (eof) {
            status = CT_SUCCESS;
            break;
        }

        if (sql_make_hash_group_row_new(stmt, cursor->group_ctx, 0, buf, &size, &key_size, cursor->mtrl.group.buf) !=
            CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        cursor->group_ctx->oper_type = OPER_TYPE_INSERT;
        if (sql_btree_insert(&cursor->group_ctx->btree_seg, buf, size, key_size)) {
            status = CT_ERROR;
            break;
        }

        CTSQL_RESTORE_STACK(stmt);
    }
    CTSQL_RESTORE_STACK(stmt);
    CTSQL_POP(stmt);
    SQL_CURSOR_POP(stmt);
    CT_RETURN_IFERR(sql_free_query_mtrl(stmt, cursor, plan->group.next));
    return status;
}

status_t sql_execute_sort_group(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    CT_RETURN_IFERR(sql_execute_query_plan(stmt, cursor, plan->group.next));

    if (cursor->eof) {
        return CT_SUCCESS;
    }

    CM_ASSERT(cursor->group_ctx == NULL);
    CT_RETURN_IFERR(sql_alloc_sort_group_ctx(stmt, cursor, &plan->group, &cursor->group_ctx));

    if (cursor->select_ctx != NULL && cursor->select_ctx->pending_col_count > 0) {
        CT_RETURN_IFERR(sql_group_mtrl_record_types(cursor, plan, &cursor->mtrl.group.buf));
    }

    CT_RETURN_IFERR(sql_mtrl_sort_group(stmt, cursor, plan));

    if (cursor->eof) {
        return CT_SUCCESS;
    }

    cursor->group_ctx->oper_type = OPER_TYPE_FETCH;
    return sql_btree_open(&cursor->group_ctx->btree_seg, &cursor->group_ctx->btree_cursor);
}

status_t sql_fetch_sort_group(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    sql_btree_row_t *btree_row = NULL;
    mtrl_cursor_t *mtrl_cursor = NULL;

    CT_RETURN_IFERR(sql_btree_fetch(&cursor->group_ctx->btree_seg, &cursor->group_ctx->btree_cursor, eof));
    if (*eof) {
        return CT_SUCCESS;
    }

    btree_row = cursor->group_ctx->btree_cursor.btree_row;

    mtrl_cursor = &cursor->mtrl.cursor;
    mtrl_cursor->eof = CT_FALSE;
    mtrl_cursor->type = MTRL_CURSOR_SORT_GROUP;
    mtrl_cursor->row.data = btree_row->data;
    cm_decode_row(mtrl_cursor->row.data, mtrl_cursor->row.offsets, mtrl_cursor->row.lens, NULL);
    mtrl_cursor->hash_group.aggrs = mtrl_cursor->row.data + btree_row->key_size;
    CT_RETURN_IFERR(sql_hash_group_convert_rowid_to_str_row(cursor->group_ctx, cursor->stmt, cursor,
        cursor->group_ctx->group_p->aggrs));
    return sql_group_re_calu_aggr(cursor->group_ctx, plan->group.aggrs);
}

static status_t sql_mtrl_merge_sort_group(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    bool32 eof = CT_FALSE;
    char *buf = NULL;
    mtrl_rowid_t rid;
    status_t status;

    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));

    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buf));

    CTSQL_SAVE_STACK(stmt);
    for (;;) {
        if (sql_fetch_query(stmt, cursor, plan->group.next, &eof) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            status = CT_ERROR;
            break;
        }

        if (eof) {
            CTSQL_RESTORE_STACK(stmt);
            status = CT_SUCCESS;
            break;
        }

        if (sql_make_mtrl_group_row(stmt, cursor->mtrl.group.buf, &plan->group, buf) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            status = CT_ERROR;
            break;
        }

        if (mtrl_insert_row(&stmt->mtrl, cursor->mtrl.group.sid, buf, &rid) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            status = CT_ERROR;
            break;
        }

        CTSQL_RESTORE_STACK(stmt);
    }
    CTSQL_POP(stmt);
    SQL_CURSOR_POP(stmt);
    return status;
}

status_t sql_execute_merge_sort_group(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    status_t status = CT_ERROR;
    CT_RETURN_IFERR(sql_init_group_exec_data(stmt, cursor, &plan->group));

    do {
        CT_BREAK_IF_ERROR(sql_execute_query_plan(stmt, cursor, plan->group.next));
        if (cursor->eof) {
            status = CT_SUCCESS;
            break;
        }

        CT_BREAK_IF_ERROR(mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_AGGR, NULL, &cursor->mtrl.aggr));

        CT_BREAK_IF_ERROR(
            mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_GROUP, (handle_t)plan->group.exprs, &cursor->mtrl.group.sid));

        if (cursor->select_ctx != NULL && cursor->select_ctx->pending_col_count > 0) {
            CT_BREAK_IF_ERROR(sql_group_mtrl_record_types(cursor, plan, &cursor->mtrl.group.buf));
        }
        cursor->mtrl.cursor.type = MTRL_CURSOR_OTHERS;
        CT_BREAK_IF_ERROR(mtrl_open_segment(&stmt->mtrl, cursor->mtrl.aggr));
        CT_BREAK_IF_ERROR(sql_init_aggr_page(stmt, cursor, plan->group.aggrs));

        if (mtrl_open_segment(&stmt->mtrl, cursor->mtrl.group.sid) != CT_SUCCESS) {
            mtrl_close_segment(&stmt->mtrl, cursor->mtrl.aggr);
            mtrl_release_segment(&stmt->mtrl, cursor->mtrl.aggr);
            cursor->mtrl.aggr = CT_INVALID_ID32;
            break;
        }

        if (sql_mtrl_merge_sort_group(stmt, cursor, plan) != CT_SUCCESS) {
            mtrl_close_segment(&stmt->mtrl, cursor->mtrl.aggr);
            mtrl_release_segment(&stmt->mtrl, cursor->mtrl.aggr);
            cursor->mtrl.aggr = CT_INVALID_ID32;
            mtrl_close_segment(&stmt->mtrl, cursor->mtrl.group.sid);
            break;
        }

        mtrl_close_segment(&stmt->mtrl, cursor->mtrl.group.sid);

        if (cursor->eof) {
            status = CT_SUCCESS;
            break;
        }
        CT_RETURN_IFERR(mtrl_sort_segment(&stmt->mtrl, cursor->mtrl.group.sid));

        if (mtrl_open_cursor(&stmt->mtrl, cursor->mtrl.group.sid, &cursor->mtrl.cursor) != CT_SUCCESS) {
            mtrl_close_segment(&stmt->mtrl, cursor->mtrl.aggr);
            mtrl_release_segment(&stmt->mtrl, cursor->mtrl.aggr);
            cursor->mtrl.aggr = CT_INVALID_ID32;
            break;
        }
        status = CT_SUCCESS;
    } while (0);

    CT_RETURN_IFERR(sql_free_query_mtrl(stmt, cursor, plan->group.next));
    return status;
}

status_t sql_fetch_merge_sort_group(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    uint32 rows, avgs;
    bool32 group_changed = CT_FALSE;

    rows = 0;

    if (cursor->mtrl.cursor.eof) {
        *eof = CT_TRUE;
        return CT_SUCCESS;
    }

    cursor->mtrl.cursor.type = MTRL_CURSOR_OTHERS;
    CT_RETURN_IFERR(sql_init_aggr_values(stmt, cursor, plan->group.next, plan->group.aggrs, &avgs));

    while (!group_changed) {
        if (mtrl_fetch_group(&stmt->mtrl, &cursor->mtrl.cursor, &group_changed) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cursor->mtrl.cursor.eof) {
            break;
        }
        rows++;
        if (sql_aggregate_group(stmt, cursor, plan) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (avgs > 0 && rows > 0) {
        CT_RETURN_IFERR(sql_exec_aggr(stmt, cursor, plan->group.aggrs, plan));
    }

    *eof = cursor->mtrl.cursor.eof;
    return CT_SUCCESS;
}