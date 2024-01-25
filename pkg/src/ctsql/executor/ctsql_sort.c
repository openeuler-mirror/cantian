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
 * ctsql_sort.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_sort.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_sort.h"
#include "ctsql_mtrl.h"
#include "ctsql_select.h"
#include "srv_instance.h"
#include "knl_mtrl.h"

status_t sql_fetch_sort(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    if (mtrl_fetch_sort(&stmt->mtrl, &cursor->mtrl.cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    *eof = cursor->mtrl.cursor.eof;
    return CT_SUCCESS;
}

static status_t sql_cmp_with_top_row(mtrl_context_t *ctx, uint32 seg_id, mtrl_rowid_list_t *rowid_list, char *sort_row,
    bool32 *candidate)
{
    *candidate = CT_TRUE;
    if (rowid_list->row_cnt < rowid_list->max_row) {
        return CT_SUCCESS;
    }
    mtrl_segment_t *seg = ctx->segments[seg_id];
    mtrl_rowid_t top_rid = rowid_list->rid[rowid_list->max_row - 1];
    vm_page_t *tmp_page = seg->curr_page;
    mtrl_page_t *page = NULL;
    char *cmp_row = NULL;
    int32 res;
    status_t status;

    if (tmp_page->vmid != top_rid.vmid) {
        CT_RETURN_IFERR(vm_open(ctx->session, ctx->pool, top_rid.vmid, &tmp_page));
    }
    page = (mtrl_page_t *)tmp_page->data;
    cmp_row = MTRL_GET_ROW(page, top_rid.slot);

    status = ctx->sort_cmp(seg, sort_row, cmp_row, &res);
    if (status == CT_SUCCESS && res >= 0) {
        *candidate = CT_FALSE;
    }
    if (tmp_page->vmid != seg->curr_page->vmid) {
        vm_close(ctx->session, ctx->pool, tmp_page->vmid, VM_ENQUE_TAIL);
    }

    return status;
}

static status_t sql_make_query_sort_row(char *sort_buf, mtrl_rowid_t rid)
{
    row_head_t *row = (row_head_t *)sort_buf;
    if (row->size + sizeof(mtrl_rowid_t) > CT_MAX_ROW_SIZE) {
        CT_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, row->size + sizeof(mtrl_rowid_t), CT_MAX_ROW_SIZE);
        return CT_ERROR;
    }
    *(mtrl_rowid_t *)(sort_buf + row->size) = rid;
    row->size += sizeof(mtrl_rowid_t);
    return CT_SUCCESS;
}

static status_t mtrl_get_sort_pos(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_rowid_list_t *rowid_list, char *row,
    uint32 *pos)
{
    if (rowid_list->row_cnt == 0) {
        *pos = 0;
        return CT_SUCCESS;
    }
    uint32 begin = 0;
    uint32 end = rowid_list->row_cnt - 1;
    uint32 curr = 0;
    mtrl_rowid_t cmp_rid = rowid_list->rid[end];
    int32 res;
    vm_page_t *temp_page = NULL;
    mtrl_page_t *page = NULL;

    CT_RETURN_IFERR(vm_open(ctx->session, ctx->pool, cmp_rid.vmid, &temp_page));
    page = (mtrl_page_t *)temp_page->data;

    char *cmp_row = MTRL_GET_ROW(page, cmp_rid.slot);

    if (ctx->sort_cmp(segment, row, cmp_row, &res) != CT_SUCCESS) {
        vm_close(ctx->session, ctx->pool, temp_page->vmid, VM_ENQUE_TAIL);
        return CT_ERROR;
    }

    if (res >= 0) {
        *pos = rowid_list->row_cnt;
        vm_close(ctx->session, ctx->pool, temp_page->vmid, VM_ENQUE_TAIL);
        return CT_SUCCESS;
    }
    while (begin < end) {
        curr = (end + begin) >> 1;
        cmp_rid = rowid_list->rid[curr];
        if (temp_page->vmid != cmp_rid.vmid) {
            vm_close(ctx->session, ctx->pool, temp_page->vmid, VM_ENQUE_TAIL);
            CT_RETURN_IFERR(vm_open(ctx->session, ctx->pool, cmp_rid.vmid, &temp_page));
            page = (mtrl_page_t *)temp_page->data;
        }
        cmp_row = MTRL_GET_ROW(page, cmp_rid.slot);
        if (ctx->sort_cmp(segment, row, cmp_row, &res) != CT_SUCCESS) {
            vm_close(ctx->session, ctx->pool, temp_page->vmid, VM_ENQUE_TAIL);
            return CT_ERROR;
        }
        CT_BREAK_IF_TRUE(res == 0);

        if (res < 0) {
            end = curr;
        } else {
            begin = curr + 1;
        }
    }
    *pos = res >= 0 ? curr + 1 : curr;
    vm_close(ctx->session, ctx->pool, temp_page->vmid, VM_ENQUE_TAIL);
    return CT_SUCCESS;
}

static status_t sql_save_result_into_page(mtrl_context_t *ctx, uint32 seg_id, mtrl_rowid_list_t *rowid_list)
{
    mtrl_segment_t *seg = ctx->segments[seg_id];
    id_list_t ori_list = seg->vm_list;
    mtrl_page_t *page = NULL;
    mtrl_page_t *ori_page = NULL;
    vm_page_t *tmp_page = NULL;
    char *sort_row = NULL;
    mtrl_rowid_t rowid;
    status_t status = CT_ERROR;

    if (rowid_list->row_cnt == 0) {
        return CT_SUCCESS;
    }

    mtrl_close_segment(ctx, seg_id);

    do {
        seg->vm_list.count = 0;
        CT_BREAK_IF_ERROR(mtrl_extend_segment(ctx, seg));
        CT_BREAK_IF_ERROR(mtrl_open_page(ctx, seg->vm_list.first, &seg->curr_page));
        page = (mtrl_page_t *)seg->curr_page->data;
        mtrl_init_page(page, seg->vm_list.first);

        CT_BREAK_IF_ERROR(vm_open(ctx->session, ctx->pool, rowid_list->rid[0].vmid, &tmp_page));
        ori_page = (mtrl_page_t *)tmp_page->data;

        handle_t cmp_items = seg->cmp_items;
        seg->cmp_items = NULL;
        for (uint32 i = 0; i < rowid_list->row_cnt; i++) {
            rowid = rowid_list->rid[i];
            if (rowid.vmid != tmp_page->vmid) {
                if (vm_open(ctx->session, ctx->pool, rowid.vmid, &tmp_page) != CT_SUCCESS) {
                    vm_free_list(ctx->session, ctx->pool, &ori_list);
                    return CT_ERROR;
                }
                ori_page = (mtrl_page_t *)tmp_page->data;
            }
            sort_row = MTRL_GET_ROW(ori_page, rowid.slot);
            if (mtrl_insert_row(ctx, seg_id, sort_row, &rowid) != CT_SUCCESS) {
                vm_free_list(ctx->session, ctx->pool, &ori_list);
                return CT_ERROR;
            }
            rowid_list->rid[i] = rowid;
        }
        seg->cmp_items = cmp_items;
        status = CT_SUCCESS;
    } while (0);

    CT_LOG_DEBUG_INF("shrink vm page: original num %u, current num %u", ori_list.count, seg->vm_list.count);
    vm_free_list(ctx->session, ctx->pool, &ori_list);
    return status;
}

static status_t sql_mtrl_insert_sort_row(mtrl_context_t *ctx, uint32 seg_id, char *row, mtrl_rowid_t rs_rid,
    mtrl_rowid_list_t *rowid_list)
{
    mtrl_rowid_t rid;
    uint32 pos;
    mtrl_segment_t *seg = ctx->segments[seg_id];
    uint32 copy_size, max_size, row_size;
    double utilization;

    CT_RETURN_IFERR(sql_make_query_sort_row(row, rs_rid));
    handle_t cmp_items = seg->cmp_items;
    seg->cmp_items = NULL;
    CT_RETURN_IFERR(mtrl_insert_row(ctx, seg_id, row, &rid));
    seg->cmp_items = cmp_items;
    CT_RETURN_IFERR(mtrl_get_sort_pos(ctx, seg, rowid_list, row, &pos));

    if (pos == rowid_list->row_cnt && rowid_list->row_cnt < rowid_list->max_row) {
        rowid_list->rid[rowid_list->row_cnt++] = rid;
        return CT_SUCCESS;
    }
    copy_size = (rowid_list->row_cnt - pos) * sizeof(mtrl_rowid_t);
    max_size = (rowid_list->max_row - pos - 1) * sizeof(mtrl_rowid_t);
    if (rowid_list->row_cnt < rowid_list->max_row) {
        rowid_list->row_cnt++;
    } else {
        copy_size = max_size;
    }

    if (max_size != 0) {
        MEMS_RETURN_IFERR(memmove_s(&rowid_list->rid[pos + 1], max_size, &rowid_list->rid[pos], copy_size));
    }
    rowid_list->rid[pos] = rid;

    row_size = (uint32)((row_head_t *)row)->size * rowid_list->max_row;
    utilization = (double)(row_size / CT_VMEM_PAGE_SIZE + 1) / seg->vm_list.count;
    // when vm utilization is less than 0.1, need to compress the memory
    if (utilization < 0.1) {
        CT_RETURN_IFERR(sql_save_result_into_page(ctx, seg_id, rowid_list));
    }
    return CT_SUCCESS;
}

static inline status_t sql_insert_sort_row(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, char *buf,
    char *sort_buf, mtrl_rowid_list_t *rowid_list)
{
    mtrl_rowid_t rid;

    CT_RETURN_IFERR(sql_make_mtrl_rs_row(stmt, cursor->mtrl.rs.buf, plan->query_sort.select_columns, buf));

    CT_RETURN_IFERR(mtrl_insert_row(&stmt->mtrl, cursor->mtrl.rs.sid, buf, &rid));

    CT_RETURN_IFERR(sql_mtrl_insert_sort_row(&stmt->mtrl, cursor->mtrl.sort.sid, sort_buf, rid, rowid_list));

    return CT_SUCCESS;
}

static inline status_t judge_row_is_candidate(sql_stmt_t *stmt, sql_cursor_t *cursor, galist_t *sort_items,
    char *sort_buf, mtrl_rowid_list_t *rowid_list, bool32 *candidate)
{
    row_assist_t ra;

    row_init(&ra, sort_buf, CT_MAX_ROW_SIZE, sort_items->count);

    CT_RETURN_IFERR(sql_make_mtrl_sort_row(stmt, cursor->mtrl.sort.buf, sort_items, &ra));

    CT_RETURN_IFERR(sql_cmp_with_top_row(&stmt->mtrl, cursor->mtrl.sort.sid, rowid_list, sort_buf, candidate));

    return CT_SUCCESS;
}

static status_t sql_mtrl_query_sort_by_rownum(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    bool32 eof = CT_FALSE;
    char *buf = NULL;
    char *s_buf = NULL;
    status_t status = CT_ERROR;
    mtrl_rowid_list_t *rowid_list = NULL;
    bool32 candidate = CT_TRUE;

    if (plan->query_sort.rownum_upper == 0) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }
    uint32 size = sizeof(mtrl_rowid_t) * plan->query_sort.rownum_upper + sizeof(mtrl_rowid_list_t);
    CTSQL_SAVE_STACK(stmt);
    CT_RETURN_IFERR(sql_push(stmt, size, (void **)&rowid_list));
    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buf));
    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&s_buf));
    rowid_list->row_cnt = 0;
    rowid_list->max_row = plan->query_sort.rownum_upper;

    for (;;) {
        CTSQL_SAVE_STACK(stmt);
        if (sql_fetch_query(stmt, cursor, plan->query_sort.next, &eof) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            break;
        }

        if (eof) {
            CTSQL_RESTORE_STACK(stmt);
            status = CT_SUCCESS;
            break;
        }

        if (judge_row_is_candidate(stmt, cursor, plan->query_sort.items, s_buf, rowid_list, &candidate) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            break;
        }

        if (!candidate) {
            CTSQL_RESTORE_STACK(stmt);
            continue;
        }

        if (sql_insert_sort_row(stmt, cursor, plan, buf, s_buf, rowid_list) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            break;
        }
        CTSQL_RESTORE_STACK(stmt);
    }
    if (status == CT_SUCCESS) {
        status = sql_save_result_into_page(&stmt->mtrl, cursor->mtrl.sort.sid, rowid_list);
    }
    CTSQL_RESTORE_STACK(stmt);
    CT_RETURN_IFERR(sql_free_query_mtrl(stmt, cursor, plan->query_sort.next));
    return status;
}

status_t sql_mtrl_query_sort(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    bool32 eof = CT_FALSE;
    char *buf = NULL;
    mtrl_rowid_t rid;
    status_t status = CT_SUCCESS;

    if (plan->query_sort.rownum_upper <= g_instance->sql.topn_threshold && g_instance->sql.topn_threshold != 0) {
        mtrl_reset_sort_type(&stmt->mtrl, cursor->mtrl.sort.sid);
        return sql_mtrl_query_sort_by_rownum(stmt, cursor, plan);
    }

    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buf));

    for (;;) {
        CTSQL_SAVE_STACK(stmt);
        if (sql_fetch_query(stmt, cursor, plan->query_sort.next, &eof) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            status = CT_ERROR;
            break;
        }

        if (eof) {
            CTSQL_RESTORE_STACK(stmt);
            break;
        }

        if (sql_make_mtrl_rs_row(stmt, cursor->mtrl.rs.buf, plan->query_sort.select_columns, buf) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            status = CT_ERROR;
            break;
        }

        if (mtrl_insert_row(&stmt->mtrl, cursor->mtrl.rs.sid, buf, &rid) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            status = CT_ERROR;
            break;
        }

        if (sql_make_mtrl_query_sort_row(stmt, cursor->mtrl.sort.buf, plan->query_sort.items, &rid, buf) !=
            CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            status = CT_ERROR;
            break;
        }

        if (mtrl_insert_row(&stmt->mtrl, cursor->mtrl.sort.sid, buf, &rid) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            status = CT_ERROR;
            break;
        }
        CTSQL_RESTORE_STACK(stmt);
    }
    CTSQL_POP(stmt);
    CT_RETURN_IFERR(sql_free_query_mtrl(stmt, cursor, plan->query_sort.next));
    return status;
}

static status_t sql_mtrl_select_sort(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_cursor_t *sub_cursor,
    plan_node_t *plan)
{
    bool32 eof = CT_FALSE;
    char *buf = NULL;
    mtrl_rowid_t rid;
    status_t status = CT_SUCCESS;

    if (cursor->exec_data.select_limit != NULL) {
        mtrl_reset_sort_type(&stmt->mtrl, cursor->mtrl.sort.sid);
    }
    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, sub_cursor));

    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buf));

    for (;;) {
        CTSQL_SAVE_STACK(stmt);
        if (sql_fetch_cursor(stmt, sub_cursor, plan->select_sort.next, &eof) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            status = CT_ERROR;
            break;
        }

        if (eof) {
            CTSQL_RESTORE_STACK(stmt);
            break;
        }

        if (sql_make_mtrl_rs_row(stmt, sub_cursor->mtrl.rs.buf, sub_cursor->columns, buf) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            status = CT_ERROR;
            break;
        }

        if (mtrl_insert_row(&stmt->mtrl, cursor->mtrl.rs.sid, buf, &rid) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            status = CT_ERROR;
            break;
        }

        if (sql_make_mtrl_select_sort_row(stmt, sub_cursor->mtrl.rs.buf, sub_cursor, plan->select_sort.items, &rid,
            buf) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            status = CT_ERROR;
            break;
        }

        if (mtrl_insert_row(&stmt->mtrl, cursor->mtrl.sort.sid, buf, &rid) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            status = CT_ERROR;
            break;
        }
        CTSQL_RESTORE_STACK(stmt);
    }

    CTSQL_POP(stmt);
    SQL_CURSOR_POP(stmt);
    CT_RETURN_IFERR(sql_free_query_mtrl(stmt, cursor, plan->select_sort.next));
    return status;
}

status_t sql_sort_mtrl_record_types(vmc_t *vmc, mtrl_segment_type_t sort_type, galist_t *cmp_items, char **buf)
{
    uint32 i;
    ct_type_t *types = NULL;
    ct_type_t data_type;
    sort_item_t *item = NULL;
    select_sort_item_t *sort_item = NULL;
    rs_column_t *column = NULL;
    expr_tree_t *expr = NULL;

    if (*buf == NULL) {
        uint32 mem_cost_size = cmp_items->count * sizeof(ct_type_t);
        mem_cost_size += sizeof(uint32);
        CT_RETURN_IFERR(vmc_alloc(vmc, mem_cost_size, (void **)buf));
        *(uint32 *)(*buf) = mem_cost_size;
    }

    types = (ct_type_t *)(*buf + sizeof(uint32));

    for (i = 0; i < cmp_items->count; i++) {
        switch (sort_type) {
            case MTRL_SEGMENT_QUERY_SORT:
            case MTRL_SEGMENT_CONCAT_SORT:
            case MTRL_SEGMENT_SIBL_SORT:
                item = (sort_item_t *)cm_galist_get(cmp_items, i);
                expr = item->expr;
                data_type = expr->root->datatype;
                break;

            case MTRL_SEGMENT_SELECT_SORT:
                sort_item = (select_sort_item_t *)cm_galist_get(cmp_items, i);
                data_type = sort_item->datatype;
                break;

            case MTRL_SEGMENT_DISTINCT:
            case MTRL_SEGMENT_RS:
                column = (rs_column_t *)cm_galist_get(cmp_items, i);
                data_type = column->datatype;
                break;

            default:
                expr = (expr_tree_t *)cm_galist_get(cmp_items, i);
                data_type = expr->root->datatype;
                break;
        }

        types[i] = data_type;
    }

    return CT_SUCCESS;
}

status_t sql_sort_mtrl_open_segment(sql_stmt_t *stmt, sql_cursor_t *cursor, mtrl_segment_type_t sort_type,
    galist_t *cmp_items)
{
    if (mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_RS, NULL, &cursor->mtrl.rs.sid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (mtrl_create_segment(&stmt->mtrl, sort_type, (handle_t)cmp_items, &cursor->mtrl.sort.sid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (mtrl_open_segment(&stmt->mtrl, cursor->mtrl.rs.sid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (mtrl_open_segment(&stmt->mtrl, cursor->mtrl.sort.sid) != CT_SUCCESS) {
        mtrl_close_segment(&stmt->mtrl, cursor->mtrl.rs.sid);
        return CT_ERROR;
    }

    if (cursor->select_ctx != NULL && cursor->select_ctx->pending_col_count > 0) {
        CT_RETURN_IFERR(sql_sort_mtrl_record_types(&cursor->vmc, sort_type, cmp_items, &cursor->mtrl.sort.buf));
        stmt->mtrl.segments[cursor->mtrl.sort.sid]->pending_type_buf = cursor->mtrl.sort.buf;
    }

    return CT_SUCCESS;
}

void sql_sort_mtrl_close_segment(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    if (cursor->mtrl.rs.sid != CT_INVALID_ID32) {
        mtrl_close_segment(&stmt->mtrl, cursor->mtrl.rs.sid);
    }
    if (cursor->mtrl.sort.sid != CT_INVALID_ID32) {
        mtrl_close_segment(&stmt->mtrl, cursor->mtrl.sort.sid);
    }
}

void sql_sort_mtrl_release_segment(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    CTSQL_RELEASE_SEGMENT(stmt, cursor->mtrl.rs.sid);
    CTSQL_RELEASE_SEGMENT(stmt, cursor->mtrl.sort.sid);
}

status_t sql_execute_select_sort(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    sql_cursor_t *sub_cur = NULL;
    uint32 mem_size;
#ifdef TIME_STATISTIC
    clock_t start;
    double timeuse;
    start = cm_cal_time_bengin();
#endif

    sql_open_select_cursor(stmt, cursor, plan->select_sort.rs_columns);

    // order by for select,e.g. select ..union all select ... order by ...
    if (sql_alloc_cursor(stmt, &sub_cur) != CT_SUCCESS) {
        return CT_ERROR;
    }
    sub_cur->scn = cursor->scn;
    sub_cur->ancestor_ref = cursor->ancestor_ref;

    if (sql_execute_select_plan(stmt, sub_cur, plan->select_sort.next) != CT_SUCCESS) {
        sql_free_cursor(stmt, sub_cur);
        return CT_ERROR;
    }

    if (sql_sort_mtrl_open_segment(stmt, cursor, MTRL_SEGMENT_SELECT_SORT, plan->select_sort.items) != CT_SUCCESS) {
        sql_free_cursor(stmt, sub_cur);
        return CT_ERROR;
    }

    if (sql_mtrl_select_sort(stmt, cursor, sub_cur, plan) != CT_SUCCESS) {
        sql_sort_mtrl_close_segment(stmt, cursor);
        sql_free_cursor(stmt, sub_cur);
        return CT_ERROR;
    }
    sql_sort_mtrl_close_segment(stmt, cursor);

    if (cursor->mtrl.rs.buf == NULL && sub_cur->mtrl.rs.buf != NULL) {
        mem_size = *(uint32 *)sub_cur->mtrl.rs.buf;
        CT_RETURN_IFERR(vmc_alloc(&cursor->vmc, mem_size, (void **)&cursor->mtrl.rs.buf));
        MEMS_RETURN_IFERR(memcpy_s(cursor->mtrl.rs.buf, mem_size, sub_cur->mtrl.rs.buf, mem_size));
    }
    sql_free_cursor(stmt, sub_cur);

    if (mtrl_sort_segment(&stmt->mtrl, cursor->mtrl.sort.sid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (mtrl_open_cursor(&stmt->mtrl, cursor->mtrl.sort.sid, &cursor->mtrl.cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

#ifdef TIME_STATISTIC
    timeuse = cm_cal_time_end(start);
    stmt->mt_time += timeuse;
#endif
    return CT_SUCCESS;
}

status_t sql_execute_query_sort(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    status_t status = CT_ERROR;

#ifdef TIME_STATISTIC
    clock_t start;
    double timeuse;
    start = cm_cal_time_bengin();
#endif

    do {
        CT_BREAK_IF_ERROR(sql_execute_query_plan(stmt, cursor, plan->query_sort.next));
        if (cursor->eof) {
            status = CT_SUCCESS;
            break;
        }

        CT_BREAK_IF_ERROR(sql_sort_mtrl_open_segment(stmt, cursor, MTRL_SEGMENT_QUERY_SORT, plan->query_sort.items));

        if (sql_mtrl_query_sort(stmt, cursor, plan) != CT_SUCCESS) {
            sql_sort_mtrl_close_segment(stmt, cursor);
            break;
        }
        sql_sort_mtrl_close_segment(stmt, cursor);

        if (cursor->eof) {
            status = CT_SUCCESS;
            break;
        }

        CT_BREAK_IF_ERROR(mtrl_sort_segment(&stmt->mtrl, cursor->mtrl.sort.sid));

        CT_BREAK_IF_ERROR(mtrl_open_cursor(&stmt->mtrl, cursor->mtrl.sort.sid, &cursor->mtrl.cursor));

        status = CT_SUCCESS;
    } while (0);

#ifdef TIME_STATISTIC
    timeuse = cm_cal_time_end(start);
    stmt->mt_time += timeuse;
#endif
    return status;
}

status_t sql_put_sort_row(sql_stmt_t *stmt, sql_cursor_t *cursor, bool32 *is_full)
{
    char *row = cursor->mtrl.cursor.row.data;
    CT_RETURN_IFERR(my_sender(stmt)->send_row_data(stmt, row, is_full));
    sql_inc_rows(stmt, cursor);
    return CT_SUCCESS;
}

status_t sql_alloc_mtrl_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, mtrl_cursor_t **mtrl_cursor, mtrl_rowid_t *rid)
{
    if (cursor->mtrl.sibl_sort.cursor_sid == CT_INVALID_ID32) {
        CT_RETURN_IFERR(
            mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_SIBL_SORT, NULL, &cursor->mtrl.sibl_sort.cursor_sid));
        CT_RETURN_IFERR(mtrl_open_segment(&stmt->mtrl, cursor->mtrl.sibl_sort.cursor_sid));
    }
    CT_RETURN_IFERR(sql_alloc_mem_from_seg(stmt, stmt->mtrl.segments[cursor->mtrl.sibl_sort.cursor_sid],
        sizeof(mtrl_cursor_t), (void **)mtrl_cursor, rid));
    MEMS_RETURN_IFERR(memset_s((*mtrl_cursor), sizeof(mtrl_cursor_t), 0, sizeof(mtrl_cursor_t)));
    return CT_SUCCESS;
}

/* deep recursive traversal:
 * 1.if next_level_cursor is not eof, fetch from next_level_cursor and return.
   2.if curr_level_cursor is eof, fetch from pre_level_cursor and return.
   3.fetch from curr_level_cursor, if fetched row is a non-leaf node, sort its sub-segment and open next_level_cursor.
 */
status_t sql_fetch_sibl_sort_one_record(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    sibl_sort_row_t sibl_row;
    mtrl_segment_t *seg = NULL;
    mtrl_cursor_t *curr_cur = NULL;
    mtrl_cursor_t *next_cur = NULL;
    mtrl_cursor_t *pre_cur = NULL;
    mtrl_rowid_t next_cursor_rid;
    mtrl_rowid_t pre_cursor_rid;
    vm_page_t *page = NULL;

    CT_RETURN_IFERR(sql_stack_safe(stmt));
    CT_RETURN_IFERR(sql_get_mtrl_cursor(stmt, cursor, &cursor->mtrl.cursor.curr_cursor_rid, &curr_cur));
    next_cursor_rid = curr_cur->next_cursor_rid;
    pre_cursor_rid = curr_cur->pre_cursor_rid;
    CT_RETURN_IFERR(sql_get_mtrl_cursor(stmt, cursor, &next_cursor_rid, &next_cur));
    if (next_cur != NULL && !next_cur->eof) {
        cursor->mtrl.cursor.curr_cursor_rid = next_cursor_rid;
        return sql_fetch_sibl_sort_one_record(stmt, cursor);
    }
    CT_RETURN_IFERR(sql_get_mtrl_cursor(stmt, cursor, &cursor->mtrl.cursor.curr_cursor_rid, &curr_cur));
    CT_RETURN_IFERR(mtrl_fetch_sibl_sort(&stmt->mtrl, &cursor->mtrl.cursor, curr_cur, &sibl_row));
    if (curr_cur->eof) {
        CT_RETURN_IFERR(sql_get_mtrl_cursor(stmt, cursor, &pre_cursor_rid, &pre_cur));
        if (pre_cur == NULL) {
            cursor->mtrl.cursor.eof = CT_TRUE;
            return CT_SUCCESS;
        }
        // re-open the parent segment when returning to the parent node
        if (mtrl_open_page(&stmt->mtrl, pre_cur->sort.vmid, &page) != CT_SUCCESS) {
            return CT_ERROR;
        }
        pre_cur->sort.page = (mtrl_page_t *)page->data;
        cursor->mtrl.cursor.curr_cursor_rid = pre_cursor_rid;
        return sql_fetch_sibl_sort_one_record(stmt, cursor);
    }

    if (sibl_row.child_seg_rid.vmid != CT_INVALID_ID32) {
        if (next_cursor_rid.vmid == CT_INVALID_ID32) {
            CT_RETURN_IFERR(sql_alloc_mtrl_cursor(stmt, cursor, &next_cur, &next_cursor_rid));
        } else {
            CT_RETURN_IFERR(sql_get_mtrl_cursor(stmt, cursor, &next_cursor_rid, &next_cur));
        }
        CT_RETURN_IFERR(sql_get_segment_in_vm(stmt, cursor->mtrl.sibl_sort.sid, &sibl_row.child_seg_rid, &seg));
        CT_RETURN_IFERR(mtrl_sort_segment2(&stmt->mtrl, seg));
        if (mtrl_open_cursor2(&stmt->mtrl, seg, next_cur) != CT_SUCCESS) {
            return CT_ERROR;
        }
        next_cur->pre_cursor_rid = cursor->mtrl.cursor.curr_cursor_rid;
        CT_RETURN_IFERR(sql_get_mtrl_cursor(stmt, cursor, &cursor->mtrl.cursor.curr_cursor_rid, &curr_cur));
        curr_cur->next_cursor_rid = next_cursor_rid;
        // close the parent segment when opening the sub-segment
        mtrl_close_page(&stmt->mtrl, curr_cur->sort.vmid);
    }
    if (!sibl_row.match_filter) {
        return sql_fetch_sibl_sort_one_record(stmt, cursor);
    }
    return CT_SUCCESS;
}

status_t sql_fetch_sibl_sort(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    if (sql_fetch_sibl_sort_one_record(stmt, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }
    *eof = cursor->mtrl.cursor.eof;
    return CT_SUCCESS;
}

// create a segment to cache rowid list of the sub-segments
status_t sql_alloc_mtrl_sibl_sort_seg(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan,
    mtrl_rowid_t *sub_seg_rid)
{
    mtrl_segment_t *sub_seg = NULL;
    if (cursor->mtrl.sibl_sort.sid == CT_INVALID_ID32) {
        CT_RETURN_IFERR(mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_SIBL_SORT, NULL, &cursor->mtrl.sibl_sort.sid));
        CT_RETURN_IFERR(mtrl_open_segment(&stmt->mtrl, cursor->mtrl.sibl_sort.sid));
    }

    CT_RETURN_IFERR(sql_alloc_segment_in_vm(stmt, cursor->mtrl.sibl_sort.sid, &sub_seg, sub_seg_rid));
    mtrl_init_segment(sub_seg, MTRL_SEGMENT_SIBL_SORT, plan->query_sort.items);
    CT_RETURN_IFERR(mtrl_extend_segment(&stmt->mtrl, sub_seg));
    CT_RETURN_IFERR(mtrl_open_page(&stmt->mtrl, sub_seg->vm_list.last, &sub_seg->curr_page));
    mtrl_init_page((mtrl_page_t *)sub_seg->curr_page->data, sub_seg->vm_list.last);
    mtrl_close_segment2(&stmt->mtrl, sub_seg);
    return CT_SUCCESS;
}

status_t sql_get_last_sibl_sort_row(galist_t *last_sibl_sort_rows, uint32 level, sibl_sort_row_t **sibl_sort_row)
{
    *sibl_sort_row = NULL;
    if (last_sibl_sort_rows->count >= level) {
        *sibl_sort_row = cm_galist_get(last_sibl_sort_rows, level - 1);
    }
    return CT_SUCCESS;
}

status_t sql_set_last_sibl_sort_row(galist_t *last_sibl_sort_rows, uint32 level, sibl_sort_row_t *sibl_sort_row)
{
    sibl_sort_row_t *row = NULL;
    if (last_sibl_sort_rows->count < level) {
        CT_RETURN_IFERR(cm_galist_new(last_sibl_sort_rows, sizeof(sibl_sort_row_t), (pointer_t *)&row));
    } else {
        row = cm_galist_get(last_sibl_sort_rows, level - 1);
    }
    *row = *sibl_sort_row;
    return CT_SUCCESS;
}

/* cache rows into sibling sort segments:
 * 1. for root node data(level == 1),cache to the default sort segment(cursor->mtrl.sort.sid);
   2. for child node data, cache to sub-segment created by the parent node.
 */
status_t sql_insert_mtrl_sibl_sort_row(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, char *buf,
    sibl_sort_row_t *sibl_sort_row, galist_t *last_sibl_sort_rows, bool8 last_is_leaf)
{
    mtrl_rowid_t sort_rid;
    mtrl_segment_t *seg = NULL;
    sibl_sort_row_t *last_sibl_sort_row = NULL;
    sql_cursor_t *cur_level_cursor = cursor->connect_data.first_level_cursor->connect_data.cur_level_cursor;

    if (cur_level_cursor->connect_data.level == 1) {
        CT_RETURN_IFERR(
            sql_make_mtrl_sibl_sort_row(stmt, cursor->mtrl.sort.buf, plan->query_sort.items, buf, sibl_sort_row));
        CT_RETURN_IFERR(mtrl_insert_row(&stmt->mtrl, cursor->mtrl.sort.sid, buf, &sort_rid));
    } else {
        // current data is a child of the previous data
        if (!last_is_leaf) {
            CT_RETURN_IFERR(sql_get_last_sibl_sort_row(last_sibl_sort_rows, cur_level_cursor->connect_data.level - 1,
                &last_sibl_sort_row));
            sibl_sort_row->sibling_seg_rid = last_sibl_sort_row->child_seg_rid;
        } else { // current data is the sibling of the previous data with the same level
            CT_RETURN_IFERR(sql_get_last_sibl_sort_row(last_sibl_sort_rows, cur_level_cursor->connect_data.level,
                &last_sibl_sort_row));
            sibl_sort_row->sibling_seg_rid = last_sibl_sort_row->sibling_seg_rid;
        }
        CT_RETURN_IFERR(
            sql_get_segment_in_vm(stmt, cursor->mtrl.sibl_sort.sid, &sibl_sort_row->sibling_seg_rid, &seg));
        CT_RETURN_IFERR(
            sql_make_mtrl_sibl_sort_row(stmt, cursor->mtrl.sort.buf, plan->query_sort.items, buf, sibl_sort_row));
        CT_RETURN_IFERR(mtrl_open_page(&stmt->mtrl, seg->vm_list.last, &seg->curr_page));
        if (mtrl_insert_row2(&stmt->mtrl, seg, buf, &sort_rid) != CT_SUCCESS) {
            mtrl_close_segment2(&stmt->mtrl, seg);
            return CT_ERROR;
        }
        mtrl_close_segment2(&stmt->mtrl, seg);
    }
    return CT_SUCCESS;
}
void sql_init_sibl_sort_row(sibl_sort_row_t *sibl_sort_row)
{
    sibl_sort_row->rs_rid.slot = CT_INVALID_ID32;
    sibl_sort_row->rs_rid.vmid = CT_INVALID_ID32;
    sibl_sort_row->child_seg_rid.slot = CT_INVALID_ID32;
    sibl_sort_row->child_seg_rid.vmid = CT_INVALID_ID32;
    sibl_sort_row->sibling_seg_rid.slot = CT_INVALID_ID32;
    sibl_sort_row->sibling_seg_rid.vmid = CT_INVALID_ID32;
    sibl_sort_row->match_filter = CT_TRUE;
}
status_t sql_mtrl_query_sibl_sort(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    bool32 eof = CT_FALSE;
    char *buf = NULL;
    status_t status = CT_ERROR;
    sql_cursor_t *cur_level_cursor = NULL;
    sibl_sort_row_t sibl_sort_row;
    galist_t *last_sibl_sort_rows = NULL;
    bool8 last_is_leaf = CT_FALSE;
    vmc_t vmc;

    vmc_init(&stmt->session->vmp, &vmc);
    CT_RETURN_IFERR(vmc_alloc(&vmc, sizeof(galist_t), (void **)&last_sibl_sort_rows));
    cm_galist_init(last_sibl_sort_rows, &vmc, vmc_alloc);
    if (sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buf) != CT_SUCCESS) {
        vmc_free(&vmc);
        return CT_ERROR;
    }
    CTSQL_SAVE_STACK(stmt);
    do {
        sql_init_sibl_sort_row(&sibl_sort_row);
        CT_BREAK_IF_ERROR(sql_fetch_query(stmt, cursor, plan->query_sort.next, &eof));
        if (eof) {
            status = CT_SUCCESS;
            break;
        }
        CT_BREAK_IF_ERROR(sql_make_mtrl_rs_row(stmt, cursor->mtrl.rs.buf, plan->query_sort.select_columns, buf));
        CT_BREAK_IF_ERROR(mtrl_insert_row(&stmt->mtrl, cursor->mtrl.rs.sid, buf, &sibl_sort_row.rs_rid));
        if (cursor->query != NULL && cursor->query->filter_cond != NULL) {
            CT_BREAK_IF_ERROR(sql_match_cond_node(stmt, cursor->query->filter_cond->root, &sibl_sort_row.match_filter));
        }

        cur_level_cursor = cursor->connect_data.first_level_cursor->connect_data.cur_level_cursor;
        if (!cur_level_cursor->connect_data.connect_by_isleaf) {
            CT_BREAK_IF_ERROR(sql_alloc_mtrl_sibl_sort_seg(stmt, cursor, plan, &sibl_sort_row.child_seg_rid));
        }
        CT_BREAK_IF_ERROR(
            sql_insert_mtrl_sibl_sort_row(stmt, cursor, plan, buf, &sibl_sort_row, last_sibl_sort_rows, last_is_leaf));

        CT_BREAK_IF_ERROR(
            sql_set_last_sibl_sort_row(last_sibl_sort_rows, cur_level_cursor->connect_data.level, &sibl_sort_row));
        last_is_leaf = cur_level_cursor->connect_data.connect_by_isleaf;
        cursor->rownum++;
        CTSQL_RESTORE_STACK(stmt);
    } while (CT_TRUE);

    cursor->rownum = 1;
    CTSQL_RESTORE_STACK(stmt);
    CTSQL_POP(stmt);
    vmc_free(&vmc);
    return status;
}

static void sql_sibl_sort_mtrl_close_segment(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    sql_sort_mtrl_close_segment(stmt, cursor);

    if (cursor->mtrl.sibl_sort.sid != CT_INVALID_ID32) {
        mtrl_close_segment(&stmt->mtrl, cursor->mtrl.sibl_sort.sid);
    }
}

status_t sql_execute_query_sibl_sort(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    status_t status = CT_ERROR;
    mtrl_cursor_t *curr_cursor = NULL;

#ifdef TIME_STATISTIC
    clock_t start;
    double timeuse;
    start = cm_cal_time_bengin();
#endif

    do {
        CT_BREAK_IF_ERROR(sql_execute_query_plan(stmt, cursor, plan->query_sort.next));
        if (cursor->eof) {
            status = CT_SUCCESS;
            break;
        }

        CT_BREAK_IF_ERROR(sql_sort_mtrl_open_segment(stmt, cursor, MTRL_SEGMENT_SIBL_SORT, plan->query_sort.items));
        if (sql_mtrl_query_sibl_sort(stmt, cursor, plan) != CT_SUCCESS) {
            sql_sibl_sort_mtrl_close_segment(stmt, cursor);
            break;
        }
        sql_sort_mtrl_close_segment(stmt, cursor);

        if (cursor->eof) {
            status = CT_SUCCESS;
            break;
        }
        CT_BREAK_IF_ERROR(mtrl_sort_segment(&stmt->mtrl, cursor->mtrl.sort.sid));
        CT_BREAK_IF_ERROR(sql_alloc_mtrl_cursor(stmt, cursor, &curr_cursor, &cursor->mtrl.cursor.curr_cursor_rid));
        CT_BREAK_IF_ERROR(mtrl_open_cursor(&stmt->mtrl, cursor->mtrl.sort.sid, curr_cursor));
        curr_cursor->curr_cursor_rid = cursor->mtrl.cursor.curr_cursor_rid;
        status = CT_SUCCESS;
    } while (0);

#ifdef TIME_STATISTIC
    timeuse = cm_cal_time_end(start);
    stmt->mt_time += timeuse;
#endif
    return status;
}

status_t sql_fetch_sort_for_minus(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    bool32 group_changed = CT_FALSE;

    if (cursor->mtrl.cursor.eof) {
        *eof = CT_TRUE;
        return CT_SUCCESS;
    }

    if (!(cursor->mtrl.cursor.eof)) {
        if (mtrl_fetch_group(&stmt->mtrl, &cursor->mtrl.cursor, &group_changed) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    *eof = cursor->mtrl.cursor.eof;
    return CT_SUCCESS;
}
