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
 * ctsql_index_group.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_index_group.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_index_group.h"
#include "ctsql_group.h"
#include "ctsql_select.h"
#include "ctsql_aggr.h"

status_t sql_execute_index_group(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    CT_RETURN_IFERR(sql_init_group_exec_data(stmt, cursor, &plan->group));
    // IF CT_ERROR, segment will be close and release in mtrl_release_context
    CT_RETURN_IFERR(sql_execute_query_plan(stmt, cursor, plan->group.next));
    if (cursor->eof) {
        return CT_SUCCESS;
    }

    if (cursor->select_ctx != NULL && cursor->select_ctx->pending_col_count > 0) {
        CT_RETURN_IFERR(sql_group_mtrl_record_types(cursor, plan, &cursor->mtrl.group.buf));
    }

    CT_RETURN_IFERR(mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_GROUP, plan->group.exprs, &cursor->mtrl.group_index));
    CT_RETURN_IFERR(mtrl_open_segment(&stmt->mtrl, cursor->mtrl.group_index));

    mtrl_page_t *page = (mtrl_page_t *)stmt->mtrl.segments[cursor->mtrl.group_index]->curr_page->data;
    if (page->free_begin + 2 * CT_MAX_ROW_SIZE + sizeof(bool32) > CT_VMEM_PAGE_SIZE) {
        CT_THROW_ERROR(ERR_NO_FREE_VMEM, "one page free size is smaller than needed memory");
        return CT_ERROR;
    }
    *(bool32 *)((char *)page + page->free_begin) = CT_TRUE;
    CT_RETURN_IFERR(mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_AGGR, NULL, &cursor->mtrl.aggr));
    CT_RETURN_IFERR(mtrl_open_segment(&stmt->mtrl, cursor->mtrl.aggr));
    cursor->mtrl.cursor.type = MTRL_CURSOR_OTHERS;
    CT_RETURN_IFERR(sql_init_aggr_page(stmt, cursor, plan->group.aggrs));

    return CT_SUCCESS;
}

static status_t sql_get_group_index_row_buf(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof,
    char **next_row_buf)
{
    mtrl_segment_t *seg = stmt->mtrl.segments[cursor->mtrl.group_index];
    mtrl_page_t *page = (mtrl_page_t *)seg->curr_page->data;
    bool32 *flag = (bool32 *)((char *)page + page->free_begin);
    char *row_buf1 = (char *)page + page->free_begin + sizeof(bool32);
    char *row_buf2 = row_buf1 + CT_MAX_ROW_SIZE;
    mtrl_cursor_t *mtrl_cur = &cursor->mtrl.cursor;

    if (*flag) {
        *flag = CT_FALSE;
        CT_RETURN_IFERR(sql_fetch_query(stmt, cursor, plan->group.next, eof));
        if (*eof) {
            return CT_SUCCESS;
        }

        CT_RETURN_IFERR(sql_make_mtrl_group_row(stmt, cursor->mtrl.group.buf, &plan->group, row_buf1));
        mtrl_cur->row.data = row_buf1;
        *next_row_buf = row_buf2;
    } else {
        if (mtrl_cur->row.data == row_buf1) {
            mtrl_cur->row.data = row_buf2;
            *next_row_buf = row_buf1;
        } else {
            mtrl_cur->row.data = row_buf1;
            *next_row_buf = row_buf2;
        }
        *eof = IS_INVALID_ROW(mtrl_cur->row.data);
        if (*eof) {
            return CT_SUCCESS;
        }
    }
    cm_decode_row(mtrl_cur->row.data, mtrl_cur->row.offsets, mtrl_cur->row.lens, NULL);
    mtrl_cur->eof = CT_FALSE;
    return CT_SUCCESS;
}

status_t sql_fetch_index_group(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    bool32 group_eof = CT_FALSE;
    uint32 avgs;
    int32 result;
    char *next_row_buf = NULL;
    mtrl_cursor_t *mtrl_cursor = &cursor->mtrl.cursor;
    mtrl_segment_t *segment = stmt->mtrl.segments[cursor->mtrl.group_index];

    if (cursor->eof) {
        *eof = CT_TRUE;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_get_group_index_row_buf(stmt, cursor, plan, eof, &next_row_buf));
    if (*eof) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_init_aggr_values(stmt, cursor, plan->group.next, plan->group.aggrs, &avgs));
    for (;;) {
        CT_RETURN_IFERR(sql_aggregate_group(stmt, cursor, plan));

        CT_RETURN_IFERR(sql_fetch_query(stmt, cursor, plan->group.next, &group_eof));

        if (group_eof) {
            CM_SET_INVALID_ROW(next_row_buf);
            break;
        }

        CT_RETURN_IFERR(sql_make_mtrl_group_row(stmt, cursor->mtrl.group.buf, &plan->group, next_row_buf));
        CT_RETURN_IFERR(sql_mtrl_sort_cmp(segment, mtrl_cursor->row.data, next_row_buf, &result));
        if (result != 0) {
            break;
        }
        SWAP(char *, mtrl_cursor->row.data, next_row_buf);
        cm_decode_row(mtrl_cursor->row.data, mtrl_cursor->row.offsets, mtrl_cursor->row.lens, NULL);
        mtrl_cursor->eof = CT_FALSE;
    }

    if (avgs > 0) {
        CT_RETURN_IFERR(sql_exec_aggr(stmt, cursor, plan->group.aggrs, plan));
    }

    CT_RETURN_IFERR(sql_exec_aggr_extra(stmt, cursor, plan->group.aggrs, plan));

    mtrl_cursor->type = MTRL_CURSOR_OTHERS;
    return CT_SUCCESS;
}