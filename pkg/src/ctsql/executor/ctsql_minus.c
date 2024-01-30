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
 * ctsql_minus.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_minus.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_minus.h"
#include "ctsql_select.h"
#include "ctsql_mtrl.h"
#include "ctsql_sort.h"

static status_t sql_fetch_distinct_4_minus(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    bool32 group_changed = CT_FALSE;

    if (cursor->mtrl.cursor.eof) {
        *eof = CT_TRUE;
        return CT_SUCCESS;
    }

    while (!(group_changed || cursor->mtrl.cursor.eof)) {
        if (mtrl_fetch_group(&stmt->mtrl, &cursor->mtrl.cursor, &group_changed) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    *eof = cursor->mtrl.cursor.eof;
    return CT_SUCCESS;
}

static status_t sql_materialize_minus(sql_stmt_t *stmt, sql_cursor_t **sub_cursor, sql_cursor_t *cursor,
    plan_node_t *plan, minus_plan_t *minus_cols)
{
    sql_cursor_t *sql_cur = NULL;

    CT_RETURN_IFERR(sql_alloc_cursor(stmt, &sql_cur));
    sql_cur->scn = cursor->scn;
    sql_cur->ancestor_ref = cursor->ancestor_ref;

    sql_open_select_cursor(stmt, sql_cur, minus_cols->rs_columns);

    if (mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_RS, minus_cols->minus_columns, &sql_cur->mtrl.rs.sid) !=
        CT_SUCCESS) {
        sql_free_cursor(stmt, sql_cur);
        return CT_ERROR;
    }

    if (mtrl_open_segment(&stmt->mtrl, sql_cur->mtrl.rs.sid) != CT_SUCCESS) {
        sql_free_cursor(stmt, sql_cur);
        return CT_ERROR;
    }

    // rs datatype depends on the first query
    CT_RETURN_IFERR(sql_inherit_pending_buf(cursor, sql_cur));

    if (sql_materialize_base(stmt, sql_cur, plan) != CT_SUCCESS) {
        mtrl_close_segment(&stmt->mtrl, sql_cur->mtrl.rs.sid);
        sql_free_cursor(stmt, sql_cur);
        return CT_ERROR;
    }

    mtrl_close_segment(&stmt->mtrl, sql_cur->mtrl.rs.sid);

    if (mtrl_sort_segment(&stmt->mtrl, sql_cur->mtrl.rs.sid) != CT_SUCCESS) {
        sql_free_cursor(stmt, sql_cur);
        return CT_ERROR;
    }

    if (mtrl_open_cursor(&stmt->mtrl, sql_cur->mtrl.rs.sid, &sql_cur->mtrl.cursor) != CT_SUCCESS) {
        sql_free_cursor(stmt, sql_cur);
        return CT_ERROR;
    }

    *sub_cursor = sql_cur;
    CT_RETURN_IFERR(sql_revert_pending_buf(cursor, sql_cur));

    return CT_SUCCESS;
}

static int32 sql_compare_minus_result(sql_cursor_t *l_cursor, sql_cursor_t *r_cursor, galist_t *cmp_items)
{
    mtrl_row_t *left_row = &l_cursor->mtrl.cursor.row;
    mtrl_row_t *right_row = &r_cursor->mtrl.cursor.row;
    uint32 i;
    rs_column_t *column = NULL;
    int32 result = 0;

    cm_decode_row(left_row->data, left_row->offsets, left_row->lens, NULL);
    cm_decode_row(right_row->data, right_row->offsets, right_row->lens, NULL);

    for (i = 0; i < cmp_items->count; i++) {
        column = (rs_column_t *)cm_galist_get(cmp_items, i);
        result = sql_compare_data_ex(MT_CDATA(left_row, i), MT_CSIZE(left_row, i), MT_CDATA(right_row, i), MT_CSIZE(right_row, i),
            column->datatype);
        if (result != 0) {
            return result;
        }
    }

    return 0;
}

static bool32 compare_intersect_result(sql_cursor_t *left_cursor, sql_cursor_t *right_cursor, galist_t *cmp_items,
    bool32 *l_continue_fetch, bool32 *r_continue_fetch)
{
    int cmp_result;
    cmp_result = sql_compare_minus_result(left_cursor, right_cursor, cmp_items);
    if (cmp_result > 0) {
        *l_continue_fetch = CT_FALSE;
        *r_continue_fetch = CT_TRUE;
    } else if (cmp_result == 0) {
        *l_continue_fetch = CT_TRUE;
        *r_continue_fetch = CT_TRUE;
        return CT_TRUE;
    } else {
        *l_continue_fetch = CT_TRUE;
        *r_continue_fetch = CT_FALSE;
    }
    return CT_FALSE;
}

static bool32 compare_minus_result(sql_cursor_t *left_cursor, sql_cursor_t *right_cursor, galist_t *cmp_items,
    bool32 *l_continue_fetch, bool32 *r_continue_fetch)
{
    int cmp_result;
    cmp_result = sql_compare_minus_result(left_cursor, right_cursor, cmp_items);
    if (cmp_result > 0) {
        *l_continue_fetch = CT_FALSE;
        *r_continue_fetch = CT_TRUE;
    } else if (cmp_result == 0) {
        *l_continue_fetch = CT_TRUE;
        *r_continue_fetch = CT_TRUE;
    } else {
        *r_continue_fetch = CT_FALSE;
        return CT_TRUE;
    }

    return CT_FALSE;
}

static status_t sql_generate_minus_result(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan,
    galist_t *cmp_items, bool32 *eof)
{
    sql_cursor_t *l_cursor = cursor->left_cursor;
    sql_cursor_t *r_cursor = cursor->right_cursor;
    bool32 *r_continue_fetch = &cursor->exec_data.minus.r_continue_fetch;
    bool32 l_continue_fetch = CT_TRUE;
    bool32 isBreak = CT_FALSE;

    do {
        // fetch row from left plan
        if (l_continue_fetch) {
            CT_RETURN_IFERR(sql_fetch_distinct_4_minus(stmt, l_cursor, plan, &l_cursor->eof));
            if (l_cursor->eof || r_cursor->eof) {
                break;
            }
        }

        // fetch row from right plan
        if (*r_continue_fetch) {
            CT_RETURN_IFERR(sql_fetch_distinct_4_minus(stmt, r_cursor, plan, &r_cursor->eof));
            if (r_cursor->eof) {
                break;
            }
        }

        // merge compare left row and right row
        isBreak = compare_minus_result(l_cursor, r_cursor, cmp_items, &l_continue_fetch, r_continue_fetch);
        if (isBreak) {
            break;
        }
    } while (CT_TRUE);

    *eof = l_cursor->eof;
    return CT_SUCCESS;
}

static status_t sql_generate_intersect_all_result(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan,
    galist_t *cmp_items, bool32 *eof)
{
    sql_cursor_t *l_cursor = cursor->left_cursor;
    sql_cursor_t *r_cursor = cursor->right_cursor;
    bool32 *r_continue_fetch = &cursor->exec_data.minus.r_continue_fetch;
    bool32 l_continue_fetch = CT_TRUE;
    bool32 isBreak = CT_FALSE;

    do {
        // fetch row from left plan
        if (l_continue_fetch) {
            CT_RETURN_IFERR(sql_fetch_sort_for_minus(stmt, l_cursor, plan, &l_cursor->eof));
            if (l_cursor->eof || r_cursor->eof) {
                break;
            }
        }

        // fetch row from right plan
        if (*r_continue_fetch) {
            CT_RETURN_IFERR(sql_fetch_sort_for_minus(stmt, r_cursor, plan, &r_cursor->eof));
            if (r_cursor->eof) {
                break;
            }
        }

        // merge compare left row and right row
        isBreak = compare_intersect_result(l_cursor, r_cursor, cmp_items, &l_continue_fetch, r_continue_fetch);
        if (isBreak) {
            break;
        }
    } while (CT_TRUE);

    *eof = l_cursor->eof || r_cursor->eof;
    return CT_SUCCESS;
}

static status_t sql_generate_intersect_result(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan,
    galist_t *cmp_items, bool32 *eof)
{
    sql_cursor_t *l_cursor = cursor->left_cursor;
    sql_cursor_t *r_cursor = cursor->right_cursor;
    bool32 *r_continue_fetch = &cursor->exec_data.minus.r_continue_fetch;
    bool32 l_continue_fetch = CT_TRUE;
    bool32 isBreak = CT_FALSE;

    do {
        // fetch row from left plan
        if (l_continue_fetch) {
            CT_RETURN_IFERR(sql_fetch_distinct_4_minus(stmt, l_cursor, plan, &l_cursor->eof));
            if (l_cursor->eof || r_cursor->eof) {
                break;
            }
        }

        // fetch row from right plan
        if (*r_continue_fetch) {
            CT_RETURN_IFERR(sql_fetch_distinct_4_minus(stmt, r_cursor, plan, &r_cursor->eof));
            if (r_cursor->eof) {
                break;
            }
        }

        // merge compare left row and right row
        isBreak = compare_intersect_result(l_cursor, r_cursor, cmp_items, &l_continue_fetch, r_continue_fetch);
        if (isBreak) {
            break;
        }
    } while (CT_TRUE);

    *eof = l_cursor->eof || r_cursor->eof;
    return CT_SUCCESS;
}

static status_t sql_generate_except_all_result(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan,
    galist_t *cmp_items, bool32 *eof)
{
    sql_cursor_t *l_cursor = cursor->left_cursor;
    sql_cursor_t *r_cursor = cursor->right_cursor;
    bool32 *r_continue_fetch = &cursor->exec_data.minus.r_continue_fetch;
    bool32 l_continue_fetch = CT_TRUE;
    bool32 isBreak = CT_FALSE;

    do {
        // fetch row from left plan
        if (l_continue_fetch) {
            CT_RETURN_IFERR(sql_fetch_sort_for_minus(stmt, l_cursor, plan, &l_cursor->eof));
            if (l_cursor->eof || r_cursor->eof) {
                break;
            }
        }

        // fetch row from right plan
        if (*r_continue_fetch) {
            CT_RETURN_IFERR(sql_fetch_sort_for_minus(stmt, r_cursor, plan, &r_cursor->eof));
            if (r_cursor->eof) {
                break;
            }
        }

        // merge compare left row and right row
        isBreak = compare_minus_result(l_cursor, r_cursor, cmp_items, &l_continue_fetch, r_continue_fetch);
        if (isBreak) {
            break;
        }
    } while (CT_TRUE);

    *eof = l_cursor->eof;
    return CT_SUCCESS;
}

status_t sql_execute_minus(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    set_plan_t *set_p = &plan->set_p;
    sql_cursor_t *l_cursor = NULL;
    sql_cursor_t *r_cursor = NULL;

    sql_open_select_cursor(stmt, cursor, set_p->minus_p.rs_columns);

    // init plan_exec_data
    cursor->exec_data.minus.r_continue_fetch = CT_TRUE;

    // materialize left plan and right plan
    CT_RETURN_IFERR(sql_materialize_minus(stmt, &l_cursor, cursor, set_p->left, &set_p->minus_p));
    cursor->left_cursor = l_cursor;

    CT_RETURN_IFERR(sql_materialize_minus(stmt, &r_cursor, cursor, set_p->right, &set_p->minus_p));
    cursor->right_cursor = r_cursor;

    return CT_SUCCESS;
}

status_t sql_fetch_minus(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    if (plan->set_p.minus_p.minus_type == INTERSECT_ALL) {
        CT_RETURN_IFERR(sql_generate_intersect_all_result(stmt, cursor, plan, plan->set_p.minus_p.rs_columns, eof));
    } else if (plan->set_p.minus_p.minus_type == EXCEPT_ALL) {
        CT_RETURN_IFERR(sql_generate_except_all_result(stmt, cursor, plan, plan->set_p.minus_p.rs_columns, eof));
    } else if (plan->set_p.minus_p.minus_type == INTERSECT) {
        CT_RETURN_IFERR(sql_generate_intersect_result(stmt, cursor, plan, plan->set_p.minus_p.rs_columns, eof));
    } else {
        CT_RETURN_IFERR(sql_generate_minus_result(stmt, cursor, plan, plan->set_p.minus_p.rs_columns, eof));
    }

    if (*eof) {
        sql_free_cursor(stmt, cursor->left_cursor);
        sql_free_cursor(stmt, cursor->right_cursor);
        cursor->left_cursor = NULL;
        cursor->right_cursor = NULL;
    } else {
        cursor->mtrl.cursor.row = cursor->left_cursor->mtrl.cursor.row;
    }

    cursor->mtrl.cursor.eof = *eof;
    return CT_SUCCESS;
}
