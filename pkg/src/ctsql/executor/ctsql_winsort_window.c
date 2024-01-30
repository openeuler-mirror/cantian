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
 * ctsql_winsort_window.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_winsort_window.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_aggr.h"
#include "ctsql_mtrl.h"
#include "ctsql_winsort_window.h"


typedef struct st_windowing_assist {
    aggr_assist_t aa;
    mtrl_sort_cursor_t part_cur;
    mtrl_rowid_t rid;
    uint32 *rownum;
    aggr_var_t *cur_aggr;
    variant_t *l_var;      // windowing left border value
    variant_t *r_var;      // windowing right border value
    sql_cursor_t *qry_cur; // query cursor
    expr_node_t *winsort;
    aggr_var_t *tmp_aggr; // used to copy aggr
    ct_type_t datatype;   // winsort function argument datatype
    uint32 part_rownum;   // the first rownum of next partition
    bool32 grp_chged;
    struct { // for RANGE
        order_mode_t sort_mode;
        bool32 ord_chged;
        variant_t *sort_val;
    };
    struct st_windowing_funcs *win_func;
} windowing_assist_t;

typedef status_t (*border_srch_func_t)(sql_stmt_t *stmt, variant_t *sort_val, variant_t *bor_val, order_mode_t mode,
    bool32 *found);
typedef status_t (*windowing_invoke_func_t)(windowing_assist_t *win_ass, sql_cursor_t *cursor, const char *buf);

typedef struct st_border_srch_assist {
    variant_t sort_val;
    order_mode_t sort_mode;
    ct_type_t datatype;
    uint32 id;
    variant_t *bor_val;
    border_srch_func_t search_func;
} border_srch_assist_t;

typedef struct st_windowing_funcs {
    windowing_invoke_func_t invoke;
} windowing_funcs_t;

static inline void win_mtrl_init_search_cursor(mtrl_sort_cursor_t *srch_cur, mtrl_sort_cursor_t *origin_cur)
{
    srch_cur->vmid = origin_cur->vmid;
    srch_cur->last_vmid = origin_cur->vmid;
    srch_cur->slot = origin_cur->slot;
    srch_cur->rownum = origin_cur->rownum;
    srch_cur->page = NULL;
    srch_cur->part = origin_cur->part;
    srch_cur->segment = origin_cur->segment;
    srch_cur->ctx = origin_cur->ctx;
    srch_cur->row = NULL;
}

static status_t mtrl_fetch_win_args_row(mtrl_context_t *mtrl_ctx, mtrl_cursor_t *cur, mtrl_sort_cursor_t *sort)
{
    mtrl_rowid_t *rid = NULL;
    vm_page_t *vm_page = NULL;
    uint16 row_size = ((row_head_t *)sort->row)->size;

    rid = (mtrl_rowid_t *)(sort->row + row_size - sizeof(mtrl_rowid_t));
    if (rid->vmid != cur->rs_vmid) {
        if (cur->rs_vmid != CT_INVALID_ID32) {
            mtrl_close_page(mtrl_ctx, cur->rs_vmid);
            cur->rs_vmid = CT_INVALID_ID32;
        }

        if (mtrl_open_page(mtrl_ctx, rid->vmid, &vm_page) != CT_SUCCESS) {
            return CT_ERROR;
        }

        cur->rs_vmid = rid->vmid;
        cur->rs_page = (mtrl_page_t *)vm_page->data;
    }

    cur->row.data = MTRL_GET_ROW(cur->rs_page, rid->slot);
    cm_decode_row(cur->row.data, cur->row.offsets, cur->row.lens, NULL);
    return CT_SUCCESS;
}

static status_t mtrl_fetch_win_sort_row(mtrl_context_t *mtrl_ctx, mtrl_sort_cursor_t *sort_cur,
                                        bool32 *grp_chged, bool32 *eof)
{
    if (sort_cur->rownum > sort_cur->part.rows) {
        if (eof != NULL) {
            *eof = CT_TRUE;
        }
        return CT_SUCCESS;
    }
    if (sort_cur->last_vmid != sort_cur->vmid) {
        mtrl_close_page(mtrl_ctx, sort_cur->last_vmid);
    }
    sort_cur->row = MTRL_GET_ROW(sort_cur->page, sort_cur->slot - 1);
    sort_cur->last_vmid = sort_cur->vmid;

    if (mtrl_move_group_cursor(mtrl_ctx, sort_cur) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (grp_chged != NULL) {
        if (sort_cur->rownum > sort_cur->part.rows) {
            *grp_chged = CT_FALSE;
            return CT_SUCCESS;
        }
        int32 result;
        char *next_row = MTRL_GET_ROW(sort_cur->page, sort_cur->slot - 1);
        sort_cur->segment->cmp_flag = WINSORT_PART;
        if (mtrl_ctx->sort_cmp(sort_cur->segment, next_row, sort_cur->row, &result) != CT_SUCCESS) {
            return CT_ERROR;
        }
        *grp_chged = (result != 0);
    }
    return CT_SUCCESS;
}

static inline status_t sql_win_aggr_curr_row(aggr_assist_t *aa, expr_tree_t *func_expr, aggr_var_t *aggr_var,
    const char *buf)
{
    variant_t vars[FO_VAL_MAX - 1];
    expr_tree_t *argument = func_expr->root->argument;

    CT_RETURN_IFERR(sql_exec_expr(aa->stmt, argument, &vars[0]));
    if (aa->aggr_type == AGGR_TYPE_CORR || aa->aggr_type == AGGR_TYPE_COVAR_POP ||
        aa->aggr_type == AGGR_TYPE_COVAR_SAMP) {
        CT_RETURN_IFERR(sql_exec_expr(aa->stmt, argument->next, &vars[1]));
    } else {
        vars[1].is_null = CT_TRUE;
    }

    if (vars[0].is_null) {
        sql_winsort_aggr_value_null(aggr_var, func_expr, aa->aggr_type, &aggr_var->var);
        return CT_SUCCESS;
    }
    return sql_get_winsort_aggr_value(aa, aggr_var, buf, vars, &aggr_var->var);
}

static inline status_t win_mtrl_open_search_cursor(mtrl_context_t *mtrl_ctx, mtrl_sort_cursor_t *sort_cur)
{
    vm_page_t *page = NULL;

    if (mtrl_open_page(mtrl_ctx, sort_cur->vmid, &page) != CT_SUCCESS) {
        return CT_ERROR;
    }
    sort_cur->page = (mtrl_page_t *)page->data;
    return CT_SUCCESS;
}

static inline void win_mtrl_close_search_cursor(mtrl_context_t *mtrl_ctx, mtrl_sort_cursor_t *sort_cur)
{
    if (sort_cur->vmid != CT_INVALID_ID32) {
        mtrl_close_page(mtrl_ctx, sort_cur->vmid);
        if (sort_cur->last_vmid != sort_cur->vmid && sort_cur->last_vmid != CT_INVALID_ID32) {
            mtrl_close_page(mtrl_ctx, sort_cur->last_vmid);
            sort_cur->last_vmid = CT_INVALID_ID32;
        }
        sort_cur->vmid = CT_INVALID_ID32;
    }
}

static inline status_t win_search_value_in_border(sql_stmt_t *stmt, variant_t *sort_val, variant_t *bor_val,
    order_mode_t mode, bool32 *found)
{
    if (bor_val->is_null | sort_val->is_null) {
        if (bor_val->is_null == sort_val->is_null) {
            *found = CT_TRUE;
        } else {
            if (bor_val->is_null) {
                *found = (mode.nulls_pos != SORT_NULLS_LAST);
            } else {
                *found = (mode.nulls_pos != SORT_NULLS_FIRST);
            }
        }
        return CT_SUCCESS;
    }
    if (sort_val->is_null) {
        *found = CT_FALSE;
        return CT_SUCCESS;
    }

    int32 res;
    if (mode.direction == SORT_MODE_DESC) {
        CT_RETURN_IFERR(sql_compare_variant(stmt, bor_val, sort_val, &res));
    } else {
        CT_RETURN_IFERR(sql_compare_variant(stmt, sort_val, bor_val, &res));
    }
    *found = res >= 0;
    return CT_SUCCESS;
}

static inline status_t win_search_value_out_border(sql_stmt_t *stmt, variant_t *sort_val, variant_t *bor_val,
    order_mode_t mode, bool32 *found)
{
    if (bor_val->is_null | sort_val->is_null) {
        if (bor_val->is_null == sort_val->is_null) {
            *found = CT_FALSE;
        } else {
            if (bor_val->is_null) {
                *found = (mode.nulls_pos != SORT_NULLS_LAST);
            } else {
                *found = (mode.nulls_pos != SORT_NULLS_FIRST);
            }
        }
        return CT_SUCCESS;
    }

    int32 res;
    if (mode.direction == SORT_MODE_DESC) {
        CT_RETURN_IFERR(sql_compare_variant(stmt, bor_val, sort_val, &res));
    } else {
        CT_RETURN_IFERR(sql_compare_variant(stmt, sort_val, bor_val, &res));
    }
    *found = res > 0;
    return CT_SUCCESS;
}

static status_t mtrl_move_cursor_next_page(mtrl_context_t *mtrl_ctx, mtrl_sort_cursor_t *sort_cur,
                                           uint32 rownum, bool32 *eof)
{
    vm_page_t *page = NULL;
    vm_ctrl_t *ctrl = NULL;
    uint16 rows = sort_cur->page->rows - sort_cur->slot;

    if (sort_cur->rownum + rows + 1 >= rownum) {
        *eof = CT_TRUE;
        sort_cur->slot += rownum - sort_cur->rownum - 1;
        sort_cur->rownum = rownum - 1;
        return CT_SUCCESS;
    }
    ctrl = vm_get_ctrl(mtrl_ctx->pool, sort_cur->vmid);
    if (ctrl->next == CT_INVALID_ID32) {
        *eof = CT_TRUE;
        sort_cur->rownum += rows;
        sort_cur->slot = sort_cur->page->rows;
        return CT_SUCCESS;
    }

    if (mtrl_open_page(mtrl_ctx, ctrl->next, &page) != CT_SUCCESS) {
        return CT_ERROR;
    }
    sort_cur->page = (mtrl_page_t *)page->data;
    sort_cur->vmid = ctrl->next;
    sort_cur->slot = 1;
    sort_cur->rownum += rows + 1;
    return CT_SUCCESS;
}

static status_t win_mtrl_fetch_grp_chg_page(mtrl_context_t *mtrl_ctx, mtrl_sort_cursor_t *sort_cur, uint32 rownum)
{
    bool32 eof = CT_FALSE;
    mtrl_page_t *page = NULL;
    char *new_row = NULL;
    int32 result;

    do {
        page = sort_cur->page;
        sort_cur->last_vmid = sort_cur->vmid;
        if (mtrl_move_cursor_next_page(mtrl_ctx, sort_cur, rownum, &eof) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (eof) {
            return CT_SUCCESS;
        }

        new_row = MTRL_GET_ROW(sort_cur->page, sort_cur->slot - 1);
        sort_cur->segment->cmp_flag = WINSORT_PART;
        if (mtrl_ctx->sort_cmp(sort_cur->segment, new_row, sort_cur->row, &result) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (result != 0) {
            break;
        }
        sort_cur->row = new_row;
        mtrl_close_page(mtrl_ctx, sort_cur->last_vmid);
    } while (CT_TRUE);

    mtrl_close_page(mtrl_ctx, sort_cur->vmid);
    sort_cur->page = page;
    sort_cur->slot = page->rows;
    sort_cur->rownum--;
    sort_cur->vmid = sort_cur->last_vmid;
    return CT_SUCCESS;
}

static status_t sql_win_get_next_partion_rownum(mtrl_context_t *mtrl_ctx, mtrl_sort_cursor_t *sort_cur, uint32 *rownum)
{
    uint32 l_slot, r_slot;
    int32 result;
    bool32 grp_chg = CT_FALSE;
    bool32 eof = CT_FALSE;
    uint32 first_vmid;
    mtrl_sort_cursor_t srch_cur;

    win_mtrl_init_search_cursor(&srch_cur, sort_cur);
    if (win_mtrl_open_search_cursor(mtrl_ctx, &srch_cur) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (mtrl_fetch_win_sort_row(mtrl_ctx, &srch_cur, &grp_chg, &eof) != CT_SUCCESS) {
        win_mtrl_close_search_cursor(mtrl_ctx, &srch_cur);
        return CT_ERROR;
    }
    if (grp_chg || eof) {
        *rownum = srch_cur.rownum;
        win_mtrl_close_search_cursor(mtrl_ctx, &srch_cur);
        return CT_SUCCESS;
    }

    first_vmid = srch_cur.vmid;
    l_slot = srch_cur.slot;
    if (win_mtrl_fetch_grp_chg_page(mtrl_ctx, &srch_cur, (uint32)MIN(srch_cur.part.rows + 1, CT_MAX_UINT32)) !=
        CT_SUCCESS) {
        win_mtrl_close_search_cursor(mtrl_ctx, &srch_cur);
        return CT_ERROR;
    }

    if (first_vmid != srch_cur.vmid) {
        l_slot = 1;
    }
    r_slot = srch_cur.slot;
    while (l_slot <= r_slot) {
        uint32 mid = (l_slot + r_slot) >> 1;
        char *mid_row = MTRL_GET_ROW(srch_cur.page, mid - 1);
        srch_cur.segment->cmp_flag = WINSORT_PART;
        if (mtrl_ctx->sort_cmp(srch_cur.segment, mid_row, srch_cur.row, &result) != CT_SUCCESS) {
            win_mtrl_close_search_cursor(mtrl_ctx, &srch_cur);
            return CT_ERROR;
        }
        if (result == 0) {
            l_slot = mid + 1;
        } else {
            r_slot = mid - 1;
        }
    }
    *rownum = srch_cur.rownum - srch_cur.slot + l_slot;
    win_mtrl_close_search_cursor(mtrl_ctx, &srch_cur);
    return CT_SUCCESS;
}

static inline void win_init_bor_srch_assist(border_srch_assist_t *srch_ass, variant_t *border, winsort_args_t *args,
    border_srch_func_t search_func)
{
    sort_item_t *item = (sort_item_t *)cm_galist_get(args->sort_items, 0);
    srch_ass->sort_mode = item->sort_mode;
    srch_ass->datatype = item->expr->root->datatype;
    srch_ass->id = (args->group_exprs != NULL) ? args->group_exprs->count : 0;
    srch_ass->bor_val = border;
    srch_ass->search_func = search_func;
}

static status_t win_mtrl_fetch_border_page(sql_stmt_t *stmt, mtrl_context_t *mtrl_ctx, mtrl_sort_cursor_t *sort_cur,
    border_srch_assist_t *srch_ass, uint32 rownum)
{
    bool32 eof = CT_FALSE;
    mtrl_page_t *page = NULL;
    bool32 found = CT_FALSE;

    do {
        page = sort_cur->page;
        sort_cur->last_vmid = sort_cur->vmid;
        if (mtrl_move_cursor_next_page(mtrl_ctx, sort_cur, rownum, &eof) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (eof) {
            return CT_SUCCESS;
        }

        sort_cur->row = MTRL_GET_ROW(sort_cur->page, sort_cur->slot - 1);
        CT_RETURN_IFERR(sql_mtrl_get_windowing_sort_val(sort_cur, srch_ass->id, srch_ass->datatype, &srch_ass->sort_val));
        if (srch_ass->search_func(stmt, &srch_ass->sort_val, srch_ass->bor_val, srch_ass->sort_mode, &found) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (found) {
            break;
        }
        mtrl_close_page(mtrl_ctx, sort_cur->last_vmid);
    } while (CT_TRUE);

    mtrl_close_page(mtrl_ctx, sort_cur->vmid);
    sort_cur->page = page;
    sort_cur->slot = page->rows;
    sort_cur->rownum--;
    sort_cur->row = MTRL_GET_ROW(sort_cur->page, sort_cur->slot - 1);
    sort_cur->vmid = sort_cur->last_vmid;
    return CT_SUCCESS;
}

static status_t win_mtrl_fetch_border_row(sql_stmt_t *stmt, mtrl_context_t *mtrl_ctx, mtrl_sort_cursor_t *sort_cur,
    border_srch_assist_t *srch_ass, uint32 rownum)
{
    uint32 l_vmid = sort_cur->vmid;
    uint32 l_slot = sort_cur->slot;
    uint32 r_slot;
    bool32 found = CT_FALSE;

    if (win_mtrl_fetch_border_page(stmt, mtrl_ctx, sort_cur, srch_ass, rownum) != CT_SUCCESS) {
        return CT_ERROR;
    }
    r_slot = sort_cur->slot;
    if (l_vmid != sort_cur->vmid) {
        l_slot = 1;
    }

    while (l_slot <= r_slot) {
        uint32 mid = (l_slot + r_slot) >> 1;
        sort_cur->row = MTRL_GET_ROW(sort_cur->page, mid - 1);
        CT_RETURN_IFERR(sql_mtrl_get_windowing_sort_val(sort_cur, srch_ass->id, srch_ass->datatype, &srch_ass->sort_val));
        if (srch_ass->search_func(stmt, &srch_ass->sort_val, srch_ass->bor_val, srch_ass->sort_mode, &found) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (found) {
            r_slot = mid - 1;
        } else {
            l_slot = mid + 1;
        }
    }

    // No need to set sort_cur->row, because cursor will be moved to next row and next row will be fetched if need
    sort_cur->row = NULL;
    sort_cur->rownum -= sort_cur->slot - r_slot;
    sort_cur->slot = r_slot;
    return mtrl_move_group_cursor(mtrl_ctx, sort_cur);
}

static status_t sql_win_aggr_value_until_row(windowing_assist_t *win_ass, mtrl_cursor_t *mtrl_cur, mtrl_sort_cursor_t *sort,
    uint32 rownum, const char *buf)
{
    aggr_assist_t *aggr_ass = &win_ass->aa;
    mtrl_context_t *mtrl_ctx = &aggr_ass->stmt->mtrl;
    expr_tree_t *arg_expr = win_ass->winsort->argument;
    bool32 eof = CT_FALSE;

    if (aggr_ass->aggr_type == AGGR_TYPE_COUNT) {
        if (TREE_IS_CONST(arg_expr->root->argument)) {
            if (sort->rownum <= rownum) {
                win_ass->cur_aggr->var.is_null = CT_FALSE;
                win_ass->cur_aggr->var.v_bigint += rownum - sort->rownum + 1;
            }
            return sql_winsort_aggr_value_end(aggr_ass->stmt, aggr_ass->aggr_type, win_ass->qry_cur, win_ass->cur_aggr);
        }
    }

    while (sort->rownum <= rownum) {
        // fetch rs row which contains arguments group value
        CT_RETURN_IFERR(mtrl_fetch_win_args_row(mtrl_ctx, mtrl_cur, sort));
        CT_RETURN_IFERR(sql_win_aggr_curr_row(aggr_ass, arg_expr, win_ass->cur_aggr, buf));
        // fetch next row and check sort value out of range
        CT_RETURN_IFERR(mtrl_fetch_win_sort_row(mtrl_ctx, sort, NULL, &eof));
        if (eof) {
            break;
        }
    };

    return sql_winsort_aggr_value_end(aggr_ass->stmt, aggr_ass->aggr_type, win_ass->qry_cur, win_ass->cur_aggr);
}

static inline status_t sql_calc_win_pre_border(sql_stmt_t *stmt, variant_t *sort_val, sort_direction_t dir,
    variant_t *bor)
{
    operator_type_t oper = (dir == SORT_MODE_DESC) ? OPER_TYPE_ADD : OPER_TYPE_SUB;
    return opr_exec(oper, SESSION_NLS(stmt), sort_val, bor, bor);
}

static inline status_t sql_calc_win_fol_border(sql_stmt_t *stmt, variant_t *sort_val, sort_direction_t dir,
    variant_t *bor)
{
    operator_type_t oper = (dir == SORT_MODE_DESC) ? OPER_TYPE_SUB : OPER_TYPE_ADD;
    return opr_exec(oper, SESSION_NLS(stmt), sort_val, bor, bor);
}

static status_t mtrl_search_win_right_border(sql_stmt_t *stmt, mtrl_context_t *mtrl_ctx, mtrl_sort_cursor_t *sort_cur,
    variant_t *val, uint32 *rownum)
{
    bool32 found = CT_FALSE;
    status_t status = CT_SUCCESS;
    border_srch_assist_t srch_ass;

    win_init_bor_srch_assist(&srch_ass, val, (winsort_args_t *)sort_cur->segment->cmp_items, win_search_value_out_border);
    if (sql_mtrl_get_windowing_sort_val(sort_cur, srch_ass.id, srch_ass.datatype, &srch_ass.sort_val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (win_search_value_out_border(stmt, &srch_ass.sort_val, val, srch_ass.sort_mode, &found) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (found) {
        *rownum = sort_cur->rownum - 1;
        return CT_SUCCESS;
    }
    if (*rownum > sort_cur->rownum) {
        mtrl_sort_cursor_t search_cur;
        win_mtrl_init_search_cursor(&search_cur, sort_cur);
        if (win_mtrl_open_search_cursor(mtrl_ctx, &search_cur) != CT_SUCCESS) {
            return CT_ERROR;
        }
        status = win_mtrl_fetch_border_row(stmt, mtrl_ctx, &search_cur, &srch_ass, *rownum);
        *rownum = search_cur.rownum;
        win_mtrl_close_search_cursor(mtrl_ctx, &search_cur);
    }
    return status;
}

static status_t mtrl_search_win_left_border(sql_stmt_t *stmt, mtrl_context_t *ctx, mtrl_sort_cursor_t *search_cur,
    variant_t *val, uint32 rownum, uint32 *found)
{
    border_srch_assist_t srch_ass;

    win_init_bor_srch_assist(&srch_ass, val, (winsort_args_t *)search_cur->segment->cmp_items, win_search_value_in_border);
    CT_RETURN_IFERR(sql_mtrl_get_windowing_sort_val(search_cur, srch_ass.id, srch_ass.datatype, &srch_ass.sort_val));
    CT_RETURN_IFERR(win_search_value_in_border(stmt, &srch_ass.sort_val, val, srch_ass.sort_mode, found));
    if (*found || search_cur->rownum >= rownum) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(win_mtrl_fetch_border_row(stmt, ctx, search_cur, &srch_ass, rownum));
    if (search_cur->rownum < rownum) {
        *found = CT_TRUE;
        CT_RETURN_IFERR(mtrl_fetch_win_sort_row(ctx, search_cur, NULL, NULL));
    }
    return CT_SUCCESS;
}

static status_t sql_aggr_value_until_rborder(windowing_assist_t *win_ass, mtrl_cursor_t *mtrl_cur,
    mtrl_sort_cursor_t *sort_cur, variant_t *bor, const char *buf)
{
    mtrl_context_t *ctx = &win_ass->aa.stmt->mtrl;
    uint32 rownum = win_ass->part_rownum;
    bool32 eof = CT_FALSE;
    status_t status;
    mtrl_sort_cursor_t search_cur;

    win_mtrl_init_search_cursor(&search_cur, sort_cur);
    if (win_mtrl_open_search_cursor(ctx, &search_cur) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (mtrl_fetch_win_sort_row(ctx, &search_cur, NULL, &eof) != CT_SUCCESS) {
        win_mtrl_close_search_cursor(ctx, &search_cur);
        return CT_ERROR;
    }
    if (eof) {
        rownum = search_cur.rownum - 1;
    } else {
        if (mtrl_search_win_right_border(win_ass->aa.stmt, ctx, &search_cur, bor, &rownum)) {
            win_mtrl_close_search_cursor(ctx, &search_cur);
            return CT_ERROR;
        }
    }

    status = sql_win_aggr_value_until_row(win_ass, mtrl_cur, &search_cur, rownum, buf);
    win_mtrl_close_search_cursor(ctx, &search_cur);
    return status;
}

static status_t sql_aggr_value_between_borders(windowing_assist_t *win_ass, mtrl_cursor_t *mtrl_cur,
    mtrl_sort_cursor_t *sort_cur, uint32 temp_rownum, const char *buf)
{
    sql_stmt_t *stmt = win_ass->aa.stmt;
    mtrl_context_t *ctx = &stmt->mtrl;
    bool32 found = CT_FALSE;
    status_t status;
    mtrl_sort_cursor_t search_cur;
    uint32 rownum = temp_rownum;

    win_mtrl_init_search_cursor(&search_cur, sort_cur);
    if (win_mtrl_open_search_cursor(ctx, &search_cur) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (mtrl_fetch_win_sort_row(ctx, &search_cur, NULL, NULL) != CT_SUCCESS) {
        win_mtrl_close_search_cursor(ctx, &search_cur);
        return CT_ERROR;
    }
    if (mtrl_search_win_left_border(stmt, ctx, &search_cur, win_ass->l_var, rownum, &found)) {
        win_mtrl_close_search_cursor(ctx, &search_cur);
        return CT_ERROR;
    }
    if (found) {
        rownum = win_ass->part_rownum;
        if (mtrl_search_win_right_border(win_ass->aa.stmt, ctx, &search_cur, win_ass->r_var, &rownum)) {
            win_mtrl_close_search_cursor(ctx, &search_cur);
            return CT_ERROR;
        }
        status = sql_win_aggr_value_until_row(win_ass, mtrl_cur, &search_cur, rownum, buf);
    } else {
        status = sql_winsort_aggr_value_end(stmt, win_ass->aa.aggr_type, win_ass->qry_cur, win_ass->cur_aggr);
    }
    win_mtrl_close_search_cursor(ctx, &search_cur);
    return status;
}

static status_t sql_aggr_value_after_lborder(windowing_assist_t *win_ass, mtrl_cursor_t *mtrl_cur,
    mtrl_sort_cursor_t *sort_cur, uint32 rownum, const char *buf)
{
    sql_stmt_t *stmt = win_ass->aa.stmt;
    mtrl_context_t *ctx = &stmt->mtrl;
    bool32 found = CT_FALSE;
    status_t status;
    mtrl_sort_cursor_t search_cur;

    win_mtrl_init_search_cursor(&search_cur, sort_cur);
    if (win_mtrl_open_search_cursor(ctx, &search_cur) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (mtrl_fetch_win_sort_row(ctx, &search_cur, NULL, NULL) != CT_SUCCESS) {
        win_mtrl_close_search_cursor(ctx, &search_cur);
        return CT_ERROR;
    }
    if (mtrl_search_win_left_border(stmt, ctx, &search_cur, win_ass->l_var, rownum, &found)) {
        win_mtrl_close_search_cursor(ctx, &search_cur);
        return CT_ERROR;
    }
    if (found) {
        status = sql_win_aggr_value_until_row(win_ass, mtrl_cur, &search_cur, win_ass->part_rownum, buf);
    } else {
        status = sql_winsort_aggr_value_end(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur,
                                            win_ass->cur_aggr);
    }
    win_mtrl_close_search_cursor(ctx, &search_cur);
    return status;
}

static status_t sql_aggr_value_after_cur_row(windowing_assist_t *win_ass, mtrl_cursor_t *mtrl_cur,
    mtrl_sort_cursor_t *sort_cur, const char *buf)
{
    sql_stmt_t *stmt = win_ass->aa.stmt;
    mtrl_context_t *ctx = &stmt->mtrl;
    bool32 eof = CT_FALSE;
    status_t status;
    mtrl_sort_cursor_t search_cur;

    win_mtrl_init_search_cursor(&search_cur, sort_cur);
    if (win_mtrl_open_search_cursor(ctx, &search_cur) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (mtrl_fetch_win_sort_row(ctx, &search_cur, NULL, &eof) != CT_SUCCESS) {
        win_mtrl_close_search_cursor(ctx, &search_cur);
        return CT_ERROR;
    }

    if (eof) {
        status = sql_winsort_aggr_value_end(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur,
                                            win_ass->cur_aggr);
    } else {
        status = sql_win_aggr_value_until_row(win_ass, mtrl_cur, &search_cur, win_ass->part_rownum, buf);
    }
    win_mtrl_close_search_cursor(ctx, &search_cur);
    return status;
}

// for RANGE BETWEEN UNBOUNDED PRECEDING AND value PRECEDING
static inline status_t sql_windowing_aggr_range_up_vp(windowing_assist_t *win_ass,
                                                      sql_cursor_t *cursor, const char *buf)
{
    CT_RETURN_IFERR(sql_mtrl_get_windowing_value(&cursor->mtrl.cursor, win_ass->sort_val,
                                                 win_ass->l_var, win_ass->r_var));
    CT_RETURN_IFERR(sql_calc_win_pre_border(win_ass->aa.stmt, win_ass->sort_val,
                                            win_ass->sort_mode.direction, win_ass->r_var));
    CT_RETURN_IFERR(sql_aggr_value_until_rborder(win_ass, &cursor->mtrl.cursor,
                                                 &win_ass->part_cur, win_ass->r_var, buf));
    return sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur,
                                  &win_ass->cur_aggr, win_ass->datatype, &win_ass->rid,
                                  win_ass->winsort->argument);
}

// for RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
static inline status_t sql_windowing_aggr_range_up_cr(windowing_assist_t *win_ass, sql_cursor_t *cursor, const char *buf)
{
    CT_RETURN_IFERR(sql_win_aggr_curr_row(&win_ass->aa, win_ass->winsort->argument, win_ass->cur_aggr, buf));
    if (*win_ass->rownum >= win_ass->part_rownum) {
        CT_RETURN_IFERR(sql_winsort_aggr_value_end(win_ass->aa.stmt, win_ass->aa.aggr_type,
                                                   win_ass->qry_cur, win_ass->cur_aggr));
        return sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur,
                                      &win_ass->cur_aggr, win_ass->datatype, &win_ass->rid,
                                      win_ass->winsort->argument);
    }
    if (!win_ass->ord_chged) {
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(sql_copy_aggr(win_ass->aa.aggr_type, win_ass->cur_aggr, win_ass->tmp_aggr));
    CT_RETURN_IFERR(sql_winsort_aggr_value_end(win_ass->aa.stmt, win_ass->aa.aggr_type,
                                               win_ass->qry_cur, win_ass->cur_aggr));
    CT_RETURN_IFERR(sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type,
                                           win_ass->qry_cur, &win_ass->cur_aggr, win_ass->datatype,
                                           &win_ass->rid, win_ass->winsort->argument));
    return sql_copy_aggr(win_ass->aa.aggr_type, win_ass->tmp_aggr, win_ass->cur_aggr);
}

// for RANGE BETWEEN UNBOUNDED PRECEDING AND value FOLLOWING
static inline status_t sql_windowing_aggr_range_up_vf(windowing_assist_t *win_ass, sql_cursor_t *cursor,
                                                      const char *buf)
{
    CT_RETURN_IFERR(sql_win_aggr_curr_row(&win_ass->aa, win_ass->winsort->argument, win_ass->cur_aggr, buf));
    if (*win_ass->rownum >= win_ass->part_rownum) {
        CT_RETURN_IFERR(sql_winsort_aggr_value_end(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur,
                                                   win_ass->cur_aggr));
        return sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur,
                                      &win_ass->cur_aggr, win_ass->datatype, &win_ass->rid,
                                      win_ass->winsort->argument);
    }

    CT_RETURN_IFERR(sql_copy_aggr(win_ass->aa.aggr_type, win_ass->cur_aggr, win_ass->tmp_aggr));
    CT_RETURN_IFERR(sql_mtrl_get_windowing_value(&cursor->mtrl.cursor, win_ass->sort_val, win_ass->l_var,
                                                 win_ass->r_var));
    CT_RETURN_IFERR(sql_calc_win_fol_border(win_ass->aa.stmt, win_ass->sort_val,
                                            win_ass->sort_mode.direction, win_ass->r_var));
    CT_RETURN_IFERR(sql_aggr_value_until_rborder(win_ass, &cursor->mtrl.cursor, &cursor->mtrl.cursor.sort,
                                                 win_ass->r_var, buf));

    CT_RETURN_IFERR(sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur,
                                           &win_ass->cur_aggr, win_ass->datatype,
        &win_ass->rid, win_ass->winsort->argument));
    return sql_copy_aggr(win_ass->aa.aggr_type, win_ass->tmp_aggr, win_ass->cur_aggr);
}

// for RANGE BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
static inline status_t sql_windowing_aggr_range_up_uf(windowing_assist_t *win_ass, sql_cursor_t *cursor,
                                                      const char *buf)
{
    CT_RETURN_IFERR(sql_win_aggr_curr_row(&win_ass->aa, win_ass->winsort->argument, win_ass->cur_aggr, buf));
    if (*win_ass->rownum >= win_ass->part_rownum) {
        CT_RETURN_IFERR(sql_winsort_aggr_value_end(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur,
                                                   win_ass->cur_aggr));
        return sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, &win_ass->cur_aggr,
                                      win_ass->datatype, &win_ass->rid,
                                      win_ass->winsort->argument);
    }
    return CT_SUCCESS;
}

// for RANGE BETWEEN value PRECEDING AND value PRECEDING
static inline status_t sql_windowing_aggr_range_vp_vp(windowing_assist_t *win_ass, sql_cursor_t *cursor,
                                                      const char *buf)
{
    CT_RETURN_IFERR(sql_mtrl_get_windowing_value(&cursor->mtrl.cursor, win_ass->sort_val, win_ass->l_var,
                                                 win_ass->r_var));
    CT_RETURN_IFERR(sql_calc_win_pre_border(win_ass->aa.stmt, win_ass->sort_val, win_ass->sort_mode.direction,
                                            win_ass->l_var));
    CT_RETURN_IFERR(sql_calc_win_pre_border(win_ass->aa.stmt, win_ass->sort_val, win_ass->sort_mode.direction,
                                            win_ass->r_var));
    CT_RETURN_IFERR(sql_aggr_value_between_borders(win_ass, &cursor->mtrl.cursor, &win_ass->part_cur,
                                                   *win_ass->rownum, buf));
    return sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur,
                                  &win_ass->cur_aggr, win_ass->datatype, &win_ass->rid, win_ass->winsort->argument);
}

// for RANGE BETWEEN value PRECEDING AND CURRENT ROW
static inline status_t sql_windowing_aggr_range_vp_cr(windowing_assist_t *win_ass, sql_cursor_t *cursor,
                                                      const char *buf)
{
    CT_RETURN_IFERR(sql_mtrl_get_windowing_value(&cursor->mtrl.cursor, win_ass->sort_val, win_ass->l_var,
                                                 win_ass->r_var));
    CT_RETURN_IFERR(sql_calc_win_pre_border(win_ass->aa.stmt, win_ass->sort_val, win_ass->sort_mode.direction,
                                            win_ass->l_var));
    win_ass->r_var = win_ass->sort_val;
    CT_RETURN_IFERR(sql_aggr_value_between_borders(win_ass, &cursor->mtrl.cursor,
                                                   &win_ass->part_cur, *win_ass->rownum, buf));
    win_ass->r_var = NULL;
    return sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur,
                                  &win_ass->cur_aggr, win_ass->datatype, &win_ass->rid,
                                  win_ass->winsort->argument);
}

// for RANGE BETWEEN value PRECEDING AND value FOLLOWING
static inline status_t sql_windowing_aggr_range_vp_vf(windowing_assist_t *win_ass, sql_cursor_t *cursor,
                                                      const char *buf)
{
    CT_RETURN_IFERR(sql_mtrl_get_windowing_value(&cursor->mtrl.cursor, win_ass->sort_val, win_ass->l_var,
                                                 win_ass->r_var));
    CT_RETURN_IFERR(sql_calc_win_pre_border(win_ass->aa.stmt, win_ass->sort_val, win_ass->sort_mode.direction,
                                            win_ass->l_var));
    CT_RETURN_IFERR(sql_calc_win_fol_border(win_ass->aa.stmt, win_ass->sort_val, win_ass->sort_mode.direction,
                                            win_ass->r_var));
    CT_RETURN_IFERR(sql_aggr_value_between_borders(win_ass, &cursor->mtrl.cursor, &win_ass->part_cur,
                                                   *win_ass->rownum, buf));
    return sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur,
                                  &win_ass->cur_aggr, win_ass->datatype, &win_ass->rid,
                                  win_ass->winsort->argument);
}

// for RANGE BETWEEN value PRECEDING AND UNBOUNDED FOLLOWING
static inline status_t sql_windowing_aggr_range_vp_uf(windowing_assist_t *win_ass, sql_cursor_t *cursor,
                                                      const char *buf)
{
    CT_RETURN_IFERR(sql_mtrl_get_windowing_value(&cursor->mtrl.cursor, win_ass->sort_val, win_ass->l_var,
                                                 win_ass->r_var));
    CT_RETURN_IFERR(sql_calc_win_pre_border(win_ass->aa.stmt, win_ass->sort_val, win_ass->sort_mode.direction,
                                            win_ass->l_var));
    CT_RETURN_IFERR(sql_aggr_value_after_lborder(win_ass, &cursor->mtrl.cursor, &win_ass->part_cur,
                                                 *win_ass->rownum, buf));
    return sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, &win_ass->cur_aggr,
                                  win_ass->datatype, &win_ass->rid, win_ass->winsort->argument);
}

// for RANGE BETWEEN CURRENT ROW AND CURRENT ROW
static inline status_t sql_windowing_aggr_range_cr_cr(windowing_assist_t *win_ass, sql_cursor_t *cursor,
                                                      const char *buf)
{
    CT_RETURN_IFERR(sql_win_aggr_curr_row(&win_ass->aa, win_ass->winsort->argument,
                                          win_ass->cur_aggr, buf));
    if (*win_ass->rownum >= win_ass->part_rownum || win_ass->ord_chged) {
        CT_RETURN_IFERR(sql_winsort_aggr_value_end(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur,
                                                   win_ass->cur_aggr));
        return sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur,
                                      &win_ass->cur_aggr, win_ass->datatype, &win_ass->rid, win_ass->winsort->argument);
    }
    return CT_SUCCESS;
}

// for RANGE BETWEEN CURRENT ROW AND value FOLLOWING
static inline status_t sql_windowing_aggr_range_cr_vf(windowing_assist_t *win_ass, sql_cursor_t *cursor,
                                                      const char *buf)
{
    CT_RETURN_IFERR(sql_win_aggr_curr_row(&win_ass->aa, win_ass->winsort->argument, win_ass->cur_aggr, buf));
    if (*win_ass->rownum >= win_ass->part_rownum) {
        CT_RETURN_IFERR(sql_winsort_aggr_value_end(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur,
                                                   win_ass->cur_aggr));
        return sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur,
                                      &win_ass->cur_aggr, win_ass->datatype, &win_ass->rid, win_ass->winsort->argument);
    }
    if (!win_ass->ord_chged) {
        CT_RETURN_IFERR(sql_copy_aggr(win_ass->aa.aggr_type, win_ass->cur_aggr, win_ass->tmp_aggr));
    }
    CT_RETURN_IFERR(sql_mtrl_get_windowing_value(&cursor->mtrl.cursor, win_ass->sort_val, win_ass->l_var,
                                                 win_ass->r_var));
    CT_RETURN_IFERR(sql_calc_win_fol_border(win_ass->aa.stmt, win_ass->sort_val, win_ass->sort_mode.direction,
                                            win_ass->r_var));
    CT_RETURN_IFERR(sql_aggr_value_until_rborder(win_ass, &cursor->mtrl.cursor, &cursor->mtrl.cursor.sort,
                                                 win_ass->r_var, buf));

    CT_RETURN_IFERR(sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur,
                                           &win_ass->cur_aggr, win_ass->datatype,
                                           &win_ass->rid, win_ass->winsort->argument));
    if (!win_ass->ord_chged) {
        return sql_copy_aggr(win_ass->aa.aggr_type, win_ass->tmp_aggr, win_ass->cur_aggr);
    }
    return CT_SUCCESS;
}

// for RANGE BETWEEN CURRENT ROW AND UNBOUNDED FOLLOWING
static inline status_t sql_windowing_aggr_range_cr_uf(windowing_assist_t *win_ass, sql_cursor_t *cursor,
                                                      const char *buf)
{
    CT_RETURN_IFERR(sql_win_aggr_curr_row(&win_ass->aa, win_ass->winsort->argument, win_ass->cur_aggr, buf));
    if (*win_ass->rownum >= win_ass->part_rownum) {
        CT_RETURN_IFERR(sql_winsort_aggr_value_end(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur,
                                                   win_ass->cur_aggr));
        return sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, &win_ass->cur_aggr,
                                      win_ass->datatype, &win_ass->rid, win_ass->winsort->argument);
    }
    if (!win_ass->ord_chged) {
        CT_RETURN_IFERR(sql_copy_aggr(win_ass->aa.aggr_type, win_ass->cur_aggr, win_ass->tmp_aggr));
    }
    CT_RETURN_IFERR(sql_aggr_value_after_cur_row(win_ass, &cursor->mtrl.cursor, &cursor->mtrl.cursor.sort, buf));
    CT_RETURN_IFERR(sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur,
                                           &win_ass->cur_aggr, win_ass->datatype,
                                           &win_ass->rid, win_ass->winsort->argument));
    if (!win_ass->ord_chged) {
        return sql_copy_aggr(win_ass->aa.aggr_type, win_ass->tmp_aggr, win_ass->cur_aggr);
    }
    return CT_SUCCESS;
}

// for RANGE BETWEEN value FOLLOWING AND value FOLLOWING
static inline status_t sql_windowing_aggr_range_vf_vf(windowing_assist_t *win_ass, sql_cursor_t *cursor,
                                                      const char *buf)
{
    CT_RETURN_IFERR(sql_mtrl_get_windowing_value(&cursor->mtrl.cursor, win_ass->sort_val, win_ass->l_var,
                                                 win_ass->r_var));
    CT_RETURN_IFERR(sql_calc_win_fol_border(win_ass->aa.stmt, win_ass->sort_val, win_ass->sort_mode.direction,
                                            win_ass->l_var));
    CT_RETURN_IFERR(sql_calc_win_fol_border(win_ass->aa.stmt, win_ass->sort_val, win_ass->sort_mode.direction,
                                            win_ass->r_var));
    CT_RETURN_IFERR(sql_aggr_value_between_borders(win_ass, &cursor->mtrl.cursor, &win_ass->part_cur,
                                                   win_ass->part_rownum, buf));
    return sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur,
                                  &win_ass->cur_aggr, win_ass->datatype, &win_ass->rid,
                                  win_ass->winsort->argument);
}

// for RANGE BETWEEN value FOLLOWING AND UNBOUNED FOLLOWING
static inline status_t sql_windowing_aggr_range_vf_uf(windowing_assist_t *win_ass, sql_cursor_t *cursor,
                                                      const char *buf)
{
    CT_RETURN_IFERR(sql_mtrl_get_windowing_value(&cursor->mtrl.cursor, win_ass->sort_val, win_ass->l_var,
                                                 win_ass->r_var));
    CT_RETURN_IFERR(sql_calc_win_fol_border(win_ass->aa.stmt, win_ass->sort_val, win_ass->sort_mode.direction,
                                            win_ass->l_var));
    CT_RETURN_IFERR(sql_aggr_value_after_lborder(win_ass, &cursor->mtrl.cursor, &win_ass->part_cur,
                                                 win_ass->part_rownum, buf));
    return sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur,
                                  &win_ass->cur_aggr, win_ass->datatype, &win_ass->rid,
                                  win_ass->winsort->argument);
}

static windowing_funcs_t g_windowing_range_funcs[WB_TYPE_UNBOUNDED_FOLLOW + 1][WB_TYPE_UNBOUNDED_FOLLOW + 1] = {
    [WB_TYPE_UNBOUNDED_PRECED][WB_TYPE_VALUE_PRECED] = { .invoke = sql_windowing_aggr_range_up_vp },
    [WB_TYPE_UNBOUNDED_PRECED][WB_TYPE_CURRENT_ROW] = { .invoke = sql_windowing_aggr_range_up_cr },
    [WB_TYPE_UNBOUNDED_PRECED][WB_TYPE_VALUE_FOLLOW] = { .invoke = sql_windowing_aggr_range_up_vf },
    [WB_TYPE_UNBOUNDED_PRECED][WB_TYPE_UNBOUNDED_FOLLOW] = { .invoke = sql_windowing_aggr_range_up_uf },

    [WB_TYPE_VALUE_PRECED][WB_TYPE_VALUE_PRECED] = { .invoke = sql_windowing_aggr_range_vp_vp },
    [WB_TYPE_VALUE_PRECED][WB_TYPE_CURRENT_ROW] = { .invoke = sql_windowing_aggr_range_vp_cr },
    [WB_TYPE_VALUE_PRECED][WB_TYPE_VALUE_FOLLOW] = { .invoke = sql_windowing_aggr_range_vp_vf },
    [WB_TYPE_VALUE_PRECED][WB_TYPE_UNBOUNDED_FOLLOW] = { .invoke = sql_windowing_aggr_range_vp_uf },

    [WB_TYPE_CURRENT_ROW][WB_TYPE_CURRENT_ROW] = { .invoke = sql_windowing_aggr_range_cr_cr },
    [WB_TYPE_CURRENT_ROW][WB_TYPE_VALUE_FOLLOW] = { .invoke = sql_windowing_aggr_range_cr_vf },
    [WB_TYPE_CURRENT_ROW][WB_TYPE_UNBOUNDED_FOLLOW] = { .invoke = sql_windowing_aggr_range_cr_uf },

    [WB_TYPE_VALUE_FOLLOW][WB_TYPE_VALUE_FOLLOW] = { .invoke = sql_windowing_aggr_range_vf_vf },
    [WB_TYPE_VALUE_FOLLOW][WB_TYPE_UNBOUNDED_FOLLOW] = { .invoke = sql_windowing_aggr_range_vf_uf }
};


static inline status_t sql_calc_win_pre_border_rownum(sql_stmt_t *stmt, uint32 row_num, variant_t *bor)
{
    CT_RETURN_IFERR(var_as_floor_uint32(bor));
    int64 bigint = (int64)row_num - (int64)bor->v_uint32;
    if (bigint < 0) {
        bor->v_uint32 = 0;
    } else {
        bor->v_uint32 = (uint32)bigint;
    }
    return CT_SUCCESS;
}

static inline status_t sql_calc_win_fol_border_rownum(sql_stmt_t *stmt, uint32 row_num, variant_t *bor)
{
    CT_RETURN_IFERR(var_as_floor_uint32(bor));
    int64 bigint = (int64)row_num + (int64)bor->v_uint32;
    if (bigint < 0 || bigint > CT_MAX_UINT32) {
        bor->v_uint32 = CT_MAX_UINT32;
    } else {
        bor->v_uint32 = (uint32)bigint;
    }
    return CT_SUCCESS;
}

static inline status_t win_mtrl_search_cur_to_rownum(mtrl_context_t *ctx, mtrl_sort_cursor_t *sort, uint32 row_num,
    bool32 *eof)
{
    status_t status;
    do {
        status = mtrl_fetch_win_sort_row(ctx, sort, NULL, eof);
        if (*eof || status != CT_SUCCESS) {
            break;
        }
    } while (sort->rownum < row_num);
    return status;
}

static status_t sql_aggr_value_until_rownum(windowing_assist_t *win_ass, mtrl_cursor_t *mtrl_cur,
    mtrl_sort_cursor_t *sort_cur, uint32 temp_rownum, const char *buf)
{
    mtrl_context_t *ctx = &win_ass->aa.stmt->mtrl;
    bool32 eof = CT_FALSE;
    status_t status;
    mtrl_sort_cursor_t search_cur;
    uint32 rownum = temp_rownum;

    win_mtrl_init_search_cursor(&search_cur, sort_cur);
    if (win_mtrl_open_search_cursor(ctx, &search_cur) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (mtrl_fetch_win_sort_row(ctx, &search_cur, NULL, &eof) != CT_SUCCESS) {
        win_mtrl_close_search_cursor(ctx, &search_cur);
        return CT_ERROR;
    }
    if (eof) {
        rownum = search_cur.rownum - 1;
    }
    status = sql_win_aggr_value_until_row(win_ass, mtrl_cur, &search_cur, MIN(rownum, win_ass->part_rownum), buf);
    win_mtrl_close_search_cursor(ctx, &search_cur);
    return status;
}

static status_t sql_aggr_value_between_rownums(windowing_assist_t *win_ass, mtrl_cursor_t *mtrl_cur,
    mtrl_sort_cursor_t *sort_cur, uint32 lnum, uint32 rnum, const char *buf)
{
    mtrl_context_t *ctx = &win_ass->aa.stmt->mtrl;
    bool32 eof = CT_FALSE;
    status_t status;
    mtrl_sort_cursor_t search_cur;

    win_mtrl_init_search_cursor(&search_cur, sort_cur);
    if (win_mtrl_open_search_cursor(ctx, &search_cur) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (win_mtrl_search_cur_to_rownum(ctx, &search_cur, lnum, &eof) != CT_SUCCESS) {
        win_mtrl_close_search_cursor(ctx, &search_cur);
        return CT_ERROR;
    }
    if (lnum <= search_cur.rownum) {
        status = sql_win_aggr_value_until_row(win_ass, mtrl_cur, &search_cur, MIN(rnum, win_ass->part_rownum), buf);
    } else {
        status = sql_winsort_aggr_value_end(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, win_ass->cur_aggr);
    }
    win_mtrl_close_search_cursor(ctx, &search_cur);
    return status;
}

// for ROWS BETWEEN UNBOUNDED PRECEDING AND value PRECEDING
static inline status_t sql_windowing_aggr_rows_up_vp(windowing_assist_t *win_ass, sql_cursor_t *cursor, const char *buf)
{
    CT_RETURN_IFERR(sql_mtrl_get_windowing_border(&cursor->mtrl.cursor, win_ass->l_var, win_ass->r_var));
    CT_RETURN_IFERR(sql_calc_win_pre_border_rownum(win_ass->aa.stmt, *win_ass->rownum, win_ass->r_var));
    CT_RETURN_IFERR(sql_aggr_value_until_rownum(win_ass, &cursor->mtrl.cursor, &win_ass->part_cur, win_ass->r_var->v_uint32, buf));
    return sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, &win_ass->cur_aggr, win_ass->datatype, &win_ass->rid,
        win_ass->winsort->argument);
}

// for ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
static inline status_t sql_windowing_aggr_rows_up_cr(windowing_assist_t *win_ass, sql_cursor_t *cursor, const char *buf)
{
    CT_RETURN_IFERR(sql_win_aggr_curr_row(&win_ass->aa, win_ass->winsort->argument, win_ass->cur_aggr, buf));
    if (win_ass->part_rownum <= *win_ass->rownum) {
        CT_RETURN_IFERR(sql_winsort_aggr_value_end(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, win_ass->cur_aggr));
        return sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, &win_ass->cur_aggr, win_ass->datatype, &win_ass->rid,
            win_ass->winsort->argument);
    }
    CT_RETURN_IFERR(sql_copy_aggr(win_ass->aa.aggr_type, win_ass->cur_aggr, win_ass->tmp_aggr));
    CT_RETURN_IFERR(sql_winsort_aggr_value_end(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, win_ass->cur_aggr));
    CT_RETURN_IFERR(sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, &win_ass->cur_aggr, win_ass->datatype,
        &win_ass->rid, win_ass->winsort->argument));
    return sql_copy_aggr(win_ass->aa.aggr_type, win_ass->tmp_aggr, win_ass->cur_aggr);
}

// for ROWS BETWEEN UNBOUNDED PRECEDING AND value FOLLOWING
static inline status_t sql_windowing_aggr_rows_up_vf(windowing_assist_t *win_ass, sql_cursor_t *cursor, const char *buf)
{
    CT_RETURN_IFERR(sql_win_aggr_curr_row(&win_ass->aa, win_ass->winsort->argument, win_ass->cur_aggr, buf));
    if (win_ass->part_rownum <= *win_ass->rownum) {
        CT_RETURN_IFERR(sql_winsort_aggr_value_end(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, win_ass->cur_aggr));
        return sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, &win_ass->cur_aggr, win_ass->datatype, &win_ass->rid,
            win_ass->winsort->argument);
    }

    CT_RETURN_IFERR(sql_copy_aggr(win_ass->aa.aggr_type, win_ass->cur_aggr, win_ass->tmp_aggr));
    CT_RETURN_IFERR(sql_mtrl_get_windowing_border(&cursor->mtrl.cursor, win_ass->l_var, win_ass->r_var));
    CT_RETURN_IFERR(sql_calc_win_fol_border_rownum(win_ass->aa.stmt, *win_ass->rownum, win_ass->r_var));
    CT_RETURN_IFERR(
        sql_aggr_value_until_rownum(win_ass, &cursor->mtrl.cursor, &cursor->mtrl.cursor.sort, win_ass->r_var->v_uint32, buf));

    CT_RETURN_IFERR(sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, &win_ass->cur_aggr, win_ass->datatype,
        &win_ass->rid, win_ass->winsort->argument));
    return sql_copy_aggr(win_ass->aa.aggr_type, win_ass->tmp_aggr, win_ass->cur_aggr);
}

// for ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
static inline status_t sql_windowing_aggr_rows_up_uf(windowing_assist_t *win_ass, sql_cursor_t *cursor, const char *buf)
{
    CT_RETURN_IFERR(sql_win_aggr_curr_row(&win_ass->aa, win_ass->winsort->argument, win_ass->cur_aggr, buf));
    if (win_ass->part_rownum <= *win_ass->rownum) {
        CT_RETURN_IFERR(sql_winsort_aggr_value_end(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, win_ass->cur_aggr));
        return sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, &win_ass->cur_aggr, win_ass->datatype, &win_ass->rid,
            win_ass->winsort->argument);
    }
    return CT_SUCCESS;
}

// for ROWS BETWEEN value PRECEDING AND value PRECEDING
static inline status_t sql_windowing_aggr_rows_vp_vp(windowing_assist_t *win_ass, sql_cursor_t *cursor, const char *buf)
{
    CT_RETURN_IFERR(sql_mtrl_get_windowing_border(&cursor->mtrl.cursor, win_ass->l_var, win_ass->r_var));
    CT_RETURN_IFERR(sql_calc_win_pre_border_rownum(win_ass->aa.stmt, *win_ass->rownum, win_ass->l_var));
    CT_RETURN_IFERR(sql_calc_win_pre_border_rownum(win_ass->aa.stmt, *win_ass->rownum, win_ass->r_var));
    CT_RETURN_IFERR(sql_aggr_value_between_rownums(win_ass, &cursor->mtrl.cursor, &win_ass->part_cur, win_ass->l_var->v_uint32,
        win_ass->r_var->v_uint32, buf));
    return sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, &win_ass->cur_aggr, win_ass->datatype, &win_ass->rid,
        win_ass->winsort->argument);
}

// for ROWS BETWEEN value PRECEDING AND CURRENT ROW
static inline status_t sql_windowing_aggr_rows_vp_cr(windowing_assist_t *win_ass, sql_cursor_t *cursor, const char *buf)
{
    CT_RETURN_IFERR(sql_mtrl_get_windowing_border(&cursor->mtrl.cursor, win_ass->l_var, win_ass->r_var));
    CT_RETURN_IFERR(sql_calc_win_pre_border_rownum(win_ass->aa.stmt, *win_ass->rownum, win_ass->l_var));
    CT_RETURN_IFERR(
        sql_aggr_value_between_rownums(win_ass, &cursor->mtrl.cursor, &win_ass->part_cur, win_ass->l_var->v_uint32, *win_ass->rownum, buf));
    return sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, &win_ass->cur_aggr, win_ass->datatype, &win_ass->rid,
        win_ass->winsort->argument);
}

// for ROWS BETWEEN value PRECEDING AND value FOLLOWING
static inline status_t sql_windowing_aggr_rows_vp_vf(windowing_assist_t *win_ass, sql_cursor_t *cursor, const char *buf)
{
    CT_RETURN_IFERR(sql_mtrl_get_windowing_border(&cursor->mtrl.cursor, win_ass->l_var, win_ass->r_var));
    CT_RETURN_IFERR(sql_calc_win_pre_border_rownum(win_ass->aa.stmt, *win_ass->rownum, win_ass->l_var));
    CT_RETURN_IFERR(sql_calc_win_fol_border_rownum(win_ass->aa.stmt, *win_ass->rownum, win_ass->r_var));
    CT_RETURN_IFERR(sql_aggr_value_between_rownums(win_ass, &cursor->mtrl.cursor, &win_ass->part_cur, win_ass->l_var->v_uint32,
        win_ass->r_var->v_uint32, buf));
    return sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, &win_ass->cur_aggr, win_ass->datatype, &win_ass->rid,
        win_ass->winsort->argument);
}

// for ROWS BETWEEN value PRECEDING AND UNBOUNDED FOLLOWING
static inline status_t sql_windowing_aggr_rows_vp_uf(windowing_assist_t *win_ass, sql_cursor_t *cursor, const char *buf)
{
    CT_RETURN_IFERR(sql_mtrl_get_windowing_border(&cursor->mtrl.cursor, win_ass->l_var, win_ass->r_var));
    CT_RETURN_IFERR(sql_calc_win_pre_border_rownum(win_ass->aa.stmt, *win_ass->rownum, win_ass->l_var));
    CT_RETURN_IFERR(sql_aggr_value_between_rownums(win_ass, &cursor->mtrl.cursor, &win_ass->part_cur, win_ass->l_var->v_uint32,
        win_ass->part_rownum, buf));
    return sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, &win_ass->cur_aggr, win_ass->datatype, &win_ass->rid,
        win_ass->winsort->argument);
}

// for ROWS BETWEEN CURRENT ROW AND CURRENT ROW
static inline status_t sql_windowing_aggr_rows_cr_cr(windowing_assist_t *win_ass, sql_cursor_t *cursor, const char *buf)
{
    CT_RETURN_IFERR(sql_win_aggr_curr_row(&win_ass->aa, win_ass->winsort->argument, win_ass->cur_aggr, buf));
    CT_RETURN_IFERR(sql_winsort_aggr_value_end(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, win_ass->cur_aggr));
    return sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, &win_ass->cur_aggr, win_ass->datatype, &win_ass->rid,
        win_ass->winsort->argument);
}

// for ROWS BETWEEN CURRENT ROW AND value FOLLOWING
static inline status_t sql_windowing_aggr_rows_cr_vf(windowing_assist_t *win_ass, sql_cursor_t *cursor, const char *buf)
{
    CT_RETURN_IFERR(sql_mtrl_get_windowing_border(&cursor->mtrl.cursor, win_ass->l_var, win_ass->r_var));
    CT_RETURN_IFERR(sql_calc_win_fol_border_rownum(win_ass->aa.stmt, *win_ass->rownum, win_ass->r_var));
    CT_RETURN_IFERR(sql_win_aggr_curr_row(&win_ass->aa, win_ass->winsort->argument, win_ass->cur_aggr, buf));
    if (win_ass->part_rownum <= *win_ass->rownum) {
        CT_RETURN_IFERR(sql_winsort_aggr_value_end(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, win_ass->cur_aggr));
    } else {
        CT_RETURN_IFERR(
            sql_aggr_value_until_rownum(win_ass, &cursor->mtrl.cursor, &cursor->mtrl.cursor.sort, win_ass->r_var->v_uint32, buf));
    }
    return sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, &win_ass->cur_aggr, win_ass->datatype, &win_ass->rid,
        win_ass->winsort->argument);
}

// for ROWS BETWEEN CURRENT ROW AND UNBOUNDED FOLLOWING
static inline status_t sql_windowing_aggr_rows_cr_uf(windowing_assist_t *win_ass, sql_cursor_t *cursor, const char *buf)
{
    CT_RETURN_IFERR(sql_win_aggr_curr_row(&win_ass->aa, win_ass->winsort->argument, win_ass->cur_aggr, buf));
    if (win_ass->part_rownum <= *win_ass->rownum) {
        CT_RETURN_IFERR(sql_winsort_aggr_value_end(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, win_ass->cur_aggr));
    } else {
        CT_RETURN_IFERR(
            sql_aggr_value_until_rownum(win_ass, &cursor->mtrl.cursor, &cursor->mtrl.cursor.sort, win_ass->part_rownum, buf));
    }
    return sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, &win_ass->cur_aggr, win_ass->datatype, &win_ass->rid,
        win_ass->winsort->argument);
}

// for ROWS BETWEEN value FOLLOWING AND value FOLLOWING
static inline status_t sql_windowing_aggr_rows_vf_vf(windowing_assist_t *win_ass, sql_cursor_t *cursor, const char *buf)
{
    CT_RETURN_IFERR(sql_mtrl_get_windowing_border(&cursor->mtrl.cursor, win_ass->l_var, win_ass->r_var));
    CT_RETURN_IFERR(sql_calc_win_fol_border_rownum(win_ass->aa.stmt, *win_ass->rownum, win_ass->l_var));
    CT_RETURN_IFERR(sql_calc_win_fol_border_rownum(win_ass->aa.stmt, *win_ass->rownum, win_ass->r_var));
    if (*win_ass->rownum == win_ass->l_var->v_uint32) {
        CT_RETURN_IFERR(sql_win_aggr_curr_row(&win_ass->aa, win_ass->winsort->argument, win_ass->cur_aggr, buf));
        if (win_ass->part_rownum <= *win_ass->rownum) {
            CT_RETURN_IFERR(sql_winsort_aggr_value_end(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, win_ass->cur_aggr));
        } else {
            CT_RETURN_IFERR(sql_aggr_value_until_rownum(win_ass, &cursor->mtrl.cursor, &cursor->mtrl.cursor.sort,
                win_ass->r_var->v_uint32, buf));
        }
    } else {
        if (win_ass->part_rownum <= *win_ass->rownum) {
            CT_RETURN_IFERR(sql_winsort_aggr_value_end(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, win_ass->cur_aggr));
        } else {
            CT_RETURN_IFERR(sql_aggr_value_between_rownums(win_ass, &cursor->mtrl.cursor, &cursor->mtrl.cursor.sort,
                win_ass->l_var->v_uint32, win_ass->r_var->v_uint32, buf));
        }
    }
    return sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, &win_ass->cur_aggr, win_ass->datatype, &win_ass->rid,
        win_ass->winsort->argument);
}

// for ROWS BETWEEN value FOLLOWING AND UNBOUNED FOLLOWING
static inline status_t sql_windowing_aggr_rows_vf_uf(windowing_assist_t *win_ass, sql_cursor_t *cursor, const char *buf)
{
    CT_RETURN_IFERR(sql_mtrl_get_windowing_border(&cursor->mtrl.cursor, win_ass->l_var, win_ass->r_var));
    CT_RETURN_IFERR(sql_calc_win_fol_border_rownum(win_ass->aa.stmt, *win_ass->rownum, win_ass->l_var));
    if (*win_ass->rownum == win_ass->l_var->v_uint32) {
        CT_RETURN_IFERR(sql_win_aggr_curr_row(&win_ass->aa, win_ass->winsort->argument, win_ass->cur_aggr, buf));
        if (win_ass->part_rownum <= *win_ass->rownum) {
            CT_RETURN_IFERR(sql_winsort_aggr_value_end(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, win_ass->cur_aggr));
        } else {
            CT_RETURN_IFERR(
                sql_aggr_value_until_rownum(win_ass, &cursor->mtrl.cursor, &cursor->mtrl.cursor.sort, win_ass->part_rownum, buf));
        }
    } else {
        if (win_ass->part_rownum <= *win_ass->rownum) {
            CT_RETURN_IFERR(sql_winsort_aggr_value_end(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, win_ass->cur_aggr));
        } else {
            CT_RETURN_IFERR(sql_aggr_value_between_rownums(win_ass, &cursor->mtrl.cursor, &cursor->mtrl.cursor.sort,
                win_ass->l_var->v_uint32, win_ass->part_rownum, buf));
        }
    }
    return sql_win_aggr_var_alloc(win_ass->aa.stmt, win_ass->aa.aggr_type, win_ass->qry_cur, &win_ass->cur_aggr, win_ass->datatype, &win_ass->rid,
        win_ass->winsort->argument);
}

static windowing_funcs_t g_windowing_rows_funcs[WB_TYPE_UNBOUNDED_FOLLOW + 1][WB_TYPE_UNBOUNDED_FOLLOW + 1] = {
    [WB_TYPE_UNBOUNDED_PRECED][WB_TYPE_VALUE_PRECED] = { .invoke = sql_windowing_aggr_rows_up_vp },
    [WB_TYPE_UNBOUNDED_PRECED][WB_TYPE_CURRENT_ROW] = { .invoke = sql_windowing_aggr_rows_up_cr },
    [WB_TYPE_UNBOUNDED_PRECED][WB_TYPE_VALUE_FOLLOW] = { .invoke = sql_windowing_aggr_rows_up_vf },
    [WB_TYPE_UNBOUNDED_PRECED][WB_TYPE_UNBOUNDED_FOLLOW] = { .invoke = sql_windowing_aggr_rows_up_uf },

    [WB_TYPE_VALUE_PRECED][WB_TYPE_VALUE_PRECED] = { .invoke = sql_windowing_aggr_rows_vp_vp },
    [WB_TYPE_VALUE_PRECED][WB_TYPE_CURRENT_ROW] = { .invoke = sql_windowing_aggr_rows_vp_cr },
    [WB_TYPE_VALUE_PRECED][WB_TYPE_VALUE_FOLLOW] = { .invoke = sql_windowing_aggr_rows_vp_vf },
    [WB_TYPE_VALUE_PRECED][WB_TYPE_UNBOUNDED_FOLLOW] = { .invoke = sql_windowing_aggr_rows_vp_uf },

    [WB_TYPE_CURRENT_ROW][WB_TYPE_CURRENT_ROW] = { .invoke = sql_windowing_aggr_rows_cr_cr },
    [WB_TYPE_CURRENT_ROW][WB_TYPE_VALUE_FOLLOW] = { .invoke = sql_windowing_aggr_rows_cr_vf },
    [WB_TYPE_CURRENT_ROW][WB_TYPE_UNBOUNDED_FOLLOW] = { .invoke = sql_windowing_aggr_rows_cr_uf },

    [WB_TYPE_VALUE_FOLLOW][WB_TYPE_VALUE_FOLLOW] = { .invoke = sql_windowing_aggr_rows_vf_vf },
    [WB_TYPE_VALUE_FOLLOW][WB_TYPE_UNBOUNDED_FOLLOW] = { .invoke = sql_windowing_aggr_rows_vf_uf }
};

static status_t sql_windowing_assist_init(windowing_assist_t *win_ass, sql_cursor_t *cursor, plan_node_t *plan,
    sql_aggr_type_t type, bool32 is_range)
{
    sql_stmt_t *stmt = cursor->stmt;
    expr_tree_t *func_expr = plan->winsort_p.winsort->argument;
    uint32 l_type = plan->winsort_p.winsort->win_args->windowing->l_type;
    uint32 r_type = plan->winsort_p.winsort->win_args->windowing->r_type;

    SQL_INIT_AGGR_ASSIST(&win_ass->aa, stmt, NULL);
    win_ass->aa.aggr_type = type;
    win_ass->aa.aggr_node = plan->winsort_p.winsort->argument->root;
    win_ass->winsort = plan->winsort_p.winsort;
    win_ass->win_func = (is_range) ? &g_windowing_range_funcs[l_type][r_type] : &g_windowing_rows_funcs[l_type][r_type];
    win_ass->datatype = func_expr->root->datatype;
    win_ass->rownum = &cursor->mtrl.cursor.sort.rownum;
    win_ass->grp_chged = CT_FALSE;
    win_ass->ord_chged = CT_FALSE;
    win_ass->part_rownum = 0;
    win_ass->sort_mode.direction = SORT_MODE_ASC;
    win_ass->sort_mode.nulls_pos = SORT_NULLS_LAST;
    win_ass->sort_val = NULL;
    win_mtrl_init_search_cursor(&win_ass->part_cur, &cursor->mtrl.cursor.sort);
    CT_RETURN_IFERR(sql_winsort_get_aggr_type(stmt, cursor, type, win_ass->winsort->argument, &win_ass->datatype));
    CT_RETURN_IFERR(sql_win_aggr_var_alloc(stmt, type, win_ass->qry_cur, &win_ass->cur_aggr, win_ass->datatype, &win_ass->rid, func_expr));
    // alloc for left and right range
    if ((l_type & WB_TYPE_VALUE_PRECED) == WB_TYPE_VALUE_PRECED) {
        CT_RETURN_IFERR(sql_push(stmt, sizeof(variant_t), (void **)&win_ass->l_var));
    } else {
        win_ass->l_var = NULL;
    }
    if ((r_type & WB_TYPE_VALUE_PRECED) == WB_TYPE_VALUE_PRECED) {
        CT_RETURN_IFERR(sql_push(stmt, sizeof(variant_t), (void **)&win_ass->r_var));
    } else {
        win_ass->r_var = NULL;
    }
    CT_RETURN_IFERR(sql_stack_alloc_aggr_var(stmt, type, (void **)&win_ass->tmp_aggr));
    return sql_win_get_next_partion_rownum(&cursor->stmt->mtrl, &cursor->mtrl.cursor.sort, &win_ass->part_rownum);
}

static inline status_t sql_windowing_assist_init_range(windowing_assist_t *win_ass, sql_cursor_t *cursor,
    sql_cursor_t *query_cursor, plan_node_t *plan, sql_aggr_type_t type)
{
    sort_item_t *item = (sort_item_t *)cm_galist_get(plan->winsort_p.winsort->win_args->sort_items, 0);

    win_ass->qry_cur = query_cursor;
    CT_RETURN_IFERR(sql_windowing_assist_init(win_ass, cursor, plan, type, CT_TRUE));
    win_ass->sort_mode = item->sort_mode;
    return sql_push(cursor->stmt, sizeof(variant_t), (void **)&win_ass->sort_val);
}

status_t sql_func_winsort_aggr_range(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, sql_aggr_type_t type,
    const char *buf)
{
    windowing_assist_t win_ass;
    mtrl_row_t *row = NULL;
    sql_cursor_t *query_cursor = CTSQL_CURR_CURSOR(stmt);
    uint32 rs_col_id = VALUE(uint32, &plan->winsort_p.winsort->value);
    status_t status = CT_ERROR;

    CT_RETURN_IFERR(mtrl_open_cursor(&stmt->mtrl, cursor->mtrl.winsort_sort.sid, &cursor->mtrl.cursor));
    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));
    CTSQL_SAVE_STACK(stmt);
    CT_RETURN_IFERR(sql_windowing_assist_init_range(&win_ass, cursor, query_cursor, plan, type));
    for (;;) {
        SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt);
        CT_BREAK_IF_ERROR(mtrl_fetch_winsort_rid(&stmt->mtrl, &cursor->mtrl.cursor, WINSORT_PART | WINSORT_ORDER,
            &win_ass.grp_chged, &win_ass.ord_chged));
        if (cursor->mtrl.cursor.eof) {
            status = sql_winsort_aggr_value_end(stmt, type, query_cursor, win_ass.cur_aggr);
            break;
        }

        row = &cursor->mtrl.cursor.row;
        if (row->lens[rs_col_id] != sizeof(mtrl_rowid_t)) {
            CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "row->lens[rs_col_id](%u) == sizeof(mtrl_rowid_t)(%u)",
                (uint32)row->lens[rs_col_id], (uint32)sizeof(mtrl_rowid_t));
            break;
        }
        *(mtrl_rowid_t *)(row->data + row->offsets[rs_col_id]) = win_ass.rid;
        CT_BREAK_IF_ERROR(win_ass.win_func->invoke(&win_ass, cursor, buf));
        if (win_ass.part_rownum <= *win_ass.rownum) {
            win_mtrl_init_search_cursor(&win_ass.part_cur, &cursor->mtrl.cursor.sort);
            CT_BREAK_IF_ERROR(sql_win_get_next_partion_rownum(&stmt->mtrl, &win_ass.part_cur, &win_ass.part_rownum));
        }
    }

    CTSQL_RESTORE_STACK(stmt);
    SQL_CURSOR_POP(stmt);
    mtrl_close_cursor(&stmt->mtrl, &cursor->mtrl.cursor);
    return status;
}

static inline status_t sql_windowing_assist_init_rows(windowing_assist_t *win_ass, sql_cursor_t *cursor,
    sql_cursor_t *query_cursor, plan_node_t *plan, sql_aggr_type_t type)
{
    win_ass->qry_cur = query_cursor;
    return sql_windowing_assist_init(win_ass, cursor, plan, type, CT_FALSE);
}

status_t sql_func_winsort_aggr_rows(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, sql_aggr_type_t type,
    const char *buf)
{
    windowing_assist_t win_ass;
    mtrl_row_t *row = NULL;
    sql_cursor_t *query_cursor = CTSQL_CURR_CURSOR(stmt);
    uint32 rs_col_id = VALUE(uint32, &plan->winsort_p.winsort->value);
    status_t status = CT_ERROR;

    CT_RETURN_IFERR(mtrl_open_cursor(&stmt->mtrl, cursor->mtrl.winsort_sort.sid, &cursor->mtrl.cursor));
    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));
    CTSQL_SAVE_STACK(stmt);
    CT_RETURN_IFERR(sql_windowing_assist_init_rows(&win_ass, cursor, query_cursor, plan, type));
    for (;;) {
        SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt);
        CT_BREAK_IF_ERROR(mtrl_fetch_winsort_rid(&stmt->mtrl, &cursor->mtrl.cursor, 0, &win_ass.grp_chged, &win_ass.ord_chged));
        if (cursor->mtrl.cursor.eof) {
            status = sql_winsort_aggr_value_end(stmt, type, query_cursor, win_ass.cur_aggr);
            break;
        }
        row = &cursor->mtrl.cursor.row;
        if (row->lens[rs_col_id] != sizeof(mtrl_rowid_t)) {
            CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "row->lens[rs_col_id](%u) == sizeof(mtrl_rowid_t)(%u)",
                (uint32)row->lens[rs_col_id], (uint32)sizeof(mtrl_rowid_t));
            break;
        }

        *(mtrl_rowid_t *)(row->data + row->offsets[rs_col_id]) = win_ass.rid;
        CT_BREAK_IF_ERROR(win_ass.win_func->invoke(&win_ass, cursor, buf));
        if (win_ass.part_rownum <= *win_ass.rownum) {
            win_mtrl_init_search_cursor(&win_ass.part_cur, &cursor->mtrl.cursor.sort);
            CT_BREAK_IF_ERROR(sql_win_get_next_partion_rownum(&stmt->mtrl, &win_ass.part_cur, &win_ass.part_rownum));
        }
    }

    CTSQL_RESTORE_STACK(stmt);
    SQL_CURSOR_POP(stmt);
    mtrl_close_cursor(&stmt->mtrl, &cursor->mtrl.cursor);
    return status;
}
