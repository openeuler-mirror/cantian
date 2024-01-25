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
 * ctsql_mtrl.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_mtrl.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_instance.h"
#include "ctsql_mtrl.h"
#include "ctsql_proj.h"
#include "ctsql_select.h"
#include "ctsql_func.h"
#include "ctsql_scan.h"
#include "var_defs.h"
#include "ctsql_expr_datatype.h"

static char g_null_row[CT_MAX_ROW_SIZE];
static rowid_t *g_null_rowid;

static spinlock_t g_null_row_lock;
static bool32 g_row_init = CT_FALSE;
static uint16 *g_null_row_offsets = NULL;
static uint16 *g_null_row_lens = NULL;
status_t init_null_row(void)
{
    status_t status = CT_SUCCESS;
    if (!g_row_init) {
        cm_spin_lock(&g_null_row_lock, NULL);
        while (!g_row_init) {
            row_assist_t ra;
            errno_t errcode;
            row_init(&ra, g_null_row, CT_MAX_ROW_SIZE, g_instance->kernel.attr.max_column_count - 1);
            g_null_rowid = (rowid_t *)(ra.buf + ra.head->size);
            *g_null_rowid = g_invalid_temp_rowid;
            uint32 alloc_size = sizeof(uint16) * CT_MAX_COLUMNS;
            g_null_row_offsets = (uint16 *)malloc(alloc_size);
            if (g_null_row_offsets == NULL) {
                CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)alloc_size, "alloc null row offsets");
                status = CT_ERROR;
                break;
            }
            g_null_row_lens = (uint16 *)malloc(alloc_size);
            if (g_null_row_lens == NULL) {
                CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)alloc_size, "alloc null row lens");
                status = CT_ERROR;
                break;
            }
            errcode = memset_s(g_null_row_offsets, alloc_size, 0, alloc_size);
            if (errcode != EOK) {
                CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
                status = CT_ERROR;
                break;
            }
            errcode = memset_s(g_null_row_lens, alloc_size, 0, alloc_size);
            if (errcode != EOK) {
                CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
                status = CT_ERROR;
                break;
            }
            cm_decode_row(g_null_row, g_null_row_offsets, g_null_row_lens, NULL);
            g_row_init = CT_TRUE;
        }
        if (status != CT_SUCCESS) {
            sql_free_null_row();
        }
        cm_spin_unlock(&g_null_row_lock);
    }
    return status;
}

status_t sql_make_mtrl_null_rs_row(mtrl_context_t *mtrl, uint32 seg_id, mtrl_rowid_t *rid)
{
    CT_RETURN_IFERR(init_null_row());
    return mtrl_insert_row(mtrl, seg_id, g_null_row, rid);
}

void sql_free_null_row(void)
{
    CM_FREE_PTR(g_null_row_offsets);
    CM_FREE_PTR(g_null_row_lens);
}

status_t sql_fetch_null_row(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    CT_RETURN_IFERR(init_null_row());
    row_addr_t *rows = cursor->exec_data.join;
    uint32 count = (g_instance->kernel.attr.max_column_count - 1) * sizeof(uint16);
    for (uint32 i = 0; i < cursor->table_count; i++) {
        *(rows[i].data) = g_null_row;
        if (rows[i].rowid != NULL) {
            *(rows[i].rowid) = *g_null_rowid;
        }
        MEMS_RETURN_IFERR(memcpy_sp(rows[i].offset, CT_MAX_COLUMNS * sizeof(uint16), g_null_row_offsets, count));
        MEMS_RETURN_IFERR(memcpy_sp(rows[i].len, CT_MAX_COLUMNS * sizeof(uint16), g_null_row_lens, count));
    }
    return CT_SUCCESS;
}

static inline int32 sql_compare_winsort_mtrl_row(mtrl_segment_t *seg, mtrl_row_t *row1, mtrl_row_t *row2)
{
    uint32 i;
    sort_item_t *sort_item = NULL;
    expr_tree_t *expr_tree = NULL;
    ct_type_t datatype;
    winsort_args_t *args = (winsort_args_t *)seg->cmp_items;
    int32 result;

    if ((seg->cmp_flag & WINSORT_PART) && (args->group_exprs != NULL)) {
        for (i = 0; i < args->group_exprs->count; i++) {
            expr_tree = (expr_tree_t *)cm_galist_get(args->group_exprs, i);
            datatype = expr_tree->root->datatype;

            result = sql_compare_data_ex(MT_CDATA(row1, i), MT_CSIZE(row1, i), MT_CDATA(row2, i), MT_CSIZE(row2, i),
                datatype);
            if (result != 0) {
                return result;
            }
        }
    }

    if ((seg->cmp_flag & WINSORT_ORDER) && (args->sort_items != NULL)) {
        for (i = 0; i < args->sort_items->count; i++) {
            uint32 id = (args->group_exprs != NULL) ? (i + args->group_exprs->count) : i;
            sort_item = (sort_item_t *)cm_galist_get(args->sort_items, i);
            expr_tree = sort_item->expr;
            datatype = expr_tree->root->datatype;
            result = sql_sort_mtrl_rows(row1, row2, id, datatype, &sort_item->sort_mode);
            if (result != 0) {
                return result;
            }
        }
    }
    return 0;
}

static inline void sql_calc_pending_datatype(mtrl_segment_t *segment, uint32 id, ct_type_t src_type,
    ct_type_t *dts_type)
{
    ct_type_t *types = NULL;
    if (src_type == CT_TYPE_UNKNOWN && segment->pending_type_buf != NULL) {
        types = (ct_type_t *)(segment->pending_type_buf + PENDING_HEAD_SIZE);
        *dts_type = types[id];
    } else {
        *dts_type = src_type;
    }
}

static inline int32 sql_compare_mtrl_row(mtrl_segment_t *seg, mtrl_row_t *row1, mtrl_row_t *row2)
{
    uint32 i;
    sort_item_t *item = NULL;
    select_sort_item_t *select_sort_item = NULL;
    expr_tree_t *expr = NULL;
    rs_column_t *rs_col = NULL;
    order_mode_t order_mode = { SORT_MODE_NONE, SORT_NULLS_DEFAULT };
    ct_type_t datatype;
    int32 result;

    if (seg->type == MTRL_SEGMENT_WINSORT) {
        return sql_compare_winsort_mtrl_row(seg, row1, row2);
    }

    for (i = 0; i < ((galist_t *)seg->cmp_items)->count; i++) {
        switch (seg->type) {
            case MTRL_SEGMENT_QUERY_SORT:
            case MTRL_SEGMENT_CONCAT_SORT:
            case MTRL_SEGMENT_SIBL_SORT:
                item = (sort_item_t *)cm_galist_get((galist_t *)seg->cmp_items, i);
                expr = item->expr;
                sql_calc_pending_datatype(seg, i, expr->root->datatype, &datatype);
                order_mode = item->sort_mode;
                break;

            case MTRL_SEGMENT_SELECT_SORT:
                select_sort_item = (select_sort_item_t *)cm_galist_get((galist_t *)seg->cmp_items, i);
                sql_calc_pending_datatype(seg, i, select_sort_item->datatype, &datatype);
                order_mode = select_sort_item->sort_mode;
                break;

            case MTRL_SEGMENT_DISTINCT:
            case MTRL_SEGMENT_RS:
                rs_col = (rs_column_t *)cm_galist_get((galist_t *)seg->cmp_items, i);
                sql_calc_pending_datatype(seg, i, rs_col->datatype, &datatype);
                order_mode.direction = SORT_MODE_ASC;
                order_mode.nulls_pos = DEFAULT_NULLS_SORTING_POSITION(SORT_MODE_ASC);
                break;

            default:
                expr = (expr_tree_t *)cm_galist_get((galist_t *)seg->cmp_items, i);
                sql_calc_pending_datatype(seg, i, expr->root->datatype, &datatype);
                order_mode.direction = SORT_MODE_ASC;
                order_mode.nulls_pos = DEFAULT_NULLS_SORTING_POSITION(SORT_MODE_ASC);
                break;
        }

        result = sql_sort_mtrl_rows(row1, row2, i, datatype, &order_mode);
        if (result != 0) {
            return result;
        }
    }
    return 0;
}

static inline void sql_decode_mtrl_row(mtrl_row_t *mtrl_row, char *data)
{
    mtrl_row->data = data;
    cm_decode_row(data, mtrl_row->offsets, mtrl_row->lens, NULL);
}

status_t sql_mtrl_sort_cmp(mtrl_segment_t *seg, char *data1, char *data2, int32 *result)
{
    mtrl_row_t mtrl_row1, mtrl_row2;
    sql_decode_mtrl_row(&mtrl_row1, data1);
    sql_decode_mtrl_row(&mtrl_row2, data2);
    *result = sql_compare_mtrl_row(seg, &mtrl_row1, &mtrl_row2);
    return CT_SUCCESS;
}

static inline status_t sql_mtrl_row_get_win_bor_value(mtrl_segment_t *seg, mtrl_row_t *row, uint32 *id,
    expr_tree_t *expr, variant_t *val)
{
    ct_type_t datatype;
    if (expr != NULL) {
        if (TREE_IS_CONST(expr)) {
            *val = expr->root->value;
        } else {
            mtrl_row_assist_t row_ass;
            mtrl_row_init(&row_ass, row);
            sql_calc_pending_datatype(seg, *id, expr->root->datatype, &datatype);
            CT_RETURN_IFERR(mtrl_get_column_value(&row_ass, CT_FALSE, *id, datatype, CT_FALSE, val));
            (*id)++;
        }
    }
    return CT_SUCCESS;
}

static inline status_t sql_mtrl_row_get_win_border(mtrl_cursor_t *cursor, mtrl_row_t *row, uint32 id, variant_t *l_val,
    variant_t *r_val)
{
    mtrl_segment_t *seg = cursor->sort.segment;
    winsort_args_t *args = (winsort_args_t *)seg->cmp_items;
    expr_tree_t *l_expr = args->windowing->l_expr;
    expr_tree_t *r_expr = args->windowing->r_expr;

    CT_RETURN_IFERR(sql_mtrl_row_get_win_bor_value(seg, row, &id, l_expr, l_val));
    return sql_mtrl_row_get_win_bor_value(seg, row, &id, r_expr, r_val);
}

status_t sql_mtrl_get_windowing_sort_val(mtrl_sort_cursor_t *sort, uint32 id, ct_type_t datatype, variant_t *sort_val)
{
    mtrl_row_t mtrl_row;
    mtrl_row_assist_t row_assist;

    sql_decode_mtrl_row(&mtrl_row, sort->row);
    mtrl_row_init(&row_assist, &mtrl_row);
    return mtrl_get_column_value(&row_assist, CT_FALSE, id, datatype, CT_FALSE, sort_val);
}

status_t sql_mtrl_get_windowing_value(mtrl_cursor_t *cursor, variant_t *sort_val, variant_t *l_val, variant_t *r_val)
{
    winsort_args_t *winsort_args = (winsort_args_t *)cursor->sort.segment->cmp_items;
    uint32 id = (winsort_args->group_exprs != NULL) ? winsort_args->group_exprs->count : 0;
    sort_item_t *item = (sort_item_t *)cm_galist_get(winsort_args->sort_items, 0);
    mtrl_row_t mtrl_row;
    mtrl_row_assist_t row_assist;

    sql_decode_mtrl_row(&mtrl_row, cursor->sort.row);
    mtrl_row_init(&row_assist, &mtrl_row);
    CT_RETURN_IFERR(
        mtrl_get_column_value(&row_assist, cursor->eof, id, item->expr->root->datatype, CT_FALSE, sort_val));
    id += winsort_args->sort_items->count;
    return sql_mtrl_row_get_win_border(cursor, &mtrl_row, id, l_val, r_val);
}

status_t sql_mtrl_get_windowing_border(mtrl_cursor_t *cursor, variant_t *l_val, variant_t *r_val)
{
    winsort_args_t *winsort_args = (winsort_args_t *)cursor->sort.segment->cmp_items;
    uint32 id = (winsort_args->group_exprs != NULL) ? winsort_args->group_exprs->count : 0;
    mtrl_row_t mtrl_row;

    sql_decode_mtrl_row(&mtrl_row, cursor->sort.row);
    id += winsort_args->sort_items->count;
    return sql_mtrl_row_get_win_border(cursor, &mtrl_row, id, l_val, r_val);
}

void sql_init_mtrl(mtrl_context_t *mtrl_ctx, session_t *session)
{
    mtrl_init_context(mtrl_ctx, session);
    mtrl_ctx->sort_cmp = sql_mtrl_sort_cmp;
}

static void sql_free_sort(sql_stmt_t *stmt, sql_cursor_t *sql_cursor)
{
    CTSQL_RELEASE_SEGMENT(stmt, sql_cursor->mtrl.sort.sid);
    sql_cursor->mtrl.sort.buf = NULL;

    if (sql_cursor->mtrl.sort_seg != CT_INVALID_ID32) {
        mtrl_close_segment(&stmt->mtrl, sql_cursor->mtrl.sort_seg);
        sql_free_segment_in_vm(stmt, sql_cursor->mtrl.sort_seg);
        mtrl_release_segment(&stmt->mtrl, sql_cursor->mtrl.sort_seg);
        sql_cursor->mtrl.sort_seg = CT_INVALID_ID32;
    }
}

static void sql_free_aggr(sql_stmt_t *stmt, sql_cursor_t *sql_cursor)
{
    if (sql_cursor->mtrl.aggr != CT_INVALID_ID32) {
        mtrl_close_segment(&stmt->mtrl, sql_cursor->mtrl.aggr);
        mtrl_release_segment(&stmt->mtrl, sql_cursor->mtrl.aggr);
        sql_cursor->mtrl.aggr = CT_INVALID_ID32;
        sql_cursor->aggr_page = NULL;
    }

    CTSQL_RELEASE_SEGMENT(stmt, sql_cursor->mtrl.aggr_str);
}

static void sql_free_winsort(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    CTSQL_RELEASE_SEGMENT(stmt, cursor->mtrl.winsort_rs.sid);
    cursor->mtrl.winsort_rs.buf = NULL;
    CTSQL_RELEASE_SEGMENT(stmt, cursor->mtrl.winsort_aggr.sid);
    CTSQL_RELEASE_SEGMENT(stmt, cursor->mtrl.winsort_aggr_ext.sid);
    CTSQL_RELEASE_SEGMENT(stmt, cursor->mtrl.winsort_sort.sid);
    cursor->mtrl.winsort_sort.buf = NULL;
}

static inline void sql_free_connect_mtrl_cursor(sql_stmt_t *stmt, sql_cursor_t **cursor)
{
    sql_cursor_t *dst_cur = *cursor;
    if (dst_cur == NULL) {
        return;
    }
    dst_cur->connect_data.next_level_cursor = NULL;
    sql_free_cursor(stmt, dst_cur);
    (*cursor) = NULL;
}

static void sql_free_connect_mtrl_prior(sql_stmt_t *stmt, sql_cursor_t *sql_cursor)
{
    if (GET_VM_CTX(stmt) == NULL || sql_cursor->cb_mtrl_ctx->curr_level == 0) {
        return;
    }

    cb_mtrl_data_t *data = NULL;
    for (uint32 i = 0; i < sql_cursor->cb_mtrl_ctx->curr_level; i++) {
        data = (cb_mtrl_data_t *)(cm_galist_get(sql_cursor->cb_mtrl_ctx->cb_data, i));
        CT_CONTINUE_IFTRUE(IS_INVALID_MTRL_ROWID(data->prior_row));

        if (vmctx_free(GET_VM_CTX(stmt), &data->prior_row) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("failed to free row id vm id %u, vm slot %u", data->prior_row.vmid, data->prior_row.slot);
            return;
        }
        data->prior_row = g_invalid_entry;
    }
}

static void sql_free_connect_hash(sql_stmt_t *stmt, sql_cursor_t *sql_cursor)
{
    sql_free_connect_mtrl_prior(stmt, sql_cursor);
    sql_free_connect_mtrl_cursor(stmt, &sql_cursor->cb_mtrl_ctx->last_cursor);
    sql_free_connect_mtrl_cursor(stmt, &sql_cursor->cb_mtrl_ctx->curr_cursor);
    sql_free_connect_mtrl_cursor(stmt, &sql_cursor->cb_mtrl_ctx->next_cursor);
    sql_cursor->connect_data.last_level_cursor = NULL;
    sql_cursor->connect_data.cur_level_cursor = NULL;
    sql_cursor->connect_data.next_level_cursor = NULL;
    sql_cursor->cb_mtrl_ctx->key_types = NULL;

    mtrl_close_cursor(&stmt->mtrl, &sql_cursor->mtrl.cursor);
    CTSQL_RELEASE_SEGMENT(stmt, sql_cursor->cb_mtrl_ctx->hash_table_rs);
    vm_hash_segment_deinit(&sql_cursor->cb_mtrl_ctx->hash_segment);
    vm_free(KNL_SESSION(stmt), KNL_SESSION(stmt)->temp_pool, sql_cursor->cb_mtrl_ctx->vmid);
    sql_cursor->cb_mtrl_ctx = NULL;
}

static void sql_free_connect(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    sql_cursor_t *curr_level_cur = cursor->connect_data.next_level_cursor;
    sql_cursor_t *next_level_cur = NULL;
    while (curr_level_cur != NULL) {
        next_level_cur = curr_level_cur->connect_data.next_level_cursor;
        curr_level_cur->connect_data.next_level_cursor = NULL;
        sql_free_cursor(stmt, curr_level_cur);
        curr_level_cur = next_level_cur;
    }

    cursor->connect_data.next_level_cursor = NULL;
    cursor->connect_data.cur_level_cursor = NULL;
}

void sql_free_connect_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    if (cursor->cb_mtrl_ctx != NULL) {
        sql_free_connect_hash(stmt, cursor);
    } else {
        sql_free_connect(stmt, cursor);
    }
}

static void sql_free_distinct(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    cursor->mtrl.cursor.distinct.row.lens = NULL;
    cursor->mtrl.cursor.distinct.row.offsets = NULL;
    CTSQL_RELEASE_SEGMENT(stmt, cursor->mtrl.distinct);
    CTSQL_RELEASE_SEGMENT(stmt, cursor->mtrl.index_distinct);
}

static void sql_free_hash_ctx(sql_stmt_t *stmt, sql_cursor_t *sql_cursor)
{
    if ((sql_cursor->hash_join_ctx != NULL) && (sql_cursor->hash_join_ctx->iter.hash_table != NULL)) {
        vm_hash_close_page(&sql_cursor->hash_seg, &sql_cursor->hash_table_entry.page);
        sql_cursor->hash_join_ctx->iter.hash_table = NULL;
    }

    if (sql_cursor->hash_table_status == HASH_TABLE_STATUS_CLONE) {
        mtrl_close_sort_cursor(&stmt->mtrl, &sql_cursor->mtrl.cursor.sort);
        sql_cursor->mtrl.cursor.rs_vmid = CT_INVALID_ID32;
    } else {
        mtrl_close_cursor(&stmt->mtrl, &sql_cursor->mtrl.cursor);
    }

    if ((sql_cursor->hash_seg.sess != NULL) && (sql_cursor->hash_table_status != HASH_TABLE_STATUS_CLONE)) {
        vm_hash_segment_deinit(&sql_cursor->hash_seg);
        sql_cursor->hash_seg.sess = NULL;
    }

    if (sql_cursor->hash_table_status != HASH_TABLE_STATUS_CLONE) {
        CTSQL_RELEASE_SEGMENT(stmt, sql_cursor->mtrl.hash_table_rs);
    }

    if (sql_cursor->hash_table_status == HASH_TABLE_STATUS_CLONE) {
        sql_cursor->hash_seg.sess = NULL;
        sql_cursor->mtrl.hash_table_rs = CT_INVALID_ID32;
    }

    sql_cursor->hash_table_status = HASH_TABLE_STATUS_NOINIT;
    if (sql_cursor->hash_join_ctx != NULL) {
        sql_cursor->hash_join_ctx->key_types = NULL;
        sql_cursor->hash_join_ctx->iter.callback_ctx = NULL;
        sql_cursor->hash_join_ctx->iter.curr_bucket = 0;
        sql_cursor->hash_join_ctx->iter.curr_match.vmid = CT_INVALID_ID32;
    }
}

void sql_reset_mtrl(sql_stmt_t *stmt, sql_cursor_t *sql_cursor)
{
    sql_cursor->mtrl.cursor.rs_page = NULL;
    sql_cursor->mtrl.cursor.type = MTRL_CURSOR_OTHERS;
    mtrl_init_mtrl_rowid(&sql_cursor->mtrl.cursor.next_cursor_rid);
    mtrl_init_mtrl_rowid(&sql_cursor->mtrl.cursor.pre_cursor_rid);
    mtrl_init_mtrl_rowid(&sql_cursor->mtrl.cursor.curr_cursor_rid);
    sql_cursor->mtrl.aggr_fetched = CT_FALSE;

    sql_free_hash_ctx(stmt, sql_cursor);

    CTSQL_RELEASE_SEGMENT(stmt, sql_cursor->mtrl.rs.sid);
    sql_cursor->mtrl.rs.buf = NULL;
    CTSQL_RELEASE_SEGMENT(stmt, sql_cursor->mtrl.predicate.sid);

    sql_free_aggr(stmt, sql_cursor);

    sql_free_sort(stmt, sql_cursor);

    sql_free_sibl_sort(stmt, sql_cursor);

    CTSQL_RELEASE_SEGMENT(stmt, sql_cursor->mtrl.group.sid);
    sql_cursor->mtrl.group.buf = NULL;
    CTSQL_RELEASE_SEGMENT(stmt, sql_cursor->mtrl.group_index);
    sql_free_distinct(stmt, sql_cursor);

    sql_free_winsort(stmt, sql_cursor);

    CTSQL_RELEASE_SEGMENT(stmt, sql_cursor->mtrl.for_update);
}

status_t sql_row_put_value(sql_stmt_t *stmt, row_assist_t *row_ass, variant_t *value)
{
    switch (value->type) {
        case CT_TYPE_UINT32:
            return row_put_uint32(row_ass, VALUE(uint32, value));

        case CT_TYPE_INTEGER:
            return row_put_int32(row_ass, VALUE(int32, value));

        case CT_TYPE_BOOLEAN:
            return row_put_bool(row_ass, value->v_bool);

        case CT_TYPE_BIGINT:
            return row_put_int64(row_ass, VALUE(int64, value));

        case CT_TYPE_REAL:
            return row_put_real(row_ass, VALUE(double, value));

        case CT_TYPE_DATE:
            return row_put_date(row_ass, VALUE(date_t, value));

        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
            return row_put_date(row_ass, VALUE(date_t, value));

        case CT_TYPE_TIMESTAMP_TZ:
            return row_put_timestamp_tz(row_ass, VALUE_PTR(timestamp_tz_t, value));

        case CT_TYPE_INTERVAL_DS:
            return row_put_dsinterval(row_ass, VALUE(interval_ds_t, value));

        case CT_TYPE_INTERVAL_YM:
            return row_put_yminterval(row_ass, VALUE(interval_ym_t, value));

        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
            return row_put_text(row_ass, VALUE_PTR(text_t, value));

        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
            return row_put_dec4(row_ass, VALUE_PTR(dec8_t, value));
        case CT_TYPE_NUMBER2:
            return row_put_dec2(row_ass, VALUE_PTR(dec8_t, value));

        case CT_TYPE_CLOB:
        case CT_TYPE_BLOB:
        case CT_TYPE_IMAGE:
            return sql_row_put_lob(stmt, row_ass, g_instance->sql.sql_lob_locator_size, VALUE_PTR(var_lob_t, value));

        case CT_TYPE_ARRAY:
            return sql_row_put_array(stmt, row_ass, &value->v_array);

        case CT_TYPE_BINARY:
        case CT_TYPE_RAW:
        default:
            return row_put_bin(row_ass, VALUE_PTR(binary_t, value));
    }
}

status_t sql_put_row_value(sql_stmt_t *stmt, char *pending_buf, row_assist_t *ra, ct_type_t temp_type, variant_t *value)
{
    ct_type_t type = temp_type;
    // try make pending column definition when project column
    if (type == CT_TYPE_UNKNOWN) {
        type = sql_make_pending_column_def(stmt, pending_buf, type, ra->col_id, value);
    }

    if (value->is_null) {
        return row_put_null(ra);
    }

    if (value->type == CT_TYPE_VM_ROWID) {
        return row_put_vmid(ra, &value->v_vmid);
    }

    if (value->type != type && value->type != CT_TYPE_ARRAY) {
        CT_RETURN_IFERR(sql_convert_variant(stmt, value, type));
    }

    return sql_row_put_value(stmt, ra, value);
}

static inline status_t sql_convert_row_value(sql_stmt_t *stmt, variant_t *value, ct_type_t type)
{
    if (value->type == type || value->type == CT_TYPE_ARRAY) {
        return CT_SUCCESS;
    }
    return sql_convert_variant(stmt, value, type);
}

status_t sql_set_row_value(sql_stmt_t *stmt, row_assist_t *row_ass, ct_type_t type, variant_t *value, uint32 col_id)
{
    // The CT_TYPE_LOGIC_TRUE indicates that the result set is empty in ALL(xxx) conditon, which different from NULL.
    if (value->is_null || value->type == CT_TYPE_LOGIC_TRUE) {
        return row_set_null(row_ass, col_id);
    }

    CT_RETURN_IFERR(sql_convert_row_value(stmt, value, type));
    switch (value->type) {
        case CT_TYPE_UINT32:
            return row_set_uint32(row_ass, VALUE(uint32, value), col_id);

        case CT_TYPE_INTEGER:
            return row_set_int32(row_ass, VALUE(int32, value), col_id);

        case CT_TYPE_BOOLEAN:
            return row_set_bool(row_ass, value->v_bool, col_id);

        case CT_TYPE_BIGINT:
            return row_set_int64(row_ass, VALUE(int64, value), col_id);

        case CT_TYPE_REAL:
            return row_set_real(row_ass, VALUE(double, value), col_id);

        case CT_TYPE_DATE:
            return row_set_date(row_ass, VALUE(date_t, value), col_id);

        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
            return row_set_date(row_ass, VALUE(date_t, value), col_id);

        case CT_TYPE_TIMESTAMP_TZ:
            return row_set_timestamp_tz(row_ass, VALUE_PTR(timestamp_tz_t, value), col_id);

        case CT_TYPE_INTERVAL_DS:
            return row_set_dsinterval(row_ass, VALUE(interval_ds_t, value), col_id);

        case CT_TYPE_INTERVAL_YM:
            return row_set_yminterval(row_ass, VALUE(interval_ym_t, value), col_id);

        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
            return row_set_text(row_ass, VALUE_PTR(text_t, value), col_id);

        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
            return row_set_dec4(row_ass, VALUE_PTR(dec8_t, value), col_id);
        case CT_TYPE_NUMBER2:
            return row_set_dec2(row_ass, VALUE_PTR(dec8_t, value), col_id);
        case CT_TYPE_CLOB:
        case CT_TYPE_BLOB:
        case CT_TYPE_IMAGE:
            return sql_row_set_lob(stmt, row_ass, g_instance->sql.sql_lob_locator_size, VALUE_PTR(var_lob_t, value), col_id);

        case CT_TYPE_ARRAY:
            return sql_row_set_array(stmt, row_ass, value, col_id);

        case CT_TYPE_BINARY:
        case CT_TYPE_RAW:
        default:
            return row_set_bin(row_ass, VALUE_PTR(binary_t, value), col_id);
    }
}

static inline void sql_set_table_rowid(sql_stmt_t *stmt, row_assist_t *ra, sql_table_t *table)
{
    sql_cursor_t *cursor = NULL;
    sql_table_cursor_t *tab_cursor = NULL;

    if (table->type != NORMAL_TABLE) {
        return;
    }
    cursor = CTSQL_CURR_CURSOR(stmt);
    tab_cursor = &cursor->tables[table->id];
    if (tab_cursor->knl_cur->eof) {
        tab_cursor->knl_cur->rowid = INVALID_ROWID;
    }
    *(rowid_t *)(ra->buf + ra->head->size) = tab_cursor->knl_cur->rowid;
    ra->head->size += KNL_ROWID_LEN;
}

static status_t sql_make_mtrl_rs_one_row(sql_stmt_t *stmt, char *pending_buf, row_assist_t *ra, rs_column_t *rs_col)
{
    variant_t value;

    switch (rs_col->type) {
        case RS_COL_COLUMN:
            if (sql_get_table_value(stmt, &rs_col->v_col, &value) != CT_SUCCESS) {
                return CT_ERROR;
            }
            return sql_put_row_value(stmt, pending_buf, ra, rs_col->datatype, &value);

        case RS_COL_CALC:
            if (sql_exec_expr(stmt, rs_col->expr, &value) != CT_SUCCESS) {
                return CT_ERROR;
            }
            return sql_put_row_value(stmt, pending_buf, ra, rs_col->datatype, &value);

        default:
            CT_THROW_ERROR(ERR_INVALID_COL_TYPE, rs_col->type);
            return CT_ERROR;
    }
}

static inline status_t sql_sql_exec_win_border_expr(sql_stmt_t *stmt, expr_tree_t *expr, ct_type_t sort_type,
    variant_t *value, bool32 is_range)
{
    CT_RETURN_IFERR(sql_exec_expr(stmt, expr, value));
    if (value->is_null) {
        CT_SRC_THROW_ERROR_EX(expr->loc, ERR_SQL_SYNTAX_ERROR, "windowing border value cannot be NULL");
        return CT_ERROR;
    }
    if (!is_range || !CT_IS_DATETIME_TYPE(sort_type) ||
        (!CT_IS_DSITVL_TYPE(expr->root->datatype) && !CT_IS_YMITVL_TYPE(expr->root->datatype))) {
        CT_RETURN_IFERR(var_as_num(value));
    }
    if (var_is_negative(value)) {
        CT_SRC_THROW_ERROR_EX(expr->loc, ERR_SQL_SYNTAX_ERROR, "windowing border value cannot be negative");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_make_mtrl_winsort_row(sql_stmt_t *stmt, winsort_args_t *args, mtrl_rowid_t *rid, char *buf,
    char *pending_buf)
{
    uint32 i;
    expr_tree_t *expr = NULL;
    sort_item_t *item = NULL;
    variant_t value;
    row_assist_t ra;

    row_init(&ra, buf, CT_MAX_ROW_SIZE, args->sort_columns);

    if (args->group_exprs != NULL) {
        for (i = 0; i < args->group_exprs->count; i++) {
            expr = (expr_tree_t *)cm_galist_get(args->group_exprs, i);
            CT_RETURN_IFERR(sql_exec_expr(stmt, expr, &value));
            CT_RETURN_IFERR(sql_put_row_value(stmt, pending_buf, &ra, expr->root->datatype, &value));
        }
    }

    if (args->sort_items != NULL) {
        for (i = 0; i < args->sort_items->count; i++) {
            item = (sort_item_t *)cm_galist_get(args->sort_items, i);
            CT_RETURN_IFERR(sql_exec_expr(stmt, item->expr, &value));
            CT_RETURN_IFERR(sql_put_row_value(stmt, pending_buf, &ra, item->expr->root->datatype, &value));
        }
        if (args->windowing != NULL) {
            if (args->windowing->l_expr != NULL && !TREE_IS_CONST(args->windowing->l_expr)) {
                CT_RETURN_IFERR(sql_sql_exec_win_border_expr(stmt, args->windowing->l_expr, item->expr->root->datatype,
                    &value, args->windowing->is_range));
                CT_RETURN_IFERR(
                    sql_put_row_value(stmt, pending_buf, &ra, args->windowing->l_expr->root->datatype, &value));
            }
            if (args->windowing->r_expr != NULL && !TREE_IS_CONST(args->windowing->r_expr)) {
                CT_RETURN_IFERR(sql_sql_exec_win_border_expr(stmt, args->windowing->r_expr, item->expr->root->datatype,
                    &value, args->windowing->is_range));
                CT_RETURN_IFERR(
                    sql_put_row_value(stmt, pending_buf, &ra, args->windowing->r_expr->root->datatype, &value));
            }
        }
    }

    if (ra.head->size + sizeof(mtrl_rowid_t) > CT_MAX_ROW_SIZE) {
        CT_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, ra.head->size + sizeof(mtrl_rowid_t), CT_MAX_ROW_SIZE);
        return CT_ERROR;
    }

    *(mtrl_rowid_t *)(buf + ra.head->size) = *rid;
    ra.head->size += sizeof(mtrl_rowid_t);

    return CT_SUCCESS;
}

status_t sql_make_mtrl_rs_row(sql_stmt_t *stmt, char *pending_buf, galist_t *columns, char *buf)
{
    rs_column_t *rs_col = NULL;
    row_assist_t ra;

    row_init(&ra, buf, CT_MAX_ROW_SIZE, columns->count);

    for (uint32 i = 0; i < columns->count; i++) {
        rs_col = (rs_column_t *)cm_galist_get(columns, i);
        if (sql_make_mtrl_rs_one_row(stmt, pending_buf, &ra, rs_col) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t sql_make_mtrl_sort_row(sql_stmt_t *stmt, char *pending_buf, galist_t *sort_items, row_assist_t *ra)
{
    sort_item_t *item = NULL;
    variant_t value;
    expr_tree_t *expr = NULL;

    CTSQL_SAVE_STACK(stmt);
    for (uint32 i = 0; i < sort_items->count; i++) {
        item = (sort_item_t *)cm_galist_get(sort_items, i);
        expr = item->expr;

        CT_RETURN_IFERR(sql_exec_expr(stmt, expr, &value));
        if (CT_IS_LOB_TYPE(value.type)) {
            CT_RETURN_IFERR(sql_get_lob_value(stmt, &value));
            if (value.is_null) {
                CT_RETURN_IFERR(row_put_null(ra));
            } else if (value.type == CT_TYPE_STRING) {
                CT_RETURN_IFERR(row_put_text(ra, VALUE_PTR(text_t, &value)));
            } else if (value.type == CT_TYPE_RAW) {
                CT_RETURN_IFERR(row_put_bin(ra, VALUE_PTR(binary_t, &value)));
            }
            continue;
        }

        if (!value.is_null && value.type >= CT_TYPE_OPERAND_CEIL) {
            CT_THROW_ERROR(ERR_INVALID_DATA_TYPE, "unexpected user define type");
            return CT_ERROR;
        }
        CT_RETURN_IFERR(sql_put_row_value(stmt, pending_buf, ra, expr->root->datatype, &value));
        CTSQL_RESTORE_STACK(stmt);
    }
    return CT_SUCCESS;
}

status_t sql_make_mtrl_query_sort_row(sql_stmt_t *stmt, char *pending_buf, galist_t *sort_items, mtrl_rowid_t *rid,
    char *buf)
{
    row_assist_t ra;

    row_init(&ra, buf, CT_MAX_ROW_SIZE, sort_items->count);

    if (sql_make_mtrl_sort_row(stmt, pending_buf, sort_items, &ra) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (ra.head->size + sizeof(mtrl_rowid_t) > CT_MAX_ROW_SIZE) {
        CT_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, ra.head->size + sizeof(mtrl_rowid_t), CT_MAX_ROW_SIZE);
        return CT_ERROR;
    }

    *(mtrl_rowid_t *)(buf + ra.head->size) = *rid;
    ra.head->size += sizeof(mtrl_rowid_t);
    return CT_SUCCESS;
}

status_t sql_make_mtrl_select_sort_row(sql_stmt_t *stmt, char *pending_buf, sql_cursor_t *cursor, galist_t *sort_items,
    mtrl_rowid_t *rid, char *buf)
{
    uint32 i;
    select_sort_item_t *item = NULL;
    rs_column_t *rs_column = NULL;
    row_assist_t ra;

    row_init(&ra, buf, CT_MAX_ROW_SIZE, sort_items->count);

    for (i = 0; i < sort_items->count; i++) {
        item = (select_sort_item_t *)cm_galist_get(sort_items, i);
        rs_column = (rs_column_t *)cm_galist_get(cursor->columns, item->rs_columns_id);
        if (sql_make_mtrl_rs_one_row(stmt, pending_buf, &ra, rs_column) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (ra.head->size + sizeof(mtrl_rowid_t) > CT_MAX_ROW_SIZE) {
        CT_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, ra.head->size + sizeof(mtrl_rowid_t), CT_MAX_ROW_SIZE);
        return CT_ERROR;
    }

    *(mtrl_rowid_t *)(buf + ra.head->size) = *rid;
    ra.head->size += sizeof(mtrl_rowid_t);

    return CT_SUCCESS;
}

status_t sql_make_mtrl_sibl_sort_row(sql_stmt_t *stmt, char *pending_buf, galist_t *sort_items, char *buf,
    sibl_sort_row_t *sibl_sort_row)
{
    row_assist_t ra;

    row_init(&ra, buf, CT_MAX_ROW_SIZE, sort_items->count);

    if (sql_make_mtrl_sort_row(stmt, pending_buf, sort_items, &ra) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (ra.head->size + sizeof(sibl_sort_row_t) > CT_MAX_ROW_SIZE) {
        CT_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, ra.head->size + sizeof(sibl_sort_row_t), CT_MAX_ROW_SIZE);
        return CT_ERROR;
    }

    *(sibl_sort_row_t *)(buf + ra.head->size) = *sibl_sort_row;
    ra.head->size += sizeof(sibl_sort_row_t);
    return CT_SUCCESS;
}

status_t sql_make_mtrl_group_row(sql_stmt_t *stmt, char *pending_buf, group_plan_t *group_p, char *buf)
{
    uint32 i;
    expr_node_t *expr_node = NULL;
    variant_t value;
    variant_t var[FO_VAL_MAX - 1];
    row_assist_t ra;

    uint32 column_count =
        group_p->exprs->count + group_p->aggrs_args + group_p->cntdis_columns->count + group_p->aggrs_sorts;
    row_init(&ra, buf, CT_MAX_ROW_SIZE, column_count);

    for (i = 0; i < group_p->exprs->count; i++) {
        expr_tree_t *expr = (expr_tree_t *)cm_galist_get(group_p->exprs, i);
        CT_RETURN_IFERR(sql_exec_expr(stmt, expr, &value));
        CT_RETURN_IFERR(sql_put_row_value(stmt, pending_buf, &ra, expr->root->datatype, &value));
    }

    for (i = 0; i < group_p->aggrs->count; i++) {
        expr_node = (expr_node_t *)cm_galist_get(group_p->aggrs, i);
        const sql_func_t *func = sql_get_func(&expr_node->value.v_func);
        CT_CONTINUE_IFTRUE(func->aggr_type == AGGR_TYPE_DENSE_RANK || func->aggr_type == AGGR_TYPE_RANK);
        CT_RETURN_IFERR(sql_exec_expr_node(stmt, expr_node, var));
        for (uint32 j = 0; j < func->value_cnt; j++) {
            CT_RETURN_IFERR(sql_put_row_value(stmt, pending_buf, &ra, expr_node->datatype, &var[j]));
        }
    }

    for (i = 0; i < group_p->cntdis_columns->count; i++) {
        expr_node = (expr_node_t *)cm_galist_get(group_p->cntdis_columns, i);
        CT_RETURN_IFERR(sql_exec_expr_node(stmt, expr_node, &value));
        CT_RETURN_IFERR(sql_put_row_value(stmt, pending_buf, &ra, expr_node->datatype, &value));
    }

    for (i = 0; i < group_p->aggrs_sorts; i++) {
        expr_node = (expr_node_t *)cm_galist_get(group_p->sort_items, i);
        CT_RETURN_IFERR(sql_exec_expr_node(stmt, expr_node, &value));
        CT_RETURN_IFERR(sql_put_row_value(stmt, pending_buf, &ra, expr_node->datatype, &value));
    }

    return CT_SUCCESS;
}

status_t sql_inherit_pending_buf(sql_cursor_t *cursor, sql_cursor_t *sub_cursor)
{
    uint32 mem_size;
    if (cursor->mtrl.rs.buf != NULL) {
        mem_size = *(uint32 *)cursor->mtrl.rs.buf;
        CT_RETURN_IFERR(vmc_alloc(&sub_cursor->vmc, mem_size, (void **)&sub_cursor->mtrl.rs.buf));
        MEMS_RETURN_IFERR(memcpy_s(sub_cursor->mtrl.rs.buf, mem_size, cursor->mtrl.rs.buf, mem_size));
    }
    return CT_SUCCESS;
}

status_t sql_revert_pending_buf(sql_cursor_t *cursor, sql_cursor_t *sub_cursor)
{
    uint32 mem_size;
    if (cursor->mtrl.rs.buf != NULL) {
        mem_size = *(uint32 *)cursor->mtrl.rs.buf;
        MEMS_RETURN_IFERR(memcpy_s(cursor->mtrl.rs.buf, mem_size, sub_cursor->mtrl.rs.buf, mem_size));
    } else if (sub_cursor->mtrl.rs.buf != NULL) {
        mem_size = *(uint32 *)sub_cursor->mtrl.rs.buf;
        CT_RETURN_IFERR(vmc_alloc(&cursor->vmc, mem_size, (void **)&cursor->mtrl.rs.buf));
        MEMS_RETURN_IFERR(memcpy_s(cursor->mtrl.rs.buf, mem_size, sub_cursor->mtrl.rs.buf, mem_size));
    }
    return CT_SUCCESS;
}

status_t sql_materialize_base(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    sql_cursor_t *sub_cursor = NULL;
    char *buf = NULL;
    mtrl_rowid_t rid;
    status_t ret = CT_SUCCESS;

    CT_RETURN_IFERR(sql_alloc_cursor(stmt, &sub_cursor));
    sub_cursor->scn = cursor->scn;
    sub_cursor->ancestor_ref = cursor->ancestor_ref;

    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, sub_cursor));

    if (sql_execute_select_plan(stmt, sub_cursor, plan) != CT_SUCCESS) {
        SQL_CURSOR_POP(stmt);
        sql_free_cursor(stmt, sub_cursor);
        return CT_ERROR;
    }

    // rs datatype depends on the first query
    CT_RETURN_IFERR(sql_inherit_pending_buf(cursor, sub_cursor));

    if (sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buf) != CT_SUCCESS) {
        SQL_CURSOR_POP(stmt);
        sql_free_cursor(stmt, sub_cursor);
        return CT_ERROR;
    }

    for (;;) {
        CTSQL_SAVE_STACK(stmt);
        if (sql_fetch_cursor(stmt, sub_cursor, plan, &sub_cursor->eof) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            ret = CT_ERROR;
            break;
        }

        if (sub_cursor->eof) {
            CTSQL_RESTORE_STACK(stmt);
            break;
        }

        if (sql_make_mtrl_rs_row(stmt, sub_cursor->mtrl.rs.buf, sub_cursor->columns, buf) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            ret = CT_ERROR;
            break;
        }

        if (mtrl_insert_row(&stmt->mtrl, cursor->mtrl.rs.sid, buf, &rid) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            ret = CT_ERROR;
            break;
        }
        CTSQL_RESTORE_STACK(stmt);
    }

    CTSQL_POP(stmt);
    SQL_CURSOR_POP(stmt);

    CT_RETURN_IFERR(sql_revert_pending_buf(cursor, sub_cursor));

    sql_free_cursor(stmt, sub_cursor);
    return ret;
}

static void sql_set_col_info(var_column_t *var_col, query_field_t *query_field)
{
    var_col->col = query_field->col_id;
    var_col->col_info_ptr->col_pro_id = query_field->pro_id;
    var_col->datatype = query_field->datatype;
    if (!QUERY_FIELD_IS_ELEMENT(query_field)) {
        var_col->is_array = query_field->is_array;
        var_col->ss_start = query_field->start;
        var_col->ss_end = query_field->end;
    } else {
        var_col->is_array = CT_TRUE;
        var_col->ss_start = (int32)CT_INVALID_ID32;
        var_col->ss_end = (int32)CT_INVALID_ID32;
    }
}

static status_t sql_set_pending_buf_coltype(sql_stmt_t *stmt, sql_cursor_t *sql_cur, char **pending_buf,
    var_column_t v_col)
{
    uint32 mem_cost_size;
    ct_type_t *types = NULL;

    if (*pending_buf == NULL) {
        mem_cost_size = PENDING_HEAD_SIZE + sql_cur->columns->count * sizeof(ct_type_t);
        CT_RETURN_IFERR(vmc_alloc(&sql_cur->vmc, mem_cost_size, (void **)pending_buf));
        *(uint32 *)*pending_buf = mem_cost_size;
    }
    types = (ct_type_t *)(*pending_buf + PENDING_HEAD_SIZE);
    types[v_col.col] = v_col.datatype;

    return CT_SUCCESS;
}

static status_t sql_make_mtrl_merge_rs_row(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_table_cursor_t *table_curs,
    sql_table_t *table, char *buf, uint32 buf_size)
{
    variant_t value;
    row_assist_t row_ass;
    var_column_t var_col;
    column_info_t col_info;
    bilist_node_t *node = NULL;
    query_field_t *query_field = NULL;
    ct_type_t rs_type;
    sql_cursor_t *sql_cur = NULL;
    char **pending_buf = NULL;

    var_col.tab = table->id;
    var_col.ancestor = 0;
    var_col.is_array = 0;
    var_col.col_info_ptr = &col_info;

    if (table->query_fields.count == 0) {
        row_init(&row_ass, buf, buf_size, 1);
    } else {
        node = cm_bilist_tail(&table->query_fields);
        query_field = BILIST_NODE_OF(query_field_t, node, bilist_node);
        row_init(&row_ass, buf, buf_size, query_field->col_id + 1);

        node = cm_bilist_head(&table->query_fields);
        for (; node != NULL; node = BINODE_NEXT(node)) {
            query_field = BILIST_NODE_OF(query_field_t, node, bilist_node);
            sql_set_col_info(&var_col, query_field);
            rs_type = (query_field->datatype == CT_TYPE_UNKNOWN) ? CT_TYPE_STRING : query_field->datatype;
            sql_cur = table_curs[table->id].sql_cur;

            if (table->type != FUNC_AS_TABLE) {
                CT_RETURN_IFERR(sql_get_table_value(stmt, &var_col, &value));
            } else {
                CT_RETURN_IFERR(sql_get_kernel_value(stmt, table, cursor->tables[table->id].knl_cur, &var_col, &value));
            }

            if (query_field->datatype == CT_TYPE_UNKNOWN && sql_cur != NULL &&
                (table->type == SUBSELECT_AS_TABLE || table->type == VIEW_AS_TABLE)) {
                pending_buf = &sql_cur->mtrl.rs.buf;
                CT_RETURN_IFERR(sql_set_pending_buf_coltype(stmt, sql_cur, pending_buf, var_col));
                rs_type = sql_make_pending_column_def(stmt, *pending_buf, rs_type, var_col.col, &value);
            }
            CT_RETURN_IFERR(sql_set_row_value(stmt, &row_ass, rs_type, &value, var_col.col));
        }
    }
    sql_set_table_rowid(stmt, &row_ass, table);
    return CT_SUCCESS;
}

static status_t sql_mtrl_insert_merge_rs_row(sql_stmt_t *stmt, sql_cursor_t *cursor, join_info_t *merge_join,
    row_assist_t *key_ra, char *key_buf)
{
    char *buf = NULL;
    mtrl_rowid_t mtrl_rid;
    sql_table_t *table = NULL;

    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE + KNL_ROWID_LEN + REMOTE_ROWNODEID_LEN, (void **)&buf));

    for (int32 i = (int32)merge_join->rs_tables.count - 1; i >= 0; --i) {
        table = (sql_table_t *)sql_array_get(&merge_join->rs_tables, i);
        if (table->subslct_tab_usage == SUBSELECT_4_NORMAL_JOIN) {
            if (sql_make_mtrl_merge_rs_row(stmt, cursor, cursor->tables, table, buf, CT_MAX_ROW_SIZE) != CT_SUCCESS) {
                CTSQL_POP(stmt);
                return CT_ERROR;
            }
            if (mtrl_insert_row(&stmt->mtrl, cursor->mtrl.rs.sid, buf, &mtrl_rid) != CT_SUCCESS) {
                CTSQL_POP(stmt);
                return CT_ERROR;
            }
        } else {
            if (sql_make_mtrl_null_rs_row(&stmt->mtrl, cursor->mtrl.rs.sid, &mtrl_rid) != CT_SUCCESS) {
                CTSQL_POP(stmt);
                return CT_ERROR;
            }
        }
        if (key_ra->head->size + sizeof(mtrl_rowid_t) > CT_MAX_ROW_SIZE) {
            CTSQL_POP(stmt);
            CT_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, key_ra->head->size + sizeof(mtrl_rowid_t), CT_MAX_ROW_SIZE);
            return CT_ERROR;
        }
        *(mtrl_rowid_t *)(key_buf + key_ra->head->size) = mtrl_rid;
        key_ra->head->size += sizeof(mtrl_rowid_t);
    }
    CTSQL_POP(stmt);
    return CT_SUCCESS;
}

status_t sql_mtrl_merge_sort_insert(sql_stmt_t *stmt, sql_cursor_t *cursor, join_info_t *merge_join)
{
    char *key_buffer = NULL;
    row_assist_t key_ra;
    mtrl_rowid_t mtrl_rid;
    status_t status = CT_ERROR;

    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&key_buffer));
    row_init(&key_ra, key_buffer, CT_MAX_ROW_SIZE, merge_join->key_items->count);

    do {
        CT_BREAK_IF_ERROR(sql_make_mtrl_sort_row(stmt, NULL, merge_join->key_items, &key_ra));

        CT_BREAK_IF_ERROR(sql_mtrl_insert_merge_rs_row(stmt, cursor, merge_join, &key_ra, key_buffer));

        CT_BREAK_IF_ERROR(mtrl_insert_row(&stmt->mtrl, cursor->mtrl.sort.sid, key_buffer, &mtrl_rid));

        status = CT_SUCCESS;
    } while (CT_FALSE);
    CTSQL_POP(stmt);
    return status;
}

status_t sql_make_mtrl_table_rs_row(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_table_cursor_t *table_curs,
    sql_table_t *table, char *buf, uint32 buf_size)
{
    return sql_make_mtrl_merge_rs_row(stmt, cursor, table_curs, table, buf, buf_size);
}

status_t sql_alloc_mem_from_seg(sql_stmt_t *stmt, mtrl_segment_t *seg, uint32 size, void **buf, mtrl_rowid_t *rid)
{
    mtrl_page_t *page = (mtrl_page_t *)seg->curr_page->data;

    if (page->id != seg->vm_list.last) {
        mtrl_close_segment2(&stmt->mtrl, seg);
        CT_RETURN_IFERR(mtrl_open_page(&stmt->mtrl, seg->vm_list.last, &seg->curr_page));
        page = (mtrl_page_t *)seg->curr_page->data;
    }

    if (page->free_begin + size > CT_VMEM_PAGE_SIZE) {
        mtrl_close_segment2(&stmt->mtrl, seg);
        if (mtrl_extend_segment(&stmt->mtrl, seg) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (mtrl_open_page(&stmt->mtrl, seg->vm_list.last, &seg->curr_page) != CT_SUCCESS) {
            return CT_ERROR;
        }
        page = (mtrl_page_t *)seg->curr_page->data;
        mtrl_init_page(page, seg->vm_list.last);
    }
    rid->vmid = seg->vm_list.last;

    *buf = ((char *)page + page->free_begin);
    rid->slot = page->rows;
    page->rows++;
    page->free_begin += size;

    return CT_SUCCESS;
}

status_t sql_alloc_segment_in_vm(sql_stmt_t *stmt, uint32 seg_id, mtrl_segment_t **seg, mtrl_rowid_t *mtrl_rid)
{
    return sql_alloc_mem_from_seg(stmt, stmt->mtrl.segments[seg_id], sizeof(mtrl_segment_t), (void **)seg, mtrl_rid);
}

status_t sql_get_mem_in_vm(sql_stmt_t *stmt, uint32 seg_id, mtrl_rowid_t *rid, uint32 row_size, void **buf)
{
    uint32 offset;
    mtrl_segment_t *seg = stmt->mtrl.segments[seg_id];
    mtrl_page_t *page = NULL;

    if (rid->vmid != seg->curr_page->vmid) {
        mtrl_close_page(&stmt->mtrl, seg->curr_page->vmid);
        seg->curr_page = NULL;
        CT_RETURN_IFERR(mtrl_open_page(&stmt->mtrl, rid->vmid, &seg->curr_page));
    }
    page = (mtrl_page_t *)seg->curr_page->data;
    offset = sizeof(mtrl_page_t) + rid->slot * row_size;
    *buf = (char *)page + offset;
    return CT_SUCCESS;
}

status_t sql_get_segment_in_vm(sql_stmt_t *stmt, uint32 seg_id, mtrl_rowid_t *rid, mtrl_segment_t **mtrl_seg)
{
    return sql_get_mem_in_vm(stmt, seg_id, rid, sizeof(mtrl_segment_t), (void **)mtrl_seg);
}

status_t sql_get_mtrl_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, mtrl_rowid_t *rid, mtrl_cursor_t **mtrl_cursor)
{
    if (rid->vmid == CT_INVALID_ID32) {
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(
        sql_get_mem_in_vm(stmt, cursor->mtrl.sibl_sort.cursor_sid, rid, sizeof(mtrl_cursor_t), (void **)mtrl_cursor));
    return CT_SUCCESS;
}

static void sql_free_segment_in_page(mtrl_context_t *mtrl, uint32 vmid)
{
    uint32 free_begin;
    vm_page_t *curr_page = NULL;
    mtrl_page_t *mtrl_page = NULL;
    mtrl_segment_t *seg = NULL;

    if (mtrl_open_page(mtrl, vmid, &curr_page) != CT_SUCCESS) {
        return;
    }
    mtrl_page = (mtrl_page_t *)curr_page->data;

    if (mtrl_page->rows == 0) {
        mtrl_close_page(mtrl, vmid);
        return;
    }

    free_begin = sizeof(mtrl_page_t);
    for (uint32 i = 0; i < mtrl_page->rows; ++i) {
        seg = (mtrl_segment_t *)((char *)mtrl_page + free_begin);
        if (seg->vm_list.count != 0) {
            vm_free_list(mtrl->session, mtrl->pool, &seg->vm_list);
        }
        free_begin += sizeof(mtrl_segment_t);
    }
    mtrl_init_page(mtrl_page, vmid);
    mtrl_close_page(mtrl, vmid);
}

void sql_free_segment_in_vm(sql_stmt_t *stmt, uint32 seg_id)
{
    uint32 id, next;
    vm_ctrl_t *vm_ctrl = NULL;
    mtrl_segment_t *seg = stmt->mtrl.segments[seg_id];

    if (seg->vm_list.count == 0) {
        return;
    }

    id = seg->vm_list.first;

    while (id != CT_INVALID_ID32) {
        vm_ctrl = vm_get_ctrl(stmt->mtrl.pool, id);
        next = vm_ctrl->next;
        sql_free_segment_in_page(&stmt->mtrl, id);
        id = next;
    }
}

status_t sql_free_mtrl_cursor_in_vm(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    mtrl_cursor_t *curr_cur = NULL;
    mtrl_cursor_t *pre_cur = NULL;
    mtrl_cursor_t *next_cur = NULL;
    mtrl_rowid_t pre_rid;
    mtrl_rowid_t next_rid;
    CT_RETURN_IFERR(sql_get_mtrl_cursor(stmt, cursor, &cursor->mtrl.cursor.curr_cursor_rid, &curr_cur));
    if (curr_cur != NULL) {
        next_rid = curr_cur->next_cursor_rid;
        pre_rid = curr_cur->pre_cursor_rid;
        CT_RETURN_IFERR(sql_get_mtrl_cursor(stmt, cursor, &next_rid, &next_cur));
        CT_RETURN_IFERR(sql_get_mtrl_cursor(stmt, cursor, &pre_rid, &pre_cur));
        mtrl_close_cursor(&stmt->mtrl, curr_cur);
        if (next_cur != NULL) {
            mtrl_close_cursor(&stmt->mtrl, next_cur);
        }
        if (pre_cur != NULL) {
            mtrl_close_cursor(&stmt->mtrl, pre_cur);
        }
    }
    return CT_SUCCESS;
}

void sql_free_sibl_sort(sql_stmt_t *stmt, sql_cursor_t *sql_cursor)
{
    if (sql_cursor->mtrl.sibl_sort.cursor_sid != CT_INVALID_ID32) {
        (void)sql_free_mtrl_cursor_in_vm(stmt, sql_cursor);
        mtrl_close_segment(&stmt->mtrl, sql_cursor->mtrl.sibl_sort.cursor_sid);
        mtrl_release_segment(&stmt->mtrl, sql_cursor->mtrl.sibl_sort.cursor_sid);
        sql_cursor->mtrl.sibl_sort.cursor_sid = CT_INVALID_ID32;
    }
    if (sql_cursor->mtrl.sibl_sort.sid != CT_INVALID_ID32) {
        mtrl_close_segment(&stmt->mtrl, sql_cursor->mtrl.sibl_sort.sid);
        sql_free_segment_in_vm(stmt, sql_cursor->mtrl.sibl_sort.sid);
        mtrl_release_segment(&stmt->mtrl, sql_cursor->mtrl.sibl_sort.sid);
        sql_cursor->mtrl.sibl_sort.sid = CT_INVALID_ID32;
    }
}

status_t sql_set_segment_pages_hold(mtrl_context_t *ctx, uint32 seg_id, uint32 pages_hold)
{
    vm_page_t *page = NULL;
    mtrl_segment_t *seg = ctx->segments[seg_id];

    seg->pages_hold = pages_hold;

    if (seg->vm_list.count < seg->pages_hold) {
        return vm_open(ctx->session, ctx->pool, seg->vm_list.last, &page);
    }
    return CT_SUCCESS;
}

static inline int32 sql_compare_expr_loc(source_location_t location1, source_location_t location2)
{
    if (location1.line != location2.line) {
        return (location1.line > location2.line) ? 1 : -1;
    } else {
        return (location1.column > location2.column) ? 1 : -1;
    }
}

status_t sql_get_hash_key_types(sql_stmt_t *stmt, sql_query_t *query, galist_t *local_keys, galist_t *peer_keys,
    ct_type_t *key_types)
{
    expr_tree_t *local_expr = NULL;
    expr_tree_t *peer_expr = NULL;
    ct_type_t local_type, peer_type, dst_type;

    CM_ASSERT(query != NULL);

    for (uint32 i = 0; i < local_keys->count; i++) {
        local_expr = (expr_tree_t *)cm_galist_get(local_keys, i);
        peer_expr = (expr_tree_t *)cm_galist_get(peer_keys, i);
        CT_RETURN_IFERR(sql_infer_expr_node_datatype(stmt, query, local_expr->root, &local_type));
        CT_RETURN_IFERR(sql_infer_expr_node_datatype(stmt, query, peer_expr->root, &peer_type));
        dst_type = get_cmp_datatype(local_type, peer_type);
        if (dst_type == INVALID_CMP_DATATYPE) {
            if (sql_compare_expr_loc(local_expr->root->loc, peer_expr->root->loc) < 0) {
                CT_SRC_ERROR_MISMATCH(peer_expr->root->loc, local_type, peer_type);
            } else {
                CT_SRC_ERROR_MISMATCH(local_expr->root->loc, peer_type, local_type);
            }
            return CT_ERROR;
        }
        key_types[i] = dst_type;
    }
    return CT_SUCCESS;
}

status_t sql_make_hash_key(sql_stmt_t *stmt, row_assist_t *ra, char *buf, galist_t *local_keys, ct_type_t *types,
    bool32 *has_null)
{
    variant_t value;
    expr_tree_t *local_expr = NULL;

    row_init(ra, buf, CT_MAX_ROW_SIZE, local_keys->count);

    for (uint32 i = 0; i < local_keys->count; i++) {
        local_expr = (expr_tree_t *)cm_galist_get(local_keys, i);
        CT_RETURN_IFERR(sql_exec_expr(stmt, local_expr, &value));
        if (CT_IS_LOB_TYPE(value.type)) {
            CT_RETURN_IFERR(sql_get_lob_value(stmt, &value));
        }
        if (value.is_null) {
            *has_null = CT_TRUE;
            return CT_SUCCESS;
        }
        if (types[i] == CT_TYPE_CHAR) {
            cm_rtrim_text(&value.v_text);
        }
        CT_RETURN_IFERR(sql_put_row_value(stmt, NULL, ra, types[i], &value));
    }

    *has_null = CT_FALSE;
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
