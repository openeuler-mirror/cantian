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
 * ctsql_mtrl.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_mtrl.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_MTRL_H__
#define __SQL_MTRL_H__

#include "dml_executor.h"
#include "knl_mtrl.h"

#define MT_CDATA(row, id) ((row)->data + (row)->offsets[id])
#define MT_CSIZE(row, id) ((row)->lens[id])

static inline int32 sql_compare_data_ex(void *data1, uint16 size1, void *data2, uint16 size2, ct_type_t type)
{
    if (size1 == CT_NULL_VALUE_LEN || size2 == CT_NULL_VALUE_LEN) {
        return (size1 == size2) ? 0 : (size1 == CT_NULL_VALUE_LEN) ? 1 : -1;
    }

    return var_compare_data_ex(data1, size1, data2, size2, type);
}

static inline int32 sql_sort_mtrl_rows(mtrl_row_t *row1, mtrl_row_t *row2, uint32 col, ct_type_t type,
    const order_mode_t *order_mode)
{
    uint32 size1 = MT_CSIZE(row1, col);
    uint32 size2 = MT_CSIZE(row2, col);
    int32 flag = 0;

    if (size1 == CT_NULL_VALUE_LEN || size2 == CT_NULL_VALUE_LEN) {
        if (size1 == size2) {
            return 0;
        }

        flag = (order_mode->nulls_pos == SORT_NULLS_LAST) ? 1 : -1;
        return (size1 == CT_NULL_VALUE_LEN) ? flag : -flag;
    }

    flag = var_compare_data_ex(MT_CDATA(row1, col), size1, MT_CDATA(row2, col), size2, type);
    return (order_mode->direction == SORT_MODE_ASC) ? flag : -flag;
}

static inline void mtrl_row_init(mtrl_row_assist_t *ra, mtrl_row_t *row)
{
    ra->data = row->data;
    ra->lens = row->lens;
    ra->offsets = row->offsets;
}

void sql_reset_mtrl(sql_stmt_t *stmt, sql_cursor_t *sql_cursor);
void sql_init_mtrl(mtrl_context_t *mtrl_ctx, session_t *session);
status_t sql_mtrl_get_windowing_sort_val(mtrl_sort_cursor_t *sort, uint32 id, ct_type_t datatype, variant_t *sort_val);
status_t sql_mtrl_get_windowing_value(mtrl_cursor_t *cursor, variant_t *sort_val, variant_t *l_val, variant_t *r_val);
status_t sql_mtrl_get_windowing_border(mtrl_cursor_t *cursor, variant_t *l_val, variant_t *r_val);
status_t sql_make_mtrl_group_row(sql_stmt_t *stmt, char *pending_buf, group_plan_t *group_p, char *buf);
status_t sql_make_mtrl_rs_row(sql_stmt_t *stmt, char *pending_buf, galist_t *columns, char *buf);
status_t sql_make_mtrl_select_sort_row(sql_stmt_t *stmt, char *pending_buf, sql_cursor_t *cursor, galist_t *sort_items,
    mtrl_rowid_t *rid, char *buf);
status_t sql_make_mtrl_query_sort_row(sql_stmt_t *stmt, char *pending_buf, galist_t *sort_items, mtrl_rowid_t *rid,
    char *buf);
status_t sql_put_row_value(sql_stmt_t *stmt, char *pending_buf, row_assist_t *ra, ct_type_t temp_type, variant_t *value);
status_t sql_set_row_value(sql_stmt_t *stmt, row_assist_t *row_ass, ct_type_t type, variant_t *value, uint32 col_id);
status_t sql_materialize_base(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan);
status_t sql_mtrl_sort_cmp(mtrl_segment_t *seg, char *data1, char *data2, int32 *result);
status_t sql_row_put_value(sql_stmt_t *stmt, row_assist_t *row_ass, variant_t *value);

static inline void sql_init_scan_assist(char *row_buf, hash_scan_assist_t *sa)
{
    row_head_t *row_head = (row_head_t *)row_buf;
    sa->scan_mode = HASH_KEY_SCAN;
    sa->buf = row_buf;
    sa->size = row_head->size;
}

#ifdef Z_SHARDING
int32 sql_compare_data_ex(void *data1, uint16 size1, void *data2, uint16 size2, ct_type_t type);
#endif

status_t sql_mtrl_merge_sort_insert(sql_stmt_t *stmt, sql_cursor_t *cursor, join_info_t *merge_join);
status_t sql_make_mtrl_winsort_row(sql_stmt_t *stmt, winsort_args_t *args, mtrl_rowid_t *rid, char *buf,
    char *pending_buf);
status_t sql_make_mtrl_table_rs_row(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_table_cursor_t *table_curs,
    sql_table_t *table, char *buf, uint32 buf_size);

status_t sql_alloc_segment_in_vm(sql_stmt_t *stmt, uint32 seg_id, mtrl_segment_t **seg, mtrl_rowid_t *mtrl_rid);
status_t sql_get_segment_in_vm(sql_stmt_t *stmt, uint32 seg_id, mtrl_rowid_t *rid, mtrl_segment_t **mtrl_seg);
status_t sql_get_mtrl_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, mtrl_rowid_t *rid, mtrl_cursor_t **mtrl_cursor);
void sql_free_segment_in_vm(sql_stmt_t *stmt, uint32 seg_id);
status_t sql_make_mtrl_sibl_sort_row(sql_stmt_t *stmt, char *pending_buf, galist_t *sort_items, char *buf,
    sibl_sort_row_t *sibl_sort_row);
status_t sql_alloc_mem_from_seg(sql_stmt_t *stmt, mtrl_segment_t *seg, uint32 size, void **buf, mtrl_rowid_t *rid);
status_t sql_free_mtrl_cursor_in_vm(sql_stmt_t *stmt, sql_cursor_t *cursor);
void sql_free_sibl_sort(sql_stmt_t *stmt, sql_cursor_t *sql_cursor);
void sql_free_connect_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor);
status_t sql_make_mtrl_null_rs_row(mtrl_context_t *mtrl, uint32 seg_id, mtrl_rowid_t *rid);
status_t sql_make_hash_key(sql_stmt_t *stmt, row_assist_t *ra, char *buf, galist_t *local_keys, ct_type_t *types,
    bool32 *has_null);
status_t sql_get_hash_key_types(sql_stmt_t *stmt, sql_query_t *query, galist_t *local_keys, galist_t *peer_keys,
    ct_type_t *key_types);
status_t init_null_row(void);
status_t sql_fetch_null_row(sql_stmt_t *stmt, sql_cursor_t *cursor);
void sql_free_null_row(void);
status_t sql_make_mtrl_sort_row(sql_stmt_t *stmt, char *pending_buf, galist_t *sort_items, row_assist_t *ra);
status_t sql_set_segment_pages_hold(mtrl_context_t *ctx, uint32 seg_id, uint32 pages_hold);
status_t sql_inherit_pending_buf(sql_cursor_t *cursor, sql_cursor_t *sub_cursor);
status_t sql_revert_pending_buf(sql_cursor_t *cursor, sql_cursor_t *sub_cursor);
void sql_free_hash_mtrl(sql_stmt_t *stmt);
#define CTSQL_RELEASE_SEGMENT(stmt, seg)                  \
    do {                                                \
        if ((seg) != CT_INVALID_ID32) {                 \
            mtrl_close_segment(&(stmt)->mtrl, (seg));   \
            mtrl_release_segment(&(stmt)->mtrl, (seg)); \
            (seg) = CT_INVALID_ID32;                    \
        }                                               \
    } while (0)

#endif