/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * mtrl_defs.h
 *
 *
 * IDENTIFICATION
 * src/kernel/include/mtrl_defs.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_MTRL_DEFS_H__
#define __KNL_MTRL_DEFS_H__

#include "knl_defs.h"

#ifdef __cplusplus
extern "C" {
#endif
  
// for materialization
typedef enum en_mtrl_segment_type {
    MTRL_SEGMENT_QUERY_SORT,
    MTRL_SEGMENT_SELECT_SORT,
    MTRL_SEGMENT_GROUP,
    MTRL_SEGMENT_DISTINCT,
    MTRL_SEGMENT_RS,
    MTRL_SEGMENT_AGGR,
    MTRL_SEGMENT_PCR_BTREE,
    MTRL_SEGMENT_RCR_BTREE,
    MTRL_SEGMENT_TEMP,
    MTRL_SEGMENT_WINSORT,
    MTRL_SEGMENT_WINSORT_AGGR,
    MTRL_SEGMENT_WINSORT_RS,
    MTRL_SEGMENT_HIST,
    MTRL_SEGMENT_HASHMAP,
    MTRL_SEGMENT_HASHMAP_RS,
    MTRL_SEGMENT_MERGE_INTO,
    MTRL_SEGMENT_EXTRA_DATA,
    MTRL_SEGMENT_CONCAT_SORT,
    MTRL_SEGMENT_SORT_SEG,
    MTRL_SEGMENT_SIBL_SORT,
    MTRL_SEGMENT_PAR_DATA,
} mtrl_segment_type_t;

typedef enum en_mtrl_sort_type {
    MTRL_SORT_TYPE_INSERT,
    MTRL_SORT_TYPE_QSORT,            // quick sort by Double-End Scanning and Swapping
    MTRL_SORT_TYPE_ADAPTIVE_SORT,    // It combines Binary-Insertion SORT, Dual-Pivot QSORT and Three-Way QSORT
} mtrl_sort_type_t;

typedef struct st_mtrl_segment {
    id_list_t vm_list;
    mtrl_segment_type_t type;
    mtrl_sort_type_t sort_type;
    handle_t cmp_items;  // list of sql_sort_item_t / sql_expr_t or index
    vm_page_t *curr_page;
    uint32 level;
    bool32 is_used;
    uint32 cmp_flag;  // winsort need more than once sort in different phase.
    uint32 pages_hold;
    char   *pending_type_buf;  // datatype for pending
} mtrl_segment_t;

typedef status_t (*mtrl_sort_cmp_t)(mtrl_segment_t *segment, char *data1, char *data2, int32 *result);
typedef void (*mtrl_print_page_t)(mtrl_segment_t *segment, char *page);

typedef struct st_mtrl_context {
    spinlock_t lock;
    uint32 seg_count;
    uint32 open_pages[GS_MAX_MTRL_OPEN_PAGES];
    handle_t session;
    vm_pool_t *pool;
    mtrl_sort_cmp_t sort_cmp;
    mtrl_print_page_t print_page;
    uint32 open_hwm;
    char *err_msg;
    vmc_t vmc;
    // segments must be at the end of mtrl_context_t
    mtrl_segment_t *segments[GS_MAX_MATERIALS];
} mtrl_context_t;

typedef struct st_mtrl_page {
    uint32 id;
    uint32 free_begin;
    uint16 rows;
    uint16 has_part_info : 1;  // for sorting, if page has part info or not.
    uint16 page_occupied : 1;  // for sorting, when part info is not in slot0, then page is occupied by 2 part.
    uint16 is_sorted : 1;      // avoid some pages being sorted multiple times in mtrl_sort_segment_parallel.
    uint16 unused : 13;
} mtrl_page_t;

typedef struct st_mtrl_part {
    uint16 size;  // as a row in page
    uint16 unused;
    mtrl_rowid_t next;
    uint64 rows;
} mtrl_part_t;

typedef struct st_mtrl_sort_cursor {
    uint32 vmid;
    uint32 last_vmid;
    uint32 slot;
    uint32 rownum;
    mtrl_page_t *page;
    mtrl_part_t part;
    mtrl_segment_t *segment;
    mtrl_context_t *ctx;
    char *row;
} mtrl_sort_cursor_t;

typedef struct st_mtrl_row {
    char *data;
    uint16 lens[GS_MAX_COLUMNS];
    uint16 offsets[GS_MAX_COLUMNS];
} mtrl_row_t;

typedef struct st_mtrl_row_assist {
    char *data;
    uint16 *lens;
    uint16 *offsets;
} mtrl_row_assist_t;

typedef struct st_row_addr {
    char **data;
    uint16 *offset;
    uint16 *len;
    rowid_t *rowid;
    uint16 *rownodeid;
} row_addr_t;

typedef struct st_mtrl_hash_group_cursor {
    char *aggrs;
} mtrl_hash_group_cursor_t;

typedef struct st_mtrl_hash_distinct_cursor {
    bool32 eof;
    mtrl_row_assist_t row;
} mtrl_hash_distinct_cursor_t;

typedef enum en_mtrl_cursor_type {
    MTRL_CURSOR_OTHERS = 0,
    MTRL_CURSOR_SORT_GROUP,
    MTRL_CURSOR_HASH_GROUP,
    MTRL_CURSOR_HASH_DISTINCT,
} mtrl_cursor_type_t;

typedef struct st_mtrl_cursor {
    mtrl_sort_cursor_t sort;
    mtrl_hash_group_cursor_t hash_group;
    mtrl_hash_distinct_cursor_t distinct;
    mtrl_row_t row;
    uint32 rs_vmid;
    mtrl_page_t *rs_page;
    bool32 eof;
    uint32 slot;
    uint32 history[GS_MAX_JOIN_TABLES];
    uint32 count;
    mtrl_cursor_type_t type;
    mtrl_rowid_t next_cursor_rid;
    mtrl_rowid_t pre_cursor_rid;
    mtrl_rowid_t curr_cursor_rid;
    mtrl_sort_cursor_t *result_cur;
} mtrl_cursor_t;

typedef struct st_mtrl_savepoint {
    uint32 rownum;
    mtrl_rowid_t vm_row_id;
} mtrl_savepoint_t;

// materialization API
static inline void mtrl_init_page(mtrl_page_t *page, uint32 id)
{
    page->id = id;
    page->rows = 0;
    page->free_begin = sizeof(mtrl_page_t);
    page->has_part_info = GS_FALSE;
    page->page_occupied = GS_FALSE;
    page->is_sorted = GS_FALSE;
    page->unused = 0;
}
void mtrl_init_context(mtrl_context_t *ctx, handle_t sess);
void mtrl_release_context(mtrl_context_t *ctx);
status_t mtrl_create_segment(mtrl_context_t *ctx, mtrl_segment_type_t type, handle_t cmp_items, uint32 *id);
void mtrl_set_sort_type(mtrl_segment_t *segment, mtrl_sort_type_t sort_type);
void mtrl_release_segment(mtrl_context_t *ctx, uint32 id);
status_t mtrl_insert_row(mtrl_context_t *ctx, uint32 seg_id, char *row, mtrl_rowid_t *rid);
status_t mtrl_open_segment(mtrl_context_t *ctx, uint32 seg_id);
void mtrl_close_segment(mtrl_context_t *ctx, uint32 seg_id);
void mtrl_close_segment2(mtrl_context_t *ctx, mtrl_segment_t *segment);
status_t mtrl_sort_segment(mtrl_context_t *ctx, uint32 seg_id);
status_t mtrl_open_cursor(mtrl_context_t *ctx, uint32 sort_seg, mtrl_cursor_t *cursor);
status_t mtrl_open_cursor2(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_cursor_t *cursor);
status_t mtrl_open_rs_cursor(mtrl_context_t *ctx, uint32 sort_seg, mtrl_cursor_t *cursor);
void mtrl_close_sort_cursor(mtrl_context_t *ctx, mtrl_sort_cursor_t *cursor);
void mtrl_close_cursor(mtrl_context_t *ctx, mtrl_cursor_t *cursor);
status_t mtrl_fetch_sort(mtrl_context_t *ctx, mtrl_cursor_t *cursor);
status_t mtrl_fetch_group(mtrl_context_t *ctx, mtrl_cursor_t *cursor, bool32 *group_changed);
status_t mtrl_get_column_value(mtrl_row_assist_t *row, bool32 eof, uint32 id, gs_type_t datatype,
                               bool8 is_array, variant_t *value);
status_t mtrl_fetch_rs(mtrl_context_t *ctx, mtrl_cursor_t *cursor, bool32 decode);
mtrl_page_t *mtrl_curr_page(mtrl_context_t *ctx, uint32 seg_id);
status_t mtrl_fetch_sort_key(mtrl_context_t *ctx, mtrl_cursor_t *cursor);
status_t mtrl_fetch_winsort_rid(mtrl_context_t *ctx, mtrl_cursor_t *cursor, uint32 cmp_flag, bool32 *grp_chged,
                                bool32 *ord_chged);
status_t mtrl_fetch_merge_sort_row(mtrl_context_t *ctx, mtrl_cursor_t *cursor, row_addr_t *rows, uint32 count,
                                   bool32 *eof);
status_t mtrl_fetch_savepoint(mtrl_context_t *ctx, uint32 sort_seg, mtrl_savepoint_t *savepoint,
                              mtrl_cursor_t *cursor, row_addr_t *rows, uint32 count);
status_t mtrl_win_aggr_append_data(mtrl_context_t *ctx, uint32 seg_id, const char *data, uint32 size);
status_t mtrl_win_aggr_alloc(mtrl_context_t *ctx, uint32 seg_id, void **var, uint32 var_size,
                             mtrl_rowid_t *rid, bool32 need_close);
void  mtrl_win_release_segment(mtrl_context_t *ctx, uint32 seg_id, uint32 *maps, uint32 max_count);
bool32 mtrl_win_cur_page_is_enough(mtrl_context_t *ctx, uint32 seg_id, uint32 size);
status_t mtrl_win_aggr_get(mtrl_context_t *ctx, uint32 seg_id, char **row, mtrl_rowid_t *rid, bool32 need_close);
void mtrl_init_mtrl_rowid(mtrl_rowid_t *rid);

#ifdef __cplusplus
}
#endif

#endif