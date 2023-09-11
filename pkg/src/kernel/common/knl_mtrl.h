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
 * knl_mtrl.h
 *
 *
 * IDENTIFICATION
 * src/kernel/common/knl_mtrl.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_MTRL_H__
#define __KNL_MTRL_H__

#include "cm_defs.h"
#include "cm_memory.h"
#include "cm_list.h"
#include "cm_thread.h"
#include "knl_interface.h"
#include "knl_session.h"
#include "knl_index.h"
#include "knl_sort_page.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_MTRL_SORT_THREADS 4
#define MAX_MTRL_SORT_EXTENTS (1024 * 8)     // 1G
#define MIN_MTRL_SORT_EXTENTS 1024         // 1024 * 128K = 128M
typedef struct st_mtrl_sort_ctrl {
    spinlock_t lock;
    bool32 use_parallel;
    bool32 sort_done;
    bool32 insert_complete;
    thread_t threads[MAX_SORT_THREADS];
    id_list_t sort_pages;
    mtrl_segment_t *segment;
    mtrl_context_t *ctx;
    uint32 thread_count;
    uint32 cur_seg_id;
    bool32 initialized;
} mtrl_sort_ctrl_t;

typedef struct st_mtrl_hash_node {
    mtrl_rowid_t rid;
} mtrl_hash_node_t;

typedef struct st_mtrl_heap_ctrl {
    mtrl_context_t *ctx;
    mtrl_segment_t *segment;
    uint32 whole_count;
    uint32 whole_pages[GS_MAX_MTRL_OPEN_PAGES];
    uint32 heap_count;
    uint32 heap_pages[GS_MAX_MTRL_OPEN_PAGES];
    uint32 seg_id;
    mtrl_page_t *heap_page;
} mtrl_heap_ctrl_t;

typedef struct st_sibl_sort_row {
    mtrl_rowid_t rs_rid;
    mtrl_rowid_t child_seg_rid;
    mtrl_rowid_t sibling_seg_rid;
    bool32 match_filter;
} sibl_sort_row_t;


#define MTRL_GET_DIR(page, id) (uint32 *)((char *)(page) + GS_VMEM_PAGE_SIZE - ((id) + 1) * sizeof(uint32))
#define MTRL_GET_ROW(page, id) ((char *)(page) + *MTRL_GET_DIR((page), (id)))
#define MTRL_DIR_SIZE(page)    ((page)->rows * sizeof(uint32))
#define MTRL_PAGE_FREE_SIZE(page) \
    (GS_VMEM_PAGE_SIZE - MTRL_DIR_SIZE(page) - ((page)->free_begin))
typedef void (*mtrl_close_page_func_t)(mtrl_context_t *ctx, mtrl_sort_cursor_t *cursor);

status_t mtrl_init_cursor(mtrl_cursor_t *cursor);
status_t mtrl_open_page(mtrl_context_t *ctx, uint32 vmid, vm_page_t **page);
void mtrl_close_page(mtrl_context_t *ctx, uint32 vmid);
status_t mtrl_extend_segment(mtrl_context_t *ctx, mtrl_segment_t *segment);
status_t mtrl_sort_init(knl_session_t *session, index_t *index, knl_part_locate_t part_loc,
    mtrl_sort_ctrl_t *sort_ctrl);
status_t mtrl_insert_row_parallel(mtrl_context_t *ctx, uint32 seg_id, const char *row, mtrl_sort_ctrl_t *sort_ctrl,
                                  mtrl_rowid_t *rid);
status_t mtrl_sort_clean(mtrl_sort_ctrl_t *sort_ctrl);
status_t mtrl_split_segment(mtrl_context_t *ctx, uint32 seg_id, uint32 *new_seg_id);
status_t mtrl_merge_2segments(mtrl_context_t *ctx, uint32 seg_id1, uint32 seg_id2);
status_t mtrl_sort_segment_parallel(mtrl_sort_ctrl_t *sort_ctrl, mtrl_context_t *ctx, uint32 seg_id);
void mtrl_close_history_page(mtrl_context_t *ctx, mtrl_cursor_t *cursor);

status_t mtrl_insert_row2(mtrl_context_t *ctx, mtrl_segment_t *segment, char *row, mtrl_rowid_t *rid);
status_t mtrl_open_segment2(mtrl_context_t *ctx, mtrl_segment_t *segment);
status_t mtrl_sort_segment2(mtrl_context_t *ctx, mtrl_segment_t *segment);
status_t mtrl_fetch_sibl_sort(mtrl_context_t *ctx, mtrl_cursor_t *cursor, mtrl_cursor_t *curr_level_cursor,
    sibl_sort_row_t *sibl_row);
bool32 mtrl_fill_page_up(mtrl_context_t *ctx, mtrl_page_t *dst_page, mtrl_page_t *src_page);
status_t mtrl_move_rs_cursor(mtrl_context_t *ctx, mtrl_cursor_t *cursor);
status_t mtrl_merge_2pools(knl_handle_t paral_ctx, uint32 id1, uint32 id2);
void mtrl_sort_proc(thread_t *thread);
void mtrl_sort_page_enqueue(mtrl_sort_ctrl_t *sort_ctrl, vm_page_t *vm_page);
status_t mtrl_open_sort_cursor(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_rowid_t *rid,
    uint32 level, mtrl_sort_cursor_t *cursor);
status_t mtrl_merge_compare(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_sort_cursor_t *cursor1,
    mtrl_sort_cursor_t *cursor2, mtrl_sort_cursor_t **result_cur);
void mtrl_close_sorted_page(mtrl_context_t *ctx, mtrl_sort_cursor_t *cursor);
status_t mtrl_move_sort_cursor(mtrl_context_t *ctx, mtrl_sort_cursor_t *cursor, mtrl_close_page_func_t close_func);
void mtrl_reset_sort_type(mtrl_context_t *ctx, uint32 id);
status_t mtrl_move_group_cursor(mtrl_context_t *ctx, mtrl_sort_cursor_t *cursor);
status_t mtrl_ins_row_in_page(mtrl_context_t *ctx, uint32 page_id, const char *row, bool32 *is_full);

static inline void mtrl_init_segment(mtrl_segment_t *segment, mtrl_segment_type_t type, handle_t cmp_items)
{
    segment->vm_list.count = 0;
    segment->type = type;
    segment->sort_type = MTRL_SORT_TYPE_INSERT;
    segment->cmp_items = cmp_items;
    segment->curr_page = NULL;
    segment->level = 0;
    segment->pending_type_buf = NULL;
    segment->pages_hold = 0;
}

#ifdef __cplusplus
}
#endif

#endif
