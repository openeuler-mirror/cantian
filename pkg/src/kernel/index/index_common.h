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
 * index_common.h
 *
 *
 * IDENTIFICATION
 * src/kernel/index/index_common.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __INDEX_COMMON_H__
#define __INDEX_COMMON_H__

#include "rcr_btree.h"
#include "knl_common.h"
#include "knl_interface.h"
#include "knl_session.h"
#include "knl_index.h"
#include "rb_purge.h"
#include "knl_mtrl.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CSF_NUMBER_INDEX_LEN 4

#define MAX_IDX_PARAL_THREADS 64

#define MAX_SPLIT_RANGE_CNT 32

#define REBUILD_WAIT_MSEC   200

typedef struct st_idx_part_info {
    knl_part_locate_t part_loc;
    knl_part_locate_t curr_part;
    uint32 seg_count;
}idx_part_info_t;

typedef struct st_idxpart_worker {
    knl_session_t *session;
    thread_t thread;
    volatile uint32 is_working;
    struct st_idxpart_paral_ctx *ctx;
}idxpart_worker_t;

typedef struct st_idxpart_paral_ctx {
    spinlock_t parl_lock;
    knl_dictionary_t *private_dc;
    idx_part_info_t part_info;
    index_t **indexes;
    uint32 index_cnt;
    uint32 paral_count;     // internal fetch parallel count
    bool32 nologging;       // construct btree segemnt in nologging mode
    char err_msg[GS_MESSAGE_BUFFER_SIZE];
    struct st_idxpart_worker workers[MAX_IDX_PARAL_THREADS];
}idxpart_paral_ctx_t;

typedef enum en_idx_sort_phase {
    INIT_SEGMENT_PHASE = 0,
    BUILD_SEGMENT_PHASE = 1,
    SORT_SEGMENT_PHASE = 2,
    MERGE_SEGMENT_PHASE = 3,
    CONSTRUCT_INDEX_PHASE = 4,
    COMPLETE_PHASE = 5
} idx_sort_phase_t;

typedef struct st_idx_sort_worker {
    uint32 id;
    uint32 pool_id;
    uint32 seg_id;
    uint32 next_id;
    uint32 index_id;    /* alloc specified index for this worker */
    uint64 rows;
    knl_session_t *session;
    thread_t thread;
    mtrl_context_t *mtrl_ctx;
    mtrl_segment_t *segment;
    knl_scan_range_t scan_range;
    volatile bool32 is_working;
    volatile idx_sort_phase_t phase;
    struct st_idx_paral_sort_ctx *ctx;
} idx_sort_worker_t;

typedef struct st_idx_multi_info {
    btree_t *btree;
    uint32 seg_id;
    mtrl_context_t mtrl_ctx;
    mtrl_segment_t *segment;
    struct st_idx_build_worker *ctx;
} idx_multi_info_t;

typedef struct st_idx_build_worker {
    spinlock_t parl_lock;
    uint32 pool_id;
    uint32 paral_count;
    uint32 index_count;
    volatile bool32 is_working;
    knl_dictionary_t *private_dc;
    idx_part_info_t part_info;
    knl_scan_range_t scan_range;
    uint64 rows;
    knl_session_t *session;
    thread_t thread;
    struct st_idx_multi_info *idx_info;
    struct st_idx_paral_sort_ctx *ctx;
} idx_build_worker_t;

typedef struct st_idx_paral_sort_ctx {
    spinlock_t parl_lock;
    uint32 paral_count;
    uint32 build_count;
    volatile uint32 working_count;
    btree_t *btree[GS_MAX_INDEX_COUNT_PERSQL];
    uint32 index_count;
    knl_dictionary_t *private_dc;
    idx_part_info_t part_info;
    union {
        id_list_t sort_info;
        id_list_t multi_sort_info[GS_MAX_INDEX_COUNT_PERSQL];
    };
    bool32 is_global;
    bool32 nologging;
    char err_msg[GS_MESSAGE_BUFFER_SIZE];
    volatile idx_sort_phase_t phase;
    idx_sort_worker_t *workers;
    idx_build_worker_t *build_workers;
} idx_paral_sort_ctx_t;

typedef struct st_idx_conflict_info {
    bool32 conflict;
    bool32 is_duplicate;
}idx_conflict_info_t;

typedef struct st_idx_paral_rebuild_worker {
    spinlock_t parl_lock;
    uint32 id;
    int32 current_range_index;
    knl_part_locate_t part_loc;
    knl_scan_range_t range;
    knl_scan_range_t *split_range[MAX_SPLIT_RANGE_CNT];
    volatile bool32 is_working;
    volatile uint32 splited_cnt; // balance worker rebuild one range no need split range.
    knl_session_t *session;
    thread_t thread;
    struct st_idx_paral_rebuild_ctx *ctx;
}idx_paral_rebuild_worker_t;

typedef struct st_idx_paral_rebuild_ctx {
    knl_dictionary_t *dc;
    uint32 paral_cnt;
    knl_part_locate_t current_part;
    char err_msg[GS_MESSAGE_BUFFER_SIZE];
    struct st_idx_paral_rebuild_worker workers[GS_MAX_REBUILD_INDEX_PARALLELISM];
}idx_paral_rebuild_ctx_t;

void btree_area_init(knl_session_t *session);
void btree_copy_root_page(knl_session_t *session, btree_t *btree, btree_page_t *root);
void btree_copy_root_page_base(knl_session_t *session, btree_t *btree, btree_page_t *root, knl_scn_t recycle_ver_scn);

void btree_release_root_copy(knl_session_t *session);

void btree_decode_key_column(knl_scan_key_t *scan_key, uint16 *bitmap, uint16 *offset, gs_type_t type, uint32 id,
    bool32 is_pcr);

uint16 btree_max_key_size(index_t *index);
uint16 btree_max_allowed_size(knl_session_t *session, knl_index_desc_t *index_desc);
bool32 btree_get_index_shadow(knl_session_t *session, knl_cursor_t *cursor, knl_handle_t shadow_handle);
status_t btree_segment_dump(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump);

void btree_drop_garbage_segment(knl_session_t *session, knl_seg_desc_t *seg);
void btree_drop_part_garbage_segment(knl_session_t *session, knl_seg_desc_t *seg);
void btree_truncate_garbage_segment(knl_session_t *session, knl_seg_desc_t *seg);
void btree_truncate_part_garbage_segment(knl_session_t *session, knl_seg_desc_t *seg);
bool32 bt_recycle_leaf_reusable(knl_session_t *session, knl_scn_t recycle_scn, knl_scn_t min_scn);
status_t btree_create_entry(knl_session_t *session, btree_t *btree);
status_t btree_create_part_entry(knl_session_t *session, btree_t *btree, index_part_t *index_part,
                                 knl_part_locate_t part_loc);
void btree_concat_extent(knl_session_t *session, btree_t *btree, page_id_t extent, uint32 extent_size, bool32 is_degrade);
void bt_all_pageid(knl_session_t *session, btree_t *btree, btree_alloc_assist_t *assist);
void bt_upd_ow_recycle_scn(knl_session_t *session, btree_t *btree, btree_alloc_assist_t *assist);
void bt_upd_recycle_ver_scn(knl_session_t *session, btree_t *btree);
void bt_all_page(knl_session_t *session, btree_t *btree, btree_alloc_assist_t *assist);
void btree_alloc_from_ufp(knl_session_t *session, btree_t *btree, page_id_t *page_id, bool32 *is_ext_first);
void btree_format_page(knl_session_t *session, btree_segment_t *segment, page_id_t page_id,
    uint32 level, uint8 extent_size, bool8 reserve_ext);
status_t btree_constructor_init(knl_session_t *session, btree_mt_context_t *ctx, btree_t *btree);
status_t btree_build_segment(knl_session_t *session, index_t *index);
status_t btree_create_segment(knl_session_t *session, index_t *index);
status_t btree_create_part_segment(knl_session_t *session, index_part_t *index_part);
void btree_truncate_segment(knl_session_t *session, knl_index_desc_t *desc, bool32 reuse_storage);
void btree_truncate_part_segment(knl_session_t *session, knl_index_part_desc_t *desc, bool32 reuse_storage);
void btree_drop_segment(knl_session_t *session, index_t *index);
void btree_drop_part_segment(knl_session_t *session, index_part_t *index_part);
void btree_purge_segment(knl_session_t *session, knl_seg_desc_t *desc);
status_t btree_purge_prepare(knl_session_t *session, knl_rb_desc_t *desc);

bool32 btree_need_extend(knl_session_t *session, btree_segment_t *segment);
status_t btree_generate_create_undo(knl_session_t *session, page_id_t entry, uint32 space_id, bool32 need_redo);
status_t btree_prepare_pages(knl_session_t *session, btree_t *btree);
void btree_undo_create(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot);
void btree_init_page(knl_session_t *session, btree_page_t *page, rd_btree_page_init_t *redo);
void btree_format_vm_page(knl_session_t *session, btree_segment_t *segment, btree_page_t *page, page_id_t page_id,
    uint32 level);
void btree_rd_set_scn(knl_session_t *session, rd_btree_info_t btree_info, rd_btree_set_recycle_t *recycle_info);
btree_t *btree_get_handle_by_undo(knl_session_t *session, knl_dictionary_t *dc, knl_part_locate_t part_loc,
    char *undo_row);
void btree_set_initrans(knl_session_t *session, btree_t *btree, uint32 initrans);
void bt_put_change_stats(btree_t *btree);

status_t idxpart_alloc_resource(knl_session_t *session, uint32 paral_no, idxpart_paral_ctx_t *paral_ctx);
void idxpart_release_resource(uint32 paral_no, idxpart_paral_ctx_t *paral_ctx);
status_t idx_fetch_alloc_resource(knl_session_t *session, idx_paral_sort_ctx_t *sort_ctx);
void idx_fetch_release_resource(idx_paral_sort_ctx_t *sort_ctx);
void idx_start_all_workers(idx_paral_sort_ctx_t *ctx, idx_sort_phase_t phase);
status_t idx_wait_all_workers(knl_session_t *session, idx_paral_sort_ctx_t *ctx);
status_t idx_wait_rebuild_workers(knl_session_t *session, idx_paral_rebuild_ctx_t *ctx);
status_t idx_build_alloc_resource(knl_session_t *session, idx_paral_sort_ctx_t *sort_ctx);
status_t idx_construct_alloc_resource(knl_session_t *session, idx_paral_sort_ctx_t *sort_ctx);
void idx_build_release_resource(idx_paral_sort_ctx_t *sort_ctx, bool32 is_free);
void idx_close_build_thread(idx_paral_sort_ctx_t *sort_ctx);
void idx_construct_release_resource(idx_paral_sort_ctx_t *sort_ctx);
status_t idx_switch_create_phase(knl_session_t *session, idx_paral_sort_ctx_t *paral_ctx,
    idx_sort_phase_t phase1, idx_sort_phase_t phase2);
void idx_start_build_workers(idx_paral_sort_ctx_t *ctx, idx_sort_phase_t phase);
status_t idx_wait_build_workers(knl_session_t *session, idx_paral_sort_ctx_t *ctx);

index_t *idx_get_index_by_shadow(knl_dictionary_t *dc);
bool32 idx_is_multi_segments(idx_paral_rebuild_ctx_t *ctx, knl_parts_locate_t parts_loc,
    rebuild_index_def_t *rebuild_def);
void idx_rebuild_index_proc(thread_t *thread);
status_t idx_start_rebuild_workers(knl_session_t *session,
    idx_paral_rebuild_ctx_t *ctx, knl_parts_locate_t parts_loc);
bool32 idx_start_rebuild_worker(knl_session_t *session, idx_paral_rebuild_ctx_t *ctx, uint32 split_cnt);
status_t idx_alloc_parallel_rebuild_rsc(knl_session_t *session, knl_dictionary_t *dc, uint32 paral_count,
    idx_paral_rebuild_ctx_t **ctx);
void idx_release_parallel_rebuild_rsc(knl_session_t *session, idx_paral_rebuild_ctx_t *ctx, uint32 workers);
void idx_init_construct_ctx(idx_paral_sort_ctx_t *paral_ctx, uint32 id1, uint32 id2,
    btree_mt_context_t *ctx);
#ifdef __cplusplus
}
#endif
#endif
