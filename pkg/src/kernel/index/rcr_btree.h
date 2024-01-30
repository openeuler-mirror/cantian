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
 * rcr_btree.h
 *
 *
 * IDENTIFICATION
 * src/kernel/index/rcr_btree.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __RCR_BTREE_H__
#define __RCR_BTREE_H__

#include "knl_index_module.h"
#include "cm_defs.h"
#include "knl_common.h"
#include "knl_interface.h"
#include "knl_session.h"
#include "knl_page.h"
#include "knl_lock.h"
#include "knl_index.h"
#include "knl_undo.h"
#include "rb_purge.h"
#include "knl_dc.h"
#include "knl_buffer.h"
#include "rcr_btree_protect.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BTREE_CURR_PAGE(session) ((btree_page_t *)((session)->curr_page))
#define BTREE_GET_SEGMENT(session) ((btree_segment_t *)(CURR_PAGE((session)) + CM_ALIGN8(sizeof(btree_page_t))))
#define BTREE_NEED_COMPACT(page, cost_size) \
    ((page)->free_size >= (cost_size) && (page)->free_begin + (cost_size) > (page)->free_end)
#define BTREE_NEXT_DEL_PAGE(session, cipher_size) \
    (page_id_t *)((char *)CURR_PAGE((session)) + sizeof(btree_page_t) + (cipher_size))
#define BTREE_NEXT_RECYCLE_SCN(session, cipher) \
    (knl_scn_t *)((char *)(BTREE_NEXT_DEL_PAGE((session), cipher)) + sizeof(page_id_t))
#define BTREE_PCT_SIZE(btree) (uint16)(DEFAULT_PAGE_SIZE(session) / 100 * ((btree)->segment->pctfree))

#define BTREE_ITL_ADDR(page) \
    ((itl_t *)((char *)(page) + PAGE_SIZE((page)->head) - sizeof(itl_t) * (page)->itls - sizeof(page_tail_t)))
#define BTREE_GET_ITL(page, id) (BTREE_ITL_ADDR(page) + (page)->itls - ((id) + 1))
#define BTREE_GET_KEY(page, dir) ((btree_key_t *)((char *)(page) + ((dir)->offset)))
#define BTREE_GET_DIR(page, pos) ((btree_dir_t *)((char *)(BTREE_ITL_ADDR(page)) - ((pos) + 1) * sizeof(btree_dir_t)))
#define BTREE_COST_SIZE(key) (((uint16)(key)->size) + sizeof(btree_dir_t))

// used for insert key, may cost an extra itl size
#define BTREE_MAX_COST_SIZE(key) (BTREE_COST_SIZE(key) + sizeof(itl_t))

#define BTREE_COPY_ROWID(src_key, dst_cur) ROWID_COPY((dst_cur)->rowid, (src_key)->rowid)

#define BTREE_COMPARE_SLOT_GAP 8
#define BTREE_ROOT_COPY_VALID(root_copy) (((root_copy) != NULL) && (!((index_page_item_t *)(root_copy))->is_invalid))
#define BTREE_GET_ROOT_COPY(root_copy) (((index_page_item_t *)(root_copy))->page)

#define BTREE_KEY_IS_NULL(key) ((key)->bitmap == 0)
#define BTREE_ROOT_COPY_SIZE(session) \
    ((uint32)(OFFSET_OF(index_page_item_t, page) + (session)->kernel->attr.page_size))
#define BTREE_GET_ITEM(session, area, id) \
    (index_page_item_t *)((char *)(area)->items + (id) * BTREE_ROOT_COPY_SIZE(session))

#define BTREE_RESERVE_SIZE 500

#define BTREE_PAGE_BODY(page) ((char *)(page) + sizeof(page_head_t))
#define BTREE_PAGE_BODY_SIZE(page) (PAGE_SIZE((page)->head) - sizeof(page_head_t) - sizeof(page_tail_t))
#define BTREE_MIN_SKIP_COLUMNS 1
#define BTREE_SPLIT_PAGE_SIZE (PAGE_UNIT_SIZE * 2)
#define BTREE_PAGE_FREE_SIZE(page) (((page)->free_end) - ((page)->free_begin))

#define BTREE_SEGMENT(session, pageid, segment)                                                     \
    ((buf_check_resident_page_version((session), (pageid))) ? ((btree_segment_t *)(segment)) \
                                                          : ((btree_segment_t *)(segment)))

#define BTREE_SEGMENT_WITH_CTRL(session, ctrl, pageid, segment)                                                     \
    ((buf_check_resident_page_version_with_ctrl((session), (ctrl), (pageid))) ? ((btree_segment_t *)(segment)) \
                                                          : ((btree_segment_t *)(segment)))

typedef struct st_btree_key_data {
    btree_key_t *key;
    char *data[CT_MAX_INDEX_COLUMNS];
    uint16 size[CT_MAX_INDEX_COLUMNS];
} btree_key_data_t;

typedef struct st_btree_search {
    btree_t *btree;
    knl_scn_t seg_scn;
    knl_tree_info_t tree_info;
    knl_scn_t query_scn;
    uint32 ssn;
    bool8 is_dsc_scan;
    bool8 is_equal;
    bool8 is_full_scan;
    bool8 read_root_copy;
    bool8 use_cr_pool;
    uint8 isolevel;
    knl_scn_t parent_snap_scn;
    knl_scn_t child_snap_scn;
} btree_search_t;

typedef enum en_btree_alloc_type {
    BTREE_ALLOC_NEW_PAGE = 0,
    BTREE_ALLOC_NEW_EXTENT,
    BTREE_REUSE_STORAGE,
    BTREE_RECYCLE_DELETED,
    BTREE_ALLOC_RECYCLED,
} btree_alloc_type_t;

typedef struct st_btree_alloc_assist {
    btree_alloc_type_t type;
    page_id_t new_pageid;
    page_id_t next_pageid;
    knl_scn_t next_recycle_scn;
    knl_scn_t ow_recycle_scn;
} btree_alloc_assist_t;

typedef struct st_idx_recycle_info {
    uint64 garbage_size;
    uint64 garbage_ratio;
    uint64 empty_ratio;
    uint64 segment_size;
    uint64 recycled_size;
    knl_scn_t segment_scn;
    knl_scn_t first_recycle_scn;
    knl_scn_t last_recycle_scn;
    uint16 btree_level;
    bool8 recycled_reusable;
} idx_recycle_info_t;

typedef struct st_btree_recycle_desc {
    knl_scn_t max_del_scn;
    uint64 snapshot_lsn;
    page_id_t leaf_id;
    bool8 force_recycle;
    bool8 is_empty;
    bool8 is_first_child;
    bool8 is_sparse;
    bool8 is_recycled;
    bool8 active_txn;
    bool8 unexpire;
    xid_t xid;
} btree_recycle_desc_t;

#define CURR_KEY_PTR(key) ((char *)(key) + (key)->size)

status_t btree_insert(knl_session_t *session, knl_cursor_t *cursor);
status_t btree_insert_into_shadow(knl_session_t *session, knl_cursor_t *cursor);
status_t btree_delete(knl_session_t *session, knl_cursor_t *cursor);
void btree_decode_key(index_t *index, btree_key_t *key, knl_scan_key_t *scan_key);

void btree_get_end_slot(knl_session_t *session, knl_cursor_t *cursor);
void btree_convert_row(knl_session_t *session, knl_index_desc_t *desc, char *key_buf, row_head_t *row, uint16 *bitmap);
void btree_construct_ancestors_finish(knl_session_t *session, btree_t *btree, btree_page_t **parent_page,
    bool32 nologging);
void btree_append_to_page(knl_session_t *session, btree_page_t *page, btree_key_t *key, uint8 itl_id);
void btree_init_key(btree_key_t *key, rowid_t *rid);
void btree_put_key_data(char *key_buf, ct_type_t type, const char *data, uint16 len, uint16 id);
void btree_clean_lock(knl_session_t *session, lock_item_t *lock);
status_t btree_construct(btree_mt_context_t *ctx);
status_t bt_chk_exist_pre(knl_session_t *session, btree_t *btree, btree_search_t *search_info);
status_t btree_check_key_exist(knl_session_t *session, btree_t *btree, char *data, bool32 *exists);
status_t btree_dump_page(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump);
status_t btree_coalesce(knl_session_t *session, btree_t *btree, idx_recycle_stats_t *stats,
    knl_part_locate_t part_loc, bool32 is_auto);
void btree_concat_next_to_prev(knl_session_t *session, page_id_t next_page_id, page_id_t prev_page_id);
status_t btree_fetch_depended(knl_session_t *session, knl_cursor_t *cursor);
bool32 bt_recycle_page(knl_session_t *session, btree_t *btree, btree_recycle_desc_t *recycle_desc,
    knl_part_locate_t part_locate);
void btree_concat_del_pages(knl_session_t *session, btree_t *btree, btree_recycle_desc_t *desc);
void btree_get_parl_schedule(knl_session_t *session, index_t *index, knl_idx_paral_info_t paral_info,
                             idx_range_info_t org_info, uint32 root_level, knl_index_paral_range_t *sub_range);
page_id_t btree_clean_copied_itl(knl_session_t *session, uint64 itl_xid, page_id_t p_page_id, bool32 need_redo);
void btree_try_notify_recycle(knl_session_t *session, btree_t *btree, knl_part_locate_t part_loc);
knl_scn_t btree_get_recycle_min_scn(knl_session_t *session);
bool32 bt_recycle_time_expire(knl_session_t *session, knl_scn_t interval_scn, knl_scn_t min_scn,
    knl_scn_t commit_scn);
status_t btree_compare_mtrl_key(mtrl_segment_t *segment, char *data1, char *data2, int32 *result);
char *btree_get_column(knl_scan_key_t *key, ct_type_t type, uint32 id, uint16 *len, bool32 is_pcr);
uint16 btree_max_column_size(ct_type_t type, uint16 size, bool32 is_pcr);
bool32 btree_need_recycle(knl_session_t *session, btree_t *btree, idx_recycle_info_t *recycle_info);

#ifdef LOG_DIAG
    void btree_validate_page(knl_session_t *session, page_head_t *page);
#endif
static inline void btree_put_part_id(char *key_buf, uint32 part_id)
{
    *(uint32 *)(key_buf + ((btree_key_t *)key_buf)->size) = part_id;
    ((btree_key_t *)key_buf)->size += sizeof(uint32);
}

static inline uint32 btree_get_subpart_id(btree_key_t *key)
{
    return *(uint32 *)((char *)key + key->size - sizeof(uint32) - sizeof(uint32));
}

static inline uint32 btree_get_part_id(btree_key_t *key)
{
    return *(uint32 *)((char *)key + key->size - sizeof(uint32));
}

static inline uint16 btree_get_key_size(char *key)
{
    return (uint16)((btree_key_t *)key)->size;
}

static inline void btree_set_bitmap(uint16 *bitmap, uint16 idx)
{
    (*bitmap) |= (0x8000 >> idx);
}

static inline bool32 btree_get_bitmap(uint16 *bitmap, uint16 id)
{
    return ((*bitmap) & (0x8000 >> id));
}

static inline void btree_set_key_rowid(btree_key_t *key, rowid_t *rid)
{
    ROWID_COPY(key->rowid, *rid);
}

// set err_code outside
static inline status_t btree_check_segment_scn(btree_page_t *page, page_type_t type, knl_scn_t seg_scn)
{
    if (page->head.type != type || page->seg_scn != seg_scn) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static inline status_t btree_check_min_scn(knl_scn_t query_scn, knl_scn_t min_scn, uint16 level)
{
    if (level == 0 && query_scn < min_scn) {
        CT_LOG_RUN_ERR("snapshot too old, detail: query_scn %llu, btree_min_scn %llu", query_scn, min_scn);
        CT_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static inline btree_t *knl_cursor_btree(knl_cursor_t *cursor)
{
    if (IS_PART_INDEX(cursor->index)) {
        return &((index_part_t *)cursor->index_part)->btree;
    } else {
        return &((index_t *)cursor->index)->btree;
    }
}

#define CURSOR_BTREE(cursor) knl_cursor_btree(cursor)

static inline btree_segment_t *btree_get_segment(knl_session_t *session, index_t *index, uint32 part_no)
{
    btree_segment_t *segment = NULL;

    if (IS_PART_INDEX(index)) {
        index_part_t *index_part = INDEX_GET_PART(index, part_no);
        segment = BTREE_SEGMENT(session, index_part->btree.entry, index_part->btree.segment);
    } else {
        segment = BTREE_SEGMENT(session, index->btree.entry, index->btree.segment);
    }

    return segment;
}

static inline uint32 btree_get_extents_count(knl_session_t *session, index_t *index, uint32 part_no)
{
    btree_segment_t *segment = btree_get_segment(session, index, part_no);

    return segment->extents.count;
}

void btree_get_txn_info(knl_session_t *session, bool32 is_scan, btree_page_t *page, btree_dir_t *dir,
    btree_key_t *key, txn_info_t *txn_info);
void btree_cache_reset(knl_session_t *session);
void btree_undo_insert(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot,
                       knl_dictionary_t *dc);
void btree_undo_delete(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot,
                       knl_dictionary_t *dc);
bool32 bt_chk_leaf_recycled(knl_session_t *session, btree_t *btree, btree_page_t *btree_page,
    knl_scn_t snap_scn);
status_t bt_chk_keys_recycled(knl_session_t *session, btree_t *btree, btree_page_t *btree_page,
    uint8 isolevel, knl_scn_t query_scn);
void btree_compact_page(knl_session_t *session, btree_page_t *page, knl_scn_t min_scn);
void btree_insert_into_page(knl_session_t *session, btree_page_t *page, btree_key_t *key, rd_btree_insert_t *redo);
void btree_reuse_itl(knl_session_t *session, btree_page_t *page, itl_t *itl, uint8 itl_id, knl_scn_t min_scn);
uint8 btree_copy_itl(knl_session_t *session, itl_t *src_itl, btree_page_t *dst_page);
void btree_set_match_cond(knl_cursor_t *cursor);
void btree_init_match_cond(knl_cursor_t *cursor, bool32 is_pcr);
void btree_flush_garbage_size(knl_session_t *session, dc_entity_t *entity);
status_t btree_open_mtrl_cursor(btree_mt_context_t *ctx, mtrl_sort_cursor_t *cur1,
    mtrl_sort_cursor_t *cur2, mtrl_cursor_t *cursor);
status_t btree_fetch_mtrl_sort_key(btree_mt_context_t *ctx, mtrl_sort_cursor_t *cur1,
    mtrl_sort_cursor_t *cur2, mtrl_cursor_t *cursor);
void btree_close_mtrl_cursor(btree_mt_context_t *ctx, mtrl_sort_cursor_t *cur1,
    mtrl_sort_cursor_t *cur2, mtrl_cursor_t *cursor);
uint16 bt_alloc_page_size(knl_session_t *session, btree_t *btree);
static inline void btree_clean_key(knl_session_t *session, btree_page_t *page, uint16 slot)
{
    btree_dir_t *dir = BTREE_GET_DIR(page, slot);
    btree_key_t *key = BTREE_GET_KEY(page, dir);

    for (uint16 j = slot; j < page->keys - 1; j++) {
        *BTREE_GET_DIR(page, j) = *BTREE_GET_DIR(page, j + 1);
    }

    page->free_size += ((uint16)key->size + sizeof(btree_dir_t));
    key->is_cleaned = (uint16)CT_TRUE;
    page->keys--;
}

static inline void btree_delete_key(knl_session_t *session, btree_page_t *page, rd_btree_delete_t *redo)
{
    btree_dir_t *dir = BTREE_GET_DIR(page, redo->slot);
    btree_key_t *key = BTREE_GET_KEY(page, dir);

    key->is_deleted = CT_TRUE;
    dir->itl_id = redo->itl_id;
    key->scn = redo->ssn;
    key->undo_page = redo->undo_page;
    key->undo_slot = redo->undo_slot;
    key->is_owscn = CT_FALSE;
}

static inline uint8 btree_new_itl(knl_session_t *session, btree_page_t *page)
{
    char *src = (char *)page + page->free_end;
    char *dst = src - sizeof(itl_t);

    errno_t err = memmove_s(dst, PAGE_SIZE(page->head) - page->free_end + sizeof(itl_t), src,
                            page->keys * sizeof(btree_dir_t));
    knl_securec_check(err);

    uint8 itl_id = page->itls;
    page->itls++;
    page->free_end -= sizeof(itl_t);
    page->free_size -= sizeof(itl_t);

    return itl_id;
}

static inline uint32 btree_get_segment_page_count(space_t *space, btree_segment_t *segment)
{
    if (segment->page_count == 0) {
        return spc_pages_by_ext_cnt(space, segment->extents.count, PAGE_TYPE_BTREE_HEAD);
    }
    return segment->page_count;
}

static inline void btree_try_update_segment_pagecount(btree_segment_t *segment, uint32 ext_size)
{
    if (segment->page_count == 0) {
        return;
    }
    segment->page_count += ext_size;
}

static inline void btree_try_init_segment_pagecount(space_t *space, btree_segment_t *segment)
{
    if (segment->page_count == 0) {
        // print log when first degrade happened
        CT_LOG_RUN_INF("btree segment degraded alloc extent, space id: %u, uid: %u, table id: %u, index id: %u.",
            (uint32)segment->space_id, (uint32)segment->uid, segment->table_id, (uint32)segment->index_id);
        segment->page_count = spc_pages_by_ext_cnt(space, segment->extents.count, PAGE_TYPE_BTREE_HEAD);
    }
}

static inline void btree_init_find_assist(btree_t *btree, btree_path_info_t *path_info, knl_scan_key_t *scan_key,
    btree_find_type find_type, btree_find_assist_t *find_assist)
{
    find_assist->btree = btree;
    find_assist->find_type = find_type;
    find_assist->page_damage = CT_FALSE;
    find_assist->page_id = INVALID_PAGID;
    find_assist->path_info = path_info;
    find_assist->scan_key = scan_key;
}
#ifdef __cplusplus
}
#endif

#endif
