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
 * knl_lob.h
 *
 *
 * IDENTIFICATION
 * src/kernel/lob/knl_lob.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_LOB_H
#define __KNL_LOB_H

#include "cm_defs.h"
#include "knl_session.h"
#include "knl_heap.h"
#include "knl_interface.h"
#include "rb_purge.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LOB_MAX_INLIINE_SIZE (GS_LOB_LOCATOR_BUF_SIZE - OFFSET_OF(lob_locator_t, data))
#define COLUMN_IS_LOB(c) \
    (((c)->datatype == GS_TYPE_CLOB) || ((c)->datatype == GS_TYPE_BLOB) || \
    ((c)->datatype == GS_TYPE_IMAGE) || KNL_COLUMN_IS_ARRAY(c))

#define LOB_SEG_HEAD(session)         (lob_segment_t *)((session)->curr_page + PAGE_HEAD_SIZE)

#define MAX_LOB_ITEMS_PAGES                 1024
#define LOB_ITEM_PAGE_CAPACITY              (GS_SHARED_PAGE_SIZE / sizeof(lob_item_t))
#define MAX_LOB_ITEMS                       (MAX_LOB_ITEMS_PAGES * LOB_ITEM_PAGE_CAPACITY)
#define KNL_LOB_LOCATOR_SIZE                sizeof(lob_locator_t)
#define LOB_CHECK_ORG_SCN(locator, data) \
    ((data)->head.type == PAGE_TYPE_LOB_DATA && (data)->chunk.org_scn == (locator)->org_scn)
#define LOB_CHECK_XID(locator, chunk)       ((locator)->xid.value == (chunk)->ins_xid.value)
#define LOB_IS_INLINE(locator)              (!(locator)->head.is_outline)
#define LOB_INLINE_DATA(locator)            (char *)((locator)->data)
#define KNL_LOB_LOCATOR_OFFSERT(cursor, id) ((cursor)->offsets[id] - sizeof(uint16))
#define KNL_LOB_INLINE_SIZE(lob_len)        CM_ALIGN4(sizeof(uint16) + sizeof(lob_head_t) + (lob_len))
#define KNL_LOB_OUTLINE_SIZE                CM_ALIGN4(sizeof(uint16) + sizeof(lob_locator_t))
#define DEFAULT_LOB_CHUNK_SIZE              4096
#define LOB_MAX_CHUNK_SIZE(session)     (DEFAULT_PAGE_SIZE(session) - sizeof(lob_data_page_t) - sizeof(page_tail_t))
#define LOB_GET_LOCATOR(locator)        (lob_locator_t *)(locator)
#define LOB_GET_CHUNK_COUNT(session, locator)    \
    (((locator)->head.size + LOB_MAX_CHUNK_SIZE(session) - 1) / LOB_MAX_CHUNK_SIZE(session))
#define LOB_CURR_DATA_PAGE(session)              (lob_data_page_t *)CURR_PAGE(session)
#define LOB_NEXT_DATA_PAGE(session)              ((LOB_CURR_DATA_PAGE(session))->chunk.next)
#define LOB_GET_CHUNK(session)                   (&(LOB_CURR_DATA_PAGE(session))->chunk)
#define LOB_PCT_RATIO(lob_free_pages, lob_page_count) (((double)(lob_free_pages) / (double)(lob_page_count)) * 100)
#define LOB_MIN_SHRINK_EXTENTS          3
#define LOB_SEGMENT(session, pageid, segment) \
    ((buf_check_resident_page_version((session), (pageid))) ? \
        ((lob_segment_t *)(segment)) : ((lob_segment_t *)(segment)))

#pragma pack(4)
typedef struct st_lob_head {
    /* size + type must be defined first!!! */
    uint32 size;
    uint32 type;
    uint32 is_outline : 1;
    uint32 node_id : 9;
    uint32 unused : 22;
} lob_head_t;

typedef struct st_lob_locator {
    lob_head_t head;
    union {
        struct {
            xid_t xid;
            knl_scn_t org_scn;
            page_id_t first;
            page_id_t last;
        };

        uint8 data[0];
    };
} lob_locator_t;

typedef struct st_lob_chunk {
    xid_t ins_xid;  // xid of session when insert lob data
    xid_t del_xid;  // xid of session when delete lob data
    knl_scn_t org_scn;
    uint32 size;
    page_id_t next;
    page_id_t free_next;
    bool32 is_recycled;
    char data[4];
} lob_chunk_t;

typedef struct st_lob_data_page {
    page_head_t head;
    page_id_t pre_free_page;  // pre free page of segment's free_list
    uint8 reserved[8];  // reserved for future use
    lob_chunk_t chunk;
} lob_data_page_t;

typedef struct st_lob_undo {
    uint32 part_no;
    lob_locator_t locator;
} lob_undo_t;

typedef struct st_lob_del_undo {
    page_id_t prev_page;
    page_id_t first_page;
    page_id_t last_page;
    uint32 chunk_count;
} lob_del_undo_t;

typedef struct st_lob_seg_undo {
    uint32 part_no;
    page_list_t free_list;
    page_id_t entry;
} lob_seg_undo_t;

typedef struct st_lob_seg_recycle_undo {
    uint32 part_no;
    page_list_t free_list;
    page_id_t pre_free_last;
    page_id_t entry;
} lob_seg_recycle_undo_t;

typedef struct st_lob_segment {
    knl_scn_t org_scn;
    knl_scn_t seg_scn;
    uint32 table_id;
    uint16 uid;
    uint16 space_id;
    uint16 column_id;
    uint16 aligned;

    page_list_t extents;
    page_list_t free_list; /* << lob recycle page */
    uint32 ufp_count;      /* free pages left on current free extent */
    page_id_t ufp_first;   /* first free page */
    page_id_t ufp_extent;  /* first unused extent */
    knl_scn_t shrink_scn; /* lob shrink timestamp scn */
} lob_segment_t;

typedef struct st_lob_undo_alloc_page {
    page_id_t first_page;
    knl_scn_t ori_scn;
} lob_undo_alloc_page_t;
#pragma pack()

typedef struct st_lob_shrink_assist {
    knl_scn_t min_scn;
    page_id_t last_extent;
    page_id_t last_free_pagid;
    page_id_t new_extent;
    uint32    free_count;
    page_list_t extents;
} lob_shrink_assist_t;

typedef struct st_undo_lob_create {
    uint32 space_id;
    page_id_t entry;
} undo_lob_create_t;

typedef struct st_knl_lob_desc {
    uint32 uid;
    uint32 table_id;
    uint32 column_id;
    uint32 space_id;
    page_id_t entry;
    knl_scn_t org_scn;
    knl_scn_t chg_scn;
    knl_scn_t seg_scn;
    uint32 chunk;
    uint32 retention;
    uint32 pctversion;
    union {
        uint32 flags;
        struct {
            uint32 is_stored : 1;
            uint32 is_compressed : 1;
            uint32 is_encrypted : 1;
            uint32 is_inrow : 1;
            uint32 unused : 28;
        };
    };
} knl_lob_desc_t;

typedef struct st_lob {
    knl_lob_desc_t desc;
    lob_entity_t lob_entity;  // lob storage entity
    struct st_part_lob *part_lob;
} lob_t;

#define LOB_GET_PART(lob, part_no) PART_GET_ENTITY(((lob_t *)(lob))->part_lob, part_no)

typedef struct st_lob_pages_info {
    uint32 uid;
    uint32 table_id;
    uint32 col_id;
    knl_part_locate_t part_loc;
    page_id_t entry;
    page_list_t del_pages;
} lob_pages_info_t;

typedef struct st_lob_item {
    spinlock_t lock;
    uint32 item_id;
    uint32 next;
    lob_pages_info_t pages_info;
    struct st_lob_item *next_item;
} lob_item_t;

typedef struct st_lob_area {
    spinlock_t lock;
    memory_pool_t pool;
    uint32 page_count;
    char *pages[MAX_LOB_ITEMS_PAGES];
    id_list_t free_items;
    uint32 hwm;
    uint32 capacity;
} lob_area_t;

typedef struct st_lob_alloc_assist {
    page_id_t *lob_page_id;
    knl_scn_t org_scn;
    bool32 generate_undo; // it is true, just alloc first page for locator
} lob_alloc_assist_t;

void lob_init_page(knl_session_t *session, page_id_t page_id, page_type_t type, bool32 init_head);
void lob_area_init(knl_session_t *session);
void lob_items_reset(knl_rm_t *rm);
void lob_items_free(knl_session_t *session);
void lob_reset_svpt(knl_session_t *session, knl_savepoint_t *savepoint);

status_t lob_create_segment(knl_session_t *session, lob_t *lob);
status_t lob_create_part_segment(knl_session_t *session, lob_part_t *lob_part);
void lob_drop_segment(knl_session_t *session, lob_t *lob);
void lob_drop_part_segment(knl_session_t *session, lob_part_t *lob_part);
void lob_truncate_segment(knl_session_t *session, knl_lob_desc_t *desc, bool32 reuse_storage);
void lob_truncate_part_segment(knl_session_t *session, knl_lob_part_desc_t *desc, bool32 reuse_storage);
status_t lob_purge_prepare(knl_session_t *session, knl_rb_desc_t *desc);
void lob_purge_segment(knl_session_t *session, knl_seg_desc_t *desc);

status_t lob_delete(knl_session_t *session, knl_cursor_t *cursor);
status_t lob_update(knl_session_t *session, knl_cursor_t *cursor, heap_update_assist_t *ua);
status_t lob_set_column_default(knl_session_t *session, knl_cursor_t *cursor, lob_locator_t *locator, void *data,
                                knl_column_t *column, void *stmt);

status_t knl_copy_lob(knl_session_t *session, knl_cursor_t *dst_cursor, lob_locator_t *dst_locator,
                      lob_locator_t *src_locator, knl_column_t *column);

void lob_free_delete_pages(knl_session_t *session);
void lob_undo_insert(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot,
                     knl_dictionary_t *dc);
void lob_undo_delete_commit_recycle(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot);
void lob_undo_delete(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot);
void lob_undo_delete_commit(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot);
void lob_undo_write_page(knl_session_t *session, undo_row_t *ud_row);

status_t lob_write_2pc_buff(knl_session_t *session, binary_t *buf, uint32 max_size);
status_t lob_create_2pc_items(knl_session_t *session, uint8 *buf, uint32 buf_size, lob_item_list_t *item_list);
status_t lob_recycle_pages(knl_session_t *session, knl_cursor_t *cursor, lob_t *lob, lob_locator_t *locator);
void lob_drop_garbage_segment(knl_session_t *session, knl_seg_desc_t *seg);
void lob_drop_part_garbage_segment(knl_session_t *session, knl_seg_desc_t *seg);
void lob_truncate_garbage_segment(knl_session_t *session, knl_seg_desc_t *seg);
void lob_truncate_part_garbage_segment(knl_session_t *session, knl_seg_desc_t *seg);
status_t lob_reorganize_columns(knl_session_t *session, knl_cursor_t *cursor, heap_update_assist_t *ua,
                                knl_update_info_t *lob_info, bool32 *changed);
status_t lob_shrink_space(knl_session_t *session, knl_cursor_t *cursor, knl_column_t *column);
#ifdef LOG_DIAG
void lob_validate_page(knl_session_t *session, page_head_t *page);
#endif
static inline lob_item_t *lob_item_addr(lob_area_t *area, uint32 id)
{
    uint32 page_id = id / LOB_ITEM_PAGE_CAPACITY;
    uint32 item_id = id % LOB_ITEM_PAGE_CAPACITY;
    return (lob_item_t *)(area->pages[page_id] + item_id * sizeof(lob_item_t));
}

static inline uint32 knl_lob_locator_size(knl_handle_t locator)
{
    lob_locator_t *lob = (lob_locator_t *)locator;

    if (lob->head.is_outline) {
        return sizeof(lob_locator_t);
    }

    return (uint32)(lob->head.size + OFFSET_OF(lob_locator_t, data));
}

static inline uint32 knl_lob_inline_size(bool32 is_csf, uint32 lob_len, bool32 with_colsize)
{
    uint32 row_len;
    if (is_csf) {
        row_len = sizeof(lob_head_t) + (lob_len);
        return with_colsize ? ((row_len < CSF_VARLEN_EX) ?
            (row_len + CSF_SHORT_COL_DESC_LEN) : (row_len + CSF_LONG_COL_DESC_LEN)) : (row_len);
    } else {
        return with_colsize ? KNL_LOB_INLINE_SIZE(lob_len) : (KNL_LOB_INLINE_SIZE(lob_len) - sizeof(uint16));
    }
}

static inline uint32 knl_lob_outline_size(bool32 is_csf)
{
    return is_csf ? (sizeof(lob_locator_t) + CSF_SHORT_COL_DESC_LEN) : KNL_LOB_OUTLINE_SIZE;
}

static inline lob_locator_t *knl_lob_col_new_start(bool32 is_csf, lob_locator_t *locator, uint32 lob_len)
{
    char  *new_addr = (char *)locator;
    
    if (is_csf && !(locator->head.is_outline)) {
        if ((sizeof(lob_head_t) + lob_len) >= CSF_VARLEN_EX) {
            new_addr -= (CSF_LONG_COL_DESC_LEN - CSF_SHORT_COL_DESC_LEN);
        }
        return (lob_locator_t *)new_addr;
    } else {
        return locator;
    }
}

static inline void lob_init_assist(lob_alloc_assist_t *lob_assist, page_id_t *page_id,
    knl_scn_t org_scn, bool32 generate_undo)
{
    lob_assist->lob_page_id = page_id;
    lob_assist->org_scn = org_scn;
    lob_assist->generate_undo = generate_undo;
}

status_t lob_dump_page(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump);
status_t lob_segment_dump(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump);
status_t lob_get_table_by_page(knl_session_t *session, page_head_t *page, uint32 *uid, uint32 *table_id);
status_t lob_corruption_scan(knl_session_t *session, lob_segment_t *segment, knl_corrupt_info_t *corrupt_info);
status_t lob_check_space(knl_session_t *session, table_t *table, uint32 space_id);
void lob_clean_all_default_segments(knl_session_t *session, knl_handle_t entity, uint32 old_col_count);

status_t lob_generate_create_undo(knl_session_t *session, page_id_t entry, uint32 space_id, bool32 need_redo);
void lob_undo_create_part(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot);

#ifdef __cplusplus
}
#endif

#endif
