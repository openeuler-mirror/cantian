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
 * knl_map.h
 *
 *
 * IDENTIFICATION
 * src/kernel/table/knl_map.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_MAP_H__
#define __KNL_MAP_H__

#include "cm_defs.h"
#include "knl_common.h"
#include "knl_page.h"
#include "knl_interface.h"
#include "knl_log.h"
#include "knl_space_manage.h"
#include "knl_undo.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HEAP_MAX_MAP_LEVEL   3
#define HEAP_MAP_LEVEL1      0
#define HEAP_MAP_LEVEL2      1
#define HEAP_MAP_LEVEL3      2
#define HEAP_FREE_LIST_COUNT 6
#define HEAP_PAGE_FREE_SIZE_PARTS 15
#define HEAP_SEGMENT_MIN_PAGES 2
#define HEAP_PAGE_FORMAT_UNIT (uint32)128
#define HEAP_MAP_PAGE_RESERVED 16
#define MAP_LIST_EQUAL_DIVISON_NUM 4
#define MAX_SEG_PAGES (uint32)(1000 * 1014 * 1014)

// heap segment extents has been degrade alloced, so page_count has been recorded
#define HEAP_SEG_BITMAP_IS_DEGRADE(seg)     ((seg)->page_count > 0)

#pragma pack(4)
// node in map page
typedef struct st_heap_map_node {
    uint64 file : 10;
    uint64 page : 30;
    uint64 prev : 12;
    uint64 next : 12;
} map_node_t;

// free list at the head of map page
typedef struct st_heap_map_list {
    uint16 count;
    uint16 first;
} map_list_t;

typedef struct st_map_index {
    uint64 file : 10;  // map page
    uint64 page : 30;
    uint64 slot : 16;    // map slot
    uint64 list_id : 8;  // map list id
} map_index_t;

// map page head
typedef struct st_heap_map_page {
    page_head_t head;
    map_index_t map;
    map_list_t lists[HEAP_FREE_LIST_COUNT];
    uint16 hwm;
    uint16 aligned;
    uint8 reserved[HEAP_MAP_PAGE_RESERVED];  // reserved for extend
} map_page_t;

typedef struct st_heap_segment {
    knl_tree_info_t tree_info;
    knl_scn_t seg_scn;
    knl_scn_t org_scn;
    uint32 oid;
    uint16 uid;
    uint16 space_id;
    uint64 serial;
    // extents.count : 1, indicates the next pages that will be added;
    // extents.count > 1, indicates the first page of next extent that will be added
    page_list_t extents;
    page_list_t free_extents;
    page_id_t free_ufp;
    page_id_t data_first;
    page_id_t data_last;

    uint8 initrans;
    uint8 cr_mode;
    uint16 ufp_count;
    uint16 list_range[HEAP_FREE_LIST_COUNT];  // map list range
    uint32 map_count[HEAP_MAX_MAP_LEVEL];     // map page statistic
    page_id_t curr_map[HEAP_MAX_MAP_LEVEL];   // allocate map node from curr_mp
    page_id_t cmp_hwm;                        // reserved for shrink compact

    /**
     * ONLY for BITMAP:
     * this are new variables for record page_count of this table
     * used for bitmap scenario when try to allow THE SIZE is not available,
     * then try to degrade size (eg 8192 -> 1024 ->128 -> 8), will update this vaule
     * otherwise, always be 0 (also elder version is 0).
     * scenarios(same usage for btree segment):
     *  1 page_count is 0, extent size and page count of this table should be count as before
     *  2 page_count is not 0, page count size must read for extent head (page_head_t)ext_size,
     *    page count used this one.
     *
     *  page_count is also a FLAG of whether there is any degrade happened(not 0 means degrade happened).
     */
    uint32 page_count;          // page count for extents
    uint32 free_page_count;     // free_page_count for free_extents
    uint8 last_ext_size : 2;    // It is id, use after transform
    uint8 compress : 1;
    uint8 unused : 5;
    knl_scn_t shrinkable_scn;
} heap_segment_t;

typedef struct st_heap_map_path {
    map_index_t index[HEAP_MAX_MAP_LEVEL];
    uint32 level;
} map_path_t;

typedef struct st_rd_alloc_map_node {
    uint32 page;
    uint16 file;
    uint8 lid;
    uint8 aligned;
} rd_alloc_map_node_t;

typedef struct st_rd_change_map {
    uint16 slot;
    uint8 old_lid;
    uint8 new_lid;
} rd_change_map_t;

typedef struct st_heap_format_page {
    page_id_t page_id;
    uint32 extent_size;
} rd_heap_format_page_t;

typedef struct st_undo_heap_create {
    uint32 space_id;
    page_id_t entry;
} undo_heap_create_t;

#pragma pack()

status_t heap_find_free_page(knl_session_t *session, knl_handle_t heap_handle, knl_part_locate_t part_loc, uint8 mid,
                             bool32 use_cached, page_id_t *page_id, bool32 *degrade_mid);
status_t heap_find_appendonly_page(knl_session_t *session, knl_handle_t heap_handle, knl_part_locate_t part_loc,
                                   uint32 data_size, page_id_t *page_id);
void heap_remove_cached_page(knl_session_t *session, bool32 appendonly);
void heap_add_tx_free_page(knl_session_t *session, knl_handle_t heap_handle, page_id_t page_id, uint8 itl_id,
    xid_t xid, knl_scn_t seg_scn);
int32 heap_find_tx_free_page_index(knl_session_t *session, knl_handle_t heap_handle, uint8 *next, uint8 *count);
void heap_get_paral_schedule(knl_session_t *session, knl_handle_t heap_handle, knl_scn_t org_scn, uint32 workers,
                             knl_paral_range_t *range);
uint8 heap_get_owner_list(knl_session_t *session, heap_segment_t *segment, uint32 free_size);
uint32 heap_get_target_list(knl_session_t *session, heap_segment_t *segment, uint32 size);
void heap_try_change_map(knl_session_t *session, knl_handle_t heap_handle, page_id_t page_id);
void heap_degrade_change_map(knl_session_t *session, knl_handle_t heap_handle, page_id_t page_id, uint8 new_id);
void heap_set_pctfree(knl_session_t *session, heap_segment_t *segment, uint32 pctfree);

void heap_get_map_path(knl_session_t *session, knl_handle_t heap_handle, page_id_t page_id, map_path_t *path);
int32 heap_compare_map_path(map_path_t *left, map_path_t *right);
status_t heap_seq_find_map(knl_session_t *session, knl_handle_t heap_handle, map_path_t *path,
                           uint32 mid_input, page_id_t *page_id, bool32 *degrade_mid);

void heap_drop_garbage_segment(knl_session_t *session, knl_seg_desc_t *seg);
void heap_drop_part_garbage_segment(knl_session_t *session, knl_seg_desc_t *seg);
void heap_truncate_garbage_segment(knl_session_t *session, knl_seg_desc_t *seg);
void heap_truncate_part_garbage_segment(knl_session_t *session, knl_seg_desc_t *seg);
void heap_format_free_ufp(knl_session_t *session, heap_segment_t *segment);
void heap_change_map(knl_session_t *session, heap_segment_t *segment, map_index_t *map, uint8 new_id, uint32 level);
void heap_add_ufp(knl_session_t *session, heap_segment_t *segment,
    page_id_t page_id, uint32 count, bool32 need_noread);

static inline void heap_format_map(knl_session_t *session, map_page_t *page, page_id_t page_id, uint32 extent_size)
{
    page_init(session, (page_head_t *)page, page_id, PAGE_TYPE_HEAP_MAP);

    page->head.type = PAGE_TYPE_HEAP_MAP;
    TO_PAGID_DATA(INVALID_PAGID, page->head.next_ext);
    page->head.ext_size = spc_ext_id_by_size(extent_size);

    page->map.file = INVALID_FILE_ID;
    page->map.page = 0;
    page->map.slot = INVALID_SLOT;
    page->map.list_id = 0;
    page->hwm = 0;

    for (uint32 i = 0; i < HEAP_FREE_LIST_COUNT; i++) {
        page->lists[i].count = 0;
        page->lists[i].first = INVALID_SLOT;
    }
}

static inline void heap_reset_page_count(heap_segment_t *segment)
{
    segment->page_count = 0;
    segment->free_page_count = 0;
    segment->last_ext_size = 0;
}

static inline uint8 heap_find_last_list(map_page_t *page)
{
    uint8 i;

    for (i = HEAP_FREE_LIST_COUNT - 1; i > 0; i--) {
        if (page->lists[i].count > 0) {
            return i;
        }
    }

    return 0;
}

static inline map_node_t *heap_get_map_node(char *page, uint16 slot)
{
    char *base_ptr = ((char *)page) + sizeof(map_page_t);
    return (map_node_t *)(base_ptr + (uint32)slot * sizeof(map_node_t));
}

static inline void heap_insert_into_list(map_page_t *page, map_list_t *list, uint16 slot)
{
    map_node_t *node;
    map_node_t *first_node = NULL;

    node = heap_get_map_node((char *)page, slot);
    node->next = list->first;
    node->prev = INVALID_SLOT;

    if (list->count > 0) {
        first_node = heap_get_map_node((char *)page, list->first);
        first_node->prev = slot;
    }

    list->first = slot;
    list->count++;
}

static inline void heap_remove_from_list(map_page_t *page, map_list_t *list, uint16 slot)
{
    knl_panic(list->count > 0);

    map_node_t *node = heap_get_map_node((char *)page, slot);

    if (list->first == slot) {
        list->first = (uint16)node->next;
    }

    if (node->prev != INVALID_SLOT) {
        map_node_t *prev_node = heap_get_map_node((char *)page, (uint16)node->prev);
        prev_node->next = node->next;
    }

    if (node->next != INVALID_SLOT) {
        map_node_t *next_node = heap_get_map_node((char *)page, (uint16)node->next);
        next_node->prev = node->prev;
    }

    list->count--;
}

status_t map_dump_page(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump);
status_t map_segment_dump(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump);

static inline uint32 heap_get_segment_page_count(space_t *space, heap_segment_t *segment)
{
    if (segment->page_count == 0) {
        return spc_pages_by_ext_cnt(space, segment->extents.count, PAGE_TYPE_HEAP_HEAD);
    }
    return segment->page_count;
}

// contains extent and free extent
static inline uint32 heap_get_all_page_count(space_t *space, heap_segment_t *segment)
{
    uint32 total_count = segment->page_count + segment->free_page_count;
    if (total_count == 0) {
        return spc_pages_by_ext_cnt(space, segment->extents.count + segment->free_extents.count, PAGE_TYPE_HEAP_HEAD);
    }
    // total_count can not be 0 when free_page_count is not 0
    knl_panic(segment->page_count != 0);
    return total_count;
}

status_t heap_generate_create_undo(knl_session_t *session, page_id_t entry, uint32 space_id, bool32 need_redo);
void heap_undo_create_part(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot);

#ifdef __cplusplus
}
#endif

#endif
