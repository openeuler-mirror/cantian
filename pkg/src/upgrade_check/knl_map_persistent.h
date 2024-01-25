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
 * knl_map_persistent.h
 *
 *
 * IDENTIFICATION
 * src/upgrade_check/knl_map_persistent.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_MAP_PERSISTENT_H__
#define __KNL_MAP_PERSISTENT_H__
 
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
#ifdef __cplusplus
}
#endif
 
#endif