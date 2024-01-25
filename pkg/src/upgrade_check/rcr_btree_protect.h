
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
 * rb_purge_persistent.h
 *
 *
 * IDENTIFICATION
 * src/upgrade_check/rb_purge_persistent.h
 *
 * -------------------------------------------------------------------------
 * Description: add upgrade check
 * Create: 2023-01-06
*/
#ifndef RCR_BTREE_PROTECT_H
#define RCR_BTREE_PROTECT_H

#ifdef __cplusplus
extern "C" {
#endif
typedef enum st_btree_find_type {
    BTREE_FIND_INSERT = 0,
    BTREE_FIND_DELETE,
    BTREE_FIND_INSERT_LOCKED,
    BTREE_FIND_DELETE_NEXT,
} btree_find_type;

#pragma pack(4)
typedef struct st_btree_page {
    page_head_t head;
    knl_scn_t seg_scn;  // it is also org_scn on temp btree

    uint16 is_recycled : 1;
    uint16 unused : 15;
    uint16 keys;

    pagid_data_t prev;
    uint8 level;
    uint8 itls;

    pagid_data_t next;
    uint16 free_begin;

    uint16 free_end;
    uint16 free_size;
    knl_scn_t scn;      // max committed itl scn(except delayed itl)
    uint8 reserved[8];  // reserved for future use
} btree_page_t;

typedef struct st_btree_dir_t {
    uint16 offset;
    uint8 itl_id;
    uint8 unused;
} btree_dir_t;

typedef struct st_btree_key {
    union {
        knl_scn_t scn;  // sql sequence number(txn in progress) or commit scn
        page_id_t child;
    };

    union {
        rowid_t rowid;  // leaf node: rowid;
        struct {
            uint64 align_rowid : ROWID_VALUE_BITS;
            uint64 size : ROWID_UNUSED_BITS;
        };
    };

    undo_page_id_t undo_page;
    uint16 undo_slot : 12;
    uint16 is_deleted : 1;
    uint16 is_infinite : 1;
    uint16 is_owscn : 1;
    uint16 is_cleaned : 1;
    uint16 bitmap;
} btree_key_t;

typedef struct st_btree_segment {
    knl_tree_info_t tree_info;
    knl_scn_t org_scn;
    knl_scn_t seg_scn;
    uint32 table_id;
    uint16 uid;
    uint16 index_id;

    uint16 space_id;
    uint8 initrans;
    uint8 cr_mode;
    page_list_t extents;

    uint32 ufp_count;
    page_id_t ufp_first;
    page_id_t ufp_extent;

    knl_scn_t del_scn;  // recycle scn of last page in del_pages
    page_list_t del_pages;  // recycled page list
    uint32 pctfree;

    /**
     * this is new variable for rocord page_count of this index
     * used for bitmap scenario when try to allow THE SIZE is not available,
     * then try to degrade size (eg 8192 -> 1024 ->128 -> 8), will update this vaule
     * otherwise, always be 0 (also elder version is 0).
     * scenarios(same usage for heap segment):
     *  1 page_count is 0, extent size and page count of this table should be count as before
     *  2 page_count is not 0, page count size must read for extent head (page_head_t)ext_size,
     *    page count used this one.
     */
    uint32 page_count;
    uint64 garbage_size;
    knl_scn_t first_recycle_scn;  // recycle scn of first page in del_pages
    knl_scn_t ow_del_scn;
    atomic_t ow_recycle_scn;
    knl_scn_t last_recycle_scn;  // recycle scn of last page in del_pages
    page_list_t recycled_pages;  // recycled page list
    uint32 unused;
    atomic_t recycle_ver_scn;
} btree_segment_t;

typedef struct st_rd_btree_insert {
    uint16 slot;
    uint8 is_reuse;
    uint8 itl_id;
    char key[0];
} rd_btree_insert_t;

typedef struct st_rd_btree_reuse_itl {
    knl_scn_t min_scn;
    xid_t xid;
    uint8 itl_id;
    uint8 unused1;   // for future use
    uint16 unused2;  // for future use
} rd_btree_reuse_itl_t;

typedef struct st_rd_btree_clean_itl {
    knl_scn_t scn;
    uint8 itl_id;
    uint8 is_owscn;
    uint8 is_copied;
    uint8 aligned;
} rd_btree_clean_itl_t;

typedef struct st_rd_btree_delete {
    uint32 ssn;
    undo_page_id_t undo_page;
    uint16 undo_slot;
    uint16 slot;
    uint8 itl_id;
    uint8 unused1;   // for future use
    uint16 unused2;  // for future use
} rd_btree_delete_t;

typedef struct st_rd_btree_clean_keys {
    uint16 keys;
    uint16 free_size;
} rd_btree_clean_keys_t;

typedef struct st_rd_btree_page_init {
    knl_scn_t seg_scn;
    page_id_t page_id;
    uint8 level;
    uint8 itls;
    uint8 cr_mode;
    uint8 extent_size;
    bool8 reserve_ext;
    uint8 aligned;
    uint16 unused;
} rd_btree_page_init_t;

typedef struct st_rd_btree_undo {
    knl_scn_t scn;
    rowid_t rowid;
    undo_page_id_t undo_page;
    uint16 undo_slot : 12;
    uint16 is_xfirst : 1;
    uint16 is_owscn : 1;
    uint16 unused : 2;
    uint16 slot;  // btree slot
} rd_btree_undo_t;

typedef struct st_rd_update_btree_partid {
    uint32 part_id;
    uint32 parent_partid;
    uint16 slot;
    uint16 is_compart_table : 1;
    uint16 unused : 15;
} rd_update_btree_partid_t;

typedef struct st_undo_btree_create {
    uint32 space_id;
    page_id_t entry;
} undo_btree_create_t;

typedef struct st_rd_btree_init_entry {
    page_id_t page_id;
    uint32 extent_size;
} rd_btree_init_entry_t;

typedef struct st_rd_btree_info {
    knl_scn_t min_scn;
    uint32 uid;
    uint32 oid;
    uint32 idx_id;
    knl_part_locate_t part_loc;
} rd_btree_info_t;

typedef struct st_rd_btree_set_recycle {
    rd_btree_info_t btree_info;
    knl_scn_t ow_del_scn;
} rd_btree_set_recycle_t;

typedef struct st_rd_btree_concat_dels {
    page_id_t next_del_page;
    knl_scn_t next_recycle_scn;
} rd_btree_concat_dels_t;

typedef struct st_btree_find_assist {
    btree_t *btree;
    bool32 page_damage;
    page_id_t page_id;
    knl_scan_key_t *scan_key;
    btree_path_info_t *path_info;
    btree_find_type find_type;
} btree_find_assist_t;

#pragma pack()
#ifdef __cplusplus
}
#endif

#endif