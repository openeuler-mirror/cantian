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
 * knl_heap_persistent.h
 *
 *
 * IDENTIFICATION
 * src/upgrade_check/knl_heap_persistent.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_HEAD_PERSISTENT_H__
#define __KNL_HEAD_PERSISTENT_H__
 
#ifdef __cplusplus
extern "C" {
#endif
 
#pragma pack(4)
typedef struct st_rd_heap_alloc_itl {
    xid_t xid;
    uint8 itl_id;
    uint8 unused1;
    uint16 unused2;
} rd_heap_alloc_itl_t;

typedef struct st_rd_heap_clean_itl {
    knl_scn_t scn;
    uint8 itl_id;
    uint8 is_owscn;
    uint16 aligned;
} rd_heap_clean_itl_t;

typedef struct st_rd_heap_change_dir {
    knl_scn_t scn;
    undo_page_id_t undo_page;
    uint16 undo_slot;
    uint16 slot;
} rd_heap_change_dir_t;

typedef struct st_rd_heap_lock_row {
    knl_scn_t scn;
    uint16 slot;
    uint8 itl_id;
    uint8 is_owscn;
} rd_heap_lock_row_t;

typedef struct st_rd_heap_insert {
    uint32 ssn;
    undo_page_id_t undo_page;
    uint16 undo_slot;
    uint8  new_dir;
    uint8 aligned;
    char data[4];
} rd_heap_insert_t;

typedef struct st_rd_heap_insert_lrep {
    uint32 insert_row_count;
    uint32 column_count : 16;
    uint32 reserved : 16;
} rd_heap_insert_lrep_t;

typedef struct st_rd_heap_logic_data {
    uint32 tbl_id;   // table id
    uint32 tbl_uid;  // user id
    uint32 tbl_oid;
} rd_heap_logic_data_t;

typedef struct st_rd_logic_rep_head {
    uint16 col_count;
    bool8 is_pcr;
    uint8 unused;
} rd_logic_rep_head;

typedef struct st_rd_heap_update_inplace {
    uint16 slot;
    uint16 count;  // update columns
    uint16 columns[0];
    // following is update column data
} rd_heap_update_inplace_t;

typedef struct st_rd_heap_update_inpage {
    uint16 slot;
    uint16 new_cols;  // new columns
    int16 inc_size;
    uint16 count;     // update columns
    uint16 columns[0];  // following is update column data
} rd_heap_update_inpage_t;

typedef struct st_rd_set_link {
    rowid_t link_rid;
    uint16 slot;
    uint16 aligned;
} rd_set_link_t;

typedef struct st_rd_heap_delete {
    uint32 ssn;
    undo_page_id_t undo_page;
    uint16 undo_slot;
    uint16 slot;
} rd_heap_delete_t;

typedef struct st_rd_heap_undo {
    knl_scn_t scn;
    undo_page_id_t undo_page;
    uint16 undo_slot;
    uint16 slot;
    uint8 is_xfirst;
    uint8 is_owscn;
    uint16 aligned;
} rd_heap_undo_t;
#pragma pack()

#pragma pack(4)
typedef struct st_row_dir {
    union {
        struct {
            uint16 offset;          // offset of row
            uint16 is_owscn : 1;    // txn scn overwrite or not
            uint16 undo_slot : 15;  // undo row index
        };
        struct {
            uint16 is_free : 1;     // directory free flag
            uint16 next_slot : 15;  // next free slot id
            uint16 aligned;
        };
    };

    undo_page_id_t undo_page;
    knl_scn_t scn;  // sql sequence number(txn in progress) or commit scn
} row_dir_t;

// default heap page, as data page
typedef struct st_heap_page {
    page_head_t head;
    map_index_t map;
    knl_scn_t org_scn;
    knl_scn_t seg_scn;
    uint32 oid;
    uint16 uid;
    uint16 first_free_dir;
    pagid_data_t next;  // next data page
    uint16 free_begin;
    uint16 free_end;
    uint16 free_size;
    uint16 rows;  // row count
    uint16 dirs;  // row directory count
    // ==== above aligned by 4 bytes ===
    uint8 itls;  // itl count
    uint8 aligned[3];
    knl_scn_t scn;  // max committed itl scn(except delayed itl)
    uint8 reserved[4];
} heap_page_t;
#pragma pack()

typedef struct st_heap_key {
    uint16 col_count;
    uint16 reserved;
    uint16 col_id[CT_MAX_INDEX_COLUMNS];
    uint16 col_size[CT_MAX_INDEX_COLUMNS];
    char col_values[CT_KEY_BUF_SIZE];  // key data
} heap_key_t;
 
#ifdef __cplusplus
}
#endif
 
#endif
