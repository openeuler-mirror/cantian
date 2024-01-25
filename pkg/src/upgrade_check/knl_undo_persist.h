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
 * knl_undo_persist.h
 *
 *
 * IDENTIFICATION
 * src/upgrade_check/knl_undo_persist.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_UNDO_PERSIST_H__
#define __KNL_UNDO_PERSIST_H__
 
#ifdef __cplusplus
extern "C" {
#endif
 
#define UNDO_MAX_TXN_PAGE (uint32)64
#define UNDO_DATA_RESERVED 4
/* current supported undo type definition */
typedef enum en_undo_type {
    /* heap */
    UNDO_HEAP_INSERT = 1,      /* < heap insert */
    UNDO_HEAP_DELETE = 2,      /* < heap delete */
    UNDO_HEAP_UPDATE = 3,      /* < heap update */
    UNDO_HEAP_UPDATE_FULL = 4, /* < heap update full */

    /* btree */
    UNDO_BTREE_INSERT = 5,  /* < btree insert */
    UNDO_BTREE_DELETE = 6,  /* < btree delete */
    UNDO_LOCK_SNAPSHOT = 7, /* < not used */
    UNDO_CREATE_INDEX = 8,  /* < fill index */

    UNDO_LOB_INSERT = 9, /* < lob insert */
    UNDO_LOB_DELETE_COMMIT = 10,

    /* temp table */
    UNDO_TEMP_HEAP_INSERT = 11,
    UNDO_TEMP_HEAP_DELETE = 12,
    UNDO_TEMP_HEAP_UPDATE = 13,
    UNDO_TEMP_HEAP_UPDATE_FULL = 14,
    UNDO_TEMP_BTREE_INSERT = 15,
    UNDO_TEMP_BTREE_DELETE = 16,

    UNDO_LOB_DELETE = 17,

    /* heap chain */
    UNDO_HEAP_INSERT_MIGR = 18,
    UNDO_HEAP_UPDATE_LINKRID = 19,
    UNDO_HEAP_DELETE_MIGR = 20,
    UNDO_HEAP_DELETE_ORG = 21,
    UNDO_HEAP_COMPACT_DELETE = 22,
    UNDO_HEAP_COMPACT_DELETE_ORG = 23,

    /* temp table batch insert */
    UNDO_TEMP_HEAP_BINSERT = 24,
    UNDO_TEMP_BTREE_BINSERT = 25,

    /* PCR heap */
    UNDO_PCRH_ITL = 30,
    UNDO_PCRH_INSERT = 31,
    UNDO_PCRH_DELETE = 32,
    UNDO_PCRH_UPDATE = 33,
    UNDO_PCRH_UPDATE_FULL = 34,
    UNDO_PCRH_UPDATE_LINK_SSN = 35,
    UNDO_PCRH_UPDATE_NEXT_RID = 36,
    UNDO_PCRH_BATCH_INSERT = 37,
    UNDO_PCRH_COMPACT_DELETE = 38,

    /* PCR btree */
    UNDO_PCRB_ITL = 40,
    UNDO_PCRB_INSERT = 41,
    UNDO_PCRB_DELETE = 42,
    UNDO_PCRB_BATCH_INSERT = 43,

    /* lob new delete commit */
    UNDO_LOB_DELETE_COMMIT_RECYCLE = 50,
    UNDO_LOB_ALLOC_PAGE = 51,
    UNDO_CREATE_HEAP = 52, /* < add hash partition */
    UNDO_CREATE_LOB = 53, /* < add hash partition */
    UNDO_LOB_TEMP_ALLOC_PAGE = 54,
    UNDO_LOB_TEMP_DELETE = 55,
} undo_type_t;

#pragma pack(4)
/* physical definition of undo segment */
typedef struct st_undo_segment {
    undo_page_list_t page_list;
    uint32 txn_page_count;
    undo_page_id_t txn_page[UNDO_MAX_TXN_PAGE];
} undo_segment_t;

/* physical definition of undo page */
typedef struct st_undo_page {
    page_head_t head;
    date_t ss_time;  // the last snapshot time on page.
    undo_page_id_t prev;
    uint16 rows;
    uint16 free_size;
    uint16 free_begin;
    uint16 begin_slot;  // the begin slot of current txn
    uint8 aligned[16];
} undo_page_t;

/* physical definition of undo row */
typedef struct st_undo_row {
    union {
        rowid_t rowid;
        struct {
            uint64 seg_file : 10;  // btree segment page id
            uint64 seg_page : 30;  // btree segment page id
            uint64 user_id : 14;
            uint64 index_id : 6;
            uint64 unused1 : 4;
        };
    };

    undo_page_id_t prev_page;  // previous undo page_id
    uint16 prev_slot;          // previous undo slot
    uint16 data_size;
    uint16 is_xfirst : 1;  // is first time change or first allocated dir or itl for PCR
    uint16 is_owscn : 1;
    uint16 is_cleaned : 1;
    uint16 contain_subpartno : 1;    // whether the ud_row contain subpart_no
    uint16 unused2 : 1;
    uint16 type : 8;
    uint16 unused : 3;
    uint16 aligned;
    uint32 ssn;     // sql sequence number that generated the undo
    knl_scn_t scn;  // last txn scn on this object or DB_CURR_SCN when generated the undo
    xid_t xid;      // xid that generated the undo
    char data[UNDO_DATA_RESERVED];   // reserve an address for the undo data size which the size is unknown
} undo_row_t;

/* memory definition of undo data for callers to generate undo */
typedef struct st_undo_data {
    uint32 size;      /* < data size, not include undo row head */
    undo_type_t type; /* < undo type */

    union {
        rowid_t rowid; /* < rowid to locate row or itl */
        struct {
            uint64 seg_file : 10; /* < btree segment entry file_id */
            uint64 seg_page : 30; /* < btree segment entry page_id */
            uint64 user_id : 14;  /* < user id */
            uint64 index_id : 6;  /* < index id */
            uint64 unused : 4;
        };
    };

    uint32 ssn;               /* < ssn generate current undo */
    undo_snapshot_t snapshot; /* < undo snapshot info */
    char *data;
} undo_data_t;

/* redo log definition for undo */
typedef struct st_rd_undo_alloc_seg {
    uint32 id;
    undo_page_id_t entry;
} rd_undo_alloc_seg_t;

typedef struct st_rd_undo_write {
    date_t time;
    char data[UNDO_DATA_RESERVED]; // reserve an address for the undo data size which the size is unknown
} rd_undo_write_t;

typedef struct st_rd_undo_create_seg {
    uint32 id;
    undo_segment_t seg;
} rd_undo_create_seg_t;

typedef struct st_rd_undo_chg_page {
    undo_page_id_t prev;
    uint16 slot;
    uint16 aligned;
} rd_undo_chg_page_t;

typedef struct st_rd_undo_fmt_page {
    undo_page_id_t page_id;
    undo_page_id_t prev;
    undo_page_id_t next;
} rd_undo_fmt_page_t;

typedef struct st_rd_undo_cipher_reserve {
    uint8 cipher_reserve_size;
    uint8 unused;
    uint16 aligned;
} rd_undo_cipher_reserve_t;

typedef struct st_rd_undo_chg_txn {
    xmap_t xmap;
    undo_page_list_t undo_pages;
} rd_undo_chg_txn_t;
#pragma pack()

typedef struct st_rd_set_ud_link {
    undo_rowid_t ud_link_rid;
    uint16 slot;
    uint16 aligned;
} rd_set_ud_link_t;

typedef struct st_rd_undo_alloc_txn_page {
    page_id_t txn_extent;
    uint32 slot;
} rd_undo_alloc_txn_page_t;

typedef struct st_rd_switch_undo_space {
    logic_op_t op_type;
    uint32 space_id;
    page_id_t space_entry;
} rd_switch_undo_space_t;

#ifdef __cplusplus
}
#endif

#endif
