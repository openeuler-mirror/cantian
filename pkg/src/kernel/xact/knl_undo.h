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
 * knl_undo.h
 *
 *
 * IDENTIFICATION
 * src/kernel/xact/knl_undo.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_UNDO_H__
#define __KNL_UNDO_H__

#include "cm_defs.h"
#include "knl_interface.h"
#include "knl_page.h"
#include "knl_session.h"
#include "knl_tran.h"
#include "knl_space_base.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RETENTION_TIME_PERCENT (uint32)2
#define UNDO_EXTENT_SIZE  (uint32)1
#define UNDO_MAX_TXN_PAGE (uint32)64
#define UNDO_SHRINK_PAGES (uint32)1024
#define UNDO_PAGE_PER_LINE (uint32)(8)
#define UNDO_DATA_RESERVED 4
#define UNDO_STAT_SNAP_INTERVAL 600000 // about 10 minutes
#define GS_MAX_UNDO_STAT_RECORDS (uint32)1024

#define UNDO_DEF_TXN_PAGE(session) (uint32)(UNDO_MAX_TXN_PAGE * SIZE_K(8) / DEFAULT_PAGE_SIZE(session))
#define UNDO_SEGMENT_COUNT(session)        (((knl_session_t *)(session))->kernel->attr.undo_segments)
#define UNDO_ACTIVE_SEGMENT_COUNT(session) (((knl_session_t *)(session))->kernel->attr.undo_active_segments)
#define UNDO_AUTON_TRANS_SEGMENT_COUNT(session) (((knl_session_t *)(session))->kernel->attr.undo_auton_trans_segments)
#define UNDO_IS_AUTON_BIND_OWN(session) (((knl_session_t *)(session))->kernel->attr.undo_auton_bind_own)

#define UNDO_INIT_PAGES(session, pages) \
    (uint32)(((pages) - UNDO_SEGMENT_COUNT(session) * (1 + UNDO_DEF_TXN_PAGE(session))) / \
    UNDO_SEGMENT_COUNT(session) * 40 / 100)
#define UNDO_RESERVE_PAGES(session, pages) \
    (uint32)(((pages) - UNDO_SEGMENT_COUNT(session) * (1 + UNDO_DEF_TXN_PAGE(session))) / \
    UNDO_ACTIVE_SEGMENT_COUNT(session) * 60 / 100)

#define UNDO_RESERVE_TEMP_PAGES(session, pages) (uint32)((pages) / UNDO_ACTIVE_SEGMENT_COUNT(session) * 60 / 100)

#define UNDO_GET_SEGMENT(session)    ((undo_segment_t *)(CURR_PAGE(session) + PAGE_HEAD_SIZE))

#define UNDO_SLOT(session, page, id) \
    (uint16 *)((char *)(page) + DEFAULT_PAGE_SIZE(session) - \
    (uint32)(sizeof(page_tail_t) + ((id) + 1) * sizeof(uint16)))

#define UNDO_ROW(session, page, id)  (undo_row_t *)((char *)(page) + *UNDO_SLOT(session, page, id))

#define UNDO_ROW_HEAD_SIZE (OFFSET_OF(undo_row_t, data))

#define UNDO_MAX_ROW_SIZE(session)                                               \
    (DEFAULT_PAGE_SIZE(session) - sizeof(undo_page_t) - sizeof(page_tail_t) -    \
    UNDO_ROW_HEAD_SIZE - sizeof(uint16) - sizeof(rowid_t))

#define UNDO_GET_SESSION_UNDO_SEGID(session)    ((session)->rm->undo_segid)

#define UNDO_GET_INST_ID(seg_id)    ((seg_id) / GS_MAX_UNDO_SEGMENT)

#define UNDO_GET_SESSION_UNDO_SEGMENT(session) \
    (&((session)->kernel->undo_ctx.undos[UNDO_GET_SESSION_UNDO_SEGID(session)]))

#define UNDO_GET_FREE_PAGELIST(undo, need_redo) \
    ((need_redo) ? &(undo)->segment->page_list : &(undo)->temp_free_page_list)

#define UNDO_GET_PAGE_INFO(session, need_redo) \
    ((need_redo) ? &(session)->rm->undo_page_info : &(session)->rm->noredo_undo_page_info)

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
} undo_type_t;

/* real-time undo segment information statistics */
typedef struct st_undo_seg_stat {
    date_t begin_time;
    uint32 reuse_expire_pages;
    uint32 reuse_unexpire_pages;
    uint32 use_space_pages;
    uint32 steal_expire_pages;
    uint32 steal_unexpire_pages;
    uint32 stealed_expire_pages;
    uint32 stealed_unexpire_pages;
    uint32 txn_cnts;
    uint64 buf_busy_waits;
} undo_seg_stat_t;

/* Real-time undo space information statistics */
typedef struct st_undo_stat {
    spinlock_t lock;
    date_t begin_time;
    date_t end_time;
    uint32 total_undo_pages;
    uint32 reuse_expire_pages;
    uint32 reuse_unexpire_pages;
    uint32 use_space_pages;
    uint32 steal_expire_pages;
    uint32 steal_unexpire_pages;
    uint32 txn_cnts;
    uint64 longest_sql_time;
    uint64 total_buf_busy_waits;
    uint32 busy_wait_segment;
    uint32 busy_seg_pages;
} undo_stat_t;

/* physical definition of undo segment */
#pragma pack(4)
typedef struct st_undo_segment {
    undo_page_list_t page_list;
    uint32 txn_page_count;
    undo_page_id_t txn_page[UNDO_MAX_TXN_PAGE];
} undo_segment_t;
#pragma pack()

/* memory definition of undo */
typedef struct st_undo {
    spinlock_t lock;
    knl_scn_t ow_scn;
    id_list_t free_items;
    tx_item_t *items;
    uint32 capacity;
    undo_page_id_t entry;     // segment entry
    undo_segment_t *segment;  // pinned in data buffer
    txn_page_t *txn_pages[UNDO_MAX_TXN_PAGE];
    undo_page_list_t temp_free_page_list;
    undo_seg_stat_t stat;
} undo_t;

typedef struct st_undo_set {
    space_t *space;
    bool32 used;
    uint32 inst_id;
    char *tx_buf;
    uint32 assign_workers;     // assign workers for rollback
    atomic_t active_workers;
    atomic_t rollback_num;  // txn rollback thread num
    rollback_ctx_t rb_ctx[GS_MAX_ROLLBACK_PROC];
    undo_t undos[GS_MAX_UNDO_SEGMENT];
} undo_set_t;

/* memory definition of undo/transaction context */
typedef struct st_undo_context {
    latch_t latch;
    thread_t thread;
    uint32 retention;
    space_t *space;
    space_t *temp_space;
    undo_t *undos;
    undo_set_t undo_sets[GS_MAX_INSTANCES];

    bool32 is_switching;
    bool32 is_extended;
    uint32 extend_segno;
    uint32 extend_cnt;
    uint32 stat_cnt;
    uint64 longest_sql_time;
    undo_stat_t stat[GS_MAX_UNDO_STAT_RECORDS];
    atomic_t active_workers;
} undo_context_t;

#define UNDO_PAGE_FREE_END(session, page) \
    (uint16)(DEFAULT_PAGE_SIZE(session) - sizeof(page_tail_t) - (page)->rows * sizeof(uint16))
#define UNDO_PAGE_MAX_FREE_SIZE(session)  \
    (uint16)(DEFAULT_PAGE_SIZE(session) - sizeof(undo_page_t) - sizeof(page_tail_t))

#pragma pack(4)
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

typedef struct st_undo_type_descriptor {
    uint8 undo_type;
    char *type_desc;
} undo_type_descriptor_t;

void temp2_undo_init(knl_session_t *session);
void undo_init(knl_session_t *session, uint32 lseg_no, uint32 rseg_no);
void undo_init_impl(knl_session_t *session, undo_set_t *undo_set, uint32 lseg_no, uint32 rseg_no);
status_t undo_create(knl_session_t *session, uint32 inst_id, uint32 space_id, uint32 lseg_no, uint32 count);
status_t undo_preload(knl_session_t *session);
void undo_close(knl_session_t *session);
void undo_set_release(knl_session_t *session, undo_set_t *undo_set);
status_t undo_multi_prepare(knl_session_t *session, uint32 count, uint32 size, bool32 need_redo, bool32 need_encrypt);
void undo_write(knl_session_t *session, undo_data_t *undo_data, bool32 need_redo, bool32 nolog_insert);
uint32 undo_max_prepare_size(knl_session_t *session, uint32 count);
void undo_shrink_segments(knl_session_t *session);
void undo_shrink_inactive_segments(knl_session_t *session);
void undo_release_pages(knl_session_t *session, undo_t *undo, undo_page_list_t *undo_pages, bool32 need_redo);
status_t undo_dump_page(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump);
bool32 undo_check_active_transaction(knl_session_t *session);
void undo_get_txn_hwms(knl_session_t *session, space_t *space, uint32 *hwms);
void undo_clean_segment_pagelist(knl_session_t *session, space_t *space);
void undo_format_page(knl_session_t *session, undo_page_t *page, page_id_t page_id,
                      undo_page_id_t prev, undo_page_id_t next);
const char *undo_type(uint8 type);
uint32 undo_part_locate_size(knl_handle_t knl_table);

static inline status_t undo_prepare(knl_session_t *session, uint32 size, bool32 need_redo, bool32 need_encrypt)
{
    return undo_multi_prepare(session, 1, size, need_redo, need_encrypt);
}

status_t undo_segment_dump(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump);
status_t undo_switch_space(knl_session_t *session, uint32 space_id);
void undo_reload_segment(knl_session_t *session, page_id_t entry);
void undo_invalid_segments(knl_session_t *session);
bool32 undo_valid_encrypt(knl_session_t *session, page_head_t *page);
status_t undo_df_create(knl_session_t *session, uint32 space_id, uint32 lseg_no, uint32 count, datafile_t *df);
void undo_timed_task(knl_session_t *session);

#ifdef __cplusplus
}
#endif

#endif
