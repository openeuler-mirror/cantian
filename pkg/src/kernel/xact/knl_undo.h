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
#include "knl_undo_persist.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RETENTION_TIME_PERCENT (uint32)2
#define UNDO_EXTENT_SIZE  (uint32)1
#define UNDO_SHRINK_PAGES (uint32)1024
#define UNDO_PAGE_PER_LINE (uint32)(8)
#define UNDO_STAT_SNAP_INTERVAL 600000 // about 10 minutes
#define CT_MAX_UNDO_STAT_RECORDS (uint32)1024

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

#define UNDO_GET_INST_ID(seg_id)    ((seg_id) / CT_MAX_UNDO_SEGMENT)

#define UNDO_GET_SESSION_UNDO_SEGMENT(session) \
    (&((session)->kernel->undo_ctx.undos[UNDO_GET_SESSION_UNDO_SEGID(session)]))

#define UNDO_GET_FREE_PAGELIST(undo, need_redo) \
    ((need_redo) ? &(undo)->segment->page_list : &(undo)->temp_free_page_list)

#define UNDO_GET_PAGE_INFO(session, need_redo) \
    ((need_redo) ? &(session)->rm->undo_page_info : &(session)->rm->noredo_undo_page_info)

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


#define UNDO_INIT_THREAD_NUMS (16)

typedef struct undo_init_worker {
    undo_page_id_t *entry;
    uint32 lseg_no;
    uint32 rseg_no;
    thread_t thread;
    struct undo_init_ctx *undo_ctx;
    undo_set_t *undo_set;
} undo_init_worker_t;

typedef struct undo_init_ctx {
    undo_init_worker_t workers[UNDO_INIT_THREAD_NUMS];
    atomic_t undo_init_active_workers;
} undo_init_ctx_t;


typedef struct st_undo_set {
    space_t *space;
    bool32 used;
    uint32 inst_id;
    char *tx_buf;
    uint32 assign_workers;     // assign workers for rollback
    atomic_t active_workers;
    atomic_t rollback_num;  // txn rollback thread num
    rollback_ctx_t rb_ctx[CT_MAX_ROLLBACK_PROC];
    undo_t undos[CT_MAX_UNDO_SEGMENT];
} undo_set_t;

/* memory definition of undo/transaction context */
typedef struct st_undo_context {
    latch_t latch;
    thread_t thread;
    uint32 retention;
    space_t *space;
    space_t *temp_space;
    undo_t *undos;
    undo_set_t undo_sets[CT_MAX_INSTANCES];
    undo_t *temp_undos;
    undo_set_t temp_undo_sets[CT_MAX_INSTANCES];

    bool32 is_switching;
    bool32 is_extended;
    uint32 extend_segno;
    uint32 extend_cnt;
    uint32 stat_cnt;
    uint64 longest_sql_time;
    undo_stat_t stat[CT_MAX_UNDO_STAT_RECORDS];
    atomic_t active_workers;
} undo_context_t;

#define UNDO_PAGE_FREE_END(session, page) \
    (uint16)(DEFAULT_PAGE_SIZE(session) - sizeof(page_tail_t) - (page)->rows * sizeof(uint16))
#define UNDO_PAGE_MAX_FREE_SIZE(session)  \
    (uint16)(DEFAULT_PAGE_SIZE(session) - sizeof(undo_page_t) - sizeof(page_tail_t))
typedef struct st_undo_type_descriptor {
    uint8 undo_type;
    char *type_desc;
} undo_type_descriptor_t;

void temp2_undo_init(knl_session_t *session);
void undo_init(knl_session_t *session, uint32 lseg_no, uint32 rseg_no);
void undo_init_impl(knl_session_t *session, undo_set_t *undo_set, uint32 lseg_no, uint32 rseg_no);
status_t undo_create(knl_session_t *session, uint32 inst_id, uint32 space_id, uint32 lseg_no, uint32 count);
status_t temp_undo_create(knl_session_t *session, uint32 inst_id, uint32 space_id, uint32 lseg_no, uint32 count);
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
