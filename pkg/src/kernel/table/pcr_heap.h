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
 * pcr_heap.h
 *
 *
 * IDENTIFICATION
 * src/kernel/table/pcr_heap.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_PCR_HEAP_H__
#define __KNL_PCR_HEAP_H__

#include "knl_table_module.h"
#include "cm_defs.h"
#include "cm_row.h"
#include "knl_index.h"
#include "knl_lock.h"
#include "knl_map.h"
#include "knl_page.h"
#include "knl_session.h"
#include "knl_tran.h"
#include "knl_undo.h"
#include "rb_purge.h"
#include "knl_heap.h"
#include "pcr_heap_persistent.h"

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(4)
typedef uint16 pcr_row_dir_t;

/*
 * max row count is 32K / (HEAP_MIN_ROW_SIZE + sizeof(pcr_row_dir_t), about 1821
 * When row_dir is valid, it points to the position of row in page, 32K needs all 2bytes.
 * When row_dir is free, it points to the slot of next free row_dir, the max value
 * is 1821, 11 bits is enough for this.
 */
#define PCRH_DIR_FREE_MASK 0x8000
#define PCRH_DIR_NEW_MASK  0x4000
#define PCRH_NO_FREE_DIR   0x3FFF

#define PCRH_NEXT_FREE_DIR(dir) ((*(dir)) & (~PCRH_DIR_NEW_MASK) & (~PCRH_DIR_FREE_MASK))
#define PCRH_DIR_IS_FREE(dir)   (((*(dir)) & PCRH_DIR_FREE_MASK) != 0)
#define PCRH_DIR_IS_NEW(dir)    (((*(dir)) & PCRH_DIR_NEW_MASK) != 0)

#define PCRH_GET_ROW(page, dir) (row_head_t *)((char *)(page) + *(dir))

#define PCRH_MIN_ROW_SIZE    HEAP_MIN_ROW_SIZE  /* same with RCR heap */
#define PCRH_MAX_COST_SIZE(session)   HEAP_MAX_COST_SIZE(session) /* same with RCR heap */
#define PCRH_MAX_MIGR_SIZE(session)   (PCRH_MAX_COST_SIZE(session) - sizeof(pcr_row_dir_t) - sizeof(pcr_itl_t))
#define PCRH_MAX_ROW_SIZE(session)    \
    (PCRH_MAX_COST_SIZE(session) - sizeof(pcr_row_dir_t) - sizeof(pcr_itl_t) - sizeof(rowid_t))
#define PCRH_INSERT_MAX_CHAIN_COUNT 16

#define PCRH_MERGE_CHAIN_COUNT     (CT_MAX_CHAIN_COUNT - PCRH_INSERT_MAX_CHAIN_COUNT + 1)
#define PCRH_NEXT_ROWID(row) \
    (rowid_t *)((char *)(row) + (((row)->is_csf) ? (cm_row_init_size((row)->is_csf, ROW_COLUMN_COUNT(row))) : \
    (sizeof(row_head_t) + ((row)->is_link ? 0 : ROW_BITMAP_EX_SIZE((row))))))

#define PCRH_UPDATE_INPAGE_SIZE(cols) (sizeof(rd_pcrh_update_inpage_t) + CM_ALIGN4(sizeof(uint16) * (cols)))

#pragma pack()

/* structures using in compact page */
typedef struct st_compact_item {
    uint16 offset;
    uint16 prev;
    uint16 next;
    uint16 aligned;
} compact_item_t;

typedef struct st_compact_list {
    uint16 count;
    uint16 first;
    uint16 last;
    uint16 aligned;
} compact_list_t;

static inline pcr_row_dir_t *pcrh_get_dir(heap_page_t *page, uint16 slot)
{
    uint32 offset = (uint32)PAGE_SIZE(page->head) - sizeof(page_tail_t);
    offset -= page->itls * sizeof(pcr_itl_t);
    offset -= (slot + 1) * sizeof(pcr_row_dir_t);
    return (pcr_row_dir_t *)((char *)(page) + offset);
}

static inline pcr_itl_t *pcrh_get_itl(heap_page_t *page, uint8 id)
{
    uint32 offset = (uint32)PAGE_SIZE(page->head) - sizeof(page_tail_t);
    knl_panic(id < page->itls);
    offset -= (id + 1) * sizeof(pcr_itl_t);
    return (pcr_itl_t *)((char *)(page) + offset);
}

/*
 * PCR init a normal row
 * @param kernel session, row assist, row buffer, column count, itl_id, row flags
 */
void pcrh_init_row(knl_session_t *session, row_assist_t *ra, char *buf,
    uint32 column_count, uint8 itl_id, uint16 flags);
status_t pcrh_lock_row(knl_session_t *session, knl_cursor_t *cursor, bool32 *is_locked);
status_t pcrh_insert(knl_session_t *session, knl_cursor_t *cursor);
status_t pcrh_update(knl_session_t *session, knl_cursor_t *cursor);
status_t pcrh_delete(knl_session_t *session, knl_cursor_t *cursor);
uint32 pcrh_calc_insert_cost(knl_session_t *session, heap_segment_t *segment, uint16 row_size);
void pcrh_init_migr_row(knl_session_t *session, row_assist_t *ra, char *buf, uint32 column_count,
    uint8 itl_id, uint16 flags, rowid_t next_rid);
void pcrh_clean_lock(knl_session_t *session, lock_item_t *item);

uint8 pcrh_new_itl(knl_session_t *session, heap_page_t *page);
void pcrh_reuse_itl(knl_session_t *session, heap_page_t *page, pcr_itl_t *itl, uint8 itl_id);
void pcrh_clean_itl(knl_session_t *session, heap_page_t *page, rd_pcrh_clean_itl_t *redo);
void pcrh_insert_into_page(knl_session_t *session, heap_page_t *page, row_head_t *row,
                           undo_data_t *undo, rd_pcrh_insert_t *rd, uint16 *slot);
void pcrh_update_inpage(knl_session_t *session, heap_page_t *page, heap_update_assist_t *ua);
void pcrh_compact_page(knl_session_t *session, heap_page_t *page);
void pcrh_reset_self_changed(knl_session_t *session, heap_page_t *page, uint8 itl_id);
void pcrh_cleanout_itls(knl_session_t *session, knl_cursor_t *cursor, heap_page_t *page, bool32 *changed);
status_t pcrh_check_ud_row_info(heap_page_t *cr_page, undo_row_t *ud_row);
#ifdef __cplusplus
}
#endif

#endif

