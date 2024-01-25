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
 * pcr_heap_scan.h
 *
 *
 * IDENTIFICATION
 * src/kernel/table/pcr_heap_scan.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PCR_HEAP_SCAN_H__
#define __PCR_HEAP_SCAN_H__

#include "knl_session.h"
#include "knl_heap.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t pcrh_fetch_inter(knl_handle_t handle, knl_cursor_t *cursor);
status_t pcrh_rowid_scan_fetch(knl_handle_t session, knl_cursor_t *cursor);
status_t pcrh_enter_crpage(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn, rowid_t rowid);
status_t pcrh_read_by_given_rowid(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn,
                                  isolation_level_t isolevel, bool32 *is_found);
void pcrh_leave_current_page(knl_session_t *session, knl_cursor_t *cursor);
status_t pcrh_fetch_chain_r(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn,
    rowid_t rowid, row_head_t **row);
status_t pcrh_chk_curr_visible(knl_session_t *session, cr_cursor_t *cursor, heap_page_t *cr_page,
                               bool32 check_restart, bool32 *is_found);
status_t pcrh_dump_page(knl_session_t *session, page_head_t *head, cm_dump_t *dump);
void pcrh_validate_page(knl_session_t *session, page_head_t *page_head);
status_t pcrh_enter_ins_page(knl_session_t *session, knl_cursor_t *cursor, row_head_t *row, page_id_t *page_id);
status_t pcrh_alloc_itl(knl_session_t *session, knl_cursor_t *cursor, heap_page_t *page,
                        pcr_itl_t **itl, bool32 *changed);
status_t pcrh_fetch_by_rid(knl_session_t *session, knl_cursor_t *cursor);
status_t pcrh_prefetch_crpage(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn_input,
                               page_id_t page_id, char *page_buf, bool8 *fb_mark);
void pcrh_initialize_cr_cursor(cr_cursor_t *cr_cursor, knl_cursor_t *cursor, rowid_t rowid, knl_scn_t query_scn);
status_t pcrh_fetch_invisible_itl(knl_session_t *session, cr_cursor_t *cursor, heap_page_t *cr_page);
status_t pcrh_wait_for_txn(knl_session_t *session, knl_cursor_t *cursor, cr_cursor_t *cr_cursor);
bool32 pcrh_chk_r_visible(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn, heap_page_t *page,
                              uint16 slot);
status_t pcrh_chk_visible_with_undo_ss(knl_session_t *session, cr_cursor_t *cursor, heap_page_t *cr_page,
                                       bool32 check_restart, bool32 *is_found);

/*
 * get current heap page during current page cache type
 */
static inline heap_page_t *pcrh_get_current_page(knl_session_t *session, knl_cursor_t *cursor)
{
    switch (cursor->page_cache) {
        case NO_PAGE_CACHE:
            return (heap_page_t *)CURR_PAGE(session);
        case GLOBAL_PAGE_CACHE:
            return (heap_page_t *)CURR_CR_PAGE(session);
        case LOCAL_PAGE_CACHE:
            return (heap_page_t *)cursor->page_buf;
        default:
            return NULL;
    }
}

/*
 * CR rollback function
 * revert an itl operation from undo
 * @param kernel session, CR page, itl, undo row
 */
static inline void pcrh_revert_itl(knl_session_t *session, heap_page_t *cr_page, pcr_itl_t *itl, undo_row_t *undo_row)
{
    itl->xid = *(xid_t *)undo_row->data;
    itl->scn = undo_row->scn;
    itl->is_owscn = undo_row->is_owscn;
    itl->undo_page = undo_row->prev_page;
    itl->undo_slot = undo_row->prev_slot;
    itl->is_active = CT_FALSE;
}

#ifdef __cplusplus
}
#endif

#endif
