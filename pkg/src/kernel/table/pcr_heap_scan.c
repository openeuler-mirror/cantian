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
 * pcr_heap_scan.c
 *
 *
 * IDENTIFICATION
 * src/kernel/table/pcr_heap_scan.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_table_module.h"
#include "pcr_heap_scan.h"
#include "pcr_heap_undo.h"
#include "pcr_heap.h"
#include "knl_context.h"
#include "dtc_heap.h"
#include "cm_io_record.h"

/*
 * get invisible itl from current CR page
 * @note This is the core function to construct a CR page.
 *
 * The CR rollback algorithm is as follow:
 * 1. Find all active transactions in current page to do CR rollback (neglect transaction order).
 * 2. For current transaction, we only rollback changes after current cursor to keep statement consistency.
 * 3. Find all inactive transactions in current page to do CR rollback (rollback in commit scn order).
 *
 * We do serialize check in page level not row level.
 * If current itl commit scn is ow_scn and query scn < commit scn, we can't decide whether to do rollback or not,
 * just throw 'snapshot too old' error here.
 * @param kernel session, kernel cursor, query scn, CR page, invisible itl(output), cleanout page
 */
status_t pcrh_fetch_invisible_itl(knl_session_t *session, cr_cursor_t *cursor, heap_page_t *cr_page)
{
    pcr_itl_t *item = NULL;
    txn_info_t txn_info;
    uint8 i;
    knl_scn_t query_scn = cursor->query_scn;
    pcr_itl_t **itl = &cursor->itl;
    bool8 *cleanout = &cursor->cleanout;

    *itl = NULL;

    for (i = 0; i < cr_page->itls; i++) {
        item = pcrh_get_itl(cr_page, i);
        tx_get_pcr_itl_info(session, CT_TRUE, item, &txn_info);

        if (txn_info.status == (uint8)XACT_END) {
            if (item->is_active) {
                *cleanout = CT_TRUE;
                cr_page->free_size += item->fsc;
                item->is_active = 0;
                item->scn = txn_info.scn;
                item->is_owscn = (uint16)txn_info.is_owscn;
            } else if (item->is_fast) {
                *cleanout = CT_TRUE;
            }

            if (txn_info.scn <= query_scn) {
                continue;
            }

            if (txn_info.is_owscn) {
                tx_record_sql(session);
                CT_LOG_RUN_ERR("snapshot too old, detail: itl owscn %llu, query scn %llu", txn_info.scn, query_scn);
                CT_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
                return CT_ERROR;
            }

            /*            if (cursor->isolevel == (uint8)ISOLATION_SERIALIZABLE) {
                            cursor->ssi_conflict = CT_TRUE;
                        }
            */

            /* find the recent itl to do CR rollback */
            if ((*itl) == NULL || (*itl)->scn < item->scn) {
                *itl = item;
            }
        } else {
            if (item->xid.value == cursor->xid.value) {
                if (item->ssn < cursor->ssn) {
                    continue;
                }
            } else if (TX_XA_CONSISTENCY(session)) {
                if ((txn_info.status == (uint8)XACT_PHASE1 ||
                    txn_info.status == (uint8)XACT_PHASE2) &&
                    txn_info.scn < query_scn) {
                    CT_LOG_DEBUG_INF("wait prepared transaction %u-%u-%u, status %u, scn %llu, query_scn %llu",
                                     item->xid.xmap.seg_id, item->xid.xmap.slot, item->xid.xnum, txn_info.status,
                                     txn_info.scn, query_scn);
                    session->wxid = item->xid;
                    ROWID_COPY(session->wrid, cursor->rowid);
                }
            }

            /* for active itl, just return to do CR rollback */
            *itl = item;
            return CT_SUCCESS;
        }
    }

    if (*itl != NULL) {
        return CT_SUCCESS;
    }

    /* user current query_scn as CR page scn */
    cr_page->scn = query_scn;

    return CT_SUCCESS;
}

void pcrh_initialize_cr_cursor(cr_cursor_t *cr_cursor, knl_cursor_t *cursor, rowid_t rowid, knl_scn_t query_scn)
{
    cr_cursor->rowid = rowid;

    cr_cursor->xid.value = cursor->xid;
    cr_cursor->wxid.value = CT_INVALID_ID64;
    cr_cursor->query_scn = query_scn;
    cr_cursor->ssn = (uint32)cursor->ssn;
    cr_cursor->ssi_conflict = cursor->ssi_conflict;
    cr_cursor->cleanout = CT_FALSE;
    cr_cursor->is_remote = CT_FALSE;
    cr_cursor->local_cr = CT_FALSE;
}

/*
 * PCR construct CR page interface
 * @note use the given query scn to rollback current page to a consistent status
 * After rollback, the CR page may not be exist in history, but it's consistent for current query scn
 * @attention stop rollback when we detect that we need to wait prepared transaction
 * @param kernel session, kernel cursor, query scn, CR page, flashback mark, cleanout page
 */
static status_t pcrh_construct_cr_page_interface(knl_session_t *session, cr_cursor_t *cursor, heap_page_t *cr_page,
                                       bool8 *fb_mark)
{
    cursor->ssi_conflict = CT_FALSE;
    bool8 constructed = CT_FALSE;
    // knl_scn_t query_scn = cursor->query_scn;
    // bool8 *cleanout = &cursor->cleanout;

    for (;;) {
        if (pcrh_fetch_invisible_itl(session, cursor, cr_page) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cursor->itl == NULL || cursor->wxid.value != CT_INVALID_ID64) {
            /*
             * 1.no invisible itl, just return current CR page
             * 2.waiting for prepared transaction
             */
            if (constructed) {
                session->stat->pcr_construct_count++;
            }
            return CT_SUCCESS;
        }

        if (pcrh_reorganize_with_ud_list(session, cursor, cr_page, fb_mark) != CT_SUCCESS) {
            return CT_ERROR;
        }
        constructed = CT_TRUE;
    }
}

status_t pcrh_wait_for_txn(knl_session_t *session, knl_cursor_t *cursor, cr_cursor_t *cr_cursor)
{
    session->wxid = cr_cursor->wxid;

    if (tx_wait(session, 0, ENQ_TX_READ_WAIT) != CT_SUCCESS) {
        tx_record_rowid(cr_cursor->rowid);
        return CT_ERROR;
    }

    if (cursor->isolevel == ISOLATION_CURR_COMMITTED) {
        cursor->query_scn = DB_CURR_SCN(session);
        cr_cursor->query_scn = cursor->query_scn;
    }

    cr_cursor->cleanout = cursor->cleanout;
    cr_cursor->ssi_conflict = cursor->ssi_conflict;
    return CT_SUCCESS;
}

/*
 * PCR heap prefetch CR page
 * @note enter a current page, rollback it to a consistent status during query scn
 * @param kernel session, kernel cursor, query scn, page id, CR page, flashback mark
 */
status_t pcrh_prefetch_crpage(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn_input,
                               page_id_t page_id, char *page_buf, bool8 *fb_mark)
{
    knl_scn_t query_scn = query_scn_input;
    heap_page_t *page = NULL;
    cr_cursor_t cr_cursor;
    errno_t ret;

    for (;;) {
        if (cursor->isolevel == ISOLATION_CURR_COMMITTED) {
            cursor->query_scn = DB_CURR_SCN(session);
            query_scn = cursor->query_scn;
            cursor->cc_cache_time = KNL_NOW(session);
        }

        /* try get page from CR pool */
        pcrp_enter_page(session, page_id, query_scn, (uint32)cursor->ssn);
        page = (heap_page_t *)CURR_CR_PAGE(session);
        if (page != NULL && SECUREC_LIKELY(cursor->isolevel != ISOLATION_SERIALIZABLE)) {
            if (heap_check_page(session, cursor, page, PAGE_TYPE_PCRH_DATA)) {
                ret = memcpy_s(page_buf, DEFAULT_PAGE_SIZE(session), page, DEFAULT_PAGE_SIZE(session));
                knl_securec_check(ret);
                pcrp_leave_page(session, CT_FALSE);
                return CT_SUCCESS;
            } else {
                /* current CR page is no used for current session, just release it */
                pcrp_leave_page(session, CT_TRUE);
            }
        }

        if (page != NULL) {
            pcrp_leave_page(session, CT_TRUE);
        }

        if (DB_IS_CLUSTER(session)) {
            return dtc_heap_prefetch_cr_page(session, cursor, query_scn, page_buf, fb_mark);
        }

        pcrh_initialize_cr_cursor(&cr_cursor, cursor, cursor->rowid, query_scn);

        if (buf_read_prefetch_page(session, page_id, LATCH_MODE_S, ENTER_PAGE_SEQUENTIAL) != CT_SUCCESS) {
            return CT_ERROR;
        }

        page = (heap_page_t *)CURR_PAGE(session);
        if (!heap_check_page(session, cursor, page, PAGE_TYPE_PCRH_DATA)) {
            buf_leave_page(session, CT_FALSE);
            HEAP_CHECKPAGE_ERROR(cursor);
            return CT_ERROR;
        }

        ret = memcpy_sp(page_buf, DEFAULT_PAGE_SIZE(session), page, DEFAULT_PAGE_SIZE(session));
        knl_securec_check(ret);
        buf_leave_page(session, CT_FALSE);

        if (pcrh_construct_cr_page_interface(session, &cr_cursor, (heap_page_t *)page_buf, fb_mark) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cr_cursor.wxid.value != CT_INVALID_ID64) {
            if (pcrh_wait_for_txn(session, cursor, &cr_cursor) != CT_SUCCESS) {
                tx_record_rowid(session->wrid);
                return CT_ERROR;
            }
            continue;
        }

        cursor->ssi_conflict = cr_cursor.ssi_conflict;
        cursor->cleanout = cr_cursor.cleanout;

        if (cursor->global_cached) {
            pcrp_alloc_page(session, page_id, query_scn, (uint32)cursor->ssn);
            ret = memcpy_s(CURR_CR_PAGE(session), DEFAULT_PAGE_SIZE(session), page_buf, DEFAULT_PAGE_SIZE(session));
            knl_securec_check(ret);
            pcrp_leave_page(session, CT_FALSE);
        }

        return CT_SUCCESS;
    }
}

/*
 * PCR get row from page
 * @note in current page, all rows are visible to us after CR rollback (if necessary), just read it.
 * @param kernel session, kernel cursor, query_scn, CR page,
 */
static bool32 pcrh_get_row_from_page(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn, heap_page_t *page)
{
    pcr_row_dir_t *dir = NULL;
    pcr_itl_t *itl = NULL;
    row_head_t *row = NULL;
    txn_info_t txn_info;
    errno_t ret;

    dir = pcrh_get_dir(page, (uint16)cursor->rowid.slot);
    if (PCRH_DIR_IS_FREE(dir)) {
        return CT_FALSE;
    }

    row = PCRH_GET_ROW(page, dir);
    if (row->is_deleted) {
        return CT_FALSE;
    }

    if (row->is_migr) {
        session->has_migr = CT_TRUE;
        return CT_FALSE;
    }

    if (!row->is_link) {
        if (cursor->page_cache == LOCAL_PAGE_CACHE) {
            /* cursor row can point to local CR page row directly */
            cursor->row = row;
        } else {
            /* we should copy row to row buffer from current page */
            cursor->row = (row_head_t *)cursor->buf;
            ret = memcpy_sp((cursor)->row, DEFAULT_PAGE_SIZE(session), (row), (row)->size);
            knl_securec_check(ret);
        }
    } else {
        /* If we see a link flag in current page, it means we have to read the migration */
        cursor->link_rid = *PCRH_NEXT_ROWID(row);
    }

    if (cursor->page_cache != NO_PAGE_CACHE || ROW_ITL_ID(row) == CT_INVALID_ID8 || !row->is_changed) {
        /** use the current query_scn as row scn */
        cursor->scn = query_scn;
    } else {
        itl = pcrh_get_itl(page, ROW_ITL_ID(row));
        tx_get_pcr_itl_info(session, CT_TRUE, itl, &txn_info);
        cursor->scn = txn_info.scn;
    }

    return CT_TRUE;
}

/*
 * PCR heap scan CR page
 * @param kernel session, kernel cursor, query_scn, CR page, is_found(output)
 */
static status_t pcrh_search_cr_page(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn,
                                  heap_page_t *cr_page, bool32 *is_found)
{
    *is_found = CT_FALSE;

    cursor->chain_count = 0;
    SET_ROWID_PAGE(&cursor->link_rid, INVALID_PAGID);

    for (;;) {
        if (cursor->rowid.slot == INVALID_SLOT) {
            cursor->rowid.slot = 0;
        } else {
            cursor->rowid.slot++;
        }

        if (cursor->rowid.slot == cr_page->dirs) {
            if (IS_SAME_PAGID(cursor->scan_range.r_page, AS_PAGID(cr_page->head.id))) {
                SET_ROWID_PAGE(&cursor->rowid, INVALID_PAGID);
            } else {
                SET_ROWID_PAGE(&cursor->rowid, AS_PAGID(cr_page->next));
            }

            cursor->rowid.slot = INVALID_SLOT;

            return CT_SUCCESS;
        } else if (cursor->rowid.slot > cr_page->dirs) {
            CT_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, "table");
            return CT_ERROR;
        }

        if (pcrh_get_row_from_page(session, cursor, query_scn, cr_page)) {
            *is_found = CT_TRUE;
            return CT_SUCCESS;
        }
    }
}

/*
 * check row visible
 * We do this check before we try to construct a CR page in rowid fetch
 * The main idea is to reduce CR page construct as little as possible.
 * @attention This function in only called under PCR heap point fetch.
 * @param kernel session, kernel cursor, query scn, heap page, row slot
 */
bool32 pcrh_chk_r_visible(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn, heap_page_t *page,
                              uint16 slot)
{
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    pcr_itl_t *itl = NULL;
    txn_info_t txn_info;

    /* invalid slot, no need to construct CR page */
    if (SECUREC_UNLIKELY(slot >= page->dirs)) {
        return CT_TRUE;
    }

    dir = pcrh_get_dir(page, slot);
    if (SECUREC_LIKELY(!PCRH_DIR_IS_FREE(dir))) {
        row = PCRH_GET_ROW(page, dir);
    }

    if (row == NULL || !row->is_changed || ROW_ITL_ID(row) == CT_INVALID_ID8) {
        txn_info.scn = page->scn;
        txn_info.status = (uint8)XACT_END;
    } else {
        itl = pcrh_get_itl(page, ROW_ITL_ID(row));
        tx_get_pcr_itl_info(session, CT_TRUE, itl, &txn_info);
    }

    if (txn_info.status == (uint8)XACT_END) {
        if (txn_info.scn <= query_scn) {
            return CT_TRUE;
        }
    } else {
        if (itl->xid.value == cursor->xid && itl->ssn < cursor->ssn) {
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

/*
 * PCR heap enter CR page
 * @note enter a current page, check if *current row* is visible to us,
 * if visible, return current page, otherwise, copy it as cached page,
 * rollback the copied page to a consistent status using query scn
 * @param kernel session, kernel cursor, query scn, rowid
 */
status_t pcrh_enter_crpage(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn, rowid_t rowid)
{
    page_id_t page_id = GET_ROWID_PAGE(rowid);
    heap_page_t *page = NULL;
    cr_cursor_t cr_cursor;
    errno_t ret;

    session->stat->cr_reads++;
    if (DB_IS_CLUSTER(session)) {
        return dtc_heap_enter_cr_page(session, cursor, query_scn, rowid);
    }

    for (;;) {
        if (buf_read_page(session, page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL) != CT_SUCCESS) {
            return CT_ERROR;
        }
        page = (heap_page_t *)CURR_PAGE(session);
        if (!heap_check_page(session, cursor, page, PAGE_TYPE_PCRH_DATA)) {
            buf_leave_page(session, CT_FALSE);
            HEAP_CHECKPAGE_ERROR(cursor);
            return CT_ERROR;
        }

        /* check row in current page is visible or not */
        if (pcrh_chk_r_visible(session, cursor, query_scn, page, (uint16)rowid.slot)) {
            cursor->page_cache = NO_PAGE_CACHE;
            return CT_SUCCESS;
        }

        /* try get page from CR pool */
        pcrp_enter_page(session, page_id, query_scn, (uint32)cursor->ssn);
        page = (heap_page_t *)CURR_CR_PAGE(session);
        if (page != NULL && SECUREC_LIKELY(cursor->isolevel != ISOLATION_SERIALIZABLE)) {
            /*
             * if current CR page is valid, leave current page and use CR page.
             * otherwise, reuse it to generate a new CR page
             */
            if (heap_check_page(session, cursor, page, PAGE_TYPE_PCRH_DATA)) {
                buf_leave_page(session, CT_FALSE);
                cursor->page_cache = GLOBAL_PAGE_CACHE;
                return CT_SUCCESS;
            }
        } else {
            if (page != NULL) {
                pcrp_leave_page(session, CT_TRUE);
            }

            pcrp_alloc_page(session, page_id, query_scn, (uint32)cursor->ssn);
            page = (heap_page_t *)CURR_CR_PAGE(session);
        }

        ret = memcpy_sp((char *)page, DEFAULT_PAGE_SIZE(session), CURR_PAGE(session), DEFAULT_PAGE_SIZE(session));
        knl_securec_check(ret);
        buf_leave_page(session, CT_FALSE);

        pcrh_initialize_cr_cursor(&cr_cursor, cursor, rowid, query_scn);

        if (pcrh_construct_cr_page_interface(session, &cr_cursor, page, NULL) != CT_SUCCESS) {
            pcrp_leave_page(session, CT_TRUE);
            return CT_ERROR;
        }

        if (cr_cursor.wxid.value != CT_INVALID_ID64) {
            pcrp_leave_page(session, CT_TRUE);
            session->wxid = cr_cursor.wxid;
            if (tx_wait(session, 0, ENQ_TX_READ_WAIT) != CT_SUCCESS) {
                tx_record_rowid(session->wrid);
                return CT_ERROR;
            }
            continue;
        }

        cursor->ssi_conflict = cr_cursor.ssi_conflict;
        cursor->page_cache = GLOBAL_PAGE_CACHE;
        return CT_SUCCESS;
    }
}

/*
 * PCR rowid scan fetch interface
 * @param kernel session, kernel cursor
 */
status_t pcrh_rowid_scan_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    for (;;) {
        if (cursor->rowid_no == cursor->rowid_count) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }

        ROWID_COPY(cursor->rowid, cursor->rowid_array[cursor->rowid_no]);
        cursor->rowid_no++;

        if (!spc_validate_page_id((knl_session_t *)session, GET_ROWID_PAGE(cursor->rowid))) {
            continue;
        }

        if (IS_DUAL_TABLE((table_t *)cursor->table)) {
            cursor->rowid.slot = INVALID_SLOT;
            return dual_fetch((knl_session_t *)session, cursor);
        }

        if (cursor->isolevel == ISOLATION_CURR_COMMITTED) {
            cursor->query_scn = DB_CURR_SCN((knl_session_t *)session);
            cursor->cc_cache_time = KNL_NOW((knl_session_t *)session);
        }

        if (pcrh_fetch_by_rid((knl_session_t *)session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cursor->is_found) {
            return CT_SUCCESS;
        }
    }
}

/*
 * PCR fetch row by rowid
 * @param kernel session, kernel cursor, is_found(output)
 */
status_t pcrh_fetch_by_rid(knl_session_t *session, knl_cursor_t *cursor)
{
    timeval_t tv_begin;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_KNL_FETCH_BY_ROWID, &tv_begin);
    cursor->ssi_conflict = CT_FALSE;
    if (pcrh_read_by_given_rowid(session, cursor, cursor->query_scn, cursor->isolevel, &cursor->is_found) != CT_SUCCESS) {
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_FETCH_BY_ROWID, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    if (!cursor->is_found) {
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_FETCH_BY_ROWID, &tv_begin, IO_STAT_SUCCESS);
        return CT_SUCCESS;
    }

    if (knl_match_cond(session, cursor, &cursor->is_found) != CT_SUCCESS) {
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_FETCH_BY_ROWID, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    if (!cursor->is_found || cursor->action <= CURSOR_ACTION_SELECT) {
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_FETCH_BY_ROWID, &tv_begin, IO_STAT_SUCCESS);
        return CT_SUCCESS;
    }

    if (pcrh_lock_row(session, cursor, &cursor->is_found) != CT_SUCCESS) {
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_FETCH_BY_ROWID, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }
    cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_FETCH_BY_ROWID, &tv_begin, IO_STAT_SUCCESS);
    return CT_SUCCESS;
}

/*
 * release current heap page during current page cache type
 */
void pcrh_leave_current_page(knl_session_t *session, knl_cursor_t *cursor)
{
    switch (cursor->page_cache) {
        case NO_PAGE_CACHE:
            buf_leave_page(session, CT_FALSE);
            break;
        case GLOBAL_PAGE_CACHE:
            pcrp_leave_page(session, CT_FALSE);
            break;
        default:
            break;
    }
}

/*
* PCR fetch single chain row interface
* @note some single chain rows will construct the whole row. if fetching success, current page would be
*       release after merge chain row.
* @param kernel session, kernel cursor, query scn, rowid
*/
status_t pcrh_fetch_chain_r(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn,
    rowid_t rowid, row_head_t **row)
{
    heap_page_t *page = NULL;
    pcr_row_dir_t *dir = NULL;

    if (pcrh_enter_crpage(session, cursor, query_scn, rowid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    page = pcrh_get_current_page(session, cursor);
    if (rowid.slot >= page->dirs) {
        pcrh_leave_current_page(session, cursor);
        CT_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, "table");
        return CT_ERROR;
    }

    dir = pcrh_get_dir(page, (uint16)rowid.slot);
    if (PCRH_DIR_IS_FREE(dir)) {
        pcrh_leave_current_page(session, cursor);
        CT_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, "table");
        return CT_ERROR;
    }

    *row = PCRH_GET_ROW(page, dir);
    knl_panic((*row)->is_migr == 1);
    return CT_SUCCESS;
}

/*
* PCR fetch chain rows interface
* @note use the query scn to construct CR pages of every chain row, reorganize all chain rows to origin row
* @param kernel session, kernel cursor, query scn, CR page
*/
static status_t pcrh_get_chain_rows(knl_session_t *session, knl_cursor_t *cursor,
    knl_scn_t query_scn, row_head_t *row)
{
    dc_entity_t *entity;
    row_chain_t *chain = (row_chain_t *)cursor->chain_info;
    rowid_t rowid, prev_rid;
    row_assist_t ra;
    uint16 slot;
    uint16 column_count;
    uint16 data_offset;
    uint16 size;
    uint32 max_row_len = heap_table_max_row_len(cursor->table, CT_MAX_ROW_SIZE, cursor->part_loc);

    slot = 0;
    column_count = 0;
    rowid = cursor->link_rid;
    prev_rid = cursor->rowid;
    entity = (dc_entity_t *)cursor->dc_entity;

    cm_row_init(&ra, (char *)cursor->row, max_row_len, entity->column_count, row->is_csf);
    data_offset = cursor->row->size;

    for (;;) {
        chain[slot].chain_rid = rowid;
        chain[slot].owner_rid = prev_rid;
        chain[slot].col_start = column_count;
        chain[slot].col_count = ROW_COLUMN_COUNT(row);
        chain[slot].row_size = row->size;

        cm_decode_row((char *)row, cursor->offsets, cursor->lens, &size);

        heap_merge_chain_row(cursor, row, column_count, size, &data_offset);

        /* max column count of table is CT_MAX_COLUMNS(4096) , so the sum will not exceed max value of uint16 */
        column_count += chain[slot].col_count;

        prev_rid = rowid;
        rowid = *PCRH_NEXT_ROWID(row);

        pcrh_leave_current_page(session, cursor); /** leave current page */

        if (IS_INVALID_ROWID(rowid)) {
            break;
        }

        /* if fetching success, current page would be release after merge chain row. */
        if (pcrh_fetch_chain_r(session, cursor, query_scn, rowid, &row) != CT_SUCCESS) {
            return CT_ERROR;
        }

        slot++;
    }

    cursor->chain_count = slot + 1;

    if (column_count != entity->column_count) {
        heap_reorganize_chain_row(session, cursor, &ra, column_count);
    }
    row_end(&ra);

    return CT_SUCCESS;
}

static status_t pcrh_chain_r_col_cnt(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn,
    uint32 *col_count)
{
    rowid_t rowid;
    row_head_t *row = NULL;
    rowid = cursor->link_rid;

    for (;;) {
        if (IS_INVALID_ROWID(rowid)) {
            break;
        }

        if (pcrh_fetch_chain_r(session, cursor, query_scn, rowid, &row) != CT_SUCCESS) {
            return CT_ERROR;
        }

        *col_count += ROW_COLUMN_COUNT(row);
        rowid = *PCRH_NEXT_ROWID(row);

        pcrh_leave_current_page(session, cursor); /** leave current page */
    }

    return CT_SUCCESS;
}

/*
 * PCR fetch chain rows interface in current committed isolation level
 * @note use the query scn to construct CR pages of every chain row, reorganize all chain rows to origin row
 * @note the column count of dc may be less the column count of row in cc-isolation level,so we need get real
         the column count of row to init row and decode row.
 * @param kernel session, kernel cursor, query scn, CR page
 */
static status_t pcrh_get_cc_chain_rows(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn,
    bool32 is_csf)
{
    dc_entity_t *entity;
    row_chain_t *chain = (row_chain_t *)cursor->chain_info;
    row_head_t *row = NULL;
    rowid_t rowid, prev_rid;
    row_assist_t ra;
    uint16 slot;
    uint16 column_count;
    uint16 data_offset;
    uint16 size;
    uint32 max_row_len = heap_table_max_row_len(cursor->table, CT_MAX_ROW_SIZE, cursor->part_loc);
    uint32 col_count = 0;

    slot = 0;
    column_count = 0;
    rowid = cursor->link_rid;
    prev_rid = cursor->rowid;
    entity = (dc_entity_t *)cursor->dc_entity;

    if (pcrh_chain_r_col_cnt(session, cursor, query_scn, &col_count) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cm_row_init(&ra, (char *)cursor->row, max_row_len, col_count, is_csf);
    data_offset = cursor->row->size;
    for (;;) {
        if (IS_INVALID_ROWID(rowid)) {
            break;
        }

        /* if fetch chain row success, current page would be release after merge chain row */
        if (pcrh_fetch_chain_r(session, cursor, query_scn, rowid, &row) != CT_SUCCESS) {
            return CT_ERROR;
        }

        chain[slot].chain_rid = rowid;
        chain[slot].owner_rid = prev_rid;
        chain[slot].col_start = column_count;
        chain[slot].col_count = ROW_COLUMN_COUNT(row);
        chain[slot].row_size = row->size;

        cm_decode_row((char *)row, cursor->offsets, cursor->lens, &size);
        heap_merge_chain_row(cursor, row, column_count, size, &data_offset);

        /* max column count of table is CT_MAX_COLUMNS(4096) , so the sum will not exceed max value of uint16 */
        column_count += chain[slot].col_count;

        prev_rid = rowid;
        rowid = *PCRH_NEXT_ROWID(row);

        pcrh_leave_current_page(session, cursor); /** leave current page */

        slot++;
    }

    cursor->chain_count = (uint8)slot;

    if (column_count != entity->column_count) {
        heap_reorganize_chain_row(session, cursor, &ra, column_count);
    }
    row_end(&ra);

    return CT_SUCCESS;
}

/*
 * PCR fetch link row
 * @param kernel session, kernel cursor, query scn
 */
static status_t pcrh_fetch_link_r(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn)
{
    /* for temp CR page, cursor row should point to cursor row buffer */
    cursor->chain_count = 1;
    cursor->row = (row_head_t *)cursor->buf;

    if (pcrh_enter_crpage(session, cursor, query_scn, cursor->link_rid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    heap_page_t *page = pcrh_get_current_page(session, cursor);
    if (cursor->link_rid.slot >= page->dirs) {
        pcrh_leave_current_page(session, cursor);
        CT_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, "table");
        return CT_ERROR;
    }

    pcr_row_dir_t *dir = pcrh_get_dir(page, (uint16)cursor->link_rid.slot);
    if (PCRH_DIR_IS_FREE(dir)) {
        pcrh_leave_current_page(session, cursor);
        CT_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, "table");
        return CT_ERROR;
    }

    row_head_t *row = PCRH_GET_ROW(page, dir);
    knl_panic_log(row->is_migr == 1, "the row is not migr, panic info: page %u-%u type %u table %s",
                  cursor->rowid.file, cursor->rowid.page, page->head.type, ((table_t *)cursor->table)->desc.name);
    rowid_t next_rid = *PCRH_NEXT_ROWID(row);
    bool32 is_csf = row->is_csf;
    if (IS_INVALID_ROWID(next_rid)) {
        /* we should copy current row to cursor row buffer */
        errno_t ret = memcpy_sp(cursor->row, DEFAULT_PAGE_SIZE(session), row, row->size);
        knl_securec_check(ret);
        pcrh_leave_current_page(session, cursor);
        return CT_SUCCESS;
    }

    if (knl_cursor_use_vm(session, cursor, CT_TRUE) != CT_SUCCESS) {
        pcrh_leave_current_page(session, cursor);
        return CT_ERROR;
    }

    if (cursor->isolevel != (uint8)ISOLATION_CURR_COMMITTED) {
        /* current page would be release during chain rows fetch */
        if (pcrh_get_chain_rows(session, cursor, query_scn, row) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        pcrh_leave_current_page(session, cursor);
        /* when isolation level is current committed, entity may be invalid during fetching rows, column count of
         * entity may be less the column count of row in cr page (eg :select and add column concurrently).we need get
         * the actual column count in row to init row and decode row.
         */
        if (pcrh_get_cc_chain_rows(session, cursor, query_scn, is_csf) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

/*
 * PCR fetch CR page
 * in current committed isolation, we update query scn when constructing a CR page
 * @param kernel session, kernel cursor, is_found(output)
 */
static status_t pcrh_fetch_crpage(knl_session_t *session, knl_cursor_t *cursor, bool32 *is_found)
{
    heap_page_t *page = NULL;

    if (heap_cached_invalid(session, cursor)) {
        if (pcrh_prefetch_crpage(session, cursor, cursor->query_scn, GET_ROWID_PAGE(cursor->rowid),
                                  cursor->page_buf, NULL) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    cursor->page_cache = LOCAL_PAGE_CACHE;
    page = (heap_page_t *)cursor->page_buf;

    if (pcrh_search_cr_page(session, cursor, cursor->query_scn, page, is_found) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (*is_found && !IS_INVALID_ROWID(cursor->link_rid)) {
        if (pcrh_fetch_link_r(session, cursor, cursor->query_scn) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

/*
 * PCR heap fetch interface
 * @param kernel session handle, kernel cursor
 */
status_t pcrh_fetch_inter(knl_handle_t handle, knl_cursor_t *cursor)
{
    knl_session_t *session = (knl_session_t *)handle;
    rowid_t row_id;
    heap_t *heap = NULL;
    seg_stat_t temp_stat;
    status_t status;
    io_record_stat_t io_stat = IO_STAT_SUCCESS;
    timeval_t tv_begin;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_PCRH_FETCH, &tv_begin);

    knl_panic_log(cursor->is_valid, "current cursor is invalid, panic info: page %u-%u type %u table %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name);

    if (IS_DUAL_TABLE((table_t *)cursor->table)) {
        status = dual_fetch(session, cursor);
        io_stat = (status == CT_SUCCESS ? IO_STAT_SUCCESS : IO_STAT_FAILED);
        cantian_record_io_stat_end(IO_RECORD_EVENT_PCRH_FETCH, &tv_begin, io_stat);
        return status;
    }

    status = CT_SUCCESS;
    heap = CURSOR_HEAP(cursor);
    SEG_STATS_INIT(session, &temp_stat);
    
    for (;;) {
        if (IS_INVALID_ROWID(cursor->rowid)) {
            cursor->is_found = CT_FALSE;
            cursor->eof = CT_TRUE;
            cantian_record_io_stat_end(IO_RECORD_EVENT_PCRH_FETCH, &tv_begin, IO_STAT_SUCCESS);
            return CT_SUCCESS;
        }

        row_id = cursor->rowid;
        if (pcrh_fetch_crpage(session, cursor, &cursor->is_found) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        if (!IS_SAME_PAGID_BY_ROWID(row_id, cursor->rowid)) {
            if (session->canceled) {
                CT_THROW_ERROR(ERR_OPERATION_CANCELED);
                status = CT_ERROR;
                break;
            }

            if (session->killed) {
                CT_THROW_ERROR(ERR_OPERATION_KILLED);
                status = CT_ERROR;
                break;
            }

            if (cursor->cleanout) {
                heap_cleanout_page(session, cursor, GET_ROWID_PAGE(row_id), CT_TRUE);
            }
        }

        if (!cursor->is_found) {
            continue;
        }

        if (knl_match_cond(session, cursor, &cursor->is_found) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        if (!cursor->is_found) {
            continue;
        }

        if (cursor->action <= CURSOR_ACTION_SELECT) {
            break;
        }

        if (pcrh_lock_row(session, cursor, &cursor->is_found) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        if (cursor->is_found) {
            break;
        }
    }

    SEG_STATS_RECORD(session, temp_stat, &heap->stat);
    io_stat = (status == CT_SUCCESS ? IO_STAT_SUCCESS : IO_STAT_FAILED);
    cantian_record_io_stat_end(IO_RECORD_EVENT_PCRH_FETCH, &tv_begin, io_stat);
    return status;
}

static inline bool32 pcrh_chk_visible_with_itl(knl_session_t *session, cr_cursor_t *cursor, heap_page_t *cr_page,
                                                 undo_row_t *ud_row, pcr_itl_t *itl)
{
    /* no need to check the same transaction, this code may be not necessary */
    if (ud_row->xid.value == cursor->xid.value && ud_row->ssn < cursor->ssn) {
        itl->ssn = ud_row->ssn;
        return CT_FALSE;
    }

    if (ud_row->type == UNDO_PCRH_ITL) {
        pcrh_revert_itl(session, cr_page, itl, ud_row);
        return CT_FALSE;
    }

    return CT_TRUE;
}

static status_t pcrh_chk_visible_with_udrow(knl_session_t *session, cr_cursor_t *cursor, undo_row_t *ud_row,
                                              bool32 check_restart, bool32 *is_found)
{
    if (check_restart) {
        if (ud_row->type == UNDO_PCRH_COMPACT_DELETE && IS_SAME_ROWID(ud_row->rowid, cursor->rowid)) {
            CT_THROW_ERROR(ERR_NEED_RESTART);
            return CT_ERROR;
        }

        return CT_SUCCESS;
    }

    /* current row is not visible, don't do following check */
    if (ud_row->type == UNDO_PCRH_INSERT && IS_SAME_ROWID(ud_row->rowid, cursor->rowid)) {
        *is_found = CT_FALSE;
        return CT_SUCCESS;
    }

    if (ud_row->type != UNDO_PCRH_BATCH_INSERT) {
        return CT_SUCCESS;
    }

    pcrh_undo_batch_insert_t *batch_undo = (pcrh_undo_batch_insert_t *)ud_row->data;
    for (int32 i = batch_undo->count - 1; i >= 0; i--) {
        if (cursor->rowid.slot == batch_undo->undos[i].slot) {
            *is_found = CT_FALSE;
            return CT_SUCCESS;
        }
    }

    return CT_SUCCESS;
}

/*
 * PCR check visible with undo snapshot
 * @note check the row we just read in current committed mode are the row we wants
 * or which has been deleted and inserted. This is necessary to keep consistent read
 * in read committed isolation level.
 * @param kernel session, kernel cursor, CR page, itl, is_found(output)
 */
status_t pcrh_chk_visible_with_undo_ss(knl_session_t *session, cr_cursor_t *cursor, heap_page_t *cr_page,
                                      bool32 check_restart, bool32 *is_found)
{
    pcr_itl_t *itl = cursor->itl;
    itl->is_hist = CT_TRUE;
    if (!itl->is_active) {
        itl->is_active = CT_TRUE;
        itl->is_owscn = CT_FALSE;
        itl->fsc = 0;
    }

    uint8 options = cursor->is_remote ? ENTER_PAGE_TRY : ENTER_PAGE_NORMAL;
    for (;;) {
        if (buf_read_page(session, PAGID_U2N(itl->undo_page), LATCH_MODE_S, options) != CT_SUCCESS) {
            return CT_ERROR;
        }

        undo_page_t *ud_page = (undo_page_t *)CURR_PAGE(session);
        if (ud_page == NULL) {
            /* only in remote visible check, force the requester to do local read */
            cursor->local_cr = CT_TRUE;
            return CT_SUCCESS;
        }

        if (itl->undo_slot >= ud_page->rows) {
            buf_leave_page(session, CT_FALSE);
            tx_record_sql(session);
            CT_LOG_RUN_ERR("snapshot too old, detail: snapshot slot %u, undo rows %u, "
                "query scn %llu, check_restart %u", (uint32)itl->undo_slot,
                (uint32)ud_page->rows, cursor->query_scn, (uint32)check_restart);
            CT_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
            return CT_ERROR;
        }

        undo_row_t *ud_row = UNDO_ROW(session, ud_page, itl->undo_slot);
        if (itl->xid.value != ud_row->xid.value) {
            buf_leave_page(session, CT_FALSE);
            tx_record_sql(session);
            CT_LOG_RUN_ERR("snapshot too old, detail: snapshot xid %llu, undo row xid %llu, "
                "query scn %llu, check_restart %u", itl->xid.value, ud_row->xid.value,
                cursor->query_scn, (uint32)check_restart);
            CT_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
            return CT_ERROR;
        }

        if (!pcrh_chk_visible_with_itl(session, cursor, cr_page, ud_row, itl)) {
            buf_leave_page(session, CT_FALSE);
            return CT_SUCCESS;
        }

        itl->ssn = ud_row->ssn;
        itl->undo_page = ud_row->prev_page;
        itl->undo_slot = ud_row->prev_slot;

        if (pcrh_chk_visible_with_udrow(session, cursor, ud_row, check_restart, is_found) != CT_SUCCESS) {
            buf_leave_page(session, CT_FALSE);
            return CT_ERROR;
        }
        buf_leave_page(session, CT_FALSE);

        if (!(*is_found)) {
            return CT_SUCCESS;
        }
    }
}

/*
 * PCR check current visible
 * @note check current row is the row we are reading or not.
 * this would be called when are re-reading in current read when concurrent update/delete happens
 * @param kernel session, kernel cursor, CR page, is_found(output)
 */
status_t pcrh_chk_curr_visible(knl_session_t *session, cr_cursor_t *cursor, heap_page_t *cr_page,
                                    bool32 check_restart, bool32 *is_found)
{
    if (DB_IS_CLUSTER(session)) {
        return dtc_heap_check_current_visible(session, cursor, cr_page, is_found);
    }

    for (;;) {
        if (pcrh_fetch_invisible_itl(session, cursor, cr_page) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cursor->itl == NULL) {
            /* all itls have been checked read consistency */
            return CT_SUCCESS;
        }

        // We treat it as invisible transaction because it's unnecessary to wait prepared transaction here.
        if (session->wxid.value != CT_INVALID_ID64) {
            session->wxid.value = CT_INVALID_ID64;
        }

        if (pcrh_chk_visible_with_undo_ss(session, cursor, cr_page, check_restart, is_found) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (check_restart) {
            continue;
        }

        if (!*is_found) {
            /* visible row has been deleted */
            return CT_SUCCESS;
        }
    }
}


/*
 * PCR read by given rowid
 * @note support read current committed, serialize read, read committed
 * In this function we should push a temp CR page to do following work, because
 * we could not use the second cursor buffer when doing index fetch.
 * @param kernel session, kernel cursor, query_scn, isolation level, is_found(output)
 */
status_t pcrh_read_by_given_rowid(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn,
                                  isolation_level_t isolevel, bool32 *is_found)
{
    heap_page_t *page = NULL;
    heap_page_t *temp_page = NULL;
    cr_cursor_t cr_cursor;
    errno_t ret;
 
    cursor->chain_count = 0;
    SET_ROWID_PAGE(&cursor->link_rid, INVALID_PAGID);

    if (pcrh_enter_crpage(session, cursor, query_scn, cursor->rowid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    page = pcrh_get_current_page(session, cursor);
    if (cursor->rowid.slot >= page->dirs) {
        pcrh_leave_current_page(session, cursor);
        CT_THROW_ERROR(ERR_INVALID_ROWID);
        return CT_ERROR;
    }

    if (!pcrh_get_row_from_page(session, cursor, query_scn, page)) {
        pcrh_leave_current_page(session, cursor);
        *is_found = CT_FALSE;
        return CT_SUCCESS;
    }

    *is_found = CT_TRUE;

    if (isolevel == (uint8)ISOLATION_CURR_COMMITTED &&
        cursor->isolevel != (uint8)ISOLATION_SERIALIZABLE &&
        cursor->scn > cursor->query_scn) {
        /*
         * We cannot check current visible on current page or current global CR page,
         * so, alloc a temp page to this check.
         */
        temp_page = (heap_page_t *)cm_push(session->stack, DEFAULT_PAGE_SIZE(session));
        ret = memcpy_sp((char *)temp_page, DEFAULT_PAGE_SIZE(session), page, DEFAULT_PAGE_SIZE(session));
        knl_securec_check(ret);
        pcrh_leave_current_page(session, cursor);

        pcrh_initialize_cr_cursor(&cr_cursor, cursor, cursor->rowid, cursor->query_scn);

        if (pcrh_chk_curr_visible(session, &cr_cursor, temp_page, CT_FALSE, is_found) != CT_SUCCESS) {
            cm_pop(session->stack);
            return CT_ERROR;
        }

        cm_pop(session->stack);

        if (!*is_found) {
            return CT_SUCCESS;
        }
    } else {
        pcrh_leave_current_page(session, cursor);
    }

    if (!IS_INVALID_ROWID(cursor->link_rid)) {
        if (pcrh_fetch_link_r(session, cursor, query_scn) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

/*
 * generate undo for PCR heap itl
 * @param kernel session, kernel cursor, heap page, itl, undo
 */
static void pcrh_gener_itl_undo(knl_session_t *session, knl_cursor_t *cursor, heap_page_t *page,
                                   pcr_itl_t *itl, undo_data_t *undo)
{
    pcrh_undo_itl_t undo_itl;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);
    undo->snapshot.scn = itl->scn;
    undo->snapshot.is_owscn = itl->is_owscn;
    undo->snapshot.undo_page = itl->undo_page;
    undo->snapshot.undo_slot = itl->undo_slot;
    undo->snapshot.is_xfirst = CT_TRUE;

    undo_itl.xid = itl->xid;
    undo_itl.part_loc = cursor->part_loc;
    undo->size = sizeof(pcrh_undo_itl_t);
    undo->data = (char *)&undo_itl;

    undo->type = UNDO_PCRH_ITL;
    undo->rowid.file = AS_PAGID_PTR(page->head.id)->file;
    undo->rowid.page = AS_PAGID_PTR(page->head.id)->page;
    undo->rowid.slot = session->itl_id;
    /* cursor->ssn is from session->xact_ssn(uint32) or stmt->xact_ssn(uint32) for not temp table */
    undo->ssn = (uint32)cursor->ssn;

    undo_write(session, undo, need_redo, !cursor->logging);
}

static void pcrh_initialize_itl(knl_session_t *session, knl_cursor_t *cursor, heap_page_t *page,
    pcr_itl_t **itl, bool32 *changed)
{
    undo_data_t undo;
    rd_pcrh_reuse_itl_t rd_reuse;
    rd_pcrh_new_itl_t rd_new;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);
    undo_page_info_t *undo_page_info = UNDO_GET_PAGE_INFO(session, need_redo);

    if (*itl == NULL) {
        session->itl_id = pcrh_new_itl(session, page);
        if (session->itl_id == CT_INVALID_ID8) {
            return;
        }

        *itl = pcrh_get_itl(page, session->itl_id);
        /* cursor->ssn is from session->xact_ssn(uint32) or stmt->xact_ssn(uint32) for not temp table */
        rd_new.ssn = (uint32)cursor->ssn;
        rd_new.xid = session->rm->xid;
        rd_new.undo_rid = undo_page_info->undo_rid;

        if (cursor->nologging_type != SESSION_LEVEL) {
            pcrh_gener_itl_undo(session, cursor, page, *itl, &undo);
            tx_init_pcr_itl(session, *itl, &rd_new.undo_rid, rd_new.xid, rd_new.ssn);
            if (need_redo && cursor->logging) {
                log_put(session, RD_PCRH_NEW_ITL, &rd_new, sizeof(rd_pcrh_new_itl_t), LOG_ENTRY_FLAG_NONE);
            }
        } else {
            rd_reuse.undo_rid = g_invalid_undo_rowid;
            tx_init_pcr_itl(session, *itl, &rd_reuse.undo_rid, rd_new.xid, rd_new.ssn);
        }
    } else {
        pcrh_reuse_itl(session, page, *itl, session->itl_id);

        rd_reuse.ssn = (uint32)cursor->ssn;
        rd_reuse.xid = session->rm->xid;
        rd_reuse.undo_rid = undo_page_info->undo_rid;
        rd_reuse.itl_id = session->itl_id;

        if (cursor->nologging_type != SESSION_LEVEL) {
            pcrh_gener_itl_undo(session, cursor, page, *itl, &undo);
            tx_init_pcr_itl(session, *itl, &rd_reuse.undo_rid, rd_reuse.xid, rd_reuse.ssn);
            if (need_redo && cursor->logging) {
                log_put(session, RD_PCRH_REUSE_ITL, &rd_reuse, sizeof(rd_pcrh_reuse_itl_t), LOG_ENTRY_FLAG_NONE);
            }
        } else {
            rd_reuse.undo_rid = g_invalid_undo_rowid;
            tx_init_pcr_itl(session, *itl, &rd_reuse.undo_rid, rd_reuse.xid, rd_reuse.ssn);
        }
    }

    *changed = CT_TRUE;
}

static status_t pcrh_fetch_reusable_itl(knl_session_t *session, knl_cursor_t *cursor, heap_page_t *page,
                                      pcr_itl_t **itl, bool32 *changed)
{
    heap_t *heap = CURSOR_HEAP(cursor);
    pcr_itl_t *item = NULL;
    txn_info_t txn_info;
    uint8 i, owner_list;
    rd_pcrh_clean_itl_t rd_clean;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);

    session->change_list = 0;

    for (i = 0; i < page->itls; i++) {
        item = pcrh_get_itl(page, i);
        if (item->xid.value == session->rm->xid.value) {
            knl_panic_log(item->is_active || DB_NOT_READY(session),
                          "current itl is inactive, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                          cursor->rowid.page, page->head.type, ((table_t *)cursor->table)->desc.name);
            session->itl_id = i;  // itl already exists
            *itl = item;

            if (item->ssn != cursor->ssn) {
                /* new statement, reset all changed rows in page */
                pcrh_reset_self_changed(session, page, i);
                if (cursor->logging && need_redo) {
                    log_put(session, RD_PCRH_RESET_SELF_CHANGE, &i, sizeof(uint8), LOG_ENTRY_FLAG_NONE);
                }
            }
            return CT_SUCCESS;
        }

        if (!item->is_active) {
            /* find the oldest itl to reuse */
            if (*itl == NULL || item->scn < (*itl)->scn) {
                session->itl_id = i;
                *itl = item;
            }
            continue;
        }

        tx_get_pcr_itl_info(session, CT_FALSE, item, &txn_info);
        if (txn_info.status != (uint8)XACT_END) {
            continue;
        }

        if (cursor->isolevel == (uint8)ISOLATION_SERIALIZABLE && cursor->query_scn < txn_info.scn) {
            CT_THROW_ERROR(ERR_SERIALIZE_ACCESS);
            return CT_ERROR;
        }

        rd_clean.itl_id = i;
        rd_clean.scn = txn_info.scn;
        rd_clean.is_owscn = (uint8)txn_info.is_owscn;
        rd_clean.is_fast = 1;
        rd_clean.aligned = 0;
        pcrh_clean_itl(session, page, &rd_clean);
        if (cursor->logging && need_redo) {
            log_put(session, RD_PCRH_CLEAN_ITL, &rd_clean, sizeof(rd_pcrh_clean_itl_t), LOG_ENTRY_FLAG_NONE);
        }
        *changed = CT_TRUE;

        if (*itl == NULL || item->scn < (*itl)->scn) {
            session->itl_id = i;
            *itl = item;
        }

        owner_list = heap_get_owner_list(session, (heap_segment_t *)heap->segment, page->free_size);
        session->change_list = owner_list - (uint8)page->map.list_id;
    }

    return CT_SUCCESS;
}

/*
 * reuse an oldest itl or alloc a new itl for caller.
 * caller should reserved enough undo space for undo itl
 */
status_t pcrh_alloc_itl(knl_session_t *session, knl_cursor_t *cursor, heap_page_t *page,
                        pcr_itl_t **itl, bool32 *changed)
{
    *changed = CT_FALSE;
    *itl = NULL;
    session->itl_id = CT_INVALID_ID8;

    if (pcrh_fetch_reusable_itl(session, cursor, page, itl, changed) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (*itl != NULL && (*itl)->xid.value == session->rm->xid.value) {
        return CT_SUCCESS;
    }

    pcrh_initialize_itl(session, cursor, page, itl, changed);

    if (session->itl_id == CT_INVALID_ID8) {
        return CT_SUCCESS;
    }

    if (DB_NOT_READY(session)) {
        (*itl)->is_active = 0;
        return CT_SUCCESS;
    }

    knl_panic_log(!DB_IS_READONLY(session), "current DB is readonly, panic info: page %u-%u type %u table %s",
                  cursor->rowid.file, cursor->rowid.page, page->head.type, ((table_t *)cursor->table)->desc.name);

    knl_part_locate_t part_loc;
    if (IS_PART_TABLE(cursor->table)) {
        part_loc.part_no = cursor->part_loc.part_no;
        part_loc.subpart_no = cursor->part_loc.subpart_no;
    } else {
        part_loc.part_no = CT_INVALID_ID24;
        part_loc.subpart_no = CT_INVALID_ID32;
    }

    if (lock_itl(session, *AS_PAGID_PTR(page->head.id), session->itl_id, part_loc,
                 g_invalid_pagid, LOCK_TYPE_PCR_RX) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/*
 * PCR enter insert page
 * @note find a heap page from map tree to insert the specified row
 * We lazy init the page itl here if it's a new page.
 * @attention caller should reserved enough undo for alloc itl.
 * @param kernel session kernel cursor, row cost size, page_id(output)
 */
status_t pcrh_enter_ins_page(knl_session_t *session, knl_cursor_t *cursor, row_head_t *row, page_id_t *page_id)
{
    heap_t *heap;
    heap_segment_t *segment;
    pcr_itl_t *itl = NULL;
    heap_page_t *page = NULL;
    bool32 appendonly;
    bool32 use_cached;
    uint8 owner_list;
    uint32 maxtrans;
    bool32 changed = CT_FALSE;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);
    bool32 degrade_mid = CT_FALSE;
    uint8 mid;
    uint32 cost_size;

    uint8 tx_fpl_next = session->tx_fpl.index; // transaction free page list
    uint8 tx_fpl_count = session->tx_fpl.count;
    int32 tx_fpl_index = -1;
    pcr_itl_t *tx_fpl_itl = NULL;

    use_cached = CT_TRUE;
    heap = CURSOR_HEAP(cursor);
    segment = HEAP_SEGMENT(session, heap->entry, heap->segment);
    appendonly = heap_use_appendonly(session, cursor, segment);

    cost_size = pcrh_calc_insert_cost(session, segment, row->size);
    // list id range is [0, HEAP_FREE_LIST_COUNT-1(5)]
    mid = (uint8)heap_get_target_list(session, segment, cost_size);

    for (;;) {
        if (appendonly) {
            if (heap_find_appendonly_page(session, heap, cursor->part_loc, cost_size, page_id) != CT_SUCCESS) {
                knl_end_itl_waits(session);
                CT_THROW_ERROR(ERR_FIND_FREE_SPACE, cost_size);
                return CT_ERROR;
            }
        } else {
            tx_fpl_index = heap_find_tx_free_page_index(session, heap, &tx_fpl_next, &tx_fpl_count);
            if (tx_fpl_index >= 0) {
                // has transaction free page
                *page_id = session->tx_fpl.pages[tx_fpl_index].page_id;
            } else if (heap_find_free_page(session, heap, cursor->part_loc, mid, use_cached,
                                           page_id, &degrade_mid) != CT_SUCCESS) {
                knl_end_itl_waits(session);
                CT_THROW_ERROR(ERR_FIND_FREE_SPACE, cost_size);
                return CT_ERROR;
            }
        }

        log_atomic_op_begin(session);
        log_set_group_nolog_insert(session, cursor->logging);
        if (buf_read_page(session, *page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL) != CT_SUCCESS) {
            log_atomic_op_end(session);
            knl_end_itl_waits(session);
            return CT_ERROR;
        }
        page = (heap_page_t *)CURR_PAGE(session);
        if (PAGE_IS_SOFT_DAMAGE((page_head_t*)page)) {
            buf_leave_page(session, CT_FALSE);
            log_atomic_op_end(session);
            knl_end_itl_waits(session);
            CT_THROW_ERROR(ERR_PAGE_SOFT_DAMAGED, page_id->file, page_id->page);
            return CT_ERROR;
        }

        /* if the page is not heap page, we should skip it and try again */
        if (page->head.type != PAGE_TYPE_PCRH_DATA) {
            buf_leave_page(session, CT_FALSE);
            log_atomic_op_end(session);
            heap_remove_cached_page(session, appendonly);
            use_cached = CT_FALSE;
            continue;
        }

        knl_panic_log(page->oid == segment->oid && page->uid == segment->uid && page->org_scn == segment->org_scn &&
                      page->seg_scn == segment->seg_scn, "the oid/uid/org_scn/seg_scn of page and segment are not "
                      "equal, panic info: page %u-%u type %u table %s page_oid %u seg_oid %u page_uid %u seg_uid %u",
                      cursor->rowid.file, cursor->rowid.page, page->head.type, ((table_t *)cursor->table)->desc.name,
                      page->oid, segment->oid, page->uid, segment->uid);

        tx_fpl_itl = NULL;
        if (tx_fpl_index >= 0) {
            uint8 itl_id = session->tx_fpl.pages[tx_fpl_index].itl_id;
            tx_fpl_itl = pcrh_get_itl(page, itl_id);
        }

        if (tx_fpl_index >= 0 && tx_fpl_itl != NULL &&
            page->free_size + tx_fpl_itl->fsc > cost_size && // ensure PCTFREE
            page->free_size >= row->size + sizeof(pcr_itl_t) + sizeof(pcr_row_dir_t)) {
            // Page in transaction free page list has enough space
            // We can use this page to insert
        } else if (page->free_size < cost_size &&
            !(page->rows == 0 && page->free_size >= row->size + sizeof(pcr_itl_t) + sizeof(pcr_row_dir_t))) {
            owner_list = heap_get_owner_list(session, segment, page->free_size);
            session->change_list = owner_list - (uint8)page->map.list_id;
            buf_leave_page(session, CT_FALSE);
            log_atomic_op_end(session);
            if (degrade_mid && (owner_list == mid - 1)) {
                heap_degrade_change_map(session, heap, *page_id, owner_list - 1);
            } else {
                heap_try_change_map(session, heap, *page_id);
            }

            heap_remove_cached_page(session, appendonly);
            use_cached = CT_FALSE;
            continue;
        }

        if (cursor->isolevel == (uint8)ISOLATION_SERIALIZABLE && cursor->query_scn < page->scn) {
            buf_leave_page(session, CT_FALSE);
            log_atomic_op_end(session);
            knl_end_itl_waits(session);
            CT_THROW_ERROR(ERR_SERIALIZE_ACCESS);
            return CT_ERROR;
        }

        if (page->itls == 0) {
            maxtrans = (page->free_size - cost_size) / sizeof(pcr_itl_t);
            page->itls = (maxtrans < segment->initrans) ? maxtrans : segment->initrans;
            /*
             * free_size is larger than page->itls * sizeof(pcr_itl_t) in empty page,
             * free_end larger than free_size
             */
            page->free_end -= page->itls * sizeof(pcr_itl_t);
            page->free_size -= page->itls * sizeof(pcr_itl_t);
            if (need_redo && cursor->logging) {
                log_put(session, RD_PCRH_INIT_ITLS, &page->itls, sizeof(uint32), LOG_ENTRY_FLAG_NONE);
            }
        }

        if (pcrh_alloc_itl(session, cursor, page, &itl, &changed) != CT_SUCCESS) {
            buf_leave_page(session, changed);
            log_atomic_op_end(session);
            knl_end_itl_waits(session);
            heap_try_change_map(session, heap, *page_id);
            return CT_ERROR;
        }

        if (itl == NULL) {
            session->wpid = AS_PAGID(page->head.id);
            buf_leave_page(session, CT_FALSE);
            log_atomic_op_end(session);

            if (knl_begin_itl_waits(session, &heap->stat.itl_waits) != CT_SUCCESS) {
                knl_end_itl_waits(session);
                return CT_ERROR;
            }
            use_cached = CT_FALSE;
            continue;
        }

        knl_end_itl_waits(session);
        return CT_SUCCESS;
    }
}

/*
 * PCR heap validate page
 * @param kernel session, page
 */
void pcrh_validate_page(knl_session_t *session, page_head_t *page_head)
{
    space_t *space = SPACE_GET(session, DATAFILE_GET(session, AS_PAGID_PTR(page_head->id)->file)->space_id);
    uint32 total_fsc = 0;

    heap_page_t *copy_page = (heap_page_t *)cm_push(session->stack, DEFAULT_PAGE_SIZE(session));
    errno_t ret = memcpy_sp(copy_page, DEFAULT_PAGE_SIZE(session), page_head, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);

    for (uint8 j = 0; j < copy_page->itls; j++) {
        pcr_itl_t *itl = pcrh_get_itl(copy_page, j);
        if (itl->is_active) {
            knl_panic_log(itl->xid.value != CT_INVALID_ID64,
                          "itl's xid is invalid, panic info: copy_page %u-%u type %u, page %u-%u type %u",
                          AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page, copy_page->head.type,
                          AS_PAGID(page_head->id).file, AS_PAGID(page_head->id).page, page_head->type);
            /* the sum of itl's fsc is less than page size(8192) */
            total_fsc += itl->fsc;
        }
    }

    for (uint16 i = 0; i < copy_page->dirs; i++) {
        pcr_row_dir_t *dir = pcrh_get_dir(copy_page, i);
        if (PCRH_DIR_IS_FREE(dir)) {
            continue;
        }
        knl_panic_log(*dir < copy_page->free_begin, "Position of dir is wrong, panic info: copy_page %u-%u "
            "type %u free_begin %u, page %u-%u type %u dir's position %u", AS_PAGID(copy_page->head.id).file,
            AS_PAGID(copy_page->head.id).page, copy_page->head.type, copy_page->free_begin, AS_PAGID(page_head->id).file,
            AS_PAGID(page_head->id).page, page_head->type, *dir);
        knl_panic_log(*dir >= sizeof(heap_page_t) + space->ctrl->cipher_reserve_size, "Position of dir is wrong, "
            "panic info: copy_page %u-%u type %u, page %u-%u type %u dir's position %u cipher_reserve_size %u",
            AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page, copy_page->head.type,
            AS_PAGID(page_head->id).file, AS_PAGID(page_head->id).page, page_head->type, *dir, space->ctrl->cipher_reserve_size);
        row_head_t *row = PCRH_GET_ROW(copy_page, dir);
        uint8 itl_id = ROW_ITL_ID(row);
        knl_panic_log(itl_id == CT_INVALID_ID8 || itl_id < copy_page->itls, "itl_id is abnormal, panic info: "
                      "copy_page itls %u copy_page %u-%u type %u, page %u-%u type %u itl_id %u",
                      copy_page->itls, AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page,
                      copy_page->head.type, AS_PAGID(page_head->id).file, AS_PAGID(page_head->id).page, page_head->type, itl_id);
    }

    pcrh_compact_page(session, copy_page);
    knl_panic_log(copy_page->free_begin + copy_page->free_size + total_fsc == copy_page->free_end,
                  "copy_page is abnormal, panic info: copy_page %u-%u type %u free_begin %u free_size %u free_end %u "
                  "total_fsc %u, page %u-%u type %u", copy_page->free_begin, copy_page->free_size, copy_page->free_end,
                  total_fsc, AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page,
                  copy_page->head.type, AS_PAGID(page_head->id).file, AS_PAGID(page_head->id).page, page_head->type);
    cm_pop(session->stack);
}

/*
 * PCR dump page information
 * @param kernel session, page
 */
status_t pcrh_dump_page(knl_session_t *session, page_head_t *head, cm_dump_t *dump)
{
    heap_page_t *page = (heap_page_t *)head;

    cm_dump(dump, "heap page information\n");

    cm_dump(dump, "\tmap index info: map %u-%u, lid %u, &lenth %u\n",
        (uint32)page->map.file, (uint32)page->map.page, (uint32)page->map.list_id, (uint32)page->map.slot);
    cm_dump(dump, "\ttable info: uid %u, oid %u, org_scn %llu, seg_scn %llu\n",
        page->uid, page->oid, page->org_scn, page->seg_scn);
    cm_dump(dump, "\tpage info: next_page %u-%u, free_begin %u, free_end %u, free_size %u, first_free_dir %u ",
        AS_PAGID_PTR(page->next)->file, AS_PAGID_PTR(page->next)->page, page->free_begin,
        page->free_end, page->free_size, page->first_free_dir);
    cm_dump(dump, "itls %u, dirs %u, rows %u\n", page->itls, page->dirs, page->rows);

    cm_dump(dump, "itl information on this page\n");

    CM_DUMP_WRITE_FILE(dump);
    pcr_itl_t *itl = NULL;
    for (uint8 slot_itl = 0; slot_itl < page->itls; slot_itl++) {
        itl = pcrh_get_itl(page, slot_itl);

        cm_dump(dump, "\tslot: #%-3u", slot_itl);
        cm_dump(dump, "\tscn: %llu", itl->scn);
        cm_dump(dump, "\txmap: %u-%u", itl->xid.xmap.seg_id, itl->xid.xmap.slot);
        cm_dump(dump, "\txnum: %u", itl->xid.xnum);
        cm_dump(dump, "\tfsc: %u", itl->fsc);
        cm_dump(dump, "\tis_active: %u", itl->is_active);
        cm_dump(dump, "\tis_owscn: %u\n", itl->is_owscn);
        cm_dump(dump, "\tis_hist: %u\n", itl->is_hist);
        cm_dump(dump, "\tis_fast: %u\n", itl->is_fast);

        CM_DUMP_WRITE_FILE(dump);
    }

    cm_dump(dump, "row information on this page\n");
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    for (uint16 slot_dir = 0; slot_dir < page->dirs; slot_dir++) {
        dir = pcrh_get_dir(page, slot_dir);
        cm_dump(dump, "\tslot: #%-3u", slot_dir);
        cm_dump(dump, "\toffset: %-5u", dir);

        if (PCRH_DIR_IS_FREE(dir)) {
            cm_dump(dump, "\t(free_dir)\n");
            CM_DUMP_WRITE_FILE(dump);
            continue;
        }

        row = PCRH_GET_ROW(page, dir);
        cm_dump(dump, "\tsize: %u", row->size);
        cm_dump(dump, "\tcols: %u", ROW_COLUMN_COUNT(row));
        cm_dump(dump, "\titl_id: %u", ROW_ITL_ID(row));
        cm_dump(dump, "\tdeleted/link/migr/self_chg/changed %u/%u/%u/%u/%u\n",
            row->is_deleted, row->is_link, row->is_migr, row->self_chg, row->is_changed);

        CM_DUMP_WRITE_FILE(dump);
    }
    return CT_SUCCESS;
}

