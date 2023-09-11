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
 * dtc_heap.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_heap.c
 *
 * -------------------------------------------------------------------------
 */
#include "dtc_heap.h"
#include "pcr_heap.h"
#include "pcr_heap_scan.h"
#include "pcr_heap_undo.h"
#include "knl_context.h"
#include "dtc_context.h"
#include "pcr_pool.h"
#include "dtc_buffer.h"
#include "dtc_drc.h"
#include "dtc_dcs.h"
#include "knl_tran.h"


static status_t dtc_heap_construct_cr_page(knl_session_t *session, cr_cursor_t *cursor, heap_page_t *page, bool8 *fb_buf)
{
    uint8 inst_id;

    for (;;) {
        if (pcrh_fetch_invisible_itl(session, cursor, page) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (cursor->itl == NULL || cursor->wxid.value != GS_INVALID_ID64) {
            return GS_SUCCESS;
        }

        inst_id = xid_get_inst_id(session, cursor->itl->xid);
        if (inst_id == session->kernel->id || cursor->local_cr) {
            if (pcrh_reorganize_with_ud_list(session, cursor, page, fb_buf) != GS_SUCCESS) {
                return GS_ERROR;
            }
        } else {
            if (dcs_heap_request_cr_page(session, cursor, (char *)page, inst_id) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (cursor->itl == NULL || cursor->wxid.value != GS_INVALID_ID64) {
                return GS_SUCCESS;
            }
        }
    }
}

status_t dtc_heap_check_current_visible(knl_session_t *session, cr_cursor_t *cursor,
                                        heap_page_t *page, bool32 *is_found)
{
    uint8 inst_id;

    if (g_dtc->profile.enable_rmo_cr) {
        /* in RMO mode, we force to check current visible in local */
        cursor->local_cr = GS_TRUE;
    }

    for (;;) {
        if (pcrh_fetch_invisible_itl(session, cursor, page) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (cursor->itl == NULL) {
            return GS_SUCCESS;
        }

        inst_id = xid_get_inst_id(session, cursor->itl->xid);
        if (inst_id == session->kernel->id || cursor->local_cr) {
            if (pcrh_chk_visible_with_undo_ss(session, cursor, page, GS_FALSE, is_found) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (!*is_found) {
                return GS_SUCCESS;
            }
        } else {
            if (dcs_check_current_visible(session, cursor, (char *)page, inst_id, is_found) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (cursor->itl == NULL || !*is_found) {
                return GS_SUCCESS;
            }
        }
    }
}

static status_t dtc_heap_read_prefetch_page(knl_session_t *session, knl_cursor_t *cursor, cr_cursor_t *cr_cursor,
                                            page_id_t page_id, pcr_status_t *status)
{
    buf_read_assist_t ra;
    uint8 options = ((cr_cursor->local_cr || *status == PCR_LOCAL_READ) ? ENTER_PAGE_NORMAL : ENTER_PAGE_TRY);

    dtc_read_init(&ra, page_id, LATCH_MODE_S, options, cr_cursor->query_scn, DTC_BUF_PREFETCH_EXT_NUM);
    if (dtc_read_page(session, &ra) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (session->curr_page == NULL) {
        // no page available in local data buffer in try mode, check from master
        *status = PCR_CHECK_MASTER;
        return GS_SUCCESS;
    }

    if (!heap_check_page(session, cursor, (heap_page_t *)CURR_PAGE(session), PAGE_TYPE_PCRH_DATA)) {
        buf_leave_page(session, GS_FALSE);
        HEAP_CHECKPAGE_ERROR(cursor);
        return GS_ERROR;
    }

    *status = PCR_READ_PAGE;
    return GS_SUCCESS;
}

status_t dtc_heap_enter_prefetch_page(knl_session_t *session, knl_cursor_t *cursor, cr_cursor_t *cr_cursor,
                                      char *page_buf, pcr_status_t *status)
{
    page_id_t page_id = GET_ROWID_PAGE(cursor->rowid);
    uint8 dst_id;

    *status = PCR_TRY_READ;

    for (;;) {
        if (*status == PCR_TRY_READ || *status == PCR_LOCAL_READ) {
            // read page from local data buffer, if page not exist in try mode, check master
            if (dtc_heap_read_prefetch_page(session, cursor, cr_cursor, page_id, status) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (*status == PCR_READ_PAGE) {
                return GS_SUCCESS;
            }
        }

        if (dcs_pcr_check_master(session, page_id, CR_TYPE_HEAP, &dst_id, status) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (*status == PCR_LOCAL_READ) {
            continue;
        }

        if (*status == PCR_REQUEST_MASTER) {
            // request master to notify owner to start CR page construct
            if (dcs_pcr_request_master(session, cr_cursor, page_buf, dst_id, CR_TYPE_HEAP, status) != GS_SUCCESS) {
                return GS_ERROR;
            }
        } else {
            // request owner to start CR page construct
            if (dcs_pcr_request_owner(session, cr_cursor, page_buf, dst_id, CR_TYPE_HEAP, status) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
        session->stat->dcs_cr_reads++;

        if (*status == PCR_CONSTRUCT || *status == PCR_PAGE_VISIBLE) {
            session->stat->dcs_cr_gets++;
            return GS_SUCCESS;
        }

        if (cr_cursor->wxid.value != GS_INVALID_ID64) {
            if (pcrh_wait_for_txn(session, cursor, cr_cursor) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }
}

status_t dtc_heap_prefetch_cr_page(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn,
                                   char *page_buf, bool8 *fb_buf)
{
    page_id_t page_id;
    cr_cursor_t cr_cursor;
    errno_t ret;
    pcr_status_t status;

    page_id = GET_ROWID_PAGE(cursor->rowid);

    for (;;) {
        pcrh_initialize_cr_cursor(&cr_cursor, cursor, cursor->rowid, query_scn);
        if (fb_buf != NULL) {
            /* for flashback, we force to do local consistent read */
            cr_cursor.local_cr = GS_TRUE;
        }

        if (dtc_heap_enter_prefetch_page(session, cursor, &cr_cursor, page_buf, &status) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (status == PCR_READ_PAGE) {
            ret = memcpy_sp(page_buf, DEFAULT_PAGE_SIZE(session), session->curr_page, DEFAULT_PAGE_SIZE(session));
            knl_securec_check(ret);
            buf_leave_page(session, GS_FALSE);
        }

        if (status != PCR_PAGE_VISIBLE) {
            if (g_dtc->profile.enable_rmo_cr) {
                /* in RMO mode, we force to do local consistent read */
                cr_cursor.local_cr = GS_TRUE;
            }

            if (dtc_heap_construct_cr_page(session, &cr_cursor, (heap_page_t *)page_buf, fb_buf) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (cr_cursor.wxid.value != GS_INVALID_ID64) {
                if (pcrh_wait_for_txn(session, cursor, &cr_cursor) != GS_SUCCESS) {
                    return GS_ERROR;
                }
                continue;
            }
        }

        cursor->ssi_conflict = cr_cursor.ssi_conflict;
        cursor->cleanout = cr_cursor.cleanout;

        if (knl_cursor_ssi_conflict(cursor, GS_FALSE) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (cursor->global_cached) {
            pcrp_alloc_page(session, page_id, query_scn, (uint32)cursor->ssn);
            ret = memcpy_sp(CURR_CR_PAGE(session), DEFAULT_PAGE_SIZE(session), page_buf, DEFAULT_PAGE_SIZE(session));
            knl_securec_check(ret);
            pcrp_leave_page(session, GS_FALSE);
        }

        return GS_SUCCESS;
    }
}

static status_t dtc_heap_read_page(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn, page_id_t page_id,
                                   pcr_status_t *status)
{
    buf_read_assist_t ra;
    uint8 options = (*status == PCR_LOCAL_READ ? ENTER_PAGE_NORMAL : ENTER_PAGE_TRY);

    dtc_read_init(&ra, page_id, LATCH_MODE_S, options, query_scn, DTC_BUF_READ_ONE);
    if (dtc_read_page(session, &ra) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (session->curr_page == NULL) {
        // no page available in local data buffer, check from master
        *status = PCR_CHECK_MASTER;
        return GS_SUCCESS;
    }

    if (!heap_check_page(session, cursor, (heap_page_t *)CURR_PAGE(session), PAGE_TYPE_PCRH_DATA)) {
        buf_leave_page(session, GS_FALSE);
        HEAP_CHECKPAGE_ERROR(cursor);
        return GS_ERROR;
    }

    *status = PCR_READ_PAGE;
    return GS_SUCCESS;
}

status_t dtc_heap_enter_page(knl_session_t *session, knl_cursor_t *cursor, cr_cursor_t *cr_cursor, pcr_status_t *status)
{
    page_id_t page_id = GET_ROWID_PAGE(cr_cursor->rowid);
    heap_page_t *page = NULL;
    uint8 dst_id;
    bool32 use_cr_pool = GS_TRUE;

    *status = PCR_TRY_READ;

    for (;;) {
        if (*status == PCR_TRY_READ || *status == PCR_LOCAL_READ) {
            // read page from local data buffer, if page not exist in try mode, check master
            if (dtc_heap_read_page(session, cursor, cr_cursor->query_scn, page_id, status) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (*status == PCR_READ_PAGE) {
                return GS_SUCCESS;
            }
        }

        if (use_cr_pool) {
            // before we request master for page, check local CR pool
            pcrp_enter_page(session, page_id, cr_cursor->query_scn, cr_cursor->ssn);
            page = (heap_page_t *)CURR_CR_PAGE(session);
            if (page != NULL) {
                if (heap_check_page(session, cursor, page, PAGE_TYPE_PCRH_DATA)) {
                    *status = PCR_PAGE_VISIBLE;
                    return GS_SUCCESS;
                }
                pcrp_leave_page(session, GS_TRUE);
            }
            use_cr_pool = GS_FALSE;
        }

        if (dcs_pcr_check_master(session, page_id, CR_TYPE_HEAP, &dst_id, status) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (*status == PCR_LOCAL_READ) {
            continue;
        }

        pcrp_alloc_page(session, page_id, cr_cursor->query_scn, cr_cursor->ssn);
        page = (heap_page_t *)CURR_CR_PAGE(session);

        session->stat->dcs_cr_reads++;
        if (*status == PCR_REQUEST_MASTER) {
            // request master to notify owner to start CR page construct
            if (dcs_pcr_request_master(session, cr_cursor, (char *)page, dst_id, CR_TYPE_HEAP, status) != GS_SUCCESS) {
                pcrp_leave_page(session, GS_TRUE);
                return GS_ERROR;
            }
        } else {
            // request owner to start CR page construct
            if (dcs_pcr_request_owner(session, cr_cursor, (char *)page, dst_id, CR_TYPE_HEAP, status) != GS_SUCCESS) {
                pcrp_leave_page(session, GS_TRUE);
                return GS_ERROR;
            }
        }

        if (*status == PCR_CONSTRUCT || *status == PCR_PAGE_VISIBLE) {
            session->stat->dcs_cr_gets++;
            return GS_SUCCESS;
        }

        pcrp_leave_page(session, GS_TRUE);

        if (cr_cursor->wxid.value != GS_INVALID_ID64) {
            if (pcrh_wait_for_txn(session, cursor, cr_cursor) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }
}

status_t dtc_heap_enter_cr_page(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn, rowid_t rowid)
{
    page_id_t page_id;
    cr_cursor_t cr_cursor;
    heap_page_t *page = NULL;
    errno_t ret;
    pcr_status_t status;

    page_id = GET_ROWID_PAGE(rowid);

    for (;;) {
        pcrh_initialize_cr_cursor(&cr_cursor, cursor, rowid, query_scn);

        if (dtc_heap_enter_page(session, cursor, &cr_cursor, &status) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (status == PCR_READ_PAGE) {
            page = (heap_page_t *)CURR_PAGE(session);
            if (pcrh_chk_r_visible(session, cursor, query_scn, page, (uint16)rowid.slot)) {
                cursor->page_cache = NO_PAGE_CACHE;
                return GS_SUCCESS;
            }

            pcrp_enter_page(session, page_id, query_scn, (uint32)cursor->ssn);
            page = (heap_page_t *)CURR_CR_PAGE(session);
            if (page != NULL) {
                if (heap_check_page(session, cursor, page, PAGE_TYPE_PCRH_DATA)) {
                    buf_leave_page(session, GS_FALSE);
                    cursor->page_cache = GLOBAL_PAGE_CACHE;
                    return GS_SUCCESS;
                }
            } else {
                pcrp_alloc_page(session, page_id, query_scn, (uint32)cursor->ssn);
                page = (heap_page_t *)CURR_CR_PAGE(session);
            }

            ret = memcpy_sp((char *)page, DEFAULT_PAGE_SIZE(session), CURR_PAGE(session), DEFAULT_PAGE_SIZE(session));
            knl_securec_check(ret);
            buf_leave_page(session, GS_FALSE);
        }

        if (status != PCR_PAGE_VISIBLE) {
            if (g_dtc->profile.enable_rmo_cr) {
                /* in RMO mode, we do local CR consistent read */
                cr_cursor.local_cr = GS_TRUE;
            }

            page = (heap_page_t *)CURR_CR_PAGE(session);
            if (dtc_heap_construct_cr_page(session, &cr_cursor, page, NULL) != GS_SUCCESS) {
                pcrp_leave_page(session, GS_TRUE);
                return GS_ERROR;
            }

            if (cr_cursor.wxid.value != GS_INVALID_ID64) {
                pcrp_leave_page(session, GS_TRUE);
                if (pcrh_wait_for_txn(session, cursor, &cr_cursor) != GS_SUCCESS) {
                    return GS_ERROR;
                }
                continue;
            }
        }

        cursor->ssi_conflict = cr_cursor.ssi_conflict;
        if (knl_cursor_ssi_conflict(cursor, GS_FALSE) != GS_SUCCESS) {
            pcrp_leave_page(session, GS_FALSE);
            return GS_ERROR;
        }

        cursor->page_cache = GLOBAL_PAGE_CACHE;
        return GS_SUCCESS;
    }
}
