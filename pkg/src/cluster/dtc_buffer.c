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
 * dtc_buffer.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_buffer.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_cluster_module.h"
#include <knl_buffer.h>
#include "dtc_buffer.h"
#include "dtc_drc.h"
#include "dtc_dcs.h"
#include "dtc_context.h"
#include "dtc_trace.h"
#include "knl_datafile.h"
#include "knl_buflatch.h"

static inline bool32 dtc_buf_prepare_ctrl(knl_session_t *session, buf_read_assist_t *ra, buf_ctrl_t **ctrl)
{
    *ctrl = buf_alloc_ctrl(session, ra->page_id, ra->mode, ra->options);
    if (SECUREC_UNLIKELY(*ctrl == NULL)) {
        knl_panic(ra->options & ENTER_PAGE_TRY);
        session->curr_page = NULL;
        session->curr_page_ctrl = NULL;
        return CT_FALSE;
    }
    return CT_TRUE;
}

static inline bool32 dtc_buf_try_local(knl_session_t *session, buf_read_assist_t *ra, buf_ctrl_t *ctrl)
{
    return dcs_local_page_usable(session, ctrl, ra->mode);
}

static inline bool32 dtc_buf_try_edp(knl_session_t *session, buf_read_assist_t *ra, buf_ctrl_t *ctrl)
{
    if (ra->try_edp) {
        if (ctrl->is_edp && ra->query_scn <= ctrl->edp_scn) {
            DTC_DCS_DEBUG_INF(
                "dtc_buf_try_edp, [%u-%llu], query_scn:%llu, edp_scn:%llu, load_status:%d, lock_mode:%d, pcn:%u, lsn:%llu",
                (uint32)ctrl->page_id.file, (uint64)ctrl->page_id.page, ra->query_scn, ctrl->edp_scn, ctrl->load_status,
                ctrl->lock_mode, ctrl->page->pcn, ctrl->page->lsn);
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

static inline bool32 dtc_buf_give_up_try(knl_session_t *session, buf_read_assist_t *ra, buf_ctrl_t *ctrl)
{
    if ((ra->options & ENTER_PAGE_TRY) && !ctrl->force_request) {
        if (ctrl->load_status == (uint8)BUF_NEED_LOAD) {
            ctrl->load_status = (uint8)BUF_LOAD_FAILED;
        }
        buf_unlatch(session, ctrl, CT_TRUE);
        session->curr_page = NULL;
        session->curr_page_ctrl = NULL;
        return CT_TRUE;
    }
    return CT_FALSE;
}

static inline bool32 dtc_buf_try_remote(knl_session_t *session, buf_read_assist_t *ra, buf_ctrl_t *ctrl)
{
    drc_lock_mode_e req_mode = (ra->mode == LATCH_MODE_S ? DRC_LOCK_SHARE : DRC_LOCK_EXCLUSIVE);
    ctrl->transfer_status = BUF_TRANS_TRY_REMOTE;

    if (dcs_request_page(session, ctrl, ra->page_id, req_mode) == CT_SUCCESS) {
        ctrl->transfer_status = BUF_TRANS_NONE;
        return CT_TRUE;
    }

    ctrl->transfer_status = BUF_TRANS_NONE;
    if (ctrl->load_status != BUF_IS_LOADED) {
        ctrl->load_status = (uint8)BUF_LOAD_FAILED;
    }
    buf_unlatch(session, ctrl, CT_TRUE);
    return CT_FALSE;
}

static status_t dtc_buf_try_prefetch(knl_session_t *session, buf_read_assist_t *ra, buf_ctrl_t *ctrl)
{
    if (DTC_BUF_NO_PREFETCH(ra->read_num)) {
        if (buf_load_page(session, ctrl, ra->page_id) != CT_SUCCESS) {
            ctrl->load_status = (uint8)BUF_LOAD_FAILED;
            buf_unlatch(session, ctrl, CT_TRUE);
            return CT_ERROR;
        }
        ctrl->force_request = 0;
        ctrl->load_status = (uint8)BUF_IS_LOADED;
    } else if (DTC_BUF_PREFETCH_EXTENT(ra->read_num)) {
        if (buf_read_prefetch_normal(session, ctrl, ra->page_id, LATCH_MODE_S, ra->options) != CT_SUCCESS) {
            buf_unlatch(session, ctrl, CT_TRUE);
            return CT_ERROR;
        }
    } else {
        // may be not at extent boundary
        if (buf_read_prefetch_num_normal(session, ctrl, ra->page_id, ra->read_num, LATCH_MODE_S, ra->options) !=
            CT_SUCCESS) {
            buf_unlatch(session, ctrl, CT_TRUE);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

static status_t dtc_buf_finish(knl_session_t *session, buf_read_assist_t *ra, buf_ctrl_t *ctrl, knl_buf_wait_t *temp_stat)
{
    BUF_UNPROTECT_PAGE(ctrl->page);
    if (ctrl->load_status == (uint8)BUF_NEED_LOAD) {
        bool32 try_load = CT_TRUE;
        if (ra->options & ENTER_PAGE_NO_READ) {
            if (ra->options & ENTER_PAGE_TRY_PREFETCH) {
                ra->read_num = DTC_BUF_PREFETCH_EXT_NUM;
            } else {
                try_load = CT_FALSE;
            }
        }
        if (try_load && dtc_buf_try_prefetch(session, ra, ctrl) != CT_SUCCESS) {
            session->curr_page_ctrl = ctrl;
            CT_LOG_RUN_ERR("[DTC_BNUFFER][%u-%u][dtc buf try prefetch] failed, read num:%u",
                ctrl->page_id.file, ctrl->page_id.page, ra->read_num);
            return CT_ERROR;
        }
        if (ra->options & ENTER_PAGE_NO_READ) {
            ctrl->load_status = (uint8)BUF_IS_LOADED;
            if (SECUREC_UNLIKELY(KNL_GBP_ENABLE(session->kernel))) {
                ctrl->gbp_ctrl->page_status = GBP_PAGE_NOREAD;
            }
        }
    } else {
        if (!buf_check_loaded_page_checksum(session, ctrl, ra->mode, ra->options)) {
            CT_THROW_ERROR(ERR_PAGE_CORRUPTED, ctrl->page_id.file, ctrl->page_id.page);
            buf_unlatch(session, ctrl, CT_TRUE);
            return CT_ERROR;
        }
    }

    knl_panic_log(IS_SAME_PAGID(ra->page_id, ctrl->page_id),
                  "page_id and ctrl's page_id are not same, panic info: page %u-%u ctrl page %u-%u type %u",
                  ra->page_id.file, ra->page_id.page, ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);

    session->curr_page = (char *)ctrl->page;
    session->curr_page_ctrl = ctrl;
    session->stat->buffer_gets++;

    if (SECUREC_UNLIKELY(ctrl->page->type == PAGE_TYPE_UNDO)) {
        session->stat->undo_buf_reads++;
    }

#ifdef __PROTECT_BUF__
    if (mode != LATCH_MODE_X && !ctrl->is_readonly) {
        BUF_PROTECT_PAGE(ctrl->page);
    }
#endif

    //    stats_buf_record(session, &temp_stat, ctrl);
    buf_push_page(session, ctrl, ra->mode);
    buf_log_enter_page(session, ctrl, ra->mode, ra->options);

    if (DTC_BUF_PREFETCH_EXTENT(ra->read_num) && session->kernel->attr.enable_asynch) {
        knl_panic(0);
        if (buf_try_prefetch_next_ext(session, ctrl) != CT_SUCCESS) {
            CT_LOG_RUN_WAR("failed to prefetch next extent file : %u , page: %llu",
                           (uint32)ctrl->page_id.file, (uint64)ctrl->page_id.page);
        }
    }
    return CT_SUCCESS;
}

// unit: ms
#define DCS_LOG_LIMIT_INTERVAL (500)
status_t dtc_read_page(knl_session_t *session, buf_read_assist_t *ra)
{
    buf_ctrl_t *ctrl = NULL;
    knl_buf_wait_t temp_stat;

    stats_buf_init(session, &temp_stat);
    date_t last_time = 0;

    for (;;) {
        if (!dtc_dcs_readable(session)) {
            if (last_time + DCS_LOG_LIMIT_INTERVAL * MICROSECS_PER_MILLISEC <= KNL_NOW(session)) {
                last_time = KNL_NOW(session);
                CT_LOG_DEBUG_ERR("[DCS][%u-%u] dcs not readable, session is hanging.",
                    ra->page_id.file, ra->page_id.page);
            }
            cm_sleep(DCS_RESEND_MSG_INTERVAL);
            continue;
        }

        if (!dtc_buf_prepare_ctrl(session, ra, &ctrl)) {
            return CT_SUCCESS;
        }

        if (dtc_buf_try_local(session, ra, ctrl)) {
            break;
        }

        /*
         * TODO: need to check edp ensure CR.
         */

        if (dtc_buf_give_up_try(session, ra, ctrl)) {
            return CT_SUCCESS;
        }

        if (dtc_buf_try_remote(session, ra, ctrl)) {
            break;
        }
        cm_sleep(DCS_RESEND_MSG_INTERVAL);
    }

    return dtc_buf_finish(session, ra, ctrl, &temp_stat);
}

status_t dtc_get_share_owner_pages(knl_session_t *session, buf_ctrl_t **ctrl_array, buf_ctrl_t *ctrl, uint32 count)
{
    uint32 i;
    uint8 master_id = CT_INVALID_ID8;
    page_id_t *page_ids = (page_id_t *)cm_push(session->stack, sizeof(page_id_t) * count);
    if (NULL == page_ids) {
        CT_LOG_RUN_ERR("[BUFFER] page_ids failed to malloc memory");
        return CT_ERROR;
    }
    uint32 valid_count = 0;

    for (i = 0; i < count; i++) {
        page_ids[i] = INVALID_PAGID;
    }

    /* The ownership of target ctrl has been fetched through dtc_buf_try_remote, here we will prefetch all the left
     * ctrls in the extent. */
    for (i = 0; i < count; i++) {
        if (ctrl_array[i] != NULL && ctrl_array[i] != ctrl) {
            if (master_id == CT_INVALID_ID8) {
                (void)drc_get_page_master_id(ctrl_array[i]->page_id, &master_id);
            }
            uint8 master_id_tmp = CT_INVALID_ID8;
            (void)drc_get_page_master_id(ctrl_array[i]->page_id, &master_id_tmp);
            knl_panic(master_id != CT_INVALID_ID8 && ctrl_array[i]->lock_mode == DRC_LOCK_NULL);
            if (master_id_tmp != master_id) {
                break;  // master has changed
            }
            ctrl_array[i]->transfer_status = BUF_TRANS_TRY_REMOTE;
            page_ids[i] = ctrl_array[i]->page_id;
            valid_count++;
        }
    }

    if (valid_count > 0) {
        (void)dcs_try_get_page_share_owner(session, ctrl_array, page_ids, count, master_id, &valid_count);
    }

    for (i = 0; i < count; i++) {
        if (ctrl_array[i] != NULL && (ctrl_array[i] != ctrl) && (ctrl_array[i]->lock_mode == DRC_LOCK_NULL)) {
            knl_panic(!DB_IS_CLUSTER(session) || (!(ctrl_array[i]->is_edp || ctrl_array[i]->is_dirty) &&
                                                  (ctrl_array[i]->load_status == (uint8)(BUF_NEED_LOAD))));
            ctrl_array[i]->load_status = BUF_LOAD_FAILED;
            buf_unlatch(session, ctrl_array[i], CT_TRUE);
            ctrl_array[i]->transfer_status = BUF_TRANS_NONE;
            ctrl_array[i] = NULL;
        }
    }

    if (valid_count > 0) {
        (void)dcs_claim_page_share_owners(session, page_ids, count, master_id);
    }
    cm_pop(session->stack);
    return CT_SUCCESS;
}

bool32 dtc_dcs_readable(knl_session_t *session)
{
    drc_part_mngr_t *part_mngr = (&g_drc_res_ctx.part_mngr);

    return (part_mngr->remaster_status == REMASTER_DONE &&
            (g_rc_ctx->status >= REFORM_RECOVER_DONE || DAAC_SESSION_IN_RECOVERY(session) ||
             g_rc_ctx->status == REFORM_MOUNTING));
}
