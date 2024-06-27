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
 * dtc_dcs.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_dcs.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_cluster_module.h"
#include "dtc_dcs.h"
#include "cm_defs.h"
#include "cm_thread.h"
#include "knl_context.h"
#include "srv_instance.h"
#include "pcr_heap.h"
#include "pcr_heap_undo.h"
#include "pcr_heap_scan.h"
#include "pcr_btree.h"
#include "pcr_btree_scan.h"
#include "dtc_drc.h"
#include "dtc_database.h"
#include "dtc_tran.h"
#include "dtc_dc.h"
#include "dtc_buffer.h"
#include "dtc_recovery.h"
#include "dtc_trace.h"
#include "dtc_ckpt.h"
#include "rc_reform.h"
#include "dtc_context.h"

bool32 dcs_page_latch_usable[][DRC_LOCK_MODE_MAX] = {
    // DRC_LOCK_NULL,  DRC_LOCK_SHARE, DRC_LOCK_EXCLUSIVE, DRC_LOCK_MODE_MAX
    { CT_FALSE, CT_FALSE, CT_FALSE },  // invalidate latch_mode_t
    { CT_FALSE, CT_TRUE, CT_TRUE },    // read:         LATCH_MODE_S
    { CT_FALSE, CT_FALSE, CT_TRUE },   // write:        LATCH_MODE_X
    { CT_FALSE, CT_TRUE, CT_TRUE },    // force read:   LATCH_MODE_FORCE_S
};
bool32 dcs_local_page_usable(knl_session_t *session, buf_ctrl_t *ctrl, latch_mode_t mode)
{
    return dcs_page_latch_usable[mode][ctrl->lock_mode];
}

status_t dcs_send_data_retry(void *msg)
{
    uint32 retry_time = 0;
    status_t status = CT_SUCCESS;
    SYNC_POINT_GLOBAL_START(CANTIAN_DCS_SEND_EDP_MESSAGE_FAIL, &status, CT_ERROR);
    status = mes_send_data(msg);
    SYNC_POINT_GLOBAL_END;
    while (status != CT_SUCCESS) {
        retry_time++;
        mes_message_head_t *head = (mes_message_head_t *)msg;
        if (head->dst_inst >= CT_MAX_INSTANCES) {
            CT_LOG_RUN_ERR("invalid inst id(%u)", head->dst_inst);
            return CT_ERROR;
        }
        cluster_view_t view;
        rc_get_cluster_view(&view, CT_FALSE);
        if (rc_bitmap64_exist(&view.bitmap, head->dst_inst)) {
            cm_sleep(DCS_RESEND_MSG_INTERVAL);
            SYNC_POINT_GLOBAL_START(CANTIAN_DCS_SEND_EDP_MESSAGE_FAIL, &status, CT_ERROR);
            status = mes_send_data(msg);
            SYNC_POINT_GLOBAL_END;
        } else {
            CT_LOG_RUN_WAR("inst id(%u) is not alive, alive bitmap:%llu", head->dst_inst, view.bitmap);
            return status;
        }
        if (retry_time % DCS_RESEND_MSG_TIMES == 0) {
            CT_LOG_RUN_WAR("send message failed times:%u, alive bitmap:%llu", retry_time, view.bitmap);
        }
    }
    return status;
}

status_t dcs_send_data3_retry(mes_message_head_t *head, uint32 head_size, const void *body)
{
    if (head->dst_inst >= CT_MAX_INSTANCES) {
        CT_LOG_RUN_ERR("invalid inst id(%u)", head->dst_inst);
        return CT_ERROR;
    }
    uint32 retry_time = 0;
    status_t status = CT_SUCCESS;
    status = mes_send_data3(head, head_size, body);
    while (status != CT_SUCCESS) {
        retry_time++;
        cluster_view_t view;
        rc_get_cluster_view(&view, CT_FALSE);
        if (rc_bitmap64_exist(&view.bitmap, head->dst_inst)) {
            cm_sleep(DCS_RESEND_MSG_INTERVAL);
            status = mes_send_data3(head, head_size, body);
        } else {
            CT_LOG_RUN_WAR("inst id(%u) is not alive, alive bitmap:%llu", head->dst_inst, view.bitmap);
            return status;
        }
        if (retry_time % DCS_RESEND_MSG_TIMES == 0) {
            CT_LOG_RUN_WAR("send message failed times:%u, alive bitmap:%llu", retry_time, view.bitmap);
        }
    }
    return status;
}

static inline status_t dcs_claim_ownership_r(knl_session_t *session, uint32 master_id, page_id_t page_id,
                                             bool32 has_edp, drc_lock_mode_e mode, uint64 page_lsn, uint64 req_version)
{
    msg_claim_owner_t request;
    status_t ret;

    mes_init_send_head(&request.head, MES_CMD_CLAIM_OWNER_REQ, sizeof(msg_claim_owner_t), CT_INVALID_ID32,
                       session->kernel->dtc_attr.inst_id, master_id, session->id, CT_INVALID_ID16);
    request.page_id = page_id;
    request.has_edp = has_edp;
    request.mode = mode;
    request.lsn = page_lsn;
    request.req_version = req_version;

    SYNC_POINT_GLOBAL_START(CANTIAN_DCS_CLAIM_OWNER_SEND_FAIL, &ret, CT_ERROR);
    ret = dcs_send_data_retry(&request);
    SYNC_POINT_GLOBAL_END;
    DTC_DCS_DEBUG(ret, "[DCS][%u-%u][%s]: src_id=%u, dest_id=%u, has_edp=%u, req mode=%d, page lsn=%llu", page_id.file,
                  page_id.page, MES_CMD2NAME(request.head.cmd), request.head.src_inst, request.head.dst_inst,
                  request.has_edp, request.mode, page_lsn);
    return ret;
}

static inline status_t dcs_notify_local_owner4page(knl_session_t * session, cvt_info_t *cvt_info)
{
    msg_page_req_t page_req;
    status_t ret;
    mes_init_send_head(&page_req.head, MES_CMD_ASK_OWNER, sizeof(msg_page_req_t), cvt_info->req_rsn, cvt_info->req_id,
                       cvt_info->owner_id, cvt_info->req_sid, CT_INVALID_ID16);
    page_req.page_id = cvt_info->pageid;
    page_req.req_mode = cvt_info->req_mode;
    page_req.curr_mode = cvt_info->curr_mode;
    page_req.req_version = cvt_info->req_version;
    page_req.action = DRC_RES_INVALID_ACTION;
    page_req.lsn = cvt_info->lsn;
    page_req.is_retry = CT_FALSE;

    if (DRC_STOP_DCS_IO_FOR_REFORMING(page_req.req_version, session)) {
        CT_LOG_RUN_ERR("[DCS][%u-%u]: reforming, notify local owner4page failed, req_rsn=%u, "
            "req_version=%llu, cur_version=%llu",
            page_req.page_id.file, page_req.page_id.page,
            cvt_info->req_rsn, page_req.req_version, DRC_GET_CURR_REFORM_VERSION);
        // TODO 4node deal with the cvting
        return CT_ERROR;
    }
    SYNC_POINT_GLOBAL_START(CANTIAN_DCS_NOTIFY_OWNER_SEND_FAIL, &ret, CT_ERROR);
    ret = dcs_send_data_retry(&page_req);
    SYNC_POINT_GLOBAL_END;
    DTC_DCS_DEBUG(ret,
                  "[DCS][%u-%u][%s internal]: status=(%d), src_id=%u, src_sid=%u, "
                  "dest_id=%u, dest_sid=%u, req_mode=%u, curr_mode=%u, copy_insts=%llu",
                  cvt_info->pageid.file, cvt_info->pageid.page, MES_CMD2NAME(page_req.head.cmd), ret,
                  page_req.head.src_inst, page_req.head.src_sid, page_req.head.dst_inst, page_req.head.dst_sid,
                  page_req.req_mode, page_req.curr_mode, cvt_info->readonly_copies);
    SYNC_POINT_GLOBAL_START(CANTIAN_DCS_NOTIFY_OWNER_SUCC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    return ret;
}

extern status_t dcs_try_notify_owner_for_page(knl_session_t *session, cvt_info_t *cvt_info);

status_t dcs_claim_ownership_internal(knl_session_t *session, claim_info_t *claim_info, uint64 req_version)
{
    cvt_info_t cvt_info;
    drc_claim_page_owner(session, claim_info, &cvt_info, req_version);

    DTC_DCS_DEBUG_INF("[DCS][%u-%u][claim owner]: src_id=%u, mode=%u, has_edp=%u, page lsn=%llu",
                      claim_info->page_id.file, claim_info->page_id.page, DCS_SELF_INSTID(session), claim_info->mode,
                      claim_info->has_edp, claim_info->lsn);

    if (cvt_info.req_id == CT_INVALID_ID8) {
        return CT_SUCCESS;
    }

    if (cvt_info.owner_id == DCS_SELF_INSTID(session)) {
        return dcs_notify_local_owner4page(session, &cvt_info);
    }

    return dcs_try_notify_owner_for_page(session, &cvt_info);
}

status_t dcs_claim_ownership_l(knl_session_t *session, page_id_t page_id, drc_lock_mode_e mode, bool32 has_edp,
                               uint64 page_lsn, uint64 req_version)
{
    claim_info_t claim_info;
    DRC_SET_CLAIM_INFO(&claim_info, DCS_SELF_INSTID(session), session->id, page_id, has_edp, mode, page_lsn);

    return dcs_claim_ownership_internal(session, &claim_info, req_version);
}

static void dcs_handle_page_from_owner(knl_session_t *session, buf_ctrl_t *ctrl, mes_message_t *msg, drc_lock_mode_e mode)
{
    msg_ask_page_ack_t *ack = (msg_ask_page_ack_t *)(msg->buffer);
    uint8 flags = msg->head->flags;
    uint16 size = msg->head->size;

    knl_panic(ack->head.cmd == MES_CMD_PAGE_READY);
    knl_panic(DCS_BUF_CTRL_NOT_OWNER(session, ctrl));

    if (size > DEFAULT_PAGE_SIZE(session)) {
        knl_panic(!(flags & MES_FLAG_NEED_LOAD) && !(flags & MES_FLAG_READONLY2X));
        uint64 new_lsn = ((page_head_t *)(msg->buffer + sizeof(msg_ask_page_ack_t)))->lsn;
        knl_panic(new_lsn >= dtc_get_ctrl_lsn(ctrl));
        errno_t err = memcpy_sp(ctrl->page, DEFAULT_PAGE_SIZE(session), msg->buffer + sizeof(msg_ask_page_ack_t), DEFAULT_PAGE_SIZE(session));
        knl_securec_check(err);

        session->stat->dcs_buffer_gets++;
    }

    if (ack->lsn != 0) {
        dtc_update_lsn(session, ack->lsn);
    }

    if (ack->scn != 0) {
        dtc_update_scn(session, ack->scn);
    }

    if ((flags & MES_FLAG_NEED_LOAD) && ctrl->is_edp) { /* clean edp msg may come later. */
        DTC_DCS_DEBUG_INF("[DCS][%u-%u][%s]: need load, and clean edp, dirty=%u", ctrl->page_id.file,
                          ctrl->page_id.page, MES_CMD2NAME(msg->head->cmd), ctrl->is_dirty);
        dcs_buf_clean_ctrl_edp(session, ctrl, CT_TRUE);
    }

    knl_panic(mode == ack->mode);
    ctrl->lock_mode = mode;
    ctrl->is_fixed = 0;
    if (ctrl->lock_mode == DRC_LOCK_EXCLUSIVE) {
        ctrl->is_edp = 0;
        ctrl->is_remote_dirty = DCS_ACK_PG_IS_DIRTY(msg) || DCS_ACK_PG_IS_REMOTE_DIRTY(msg);
    } else {
        ctrl->is_remote_dirty = 0;
    }

    ctrl->force_request = 0;
    CM_MFENCE;
    if (flags & MES_FLAG_NEED_LOAD) {
        ctrl->load_status = (uint8)BUF_NEED_LOAD;
    } else {
        ctrl->load_status = (uint8)BUF_IS_LOADED;
    }

    DTC_DCS_DEBUG_INF(
        "[DCS][%u-%u][%s]: handle page from owner, lock mode=%u, edp=%d, src_id=%u, src_sid=%u, dest_id=%u, dest_sid=%u, mode=%u, dirty=%u, remote dirty=%u,"
        "remote remote diry=%u, page pcn=%d, page lsn=%llu, sync lsn=%llu, sync scn=%llu, page_type=%u, load_status=%d",
        ctrl->page_id.file, ctrl->page_id.page, MES_CMD2NAME(msg->head->cmd), ctrl->lock_mode, ctrl->is_edp,
        msg->head->src_inst, msg->head->src_sid, msg->head->dst_inst, msg->head->dst_sid, mode, ctrl->is_dirty,
        ctrl->is_remote_dirty, DCS_ACK_PG_IS_REMOTE_DIRTY(msg), ctrl->page->pcn, ctrl->page->lsn, ack->lsn, ack->scn,
        ((heap_page_t *)ctrl->page)->head.type, ctrl->load_status);
}

static status_t dcs_send_ask_master_req(knl_session_t *session, uint8 master_id, buf_ctrl_t *ctrl,
                                        drc_lock_mode_e req_mode, uint64 req_version)
{
    msg_page_req_t page_req;
    status_t ret;

    mes_init_send_head(&page_req.head, MES_CMD_ASK_MASTER, sizeof(msg_page_req_t), CT_INVALID_ID32,
                       DCS_SELF_INSTID(session), master_id, DCS_SELF_SID(session), CT_INVALID_ID16);
    page_req.page_id = ctrl->page_id;
    page_req.req_mode = req_mode;
    page_req.curr_mode = ctrl->lock_mode;
    page_req.req_version = req_version;
    page_req.lsn = dtc_get_ctrl_lsn(ctrl);

    DTC_DCS_DEBUG_INF(
        "[DCS][%u-%u][%s]: src_id=%u, dest_id=%u, req_mode=%u, curr_mode=%u, is_dirty=%d, is_edp=%d, is_remote_dirty=%d, pcn=%d, lsn=%llu",
        ctrl->page_id.file, ctrl->page_id.page, MES_CMD2NAME(MES_CMD_ASK_MASTER), DCS_SELF_INSTID(session), master_id,
        req_mode, ctrl->lock_mode, ctrl->is_dirty, ctrl->is_edp, ctrl->is_remote_dirty, ctrl->page->pcn,
        ctrl->page->lsn);
    SYNC_POINT_GLOBAL_START(CANTIAN_DCS_ASK_MASTER_SEND_FAIL, &ret, CT_ERROR);
    ret = dcs_send_data_retry(&page_req);
    SYNC_POINT_GLOBAL_END;
    if (ret == CT_SUCCESS) {
        SYNC_POINT_GLOBAL_START(CANTIAN_DCS_ASK_MASTER_SUCC_ABORT, NULL, 0);
        SYNC_POINT_GLOBAL_END;
        return CT_SUCCESS;
    }

    cm_reset_error();
    CT_THROW_ERROR(ERR_DCS_MSG_EAGAIN, "failed to send ask master request. Try again later");
    return CT_ERROR;
}

void static inline dcs_leave_page(knl_session_t *session)
{
    buf_ctrl_t *ctrl = buf_curr_page(session);
    buf_unlatch_page(session, ctrl);
    buf_pop_page(session);
}

static inline void dcs_set_ctrl4granted(knl_session_t *session, buf_ctrl_t *ctrl)
{
    ctrl->load_status = (uint8)BUF_NEED_LOAD;

    if (ctrl->is_edp) {
        /* the clean edp msg may not be processed. */
        knl_panic(ctrl && ctrl->is_dirty && ctrl->is_edp && !ctrl->is_readonly);
        dcs_buf_clean_ctrl_edp(session, ctrl, CT_TRUE);
        DTC_DCS_DEBUG_INF("[DCS]edp page[%u-%u] (lsn:%lld) is ok", ctrl->page_id.file, ctrl->page_id.page,
            ctrl->page->lsn);
    }

    // first load of this page, give X mode directly
    // master already marked X mode.
    ctrl->lock_mode = DRC_LOCK_EXCLUSIVE;
    ctrl->is_fixed = 0;
    ctrl->force_request = 0;
    ctrl->transfer_status = BUF_TRANS_NONE;
    DTC_DCS_DEBUG_INF("[DCS][%u-%u][dcs set ctrl4granted] success", ctrl->page_id.file, ctrl->page_id.page);
}

static inline void dcs_set_ctrl4already_owner(knl_session_t *session, buf_ctrl_t *ctrl, drc_lock_mode_e req_mode,
                                              uint8 action)
{
    ctrl->is_fixed = 0;
    if (action != DRC_RES_INVALID_ACTION && ctrl->is_edp) {
        knl_panic(action == DRC_RES_SHARE_ACTION || action == DRC_RES_EXCLUSIVE_ACTION);
        dcs_clean_local_ctrl(session, ctrl, action, CT_INVALID_ID64);
    }

    knl_panic(ctrl->is_edp == 0);
    if (req_mode == DRC_LOCK_EXCLUSIVE) {
        ctrl->lock_mode = DRC_LOCK_EXCLUSIVE;
        ctrl->is_edp = 0;
    } else {
        ctrl->lock_mode = DRC_LOCK_SHARE;
        CM_ASSERT(req_mode == DRC_LOCK_SHARE);
    }
    ctrl->transfer_status = BUF_TRANS_NONE;

#ifdef DB_DEBUG_VERSION
    if (ctrl->load_status == BUF_NEED_LOAD) {
        DTC_DCS_DEBUG_INF("[DCS][%u-%u]: set ctrl already owner, need load page, lock mode(%d).", ctrl->page_id.file,
                          ctrl->page_id.page, ctrl->lock_mode);
    }
#endif
}

static inline status_t dcs_handle_ack_need_load(knl_session_t *session, mes_message_t *msg, buf_ctrl_t *ctrl,
                                                drc_lock_mode_e mode)
{
    msg_pg_ack_ld_t *ack = (msg_pg_ack_ld_t *)msg->buffer;

    page_id_t page_id = ctrl->page_id;
    if (DRC_STOP_DCS_IO_FOR_REFORMING(ack->req_version, session)) {
        CT_LOG_RUN_ERR("[DCS][%u-%u]reforming, handle ack need_load failed, req_version=%llu, cur_version=%llu",
            page_id.file, page_id.page, ack->req_version, DRC_GET_CURR_REFORM_VERSION);
        // TODO 4node
        return CT_ERROR;
    }

    // load page from disk, need to sync scn/lsn with master
    dtc_update_lsn(session, ack->master_lsn);
    dtc_update_scn(session, ack->scn);

    dcs_set_ctrl4granted(session, ctrl);

    return CT_SUCCESS;
}

static inline status_t dcs_handle_ack_already_owner(knl_session_t *session, uint32 master_id, mes_message_t *msg, buf_ctrl_t *ctrl, drc_lock_mode_e mode)
{
    msg_ack_owner_t *ack = (msg_ack_owner_t *)msg->buffer;

    page_id_t page_id = ctrl->page_id;
    if (DRC_STOP_DCS_IO_FOR_REFORMING(ack->req_version, session)) {
        // master inst down
        CT_LOG_RUN_ERR("[DCS][%u-%u]reforming, handle ack already owner failed, masterId=%u, "
                       "req_version=%llu, cur_version=%llu",
                       page_id.file, page_id.page, master_id,
                       ack->req_version, DRC_GET_CURR_REFORM_VERSION);
        return CT_ERROR;
    }

    knl_panic(mode <= ack->req_mode);
    dcs_set_ctrl4already_owner(session, ctrl, ack->req_mode, ack->action);

    if (master_id != DCS_SELF_INSTID(session)) {
        (void)dcs_claim_ownership_r(session, master_id, ctrl->page_id, CT_FALSE, ack->req_mode, dtc_get_ctrl_latest_lsn(ctrl),
                                    ack->req_version);
    } else {
        (void)dcs_claim_ownership_l(session, ctrl->page_id, ack->req_mode, CT_FALSE, dtc_get_ctrl_latest_lsn(ctrl),
                                    ack->req_version);
    }

    return CT_SUCCESS;
}

static inline status_t dcs_handle_ack_page_ready(knl_session_t *session, uint32 master_id, mes_message_t *msg,
                                                 buf_ctrl_t *ctrl, drc_lock_mode_e lock_mode)
{
    drc_lock_mode_e mode = lock_mode;
    msg_ask_page_ack_t *ack = (msg_ask_page_ack_t *)(msg->buffer);
    page_id_t page_id = ctrl->page_id;
    if (DRC_STOP_DCS_IO_FOR_REFORMING(ack->req_version, session)) {
        // master inst down
        CT_LOG_RUN_ERR("[DCS][%u-%u]reforming, handle ack page ready failed, masterId=%u,"
            "req_version=%llu, cur_version=%llu",
            page_id.file, page_id.page, master_id, ack->req_version, DRC_GET_CURR_REFORM_VERSION);
        return CT_ERROR;
    }

    uint8 ack_mode = ((msg_ask_page_ack_t *)(msg->buffer))->mode;
    knl_panic(mode <= ack_mode);
    mode = ack_mode;
    dcs_handle_page_from_owner(session, ctrl, msg, mode);

    if (master_id != DCS_SELF_INSTID(session)) {
        (void)dcs_claim_ownership_r(session, master_id, ctrl->page_id, DCS_ACK_PG_IS_DIRTY(msg), mode,
                                    dtc_get_ctrl_latest_lsn(ctrl), ack->req_version);
    } else {
        (void)dcs_claim_ownership_l(session, ctrl->page_id, mode, DCS_ACK_PG_IS_DIRTY(msg),
                                    dtc_get_ctrl_latest_lsn(ctrl), ack->req_version);
    }

    return CT_SUCCESS;
}

status_t dcs_handle_ask_master_ack(knl_session_t *session, uint8 master_id, buf_ctrl_t *ctrl, drc_lock_mode_e mode, wait_event_t *ack_event)
{
    if (ack_event) {
        *ack_event = DCS_REQ_MASTER4PAGE_2WAY;
    }

    mes_message_t msg;
    status_t ret = mes_recv(session->id, &msg, CT_TRUE, mes_get_current_rsn(session->id), DCS_WAIT_MSG_TIMEOUT);
    if (SECUREC_UNLIKELY(ret != CT_SUCCESS)) {
        CT_LOG_RUN_ERR("[DCS][%u-%u][wait for master ack]: timeout, timeout=%u ms",
            ctrl->page_id.file, ctrl->page_id.page, DCS_WAIT_MSG_TIMEOUT);
        return CT_ERROR;
    }
    SYNC_POINT_GLOBAL_START(CANTIAN_DCS_ASK_MASTER_ACK_SUCC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    DTC_DCS_DEBUG_INF("[DCS][%u-%u][%s]: src_id=%u, dest_id=%u, flag=%u",
        ctrl->page_id.file, ctrl->page_id.page, MES_CMD2NAME(msg.head->cmd), msg.head->src_inst, msg.head->dst_inst, msg.head->flags);

    switch (msg.head->cmd) {
        case MES_CMD_MASTER_ACK_NEED_LOAD:
            ret = dcs_handle_ack_need_load(session, &msg, ctrl, DRC_LOCK_EXCLUSIVE);
            break;

        case MES_CMD_MASTER_ACK_ALREADY_OWNER:
            ret = dcs_handle_ack_already_owner(session, master_id, &msg, ctrl, mode);
            break;

        case MES_CMD_ERROR_MSG:
            ret = CT_ERROR;
            break;

        default:
            ret = dcs_handle_ack_page_ready(session, master_id, &msg, ctrl, mode);
            if (ack_event) {
                *ack_event = DCS_REQ_MASTER4PAGE_3WAY;
            }
            break;
    }

    mes_release_message_buf(msg.buffer);
    return ret;
}

static inline status_t dcs_ask_master4page_r(knl_session_t *session, buf_ctrl_t *ctrl, uint8 master_id, drc_lock_mode_e mode)
{
    uint64 req_version = DRC_GET_CURR_REFORM_VERSION;
    knl_begin_session_wait(session, DCS_REQ_MASTER4PAGE_2WAY, CT_TRUE);

    status_t ret = dcs_send_ask_master_req(session, master_id, ctrl, mode, req_version);
    if (ret == CT_SUCCESS) {
        wait_event_t event = DCS_REQ_MASTER4PAGE_2WAY;
        ret = dcs_handle_ask_master_ack(session, master_id, ctrl, mode, &event);
        if (event != DCS_REQ_MASTER4PAGE_2WAY) {
            knl_end_session_wait_ex(session, DCS_REQ_MASTER4PAGE_2WAY, event);
        } else {
            knl_end_session_wait(session, event);
        }
        return ret;
    }

    knl_end_session_wait(session, DCS_REQ_MASTER4PAGE_2WAY);
    return ret;
}

static status_t dcs_try_get_page_share_owner_r(knl_session_t *session, page_id_t *page_ids, uint32 count,
                                               uint32 master_id, drc_req_owner_result_t *result)
{
    msg_page_req_batch_t page_req;
    mes_init_send_head(&page_req.head, MES_CMD_TRY_ASK_MASTER, sizeof(msg_page_req_batch_t), CT_INVALID_ID32,
                       DCS_SELF_INSTID(session), master_id, DCS_SELF_SID(session), CT_INVALID_ID16);
    page_req.count = count;
    errno_t err_s;
    err_s = memcpy_s(page_req.page_ids, count * sizeof(page_id_t), page_ids, count * sizeof(page_id_t));
    knl_securec_check(err_s);
    page_req.req_version = DRC_GET_CURR_REFORM_VERSION;

    knl_begin_session_wait(session, DCS_REQ_MASTER4PAGE_TRY, CT_TRUE);
    if (mes_send_data(&page_req) != CT_SUCCESS) {
        knl_end_session_wait(session, DCS_REQ_MASTER4PAGE_TRY);

        CT_LOG_RUN_ERR("[DCS][%s]: failed to send msg, src_id=%u, src_sid=%u, dest_id=%u",
                       MES_CMD2NAME(page_req.head.cmd), page_req.head.src_inst, page_req.head.src_sid,
                       page_req.head.dst_inst);
        return CT_ERROR;
    }

    mes_message_t msg;
    if (mes_recv(session->id, &msg, CT_TRUE, page_req.head.rsn, MES_WAIT_MAX_TIME) != CT_SUCCESS) {
        knl_end_session_wait(session, DCS_REQ_MASTER4PAGE_TRY);

        CT_LOG_RUN_ERR("[DCS][%s]: ack timeout, src_id=%u, src_sid=%u, dest_id=%u", MES_CMD2NAME(page_req.head.cmd),
                       page_req.head.src_inst, page_req.head.src_sid, page_req.head.dst_inst);
        return CT_ERROR;
    }

    knl_end_session_wait(session, DCS_REQ_MASTER4PAGE_TRY);

    status_t ret = (msg.head->cmd == MES_CMD_TRY_ASK_MASTER_ACK) ? CT_SUCCESS : CT_ERROR;
    session->stat->dcs_net_time += session->wait_pool[DCS_REQ_MASTER4PAGE_TRY].usecs;
    if (ret == CT_SUCCESS) {
        msg_owner_req_t *owner_ack = (msg_owner_req_t *)(msg.buffer);
        err_s = memcpy_s(result, count * sizeof(drc_req_owner_result_t), owner_ack->result,
                         count * sizeof(drc_req_owner_result_t));
        knl_securec_check(err_s);
        knl_panic(count == owner_ack->count);
    }

    mes_release_message_buf(msg.buffer);
    return ret;
}

status_t dcs_read_local_page4transfer(knl_session_t *session, msg_page_req_t *page_req, buf_ctrl_t **return_ctrl, bool32 *need_load)
{
    buf_ctrl_t *ctrl;

    ctrl = buf_try_latchx_page(session, page_req->page_id, (page_req->req_mode == DRC_LOCK_EXCLUSIVE));
    if (ctrl == NULL) {
        CT_LOG_DEBUG_WAR("[DCS][%u-%u][buf_read_local_page_for_transfer]: not found in memory", page_req->page_id.file,
                         page_req->page_id.page);
        *return_ctrl = NULL;
        return CT_SUCCESS;
    }

    *need_load = CT_FALSE;
    *return_ctrl = ctrl;
    if (ctrl->load_status == (uint8)BUF_LOAD_FAILED) {
        /* If ctrl is not dirty, it's safe to be loaded from disk, otherwise ctrl->page is unsafe.
            cases:
            1) page has been swapped out and just been swapped in and ask master failed. lock_mode is NULL in this case.
            2) requester retry to ask master/owner for page and owner has already changed its ctrl status, lock_mode is null.
            3) In page prefetch for NORMAL or NO-READ page, we try to fetch owners for an extent of pages,
               lock_mode of those pages are DRC_LOCK_EXCLUSIVE. But it's load_status may be load_failed for NO-READ page.
         */
        CT_LOG_DEBUG_WAR(
            "[DCS][%u-%u][buf_read_local_page_for_transfer]: found in memory, but lock is null, is_dirty(%d), remote_dirty(%d), edp(%d), can evict(%d)",
            page_req->page_id.file, page_req->page_id.page, ctrl->is_dirty, ctrl->is_remote_dirty, ctrl->is_edp,
            BUF_IN_USE_IS_RECYCLABLE(ctrl));

        if (BUF_IN_USE_IS_RECYCLABLE(ctrl)) {
            *need_load = CT_TRUE;
            session->curr_page = (char *)ctrl->page;
            session->curr_page_ctrl = ctrl;
            buf_push_page(session, ctrl, LATCH_MODE_X);
            return CT_SUCCESS;
        }

        CM_ASSERT(IS_SAME_PAGID(AS_PAGID(ctrl->page->id), ctrl->page_id) && (page_req->lsn <= ctrl->page->lsn));
        if (!IS_SAME_PAGID(AS_PAGID(ctrl->page->id), ctrl->page_id) || !(page_req->lsn <= ctrl->page->lsn)) {
            CT_LOG_RUN_ERR("[DCS] invalid page id %u-%u, %u-%u, or lsn %llu-%llu", AS_PAGID(ctrl->page->id).file,
                AS_PAGID(ctrl->page->id).page, ctrl->page_id.file, ctrl->page_id.page, page_req->lsn, ctrl->page->lsn);
            buf_unlatch_page(session, ctrl);
            return CT_ERROR;
        }
        if (!DCS_BUF_CTRL_IS_OWNER(session, ctrl) && !page_req->is_retry) {
            /*  requester retry to ask master/owner for page and old msg comes later, so current ctrl is not owner
                just skip and return error
            */
            CT_LOG_RUN_WAR(
                "[DCS][%u-%u][buf_read_local_page_for_transfer]: not owner and is an old msg, skip, is_dirty(%d), remote_dirty(%d), edp(%d), can evict(%d)",
                page_req->page_id.file, page_req->page_id.page, ctrl->is_dirty, ctrl->is_remote_dirty, ctrl->is_edp,
                BUF_IN_USE_IS_RECYCLABLE(ctrl));
            buf_unlatch_page(session, ctrl);
            return CT_ERROR;
        }
    }

    CM_ASSERT(DCS_BUF_CTRL_IS_OWNER(session, ctrl) || page_req->is_retry);
    if (!DCS_BUF_CTRL_IS_OWNER(session, ctrl) && !page_req->is_retry) {
        CT_LOG_RUN_ERR("[DCS] invalid ctrl or page_req, lock_mode %d, is_edp %d, or page_req->is_retry %d",
            ctrl->lock_mode, ctrl->is_edp, page_req->is_retry);
        buf_unlatch_page(session, ctrl);
        return CT_ERROR;
    }
    CM_ASSERT(page_req->curr_mode != DRC_LOCK_EXCLUSIVE);
    if (page_req->curr_mode == DRC_LOCK_EXCLUSIVE) {
        CT_LOG_RUN_ERR("[DCS] invalid page_req->curr_mode");
        buf_unlatch_page(session, ctrl);
        return CT_ERROR;
    }
    if (page_req->req_mode == DRC_LOCK_EXCLUSIVE) {
        ctrl->transfer_status = BUF_TRANS_REL_OWNER;
    }
    session->curr_page = (char *)ctrl->page;
    session->curr_page_ctrl = ctrl;
    buf_push_page(session, ctrl, LATCH_MODE_X);
    return CT_SUCCESS;
}

void dcs_clean_local_ctrl(knl_session_t *session, buf_ctrl_t *ctrl, drc_res_action_e action, uint64 clean_lsn)
{
    /*  during recovery: only recovery session can clean ctrl stautus
     */
    knl_panic(DAAC_SESSION_IN_RECOVERY(session) || (g_rc_ctx->status >= REFORM_RECOVER_DONE));
    buf_set_t *set = &session->kernel->buf_ctx.buf_set[ctrl->buf_pool_id];
    buf_bucket_t *bucket = BUF_GET_BUCKET(set, ctrl->bucket_id);

    CT_LOG_DEBUG_WAR(
        "[DCS][%u-%u]: fix local lock mode from buf_res after recovery, is_edp:%d, is_dirty:%d, is_remote_dirty:%d, "
        " action:%d, load status:%d, fixed:%d, clean lsn:%llu, page lsn:%llu, lock_mode:%d",
        ctrl->page_id.file, ctrl->page_id.page, ctrl->is_edp, ctrl->is_dirty, ctrl->is_remote_dirty, action,
        ctrl->load_status, ctrl->is_fixed, clean_lsn, ctrl->page->lsn, ctrl->lock_mode);

    cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
    knl_panic(ctrl->is_edp);

    if (ctrl->is_fixed) { /* this ctrl has been fixed by another thread and been transfered away to other node. */
        cm_spin_unlock(&bucket->lock);
        return;
    }
    ctrl->is_fixed = 1;

    if (action == DRC_RES_SHARE_ACTION) {
        CM_ASSERT(ctrl->lock_mode == DRC_LOCK_SHARE && ctrl->load_status == BUF_IS_LOADED);
        ctrl->is_edp = 0;
    } else if (action == DRC_RES_CLEAN_EDP_ACTION) {
        CM_ASSERT(clean_lsn != CT_INVALID_ID64);
        if (clean_lsn >= ctrl->page->lsn) {
            dcs_buf_clean_ctrl_edp(session, ctrl, CT_FALSE);
        }
    } else if (action == DRC_RES_EXCLUSIVE_ACTION) {
        // in case the lsn of page on disk is larger than this edp page in recovery
        buf_ctrl_t *tmp_ctrl =
            (buf_ctrl_t *)cm_push(session->stack,
                                  sizeof(buf_ctrl_t) + (uint32)(DEFAULT_PAGE_SIZE(session) + CT_MAX_ALIGN_SIZE_4K));
        *tmp_ctrl = *ctrl;
        tmp_ctrl->lock_mode = DRC_LOCK_SHARE;
        tmp_ctrl->is_edp = 0;
        tmp_ctrl->is_dirty = 0;
        tmp_ctrl->page = (page_head_t *)cm_aligned_buf((char *)tmp_ctrl + (uint64)sizeof(buf_ctrl_t));
        tmp_ctrl->page->lsn = 0;
        if (buf_load_page(session, tmp_ctrl, tmp_ctrl->page_id) != CT_SUCCESS) {
            tmp_ctrl->load_status = (uint8)BUF_LOAD_FAILED;
            knl_panic_log(0, "[DCS]edp page[%u-%u] (lsn:%lld) load from disk failed", ctrl->page_id.file,
                          ctrl->page_id.page, ctrl->page->lsn);
        }
        if (ctrl->page->lsn < dtc_get_ctrl_lsn(tmp_ctrl)) {
            CT_LOG_RUN_WAR("[DCS]edp page[%u-%u] (lsn:%lld) is older than disk page(%lld), reload from disk",
                           ctrl->page_id.file, ctrl->page_id.page, ctrl->page->lsn, tmp_ctrl->page->lsn);
            errno_t err_s;
            err_s = memcpy_s(ctrl->page, DEFAULT_PAGE_SIZE(session), tmp_ctrl->page, DEFAULT_PAGE_SIZE(session));
            knl_securec_check(err_s);
            dcs_buf_clean_ctrl_edp(session, ctrl, CT_FALSE);
        }
        cm_pop(session->stack);

        ctrl->is_edp = 0;
        ctrl->lock_mode = DRC_LOCK_EXCLUSIVE;
        ctrl->load_status = BUF_IS_LOADED;

        ctrl->force_request = 0;
    } else {
        CM_ASSERT(0);
    }
    ctrl->is_fixed = 0;
    cm_spin_unlock(&bucket->lock);
}

/*
 * owner transfer local page to requester
 */
status_t static inline dcs_owner_transfer_page(knl_session_t *session, uint8 owner_id, msg_page_req_t *page_req)
{
    mes_message_head_t req_head;
    buf_ctrl_t *ctrl = NULL;
    uint8 flag = 0;
    uint16 size;
    status_t ret;
    bool32 skip_check = page_req->is_retry; /* retry to ask owner for page. It's safe to resend page as the claimed
                                               owner is not changed. */
    uint8 req_id = page_req->head.src_inst;
    uint32 req_sid = page_req->head.src_sid;
    uint32 req_rsn = page_req->head.rsn;

    if (page_req->page_id.file >= INVALID_FILE_ID ||
        (page_req->req_mode != DRC_LOCK_EXCLUSIVE && page_req->req_mode != DRC_LOCK_SHARE) ||
        (page_req->action != DRC_RES_INVALID_ACTION && page_req->action != DRC_RES_SHARE_ACTION && page_req->action != DRC_RES_EXCLUSIVE_ACTION)) {
        CT_LOG_RUN_ERR("invalid page_id [%u-%u] or req mode %u or action %d", page_req->page_id.file,
            page_req->page_id.page, page_req->req_mode, page_req->action);
        mes_send_error_msg(&page_req->head);
        return CT_ERROR;
    }

    if (DRC_STOP_DCS_IO_FOR_REFORMING(page_req->req_version, session)) {
        CT_LOG_RUN_ERR("[DCS][%u-%u]: reforming, owner transfer page failed, req_version=%llu, cur_version=%llu",
            page_req->page_id.file, page_req->page_id.page, page_req->req_version, DRC_GET_CURR_REFORM_VERSION);
        mes_send_error_msg(&page_req->head);
        return CT_ERROR;
    }

    bool32 need_load = CT_FALSE;
    ret = dcs_read_local_page4transfer(session, page_req, &ctrl, &need_load);
    if (ret == CT_ERROR) {
        mes_send_error_msg(&page_req->head);
        return ret;
    }

    if (!ctrl || need_load) {
        flag = MES_FLAG_NEED_LOAD;
    } else {
        if (page_req->action != DRC_RES_INVALID_ACTION && ctrl->is_edp) {
            dcs_clean_local_ctrl(session, ctrl, page_req->action, CT_INVALID_ID64);
        }

        if ((page_req->curr_mode == DRC_LOCK_SHARE) && (page_req->req_mode == DRC_LOCK_EXCLUSIVE)) {
            if (ctrl->lock_mode != DRC_LOCK_SHARE && !skip_check) {
                CT_LOG_RUN_ERR("[DCS][%u-%u]: owner transfer page failed, invalid lock_mode(%u)",
                    page_req->page_id.file, page_req->page_id.page, ctrl->lock_mode);
                mes_send_error_msg(&page_req->head);
                dcs_leave_page(session);
                return CT_ERROR;
            }
            flag = MES_FLAG_READONLY2X;
        }
        if (page_req->lsn > ctrl->page->lsn) {
            CT_LOG_RUN_ERR(
                "[DCS][%u-%u]: owner transfer page failed, invalid page_req->lsn(%llu), ctrl->page->lsn(%llu)",
                page_req->page_id.file, page_req->page_id.page, page_req->lsn, ctrl->page->lsn);
            mes_send_error_msg(&page_req->head);
            dcs_leave_page(session);
            return CT_ERROR;
        }
    }

    msg_ask_page_ack_t ask_page;
    req_head.src_inst = req_id;
    req_head.dst_inst = owner_id;
    req_head.src_sid = req_sid;
    req_head.rsn = req_rsn;
    ask_page.req_version = page_req->req_version;
    size = sizeof(msg_ask_page_ack_t);
    if (flag == 0) {
        size += DEFAULT_PAGE_SIZE(session);
    }
    mes_init_ack_head(&req_head, &ask_page.head, MES_CMD_PAGE_READY, size, DCS_SELF_SID(session));

    ask_page.lsn = 0;
    ask_page.scn = 0;
    ask_page.mode = page_req->req_mode;
    ask_page.head.flags = flag;
    if (!ctrl) {
        SYNC_POINT_GLOBAL_START(CANTIAN_DCS_TRANSFER_BEFORE_SEND_ABORT, NULL, 0);
        SYNC_POINT_GLOBAL_END;
        ret = dcs_send_data_retry((void *)&ask_page);
        DTC_DCS_DEBUG(ret, "[DCS][%u-%u][%s]: status=(%d), need load, dest_id=%u, dest_sid=%u, mode=%u",
                      page_req->page_id.file, page_req->page_id.page, MES_CMD2NAME(ask_page.head.cmd), ret,
                      ask_page.head.dst_inst, ask_page.head.dst_sid, page_req->req_mode);
        SYNC_POINT_GLOBAL_START(CANTIAN_DCS_TRANSFER_AFTER_SEND_ABORT, NULL, 0);
        SYNC_POINT_GLOBAL_END;
        return ret;
    }

    knl_panic(!ctrl->is_readonly);
    if (ctrl->is_dirty || ctrl->is_marked) {
        knl_begin_session_wait(session, DCS_TRANSFER_PAGE_FLUSHLOG, CT_TRUE);
        if (DAAC_NEED_FLUSH_LOG(session, ctrl)) {
            if (log_flush(session, NULL, NULL, NULL) != CT_SUCCESS) {
                CM_ABORT(0, "[DTC DCS][%u-%u]: ABORT INFO: flush redo log failed", page_req->page_id.file, page_req->page_id.page);
            }
        }
        knl_end_session_wait(session, DCS_TRANSFER_PAGE_FLUSHLOG);
    }

    ask_page.lsn = DB_CURR_LSN(session);
    ask_page.scn = DB_CURR_SCN(session);

    if (ctrl->is_dirty) {
        ask_page.head.flags |= MES_FLAG_DIRTY_PAGE;
    }

    if (ctrl->is_remote_dirty) {
        ask_page.head.flags |= MES_FLAG_REMOTE_DIRTY_PAGE;
    }

    if (page_req->req_mode == DRC_LOCK_EXCLUSIVE) {
        knl_panic(!ctrl->is_marked && !ctrl->is_readonly);
    } else {
        //send read-only copy, don't change owner
        knl_panic(flag != MES_FLAG_READONLY2X);
    }

    knl_begin_session_wait(session, DCS_TRANSFER_PAGE, CT_TRUE);
    SYNC_POINT_GLOBAL_START(CANTIAN_DCS_TRANSFER_BEFORE_SEND_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    
    if (DRC_STOP_DCS_IO_FOR_REFORMING(page_req->req_version, session)) {
        CT_LOG_RUN_ERR("[DCS][%u-%u]: reforming, owner transfer page failed, req_version=%llu, cur_version=%llu",
            page_req->page_id.file, page_req->page_id.page, page_req->req_version, DRC_GET_CURR_REFORM_VERSION);
        ctrl->transfer_status = BUF_TRANS_NONE;
        dcs_leave_page(session);
        mes_send_error_msg(&page_req->head);
        return CT_ERROR;
    }
    if (flag != 0) {
        ret = dcs_send_data_retry((void*)&ask_page);
    } else {
        ret = dcs_send_data3_retry(&ask_page.head, sizeof(msg_ask_page_ack_t), (void*)session->curr_page);
        if (ret == CT_SUCCESS) {
            session->stat->dcs_buffer_sends++;
        }
    }

    if (ret == CT_SUCCESS && DCS_BUF_CTRL_IS_OWNER(session, ctrl)) {
        SYNC_POINT_GLOBAL_START(CANTIAN_DCS_TRANSFER_AFTER_SEND_ABORT, NULL, 0);
        SYNC_POINT_GLOBAL_END;
        if (page_req->req_mode == DRC_LOCK_EXCLUSIVE) {
            // invalidate local buf ctrl
            ctrl->lock_mode = DRC_LOCK_NULL;
            ctrl->load_status = BUF_LOAD_FAILED;
            if (ctrl->is_dirty) {
                ctrl->is_edp = CT_TRUE;
                ctrl->edp_scn = DB_CURR_SCN(session);
            }
            ctrl->is_remote_dirty = 0;
        } else {
            // send read-only copy, don't change owner
            ctrl->lock_mode = DRC_LOCK_SHARE;
        }
    } else if (ret == CT_SUCCESS && !DCS_BUF_CTRL_IS_OWNER(session, ctrl)) {
        knl_panic(0);
    }
    if (ret != CT_SUCCESS && ctrl->transfer_status == BUF_TRANS_REL_OWNER) {
        ctrl->transfer_status = BUF_TRANS_NONE;
    }
    knl_end_session_wait(session, DCS_TRANSFER_PAGE);

    DTC_DCS_DEBUG(
        ret,
        "[DCS][%u-%u][%s]: after owner transfer page, status=(%d), dest_id=%u, dest_sid=%u, mode=%u, ctrl_dirty=%u, remote dirty=%u, ctrl_lock_mode=%u, ctrl_is_edp=%u,"
        "page pcn=%d, page_lsn=%llu, sync lsn=%llu, sync scn=%llu, page_type=%u, page req mode=%d, flag=%d, retry=%d, req rsn=%u",
        page_req->page_id.file, page_req->page_id.page, MES_CMD2NAME(ask_page.head.cmd), ret, ask_page.head.dst_inst,
        ask_page.head.dst_sid, page_req->req_mode, ctrl->is_dirty, ctrl->is_remote_dirty, ctrl->lock_mode, ctrl->is_edp,
        ctrl->page->pcn, ctrl->page->lsn, ask_page.lsn, ask_page.scn, ((heap_page_t *)session->curr_page)->head.type,
        page_req->req_mode, flag, skip_check, ask_page.head.rsn);

    dcs_leave_page(session);
    return ret;
}

static inline status_t dcs_notify_owner_for_page_r(knl_session_t *session, uint8 owner_id, msg_page_req_t *page_req)
{
    status_t ret;
    uint8 req_id = page_req->head.src_inst;
    uint32 req_sid = page_req->head.src_sid;
    uint32 req_rsn = page_req->head.rsn;

    if (owner_id != req_id) {
        if (DRC_STOP_DCS_IO_FOR_REFORMING(page_req->req_version, session)) {
            CT_LOG_RUN_ERR("[DCS][%u-%u]: doing remaster", page_req->page_id.file, page_req->page_id.page);
            return CT_ERROR;
        }
        mes_init_send_head(&page_req->head, MES_CMD_ASK_OWNER, sizeof(msg_page_req_t), req_rsn, req_id, owner_id,
                           req_sid, CT_INVALID_ID16);
        SYNC_POINT_GLOBAL_START(CANTIAN_DCS_NOTIFY_OWNER_SEND_FAIL, &ret, CT_ERROR);
        ret = dcs_send_data_retry(page_req);
        SYNC_POINT_GLOBAL_END;
        if (ret == CT_SUCCESS) {
            DTC_DCS_DEBUG_INF("[DCS][%u-%u][%s]: dest_id=%u, dest_sid=%u, mode=%u",
                page_req->page_id.file, page_req->page_id.page, MES_CMD2NAME(page_req->head.cmd),
                page_req->head.dst_inst, page_req->head.dst_sid, page_req->req_mode);
            SYNC_POINT_GLOBAL_START(CANTIAN_DCS_NOTIFY_OWNER_SUCC_ABORT, NULL, 0);
            SYNC_POINT_GLOBAL_END;
            return CT_SUCCESS;
        }

        CT_LOG_RUN_ERR("[DCS][%u-%u][%s]: dcs_notify_owner_for_page_r failed, dest_id=%u, dest_sid=%u, mode=%u",
            page_req->page_id.file, page_req->page_id.page, MES_CMD2NAME(page_req->head.cmd), page_req->head.dst_inst,
            page_req->head.dst_sid, page_req->req_mode);
        return CT_ERROR;
    }

    // asker is already owner, just notify requester(owner) page is ready
    msg_ack_owner_t ack;
    mes_init_send_head(&ack.head, MES_CMD_MASTER_ACK_ALREADY_OWNER, sizeof(msg_ack_owner_t), req_rsn,
                       DCS_SELF_INSTID(session), req_id, DCS_SELF_SID(session), req_sid);
    ack.req_version = page_req->req_version;
    ack.action = page_req->action;
    ack.lsn = page_req->lsn;
    ack.req_mode = page_req->req_mode;

    if (dcs_send_data_retry(&ack) == CT_SUCCESS) {
        DTC_DCS_DEBUG_INF("[DCS][%u-%u][%s]: dest_id=%u, dest_sid=%u, mode=%u",
            page_req->page_id.file, page_req->page_id.page, MES_CMD2NAME(ack.head.cmd),
            ack.head.dst_inst, ack.head.dst_sid, page_req->req_mode);
        return CT_SUCCESS;
    }

    CT_LOG_RUN_ERR("[DCS][%u-%u][%s]: failed, dest_id=%u, dest_sid=%u, mode=%u",
        page_req->page_id.file, page_req->page_id.page, MES_CMD2NAME(ack.head.cmd),
        ack.head.dst_inst, ack.head.dst_sid, page_req->req_mode);
    return CT_ERROR;
}

status_t dcs_notify_owner_for_page(knl_session_t *session, uint8 owner_id, msg_page_req_t *page_req)
{
    // TODO 4node deal with owner failed
    if ((DCS_SELF_INSTID(session) == owner_id) && (owner_id != page_req->head.src_inst)) {
        // this instance is owner, transfer local page, and requester must be on another instance
        status_t ret = dcs_owner_transfer_page(session, owner_id, page_req);
        if (SECUREC_UNLIKELY(ret != CT_SUCCESS)) {
            CT_LOG_RUN_ERR("[DCS][%u-%u][owner transfer page]: failed, dest_id=%u, dest_sid=%u, dest_rsn=%u, mode=%u",
                              page_req->page_id.file, page_req->page_id.page, page_req->head.src_inst,
                              page_req->head.src_sid, page_req->head.rsn, page_req->req_mode);
        }
        return ret;
    }

    // notify owner to transfer this page to requester
#ifdef DB_DEBUG_VERSION
    if (owner_id == page_req->head.src_inst) {
        DTC_DCS_DEBUG_INF("[DCS][%u-%u]notify owner for page, set already owner on same node, owner_id=%d, dest_id=%u, "
                          "dest_sid=%u, dest_rsn=%u, mode=%u",
                          page_req->page_id.file, page_req->page_id.page, owner_id, page_req->head.src_inst,
                          page_req->head.src_sid, page_req->head.rsn, page_req->req_mode);
    }
#endif
    return dcs_notify_owner_for_page_r(session, owner_id, page_req);
}

static inline void dcs_send_requester_granted(knl_session_t *session, msg_page_req_t *page_req)
{
    // this page not in memory of other instance, notify requester to load from disk
    msg_pg_ack_ld_t ack;

    mes_init_ack_head(&page_req->head, &ack.head, MES_CMD_MASTER_ACK_NEED_LOAD,
        sizeof(msg_pg_ack_ld_t), DCS_SELF_SID(session));
    ack.head.rsn = page_req->head.rsn;
    ack.master_lsn = DB_CURR_LSN(session);
    ack.scn = DB_CURR_SCN(session);
    ack.req_version = page_req->req_version;

    if (dcs_send_data_retry(&ack) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DCS]failed to send ack");
        // TODO reform
        return;
    }

    if (LOG_DEBUG_INF_ON) {
        DTC_DCS_DEBUG_INF("[DCS][%u-%u][%s]: dest_id=%u, dest_sid=%u, mode=%u, rsn=%u",
            page_req->page_id.file, page_req->page_id.page, MES_CMD2NAME(ack.head.cmd),
            ack.head.dst_inst, ack.head.dst_sid, page_req->req_mode, ack.head.rsn);
    }
}

static inline void dcs_send_requester_already_owner(knl_session_t *session, msg_page_req_t *page_req)
{
    //asker is already owner, just notify requester(owner) page is ready
    msg_ack_owner_t ack;
    mes_init_ack_head(&page_req->head, &ack.head, MES_CMD_MASTER_ACK_ALREADY_OWNER,
        sizeof(msg_ack_owner_t), DCS_SELF_SID(session));
    ack.req_version = page_req->req_version;
    ack.action = page_req->action;
    ack.lsn = page_req->lsn;
    ack.req_mode = page_req->req_mode;

    if (dcs_send_data_retry(&ack) != CT_SUCCESS) {
        // TODO reform
        return;
    }

    if (LOG_DEBUG_INF_ON) {
        DTC_DCS_DEBUG_INF("[DCS][%u-%u][%s]: dest_id=%u, dest_sid=%u, mode=%u, rsn=%u",
            page_req->page_id.file, page_req->page_id.page, MES_CMD2NAME(ack.head.cmd), ack.head.dst_inst,
            ack.head.dst_sid, page_req->req_mode, ack.head.rsn);
    }
}

static inline void dcs_send_error_msg(knl_session_t *session, msg_page_req_t *page_req)
{
    //asker is already owner, just notify requester(owner) page is ready
    mes_message_head_t head;
    mes_init_ack_head(&page_req->head, &head, MES_CMD_MASTER_ACK_ALREADY_OWNER,
        sizeof(mes_message_head_t), DCS_SELF_SID(session));

    if (mes_send_data(&head) != CT_SUCCESS) {
        return;
    }

    if (LOG_DEBUG_INF_ON) {
        DTC_DCS_DEBUG_INF("[DCS][%u-%u][%s]: dest_id=%u, dest_sid=%u, mode=%u, rsn=%u", page_req->page_id.file,
            page_req->page_id.page, MES_CMD2NAME(head.cmd), head.dst_inst, head.dst_sid, page_req->req_mode, head.rsn);
    }
}

void dcs_process_ask_master_for_page(void *sess, mes_message_t * receive_msg)
{
    drc_req_owner_result_t result;
    knl_session_t *session = (knl_session_t *)sess;
    if (sizeof(msg_page_req_t) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("process ask master for page msg is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }

    msg_page_req_t page_req = *(msg_page_req_t *)(receive_msg->buffer);
    mes_release_message_buf(receive_msg->buffer);
    if (page_req.req_mode >= DRC_LOCK_MODE_MAX || page_req.curr_mode >= DRC_LOCK_MODE_MAX) {
        CT_LOG_RUN_ERR("[DCS][%u-%u][ask master for page_req]req mode invalid, cur_mode %d, req_mode %d",
            page_req.page_id.file, page_req.page_id.page, page_req.curr_mode, page_req.req_mode);
        return;
    }

    page_id_t page_id = page_req.page_id;
    if (DRC_STOP_DCS_IO_FOR_REFORMING(page_req.req_version, session)) {
        CT_LOG_RUN_ERR("[DCS][%u-%u]reforming, ask master failed, req_version=%llu, cur_version=%llu",
            page_id.file, page_id.page, page_req.req_version, DRC_GET_CURR_REFORM_VERSION);
        // if requester alive, send err msg
        mes_send_error_msg(&page_req.head);
        return;
    }

    DTC_DCS_DEBUG_INF(
        "[DCS][%u-%u][%s]: ask master for page, src_id=%u, src_sid=%u, req_mode=%u, curr_mode=%u, rsn=%u, lsn=%llu",
        page_req.page_id.file, page_req.page_id.page, MES_CMD2NAME(page_req.head.cmd), page_req.head.src_inst,
        page_req.head.src_sid, page_req.req_mode, page_req.curr_mode, page_req.head.rsn, page_req.lsn);

    drc_req_info_t req_info;
    req_info.inst_id = page_req.head.src_inst;
    req_info.inst_sid = page_req.head.src_sid;
    req_info.rsn = page_req.head.rsn;
    req_info.req_mode = page_req.req_mode;
    req_info.curr_mode = page_req.curr_mode;
    req_info.req_time = page_req.head.req_start_time;
    req_info.req_version = page_req.req_version;
    req_info.lsn = page_req.lsn;
    SYNC_POINT_GLOBAL_START(CANTIAN_DCS_PROC_ASK_MASTER_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    status_t ret = drc_request_page_owner(session, page_req.page_id, &req_info, CT_FALSE, &result);
    if (SECUREC_UNLIKELY(ret != CT_SUCCESS)) {
        // if requester alive, send err msg
        mes_send_error_msg(&page_req.head);

        DTC_DCS_DEBUG_ERR(
            "[DCS][%u-%u][%s]: failed to request page_req owner, src_id=%u, src_sid=%u, req_mode=%u, curr_mode=%u, "
            "req_rsn=%u",
            page_req.page_id.file, page_req.page_id.page, MES_CMD2NAME(page_req.head.cmd), page_req.head.src_inst,
            page_req.head.src_sid, page_req.req_mode, page_req.curr_mode, page_req.head.rsn);
        return;
    }

    DTC_DRC_DEBUG_INF(
        "[DRC][%u-%u][ask master for page, after request]: req_id=%u, req_sid=%u, req_rsn=%u, "
        "req_mode=%u, curr_mode=%u, req_version=%llu, cur_version=%llu, result=%d, action=%d, curr owner:%d",
        page_id.file, page_id.page, req_info.inst_id, req_info.inst_sid, req_info.rsn, req_info.req_mode,
        req_info.curr_mode, req_info.req_version, DRC_GET_CURR_REFORM_VERSION, result.type, result.action,
        result.curr_owner_id);

    page_req.action = result.action;
    page_req.is_retry = result.is_retry;
    page_req.req_mode = result.req_mode;
    switch (result.type) {
        case DRC_REQ_OWNER_GRANTED:
            dcs_send_requester_granted(session, &page_req);
            break;

        case DRC_REQ_OWNER_ALREADY_OWNER:
            dcs_send_requester_already_owner(session, &page_req);
            break;

        case DRC_REQ_OWNER_WAITING:
            // do nothing.
            DTC_DCS_DEBUG_INF("[DCS][%u-%u][waiting for converting]: dest_id=%u, dest_sid=%u, req_mode=%u, curr_mode=%u",
                page_req.page_id.file, page_req.page_id.page, page_req.head.src_inst, page_req.head.src_sid,
                page_req.req_mode, page_req.curr_mode);
            break;

        case DRC_REQ_OWNER_CONVERTING:
            (void)dcs_notify_owner_for_page(session, result.curr_owner_id, &page_req);
            break;

        default:
            CT_LOG_RUN_ERR("[DCS][%u-%u] unexpected owner request result, type=%u",
                page_req.page_id.file, page_req.page_id.page, result.type);
            break;
    }
}

static status_t dcs_try_get_page_share_owner_l(knl_session_t *session, drc_req_info_t *req_info, page_id_t *page_ids,
                                               uint32 count, drc_req_owner_result_t *result);
void dcs_process_try_ask_master_for_page(void *sess, mes_message_t * receive_msg)
{
    msg_owner_req_t owner_ack;
    msg_page_req_batch_t *page_req = (msg_page_req_batch_t *)(receive_msg->buffer);
    knl_session_t *session = (knl_session_t *)sess;

    if (sizeof(msg_page_req_batch_t) != receive_msg->head->size || page_req->count > BUF_MAX_PREFETCH_NUM) {
        CT_LOG_RUN_ERR("msg is invalid, msg size %u, count:%u", receive_msg->head->size, page_req->count);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    drc_req_info_t req_info;
    req_info.inst_id = page_req->head.src_inst;
    req_info.inst_sid = page_req->head.src_sid;
    req_info.req_mode = DRC_LOCK_SHARE;
    req_info.curr_mode = DRC_LOCK_NULL;
    req_info.rsn = page_req->head.rsn;
    req_info.req_time = page_req->head.req_start_time;
    req_info.req_version = page_req->req_version;
    req_info.lsn = 0;
    for (uint32 i = 0; i < page_req->count; i++) {
        owner_ack.result[i].type = DRC_REQ_OWNER_INVALID;
    }

    (void)dcs_try_get_page_share_owner_l(session, &req_info, page_req->page_ids, page_req->count, owner_ack.result);
    owner_ack.count = page_req->count;
#ifdef DB_DEBUG_VERSION
    char msg[SIZE_K(2)] = { 0 };
    uint16 msg_len = SIZE_K(2);
    uint32 pos = 0;
    int iret_snprintf;
    for (uint32 i = 0; i < owner_ack.count; i++) {
        if (!IS_INVALID_PAGID(page_req->page_ids[i])) {
            iret_snprintf = snprintf_s(msg + pos, msg_len - pos, msg_len - pos - 1, "%u-%u:%d",
                                       page_req->page_ids[i].file, page_req->page_ids[i].page,
                                       owner_ack.result[i].type);
            if (SECUREC_UNLIKELY(iret_snprintf == -1)) {
                knl_panic_log(0, "Secure C lib has thrown an error %d", iret_snprintf);
            }
            pos += iret_snprintf;
        }
    }
    DTC_DCS_DEBUG_INF("[DCS][after try to ask master for page_req]: dest_id=%u, dest_sid=%u, %s",
                      page_req->head.src_inst, page_req->head.src_sid, msg);
#endif
    mes_release_message_buf(receive_msg->buffer);

    mes_init_ack_head(&page_req->head, &owner_ack.head, MES_CMD_TRY_ASK_MASTER_ACK, sizeof(msg_owner_req_t),
                      CT_INVALID_ID16);
    if (dcs_send_data_retry(&owner_ack) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DCS]failed to send ack");
        return;
    }
}

static status_t dcs_ask_owner_for_page(knl_session_t *session, buf_ctrl_t *ctrl, drc_req_owner_result_t *result,
                                       drc_lock_mode_e req_mode, uint64 req_version)
{
    status_t ret;
    page_id_t page_id = ctrl->page_id;

    msg_page_req_t page_req;
    mes_init_send_head(&page_req.head, MES_CMD_ASK_OWNER, sizeof(msg_page_req_t), CT_INVALID_ID32,
                       DCS_SELF_INSTID(session), result->curr_owner_id, DCS_SELF_SID(session), CT_INVALID_ID16);
    page_req.page_id = page_id;
    page_req.req_mode = req_mode;
    page_req.curr_mode = ctrl->lock_mode;
    page_req.req_version = req_version;
    page_req.action = result->action;
    page_req.lsn = dtc_get_ctrl_lsn(ctrl);
    page_req.is_retry = result->is_retry;

    if (DRC_STOP_DCS_IO_FOR_REFORMING(page_req.req_version, session)) {
        CT_LOG_RUN_ERR("[DCS][%u-%u]: reforming, send ask owner failed, req_version=%llu, cur_version=%llu",
            page_req.page_id.file, page_req.page_id.page, req_version, DRC_GET_CURR_REFORM_VERSION);
        return CT_ERROR;
    }

    SYNC_POINT_GLOBAL_START(CANTIAN_DCS_NOTIFY_OWNER_SEND_FAIL, &ret, CT_ERROR);
    ret = dcs_send_data_retry(&page_req);
    SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DCS][%u-%u][%s]: send msg failed, src_id=%u, src_sid=%u, dest_id=%u, dest_sid=%u, req_mode=%u",
            page_id.file, page_id.page, MES_CMD2NAME(page_req.head.cmd), page_req.head.src_inst, page_req.head.src_sid,
            page_req.head.dst_inst, page_req.head.dst_sid, req_mode);
        return CT_ERROR;
    }

    DTC_DCS_DEBUG_INF("[DCS][%u-%u][%s]: src_id=%u, src_sid=%u, dest_id=%u, dest_sid=%u, req_mode=%u", page_id.file,
                      page_id.page, MES_CMD2NAME(page_req.head.cmd), page_req.head.src_inst, page_req.head.src_sid,
                      page_req.head.dst_inst, page_req.head.dst_sid, req_mode);
    SYNC_POINT_GLOBAL_START(CANTIAN_DCS_NOTIFY_OWNER_SUCC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    mes_message_t msg;
    if (mes_recv(session->id, &msg, CT_FALSE, page_req.head.rsn, DCS_WAIT_MSG_TIMEOUT) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DCS][%u-%u][%s]: ack time out, src_id=%u, src_sid=%u, dest_id=%u, dest_sid=%u, req_mode=%u",
            page_id.file, page_id.page, MES_CMD2NAME(page_req.head.cmd), page_req.head.src_inst, page_req.head.src_sid,
            page_req.head.dst_inst, page_req.head.dst_sid, req_mode);
        return CT_ERROR;
    }
    if (msg.head->cmd == MES_CMD_ERROR_MSG) {
        DTC_DCS_DEBUG_ERR("[DCS][%u-%u][%s]: ack err msg, src_id=%u, src_sid=%u, dest_id=%u, dest_sid=%u, req_mode=%u",
            page_id.file, page_id.page, MES_CMD2NAME(page_req.head.cmd), page_req.head.src_inst, page_req.head.src_sid,
            page_req.head.dst_inst, page_req.head.dst_sid, req_mode);
        mes_release_message_buf(msg.buffer);
        return CT_ERROR;
    }
    SYNC_POINT_GLOBAL_START(CANTIAN_DCS_ASK_MASTER_ACK_SUCC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    ret = dcs_handle_ack_page_ready(session, DCS_SELF_INSTID(session), &msg, ctrl, req_mode);

    mes_release_message_buf(msg.buffer);
    return ret;
}

void dcs_process_ask_owner_for_page(void *sess, mes_message_t *receive_msg)
{
    knl_session_t *session = (knl_session_t *)sess;
    if (sizeof(msg_page_req_t) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("process ask owner for page msg is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    msg_page_req_t page_req = *(msg_page_req_t *)(receive_msg->buffer);
    mes_release_message_buf(receive_msg->buffer);

    status_t ret = dcs_owner_transfer_page(session, DCS_SELF_INSTID(session), &page_req);
    if (SECUREC_UNLIKELY(ret != CT_SUCCESS)) {
        CT_LOG_RUN_ERR(
            "[DCS][%u-%u][process ask owner] failed, owner_id=%u, req_id=%u, req_sid=%u, req_rsn=%u, mode=%u, lsn=%llu",
            page_req.page_id.file, page_req.page_id.page, DCS_SELF_INSTID(session), page_req.head.src_inst,
            page_req.head.src_sid, page_req.head.rsn, page_req.req_mode, page_req.lsn);
    }
}

status_t inline dcs_try_notify_owner_for_page(knl_session_t *session, cvt_info_t *cvt_info)
{
    if (!DCS_INSTID_VALID(cvt_info->req_id)) {
        // no converting, just return
        return CT_SUCCESS;
    }

    msg_page_req_t page_req;
    mes_init_send_head(&page_req.head, MES_CMD_ASK_OWNER, sizeof(msg_page_req_t), cvt_info->req_rsn, cvt_info->req_id,
                       cvt_info->owner_id, cvt_info->req_sid, CT_INVALID_ID16);
    page_req.page_id = cvt_info->pageid;
    page_req.req_mode = cvt_info->req_mode;
    page_req.curr_mode = cvt_info->curr_mode;
    page_req.req_version = cvt_info->req_version;
    page_req.lsn = cvt_info->lsn;
    page_req.action = DRC_RES_INVALID_ACTION;
    page_req.is_retry = CT_FALSE;

    status_t ret = dcs_notify_owner_for_page(session, cvt_info->owner_id, &page_req);
    if (SECUREC_UNLIKELY(ret != CT_SUCCESS)) {
        CT_LOG_RUN_ERR("[DCS][%u-%u][notify owner transfer page]: failed, owner_id=%u, req_id=%u, "
                          "req_sid=%u, req_rsn=%u, req_mode=%u, curr_mode=%u, copy_insts=%llu",
                          page_req.page_id.file, page_req.page_id.page, cvt_info->owner_id, cvt_info->req_id,
                          cvt_info->req_sid, cvt_info->req_rsn, cvt_info->req_mode, cvt_info->curr_mode,
                          cvt_info->readonly_copies);
    }

    return ret;
}

void dcs_process_claim_ownership_req(void *sess, mes_message_t *receive_msg)
{
    if (sizeof(msg_claim_owner_t) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("process claim ownership msg is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    msg_claim_owner_t *request = (msg_claim_owner_t *)(receive_msg->buffer);
    knl_session_t *session = (knl_session_t *)sess;
    uint64 req_version = request->req_version;

    cvt_info_t cvt_info;

    DTC_DCS_DEBUG_INF("[DCS][%u-%u][%s]: src_id=%u, src_sid=%u, dest_id=%u, dest_sid=%u, has_edp=%u, req mode=%d",
                      request->page_id.file, request->page_id.page, MES_CMD2NAME(request->head.cmd),
                      request->head.src_inst, request->head.src_sid, request->head.dst_inst, request->head.dst_sid,
                      request->has_edp, request->mode);

    // call drc interface to claim ownership
    claim_info_t claim_info;
    DRC_SET_CLAIM_INFO(&claim_info, request->head.src_inst, request->head.src_sid, request->page_id, request->has_edp,
                       request->mode, request->lsn);

    if (DRC_STOP_DCS_IO_FOR_REFORMING(req_version, session)) {
        CT_LOG_RUN_ERR("[DCS][%u-%u]: reforming, claim owner failed, req_version=%llu, cur_version=%llu",
            request->page_id.file, request->page_id.page, req_version, DRC_GET_CURR_REFORM_VERSION);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }

    drc_claim_page_owner(session, &claim_info, &cvt_info, req_version);

    mes_release_message_buf(receive_msg->buffer);

    dcs_try_notify_owner_for_page(session, &cvt_info);
}

void dcs_process_claim_ownership_req_batch(void *sess, mes_message_t *receive_msg)
{
    if (sizeof(msg_claim_owner_batch_t) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("process claim ownership batch msg is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    msg_claim_owner_batch_t *request = (msg_claim_owner_batch_t *)(receive_msg->buffer);
    knl_session_t *session = (knl_session_t *)sess;
    uint64 req_version = request->req_version;
    if (request->count > BUF_MAX_PREFETCH_NUM) {
        CT_LOG_RUN_ERR("[DCS] invalid count %u", request->count);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    DTC_DCS_DEBUG_INF("[DCS][%s]: process batch claim, src_id=%u, src_sid=%u, dest_id=%u, dest_sid=%u, total count=%d",
                      MES_CMD2NAME(request->head.cmd), request->head.src_inst, request->head.src_sid,
                      request->head.dst_inst, request->head.dst_sid, request->count);

    claim_info_t claim_info;
    for (uint32 i = 0; i < request->count; i++) {
        if (IS_INVALID_PAGID(request->page_ids[i])) {
            continue;
        }

        DRC_SET_CLAIM_INFO(&claim_info, request->head.src_inst, request->head.src_sid, request->page_ids[i], CT_FALSE,
                           DRC_LOCK_SHARE, 0);

        dcs_claim_ownership_internal(session, &claim_info, req_version);
    }
    mes_release_message_buf(receive_msg->buffer);
}

/*
    requester and master are on the same instance, req_id equals to master_id/self_id
*/
status_t dcs_ask_master4page_l(knl_session_t *session, buf_ctrl_t *ctrl, drc_lock_mode_e req_mode)
{
    uint64 req_version = DRC_GET_CURR_REFORM_VERSION;
    page_id_t page_id = ctrl->page_id;
    uint8 req_id = DCS_SELF_INSTID(session);
    drc_req_owner_result_t result;

    uint32 req_rsn = mes_get_rsn(session->id);
    drc_req_info_t req_info;
    req_info.inst_id = req_id;
    req_info.inst_sid = session->id;
    req_info.req_mode = req_mode;
    req_info.curr_mode = ctrl->lock_mode;
    req_info.rsn = req_rsn;
    req_info.req_time = KNL_NOW(session);
    req_info.req_version = req_version;
    req_info.lsn = dtc_get_ctrl_lsn(ctrl);

    DTC_DCS_DEBUG_INF("[DCS][%u-%u][ask master local]: src_id=%u, dest_id=%u, req_mode=%u, ctrl_lock_mode=%u "
                      "req_version=%llu, req_rsn=%u, pcn=%d, lsn=%llu",
                      page_id.file, page_id.page, DCS_SELF_INSTID(session), DCS_SELF_INSTID(session), req_mode,
                      ctrl->lock_mode, req_version, req_rsn, ctrl->page->pcn, ctrl->page->lsn);

    knl_begin_session_wait(session, DCS_REQ_MASTER4PAGE_1WAY, CT_TRUE);

    status_t ret = drc_request_page_owner(session, page_id, &req_info, CT_FALSE, &result);
    if (SECUREC_UNLIKELY(ret != CT_SUCCESS)) {
        knl_end_session_wait(session, DCS_REQ_MASTER4PAGE_1WAY);
        DTC_DCS_DEBUG_ERR("[DCS]failed to get page owner id: file=%u, page=%u, master id=%u",
            page_id.file, page_id.page, req_id);
        return CT_ERROR;
    }

    DTC_DRC_DEBUG_INF(
        "[DRC][%u-%u][ask master local, after request]: req_id=%u, req_sid=%u, req_rsn=%u, "
        "req_mode=%u, curr_mode=%u, req_version=%llu, cur_version=%llu, result=%d, action=%d, curr owner:%d",
        page_id.file, page_id.page, req_info.inst_id, req_info.inst_sid, req_info.rsn, req_info.req_mode,
        req_info.curr_mode, req_info.req_version, DRC_GET_CURR_REFORM_VERSION, result.type, result.action,
        result.curr_owner_id);

    knl_panic(result.req_mode >= req_mode);
    switch (result.type) {
        case DRC_REQ_OWNER_GRANTED: {
            knl_panic(result.action == DRC_RES_INVALID_ACTION);
            dcs_set_ctrl4granted(session, ctrl);

            knl_end_session_wait(session, DCS_REQ_MASTER4PAGE_1WAY);
            DTC_DCS_DEBUG_INF("[DCS][%u-%u][ask master local]: granted, src_id=%u, dest_id=%u, "
                "req_mode=%u, ctrl_lock_mode=%u",
                page_id.file, page_id.page, DCS_SELF_INSTID(session), DCS_SELF_INSTID(session),
                result.req_mode, ctrl->lock_mode);
            return CT_SUCCESS;
        }

        case DRC_REQ_OWNER_ALREADY_OWNER: {
            dcs_set_ctrl4already_owner(session, ctrl, result.req_mode, result.action);

            (void)dcs_claim_ownership_l(session, page_id, result.req_mode, CT_FALSE, dtc_get_ctrl_latest_lsn(ctrl),
                                        req_version);

            knl_end_session_wait(session, DCS_REQ_MASTER4PAGE_1WAY);
            return CT_SUCCESS;
        }

        case DRC_REQ_OWNER_CONVERTING: {
            // owner is another instance
            ret = dcs_ask_owner_for_page(session, ctrl, &result, result.req_mode, req_version);

            knl_end_session_wait_ex(session, DCS_REQ_MASTER4PAGE_1WAY, DCS_REQ_OWNER4PAGE);
            return ret;
        }

        case DRC_REQ_OWNER_WAITING: {
            ret = dcs_handle_ask_master_ack(session, DCS_SELF_INSTID(session), ctrl, result.req_mode, NULL);

            knl_end_session_wait_ex(session, DCS_REQ_MASTER4PAGE_1WAY, DCS_REQ_OWNER4PAGE);
            return ret;
        }

        default: {
            knl_end_session_wait(session, DCS_REQ_MASTER4PAGE_1WAY);
            knl_panic_log(0, "unexpected owner request result, type=%u", result.type);
            return CT_ERROR;
        }
    }
}

status_t dcs_request_page_internal(knl_session_t *session, buf_ctrl_t *ctrl, page_id_t page_id, drc_lock_mode_e req_mode)
{
    uint8 master_id = CT_INVALID_ID8;
    (void)drc_get_page_master_id(page_id, &master_id);

    status_t ret;
    if (master_id == DCS_SELF_INSTID(session)) {
        ret = dcs_ask_master4page_l(session, ctrl, req_mode);
    } else {
        ret = dcs_ask_master4page_r(session, ctrl, master_id, req_mode);
    }

    return ret;
}

status_t dcs_request_page(knl_session_t *session, buf_ctrl_t *ctrl, page_id_t page_id, drc_lock_mode_e mode)
{
    DTC_DCS_DEBUG_INF("[DCS][%u-%u][dcs request page]: enter", page_id.file, page_id.page);

    for (;;) {
        status_t ret = CT_SUCCESS;
        SYNC_POINT_GLOBAL_START(CANTIAN_DCS_REQUEST_PAGE_INTERNAL_FAIL, &ret, CT_ERROR);
        ret = dcs_request_page_internal(session, ctrl, page_id, mode);
        SYNC_POINT_GLOBAL_END;
        if (ret == CT_SUCCESS) {
            DTC_DCS_DEBUG_INF("[DCS][%u-%u][dcs request page]: leave, load_status=%u",
                page_id.file, page_id.page, ctrl->load_status);
            return CT_SUCCESS;
        }

        if (!dtc_dcs_readable(session)) {
            DTC_DCS_DEBUG_INF("[DCS][%u-%u] dcs not readable, stop trying to read page.", page_id.file, page_id.page);
            return ret;
        }

        if (cm_get_error_code() != ERR_DCS_MSG_EAGAIN) {
            return ret;
        }

        cm_reset_error();
        cm_sleep(DCS_RESEND_MSG_INTERVAL);
    }

    session->stat->dcs_net_time += session->stat->wait_time[DCS_REQ_MASTER4PAGE_1WAY] +
                                   session->stat->wait_time[DCS_REQ_MASTER4PAGE_1WAY] +
                                   session->stat->wait_time[DCS_REQ_MASTER4PAGE_3WAY];
}

static status_t dcs_try_get_page_share_owner_l(knl_session_t *session, drc_req_info_t *req_info, page_id_t *page_ids,
                                               uint32 count, drc_req_owner_result_t *result)
{
    for (uint32 i = 0; i < count; i++) {
        if (IS_INVALID_PAGID(page_ids[i])) {
            continue;
        }
        (void)drc_request_page_owner(session, page_ids[i], req_info, CT_TRUE, &result[i]);
        DTC_DRC_DEBUG_INF(
            "[DRC][%u-%u][try get page owner, after request]: req_id=%u, req_sid=%u, req_rsn=%u, "
            "req_mode=%u, curr_mode=%u, req_version=%llu, cur_version=%llu, result=%d, action=%d, curr owner:%d",
            page_ids[i].file, page_ids[i].page, req_info->inst_id, req_info->inst_sid, req_info->rsn,
            req_info->req_mode, req_info->curr_mode, req_info->req_version, DRC_GET_CURR_REFORM_VERSION, result[i].type,
            result[i].action, result[i].curr_owner_id);
    }
    return CT_SUCCESS;
}

status_t dcs_try_get_page_share_owner(knl_session_t *session, buf_ctrl_t **ctrl_array, page_id_t *page_ids,
                                      uint32 count, uint8 master_id, uint32 *valid_count)
{
    drc_req_owner_result_t *result = (drc_req_owner_result_t *)cm_push(session->stack,
                                                                       sizeof(drc_req_owner_result_t) * count);
    if (NULL == result) {
        CT_LOG_RUN_ERR("[DCS] req owner result failed to malloc memory");
        return CT_ERROR;
    }
    status_t ret;

    for (uint32 i = 0; i < count; i++) {
        result[i].type = DRC_REQ_OWNER_INVALID;
    }
#ifdef DB_DEBUG_VERSION
    char msg[SIZE_K(2)] = { 0 };
    uint16 msg_len = SIZE_K(2);
    uint32 pos = 0;
    int iret_snprintf;
    for (uint32 i = 0; i < count; i++) {
        if (!IS_INVALID_PAGID(page_ids[i])) {
            iret_snprintf = snprintf_s(msg + pos, msg_len - pos, msg_len - pos - 1, "%u-%u, ", page_ids[i].file,
                                       page_ids[i].page);
            if (SECUREC_UNLIKELY(iret_snprintf == -1)) {
                knl_panic_log(0, "Secure C lib has thrown an error %d", iret_snprintf);
            }
            pos += iret_snprintf;
        }
    }
    DTC_DCS_DEBUG_INF("[DCS][try get share owner for pages]: %s", msg);
#endif
    if (master_id == DCS_SELF_INSTID(session)) {
        drc_req_info_t req_info;
        req_info.inst_id = DCS_SELF_INSTID(session);
        req_info.inst_sid = session->id;
        req_info.req_mode = DRC_LOCK_SHARE;
        req_info.curr_mode = DRC_LOCK_NULL;
        req_info.rsn = CT_INVALID_ID32;
        req_info.req_time = KNL_NOW(session);
        req_info.req_version = DRC_GET_CURR_REFORM_VERSION;
        req_info.lsn = 0;
        ret = dcs_try_get_page_share_owner_l(session, &req_info, page_ids, count, result);
    } else {
        knl_panic(master_id != CT_INVALID_ID8);
        ret = dcs_try_get_page_share_owner_r(session, page_ids, count, master_id, result);
    }

#ifdef DB_DEBUG_VERSION
    pos = 0;
    for (uint32 i = 0; i < count; i++) {
        if (!IS_INVALID_PAGID(page_ids[i])) {
            iret_snprintf = snprintf_s(msg + pos, msg_len - pos, msg_len - pos - 1, "%u-%u:%d, ", page_ids[i].file,
                                       page_ids[i].page, result[i].type);
            if (SECUREC_UNLIKELY(iret_snprintf == -1)) {
                knl_panic_log(0, "Secure C lib has thrown an error %d", iret_snprintf);
            }
            pos += iret_snprintf;
        }
    }
    DTC_DCS_DEBUG_INF("[DCS][after try get share owner for pages]: %s", msg);
#endif

    *valid_count = 0;
    for (uint32 i = 0; i < count; i++) {
        switch (result[i].type) {
            case DRC_REQ_OWNER_GRANTED: {
                knl_panic(result[i].action == DRC_RES_INVALID_ACTION);
                dcs_set_ctrl4granted(session, ctrl_array[i]);
                page_ids[i] = INVALID_PAGID;
                break;
            }

            case DRC_REQ_OWNER_ALREADY_OWNER: {
                dcs_set_ctrl4already_owner(session, ctrl_array[i], result[i].req_mode, result[i].action);
                (*valid_count)++;
                // keep page id in array page_ids, so that we can claim those pages later
                break;
            }
            default: {
                knl_panic(result[i].type != DRC_REQ_OWNER_CONVERTING);
                DTC_DRC_DEBUG_INF("[DCS][%u-%u][dcs try get page owner] failed, master_id:%u, session_inst_id:%u",
                                  page_ids[i].file, page_ids[i].page, master_id, session->kernel->id);
                page_ids[i] = INVALID_PAGID;
            }
        }
    }

    /*
       both of below 3 cases, we can't do batch load, flag BUF_NEED_TRANSFER will set ctrl to NULL
       1) current node is already owner, but since this request is not in queue, we can't call
       dcs_set_ctrl4already_owner to change local lock_mode since other node may be claiming the ownership and change
       local lock_mode at the same time. 2) page owner is on other instance. 3) get ownership failed
    */
    cm_pop(session->stack);

    return ret;
}

status_t dcs_claim_page_share_owners_r(knl_session_t *session, page_id_t *page_ids, uint32 count, uint8 master_id)
{
    status_t ret;
    uint64 req_version = DRC_GET_CURR_REFORM_VERSION;

    msg_claim_owner_batch_t request;

    mes_init_send_head(&request.head, MES_CMD_CLAIM_OWNER_REQ_BATCH, sizeof(msg_claim_owner_batch_t), CT_INVALID_ID32,
                       session->kernel->dtc_attr.inst_id, master_id, session->id, CT_INVALID_ID16);
    request.count = count;
    errno_t err_s;
    err_s = memcpy_s(request.page_ids, count * sizeof(page_id_t), page_ids, count * sizeof(page_id_t));
    knl_securec_check(err_s);
    request.req_version = req_version;

    SYNC_POINT_GLOBAL_START(CANTIAN_DCS_CLAIM_OWNER_SEND_FAIL, &ret, CT_ERROR);
    ret = dcs_send_data_retry(&request);
    SYNC_POINT_GLOBAL_END;
    DTC_DCS_DEBUG(ret, "[DCS]: after send batch claim, src_id=%u, dest_id=%u, count=%d", request.head.src_inst,
                  request.head.dst_inst, count);
    return ret;
}

status_t dcs_claim_page_share_owners(knl_session_t *session, page_id_t *page_ids, uint32 count, uint8 master_id)
{
    status_t ret = CT_SUCCESS;
    uint64 req_version = DRC_GET_CURR_REFORM_VERSION;
#ifdef DB_DEBUG_VERSION
    char msg[SIZE_K(2)] = { 0 };
    uint16 msg_len = SIZE_K(2);
    uint32 pos = 0;
    int iret_snprintf;
    for (uint32 i = 0; i < count; i++) {
        if (!IS_INVALID_PAGID(page_ids[i])) {
            iret_snprintf = snprintf_s(msg + pos, msg_len - pos, msg_len - pos - 1, "%u-%u, ", page_ids[i].file,
                                       page_ids[i].page);
            if (SECUREC_UNLIKELY(iret_snprintf == -1)) {
                knl_panic_log(0, "Secure C lib has thrown an error %d", iret_snprintf);
            }
            pos += iret_snprintf;
        }
    }
    DTC_DCS_DEBUG_INF("[DCS][try to claim share page owner for pages]: %s", msg);
#endif
    if (master_id == DCS_SELF_INSTID(session)) {
        for (uint32 i = 0; i < count; i++) {
            if (IS_INVALID_PAGID(page_ids[i])) {
                continue;
            }
            (void)dcs_claim_ownership_l(session, page_ids[i], DRC_LOCK_SHARE, CT_FALSE, 0, req_version);
        }
    } else {
        knl_panic(master_id != CT_INVALID_ID8);
        ret = dcs_claim_page_share_owners_r(session, page_ids, count, master_id);
    }

    return ret;
}

void dcs_process_recycle_owner(void *sess, mes_message_t *receive_msg)
{
    if (sizeof(msg_recycle_owner_req_t) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("process recycle owner msg is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    msg_recycle_owner_req_t *req = (msg_recycle_owner_req_t *)(receive_msg->buffer);
    knl_session_t *session = (knl_session_t *)sess;

    if (req->head.src_inst != DCS_SELF_INSTID(session)) {
        dtc_update_lsn(session, req->owner_lsn);
        dtc_update_scn(session, req->owner_scn);
    }

    for (uint32 i = 0; i < RECYCLE_PAGE_NUM; i++) {
        DTC_DCS_DEBUG_INF(
            "[DCS][%u-%u][%s]: process recycle owner, owner_lsn=%llu, owner_scn=%llu, src_id=%d, req_time=%lld, num=%u",
            req->pageids[i].file, req->pageids[i].page, MES_CMD2NAME(req->head.cmd), req->owner_lsn, req->owner_scn,
            req->head.src_inst, req->req_start_times[i], i);
        drc_buf_res_recycle(session, req->head.src_inst, req->req_start_times[i], req->pageids[i], req->req_version);
    }
    mes_release_message_buf(receive_msg->buffer);
}

void dcs_clean_edp_pages_local(knl_session_t *session, edp_page_info_t *pages, uint32 page_count)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    uint32 i = 0;
    uint32 times = 0;

    if (page_count == 0) {
        return;
    }

    knl_panic(!DAAC_CKPT_SESSION(session));
    ckpt_clean_edp_group_t* group = &ctx->local_edp_clean_group;
    CT_LOG_DEBUG_INF("[CKPT] local prepare to clean (%d) edp flag", page_count);

    ckpt_sort_page_id_array(pages, page_count);
    cm_spin_lock(&group->lock, NULL);
    while (i < page_count && !CKPT_CLOSED(session)) {
        i = ckpt_merge_to_array(pages, i, page_count - i, group->pages, &group->count, CT_CLEAN_EDP_GROUP_SIZE);
        if (i == page_count) {
            break;
        }
        cm_spin_unlock(&group->lock);
        ckpt_trigger(session, CT_FALSE, CKPT_TRIGGER_INC);
        if (times++ > CKPT_TRY_ADD_TO_GROUP_TIMES * 2 || !ctx->ckpt_enabled) {
            CT_LOG_DEBUG_WAR("[CKPT] local edp clean group is full when local prepare to clean (%d) edp flag"
                             "or ckpt is disabled %d", page_count, ctx->ckpt_enabled);
            return;
        }
        cm_sleep(300);
        cm_spin_lock(&group->lock, NULL);
        continue;
    }
    cm_spin_unlock(&group->lock);
    ckpt_trigger(session, CT_FALSE, CKPT_TRIGGER_INC);
}

status_t dcs_master_clean_edp(knl_session_t *session, edp_page_info_t *pages, uint32 start, uint32 end, uint32 length)
{
    CT_LOG_DEBUG_INF("[CKPT][master process request to clean edp flag]: src_id=%u, count=%d", DCS_SELF_INSTID(session), end - start);

    if (start >= end) {
        return CT_SUCCESS;
    }
    if (end > length) {
        CT_LOG_RUN_ERR("[CKPT] invalid idx end %u", end);
        return CT_ERROR;
    }
    knl_panic(end - start <= CT_CKPT_EDP_GROUP_SIZE(session));
    msg_ckpt_edp_request_t *msg = (msg_ckpt_edp_request_t *)cm_push(session->stack, CT_MSG_EDP_REQ_SIZE(session));
    if (msg == NULL) {
        CT_LOG_RUN_ERR("msg failed to malloc memory");
        return CT_ERROR;
    }
    status_t status;

    int32 idx_start = start;
    int32 idx_end = end;
    page_id_t page_id;
    drc_edp_info_t edp_info;
    status_t ret;
    cluster_view_t view;

    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        rc_get_cluster_view(&view, CT_FALSE);
        if (!rc_bitmap64_exist(&view.bitmap, i)) {
            CT_LOG_RUN_INF("[CKPT] inst id (%u) is not alive, alive bitmap: %llu", i, view.bitmap);
            continue;
        }

        if (i == DCS_SELF_INSTID(session) && DAAC_CKPT_SESSION(session)) {
            // current node is page owner
            continue;
        }

        msg->count = 0;
        idx_start = start;
        while (idx_start < idx_end) {
            page_id = pages[idx_start].page;
            if (page_id.file >= INVALID_FILE_ID || (page_id.page == 0 && page_id.file == 0)) {
                CT_LOG_RUN_ERR("[%u-%u] page_id invalid,", page_id.file, page_id.page);
                cm_pop(session->stack);
                return CT_ERROR;
            }

            ret = drc_get_edp_info(page_id, &edp_info);
            if (ret != CT_SUCCESS) {
                CT_LOG_DEBUG_INF("[CKPT][%u-%u][master process failed to get edp info", page_id.file, page_id.page);
                --idx_end;
                SWAP(edp_page_info_t, pages[idx_start], pages[idx_end]);
                continue;
            }

            if (MES_IS_INST_SEND(edp_info.edp_map, DCS_SELF_INSTID(session)) && DAAC_CKPT_SESSION(session)) {
                CT_LOG_DEBUG_INF(
                    "[CKPT][%u-%u][master process ignore request to clean edp flag, owner transfer to other node",
                    page_id.file, page_id.page);
                --idx_end;
                SWAP(edp_page_info_t, pages[idx_start], pages[idx_end]);
                continue;
            }

            if (edp_info.lsn > pages[idx_start].lsn) {
                CT_LOG_DEBUG_INF(
                    "[CKPT][%u-%u][master process ignore request to clean edp flag, drc edp has larger lsn (%lld) than clean request (%lld)",
                    page_id.file, page_id.page, edp_info.lsn, pages[idx_start].lsn);
                --idx_end;
                SWAP(edp_page_info_t, pages[idx_start], pages[idx_end]);
                continue;
            }

            if (edp_info.edp_map == 0) {
                CT_LOG_DEBUG_INF(
                    "[CKPT][%u-%u][edp map on master is 0, need to broadcast to clean edp in case previous clean edp msg is lost",
                    page_id.file, page_id.page);
            }

            if (edp_info.edp_map == 0 || MES_IS_INST_SEND(edp_info.edp_map, i)) {
                msg->edp_pages[msg->count++] = pages[idx_start];
            }
            idx_start++;
        }

        if (msg->count == 0) {
            continue;
        }

        if ((i == DCS_SELF_INSTID(session)) && !DAAC_CKPT_SESSION(session)) {
            dcs_clean_edp_pages_local(session, msg->edp_pages, msg->count);
            continue;
        }

        mes_init_send_head(&msg->head, MES_CMD_CLEAN_EDP_REQ, CT_MSG_EDP_REQ_SEND_SIZE(msg->count),
            CT_INVALID_ID32, DCS_SELF_INSTID(session), i, DCS_SELF_SID(session), CT_INVALID_ID16);
        status = dcs_send_data_retry((void *)msg);
        if (status != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[CKPT][%u-%u] send message failed, inst id(%u) is not alive",
                page_id.file, page_id.page, i);
            continue;
        }

        CT_LOG_DEBUG_INF("[CKPT] broadcast clean (%d) edp flags to edp node %d", msg->count, i);
    }

    for (idx_start = start; idx_start < idx_end; idx_start++) {
        page_id = pages[idx_start].page;
        (void)drc_clean_edp_info(pages[idx_start]);  // should double check if the clean action is right
        CT_LOG_DEBUG_INF("[CKPT][%u-%u][master process clean edp info", page_id.file, page_id.page);
    }
    cm_pop(session->stack);
    return CT_SUCCESS;
}

status_t dcs_clean_edp(knl_session_t *session, ckpt_context_t *ctx)
{
    if (!DB_IS_CLUSTER(session) || ctx->remote_edp_clean_group.count == 0) {
        return CT_SUCCESS;
    }

    uint8 master_id;
    uint32 notify_master_idx = 0;
    errno_t ret;
    status_t status;
    edp_page_info_t *pages = ctx->remote_edp_clean_group.pages;
    uint32 count = ctx->remote_edp_clean_group.count;
    ctx->remote_edp_clean_group.count = 0;

    for (uint32 i = 0; i < count; i++) {
        if ((pages[i].page.page == 0 && pages[i].page.file == 0) || pages[i].page.file >= INVALID_FILE_ID) {
            CT_LOG_RUN_ERR("[%u-%u][dcs] dcs clean edp pageid is invalid", pages[i].page.page, pages[i].page.file);
            return CT_ERROR;
        }
        if (drc_get_page_master_id(pages[i].page, &master_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (master_id != DCS_SELF_INSTID(session)) {
            SWAP(edp_page_info_t, pages[i], pages[notify_master_idx]);
            notify_master_idx++;
        }
    }

    // local node is master
    uint32 page_start = notify_master_idx;
    uint32 page_end = notify_master_idx;
    while (page_end < count) {
        page_end = MIN(page_start + CT_CKPT_EDP_GROUP_SIZE(session), count);
        status = dcs_master_clean_edp(session, pages, page_start, page_end, CT_CKPT_GROUP_SIZE(session) + 1);
        if (status != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[CKPT] master process local clean edp flag failed, notify_master_idx=%d", notify_master_idx);
            return CT_ERROR;
        }
        page_start = page_end;
    }

    if (notify_master_idx == 0) {
        return CT_SUCCESS;
    }

    // master is on other nodes
    msg_ckpt_edp_request_t *msg = (msg_ckpt_edp_request_t *)cm_push(session->stack, CT_MSG_EDP_REQ_SIZE(session));
    if (msg == NULL) {
        CT_LOG_RUN_ERR("msg failed to malloc memory");
        return CT_ERROR;
    }
    uint32 page_left = notify_master_idx;
    uint32 page_sent = 0;
    while (page_left > 0) {
        msg->count = MIN(CT_CKPT_EDP_GROUP_SIZE(session), page_left);
        ret = memcpy_sp((char*)msg->edp_pages, msg->count * sizeof(edp_page_info_t),
                        (char*)ctx->remote_edp_clean_group.pages + page_sent * sizeof(edp_page_info_t), msg->count * sizeof(edp_page_info_t));
        knl_securec_check(ret);

        mes_init_send_head(&msg->head, MES_CMD_NOTIFY_MASTER_CLEAN_EDP_REQ, CT_MSG_EDP_REQ_SEND_SIZE(msg->count),
                           CT_INVALID_ID32, g_dtc->profile.inst_id, 0, session->id, CT_INVALID_ID16);
        mes_broadcast(session->id, MES_BROADCAST_ALL_INST, msg, NULL);

        page_sent += msg->count;
        page_left -= msg->count;
    }

    CT_LOG_DEBUG_INF("[CKPT] broadcast (%d) clean edp flag, total %d edp pages to master", notify_master_idx, count);
    cm_pop(session->stack);
    return CT_SUCCESS;
}

static inline status_t dcs_request_edpinfo_r(knl_session_t *session, uint8 master_id, page_id_t page_id,
                                             drc_edp_info_t *edp_info)
{
    msg_edpinfo_req_t req;

    mes_init_send_head(&req.head, MES_CMD_EDPINFO_REQ, sizeof(msg_edpinfo_req_t), CT_INVALID_ID32,
                       DCS_SELF_INSTID(session), 0, DCS_SELF_SID(session), CT_INVALID_ID16);
    req.page_id = page_id;

    status_t ret = mes_send_data((void *)&req);

    DTC_DCS_DEBUG_INF("[DCS][%u-%u][%s]:dest_id=%u, dest_sid=%u, rsn=%u, result=%u", page_id.file, page_id.page,
                      MES_CMD2NAME(req.head.cmd), req.head.dst_inst, req.head.dst_sid, req.head.rsn, ret);

    if (SECUREC_UNLIKELY(ret != CT_SUCCESS)) {
        return CT_ERROR;
    }

    mes_message_t msg;
    ret = mes_recv(session->id, &msg, CT_TRUE, req.head.rsn, MES_WAIT_MAX_TIME);

    DTC_DCS_DEBUG_INF("[DCS][%u-%u][edpinfo ack]:result=%u", page_id.file, page_id.page, ret);

    if (SECUREC_UNLIKELY(ret != CT_SUCCESS)) {
        return CT_ERROR;
    }

    if (msg.head->cmd == MES_CMD_EDPINFO_ACK) {
        msg_edpinfo_ack_t *ack = (msg_edpinfo_ack_t *)msg.buffer;
        *edp_info = ack->edp_info;
        ret = CT_SUCCESS;
    } else {
        ret = CT_ERROR;
    }

    mes_release_message_buf(msg.buffer);
    return ret;
}

status_t dcs_request_edpinfo(knl_session_t *session, page_id_t page_id, drc_edp_info_t *edp_info)
{
    uint8 master_id = CT_INVALID_ID8;

    if (drc_get_page_master_id(page_id, &master_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (master_id != DCS_SELF_INSTID(session)) {
        return dcs_request_edpinfo_r(session, master_id, page_id, edp_info);
    }

    return drc_get_edp_info(page_id, edp_info);
}

void dcs_process_notify_master_clean_edp_req(void *sess, mes_message_t * receive_msg)
{
    if (sizeof(msg_ckpt_edp_request_t) > receive_msg->head->size) {
        CT_LOG_RUN_ERR("process notify master clean edp is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    msg_ckpt_edp_request_t *req = (msg_ckpt_edp_request_t *)receive_msg->buffer;
    if (CT_MSG_EDP_REQ_SEND_SIZE(req->count) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("process notify master clean edp is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    knl_session_t *session = (knl_session_t *)sess;
    edp_page_info_t *pages = req->edp_pages;
    uint32 count = req->count;
    uint8 master_id;
    uint32 notify_master_idx = 0;
    page_id_t page_id;
    if (count > CT_CKPT_EDP_GROUP_SIZE(session)) {
        CT_LOG_RUN_ERR("req->count(%d) err, larger than %u", count, CT_CKPT_EDP_GROUP_SIZE(session));
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    // knl_panic(count <= CT_CKPT_EDP_GROUP_SIZE(session));

    DTC_DCS_DEBUG_INF("[CKPT]master start to process clean edp flag req, src_id=%u, src_sid=%u, dest_id=%u, dest_sid=%u",
        req->head.src_inst, req->head.src_sid, req->head.dst_inst, req->head.dst_sid);

    for (uint32 i = 0; i < count; i++) {
        page_id = pages[i].page;
        if (page_id.file >= INVALID_FILE_ID || (page_id.page == 0 && page_id.file == 0)) {
            CT_LOG_RUN_ERR("[%u-%u] page_id invalid,", page_id.file, page_id.page);
            mes_release_message_buf(receive_msg->buffer);
            return;
        }
        // knl_panic(!(page_id.page == 0 && page_id.file == 0));
        // knl_panic(page_id.file != INVALID_FILE_ID);
        if (drc_get_page_master_id(page_id, &master_id) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("get master for page[%u-%u] failed,", page_id.file, page_id.page);
            mes_release_message_buf(receive_msg->buffer);
            return;
        }
        if (master_id != DCS_SELF_INSTID(session)) {
            SWAP(edp_page_info_t, pages[i], pages[notify_master_idx]);
            notify_master_idx++;
        }
    }

    (void)dcs_master_clean_edp(session, pages, notify_master_idx, count, CT_CKPT_EDP_GROUP_SIZE(session));

    mes_release_message_buf(receive_msg->buffer);
}

void dcs_process_clean_edp_req(void *sess, mes_message_t * receive_msg)
{
    if (sizeof(msg_ckpt_edp_request_t) > receive_msg->head->size) {
        CT_LOG_RUN_ERR("process clean edp is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    msg_ckpt_edp_request_t *req = (msg_ckpt_edp_request_t *)receive_msg->buffer;
    if (CT_MSG_EDP_REQ_SEND_SIZE(req->count) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("process notify master clean edp is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    knl_session_t *session = (knl_session_t *)sess;

    if (req->count > CT_CKPT_EDP_GROUP_SIZE(session)) {
        CT_LOG_RUN_ERR("req->count(%d) err, larger than %u", req->count, CT_CKPT_EDP_GROUP_SIZE(session));
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    // knl_panic(req->count <= CT_CKPT_EDP_GROUP_SIZE);
    dcs_clean_edp_pages_local(session, req->edp_pages, req->count);
    mes_release_message_buf(receive_msg->buffer);
}

void dcs_process_edpinfo_req(    void *sess, mes_message_t * receive_msg)
{
    if (sizeof(msg_edpinfo_req_t) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("process edpinfo req is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    msg_edpinfo_req_t *req = (msg_edpinfo_req_t *)receive_msg->buffer;
    page_id_t page_id = req->page_id;
    knl_session_t *session = (knl_session_t *)sess;

    DTC_DCS_DEBUG_INF("[DCS][%u-%u][%s]: src_id=%u, src_sid=%u, dest_id=%u, dest_sid=%u",
        page_id.file, page_id.page, MES_CMD2NAME(req->head.cmd), req->head.src_inst, req->head.src_sid, req->head.dst_inst, req->head.dst_sid);

    msg_edpinfo_ack_t ack;
    status_t ret = drc_get_edp_info(page_id, &ack.edp_info);
    if (SECUREC_UNLIKELY(ret != CT_SUCCESS)) {
        mes_send_error_msg(receive_msg->head);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }

    mes_init_ack_head(&req->head, &ack.head, MES_CMD_EDPINFO_ACK, sizeof(msg_edpinfo_ack_t), session->id);

    ret = mes_send_data(&ack);
    DTC_DCS_DEBUG_INF("[DCS][%u-%u][%s]: dest_id=%u, dest_sid=%u, result=%u",
        page_id.file, page_id.page, MES_CMD2NAME(ack.head.cmd), ack.head.dst_inst, ack.head.dst_sid, ret);
    mes_release_message_buf(receive_msg->buffer);
}

void dcs_process_page_req(void *sess, mes_message_t * msg)
{
    dtc_page_req_t *req = (dtc_page_req_t *)msg->buffer;
    mes_message_head_t ack_head;
    page_id_t          pagid;
    knl_session_t *session = (knl_session_t *)sess;
    /*
    printf("send page to instance %d sid %d, page id %d:%d\n",
        (int32)req->head.src_inst, (int32)req->head.src_sid, (int32)req->pagid.file, (int32)req->pagid.page);
    */

    mes_init_ack_head(&req->head, &ack_head, MES_CMD_PAGE_ACK, (DEFAULT_PAGE_SIZE(session) + sizeof(mes_message_head_t)), session->id);
    pagid = req->pagid;

    mes_release_message_buf(msg->buffer);
    buf_enter_page(session, pagid, LATCH_MODE_S, 0);
    mes_send_data2(&ack_head, (void *)session->curr_page);
    buf_leave_page(session, CT_FALSE);
    return;
}

void dcs_process_invld_req(void *sess, mes_message_t * msg)
{
    knl_begin_session_wait(sess, DCS_INVLDT_READONLY_PROCESS, CT_TRUE);
    if (sizeof(dtc_page_req_t) != msg->head->size) {
        CT_LOG_RUN_ERR("process invld req msg is invalid, msg size %u.", msg->head->size);
        mes_release_message_buf(msg->buffer);
        return;
    }
    dtc_page_req_t *req = (dtc_page_req_t *)msg->buffer;
    mes_message_head_t ack_head = {0};
    knl_session_t *session = (knl_session_t *)sess;
    page_id_t pagid = req->pagid;
    if (IS_INVALID_PAGID(pagid)) {
        CT_LOG_RUN_ERR("[DCS][%u-%u] process invalid req failed, page_id invalid", pagid.file, pagid.page);
        mes_release_message_buf(msg->buffer);
        return;
    }
    bool32 is_owner = (req->head.flags & MES_FLAG_OWNER);
    mes_command_t ack_type = is_owner ? MES_CMD_INVLDT_ACK : MES_CMD_BROADCAST_ACK;
    status_t ret;
    SYNC_POINT_GLOBAL_START(CANTIAN_DCS_INVALID_PROC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    mes_init_ack_head(&(req->head), &ack_head, ack_type, sizeof(mes_message_head_t), session->id);

    DTC_DCS_DEBUG_INF("[DCS][%u-%u][%s]: started, src_id=%u, src_sid=%u, owner=%d", pagid.file, pagid.page,
                      MES_CMD2NAME(req->head.cmd), req->head.src_inst, req->head.src_sid, is_owner);

    // if reforming, stop invalidate readonly copy
    if (DRC_STOP_DCS_IO_FOR_REFORMING(req->req_version, session)) {
        CT_LOG_RUN_ERR("[DCS][%u-%u]reforming, invalidate copy failed, req_version=%llu, cur_version=%llu",
            pagid.file, pagid.page, req->req_version, DRC_GET_CURR_REFORM_VERSION);
        ret = CT_ERROR;
    } else {
        if (!is_owner) {
            ret = buf_invalidate_page_with_version(session, pagid, req->req_version);
        } else {
            ret = buf_invalidate_page_owner(session, pagid, req->req_version);
        }
    }
    mes_release_message_buf(msg->buffer);

    ack_head.status = ret;
    ret = dcs_send_data_retry(&ack_head);

    DTC_DCS_DEBUG(ret,
                  "[DCS][%u-%u][%s]: finished, status(%d), invalidate status(%d),dest_id=%u, dest_sid=%u, owner=%d",
                  pagid.file, pagid.page, MES_CMD2NAME(ack_head.cmd), ret, ack_head.status, ack_head.dst_inst,
                  ack_head.dst_sid, is_owner);

    knl_end_session_wait(sess, DCS_INVLDT_READONLY_PROCESS);
}

/*
    exception - don't send msg to specified instance for some scenarios.
*/
status_t dcs_invalidate_readonly_copy(knl_session_t *session, page_id_t page_id, uint64 readonly_copies,
                                      uint8 exception, uint64 req_version)
{
    knl_begin_session_wait(session, DCS_INVLDT_READONLY_REQ, CT_TRUE);
    uint64 invld_insts = readonly_copies;
    if (exception >= CT_MAX_INSTANCES) {
        CT_LOG_RUN_ERR("invalid inst id(%u)", exception);
        return CT_ERROR;
    }
    if (exception != CT_INVALID_ID8) {
        drc_bitmap64_clear(&invld_insts, exception);
    }

    // if reforming, stop invalidate readonly copy
    if (DRC_STOP_DCS_IO_FOR_REFORMING(req_version, session)) {
        CT_LOG_RUN_ERR("[DCS][%u-%u]reforming, invalidate copy failed,, req_version=%llu, cur_version=%llu",
            page_id.file, page_id.page, req_version, DRC_GET_CURR_REFORM_VERSION);
        knl_end_session_wait(session, DCS_INVLDT_READONLY_REQ);
        return CT_ERROR;
    }

    if (drc_bitmap64_exist(&invld_insts, DCS_SELF_INSTID(session))) {
        if (buf_invalidate_page_with_version(session, page_id, req_version) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DCS][%u-%u]reforming, invalidate copy failed,, req_version=%llu, cur_version=%llu",
                page_id.file, page_id.page, req_version, DRC_GET_CURR_REFORM_VERSION);
            return CT_ERROR;
        }
        drc_bitmap64_clear(&invld_insts, DCS_SELF_INSTID(session));
    }

    if (!invld_insts) {
        knl_end_session_wait(session, DCS_INVLDT_READONLY_REQ);
        return CT_SUCCESS;
    }

    dtc_page_req_t req;
    mes_init_send_head(&req.head, MES_CMD_INVLDT_REQ, sizeof(dtc_page_req_t), CT_INVALID_ID32, DCS_SELF_INSTID(session),
                       0, session->id, CT_INVALID_ID16);
    req.pagid = page_id;
    req.req_version = req_version;

    // if reforming, stop invalidate readonly copy
    if (DRC_STOP_DCS_IO_FOR_REFORMING(req_version, session)) {
        CT_LOG_RUN_ERR("[DCS][%u-%u]reforming, invalidate copy failed, req_version=%llu, cur_version=%llu",
            page_id.file, page_id.page, req_version, DRC_GET_CURR_REFORM_VERSION);
        knl_end_session_wait(session, DCS_INVLDT_READONLY_REQ);
        return CT_ERROR;
    }

    status_t ret = mes_broadcast_data_and_wait_with_retry(session->id, invld_insts, (void *)&req,
                                                          DCS_WAIT_MSG_TIMEOUT, DCS_MAX_RETRY_TIEMS);

    DTC_DCS_DEBUG_INF("[DCS][%u-%u][invalidate readonly copy]: copy_insts=%llu, invld_insts=%llu, exception=%u, ret=%d",
                      page_id.file, page_id.page, readonly_copies, invld_insts, exception, ret);

    knl_end_session_wait(session, DCS_INVLDT_READONLY_REQ);
    return ret;
}

status_t dcs_invalidate_page_owner(knl_session_t *session, page_id_t page_id, uint8 owner_id, uint64 req_version)
{
    status_t ret;
    knl_begin_session_wait(session, DCS_INVLDT_READONLY_REQ, CT_TRUE);

    if (owner_id == DCS_SELF_INSTID(session)) {
        ret = buf_invalidate_page_owner(session, page_id, req_version);
        knl_end_session_wait(session, DCS_INVLDT_READONLY_REQ);
        return ret;
    }

    dtc_page_req_t req;
    mes_init_send_head(&req.head, MES_CMD_INVLDT_REQ, sizeof(dtc_page_req_t), CT_INVALID_ID32, DCS_SELF_INSTID(session),
                       owner_id, session->id, CT_INVALID_ID16);
    req.pagid = page_id;
    req.head.flags = MES_FLAG_OWNER;
    req.req_version = req_version;

    if (dcs_send_data_retry(&req) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DCS][%u-%u][%s]: mes send data failed, src_id=%u, src_sid=%u, dest_id=%u, dest_sid=%u",
            page_id.file, page_id.page, MES_CMD2NAME(req.head.cmd), req.head.src_inst, req.head.src_sid,
            req.head.dst_inst, req.head.dst_sid);
        knl_end_session_wait(session, DCS_INVLDT_READONLY_REQ);
        return CT_ERROR;
    }

    mes_message_t msg;
    if (mes_recv(session->id, &msg, CT_TRUE, req.head.rsn, MES_WAIT_MAX_TIME) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DCS][%u-%u][%s]: invalidate owner time out, src_id=%u, src_sid=%u, dest_id=%u, dest_sid=%u",
            page_id.file, page_id.page, MES_CMD2NAME(req.head.cmd), req.head.src_inst, req.head.src_sid,
            req.head.dst_inst, req.head.dst_sid);
        knl_end_session_wait(session, DCS_INVLDT_READONLY_REQ);
        return CT_ERROR;
    }

    ret = msg.head->status;

    DTC_DCS_DEBUG(ret, "[DCS][%u-%u][%s]: src_id=%u, src_sid=%u, dest_id=%u, dest_sid=%u, result=%d", page_id.file,
                  page_id.page, MES_CMD2NAME(req.head.cmd), req.head.src_inst, req.head.src_sid, req.head.dst_inst,
                  req.head.dst_sid, ret);
    mes_release_message_buf(msg.buffer);
    knl_end_session_wait(session, DCS_INVLDT_READONLY_REQ);

    return ret;
}

void dcs_process_ddl_broadcast(void *sess, mes_message_t * msg)
{
    uint32 offset = sizeof(msg_ddl_info_t);
    uint32 verify_offset = sizeof(msg_ddl_info_t);
    if (sizeof(msg_ddl_info_t) > msg->head->size) {
        CT_LOG_RUN_ERR("msg ddl broadcast is invalid, msg size %u.", msg->head->size);
        mes_release_message_buf(msg->buffer);
        return;
    }
    msg_ddl_info_t *info = (msg_ddl_info_t *)((char *)msg->buffer);
    if (sizeof(msg_ddl_info_t) + info->log_len != msg->head->size) {
        CT_LOG_RUN_ERR("msg ddl broadcast is invalid, msg size %u.", msg->head->size);
        mes_release_message_buf(msg->buffer);
        return;
    }
    knl_scn_t lamport_scn = info->scn;
    log_entry_t *log = NULL;
    uint32 log_len = info->log_len;
    mes_message_head_t head;
    knl_session_t *session = (knl_session_t *)sess;
    while (verify_offset < log_len + sizeof(msg_ddl_info_t)) {
        log = (log_entry_t *)((char*)info + verify_offset);
        verify_offset += log->size;
    }
    if (log_len + sizeof(msg_ddl_info_t) != verify_offset) {
        CT_LOG_RUN_ERR(
            "log len(%u) and offset(%u) is not invalid, not process this sync ddl message, wait retry message", log_len,
            verify_offset);
        return;
    }
    dtc_update_scn(session, lamport_scn);

    SYNC_POINT_GLOBAL_START(CANTIAN_SYNC_DDL_BEFORE_BCAST_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    while (offset < log_len + sizeof(msg_ddl_info_t)) {
        log = (log_entry_t *)((char*)info + offset);
        if (dtc_refresh_ddl(session, log) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("refresh ddl failed, not process this sync ddl message, wait retry message");
            return;
        }
        offset += log->size;
    }

    mes_init_ack_head(msg->head, &head, MES_CMD_DDL_BROADCAST_ACK, sizeof(mes_message_head_t), CT_INVALID_ID16);

    mes_release_message_buf(msg->buffer);
    if (mes_send_data(&head) != CT_SUCCESS) {
        CM_ASSERT(0);
    }

    //sanity check
#ifdef LOG_DIAG
    knl_panic(!session->atomic_op);
#endif
    knl_panic(!DB_IS_PRIMARY(&session->kernel->db) || !DB_IS_READONLY(session));
    knl_panic(session->page_stack.depth == 0);
    knl_panic(session->dirty_count == 0);
    knl_panic(session->changed_count == 0);
    knl_panic(DAAC_REPLAY_NODE(session));
}

static void dcs_init_pcr_request(knl_session_t *session, cr_cursor_t *cursor, cr_type_t type, msg_pcr_request_t *request)
{
    request->cr_type = type;
    request->page_id = GET_ROWID_PAGE(cursor->rowid);
    request->xid = cursor->xid;
    request->query_scn = cursor->query_scn;
    request->ssn = cursor->ssn;
    request->ssi_conflict = cursor->ssi_conflict;
    request->cleanout = cursor->cleanout;
    request->force_cvt = 0;
}

static status_t dcs_send_pcr_request(knl_session_t *session, msg_pcr_request_t *request,
    cr_cursor_t *cursor, uint8 dst_id)
{
    bool8 local_cr = g_dtc->profile.enable_rmo_cr || cursor->local_cr;
    request->head.dst_inst = local_cr ? request->head.src_inst : dst_id;
    request->ssi_conflict = cursor->ssi_conflict;
    request->cleanout = cursor->cleanout;
    request->local_cr = local_cr;

    DTC_DCS_DEBUG_INF("[PCR][%u-%u][send pcr request] cr_type %u query_scn %llu query_ssn %u "
                      "src_inst %u src_sid %u dst_inst %u local_cr %u force_cvt %u",
                      (uint32)request->page_id.file, (uint32)request->page_id.page, request->cr_type,
                      request->query_scn, request->ssn, request->head.src_inst, request->head.src_sid, dst_id,
                      request->local_cr, request->force_cvt);

    if (mes_send_data(request) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t dcs_send_pcr_ack(knl_session_t *session, msg_pcr_request_t *request, char *page, cr_cursor_t *cursor)
{
    msg_pcr_ack_t msg;

    mes_init_ack_head(&request->head, &msg.head, MES_CMD_PCR_ACK, (sizeof(msg_pcr_ack_t) + DEFAULT_PAGE_SIZE(session)), session->id);
    msg.head.src_inst = session->kernel->id;
    CM_ASSERT(request->head.dst_inst == session->kernel->id);
    msg.ssi_conflict = cursor->ssi_conflict;
    msg.cleanout = cursor->cleanout;
    msg.force_cvt = request->force_cvt;

    DTC_DCS_DEBUG_INF("[PCR][%u-%u][send pcr ack] cr_type %u src_inst %u src_sid %u dst_inst %u dst_sid %u force_cvt %u",
                      (uint32)request->page_id.file, (uint32)request->page_id.page, request->cr_type, msg.head.src_inst,
                      msg.head.src_sid, msg.head.dst_inst, msg.head.dst_sid, msg.force_cvt);

    status_t ret = CT_SUCCESS;
    SYNC_POINT_GLOBAL_START(CANTIAN_PCR_ACK_FAIL, &ret, CT_ERROR);
    ret = mes_send_data3(&msg.head, sizeof(msg_pcr_ack_t), page);
    SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_MES_SEND_DATA_FAIL, "pcr ack");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t dcs_send_txn_wait(knl_session_t *session, msg_pcr_request_t *request, xid_t wxid)
{
    msg_txn_wait_t msg;

    mes_init_ack_head(&request->head, &msg.head, MES_CMD_TXN_WAIT, sizeof(msg_txn_wait_t), session->id);
    msg.head.src_inst = session->kernel->id;
    CM_ASSERT(request->head.dst_inst == session->kernel->id);
    msg.wxid = wxid;

    DTC_DCS_DEBUG_INF("[PCR][%u-%u][send txn wait] wxid %u-%u-%u src_inst %u src_sid %u dst_inst %u dst_sid %u",
                      (uint32)request->page_id.file, (uint32)request->page_id.page, wxid.xmap.seg_id, wxid.xmap.slot,
                      wxid.xnum, msg.head.src_inst, msg.head.src_sid, msg.head.dst_inst, msg.head.dst_sid);

    status_t ret = CT_SUCCESS;
    SYNC_POINT_GLOBAL_START(CANTIAN_TXN_WAIT_SEND_FAIL, &ret, CT_ERROR);
    ret = mes_send_data(&msg);
    SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static inline void dcs_heap_init_cr_cursor(cr_cursor_t *cr_cursor, msg_pcr_request_t *request)
{
    knl_set_rowid_page(&cr_cursor->rowid, request->page_id);

    cr_cursor->xid = request->xid;
    cr_cursor->wxid.value = CT_INVALID_ID64;
    cr_cursor->query_scn = request->query_scn;
    cr_cursor->ssn = request->ssn;
    cr_cursor->ssi_conflict = request->ssi_conflict;
    cr_cursor->cleanout = request->cleanout;
    cr_cursor->is_remote = CT_TRUE;
    cr_cursor->local_cr = CT_FALSE;
}

static status_t dcs_heap_construct_cr_page(knl_session_t *session, msg_pcr_request_t *request)
{
    heap_page_t *cr_page = (heap_page_t *)((char *)request + sizeof(msg_pcr_request_t));
    cr_cursor_t cr_cursor;
    uint8 inst_id;
    if (!IS_SAME_PAGID(AS_PAGID(cr_page->head.id), request->page_id) || !CHECK_PAGE_PCN((page_head_t *)cr_page)) {
        CT_LOG_RUN_ERR("dcs handle pcr req is invalid, cr page[%u-%u], request page[%u-%u], page head pcn %u, page "
            "tail pcn %u",
            AS_PAGID(cr_page->head.id).file, AS_PAGID(cr_page->head.id).page, request->page_id.page,
            request->page_id.file, ((page_head_t *)cr_page)->pcn, PAGE_TAIL((page_head_t *)cr_page)->pcn);
        return CT_ERROR;
    }
    dtc_flush_log(session, request->page_id);
    dcs_heap_init_cr_cursor(&cr_cursor, request);

    for (;;) {
        if (pcrh_fetch_invisible_itl(session, &cr_cursor, cr_page) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cr_cursor.itl == NULL) {
            if (dcs_send_pcr_ack(session, request, (char *)cr_page, &cr_cursor) != CT_SUCCESS) {
                return CT_ERROR;
            }
            return CT_SUCCESS;
        }

        if (cr_cursor.wxid.value != CT_INVALID_ID64) {
            if (dcs_send_txn_wait(session, request, cr_cursor.wxid) != CT_SUCCESS) {
                return CT_ERROR;
            }
            return CT_SUCCESS;
        }

        inst_id = xid_get_inst_id(session, cr_cursor.itl->xid);
        if (inst_id == session->kernel->id && !cr_cursor.local_cr) {
            if (pcrh_reorganize_with_ud_list(session, &cr_cursor, cr_page, NULL) != CT_SUCCESS) {
                return CT_ERROR;
            }
        } else {
            return dcs_send_pcr_request(session, request, &cr_cursor, inst_id);
        }
    }
}

static inline void dcs_btree_init_cr_cursor(cr_cursor_t *cr_cursor, msg_pcr_request_t *request)
{
    msg_btree_request_t *btree_request = (msg_btree_request_t *)request;

    knl_set_rowid_page(&cr_cursor->rowid, request->page_id);

    cr_cursor->xid = request->xid;
    cr_cursor->wxid.value = CT_INVALID_ID64;
    cr_cursor->query_scn = request->query_scn;
    cr_cursor->ssn = request->ssn;
    cr_cursor->ssi_conflict = request->ssi_conflict;
    cr_cursor->cleanout = request->cleanout;
    cr_cursor->entry = btree_request->entry;
    cr_cursor->profile = &btree_request->profile;
    cr_cursor->is_remote = CT_TRUE;
    cr_cursor->local_cr = CT_FALSE;
}

static status_t dcs_btree_construct_cr_page(knl_session_t *session, msg_pcr_request_t *request)
{
    btree_page_t *cr_page = (btree_page_t *)((char *)request + sizeof(msg_btree_request_t));
    cr_cursor_t cr_cursor;
    uint8 inst_id;
    dtc_flush_log(session, request->page_id);
    dcs_btree_init_cr_cursor(&cr_cursor, request);

    for (;;) {
        if (pcrb_get_invisible_itl(session, &cr_cursor, cr_page) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cr_cursor.itl == NULL) {
            if (dcs_send_pcr_ack(session, request, (char *)cr_page, &cr_cursor) != CT_SUCCESS) {
                return CT_ERROR;
            }
            return CT_SUCCESS;
        }

        if (cr_cursor.wxid.value != CT_INVALID_ID64) {
            if (dcs_send_txn_wait(session, request, cr_cursor.wxid) != CT_SUCCESS) {
                return CT_ERROR;
            }
            return CT_SUCCESS;
        }

        inst_id = xid_get_inst_id(session, cr_cursor.itl->xid);
        if (inst_id == session->kernel->id && !cr_cursor.local_cr) {
            if (pcrb_reorganize_with_undo_list(session, &cr_cursor, cr_page) != CT_SUCCESS) {
                return CT_ERROR;
            }
        } else {
            return dcs_send_pcr_request(session, request, &cr_cursor, inst_id);
        }
    }
}

static inline void dcs_handle_pcr_request(knl_session_t *session, mes_message_t *msg)
{
    if (sizeof(msg_pcr_request_t) > msg->head->size) {
        CT_LOG_RUN_ERR("dcs handle pcr req is invalid, msg size %u.", msg->head->size);
        mes_send_error_msg(msg->head);
        return;
    }
    msg_pcr_request_t *request = (msg_pcr_request_t *)(msg->buffer);

    if (request->cr_type == CR_TYPE_HEAP) {
        if (sizeof(msg_pcr_request_t) + DEFAULT_PAGE_SIZE(session) != msg->head->size) {
            CT_LOG_RUN_ERR("dcs handle pcr req is invalid, msg size %u.", msg->head->size);
            mes_send_error_msg(msg->head);
            return;
        }
        if (dcs_heap_construct_cr_page(session, request) != CT_SUCCESS) {
            mes_send_error_msg(msg->head);
        }
    } else if (request->cr_type == CR_TYPE_BTREE) {
            if (sizeof(msg_btree_request_t) + DEFAULT_PAGE_SIZE(session) != msg->head->size) {
                CT_LOG_RUN_ERR("dcs handle pcr req is invalid, msg size %u.", msg->head->size);
                mes_send_error_msg(msg->head);
                return;
            }
        if (dcs_btree_construct_cr_page(session, request) != CT_SUCCESS) {
            mes_send_error_msg(msg->head);
        }
    } else {
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT);
        mes_send_error_msg(msg->head);
    }
}

void dcs_process_pcr_request(void *sess, mes_message_t *msg)
{
    knl_session_t *session = (knl_session_t *)sess;

    if (msg->head->src_inst == session->kernel->id) {
        msg->head->dst_sid = msg->head->src_sid;
        mes_process_msg_ack(sess, msg);
        return;
    }

    dcs_handle_pcr_request(session, msg);
    mes_release_message_buf(msg->buffer);
}

static status_t dcs_pcr_process_message(knl_session_t *session, mes_message_t *message, cr_cursor_t *cursor,
                                        char *page_buf, pcr_status_t *status, bool32 *is_found)
{
    char *recv_page = NULL;
    errno_t ret;

    switch (message->head->cmd) {
        case MES_CMD_MASTER_ACK_NEED_LOAD:
        case MES_CMD_MASTER_ACK_ALREADY_OWNER:
            *status = PCR_LOCAL_READ;
            break;
        case MES_CMD_PCR_REQ_MASTER:
            *status = PCR_CHECK_MASTER;
            break;
        case MES_CMD_PCR_REQ: {
            msg_pcr_request_t *reply = (msg_pcr_request_t *)(message->buffer);
            uint32 head_size = (reply->cr_type != CR_TYPE_BTREE) ? sizeof(msg_pcr_request_t)
                                                                 : sizeof(msg_btree_request_t);
            recv_page = (char *)reply + head_size;
            cursor->cleanout = reply->cleanout;
            cursor->ssi_conflict = reply->ssi_conflict;
            cursor->local_cr = reply->local_cr;
            ret = memcpy_sp(page_buf, DEFAULT_PAGE_SIZE(session), recv_page, DEFAULT_PAGE_SIZE(session));
            knl_securec_check(ret);
            *status = PCR_CONSTRUCT;

            if (reply->force_cvt) {
                buf_set_force_request(session, reply->page_id);
            }
            break;
        }
        case MES_CMD_PCR_ACK: {
            msg_pcr_ack_t *ack = (msg_pcr_ack_t *)(message->buffer);
            recv_page = (char *)ack + sizeof(msg_pcr_ack_t);
            cursor->cleanout = ack->cleanout;
            cursor->ssi_conflict = ack->ssi_conflict;
            ret = memcpy_sp(page_buf, DEFAULT_PAGE_SIZE(session), recv_page, DEFAULT_PAGE_SIZE(session));
            knl_securec_check(ret);
            *status = PCR_PAGE_VISIBLE;
            cursor->itl = NULL;

            if (ack->force_cvt) {
                buf_set_force_request(session, GET_ROWID_PAGE(cursor->rowid));
            }
            break;
        }
        case MES_CMD_CHECK_VISIBLE: {
            msg_cr_check_t *check = (msg_cr_check_t *)(message->buffer);
            cursor->local_cr = check->local_cr;
            recv_page = (char *)check + sizeof(msg_cr_check_t);
            ret = memcpy_sp(page_buf, DEFAULT_PAGE_SIZE(session), recv_page, DEFAULT_PAGE_SIZE(session));
            knl_securec_check(ret);
            break;
        }
        case MES_CMD_CHECK_VISIBLE_ACK: {
            *is_found = *(bool32 *)MES_MESSAGE_BODY(message);
            cursor->itl = NULL;
            break;
        }
        case MES_CMD_TXN_WAIT:
            cursor->wxid = *(xid_t *)MES_MESSAGE_BODY(message);
            *status = PCR_TRY_READ;
            break;
        case MES_CMD_ERROR_MSG:
            mes_handle_error_msg(message->buffer);
            return CT_ERROR;
        default:
            CT_THROW_ERROR(ERR_MES_ILEGAL_MESSAGE, "invalid MES message type");
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t dcs_heap_request_cr_page(knl_session_t *session, cr_cursor_t *cursor, char *page, uint8 dst_id)
{
    msg_pcr_request_t request;
    mes_message_t message;
    pcr_status_t status;

    uint16 size = (sizeof(msg_pcr_request_t) + DEFAULT_PAGE_SIZE(session));
    mes_init_send_head(&request.head, MES_CMD_PCR_REQ, size, CT_INVALID_ID32, session->kernel->id, dst_id, session->id,
                       CT_INVALID_ID16);
    dcs_init_pcr_request(session, cursor, CR_TYPE_HEAP, &request);

    DTC_DCS_DEBUG_INF("[PCR][%u-%u][request cr page] cr_type %u query_scn %llu query_ssn %u "
                      "src_inst %u src_sid %u dst_inst %u",
                      (uint32)request.page_id.file, (uint32)request.page_id.page, request.cr_type, request.query_scn,
                      request.ssn, session->kernel->id, session->id, dst_id);

    for (;;) {
        knl_begin_session_wait(session, PCR_REQ_HEAP_PAGE, CT_TRUE);
        status_t ret = CT_SUCCESS;
        SYNC_POINT_GLOBAL_START(CANTIAN_PCR_REQ_HEAP_PAGE_SEND_FAIL, &ret, CT_ERROR);
        ret = mes_send_data3(&request.head, sizeof(msg_pcr_request_t), page);
        SYNC_POINT_GLOBAL_END;
        if (ret != CT_SUCCESS) {
            knl_end_session_wait(session, PCR_REQ_HEAP_PAGE);
            break;
        }

        if (mes_recv(session->id, &message, CT_TRUE, request.head.rsn, DCS_CR_REQ_TIMEOUT) != CT_SUCCESS) {
            knl_end_session_wait(session, PCR_REQ_HEAP_PAGE);
            break;
        }
        knl_end_session_wait(session, PCR_REQ_HEAP_PAGE);

        if (dcs_pcr_process_message(session, &message, cursor, page, &status, NULL) != CT_SUCCESS) {
            mes_release_message_buf(message.buffer);
            return CT_ERROR;
        }

        mes_release_message_buf(message.buffer);
        return CT_SUCCESS;
    }

    DTC_DCS_DEBUG_INF("[PCR][%u-%u][request cr page failed] cr_type %u query_scn %llu query_ssn %u "
                      "src_inst %u src_sid %u dst_inst %u",
                      (uint32)request.page_id.file, (uint32)request.page_id.page, request.cr_type, request.query_scn,
                      request.ssn, session->kernel->id, session->id, dst_id);
    cm_reset_error();
    cm_sleep(MES_MSG_RETRY_TIME);

    return CT_SUCCESS;
}

status_t dcs_btree_request_cr_page(knl_session_t *session, cr_cursor_t *cursor, char *page, uint8 dst_id)
{
    msg_btree_request_t msg;
    msg_pcr_request_t *request = &msg.pcr_request;
    mes_message_t message;
    pcr_status_t status;

    uint16 size = (uint16)(sizeof(msg_btree_request_t) + DEFAULT_PAGE_SIZE(session));
    mes_init_send_head(&request->head, MES_CMD_PCR_REQ, size, CT_INVALID_ID32, session->kernel->id, dst_id, session->id,
                       CT_INVALID_ID16);
    dcs_init_pcr_request(session, cursor, CR_TYPE_BTREE, request);

    msg.entry = cursor->entry;
    msg.profile = *cursor->profile;

    DTC_DCS_DEBUG_INF("[PCR][%u-%u][request cr page] cr_type %u query_scn %llu query_ssn %u "
                      "src_inst %u src_sid %u dst_inst %u",
                      (uint32)request->page_id.file, (uint32)request->page_id.page, request->cr_type,
                      request->query_scn, request->ssn, session->kernel->id, session->id, dst_id);

    for (;;) {
        knl_begin_session_wait(session, PCR_REQ_BTREE_PAGE, CT_TRUE);
        status_t ret = CT_SUCCESS;
        SYNC_POINT_GLOBAL_START(CANTIAN_PCR_REQ_BTREE_PAGE_SEND_FAIL, &ret, CT_ERROR);
        ret = mes_send_data3(&request->head, sizeof(msg_btree_request_t), page);
        SYNC_POINT_GLOBAL_END;
        if (ret != CT_SUCCESS) {
            knl_end_session_wait(session, PCR_REQ_BTREE_PAGE);
            break;
        }

        if (mes_recv(session->id, &message, CT_TRUE, request->head.rsn, DCS_CR_REQ_TIMEOUT) != CT_SUCCESS) {
            knl_end_session_wait(session, PCR_REQ_BTREE_PAGE);
            break;
        }
        knl_end_session_wait(session, PCR_REQ_BTREE_PAGE);

        if (dcs_pcr_process_message(session, &message, cursor, page, &status, NULL) != CT_SUCCESS) {
            mes_release_message_buf(message.buffer);
            return CT_ERROR;
        }

        mes_release_message_buf(message.buffer);
        return CT_SUCCESS;
    }

    DTC_DCS_DEBUG_INF("[PCR][%u-%u][request cr page failed] cr_type %u query_scn %llu query_ssn %u "
                      "src_inst %u src_sid %u dst_inst %u",
                      (uint32)request->page_id.file, (uint32)request->page_id.page, request->cr_type,
                      request->query_scn, request->ssn, session->kernel->id, session->id, dst_id);
    cm_reset_error();
    cm_sleep(MES_MSG_RETRY_TIME);

    return CT_SUCCESS;
}

status_t dcs_pcr_request_master(knl_session_t *session, cr_cursor_t *cursor, char *page_buf, uint8 master_id,
                                cr_type_t type, pcr_status_t *status)
{
    msg_pcr_request_t request;
    mes_message_t message;

    knl_panic(*status == PCR_REQUEST_MASTER);

    mes_init_send_head(&request.head, MES_CMD_PCR_REQ_MASTER, sizeof(msg_pcr_request_t), CT_INVALID_ID32,
                       session->kernel->id, master_id, session->id, CT_INVALID_ID16);
    dcs_init_pcr_request(session, cursor, type, &request);

    DTC_DCS_DEBUG_INF("[PCR][%u-%u][request master] cr_type %u query_scn %llu query_ssn %u "
                      "src_inst %u src_sid %u dst_inst %u",
                      (uint32)request.page_id.file, (uint32)request.page_id.page, type, request.query_scn, request.ssn,
                      session->kernel->id, session->id, master_id);

    for (;;) {
        knl_begin_session_wait(session, PCR_REQ_MASTER, CT_TRUE);
        status_t ret = CT_SUCCESS;
        SYNC_POINT_GLOBAL_START(CANTIAN_PCR_REQ_MASTER_SEND_FAIL, &ret, CT_ERROR);
        ret = mes_send_data(&request);
        SYNC_POINT_GLOBAL_END;
        if (ret != CT_SUCCESS) {
            knl_end_session_wait(session, PCR_REQ_MASTER);
            break;
        }

        if (mes_recv(session->id, &message, CT_TRUE, request.head.rsn, DCS_CR_REQ_TIMEOUT) != CT_SUCCESS) {
            knl_end_session_wait(session, PCR_REQ_MASTER);
            break;
        }
        knl_end_session_wait(session, PCR_REQ_MASTER);
        session->stat->dcs_net_time += session->wait_pool[PCR_REQ_MASTER].usecs;

        if (dcs_pcr_process_message(session, &message, cursor, page_buf, status, NULL) != CT_SUCCESS) {
            mes_release_message_buf(message.buffer);
            return CT_ERROR;
        }

        mes_release_message_buf(message.buffer);
        return CT_SUCCESS;
    }

    DTC_DCS_DEBUG_INF("[PCR][%u-%u][request master failed] cr_type %u query_scn %llu query_ssn %u "
                      "src_inst %u src_sid %u dst_inst %u",
                      (uint32)request.page_id.file, (uint32)request.page_id.page, type, request.query_scn, request.ssn,
                      session->kernel->id, session->id, master_id);
    cm_reset_error();
    *status = PCR_CHECK_MASTER;
    cm_sleep(MES_MSG_RETRY_TIME);

    return CT_SUCCESS;
}

status_t dcs_pcr_request_owner(knl_session_t *session, cr_cursor_t *cursor, char *page_buf, uint8 owner_id,
                               cr_type_t type, pcr_status_t *status)
{
    msg_pcr_request_t request;
    mes_message_t message;

    knl_panic(*status == PCR_REQUEST_OWNER);

    mes_init_send_head(&request.head, MES_CMD_PCR_REQ_OWNER, sizeof(msg_pcr_request_t), CT_INVALID_ID32,
                       session->kernel->id, owner_id, session->id, CT_INVALID_ID16);
    dcs_init_pcr_request(session, cursor, type, &request);

    DTC_DCS_DEBUG_INF("[PCR][%u-%u][request owner] cr_type %u query_scn %llu query_ssn %u "
                      "src_inst %u src_sid %u dst_inst %u",
                      (uint32)request.page_id.file, (uint32)request.page_id.page, type, request.query_scn, request.ssn,
                      session->kernel->id, session->id, owner_id);

    for (;;) {
        knl_begin_session_wait(session, PCR_REQ_OWNER, CT_TRUE);
        status_t ret = CT_SUCCESS;
        SYNC_POINT_GLOBAL_START(CANTIAN_PCR_REQ_OWNER_SEND_FAIL, &ret, CT_ERROR);
        ret = mes_send_data(&request);
        SYNC_POINT_GLOBAL_END;
        if (ret != CT_SUCCESS) {
            knl_end_session_wait(session, PCR_REQ_OWNER);
            break;
        }

        if (mes_recv(session->id, &message, CT_TRUE, request.head.rsn, DCS_CR_REQ_TIMEOUT) != CT_SUCCESS) {
            knl_end_session_wait(session, PCR_REQ_OWNER);
            break;
        }
        knl_end_session_wait(session, PCR_REQ_OWNER);
        session->stat->dcs_net_time += session->wait_pool[PCR_REQ_OWNER].usecs;

        if (dcs_pcr_process_message(session, &message, cursor, page_buf, status, NULL) != CT_SUCCESS) {
            mes_release_message_buf(message.buffer);
            return CT_ERROR;
        }

        mes_release_message_buf(message.buffer);
        return CT_SUCCESS;
    }

    DTC_DCS_DEBUG_INF("[PCR][%u-%u][request owner failed] cr_type %u query_scn %llu query_ssn %u "
                      "src_inst %u src_sid %u dst_inst %u",
                      (uint32)request.page_id.file, (uint32)request.page_id.page, type, request.query_scn, request.ssn,
                      session->kernel->id, session->id, owner_id);
    cm_reset_error();
    *status = PCR_CHECK_MASTER;
    cm_sleep(MES_MSG_RETRY_TIME);

    return CT_SUCCESS;
}

status_t dcs_pcr_check_master(knl_session_t *session, page_id_t page_id, cr_type_t type,
                              uint8 *dst_id, pcr_status_t *status)
{
    uint8 master_id, owner_id;

    knl_panic(*status == PCR_CHECK_MASTER);

    if (drc_get_page_master_id(page_id, &master_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (master_id == session->kernel->id) {
        (void)drc_get_page_owner_id(session, page_id, &owner_id, NULL);

        if (owner_id == CT_INVALID_ID8 || owner_id == session->kernel->id) {
            *status = PCR_LOCAL_READ;
        } else {
            *status = PCR_REQUEST_OWNER;
            *dst_id = owner_id;
        }
    } else {
        *status = PCR_REQUEST_MASTER;
        *dst_id = master_id;
    }

    return CT_SUCCESS;
}

static status_t dcs_pcr_reroute_request(knl_session_t *session, msg_pcr_request_t *request, bool32 *local_route)
{
    uint8 master_id;

    if (drc_get_page_master_id(request->page_id, &master_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // current instance is master, route in caller
    if (master_id == session->kernel->id) {
        *local_route = CT_TRUE;
        return CT_SUCCESS;
    }

    mes_init_send_head(&request->head, MES_CMD_PCR_REQ_MASTER, request->head.size, request->head.rsn,
                       request->head.src_inst, master_id, request->head.src_sid, CT_INVALID_ID16);

    DTC_DCS_DEBUG_INF("[PCR][%u-%u][reroute request] cr_type %u query_scn %llu query_ssn %u "
                      "src_inst %u src_sid %u dst_inst %u",
                      (uint32)request->page_id.file, (uint32)request->page_id.page, request->cr_type,
                      request->query_scn, request->ssn, request->head.src_inst, request->head.src_sid, master_id);

    if (mes_send_data(request) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t dcs_process_heap_pcr_construct(knl_session_t *session, msg_pcr_request_t *request, bool32 *local_route)
{
    buf_read_assist_t ra;
    msg_pcr_request_t *new_req = NULL;
    heap_page_t *page = NULL;

    *local_route = CT_FALSE;
    dtc_read_init(&ra, request->page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL | ENTER_PAGE_FROM_REMOTE, request->query_scn,
                  DTC_BUF_READ_ONE);

    if (dtc_read_page(session, &ra) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // page owner has changed, request master to start the next round construct
    page = (heap_page_t *)CURR_PAGE(session);
    if (page == NULL) {
        return dcs_pcr_reroute_request(session, request, local_route);
    }

    // if current page is not heap page, just return error to requester
    if (page->head.type != PAGE_TYPE_PCRH_DATA) {
        buf_leave_page(session, CT_FALSE);
        CT_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, "table");
        return CT_ERROR;
    }

    // use the received request to generate new request to construct CR page
    new_req = (msg_pcr_request_t *)cm_push(session->stack, sizeof(msg_pcr_request_t) + DEFAULT_PAGE_SIZE(session));
    if (new_req == NULL) {
        buf_leave_page(session, CT_FALSE);
        CT_LOG_RUN_ERR("send_msg failed to malloc memory, send_msg size %u.",
            (uint32_t)(sizeof(msg_pcr_request_t) + DEFAULT_PAGE_SIZE(session)));
        return CT_ERROR;
    }
    *new_req = *(msg_pcr_request_t *)request;
    new_req->head.cmd = MES_CMD_PCR_REQ;
    new_req->head.size = (uint16)(sizeof(msg_pcr_request_t) + DEFAULT_PAGE_SIZE(session));

    errno_t ret = memcpy_sp((char *)new_req + sizeof(msg_pcr_request_t), DEFAULT_PAGE_SIZE(session),
                            (void *)page, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);

    if (g_dtc->profile.remote_access_limit != 0 &&
        (uint32)session->curr_page_ctrl->remote_access >= g_dtc->profile.remote_access_limit) {
        new_req->force_cvt = 1;
    }

    buf_leave_page(session, CT_FALSE);

    /* sync scn before construct CR page */
    dtc_update_scn(session, request->query_scn);

    if (dcs_heap_construct_cr_page(session, new_req) != CT_SUCCESS) {
        cm_pop(session->stack);
        return CT_ERROR;
    }

    cm_pop(session->stack);

    return CT_SUCCESS;
}

static void dcs_send_already_owner(knl_session_t *session, mes_message_t *msg)
{
    mes_message_head_t head;

    mes_init_ack_head(msg->head, &head, MES_CMD_MASTER_ACK_ALREADY_OWNER, sizeof(mes_message_head_t), DCS_SELF_SID(session));

    (void)mes_send_data(&head);
}

static void dcs_send_grant_owner(knl_session_t *session, mes_message_t *msg)
{
    mes_message_head_t head;

    mes_init_ack_head(msg->head, &head, MES_CMD_MASTER_ACK_NEED_LOAD, sizeof(mes_message_head_t), DCS_SELF_SID(session));

    (void)mes_send_data(&head);
}

void dcs_route_pcr_request_owner(knl_session_t *session, msg_pcr_request_t *request, uint8 owner_id)
{
    mes_init_send_head(&request->head, MES_CMD_PCR_REQ_OWNER, request->head.size, request->head.rsn,
                       request->head.src_inst, owner_id, request->head.src_sid, CT_INVALID_ID16);

    (void)mes_send_data(request);
}

static inline void dcs_handle_pcr_req_master(knl_session_t *session, mes_message_t *msg)
{
    msg_pcr_request_t *request = (msg_pcr_request_t *)(msg->buffer);
    uint8 owner_id;
    bool32 local_route = CT_TRUE;
    if (request->page_id.file >= INVALID_FILE_ID || (request->page_id.page == 0 && request->page_id.file == 0)) {
        CT_LOG_RUN_ERR("[%u-%u] page_id invalid,", request->page_id.file, request->page_id.page);
        mes_send_error_msg(msg->head);
        return;
    }

    while (local_route) {
        (void)drc_get_page_owner_id(session, request->page_id, &owner_id, NULL);
        if (owner_id == CT_INVALID_ID8) {
            dcs_send_grant_owner(session, msg);
            break;
        }

        if (owner_id == msg->head->src_inst) {
            dcs_send_already_owner(session, msg);
            break;
        }

        if (owner_id != session->kernel->id) {
            dcs_route_pcr_request_owner(session, request, owner_id);
            break;
        }

        local_route = CT_FALSE;
        if (request->cr_type == CR_TYPE_HEAP) {
            if (dcs_process_heap_pcr_construct(session, request, &local_route) != CT_SUCCESS) {
                mes_send_error_msg(msg->head);
            }
        } else {
            CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT);
            mes_send_error_msg(msg->head);
        }
    }
}

/*
 * requester would receive REQ_MASTER message sent from itself
 */
void dcs_process_pcr_req_master(void *sess, mes_message_t *msg)
{
    knl_session_t *session = (knl_session_t *)sess;

    if (msg->head->src_inst == session->kernel->id) {
        msg->head->dst_sid = msg->head->src_sid;
        mes_process_msg_ack(sess, msg);
        return;
    }
    if (sizeof(msg_pcr_request_t) != msg->head->size) {
        CT_LOG_RUN_ERR("process pcr req master is invalid, msg size %u.", msg->head->size);
        mes_release_message_buf(msg->buffer);
        return;
    }
    dcs_handle_pcr_req_master(session, msg);
    mes_release_message_buf(msg->buffer);
}

/*
 * requester would not receive REQ_OWNER message sent from itself
 */
void dcs_process_pcr_req_owner(void *sess, mes_message_t *msg)
{
    msg_pcr_request_t *request = (msg_pcr_request_t *)(msg->buffer);
    bool32 local_route = CT_FALSE;
    knl_session_t *session = (knl_session_t *)sess;
    if (sizeof(msg_pcr_request_t) != msg->head->size) {
        CT_LOG_RUN_ERR("pcr req owner is invalid, msg size %u.", msg->head->size);
        mes_send_error_msg(msg->head);
        mes_release_message_buf(msg->buffer);
        return;
    }
    if (request->page_id.file >= INVALID_FILE_ID || (request->page_id.page == 0 && request->page_id.file == 0)) {
        CT_LOG_RUN_ERR("[%u-%u] page_id invalid,", request->page_id.file, request->page_id.page);
        mes_send_error_msg(&request->head);
        mes_release_message_buf(msg->buffer);
        return;
    }

    if (request->cr_type == CR_TYPE_HEAP) {
        if (dcs_process_heap_pcr_construct(session, request, &local_route) != CT_SUCCESS) {
            mes_send_error_msg(msg->head);
        }
    } else {
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT);
        mes_send_error_msg(msg->head);
    }

    if (local_route) {
        dcs_handle_pcr_req_master(session, msg);
    }

    mes_release_message_buf(msg->buffer);
}

static inline void dcs_init_check_cursor(cr_cursor_t *cr_cursor, msg_cr_check_t *check)
{
    cr_cursor->rowid = check->rowid;
    cr_cursor->xid = check->xid;
    cr_cursor->wxid.value = CT_INVALID_ID64;
    cr_cursor->query_scn = check->query_scn;
    cr_cursor->ssn = check->ssn;
    cr_cursor->ssi_conflict = CT_FALSE;
    cr_cursor->cleanout = CT_FALSE;
    cr_cursor->is_remote = CT_TRUE;
    cr_cursor->local_cr = CT_FALSE;
}

status_t dcs_check_current_visible(knl_session_t *session, cr_cursor_t *cursor, char *page,
                                   uint8 dst_id, bool32 *is_found)
{
    msg_cr_check_t check;
    mes_message_t message;
    pcr_status_t status;

    uint16 size = (uint16)(sizeof(msg_cr_check_t) + DEFAULT_PAGE_SIZE(session));
    mes_init_send_head(&check.head, MES_CMD_CHECK_VISIBLE, size, CT_INVALID_ID32, session->kernel->id, dst_id,
                       session->id, CT_INVALID_ID16);
    check.rowid = cursor->rowid;
    check.xid = cursor->xid;
    check.query_scn = cursor->query_scn;
    check.ssn = cursor->ssn;

    DTC_DCS_DEBUG_INF("[PCR][%u-%u-%u][check current visible] query_scn %llu query_ssn %u "
                      "src_inst %u src_sid %u dst_inst %u",
                      (uint32)check.rowid.file, (uint32)check.rowid.page, (uint32)check.rowid.slot, check.query_scn,
                      check.ssn, check.head.src_inst, check.head.src_sid, dst_id);

    for (;;) {
        knl_begin_session_wait(session, PCR_CHECK_CURR_VISIBLE, CT_TRUE);
        status_t ret = CT_SUCCESS;
        SYNC_POINT_GLOBAL_START(CANTIAN_HEAP_CHECK_VISIBLE_SEND_FAIL, &ret, CT_ERROR);
        ret = mes_send_data3(&check.head, sizeof(msg_cr_check_t), page);
        SYNC_POINT_GLOBAL_END;
        if (ret != CT_SUCCESS) {
            knl_end_session_wait(session, PCR_CHECK_CURR_VISIBLE);
            break;
        }

        if (mes_recv(session->id, &message, CT_TRUE, check.head.rsn, DCS_CR_REQ_TIMEOUT) != CT_SUCCESS) {
            knl_end_session_wait(session, PCR_CHECK_CURR_VISIBLE);
            break;
        }
        knl_end_session_wait(session, PCR_CHECK_CURR_VISIBLE);

        if (dcs_pcr_process_message(session, &message, cursor, page, &status, is_found) != CT_SUCCESS) {
            mes_release_message_buf(message.buffer);
            return CT_ERROR;
        }

        mes_release_message_buf(message.buffer);
        return CT_SUCCESS;
    }

    DTC_DCS_DEBUG_ERR("[PCR][%u-%u-%u][check current visible failed] query_scn %llu query_ssn %u "
                      "src_inst %u src_sid %u dst_inst %u",
                      (uint32)check.rowid.file, (uint32)check.rowid.page, (uint32)check.rowid.slot, check.query_scn,
                      check.ssn, check.head.src_inst, check.head.src_sid, dst_id);
    cm_reset_error();
    cm_sleep(MES_MSG_RETRY_TIME);

    return CT_SUCCESS;
}

static inline status_t dcs_send_check_visible(knl_session_t *session, msg_cr_check_t *check,
                                              cr_cursor_t *cursor, uint8 dst_id)
{
    bool8 local_cr = g_dtc->profile.enable_rmo_cr || cursor->local_cr;
    check->head.dst_inst = local_cr ? check->head.src_inst : dst_id;
    check->local_cr = local_cr;

    DTC_DCS_DEBUG_INF("[PCR][%u-%u-%u][send check visible] query_scn %llu query_ssn %u "
                      "src_inst %u src_sid %u dst_inst %u local_cr %u",
                      (uint32)check->rowid.file, (uint32)check->rowid.page, (uint32)check->rowid.slot, check->query_scn,
                      check->ssn, check->head.src_inst, check->head.src_sid, dst_id, check->local_cr);

    if (mes_send_data(check) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t dcs_send_check_visible_ack(knl_session_t *session, msg_cr_check_t *check, bool32 is_found)
{
    msg_cr_check_ack_t msg;

    mes_init_ack_head(&check->head, &msg.head, MES_CMD_CHECK_VISIBLE_ACK, sizeof(msg_cr_check_ack_t), session->id);
    msg.is_found = is_found;

    DTC_DCS_DEBUG_INF("[PCR][%u-%u-%u][send check visible ack] is_found %u "
                      "src_inst %u src_sid %u dst_inst %u dst_sid %u",
                      (uint32)check->rowid.file, (uint32)check->rowid.page, (uint32)check->rowid.slot, (uint32)is_found,
                      session->kernel->id, session->id, check->head.src_inst, check->head.src_sid);

    status_t ret = CT_SUCCESS;
    SYNC_POINT_GLOBAL_START(CANTIAN_HEAP_CHECK_VISIBLE_ACK_FAIL, &ret, CT_ERROR);
    ret = mes_send_data(&msg);
    SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t dcs_heap_check_visible(knl_session_t *session, msg_cr_check_t *check)
{
    heap_page_t *page = (heap_page_t *)((char *)check + sizeof(msg_cr_check_t));
    cr_cursor_t cr_cursor;
    bool32 is_found = CT_TRUE;
    uint8 inst_id;

    dcs_init_check_cursor(&cr_cursor, check);

    for (;;) {
        if (pcrh_fetch_invisible_itl(session, &cr_cursor, page) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cr_cursor.itl == NULL) {
            return dcs_send_check_visible_ack(session, check, is_found);
        }

        inst_id = xid_get_inst_id(session, cr_cursor.itl->xid);
        if (inst_id == session->kernel->id && !cr_cursor.local_cr) {
            if (pcrh_chk_visible_with_undo_ss(session, &cr_cursor, page, CT_FALSE, &is_found) != CT_SUCCESS) {
                return CT_ERROR;
            }

            if (!is_found) {
                return dcs_send_check_visible_ack(session, check, is_found);
            }
        } else {
            return dcs_send_check_visible(session, check, &cr_cursor, inst_id);
        }
    }
}

void dcs_process_check_visible(void *sess, mes_message_t *msg)
{
    knl_session_t *session = (knl_session_t *)sess;

    if (msg->head->src_inst == session->kernel->id) {
        msg->head->dst_sid = msg->head->src_sid;
        mes_process_msg_ack(sess, msg);
        return;
    }
    if (sizeof(msg_cr_check_t) + DEFAULT_PAGE_SIZE(sess) != msg->head->size) {
        CT_LOG_RUN_ERR("process check visible msg size is invalid, msg size %u.", msg->head->size);
        mes_send_error_msg(msg->head);
        mes_release_message_buf(msg->buffer);
        return;
    }
    if (dcs_heap_check_visible(session, (msg_cr_check_t *)(msg->buffer)) != CT_SUCCESS) {
        mes_send_error_msg(msg->head);
    }

    mes_release_message_buf(msg->buffer);
}

void dcs_buf_clean_ctrl_edp(knl_session_t *session, buf_ctrl_t *ctrl, bool32 need_lock)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;

    buf_set_t *set = &session->kernel->buf_ctx.buf_set[ctrl->buf_pool_id];
    buf_bucket_t *bucket = BUF_GET_BUCKET(set, ctrl->bucket_id);
    if (need_lock) {
        cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
    }
    if (!ctrl->is_edp) {
        DTC_DCS_DEBUG_INF("[DCS] edp page[%u-%u] (lsn:%lld) has already been cleaned.", ctrl->page_id.file,
                          ctrl->page_id.page, ctrl->page->lsn);
        if (need_lock) {
            cm_spin_unlock(&bucket->lock);
        }
        return;
    }

    knl_panic(ctrl && ctrl->is_dirty && ctrl->is_edp && !ctrl->is_readonly);
    knl_panic(DCS_BUF_CTRL_NOT_OWNER(session, ctrl));

    if (ctrl == ctx->batch_end) {
        ctx->batch_end = ctx->batch_end->ckpt_prev;
    }

    ckpt_pop_page(session, ctx, ctrl);
    CM_MFENCE;
    ctrl->is_dirty = 0;
    ctrl->is_remote_dirty = 0;
    ctrl->is_edp = 0;
    if (need_lock) {
        cm_spin_unlock(&bucket->lock);
    }
}

status_t dcs_alter_set_param(knl_session_t *session, const char *value, config_scope_t scope)
{
    msg_arch_set_request_t req = { 0 };
    req.scope = scope;
    error_t ret = memcpy_sp(req.value, CT_PARAM_BUFFER_SIZE, value, CT_PARAM_BUFFER_SIZE);
    if (ret != 0) {
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[DCS] request to arch set params, scope %u, value %s", req.scope, req.value);
    mes_init_send_head(&req.head, MES_CMD_ARCH_SET_REQ, sizeof(msg_arch_set_request_t), CT_INVALID_ID32,
        DCS_SELF_INSTID(session), 0, session->id, CT_INVALID_ID16);
    if (mes_broadcast_and_wait(session->id, MES_BROADCAST_ALL_INST,
                               (void *)&req, MES_WAIT_MAX_TIME, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void dcs_process_arch_set_request(void *sess, mes_message_t *msg)
{
    CT_LOG_RUN_INF("[DCS] process request to arch set params");
    knl_session_t *session = (knl_session_t*)sess;
    msg_arch_set_request_t *req = (msg_arch_set_request_t*)msg->buffer;
    mes_message_head_t head = {0};

    database_t *db = &session->kernel->db;
    config_item_t *item = NULL;
    bool32 force = CT_TRUE;
    if (db->status != DB_STATUS_MOUNT && db->status != DB_STATUS_OPEN) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "set param only work in mount or open state");
        return;
    }

    char arch_set_param[CT_NAME_BUFFER_SIZE] = "ARCH_TIME";
    text_t name = {
        .str = arch_set_param,
        .len = (uint32)strlen(arch_set_param)
    };
    item = cm_get_config_item(GET_CONFIG, &name, CT_TRUE);
    if (item == NULL) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER_NAME, arch_set_param);
        return;
    }
    if (req->scope != CONFIG_SCOPE_DISK) {
        if (item->notify && item->notify((knl_handle_t)session, (void *)item, req->value)) {
            return;
        }
    } else {
        if (item->notify_pfile && item->notify_pfile((knl_handle_t)session, (void *)item, req->value)) {
            return;
        }
    }

    if (item->attr & ATTR_READONLY) {
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
        force = CT_TRUE;
#else
        force = CT_FALSE; // can not alter parameter whose attr is readonly  for release
#endif
    }
    if (cm_alter_config(session->kernel->attr.config, arch_set_param, req->value, req->scope, force) != CT_SUCCESS) {
        return;
    }

    mes_init_ack_head(msg->head, &head, MES_CMD_BROADCAST_ACK, sizeof(mes_message_head_t), CT_INVALID_ID16);
    mes_release_message_buf(msg->buffer);
    if (mes_send_data(&head) != CT_SUCCESS) {
        return;
    }
    CT_LOG_RUN_INF("[DCS] done request to arch set params");

    return;
}
