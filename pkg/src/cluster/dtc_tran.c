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
 * dtc_tran.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_tran.c
 *
 * -------------------------------------------------------------------------
 */
#include "dtc_tran.h"
#include "dtc_database.h"
#include "dtc_reform.h"

status_t dtc_get_remote_txn_info(knl_session_t *session, bool32 is_scan, xid_t xid, uint8 dst_id, txn_info_t *txn_info)
{
    msg_txn_info_t request;
    mes_message_t message;

    mes_init_send_head(&request.head, MES_CMD_TXN_INFO_REQ, sizeof(msg_txn_info_t), GS_INVALID_ID32,
                       session->kernel->id, dst_id, session->id, GS_INVALID_ID16);
    request.xid = xid;
    request.curr_scn = DB_CURR_SCN(session);
    request.is_can = is_scan;

    knl_try_begin_session_wait(session, TXN_REQ_INFO, GS_TRUE);
    status_t ret = GS_SUCCESS;
    SYNC_POINT_GLOBAL_START(CANTIAN_TXN_INF_REQ_SEND_FAIL, &ret, GS_ERROR);
    ret = mes_send_data(&request);
    SYNC_POINT_GLOBAL_END;
    if (ret != GS_SUCCESS) {
        knl_try_end_session_wait(session, TXN_REQ_INFO);
        GS_LOG_DEBUG_ERR("[TXN][%u-%u-%u][request txn info failed] src_inst %u src_sid %u dst_inst %u",
                         xid.xmap.seg_id, xid.xmap.slot, xid.xnum, session->kernel->id, session->id, dst_id);
        return GS_ERROR;
    }

    if (mes_recv(session->id, &message, GS_FALSE, request.head.rsn, TXN_REQ_TIMEOUT) != GS_SUCCESS) {
        knl_try_end_session_wait(session, TXN_REQ_INFO);
        GS_LOG_DEBUG_ERR("[TXN][%u-%u-%u][recv txn info failed] src_inst %u src_sid %u dst_inst %u",
                         xid.xmap.seg_id, xid.xmap.slot, xid.xnum, session->kernel->id, session->id, dst_id);
        return GS_ERROR;
    }
    knl_try_end_session_wait(session, TXN_REQ_INFO);

    switch (message.head->cmd) {
        case MES_CMD_TXN_INFO_ACK:
            *txn_info = *(txn_info_t *)MES_MESSAGE_BODY(&message);
            mes_release_message_buf(message.buffer);

            dtc_update_scn(session, txn_info->scn);
            return GS_SUCCESS;
        case MES_CMD_ERROR_MSG:
            mes_handle_error_msg(message.buffer);
            mes_release_message_buf(message.buffer);
            return GS_ERROR;
        default:
            GS_THROW_ERROR(ERR_MES_ILEGAL_MESSAGE, "invalid MES message type");
            mes_release_message_buf(message.buffer);
            return GS_ERROR;
    }
}

page_id_t dtc_get_txn_page_id(knl_session_t *session, xmap_t xmap)
{
    uint32 page_capacity = TXN_PER_PAGE(session);
    undo_set_t *undo_set = UNDO_SET(session, XMAP_INST_ID(xmap));
    undo_t *undo = &undo_set->undos[XMAP_SEG_ID(xmap)];
    txn_page_t *txn_page = undo->txn_pages[xmap.slot / page_capacity];
    page_id_t page_id = AS_PAGID(txn_page->head.id);
    return page_id;
}

void dtc_flush_log(knl_session_t *session, page_id_t page_id)
{
    buf_bucket_t *bucket = buf_find_bucket(session, page_id);
    cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
    buf_ctrl_t *ctrl = buf_find_from_bucket(bucket, page_id);
    bool32 need_flush = ctrl->is_dirty && DAAC_NEED_FLUSH_LOG(session, ctrl);
    cm_spin_unlock(&bucket->lock);

    if (need_flush) {
        if (log_flush(session, NULL, NULL, NULL) != GS_SUCCESS) {
            CM_ABORT(0, "[DTC][%u-%u]: ABORT INFO: flush redo log failed", page_id.file, page_id.page);
        }
    }
}

void dtc_process_txn_info_req(void *sess, mes_message_t *msg)
{
    knl_session_t *session = (knl_session_t *)sess;
    msg_txn_info_t *request = (msg_txn_info_t *)msg->buffer;
    mes_message_head_t head;
    txn_info_t txn_info;
    uint8 inst_id, curr_id;
    bool32 is_scan = request->is_can;

    /* try update local scn to keep read consistent */
    dtc_update_scn(session, request->curr_scn);

    inst_id = XID_INST_ID(request->xid);
    if (inst_id == session->kernel->id) {
        if (session->kernel->db.status >= DB_STATUS_INIT_PHASE2) {
            tx_get_info(session, is_scan, request->xid, &txn_info);
        } else {
            GS_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "request txn info");
            mes_send_error_msg(msg->head);
            mes_release_message_buf(msg->buffer);
            return;
        }
    } else {
        curr_id = xid_get_inst_id(session, request->xid);
        if (curr_id == session->kernel->id && rc_instance_accessible(inst_id)) {
            tx_get_info(session, is_scan, request->xid, &txn_info);
        } else {
            GS_THROW_ERROR(ERR_ACCESS_DEPOSIT_INST, inst_id, curr_id);
            mes_send_error_msg(msg->head);
            mes_release_message_buf(msg->buffer);
            return;
        }
    }

    /* sync scn in info message if transaction is active */
    if (txn_info.status == XACT_BEGIN) {
        txn_info.scn = DB_CURR_SCN(session);
    } else {
        page_id_t page_id = dtc_get_txn_page_id(session, request->xid.xmap);
        dtc_flush_log(session, page_id);
    }

    mes_init_ack_head(msg->head, &head, MES_CMD_TXN_INFO_ACK, sizeof(mes_message_head_t) + sizeof(txn_info_t), GS_INVALID_ID16);
    mes_release_message_buf(msg->buffer);

    status_t ret = GS_SUCCESS;
    SYNC_POINT_GLOBAL_START(CANTIAN_TXN_INF_ACK_SEND_FAIL, &ret, GS_ERROR);
    ret = mes_send_data2(&head, (void *)&txn_info);
    SYNC_POINT_GLOBAL_END;
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_INF("[TXN][%u-%u-%u][send request txn info ack failed]",
            txn_info.xid.xmap.seg_id, txn_info.xid.xmap.slot, txn_info.xid.xnum);
    }
}

status_t dtc_get_remote_txn_snapshot(knl_session_t *session, xmap_t xmap, uint32 dst_id, txn_snapshot_t *snapshot)
{
    msg_txn_snapshot_t request;
    mes_message_t message;

    mes_init_send_head(&request.head, MES_CMD_TXN_SNAPSHOT_REQ, sizeof(msg_txn_snapshot_t), GS_INVALID_ID32,
                       session->kernel->id, dst_id, session->id, GS_INVALID_ID16);
    request.xmap = xmap;

    knl_try_begin_session_wait(session, TXN_REQ_SNAPSHOT, GS_TRUE);
    status_t ret = GS_SUCCESS;
    SYNC_POINT_GLOBAL_START(CANTIAN_TXN_SNAPSHOT_REQ_SEND_FAIL, &ret, GS_ERROR);
    ret = mes_send_data(&request);
    SYNC_POINT_GLOBAL_END;
    if (ret != GS_SUCCESS) {
        knl_try_end_session_wait(session, TXN_REQ_SNAPSHOT);
        GS_LOG_DEBUG_ERR("[TXN][%u-%u][request txn snapshot failed] src_inst %u src_sid %u dst_inst %u",
                         xmap.seg_id, xmap.slot, session->kernel->id, session->id, dst_id);
        return GS_ERROR;
    }

    if (mes_recv(session->id, &message, GS_FALSE, request.head.rsn, TXN_REQ_TIMEOUT) != GS_SUCCESS) {
        knl_try_end_session_wait(session, TXN_REQ_SNAPSHOT);
        GS_LOG_DEBUG_ERR("[TXN][%u-%u][recv txn snapshot failed] src_inst %u src_sid %u dst_inst %u",
                         xmap.seg_id, xmap.slot, session->kernel->id, session->id, dst_id);
        return GS_ERROR;
    }
    knl_try_end_session_wait(session, TXN_REQ_SNAPSHOT);

    switch (message.head->cmd) {
        case MES_CMD_TXN_SNAPSHOT_ACK:
            *snapshot = *(txn_snapshot_t *)MES_MESSAGE_BODY(&message);
            mes_release_message_buf(message.buffer);

            if (snapshot->status == XACT_END) {
                dtc_update_scn(session, snapshot->scn);
            }
            return GS_SUCCESS;
        case MES_CMD_ERROR_MSG:
            mes_handle_error_msg(message.buffer);
            mes_release_message_buf(message.buffer);
            return GS_ERROR;
        default:
            GS_THROW_ERROR(ERR_MES_ILEGAL_MESSAGE, "invalid MES message type");
            mes_release_message_buf(message.buffer);
            return GS_ERROR;
    }
}

void dtc_process_txn_snapshot_req(void *sess, mes_message_t *msg)
{
    knl_session_t *session = (knl_session_t *)sess;
    msg_txn_snapshot_t *request = (msg_txn_snapshot_t *)msg->buffer;
    mes_message_head_t head;
    txn_snapshot_t txn_snapshot;
    uint8 inst_id, curr_id;

    inst_id = XMAP_INST_ID(request->xmap);
    if (inst_id == session->kernel->id) {
        if (session->kernel->db.status >= DB_STATUS_INIT_PHASE2) {
            tx_get_local_snapshot(session, request->xmap, &txn_snapshot);
        } else {
            GS_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "request txn snapshot");
            mes_send_error_msg(msg->head);
            mes_release_message_buf(msg->buffer);
            return;
        }
    } else {
        curr_id = xmap_get_inst_id(session, request->xmap);
        if (curr_id == session->kernel->id && rc_instance_accessible(inst_id)) {
            tx_get_local_snapshot(session, request->xmap, &txn_snapshot);
        } else {
            GS_THROW_ERROR(ERR_ACCESS_DEPOSIT_INST, inst_id, curr_id);
            mes_send_error_msg(msg->head);
            mes_release_message_buf(msg->buffer);
            return;
        }
    }

    mes_init_ack_head(msg->head, &head, MES_CMD_TXN_SNAPSHOT_ACK, sizeof(mes_message_head_t) + sizeof(txn_snapshot_t), GS_INVALID_ID16);

    mes_release_message_buf(msg->buffer);

    status_t ret = GS_SUCCESS;
    SYNC_POINT_GLOBAL_START(CANTIAN_TXN_SNAPSHOT_ACK_SEND_FAIL, &ret, GS_ERROR);
    ret = mes_send_data2(&head, (void *)&txn_snapshot);
    SYNC_POINT_GLOBAL_END;
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_INF("[TXN][send request txn snapshot ack failed] snapshot rmid=%u, xnum=%u, status=%u",
            txn_snapshot.rmid, txn_snapshot.xnum, txn_snapshot.status);
    }
}

void dtc_get_txn_info(knl_session_t *session, bool32 is_scan, xid_t xid, txn_info_t *txn_info)
{
    uint8 inst_id, curr_id;

    inst_id = XID_INST_ID(xid);
    if (inst_id == session->kernel->id) {
        tx_get_info(session, is_scan, xid, txn_info);
        return;
    }

    for (;;) {
        curr_id = xid_get_inst_id(session, xid);
        if (curr_id == session->kernel->id) {
            if (rc_instance_accessible(inst_id)) {
                tx_get_info(session, is_scan, xid, txn_info);
            } else {
                cm_sleep(MES_MSG_RETRY_TIME);
                continue;
            }
        } else {
            if (dtc_get_remote_txn_info(session, is_scan, xid, curr_id, txn_info) != GS_SUCCESS) {
                cm_reset_error();
                cm_sleep(MES_MSG_RETRY_TIME);
                continue;
            }
        }
        return;
    }
}

void dtc_undo_init(knl_session_t *session, uint8 inst_id)
{
    if (inst_id == session->kernel->id) {
        return;
    }

    GS_LOG_RUN_INF("[RC] init deposit undo for instance %u", inst_id);

    undo_set_t *undo_set = UNDO_SET(session, inst_id);
    space_t *space = space_get_undo_spc(session, inst_id);
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(session);

    undo_set->space = space;
    undo_set->inst_id = inst_id;
    undo_init_impl(session, undo_set, 0, core_ctrl->undo_segments);
}

status_t dtc_tx_area_init(knl_session_t *session, uint8 inst_id)
{
    undo_set_t *undo_set = UNDO_SET(session, inst_id);

    if (inst_id == session->kernel->id) {
        return GS_SUCCESS;
    }

    GS_LOG_RUN_INF("[RC] init deposit transaction area for instance %u", inst_id);
    if (undo_set->tx_buf == NULL) {
        undo_set->tx_buf = (char *)malloc((size_t)session->kernel->attr.tran_buf_size);
        if (undo_set->tx_buf == NULL) {
            GS_LOG_RUN_ERR("[RC] failed to malloc memory for tx_buf in undo_set");
            GS_THROW_ERROR(ERR_ALLOC_MEMORY, session->kernel->attr.tran_buf_size, "deposit transaction");
            return GS_ERROR;
        }
    }
    status_t ret = memset_s(undo_set->tx_buf, (size_t)session->kernel->attr.tran_buf_size,
                            0, (size_t)session->kernel->attr.tran_buf_size);
    knl_securec_check(ret);
    /* for deposit transaction, only assign one background session to do rollback */
    undo_set->assign_workers = 1;
    for (uint32 i = 0; i < undo_set->assign_workers; i++) {
        undo_set->rb_ctx[i].inst_id = inst_id;

        if (g_knl_callback.alloc_knl_session(GS_TRUE, (knl_handle_t *)&undo_set->rb_ctx[i].session) != GS_SUCCESS) {
            CM_FREE_PTR(undo_set->tx_buf);
            GS_LOG_RUN_ERR("[RC] failed to alloc kernel session for undo rollback");
            return GS_ERROR;
        }
    }

    return tx_area_init_impl(session, undo_set, 0, UNDO_SEGMENT_COUNT(session), GS_FALSE);
}

status_t dtc_tx_rollback_start(knl_session_t *session, uint8 inst_id)
{
    undo_set_t *undo_set = UNDO_SET(session, inst_id);

    if (inst_id == session->kernel->id) {
        return GS_SUCCESS;
    }

    for (uint32 i = 0; i < undo_set->assign_workers; i++) {
        if (cm_create_thread(tx_rollback_proc, 0, &undo_set->rb_ctx[i], &undo_set->rb_ctx[i].thread) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("failed to create tx_rollback_proc %u", i);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t dtc_tx_area_load(knl_session_t *session, uint8 inst_id)
{
    if (inst_id == session->kernel->id) {
        return GS_SUCCESS;
    }

    GS_LOG_RUN_INF("[RC] load deposit transaction area for instance %u", inst_id);

    undo_set_t *undo_set = UNDO_SET(session, inst_id);
    tx_area_release(session, undo_set);
    if (dtc_tx_rollback_start(session, inst_id) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[RC] failed to start dtc_tx_rollback");
        return GS_ERROR;
    }
    GS_LOG_RUN_INF("[RC] start dtc_tx_rollback");

    return GS_SUCCESS;
}

void dtc_tx_rollback_close(knl_session_t *session, uint8 inst_id)
{
    undo_set_t *undo_set = UNDO_SET(session, inst_id);

    if (inst_id == session->kernel->id) {
        return;
    }

    for (uint32 i = 0; i < undo_set->assign_workers; i++) {
        if (undo_set->rb_ctx[i].session != NULL) {
            undo_set->rb_ctx[i].session->killed = GS_TRUE;
            undo_set->rb_ctx[i].session->force_kill = GS_TRUE;
        }
        cm_close_thread(&undo_set->rb_ctx[i].thread);
    }

    if (undo_set->active_workers > 0) {
        GS_LOG_RUN_WAR("[RC] incomplete deposit rollback %u", inst_id);
    }
}

void dtc_rollback_close(knl_session_t *session, uint8 inst_id)
{
    undo_set_t *undo_set = UNDO_SET(session, inst_id);

    if (inst_id == session->kernel->id) {
        return;
    }

    GS_LOG_RUN_INF("[RC] release deposit transaction area for instance %u", inst_id);

    dtc_tx_rollback_close(session, inst_id);

    for (uint32 i = 0; i < undo_set->assign_workers; i++) {
        if (undo_set->rb_ctx[i].session != NULL) {
            g_knl_callback.release_knl_session(undo_set->rb_ctx[i].session);
            undo_set->rb_ctx[i].session = NULL;
        }
    }

    // CM_FREE_PTR(undo_set->tx_buf);
    undo_set->assign_workers = 0;
    undo_set->active_workers = 0;
}

void dtc_undo_release(knl_session_t *session, uint8 inst_id)
{
    undo_set_t *undo_set = UNDO_SET(session, inst_id);

    if (inst_id == session->kernel->id) {
        return;
    }

    GS_LOG_RUN_INF("[RC] release deposit undo for instance %u", inst_id);

    if (undo_set->used) {
        undo_set_release(session, undo_set);
    }
}
