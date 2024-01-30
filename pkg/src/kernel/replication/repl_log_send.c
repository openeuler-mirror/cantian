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
 * repl_log_send.c
 *
 *
 * IDENTIFICATION
 * src/kernel/replication/repl_log_send.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_replication_module.h"
#include "repl_log_send.h"
#include "cs_protocol.h"
#include "knl_context.h"
#include "knl_abr.h"
#include "dtc_dls.h"

#define LSND_TID(ctx)           ((ctx)->thread.id)
#define LOGIN_CS_RETRY_COUNT    10 // login cascaded standby retry count

/* Check whether LOG_ARCHIVE_DEST_n is set both SYNC and AFFIRM */
#define LSND_SYNC_AFFIRM(ctx)   ((ctx)->dest_info.sync_mode == LOG_NET_TRANS_MODE_SYNC && \
    (ctx)->dest_info.affirm_mode == LOG_ARCH_AFFIRM)

/* Check whether LOG_ARCHIVE_DEST_n is in temp async state */
#define LSND_IS_TMP_ASYNC(ctx)  ((ctx)->dest_info.sync_mode == LOG_NET_TRANS_MODE_SYNC && (ctx)->tmp_async)

/*
 * There are three scenes that do not need to wait for log synced on SYNC standby:
 * 1) If database is not primary;
 * 2) If database is set MAX_PERFORMANCE mode;
 * 3) If database is set AVAILABILITY mode and no established SYNC standby
 */
#define LSND_NO_NEED_WAIT_SYNC(db, ctx) \
    (!DB_IS_PRIMARY((db)) || MODE_MAX_PERFORMANCE((db)) || \
    (MODE_MAX_AVAILABILITY(db) && (ctx)->est_sync_standby_num == 0))

/*
 * There are three scenes that do not need to wait for log synced on ALL TYPE standby:
 * 1) If database is not primary;
 * 2) If database is set MAX_PERFORMANCE mode;
 * 3) If database is set AVAILABILITY mode and no established standby
 */
#define LSND_NO_NEED_WAIT_ALL(db, ctx) \
    (!DB_IS_PRIMARY((db)) || MODE_MAX_PERFORMANCE((db)) || (MODE_MAX_AVAILABILITY(db) && (ctx)->est_standby_num == 0))
/*
 * 1) If the standby is set ASYNC, no need to wait;
 * 2) If all standbys are set NOAFFIRM, log sender just wait for only one standby's ack.
 */
#define STANDBY_NO_NEED_WAIT(db, ctx, lsnd) \
    ((lsnd)->status < LSND_LOG_SHIFTING || \
    (lsnd)->dest_info.sync_mode != LOG_NET_TRANS_MODE_SYNC || \
    (MODE_MAX_PROTECTION(db) && (ctx)->affirm_standy_num > 0 && (lsnd)->dest_info.affirm_mode != LOG_ARCH_AFFIRM) || \
    (MODE_MAX_AVAILABILITY(db) && (ctx)->est_affirm_standy_num > 0 && (lsnd)->dest_info.affirm_mode != LOG_ARCH_AFFIRM))

typedef enum en_degrade_type {
    DEGRADE_FLUSH_LOG = 0,
    DEGRADE_WAIT_RESP = 1,
    DEGRADE_WAIT_SWITCH = 2,
    DEGRADE_SESSION_KILL = 3,
} degrade_type_t;

static void lsnd_set_tmp_async(lsnd_t *lsnd, degrade_type_t type);
static bool32 lsnd_flush_need_exit(knl_session_t *session);

static void lsnd_close_single_thread(lsnd_t *lsnd)
{
    knl_instance_t *kernel = lsnd->session->kernel;
    lsnd_context_t *ctx = &kernel->lsnd_ctx;
    log_file_t *logfile = NULL;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(lsnd->session);

    cm_close_thread(&lsnd->thread);
    cm_close_device(cm_device_type(lsnd->arch_file.file_name), &lsnd->arch_file.handle);

    for (uint32 i = 0; i < logfile_set->logfile_hwm; i++) {
        logfile = &logfile_set->items[i];
        if (LOG_IS_DROPPED(logfile->ctrl->flg)) {
            continue;
        }

        cm_close_device(logfile->ctrl->type, &lsnd->log_handle[i]);
    }

    if (LSND_SYNC_AFFIRM(lsnd) && ctx->affirm_standy_num > 0) {
        ctx->affirm_standy_num--;
    }

    if (lsnd->status >= LSND_LOG_SHIFTING) {
        ctx->est_standby_num--;
        if (lsnd->dest_info.sync_mode == LOG_NET_TRANS_MODE_SYNC && !lsnd->tmp_async) {
            knl_panic(ctx->est_sync_standby_num > 0);
            ctx->est_sync_standby_num--;

            if (LSND_SYNC_AFFIRM(lsnd) && ctx->est_affirm_standy_num > 0) {
                ctx->est_affirm_standy_num--;
            }
        }
    }
    cm_aligned_free(&lsnd->send_buf.read_buf);
    cm_aligned_free(&lsnd->recv_buf.read_buf);
    if (lsnd->dest_info.compress_alg != COMPRESS_NONE) {
        cm_aligned_free(&lsnd->c_ctx.compress_buf);
        if (lsnd->dest_info.compress_alg == COMPRESS_ZSTD) {
            (void)ZSTD_freeCCtx(lsnd->c_ctx.zstd_cctx);
        }
    }
    CM_FREE_PTR(lsnd->extra_head);
    lsnd->is_disable = CT_TRUE;
}

static void lsnd_free_single_proc_context(lsnd_t *lsnd)
{
    if (lsnd == NULL || lsnd->is_disable) {
        return;
    }

    knl_session_t *session = lsnd->session;
    log_file_t *logfile = NULL;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);

    cm_aligned_free(&lsnd->send_buf.read_buf);
    cm_aligned_free(&lsnd->recv_buf.read_buf);
    if (lsnd->dest_info.compress_alg != COMPRESS_NONE) {
        cm_aligned_free(&lsnd->c_ctx.compress_buf);
        if (lsnd->dest_info.compress_alg == COMPRESS_ZSTD) {
            (void)ZSTD_freeCCtx(lsnd->c_ctx.zstd_cctx);
        }
    }
    CM_FREE_PTR(lsnd->extra_head);

    for (uint32 i = 0; i < logfile_set->logfile_hwm; i++) {
        logfile = &logfile_set->items[i];
        if (LOG_IS_DROPPED(logfile->ctrl->flg)) {
            continue;
        }

        cm_close_device(logfile->ctrl->type, &lsnd->log_handle[i]);
    }

    lsnd->is_disable = CT_TRUE;
}

static bool32 lsnd_connecting_primary(knl_session_t *session, const char *host, uint16 port)
{
    database_t *db = &session->kernel->db;
    char pri_host[CT_HOST_NAME_BUFFER_SIZE];
    uint16 pri_port;

    if (DB_IS_PRIMARY(db) || session->kernel->lrcv_ctx.pipe == NULL) {
        return CT_FALSE;
    }

    if (lrcv_get_primary_server(session, 0, pri_host, CT_HOST_NAME_BUFFER_SIZE, &pri_port) != CT_SUCCESS) {
        return CT_FALSE;
    }

    if (strcmp(host, pri_host) == 0 && port == pri_port) {
        return CT_TRUE;
    }

    return CT_FALSE;
}

void lsnd_close_all_thread(knl_session_t *session)
{
    lsnd_context_t *ctx = &session->kernel->lsnd_ctx;
    cm_latch_x(&ctx->latch, session->id, NULL);

    for (uint16 i = 0; i < ctx->standby_num; i++) {
        if (ctx->lsnd[i] == NULL || ctx->lsnd[i]->is_disable) {
            continue;
        }

        lsnd_close_single_thread(ctx->lsnd[i]);
    }

    cm_release_eventfd(&ctx->eventfd);
    errno_t err = memset_sp(ctx, (uint32)OFFSET_OF(lsnd_context_t, lsnd), 0, (uint32)OFFSET_OF(lsnd_context_t, lsnd));
    knl_securec_check(err);

    cm_unlatch(&ctx->latch, NULL);
    CT_LOG_RUN_INF("[Log Sender] close all log sender thread.");
}

void lsnd_close_disabled_thread(knl_session_t *session)
{
    lsnd_context_t *ctx = &session->kernel->lsnd_ctx;

    cm_latch_x(&ctx->latch, session->id, NULL);

    for (uint16 i = 0; i < ctx->standby_num; i++) {
        if (ctx->lsnd[i] == NULL || ctx->lsnd[i]->is_disable) {
            continue;
        }

        if (lsnd_connecting_primary(session, ctx->lsnd[i]->dest_info.peer_host, ctx->lsnd[i]->dest_info.peer_port) ||
            arch_dest_state_disabled(session, ctx->lsnd[i]->dest_info.attr_idx) ||
            DB_IS_CASCADED_PHYSICAL_STANDBY(&session->kernel->db)) {
            CT_LOG_RUN_INF("[Log Sender] close unused log sender thread");
            ctx->lsnd[i]->is_deferred = CT_TRUE;

            lsnd_close_single_thread(ctx->lsnd[i]);
        }
    }

    cm_unlatch(&ctx->latch, NULL);
}

void lsnd_mark_reconnect(knl_session_t *session, bool32 resetid_changed, bool32 host_changed)
{
    lsnd_context_t *ctx = &session->kernel->lsnd_ctx;

    cm_latch_s(&ctx->latch, session->id, CT_FALSE, NULL);

    for (uint16 i = 0; i < ctx->standby_num; i++) {
        if (ctx->lsnd[i] != NULL && !ctx->lsnd[i]->is_disable && ctx->lsnd[i]->status > LSND_DISCONNECTED) {
            ctx->lsnd[i]->resetid_changed_reconnect = resetid_changed;
            ctx->lsnd[i]->host_changed_reconnect = host_changed;
        }
    }

    cm_unlatch(&ctx->latch, NULL);
}

static bool32 lsnd_rcv_msg_is_valid(lsnd_t *lsnd, uint32 type)
{
    switch (type) {
        case REP_BATCH_RESP: {
            rep_batch_resp_t *batch_resp = (rep_batch_resp_t *)lsnd->recv_buf.read_buf.aligned_buf;
            if (log_point_is_invalid(&batch_resp->flush_point) || log_point_is_invalid(&batch_resp->rcy_point)) {
                return CT_FALSE;
            }
            break;
        }

        case REP_HEART_BEAT_RESP: {
            rep_hb_resp_t *hb_resp = (rep_hb_resp_t *)lsnd->recv_buf.read_buf.aligned_buf;
            if (lsnd->status < LSND_LOG_SHIFTING) {
                break;
            }
            if (log_point_is_invalid(&hb_resp->flush_point) || log_point_is_invalid(&hb_resp->rcy_point)) {
                return CT_FALSE;
            }
            break;
        }

        case REP_LOG_SWITCH_WAIT_REQ:
        case REP_QUERY_STATUS_RESP:
        case REP_SWITCH_REQ:
        case REP_ABR_RESP: {
            break;
        }

        case REP_RECORD_BACKUPSET_REQ: {
            bak_record_t *rec = (bak_record_t *)lsnd->recv_buf.read_buf.aligned_buf;
            if (rec->attr.tag[0] == '\0' || rec->path[0] == '\0' ||
                rec->attr.backup_type < BACKUP_MODE_INVALID || rec->attr.backup_type > BACKUP_MODE_TABLESPACE ||
                rec->attr.compress < COMPRESS_NONE || rec->attr.compress > COMPRESS_LZ4 ||
                rec->status < BACKUP_SUCCESS || rec->status > BACKUP_FAILED ||
                rec->device < DEVICE_DISK || rec->device > DEVICE_UDS ||
                log_point_is_invalid(&rec->ctrlinfo.rcy_point) ||
                log_point_is_invalid(&rec->ctrlinfo.lrp_point)) {
                return CT_FALSE;
            }
            break;
        }

        default: {
            return CT_FALSE;
        }
    }

    return CT_TRUE;
}

static status_t lsnd_receive(lsnd_t *lsnd, uint32 timeout, uint32 *type, int32 *recv_size)
{
    rep_msg_header_t message_header;

    if (cs_read_stream(&lsnd->pipe, (char *)&message_header, timeout, sizeof(rep_msg_header_t),
                       recv_size) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[Log Sender] failed to receive message from standby");
        return CT_ERROR;
    }

    if (*recv_size == 0) {
        return CT_SUCCESS;
    }

    *type = message_header.type;
    uint32 remain_size = message_header.size - (uint32)*recv_size;

    if (message_header.size < (uint32)*recv_size || remain_size > lsnd->recv_buf.read_buf.buf_size) {
        CT_LOG_RUN_ERR("[Log Sender] invalid message_header size %u received, buf_size is %u, recv_size is %u",
                       message_header.size, (uint32)lsnd->recv_buf.read_buf.buf_size, (uint32)*recv_size);
        return CT_ERROR;
    }

    if (remain_size > 0) {
        if (cs_read_stream(&lsnd->pipe, lsnd->recv_buf.read_buf.aligned_buf, REPL_RECV_TIMEOUT, remain_size,
                           recv_size) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[Log Sender] failed to receive message from standby");
            return CT_ERROR;
        }

        remain_size -= (uint32)*recv_size;
    }

    if (remain_size != 0) {
        CT_LOG_RUN_ERR("[Log Sender] receive abnormal message from standby, expected size is %u, but actual size is %d",
            (uint32)(message_header.size - sizeof(rep_msg_header_t)), *recv_size);
        return CT_ERROR;
    }

    if (!lsnd_rcv_msg_is_valid(lsnd, *type)) {
        CT_LOG_RUN_ERR("[Log Sender] invalid message %u received", *type);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t lsnd_send_switch_response(lsnd_t *lsnd)
{
    rep_msg_header_t rep_msg_header;
    rep_switch_resp_t req_switch_resp;

    rep_msg_header.size = sizeof(rep_msg_header_t) + sizeof(rep_switch_resp_t);
    rep_msg_header.type = REP_SWITCH_RESP;
    req_switch_resp.state = lsnd->state;

    if (cs_write_stream(&lsnd->pipe, (char *)&rep_msg_header, sizeof(rep_msg_header_t),
        (int32)cm_atomic_get(&lsnd->session->kernel->attr.repl_pkg_size)) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[Log Sender] failed to send switchover response message to standby");
        return CT_ERROR;
    }

    if (cs_write_stream(&lsnd->pipe, (char *)&req_switch_resp, sizeof(rep_switch_resp_t),
        (int32)cm_atomic_get(&lsnd->session->kernel->attr.repl_pkg_size)) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[Log Sender] failed to send log sender state response message to standby");
        return CT_ERROR;
    }

    lsnd->state = REP_STATE_NORMAL;

    CT_LOG_RUN_INF("[Log Sender] send switchover response to standby");

    return CT_SUCCESS;
}

static status_t lsnd_process_switch_request(lsnd_t *lsnd)
{
    switch_ctrl_t *ctrl = &lsnd->session->kernel->switch_ctrl;

    cm_spin_lock(&ctrl->lock, NULL);

    if (ctrl->request != SWITCH_REQ_NONE) {
        cm_spin_unlock(&ctrl->lock);

        CT_LOG_RUN_INF("[Log Sender] primary may doing switchover");

        return lsnd_send_switch_response(lsnd);
    }
    ctrl->request = SWITCH_REQ_DEMOTE;
    lsnd->state = REP_STATE_DEMOTE_REQUEST;

    cm_spin_unlock(&ctrl->lock);

    CT_LOG_RUN_INF("[Log Sender] received switchover request from standby");

    return CT_SUCCESS;
}

static inline void lsnd_trigger_record_backup(knl_session_t *session, uint32 client_id)
{
    knl_panic(!session->kernel->record_backup_trigger[client_id]);
    session->kernel->record_backup_trigger[client_id] = CT_TRUE;
}

static status_t lsnd_process_record_bak_request(lsnd_t *lsnd)
{
    lsnd_bak_task_t *bak_task = &lsnd->bak_task;
    if (bak_task->task.status != BAK_TASK_DONE) {
        CT_LOG_RUN_ERR("[Log Sender] another backup record request is in progress");
        return CT_ERROR;
    }

    errno_t err = memcpy_s(&bak_task->record, sizeof(bak_record_t),
                           lsnd->recv_buf.read_buf.aligned_buf, sizeof(bak_record_t));
    knl_securec_check(err);
    lsnd_trigger_record_backup(lsnd->session, lsnd->id);
    bak_task->task.failed = CT_FALSE;
    bak_task->task.status = BAK_TASK_WAIT_PROCESS;
    return CT_SUCCESS;
}

static void lsnd_process_abr_resp(lsnd_t *lsnd)
{
    rep_abr_resp_t *abr_resp = (rep_abr_resp_t *)lsnd->recv_buf.read_buf.aligned_buf;
    lsnd_abr_task_t *task = &lsnd->abr_task;
    if (task == NULL) {
        CT_LOG_RUN_ERR("[ABR] failed to process response, error log sender id %u", abr_resp->lsnd_id);
        return;
    }

    char *page = ((char *)abr_resp + sizeof(rep_abr_resp_t));
    abr_finish_task(task, CT_TRUE, page, task->buf_size);
}

static inline void lsnd_process_batch_resp(lsnd_t *lsnd)
{
    rep_batch_resp_t *batch_resp = (rep_batch_resp_t *)lsnd->recv_buf.read_buf.aligned_buf;

    lsnd->peer_flush_point = batch_resp->flush_point;

    cm_thread_eventfd_t *eventfd = &lsnd->session->kernel->lsnd_ctx.eventfd;
    cm_wakeup_eventfd(eventfd);

    lsnd->peer_rcy_point = batch_resp->rcy_point;
    lsnd->peer_replay_lsn = batch_resp->replay_lsn;
    lsnd->peer_flush_scn = batch_resp->flush_scn;
    lsnd->peer_current_scn = batch_resp->current_scn;
    if (lsnd->pipe.version >= CS_VERSION_13) {
        lsnd->peer_contflush_point = batch_resp->contflush_point;
    }

    CT_LOG_DEBUG_INF("[Log Sender] peer flush point [%u-%u/%u/%llu], peer rcy point [%u-%u/%u/%llu]",
                     lsnd->peer_flush_point.rst_id, lsnd->peer_flush_point.asn,
                     lsnd->peer_flush_point.block_id, (uint64)lsnd->peer_flush_point.lfn,
                     lsnd->peer_rcy_point.rst_id, lsnd->peer_rcy_point.asn,
                     lsnd->peer_rcy_point.block_id, (uint64)lsnd->peer_rcy_point.lfn);
}

static inline void lsnd_process_hb_resp(lsnd_t *lsnd)
{
    rep_hb_resp_t *hb_resp = (rep_hb_resp_t *)lsnd->recv_buf.read_buf.aligned_buf;

    lsnd->peer_flush_point = hb_resp->flush_point;
    lsnd->peer_rcy_point = hb_resp->rcy_point;
    lsnd->peer_replay_lsn = hb_resp->replay_lsn;
    lsnd->peer_flush_scn = hb_resp->flush_scn;
    lsnd->peer_current_scn = hb_resp->current_scn;
    if (lsnd->pipe.version >= CS_VERSION_13) {
        lsnd->peer_contflush_point = hb_resp->contflush_point;
    }
}

static void lsnd_process_query_status_ready(lsnd_t *lsnd)
{
    reset_log_t rst_log = lsnd->session->kernel->db.ctrl.core.resetlogs;
    lsnd_context_t *lsnd_ctx = &lsnd->session->kernel->lsnd_ctx;
    rep_query_status_resp_t *query_resp = (rep_query_status_resp_t *)lsnd->recv_buf.read_buf.aligned_buf;

    lsnd->peer_flush_point = query_resp->flush_point;
    lsnd->peer_rcy_point = query_resp->rcy_point;
    lsnd->peer_replay_lsn = query_resp->replay_lsn;
    lsnd->send_point = lsnd->peer_flush_point;
    CT_LOG_RUN_INF("[Log Sender] received message REP_QUERY_STATUS_RESP, peer flush point "
                   "[%u-%u/%u/%llu], peer rcy point [%u-%u/%u/%llu]",
                   lsnd->peer_flush_point.rst_id, lsnd->peer_flush_point.asn,
                   lsnd->peer_flush_point.block_id, (uint64)lsnd->peer_flush_point.lfn,
                   lsnd->peer_rcy_point.rst_id, lsnd->peer_rcy_point.asn,
                   lsnd->peer_rcy_point.block_id, (uint64)lsnd->peer_rcy_point.lfn);

    if (lsnd->send_point.lfn == rst_log.last_lfn) {
        lsnd->send_point.rst_id = rst_log.rst_id;
        lsnd->send_point.asn = rst_log.last_asn + 1;
        lsnd->send_point.block_id = 0;
        CT_LOG_RUN_INF("[Log Sender] Peer flush point equals to last restlog[%u-%u/%llu], "
                       "so move send point to next [%u-%u/%u/%llu]",
                       rst_log.rst_id, rst_log.last_asn, rst_log.last_lfn,
                       lsnd->send_point.rst_id, lsnd->send_point.asn,
                       lsnd->send_point.block_id, (uint64)lsnd->send_point.lfn);
    }

    lsnd->send_buf.read_pos = 0;
    lsnd->send_buf.write_pos = 0;
    lsnd->status = LSND_LOG_SHIFTING;

    lsnd_ctx->est_standby_num++;
    if (lsnd->dest_info.sync_mode == LOG_NET_TRANS_MODE_SYNC && !lsnd->tmp_async) {
        lsnd_ctx->est_sync_standby_num++;
        if (lsnd->dest_info.affirm_mode == LOG_ARCH_AFFIRM) {
            lsnd_ctx->est_affirm_standy_num++;
        }
    }
}

static status_t lsnd_process_query_status_resp(lsnd_t *lsnd)
{
    rep_query_status_resp_t *query_resp = (rep_query_status_resp_t *)lsnd->recv_buf.read_buf.aligned_buf;

    if (query_resp->is_ready) {
        lsnd_process_query_status_ready(lsnd);
    } else {
        CT_LOG_DEBUG_INF("[Log Sender] Receive message REP_QUERY_STATUS_RESP, standby is not ready.");
    }

    lsnd->peer_is_building = query_resp->is_building;

    if (DB_IS_PRIMARY(&lsnd->session->kernel->db) && query_resp->is_building_cascaded) {
        lsnd->is_deferred = CT_TRUE;
        arch_set_deststate_disabled(lsnd->session, lsnd->dest_info.attr_idx);
        CT_LOG_RUN_INF("[Log Sender] query standby status, local is primary, "
                       "peer is building cascaded physical standby, should disconnect with it");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static void lsnd_process_switch_wait(lsnd_t *lsnd)
{
    rep_log_switch_wait_t *switch_wait = (rep_log_switch_wait_t *)lsnd->recv_buf.read_buf.aligned_buf;

    if (switch_wait->wait_point.asn != CT_INVALID_ASN) {
        lsnd->wait_point = switch_wait->wait_point;
        if (lsnd->dest_info.sync_mode == LOG_NET_TRANS_MODE_SYNC) {
            lsnd_set_tmp_async(lsnd, DEGRADE_WAIT_SWITCH);
        }
    } else {
        lsnd->send_point = lsnd->wait_point;
        lsnd->wait_point = switch_wait->wait_point;
        CT_LOG_RUN_INF("[Log Sender] standby log switch will go ahead");
    }
}

static status_t lsnd_process_message(lsnd_t *lsnd, uint32 type)
{
    lsnd->last_recv_time = cm_current_time();

    switch (type) {
        case REP_BATCH_RESP: {
            lsnd_process_batch_resp(lsnd);
            break;
        }
        case REP_QUERY_STATUS_RESP: {
            if (lsnd_process_query_status_resp(lsnd) != CT_SUCCESS) {
                return CT_ERROR;
            }
            break;
        }
        case REP_HEART_BEAT_RESP: {
            lsnd_process_hb_resp(lsnd);
            break;
        }
        case REP_SWITCH_REQ: {
            if (lsnd_process_switch_request(lsnd) != CT_SUCCESS) {
                return CT_ERROR;
            }
            break;
        }
        case REP_ABR_RESP: {
            lsnd_process_abr_resp(lsnd);
            break;
        }
        case REP_RECORD_BACKUPSET_REQ: {
            if (lsnd_process_record_bak_request(lsnd) != CT_SUCCESS) {
                return CT_ERROR;
            }
            break;
        }
        case REP_LOG_SWITCH_WAIT_REQ: {
            lsnd_process_switch_wait(lsnd);
            break;
        }
        default: {
            CT_LOG_RUN_ERR("[Log Sender] invalid replication message type %u", type);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t lsnd_process_message_if_any(lsnd_t *lsnd)
{
    int32 recv_size;
    uint32 type;

    while (1) {
        if (lsnd_receive(lsnd, 0, &type, &recv_size) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (recv_size == 0) {
            break;
        }

        if (lsnd_process_message(lsnd, type) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[Log Sender] failed to process message from standby");
            return CT_ERROR;
        }
    }

    if (lsnd->state == REP_STATE_NORMAL && ((cm_current_time() - lsnd->last_recv_time) >= lsnd->timeout)) {
        CT_LOG_RUN_ERR("[Log Sender] %lu has not received response more than %u s", LSND_TID(lsnd), lsnd->timeout);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t lsnd_process_record_backup_response(lsnd_t *lsnd)
{
    rep_bak_task_t *task = &lsnd->bak_task.task;
    rep_msg_header_t rep_msg_header;

    if (task->status != BAK_TASK_WAIT_RESPONSE) {
        return CT_SUCCESS;
    }

    rep_msg_header.size = sizeof(rep_msg_header_t) + sizeof(bool32);
    rep_msg_header.type = REP_RECORD_BACKUPSET_RESP;

    if (cs_write_stream(&lsnd->pipe, (char *)&rep_msg_header, sizeof(rep_msg_header_t),
                        (int32)cm_atomic_get(&lsnd->session->kernel->attr.repl_pkg_size)) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[Log Sender] failed to send record backupset response message to standby");
        return CT_ERROR;
    }

    if (cs_write_stream(&lsnd->pipe, (char *)&task->failed, sizeof(bool32),
                        (int32)cm_atomic_get(&lsnd->session->kernel->attr.repl_pkg_size)) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[Log Sender] failed to send record backupset status to standby");
        return CT_ERROR;
    }

    CT_LOG_RUN_INF("[Log Sender] send record backupset response to standby");

    task->status = BAK_TASK_DONE;
    return CT_SUCCESS;
}

// Process ABR message to standby if any ABR task is triggered
void lsnd_process_abr_task(lsnd_t *lsnd)
{
    lsnd_abr_task_t *task = &lsnd->abr_task;

    cm_spin_lock(&task->lock, NULL);
    if (task->running && !task->executing) {
        task->executing = CT_TRUE;
        // send ABR message to standby
        if (abr_send_page_fetch_req(lsnd, task) != CT_SUCCESS) {
            /*
             * if send ABR failed, just continue and retry at next time.
             * no need to return failure. When send timeout, task will been reset at abr_wait_task_done
             */
            task->executing = CT_FALSE;
            CT_LOG_RUN_WAR("[ABR] failed to send ABR task to standby for page[%u-%u] with lsnd id %u",
                           task->file, task->page, task->lsnd_id);
        } else {
            CT_LOG_RUN_INF("[ABR] succeed to send ABR task to standby for file %u page %u with lsnd id %u",
                           task->file, task->page, task->lsnd_id);
        }
    }

    cm_spin_unlock(&task->lock);
}

static status_t lsnd_process_message_once(lsnd_t *lsnd)
{
    int32 recv_size;
    uint32 type;

    if (lsnd_receive(lsnd, 0, &type, &recv_size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (recv_size > 0) {
        return lsnd_process_message(lsnd, type);
    }

    return CT_SUCCESS;
}

static inline bool32 lsnd_need_notify_repair(lsnd_t *lsnd)
{
    lrcv_context_t *lrcv = &lsnd->session->kernel->lrcv_ctx;
    database_t *db = &lsnd->session->kernel->db;

    if (DB_IS_PRIMARY(db) ||
        (DB_IS_PHYSICAL_STANDBY(db) && lrcv->status == LRCV_READY)) {
        return CT_TRUE;
    }

    return CT_FALSE;
}

static status_t lsnd_put_batch_message(lsnd_t *lsnd, log_point_t *point, uint32 file_id, uint64 size)
{
    rep_msg_header_t *rep_msg_header = NULL;
    rep_batch_req_t *rep_batch_req = NULL;
    log_batch_t *batch = NULL;
    log_batch_tail_t *tail = NULL;
    uint32 left_size = (uint32)size;
    log_context_t *redo_ctx = &lsnd->session->kernel->redo_ctx;
    log_file_t *file = &redo_ctx->files[file_id];
    uint32 new_compress_buf_size = 0;

    lsnd->send_buf.read_pos = 0;
    lsnd->send_buf.write_pos = 0;

    rep_msg_header = (rep_msg_header_t *)(lsnd->extra_head);
    rep_msg_header->size = (uint32)size + lsnd->header_size;
    rep_msg_header->type = REP_BATCH_REQ;

    rep_batch_req = (rep_batch_req_t *)(lsnd->extra_head + sizeof(rep_msg_header_t));
    rep_batch_req->log_point = *point;
    rep_batch_req->log_file_id = file_id;
    rep_batch_req->curr_point = redo_ctx->curr_point;
    rep_batch_req->compress_alg = lsnd->dest_info.compress_alg;

    batch = (log_batch_t *)lsnd->send_buf.read_buf.aligned_buf;
    if (log_need_realloc_buf(batch, &lsnd->send_buf.read_buf, "lsnd batch buffer", CT_MAX_BATCH_SIZE + SIZE_K(4))) {
        if (lsnd->dest_info.compress_alg == COMPRESS_NONE) {
            return CT_SUCCESS;
        } else if (lsnd->dest_info.compress_alg == COMPRESS_ZSTD) {
            new_compress_buf_size = (uint32)ZSTD_compressBound((uint32)CT_MAX_BATCH_SIZE) + SIZE_K(4);
        } else if (lsnd->dest_info.compress_alg == COMPRESS_LZ4) {
            new_compress_buf_size = (uint32)LZ4_compressBound((int32)CT_MAX_BATCH_SIZE) + SIZE_K(4);
        } else {
            CT_LOG_RUN_ERR("[Log Sender] unsupported compress algorithm.");
            return CT_ERROR;
        }

        if (cm_aligned_realloc((int64)new_compress_buf_size, "lsnd compress buffer",
                               &lsnd->c_ctx.compress_buf) != CT_SUCCESS) {
            CM_ABORT(0, "ABORT INFO: malloc lsnd compress buffer fail.");
        }
        lsnd->c_ctx.compress_buf.buf_size = new_compress_buf_size;
        return CT_SUCCESS;
    }
    tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));
    lsnd->last_put_point = *point;

    if (size < batch->space_size) {
        lsnd->notify_repair = lsnd_need_notify_repair(lsnd);
        CT_LOG_RUN_ERR("[Log Sender] found invalid batch at point [%u-%u/%u/%llu], batch size is %u, "
                       "larger than read size %llu",
                       point->rst_id, point->asn, point->block_id, (uint64)point->lfn, batch->space_size, size);
        return CT_ERROR;
    }

    while (left_size >= sizeof(log_batch_t)) {
        if (!rcy_validate_batch(batch, tail)) {
            lsnd->notify_repair = lsnd_need_notify_repair(lsnd);
            CT_LOG_RUN_ERR("[Log Sender] Invalid batch with lfn %llu read, size is [%u/%llu]",
                           (uint64)batch->head.point.lfn, left_size, size);
            return CT_ERROR;
        }

        if (rcy_verify_checksum(lsnd->session, batch) != CT_SUCCESS) {
            return CT_ERROR;
        }

        CT_LOG_DEBUG_INF("[Log Sender] Put batch [%u-%u/%u/%llu] space size %u",
                         lsnd->last_put_point.rst_id, lsnd->last_put_point.asn,
                         lsnd->last_put_point.block_id, (uint64)batch->head.point.lfn, batch->space_size);

        rep_batch_req->log_point.lfn = batch->head.point.lfn;
        rep_batch_req->scn = batch->scn;
        lsnd->last_put_point.lfn = batch->head.point.lfn;
        lsnd->last_put_point.block_id += batch->space_size / file->ctrl->block_size;

        left_size -= batch->space_size;

        batch = (log_batch_t *)((char *)batch + batch->space_size);
        tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));

        if (left_size < batch->space_size) {
            rep_msg_header->size -= left_size;
            break;
        }
    }

    lsnd->send_buf.write_pos = (uint32)(size - left_size);
    return CT_SUCCESS;
}

static status_t lsnd_read_online_logfile(lsnd_t *lsnd, uint32 file_id)
{
    knl_session_t *session = lsnd->session;
    log_context_t *ctx = &session->kernel->redo_ctx;
    log_point_t *point = &lsnd->send_point;
    log_file_t *file = NULL;
    uint64 size;
    int64 offset;

    file = &ctx->files[file_id];
    if (point->block_id == 0) {
        point->block_id = 1;
    }

    offset = (int64)file->head.block_size * point->block_id;
    if (file->head.write_pos < (uint64)offset) {
        log_unlatch_file(session, file_id);
        CT_LOG_RUN_ERR("[Log Sender] found corrupted file[%u] %s, write pos is %llu, expected read offset is %llu",
                       file_id, file->ctrl->name, file->head.write_pos, (uint64)offset);
        return CT_ERROR;
    }

    size = file->head.write_pos - (uint64)offset;
    if (size == 0) {
        cm_unlatch(&file->latch, NULL);
        return CT_SUCCESS;
    }
    size = (size > (uint64)lsnd->send_buf.read_buf.buf_size) ? (uint64)lsnd->send_buf.read_buf.buf_size : size;
    if (cm_read_device(file->ctrl->type, lsnd->log_handle[file_id], offset, lsnd->send_buf.read_buf.aligned_buf,
                       (uint32)size) != CT_SUCCESS) {
        log_unlatch_file(session, file_id);
        CT_LOG_RUN_ERR("[Log Sender] failed to read %s ", file->ctrl->name);
        return CT_ERROR;
    }

    lsnd->last_read_asn = file->head.asn;
    lsnd->last_read_file_id = file_id;
    log_unlatch_file(session, file_id);

    return lsnd_put_batch_message(lsnd, point, file_id, size);
}

static status_t lsnd_read_arch_logfile(lsnd_t *lsnd)
{
    knl_session_t *session = lsnd->session;
    log_point_t *point = &lsnd->send_point;
    lsnd_arch_file_t *file = &lsnd->arch_file;
    bool32 read_end = CT_FALSE;
    uint64 size;
    device_type_t type = cm_device_type(file->file_name);

    if (file->asn > point->asn) {
        CT_LOG_RUN_ERR("[Log Sender] invalid send point [%u-%u/%u/%llu], arch file asn is %u, name %s",
                       point->rst_id, point->asn, point->block_id, (uint64)point->lfn, file->asn, file->file_name);
        return CT_ERROR;
    }

    if (file->asn != point->asn) {
        arch_ctrl_t *arch_ctrl = arch_get_archived_log_info(session, (uint32)point->rst_id, point->asn, 1,
                                                            session->kernel->id);
        if (arch_ctrl == NULL) {
            CT_LOG_RUN_ERR("[Log Sender] failed to get archived log file [%u-%u]", point->rst_id, point->asn);
            return CT_ERROR;
        }

        bool32 compressed = arch_is_compressed(arch_ctrl);
        errno_t ret = strcpy_sp(file->file_name, CT_FILE_NAME_BUFFER_SIZE, arch_ctrl->name);
        knl_securec_check(ret);

        /* file is closed in lsnd_set_conn_error, or when file is read end in this function */
        if (cm_open_device(file->file_name, type,
                           knl_arch_io_flag(session, compressed), &file->handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[Log Sender] failed to open %s, handle %d", file->file_name, file->handle);
            return CT_ERROR;
        }

        file->asn = point->asn;
        file->block_size = (uint32)arch_ctrl->block_size;

        log_file_head_t *head = (log_file_head_t *)lsnd->send_buf.read_buf.aligned_buf;
        size = CM_CALC_ALIGN(sizeof(log_file_head_t), file->block_size);
        if (cm_read_device(type, file->handle, 0, head, size) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[Log Sender] failed to read %s, handle %d", file->file_name, file->handle);
            return CT_ERROR;
        }

        if (log_verify_head_checksum(session, head, file->file_name) != CT_SUCCESS) {
            return CT_ERROR;
        }

        file->write_pos = head->write_pos;
    }

    if (point->block_id == 0) {
        point->block_id = 1;
    }

    size = file->write_pos - (uint64)point->block_id * file->block_size;
    if (size == 0) {
        cm_close_device(type, &file->handle);
        return CT_SUCCESS;
    }

    if (size <= (uint64)lsnd->send_buf.read_buf.buf_size) {
        read_end = CT_TRUE;
    } else {
        size = (uint64)lsnd->send_buf.read_buf.buf_size;
    }

    if (cm_open_device(file->file_name, type, knl_redo_io_flag(session),
                       &file->handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[Log Sender] failed to open %s ", file->file_name);
        return CT_ERROR;
    }

    if (cm_read_device(type, file->handle, (int64)point->block_id * file->block_size,
                       lsnd->send_buf.read_buf.aligned_buf, (int32)size) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[Log Sender] failed to read %s ", file->file_name);
        return CT_ERROR;
    }

    if (read_end) {
        cm_close_device(type, &file->handle);
    }

    return lsnd_put_batch_message(lsnd, point, (uint32)lsnd->last_read_file_id, size);
}

static bool32 lsnd_read_log_precheck(lsnd_t *lsnd, log_point_t *target_point)
{
    log_point_t *send_point = &lsnd->send_point;
    log_point_t flush_point = lsnd->session->kernel->lrcv_ctx.flush_point;
    database_t *db = &lsnd->session->kernel->db;

    /*
     * The primary does not send logs to the standby temporarily,
     * when the standby is waiting for log switch.
     */
    if (SECUREC_UNLIKELY(lsnd->wait_point.asn != CT_INVALID_ASN)) {
        return CT_FALSE;
    }

    // Sync standby no need to read batch from log file.
    if (DB_IS_PRIMARY(db) && lsnd->dest_info.sync_mode == LOG_NET_TRANS_MODE_SYNC && !lsnd->tmp_async) {
        return CT_FALSE;
    }

    if (DB_IS_PHYSICAL_STANDBY(db)) {
        if (log_cmp_point(&flush_point, target_point) > 0) {
            *target_point = flush_point;
        }
    }

    if (log_cmp_point(send_point, target_point) >= 0 || LOG_POINT_LFN_EQUAL(send_point, target_point)) {
        return CT_FALSE;
    }

    cm_spin_lock(&lsnd->lock, NULL);
    if ((DB_IS_PRIMARY(db) && lsnd->dest_info.sync_mode == LOG_NET_TRANS_MODE_SYNC && !lsnd->tmp_async) ||
        (send_point->lfn == target_point->lfn + 1)) {
        cm_spin_unlock(&lsnd->lock);
        return CT_FALSE;
    }
    lsnd->in_async = CT_TRUE;
    cm_spin_unlock(&lsnd->lock);

    return CT_TRUE;
}

static bool32 lsnd_need_reconnect_cs(lsnd_t *lsnd)
{
    knl_instance_t *knl = lsnd->session->kernel;
    lrcv_context_t *lrcv = &knl->lrcv_ctx;
    database_t *db = &knl->db;

    if (!DB_IS_PHYSICAL_STANDBY(db) || !lsnd->host_changed_reconnect || lrcv->status != LRCV_READY) {
        return CT_FALSE;
    }

    if (lrcv->reset_asn == CT_INVALID_ASN) {
        lsnd->host_changed_reconnect = CT_FALSE;
        return CT_FALSE;
    }

    if (lsnd->send_point.asn >= lrcv->reset_asn) {
        lsnd->host_changed_reconnect = CT_FALSE;
        CT_LOG_RUN_INF("[LSND] Reconnect to cascaded standby, for host of primary has changed");
        return CT_TRUE;
    }

    return CT_FALSE;
}

static inline bool32 lsnd_read_log_should_suspend(knl_session_t *session, uint32 fileid, bool32 loading_curr)
{
    if (!DB_IS_PHYSICAL_STANDBY(&session->kernel->db)) {
        return CT_FALSE;
    }

    if (fileid == CT_INVALID_ID32 || !loading_curr) {
        return CT_FALSE;
    }

    if (session->kernel->lrcv_ctx.status < LRCV_READY) {
        return CT_TRUE;
    }

    return CT_FALSE;
}

static status_t lsnd_read_log(lsnd_t *lsnd)
{
    log_point_t *send_point = &lsnd->send_point;
    log_point_t target_point = lsnd->session->kernel->redo_ctx.curr_point;
    database_t *db = &lsnd->session->kernel->db;
    uint32 file_id;
    reset_log_t *reset_log = &db->ctrl.core.resetlogs;
    bool32 loading_curr_file = CT_FALSE;

    if (!lsnd_read_log_precheck(lsnd, &target_point)) {
        return CT_SUCCESS;
    }

    if (lsnd_need_reconnect_cs(lsnd)) {
        return CT_ERROR;
    }

    // Read log data from log file to send_buf
    if (!log_try_lock_logfile(lsnd->session)) {
        return CT_SUCCESS;
    }
    file_id = log_get_id_by_asn(lsnd->session, (uint32)send_point->rst_id, send_point->asn, &loading_curr_file);
    log_unlock_logfile(lsnd->session);

    if (lsnd_read_log_should_suspend(lsnd->session, file_id, loading_curr_file)) {
        log_unlatch_file(lsnd->session, file_id);
        return CT_SUCCESS;
    }

    if (file_id == CT_INVALID_ID32) {
        if (lsnd->last_read_asn == send_point->asn && lsnd->last_read_file_id != -1) {
            // read the archive log file
            // NOTICE: Only the online file is archived after we start to read it CAN we read
            // the corresponding archived file so that the log file id(last_read_file_id) can be used.
            if (lsnd_read_arch_logfile(lsnd) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[Log Sender] failed to read archived log file with asn %u id %u ", send_point->asn,
                               lsnd->last_read_file_id);
                return CT_ERROR;
            }
        } else {
            log_file_t *file = lsnd->session->kernel->redo_ctx.files + lsnd->session->kernel->redo_ctx.active_file;
            // skip archive log file
            while (file_id == CT_INVALID_ID32 && send_point->asn < file->head.asn) {
                // If is archive log file, just move to next asn until it is an online log file.
                if (send_point->rst_id < reset_log->rst_id && send_point->asn == reset_log->last_asn) {
                    send_point->rst_id++;
                }
                send_point->asn++;
                send_point->block_id = 0;

                if (!log_try_lock_logfile(lsnd->session)) {
                    return CT_SUCCESS;
                }
                file_id = log_get_id_by_asn(lsnd->session, (uint32)send_point->rst_id,
                                            send_point->asn, &loading_curr_file);
                log_unlock_logfile(lsnd->session);
            }

            if (file_id != CT_INVALID_ID32 && lsnd_read_online_logfile(lsnd, file_id) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[Log Sender] failed to read online log file with id %u ", file_id);
                return CT_ERROR;
            }
        }
    } else {
        if (lsnd_read_online_logfile(lsnd, file_id) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[Log Sender] failed to read online log file with id %u ", file_id);
            return CT_ERROR;
        }
    }

    // If there is no more log in this file, just return and try to read next time.
    if (lsnd->send_buf.write_pos == 0) {
        if (file_id == CT_INVALID_ID32 || !loading_curr_file) {
            CT_LOG_DEBUG_INF("[Log Sender] send point [%u-%u/%u/%llu], target point [%u-%u/%u/%llu], "
                             "resetlog [%u-%u/%llu], asn will move next",
                             send_point->rst_id, send_point->asn, send_point->block_id, (uint64)send_point->lfn,
                             target_point.rst_id, target_point.asn, target_point.block_id, (uint64)target_point.lfn,
                             reset_log->rst_id, reset_log->last_asn, reset_log->last_lfn);

            if (send_point->rst_id < reset_log->rst_id && send_point->asn == reset_log->last_asn) {
                send_point->rst_id++;
            }
            send_point->asn++;
            send_point->block_id = 0;
        }
        return CT_SUCCESS;
    }

    return CT_SUCCESS;
}

static bool32 lsnd_need_send_batch(lsnd_t *lsnd, uint32 *read_pos, uint32 *write_pos)
{
    cm_spin_lock(&lsnd->lock, NULL);
    if (lsnd->send_buf.write_pos > lsnd->send_buf.read_pos) {
        *read_pos = lsnd->send_buf.read_pos;
        *write_pos = lsnd->send_buf.write_pos;
        cm_spin_unlock(&lsnd->lock);
        return CT_TRUE;
    }

    cm_spin_unlock(&lsnd->lock);
    return CT_FALSE;
}

static inline status_t lsnd_zstd_compress(lsnd_t *lsnd, const char *buf, uint32 data_size)
{
    lsnd->c_ctx.data_size = (uint32)ZSTD_compressCCtx(lsnd->c_ctx.zstd_cctx, lsnd->c_ctx.compress_buf.aligned_buf,
        lsnd->c_ctx.buf_size, buf, data_size, 1);
    if (ZSTD_isError(lsnd->c_ctx.data_size)) {
        CT_LOG_RUN_ERR("[Log Sender] failed to compress(zstd) log batch message");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static inline status_t lsnd_lz4_compress(lsnd_t *lsnd, const char *buf, uint32 data_size)
{
    lsnd->c_ctx.data_size = (uint32)LZ4_compress_default(buf, lsnd->c_ctx.compress_buf.aligned_buf, (int32)data_size,
        (int32)lsnd->c_ctx.buf_size);
    if (lsnd->c_ctx.data_size == 0) {
        CT_LOG_RUN_ERR("[Log Sender] failed to compress(lz4) log batch message");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}


static status_t lsnd_compress_send_log(lsnd_t *lsnd, bool32 is_sync)
{
    char *buf = lsnd->send_buf.read_buf.aligned_buf;
    rep_msg_header_t *rep_msg_header = NULL;
    char *batches = NULL;

    if (is_sync) {
        rep_msg_header = (rep_msg_header_t *)(buf + lsnd->send_buf.read_pos);
        batches = buf + lsnd->send_buf.read_pos + sizeof(rep_msg_header_t) + sizeof(rep_batch_req_t);
    } else {
        rep_msg_header = (rep_msg_header_t *)lsnd->extra_head;
        batches = buf;
    }

    switch (lsnd->dest_info.compress_alg) {
        case COMPRESS_ZSTD:
            if (lsnd_zstd_compress(lsnd, batches, rep_msg_header->size - lsnd->header_size) != CT_SUCCESS) {
                return CT_ERROR;
            }
            break;
        case COMPRESS_LZ4:
            if (lsnd_lz4_compress(lsnd, batches, rep_msg_header->size - lsnd->header_size) != CT_SUCCESS) {
                return CT_ERROR;
            }
            break;
        default:
            break;
    }

    // modify the value of rep_msg_header->size to the sum of lsnd->header_size and the compressed data size
    rep_msg_header->size = lsnd->header_size + lsnd->c_ctx.data_size;
    if (cs_write_stream(&lsnd->pipe, (char *)rep_msg_header, lsnd->header_size,
                        (int32)cm_atomic_get(&lsnd->session->kernel->attr.repl_pkg_size)) == CT_SUCCESS) {
        if (cs_write_stream(&lsnd->pipe, lsnd->c_ctx.compress_buf.aligned_buf, lsnd->c_ctx.data_size,
                            (int32)cm_atomic_get(&lsnd->session->kernel->attr.repl_pkg_size)) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[Log Sender] failed to send log batch message to standby sync");
            return CT_ERROR;
        }
    } else {
        CT_LOG_RUN_ERR("[Log Sender] failed to send log batch header message to standby");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/* merge multiple batch together for lsnd send performance, return last batch's offset */
static inline uint32 lsnd_merge_multiple_batches(char *buf, uint32 read_pos, uint32 write_pos)
{
    rep_msg_header_t *rep_msg_header = NULL;
    uint32 offset = 0;

    while (write_pos > (offset + read_pos)) {
        rep_msg_header = (rep_msg_header_t *)(buf + offset + read_pos);
        offset += rep_msg_header->size;
    }
    knl_panic(write_pos == (offset + read_pos));
    return (offset - rep_msg_header->size);
}

static inline bool32 lsnd_read_pos_updated(lsnd_t *lsnd, uint32 read_pos)
{
    cm_spin_lock(&lsnd->lock, NULL);
    if (lsnd->tmp_async) {
        cm_spin_unlock(&lsnd->lock);
        return CT_FALSE;
    }

    lsnd->send_buf.read_pos = read_pos;
    cm_spin_unlock(&lsnd->lock);
    return CT_TRUE;
}

/*
 * +----------------------+----------------------+----------------------+-------------------+
 * |        batch1        |        batch2        |        batch3        |        ...        |
 * +----------------------+----------------------+----------------------+-------------------+
 * 0                   offset1                offset2                offset3             offsetn
 *
 * In synchronous mode, the offset in send point is updated to 'offset2' after batch3 is sent,
 * if it is changed to temporary asynchronous mode, primary will read batches from 'offset2',
 * this leads to the batch3 is sent repeatly, and redo free size on standby would be subtracted
 * repeatly too.
 *
 * So we should update send point to 'offset3' before reading batches from online logfile.
 */
static inline void lsnd_update_send_point(lsnd_t *lsnd, log_batch_t *batch, uint32 file_id)
{
    log_context_t *ctx = &lsnd->session->kernel->redo_ctx;
    log_file_t *file = &ctx->files[file_id];

    lsnd->send_point.block_id += (uint32)(batch->space_size / file->ctrl->block_size);
}

static status_t lsnd_send_log_sync(lsnd_t *lsnd, bool32 *sent)
{
    rep_msg_header_t *rep_msg_header = NULL;
    rep_batch_req_t *rep_batch_req = NULL;
    char *buf = lsnd->send_buf.read_buf.aligned_buf;
    log_batch_t *batch = NULL;
    log_batch_tail_t *tail = NULL;
    uint32 ori_size;
    uint32 offset;
    uint32 read_pos, write_pos;

    *sent = CT_FALSE;

    while (lsnd_need_send_batch(lsnd, &read_pos, &write_pos)) {
        offset = 0;
        if (lsnd->dest_info.compress_alg == COMPRESS_NONE) {
            offset = lsnd_merge_multiple_batches(buf, read_pos, write_pos);
        }
        rep_msg_header = (rep_msg_header_t *)(buf + offset + read_pos);
        rep_batch_req = (rep_batch_req_t *)(buf + offset + read_pos + sizeof(rep_msg_header_t));

        batch = (log_batch_t *)(buf + offset + read_pos + sizeof(rep_msg_header_t) + sizeof(rep_batch_req_t));
        tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));
        CT_LOG_DEBUG_INF("[Log Sender] Ready to Send batch SYNC from read pos %u write pos %u with size %u "
                         "on log file[%d] at log point [%u-%u/%u/%llu] size %u head [%llu/%llu/%llu] tail [%llu/%llu]",
                         read_pos, lsnd->send_buf.write_pos, rep_msg_header->size,
                         rep_batch_req->log_file_id, rep_batch_req->log_point.rst_id, rep_batch_req->log_point.asn,
                         rep_batch_req->log_point.block_id, (uint64)rep_batch_req->log_point.lfn,
                         batch->size, batch->head.magic_num, (uint64)batch->head.point.lfn, batch->raft_index,
                         tail->magic_num, (uint64)tail->point.lfn);

        if (lsnd->dest_info.compress_alg == COMPRESS_NONE) {
            ori_size = write_pos - read_pos;
            if (cs_write_stream(&lsnd->pipe, buf + read_pos, ori_size,
                                (int32)cm_atomic_get(&lsnd->session->kernel->attr.repl_pkg_size)) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[Log Sender] failed to send log batch message to standby sync");
                return CT_ERROR;
            }
        } else {
            ori_size = rep_msg_header->size;
            if (lsnd_compress_send_log(lsnd, CT_TRUE) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }

        *sent = CT_TRUE;
        lsnd->last_send_time = cm_current_time();
        CT_LOG_DEBUG_INF("[Log Sender] Send batch SYNC from read pos %u with size %u on log file[%d] "
                         "at log point [%u-%u/%u/%llu]",
                         read_pos, rep_msg_header->size, rep_batch_req->log_file_id,
                         rep_batch_req->log_point.rst_id, rep_batch_req->log_point.asn,
                         rep_batch_req->log_point.block_id, (uint64)rep_batch_req->log_point.lfn);

        // Update send point
        lsnd->send_point = rep_batch_req->log_point;
        read_pos += ori_size;
        if (!lsnd_read_pos_updated(lsnd, read_pos)) {
            lsnd_update_send_point(lsnd, batch, rep_batch_req->log_file_id);
        }

        if (lsnd_process_message_once(lsnd) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[Log Sender] failed to process message in send batch sync");
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t lsnd_send_log_async(lsnd_t *lsnd, bool32 *sent)
{
    rep_msg_header_t *rep_msg_header = NULL;
    uint32 ori_size;

    *sent = CT_FALSE;
    if (lsnd->send_buf.write_pos > lsnd->send_buf.read_pos && lsnd->in_async) {
        rep_msg_header = (rep_msg_header_t *)lsnd->extra_head;
        ori_size = rep_msg_header->size;
        if (lsnd->dest_info.compress_alg == COMPRESS_NONE) {
            if (cs_write_stream(&lsnd->pipe, lsnd->extra_head, lsnd->header_size,
                                (int32)cm_atomic_get(&lsnd->session->kernel->attr.repl_pkg_size)) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[Log Sender] failed to send log batch header message to standby");
                return CT_ERROR;
            }
            if (cs_write_stream(&lsnd->pipe, lsnd->send_buf.read_buf.aligned_buf,
                                rep_msg_header->size - lsnd->header_size,
                                (int32)cm_atomic_get(&lsnd->session->kernel->attr.repl_pkg_size)) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[Log Sender] failed to send log batch message to standby async");
                return CT_ERROR;
            }
        } else {
            if (lsnd_compress_send_log(lsnd, CT_FALSE) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }

        lsnd->last_send_time = cm_current_time();
        lsnd->send_buf.read_pos += ori_size - lsnd->header_size;
        lsnd->send_buf.write_pos = 0;
        lsnd->send_buf.read_pos = 0;
        cm_spin_lock(&lsnd->lock, NULL);
        lsnd->in_async = CT_FALSE;
        cm_spin_unlock(&lsnd->lock);
        *sent = CT_TRUE;

        // Update send point
        lsnd->send_point.asn = lsnd->last_put_point.asn;
        lsnd->send_point.lfn = lsnd->last_put_point.lfn;
        lsnd->send_point.block_id = lsnd->last_put_point.block_id;
        CT_LOG_DEBUG_INF("[Log Sender] Send batch ASYNC from read pos %u with size %u at log point [%u-%u/%u/%llu]",
                         lsnd->send_buf.read_pos, rep_msg_header->size,
                         lsnd->send_point.rst_id, lsnd->send_point.asn,
                         lsnd->send_point.block_id, (uint64)lsnd->send_point.lfn);
    }

    return CT_SUCCESS;
}

static status_t lsnd_send_log(lsnd_t *lsnd, bool32 *sent)
{
    /*
     * The primary does not send logs to the standby temporarily,
     * when the standby is waiting for log switch.
     */
    if (SECUREC_UNLIKELY(lsnd->wait_point.asn != CT_INVALID_ASN)) {
        return CT_SUCCESS;
    }

    if (lsnd->dest_info.sync_mode == LOG_NET_TRANS_MODE_ASYNC ||
        lsnd->tmp_async ||
        DB_IS_PHYSICAL_STANDBY(&lsnd->session->kernel->db)) {
        return lsnd_send_log_async(lsnd, sent);
    } else {
        return lsnd_send_log_sync(lsnd, sent);
    }
}

static status_t lsnd_connect(lsnd_t *lsnd, uint32 *cs_fail_cnt)
{
    int32 login_err = 0;
    char url[CT_HOST_NAME_BUFFER_SIZE + CT_TCP_PORT_MAX_LENGTH];
    errno_t print_num;
    dest_info_t *info = &lsnd->dest_info;

    print_num = snprintf_s(url, sizeof(url), sizeof(url) - 1, "%s:%u", info->peer_host, info->peer_port);
    if (print_num == -1 || print_num >= (int32)sizeof(url)) {
        CT_LOG_RUN_ERR("[Log Sender] Url %s is truncated", url);
        return CT_ERROR;
    }

    lsnd->pipe.options = 0;
    lsnd->pipe.connect_timeout = REPL_CONNECT_TIMEOUT;
    lsnd->pipe.socket_timeout = REPL_SOCKET_TIMEOUT;
    if (cs_connect((const char *)url, &lsnd->pipe, info->local_host, NULL, NULL) != CT_SUCCESS) {
        CT_LOG_DEBUG_ERR("[Log Sender] failed to connect %s", url);
        return CT_ERROR;
    }
    CT_LOG_DEBUG_INF("[Log Sender] connected to %s, local host : %s", url, info->local_host);

    if (knl_login(lsnd->session, &lsnd->pipe, REP_LOGIN_REPL,
        (const char *)info->local_host, &login_err) != CT_SUCCESS) {
        if (DB_IS_PRIMARY(&lsnd->session->kernel->db) && login_err == ERR_CASCADED_STANDBY_CONNECTED) {
            if ((*cs_fail_cnt)++ >= LOGIN_CS_RETRY_COUNT) {
                lsnd->is_deferred = CT_TRUE;
                arch_set_deststate_disabled(lsnd->session, info->attr_idx);
                CT_LOG_RUN_INF("lsnd[%lu] login failed, local is primary, peer is cascaded physical standby, "
                               "should disconnect with it", LSND_TID(lsnd));
                return CT_ERROR;
            }
        }

        CT_LOG_DEBUG_ERR("lsnd[%lu] login failed, errcode %d", LSND_TID(lsnd), login_err);
        return CT_ERROR;
    }

    *cs_fail_cnt = 0;
    lsnd->status = LSND_STATUS_QUERYING;
    lsnd->last_recv_time = cm_current_time();
    cm_reset_error();
    CT_LOG_RUN_INF("[Log Sender] Standby[%s] connected", url);

    return CT_SUCCESS;
}

static status_t lsnd_wait_query_resp(lsnd_t *lsnd)
{
    uint32 type;
    int32 recv_size;

    while (!lsnd->thread.closed) {
        if (lsnd_receive(lsnd, lsnd->timeout, &type, &recv_size) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (recv_size == 0) {
            continue;
        }

        if (lsnd_process_message(lsnd, type) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (type == REP_QUERY_STATUS_RESP) {
            lsnd->notify_repair = CT_FALSE;
            break;
        }
    }

    return CT_SUCCESS;
}

static status_t lsnd_query_standby_status(lsnd_t *lsnd)
{
    log_context_t *log_ctx = &lsnd->session->kernel->redo_ctx;
    char *buf = lsnd->send_buf.read_buf.aligned_buf;
    log_file_t *logfile = NULL;

    lsnd->send_buf.read_pos = 0;
    lsnd->send_buf.write_pos = 0;

    rep_msg_header_t *msg_hdr = (rep_msg_header_t *)buf;
    msg_hdr->size = sizeof(rep_msg_header_t) + sizeof(rep_query_status_req_t);
    msg_hdr->type = REP_QUERY_STATUS_REQ;

    rep_query_status_req_t *req = (rep_query_status_req_t *)(buf + sizeof(rep_msg_header_t));
    req->rst_log = lsnd->session->kernel->db.ctrl.core.resetlogs;
    req->curr_point.lfn = log_ctx->curr_point.lfn;
    req->curr_point.asn = log_ctx->files[log_ctx->curr_file].head.asn;
    req->curr_point.rst_id = log_ctx->files[log_ctx->curr_file].head.rst_id;
    req->curr_point.block_id = (uint32)(log_ctx->files[log_ctx->curr_file].head.write_pos /
                                        log_ctx->files[log_ctx->curr_file].ctrl->block_size);
    req->is_standby = DB_IS_PHYSICAL_STANDBY(&lsnd->session->kernel->db);
    req->repl_port = lsnd->session->kernel->attr.repl_port;
    req->version = ST_VERSION_1;
    req->dbid = lsnd->session->kernel->db.ctrl.core.dbid;
    req->notify_repair = lsnd->notify_repair;
    req->reserved_field = 0;
    req->reset_log_scn = lsnd->session->kernel->db.ctrl.core.reset_log_scn;
    errno_t err = memset_s(req->reserved, sizeof(req->reserved), 0, sizeof(req->reserved));
    knl_securec_check(err);

    req->log_num = log_ctx->logfile_hwm;
    uint32 offset = sizeof(rep_msg_header_t) + sizeof(rep_query_status_req_t);
    for (uint32 i = 0; i < log_ctx->logfile_hwm; i++) {
        logfile = &log_ctx->files[i];
        err = memcpy_sp(buf + offset, (uint32)lsnd->send_buf.read_buf.buf_size - offset, (char *)logfile->ctrl,
                        sizeof(log_file_ctrl_t));
        knl_securec_check(err);
        offset += sizeof(log_file_ctrl_t);
    }

    msg_hdr->size = offset;
    CT_LOG_DEBUG_INF("[Log Sender] Query standby status with current log point [%u-%u/%u], port : %u",
                     req->curr_point.rst_id, req->curr_point.asn, req->curr_point.block_id, req->repl_port);

    if (cs_write_stream(&lsnd->pipe, buf, msg_hdr->size,
                        (int32)cm_atomic_get(&lsnd->session->kernel->attr.repl_pkg_size)) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[Log Sender] failed to send query status message to standby");
        return CT_ERROR;
    }

    return lsnd_wait_query_resp(lsnd);
}

static status_t lsnd_send_heart_beat(lsnd_t *lsnd)
{
    rep_msg_header_t rep_msg_header;
    time_t now = cm_current_time();
    /*
     * If the system time is adjusted forward, then current time will be smaller than the last sending time,
     * and the difference will be negative for 'time_t' is signed long type. In order to prevent the primary
     * disconnected with the standby, make sure current time is greater than or equal to last sending time.
     */
    if (now >= lsnd->last_send_time && (now - lsnd->last_send_time) < REPL_HEART_BEAT_CHECK) {
        return CT_SUCCESS;
    }

    rep_msg_header.size = sizeof(rep_msg_header_t);
    rep_msg_header.type = REP_HEART_BEAT_REQ;
    lsnd->last_send_time = now;

    status_t status = cs_write_stream(&lsnd->pipe, (char *)&rep_msg_header, rep_msg_header.size,
        (int32)cm_atomic_get(&lsnd->session->kernel->attr.repl_pkg_size));
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[Log Sender] failed to send heart beat message to standby");
    }
    return status;
}

static void lsnd_reset_bak_task(lsnd_t *ctx)
{
    lsnd_bak_task_t *bak_task = &ctx->bak_task;

    cm_spin_lock(&bak_task->lock, NULL);
    if (bak_task->task.status != BAK_TASK_DONE) {
        bak_task->task.status = BAK_TASK_DONE;
    }
    cm_spin_unlock(&bak_task->lock);
}

static void lsnd_set_conn_error(lsnd_t *ctx)
{
    knl_session_t *session = ctx->session;
    lsnd_context_t *lsnd_ctx = &session->kernel->lsnd_ctx;

    knl_disconnect(&(ctx)->pipe);
    lsnd_reset_bak_task(ctx);
    errno_t err = memset_sp(&ctx->wait_point, sizeof(log_point_t), 0, sizeof(log_point_t));
    knl_securec_check(err);
    CT_LOG_RUN_INF("[Log Sender] Standby [%s:%u] disconnected", ctx->dest_info.peer_host, ctx->dest_info.peer_port);
    if (lsnd_ctx->est_standby_num > 0 && ctx->status >= LSND_LOG_SHIFTING) {
        lsnd_ctx->est_standby_num--;
        if (ctx->dest_info.sync_mode == LOG_NET_TRANS_MODE_SYNC && !ctx->tmp_async) {
            knl_panic(lsnd_ctx->est_sync_standby_num > 0);
            lsnd_ctx->est_sync_standby_num--;

            if (ctx->dest_info.affirm_mode == LOG_ARCH_AFFIRM) {
                CM_ASSERT(lsnd_ctx->est_affirm_standy_num > 0);
                lsnd_ctx->est_affirm_standy_num--;
            }
        }
    }

    ctx->status = LSND_DISCONNECTED;
    ctx->tmp_async = CT_TRUE;
    ctx->peer_is_building = CT_FALSE;

    ctx->last_read_file_id = -1;
    ctx->last_read_asn = CT_INVALID_ASN;
    ctx->arch_file.asn = CT_INVALID_ASN;
    cm_close_device(cm_device_type(ctx->arch_file.file_name), &ctx->arch_file.handle);

    if (ctx->state != REP_STATE_NORMAL) {
        ctx->state = REP_STATE_DEMOTE_FAILED;
    }

    cm_sleep(1000);
}

static bool32 lsnd_need_terminate(lsnd_t *lsnd)
{
    if (lsnd->is_deferred) {
        return CT_TRUE;
    }

    if (lsnd_connecting_primary(lsnd->session, lsnd->dest_info.peer_host, lsnd->dest_info.peer_port)) {
        return CT_TRUE;
    }

    return CT_FALSE;
}

void lsnd_proc(thread_t *thread)
{
    lsnd_t *lsnd = (lsnd_t *)thread->argument;
    knl_instance_t *knl = lsnd->session->kernel;
    bool32 sent = CT_FALSE;
    uint32 cs_fail_cnt = 0;

    cm_set_thread_name("log_sender");
    CT_LOG_RUN_INF("[Log Sender] Thread started");

    for (;;) {
        if (lsnd->thread.closed && lsnd->state != REP_STATE_PROMOTE_APPROVE) {
            CT_LOG_RUN_INF("[Log Sender] Thread closed");
            break;
        }

        if (lsnd->resetid_changed_reconnect && knl->redo_ctx.curr_point.lfn >= knl->db.ctrl.core.resetlogs.last_lfn) {
            lsnd_set_conn_error(lsnd);
            lsnd->resetid_changed_reconnect = CT_FALSE;
            CT_LOG_RUN_INF("[Log Sender] Reconnect to cascaded standby, for peer(primary) has failover");
        }

        switch (lsnd->status) {
            // Try to connect standby
            case LSND_DISCONNECTED: {
                if (lsnd_need_terminate(lsnd) || lsnd_connect(lsnd, &cs_fail_cnt) != CT_SUCCESS) {
                    cm_sleep(1000);
                    continue;
                }
                break;
            }
            // Query standby status
            case LSND_STATUS_QUERYING: {
                cm_reset_error();
                if (lsnd_query_standby_status(lsnd) != CT_SUCCESS) {
                    lsnd_set_conn_error(lsnd);
                    continue;
                }

                if (lsnd->status == LSND_STATUS_QUERYING) {
                    cm_sleep(1000);
                    continue;
                }
                break;
            }
            // Once connected with standby, loop reading and sending messages
            default: {
                // Process message if got any.
                if (lsnd_process_message_if_any(lsnd) != CT_SUCCESS) {
                    lsnd_set_conn_error(lsnd);
                    continue;
                }

                lsnd_process_abr_task(lsnd);
                if (lsnd_process_record_backup_response(lsnd) != CT_SUCCESS) {
                    lsnd_set_conn_error(lsnd);
                    continue;
                }

                if (lsnd->state == REP_STATE_PROMOTE_APPROVE) {
                    if (lsnd_send_switch_response(lsnd) != CT_SUCCESS) {
                        lsnd_set_conn_error(lsnd);
                        continue;
                    }
                }

                // Read log from log file if async.
                if (lsnd_read_log(lsnd) != CT_SUCCESS) {
                    lsnd_set_conn_error(lsnd);
                    continue;
                }

                // Send log to standby
                if (lsnd_send_log(lsnd, &sent) != CT_SUCCESS) {
                    lsnd_set_conn_error(lsnd);
                    continue;
                }

                // Heart beat check
                if (lsnd_send_heart_beat(lsnd) != CT_SUCCESS) {
                    lsnd_set_conn_error(lsnd);
                    continue;
                }

                // If log sender is not waiting for a response
                if (!sent && ((uint64)knl->lfn == lsnd->peer_flush_point.lfn ||
                              knl->redo_ctx.curr_point.lfn == lsnd->peer_flush_point.lfn)) {
                    (void)cm_wait_cond(&lsnd->cond, knl->attr.lsnd_wait_time);
                }
            }
        }
    }

    knl_disconnect(&lsnd->pipe);
    lsnd_reset_bak_task(lsnd);

    CT_LOG_RUN_INF("[Log Sender] Thread closed");
}

static status_t lsnd_init_log_files(knl_session_t *session, lsnd_t *lsnd)
{
    log_file_t *logfile = NULL;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);

    for (uint32 i = 0; i < CT_MAX_LOG_FILES; i++) {
        lsnd->log_handle[i] = INVALID_FILE_HANDLE;
    }

    for (uint32 i = 0; i < logfile_set->logfile_hwm; i++) {
        logfile = &logfile_set->items[i];
        if (LOG_IS_DROPPED(logfile->ctrl->flg)) {
            continue;
        }

        /* closed in lsnd_close_specified_logfile */
        if (cm_open_device(logfile->ctrl->name, logfile->ctrl->type, knl_redo_io_flag(session),
                           &lsnd->log_handle[i]) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[Log Sender] failed to open %s when initializing log file handles for standby %s",
                           logfile->ctrl->name, lsnd->dest_info.peer_host);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t lsnd_init_proc_context(knl_session_t *session, uint32 idx, arch_attr_t *arch_attr, lsnd_t **lsnd)
{
    size_t host_len;
    uint32 log_size = (uint32)LOG_LGWR_BUF_SIZE(session);  /* LOG_LGWR_BUF_SIZE(session) <= 64M, cannot oveflow */

    if ((*lsnd) == NULL) {
        /* reserve lsnd until cantiand instance exit */
        (*lsnd) = (lsnd_t *)malloc(sizeof(lsnd_t));
        if ((*lsnd) == NULL) {
            CT_LOG_RUN_ERR("[Log Sender] failed to allocate %llu bytes for %s",
                (uint64)sizeof(lsnd_t), "lsnd_proc context");
            return CT_ERROR;
        }
    }

    errno_t err = memset_sp((*lsnd), sizeof(lsnd_t), 0, sizeof(lsnd_t));
    knl_securec_check(err);
    (*lsnd)->is_disable = CT_TRUE;

    uint32 buf_size = log_size + SIZE_K(4);
    (*lsnd)->send_buf.illusion_count = 0;
    (*lsnd)->send_buf.read_pos = 0;
    (*lsnd)->send_buf.write_pos = 0;

    if (cm_aligned_malloc((int64)buf_size, "lsnd batch buffer", &(*lsnd)->send_buf.read_buf) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[Log Sender] failed to alloc send buffer with size %u", buf_size);
        return CT_ERROR;
    }

    if (arch_attr->compress_alg != COMPRESS_NONE) {
        if (arch_attr->compress_alg == COMPRESS_ZSTD) {
            (*lsnd)->c_ctx.zstd_cctx = ZSTD_createCCtx();
            (*lsnd)->c_ctx.buf_size = (uint32)ZSTD_compressBound(log_size) + SIZE_K(4);
        } else if (arch_attr->compress_alg == COMPRESS_LZ4) {
            (*lsnd)->c_ctx.buf_size = (uint32)LZ4_compressBound((int32)log_size) + SIZE_K(4);
        }
        (*lsnd)->c_ctx.data_size = 0;

        if (cm_aligned_malloc((int64)(*lsnd)->c_ctx.buf_size, "lsnd compress buffer",
            &(*lsnd)->c_ctx.compress_buf) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[Log Sender] failed to alloc compress buffer with size %u", (*lsnd)->c_ctx.buf_size);
            cm_aligned_free(&(*lsnd)->send_buf.read_buf);
            return CT_ERROR;
        }
    }

    buf_size = SIZE_K(64);
    (*lsnd)->recv_buf.illusion_count = 0;
    (*lsnd)->recv_buf.read_pos = 0;
    (*lsnd)->recv_buf.write_pos = 0;

    if (cm_aligned_malloc((int64)buf_size, "lsnd batch buffer", &(*lsnd)->recv_buf.read_buf) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[Log Sender] failed to alloc recv buffer with size %u", buf_size);
        cm_aligned_free(&(*lsnd)->send_buf.read_buf);
        cm_aligned_free(&(*lsnd)->c_ctx.compress_buf);
        return CT_ERROR;
    }

    (*lsnd)->header_size = sizeof(rep_msg_header_t) + sizeof(rep_batch_req_t);
    (*lsnd)->extra_head = (char *)malloc((*lsnd)->header_size);
    if ((*lsnd)->extra_head == NULL) {
        CT_LOG_RUN_ERR("[Log Sender] failed to malloc lsnd extra_head with size %u", (*lsnd)->header_size);
        cm_aligned_free(&(*lsnd)->send_buf.read_buf);
        cm_aligned_free(&(*lsnd)->recv_buf.read_buf);
        cm_aligned_free(&(*lsnd)->c_ctx.compress_buf);
        return CT_ERROR;
    }

    (*lsnd)->dest_info.attr_idx = idx;
    host_len = strlen(arch_attr->service.host);
    err = strncpy_s((*lsnd)->dest_info.peer_host, CT_HOST_NAME_BUFFER_SIZE, arch_attr->service.host, host_len);
    knl_securec_check(err);
    host_len = strlen(arch_attr->local_host);
    err = strncpy_s((*lsnd)->dest_info.local_host, CT_HOST_NAME_BUFFER_SIZE, arch_attr->local_host, host_len);
    knl_securec_check(err);
    (*lsnd)->session = session;
    (*lsnd)->dest_info.peer_port = arch_attr->service.port;
    (*lsnd)->dest_info.sync_mode = arch_attr->net_mode;
    (*lsnd)->dest_info.affirm_mode = arch_attr->affirm_mode;
    (*lsnd)->dest_info.compress_alg = arch_attr->compress_alg;
    (*lsnd)->tmp_async = CT_TRUE;
    (*lsnd)->last_read_file_id = -1;
    (*lsnd)->last_read_asn = CT_INVALID_ASN;
    (*lsnd)->timeout = session->kernel->attr.repl_wait_timeout;
    (*lsnd)->in_async = CT_FALSE;
    (*lsnd)->arch_file.handle = CT_INVALID_HANDLE;

    (*lsnd)->abr_task.lsnd_id = (uint16)idx; /* MAX(inx) == 9, will not overflow */
    (*lsnd)->abr_task.running = CT_FALSE;
    (*lsnd)->abr_task.executing = CT_FALSE;
    (*lsnd)->abr_task.succeeded = CT_FALSE;
    (*lsnd)->is_disable = CT_FALSE;

    return CT_SUCCESS;
}

static inline bool32 lsnd_is_running(lsnd_context_t *ctx, arch_attr_t *arch_attr)
{
    uint32 i;
    lsnd_t *lsnd = NULL;

    for (i = 0; i < CT_MAX_PHYSICAL_STANDBY; i++) {
        lsnd = ctx->lsnd[i];
        if (lsnd == NULL || lsnd->is_disable) {
            continue;
        }

        if (strcmp(lsnd->dest_info.peer_host, arch_attr->service.host) == 0 &&
            lsnd->dest_info.peer_port == arch_attr->service.port) {
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

static inline uint32 lsnd_get_free_slot(lsnd_context_t *ctx)
{
    for (uint32 i = 0; i < CT_MAX_PHYSICAL_STANDBY; i++) {
        if (ctx->lsnd[i] == NULL || ctx->lsnd[i]->is_disable) {
            return i;
        }
    }

    return CT_MAX_PHYSICAL_STANDBY;
}

static inline uint16 lsnd_get_sync_count(lsnd_context_t *ctx)
{
    lsnd_t *lsnd = NULL;
    uint16 sync_cnt = 0;

    for (uint16 i = 0; i < ctx->standby_num; i++) {
        lsnd = ctx->lsnd[i];
        if (lsnd == NULL || lsnd->is_disable) {
            continue;
        }

        if (lsnd->dest_info.sync_mode == LOG_NET_TRANS_MODE_SYNC) {
            sync_cnt++;
        }
    }

    return sync_cnt;
}

static bool32 lsnd_start_precheck(knl_session_t *session, arch_attr_t *arch_attr)
{
    lsnd_context_t *ctx = &session->kernel->lsnd_ctx;
    database_t *db = &session->kernel->db;

    if (arch_attr->dest_mode != LOG_ARCH_DEST_SERVICE || !arch_attr->enable) {
        return CT_FALSE;
    }

    if ((DB_IS_PRIMARY(db) && arch_attr->role_valid == VALID_FOR_STANDBY_ROLE) ||
        (DB_IS_PHYSICAL_STANDBY(db) && arch_attr->role_valid == VALID_FOR_PRIMARY_ROLE) ||
        DB_IS_CASCADED_PHYSICAL_STANDBY(db)) {
        return CT_FALSE;
    }

    if (lsnd_connecting_primary(session, arch_attr->service.host, arch_attr->service.port)) {
        return CT_FALSE;
    }

    if (lsnd_is_running(ctx, arch_attr)) {
        return CT_FALSE;
    }

    return CT_TRUE;
}

static status_t lsnd_init_each_proc(knl_session_t *session, uint32 idx)
{
    lsnd_t *lsnd = NULL;
    arch_attr_t *arch_attr = NULL;
    knl_attr_t *attr = &session->kernel->attr;
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    lsnd_context_t *ctx = &session->kernel->lsnd_ctx;
    uint32 free_slot;

    arch_attr = &attr->arch_attr[idx + 1];
    if (!lsnd_start_precheck(session, arch_attr)) {
        return CT_SUCCESS;
    }

    free_slot = lsnd_get_free_slot(ctx);
    if (free_slot >= CT_MAX_PHYSICAL_STANDBY) {
        CT_LOG_RUN_ERR("standby number larger than %u", CT_MAX_PHYSICAL_STANDBY);
        return CT_ERROR;
    }

    lsnd = ctx->lsnd[free_slot];

    // 1. Init proc context
    if (lsnd_init_proc_context(session, idx + 1, arch_attr, &lsnd) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // 2. Open log file
    if (lsnd_init_log_files(session, lsnd) != CT_SUCCESS) {
        lsnd_free_single_proc_context(lsnd);
        return CT_ERROR;
    }

    // 3. Start log sender thread
    if (cm_create_thread(lsnd_proc, 0, lsnd, &lsnd->thread) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[Log Sender] failed to start log sender thread for standby %s", lsnd->dest_info.peer_host);
        lsnd_free_single_proc_context(lsnd);
        return CT_ERROR;
    }

    cm_init_cond(&lsnd->cond);

    lsnd->id = free_slot;
    ctx->lsnd[free_slot] = lsnd;
    if (free_slot >= ctx->standby_num) {
        ctx->standby_num++;
    }

    if (LSND_SYNC_AFFIRM(lsnd)) {
        ctx->affirm_standy_num++;
    }

    if (arch_ctx->arch_dest_state_changed) {
        CT_LOG_RUN_INF("[Log Sender] start new lsnd thread in free slot %u for archive dest state enabled",
                       free_slot);
    }

    return CT_SUCCESS;
}

status_t lsnd_init(knl_session_t *session)
{
    knl_session_t *lsnd_session = session->kernel->sessions[SESSION_ID_LSND];
    knl_attr_t *attr = &session->kernel->attr;
    lsnd_context_t *ctx = &lsnd_session->kernel->lsnd_ctx;

    if (DB_IS_RAFT_ENABLED(session->kernel)) {
        CT_LOG_RUN_WAR("RAFT: skip init log sender thread when raft is enabled.");
        return CT_SUCCESS;
    }

    // For physical standby, waits for primary's connection in switchover
    if (DB_IS_PHYSICAL_STANDBY(&session->kernel->db) && session->kernel->switch_ctrl.request == SWITCH_REQ_DEMOTE) {
        uint32 begin_time = attr->timer->systime;
        uint32 timeout = attr->repl_wait_timeout * REPL_WAIT_MULTI;

        while (session->kernel->lrcv_ctx.session == NULL) {
            if (attr->timer->systime - begin_time >= timeout) {
                CT_LOG_RUN_WAR("primary has not connected here in %us, promote failed probably", timeout);
                break;
            }
            cm_sleep(100);
        }
    }

    cm_latch_x(&ctx->latch, session->id, NULL);

    for (uint32 i = 0; i < CT_MAX_PHYSICAL_STANDBY; i++) {
        if (lsnd_init_each_proc(lsnd_session, i) != CT_SUCCESS) {
            cm_unlatch(&ctx->latch, NULL);
            lsnd_close_all_thread(session);
            return CT_ERROR;
        }
    }

    cm_init_eventfd(&ctx->eventfd);

    ctx->quorum_any = attr->quorum_any;
    cm_unlatch(&ctx->latch, NULL);

    if (DB_IS_PRIMARY(&session->kernel->db) && MODE_MAX_PROTECTION(&session->kernel->db)) {
        if (ctx->quorum_any == 0 && lsnd_get_sync_count(ctx) == 0) {
            CT_LOG_RUN_ERR("[Log Sender] at least one standby should be set sync when "
                           "primary runs in max protection mode");
            lsnd_close_all_thread(session);
            return CT_ERROR;
        }

        if (ctx->quorum_any > ctx->standby_num) {
            CT_LOG_RUN_ERR("[Log Sender] Quorum Any requires at least %u standbys, but only %u configured",
                           ctx->quorum_any, ctx->standby_num);
            lsnd_close_all_thread(session);
            return CT_ERROR;
        }
    }

    if (ctx->standby_num > 0 && !session->kernel->arch_ctx.is_archive) {
        CT_THROW_ERROR(ERR_DATABASE_NOT_ARCHIVE, "primary database must run in archive mode when it has standby");
        lsnd_close_all_thread(session);
        return CT_ERROR;
    }

    if (ctx->standby_num > 0 && session->kernel->attr.enable_arch_compress) {
        CT_THROW_ERROR(ERR_DATABASE_NOT_ARCHIVE,
            "primary database can not config ENABLE_ARCH_COMPRESS to TRUE when it has standby");
        lsnd_close_all_thread(session);
        return CT_ERROR;
    }

    if (ctx->standby_num == 0) {
        CT_LOG_RUN_INF("no valid standby configuration");
    }

    return CT_SUCCESS;
}

void lsnd_try_clear_tmp_async(lsnd_t *lsnd, log_point_t *point)
{
    lsnd_context_t *ctx = &lsnd->session->kernel->lsnd_ctx;

    if (!lsnd->tmp_async) {
        return;
    }

    cm_spin_lock(&lsnd->lock, NULL);

    if (!lsnd->tmp_async || lsnd->in_async) {
        cm_spin_unlock(&lsnd->lock);
        return;
    }

    if (point->lfn != lsnd->peer_flush_point.lfn && point->lfn != lsnd->peer_flush_point.lfn + 1 &&
        log_cmp_point(point, &lsnd->peer_flush_point) != 0) {
        cm_spin_unlock(&lsnd->lock);
        return;
    }

    lsnd->tmp_async = CT_FALSE;
    ctx->est_sync_standby_num++;
    if (lsnd->dest_info.affirm_mode == LOG_ARCH_AFFIRM) {
        ctx->est_affirm_standy_num++;
    }
    cm_spin_unlock(&lsnd->lock);

    CT_LOG_ALARM_RECOVER(WARN_DEGRADE, "'peer-host':'%s', 'peer-port':'%u', 'status':'%s'}",
                         lsnd->dest_info.peer_host, lsnd->dest_info.peer_port, "flush log");
    CT_LOG_RUN_INF("[Log Sender] %lu read log from send buffer", LSND_TID(lsnd));
}

static void lsnd_record_alarm_log(lsnd_t *lsnd, degrade_type_t type)
{
    switch (type) {
        case DEGRADE_FLUSH_LOG:
            CT_LOG_RUN_INF("[Log Sender] LSND(%lu) send buffer is full, need to read log from file directly "
                "during flushing log", LSND_TID(lsnd));
            CT_LOG_ALARM(WARN_DEGRADE, "'peer-host':'%s', 'peer-port':'%u', 'status':'%s'}",
                lsnd->dest_info.peer_host, lsnd->dest_info.peer_port, "flush log");
            break;

        case DEGRADE_WAIT_RESP:
            CT_LOG_RUN_INF("[Log Sender] LSND(%lu) is changed to temporary asynchronous in waiting", LSND_TID(lsnd));
            CT_LOG_ALARM(WARN_DEGRADE, "'peer-host':'%s', 'peer-port':'%u', 'status':'%s'}",
                lsnd->dest_info.peer_host, lsnd->dest_info.peer_port, "waiting");
            break;

        case DEGRADE_WAIT_SWITCH:
            CT_LOG_RUN_INF("[Log Sender] LSND(%lu) standby log switch waiting at [%u-%u/%u/%llu]", LSND_TID(lsnd),
                lsnd->wait_point.rst_id, lsnd->wait_point.asn, lsnd->wait_point.block_id, (uint64)lsnd->wait_point.lfn);
            CT_LOG_ALARM(WARN_DEGRADE, "'peer-host':'%s', 'peer-port':'%u', 'status':'%s'}",
                lsnd->dest_info.peer_host, lsnd->dest_info.peer_port, "switch log waiting");
            break;

        default:
            CT_LOG_RUN_INF("[Log Sender] LSND(%lu) flush log should stop for session kill", LSND_TID(lsnd));
            CT_LOG_ALARM(WARN_DEGRADE, "'peer-host':'%s', 'peer-port':'%u', 'status':'%s'}",
                lsnd->dest_info.peer_host, lsnd->dest_info.peer_port, "session kill");
            break;
    }
}

static void lsnd_set_tmp_async(lsnd_t *lsnd, degrade_type_t type)
{
    lsnd_context_t *ctx = &lsnd->session->kernel->lsnd_ctx;

    if (lsnd->tmp_async) {
        return;
    }

    cm_spin_lock(&lsnd->lock, NULL);
    if (lsnd->tmp_async) {
        cm_spin_unlock(&lsnd->lock);
        return;
    }

    lsnd->tmp_async = CT_TRUE;
    knl_panic(ctx->est_sync_standby_num > 0);
    ctx->est_sync_standby_num--;
    if (lsnd->dest_info.affirm_mode == LOG_ARCH_AFFIRM) {
        CM_ASSERT(ctx->est_affirm_standy_num > 0);
        ctx->est_affirm_standy_num--;
    }

    lsnd->send_buf.write_pos = 0;
    lsnd->send_buf.read_pos = 0;

    cm_spin_unlock(&lsnd->lock);

    lsnd_record_alarm_log(lsnd, type);
}

static inline bool32 lsnd_need_flush(lsnd_t *lsnd)
{
    return (bool32)(!lsnd->flush_completed &&
                    lsnd->status > LSND_STATUS_QUERYING &&
                    lsnd->dest_info.sync_mode == LOG_NET_TRANS_MODE_SYNC);
}

bool32 lsnd_copy_batch(lsnd_t *lsnd, log_batch_t *batch, log_file_t *file, log_point_t *point)
{
    rep_msg_header_t *rep_msg_header = NULL;
    rep_batch_req_t *rep_batch_req = NULL;
    uint32 offset;
    uint32 pkg_size = batch->size + lsnd->header_size;
    log_context_t *redo_ctx = &lsnd->session->kernel->redo_ctx;
    log_batch_tail_t *tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));
    errno_t err;

    cm_spin_lock(&lsnd->lock, NULL);
    if (lsnd->send_buf.write_pos == lsnd->send_buf.read_pos) {
        lsnd->send_buf.write_pos = 0;
        lsnd->send_buf.read_pos = 0;
    }
    cm_spin_unlock(&lsnd->lock);

    if (pkg_size > REMAIN_BUFSZ(&lsnd->send_buf)) {
        if (lsnd->send_buf.read_pos >= pkg_size) {
            lsnd->send_buf.illusion_count++;
        }
        return CT_FALSE;
    }

    if (lsnd->session->kernel->attr.lsnd_wait_time != 0) {
        cm_release_cond_signal(&lsnd->cond);
    }

    // Message format: [rep_msg_header_t][rep_batch_req_t][log batch data]
    offset = lsnd->send_buf.write_pos;
    rep_msg_header = (rep_msg_header_t *)(lsnd->send_buf.read_buf.aligned_buf + offset);
    rep_msg_header->size = pkg_size;
    rep_msg_header->type = REP_BATCH_REQ;
    offset += sizeof(rep_msg_header_t);

    rep_batch_req = (rep_batch_req_t *)(lsnd->send_buf.read_buf.aligned_buf + offset);
    rep_batch_req->log_file_id = (uint32)file->ctrl->file_id;
    rep_batch_req->log_point = *point;
    rep_batch_req->curr_point = redo_ctx->curr_point;
    rep_batch_req->scn = batch->scn;
    rep_batch_req->compress_alg = lsnd->dest_info.compress_alg;
    offset += sizeof(rep_batch_req_t);

    err = memcpy_sp(lsnd->send_buf.read_buf.aligned_buf + offset, (uint32)lsnd->send_buf.read_buf.buf_size - offset,
                    (char *)batch, batch->size);
    knl_securec_check(err);

    CT_LOG_DEBUG_INF("[Log Sender] copy batch to write pos %u with size %u on log file[%u] at log point "
                     "[%u-%u/%u/%llu] with peer flush point [%u-%u/%u/%llu] size %u "
                     "head [%llu/%llu/%llu] tail [%llu/%llu]",
                     lsnd->send_buf.write_pos, pkg_size, file->ctrl->file_id, point->rst_id,
                     point->asn, point->block_id, (uint64)point->lfn, lsnd->peer_flush_point.rst_id,
                     lsnd->peer_flush_point.asn, lsnd->peer_flush_point.block_id,
                     (uint64)lsnd->peer_flush_point.lfn, batch->size, batch->head.magic_num,
                     (uint64)batch->head.point.lfn, batch->raft_index,
                     tail->magic_num, (uint64)tail->point.lfn);

    lsnd->last_read_asn = file->head.asn;
    lsnd->last_read_file_id = file->ctrl->file_id;
    cm_spin_lock(&lsnd->lock, NULL);
    lsnd->send_buf.write_pos += pkg_size;
    cm_spin_unlock(&lsnd->lock);
    lsnd->flush_completed = CT_TRUE;

    return CT_TRUE;
}

static void lsnd_set_async_flush_exit(lsnd_context_t *ctx, const uint16 *lsnd_index, uint16 need_flush_num)
{
    for (uint16 i = 0; i < need_flush_num; i++) {
        uint16 idx = lsnd_index[i];
        lsnd_t *lsnd = ctx->lsnd[idx];

        if (lsnd_need_flush(lsnd)) {
            lsnd_set_tmp_async(lsnd, DEGRADE_SESSION_KILL);
        }
    }
}

void lsnd_try_set_tmp_async(knl_session_t *session, log_batch_t *batch, log_point_t *point, log_file_t *file,
    const uint16 *lsnd_index, uint16 need_flush_num)
{
    knl_attr_t *attr = &session->kernel->attr;
    lsnd_context_t *ctx = &session->kernel->lsnd_ctx;
    uint32 begin_time = attr->timer->systime;
    bool32 is_timeout = CT_FALSE;

    for (;;) {
        uint16 copy_cnt = 0;
        if (lsnd_flush_need_exit(session)) {
            lsnd_set_async_flush_exit(ctx, lsnd_index, need_flush_num);
            return;
        }

        for (uint16 i = 0; i < need_flush_num; i++) {
            uint16 idx = lsnd_index[i];
            lsnd_t *lsnd = ctx->lsnd[idx];

            if (!lsnd_need_flush(lsnd)) {
                copy_cnt++;
                continue;
            }

            lsnd_try_clear_tmp_async(lsnd, point);
            if (lsnd->tmp_async) {
                copy_cnt++;
                continue;
            }

            if (lsnd_copy_batch(lsnd, batch, file, point)) {
                copy_cnt++;
                continue;
            }

            if (attr->timer->systime - begin_time >= lsnd->timeout * REPL_WAIT_MULTI) {
                is_timeout = CT_TRUE;
                lsnd_set_tmp_async(lsnd, DEGRADE_FLUSH_LOG);
            }
        }

        if (copy_cnt >= need_flush_num || is_timeout) {
            return;
        }

        cm_sleep(1);
    }
}

static inline bool32 lsnd_flush_need_exit(knl_session_t *session)
{
    if (session->killed) {
        CT_LOG_RUN_WAR("session killed");
        return CT_TRUE;
    }

    if (session->kernel->ckpt_ctx.thread.closed) {
        CT_LOG_RUN_WAR("ckpt thread will exit");
        return CT_TRUE;
    }

    if (session->kernel->redo_ctx.thread.closed) {
        CT_LOG_RUN_WAR("log thread will exit");
        return CT_TRUE;
    }

    if (session->kernel->stats_ctx.thread.closed) {
        CT_LOG_RUN_WAR("stats thread will exit");
        return CT_TRUE;
    }

    return CT_FALSE;
}

/*
 * There is no need to wait for system reserved session when instance
 * is building or state switching.
 */
static inline bool32 lsnd_sys_session_no_wait(knl_session_t *session)
{
    return (bool32)(IS_SYS_SESSION(session) &&
        (session->kernel->switch_ctrl.request != SWITCH_REQ_NONE ||
        session->kernel->backup_ctx.bak.is_building));
}

static inline uint16 lsnd_wait_count(knl_session_t *session)
{
    database_t *db = &session->kernel->db;
    lsnd_context_t *ctx = &session->kernel->lsnd_ctx;

    if (MODE_MAX_PROTECTION(db)) {
        return (ctx->affirm_standy_num > 0 ? ctx->affirm_standy_num : 1);
    } else {
        return (ctx->est_affirm_standy_num > 0 ? ctx->est_affirm_standy_num : 1);
    }
}

// protection mode
void lsnd_wait_without_quorum(knl_session_t *session, uint64 curr_lfn, uint64 *quorum_lfn)
{
    database_t *db = &session->kernel->db;
    knl_attr_t *attr = &session->kernel->attr;
    lsnd_context_t *ctx = &session->kernel->lsnd_ctx;
    uint32 begin_time = attr->timer->systime;
    uint16 affirm_cnt;

    for (;;) {
        if (lsnd_flush_need_exit(session) || SECUREC_UNLIKELY(lsnd_sys_session_no_wait(session))) {
            return;
        }

        if (LSND_NO_NEED_WAIT_SYNC(db, ctx)) {
            if (quorum_lfn != NULL) {
                *quorum_lfn = CT_INVALID_INT64;
            }
            return;
        }

        affirm_cnt = 0;

        for (uint32 i = 0; i < ctx->standby_num; i++) {
            lsnd_t *lsnd = ctx->lsnd[i];

            if (lsnd == NULL || lsnd->is_disable || STANDBY_NO_NEED_WAIT(db, ctx, lsnd)) {
                continue;
            }

            if (curr_lfn <= lsnd->peer_flush_point.lfn) {
                affirm_cnt++;
                continue;
            }

            uint32 end_time = attr->timer->systime;
            if (MODE_MAX_AVAILABILITY(db) &&
                (end_time - begin_time >= lsnd->timeout * REPL_WAIT_MULTI &&
                    lsnd->dest_info.sync_mode == LOG_NET_TRANS_MODE_SYNC)) {
                lsnd_set_tmp_async(lsnd, DEGRADE_WAIT_RESP);
            }
        }
        
        if (affirm_cnt >= lsnd_wait_count(session)) {
            if (quorum_lfn != NULL) {
                *quorum_lfn = curr_lfn;
            }
            return;
        }
        cm_timedwait_eventfd(&ctx->eventfd, 1);
    }
}

void lsnd_wait_with_quorum(knl_session_t *session, uint64 curr_lfn, uint64 *quorum_lfn)
{
    database_t *db = &session->kernel->db;
    knl_attr_t *attr = &session->kernel->attr;
    lsnd_context_t *ctx = &session->kernel->lsnd_ctx;
    uint32 sync_needed = attr->quorum_any;
    uint32 begin_time = attr->timer->systime;
    uint32 flushed, tmp_async_cnt;

    for (;;) {
        if (lsnd_flush_need_exit(session) || SECUREC_UNLIKELY(lsnd_sys_session_no_wait(session))) {
            return;
        }

        if (LSND_NO_NEED_WAIT_ALL(db, ctx)) {
            if (quorum_lfn != NULL) {
                *quorum_lfn = CT_INVALID_INT64;
            }
            return;
        }

        flushed = 0;
        tmp_async_cnt = 0;

        for (uint32 i = 0; i < ctx->standby_num; i++) {
            lsnd_t *lsnd = ctx->lsnd[i];

            if (lsnd == NULL || lsnd->is_disable || lsnd->status < LSND_LOG_SHIFTING) {
                // if standby is not enabled or not normal, just continue
                continue;
            }

            if (curr_lfn <= lsnd->peer_flush_point.lfn) {
                flushed++;
                continue;
            }

            uint32 end_time = attr->timer->systime;
            if (MODE_MAX_AVAILABILITY(db) &&
                (end_time - begin_time >= lsnd->timeout * REPL_WAIT_MULTI &&
                    lsnd->dest_info.sync_mode == LOG_NET_TRANS_MODE_SYNC)) {
                lsnd_set_tmp_async(lsnd, DEGRADE_WAIT_RESP);
            }

            if (LSND_IS_TMP_ASYNC(lsnd)) {
                tmp_async_cnt++;
            }
        }

        if (MODE_MAX_AVAILABILITY(db)) {
            sync_needed = MIN(ctx->est_standby_num - tmp_async_cnt, attr->quorum_any);
        }

        if (flushed >= sync_needed) {
            if (quorum_lfn != NULL) {
                *quorum_lfn = curr_lfn;
            }
            return;
        }
        cm_timedwait_eventfd(&ctx->eventfd, 1);
    }
}

void lsnd_wait(knl_session_t *session, uint64 curr_lfn, uint64 *quorum_lfn)
{
    if (session->kernel->attr.quorum_any > 0) {
        lsnd_wait_with_quorum(session, curr_lfn, quorum_lfn);
    } else {
        lsnd_wait_without_quorum(session, curr_lfn, quorum_lfn);
    }
}

void lsnd_flush_log(knl_session_t *session, log_context_t *redo_ctx, log_file_t *file, log_batch_t *batch)
{
    lsnd_context_t *ctx = &session->kernel->lsnd_ctx;
    log_point_t *point = &batch->head.point;
    uint16 need_flush_num = 0;
    uint16 copy_cnt = 0;

    CT_LOG_DEBUG_INF("[Log Sender] Try to flush batch %llu(%llu) in log %u asn %u offset %u",
                     (uint64)point->lfn, (uint64)batch->head.point.lfn,
                     file->ctrl->file_id, point->asn, point->block_id);

    cm_latch_s(&ctx->latch, SESSION_ID_LSND, CT_FALSE, NULL);

    uint16 lsnd_index[CT_MAX_PHYSICAL_STANDBY];
    for (uint16 i = 0; i < ctx->standby_num; i++) {
        if (ctx->lsnd[i] == NULL || ctx->lsnd[i]->is_disable || ctx->lsnd[i]->status < LSND_STATUS_QUERYING) {
            continue;
        }

        ctx->lsnd[i]->flush_completed = CT_FALSE;
    }

    for (uint16 i = 0; i < ctx->standby_num; i++) {
        lsnd_t *lsnd = ctx->lsnd[i];

        if (lsnd == NULL || lsnd->is_disable || !lsnd_need_flush(lsnd)) {
            continue;
        }

        lsnd_index[need_flush_num++] = i;
        lsnd_try_clear_tmp_async(lsnd, point);
        if (lsnd->tmp_async) {
            continue;
        }

        if (lsnd_copy_batch(lsnd, batch, file, point)) {
            copy_cnt++;
        }
    }

    if (copy_cnt >= need_flush_num) {
        cm_unlatch(&ctx->latch, NULL);
        return;
    }

    lsnd_try_set_tmp_async(session, batch, point, file, lsnd_index, need_flush_num);

    cm_unlatch(&ctx->latch, NULL);
}

status_t lsnd_open_specified_logfile(knl_session_t *session, uint32 slot)
{
    lsnd_context_t *ctx = &session->kernel->lsnd_ctx;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);
    log_file_t *logfile = &logfile_set->items[slot];
    lsnd_t *lsnd = NULL;

    cm_latch_s(&ctx->latch, session->id, CT_FALSE, NULL);

    for (uint16 i = 0; i < ctx->standby_num; i++) {
        lsnd = ctx->lsnd[i];
        if (lsnd == NULL || lsnd->is_disable) {
            continue;
        }

        /* closed in lsnd_close_specified_logfile */
        if (cm_open_device(logfile->ctrl->name, logfile->ctrl->type, knl_redo_io_flag(session),
                           &lsnd->log_handle[slot]) != CT_SUCCESS) {
            cm_unlatch(&ctx->latch, NULL);
            CT_LOG_RUN_ERR("[Log Sender] failed to open %s", logfile->ctrl->name);
            return CT_ERROR;
        }
    }

    cm_unlatch(&ctx->latch, NULL);
    return CT_SUCCESS;
}

void lsnd_close_specified_logfile(knl_session_t *session, uint32 slot)
{
    lsnd_context_t *ctx = &session->kernel->lsnd_ctx;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);
    log_file_t *logfile = &logfile_set->items[slot];
    lsnd_t *lsnd = NULL;

    cm_latch_s(&ctx->latch, session->id, CT_FALSE, NULL);

    for (uint16 i = 0; i < ctx->standby_num; i++) {
        lsnd = ctx->lsnd[i];
        if (lsnd == NULL || lsnd->is_disable || lsnd->status < LSND_STATUS_QUERYING) {
            continue;
        }

        cm_close_device(logfile->ctrl->type, &lsnd->log_handle[slot]);
    }

    cm_unlatch(&ctx->latch, NULL);
}

void lsnd_get_min_contflush_point(lsnd_context_t *ctx, log_point_t *cont_point)
{
    lsnd_t *lsnd = NULL;

    cm_latch_s(&ctx->latch, SESSION_ID_ARCH, CT_FALSE, NULL);

    for (uint32 i = 0; i < ctx->standby_num; i++) {
        lsnd = ctx->lsnd[i];

        if (lsnd == NULL || lsnd->is_disable) {
            continue;
        }

        if (lsnd->peer_contflush_point.rst_id < cont_point->rst_id ||
            lsnd->peer_contflush_point.asn < cont_point->asn) {
            cont_point->rst_id = lsnd->peer_contflush_point.rst_id;
            cont_point->asn = lsnd->peer_contflush_point.asn;
        }
    }

    cm_unlatch(&ctx->latch, NULL);
}

/* get standby max log flush point */
void lsnd_get_max_flush_point(knl_session_t *session, log_point_t *max_flush_point, bool32 need_lock)
{
    lsnd_context_t *ctx = &session->kernel->lsnd_ctx;
    lsnd_t *lsnd = NULL;
    log_point_t peer_flush_point;

    if (need_lock) {
        cm_latch_s(&ctx->latch, session->id, CT_FALSE, NULL);
    }
    for (uint32 i = 0; i < ctx->standby_num; i++) {
        lsnd = ctx->lsnd[i];
        if (lsnd == NULL || lsnd->is_disable) {
            continue;
        }
        peer_flush_point = lsnd->peer_flush_point;

        if (log_cmp_point(max_flush_point, &peer_flush_point) < 0) {
            *max_flush_point = peer_flush_point;
        }
    }
    if (need_lock) {
        cm_unlatch(&ctx->latch, NULL);
    }
}

static char *lsnd_get_role_valid(arch_attr_t *arch_attr)
{
    switch (arch_attr->role_valid) {
        case VALID_FOR_PRIMARY_ROLE:
            return "PRIMARY_ROLE";
        case VALID_FOR_STANDBY_ROLE:
            return "STANDBY_ROLE";
        case VALID_FOR_ALL_ROLES:
            return "ALL_ROLES";
        default:
            return "NULL";
    }
}

static char *lsnd_get_net_mode(arch_attr_t *arch_attr)
{
    switch (arch_attr->net_mode) {
        case LOG_NET_TRANS_MODE_SYNC:
            return "SYNC";
        case LOG_NET_TRANS_MODE_ASYNC:
            return "ASYNC";
        default:
            return "NULL";
    }
}
static void lsnd_set_lag_info(lsnd_t *lsnd, sync_info_t *sync_info, uint64 curr_lfn)
{
    timeval_t peer_current_time;
    timeval_t peer_flush_time;
    timeval_t local_time;
    uint64 quorum_lfn = (uint64)cm_atomic_get((atomic_t *)&lsnd->session->kernel->redo_ctx.quorum_lfn);

    knl_scn_to_timeval(lsnd->session, lsnd->peer_flush_scn, &peer_flush_time);
    knl_scn_to_timeval(lsnd->session, lsnd->peer_current_scn, &peer_current_time);
    knl_scn_to_timeval(lsnd->session, DB_CURR_SCN(lsnd->session), &local_time);

    /* Before the primary sending log to the standby, lsnd->peer_flush_scn = 0 */
    if (lsnd->peer_flush_scn == 0) {
        sync_info->flush_lag = INVALID_FLUSH_LAG;
    } else if (cm_timeval2date(local_time) < cm_timeval2date(peer_flush_time) ||
        (quorum_lfn != CT_INVALID_INT64 && quorum_lfn <= lsnd->peer_flush_point.lfn) ||
        (quorum_lfn == CT_INVALID_INT64 && curr_lfn == lsnd->peer_flush_point.lfn)) {
        sync_info->flush_lag = 0;   /* There is no lag in primary/standby log flush. */
    } else {
        sync_info->flush_lag = (uint64)(cm_timeval2date(local_time) - cm_timeval2date(peer_flush_time)) /
            MICROSECS_PER_MILLISEC;
    }

    if (curr_lfn == lsnd->peer_rcy_point.lfn) {
        sync_info->replay_lag = 0;
    } else if (cm_timeval2date(local_time) < cm_timeval2date(peer_current_time)) {
        sync_info->replay_lag = 0;
        CT_LOG_RUN_INF("[Log Sender] Primary scn is smaller than standby, peer_flush_scn: %llu, "
            "peer_current_scn: %llu, local_scn: %llu, peer_flush_lfn: %llu, peer_rcy_lfn: %llu, "
            "local_curr_lfn: %llu, local_quorum_lfn: %llu",
            lsnd->peer_flush_scn, lsnd->peer_current_scn, DB_CURR_SCN(lsnd->session),
            (uint64)lsnd->peer_flush_point.lfn, (uint64)lsnd->peer_rcy_point.lfn, curr_lfn, quorum_lfn);
    } else {
        sync_info->replay_lag = (uint64)(cm_timeval2date(local_time) - cm_timeval2date(peer_current_time)) /
            MICROSECS_PER_MILLISEC;
    }
}

static char* lsnd_set_build_stage(bak_stage_t *stage)
{
    uint32 build_stage = bak_get_build_stage(stage);
    switch (build_stage) {
        case BUILD_START:
            return "BUILD START";
        case BUILD_PARAM_STAGE:
            return "BUILD PARAMETER";
        case BUILD_CTRL_STAGE:
            return "BUILD CTRL FILE";
        case BUILD_DATA_STAGE:
            return "BUILD DATA FILES";
        case BUILD_LOG_STAGE:
            return "BUILD LOG FILES";
        case BUILD_HEAD_STAGE:
            return "BUILD SUMMARY";
        case BUILD_SYNC_FINISHED:
            return "BUILD SYNC END";
        default:
            return "INVALID";
    }
}

static void lsnd_set_build_info(knl_session_t *session, sync_info_t *sync_info, bool32 peer_building)
{
    bak_context_t *backup_ctx = &session->kernel->backup_ctx;
    bak_t *bak = &backup_ctx->bak;
    bak_progress_t *ctrl = &bak->progress;
    errno_t err;

    if (!peer_building || !PRIMARY_IS_BUILDING(backup_ctx) ||
        strncmp(bak->peer_host, sync_info->peer_host, CT_HOST_NAME_BUFFER_SIZE) != 0) {
        return;
    }

    if (bak->record.is_repair) {
        err = strcpy_sp(sync_info->build_type, CT_DYNVIEW_NORMAL_LEN, "REPAIR BUILD");
        knl_securec_check(err);
        return;
    } else if (bak->record.is_increment) {
        err = strcpy_sp(sync_info->build_type, CT_DYNVIEW_NORMAL_LEN, "INCREMENTAL BUILD");
        knl_securec_check(err);
        return;
    } else {
        err = strcpy_sp(sync_info->build_type, CT_DYNVIEW_NORMAL_LEN, "FULL BUILD");
        knl_securec_check(err);
    }

    err = strcpy_sp(sync_info->build_stage, CT_DYNVIEW_NORMAL_LEN, lsnd_set_build_stage(&ctrl->stage));
    knl_securec_check(err);
    sync_info->build_total_stage_size = ctrl->data_size / SIZE_K(1);
    sync_info->build_synced_stage_size = ctrl->processed_size / SIZE_K(1);

    if (ctrl->processed_size > 0) {
        double complete_rate = ctrl->processed_size * 1.0 / ctrl->data_size;
        if (complete_rate >= 1) {
            complete_rate = 1;
        }
        sync_info->build_progress = ctrl->base_rate + (uint32)(int32)(ctrl->weight * complete_rate);
    } else {
        sync_info->build_progress = ctrl->base_rate;
    }

    if ((uint64)cm_now() >= bak->record.start_time) {
        sync_info->build_time = ((uint64)cm_now() - bak->record.start_time) / MICROSECS_PER_MILLISEC;
    }
}

static void lsnd_set_sync_info(knl_session_t *session, lsnd_t *lsnd, sync_info_t *sync_info, uint64 lfn, uint64 lsn)
{
    errno_t err;
    bool32 is_building = CT_FALSE;

    sync_info->local_lfn = lfn;
    sync_info->local_lsn = lsn;

    if (lsnd == NULL || lsnd->is_disable) {
        err = strcpy_sp(sync_info->status, sizeof(sync_info->status), "NOT RUNNING");
        knl_securec_check(err);
    } else if (lsnd->status == LSND_DISCONNECTED) {
        err = strcpy_sp(sync_info->status, sizeof(sync_info->status), "DISCONNECTED");
        knl_securec_check(err);
    } else if (lsnd->status == LSND_STATUS_QUERYING) {
        is_building = lsnd->peer_is_building;
        err = strcpy_sp(sync_info->status, sizeof(sync_info->status), "CONNECTED");
        knl_securec_check(err);
    } else {
        err = strcpy_sp(sync_info->status, sizeof(sync_info->status), "SHIFTING");
        knl_securec_check(err);

        sync_info->peer_lfn = lsnd->peer_rcy_point.lfn;
        sync_info->peer_lsn = lsnd->peer_replay_lsn;

        err = snprintf_s(sync_info->local_point, sizeof(sync_info->local_point), sizeof(sync_info->local_point) - 1,
            "%llu-%u/%u", lsnd->send_point.rst_id, lsnd->send_point.asn, lsnd->send_point.block_id);
        knl_securec_check_ss(err);

        err = snprintf_s(sync_info->peer_point, sizeof(sync_info->peer_point), sizeof(sync_info->peer_point) - 1,
            "%llu-%u/%u", lsnd->peer_flush_point.rst_id, lsnd->peer_flush_point.asn, lsnd->peer_flush_point.block_id);
        knl_securec_check_ss(err);

        err = snprintf_s(sync_info->peer_cont_point, sizeof(sync_info->peer_cont_point),
            sizeof(sync_info->peer_cont_point) - 1, "%llu-%u", lsnd->peer_contflush_point.rst_id,
            lsnd->peer_contflush_point.asn);
        knl_securec_check_ss(err);

        lsnd_set_lag_info(lsnd, sync_info, lfn);
    }

    err = strncpy_s(sync_info->peer_building, sizeof(sync_info->peer_building), is_building ? "TRUE" : "FALSE",
                    CT_MAX_BOOL_STRLEN);
    knl_securec_check(err);
    lsnd_set_build_info(session, sync_info, is_building);
}

static lsnd_t *lsnd_get_match_thread(lsnd_context_t *ctx, arch_attr_t *arch_attr)
{
    lsnd_t *lsnd = NULL;

    for (uint32 i = 0; i < CT_MAX_PHYSICAL_STANDBY; i++) {
        lsnd = ctx->lsnd[i];

        if (lsnd == NULL || lsnd->is_disable) {
            continue;
        }

        if (strcmp(arch_attr->service.host, lsnd->dest_info.peer_host) == 0 &&
            arch_attr->service.port == lsnd->dest_info.peer_port && arch_attr->enable) {
            return lsnd;
        }
    }

    return lsnd;
}

void lsnd_get_sync_info(knl_session_t *session, ha_sync_info_t *ha_sync_info)
{
    lsnd_context_t *ctx = &session->kernel->lsnd_ctx;
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    knl_attr_t *attr = &session->kernel->attr;
    sync_info_t *sync_info = NULL;
    arch_attr_t *arch_attr = NULL;
    lsnd_t *lsnd = NULL;
    size_t host_len;
    char *role_valid = NULL;
    char *net_mode = NULL;
    errno_t err;

    err = memset_sp(ha_sync_info, sizeof(ha_sync_info_t), 0, sizeof(ha_sync_info_t));
    knl_securec_check(err);

    for (uint32 i = 1; i < CT_MAX_ARCH_DEST; i++) {
        arch_attr = &attr->arch_attr[i];

        if (arch_attr->dest_mode != LOG_ARCH_DEST_SERVICE || !arch_attr->used) {
            continue;
        }

        if (arch_dest_state_match_role(session, arch_attr)) {
            sync_info = &ha_sync_info->sync_info[ha_sync_info->count++];

            host_len = strlen(arch_attr->local_host);
            err = strncpy_s(sync_info->local_host, sizeof(sync_info->local_host), arch_attr->local_host, host_len);
            knl_securec_check(err);

            role_valid = lsnd_get_role_valid(arch_attr);
            err = strcpy_sp(sync_info->role_valid, sizeof(sync_info->role_valid), role_valid);
            knl_securec_check(err);

            net_mode = lsnd_get_net_mode(arch_attr);
            err = strcpy_sp(sync_info->net_mode, sizeof(sync_info->net_mode), net_mode);
            knl_securec_check(err);

            host_len = strlen(arch_attr->service.host);
            err = strncpy_s(sync_info->peer_host, sizeof(sync_info->peer_host), arch_attr->service.host, host_len);
            knl_securec_check(err);

            sync_info->peer_port = arch_attr->service.port;

            lsnd = lsnd_get_match_thread(ctx, arch_attr);
            lsnd_set_sync_info(session, lsnd, sync_info, redo_ctx->lfn, (uint64)session->kernel->lsn);
        }
    }
}

void lsnd_reset_state(knl_session_t *session)
{
    lsnd_context_t *ctx = &session->kernel->lsnd_ctx;

    cm_latch_x(&ctx->latch, session->id, NULL);

    for (uint16 i = 0; i < ctx->standby_num; i++) {
        if (ctx->lsnd[i] == NULL || ctx->lsnd[i]->is_disable || ctx->lsnd[i]->state == REP_STATE_NORMAL) {
            continue;
        }

        ctx->lsnd[i]->state = REP_STATE_NORMAL;
    }

    cm_unlatch(&ctx->latch, NULL);
}

void lsnd_trigger_task_response(knl_session_t *session, uint32 lsnd_id, bool32 failed)
{
    lsnd_context_t *ctx = &session->kernel->lsnd_ctx;
    lsnd_bak_task_t *bak_task = &ctx->lsnd[lsnd_id]->bak_task;
    rep_bak_task_t *task = &bak_task->task;

    if (task->status != BAK_TASK_WAIT_PROCESS) {
        return;
    }

    cm_spin_lock(&bak_task->lock, NULL);
    if (task->status == BAK_TASK_WAIT_PROCESS) {
        task->failed = failed;
        task->status = BAK_TASK_WAIT_RESPONSE;
    }
    cm_spin_unlock(&bak_task->lock);
}

static uint32 lsnd_standby_config_num(knl_session_t *session)
{
    uint32 standby_num = 0;
    knl_attr_t *attr = &session->kernel->attr;
    arch_attr_t *arch_attr = NULL;

    for (uint32 i = 1; i < CT_MAX_PHYSICAL_STANDBY; i++) {
        arch_attr = &attr->arch_attr[i];
        if (arch_attr->dest_mode != LOG_ARCH_DEST_SERVICE || !arch_attr->enable) {
            continue;
        }

        if (arch_attr->role_valid == VALID_FOR_STANDBY_ROLE) {
            continue;
        }
        standby_num++;
    }
    return standby_num;
}

status_t lsnd_check_protection_standby_num(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    bool32 has_sync = CT_FALSE;
    uint32 quorum_any;
    uint32 standby_num;
    lsnd_context_t *ctx = &kernel->lsnd_ctx;

    cm_latch_x(&ctx->latch, session->id, NULL);

    quorum_any = kernel->attr.quorum_any;
    standby_num = lsnd_standby_config_num(session);

    for (uint32 i = 1; i <= CT_MAX_PHYSICAL_STANDBY; i++) {
        if (kernel->attr.arch_attr[i].net_mode == LOG_NET_TRANS_MODE_SYNC &&
            kernel->attr.arch_attr[i].role_valid != VALID_FOR_STANDBY_ROLE &&
            kernel->attr.arch_attr[i].enable) {
            has_sync = CT_TRUE;
            break;
        }
    }

    if (quorum_any > 0) {
        CT_LOG_RUN_INF("[Log Sender] config standby num is %d, ctx->standby_num is %d",
                       standby_num, ctx->standby_num);
        if (quorum_any > standby_num) {
            CT_THROW_ERROR(ERR_STANDBY_LESS_QUORUM, standby_num, quorum_any);
            cm_unlatch(&ctx->latch, NULL);
            return CT_ERROR;
        }

        cm_unlatch(&ctx->latch, NULL);
        return CT_SUCCESS;
    }
    if (!has_sync) {
        CT_THROW_ERROR(ERR_NO_SYNC_STANDBY);
        cm_unlatch(&ctx->latch, NULL);
        return CT_ERROR;
    }

    cm_unlatch(&ctx->latch, NULL);
    return CT_SUCCESS;
}
