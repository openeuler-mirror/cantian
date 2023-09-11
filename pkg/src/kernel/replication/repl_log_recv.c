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
 * repl_log_recv.c
 *
 *
 * IDENTIFICATION
 * src/kernel/replication/repl_log_recv.c
 *
 * -------------------------------------------------------------------------
 */
#include "repl_log_recv.h"
#include "cm_file.h"
#include "knl_context.h"
#include "knl_abr.h"
#include "dtc_database.h"

#define SUSPEND_INTERVAL 1000
#define EMPTY_LOG_POINT(pt) (((pt).rst_id == 0) && ((pt).asn == 0) && ((pt).offset == 0) && ((pt).lfn == 0))
#define LRCV_IS_RUNING(lrcv) ((lrcv)->session != NULL)
#define LRCV_INVALID_DBID(peer_dbid, local_dbid) ((peer_dbid) != 0 && (peer_dbid) != (local_dbid))

static inline void lrcv_disconnect(lrcv_context_t *lrcv)
{
    cs_disconnect(lrcv->pipe);
}

static void lrcv_reset_bak_task(lrcv_context_t *lrcv)
{
    rep_bak_task_t *task = &lrcv->task;

    if (task->status == BAK_TASK_DONE) {
        return;
    }

    if (task->status == BAK_TASK_WAIT_PROCESS) {
        lrcv->task.error_no = ERR_SEND_RECORD_REQ_FAILED;
    } else {
        lrcv->task.error_no = ERR_RECORD_BACKUP_FAILED;
    }

    task->status = BAK_TASK_DONE;
}

static void lrcv_set_conn_err(lrcv_context_t *lrcv)
{
    lrcv_disconnect(lrcv);
    lrcv_reset_bak_task(lrcv);
}

static bool32 lrcv_need_suspend(lrcv_context_t *lrcv)
{
    database_t *db = &lrcv->session->kernel->db;

    if (lrcv->session->kernel->lftc_client_ctx.arch_lost) {
        lrcv->status = LRCV_NEED_REPAIR;
        return GS_TRUE;
    }

    if (lrcv->session->kernel->rcy_ctx.log_decrypt_failed) {
        lrcv->status = LRCV_NEED_REPAIR;
        return GS_TRUE;
    }

    if (lrcv->status == LRCV_NEED_REPAIR && DB_IS_PHYSICAL_STANDBY(db) && lrcv->peer_role == PEER_PRIMARY) {
        return GS_TRUE;
    }

    return GS_FALSE;
}

static bool32 lrcv_rcv_msg_is_valid(lrcv_context_t *lrcv)
{
    char *extend_buf = lrcv->extend_buf.read_buf.aligned_buf;
    log_context_t *redo_ctx = &lrcv->session->kernel->redo_ctx;

    switch (lrcv->header.type) {
        case REP_BATCH_REQ: {
            rep_batch_req_t *req = (rep_batch_req_t *)extend_buf;
            if (log_point_is_invalid(&req->log_point) || log_point_is_invalid(&req->curr_point) ||
                req->compress_alg < COMPRESS_NONE || req->compress_alg > COMPRESS_LZ4 ||
                req->log_file_id >= redo_ctx->logfile_hwm) {
                return GS_FALSE;
            }
            break;
        }

        case REP_QUERY_STATUS_REQ: {
            rep_query_status_req_t *query_req = (rep_query_status_req_t *)extend_buf;
            if (log_point_is_invalid(&query_req->curr_point)) {
                return GS_FALSE;
            }
            break;
        }

        case REP_SWITCH_RESP: {
            rep_switch_resp_t *switch_resp = (rep_switch_resp_t *)extend_buf;
            if (switch_resp->state < REP_STATE_NORMAL || switch_resp->state > REP_STATE_REJECTED) {
                return GS_FALSE;
            }
            break;
        }

        case REP_ABR_REQ: {
            rep_abr_req_t *abr_req = (rep_abr_req_t *)extend_buf;
            if (abr_req->blk_size != lrcv->session->kernel->attr.page_size) {
                return GS_FALSE;
            }
            break;
        }

        case REP_HEART_BEAT_REQ:
        case REP_RECORD_BACKUPSET_RESP: {
            break;
        }

        default: {
            return GS_FALSE;
        }
    }

    return GS_TRUE;
}

static bool32 lrcv_need_exit(lrcv_context_t *lrcv)
{
    database_t *db = &lrcv->session->kernel->db;

    if (lrcv->session->killed) {
        GS_LOG_RUN_INF("Log receiver thread has been killed");
        return GS_TRUE;
    }

    if (db->status >= DB_STATUS_MOUNT && DB_IS_PRIMARY(db)) {
        GS_LOG_RUN_INF("[Log Receiver] database role is primary, database status is %s, thread will exit normally",
                       db_get_status(lrcv->session));
        return GS_TRUE;
    }

    return GS_FALSE;
}

static status_t lrcv_flush_log(lrcv_context_t *lrcv, log_point_t *log_point, void *batch, uint32 size)
{
    log_context_t *log_ctx = &lrcv->session->kernel->redo_ctx;
    log_file_t *file = &log_ctx->files[log_ctx->curr_file];
    uint64 offset = (uint64)log_point->block_id * file->ctrl->block_size;
    uint32 space_size = CM_CALC_ALIGN(size, file->ctrl->block_size);
    log_batch_t *batch_x = (log_batch_t *)batch;
    log_batch_tail_t *tail = (log_batch_tail_t *)((char *)batch + batch_x->size - sizeof(log_batch_tail_t));

    if (cm_write_device(file->ctrl->type, file->handle, offset, batch, space_size) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[Log Receiver] failed to write log into %s[%u] with log size %u at point [%u-%u/%llu]",
                       file->ctrl->name, log_ctx->curr_file, space_size,
                       file->head.rst_id, file->head.asn, file->head.write_pos);
        return GS_ERROR;
    }

    GS_LOG_DEBUG_INF("[Log Receiver] Write space size %u into log file[%u] at point [%u-%u/%llu] to %llu "
                     "size %u head [%llx/%llu/%llu] tail [%llx/%llu]",
                     space_size, log_ctx->curr_file, file->head.rst_id, file->head.asn,
                     file->head.write_pos, offset + space_size, batch_x->size, batch_x->head.magic_num,
                     (uint64)batch_x->head.point.lfn, batch_x->raft_index, tail->magic_num, (uint64)tail->point.lfn);
    lrcv->session->kernel->lfn = log_point->lfn;
    file->head.write_pos = offset + space_size;
    file->head.last = batch_x->scn;
    if (file->head.first == GS_INVALID_ID64) {
        file->head.first = batch_x->scn;
        log_flush_head(lrcv->session, file);
    }
    log_point->block_id = (uint32)(file->head.write_pos / file->ctrl->block_size);
    log_ctx->free_size -= space_size;

    return GS_SUCCESS;
}

static status_t lrcv_process_heart_beat(knl_session_t *session)
{
    lrcv_context_t *lrcv = &session->kernel->lrcv_ctx;
    char *buf = lrcv->send_buf.read_buf.aligned_buf;
    rep_msg_header_t *rep_msg_header = (rep_msg_header_t *)buf;
    rep_hb_resp_t *rep_hb_resp = (rep_hb_resp_t *)(buf + sizeof(rep_msg_header_t));
    status_t status;

    rep_msg_header->size = sizeof(rep_msg_header_t) + sizeof(rep_hb_resp_t);
    rep_msg_header->type = REP_HEART_BEAT_RESP;

    rep_hb_resp->flush_point = lrcv->flush_point;
    rep_hb_resp->rcy_point = lrcv->session->kernel->redo_ctx.curr_replay_point;
    rep_hb_resp->replay_lsn = (uint64)lrcv->session->kernel->lsn;
    rep_hb_resp->flush_scn = lrcv->flush_scn;
    rep_hb_resp->current_scn = DB_CURR_SCN(lrcv->session);
    rep_hb_resp->contflush_point.rst_id = lrcv->contflush_point.rst_id;
    rep_hb_resp->contflush_point.asn = lrcv->contflush_point.asn;

    status = cs_write_stream(lrcv->pipe, buf, rep_msg_header->size,
                             (int32)cm_atomic_get(&session->kernel->attr.repl_pkg_size));
    if (status != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[Log Receiver] failed to send heart beat response message to primary");
    }
    return status;
}

status_t lrcv_fetch_archived_log(lrcv_context_t *lrcv, log_file_t *file, bool32 need_wait,
    char *arch_name, uint32 arch_name_buf_size)
{
    lftc_task_handle_t lftc_handle;
    bool32 lftc_done = GS_FALSE;
    time_t last_send_time = cm_current_time();

    uint32 rst_id = file->head.rst_id;
    uint32 asn = file->head.asn;

    // Check whether corresponding archived log exists
    if (arch_get_archived_log_name(lrcv->session, rst_id, asn, ARCH_DEFAULT_DEST, arch_name, arch_name_buf_size,
                                   lrcv->session->kernel->id)) {
        return GS_SUCCESS;
    }

    arch_set_archive_log_name(lrcv->session, rst_id, asn, ARCH_DEFAULT_DEST, arch_name, arch_name_buf_size,
                              lrcv->session->kernel->id);
    GS_LOG_RUN_INF("[Log Receiver] Archive log %s for node %d not found", arch_name, lrcv->session->kernel->id);
    if (cm_file_exist(arch_name)) {
        return GS_SUCCESS;
    }

    if (lftc_clt_create_task(lrcv->session, rst_id, asn, arch_name, &lftc_handle) != GS_SUCCESS) {
        return GS_ERROR;
    }

    // Loop to check whether corresponding archived log exists & keep heart beat
    for (;;) {
        if (lrcv_need_exit(lrcv) || lrcv_need_suspend(lrcv)) {
            return GS_ERROR;
        }

        if (need_wait) {
            time_t now = cm_current_time();
            if ((now - last_send_time) >= REPL_HEART_BEAT_CHECK) {
                if (lrcv_process_heart_beat(lrcv->session) != GS_SUCCESS) {
                    lrcv_set_conn_err(lrcv);
                    return GS_ERROR;
                }
                last_send_time = now;
            }
        }

        if (lftc_clt_task_running(lrcv->session, &lftc_handle, &lftc_done)) {
            cm_sleep(100);
            continue;
        }

        if (lftc_done) {
            return GS_SUCCESS;
        }
        if (!need_wait) {
            return GS_ERROR;
        }

        // Sleep 1 seconds and retry
        cm_sleep(1000);

        // If failed to fetch log from primary, restart the task
        arch_set_archive_log_name(lrcv->session, rst_id, asn, ARCH_DEFAULT_DEST, arch_name, arch_name_buf_size,
                                  lrcv->session->kernel->id);
        if (lftc_clt_create_task(lrcv->session, rst_id, asn, arch_name, &lftc_handle) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t lrcv_verify_checksum_batch(knl_session_t *session, log_batch_t *batch_input, uint32 size, log_point_t *log_point)
{
    uint32 left_size = size;
    log_batch_t *batch = batch_input;
    log_batch_tail_t *tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));

    while (left_size >= sizeof(log_batch_t)) {
        if (!rcy_validate_batch(batch, tail)) {
            GS_LOG_RUN_ERR("[Log Receiver] invalid received batch with lfn %llu, size is [%u/%u]",
                           (uint64)batch->head.point.lfn, left_size, size);
            return GS_ERROR;
        }

        if (rcy_verify_checksum(session, batch) != GS_SUCCESS) {
            return GS_ERROR;
        }

        log_point->lfn = batch->head.point.lfn;

        if (left_size <= batch->space_size) {
            break;
        }

        left_size -= batch->space_size;

        batch = (log_batch_t *)((char *)batch + batch->space_size);
        tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));
    }

    return GS_SUCCESS;
}

static inline void lrcv_set_switch_wait(lrcv_context_t *lrcv, rep_batch_req_t *req)
{
    lrcv->wait_info.waiting = GS_TRUE;
    lrcv->wait_info.wait_point = req->log_point;
    lrcv->wait_info.wait_point.block_id = 0; // Set to 0, easy to compare it with replay point
    lrcv->wait_info.file_id = req->log_file_id;
}

static void lrcv_reset_switch_wait(lrcv_context_t *lrcv)
{
    log_context_t *log = &lrcv->session->kernel->redo_ctx;
    log_file_t *file = &log->files[log->curr_file];
    log_point_t *wait_point = &lrcv->wait_info.wait_point;

    log_lock_logfile(lrcv->session);

    /* Invalidate current log file if it exists still */
    if (!LOG_IS_DROPPED(file->ctrl->flg)) {
        uint64 start_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
        cm_latch_x(&file->latch, lrcv->session->id, NULL);
        file->head.asn = GS_INVALID_ASN;
        log->free_size += file->head.write_pos - start_pos;
        file->head.write_pos = start_pos;
        file->ctrl->status = LOG_FILE_INACTIVE;
        file->ctrl->archived = GS_FALSE;
        log_flush_head(lrcv->session, file);
        if (db_save_log_ctrl(lrcv->session, log->curr_file, lrcv->session->kernel->id) != GS_SUCCESS) {
            CM_ABORT(0, "[Log Receiver] ABORT INFO: save control space file failed when reset switch wait");
        }
        cm_unlatch(&file->latch, NULL);
    }

    log->active_file = lrcv->wait_info.file_id;
    log->curr_file = lrcv->wait_info.file_id;

    /* Reset current log file */
    file = &log->files[log->curr_file];
    cm_latch_x(&file->latch, lrcv->session->id, NULL);
    file->head.asn = wait_point->asn;
    file->head.rst_id = (uint32)wait_point->rst_id;
    file->head.write_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
    file->ctrl->status = LOG_FILE_CURRENT;
    file->ctrl->archived = GS_FALSE;
    log_flush_head(lrcv->session, file);
    if (db_save_log_ctrl(lrcv->session, log->curr_file, lrcv->session->kernel->id) != GS_SUCCESS) {
        CM_ABORT(0, "[Log Receiver] ABORT INFO: save control space file failed when reset switch wait");
    }
    cm_unlatch(&file->latch, NULL);
    log_unlock_logfile(lrcv->session);

    dtc_my_ctrl(lrcv->session)->log_first = log->active_file;
    dtc_my_ctrl(lrcv->session)->log_last = log->curr_file;
    if (db_save_core_ctrl(lrcv->session) != GS_SUCCESS) {
        CM_ABORT(0, "[Log Receiver] ABORT INFO: save control space file failed when reset switch wait");
    }

    /* Reset switch wait info */
    lrcv->wait_info.waiting = GS_FALSE;
    errno_t err = memset_sp(wait_point, sizeof(log_point_t), 0, sizeof(log_point_t));
    knl_securec_check(err);
    lrcv->wait_info.file_id = GS_INVALID_FILEID;
}

static status_t lrcv_send_switch_wait(lrcv_context_t *lrcv)
{
    char *buf = lrcv->send_buf.read_buf.aligned_buf;
    rep_msg_header_t *rep_msg_header = (rep_msg_header_t *)buf;
    rep_log_switch_wait_t *rep_switch_wait = (rep_log_switch_wait_t *)(buf + sizeof(rep_msg_header_t));
    status_t status;

    rep_msg_header->size = sizeof(rep_msg_header_t) + sizeof(rep_log_switch_wait_t);
    rep_msg_header->type = REP_LOG_SWITCH_WAIT_REQ;

    rep_switch_wait->wait_point = lrcv->wait_info.wait_point;
    status = cs_write_stream(lrcv->pipe, buf, rep_msg_header->size,
                             (int32)cm_atomic_get(&lrcv->session->kernel->attr.repl_pkg_size));
    if (status != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[Log Receiver] failed to send log switch wait message to primary");
    }

    return status;
}

static status_t lrcv_process_switch_wait(lrcv_context_t *lrcv)
{
    knl_session_t *session = lrcv->session;
    log_point_t *rcy_point = &dtc_my_ctrl(session)->rcy_point;
    log_point_t *lrp_point = &dtc_my_ctrl(session)->lrp_point;
    lrpl_context_t *lrpl = &session->kernel->lrpl_ctx;
    log_point_t *wait_point = &lrcv->wait_info.wait_point;
    log_file_head_t *head = &session->kernel->rcy_ctx.arch_file.head;
    log_context_t *redo = &session->kernel->redo_ctx;
    log_file_head_t *curr = &redo->files[redo->curr_file].head;
    if (!lrcv->wait_info.waiting) {
        return GS_SUCCESS;
    }

    /*
     * The following three situations indicate that all logs have been replayed
     * 1. Replay point is at the end of the last archive log (the previous one of the wait point),
     * 2. Replay point is at the end of current file (replay point is on current file),
     * 3. Replay point is equal to wait point.
     */
    if (!((head->asn == wait_point->asn - 1 && lrpl->curr_point.block_id * head->block_size == head->write_pos) ||
        (curr->asn == wait_point->asn - 1 && redo->curr_point.block_id > 1 &&
        redo->curr_point.block_id * curr->block_size == curr->write_pos) ||
        (log_cmp_point(&lrpl->curr_point, wait_point) == 0))) {
        return GS_SUCCESS;
    }

    rcy_wait_replay_complete(session);

    /* Wait rcy point reaches to lrp point */
    if (rcy_point->lfn < lrp_point->lfn) {
        ckpt_trigger(session, GS_FALSE, CKPT_TRIGGER_INC);
        cm_sleep(10);
        return GS_SUCCESS;
    }

    GS_LOG_RUN_INF("[Log Receiver] asn %u can locate in fileid %u on local node, log switch will succeed",
        lrcv->wait_info.wait_point.asn, lrcv->wait_info.file_id);

    lrcv_reset_switch_wait(lrcv);
    if (lrcv_send_switch_wait(lrcv) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t lrcv_process_batch(lrcv_context_t *lrcv)
{
    log_context_t *log = &lrcv->session->kernel->redo_ctx;
    log_batch_t *batch = (log_batch_t *)(lrcv->recv_buf.read_buf.aligned_buf);
    rep_batch_req_t *req = (rep_batch_req_t *)lrcv->extend_buf.read_buf.aligned_buf;

    if (lrcv->header.size <= sizeof(rep_msg_header_t) + sizeof(rep_batch_req_t)) {
        GS_LOG_RUN_ERR("[Log Receiver] invalid batch head size %u received, which is smaller than %u",
                       lrcv->header.size, (uint32)(sizeof(rep_msg_header_t) + sizeof(rep_batch_req_t)));
        return GS_ERROR;
    }

    uint32 size = lrcv->header.size - sizeof(rep_msg_header_t) - sizeof(rep_batch_req_t);

    GS_LOG_DEBUG_INF("[Log Receiver] Received batch with size %u on log file[%u] at point [%u-%u/%u/%llu], "
                     "current log file is %u",
                     size, req->log_file_id, req->log_point.rst_id, req->log_point.asn,
                     req->log_point.block_id, (uint64)req->log_point.lfn, log->curr_file);

    lrcv->primary_curr_point = req->curr_point;

    if (lrcv->status == LRCV_PREPARE) {
        log_file_t *file = &log->files[log->curr_file];

        /*
         * 1) req log_point > file head scenario: primary switched logfile during disconnection.
         * 2) req log_point = file head scenario: standby has just been built end.
         * 3) req log_point < file head scenario: this is cascaded standby, redo switched with skip,
         *                                        and peer node has failovered.
         */
        if (LRCV_LOG_POINT_ON_POST_FILE(req->log_point, file->head) ||
            (LRCV_LOG_POINT_ON_CURR_FILE(req->log_point, file->head) && req->log_file_id != log->curr_file) ||
            LRCV_LOG_POINT_ON_PRE_FILE(req->log_point, file->head)) {
            uint64 start_pos;
            uint32 file_id = log->active_file;
            char arch_name[GS_FILE_NAME_BUFFER_SIZE];

            if (LRCV_LOG_POINT_ON_POST_FILE(req->log_point, file->head)) {
                if (lrcv_fetch_archived_log(lrcv, file, GS_TRUE, arch_name, GS_FILE_NAME_BUFFER_SIZE) != GS_SUCCESS) {
                    GS_LOG_RUN_ERR("[Log Receiver] failed to fetch archive log file [%u/%u] from primary",
                                   file->head.rst_id, file->head.asn);
                    return GS_ERROR;
                }
            }

            log_lock_logfile(lrcv->session);

            // Need to invalidate current log file
            start_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
            cm_latch_x(&file->latch, lrcv->session->id, NULL);
            file->head.asn = GS_INVALID_ASN;
            file->head.rst_id = (uint32)req->log_point.rst_id;
            log->free_size += file->head.write_pos - start_pos;
            file->head.write_pos = start_pos;
            file->ctrl->status = LOG_FILE_INACTIVE;
            file->ctrl->archived = GS_FALSE;
            log_flush_head(lrcv->session, file);
            if (db_save_log_ctrl(lrcv->session, log->curr_file, lrcv->session->kernel->id) != GS_SUCCESS) {
                CM_ABORT(0, "[Log Receiver] ABORT INFO: save control space file failed when switch log file");
            }
            cm_unlatch(&file->latch, NULL);

            GS_LOG_RUN_INF("[Log Receiver] Invalidate current file, active %u current %u",
                           log->active_file, log->curr_file);

            while (file_id != log->curr_file) {
                file = log->files + file_id;
                if (file->ctrl->status == LOG_FILE_ACTIVE) {
                    start_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
                    log->free_size += (uint64)file->ctrl->size - start_pos;
                    file->ctrl->status = LOG_FILE_UNUSED;
                }
                log_get_next_file(lrcv->session, &file_id, GS_FALSE);
            }

            log->active_file = req->log_file_id;
            log->curr_file = req->log_file_id;

            file = &log->files[log->curr_file];
            cm_latch_x(&file->latch, lrcv->session->id, NULL);
            file->head.asn = req->log_point.asn;
            file->head.rst_id = (uint32)req->log_point.rst_id;
            file->head.write_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
            file->ctrl->status = LOG_FILE_CURRENT;
            file->ctrl->archived = GS_FALSE;
            log_flush_head(lrcv->session, file);
            if (db_save_log_ctrl(lrcv->session, log->curr_file, lrcv->session->kernel->id) != GS_SUCCESS) {
                CM_ABORT(0, "[Log Receiver] ABORT INFO: save control space file failed when switch log file");
            }
            cm_unlatch(&file->latch, NULL);
            log_unlock_logfile(lrcv->session);

            GS_LOG_RUN_INF("[Log Receiver] Reset current file asn %u status %d, active %u current %u",
                           file->head.asn, file->ctrl->status, log->active_file, log->curr_file);

            dtc_my_ctrl(lrcv->session)->log_first = log->active_file;
            dtc_my_ctrl(lrcv->session)->log_last = log->curr_file;
            if (GS_SUCCESS != db_save_core_ctrl(lrcv->session)) {
                CM_ABORT(0, "[Log Receiver] ABORT INFO: save control space file failed when switch log file");
            }
        }

        lrcv->reset_asn = req->log_point.asn;
        lrcv->status = LRCV_READY;
    }

    if (req->log_file_id != log->curr_file ||
        req->log_point.asn != log->files[log->curr_file].head.asn) {
        callback_t callback;

        if (log_switch_need_wait(lrcv->session, (uint16)req->log_file_id, req->log_point.asn)) {
            lrcv_set_switch_wait(lrcv, req);
            GS_LOG_RUN_INF("[Log Receiver] asn %u does not locate in fileid %u on local node, log switch should wait",
                req->log_point.asn, req->log_file_id);
            return GS_SUCCESS;
        }

        callback.keep_hb_entry = lrcv_process_heart_beat;
        callback.keep_hb_param = lrcv->session;
        if (log_switch_logfile(lrcv->session, (uint16)req->log_file_id, req->log_point.asn,
                               &callback) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[Log Receiver] failed to switch log file to %u with asn %u", req->log_file_id,
                           req->log_point.asn);
            return GS_ERROR;
        }
    }

    knl_panic(req->log_file_id == log->curr_file);

    if (lrcv_verify_checksum_batch(lrcv->session, batch, size, &req->log_point) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lrcv_flush_log(lrcv, &req->log_point, (void *)batch, size) != GS_SUCCESS) {
        return GS_ERROR;
    }

    lrcv->flush_point = req->log_point;
    lrcv->flush_scn = req->scn;

    return GS_SUCCESS;
}

static status_t lrcv_send_batch_ack(lrcv_context_t *lrcv)
{
    char *buf = lrcv->send_buf.read_buf.aligned_buf;
    rep_msg_header_t *rep_msg_header = (rep_msg_header_t *)buf;
    rep_batch_resp_t *rep_batch_resp = (rep_batch_resp_t *)(buf + sizeof(rep_msg_header_t));
    status_t status;

    rep_msg_header->size = sizeof(rep_msg_header_t) + sizeof(rep_batch_resp_t);
    rep_msg_header->type = REP_BATCH_RESP;

    rep_batch_resp->flush_point = lrcv->flush_point;
    rep_batch_resp->rcy_point = lrcv->session->kernel->redo_ctx.curr_replay_point;
    rep_batch_resp->replay_lsn = (uint64)lrcv->session->kernel->lsn;
    rep_batch_resp->flush_scn = lrcv->flush_scn;
    rep_batch_resp->current_scn = DB_CURR_SCN(lrcv->session);
    rep_batch_resp->contflush_point.rst_id = lrcv->contflush_point.rst_id;
    rep_batch_resp->contflush_point.asn = lrcv->contflush_point.asn;

    status = cs_write_stream(lrcv->pipe, buf, rep_msg_header->size,
                             (int32)cm_atomic_get(&lrcv->session->kernel->attr.repl_pkg_size));
    if (status != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[Log Receiver] failed to send batch response message to primary");
    }
    return status;
}

void lrcv_needrepair(lrcv_context_t *lrcv)
{
    lrcv->status = LRCV_NEED_REPAIR;
    cm_sleep(2000);
}

static status_t lrcv_wait_logfile_no_active(lrcv_context_t *lrcv)
{
    log_context_t *log_ctx = &lrcv->session->kernel->redo_ctx;
    log_point_t *rcy_point = &dtc_my_ctrl(lrcv->session)->rcy_point;
    uint32 file_id = log_ctx->active_file;
    log_file_t *file = NULL;
    uint64 lfn;
    uint64 scn;

    GS_LOG_RUN_INF("[Log Receiver] log file active %u current %u", log_ctx->active_file, log_ctx->curr_file);
    // Wait for all log files before current file to become LOG_STATE_INACTIVE or LOG_STATE_UNUSED
    while (file_id != log_ctx->curr_file) {
        ckpt_trigger(lrcv->session, GS_FALSE, CKPT_TRIGGER_INC);

        file = log_ctx->files + file_id;
        if (file->ctrl->status == LOG_FILE_INACTIVE || file->ctrl->status == LOG_FILE_UNUSED) {
            log_get_next_file(lrcv->session, &file_id, GS_FALSE);
        } else if (file->ctrl->status == LOG_FILE_ACTIVE) {
            if (LRCV_LOG_POINT_ON_CURR_FILE(*rcy_point, file->head)) {
                char arch_name[GS_FILE_NAME_BUFFER_SIZE];

                if (arch_get_archived_log_name(lrcv->session, file->head.rst_id, file->head.asn, ARCH_DEFAULT_DEST,
                                               arch_name, GS_FILE_NAME_BUFFER_SIZE, lrcv->session->kernel->id)) {
                    uint64 file_offset = 0;
                    if (log_get_file_offset(lrcv->session, arch_name, &lrcv->recv_buf.read_buf, &file_offset,
                                            &lfn, &scn) != GS_SUCCESS) {
                        GS_LOG_RUN_ERR("[Log Receiver] failed to get file offset for archived log %s ", arch_name);
                        return GS_ERROR;
                    }

                    if (rcy_point->lfn >= lfn || log_ctx->lfn >= lfn) {
                        GS_LOG_RUN_INF("[Log Receiver] rcy_point [%u-%u/%u/%llu] or replay lfn %llu has reached "
                                       "the end of log file[%u] [%u-%u/%llu/%llu]",
                                       rcy_point->rst_id, rcy_point->asn, rcy_point->block_id,
                                       (uint64)rcy_point->lfn, log_ctx->lfn, file_id,
                                       file->head.rst_id, file->head.asn, file_offset, lfn);
                        log_get_next_file(lrcv->session, &file_id, GS_FALSE);
                    } else {
                        GS_LOG_DEBUG_INF("[Log Receiver] rcy_point [%u-%u/%u/%llu] has not reached the end of "
                                         "log file[%u] [%u-%u/%llu/%llu], so continue",
                                         rcy_point->rst_id, rcy_point->asn, rcy_point->block_id,
                                         (uint64)rcy_point->lfn, file_id, file->head.rst_id,
                                         file->head.asn, file_offset, lfn);
                        cm_sleep(100);
                    }
                }
            } else if (LRCV_LOG_POINT_ON_POST_FILE(*rcy_point, file->head)) {
                if (file->head.asn != GS_INVALID_ASN) {
                    log_recycle_file(lrcv->session, rcy_point);
                } else {
                    log_get_next_file(lrcv->session, &file_id, GS_FALSE);
                }
            } else {
                cm_sleep(1000);

                if (lrcv_process_heart_beat(lrcv->session) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            }
        } else {
            cm_sleep(10);
        }

        if (lrcv->session->killed || lrcv->thread.closed) {
            GS_LOG_RUN_INF("Log receiver thread has been killed");
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t lrcv_prepare_log_files(lrcv_context_t *lrcv, rep_query_status_req_t *req)
{
    log_context_t *log_ctx = &lrcv->session->kernel->redo_ctx;
    log_point_t *lrp_point = &dtc_my_ctrl(lrcv->session)->lrp_point;
    log_point_t *rcy_point = &dtc_my_ctrl(lrcv->session)->rcy_point;
    uint64 curr_lfn = 0;
    uint64 scn;
    log_file_t *file = NULL;

    if (lrcv_wait_logfile_no_active(lrcv) != GS_SUCCESS) {
        return GS_ERROR;
    }

    arch_reset_file_id(lrcv->session, ARCH_DEFAULT_DEST);

    lrcv->flush_point.lfn = 0;
    lrcv->contflush_point.rst_id = dtc_my_ctrl(lrcv->session)->rcy_point.rst_id;
    lrcv->contflush_point.asn = dtc_my_ctrl(lrcv->session)->rcy_point.asn;
    file = &log_ctx->files[log_ctx->curr_file];

    GS_LOG_RUN_INF("[Log Receiver] Standby current log file[%u] status %d log point is [%u-%u/%llu/%llu]",
                   log_ctx->curr_file, file->ctrl->status, file->head.rst_id,
                   file->head.asn, file->head.write_pos, curr_lfn);
    GS_LOG_RUN_INF("[Log Receiver] Standby lrp_point is [%u-%u/%u/%llu] rcy_point is [%u-%u/%u/%llu]",
                   lrp_point->rst_id, lrp_point->asn, lrp_point->block_id, (uint64)lrp_point->lfn,
                   rcy_point->rst_id, rcy_point->asn, rcy_point->block_id, (uint64)rcy_point->lfn);
    GS_LOG_RUN_INF("[Log Receiver] Primary current log point is [%u-%u/%u/%llu]",
                   req->curr_point.rst_id, req->curr_point.asn,
                   req->curr_point.block_id, (uint64)req->curr_point.lfn);

    if (LRCV_LOG_POINT_ON_CURR_FILE(*lrp_point, file->head)) {
        if (LRCV_LOG_POINT_ON_CURR_FILE(req->curr_point, file->head)) {
            if (!lrcv->reconnected) {
                lrcv->flush_point.rst_id = file->head.rst_id;
                lrcv->flush_point.asn = file->head.asn;
                if (log_get_file_offset(lrcv->session, file->ctrl->name, &lrcv->recv_buf.read_buf,
                                        (uint64 *)&file->head.write_pos, &curr_lfn, &scn) != GS_SUCCESS) {
                    GS_LOG_RUN_ERR("[Log Receiver] failed to get file offset for online log %s ", file->ctrl->name);
                    return GS_ERROR;
                }
                GS_LOG_RUN_INF("[Log Receiver] Standby repaired current log file[%u] status %d log point is [%u-%u/%llu/%llu]",
                               log_ctx->curr_file, file->ctrl->status, file->head.rst_id, file->head.asn,
                               file->head.write_pos, curr_lfn);
                lrcv->flush_point.block_id = (uint32)(file->head.write_pos / file->ctrl->block_size);
                lrcv->flush_point.lfn = curr_lfn;
            } else {
                lrcv->flush_point = log_ctx->curr_point;
            }
            GS_LOG_RUN_INF("[Log Receiver] lrp_point is on current log, and primary/standby log has no gap");
        } else if (LRCV_LOG_POINT_ON_POST_FILE(req->curr_point, file->head)) {
            char arch_name[GS_FILE_NAME_BUFFER_SIZE];
            uint64 write_pos_ori = file->head.write_pos;
            uint64 write_pos_new;

            // Start LFTC to fetch corresponding archived log from primary
            if (lrcv_fetch_archived_log(lrcv, file, GS_FALSE, arch_name, GS_FILE_NAME_BUFFER_SIZE) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[Log Receiver] failed to fetch archive log file [%u/%u] from primary",
                               file->head.rst_id, file->head.asn);
                return GS_ERROR;
            }
            file->ctrl->archived = GS_TRUE;
            if (db_save_log_ctrl(lrcv->session, log_ctx->curr_file, lrcv->session->kernel->id) != GS_SUCCESS) {
                CM_ABORT(0, "[Log Receiver] ABORT INFO: save control redo file failed when prepare logfile");
            }
            lrcv->flush_point.rst_id = file->head.rst_id;
            lrcv->flush_point.asn = file->head.asn;
            if (log_get_file_offset(lrcv->session, arch_name, &lrcv->recv_buf.read_buf,
                                    &write_pos_new, &curr_lfn, &scn) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[Log Receiver] failed to get file offset for archived log %s ", arch_name);
                return GS_ERROR;
            }

            log_set_logfile_writepos(lrcv->session, file, write_pos_new);
            GS_LOG_RUN_INF("[Log Receiver] Standby repaired current log file[%u] status %d log point "
                           "is [%u-%u/%llu/%llu] with old pos %llu",
                           log_ctx->curr_file, file->ctrl->status, file->head.rst_id, file->head.asn,
                           file->head.write_pos, curr_lfn, write_pos_ori);
            if (lrcv->reconnected) {
                log_ctx->free_size -= file->head.write_pos - write_pos_ori;
            }
            lrcv->flush_point.lfn = curr_lfn;
            lrcv->flush_point.block_id = (uint32)(file->head.write_pos / file->ctrl->block_size);
            GS_LOG_RUN_INF("[Log Receiver] lrp_point is on current log, and primary/standby log has gap");
        } else {
            GS_LOG_RUN_ERR("[Log Receiver] current log point [%u-%u/%u/%llu] from primary is "
                           "less than standby current log [%u-%u]",
                           req->curr_point.rst_id, req->curr_point.asn, req->curr_point.block_id,
                           (uint64)req->curr_point.lfn, file->head.rst_id, file->head.asn);
            return GS_ERROR;
        }
    } else if (LRCV_LOG_POINT_ON_PRE_FILE(*lrp_point, file->head)) {
        lrcv->flush_point = log_ctx->curr_point;

        if (!lrcv->reconnected) {
            if (log_get_file_offset(lrcv->session, file->ctrl->name, &lrcv->recv_buf.read_buf,
                                    (uint64 *)&file->head.write_pos, &curr_lfn, &scn) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[Log Receiver] failed to get file offset for logfile[%u] %s, latest lfn %llu",
                               log_ctx->curr_file, file->ctrl->name, curr_lfn);
                return GS_ERROR;
            }
        }

        /*
         * The current point of the primary node is smaller than the current file of the standby node,
         * this issue occurs only when redo skips and the peer node becomes the primary node after failover.
         * In this case, we set flush point with redo current point.
         */
        if (!LRCV_LOG_POINT_ON_PRE_FILE(req->curr_point, file->head)) {
            lrcv->flush_point.rst_id = file->head.rst_id;
            lrcv->flush_point.asn = file->head.asn;
            lrcv->flush_point.block_id = (uint32)(file->head.write_pos / file->ctrl->block_size);
            if (curr_lfn > lrcv->flush_point.lfn) {
                lrcv->flush_point.lfn = curr_lfn;
            }
        }

        GS_LOG_RUN_INF("[Log Receiver] lrp_point is on previous log");
    } else {
        knl_panic(file->head.asn == GS_INVALID_ASN);
    }

    if (!lrcv->reconnected) {
        log_ctx->free_size += log_file_freesize(file);
    }

    GS_LOG_RUN_INF("[Log Receiver] Set flush point to [%u-%u/%u/%llu], log free size is %llu",
                   lrcv->flush_point.rst_id, lrcv->flush_point.asn, lrcv->flush_point.block_id,
                   (uint64)lrcv->flush_point.lfn, log_ctx->free_size);
    return GS_SUCCESS;
}

static bool32 lrcv_log_ctrl_check(lrcv_context_t *lrcv, rep_query_status_req_t *req)
{
    log_context_t *log_ctx = &lrcv->session->kernel->redo_ctx;
    log_file_t *logfile = NULL;
    log_file_ctrl_t *ctrl_pri = NULL;

    if (req->log_num != log_ctx->logfile_hwm) {
        GS_LOG_RUN_ERR("[Log Receiver] Redo hwm [%u/%u] is no equal for primary/standby, need repair",
                       req->log_num, log_ctx->logfile_hwm);
        return GS_FALSE;
    }

    ctrl_pri = (log_file_ctrl_t *)((char *)req + sizeof(rep_query_status_req_t));
    for (uint32 i = 0; i < log_ctx->logfile_hwm; i++) {
        logfile = &log_ctx->files[i];

        if (logfile->ctrl->flg != ctrl_pri->flg) {
            GS_LOG_RUN_ERR("[Log Receiver] %s flag %u is different from %s flag %u (0-normal, 1-dropped, 2-alarmed), "
                           "need repair", (strlen(ctrl_pri->name) != 0) ? ctrl_pri->name : "redo", ctrl_pri->flg,
                           (strlen(logfile->ctrl->name) != 0) ? logfile->ctrl->name : "redo", logfile->ctrl->flg);
            return GS_FALSE;
        }

        if (logfile->ctrl->block_size != ctrl_pri->block_size) {
            GS_LOG_RUN_ERR("[Log Receiver] %s block size %u is different from %s block size %u, need repair",
                           ctrl_pri->name, ctrl_pri->block_size, logfile->ctrl->name, logfile->ctrl->block_size);
            return GS_FALSE;
        }

        if (logfile->ctrl->file_id != ctrl_pri->file_id) {
            GS_LOG_RUN_ERR("[Log Receiver] %s fileid %d is different from %s fileid %d, need repair",
                           ctrl_pri->name, ctrl_pri->file_id, logfile->ctrl->name, logfile->ctrl->file_id);
            return GS_FALSE;
        }

        if (logfile->ctrl->size != ctrl_pri->size) {
            GS_LOG_RUN_ERR("[Log Receiver] %s file size %lld is different from %s file size %lld, need repair",
                           ctrl_pri->name, ctrl_pri->size, logfile->ctrl->name, logfile->ctrl->size);
            return GS_FALSE;
        }

        if (logfile->ctrl->type != ctrl_pri->type) {
            GS_LOG_RUN_ERR("[Log Receiver] %s type %u is different from %s type %u (1-file, 2-raw, 3-cfs), "
                           "need repair", ctrl_pri->name, ctrl_pri->type, logfile->ctrl->name, logfile->ctrl->type);
            return GS_FALSE;
        }

        ctrl_pri++;
    }

    return GS_TRUE;
}

static void lrcv_repair_logfile_rstid(knl_session_t *session, reset_log_t *rst_log)
{
    log_file_t *file = NULL;
    log_context_t *ctx = &session->kernel->redo_ctx;

    for (uint32 i = 0; i < ctx->logfile_hwm; i++) {
        file = &ctx->files[i];

        if (file->head.asn > rst_log->last_asn && file->head.rst_id < rst_log->rst_id) {
            GS_LOG_RUN_INF("[Log Receiver] logfile %s asn %u larger than resetlog asn %u, "
                           "but rstid %u less than resetlog rstid %u, revise file rstid with %u",
                           file->ctrl->name, file->head.asn, rst_log->last_asn, file->head.rst_id,
                           rst_log->rst_id, rst_log->rst_id);
            file->head.rst_id = rst_log->rst_id;
            log_flush_head(session, file);
        }
    }
}

static status_t lrcv_check_resetid(lrcv_context_t *lrcv, rep_query_status_req_t *req)
{
    log_point_t *point = &lrcv->session->kernel->redo_ctx.curr_point;
    database_t *db = &lrcv->session->kernel->db;
    log_point_t *rcy_point = &dtc_my_ctrl(lrcv->session)->rcy_point;
    reset_log_t *resetlog = &db->ctrl.core.resetlogs;

    if (req->rst_log.rst_id == resetlog->rst_id && resetlog->rst_id != 0 &&
        req->rst_log.last_lfn != resetlog->last_lfn) {
        lrcv_needrepair(lrcv);
        GS_LOG_RUN_ERR("[Log Receiver] primary has same resetid [%u] with standby, "
                       "but last lfn is not equal [%llu/%llu], "
                       "they are different sources, need repair",
                       req->rst_log.rst_id, req->rst_log.last_lfn, resetlog->last_lfn);
        return GS_ERROR;
    }

    if (req->rst_log.rst_id > point->rst_id + GS_MAX_RESETLOG_DISTANCE) {
        lrcv_needrepair(lrcv);
        GS_LOG_RUN_ERR("[Log Receiver] Resetlog distance is larger than [%u], need repair, "
                       "rst_id in message/curr_point is %u/%u",
                       GS_MAX_RESETLOG_DISTANCE, req->rst_log.rst_id, point->rst_id);
        return GS_ERROR;
    }

    if (req->rst_log.rst_id > rcy_point->rst_id + GS_MAX_RESETLOG_DISTANCE) {
        // wait ckpt update rcy point
        ckpt_trigger(lrcv->session, GS_TRUE, CKPT_TRIGGER_FULL);
        if (req->rst_log.rst_id > rcy_point->rst_id + GS_MAX_RESETLOG_DISTANCE) {
            lrcv_needrepair(lrcv);
            GS_LOG_RUN_ERR("[Log Receiver] Resetlog distance is larger than [%u], need repair, "
                           "rst_id in message/rcy_point is %u/%u",
                           GS_MAX_RESETLOG_DISTANCE, req->rst_log.rst_id, rcy_point->rst_id);
            return GS_ERROR;
        }
    }

    if (req->rst_log.rst_id < point->rst_id || req->rst_log.rst_id < resetlog->rst_id) {
        lrcv_needrepair(lrcv);
        GS_LOG_RUN_ERR("[Log Receiver] Standby current point resetid [%u] or resetlogs resetid [%u] is faster "
                       "than primary resetlogs [%u], need repair",
                       point->rst_id, resetlog->rst_id, req->rst_log.rst_id);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void lrcv_reset_primary_host(knl_session_t *session)
{
    lrcv_context_t *lrcv = &session->kernel->lrcv_ctx;
    errno_t ret = memset_sp(&lrcv->primary_host, sizeof(lrcv->primary_host), 0, sizeof(lrcv->primary_host));
    knl_securec_check(ret);
}

static void lrcv_trigger_start_lsnd(lrcv_context_t *lrcv)
{
    knl_session_t *session = lrcv->session;
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;

    cm_spin_lock(&arch_ctx->dest_lock, NULL);
    arch_ctx->arch_dest_state_changed = GS_TRUE;
    while (arch_ctx->arch_dest_state_changed) {
        if (session->killed) {
            cm_spin_unlock(&arch_ctx->dest_lock);
            return;
        }
        cm_sleep(1);
    }

    cm_spin_unlock(&arch_ctx->dest_lock);
}


static status_t lrcv_resetlog_check(lrcv_context_t *lrcv, rep_query_status_req_t *req)
{
    log_point_t *point = &lrcv->session->kernel->redo_ctx.curr_point;
    database_t *db = &lrcv->session->kernel->db;
    log_point_t *rcy_point = &dtc_my_ctrl(lrcv->session)->rcy_point;
    log_point_t *lrp_point = &dtc_my_ctrl(lrcv->session)->lrp_point;
    reset_log_t *resetlog = &db->ctrl.core.resetlogs;
    bool32 resetid_changed = GS_FALSE;

    if (req->version >= ST_VERSION_1 && req->notify_repair) {
        lrcv_needrepair(lrcv);
        GS_LOG_RUN_ERR("[Log Receiver] primary detects invalid batches based on the sending point returned by "
                       "standby, need repair");
        return GS_ERROR;
    }

    if (!db->ctrl.core.is_restored && LRCV_INVALID_DBID(req->dbid, db->ctrl.core.dbid)) {
        lrcv_needrepair(lrcv);
        GS_LOG_RUN_ERR("[Log Receiver] primary dbid [%u] is not equal to standby dbid [%u], need repair",
                       req->dbid, db->ctrl.core.dbid);
        return GS_ERROR;
    }

    GS_LOG_RUN_INF("[Log Receiver] resetlog_check primary resetlog is [%u/%u/%llu], standby resetlog is [%u/%u/%llu], "
                   "primary current point is [%u/%u/%llu], standby current point is [%u/%u/%llu], "
                   "standby rcy point is [%u/%u/%llu], lrp point is [%u/%u/%llu], "
                   "standby flush point is [%u/%u/%llu]",
                   req->rst_log.rst_id, req->rst_log.last_asn, req->rst_log.last_lfn,
                   resetlog->rst_id, resetlog->last_asn, resetlog->last_lfn,
                   req->curr_point.rst_id, req->curr_point.asn, (uint64)req->curr_point.lfn,
                   point->rst_id, point->asn, (uint64)point->lfn,
                   rcy_point->rst_id, rcy_point->asn, (uint64)rcy_point->lfn,
                   lrp_point->rst_id, lrp_point->asn, (uint64)lrp_point->lfn,
                   lrcv->flush_point.rst_id, lrcv->flush_point.asn, (uint64)lrcv->flush_point.lfn);

    if (lrcv_check_resetid(lrcv, req) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (req->curr_point.lfn < point->lfn || LOG_POINT_FILE_LT(req->curr_point, *point)) {
        lrcv_needrepair(lrcv);
        GS_LOG_RUN_ERR("[Log Receiver] Standby current point [%u/%u/%llu] is faster "
                       "than primary current point [%u/%u/%llu], need repair", point->rst_id, point->asn,
                       (uint64)point->lfn, req->curr_point.rst_id, req->curr_point.asn, (uint64)req->curr_point.lfn);
        return GS_ERROR;
    }

    if (req->rst_log.rst_id != point->rst_id &&
        ((req->rst_log.last_lfn < lrp_point->lfn - 1) || (req->rst_log.last_lfn < point->lfn))) {
        lrcv_needrepair(lrcv);
        GS_LOG_RUN_ERR("[Log Receiver] Standby log lrp point [%u/%llu] current redo point [%u/%llu] is faster "
                       "than primary [%u/%llu], need repair",
                       point->rst_id, (uint64)lrp_point->lfn - 1, point->rst_id,
                       (uint64)point->lfn, req->rst_log.rst_id, req->rst_log.last_lfn);
        return GS_ERROR;
    }

    if (!lrcv_log_ctrl_check(lrcv, req)) {
        lrcv_needrepair(lrcv);
        return GS_ERROR;
    }

    /*
     * Consider the disaster recovery scenario as follows: node A is primary, node B & C is standby,
     * and node D is cascaded standby.
     * A ----------> C
     * |             |
     * B             D
     *
     * If node A is down abnormally, and node B is promoted to primary by failover, then node B will
     * connect to node C.
     * A        ---> C
     *        /      |
     * B ----        D
     *
     * resetlog in node C will be different from D. So node C should reconnect to node D to transfer
     * new resetlog to node D.
     */
    if (req->rst_log.rst_id > resetlog->rst_id) {
        resetid_changed = GS_TRUE;
    }

    *resetlog = req->rst_log;
    if (!GS_INVALID_SCN(req->reset_log_scn)) {
        db->ctrl.core.reset_log_scn = req->reset_log_scn;
    }
    if (db_save_core_ctrl(lrcv->session) != GS_SUCCESS) {
        CM_ABORT(0, "[Log Receiver] ABORT INFO: Save core control file failed when database reset logs, need repair");
    }

    if (resetid_changed || lrcv->host_changed) {
        lsnd_mark_reconnect(lrcv->session, resetid_changed, lrcv->host_changed);
    }

    lrcv_repair_logfile_rstid(lrcv->session, &req->rst_log);

    GS_LOG_RUN_INF("[Log Receiver] Resetlog check passed. Current reset log is [%u/%u/%llu], "
                   "current log point in redo context is [%u-%u/%u/%llu]",
                   req->rst_log.rst_id, req->rst_log.last_asn, req->rst_log.last_lfn,
                   point->rst_id, point->asn, point->block_id, (uint64)point->lfn);

    return GS_SUCCESS;
}

static void lrcv_try_change_db_role(lrcv_context_t *lrcv)
{
    database_t *db = &lrcv->session->kernel->db;

    if (lrcv->role_spec_building) {
        return;
    }

    if (DB_IS_PHYSICAL_STANDBY(db) && (lrcv->peer_role == PEER_STANDBY)) {
        db->ctrl.core.db_role = REPL_ROLE_CASCADED_PHYSICAL_STANDBY;
        GS_LOG_RUN_INF("[Log Receiver] Changes database role from physical standby to cascaded physical standby");
    }

    if (DB_IS_CASCADED_PHYSICAL_STANDBY(db) && (lrcv->peer_role == PEER_PRIMARY)) {
        db->ctrl.core.db_role = REPL_ROLE_PHYSICAL_STANDBY;
        lrcv_trigger_start_lsnd(lrcv);
        GS_LOG_RUN_INF("[Log Receiver] Changes database role from cascaded physical standby to physical standby");
    }

    if (db->status == DB_STATUS_OPEN && db_save_core_ctrl(lrcv->session) != GS_SUCCESS) {
        CM_ABORT(0, "[Log Receiver] ABORT INFO: Save core control file failed when changes database role");
    }
}

static void lrcv_try_save_dbid(lrcv_context_t *lrcv)
{
    database_t *db = &lrcv->session->kernel->db;

    if (db->ctrl.core.is_restored) {
        db->ctrl.core.dbid = lrcv->dbid;
        db_set_ctrl_restored(lrcv->session, GS_FALSE);
    }
}

static status_t lrcv_process_query_status(lrcv_context_t *lrcv, rep_query_status_req_t *req)
{
    database_t *db = &lrcv->session->kernel->db;
    char *buf = lrcv->send_buf.read_buf.aligned_buf;
    rep_msg_header_t *msg_hdr = (rep_msg_header_t *)buf;
    rep_query_status_resp_t *resp = (rep_query_status_resp_t *)(buf + sizeof(rep_msg_header_t));
    status_t status;
    bool32 is_building_cascaded = GS_FALSE;

    lrcv->peer_repl_port = req->repl_port;
    lrcv->peer_role = req->is_standby ? PEER_STANDBY : PEER_PRIMARY;

    if (DB_IS_CASCADED_PHYSICAL_STANDBY(db) && lrcv->role_spec_building) {
        is_building_cascaded = GS_TRUE;
    }

    lrcv->dbid = req->dbid;
    lrcv->primary_curr_point = req->curr_point;
    lrcv->primary_resetlog = req->rst_log;
    lrcv->primary_reset_log_scn = req->reset_log_scn;

    if (db->status != DB_STATUS_OPEN || (is_building_cascaded && lrcv->peer_role == PEER_PRIMARY)) {
        resp->is_ready = GS_FALSE;
    } else {
        if (lrcv_resetlog_check(lrcv, req) == GS_SUCCESS) {
            if (lrcv_prepare_log_files(lrcv, req) == GS_SUCCESS) {
                resp->is_ready = GS_TRUE;
                resp->flush_point = lrcv->flush_point;
                resp->rcy_point = dtc_my_ctrl(lrcv->session)->rcy_point;
                resp->replay_lsn = (uint64)lrcv->session->kernel->lsn;
                lrcv->status = LRCV_PREPARE;
                lrcv->reconnected = GS_TRUE;

                lrcv_try_save_dbid(lrcv);
                lrcv_try_change_db_role(lrcv);
            } else {
                GS_LOG_RUN_ERR("[Log Receiver] Failed to prepare log files");
                resp->is_ready = GS_FALSE;
            }
        } else {
            GS_LOG_RUN_ERR("[Log Receiver] Failed to check reset log");
            return GS_ERROR;
        }
    }

    resp->is_building_cascaded = is_building_cascaded;
    resp->is_building = lrcv->is_building;
    msg_hdr->size = sizeof(rep_msg_header_t) + sizeof(rep_query_status_resp_t);
    msg_hdr->type = REP_QUERY_STATUS_RESP;
    status = cs_write_stream(lrcv->pipe, buf, msg_hdr->size,
                             (int32)cm_atomic_get(&lrcv->session->kernel->attr.repl_pkg_size));
    if (status != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[Log Receiver] failed to send query status response to primary");
    }
    return status;
}

status_t lrcv_buf_alloc(knl_session_t *session, lrcv_context_t *lrcv)
{
    uint32 log_size = (uint32)LOG_LGWR_BUF_SIZE(session); /* LOG_LGWR_BUF_SIZE(session) <= 64M, cannot overflow */
    uint32 buf_size;

    if (lrcv->recv_buf.read_buf.alloc_buf != NULL) {
        return GS_SUCCESS;
    }

    buf_size = log_size + SIZE_K(4);
    if (cm_aligned_malloc((int64)buf_size, "lrcv recv buffer", &lrcv->recv_buf.read_buf) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[Log Receiver] failed to alloc recv buffer with size %u", buf_size);
        return GS_ERROR;
    }
    lrcv->recv_buf.illusion_count = 0;
    lrcv->recv_buf.read_pos = 0;
    lrcv->recv_buf.write_pos = 0;

    lrcv->d_ctx.zstd_dctx = ZSTD_createDCtx();
    lrcv->d_ctx.buf_size = (uint32)LZ4_compressBound((int32)log_size) + SIZE_K(4);
    lrcv->d_ctx.data_size = 0;
    if (cm_aligned_malloc((int64)lrcv->d_ctx.buf_size, "lrcv compressed buffer",
                          &lrcv->d_ctx.compressed_buf) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[Log Receiver] failed to alloc compressed buffer with size %u", lrcv->d_ctx.buf_size);
        cm_aligned_free(&lrcv->recv_buf.read_buf);
        return GS_ERROR;
    }

    buf_size = SIZE_K(64);
    if (cm_aligned_malloc((int64)buf_size, "lrcv send buffer", &lrcv->send_buf.read_buf) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[Log Receiver] failed to alloc send buffer with size %u", buf_size);
        cm_aligned_free(&lrcv->recv_buf.read_buf);
        cm_aligned_free(&lrcv->d_ctx.compressed_buf);
        return GS_ERROR;
    }
    lrcv->send_buf.illusion_count = 0;
    lrcv->send_buf.read_pos = 0;
    lrcv->send_buf.write_pos = 0;

    buf_size = SIZE_M(1);
    if (cm_aligned_malloc((int64)buf_size, "lrcv extend buffer", &lrcv->extend_buf.read_buf) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[Log Receiver] failed to alloc extend buffer with size %u", buf_size);
        cm_aligned_free(&lrcv->recv_buf.read_buf);
        cm_aligned_free(&lrcv->send_buf.read_buf);
        cm_aligned_free(&lrcv->d_ctx.compressed_buf);
        return GS_ERROR;
    }
    lrcv->extend_buf.illusion_count = 0;
    lrcv->extend_buf.read_pos = 0;
    lrcv->extend_buf.write_pos = 0;

    return GS_SUCCESS;
}

static status_t lrcv_process_switch_response(lrcv_context_t *lrcv, rep_switch_resp_t *resp)
{
    switch_ctrl_t *ctrl = &lrcv->session->kernel->switch_ctrl;

    cm_spin_lock(&lrcv->lock, NULL);
    if (lrcv->state != REP_STATE_WAITING_DEMOTE) {
        cm_spin_unlock(&lrcv->lock);
        GS_LOG_RUN_INF("[Log Receiver] ignore switchover response message from primary");
        return GS_SUCCESS;
    }

    if (resp->state != REP_STATE_PROMOTE_APPROVE) {
        lrcv->state = REP_STATE_REJECTED;
        cm_spin_unlock(&lrcv->lock);
        GS_LOG_RUN_INF("[Log Receiver] switchover request is rejected by primary");
        return GS_SUCCESS;
    }

    GS_LOG_RUN_INF("[Log Receiver] received switchover response message from primary");

    cm_spin_lock(&ctrl->lock, NULL);
    ctrl->request = SWITCH_REQ_PROMOTE;
    cm_spin_unlock(&ctrl->lock);

    lrcv->state = REP_STATE_STANDBY_PROMOTING;
    cm_spin_unlock(&lrcv->lock);

    return GS_SUCCESS;
}

static status_t lrcv_process_abr_req(lrcv_context_t *lrcv, rep_abr_req_t *abr_req)
{
    char *buf = lrcv->send_buf.read_buf.aligned_buf;
    rep_msg_header_t *msg_hdr = (rep_msg_header_t *)buf;
    rep_abr_resp_t *abr_resp = (rep_abr_resp_t *)(buf + sizeof(rep_msg_header_t));
    uint32 page_offset = sizeof(rep_msg_header_t) + sizeof(rep_abr_resp_t);
    page_id_t page_id;
    status_t status;
    errno_t err;

    page_id.file = abr_req->file;
    page_id.page = abr_req->page;

    msg_hdr->size = page_offset + abr_req->blk_size;
    msg_hdr->type = REP_ABR_RESP;

    abr_resp->lsnd_id = abr_req->lsnd_id;
    abr_resp->file = abr_req->file;
    abr_resp->page = abr_req->page;

    if (abr_req->blk_size != lrcv->session->kernel->attr.page_size) {
        GS_LOG_RUN_ERR("[Log Receiver] receives invalid ABR message, request page size is %u, default page size is %u",
                       abr_req->blk_size, lrcv->session->kernel->attr.page_size);
        return GS_ERROR;
    }

    if (abr_wait_paral_rcy_compelte(lrcv->session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (buf_read_page(lrcv->session, page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[Log Receiver] ABR standby failed to read page [%u-%u]", page_id.file, page_id.page);
        return GS_ERROR;
    }
    err = memcpy_sp(buf + page_offset, (uint32)lrcv->send_buf.read_buf.buf_size - page_offset, lrcv->session->curr_page,
                    abr_req->blk_size);
    knl_securec_check(err);
    buf_leave_page(lrcv->session, GS_FALSE);

    status = cs_write_stream(lrcv->pipe, buf, msg_hdr->size,
                             (int32)cm_atomic_get(&lrcv->session->kernel->attr.repl_pkg_size));
    GS_LOG_RUN_INF("[Log Receiver] send ABR response to primary for file %u page %u with lsnd id %u status %d",
                   abr_req->file, abr_req->page, abr_req->lsnd_id, status);
    return status;
}

static status_t lrcv_process_message(lrcv_context_t *lrcv)
{
    char *extend_buf = lrcv->extend_buf.read_buf.aligned_buf;

    switch (lrcv->header.type) {
        case REP_BATCH_REQ: {
            /* The remaining batches in the message queue should be discarded */
            if (SECUREC_UNLIKELY(lrcv->wait_info.waiting)) {
                break;
            }

            if (lrcv_process_batch(lrcv) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (SECUREC_UNLIKELY(lrcv->wait_info.waiting)) {
                if (lrcv_send_switch_wait(lrcv) != GS_SUCCESS) {
                    return GS_ERROR;
                }
                break;
            }

            if (lrcv_send_batch_ack(lrcv) != GS_SUCCESS) {
                return GS_ERROR;
            }
            break;
        }

        case REP_QUERY_STATUS_REQ: {
            rep_query_status_req_t *rep_query_status_req = (rep_query_status_req_t *)extend_buf;
            if (lrcv_process_query_status(lrcv, rep_query_status_req) != GS_SUCCESS) {
                return GS_ERROR;
            }
            break;
        }

        case REP_HEART_BEAT_REQ: {
            if (lrcv_process_heart_beat(lrcv->session) != GS_SUCCESS) {
                return GS_ERROR;
            }
            break;
        }

        case REP_SWITCH_RESP: {
            rep_switch_resp_t *switch_resp = (rep_switch_resp_t *)extend_buf;

            if (lrcv_process_switch_response(lrcv, switch_resp) != GS_SUCCESS) {
                return GS_ERROR;
            }
            break;
        }

        case REP_ABR_REQ: {
            rep_abr_req_t *abr_req = (rep_abr_req_t *)extend_buf;

            if (lrcv_process_abr_req(lrcv, abr_req) != GS_SUCCESS) {
                return GS_ERROR;
            }
            break;
        }

        case REP_RECORD_BACKUPSET_RESP: {
            lrcv->task.failed = *(bool32 *)extend_buf;
            if (lrcv->task.failed) {
                lrcv->task.error_no = ERR_RECORD_BACKUP_FAILED;
            }
            lrcv->task.status = BAK_TASK_DONE;
            break;
        }

        default:
            GS_LOG_RUN_ERR("[Log Receiver] invalid replication message type %u", lrcv->header.type);
            return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t lrcv_zstd_decompress(lrcv_context_t *lrcv, const char *buf, uint32 size, uint32 *data_size)
{
    if (lrcv->recv_buf.read_buf.buf_size != GS_MAX_BATCH_SIZE + SIZE_K(4)) {
        uint64 ori_batches_size = ZSTD_getFrameContentSize(buf, size);
        if (ori_batches_size == ZSTD_CONTENTSIZE_ERROR || ori_batches_size == ZSTD_CONTENTSIZE_UNKNOWN) {
            GS_LOG_RUN_ERR("[Log Receiver] failed to decompress(zstd) log batch message");
            return GS_ERROR;
        }
        if (ori_batches_size > lrcv->recv_buf.read_buf.buf_size) {
            if (cm_aligned_realloc((int64)(GS_MAX_BATCH_SIZE + SIZE_K(4)), "lrcv recv buffer",
                                   &lrcv->recv_buf.read_buf) != GS_SUCCESS) {
                CM_ABORT(0, "ABORT INFO: malloc lrcv compressed buffer fail.");
            }
        }
    }

    *data_size = (uint32)ZSTD_decompressDCtx(lrcv->d_ctx.zstd_dctx, lrcv->recv_buf.read_buf.aligned_buf,
                                             (size_t)lrcv->recv_buf.read_buf.buf_size, buf, size);
    if (ZSTD_isError(*data_size)) {
        GS_LOG_RUN_ERR("[Log Receiver] failed to decompress(zstd) log batch message");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t lrcv_lz4_decompress(lrcv_context_t *lrcv, const char *buf, uint32 size, uint32 *data_size)
{
    int result = LZ4_decompress_safe(buf, lrcv->recv_buf.read_buf.aligned_buf, (int32)size,
                                     (int32)lrcv->recv_buf.read_buf.buf_size);
    if (result <= 0) {
        if (lrcv->recv_buf.read_buf.buf_size != GS_MAX_BATCH_SIZE + SIZE_K(4)) {
            if (cm_aligned_realloc((int64)(GS_MAX_BATCH_SIZE + SIZE_K(4)), "lrcv recv buffer",
                                   &lrcv->recv_buf.read_buf) != GS_SUCCESS) {
                CM_ABORT(0, "ABORT INFO: malloc lrcv compressed buffer fail.");
            }
            result = LZ4_decompress_safe(buf, lrcv->recv_buf.read_buf.aligned_buf, (int32)size,
                                         (int32)lrcv->recv_buf.read_buf.buf_size);
            if (result < 0) {
                GS_LOG_RUN_ERR("[Log Receiver] failed to decompress(lz4) log batch message");
                return GS_ERROR;
            }
        } else {
            GS_LOG_RUN_ERR("[Log Receiver] failed to decompress(lz4) log batch message");
            return GS_ERROR;
        }
    }
    *data_size = (uint32)result;
    return GS_SUCCESS;
}

static status_t lrcv_compress_receive(lrcv_context_t *lrcv, rep_batch_req_t *req, uint32 remain_size, int32 *recv_size)
{
    uint32 batches_size = 0;
    if (cs_read_stream(lrcv->pipe, lrcv->d_ctx.compressed_buf.aligned_buf, REPL_RECV_TIMEOUT, remain_size,
                       recv_size) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[Log Receiver] failed to receive log batch message from primary with size %u", remain_size);
        return GS_ERROR;
    }
    if ((uint32)*recv_size != remain_size) {
        GS_LOG_RUN_ERR("[Log Receiver] failed to receive log batch message from primary with size %u, %u received",
                       remain_size, *recv_size);
        return GS_ERROR;
    }

    switch (req->compress_alg) {
        case COMPRESS_ZSTD:
            if (lrcv_zstd_decompress(lrcv, lrcv->d_ctx.compressed_buf.aligned_buf, (uint32)*recv_size,
                &batches_size) != GS_SUCCESS) {
                return GS_ERROR;
            }
            break;
        case COMPRESS_LZ4:
            if (lrcv_lz4_decompress(lrcv, lrcv->d_ctx.compressed_buf.aligned_buf, (uint32)*recv_size,
                &batches_size) != GS_SUCCESS) {
                return GS_ERROR;
            }
            break;
        default:
            break;
    }

    lrcv->header.size = sizeof(rep_msg_header_t) + sizeof(rep_batch_req_t) + batches_size;
    return GS_SUCCESS;
}

static status_t lrcv_receive(lrcv_context_t *lrcv, uint32 timeout, int32 *recv_size)
{
    rep_batch_req_t *rep_batch_req = NULL;
    uint32 remain_size;
    uint32 new_compress_buf_size = 0;
    uint32 new_buf_size;

    if (cs_read_stream(lrcv->pipe, (char *)&lrcv->header, timeout, sizeof(rep_msg_header_t), recv_size) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[Log Receiver] failed to receive message from primary");
        return GS_ERROR;
    }

    if (*recv_size == 0) {
        return GS_SUCCESS;
    }

    if (lrcv->header.size < (uint32)*recv_size) {
        GS_LOG_RUN_ERR("[Log Receiver] invalid head size %u received, which is smaller than %u", lrcv->header.size,
            (uint32)*recv_size);
        return GS_ERROR;
    }

    remain_size = lrcv->header.size - (uint32)*recv_size;

    if (lrcv->header.type == REP_BATCH_REQ) {
        // For batch message, batch should be 4K aligned in recv_buf
        if (cs_read_stream(lrcv->pipe, lrcv->extend_buf.read_buf.aligned_buf, REPL_RECV_TIMEOUT,
                           sizeof(rep_batch_req_t), recv_size) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[Log Receiver] failed to receive rep_batch_req_t message from primary with size %u",
                           (uint32)sizeof(rep_batch_req_t));
            return GS_ERROR;
        }
        if (*recv_size != sizeof(rep_batch_req_t)) {
            GS_LOG_RUN_ERR("[Log Receiver] failed to receive rep_batch_req_t message from "
                           "primary with size %u, %u received",
                           (uint32)sizeof(rep_batch_req_t), *recv_size);
            return GS_ERROR;
        }
        rep_batch_req = (rep_batch_req_t *)lrcv->extend_buf.read_buf.aligned_buf;
        if (remain_size <= (uint32)*recv_size) {
            GS_LOG_RUN_ERR("[Log Receiver] invalid head size %u received, which is smaller than %u", lrcv->header.size,
                lrcv->header.size - remain_size + (uint32)*recv_size);
                return GS_ERROR;
        }
        remain_size -= (uint32)*recv_size;

        if (rep_batch_req->compress_alg == COMPRESS_NONE) {
            if (lrcv->header.size > lrcv->recv_buf.read_buf.buf_size) {
                new_buf_size = GS_MAX_BATCH_SIZE + SIZE_K(8);
                if (cm_aligned_realloc((int64)new_buf_size, "lrcv recv buffer",
                                       &lrcv->recv_buf.read_buf) != GS_SUCCESS) {
                    CM_ABORT(0, "[Log Receiver] failed to alloc recv buffer with size %u", new_buf_size);
                }
            }
            if (remain_size > lrcv->recv_buf.read_buf.buf_size) {
                GS_LOG_RUN_ERR("[Log Receiver] the remain data size %u exceeds the receive buffer size %u",
                               remain_size, (uint32)lrcv->extend_buf.read_buf.buf_size);
                return GS_ERROR;
            }
            // Now we are truly receiving the log batch
            if (cs_read_stream(lrcv->pipe, lrcv->recv_buf.read_buf.aligned_buf, REPL_RECV_TIMEOUT, remain_size,
                               recv_size) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[Log Receiver] failed to receive log batch message from primary with size %u",
                               remain_size);
                return GS_ERROR;
            }
            if ((uint32)*recv_size != remain_size) {
                GS_LOG_RUN_ERR("[Log Receiver] failed to receive log batch message from primary "
                               "with size %u, %u received",
                               remain_size, *recv_size);
                return GS_ERROR;
            }
        } else {
            if (lrcv->header.size > lrcv->d_ctx.compressed_buf.buf_size) {
                if (rep_batch_req->compress_alg == COMPRESS_ZSTD) {
                    new_compress_buf_size = (uint32)ZSTD_compressBound(GS_MAX_BATCH_SIZE) + SIZE_K(4);
                } else if (rep_batch_req->compress_alg == COMPRESS_LZ4) {
                    new_compress_buf_size = (uint32)LZ4_compressBound((int32)GS_MAX_BATCH_SIZE) + SIZE_K(4);
                } else {
                    GS_LOG_RUN_ERR("[Log Receiver] unsupported compress algorithm.");
                    return GS_ERROR;
                }
                if (cm_aligned_realloc((int64)new_compress_buf_size, "lrcv compressed buffer",
                                       &lrcv->d_ctx.compressed_buf) != GS_SUCCESS) {
                    CM_ABORT(0, "ABORT INFO: malloc lrcv compress buffer fail.");
                }
                lrcv->d_ctx.compressed_buf.buf_size = new_compress_buf_size;
            }
            if (lrcv_compress_receive(lrcv, rep_batch_req, remain_size, recv_size) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    } else {
        if (remain_size > 0) {
            if (remain_size > lrcv->extend_buf.read_buf.buf_size) {
                GS_LOG_RUN_ERR("[Log Receiver] the remain data size %u exceeds the receive buffer size %u",
                               remain_size, (uint32)lrcv->extend_buf.read_buf.buf_size);
                return GS_ERROR;
            }
            if (cs_read_stream(lrcv->pipe, lrcv->extend_buf.read_buf.aligned_buf, REPL_RECV_TIMEOUT, remain_size,
                               recv_size) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[Log Receiver] failed to receive message %u from primary with size %u",
                               lrcv->header.type, remain_size);
                return GS_ERROR;
            }
            if ((uint32)*recv_size != remain_size) {
                GS_LOG_RUN_ERR("[Log Receiver] failed to receive message %u from primary with size %u, %u received",
                               lrcv->header.type, remain_size, *recv_size);
                return GS_ERROR;
            }
        }
    }

    (*recv_size) = lrcv->header.size;

    if (!lrcv_rcv_msg_is_valid(lrcv)) {
        GS_LOG_RUN_ERR("[Log Receiver] invalid message %u received", lrcv->header.type);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t lrcv_send_switch_request(lrcv_context_t *lrcv)
{
    char *buf = lrcv->send_buf.read_buf.aligned_buf;
    rep_msg_header_t *rep_msg_header = (rep_msg_header_t *)buf;

    rep_msg_header->size = sizeof(rep_msg_header_t);
    rep_msg_header->type = REP_SWITCH_REQ;

    if (cs_write_stream(lrcv->pipe, buf, rep_msg_header->size,
                        (int32)cm_atomic_get(&lrcv->session->kernel->attr.repl_pkg_size)) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[Log Receiver] failed to send switchover request message to primary");
        return GS_ERROR;
    }

    lrcv->state = REP_STATE_WAITING_DEMOTE;

    GS_LOG_RUN_INF("[Log Receiver] send switchover request to primary");

    return GS_SUCCESS;
}

static status_t lrcv_send_record_backupset(lrcv_context_t *lrcv)
{
    bak_context_t *bak_ctx = &lrcv->session->kernel->backup_ctx;
    bak_record_t *record = &bak_ctx->bak.record;
    rep_msg_header_t rep_msg_header;

    rep_msg_header.size = sizeof(rep_msg_header_t) + sizeof(bak_record_t);
    rep_msg_header.type = REP_RECORD_BACKUPSET_REQ;

    if (cs_write_stream(lrcv->pipe, (char *)&rep_msg_header, sizeof(rep_msg_header_t),
                        (int32)cm_atomic_get(&lrcv->session->kernel->attr.repl_pkg_size)) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[Log Receiver] failed to send record backupset request message to primary");
        return GS_ERROR;
    }

    if (cs_write_stream(lrcv->pipe, (char *)record, sizeof(bak_record_t),
                        (int32)cm_atomic_get(&lrcv->session->kernel->attr.repl_pkg_size)) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[Log Receiver] failed to send backupset record data to standby");
        return GS_ERROR;
    }

    GS_LOG_RUN_INF("[Log Receiver] send record backupset request to primary");

    return GS_SUCCESS;
}

static void lrcv_process_backup_req(lrcv_context_t *lrcv)
{
    rep_bak_task_t *task = &lrcv->task;

    if (task->status != BAK_TASK_WAIT_PROCESS) {
        return;
    }

    if (lrcv_send_record_backupset(lrcv) != GS_SUCCESS) {
        task->status = BAK_TASK_DONE;
        task->failed = GS_TRUE;
        task->error_no = ERR_SEND_RECORD_REQ_FAILED;
    } else {
        task->status = BAK_TASK_WAIT_RESPONSE;
    }
}

static status_t lrcv_process_req(lrcv_context_t *lrcv)
{
    if (lrcv->state == REP_STATE_DEMOTE_REQUEST) {
        return lrcv_send_switch_request(lrcv);
    }

    lrcv_process_backup_req(lrcv);

    if (lrcv_process_switch_wait(lrcv) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t lrcv_process_msg_loop(lrcv_context_t *lrcv)
{
    int32 recv_size;

    do {
        if (lrcv_process_message(lrcv) != GS_SUCCESS) {
            return GS_ERROR;
        }
    
        if (lrcv_process_req(lrcv) != GS_SUCCESS) {
            return GS_ERROR;
        }
    
        if (lrcv_receive(lrcv, 0, &recv_size) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } while (recv_size > 0);

    return GS_SUCCESS;
}

static inline void lrcv_try_set_repl_port(lrcv_context_t *lrcv, int32 recv_size)
{
    if (recv_size == 0) {
        return;
    }

    if (lrcv->header.type == REP_QUERY_STATUS_REQ) {
        rep_query_status_req_t *req = (rep_query_status_req_t *)lrcv->extend_buf.read_buf.aligned_buf;
        lrcv->peer_repl_port = req->repl_port;
    }
}

status_t lrcv_proc(lrcv_context_t *lrcv)
{
    thread_t *thread = &lrcv->thread;
    int32 recv_size;
    uint32 recv_retry_cnt = 0;

    cm_set_thread_name("log_receiver");
    GS_LOG_RUN_INF("log receiver thread started");

    while (!thread->closed) {
        if (lrcv_need_exit(lrcv)) {
            lrcv_set_conn_err(lrcv);
            return GS_ERROR;
        }

        if (lrcv_process_req(lrcv) != GS_SUCCESS) {
            lrcv_set_conn_err(lrcv);
            return GS_ERROR;
        }

        if (lrcv_receive(lrcv, LRCV_RECV_INTERVAL, &recv_size) != GS_SUCCESS) {
            lrcv_set_conn_err(lrcv);
            return GS_ERROR;
        }

        if (lrcv_need_suspend(lrcv)) {
            lrcv_try_set_repl_port(lrcv, recv_size);
            cm_sleep(SUSPEND_INTERVAL);
            continue;
        }

        if (recv_size > 0) {
            recv_retry_cnt = 0;
            if (lrcv_process_msg_loop(lrcv) != GS_SUCCESS) {
                lrcv_set_conn_err(lrcv);
                return GS_ERROR;
            }
        } else {
            if ((lrcv->status == LRCV_PREPARE || lrcv->status == LRCV_READY) &&
                (recv_retry_cnt++ > lrcv->timeout * MILLISECS_PER_SECOND / LRCV_RECV_INTERVAL)) {
                GS_LOG_RUN_INF("[Log Receiver] lrcv has not received message more than %us, primary is down probably",
                               lrcv->timeout);
                lrcv_set_conn_err(lrcv);
                return GS_ERROR;
            }
        }
    }

    lrcv_set_conn_err(lrcv);
    GS_LOG_RUN_INF("log receiver thread closed");
    return GS_SUCCESS;
}

void lrcv_close(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    lrcv_context_t *lrcv = &kernel->lrcv_ctx;

    lrcv_reset_primary_host(session);
    lrcv->thread.closed = GS_TRUE;
    while (LRCV_IS_RUNING(lrcv) && lrcv->thread.closed) {
        cm_sleep(10);
    }
}

static status_t lrcv_get_primary_host(knl_session_t *session, int32 retry_count_input, char *host, uint32 host_buf_size)
{
    int32 retry_count = retry_count_input;
    lrcv_context_t *lrcv = NULL;
    errno_t ret;

    while (session->kernel->lrcv_ctx.pipe == NULL) {
        if (retry_count == 0) {
            GS_LOG_RUN_ERR("[Log Receiver] abort wait connection ready during to exceeded max retries");
            GS_THROW_ERROR(ERR_PRI_NOT_CONNECT, "primary info");
            return GS_ERROR;
        }

        if (knl_failover_triggered(session->kernel)) {
            GS_LOG_RUN_ERR("[Log Receiver] abort wait connection ready during to force promote");
            return GS_ERROR;
        }

        if (session->kernel->lrpl_ctx.thread.closed) {
            GS_LOG_RUN_ERR("[Log Receiver] abort wait connection ready during to lrpl closed");
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            return GS_ERROR;
        }
        cm_sleep(5);

        if (retry_count > 0) {
            retry_count--;
        }
    }

    lrcv = &session->kernel->lrcv_ctx;
    ret = strncpy_s(host, host_buf_size, lrcv->primary_host, GS_HOST_NAME_BUFFER_SIZE - 1);

    knl_securec_check(ret);
    return GS_SUCCESS;
}

status_t lrcv_get_primary_server(knl_session_t *session, int32 retry_count,
    char *host, uint32 host_buf_size, uint16 *port)
{
    lrcv_context_t *lrcv = &session->kernel->lrcv_ctx;

    if (lrcv_get_primary_host(session, retry_count, host, host_buf_size) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (port == NULL) {
        return GS_SUCCESS;
    }

    *port = lrcv->peer_repl_port;
    if (*port == 0) {
        GS_THROW_ERROR(ERR_INVALID_REPL_PORT);
        GS_LOG_RUN_ERR("[Log Receiver] peer repl port is 0, it may be that the REPL_PORT parameter "
                       "of the peer node is not set, or it has been disconnected from the peer node");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

bool32 lrcv_switchover_enabled(knl_session_t *session)
{
    char pri_host[GS_HOST_NAME_BUFFER_SIZE];
    uint16 pri_port;
    knl_attr_t *attr = &session->kernel->attr;
    arch_attr_t *arch_attr = NULL;

    if (lrcv_get_primary_server(session, 0, pri_host, GS_HOST_NAME_BUFFER_SIZE, &pri_port) != GS_SUCCESS) {
        return GS_FALSE;
    }

    for (uint32 i = 1; i < GS_MAX_ARCH_DEST; i++) {
        arch_attr = &attr->arch_attr[i];

        if (strcmp(pri_host, arch_attr->service.host) == 0 && pri_port == arch_attr->service.port &&
            arch_attr->enable && arch_attr->role_valid != VALID_FOR_STANDBY_ROLE) {
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

void lrcv_trigger_backup_task(knl_session_t *session)
{
    lrcv_context_t *lrcv = &session->kernel->lrcv_ctx;
    rep_bak_task_t *task = &lrcv->task;

    CM_ASSERT(task->status == BAK_TASK_DONE);

    if (LRCV_IS_RUNING(lrcv)) {
        task->failed = GS_FALSE;
        task->status = BAK_TASK_WAIT_PROCESS;
    } else {
        task->failed = GS_TRUE;
        task->error_no = ERR_SEND_RECORD_REQ_FAILED;
    }
}

status_t lrcv_wait_task_process(knl_session_t *session)
{
    lrcv_context_t *lrcv = &session->kernel->lrcv_ctx;
    rep_bak_task_t *task = &lrcv->task;

    while (task->status != BAK_TASK_DONE) {
        if (session->canceled) {
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            return GS_ERROR;
        }

        if (session->killed) {
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            return GS_ERROR;
        }

        cm_sleep(100);
    }

    if (task->failed) {
        GS_THROW_ERROR(task->error_no);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void lrcv_wait_status_prepared(knl_session_t *session)
{
    lrcv_context_t *lrcv = &session->kernel->lrcv_ctx;

    while (lrcv->status < LRCV_PREPARE) {
        if (lrcv->session == NULL || lrcv->session->killed) {
            return;
        }

        cm_sleep(100);
    }
}

void lrcv_clear_needrepair_for_failover(knl_session_t *session)
{
    session->kernel->lrcv_ctx.status = LRCV_DISCONNECTED;
    session->kernel->lftc_client_ctx.arch_lost = GS_FALSE;
    session->kernel->rcy_ctx.log_decrypt_failed = GS_FALSE;
}
