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
 * repl_raft.c
 *
 *
 * IDENTIFICATION
 * src/kernel/replication/repl_raft.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_replication_module.h"
#include "repl_raft.h"
#include "knl_recovery.h"
#include "knl_context.h"
#include "dtc_dls.h"
#include "dtc_database.h"

knl_session_t *g_raft_session = NULL;

void raft_pending_switch_request(knl_session_t *session, switch_ctrl_t *ctrl)
{
    cm_spin_lock(&ctrl->lock, NULL);
    ctrl->request = SWITCH_REQ_RAFT_PROMOTE_PENDING;
    ctrl->state = SWITCH_IDLE;
    ctrl->keep_sid = session->id;
    ctrl->handling = CT_FALSE;
    cm_spin_unlock(&ctrl->lock);
}

unsigned long long raft_getappliedindex_cb(void)
{
    static uint64 prev_lfn = CT_INVALID_ID64;
    static uint64 prev_raft_idx = CT_INVALID_ID64;
    raft_context_t *ctx = &g_raft_session->kernel->raft_ctx;

    CT_LOG_DEBUG_INF("RAFT: get appliedindex raft saved raft flush point lfn=%lld, saved raft flush point index=%lld\n",
                     (uint64)ctx->saved_raft_flush_point.lfn, ctx->saved_raft_flush_point.raft_index);

    knl_panic((prev_lfn == CT_INVALID_ID64 && prev_raft_idx == CT_INVALID_ID64) ||
              (prev_lfn <= ctx->saved_raft_flush_point.lfn && prev_raft_idx <= ctx->saved_raft_flush_point.raft_index));

    prev_lfn = ctx->saved_raft_flush_point.lfn;
    prev_raft_idx = ctx->saved_raft_flush_point.raft_index;

    return ctx->saved_raft_flush_point.raft_index;
}

static status_t db_notify_failover_promote_for_raft(knl_session_t *session)
{
    switch_ctrl_t *ctrl = &session->kernel->switch_ctrl;

    cm_spin_lock(&ctrl->lock, NULL);

    if (ctrl->request == SWITCH_REQ_NONE) {
        ctrl->request = SWITCH_REQ_RAFT_PROMOTE_PENDING;
        ctrl->state = SWITCH_IDLE;
        ctrl->keep_sid = 0;
        ctrl->handling = CT_FALSE;
    }

    if (ctrl->request != SWITCH_REQ_RAFT_PROMOTE_PENDING) {
        cm_spin_unlock(&ctrl->lock);
        CT_LOG_RUN_INF("RAFT: invalid switch request, server is handling another switch request");
        CT_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "server is handling another switch request");
        return CT_ERROR;
    }

    ctrl->request = SWITCH_REQ_RAFT_PROMOTE;

    cm_spin_unlock(&ctrl->lock);

    CT_LOG_RUN_INF("[DB] notify server to do failover");

    return CT_SUCCESS;
}

void raft_promote_cb(long long errCode)
{
    status_t status;
    raft_context_t *raft_ctx = &g_raft_session->kernel->raft_ctx;

    CT_LOG_RUN_WAR("RAFT: promote cb start to promote leader: errCode=%lld\n", errCode);

    /* make sure local disk has all redo logs */
    raft_wait_for_log_flush(g_raft_session, raft_ctx->commit_lfn);

    knl_panic(raft_ctx->logwr_async_buf_write_pos == raft_ctx->logwr_async_buf_flush_pos);
    raft_reset_async_buffer(raft_ctx);

    status = db_notify_failover_promote_for_raft(g_raft_session);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_WAR("RAFT: promote cb fail to do failover.");
    } else {
        CT_LOG_RUN_WAR("RAFT: promote cb failover successfully.");
    }
}

void raft_demote_cb(long long errCode)
{
    CM_ABORT(0, "[RAFT] ABORT INFO: demote to follower, shutdown DB, and wait for CM to restart it, errCode=%lld\n",
             errCode);
}

static status_t raft_batch_verify_checksum(log_batch_t *batch, uint32 len)
{
    log_batch_tail_t *tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));

    if (batch->space_size != len) {
        CT_LOG_RUN_ERR("[RAFT] invalid received size for batch ,lfn :%llu", (uint64)batch->head.point.lfn);
        return CT_ERROR;
    }

    if (!rcy_validate_batch(batch, tail)) {
        CT_LOG_RUN_ERR("[RAFT] invalid received batch ,lfn :%llu", (uint64)batch->head.point.lfn);
        return CT_ERROR;
    }

    if (rcy_verify_checksum(g_raft_session, batch) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void raft_get_lfn_scn_cb(char *buf, uint32 len, uint64 *lfn, uint64 *scn)
{
    raft_context_t *raft_ctx = &g_raft_session->kernel->raft_ctx;

    *lfn = 0;
    *scn = 0;

    if (raft_ctx->status == RAFT_STATUS_CLOSING) {
        return;
    }

    if (!DB_IS_PRIMARY(&g_raft_session->kernel->db)) {
        return;
    }

    if (buf == NULL) {
        *lfn = raft_ctx->raft_flush_point.lfn;
        *scn = raft_ctx->raft_flush_point.scn;
        return;
    }

    log_batch_t *batch = (log_batch_t *)buf;
    batch->raft_index = 0;
    if (raft_batch_verify_checksum(batch, len) != CT_SUCCESS) {
        return;
    }
    *lfn = batch->head.point.lfn;
    *scn = batch->scn;
}

// 0: invalid leader node id
uint64  raft_get_primary_id(knl_session_t *session)
{
    status_t status;
    char *start_ptr = NULL;
    char *end_ptr = NULL;
    char *query_info = NULL;
    uint64 leader_node_id = 0;
    uint32 leader_id_index = 3;
    uint32 pos;

    status = knl_raft_query_info(session, "cluster", &query_info);
    if (status != CT_SUCCESS) {
        return leader_node_id;
    }

    if (query_info == NULL) {
        return leader_node_id;
    }

    pos = 0;
    start_ptr = query_info;
    end_ptr = strstr(query_info, ";");
    while (pos != leader_id_index && end_ptr != NULL) {
        start_ptr = end_ptr + 1;
        end_ptr = strstr(start_ptr, ";");
        pos++;
    }

    if (start_ptr == NULL || end_ptr == NULL) {
        free(query_info);
        return leader_node_id;
    }

    leader_node_id = strtoull(start_ptr, &end_ptr, 10);  /* 10 for decimal */

    free(query_info);
    return leader_node_id;
}

bool32 raft_is_primary_alive(knl_session_t *session)
{
    return raft_get_primary_id(session) != 0;
}

void raft_printfunc(int level, char *raft_log, int len)
{
    CT_LOG_RAFT(level, "%s, len=%d", raft_log, len);
}

void raft_log_flush_async_head(raft_context_t *raft_ctx, log_file_t *file)
{
    errno_t err;
    uint32 block_size = CM_CALC_ALIGN(file->ctrl->block_size, sizeof(log_file_head_t));
    knl_panic(block_size <= raft_ctx->logwr_head_buf_size);

    err = memset_sp(raft_ctx->logwr_head_buf, raft_ctx->logwr_head_buf_size, 0, block_size);
    knl_securec_check(err);
    err = memcpy_sp(raft_ctx->logwr_head_buf, raft_ctx->logwr_head_buf_size, &file->head, sizeof(log_file_head_t));
    knl_securec_check(err);

    if (cm_write_device(file->ctrl->type, file->handle, 0, raft_ctx->logwr_head_buf, block_size) != CT_SUCCESS) {
        CM_ABORT(0, "[RAFT] ABORT INFO: flush redo file:%s, offset:%u, size:%lu failed.", file->ctrl->name, 0,
                 sizeof(log_file_head_t));
    }
}

void raft_log_flush_init(knl_session_t *session, log_batch_t *batch)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    raft_context_t *raft_ctx = &session->kernel->raft_ctx;
    log_file_t       *file = redo_ctx->files + redo_ctx->curr_file;
    uint32            next;

    knl_panic(batch->head.point.asn == file->head.asn || batch->head.point.asn == file->head.asn + 1);
    if (file->head.asn != batch->head.point.asn) {
        knl_panic(!DB_IS_PRIMARY(&session->kernel->db));
        log_flush_head(session, file);

        log_get_next_file(session, &next, CT_TRUE);
        while (next == redo_ctx->active_file) {
            cm_spin_unlock(&raft_ctx->raft_write_disk_lock);
            ckpt_trigger(session, CT_FALSE, CKPT_TRIGGER_INC);
            CT_LOG_RUN_WAR("RAFT: log free size not enough in raft log flush init, wait for ckpt.");
            cm_sleep(100);
            cm_spin_lock(&raft_ctx->raft_write_disk_lock, NULL);
            log_get_next_file(session, &next, CT_TRUE);
        }

        (void)log_switch_file(session);
        knl_panic(redo_ctx->files[redo_ctx->curr_file].head.asn == batch->head.point.asn);
        redo_ctx->stat.space_requests++;
        CT_LOG_DEBUG_INF("RAFT: log flush init switch log file.");
    }

    file = &redo_ctx->files[redo_ctx->curr_file];
    knl_panic((uint64)file->ctrl->size >= batch->space_size + batch->head.point.block_id * file->ctrl->block_size);
}

void log_flush_init_for_raft(knl_session_t *session, uint32 batch_size)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    log_file_t *file = ctx->files + ctx->curr_file;

    if (log_file_freesize(file) < batch_size) {
        raft_context_t *raft_ctx = &session->kernel->raft_ctx;
        uint32 asn = file->head.asn;

        CT_LOG_DEBUG_INF("RAFT: log flush init for raft, flush buffer before switch logfile: "
            "flush pos=%d, raft pos=%d, write pos= %d\n",
            raft_ctx->logwr_async_buf_flush_pos, raft_ctx->logwr_async_buf_raft_pos,
            raft_ctx->logwr_async_buf_write_pos);

        raft_wait_for_log_flush(session, raft_ctx->sent_lfn);
        log_flush_head(session, file);
        (void)log_switch_file(session);
        ctx->stat.space_requests++;
        file = ctx->files + ctx->curr_file;
        knl_panic(asn + 1 == file->head.asn);
    }

    file = ctx->files + ctx->curr_file;
    knl_panic(log_file_freesize(file) >= batch_size);
}

status_t raft_check_log_size(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    log_context_t *ctx = &kernel->redo_ctx;
    log_file_t *file = NULL;

    ctx->logfile_hwm = MY_LOGFILE_SET(session)->logfile_hwm;
    ctx->files = MY_LOGFILE_SET(session)->items;
    int64 size = ctx->files[0].ctrl->size;
    for (uint32 i = 0; i < ctx->logfile_hwm; i++) {
        file = &ctx->files[i];
        if (LOG_IS_DROPPED(file->ctrl->flg)) {
            continue;
        }
        if (file->ctrl->size != size) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t raft_load(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    raft_context_t *raft_ctx = NULL;

    if (!DB_IS_RAFT_ENABLED(kernel)) {
        return CT_SUCCESS;
    }

    raft_ctx = &kernel->raft_ctx;
    raft_ctx->status = RAFT_STATUS_STARTING;

    // check if block size of all logs are the same before log_load
    if (raft_check_log_size(session) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_LOG_SIZE_NOT_MATCH);
        return CT_ERROR;
    }

    if (log_check_blocksize(session) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_LOG_BLOCK_NOT_MATCH);
        return CT_ERROR;
    }

    if (log_check_minsize(session) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_LOG_FILE_SIZE_TOO_SMALL, (int64)LOG_MIN_SIZE(session, kernel));
        return CT_ERROR;
    }

    if (RAFT_IS_RESTORE_PRIMARY(kernel)) {
        kernel->db.ctrl.core.raft_flush_point.raft_index = RAFT_DEFAULT_INDEX;
        kernel->db.ctrl.core.raft_flush_point.scn = CT_INVALID_ID64;
        kernel->db.ctrl.core.raft_flush_point.lfn = dtc_my_ctrl(session)->lrp_point.lfn;
        if (db_save_core_ctrl(session) != CT_SUCCESS) {
            CM_ABORT(0, "[DB] ABORT INFO: save core control file failed reset lrp raft index.");
        }
    }

    raft_ctx->log_block_size = kernel->redo_ctx.files[0].ctrl->block_size;
    raft_ctx->raft_flush_point = kernel->db.ctrl.core.raft_flush_point;
    raft_ctx->raft_recv_point = kernel->db.ctrl.core.raft_flush_point;
    raft_ctx->saved_raft_flush_point = kernel->db.ctrl.core.raft_flush_point;

    raft_ctx->old_role = kernel->db.ctrl.core.db_role;
    return CT_SUCCESS;
}

void raft_sendlog_cb(char *buf, int buf_len, unsigned long long lsn, unsigned long long raft_index,
                     long long errorCode)
{
    log_context_t *redo_ctx = &g_raft_session->kernel->redo_ctx;
    raft_context_t *raft_ctx = &g_raft_session->kernel->raft_ctx;
    log_batch_t *batch_log = NULL;
    log_batch_t *new_batch = NULL;
    log_batch_tail_t *tail = NULL;

    // don't receive log when db is closing.
    if (raft_ctx->status == RAFT_STATUS_CLOSING) {
        return;
    }

    batch_log = (log_batch_t *)buf;
    tail = (log_batch_tail_t *)((char *)batch_log + batch_log->size - sizeof(log_batch_tail_t));

    CT_LOG_DEBUG_INF("RAFT: sendlog cb: lsn=%lld, raft_index=%lld, batch len= %d, batch log size=%d, "
                     "batch log space size=%d, batch head lfn=%lld,"
                     "batch tail lfn=%lld, curr_point lfn=%lld, recv_point lfn =%lld, flush_point lfn=%lld\n",
                     lsn, raft_index, buf_len, batch_log->size, batch_log->space_size,
                     (uint64)batch_log->head.point.lfn, (uint64)tail->point.lfn, (uint64)redo_ctx->curr_point.lfn,
                     (uint64)raft_ctx->recv_point.lfn, (uint64)raft_ctx->flush_point.lfn);

    knl_panic(!DB_IS_PRIMARY(&g_raft_session->kernel->db) || g_raft_session->kernel->db.status != DB_STATUS_OPEN);
    knl_panic(lsn == batch_log->head.point.lfn);
    knl_panic(batch_log->head.magic_num == LOG_MAGIC_NUMBER);
    knl_panic(tail->magic_num == LOG_MAGIC_NUMBER);
    knl_panic(batch_log->head.point.lfn == tail->point.lfn);
    knl_panic(raft_ctx->recv_point.lfn >= raft_ctx->flush_point.lfn);
    knl_panic(raft_ctx->raft_recv_point.raft_index >= raft_ctx->raft_flush_point.raft_index);

    if (batch_log->head.point.lfn <= raft_ctx->recv_point.lfn) {
        CT_LOG_RUN_WAR("RAFT: sendlog cb, ignore duplicated batch: lsn=%lld, raft_index=%lld, batch len= %d, "
                       "batch lfn=%lld, recv point=%lld, flush_point=%lld\n",
                       lsn, raft_index, buf_len, (uint64)batch_log->head.point.lfn,
                       (uint64)raft_ctx->recv_point.lfn, (uint64)raft_ctx->flush_point.lfn);
        return;
    }

    if (batch_log->head.point.lfn != raft_ctx->recv_point.lfn + 1) {
        CM_ABORT(0, "[RAFT] ABORT INFO: sendlog cb: log lost,  lsn=%llu, raft_index=%llu, buf_len= %d, "
                 "batch lfn=%llu, recv point=%llu, flush_point=%llu\n",
                 lsn, raft_index, buf_len, (uint64)batch_log->head.point.lfn, (uint64)raft_ctx->recv_point.lfn,
                 (uint64)raft_ctx->flush_point.lfn);
    }

    // for raft batch, two message may have same raft raft_index
    if (raft_index < raft_ctx->raft_recv_point.raft_index) {
        CM_ABORT(0, "[RAFT] ABORT INFO: sendlog cb: raft not in order,  lsn=%llu, raft_index=%llu, buf_len= %d, "
                 "batch lfn=%llu, recv point lfn=%llu, recv point raft_index=%llu, "
                 "flush_point lfn=%llu, flush_point raft_index=%llu\n",
                 lsn, raft_index, buf_len, (uint64)batch_log->head.point.lfn, (uint64)raft_ctx->recv_point.lfn,
                 (uint64)raft_ctx->raft_recv_point.raft_index, (uint64)raft_ctx->flush_point.lfn,
                 (uint64)raft_ctx->raft_flush_point.raft_index);
    }

    batch_log->raft_index = raft_index;

    // copy batch to async write list
    CT_LOG_DEBUG_INF("RAFT: sendlog cb1: flush pos=%d, raft pos=%d, write pos= %d,"
                     "batch lfn=%lld, batch raft_index=%lld\n",
                     raft_ctx->logwr_async_buf_flush_pos, raft_ctx->logwr_async_buf_raft_pos,
                     raft_ctx->logwr_async_buf_write_pos, (uint64)batch_log->head.point.lfn, batch_log->raft_index);

    if (raft_write_to_async_buffer_num(g_raft_session, batch_log, &new_batch) != CT_SUCCESS) {
        return;
    }

    cm_spin_lock(&raft_ctx->raft_lock, NULL);
    raft_ctx->logwr_async_buf_raft_pos = raft_ctx->logwr_async_buf_write_pos;
    raft_ctx->recv_point.rst_id = batch_log->head.point.rst_id;
    raft_ctx->recv_point.asn = batch_log->head.point.asn;
    raft_ctx->recv_point.block_id = batch_log->head.point.block_id + batch_log->space_size / raft_ctx->log_block_size;
    raft_ctx->recv_point.lfn = new_batch->head.point.lfn;
    raft_ctx->raft_recv_point.lfn = new_batch->head.point.lfn;
    raft_ctx->raft_recv_point.raft_index = raft_index;

    raft_ctx->sent_lfn = new_batch->head.point.lfn;
    raft_ctx->commit_lfn = new_batch->head.point.lfn;

    CT_LOG_DEBUG_INF("RAFT: sendlog cb3: flush pos=%d, raft pos=%d, write pos= %d, "
                     "batch lfn=%lld, batch raft_index=%lld\n",
                     raft_ctx->logwr_async_buf_flush_pos, raft_ctx->logwr_async_buf_raft_pos,
                     raft_ctx->logwr_async_buf_write_pos, (uint64)new_batch->head.point.lfn, new_batch->raft_index);

    cm_spin_unlock(&raft_ctx->raft_lock);

    (void)cm_release_cond(&raft_ctx->cond);
}

static void raft_set_gbp_trunc_point(raft_context_t *raft_ctx)
{
    knl_session_t *session = g_raft_session->kernel->sessions[SESSION_ID_KERNEL];
    log_point_t raft_flush_point;

    if (SECUREC_LIKELY(!KNL_GBP_ENABLE(g_raft_session->kernel))) {
        return;
    }

    cm_spin_lock(&raft_ctx->raft_write_disk_lock, NULL);
    raft_flush_point = raft_ctx->flush_point;
    cm_spin_unlock(&raft_ctx->raft_write_disk_lock);

    gbp_queue_set_trunc_point(session, &raft_flush_point);
}

void raft_writelog_cb(unsigned long long lsn, unsigned long long raft_index, long long errorCode)
{
    raft_context_t *raft_ctx = &g_raft_session->kernel->raft_ctx;
    log_batch_t *batch_log = NULL;
    log_batch_tail_t *tail = NULL;
    static uint64 prev_lfn = CT_INVALID_ID64;
    static uint64 prev_raft_index = CT_INVALID_ID64;

    CT_LOG_DEBUG_INF("RAFT: writelog cb lsn: %llu, raft_index: %llu, errorCode: %llu", lsn, raft_index, errorCode);

    knl_panic(DB_IS_PRIMARY(&g_raft_session->kernel->db));
    knl_panic(lsn != 0);
    knl_panic(lsn != CT_INVALID_ID64);
    knl_panic(raft_index != 0);
    knl_panic(raft_index != CT_INVALID_ID64);
    knl_panic(prev_lfn == CT_INVALID_ID64 || prev_lfn + 1 == lsn);
    knl_panic(prev_raft_index == CT_INVALID_ID64 ||
              prev_raft_index <= raft_index);  // for raft batch, raft index may be equal
    knl_panic(raft_ctx->commit_lfn == 0 || raft_ctx->commit_lfn + 1 == lsn);

    CT_LOG_DEBUG_INF("RAFT: writelog_cb1: flush pos=%d, raft pos=%d, write pos= %d\n",
                     raft_ctx->logwr_async_buf_flush_pos, raft_ctx->logwr_async_buf_raft_pos,
                     raft_ctx->logwr_async_buf_write_pos);

    prev_lfn = lsn;
    prev_raft_index = raft_index;
    raft_ctx->commit_lfn = lsn;
    knl_panic(raft_ctx->sent_lfn >= raft_ctx->commit_lfn);

    cm_spin_lock(&raft_ctx->raft_lock, NULL);
    batch_log = (log_batch_t *)(raft_ctx->logwr_async_buf +
        (uint64)raft_ctx->logwr_async_buf_raft_pos * raft_ctx->logwr_async_buf_slot_size);
    tail = (log_batch_tail_t *)((char *)batch_log + batch_log->size - sizeof(log_batch_tail_t));
    knl_panic(batch_log->head.point.lfn == lsn);
    knl_panic(batch_log->head.point.lfn == tail->point.lfn);
    knl_panic(batch_log->head.magic_num == LOG_MAGIC_NUMBER);
    knl_panic(tail->magic_num == LOG_MAGIC_NUMBER);
    knl_panic(batch_log->raft_index == CT_INVALID_ID64);

    batch_log->raft_index = raft_index;
    raft_ctx->logwr_async_buf_raft_pos = RAFT_ASYNC_LOG_NEXT(raft_ctx, raft_ctx->logwr_async_buf_raft_pos);

    raft_ctx->recv_point.rst_id = batch_log->head.point.rst_id;
    raft_ctx->recv_point.asn = batch_log->head.point.asn;
    raft_ctx->recv_point.block_id = batch_log->head.point.block_id + batch_log->space_size / raft_ctx->log_block_size;
    raft_ctx->recv_point.lfn = batch_log->head.point.lfn;
    raft_ctx->raft_recv_point.lfn = batch_log->head.point.lfn;
    raft_ctx->raft_recv_point.raft_index = raft_index;

    CT_LOG_DEBUG_INF("RAFT: writelog cb2: flush pos=%d, raft pos=%d, write pos= %d, batch lfn=%lld, "
                     "batch raft_index=%lld, send lfn =%lld, commit lfn=%lld\n",
                     raft_ctx->logwr_async_buf_flush_pos, raft_ctx->logwr_async_buf_raft_pos,
                     raft_ctx->logwr_async_buf_write_pos, (uint64)batch_log->head.point.lfn,
                     batch_log->raft_index, raft_ctx->sent_lfn, raft_ctx->commit_lfn);

    cm_spin_unlock(&raft_ctx->raft_lock);

    (void)cm_release_cond(&raft_ctx->cond);


    raft_set_gbp_trunc_point(raft_ctx);
}

void raft_db_register_callback(knl_session_t *session)
{
    raft_context_t *ctx = &session->kernel->raft_ctx;
    char *writelog_cb_func_name = "WriteLogCallbackIn";
    char *sendlog_cb_func_name = "SendLogCBFunc";
    char *getappliedindex_func_name = "GetAppliedIndex";
    char *promote_cb_func_name = "PromoteCBFunc";
    char *demote_cb_func_name = "DemoteCBFunc";
    char *print_func_name = "PrintFuncName";
    char *get_lfn_scn_name = "GetLfnScn";

    (void)raft_lib_register(&ctx->raft_proc, print_func_name, (void *)raft_printfunc);
    (void)raft_lib_register(&ctx->raft_proc, writelog_cb_func_name, (void *)raft_writelog_cb);
    (void)raft_lib_register(&ctx->raft_proc, sendlog_cb_func_name, (void *)raft_sendlog_cb);
    (void)raft_lib_register(&ctx->raft_proc, getappliedindex_func_name, (void *)raft_getappliedindex_cb);
    (void)raft_lib_register(&ctx->raft_proc, promote_cb_func_name, (void *)raft_promote_cb);
    (void)raft_lib_register(&ctx->raft_proc, demote_cb_func_name, (void *)raft_demote_cb);
    (void)raft_lib_register(&ctx->raft_proc, get_lfn_scn_name, (void *)raft_get_lfn_scn_cb);
}

status_t raft_db_init_module(knl_session_t *session, uint64 *last_committed_lfn)
{
    knl_attr_t *attr = &session->kernel->attr;
    raft_context_t *raft_ctx = &session->kernel->raft_ctx;
    status_t status;
    errno_t errcode;

    if (attr->raft_kudu_dir[0] == '\0') {
        errno_t ret;
        ret = snprintf_s(attr->raft_kudu_dir, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1, "%s/kudu",
                         session->kernel->home);
        knl_securec_check_ss(ret);
    }

    cm_init_cond(&raft_ctx->cond);

    if (raft_load_lib(&raft_ctx->raft_proc) != CT_SUCCESS) {
        CT_LOG_RUN_INF("RAFT: failed to load ibconsistency.so");
        CT_THROW_ERROR(ERR_RAFT_INIT_FAILED, "load ibconsistency.so");
        return CT_ERROR;
    }

    if (raft_lib_initDBEngines(&raft_ctx->raft_proc, attr->raft_log_level) != CT_SUCCESS) {
        CT_LOG_RUN_INF("RAFT: failed to init db engine");
        CT_THROW_ERROR(ERR_RAFT_INIT_FAILED, "init db engine");
        return CT_ERROR;
    }

    g_raft_session = session->kernel->sessions[SESSION_ID_LOGWR_ASYNC];

    raft_db_register_callback(session);

    status = raft_lib_set_param(&raft_ctx->raft_proc, (char *)"RAFT_PRIORITY_TYPE", (void *)attr->raft_priority_type);
    if (status != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_RAFT_INIT_FAILED, "set raft priority type");
        return CT_ERROR;
    }
    errcode = strncpy_s(raft_ctx->priority_type, CT_FILE_NAME_BUFFER_SIZE,
                        attr->raft_priority_type, strlen(attr->raft_priority_type));
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }

    status = raft_lib_set_param(&raft_ctx->raft_proc, (char *)"RAFT_PRIORITY_LEVEL", (void *)attr->raft_priority_level);
    if (status != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_RAFT_INIT_FAILED, "set raft priority level");
        return CT_ERROR;
    }
    errcode = strncpy_s(raft_ctx->priority_level, CT_FILE_NAME_BUFFER_SIZE,
                        attr->raft_priority_level, strlen(attr->raft_priority_level));
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }

    status = raft_lib_set_param(&raft_ctx->raft_proc, (char *)"RAFT_LAYOUT_INFO", (void *)attr->raft_layout_info);
    if (status != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_RAFT_INIT_FAILED, "set raft layout info");
        return CT_ERROR;
    }
    errcode = strncpy_s(raft_ctx->layout_info, CT_FILE_NAME_BUFFER_SIZE,
                        attr->raft_layout_info, strlen(attr->raft_layout_info));
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }

    status = raft_lib_set_param(&raft_ctx->raft_proc, (char *)"RAFT_PENDING_CMDS_BUFFER_SIZE",
                                (void *)attr->raft_pending_cmds_buffer_size);
    if (status != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_RAFT_INIT_FAILED, "set raft pending cmds buffer size");
        return CT_ERROR;
    }

    status = raft_lib_set_param(&raft_ctx->raft_proc, (char *)"RAFT_SEND_BUFFER_SIZE",
                                (void *)attr->raft_send_buffer_size);
    if (status != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_RAFT_INIT_FAILED, "set raft send buffer size");
        return CT_ERROR;
    }

    status = raft_lib_set_param(&raft_ctx->raft_proc, (char *)"RAFT_RECEIVE_BUFFER_SIZE",
                                (void *)attr->raft_receive_buffer_size);
    if (status != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_RAFT_INIT_FAILED, "set raft receive buffer size");
        return CT_ERROR;
    }

    status = raft_lib_set_param(&raft_ctx->raft_proc, (char *)"RAFT_RAFT_ENTRY_CACHE_MEMORY_SIZE",
                                (void *)attr->raft_entry_cache_memory_size);
    if (status != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_RAFT_INIT_FAILED, "set raft entry cache memory size");
        return CT_ERROR;
    }

    status = raft_lib_set_param(&raft_ctx->raft_proc, (char *)"RAFT_MAX_SIZE_PER_MSG",
                                (void *)attr->raft_max_size_per_msg);
    if (status != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_RAFT_INIT_FAILED, "set raft max size per msg");
        return CT_ERROR;
    }

    CT_LOG_RUN_INF("RAFT: set raft tls dir : %s", attr->raft_tls_dir);
    if (attr->raft_tls_dir[0] != '\0') {
        status = raft_lib_set_param(&raft_ctx->raft_proc, (char *)"RAFT_TLS_DIR", (void *)attr->raft_tls_dir);
        if (status != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_RAFT_INIT_FAILED, "set raft TLS dir");
            return CT_ERROR;
        }
    }

    CT_LOG_RUN_INF("RAFT: set raft token verify : %s", attr->raft_token_verify);
    if (attr->raft_token_verify[0] != '\0') {
        status = raft_lib_set_param(&raft_ctx->raft_proc, (char *)"RAFT_TOKEN_VERIFY", (void *)attr->raft_token_verify);
        if (status != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_RAFT_INIT_FAILED, "set raft token verify");
            return CT_ERROR;
        }
    }

    status = raft_lib_set_param(&raft_ctx->raft_proc, (char *)"RAFT_MEMORY_THRESHOLD",
                                (void *)attr->raft_mem_threshold);
    if (status != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_RAFT_INIT_FAILED, "set raft mem threshold");
        return CT_ERROR;
    }

    status = raft_lib_set_param(&raft_ctx->raft_proc, (char *)"RAFT_ELECTION_TIMEOUT",
                                (void *)attr->raft_election_timeout);
    if (status != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_RAFT_INIT_FAILED, "set raft election timeout");
        return CT_ERROR;
    }

    char raft_failover_lib_timeout[CT_HOST_NAME_BUFFER_SIZE] = {0};
    int iret = sprintf_s(raft_failover_lib_timeout, CT_HOST_NAME_BUFFER_SIZE, "%llu",
        (unsigned long long)MILLISECS_PER_SECOND * attr->raft_failover_lib_timeout);
    if (iret == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, iret);
        return CT_ERROR;
    }
    status = raft_lib_set_param(&raft_ctx->raft_proc, (char *)"RAFT_FAILOVER_LIB_TIMEOUT",
                                (void *)raft_failover_lib_timeout);
    if (status != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_RAFT_INIT_FAILED, "set raft failover lib timeout");
        return CT_ERROR;
    }

    status = raft_lib_init_consistency(&raft_ctx->raft_proc, attr->raft_node_id, attr->raft_peer_ids,
                                       attr->raft_kudu_dir, attr->raft_local_addr, attr->raft_peer_addrs,
                                       last_committed_lfn, attr->raft_start_mode);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_INF("RAFT: failed to init raft module");
        CT_THROW_ERROR(ERR_RAFT_INIT_FAILED, "init raft module");
        return CT_ERROR;
    }

    raft_ctx->status = RAFT_STATUS_INITED;

    knl_panic(*last_committed_lfn != CT_INVALID_ID64);
    CT_LOG_RUN_WAR("RAFT: Init consistency successfully with node id (%d)  peer(%s), kudu(%s), "
                   "addr(%s), peerAddrs(%s), lfn=%lld.",
                   attr->raft_node_id, attr->raft_peer_ids, attr->raft_kudu_dir,
                   attr->raft_local_addr, attr->raft_peer_addrs, *last_committed_lfn);

    return CT_SUCCESS;
}

void raft_reset_async_buffer(raft_context_t *raft_ctx)
{
    raft_ctx->logwr_async_buf_flush_pos = 0;
    raft_ctx->logwr_async_buf_raft_pos = 0;
    raft_ctx->logwr_async_buf_write_pos = 0;
}

void raft_wait_for_log_flush(knl_session_t *session, uint64 end_lfn)
{
    raft_context_t *raft_ctx = &session->kernel->raft_ctx;

    while (raft_ctx->raft_flush_point.lfn < end_lfn) {
        cm_sleep(1);
        if (session->killed) {
            CT_THROW_ERROR(ERR_OPERATION_KILLED);
            return;
        }
    }
}

/* wait for raft log flushed to raft */
void raft_wait_for_batch_commit_in_raft(knl_session_t *session, uint64 lfn)
{
    raft_context_t *raft_ctx = &session->kernel->raft_ctx;

    for (;;) {
        if (lfn <= raft_ctx->commit_lfn) {
            return;
        }

        if (session->killed) {
            CT_THROW_ERROR(ERR_OPERATION_KILLED);
            return;
        }

        (void)cm_wait_cond(&raft_ctx->cond, 3);
    }
}

// copy batch to async log buffer, and return the address of the new batch in the async buffer.
// must be called serialized
status_t raft_write_to_async_buffer_num(knl_session_t *session, log_batch_t *batch, log_batch_t **new_batch)
{
    raft_context_t *ctx = &session->kernel->raft_ctx;
    log_batch_tail_t *tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));

    CT_LOG_DEBUG_INF("RAFT: write to async buffer 0: flush pos=%d, raft pos=%d, write pos= %d, "
                     "batch lfn=%lld, batch index=%lld\n",
                     ctx->logwr_async_buf_flush_pos, ctx->logwr_async_buf_raft_pos,
                     ctx->logwr_async_buf_write_pos, (uint64)batch->head.point.lfn, batch->raft_index);

    batch->space_size = CM_CALC_ALIGN(batch->size, ctx->log_block_size);
    if (DB_IS_PRIMARY(&session->kernel->db)) {
        log_calc_batch_checksum(session, batch);
    }

    if (ctx->status == RAFT_STATUS_CLOSING) {
        return CT_ERROR;
    }

    cm_spin_lock(&ctx->raft_lock, NULL);
    knl_panic(batch->head.point.lfn != 0 && batch->space_size != 0 && batch->head.point.lfn == tail->point.lfn &&
              batch->head.magic_num == LOG_MAGIC_NUMBER && tail->magic_num == LOG_MAGIC_NUMBER);

    knl_panic(ctx->logwr_async_buf_slot_size >= batch->space_size);
    uint32 left_size = ctx->logwr_async_buf_size -
        (uint64)ctx->logwr_async_buf_write_pos * ctx->logwr_async_buf_slot_size;
    uint32 copy_size = left_size > SECUREC_MEM_MAX_LEN ? SECUREC_MEM_MAX_LEN : left_size;
    errno_t ret = memcpy_s(ctx->logwr_async_buf +
        (uint64)ctx->logwr_async_buf_write_pos * ctx->logwr_async_buf_slot_size, copy_size, batch, batch->space_size);
    knl_securec_check(ret);
    *new_batch = (log_batch_t *)(ctx->logwr_async_buf +
        (uint64)ctx->logwr_async_buf_write_pos * ctx->logwr_async_buf_slot_size);
    ctx->logwr_async_buf_write_pos = RAFT_ASYNC_LOG_NEXT(ctx, ctx->logwr_async_buf_write_pos);
    cm_spin_unlock(&ctx->raft_lock);

    CT_LOG_DEBUG_INF("RAFT: write to async buffer1: flush pos=%d, raft pos=%d, write pos= %d, "
                     "batch lfn=%lld, batch index=%lld\n",
                     ctx->logwr_async_buf_flush_pos, ctx->logwr_async_buf_raft_pos, ctx->logwr_async_buf_write_pos,
                     (uint64)(*new_batch)->head.point.lfn, (*new_batch)->raft_index);

    if (ctx->logwr_async_buf_write_pos != ctx->logwr_async_buf_flush_pos) {
        return CT_SUCCESS;
    }
    while (ctx->logwr_async_buf_write_pos == ctx->logwr_async_buf_flush_pos) {
        (void)cm_wait_cond(&ctx->cond, 1);
        if (ctx->status == RAFT_STATUS_CLOSING) {
            return CT_ERROR;
        }
    }
    knl_panic(ctx->logwr_async_buf_write_pos != ctx->logwr_async_buf_raft_pos);

    return CT_SUCCESS;
}


void raft_async_log_buf_init(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    raft_context_t *raft_ctx = &kernel->raft_ctx;

    raft_ctx->logwr_async_buf = kernel->attr.lgwr_async_buf;
    raft_ctx->logwr_head_buf = kernel->attr.lgwr_head_buf;
    raft_ctx->logwr_async_buf_size = (uint32)kernel->attr.lgwr_async_buf_size;
    raft_ctx->logwr_async_buf_num = kernel->attr.raft_log_async_buffer_num;
    raft_ctx->logwr_async_buf_slot_size = (uint32)kernel->attr.log_buf_size;
    raft_ctx->logwr_head_buf_size = (uint32)kernel->attr.lgwr_head_buf_size;
    raft_ctx->sent_lfn = 0;
    raft_ctx->commit_lfn = 0;

    raft_reset_async_buffer(raft_ctx);
}

status_t raft_flush_log(knl_session_t *session, log_batch_t *batch)
{
    int64 writeLogRes;

    CT_LOG_DEBUG_INF("RAFT: raft flush log : batch len= %d, batch space len=%d, batch lfn=%lld\n",
                     batch->size, batch->space_size, (uint64)batch->head.point.lfn);
    // raft message limit, if assert here in the future, we need to split buffer before send to raft
    knl_panic(batch->space_size < CT_MIN_RAFT_PER_MSG_SIZE);

    if (session->kernel->raft_ctx.status == RAFT_STATUS_CLOSING) {
        return CT_ERROR;
    }

    writeLogRes = raft_lib_exec_writelog_cmd(&session->kernel->raft_ctx.raft_proc,
                                             batch->head.point.lfn, batch, batch->space_size);
    if (writeLogRes != CT_SUCCESS) {
        CT_LOG_RUN_INF("RAFT: failed to write raft log");
        CT_THROW_ERROR(ERR_WRITE_LOG_FAILED, "raft log");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static inline void raft_primary_wait_replay(log_context_t *redo_ctx, uint64 kudu_lfn)
{
    for (;;) {
        if (redo_ctx->curr_point.lfn >= kudu_lfn) {
            break;
        }
        cm_sleep(5);
    }
}

static inline void raft_standby_wait_raftlog(raft_context_t *raft_ctx, uint64 kudu_lfn)
{
    for (;;) {
        if (raft_ctx->flush_point.lfn >= kudu_lfn) {
            break;
        }
        cm_sleep(5);
    }
}

status_t raft_db_start_follower(knl_session_t *session, repl_role_t old_role)
{
    status_t status;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    log_context_t *redo_ctx = &kernel->redo_ctx;
    lrcv_context_t *lrcv_ctx = &kernel->lrcv_ctx;
    raft_context_t *raft_ctx = &kernel->raft_ctx;
    lrpl_context_t *lrpl_ctx = &session->kernel->lrpl_ctx;
    uint64 lfn = dtc_my_ctrl(session)->rcy_point.lfn;
    uint32 file_id;

    if (!DB_IS_RAFT_ENABLED(kernel)) {
        return CT_SUCCESS;
    }

    lrcv_ctx->status = LRCV_READY;

    for (;;) {
        if (lrpl_ctx->curr_point.asn != CT_INVALID_ASN && log_point_equal(&lrpl_ctx->curr_point, redo_ctx)) {
            break;
        }
        if (session->killed) {
            CT_LOG_RUN_INF("RAFT: session killed");
            CT_THROW_ERROR(ERR_OPERATION_KILLED);
            return CT_ERROR;
        }
        cm_sleep(100);
    }

    raft_ctx->flush_point = lrpl_ctx->curr_point;
    raft_ctx->recv_point = lrpl_ctx->curr_point;
    knl_panic(raft_ctx->raft_flush_point.lfn <= raft_ctx->flush_point.lfn);
    raft_ctx->raft_flush_point.lfn = raft_ctx->flush_point.lfn;
    knl_panic(raft_ctx->raft_recv_point.lfn <= raft_ctx->recv_point.lfn);
    raft_ctx->raft_recv_point.lfn = raft_ctx->recv_point.lfn;

    file_id = log_get_id_by_asn(session, (uint32)raft_ctx->flush_point.rst_id, raft_ctx->flush_point.asn, NULL);
    knl_panic(redo_ctx->curr_file == file_id);
    log_unlatch_file(session, file_id);

    status = raft_db_init_module(session, &lfn);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_INF("RAFT: init db module failed");
        return CT_ERROR;
    }

    if (old_role == REPL_ROLE_PRIMARY) {
        raft_primary_wait_replay(redo_ctx, lfn);
    } else {
        raft_standby_wait_raftlog(raft_ctx, lfn);
    }

    CT_LOG_RUN_INF("RAFT: complete redo log from kudu finished to lfn(%lld), last role(%d).", lfn, old_role);
    return CT_SUCCESS;
}

status_t raft_db_start_leader(knl_session_t *session)
{
    if (!DB_IS_RAFT_INITED(session->kernel)) {
        CT_LOG_RUN_INF("RAFT: raft is not enabled, or raft module is not inited");
        CT_THROW_ERROR(ERR_RAFT_MODULE_NOT_INITED);
        return CT_ERROR;
    }

    uint32 raft_failover_lib_timeout = session->kernel->attr.raft_failover_lib_timeout;
    int64 promoteRes = raft_lib_promote_leader(&session->kernel->raft_ctx.raft_proc, 1,
        (unsigned long long)MILLISECS_PER_SECOND * raft_failover_lib_timeout);
    if (promoteRes != CT_SUCCESS) {
        CT_LOG_RUN_INF("RAFT: failed to promote raft leader");
        CT_THROW_ERROR(ERR_RAFT_INIT_FAILED, "promote raft leader");
        return CT_ERROR;
    }

    CT_LOG_RUN_WAR("RAFT: start callback to promote leader in database");
    return CT_SUCCESS;
}

status_t knl_raft_add_member(knl_handle_t session, uint64 node_id, char *addr, uint64 timeout, uint64 role)
{
    int64 status;
    knl_session_t *se = (knl_session_t *)session;
    CM_POINTER(session);

    if (!DB_IS_RAFT_INITED(se->kernel)) {
        CT_LOG_RUN_INF("RAFT: raft is not enabled, or raft module is not inited");
        CT_THROW_ERROR(ERR_RAFT_MODULE_NOT_INITED);
        return CT_ERROR;
    }

    CT_LOG_RUN_WAR("RAFT: add member, node id=%lld, addr=%s, role=%lld\n", node_id, addr, role);
    status = raft_lib_add_member(&se->kernel->raft_ctx.raft_proc, node_id, addr, timeout, role);
    if (status != 0) {
        CT_LOG_RUN_INF("RAFT: add member failed");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t knl_raft_del_member(knl_handle_t session, uint64 node_id, uint64 timeout)
{
    int64 status;
    knl_session_t *se = (knl_session_t *)session;
    CM_POINTER(session);

    if (!DB_IS_RAFT_INITED(se->kernel)) {
        CT_LOG_RUN_INF("RAFT: raft is not enabled, or raft module is not inited");
        CT_THROW_ERROR(ERR_RAFT_MODULE_NOT_INITED);
        return CT_ERROR;
    }

    CT_LOG_RUN_WAR("RAFT: del member, node id=%lld\n", node_id);

    status = raft_lib_delete_member(&se->kernel->raft_ctx.raft_proc, node_id, timeout);
    if (status != 0) {
        CT_LOG_RUN_INF("RAFT: delete member failed");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t knl_raft_query_info(knl_handle_t session, char *type, char **query_info)
{
    knl_session_t *se = (knl_session_t *)session;
    CM_POINTER(session);

    if (!DB_IS_RAFT_INITED(se->kernel)) {
        CT_LOG_RUN_INF("RAFT: raft is not enabled, or raft module is not inited");
        CT_THROW_ERROR(ERR_RAFT_MODULE_NOT_INITED);
        return CT_ERROR;
    }

    *query_info = raft_lib_query_info(&se->kernel->raft_ctx.raft_proc, type);
    return CT_SUCCESS;
}

status_t knl_raft_monitor_info(knl_handle_t session, char **monitor_info)
{
    knl_session_t *se = (knl_session_t *)session;
    CM_POINTER(session);

    if (!DB_IS_RAFT_INITED(se->kernel)) {
        CT_LOG_RUN_INF("RAFT: raft is not enabled, or raft module is not inited");
        CT_THROW_ERROR(ERR_RAFT_MODULE_NOT_INITED);
        return CT_ERROR;
    }

    *monitor_info = raft_lib_monitor(&se->kernel->raft_ctx.raft_proc);
    return CT_SUCCESS;
}

status_t knl_raft_version(knl_handle_t session, char **version)
{
    knl_session_t *se = (knl_session_t *)session;
    CM_POINTER(session);

    if (!DB_IS_RAFT_INITED(se->kernel)) {
        CT_LOG_RUN_INF("RAFT: raft is not enabled, or raft module is not inited");
        CT_THROW_ERROR(ERR_RAFT_MODULE_NOT_INITED);
        return CT_ERROR;
    }

    *version = raft_lib_get_version(&se->kernel->raft_ctx.raft_proc);
    return CT_SUCCESS;
}

status_t knl_raft_set_param(knl_handle_t session, char *param_name, void *value)
{
    int status;
    knl_session_t *se = (knl_session_t *)session;
    CM_POINTER(session);

    if (!DB_IS_RAFT_INITED(se->kernel)) {
        CT_LOG_RUN_INF("RAFT: raft is not enabled, or raft module is not inited");
        CT_THROW_ERROR(ERR_RAFT_MODULE_NOT_INITED);
        return CT_ERROR;
    }

    status = raft_lib_set_param(&se->kernel->raft_ctx.raft_proc, param_name, (void *)value);
    if (status != 0) {
        CT_LOG_RUN_INF("RAFT: set parameter failed");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}


status_t raft_log_flush_to_disk(knl_session_t *session, log_context_t *ctx, log_batch_t *batch)
{
    log_file_t *file = &ctx->files[ctx->curr_file];

    batch->space_size = CM_CALC_ALIGN(batch->size, file->ctrl->block_size);

    int64 offset = (int64)batch->head.point.block_id * file->head.block_size;
    if (cm_write_device(file->ctrl->type, file->handle, offset, batch, batch->space_size) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[LOG] failed to read %s", file->ctrl->name);
        cm_close_device(file->ctrl->type, &file->handle);
        return CT_ERROR;
    }

    if (!DB_IS_PRIMARY(&session->kernel->db)) {
        knl_panic(file->head.write_pos == (uint64)offset);
        file->head.write_pos += batch->space_size;
        ctx->free_size -= batch->space_size;
        file->head.last = batch->scn;
        if (file->head.first == CT_INVALID_ID64) {
            file->head.first = batch->scn;
            log_flush_head(session, file);
        }
    }

    return CT_SUCCESS;
}

void log_async_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    raft_context_t *raft_ctx = &session->kernel->raft_ctx;
    log_batch_t *batch_log = NULL;
    log_batch_tail_t *tail = NULL;

    static uint64 prev_lfn = CT_INVALID_ID64;
    static uint64 prev_raft_index = CT_INVALID_ID64;
    log_point_t last_flush_point;

    knl_panic(DB_IS_RAFT_ENABLED(session->kernel));
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());

    while (!thread->closed) {
        if (DB_NOT_READY(session) || !DB_IS_RAFT_INITED(session->kernel)) {
            cm_sleep(200);
            continue;
        }

        if (raft_ctx->logwr_async_buf_flush_pos == raft_ctx->logwr_async_buf_raft_pos) {
            (void)cm_wait_cond(&raft_ctx->cond, 2);
            continue;
        }

        cm_spin_lock(&raft_ctx->raft_lock, NULL);
        if (raft_ctx->logwr_async_buf_flush_pos == raft_ctx->logwr_async_buf_raft_pos) {
            cm_spin_unlock(&raft_ctx->raft_lock);
            continue;
        }

        batch_log = (log_batch_t *)(raft_ctx->logwr_async_buf +
            (uint64)raft_ctx->logwr_async_buf_flush_pos * raft_ctx->logwr_async_buf_slot_size);
        knl_panic(batch_log->raft_index != CT_INVALID_ID64 && batch_log->head.magic_num == LOG_MAGIC_NUMBER);

        last_flush_point = raft_ctx->flush_point;

        CT_LOG_DEBUG_INF("RAFT: log async1: flush pos=%d, raft pos=%d, write pos= %d, "
                         "batch lfn=%lld, batch index=%lld\n",
                         raft_ctx->logwr_async_buf_flush_pos, raft_ctx->logwr_async_buf_raft_pos,
                         raft_ctx->logwr_async_buf_write_pos, (uint64)batch_log->head.point.lfn, batch_log->raft_index);
        knl_panic(prev_lfn == CT_INVALID_ID64 || prev_lfn + 1 == batch_log->head.point.lfn);
        knl_panic(prev_raft_index == CT_INVALID_ID64 || prev_raft_index <= batch_log->raft_index);

        prev_lfn = batch_log->head.point.lfn;
        prev_raft_index = batch_log->raft_index;

        tail = (log_batch_tail_t *)((char *)batch_log + batch_log->size - sizeof(log_batch_tail_t));
        knl_panic(rcy_validate_batch(batch_log, tail));
        cm_spin_unlock(&raft_ctx->raft_lock);

        cm_spin_lock(&raft_ctx->raft_write_disk_lock, NULL);
        raft_log_flush_init(session, batch_log);
        /* flush batch to disk */
        if (raft_log_flush_to_disk(session, redo_ctx, (log_batch_t *)batch_log) != CT_SUCCESS) {
            cm_spin_unlock(&raft_ctx->raft_write_disk_lock);
            KNL_SESSION_CLEAR_THREADID(session);
            CM_ABORT(0, "[RAFT] ABORT INFO: raft log async proc, log flush to disk failed.");
        }

        knl_panic(batch_log->head.point.lfn == (uint64)raft_ctx->flush_point.lfn + 1);
        knl_panic(batch_log->raft_index >= raft_ctx->raft_flush_point.raft_index);
        raft_ctx->flush_point.block_id = batch_log->head.point.block_id +
            batch_log->space_size / raft_ctx->log_block_size;
        raft_ctx->flush_point.asn = batch_log->head.point.asn;
        raft_ctx->flush_point.lfn = batch_log->head.point.lfn;
        raft_ctx->flush_point.rst_id = batch_log->head.point.rst_id;
        raft_ctx->raft_flush_point.scn = batch_log->scn;
        raft_ctx->raft_flush_point.lfn = batch_log->head.point.lfn;
        raft_ctx->raft_flush_point.raft_index = batch_log->raft_index;
        session->kernel->lfn = batch_log->head.point.lfn;
        knl_panic(log_cmp_point(&last_flush_point, &raft_ctx->flush_point) < 0);
        cm_spin_unlock(&raft_ctx->raft_write_disk_lock);

        raft_ctx->logwr_async_buf_flush_pos = RAFT_ASYNC_LOG_NEXT(raft_ctx, raft_ctx->logwr_async_buf_flush_pos);

        CT_LOG_DEBUG_INF("RAFT: log async2: flush pos=%d, raft pos=%d, write pos= %d, batch lfn=%lld,"
                         "batch index=%lld, flush_point lfn=%lld, flush_point offset=%u\n",
                         raft_ctx->logwr_async_buf_flush_pos, raft_ctx->logwr_async_buf_raft_pos,
                         raft_ctx->logwr_async_buf_write_pos, (uint64)batch_log->head.point.lfn,
                         batch_log->raft_index, (uint64)raft_ctx->flush_point.lfn, raft_ctx->flush_point.block_id);
    }
    KNL_SESSION_CLEAR_THREADID(session);
}

void raft_stop_consistency(knl_session_t *session)
{
    raft_context_t  *raft_ctx = &session->kernel->raft_ctx;

    raft_lib_stop_consistency(&raft_ctx->raft_proc);
    raft_close_lib(&raft_ctx->raft_proc);

    cm_destory_cond(&raft_ctx->cond);
}