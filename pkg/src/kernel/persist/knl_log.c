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
 * knl_log.c
 *
 *
 * IDENTIFICATION
 * src/kernel/persist/knl_log.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_log.h"
#include "cm_log.h"
#include "cm_file.h"
#include "cm_checksum.h"
#include "cm_kmc.h"
#include "knl_context.h"
#include "repl_log_send.h"
#include "knl_ctrl_restore.h"
#include "knl_page.h"
#include "dtc_dcs.h"
#include "dtc_database.h"
#include "dtc_dls.h"
#include "cm_dbs_ulog.h"
#include "cm_io_record.h"

// log_buf_init: init log buffer
static inline void log_buf_init(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    log_context_t *ctx = &kernel->redo_ctx;
    log_dual_buffer_t *section = NULL;
    uint32 sid_array_size = GS_MAX_SESSIONS * sizeof(uint16);

    ctx->buf_count = kernel->attr.log_buf_count;
    ctx->buf_size = (uint32)kernel->attr.log_buf_size;
   /*
    * ctx->buf_size / 2 is the size of the async buffer,which is half of the public buffer
    * We must reserve head and tail space for each batch
    */
    uint32 buffer_size = (ctx->buf_size / 2 - sizeof(log_batch_t) - sizeof(log_batch_tail_t) - sid_array_size) /
                   ctx->buf_count - sizeof(log_part_t);
    buffer_size = (buffer_size / 8) * 8;  // ALIGN8

    for (uint32 i = 0; i < ctx->buf_count; i++) {
        section = &ctx->bufs[i];
        section->members[0].size = buffer_size;
        section->members[0].addr = kernel->attr.log_buf + (i * GS_LOG_AREA_COUNT) * buffer_size;
        section->members[1].size = buffer_size;
        section->members[1].addr = kernel->attr.log_buf + (uint64)(i * GS_LOG_AREA_COUNT + 1) * buffer_size;
    }

    ctx->wid = 0;
    ctx->fid = 1;
    ctx->flushed_lfn = 0;

    ctx->logwr_head_buf = kernel->attr.lgwr_head_buf;
    ctx->logwr_buf = kernel->attr.lgwr_buf;
    ctx->logwr_buf_size = (uint32)kernel->attr.lgwr_buf_size;
    ctx->logwr_cipher_buf = kernel->attr.lgwr_cipher_buf;
    ctx->logwr_cipher_buf_size = (uint32)kernel->attr.lgwr_cipher_buf_size;
    ctx->logwr_buf_pos = 0;
    ctx->log_encrypt = GS_FALSE;
}

static inline bool32 log_file_not_used(log_context_t *ctx, uint32 file)
{
    if (ctx->active_file <= ctx->curr_file) {
        return (bool32)(file < ctx->active_file || file > ctx->curr_file);
    } else {
        return (bool32)(file < ctx->active_file && file > ctx->curr_file);
    }
}

inline uint64 log_file_freesize(log_file_t *file)
{
    return (uint64)file->ctrl->size - file->head.write_pos;
}

status_t log_verify_head_checksum(knl_session_t *session, log_file_head_t *head, char *name)
{
    uint32 cks_level = session->kernel->attr.db_block_checksum;
    uint32 org_cks = head->checksum;

    if (DB_IS_CHECKSUM_OFF(session) || org_cks == GS_INVALID_CHECKSUM) {
        return GS_SUCCESS;
    }

    head->checksum = GS_INVALID_CHECKSUM;
    uint32 new_cks = cm_get_checksum(head, sizeof(log_file_head_t));
    head->checksum = org_cks;
    if (org_cks != new_cks) {
        GS_LOG_RUN_ERR("[LOG] invalid log file head checksum.file %s, rst_id %u, asn %u, "
                       "org_cks %u, new_cks %u, checksum level %s",
                       name, head->rst_id, head->asn, org_cks, new_cks, knl_checksum_level(cks_level));
        GS_THROW_ERROR(ERR_CHECKSUM_FAILED, name);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

void log_calc_head_checksum(knl_session_t *session, log_file_head_t *head)
{
    head->checksum = GS_INVALID_CHECKSUM;

    if (DB_IS_CHECKSUM_OFF(session)) {
        return;
    }
    head->checksum = cm_get_checksum(head, sizeof(log_file_head_t));
}

status_t log_init_file_head(knl_session_t *session, log_file_t *file)
{
    knl_instance_t *kernel = session->kernel;
    aligned_buf_t log_buf;

    if (cm_aligned_malloc((int64)kernel->attr.lgwr_buf_size, "log buffer", &log_buf) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[PITR] failed to alloc log buffer with size %u", (uint32)kernel->attr.lgwr_buf_size);
        return GS_ERROR;
    }

    if (cm_read_device(file->ctrl->type, file->handle, 0, log_buf.aligned_buf,
                       CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size)) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[LOG] failed to read %s ", file->ctrl->name);
        cm_close_device(file->ctrl->type, &file->handle);
        cm_aligned_free(&log_buf);
        return GS_ERROR;
    }

    if (log_verify_head_checksum(session, (log_file_head_t *)log_buf.aligned_buf, file->ctrl->name) != GS_SUCCESS) {
        cm_close_device(file->ctrl->type, &file->handle);
        cm_aligned_free(&log_buf);
        return GS_ERROR;
    }

    uint32 log_head_size = sizeof(log_file_head_t);
    errno_t ret = memcpy_sp(&file->head, log_head_size, log_buf.aligned_buf, log_head_size);
    knl_securec_check(ret);
    cm_aligned_free(&log_buf);

    return GS_SUCCESS;
}

static status_t log_file_init(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    log_context_t *ctx = &kernel->redo_ctx;
    database_t *db = &session->kernel->db;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);
    log_file_t *file = NULL;

    ctx->logfile_hwm = logfile_set->logfile_hwm;
    ctx->files = logfile_set->items;
    ctx->free_size = 0;

    if (cm_dbs_is_enable_dbs() == GS_TRUE) {
        file = &ctx->files[0];
        file->head.rst_id = db->ctrl.core.resetlogs.rst_id;
        file->head.write_pos = 0;
        ctx->free_size += log_file_freesize(file);
        return GS_SUCCESS;
    }

    for (uint32 i = 0; i < ctx->logfile_hwm; i++) {
        file = &ctx->files[i];

        if (LOG_IS_DROPPED(file->ctrl->flg)) {
            continue;
        }

        if (cm_read_device(file->ctrl->type, file->handle, 0, ctx->logwr_buf,
                           CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size)) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[LOG] failed to read %s ", file->ctrl->name);
            cm_close_device(file->ctrl->type, &file->handle);
            return GS_ERROR;
        }

        if (log_verify_head_checksum(session, (log_file_head_t *)ctx->logwr_buf, file->ctrl->name) != GS_SUCCESS) {
            cm_close_device(file->ctrl->type, &file->handle);
            return GS_ERROR;
        }

        if (log_file_not_used(ctx, i)) {
            file->head.rst_id = db->ctrl.core.resetlogs.rst_id;
            file->head.write_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
            file->head.block_size = file->ctrl->block_size;
            file->head.asn = GS_INVALID_ASN;
            file->head.first = GS_INVALID_ID64;
            file->head.last = GS_INVALID_ID64;
            file->head.cmp_algorithm = COMPRESS_NONE;
            ctx->free_size += log_file_freesize(&logfile_set->items[i]);
            continue;
        }

        uint32 log_head_size = sizeof(log_file_head_t);
        errno_t ret = memcpy_sp(&file->head, log_head_size, ctx->logwr_buf, log_head_size);
        knl_securec_check(ret);
    }

    return GS_SUCCESS;
}

status_t log_init(knl_session_t *session)
{
    errno_t ret = memset_sp(&session->kernel->redo_ctx, sizeof(log_context_t), 0, sizeof(log_context_t));
    knl_securec_check(ret);

    log_buf_init(session);

    raft_async_log_buf_init(session);

    return GS_SUCCESS;
}

status_t log_load(knl_session_t *session)
{
    log_context_t *ctx = &session->kernel->redo_ctx;

    ctx->active_file = dtc_my_ctrl(session)->log_first;
    ctx->curr_file = dtc_my_ctrl(session)->log_last;

    return log_file_init(session);
}

void log_close(knl_session_t *session)
{
    cm_close_thread(&session->kernel->redo_ctx.thread);
}

void log_flush_head(knl_session_t *session, log_file_t *file)
{
    log_context_t *ctx = &session->kernel->redo_ctx;

    if (file->ctrl->type == DEV_TYPE_ULOG) {
        GS_LOG_RUN_INF("NO need flush head for ulog %s.", file->ctrl->name);
        return;
    }
    
    log_calc_head_checksum(session, &file->head);
    if (DB_IS_RAFT_ENABLED(session->kernel)) {
        raft_log_flush_async_head(&session->kernel->raft_ctx, file);
        return;
    }

    /* since rebuild ctrlfiles was supported, the log file ctrl info was backup in the first block of log file. in
     * order not to overwrite it, we need to read it before write in flush log file head */
    int32 size = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
    if (cm_read_device(file->ctrl->type, file->handle, 0, ctx->logwr_head_buf, size) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[LOG] failed to read %s ", file->ctrl->name);
        CM_ABORT(0, "[LOG] ABORT INFO: read redo head:%s, offset:%u, size:%lu failed.", file->ctrl->name, 0,
                 sizeof(log_file_head_t));
    }

    *(log_file_head_t *)ctx->logwr_head_buf = file->head;

    size = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
    if (cm_write_device(file->ctrl->type, file->handle, 0, ctx->logwr_head_buf, size) != GS_SUCCESS) {
        GS_LOG_ALARM(WARN_FLUSHREDO, "'file-name':'%s'}", file->ctrl->name);
        CM_ABORT(0, "[LOG] ABORT INFO: flush redo file:%s, offset:%u, size:%lu failed.", file->ctrl->name, 0,
                 sizeof(log_file_head_t));
    }
    GS_LOG_DEBUG_INF("Flush log[%u] head with asn %u status %d", file->ctrl->file_id, file->head.asn,
                     file->ctrl->status);
}

status_t log_switch_file(knl_session_t *session)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    reset_log_t resetlog = session->kernel->db.ctrl.core.resetlogs;
    uint32 next;
    log_file_t *curr_file = NULL;

    if (cm_dbs_is_enable_dbs() == GS_TRUE) {
        curr_file = &ctx->files[ctx->curr_file];
        curr_file->head.write_pos = 0;
        GS_LOG_RUN_INF("Succeed to switch logfile active %u current %u.", ctx->active_file, ctx->curr_file);
        return GS_SUCCESS;
    }

    log_get_next_file(session, &next, GS_TRUE);
    knl_panic_log((next != ctx->active_file), "failed to switch log file, current file is %d, "
                  "active file is %d, log free size is %llu", ctx->curr_file, ctx->active_file, ctx->free_size);

    curr_file = &ctx->files[ctx->curr_file];
    curr_file->ctrl->status = LOG_FILE_ACTIVE;
    uint32 asn = curr_file->head.asn;
    uint32 rst_id = (curr_file->head.asn == resetlog.last_asn) ? (resetlog.rst_id) : curr_file->head.rst_id;
    ctx->free_size -= log_file_freesize(curr_file);
    ctx->curr_file = next;

    log_file_t *next_file = &ctx->files[next];
    next_file->arch_pos = 0;
    next_file->head.write_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), next_file->ctrl->block_size);
    next_file->head.block_size = next_file->ctrl->block_size;
    next_file->head.rst_id = rst_id;
    next_file->head.asn = asn + 1;
    next_file->head.first = GS_INVALID_ID64;
    next_file->head.cmp_algorithm = COMPRESS_NONE;
    next_file->ctrl->status = LOG_FILE_CURRENT;
    next_file->ctrl->archived = GS_FALSE;
    log_flush_head(session, next_file);

    dtc_my_ctrl(session)->log_last = ctx->curr_file;

    if (db_save_log_ctrl(session, ctx->curr_file, session->kernel->id) != GS_SUCCESS) {
        CM_ABORT(0, "[LOG] ABORT INFO: save control space file failed when switch log file");
    }

    if (ctrl_backup_log_ctrl(session, curr_file->ctrl->file_id) != GS_SUCCESS) {
        CM_ABORT(0, "[LOG] ABORT INFO: backup log control info failed when switch log file");
    }
    ctx->stat.switch_count++;

    GS_LOG_RUN_INF("succeed to switch logfile active %u current %u", ctx->active_file, ctx->curr_file);

    return GS_SUCCESS;
}

void log_flush_init(knl_session_t *session, uint32 batch_size_input)
{
    uint32 batch_size = batch_size_input;
    log_context_t *ctx = &session->kernel->redo_ctx;
    log_file_t *file = &ctx->files[ctx->curr_file];

    if (file->ctrl->type == DEV_TYPE_ULOG) {
        batch_size = cm_align_device_size(file->ctrl->type, batch_size);
    }

    if (log_file_freesize(file) < batch_size) {
        log_flush_head(session, file);
        (void)log_switch_file(session);
        ctx->stat.space_requests++;
    }

    file = &ctx->files[ctx->curr_file];
    knl_panic_log(log_file_freesize(file) >= batch_size, "the log_file_freesize is smaller than batch_size, "
                  "panic info: freesize %llu batch_size %u", log_file_freesize(file), batch_size);
}

inline void log_calc_batch_checksum(knl_session_t *session, log_batch_t *batch)
{
    batch->checksum = GS_INVALID_CHECKSUM;
    if (DB_IS_CHECKSUM_OFF(session)) {
        return;
    }

    uint32 cks = cm_get_checksum(batch, batch->size);
    batch->checksum = REDUCE_CKS2UINT16(cks);
}

status_t log_flush_to_disk(knl_session_t *session, log_context_t *ctx, log_batch_t *batch)
{
    log_file_t *file = &ctx->files[ctx->curr_file];
    uint64 free_size = 0;
    batch->space_size = CM_CALC_ALIGN(batch->size, file->ctrl->block_size);
    log_calc_batch_checksum(session, batch);
    uint32 space_size = batch->space_size;
    status_t ret = GS_SUCCESS;
    if (file->ctrl->type == DEV_TYPE_ULOG) {
        ret = cm_dbs_ulog_write(file->handle, batch->head.point.lsn, batch, batch->space_size, &free_size);
    } else {
        ret = cm_write_device(file->ctrl->type, file->handle, file->head.write_pos, batch, space_size);
    }
    if (ret != GS_SUCCESS) {
        GS_LOG_ALARM(WARN_FLUSHREDO, "'file-name':'%s'}", file->ctrl->name);
        GS_LOG_RUN_ERR("[LOG] failed to write %s", file->ctrl->name);
        cm_close_device(file->ctrl->type, &file->handle);
        return GS_ERROR;
    }

    file->head.write_pos += space_size;
    /**
     * The log_flush_init has previously checked the available capacity of the current file,
     * but the batch_size used is the estimated capacity. If there are fragments at the bottom
     * layer of DBStor, the actual space usage exceeds the estimated capacity. As a result,
     * write_pos exceeds the total size. In this case, use log_switch_file to rectify the fault.
     * */
    if (file->ctrl->type == DEV_TYPE_ULOG && file->head.write_pos > file->ctrl->size) {
        (void)log_switch_file(session);
        ctx->stat.space_requests++;
    }
    if (file->ctrl->type == DEV_TYPE_ULOG) {
        ctx->free_size = free_size;
    } else {
        ctx->free_size -= space_size;
    }
    
    file->head.last = batch->scn;
    if (file->head.first == GS_INVALID_ID64) {
        file->head.first = batch->scn;
        log_flush_head(session, file);
    }

    return GS_SUCCESS;
}

static inline void log_assemble_buffer(log_context_t *ctx, log_buffer_t *buf, uint64 *max_lsn)
{
    log_part_t part;

    part.size = buf->write_pos;
    *(log_part_t *)(ctx->logwr_buf + ctx->logwr_buf_pos) = part;
    ctx->logwr_buf_pos += sizeof(log_part_t);

    errno_t ret = memcpy_sp(ctx->logwr_buf + ctx->logwr_buf_pos, ctx->logwr_buf_size - ctx->logwr_buf_pos,
        buf->addr, buf->write_pos);
    knl_securec_check(ret);
    ctx->logwr_buf_pos += buf->write_pos;
    if (buf->log_encrypt) {
        ctx->log_encrypt = GS_TRUE;
    }
    buf->write_pos = 0;
    buf->log_encrypt = GS_FALSE;
    if (buf->lsn > *max_lsn) {
        *max_lsn = buf->lsn;
        buf->lsn = 0;
    }
}

inline void log_stat_prepare(log_context_t *ctx)
{
    (void)cm_gettimeofday(&ctx->stat.flush_begin);
}

static inline void log_stat(log_context_t *ctx, uint32 size)
{
    struct timeval flush_end;

    (void)cm_gettimeofday(&flush_end);
    int64 usecs = (flush_end.tv_sec - ctx->stat.flush_begin.tv_sec) * MICROSECS_PER_SECOND;
    usecs += flush_end.tv_usec - ctx->stat.flush_begin.tv_usec;
    ctx->stat.flush_elapsed += (uint64)usecs;
    ctx->stat.flush_bytes += size;
    ctx->stat.flush_times++;

    if (size <= SIZE_K(128)) {  // binary testing
        if (size <= SIZE_K(16)) {
            if (size <= SIZE_K(8)) {
                if (size <= SIZE_K(4)) {
                    ctx->stat.times_4k++;
                } else {
                    ctx->stat.times_8k++;
                }
            } else {
                ctx->stat.times_16k++;
            }
        } else {
            if (size <= SIZE_K(64)) {
                if (size <= SIZE_K(32)) {
                    ctx->stat.times_32k++;
                } else {
                    ctx->stat.times_64k++;
                }
            } else {
                ctx->stat.times_128k++;
            }
        }
    } else if (size <= SIZE_K(512)) {
        if (size <= SIZE_K(256)) {
            ctx->stat.times_256k++;
        } else {
            ctx->stat.times_512k++;
        }
    } else if (size <= SIZE_K(1024)) {
        ctx->stat.times_1m++;
    } else {
        ctx->stat.times_inf++;
    }
}

bool32 log_try_lock_logfile(knl_session_t *session)
{
    return cm_spin_try_lock(&session->kernel->redo_ctx.flush_lock);
}

inline void log_lock_logfile(knl_session_t *session)
{
    cm_spin_lock(&session->kernel->redo_ctx.flush_lock, &session->stat->spin_stat.stat_log_flush);
}

inline void log_unlock_logfile(knl_session_t *session)
{
    cm_spin_unlock(&session->kernel->redo_ctx.flush_lock);
}

status_t log_decrypt(knl_session_t *session, log_batch_t *batch, char *plain_buf, uint32 plain_length)
{
    uint32 plain_len = plain_length;
    char *tmp_buf = NULL;
    knl_panic_log(batch->encrypted, "the batch is not encrypted.");
    cipher_ctrl_t cipher_ctrl = *(cipher_ctrl_t *)((char *)batch + sizeof(log_batch_t));
    log_batch_tail_t tail = *(log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));

    char *cipher_buf = (char *)batch + cipher_ctrl.offset;
    uint32 cipher_len = batch->size - sizeof(log_batch_t) - sizeof(cipher_ctrl_t) - sizeof(log_batch_tail_t);

    if (cipher_len - cipher_ctrl.cipher_expanded_size > plain_len) {
        tmp_buf = (char *)malloc(cipher_len - cipher_ctrl.cipher_expanded_size);
        if (tmp_buf == NULL) {
            GS_LOG_RUN_ERR("[LOG] failed to malloc length: %d", (cipher_len - cipher_ctrl.cipher_expanded_size));
            return GS_ERROR;
        }
        plain_buf = tmp_buf;
        plain_len = cipher_len - cipher_ctrl.cipher_expanded_size;
    }
    uint32 org_plain_len = plain_len;
    status_t status = cm_kmc_decrypt(GS_KMC_KERNEL_DOMAIN, cipher_buf, cipher_len, plain_buf, &plain_len);
    if (status != GS_SUCCESS) {
        GS_LOG_RUN_ERR("batch decrypt failed");
        if (tmp_buf != NULL) {
            free(tmp_buf);
        }
        return GS_ERROR;
    }

#ifdef LOG_DIAG
    uint32 cks = cm_get_checksum(plain_buf, plain_len);
    knl_panic_log(cipher_ctrl.plain_cks == REDUCE_CKS2UINT16(cks),
                  "the plain_cks is abnormal, panic info: plain_cks %u", cipher_ctrl.plain_cks);
#endif

    knl_panic_log(cipher_len - cipher_ctrl.cipher_expanded_size == plain_len, "the cipher_len is abnormal, "
                  "panic info: cipher_len %u cipher_expanded_size %u plain_len %u", cipher_len,
                  cipher_ctrl.cipher_expanded_size, plain_len);
    char *org_plain_buf = (char *)batch + sizeof(log_batch_t);
    errno_t ret = memcpy_sp(org_plain_buf, org_plain_len, plain_buf, plain_len);
    knl_securec_check(ret);

    log_batch_tail_t *org_tail = (log_batch_tail_t *)((char *)batch + sizeof(log_batch_t) + plain_len);
    *org_tail = tail;
    batch->size = sizeof(log_batch_t) + plain_len + sizeof(log_batch_tail_t);

    if (tmp_buf != NULL) {
        free(tmp_buf);
    }
    return GS_SUCCESS;
}

static void log_encrypt(knl_session_t *session, log_context_t *ctx)
{
    log_batch_t *batch = (log_batch_t *)ctx->logwr_buf;

    knl_panic_log(!batch->encrypted, "the batch is encrypted.");
    char *cipher_buf = ctx->logwr_cipher_buf;
    uint32 cipher_len = ctx->logwr_cipher_buf_size;
    char *plain_buf = (char *)batch + sizeof(log_batch_t);
    uint32 plain_len = ctx->logwr_buf_pos - sizeof(log_batch_t);

#ifdef LOG_DIAG
    uint32 cks = cm_get_checksum(plain_buf, plain_len);
#endif

    status_t status = cm_kmc_encrypt(GS_KMC_KERNEL_DOMAIN, KMC_DEFAULT_ENCRYPT,
        plain_buf, plain_len, cipher_buf, &cipher_len);
    if (status != GS_SUCCESS) {
        GS_LOG_RUN_ERR("batch encrypt failed");
        return;
    }

    knl_panic_log(sizeof(log_batch_t) + sizeof(cipher_ctrl_t) + cipher_len + sizeof(log_batch_tail_t) <=
                  ctx->logwr_buf_size, "the plain_len is abnormal, panic info: plain_len %u logwr_buf_size %u",
                  cipher_len, ctx->logwr_buf_size);
    cipher_ctrl_t *cipher_ctrl = (cipher_ctrl_t *)((char *)batch + sizeof(log_batch_t));
    cipher_ctrl->cipher_expanded_size = cipher_len - plain_len;
    cipher_ctrl->encrypt_version = KMC_DEFAULT_ENCRYPT;
    cipher_ctrl->offset = sizeof(log_batch_t) + sizeof(cipher_ctrl_t);
    cipher_ctrl->plain_cks = 0;
    cipher_ctrl->reserved = 0;

#ifdef LOG_DIAG
    cipher_ctrl->plain_cks = REDUCE_CKS2UINT16(cks);
#endif

    errno_t ret = memcpy_sp((char *)batch + cipher_ctrl->offset, ctx->logwr_buf_size - cipher_ctrl->offset,
        cipher_buf, cipher_len);
    knl_securec_check(ret);
    batch->encrypted = GS_TRUE;
    knl_panic_log(sizeof(log_batch_t) + plain_len == ctx->logwr_buf_pos,
        "the plain_len is abnormal, panic info: plain_len %u logwr_buf_pos %u", plain_len, ctx->logwr_buf_pos);
    ctx->logwr_buf_pos = sizeof(log_batch_t) + sizeof(cipher_ctrl_t) + cipher_len;
}

static log_batch_t *log_assemble_batch(knl_session_t *session, log_context_t *ctx)
{
    log_batch_t *batch = (log_batch_t *)ctx->logwr_buf;
    uint32 part_count = 0;
    uint32 spin_times = 0;
    bool8 handled[GS_MAX_LOG_BUFFERS] = { GS_FALSE };
    uint64 max_lsn = 0;

    uint32 fid = ctx->fid;
    batch->encrypted = GS_FALSE;
    ctx->log_encrypt = GS_FALSE;
    ctx->logwr_buf_pos = sizeof(log_batch_t);

    for (;;) {
        uint32 skip_count = 0;
        for (uint32 i = 0; i < ctx->buf_count; i++) {
            log_buffer_t *buf = &ctx->bufs[i].members[fid];

            if (handled[i]) {
                continue;
            }

            if (buf->value != 0) {
                skip_count++;
                continue;
            }

            cm_spin_lock(&buf->lock, &session->stat->spin_stat.stat_redo_buf);
            if (buf->value != 0) {
                cm_spin_unlock(&buf->lock);
                skip_count++;
                continue;
            }
            cm_spin_unlock(&buf->lock);

            if (buf->write_pos > 0) {
                log_assemble_buffer(ctx, buf, &max_lsn);
                spin_times = 0;
                part_count++;
            }

            handled[i] = GS_TRUE;
        }

        if (skip_count == 0) {
            break;
        }

        SPIN_STAT_INC(&session->stat->spin_stat.stat_redo_buf, spins);
        spin_times++;
        if (spin_times == GS_SPIN_COUNT) {
            cm_spin_sleep_and_stat(&session->stat->spin_stat.stat_redo_buf);
            spin_times = 0;
        }
    }

    batch->batch_session_cnt = ctx->batch_session_cnt;
    if (ctx->batch_session_cnt > 0) {
        uint32 sid_array_size = ctx->batch_session_cnt * sizeof(uint32);
        errno_t ret = memcpy_sp(ctx->logwr_buf + ctx->logwr_buf_pos, ctx->logwr_buf_size - ctx->logwr_buf_pos,
            (char *)ctx->batch_sids, sid_array_size);
        knl_securec_check(ret);

        ctx->logwr_buf_pos += sid_array_size;
        ctx->batch_session_cnt = 0;
    }

    if (ctx->log_encrypt) {
        log_encrypt(session, ctx);
    }
    batch->size = ctx->logwr_buf_pos + sizeof(log_batch_tail_t);
    batch->part_count = part_count;
    batch->scn = db_next_scn(session);
    batch->lsn = max_lsn;

    return batch;
}

bool32 log_need_flush(log_context_t *ctx)
{
    uint32 wid = ctx->wid;

    for (uint32 i = 0; i < ctx->buf_count; i++) {
        log_buffer_t *buf = &ctx->bufs[i].members[wid];

        if (buf->value != 0) {
            return GS_TRUE;
        }

        if (buf->write_pos != 0) {
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

void log_switch_buffer(knl_session_t *session, log_context_t *ctx)
{
    uint32 wid = ctx->wid;
    bool32 dbs_enabled = cm_dbs_is_enable_dbs();
    if (dbs_enabled) {
        for (uint32 i = 0; i < ctx->buf_count; i++) {
            log_buffer_t *buf = &ctx->bufs[i].members[wid];
            cm_spin_lock(&buf->lock, &session->stat->spin_stat.stat_redo_buf);
        }
    }

    ctx->wid = !ctx->wid;
    ctx->fid = !ctx->fid;

    if (dbs_enabled) {
        for (uint32 i = 0; i < ctx->buf_count; i++) {
            log_buffer_t *buf = &ctx->bufs[i].members[wid];
            cm_spin_unlock(&buf->lock);
        }
    }
}

status_t log_flush(knl_session_t *session, log_point_t *point, knl_scn_t *scn, uint64 *lsn)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    raft_context_t *raft_ctx = &session->kernel->raft_ctx;
    log_batch_t *new_batch = NULL;

    cm_spin_lock(&ctx->flush_lock, &session->stat->spin_stat.stat_log_flush);

    if (DB_NOT_READY(session) || DB_IS_READONLY(session)) {
        if (point != NULL && log_cmp_point(point, &ctx->curr_point) < 0) {
            *point = ctx->curr_point;
        }

        if (scn != NULL) {
            *scn = DB_CURR_SCN(session);
        }
        if (lsn != NULL) {
            *lsn = ctx->flushed_lsn;
        }
        cm_spin_unlock(&ctx->flush_lock);
        return GS_SUCCESS;
    }

    if (!log_need_flush(ctx)) {
        if (point != NULL && log_cmp_point(point, &ctx->curr_point) < 0) {
            *point = ctx->curr_point;
        }

        if (scn != NULL) {
            *scn = DB_CURR_SCN(session);
        }
        if (lsn != NULL) {
            *lsn = ctx->flushed_lsn;
        }
        cm_spin_unlock(&ctx->flush_lock);
        return GS_SUCCESS;
    }

    /* set next write buffer expected lfn */
    ctx->buf_lfn[ctx->fid] = ctx->lfn + GS_LOG_AREA_COUNT;

    /* switch write buffer */
    log_switch_buffer(session, ctx);

    log_batch_t *batch = log_assemble_batch(session, ctx);

    log_stat_prepare(ctx);

    if (!DB_IS_RAFT_ENABLED(session->kernel)) {
        log_flush_init(session, batch->size);
    } else {
        log_flush_init_for_raft(session, batch->size);
    }

    log_file_t *file = &ctx->files[ctx->curr_file];

    batch->head.magic_num = LOG_MAGIC_NUMBER;
    batch->head.point.lfn = DB_INC_LFN(ctx->lfn);
    batch->head.point.block_id = (uint32)(file->head.write_pos / file->ctrl->block_size);
    batch->head.point.asn = file->head.asn;
    batch->head.point.rst_id = file->head.rst_id;
    if (cm_dbs_is_enable_dbs() == GS_TRUE) {
        batch->head.point.lsn = batch->lsn;
    }
    log_batch_tail_t *tail = (log_batch_tail_t *)(ctx->logwr_buf + ctx->logwr_buf_pos);
    tail->magic_num = batch->head.magic_num;
    tail->point = batch->head.point;

    if (!DB_IS_RAFT_ENABLED(session->kernel)) {
        // do not reset raft_index in cluster mode
        if (!DB_IS_CLUSTER(session)) {
            batch->raft_index = RAFT_DEFAULT_INDEX;
        }

        if (log_flush_to_disk(session, ctx, batch) != GS_SUCCESS) {
            CM_ABORT_REASONABLE(0,
                "[LOG] ABORT INFO: flush redo filed, Flush batch %llu lsn %llu scn %llu head magic %llx point "
                "[%u-%u/%u/%llu] size %u space size %u for instance %u, freesize of ulog is %llu",
                (uint64)batch->head.point.lfn, batch->lsn, batch->scn, batch->head.magic_num, batch->head.point.rst_id,
                batch->head.point.asn, batch->head.point.block_id, (uint64)batch->head.point.lfn, batch->size,
                batch->space_size, session->kernel->id, ctx->free_size);
            cm_spin_unlock(&ctx->flush_lock);
            return GS_ERROR;
        }

        session->kernel->lfn = batch->head.point.lfn;
        if (session->kernel->lsnd_ctx.standby_num > 0) {
            lsnd_flush_log(session, ctx, file, batch);
        }
    } else {
        batch->raft_index = GS_INVALID_ID64;

        /* set batch->space_size inside raft_write_to_async_buffer */
        knl_panic_log(raft_ctx->status >= RAFT_STATUS_INITED, "the raft_ctx's status is abnormal.");
        if (raft_write_to_async_buffer_num(session, batch, &new_batch) != GS_SUCCESS) {
            cm_spin_unlock(&ctx->flush_lock);
            return GS_ERROR;
        }

        file->head.write_pos += batch->space_size;
        ctx->free_size -= batch->space_size;
        file->head.last = batch->scn;
        if (file->head.first == GS_INVALID_ID64) {
            file->head.first = batch->scn;
            log_flush_head(session, file);
        }

        raft_ctx->sent_lfn = batch->head.point.lfn;

        knl_panic_log(new_batch != NULL, "the new_batch is NULL.");
        if (raft_flush_log(session, new_batch) != GS_SUCCESS) {
            cm_spin_unlock(&ctx->flush_lock);
            return GS_ERROR;
        }
    }

    ctx->flushed_lfn = batch->head.point.lfn;
    ctx->curr_point = batch->head.point;
    ctx->curr_point.block_id += (uint32)(batch->space_size / file->ctrl->block_size);
    if (cm_dbs_is_enable_dbs() == GS_TRUE) {
        ctx->curr_point.lsn = batch->lsn;
    }
    ctx->curr_replay_point = ctx->curr_point;
    ckpt_set_trunc_point(session, &ctx->curr_point);
    gbp_queue_set_trunc_point(session, &ctx->curr_point);

    if (point != NULL && log_cmp_point(point, &ctx->curr_point) < 0) {
        *point = ctx->curr_point;
    }

    if (scn != NULL) {
        *scn = batch->scn;
    }
    if (lsn != NULL) {
        *lsn = batch->lsn;
    }

    knl_panic(ctx->flushed_lsn < batch->lsn || !cm_dbs_is_enable_dbs());
    ctx->flushed_lsn = batch->lsn;
    ctx->curr_scn = batch->scn;
    log_stat(ctx, batch->space_size);
    cm_spin_unlock(&ctx->flush_lock);
    GS_LOG_DEBUG_INF("[DTC RCY] Flush batch %llu lsn %llu scn %llu head magic %llx point [%u-%u/%u/%llu] size %u space size %u for instance %u",
                     (uint64)batch->head.point.lfn, batch->lsn, batch->scn, batch->head.magic_num,
                     batch->head.point.rst_id, batch->head.point.asn, batch->head.point.block_id,
                     (uint64)batch->head.point.lfn, batch->size, batch->space_size, session->kernel->id);
    return GS_SUCCESS;
}

void log_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    log_context_t *ctx = &session->kernel->redo_ctx;
    time_t flush_time = cm_current_time();
    uint32 flush_needed = GS_FALSE;

    cm_set_thread_name("lgwr");
    GS_LOG_RUN_INF("lgwr thread started");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());
    while (!thread->closed) {
        if (DB_NOT_READY(session)) {
            cm_sleep(200);
            continue;
        }

        if (DB_IS_READONLY(session)) {
            cm_sleep(200);
            continue;
        }

        uint32 wid = ctx->wid;

        for (uint32 i = 0; i < ctx->buf_count; i++) {
            if (ctx->bufs[i].members[wid].write_pos >= LOG_FLUSH_THRESHOLD) {
                flush_needed = GS_TRUE;
                break;
            }
        }

        if ((cm_current_time() - flush_time) < LOG_FLUSH_INTERVAL && !flush_needed) {
            cm_sleep(5);
            continue;
        }

        if (log_flush(session, NULL, NULL, NULL) != GS_SUCCESS) {
            KNL_SESSION_CLEAR_THREADID(session);
            CM_ABORT(0, "[LOG] ABORT INFO: redo log task flush redo file failed.");
        }

        flush_needed = GS_FALSE;
        flush_time = cm_current_time();
    }

    GS_LOG_RUN_INF("lgwr thread closed");
    KNL_SESSION_CLEAR_THREADID(session);
}

// important: this function ensures clean read-only after set SCN
void log_reset_readonly(buf_ctrl_t *ctrl)
{
#if !defined(__arm__) && !defined(__aarch64__)
    if (SECUREC_UNLIKELY(ctrl == NULL)) {
        return;
    }
#endif

    ctrl->is_readonly = 0;
}

static inline void log_calc_checksum(knl_session_t *session, page_head_t *page, uint32 checksum_level)
{
    if (checksum_level == (uint32)CKS_FULL) {
        page_calc_checksum(page, DEFAULT_PAGE_SIZE(session));
    }
}

void log_set_page_lsn(knl_session_t *session, uint64 lsn, uint64 lfn)
{
    for (uint32 i = 0; i < session->changed_count; i++) {
        buf_ctrl_t *ctrl = session->changed_pages[i];
        ctrl->lastest_lfn = lfn;

        DB_SET_LSN(ctrl->page->lsn, lsn);
        log_calc_checksum(session, ctrl->page, g_cks_level);

#ifdef __PROTECT_BUF__
        if (!IS_BLOCK_RECOVER(session)) {
            BUF_PROTECT_PAGE(ctrl->page);
        }
#endif

#if defined(__arm__) || defined(__aarch64__)
        CM_MFENCE;
#endif
        knl_panic(!DB_IS_CLUSTER(session) || DCS_BUF_CTRL_IS_OWNER(session, ctrl));
        log_reset_readonly(ctrl);
    }

    session->changed_count = 0;
}

static bool32 log_commit_try_lock(knl_session_t *session, log_context_t *ctx)
{
    for (;;) {
        if (session->log_progress == LOG_COMPLETED) {
            return GS_FALSE;
        }

        if (session->log_progress == LOG_PENDING) {
            if (cm_spin_try_lock(&ctx->commit_lock)) {
                if (session->log_progress == LOG_PENDING) {
                    return GS_TRUE;
                }
                cm_spin_unlock(&ctx->commit_lock);
            }
        }
        (void)cm_wait_cond(&session->commit_cond, 3);
    }
}

static void log_set_commit_progress(knl_session_t *begin, knl_session_t *end, log_progress_t log_progress)
{
    knl_session_t *next = NULL;
    knl_session_t *curr = begin;
    log_context_t *ctx = &curr->kernel->redo_ctx;

    for (;;) {
        next = curr->log_next;
#if defined(__arm__) || defined(__aarch64__)
        CM_MFENCE;
#endif

        if (log_progress == LOG_WAITING && curr->kernel->db.ctrl.core.lrep_mode == LOG_REPLICATION_ON) {
            ctx->batch_sids[ctx->batch_session_cnt] = curr->id;
            ctx->batch_session_cnt++;
        }
        curr->log_progress = log_progress;

        if (log_progress == LOG_COMPLETED) {
            cm_release_cond_signal(&curr->commit_cond);
        }

        if (curr == end) {
            break;
        }
        curr = next;
    }
}

static inline void log_wake_up_waiter(knl_session_t *session, log_context_t *ctx)
{
    cm_spin_lock(&ctx->tx_queue.lock, &session->stat->spin_stat.stat_commit_queue);
    knl_session_t *next_head = ctx->tx_queue.first;
    cm_spin_unlock(&ctx->tx_queue.lock);

    if (next_head != NULL) {
        cm_release_cond_signal(&next_head->commit_cond);
    }
}

static status_t log_commit_flush(knl_session_t *session)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    uint64 quorum_lfn = 0;

    if (!log_commit_try_lock(session, ctx)) {
        return GS_SUCCESS;
    }

    cm_spin_lock(&ctx->tx_queue.lock, &session->stat->spin_stat.stat_commit_queue);
    knl_session_t *begin = ctx->tx_queue.first;
    knl_session_t *end = ctx->tx_queue.last;
    ctx->tx_queue.first = NULL;
    cm_spin_unlock(&ctx->tx_queue.lock);

    log_set_commit_progress(begin, end, LOG_WAITING);

    if (log_flush(session, NULL, NULL, NULL) != GS_SUCCESS) {
        cm_spin_unlock(&ctx->commit_lock);
        log_wake_up_waiter(session, ctx);
        return GS_ERROR;
    }
    uint64 flushed_lfn = ctx->flushed_lfn;
    cm_spin_unlock(&ctx->commit_lock);
    log_wake_up_waiter(session, ctx);

    if (DB_IS_RAFT_ENABLED(session->kernel)) {
        knl_panic_log(session->kernel->raft_ctx.status == RAFT_STATUS_INITED, "the raft_ctx's status is abnormal.");
        raft_wait_for_batch_commit_in_raft(session, flushed_lfn);
    } else if (session->kernel->lsnd_ctx.standby_num > 0) {
        lsnd_wait(session, flushed_lfn, &quorum_lfn);

        if (quorum_lfn > 0) {
            cm_atomic_set((atomic_t *)&session->kernel->redo_ctx.quorum_lfn, (int64)quorum_lfn);
        }
    }
    log_set_commit_progress(begin, end, LOG_COMPLETED);

    return GS_SUCCESS;
}

static void log_commit_enque(knl_session_t *session)
{
    log_context_t *ctx = &session->kernel->redo_ctx;

    session->log_progress = LOG_PENDING;
    session->log_next = NULL;

    cm_spin_lock(&ctx->tx_queue.lock, &session->stat->spin_stat.stat_commit_queue);
    if (ctx->tx_queue.first == NULL) {
        ctx->tx_queue.first = session;
        ctx->tx_queue.last = session;
    } else {
        ctx->tx_queue.last->log_next = session;
        ctx->tx_queue.last = session;
    }
    cm_spin_unlock(&ctx->tx_queue.lock);
}

void log_commit(knl_session_t *session)
{
    uint64 quorum_lfn = 0;

    if (SECUREC_UNLIKELY(DB_NOT_READY(session))) {
        return;
    }

    knl_panic_log(!DB_IS_READONLY(session), "current DB is readonly.");

    if (session->commit_nowait) {
        session->stat->nowait_commits++;
        return;
    }

    if (session->curr_lfn <= session->kernel->redo_ctx.flushed_lfn) {
        if (DB_IS_RAFT_ENABLED(session->kernel)) {
            knl_panic_log(session->kernel->raft_ctx.status == RAFT_STATUS_INITED, "the raft_ctx status is abnormal.");
            raft_wait_for_batch_commit_in_raft(session, session->curr_lfn);
        } else if (session->kernel->lsnd_ctx.standby_num > 0) {
            lsnd_wait(session, session->curr_lfn, &quorum_lfn);

            if (quorum_lfn > 0) {
                cm_atomic_set((atomic_t *)&session->kernel->redo_ctx.quorum_lfn, (int64)quorum_lfn);
            }
        }
        return;
    }

    log_commit_enque(session);
    if (SECUREC_UNLIKELY(session->commit_batch)) {
        cm_sleep(GS_WAIT_FLUSH_TIME);
        if (session->log_progress == LOG_COMPLETED) {
            return;
        }
    }
    knl_begin_session_wait(session, LOG_FILE_SYNC, GS_TRUE);
    if (log_commit_flush(session) != GS_SUCCESS) {
        CM_ABORT(0, "[LOG] ABORT INFO: commit flush redo log failed");
    }
    knl_end_session_wait(session);
}

// copy redo log from session private buffer to kernel public buffer
static void log_copy(knl_session_t *session, log_buffer_t *buf, uint32 start_pos)
{
    knl_rm_t *rm = session->rm;
    log_group_t *group = (log_group_t *)session->log_buf;
    uint32 ori_group_size = group->size;

    // Update group size if having logic log before flushing log
    if (rm->need_copy_logic_log) {
        group->size += rm->logic_log_size;
    }

    uint32 remain_buf_size = buf->size - start_pos;
    errno_t ret = memcpy_sp(buf->addr + start_pos, remain_buf_size, session->log_buf, ori_group_size);
    knl_securec_check(ret);

    if (rm->need_copy_logic_log) {
        log_copy_logic_data(session, buf, start_pos + ori_group_size);
    }
}

static log_buffer_t *log_write_try_lock(knl_session_t *session, log_context_t *ctx)
{
    uint32 buf_id = session->id % ctx->buf_count;

    for (;;) {
        uint32 wid = ctx->wid;
        log_buffer_t *buf = &ctx->bufs[buf_id].members[wid];

        if (buf->value == LOG_BUF_SLOT_FULL) {
            cm_spin_sleep();
            continue;
        }

        cm_spin_lock(&buf->lock, &session->stat->spin_stat.stat_redo_buf);
        if (buf->value == LOG_BUF_SLOT_FULL) {
            cm_spin_unlock(&buf->lock);
            cm_spin_sleep();
            continue;
        }
        if (wid == ctx->wid) {
            session->curr_lfn = ctx->buf_lfn[wid];
            return buf;
        }
        cm_spin_unlock(&buf->lock);
        continue;
    }
}

static void log_write(knl_session_t *session)
{
    log_buffer_t *buf = NULL;
    uint8 cur_slot = 0;

    if (SECUREC_UNLIKELY(DB_NOT_READY(session))) {
        return;
    }
    knl_panic_log(!DB_IS_READONLY(session), "current DB is readonly.");

    log_group_t *group = (log_group_t *)session->log_buf;
    uint32 log_size = (!session->rm->need_copy_logic_log) ?
        group->size : (group->size + session->rm->logic_log_size);

    if (log_size <= sizeof(log_group_t)) {
        if (session->changed_count > 0) {
            /*
             * lsn is used to check if the page changed in btree split. for nologging table,
             * if page changed, there is no log recording, lsn should increase though.
             */
            session->curr_lsn = (uint64)DB_INC_LSN(session);
        }
        return;
    }

    group->rmid = session->rmid;
    group->opr_uid = (uint16)session->uid;
    uint32 total_size = (!session->rm->need_copy_logic_log) ?
                 group->size : (group->size + session->rm->logic_log_size);
    session->stat->atomic_opers++;
    session->stat->redo_bytes += group->size;

    if (SECUREC_UNLIKELY(session->kernel->switch_ctrl.request == SWITCH_REQ_DEMOTE)) {
        knl_panic(DB_IS_PRIMARY(&session->kernel->db) && session->kernel->switch_ctrl.state < SWITCH_WAIT_LOG_SYNC);
    }

    for (;;) {
        buf = log_write_try_lock(session, &session->kernel->redo_ctx);
        if (buf->size - buf->write_pos >= total_size) {
            break;
        }

        cm_spin_unlock(&buf->lock);

        if (log_flush(session, NULL, NULL, NULL) != GS_SUCCESS) {
            CM_ABORT(0, "[LOG] ABORT INFO: flush redo log failed");
        }

        continue;
    }

    /* lsn of groups that inside one log_buf, must be ordered, so it must be protected by spinlock */
    session->curr_lsn = (uint64)DB_INC_LSN(session);
    uint32 start_pos = buf->write_pos;
    buf->write_pos += total_size;

    if (SECUREC_UNLIKELY(session->log_encrypt)) {
        buf->log_encrypt = GS_TRUE;
    }
    for (uint8 i = 0; i < LOG_BUF_SLOT_COUNT; i++) {
        if (buf->slots[i] == 0) {
            buf->slots[i] = 1;
            cur_slot = i;
            break;
        }
    }

    group->lsn = session->curr_lsn;
    if (group->lsn > buf->lsn) {
        buf->lsn = group->lsn;
    }
    
    cm_spin_unlock(&buf->lock);

    log_copy(session, buf, start_pos);
    CM_MFENCE;
    buf->slots[cur_slot] = 0;
}

bool32 log_can_recycle(knl_session_t *session, log_file_t *file, arch_log_id_t *last_arch_log)
{
    bool32 is_archive = session->kernel->arch_ctx.is_archive;
    if (cm_dbs_is_enable_dbs() == GS_TRUE) {
        return GS_TRUE;
    }
    if (is_archive) {
        if (last_arch_log->asn == GS_INVALID_ASN) {
            /*
             * If archive thread has not archived any log file,
             * there is only one situation can we recycle log file:
             * The active log is invalid
             */
            knl_panic_log(last_arch_log->rst_id == 0, "the last_arch_log's rst_id is abnormal, panic info: rst_id %u",
                          last_arch_log->rst_id);
            if (file->head.asn != GS_INVALID_ASN) {
                return GS_FALSE;
            }
        } else {
            // Should not recycle log file if it is not archived
            if (file->head.asn > last_arch_log->asn ||
                (file->ctrl->status == LOG_FILE_ACTIVE && !file->ctrl->archived)) {
                return GS_FALSE;
            }
        }
    }
    return GS_TRUE;
}

static void log_recycle_ulog_space(knl_session_t *session, log_point_t *point)
{
    uint64_t free_size = 0;
    log_context_t *ctx = &session->kernel->redo_ctx;
    log_file_t *file = NULL;

    log_lock_logfile(session);
    file = &ctx->files[ctx->curr_file];
    timeval_t tv_begin;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_NS_TRUNCATE_ULOG, &tv_begin);
    free_size = cm_dbs_ulog_recycle(file->handle, point->lsn);
    if (free_size != 0) {
        ctx->free_size = free_size;
    }
    ctx->alerted = GS_FALSE;
    cantian_record_io_stat_end(IO_RECORD_EVENT_NS_TRUNCATE_ULOG, &tv_begin, IO_STAT_SUCCESS);
    log_unlock_logfile(session);
    return;
}

static log_point_t log_recycle_get_arch_point(knl_session_t *session, log_point_t *point)
{
    st_arch_log_record_id_t last_arch_log_record = {0};
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    bool32 is_archive = session->kernel->arch_ctx.is_archive;
    log_point_t recycle_point = {0};
    arch_proc_context_t *proc_ctx = NULL;
    uint32 dest = ARCH_DEFAULT_DEST;

    if (is_archive) {
        proc_ctx = &arch_ctx->arch_proc[dest - 1];
        last_arch_log_record = proc_ctx->last_archived_log_record;
        recycle_point.lsn = MIN(point->lsn, last_arch_log_record.end_lsn);
    } else {
        recycle_point.lsn = point->lsn;
    }
    GS_LOG_DEBUG_INF("[ARCH] point(%llu), end(%llu) recycle(%llu)", point->lsn,
                     last_arch_log_record.end_lsn, recycle_point.lsn);
    return recycle_point;
}

void log_recycle_file(knl_session_t *session, log_point_t *point)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    lrcv_context_t *lrcv = &session->kernel->lrcv_ctx;
    arch_log_id_t last_arch_log;
    log_point_t recycle_point;

    arch_last_archived_log(session, ARCH_DEFAULT_DEST, &last_arch_log);

    log_file_t *file = &ctx->files[ctx->active_file];

    if (!log_can_recycle(session, file, &last_arch_log) || lrcv->wait_info.waiting) {
        return;
    }

    GS_LOG_DEBUG_INF("try to recycle log file with last_arch_log [%u-%u] active[%d] file [%u-%u]",
                     last_arch_log.rst_id, last_arch_log.asn, ctx->active_file, file->head.rst_id, file->head.asn);
    if (cm_dbs_is_enable_dbs() == GS_TRUE) {
        recycle_point = log_recycle_get_arch_point(session, point);
        log_recycle_ulog_space(session, &recycle_point);
        return;
    }
    log_lock_logfile(session);
    uint32 file_id = ctx->active_file;
    while (LOG_POINT_FILE_LT(ctx->files[file_id].head, *point) || !DB_IS_PRIMARY(&session->kernel->db)) {
        file = &ctx->files[file_id];
        if ((file_id == ctx->curr_file) || (!log_can_recycle(session, file, &last_arch_log))) {
            break;
        }

        file->ctrl->status = LOG_FILE_INACTIVE;
        file->ctrl->archived = GS_FALSE;
        GS_LOG_RUN_INF("recycle log file[%u] [%u-%u] rcy_point [%u-%u]",
                       file_id, file->head.rst_id, file->head.asn, point->rst_id, point->asn);
        knl_panic(!session->kernel->arch_ctx.is_archive || file->head.asn <= last_arch_log.asn);
        knl_try_begin_session_wait(session, LOG_RECYCLE, GS_FALSE);
        cm_latch_x(&file->latch, session->id, NULL);
        file->head.asn = GS_INVALID_ASN;
        file->head.write_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
        file->arch_pos = 0;
        cm_unlatch(&file->latch, NULL);

        ctx->free_size += log_file_freesize(file);
        log_get_next_file(session, &file_id, GS_FALSE);

        ctx->active_file = file_id;
        dtc_my_ctrl(session)->log_first = file_id;

        if (db_save_log_ctrl(session, file_id, session->kernel->id) != GS_SUCCESS) {
            CM_ABORT(0, "[LOG] ABORT INFO: save core control file failed when recycling log file");
        }

        if (ctx->alerted) {
            ctx->alerted = GS_FALSE;
            GS_LOG_RUN_WAR("[LOG] Alert for checkpoint is cleared.");
        }
    }
    knl_try_end_session_wait(session, LOG_RECYCLE);
    log_unlock_logfile(session);
}

void log_reset_point(knl_session_t *session, log_point_t *point)
{
    log_context_t *ctx = &session->kernel->redo_ctx;

    cm_spin_lock(&ctx->flush_lock, &session->stat->spin_stat.stat_log_flush);
    ctx->curr_point = *point;
    cm_spin_unlock(&ctx->flush_lock);
}

void log_reset_analysis_point(knl_session_t *session, log_point_t *point)
{
    session->kernel->redo_ctx.curr_analysis_point = *point;
}

/*
 * find logfile with specified (rst_id, asn), return logfile id if found, else invalid id.
 * Notes:
 *   if return valid file id, file is latched, caller should release the latch explicit by calling `log_unlatch_file'.
 */
uint32 log_get_id_by_asn(knl_session_t *session, uint32 rst_id, uint32 asn, bool32 *is_curr_file)
{
    log_context_t *ctx = &session->kernel->redo_ctx;

    if (asn == GS_INVALID_ASN) {
        CM_SET_VALUE_IF_NOTNULL(is_curr_file, GS_FALSE);
        return GS_INVALID_ID32;
    }

    for (uint32 i = 0; i < ctx->logfile_hwm; i++) {
        log_file_t *file = &ctx->files[i];

        if (LOG_IS_DROPPED(file->ctrl->flg)) {
            continue;
        }

        if (file->head.rst_id != rst_id || file->head.asn != asn) {
            continue;
        }

        cm_latch_s(&file->latch, session->id, GS_FALSE, NULL);
        if (file->head.rst_id != rst_id || file->head.asn != asn) {
            cm_unlatch(&file->latch, NULL);
            continue;
        }

        CM_SET_VALUE_IF_NOTNULL(is_curr_file, (i == ctx->curr_file));
        return i;
    }

    CM_SET_VALUE_IF_NOTNULL(is_curr_file, GS_FALSE);
    return GS_INVALID_ID32;
}

void log_unlatch_file(knl_session_t *session, uint32 file_id)
{
    knl_panic_log(file_id < GS_MAX_LOG_FILES, "the file_id is abnormal, panic info: file_id %u", file_id);
    log_file_t *file = &session->kernel->redo_ctx.files[file_id];

    cm_unlatch(&file->latch, NULL);
}

void log_reset_file(knl_session_t *session, log_point_t *point)
{
    knl_instance_t *kernel = session->kernel;
    bak_context_t *bak_ctx = &kernel->backup_ctx;
    bak_t *bak = &bak_ctx->bak;
    log_context_t *ctx = &kernel->redo_ctx;

    if (!DB_IS_RAFT_ENABLED(session->kernel) && !DB_IS_PRIMARY(&kernel->db)) {
        return;
    }
    uint32 file_id = bak_log_get_id(session, bak->record.data_type, (uint32)point->rst_id, point->asn);
    if (file_id == GS_INVALID_ID32) {
        return;
    }

    /* if not last file, do not reset write_pos */
    if (DB_IS_RAFT_ENABLED(session->kernel) && file_id != ctx->curr_file) {
        log_unlatch_file(session, file_id);
        return;
    }

    log_file_t *file = &ctx->files[file_id];

    file->head.write_pos = (uint64)point->block_id * file->ctrl->block_size;
    ctx->free_size += log_file_freesize(file);
    log_unlatch_file(session, file_id);
}

// try to alerting for check point not completed
void log_try_alert(log_context_t *ctx)
{
    if (ctx->alerted) {
        return;
    }

    cm_spin_lock(&ctx->alert_lock, NULL);

    if (ctx->alerted) {
        cm_spin_unlock(&ctx->alert_lock);
        return;
    }

    ctx->alerted = GS_TRUE;
    cm_spin_unlock(&ctx->alert_lock);

    GS_LOG_RUN_WAR("checkpoint not completed, freesize of rlog is %llu.", ctx->free_size);
}

wait_event_t log_get_switch_wait_event(knl_session_t *session)
{
    arch_log_id_t last_arch_log;
    log_context_t *ctx = &session->kernel->redo_ctx;

    arch_last_archived_log(session, ARCH_DEFAULT_DEST, &last_arch_log);

    log_file_t *log_file = &ctx->files[ctx->active_file];
    if (!log_can_recycle(session, log_file, &last_arch_log)) {
        return LOG_FILE_SWITCH_ARCH;
    }

    return LOG_FILE_SWITCH_CKPT;
}

void log_atomic_op_begin(knl_session_t *session)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    log_group_t *group = (log_group_t *)session->log_buf;
    knl_panic_log(!session->atomic_op, "the atomic_op of session is true.");
    session->atomic_op = GS_TRUE;
    group->lsn = GS_INVALID_ID64;
    group->rmid = session->rmid;
    group->opr_uid = (uint16)session->uid;
    group->size = sizeof(log_group_t);
    group->nologging_insert = GS_FALSE;

    if (DB_NOT_READY(session)) {
        knl_panic_log(!session->kernel->db.ctrl.core.build_completed, "the core table is build_completed.");
        return;
    }

    knl_panic_log(!DB_IS_READONLY(session), "current DB is readonly.");

    wait_event_t wait_event = log_get_switch_wait_event(session);
    for (;;) {
        if (ctx->free_size > LOG_KEEP_SIZE(session, session->kernel)) {
            break;
        }
        knl_try_begin_session_wait(session, wait_event, GS_TRUE);
        log_try_alert(ctx);
        ckpt_trigger(session, GS_FALSE, CKPT_TRIGGER_INC);
        cm_sleep(200);
    }
    knl_try_end_session_wait(session, wait_event);

    knl_panic_log(session->page_stack.depth == 0, "page_stack's depth is abnormal, panic info: page_stack depth %u",
                  session->page_stack.depth);
    knl_panic_log(session->dirty_count == 0, "the dirty_count is abnormal, panic info: dirty_count %u",
                  session->dirty_count);
    knl_panic_log(session->changed_count == 0, "the changed_count is abnormal, panic info: changed_count %u",
                  session->changed_count);
}

void log_atomic_op_end(knl_session_t *session)
{
    log_group_t *group = (log_group_t *)session->log_buf;

    knl_panic_log(group->size > 0, "the group's size is abnormal, panic info: group size %u", group->size);
    knl_panic_log(session->atomic_op, "the session's atomic_op is false.");

    if (session->dirty_count > 0) {
        ckpt_enque_page(session);
    }

    if (SECUREC_UNLIKELY(session->gbp_dirty_count > 0)) {
        gbp_enque_pages(session);
    }
    log_write(session);

    if (session->changed_count > 0) {
        log_set_page_lsn(session, session->curr_lsn, session->curr_lfn);
    }

    group->size = 0;
    group->nologging_insert = GS_FALSE;
    session->log_encrypt = GS_FALSE;
    session->atomic_op = GS_FALSE;
}

void log_put_logic_data(knl_session_t *session, const void *data, uint32 size, uint8 flag)
{
    knl_rm_t *rm = session->rm;
    log_entry_t *entry = (log_entry_t *)(rm->logic_log_buf + rm->logic_log_size);
    char *logic_log_buf = NULL;
    uint32 log_buf_size = KNL_LOGIC_LOG_BUF_SIZE;
    errno_t ret;
    if (rm->logic_log_size + size + LOG_ENTRY_SIZE > KNL_LOGIC_LOG_BUF_SIZE) {
    // Shared storage writes more logical logs, log_buf maybe exceed 800 bytes.
        if (rm->large_page_id == GS_INVALID_ID32) {
            knl_begin_session_wait(session, LARGE_POOL_ALLOC, GS_FALSE);
            while (!mpool_try_alloc_page(session->kernel->attr.large_pool, &rm->large_page_id)) {
                cm_spin_sleep_and_stat2(1);
            }
            knl_end_session_wait(session);
        }
 
        logic_log_buf = mpool_page_addr(session->kernel->attr.large_pool, rm->large_page_id);
        if (rm->logic_log_size <= KNL_LOGIC_LOG_BUF_SIZE) {
            ret = memcpy_sp(logic_log_buf, GS_LARGE_PAGE_SIZE, rm->logic_log_buf, rm->logic_log_size);
            knl_securec_check(ret);
        }
        entry = (log_entry_t *)(logic_log_buf + rm->logic_log_size);
        log_buf_size = GS_LARGE_PAGE_SIZE;
        GS_LOG_RUN_INF("logic log buffer exceed 800 bytes，logic_log_size %u size %u", rm->logic_log_size,
                       size);
    }
    entry->type = RD_LOGIC_OPERATION;
    entry->size = (uint16)LOG_ENTRY_SIZE;
    entry->flag = flag;
    rm->logic_log_size += LOG_ENTRY_SIZE;

    if (size > 0) {
        uint32 remain_buf_size = log_buf_size - rm->logic_log_size;
        ret = memcpy_sp(entry->data, remain_buf_size, data, size);
        knl_securec_check(ret);
        entry->size += CM_ALIGN4(size);
        rm->logic_log_size += CM_ALIGN4(size);
    }

    session->log_entry = entry;
}

void log_copy_logic_data(knl_session_t *session, log_buffer_t *buf, uint32 start_pos)
{
    knl_rm_t *rm = session->rm;

    knl_panic_log(rm->logic_log_size > 0, "the logic_log_size is abnormal, panic info: logic_log_size %u",
                  rm->logic_log_size);
    knl_panic_log(rm->need_copy_logic_log, "the need_copy_logic_log is false.");

    uint32 remain_buf_size = buf->size - start_pos;
    if (rm->logic_log_size <= KNL_LOGIC_LOG_BUF_SIZE) {
        errno_t ret = memcpy_sp(buf->addr + start_pos, remain_buf_size, rm->logic_log_buf, rm->logic_log_size);
        knl_securec_check(ret);
    } else {
        knl_panic_log(rm->large_page_id != GS_INVALID_ID32, "the rm's large_page_id is invalid.");
        char *logic_log_buf = mpool_page_addr(session->kernel->attr.large_pool, rm->large_page_id);
        errno_t ret = memcpy_sp(buf->addr + start_pos, remain_buf_size, logic_log_buf, rm->logic_log_size);
        knl_securec_check(ret);
    }
    
    if (!DB_IS_CLUSTER(session)) {
        if (rm->large_page_id != GS_INVALID_ID32) {
            mpool_free_page(session->kernel->attr.large_pool, rm->large_page_id);
            rm->large_page_id = GS_INVALID_ID32;
        }
    }

    session->logic_log_size = rm->logic_log_size;
    rm->logic_log_size = 0;
    rm->need_copy_logic_log = GS_FALSE;
    session->log_entry = NULL;
}

void log_put(knl_session_t *session, log_type_t type, const void *data, uint32 size, uint8 flag)
{
    log_group_t *group = (log_group_t *)(session->log_buf);
    log_entry_t *entry = (log_entry_t *)(session->log_buf + group->size);

    if (DB_NOT_READY(session)) {
        knl_panic_log(!session->kernel->db.ctrl.core.build_completed,
                      "Attempt to generate log information when db is not ready.");
        return;
    }

    knl_panic_log(!DB_IS_READONLY(session), "current DB is readonly.");

    if (type == RD_LOGIC_OPERATION) {
        log_put_logic_data(session, data, size, flag);
        return;
    }

#ifdef LOG_DIAG
    if (session->log_diag) {
        (void)printf("WARNING : disable put log on recovery proc\n");
        return;
    }
#endif

    knl_panic_log(size + group->size + LOG_ENTRY_SIZE <= DEFAULT_PAGE_SIZE(session) * GS_PLOG_PAGES,
                  "the log size is abnormal, panic info: size %u group size %u", size, group->size);

    entry->type = type;
    entry->flag = flag;
    entry->size = (uint16)LOG_ENTRY_SIZE;
    group->size += (uint16)LOG_ENTRY_SIZE;

    if (size > 0) {
        uint32 remain_buf_size = DEFAULT_PAGE_SIZE(session) * GS_PLOG_PAGES - group->size;
        errno_t ret = memcpy_sp(entry->data, remain_buf_size, data, size);
        knl_securec_check(ret);
        entry->size += CM_ALIGN4(size);
        group->size += CM_ALIGN4(size);
    }

    session->log_entry = entry;
}

void log_append_data(knl_session_t *session, const void *data, uint32 size)
{
    knl_rm_t *rm = session->rm;
    log_group_t *group = (log_group_t *)(session->log_buf);
    log_entry_t *entry = (log_entry_t *)(session->log_entry);
    errno_t ret;

    if (DB_NOT_READY(session)) {
        return;
    }

    knl_panic_log(!DB_IS_READONLY(session), "current DB is readonly.");

#ifdef LOG_DIAG
    if (session->log_diag) {
        (void)printf("WARNING : disable append log on recovery proc\n");
        return;
    }
#endif

    if (entry->type == RD_LOGIC_OPERATION) {
        char *logic_log_buf = NULL;
        uint32 max_buf_len;

        if (rm->logic_log_size + size <= KNL_LOGIC_LOG_BUF_SIZE) {
            logic_log_buf = rm->logic_log_buf;
            max_buf_len = KNL_LOGIC_LOG_BUF_SIZE;
        } else {
            if (rm->large_page_id == GS_INVALID_ID32) {
                knl_begin_session_wait(session, LARGE_POOL_ALLOC, GS_FALSE);
                while (!mpool_try_alloc_page(session->kernel->attr.large_pool, &rm->large_page_id)) {
                    cm_spin_sleep_and_stat2(1);
                }
                knl_end_session_wait(session);
            }

            logic_log_buf = mpool_page_addr(session->kernel->attr.large_pool, rm->large_page_id);
            if (rm->logic_log_size > 0) {
                ret = memcpy_sp(logic_log_buf, GS_LARGE_PAGE_SIZE, rm->logic_log_buf, rm->logic_log_size);
                knl_securec_check(ret);
            }
            max_buf_len = GS_LARGE_PAGE_SIZE;
            entry = (log_entry_t *)logic_log_buf;
            session->log_entry = entry;
        }

        ret = memcpy_sp(logic_log_buf + rm->logic_log_size, max_buf_len - rm->logic_log_size, data, size);
        knl_securec_check(ret);
        entry->size += CM_ALIGN4(size);
        rm->logic_log_size += CM_ALIGN4(size);
    } else {
        knl_panic_log(size + group->size <= DEFAULT_PAGE_SIZE(session) * GS_PLOG_PAGES,
                      "the log size is abnormal, panic info: size %u group size %u", size, group->size);

        uint32 remain_buf_size = DEFAULT_PAGE_SIZE(session) * GS_PLOG_PAGES - group->size;
        ret = memcpy_sp(session->log_buf + group->size, remain_buf_size, data, size);
        knl_securec_check(ret);
        entry->size += CM_ALIGN4(size);
        group->size += CM_ALIGN4(size);
    }
}

uint32 log_get_free_count(knl_session_t *session)
{
    uint32 next;
    uint32 count = 0;

    log_get_next_file(session, &next, GS_TRUE);
    while (next != session->kernel->redo_ctx.active_file) {
        ++count;
        log_get_next_file(session, &next, GS_FALSE);
    }
    return count;
}

void log_get_next_file(knl_session_t *session, uint32 *next, bool32 use_curr)
{
    log_context_t *ctx = &session->kernel->redo_ctx;

    if (use_curr) {
        *next = ctx->curr_file;
    }

    for (;;) {
        CM_CYCLED_MOVE_NEXT(ctx->logfile_hwm, *next);
        log_file_t *logfile = &ctx->files[*next];
        if (!LOG_IS_DROPPED(logfile->ctrl->flg)) {
            break;
        }
    }
}

status_t log_switch_keep_hb(callback_t *callback, time_t *last_send_time)
{
    time_t now = cm_current_time();

    if (callback != NULL && callback->keep_hb_entry != NULL) {
        if ((now - *last_send_time) >= REPL_HEART_BEAT_CHECK) {
            if (callback->keep_hb_entry(callback->keep_hb_param) != GS_SUCCESS) {
                return GS_ERROR;
            }
            *last_send_time = now;
        }
    }
    return GS_SUCCESS;
}

static inline bool32 log_switch_finished(uint16 spec_file_id, uint32 spec_asn, uint16 file_id, uint32 file_asn)
{
    if (spec_file_id == GS_INVALID_FILEID || spec_asn == GS_INVALID_ASN ||
        (file_id == spec_file_id && file_asn == spec_asn)) {
        return GS_TRUE;
    }

    return GS_FALSE;
}

static inline bool32 log_fileid_asn_mismatch(log_context_t *ctx, uint16 spec_fileid, uint32 spec_asn, uint32 next)
{
    if (spec_fileid == GS_INVALID_FILEID || spec_asn == GS_INVALID_ASN) {
        return GS_FALSE;
    }

    log_file_t *file = &ctx->files[ctx->curr_file];
    uint32 next_asn = file->head.asn + 1;

    if (spec_asn == next_asn && next != spec_fileid) {
        GS_THROW_ERROR(ERR_SWITCH_LOGFILE, "asn %u located in different fileid %u/%u on peer node and local node",
            spec_asn, spec_fileid, next);
        GS_LOG_RUN_ERR("[LOG] asn %u located in different fileid %u/%u on peer node and local node, "
                       "perhaps the add/drop logfile has not been replayed", spec_asn, spec_fileid, next);
        return GS_TRUE;
    }

    return GS_FALSE;
}

bool32 log_switch_need_wait(knl_session_t *session, uint16 spec_file_id, uint32 spec_asn)
{
    log_context_t *log = &session->kernel->redo_ctx;
    uint32 curr_asn;

    log_lock_logfile(session);
    uint32 next_asn = log->files[log->curr_file].head.asn;
    uint32 next_file = log->curr_file;

    for (;;) {
        curr_asn = next_asn;
        log_get_next_file(session, &next_file, GS_FALSE);
        next_asn = curr_asn + 1;

        if (spec_asn == next_asn && next_file != spec_file_id) {
            log_unlock_logfile(session);
            return GS_TRUE;
        }

        if (log_switch_finished(spec_file_id, spec_asn, next_file, next_asn)) {
            break;
        }
    }

    log_unlock_logfile(session);
    return GS_FALSE;
}

/*
 * switch logfile will not stop until final current file id equal to spec_file_id and file asn equal to spec_asn
 */
status_t log_switch_logfile(knl_session_t *session, uint16 spec_file_id, uint32 spec_asn, callback_t *callback)
{
    status_t status;
    uint32 next;
    log_context_t *log = &session->kernel->redo_ctx;
    time_t last_send_time = cm_current_time();
    bool32 need_skip = GS_FALSE;

    log_lock_logfile(session);

    if (DB_IS_RAFT_ENABLED(session->kernel) && (session->kernel->raft_ctx.status >= RAFT_STATUS_INITED)) {
        raft_wait_for_log_flush(session, session->kernel->raft_ctx.sent_lfn);
    }

    log_file_t *file = &log->files[log->curr_file];
    if (file->head.write_pos == CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size)) {
        if (log_switch_finished(spec_file_id, spec_asn, log->curr_file, file->head.asn)) {
            log_unlock_logfile(session);
            return GS_SUCCESS;
        }

        need_skip = GS_TRUE;
        GS_LOG_RUN_INF("[LOG] Switch log, need to skip file %u asn %u state %d",
                       log->curr_file, file->head.asn, file->ctrl->status);
    }

    log_unlock_logfile(session);

    for (;;) {
        log_get_next_file(session, &next, GS_TRUE);
        while (next == log->active_file) {
            ckpt_trigger(session, GS_FALSE, CKPT_TRIGGER_INC);
            cm_sleep(1);

            if (session->killed) {
                GS_THROW_ERROR(ERR_OPERATION_KILLED);
                return GS_ERROR;
            }

            if (log_switch_keep_hb(callback, &last_send_time) != GS_SUCCESS) {
                GS_THROW_ERROR(ERR_SWITCH_LOGFILE, "the standby failed to send heart beat message to primary");
                return GS_ERROR;
            }

            log_get_next_file(session, &next, GS_TRUE);
        }

        if (log_fileid_asn_mismatch(log, spec_file_id, spec_asn, next)) {
            return GS_ERROR;
        }

        log_lock_logfile(session);

        if (DB_IS_RAFT_ENABLED(session->kernel) && (session->kernel->raft_ctx.status >= RAFT_STATUS_INITED)) {
            raft_wait_for_log_flush(session, session->kernel->raft_ctx.sent_lfn);
        }

        file = &log->files[log->curr_file];
        if (file->head.write_pos == CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size)) {
            if (spec_file_id == GS_INVALID_FILEID || spec_asn == GS_INVALID_ASN) {
                log_unlock_logfile(session);
                return GS_SUCCESS;
            }
        }

        log_get_next_file(session, &next, GS_TRUE);
        if (next == log->active_file) {
            log_unlock_logfile(session);
            continue;
        }

        uint16 pre_fileid = log->curr_file;
        file = &log->files[log->curr_file];
        if (DB_NOT_READY(session) && log_repair_file_offset(session, file) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_SWITCH_LOGFILE, "repair current log offset failed");
            log_unlock_logfile(session);
            return GS_ERROR;
        }
        log_flush_head(session, file);
        status = log_switch_file(session);
        log->alerted = GS_FALSE;

        if (need_skip) {
            file = &log->files[pre_fileid];
            file->head.asn = GS_INVALID_ASN;
            file->ctrl->status = LOG_FILE_INACTIVE;
            file->ctrl->archived = GS_FALSE;
            log_flush_head(session, file);
            if (db_save_log_ctrl(session, pre_fileid, session->kernel->id) != GS_SUCCESS) {
                CM_ABORT(0, "[LOG] ABORT INFO: save control space file failed when switch log file");
            }
        }

        file = &log->files[log->curr_file];
        if (status == GS_SUCCESS && !log_switch_finished(spec_file_id, spec_asn, log->curr_file, file->head.asn)) {
            need_skip = GS_TRUE;
            log_unlock_logfile(session);
            GS_LOG_RUN_INF("[LOG] Switch log, need to skip file %u asn %u state %d",
                           log->curr_file, file->head.asn, file->ctrl->status);
            continue;
        }

        log_unlock_logfile(session);

        return status;
    }
}

void log_add_freesize(knl_session_t *session, uint32 inx)
{
    log_context_t *ctx = &session->kernel->redo_ctx;

    if (log_file_not_used(ctx, inx)) {
        log_file_t *logfile = &ctx->files[inx];
        ctx->free_size += log_file_freesize(logfile);
    }
}

void log_decrease_freesize(log_context_t *ctx, log_file_t *logfile)
{
    ctx->free_size -= log_file_freesize(logfile);
}

bool32 log_file_can_drop(log_context_t *ctx, uint32 file)
{
    return log_file_not_used(ctx, file);
}

status_t log_check_blocksize(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    log_context_t *ctx = &kernel->redo_ctx;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);

    ctx->logfile_hwm = logfile_set->logfile_hwm;
    ctx->files = logfile_set->items;
    int64 blocksize = ctx->files[0].ctrl->block_size;
    for (uint32 i = 0; i < ctx->logfile_hwm; i++) {
        log_file_t *file = &ctx->files[i];
        if (!LOG_IS_DROPPED(file->ctrl->flg) && file->ctrl->block_size != blocksize) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t log_check_minsize(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);
    int64 min_size = (int64)LOG_MIN_SIZE(session, kernel);

    for (uint32 i = 0; i < logfile_set->logfile_hwm; i++) {
        log_file_t *file = &logfile_set->items[i];
        if (!LOG_IS_DROPPED(file->ctrl->flg) && file->ctrl->size <= min_size) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t log_get_first_batch_lfn(knl_session_t *session, log_file_t *logfile, uint64 *first_batch_lfn)
{
    uint32 log_head_size = CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size);
    aligned_buf_t log_buf;

    if (cm_aligned_malloc(GS_MAX_BATCH_SIZE, "log buffer", &log_buf) != GS_SUCCESS) {
        return GS_ERROR;
    }
    int64 size = logfile->ctrl->size - log_head_size;
    size = (size > GS_MAX_BATCH_SIZE) ? GS_MAX_BATCH_SIZE : size;
    if (cm_read_device(logfile->ctrl->type, logfile->handle, log_head_size,
        log_buf.aligned_buf, (int32)size) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[LOG] failed to read %s ", logfile->ctrl->name);
        cm_aligned_free(&log_buf);
        return GS_ERROR;
    }

    log_batch_t *batch = (log_batch_t *)log_buf.aligned_buf;
    log_batch_tail_t *tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));
    if (!rcy_validate_batch(batch, tail)) {
        GS_LOG_RUN_INF("[LOG] %s may be new or corrupted, first batch size %u head [%llu/%llu/%llu] tail [%llu/%llu]",
            logfile->ctrl->name, batch->size, batch->head.magic_num, (uint64)batch->head.point.lfn, batch->raft_index,
            tail->magic_num, (uint64)tail->point.lfn);
        cm_aligned_free(&log_buf);
        return GS_ERROR;
    }

    *first_batch_lfn = batch->head.point.lfn;
    cm_aligned_free(&log_buf);
    return GS_SUCCESS;
}

static bool32 log_lfn_is_effective(knl_session_t *session, log_file_t *logfile)
{
    log_point_t rcy_point = dtc_my_ctrl(session)->rcy_point;
    uint64 first_batch_lfn;

    if (log_get_first_batch_lfn(session, logfile, &first_batch_lfn) != GS_SUCCESS) {
        return GS_FALSE;
    }

    if (first_batch_lfn < rcy_point.lfn) {
        return (logfile->head.asn == rcy_point.asn);
    }

    return GS_TRUE;
}

// After restore, only arch log will be replayed, online logfile is empty, so rcy point not in online log
static bool32 rcy_point_belong_previous_log(log_file_t *logfile, log_point_t rcy_point)
{
    if (rcy_point.block_id <= 1) {
        // after pitr restore, rcy block_id must be 1, and rcy asn maybe reset to curr asn
        return (bool32)((logfile->head.asn == rcy_point.asn + 1) || (logfile->head.asn == rcy_point.asn));
    }
    // after normal restore, rcy asn is curr asn - 1
    return (bool32)(logfile->head.asn == rcy_point.asn + 1);
}

static bool32 log_current_asn_is_correct(knl_session_t *session, log_file_t *logfile, uint64 *first_batch_lfn)
{
    log_point_t rcy_point = dtc_my_ctrl(session)->rcy_point;
    bool32 real_empty = log_is_empty(&logfile->head) && !log_lfn_is_effective(session, logfile);
    if (real_empty) {
        // After backup, restore and recover database, current log is first active log and is empty,
        // but rcy_point must be in the previous log of the current log.
        if (logfile->head.asn > GS_FIRST_ASN) {
            return rcy_point_belong_previous_log(logfile, rcy_point);
        }
        return (bool32)(logfile->head.asn == rcy_point.asn);
    }

    if (log_get_first_batch_lfn(session, logfile, first_batch_lfn) != GS_SUCCESS) {
        return GS_FALSE;
    }
    // After installation, rcy_point.lfn maybe 0, first batch lfn of current log is 1,
    // but rcy_point is in the current log
    if (rcy_point.lfn != 0 && LFN_IS_CONTINUOUS(*first_batch_lfn, rcy_point.lfn)) {
        return rcy_point_belong_previous_log(logfile, rcy_point);
    }

    // When the standby switchover to primary, rcy_point may be in the archived log.
    bool32 is_archive = session->kernel->db.ctrl.core.log_mode == ARCHIVE_LOG_ON;
    arch_log_id_t last_arch_log = session->kernel->arch_ctx.arch_proc[0].last_archived_log;
    if (rcy_point.asn < logfile->head.asn) {
        return (is_archive && logfile->head.asn == last_arch_log.asn + 1);
    }

    return (bool32)(logfile->head.asn == rcy_point.asn);
}

static status_t log_check_active_log_asn(knl_session_t *session, uint32 *pre_asn)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    *pre_asn = ctx->files[ctx->active_file].head.asn;
    uint32 file_id = ctx->active_file;
    log_file_t *logfile = NULL;

    while (file_id != ctx->curr_file) {
        logfile = &ctx->files[file_id];
        if (logfile->ctrl->status == LOG_FILE_UNUSED) {
            log_get_next_file(session, &file_id, GS_FALSE);
            continue;
        }
        if (logfile->head.asn == GS_INVALID_ASN) {
            GS_LOG_RUN_ERR("[LOG] asn of redo log %s is invalid", logfile->ctrl->name);
            return GS_ERROR;
        }

        if (file_id != ctx->active_file && *pre_asn != GS_INVALID_ASN && logfile->head.asn != *pre_asn + 1) {
            GS_LOG_RUN_ERR("[LOG] redo log asn are not continuous, %s asn: %u, previous log asn: %u",
                logfile->ctrl->name, logfile->head.asn, *pre_asn);
            return GS_ERROR;
        }

        *pre_asn = logfile->head.asn;
        log_get_next_file(session, &file_id, GS_FALSE);
    }
    return GS_SUCCESS;
}

/*
 * Check if asn is normal:
 * 1.Rcy_point is usually in the the log between first active and current logs.
      When the standby switchover to primary, rcy_point may be in the archived log.
 * 2.Asn of active and current redo logs must be valid and continuous.
 * 3.If first active log is also current log, rcy_point must be in the current log or the previous log of current log.
 */
status_t log_check_asn(knl_session_t *session, bool32 force_ignorlog)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    log_point_t rcy_point = dtc_my_ctrl(session)->rcy_point;

    if (LOG_SKIP_CHECK_ASN(session->kernel, force_ignorlog)) {
        return GS_SUCCESS;
    }

    if (ctx->active_file == ctx->curr_file) {
        log_file_t *logfile = &ctx->files[ctx->curr_file];
        if (logfile->ctrl->type == DEV_TYPE_ULOG) {
            return GS_SUCCESS;
        }
        uint64 first_batch_lfn = 0;
        if (!log_current_asn_is_correct(session, logfile, &first_batch_lfn)) {
            GS_LOG_RUN_ERR("[LOG] check asn of redo log %s failed, logfile [%u-%u/%llu], "
                "first batch lfn: %llu, rcy_point [%llu-%u-%llu]",
                logfile->ctrl->name, logfile->head.rst_id, logfile->head.asn, logfile->head.write_pos,
                first_batch_lfn, (uint64)rcy_point.rst_id, rcy_point.asn, (uint64)rcy_point.lfn);
            return GS_ERROR;
        }
        return GS_SUCCESS;
    }

    uint32 last_active_asn;
    if (log_check_active_log_asn(session, &last_active_asn) != GS_SUCCESS) {
        return GS_ERROR;
    }

    log_file_t *logfile = &ctx->files[ctx->curr_file];
    if (logfile->head.asn != last_active_asn + 1) {
        GS_LOG_RUN_ERR("[LOG] redo log asn are not continuous, %s asn: %u, previous log asn: %u",
            logfile->ctrl->name, logfile->head.asn, last_active_asn);
        return GS_ERROR;
    }

    /*
     * When the standby switchover to primary, rcy_point may be in the archived log.
     * In this case, inactive logs must be archived, active logs may or may not be archived.
     */
    bool32 is_archive = session->kernel->db.ctrl.core.log_mode == ARCHIVE_LOG_ON;
    arch_log_id_t last_arch_log = session->kernel->arch_ctx.arch_proc[0].last_archived_log;
    if ((rcy_point.asn < ctx->files[ctx->active_file].head.asn &&
        !(is_archive && last_arch_log.asn >= ctx->files[ctx->active_file].head.asn - 1)) ||
        rcy_point.asn > logfile->head.asn) {
        GS_LOG_RUN_ERR("[LOG] check log asn failed, rcy_point[%u], online log start[%u] end[%u], last arch log[%u]",
            rcy_point.asn, ctx->files[ctx->active_file].head.asn, logfile->head.asn, last_arch_log.asn);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

uint32 log_get_count(knl_session_t *session)
{
    uint32 count = 0;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);
    uint32 hwm = logfile_set->logfile_hwm;
    for (uint32 i = 0; i < hwm; i++) {
        log_file_t *logfile = &logfile_set->items[i];

        if (!LOG_IS_DROPPED(logfile->ctrl->flg)) {
            count++;
        }
    }

    return count;
}

bool32 log_point_equal(log_point_t *point, log_context_t *redo_ctx)
{
    log_file_t *curr_file = &redo_ctx->files[redo_ctx->curr_file];
    uint32 block_id = point->block_id;

    if (block_id == 0) {
        block_id = 1;
    }

    bool32 is_equal = ((point->rst_id == curr_file->head.rst_id) && (point->asn == curr_file->head.asn) &&
                ((uint64)block_id * curr_file->ctrl->block_size >= curr_file->head.write_pos));
    return is_equal;
}

void log_get_curr_rstid_asn(knl_session_t *session, uint32 *rst_id, uint32 *asn)
{
    *rst_id = (uint32)session->kernel->redo_ctx.curr_point.rst_id;
    *asn = session->kernel->redo_ctx.curr_point.asn;
}

status_t log_set_file_asn(knl_session_t *session, uint32 asn, uint32 log_first)
{
    database_t *db = &session->kernel->db;
    core_ctrl_t *core = &db->ctrl.core;
    log_context_t *ctx = &session->kernel->redo_ctx;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);
    log_file_ctrl_t *log_file = logfile_set->items[dtc_my_ctrl(session)->log_first].ctrl;
    log_file_head_t tmp_head;
    log_file_head_t *head = &tmp_head;
    int32 handle = GS_INVALID_HANDLE;

    if (cm_open_device(log_file->name, log_file->type, knl_redo_io_flag(session), &handle) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] failed to open %s", log_file->name);
        return GS_ERROR;
    }

    if (cm_read_device(log_file->type, handle, 0, ctx->logwr_head_buf,
        CM_CALC_ALIGN(sizeof(log_file_head_t), log_file->block_size)) != GS_SUCCESS) {
        cm_close_device(log_file->type, &handle);
        GS_LOG_RUN_ERR("[BACKUP] failed to read log head %s", log_file->name);
        return GS_ERROR;
    }

    errno_t ret = memcpy_sp(head, sizeof(log_file_head_t), ctx->logwr_head_buf, sizeof(log_file_head_t));
    knl_securec_check(ret);

    if (log_first == GS_INVALID_ID32) {
        head->first = GS_INVALID_ID64;
        head->last = GS_INVALID_ID64;
        head->write_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), log_file->block_size);
    }
    head->asn = asn;
    head->block_size = log_file->block_size;
    head->rst_id = core->resetlogs.rst_id;
    head->cmp_algorithm = COMPRESS_NONE;
    log_calc_head_checksum(session, head);

    ret = memcpy_sp(ctx->logwr_head_buf, log_file->block_size, head, sizeof(log_file_head_t));
    knl_securec_check(ret);

    if (cm_write_device(log_file->type, handle, 0, ctx->logwr_head_buf,
                        CM_CALC_ALIGN(sizeof(log_file_head_t), log_file->block_size)) != GS_SUCCESS) {
        cm_close_device(log_file->type, &handle);
        GS_LOG_RUN_ERR("[BACKUP] failed to write %s", log_file->name);
        return GS_ERROR;
    }

    cm_close_device(log_file->type, &handle);
    return GS_SUCCESS;
}

void log_reset_log_head(knl_session_t *session, log_file_t *logfile)
{
    errno_t ret = memset_s(&logfile->head, sizeof(log_file_head_t), 0, sizeof(log_file_head_t));
    knl_securec_check(ret);
    log_flush_head(session, logfile);
}

status_t log_reset_logfile(knl_session_t *session, uint32 asn, uint32 log_first)
{
    uint32 curr = log_first;

    for (uint32 i = 0; i < dtc_my_ctrl(session)->log_hwm; i++) {
        log_file_t *logfile = &MY_LOGFILE_SET(session)->items[i];
        log_file_ctrl_t *logfile_ctrl = logfile->ctrl;
        if (LOG_IS_DROPPED(logfile_ctrl->flg)) {
            logfile_ctrl->status = LOG_FILE_INACTIVE;
            continue;
        }

        if (curr == GS_INVALID_ID32 || curr == i) {
            curr = i;
            dtc_my_ctrl(session)->log_first = i;
            dtc_my_ctrl(session)->log_last = i;
            logfile_ctrl->status = LOG_FILE_CURRENT;
        } else {
            logfile_ctrl->status = LOG_FILE_INACTIVE;
        }

        logfile_ctrl->archived = GS_FALSE;
        if (db_save_log_ctrl(session, i, session->kernel->id) != GS_SUCCESS) {
            CM_ABORT(0, "[BACKUP] ABORT INFO: save core control file failed when restore log files");
        }
    }

    knl_panic_log(curr < dtc_my_ctrl(session)->log_hwm,
                  "curr position is more than core's log_hwm, panic info: curr position %u log_hwm %u", curr,
                  dtc_my_ctrl(session)->log_hwm);

    if (log_set_file_asn(session, asn, log_first) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void log_reset_inactive_head(knl_session_t *session)
{
    for (uint32 i = 0; i < dtc_my_ctrl(session)->log_hwm; i++) {
        log_file_t *logfile = &MY_LOGFILE_SET(session)->items[i];

        if (LOG_IS_DROPPED(logfile->ctrl->flg)) {
            continue;
        }

        if (logfile->ctrl->status == LOG_FILE_INACTIVE) {
            log_reset_log_head(session, logfile);
        }
    }
}

status_t log_prepare_for_pitr(knl_session_t *se)
{
    arch_ctrl_t *last = arch_get_last_log(se);
    uint32 rst_id = se->kernel->db.ctrl.core.resetlogs.rst_id;
    uint32 archive_asn = last->asn + 1;

    if (arch_try_regist_archive(se, rst_id, &archive_asn) != GS_SUCCESS) {
        return GS_ERROR;
    }

    uint32 max_asn;
    if (arch_try_arch_redo(se, &max_asn) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (max_asn >= archive_asn) {
        archive_asn = max_asn + 1;
    }

    if (log_reset_logfile(se, archive_asn, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }
    log_reset_inactive_head(se);

    return GS_SUCCESS;
}

bool32 log_need_realloc_buf(log_batch_t *batch, aligned_buf_t *buf, const char *name, int64 new_size)
{
    if (batch->head.magic_num != LOG_MAGIC_NUMBER) {
        return GS_FALSE;
    }
    if (batch->space_size > GS_MAX_BATCH_SIZE) {
        return GS_FALSE;
    }
    if (batch->space_size <= buf->buf_size) {
        return GS_FALSE;
    }

    if (cm_aligned_realloc(new_size, name, buf) != GS_SUCCESS) {
        CM_ABORT(0, "ABORT INFO: malloc redo buf fail.");
    }
    return GS_TRUE;
}

status_t log_get_file_offset(knl_session_t *session, const char *file_name, aligned_buf_t *buf, uint64 *offset,
    uint64 *latest_lfn, uint64 *last_scn)
{
    log_file_head_t head;
    int32 handle = GS_INVALID_HANDLE;
    bool32 finished = GS_FALSE;
    uint64 size, remain_size;
    char *read_buf = buf->aligned_buf;
    uint64 buf_size = buf->buf_size;
    bool32 first_batch = GS_TRUE;
    device_type_t type = cm_device_type(file_name);

    if (log_get_file_head(file_name, &head) != GS_SUCCESS) {
        return GS_ERROR;
    }

    bool32 compressed = (head.cmp_algorithm == COMPRESS_ZSTD);
    if (cm_open_device(file_name, type, knl_arch_io_flag(session, compressed), &handle) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[LOG] failed to open %s ", file_name);
        return GS_ERROR;
    }

    int64 file_size = cm_file_size(handle);
    if (file_size == -1) {
        cm_close_file(handle);
        GS_LOG_RUN_ERR("[LOG] failed to get %s size ", file_name);
        GS_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_END, errno);
        return GS_ERROR;
    }

    *offset = CM_CALC_ALIGN(sizeof(log_file_head_t), (uint32)head.block_size);
    *last_scn = GS_INVALID_ID64;
    *latest_lfn = 0;

    while (1) {
        size = (uint64)file_size - *offset;
        size = size > buf_size ? buf_size : size;
        if (finished || size == 0) {
            break;
        }

        if (cm_read_device(type, handle, *offset, read_buf, size) != GS_SUCCESS) {
            cm_close_device(type, &handle);
            return GS_ERROR;
        }

        log_batch_t *batch = (log_batch_t *)read_buf;
        if (log_need_realloc_buf(batch, buf, "log buffer", GS_MAX_BATCH_SIZE + SIZE_K(4))) {
            read_buf = buf->aligned_buf;
            buf_size = buf->buf_size;
            continue;
        }
        log_batch_tail_t *tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));

        if (first_batch && !DB_IS_RAFT_ENABLED(session->kernel) &&
            (batch->head.point.asn != head.asn || batch->head.point.rst_id != head.rst_id)) {
            *offset = CM_CALC_ALIGN(sizeof(log_file_head_t), (uint32)head.block_size);
            cm_close_file(handle);
            GS_LOG_RUN_INF("[LOG] no need to repair file offset for %s, "
                           "batch rstid/asn [%u/%u], file head rstid/asn [%u/%u]",
                           file_name, batch->head.point.rst_id, batch->head.point.asn, head.rst_id, head.asn);
            return GS_SUCCESS;
        }

        remain_size = size;
        while (remain_size >= sizeof(log_batch_t)) {
            if (remain_size < batch->space_size || !rcy_validate_batch(batch, tail) ||
                batch->head.point.rst_id != head.rst_id ||
                (*latest_lfn != 0 && batch->head.point.lfn != *latest_lfn + 1)) {
                finished = GS_TRUE;
                GS_LOG_RUN_INF("[LOG] log %s [%u-%u] offset %llu invalid batch size %u "
                               "head [%llu/%u-%u/%llu/%llu] latest_lfn %llu",
                               file_name, head.rst_id, head.asn, *offset, batch->size, batch->head.magic_num,
                               batch->head.point.rst_id, batch->head.point.asn,
                               (uint64)batch->head.point.lfn, batch->raft_index, *latest_lfn);

                break;
            }

            first_batch = GS_FALSE;
            *latest_lfn = batch->head.point.lfn;
            *last_scn = batch->scn;
            *offset += batch->space_size;
            remain_size -= batch->space_size;
            batch = (log_batch_t *)((char *)batch + batch->space_size);
            tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));
            if (remain_size < batch->space_size) {
                break;
            }
        }
    }

    cm_close_file(handle);
    return GS_SUCCESS;
}

status_t log_repair_file_offset(knl_session_t *session, log_file_t *file)
{
    uint64 latest_lfn;
    aligned_buf_t log_buf;

    if (cm_aligned_malloc((int64)LOG_LGWR_BUF_SIZE(session), "log buffer", &log_buf) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[LOG] failed to alloc log buffer with size %u", (uint32)LOG_LGWR_BUF_SIZE(session));
        return GS_ERROR;
    }

    if (log_get_file_offset(session, file->ctrl->name, &log_buf, (uint64 *)&file->head.write_pos,
        &latest_lfn, &file->head.last) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[LOG] failed to get online log %s write pos", file->ctrl->name);
        cm_aligned_free(&log_buf);
        return GS_ERROR;
    }
    cm_aligned_free(&log_buf);
    return GS_SUCCESS;
}

log_group_t *log_fetch_group(log_context_t *ctx, log_cursor_t *cursor)
{
    uint32 i, id;
    log_group_t *group;
    log_group_t *group_cmp = NULL;

    id = 0;
    group = CURR_GROUP(cursor, 0);

    for (i = 1; i < cursor->part_count; i++) {
        if (group == NULL) {
            group = CURR_GROUP(cursor, i);
            id = i;
            continue;
        }

        group_cmp = CURR_GROUP(cursor, i);
        if (group_cmp == NULL) {
            continue;
        }

        if (group->lsn > group_cmp->lsn) {
            group = group_cmp;
            id = i;
        }
    }

    if (group == NULL) {
        return NULL;
    }

    cursor->offsets[id] += group->size;
    return group;
}

status_t log_get_file_head(const char *file_name, log_file_head_t *head)
{
    int32 handle = GS_INVALID_HANDLE;
    device_type_t type = cm_device_type(file_name);
    if (cm_open_device(file_name, type, 0, &handle) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[LOG] failed to open %s", file_name);
        return GS_ERROR;
    }

    if (cm_read_device(type, handle, 0, head, sizeof(log_file_head_t)) != GS_SUCCESS) {
        cm_close_device(type, &handle);
        GS_LOG_RUN_ERR("[LOG] failed to read %s", file_name);
        return GS_ERROR;
    }

    cm_close_device(type, &handle);
    return GS_SUCCESS;
}

void log_set_logfile_writepos(knl_session_t *session, log_file_t *file, uint64 offset)
{
    cm_latch_x(&file->latch, session->id, NULL);
    file->head.write_pos = offset;
    cm_unlatch(&file->latch, NULL);
}

