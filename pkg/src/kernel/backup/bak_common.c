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
 * bak_common.c
 *
 *
 * IDENTIFICATION
 * src/kernel/backup/bak_common.c
 *
 * -------------------------------------------------------------------------
 */

#include "bak_common.h"
#include "bak_restore.h"
#include "cm_log.h"
#include "cm_file.h"
#include "cm_list.h"
#include "cm_error.h"
#include "cs_protocol.h"
#include "knl_context.h"
#include "knl_backup.h"
#include "dtc_dls.h"
#include "dtc_ckpt.h"
#include "dtc_backup.h"
#include "dtc_database.h"
#include "rc_reform.h"

#ifdef __cplusplus
extern "C" {
#endif

uint32 bak_get_build_stage(bak_stage_t *stage)
{
    switch (*stage) {
        case BACKUP_START:
            return BUILD_START;

        case BACKUP_CTRL_STAGE:
            return BUILD_CTRL_STAGE;

        case BACKUP_HEAD_STAGE:
            return BUILD_HEAD_STAGE;

        case BACKUP_DATA_STAGE:
            return BUILD_DATA_STAGE;

        case BACKUP_LOG_STAGE:
            return BUILD_LOG_STAGE;

        case BACKUP_PARAM_STAGE:
            return BUILD_PARAM_STAGE;

        case BACKUP_READ_FINISHED:
        case BACKUP_END:
            return BUILD_SYNC_FINISHED;

        default:
            return GS_INVALID_ID32;
    }
}

void bak_replace_password(char *password)
{
    size_t len = strlen(password);
    if (len != 0) {
        errno_t ret = memset_s(password, len, '*', len);
        knl_securec_check(ret);
    }
}

bool32 bak_paral_task_enable(knl_session_t *session)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;

    if (bak->restore && bak->is_noparal_version) {
        return GS_FALSE;
    } else if (bak->is_building && bak->proc_count == BUILD_SINGLE_THREAD) {
        return GS_FALSE;
    } else {
        return GS_TRUE;
    }
}

bool32 ctbak_paral_logfile_enable(bak_t *ct_bak)
{
    return FALSE;
}

bool32 ctbak_wait_log_arch_finish(knl_session_t *ct_se)
{
    return TRUE;
}

status_t bak_check_session_status(knl_session_t *session)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;

    if (bak->failed) {
        return GS_ERROR;
    }

    if (session->canceled) {
        GS_THROW_ERROR(ERR_OPERATION_CANCELED);
        return GS_ERROR;
    }

    if (session->killed) {
        GS_THROW_ERROR(ERR_OPERATION_KILLED);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static void ctbak_set_paral_proc_scope(bak_t *ct_bak, uint32 *start_index, uint32 *end_index, bool32 paral_logfile)
{
    return;
}

/*
* condition 1: total proc num euqals parallelism add 3 more thread num;
* condition 2: total proc num equals parallelism
* |       0      |         1       |    ...    |  parallelism |      +1     |     +2     |     +3     |
* | common proc  | log common proc |           data paral proc              |     log paral proc      |
* | common proc  |           data/log paral proc              |
*/
status_t bak_get_free_proc(knl_session_t *session, bak_process_t **proc, bool32 is_paral_log_proc)
{
    bak_context_t *bak_ctx = &session->kernel->backup_ctx;
    bak_process_t *bg_process = bak_ctx->process;
    bak_process_t *process = NULL;
    bak_t *bak = &bak_ctx->bak;
    uint32 start_id = 0;
    uint32 end_id = 0;

    *proc = NULL;
    if (!bak_paral_task_enable(session)) {
        GS_LOG_RUN_ERR("[%s] parallel backup/restore does not enable", bak->restore ? "RESTORE" : "BACKUP");
        return GS_ERROR;
    }

    ctbak_set_paral_proc_scope(bak, &start_id, &end_id, is_paral_log_proc);
    uint32 curr_id = start_id;
    while (!bak->failed) {
        if (bg_process[curr_id].is_free) {
            process = &bg_process[curr_id];
            break;
        }
        cm_sleep(100);
        curr_id++;
        curr_id = (curr_id > end_id) ? start_id : curr_id;
    }

    if (process == NULL) {
        GS_LOG_RUN_ERR("[%s] process is NULL", bak->restore ? "RESTORE" : "BACKUP");
        return GS_ERROR;
    }

    *proc = process;
    return GS_SUCCESS;
}

void bak_wait_paral_proc(knl_session_t *session, bool32 is_paral_log_proc)
{
    bak_context_t *bak_ctx = &session->kernel->backup_ctx;
    bak_process_t *bg_process = bak_ctx->process;
    bak_t *bak = &bak_ctx->bak;
    uint32 start_id = 0;
    uint32 end_id = 0;

    if (!bak_paral_task_enable(session)) {
        return;
    }

    ctbak_set_paral_proc_scope(bak, &start_id, &end_id, is_paral_log_proc);
    for (uint32 id = start_id; id <= end_id; id++) {
        while (!bak->failed && !bg_process[id].is_free) {
            cm_sleep(100);
        }
    }

    GS_LOG_DEBUG_INF("[%s] wait parallel backup/restore bak_task completed", bak->restore ? "RESTORE" : "BACKUP");
}

/*
 * return section count and section size of datafile when parallel backup, if filesize exceed section_threshold,
 * we divede this datafile as mutilple files, but section count will not exceed proc_count.
 * for example, section_threshold = 128M, proc_count = 4
 * 1. filesize = 300M, will generate 3 files, sec_size = 128M, [0, 128M], [128M, 256M], [256M, 300M]
 * 2. filesize = 1200M, will generate 4 files, sec_size = 300M, [0, 300M], [300M, 600M], [600M, 900M], [900M, 1200M]
 * 3. filesize = 100M, do not section, sec_size = filesize = 100M, still backup as one file
 */
uint32 ctbak_get_datafile_sec_cnt(knl_session_t *ct_se, uint64 file_size, uint32 hwm_start,
    uint64 *sec_size, bool32 *diveded)
{
    return 0;
}

status_t bak_encrypt_rand_iv(bak_file_t *file)
{
    unsigned char iv[BAK_DEFAULT_GCM_IV_LENGTH];
    errno_t ret;

    if (cm_rand(iv, BAK_DEFAULT_GCM_IV_LENGTH) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_CRYPTION_ERROR, "failed to acquire random iv");
        return GS_ERROR;
    }

    ret = memcpy_sp(file->gcm_iv, BAK_DEFAULT_GCM_IV_LENGTH, iv, BAK_DEFAULT_GCM_IV_LENGTH);
    knl_securec_check(ret);
    return GS_SUCCESS;
}

status_t bak_encrypt_init(bak_t *bak, bak_encrypt_ctx_t *encrypt_ctx, bak_file_t *file, bool32 is_encrypt)
{
    unsigned char iv[BAK_DEFAULT_GCM_IV_LENGTH];
    const unsigned char *key = (const unsigned char *)bak->key;
    errno_t ret;
    int32 res;

    res = EVP_CIPHER_CTX_init(encrypt_ctx->ctx);
    if (res == 0) {
        GS_THROW_ERROR(ERR_CRYPTION_ERROR, "failed to init evp cipher ctx");
        return GS_ERROR;
    }

    if (is_encrypt) {
        if (cm_rand(iv, BAK_DEFAULT_GCM_IV_LENGTH) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_CRYPTION_ERROR, "failed to acquire random iv");
            return GS_ERROR;
        }

        res = EVP_EncryptInit_ex(encrypt_ctx->ctx, EVP_aes_256_gcm(), NULL, key, (const unsigned char *)iv);
        ret = memcpy_sp(file->gcm_iv, BAK_DEFAULT_GCM_IV_LENGTH, iv, BAK_DEFAULT_GCM_IV_LENGTH);
        knl_securec_check(ret);
    } else {
        res = EVP_DecryptInit_ex(encrypt_ctx->ctx, EVP_aes_256_gcm(), NULL, key, (const unsigned char *)file->gcm_iv);
    }

    if (res == 0) {
        GS_THROW_ERROR(ERR_CRYPTION_ERROR, "failed to init cryption ctx");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t bak_encrypt_end(bak_t *bak, bak_encrypt_ctx_t *encrypt_ctx)
{
    int32 out_len, res;

    res = EVP_EncryptFinal_ex(encrypt_ctx->ctx, (unsigned char *)encrypt_ctx->encrypt_buf.aligned_buf, &out_len);
    if (res == 0) {
        GS_THROW_ERROR(ERR_CRYPTION_ERROR, "failed to finalize the encryption");
        return GS_ERROR;
    }

    res = EVP_CIPHER_CTX_ctrl(encrypt_ctx->ctx, EVP_CTRL_AEAD_GET_TAG, EVP_GCM_TLS_TAG_LEN,
        encrypt_ctx->encrypt_buf.aligned_buf);
    if (res == 0) {
        GS_THROW_ERROR(ERR_CRYPTION_ERROR, "failed to get the encryption tag");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t bak_decrypt_end(bak_t *bak, bak_encrypt_ctx_t *encrypt_ctx, bak_file_t *file, bool32 ignore_logfile)
{
    int32 res, outlen;

    if (ignore_logfile) {
        // the logfile is ignored, do not check tag
        return GS_SUCCESS;
    }

    // Set expected tag value from file
    res = EVP_CIPHER_CTX_ctrl(encrypt_ctx->ctx, EVP_CTRL_AEAD_SET_TAG, EVP_GCM_TLS_TAG_LEN, (void *)file->gcm_tag);
    if (res == 0) {
        GS_THROW_ERROR(ERR_CRYPTION_ERROR, "failed to set tag");
        return GS_ERROR;
    }
    res = EVP_DecryptFinal_ex(encrypt_ctx->ctx, (unsigned char *)encrypt_ctx->encrypt_buf.aligned_buf, &outlen);
    if (res == 0) {
        GS_THROW_ERROR(ERR_CRYPTION_ERROR, "failed to verify the tag, the data may be changed");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t bak_encrypt_alloc(bak_t *bak, bak_encrypt_ctx_t *encrypt_ctx)
{
    encrypt_ctx->ctx = EVP_CIPHER_CTX_new();

    if (encrypt_ctx->ctx == NULL) {
        GS_THROW_ERROR(ERR_CRYPTION_ERROR, "failed to alloc the cryption ctx");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void bak_encrypt_free(bak_t *bak, bak_encrypt_ctx_t *encrypt_ctx)
{
    EVP_CIPHER_CTX_free(encrypt_ctx->ctx);
    encrypt_ctx->ctx = NULL;
}

status_t bak_alloc_encrypt_context(knl_session_t *session)
{
    bak_context_t *backup_ctx = &session->kernel->backup_ctx;
    bak_t *bak = &backup_ctx->bak;
    bak_process_t *proc = NULL;
    uint32 proc_count = bak->proc_count;

    if (bak->encrypt_info.encrypt_alg == ENCRYPT_NONE) {
        return GS_SUCCESS;
    }

    proc = &backup_ctx->process[BAK_COMMON_PROC];

    // for common proc, include paral restore and no paral restore
    if (bak_encrypt_alloc(bak, &proc->encrypt_ctx) != GS_SUCCESS) {
        return GS_ERROR;
    }

    for (uint32 i = 1; i <= proc_count; i++) {
        proc = &backup_ctx->process[i];

        if (bak_encrypt_alloc(bak, &proc->encrypt_ctx) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

void bak_free_encrypt_context(knl_session_t *session)
{
    bak_context_t *backup_ctx = &session->kernel->backup_ctx;
    bak_t *bak = &backup_ctx->bak;
    bak_process_t *proc = NULL;
    uint32 proc_count = bak->proc_count;

    if (bak->encrypt_info.encrypt_alg == ENCRYPT_NONE) {
        return;
    }

    proc = &backup_ctx->process[BAK_COMMON_PROC];

    // for common proc, include paral restore and no paral restore
    bak_encrypt_free(bak, &proc->encrypt_ctx);

    for (uint32 i = 1; i <= proc_count; i++) {
        proc = &backup_ctx->process[i];
        bak_encrypt_free(bak, &proc->encrypt_ctx);
    }
}

status_t rst_decrypt_data(bak_process_t *proc, const char *buf, int32 size, uint32 left_size)
{
    int32 outlen = 0;
    int32 res;
    res = EVP_DecryptUpdate(proc->encrypt_ctx.ctx, (unsigned char *)proc->encrypt_ctx.encrypt_buf.aligned_buf +
                            left_size, &outlen, (const unsigned char *)buf, size);
    if (res == 0) {
        GS_THROW_ERROR(ERR_CRYPTION_ERROR, "failed to decrypt the data");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t bak_encrypt_data(bak_process_t *proc, const char *buf, int32 size)
{
    int32 outlen = 0;
    int32 res;
    res = EVP_EncryptUpdate(proc->encrypt_ctx.ctx, (unsigned char *)proc->encrypt_ctx.encrypt_buf.aligned_buf,
                            &outlen, (const unsigned char *)buf, size);
    if (res == 0) {
        GS_THROW_ERROR(ERR_CRYPTION_ERROR, "failed to encrypt the data");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t bak_alloc_compress_context(knl_session_t *session, bool32 is_compress)
{
    bak_context_t *backup_ctx = &session->kernel->backup_ctx;
    bak_t *bak = &backup_ctx->bak;
    bak_process_t *proc = NULL;
    uint32 proc_count = bak->proc_count;

    if (bak->record.attr.compress == COMPRESS_NONE) {
        return GS_SUCCESS;
    }

    // for common proc, include paral restore and no paral restore
    if (knl_compress_alloc(bak->record.attr.compress, &bak->compress_ctx, is_compress) != GS_SUCCESS) {
        return GS_ERROR;
    }

    for (uint32 i = 1; i <= proc_count; i++) {
        proc = &backup_ctx->process[i];

        if (knl_compress_alloc(bak->record.attr.compress, &proc->compress_ctx, is_compress) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

void bak_free_compress_context(knl_session_t *session, bool32 is_compress)
{
    bak_context_t *backup_ctx = &session->kernel->backup_ctx;
    bak_t *bak = &backup_ctx->bak;
    bak_process_t *proc = NULL;
    uint32 proc_count = bak->proc_count;

    if (bak->record.attr.compress == COMPRESS_NONE) {
        return;
    }

    // for common proc, include paral bakcup and no paral backup
    knl_compress_free(bak->record.attr.compress, &bak->compress_ctx, is_compress);

    for (uint32 i = 1; i <= proc_count; i++) {
        proc = &backup_ctx->process[i];
        knl_compress_free(bak->record.attr.compress, &proc->compress_ctx, is_compress);
    }
}

// lz4 compress algorithm needs to write a compress head when starting a compression
status_t bak_write_lz4_compress_head(bak_t *bak, bak_process_t *proc, bak_local_t *bak_file)
{
    LZ4F_preferences_t ref = LZ4F_INIT_PREFERENCES;
    char *lz4_write_buf = NULL;
    size_t res;

    if (bak->record.attr.compress != COMPRESS_LZ4) {
        return GS_SUCCESS;
    }

    ref.compressionLevel = bak->compress_ctx.compress_level;
    res = LZ4F_compressBegin(proc->compress_ctx.lz4f_cstream, proc->compress_ctx.compress_buf.aligned_buf,
        (uint32)COMPRESS_BUFFER_SIZE(bak), &ref);
    if (LZ4F_isError(res)) {
        GS_THROW_ERROR(ERR_COMPRESS_ERROR, "lz4f", res, LZ4F_getErrorName(res));
        return GS_ERROR;
    }
    lz4_write_buf = proc->compress_ctx.compress_buf.aligned_buf;
    if (bak->encrypt_info.encrypt_alg != ENCRYPT_NONE) {
        if (bak_encrypt_data(proc, proc->compress_ctx.compress_buf.aligned_buf, (int32)res) != GS_SUCCESS) {
            return GS_ERROR;
        }
        lz4_write_buf = proc->encrypt_ctx.encrypt_buf.aligned_buf;
    }

    if (bak_local_write(bak_file, lz4_write_buf, (int32)res, bak, bak_file->size) != GS_SUCCESS) {
        return GS_ERROR;
    }
    bak_file->size += res;

    return GS_SUCCESS;
}

static status_t bak_get_last_recid(knl_session_t *session, uint64 *record_id)
{
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);

    knl_set_session_scn(session, GS_INVALID_ID64);
    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_BACKUP_SET_ID, 0);

    cursor->index_dsc = GS_TRUE;
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, 0);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, 0);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (cursor->eof) {
        *record_id = 0;
    } else {
        cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, NULL);
        *record_id = *(uint64 *)CURSOR_COLUMN_DATA(cursor, BAK_COL_RECID);
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t bak_get_record(knl_session_t *session, char* tag, bak_record_t *record)
{
    text_t value;
    CM_SAVE_STACK(session->stack);

    knl_set_session_scn(session, GS_INVALID_ID64);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_BACKUP_SET_ID, IX_SYS_BACKUPSET_002_ID);

    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, (void *)tag,
        (uint16)strlen(tag), IX_COL_SYS_BACKUPSET_002_TAG);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (cursor->eof) {
        GS_THROW_ERROR_EX(ERR_INVALID_OPERATION, ", tag %s does not exist in sys_backup_sets", tag);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, NULL);
    record->attr.backup_type = *(uint32 *)CURSOR_COLUMN_DATA(cursor, BAK_COL_TYPE);
    record->device = *(uint32 *)CURSOR_COLUMN_DATA(cursor, BAK_COL_DEVICE_TYPE);
    value.str = CURSOR_COLUMN_DATA(cursor, BAK_COL_DIR);
    value.len = CURSOR_COLUMN_SIZE(cursor, BAK_COL_DIR);
    (void)cm_text2str(&value, record->path, GS_FILE_NAME_BUFFER_SIZE);

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t bak_delete_record(knl_session_t *session, char *tag)
{
    status_t status;

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_BACKUP_SET_ID, IX_SYS_BACKUPSET_002_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING,
        (void *)tag, (uint16)strlen(tag), IX_COL_SYS_BACKUPSET_002_TAG);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (cursor->eof) {
        GS_THROW_ERROR_EX(ERR_INVALID_OPERATION, ", tag %s does not exist in sys_backup_sets", tag);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    status = knl_internal_delete(session, cursor);
    CM_RESTORE_STACK(session->stack);

    if (status == GS_SUCCESS) {
        knl_commit(session);
    }

    return status;
}

static status_t bak_save_record(knl_session_t *session, bak_record_t *record, uint64 recid)
{
    status_t status;
    row_assist_t ra;
    knl_cursor_t *cursor = NULL;
    uint32 max_size;
    bak_t *bak = &session->kernel->backup_ctx.bak;
    uint32 max_buffer_size;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_BACKUP_SET_ID, GS_INVALID_ID32);

    max_size = session->kernel->attr.max_row_size;
    row_init(&ra, (char *)cursor->row, max_size, BAK_COL_RCY_LSN + 1);

    (void)row_put_int64(&ra, recid);
    (void)row_put_int32(&ra, record->attr.backup_type);
    (void)row_put_int32(&ra, record->data_only ? BACKUP_DATA_STAGE : BACKUP_LOG_STAGE);
    (void)row_put_int32(&ra, record->status);
    (void)row_put_int32(&ra, record->attr.level);
    (void)row_put_str(&ra, record->attr.tag);
    (void)row_put_int64(&ra, record->ctrlinfo.scn);
    (void)row_put_int64(&ra, record->ctrlinfo.lsn);
    (void)row_put_int32(&ra, record->device);
    (void)row_put_str(&ra, record->attr.base_tag);
    (void)row_put_str(&ra, record->path);
    (void)row_put_int32(&ra, session->kernel->db.ctrl.core.resetlogs.rst_id);
    (void)row_put_str(&ra, record->policy);
    (void)row_put_int32(&ra, record->ctrlinfo.rcy_point.asn);
    (void)row_put_int64(&ra, record->ctrlinfo.rcy_point.block_id);
    (void)row_put_int64(&ra, record->ctrlinfo.rcy_point.lfn);
    (void)row_put_int32(&ra, record->ctrlinfo.lrp_point.asn);
    (void)row_put_int64(&ra, record->ctrlinfo.lrp_point.block_id);
    (void)row_put_int64(&ra, record->ctrlinfo.lrp_point.lfn);
    (void)row_put_timestamp(&ra, record->start_time);
    (void)row_put_timestamp(&ra, record->data_only ? (uint64)cm_now() : record->completion_time);

    if (record->attr.base_buffer_size >= bak->backup_buf_size) {
        max_buffer_size = record->attr.base_buffer_size;
    } else {
        max_buffer_size = bak->backup_buf_size;
    }
    (void)row_put_int32(&ra, max_buffer_size);
    (void)row_put_str(&ra, session->kernel->attr.db_version);
    uint64 min_lsn = dtc_get_min_lsn_lrp_point(session, record);
    (void)row_put_int64(&ra, min_lsn);

    status = knl_internal_insert(session, cursor);
    if (status == GS_SUCCESS) {
        knl_commit(session);
    }

    CM_RESTORE_STACK(session->stack);
    return status;
}

static status_t bak_update_record(knl_session_t *session, bak_record_t *record)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    uint16 size;
    status_t status;

    knl_set_session_scn(session, GS_INVALID_ID64);

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_BACKUP_SET_ID, 1);

    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING,
                     (void *)record->attr.tag, (uint16)strlen(record->attr.tag), 0);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, ((index_t *)cursor->index)->desc.name);
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), 4); /* 4 for SYS_BACKUP_SET column counts */
    (void)row_put_int32(&ra, record->data_only ? BACKUP_DATA_STAGE : BACKUP_LOG_STAGE);
    (void)row_put_int32(&ra, record->status);
    (void)row_put_int64(&ra, record->finish_scn);
    (void)row_put_int64(&ra, record->completion_time);

    cursor->update_info.count = 4; /* 4 for SYS_BACKUP_SET column counts */
    cursor->update_info.columns[0] = BAK_COL_STAGE;
    cursor->update_info.columns[1] = BAK_COL_STATUS;
    cursor->update_info.columns[2] = BAK_COL_SCN;
    cursor->update_info.columns[3] = BAK_COL_COMPLETION_TIME;
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    status = knl_internal_update(session, cursor);

    CM_RESTORE_STACK(session->stack);

    if (status == GS_SUCCESS) {
        knl_commit(session);
    }

    return status;
}

status_t bak_record_backup_set(knl_session_t *session, bak_record_t *record)
{
    uint64 recid;

    if (DB_IS_READONLY(session)) {
        GS_LOG_RUN_WAR("[BACKUP] do not record backup set information in read-only mode");
        return GS_SUCCESS;
    }

    if (!record->log_only || record->attr.backup_type == BACKUP_MODE_ARCHIVELOG) {
        if (bak_get_last_recid(session, &recid) != GS_SUCCESS) {
            return GS_ERROR;
        }

        recid++;
        if (bak_save_record(session, record, recid) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_BACKUP_RECORD_FAILED);
            return GS_ERROR;
        }
    } else {
        if (bak_update_record(session, record) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_BACKUP_RECORD_FAILED);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

void bak_set_progress(knl_session_t *session, bak_stage_t stage, uint64 data_size)
{
    bak_context_t *backup_ctx = &session->kernel->backup_ctx;
    bak_t *bak = &backup_ctx->bak;
    bak_progress_t *progress = &bak->progress;

    if (BAK_IS_FULL_BUILDING(bak) && !bak->is_first_link &&
        bak_get_build_stage(&progress->stage) >= bak_get_build_stage(&stage)) {
        GS_LOG_RUN_INF("[BUILD] reset progress stage to [%u] for break-point building", (uint32)progress->stage);
        progress->stage = progress->build_progress.stage;
        return;
    }
    cm_spin_lock(&progress->lock, NULL);
    progress->processed_size = 0;
    progress->stage = stage;
    progress->data_size = data_size;
    progress->base_rate += progress->weight;

    if (bak->restore) {
        if (bak->curr_id > 0 && (stage == BACKUP_HEAD_STAGE || stage == BACKUP_CTRL_STAGE)) {
            progress->weight = 0;
        } else if (stage == BACKUP_DATA_STAGE || stage == BACKUP_BUILD_STAGE) {
            /* Some data files are incomplete,workload of filling data files is estimated to recovery a data file */
            /* 2 for incremental backup file and the work of filling data files */
            progress->weight = BAK_DATE_WEIGHT / (bak->depend_num + 2);
        } else {
            progress->weight = backup_ctx->stage_weight[stage];
        }
    } else {
        progress->weight = backup_ctx->stage_weight[stage];
    }

    cm_spin_unlock(&progress->lock);
    GS_LOG_DEBUG_INF("[BACKUP] data size %llu file name %s stage %u", data_size, bak->local.name, stage);
}

void bak_update_progress(bak_t *bak, uint64 size)
{
    bak_progress_t *progress = &bak->progress;

    cm_spin_lock(&progress->update_lock, NULL);
    progress->processed_size += size;
    cm_spin_unlock(&progress->update_lock);
}

void bak_set_progress_end(bak_t *bak)
{
    bak_progress_t *progress = &bak->progress;

    cm_spin_lock(&progress->lock, NULL);
    progress->processed_size = 0;
    progress->data_size = 0;
    progress->stage = BACKUP_END;
    progress->weight = 0;

    if (!bak->restore && bak->record.data_only) {
        progress->base_rate = BAK_CTRL_WEIGHT + BAK_DATE_WEIGHT;
    } else {
        progress->base_rate = 100; /* backup progress is 100% */
    }

    cm_spin_unlock(&progress->lock);
}

void bak_reset_progress(bak_progress_t *progress)
{
    progress->processed_size = 0;
    progress->data_size = 0;
    progress->stage = BACKUP_START;
    progress->base_rate = 0;
    progress->weight = 0;
}

void bak_reset_error(bak_error_t *error)
{
    error->err_code = GS_SUCCESS;
    error->err_msg[0] = '\0';
}

status_t bak_init_uds(uds_link_t *link, const char *sun_path)
{
    if (cs_create_uds_socket(&link->sock) != GS_SUCCESS) {
        return GS_ERROR;
    }
    socket_attr_t sock_attr = { .connect_timeout = GS_CONNECT_TIMEOUT, .l_onoff = 1, .l_linger = 1 };
    if (cs_uds_connect(sun_path, NULL, link, &sock_attr) != GS_SUCCESS) {
        (void)cs_close_socket(link->sock);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static inline bool32 bak_need_set_retry(bak_t *bak)
{
    bak_stage_t *stage = &bak->progress.build_progress.stage;

    return (BAK_IS_FULL_BUILDING(bak) && bak_get_build_stage(stage) <= BUILD_HEAD_STAGE);
}

status_t bak_agent_send(bak_t *bak, const char *buf, int32 size)
{
    if (bak->is_building) {
        if (cs_write_stream_timeout(bak->remote.pipe, buf, (uint32)size,
            (int32)cm_atomic_get(&bak->kernel->attr.repl_pkg_size), GS_BUILD_SEND_TIMEOUT) != GS_SUCCESS) {
            bak->need_retry = bak_need_set_retry(bak) ? GS_TRUE : GS_FALSE;
            GS_LOG_RUN_INF("[BACKUP] send failed, need_retry : %u", bak->need_retry);
            return GS_ERROR;
        }
        return GS_SUCCESS;
    } else {
        return cs_uds_send_timed(&bak->remote.uds_link, buf, size,
            bak->kernel->attr.nbu_backup_timeout * MILLISECS_PER_SECOND);
    }
}

status_t bak_agent_recv(bak_t *bak, char *buf, int32 size)
{
    if (bak->is_building) {
        int32 recv_size;
        if (cs_read_stream(bak->remote.pipe, buf, GS_DEFAULT_NULL_VALUE, (uint32)size, &recv_size) != GS_SUCCESS) {
            bak->need_retry = bak_need_set_retry(bak) ? GS_TRUE : GS_FALSE;
            GS_LOG_RUN_INF("[BACKUP] receive failed, need_retry : %u", bak->need_retry);
            return GS_ERROR;
        }

        if (recv_size != size) {
            bak->need_retry = bak_need_set_retry(bak) ? GS_TRUE : GS_FALSE;
            GS_LOG_RUN_INF("[BACKUP] invalid recv_size %u received, expected size is %u, need_retry: %u",
                (uint32)recv_size, (uint32)size, bak->need_retry);
            return GS_ERROR;
        }

        return GS_SUCCESS;
    } else {
        return cs_uds_recv_timed(&bak->remote.uds_link, buf, size, GS_DEFAULT_NULL_VALUE);
    }
}

status_t bak_agent_wait_pkg(bak_t *bak, bak_package_type_t ack)
{
    bak_agent_head_t head;

    if (bak_agent_recv(bak, (char *)&head, sizeof(bak_agent_head_t)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (head.cmd != ack) {
        GS_THROW_ERROR(ERR_NOT_EXPECTED_BACKUP_PACKET, ack, head.cmd);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t bak_agent_file_start(bak_t *bak, const char *path, uint32 type, uint32 file_id)
{
    bak_agent_head_t head;
    bak_start_msg_t start_msg;
    errno_t ret;

    head.ver = BAK_AGENT_PROTOCOL;
    head.cmd = BAK_PKG_FILE_START;
    head.len = sizeof(bak_agent_head_t) + sizeof(bak_start_msg_t);
    head.serial_number = 0;
    head.flags = 0;
    head.reserved = 0;
    bak->remote.serial_number = 0;

    start_msg.type = type;
    start_msg.file_id = file_id;
    start_msg.frag_id = 0;
    start_msg.curr_file_index = bak->curr_file_index;
    ret = strcpy_sp(start_msg.policy, GS_BACKUP_PARAM_SIZE, bak->record.policy);
    knl_securec_check(ret);
    ret = strcpy_sp(start_msg.path, GS_FILE_NAME_BUFFER_SIZE, path);
    knl_securec_check(ret);
    GS_LOG_DEBUG_INF("[BACKUP] send start agent, type:%d, len:%u, msg type:%d, policy:%s, path:%s", type, head.len,
                     start_msg.type, start_msg.policy, start_msg.path);
    if (bak_agent_send(bak, (char *)&head, sizeof(bak_agent_head_t)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (bak_agent_send(bak, (char *)&start_msg, sizeof(start_msg)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (bak_agent_wait_pkg(bak, BAK_PKG_ACK) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t bak_agent_send_pkg(bak_t *bak, bak_package_type_t end_type)
{
    bak_agent_head_t head;

    head.ver = BAK_AGENT_PROTOCOL;
    head.serial_number = bak->remote.serial_number++;
    head.cmd = end_type;
    head.len = sizeof(bak_agent_head_t);
    head.flags = 0;
    head.reserved = 0;

    GS_LOG_DEBUG_INF("[BACKUP] send type %d", end_type);
    if (bak_agent_send(bak, (char *)&head, sizeof(bak_agent_head_t)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t bak_agent_write(bak_t *process, const char *buf, int32 size)
{
    bak_agent_head_t head;
    int32 offset = 0;
    int32 remain_size = size;
    int32 data_size;

    head.ver = BAK_AGENT_PROTOCOL;
    head.cmd = BAK_PKG_DATA;
    head.flags = 0;
    head.reserved = 0;

    while (!process->failed && remain_size > 0) {
        data_size = remain_size > (int32)BACKUP_BUFFER_SIZE(process) ?
            (int32)BACKUP_BUFFER_SIZE(process) : remain_size;
        head.len = (uint32)data_size + sizeof(bak_agent_head_t);
        head.serial_number = process->remote.serial_number++;
        if (bak_agent_send(process, (char *)&head, sizeof(bak_agent_head_t)) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (bak_agent_send(process, buf + offset, data_size) != GS_SUCCESS) {
            return GS_ERROR;
        }

        offset += data_size;
        remain_size -= data_size;
    }

    return process->failed ? GS_ERROR : GS_SUCCESS;
}

status_t rst_agent_read_head(bak_t *process, bak_package_type_t expected_type, uint32 *data_size, bool32 *read_end)
{
    bak_agent_head_t head;

    if (bak_agent_recv(process, (char *)&head, sizeof(bak_agent_head_t)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (head.cmd == BAK_PKG_FILE_END) {
        *read_end = GS_TRUE;
        return GS_SUCCESS;
    }

    if (head.cmd == BAK_PKG_ERROR && head.len > (sizeof(bak_agent_head_t) + sizeof(int32))) {
        if (bak_agent_recv(process, (char *)&process->error_info.err_code, sizeof(int32)) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (bak_agent_recv(process, process->error_info.err_msg,
                           head.len - sizeof(bak_agent_head_t) - sizeof(int32)) != GS_SUCCESS) {
            return GS_ERROR;
        }

        GS_THROW_ERROR(ERR_BACKUP_RESTORE, "build", process->error_info.err_msg);
        return GS_ERROR;
    }

    if (head.cmd != expected_type) {
        GS_THROW_ERROR(ERR_NOT_EXPECTED_BACKUP_PACKET, expected_type, head.cmd);
        return GS_ERROR;
    }

    if (head.len <= sizeof(bak_agent_head_t)) {
        GS_THROW_ERROR(ERR_INVALID_BACKUP_PACKET, head.len);
        return GS_ERROR;
    }

    *data_size = head.len - sizeof(bak_agent_head_t);
    return GS_SUCCESS;
}

status_t rst_agent_read(bak_t *bak, char *buf, uint32 buf_size, int32 *read_size, bool32 *read_end)
{
    uint32 remain_size, offset;
    uint32 size;

    *read_end = GS_FALSE;
    remain_size = buf_size;
    offset = 0;

    while (remain_size > 0 && !bak->failed) {
        if (bak->remote.remain_data_size == 0) {
            if (rst_agent_read_head(bak, BAK_PKG_DATA, &bak->remote.remain_data_size, read_end) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (*read_end) {
            break;
        }

        knl_panic(bak->remote.remain_data_size > 0);
        size = remain_size > bak->remote.remain_data_size ? bak->remote.remain_data_size : remain_size;
        if (bak_agent_recv(bak, buf + offset, size) != GS_SUCCESS) {
            return GS_ERROR;
        }

        remain_size -= size;
        offset += size;
        bak->remote.remain_data_size -= size;
    }

    *read_size = (int32)offset; /* offset <= buf_size = 8M, cannot overflow */
    return bak->failed ? GS_ERROR : GS_SUCCESS;
}

// for standby and primary with normal backup
status_t bak_set_running(knl_session_t *session, bak_context_t *ctx)
{
    status_t status = GS_ERROR;

    if (!BAK_NOT_WORK(ctx)) {
        return GS_ERROR;
    }

    if (DB_ATTR_CLUSTER(session)) {
        if (dls_spin_try_lock(session, &ctx->lock) == GS_FALSE) {
            return GS_ERROR;
        }
        if (BAK_NOT_WORK(ctx)) {
            ctx->bak_condition = RUNNING;
            status = GS_SUCCESS;
        }
        dls_spin_unlock(session, &ctx->lock);
    } else {
        cm_spin_lock(&ctx->lock.lock, NULL);
        if (BAK_NOT_WORK(ctx)) {
            ctx->bak_condition = RUNNING;
            status = GS_SUCCESS;
        }
        cm_spin_unlock(&ctx->lock.lock);
    }

    return status;
}

status_t bak_set_process_running(knl_session_t *session)
{
    status_t status = GS_ERROR;
    bak_context_t *ctx = &session->kernel->backup_ctx;
    if (!BAK_NOT_WORK(ctx)) {
        return GS_ERROR;
    }
    cm_spin_lock(&ctx->lock.lock, NULL);
    if (BAK_NOT_WORK(ctx)) {
        ctx->bak_condition = RUNNING;
        status = GS_SUCCESS;
    }
    cm_spin_unlock(&ctx->lock.lock);
    return status;
}
 
void bak_unset_process_running(knl_session_t *session)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    cm_spin_lock(&ctx->lock.lock, NULL);
    ctx->bak_condition = NOT_RUNNING;
    cm_spin_unlock(&ctx->lock.lock);
}

// for primary with building
status_t bak_set_build_running(knl_session_t *session, bak_context_t *ctx, build_progress_t *build_progress)
{
    bak_t *bak = &ctx->bak;
    build_progress_t *local_build_progress = &bak->progress.build_progress;
    status_t status = GS_ERROR;

    if (build_progress->start_time == 0) {
        if (!BAK_NOT_WORK(ctx)) {
            GS_THROW_ERROR(ERR_BACKUP_IN_PROGRESS, "backup");
            return GS_ERROR;
        }
        if (dls_spin_try_lock(session, &ctx->lock) == GS_FALSE) {
            return GS_ERROR;
        }
        if (BAK_NOT_WORK(ctx)) {
            ctx->bak_condition = RUNNING;
            status = GS_SUCCESS;
        }
        dls_spin_unlock(session, &ctx->lock);
        return status;
    }

    while (BAK_IS_RUNNING(ctx)) {
        if (bak_check_session_status(session) != GS_SUCCESS) {
            return GS_ERROR;
        }
        cm_sleep(1);
    }

    if (build_progress->start_time != local_build_progress->start_time) {
        GS_LOG_RUN_INF("[BUILD] standby build start time [%d] is not equal primary build start time [%d]",
                       build_progress->start_time, local_build_progress->start_time);
        GS_THROW_ERROR(ERR_INVALID_OPERATION, " : The break-point between primary and stanby is not equal");
        return GS_ERROR;
    }

    if (!BAK_IS_KEEP_ALIVE(ctx)) {
        GS_LOG_RUN_INF("[BUILD] timeout for break-point building");
        GS_THROW_ERROR(ERR_BACKUP_TIMEOUT, ":Timeout for break-point building");
        return GS_ERROR;
    }
    dls_spin_lock(session, &ctx->lock, NULL);
    if (BAK_IS_KEEP_ALIVE(ctx)) {
        if (!bak_parameter_is_valid(build_progress)) {
            GS_LOG_RUN_INF("[BUILD] Break-point parameters from standby database are not effective.");
            GS_THROW_ERROR(ERR_INVALID_OPERATION, " : Break-point parameters from standby database are not effective");
        }
        ctx->bak_condition = RUNNING;
        status = GS_SUCCESS;
    }
    dls_spin_unlock(session, &ctx->lock);

    return status;
}

// for standby
void bak_unset_running(knl_session_t *session, bak_context_t *ctx)
{
    GS_LOG_RUN_INF("[BACKUP] RETRY : %u", ctx->bak.need_retry);

    if (session->kernel->attr.clustered) {
        ctx->bak_condition = NOT_RUNNING;
        dls_spin_unlock(session, &ctx->lock);
    } else {
        cm_spin_lock(&ctx->lock.lock, NULL);
        ctx->bak_condition = NOT_RUNNING;
        cm_spin_unlock(&ctx->lock.lock);
    }
}

// for primary
void bak_unset_build_running(knl_session_t *session, bak_context_t *ctx)
{
    bak_progress_t *progress = &ctx->bak.progress;

    dls_spin_lock(session, &ctx->lock, NULL);
    if (ctx->bak.need_retry) {
        ctx->bak.need_retry = GS_FALSE;
        progress->stage = BACKUP_END;
        ctx->keep_live_start_time = cm_current_time();
        ctx->bak_condition = KEEP_ALIVE;
        GS_LOG_RUN_INF("[BUILD] progress stage : %u", progress->stage);
        GS_LOG_RUN_INF("[BUILD] set keep alive condition");
    } else {
        ctx->bak.need_retry = GS_FALSE;
        progress->stage = BACKUP_END;
        ctx->bak_condition = NOT_RUNNING;
    }
    dls_spin_unlock(session, &ctx->lock);
}

void bak_set_error(bak_error_t *error_info)
{
    int32 err_code;
    const char *error_msg = NULL;
    size_t msg_len;
    errno_t ret;

    cm_get_error(&err_code, &error_msg, NULL);
    if (err_code != 0 && error_info->err_code == 0) {
        cm_spin_lock(&error_info->err_lock, NULL);
        if (error_info->err_code == 0) {
            error_info->err_code = err_code;
            msg_len = strlen(error_msg) + 1;
            ret = memcpy_sp(error_info->err_msg, GS_MESSAGE_BUFFER_SIZE, error_msg, msg_len);
            knl_securec_check(ret);
        }
        cm_spin_unlock(&error_info->err_lock);
    }
}

void bak_set_fail_error(bak_error_t *error_info, const char *str)
{
    int32 err_code;
    const char *error_msg = NULL;

    cm_get_error(&err_code, &error_msg, NULL);
    if (err_code != 0) {
        if (error_info->err_code == 0) {
            // set throw error code firstly
            bak_set_error(error_info);
        }
    }

    if (strlen(error_info->err_msg) == 0) {
        errno_t ret = strcpy_s(error_info->err_msg, GS_MESSAGE_BUFFER_SIZE, "process stop");
        knl_securec_check(ret);
    }

    GS_THROW_ERROR(ERR_BACKUP_RESTORE, str, error_info->err_msg);
    if (error_info->err_code == 0) {
        // set error code 855
        bak_set_error(error_info);
    }
}

status_t bak_agent_command(bak_t *bak, bak_package_type_t type)
{
    if (!BAK_IS_UDS_DEVICE(bak)) {
        return GS_SUCCESS;
    }

    if (bak_agent_send_pkg(bak, type) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (bak_agent_wait_pkg(bak, BAK_PKG_ACK) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void bak_calc_head_checksum(bak_head_t *head, uint32 size)
{
    uint16 cks_head, cks_file;
    uint32 tmp_cks;

    head->attr.head_checksum = GS_INVALID_CHECKSUM;
    head->attr.file_checksum = GS_INVALID_CHECKSUM;

    tmp_cks = cm_get_checksum(head, sizeof(bak_head_t));
    cks_head = REDUCE_CKS2UINT16(tmp_cks);
    tmp_cks = cm_get_checksum(head, size);
    cks_file = REDUCE_CKS2UINT16(tmp_cks);

    head->attr.head_checksum = cks_head;
    head->attr.file_checksum = cks_file;
}

void bak_calc_ctrlfile_checksum(knl_session_t *session, char *ctrl_buf, uint32 count)
{
    ctrl_page_t *pages = (ctrl_page_t *)ctrl_buf;
    bool32 cks_off = DB_IS_CHECKSUM_OFF(session);
    uint32 i;

    for (i = 0; i < count; i++) {
        pages[i].tail.checksum = GS_INVALID_CHECKSUM;

        if (cks_off) {
            continue;
        }
        page_calc_checksum((page_head_t *)&pages[i], GS_DFLT_CTRL_BLOCK_SIZE);
    }
}

status_t rst_verify_ctrlfile_checksum(knl_session_t *session, const char *name)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    uint32 cks_level = kernel->attr.db_block_checksum;
    ctrl_page_t *pages = kernel->db.ctrl.pages;
    uint32 i;

    if (DB_IS_CHECKSUM_OFF(session)) {
        return GS_SUCCESS;
    }

    for (i = 0; i < CTRL_MAX_PAGES(session); i++) {
        if (pages[i].tail.checksum == GS_INVALID_CHECKSUM) {
            continue;
        }

        if (!page_verify_checksum((page_head_t *)&pages[i], GS_DFLT_CTRL_BLOCK_SIZE)) {
            GS_LOG_RUN_ERR("[RESTORE] the %d's ctrl page corrupted. "
                           "block size %u, ctrl file name %s, checksum level %s",
                           i, GS_DFLT_CTRL_BLOCK_SIZE, name, knl_checksum_level(cks_level));
            GS_THROW_ERROR(ERR_CHECKSUM_FAILED, name);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t bak_verify_datafile_checksum(knl_session_t *session, bak_process_t *ctx, uint64 offset, const char *name)
{
    uint32 cks_level = session->kernel->attr.db_block_checksum;
    uint32 size = (uint32)ctx->read_size;
    uint64 page_offset = 0;
    page_head_t *page = NULL;

    if (DB_IS_CHECKSUM_OFF(session)) {
        return GS_SUCCESS;
    }

    for (uint32 i = 0; i * DEFAULT_PAGE_SIZE(session) < size; i++) {
        page_offset = offset / DEFAULT_PAGE_SIZE(session) + i;
        page = (page_head_t *)(ctx->backup_buf.aligned_buf + i * DEFAULT_PAGE_SIZE(session));
        if (PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session)) == GS_INVALID_CHECKSUM) {
            continue;
        }

        if (!page_verify_checksum(page, DEFAULT_PAGE_SIZE(session))) {
            GS_LOG_RUN_ERR("[BACKUP] page corrupted(file %u, page %u). datafile page offset %llu, datafile name %s,"
                           "checksum level is %u, page size %u, cks %u, read_size %u, checksum level %s",
                           AS_PAGID_PTR(page->id)->file, AS_PAGID_PTR(page->id)->page, page_offset, name,
                           cks_level, PAGE_SIZE(*page), PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session)),
                           size, knl_checksum_level(cks_level));
            GS_THROW_ERROR(ERR_CHECKSUM_FAILED, name);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t rst_verify_datafile_checksum(knl_session_t *session, bak_process_t *ctx, char *buf,
                                      uint32 page_count, const char *name)
{
    uint32 cks_level = session->kernel->attr.db_block_checksum;
    bak_attr_t *attr = &session->kernel->backup_ctx.bak.record.attr;
    page_head_t *page = NULL;

    if (DB_IS_CHECKSUM_OFF(session)) {
        return GS_SUCCESS;
    }

    for (uint32 i = 0; i < page_count; i++) {
        page = (page_head_t *)(buf + i * DEFAULT_PAGE_SIZE(session));
        if (PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session)) == GS_INVALID_CHECKSUM) {
            continue;
        }
        
        page_id_t *page_id = (page_id_t*)page;
        datafile_t *df = DATAFILE_GET(session, page_id->file);
        
        if (DATAFILE_IS_COMPRESS(df) && attr->level == 0 && AS_PAGID_PTR(page->id)->page >= DF_MAP_HWM_START) {
            continue;
        }

        if (!page_verify_checksum(page, DEFAULT_PAGE_SIZE(session))) {
            uint64 page_offset = ctx->curr_offset / DEFAULT_PAGE_SIZE(session) + i;
            GS_LOG_RUN_ERR("[RESTORE] page corrupted(file %u, page %u). size %u cks %u, "
                           "page offset %llu, file name %s, checksum level %s",
                           AS_PAGID_PTR(page->id)->file, AS_PAGID_PTR(page->id)->page, PAGE_SIZE(*page),
                           PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session)),
                           page_offset, name, knl_checksum_level(cks_level));
            GS_THROW_ERROR(ERR_CHECKSUM_FAILED, name);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t rst_truncate_file(knl_session_t *session, const char *name, device_type_t type, int64 size)
{
    int64 file_size;
    int32 handle = GS_INVALID_HANDLE;

    if (cm_open_device(name, type, knl_io_flag(session), &handle) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[RESTORE] failed to open %s", name);
        return GS_ERROR;
    }

    file_size = cm_device_size(cm_device_type(name), handle);
    if (file_size == -1) {
        cm_close_device(type, &handle);
        GS_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_END, errno);
        return GS_ERROR;
    }

    if (size < file_size) {
        GS_LOG_RUN_INF("[RESTORE] truncate file from %lld to %lld, name %s", file_size, size, name);
        if (cm_truncate_device(type, handle, size) != GS_SUCCESS) {
            cm_close_device(type, &handle);
            GS_LOG_RUN_ERR("[RESTORE] failed to truncate %s", name);
            return GS_ERROR;
        }

        if (db_fsync_file(session, handle) != GS_SUCCESS) {
            cm_close_device(type, &handle);
            GS_LOG_RUN_ERR("[RESTORE] failed to fsync file %s", name);
            return GS_ERROR;
        }
    }
    cm_close_device(type, &handle);
    return GS_SUCCESS;
}

status_t rst_truncate_datafile(knl_session_t *session)
{
    datafile_t *df = NULL;
    space_t *space = NULL;

    for (uint32 i = 0; i < GS_MAX_DATA_FILES; i++) {
        df = DATAFILE_GET(session, i);
        if (!DATAFILE_IS_ONLINE(df) || !df->ctrl->used || DF_FILENO_IS_INVAILD(df)) {
            continue;
        }

        space = SPACE_GET(session, df->space_id);
        if (!SPACE_IS_ONLINE(space) || !space->ctrl->used) {
            continue;
        }

        if (rst_truncate_file(session, df->ctrl->name, df->ctrl->type, df->ctrl->size) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t rst_extend_file(knl_session_t *session, const char *name, device_type_t type, int64 size,
                         char *buf, uint32 buf_size)
{
    int64 file_size;
    int32 handle = GS_INVALID_HANDLE;

    if (cm_open_device(name, type, knl_io_flag(session), &handle) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[RESTORE] failed to open %s", name);
        return GS_ERROR;
    }

    knl_panic(cm_device_type(name) == type);
    if (type == DEV_TYPE_ULOG) {
        return GS_SUCCESS;
    }
    file_size = cm_device_size(type, handle);
    if (file_size == -1) {
        cm_close_device(type, &handle);
        GS_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_END, errno);
        return GS_ERROR;
    }

    if (size > file_size) {
        GS_LOG_RUN_INF("[RESTORE] extend file from %lld to %lld, name %s", file_size, size, name);
        if (cm_dbs_is_enable_dbs() == GS_TRUE) {
            if (cm_extend_device(type, handle, buf, buf_size, size - file_size,
                session->kernel->attr.build_datafile_prealloc) != GS_SUCCESS) {
                cm_close_device(type, &handle);
                GS_LOG_RUN_ERR("[RESTORE] failed to extend %s", name);
                return GS_ERROR;
            }
        } else {
            if (cm_try_prealloc_extend_device(type, handle, buf, buf_size, size - file_size,
                session->kernel->attr.build_datafile_prealloc) != GS_SUCCESS) {
                cm_close_device(type, &handle);
                GS_LOG_RUN_ERR("[RESTORE] failed to extend %s", name);
                return GS_ERROR;
            }
            if (db_fsync_file(session, handle) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[RESTORE] failed to fsync file %s", name);
                cm_close_device(type, &handle);
                return GS_ERROR;
            }
        }
    }
    
    cm_close_device(type, &handle);
    return GS_SUCCESS;
}

uint32 bak_get_package_type(bak_file_type_t type)
{
    switch (type) {
        case BACKUP_CTRL_FILE:
            return BAK_MSG_TYPE_CTRL;
        case BACKUP_DATA_FILE:
            return BAK_MSG_TYPE_DATA;
        case BACKUP_LOG_FILE:
            return BAK_MSG_TYPE_LOG;
        case BACKUP_ARCH_FILE:
            return BAK_MSG_TYPE_ARCH;
        default:
            return BAK_MSG_TYPE_HEAD;
    }
}

status_t bak_head_verify_checksum(knl_session_t *session, bak_head_t *head, uint32 size, bool32 is_check_file)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    uint32 cks_level = session->kernel->attr.db_block_checksum;
    uint32 tmp_cks;
    uint16 org_cks_head, org_cks_file;
    uint16 new_cks;

    /* if cks_level == CKS_OFF, do not check */
    if (DB_IS_CHECKSUM_OFF(session)) {
        return GS_SUCCESS;
    }

    org_cks_head = head->attr.head_checksum;
    org_cks_file = head->attr.file_checksum;
    head->attr.head_checksum = GS_INVALID_CHECKSUM;
    head->attr.file_checksum = GS_INVALID_CHECKSUM;
    tmp_cks = cm_get_checksum(head, size);
    new_cks = REDUCE_CKS2UINT16(tmp_cks);
    if (is_check_file && org_cks_file != new_cks) {
        GS_LOG_RUN_ERR("[BACKUP] backupset file checksum. file %s org_cks %u new_cks %u, "
                       "check type %u, checksum level %s",
                       ctx->bak.local.name, org_cks_file, new_cks,
                       (uint32)is_check_file, knl_checksum_level(cks_level));
        GS_THROW_ERROR(ERR_CHECKSUM_FAILED, ctx->bak.local.name);
        return GS_ERROR;
    }

    if (!is_check_file && org_cks_head != new_cks) {
        GS_LOG_RUN_ERR("[BACKUP] backupset file checksum. file %s org_cks %u new_cks %u, "
                       "check type %u,, checksum level %s",
                       ctx->bak.local.name, org_cks_head, new_cks,
                       (uint32)is_check_file, knl_checksum_level(cks_level));
        GS_THROW_ERROR(ERR_CHECKSUM_FAILED, ctx->bak.local.name);
        return GS_ERROR;
    }

    head->attr.head_checksum = org_cks_head;
    head->attr.file_checksum = org_cks_file;
    return GS_SUCCESS;
}

static void ctbak_set_paral_proc_cnt(bak_t *ct_bak)
{
    return;
}

void bak_reset_process_ctrl(bak_t *bak, bool32 restore)
{
    if (BAK_IS_FULL_BUILDING(bak) && !bak->is_first_link) {
        GS_LOG_RUN_INF("[BUILD] ignore reset progress for break-point building");
    } else {
        bak_reset_progress(&bak->progress);
    }
    bak_reset_error(&bak->error_info);
    bak->depend_num = 0;
    bak->curr_id = 0;
    bak->restore = restore;
    bak->record.status = BACKUP_PROCESSING;
    bak->remote.remain_data_size = 0;
    bak->ctrlfile_completed = GS_FALSE;
    bak->need_retry = GS_FALSE;
    ctbak_set_paral_proc_cnt(bak);
}

static void bak_reset_ctrl(bak_ctrl_t *ctrl)
{
    cm_close_device(ctrl->type, &ctrl->handle);
    ctrl->handle = (int32)GS_INVALID_ID32;
    ctrl->name[0] = '\0';
    ctrl->offset = 0;
}

void bak_reset_stats(knl_session_t *session)
{
    bak_process_t *procs = session->kernel->backup_ctx.process;
    errno_t ret;

    for (uint32 i = 0; i < GS_MAX_BACKUP_PROCESS; i++) {
        ret = memset_sp(&procs[i].stat, sizeof(bak_process_stat_t), 0, sizeof(bak_process_stat_t));
        knl_securec_check(ret);
    }
}

void bak_reset_process(bak_process_t *ctx)
{
    cm_close_thread(&ctx->thread);
    cm_aligned_free(&ctx->backup_buf);
    cm_aligned_free(&ctx->compress_ctx.compress_buf);
    cm_aligned_free(&ctx->encrypt_ctx.encrypt_buf);
    cm_aligned_free(&ctx->table_compress_ctx.read_buf);
    cm_aligned_free(&ctx->table_compress_ctx.unzip_buf);
    cm_aligned_free(&ctx->table_compress_ctx.zip_buf);

    ctx->read_size = 0;
    ctx->write_size = 0;
    bak_reset_ctrl(&ctx->ctrl);
}

static void bak_process_init(bak_context_t *ctx, knl_session_t *session)
{
    bak_process_t *process = NULL;
    uint32 i;
    uint32 j;

    for (i = 0; i < GS_MAX_BACKUP_PROCESS; i++) {
        process = &ctx->process[i];
        process->session = session;
        process->ctrl.handle = GS_INVALID_HANDLE;

        for (j = 0; j < GS_MAX_DATA_FILES; j++) {
            process->datafiles[j] = GS_INVALID_HANDLE;
            process->datafile_name[j][0] = '\0';
        }
        bak_reset_fileinfo(&process->assign_ctrl);
    }
}

static void bak_set_stage_weight(bak_context_t *ctx)
{
    ctx->stage_weight[BACKUP_PARAM_STAGE] = BAK_PARAM_WEIGHT;
    ctx->stage_weight[BACKUP_HEAD_STAGE] = BAK_HEAD_WEIGHT;
    ctx->stage_weight[BACKUP_CTRL_STAGE] = BAK_CTRL_WEIGHT;
    ctx->stage_weight[BACKUP_DATA_STAGE] = BAK_DATE_WEIGHT;
    ctx->stage_weight[BACKUP_LOG_STAGE] = BAK_LOG_WEIGHT;
}

static void bak_stats_init(bak_context_t *ctx)
{
    ctx->bak.stat.reads = 0;
    ctx->bak.stat.writes = 0;
}

void bak_init(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    bak_context_t *ctx = &kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;
    errno_t ret;

    knl_panic(sizeof(bak_head_t) == BAK_HEAD_STRUCT_SIZE);
    ret = memset_sp(ctx, sizeof(bak_context_t), 0, sizeof(bak_context_t));
    knl_securec_check(ret);

    bak->kernel = kernel;
    bak->local.handle = GS_INVALID_HANDLE;
    bak->log_local.handle = GS_INVALID_HANDLE;
    ctrlinfo->rcy_point.asn = GS_INVALID_ID32;
    ctrlinfo->lrp_point.asn = GS_INVALID_ID32;
    ctrlinfo->scn = GS_INVALID_ID64;
    bak->logfiles_created = GS_FALSE;

    dls_init_spinlock(&(ctx->lock), DR_TYPE_DATABASE, DR_ID_DATABASE_BAKUP, 0);

    bak_stats_init(ctx);
    bak_process_init(ctx, kernel->sessions[SESSION_ID_BRU]);
    bak_set_stage_weight(ctx);
}

static void bak_generate_datafile_name(knl_session_t *session, const char *path, uint32 index, uint32 file_id,
                                       uint32 sec_id, char *file_name)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    uint32 space_id;
    int32 ret;

    if (bak->restore) {
        ret = snprintf_s(file_name, GS_FILE_NAME_BUFFER_SIZE, GS_MAX_FILE_NAME_LEN,
                         "%s/data_%s_%u_%u.bak", path, bak->files[index].spc_name, file_id, sec_id);
    } else {
        space_id = DATAFILE_GET(session, file_id)->space_id;
        ret = strcpy_sp(bak->files[index].spc_name, GS_NAME_BUFFER_SIZE, SPACE_GET(session, space_id)->ctrl->name);
        knl_securec_check_ss(ret);
        ret = snprintf_s(file_name, GS_FILE_NAME_BUFFER_SIZE, GS_MAX_FILE_NAME_LEN,
                         "%s/data_%s_%u_%u.bak", path, bak->files[index].spc_name, file_id, sec_id);
    }
    knl_securec_check_ss(ret);
}

static int32 bak_generate_bak_log_file(bak_t *bak, const char *path, uint32 index,
                                       uint32 file_id, char *file_name)
{
    int32 ret;
    if (BAK_IS_DBSOTR(bak)) {
        ret = snprintf_s(file_name, GS_FILE_NAME_BUFFER_SIZE, GS_MAX_FILE_NAME_LEN,
                         "%s/log_%u_%u_%llx_%llx.bak",
                         path, bak->files[index].inst_id,
                         file_id, bak->files[index].start_lsn, bak->files[index].end_lsn);
    } else {
        ret = snprintf_s(file_name, GS_FILE_NAME_BUFFER_SIZE, GS_MAX_FILE_NAME_LEN,
                         "%s/log_%u_%u_0.bak",
                         path, bak->files[index].inst_id, file_id);
    }
    return ret;
}

static int32 bak_generate_bak_arch_file(bak_t *bak, const char *path, uint32 index,
                                        uint32 file_id, char *file_name)
{
    int32 ret;
    if (BAK_IS_DBSOTR(bak)) {
        ret = snprintf_s(file_name, GS_FILE_NAME_BUFFER_SIZE, GS_MAX_FILE_NAME_LEN,
                         "%s/arch_%u_%u_%llx_%llx.bak", path, bak->files[index].inst_id,
                         file_id, bak->files[index].start_lsn, bak->files[index].end_lsn);
    } else {
        ret = snprintf_s(file_name, GS_FILE_NAME_BUFFER_SIZE, GS_MAX_FILE_NAME_LEN,
                         "%s/arch_%u_%u_0.bak", path, bak->files[index].inst_id, file_id);
    }
    return ret;
}

void bak_generate_bak_file(knl_session_t *session, const char *path, bak_file_type_t type, uint32 index,
                           uint32 file_id, uint32 sec_id, char *file_name)
{
    int32 ret;
    knl_instance_t *kernel = session->kernel;
    bak_context_t *ctx = &kernel->backup_ctx;
    bak_t *bak = &ctx->bak;

    switch (type) {
        case BACKUP_CTRL_FILE:
            ret = snprintf_s(file_name, GS_FILE_NAME_BUFFER_SIZE, GS_MAX_FILE_NAME_LEN,
                             "%s/ctrl_%d_%d.bak", path, 0, 0);
            knl_securec_check_ss(ret);
            break;
        case BACKUP_DATA_FILE:
            bak_generate_datafile_name(session, path, index, file_id, sec_id, file_name);
            break;
        case BACKUP_LOG_FILE:
            ret = bak_generate_bak_log_file(bak, path, index, file_id, file_name);
            knl_securec_check_ss(ret);
            break;
        case BACKUP_ARCH_FILE:
            ret = bak_generate_bak_arch_file(bak, path, index, file_id, file_name);
            knl_securec_check_ss(ret);
            break;
        case BACKUP_HEAD_FILE:
            ret = snprintf_s(file_name, GS_FILE_NAME_BUFFER_SIZE, GS_MAX_FILE_NAME_LEN, "%s/backupset", path);
            knl_securec_check_ss(ret);
            break;
        default:
            break;
    }
}

status_t bak_get_last_rcy_point(knl_session_t *session, log_point_t *point)
{
    knl_cursor_t *cursor = NULL;
    bak_stage_t stage;

    CM_SAVE_STACK(session->stack);

    knl_set_session_scn(session, GS_INVALID_ID64);
    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_BACKUP_SET_ID, 0);

    cursor->index_dsc = GS_TRUE;
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, 0);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, 0);

    for (;;) {
        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (cursor->eof) {
            point->rst_id = 0;
            point->asn = 0;
            point->lsn = 0;
            break;
        } else {
            cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, NULL);
            point->rst_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, BAK_COL_RESETLOGS);
            point->asn = *(uint32 *)CURSOR_COLUMN_DATA(cursor, BAK_COL_RCY_ASN);
            point->lsn = *(uint64 *)CURSOR_COLUMN_DATA(cursor, BAK_COL_RCY_LSN);
            stage = *(uint32 *)CURSOR_COLUMN_DATA(cursor, BAK_COL_STAGE);
        }

        if (stage == BACKUP_LOG_STAGE) {
            break;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

void build_disconnect(bak_t *bak)
{
    bak_remote_t *remote = &bak->remote;

    knl_disconnect(&remote->send_pipe);
    remote->send_pipe.link.tcp.sock = CS_INVALID_SOCKET;
    remote->pipe = NULL;
    remote->send_pack = NULL;
    remote->recv_pack = NULL;
}

static void bak_free_stream_buffer(bak_t *bak)
{
    cm_aligned_free(&bak->send_stream.bufs[0]);
    cm_aligned_free(&bak->send_stream.bufs[1]);
    bak->send_stream.buf_size = 0;

    cm_aligned_free(&bak->recv_stream.bufs[0]);
    cm_aligned_free(&bak->recv_stream.bufs[1]);
    bak->recv_stream.buf_size = 0;
}

void bak_free_backup_buf(bak_t *bak)
{
    if (bak->backup_buf != NULL) {
        cm_aligned_free(&bak->align_buf);
        bak->backup_buf = NULL;
        bak->depends = NULL;
        bak->compress_buf = NULL;
        bak->ctrl_backup_buf = NULL;
    }
}

void bak_reset_params(knl_session_t *session, bool32 restore)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;

    if (restore) {
        bak_unset_build_running(session, ctx);
    } else {
        bak->progress.stage = BACKUP_END;
    }
    errno_t ret = memset_sp(bak->exclude_spcs, sizeof(bool32) * GS_MAX_SPACES, 0, sizeof(bool32) * GS_MAX_SPACES);
    knl_securec_check(ret);
    ret = memset_sp(bak->include_spcs, sizeof(bool32) * GS_MAX_SPACES, 0, sizeof(bool32) * GS_MAX_SPACES);
    knl_securec_check(ret);
    bak->record.status = bak->failed ? BACKUP_FAILED : BACKUP_SUCCESS;
    bak->failed = GS_FALSE;
    bak->is_building = GS_FALSE;
    bak->depends = NULL;
    bak->need_check = GS_FALSE;
    bak->record.is_increment = GS_FALSE;
    bak->record.is_repair = GS_FALSE;

    ret = memset_sp(&bak->rst_file, sizeof(rst_file_info_t), 0, sizeof(rst_file_info_t));
    knl_securec_check(ret);
    ret = memset_sp(&bak->target_info, sizeof(knl_backup_targetinfo_t), 0, sizeof(knl_backup_targetinfo_t));
    knl_securec_check(ret);

    /* in two stage backup, after backup datafiles(stage one), we need save tag to compare in the second stage */
    if (!bak->record.data_only) {
        ret = memset_sp(bak->record.attr.tag, GS_NAME_BUFFER_SIZE, 0, GS_NAME_BUFFER_SIZE);
        knl_securec_check(ret);
    }
}

void bak_end(knl_session_t *session, bool32 restore)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    ctrlfile_set_t *ctrlfiles = &session->kernel->db.ctrlfiles;
    bak_t *bak = &ctx->bak;
    bak_error_t *error_info = &bak->error_info;

    if (bak->encrypt_info.encrypt_alg != ENCRYPT_NONE) {
        bak_replace_password(bak->password);
    }

    // reset common process finally
    for (int32 i = GS_MAX_BACKUP_PROCESS - 1; i >= 0; i--) {
        bak_reset_process(&ctx->process[i]);
    }

    if (bak->failed && !bak->need_retry) {
        bak_set_fail_error(error_info, restore ? "restore" : "backup");
        GS_LOG_RUN_ERR("[%s] %s failed", restore ? "RESTORE" : "BACKUP", restore ? "restore" : "backup");
    } else {
        bak_set_progress_end(bak);
        GS_LOG_RUN_INF("[%s] %s success", restore ? "RESTORE" : "BACKUP", restore ? "restore" : "backup");
    }
    bak_free_backup_buf(bak);
    bak_free_stream_buffer(bak);
    bak_free_compress_context(session, !restore);
    bak_free_encrypt_context(session);

    if (BAK_IS_UDS_DEVICE(bak)) {
        if (bak->failed && bak->remote.uds_link.sock != CS_INVALID_SOCKET) {
            cs_uds_disconnect(&bak->remote.uds_link);
        }
    }

    cm_close_device(bak->local.type, &bak->local.handle);
    bak->local.handle = GS_INVALID_HANDLE;
    bak->local.name[0] = '\0';
    cm_close_device(bak->log_local.type, &bak->log_local.handle);
    bak->log_local.handle = GS_INVALID_HANDLE;
    bak->log_local.name[0] = '\0';

    /* only restore all database will open ctrl file and online logfiles */
    if (restore && bak->rst_file.file_type == RESTORE_ALL &&
        (cm_device_type(session->kernel->db.ctrlfiles.items[0].name) != DEV_TYPE_RAW)) {
        rst_close_ctrl_file(ctrlfiles);
        rst_close_log_files(session);
    }
    bak_reset_params(session, restore);
}

status_t bak_validate_backupset(knl_session_t *session, knl_validate_t *param)
{
    return GS_SUCCESS;
}

void bak_get_error(knl_session_t *session, int32 *code, const char **message)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;

    *code = ctx->bak.error_info.err_code;
    *message = ctx->bak.error_info.err_msg;
}

static status_t bak_generate_default_backupset_name(knl_session_t *session)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    int32 ret;

    ret = sprintf_s(bak->record.path, GS_MAX_BACKUP_PATH_LEN, DEFAULT_BAKCUPFILE_FORMAT, session->kernel->home,
                    bak->record.start_time);
    if (ret == -1) {
        GS_THROW_ERROR(ERR_EXCEED_MAX_BACKUP_PATH_LEN, "default backup path", GS_MAX_BACKUP_PATH_LEN);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static void bak_record_base_info(knl_cursor_t *cursor, bak_t *bak)
{
    bak_dependence_t *info = bak->depends + bak->depend_num;
    text_t value;

    info->device = *(uint32 *)CURSOR_COLUMN_DATA(cursor, BAK_COL_DEVICE_TYPE);
    value.str = CURSOR_COLUMN_DATA(cursor, BAK_COL_POLICY);
    value.len = CURSOR_COLUMN_SIZE(cursor, BAK_COL_POLICY);
    (void)cm_text2str(&value, info->policy, GS_NAME_BUFFER_SIZE);
    value.str = CURSOR_COLUMN_DATA(cursor, BAK_COL_DIR);
    value.len = CURSOR_COLUMN_SIZE(cursor, BAK_COL_DIR);
    (void)cm_text2str(&value, info->file_dest, GS_FILE_NAME_BUFFER_SIZE);

    bak->depend_num++;
    GS_LOG_RUN_INF("[BACKUP]depend_num1 %u, file dest %s", bak->depend_num, info->file_dest);
}

static status_t ctbak_verify_db_version(knl_session_t *ct_se, knl_cursor_t *ct_cursor)
{
    return CT_SUCCESS;
}

bool32 bak_filter_incr(knl_session_t *session, knl_cursor_t *cursor, backup_device_t device, uint32 rst_value,
    bool32 cumulative)
{
    uint32 backup_type = *(uint32 *)CURSOR_COLUMN_DATA(cursor, BAK_COL_TYPE);
    uint32 reset_logs = *(uint32 *)CURSOR_COLUMN_DATA(cursor, BAK_COL_RESETLOGS);
    backup_device_t device_type = *(uint32 *)CURSOR_COLUMN_DATA(cursor, BAK_COL_DEVICE_TYPE);
    bak_stage_t stage = *(uint32 *)CURSOR_COLUMN_DATA(cursor, BAK_COL_STAGE);
    if (backup_type != BACKUP_MODE_INCREMENTAL || reset_logs != rst_value || device_type != device ||
        stage != BACKUP_LOG_STAGE) {
        return GS_FALSE;
    }

    uint32 level = *(uint32 *)CURSOR_COLUMN_DATA(cursor, BAK_COL_LEVEL);
    if (cumulative && level != 0) {
        return GS_FALSE;
    }

    if (ctbak_verify_db_version(session, cursor) != GS_SUCCESS) {
        return GS_FALSE;
    }

    return GS_TRUE;
}

status_t bak_select_incr_info(knl_session_t *session, bak_t *bak)
{
    knl_cursor_t *cursor = NULL;
    uint32 level;
    bool32 save_lastest_incr = GS_TRUE;
    text_t value;
    bak_attr_t *attr = &bak->record.attr;

    CM_SAVE_STACK(session->stack);

    knl_set_session_scn(session, GS_INVALID_ID64);
    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_BACKUP_SET_ID, 0);

    cursor->index_dsc = GS_TRUE;
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, 0);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, 0);

    for (;;) {
        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, NULL);
        if (!bak_filter_incr(session, cursor, bak->record.device, session->kernel->db.ctrl.core.resetlogs.rst_id,
                             bak->cumulative)) {
            continue;
        }

        if (save_lastest_incr) {
            value.str = CURSOR_COLUMN_DATA(cursor, BAK_COL_TAG);
            value.len = CURSOR_COLUMN_SIZE(cursor, BAK_COL_TAG);
            (void)cm_text2str(&value, attr->base_tag, GS_NAME_BUFFER_SIZE);
            attr->base_lsn = *(uint64 *)CURSOR_COLUMN_DATA(cursor, BAK_COL_LSN);
            attr->base_buffer_size = *(uint32 *)CURSOR_COLUMN_DATA(cursor, BAK_COL_MAX_BUFFER_SIZE);
            save_lastest_incr = GS_FALSE;
        }

        bak_record_base_info(cursor, bak);
        level = *(uint32 *)CURSOR_COLUMN_DATA(cursor, BAK_COL_LEVEL);
        if (level == 0) {
            break;
        }

        if (bak->depend_num >= BAK_MAX_INCR_NUM) {
            GS_THROW_ERROR(ERR_EXCEED_MAX_INCR_BACKUP);
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t bak_set_incr_info(knl_session_t *session, bak_t *bak)
{
    bak_attr_t *attr = &bak->record.attr;

    bak->depend_num = 0;
    if (attr->level == 0) {
        attr->base_lsn = 0;
        attr->base_tag[0] = '\0';
        attr->base_buffer_size = GS_MIN_BACKUP_BUF_SIZE;
        return GS_SUCCESS;
    }

    if (bak->is_building) {
        return GS_SUCCESS;
    }

    if (bak_select_incr_info(session, bak) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (bak->depend_num == 0) {
        GS_THROW_ERROR(ERR_NO_VALID_BASE_BACKUPSET);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t bak_set_data_path(knl_session_t *session, bak_t *bak, text_t *format)
{
    if (format->len > 0) {
        if (format->len > GS_MAX_BACKUP_PATH_LEN) {
            GS_THROW_ERROR(ERR_EXCEED_MAX_BACKUP_PATH_LEN, T2S(format), GS_MAX_BACKUP_PATH_LEN);
            return GS_ERROR;
        }

        if (cm_text2str(format, bak->record.path, GS_FILE_NAME_BUFFER_SIZE) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (cm_check_exist_special_char(bak->record.path, (uint32)strlen(bak->record.path))) {
            GS_THROW_ERROR(ERR_INVALID_DIR, bak->record.path);
            return GS_ERROR;
        }
    } else {
        if (bak_generate_default_backupset_name(session) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (bak->record.device == DEVICE_DISK) {
        if (cm_create_device_dir_ex(cm_device_type(bak->record.path), bak->record.path) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t bak_set_exclude_space(knl_session_t *session, bak_t *bak, galist_t *exclude_spcs)
{
    text_t *spc_name = NULL;
    space_t *space = NULL;
    uint32 spc_id;
    errno_t ret;

    ret = memset_sp(bak->exclude_spcs, sizeof(bool32) * GS_MAX_SPACES, 0, sizeof(bool32) * GS_MAX_SPACES);
    knl_securec_check(ret);

    for (uint32 i = 0; i < exclude_spcs->count; i++) {
        spc_name = (text_t *)cm_galist_get(exclude_spcs, i);
        if (spc_get_space_id(session, spc_name, GS_TRUE, &spc_id) != GS_SUCCESS) {
            return GS_ERROR;
        }
        space = SPACE_GET(session, spc_id);
        if (SPACE_IS_DEFAULT(space)) {
            GS_THROW_ERROR(ERR_EXCLUDE_SPACES, T2S(spc_name));
            return GS_ERROR;
        }

        bak->exclude_spcs[spc_id] = GS_TRUE;
    }

    return GS_SUCCESS;
}

status_t bak_set_include_space(knl_session_t *session, bak_t *bak, galist_t *include_spcs)
{
    text_t *spc_name = NULL;
    uint32 spc_id;
    errno_t ret;

    ret = memset_sp(bak->include_spcs, sizeof(bool32) * GS_MAX_SPACES, 0, sizeof(bool32) * GS_MAX_SPACES);
    knl_securec_check(ret);

    for (uint32 i = 0; i < include_spcs->count; i++) {
        spc_name = (text_t *)cm_galist_get(include_spcs, i);
        if (spc_get_space_id(session, spc_name, GS_TRUE, &spc_id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        bak->include_spcs[spc_id] = GS_TRUE;
    }

    return GS_SUCCESS;
}

static status_t bak_check_backupset_to_delete(knl_session_t *session, knl_alterdb_backupset_t *def,
    bak_record_t *record)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;

    if (def->force_delete) {
        return GS_SUCCESS;
    }

    if (BAK_IS_UDS_DEVICE(bak)) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ", backupset device type is not disk, please use delete force");
        return GS_ERROR;
    }

    if (!cm_dir_exist(record->path)) {
        GS_THROW_ERROR_EX(ERR_INVALID_OPERATION, ", %s does not exist", record->path);
        return GS_ERROR;
    }

    if (cm_access_file(record->path, R_OK | W_OK | X_OK) != GS_SUCCESS) {
        GS_THROW_ERROR_EX(ERR_INVALID_OPERATION, ", %s is not an readable or writable or executable folder",
            record->path);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t bak_check_exist_dependent_backupset(knl_session_t *session, const char *tag)
{
    text_t base_tag;

    CM_SAVE_STACK(session->stack);

    knl_set_session_scn(session, GS_INVALID_ID64);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_BACKUP_SET_ID, IX_SYS_BACKUPSET_001_ID);

    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_BACKUPSET_001_RECID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_BACKUPSET_001_RECID);

    for (;;) {
        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, NULL);
        base_tag.str = CURSOR_COLUMN_DATA(cursor, BAK_COL_BASE_TAG);
        base_tag.len = CURSOR_COLUMN_SIZE(cursor, BAK_COL_BASE_TAG);
        if (cm_text_str_equal_ins(&base_tag, tag)) {
            GS_THROW_ERROR_EX(ERR_INVALID_OPERATION, ", exists backupset depends on the backupset");
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t bak_delete_backset_precheck(knl_session_t *session, knl_alterdb_backupset_t *def, bak_record_t *record)
{
    if (bak_get_record(session, def->tag, record) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (bak_check_backupset_to_delete(session, def, record) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (record->attr.backup_type == BACKUP_MODE_INCREMENTAL &&
        bak_check_exist_dependent_backupset(session, def->tag) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t bak_delete_backup_set(knl_session_t *session, knl_alterdb_backupset_t *def)
{
    status_t status = GS_SUCCESS;
    bak_record_t record;
    bak_context_t *ctx = &session->kernel->backup_ctx;

    if (bak_set_running(session, ctx) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_BACKUP_IN_PROGRESS, "backup or delete backupset");
        return GS_ERROR;
    }

    if (bak_delete_backset_precheck(session, def, &record) != GS_SUCCESS) {
        bak_unset_running(session, ctx);
        return GS_ERROR;
    }

    if (bak_delete_record(session, def->tag) != GS_SUCCESS) {
        bak_unset_running(session, ctx);
        GS_LOG_RUN_ERR("[BACKUP] Failed to delete backupset record of %s", record.path);
        return GS_ERROR;
    }

#ifndef WIN32
    if (record.device == DEVICE_DISK && cm_remove_dir(record.path) != GS_SUCCESS) {
        if (def->force_delete) {
            GS_LOG_RUN_INF("[BACKUP] Delete backupset %s error is ignored ", record.path);
            status = GS_SUCCESS;
        } else {
            GS_THROW_ERROR(ERR_REMOVE_DIR, record.path);
            status = GS_ERROR;
        }
    }
#endif
    bak_unset_running(session, ctx);
    return status;
}

bool32 bak_datafile_contains_dw(knl_session_t *session, bak_assignment_t *assign_ctrl)
{
    if (assign_ctrl->type != BACKUP_DATA_FILE) {
        return GS_FALSE;
    }

    uint32 dw_file_id = knl_get_dbwrite_file_id(session);
    datafile_t *df = DATAFILE_GET(session, assign_ctrl->file_id);
    return (bool32)(DATAFILE_CONTAINS_DW(df, dw_file_id));
}

/*
* Backup pages before file_hwm_start firstly, to ensure data pages are backed up in group of 8 pages.
* Temporary tablespace datafile only backup space head page.
* Datafile containing dw first backup space head page, and then if is bitmap managed,
* backup map pages before file_hwm_start.
*/
uint64 bak_set_datafile_read_size(knl_session_t *session, uint64 offset, bool32 contains_dw,
    uint64 file_size, uint32 hwm_start)
{
    uint64 read_size;

    if (offset == DEFAULT_PAGE_SIZE(session)) {
        if (contains_dw || file_size == SPACE_HEAD_END * DEFAULT_PAGE_SIZE(session)) {
            read_size = DEFAULT_PAGE_SIZE(session);                    /* backup space head page */
        } else {
            knl_panic(file_size >= offset);
            read_size = hwm_start > 1 ? (hwm_start - 1) * DEFAULT_PAGE_SIZE(session) : file_size - offset; /* skip file head page */
        }
    } else {
        if (contains_dw && offset == DW_SPC_HWM_START * DEFAULT_PAGE_SIZE(session) && hwm_start > DW_SPC_HWM_START) {
            read_size = (hwm_start - DW_SPC_HWM_START) * DEFAULT_PAGE_SIZE(session);
        } else {
            knl_panic(file_size >= offset);
            read_size = file_size - offset;
        }
    }
    return read_size;
}

#ifndef WIN32
static bool32 bak_is_above_hwm_start(knl_session_t *session, uint32 size)
{
    if (size == DEFAULT_PAGE_SIZE(session) || size == (DF_MAP_HWM_START - 1) * DEFAULT_PAGE_SIZE(session)) {
        return GS_FALSE;
    }
    return GS_TRUE;
}

status_t bak_construct_decompress_group(knl_session_t *session, char *first_page)
{
    page_head_t *page = NULL;

    for (uint32 i = 0; i < PAGE_GROUP_COUNT; i++) {
        page = (page_head_t *)(first_page + i * DEFAULT_PAGE_SIZE(session));
        if (page->size_units == 0) {
            continue;
        }
        page->compressed = 0;
        if (!buf_check_load_page(session, page, *AS_PAGID_PTR(page->id), GS_TRUE)) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

bool32 bak_need_decompress(knl_session_t *session, bak_process_t *bak_proc)
{
    bak_context_t *bak_ctx = &session->kernel->backup_ctx;
    bak_attr_t *attr = &bak_ctx->bak.record.attr;
    uint32 file_id = bak_proc->assign_ctrl.file_id;
    datafile_t *df = DATAFILE_GET(session, file_id);

    if (attr->level == 0 && DB_IS_CHECKSUM_OFF(session)) {
        return GS_FALSE;
    }

    if (!DATAFILE_IS_COMPRESS(df)) {
        return GS_FALSE;
    }

    if (!bak_is_above_hwm_start(session, bak_proc->read_size)) {
        return GS_FALSE;
    }

    return GS_TRUE;
}

status_t bak_decompress_and_verify_datafile(knl_session_t *session, bak_process_t *bak_proc)
{
    bak_context_t *bak_ctx = &session->kernel->backup_ctx;
    bak_attr_t *attr = &bak_ctx->bak.record.attr;
    uint32 level = attr->level;
    uint32 total_size = (uint32)bak_proc->read_size;
    page_head_t *first_page = NULL;
    pcb_assist_t src_pcb_assist;
    uint32 group_size;
    errno_t ret;

    knl_panic_log(total_size % (DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT) == 0,
                  "buf size %u is not in multiples of 8k", total_size);

    if (pcb_get_buf(session, &src_pcb_assist) != GS_SUCCESS) {
        return GS_ERROR;
    }

    for (uint32 i = 0; i * DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT < total_size; i++) {
        first_page = (page_head_t *)(bak_proc->backup_buf.aligned_buf +
                                     i * DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT);
        if (!first_page->compressed) {
            continue;
        }
        if (buf_decompress_group(session, src_pcb_assist.aligned_buf, (const char *)first_page, &group_size) !=
            GS_SUCCESS) {
            pcb_release_buf(session, &src_pcb_assist);
            return GS_ERROR;
        }
        knl_panic_log(group_size == DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT,
                      "group size %u is not corrent", group_size);
        if (bak_construct_decompress_group(session, src_pcb_assist.aligned_buf) != GS_SUCCESS) {
            pcb_release_buf(session, &src_pcb_assist);
            return GS_ERROR;
        }

        /*
         * Full backup will back up compressed pages, while decompression is only for verification.
         * Incremental backup will back up decompressed single pages.
         */
        if (level == 1) {
            ret = memcpy_sp(first_page, DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT, src_pcb_assist.aligned_buf,
                DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT);
            knl_securec_check(ret);
        }
    }
    pcb_release_buf(session, &src_pcb_assist);

    return GS_SUCCESS;
}

page_id_t bak_first_compress_group_id(knl_session_t *session, page_id_t page_id)
{
    page_id_t first;

    knl_panic_log(page_id.page >= DF_MAP_HWM_START, "page %u-%u before space first extent %u-%u", page_id.file,
        page_id.page, page_id.file, DF_MAP_HWM_START);
    first.page = page_id.page - ((page_id.page - DF_MAP_HWM_START) % PAGE_GROUP_COUNT);
    first.file = page_id.file;
    first.aligned = 0;

    return first;
}
#endif

/*
 * Primary backup and some DDL operations are mutually exclusive,
 * and these DDL are also not allowed during standby backup.
 * If the standby replays these DDL redo during backup, the backup needs to be set to fail.
 */

void ctbak_support_log_entry(knl_session_t *ct_se, log_entry_t *redo_log, bool32 *unblock_bak)
{
    return;
}

void ctbak_unsupport_log_entry(knl_session_t *ct_se, log_entry_t *redo_log, bool32 *unblock_bak)
{
    return;
}

/*
 * Primary backup and some DDL operations are mutually exclusive,
 * and these DDL are also not allowed during standby backup.
 * If the standby replays these DDL redo during backup, the backup needs to be set to fail.
 */
static bool32 backup_allow_logic_redo_type(logic_op_t type)
{
    switch (type) {
        case RD_ADD_LOGFILE:
        case RD_DROP_LOGFILE:
        case RD_SPC_RENAME_SPACE:
            return GS_FALSE;
        default:
            return GS_TRUE;
    }
    return GS_TRUE;
}

static bool32 backup_allow_redo_type(log_entry_t *log)
{
    logic_op_t *logic_type = (logic_op_t *)log->data;

    switch (log->type) {
        case RD_SPC_CREATE_SPACE:
        case RD_SPC_REMOVE_SPACE:
        case RD_SPC_CREATE_DATAFILE:
        case RD_SPC_REMOVE_DATAFILE:
        case RD_SPC_TRUNCATE_DATAFILE:
            return GS_FALSE;
        case RD_LOGIC_OPERATION:
            return backup_allow_logic_redo_type(*logic_type);
        default:
            return GS_TRUE;
    }
    return GS_TRUE;
}

void backup_safe_entry(knl_session_t *session, log_entry_t *log, bool32 *need_unblock_backup)
{
    if (!backup_allow_redo_type(log)) {
        CM_ABORT(0, "[RCY] ABORT INFO: recover failed when redo %s is not allowed during standby backup",
            rcy_redo_name(log));
    }
    *need_unblock_backup = GS_FALSE;
}

uint32 bak_log_get_id(knl_session_t *session, backup_data_type_t backup_type, uint32 rst_id, uint32 asn)
{
    if (backup_type == DATA_TYPE_DBSTOR) {
        return GS_INVALID_ID32;
    } else {
        return log_get_id_by_asn(session, rst_id, asn, NULL);
    }
}

uint32 bak_get_rst_id(bak_t *bak, uint32 asn, reset_log_t *rst_log)
{
    if (BAK_IS_DBSOTR(bak)) {
        // rst_id = bak->record.ctrlinfo.rcy_point.lsn <= rst_log->last_lsn ? (rst_log->rst_id - 1) : rst_log->rst_id;
        return rst_log->rst_id;
    } else {
        return asn <= rst_log->last_asn ? (rst_log->rst_id - 1) : rst_log->rst_id;
    }
}

void bak_set_data_type(knl_session_t *session)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    bak->record.data_type = knl_dbs_is_enable_dbs() ? DATA_TYPE_DBSTOR : DATA_TYPE_FILE;
}

#ifdef __cplusplus
}
#endif
