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
 * bak_paral.c
 *
 *
 * IDENTIFICATION
 * src/kernel/backup/bak_paral.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_backup_module.h"
#include "bak_common.h"
#include "cm_file.h"
#include "knl_backup.h"
#include "bak_restore.h"
#include "knl_context.h"
#include "dtc_backup.h"

static void bak_unlatch_logfile(knl_session_t *session, bak_process_t *process)
{
    bak_assignment_t *assign_ctrl = &process->assign_ctrl;

    if (assign_ctrl->file_id == CT_INVALID_ID32) {
        return;
    }
    log_unlatch_file(session, assign_ctrl->file_id);
}

void bak_unlatch_logfile_if_necessary(knl_session_t *session, bak_process_t *proc)
{
    if (bak_need_wait_arch(session)) {
        return;
    }
    bak_unlatch_logfile(session, proc);
}

static status_t bak_block_zstd_compress(bak_t *bak, knl_compress_t *compress_ctx, const char *src, uint32 src_size,
                                        uint32 *out_size)
{
    char *dest = compress_ctx->compress_buf.aligned_buf;
    size_t output_size = ZSTD_compress(dest, COMPRESS_BUFFER_SIZE(bak), src, src_size,
                                       compress_ctx->compress_level);
    if (ZSTD_isError(output_size)) {
        CT_LOG_RUN_ERR("[BACKUP] failed to compress(zstd) block, error code: %lu, reason: %s", output_size,
                       ZSTD_getErrorName(output_size));
        return CT_ERROR;
    }

    *out_size = (uint32)output_size;
    return CT_SUCCESS;
}

static status_t rst_block_zstd_decompress(bak_t *bak, knl_compress_t *compress_ctx, const char *src, uint32 src_size,
                                          uint32 *out_size)
{
    char *dest = compress_ctx->compress_buf.aligned_buf;
    size_t output_size = ZSTD_decompress(dest, COMPRESS_BUFFER_SIZE(bak), src, src_size);
    if (ZSTD_isError(output_size)) {
        CT_LOG_RUN_ERR("[BACKUP] failed to decompress(zstd) block, error code: %lu, reason: %s", output_size,
                       ZSTD_getErrorName(output_size));
        return CT_ERROR;
    }

    *out_size = (uint32)output_size;
    return CT_SUCCESS;
}

static status_t bak_block_lz4_compress(bak_t *bak, knl_compress_t *compress_ctx, const char *src, uint32 src_size,
                                       uint32 *out_size)
{
    char *dest = compress_ctx->compress_buf.aligned_buf;
    uint32 output_size = (uint32)LZ4_compress_default(src, dest, (int32)src_size,
                                                      (int32)COMPRESS_BUFFER_SIZE(bak));
    if (output_size == 0) {
        CT_LOG_RUN_ERR("[BACKUP] failed to compress(lz4) block");
        return CT_ERROR;
    }
    *out_size = output_size;
    return CT_SUCCESS;
}

static status_t rst_block_lz4_decompress(bak_t *bak, knl_compress_t *compress_ctx, const char *src, uint32 src_size,
                                         uint32 *out_size)
{
    char *dest = compress_ctx->compress_buf.aligned_buf;
    int32 output_size = (int32)LZ4_decompress_safe(src, dest, (int32)src_size,
                                                   (int32)COMPRESS_BUFFER_SIZE(bak));
    if (output_size <= 0) {
        CT_LOG_RUN_ERR("[BACKUP] failed to decompress(lz4) block, error code: %d", output_size);
        return CT_ERROR;
    }
    *out_size = (uint32)output_size;
    return CT_SUCCESS;
}

static status_t bak_block_encrypt(bak_t *bak, bak_encrypt_ctx_t *encrypt_ctx, const char *src, uint32 src_size,
                                  const unsigned char *gcm_iv)
{
    const unsigned char *key = (const unsigned char *)bak->key;
    char *encrypt_buf = encrypt_ctx->encrypt_buf.aligned_buf;
    int32 out_len = 0;

    if (EVP_CIPHER_CTX_init(encrypt_ctx->ctx) == 0) {
        CT_THROW_ERROR(ERR_CRYPTION_ERROR, "failed to init evp cipher ctx");
        return CT_ERROR;
    }

    if (EVP_EncryptInit_ex(encrypt_ctx->ctx, EVP_aes_256_gcm(), NULL, key, gcm_iv) == 0) {
        CT_THROW_ERROR(ERR_CRYPTION_ERROR, "failed to init cryption ctx");
        return CT_ERROR;
    }

    if (EVP_EncryptUpdate(encrypt_ctx->ctx, (unsigned char *)encrypt_buf, &out_len, (const unsigned char *)src,
                          src_size) == 0) {
        CT_THROW_ERROR(ERR_CRYPTION_ERROR, "failed to encrypt the data");
        return CT_ERROR;
    }

    if (EVP_EncryptFinal_ex(encrypt_ctx->ctx, (unsigned char *)encrypt_buf + src_size, &out_len) == 0) {
        CT_THROW_ERROR(ERR_CRYPTION_ERROR, "failed to finalize the encryption");
        return CT_ERROR;
    }
    knl_panic(out_len == 0);
    if (EVP_CIPHER_CTX_ctrl(encrypt_ctx->ctx, EVP_CTRL_AEAD_GET_TAG, EVP_GCM_TLS_TAG_LEN,
                            encrypt_buf + src_size) == 0) {
        CT_THROW_ERROR(ERR_CRYPTION_ERROR, "failed to get the encryption tag");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t rst_block_decrypt(bak_t *bak, bak_encrypt_ctx_t *encrypt_ctx, char *src, uint32 src_size,
                                  const unsigned char *gcm_iv)
{
    const unsigned char *key = (const unsigned char *)bak->key;
    char *encrypt_buf = encrypt_ctx->encrypt_buf.aligned_buf;
    uint32 data_size = src_size - EVP_GCM_TLS_TAG_LEN;
    int32 out_len;
    char *tag = NULL;

    if (EVP_CIPHER_CTX_init(encrypt_ctx->ctx) == 0) {
        CT_THROW_ERROR(ERR_CRYPTION_ERROR, "failed to init evp cipher ctx");
        return CT_ERROR;
    }

    int32 res = EVP_DecryptInit_ex(encrypt_ctx->ctx, EVP_aes_256_gcm(), NULL, key, gcm_iv);
    if (res == 0) {
        CT_THROW_ERROR(ERR_CRYPTION_ERROR, "failed to init cryption ctx");
        return CT_ERROR;
    }
    knl_panic(src_size > EVP_GCM_TLS_TAG_LEN);

    tag = src + data_size;

    if (EVP_DecryptUpdate(encrypt_ctx->ctx, (unsigned char *)encrypt_buf, &out_len, (const unsigned char *)src,
                          data_size) == 0) {
        CT_THROW_ERROR(ERR_CRYPTION_ERROR, "failed to decrypt the data");
        return CT_ERROR;
    }

    // Set expected tag value from block tail
    if (EVP_CIPHER_CTX_ctrl(encrypt_ctx->ctx, EVP_CTRL_AEAD_SET_TAG, EVP_GCM_TLS_TAG_LEN, (void *)tag) == 0) {
        CT_THROW_ERROR(ERR_CRYPTION_ERROR, "failed to set tag");
        return CT_ERROR;
    }

    if (EVP_DecryptFinal_ex(encrypt_ctx->ctx, (unsigned char *)encrypt_buf + data_size, &out_len) == 0) {
        CT_THROW_ERROR(ERR_CRYPTION_ERROR, "failed to verify the tag, the data may be changed");
        return CT_ERROR;
    }
    knl_panic(out_len == 0);
    return CT_SUCCESS;
}

status_t bak_paral_create_bakfile(knl_session_t *session, uint32 file_index, bak_assignment_t *assign_ctrl)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    char *path = bak->record.path;
    uint32 sec_id = assign_ctrl->sec_id;
    bool32 is_paral_log_backup = assign_ctrl->is_paral_log_backup;
    char *bak_name = NULL;
    int32 *bak_handle = NULL;
    uint32 mode = O_BINARY | O_RDWR | O_EXCL;

    if (!is_paral_log_backup) {
        bak_name = bak->local.name;
        bak_handle = &bak->local.handle;
        CT_LOG_DEBUG_INF("[BACKUP] start generate bak file");
    } else {
        bak_name = bak->log_local.name;
        bak_handle = &bak->log_local.handle;
        CT_LOG_DEBUG_INF("[BACKUP] start generate paral log bak file");
    }

    bak_generate_bak_file(session, path, bak->files[file_index].type, file_index, bak->files[file_index].id, sec_id,
        bak_name);
    mode = (bak->record.attr.compress != COMPRESS_NONE ? mode : (mode | O_DIRECT));
    if (cm_create_file(bak_name, mode, bak_handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] failed to generate bak file %s, file_index %u, sec_id %u.", bak_name, file_index, sec_id);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[BACKUP] successful to generate bak file %s, handle %d, file_index %u, sec_id %u.", bak_name, *bak_handle, file_index, sec_id);
    cm_close_file(*bak_handle);
    return CT_SUCCESS;
}

status_t rst_paral_open_bakfile(knl_session_t *session, bak_file_type_t file_type, uint32 file_index,
                                uint32 file_id, uint32 sec_id)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    char *path = NULL;
    uint32 mode = O_BINARY | O_SYNC | O_RDWR;

    path = rst_fetch_filename(bak);

    bak_generate_bak_file(session, path, file_type, file_index, file_id, sec_id, bak->local.name);
    bak->local.type = cm_device_type(bak->local.name);
    mode = (bak->record.attr.compress != COMPRESS_NONE ? mode : (mode | O_DIRECT));
    if (cm_open_file(bak->local.name, mode, &bak->local.handle) != CT_SUCCESS) {
        return CT_ERROR;
    }
    CT_LOG_DEBUG_INF("[RESTORE] file name:%s, type=%d, handle=%d", bak->local.name, bak->local.type, bak->local.handle);
    return CT_SUCCESS;
}

status_t bak_paral_task_simulation(knl_session_t *session, uint64 *proc_workloads, uint32 proc_count,
    uint64 file_size, uint32 hwm_start, uint32 *sec_num)
{
    uint32 next_proc;
    uint64 min_works;
    uint32 sec_id;
    uint32 proc_id;
    uint64 sec_size;
    uint64 part_size;
    bool32 devided = CT_TRUE;

    *sec_num = bak_datafile_section_count(session, file_size, hwm_start, &sec_size, &devided);
    uint64 no_head_file_size = devided ? file_size - hwm_start * DEFAULT_PAGE_SIZE(session) : file_size;
    for (sec_id = 0; sec_id < *sec_num; sec_id++) {
        next_proc = CT_INVALID_ID32;
        min_works = CT_INVALID_ID64;

        for (proc_id = 0; proc_id < proc_count; proc_id++) {
            if (proc_workloads[proc_id] < min_works) {
                min_works = proc_workloads[proc_id];
                next_proc = proc_id;
            }
        }

        part_size = (sec_id < *sec_num - 1) ? sec_size : no_head_file_size - sec_id * sec_size;
        proc_workloads[next_proc] += part_size;
        if (part_size > sec_size) {
            CT_LOG_RUN_ERR("[BACKUP] failed to calcute the optimal section threshold, "
                "file_size: %llu, hwm_start: %u, sec_size: %llu, sec_num: %u, part_size: %llu",
                file_size, hwm_start, sec_size, *sec_num, part_size);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

uint64 bak_optimun_section_threshold(uint64 *workloads, uint32 *file_count, uint32 res_id)
{
    uint64 sec_size;
    uint64 min_workload = CT_INVALID_ID64;
    uint32 min_file_count = CT_INVALID_ID32;
    uint32 best_count;
    uint32 min_id = CT_INVALID_ID32;

    for (uint32 id = 0; id < res_id; id++) {
        if (workloads[id] < min_workload) {
            min_workload = workloads[id];
            min_file_count = file_count[id];
        }
    }

    best_count = min_file_count;
    min_workload = (uint64)(min_workload * BAK_SECTION_SIZE_RATIO);
    for (uint32 id = 0; id < res_id; id++) {
        if (workloads[id] > min_workload) {
            continue;
        }

        if (file_count[id] <= min_file_count) {
            min_file_count = file_count[id];
            min_id = id;
        }
    }

    min_workload = (uint64)(min_workload / BAK_SECTION_SIZE_RATIO) + 1;
    sec_size = (uint64)SIZE_M(128) + (uint64)min_id * SIZE_M(128);

    CT_LOG_RUN_INF("[BACKUP] optimun file count %u, file count %u at best workload, min workload %lluM",
        min_file_count, best_count, min_workload / SIZE_M(1));
    return sec_size;
}

status_t bak_get_section_threshold(knl_session_t *session)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    uint64 file_size;
    uint32 file_hwm_start = 0;
    uint64 max_filesize = 0;
    uint64 max_workload = 0;
    uint32 datafile_num = 0;
    uint32 file_id = 0;
    uint32 bak_file_num = 0;
    uint32 res_id;
    uint32 proc_count = bak_log_paral_enable(bak) ? (bak->proc_count - BAK_PARAL_LOG_PROC_NUM) : bak->proc_count;
    uint64 proc_workloads[DATAFILE_MAX_BLOCK_NUM] = { 0 };
    uint32 sec_num;

    if (bak->section_threshold > 0) {
        bak->section_threshold = (bak->section_threshold / DEFAULT_PAGE_SIZE(session)) * DEFAULT_PAGE_SIZE(session);
        CT_LOG_RUN_INF("[BACKUP] user defined section threshold is %lluM", bak->section_threshold / SIZE_M(1));
        return CT_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);

    uint64 *files_size = (uint64 *)cm_push(session->stack, CT_MAX_DATA_FILES * sizeof(uint64));
    uint32 *hwm_start = (uint32 *)cm_push(session->stack, CT_MAX_DATA_FILES * sizeof(uint32));
    for (;;) {
        datafile_t *datafile = db_get_next_datafile(session, &file_id, &file_size, &file_hwm_start);
        if (datafile == NULL) {
            // end of valid datafile
            break;
        }

        if (bak->target_info.target == TARGET_ALL && !bak->exclude_spcs[datafile->space_id]) {
            files_size[datafile_num] = file_size;
            hwm_start[datafile_num] = file_hwm_start;
            max_filesize = MAX(max_filesize, file_size);
            datafile_num++;
        }

        if (bak->target_info.target == TARGET_TABLESPACE && bak->include_spcs[datafile->space_id]) {
            files_size[datafile_num] = file_size;
            hwm_start[datafile_num] = file_hwm_start;
            max_filesize = MAX(max_filesize, file_size);
            datafile_num++;
        }

        file_id = datafile->ctrl->id + 1;
    }

    knl_panic(max_filesize > 0 && max_filesize <= SIZE_T(8));
    uint32 simulate_num = (uint32)((max_filesize - 1) / SIZE_M(128) + 1); /* max num 8T / 128M = 65536 */

    uint64 *workloads = (uint64 *)cm_push(session->stack, simulate_num * sizeof(uint64));
    uint32 *file_count = (uint32 *)cm_push(session->stack, simulate_num * sizeof(uint32));

    for (res_id = 0; res_id < simulate_num; res_id++) {
        bak_file_num = 0;
        bak->section_threshold = (uint64)SIZE_M(128) * (res_id + 1);
        for (uint32 i = 0; i < datafile_num; i++) {
            if (bak_paral_task_simulation(session, proc_workloads, proc_count, files_size[i],
                hwm_start[i], &sec_num) != CT_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return CT_ERROR;
            }
            bak_file_num += sec_num;
        }

        max_workload = 0;
        for (uint32 j = 0; j < proc_count; j++) {
            if (proc_workloads[j] > max_workload) {
                max_workload = proc_workloads[j];
            }
            proc_workloads[j] = 0;
        }

        workloads[res_id] = max_workload;
        file_count[res_id] = bak_file_num;
    }
    knl_panic(res_id == simulate_num);
    uint64 sec_thresh = bak_optimun_section_threshold(workloads, file_count, simulate_num);

    knl_panic(sec_thresh >= SIZE_M(128) && sec_thresh < max_filesize + SIZE_M(128));
    bak->section_threshold = sec_thresh;
    CT_LOG_RUN_INF("[BACKUP] optimun section threshold %lluM, max file size %lluM, datafile count %u",
                   sec_thresh / SIZE_M(1), max_filesize / SIZE_M(1), datafile_num);

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

static bool32 bak_is_sec_num_equal(knl_session_t *session, bak_assignment_t *assign_ctrl, uint32 sec_num)
{
    bak_context_t *bkup_ctx = &session->kernel->backup_ctx;
    bak_t *bak = &bkup_ctx->bak;

    if (!bak_log_paral_enable(bak)) {
        return CT_TRUE;
    }

    if (bak->device.datafile[assign_ctrl->file_id].sec_num != sec_num) {
        CT_LOG_RUN_ERR("[BACKUP] datafile sec num has been changed from %u to %u",
            bak->device.datafile[assign_ctrl->file_id].sec_num, sec_num);
        return CT_FALSE;
    }
    return CT_TRUE;
}

static uint32 bak_get_index(bak_t *bak, bak_assignment_t *assign_ctrl)
{
    uint32 index;

    if (assign_ctrl->is_paral_log_backup) {
        // pos 0 is for ctrl. 1 ~ sec number is for datafile. (sec numbser + 1) ~ max is for logfile
        index = bak->device.sec_number + bak->paral_log_bak_number;
        CT_LOG_DEBUG_INF("[BACKUP] get index [%u] for paral log. Current sec number %u and paral log bak number %u",
            index, bak->device.sec_number, bak->paral_log_bak_number);
    } else {
        index = bak->file_count - 1;
        CT_LOG_RUN_INF("[BACKUP] get index [%u], current file count %u", index, bak->file_count);
    }
    return index;
}

static void bak_task_prepare_file_param(bak_t *bak, bak_assignment_t *assign_ctrl)
{
    errno_t ret;

    if (!assign_ctrl->is_paral_log_backup) {
        assign_ctrl->bak_file.handle = bak->local.handle;
        bak->local.type = cm_device_type(bak->local.name);
        assign_ctrl->bak_file.type = bak->local.type;
        ret = strncpy_s(assign_ctrl->bak_file.name, CT_FILE_NAME_BUFFER_SIZE, bak->local.name, strlen(bak->local.name));
        knl_securec_check(ret);
        bak->local.handle = CT_INVALID_HANDLE;
        bak->local.name[0] = '\0';
    } else {
        assign_ctrl->bak_file.handle = bak->log_local.handle;
        bak->log_local.type = cm_device_type(bak->log_local.name);
        assign_ctrl->bak_file.type = bak->log_local.type;
        ret = strncpy_s(assign_ctrl->bak_file.name, CT_FILE_NAME_BUFFER_SIZE, bak->log_local.name,
            strlen(bak->log_local.name));
        knl_securec_check(ret);
        bak->log_local.handle = CT_INVALID_HANDLE;
        bak->log_local.name[0] = '\0';
    }
}

status_t bak_task_prepare(knl_session_t *session, bak_assignment_t *assign_ctrl, uint32 *bak_id)
{
    bak_context_t *bak_ctx = &session->kernel->backup_ctx;
    bak_t *bak = &bak_ctx->bak;
    uint32 bak_index;

    if (bak->rst_file.file_type == RESTORE_ALL) {
        if (rst_wait_ctrlfile_ready(bak) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (assign_ctrl->task == BAK_BACKUP_TASK) {
        bak_index = bak_get_index(bak, assign_ctrl);
        if (bak_paral_create_bakfile(session, bak_index, assign_ctrl) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else if (assign_ctrl->task == BAK_RESTORE_TASK) {
        bak_index = bak->curr_file_index;
        if (rst_paral_open_bakfile(session, bak->files[bak_index].type, bak_index, bak->files[bak_index].id,
                                   bak->files[bak_index].sec_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        return CT_ERROR;
    }

    *bak_id = bak_index;
    assign_ctrl->start = 0;
    assign_ctrl->end = 0;
    assign_ctrl->section_start = 0;
    assign_ctrl->section_end = 0;
    assign_ctrl->bak_index = bak_index;
    assign_ctrl->type = bak->files[bak_index].type;
    bak_task_prepare_file_param(bak, assign_ctrl);

    assign_ctrl->arch_id = CT_INVALID_ID32;
    if (bak->files[bak_index].type == BACKUP_ARCH_FILE) {
        assign_ctrl->arch_id = 0;
        for (uint32 i = 0; i < bak_index; i++) {
            if (bak->files[i].type == BACKUP_ARCH_FILE && bak->files[i].skipped != CT_TRUE) {
                assign_ctrl->arch_id++;
            }
        }
    }

    CT_LOG_RUN_INF("[BACKUP] is backup %u, sec id %u, bak index %u, file type %u, size %llu, name %s",
                   assign_ctrl->task == BAK_BACKUP_TASK, assign_ctrl->sec_id, bak_index, assign_ctrl->type,
                   assign_ctrl->file_size, assign_ctrl->bak_file.name);

    return CT_SUCCESS;
}

uint32 bak_datafile_count_sec(knl_session_t *session, uint64 file_size_input, uint32 hwm_start,
    uint64 *sec_size, bool32 *diveded)
{
    uint64 file_size = file_size_input;
    bak_t *bak = &session->kernel->backup_ctx.bak;
    uint64 sec_min_size = bak->section_threshold;
    uint32 proc_count = bak_log_paral_enable(bak) ? (bak->proc_count - BAK_PARAL_LOG_PROC_NUM) : bak->proc_count;
    uint32 sec_num;
    uint64 page_count;
    uint64 sec_page_count;

    if (proc_count == 1 || file_size <= (sec_min_size + hwm_start * DEFAULT_PAGE_SIZE(session))) {
        *sec_size = file_size;
        sec_num = 1;
        *diveded = CT_FALSE;
        return sec_num;
    }

    file_size -= hwm_start * DEFAULT_PAGE_SIZE(session);
    page_count = file_size / DEFAULT_PAGE_SIZE(session);
    if (file_size > (proc_count - 1) * sec_min_size) {
        // max datafile section count is proc_count, need calculate new sec_size
        sec_page_count = (page_count - 1) / proc_count + 1;
        *sec_size = (CM_ALIGN_ANY(sec_page_count, PAGE_GROUP_COUNT)) * DEFAULT_PAGE_SIZE(session);
        sec_num = proc_count;
    } else {
        *sec_size = sec_min_size;
        sec_page_count = sec_min_size / DEFAULT_PAGE_SIZE(session);
        sec_num = page_count % sec_page_count == 0 ?
            (uint32)(page_count / sec_page_count) : (uint32)(page_count / sec_page_count) + 1;
    }
    *diveded = CT_TRUE;
    return sec_num;
}

status_t bak_assign_backup_task(knl_session_t *session, bak_process_t *proc,
    uint64 datafile_size, bool32 paral_log_backup)
{
    bak_context_t *bak_ctx = &session->kernel->backup_ctx;
    bak_t *bak = &bak_ctx->bak;
    bak_assignment_t *assign_ctrl = &proc->assign_ctrl;
    bak_file_t *bak_file = NULL;
    uint32 sec_id = 0;
    uint64 sec_size;
    uint32 bak_index;
    uint32 sec_num;
    bool32 devided = CT_TRUE;

    knl_panic(proc->is_free);
    assign_ctrl->is_paral_log_backup = paral_log_backup;
    assign_ctrl->task = BAK_BACKUP_TASK;
    if (bak_task_prepare(session, assign_ctrl, &bak_index) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (assign_ctrl->type == BACKUP_DATA_FILE) {
        if (assign_ctrl->file_id >= CT_MAX_DATA_FILES) {
            CT_THROW_ERROR(ERR_INVALID_DATAFILE_NUMBER, assign_ctrl->file_id, 0, (CT_MAX_DATA_FILES - 1));
            return CT_ERROR;
        }
        sec_id = assign_ctrl->sec_id;
        if (paral_log_backup) {
            sec_num = bak_datafile_section_count(session, datafile_size, assign_ctrl->file_hwm_start,
                                                 &sec_size, &devided);
        } else {
            sec_num = bak_datafile_count_sec(session, datafile_size, assign_ctrl->file_hwm_start, &sec_size, &devided);
        }
        if (!bak_is_sec_num_equal(session, assign_ctrl, sec_num)) {
            return CT_ERROR;
        }
        assign_ctrl->is_section = sec_num > 1;

        if (sec_id == 0) {
            assign_ctrl->section_start = 0;
            assign_ctrl->section_end = devided ?
                (sec_size + assign_ctrl->file_hwm_start * DEFAULT_PAGE_SIZE(session)) : sec_size;
        } else {
            assign_ctrl->section_start = sec_id * sec_size + assign_ctrl->file_hwm_start * DEFAULT_PAGE_SIZE(session);
            assign_ctrl->section_end = assign_ctrl->section_start + sec_size;
        }

        if (assign_ctrl->section_end > datafile_size) {
            assign_ctrl->section_end = datafile_size;
            knl_panic(sec_num > 1);
            knl_panic(sec_id == sec_num - 1);
        }

        knl_panic(assign_ctrl->section_end > assign_ctrl->section_start);

        proc->ctrl.offset = (sec_id == 0) ? DEFAULT_PAGE_SIZE(session) : assign_ctrl->section_start;
        assign_ctrl->start = proc->ctrl.offset;
        assign_ctrl->end = proc->ctrl.offset;
        assign_ctrl->file_size = assign_ctrl->section_end;
    }

    bak_file = &bak->files[bak_index];
    bak_file->sec_start = assign_ctrl->section_start;
    bak_file->sec_end = assign_ctrl->section_end;
    CT_LOG_RUN_INF("[BACKUP] backup file_%u_%u, section [%lldK, %lldK], id %u, type %u, offset %llu, devided %u, "
                   "hwm_start %u", bak_file->id, sec_id, bak_file->sec_start / SIZE_K(1), bak_file->sec_end / SIZE_K(1),
                   bak_index, assign_ctrl->type, proc->ctrl.offset, devided, assign_ctrl->file_hwm_start);
    CM_MFENCE;
    proc->is_free = CT_FALSE;
    return CT_SUCCESS;
}

status_t bak_assign_restore_task(knl_session_t *session, bak_process_t *proc)
{
    bak_context_t *bak_ctx = &session->kernel->backup_ctx;
    bak_t *bak = &bak_ctx->bak;
    bak_process_t *bg_process = bak_ctx->process;
    bak_process_t *common_proc = &bg_process[BAK_COMMON_PROC];
    bak_assignment_t *assign_ctrl = &proc->assign_ctrl;
    bak_file_t *bak_file = NULL;
    uint32 bak_index;
    int64 curr_filesize;

    knl_panic(proc->is_free);
    assign_ctrl->task = BAK_RESTORE_TASK;
    if (bak_task_prepare(session, assign_ctrl, &bak_index) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (assign_ctrl->type == BACKUP_DATA_FILE) {
        bak_file = &bak->files[bak_index];

        curr_filesize = common_proc->datafile_size[bak_file->id];
        knl_panic(curr_filesize >= 0);
        CT_LOG_RUN_INF("[RESTORE] restore data_%u_%u, recent filesize %lldK, section [%lluK, %lluK], bakcup id %u",
                       bak_file->id, bak_file->sec_id, curr_filesize / (int64)SIZE_K(1),
                       bak_file->sec_start / SIZE_K(1), bak_file->sec_end / SIZE_K(1), bak_index);

        /* for incremental restore, fill_offset can not be less than current file size */
        assign_ctrl->fill_offset = MAX(bak_file->sec_start, (uint64)curr_filesize);
        assign_ctrl->section_start = bak_file->sec_start;
        assign_ctrl->section_end = bak_file->sec_end;
    }

    for (uint32 j = 0; j < CT_MAX_DATA_FILES; j++) {
        knl_panic(proc->datafiles[j] == CT_INVALID_HANDLE);
    }
    CM_MFENCE;
    proc->is_free = CT_FALSE;
    return CT_SUCCESS;
}

status_t bak_paral_backup_datafile(knl_session_t *session, bak_assignment_t *assign_ctrl, datafile_t *datafile,
                                   uint64 data_size)
{
    bak_process_t *proc = NULL;
    uint64 sec_size;
    bool32 diveded = CT_TRUE;
    uint32 sec_num = bak_datafile_count_sec(session, data_size, assign_ctrl->file_hwm_start, &sec_size, &diveded);
    if (!bak_is_sec_num_equal(session, assign_ctrl, sec_num)) {
        return CT_ERROR;
    }

    for (uint32 sec_id = 0; sec_id < sec_num; sec_id++) {
        if (bak_get_free_proc(session, &proc, CT_FALSE) != CT_SUCCESS) {
            return CT_ERROR;
        }

        proc->assign_ctrl = *assign_ctrl;
        bak_read_prepare(session, proc, datafile, sec_id);
        if (bak_assign_backup_task(session, proc, data_size, CT_FALSE) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

void bak_assign_stream_backup_task(knl_session_t *session, device_type_t device_type, const char *file_name,
    bool32 arch_compressed, uint32 file_id, uint64 hwm_size, uint32 hwm_start)
{
    bak_context_t *bak_ctx = &session->kernel->backup_ctx;
    bak_t *bak = &bak_ctx->bak;
    bak_ctrl_t *ctrl = NULL;
    bak_process_t *proc = NULL;
    bak_assignment_t *assign_ctrl = NULL;
    uint32 bak_index = bak->file_count - 1;
    errno_t ret;

    for (uint32 id = 0; id < bak->proc_count; id++) {
        proc = &bak_ctx->process[id + 1];

        ctrl = &proc->ctrl;
        ctrl->type = device_type;
        ctrl->offset = DEFAULT_PAGE_SIZE(session);
        ctrl->handle = CT_INVALID_HANDLE;
        ctrl->arch_compressed = arch_compressed;

        ret = strcpy_sp(ctrl->name, CT_FILE_NAME_BUFFER_SIZE, file_name);
        knl_securec_check(ret);

        assign_ctrl = &proc->assign_ctrl;
        assign_ctrl->start = 0;
        assign_ctrl->end = 0;
        assign_ctrl->file_id = file_id;
        assign_ctrl->sec_id = 0;
        assign_ctrl->file_size = hwm_size;
        assign_ctrl->file_hwm_start = hwm_start;
        assign_ctrl->section_start = 0;
        assign_ctrl->section_end = 0;
        assign_ctrl->bak_index = bak_index;
        assign_ctrl->type = bak->files[bak_index].type;

        knl_panic(proc->is_free);
        assign_ctrl->task = bak->is_building ? BAK_BUILD_BACKUP_TASK : BAK_STREAM_BACKUP_TASK;
        CM_MFENCE;
        proc->is_free = CT_FALSE;
    }
}

static status_t bak_compress_local_write(bak_t *bak, bak_process_t *bak_proc, char *buf, int32 size, bool32 stream_end)
{
    knl_compress_t *compress_ctx = &bak_proc->compress_ctx;
    char *compress_buf = compress_ctx->compress_buf.aligned_buf;
    bak_local_t *bak_file = &bak_proc->assign_ctrl.bak_file;
    char *use_buf = NULL;
    date_t start;

    knl_compress_set_input(bak->record.attr.compress, compress_ctx, buf, (uint32)size);
    CT_LOG_DEBUG_INF("[BACKUP] compress set input with size %d stream_end %d", size, stream_end);
    bak_proc->stat.encode_size += size;
    for (;;) {
        start = g_timer()->now;
        if (knl_compress(bak->record.attr.compress, compress_ctx, stream_end, compress_buf,
            (uint32)COMPRESS_BUFFER_SIZE(bak)) != CT_SUCCESS) {
            return CT_ERROR;
        }
        CT_LOG_DEBUG_INF("[BACKUP] compress data from %d to %u, stream_end %d",
            size, compress_ctx->write_len, stream_end);
        use_buf = compress_buf;

        if (bak->encrypt_info.encrypt_alg != ENCRYPT_NONE) {
            if (bak_encrypt_data(bak_proc, compress_buf, compress_ctx->write_len) != CT_SUCCESS) {
                return CT_ERROR;
            }
            use_buf = bak_proc->encrypt_ctx.encrypt_buf.aligned_buf;
        }
        bak_proc->stat.encode_time += (g_timer()->now - start);

        if (bak_local_write(bak_file, use_buf, compress_ctx->write_len, bak, bak_file->size) != CT_SUCCESS) {
            return CT_ERROR;
        }
        bak_proc->stat.write_size += compress_ctx->write_len;
        bak_file->size += compress_ctx->write_len;
        if (compress_ctx->finished) {
            break;
        }
    }

    return CT_SUCCESS;
}

status_t bak_write_to_local_disk(bak_context_t *ctx, bak_process_t *bak_proc, char *buf, int32 size,
    bool32 stream_end, bool32 arch_compressed)
{
    bak_t *bak = &ctx->bak;
    bak_local_t *bak_file = &bak_proc->assign_ctrl.bak_file;
    char *write_buf = buf;
    status_t status;
    date_t start;

    if (stream_end) {
        knl_panic(size == 0);
    } else {
        knl_panic(size > 0);
    }
    if (bak_file->size != cm_device_size(bak_file->type, bak_file->handle)) {
        CT_LOG_RUN_INF("[BACKUP] write size %d, write offset %lld, proc id %u",
            size, bak_file->size, bak_proc->proc_id);
        return CT_ERROR;
    }
    if (bak->record.attr.compress == COMPRESS_NONE) {
        if (bak->encrypt_info.encrypt_alg != ENCRYPT_NONE) {
            start = g_timer()->now;
            if (bak_encrypt_data(bak_proc, buf, size) != CT_SUCCESS) {
                return CT_ERROR;
            }
            bak_proc->stat.encode_time += (g_timer()->now - start);
            bak_proc->stat.encode_size += size;
            write_buf = bak_proc->encrypt_ctx.encrypt_buf.aligned_buf;
        }

        status = bak_local_write(bak_file, write_buf, size, bak, bak_file->size);
        bak_proc->stat.write_size += size;
        bak_file->size += size;
    } else {
        status = bak_compress_local_write(bak, bak_proc, write_buf, size, stream_end);
    }

    bak_update_progress(bak, (uint64)size);
    CT_LOG_DEBUG_INF("[BACKUP] paral write data, size %d", size);
    status = (bak->failed) ? CT_ERROR : status;
    return status;
}

static status_t bak_paral_backup_init(knl_session_t *session, bak_process_t *proc)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    uint32 bak_file_id = proc->assign_ctrl.bak_index;
    bak_file_type_t file_type = bak->files[bak_file_id].type;
    bak_local_t *bak_file = &proc->assign_ctrl.bak_file;

    bak_file->size = 0;
    knl_panic(file_type == proc->assign_ctrl.type);

    if (bak->encrypt_info.encrypt_alg != ENCRYPT_NONE) {
        if (bak_encrypt_init(bak, &proc->encrypt_ctx, &bak->files[bak_file_id], CT_TRUE) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    if (bak->record.attr.compress != COMPRESS_NONE) {
        if (knl_compress_init(bak->record.attr.compress, &proc->compress_ctx, CT_TRUE) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t bak_paral_backup(knl_session_t *session, bak_process_t *proc)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    uint32 bak_file_id = proc->assign_ctrl.bak_index;
    uint32 log_block_size = proc->assign_ctrl.log_block_size;
    bak_file_type_t file_type = bak->files[bak_file_id].type;
    bak_local_t *bak_file = &proc->assign_ctrl.bak_file;
    errno_t ret;
    status_t status;

    if (bak_paral_backup_init(session, proc) != CT_SUCCESS) {
        return CT_ERROR;
    }
    bool32 arch_compressed = CT_FALSE;
    knl_panic(file_type >= BACKUP_DATA_FILE && file_type <= BACKUP_ARCH_FILE);
    if (file_type == BACKUP_DATA_FILE) {
        if (bak_write_lz4_compress_head(bak, proc, bak_file) != CT_SUCCESS) {
            return CT_ERROR;
        }
        status = bak_read_datafile(session, proc, CT_TRUE);
    } else {
        status = bak_read_logfile(session, ctx, proc, log_block_size, CT_TRUE, &arch_compressed);
    }

    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] status %u, %s", status, proc->ctrl.name);
        return CT_ERROR;
    }

    if (bak->record.attr.compress != COMPRESS_NONE) {
        if (bak_write_to_local_disk(ctx, proc, proc->backup_buf.aligned_buf, 0, CT_TRUE, CT_FALSE) != CT_SUCCESS) {
            return CT_ERROR;
        }
        knl_compress_end(bak->record.attr.compress, &proc->compress_ctx, CT_TRUE);
    }

    if (bak->encrypt_info.encrypt_alg != ENCRYPT_NONE) {
        if (bak_encrypt_end(bak, &proc->encrypt_ctx) != CT_SUCCESS) {
            return CT_ERROR;
        }
        /* gcm_tag is used as memory, not a string */
        ret = memcpy_sp(bak->files[bak_file_id].gcm_tag, EVP_GCM_TLS_TAG_LEN, proc->encrypt_ctx.encrypt_buf.aligned_buf,
                        EVP_GCM_TLS_TAG_LEN);
        knl_securec_check(ret);
    }

    return CT_SUCCESS;
}

status_t bak_check_direct_mode_for_archfile(bak_assignment_t *assign_ctrl, bak_t *bak, uint32 mode, bool32 *can_direct)
{
    if (bak->record.attr.compress != COMPRESS_NONE) {
        *can_direct = CT_FALSE;
        return CT_SUCCESS;
    }
    if (assign_ctrl->type == BACKUP_DATA_FILE) {
        *can_direct = CT_TRUE;
        return CT_SUCCESS;
    }
    bak_local_t *bak_file = &assign_ctrl->bak_file;
    char *buf = (char *)malloc(sizeof(log_file_head_t));
    errno_t err = memset_sp(buf, sizeof(log_file_head_t), 0, sizeof(log_file_head_t));
    knl_securec_check(err);
    mode = mode | O_DIRECT;
    int32 handle = -1;
    if (cm_open_file(bak_file->name, mode, &handle) == CT_SUCCESS) {
        if (cm_write_file(handle, buf, sizeof(log_file_head_t)) == CT_SUCCESS) {
            *can_direct = CT_TRUE;
            CT_LOG_RUN_INF("[BACKUP] write 512 to file succ, mode |= O_DIRECT");
        } else {
            if (errno != EINVAL) {
                cm_close_file(handle);
                CM_FREE_PTR(buf);
                CT_LOG_RUN_ERR("[BACKUP] write 512 to file fail, errno %u.", errno);
                return CT_ERROR;
            }
            cm_reset_error();
            *can_direct = CT_FALSE;
            CT_LOG_RUN_INF("[BACKUP] write 512 to file fail.");
        }
    } else {
        CT_LOG_RUN_ERR("[BACKUP] open file failed.");
        return CT_ERROR;
    }
    cm_close_file(handle);
    CM_FREE_PTR(buf);
    return CT_SUCCESS;
}

void bak_paral_backup_task(knl_session_t *session, bak_process_t *proc)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_assignment_t *assign_ctrl = &proc->assign_ctrl;
    bak_local_t *bak_file = &assign_ctrl->bak_file;
    bak_ctrl_t *ctrl = &proc->ctrl;
    timeval_t tv_begin;
    status_t status;
    uint32 mode = O_BINARY | O_RDWR;
    bool32 can_direct = CT_FALSE;
    if (bak_check_direct_mode_for_archfile(assign_ctrl, bak, mode, &can_direct) != CT_SUCCESS) {
        bak->failed = CT_TRUE;
        CT_LOG_RUN_ERR("[BACKUP] check dircet mode failed, proc id %u, file id %u, backup index %u, name %s",
                       proc->proc_id, assign_ctrl->file_id, assign_ctrl->bak_index, proc->ctrl.name);
    } else {
        mode = (can_direct != CT_TRUE ? mode : mode | O_DIRECT);
    }
    knl_panic(!bak->restore);
    CT_LOG_DEBUG_INF("[BACKUP] start backup, proc id %u, file id %u, backup id %u, file name %s, file size %llu",
        proc->proc_id, assign_ctrl->file_id, assign_ctrl->bak_index, proc->ctrl.name, assign_ctrl->file_size);

    if (bak->failed != CT_TRUE && cm_open_file(bak_file->name, mode, &bak_file->handle) == CT_SUCCESS) {
        if (bak_paral_backup(session, proc) != CT_SUCCESS) {
            bak->failed = CT_TRUE;
            CT_LOG_RUN_ERR("[BACKUP] backup task failed, proc id %u, file id %u, backup index %u, name %s",
                           proc->proc_id, assign_ctrl->file_id, assign_ctrl->bak_index, proc->ctrl.name);
        }
    } else {
        bak->failed = CT_TRUE;
        CT_LOG_RUN_ERR("[BACKUP] backup task failed, can not open file %s", bak_file->name);
    }

    cantian_record_io_stat_begin(IO_RECORD_EVENT_BAK_FSYNC, &tv_begin);
    status = bak_fsync_and_close(bak, bak_file->type, &bak_file->handle);
    cantian_record_io_stat_end(IO_RECORD_EVENT_BAK_FSYNC, &tv_begin, IO_RECORD_STAT_RET(status));
    bak_file->handle = CT_INVALID_HANDLE;

    if (assign_ctrl->type == BACKUP_DATA_FILE) {
        for (uint32 id = 0; id < CT_MAX_DATA_FILES; id++) {
            cm_close_device(proc->file_type[id], &proc->datafiles[id]);
        }
    } else {
        if (bak->inst_id != g_dtc->profile.inst_id) {
            dtc_bak_unlatch_logfile(session, proc, bak->inst_id);
        } else {
            bak_unlatch_logfile_if_necessary(session, proc);
        }
        cm_close_device(ctrl->type, &ctrl->handle);
    }

    bak->files[assign_ctrl->bak_index].size = (uint64)bak_file->size;
    CT_LOG_DEBUG_INF("[BACKUP] end backup, proc id %u, file id %u, backup index %u, backup size %llu,"
        "file name %s",
        proc->proc_id, assign_ctrl->file_id, assign_ctrl->bak_index, assign_ctrl->bak_file.size, proc->ctrl.name);
}

status_t bak_block_data_encode(bak_t *bak, bak_process_t *proc, char **buf, uint32 *size, bak_file_t *file)
{
    char *data_buf = *buf;
    uint32 data_size = *size;
    status_t status;
    date_t start = g_timer()->now;
    knl_session_t *session = proc->session;

    knl_panic_log(data_size <= BACKUP_STREAM_BUFSIZE(session, bak),
                  "current data_size is abnormal, panic info: data_size %d", data_size);
    if (bak->record.attr.compress != COMPRESS_NONE && data_size > 0) {
        uint32 compress_size = 0;
        char *compress_buf = proc->compress_ctx.compress_buf.aligned_buf;
        if (bak->record.attr.compress == COMPRESS_LZ4) {
            status = bak_block_lz4_compress(bak, &proc->compress_ctx, data_buf, data_size, &compress_size);
        } else {
            status = bak_block_zstd_compress(bak, &proc->compress_ctx, data_buf, data_size, &compress_size);
        }
        if (status != CT_SUCCESS) {
            return CT_ERROR;
        }
        data_buf = compress_buf;
        data_size = compress_size;
    }

    if (bak->encrypt_info.encrypt_alg != ENCRYPT_NONE && data_size > 0) {
        if (bak_block_encrypt(bak, &proc->encrypt_ctx, data_buf, data_size,
            (const unsigned char *)file->gcm_iv) != CT_SUCCESS) {
            return CT_ERROR;
        }

        data_buf = proc->encrypt_ctx.encrypt_buf.aligned_buf;
        data_size += EVP_GCM_TLS_TAG_LEN;
    }
    proc->stat.encode_size += (*size);
    proc->stat.encode_time += (g_timer()->now - start);

    *buf = data_buf;
    *size = data_size;
    return CT_SUCCESS;
}

void bak_copy_block_to_sendbuf(bak_stream_buf_t *send_stream, bak_block_head_t block_info,
                               const char *data_buf, uint32 data_size)
{
    char *send_buf = send_stream->bufs[send_stream->wid].aligned_buf;
    uint32 used_size = send_stream->data_size[send_stream->wid];
    uint32 remain_size = send_stream->buf_size - used_size;
    bak_block_head_t *block = (bak_block_head_t *)(send_buf + used_size);
    errno_t ret;

    knl_panic(block_info.block_size >= sizeof(bak_block_head_t));

    if (data_size == 0) {
        send_stream->read_offset = block_info.offset + block_info.read_size;
        send_stream->curr_block_id++;
        knl_panic(used_size <= send_stream->buf_size);
        CT_LOG_DEBUG_INF("[BACKUP] skip copy zero block, offset %llu", block_info.offset);
        return;
    }

    *block = block_info;
    ret = memcpy_sp((char *)block + sizeof(bak_block_head_t), remain_size, data_buf, data_size);
    knl_securec_check(ret);

    send_stream->read_offset = block_info.offset + block_info.read_size;
    send_stream->curr_block_id++;
    send_stream->data_size[send_stream->wid] += block_info.block_size;
    send_stream->bakfile_size += block_info.block_size;

    knl_panic(block_info.block_size == data_size + sizeof(bak_block_head_t));
    knl_panic(send_stream->data_size[send_stream->wid] <= send_stream->buf_size);
}

status_t bak_read_file_block(knl_session_t *session, bak_process_t *proc, uint64 offset, int32 read_size)
{
    bak_assignment_t *assign_ctrl = &proc->assign_ctrl;
    bak_ctrl_t *ctrl = &proc->ctrl;
    char *backup_buf = proc->backup_buf.aligned_buf;
    date_t start = g_timer()->now;

    ctrl->offset = offset;
    assign_ctrl->file_size = offset + read_size;
    knl_panic_log(read_size <= BACKUP_STREAM_BUFSIZE(session, &session->kernel->backup_ctx.bak),
                  "current read_size is abnormal, panic info: read_size %d", read_size);

    if (assign_ctrl->type != BACKUP_DATA_FILE) {
        if (cm_read_device(ctrl->type, ctrl->handle, ctrl->offset, backup_buf, read_size) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BACKUP] failed to read %s", ctrl->name);
            return CT_ERROR;
        }
        proc->write_size = read_size;
    } else {
        if (bak_read_datafile_pages(session, proc) != CT_SUCCESS) {
            return CT_ERROR;
        }
        knl_panic(proc->write_size <= read_size);
    }
    proc->stat.read_time += (g_timer()->now - start);
    proc->stat.read_size += read_size;

    return CT_SUCCESS;
}

status_t bak_read_block_to_stream(knl_session_t *session, bak_process_t *proc, uint64 offset, uint32 read_size,
                                  uint32 block_id)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    bak_stream_buf_t *stream = &bak->send_stream;
    bak_block_head_t block_info;
    char *data_buf = proc->backup_buf.aligned_buf;
    uint32 bak_file_id = proc->assign_ctrl.bak_index;

    if (bak_read_file_block(session, proc, offset, read_size) != CT_SUCCESS) {
        return CT_ERROR;
    }
    uint32 origin_size = proc->write_size; // real read size
    knl_panic(read_size >= origin_size);

    uint32 data_size = origin_size;
    if (bak_block_data_encode(bak, proc, &data_buf, &data_size, &bak->files[bak_file_id]) != CT_SUCCESS) {
        return CT_ERROR;
    }
    uint32 block_size = data_size + sizeof(bak_block_head_t);
    knl_panic_log(block_size <= BACKUP_BUFFER_SIZE(bak),
                  "current block_size is abnormal, panic info: block_size %d", block_size);

    for (;;) {
        if (bak_check_session_status(session) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!cm_spin_try_lock(&stream->lock)) {
            cm_spin_sleep();
            continue;
        }

        // make sure the sending order of file blocks
        if (stream->curr_block_id == block_id &&
            stream->data_size[stream->wid] + block_size <= stream->buf_size) {
            // it's the turn to send this block, need copy block to send buffer
            // skip double write area
            if (bak_datafile_contains_dw(session, &proc->assign_ctrl) && block_id == 1) {
                knl_panic(stream->read_offset + DW_DISTRICT_PAGES * DEFAULT_PAGE_SIZE(session) == offset);
            } else {
                knl_panic(stream->read_offset == offset);
            }
            break;
        }
        cm_spin_unlock(&stream->lock);
        cm_spin_sleep();
    }

    block_info.offset = offset;
    block_info.read_size = read_size;
    block_info.origin_size = origin_size; // origin_size must not be large than read_size
    block_info.block_size = block_size;
    block_info.block_id = block_id;
    block_info.file_id = bak_file_id;
    block_info.magic_num = LOG_MAGIC_NUMBER;
    block_info.checksum = 0;
    bak_copy_block_to_sendbuf(stream, block_info, data_buf, data_size);
    cm_spin_unlock(&stream->lock);

    return CT_SUCCESS;
}

status_t bak_paral_stream_backup(knl_session_t *session, bak_process_t *proc)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    bak_assignment_t *assign_ctrl = &proc->assign_ctrl;
    uint32 bak_file_id = assign_ctrl->bak_index;
    bak_file_type_t file_type = bak->files[bak_file_id].type;
    bak_read_cursor_t *cursor = &bak->read_cursor;
    uint64 read_size;
    uint32 block_id;
    uint64 offset;
    bool32 contains_dw = bak_datafile_contains_dw(session, assign_ctrl);

    assign_ctrl->bak_file.size = 0;
    knl_panic(file_type == assign_ctrl->type);
    knl_panic(file_type >= BACKUP_DATA_FILE && file_type <= BACKUP_ARCH_FILE);

    for (;;) {
        if (bak_check_session_status(session) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!cm_spin_try_lock(&cursor->lock)) {
            cm_spin_sleep();
            continue;
        }

        if (cursor->offset >= cursor->file_size) {
            // current file read end
            knl_panic(cursor->offset == cursor->file_size);
            cm_spin_unlock(&cursor->lock);
            break;
        }

        /* skip double write area */
        if (contains_dw && cursor->offset == SPACE_HEAD_END * DEFAULT_PAGE_SIZE(session)) {
            cursor->offset = DW_SPC_HWM_START * DEFAULT_PAGE_SIZE(session);
        }
        offset = cursor->offset;
        block_id = cursor->block_id;

        if (assign_ctrl->type == BACKUP_DATA_FILE) {
            read_size = bak_set_datafile_read_size(session, offset, contains_dw,
                cursor->file_size, assign_ctrl->file_hwm_start);
        } else {
            read_size = cursor->file_size - offset;
        }

        if (read_size > BACKUP_STREAM_BUFSIZE(session, bak)) {
            read_size = BACKUP_STREAM_BUFSIZE(session, bak);
        }

        cursor->block_id++;
        cursor->offset += read_size;
        cursor->read_size = read_size;
        cm_spin_unlock(&cursor->lock); // after get offset and read_size, unlock cursor

        // read block for range [offset, offset + read_size], then send block to send buffer in order
        if (bak_read_block_to_stream(session, proc, offset, (uint32)read_size, block_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

void bak_paral_stream_backup_task(knl_session_t *session, bak_process_t *proc)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    bak_assignment_t *assign_ctrl = &proc->assign_ctrl;
    bak_ctrl_t *ctrl = &proc->ctrl;

    CT_LOG_DEBUG_INF("[BACKUP] start stream backup, proc id %u, file id %u, backup id %u, file name %s", proc->proc_id,
                     assign_ctrl->file_id, assign_ctrl->bak_index, proc->ctrl.name);
    knl_panic(ctrl->handle == CT_INVALID_HANDLE);

    uint32 io_flag = (assign_ctrl->type == BACKUP_DATA_FILE) ?
        knl_io_flag(session) : knl_arch_io_flag(session, ctrl->arch_compressed);
    if (cm_open_device(ctrl->name, ctrl->type, io_flag, &ctrl->handle) != CT_SUCCESS) {
        bak->failed = CT_TRUE;
    }

    if (bak_paral_stream_backup(session, proc) != CT_SUCCESS) {
        bak->failed = CT_TRUE;
        CT_LOG_RUN_ERR("[BACKUP] backup task failed, proc id %u, file id %u, backup index %u, name %s", proc->proc_id,
                       assign_ctrl->file_id, assign_ctrl->bak_index, proc->ctrl.name);
    }
    cm_close_device(ctrl->type, &ctrl->handle);

    CT_LOG_DEBUG_INF("[BACKUP] end backup, proc id %u, file id %u, backup index %u, backup size %llu, file name %s",
                     proc->proc_id, assign_ctrl->file_id, assign_ctrl->bak_index, assign_ctrl->bak_file.size,
                     proc->ctrl.name);
}

status_t rst_paral_write_to_disk(bak_process_t *ctx, char *use_buf,
    int32 buf_size, uint64 file_offset, int32 *write_size)
{
    knl_session_t *session = ctx->session;
    bak_t *bak = &session->kernel->backup_ctx.bak;
    bak_local_t *bak_file = &ctx->assign_ctrl.bak_file;
    uint32 left_offset;
    uint32 align_size = ctx->blk_size > 0 ? ctx->blk_size : DEFAULT_PAGE_SIZE(session);
    date_t start = g_timer()->now;
    errno_t ret;

    ctx->curr_offset = file_offset;
    ctx->write_size = 0;
    ctx->read_size = buf_size;

    ctx->left_size = ctx->read_size % (int32)align_size;
    left_offset = (uint32)(ctx->read_size - ctx->left_size);
    ctx->read_size -= ctx->left_size;
    *write_size = ctx->read_size;

    if (ctx->blk_size > 0) {
        if (rst_write_data(session, &ctx->ctrl, use_buf, ctx->read_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (rst_restore_datafile(session, bak, ctx, use_buf, bak_file->name) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    ctx->stat.write_time += (g_timer()->now - start);
    ctx->stat.write_size += ctx->read_size;
    if (ctx->left_size > 0) {
        ret = memmove_s(use_buf, BACKUP_BUFFER_SIZE(bak), use_buf + left_offset, ctx->left_size);
        knl_securec_check(ret);
    }

    ctx->read_size = 0;

    return bak->failed ? CT_ERROR : CT_SUCCESS;
}

status_t rst_paral_decompress_to_disk(bak_process_t *process, uint32 read_size,
    bool32 read_end, uint64 file_offset, char *use_buf)
{
    bak_t *bak = &process->session->kernel->backup_ctx.bak;
    knl_compress_t *compress_ctx = &process->compress_ctx;
    char *compress_buf = compress_ctx->compress_buf.aligned_buf;
    date_t start;
    int32 write_size = 0;

    knl_compress_set_input(bak->record.attr.compress, compress_ctx, use_buf, read_size);
    CT_LOG_DEBUG_INF("[BACKUP] set input with %d", read_size);
    process->stat.encode_size += read_size;
    for (;;) {
        start = g_timer()->now;
        if (knl_decompress(bak->record.attr.compress, compress_ctx, read_end, compress_buf + process->left_size,
            BACKUP_BUFFER_SIZE(bak) - (uint32)process->left_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
        CT_LOG_DEBUG_INF("[BACKUP] decompress from %d to %d", read_size, compress_ctx->write_len);
        process->stat.encode_time += (g_timer()->now - start);
        knl_panic(compress_ctx->write_len + (uint32)process->left_size <= BACKUP_BUFFER_SIZE(bak));
        if (rst_paral_write_to_disk(process, compress_buf,
            (int32)compress_ctx->write_len + process->left_size, file_offset, &write_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
        process->uncompressed_offset += write_size;
        if (compress_ctx->finished) {
            break;
        }
    }
    if (compress_ctx->last_left_size > 0) {
        char *next_use_buf = process->backup_rw_buf.buf_data[!process->backup_rw_buf.write_index].data_addr +
                             process->start_loc - compress_ctx->last_left_size;
        errno_t ret = memmove_s(next_use_buf, process->start_loc, use_buf, compress_ctx->last_left_size);
        knl_securec_check(ret);
    }
    return CT_SUCCESS;
}

static status_t rst_paral_fill_datafile_tail(knl_session_t *session, bak_process_t *proc)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_assignment_t *assign_ctrl = &proc->assign_ctrl;
    int32 handle = INVALID_FILE_HANDLE;
    uint32 bak_index = assign_ctrl->bak_index;
    uint32 file_id = bak->files[bak_index].id;
    datafile_t *df = DATAFILE_GET(session, file_id);

    if (assign_ctrl->fill_offset >= assign_ctrl->section_end) {
        return CT_SUCCESS;
    }

    CT_LOG_RUN_INF("[RESTORE] fill datafile tail, start %lluK, end %lluK, backup id %u",
                   assign_ctrl->fill_offset / SIZE_K(1), assign_ctrl->section_end / SIZE_K(1), bak_index);
    if (spc_open_datafile(session, df, &proc->datafiles[file_id]) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] failed to open datafile %s", df->ctrl->name);
        return CT_ERROR;
    }
    proc->file_type[file_id] = df->ctrl->type;
    handle = proc->datafiles[file_id];

    if (!BAK_FILE_NEED_PUNCH(df) && rst_fill_file_gap(df->ctrl->type, handle, assign_ctrl->fill_offset,
        assign_ctrl->section_end, proc->fill_buf, BACKUP_BUFFER_SIZE(bak)) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] failed to write datafile %s", df->ctrl->name);
        return CT_ERROR;
    }

    if (db_fdatasync_file(session, handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] failed to fdatasync datafile %s", df->ctrl->name);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/*
impact of ENABLE_ARCH_COMPRESS/BACKUP OPTION/RESTORE_ARCH_COMPRESSED of archived logfiles:
+-----------------------+--------------+----------------+-------------------+--------------------------+--------------+
| ENABLE_ARCH_COMPRESS  | ARCHIVED LOG | BACKUP OPTION  | LOG IN BACKUP SET | RESTORE_ARCH_COMPRESSED  | RESTORED LOG |
+-----------------------+--------------+----------------+-------------------+--------------------------+--------------+
|         FALSE         |     NONE     |      NONE      |       NONE        |          FALSE           |     NONE     |
+-----------------------+--------------+----------------+-------------------+--------------------------+--------------+
|         FALSE         |     NONE     |      NONE      |       NONE        |          TRUE            |     NONE     |
+-----------------------+--------------+----------------+-------------------+--------------------------+--------------+
|         FALSE         |     NONE     |      ZSTD      |       ZSTD        |          FALSE           |     NONE     |
+-----------------------+--------------+----------------+-------------------+--------------------------+--------------+
|         FALSE         |     NONE     |      ZSTD      |       ZSTD        |          TRUE            |     ZSTD     |
+-----------------------+--------------+----------------+-------------------+--------------------------+--------------+
|         FALSE         |     NONE     |      LZ4       |       LZ4         |          FALSE           |     NONE     |
+-----------------------+--------------+----------------+-------------------+--------------------------+--------------+
|         FALSE         |     NONE     |      LZ4       |       LZ4         |          TRUE            |     NONE     |
+-----------------------+--------------+----------------+-------------------+--------------------------+--------------+
|         TRUE          |     ZSTD     |      NONE      |       ZSTD        |          FALSE           |     ZSTD     |
+-----------------------+--------------+----------------+-------------------+--------------------------+--------------+
|         TRUE          |     ZSTD     |      NONE      |       ZSTD        |          TRUE            |     ZSTD     |
+-----------------------+--------------+----------------+-------------------+--------------------------+--------------+
|         TRUE          |     ZSTD     |      ZSTD      |       ZSTD        |          FALSE           |     ZSTD     |
+-----------------------+--------------+----------------+-------------------+--------------------------+--------------+
|         TRUE          |     ZSTD     |      ZSTD      |       ZSTD        |          TRUE            |     ZSTD     |
+-----------------------+--------------+----------------+-------------------+--------------------------+--------------+
|         TRUE          |     ZSTD     |      LZ4       |       ZSTD        |          FALSE           |     ZSTD     |
+-----------------------+--------------+----------------+-------------------+--------------------------+--------------+
|         TRUE          |     ZSTD     |      LZ4       |       ZSTD        |          TRUE            |     ZSTD     |
+-----------------------+--------------+----------------+-------------------+--------------------------+--------------+
*/
bool32 rst_file_need_decompress(compress_algo_e compress, bak_file_type_t type, bak_t *bak,
    bool32 arch_compressed)
{
    // for data/ctrl file
    if (type != BACKUP_LOG_FILE && type != BACKUP_ARCH_FILE) {
        return (compress != COMPRESS_NONE);
    }

    // for archived logfile
    if (compress == COMPRESS_NONE) {
        return CT_FALSE;
    } else if (compress == COMPRESS_LZ4 || compress == COMPRESS_ZLIB) {
        return CT_TRUE;
    } else {
        if (arch_compressed) {
            return CT_TRUE;
        } else {
            return !bak->arch_keep_compressed;
        }
    }
}

static status_t rst_paral_arch_compressed_head(knl_session_t *session, bak_process_t *proc, log_file_head_t *log_head)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    char *backup_buf = proc->backup_buf.aligned_buf;
    log_file_head_t *head = (log_file_head_t *)backup_buf;
    bool32 arch_compressed = (log_head->cmp_algorithm == COMPRESS_ZSTD);

    if (arch_compressed || !bak->arch_keep_compressed) {
        return CT_SUCCESS;
    }

    if (bak->record.attr.compress == COMPRESS_NONE) {
        CT_LOG_RUN_ERR("[RESTORE] arch compressed mode expected compress algorithm is zstd, actual is COMPRESS_NONE");
        CT_THROW_ERROR(ERR_BACKUP_RESTORE, "check arch compress algorithm",
            "arch compressed mode expected compress algorithm is zstd, actual is COMPRESS_NONE");
        return CT_ERROR;
    }
    if (bak->record.attr.compress != COMPRESS_ZSTD) {
        CT_LOG_RUN_ERR("[RESTORE] arch compressed mode expected compress algorithm is zstd, actual is %s",
            bak_compress_algorithm_name(bak->record.attr.compress));
        CT_THROW_ERROR(ERR_BACKUP_RESTORE, "check arch compress algorithm",
            "arch compressed mode expected compress algorithm is zstd, actual is zlib or lz4");
        return CT_ERROR;
    }

    if (head->cmp_algorithm != COMPRESS_NONE) {
        CT_LOG_RUN_ERR("[RESTORE] arch compressed mode expected log head compress algorithm is COMPRESS_NONE, actual is %s",
            bak_compress_algorithm_name(head->cmp_algorithm));
        CT_THROW_ERROR(ERR_BACKUP_RESTORE, "check log head arch compress algorithm",
            "arch compressed mode expected log head compress algorithm is COMPRESS_NONE");
        return CT_ERROR;
    }
    if (log_verify_head_checksum(session, head, proc->ctrl.name) != CT_SUCCESS) {
        return CT_ERROR;
    }
    head->cmp_algorithm = bak->record.attr.compress;
    log_calc_head_checksum(session, head);
    *log_head = *(log_file_head_t *)backup_buf;
    CT_LOG_RUN_INF("[RESTORE] arch need to keep file %s compressed", proc->ctrl.name);

    return CT_SUCCESS;
}

static status_t rst_paral_read_log_head(knl_session_t *session, bak_process_t *process, log_file_head_t *log_head,
    uint32 *blocksize, bool32 *ignore_data, bool32 *arch_compress)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    bak_assignment_t *ctrl = &process->assign_ctrl;
    bak_file_t *bak_file = &bak->files[ctrl->bak_index];
    char *backup_buf = process->backup_buf.aligned_buf;
    bool32 ignore_logfile = CT_FALSE;
    int32 read_size = 0;

    CT_LOG_DEBUG_INF("[RESTORE] start restore arch_%u_%u_0, backup id %u, log name %s", bak_file->inst_id, bak_file->id,
                     ctrl->bak_index, ctrl->bak_file.name);

    if (cm_read_device_nocheck(ctrl->bak_file.type, ctrl->bak_file.handle, 0, backup_buf, sizeof(log_file_head_t),
                               &read_size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if ((uint32)read_size < sizeof(log_file_head_t)) {
        CT_LOG_RUN_ERR("[RESTOR] failed to read log file head, read size %d less than %u, file %s", read_size,
                       (uint32)sizeof(log_file_head_t), ctrl->bak_file.name);
        return CT_ERROR;
    }

    *log_head = *(log_file_head_t *)backup_buf;
    if (log_verify_head_checksum(session, log_head, ctrl->bak_file.name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (log_head->cmp_algorithm == COMPRESS_NONE) {
        *arch_compress = CT_FALSE;
    } else if (log_head->cmp_algorithm == COMPRESS_ZSTD) {
        *arch_compress = CT_TRUE;
    } else {
        return CT_ERROR;
    }

    uint32 log_blocksize = CM_CALC_ALIGN(sizeof(log_file_head_t), (uint32)log_head->block_size);
    uint32 fill_size = log_blocksize - sizeof(log_file_head_t);

    CT_LOG_DEBUG_INF("[RESTORE] archived log %s:%d:%u:%d:%d is %s", ctrl->bak_file.name, ctrl->bak_file.type, fill_size,
        bak_file->type, log_head->block_size,
        (*arch_compress) ? "compressed" : "non-compressed");

    if (cm_read_device_nocheck(ctrl->bak_file.type, ctrl->bak_file.handle, 0, backup_buf + sizeof(log_file_head_t),
                               fill_size, &read_size) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] read file %s faile", ctrl->bak_file.name);
        return CT_ERROR;
    }

    if (session->kernel->attr.clustered) {
        if (dtc_bak_set_logfile_ctrl(session, ctrl->bak_index, log_head, &process->ctrl, &ignore_logfile) !=
            CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RESTORE] bak set logfile ctrl faile");
            return CT_ERROR;
        }
    } else {
        if (rst_set_logfile_ctrl(session, ctrl->bak_index, log_head, &process->ctrl, &ignore_logfile) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    *blocksize = log_blocksize;
    *ignore_data = ignore_logfile;
    if (ignore_logfile) {
        return CT_SUCCESS;
    }

    if (rst_paral_arch_compressed_head(session, process, log_head) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return rst_write_data(session, &process->ctrl, backup_buf, log_blocksize);
}

static status_t rst_paral_record_arch(knl_session_t *session, bak_process_t *proc, log_file_head_t *log_head)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_assignment_t *assign_ctrl = &proc->assign_ctrl;
    bak_t *bak = &ctx->bak;
    int32 bak_index = assign_ctrl->bak_index;

    while (bak->curr_arch_id < assign_ctrl->arch_id) {
        if (bak->failed) {
            CT_LOG_DEBUG_ERR("[RESTORE] some error occurs when restore");
            return CT_ERROR;
        }
        cm_sleep(1);
    }

    if (session->kernel->attr.clustered) {
        if (dtc_rst_arch_try_record_archinfo(session, ARCH_DEFAULT_DEST, proc->ctrl.name, log_head,
                                             bak->files[assign_ctrl->bak_index].inst_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (arch_try_record_archinfo(session, ARCH_DEFAULT_DEST, proc->ctrl.name, log_head) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    CT_LOG_RUN_INF("[RESTORE] end restore arch_%u_0, archive id %u, backup id %u, log name %s",
                   bak->files[bak_index].id, bak->curr_arch_id, assign_ctrl->bak_index, assign_ctrl->bak_file.name);

    bak->curr_arch_id++;
    return CT_SUCCESS;
}

status_t rst_paral_write_data(bak_t *bak, bak_process_t *proc)
{
    int32 read_size = proc->write_buf->data_size;
    knl_compress_t *compress_ctx = &proc->compress_ctx;
    date_t start;
    bool32 read_end = ((uint32)read_size < BACKUP_BUFFER_SIZE(bak) - proc->start_loc);
    bak_assignment_t *assign_ctrl = &proc->assign_ctrl;
    bak_file_type_t type = bak->files[assign_ctrl->bak_index].type;
    bool32 need_decompress = rst_file_need_decompress(bak->record.attr.compress, type, bak, proc->arch_compress);
    int32 write_size = 0;
    char *use_buf = proc->write_buf->data_addr + proc->start_loc - compress_ctx->last_left_size;

    if (bak->encrypt_info.encrypt_alg != ENCRYPT_NONE) {
        start = g_timer()->now;
        if (rst_decrypt_data(proc, use_buf + compress_ctx->last_left_size, read_size,
            compress_ctx->last_left_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
        proc->stat.encode_size += read_size;
        proc->stat.encode_time += (g_timer()->now - start);
        use_buf = proc->encrypt_ctx.encrypt_buf.aligned_buf;
    }

    if (need_decompress) {
        if (rst_paral_decompress_to_disk(proc, (uint32)read_size + proc->compress_ctx.last_left_size,
            read_end, proc->write_buf->curr_offset, use_buf) != CT_SUCCESS) {
            return CT_ERROR;
        }
        // set use_buf to compress buffer for rst_write_remain_buff
    } else {
        if (rst_paral_write_to_disk(proc, use_buf, read_size,
            proc->write_buf->curr_offset, &write_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t rst_write_remain_buff(knl_session_t *session, bak_t *bak, bak_process_t *proc, bool32 arch_compress)
{
    if (proc->left_size == 0) {
        return CT_SUCCESS;
    }
    char *use_buf = proc->compress_ctx.compress_buf.aligned_buf;
    bak_assignment_t *assign_ctrl = &proc->assign_ctrl;
    bak_file_type_t type = bak->files[assign_ctrl->bak_index].type;
    if (type != BACKUP_LOG_FILE && type != BACKUP_ARCH_FILE) {
        CT_LOG_RUN_ERR("[BACKUP] only restore remain buf for archfile or logfile");
        return CT_ERROR;
    }

    if (rst_write_data(session, &proc->ctrl, use_buf, proc->left_size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t rst_paral_restore_prepare(knl_session_t *session, bak_process_t *proc, bak_t *bak, uint32 blk_size,
                                   bool32 arch_compress)
{
    bak_assignment_t *assign_ctrl = &proc->assign_ctrl;
    knl_compress_t *compress_ctx = &proc->compress_ctx;
    bak_file_type_t type = bak->files[assign_ctrl->bak_index].type;
    bool32 need_decompress = rst_file_need_decompress(bak->record.attr.compress, type, bak, arch_compress);
    bak_local_t *bak_file = &assign_ctrl->bak_file;

    CT_LOG_RUN_INF("[RESTORE] start restore file %s", bak_file->name);
    if (need_decompress) {
        if (type == BACKUP_ARCH_FILE || type == BACKUP_LOG_FILE) {
            proc->start_loc = blk_size;
        } else {
            proc->start_loc = DEFAULT_PAGE_SIZE(session);
        }
    } else {
            proc->start_loc = 0;
    }
    if (bak->encrypt_info.encrypt_alg != ENCRYPT_NONE) {
        if (bak_encrypt_init(bak, &proc->encrypt_ctx, &bak->files[assign_ctrl->bak_index], CT_FALSE) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RESTORE] restore encrypt init failed");
            return CT_ERROR;
        }
    }

    if (bak->record.attr.compress != COMPRESS_NONE) {
        if (knl_compress_init(bak->record.attr.compress, compress_ctx, CT_FALSE) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RESTORE] restore compress init failed");
            return CT_ERROR;
        }
    }
    proc->left_size = 0;
    proc->uncompressed_offset = 0;
    proc->arch_compress = arch_compress;
    proc->blk_size = blk_size;
    compress_ctx->last_left_size = 0;
    return CT_SUCCESS;
}

status_t rst_paral_restore_end(bak_process_t *proc, bak_t *bak, uint64 offset, bool32 ignore_logfile)
{
    bak_assignment_t *assign_ctrl = &proc->assign_ctrl;
    uint64 filesize = bak->files[assign_ctrl->bak_index].size;
    bak_local_t *bakfile = &assign_ctrl->bak_file;
    CT_LOG_RUN_INF("[RESTORE] end restore file %s", bakfile->name);
    if (bak->record.attr.compress != COMPRESS_NONE) {
        knl_compress_end(bak->record.attr.compress, &proc->compress_ctx, CT_FALSE);
    }
    if (bak->encrypt_info.encrypt_alg != ENCRYPT_NONE) {
        if (bak_decrypt_end(bak, &proc->encrypt_ctx, &bak->files[assign_ctrl->bak_index],
            ignore_logfile) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    if (proc->write_failed || proc->read_failed || bak->failed) {
        CT_LOG_RUN_ERR("[RESTORE] there are some errors in read or write proc");
        return CT_ERROR;
    } else if (!ignore_logfile && (offset != filesize)) {
        CT_LOG_RUN_ERR("[RESTORE] read size %llu is not equal with file size is %llu, rst file name %s", offset,
                       filesize, bakfile->name);
        return CT_ERROR;
    } else {
        return CT_SUCCESS;
    }
}

status_t rst_paral_restore_file(knl_session_t *session, bak_process_t *proc, uint32 blk_size,
    bool32 ignore_logfile, bool32 arch_compress)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_stat_t *stat = &ctx->bak.stat;
    bak_assignment_t *assign_ctrl = &proc->assign_ctrl;
    bak_local_t *bak_file = &assign_ctrl->bak_file;
    bool32 read_end = CT_FALSE;
    int32 read_size = 0;
    uint64 file_size = bak->files[assign_ctrl->bak_index].size;
    uint64 file_offset = blk_size;
    date_t start;
    if (rst_paral_restore_prepare(session, proc, bak, blk_size, arch_compress) != CT_SUCCESS) {
        return CT_ERROR;
    }

    proc->read_execute = CT_TRUE;
    while (!bak->failed && !proc->write_failed && !read_end) {
        if (ignore_logfile) {
            bak_update_progress(&ctx->bak, file_size);
            break;
        }
        if (bak_get_read_buf(&proc->backup_rw_buf, &proc->read_buf) != CT_SUCCESS) {
            cm_sleep(BAK_WAIT_RW_BUF_TIME);
            continue;
        }
        start = g_timer()->now;
        if (cm_read_device_nocheck(bak_file->type, bak_file->handle, file_offset,
                                   proc->read_buf->data_addr + proc->start_loc,
                                   (int32)(BACKUP_BUFFER_SIZE(bak) - proc->start_loc),
                                   &read_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
        proc->read_buf->data_size = read_size;
        proc->read_buf->curr_offset = file_offset;
        proc->stat.read_time += (g_timer()->now - start);
        proc->stat.read_size += read_size;
        (void)cm_atomic_inc(&stat->reads);
        read_end = ((uint32)read_size < BACKUP_BUFFER_SIZE(bak) - proc->start_loc);
        file_offset += read_size;
        bak_update_progress(bak, (uint64)read_size);
        bak_set_read_done(&proc->backup_rw_buf);
    }
    bak_wait_write_finish(&proc->backup_rw_buf, proc);
    proc->read_execute = CT_FALSE;
    /* In arch_compressed, the compressed file read is not aligned with 512,
     * so there is A possibility that the last read file has not been written out,
     * so it is necessary to ensure that the backup_buf write out
     */
    if (rst_write_remain_buff(session, bak, proc, arch_compress) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return rst_paral_restore_end(proc, bak, file_offset, ignore_logfile);
}

status_t rst_paral_restore(knl_session_t *session, bak_process_t *proc)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_assignment_t *assign_ctrl = &proc->assign_ctrl;
    bak_file_type_t type = bak->files[assign_ctrl->bak_index].type;
    log_file_head_t head;
    bool32 ignore_logfile = CT_FALSE;
    uint32 log_blocksize = 0;
    bool32 arch_compress = CT_FALSE;
    knl_panic(type == assign_ctrl->type);

    if (type == BACKUP_LOG_FILE || type == BACKUP_ARCH_FILE) {
        if (rst_paral_read_log_head(session, proc, &head, &log_blocksize,
            &ignore_logfile, &arch_compress) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RESTORE] read file %s faile", assign_ctrl->bak_file.name);
            return CT_ERROR;
        }
    }

    if (rst_paral_restore_file(session, proc, log_blocksize, ignore_logfile, arch_compress) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (type == BACKUP_DATA_FILE && rst_paral_fill_datafile_tail(session, proc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (type == BACKUP_ARCH_FILE && rst_paral_record_arch(session, proc, &head) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t rst_block_data_decode(bak_t *bak, bak_process_t *proc, char **buf, uint32 *size, bak_file_t *file)
{
    char *data_buf = *buf;
    uint32 data_size = *size;
    date_t start = g_timer()->now;

    if (bak->encrypt_info.encrypt_alg != ENCRYPT_NONE) {
        if (rst_block_decrypt(bak, &proc->encrypt_ctx, data_buf, data_size,
            (const unsigned char *)file->gcm_iv) != CT_SUCCESS) {
            return CT_ERROR;
        }
        data_buf = proc->encrypt_ctx.encrypt_buf.aligned_buf;
        data_size -= EVP_GCM_TLS_TAG_LEN;
    }

    if (bak->record.attr.compress != COMPRESS_NONE) {
        uint32 decompress_size = 0;
        status_t status;

        if (bak->record.attr.compress == COMPRESS_LZ4) {
            status = rst_block_lz4_decompress(bak, &proc->compress_ctx, data_buf, data_size, &decompress_size);
        } else {
            status = rst_block_zstd_decompress(bak, &proc->compress_ctx, data_buf, data_size, &decompress_size);
        }
        if (status != CT_SUCCESS) {
            return CT_ERROR;
        }

        data_buf = proc->compress_ctx.compress_buf.aligned_buf;
        data_size = decompress_size;
    }

    proc->stat.encode_size += (*size);
    proc->stat.encode_time += (g_timer()->now - start);
    *buf = data_buf;
    *size = data_size;
    return CT_SUCCESS;
}

bak_block_head_t rst_fetch_stream_block(bak_t *bak, bak_process_t *proc, rst_stream_buf_t *recv_stream,
                                        bak_assignment_t *assign_ctrl)
{
    char *block_buf = recv_stream->bufs[recv_stream->wid].aligned_buf + recv_stream->curr_block_offset;
    char *rst_buf = proc->backup_buf.aligned_buf;
    bak_block_head_t block_head = *(bak_block_head_t *)block_buf;
    uint32 data_size = block_head.block_size - sizeof(bak_block_head_t);
    errno_t ret;

    knl_panic(data_size <= BACKUP_BUFFER_SIZE(bak) - sizeof(bak_block_head_t));
    ret = memcpy_sp(rst_buf, BACKUP_BUFFER_SIZE(bak), block_buf + sizeof(bak_block_head_t), data_size);
    knl_securec_check(ret);

    assign_ctrl->section_start = block_head.offset;
    assign_ctrl->section_end = block_head.offset + block_head.read_size;
    assign_ctrl->fill_offset = MAX(recv_stream->base_filesize, recv_stream->curr_file_tail);

    knl_panic(recv_stream->curr_file_tail <= block_head.offset);
    recv_stream->curr_file_tail = block_head.offset + block_head.read_size;
    recv_stream->curr_block_offset += block_head.block_size;
    if (block_head.block_id > 0) {
        knl_panic(block_head.block_id > recv_stream->prev_block);
    }

    recv_stream->prev_block = block_head.block_id;
    knl_panic(recv_stream->usable_size[recv_stream->wid] >= recv_stream->curr_block_offset);
    return block_head;
}

status_t rst_write_block_to_file(knl_session_t *session, bak_process_t *proc, uint64 offset,
                                 char *data_buf, uint32 data_size)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    bak_assignment_t *assign_ctrl = &proc->assign_ctrl;
    bak_file_type_t type = bak->files[assign_ctrl->bak_index].type;
    date_t start = g_timer()->now;

    proc->read_size = data_size;
    proc->left_size = 0;
    proc->write_size = 0;
    proc->curr_offset = offset;
    proc->ctrl.offset = offset;

    if (type == BACKUP_DATA_FILE) {
        if (rst_restore_datafile(session, bak, proc, data_buf, "") != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (rst_paral_fill_datafile_tail(session, proc) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (rst_write_data(session, &proc->ctrl, data_buf, proc->read_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
        knl_panic(proc->ctrl.offset == offset + data_size);
    }
    proc->stat.write_time += (g_timer()->now - start);
    proc->stat.write_size += data_size;
    return CT_SUCCESS;
}

status_t rst_paral_stream_restore(knl_session_t *session, bak_process_t *proc)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    bak_assignment_t *assign_ctrl = &proc->assign_ctrl;
    bak_file_type_t type = bak->files[assign_ctrl->bak_index].type;
    rst_stream_buf_t *stream = &bak->recv_stream;
    bak_block_head_t block_head;
    char *data_buf = NULL;
    uint32 data_size;

    knl_panic(type == assign_ctrl->type);
    for (;;) {
        if (bak_check_session_status(session) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!cm_spin_try_lock(&stream->lock)) {
            cm_spin_sleep();
            continue;
        }

        if (stream->usable_size[stream->wid] == stream->curr_block_offset) {
            // all block of working buffer has been restored, need retry
            if (stream->is_eof) {
                cm_spin_unlock(&stream->lock);
                CT_LOG_DEBUG_INF("[RESTORE] end of file");
                break;
            }
            cm_spin_unlock(&stream->lock);
            cm_spin_sleep();
            continue;
        }

        block_head = rst_fetch_stream_block(bak, proc, stream, assign_ctrl);
        cm_spin_unlock(&stream->lock);

        data_buf = proc->backup_buf.aligned_buf;
        data_size = block_head.block_size - sizeof(bak_block_head_t);
        if (rst_block_data_decode(bak, proc, &data_buf, &data_size,
            &bak->files[assign_ctrl->bak_index]) != CT_SUCCESS) {
            return CT_ERROR;
        }
        knl_panic(data_size == block_head.origin_size);

        if (rst_write_block_to_file(session, proc, block_head.offset, data_buf, data_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

void bak_paral_restore_task(knl_session_t *session, bak_process_t *proc)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_assignment_t *assign_ctrl = &proc->assign_ctrl;
    bak_local_t *bak_file = &assign_ctrl->bak_file;

    if (rst_paral_restore(session, proc) != CT_SUCCESS) {
        bak->failed = CT_TRUE;
        CT_LOG_RUN_ERR("[RESTORE] restore task failed, proc id %u, file id %u, backup id %u, name %s",
                       proc->proc_id, assign_ctrl->file_id, assign_ctrl->bak_index, bak_file->name);
    }

    if (assign_ctrl->type == BACKUP_DATA_FILE) {
        for (uint32 id = 0; id < CT_MAX_DATA_FILES; id++) {
            cm_close_device(proc->file_type[id], &proc->datafiles[id]);
        }
    } else {
        cm_close_device(proc->ctrl.type, &proc->ctrl.handle);
    }

    cm_close_device(bak_file->type, &bak_file->handle);
    bak_file->handle = CT_INVALID_HANDLE;
}

void bak_paral_stream_restore_task(knl_session_t *session, bak_process_t *proc)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_assignment_t *assign_ctrl = &proc->assign_ctrl;
    bak_local_t *bak_file = &assign_ctrl->bak_file;

    if (rst_paral_stream_restore(session, proc) != CT_SUCCESS) {
        bak->failed = CT_TRUE;
        CT_LOG_RUN_ERR("[RESTORE] restore task failed, proc id %u, file id %u, backup id %u, name %s", proc->proc_id,
                       assign_ctrl->file_id, assign_ctrl->bak_index, bak_file->name);
    }

    if (assign_ctrl->type == BACKUP_DATA_FILE) {
        for (uint32 id = 0; id < CT_MAX_DATA_FILES; id++) {
            cm_close_device(proc->file_type[id], &proc->datafiles[id]);
        }
    } else {
        cm_close_device(proc->ctrl.type, &proc->ctrl.handle);
    }
}

void bak_paral_extend_task(knl_session_t *session, bak_process_t *proc)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_ctrl_t *ctrl = &proc->ctrl;
    bak_assignment_t *assign_ctrl = &proc->assign_ctrl;

    knl_panic(assign_ctrl->task == BAK_EXTEND_TASK);
    if (rst_extend_file(session, ctrl->name, ctrl->type, ctrl->offset,
                        proc->backup_buf.aligned_buf, BACKUP_BUFFER_SIZE(bak)) != CT_SUCCESS) {
        bak->failed = CT_TRUE;
    }
    bak_update_progress(&ctx->bak, ctrl->offset);
}

status_t bak_deal_datafile_pages_write(knl_session_t *session, bak_process_t *bak_proc)
{
    bak_ctrl_t *ctrl = &bak_proc->ctrl;
    timeval_t tv_begin;
    if (bak_proc->write_buf->write_deal == CT_FALSE) {
        return CT_SUCCESS;
    }

#ifndef WIN32
    if (bak_need_decompress(session, bak_proc)) {
        if (bak_decompress_and_verify_datafile(session, bak_proc, bak_proc->write_buf)) {
            return CT_ERROR;
        }
    } else {
        cantian_record_io_stat_begin(IO_RECORD_EVENT_BAK_CHECKSUM, &tv_begin);
        if (bak_verify_datafile_checksum(session, bak_proc,
                                         ctrl->offset, ctrl->name, bak_proc->write_buf) != CT_SUCCESS) {
            cantian_record_io_stat_end(IO_RECORD_EVENT_BAK_CHECKSUM, &tv_begin, IO_STAT_FAILED);
            return CT_ERROR;
        }
        cantian_record_io_stat_end(IO_RECORD_EVENT_BAK_CHECKSUM, &tv_begin, IO_STAT_SUCCESS);
    }
#endif
    cantian_record_io_stat_begin(IO_RECORD_EVENT_BAK_FILTER, &tv_begin);
    bak_filter_pages(session, bak_proc, bak_proc->write_buf);
    cantian_record_io_stat_end(IO_RECORD_EVENT_BAK_FILTER, &tv_begin, IO_STAT_SUCCESS);
    bak_proc->write_buf->data_size = bak_proc->write_size;
    return CT_SUCCESS;
}

void bak_paral_task_write_proc(thread_t *thread)
{
    bak_process_t *bak_proc = (bak_process_t *)thread->argument;
    knl_session_t *session = bak_proc->session;
    bak_context_t *bak_ctx = &session->kernel->backup_ctx;
    status_t status;
    date_t start;
    CT_LOG_RUN_INF("[BACKUP] start backup write proc, id %u", bak_proc->proc_id);

    while (!thread->closed) {
        if (!bak_proc->read_execute) {
            cm_sleep(BAK_WAIT_READ_START_TIME);
            continue;
        }
        if (bak_get_write_buf(&bak_proc->backup_rw_buf, &bak_proc->write_buf) != CT_SUCCESS) {
            cm_sleep(1);
            continue;
        }
        start = g_timer()->now;
        if (bak_deal_datafile_pages_write(session, bak_proc) != CT_SUCCESS) {
            bak_proc->write_failed = CT_TRUE;
            break;
        }
        if (bak_proc->write_buf->data_size != 0) {
            SYNC_POINT_GLOBAL_START(CANTIAN_BACKUP_WRITE_PAGE_TO_FILE_FAIL, &status, CT_ERROR);
            status = bak_write_to_local_disk(bak_ctx, bak_proc, bak_proc->write_buf->data_addr,
                bak_proc->write_buf->data_size, CT_FALSE, CT_FALSE);
            SYNC_POINT_GLOBAL_END;
            bak_proc->stat.write_time += (g_timer()->now - start);
            if (status != CT_SUCCESS) {
                bak_proc->write_failed = CT_TRUE;
                break;
            }
        }
        bak_set_write_done(&bak_proc->backup_rw_buf);
    }
    if (bak_proc->write_failed == CT_TRUE) {
        bak_set_error(&bak_ctx->bak.error_info);
    }
}

void rst_paral_task_write_proc(thread_t *thread)
{
    bak_process_t *proc = (bak_process_t *)thread->argument;
    knl_session_t *session = proc->session;
    bak_context_t *bak_ctx = &session->kernel->backup_ctx;
    bak_t *bak = &bak_ctx->bak;

    while (!thread->closed) {
        if (!proc->read_execute) {
            cm_sleep(BAK_WAIT_READ_START_TIME);
            continue;
        }
        if (bak_get_write_buf(&proc->backup_rw_buf, &proc->write_buf) != CT_SUCCESS) {
            cm_sleep(1);
            continue;
        }

        if (rst_paral_write_data(bak, proc) != CT_SUCCESS) {
            proc->write_failed = CT_TRUE;
            bak_set_error(&bak->error_info);
            break;
        }

        bak_set_write_done(&proc->backup_rw_buf);
    }
}

void bak_paral_task_proc(thread_t *thread)
{
    bak_process_t *process = (bak_process_t *)thread->argument;
    knl_session_t *session = process->session;
    bak_assignment_t *assign_ctrl = &process->assign_ctrl;
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;

    process->is_free = CT_TRUE;
    knl_panic(process->proc_id > BAK_COMMON_PROC);
    CT_LOG_RUN_INF("[%s] parallel process %u start", bak->restore ? "RESTORE" : "BACKUP", process->proc_id);

    while (!thread->closed) {
        if (process->is_free || bak->failed) {
            cm_sleep(BAK_WAIT_CALL_TIME);
            continue;
        }

        switch (assign_ctrl->task) {
            case BAK_BACKUP_TASK:
                bak_paral_backup_task(session, process);
                break;
            case BAK_RESTORE_TASK:
                bak_paral_restore_task(session, process);
                break;
            case BAK_STREAM_BACKUP_TASK:
            case BAK_BUILD_BACKUP_TASK:
                bak_paral_stream_backup_task(session, process);
                break;
            case BAK_STREAM_RESTORE_TASK:
            case BAK_BUILD_RESTORE_TASK:
                bak_paral_stream_restore_task(session, process);
                break;
            case BAK_EXTEND_TASK:
                bak_paral_extend_task(session, process);
                break;
            default:
                knl_panic(0);
                break;
        }

        process->is_free = CT_TRUE;
        bak_set_error(&bak->error_info);
    }
    CT_LOG_RUN_INF("[%s] parallel process %u stop", bak->restore ? "RESTORE" : "BACKUP", process->proc_id);
}
