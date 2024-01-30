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
 * knl_backup.c
 *
 *
 * IDENTIFICATION
 * src/kernel/backup/knl_backup.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_backup_module.h"
#include "knl_backup.h"
#include "cm_file.h"
#include "bak_paral.h"
#include "bak_log_paral.h"
#include "cm_kmc.h"
#include "knl_context.h"
#include "knl_space_ddl.h"
#include "dtc_dls.h"
#include "dtc_ckpt.h"
#include "dtc_log.h"
#include "dtc_backup.h"
#include "dtc_database.h"
#include "rc_reform.h"
#include "cm_malloc.h"
#include "cm_io_record.h"
#include "knl_badblock.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BAK_NEED_LOAD_FILE(session) ((session)->kernel->db.status == DB_STATUS_MOUNT)
#define BAK_NEED_UNLOAD_FILE(session) ((session)->kernel->db.status == DB_STATUS_MOUNT)
#define BAK_DISTRIBUTED_PHASE_SECOND(bak) ((bak)->record.log_only && (bak)->target_info.target != TARGET_ARCHIVE)
#define BAK_DATAFILE_VERSION    DATAFILE_STRUCTURE_VERSION
#define BAK_WAIT_REFORM_TIMEOUT (60 * (MICROSECS_PER_MIN))
#define BAK_RW_TIME_THRESHOLD 1.2

void bak_read_proc(thread_t *thread); // backup process for read local file

void bak_record_new_file(bak_t *bak, bak_file_type_t file_type, uint32 file_id, uint32 sec_id, uint32 rst_id,
                         bool32 is_paral_log_proc, uint64 start_lsn, uint64 end_lsn)
{
    uint32 slot = bak_get_log_slot(bak, is_paral_log_proc);

    knl_panic_log(bak->file_count < BAK_MAX_FILE_NUM, "file count [%u] should less than the max file number [%u]",
        bak->file_count, BAK_MAX_FILE_NUM);
    bak_file_t *new_file = &bak->files[slot];
    errno_t ret = memset_sp(new_file, sizeof(bak_file_t), 0, sizeof(bak_file_t));
    knl_securec_check(ret);

    if (file_type == BACKUP_LOG_FILE || file_type == BACKUP_ARCH_FILE) {
        new_file->inst_id = bak->inst_id;
    }
    new_file->type = file_type;
    new_file->id = file_id;
    new_file->sec_id = sec_id;
    new_file->start_lsn = start_lsn;
    new_file->end_lsn = end_lsn;
    new_file->rst_id = rst_id;
    // while datafile is backing up, DO NOT update bak->file_count caused by paral log proc
    // bak->file_count will update with bak->paral_log_bak_number when datafile's backup has finished.
    if (!is_paral_log_proc) {
        bak->file_count++;
        CT_LOG_DEBUG_INF("[BACKUP] record new file");
    } else {
        bak->paral_log_bak_number++;
        bak->paral_last_asn = file_id;
        CT_LOG_DEBUG_INF("[BACKUP] record new paral log file");
    }
    CT_LOG_DEBUG_INF("[BACKUP] new file slot: %u, type: %u, id: %u, sec id: %u",
        slot, (uint32)new_file->type, new_file->id, new_file->sec_id);
    CT_LOG_RUN_INF("[BACKUP] current file count: %u, current paral log back number: %u, current paral last asn: %u",
        bak->file_count, bak->paral_log_bak_number, bak->paral_last_asn);
}

static inline void bak_generate_default_backupset_tag(bak_t *bak, knl_scn_t scn)
{
    int32 ret = snprintf_s(bak->record.attr.tag, CT_NAME_BUFFER_SIZE, CT_NAME_BUFFER_SIZE - 1, DEFAULT_TAG_FORMAT,
        bak->record.start_time, scn);
    knl_securec_check_ss(ret);
}

static status_t bak_tag_exists(knl_session_t *session, const char *tag, bool32 *exists)
{
    CM_SAVE_STACK(session->stack);

    knl_set_session_scn(session, CT_INVALID_ID64);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_BACKUP_SET_ID, 1);

    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, (void *)tag,
                     (uint16)strlen(tag), 0);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    *exists = !cursor->eof;
    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

void bak_reset_fileinfo(bak_assignment_t *assign_ctrl)
{
    assign_ctrl->start = 0;
    assign_ctrl->end = 0;
    assign_ctrl->file_id = 0;
    assign_ctrl->is_section = CT_FALSE;
    assign_ctrl->sec_id = 0;
    assign_ctrl->section_start = 0;
    assign_ctrl->section_end = 0;
    assign_ctrl->type = BACKUP_HEAD_FILE;
}

status_t bak_local_write(bak_local_t *local, const void *buf, int32 size, bak_t *bak, int64 offset)
{
    bak_stat_t *stat = &bak->stat;
    timeval_t tv_begin;

    if (size == 0) {
        return CT_SUCCESS;
    }
    cantian_record_io_stat_begin(IO_RECORD_EVENT_BAK_WRITE_LOCAL, &tv_begin);
    if (cm_write_device(local->type, local->handle, offset, buf, size) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] failed to write %s", local->name);
        cantian_record_io_stat_end(IO_RECORD_EVENT_BAK_WRITE_LOCAL, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }
    cantian_record_io_stat_end(IO_RECORD_EVENT_BAK_WRITE_LOCAL, &tv_begin, IO_STAT_SUCCESS);
    if (bak->kernel->attr.enable_fdatasync) {
        if (cm_fdatasync_file(local->handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BACKUP] failed to fdatasync datafile %s", local->name);
            return CT_ERROR;
        }
    }

    (void)cm_atomic_inc(&stat->writes);

    CT_LOG_DEBUG_INF("[BACKUP] bakup write data size:%d", size);
    return CT_SUCCESS;
}

status_t bak_read_data(bak_process_t *bak_proc, bak_ctrl_t *ctrl, log_file_head_t *buf, int32 size)
{
    date_t start = g_timer()->now;
    if (cm_read_device(ctrl->type, ctrl->handle, ctrl->offset, (void*)buf, size) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] failed to read %s", ctrl->name);
        return CT_ERROR;
    }
    bak_proc->stat.read_size += size;
    bak_proc->stat.read_time += (g_timer()->now - start);
    ctrl->offset += size;
    return CT_SUCCESS;
}

static status_t bak_set_log_point(knl_session_t *session, bak_ctrlinfo_t *ctrlinfo, bool32 update, bool32 force_switch)
{
    if (session->kernel->attr.clustered) {
        return dtc_bak_set_log_point(session, ctrlinfo, update, force_switch);
    }
    knl_instance_t *kernel = session->kernel;
    bak_context_t *ctx = &kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    log_context_t *log = &session->kernel->redo_ctx;

    // to switch arch file
    if (BAK_IS_DBSOTR(bak) && force_switch) {
        if (arch_switch_archfile_trigger(session, CT_FALSE) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BACKUP] faile switch archfile");
            return CT_ERROR;
        }
    }
    ckpt_trigger(session, CT_TRUE, CKPT_TRIGGER_INC);
    if (!update) {
        ctrlinfo->rcy_point = dtc_my_ctrl(session)->rcy_point;
        errno_t ret = memset_sp(&bak->arch_stat, sizeof(arch_bak_status_t), 0, sizeof(arch_bak_status_t));
        knl_securec_check(ret);
        bak->arch_stat.start_asn = ctrlinfo->rcy_point.asn;
        CT_LOG_RUN_INF("[BACKUP] set rcy log point: [%llu/%llu/%llu/%u], instid[0]",
                       (uint64)ctrlinfo->rcy_point.rst_id,
                       ctrlinfo->rcy_point.lsn, (uint64)ctrlinfo->rcy_point.lfn,
                       ctrlinfo->rcy_point.asn);
    }
    
    ctrlinfo->lrp_point = dtc_my_ctrl(session)->lrp_point;

    log_lock_logfile(session);
    ctrlinfo->scn = DB_CURR_SCN(session);
    uint32 file_id = bak_log_get_id(session, bak->record.data_type, (uint32)ctrlinfo->lrp_point.rst_id,
                                    ctrlinfo->lrp_point.asn);
    if (file_id != CT_INVALID_ID32) {
        log_unlatch_file(session, file_id);
        log_get_next_file(session, &file_id, CT_FALSE);
    } else if (log->files[log->curr_file].head.asn == ctrlinfo->lrp_point.asn + 1) {
        file_id = log->curr_file; // lrp online log is recycled, head asn is invalid
    } else {
        knl_panic_log(!DB_IS_RAFT_ENABLED(session->kernel), "[BACKUP] failed to get log slot, lrp asn %u, curr asn %u",
                      ctrlinfo->lrp_point.asn, log->files[log->curr_file].head.asn);
        file_id = 0;
    }
    bak->log_first_slot = file_id;
    CT_LOG_RUN_INF("[BACKUP] first file id %u, log curr file %u", file_id, (uint32)log->curr_file);
    CT_LOG_RUN_INF("[BACKUP] set lrp log point: [%llu/%llu/%llu/%u], instid[0]",
                   (uint64)ctrlinfo->lrp_point.rst_id,
                   ctrlinfo->lrp_point.lsn, (uint64)ctrlinfo->lrp_point.lfn,
                   ctrlinfo->lrp_point.asn);
    log_unlock_logfile(session);

    return CT_SUCCESS;
}

status_t bak_load_log_batch(knl_session_t *session, log_point_t *point, uint32 *data_size, aligned_buf_t *buf,
    uint32 *block_size)
{
    knl_instance_t *kernel = session->kernel;
    bak_context_t *ctx = &kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    int32 handle = CT_INVALID_HANDLE;
    arch_file_t arch_file = { .name = { 0 }, .handle = CT_INVALID_HANDLE };
    status_t status;

    log_lock_logfile(session);
    uint32 file_id = bak_log_get_id(session, bak->record.data_type, (uint32)point->rst_id, point->asn);
    log_unlock_logfile(session);

    if (file_id != CT_INVALID_ID32) {
        status = rcy_load_from_online(session, file_id, point, data_size, &handle, buf);
        *block_size = session->kernel->redo_ctx.files[file_id].ctrl->block_size;
        cm_close_device(session->kernel->redo_ctx.files[file_id].ctrl->type, &handle);
    } else {
        status = rcy_load_from_arch(session, point, data_size, &arch_file, buf);
        *block_size = arch_file.head.block_size;
        cm_close_device(cm_device_type(arch_file.name), &arch_file.handle);
    }

    return status;
}

static status_t bak_set_lsn(knl_session_t *session, bak_t *bak)
{
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;
    log_point_t start_point = ctrlinfo->rcy_point;
    log_batch_t *batch = NULL;
    log_batch_tail_t *tail = NULL;
    uint32 data_size;
    uint32 block_size;
    database_t *db = &session->kernel->db;
    reset_log_t rst_log = db->ctrl.core.resetlogs;
    aligned_buf_t log_buf;

    if (BAK_IS_DBSOTR(bak)) {
        return CT_SUCCESS;
    }

    if (bak->record.attr.backup_type == BACKUP_MODE_FULL) {
        return CT_SUCCESS;
    }

    if (ctrlinfo->lrp_point.lfn == ctrlinfo->rcy_point.lfn) {
        // make sure pages whose lsn is less than ctrlinfo->lsn flushed
        ckpt_trigger(session, CT_TRUE, CKPT_TRIGGER_FULL);
        CT_LOG_RUN_INF("[BACKUP] current database base lsn: %llu, rcy lfn %llu, lrp lfn %llu", ctrlinfo->lsn,
                       (uint64)dtc_my_ctrl(session)->rcy_point.lfn, (uint64)dtc_my_ctrl(session)->lrp_point.lfn);
        return CT_SUCCESS;
    }
    knl_panic(log_cmp_point(&ctrlinfo->rcy_point, &ctrlinfo->lrp_point) < 0);
    CT_LOG_RUN_INF("[BACKUP] fetch incremental backup base lsn for point asn %u, lfn %llu, block id %u",
                   start_point.asn, (uint64)start_point.lfn, start_point.block_id);
    if (cm_aligned_malloc(CT_MAX_BATCH_SIZE, "backup log buffer", &log_buf) != CT_SUCCESS) {
        return CT_ERROR;
    }

    for (;;) {
        if (bak_load_log_batch(session, &start_point, &data_size, &log_buf, &block_size) != CT_SUCCESS) {
            cm_aligned_free(&log_buf);
            return CT_ERROR;
        }

        batch = (log_batch_t *)log_buf.aligned_buf;
        if (data_size >= sizeof(log_batch_t) && data_size >= batch->size) {
            tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));
            if (rcy_validate_batch(batch, tail)) {
                break;
            }
        }

        start_point.asn++;
        start_point.rst_id = bak_get_rst_id(bak, start_point.asn, &rst_log);
        start_point.block_id = 0;
    }

    ctrlinfo->lsn = rcy_fetch_batch_lsn(session, batch);
    CT_LOG_RUN_INF("[BACKUP] fetch base lsn %llu from batch asn %u, lfn %llu, block id %u",
                   ctrlinfo->lsn, batch->head.point.asn, (uint64)batch->head.point.lfn, batch->head.point.block_id);
    cm_aligned_free(&log_buf);
    return CT_SUCCESS;
}

status_t bak_write(bak_t *bak, bak_process_t *proc, char *buf, int32 size)
{
    status_t status;
    char *write_buf = buf;

    if (bak->encrypt_info.encrypt_alg != ENCRYPT_NONE && bak->files[bak->curr_file_index].type != BACKUP_HEAD_FILE &&
        !bak->is_building) {
        if (bak_encrypt_data(proc, buf, size) != CT_SUCCESS) {
            return CT_ERROR;
        }
        write_buf = proc->encrypt_ctx.encrypt_buf.aligned_buf;
    }

    if (bak->is_building || BAK_IS_UDS_DEVICE(bak)) {
        status = bak_agent_write(bak, write_buf, size);
    } else {
        CT_LOG_DEBUG_INF("[BACKUP] name %s, id %u, backup size %llu",
            bak->local.name, bak->files[bak->curr_file_index].id, bak->backup_size);
        status = bak_local_write(&bak->local, write_buf, size, bak, bak->backup_size);
        if (bak->files[bak->curr_file_index].type == BACKUP_CTRL_FILE) {
            SYNC_POINT_GLOBAL_START(CANTIAN_BACKUP_WRITE_CTRL_TO_FILE_FAIL, &status, CT_ERROR);
            SYNC_POINT_GLOBAL_END;
        } else if (bak->files[bak->curr_file_index].type == BACKUP_HEAD_FILE) {
            SYNC_POINT_GLOBAL_START(CANTIAN_BACKUP_WRITE_BACKUPSET_TO_FILE_FAIL, &status, CT_ERROR);
            SYNC_POINT_GLOBAL_END;
        }
    }

    bak->backup_size += size;
    return status;
}

static status_t bak_compress_write(bak_t *bak, bak_process_t *proc, char *buf, int32 size, bool32 stream_end)
{
    knl_compress_set_input(bak->record.attr.compress, &bak->compress_ctx, buf, (uint32)size);
    for (;;) {
        if (knl_compress(bak->record.attr.compress, &bak->compress_ctx, stream_end, bak->compress_buf,
                         (uint32)COMPRESS_BUFFER_SIZE(bak)) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (bak_write(bak, proc, bak->compress_buf, bak->compress_ctx.write_len) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (bak->compress_ctx.finished) {
            break;
        }
    }

    return CT_SUCCESS;
}

static status_t bak_set_finish_info(bak_t *bak, knl_backup_t *param)
{
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;

    if (!bak->record.data_only || !cm_str_equal(bak->record.attr.tag, param->tag)) {
        CT_THROW_ERROR(ERR_BACKUP_NOT_PREPARE, param->tag);
        return CT_ERROR;
    }

    if (ctrlinfo->scn > param->finish_scn) {
        CT_THROW_ERROR(ERR_INVALID_FINISH_SCN, ctrlinfo->scn);
        return CT_ERROR;
    }

    bak->record.log_only = CT_TRUE;
    bak->record.data_only = CT_FALSE;
    bak->record.finish_scn = param->finish_scn;
    CT_LOG_RUN_INF("[BACKUP] ctrl info scn %llu", ctrlinfo->scn);
    return CT_SUCCESS;
}

static status_t bak_set_tag(knl_session_t *session, bak_t *bak, const char *tag)
{
    bool32 exists = CT_FALSE;

    if (tag[0] == '\0') {
        bak_generate_default_backupset_tag(bak, DB_CURR_SCN(session));
    } else {
        if (DB_IS_OPEN(session) && bak_tag_exists(session, tag, &exists) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (exists) {
            CT_THROW_ERROR(ERR_BACKUP_TAG_EXISTS, tag);
            return CT_ERROR;
        }

        errno_t ret = strncpy_s(bak->record.attr.tag, CT_NAME_BUFFER_SIZE, tag, strlen(tag));
        knl_securec_check(ret);
    }

    return CT_SUCCESS;
}

static status_t bak_encrypt_param_init(knl_session_t *session, knl_backup_t *param)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    uchar salt[CT_KDF2SALTSIZE];
    uchar kdf2_key[CT_AES256KEYSIZE];
    uint32 cipher_len = CT_PASSWORD_BUFFER_SIZE;

    if (cm_rand(salt, CT_KDF2SALTSIZE) != CT_SUCCESS) {
        bak_replace_password(param->crypt_info.password);
        return CT_ERROR;
    }
    errno_t ret = memcpy_sp(bak->encrypt_info.salt, CT_KDF2SALTSIZE, salt, CT_KDF2SALTSIZE);
    knl_securec_check(ret);

    if (cm_encrypt_KDF2((uchar *)param->crypt_info.password, (uint32)strlen(param->crypt_info.password), salt,
        CT_KDF2SALTSIZE, CT_KDF2DEFITERATION, kdf2_key, CT_AES256KEYSIZE) != CT_SUCCESS) {
        bak_replace_password(param->crypt_info.password);
        return CT_ERROR;
    }

    if (cm_generate_scram_sha256(param->crypt_info.password, (uint32)strlen(param->crypt_info.password),
        CT_KDF2DEFITERATION, (uchar *)bak->sys_pwd, &cipher_len) != CT_SUCCESS) {
        bak_replace_password(param->crypt_info.password);
        return CT_ERROR;
    }
    ret = memcpy_sp(bak->key, CT_AES256KEYSIZE, kdf2_key, CT_AES256KEYSIZE);
    knl_securec_check(ret);
    bak_replace_password(param->crypt_info.password);
    return CT_SUCCESS;
}

void bak_record_init(bak_t *bak, knl_backup_t *param)
{
    status_t ret = memset_s(&bak->record, sizeof(bak_record_t), 0, sizeof(bak_record_t));
    knl_securec_check(ret);
    bak_attr_t *attr = &bak->record.attr;

    bak->record.start_time = (uint64)cm_now();
    bak->record.log_only = CT_FALSE;
    bak->record.finish_scn = 0;
    bak->record.data_only = param->prepare;
    bak->record.data_type = knl_dbs_is_enable_dbs() ? DATA_TYPE_DBSTOR : DATA_TYPE_FILE;
    bak->record.device = param->device;
    (void)cm_text2str(&param->policy, bak->record.policy, CT_BACKUP_PARAM_SIZE);
    if (param->type == BACKUP_MODE_INCREMENTAL && param->level > 0) {
        attr->backup_type = param->cumulative ? BACKUP_MODE_INCREMENTAL_CUMULATIVE : BACKUP_MODE_INCREMENTAL;
    } else {
        attr->backup_type = param->type;
    }
    attr->level = param->level;
    attr->compress = param->compress_algo;
    if (param->target_info.target == TARGET_ARCHIVE) {
        bak->record.log_only = CT_TRUE;
        bak->record.data_only = CT_FALSE;
    }
    return;
}

static void bak_param_paral_init(knl_session_t *session, knl_backup_t *param)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;

    bak->backup_log_prealloc = session->kernel->attr.backup_log_prealloc;
    bak->cumulative = param->cumulative;
    bak->section_threshold = param->section_threshold;
    CT_LOG_RUN_INF("[BACKUP] section threshold %llu", bak->section_threshold);
    bak->proc_count = param->parallelism == 0 ? BAK_DEFAULT_PARALLELISM : param->parallelism;
    bak->log_proc_count = 0;
    bak->paral_log_bak_complete = CT_FALSE;
    bak->paral_last_asn = CT_INVALID_ID32;
    bak->paral_log_bak_number = 0;
    return;
}

#define BAK_CHECK_REFORM_TIME (3 * (MILLISECS_PER_SECOND)) // unit is seconds

void bak_free_reform_veiw_buffer(bak_t *bak)
{
    if (bak->reform_check.view != NULL) {
        cm_free(bak->reform_check.view);
        bak->reform_check.view = NULL;
    }
}

status_t bak_init_reform_check(bak_t *bak)
{
    date_t start_time = cm_now();
    bak->reform_check.view = cm_malloc(sizeof(cluster_view_t));
    if (bak->reform_check.view == NULL) {
        CT_LOG_RUN_ERR("[BACKUP] malloc cluster_view_t faile");
        return CT_ERROR;
    }
    (void)memset_s(bak->reform_check.view, sizeof(cluster_view_t), 0, sizeof(cluster_view_t));
    while (CT_TRUE) {
        rc_get_cluster_view((cluster_view_t *)bak->reform_check.view, CT_FALSE);
        if ((((cluster_view_t *)bak->reform_check.view)->is_stable == CT_TRUE) && (g_rc_ctx->status == REFORM_DONE)) {
            break;
        }
        cm_sleep(BAK_CHECK_REFORM_TIME);
        if (cm_now() - start_time > BAK_WAIT_REFORM_TIMEOUT) {
            CT_LOG_RUN_ERR("[BACKUP] can not try to backup because wait reform failed");
            return CT_ERROR;
        }
    }
    bak->reform_check.is_reformed = CT_FALSE;
    return CT_SUCCESS;
}


status_t bak_wait_reform_finish(void)
{
    cluster_view_t view;
    date_t start_time = cm_now();

    CT_LOG_RUN_INF("[BACKUP] start wait reform finish");
    while (CT_TRUE) {
        (void)memset_s(&view, sizeof(view), 0, sizeof(view));
        rc_get_cluster_view(&view, CT_FALSE);
        if ((view.is_stable == CT_TRUE) && (g_rc_ctx->status == REFORM_DONE)) {
            break;
        }
        cm_sleep(BAK_CHECK_REFORM_TIME);

        if (cm_now() - start_time > BAK_WAIT_REFORM_TIMEOUT) {
            CT_LOG_RUN_ERR("[BACKUP] wait reform timeout");
            return CT_ERROR;
        }
    }
    CT_LOG_RUN_INF("[BACKUP] end wait reform finish");
    return CT_SUCCESS;
}

void bak_free_check_reform(knl_session_t *session)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    if (bak->failed) {
        if (rc_is_cluster_changed((cluster_view_t *)(bak->reform_check.view))) {
            bak->reform_check.is_reformed = CT_TRUE;
        }
    }
    bak_free_reform_veiw_buffer(bak);
}

static status_t bak_set_params(knl_session_t *session, knl_backup_t *param)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    errno_t ret;

    bak->is_building = CT_FALSE;
    bak->is_first_link = CT_TRUE;
    bak->need_retry = CT_FALSE;
    bak->need_check = CT_FALSE;
    bak->failed = CT_FALSE;
    if (param->type == BACKUP_MODE_FINISH_LOG) {
        return bak_set_finish_info(bak, param);
    }
    bak->compress_ctx.compress_level = param->compress_level;
    bak->encrypt_info.encrypt_alg = param->crypt_info.encrypt_alg;
    bak->target_info = param->target_info;
    bak->backup_buf_size = param->buffer_size;
    bak->skip_badblock = param->skip_badblock;
    bak->has_badblock = CT_FALSE;

    bak_param_paral_init(session, param);
    bak_record_init(bak, param);
    if (bak->encrypt_info.encrypt_alg != ENCRYPT_NONE) {
        if (bak_encrypt_param_init(session, param) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    if (bak_set_data_path(session, bak, &param->format) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (bak_set_tag(session, bak, param->tag) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (bak_set_exclude_space(session, bak, param->exclude_spcs) != CT_SUCCESS) {
        ret = memset_sp(bak->exclude_spcs, sizeof(bool32) * CT_MAX_SPACES, 0, sizeof(bool32) * CT_MAX_SPACES);
        knl_securec_check(ret);
        return CT_ERROR;
    }
    if (bak_set_include_space(session, bak, param->target_info.target_list) != CT_SUCCESS) {
        ret = memset_sp(bak->include_spcs, sizeof(bool32) * CT_MAX_SPACES, 0, sizeof(bool32) * CT_MAX_SPACES);
        knl_securec_check(ret);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t bak_set_head(knl_session_t *session)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;

    if (bak_set_incr_info(session, bak) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (bak->record.log_only && bak->target_info.target != TARGET_ARCHIVE) {
        return CT_SUCCESS;
    }

    bak->file_count = 0;
    bak->curr_file_index = 0;
    ctrlinfo->lsn = DB_CURR_LSN(session);  // for incremental backup restore
    ctrlinfo->max_rcy_lsn = ctrlinfo->lsn;
    bak->send_buf.offset = CT_INVALID_ID32;
    bak->record.status = BACKUP_PROCESSING;
    if (bak_set_log_point(session, ctrlinfo, CT_FALSE, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    bak_set_head_for_paral_log(bak);
    if (bak_set_lsn(session, bak) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t bak_alloc_resource(knl_session_t *session, bak_t *bak)
{
    char uds_path[CT_FILE_NAME_BUFFER_SIZE];

    /* malloc space for bak->backup_buf,bak->depends, so it is multiplied by 2
     * malloc space for bak->compress_buf
     */
    const int32 ctrl_backup_buffer_size = (CTRL_MAX_PAGES(session) + 1) * CT_DFLT_CTRL_BLOCK_SIZE;
    const int32 node_ctrl_page_size = CT_DFLT_CTRL_BLOCK_SIZE * CT_MAX_INSTANCES;
    if (cm_aligned_malloc(BACKUP_BUFFER_SIZE(bak) * 2 + COMPRESS_BUFFER_SIZE(bak) +
        ctrl_backup_buffer_size + node_ctrl_page_size,
        "bak buffer", &bak->align_buf) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY,
            (uint64)BACKUP_BUFFER_SIZE(bak) * 2 + (uint64)COMPRESS_BUFFER_SIZE(bak), "backup");
        return CT_ERROR;
    }
    bak->backup_buf = bak->align_buf.aligned_buf;
    bak->depends = (bak_dependence_t *)(bak->backup_buf + BACKUP_BUFFER_SIZE(bak));
    /* 2 * CT_BACKUP_BUFFER_SIZE for size of bak->backup_buf and size of bak->depends */
    bak->compress_buf = bak->backup_buf + 2 * BACKUP_BUFFER_SIZE(bak);
    bak->ctrl_backup_buf = bak->compress_buf + COMPRESS_BUFFER_SIZE(bak);
    bak->ctrl_backup_bak_buf = bak->ctrl_backup_buf + ctrl_backup_buffer_size;

    if (BAK_IS_UDS_DEVICE(bak)) {
        int32 ret = snprintf_s(&uds_path[0], CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, BAK_SUN_PATH_FORMAT,
            session->kernel->home, session->kernel->instance_name);
        knl_securec_check_ss(ret);
        if (bak_init_uds(&bak->remote.uds_link, uds_path) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    // send_stream buffers are released in bak_end
    if (cm_aligned_malloc(BACKUP_BUFFER_SIZE(bak), "bak stream buf0", &bak->send_stream.bufs[0]) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cm_aligned_malloc(BACKUP_BUFFER_SIZE(bak), "bak stream buf1", &bak->send_stream.bufs[1]) != CT_SUCCESS) {
        return CT_ERROR;
    }
    bak->send_stream.buf_size = BACKUP_BUFFER_SIZE(bak);
    return CT_SUCCESS;
}

status_t bak_init_paral_proc_resource(bak_process_t *proc, bak_context_t *ctx, uint32 i)
{
    proc->proc_id = i;
    proc->is_free = CT_FALSE;
    proc->read_failed = CT_FALSE;
    proc->write_failed = CT_FALSE;
    proc->read_execute = CT_FALSE;
    proc->compress_ctx.compress_level = ctx->bak.compress_ctx.compress_level;

    if (cm_aligned_malloc((int64)BACKUP_BUFFER_SIZE(&ctx->bak), "backup paral process", &proc->backup_buf) !=
        CT_SUCCESS) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)BACKUP_BUFFER_SIZE(&ctx->bak), "backup paral process");
        return CT_ERROR;
    }

    if (bak_init_rw_buf(proc, (int64)BACKUP_BUFFER_SIZE(&ctx->bak), "BACKUP") != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)BACKUP_BUFFER_SIZE(&ctx->bak), "backup paral process");
        return CT_ERROR;
    }

    if (cm_aligned_malloc((int64)COMPRESS_BUFFER_SIZE(&ctx->bak), "backup paral process",
        &proc->encrypt_ctx.encrypt_buf) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)COMPRESS_BUFFER_SIZE(&ctx->bak), "backup paral process");
        return CT_ERROR;
    }

    if (cm_aligned_malloc((int64)COMPRESS_BUFFER_SIZE(&ctx->bak), "backup paral process",
        &proc->compress_ctx.compress_buf) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)COMPRESS_BUFFER_SIZE(&ctx->bak), "backup paral process");
        return CT_ERROR;
    }
    if (cm_create_thread(bak_paral_task_write_proc, 0, proc, &proc->write_thread) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cm_create_thread(bak_paral_task_proc, 0, proc, &proc->thread) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t bak_start_read_thread(knl_session_t *session)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_process_t *proc = &ctx->process[BAK_COMMON_PROC];
    uint32 proc_count = ctx->bak.proc_count;

    proc->proc_id = BAK_COMMON_PROC;
    if (cm_aligned_malloc((int64)BACKUP_BUFFER_SIZE(&ctx->bak), "backup process", &proc->backup_buf) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)BACKUP_BUFFER_SIZE(&ctx->bak), "backup process");
        return CT_ERROR;
    }
    if (bak_init_rw_buf(proc, (int64)BACKUP_BUFFER_SIZE(&ctx->bak), "BACKUP") != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)BACKUP_BUFFER_SIZE(&ctx->bak), "backup write process");
        return CT_ERROR;
    }

    if (cm_aligned_malloc((int64)COMPRESS_BUFFER_SIZE(&ctx->bak), "backup process", &proc->encrypt_ctx.encrypt_buf) !=
        CT_SUCCESS) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)COMPRESS_BUFFER_SIZE(&ctx->bak), "backup process");
        return CT_ERROR;
    }

    if (cm_create_thread(bak_read_proc, 0, session, &proc->thread) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!bak_paral_task_enable(session)) {
        return CT_SUCCESS;
    }

    if (bak_log_paral_enable(&ctx->bak)) {
        bak_process_t *log_proc = &ctx->process[BAK_LOG_COMMON_PROC];
        log_proc->proc_id = BAK_LOG_COMMON_PROC;
        if (cm_create_thread(bak_log_read_proc, 0, log_proc, &log_proc->thread) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    uint32 proc_start_num = bak_log_paral_enable(&ctx->bak) ? (BAK_LOG_COMMON_PROC + 1) : (BAK_COMMON_PROC + 1);
    for (uint32 i = proc_start_num; i <= proc_count; i++) {
        proc = &ctx->process[i];
        if (bak_init_paral_proc_resource(proc, ctx, i) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    bak_wait_paral_proc(session, CT_FALSE);
    return CT_SUCCESS;
}

status_t bak_start(knl_session_t *session)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;

    bak_reset_process_ctrl(bak, CT_FALSE);
    bak_reset_stats(session);
    if (bak_alloc_resource(session, bak) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (BAK_IS_FULL_BUILDING(bak) && !bak->is_first_link) {
        CT_LOG_RUN_INF("[BUILD] ignore set head for break-point building");
    } else {
        if (bak_set_head(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (bak_alloc_compress_context(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (bak_alloc_encrypt_context(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (badblock_init(session) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (bak_start_read_thread(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static uint32 log_fetch_asn(knl_session_t *session, uint32 start_asn, uint64 scn)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    uint32 i;

    if (redo_ctx->files[redo_ctx->curr_file].head.first <= scn &&
        !log_is_empty(&redo_ctx->files[redo_ctx->curr_file].head)) {
        return redo_ctx->files[redo_ctx->curr_file].head.asn;
    }

    for (i = redo_ctx->active_file; i != redo_ctx->curr_file;) {
        if (redo_ctx->files[i].head.last > scn) {
            return redo_ctx->files[i].head.asn;
        }
        log_get_next_file(session, &i, CT_FALSE);
    }

    return redo_ctx->files[i].head.asn;
}

static status_t bak_switch_logfile(knl_session_t *session, uint32 last_asn, bool32 switch_log)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;

    knl_panic(redo_ctx->files[redo_ctx->curr_file].head.asn >= last_asn);
    if (redo_ctx->files[redo_ctx->curr_file].head.asn != last_asn) {
        return CT_SUCCESS;
    }

    if (!switch_log) {
        return CT_SUCCESS;
    }
    ckpt_trigger(session, CT_FALSE, CKPT_TRIGGER_INC);

    if (DB_IS_RAFT_ENABLED(session->kernel) || DB_IS_PRIMARY(&session->kernel->db)) {
        return log_switch_logfile(session, CT_INVALID_FILEID, CT_INVALID_ASN, NULL);
    } else {
        return CT_SUCCESS;
    }
}

static status_t bak_fetch_last_log(knl_session_t *session, bak_t *bak, uint32 *last_asn)
{
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;

    if (BAK_DISTRIBUTED_PHASE_SECOND(bak)) {
        log_lock_logfile(session);
        *last_asn = log_fetch_asn(session, ctrlinfo->lrp_point.asn, bak->record.finish_scn);
        bak->record.ctrlinfo.scn = MIN(DB_CURR_SCN(session), bak->record.finish_scn);
        CT_LOG_RUN_INF("[BACKUP] fetch last log by scn %llu, new backup scn %llu",
                       bak->record.finish_scn, bak->record.ctrlinfo.scn);
        log_unlock_logfile(session);
    } else {
        *last_asn = ctrlinfo->lrp_point.asn;
    }

    if (BAK_IS_FULL_BUILDING(bak) && bak->progress.build_progress.stage == BACKUP_LOG_STAGE) {
        CT_LOG_RUN_INF("[BUILD] ignore switch logfile for break-point building");
        return CT_SUCCESS;
    }

    return bak_switch_logfile(session, *last_asn, CT_FALSE);
}

static status_t bak_notify_lrcv_record(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;

    if (DB_IS_RAFT_ENABLED(kernel)) {
        CT_LOG_RUN_WAR("[BACKUP] do not record backupset info on raft mode");
        return CT_SUCCESS;
    }

    lrcv_trigger_backup_task(session);

    if (lrcv_wait_task_process(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/* wait bak_read_proc read file data to send_buf */
static status_t bak_wait_write_data(bak_context_t *ctx, uint32 curr_file)
{
    bak_t *bak = &ctx->bak;
    bak_buf_t *send_buf = &bak->send_buf;

    while (!bak->failed && bak->progress.stage != BACKUP_READ_FINISHED &&
           send_buf->offset != 0 && curr_file == bak->file_count) {
        cm_sleep(1);
        continue;
    }

    return bak->failed ? CT_ERROR : CT_SUCCESS;
}

static status_t bak_write_data(bak_context_t *ctx, char *buf, int32 size)
{
    bak_t *bak = &ctx->bak;
    bak_attr_t *attr = &bak->record.attr;
    bak_process_t proc = ctx->process[BAK_COMMON_PROC];

    if ((attr->compress == COMPRESS_NONE) || bak->progress.stage == BACKUP_HEAD_STAGE) {
        return bak_write(bak, &proc, buf, size);
    }

    return bak_compress_write(bak, &proc, buf, size, CT_FALSE);
}

static status_t bak_write_file(knl_session_t *session, uint32 curr_file)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_buf_t *send_buf = &bak->send_buf;
    bak_attr_t *attr = &bak->record.attr;
    LZ4F_preferences_t ref = LZ4F_INIT_PREFERENCES;

    if (attr->compress == COMPRESS_LZ4 && bak->files[bak->curr_file_index].type != BACKUP_HEAD_FILE) {
        ref.compressionLevel = bak->compress_ctx.compress_level;
        size_t res = LZ4F_compressBegin(bak->compress_ctx.lz4f_cstream, bak->compress_buf,
            (uint32)COMPRESS_BUFFER_SIZE(bak), &ref);
        if (LZ4F_isError(res)) {
            CT_THROW_ERROR(ERR_COMPRESS_ERROR, "lz4f", res, LZ4F_getErrorName(res));
            return CT_ERROR;
        }
        if (bak_write(bak, &ctx->process[BAK_COMMON_PROC], bak->compress_buf, (int32)res) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    while (!bak->failed) {
        if (bak_check_session_status(session) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (bak_wait_write_data(ctx, curr_file) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (curr_file != bak->file_count || bak->progress.stage == BACKUP_READ_FINISHED) {
            break;
        }

        knl_panic(send_buf->offset == 0);
        knl_panic(send_buf->buf_size > 0);
        if (bak_write_data(ctx, send_buf->buf, send_buf->buf_size) != CT_SUCCESS) {
            return CT_ERROR;
        }

        bak_update_progress(bak, send_buf->buf_size);
        send_buf->offset = send_buf->buf_size;
    }

    if ((attr->compress != COMPRESS_NONE) && bak->files[bak->curr_file_index].type != BACKUP_HEAD_FILE) {
        if (bak_compress_write(bak, &ctx->process[BAK_COMMON_PROC], NULL, 0, CT_TRUE) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t bak_write_start(knl_session_t *session, uint32 file_index, uint32 sec_id)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    char *path = bak->record.path;

    bak->backup_size = 0;

    if (bak->is_building || BAK_IS_UDS_DEVICE(bak)) {
        uint32 start_type = bak_get_package_type(bak->files[file_index].type);
        if (bak_agent_file_start(bak, path, start_type, bak->files[file_index].id) != CT_SUCCESS) {
            return CT_ERROR;
        }
        bak->remote.remain_data_size = 0;
    } else {
        bak_generate_bak_file(session, path, bak->files[file_index].type, file_index, bak->files[file_index].id, sec_id,
                              bak->local.name);
        bak->local.type = cm_device_type(bak->local.name);
        CT_LOG_RUN_INF("[BACKUP] name %s, id %u", bak->local.name, bak->files[file_index].id);
        if (cm_create_device(bak->local.name, bak->local.type, O_BINARY | O_SYNC | O_RDWR | O_EXCL,
                             &bak->local.handle) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (bak->files[file_index].type != BACKUP_HEAD_FILE && bak->encrypt_info.encrypt_alg != ENCRYPT_NONE) {
        if (bak_encrypt_init(bak, &ctx->process[BAK_COMMON_PROC].encrypt_ctx, &bak->files[file_index],
            CT_TRUE) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (bak->files[file_index].type != BACKUP_HEAD_FILE && (bak->record.attr.compress != COMPRESS_NONE)) {
        if (knl_compress_init(bak->record.attr.compress, &bak->compress_ctx, CT_TRUE) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t bak_write_end(knl_session_t *session, bak_t *bak, bak_stage_t stage)
{
    bak_attr_t *attr = &bak->record.attr;
    bak_context_t *ctx = &session->kernel->backup_ctx;
    errno_t ret;

    if (bak->is_building || BAK_IS_UDS_DEVICE(bak)) {
        if (bak_agent_send_pkg(bak, BAK_PKG_FILE_END) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (bak_agent_wait_pkg(bak, BAK_PKG_ACK) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (bak->is_building) {
            bak->curr_file_index++;
            if ((attr->compress != COMPRESS_NONE) && stage != BACKUP_HEAD_STAGE) {
                knl_compress_end(bak->record.attr.compress, &bak->compress_ctx, CT_TRUE);
            }
            return CT_SUCCESS;
        }
    } else {
        cm_close_device(bak->local.type, &bak->local.handle);
        bak->local.handle = CT_INVALID_HANDLE;
    }

    if ((attr->compress != COMPRESS_NONE) && stage != BACKUP_HEAD_STAGE) {
        knl_compress_end(bak->record.attr.compress, &bak->compress_ctx, CT_TRUE);
    }

    if (bak->encrypt_info.encrypt_alg != ENCRYPT_NONE && stage != BACKUP_HEAD_STAGE) {
        if (bak_encrypt_end(bak, &ctx->process[BAK_COMMON_PROC].encrypt_ctx) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (bak->files[bak->curr_file_index].type != BACKUP_HEAD_FILE) {
        knl_panic(bak->curr_file_index < BAK_MAX_FILE_NUM);
        bak->files[bak->curr_file_index].size = bak->backup_size;
        bak->files[bak->curr_file_index].sec_start = 0;
        bak->files[bak->curr_file_index].sec_end = 0;
        if (bak->encrypt_info.encrypt_alg != ENCRYPT_NONE) {
            ret = memcpy_sp(bak->files[bak->curr_file_index].gcm_tag, EVP_GCM_TLS_TAG_LEN,
                ctx->process[BAK_COMMON_PROC].encrypt_ctx.encrypt_buf.aligned_buf, EVP_GCM_TLS_TAG_LEN);
            knl_securec_check(ret);
        }
        bak->curr_file_index++;
    }

    return CT_SUCCESS;
}

static status_t bak_write_files(knl_session_t *session)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_stage_t stage = BACKUP_START;

    while (!bak->failed && bak->progress.stage != BACKUP_READ_FINISHED) {
        if (bak_check_session_status(session) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (bak->curr_file_index == bak->file_count) {
            cm_sleep(1);
            continue;
        }

        bak_file_type_t type = bak->files[bak->curr_file_index].type;
        if (type >= BACKUP_DATA_FILE && type <= BACKUP_ARCH_FILE) {
            bak->ctrlfile_completed = CT_TRUE;
            if (bak_paral_task_enable(session)) {
                cm_sleep(10);
                continue;
            }
        }

        stage = bak->progress.stage;
        if (bak_write_start(session, bak->curr_file_index, 0) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (bak_write_file(session, bak->curr_file_index + 1) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BACKUP] bak_write_file write exit");
            return CT_ERROR;
        }

        if (bak_write_end(session, bak, stage) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return bak->failed ? CT_ERROR : CT_SUCCESS;
}

status_t bak_record(knl_session_t *session)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;

    if (bak->is_building) {
        return CT_SUCCESS;
    }

    if (session->kernel->db.status == DB_STATUS_MOUNT) {
        return CT_SUCCESS;
    }

    if (DB_IS_PRIMARY(&session->kernel->db)) {
        bak->record.status = (bak->failed) ? BACKUP_FAILED : BACKUP_SUCCESS;
        return bak_record_backup_set(session, &bak->record);
    }

    return bak_notify_lrcv_record(session);
}

static status_t bak_write_config_param(bak_context_t *ctx)
{
    bak_t *bak = &ctx->bak;
    bak_buf_t *send_buf = &bak->send_buf;

    CT_LOG_RUN_INF("[BACKUP] start write config parameter");
    while (!bak->failed) {
        if (bak_wait_write_data(ctx, 0) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (bak->file_count != 0) {
            break;
        }

        knl_panic(send_buf->offset == 0);
        knl_panic(send_buf->buf_size > 0);

        if (bak_write(&ctx->bak, &ctx->process[BAK_COMMON_PROC], send_buf->buf,
            (int32)send_buf->buf_size) != CT_SUCCESS) {
            return CT_ERROR;
        }

        bak_update_progress(bak, send_buf->buf_size);
        send_buf->offset = send_buf->buf_size;
    }
    CT_LOG_RUN_INF("[BACKUP] write config parameter successfully");

    return CT_SUCCESS;
}

static status_t bak_wait_write_ctrl_file(knl_session_t *session)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_buf_t *send_buf = &bak->send_buf;

    if (send_buf->offset < send_buf->buf_size) {
        return CT_SUCCESS;
    }

    while ((!bak->failed && send_buf->offset != 0) || send_buf->buf_size == 0) {
        if (bak_check_session_status(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
        cm_sleep(1);
        continue;
    }

    return bak->failed ? CT_ERROR : CT_SUCCESS;
}

static status_t bak_write_ctrl_file(knl_session_t *session)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_buf_t *send_buf = &bak->send_buf;
    bak_agent_head_t head;

    if (!BAK_IS_FULL_BUILDING(bak)) {
        return CT_SUCCESS;
    }

    if (bak->is_first_link) {
        return CT_SUCCESS;
    }

    CT_LOG_RUN_INF("[BACKUP] start write ctrl file");
    for (uint32 i = 0; i < BAK_BUILD_CTRL_SEND_TIME; i++) {
        if (bak_wait_write_ctrl_file(session) != CT_SUCCESS) {
            return CT_ERROR;
        }

        knl_panic(send_buf->offset == 0);
        knl_panic(send_buf->buf_size > 0);

        head.ver = BAK_AGENT_PROTOCOL;
        head.cmd = BAK_PKG_DATA;
        head.len = sizeof(bak_agent_head_t) + send_buf->buf_size;
        head.flags = 0;
        head.serial_number = 0;
        head.reserved = 0;

        if (bak_agent_send(bak, (char *)&head, sizeof(bak_agent_head_t)) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (bak_agent_send(bak, send_buf->buf, send_buf->buf_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
        send_buf->offset += send_buf->buf_size;
        CT_LOG_RUN_INF("[BACKUP] send_buf->offset : %u ", send_buf->offset);
        CT_LOG_RUN_INF("[BACKUP] send_buf->buf_size : %u ", send_buf->buf_size);
    }

    if (bak_agent_wait_pkg(bak, BAK_PKG_ACK) != CT_SUCCESS) {
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[BACKUP] write ctrl file successfully");

    return CT_SUCCESS;
}

status_t bak_write_proc(knl_session_t *session, bak_context_t *ctx)
{
    bak_t *bak = &ctx->bak;

    // send param
    if (bak->is_building && bak->is_first_link && !bak->record.is_repair) {
        if (bak_write_config_param(ctx) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    if (bak_write_ctrl_file(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (bak_agent_command(bak, BAK_PKG_SET_START) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (bak_write_files(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (bak_agent_command(bak, BAK_PKG_SET_END) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (BAK_IS_UDS_DEVICE(bak)) {
        cs_uds_disconnect(&bak->remote.uds_link);
    }

    return CT_SUCCESS;
}

status_t bak_load_tablespaces(knl_session_t *session)
{
    for (uint16 i = 0; i < CT_MAX_SPACES; i++) {
        space_t *space = SPACE_GET(session, i);
        if (space->ctrl->file_hwm == 0) {
            continue;
        }

        if (!SPACE_IS_ONLINE(space)) {
            continue;
        }

        if (spc_mount_space(session, space, CT_TRUE) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t bak_load_files(knl_session_t *session)
{
    if (bak_load_tablespaces(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (log_load(session) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] backup failed when load log in mount mode");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void bak_unload_tablespace(knl_session_t *session)
{
    for (uint16 i = 0; i < CT_MAX_SPACES; i++) {
        space_t *space = SPACE_GET(session, i);
        if (space->ctrl->file_hwm == 0) {
            continue;
        }

        if (!SPACE_IS_ONLINE(space)) {
            continue;
        }

        spc_umount_space(session, space);
    }
}

status_t bak_precheck(knl_session_t *session)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    bak_t *bak = &session->kernel->backup_ctx.bak;
    CT_LOG_RUN_INF("[BACKUP] start backup precheck");
    if (!session->kernel->db.ctrl.core.build_completed) {
        CT_THROW_ERROR(ERR_DATABASE_NOT_COMPLETED);
        return CT_ERROR;
    }

    if (bak->build_stopped) {
        CT_THROW_ERROR(ERR_BUILD_CANCELLED);
        return CT_ERROR;
    }

    if (session->kernel->attr.clustered) {
        cluster_view_t view;
        rc_get_cluster_view(&view, CT_FALSE);
        bak->target_bits = view.bitmap;
        // wait if not get master_id info yet
        while (CT_INVALID_ID8 == g_rc_ctx->info.master_id) {
            CT_LOG_RUN_INF("[BACKUP] wait for reform successful.");
            cm_sleep(1000);
        }

        msg_pre_bak_check_t pre_check;
        for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
            if (SECUREC_UNLIKELY(i == g_dtc->profile.inst_id)) {
                continue;
            }
            rc_get_cluster_view(&view, CT_FALSE);
            if (!rc_bitmap64_exist(&view.bitmap, i)) {
                continue;
            }
            if (dtc_bak_precheck(session, i, &pre_check) != CT_SUCCESS) {
                CT_LOG_RUN_WAR("[BACKUP] dtc bak precheck failed, ignore other nodes.");
                cm_reset_error();
                continue;
            }
            if (!pre_check.is_archive) {
                CT_THROW_ERROR(ERR_DATABASE_NOT_ARCHIVE, "database must run in archive mode when backup");
                return CT_ERROR;
            }
            if (pre_check.is_switching) {
                CT_THROW_ERROR(ERR_SESSION_CLOSED, "server is doing switch request");
                return CT_ERROR;
            }
        }
    }

    if (session->kernel->switch_ctrl.request != SWITCH_REQ_NONE) {
        CT_THROW_ERROR(ERR_SESSION_CLOSED, "server is doing switch request");
        return CT_ERROR;
    }

    if (!arch_ctx->is_archive) {
        CT_THROW_ERROR(ERR_DATABASE_NOT_ARCHIVE, "database must run in archive mode when backup");
        return CT_ERROR;
    }

    if (DB_IS_RAFT_ENABLED(session->kernel) && !DB_IS_PRIMARY(&session->kernel->db) && raft_is_primary_alive(session)) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION,
            "not allowed to backup on standby node when primary is alive in raft mode");
        return CT_ERROR;
    }

    if (!DB_IS_PRIMARY(&session->kernel->db) && bak->rcy_stop_backup) {
        CT_THROW_ERROR_EX(ERR_INVALID_OPERATION,
            "not allowed to backup on standby node when standby is replaying redo %s", bak->unsafe_redo);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[BACKUP] backup precheck finished");
    return CT_SUCCESS;
}

status_t bak_end_check(knl_session_t *session)
{
    status_t status = CT_SUCCESS;
    bak_t *bak = &session->kernel->backup_ctx.bak;
    bak_free_check_reform(session);
    if (bak->failed) {
        status = CT_ERROR;
    } else {
        if (bak_record(session) != CT_SUCCESS) {
            bak->failed = CT_TRUE;
            status = CT_ERROR;
        }
    }
    bak_end(session, CT_FALSE);
    return status;
}

void bak_print_log_point(knl_session_t *session, bak_context_t *ctx)
{
    bak_t *bak = &ctx->bak;
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;
    struct tm *today = NULL;
    timeval_t time_val;
    time_t t;
    char timef[CT_MAX_NUMBER_LEN];
    time_t init_time = DB_INIT_TIME(session);

    KNL_SCN_TO_TIME(ctrlinfo->scn, &time_val, init_time);
    t = time_val.tv_sec;
    today = localtime(&t);
    if (today != NULL) {
        (void)strftime(timef, CT_MAX_NUMBER_LEN, "%Y-%m-%d %H:%M:%S", today);
        CT_LOG_RUN_INF("[BACKUP] The lrp point for this time of backup is %s\n ", timef);
    } else {
        CT_LOG_RUN_INF("[BACKUP] calculate the lrp point for this time of backup failed");
    }
}

status_t bak_backup_proc(knl_session_t *session)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;

    if (bak_start(session) != CT_SUCCESS) {
        bak->failed = CT_TRUE;
        (void)bak_end_check(session);
        return CT_ERROR;
    }
    if (bak_write_proc(session, ctx) != CT_SUCCESS) {
        bak->failed = CT_TRUE;
        (void)bak_end_check(session);
        return CT_ERROR;
    }

    bak_print_log_point(session, ctx);
    if (bak_end_check(session) != CT_SUCCESS) {
        return CT_ERROR;
    }
    
    return CT_SUCCESS;
}
 
status_t bak_check_increment_type(knl_session_t *session, knl_backup_t *param)
{
    knl_cursor_t *bak_cursor = NULL;
    backup_type_t last_inc_type;
    backup_type_t cur_inc_type;
    uint32 last_level;
 
    CM_SAVE_STACK(session->stack);
    if (param->level == 0) {
        CM_RESTORE_STACK(session->stack);
        return CT_SUCCESS;
    }

    CT_LOG_RUN_INF("[BACKUP] incremental backup, cumulative is [%u].", param->cumulative);
    knl_set_session_scn(session, CT_INVALID_ID64);
    bak_cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, bak_cursor, CURSOR_ACTION_SELECT, SYS_BACKUP_SET_ID, 0);

    bak_cursor->index_dsc = CT_TRUE;
    knl_init_index_scan(bak_cursor, CT_FALSE);
    knl_set_key_flag(&bak_cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, 0);
    knl_set_key_flag(&bak_cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, 0);
 
    if (knl_fetch(session, bak_cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
 
    if (bak_cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        return CT_SUCCESS;
    } else {
        cm_decode_row((char *)bak_cursor->row, bak_cursor->offsets, bak_cursor->lens, NULL);
    }
    last_inc_type = *(uint32 *)CURSOR_COLUMN_DATA(bak_cursor, BAK_COL_TYPE);
    last_level = *(uint32 *)CURSOR_COLUMN_DATA(bak_cursor, BAK_COL_LEVEL);
    if (last_level == 0) {
        CM_RESTORE_STACK(session->stack);
        return CT_SUCCESS;
    }

    cur_inc_type = param->cumulative ? BACKUP_MODE_INCREMENTAL_CUMULATIVE : BACKUP_MODE_INCREMENTAL;
    if (last_inc_type != cur_inc_type) {
        CT_THROW_ERROR_EX(ERR_INVALID_OPERATION,
            " not allowed to backup increment set with different types on the same full backup set,"
            "last incremental backup type is [%s], current type is [%s]!",
            last_inc_type == BACKUP_MODE_INCREMENTAL ? "variance increment" : "cumulative increment",
            cur_inc_type == BACKUP_MODE_INCREMENTAL ? "variance increment" : "cumulative increment");
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
 
    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}
 
static status_t bak_backup_database_internal(knl_session_t *session, knl_backup_t *param)
{
    uint32 proc_count = param->parallelism == 0 ? BAK_DEFAULT_PARALLELISM : param->parallelism;
    bak_context_t *ctx = &session->kernel->backup_ctx;

    if (bak_init_reform_check(&(ctx->bak)) != CT_SUCCESS) {
        bak_free_check_reform(session);
        return CT_ERROR;
    }
    if (bak_precheck(session) != CT_SUCCESS) {
        bak_free_check_reform(session);
        return CT_ERROR;
    }
    if (bak_check_increment_type(session, param) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (DB_IS_PRIMARY(&session->kernel->db) && DB_IS_READONLY(session) && param->type != BACKUP_MODE_FULL) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION,
                       ", only full backup is allowed when primary is read-only mode");
        bak_free_check_reform(session);
        return CT_ERROR;
    }

    CT_LOG_RUN_INF("[BACKUP] backup start, type :%d, level:%d, path:%s, device:%d, policy:%s, tag:%s, "
                   "finish scn :%llu, prepare:%d, process count %u, compress type:%u level:%u, buffer size:%uM",
                   param->type, param->level, T2S(&param->format), param->device, T2S_EX(&param->policy), param->tag,
                   param->finish_scn, param->prepare, proc_count, param->compress_algo, param->compress_level,
                   param->buffer_size / SIZE_M(1));
    if (bak_set_params(session, param) != CT_SUCCESS) {
        bak_free_check_reform(session);
        return CT_ERROR;
    }

    if (bak_backup_proc(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t bak_backup_database(knl_session_t *session, knl_backup_t *param)
{
    status_t status = CT_SUCCESS;

    if (param->force_cancel) {
        session->kernel->backup_ctx.bak.failed = CT_TRUE;
        session->kernel->backup_ctx.bak.record.data_only = CT_FALSE;
        CT_LOG_RUN_WAR("[BACKUP] backup process is canceled by user");
        return CT_SUCCESS;
    }

    if (BAK_NEED_LOAD_FILE(session)) {
        if (bak_load_files(session) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BACKUP] backup failed when load spaces in mount mode");
            return CT_ERROR;
        }
    }

    if (bak_backup_database_internal(session, param) != CT_SUCCESS) {
        status = CT_ERROR;
    }

    if (BAK_NEED_UNLOAD_FILE(session)) {
        bak_unload_tablespace(session);
    }

    return status;
}

static status_t bak_set_read_range(knl_session_t *session, bak_assignment_t *assign_ctrl, uint64 offset_input)
{
    uint64 offset = offset_input;
    datafile_t *df = DATAFILE_GET(session, assign_ctrl->file_id);
    uint32 sec_id = assign_ctrl->sec_id;
    uint64 success_inst = 0;

    bool32 contains_dw = bak_datafile_contains_dw(session, assign_ctrl);
    if (contains_dw && offset == 2 * DEFAULT_PAGE_SIZE(session)) {      /* skip double write area */
        offset = DW_SPC_HWM_START * DEFAULT_PAGE_SIZE(session);
        CT_LOG_RUN_INF("[BACKUP] skip double write area, offset %llu", offset);
    }

    uint64 read_size = bak_set_datafile_read_size(session, offset, contains_dw,
        assign_ctrl->file_size, assign_ctrl->file_hwm_start);
    if (read_size > BACKUP_BUFFER_SIZE(&session->kernel->backup_ctx.bak)) {
        read_size = BACKUP_BUFFER_SIZE(&session->kernel->backup_ctx.bak);
    }

    if (BAK_IS_UDS_DEVICE(&session->kernel->backup_ctx.bak) &&
        read_size > BACKUP_STREAM_BUFSIZE(session, &session->kernel->backup_ctx.bak)) {
        read_size = BACKUP_STREAM_BUFSIZE(session, &session->kernel->backup_ctx.bak);
    }

    assign_ctrl->start = offset;
    assign_ctrl->end = offset + read_size;

    if (DB_ATTR_CLUSTER(session)) {
        dtc_bak_file_blocking(session, assign_ctrl->file_id, sec_id, assign_ctrl->start, assign_ctrl->end,
                              &success_inst);
        if (dtc_get_mes_sent_success_cnt(success_inst) != (session->kernel->db.ctrl.core.node_count - 1)) {
            CT_LOG_DEBUG_ERR("[BACKUP] failed to block remote file.");
            return CT_ERROR;
        }
    }
    spc_block_datafile(df, sec_id, assign_ctrl->start, assign_ctrl->end);

    return CT_SUCCESS;
}

static bool32 bak_check_page_list(knl_session_t *session, page_head_t *page)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    page_id_t id = PAGE_GET_PAGEID(page);
    uint32 file_hash = id.file % BUILD_ALY_MAX_FILE;
    uint32 page_hash = id.page % BUILD_ALY_MAX_BUCKET_PER_FILE;
    build_analyse_bucket_t *bucket = &bak->build_aly_buckets[file_hash * BUILD_ALY_MAX_BUCKET_PER_FILE + page_hash];
    build_analyse_item_t *item = bucket->first;

    while (item != NULL) {
        if (IS_SAME_PAGID(id, *item->page_id)) {
            CT_LOG_DEBUG_INF("[REPAIR] find page %u-%u", id.file, id.page);
            return CT_TRUE;
        }
        item = item->next;
    }

    return CT_FALSE;
}

void bak_filter_pages(knl_session_t *session, bak_process_t *ctx, bak_buf_data_t *data_buf)
{
    bak_context_t *backup_ctx = &session->kernel->backup_ctx;
    bak_attr_t *attr = &backup_ctx->bak.record.attr;
    uint64 base_lsn = attr->base_lsn;
    uint32 level = attr->level;
    uint32 file_id = ctx->assign_ctrl.file_id;
    datafile_t *df = DATAFILE_GET(session, file_id);
    bool32 punched;
    int32 size;
    errno_t ret;
    page_id_t id;
    uint64 filter_num = 0;

    if (level == 0) {
        ctx->write_size = data_buf->data_size;
        return;
    }

    for (ctx->write_size = 0, size = 0; size < data_buf->data_size; size += DEFAULT_PAGE_SIZE(session)) {
        page_head_t *page = (page_head_t *)(data_buf->data_addr + size);
        punched = (DATAFILE_IS_PUNCHED(df) && page->size_units == 0);
        if (punched  || page->lsn >= base_lsn ||
            (backup_ctx->bak.record.is_repair && bak_check_page_list(session, page))) {
            if (punched) {
                id.file = file_id;
                id.page = (data_buf->curr_offset + size) / DEFAULT_PAGE_SIZE(session);
                CT_LOG_RUN_WAR("[BACKUP] datafile is punched and page(%u) size_units are zero, init page", id.page);
                page_init(session, page, id, PAGE_TYPE_PUNCH_PAGE);
            }
            CT_LOG_DEBUG_INF("[BACKUP] incr backup get page_id %u-%u, punched %u", AS_PAGID_PTR(page->id)->file,
                AS_PAGID_PTR(page->id)->page, (uint32)punched);
            if (ctx->write_size < size) {
                ret = memcpy_sp(data_buf->data_addr + ctx->write_size,
                    BACKUP_BUFFER_SIZE(&backup_ctx->bak) - (uint32)ctx->write_size, data_buf->data_addr + size,
                    DEFAULT_PAGE_SIZE(session));
                knl_securec_check(ret);
            }
            ctx->write_size += (int32)DEFAULT_PAGE_SIZE(session);
        } else {
            filter_num++;
            CT_LOG_DEBUG_INF("[BACKUP] incr backup get page_id %u-%u, punched %u", AS_PAGID_PTR(page->id)->file,
                AS_PAGID_PTR(page->id)->page, (uint32)punched);
        }
    }
    ctx->page_filter_num += filter_num;
    if (filter_num * DEFAULT_PAGE_SIZE(session) != data_buf->data_size - ctx->write_size) {
        CT_LOG_RUN_ERR("[BACKUP] curr offset %llu, data size %d, write size %d, filter num %llu",
                       data_buf->curr_offset, data_buf->data_size, ctx->write_size, filter_num);
        ctx->write_failed = CT_TRUE;
    }
}

void bak_fetch_read_range(knl_session_t *session, bak_process_t *bak_proc)
{
    bak_assignment_t *assign_ctrl = &bak_proc->assign_ctrl;
    bak_ctrl_t *ctrl = &bak_proc->ctrl;

    bak_proc->read_size = 0;
    knl_panic(ctrl->offset < assign_ctrl->file_size);

    bak_set_read_range(session, assign_ctrl, ctrl->offset);
    uint64 size = assign_ctrl->end - assign_ctrl->start;
    knl_panic(size <= BACKUP_BUFFER_SIZE(&session->kernel->backup_ctx.bak));
    bak_proc->read_size = (int32)size; // size <= 8M, can not overflow
    ctrl->offset = assign_ctrl->start;
}

status_t bak_read_datafile_pages(knl_session_t *session, bak_process_t *bak_proc)
{
    bak_ctrl_t *ctrl = &bak_proc->ctrl;
    bak_assignment_t *assign_ctrl = &bak_proc->assign_ctrl;
    bak_context_t *bak_ctx = &session->kernel->backup_ctx;
    bak_stat_t *stat = &bak_ctx->bak.stat;
    status_t status;
    timeval_t tv_begin;

    bak_fetch_read_range(session, bak_proc);

    cantian_record_io_stat_begin(IO_RECORD_EVENT_BAK_READ_DATA, &tv_begin);
    SYNC_POINT_GLOBAL_START(CANTIAN_BACKUP_READ_PAGE_FROM_DBSTOR_FAIL, &status, CT_ERROR);
    status = cm_read_device(ctrl->type, ctrl->handle, ctrl->offset, bak_proc->read_buf->data_addr,
        bak_proc->read_size);
    SYNC_POINT_GLOBAL_END;
    cantian_record_io_stat_end(IO_RECORD_EVENT_BAK_READ_DATA, &tv_begin, IO_RECORD_STAT_RET(status));
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] failed to read %s", ctrl->name);
        if (DB_ATTR_CLUSTER(session)) {
            dtc_bak_file_unblocking(session, assign_ctrl->file_id, assign_ctrl->sec_id);
        }
        spc_unblock_datafile(DATAFILE_GET(session, assign_ctrl->file_id), assign_ctrl->sec_id);
        return CT_ERROR;
    }
    if (DB_ATTR_CLUSTER(session)) {
        dtc_bak_file_unblocking(session, assign_ctrl->file_id, assign_ctrl->sec_id);
    }
    spc_unblock_datafile(DATAFILE_GET(session, assign_ctrl->file_id), assign_ctrl->sec_id);
    (void)cm_atomic_inc(&stat->reads);
    (void)cm_atomic_inc(&session->kernel->total_io_read);
    bak_proc->read_buf->curr_offset = ctrl->offset;
    bak_proc->read_buf->data_size = bak_proc->read_size;
    ctrl->offset += bak_proc->read_size;
    bak_proc->total_read_size += bak_proc->read_size;
    return CT_SUCCESS;
}

void bak_close(knl_session_t *session)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;

    bak->failed = CT_TRUE;
}

/* wait bak_write_proc write send_buf data to local disk */
status_t bak_wait_write(bak_t *bak)
{
    bak_buf_t *send_buf = &bak->send_buf;

    while (!bak->failed && send_buf->offset != send_buf->buf_size) {
        cm_sleep(1);
        continue;
    }

    return bak->failed ? CT_ERROR : CT_SUCCESS;
}

static void bak_offline_space(knl_session_t *session, ctrl_page_t *pages, uint32 id)
{
    database_ctrl_t *ctrl = &session->kernel->db.ctrl;

    // pages from backup buffer, not the original database ctrl pages
    space_ctrl_t *space = (space_ctrl_t *)db_get_ctrl_item(pages, id, sizeof(space_ctrl_t), ctrl->space_segment);
    CM_CLEAN_FLAG(space->flag, SPACE_FLAG_ONLINE);
    CT_LOG_RUN_INF("[BACKUP] backup offline space %s", space->name);

    for (uint32 i = 0; i < space->file_hwm; i++) {
        uint32 file = space->files[i];
        if (file == CT_INVALID_ID32) {
            continue;
        }
        datafile_ctrl_t *datafile = (datafile_ctrl_t *)db_get_ctrl_item(pages, file, sizeof(datafile_ctrl_t),
            ctrl->datafile_segment);
        CM_CLEAN_FLAG(datafile->flag, DATAFILE_FLAG_ONLINE);
    }
}

static void bak_offline_exclude_spaces(knl_session_t *session, ctrl_page_t *pages, bak_t *bak)
{
    for (uint32 i = 0; i < CT_MAX_SPACES; i++) {
        if (!bak->exclude_spcs[i]) {
            continue;
        }

        bak_offline_space(session, pages, i);
    }
}

static void bak_read_ctrl_pages(knl_session_t *session, bak_t *bak, ctrl_page_t *pages, uint32 page_count)
{
    uint32 size = page_count * CT_DFLT_CTRL_BLOCK_SIZE;
    const int32 ctrl_backup_buffer_size = (CTRL_MAX_PAGES(session) + 1) * CT_DFLT_CTRL_BLOCK_SIZE;
    CT_LOG_DEBUG_INF("[BACKUP] size %u, buffer size %u", size, ctrl_backup_buffer_size);
    knl_panic(size <= ctrl_backup_buffer_size);
    errno_t ret = memcpy_sp(bak->backup_buf, ctrl_backup_buffer_size, pages, size);
    knl_securec_check(ret);

    bak_offline_exclude_spaces(session, (ctrl_page_t *)bak->backup_buf, bak);
}

status_t bak_wait_write_ctrl(bak_t *bak, uint32 page_count)
{
    bak_buf_t *send_buf = &bak->send_buf;
    uint32 size = 0;
    uint32 sender_offset = 0;
    int32 remain_size = (int32)(page_count * CT_DFLT_CTRL_BLOCK_SIZE);
    while (remain_size > 0) {
        send_buf->buf = bak->backup_buf + sender_offset;
        size = remain_size > BACKUP_BUFFER_SIZE(bak) ? BACKUP_BUFFER_SIZE(bak) : remain_size;
        remain_size -= size;
        send_buf->buf_size = size;
        send_buf->offset = 0;
        sender_offset += size;
        if (bak_wait_write(bak) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    CT_LOG_RUN_INF("[BACKUP] arch send_buf->buf_size : %u", page_count * CT_DFLT_CTRL_BLOCK_SIZE);
    return CT_SUCCESS;
}

static void bak_read_arch_pages(knl_session_t *session, bak_t *bak, uint32 page_count)
{
    uint32 size = page_count * CT_DFLT_CTRL_BLOCK_SIZE;
    const int32 ctrl_backup_buffer_size = (CTRL_MAX_PAGES(session) + 1) * CT_DFLT_CTRL_BLOCK_SIZE;
    knl_panic(size <= ctrl_backup_buffer_size);
    errno_t ret = memset_sp(bak->backup_buf, ctrl_backup_buffer_size, 0, size);
    knl_securec_check(ret);
}

status_t bak_get_datafile_size(knl_session_t *session, datafile_ctrl_t *ctrl, datafile_t *df,
    uint64_t *datafile_size)
{
    int32 *handle = NULL;
    status_t ret = CT_SUCCESS;
    if (!DB_IS_CLUSTER(session)) {
        return CT_SUCCESS;
    }
    handle = DATAFILE_FD(session, ctrl->id);
    SYNC_POINT_GLOBAL_START(CANTIAN_SPC_OPEN_DATAFILE_FAIL, &ret, CT_ERROR);
    ret = spc_open_datafile(session, df, handle);
    SYNC_POINT_GLOBAL_END;
    if (*handle == -1 && ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[SPACE] failed to open file %s", ctrl->name);
        return CT_ERROR;
    }
    uint64_t datafile_size_disk = cm_device_size(ctrl->type, *handle);
    if (datafile_size_disk > *datafile_size) {
        CT_LOG_RUN_INF("[BACKUP] the datafile %s size is not the latest in memory, update it from [%lu] to [%lu]",
            ctrl->name, *datafile_size, datafile_size_disk);
        *datafile_size = datafile_size_disk;
    }
    spc_close_datafile(df, handle);
    return CT_SUCCESS;
}

char *bak_get_ctrl_datafile_item(knl_session_t *session, ctrl_page_t *pages, uint32 id)
{
    database_t *db = &session->kernel->db;
    uint32 offset = db->ctrl.datafile_segment;
    uint32 item_size = sizeof(datafile_ctrl_t);
    uint32 count = CTRL_MAX_BUF_SIZE / item_size;
    uint32 page_id = offset + id / count;
    uint16 slot = id % count;
    ctrl_page_t *page = pages + page_id;

    return page->buf + slot * item_size;
}

status_t bak_update_datafile_size(knl_session_t *session, bak_t *bak)
{
    uint64 id = 0;
    datafile_t *df = NULL;
    uint64_t datafile_size = 0;
    database_t *db = &session->kernel->db;
    ctrl_page_t *ctrl_pages = (ctrl_page_t *)bak->backup_buf;
    datafile_ctrl_t *ctrl_in_pages = NULL;
    datafile_ctrl_t *ctrl_in_bakbuf = NULL;
    for (;;) {
        if (id >= CT_MAX_DATA_FILES) {
            break;
        }
        df = &db->datafiles[id];
        ctrl_in_pages = df->ctrl;
        datafile_size = ctrl_in_pages->size;
        if (ctrl_in_pages->used) {
            CT_RETURN_IFERR(bak_get_datafile_size(session, ctrl_in_pages, df, &datafile_size));
            ctrl_in_bakbuf = (datafile_ctrl_t *)bak_get_ctrl_datafile_item(session, ctrl_pages, id);
            ctrl_in_bakbuf->size = datafile_size;
        }
        id++;
    }
    return CT_SUCCESS;
}

void bak_update_rcy_point(knl_session_t *session)
{
    if (!session->kernel->attr.clustered) {
        return;
    }
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    ctrl_page_t *pages = (ctrl_page_t *)(bak->backup_buf);
    dtc_node_ctrl_t *page_ctrl;
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;
    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        if (SECUREC_UNLIKELY(i == g_dtc->profile.inst_id)) {
            CT_LOG_RUN_INF("[BACKUP] node %u rcy lsn is %llu", i, ctrlinfo->dtc_rcy_point[i].lsn);
            continue;
        }
        // Previous ckpt has not been triggered
        if (ctrlinfo->dtc_rcy_point[i].lsn == 0) {
            page_ctrl = (dtc_node_ctrl_t *)(pages[CTRL_LOG_SEGMENT + i].buf);
            ctrlinfo->dtc_rcy_point[i] = page_ctrl->rcy_point;
        }
        CT_LOG_RUN_INF("[BACKUP] node %u rcy lsn is %llu", i, ctrlinfo->dtc_rcy_point[i].lsn);
    }
    CT_LOG_RUN_INF("[BACKUP] backup update rcy point lsn for all nodes finished");
    return;
}

static status_t bak_read_ctrlfile(knl_session_t *session)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    database_t *db = &session->kernel->db;
    uint32 page_count = db->ctrl.arch_segment;

    if (BAK_IS_FULL_BUILDING(bak) && !bak->is_first_link) {
        CT_LOG_RUN_INF("[BUILD] ignore setting progress for break-point building");
    } else {
        bak->ctrlfile_completed = CT_FALSE;
        bak_set_progress(session, BACKUP_CTRL_STAGE, CTRL_MAX_PAGES(session) * CT_DFLT_CTRL_BLOCK_SIZE);
        bak_record_new_file(bak, BACKUP_CTRL_FILE, 0, 0, 0, CT_FALSE, 0, 0);
    }
    char *backup_addr = bak->backup_buf;
    bak->backup_buf = bak->ctrl_backup_buf;
    cm_spin_lock(&db->ctrl_lock, NULL);
    db_store_core(db);
    bak_read_ctrl_pages(session, bak, db->ctrl.pages, page_count);
    cm_spin_unlock(&db->ctrl_lock);

    if (bak_update_datafile_size(session, bak) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] update datafile size failed");
        bak->backup_buf = backup_addr;
        return CT_ERROR;
    }
    if (session->kernel->attr.clustered) {
        status_t s = dtc_bak_get_ctrl_all(session);
        if (s != CT_SUCCESS) {
            bak->backup_buf = backup_addr;
            return s;
        }
        dtc_bak_copy_ctrl_buf_2_send(session);
    }
    bak_update_rcy_point(session);
    bak_calc_ctrlfile_checksum(session, bak->backup_buf, page_count);

    if (bak_wait_write_ctrl(bak, page_count) != CT_SUCCESS) {
        bak->backup_buf = backup_addr;
        return CT_ERROR;
    }

    page_count = CTRL_MAX_PAGES(session) - db->ctrl.arch_segment;
    bak_read_arch_pages(session, bak, page_count);

    if (bak_wait_write_ctrl(bak, page_count) != CT_SUCCESS) {
        bak->backup_buf = backup_addr;
        return CT_ERROR;
    }
    bak->backup_buf = backup_addr;
    CT_LOG_RUN_INF("[BACKUP] prepare ctrl succ");

    return CT_SUCCESS;
}

static status_t bak_read_keyfile(knl_session_t *session, char *buf, uint64 buf_size)
{
    int32 handle = INVALID_FILE_HANDLE;
    char keyfile_name[CT_FILE_NAME_BUFFER_SIZE];
    int32 read_size = 0;
    int64 file_size = 0;

    if (!g_knl_callback.have_ssl()) {
        ((keyfile_ctrl_t *)buf)->size = file_size;
        CT_LOG_RUN_INF("[BACKUP] HA don't have ssl, can't send keyfile when build standby");
        return CT_SUCCESS;
    }

    errno_t ret = snprintf_s(keyfile_name, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1, "%s.building.export",
                             session->kernel->attr.kmc_key_files[0].name);
    knl_securec_check_ss(ret);

    if (cm_file_exist(keyfile_name)) {
        if (cm_remove_file(keyfile_name) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BACKUP] failed to remove building key file %s", keyfile_name);
            return CT_ERROR;
        }
    }

    if (cm_kmc_export_keyfile(keyfile_name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cm_open_file(keyfile_name, O_RDONLY | O_BINARY, &handle) != CT_SUCCESS) {
        return CT_ERROR;
    }

    file_size = cm_file_size(handle);
    if (file_size <= 0) {
        cm_close_file(handle);
        CT_LOG_RUN_ERR("[BACKUP] seek file failed :%s.", keyfile_name);
        return CT_ERROR;
    }

    knl_panic((uint64)file_size + sizeof(keyfile_ctrl_t) <= buf_size);

    if (cm_seek_file(handle, 0, SEEK_SET) != 0) {
        cm_close_file(handle);
        CT_LOG_RUN_ERR("[BACKUP] seek file failed :%s.", keyfile_name);
        return CT_ERROR;
    }

    ((keyfile_ctrl_t *)buf)->size = file_size;
    if (cm_read_file(handle, buf + sizeof(keyfile_ctrl_t), (int32)(buf_size - sizeof(keyfile_ctrl_t)),
                     &read_size) != CT_SUCCESS) {
        cm_close_file(handle);
        CT_LOG_RUN_ERR("[BACKUP] read file failed :%s.", keyfile_name);
        return CT_ERROR;
    }
    cm_close_file(handle);

    if (read_size != file_size) {
        CT_LOG_RUN_ERR("[BACKUP] file %s, read size %d, file size %lld.",
            keyfile_name, read_size, file_size);
        return CT_ERROR;
    }

    if (cm_file_exist(keyfile_name)) {
        if (cm_remove_file(keyfile_name) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BACKUP] failed to remove building key file %s", keyfile_name);
            return CT_ERROR;
        }
    }

    CT_LOG_DEBUG_INF("[BACKUP] prepare key file");
    return CT_SUCCESS;
}

status_t bak_write_to_write_buf(bak_context_t *ctx, const void *buf, int32 size)
{
    bak_t *bak = &ctx->bak;
    bak_buf_t *send_buf = &bak->send_buf;

    if (bak_wait_write(bak) != CT_SUCCESS) {
        return CT_ERROR;
    }

    knl_panic(size > 0);
    errno_t ret = memcpy_sp(bak->backup_buf, BACKUP_BUFFER_SIZE(bak), buf, size);
    knl_securec_check(ret);
    send_buf->buf = bak->backup_buf;
    send_buf->buf_size = (uint32)size;
    CM_MFENCE;
    send_buf->offset = 0;
    CT_LOG_DEBUG_INF("[BACKUP] prepare data, size %u", size);
    return CT_SUCCESS;
}

void bak_read_prepare(knl_session_t *session, bak_process_t *process, datafile_t *datafile, uint32 sec_id)
{
    bak_context_t *bkup_ctx = &session->kernel->backup_ctx;
    bak_t *bak = &bkup_ctx->bak;
    bak_assignment_t *assign_ctrl = &process->assign_ctrl;
    bak_ctrl_t *ctrl = &process->ctrl;
    build_progress_t *build_progress = &bak->progress.build_progress;

    errno_t ret = strcpy_sp(ctrl->name, CT_FILE_NAME_BUFFER_SIZE, datafile->ctrl->name);
    knl_securec_check(ret);
    ctrl->type = datafile->ctrl->type;

    if (BAK_IS_FULL_BUILDING(bak) && bak->need_check) {
        CT_LOG_RUN_INF("[BUILD] reset ctrl offset for break-point building");
        ctrl->offset = build_progress->data_offset;
        bak->need_check = CT_FALSE;
    } else {
        ctrl->offset = DEFAULT_PAGE_SIZE(session);
    }

    assign_ctrl->start = ctrl->offset;
    assign_ctrl->end = ctrl->offset;
    assign_ctrl->file_id = datafile->ctrl->id;
    assign_ctrl->sec_id = sec_id;
    assign_ctrl->type = ctrl->type;

    process->total_read_size = 0;
    process->page_filter_num = 0;

    bak_record_new_file(bak, BACKUP_DATA_FILE, assign_ctrl->file_id, sec_id, 0, CT_FALSE, 0, 0);
}

status_t bak_deal_datafile_pages_read(knl_session_t *session, bak_process_t *bak_proc, bool32 to_disk)
{
    bak_ctrl_t *ctrl = &bak_proc->ctrl;
    timeval_t tv_begin;

    if (to_disk && bak_proc->write_deal == CT_TRUE) {
        bak_proc->read_buf->write_deal = CT_TRUE;
        return CT_SUCCESS;
    }
#ifndef WIN32
    if (bak_need_decompress(session, bak_proc)) {
        if (bak_decompress_and_verify_datafile(session, bak_proc, bak_proc->read_buf)) {
            return CT_ERROR;
        }
    } else {
        cantian_record_io_stat_begin(IO_RECORD_EVENT_BAK_CHECKSUM, &tv_begin);
        if (bak_verify_datafile_checksum(session, bak_proc, ctrl->offset,
                                         ctrl->name, bak_proc->read_buf) != CT_SUCCESS) {
            cantian_record_io_stat_end(IO_RECORD_EVENT_BAK_CHECKSUM, &tv_begin, IO_STAT_FAILED);
            return CT_ERROR;
        }
        cantian_record_io_stat_end(IO_RECORD_EVENT_BAK_CHECKSUM, &tv_begin, IO_STAT_SUCCESS);
    }
#endif
    cantian_record_io_stat_begin(IO_RECORD_EVENT_BAK_FILTER, &tv_begin);
    bak_filter_pages(session, bak_proc, bak_proc->read_buf);
    cantian_record_io_stat_end(IO_RECORD_EVENT_BAK_FILTER, &tv_begin, IO_STAT_SUCCESS);
    bak_proc->read_buf->write_deal = CT_FALSE;
    bak_proc->read_buf->data_size = bak_proc->write_size;
    return CT_SUCCESS;
}

status_t bak_write_datafile(bak_process_t *bak_proc, bak_context_t *bak_ctx, bool32 to_disk)
{
    if (to_disk) {
        bak_set_read_done(&bak_proc->backup_rw_buf);
    } else {
        if (bak_write_to_write_buf(bak_ctx, bak_proc->read_buf, bak_proc->write_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

void bak_write_datafile_wait(bak_process_t *bak_proc, bak_context_t *bak_ctx, bool32 to_disk)
{
    bak_t *bak = &bak_ctx->bak;
    if (to_disk) {
        bak_wait_write_finish(&bak_proc->backup_rw_buf, bak_proc);
        bak_proc->read_execute = CT_FALSE;
    } else {
        if (bak_proc->read_failed) {
            return;
        }
        if (bak_wait_write(bak) != CT_SUCCESS) {
            bak_proc->read_failed = CT_TRUE;
        }
    }
    return;
}

status_t bak_read_end_check(knl_session_t *session, bak_process_t *bak_proc)
{
    if (bak_proc->read_failed || bak_proc->write_failed) {
        CT_LOG_RUN_INF("[BACKUP] fail to backup datafile %s", bak_proc->ctrl.name);
        return CT_ERROR;
    }

    bak_t *bak = &session->kernel->backup_ctx.bak;
    bak_assignment_t *assign_ctrl = &bak_proc->assign_ctrl;
    bool32 contains_dw = bak_datafile_contains_dw(session, assign_ctrl);
    uint64 skip_size = 0;
    if (assign_ctrl->sec_id == 0) {
        if (contains_dw) {
            skip_size = (DW_SPC_HWM_START - 1) * DEFAULT_PAGE_SIZE(session);
        } else {
            skip_size = DEFAULT_PAGE_SIZE(session);
        }
    }
    if (bak_proc->total_read_size != assign_ctrl->section_end - assign_ctrl->section_start - skip_size) {
        CT_LOG_RUN_ERR("[BACKUP] total read size %llu, section start %llu, section end %llu, bak file id %u",
            bak_proc->total_read_size, assign_ctrl->section_start, assign_ctrl->section_end, assign_ctrl->bak_index);
        return CT_ERROR;
    }
    if (bak->record.attr.compress == COMPRESS_NONE && bak->encrypt_info.encrypt_alg == ENCRYPT_NONE) {
        if (bak_proc->page_filter_num * DEFAULT_PAGE_SIZE(session) !=
            bak_proc->total_read_size - assign_ctrl->bak_file.size) {
            CT_LOG_RUN_ERR("[BACKUP] total read size %llu, page filter num %llu, bak file size %llu, id %u",
                bak_proc->total_read_size, bak_proc->page_filter_num,
                assign_ctrl->bak_file.size, assign_ctrl->bak_index);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

// adjust the page processing thread based on the read/write time ratio
void bak_set_write_deal(bak_process_t *bak_proc)
{
    if (bak_proc->stat.read_time > bak_proc->stat.write_time * BAK_RW_TIME_THRESHOLD) {
        bak_proc->write_deal = CT_TRUE;
    } else {
        bak_proc->write_deal = CT_FALSE;
    }
    return;
}

status_t bak_read_datafile(knl_session_t *session, bak_process_t *bak_proc, bool32 to_disk)
{
    bak_context_t *bak_ctx = &session->kernel->backup_ctx;
    bak_t *bak = &bak_ctx->bak;
    bak_assignment_t *assign_ctrl = &bak_proc->assign_ctrl;
    bak_ctrl_t *ctrl = &bak_proc->ctrl;
    uint64 curr_offset = ctrl->offset;
    date_t start;
    if (cm_open_device(ctrl->name, ctrl->type, knl_io_flag(session), &ctrl->handle) != CT_SUCCESS) {
        return CT_ERROR;
    }
    bak_set_write_deal(bak_proc);
    CT_LOG_RUN_INF("[BACKUP] start backup datafile %s, write deal %u", ctrl->name, bak_proc->write_deal);
    bak_proc->read_execute = CT_TRUE;
    while (!bak->failed && !bak_proc->write_failed) {
        if (ctrl->offset == assign_ctrl->file_size) {
            break;
        }
        if (bak_get_read_buf(&bak_proc->backup_rw_buf, &bak_proc->read_buf) != CT_SUCCESS) {
            cm_sleep(1);
            continue;
        }
        start = g_timer()->now;
        if (bak_read_datafile_pages(session, bak_proc) != CT_SUCCESS) {
            bak_proc->read_failed = CT_TRUE;
            break;
        }
        if (bak_deal_datafile_pages_read(session, bak_proc, to_disk) != CT_SUCCESS) {
            bak_proc->read_failed = CT_TRUE;
            break;
        }
        bak_proc->stat.read_time += (g_timer()->now - start);
        bak_proc->stat.read_size += (ctrl->offset - curr_offset);
        curr_offset = ctrl->offset;
        if (bak_proc->read_buf->data_size == 0) {
            continue;
        }
        if (bak_write_datafile(bak_proc, bak_ctx, to_disk) != CT_SUCCESS) {
            bak_proc->read_failed = CT_TRUE;
            break;
        }
    }
    bak_write_datafile_wait(bak_proc, bak_ctx, to_disk);
    CT_LOG_RUN_INF("[BACKUP] end backup datafile %s, read time [%lld], write time [%lld], file size %lld",
        assign_ctrl->bak_file.name, bak_proc->stat.read_time, bak_proc->stat.write_time, assign_ctrl->bak_file.size);
    cm_close_device(ctrl->type, &ctrl->handle);
    return bak_read_end_check(session, bak_proc);
}

status_t bak_wait_ctrlfiles_ready(bak_t *bak)
{
    while (!bak->ctrlfile_completed) {
        if (bak->failed) {
            return CT_ERROR;
        }
        cm_sleep(1);
    }
    return CT_SUCCESS;
}

status_t bak_stream_read_datafile(knl_session_t *session, bak_process_t *process, datafile_ctrl_t *df_ctrl,
    uint64 data_size, uint32 hwm_start)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    bak_assignment_t *assign_ctrl = &process->assign_ctrl;
    bak_stream_buf_t *stream_buf = &bak->send_stream;
    char *path = bak->record.path;

    if (bak_wait_ctrlfiles_ready(bak) != CT_SUCCESS) {
        return CT_ERROR;
    }
    bak_init_send_stream(bak, DEFAULT_PAGE_SIZE(session), assign_ctrl->file_size, assign_ctrl->file_id);

    if (bak->encrypt_info.encrypt_alg != ENCRYPT_NONE) {
        if (bak_encrypt_rand_iv(&bak->files[bak->curr_file_index]) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    bak->backup_size = 0;
    uint32 start_type = bak_get_package_type(bak->files[bak->curr_file_index].type);
    if (bak_agent_file_start(bak, path, start_type, bak->files[bak->curr_file_index].id) != CT_SUCCESS) {
        return CT_ERROR;
    }
    bak->remote.remain_data_size = 0;

    bak_assign_stream_backup_task(session, df_ctrl->type, df_ctrl->name, CT_FALSE, df_ctrl->id, data_size, hwm_start);
    if (bak_send_stream_data(session, bak, assign_ctrl) != CT_SUCCESS) {
        return CT_ERROR;
    }

    bak_wait_paral_proc(session, CT_FALSE);
    if (bak_stream_send_end(bak, stream_buf) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t bak_read_datafiles(knl_session_t *session, bak_process_t *process)
{
    bak_context_t *bkup_ctx = &session->kernel->backup_ctx;
    bak_t *bak = &bkup_ctx->bak;
    bak_assignment_t *assign_ctrl = &process->assign_ctrl;
    build_progress_t *build_progress = &bak->progress.build_progress;
    bak_ctrl_t *ctrl = &process->ctrl;
    bak_stage_t *stage = &bak->progress.build_progress.stage;

    if (BAK_IS_FULL_BUILDING(bak) && bak_get_build_stage(stage) > BUILD_DATA_STAGE) {
        CT_LOG_RUN_INF("[BUILD] ignore read datafiles for break-point building");
        return CT_SUCCESS;
    }

    if (bak_check_datafiles_num(session, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    uint64 data_size = db_get_datafiles_used_size(session);
    bak_set_progress(session, BACKUP_DATA_STAGE, data_size);
    if (bak_paral_task_enable(session) && !BAK_IS_STREAM_READING(bkup_ctx)) {
        if (bak_get_section_threshold(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (bak_check_datafiles_num(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (BAK_IS_FULL_BUILDING(bak) && !bak->is_first_link) {
        CT_LOG_RUN_INF("[BUILD] bak->is_first_link : %u", bak->is_first_link);
        assign_ctrl->file_id = build_progress->file_id;
        ctrl->offset = build_progress->data_offset;
    } else {
        assign_ctrl->file_id = 0;
    }

    while (!bak->failed) {
        datafile_t *datafile = db_get_next_datafile(session, &assign_ctrl->file_id, &assign_ctrl->file_size,
            &assign_ctrl->file_hwm_start);
        if (datafile == NULL) {
            break;
        }

        if (bak->target_info.target == TARGET_ALL && bak->exclude_spcs[datafile->space_id]) {
            assign_ctrl->file_id = datafile->ctrl->id + 1;
            continue;
        }

        if (bak->target_info.target == TARGET_TABLESPACE && !bak->include_spcs[datafile->space_id]) {
            assign_ctrl->file_id = datafile->ctrl->id + 1;
            continue;
        }

        if (bak_check_bak_device(bak, datafile, assign_ctrl) != CT_SUCCESS) {
            return CT_ERROR;
        }

        // keep the sec num same, so paral log bak can get correct slot number before data backup operation.
        bak_try_reset_file_size(bak, assign_ctrl);
        data_size = assign_ctrl->file_size;
        CT_LOG_DEBUG_INF("[BACKUP] backup datafile %u, size %lluKB name %s",
                         assign_ctrl->file_id, data_size / SIZE_K(1), datafile->ctrl->name);
        if (bak_paral_task_enable(session)) {
            if (BAK_IS_STREAM_READING(bkup_ctx)) {
                bak_read_prepare(session, process, datafile, 0);
                if (bak_stream_read_datafile(session, process, datafile->ctrl, data_size,
                    assign_ctrl->file_hwm_start) != CT_SUCCESS) {
                    return CT_ERROR;
                }
            } else {
                if (bak_paral_backup_datafile(session, assign_ctrl, datafile, data_size) != CT_SUCCESS) {
                    return CT_ERROR;
                }
            }
        } else {
            bak_read_prepare(session, process, datafile, 0);
            if (bak_read_datafile(session, process, CT_FALSE) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
        assign_ctrl->file_id = datafile->ctrl->id + 1;
    }

    bak_wait_paral_proc(session, CT_FALSE);
    return (bak->failed) ? CT_ERROR : CT_SUCCESS;
}

bool32 bak_logfile_not_backed(knl_session_t *session, uint32 asn)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    bak_progress_t *progress = &bak->progress;
    bool32 bak_done = CT_FALSE;

    cm_spin_lock(&progress->lock, NULL);
    if (progress->stage == BACKUP_DATA_STAGE || progress->stage == BACKUP_LOG_STAGE) {
        if (asn >= bak->arch_stat.start_asn && (asn - bak->arch_stat.start_asn) < BAK_MAX_FILE_NUM) {
            bak_done = bak->arch_stat.bak_done[asn - bak->arch_stat.start_asn];
        } else if (asn < bak->arch_stat.start_asn) {
            bak_done = CT_TRUE;
        } else {
            bak_done = CT_FALSE;
        }
    }
    cm_spin_unlock(&progress->lock);

    return !bak_done;
}

static void bak_set_logfile_backed(knl_session_t *session, uint32 asn)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;

    if (asn >= bak->arch_stat.start_asn && (asn - bak->arch_stat.start_asn) < BAK_MAX_FILE_NUM) {
        bak->arch_stat.bak_done[asn - bak->arch_stat.start_asn] = CT_TRUE;
    } else {
        CT_LOG_RUN_ERR("[BACKUP] failed to refresh logfile bakcup status for asn %u, start asn is %u",
            asn, bak->arch_stat.start_asn);
    }
}

status_t bak_verify_log_head_checksum(knl_session_t *session, bak_process_t *bak_proc, bak_ctrl_t *ctrl,
    log_file_head_t *head, int32 head_len)
{
    ctrl->offset = 0;
    if (bak_read_data(bak_proc, ctrl, head, head_len) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (log_verify_head_checksum(session, head, ctrl->name) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void bak_calc_log_head_checksum(knl_session_t *session, bak_assignment_t *assign_ctrl, log_file_head_t *head)
{
    if (assign_ctrl->file_size > 0) {
        head->write_pos = assign_ctrl->file_size;
        log_calc_head_checksum(session, head);
    }
    return;
}

status_t bak_read_logfile_with_proc(bak_process_t *bak_proc, bak_ctrl_t *ctrl, log_file_head_t *buf, int32 size)
{
    status_t status;
    timeval_t tv_begin;

    cantian_record_io_stat_begin(IO_RECORD_EVENT_BAK_READ_LOG, &tv_begin);
    SYNC_POINT_GLOBAL_START(CANTIAN_BACKUP_READ_LOG_FROM_ARCH_FAIL, &status, CT_ERROR);
    status = bak_read_data(bak_proc, ctrl, buf, size);
    SYNC_POINT_GLOBAL_END;
    cantian_record_io_stat_end(IO_RECORD_EVENT_BAK_READ_LOG, &tv_begin, IO_RECORD_STAT_RET(status));
    return status;
}

status_t bak_write_logfile_with_proc(bak_context_t *ctx, bak_process_t *bak_proc, char *buf, int32 size,
    bool32 arch_compressed)
{
    status_t status;
    timeval_t tv_begin;
    bool32 stream_end = CT_FALSE;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_BAK_WRITE_LOCAL, &tv_begin);
    SYNC_POINT_GLOBAL_START(CANTIAN_BACKUP_WRITE_LOG_TO_FILE_FAIL, &status, CT_ERROR);
    status = bak_write_to_local_disk(ctx, bak_proc, buf, size, stream_end, arch_compressed);
    SYNC_POINT_GLOBAL_END;
    cantian_record_io_stat_end(IO_RECORD_EVENT_BAK_WRITE_LOCAL, &tv_begin, IO_RECORD_STAT_RET(status));
    return status;
}

status_t bak_read_logfile(knl_session_t *session, bak_context_t *ctx, bak_process_t *bak_proc,
    uint32 block_size, bool32 to_disk, bool32 *arch_compressed)
{
    bak_assignment_t *assign_ctrl = &bak_proc->assign_ctrl;
    bak_ctrl_t *ctrl = &bak_proc->ctrl;
    char *backup_buf = bak_proc->backup_buf.aligned_buf;
    log_file_head_t *head = (log_file_head_t *)backup_buf;
    bak_local_t *bak_file = &bak_proc->assign_ctrl.bak_file;
    bak_t *bak = &session->kernel->backup_ctx.bak;
    status_t status = CT_ERROR;

    int32 read_size = CM_CALC_ALIGN(sizeof(log_file_head_t), block_size);
    if (bak_verify_log_head_checksum(session, bak_proc, ctrl, head, read_size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // write_pos is inaccurate when we try to backup online logfile
    // Need to correct it using file size we stored in assign ctrl
    // using in-memory write_pos when calling bak_set_log_ctrl
    bak_calc_log_head_checksum(session, assign_ctrl, head);
    
    *arch_compressed = (head->cmp_algorithm != COMPRESS_NONE);
    uint64 file_size = *arch_compressed ? (uint64)cm_device_size(ctrl->type, ctrl->handle) : head->write_pos;
    CT_LOG_RUN_INF("[BACKUP] prepare %s log %s, size %llu ",
        bak_file->name, *arch_compressed ? "compressed" : "non-compressed", file_size);

    if (to_disk) {
        if (bak_local_write(bak_file, backup_buf, read_size, bak, bak_file->size) != CT_SUCCESS) {  // do not compress
                                                                                                    // log head
            return CT_ERROR;
        }
        bak_file->size += read_size;
        bak_update_progress(bak, (uint64)read_size);
        if (bak_write_lz4_compress_head(bak, bak_proc, bak_file) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (bak_write_to_write_buf(ctx, backup_buf, read_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    knl_panic(file_size >= (uint32)read_size);
    uint64 data_size = file_size - read_size;
    while (!bak->failed && data_size > 0) {
        /* when data_size > 8M, read_size = 8M, can not overflow */
        read_size = data_size > BACKUP_BUFFER_SIZE(bak) ? (int32)BACKUP_BUFFER_SIZE(bak) : (int32)data_size;
        status = bak_read_logfile_with_proc(bak_proc, ctrl, (log_file_head_t *)backup_buf, read_size);
        if (status != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (to_disk) {
            status = bak_write_logfile_with_proc(ctx, bak_proc, backup_buf, read_size, *arch_compressed);
        } else {
            status = bak_write_to_write_buf(ctx, backup_buf, read_size);
        }

        if (status != CT_SUCCESS) {
            return CT_ERROR;
        }

        data_size -= read_size;
    }

    /* logfile backed flag used for determining to clean arch log when backup full database */
    if (bak->target_info.target != TARGET_ARCHIVE) {
        bak_set_logfile_backed(session, assign_ctrl->log_asn);
    }

    CT_LOG_DEBUG_INF("[BACKUP] finish %s with size %llu ",
        bak_file->name, (uint64)cm_device_size(bak_file->type, bak_file->handle));
    return CT_SUCCESS;
}

static status_t bak_get_start_asn(knl_session_t *session, uint32 *start_asn, uint32 last_asn)
{
    knl_instance_t *kernel = session->kernel;
    bak_t *bak = &kernel->backup_ctx.bak;
    arch_ctrl_t *start_ctrl = db_get_arch_ctrl(session, dtc_my_ctrl(session)->archived_start, session->kernel->id);

    if (bak->target_info.backup_arch_mode == ARCHIVELOG_ALL) {
        *start_asn = start_ctrl->asn;
    } else {
        *start_asn = bak->target_info.backup_begin_asn;
    }

    if (*start_asn < start_ctrl->asn || *start_asn > last_asn) {
        CT_THROW_ERROR_EX(ERR_INVALID_ARCHIVE_PARAMETER, " asn: '%d' is not in the range of archivelogs", *start_asn);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t bak_send_logfile_head(knl_session_t *session, bak_process_t *proc, uint32 block_size,
                               uint64 *file_size)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    char *backup_buf = proc->backup_buf.aligned_buf;
    log_file_head_t *head = (log_file_head_t *)backup_buf;
    bak_assignment_t *assign_ctrl = &proc->assign_ctrl;
    int32 read_size = CM_CALC_ALIGN(sizeof(log_file_head_t), block_size);
    bak_ctrl_t *ctrl = &proc->ctrl;

    ctrl->offset = 0;
    if (bak_read_data(proc, ctrl, head, read_size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (log_verify_head_checksum(session, head, ctrl->name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (assign_ctrl->file_size > 0) {
        head->write_pos = assign_ctrl->file_size;
        log_calc_head_checksum(session, head);
    }

    *file_size = head->write_pos;
    bool32 arch_compressed = (head->cmp_algorithm != COMPRESS_NONE);
    *file_size = arch_compressed ? (uint64)cm_device_size(ctrl->type, ctrl->handle) : head->write_pos;
    CT_LOG_RUN_INF("[BACKUP] prepare log, size %lluKB", *file_size / SIZE_K(1));

    if (bak_agent_write(bak, backup_buf, read_size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    bak_update_progress(bak, read_size);
    return CT_SUCCESS;
}

status_t bak_stream_read_logfile(knl_session_t *session, bak_process_t *proc, uint32 block_size, bool32 arch_compressed)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    bak_stream_buf_t *stream = &bak->send_stream;
    bak_assignment_t *assign_ctrl = &proc->assign_ctrl;
    char *path = bak->record.path;
    uint64 file_size = 0;

    if (bak_wait_ctrlfiles_ready(bak) != CT_SUCCESS) {
        return CT_ERROR;
    }
    bak->backup_size = 0;

    if (bak->encrypt_info.encrypt_alg != ENCRYPT_NONE) {
        if (bak_encrypt_rand_iv(&bak->files[bak->curr_file_index]) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    uint32 start_type = bak_get_package_type(bak->files[bak->curr_file_index].type);
    if (bak_agent_file_start(bak, path, start_type, bak->files[bak->curr_file_index].id) != CT_SUCCESS) {
        return CT_ERROR;
    }
    bak->remote.remain_data_size = 0;

    if (bak_send_logfile_head(session, proc, block_size, &file_size) != CT_SUCCESS) {
        return CT_ERROR;
    }
    assign_ctrl->file_size = file_size;

    bak_init_send_stream(bak, CM_CALC_ALIGN(sizeof(log_file_head_t), block_size), assign_ctrl->file_size,
        assign_ctrl->file_id);

    bak_assign_stream_backup_task(session, proc->ctrl.type, proc->ctrl.name, arch_compressed,
        assign_ctrl->file_id, file_size, 0);
    if (bak_send_stream_data(session, bak, assign_ctrl) != CT_SUCCESS) {
        return CT_ERROR;
    }

    bak_wait_paral_proc(session, CT_FALSE);
    if (bak_stream_send_end(bak, stream) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t bak_get_logfiles_used_size(knl_session_t *session, uint32 curr_asn_input, uint32 last_asn,
                                           uint64 *data_size)
{
    uint32 curr_asn = curr_asn_input;
    database_t *db = &session->kernel->db;
    reset_log_t rst_log = db->ctrl.core.resetlogs;
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;

    for (; curr_asn <= last_asn; curr_asn++) {
        uint32 rst_id = bak_get_rst_id(bak, curr_asn, &(rst_log));
        uint32 file_id = bak_log_get_id(session, bak->record.data_type, rst_id, curr_asn);
        if (file_id == CT_INVALID_ID32) {
            arch_ctrl_t *arch_ctrl = arch_get_archived_log_info(session, rst_id, curr_asn, ARCH_DEFAULT_DEST,
                                                                session->kernel->id);
            if (arch_ctrl == NULL) {
                CT_LOG_RUN_ERR("[BACKUP] failed to get archived log for [%u-%u]", rst_id, curr_asn);
                CT_THROW_ERROR(ERR_FILE_NOT_EXIST, "archive log", "for backup");
                return CT_ERROR;
            }
            *data_size += (uint64)arch_get_ctrl_real_size(arch_ctrl);
        } else {
            log_file_t *file = &MY_LOGFILE_SET(session)->items[file_id];
            *data_size += file->head.write_pos;
            log_unlatch_file(session, file_id);
        }
    }
    return CT_SUCCESS;
}

status_t bak_get_arch_start_and_end_point(knl_session_t *session, uint32 *start_asn, uint32 *end_asn)
{
    knl_instance_t *kernel = session->kernel;
    bak_context_t *ctx = &kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;

    if (BAK_IS_DBSOTR(bak)) {
        // point is [rcy_point.lsn, lrp_point.lsn]
        status_t status = arch_lsn_asn_convert(session, bak->record.ctrlinfo.rcy_point.lsn, start_asn);
        if (status != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BACKUP] can not find start asn");
            return status;
        }
        if (session->kernel->attr.clustered) {
            status = arch_lsn_asn_convert(session, bak->max_lrp_lsn, end_asn);
        } else {
            status = arch_lsn_asn_convert(session, bak->record.ctrlinfo.lrp_point.lsn, end_asn);
        }
        if (status != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BACKUP] can not find start asn");
            return status;
        }
        CT_LOG_RUN_INF("[BACKUP] get arch start asn %u end asn %u instid %u", *start_asn, *end_asn, kernel->id);
    } else {
        *start_asn = ctrlinfo->rcy_point.asn;
        if (bak_fetch_last_log(session, bak, end_asn) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BACKUP] fetch last log failed");
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

bool32 bak_point_need_archfile(knl_session_t *session, bak_t *bak, uint32 node_id)
{
    if (!BAK_IS_DBSOTR(bak)) {
        return CT_TRUE;
    }
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;
    if (!session->kernel->attr.clustered) {
        return log_cmp_point_lsn(&ctrlinfo->rcy_point, &ctrlinfo->lrp_point) != 0;
    }

    log_point_t lrp_point = ctrlinfo->dtc_lrp_point[node_id];
    log_point_t rcy_point = ctrlinfo->dtc_rcy_point[node_id];
    if (log_cmp_point_lsn(&rcy_point, &lrp_point) != 0) {
        return CT_TRUE;
    } else {
        for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
            if (i == node_id) {
                continue;
            }
            if (log_cmp_point_lsn(&lrp_point, &ctrlinfo->dtc_lrp_point[i]) < 0 &&
                log_cmp_point_lsn(&ctrlinfo->dtc_rcy_point[i], &ctrlinfo->dtc_lrp_point[i]) != 0) {
                return CT_TRUE;
            }
        }
    }
    return CT_FALSE;
}

static bool32 bak_read_log_check_param(knl_session_t *session, uint32 *start_asn)
{
    knl_instance_t *kernel = session->kernel;
    bak_context_t *ctx = &kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_stage_t *stage = &bak->progress.build_progress.stage;
    uint32 arch_num;

    if (BAK_IS_FULL_BUILDING(bak) && bak_get_build_stage(stage) > BUILD_LOG_STAGE) {
        CT_LOG_RUN_INF("[BUILD] ignore read logfiles for break-point building");
        return CT_FALSE;
    }

    if (bak_point_need_archfile(session, bak, bak->inst_id) == CT_FALSE) {
        CT_LOG_RUN_INF("[BACKUP] current node no need to backup arch file");
        if (bak_paral_task_enable(session)) {
            /* parallel backup dose not enter bak_write_end, need update curr_file_index here */
            bak->curr_file_index = bak->file_count;
        }
        return CT_FALSE;
    }

    arch_get_files_num(session, ARCH_DEFAULT_DEST, bak->inst_id, &arch_num);
    if (arch_num == 0 && log_cmp_point_lsn(&bak->record.ctrlinfo.rcy_point, &bak->record.ctrlinfo.lrp_point) == 0) {
        CT_LOG_RUN_INF("[BACKUP] current node no arch file to backup");
        if (bak_paral_task_enable(session)) {
            bak->curr_file_index = bak->file_count;
        }
        return CT_FALSE;
    }

    return CT_TRUE;
}

static status_t bak_get_log_ctrl_info(knl_session_t *session, bak_process_t *proc, uint32 curr_asn,
                                      uint32 *block_size, bool32 *arch_compressed)
{
    if (bak_need_wait_arch(session)) {
        CT_LOG_DEBUG_INF("[BACKUP] start ctrl operation: set archived log only");
        if (bak_set_archived_log_ctrl(session, proc, curr_asn, block_size, arch_compressed, CT_FALSE) !=
            CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        CT_LOG_DEBUG_INF("[BACKUP] start ctrl operation: set online log priority");
        if (bak_set_log_ctrl(session, proc, curr_asn, block_size, arch_compressed) != CT_SUCCESS) {
            bak_unlatch_logfile_if_necessary(session, proc);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

static status_t bak_read_logfile_data(knl_session_t *session, bak_process_t *proc, uint32 block_size,
                                      bool32 arch_compressed)
{
    knl_instance_t *kernel = session->kernel;
    bak_context_t *ctx = &kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    status_t status = CT_SUCCESS;

    if (bak_paral_task_enable(session)) {
        if (BAK_IS_STREAM_READING(ctx)) {
            status = bak_stream_read_logfile(session, proc, block_size, arch_compressed);
            bak_unlatch_logfile_if_necessary(session, proc);
            cm_close_device(proc->ctrl.type, &proc->ctrl.handle);
            if (status != CT_SUCCESS) {
                return CT_ERROR;
            }
        } else {
            if (bak_assign_backup_task(session, proc, 0, CT_FALSE) != CT_SUCCESS) {
                bak_unlatch_logfile_if_necessary(session, proc);
                cm_close_device(proc->ctrl.type, &proc->ctrl.handle);
                return CT_ERROR;
            }
        }
    } else {
        bool32 arch_compressed_bak = CT_FALSE;
        status = bak_read_logfile(session, ctx, proc, block_size, CT_FALSE, &arch_compressed_bak);
        bak_unlatch_logfile_if_necessary(session, proc);
        cm_close_device(proc->ctrl.type, &proc->ctrl.handle);
        if (status != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (bak_wait_write(bak) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

// todo xjl
static status_t bak_read_logfiles(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    bak_context_t *ctx = &kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;
    uint32 curr_asn = (uint32)ctrlinfo->rcy_point.asn;
    bak_process_t *proc = &ctx->process[BAK_COMMON_PROC];
    uint32 last_asn = 0;
    uint64 data_size = 0;
    uint32 block_size;
    bool32 arch_compressed = CT_FALSE;

    bak->inst_id = g_dtc->profile.inst_id;
    if (bak_read_log_check_param(session, &curr_asn) == CT_FALSE) {
        return CT_SUCCESS;
    }

    if (bak_get_arch_start_and_end_point(session, &curr_asn, &last_asn) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] get log start and end log failed");
        return CT_ERROR;
    }
    
    if (BAK_IS_FULL_BUILDING(bak) && bak_get_build_stage(&bak->progress.build_progress.stage) == BUILD_LOG_STAGE) {
        CT_LOG_RUN_INF("[BUILD] break-point condition, curr asn : %u", bak->progress.build_progress.asn);
        curr_asn = (uint32)bak->progress.build_progress.asn;
    }

    if (bak->target_info.target == TARGET_ARCHIVE) {
        if (bak_get_start_asn(session, &curr_asn, last_asn) != CT_SUCCESS) {
            return CT_ERROR;
        }

        ctrlinfo->rcy_point.asn = curr_asn;
        ctrlinfo->lrp_point.asn = last_asn;

        bak->send_buf.buf_size = CT_INVALID_ID32;
        bak->send_buf.offset = CT_INVALID_ID32;
    }
    knl_panic(last_asn >= curr_asn);

    bak_try_wait_paral_log_proc(bak);
    // update curr_asn &bak info in paral log bak condition
    if (bak_try_merge_bak_info(bak, last_asn, &curr_asn) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (bak_get_logfiles_used_size(session, curr_asn, last_asn, &data_size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    bak_set_progress(session, BACKUP_LOG_STAGE, data_size);
    for (; curr_asn <= last_asn; curr_asn++) {
        if (curr_asn == last_asn && !BAK_IS_DBSOTR(bak)) {
            if (bak_switch_logfile(session, last_asn, CT_TRUE) != CT_SUCCESS) {
                return CT_ERROR;
            }
            if (bak_equal_last_asn(session, last_asn)) {
                break;
            }
        }
        if (bak_paral_task_enable(session) && !BAK_IS_STREAM_READING(ctx)) {
            if (bak_get_free_proc(session, &proc, CT_FALSE) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
        if (bak_get_log_ctrl_info(session, proc, curr_asn, &block_size, &arch_compressed) != CT_SUCCESS) {
            return CT_ERROR;
        }
        proc->assign_ctrl.log_block_size = block_size;
        if (bak_read_logfile_data(session, proc, block_size, arch_compressed) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    bak_wait_paral_proc(session, CT_FALSE);
    if (bak_paral_task_enable(session)) {
        /* parallel backup dose not enter bak_write_end, need update curr_file_index here */
        bak->curr_file_index = bak->file_count;
    }
    return CT_SUCCESS;
}

static void bak_set_config_param(knl_session_t *session, char *buf)
{
    errno_t ret = memset_sp(buf, CT_MAX_CONFIG_LINE_SIZE, 0, CT_MAX_CONFIG_LINE_SIZE);
    knl_securec_check(ret);
    char *param = cm_get_config_value(session->kernel->attr.config, "CONTROL_FILES");
    knl_panic(param != NULL);
    size_t param_len = strlen(param) + 1;
    ret = memcpy_sp(buf, CT_MAX_CONFIG_LINE_SIZE, param, param_len);
    knl_securec_check(ret);
}

status_t bak_read_param(knl_session_t *session)
{
    bak_context_t *backup_ctx = &session->kernel->backup_ctx;
    bak_t *bak = &backup_ctx->bak;
    bak_process_t *process = &backup_ctx->process[BAK_COMMON_PROC];
    bak_buf_t *send_buf = &bak->send_buf;

    CT_LOG_RUN_INF("[BUILD] read param for building of first link");

    bak_set_progress(session, BACKUP_PARAM_STAGE, CT_MAX_CONFIG_LINE_SIZE);
    bak_set_config_param(session, process->backup_buf.aligned_buf);

    send_buf->buf = process->backup_buf.aligned_buf;
    send_buf->buf_size = CT_MAX_CONFIG_LINE_SIZE;
    send_buf->offset = 0;

    if (bak_wait_write(bak) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static void bak_build_head(knl_session_t *session, bak_head_t *head)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    core_ctrl_t *core = &session->kernel->db.ctrl.core;
    bak_attr_t *attr = &bak->record.attr;
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;

    head->version.major_ver = BAK_VERSION_MAJOR;
    head->version.min_ver = BAK_VERSION_MIN;
    head->version.magic = BAK_VERSION_MAGIC;

    head->attr.backup_type = attr->backup_type;
    errno_t ret = strcpy_sp(head->attr.tag, CT_NAME_BUFFER_SIZE, attr->tag);
    knl_securec_check(ret);

    head->attr.base_lsn = attr->base_lsn;
    ret = strcpy_sp(head->attr.base_tag, CT_NAME_BUFFER_SIZE, attr->base_tag);
    knl_securec_check(ret);

    head->attr.level = attr->level;
    head->attr.compress = attr->compress;
    head->file_count = bak->is_building ? 0 : bak->file_count - 1;

    head->ctrlinfo.rcy_point = ctrlinfo->rcy_point;
    head->ctrlinfo.lrp_point = ctrlinfo->lrp_point;
    head->ctrlinfo.scn = ctrlinfo->scn;
    head->ctrlinfo.lsn = ctrlinfo->lsn;
    head->ddl_pitr_lsn = DB_CURR_LSN(session);
    CT_LOG_RUN_INF("[BACKUP] head ddl pitr lsn %llu", head->ddl_pitr_lsn);

    head->depend_num = bak->depend_num;
    head->start_time = bak->record.start_time;
    head->completion_time = bak->record.completion_time;
    head->encrypt_info.encrypt_alg = bak->encrypt_info.encrypt_alg;
    head->log_fisrt_slot = bak->log_first_slot;

    if (head->encrypt_info.encrypt_alg != ENCRYPT_NONE) {
        ret = memcpy_sp(head->encrypt_info.salt, CT_KDF2SALTSIZE, bak->encrypt_info.salt, CT_KDF2SALTSIZE);
        knl_securec_check(ret);

        ret = strncpy_sp(head->sys_pwd, CT_PASSWORD_BUFFER_SIZE, bak->sys_pwd, strlen(bak->sys_pwd));
        knl_securec_check(ret);
    }

    head->db_id = core->dbid;
    head->db_role = core->db_role;
    head->db_init_time = core->init_time;
    ret = strcpy_s(head->db_name, CT_DB_NAME_LEN, core->name);
    knl_securec_check(ret);
    ret = strcpy_s(head->db_version, CT_DB_NAME_LEN, session->kernel->attr.db_version);
    knl_securec_check(ret);

    ret = memset_s(head->unused, BAK_HEAD_UNUSED_SIZE, 0, BAK_HEAD_UNUSED_SIZE);
    knl_securec_check(ret);
    head->df_struc_version = (uint32)BAK_DATAFILE_VERSION;

    if (bak->backup_buf_size >= attr->base_buffer_size) {
        head->max_buffer_size = bak->backup_buf_size;
    } else {
        head->max_buffer_size = attr->base_buffer_size;
    }

    if (session->kernel->attr.clustered) {
        for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
            head->ctrlinfo.dtc_rcy_point[i] = ctrlinfo->dtc_rcy_point[i];
            head->ctrlinfo.dtc_lrp_point[i] = ctrlinfo->dtc_lrp_point[i];
        }
    }

    bak_set_config_param(session, head->control_files);
}

static status_t bak_wait_write_finished(bak_t *bak)
{
    if (bak->is_building) {
        return CT_SUCCESS;
    }

    while (!bak->failed && bak->file_count != (bak->curr_file_index + 1)) {
        cm_sleep(1);
    }

    return bak->failed ? CT_ERROR : CT_SUCCESS;
}

static status_t bak_generate_backupset_head(knl_session_t *session, bak_context_t *ctx)
{
    bak_t *bak = &ctx->bak;
    bak_buf_t *send_buf = &bak->send_buf;
    bak_head_t *head = (bak_head_t *)ctx->process[BAK_COMMON_PROC].backup_buf.aligned_buf;
    uint64 data_size;
    bak_stage_t *stage = &bak->progress.build_progress.stage;

    if (BAK_IS_FULL_BUILDING(bak) && bak_get_build_stage(stage) > BUILD_HEAD_STAGE) {
        CT_LOG_RUN_INF("[BUILD] ignore gneerate backupset for break-point building");
        return CT_SUCCESS;
    }

    /* store key file before bak_head */
    if (bak->is_building) {
        if (bak_read_keyfile(session, (char *)head, BACKUP_BUFFER_SIZE(bak)) != CT_SUCCESS) {
            return CT_ERROR;
        }
        data_size = (uint64)sizeof(bak_head_t) + CT_KMC_MAX_KEY_SIZE;
        if (data_size > BACKUP_BUFFER_SIZE(bak)) {
            CT_LOG_RUN_ERR("[BACKUP] store keyfile befor bak_head failed.");
            return CT_ERROR;
        }
        head = (bak_head_t *)((char *)head + CT_KMC_MAX_KEY_SIZE);
    } else {
        data_size = (uint64)sizeof(bak_head_t) + (uint64)bak->file_count * sizeof(bak_file_t) +
            (uint64)bak->depend_num * sizeof(bak_dependence_t);
    }

    bak_set_progress(session, BACKUP_HEAD_STAGE, data_size);
    bak_record_new_file(bak, BACKUP_HEAD_FILE, 0, 0, 0, CT_FALSE, 0, 0); // will not save in backupset file

    if (bak_wait_write_finished(bak) != CT_SUCCESS) {
        return CT_ERROR;
    }

    bak->record.completion_time = (uint64)cm_now();
    bak_build_head(session, head);
    CT_LOG_DEBUG_INF("[BACKUP] prepare head, size %u, file count %u, tag %s",
                     (uint32)sizeof(bak_head_t), head->file_count, head->attr.tag);
    if (bak->is_building) {
        bak_calc_head_checksum(head, sizeof(bak_head_t));
        send_buf->buf = ctx->process[BAK_COMMON_PROC].backup_buf.aligned_buf;
        send_buf->buf_size = (uint32)(CT_KMC_MAX_KEY_SIZE + sizeof(bak_head_t));
        send_buf->offset = 0;

        CT_LOG_DEBUG_INF("[BACKUP] build is running, only send backup head, size %u",
            (uint32)(CT_KMC_MAX_KEY_SIZE + sizeof(bak_head_t)));
        if (bak_wait_write(bak) != CT_SUCCESS) {
            return CT_ERROR;
        }
        return CT_SUCCESS;
    }

    uint32 offset = sizeof(bak_head_t);
    uint32 send_size = (bak->file_count - 1) * sizeof(bak_file_t); /* max bak->file_count is 2048, cannot overflow */
    errno_t ret = memcpy_sp((char *)head + offset, BACKUP_BUFFER_SIZE(bak) - offset, (char *)bak->files, send_size);
    knl_securec_check(ret);
    offset += send_size;
    CT_LOG_DEBUG_INF("[BACKUP] prepare file_info, size %u", send_size);

    if (bak->depend_num > 0) {
        if (bak->depend_num > BAK_MAX_DEPEND_NUM) {
            CT_LOG_RUN_ERR("[BACKUP] depend incremental backup number too large, size %u", bak->depend_num);
            return CT_ERROR;
        }

        send_size = bak->depend_num * sizeof(bak_dependence_t);
        ret = memcpy_sp((char *)head + offset, BACKUP_BUFFER_SIZE(bak) - offset, (char *)bak->depends, send_size);
        knl_securec_check(ret);
        offset += send_size;
        CT_LOG_DEBUG_INF("[BACKUP] prepare depend, size %u", send_size);
    }

    bak_calc_head_checksum(head, offset);
    send_buf->buf = (char *)head;
    send_buf->buf_size = offset;
    send_buf->offset = 0;

    if (bak_wait_write(bak) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void bak_update_lrp_point(knl_session_t *session)
{
    if (!session->kernel->attr.clustered) {
        return;
    }
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    ctrl_page_t *pages = (ctrl_page_t *)(bak->ctrl_backup_bak_buf);
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;
    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        if (SECUREC_UNLIKELY(i == g_dtc->profile.inst_id)) {
            CT_LOG_RUN_INF("[BACKUP] node %u lrp lsn is %llu", i, ctrlinfo->dtc_lrp_point[i].lsn);
            continue;
        }
        // if previous ckpt has not been triggered
        if (ctrlinfo->dtc_lrp_point[i].lsn == 0) {
            dtc_node_ctrl_t *page_ctrl = (dtc_node_ctrl_t *)(pages[i].buf);
            ctrlinfo->dtc_lrp_point[i] = page_ctrl->lrp_point;
            bak->rcy_lsn[i] = page_ctrl->rcy_point.lsn;
        }
        CT_LOG_RUN_INF("[BACKUP] node %u rcy lsn is %llu, lrp lsn is %llu", i, bak->rcy_lsn[i], ctrlinfo->dtc_lrp_point[i].lsn);
    }
    return;
}

void bak_read_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;
    bak_process_t *process = &ctx->process[BAK_COMMON_PROC];
    bak_stage_t *stage = &bak->progress.build_progress.stage;

    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());
    while (!thread->closed && !bak->failed) {
        if (bak->is_building && bak->is_first_link && !bak->record.is_repair) {
            if (bak_read_param(session) != CT_SUCCESS) {
                bak->failed = CT_TRUE;
                break;
            }
        }

        if (!bak->record.log_only) {
            CT_LOG_RUN_INF("[BACKUP] start backup ctrl files");
            if (bak_read_ctrlfile(session) != CT_SUCCESS) {
                bak->failed = CT_TRUE;
                break;
            }
            CT_LOG_RUN_INF("[BACKUP] start backup data files");
            if (bak_read_datafiles(session, process) != CT_SUCCESS) {
                bak->failed = CT_TRUE;
                break;
            }

            if ((BAK_IS_FULL_BUILDING(bak) && bak_get_build_stage(stage) > BUILD_DATA_STAGE)) {
                CT_LOG_RUN_INF("[BACKUP] ignore set log point for break-porint building");
            } else {
                CT_LOG_RUN_INF("[BACKUP] finish datafiles reading, start set log point");
                if (bak_set_log_point(session, ctrlinfo, CT_TRUE, CT_FALSE) != CT_SUCCESS) {
                    bak->failed = CT_TRUE;
                    break;
                }
            }
        }

        if (bak->record.data_only) {
            break;
        }

        if (dtc_bak_set_lrp_point(session) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BACKUP] get node ctrl for lrp point failed!");
            bak->failed = CT_TRUE;
            break;
        }
        if (dtc_bak_handle_cluster_arch(session) != CT_SUCCESS) {
            bak->failed = CT_TRUE;
            break;
        }
        CT_LOG_RUN_INF("[BACKUP] start backup log files");
        if (bak_read_logfiles(session) != CT_SUCCESS) {
            bak->failed = CT_TRUE;
            break;
        }

        if (session->kernel->attr.clustered) {
            if (dtc_bak_read_all_logfiles(session) != CT_SUCCESS) {
                bak->failed = CT_TRUE;
                break;
            }
        }

        CT_LOG_RUN_INF("[BACKUP] start record backupset file");
        if (bak_generate_backupset_head(session, ctx) != CT_SUCCESS) {
            bak->failed = CT_TRUE;
            break;
        }
        break;
    }

    if (bak->failed) {
        bak_set_error(&bak->error_info);
    }

    bak_reset_fileinfo(&process->assign_ctrl);
    CT_LOG_RUN_INF("[BACKUP] backup to remote, read proc finished and exit");
    KNL_SESSION_CLEAR_THREADID(session);
    bak->progress.stage = BACKUP_READ_FINISHED;
}

bool8 bak_backup_database_need_retry(knl_session_t *session)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    return bak->reform_check.is_reformed;
}

status_t bak_delete_backupset_for_retry(knl_backup_t *param)
{
#ifndef WIN32
    char path[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    if (param->device == DEVICE_DISK) {
        if (cm_text2str(&param->format, path, CT_FILE_NAME_BUFFER_SIZE) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BACKUP] get path in param failed");
            return CT_ERROR;
        }
        
        if (cm_remove_dir(path) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BACKUP] remove dir(%s) for retry failed", path);
            return CT_ERROR;
        } else {
            CT_LOG_RUN_INF("[BACKUP] remove dir(%s) for retry succ", path);
            return CT_SUCCESS;
        }
    }
#endif
    return CT_ERROR;
}

status_t bak_fsync_and_close(bak_t *bak, device_type_t type, int32 *handle)
{
    if (*handle == CT_INVALID_HANDLE) {
        return CT_SUCCESS;
    }
    if (cm_fsync_file(*handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] failed to fsync datafile %s, handle %d", bak->local.name, *handle);
        cm_close_device(type, handle);
        bak->failed = CT_TRUE;
        return CT_ERROR;
    }
    cm_close_device(type, handle);
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif