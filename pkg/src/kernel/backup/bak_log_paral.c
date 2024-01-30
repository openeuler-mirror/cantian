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
 * bak_log_paral.c
 *
 *
 * IDENTIFICATION
 * src/kernel/backup/bak_log_paral.c
 *
 * -------------------------------------------------------------------------
 */

#include "bak_log_paral.h"
#include "dtc_database.h"
#include "knl_backup_module.h"

#ifdef __cplusplus
extern "C" {
#endif

void bak_set_head_for_paral_log(bak_t *bak)
{
    bak->log_proc_count = 0;
    bak->paral_log_bak_complete = CT_FALSE;
    bak->paral_log_bak_number = 0;
    bak->paral_last_asn = 0;
    bak->arch_is_lost = CT_FALSE;
    bak->log_proc_is_ready = CT_FALSE;
    errno_t ret = memset_sp(&bak->device, sizeof(bak_device_t), 0, sizeof(bak_device_t));
    knl_securec_check(ret);
}

status_t bak_found_archived_log(knl_session_t *session, uint32 rst_id, uint32 asn, arch_ctrl_t **arch_ctrl,
    bool32 is_paral_log_proc)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;

    CT_LOG_DEBUG_INF("[BACKUP] start wait for archivelog: %u-%u", rst_id, asn);
    while (*arch_ctrl == NULL && !bak->failed) {
        *arch_ctrl = arch_get_archived_log_info(session, rst_id, asn, ARCH_DEFAULT_DEST, session->kernel->id);

        if (is_paral_log_proc && bak->progress.stage == BACKUP_LOG_STAGE) {
            return CT_SUCCESS;
        }
        cm_sleep(BAK_LOG_SLEEP_TIME);
    }

    if (*arch_ctrl != NULL && !cm_file_exist((*arch_ctrl)->name)) {
        CT_LOG_RUN_ERR("[BACKUP] failed to get archived log for [%u-%u]", rst_id, asn);
        return CT_ERROR;
    }

    if (bak->failed) {
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[BACKUP] found archivelog: %u-%u, name: %s", rst_id, asn, (*arch_ctrl)->name);

    return CT_SUCCESS;
}

status_t bak_set_log_ctrl(knl_session_t *session, bak_process_t *process, uint32 asn, uint32 *block_size, bool32 *compressed)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    database_t *db = &session->kernel->db;
    bak_assignment_t *assign_ctrl = &process->assign_ctrl;
    bak_ctrl_t *ctrl = &process->ctrl;
    log_file_t *file = NULL;
    arch_ctrl_t *arch_ctrl = NULL;
    uint32 rst_id = bak_get_rst_id(bak, asn, &(db->ctrl.core.resetlogs));
    errno_t ret;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);

    CT_LOG_RUN_INF("[BACKUP] Try to get archived log for [%u-%u]", rst_id, asn);

    assign_ctrl->log_asn = asn;
    assign_ctrl->file_id = bak_log_get_id(session, bak->record.data_type, rst_id, asn);
    assign_ctrl->file_size = 0;

    if (assign_ctrl->file_id == CT_INVALID_ID32) {
        arch_ctrl = arch_get_archived_log_info(session, rst_id, asn, ARCH_DEFAULT_DEST, session->kernel->id);
        if (arch_ctrl == NULL) {
            CT_LOG_RUN_ERR("[BACKUP] failed to get archived log for [%u-%u]", rst_id, asn);
            CT_THROW_ERROR(ERR_FILE_NOT_EXIST, "archive log", "for backup");
            return CT_ERROR;
        }
        ret = strcpy_sp(ctrl->name, CT_FILE_NAME_BUFFER_SIZE, arch_ctrl->name);
        knl_securec_check(ret);
        ctrl->type = cm_device_type(arch_ctrl->name);
        CT_LOG_DEBUG_INF("[BACKUP] Get archived log %s for [%u-%u]", ctrl->name, rst_id, asn);
        *block_size = (uint32)arch_ctrl->block_size;
        *compressed = arch_is_compressed(arch_ctrl);
        bak_record_new_file(bak, BACKUP_ARCH_FILE, asn, 0, rst_id, CT_FALSE, arch_ctrl->start_lsn, arch_ctrl->end_lsn);
    } else {
        file = &logfile_set->items[assign_ctrl->file_id];
        ret = strcpy_sp(ctrl->name, CT_FILE_NAME_BUFFER_SIZE, file->ctrl->name);
        knl_securec_check(ret);
        ctrl->type = file->ctrl->type;
        *block_size = file->ctrl->block_size;
        *compressed = CT_FALSE;
        CT_LOG_DEBUG_INF("[BACKUP] Get online log %s for [%u-%u] write pos %llu",
            ctrl->name, rst_id, asn, file->head.write_pos);

        if (assign_ctrl->file_id == dtc_my_ctrl(session)->log_last) {
            bak_record_new_file(bak, BACKUP_LOG_FILE, assign_ctrl->file_id, 0, rst_id, CT_FALSE, 0, 0);
            assign_ctrl->file_size = file->head.write_pos;
        } else {
            bak_record_new_file(bak, BACKUP_ARCH_FILE, asn, 0, rst_id, CT_FALSE, 0, 0);
        }
    }

    if (cm_open_device(ctrl->name, ctrl->type, knl_arch_io_flag(session, *compressed), &ctrl->handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] failed to open %s", ctrl->name);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t bak_set_archived_log_ctrl(knl_session_t *session, bak_process_t *process, uint32 asn, uint32 *block_size,
    bool32 *compressed, bool32 is_paral_log_proc)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    database_t *db = &session->kernel->db;
    bak_assignment_t *assign_ctrl = &process->assign_ctrl;
    bak_ctrl_t *ctrl = &process->ctrl;
    arch_ctrl_t *arch_ctrl = NULL;
    reset_log_t rst_log = db->ctrl.core.resetlogs;
    uint32 rst_id = bak_get_rst_id(bak, asn, &(rst_log));
    errno_t ret;

    if (bak_found_archived_log(session, rst_id, asn, &arch_ctrl, is_paral_log_proc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (arch_ctrl == NULL) {
        bak->arch_is_lost = CT_TRUE;
        knl_panic_log(is_paral_log_proc,
            "[BACKUP] only in paral log proc, arch ctrl could get nothing while paral log proc is exiting");
        return CT_SUCCESS;
    }
    assign_ctrl->file_id = CT_INVALID_ID32;
    assign_ctrl->log_asn = asn;
    assign_ctrl->file_size = 0;
    ret = strcpy_sp(ctrl->name, CT_FILE_NAME_BUFFER_SIZE, arch_ctrl->name);
    knl_securec_check(ret);
    *block_size = (uint32)arch_ctrl->block_size;
    *compressed = arch_is_compressed(arch_ctrl);
    // todo xjl
    bak_record_new_file(bak, BACKUP_ARCH_FILE, asn, 0, rst_id,
                        is_paral_log_proc, arch_ctrl->start_lsn,
                        arch_ctrl->end_lsn);

    ctrl->type = cm_device_type(ctrl->name);
    if (cm_open_device(ctrl->name, ctrl->type, knl_arch_io_flag(session, *compressed), &ctrl->handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] failed to open %s", ctrl->name);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

uint32 bak_get_log_slot(bak_t *bak, bool32 is_paral_log_proc)
{
    if (is_paral_log_proc) {
        uint32 slot = bak->device.sec_number + bak->paral_log_bak_number + 1;
        knl_panic_log(slot > bak->device.sec_number,
            "[BACKUP] log's slot number %u should larger than df's sec number %u", slot, bak->device.sec_number);
        return slot;
    }
    return bak->file_count;
}

static void bak_try_update_device_info(knl_session_t *session, datafile_t *datafile, uint32 file_id, uint64 file_size,
    uint32 file_hwm_start)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    uint64 sec_size = 0;
    bool32 diveded = CT_FALSE;

    if (!bak_log_paral_enable(bak)) {
        return;
    }
    knl_panic_log(bak->section_threshold > 0, "[BACKUP] section_threshold [%llu] is not correct",
        bak->section_threshold);
    bak->device.datafile[file_id].file_size = file_size;
    bak->device.datafile[file_id].hwm_start = file_hwm_start;
    bak->device.datafile[file_id].id = datafile->ctrl->id;
    bak->device.datafile[file_id].sec_num =
        bak_datafile_section_count(session, file_size, file_hwm_start, &sec_size, &diveded);
    errno_t ret = strcpy_sp(bak->device.datafile[file_id].name, CT_FILE_NAME_BUFFER_SIZE, datafile->ctrl->name);
    knl_securec_check(ret);
    bak->device.sec_number += bak->device.datafile[file_id].sec_num;
}

status_t bak_check_datafiles_num(knl_session_t *session, bool32 update_device)
{
    bak_context_t *bkup_ctx = &session->kernel->backup_ctx;
    bak_t *bak = &bkup_ctx->bak;
    uint32 file_id = 0;
    uint32 datafile_num = 0;
    uint64 file_size = 0;
    uint32 file_hwm_start = 0;

    bak->device.sec_number = 0;
    for (;;) {
        datafile_t *datafile = db_get_next_datafile(session, &file_id, &file_size, &file_hwm_start);
        if (datafile == NULL) {
            break;
        }

        if (bak->target_info.target == TARGET_ALL && bak->exclude_spcs[datafile->space_id]) {
            file_id = datafile->ctrl->id + 1;
            continue;
        }

        if (bak->target_info.target == TARGET_TABLESPACE && !bak->include_spcs[datafile->space_id]) {
            file_id = datafile->ctrl->id + 1;
            continue;
        }

        if (update_device) {
            bak_try_update_device_info(session, datafile, file_id, file_size, file_hwm_start);
        }

        datafile_num++;
        file_id = datafile->ctrl->id + 1;
    }

    if (datafile_num == 0) {
        bak->failed = CT_TRUE;
        CT_LOG_RUN_ERR("[BACKUP] valid datafiles number is 0");
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", can not backup when valid datafiles number is 0");
        return CT_ERROR;
    }
    if (update_device) {
        bak->log_proc_is_ready = CT_TRUE;
    }

    return CT_SUCCESS;
}

status_t bak_check_bak_device(bak_t *bak, datafile_t *datafile, bak_assignment_t *assign_ctrl)
{
    if (!bak_log_paral_enable(bak)) {
        return CT_SUCCESS;
    }

    if (bak->device.datafile[assign_ctrl->file_id].id != datafile->ctrl->id) {
        CT_LOG_RUN_ERR("[BACKUP] datafile id has been changed from %u to %u",
            bak->device.datafile[assign_ctrl->file_id].id, datafile->ctrl->id);
        return CT_ERROR;
    }
    if (bak->device.datafile[assign_ctrl->file_id].file_size > assign_ctrl->file_size) {
        CT_LOG_RUN_ERR("[BACKUP] datafile size has been shrink from %llu to %llu",
            bak->device.datafile[assign_ctrl->file_id].file_size, assign_ctrl->file_size);
        return CT_ERROR;
    }

    if (bak->device.datafile[assign_ctrl->file_id].hwm_start != assign_ctrl->file_hwm_start) {
        CT_LOG_RUN_ERR("[BACKUP] datafile hwm_start has been changed from %u to %u",
            bak->device.datafile[assign_ctrl->file_id].hwm_start, assign_ctrl->file_hwm_start);
        return CT_ERROR;
    }

    if (strcmp(bak->device.datafile[assign_ctrl->file_id].name, datafile->ctrl->name) != 0) {
        CT_LOG_RUN_ERR("[BACKUP] datafile name has been changed from %s to %s",
            bak->device.datafile[assign_ctrl->file_id].name, datafile->ctrl->name);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void bak_try_reset_file_size(bak_t *bak, bak_assignment_t *assign_ctrl)
{
    if (bak_log_paral_enable(bak)) {
        CT_LOG_RUN_INF("[BACKUP] file [id: %u] size been reset from %llu to %llu", assign_ctrl->file_id,
            assign_ctrl->file_size, bak->device.datafile[assign_ctrl->file_id].file_size);
        assign_ctrl->file_size = bak->device.datafile[assign_ctrl->file_id].file_size;
    }
}

void bak_try_wait_paral_log_proc(bak_t *bak)
{
    bak_progress_t *progress = &bak->progress;

    if (!bak_log_paral_enable(bak)) {
        CT_LOG_RUN_INF("[BACKUP] do not need wait paral log proc");
        return;
    }

    cm_spin_lock(&progress->lock, NULL);
    progress->stage = BACKUP_LOG_STAGE;
    cm_spin_unlock(&progress->lock);

    while (!bak->failed) {
        if (bak->paral_log_bak_complete) {
            break;
        }
        cm_sleep(BAK_LOG_SLEEP_TIME);
    }
    CT_LOG_RUN_INF("[BACKUP] successful to found paral log proc exit");
}

status_t bak_try_merge_bak_info(bak_t *bak, uint32 last_asn, uint32 *start_asn)
{
    if (!bak_log_paral_enable(bak)) {
        CT_LOG_RUN_INF("[BACKUP] do not need merge bak info");
        return CT_SUCCESS;
    }
    if (bak->paral_last_asn == 0) {
        CT_LOG_RUN_INF("[BACKUP] paral log proc doesn't obtain any archive log before exit");
        return CT_SUCCESS;
    }
    knl_panic_log(*start_asn <= last_asn, "start asn [%u] should be not more than last asn [%u]", *start_asn, last_asn);
    if (bak->paral_last_asn < *start_asn || bak->paral_last_asn > last_asn) {
        CT_LOG_RUN_ERR("[BACKUP] paral last asn: %u is invalid, start asn: %u, last asn: %u",
            bak->paral_last_asn, *start_asn, last_asn);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[BACKUP] update start asn from %u to %u", *start_asn, bak->paral_last_asn + 1);
    *start_asn = bak->paral_last_asn + 1;

    uint32 temp_count = bak->file_count;
    bak->file_count += bak->paral_log_bak_number;
    CT_LOG_RUN_INF("[BACKUP] update file_count from %u to %u", temp_count, bak->file_count);

    return CT_SUCCESS;
}

// while lrp point is an empty file, switch logfile operations do not work. (1) last asn will euqals curr file and
// it is not necessary to backup an empty file. (2) we can not get archived logfile of last asn while last asn is
// curr file.
bool32 bak_equal_last_asn(knl_session_t *session, uint32 last_asn)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;

    if (!bak_need_wait_arch(session)) {
        return CT_FALSE;
    }
    CT_LOG_RUN_INF("[BACKUP] curr file's asn: %u, last asn: %u in backing up operation",
        redo_ctx->files[redo_ctx->curr_file].head.asn, last_asn);
    return (redo_ctx->files[redo_ctx->curr_file].head.asn == last_asn);
}

void bak_log_read_proc(thread_t *thread)
{
    bak_process_t *process = (bak_process_t *)thread->argument;
    knl_session_t *session = process->session;
    bak_t *bak = &session->kernel->backup_ctx.bak;
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;
    uint32 curr_asn = (uint32)ctrlinfo->rcy_point.asn;
    bak_process_t *proc = NULL;
    uint32 block_size = 0;
    bool32 arch_compressed = CT_FALSE;

    CT_LOG_RUN_INF("[BACKUP] parallel process %u start to backup archive log", process->proc_id);
    while (!thread->closed && !bak->failed) {
        if (!bak->log_proc_is_ready) {
            cm_sleep(BAK_LOG_SLEEP_TIME);
            continue;
        }

        if (bak->progress.stage == BACKUP_LOG_STAGE) {
            bak_wait_paral_proc(session, CT_TRUE);
            bak->paral_log_bak_complete = CT_TRUE;
            break;
        }

        if (bak_get_free_proc(session, &proc, CT_TRUE) != CT_SUCCESS) {
            bak->failed = CT_TRUE;
            break;
        }

        if (bak_set_archived_log_ctrl(session, proc, curr_asn, &block_size, &arch_compressed, CT_TRUE) != CT_SUCCESS) {
            bak->failed = CT_TRUE;
            break;
        }

        if (bak->arch_is_lost) {
            knl_panic_log(bak->progress.stage == BACKUP_LOG_STAGE, "only in BACKUP LOG STAGE, get arch log can failed");
            bak_wait_paral_proc(session, CT_TRUE);
            bak->paral_log_bak_complete = CT_TRUE;
            break;
        }

        proc->assign_ctrl.log_block_size = block_size;
        if (bak_assign_backup_task(session, proc, 0, CT_TRUE) != CT_SUCCESS) {
            cm_close_device(proc->ctrl.type, &proc->ctrl.handle);
            bak->failed = CT_TRUE;
            break;
        }
        curr_asn++;
    }

    if (bak->failed) {
        CT_LOG_RUN_ERR("[BACKUP] failed: paral log process %u stop", process->proc_id);
        bak_set_error(&bak->error_info);
    } else {
        CT_LOG_RUN_INF("[BACKUP] success: paral log process %u stop", process->proc_id);
    }
}

#ifdef __cplusplus
}
#endif
