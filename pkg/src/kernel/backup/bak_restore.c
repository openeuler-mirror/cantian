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
 * bak_restore.c
 *
 *
 * IDENTIFICATION
 * src/kernel/backup/bak_restore.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_backup_module.h"
#include "bak_restore.h"
#include "cm_file.h"
#include "bak_paral.h"
#include "knl_abr.h"
#include "knl_context.h"
#include "knl_space_ddl.h"
#include "dtc_dls.h"
#include "dtc_ckpt.h"
#include "dtc_backup.h"
#include "dtc_log.h"
#include "dtc_database.h"
#include "rc_reform.h"
#include "srv_param_common.h"
#include "knl_badblock.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RST_NEED_RESTORE_CTRLFILE(bak) ((bak)->rst_file.file_type == RESTORE_ALL || \
                                        (bak)->rst_file.file_type == RESTORE_CTRL)
#define RST_NEED_RESTORE_DATAFILE(bak) ((bak)->rst_file.file_type == RESTORE_ALL || \
                                        (bak)->rst_file.file_type == RESTORE_DATAFILE)
#define RST_NEED_RESTORE_ARCHFILE(bak) ((bak)->rst_file.file_type == RESTORE_ALL || \
                                        (bak)->rst_file.file_type == RESTORE_ARCHFILE)
#define ESTIMATE_VALID_DATA_PERCENT 0.5

#define BAK_WAIT_FILE_EXTEND_MS 1000

static void rst_wait_logfiles_created(bak_t *bak);

void rst_close_ctrl_file(ctrlfile_set_t *ctrlfiles)
{
    for (uint32 i = 0; i < ctrlfiles->count; i++) {
        cm_close_device(ctrlfiles->items[i].type, &ctrlfiles->items[i].handle);
    }
}

void rst_close_log_files(knl_session_t *session)
{
    log_file_t *file = NULL;

    for (uint32 i = 0; i < dtc_my_ctrl(session)->log_hwm; i++) {
        file = &MY_LOGFILE_SET(session)->items[i];
        if (LOG_IS_DROPPED(file->ctrl->flg)) {
            continue;
        }

        cm_close_device(file->ctrl->type, &file->handle);
    }
}

status_t rst_write_data(knl_session_t *session, bak_ctrl_t *ctrl, const char *buf, int32 size)
{
    /* closed in rst_restore_logfiles */
    if (cm_open_device(ctrl->name, ctrl->type, O_SYNC, &ctrl->handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] failed to open %s", ctrl->name);
        return CT_ERROR;
    }
    if (cm_write_device(ctrl->type, ctrl->handle, ctrl->offset, buf, size) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] failed to write %s", ctrl->name);
        return CT_ERROR;
    }

    if (db_fdatasync_file(session, ctrl->handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] failed to fdatasync logfile %s", ctrl->name);
        return CT_ERROR;
    }

    ctrl->offset += size;
    return CT_SUCCESS;
}

static status_t rst_create_ctrl_device(knl_session_t *session, ctrlfile_t *ctrlfile)
{
    knl_instance_t *kernel = session->kernel;
    bool32 is_dbstor = knl_dbs_is_enable_dbs();
    if (is_dbstor) {
        ctrlfile->blocks = kernel->attr.clustered ? CTRL_MAX_PAGES_CLUSTERED : CTRL_MAX_PAGES_NONCLUSTERED;
        ctrlfile->block_size = CT_DFLT_CTRL_BLOCK_SIZE;
        uint32 flags = (ctrlfile->type == DEV_TYPE_PGPOOL ? 0xFFFFFFFF : knl_io_flag(session));
        if (cm_build_device(ctrlfile->name, ctrlfile->type, kernel->attr.xpurpose_buf,
            CT_XPURPOSE_BUFFER_SIZE, (int64)ctrlfile->blocks * ctrlfile->block_size,
            flags, CT_FALSE, &ctrlfile->handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RESTORE] failed to build %s ", ctrlfile->name);
            return CT_ERROR;
        }
        if (cm_open_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RESTORE] failed to open %s", ctrlfile->name);
            return CT_ERROR;
        }
    } else {
        if (cm_create_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RESTORE] failed to create %s ", ctrlfile->name);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

static status_t rst_build_ctrl_file(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    ctrlfile_set_t *ctrlfiles = &kernel->db.ctrlfiles;
    ctrlfile_t *ctrlfile = NULL;
    uint32 size = CTRL_MAX_PAGES(session) * CT_DFLT_CTRL_BLOCK_SIZE;

    db_store_core(&kernel->db);
    knl_panic(ctrlfiles->count <= CT_MAX_CTRL_FILES);
    bak_calc_ctrlfile_checksum(session, (char *)kernel->db.ctrl.pages, CTRL_MAX_PAGES(session));
    for (uint32 i = 0; i < ctrlfiles->count; i++) {
        ctrlfile = &ctrlfiles->items[i];
        if (!cm_exist_device(ctrlfile->type, ctrlfile->name)) {
            if (rst_create_ctrl_device(session, ctrlfile)) {
                return CT_ERROR;
            }
        } else {
            if (cm_open_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[RESTORE] failed to open %s", ctrlfile->name);
                return CT_ERROR;
            }
        }

        if (cm_write_device(ctrlfile->type, ctrlfile->handle, 0, (void *)(&kernel->db.ctrl.pages[0]),
                            size) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RESTORE] failed to write %s", ctrlfile->name);
            cm_close_device(ctrlfile->type, &ctrlfile->handle);
            return CT_ERROR;
        }

        if (db_fdatasync_file(session, ctrlfile->handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RESTORE] failed to fdatasync datafile %s", ctrlfile->name);
            cm_close_device(ctrlfile->type, &ctrlfile->handle);
            return CT_ERROR;
        }

        cm_close_device(ctrlfile->type, &ctrlfile->handle);
    }

    return CT_SUCCESS;
}

static void rst_offline_unused_space(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    database_t *db = &kernel->db;
    space_t *space = NULL;
    space_ctrl_t *ctrl = NULL;
    bak_t *bak = &kernel->backup_ctx.bak;

    if (!BAK_IS_TABLESPCE_RESTORE(bak)) {
        return;
    }

    for (uint32 i = 0; i < CT_MAX_SPACES; i++) {
        space = &db->spaces[i];
        ctrl = space->ctrl;
        if (SPACE_IS_DEFAULT(space) || !ctrl->used ||
            cm_str_equal(bak->spc_name, ctrl->name)) {
            continue;
        }

        spc_offline_space_files(session, db->spaces[i].ctrl->files, db->spaces[i].ctrl->file_hwm);
    }
}

static void rst_convert_temp_path(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    bak_t *bak = &kernel->backup_ctx.bak;
    char convert_path[CT_FILE_NAME_BUFFER_SIZE];
    errno_t err;

    if (!BAK_IS_TABLESPCE_RESTORE(bak)) {
        return;
    }
    err = snprintf_s(convert_path, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1, "%s/data", kernel->home);
    knl_securec_check_ss(err);
    db_convert_temp_path(session, convert_path);
}

static status_t rst_restore_ctrlfile_items(knl_session_t *session)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;

    if (db_generate_ctrlitems(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (db_update_ctrl_filename(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (db_update_config_ctrl_name(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (bak->record.attr.level == 0) {
        if (db_create_ctrl_file(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (db_update_storage_filename(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    rst_convert_temp_path(session);
    rst_offline_unused_space(session);

    return CT_SUCCESS;
}

status_t rst_process_existed_datafile(bak_process_t *ctx, datafile_ctrl_t *df, uint32 i)
{
    status_t status;

    if (ctx->datafiles[i] != CT_INVALID_HANDLE && !cm_str_equal(ctx->datafile_name[i], df->name)) {
        if (ctx->datafile_version[i] == df->create_version) {
            CT_LOG_RUN_WAR("[RESTORE] datafile %s has been renamed to %s, id %u, create version %u",
                ctx->datafile_name[i], df->name, i, df->create_version);
            status = cm_rename_device(df->type, ctx->datafile_name[i], df->name);
        } else {
            CT_LOG_RUN_WAR("[RESTORE] datafile %s has been deleted, recreated as %s, id %u, version: old %u, new %u",
                ctx->datafile_name[i], df->name, i, ctx->datafile_version[i], df->create_version);
            cm_close_device(df->type, &ctx->datafiles[i]);
            status = cm_remove_device(ctx->file_type[i], ctx->datafile_name[i]);
            ctx->datafiles[i] = CT_INVALID_HANDLE;
        }

        return status;
    }

    return CT_SUCCESS;
}

static status_t rst_create_datafile_device(knl_session_t *session, datafile_t *df, bak_process_t *ctx, uint32 file_index)
{
    knl_instance_t *kernel = session->kernel;
    bool32 is_dbstor = knl_dbs_is_enable_dbs();
    if (is_dbstor) {
        if (cm_build_device(df->ctrl->name, df->ctrl->type, kernel->attr.xpurpose_buf,
            CT_XPURPOSE_BUFFER_SIZE, df->ctrl->size,
            knl_io_flag(session), CT_FALSE, &ctx->datafiles[file_index]) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RESTORE] failed to build %s ", df->ctrl->name);
            return CT_ERROR;
        }

        /* ctrlfile can be opened for a long time, closed in db_close_ctrl_files */
        if (cm_open_device(df->ctrl->name, df->ctrl->type,
                           knl_io_flag(session), &ctx->datafiles[file_index]) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RESTORE] failed to open %s ", df->ctrl->name);
            return CT_ERROR;
        }
    } else {
        if (cm_create_device(df->ctrl->name, df->ctrl->type, knl_io_flag(session),
            &ctx->datafiles[file_index]) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RESTORE] failed to create %s ", df->ctrl->name);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t rst_create_datafiles(knl_session_t *session, bak_process_t *ctx)
{
    knl_instance_t *kernel = session->kernel;
    bak_context_t *bak_ctx = &session->kernel->backup_ctx;
    bak_t *bak = &kernel->backup_ctx.bak;
    datafile_t *df = NULL;
    errno_t ret;

    if (BAK_IS_FULL_BUILDING(bak) && !bak->is_first_link) {
        return CT_SUCCESS;
    }

    for (uint32 i = 0; i < CT_MAX_DATA_FILES; i++) {
        ctx->datafile_size[i] = CT_INVALID_INT64;
        df = &kernel->db.datafiles[i];

        if (bak->rst_file.file_type == RESTORE_DATAFILE && bak->rst_file.file_id != df->ctrl->id) {
            continue;
        }
        CT_LOG_DEBUG_INF("[BACKUP] %u datafile1 %s, datatfile2 %s", i, df->ctrl->name, ctx->datafile_name[i]);
        if (!df->ctrl->used || !DATAFILE_IS_ONLINE(df)) {
            if (strlen(ctx->datafile_name[i]) <= 0) {
                continue;
            }
            cm_close_device(ctx->file_type[i], &ctx->datafiles[i]);
            if (cm_remove_device(ctx->file_type[i], ctx->datafile_name[i]) != CT_SUCCESS) {
                return CT_ERROR;
            }
            ctx->datafile_name[i][0] = '\0';
            ctx->datafiles[i] = CT_INVALID_HANDLE;
            continue;
        }

        if (rst_process_existed_datafile(ctx, df->ctrl, i) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (ctx->datafiles[i] == CT_INVALID_HANDLE) {
            if (rst_create_datafile_device(session, df, ctx, i) != CT_SUCCESS) {
                return CT_ERROR;
            }
            bak->extended[i] = 0;
            CT_LOG_DEBUG_INF("[RESTORE] build file %s size %llu block size %u ", df->ctrl->name,
                             (uint64)(df->ctrl->size), df->ctrl->block_size);
        } else {
            if (rst_extend_database_file(session, bak_ctx, df->ctrl->name, df->ctrl->type, df->ctrl->size) != CT_SUCCESS) {
                return CT_ERROR;
            }
            bak->extended[i] = 1;
            CT_LOG_RUN_INF("[RESTORE] extend file %s, file size: %lld", df->ctrl->name, df->ctrl->size);
        }

        ret = strcpy_sp(ctx->datafile_name[i], CT_FILE_NAME_BUFFER_SIZE, df->ctrl->name);
        knl_securec_check(ret);
        ctx->file_type[i] = df->ctrl->type;
        ctx->datafile_version[i] = df->ctrl->create_version;

        ctx->datafile_size[i] = cm_device_size(cm_device_type(ctx->datafile_name[i]), ctx->datafiles[i]);
        if (ctx->datafile_size[i] == -1) {
            CT_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_END, errno);
            return CT_ERROR;
        }
    }
    CT_LOG_RUN_INF("[RESTORE] create all datafiles finished");

    return CT_SUCCESS;
}

status_t rst_create_logfiles(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    log_file_ctrl_t *logfile = NULL;
    int32 handle = CT_INVALID_HANDLE;
    uint32 i;
    bak_t *bak = &kernel->backup_ctx.bak;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);
    bool32 is_dbstor = knl_dbs_is_enable_dbs();

    for (i = 0; i < logfile_set->logfile_hwm; i++) {
        logfile = logfile_set->items[i].ctrl;
        if (LOG_IS_DROPPED(logfile->flg)) {
            continue;
        }
        if (BAK_IS_FULL_BUILDING(bak) && !bak->is_first_link && cm_file_exist(logfile->name)) {
            CT_LOG_RUN_INF("[BUILD] delete logfile %s ", logfile->name);
            if (cm_remove_device(logfile->type, logfile->name) != CT_SUCCESS) {
                return CT_ERROR;
            }
            CT_LOG_RUN_INF("[BUILD] create logfile %s ", logfile->name);
        }

        if (cm_create_device(logfile->name, logfile->type, knl_redo_io_flag(session), &handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RESTORE] failed to create %s ", logfile->name);
            return CT_ERROR;
        }
        CT_LOG_RUN_INF("[RESTORE] restore build file, src_file:%s, file size :%lld", logfile->name, logfile->size);
        cm_close_device(logfile->type, &handle);
        if (is_dbstor) {
            break;
        }
    }

    return CT_SUCCESS;
}

status_t rst_extend_database_file(knl_session_t *session, bak_context_t *ctx, const char *name, device_type_t type,
                                  int64 size)
{
    bak_process_t *proc = NULL;
    proc = &ctx->process[BAK_COMMON_PROC];
    if (rst_extend_file(session, name, type, size, proc->backup_buf.aligned_buf,
                        BACKUP_BUFFER_SIZE(&session->kernel->backup_ctx.bak)) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t rst_set_logfile_ctrl(knl_session_t *session, uint32 curr_file_index, log_file_head_t *head,
                              bak_ctrl_t *ctrl, bool32 *ignore_data)
{
    knl_instance_t *kernel = session->kernel;
    bak_t *bak = &kernel->backup_ctx.bak;
    bak_file_t *file_info = &bak->files[curr_file_index];
    log_file_ctrl_t *logfile = NULL;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);

    *ignore_data = CT_FALSE;
    ctrl->offset = 0;

    if (file_info->type == BACKUP_LOG_FILE) {
        rst_wait_logfiles_created(bak);
        logfile = logfile_set->items[file_info->id].ctrl;
        ctrl->type = logfile->type;
        errno_t ret = strcpy_sp(ctrl->name, CT_FILE_NAME_BUFFER_SIZE, logfile->name);
        knl_securec_check(ret);
        /* open when build log files, closed in bak_end => bak_reset_ctrl */
        if (cm_open_device(logfile->name, logfile->type, knl_redo_io_flag(session), &ctrl->handle) != CT_SUCCESS) {
            return CT_ERROR;
        }

        return CT_SUCCESS;
    }
    knl_panic(file_info->id == head->asn);
    if (BAK_IS_DBSOTR(bak)) {
        arch_file_name_info_t file_name_info = {head->rst_id, head->asn, file_info->inst_id,
                                                CT_FILE_NAME_BUFFER_SIZE, head->first_lsn, head->last_lsn, ctrl->name};
        arch_set_archive_log_name_with_lsn(session, ARCH_DEFAULT_DEST, &file_name_info);
    } else {
        arch_set_archive_log_name(session, head->rst_id, head->asn, ARCH_DEFAULT_DEST,
                                  ctrl->name, CT_FILE_NAME_BUFFER_SIZE, session->kernel->id);
    }
    ctrl->type = cm_device_type(ctrl->name);
    CT_LOG_DEBUG_INF("[RESTORE] bak_set_logfile_ctrl get archive log %s", ctrl->name);

    if (cm_exist_device(ctrl->type, ctrl->name)) {
        CT_LOG_RUN_INF("[RESTORE] Archive log %s exists", ctrl->name);
        if (arch_process_existed_archfile(session, ctrl->name, *head, ignore_data) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (!*ignore_data) {
        if (cm_create_device(ctrl->name, ctrl->type, O_BINARY | O_SYNC | O_RDWR | O_EXCL, &ctrl->handle) !=
            CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RESTORE] failed to create %s", ctrl->name);
            return CT_ERROR;
        }
        CT_LOG_RUN_INF("[RESTORE] Create %s", ctrl->name);
    }

    return CT_SUCCESS;
}

static status_t rst_amend_ctrlinfo(knl_session_t *session, uint32 last_asn, uint32 log_first)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;

    if (log_reset_logfile(session, last_asn, log_first) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dtc_my_ctrl(session)->dw_start = dtc_my_ctrl(session)->dw_end = DW_DISTRICT_BEGIN(session->kernel->id);
    dtc_my_ctrl(session)->scn = ctrlinfo->scn;
    dtc_my_ctrl(session)->lrp_point = ctrlinfo->lrp_point;
    session->kernel->scn = dtc_my_ctrl(session)->scn;
    if (dtc_save_ctrl(session, session->kernel->id) != CT_SUCCESS) {
        CM_ABORT(0, "[RESTORE] ABORT INFO: save node control file failed when restore log files");
    }

    return CT_SUCCESS;
}

static status_t rst_wait_read_data(bak_t *bak, bak_process_t *ctx)
{
    while (!bak->failed && ctx->read_size == 0) {
        if (bak->progress.stage == BACKUP_READ_FINISHED) {
            CT_THROW_ERROR(ERR_INVALID_BACKUPSET, "incomplete backup");
            return CT_ERROR;
        }
        cm_sleep(1);
    }

    return bak->failed ? CT_ERROR : CT_SUCCESS;
}

static status_t rst_update_track_file(knl_session_t *session, bak_t *bak, bool32 allow_not_exist)
{
    build_progress_t *build_progress = &bak->progress.build_progress;
    char bak_process_file[CT_FILE_NAME_BUFFER_SIZE];
    int32 handle = INVALID_FILE_HANDLE;
    errno_t ret;

    if (!BAK_IS_FULL_BUILDING(bak)) {
        return CT_SUCCESS;
    }

    ret = snprintf_s(bak_process_file, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1, "%s/bak_process_file",
                     session->kernel->home);
    knl_securec_check_ss(ret);

    if (!cm_file_exist((const char *)bak_process_file)) {
        if (allow_not_exist) {
            if (cm_create_file(bak_process_file, O_BINARY | O_RDWR, &handle) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[BUILD] failed to create track file %s", bak_process_file);
                return CT_ERROR;
            }
        } else {
            CT_LOG_RUN_ERR("[BUILD] bak track file : %s does not exist", bak_process_file);
            return CT_ERROR;
        }
    } else {
        if (cm_open_file(bak_process_file, O_BINARY | O_RDWR, &handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BUILD] failed to open %s ", bak_process_file);
            return CT_ERROR;
        }
    }

    if (cm_write_file(handle, (void *)build_progress, sizeof(build_progress_t)) != CT_SUCCESS) {
        cm_close_file(handle);
        CT_LOG_RUN_ERR("[BUILD] failed to write %s", bak_process_file);
        return CT_ERROR;
    }

    if (session->kernel->attr.enable_fdatasync) {
        if (cm_fdatasync_file(handle) != CT_SUCCESS) {
            cm_close_file(handle);
            CT_LOG_RUN_ERR("[BUILD] failed to fdatasync datafile %s", bak_process_file);
            return CT_ERROR;
        }
    }
    bak->build_retry_time = 0;
    cm_close_file(handle);

    return CT_SUCCESS;
}

status_t rst_delete_track_file(knl_session_t *session, bak_t *bak, bool32 allow_not_exist)
{
    char bak_process_file[CT_FILE_NAME_BUFFER_SIZE];
    errno_t ret;

    if (!BAK_IS_FULL_BUILDING(bak) && bak->error_info.err_code != ERR_BUILD_CANCELLED) {
        return CT_SUCCESS;
    }

    ret = snprintf_s(bak_process_file, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1, "%s/bak_process_file",
                     session->kernel->home);
    knl_securec_check_ss(ret);

    if (!cm_file_exist((const char *)bak_process_file)) {
        if (allow_not_exist) {
            return CT_SUCCESS;
        }
        CT_LOG_RUN_ERR("[BUILD] failed to find track file %s", bak_process_file);
        return CT_ERROR;
    }

    if (cm_remove_file(bak_process_file) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BUILD] failed to delete track file %s", bak_process_file);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t rst_restore_logfile(knl_session_t *session, log_file_head_t *head, bool32 ignore_data)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_process_t *write_ctx = &ctx->process[BAK_COMMON_PROC];
    bak_t *bak = &ctx->bak;
    uint64 data_size = head->write_pos;
    uint32 read_size = CM_CALC_ALIGN((uint32)head->block_size, sizeof(log_file_head_t));
    int32 left_offset;
    errno_t ret;
    build_progress_t *build_progress = &bak->progress.build_progress;

    if (!ignore_data) {
        if (rst_write_data(session, &write_ctx->ctrl, (const char *)head, read_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    knl_panic(data_size >= read_size);
    data_size -= read_size;
    while (data_size > 0) {
        if (rst_wait_read_data(bak, write_ctx) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (write_ctx->read_size < 0) {
            return CT_ERROR;
        }

        write_ctx->left_size = write_ctx->read_size % head->block_size;
        left_offset = write_ctx->read_size - write_ctx->left_size;
        write_ctx->read_size -= write_ctx->left_size;

        /* write_ctx->read_size is int32, when write_ctx->read_size > data_size, (uint32)data_size cannot overdlow */
        read_size = ((uint64)write_ctx->read_size > data_size) ? (uint32)data_size : (uint32)write_ctx->read_size;
        if (!ignore_data) {
            if (rst_write_data(session, &write_ctx->ctrl, write_ctx->backup_buf.aligned_buf + write_ctx->write_size,
                               read_size) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }

        if (write_ctx->left_size > 0) {
            ret = memmove_s(write_ctx->backup_buf.aligned_buf, BACKUP_BUFFER_SIZE(bak),
                            write_ctx->backup_buf.aligned_buf + left_offset, write_ctx->left_size);
            knl_securec_check(ret);
        }
        /* should assign build_progress before write_ctx->read_size becoming zero. */
        /* and should persistence build_progress after persisting one complete log file */
        if (BAK_IS_FULL_BUILDING(bak)) {
            build_progress->asn = head->asn;
            build_progress->stage = BACKUP_LOG_STAGE;
            build_progress->curr_file_index = bak->curr_file_index;
        }

        write_ctx->read_size -= (int32)read_size;
        write_ctx->write_size += (int32)read_size;
        data_size -= read_size;
    }

    if (rst_update_track_file(session, bak, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t rst_write_to_buf(bak_t *bak, bak_process_t *write_ctx, char *buf, uint32 buf_size)
{
    int32 remain_size, offset;
    int32 read_size;
    errno_t ret;

    remain_size = buf_size;
    offset = 0;
    while (remain_size > 0) {
        if (rst_wait_read_data(bak, write_ctx) != CT_SUCCESS) {
            return CT_ERROR;
        }

        read_size = (write_ctx->read_size > remain_size) ? remain_size : write_ctx->read_size;
        ret = memcpy_sp(buf + offset, remain_size, write_ctx->backup_buf.aligned_buf + write_ctx->write_size,
                        read_size);
        knl_securec_check(ret);
        write_ctx->read_size -= read_size;
        write_ctx->write_size += read_size;
        offset += read_size;
        remain_size -= read_size;
    }

    CT_LOG_DEBUG_INF("[RESTORE] restore to buf size:%u", buf_size);
    return CT_SUCCESS;
}

status_t rst_prepare_logfile(knl_session_t *session, char *buf, uint32 curr_file_index, bak_process_t *write_ctx,
                             bool32 *ignore_data)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    uint32 fill_size;
    log_file_head_t *head = (log_file_head_t *)buf;

    if (rst_write_to_buf(bak, write_ctx, (char *)head, sizeof(log_file_head_t)) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (log_verify_head_checksum(session, head, bak->local.name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    fill_size = CM_CALC_ALIGN((uint32)head->block_size, sizeof(log_file_head_t)) - sizeof(log_file_head_t);
    if (rst_write_to_buf(bak, write_ctx, buf + sizeof(log_file_head_t), fill_size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (session->kernel->attr.clustered) {
        if (dtc_bak_set_logfile_ctrl(session, curr_file_index, head, &write_ctx->ctrl, ignore_data) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (rst_set_logfile_ctrl(session, curr_file_index, head, &write_ctx->ctrl, ignore_data) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

static status_t rst_restore_arch_log(knl_session_t *session, log_file_head_t *head, uint32 curr_file_index)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_process_t *write_ctx = &ctx->process[BAK_COMMON_PROC];
    bak_t *bak = &ctx->bak;
    status_t status;
    bool32 ignore_data = CT_FALSE;

    if (rst_prepare_logfile(session, (char *)head, curr_file_index, write_ctx, &ignore_data) != CT_SUCCESS) {
        return CT_ERROR;
    }

    status = rst_restore_logfile(session, head, ignore_data);
    cm_close_device(write_ctx->ctrl.type, &write_ctx->ctrl.handle);
    if (status != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (bak->files[curr_file_index].type == BACKUP_ARCH_FILE && bak->rst_file.file_type == RESTORE_ALL) {
        // Update control file archive information
        if (session->kernel->attr.clustered) {
            if (dtc_rst_arch_try_record_archinfo(session, ARCH_DEFAULT_DEST, write_ctx->ctrl.name, head,
                                                 bak->files[curr_file_index].inst_id) != CT_SUCCESS) {
                return CT_ERROR;
            }
        } else {
            if (arch_try_record_archinfo(session, ARCH_DEFAULT_DEST, write_ctx->ctrl.name, head) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

static status_t rst_restore_logfiles(knl_session_t *session, uint32 *last_log_index)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_process_t *write_ctx = &ctx->process[BAK_COMMON_PROC];
    bak_t *bak = &ctx->bak;
    status_t status;
    log_context_t *log_ctx = &session->kernel->redo_ctx;
    char *buf = log_ctx->logwr_buf;
    log_file_head_t *head = (log_file_head_t *)buf;
    uint32 curr_file_index = bak->curr_file_index;
    bak_stage_t *stage = &bak->progress.build_progress.stage;

    if (BAK_IS_FULL_BUILDING(bak) && bak_get_build_stage(stage) > BUILD_LOG_STAGE) {
        return CT_SUCCESS;
    }

    /* only when restore full database, log file will be created */
    if (bak->rst_file.file_type == RESTORE_ALL) {
        if (bak->record.attr.level > 0 && bak->is_building) {
            status = rst_build_update_logfiles(session, write_ctx);
        } else {
            if (session->kernel->attr.clustered) {
                status = dtc_rst_create_logfiles(session);
            } else {
                status = rst_create_logfiles(session);
            }
        }

        if (status != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    bak->logfiles_created = CT_TRUE;
    CT_LOG_RUN_INF("[RESTORE] create logfiles completed");

    while (!bak->failed && bak->progress.stage != BACKUP_READ_FINISHED) {
        if (write_ctx->read_size == 0 || bak_paral_task_enable(session)) {
            cm_sleep(1);
            continue;
        }

        curr_file_index = bak->curr_file_index;
        if (rst_restore_arch_log(session, head, curr_file_index) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (bak_paral_task_enable(session)) {
        *last_log_index = bak->file_count - 1;
    } else {
        *last_log_index = curr_file_index;
    }
    return bak->failed ? CT_ERROR : CT_SUCCESS;
}

static status_t rst_write_to_ctrl_buf(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    bak_process_t *write_ctx = &kernel->backup_ctx.process[BAK_COMMON_PROC];
    bak_t *bak = &kernel->backup_ctx.bak;
    uint32 size = CTRL_MAX_PAGES(session) * CT_DFLT_CTRL_BLOCK_SIZE;

    if (bak->record.is_repair) {
        if (rst_write_to_buf(bak, write_ctx, bak->ctrl_data_buf, size) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (!rst_db_files_not_changed(session, (ctrl_page_t *)bak->ctrl_data_buf)) {
            CT_LOG_RUN_ERR("[BUILD] primary's log/data amount/name has changed");
            CT_THROW_ERROR(ERR_INVALID_OPERATION, ": primary's log/data amount/name has changed");
            return CT_ERROR;
        }
        CT_LOG_RUN_INF("[BUILD] check file amount/name successfully");
        errno_t ret = memcpy_sp((char *)(&kernel->db.ctrl.pages[0]), size, bak->ctrl_data_buf, size);
        knl_securec_check(ret);
    } else if (rst_write_to_buf(bak, write_ctx, (char *)(&kernel->db.ctrl.pages[0]), size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t rst_restore_ctrlfiles(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    bak_process_t *write_ctx = &kernel->backup_ctx.process[BAK_COMMON_PROC];
    bak_t *bak = &kernel->backup_ctx.bak;

    if (BAK_IS_FULL_BUILDING(bak) && !bak->is_first_link) {
        return CT_SUCCESS;
    }

    while (bak->progress.stage != BACKUP_CTRL_STAGE) {
        if (bak->failed) {
            return CT_ERROR;
        }
        cm_sleep(1);
    }

    if (rst_write_to_ctrl_buf(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    db_load_core(&kernel->db);

    if (rst_verify_ctrlfile_checksum(session, bak->local.name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (rst_restore_ctrlfile_items(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!db_sysdata_version_is_equal(session, CT_FALSE)) {
        return CT_ERROR;
    }

    arch_set_arch_start(session, 0, session->kernel->id);
    arch_set_arch_end(session, 0, session->kernel->id);
    if (session->kernel->attr.clustered) {
        dtc_rst_arch_set_arch_start_and_end(session);
    }

    kernel->db.ctrl.core.build_completed = CT_FALSE;
    kernel->db.ctrl.core.db_role = bak->is_building ? REPL_ROLE_PHYSICAL_STANDBY : REPL_ROLE_PRIMARY;
    if (rst_build_ctrl_file(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (rst_create_datafiles(session, write_ctx) != CT_SUCCESS) {
        bak->failed = CT_TRUE;
        return CT_ERROR;
    }

    bak->ctrlfile_completed = CT_TRUE;
    session->kernel->db.ctrl.core.bak_dbid = session->kernel->db.ctrl.core.dbid;
    session->kernel->db.ctrl.core.ddl_pitr_lsn = bak->ddl_pitr_lsn;
    return CT_SUCCESS;
}

uint32 rst_skip_empty_pages(char *buf, uint32 size, uint32 page_size)
{
    page_head_t *page = NULL;
    uint32 offset = 0;

    while (offset < size) {
        page = (page_head_t *)(buf + offset);
        if (page->size_units != 0) {
            break;
        }

        offset += page_size;
    }

    return offset;
}

uint32 rst_calc_ordered_pages(char *buf, uint32 size, uint32 page_size)
{
    page_head_t *page = (page_head_t *)buf;
    uint32 offset = page_size;
    uint32 count = 1;
    page_id_t *page_id = AS_PAGID_PTR(page->id);
    uint16 file_id = page_id->file;
    uint32 page_pos = page_id->page + 1;

    while (offset < size) {
        page = (page_head_t *)(buf + offset);
        page_id = AS_PAGID_PTR(page->id);
        if (page_id->file != file_id || page_id->page != page_pos) {
            break;
        }

        offset += page_size;
        page_pos = page_id->page + 1;
        count++;
    }

    return count;
}

status_t rst_fill_file_gap(device_type_t type, int32 handle, int64 start, int64 end, const char *buf, uint32 buf_size)
{
    uint32 data_size;
    int64 offset = start;

    if ((uint64)offset == CT_INVALID_ID64) {
        offset = cm_device_size(type, handle);
        if (offset == -1) {
            CT_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_END, errno);
            return CT_ERROR;
        }
    }

    knl_panic(offset >= 0);

    while (offset < end) {
        if (end - offset > buf_size) {
            data_size = buf_size;
        } else {
            data_size = (uint32)(end - offset);
        }

        if (cm_write_device(type, handle, offset, buf, data_size) != CT_SUCCESS) {
            return CT_ERROR;
        }

        offset += data_size;
    }

    return CT_SUCCESS;
}

#ifndef WIN32
static status_t rst_get_group_for_one_page(knl_session_t *session, datafile_t *df, int32 handle, page_id_t first,
    bak_table_compress_ctx_t *table_compress_ctx, char **group)
{
    char *read_buf = table_compress_ctx->read_buf.aligned_buf;
    char *unzip_buf = table_compress_ctx->unzip_buf.aligned_buf;
    int64 offset = (int64)first.page * DEFAULT_PAGE_SIZE(session);
    errno_t ret;

    ret = memset_sp(read_buf, DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT, 0,
                    DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT);
    knl_securec_check(ret);
    ret = memset_sp(unzip_buf, DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT, 0,
                    DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT);
    knl_securec_check(ret);

    if (offset >= cm_device_size(df->ctrl->type, handle)) {
        *group = read_buf;
        return CT_SUCCESS;
    }

    knl_panic_log(offset + DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT <= cm_device_size(df->ctrl->type, handle),
                  "offset: %lld is right with file size: %lld", offset, cm_device_size(df->ctrl->type, handle));
    if (cm_read_device(df->ctrl->type, handle, offset, read_buf,
                       DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BUFFER] failed to read datafile %s, offset %lld, size %u", df->ctrl->name, offset,
                       DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT);
        return CT_ERROR;
    }

    if (((page_head_t *)read_buf)->size_units == 0 || !((page_head_t *)read_buf)->compressed) {
        *group = read_buf;
    } else {
        uint32 group_size;
        if (buf_decompress_group(session, unzip_buf, read_buf, &group_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
        knl_panic_log(group_size == DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT,
                      "group size %u is not correct", group_size);
        if (bak_construct_decompress_group(session, unzip_buf) != CT_SUCCESS) {
            return CT_ERROR;
        }
        *group = unzip_buf;
    }

    return CT_SUCCESS;
}

static uint32 rst_update_group(knl_session_t *session, page_id_t first, page_head_t *target_page, uint32 remain_input,
    char **group)
{
    uint32 remain = remain_input;
    uint32 offset_in_group = AS_PAGID_PTR(target_page->id)->page - first.page;
    uint32 page_list_num = 1;
    page_id_t first_for_next;
    page_head_t *next_page = NULL;

    knl_panic_log(AS_PAGID_PTR(target_page->id)->page >= first.page, "page %u-%u pos should larger than %u-%u",
        AS_PAGID_PTR(target_page->id)->file, AS_PAGID_PTR(target_page->id)->page, first.file, first.page);
    while (remain > 0) {
        next_page = (page_head_t *)((char *)target_page + page_list_num * DEFAULT_PAGE_SIZE(session));
        knl_panic_log(AS_PAGID_PTR(next_page->id)->page > first.page, "page %u-%u pos should larger than %u-%u",
            AS_PAGID_PTR(next_page->id)->file, AS_PAGID_PTR(next_page->id)->page, first.file, first.page);
        first_for_next = bak_first_compress_group_id(session, *AS_PAGID_PTR(next_page->id));
        if (!IS_SAME_PAGID(first_for_next, first)) {
            break;
        }
        page_list_num++;
        remain--;
    }
    // insert bak's pages which from same group into restore's unzip group buffer
    errno_t ret = memcpy_sp(*group + offset_in_group * DEFAULT_PAGE_SIZE(session),
                            page_list_num * DEFAULT_PAGE_SIZE(session),
        (char *)target_page, page_list_num * DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);
    CT_LOG_DEBUG_INF("[RESTORE] update pages start pos %u, num: %u", offset_in_group, page_list_num);

    return page_list_num;
}

static status_t rst_punch_hole_in_group(knl_session_t *session, datafile_t *df, int32 handle, int64 first_hole_offset,
    uint32 hole_num)
{
    knl_panic_log(hole_num > 0, "hole number %u should larger than zero", hole_num);

    for (uint32 i = 0; i < hole_num; i++) {
        if (cm_file_punch_hole(handle, first_hole_offset + i * DEFAULT_PAGE_SIZE(session),
                               DEFAULT_PAGE_SIZE(session)) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t rst_write_group_directly(knl_session_t *session, datafile_t *df, int32 handle, char *group)
{
    page_head_t *page = (page_head_t *)group;
    page_id_t page_id = *AS_PAGID_PTR(page->id);
    int64 offset = (int64)(AS_PAGID_PTR(page->id)->page) * DEFAULT_PAGE_SIZE(session);
    if (cm_write_device(df->ctrl->type, handle, offset, group,
                        DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] failed to write datafile %s", df->ctrl->name);
        return CT_ERROR;
    }
    CT_LOG_DEBUG_INF("[RESTORE] write de-compressed group start:%u-%u,type:%u", page_id.file, page_id.page,
        (uint32)page->type);

    return CT_SUCCESS;
}

static status_t rst_write_hole(knl_session_t *session, bak_process_t *ctx, datafile_t *df, int32 handle,
    page_head_t *page, uint32 slot)
{
    page_id_t hole_page_id = *AS_PAGID_PTR(page->id);
    int64 first_hole_offset = (int64)hole_page_id.page * DEFAULT_PAGE_SIZE(session) + DEFAULT_PAGE_SIZE(session);
    uint32 hole_num = PAGE_GROUP_COUNT - slot;
    int64 last_hole_offset = first_hole_offset + hole_num * DEFAULT_PAGE_SIZE(session);
    if (rst_fill_file_gap(df->ctrl->type, handle, first_hole_offset, last_hole_offset, ctx->fill_buf,
        BACKUP_BUFFER_SIZE(&session->kernel->backup_ctx.bak)) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] failed to write datafile %s", df->ctrl->name);
        return CT_ERROR;
    }

    if (rst_punch_hole_in_group(session, df, handle, first_hole_offset, hole_num) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] failed to punch datafile %s", df->ctrl->name);
        return CT_ERROR;
    }
    CT_LOG_DEBUG_INF("[RESTORE] punch holes start page_id %u, total page num: %u", hole_page_id.page + 1, hole_num);

    return CT_SUCCESS;
}

static status_t rst_write_group(knl_session_t *session, bak_process_t *ctx, datafile_t *df, int32 handle,
    bak_table_compress_ctx_t *compress_ctx, char *group)
{
    char *zip_buf = compress_ctx->zip_buf.aligned_buf;
    uint32 compressed_size, remaining_size, actual_size, zsize;
    errno_t ret;

    compressed_size = ZSTD_compress((char *)zip_buf, DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT, group,
        DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT, ZSTD_DEFAULT_COMPRESS_LEVEL);
    if (ZSTD_isError(compressed_size)) {
        knl_panic(0);
    }
    if (compressed_size > DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT) {
        if (rst_write_group_directly(session, df, handle, group) != CT_SUCCESS) {
            return CT_ERROR;
        }
        return CT_SUCCESS;
    }

    remaining_size = compressed_size;
    knl_panic_log(compressed_size <= DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT,
                  "size %u is not correct", compressed_size);
    zsize = COMPRESS_PAGE_VALID_SIZE(session);
    uint32 slot = 0;
    page_head_t *page = NULL;
    uint32 offset_in_zip = 0;
    do {
        if (remaining_size > zsize) {
            actual_size = zsize;
        } else {
            actual_size = remaining_size;
        }
        page = (page_head_t *)(group + slot * DEFAULT_PAGE_SIZE(session));
        ret = memcpy_sp((char *)page + DEFAULT_PAGE_SIZE(session) - zsize, actual_size,
                        zip_buf + offset_in_zip, actual_size);
        knl_securec_check(ret);
        COMPRESS_PAGE_HEAD(page)->compressed_size = compressed_size;
        COMPRESS_PAGE_HEAD(page)->compress_algo = COMPRESS_ZSTD;
        COMPRESS_PAGE_HEAD(page)->group_cnt = GROUP_COUNT_8;
        COMPRESS_PAGE_HEAD(page)->unused = 0;
        page->compressed = 1;
        dbwr_compress_checksum(session, page);
        if (cm_write_device(df->ctrl->type, handle, (int64)(AS_PAGID_PTR(page->id)->page) * DEFAULT_PAGE_SIZE(session),
                            page, DEFAULT_PAGE_SIZE(session)) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RESTORE] failed to write datafile %s", df->ctrl->name);
            return CT_ERROR;
        }
        page_id_t page_id = *AS_PAGID_PTR(page->id);
        CT_LOG_DEBUG_INF("[RESTORE] write compress page:%u-%u,type:%u", page_id.file, page_id.page, (uint32)page->type);
        remaining_size -= actual_size;
        offset_in_zip += actual_size;
        slot++;
    } while (remaining_size != 0);

    if (slot == PAGE_GROUP_COUNT) {
        return CT_SUCCESS;
    }
    if (rst_write_hole(session, ctx, df, handle, page, slot) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t rst_incr_write_compress_pages(knl_session_t *session, bak_process_t *ctx, page_head_t *page,
    rst_assist_t rst_assist)
{
    bak_table_compress_ctx_t *table_compress_ctx = &ctx->table_compress_ctx;
    page_id_t page_id = rst_assist.page_id;
    uint32 page_count = rst_assist.page_count;
    int32 handle = ctx->datafiles[page_id.file];
    datafile_t *df = rst_assist.datafile;
    uint32 pos = 0;

    while (pos < page_count) {
        page_head_t *target_page = (page_head_t *)((char *)page + pos * DEFAULT_PAGE_SIZE(session));
        page_id_t target_page_id = *AS_PAGID_PTR(target_page->id);
        if (target_page_id.page < DF_MAP_HWM_START) {
            if (cm_write_device(df->ctrl->type, handle, (int64)(target_page_id.page) * DEFAULT_PAGE_SIZE(session),
                                target_page, DEFAULT_PAGE_SIZE(session)) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[RESTORE] failed to write datafile %s", df->ctrl->name);
                return CT_ERROR;
            }
            CT_LOG_DEBUG_INF("[RESTORE] write less 128's page:%u-%u,type:%u",
                target_page_id.file, target_page_id.page, (uint32)target_page->type);
            pos++;
            continue;
        }
        page_id_t first = bak_first_compress_group_id(session, *AS_PAGID_PTR(target_page->id));
        knl_panic_log(target_page->size_units != 0, "zero page not allowed");
        char *group = NULL;
        if (rst_get_group_for_one_page(session, df, handle, first, table_compress_ctx, &group) != CT_SUCCESS) {
            return CT_ERROR;
        }

        uint32 remain = page_count - pos - 1;
        uint32 page_list_num = rst_update_group(session, first, target_page, remain, &group);
        knl_panic_log(page_list_num >= 1 && page_list_num <= PAGE_GROUP_COUNT, "page number %u is not correct",
            page_list_num);
        pos += page_list_num;
        if (rst_write_group(session, ctx, df, handle, table_compress_ctx, group) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t rst_incr_write_punch_datafile(knl_session_t *session, bak_process_t *ctx, page_head_t *page,
    rst_assist_t rst_assist)
{
    page_id_t page_id = rst_assist.page_id;
    uint32 page_count = rst_assist.page_count;
    int32 handle = ctx->datafiles[page_id.file];
    datafile_t *df = rst_assist.datafile;
    page_head_t *target_page = NULL;

    for (uint32 i = 0; i < page_count; i++) {
        target_page = (page_head_t *)((char *)page + i * DEFAULT_PAGE_SIZE(session));
        page_id_t target_page_id = *AS_PAGID_PTR(target_page->id);
        int64 page_offset = (int64)target_page_id.page * DEFAULT_PAGE_SIZE(session);

        if (target_page->type == PAGE_TYPE_PUNCH_PAGE) {
            if (rst_fill_file_gap(df->ctrl->type, handle, page_offset, page_offset + DEFAULT_PAGE_SIZE(session),
                ctx->fill_buf, BACKUP_BUFFER_SIZE(&session->kernel->backup_ctx.bak)) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[RESTORE] failed to write datafile %s", df->ctrl->name);
                return CT_ERROR;
            }
            if (cm_file_punch_hole(handle, page_offset, DEFAULT_PAGE_SIZE(session)) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[RESTORE] failed to punch datafile %s", df->ctrl->name);
                return CT_ERROR;
            }
            CT_LOG_DEBUG_INF("[RESTORE] punch datafile %s page_id %u-%u",
                df->ctrl->name, target_page_id.file, target_page_id.page);
            continue;
        }

        if (cm_write_device(df->ctrl->type, handle, page_offset, target_page,
                            DEFAULT_PAGE_SIZE(session)) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RESTORE] failed to write datafile %s", df->ctrl->name);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

static status_t rst_save_continuous_pages(knl_session_t *session, bak_process_t *ctx, page_head_t *page,
    rst_assist_t rst_assist)
{
    datafile_t *df = rst_assist.datafile;
    bak_context_t *bak_ctx = &session->kernel->backup_ctx;
    bak_attr_t *attr = &bak_ctx->bak.record.attr;

    if (DATAFILE_IS_COMPRESS(df) && attr->level == 1) {
        if (DATAFILE_IS_PUNCHED(df)) {
            CT_LOG_RUN_ERR("[RESTORE] compress datafile %s is not expected to be a punched datafile", df->ctrl->name);
            return CT_ERROR;
        }
        if (rst_incr_write_compress_pages(session, ctx, page, rst_assist) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RESTORE] failed to write compress datafile %s", df->ctrl->name);
            return CT_ERROR;
        }
        CT_LOG_DEBUG_INF("[RESTORE] inc rst, compress datafile. start page:%u-%u,type:%u,count:%u write sucessfully",
            rst_assist.page_id.file, rst_assist.page_id.page, (uint32)page->type, rst_assist.page_count);
        return CT_SUCCESS;
    }

    if (DATAFILE_IS_PUNCHED(df) && attr->level == 1) {
        if (rst_incr_write_punch_datafile(session, ctx, page, rst_assist) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RESTORE] failed to write punched datafile %s", df->ctrl->name);
            return CT_ERROR;
        }
        CT_LOG_DEBUG_INF("[RESTORE] inc rst, punched datafile. start page:%u-%u,type:%u,count:%u write sucessfully",
            rst_assist.page_id.file, rst_assist.page_id.page, (uint32)page->type, rst_assist.page_count);
        return CT_SUCCESS;
    }

    page_id_t page_id = rst_assist.page_id;
    uint32 page_count = rst_assist.page_count;
    int64 offset = rst_assist.file_offset;
    int32 handle = ctx->datafiles[page_id.file];

    if (cm_write_device(df->ctrl->type, handle, offset, page, DEFAULT_PAGE_SIZE(session) * page_count) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] failed to write datafile %s", df->ctrl->name);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}
#endif

status_t rst_save_pages(knl_session_t *session, bak_process_t *ctx, page_head_t *page, rst_assist_t rst_assist)
{
    const char *fill_buf = ctx->fill_buf;
    page_id_t page_id = rst_assist.page_id;
    uint32 page_count = rst_assist.page_count;
    datafile_t *df = rst_assist.datafile;
    int32 handle = INVALID_FILE_HANDLE;
    int64 offset = rst_assist.file_offset;
    uint64 fill_start = CT_INVALID_ID64;
    bak_context_t *bak_ctx = &session->kernel->backup_ctx;
    bak_stat_t *stat = &bak_ctx->bak.stat;
    bak_t *bak = &session->kernel->backup_ctx.bak;
    build_progress_t *build_progress = &bak->progress.build_progress;

    if (bak_paral_task_enable(session) && ctx->assign_ctrl.section_end != 0) {
        fill_start = ctx->assign_ctrl.fill_offset;
    }

    if (page_id.file == 0 && page_id.page == 0 && !DATAFILE_IS_COMPRESS(df)) {
        knl_panic_log(page_count == 1, "the page_count is abnormal, panic info: page %u-%u type %u, page_count %u",
                      page_id.file, page_id.page, page->type, page_count);
        return CT_SUCCESS;
    }
    brain_repair_filer_page_from_remote(session, page, page_count);

    if (spc_open_datafile(session, df, &ctx->datafiles[page_id.file]) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] failed to open datafile %s", df->ctrl->name);
        return CT_ERROR;
    }
    ctx->file_type[page_id.file] = df->ctrl->type;
    handle = ctx->datafiles[page_id.file];

    if (!BAK_FILE_NEED_PUNCH(df) && rst_fill_file_gap(df->ctrl->type, handle, (int64)fill_start,
        (int64)page_id.page * DEFAULT_PAGE_SIZE(session), fill_buf, BACKUP_BUFFER_SIZE(bak)) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] failed to write datafile %s", df->ctrl->name);
        return CT_ERROR;
    }

#ifdef WIN32
    if (cm_write_device(df->ctrl->type, handle, offset, page, DEFAULT_PAGE_SIZE(session) * page_count) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] failed to write datafile %s", df->ctrl->name);
        return CT_ERROR;
    }
#else
    if (rst_save_continuous_pages(session, ctx, page, rst_assist) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] failed to write datafile %s", df->ctrl->name);
        return CT_ERROR;
    }
#endif
    if (db_fdatasync_file(session, handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] failed to fdatasync datafile %s", df->ctrl->name);
        return CT_ERROR;
    }

    (void)cm_atomic_inc(&stat->writes);

    if (ctx->assign_ctrl.fill_offset < (uint64)offset + DEFAULT_PAGE_SIZE(session) * page_count) {
        ctx->assign_ctrl.fill_offset = (uint64)offset + DEFAULT_PAGE_SIZE(session) * page_count;
    }

    if (BAK_IS_FULL_BUILDING(bak)) {
        build_progress->stage = bak->progress.stage;
        build_progress->file_id = df->ctrl->id;
        build_progress->data_offset = (uint64)offset + DEFAULT_PAGE_SIZE(session) * page_count;
        build_progress->curr_file_index = bak->curr_file_index;
        if (rst_update_track_file(session, bak, CT_FALSE) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RESTORE] failed to update track file");
            return CT_ERROR;
        }
    }

    if (bak_paral_task_enable(session) && ctx->assign_ctrl.section_end != 0) {
        knl_panic_log((uint64)offset + DEFAULT_PAGE_SIZE(session) * page_count <= ctx->assign_ctrl.section_end,
                      "panic info: page %u-%u type %u", page_id.file, page_id.page, page->type);
        knl_panic_log((uint64)offset >= ctx->assign_ctrl.section_start, "panic info: page %u-%u type %u",
                      page_id.file, page_id.page, page->type);
    }
    return CT_SUCCESS;
}

static uint64 rst_get_punch_start(knl_session_t *session, bak_process_t *ctx, uint32 file_id, uint32 data_offset)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    uint64 punch_start;

    if (BAK_IS_UDS_DEVICE(bak)) {
        punch_start = ctx->curr_offset + data_offset;
        return punch_start;
    }

    if (bak->is_building) {
        punch_start = (bak->proc_count == BUILD_SINGLE_THREAD)
                          ? cm_device_size(cm_device_type(ctx->datafile_name[file_id]), ctx->datafiles[file_id])
                          : ctx->curr_offset + data_offset;
        return punch_start;
    }

    if (bak->record.attr.compress == COMPRESS_NONE) {
        punch_start = (ctx->assign_ctrl.section_start == 0 ?
            ctx->curr_offset + data_offset + DEFAULT_PAGE_SIZE(session) :
            ctx->curr_offset + data_offset + ctx->assign_ctrl.section_start);
    } else {
        punch_start = (ctx->assign_ctrl.section_start == 0 ?
            ctx->uncompressed_offset + data_offset + DEFAULT_PAGE_SIZE(session) :
            ctx->uncompressed_offset + data_offset + ctx->assign_ctrl.section_start);
    }
    return punch_start;
}

static status_t rst_try_punch_empty_pages(knl_session_t *session, bak_process_t *ctx,
    uint32 data_offset, uint32 zero_pages_offsets)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    const char *fill_buf = ctx->fill_buf;
    uint32 file_id = bak_paral_task_enable(session) ?
        bak->files[ctx->assign_ctrl.bak_index].id : bak->files[bak->curr_file_index].id;
    datafile_t *df = DATAFILE_GET(session, file_id);

    if (zero_pages_offsets == 0 || !BAK_FILE_NEED_PUNCH(df)) {
        return CT_SUCCESS;
    }

    uint64 punch_start = rst_get_punch_start(session, ctx, file_id, data_offset);
    uint64 punch_end = punch_start + zero_pages_offsets;
    if (punch_start % DEFAULT_PAGE_SIZE(session) != 0) {
        CT_LOG_RUN_ERR("[RESTORE] datafile %s punch offset %llu is not an integral multiple of page size",
            df->ctrl->name, punch_start);
        return CT_ERROR;
    }
    CT_LOG_DEBUG_INF("[RESTORE] punch datafile %s start page id %u-%u, total page num: %u",
                     df->ctrl->name, file_id, (uint32)punch_start / DEFAULT_PAGE_SIZE(session),
                     zero_pages_offsets / DEFAULT_PAGE_SIZE(session));

    if (spc_open_datafile(session, df, &ctx->datafiles[file_id]) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] failed to open datafile %s", df->ctrl->name);
        return CT_ERROR;
    }
    ctx->file_type[file_id] = df->ctrl->type;

    if (rst_fill_file_gap(df->ctrl->type, ctx->datafiles[file_id], (int64)punch_start,
        (int64)punch_end, fill_buf, BACKUP_BUFFER_SIZE(bak)) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] failed to write datafile %s", df->ctrl->name);
        return CT_ERROR;
    }

    if (cm_file_punch_hole(ctx->datafiles[file_id], punch_start, punch_end - punch_start) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] failed to punch datafile %s start page_id %u-%u, total page num: %u",
                       df->ctrl->name, file_id, (uint32)punch_start / DEFAULT_PAGE_SIZE(session),
                       zero_pages_offsets / DEFAULT_PAGE_SIZE(session));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static void rst_build_wait_write_datafile(knl_session_t *session, bak_t *bak, bool32 *skip_write)
{
    bak_stage_t *stage = &bak->progress.build_progress.stage;
    if (bak_get_build_stage(stage) > BUILD_DATA_STAGE) {
        *skip_write = CT_TRUE;
        return;
    }

    while (!bak->failed && bak->progress.stage != BACKUP_DATA_STAGE) {
        if (bak->progress.stage < BACKUP_DATA_STAGE) {
            cm_sleep(1);
        } else {
            // For breakpoint build when the standby is disconnected before receiving a complete archive log.
            *skip_write = CT_TRUE;
            return;
        }
    }

    bak->progress.build_progress.stage = bak->progress.stage;
    bak->progress.build_progress.curr_file_index = bak->curr_file_index;
    bak->progress.build_progress.data_offset = DEFAULT_PAGE_SIZE(session);
    if (rst_update_track_file(session, bak, bak->is_first_link) != CT_SUCCESS) {
        bak->failed = CT_TRUE;
    }
}

static void rst_wait_write_datafile(bak_t *bak)
{
    while (!bak->failed && bak->progress.stage != BACKUP_DATA_STAGE) {
        cm_sleep(1);
    }
}

status_t rst_restore_datafile(knl_session_t *session, bak_t *bak, bak_process_t *ctx, char *buf, const char *filename)
{
    uint32 zero_pages_offsets;
    uint32 data_offset = 0;
    bak_attr_t *attr = &bak->record.attr;
    rst_assist_t rst_assist;
    rst_assist.page_count = 1;
    if (rst_verify_datafile_checksum(session, ctx, buf, (uint32)ctx->read_size / DEFAULT_PAGE_SIZE(session),
                                     filename) != CT_SUCCESS) {
        return CT_ERROR;
    }

    while (!bak->failed && data_offset < (uint32)ctx->read_size) {
        if (attr->level == 0) {
            zero_pages_offsets = rst_skip_empty_pages(buf + data_offset, (uint32)ctx->read_size - data_offset,
                DEFAULT_PAGE_SIZE(session));
            if (rst_try_punch_empty_pages(session, ctx, data_offset, zero_pages_offsets) != CT_SUCCESS) {
                return CT_ERROR;
            }
            data_offset += zero_pages_offsets;
            if (data_offset >= (uint32)ctx->read_size) {
                break;
            }
        }
        rst_assist.page_id = *(page_id_t *)(buf + data_offset);
        rst_assist.datafile = DATAFILE_GET(session, rst_assist.page_id.file);
        rst_assist.file_offset = (int64)rst_assist.page_id.page * DEFAULT_PAGE_SIZE(session);
        rst_assist.page_count = rst_calc_ordered_pages(buf + data_offset, (uint32)ctx->read_size - data_offset,
            DEFAULT_PAGE_SIZE(session));
        while (bak->extended[rst_assist.page_id.file] == 0) {
            CT_LOG_RUN_WAR("[RESTORE] page_file %u has not been extend.", rst_assist.page_id.file);
            cm_sleep(BAK_WAIT_FILE_EXTEND_MS);
        }
        if (rst_save_pages(session, ctx, (page_head_t *)(buf + data_offset), rst_assist) != CT_SUCCESS) {
            return CT_ERROR;
        }

        /* page_count <= ctx->read_size / DEFAULT_PAGE_SIZE(session), data_offset cannot overflow */
        data_offset += DEFAULT_PAGE_SIZE(session) * rst_assist.page_count;
        zero_pages_offsets = 0;
    }

    return bak->failed ? CT_ERROR : CT_SUCCESS;
}

static status_t rst_restore_datafiles(knl_session_t *session, bak_context_t *ctx, bak_process_t *write_ctx)
{
    bak_t *bak = &ctx->bak;
    int32 left_offset;
    errno_t ret;
    bool32 skip_write = CT_FALSE;

    if (BAK_IS_FULL_BUILDING(bak)) {
        rst_build_wait_write_datafile(session, bak, &skip_write);
    } else {
        rst_wait_write_datafile(bak);
    }

    if (skip_write) {
        return CT_SUCCESS;
    }

    while (!bak->failed && bak->progress.stage == BACKUP_DATA_STAGE) {
        if (write_ctx->read_size == 0 || bak_paral_task_enable(session)) {
            cm_sleep(1);
            continue;
        }

        write_ctx->left_size = write_ctx->read_size % (int32)DEFAULT_PAGE_SIZE(session);
        left_offset = write_ctx->read_size - write_ctx->left_size;
        write_ctx->read_size -= write_ctx->left_size;

        if (rst_restore_datafile(session, bak, write_ctx, write_ctx->backup_buf.aligned_buf,
                                 bak->local.name) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (write_ctx->left_size > 0) {
            ret = memmove_s(write_ctx->backup_buf.aligned_buf, BACKUP_BUFFER_SIZE(bak),
                            write_ctx->backup_buf.aligned_buf + left_offset, write_ctx->left_size);
            knl_securec_check(ret);
        }

        write_ctx->read_size = 0;
    }

    return bak->failed ? CT_ERROR : CT_SUCCESS;
}

static status_t rst_regist_archive(knl_session_t *session, uint32 *last_arvhied_asn)
{
    database_t *db = &session->kernel->db;
    uint32 rst_id = db->ctrl.core.resetlogs.rst_id;
    uint32 archive_asn = *last_arvhied_asn + 1;

    if (arch_try_regist_archive(session, rst_id, &archive_asn) != CT_SUCCESS) {
        return CT_ERROR;
    }

    *last_arvhied_asn = archive_asn - 1;
    return CT_SUCCESS;
}

status_t arch_try_regist_archive_by_dbstor(knl_session_t *session, uint32 *asn, uint32 rst_id,
                                           uint64 start_lsn, uint64 end_lsn, uint32 inst_id)
{
    char file_name[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    bool32 is_first = CT_TRUE;
    arch_file_name_info_t file_name_info = {rst_id, *asn, inst_id, CT_FILE_NAME_BUFFER_SIZE,
                                            start_lsn, end_lsn, file_name};
    uint64 *find_lsn = &file_name_info.start_lsn;

    for (;;) {
        if (is_first) {
            arch_set_archive_log_name_with_lsn(session, ARCH_DEFAULT_DEST, &file_name_info);
            *find_lsn = file_name_info.end_lsn + 1;
            is_first = CT_FALSE;
        } else {
            status_t status = arch_find_archive_log_name(session, &file_name_info);
            if (status != CT_SUCCESS) {
                return CT_SUCCESS;
            }
            *find_lsn = file_name_info.end_lsn + 1;
        }

        if (!cm_exist_device(cm_device_type(file_name), file_name)) {
            return CT_SUCCESS;
        }

        if (arch_regist_archive(session, file_name) != CT_SUCCESS) {
                return CT_ERROR;
        }
        *asn = file_name_info.asn;
    }
    return CT_SUCCESS;
}

static status_t rst_regist_archive_by_dbstor(knl_session_t *session, uint32 *last_archived_asn)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    int32 file_index = bak->file_count - 1;

    if (file_index < 0) {
        return CT_SUCCESS;
    }
    
    if (bak->files[file_index].type != BACKUP_ARCH_FILE) {
        return CT_SUCCESS;
    }
    
    if (arch_try_regist_archive_by_dbstor(session, last_archived_asn, bak->files[file_index].rst_id,
                                          bak->files[file_index].start_lsn, bak->files[file_index].end_lsn,
                                          bak->files[file_index].inst_id) != CT_ERROR) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t rst_build_wait_head(knl_session_t *session)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;

    if (!bak->is_building) {
        return CT_SUCCESS;
    }

    while (!bak->failed && !bak->head_is_built) {
        if (bak_check_session_status(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
        cm_sleep(1);
    }
    return bak->failed ? CT_ERROR : CT_SUCCESS;
}

static void get_asn_and_file_id(knl_session_t *session, uint32 file_index, uint32* asn, uint32* file_id)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;

    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;
    if (bak->files[file_index].type == BACKUP_ARCH_FILE) {
        *asn = ctrlinfo->lrp_point.asn;
        if (DB_IS_RAFT_ENABLED(session->kernel)) {
            *file_id = bak->log_first_slot; // for raft, standby log slot must be same as primary log slot
            CT_LOG_RUN_INF("[RESTORE] raft log fisrt is %u", *file_id);
        }
    } else {
        *asn = ctrlinfo->lrp_point.asn - 1;
        *file_id = bak->files[file_index].id;
    }
}

void rst_update_process_data_size(knl_session_t *session, bak_context_t *ctx)
{
    knl_instance_t *kernel = session->kernel;
    datafile_t *datafile = NULL;
    log_file_ctrl_t *logfile = NULL;
    uint32 i;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);

    for (i = 0; i < CT_MAX_DATA_FILES; i++) {
        datafile = &kernel->db.datafiles[i];
        if (!datafile->ctrl->used || !DATAFILE_IS_ONLINE(datafile)) {
            continue;
        }
        if (ctx->bak.rst_file.file_type == RESTORE_DATAFILE && ctx->bak.rst_file.file_id != datafile->ctrl->id) {
            continue;
        }
        bak_update_progress(&ctx->bak, (uint64)datafile->ctrl->size);
    }
    if (ctx->bak.rst_file.file_type == RESTORE_DATAFILE) {
        return;
    }
    for (i = 0; i < logfile_set->logfile_hwm; i++) {
        logfile = logfile_set->items[i].ctrl;
        if (LOG_IS_DROPPED(logfile->flg)) {
            continue;
        }
        bak_update_progress(&ctx->bak, (uint64)logfile->size);
    }
    return;
}

static status_t rst_amend_files(knl_session_t *session, uint32 last_log_index)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    uint32 bak_last_asn;
    uint32 log_first = CT_INVALID_ID32;
    uint32 last_archived_asn;
    uint64 data_size;

    data_size = db_get_datafiles_size(session) + db_get_logfiles_size(session);
    bak_set_progress(session, BACKUP_BUILD_STAGE, data_size);
    rst_update_process_data_size(session, ctx);

    /* it just return after extending the datafile to repair when restore the specifical file */
    if (ctx->bak.rst_file.file_type == RESTORE_DATAFILE) {
        return CT_SUCCESS;
    }

    bool32 is_dbstor = BAK_IS_DBSOTR(bak);
    if (!is_dbstor) {
        get_asn_and_file_id(session, last_log_index, &last_archived_asn, &log_first);
    }

    if (!bak->is_building) {
        if (is_dbstor) {
            last_archived_asn = 0;
            bak_last_asn = last_archived_asn;
            if (rst_regist_archive_by_dbstor(session, &last_archived_asn) != CT_SUCCESS) {
                return CT_ERROR;
            }
        } else {
            bak_last_asn = last_archived_asn;
            if (rst_regist_archive(session, &last_archived_asn) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
        if (last_archived_asn != bak_last_asn) {
            log_first = CT_INVALID_ID32; // database has more archived logfiles, reset first online log index
        }
    }

    if (rst_amend_ctrlinfo(session, last_archived_asn + 1, log_first) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

char *rst_fetch_filename(bak_t *bak)
{
    int32 pos = bak->depend_num - bak->curr_id;

    if (bak->depend_num > 0 && pos > 0) {
        CT_LOG_DEBUG_INF("[BACKUP]depend_num2 %u, file dest %s", pos, (bak->depends + pos - 1)->file_dest);
        return (bak->depends + pos - 1)->file_dest;
    }
    CT_LOG_DEBUG_INF("[BACKUP]depend_num3 %u, record path %s", pos, bak->record.path);
    return bak->record.path;
}

static void rst_write_all_files(knl_session_t *session, bak_t *bak, bak_process_t *write_ctx, uint32 *last_log_index)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;

    while (BAK_IS_FULL_BUILDING(bak) && bak->progress.stage < BACKUP_CTRL_STAGE) {
        if (bak->failed) {
            return;
        }
        cm_sleep(1);
    }

    while (!bak->failed) {
        if (RST_NEED_RESTORE_CTRLFILE(bak)) {
            if (rst_restore_ctrlfiles(session) != CT_SUCCESS) {
                bak->failed = CT_TRUE;
                break;
            }
        }

        if (RST_NEED_RESTORE_DATAFILE(bak)) {
            if (rst_create_datafiles(session, write_ctx) != CT_SUCCESS) {
                bak->failed = CT_TRUE;
                break;
            }
            CT_LOG_RUN_INF("[RESTORE] create datafiles finished");

            if (rst_restore_datafiles(session, ctx, write_ctx) != CT_SUCCESS) {
                bak->failed = CT_TRUE;
                break;
            }
            CT_LOG_RUN_INF("[RESTORE] restore datafiles finished");
        }

        while (!bak->failed && bak->progress.stage == BACKUP_DATA_STAGE) {
            cm_sleep(1);
        }

        if (bak->progress.stage >= BACKUP_LOG_STAGE) {
            break;
        }
    }
    // ensure start msg and curr_file_index have been updated with BACKUP_LOG_STAGE by read thread
    if (!bak->failed && RST_NEED_RESTORE_ARCHFILE(bak)) {
        if (rst_restore_logfiles(session, last_log_index) != CT_SUCCESS) {
            bak->failed = CT_TRUE;
        }
        CT_LOG_RUN_INF("[RESTORE] restore logfiles finished, current backupset %s", rst_fetch_filename(bak));
    }
}

void rst_write_proc(thread_t *thread)
{
    bak_process_t *write_ctx = (bak_process_t *)thread->argument;
    knl_session_t *session = write_ctx->session;
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    build_progress_t *build_progress = &bak->progress.build_progress;
    uint32 i;
    uint32 last_log_index = CT_INVALID_ID32;

    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());
    rst_write_all_files(session, bak, write_ctx, &last_log_index);
    /* only restore arch files need not amend files */
    if (!bak->failed && bak->rst_file.file_type != RESTORE_ARCHFILE) {
        if (BAK_IS_FULL_BUILDING(bak) && !bak->is_first_link) {
            last_log_index = build_progress->curr_file_index;
        }

        if (rst_build_wait_head(session) != CT_SUCCESS) {
            bak->failed = CT_TRUE;
        }
        CT_LOG_RUN_INF("[RESTORE] all files have heen written");

        if (rst_delete_track_file(session, bak, CT_FALSE) != CT_SUCCESS) {
            bak->failed = CT_TRUE;
        }

        if (session->kernel->attr.clustered) {
            if (dtc_rst_amend_files(session, bak->file_count - 1) != CT_SUCCESS) {
                bak->failed = CT_TRUE;
            }
        } else {
            if (rst_amend_files(session, last_log_index) != CT_SUCCESS) {
                bak->failed = CT_TRUE;
            }
        }
    }

    bak->progress.stage = BACKUP_WRITE_FINISHED;
    for (i = 0; i < CT_MAX_DATA_FILES; i++) {
        cm_close_device(write_ctx->file_type[i], &write_ctx->datafiles[i]);
        write_ctx->datafile_name[i][0] = '\0';
    }

    if (cm_device_type(session->kernel->db.ctrlfiles.items[0].name) == DEV_TYPE_RAW) {
        rst_close_ctrl_file(&session->kernel->db.ctrlfiles);
    }

    bak_set_error(&bak->error_info);
    KNL_SESSION_CLEAR_THREADID(session);
}

static status_t rst_set_params(bak_t *bak, knl_restore_t *param)
{
    errno_t ret;

    bak->is_building = CT_FALSE;
    bak->is_first_link = CT_TRUE;
    bak->need_check = CT_FALSE;

    (void)cm_text2str(&param->path, bak->record.path, CT_FILE_NAME_BUFFER_SIZE);
    (void)cm_text2str(&param->policy, bak->record.policy, CT_BACKUP_PARAM_SIZE);
    bak->record.device = param->device;
    bak->record.data_type = knl_dbs_is_enable_dbs() ? DATA_TYPE_DBSTOR : DATA_TYPE_FILE;
    bak->proc_count = param->parallelism == 0 ? BAK_DEFAULT_PARALLELISM : param->parallelism;
    bak->encrypt_info.encrypt_alg = param->crypt_info.encrypt_alg;
    (void)cm_text2str(&param->spc_name, bak->spc_name, CT_NAME_BUFFER_SIZE);

    if (bak->encrypt_info.encrypt_alg != ENCRYPT_NONE) {
        ret = strncpy_sp(bak->password, CT_PASSWORD_BUFFER_SIZE, param->crypt_info.password,
                         strlen(param->crypt_info.password));
        knl_securec_check(ret);
        bak_replace_password(param->crypt_info.password);
    }
    bak->backup_buf_size = param->buffer_size;
    bak->repair_type = param->repair_type;
    CT_RETURN_IFERR(srv_get_param_bool32("RESTOR_ARCH_PREFER_BAK_SET", &bak->prefer_bak_set));
    return CT_SUCCESS;
}

status_t rst_alloc_resource(knl_session_t *session, bak_t *bak)
{
    char uds_path[CT_FILE_NAME_BUFFER_SIZE];
    int32 ret;

    /* malloc space for bak->backup_buf,bak->depends and bak->compress_buf at once, so it is multiplied by 3 */
    if (cm_aligned_malloc(BACKUP_BUFFER_SIZE(bak) * 3, "bak buffer", &bak->align_buf) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)BACKUP_BUFFER_SIZE(bak) * 3, "backup");
        return CT_ERROR;
    }
    bak->backup_buf = bak->align_buf.aligned_buf;
    bak->depends = (bak_dependence_t *)(bak->backup_buf + BACKUP_BUFFER_SIZE(bak));
    /* 2 * CT_BACKUP_BUFFER_SIZE for size of bak->backup_buf and size of bak->depends */
    bak->compress_buf = bak->backup_buf + 2 * BACKUP_BUFFER_SIZE(bak);

    if (BAK_IS_UDS_DEVICE(bak)) {
        ret = sprintf_s(uds_path, CT_FILE_NAME_BUFFER_SIZE, BAK_SUN_PATH_FORMAT,
            session->kernel->home, session->kernel->instance_name);
        knl_securec_check_ss(ret);
        if (bak_init_uds(&bak->remote.uds_link, uds_path) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    // recv_stream buffers are released in bak_end
    if (cm_aligned_malloc(BACKUP_BUFFER_SIZE(bak), "rst stream buf0", &bak->recv_stream.bufs[0]) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cm_aligned_malloc(BACKUP_BUFFER_SIZE(bak), "rst stream buf1", &bak->recv_stream.bufs[1]) != CT_SUCCESS) {
        return CT_ERROR;
    }
    bak->recv_stream.buf_size = BACKUP_BUFFER_SIZE(bak);

    return CT_SUCCESS;
}

static status_t rst_alloc_write_resource(bak_process_t *common_proc)
{
    knl_session_t *session = common_proc->session;
    errno_t ret;
    bak_t *bak = &session->kernel->backup_ctx.bak;

    /* malloc space for ctx->backup_buf and ctx->fill_buf at once, so it is multiplied by 2 */
    if (cm_aligned_malloc((int64)BACKUP_BUFFER_SIZE(bak) * 2, "backup process",
        &common_proc->backup_buf) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)BACKUP_BUFFER_SIZE(bak) * 2, "backup process");
        return CT_ERROR;
    }

    common_proc->fill_buf = common_proc->backup_buf.aligned_buf + BACKUP_BUFFER_SIZE(bak);
    ret = memset_sp(common_proc->fill_buf, BACKUP_BUFFER_SIZE(bak), 0, BACKUP_BUFFER_SIZE(bak));
    knl_securec_check(ret);

    if (cm_aligned_malloc((int64)BACKUP_BUFFER_SIZE(bak), "backup process", &common_proc->encrypt_ctx.encrypt_buf) !=
        CT_SUCCESS) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)BACKUP_BUFFER_SIZE(bak), "backup process");
        return CT_ERROR;
    }

    if (cm_aligned_malloc((int64)DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT, "backup process",
        &common_proc->table_compress_ctx.read_buf) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT, "backup process");
        return CT_ERROR;
    }

    if (cm_aligned_malloc((int64)DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT, "backup process",
        &common_proc->table_compress_ctx.unzip_buf) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT, "backup process");
        return CT_ERROR;
    }

    if (cm_aligned_malloc((int64)DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT, "backup process",
        &common_proc->table_compress_ctx.zip_buf) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT, "backup process");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t rst_init_paral_proc_resource(bak_process_t *common_proc, bak_process_t *proc, bak_context_t *ctx, uint32 i)
{
    knl_session_t *session = common_proc->session;
    proc->read_size = 0;
    proc->write_size = 0;
    proc->left_size = 0;
    proc->proc_id = i;
    proc->is_free = CT_FALSE;
    proc->read_failed = CT_FALSE;
    proc->write_failed = CT_FALSE;
    proc->read_execute = CT_FALSE;
    proc->fill_buf = common_proc->fill_buf;
    if (cm_aligned_malloc((int64)BACKUP_BUFFER_SIZE(&ctx->bak), "restore process", &proc->backup_buf) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (bak_init_rw_buf(proc, (int64)BACKUP_BUFFER_SIZE(&ctx->bak), "RESTORE") != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)BACKUP_BUFFER_SIZE(&ctx->bak), "restore process");
        return CT_ERROR;
    }
    if (cm_aligned_malloc((int64)BACKUP_BUFFER_SIZE(&ctx->bak), "restore process",
        &proc->compress_ctx.compress_buf) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cm_aligned_malloc((int64)BACKUP_BUFFER_SIZE(&ctx->bak), "restore process",
        &proc->encrypt_ctx.encrypt_buf) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cm_aligned_malloc((int64)DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT, "restore process",
        &proc->table_compress_ctx.read_buf) != CT_SUCCESS) {
            return CT_ERROR;
        }
    if (cm_aligned_malloc((int64)DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT, "restore process",
        &proc->table_compress_ctx.unzip_buf) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cm_aligned_malloc((int64)DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT, "restore process",
        &proc->table_compress_ctx.zip_buf) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cm_create_thread(rst_paral_task_write_proc, 0, proc, &proc->write_thread) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cm_create_thread(bak_paral_task_proc, 0, proc, &proc->thread) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t rst_start_write_thread(bak_process_t *common_proc)
{
    bak_context_t *backup_ctx = &common_proc->session->kernel->backup_ctx;
    bak_process_t *proc = NULL;
    uint32 proc_count = backup_ctx->bak.proc_count;

    common_proc->read_size = 0;
    common_proc->write_size = 0;
    common_proc->left_size = 0;
    common_proc->proc_id = BAK_COMMON_PROC;

    if (rst_alloc_write_resource(common_proc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cm_create_thread(rst_write_proc, 0, common_proc, &common_proc->thread) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!bak_paral_task_enable(common_proc->session)) {
        return CT_SUCCESS;
    }

    for (uint32 i = 1; i <= proc_count; i++) {
        proc = &backup_ctx->process[i];
        if (rst_init_paral_proc_resource(common_proc, proc, backup_ctx, i) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    bak_wait_paral_proc(common_proc->session, CT_FALSE);
    return CT_SUCCESS;
}

status_t rst_prepare(knl_session_t *session, knl_restore_t *param)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;

    if (rst_set_params(bak, param) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (param->file_type == RESTORE_ARCHFILE) {
        bak->rst_file.file_type = RESTORE_ARCHFILE;
    }

    /* file repair does't need arch init */
    if (bak->rst_file.file_type != RESTORE_DATAFILE) {
        if (arch_init(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    bak_reset_process_ctrl(bak, CT_TRUE);
    bak_reset_stats(session);
    if (rst_alloc_resource(session, bak) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (badblock_init(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (rst_start_write_thread(&ctx->process[BAK_COMMON_PROC]) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t rst_read_data(bak_context_t *ctx, void *buf, int32 buf_size, int32 *read_size, bool32 *end, uint64 file_offset)
{
    bak_stat_t *stat = &ctx->bak.stat;
    bak_t *bak = &ctx->bak;

    if (ctx->bak.is_building || BAK_IS_UDS_DEVICE(bak)) {
        if (rst_agent_read(&ctx->bak, (char *)buf, (uint32)buf_size, read_size, end) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        status_t s = cm_read_device_nocheck(ctx->bak.local.type, ctx->bak.local.handle,
                                            file_offset, buf, buf_size, read_size);
        if (s != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (ctx->block_repairing) {
            return CT_SUCCESS;
        }
        (void)cm_atomic_inc(&stat->reads);

        *end = (*read_size < buf_size);
    }

    bak_update_progress(&ctx->bak, (uint64)*read_size);
    CT_LOG_DEBUG_INF("[RESTORE] read size :%u file name:%s", *read_size, bak->local.name);
    return CT_SUCCESS;
}

status_t rst_read_check_size(int32 read_size, int32 expect_size, const char *file_name)
{
    if (read_size != expect_size) {
        CT_LOG_RUN_ERR("[RESTORE] read incomplete data from %s", file_name);
        CT_THROW_ERROR(ERR_READ_DEVICE_INCOMPLETE, read_size, expect_size);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t rst_read_start(knl_session_t *session, bak_file_type_t file_type, uint32 file_index,
                               uint32 file_id, uint32 sec_id)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    char *path = NULL;
    uint32 read_type;
    bak_attr_t *attr = &bak->record.attr;

    path = rst_fetch_filename(bak);

    ctx->process[BAK_COMMON_PROC].read_size = 0;
    ctx->process[BAK_COMMON_PROC].write_size = 0;

    if (bak->is_building) {
        bak->remote.remain_data_size = 0;
    } else if (BAK_IS_UDS_DEVICE(bak)) {
        read_type = bak_get_package_type(file_type);
        if (bak_agent_file_start(bak, path, read_type, file_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
        bak->remote.remain_data_size = 0;
    } else {
        bak_generate_bak_file(session, path, file_type, file_index, file_id, sec_id, bak->local.name);
        bak->local.type = cm_device_type(bak->local.name);
        if (cm_open_device(bak->local.name, bak->local.type, O_BINARY | O_SYNC | O_RDWR, &bak->local.handle) !=
            CT_SUCCESS) {
            return CT_ERROR;
        }
        CT_LOG_RUN_INF("[RESTORE] file name:%s, type=%d, handle=%d",
                       bak->local.name, bak->local.type, bak->local.handle);
    }

    if (file_type != BACKUP_HEAD_FILE && (attr->compress != COMPRESS_NONE)) {
        if (knl_compress_init(bak->record.attr.compress, &bak->compress_ctx, CT_FALSE) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (file_type != BACKUP_HEAD_FILE && (bak->encrypt_info.encrypt_alg != ENCRYPT_NONE)) {
        if (bak_encrypt_init(bak, &ctx->process[BAK_COMMON_PROC].encrypt_ctx, &bak->files[file_index],
            CT_FALSE) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t rst_read_end(knl_session_t *session, bak_t *bak, bak_file_type_t file_type, bak_file_t *file)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;

    if (bak->is_building) {
        if (file_type != BACKUP_HEAD_FILE && (bak->record.attr.compress != COMPRESS_NONE)) {
            knl_compress_end(bak->record.attr.compress, &bak->compress_ctx, CT_FALSE);
        }
        return CT_SUCCESS;
    } else if (BAK_IS_UDS_DEVICE(bak)) {
        if (bak_agent_send_pkg(bak, BAK_PKG_ACK) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        cm_close_device(bak->local.type, &bak->local.handle);
        bak->local.handle = CT_INVALID_HANDLE;
    }

    if (file_type != BACKUP_HEAD_FILE && (bak->record.attr.compress != COMPRESS_NONE)) {
        knl_compress_end(bak->record.attr.compress, &bak->compress_ctx, CT_FALSE);
    }

    if (file_type != BACKUP_HEAD_FILE && (bak->encrypt_info.encrypt_alg != ENCRYPT_NONE)) {
        if (bak_decrypt_end(bak, &ctx->process[BAK_COMMON_PROC].encrypt_ctx, file, CT_FALSE) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t rst_check_encrypt_version(bak_t *bak, bak_head_t *head)
{
    text_t c_cipher, s_cipher;

    // the backup set is encryption version
    if (bak->encrypt_info.encrypt_alg != head->encrypt_info.encrypt_alg) {
        CT_THROW_ERROR(ERR_CRYPTION_ERROR,
                       "the SQL statement does not match the encryption attribute of the backup set");
        return CT_ERROR;
    }

    if (head->encrypt_info.encrypt_alg != ENCRYPT_NONE) {
        cm_str2text(bak->password, &c_cipher);
        cm_str2text(head->sys_pwd, &s_cipher);

        if (cm_check_password(&c_cipher, &s_cipher) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_CRYPTION_ERROR, "Authentication failure");
            return CT_ERROR;
        }

        if (cm_encrypt_KDF2((uchar *)bak->password, (uint32)strlen(bak->password),
            (uchar *)head->encrypt_info.salt, CT_KDF2SALTSIZE, CT_KDF2DEFITERATION,
            (uchar *)bak->key, CT_AES256KEYSIZE) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t rst_set_head(knl_session_t *session, bak_head_t *head, bool32 set_config)
{
    config_t *config = session->kernel->attr.config;
    bak_t *bak = &session->kernel->backup_ctx.bak;
    bak_attr_t *attr = &bak->record.attr;
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;

    attr->backup_type = head->attr.backup_type;
    attr->level = head->attr.level;
    attr->compress = head->attr.compress;
    errno_t ret = strcpy_sp(attr->tag, CT_NAME_BUFFER_SIZE, head->attr.tag);
    knl_securec_check(ret);

    if (rst_check_encrypt_version(bak, head) != CT_SUCCESS) {
        return CT_ERROR;
    }

    bak->file_count = bak->is_building ? bak->file_count : head->file_count;
    ctrlinfo->rcy_point = head->ctrlinfo.rcy_point;
    ctrlinfo->lrp_point = head->ctrlinfo.lrp_point;
    ctrlinfo->scn = head->ctrlinfo.scn;
    ctrlinfo->lsn = head->ctrlinfo.lsn;
    if (session->kernel->attr.clustered) {
        for (uint32 i = 0; i < CT_MAX_INSTANCES; i++) {
            ctrlinfo->dtc_rcy_point[i] = head->ctrlinfo.dtc_rcy_point[i];
            ctrlinfo->dtc_lrp_point[i] = head->ctrlinfo.dtc_lrp_point[i];
        }
    }

    bak->log_first_slot = head->log_fisrt_slot;
    bak->curr_file_index = 0;
    bak->ddl_pitr_lsn = head->ddl_pitr_lsn;
    CT_LOG_RUN_INF("[RESTORE] get ddl pitr lsn %llu from backupset head", head->ddl_pitr_lsn);

    if (!set_config) {
        return CT_SUCCESS;
    }

    if (cm_alter_config(config, "CONTROL_FILES", head->control_files, CONFIG_SCOPE_BOTH, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t rst_restore_config_param(knl_session_t *session)
{
    config_t *config = session->kernel->attr.config;
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bool32 read_end = CT_FALSE;
    int32 read_size;

    if ((BAK_IS_FULL_BUILDING(bak) && !bak->is_first_link) || bak->record.is_repair) {
        return CT_SUCCESS;
    }

    if (rst_read_data(ctx, bak->backup_buf, CT_MAX_CONFIG_LINE_SIZE, &read_size, &read_end, 0) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (rst_read_check_size(read_size, (int32)CT_MAX_CONFIG_LINE_SIZE, "config") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cm_alter_config(config, "CONTROL_FILES", bak->backup_buf, CONFIG_SCOPE_BOTH, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t rst_wait_agent_process(bak_t *bak)
{
    if (!bak->is_building && !BAK_IS_UDS_DEVICE(bak)) {
        return CT_SUCCESS;
    }

    if (bak_agent_wait_pkg(bak, BAK_PKG_FILE_END) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t rst_restore_fileinfo(bak_context_t *ctx, bak_head_t *head, char *buf)
{
    bool32 read_end = CT_FALSE;
    int32 read_size;
    int32 expect_size = bak_get_align_size(ctx->bak.local.type, head->file_count * sizeof(bak_file_t),
                                           CM_CTSTORE_ALIGN_SIZE);
    uint32 head_size = bak_get_align_size(ctx->bak.local.type, sizeof(bak_head_t), CM_CTSTORE_ALIGN_SIZE);

    if (head->file_count == 0) {
        return CT_SUCCESS;
    }

    if (head->file_count > BAK_MAX_FILE_NUM) {
        CT_THROW_ERROR(ERR_INVALID_BACKUPSET, "invalid number of backupset file count");
        return CT_ERROR;
    }

    if (rst_read_data(ctx, buf, expect_size, &read_size, &read_end, head_size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (rst_read_check_size(read_size, expect_size, "backupset file items") != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t rst_restore_dependents(bak_context_t *ctx, bak_head_t *head, char *buf)
{
    bool32 read_end = CT_FALSE;
    int32 read_size;
    int32 expect_size = bak_get_align_size(ctx->bak.local.type, head->depend_num * sizeof(bak_dependence_t),
                                           CM_CTSTORE_ALIGN_SIZE);
    uint32 head_size = bak_get_align_size(ctx->bak.local.type,
                                          sizeof(bak_head_t) + head->file_count * sizeof(bak_file_t),
                                          CM_CTSTORE_ALIGN_SIZE);
    if (head->depend_num == 0) {
        return CT_SUCCESS;
    }

    if (head->depend_num > BAK_MAX_INCR_NUM) {
        CT_THROW_ERROR(ERR_INVALID_BACKUPSET, "invalid number of backupset depentdent count");
        return CT_ERROR;
    }

    CT_LOG_DEBUG_INF("[BACKUP] read catalog");
    if (rst_read_data(ctx, buf, expect_size, &read_size, &read_end, head_size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (rst_read_check_size(read_size, expect_size, "backupset dependent items") != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t rst_set_backupset_info(knl_session_t *session, bak_t *bak, bak_head_t *head, bool32 fetch_catalog,
                                       uint32 version_head_size)
{
    errno_t ret;
    uint32 offset;
    bool32 set_config = !session->kernel->backup_ctx.block_repairing;

    bak_free_compress_context(session, CT_FALSE); // for increment restore, need reset compress algorithm
    bak_free_encrypt_context(session); // for increment restore, need reset encryption
    if (rst_set_head(session, head, set_config) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (bak_alloc_compress_context(session, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (bak_alloc_encrypt_context(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    offset = bak_get_align_size(bak->local.type, version_head_size, CM_CTSTORE_ALIGN_SIZE);
    if (head->file_count > 0) {
        ret = memcpy_sp(bak->files, BAK_MAX_FILE_NUM * sizeof(bak_file_t), (char *)head + offset,
                        head->file_count * sizeof(bak_file_t));
        knl_securec_check(ret);
        offset += bak_get_align_size(bak->local.type, bak->file_count * sizeof(bak_file_t), CM_CTSTORE_ALIGN_SIZE);
    }

    if (!fetch_catalog) {
        return CT_SUCCESS;
    }

    if (head->depend_num > 0) {
        ret = memcpy_sp(bak->depends, BACKUP_BUFFER_SIZE(bak), (char *)head + offset,
                        sizeof(bak_dependence_t) * head->depend_num);
        knl_securec_check(ret);
    }
    bak->depend_num = head->depend_num;

    return CT_SUCCESS;
}

status_t rst_bakcup_version_check(bak_t *bak, bak_head_t *head, uint32 *left_size)
{
    bak_version_t version = head->version;

    if (version.major_ver != BAK_VERSION_MAJOR || version.min_ver != BAK_VERSION_MIN ||
        version.magic != BAK_VERSION_MAGIC) {
        CT_LOG_RUN_WAR("[RESTORE] backupset version mismatch, expected %u-%u-%u, input is %u-%u-%u",
                       BAK_VERSION_MAJOR, BAK_VERSION_MIN, BAK_VERSION_MAGIC,
                       version.major_ver, version.min_ver, version.magic);
    }

    if (version.major_ver < BAK_VERSION_MIN_WITH_ENCRYPTION) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", backupset version is too old");
        return CT_ERROR;
    }

    if (version.major_ver == BAK_VERSION_MIN_WITH_ENCRYPTION && version.min_ver == 0) {
        bak->is_noparal_version = CT_TRUE;
        *left_size = sizeof(bak_old_version_head_t) - sizeof(bak_version_t);
    } else {
        bak->is_noparal_version = CT_FALSE;
        *left_size = sizeof(bak_head_t) - sizeof(bak_version_t);
    }

    return CT_SUCCESS;
}

// only calc main version, for example version 1.0.0.sp001 return strlen(1.0.0)
uint32 rst_get_db_main_version_len(char *db_version)
{
#define MAIN_VERSION_SEG_NUM 3
    char *cur_pos = db_version;
    uint32_t len = 0;
    uint32_t seg_num = 0;

    while (*cur_pos != '\0') {
        if (*cur_pos == '.') {
            seg_num++;
        }
        len++;

        if (seg_num == MAIN_VERSION_SEG_NUM) {
            len--;   // return len need dec last dos.
            break;
        }
        cur_pos++;
    }
    return len;
#undef MAIN_VERSION_SEG_NUM
}

status_t rst_db_version_check(knl_session_t *session, bak_t *bak, bak_head_t *head)
{
    knl_attr_t *attr = &session->kernel->attr;

    if (!attr->restore_check_version) {
        return CT_SUCCESS;
    }

    if (bak->is_noparal_version) {
        return CT_ERROR;
    }

    if (rst_get_db_main_version_len(head->db_version) != rst_get_db_main_version_len(attr->db_version)) {
        CT_LOG_RUN_ERR("[RESTORE] backupset version %s mismatch with db version %s",
            head->db_version, attr->db_version);
        return CT_ERROR;
    }

    if (strncmp(head->db_version, attr->db_version, rst_get_db_main_version_len(head->db_version)) != 0) {
        CT_LOG_RUN_ERR("[RESTORE] backupset version %s mismatch with db version %s",
            head->db_version, attr->db_version);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

/*
 * For example, incremental backupsets include: incr_0(level0),incr_1(level1),incr_2(level1)
 * Block repair only find page from incremental backupset, no need to check.
 * Restore database will first open incr_2 head to find the dependent backupsets,
 * and then restore in the order of incr_0, incr_1, incr_2.
 * Therefore, previous opened backupset tag is the same as next opened backupset base_tag.
 */
static status_t rst_incremental_backset_tag_check(knl_session_t *session, bak_t *bak, bak_head_t *head)
{
    if (session->kernel->backup_ctx.block_repairing) {
        return CT_SUCCESS;
    }

    if (head->attr.level == 1 && !CM_IS_EMPTY_STR(bak->record.attr.tag) &&
        !cm_str_equal_ins(bak->record.attr.tag, head->attr.base_tag)) {
        CT_THROW_ERROR_EX(ERR_INVALID_OPERATION,
            ", backupset with tag %s expected base backupset tag to be %s but found %s.",
            head->attr.tag, head->attr.base_tag, bak->record.attr.tag);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t rst_check_backupset(knl_session_t *session, bak_t *bak, bak_head_t *head)
{
    if (head->attr.backup_type != BACKUP_MODE_FULL && BAK_IS_TABLESPCE_RESTORE(bak)) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION,
                       ", can not restore tablespace from backupset which is not full backupset");
        return CT_ERROR;
    }

    /*
     * There are four backupset types: full database backupset, incremental database backupset,
     * tablespace backupset, archivelog backupset.
     * tablespace backupset must be used for datafile repair.
     * archivelog backupset must be used for archivelog restore.
     * incremental database backupset must be used for database restore.
     */
    if (head->attr.backup_type == BACKUP_MODE_FULL && bak->rst_file.file_type == RESTORE_ARCHFILE) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", because it's a full database backupset");
        return CT_ERROR;
    }

    if (BAK_MODE_IS_INCREMENTAL(head->attr.backup_type) && bak->rst_file.file_type != RESTORE_ALL) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", because it's a incremental backupset");
        return CT_ERROR;
    }

    if (head->attr.backup_type == BACKUP_MODE_TABLESPACE && bak->rst_file.file_type != RESTORE_DATAFILE) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", because it's a tablespace backupset");
        return CT_ERROR;
    }

    if (head->attr.backup_type == BACKUP_MODE_ARCHIVELOG && bak->rst_file.file_type != RESTORE_ARCHFILE) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", because it's a archivelog backupset");
        return CT_ERROR;
    }

    if (rst_db_version_check(session, bak, head) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", database version and backupset version do not match.");
        return CT_ERROR;
    }

    if (rst_incremental_backset_tag_check(session, bak, head) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (BAK_IS_UDS_DEVICE(bak) && (head->max_buffer_size > bak->backup_buf_size)) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION,
            ", buffer size for restore(%u) cannot be smaller than buffer size for backup(%u).",
            bak->backup_buf_size, head->max_buffer_size);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t rst_restore_backupset_head(knl_session_t *session, bool32 fetch_catalog)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_head_t *head = (bak_head_t *)bak->backup_buf;
    bool32 read_end = CT_FALSE;
    int32 read_size;
    uint32 head_size = 0;
    uint32 left_size; // head size without version : sizeof(bak_head_t) - sizeof(bak_version_t)

    if (rst_read_data(ctx, bak->backup_buf, sizeof(bak_version_t), &read_size, &read_end, head_size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (rst_read_check_size(read_size, (int32)sizeof(bak_version_t), "backupset version") != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (rst_bakcup_version_check(bak, head, &left_size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    head_size = sizeof(bak_version_t);
    if (rst_read_data(ctx, bak->backup_buf + head_size, left_size, &read_size, &read_end, head_size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (rst_read_check_size(read_size, (int32)left_size, "backupset head") != CT_SUCCESS) {
        return CT_ERROR;
    }

    head_size += left_size;
    if (bak_head_verify_checksum(session, head, (uint32)head_size, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (rst_check_backupset(session, bak, head) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (rst_restore_fileinfo(ctx, head, bak->backup_buf + head_size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    head_size += head->file_count * sizeof(bak_file_t);
    if (rst_restore_dependents(ctx, head, bak->backup_buf + head_size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    head_size += head->depend_num * sizeof(bak_dependence_t);
    if (bak_head_verify_checksum(session, head, head_size, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (rst_set_backupset_info(session, bak, head, fetch_catalog, left_size + sizeof(bak_version_t)) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t rst_read_head_file(knl_session_t *session, bool32 fetch_catalog)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    uint64 data_size;

    data_size = sizeof(bak_head_t) + BAK_MAX_FILE_NUM * sizeof(bak_file_t);
    bak_set_progress(session, BACKUP_HEAD_STAGE, data_size);

    if (rst_read_start(session, BACKUP_HEAD_FILE, 0, 0, 0) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (rst_restore_backupset_head(session, fetch_catalog) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (rst_wait_agent_process(bak) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (rst_read_end(session, bak, BACKUP_HEAD_FILE, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t rst_wait_write(bak_t *bak, bak_process_t *ctx)
{
    while (!bak->failed && ctx->read_size != 0) {
        cm_sleep(1);
        continue;
    }

    return bak->failed ? CT_ERROR : CT_SUCCESS;
}

static status_t rst_write_to_write_buf(bak_t *bak, bak_process_t *ctx, const char *buf, int32 buf_size,
                                       uint64 file_offset)
{
    errno_t ret;
    int32 offset = 0;
    int32 remain_size = buf_size;
    int32 data_size;

    while (!bak->failed && remain_size > 0) {
        if (rst_wait_write(bak, ctx) != CT_SUCCESS) {
            return CT_ERROR;
        }

        data_size = remain_size > ((int32)BACKUP_BUFFER_SIZE(bak) - ctx->left_size) ?
                    ((int32)BACKUP_BUFFER_SIZE(bak) - ctx->left_size) : remain_size;
        ret = memcpy_sp(ctx->backup_buf.aligned_buf + ctx->left_size,
            (uint32)(BACKUP_BUFFER_SIZE(bak) - ctx->left_size), buf + offset, (uint32)data_size);
        knl_securec_check(ret);
        ctx->curr_offset = file_offset + (uint64)offset;
        ctx->write_size = 0;
        CM_MFENCE;
        ctx->read_size = ctx->left_size + data_size;

        offset += data_size;
        remain_size -= data_size;
    }

    return bak->failed ? CT_ERROR : CT_SUCCESS;
}

static status_t rst_decompress_to_write_buf(bak_t *bak, bak_process_t *ctx, char *buf, uint32 buf_size,
                                            bool32 last_package, uint64 file_offset)
{
    knl_compress_set_input(bak->record.attr.compress, &bak->compress_ctx, buf, buf_size);

    for (;;) {
        if (knl_decompress(bak->record.attr.compress, &bak->compress_ctx, last_package, bak->compress_buf,
            BACKUP_BUFFER_SIZE(bak)) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (rst_write_to_write_buf(bak, ctx, bak->compress_buf, (int32)bak->compress_ctx.write_len,
                                   file_offset) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (bak->compress_ctx.finished) {
            break;
        }
    }

    return CT_SUCCESS;
}

static status_t rst_read_file_data(knl_session_t *session)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bool32 read_end = CT_FALSE;
    int32 read_size = 0;
    uint32 buf_content_size;
    uint64 file_size = bak->files[bak->curr_file_index].size;
    uint64 file_offset = 0;
    bool32 compressed = (bak->record.attr.compress != COMPRESS_NONE);
    bool32 encrypted = (bak->encrypt_info.encrypt_alg != ENCRYPT_NONE);
    bak_process_t *proc = &ctx->process[BAK_COMMON_PROC];
    char *use_buf = bak->backup_buf;
    int32 buf_size = (int32)(BACKUP_BUFFER_SIZE(bak) - bak->compress_ctx.last_left_size);
    int32 request_size;
    bak->compress_ctx.last_left_size = 0;

    while (!bak->failed && !read_end) {
        if (bak_check_session_status(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
        request_size = (file_size - file_offset <= buf_size) ? (file_size - file_offset) : buf_size;
        if (request_size == 0) {
            break;
        }

        if (rst_read_data(ctx, bak->backup_buf + bak->compress_ctx.last_left_size,
                          request_size, &read_size, &read_end, file_offset) != CT_SUCCESS) {
            bak->failed = CT_TRUE;
            break;
        }
        read_end = (file_size == file_offset + read_size);

        if (encrypted) {
            if (rst_decrypt_data(proc, bak->backup_buf + bak->compress_ctx.last_left_size, read_size,
                                 bak->compress_ctx.last_left_size) != CT_SUCCESS) {
                return CT_ERROR;
            }
            use_buf = proc->encrypt_ctx.encrypt_buf.aligned_buf;
        }

        if (compressed) {
            buf_content_size = (uint32)read_size + bak->compress_ctx.last_left_size;
            if (rst_decompress_to_write_buf(bak, proc, use_buf, buf_content_size, read_end,
                                            file_offset) != CT_SUCCESS) {
                bak->failed = CT_TRUE;
                break;
            }
        } else {
            if (rst_write_to_write_buf(bak, proc, use_buf, read_size, file_offset) != CT_SUCCESS) {
                bak->failed = CT_TRUE;
                return CT_ERROR;
            }
        }
        file_offset += read_size;
    }

    if (!bak->is_building && file_size != file_offset) {
        CT_LOG_RUN_ERR("[RESTORE] unexpected read size %llu, expected file size is %llu, file name %s", file_offset,
                       file_size, bak->local.name);
        CT_THROW_ERROR(ERR_FILE_SIZE_MISMATCH, (int64)file_offset, file_size);
        bak->failed = CT_TRUE;
        return CT_ERROR;
    }
    return bak->failed ? CT_ERROR : CT_SUCCESS;
}

status_t rst_read_file(knl_session_t *session, uint32 file_index)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;

    if (rst_read_start(session, bak->files[file_index].type, file_index, bak->files[file_index].id,
                       bak->files[file_index].sec_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (rst_read_file_data(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (rst_wait_write(bak, &ctx->process[BAK_COMMON_PROC]) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (rst_read_end(session, bak, bak->files[file_index].type, &bak->files[file_index]) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static bool32 rst_skip_file(knl_session_t *session, bak_file_t *file)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    datafile_t *df = NULL;

    /* when executing 'restore filerecover', only the specific datafile will be restore */
    if (bak->rst_file.file_type == RESTORE_DATAFILE) {
        if (file->type != BACKUP_DATA_FILE || bak->rst_file.file_id != file->id) {
            return CT_TRUE;
        } else {
            bak->rst_file.exist_repair_file = CT_TRUE;
            return CT_FALSE;
        }
    }

    if (file->type != BACKUP_DATA_FILE) {
        return CT_FALSE;
    }

    df = DATAFILE_GET(session, file->id);
    return (bool32)((BAK_IS_TABLESPCE_RESTORE(bak) && !DATAFILE_IS_ONLINE(df)));
}

status_t rst_find_duplicative_archfile(knl_session_t *session, bak_file_t *file, bool32 *found_duplicate)
{
    bool32 found_start_lsn = CT_FALSE;
    bool32 found_end_lsn = CT_FALSE;
    local_arch_file_info_t file_info;
    DIR *arch_dir;
    struct dirent *arch_dirent;
    char *arch_path = session->kernel->attr.arch_attr[0].local_path;
    bool32 is_dbstor = BAK_IS_DBSOTR(&session->kernel->backup_ctx.bak);
    bool32 dbid_equal = CT_FALSE;
    if ((arch_dir = opendir(arch_path)) == NULL) {
        return CT_ERROR;
    }
    while ((arch_dirent = readdir(arch_dir)) != NULL) {
        if (bak_convert_archfile_name(arch_dirent->d_name, &file_info,
                                      file->inst_id, file->rst_id, is_dbstor) == CT_FALSE) {
            continue;
        }
        if (bak_check_archfile_dbid(session, arch_path, arch_dirent->d_name, &dbid_equal) != CT_SUCCESS) {
            closedir(arch_dir);
            return CT_ERROR;
        }
        if (dbid_equal != CT_TRUE) {
            continue;
        }
        if (is_dbstor) {
            if (file_info.local_end_lsn >= file->end_lsn && file_info.local_start_lsn < file->end_lsn) {
                found_end_lsn = CT_TRUE;
            }
            if (file_info.local_end_lsn >= file->start_lsn + 1 && file_info.local_start_lsn < file->start_lsn + 1) {
                found_start_lsn = CT_TRUE;
            }
            if (found_end_lsn && found_start_lsn) {
                *found_duplicate = CT_TRUE;
                break;
            }
        } else {
            if (file_info.local_asn == file->id) {
                *found_duplicate = CT_TRUE;
                break;
            }
        }
    }
    closedir(arch_dir);
    return CT_SUCCESS;
}
 
bool32 rst_skip_for_duplicative_archfile(knl_session_t *session, bak_file_t *cur_file, bak_file_t *next_file)
{
    if (cur_file->type == BACKUP_ARCH_FILE) {
        cur_file->skipped = CT_FALSE;
        if (session->kernel->backup_ctx.bak.prefer_bak_set == CT_TRUE) {
            return CT_FALSE;
        }
        if (next_file->type != BACKUP_ARCH_FILE || next_file->inst_id != cur_file->inst_id) {
            bool32 found_duplicate = CT_FALSE;
            if (rst_find_duplicative_archfile(session, cur_file, &found_duplicate) != CT_SUCCESS) {
                return CT_FALSE;
            }
            if (found_duplicate) {
                cur_file->skipped = CT_TRUE;
                CT_LOG_RUN_INF("[RESTORE] restore logfile %u from arch dir", cur_file->id);
                return CT_TRUE;
            }
        }
    }
    return CT_FALSE;
}

status_t rst_stream_read_file(knl_session_t *session)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    rst_stream_buf_t *recv_stream = &bak->recv_stream;
    bak_process_t *common_proc = &session->kernel->backup_ctx.process[BAK_COMMON_PROC];
    log_file_head_t *head = (log_file_head_t *)common_proc->backup_buf.aligned_buf;
    uint32 bak_index = bak->curr_file_index;
    uint32 file_id = bak->files[bak_index].id;
    bool32 ignore_logfile = CT_FALSE;
    char *path = rst_fetch_filename(bak);
    bak_file_type_t type = bak->files[bak->curr_file_index].type;

    if (bak->rst_file.file_type == RESTORE_ALL) {
        if (rst_wait_ctrlfile_ready(bak) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (BAK_IS_UDS_DEVICE(bak)) {
        /* build is not needed */
        if (bak_agent_file_start(bak, path, bak_get_package_type(type), file_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    bak->remote.remain_data_size = 0;

    rst_init_recv_stream(bak);
    if (rst_stream_read_prepare(session, recv_stream, head, &ignore_logfile) != CT_SUCCESS) {
        return CT_ERROR;
    }
    rst_assign_stream_restore_task(session, &common_proc->ctrl);

    if (rst_recv_stream_data(session, ignore_logfile) != CT_SUCCESS) {
        return CT_ERROR;
    }
    bak_wait_paral_proc(session, CT_FALSE);

    if (BAK_IS_UDS_DEVICE(bak)) {
        if (bak_agent_send_pkg(bak, BAK_PKG_ACK) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (BAK_IS_FULL_BUILDING(bak) && (bak->files[bak->curr_file_index].type == BACKUP_LOG_FILE ||
        bak->files[bak->curr_file_index].type == BACKUP_ARCH_FILE)) {
        build_progress_t *build_progress = &bak->progress.build_progress;
        build_progress->asn = head->asn;
        build_progress->stage = BACKUP_LOG_STAGE;
        build_progress->curr_file_index = bak->curr_file_index;
    }

    if (bak->files[bak->curr_file_index].type == BACKUP_ARCH_FILE && bak->rst_file.file_type == RESTORE_ALL) {
        if (arch_try_record_archinfo(session, ARCH_DEFAULT_DEST, common_proc->ctrl.name, head) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t rst_read_files(knl_session_t *session, bak_file_type_t type)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    bak_process_t *proc = NULL;

    while (!bak->failed && bak->curr_file_index < bak->file_count) {
        if (bak_check_session_status(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (bak->files[bak->curr_file_index].type > type) {
            break;
        }
        if (rst_skip_file(session, &bak->files[bak->curr_file_index]) ||
            rst_skip_for_duplicative_archfile(session, &bak->files[bak->curr_file_index],
                                              &bak->files[bak->curr_file_index + 1])) {
            bak->curr_file_index++;
            continue;
        }

        if (type >= BACKUP_DATA_FILE && type <= BACKUP_ARCH_FILE && bak_paral_task_enable(session)) {
            if (BAK_IS_UDS_DEVICE(bak)) {
                if (rst_stream_read_file(session)) {
                    return CT_ERROR;
                }
            } else {
                if (bak_get_free_proc(session, &proc, CT_FALSE) != CT_SUCCESS) {
                    return CT_ERROR;
                }
                if (bak_assign_restore_task(session, proc) != CT_SUCCESS) {
                    return CT_ERROR;
                }
            }
        } else {
            if (rst_read_file(session, bak->curr_file_index) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }

        bak->curr_file_index++;
    }
    bak_wait_paral_proc(session, CT_FALSE);
    return bak->failed ? CT_ERROR : CT_SUCCESS;
}

status_t rst_wait_ctrlfile_ready(bak_t *bak)
{
    while (!bak->ctrlfile_completed) {
        if (bak->failed) {
            return CT_ERROR;
        }
        cm_sleep(10);
    }
    return CT_SUCCESS;
}

static status_t rst_read_ctrl_file(knl_session_t *session, bak_t *bak)
{
    uint32 data_size = CTRL_MAX_PAGES(session) * CT_DFLT_CTRL_BLOCK_SIZE;

    bak->ctrlfile_completed = CT_FALSE;
    bak_set_progress(session, BACKUP_CTRL_STAGE, data_size);
    if (rst_read_files(session, BACKUP_CTRL_FILE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (rst_wait_ctrlfile_ready(bak) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

uint64 rst_calc_bakfiles_size(knl_session_t *session, bak_t *bak, bak_file_type_t type)
{
    uint64 size = 1; // avoid zero
    uint32 id = bak->curr_file_index;

    while (id < bak->file_count) {
        if (bak->files[id].type > type) {
            break;
        }

        if (!rst_skip_file(session, &bak->files[id])) {
            size += bak->files[id].size;
        }
        id++;
    }

    return size;
}

static status_t rst_read_datafile(knl_session_t *session, bak_t *bak)
{
    uint64 data_size;
    if (bak->is_building) {
        data_size = (uint64)(db_get_datafiles_size(session) * ESTIMATE_VALID_DATA_PERCENT);
    } else {
        data_size = rst_calc_bakfiles_size(session, bak, BACKUP_DATA_FILE);
    }
    bak_set_progress(session, BACKUP_DATA_STAGE, data_size);
    if (rst_read_files(session, BACKUP_DATA_FILE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (bak->rst_file.file_type == RESTORE_DATAFILE) {
        if (!bak->rst_file.exist_repair_file) {
            CT_THROW_ERROR(ERR_FILE_NOT_EXIST, "in backupset the", "specifical");
            return CT_ERROR;
        }
        bak->rst_file.rcy_point = bak->record.ctrlinfo.rcy_point;
    }

    return CT_SUCCESS;
}

static void rst_wait_logfiles_created(bak_t *bak)
{
    while (!bak->logfiles_created) {
        if (bak->failed) {
            break;
        }
        cm_sleep(1);
    }
}

static status_t rst_read_archfile(knl_session_t *session, bak_t *bak)
{
    uint64 data_size;
    if (bak->is_building) {
        data_size = db_get_logfiles_size(session);
    } else {
        data_size = rst_calc_bakfiles_size(session, bak, BACKUP_ARCH_FILE);
    }
    bak->logfiles_created = CT_FALSE;
    bak_set_progress(session, BACKUP_LOG_STAGE, data_size);
    rst_wait_logfiles_created(bak);

    bak->curr_arch_id = 0;
    if (rst_read_files(session, BACKUP_ARCH_FILE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (bak_agent_command(bak, BAK_PKG_SET_END) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t rst_restore_one_bakset(knl_session_t *session, bool32 fetch_catalog)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;

    if (bak->is_building) {
        if (rst_restore_config_param(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (bak_agent_command(bak, BAK_PKG_SET_START) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (rst_read_head_file(session, fetch_catalog) != CT_SUCCESS) {
            return CT_ERROR;
        }

        /* it must be restore full backset firstly */
        if (fetch_catalog && bak->depend_num > 0) {
            if (rst_read_head_file(session, CT_FALSE) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }

    if (RST_NEED_RESTORE_CTRLFILE(bak)) {
        if (rst_read_ctrl_file(session, bak) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (RST_NEED_RESTORE_DATAFILE(bak)) {
        if (rst_read_datafile(session, bak) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t rst_restore_all_incremental_backset(knl_session_t *session, bak_t *bak)
{
    while (!bak->failed) {
        if (bak_check_session_status(session) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (bak->curr_id == bak->depend_num) {
            break;
        }

        bak->curr_id++;

        /* only restore all database will open ctrl file */
        if (bak->rst_file.file_type == RESTORE_ALL) {
            rst_close_ctrl_file(&session->kernel->db.ctrlfiles);
        }

        if (bak_agent_command(bak, BAK_PKG_SET_END) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (rst_restore_one_bakset(session, CT_FALSE) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t rst_restore(knl_session_t *session)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;

    if (bak_agent_command(bak, BAK_PKG_START) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (rst_restore_one_bakset(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (bak->depend_num > 0) {
        if (rst_restore_all_incremental_backset(session, bak) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (!bak->failed && RST_NEED_RESTORE_ARCHFILE(bak)) {
        if (rst_read_archfile(session, bak) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    bak->progress.stage = BACKUP_READ_FINISHED;

    if (!bak->failed) {
        if (bak_agent_command(bak, BAK_PKG_END) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (BAK_IS_UDS_DEVICE(bak)) {
            cs_uds_disconnect(&bak->remote.uds_link);
        }
    }

    return CT_SUCCESS;
}

void rst_wait_write_end(bak_t *ctrl)
{
    while (!ctrl->failed && ctrl->progress.stage != BACKUP_WRITE_FINISHED) {
        cm_sleep(1);
    }
}

status_t rst_proc(knl_session_t *session)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    status_t status = CT_SUCCESS;

    if (rst_restore(session) != CT_SUCCESS) {
        bak->failed = CT_TRUE;
        status = CT_ERROR;
    }

    rst_wait_write_end(bak);

    /* when recover datafile, bak_end would be called after recovering datafile to lastest */
    if (bak->rst_file.file_type != RESTORE_DATAFILE) {
        bak_end(session, CT_TRUE);
    }

    if (bak->failed) {
        status = CT_ERROR;
    }

    return status;
}

void rst_backend_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    bak_context_t *ctx = &session->kernel->backup_ctx;

    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());
    (void)rst_proc(session);
    KNL_SESSION_CLEAR_THREADID(session);
    bak_set_error(&ctx->bak.error_info);
}

status_t rst_check_backupset_path(knl_restore_t *param)
{
    char path[CT_FILE_NAME_BUFFER_SIZE];

    if (param->path.len > CT_MAX_BACKUP_PATH_LEN) {
        CT_THROW_ERROR(ERR_EXCEED_MAX_BACKUP_PATH_LEN, T2S(&param->path), CT_MAX_BACKUP_PATH_LEN);
        return CT_ERROR;
    }

    (void)cm_text2str(&param->path, path, CT_FILE_NAME_BUFFER_SIZE);

    // the path does not actually exist in nbu restore
    if (cm_check_exist_special_char(path, (uint32)strlen(path)) ||
        (param->device == DEVICE_DISK && !cm_dir_exist(path))) {
        CT_THROW_ERROR(ERR_INVALID_DIR, path);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t rst_restore_database(knl_session_t *session, knl_restore_t *param)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    uint32 paral_count = param->parallelism == 0 ? BAK_DEFAULT_PARALLELISM : param->parallelism;
    status_t status;
    if (bak_set_running(session, ctx) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_BACKUP_IN_PROGRESS, "restore");
        return CT_ERROR;
    }

    if (param->type == RESTORE_BLOCK_RECOVER) {
        ctx->block_repairing = CT_TRUE;
        status = abr_restore_block_recover(session, param);
        bak_unset_running(session, ctx);
        ctx->block_repairing = CT_FALSE;
        return status;
    }

    ctx->bak.arch_keep_compressed = session->kernel->attr.restore_keep_arch_compressed;
    CT_LOG_RUN_INF("[RESTORE] restore start, device:%d, policy:%s, paral count %u, path:%s, arch_compressed %u, "
        "buffer size:%uM", param->device, T2S(&param->policy), paral_count, T2S_EX(&param->path),
        ctx->bak.arch_keep_compressed, param->buffer_size / SIZE_M(1));

    if (rst_prepare(session, param) != CT_SUCCESS) {
        bak_end(session, CT_TRUE);
        return CT_ERROR;
    }

    if (param->disconnect) {
        if (cm_create_thread(rst_backend_proc, 0, session->kernel->sessions[SESSION_ID_BRU],
                             &ctx->bak.restore_thread) != CT_SUCCESS) {
            bak_end(session, CT_TRUE);
            return CT_ERROR;
        }
        return CT_SUCCESS;
    }

    return rst_proc(session);
}

status_t dtc_init_logset_for_pitr(knl_session_t *session, uint8 node_id)
{
    knl_instance_t *kernel = session->kernel;
    database_t *db = &kernel->db;
    log_file_t *logfile = NULL;
    logfile_set_t *file_set = LOGFILE_SET(session, node_id);
    uint32 i;
    status_t ret;

    if (session->kernel->id == node_id) {
        return CT_SUCCESS;
    }

    // mount redo files
    file_set->logfile_hwm = dtc_get_ctrl(session, node_id)->log_hwm;
    file_set->log_count = dtc_get_ctrl(session, node_id)->log_count;

    for (i = 0; i < file_set->logfile_hwm; i++) {
        logfile = &file_set->items[i];
        logfile->ctrl = (log_file_ctrl_t *)db_get_log_ctrl_item(db->ctrl.pages, i, sizeof(log_file_ctrl_t),
                                                                db->ctrl.log_segment, node_id);
        if (LOG_IS_DROPPED(logfile->ctrl->flg)) {
            continue;
        }
        logfile->handle = CT_INVALID_HANDLE;
        /* closed in dtc_rcy_close_logfile */
        ret = cm_open_device(logfile->ctrl->name, logfile->ctrl->type, knl_redo_io_flag(session), &logfile->handle);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to open %s ", logfile->ctrl->name);
            return CT_ERROR;
        }
    }
    CT_LOG_RUN_INF("[DB] init logset for node %u finish.", node_id);
    return CT_SUCCESS;
}

status_t dtc_log_prepare_for_pitr(knl_session_t *se)
{
    knl_instance_t *kernel = se->kernel;
    uint32 rst_id = kernel->db.ctrl.core.resetlogs.rst_id;
    for (uint32 i = 0; i < kernel->db.ctrl.core.node_count; i++) {
        uint32 archive_asn = dtc_get_ctrl(se, i)->rcy_point.asn;
        CT_LOG_RUN_INF("[RESTORE] archive_asn %llu.", (uint64)archive_asn);
        if (dtc_rst_regist_archive(se, &archive_asn, rst_id, i) != CT_SUCCESS) {
            return CT_ERROR;
        }
        CT_LOG_RUN_INF("[RESTORE] after register, archive_asn %llu.", (uint64)archive_asn);
        if (dtc_init_logset_for_pitr(se, i) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RESTORE] init logset for node %u failed.", i);
            return CT_ERROR;
        }
        uint32 max_asn;
        if (arch_try_arch_redo_by_nodeid(se, &max_asn, i) != CT_SUCCESS) {
            return CT_ERROR;
        }
        CT_LOG_RUN_INF("[RESTORE] find redo max_asn %llu.", (uint64)max_asn);

        archive_asn = MAX(archive_asn, max_asn);
        archive_asn += 1;
        
        CT_LOG_RUN_INF("[RESTORE] set redo asn %llu.", (uint64)archive_asn);

        if (dtc_bak_reset_logfile(se, archive_asn, CT_INVALID_ID32, i) != CT_SUCCESS) {
            return CT_ERROR;
        }
        log_reset_inactive_head(se);
    }
    return CT_SUCCESS;
}

status_t log_prepare_for_pitr_dbstor(knl_session_t *se)
{
    arch_ctrl_t *last = arch_get_last_log(se);
    uint32 rst_id = se->kernel->db.ctrl.core.resetlogs.rst_id;
    uint32 archive_asn = last->asn + 1;

    if (arch_try_regist_archive_by_dbstor(se, &archive_asn, rst_id, last->start_lsn,
                                          last->end_lsn, 0) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t dtc_log_prepare_pitr(knl_session_t *se)
{
    bool32 is_dbstor = knl_dbs_is_enable_dbs();
    if (se->kernel->attr.clustered) {
        if (is_dbstor) {
            return dtc_rst_amend_all_arch_file_dbstor(se);
        }
        return dtc_log_prepare_for_pitr(se);
    } else {
        if (is_dbstor) {
            return log_prepare_for_pitr_dbstor(se);
        }
        return log_prepare_for_pitr(se);
    }
}

#ifdef __cplusplus
}
#endif
