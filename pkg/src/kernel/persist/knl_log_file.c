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
 * knl_log_file.c
 *
 *
 * IDENTIFICATION
 * src/kernel/persist/knl_log_file.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_persist_module.h"
#include "knl_log_file.h"
#include "cm_file.h"
#include "knl_context.h"
#include "knl_ctrl_restore.h"
#include "dtc_database.h"

static uint32 log_check_logfile_exist(knl_session_t *session, uint32 hwl, const text_t *log_name,
                                      bool32 *exist)
{
    uint32 i;
    log_file_ctrl_t *ctrl = NULL;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);

    for (i = 0; i < hwl; i++) {
        ctrl = logfile_set->items[i].ctrl;
        if (cm_filename_equal(log_name, ctrl->name)) {
            *exist = CT_TRUE;
            return i;
        }
    }

    *exist = CT_FALSE;
    return 0;
}

static bool32 log_check_filepath_exist(text_t *log_name)
{
    char file_name[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    char file_path[CT_FILE_NAME_BUFFER_SIZE] = { 0 };

    (void)cm_text2str(log_name, file_name, CT_FILE_NAME_BUFFER_SIZE);
    cm_trim_filename(file_name, CT_FILE_NAME_BUFFER_SIZE, file_path);

    if (!cm_exist_device_dir(cm_device_type(file_path), file_path)) {
        log_name->str[strlen(file_path)] = '\0';
        return CT_FALSE;
    }

    return CT_TRUE;
}


static status_t log_precheck(knl_session_t *session, knl_alterdb_def_t *def)
{
    bool32 is_exist = CT_FALSE;
    int64 min_size;
    knl_device_def_t *dev_def = NULL;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    log_file_ctrl_t *ctrl = NULL;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);

    for (uint32 i = 0; i < logfile_set->logfile_hwm; i++) {
        ctrl = logfile_set->items[i].ctrl;
        if (LOG_IS_DROPPED(ctrl->flg)) {
            continue;
        }
    }

    // log_count <= 256, count <= 256, so sum total value is smaller than max uint32 value
    if (logfile_set->log_count + def->logfile.logfiles.count > CT_MAX_LOG_FILES) {
        CT_THROW_ERROR(ERR_TOO_MANY_OBJECTS, CT_MAX_LOG_FILES, "logfile");
        return CT_ERROR;
    }
    // log_count <= 256, count <= 256, so sum total value is smaller than max uint32 value
    if (dtc_my_ctrl(session)->log_count + def->logfile.logfiles.count > CT_MAX_LOG_FILES * CT_MAX_INSTANCES) {
        CT_THROW_ERROR(ERR_TOO_MANY_OBJECTS, CT_MAX_LOG_FILES, "logfile");
        return CT_ERROR;
    }

    min_size = (int64)LOG_MIN_SIZE(session, kernel);
    for (uint32 i = 0; i < def->logfile.logfiles.count; i++) {
        dev_def = (knl_device_def_t *)cm_galist_get(&def->logfile.logfiles, i);
        if (dev_def->size <= min_size) {
            CT_THROW_ERROR(ERR_LOG_FILE_SIZE_TOO_SMALL, min_size);
            return CT_ERROR;
        }

        if (DB_IS_RAFT_ENABLED(kernel) && dev_def->size != ctrl->size) {
            CT_THROW_ERROR(ERR_LOG_SIZE_NOT_MATCH);
            return CT_ERROR;
        }

        if (dev_def->name.str[dev_def->name.len - 1] == '/' || (dev_def->name.str[dev_def->name.len - 1] == '\\')) {
            CT_THROW_ERROR(ERR_LOG_FILE_NAME_MISS);
            return CT_ERROR;
        }

        (void)log_check_logfile_exist(session, logfile_set->logfile_hwm, &dev_def->name, &is_exist);
        if (is_exist) {
            dev_def->name.str[dev_def->name.len] = '\0';
            CT_THROW_ERROR(ERR_OBJECT_EXISTS, "file or directory", dev_def->name.str);
            return CT_ERROR;
        }

        if (!log_check_filepath_exist(&dev_def->name)) {
            CT_THROW_ERROR(ERR_DIR_NOT_EXISTS, dev_def->name.str);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static uint32 log_find_hole_idx(knl_session_t *session, uint32 hwm, bool32 *found)
{
    log_file_ctrl_t *ctrl = NULL;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);

    for (uint32 i = 0; i < hwm; i++) {
        ctrl = logfile_set->items[i].ctrl;
        if (LOG_IS_DROPPED(ctrl->flg)) {
            *found = CT_TRUE;
            return i;
        }
    }

    *found = CT_FALSE;
    return CT_INVALID_ID32;
}

status_t db_alter_add_logfile(knl_session_t *session, knl_alterdb_def_t *def)
{
    uint32 slot, hole_inx;
    bool32 hole_found = CT_FALSE;
    knl_device_def_t *dev_def = NULL;
    log_file_t *logfile = NULL;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    rmon_t *rmon_ctx = &session->kernel->rmon_ctx;
    database_t *db = &kernel->db;
    log_context_t *ctx = &kernel->redo_ctx;
    rd_altdb_logfile_t rd;
    int64 block_num;
    errno_t err;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);

    if (log_precheck(session, def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    for (uint32 i = 0; i < def->logfile.logfiles.count; i++) {
        dev_def = (knl_device_def_t *)cm_galist_get(&def->logfile.logfiles, i);

        hole_inx = log_find_hole_idx(session, logfile_set->logfile_hwm, &hole_found);
        if (hole_found) {
            knl_panic_log(logfile_set->log_count < logfile_set->logfile_hwm,
                          "the log_count is more than log_hwm, "
                          "panic info: log_count %u log_hwm %u",
                          logfile_set->log_count, logfile_set->logfile_hwm);
            slot = hole_inx;
        } else {
            knl_panic_log(logfile_set->log_count == logfile_set->logfile_hwm,
                          "the log_count is not equal to log_hwm, "
                          "panic info: log_count %u log_hwm %u",
                          logfile_set->log_count, logfile_set->logfile_hwm);
            slot = logfile_set->log_count;
        }

        logfile = &logfile_set->items[slot];
        logfile->ctrl = (log_file_ctrl_t *)db_get_log_ctrl_item(db->ctrl.pages, slot, sizeof(log_file_ctrl_t),
                                                                db->ctrl.log_segment, kernel->id);
        logfile->ctrl->file_id = (int32)slot;
        logfile->ctrl->size = dev_def->size;
        logfile->ctrl->node_id = dev_def->node_id;
        logfile->ctrl->block_size = dev_def->block_size == 0 ? CT_DFLT_LOG_BLOCK_SIZE : (uint16)dev_def->block_size;
        block_num = logfile->ctrl->size / (int16)logfile->ctrl->block_size;
        INT32_OVERFLOW_CHECK(block_num);
        (void)cm_text2str(&dev_def->name, logfile->ctrl->name, CT_FILE_NAME_BUFFER_SIZE);
        logfile->ctrl->type = cm_device_type(logfile->ctrl->name);
        logfile->ctrl->status = LOG_FILE_UNUSED;

        if (cm_build_device(logfile->ctrl->name, logfile->ctrl->type, kernel->attr.xpurpose_buf,
            CT_XPURPOSE_BUFFER_SIZE, logfile->ctrl->size, knl_redo_io_flag(session),
            CT_FALSE, &logfile->handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to build %s ", logfile->ctrl->name);
            return CT_ERROR;
        }

        logfile->head.first = CT_INVALID_ID64;
        logfile->head.last = CT_INVALID_ID64;
        logfile->head.write_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size);
        logfile->head.asn = CT_INVALID_ASN;
        logfile->head.block_size = (int32)logfile->ctrl->block_size;
        logfile->head.rst_id = 0;
        logfile->head.cmp_algorithm = COMPRESS_NONE;
        logfile->head.dbid = db->ctrl.core.dbid;
        status_t ret = memset_sp(logfile->head.unused, CT_LOG_HEAD_RESERVED_BYTES, 0, CT_LOG_HEAD_RESERVED_BYTES);
        knl_securec_check(ret);

        if (cm_open_device(logfile->ctrl->name, logfile->ctrl->type, knl_redo_io_flag(session),
                           &logfile->handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to open %s ", logfile->ctrl->name);
            cm_remove_device(logfile->ctrl->type, logfile->ctrl->name);
            return CT_ERROR;
        }

        if (lsnd_open_specified_logfile(session, slot) != CT_SUCCESS) {
            cm_close_device(logfile->ctrl->type, &logfile->handle);
            cm_remove_device(logfile->ctrl->type, logfile->ctrl->name);
            return CT_ERROR;
        }

        log_lock_logfile(session);
        log_flush_head(session, logfile);
        log_unlock_logfile(session);

        uint32 change_num = hole_found ? 0 : 1;
        dtc_my_ctrl(session)->log_count++;
        dtc_my_ctrl(session)->log_hwm += change_num;
        logfile_set->log_count++;
        logfile_set->logfile_hwm += change_num;
        if (kernel->attr.clustered) {
            dtc_node_ctrl_t *ctrl = dtc_get_ctrl(session, kernel->id);
            ctrl->log_count++;
            ctrl->log_hwm++;
        }

        LOG_SET_DROPPED(logfile->ctrl->flg);

        if (cm_add_device_watch(logfile->ctrl->type, rmon_ctx->watch_fd, logfile->ctrl->name, &logfile->wd) !=
            CT_SUCCESS) {
            CT_LOG_RUN_WAR("[RMON]: failed to add monitor of logfile %s", logfile->ctrl->name);
        }

        rd.op_type = RD_ADD_LOGFILE;
        rd.slot = slot;
        rd.node_id = dev_def->node_id;
        rd.size = logfile->ctrl->size;
        rd.block_size = (int32)logfile->ctrl->block_size;
        err = strcpy_sp(rd.name, CT_FILE_NAME_BUFFER_SIZE, logfile->ctrl->name);
        knl_securec_check(err);
        rd.hole_found = hole_found;
        log_put(session, RD_LOGIC_OPERATION, &rd, sizeof(rd_altdb_logfile_t), LOG_ENTRY_FLAG_NONE);

        knl_commit(session);

        log_lock_logfile(session);
        LOG_UNSET_DROPPED(logfile->ctrl->flg);
        ctx->logfile_hwm = logfile_set->logfile_hwm;
        ctx->files = logfile_set->items;
        log_add_freesize(session, slot);
        log_unlock_logfile(session);
        if (db_save_log_ctrl(session, slot, dev_def->node_id) != CT_SUCCESS) {
            cm_remove_device(logfile->ctrl->type, logfile->ctrl->name);
            CM_ABORT(0, "[DB] ABORT INFO: failed to save whole control file when alter database");
        }
    }

    return CT_SUCCESS;
}

status_t db_alter_drop_logfile(knl_session_t *session, knl_alterdb_def_t *def)
{
    uint32 inx;
    uint32 log_count;
    bool32 is_exist = CT_FALSE;
    knl_device_def_t *dev_def;
    log_file_t *logfile = NULL;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    log_context_t *ctx = &kernel->redo_ctx;
    rmon_t *rmon_ctx = &kernel->rmon_ctx;
    rd_altdb_logfile_t rd;
    errno_t err;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);
    uint32 node_id;

    dev_def = (knl_device_def_t *)cm_galist_get(&def->logfile.logfiles, 0);

    inx = log_check_logfile_exist(session, dtc_my_ctrl(session)->log_hwm, &dev_def->name, &is_exist);
    if (!is_exist) {
        CT_THROW_ERROR(ERR_LOG_FILE_NOT_EXIST);
        return CT_ERROR;
    }

    logfile = &logfile_set->items[inx];

    log_count = log_get_count(session);
    if (log_count <= CT_MIN_LOG_FILES) {
        CT_THROW_ERROR(ERR_LOG_FILE_NOT_ENOUGH);
        return CT_ERROR;
    }

    log_lock_logfile(session);
    if (!log_file_can_drop(ctx, inx) ||
        (ctx->free_size - log_file_freesize(logfile) < LOG_KEEP_SIZE(session, session->kernel))) {
        CT_THROW_ERROR(ERR_LOG_IN_USE);
        log_unlock_logfile(session);
        return CT_ERROR;
    }

    /* remove datafile from resource monitor */
    if (cm_file_exist(logfile->ctrl->name)) {
        if (cm_rm_device_watch(logfile->ctrl->type, rmon_ctx->watch_fd, &logfile->wd) != CT_SUCCESS) {
            CT_LOG_RUN_WAR("[RMON]: failed to remove monitor of logfile %s", logfile->ctrl->name);
        }
    }

    cm_close_device(logfile->ctrl->type, &logfile->handle);
    if (cm_remove_device(logfile->ctrl->type, logfile->ctrl->name) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DB] failed to remove %s ", logfile->ctrl->name);
        log_unlock_logfile(session);
        return CT_ERROR;
    }

    rd.op_type = RD_DROP_LOGFILE;
    err = strcpy_sp(rd.name, CT_FILE_NAME_BUFFER_SIZE, logfile->ctrl->name);
    knl_securec_check(err);

    log_decrease_freesize(ctx, logfile);
    LOG_SET_DROPPED(logfile->ctrl->flg);
    err = memset_sp(logfile->ctrl->name, CT_FILE_NAME_BUFFER_SIZE, 0, CT_FILE_NAME_BUFFER_SIZE);
    knl_securec_check(err);
    node_id = logfile->ctrl->node_id;
    log_unlock_logfile(session);

    dtc_my_ctrl(session)->log_count--;
    logfile_set->log_count--;

    if (db_save_log_ctrl(session, inx, node_id) != CT_SUCCESS) {
        CM_ABORT(0, "[DB] ABORT INFO: failed to save whole control file when alter database");
    }

    lsnd_close_specified_logfile(session, inx);
    log_put(session, RD_LOGIC_OPERATION, &rd, sizeof(rd_altdb_logfile_t), LOG_ENTRY_FLAG_NONE);
    knl_commit(session);
    return CT_SUCCESS;
}

void rd_alter_add_logfile(knl_session_t *session, log_entry_t *log)
{
    rd_altdb_logfile_t *rd = (rd_altdb_logfile_t *)log->data;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    log_context_t *ctx = &kernel->redo_ctx;
    log_file_t *logfile = NULL;
    char dev_name_str[CT_FILE_NAME_BUFFER_SIZE];
    text_t dev_name;
    bool32 is_exist = CT_FALSE;
    errno_t err;
    int32 size;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);

    knl_panic(!DB_IS_CLUSTER(session)); /* redesign in daac for alter add/delete log */

    err = memset_sp(dev_name_str, CT_FILE_NAME_BUFFER_SIZE, 0, CT_FILE_NAME_BUFFER_SIZE);
    knl_securec_check(err);
    if (db_change_storage_path(&kernel->attr.log_file_convert, rd->name, CT_FILE_NAME_BUFFER_SIZE) != CT_SUCCESS) {
        return;
    }
    err = strcpy_sp(dev_name_str, CT_FILE_NAME_BUFFER_SIZE, rd->name);
    knl_securec_check(err);
    dev_name.str = dev_name_str;
    dev_name.len = (uint32)strlen(dev_name_str);
    (void)log_check_logfile_exist(session, dtc_my_ctrl(session)->log_hwm, &dev_name, &is_exist);
    if (is_exist) {
        return;
    }

    if (!session->log_diag) {
        cm_latch_x(&session->kernel->db.ddl_latch.latch, session->id, NULL);
    }

    logfile = &logfile_set->items[rd->slot];
    logfile->ctrl->size = rd->size;
    logfile->ctrl->file_id = (int32)rd->slot;
    logfile->ctrl->node_id = (uint8)rd->node_id;
    logfile->ctrl->block_size = (uint16)rd->block_size;
    err = strcpy_sp(logfile->ctrl->name, CT_FILE_NAME_BUFFER_SIZE, rd->name);
    knl_securec_check(err);
    logfile->ctrl->type = cm_device_type(logfile->ctrl->name);
    logfile->ctrl->status = LOG_FILE_UNUSED;

    if (cm_build_device(logfile->ctrl->name, logfile->ctrl->type, kernel->attr.xpurpose_buf, CT_XPURPOSE_BUFFER_SIZE,
        logfile->ctrl->size, knl_redo_io_flag(session), CT_FALSE, &logfile->handle) != CT_SUCCESS) {
        if (!session->log_diag) {
            cm_unlatch(&session->kernel->db.ddl_latch.latch, NULL);
        }
        CT_LOG_RUN_ERR("[DB] failed to build file %s", logfile->ctrl->name);
        return;
    }

    logfile->head.first = CT_INVALID_ID64;
    logfile->head.last = CT_INVALID_ID64;
    logfile->head.write_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size);
    logfile->head.asn = CT_INVALID_ASN;
    logfile->head.block_size = (int32)logfile->ctrl->block_size;
    logfile->head.rst_id = 0;

    if (cm_open_device(logfile->ctrl->name, logfile->ctrl->type, knl_redo_io_flag(session),
        &logfile->handle) != CT_SUCCESS) {
        if (!session->log_diag) {
            cm_unlatch(&session->kernel->db.ddl_latch.latch, NULL);
        }
        CT_LOG_RUN_ERR("[DB] failed to open %s ", logfile->ctrl->name);
        return;
    }

    log_calc_head_checksum(session, &logfile->head);

    err = memset_sp(ctx->logwr_head_buf, logfile->ctrl->block_size, 0, logfile->ctrl->block_size);
    knl_securec_check(err);
    *(log_file_head_t *)ctx->logwr_head_buf = logfile->head;
    size = CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size);
    if (cm_write_device(logfile->ctrl->type, logfile->handle, 0, ctx->logwr_head_buf,
        size) != CT_SUCCESS) {
        if (!session->log_diag) {
            cm_unlatch(&session->kernel->db.ddl_latch.latch, NULL);
        }
        CT_LOG_RUN_ERR("[DB] failed to write %s ", logfile->ctrl->name);
        CT_THROW_ERROR(ERR_FLUSH_REDO_FILE_FAILED, logfile->ctrl->name, 0, sizeof(log_file_head_t));
        cm_close_device(logfile->ctrl->type, &logfile->handle);
        return;
    }

    uint32 change_num = rd->hole_found ? 0 : 1;
    dtc_my_ctrl(session)->log_count++;
    dtc_my_ctrl(session)->log_hwm += change_num;
    logfile_set->log_count++;
    logfile_set->logfile_hwm += change_num;

    LOG_SET_DROPPED(logfile->ctrl->flg);

    if (!session->log_diag) {
        cm_unlatch(&session->kernel->db.ddl_latch.latch, NULL);
    }
    log_lock_logfile(session);
    LOG_UNSET_DROPPED(logfile->ctrl->flg);
    ctx->logfile_hwm = logfile_set->logfile_hwm;
    ctx->files = logfile_set->items;
    log_add_freesize(session, rd->slot);
    log_unlock_logfile(session);
    if (db_save_log_ctrl(session, rd->slot, rd->node_id) != CT_SUCCESS) {
        CM_ABORT(0, "[DB] ABORT INFO: failed to save whole control file");
    }

    (void)lsnd_open_specified_logfile(session, rd->slot);
    (void)cm_open_device(logfile->ctrl->name, logfile->ctrl->type, knl_redo_io_flag(session),
                         &kernel->lrpl_ctx.log_handle[rd->slot]);
    if (KNL_GBP_ENABLE(session->kernel)) {
        (void)cm_open_device(logfile->ctrl->name, logfile->ctrl->type, knl_redo_io_flag(session),
                             &kernel->gbp_aly_ctx.log_handle[rd->slot]);
    }
}

void print_alter_add_logfile(log_entry_t *log)
{
    rd_altdb_logfile_t *rd = (rd_altdb_logfile_t *)log->data;
    (void)printf("alter add logfile slot:%u,size:%lld,block_size:%d,name:%s,hole_found:%u\n",
        rd->slot, rd->size, rd->block_size, rd->name, rd->hole_found);
}

void rd_alter_drop_logfile(knl_session_t *session, log_entry_t *log)
{
    rd_altdb_logfile_t *rd = (rd_altdb_logfile_t *)log->data;
    uint32 inx;
    uint32 log_count;
    bool32 is_exist = CT_FALSE;
    char dev_name_str[CT_FILE_NAME_BUFFER_SIZE];
    text_t dev_name;
    log_file_t *logfile = NULL;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    log_context_t *ctx = &kernel->redo_ctx;
    rmon_t *rmon_ctx = &kernel->rmon_ctx;
    lrcv_context_t *lrcv = &kernel->lrcv_ctx;
    errno_t err;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);
    knl_panic(!DB_IS_CLUSTER(session));

    err = memset_sp(dev_name_str, CT_FILE_NAME_BUFFER_SIZE, 0, CT_FILE_NAME_BUFFER_SIZE);
    knl_securec_check(err);
    if (db_change_storage_path(&kernel->attr.log_file_convert, rd->name, CT_FILE_NAME_BUFFER_SIZE) != CT_SUCCESS) {
        return;
    }
    err = strcpy_sp(dev_name_str, CT_FILE_NAME_BUFFER_SIZE, rd->name);
    knl_securec_check(err);
    cm_str2text_safe(dev_name_str, (uint32)strlen(dev_name_str), &dev_name);
    inx = log_check_logfile_exist(session, dtc_my_ctrl(session)->log_hwm, &dev_name, &is_exist);
    if (!is_exist) {
        CT_THROW_ERROR(ERR_LOG_FILE_NOT_EXIST);
        return;
    }

    logfile = &logfile_set->items[inx];
    log_count = log_get_count(session);
    if (log_count <= CT_MIN_LOG_FILES) {
        CT_THROW_ERROR(ERR_LOG_FILE_NOT_ENOUGH);
        return;
    }

    if (!session->log_diag) {
        cm_latch_x(&session->kernel->db.ddl_latch.latch, session->id, NULL);
    }

    /* Wait until specified log file can be dropped. */
    for (;;) {
        log_lock_logfile(session);
        if (log_file_can_drop(ctx, inx) || lrcv->wait_info.waiting || session->killed) {
            break;
        }
        log_unlock_logfile(session);
        ckpt_trigger(session, CT_FALSE, CKPT_TRIGGER_INC);
        cm_sleep(10);
    }

    lsnd_close_specified_logfile(session, inx);
    cm_close_device(logfile->ctrl->type, &logfile->handle);
    cm_close_device(logfile->ctrl->type, &kernel->lrpl_ctx.log_handle[inx]);
    if (KNL_GBP_ENABLE(kernel)) {
        cm_close_device(logfile->ctrl->type, &kernel->gbp_aly_ctx.log_handle[inx]);
    }

    if (cm_exist_device(logfile->ctrl->type, logfile->ctrl->name)) {
        if (cm_rm_device_watch(logfile->ctrl->type, rmon_ctx->watch_fd, &logfile->wd) != CT_SUCCESS) {
            CT_LOG_RUN_WAR("[RMON]: failed to remove monitor of logfile %s", logfile->ctrl->name);
        }
    }

    if (cm_remove_device(logfile->ctrl->type, logfile->ctrl->name) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DB] failed to remove %s ", logfile->ctrl->name);
        log_unlock_logfile(session);
        if (!session->log_diag) {
            cm_unlatch(&session->kernel->db.ddl_latch.latch, NULL);
        }
        return;
    }

    log_decrease_freesize(ctx, logfile);
    LOG_SET_DROPPED(logfile->ctrl->flg);
    err = memset_sp(logfile->ctrl->name, CT_FILE_NAME_BUFFER_SIZE, 0, CT_FILE_NAME_BUFFER_SIZE);
    knl_securec_check(err);
    log_unlock_logfile(session);

    logfile_set->log_count--;
    dtc_node_ctrl_t *ctrl = dtc_get_ctrl(session, session->kernel->id);
    ctrl->log_count--;
    if (db_save_log_ctrl(session, inx, logfile->ctrl->node_id) != CT_SUCCESS) {
        CM_ABORT(0, "[DB] ABORT INFO: failed to save whole control file");
    }

    if (!session->log_diag) {
        cm_unlatch(&session->kernel->db.ddl_latch.latch, NULL);
    }
}

void print_alter_drop_logfile(log_entry_t *log)
{
    rd_altdb_logfile_t *rd = (rd_altdb_logfile_t *)log->data;
    (void)printf("alter drop logfile slot:%u,size:%lld,block_size:%d,name:%s,hole_found:%u\n",
        rd->slot, rd->size, rd->block_size, rd->name, rd->hole_found);
}

status_t db_alter_archive_logfile(knl_session_t *session, knl_alterdb_def_t *def)
{
    knl_device_def_t *device = NULL;
    log_file_t log;
    log_file_ctrl_t log_ctrl;
    log_file_t *logfile = &log;
    logfile->ctrl = &log_ctrl;
    aligned_buf_t log_buf;
    aligned_buf_t arch_buf;
    knl_compress_t compress_ctx;
    bool32 is_continue = CT_FALSE;

    if (DB_STATUS(session) != DB_STATUS_NOMOUNT) {
        CT_THROW_ERROR_EX(ERR_INVALID_OPERATION, ", operation only supported in nomount mode");
        return CT_ERROR;
    }

    if (arch_init(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (arch_redo_alloc_resource(session, &log_buf, &arch_buf, &compress_ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }

    for (uint32 i = 0; i < def->logfile.logfiles.count; i++) {
        device = (knl_device_def_t *)cm_galist_get(&def->logfile.logfiles, i);
        (void)cm_text2str(&device->name, logfile->ctrl->name, CT_MAX_FILE_NAME_LEN);

        if (ctrl_init_logfile_ctrl(session, logfile) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to get logfile %s ctrl info", logfile->ctrl->name);
            cm_aligned_free(&log_buf);
            cm_aligned_free(&arch_buf);
            cm_aligned_free(&compress_ctx.compress_buf);
            knl_compress_free(DEFAULT_ARCH_COMPRESS_ALGO, &compress_ctx, CT_TRUE);
            return CT_ERROR;
        }

        device_type_t type = cm_device_type(logfile->ctrl->name);
        if (arch_archive_redo(session, logfile, arch_buf, log_buf, &is_continue, &compress_ctx) != CT_SUCCESS) {
            cm_close_device(type, &logfile->handle);
            cm_aligned_free(&log_buf);
            cm_aligned_free(&arch_buf);
            cm_aligned_free(&compress_ctx.compress_buf);
            knl_compress_free(DEFAULT_ARCH_COMPRESS_ALGO, &compress_ctx, CT_TRUE);
            return CT_ERROR;
        }

        cm_close_device(type, &logfile->handle);
    }

    cm_aligned_free(&log_buf);
    cm_aligned_free(&arch_buf);
    cm_aligned_free(&compress_ctx.compress_buf);
    knl_compress_free(DEFAULT_ARCH_COMPRESS_ALGO, &compress_ctx, CT_TRUE);
    return CT_SUCCESS;
}

