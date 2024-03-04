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
 * knl_datafile.c
 *
 *
 * IDENTIFICATION
 * src/kernel/tablespace/knl_datafile.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_space_module.h"
#include "knl_datafile.h"
#include "cm_file.h"
#include "knl_context.h"
#include "dtc_dls.h"
#include "dtc_dcs.h"
#include "dtc_dc.h"
#include "dtc_backup.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DF_VIEW_WAIT_INTERVAL   100

void df_build_proc(thread_t *thread);

status_t spc_open_datafile_common(knl_session_t *session, datafile_t *df, int32 *handle, uint8 is_retry)
{
    uint32 io_flag;
    dtc_node_ctrl_t *node_ctrl = dtc_my_ctrl(session);

    if (df->space_id == node_ctrl->swap_space) {
        io_flag = 0;
    } else {
        io_flag = knl_io_flag(session);
    }

    /* datafile can be opened for a long time, closed in spc_close_datafile */
    if (is_retry) {
        return cm_open_device(df->ctrl->name, df->ctrl->type, io_flag, handle);
    } else {
        return cm_open_device_no_retry(df->ctrl->name, df->ctrl->type, io_flag, handle);
    }
}

status_t spc_open_datafile(knl_session_t *session, datafile_t *df, int32 *handle)
{
    return spc_open_datafile_common(session, df, handle, CT_TRUE);
}

status_t spc_open_datafile_no_retry(knl_session_t *session, datafile_t *df, int32 *handle)
{
    return spc_open_datafile_common(session, df, handle, CT_FALSE);
}

void spc_close_datafile(datafile_t *df, int32 *handle)
{
    cm_close_device(df->ctrl->type, handle);
}

status_t spc_read_datafile(knl_session_t *session, datafile_t *df, int32 *handle, int64 offset, void *buf, uint32 size)
{
    if (*handle == -1) {
        if (spc_open_datafile(session, df, handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[SPACE] failed to open datafile %s", df->ctrl->name);
            return CT_ERROR;
        }
    }

    return cm_read_device(df->ctrl->type, *handle, offset, buf, size);
}

status_t spc_write_datafile(knl_session_t *session, datafile_t *df, int32 *handle, int64 offset, const void *buf,
                            int32 size)
{
    uint64 end_pos = (uint64)offset + size;  // max offset size is less than 8T
    status_t status;

    if (*handle == -1) {
        if (spc_open_datafile(session, df, handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[SPACE] failed to open datafile %s", df->ctrl->name);
            return CT_ERROR;
        }
    }
    
    // dbstor can ensure that atomicity of read and write when page size is smaller than 8K
    if (!(cm_dbs_is_enable_dbs() == CT_TRUE && size == CT_UDFLT_VALUE_BUFFER_SIZE)) {
        for (;;) {
            cm_latch_s(&df->block_latch, CT_INVALID_ID32, CT_FALSE, NULL);
            if (!spc_datafile_is_blocked(session, df, (uint64)offset, end_pos)) {
                break;
            }
            cm_unlatch(&df->block_latch, NULL);
            cm_sleep(1);
        }
    }

    status = cm_write_device(df->ctrl->type, *handle, offset, buf, size);
    if (!(cm_dbs_is_enable_dbs() == CT_TRUE && size == CT_UDFLT_VALUE_BUFFER_SIZE)) {
        cm_unlatch(&df->block_latch, NULL);
    }
    return status;
}

status_t df_wait_extend_completed(datafile_t *df)
{
    for (uint32 i = 0; i < DF_PARAL_BUILD_THREAD; i++) {
        df_build_ctx_t *ctx = &df->build_ctx[i];

        while (ctx->status == DF_IS_BUILDING) {
            cm_spin_sleep();
        }

        if (ctx->status == DF_BUILD_FAILED) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

static void spc_extend_datafile_clean(datafile_t *df, int64 thread_cnt)
{
    for (int64 i = 0; i < thread_cnt; i++) {
        df_build_ctx_t *build_ctx = &df->build_ctx[i];
        build_ctx->status = DF_BUILD_FAILED;
        cm_close_thread(&build_ctx->thread);
    }
}

status_t spc_extend_datafile_paral(knl_session_t *session, datafile_t *df, int32 *handle,
    int64 org_size, int64 extend_size_input)
{
    int64 extend_size = extend_size_input;
    int64 size_unit = extend_size / DF_PARAL_BUILD_THREAD;
    df_build_ctx_t *build_ctx = NULL;
    char *buf = session->kernel->attr.xpurpose_buf;

    if (spc_open_datafile(session, df, handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[SPACE] failed to open file %s when extending datafile", df->ctrl->name);
        return CT_ERROR;
    }

    if (cm_truncate_file(*handle, org_size + extend_size) != CT_SUCCESS) {
        cm_close_device(df->ctrl->type, handle);
        return CT_ERROR;
    }

    errno_t ret = memset_sp(buf, (size_t)CT_XPURPOSE_BUFFER_SIZE, 0, (size_t)CT_XPURPOSE_BUFFER_SIZE);
    knl_securec_check(ret);

    for (int64 i = 0; i < DF_PARAL_BUILD_THREAD; i++) {
        build_ctx = &df->build_ctx[i];
        build_ctx->df = df;
        build_ctx->session = session;
        build_ctx->offset = org_size + size_unit * i;
        build_ctx->size = (i == DF_PARAL_BUILD_THREAD - 1) ? extend_size : size_unit;
        build_ctx->buf = buf;
        extend_size -= size_unit;
        build_ctx->status = DF_IS_BUILDING;
        if (cm_create_thread(df_build_proc, 0, build_ctx, &build_ctx->thread) != CT_SUCCESS) {
            spc_extend_datafile_clean(df, i);
            cm_close_device(df->ctrl->type, handle);
            CT_LOG_RUN_ERR("[SPACE] failed to start thread when create datafile %s", df->ctrl->name);
            return CT_ERROR;
        }
    }

    if (df_wait_extend_completed(df) != CT_SUCCESS) {
        spc_extend_datafile_clean(df, DF_PARAL_BUILD_THREAD);
        cm_reset_error();
        CT_THROW_ERROR(ERR_CREATE_FILE, df->ctrl->name, errno);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t spc_extend_datafile_serial(knl_session_t *session, datafile_t *df, int32 *handle, int64 size)
{
    if (spc_open_datafile(session, df, handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[SPACE] failed to open file %s when extending datafile", df->ctrl->name);
        return CT_ERROR;
    }

    return cm_extend_device(df->ctrl->type, *handle, session->kernel->attr.xpurpose_buf, CT_XPURPOSE_BUFFER_SIZE,
        size, session->kernel->attr.build_datafile_prealloc);
}

status_t spc_build_datafile_serial(knl_session_t *session, datafile_t *df, int32 *handle)
{
    char *buf = session->kernel->attr.xpurpose_buf;

    df->ctrl->type = cm_device_type(df->ctrl->name);
    return cm_build_device(df->ctrl->name, df->ctrl->type, buf, CT_XPURPOSE_BUFFER_SIZE, df->ctrl->size,
        knl_io_flag(session), session->kernel->attr.build_datafile_prealloc, handle);
}

status_t spc_extend_datafile(knl_session_t *session, datafile_t *df, int32 *handle, int64 size, bool32 need_redo)
{
#ifndef WIN32
    if (size >= DF_BUILD_PARAL_THRES && session->kernel->attr.build_datafile_parallel) {
        if (spc_extend_datafile_paral(session, df, handle, df->ctrl->size, size) != CT_SUCCESS) {
            (void)spc_truncate_datafile(session, df, handle, df->ctrl->size, need_redo);
            return CT_ERROR;
        }
    } else {
        if (spc_extend_datafile_serial(session, df, handle, size) != CT_SUCCESS) {
            (void)spc_truncate_datafile(session, df, handle, df->ctrl->size, need_redo);
            return CT_ERROR;
        }
    }
#else
    if (spc_extend_datafile_serial(session, df, handle, size) != CT_SUCCESS) {
        (void)spc_truncate_datafile(session, df, handle, df->ctrl->size, need_redo);
        return CT_ERROR;
    }
#endif

    if (db_fsync_file(session, *handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[SPACE] failed to fsync datafile %s", df->ctrl->name);
        (void)spc_truncate_datafile(session, df, handle, df->ctrl->size, need_redo);
        return CT_ERROR;
    }

    cm_spin_lock(&session->kernel->db.ctrl_lock, NULL);
    df->ctrl->size += size;  // max datafile size is 8T
    cm_spin_unlock(&session->kernel->db.ctrl_lock);

    rd_extend_datafile_daac_t daac_redo;
    if (need_redo) {
        rd_extend_datafile_t *redo = &daac_redo.datafile;
        daac_redo.op_type = RD_SPC_EXTEND_DATAFILE_DAAC;
        redo->id = df->ctrl->id;
        redo->size = df->ctrl->size;
        log_put(session, RD_SPC_EXTEND_DATAFILE, redo, sizeof(rd_extend_datafile_t), LOG_ENTRY_FLAG_NONE);
    }

    // There is no need sync extend datafile, if other node extent the extent will get the real size from disk.
    // If write an logic log hear, CKPT process maybe blocked.
    if (db_save_datafile_ctrl(session, df->ctrl->id) != CT_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when extending datafile");
    }

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_EXTEND_DATAFILE_BEFORE_SYNC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    return CT_SUCCESS;
}

status_t spc_extend_datafile_ddl(knl_session_t *session, datafile_t *df, int32 *handle, int64 size, bool32 need_redo)
{
    log_atomic_op_begin(session);

    cm_spin_lock(&session->kernel->db.ctrl_lock, NULL);
    df->ctrl->size += size;  // max datafile size is 8T
    cm_spin_unlock(&session->kernel->db.ctrl_lock);

    rd_extend_datafile_daac_t daac_redo;
    if (need_redo) {
        rd_extend_datafile_t *redo = &daac_redo.datafile;
        daac_redo.op_type = RD_SPC_EXTEND_DATAFILE_DAAC;
        redo->id = df->ctrl->id;
        redo->size = df->ctrl->size;
        log_put(session, RD_SPC_EXTEND_DATAFILE, redo, sizeof(rd_extend_datafile_t), LOG_ENTRY_FLAG_NONE);
        if (DB_IS_CLUSTER(session) && !DAAC_REPLAY_NODE(session)) {
            log_put(session, RD_LOGIC_OPERATION, &daac_redo, sizeof(rd_extend_datafile_daac_t), LOG_ENTRY_FLAG_NONE);
        }
    }

    log_atomic_op_end(session);

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_EXTEND_DATAFILE_BEFORE_LOG_COMMIT_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    
    log_commit(session);

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_EXTEND_DATAFILE_BEFORE_EXTEND_DEVICE_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    status_t sp_ret = CT_SUCCESS;
    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_EXTEND_DATAFILE_FAIL, &sp_ret, CT_ERROR);
#ifndef WIN32
    if (size >= DF_BUILD_PARAL_THRES && session->kernel->attr.build_datafile_parallel) {
        sp_ret = spc_extend_datafile_paral(session, df, handle, df->ctrl->size, size);
    } else {
        sp_ret = spc_extend_datafile_serial(session, df, handle, size);
    }
#else
    sp_ret = spc_extend_datafile_serial(session, df, handle, size);
#endif
    SYNC_POINT_GLOBAL_END;
    if (sp_ret != CT_SUCCESS) {
        (void)spc_truncate_datafile(session, df, handle, df->ctrl->size, need_redo);
        return CT_ERROR;
    }

    if (db_fsync_file(session, *handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[SPACE] failed to fsync datafile %s", df->ctrl->name);
        (void)spc_truncate_datafile(session, df, handle, df->ctrl->size, need_redo);
        return CT_ERROR;
    }

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_EXTEND_DATAFILE_BEFORE_SAVE_DF_CTRL_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_EXTEND_DATAFILE_SAVE_DF_CTRL_FAIL, &sp_ret, CT_ERROR);
    sp_ret = db_save_datafile_ctrl(session, df->ctrl->id);
    SYNC_POINT_GLOBAL_END;
    if (sp_ret != CT_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when extending datafile");
    }

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_EXTEND_DATAFILE_BEFORE_SYNC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    if (DB_IS_CLUSTER(session)) {
        tx_copy_logic_log(session);
        if (session->logic_log_size > 0 || session->rm->logic_log_size > 0) {
            if (db_write_ddl_op(session) != CT_SUCCESS) {
                knl_panic_log(0, "[DDL]can't record logical log for session(%d)", session->id);
            }
            dtc_sync_ddl(session);
        }
    }
    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_EXTEND_DATAFILE_AFTER_SYNC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    return CT_SUCCESS;
}

status_t spc_truncate_datafile(knl_session_t *session, datafile_t *df, int32 *handle, int64 keep_size, bool32 need_redo)
{
    rd_truncate_datafile_daac_t daac_redo;
    rd_truncate_datafile_t *redo = &daac_redo.datafile;

    if (*handle == -1) {
        if (spc_open_datafile(session, df, handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[SPACE] failed to open file %s when truncate datafile", df->ctrl->name);
            return CT_ERROR;
        }
    }

    /* Change the size first to prevent system failure */
    df->ctrl->size = keep_size;

    daac_redo.op_type = RD_SPC_TRUNCATE_DATAFILE_DAAC;
    redo->id = df->ctrl->id;
    redo->size = df->ctrl->size;

    if (need_redo) {
        log_put(session, RD_SPC_TRUNCATE_DATAFILE, redo, sizeof(rd_truncate_datafile_t), LOG_ENTRY_FLAG_NONE);
    }

    if (cm_truncate_device(df->ctrl->type, *handle, keep_size) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[SPACE] failed to truncate datafile %s", df->ctrl->name);
        return CT_ERROR;
    }

    if (db_fsync_file(session, *handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[SPACE] failed to fsync datafile %s", df->ctrl->name);
        return CT_ERROR;
    }

    if (db_save_datafile_ctrl(session, df->ctrl->id) != CT_SUCCESS) {
        CM_ABORT(0, "[SPACE] failed to save whole control file when truncate datafile");
    }

    if (DB_IS_CLUSTER(session) && !DAAC_REPLAY_NODE(session)) {
        log_put(session, RD_LOGIC_OPERATION, &daac_redo, sizeof(rd_truncate_datafile_daac_t), LOG_ENTRY_FLAG_NONE);
    }

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_TRUNCATE_DATAFILE_BEFORE_SYNC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    return CT_SUCCESS;
}

status_t spc_truncate_datafile_ddl(knl_session_t *session, datafile_t *df, int32 *handle, int64 keep_size,
                                   bool32 need_redo)
{
    rd_truncate_datafile_daac_t daac_redo;
    rd_truncate_datafile_t *redo = &daac_redo.datafile;

    if (*handle == -1) {
        if (spc_open_datafile(session, df, handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[SPACE] failed to open file %s when truncate datafile", df->ctrl->name);
            return CT_ERROR;
        }
    }

    /* Change the size first to prevent system failure */
    df->ctrl->size = keep_size;

    log_atomic_op_begin(session);

    daac_redo.op_type = RD_SPC_TRUNCATE_DATAFILE_DAAC;
    redo->id = df->ctrl->id;
    redo->size = df->ctrl->size;

    if (need_redo) {
        log_put(session, RD_SPC_TRUNCATE_DATAFILE, redo, sizeof(rd_truncate_datafile_t), LOG_ENTRY_FLAG_NONE);
    }

    if (DB_IS_CLUSTER(session) && !DAAC_REPLAY_NODE(session)) {
        log_put(session, RD_LOGIC_OPERATION, &daac_redo, sizeof(rd_truncate_datafile_daac_t), LOG_ENTRY_FLAG_NONE);
    }

    log_atomic_op_end(session);

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_TRUNCATE_DATAFILE_BEFORE_LOG_COMMIT_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    log_commit(session);

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_TRUNCATE_DATAFILE_BEFORE_TRUNCATE_DEVICE_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    status_t sp_ret = CT_SUCCESS;
    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_TRUNCATE_DATAFILE_FAIL, &sp_ret, CT_ERROR);
    sp_ret = cm_truncate_device(df->ctrl->type, *handle, keep_size);
    SYNC_POINT_GLOBAL_END;
    if (sp_ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[SPACE] failed to truncate datafile %s", df->ctrl->name);
        return CT_ERROR;
    }

    if (db_fsync_file(session, *handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[SPACE] failed to fsync datafile %s", df->ctrl->name);
        return CT_ERROR;
    }

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_TRUNCATE_DATAFILE_BEFORE_SAVE_DF_CTRL_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_TRUNCATE_DATAFILE_SAVE_DF_CTRL_FAIL, &sp_ret, CT_ERROR);
    sp_ret = db_save_datafile_ctrl(session, df->ctrl->id);
    SYNC_POINT_GLOBAL_END;
    if (sp_ret != CT_SUCCESS) {
        CM_ABORT(0, "[SPACE] failed to save whole control file when truncate datafile");
    }

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_TRUNCATE_DATAFILE_BEFORE_SYNC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    if (DB_IS_CLUSTER(session)) {
        tx_copy_logic_log(session);
        if (session->logic_log_size > 0 || session->rm->logic_log_size > 0) {
            if (db_write_ddl_op(session) != CT_SUCCESS) {
                knl_panic_log(0, "[DDL]can't record logical log for session(%d)", session->id);
            }
            dtc_sync_ddl(session);
        }
    }
    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_TRUNCATE_DATAFILE_AFTER_SYNC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    
    return CT_SUCCESS;
}

status_t spc_build_datafile_paral(knl_session_t *session, datafile_t *df, int32 *handle)
{
    *handle = -1;
    df->ctrl->type = cm_device_type(df->ctrl->name);
    if (cm_create_device(df->ctrl->name, df->ctrl->type, knl_io_flag(session), handle) != CT_SUCCESS) {
        cm_close_device(df->ctrl->type, handle);
        return CT_ERROR;
    }

    if (spc_extend_datafile_paral(session, df, handle, 0, df->ctrl->size) != CT_SUCCESS) {
        cm_close_device(df->ctrl->type, handle);
        return CT_ERROR;
    }

    if (db_fsync_file(session, *handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[SPACE] failed to fsync datafile %s", df->ctrl->name);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t spc_build_datafile(knl_session_t *session, datafile_t *df, int32 *handle)
{
#ifndef WIN32
    if (df->ctrl->size >= DF_BUILD_PARAL_THRES && session->kernel->attr.build_datafile_parallel) {
        if (spc_build_datafile_paral(session, df, handle) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (spc_build_datafile_serial(session, df, handle) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
#else
    if (spc_build_datafile_serial(session, df, handle) != CT_SUCCESS) {
        return CT_ERROR;
    }
#endif

    return CT_SUCCESS;
}

static void df_expire_buffer_page(knl_session_t *session, uint32 file_id)
{
    buf_context_t *ctx = &session->kernel->buf_ctx;
    buf_set_t *buf_set = NULL;
    buf_ctrl_t *buf_ctrl = NULL;

    for (uint32 i = 0; i < ctx->buf_set_count; i++) {
        buf_set = &ctx->buf_set[i];
        for (uint32 j = 0; j < buf_set->hwm; j++) {
            buf_ctrl = &buf_set->ctrls[j];
            if (buf_ctrl->page_id.file == file_id) {
                buf_expire_page(session, buf_ctrl->page_id);
            }
        }
    }
}

/*
 * close fd to invalidate datafile that will be removed
 * @note caller must guarantee that the page in this file is not being visited in buffer
 *        and datafile has been offline
 * @param kernel session, datafile to be invalidated
 */
void spc_invalidate_datafile(knl_session_t *session, datafile_t *df, bool32 ckpt_disable)
{
    knl_session_t *curr_session = NULL;
    knl_instance_t *kernel = session->kernel;
    ckpt_context_t *ckpt_ctx = &kernel->ckpt_ctx;
    dbwr_context_t *dbwr_ctx = NULL;
    rmon_t *rmon_ctx = &kernel->rmon_ctx;
    uint32 i;
    uint32 name_len = (uint32)strlen(df->ctrl->name);
    char delete_name[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    errno_t ret;

    /* remember to remove dirty pages from ckpt queue and edp pages from arrarys. */
    /* close fd of datafile allocated to each session */
    for (i = 0; i < CT_MAX_SESSIONS; i++) {
        curr_session = kernel->sessions[i];
        if (curr_session != NULL && curr_session->datafiles[df->ctrl->id] != -1) {
            cm_close_device(df->ctrl->type, &curr_session->datafiles[df->ctrl->id]);
        }
    }

    /* remove dirty page of current file from ckpt queue */
    ckpt_remove_df_page(session, df, ckpt_disable);

    /* expire all page of the datafile from buffer */
    df_expire_buffer_page(session, df->ctrl->id);

    /* close fd of datafile allocated to dbwr */
    for (i = 0; i < ckpt_ctx->dbwr_count; i++) {
        dbwr_ctx = &ckpt_ctx->dbwr[i];
        if (dbwr_ctx->datafiles[df->ctrl->id] != -1) {
            cm_close_device(df->ctrl->type, &dbwr_ctx->datafiles[df->ctrl->id]);
        }
    }

    /* remove datafile from resource monitor */
    if (cm_exist_device(df->ctrl->type, df->ctrl->name)) {
        if (cm_rm_device_watch(df->ctrl->type, rmon_ctx->watch_fd, &df->wd) != CT_SUCCESS) {
            CT_LOG_RUN_WAR("[RMON]: failed to remove monitor of datafile %s", df->ctrl->name);
        }
        // remove the device watch on remote node
        (void)dtc_remove_df_watch(session, df->ctrl->id);

        if (CT_DROP_DATAFILE_FORMAT_NAME_LEN(name_len) < CT_FILE_NAME_BUFFER_SIZE - 1 && !DAAC_REPLAY_NODE(session)) {
            ret = sprintf_s(delete_name, CT_FILE_NAME_BUFFER_SIZE, "%s.delete", df->ctrl->name);
            knl_securec_check_ss(ret);
            if (cm_rename_device(df->ctrl->type, df->ctrl->name, delete_name) != CT_SUCCESS) {
                CT_LOG_RUN_WAR("[SPACE]: failed to rename space datafile %s", df->ctrl->name);
                return;
            }
            ret = memcpy_sp(df->ctrl->name, CT_FILE_NAME_BUFFER_SIZE, delete_name, CT_FILE_NAME_BUFFER_SIZE);
            knl_securec_check(ret);
        }
    }
}

status_t spc_init_datafile_head(knl_session_t *session, datafile_t *df)
{
    char *buf = (char *)cm_push(session->stack, (uint32)(df->ctrl->block_size + CT_MAX_ALIGN_SIZE_4K));
    page_head_t *page = (page_head_t *)cm_aligned_buf(buf);
    page_id_t page_id;
    errno_t ret;

    page_id.file = df->ctrl->id;
    page_id.page = 0;
    page_init(session, (page_head_t *)page, page_id, PAGE_TYPE_FILE_HEAD);

    ret = memcpy_sp((char *)page + sizeof(page_head_t), df->ctrl->block_size - sizeof(page_head_t), &df->head,
                    sizeof(df->head));
    knl_securec_check(ret);

    if (cm_write_device(df->ctrl->type, session->datafiles[df->ctrl->id], 0, page, (int32)df->ctrl->block_size) !=
        CT_SUCCESS) {
        cm_pop(session->stack);
        return CT_ERROR;
    }

    if (db_fdatasync_file(session, session->datafiles[df->ctrl->id]) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[SPACE] failed to fdatasync datafile %s", df->ctrl->name);
        cm_pop(session->stack);
        return CT_ERROR;
    }

    cm_pop(session->stack);
    return CT_SUCCESS;
}

/*
 * create a new bitmap group starting with given page id
 * pages that will be used for new bitmap are extended just now and must be fulled with 0,
 * so we need not to initialize bits on bitmap.
 */
void df_add_map_group(knl_session_t *session, datafile_t *df, page_id_t page_id, uint8 group_size)
{
    df_map_page_t *bitmap_page = NULL;
    df_map_head_t *bitmap_head = NULL;
    df_map_group_t *bitmap_group = NULL;
    rd_df_add_map_group_t redo;
    page_id_t data_start;
    uint32 i;

    /* update bitmap head */
    buf_enter_page(session, df->map_head_entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);

    bitmap_head = (df_map_head_t *)CURR_PAGE(session);
    bitmap_group = &bitmap_head->groups[bitmap_head->group_count++];
    bitmap_group->first_map = page_id;
    bitmap_group->page_count = group_size;

    redo.begin_page = page_id;
    redo.page_count = group_size;
    log_put(session, RD_SPC_ADD_MAP_GROUP, &redo, sizeof(rd_df_add_map_group_t), LOG_ENTRY_FLAG_NONE);
    buf_leave_page(session, CT_TRUE);

    data_start.file = page_id.file;
    data_start.page = page_id.page + group_size;
    data_start.aligned = 0;

    /* initialize bitmap page by page */
    for (i = 0; i < group_size; i++) {
        buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NO_READ);
        page_init(session, (page_head_t *)CURR_PAGE(session), page_id, PAGE_TYPE_DF_MAP_DATA);

        bitmap_page = (df_map_page_t *)CURR_PAGE(session);
        bitmap_page->free_begin = 0;
        bitmap_page->free_bits = DF_MAP_BIT_CNT(session);
        bitmap_page->first_page = data_start;

        log_put(session, RD_SPC_INIT_MAP_PAGE, &data_start, sizeof(page_id_t), LOG_ENTRY_FLAG_NONE);
        buf_leave_page(session, CT_TRUE);

        data_start.page += DF_MAP_BIT_CNT(session) * df->map_head->bit_unit;
        page_id.page++;
    }
}

void df_add_map_group_swap(knl_session_t *session, datafile_t *df, page_id_t page_id, uint8 group_size)
{
    df_map_page_t *bitmap_page = NULL;
    page_id_t data_start;

    /* update bitmap head */
    buf_enter_temp_page(session, df->map_head_entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    df_map_head_t *bitmap_head = (df_map_head_t *)CURR_PAGE(session);
    df_map_group_t *bitmap_group = &bitmap_head->groups[bitmap_head->group_count++];
    bitmap_group->first_map = page_id;
    bitmap_group->page_count = group_size;
    buf_leave_temp_page(session);

    data_start.file = page_id.file;
    data_start.page = page_id.page + group_size;
    data_start.aligned = 0;

    /* initialize bitmap page by page */
    for (uint32 i = 0; i < group_size; i++) {
        buf_enter_temp_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_RESIDENT | ENTER_PAGE_NO_READ);
        page_init(session, (page_head_t *)CURR_PAGE(session), page_id, PAGE_TYPE_DF_MAP_DATA);

        bitmap_page = (df_map_page_t *)CURR_PAGE(session);
        bitmap_page->free_begin = 0;
        bitmap_page->free_bits = DF_MAP_BIT_CNT(session);
        bitmap_page->first_page = data_start;

        buf_leave_temp_page(session);

        data_start.page += DF_MAP_BIT_CNT(session) * df->map_head->bit_unit;
        page_id.page++;
    }
}

/*
 * initialize bitmap head and add the first bitmap group
 */
void df_init_map_head(knl_session_t *session, datafile_t *df)
{
    df_map_head_t *bitmap_head = NULL;
    space_t *space = NULL;
    page_id_t page_id;
    uint8 bitmap_cnt;

    page_id.aligned = 0;
    page_id.file = df->ctrl->id;
    // Double write head
    if (df->ctrl->id == knl_get_dbwrite_file_id(session)) {
        page_id.page = DW_MAP_HEAD_PAGE;
        bitmap_cnt = DW_MAP_INIT_SIZE;
    } else {
        page_id.page = DF_MAP_HEAD_PAGE;
        bitmap_cnt = DF_MAP_GROUP_INIT_SIZE;
    }

    /* initialize bitmap head */
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_RESIDENT | ENTER_PAGE_NO_READ);
    page_init(session, (page_head_t *)CURR_PAGE(session), page_id, PAGE_TYPE_DF_MAP_HEAD);

    df->map_head_entry = page_id;
    df->map_head = (df_map_head_t *)CURR_PAGE(session);

    space = SPACE_GET(session, df->space_id);
    bitmap_head = (df_map_head_t *)CURR_PAGE(session);
    bitmap_head->bit_unit = space->ctrl->extent_size;
    bitmap_head->group_count = 0;

    log_put(session, RD_SPC_INIT_MAP_HEAD, &page_id, sizeof(page_id_t), LOG_ENTRY_FLAG_NONE);
    buf_leave_page(session, CT_TRUE);

    /* add the first bitmap group starting with next page */
    page_id.page++;
    df_add_map_group(session, df, page_id, bitmap_cnt);
}

void df_init_swap_map_head(knl_session_t *session, datafile_t *df)
{
    page_id_t page_id;
    page_id.aligned = 0;
    page_id.file = df->ctrl->id;

    // swap bitmap can not be double write space
    page_id.page = DF_MAP_HEAD_PAGE;
    uint8 bitmap_cnt = DF_MAP_GROUP_INIT_SIZE;

    /* initialize bitmap head */
    buf_enter_temp_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_RESIDENT | ENTER_PAGE_NO_READ);
    page_init(session, (page_head_t *)CURR_PAGE(session), page_id, PAGE_TYPE_DF_MAP_HEAD);
    df->map_head_entry = page_id;
    df->map_head = (df_map_head_t *)CURR_PAGE(session);
    space_t *space = SPACE_GET(session, df->space_id);
    df_map_head_t *bitmap_head = (df_map_head_t *)CURR_PAGE(session);
    bitmap_head->bit_unit = space->ctrl->extent_size;
    bitmap_head->group_count = 0;
    buf_leave_temp_page(session);

    /* add the first bitmap group starting with next page */
    page_id.page++;
    df_add_map_group_swap(session, df, page_id, bitmap_cnt);
    CT_LOG_DEBUG_INF("[SPACE] init swap space %u datafile %u bitmap group.", space->ctrl->id, df->ctrl->id);
}

/*
 * search the bitmap and return the start bit that fulfill the requirement.
 * we align position that search started by extent size for decreasing fragment.
 */
status_t df_search_bitmap(knl_session_t *session, df_map_page_t *map_page, uint16 bits, uint16 *extent_bit)
{
    uint8 *bitmap = map_page->bitmap;
    uint32 curr, start, match_cnt;

    start = CM_ALIGN_ANY(map_page->free_begin, bits);
    curr = start;
    match_cnt = 0;

    while (start + bits <= DF_MAP_BIT_CNT(session)) {
        /* match bit by bit */
        while (DF_MAP_MATCH(bitmap, curr)) {
            if (++match_cnt == bits) {
                *extent_bit = start;
                knl_panic_log(curr < DF_MAP_BIT_CNT(session), "curr pos is more than the limit, panic info: "
                              "page %u-%u type %u curr %u", AS_PAGID(map_page->page_head.id).file,
                              AS_PAGID(map_page->page_head.id).page, map_page->page_head.type, curr);
                return CT_SUCCESS;
            }
            curr++;
        }

        start += bits;
        curr = start;
        match_cnt = 0;
    }
    return CT_ERROR;
}

/*
 * search extent on bitmap bit by bit.
 */
status_t df_alloc_extent_from_map(knl_session_t *session, datafile_t *df, page_id_t map_page_id, uint32 extent_size,
                                  page_id_t *extent, bool32 *need_extend)
{
    uint16 extent_bit, need_bits;
    rd_df_change_map_t redo;
    df_map_page_t *map_page = NULL;

    need_bits = extent_size / df->map_head->bit_unit;

    buf_enter_page(session, map_page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    map_page = (df_map_page_t *)CURR_PAGE(session);
    if (map_page->free_bits < need_bits) {
        buf_leave_page(session, CT_FALSE);
        return CT_ERROR;
    }

    /* search extent on current bitmap */
    if (df_search_bitmap(session, map_page, need_bits, &extent_bit) != CT_SUCCESS) {
        buf_leave_page(session, CT_FALSE);
        return CT_ERROR;
    }

    *extent = map_page->first_page;
    extent->page += extent_bit * df->map_head->bit_unit;

    /* bits that searched exceed the file size, no extent available in current datafile */
    if ((extent->page + extent_size) * (int64)df->ctrl->block_size > df->ctrl->size) {
        *need_extend = CT_TRUE;
        buf_leave_page(session, CT_FALSE);
        return CT_ERROR;
    }

    /* set bits and update bitmap info */
    df_set_bitmap(map_page->bitmap, extent_bit, need_bits);

    knl_panic_log(map_page->free_bits >= need_bits,
                  "map_page's free_bits is abnormal, panic info: page %u-%u type %u free_bits %u need_bits %u",
                  map_page_id.file, map_page_id.page, map_page->page_head.type, map_page->free_bits, need_bits);
    map_page->free_bits -= need_bits;
    if (map_page->free_begin == extent_bit) {
        map_page->free_begin += need_bits;
    }

    redo.start = extent_bit;
    redo.size = need_bits;
    redo.is_set = CT_TRUE;
    log_put(session, RD_SPC_CHANGE_MAP, &redo, sizeof(rd_df_change_map_t), LOG_ENTRY_FLAG_NONE);
    buf_leave_page(session, CT_TRUE);

    return CT_SUCCESS;
}

/*
 * search extent on bitmap bit by bit.
 */
status_t df_alloc_extent_swap_map(knl_session_t *session, datafile_t *df, page_id_t map_page_id,
    page_id_t *extent, bool32 *need_extend)
{
    df_map_page_t *map_page = NULL;

    uint32 extent_size = df->map_head->bit_unit;
    uint16 need_bits = 1;  // for swap extent, only need 1 extent

    buf_enter_temp_page(session, map_page_id, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    map_page = (df_map_page_t *)CURR_PAGE(session);
    if (map_page->free_bits < need_bits) {
        buf_leave_temp_page(session);
        return CT_ERROR;
    }

    /* search extent on current bitmap */
    uint16 extent_bit;
    if (df_search_bitmap(session, map_page, need_bits, &extent_bit) != CT_SUCCESS) {
        buf_leave_temp_page(session);
        return CT_ERROR;
    }

    *extent = map_page->first_page;
    extent->page += extent_bit * df->map_head->bit_unit;

    /* bits that searched exceed the file size, no extent available in current datafile */
    if ((extent->page + extent_size) * (int64)df->ctrl->block_size > df->ctrl->size) {
        *need_extend = CT_TRUE;
        buf_leave_temp_page(session);
        return CT_ERROR;
    }

    /* set bits and update bitmap info */
    df_set_bitmap(map_page->bitmap, extent_bit, need_bits);
    knl_panic_log(map_page->free_bits >= need_bits, "[SPACE] alloc bitmap extent error, "
        "map page free bits %u is less than need bits %u.", map_page->free_bits, need_bits);
    map_page->free_bits -= need_bits;
    if (map_page->free_begin == extent_bit) {
        map_page->free_begin += need_bits;
    }
    buf_leave_temp_page(session);

    return CT_SUCCESS;
}

/*
 * datafile allocate extent from bitmap, search extent bitmap group by group, page by page
 */
status_t df_alloc_extent(knl_session_t *session, datafile_t *df, uint32 extent_size, page_id_t *extent)
{
    df_map_group_t *map_group = NULL;
    df_map_page_t *map_page = NULL;
    page_id_t curr_map, new_group;
    uint16 i, j;
    bool32 need_extend = CT_FALSE;

    for (i = 0; i < df->map_head->group_count; i++) {
        map_group = &df->map_head->groups[i];
        curr_map = map_group->first_map;

        for (j = 0; j < map_group->page_count; j++) {
            if (df_alloc_extent_from_map(session, df, curr_map, extent_size, extent, &need_extend) == CT_SUCCESS) {
                return CT_SUCCESS;
            }

            /* current map has already exceed the datafile size, switch to next datafile */
            if (need_extend) {
                return CT_ERROR;
            }
            curr_map.page++;
        }
    }

    /*
     * no extent available and does not exceed datafile size in existing maps means that
     * datafile size exceed range that existing maps can managed. so we need to add a new
     * map group starting with last data page and then alloc extent from the first map.if
     * no space to add new group, return error to extend file.
     */
    curr_map.page--;
    buf_enter_page(session, curr_map, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    map_page = (df_map_page_t *)CURR_PAGE(session);
    new_group = map_page->first_page;
    buf_leave_page(session, CT_FALSE);

    /* get the first map page of new group */
    new_group.page += DF_MAP_BIT_CNT(session) * (uint32)df->map_head->bit_unit;
    if ((new_group.page + DF_MAP_GROUP_SIZE) * (int64)DEFAULT_PAGE_SIZE(session) > df->ctrl->size) {
        return CT_ERROR;
    }

    df_add_map_group(session, df, new_group, DF_MAP_GROUP_SIZE);

    return df_alloc_extent_from_map(session, df, new_group, extent_size, extent, &need_extend);
}

/*
 * datafile allocate extent from bitmap, search extent bitmap group by group, page by page
 */
status_t df_alloc_swap_map_extent(knl_session_t *session, datafile_t *df, page_id_t *extent)
{
    df_map_group_t *map_group = NULL;
    df_map_page_t *map_page = NULL;
    page_id_t curr_map, new_group;
    uint16 i, j;
    bool32 need_extend = CT_FALSE;

    for (i = 0; i < df->map_head->group_count; i++) {
        map_group = &df->map_head->groups[i];
        curr_map = map_group->first_map;

        for (j = 0; j < map_group->page_count; j++) {
            if (df_alloc_extent_swap_map(session, df, curr_map, extent, &need_extend) == CT_SUCCESS) {
                return CT_SUCCESS;
            }

            /* current map has already exceed the datafile size, switch to next datafile */
            if (need_extend) {
                return CT_ERROR;
            }
            curr_map.page++;
        }
    }

    /*
     * no extent available and does not exceed datafile size in existing maps means that
     * datafile size exceed range that existing maps can managed. so we need to add a new
     * map group starting with last data page and then alloc extent from the first map.if
     * no space to add new group, return error to extend file.
     */
    curr_map.page--;
    buf_enter_temp_page(session, curr_map, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
    map_page = (df_map_page_t *)CURR_PAGE(session);
    new_group = map_page->first_page;
    buf_leave_temp_page(session);

    /* get the first map page of new group */
    new_group.page += DF_MAP_BIT_CNT(session) * (uint32)df->map_head->bit_unit;
    if ((new_group.page + DF_MAP_GROUP_SIZE) * (int64)DEFAULT_PAGE_SIZE(session) > df->ctrl->size) {
        return CT_ERROR;
    }

    df_add_map_group_swap(session, df, new_group, DF_MAP_GROUP_SIZE);

    return df_alloc_extent_swap_map(session, df, new_group, extent, &need_extend);
}

/*
 * find bitmap group, map page id in group and bit id in bitmap of given page id
 */
static void df_locate_map_by_pageid(knl_session_t *session, df_map_head_t *map_head, page_id_t page_id,
                                    df_map_group_t *map_group, uint16 *map_id, uint16 *bit_id)
{
    uint32 i, page_start, page_end;
    df_map_page_t *map_page = NULL;

    /* find bitmap group, map page id in group and bit id in bitmap of this extent */
    for (i = 0; i < map_head->group_count; i++) {
        *map_group = map_head->groups[i];

        buf_enter_page(session, map_group->first_map, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        map_page = (df_map_page_t *)CURR_PAGE(session);
        page_start = map_page->first_page.page;
        buf_leave_page(session, CT_FALSE);

        page_end = page_start + DF_MAP_BIT_CNT(session) * map_head->bit_unit * map_group->page_count - 1;
        if (page_id.page <= page_end) {
            *map_id = (page_id.page - page_start) / map_head->bit_unit / DF_MAP_BIT_CNT(session);
            *bit_id = (page_id.page - page_start) / map_head->bit_unit % DF_MAP_BIT_CNT(session);
            break;
        }
    }
}

static void df_locate_swap_map_pageid(knl_session_t *session, df_map_head_t *map_head, page_id_t page_id,
    df_map_group_t *map_group, uint16 *map_id, uint16 *bit_id)
{
    uint32 i, page_start, page_end;
    df_map_page_t *map_page = NULL;

    /* find bitmap group, map page id in group and bit id in bitmap of this extent */
    for (i = 0; i < map_head->group_count; i++) {
        *map_group = map_head->groups[i];

        buf_enter_temp_page(session, map_group->first_map, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
        map_page = (df_map_page_t *)CURR_PAGE(session);
        page_start = map_page->first_page.page;
        buf_leave_temp_page(session);

        page_end = page_start + DF_MAP_BIT_CNT(session) * map_head->bit_unit * map_group->page_count - 1;
        if (page_id.page <= page_end) {
            *map_id = (page_id.page - page_start) / map_head->bit_unit / DF_MAP_BIT_CNT(session);
            *bit_id = (page_id.page - page_start) / map_head->bit_unit % DF_MAP_BIT_CNT(session);
            break;
        }
    }
}

/*
 * free extent to datafile bitmap
 */
void df_free_extent(knl_session_t *session, datafile_t *df, page_id_t extent)
{
    df_map_head_t *map_head = NULL;
    df_map_group_t map_group;
    df_map_page_t *map_page = NULL;
    uint16 map_id, bit_id, bit_len;
    rd_df_change_map_t redo;
    page_head_t *page = NULL;
    page_id_t page_id;

    map_head = df->map_head;
    bit_id = 0;
    map_id = 0;

    df_locate_map_by_pageid(session, df->map_head, extent, &map_group, &map_id, &bit_id);

    /* get extent size from extent to be freed */
    buf_enter_page(session, extent, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    page = (page_head_t *)CURR_PAGE(session);
    bit_len = spc_ext_size_by_id((uint8)page->ext_size) / map_head->bit_unit;
    buf_leave_page(session, CT_FALSE);

    /* free extent to bitmap */
    page_id.file = map_group.first_map.file;
    page_id.page = map_group.first_map.page + map_id;

    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    map_page = (df_map_page_t *)CURR_PAGE(session);
    df_unset_bitmap(map_page->bitmap, bit_id, bit_len);

    map_page->free_bits += bit_len;
    knl_panic_log(map_page->free_bits <= DF_MAP_BIT_CNT(session), "[SPACE] free bitmap extent to space error, "
        "total free bits is %u, but max bits is %u. This time free %u bit(s).",
        map_page->free_bits, DF_MAP_BIT_CNT(session), bit_len);
    if (bit_id < map_page->free_begin) {
        map_page->free_begin = bit_id;
    }

    redo.start = bit_id;
    redo.size = bit_len;
    redo.is_set = CT_FALSE;
    log_put(session, RD_SPC_CHANGE_MAP, &redo, sizeof(rd_df_change_map_t), LOG_ENTRY_FLAG_NONE);
    buf_leave_page(session, CT_TRUE);
}

void df_free_swap_map_extent(knl_session_t *session, datafile_t *df, page_id_t extent)
{
    df_map_group_t map_group;
    df_map_page_t *map_page = NULL;
    uint16 map_id, bit_id;
    page_id_t page_id;

    bit_id = 0;
    map_id = 0;

    df_locate_swap_map_pageid(session, df->map_head, extent, &map_group, &map_id, &bit_id);

    uint16 bit_len = 1;

    /* free extent to bitmap */
    page_id.file = map_group.first_map.file;
    page_id.page = map_group.first_map.page + map_id;

    buf_enter_temp_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    map_page = (df_map_page_t *)CURR_PAGE(session);
    df_unset_bitmap(map_page->bitmap, bit_id, bit_len);

    map_page->free_bits += bit_len;
    knl_panic_log(map_page->free_bits <= DF_MAP_BIT_CNT(session), "[SPACE]free swap bitmap extent to space error, "
        "total free bits is %u, but max bits is %u. This time free %u bit(s).",
        map_page->free_bits, DF_MAP_BIT_CNT(session), bit_len);
    if (bit_id < map_page->free_begin) {
        map_page->free_begin = bit_id;
    }
    buf_leave_temp_page(session);
}

/*
 * get used page count of datafile by bitmap
 * 1.add up free pages and total pages basea on bitmap.
 * 2.pages calculated maybe exceed the datafile size which equals total pages minus max page of datafile size.
 * 3.minus free_pages from max page
 */
uint32 df_get_used_pages(knl_session_t *session, datafile_t *df)
{
    df_map_group_t *map_group = NULL;
    df_map_page_t *map_page = NULL;
    page_id_t curr_page;
    uint32 free_pages, total_pages, search_pages;
    uint32 i, j;

    total_pages = (uint32)((uint64)df->ctrl->size / DEFAULT_PAGE_SIZE(session));
    search_pages = DF_MAP_HEAD_PAGE + 1;
    free_pages = 0;

    for (i = 0; i < df->map_head->group_count; i++) {
        if (search_pages > total_pages) {
            break;
        }

        map_group = &df->map_head->groups[i];
        curr_page = map_group->first_map;
        search_pages += map_group->page_count;

        for (j = 0; j < map_group->page_count; j++) {
            buf_enter_page(session, curr_page, LATCH_MODE_S, ENTER_PAGE_NORMAL);
            map_page = (df_map_page_t *)CURR_PAGE(session);
            search_pages += DF_MAP_BIT_CNT(session) * df->map_head->bit_unit;
            free_pages += map_page->free_bits * df->map_head->bit_unit;

            buf_leave_page(session, CT_FALSE);
            curr_page.page++;

            if (search_pages > total_pages) {
                break;
            }
        }
    }

    free_pages -= search_pages - total_pages;
    return total_pages - free_pages;
}

static status_t df_get_next_free_extent(knl_session_t *session, datafile_t *df, df_map_page_t *map_page, uint16 p_start,
                                        uint16 *extent_bit, uint16 *bit_len, bool32 *is_last)
{
    uint16 start = p_start;
    uint8 *bitmap = map_page->bitmap;
    uint32 max_pageid, len, free_count;

    max_pageid = (uint32)((uint64)df->ctrl->size / DEFAULT_PAGE_SIZE(session));
    len = 0;
    *is_last = CT_FALSE;

    /* find the first free bit */
    while (DF_MAP_UNMATCH(bitmap, start)) {
        start++;
        /* exceed the file size, +1 for the scenario there is some space less the one extent */
        if (map_page->first_page.page + (start + 1) * df->map_head->bit_unit > max_pageid) {
            return CT_ERROR;
        }
    }

    while (DF_MAP_MATCH(bitmap, (start + len))) {
        free_count = map_page->first_page.page + (start + len) * df->map_head->bit_unit;
        if (free_count >= max_pageid) {
            if (free_count > max_pageid && len > 0) {
                len--;
            }
            *is_last = CT_TRUE;
            break;
        }
        len++;
    }

    *extent_bit = start;
    *bit_len = len;
    return CT_SUCCESS;
}

/*
 * get free extent of any size from start page in datafile
 */
status_t df_get_free_extent(knl_session_t *session, datafile_t *df, page_id_t start, uint32 *extent, uint64 *page_count,
                            bool32 *is_last)
{
    df_map_group_t map_group;
    df_map_page_t *map_page = NULL;
    page_id_t map_page_id;
    uint16 map_id = 0;
    uint16 bit_id = 0;
    uint16 extent_bit = 0;
    uint16 bit_len = 0;

    if (IS_INVALID_PAGID(start)) {
        start.file = df->ctrl->id;
        start.page = DF_MAP_HWM_START;
    }

    /* find map that this page belong to */
    df_locate_map_by_pageid(session, df->map_head, start, &map_group, &map_id, &bit_id);
    map_page_id.file = map_group.first_map.file;
    map_page_id.page = map_group.first_map.page + map_id;
    map_page_id.aligned = 0;

    buf_enter_page(session, map_page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    map_page = (df_map_page_t *)CURR_PAGE(session);
    if (df_get_next_free_extent(session, df, map_page, bit_id, &extent_bit, &bit_len, is_last) != CT_SUCCESS) {
        *extent = 0;
        *page_count = 0;
        buf_leave_page(session, CT_FALSE);
        return CT_ERROR;
    } else {
        *extent = map_page->first_page.page + extent_bit * df->map_head->bit_unit;
        *page_count = bit_len * df->map_head->bit_unit;
        buf_leave_page(session, CT_FALSE);
        return CT_SUCCESS;
    }
}

void spc_block_datafile(datafile_t *df, uint32 section_id, uint64 start, uint64 end)
{
    knl_panic(start < end);
    knl_panic(section_id < DATAFILE_MAX_BLOCK_NUM);
    cm_latch_x(&df->block_latch, CT_INVALID_ID32, NULL);
    if (df->block_end[section_id] == 0) {
        df->block_num++;
    }
    df->block_start[section_id] = start;
    df->block_end[section_id] = end;

    cm_unlatch(&df->block_latch, NULL);
}

// ONLY use for db_page_corruption, to avoid several session get lock parallelly
void spc_try_block_datafile(datafile_t *df, uint32 section_id, uint64 start, uint64 end)
{
    knl_panic(start < end);
    knl_panic(section_id < DATAFILE_MAX_BLOCK_NUM);

    for (;;) {
        cm_latch_x(&df->block_latch, CT_INVALID_ID32, NULL);
        if (df->block_end[section_id] != 0) {
            cm_unlatch(&df->block_latch, NULL);
            cm_sleep(DF_VIEW_WAIT_INTERVAL);
            continue;
        }
        df->block_num++;
        df->block_start[section_id] = start;
        df->block_end[section_id] = end;
        break;
    }

    cm_unlatch(&df->block_latch, NULL);
}

void spc_unblock_datafile(datafile_t *df, uint32 section_id)
{
    cm_latch_x(&df->block_latch, CT_INVALID_ID32, NULL);
    knl_panic(section_id < DATAFILE_MAX_BLOCK_NUM);
    if (df->block_end[section_id] > 0) {
        knl_panic(df->block_num > 0);
        df->block_num--;
    }
    df->block_start[section_id] = 0;
    df->block_end[section_id] = 0;

    cm_unlatch(&df->block_latch, NULL);
}

bool32 spc_datafile_is_blocked(knl_session_t *session, datafile_t *df, uint64 start, uint64 end)
{
    if (df->block_num == 0) {
        return CT_FALSE;
    }

    for (uint32 sec_id = 0; sec_id < DATAFILE_MAX_BLOCK_NUM; sec_id++) {
        if (end > df->block_start[sec_id] && start < df->block_end[sec_id]) {
            if (DB_IS_CLUSTER(session)) {
                bool32 running = CT_TRUE;
                if (session->kernel->backup_ctx.bak_condition) {
                    return CT_TRUE;
                }

                for (uint32 i = 0; i < session->kernel->db.ctrl.core.node_count; i++) {
                    if (SECUREC_UNLIKELY(i == session->kernel->dtc_attr.inst_id)) {
                        continue;
                    }

                    if (dtc_bak_running(session, i, &running) != CT_SUCCESS || running == CT_FALSE) {
                        return CT_FALSE;
                    }
                }
            }
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

status_t spc_get_datafile_name_bynumber(knl_session_t *session, int32 filenumber, char **filename)
{
    datafile_t *df = NULL;

    if (filenumber < 0 || filenumber >= (int32)CT_MAX_DATA_FILES) {
        CT_THROW_ERROR(ERR_INVALID_DATAFILE_NUMBER, filenumber, 0, (CT_MAX_DATA_FILES - 1));
        return CT_ERROR;
    }

    df = DATAFILE_GET(session, filenumber);
    if (DF_FILENO_IS_INVAILD(df) || !df->ctrl->used) {
        CT_THROW_ERROR(ERR_DATAFILE_NUMBER_NOT_EXIST, filenumber);
        return CT_ERROR;
    }

    if (filename != NULL) {
        *filename = df->ctrl->name;
    }
    return CT_SUCCESS;
}

static status_t spc_get_id_by_name(knl_session_t *session, text_t *name, uint32 *id)
{
    uint32 i;
    datafile_t *df = NULL;

    CM_POINTER3(session, name, id);

    for (i = 0; i < CT_MAX_DATA_FILES; i++) {
        df = DATAFILE_GET(session, i);
        if (DF_FILENO_IS_INVAILD(df) || !df->ctrl->used) {
            continue;
        }

        if (cm_text_str_equal_ins(name, df->ctrl->name)) {
            *id = i;
            return CT_SUCCESS;
        }
    }

    CT_THROW_ERROR(ERR_FILE_NOT_EXIST, "data", T2S(name));
    return CT_ERROR;
}

// precheck next extend size and maxsize which may be change in autoextend
status_t df_alter_datafile_precheck_autoextend(knl_session_t *session, datafile_t *df,
    knl_autoextend_def_t *def)
{
    if (!def->enabled) {
        return CT_SUCCESS;
    }

    // origin size, in alter process df's value has been set
    int64 next_extend_size = df->ctrl->auto_extend_size;
    int64 maxsize = df->ctrl->auto_extend_maxsize;

    if (def->nextsize != 0) {
        next_extend_size = def->nextsize;
    }

    if (def->maxsize != 0) {
        maxsize = def->maxsize;
    }

    if (next_extend_size > maxsize) {
        CT_THROW_ERROR(ERR_DATAFILE_SIZE_NOT_ALLOWED, "NEXT SIZE", df->ctrl->name);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t spc_alter_precheck_datafile(knl_session_t *session, knl_alterdb_datafile_t *def)
{
    uint32 i;
    text_t *name = NULL;
    uint32 id = CT_INVALID_ID32;
    datafile_t *df = NULL;
    int64 max_file_size;
    space_t *space = NULL;

    if (!def->autoextend.enabled) {
        return CT_SUCCESS;
    }

    for (i = 0; i < def->datafiles.count; i++) {
        name = (text_t *)cm_galist_get(&def->datafiles, i);
        if (spc_get_id_by_name(session, name, &id) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (id == CT_INVALID_ID32) {
            CT_THROW_ERROR(ERR_FILE_NOT_EXIST, "data", name->str);
            return CT_ERROR;
        }

        df = DATAFILE_GET(session, id);
        space = SPACE_GET(session, df->space_id);
        max_file_size = (int64)MAX_FILE_PAGES(space->ctrl->type) * DEFAULT_PAGE_SIZE(session);
        if (def->autoextend.nextsize > max_file_size) {
            CT_THROW_ERROR(ERR_DATAFILE_SIZE_NOT_ALLOWED, "NEXT SIZE", T2S(name));
            return CT_ERROR;
        }

        if (def->autoextend.maxsize > max_file_size) {
            CT_THROW_ERROR(ERR_DATAFILE_SIZE_NOT_ALLOWED, "MAXSIZE", T2S(name));
            return CT_ERROR;
        }

        if (def->autoextend.maxsize != 0 && def->autoextend.maxsize < df->ctrl->size) {
            CT_THROW_ERROR(ERR_DATAFILE_SIZE_NOT_ALLOWED, "MAXSIZE", T2S(name));
            return CT_ERROR;
        }

        if (df_alter_datafile_precheck_autoextend(session, df, &def->autoextend)) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t spc_alter_datafile_autoextend(knl_session_t *session, knl_alterdb_datafile_t *def)
{
    text_t *name = NULL;
    uint32 id = CT_INVALID_ID32;
    datafile_t *df = NULL;
    rd_set_df_autoextend_daac_t daac_redo;
    rd_set_df_autoextend_t *redo = &daac_redo.rd;
    space_t *space = NULL;

    if (session->kernel->db.status < DB_STATUS_OPEN) {
        CT_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "operation");
        return CT_ERROR;
    }

    if (spc_alter_precheck_datafile(session, def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    for (uint32 i = 0; i < def->datafiles.count; i++) {
        name = (text_t *)cm_galist_get(&def->datafiles, i);
        if (spc_get_id_by_name(session, name, &id) != CT_SUCCESS) {
            return CT_ERROR;
        }
        df = DATAFILE_GET(session, id);
        space = SPACE_GET(session, df->space_id);

        log_atomic_op_begin(session);
        spc_set_datafile_autoextend(session, df, &def->autoextend);

        daac_redo.op_type = RD_SPC_CHANGE_AUTOEXTEND_DAAC;
        redo->id = df->ctrl->id;
        redo->auto_extend = DATAFILE_IS_AUTO_EXTEND(df);
        redo->auto_extend_size = df->ctrl->auto_extend_size;
        redo->auto_extend_maxsize = df->ctrl->auto_extend_maxsize;

        log_put(session, RD_LOGIC_OPERATION, redo, sizeof(rd_set_df_autoextend_t), LOG_ENTRY_FLAG_NONE);

        if (DB_IS_CLUSTER(session)) {
            log_put(session, RD_LOGIC_OPERATION, &daac_redo, sizeof(rd_set_df_autoextend_daac_t), LOG_ENTRY_FLAG_NONE);
        }
        log_atomic_op_end(session);

        if (db_save_datafile_ctrl(session, df->ctrl->id) != CT_SUCCESS) {
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to save control file when extending datafile");
        }

        if (IS_SWAP_SPACE(space)) {
            session->temp_pool->get_swap_extents = 0;
        }

        if (DB_IS_CLUSTER(session)) {
            tx_copy_logic_log(session);
            if (session->logic_log_size > 0 || session->rm->logic_log_size > 0) {
                if (db_write_ddl_op(session) != CT_SUCCESS) {
                    knl_panic_log(0, "[DDL]can't record logical log for session(%d)", session->id);
                }
                dtc_sync_ddl(session);
            }
        }

        space->allow_extend = CT_TRUE;
    }

    return CT_SUCCESS;
}

static bool32 spc_is_datafile_exist(knl_session_t *session, knl_alterdb_datafile_t *def)
{
    text_t *name = NULL;
    uint32 id = CT_INVALID_ID32;

    for (uint32 i = 0; i < def->datafiles.count; i++) {
        name = (text_t *)cm_galist_get(&def->datafiles, i);
        if (spc_get_id_by_name(session, name, &id) != CT_SUCCESS) {
            return CT_FALSE;
        }

        if (id == CT_INVALID_ID32) {
            CT_THROW_ERROR(ERR_FILE_NOT_EXIST, "data", name->str);
            return CT_FALSE;
        }
    }

    return CT_TRUE;
}

status_t static spc_resize_datafile(knl_session_t *session, space_t *space, datafile_t *df, uint64 new_file_size)
{
    uint64 min_file_size, min_keep_size;
    status_t status;

    min_file_size = spc_get_datafile_minsize_byspace(session, space);

    /* check the size with the hwm of the datafile */
    dls_spin_lock(session, &space->lock, NULL);
    min_keep_size = MAX(min_file_size,
                        ((int64)SPACE_HEAD_RESIDENT(session, space)->hwms[df->file_no] * DEFAULT_PAGE_SIZE(session)));
    if (new_file_size < min_keep_size) {
        CT_THROW_ERROR(ERR_DATAFILE_RESIZE_TOO_SMALL);
        dls_spin_unlock(session, &space->lock);
        return CT_ERROR;
    }

    if (new_file_size > df->ctrl->auto_extend_maxsize) {
        CT_THROW_ERROR(ERR_DATAFILE_RESIZE_EXCEED, new_file_size, df->ctrl->auto_extend_maxsize);
        dls_spin_unlock(session, &space->lock);
        return CT_ERROR;
    }

    /* resize the datafile */
    int32 *handle = DATAFILE_FD(session, space->ctrl->files[df->file_no]);

    ckpt_disable(session);
    if (new_file_size > df->ctrl->size) {
        status = spc_extend_datafile_ddl(session, df, handle, new_file_size - df->ctrl->size, CT_TRUE);
    } else {
        status = spc_truncate_datafile_ddl(session, df, handle, new_file_size, CT_TRUE);
    }
    ckpt_enable(session);

    if (status != CT_SUCCESS) {
        dls_spin_unlock(session, &space->lock);
        CT_LOG_RUN_ERR("[SPACE] failed to resize datafile %s, old size %lld, new size %lld", df->ctrl->name,
                       df->ctrl->size, new_file_size);
        return CT_ERROR;
    }

    space->allow_extend = CT_TRUE;
    dls_spin_unlock(session, &space->lock);

    if (IS_SWAP_SPACE(space)) {
        session->temp_pool->get_swap_extents = 0;
    }

    return CT_SUCCESS;
}

status_t spc_alter_datafile_resize(knl_session_t *session, knl_alterdb_datafile_t *def)
{
    uint32 id = CT_INVALID_ID32;
    text_t *name = NULL;
    datafile_t *df = NULL;
    space_t *space = NULL;

    if (session->kernel->db.status < DB_STATUS_OPEN) {
        CT_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "operation");
        return CT_ERROR;
    }

    if (!spc_is_datafile_exist(session, def)) {
        return CT_ERROR;
    }

    for (uint32 i = 0; i < def->datafiles.count; i++) {
        name = (text_t *)cm_galist_get(&def->datafiles, i);
        if (spc_get_id_by_name(session, name, &id) != CT_SUCCESS) {
            return CT_ERROR;
        }

        df = DATAFILE_GET(session, id);
        space = SPACE_GET(session, df->space_id);
        if (!SPACE_IS_ONLINE(space)) {
            char err_msg[CT_MESSAGE_BUFFER_SIZE] = { 0 };
            errno_t ret = sprintf_s(err_msg, CT_MESSAGE_BUFFER_SIZE, "resize datafile %s failed", df->ctrl->name);
            knl_securec_check_ss(ret);
            CT_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, err_msg);
            return CT_ERROR;
        }
        
        if (spc_resize_datafile(session, space, df, def->size) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

datafile_t *db_get_next_datafile(knl_session_t *session, uint32 *file_id, uint64 *data_size, uint32 *hwm_start)
{
    datafile_t *df = NULL;
    space_t *space = NULL;
    uint64 size;

    for (; *file_id < CT_MAX_DATA_FILES; (*file_id)++) {
        df = DATAFILE_GET(session, *file_id);
        if (!DATAFILE_IS_ONLINE(df) || !df->ctrl->used || DF_FILENO_IS_INVAILD(df)) {
            continue;
        }

        space = SPACE_GET(session, df->space_id);
        if (!SPACE_IS_ONLINE(space) || !space->ctrl->used) {
            continue;
        }

        if (SPACE_IS_NOLOGGING(space)) {
            /*
             * for temp tablespace and nologging tablespace,
             * only backup the first two pages of the first file when implementing a backup task
             */
            size = (0 == df->file_no) ? (2 * DEFAULT_PAGE_SIZE(session)) : 0;
        } else {
            size = (uint64)SPACE_HEAD_RESIDENT(session, space)->hwms[df->file_no] * DEFAULT_PAGE_SIZE(session);
        }

        if (size > DEFAULT_PAGE_SIZE(session)) {
            *data_size = size;
            *hwm_start = spc_get_hwm_start(session, space, df);
            return df;
        }
    }

    return NULL;
}

status_t df_dump_map_head_page(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump)
{
    df_map_head_t *page = (df_map_head_t *)page_head;

    cm_dump(dump, "datafile dump map head information\n");
    cm_dump(dump, "\tbit unit:%u, group count:%u, reserved:%u \n", (uint32)page->bit_unit, (uint32)page->group_count,
        page->reserved);
    cm_dump(dump, "datafile group information\n");
    CM_DUMP_WRITE_FILE(dump);
    for (uint32 i = 0; i < (uint32)page->group_count; i++) {
        cm_dump(dump, "\t page:%u, file:%u, page count:%u \n", page->groups[i].first_map.page,
            (uint32)page->groups[i].first_map.file, (uint32)page->groups[i].page_count);
        CM_DUMP_WRITE_FILE(dump);
    }

    return CT_SUCCESS;
}

status_t df_dump_map_data_page(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump)
{
    df_map_page_t *page = (df_map_page_t *)page_head;

    cm_dump(dump, "datafile dump map data information\n");
    cm_dump(dump, "\t page:%u, file:%u\n", page->first_page.page, (uint32)page->first_page.file);
    cm_dump(dump, "\t first free_bit:%u, free_bits:%u, reserved:%u \n", (uint32)page->free_begin,
        (uint32)page->free_bits, page->reserved);
    cm_dump(dump, "bit map use information(1:use,0:unused)\n");
    CM_DUMP_WRITE_FILE(dump);

    uint8 *bitmap = page->bitmap;
    for (uint32 i = 0; i < DF_MAP_BIT_CNT(session); i++) {
        if (!DF_MAP_MATCH(bitmap, i)) {
            cm_dump(dump, "1");
        } else {
            cm_dump(dump, "0");
        }
        if ((i + 1) % DF_PAGE_PER_LINE == 0) {
            if ((i + 1) % DF_PAGE_PER_LINE_COUNT == 0) {
                cm_dump(dump, "\n");
            } else {
                cm_dump(dump, "\t ");
            }
            CM_DUMP_WRITE_FILE(dump);
        }
    }

    return CT_SUCCESS;
}

/*
 * build a file with given range and  fill zero page with page id.
 * @note file must has been open by session of context.
 */
void df_build_proc(thread_t *thread)
{
    cm_set_thread_name("datafile build");

    df_build_ctx_t *ctx = (df_build_ctx_t *)thread->argument;
    knl_session_t *session = ctx->session;
    datafile_t *df = ctx->df;

    int64 offset = ctx->offset;
    int64 remain_size = ctx->size;
    int32 *handle = DATAFILE_FD(session, df->ctrl->id);

    while (!thread->closed && remain_size > 0) {
        uint32 curr_size = (remain_size > CT_XPURPOSE_BUFFER_SIZE) ? (int32)CT_XPURPOSE_BUFFER_SIZE
                                                                   : (int32)remain_size;
        if (cm_write_device(df->ctrl->type, *handle, offset, ctx->buf, curr_size) != CT_SUCCESS) {
            CT_LOG_RUN_INF("[SPACE] failed to create datafile %s, error code %d", df->ctrl->name, errno);
            ctx->status = DF_BUILD_FAILED;
            return;
        }

        offset += curr_size;
        remain_size -= curr_size;

        if (ctx->status == DF_BUILD_FAILED) {
            return;
        }
    }

    ctx->status = DF_BUILD_SUCCESSED;
}

static uint32 df_locate_last_extent(knl_session_t *session, datafile_t *df, page_id_t map_pagid)
{
    uint32 curr_pos, curr_pagid, curr_byte_pos;

    buf_enter_page(session, map_pagid, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    df_map_page_t *map_page = (df_map_page_t *)CURR_PAGE(session);
    uint8 *bitmap = map_page->bitmap;

    if (map_page->free_bits == DF_MAP_BIT_CNT(session)) {
        buf_leave_page(session, CT_FALSE);
        return 0;
    }

    /* scan every bit byte by byte to find the max page id that is used */
    curr_pos = DF_MAP_SIZE(session) - 1;
    while (curr_pos > 0) {
        if (bitmap[curr_pos]) {
            break;
        }

        curr_pos--;
    }

    /* get high bit pos in one byte whose value is one */
    uint8 bit_pos = 0;
    uint8 byte_value = bitmap[curr_pos];
    while (!(byte_value & 0x80)) {
        byte_value = byte_value << 1;
        bit_pos++;
    }

    curr_byte_pos = curr_pos * UINT8_BITS + UINT8_BITS - bit_pos;
    curr_pagid = map_page->first_page.page + df->map_head->bit_unit * curr_byte_pos;
    buf_leave_page(session, CT_FALSE);

    return curr_pagid;
}

uint32 df_get_shrink_hwm(knl_session_t *session, datafile_t *df)
{
    uint32 curr_pagid;
    page_id_t curr_map;
    uint32 max_pagid = 0;
    df_map_group_t *map_group = NULL;
    uint64 begin_time = KNL_NOW(session);

    for (uint32 i = 0; i < df->map_head->group_count; i++) {
        map_group = &df->map_head->groups[i];
        curr_map = map_group->first_map;

        for (uint32 j = 0; j < map_group->page_count; j++) {
            curr_pagid = df_locate_last_extent(session, df, curr_map);
            if (max_pagid < curr_pagid) {
                max_pagid = curr_pagid;
            }

            curr_map.page++;
        }
        session->kernel->stat.spc_free_exts++;
        session->kernel->stat.spc_shrink_times += (KNL_NOW(session) - begin_time);
    }

    return max_pagid;
}

status_t df_verify_page_by_hwm(knl_session_t *session, rowid_t rowid)
{
    datafile_t *df = &session->kernel->db.datafiles[rowid.file];
    space_t *space = SPACE_GET(session, df->space_id);
    uint32 file_hwm = DF_FILENO_IS_INVAILD(df) ? 0 : (int32)SPACE_HEAD_RESIDENT(session, space)->hwms[df->file_no];
    if (rowid.page >= file_hwm) {
        CT_LOG_DEBUG_WAR("page is invaild, page id is not less than datafile hwm");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t df_verify_pageid_by_hwm(knl_session_t *session, page_id_t page_id)
{
    if (page_id.file >= CT_MAX_DATA_FILES) {
        CT_LOG_DEBUG_WAR("page is invaild, file id(%u) is larger than max datafile id", page_id.file);
        return CT_ERROR;
    }

    datafile_t *df = &session->kernel->db.datafiles[page_id.file];
    if (!df->ctrl->used || !DATAFILE_IS_ONLINE(df)) {
        CT_LOG_DEBUG_WAR("page is invaild, file(%u) is offline", page_id.file);
        return CT_ERROR;
    }

    space_t *space = SPACE_GET(session, df->space_id);
    uint32 file_hwm = DF_FILENO_IS_INVAILD(df) ? 0 : (int32)SPACE_HEAD_RESIDENT(session, space)->hwms[df->file_no];
    if (page_id.page >= file_hwm) {
        CT_LOG_DEBUG_WAR("page is invaild, page id(%u) is not less than datafile hwm(%u)",
            page_id.page, file_hwm);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t df_verify_pageid_by_size(knl_session_t *session, page_id_t page_id)
{
    if (page_id.file >= CT_MAX_DATA_FILES) {
        CT_LOG_DEBUG_WAR("page is invaild, file id(%u) is larger than max datafile id", page_id.file);
        return CT_ERROR;
    }

    datafile_t *df = &session->kernel->db.datafiles[page_id.file];
    if (!df->ctrl->used || !DATAFILE_IS_ONLINE(df)) {
        CT_LOG_DEBUG_WAR("page is invaild, file(%u) is offline", page_id.file);
        return CT_ERROR;
    }

    uint64 max_page_count = df->ctrl->size / DEFAULT_PAGE_SIZE(session);
    if (page_id.page >= (uint32)max_page_count) {
        CT_LOG_DEBUG_WAR("page is invaild, page id(%u) is not less than datafile max page count(%u)",
            page_id.page, (uint32)max_page_count);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif

