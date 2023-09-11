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
 * knl_db_alter.c
 *
 *
 * IDENTIFICATION
 * src/kernel/knl_db_alter.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_db_alter.h"
#include "knl_database.h"
#include "knl_context.h"
#include "knl_ctlg.h"
#include "cm_file.h"
#include "dtc_database.h"

typedef enum st_failover_fail_type {
    FAILOVER_INVALID_STATUS = 1,
    FAILOVER_INVALID_ROLE = 2,
    FAILOVER_ABORT_BY_OTHER = 3,
    FAILOVER_ABORT_BY_MASTER = 4,
} failover_fail_type_t;

static status_t db_alter_convert_standby_precheck(knl_session_t *session, bool32 is_cascaded)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    uint32 log_count;

    if (db->status != DB_STATUS_MOUNT) {
        GS_THROW_ERROR(ERR_DATABASE_NOT_MOUNT, "convert standby");
        return GS_ERROR;
    }

    log_count = log_get_count(session);
    if (log_count < GS_MIN_LOG_FILES) {
        GS_THROW_ERROR(ERR_LOG_FILE_NOT_ENOUGH);
        return GS_ERROR;
    }

    if (!DB_IS_PRIMARY(db) && !is_cascaded) {
        GS_THROW_ERROR(ERR_DATABASE_ROLE, "operation", "not in primary mode");
        return GS_ERROR;
    }

    if (DB_IS_CASCADED_PHYSICAL_STANDBY(db) && is_cascaded) {
        GS_THROW_ERROR(ERR_DATABASE_ROLE, "operation", "in a cascaded physical standby mode");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_alter_convert_to_standby(knl_session_t *session, knl_alterdb_def_t *def)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;

    if (DB_IS_RAFT_ENABLED(session->kernel)) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION,
            ",RAFT: alter to standby not supported when raft is enabled, please use failver.sh instead.");
        return GS_ERROR;
    }

    if (db_alter_convert_standby_precheck(session, def->is_cascaded) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (def->is_cascaded) {
        db->ctrl.core.db_role = REPL_ROLE_CASCADED_PHYSICAL_STANDBY;
    } else {
        db->ctrl.core.db_role = REPL_ROLE_PHYSICAL_STANDBY;
    }

    kernel->lrcv_ctx.reconnected = GS_FALSE;

    if (def->is_mount) {
        if (db_save_core_ctrl(session) != GS_SUCCESS) {
            CM_ABORT(0, "[DB] ABORT INFO: save core control file failed when convert database role.");
        }
    } else {
        kernel->rcy_ctx.is_demoting = GS_TRUE;
        db_open_opt_t open_options = {
            GS_FALSE, GS_FALSE, GS_FALSE, GS_FALSE, GS_TRUE, DB_OPEN_STATUS_NORMAL, GS_INVALID_LFN
        };
        if (db_open(session, &open_options) != GS_SUCCESS) {
            kernel->rcy_ctx.is_demoting = GS_FALSE;
            return GS_ERROR;
        }
        kernel->rcy_ctx.is_demoting = GS_TRUE;
    }

    GS_LOG_RUN_INF("[DB] demote to %s completely", def->is_cascaded ? "cascaded standby" : "standby");
    return GS_SUCCESS;
}

static status_t db_notify_open_mode_reset(knl_session_t *session, switch_req_t request)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    switch_ctrl_t *ctrl = &kernel->switch_ctrl;

    cm_spin_lock(&ctrl->lock, NULL);

    if (ctrl->request != SWITCH_REQ_NONE) {
        cm_spin_unlock(&ctrl->lock);
        GS_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "server is handling another switch request");
        return GS_ERROR;
    }

    ctrl->keep_sid = session->id;
    ctrl->request = request;

    cm_spin_unlock(&ctrl->lock);

    GS_LOG_RUN_INF("[DB] notify server to set %s", ctrl->request == SWITCH_REQ_READONLY ? "READONLY" : "NON_UPGRADE");

    return GS_SUCCESS;
}

static status_t db_alter_readmode_precheck(knl_session_t *session, bool32 convert_to_readonly)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    switch_ctrl_t *ctrl = &kernel->switch_ctrl;

    GS_LOG_RUN_INF("[DB] start precheck for converting to %s", convert_to_readonly ? "readonly" : "readwrite");
    if (db->status != DB_STATUS_OPEN) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in OPEN mode");
        return GS_ERROR;
    }

    cm_spin_lock(&ctrl->lock, NULL);
    if (ctrl->request == SWITCH_REQ_READONLY) {
        cm_spin_unlock(&ctrl->lock);
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ",another operation for readonly mode is running");
        return GS_ERROR;
    }
    cm_spin_unlock(&ctrl->lock);

    if (convert_to_readonly && (DB_IS_READONLY(session) || DB_IS_MAINTENANCE(session))) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in READ WRITE mode");
        return GS_ERROR;
    }
    if (!convert_to_readonly && !DB_IS_READONLY(session)) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in READ ONLY mode");
        return GS_ERROR;
    }
    if (!convert_to_readonly && !DB_IS_PRIMARY(db)) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported by primary role");
        return GS_ERROR;
    }
    GS_LOG_RUN_INF("[DB] precheck finished for converting to %s", convert_to_readonly ? "readonly" : "readwrite");

    return GS_SUCCESS;
}

status_t db_alter_convert_to_readonly(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    switch_ctrl_t *ctrl = &kernel->switch_ctrl;

    if (db_alter_readmode_precheck(session, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_notify_open_mode_reset(session, SWITCH_REQ_READONLY) != GS_SUCCESS) {
        return GS_ERROR;
    }

    cm_unlatch(&session->kernel->db.ddl_latch.latch, NULL);

    while (!DB_IS_READONLY(session) || ctrl->request != SWITCH_REQ_NONE) {
        if (session->killed) {
            cm_latch_s(&session->kernel->db.ddl_latch.latch, session->id, GS_FALSE, NULL);
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            return GS_ERROR;
        }

        cm_spin_lock(&ctrl->lock, NULL);
        if (ctrl->request != SWITCH_REQ_NONE && ctrl->request != SWITCH_REQ_READONLY) {
            cm_spin_unlock(&ctrl->lock);
            cm_latch_s(&session->kernel->db.ddl_latch.latch, session->id, GS_FALSE, NULL);
            GS_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "readonly setting aborted by other request");
            GS_LOG_RUN_ERR("[DB] readonly setting aborted by other request");

            return GS_ERROR;
        }
        cm_spin_unlock(&ctrl->lock);
        cm_sleep(10);
    }

    GS_LOG_RUN_INF("[DB] convert to readonly successfully");
    cm_latch_s(&session->kernel->db.ddl_latch.latch, session->id, GS_FALSE, NULL);

    GS_LOG_RUN_INF("[DB] add latch after readonly");
    return GS_SUCCESS;
}

status_t db_alter_convert_to_readwrite(knl_session_t *session)
{
    database_t *db = &session->kernel->db;

    if (db_alter_readmode_precheck(session, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    db->is_readonly = GS_FALSE;
    db->readonly_reason = MANUALLY_SET;

    if (tx_rollback_start(session) != GS_SUCCESS) {
        CM_ABORT(0, "[DB] READWIRTE ABORT INFO: failed to start txn rollback thread, convert to readwrite failed");
    }

    if (db_garbage_segment_clean(session) != GS_SUCCESS) {
        GS_LOG_RUN_WAR("[DB] READWIRTE: failed to clean garbage segment");
    }

    rmon_clean_alarm(session);

    GS_LOG_RUN_INF("[DB] READWIRTE: convert to readwrite successfully");

    return GS_SUCCESS;
}

static status_t db_alter_upgrade_mode_precheck(knl_session_t *session)
{
    database_t *db = &session->kernel->db;

    GS_LOG_RUN_INF("[DB] start precheck for cancelling upgrade mode");
    if (!DB_IS_PRIMARY(db)) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in primary database");
        return GS_ERROR;
    }

    if (db->status != DB_STATUS_OPEN) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in OPEN mode");
        return GS_ERROR;
    }

    if (!DB_IS_UPGRADE(session)) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in UPGRADE mode");
        return GS_ERROR;
    }

    if (db->open_status != DB_OPEN_STATUS_UPGRADE_PHASE_2) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported after initializing all objects");
        return GS_ERROR;
    }
    GS_LOG_RUN_INF("[DB] precheck finished for cancelling upgrade mode");

    return GS_SUCCESS;
}

status_t db_alter_cancel_upgrade(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    switch_ctrl_t *ctrl = &kernel->switch_ctrl;

    if (db_alter_upgrade_mode_precheck(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_notify_open_mode_reset(session, SWITCH_REQ_CANCEL_UPGRADE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (DB_IS_UPGRADE(session) || ctrl->request != SWITCH_REQ_NONE) {
        if (session->killed) {
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            return GS_ERROR;
        }

        cm_spin_lock(&ctrl->lock, NULL);
        if (ctrl->request != SWITCH_REQ_NONE && ctrl->request != SWITCH_REQ_CANCEL_UPGRADE) {
            cm_spin_unlock(&ctrl->lock);
            GS_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "CANCEL UPGRADE setting aborted by other request");
            GS_LOG_RUN_ERR("[DB] CANCEL UPGRADE setting aborted by other request");

            return GS_ERROR;
        }
        cm_spin_unlock(&ctrl->lock);
        cm_sleep(10);
    }
    GS_LOG_RUN_INF("[DB] cancel upgrade mode successfully");

    return GS_SUCCESS;
}

static status_t db_update_masterkey_begin(knl_session_t *session, uint32 domain)
{
    rd_create_mk_begin_t rd_begin;

    rd_begin.op_type = RD_CREATE_MK_BEGIN;
    rd_begin.reserved = 0;
    if (cm_kmc_get_max_mkid(domain, &rd_begin.max_mkid) != GS_SUCCESS) {
        return GS_ERROR;
    }
    log_atomic_op_begin(session);
    log_put(session, RD_LOGIC_OPERATION, &rd_begin, sizeof(rd_create_mk_begin_t), LOG_ENTRY_FLAG_NONE);
    log_atomic_op_end(session);
    knl_commit(session);

    return GS_SUCCESS;
}

static status_t knl_logput_keyfile(knl_session_t *session, int32 handle, int64 file_size)
{
    int64 remain_size = file_size;
    uint32 plain_len = GS_KMC_MAX_MK_SIZE / GS_KMC_MAX_KEYFILE_NUM;
    char plain_buf[GS_KMC_MAX_MK_SIZE];
    rd_mk_data_t rd_data;
    int32 read_size = 0;
    int64 offset = 0;

    while (remain_size > 0) {
        if (session->canceled) {
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            return GS_ERROR;
        }

        if (session->killed) {
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            return GS_ERROR;
        }

        if (cm_seek_file(handle, offset, SEEK_SET) != offset) {
            GS_LOG_RUN_ERR("seek file failed");
            return GS_ERROR;
        }

        rd_data.offset = (uint64)offset;
        if (cm_read_file(handle, plain_buf, (int32)plain_len, &read_size) != GS_SUCCESS) {
            return GS_ERROR;
        }

        knl_panic(read_size > 0);
        knl_panic((uint32)read_size <= plain_len);
        if (cm_get_cipher_len(read_size, &rd_data.len) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (rd_data.len >= GS_KMC_MAX_MK_SIZE) {
            GS_LOG_RUN_WAR("cipher data is too large %u", rd_data.len);
            return GS_ERROR;
        }

        if (cm_kmc_encrypt(GS_KMC_KERNEL_DOMAIN, KMC_DEFAULT_ENCRYPT, plain_buf, read_size, rd_data.data, &rd_data.len) != GS_SUCCESS) {
            GS_LOG_RUN_WAR("encrypt master key failed");
            return GS_ERROR;
        }

        rd_data.op_type = RD_CREATE_MK_DATA;
        rd_data.reserved = 0;
        log_atomic_op_begin(session);
        log_put(session, RD_LOGIC_OPERATION, &rd_data, sizeof(rd_mk_data_t), LOG_ENTRY_FLAG_NONE);
        log_atomic_op_end(session);
        knl_commit(session);
        remain_size -= read_size;
        offset += read_size;
    }

    return GS_SUCCESS;
}

static status_t db_execute_update_masterkey(knl_session_t *session, uint32 domain, uint32 *keyid)
{
    int32 handle = INVALID_FILE_HANDLE;
    char keyfile_name[GS_FILE_NAME_BUFFER_SIZE];

    errno_t ret = snprintf_s(keyfile_name, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s.update.export",
        session->kernel->attr.kmc_key_files[0].name);
    knl_securec_check_ss(ret);

    if (cm_file_exist(keyfile_name)) {
        if (cm_remove_file(keyfile_name) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("failed to remove update export key file %s", keyfile_name);
            return GS_ERROR;
        }
    }

    if (cm_kmc_create_masterkey(domain, keyid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_kmc_export_keyfile(keyfile_name) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_open_file(keyfile_name, O_RDONLY | O_BINARY, &handle) != GS_SUCCESS) {
        return GS_ERROR;
    }

    int64 file_size = cm_file_size(handle);
    if (file_size < 0 || file_size >= GS_KMC_MAX_KEY_SIZE) {
        cm_close_file(handle);
        GS_LOG_RUN_ERR("invalid file size:%lld %s.", file_size, keyfile_name);
        return GS_ERROR;
    }

    if (knl_logput_keyfile(session, handle, file_size) != GS_SUCCESS) {
        cm_close_file(handle);
        GS_LOG_RUN_ERR("fail to log put key file:%s.", keyfile_name);
        return GS_ERROR;
    }
    cm_close_file(handle);

    if (cm_file_exist(keyfile_name)) {
        if (cm_remove_file(keyfile_name) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("failed to remove update export key file %s", keyfile_name);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t db_update_masterkey_end(knl_session_t *session, uint32 domain, uint32 keyid)
{
    rd_create_mk_end_t rd_end;

    rd_end.hash_len = GS_KMC_MK_HASH_LEN;
    if (cm_get_masterkey_hash(domain, keyid, rd_end.hash, &rd_end.hash_len) != GS_SUCCESS) {
        return GS_ERROR;
    }
    rd_end.op_type = RD_CREATE_MK_END;
    rd_end.mk_id = keyid;
    rd_end.reserved = 0;
    log_atomic_op_begin(session);
    log_put(session, RD_LOGIC_OPERATION, &rd_end, sizeof(rd_create_mk_end_t), LOG_ENTRY_FLAG_NONE);
    log_atomic_op_end(session);
    knl_commit(session);

    return cm_kmc_active_masterkey(domain, keyid);
}

static status_t db_update_kernel_masterkey(knl_session_t *session)
{
    uint32 keyid = 0;
    uint32 count = 0;

    if (session->kernel->lsnd_ctx.standby_num > 0 && !DB_IS_RAFT_ENABLED(session->kernel)) {
        GS_LOG_DEBUG_WAR("forbid to update kernel masterkey when database in HA mode");
        return GS_SUCCESS;
    }

    if (cm_get_masterkey_count(&count) != GS_SUCCESS) {
        GS_LOG_RUN_WAR("failt to get kmc masterkey count");
        return GS_ERROR;
    }

    if (count >= GS_KMC_MAX_MK_COUNT) {
        GS_LOG_RUN_WAR("find total masterkey count %u le max masterkey count %u", count, GS_KMC_MAX_MK_COUNT);
        return GS_ERROR;
    }

    if (db_update_masterkey_begin(session, GS_KMC_KERNEL_DOMAIN) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_execute_update_masterkey(session, GS_KMC_KERNEL_DOMAIN, &keyid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_update_masterkey_end(session, GS_KMC_KERNEL_DOMAIN, keyid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    GS_LOG_RUN_INF("finish update kernel masterkey");
    return GS_SUCCESS;
}

status_t db_alter_update_server_masterkey(knl_session_t *session)
{
    rd_alter_server_mk_t rd_end;
    if (knl_ddl_enabled(session, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (g_knl_callback.update_server_masterkey(session) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_UPDATE_MASTER_KEY, "update server masterkey");
        return GS_ERROR;
    }
    rd_end.op_type = RD_ALTER_SERVER_MK;
    rd_end.reserved = 0;
    log_atomic_op_begin(session);
    log_put(session, RD_LOGIC_OPERATION, &rd_end, sizeof(rd_alter_server_mk_t), LOG_ENTRY_FLAG_NONE);
    log_atomic_op_end(session);
    return GS_SUCCESS;
}
status_t db_alter_update_kernel_masterkey(knl_session_t *session)
{
    if (knl_ddl_enabled(session, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_update_kernel_masterkey(session) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_UPDATE_MASTER_KEY, "update kernel masterkey");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}
status_t db_alter_update_masterkey(knl_session_t *session)
{
    if (knl_ddl_enabled(session, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_alter_update_server_masterkey(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_update_kernel_masterkey(session) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_UPDATE_MASTER_KEY, "update kernel masterkey");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_alter_delete_archivelog(knl_session_t *session, knl_alterdb_def_t *def)
{
    return GS_SUCCESS;
}

status_t db_alter_delete_backupset(knl_session_t *session, knl_alterdb_def_t *def)
{
    return GS_SUCCESS;
}

status_t db_alter_clear_logfile(knl_session_t *session, uint32 file_id)
{
    log_file_t *logfile = NULL;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);

    if (file_id >= dtc_my_ctrl(session)->log_hwm) {
        GS_THROW_ERROR(ERR_LOG_FILE_NOT_EXIST);
        return GS_ERROR;
    }

    if (DB_STATUS(session) != DB_STATUS_MOUNT) {
        GS_THROW_ERROR(ERR_DATABASE_NOT_MOUNT, "clear logfile");
        return GS_ERROR;
    }

    log_lock_logfile(session);
    logfile = &logfile_set->items[file_id];

    cm_latch_x(&logfile->latch, session->id, NULL);
    if (LOG_IS_DROPPED(logfile->ctrl->flg)) {
        GS_THROW_ERROR(ERR_LOG_FILE_NOT_EXIST);
        cm_unlatch(&logfile->latch, NULL);
        log_unlock_logfile(session);
        return GS_ERROR;
    }

    if (logfile->ctrl->status != LOG_FILE_INACTIVE && logfile->ctrl->status != LOG_FILE_UNUSED) {
        GS_THROW_ERROR(ERR_LOG_IN_USE);
        cm_unlatch(&logfile->latch, NULL);
        log_unlock_logfile(session);
        return GS_ERROR;
    }

    logfile->head.first = GS_INVALID_ID64;
    logfile->head.last = GS_INVALID_ID64;
    logfile->head.write_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size);
    logfile->head.block_size = (int32)logfile->ctrl->block_size;
    logfile->head.rst_id = db->ctrl.core.resetlogs.rst_id;
    logfile->head.asn = GS_INVALID_ASN;
    logfile->head.cmp_algorithm = COMPRESS_NONE;

    log_flush_head(session, logfile);

    cm_unlatch(&logfile->latch, NULL);
    log_unlock_logfile(session);

    return GS_SUCCESS;
}

status_t db_alter_rebuild_space(knl_session_t *session, text_t *name)
{
    space_t *space = NULL;
    uint32 space_id;

    if (session->kernel->db.status != DB_STATUS_MOUNT) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in mount mode");
        return GS_ERROR;
    }

    if (GS_SUCCESS != spc_get_space_id(session, name, GS_FALSE, &space_id)) {
        return GS_ERROR;
    }

    space = KNL_GET_SPACE(session, space_id);

    return spc_rebuild_space(session, space);
}

status_t db_alter_protection_mode(knl_session_t *session, knl_alterdb_def_t *def)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;

    switch (def->standby.alter_standby_mode) {
        case ALTER_SET_PROTECTION:
            if (lsnd_check_protection_standby_num(session) != GS_SUCCESS) {
                return GS_ERROR;
            }
            db->ctrl.core.protect_mode = MAXIMUM_PROTECTION;
            break;

        case ALTER_SET_AVAILABILITY:
            db->ctrl.core.protect_mode = MAXIMUM_AVAILABILITY;
            break;

        case ALTER_SET_PERFORMANCE:
            db->ctrl.core.protect_mode = MAXIMUM_PERFORMANCE;
            break;

        default:
            cm_assert(GS_FALSE);
    }

    if (db_save_core_ctrl(session) != GS_SUCCESS) {
        CM_ABORT(0, "[DB] ABORT INFO: failed to save core control file when alter protection mode");
    }

    return GS_SUCCESS;
}

static status_t db_notify_failover_promote(knl_session_t *session, lrcv_context_t *lrcv, bool32 force)
{
    switch_ctrl_t *ctrl = &session->kernel->switch_ctrl;

    cm_spin_lock(&lrcv->lock, NULL);
    bool32 connected = (bool32)(lrcv->session != NULL);

    if (connected && !force) {
        cm_spin_unlock(&lrcv->lock);
        GS_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "could not issue failover when not disconnected, "
                       "please try force failover");
        return GS_ERROR;
    }

    if (lrcv->state != REP_STATE_NORMAL) {
        cm_spin_unlock(&lrcv->lock);
        GS_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "server is handling another switch request");
        return GS_ERROR;
    }

    cm_spin_lock(&ctrl->lock, NULL);

    if (ctrl->request != SWITCH_REQ_NONE) {
        cm_spin_unlock(&ctrl->lock);
        cm_spin_unlock(&lrcv->lock);
        GS_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "server is handling another switch request");
        return GS_ERROR;
    }

    ctrl->keep_sid = session->id;
    ctrl->request = force ? SWITCH_REQ_FORCE_FAILOVER_PROMOTE : SWITCH_REQ_FAILOVER_PROMOTE;

    cm_spin_unlock(&ctrl->lock);
    cm_spin_unlock(&lrcv->lock);

    if (connected) {
        lrcv_close(session);
    }

    GS_LOG_RUN_INF("[DB] notify server to do %sfailover", force ? "force " : "");
    return GS_SUCCESS;
}

static void db_throw_failover_error(bool32 force, failover_fail_type_t type)
{
    switch (type) {
        case FAILOVER_INVALID_STATUS: {
            if (force) {
                GS_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST,
                    "force failover cannot be issued when database isn't in open status");
            } else {
                GS_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST,
                    "failover cannot be issued when database isn't in open status");
            }
            break;
        }

        case FAILOVER_INVALID_ROLE: {
            if (force) {
                GS_THROW_ERROR(ERR_DATABASE_ROLE, "force failover", "not in standby mode");
            } else {
                GS_THROW_ERROR(ERR_DATABASE_ROLE, "failover", "not in standby mode");
            }
            break;
        }

        case FAILOVER_ABORT_BY_OTHER: {
            if (force) {
                GS_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "force failover aborted by other request");
                GS_LOG_RUN_ERR("[DB] force failover aborted by other request");
            } else {
                GS_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "failover aborted by other request");
                GS_LOG_RUN_ERR("[DB] failover aborted by other request");
            }
            break;
        }

        case FAILOVER_ABORT_BY_MASTER: {
            if (force) {
                GS_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "force failover aborted by master");
                GS_LOG_RUN_ERR("[DB] force failover aborted by master");
            } else {
                GS_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "failover aborted by master");
                GS_LOG_RUN_ERR("[DB] failover aborted by master");
            }
        }
    }
}

static status_t db_alter_failover_check(knl_session_t *session, knl_alterdb_def_t *def)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;

    if (db->status != DB_STATUS_OPEN) {
        db_throw_failover_error(def->force_failover, FAILOVER_INVALID_STATUS);
        return GS_ERROR;
    }

    if (db->terminate_lfn != GS_INVALID_LFN) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "failover with terminated lfn");
        return GS_ERROR;
    }

    if (DB_IS_PRIMARY(db)) {
        db_throw_failover_error(def->force_failover, FAILOVER_INVALID_ROLE);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_alter_failover(knl_session_t *session, knl_alterdb_def_t *def)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    log_context_t *redo_ctx = &kernel->redo_ctx;
    switch_ctrl_t *ctrl = &kernel->switch_ctrl;
    database_t *db = &kernel->db;
    lrcv_context_t *lrcv = &kernel->lrcv_ctx;

    if (db_alter_failover_check(session, def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    GS_LOG_RUN_INF("[DB] database start to %sfailover", def->force_failover ? "force " : "");
    if (DB_IS_RAFT_ENABLED(kernel)) {
        knl_panic(lrcv->session == NULL);
        lrcv->session = NULL;
        raft_pending_switch_request(session, ctrl);
        if (raft_db_start_leader(session) != GS_SUCCESS) {
            ctrl->request = SWITCH_REQ_NONE;
            ctrl->handling = GS_FALSE;
            GS_LOG_RUN_WAR("RAFT: promote leader failed.");
            return GS_ERROR;
        }
    } else {
        if (db_notify_failover_promote(session, lrcv, def->force_failover) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    redo_ctx->promote_begin_time = cm_now();
    redo_ctx->last_rcy_with_gbp = GS_FALSE;
    while (!DB_IS_PRIMARY(db) || ctrl->request != SWITCH_REQ_NONE) {
        if (session->killed) {
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            return GS_ERROR;
        }

        cm_spin_lock(&ctrl->lock, NULL);
        if (ctrl->request != SWITCH_REQ_NONE && !knl_failover_triggered_pending(session->kernel)) {
            cm_spin_unlock(&ctrl->lock);
            db_throw_failover_error(def->force_failover, FAILOVER_ABORT_BY_OTHER);
            return GS_ERROR;
        }
        if (ctrl->request == SWITCH_REQ_NONE && !ctrl->handling) {
            cm_spin_unlock(&ctrl->lock);
            db_throw_failover_error(def->force_failover, FAILOVER_ABORT_BY_MASTER);
            return GS_ERROR;
        }
        cm_spin_unlock(&ctrl->lock);
        cm_sleep(10);
    }

    if (KNL_GBP_ENABLE(session->kernel)) {
        gbp_reset_unsafe(session);
    }

    redo_ctx->promote_end_time = cm_now();
    GS_LOG_RUN_INF("%sfailover completed", def->force_failover ? "force " : "");

    return GS_SUCCESS;
}

static status_t db_notify_lrcv_switchover(knl_session_t *session, lrcv_context_t *lrcv)
{
    switch_ctrl_t *ctrl = &session->kernel->switch_ctrl;

    cm_spin_lock(&lrcv->lock, NULL);
    if (lrcv->session == NULL || (lrcv->status != LRCV_PREPARE && lrcv->status != LRCV_READY)) {
        cm_spin_unlock(&lrcv->lock);
        GS_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "could not issue switchover when primary isn't connected");
        return GS_ERROR;
    }

    if (lrcv->state != REP_STATE_NORMAL) {
        cm_spin_unlock(&lrcv->lock);
        GS_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "switchover aborted by other request");
        return GS_ERROR;
    }

    if (!lrcv_switchover_enabled(session)) {
        cm_spin_unlock(&lrcv->lock);
        GS_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST,
            "could not issue switchover for the link from this node to peer(primary) is disabled");
        return GS_ERROR;
    }

    cm_spin_lock(&ctrl->lock, NULL);

    if (ctrl->request != SWITCH_REQ_NONE) {
        cm_spin_unlock(&ctrl->lock);
        cm_spin_unlock(&lrcv->lock);
        GS_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "server is handling another switch request");
        return GS_ERROR;
    }

    cm_spin_unlock(&ctrl->lock);

    lrcv->state = REP_STATE_DEMOTE_REQUEST;
    cm_spin_unlock(&lrcv->lock);

    GS_LOG_RUN_INF("[DB] notify log receiver to do switchover");

    return GS_SUCCESS;
}

static bool32 db_switchover_timeout_check(knl_session_t *session, knl_alterdb_def_t *def, date_t begin_time)
{
    lrcv_context_t *lrcv = &session->kernel->lrcv_ctx;

    if (def->switchover_timeout == 0) {
        return GS_FALSE;
    }

    if ((g_timer()->now - begin_time) / MICROSECS_PER_SECOND >= def->switchover_timeout) {
        cm_spin_lock(&lrcv->lock, NULL);
        if (lrcv->state != REP_STATE_STANDBY_PROMOTING) {
            lrcv->state = REP_STATE_NORMAL;
            cm_spin_unlock(&lrcv->lock);
            return GS_TRUE;
        }
        cm_spin_unlock(&lrcv->lock);
    }

    return GS_FALSE;
}

static status_t db_alter_switchover_check(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;

    if (db->status != DB_STATUS_OPEN) {
        GS_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "switchover cannot be issued when database isn't in open status");
        return GS_ERROR;
    }

    if (db->terminate_lfn != GS_INVALID_LFN) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "switchover with terminated lfn");
        return GS_ERROR;
    }

    if (DB_IS_RAFT_ENABLED(kernel)) {
        GS_THROW_ERROR(ERR_RAFT_ENABLED);
        return GS_ERROR;
    }

    if (!DB_IS_PHYSICAL_STANDBY(db)) {
        GS_THROW_ERROR(ERR_DATABASE_ROLE, "switchover", "not in standby mode");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_alter_switchover(knl_session_t *session, knl_alterdb_def_t *def)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    switch_ctrl_t *ctrl = &kernel->switch_ctrl;
    lrcv_context_t *lrcv = &kernel->lrcv_ctx;
    database_t *db = &kernel->db;
    date_t begin_time = g_timer()->now;

    ctrl->peer_repl_port = lrcv->peer_repl_port;

    if (db_alter_switchover_check(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_notify_lrcv_switchover(session, lrcv) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (DB_IS_PHYSICAL_STANDBY(db) || ctrl->request != SWITCH_REQ_NONE) {
        if (session->killed) {
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            return GS_ERROR;
        }

        if (lrcv->state == REP_STATE_REJECTED) {
            GS_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "switchover request rejected");
            GS_LOG_RUN_ERR("[DB] switchover request rejected");
            lrcv->state = REP_STATE_NORMAL;
            return GS_ERROR;
        }

        if (lrcv->state == REP_STATE_DEMOTE_FAILED) {
            GS_THROW_ERROR(ERR_PEER_CLOSED, "switchover failed, for tcp");
            GS_LOG_RUN_ERR("[DB] switchover failed, for connection is closed");
            lrcv->state = REP_STATE_NORMAL;
            return GS_ERROR;
        }

        if (db_switchover_timeout_check(session, def, begin_time)) {
            GS_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "switchover timeout");
            GS_LOG_RUN_ERR("[DB] switchover timeout");
            return GS_ERROR;
        }

        cm_sleep(10);
    }
    GS_LOG_RUN_INF("switchover completed");

    return GS_SUCCESS;
}

status_t db_alter_logicrep(knl_session_t *session, lrep_mode_t logic_mode)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;

    if (db->status != DB_STATUS_OPEN) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in OPEN mode");
        return GS_ERROR;
    }

    if (logic_mode == LOG_REPLICATION_ON) {
        bool32 has_nolog = GS_FALSE;
        if (knl_database_has_nolog_object(session, &has_nolog) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (has_nolog) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "set logic mode on when database has nolog object");
            return GS_ERROR;
        }
    }
    
    db->ctrl.core.lrep_mode = logic_mode;
    ckpt_get_trunc_point(session, &db->ctrl.core.lrep_point);

    if (db_save_core_ctrl(session) != GS_SUCCESS) {
        CM_ABORT(0, "[DB] ABORT INFO: failed to save core control file when alter database");
    }
    return GS_SUCCESS;
}

status_t db_alter_archivelog(knl_session_t *session, archive_mode_t archive_mode)
{
    return GS_SUCCESS;
}

status_t db_alter_charset(knl_session_t *session, uint32 charset_id)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;

    if (db->status != DB_STATUS_OPEN) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in OPEN mode");
        return GS_ERROR;
    }

    db->ctrl.core.charset_id = charset_id;
    if (db_save_core_ctrl(session) != GS_SUCCESS) {
        CM_ABORT(0, "[DB] ABORT INFO: failed to save core control file when alter database");
    }
    return GS_SUCCESS;
}

status_t db_alter_datafile(knl_session_t *session, knl_alterdb_datafile_t *def)
{
    status_t status = GS_ERROR;

    if (DB_IS_READONLY(session)) {
        GS_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "operation on read only mode");
        return GS_ERROR;
    }

    switch (def->alter_datafile_mode) {
        case ALTER_DF_AUTOEXTEND_OFF:
        case ALTER_DF_AUTOEXTEND_ON:
            status = spc_alter_datafile_autoextend(session, def);
            break;
        case ALTER_DF_RESIZE:
            status = spc_alter_datafile_resize(session, def);
            break;
        default:
            GS_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "alter datafile mode");
            GS_LOG_DEBUG_ERR("the alter datafile mode 0x%8X is not supported.", def->alter_datafile_mode);
            return GS_ERROR;
        }

    return status;
}
