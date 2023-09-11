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
 * dtc_backup.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_backup.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_defs.h"
#include "knl_log.h"
#include "knl_backup.h"
#include "knl_archive.h"
#include "bak_restore.h"
#include "bak_paral.h"
#include "dtc_backup.h"
#include "dtc_database.h"
#include "dtc_log.h"
#include "dtc_ckpt.h"

static status_t dtc_load_archive(list_t *arch_dir_list)
{
    char file_name[GS_FILE_NAME_BUFFER_SIZE] = {0};
    int32 fp;
    char *buf = NULL;
    uint32 buf_size;
    text_t text;
    text_t line;
    char *dir = NULL;
    errno_t err;

    err = snprintf_s(file_name, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s/cfg/%s", g_instance->home,
                     ARCHIVE_FILENAME);
    PRTS_RETURN_IFERR(err);

    if (!cm_file_exist((const char *)file_name) || cm_open_file((const char *)file_name, O_RDONLY, &fp) != GS_SUCCESS) {
        cm_reset_error();
        return GS_SUCCESS;
    }
    buf = (char *)malloc(SIZE_K(64));
    if (buf == NULL) {
        cm_close_file(fp);
        return GS_ERROR;
    }
    err = memset_s(buf, SIZE_K(64), 0, SIZE_K(64));
    if (err != EOK) {
        cm_close_file(fp);
        CM_FREE_PTR(buf);
        return GS_ERROR;
    }
    if (cm_read_file(fp, buf, SIZE_K(64), (int32 *)&buf_size) != GS_SUCCESS) {
        cm_close_file(fp);
        CM_FREE_PTR(buf);
        return GS_ERROR;
    }

    text.len = buf_size;
    text.str = buf;

    while (cm_fetch_text(&text, '\n', '\0', &line)) {
        cm_trim_text(&line);
        if (line.len == 0 || line.str[0] == '#') {
            continue;
        }

        if (line.len >= GS_MAX_PATH_BUFFER_SIZE) {
            GS_LOG_RUN_ERR("dir name length larger than max size %u.", GS_MAX_PATH_BUFFER_SIZE);
            cm_close_file(fp);
            CM_FREE_PTR(buf);
            return GS_ERROR;
        }

        if (cm_list_new(arch_dir_list, (void **)&dir) == GS_ERROR) {
            cm_close_file(fp);
            CM_FREE_PTR(buf);
            return GS_ERROR;
        }
        cm_text2str(&line, dir, GS_MAX_PATH_BUFFER_SIZE);
        dir = NULL;
    }
    CM_FREE_PTR(buf);
    cm_close_file(fp);

    return GS_SUCCESS;
}

uint32 dtc_get_mes_sent_success_cnt(uint64 success_inst_left)
{
    uint32 res = 0;
    uint64 success_inst = success_inst_left;
    while (success_inst) {
        ++res;
        success_inst = success_inst & (success_inst - 1);
    }

    return res;
}

void dtc_bak_file_blocking(knl_session_t *session, uint32 file_id, uint32 sec_id, uint64 start, uint64 end, uint64 *success_inst)
{
    msg_block_file_bcast_t bcast;

    mes_init_send_head(&bcast.head, MES_CMD_BLOCK_FILE, sizeof(msg_block_file_bcast_t), GS_INVALID_ID32,
                       session->kernel->id, GS_INVALID_ID8, session->id, GS_INVALID_ID16);
    bcast.block.file_id = file_id;
    bcast.block.sec_id = sec_id;
    bcast.block.start = start;
    bcast.block.end = end;

    mes_broadcast(session->id, MES_BROADCAST_ALL_INST, &bcast, success_inst);
}

void bak_process_block_file(void *sess, mes_message_t *msg)
{
    msg_block_file_bcast_t *bcast = (msg_block_file_bcast_t *)msg->buffer;
    knl_session_t *session = (knl_session_t *)sess;

    if (bcast->block.file_id >= GS_MAX_DATA_FILES) {
        GS_LOG_RUN_ERR("bcast->block.file_id(%u) err, larger than %u", bcast->block.file_id, GS_MAX_DATA_FILES);
        mes_release_message_buf(msg->buffer);
        return;
    }
    datafile_t *df = DATAFILE_GET(session, bcast->block.file_id);

    if (bcast->block.sec_id >= DATAFILE_MAX_BLOCK_NUM) {
        GS_LOG_RUN_ERR("bcast->block.sec_id(%u) err, larger than %u", bcast->block.sec_id, DATAFILE_MAX_BLOCK_NUM);
        mes_release_message_buf(msg->buffer);
        return;
    }
 
    if (bcast->block.start >= bcast->block.end) {
        GS_LOG_RUN_ERR("bcast->block.start(%llu) is not less than bcast->block.end(%llu)", bcast->block.start,
            bcast->block.end);
        mes_release_message_buf(msg->buffer);
        return;
    }
    spc_block_datafile(df, bcast->block.sec_id, bcast->block.start, bcast->block.end);
    mes_release_message_buf(msg->buffer);
}

void dtc_bak_file_unblocking(knl_session_t *session, uint32 file_id, uint32 sec_id)
{
    msg_block_file_bcast_t bcast;

    mes_init_send_head(&bcast.head, MES_CMD_UNBLOCK_FILE, sizeof(msg_block_file_bcast_t), GS_INVALID_ID32,
                       session->kernel->id, GS_INVALID_ID8, session->id, GS_INVALID_ID16);
    bcast.block.file_id = file_id;
    bcast.block.sec_id = sec_id;
    bcast.block.start = GS_INVALID_INT64;
    bcast.block.end = GS_INVALID_INT64;

    mes_broadcast(session->id, MES_BROADCAST_ALL_INST, &bcast, NULL);
}

void bak_process_unblock_file(void *sess, mes_message_t *msg)
{
    msg_block_file_bcast_t *bcast = (msg_block_file_bcast_t *)msg->buffer;
    knl_session_t *session = (knl_session_t *)sess;

    if (bcast->block.file_id >= GS_MAX_DATA_FILES) {
        GS_LOG_RUN_ERR("bcast->block.file_id(%u) err, larger than %u", bcast->block.file_id, GS_MAX_DATA_FILES);
        mes_release_message_buf(msg->buffer);
        return;
    }
    datafile_t *df = DATAFILE_GET(session, bcast->block.file_id);

    if (bcast->block.sec_id >= DATAFILE_MAX_BLOCK_NUM) {
        GS_LOG_RUN_ERR("bcast->block.sec_id(%u) err, larger than %u", bcast->block.sec_id, DATAFILE_MAX_BLOCK_NUM);
        mes_release_message_buf(msg->buffer);
        return;
    }
    spc_unblock_datafile(df, bcast->block.sec_id);
    mes_release_message_buf(msg->buffer);
}

status_t dtc_bak_get_log_asn_by_lsn(knl_session_t *session, log_start_end_lsn_t *lsn,
                                    log_start_end_asn_t *asn, uint32 inst_id)
{
    if (dtc_get_log_asn_by_lsn(session, lsn, inst_id, asn) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] dtc get log curr_asn failed.");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t dtc_bak_switch_logfile(knl_session_t *session, uint32 last_asn, uint32 inst_id)
{
    uint32 curr_asn;
    if (dtc_get_log_curr_asn(session, inst_id, &curr_asn) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] dtc get log curr_asn failed.");
        return GS_ERROR;
    }
    if (curr_asn < last_asn) {
        GS_LOG_RUN_ERR("[BACKUP] the obtained cur asn value is incorrect");
        return GS_ERROR;
    }
    if (curr_asn != last_asn) {
        return GS_SUCCESS;
    }

    if (dtc_ckpt_trigger(session, NULL, GS_FALSE, CKPT_TRIGGER_INC, inst_id, GS_TRUE, GS_FALSE) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] dtc chpt trigger failed.");
        return GS_ERROR;
    }

    if (DB_IS_RAFT_ENABLED(session->kernel) || DB_IS_PRIMARY(&session->kernel->db)) {
        return dtc_log_switch(session, 0, inst_id);
    } else {
        return GS_SUCCESS;
    }

    return GS_SUCCESS;
}

status_t dtc_bak_fetch_last_log(knl_session_t *session, bak_t *bak, uint32 *last_asn, uint32 inst_id)
{
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;

    if (bak->record.log_only) {
        GS_LOG_RUN_ERR("[BACKUP] log_only option not support in daac.");
        return GS_ERROR;
    } else {
        *last_asn = ctrlinfo->dtc_lrp_point[inst_id].asn;
    }

    return dtc_bak_switch_logfile(session, *last_asn, inst_id);
}

status_t dtc_bak_get_arch_start_and_end_point(knl_session_t *session, uint32 inst_id,
                                              uint32 *start_asn, uint32 *end_asn)
{
    knl_instance_t *kernel = session->kernel;
    bak_context_t *ctx = &kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;

    if (BAK_IS_DBSOTR(bak)) {
        log_start_end_asn_t asn = {0, 0};
        log_start_end_lsn_t lsn = {ctrlinfo->dtc_rcy_point[inst_id].lsn,
                                   bak->max_lrp_lsn};
        if (dtc_bak_get_log_asn_by_lsn(session, &lsn, &asn, inst_id) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[BACKUP] dtc fetch start end log failed");
            return GS_ERROR;
        }
        *start_asn = asn.start_asn;
        *end_asn = asn.end_asn;
        GS_LOG_RUN_INF("[BACKUP] get arch start asn %u end asn %u instid %u", asn.start_asn, asn.end_asn, inst_id);
    } else {
        *start_asn = ctrlinfo->dtc_rcy_point[inst_id].asn;
        if (dtc_bak_fetch_last_log(session, bak, end_asn, inst_id) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[BACKUP] dtc fetch last log failed");
            return GS_ERROR;
        }
        if (*end_asn < ctrlinfo->dtc_lrp_point[inst_id].asn) {
            GS_LOG_RUN_ERR("[BACKUP] dtc fetch last log asn value is incorrect");
            return GS_ERROR;
        }
    }
    if (*end_asn < *start_asn) {
        GS_LOG_RUN_ERR("[BACKUP] the obtained log start and end log asn value is incorrect");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static bool32 dtc_bak_read_log_check_param(knl_session_t *session, uint32 *curr_asn, uint32 inst_id)
{
    knl_instance_t *kernel = session->kernel;
    bak_context_t *ctx = &kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_stage_t *stage = &bak->progress.build_progress.stage;
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;

    if (BAK_IS_FULL_BUILDING(bak) && bak_get_build_stage(stage) > BUILD_LOG_STAGE) {
        GS_LOG_RUN_INF("[BUILD] ignore read logfiles for break-point building");
        return GS_FALSE;
    }

    if (BAK_IS_FULL_BUILDING(bak) && bak_get_build_stage(stage) == BUILD_LOG_STAGE) {
        GS_LOG_RUN_INF("[BUILD] break-point condition, curr asn : %u", bak->progress.build_progress.asn);
        *curr_asn = (uint32)bak->progress.build_progress.asn;
    }

    if (BAK_IS_DBSOTR(bak) &&
       (log_cmp_point_lsn(&(ctrlinfo->dtc_rcy_point[inst_id]), &(ctrlinfo->dtc_lrp_point[inst_id])) == 0)) {
        GS_LOG_RUN_INF("[BACKUP] instid %u no arch file bak", inst_id);
        if (bak_paral_task_enable(session)) {
            /* parallel backup dose not enter bak_write_end, need update curr_file_index here */
            bak->curr_file_index = bak->file_count;
        }
        return GS_FALSE;
    }

    return GS_TRUE;
}

static status_t dtc_bak_read_logfile_data(knl_session_t *session, bak_process_t *proc, uint32 block_size,
                                          uint32 inst_id)
{
    if (bak_paral_task_enable(session)) {
        if (bak_assign_backup_task(session, proc, 0, GS_FALSE) != GS_SUCCESS) {
            dtc_ctbak_unlatch_logfile(session, proc, inst_id);
            return GS_ERROR;
        }
    } else {
        bool32 arch_compressed = GS_FALSE;
        status_t status = bak_read_logfile(session, &(session->kernel->backup_ctx),
                                           proc, block_size, GS_FALSE, &arch_compressed);
        dtc_ctbak_unlatch_logfile(session, proc, inst_id);
        cm_close_device(proc->ctrl.type, &proc->ctrl.handle);
        if (status != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (bak_wait_write(&(session->kernel->backup_ctx.bak)) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t dtc_bak_read_logfiles(knl_session_t *session, uint32 inst_id)
{
    knl_instance_t *kernel = session->kernel;
    bak_context_t *ctx = &kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;
    uint32 curr_asn = (uint32)ctrlinfo->dtc_rcy_point[inst_id].asn;
    bak_process_t *proc = &ctx->process[BAK_COMMON_PROC];
    uint32 last_asn;
    uint64 data_size;
    uint32 block_size = 0;
    int64 curr_size;

    bak->inst_id = inst_id;

    if (dtc_bak_read_log_check_param(session, &curr_asn, inst_id) == GS_FALSE) {
        return GS_SUCCESS;
    }

    if (dtc_bak_get_arch_start_and_end_point(session, inst_id, &curr_asn, &last_asn) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] dtc get log start and end log failed");
        return GS_ERROR;
    }

    if (dtc_get_log_curr_size(session, inst_id, &curr_size) != GS_SUCCESS) {
        return GS_ERROR;
    }
    data_size = (uint64)curr_size * (last_asn - curr_asn + 1);
    bak_set_progress(session, BACKUP_LOG_STAGE, data_size);

    for (; curr_asn <= last_asn; curr_asn++) {
        if (curr_asn == last_asn && !BAK_IS_DBSOTR(bak)) {
            if (dtc_bak_switch_logfile(session, last_asn, inst_id) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (bak_paral_task_enable(session)) {
            if (bak_get_free_proc(session, &proc, GS_FALSE) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (dtc_bak_set_log_ctrl(session, proc, curr_asn, &block_size, inst_id) != GS_SUCCESS) {
            dtc_ctbak_unlatch_logfile(session, proc, inst_id);
            return GS_ERROR;
        }

        if (dtc_bak_read_logfile_data(session, proc, block_size, inst_id) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    bak_wait_paral_proc(session, GS_FALSE);
    if (bak_paral_task_enable(session)) {
        /* parallel backup dose not enter bak_write_end, need update curr_file_index here */
        bak->curr_file_index = bak->file_count;
    }

    return GS_SUCCESS;
}

status_t dtc_bak_read_all_logfiles(knl_session_t *session)
{
    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        if (SECUREC_UNLIKELY(i == g_dtc->profile.inst_id)) {
            continue;
        } else {
            if (!rc_bitmap64_exist(&session->kernel->backup_ctx.bak.target_bits, i)) {
                continue;
            }
            status_t s = dtc_bak_read_logfiles(session, i);
            if (s != GS_SUCCESS) {
                return s;
            }
        }
    }
    return GS_SUCCESS;
}

status_t dtc_bak_set_log_ctrl(knl_session_t *session, bak_process_t *process, uint32 asn, uint32 *block_size,
                              uint32 target_id)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    database_t *db = &session->kernel->db;
    bak_t *bak = &ctx->bak;
    uint32 rst_id = bak_get_rst_id(bak, asn, &(db->ctrl.core.resetlogs));
    errno_t ret;

    mes_message_head_t head;
    mes_message_t  msg;
    bak_log_file_info_t log_file;
    log_file.asn = asn;
    log_file.backup_type = (uint32)(bak->record.data_type);
    mes_init_send_head(&head, MES_CMD_SET_LOG_CTRL, sizeof(mes_message_head_t) + sizeof(bak_log_file_info_t),
                       GS_INVALID_ID32, session->kernel->dtc_attr.inst_id, target_id, session->id, GS_INVALID_ID16);

    if (mes_send_data2(&head, &log_file) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "send set log ctrl mes ");
        return GS_ERROR;
    }

    if (mes_recv(session->id, &msg, GS_FALSE, GS_INVALID_ID32, BAK_WAIT_TIMEOUT) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "receive set log ctrl mes ");
        return GS_ERROR;
    }

    if (SECUREC_UNLIKELY(msg.head->cmd != MES_CMD_SET_LOG_CTRL_ACK)) {
        mes_release_message_buf(msg.buffer);
        return GS_ERROR;
    }

    msg_log_ctrl_t log_ctrl;
    log_ctrl = *(msg_log_ctrl_t *)(msg.buffer + sizeof(mes_message_head_t));
    mes_release_message_buf(msg.buffer);

    if (log_ctrl.status == GS_ERROR) {
        return GS_ERROR;
    }

    process->assign_ctrl.file_id = log_ctrl.file_id;
    process->assign_ctrl.file_size = log_ctrl.file_size;
    ret = strcpy_sp(process->ctrl.name, GS_FILE_NAME_BUFFER_SIZE, log_ctrl.name);
    knl_securec_check(ret);
    process->ctrl.type = log_ctrl.type;
    *block_size = log_ctrl.block_size;
    if (log_ctrl.is_archivelog) {
        bak_record_new_file(bak, BACKUP_ARCH_FILE, asn, 0, rst_id, GS_FALSE, log_ctrl.start_lsn, log_ctrl.end_lsn);
    } else {
        bak_record_new_file(bak, BACKUP_LOG_FILE, log_ctrl.file_id, 0, rst_id, GS_FALSE,
                            log_ctrl.start_lsn, log_ctrl.end_lsn);
    }

    if (cm_open_device(process->ctrl.name, process->ctrl.type, knl_io_flag(session), &process->ctrl.handle) !=
        GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] failed to open %s", process->ctrl.name);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static uint32 dtc_bak_get_rst_id(uint32 data_type, uint32 asn, reset_log_t *rst_log)
{
    if (data_type == DATA_TYPE_DBSTOR) {
        // rst_id = bak->record.ctrlinfo.rcy_point.lsn <= rst_log->last_lsn ? (rst_log->rst_id - 1) : rst_log->rst_id;
        return rst_log->rst_id;
    } else {
        return asn <= rst_log->last_asn ? (rst_log->rst_id - 1) : rst_log->rst_id;
    }
}

static void dtc_bak_init_log_ctrl(msg_log_ctrl_t *log_ctrl, arch_ctrl_t *arch_ctrl)
{
    errno_t ret = strcpy_sp(log_ctrl->name, GS_FILE_NAME_BUFFER_SIZE, arch_ctrl->name);
    knl_securec_check(ret);
    log_ctrl->type = cm_device_type(log_ctrl->name);
    log_ctrl->block_size = (uint32)arch_ctrl->block_size;
    log_ctrl->is_archivelog = GS_TRUE;
    log_ctrl->start_lsn = arch_ctrl->start_lsn;
    log_ctrl->end_lsn = arch_ctrl->end_lsn;

    return;
}

void dtc_bak_process_set_log_ctrl(void *sess, mes_message_t * receive_msg)
{
    bak_log_file_info_t log_file = *(bak_log_file_info_t *)(receive_msg->buffer + sizeof(mes_message_head_t));
    knl_session_t *session = (knl_session_t *)sess;
    database_t *db = &session->kernel->db;
    arch_ctrl_t *arch_ctrl = NULL;
    if (log_file.backup_type != (knl_dbs_is_enable_dbs() ? DATA_TYPE_DBSTOR : DATA_TYPE_FILE)) {
        GS_LOG_RUN_ERR("[BACKUP] the backup file type is not supported by the current database");
        return;
    }
    uint32 rst_id = dtc_bak_get_rst_id(log_file.backup_type, log_file.asn, &(db->ctrl.core.resetlogs));
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);
    msg_log_ctrl_t log_ctrl;

    log_ctrl.file_id = bak_log_get_id(session, log_file.backup_type, rst_id, log_file.asn);
    log_ctrl.file_size = 0;
    if (log_ctrl.file_id == GS_INVALID_ID32) {
        arch_ctrl = arch_get_archived_log_info(session, rst_id, log_file.asn, ARCH_DEFAULT_DEST, session->kernel->id);
        if (arch_ctrl == NULL) {
            GS_LOG_RUN_ERR("[BACKUP] failed to get archived log for [%u-%u]", rst_id, log_file.asn);
            log_ctrl.status = GS_ERROR;
        } else {
            dtc_bak_init_log_ctrl(&log_ctrl, arch_ctrl);
            GS_LOG_DEBUG_INF("[BACKUP] Get archived log %s for [%u-%u]", log_ctrl.name, rst_id, log_file.asn);
        }
    } else {
        log_file_t *file = &logfile_set->items[log_ctrl.file_id];
        errno_t ret = strcpy_sp(log_ctrl.name, GS_FILE_NAME_BUFFER_SIZE, file->ctrl->name);
        knl_securec_check(ret);
        log_ctrl.type = file->ctrl->type;
        log_ctrl.block_size = file->ctrl->block_size;
        GS_LOG_DEBUG_INF("[BACKUP] Get online log %s for [%u-%u] write pos %llu", log_ctrl.name, rst_id, log_file.asn,
                         file->head.write_pos);

        dtc_node_ctrl_t *node_ctrl = NULL;
        node_ctrl = dtc_my_ctrl(session);
        if (log_ctrl.file_id == node_ctrl->log_last) {
            log_ctrl.is_archivelog = GS_FALSE;
            log_ctrl.file_size = file->head.write_pos;
        } else {
            log_ctrl.is_archivelog = GS_TRUE;
        }
        log_ctrl.start_lsn = 0;
        log_ctrl.end_lsn = 0;
    }

    mes_message_head_t head;

    mes_init_ack_head(receive_msg->head, &head, MES_CMD_SET_LOG_CTRL_ACK, (sizeof(mes_message_head_t) + sizeof(msg_log_ctrl_t)), session->id);

    mes_release_message_buf(receive_msg->buffer);
    if (mes_send_data2(&head, &log_ctrl) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "send get log curr size ack mes ");
        return;
    }
}

status_t dtc_bak_precheck(knl_session_t *session, uint32 target_id, msg_pre_bak_check_t *pre_check)
{
    mes_message_head_t head;
    mes_message_t  msg;

    mes_init_send_head(&head, MES_CMD_BAK_PRECHECK, sizeof(mes_message_head_t), GS_INVALID_ID32,
                       session->kernel->dtc_attr.inst_id, target_id, session->id, GS_INVALID_ID16);

    if (mes_send_data((void *)&head) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "send check is archive mes ");
        return GS_ERROR;
    }

    if (mes_recv(session->id, &msg, GS_FALSE, GS_INVALID_ID32, BAK_WAIT_TIMEOUT) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "receive check is archive mes ");
        return GS_ERROR;
    }

    if (SECUREC_UNLIKELY(msg.head->cmd != MES_CMD_BAK_PRECHECK_ACK)) {
        mes_release_message_buf(msg.buffer);
        return GS_ERROR;
    }

    *pre_check = *(msg_pre_bak_check_t *)(msg.buffer + sizeof(mes_message_head_t));
    mes_release_message_buf(msg.buffer);

    return GS_SUCCESS;
}

void bak_process_precheck(void *sess, mes_message_t * receive_msg)
{
    mes_message_head_t head;
    knl_session_t *session = (knl_session_t *)sess;
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    msg_pre_bak_check_t pre_check;
    pre_check.is_archive = arch_ctx->is_archive;
    pre_check.is_switching = (session->kernel->switch_ctrl.request != SWITCH_REQ_NONE);

    SYNC_POINT_GLOBAL_START(CANTIAN_BACKUP_REV_PRECHECK_REQ_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    mes_init_ack_head(receive_msg->head, &head, MES_CMD_BAK_PRECHECK_ACK, (sizeof(mes_message_head_t) + sizeof(msg_pre_bak_check_t)), session->id);

    mes_release_message_buf(receive_msg->buffer);
    if (mes_send_data2(&head, &pre_check) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "send check is archive ack mes ");
        return;
    }
}

status_t dtc_ctbak_unlatch_logfile(knl_session_t *session, bak_process_t *process, uint32 target_id)
{
    bak_assignment_t *assign_ctrl = &process->assign_ctrl;

    if (assign_ctrl->file_id == GS_INVALID_ID32) {
        return GS_SUCCESS;
    }

    mes_message_head_t head;
    mes_message_t  msg;

    mes_init_send_head(&head, MES_CMD_UNLATCH_LOGFILE, sizeof(mes_message_head_t) + sizeof(uint32), GS_INVALID_ID32,
                       session->kernel->dtc_attr.inst_id, target_id, session->id, GS_INVALID_ID16);

    if (mes_send_data2(&head, &assign_ctrl->file_id) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "send unlatch logfile mes ");
        return GS_ERROR;
    }

    if (mes_recv(session->id, &msg, GS_FALSE, GS_INVALID_ID32, BAK_WAIT_TIMEOUT) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "receive unlatch logfile mes ");
        return GS_ERROR;
    }

    if (SECUREC_UNLIKELY(msg.head->cmd != MES_CMD_UNLATCH_LOGFILE_ACK)) {
        mes_release_message_buf(msg.buffer);
        return GS_ERROR;
    }
    mes_release_message_buf(msg.buffer);

    return GS_SUCCESS;
}

void dtc_process_unlatch_logfile(void *sess, mes_message_t * receive_msg)
{
    mes_message_head_t head;
    uint32 *file_id = (uint32 *)(receive_msg->buffer + sizeof(mes_message_head_t));
    knl_session_t *session = (knl_session_t *)sess;
    
    if (*file_id >= GS_MAX_LOG_FILES) {
        GS_LOG_RUN_ERR("*file_id(%u) err, larger than %u", *file_id, GS_MAX_LOG_FILES);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    log_unlatch_file(session, *file_id);

    mes_init_ack_head(receive_msg->head, &head, MES_CMD_UNLATCH_LOGFILE_ACK, sizeof(mes_message_head_t), session->id);

    mes_release_message_buf(receive_msg->buffer);
    if (mes_send_data((void*)&head) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "send unlatch logfile mes ack ");
        return;
    }
}

status_t dtc_bak_set_lsn(knl_session_t *session, bak_t *bak)
{
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;
    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        if (SECUREC_UNLIKELY(i == g_dtc->profile.inst_id)) {
            continue;
        }
        if (!rc_bitmap64_exist(&session->kernel->backup_ctx.bak.target_bits, i)) {
            continue;
        }

        knl_panic(log_cmp_point(&ctrlinfo->dtc_rcy_point[i], &ctrlinfo->dtc_lrp_point[i]) <= 0);

        mes_message_head_t head;
        mes_message_t  msg;

        mes_init_send_head(&head, MES_CMD_SET_LOG_LSN, sizeof(mes_message_head_t) + sizeof(log_point_t),
                           GS_INVALID_ID32, session->kernel->dtc_attr.inst_id, i, session->id, GS_INVALID_ID16);

        if (mes_send_data2(&head, &ctrlinfo->dtc_rcy_point[i]) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[BACKUP] %s failed", "send get log lsn mes ");
            return GS_ERROR;
        }

        if (mes_recv(session->id, &msg, GS_FALSE, GS_INVALID_ID32, BAK_WAIT_TIMEOUT) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[BACKUP] %s failed", "receive get log lsn mes ");
            return GS_ERROR;
        }

        if (SECUREC_UNLIKELY(msg.head->cmd != MES_CMD_SET_LOG_LSN_ACK)) {
            mes_release_message_buf(msg.buffer);
            return GS_ERROR;
        }

        uint64 curr_lsn = *(uint64 *)(msg.buffer + sizeof(mes_message_head_t));
        mes_release_message_buf(msg.buffer);

        if (ctrlinfo->lsn > curr_lsn) {
            ctrlinfo->lsn = curr_lsn;
        }
    }

    return GS_SUCCESS;
}

void dtc_process_set_lsn_for_file(knl_session_t *session, mes_message_t * receive_msg)
{
    mes_message_head_t head;
    uint64 curr_lsn = 0;
    log_batch_t *batch = NULL;
    log_batch_tail_t *tail = NULL;
    uint32 data_size;
    database_t *db = &session->kernel->db;
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    reset_log_t rst_log = db->ctrl.core.resetlogs;
    log_point_t *start_point = (log_point_t *)(receive_msg->buffer + sizeof(mes_message_head_t));
    uint32 block_size;

    for (;;) {
        if (rcy_load(session, start_point, &data_size, &block_size) != GS_SUCCESS) {
            curr_lsn = GS_INVALID_INT64;
            break;
        }

        batch = (log_batch_t *)session->kernel->rcy_ctx.read_buf.aligned_buf;
        if (data_size >= sizeof(log_batch_t) && data_size >= batch->size) {
            tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));
            if (rcy_validate_batch(batch, tail)) {
                break;
            }
        }

        start_point->asn++;
        start_point->rst_id = bak_get_rst_id(bak, start_point->asn, &(rst_log));
        start_point->block_id = 0;
    }

    if (curr_lsn != GS_INVALID_INT64) {
        rcy_close_file(session);
        curr_lsn = rcy_fetch_batch_lsn(session, batch);
    }

    mes_init_ack_head(receive_msg->head, &head, MES_CMD_SET_LOG_LSN_ACK, (sizeof(mes_message_head_t) + sizeof(uint64)), session->id);

    mes_release_message_buf(receive_msg->buffer);
    if (mes_send_data2(&head, &curr_lsn) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "send set log curr lsn ack mes ");
        return;
    }
}

void dtc_process_set_lsn_for_dbstor(knl_session_t *session, mes_message_t *receive_msg)
{
    mes_message_head_t head;
    log_point_t *start_point = (log_point_t *)(receive_msg->buffer + sizeof(mes_message_head_t));
    dtc_node_ctrl_t *ctrl = dtc_my_ctrl(session);
    uint64 curr_lsn = log_cmp_point(start_point, &(ctrl->lrp_point)) != 0 ?
                                    start_point->lsn : DB_CURR_LSN(session);
    mes_init_ack_head(receive_msg->head, &head, MES_CMD_SET_LOG_LSN_ACK,
                      (sizeof(mes_message_head_t) + sizeof(uint64)), session->id);
    mes_release_message_buf(receive_msg->buffer);
    if (mes_send_data2(&head, &curr_lsn) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "send set log curr lsn ack mes ");
    }
}

void dtc_process_set_lsn(void *sess, mes_message_t *receive_msg)
{
    if (knl_dbs_is_enable_dbs()) {
        dtc_process_set_lsn_for_dbstor((knl_session_t *)sess, receive_msg);
    } else {
        dtc_process_set_lsn_for_file((knl_session_t *)sess, receive_msg);
    }
}

status_t dtc_bak_get_ctrl(knl_session_t *session, uint32 target_id, dtc_node_ctrl_t *node_ctrl)
{
    mes_message_head_t head;
    mes_message_t  msg;

    mes_init_send_head(&head, MES_CMD_BAK_GET_CTRL, sizeof(mes_message_head_t), GS_INVALID_ID32,
                       session->kernel->dtc_attr.inst_id, target_id, session->id, GS_INVALID_ID16);

    if (mes_send_data((void *)&head) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "send bak get ctrl mes ");
        return GS_ERROR;
    }

    if (mes_recv(session->id, &msg, GS_FALSE, GS_INVALID_ID32, BAK_WAIT_TIMEOUT) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "receive bak get ctrl mes ");
        return GS_ERROR;
    }

    if (SECUREC_UNLIKELY(msg.head->cmd != MES_CMD_BAK_GET_CTRL_ACK)) {
        mes_release_message_buf(msg.buffer);
        return GS_ERROR;
    }

    *node_ctrl = *(dtc_node_ctrl_t *)(msg.buffer + sizeof(mes_message_head_t));
    mes_release_message_buf(msg.buffer);

    return GS_SUCCESS;
}

static status_t dtc_bak_log_ckpt_trigger_local(knl_session_t *session, bak_ctrlinfo_t *ctrlinfo, uint32 inst_id,
                                               bool32 update, bool32 force_switch)
{
    knl_instance_t *kernel = session->kernel;
    bak_context_t *ctx = &kernel->backup_ctx;
    bak_t *bak = &ctx->bak;

    if (BAK_IS_DBSOTR(bak) && force_switch) {
        if (arch_switch_archfile_trigger(session, GS_FALSE) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[BACKUP] faile switch archfile");
            return GS_ERROR;
        }
    }

    ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_INC);
    
    if (!update) {
        ctrlinfo->rcy_point = dtc_my_ctrl(session)->rcy_point;
        ctrlinfo->dtc_rcy_point[inst_id] = ctrlinfo->rcy_point;
        ctrlinfo->lrp_point = dtc_my_ctrl(session)->lrp_point;
        ctrlinfo->dtc_lrp_point[inst_id] = ctrlinfo->lrp_point;
        GS_LOG_RUN_INF("[BACKUP] set rcy log point: [%llu/%llu/%llu/%u] instid[%u]",
            (uint64)ctrlinfo->rcy_point.rst_id, ctrlinfo->rcy_point.lsn,
            (uint64)ctrlinfo->rcy_point.lfn, ctrlinfo->rcy_point.asn, inst_id);
    } else {
        ctrlinfo->lrp_point = dtc_my_ctrl(session)->lrp_point;
        ctrlinfo->dtc_lrp_point[inst_id] = ctrlinfo->lrp_point;
        GS_LOG_RUN_INF("[BACKUP] set lrp log point: rst_id:[%llu/%llu/%llu/%u], instid[%u]",
            (uint64)ctrlinfo->lrp_point.rst_id,
            ctrlinfo->lrp_point.lsn, (uint64)ctrlinfo->lrp_point.lfn,
            ctrlinfo->lrp_point.asn, inst_id);
    }
    return GS_SUCCESS;
}

static status_t dtc_bak_log_ckpt_trigger_by_instid(knl_session_t *session, bak_ctrlinfo_t *ctrlinfo, uint32 inst_id,
                                                   bool32 update, bool32 force_switch)
{
    msg_ckpt_trigger_point_t ckpt_result;
    ckpt_result.lsn = 1;
    status_t s = dtc_ckpt_trigger(session, &ckpt_result, GS_TRUE, CKPT_TRIGGER_INC, inst_id, update, force_switch);
    if (s != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (!update) {
        if (ctrlinfo->max_rcy_lsn < ckpt_result.lsn) {
            ctrlinfo->max_rcy_lsn = ckpt_result.lsn;
            dtc_update_lsn(session, ctrlinfo->max_rcy_lsn);
        }
        ctrlinfo->dtc_rcy_point[inst_id] = ckpt_result.point;
        ctrlinfo->dtc_lrp_point[inst_id] = ckpt_result.point;
        GS_LOG_RUN_INF("[BACKUP] set rcy log point: rst_id:[%llu/%llu/%llu/%u] instid[%u]",
            (uint64)ctrlinfo->dtc_rcy_point[inst_id].rst_id, ctrlinfo->dtc_rcy_point[inst_id].lsn,
            (uint64)ctrlinfo->dtc_rcy_point[inst_id].lfn, ctrlinfo->dtc_rcy_point[inst_id].asn, inst_id);
    } else {
        ctrlinfo->dtc_lrp_point[inst_id] = ckpt_result.point;
        GS_LOG_RUN_INF("[BACKUP] set lrp log point: rst_id:[%llu/%llu/%llu/%u], instid[%u]",
            (uint64)ctrlinfo->dtc_lrp_point[inst_id].rst_id,
            ctrlinfo->dtc_lrp_point[inst_id].lsn, (uint64)ctrlinfo->dtc_lrp_point[inst_id].lfn,
            ctrlinfo->dtc_lrp_point[inst_id].asn, inst_id);
    }
    
    return GS_SUCCESS;
}

void dtc_bak_scn_broadcast(knl_session_t *session)
{
    mes_scn_bcast_t bcast;
    uint64 success_inst;

    mes_init_send_head(&bcast.head, MES_CMD_SCN_BROADCAST, sizeof(mes_scn_bcast_t), GS_INVALID_ID32,
                       g_dtc->profile.inst_id, GS_INVALID_ID8, session->id, GS_INVALID_ID16);
    bcast.scn = KNL_GET_SCN(&g_dtc->kernel->scn);
    bcast.min_scn = KNL_GET_SCN(&g_dtc->kernel->local_min_scn);
    bcast.lsn = cm_atomic_get(&g_dtc->kernel->lsn);

    mes_broadcast(session->id, MES_BROADCAST_ALL_INST, &bcast, &success_inst);
}

status_t dtc_bak_set_log_point(knl_session_t *session, bak_ctrlinfo_t *ctrlinfo,
                               bool32 update, bool32 force_switch)
{
    status_t status;
    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        if (i != g_dtc->profile.inst_id) {
            if (!rc_bitmap64_exist(&session->kernel->backup_ctx.bak.target_bits, i)) {
                continue;
            }
            status = dtc_bak_log_ckpt_trigger_by_instid(session, ctrlinfo, i, update, force_switch);
            if (status != GS_SUCCESS) {
                return status;
            }
        } else {
            status = dtc_bak_log_ckpt_trigger_local(session, ctrlinfo, i, update, force_switch);
            if (status != GS_SUCCESS) {
                return status;
            }
        }
    }
    ctrlinfo->scn = DB_CURR_SCN(session);
    if (!update) {
        dtc_bak_scn_broadcast(session);
    }
    return GS_SUCCESS;
}

uint64 dtc_bak_get_max_lrp_lsn(bak_ctrlinfo_t *ctrlinfo)
{
    uint64 lsn = 0;
    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        if (i == g_dtc->profile.inst_id) {
            lsn = MAX(lsn, ctrlinfo->lrp_point.lsn);
        } else {
            lsn = MAX(lsn, ctrlinfo->dtc_lrp_point[i].lsn);
        }
    }
    return lsn;
}

status_t dtc_bak_force_arch_local(knl_session_t *session, uint64 lsn)
{
    if (arch_force_archive_trigger(session, lsn, GS_TRUE) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] faile switch archfile");
        return GS_ERROR;
    }
    GS_LOG_RUN_INF("[BACKUP] get lasn lsn :[%llu], instid[%u]", lsn, session->kernel->id);
    return GS_SUCCESS;
}

status_t dtc_bak_force_arch_by_instid(knl_session_t *session, uint64 lsn, uint32 inst_id)
{
    status_t s = dtc_log_switch(session, lsn, inst_id);
    if (s != GS_SUCCESS) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t dtc_bak_force_arch(knl_session_t *session, bak_ctrlinfo_t *ctrlinfo, uint64 lsn)
{
    status_t status;
    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        if (i == g_dtc->profile.inst_id) {
            status = dtc_bak_force_arch_local(session, lsn);
            if (status != GS_SUCCESS) {
                return status;
            }
        } else {
            if (!rc_bitmap64_exist(&session->kernel->backup_ctx.bak.target_bits, i)) {
                continue;
            }
            status = dtc_bak_force_arch_by_instid(session, lsn, i);
            if (status != GS_SUCCESS) {
                return status;
            }
        }
    }

    ctrlinfo->scn = DB_CURR_SCN(session);
    return GS_SUCCESS;
}

status_t dtc_bak_handle_cluster_arch(knl_session_t *session)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;

    if (session->kernel->attr.clustered) {
        if (BAK_IS_DBSOTR(bak)) {
            uint64 lsn = dtc_bak_get_max_lrp_lsn(ctrlinfo);
            bak->max_lrp_lsn = lsn;
            if (dtc_bak_force_arch(session, ctrlinfo, lsn) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

status_t dtc_bak_handle_log_switch(knl_session_t *session)
{
    status_t status;
    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        if (i == g_dtc->profile.inst_id) {
            status = dtc_bak_force_arch_local(session, GS_INVALID_ID64);
            if (status != GS_SUCCESS) {
                return status;
            }
        } else {
            status = dtc_bak_force_arch_by_instid(session, GS_INVALID_ID64, i);
            if (status != GS_SUCCESS) {
                return status;
            }
        }
    }
    return GS_SUCCESS;
}

status_t dtc_bak_get_node_ctrl_by_node_id(knl_session_t *session, uint32 node_id)
{
    database_t *db = &session->kernel->db;
    bak_t *bak = &session->kernel->backup_ctx.bak;
    ctrl_page_t *pages = (ctrl_page_t *)(bak->ctrl_backup_bak_buf);
    bool32 loaded = GS_FALSE;
    for (int i = 0; i < db->ctrlfiles.count; i++) {
        ctrlfile_t *ctrlfile = &db->ctrlfiles.items[i];
        ctrl_page_t *page = &(pages[node_id]);
        int64 offset = (CTRL_LOG_SEGMENT + node_id) * ctrlfile->block_size;
        if (cm_open_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[BACKUP] failed to open num %d file %s", i, ctrlfile->name);
            continue;
        }
        if (cm_read_device(ctrlfile->type, ctrlfile->handle, offset,
                           page, ctrlfile->block_size) != GS_SUCCESS) {
            cm_close_device(ctrlfile->type, &ctrlfile->handle);
            GS_LOG_RUN_ERR("[BACKUP] get node ctrl failed, ctrl file[%d], instid[%u]", i, node_id);
            continue;
        }
        loaded = GS_TRUE;
        break;
    }
    if (!loaded) {
        GS_THROW_ERROR(ERR_LOAD_CONTROL_FILE, "no usable control file");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

void dtc_bak_copy_ctrl_buf_2_send(knl_session_t *session)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    ctrl_page_t *dst_pages = (ctrl_page_t *)bak->backup_buf;
    ctrl_page_t *src_pages = (ctrl_page_t *)(bak->ctrl_backup_bak_buf);
    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        if (SECUREC_UNLIKELY(i == g_dtc->profile.inst_id)) {
            continue;
        }
        errno_t ret = memcpy_s(dst_pages[CTRL_LOG_SEGMENT + i].buf, sizeof(dtc_node_ctrl_t),
                               src_pages[i].buf, sizeof(dtc_node_ctrl_t));
        knl_panic(ret == 0);
    }
    return;
}

void dtc_bak_copy_ctrl_page_2_buf(knl_session_t *session, dtc_node_ctrl_t *node_ctrl, uint32 inst_id)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    ctrl_page_t *pages = (ctrl_page_t *)(bak->ctrl_backup_bak_buf);
    errno_t ret = memcpy_s(pages[inst_id].buf, sizeof(dtc_node_ctrl_t),
                           node_ctrl, sizeof(dtc_node_ctrl_t));
    knl_panic(ret == 0);
}

status_t dtc_bak_get_ctrl_all(knl_session_t *session)
{
    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        if (SECUREC_UNLIKELY(i == g_dtc->profile.inst_id)) {
            continue;
        }
        if (!rc_bitmap64_exist(&session->kernel->backup_ctx.bak.target_bits, i)) {
            if (dtc_bak_get_node_ctrl_by_node_id(session, i) != GS_SUCCESS) {
                return GS_ERROR;
            }
        } else {
            dtc_node_ctrl_t tmp_ctrl;
            if (dtc_bak_get_ctrl(session, i, &tmp_ctrl) != GS_SUCCESS) {
                return GS_ERROR;
            }
            dtc_bak_copy_ctrl_page_2_buf(session, &tmp_ctrl, i);
        }
    }
    return GS_SUCCESS;
}

void dtc_process_bak_get_ctrl(void *sess, mes_message_t * receive_msg)
{
    mes_message_head_t head;
    knl_session_t *session = (knl_session_t *)sess;
    database_t *db = &session->kernel->db;
    dtc_node_ctrl_t *node_ctrl = (dtc_node_ctrl_t *)cm_push(session->stack, sizeof(dtc_node_ctrl_t));
    
    SYNC_POINT_GLOBAL_START(CANTIAN_BACKUP_REV_CTRL_REQ_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    cm_spin_lock(&db->ctrl_lock, NULL);
    *node_ctrl = *(dtc_my_ctrl(session));
    cm_spin_unlock(&db->ctrl_lock);

    mes_init_ack_head(receive_msg->head, &head, MES_CMD_BAK_GET_CTRL_ACK,
                      (sizeof(mes_message_head_t) + sizeof(dtc_node_ctrl_t)), session->id);
    mes_release_message_buf(receive_msg->buffer);
    if (mes_send_data2(&head, node_ctrl) != GS_SUCCESS) {
        cm_pop(session->stack);
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "send bak get ctrl ack mes ");
        return;
    }
    cm_pop(session->stack);
}

void dtc_rst_arch_set_arch_start_and_end(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    dtc_node_ctrl_t *node_ctrl = NULL;
    for (uint32 i = 0; i < kernel->db.ctrl.core.node_count; i++) {
        node_ctrl = dtc_get_ctrl(session, i);
        node_ctrl->archived_start = 0;
        node_ctrl->archived_end = 0;
    }
}

void dtc_rst_db_init_logfile_ctrl(knl_session_t *session, uint32 *offset)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    logfile_set_t *logfile_set = NULL;

    for (uint32 i = 0; i < kernel->db.ctrl.core.node_count; i++) {
        logfile_set =  &(kernel->db.logfile_sets[i]);
        for (uint32 logid = 0; logid < GS_MAX_LOG_FILES; logid++) {
            logfile_set->items[logid].ctrl = (log_file_ctrl_t *)db_get_log_ctrl_item(db->ctrl.pages, logid,
                                                                                     sizeof(log_file_ctrl_t),
                                                                                     *offset, i);
            logfile_set->items[logid].handle = GS_INVALID_ID32;

            if (logfile_set->items[logid].ctrl->block_size == 0 && logfile_set->items[logid].ctrl->size == 0) {
                break;
            }
        }
    }
}

static inline void arch_init_proc_ctx(arch_proc_context_t *proc_ctx, arch_ctrl_t *arch_ctrl)
{
    proc_ctx->last_archived_log_record.asn = arch_ctrl->asn + 1;
    proc_ctx->last_archived_log_record.rst_id = arch_ctrl->rst_id;
    proc_ctx->last_archived_log_record.start_lsn = GS_INVALID_ID64;
    proc_ctx->last_archived_log_record.end_lsn = arch_ctrl->end_lsn;
    proc_ctx->last_archived_log_record.cur_lsn = arch_ctrl->end_lsn;
    GS_LOG_DEBUG_INF("[ARCH] archinit asn[%u], rst_id[%u], end_lsn[%llu]",
        proc_ctx->last_archived_log_record.asn, arch_ctrl->rst_id, arch_ctrl->end_lsn);
}

void dtc_rst_db_init_logfile_ctrl_by_dbstor(knl_session_t *session, uint32 *offset)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    logfile_set_t *logfile_set = NULL;
    for (uint32 i = 0; i < kernel->db.ctrl.core.node_count; i++) {
        logfile_set =  &(kernel->db.logfile_sets[i]);
        for (uint32 logid = 0; logid < GS_MAX_LOG_FILES; logid++) {
            logfile_set->items[logid].ctrl = (log_file_ctrl_t *)db_get_log_ctrl_item(db->ctrl.pages, logid,
                sizeof(log_file_ctrl_t), *offset, i);
            logfile_set->items[logid].handle = GS_INVALID_ID32;
        }
    }
}

status_t dtc_rst_arch_record_archinfo(knl_session_t *session, uint32 dest_pos, const char *file_name,
                                      log_file_head_t *log_head, uint32 inst_id)
{
    arch_ctrl_t *arch_ctrl = NULL;
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    uint32 dest_id = dest_pos - 1;
    arch_proc_context_t *proc_ctx = &arch_ctx->arch_proc[dest_id];
    uint32 archived_start = arch_get_arch_start(session, inst_id);
    uint32 archived_end = arch_get_arch_end(session, inst_id);
    uint32 end_pos = (archived_end + 1) % GS_MAX_ARCH_NUM;
    uint32 recid;
    uint32 id;

    cm_spin_lock(&arch_ctx->record_lock, NULL);
    recid = ++arch_ctx->dtc_archived_recid[inst_id];
    cm_spin_unlock(&arch_ctx->record_lock);

    cm_spin_lock(&proc_ctx->record_lock, NULL);

    if (end_pos == archived_start) {
        arch_ctrl = db_get_arch_ctrl(session, end_pos, inst_id);
        arch_ctrl->recid = 0;
        archived_end = (archived_start + 1) % GS_MAX_ARCH_NUM;
        arch_set_arch_end(session, archived_end, inst_id);
        if (dtc_save_ctrl(session, inst_id) != GS_SUCCESS) {
            cm_spin_unlock(&proc_ctx->record_lock);
            CM_ABORT(0, "[ARCH] ABORT INFO: save core control file failed when record archive info");
        }
    }

    id = archived_end;
    arch_ctrl = db_get_arch_ctrl(session, id, inst_id);
    arch_init_arch_ctrl(session, arch_ctrl, recid, dest_id, file_name, log_head);

    if (arch_ctx->inst_id == inst_id) {
        proc_ctx->curr_arch_size += (int64)log_head->write_pos;
        if (cm_dbs_is_enable_dbs() == GS_TRUE) {
            arch_init_proc_ctx(proc_ctx, arch_ctrl);
        }
    }
    arch_set_arch_end(session, end_pos, inst_id);

    if (db_save_arch_ctrl(session, id, inst_id) != GS_SUCCESS) {
        cm_spin_unlock(&proc_ctx->record_lock);
        CM_ABORT(0, "[ARCH] ABORT INFO: save core control file failed when record archive info");
        return GS_ERROR;
    }

    GS_LOG_RUN_INF("[ARCH] Record archive log file %s for log [%u-%u-%u] start %u end %u",
                   arch_ctrl->name, inst_id, log_head->rst_id, log_head->asn,
                   archived_start, end_pos);
    cm_spin_unlock(&proc_ctx->record_lock);
    return GS_SUCCESS;
}

status_t dtc_rst_arch_try_record_archinfo(knl_session_t *session, uint32 dest_pos, const char *file_name,
                                          log_file_head_t *head, uint32 inst_id)
{
    if (arch_archive_log_recorded(session, head->rst_id, head->asn, dest_pos, inst_id)) {
        GS_LOG_DEBUG_INF("[RESTORE]  arch file head info : [%u/%llu/%llu/%u], instid[%u]",
                         head->rst_id, head->first_lsn, head->last_lsn, head->asn, inst_id);
        return GS_SUCCESS;
    }
    if (dtc_rst_arch_record_archinfo(session, ARCH_DEFAULT_DEST, file_name, head, inst_id) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t dtc_log_set_file_asn(knl_session_t *session, uint32 asn, uint32 inst_id)
{
    dtc_node_ctrl_t *node_ctrl = dtc_get_ctrl(session, inst_id);
    database_t *db = &session->kernel->db;
    core_ctrl_t *core = &db->ctrl.core;
    log_context_t *ctx = &session->kernel->redo_ctx;
    logfile_set_t *logfile_set = &(session->kernel->db.logfile_sets[inst_id]);
    log_file_ctrl_t *log_file = logfile_set->items[node_ctrl->log_first].ctrl;
    log_file_head_t tmp_head;
    log_file_head_t *head = &tmp_head;
    int32 handle = GS_INVALID_HANDLE;
    errno_t ret;

    head->first = GS_INVALID_ID64;
    head->last = GS_INVALID_ID64;
    head->write_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), log_file->block_size);
    head->asn = asn;
    head->block_size = log_file->block_size;
    head->rst_id = core->resetlogs.rst_id;
    log_calc_head_checksum(session, head);
    ret = memset_sp(ctx->logwr_buf, log_file->block_size, 0, log_file->block_size);
    knl_securec_check(ret);
    ret = memcpy_sp(ctx->logwr_buf, sizeof(log_file_head_t), head, sizeof(log_file_head_t));
    knl_securec_check(ret);

    if (cm_open_device(log_file->name, log_file->type, knl_io_flag(session), &handle) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] failed to open %s", log_file->name);
        return GS_ERROR;
    }

    if (cm_write_device(log_file->type, handle, 0, ctx->logwr_buf,
                        CM_CALC_ALIGN(sizeof(log_file_head_t), log_file->block_size)) != GS_SUCCESS) {
        cm_close_device(log_file->type, &handle);
        GS_LOG_RUN_ERR("[BACKUP] failed to write %s", log_file->name);
        return GS_ERROR;
    }

    cm_close_device(log_file->type, &handle);
    return GS_SUCCESS;
}

static status_t dtc_bak_reset_logfile(knl_session_t *session, uint32 asn, uint32 file_id, uint32 inst_id)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    dtc_node_ctrl_t *ctrl = dtc_get_ctrl(session, inst_id);
    log_file_ctrl_t *logfile = NULL;
    uint32 i;
    uint32 curr = file_id;
    logfile_set_t *logfile_set = &(kernel->db.logfile_sets[inst_id]);

    for (i = 0; i < ctrl->log_hwm; i++) {
        logfile = logfile_set->items[i].ctrl;
        if (LOG_IS_DROPPED(logfile->flg)) {
            logfile->status = LOG_FILE_INACTIVE;
            continue;
        }

        if (curr == GS_INVALID_ID32 || curr == i) {
            curr = i;
            ctrl->log_first = i;
            ctrl->log_last = i;
            logfile->status = LOG_FILE_CURRENT;
        } else {
            logfile->status = LOG_FILE_INACTIVE;
        }

        if (db_save_log_ctrl(session, i, logfile->node_id) != GS_SUCCESS) {
            CM_ABORT(0, "[BACKUP] ABORT INFO: save core control file failed when restore log files");
        }
    }

    knl_panic(curr < ctrl->log_hwm);

    if (dtc_log_set_file_asn(session, asn, inst_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t dtc_rst_amend_ctrlinfo(knl_session_t *session, uint32 last_asn, uint32 file_id, uint32 inst_id)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;

    if (!BAK_IS_DBSOTR(bak)) {
        if (dtc_bak_reset_logfile(session, last_asn, file_id, inst_id) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    dtc_get_ctrl(session, inst_id)->dw_start = DW_DISTRICT_BEGIN(inst_id);
    dtc_get_ctrl(session, inst_id)->dw_end = DW_DISTRICT_BEGIN(inst_id);
    dtc_get_ctrl(session, inst_id)->scn = ctrlinfo->scn;
    dtc_get_ctrl(session, inst_id)->lrp_point = ctrlinfo->dtc_lrp_point[inst_id];
    GS_LOG_RUN_INF("[DTC RST] save ctrlinfo, the node is %u, lrp_lsn is %llu ", inst_id,
                   ctrlinfo->dtc_lrp_point[inst_id].lsn);
    session->kernel->scn = ctrlinfo->scn;
    if (dtc_save_ctrl(session, inst_id) != GS_SUCCESS) {
        CM_ABORT(0, "[BACKUP] ABORT INFO: save core control file failed when restore log files");
    }

    return GS_SUCCESS;
}
uint64 dtc_rst_db_get_logfiles_size(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    dtc_node_ctrl_t *node_ctrl = NULL;
    log_file_ctrl_t *ctrl = NULL;
    uint64 total_size = 0;
    logfile_set_t *logfile_set = NULL;

    for (uint32 i = 0; i < kernel->db.ctrl.core.node_count; i++) {
        node_ctrl = dtc_get_ctrl(session, i);
        logfile_set =  &(kernel->db.logfile_sets[i]);
        for (uint32 logid = 0; logid < node_ctrl->log_hwm; logid++) {
            ctrl = logfile_set->items[logid].ctrl;
            if (LOG_IS_DROPPED(ctrl->flg)) {
                continue;
            }

            total_size += (uint64)ctrl->size;
        }
    }
    return total_size;
}

status_t dtc_rst_arch_regist_archive(knl_session_t *session, const char *name, uint32 inst_id)
{
    int32 handle = GS_INVALID_HANDLE;
    log_file_head_t head;
    device_type_t type = cm_device_type(name);
    if (cm_open_device(name, type, O_BINARY | O_SYNC | O_RDWR, &handle) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (cm_read_device(type, handle, 0, &head, sizeof(log_file_head_t)) != GS_SUCCESS) {
        cm_close_device(type, &handle);
        return GS_ERROR;
    }
    if ((int64)head.write_pos != cm_device_size(type, handle)) {
        cm_close_device(type, &handle);
        GS_THROW_ERROR(ERR_INVALID_ARCHIVE_LOG, name);
        return GS_ERROR;
    }
    cm_close_device(type, &handle);
    if (dtc_rst_arch_try_record_archinfo(session, ARCH_DEFAULT_DEST, name, &head, inst_id) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static bool32 dtc_rst_check_archive_is_dir(knl_session_t *session, char *file_name, size_t name_len,
    list_t *arch_dir_list)
{
    char temp_name[GS_NAME_BUFFER_SIZE] = {0};
    size_t dest_len = strlen(session->kernel->arch_ctx.arch_proc[ARCH_DEFAULT_DEST - 1].arch_dest) + 1;
    const char *arch_dir_name = NULL;
    errno_t err;

    err = strncpy_s(temp_name, GS_NAME_BUFFER_SIZE, file_name + dest_len, name_len - dest_len);
    knl_securec_check(err);

    uint32 i;
    for (i = 0; i < arch_dir_list->count; ++i) {
        arch_dir_name = (char *)cm_list_get(arch_dir_list, i);
        err = snprintf_s(file_name, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s/%s", arch_dir_name,
                         temp_name);
        PRTS_RETURN_IFERR(err);

        if (cm_exist_device(cm_device_type(file_name), file_name)) {
            break;
        }
    }

    if (i == arch_dir_list->count) {
        return GS_FALSE;
    }
    return GS_TRUE;
}

status_t get_dbid_from_arch_logfile(knl_session_t *session, uint32 *dbid, const char *name)
{
    int32 handle = GS_INVALID_HANDLE;
    log_file_head_t head;
    device_type_t type = cm_device_type(name);
    if (cm_open_device(name, type, O_BINARY | O_SYNC | O_RDWR, &handle) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (cm_read_device(type, handle, 0, &head, sizeof(log_file_head_t)) != GS_SUCCESS) {
        cm_close_device(type, &handle);
        return GS_ERROR;
    }

    *dbid = head.dbid;
    cm_close_device(type, &handle);
    return GS_SUCCESS;
}

status_t dtc_rst_regist_archive_asn_by_dbstor(knl_session_t *session, uint32 *last_archied_asn,
                                              uint32 rst_id, uint32 inst_id)
{
    uint32 archive_asn = *last_archied_asn + 1;
    status_t status;
    
    while (GS_TRUE) {
        char file_name[GS_FILE_NAME_BUFFER_SIZE] = {0};
        if (archive_asn == 1) {
            status = arch_find_first_archfile_rst(session, rst_id, inst_id, file_name,
                                                  GS_FILE_NAME_BUFFER_SIZE, &archive_asn);
        } else {
            status = arch_find_archive_asn_log_name(session, rst_id, inst_id, archive_asn,
                                                    file_name, GS_FILE_NAME_BUFFER_SIZE);
        }
        GS_LOG_DEBUG_INF("[RESTORE] arch info : [%u/%u/%u], filename[%s], status[%d]",
                         rst_id, inst_id, archive_asn, file_name, status);
        if (status != GS_SUCCESS) {
            break;
        }

        if (dtc_rst_arch_regist_archive(session, file_name, inst_id) != GS_SUCCESS) {
            return GS_ERROR;
        }
        archive_asn++;
    }
    *last_archied_asn = archive_asn - 1;
    return GS_SUCCESS;
}

status_t dtc_rst_regist_archive_by_dbstor(knl_session_t *session, uint32 *last_archived_asn, uint32 rst_id,
                                          uint64 start_lsn, uint64 end_lsn, uint32 inst_id)
{
    char file_name[GS_FILE_NAME_BUFFER_SIZE] = {0};
    bool32 is_first = GS_TRUE;
    uint64 find_lsn;
    uint64 next_lsn;
    uint32 next_asn;

    while (GS_TRUE) {
        if (is_first) {
            arch_set_archive_log_name_with_lsn(session, rst_id, *last_archived_asn, ARCH_DEFAULT_DEST, file_name,
                                               GS_FILE_NAME_BUFFER_SIZE, inst_id, start_lsn, end_lsn);
            find_lsn = end_lsn + 1;
            is_first = GS_FALSE;
        } else {
            status_t status = arch_find_archive_log_name(session, rst_id, inst_id, find_lsn,
                                                         file_name, GS_FILE_NAME_BUFFER_SIZE, &next_lsn, &next_asn);
            if (status != GS_SUCCESS) {
                return GS_SUCCESS;
            }
            find_lsn = next_lsn + 1;
        }

        GS_LOG_DEBUG_INF("[RESTORE]  arch file head info : [%u/%llu/%llu/%u], instid[%u]",
                         rst_id, start_lsn, end_lsn, *last_archived_asn, inst_id);
        if (!cm_exist_device(cm_device_type((const char *)file_name), (const char *)file_name)) {
            break;
        }
        if (dtc_rst_arch_regist_archive(session, file_name, inst_id) != GS_SUCCESS) {
            return GS_ERROR;
        }
        *last_archived_asn = next_asn;
    }
    return GS_SUCCESS;
}


status_t dtc_rst_regist_archive(knl_session_t *session, uint32 *last_archived_asn, uint32 rst_id, int32 inst_id)
{
    uint32 archive_asn = *last_archived_asn + 1;
    char file_name[GS_FILE_NAME_BUFFER_SIZE] = {0};
    list_t arch_dir_list;

    cm_create_list(&arch_dir_list, GS_MAX_PATH_BUFFER_SIZE);
    dtc_load_archive(&arch_dir_list);

    for (;;) {
        arch_set_archive_log_name(session, rst_id, archive_asn, ARCH_DEFAULT_DEST, file_name,
                                  GS_FILE_NAME_BUFFER_SIZE, inst_id);
        if (!cm_exist_device(cm_device_type((const char *)file_name), (const char *)file_name)) {
            if (!dtc_rst_check_archive_is_dir(session, file_name, strlen(file_name), &arch_dir_list)) {
                break;
            }
        }
        if (dtc_rst_arch_regist_archive(session, file_name, inst_id) != GS_SUCCESS) {
            return GS_ERROR;
        }
        archive_asn++;
    }

    *last_archived_asn = archive_asn - 1;
    return GS_SUCCESS;
}

static void dtc_get_asn_and_file_id(bak_t *bak, uint32 file_index,
                                    uint32* asn, uint32* file_id, uint32 inst_id)
{
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;
    if (bak->files[file_index].type == BACKUP_ARCH_FILE) {
        *asn = ctrlinfo->dtc_lrp_point[inst_id].asn;
    } else {
        *asn = ctrlinfo->dtc_lrp_point[inst_id].asn - 1;
        *file_id = bak->files[file_index].id;
    }
}

void dtc_rst_update_process_data_size(knl_session_t *session, bak_context_t *ctx)
{
    knl_instance_t *kernel = session->kernel;
    datafile_t *datafile = NULL;
    dtc_node_ctrl_t *node_ctrl = NULL;
    log_file_ctrl_t *logfile = NULL;
    logfile_set_t *logfile_set = NULL;
    bool32 is_dbstor = BAK_IS_DBSOTR(&(kernel->backup_ctx.bak));

    for (uint32 i = 0; i < GS_MAX_DATA_FILES; i++) {
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

    for (uint32 i = 0; i < kernel->db.ctrl.core.node_count; i++) {
        logfile_set =  &(kernel->db.logfile_sets[i]);
        node_ctrl = dtc_get_ctrl(session, i);
        for (uint32 logid = 0; logid < node_ctrl->log_hwm; logid++) {
            logfile = logfile_set->items[logid].ctrl;
            if (LOG_IS_DROPPED(logfile->flg)) {
                continue;
            }
            bak_update_progress(&ctx->bak, (uint64)logfile->size);
            if (is_dbstor) {
                break;
            }
        }
    }
    return;
}

status_t dtc_rst_amend_files(knl_session_t *session, int32 file_index)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    uint32 last_asn = GS_INVALID_ID32;
    uint32 file_id = GS_INVALID_ID32;
    uint32 last_archived_asn = GS_INVALID_ID32;
    uint64 data_size;
    bool32 is_dbstor = BAK_IS_DBSOTR(bak);
    bak_file_t *file_info;
    uint32 prev_inst_id = GS_INVALID_ID32;
    database_t *db = &session->kernel->db;
    uint32 rst_id = db->ctrl.core.resetlogs.rst_id;

    data_size = db_get_datafiles_size(session) + dtc_rst_db_get_logfiles_size(session);

    bak_set_progress(session, BACKUP_BUILD_STAGE, data_size);
    dtc_rst_update_process_data_size(session, ctx);

    if (dtc_rst_amend_ctrlinfo(session, last_archived_asn, file_id, session->kernel->id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    for (int32 i = file_index; i >= 0; i--) {
        if (bak->files[i].type != BACKUP_ARCH_FILE && bak->files[i].type != BACKUP_LOG_FILE) {
            break;
        }
        uint32 inst_id = bak->files[i].inst_id;
        // processes only the last archive file to each node
        if (prev_inst_id == inst_id) {
            continue;
        } else {
            prev_inst_id = inst_id;
        }
        if (!is_dbstor) {
            dtc_get_asn_and_file_id(bak, i, &last_archived_asn, &file_id, inst_id);
        } else {
            file_info = &bak->files[i];
            last_archived_asn = file_info->id;
        }
        if (!bak->is_building) {
            last_asn = last_archived_asn;
            if (is_dbstor) {
                if (dtc_rst_regist_archive_by_dbstor(session, &last_archived_asn, rst_id, file_info->start_lsn,
                                                     file_info->end_lsn, file_info->inst_id) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            } else {
                if (dtc_rst_regist_archive(session, &last_archived_asn, rst_id, inst_id) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            }
            if (last_archived_asn != last_asn) {
                file_id = GS_INVALID_ID32;
            }
        }
        if (dtc_rst_amend_ctrlinfo(session, last_archived_asn + 1, file_id, inst_id) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    bak->progress.stage = BACKUP_WRITE_FINISHED;
    return GS_SUCCESS;
}

status_t dtc_rst_amend_all_arch_file_dbstor(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    uint32 rst_id = kernel->db.ctrl.core.resetlogs.rst_id;

    for (uint32 i = 0; i < kernel->db.ctrl.core.node_count; i++) {
        arch_ctrl_t *last = arch_dtc_get_last_log(session, i);
        uint32 archive_asn = last->asn;
        knl_panic(rst_id >= last->rst_id);
        if (dtc_rst_regist_archive_asn_by_dbstor(session, &archive_asn, rst_id, i) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t dtc_rst_create_logfiles(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    log_file_ctrl_t *logfile = NULL;
    int32 handle = GS_INVALID_HANDLE;
    logfile_set_t *logfile_set = NULL;
    dtc_node_ctrl_t *ctrl = NULL;
    bool32 is_dbstor = knl_dbs_is_enable_dbs();

    if (BAK_IS_DBSOTR(&(kernel->backup_ctx.bak))) {
        dtc_rst_db_init_logfile_ctrl_by_dbstor(session, &session->kernel->db.ctrl.log_segment);
    } else {
        dtc_rst_db_init_logfile_ctrl(session, &session->kernel->db.ctrl.log_segment);
    }

    for (uint32 i = 0; i < kernel->db.ctrl.core.node_count; i++) {
        ctrl = dtc_get_ctrl(session, i);
        logfile_set =  &(kernel->db.logfile_sets[i]);
        for (uint32 logid = 0; logid < ctrl->log_hwm; logid++) {
            logfile = logfile_set->items[logid].ctrl;
            if (LOG_IS_DROPPED(logfile->flg)) {
                continue;
            }

            if (cm_create_device(logfile->name, logfile->type, knl_io_flag(session), &handle) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[RESTORE] failed to create %s ", logfile->name);
                return GS_ERROR;
            }
            GS_LOG_RUN_INF("[RESTORE] restore build file, src_file:%s, file size :%lld",
                           logfile->name, logfile->size);
            cm_close_device(logfile->type, &handle);
            if (is_dbstor) {
                break;
            }
        }
    }

    return GS_SUCCESS;
}

status_t dtc_bak_set_logfile_ctrl(knl_session_t *session, uint32 curr_file_index, log_file_head_t *head,
                                  bak_ctrl_t *ctrl, bool32 *ignore_data)
{
    knl_instance_t *kernel = session->kernel;
    bak_t *bak = &kernel->backup_ctx.bak;
    bak_file_t *file_info = &bak->files[curr_file_index];
    log_file_ctrl_t *logfile = NULL;
    logfile_set_t *logfile_set = &(kernel->db.logfile_sets[file_info->inst_id]);

    *ignore_data = GS_FALSE;
    ctrl->offset = 0;

    if (file_info->type == BACKUP_LOG_FILE) {
        logfile = logfile_set->items[file_info->id].ctrl;
        ctrl->type = logfile->type;
        /* open when build log files, closed in bak_end => bak_reset_ctrl */
        if (cm_open_device(logfile->name, logfile->type, knl_io_flag(session), &ctrl->handle) != GS_SUCCESS) {
            return GS_ERROR;
        }
        return GS_SUCCESS;
    }

    knl_panic(file_info->id == head->asn);

    if (BAK_IS_DBSOTR(bak)) {
        arch_set_archive_log_name_with_lsn(session, head->rst_id, head->asn, ARCH_DEFAULT_DEST, ctrl->name,
            GS_FILE_NAME_BUFFER_SIZE, file_info->inst_id, head->first_lsn, head->last_lsn);
    } else {
        arch_set_archive_log_name(session, head->rst_id, head->asn, ARCH_DEFAULT_DEST, ctrl->name,
                                  GS_FILE_NAME_BUFFER_SIZE, file_info->inst_id);
    }

    ctrl->type = cm_device_type(ctrl->name);
    GS_LOG_DEBUG_INF("[BACKUP] bak_set_logfile_ctrl get archive log %s", ctrl->name);

    if (cm_exist_device(ctrl->type, ctrl->name)) {
        GS_LOG_DEBUG_INF("[BACKUP] Archive log %s exists", ctrl->name);
        if (arch_process_existed_archfile(session, ctrl->name, *head, ignore_data) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (!*ignore_data) {
        if (cm_create_device(ctrl->name, ctrl->type, O_BINARY | O_SYNC | O_RDWR | O_EXCL, &ctrl->handle) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[BACKUP] failed to create %s", ctrl->name);
            return GS_ERROR;
        }
        GS_LOG_RUN_INF("[BACKUP] Create %s", ctrl->name);
    }

    return GS_SUCCESS;
}


status_t dtc_bak_running(knl_session_t *session, uint32 target_id, bool32 *running)
{
    mes_message_head_t head;
    mes_message_t  msg;

    mes_init_send_head(&head, MES_CMD_BAK_RUNNING, sizeof(mes_message_head_t), GS_INVALID_ID32,
                       session->kernel->dtc_attr.inst_id, target_id, session->id, GS_INVALID_ID16);

    if (mes_send_data((void *)&head) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "send bak is running mes ");
        return GS_ERROR;
    }

    if (mes_recv(session->id, &msg, GS_FALSE, GS_INVALID_ID32, BAK_WAIT_TIMEOUT) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "receive bak is running mes ");
        return GS_ERROR;
    }

    if (SECUREC_UNLIKELY(msg.head->cmd != MES_CMD_BAK_RUNNING_ACK)) {
        mes_release_message_buf(msg.buffer);
        return GS_ERROR;
    }

    *running = *(bool32 *)(msg.buffer + sizeof(mes_message_head_t));
    mes_release_message_buf(msg.buffer);

    return GS_SUCCESS;
}

void dtc_process_running(void *sess, mes_message_t * receive_msg)
{
    mes_message_head_t head;
    knl_session_t *session = (knl_session_t *)sess;

    mes_init_ack_head(receive_msg->head, &head, MES_CMD_BAK_RUNNING_ACK, (sizeof(mes_message_head_t) + sizeof(bool32)), GS_INVALID_ID16);

    mes_release_message_buf(receive_msg->buffer);
    if (mes_send_data2(&head, &session->kernel->backup_ctx.bak_condition) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "send bak is running ack mes ");
        return;
    }
}

uint64 dtc_get_min_lsn_lrp_point(knl_session_t *session, bak_record_t *record)
{
    uint64 min_lsn = GS_INVALID_ID64;
    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        if (!rc_bitmap64_exist(&session->kernel->backup_ctx.bak.target_bits, i)) {
            continue;
        }
        if (record->ctrlinfo.dtc_lrp_point[i].lsn < min_lsn) {
            min_lsn = record->ctrlinfo.dtc_lrp_point[i].lsn;
        }
    }
    return min_lsn;
}
