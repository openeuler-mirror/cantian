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
 * dtc_backup.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_backup.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_cluster_module.h"
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

#define BAK_GET_CTRL_RETRY_TIMES 3
#define ARCH_FORCE_ARCH_CHECK_INTERVAL_MS 1000

static status_t dtc_load_archive(list_t *arch_dir_list)
{
    char file_name[CT_FILE_NAME_BUFFER_SIZE] = {0};
    int32 fp;
    char *buf = NULL;
    uint32 buf_size;
    text_t text;
    text_t line;
    char *dir = NULL;
    errno_t err;

    err = snprintf_s(file_name, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1, "%s/cfg/%s", g_instance->home,
                     ARCHIVE_FILENAME);
    PRTS_RETURN_IFERR(err);

    if (!cm_file_exist((const char *)file_name) || cm_open_file((const char *)file_name, O_RDONLY, &fp) != CT_SUCCESS) {
        cm_reset_error();
        return CT_SUCCESS;
    }
    buf = (char *)malloc(SIZE_K(64));
    if (buf == NULL) {
        cm_close_file(fp);
        return CT_ERROR;
    }
    err = memset_s(buf, SIZE_K(64), 0, SIZE_K(64));
    if (err != EOK) {
        cm_close_file(fp);
        CM_FREE_PTR(buf);
        return CT_ERROR;
    }
    if (cm_read_file(fp, buf, SIZE_K(64), (int32 *)&buf_size) != CT_SUCCESS) {
        cm_close_file(fp);
        CM_FREE_PTR(buf);
        return CT_ERROR;
    }

    text.len = buf_size;
    text.str = buf;

    while (cm_fetch_text(&text, '\n', '\0', &line)) {
        cm_trim_text(&line);
        if (line.len == 0 || line.str[0] == '#') {
            continue;
        }

        if (line.len >= CT_MAX_PATH_BUFFER_SIZE) {
            CT_LOG_RUN_ERR("dir name length larger than max size %u.", CT_MAX_PATH_BUFFER_SIZE);
            cm_close_file(fp);
            CM_FREE_PTR(buf);
            return CT_ERROR;
        }

        if (cm_list_new(arch_dir_list, (void **)&dir) == CT_ERROR) {
            cm_close_file(fp);
            CM_FREE_PTR(buf);
            return CT_ERROR;
        }
        cm_text2str(&line, dir, CT_MAX_PATH_BUFFER_SIZE);
        dir = NULL;
    }
    CM_FREE_PTR(buf);
    cm_close_file(fp);

    return CT_SUCCESS;
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

    mes_init_send_head(&bcast.head, MES_CMD_BLOCK_FILE, sizeof(msg_block_file_bcast_t), CT_INVALID_ID32,
                       session->kernel->id, CT_INVALID_ID8, session->id, CT_INVALID_ID16);
    bcast.block.file_id = file_id;
    bcast.block.sec_id = sec_id;
    bcast.block.start = start;
    bcast.block.end = end;

    mes_broadcast(session->id, MES_BROADCAST_ALL_INST, &bcast, success_inst);
}

void bak_process_block_file(void *sess, mes_message_t *msg)
{
    if (sizeof(msg_block_file_bcast_t) != msg->head->size) {
        CT_LOG_RUN_ERR("bak_process_block_file msg size is invalid, msg size %u.", msg->head->size);
        mes_release_message_buf(msg->buffer);
        return;
    }
    msg_block_file_bcast_t *bcast = (msg_block_file_bcast_t *)msg->buffer;
    knl_session_t *session = (knl_session_t *)sess;

    if (bcast->block.file_id >= CT_MAX_DATA_FILES) {
        CT_LOG_RUN_ERR("bcast->block.file_id(%u) err, larger than %u", bcast->block.file_id, CT_MAX_DATA_FILES);
        mes_release_message_buf(msg->buffer);
        return;
    }
    datafile_t *df = DATAFILE_GET(session, bcast->block.file_id);

    if (bcast->block.sec_id >= DATAFILE_MAX_BLOCK_NUM) {
        CT_LOG_RUN_ERR("bcast->block.sec_id(%u) err, larger than %u", bcast->block.sec_id, DATAFILE_MAX_BLOCK_NUM);
        mes_release_message_buf(msg->buffer);
        return;
    }
 
    if (bcast->block.start >= bcast->block.end) {
        CT_LOG_RUN_ERR("bcast->block.start(%llu) is not less than bcast->block.end(%llu)", bcast->block.start,
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

    mes_init_send_head(&bcast.head, MES_CMD_UNBLOCK_FILE, sizeof(msg_block_file_bcast_t), CT_INVALID_ID32,
                       session->kernel->id, CT_INVALID_ID8, session->id, CT_INVALID_ID16);
    bcast.block.file_id = file_id;
    bcast.block.sec_id = sec_id;
    bcast.block.start = CT_INVALID_INT64;
    bcast.block.end = CT_INVALID_INT64;

    mes_broadcast(session->id, MES_BROADCAST_ALL_INST, &bcast, NULL);
}

void bak_process_unblock_file(void *sess, mes_message_t *msg)
{
    if (sizeof(msg_block_file_bcast_t) != msg->head->size) {
        CT_LOG_RUN_ERR("bak_process_unblock_file msg size is invalid, msg size %u.", msg->head->size);
        mes_release_message_buf(msg->buffer);
        return;
    }
    msg_block_file_bcast_t *bcast = (msg_block_file_bcast_t *)msg->buffer;
    knl_session_t *session = (knl_session_t *)sess;

    if (bcast->block.file_id >= CT_MAX_DATA_FILES) {
        CT_LOG_RUN_ERR("bcast->block.file_id(%u) err, larger than %u", bcast->block.file_id, CT_MAX_DATA_FILES);
        mes_release_message_buf(msg->buffer);
        return;
    }
    datafile_t *df = DATAFILE_GET(session, bcast->block.file_id);

    if (bcast->block.sec_id >= DATAFILE_MAX_BLOCK_NUM) {
        CT_LOG_RUN_ERR("bcast->block.sec_id(%u) err, larger than %u", bcast->block.sec_id, DATAFILE_MAX_BLOCK_NUM);
        mes_release_message_buf(msg->buffer);
        return;
    }
    spc_unblock_datafile(df, bcast->block.sec_id);
    mes_release_message_buf(msg->buffer);
}

static status_t dtc_bak_switch_logfile(knl_session_t *session, uint32 last_asn, uint32 inst_id)
{
    uint32 curr_asn;
    if (dtc_get_log_curr_asn(session, inst_id, &curr_asn) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] dtc get log curr_asn failed.");
        return CT_ERROR;
    }
    if (curr_asn < last_asn) {
        CT_LOG_RUN_ERR("[BACKUP] the obtained cur asn value is incorrect");
        return CT_ERROR;
    }
    if (curr_asn != last_asn) {
        return CT_SUCCESS;
    }

    if (dtc_ckpt_trigger(session, NULL, CT_FALSE, CKPT_TRIGGER_INC, inst_id, CT_TRUE, CT_FALSE) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] dtc chpt trigger failed.");
        return CT_ERROR;
    }

    if (DB_IS_RAFT_ENABLED(session->kernel) || DB_IS_PRIMARY(&session->kernel->db)) {
        return dtc_log_switch(session, 0, inst_id);
    } else {
        return CT_SUCCESS;
    }

    return CT_SUCCESS;
}

status_t dtc_bak_fetch_last_log(knl_session_t *session, bak_t *bak, uint32 *last_asn, uint32 inst_id)
{
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;

    if (bak->record.log_only) {
        CT_LOG_RUN_ERR("[BACKUP] log_only option not support in daac.");
        return CT_ERROR;
    } else {
        *last_asn = ctrlinfo->dtc_lrp_point[inst_id].asn;
    }

    return dtc_bak_switch_logfile(session, *last_asn, inst_id);
}

status_t bak_get_arch_file_head(knl_session_t *session, const char *arch_path, char *arch_name, log_file_head_t *head)
{
    char tmp_buf[CT_FILE_NAME_BUFFER_SIZE] = {0};
    status_t ret = memset_s(tmp_buf, CT_FILE_NAME_BUFFER_SIZE, 0, CT_FILE_NAME_BUFFER_SIZE);
    knl_securec_check(ret);
    bak_set_file_name(tmp_buf, arch_path, arch_name);
    int32 handle = CT_INVALID_HANDLE;
    device_type_t type = cm_device_type(tmp_buf);
    if (cm_open_device(tmp_buf, type, O_BINARY | O_SYNC | O_RDWR, &handle) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cm_read_device(type, handle, 0, head, sizeof(log_file_head_t)) != CT_SUCCESS) {
        cm_close_device(type, &handle);
        return CT_ERROR;
    }
    cm_close_device(type, &handle);
    if (head->dbid == session->kernel->db.ctrl.core.dbid) {
    } else {
        CT_LOG_RUN_WAR("[BACKUP] the dbid %u of archive logfile %s is different from the bak dbid %u",
            head->dbid, tmp_buf, session->kernel->db.ctrl.core.dbid);
    }
    return CT_SUCCESS;
}

status_t bak_get_arch_asn_file(knl_session_t *session, log_start_end_info_t arch_info, uint32 inst_id,
                               bak_arch_files_t *arch_file_buf)
{
    uint32 rst_id = session->kernel->db.ctrl.core.resetlogs.rst_id;
    local_arch_file_info_t file_info;
    DIR *arch_dir;
    struct dirent *arch_dirent;
    arch_attr_t *arch_attr = &session->kernel->attr.arch_attr[0];
    char *arch_path = arch_attr->local_path;
    log_file_head_t head;
    char tmp_file_name[CT_FILE_NAME_BUFFER_SIZE];
    if ((arch_dir = opendir(arch_path)) == NULL) {
        CT_LOG_RUN_ERR("[BACKUP] can not open arch_dir %s.", arch_path);
        return CT_ERROR;
    }
    while ((arch_dirent = readdir(arch_dir)) != NULL) {
        if (bak_convert_archfile_name(arch_dirent->d_name, &file_info, inst_id, rst_id,
                                      BAK_IS_DBSOTR(&session->kernel->backup_ctx.bak)) == CT_FALSE) {
            continue;
        }
        if (bak_get_arch_file_head(session, arch_path, arch_dirent->d_name, &head) != CT_SUCCESS) {
            closedir(arch_dir);
            return CT_ERROR;
        }

        if (head.dbid != session->kernel->db.ctrl.core.dbid) {
            CT_LOG_RUN_WAR("[BACKUP] the dbid %u of archive logfile %s is different from the bak dbid %u",
                head.dbid, arch_dirent->d_name, session->kernel->db.ctrl.core.dbid);
            continue;
        }
        arch_info.result_asn->max_asn = MAX(arch_info.result_asn->max_asn, file_info.local_asn);
        bak_set_file_name(tmp_file_name, arch_path, arch_dirent->d_name);
        if (bak_set_archfile_info_file(arch_info, file_info, arch_file_buf, tmp_file_name, &head) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    closedir(arch_dir);
    return CT_SUCCESS;
}

status_t dtc_bak_get_arch_start_and_end_point(knl_session_t *session, uint32 inst_id, bak_arch_files_t *arch_file_buf,
                                              log_start_end_asn_t *local_arch_file_asn, log_start_end_asn_t *target_asn)
{
    knl_instance_t *kernel = session->kernel;
    bak_context_t *ctx = &kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;
    log_start_end_lsn_t lsn = {0, 0, 0};
    target_asn->start_asn = ctrlinfo->dtc_rcy_point[inst_id].asn;
    target_asn->end_asn = ctrlinfo->dtc_lrp_point[inst_id].asn;
    uint64 end_lsn = 0;
    uint32 arch_num = 0;
    log_start_end_info_t arch_info = {local_arch_file_asn, target_asn, &lsn, &end_lsn, &arch_num};
    if (dtc_bak_fetch_last_log(session, bak, &target_asn->end_asn, inst_id) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] dtc fetch last log failed");
    }
    if (bak_get_arch_asn_file(session, arch_info, inst_id, arch_file_buf) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] dtc fetch start and end arch log file asn failed");
        return CT_ERROR;
    }
    if (arch_info.result_asn->start_asn > target_asn->start_asn) {
        CT_LOG_RUN_ERR("[BACKUP] dtc fetch log fail, can not fetch start_asn %u, local_start_asn %u.",
                       target_asn->start_asn, arch_info.result_asn->start_asn);
        return CT_ERROR;
    }
    if (arch_info.result_asn->end_asn < target_asn->end_asn) {
        CT_LOG_RUN_ERR("[BACKUP] dtc fetch log fail, can not fetch end_asn %u, local_end_asn %u.",
                       target_asn->end_asn, arch_info.result_asn->end_asn);
    }
    if (arch_num != 0) {
        if (arch_num != local_arch_file_asn->end_asn - local_arch_file_asn->start_asn + 1) {
            CT_LOG_RUN_ERR("[BACKUP] start or end arch log file asn invalid, "
                           "arch num %u, start asn %u, end asn %u, max asn %u",
                           arch_num, local_arch_file_asn->start_asn, local_arch_file_asn->end_asn,
                           local_arch_file_asn->max_asn);
            CT_LOG_RUN_WAR("[BACKUP] check whether the lastest archive files are lost before backup task");
        }
        for (int i = local_arch_file_asn->start_asn; i <= local_arch_file_asn->end_asn; i++) {
            bak_arch_files_t *arch_file = (bak_arch_files_t *)(arch_file_buf + (i - local_arch_file_asn->start_asn));
            CT_LOG_RUN_INF("[BACKUP] arch file name %s, start lsn %llu, end lsn %llu",
                arch_file->arch_file_name, arch_file->start_lsn, arch_file->end_lsn);
        }
    }
    CT_LOG_RUN_INF("[BACKUP] get arch log files in dir, start asn %u end asn %u instid %u.",
                   local_arch_file_asn->start_asn, local_arch_file_asn->end_asn, inst_id);
    return CT_SUCCESS;
}

bool32 dtc_bak_read_log_check_param(knl_session_t *session, uint32 *curr_asn, uint32 inst_id)
{
    knl_instance_t *kernel = session->kernel;
    bak_context_t *ctx = &kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_stage_t *stage = &bak->progress.build_progress.stage;

    if (BAK_IS_FULL_BUILDING(bak) && bak_get_build_stage(stage) > BUILD_LOG_STAGE) {
        CT_LOG_RUN_INF("[BUILD] ignore read logfiles for break-point building");
        return CT_FALSE;
    }

    if (BAK_IS_FULL_BUILDING(bak) && bak_get_build_stage(stage) == BUILD_LOG_STAGE) {
        CT_LOG_RUN_INF("[BUILD] break-point condition, curr asn : %u", bak->progress.build_progress.asn);
        *curr_asn = (uint32)bak->progress.build_progress.asn;
    }

    if (bak_point_need_archfile(session, bak, inst_id) == CT_FALSE) {
        CT_LOG_RUN_INF("[BACKUP] node %u no need to backup arch file", inst_id);
        if (bak_paral_task_enable(session)) {
            /* parallel backup dose not enter bak_write_end, need update curr_file_index here */
            bak->curr_file_index = bak->file_count;
        }
        return CT_FALSE;
    }

    return CT_TRUE;
}

status_t dtc_bak_read_logfile_data(knl_session_t *session, bak_process_t *proc, uint32 block_size, uint32 inst_id)
{
    if (bak_paral_task_enable(session)) {
        if (bak_assign_backup_task(session, proc, 0, CT_FALSE) != CT_SUCCESS) {
            dtc_bak_unlatch_logfile(session, proc, inst_id);
            return CT_ERROR;
        }
    } else {
        bool32 arch_compressed = CT_FALSE;
        status_t status = bak_read_logfile(session, &(session->kernel->backup_ctx),
                                           proc, block_size, CT_FALSE, &arch_compressed);
        dtc_bak_unlatch_logfile(session, proc, inst_id);
        cm_close_device(proc->ctrl.type, &proc->ctrl.handle);
        if (status != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (bak_wait_write(&(session->kernel->backup_ctx.bak)) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t dtc_bak_get_arch_file(knl_session_t *session, uint32 inst_id, bak_arch_files_t *arch_file_buf, log_start_end_asn_t *local_arch_file_asn)
{
    knl_instance_t *kernel = session->kernel;
    bak_context_t *ctx = &kernel->backup_ctx;
    bak_process_t *proc = &ctx->process[BAK_COMMON_PROC];
    uint32 block_size;
    uint32 local_last_asn = local_arch_file_asn->end_asn;
    uint32 local_start_asn = local_arch_file_asn->start_asn;
    uint32 curr_asn = local_start_asn;
    for (; curr_asn <= local_last_asn; curr_asn++) {
        if (bak_paral_task_enable(session)) {
            if (bak_get_free_proc(session, &proc, CT_FALSE) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
        bak_arch_files_t *arch_file = bak_get_arch_by_index(arch_file_buf, curr_asn, *local_arch_file_asn);
        if (dtc_bak_get_arch_ctrl(session, proc, curr_asn, &block_size, arch_file) != CT_SUCCESS) {
            dtc_bak_unlatch_logfile(session, proc, inst_id);
            return CT_ERROR;
        }
        proc->assign_ctrl.log_block_size = block_size;
        if (dtc_bak_read_logfile_data(session, proc, block_size, inst_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t dtc_bak_read_logfiles(knl_session_t *session, uint32 inst_id)
{
    knl_instance_t *kernel = session->kernel;
    bak_context_t *ctx = &kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;
    uint32 curr_asn = (uint32)ctrlinfo->dtc_rcy_point[inst_id].asn;
    uint64 data_size  = 0;
    int64 curr_size = 0;

    bak->inst_id = inst_id;

    if (dtc_bak_read_log_check_param(session, &curr_asn, inst_id) == CT_FALSE) {
        return CT_SUCCESS;
    }
    bak_arch_files_t *arch_file_buf = (bak_arch_files_t *)malloc(sizeof(bak_arch_files_t) * BAK_ARCH_FILE_MAX_NUM);
    errno_t ret = memset_sp(arch_file_buf, sizeof(bak_arch_files_t) * BAK_ARCH_FILE_MAX_NUM, 0, sizeof(bak_arch_files_t) * BAK_ARCH_FILE_MAX_NUM);
    knl_securec_check(ret);
    log_start_end_asn_t local_arch_file_asn = {0, 0, 0};
    log_start_end_asn_t target_arch_file_asn = {0, 0, 0};

    if (dtc_bak_get_arch_start_and_end_point(session, inst_id, arch_file_buf, &local_arch_file_asn, &target_arch_file_asn) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] dtc get log start and end log failed");
        return CT_ERROR;
    }

    if (dtc_get_log_curr_size(session, inst_id, &curr_size) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] dtc curr_size failed");
    }
    data_size = (uint64)curr_size * (local_arch_file_asn.end_asn - local_arch_file_asn.start_asn + 1);
    bak_set_progress(session, BACKUP_LOG_STAGE, data_size);
    CT_LOG_RUN_ERR("[BACKUP] curr_size %llu.", (uint64)data_size);
    uint32 target_end_asn = target_arch_file_asn.end_asn;
    if (local_arch_file_asn.end_asn < target_end_asn &&
        dtc_bak_get_logfile_by_asn_file(session, arch_file_buf, local_arch_file_asn, inst_id, &target_arch_file_asn) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (local_arch_file_asn.start_asn != 0) {
        if (dtc_bak_get_arch_file(session, inst_id, arch_file_buf, &local_arch_file_asn) != CT_SUCCESS) {
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

status_t dtc_bak_read_logfiles_dbstor(knl_session_t *session, uint32 inst_id)
{
    knl_instance_t *kernel = session->kernel;
    bak_context_t *ctx = &kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    uint32 curr_asn = 0;
    bak_process_t *proc = &ctx->process[BAK_COMMON_PROC];
    uint32 block_size;
 
    bak->inst_id = inst_id;
    if (dtc_bak_read_log_check_param(session, &curr_asn, inst_id) == CT_FALSE) {
        return CT_SUCCESS;
    }
    bak_arch_files_t *arch_file_buf = (bak_arch_files_t *)malloc(sizeof(bak_arch_files_t) * BAK_ARCH_FILE_MAX_NUM);
    log_start_end_asn_t arch_file_asn = {0, 0, 0};
    if (bak_get_arch_start_and_end_point_dbstor(session, inst_id, &arch_file_asn, arch_file_buf) != CT_SUCCESS) {
        CM_FREE_PTR(arch_file_buf);
        CT_LOG_RUN_ERR("[BACKUP] dtc get log start and end log failed");
        return CT_ERROR;
    }
    bak_set_progress(session, BACKUP_LOG_STAGE, 0);
    for (uint32 i = arch_file_asn.start_asn; i < arch_file_asn.end_asn + 1 && arch_file_asn.end_asn != 0; i++) {
        if (bak_paral_task_enable(session)) {
            if (bak_get_free_proc(session, &proc, CT_FALSE) != CT_SUCCESS) {
                CM_FREE_PTR(arch_file_buf);
                return CT_ERROR;
            }
        }
        bak_arch_files_t *arch_file = bak_get_arch_by_index(arch_file_buf, i, arch_file_asn);
        if (dtc_bak_set_log_ctrl_dbstor(session, proc, &block_size, inst_id, arch_file) != CT_SUCCESS) {
            CM_FREE_PTR(arch_file_buf);
            return CT_ERROR;
        }
        proc->assign_ctrl.log_block_size = block_size;
        if (dtc_bak_read_logfile_data(session, proc, block_size, inst_id) != CT_SUCCESS) {
            CM_FREE_PTR(arch_file_buf);
            return CT_ERROR;
        }
    }
    CT_LOG_RUN_INF("[BACKUP] backup start and end archived log files paral");
    if (bak_get_logfile_by_lsn_dbstor(session, arch_file_buf, arch_file_asn, inst_id) != CT_SUCCESS) {
        CM_FREE_PTR(arch_file_buf);
        return CT_ERROR;
    }
    bak_wait_paral_proc(session, CT_FALSE);
    if (bak_paral_task_enable(session)) {
        /* parallel backup dose not enter bak_write_end, need update curr_file_index here */
        bak->curr_file_index = bak->file_count;
    }
    CT_LOG_RUN_INF("[BACKUP] backup node %u log files finished", inst_id);
    CM_FREE_PTR(arch_file_buf);
    return CT_SUCCESS;
}

status_t dtc_bak_read_all_logfiles(knl_session_t *session)
{
    status_t status;
    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        if (SECUREC_UNLIKELY(i == g_dtc->profile.inst_id)) {
            continue;
        } else {
            if (BAK_IS_DBSOTR(&session->kernel->backup_ctx.bak)) {
                status = dtc_bak_read_logfiles_dbstor(session, i);
            } else {
                status = dtc_bak_read_logfiles(session, i);
            }
            if (status != CT_SUCCESS) {
                return status;
            }
        }
    }
    CT_LOG_RUN_INF("[BACKUP] backup all nodes redo log finished");
    return CT_SUCCESS;
}

status_t dtc_bak_set_log_ctrl_dbstor(knl_session_t *session, bak_process_t *process,
                                     uint32 *block_size, uint32 target_id, bak_arch_files_t *arch_file)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    database_t *db = &session->kernel->db;
    bak_t *bak = &ctx->bak;
    uint32 rst_id = db->ctrl.core.resetlogs.rst_id;
    errno_t ret;
    if (arch_file == NULL) {
        CT_LOG_RUN_ERR("[BACKUP] invalid archive file addr!");
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[BACKUP] arch file name %s, start lsn %llu, end lsn %llu, asn %u",
                   arch_file->arch_file_name, arch_file->start_lsn, arch_file->end_lsn, arch_file->asn);
    process->assign_ctrl.file_id = CT_INVALID_ID32;
    ret = strcpy_sp(process->ctrl.name, CT_FILE_NAME_BUFFER_SIZE, arch_file->arch_file_name);
    knl_securec_check(ret);
    process->ctrl.type = cm_device_type(process->ctrl.name);
    log_file_ctrl_t *log_ctrl = (log_file_ctrl_t *)db_get_log_ctrl_item(db->ctrl.pages, 0, sizeof(log_file_ctrl_t),
                                                                        db->ctrl.log_segment, target_id);

    *block_size = CM_CALC_ALIGN(sizeof(log_file_head_t), log_ctrl->block_size);
   
    bak_record_new_file(bak, BACKUP_ARCH_FILE, arch_file->asn, 0, rst_id, CT_FALSE,
                        arch_file->start_lsn, arch_file->end_lsn);

    if (cm_open_device(process->ctrl.name, process->ctrl.type, knl_io_flag(session), &process->ctrl.handle) !=
        CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] failed to open %s", process->ctrl.name);
        return CT_ERROR;
    }
    process->assign_ctrl.file_size = cm_device_size(process->ctrl.type, process->ctrl.handle);
    return CT_SUCCESS;
}

status_t dtc_bak_get_arch_ctrl(knl_session_t *session, bak_process_t *process, uint32 asn, uint32 *block_size, bak_arch_files_t *arch_file)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    database_t *db = &session->kernel->db;
    bak_t *bak = &ctx->bak;
    if (arch_file == NULL) {
        CT_LOG_RUN_ERR("[BACKUP] invalid archive file addr!");
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[BACKUP] arch file name %s, start lsn %llu, end lsn %llu, asn %u, block_size %u, file_size %llu.",
                   arch_file->arch_file_name, arch_file->start_lsn, arch_file->end_lsn, arch_file->asn,
                   arch_file->block_size, arch_file->file_size);
    uint32 rst_id = bak_get_rst_id(bak, asn, &(db->ctrl.core.resetlogs));
    errno_t ret;
    process->assign_ctrl.file_size = arch_file->file_size;
    ret = strcpy_sp(process->ctrl.name, CT_FILE_NAME_BUFFER_SIZE, arch_file->arch_file_name);
    knl_securec_check(ret);
    process->ctrl.type = cm_device_type(process->ctrl.name);
    *block_size = arch_file->block_size;
    bak_record_new_file(bak, BACKUP_ARCH_FILE, asn, 0, rst_id, CT_FALSE, arch_file->start_lsn, arch_file->end_lsn);

    if (cm_open_device(process->ctrl.name, process->ctrl.type, knl_io_flag(session), &process->ctrl.handle) !=
        CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] failed to open %s", process->ctrl.name);
        return CT_ERROR;
    }

    return CT_SUCCESS;
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
                       CT_INVALID_ID32, session->kernel->dtc_attr.inst_id, target_id, session->id, CT_INVALID_ID16);

    if (mes_send_data2(&head, &log_file) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] %s failed", "send set log ctrl mes ");
        return CT_ERROR;
    }

    if (mes_recv(session->id, &msg, CT_FALSE, CT_INVALID_ID32, BAK_WAIT_TIMEOUT) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] %s failed", "receive set log ctrl mes ");
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(msg.head->cmd != MES_CMD_SET_LOG_CTRL_ACK)) {
        mes_release_message_buf(msg.buffer);
        return CT_ERROR;
    }

    msg_log_ctrl_t log_ctrl;
    log_ctrl = *(msg_log_ctrl_t *)(msg.buffer + sizeof(mes_message_head_t));
    mes_release_message_buf(msg.buffer);

    if (log_ctrl.status == CT_ERROR) {
        return CT_ERROR;
    }

    process->assign_ctrl.file_id = log_ctrl.file_id;
    process->assign_ctrl.file_size = log_ctrl.file_size;
    ret = strcpy_sp(process->ctrl.name, CT_FILE_NAME_BUFFER_SIZE, log_ctrl.name);
    knl_securec_check(ret);
    process->ctrl.type = log_ctrl.type;
    *block_size = log_ctrl.block_size;
    if (log_ctrl.is_archivelog) {
        bak_record_new_file(bak, BACKUP_ARCH_FILE, asn, 0, rst_id, CT_FALSE, log_ctrl.start_lsn, log_ctrl.end_lsn);
    } else {
        bak_record_new_file(bak, BACKUP_LOG_FILE, log_ctrl.file_id, 0, rst_id, CT_FALSE,
                            log_ctrl.start_lsn, log_ctrl.end_lsn);
    }

    if (cm_open_device(process->ctrl.name, process->ctrl.type, knl_io_flag(session), &process->ctrl.handle) !=
        CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] failed to open %s", process->ctrl.name);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

uint32 dtc_bak_get_rst_id(uint32 data_type, uint32 asn, reset_log_t *rst_log)
{
    if (data_type == DATA_TYPE_DBSTOR) {
        // rst_id = bak->record.ctrlinfo.rcy_point.lsn <= rst_log->last_lsn ? (rst_log->rst_id - 1) : rst_log->rst_id;
        return rst_log->rst_id;
    } else {
        return asn <= rst_log->last_asn ? (rst_log->rst_id - 1) : rst_log->rst_id;
    }
}

void dtc_bak_init_log_ctrl(msg_log_ctrl_t *log_ctrl, arch_ctrl_t *arch_ctrl)
{
    errno_t ret = strcpy_sp(log_ctrl->name, CT_FILE_NAME_BUFFER_SIZE, arch_ctrl->name);
    if (ret != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        log_ctrl->status = CT_ERROR;
        return;
    }
    log_ctrl->type = cm_device_type(log_ctrl->name);
    log_ctrl->block_size = (uint32)arch_ctrl->block_size;
    log_ctrl->is_archivelog = CT_TRUE;
    log_ctrl->start_lsn = arch_ctrl->start_lsn;
    log_ctrl->end_lsn = arch_ctrl->end_lsn;

    return;
}

status_t bak_check_log_file(bak_log_file_info_t *log_file)
{
    if (log_file->backup_type != (knl_dbs_is_enable_dbs() ? DATA_TYPE_DBSTOR : DATA_TYPE_FILE)) {
        CT_LOG_RUN_ERR("[BACKUP] the backup file type is not supported by the current database");
        return CT_ERROR;
    }
    if (log_file->asn == CT_INVALID_ASN || log_file->asn == CT_INVALID_ID32) {
        CT_LOG_RUN_ERR("[BACKUP] the logfile asn is invalid");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t bak_cpy_file_name(log_file_t *file, msg_log_ctrl_t *log_ctrl)
{
    errno_t ret = strcpy_sp(log_ctrl->name, CT_FILE_NAME_BUFFER_SIZE, file->ctrl->name);
    if (ret != EOK) {
        CT_LOG_RUN_ERR("[BACKUP] failed to strcpy log file name");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t check_param_for_dtc_bak_process_set_log_ctrl(mes_message_t *receive_msg)
{
    if (sizeof(mes_message_head_t) + sizeof(bak_log_file_info_t) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("dtc_bak_process_set_log_ctrl msg size is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void dtc_bak_process_set_log_ctrl(void *sess, mes_message_t * receive_msg)
{
    CT_RETVOID_IFERR(check_param_for_dtc_bak_process_set_log_ctrl(receive_msg));
    bak_log_file_info_t log_file = *(bak_log_file_info_t *)(receive_msg->buffer + sizeof(mes_message_head_t));
    knl_session_t *session = (knl_session_t *)sess;
    database_t *db = &session->kernel->db;
    if (bak_check_log_file(&log_file) != CT_SUCCESS) {
        mes_release_message_buf(receive_msg->buffer);
        return;
    }

    uint32 rst_id = dtc_bak_get_rst_id(log_file.backup_type, log_file.asn, &(db->ctrl.core.resetlogs));
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);
    msg_log_ctrl_t log_ctrl;

    log_ctrl.file_id = bak_log_get_id(session, log_file.backup_type, rst_id, log_file.asn);
    log_ctrl.file_size = 0;
    if (log_ctrl.file_id == CT_INVALID_ID32) {
        arch_ctrl_t *arch_ctrl = arch_get_archived_log_info(session, rst_id, log_file.asn, ARCH_DEFAULT_DEST, session->kernel->id);
        if (arch_ctrl == NULL) {
            CT_LOG_RUN_ERR("[BACKUP] failed to get archived log for [%u-%u]", rst_id, log_file.asn);
            log_ctrl.status = CT_ERROR;
        } else {
            dtc_bak_init_log_ctrl(&log_ctrl, arch_ctrl);
            CT_LOG_DEBUG_INF("[BACKUP] Get archived log %s for [%u-%u]", log_ctrl.name, rst_id, log_file.asn);
        }
    } else {
        log_file_t *file = &logfile_set->items[log_ctrl.file_id];
        if (bak_cpy_file_name(file, &log_ctrl) != CT_SUCCESS) {
            mes_release_message_buf(receive_msg->buffer);
            return;
        }
        log_ctrl.type = file->ctrl->type;
        log_ctrl.block_size = file->ctrl->block_size;
        CT_LOG_DEBUG_INF("[BACKUP] Get online log %s for [%u-%u] write pos %llu", log_ctrl.name, rst_id, log_file.asn, file->head.write_pos);

        dtc_node_ctrl_t *node_ctrl = dtc_my_ctrl(session);
        if (log_ctrl.file_id == node_ctrl->log_last) {
            log_ctrl.is_archivelog = CT_FALSE;
            log_ctrl.file_size = file->head.write_pos;
        } else {
            log_ctrl.is_archivelog = CT_TRUE;
        }
        log_ctrl.start_lsn = 0;
        log_ctrl.end_lsn = 0;
    }

    mes_message_head_t head;

    mes_init_ack_head(receive_msg->head, &head, MES_CMD_SET_LOG_CTRL_ACK, (sizeof(mes_message_head_t) + sizeof(msg_log_ctrl_t)), session->id);

    mes_release_message_buf(receive_msg->buffer);
    if (mes_send_data2(&head, &log_ctrl) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] %s failed", "send get log curr size ack mes ");
        return;
    }
}

status_t dtc_bak_precheck(knl_session_t *session, uint32 target_id, msg_pre_bak_check_t *pre_check)
{
    mes_message_head_t head;
    mes_message_t  msg;

    mes_init_send_head(&head, MES_CMD_BAK_PRECHECK, sizeof(mes_message_head_t), CT_INVALID_ID32,
                       session->kernel->dtc_attr.inst_id, target_id, session->id, CT_INVALID_ID16);

    if (mes_send_data((void *)&head) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] %s failed", "send check is archive mes ");
        return CT_ERROR;
    }

    if (mes_recv(session->id, &msg, CT_FALSE, CT_INVALID_ID32, BAK_WAIT_TIMEOUT) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] %s failed", "receive check is archive mes ");
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(msg.head->cmd != MES_CMD_BAK_PRECHECK_ACK)) {
        mes_release_message_buf(msg.buffer);
        return CT_ERROR;
    }

    *pre_check = *(msg_pre_bak_check_t *)(msg.buffer + sizeof(mes_message_head_t));
    mes_release_message_buf(msg.buffer);

    return CT_SUCCESS;
}

void bak_process_precheck(void *sess, mes_message_t * receive_msg)
{
    if (sizeof(mes_message_head_t) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("bak_process_precheck msg size is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    mes_message_head_t head;
    knl_session_t *session = (knl_session_t *)sess;
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    msg_pre_bak_check_t pre_check;
    pre_check.is_archive = arch_ctx->is_archive;
    pre_check.is_switching = (session->kernel->switch_ctrl.request != SWITCH_REQ_NONE);

    SYNC_POINT_GLOBAL_START(CANTIAN_BACKUP_REV_PRECHECK_ARCH_REQ_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    mes_init_ack_head(receive_msg->head, &head, MES_CMD_BAK_PRECHECK_ACK, (sizeof(mes_message_head_t) + sizeof(msg_pre_bak_check_t)), session->id);

    mes_release_message_buf(receive_msg->buffer);
    if (mes_send_data2(&head, &pre_check) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] %s failed", "send check is archive ack mes ");
        return;
    }
}

status_t dtc_bak_unlatch_logfile(knl_session_t *session, bak_process_t *process, uint32 target_id)
{
    bak_assignment_t *assign_ctrl = &process->assign_ctrl;

    if (assign_ctrl->file_id == CT_INVALID_ID32) {
        return CT_SUCCESS;
    }

    mes_message_head_t head;
    mes_message_t  msg;

    mes_init_send_head(&head, MES_CMD_UNLATCH_LOGFILE, sizeof(mes_message_head_t) + sizeof(uint32), CT_INVALID_ID32,
                       session->kernel->dtc_attr.inst_id, target_id, session->id, CT_INVALID_ID16);

    if (mes_send_data2(&head, &assign_ctrl->file_id) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] %s failed", "send unlatch logfile mes ");
        return CT_ERROR;
    }

    if (mes_recv(session->id, &msg, CT_FALSE, CT_INVALID_ID32, BAK_WAIT_TIMEOUT) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] %s failed", "receive unlatch logfile mes ");
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(msg.head->cmd != MES_CMD_UNLATCH_LOGFILE_ACK)) {
        mes_release_message_buf(msg.buffer);
        return CT_ERROR;
    }
    mes_release_message_buf(msg.buffer);

    return CT_SUCCESS;
}

void dtc_process_unlatch_logfile(void *sess, mes_message_t * receive_msg)
{
    if (sizeof(mes_message_head_t) + sizeof(uint32) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("dtc_process_unlatch_logfile msg size is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    mes_message_head_t head;
    uint32 *file_id = (uint32 *)(receive_msg->buffer + sizeof(mes_message_head_t));
    knl_session_t *session = (knl_session_t *)sess;
    
    if (*file_id >= CT_MAX_LOG_FILES) {
        CT_LOG_RUN_ERR("*file_id(%u) err, larger than %u", *file_id, CT_MAX_LOG_FILES);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    log_unlatch_file(session, *file_id);

    mes_init_ack_head(receive_msg->head, &head, MES_CMD_UNLATCH_LOGFILE_ACK, sizeof(mes_message_head_t), session->id);

    mes_release_message_buf(receive_msg->buffer);
    if (mes_send_data((void*)&head) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] %s failed", "send unlatch logfile mes ack ");
        return;
    }
}

status_t dtc_bak_set_node_lsn(knl_session_t *session, bak_ctrlinfo_t *ctrlinfo, uint64 *curr_lsn, uint32 inst_id)
{
    mes_message_head_t head;
    mes_message_t msg;

    mes_init_send_head(&head, MES_CMD_SET_LOG_LSN, sizeof(mes_message_head_t) + sizeof(log_point_t),
                       CT_INVALID_ID32, session->kernel->dtc_attr.inst_id, inst_id, session->id, CT_INVALID_ID16);

    if (mes_send_data2(&head, &ctrlinfo->dtc_rcy_point[inst_id]) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] %s failed", "send get log lsn mes ");
        return CT_ERROR;
    }

    if (mes_recv(session->id, &msg, CT_FALSE, CT_INVALID_ID32, BAK_WAIT_TIMEOUT) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] %s failed", "receive get log lsn mes ");
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(msg.head->cmd != MES_CMD_SET_LOG_LSN_ACK)) {
        mes_release_message_buf(msg.buffer);
        return CT_ERROR;
    }

    *curr_lsn = *(uint64 *)(msg.buffer + sizeof(mes_message_head_t));
    mes_release_message_buf(msg.buffer);
    return CT_SUCCESS;
}

status_t dtc_bak_set_lsn(knl_session_t *session, bak_t *bak)
{
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;
    cluster_view_t view;
    uint64 curr_lsn;
    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        if (SECUREC_UNLIKELY(i == g_dtc->profile.inst_id)) {
            continue;
        }
        rc_get_cluster_view(&view, CT_FALSE);
        if (!rc_bitmap64_exist(&view.bitmap, i)) {
            continue;
        }

        if (dtc_bak_set_node_lsn(session, ctrlinfo, &curr_lsn, i) != CT_SUCCESS) {
            CT_LOG_RUN_WAR("[BACKUP] set node %u lsn failed", i);
            cm_reset_error();
            continue;
        }
        if (ctrlinfo->lsn > curr_lsn) {
            CT_LOG_RUN_INF("[BACKUP] set backup ctrlfile lsn %llu, curr_lsn %llu, inst %u", ctrlinfo->lsn, curr_lsn, i);
            ctrlinfo->lsn = curr_lsn;
        }
    }
    CT_LOG_RUN_INF("[BACKUP] set backup ctrlfile lsn %llu", ctrlinfo->lsn);
    return CT_SUCCESS;
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
        if (rcy_load(session, start_point, &data_size, &block_size) != CT_SUCCESS) {
            curr_lsn = CT_INVALID_INT64;
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

    if (curr_lsn != CT_INVALID_INT64) {
        rcy_close_file(session);
        curr_lsn = rcy_fetch_batch_lsn(session, batch);
    }

    mes_init_ack_head(receive_msg->head, &head, MES_CMD_SET_LOG_LSN_ACK, (sizeof(mes_message_head_t) + sizeof(uint64)), session->id);

    mes_release_message_buf(receive_msg->buffer);
    if (mes_send_data2(&head, &curr_lsn) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] %s failed", "send set log curr lsn ack mes ");
        return;
    }
}

void dtc_process_set_lsn_for_dbstor(knl_session_t *session, mes_message_t *receive_msg)
{
    mes_message_head_t head;
    log_point_t *start_point = (log_point_t *)(receive_msg->buffer + sizeof(mes_message_head_t));
    dtc_node_ctrl_t *ctrl = dtc_my_ctrl(session);
    SYNC_POINT_GLOBAL_START(CANTIAN_BACKUP_REV_LSN_REQ_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    uint64 curr_lsn = log_cmp_point(start_point, &(ctrl->lrp_point)) != 0 ?
                                    start_point->lsn : DB_CURR_LSN(session);
    mes_init_ack_head(receive_msg->head, &head, MES_CMD_SET_LOG_LSN_ACK,
                      (sizeof(mes_message_head_t) + sizeof(uint64)), session->id);
    mes_release_message_buf(receive_msg->buffer);
    if (mes_send_data2(&head, &curr_lsn) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] %s failed", "send set log curr lsn ack mes ");
    }
}

void dtc_process_set_lsn(void *sess, mes_message_t *receive_msg)
{
    if (sizeof(mes_message_head_t) + sizeof(log_point_t) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("dtc_process_set_ls msg size is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    if (knl_dbs_is_enable_dbs()) {
        dtc_process_set_lsn_for_dbstor((knl_session_t *)sess, receive_msg);
    } else {
        dtc_process_set_lsn_for_file((knl_session_t *)sess, receive_msg);
    }
}

status_t dtc_bak_get_node_ctrl_by_instance(knl_session_t *session, uint32 target_id, dtc_node_ctrl_t *node_ctrl)
{
    mes_message_head_t head;
    mes_message_t  msg;

    mes_init_send_head(&head, MES_CMD_BAK_GET_CTRL, sizeof(mes_message_head_t), CT_INVALID_ID32,
                       session->kernel->dtc_attr.inst_id, target_id, session->id, CT_INVALID_ID16);

    if (mes_send_data((void *)&head) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] %s failed", "send bak get ctrl mes ");
        return CT_ERROR;
    }

    if (mes_recv(session->id, &msg, CT_FALSE, CT_INVALID_ID32, BAK_WAIT_TIMEOUT) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] %s failed", "receive bak get ctrl mes ");
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(msg.head->cmd != MES_CMD_BAK_GET_CTRL_ACK)) {
        mes_release_message_buf(msg.buffer);
        return CT_ERROR;
    }

    *node_ctrl = *(dtc_node_ctrl_t *)(msg.buffer + sizeof(mes_message_head_t));
    mes_release_message_buf(msg.buffer);

    return CT_SUCCESS;
}

status_t dtc_bak_log_ckpt_trigger_local(knl_session_t *session, bak_ctrlinfo_t *ctrlinfo, uint32 inst_id,
                                        bool32 update, bool32 force_switch)
{
    knl_instance_t *kernel = session->kernel;
    bak_context_t *ctx = &kernel->backup_ctx;
    bak_t *bak = &ctx->bak;

    if (BAK_IS_DBSOTR(bak) && force_switch) {
        if (arch_switch_archfile_trigger(session, CT_FALSE) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BACKUP] faile switch archfile");
            return CT_ERROR;
        }
    }

    ckpt_trigger(session, CT_TRUE, CKPT_TRIGGER_INC);
    
    if (!update) {
        ctrlinfo->rcy_point = dtc_my_ctrl(session)->rcy_point;
        ctrlinfo->dtc_rcy_point[inst_id] = ctrlinfo->rcy_point;
        ctrlinfo->lrp_point = dtc_my_ctrl(session)->lrp_point;
        ctrlinfo->dtc_lrp_point[inst_id] = ctrlinfo->lrp_point;
        CT_LOG_RUN_INF("[BACKUP] set rcy log point: [%llu/%llu/%llu/%u] instid[%u]",
            (uint64)ctrlinfo->rcy_point.rst_id, ctrlinfo->rcy_point.lsn,
            (uint64)ctrlinfo->rcy_point.lfn, ctrlinfo->rcy_point.asn, inst_id);
    } else {
        bak->rcy_lsn[inst_id] = dtc_my_ctrl(session)->rcy_point.lsn;
        ctrlinfo->lrp_point = dtc_my_ctrl(session)->lrp_point;
        ctrlinfo->dtc_lrp_point[inst_id] = ctrlinfo->lrp_point;
        CT_LOG_RUN_INF("[BACKUP] set lrp log point: rst_id:[%llu/%llu/%llu/%u], instid[%u]",
            (uint64)ctrlinfo->lrp_point.rst_id,
            ctrlinfo->lrp_point.lsn, (uint64)ctrlinfo->lrp_point.lfn,
            ctrlinfo->lrp_point.asn, inst_id);
        CT_LOG_RUN_INF("[BACKUP] rcy log point: [%llu], instid[%u].", bak->rcy_lsn[inst_id], inst_id);
    }
    return CT_SUCCESS;
}

status_t dtc_bak_log_ckpt_trigger_by_instid(knl_session_t *session, bak_ctrlinfo_t *ctrlinfo, uint32 inst_id,
                                            bool32 update, bool32 force_switch)
{
    msg_ckpt_trigger_point_t ckpt_result;
    ckpt_result.lsn = 1;
    status_t s = dtc_ckpt_trigger(session, &ckpt_result, CT_TRUE, CKPT_TRIGGER_INC, inst_id, update, force_switch);
    if (s != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (!update) {
        if (ctrlinfo->max_rcy_lsn < ckpt_result.lsn) {
            ctrlinfo->max_rcy_lsn = ckpt_result.lsn;
            dtc_update_lsn(session, ctrlinfo->max_rcy_lsn);
        }
        ctrlinfo->dtc_rcy_point[inst_id] = ckpt_result.rcy_point;
        CT_LOG_RUN_INF("[BACKUP] set rcy log point: rst_id:[%llu/%llu/%llu/%u] instid[%u]",
            (uint64)ctrlinfo->dtc_rcy_point[inst_id].rst_id, ctrlinfo->dtc_rcy_point[inst_id].lsn,
            (uint64)ctrlinfo->dtc_rcy_point[inst_id].lfn, ctrlinfo->dtc_rcy_point[inst_id].asn, inst_id);
    } else {
        bak_t *bak = &session->kernel->backup_ctx.bak;
        bak->rcy_lsn[inst_id] = ckpt_result.rcy_point.lsn;
        ctrlinfo->dtc_lrp_point[inst_id] = ckpt_result.lrp_point;
        CT_LOG_RUN_INF("[BACKUP] set lrp log point: rst_id:[%llu/%llu/%llu/%u], instid[%u]",
            (uint64)ctrlinfo->dtc_lrp_point[inst_id].rst_id,
            ctrlinfo->dtc_lrp_point[inst_id].lsn, (uint64)ctrlinfo->dtc_lrp_point[inst_id].lfn,
            ctrlinfo->dtc_lrp_point[inst_id].asn, inst_id);
        CT_LOG_RUN_INF("[BACKUP] rcy log point: [%llu], instid[%u].", bak->rcy_lsn[inst_id], inst_id);
    }
    
    return CT_SUCCESS;
}

void dtc_bak_scn_broadcast(knl_session_t *session)
{
    mes_scn_bcast_t bcast;
    uint64 success_inst;

    mes_init_send_head(&bcast.head, MES_CMD_SCN_BROADCAST, sizeof(mes_scn_bcast_t), CT_INVALID_ID32,
                       g_dtc->profile.inst_id, CT_INVALID_ID8, session->id, CT_INVALID_ID16);
    bcast.scn = KNL_GET_SCN(&g_dtc->kernel->scn);
    bcast.min_scn = KNL_GET_SCN(&g_dtc->kernel->local_min_scn);
    bcast.lsn = cm_atomic_get(&g_dtc->kernel->lsn);

    mes_broadcast(session->id, MES_BROADCAST_ALL_INST, &bcast, &success_inst);
}

status_t dtc_bak_set_log_point(knl_session_t *session, bak_ctrlinfo_t *ctrlinfo,
                               bool32 update, bool32 force_switch)
{
    status_t status;
    cluster_view_t view;
    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        if (i != g_dtc->profile.inst_id) {
            rc_get_cluster_view(&view, CT_FALSE);
            if (!rc_bitmap64_exist(&view.bitmap, i)) {
                continue;
            }
            status = dtc_bak_log_ckpt_trigger_by_instid(session, ctrlinfo, i, update, force_switch);
            if (status != CT_SUCCESS) {
                cm_reset_error();
                continue;
            }
        } else {
            status = dtc_bak_log_ckpt_trigger_local(session, ctrlinfo, i, update, force_switch);
            if (status != CT_SUCCESS) {
                return status;
            }
        }
    }
    ctrlinfo->scn = DB_CURR_SCN(session);
    if (!update) {
        dtc_bak_scn_broadcast(session);
    }
    CT_LOG_RUN_INF("[BACKUP] backup trigger inc ckpt and force arch finish for the first time, ctrlinfo scn %llu",
        ctrlinfo->scn);
    return CT_SUCCESS;
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

status_t dtc_bak_force_arch_local_file(knl_session_t *session)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    if (log_switch_logfile(session, CT_INVALID_FILEID, CT_INVALID_ASN, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }
    cm_spin_lock(&arch_ctx->dest_lock, NULL);
    arch_ctx->force_archive_param.force_archive = CT_TRUE;
    cm_spin_unlock(&arch_ctx->dest_lock);
    while (arch_ctx->force_archive_param.force_archive == CT_TRUE) {
        cm_sleep(ARCH_FORCE_ARCH_CHECK_INTERVAL_MS);
    }
    if (arch_ctx->force_archive_param.failed) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t dtc_bak_force_arch_local(knl_session_t *session, uint64 lsn)
{
    if (arch_force_archive_trigger(session, lsn, CT_TRUE) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_FORCE_ARCH_FAILED, "in backup");
        CT_LOG_RUN_ERR("[BACKUP] failed to switch archfile");
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[BACKUP] get lasn lsn :[%llu], instid[%u]", lsn, session->kernel->id);
    return CT_SUCCESS;
}

status_t dtc_bak_force_arch_by_instid(knl_session_t *session, uint64 lsn, uint32 inst_id)
{
    status_t s = dtc_log_switch(session, lsn, inst_id);
    if (s != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_FORCE_ARCH_FAILED, "in backup");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t dtc_bak_force_arch(knl_session_t *session, bak_ctrlinfo_t *ctrlinfo, uint64 lsn)
{
    status_t status;
    cluster_view_t view;
    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        rc_get_cluster_view(&view, CT_FALSE);
        if (i == g_dtc->profile.inst_id) {
            if (cm_dbs_is_enable_dbs() == CT_TRUE) {
                status = dtc_bak_force_arch_local(session, lsn);
            } else {
                status = dtc_bak_force_arch_local_file(session);
            }
            if (status != CT_SUCCESS) {
                return status;
            }
        } else {
            if (!rc_bitmap64_exist(&view.bitmap, i)) {
                continue;
            }
            status = dtc_bak_force_arch_by_instid(session, lsn, i);
            if (status != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[BACKUP] force arch for backup lrp point redo log failed");
                cm_reset_error();
                continue;
            }
            CT_LOG_RUN_INF("[BACKUP] node %u force archive to lrp point succ", i);
        }
    }

    ctrlinfo->scn = DB_CURR_SCN(session);
    CT_LOG_RUN_INF("[BACKUP] online node force archive to max lrp lsn %llu point finished", lsn);
    return CT_SUCCESS;
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
            if (dtc_bak_force_arch(session, ctrlinfo, lsn) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }
    CT_LOG_RUN_INF("[BACKUP] backup online node force archive for lrp point redo log finished for the second time");
    return CT_SUCCESS;
}

status_t dtc_bak_handle_log_switch(knl_session_t *session)
{
    status_t status;
    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        if (i == g_dtc->profile.inst_id) {
            if (cm_dbs_is_enable_dbs() == CT_TRUE) {
                status = dtc_bak_force_arch_local(session, CT_INVALID_ID64);
            } else {
                status = dtc_bak_force_arch_local_file(session);
            }
            
            if (status != CT_SUCCESS) {
                return status;
            }
        } else {
            if (cm_dbs_is_enable_dbs() == CT_TRUE) {
                status = dtc_bak_force_arch_by_instid(session, CT_INVALID_ID64, i);
            } else {
                status = dtc_bak_force_arch_by_instid(session, 0, i);
            }
            if (status != CT_SUCCESS) {
                return status;
            }
        }
    }
    return CT_SUCCESS;
}

status_t dtc_bak_get_node_ctrl_by_device(knl_session_t *session, uint32 node_id)
{
    database_t *db = &session->kernel->db;
    bak_t *bak = &session->kernel->backup_ctx.bak;
    ctrl_page_t *pages = (ctrl_page_t *)(bak->ctrl_backup_bak_buf);
    bool32 loaded = CT_FALSE;
    for (int i = 0; i < db->ctrlfiles.count; i++) {
        ctrlfile_t *ctrlfile = &db->ctrlfiles.items[i];
        ctrl_page_t *page = &(pages[node_id]);
        int64 offset = (CTRL_LOG_SEGMENT + node_id) * ctrlfile->block_size;
        if (cm_open_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BACKUP] failed to open num %d file %s", i, ctrlfile->name);
            continue;
        }
        if (cm_read_device(ctrlfile->type, ctrlfile->handle, offset,
                           page, ctrlfile->block_size) != CT_SUCCESS) {
            cm_close_device(ctrlfile->type, &ctrlfile->handle);
            CT_LOG_RUN_ERR("[BACKUP] read offline node ctrl from ctrlfile[%d] failed, instid[%u]", i, node_id);
            continue;
        }
        if (page->head.pcn != page->tail.pcn) {
            CT_LOG_RUN_WAR("[BACKUP] get offline node %u ctrl data succ but pcn is invalid", node_id);
            continue;
        }
        CT_LOG_RUN_INF("[BACKUP] get offline node ctrl succ, ctrlfile[%d], instid[%u]", i, node_id);
        loaded = CT_TRUE;
        break;
    }
    if (!loaded) {
        CT_THROW_ERROR(ERR_LOAD_CONTROL_FILE, "no usable control file");
        return CT_ERROR;
    }
    return CT_SUCCESS;
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

status_t dtc_bak_get_node_ctrl(knl_session_t *session, uint32 node_id)
{
    uint32 retry_times = 0;
    cluster_view_t view;
    rc_get_cluster_view(&view, CT_FALSE);
    if (rc_bitmap64_exist(&view.bitmap, node_id)) {
        dtc_node_ctrl_t tmp_ctrl;
        if (dtc_bak_get_node_ctrl_by_instance(session, node_id, &tmp_ctrl) == CT_SUCCESS) {
            dtc_bak_copy_ctrl_page_2_buf(session, &tmp_ctrl, node_id);
            CT_LOG_RUN_INF("[BACKUP] get online node %u ctrl data", node_id);
            return CT_SUCCESS;
        }
    }
    // if the ctrl data cannot be obtained from the online instance, try to read from the device.
    while (retry_times < BAK_GET_CTRL_RETRY_TIMES) {
        cm_reset_error();
        if (dtc_bak_get_node_ctrl_by_device(session, node_id) == CT_SUCCESS) {
            return CT_SUCCESS;
        }
        retry_times++;
    }
    CT_LOG_RUN_ERR("[BACKUP] backup ctrlfile, get %s node %u ctrl data failed!",
                   rc_bitmap64_exist(&view.bitmap, node_id) ? "online" : "offline", node_id);
    return CT_ERROR;
}

status_t dtc_bak_get_ctrl_all(knl_session_t *session)
{
    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        if (SECUREC_UNLIKELY(i == g_dtc->profile.inst_id)) {
            continue;
        }
        if (dtc_bak_get_node_ctrl(session, i) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BACKUP] get node %u ctrl data for rcy point failed!", i);
            return CT_ERROR;
        }
    }
    CT_LOG_RUN_INF("[BACKUP] backup get all node ctrl data finished");
    return CT_SUCCESS;
}

void dtc_process_bak_get_ctrl(void *sess, mes_message_t * receive_msg)
{
    if (sizeof(mes_message_head_t) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("dtc_process_bak_get_ctrl msg size is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    mes_message_head_t head;
    knl_session_t *session = (knl_session_t *)sess;
    database_t *db = &session->kernel->db;
    dtc_node_ctrl_t *node_ctrl = (dtc_node_ctrl_t *)cm_push(session->stack, sizeof(dtc_node_ctrl_t));
    if (node_ctrl == NULL) {
        CT_LOG_RUN_INF("[BACKUP] fail to get resource from session stack");
        mes_release_message_buf(receive_msg->buffer);
        return;
    }

    SYNC_POINT_GLOBAL_START(CANTIAN_BACKUP_REV_CTRL_REQ_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    cm_spin_lock(&db->ctrl_lock, NULL);
    *node_ctrl = *(dtc_my_ctrl(session));
    cm_spin_unlock(&db->ctrl_lock);

    mes_init_ack_head(receive_msg->head, &head, MES_CMD_BAK_GET_CTRL_ACK,
                      (sizeof(mes_message_head_t) + sizeof(dtc_node_ctrl_t)), session->id);
    mes_release_message_buf(receive_msg->buffer);
    if (mes_send_data2(&head, node_ctrl) != CT_SUCCESS) {
        cm_pop(session->stack);
        CT_LOG_RUN_ERR("[BACKUP] %s failed", "send bak get ctrl ack mes ");
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
        for (uint32 logid = 0; logid < CT_MAX_LOG_FILES; logid++) {
            logfile_set->items[logid].ctrl = (log_file_ctrl_t *)db_get_log_ctrl_item(db->ctrl.pages, logid,
                                                                                     sizeof(log_file_ctrl_t),
                                                                                     *offset, i);
            logfile_set->items[logid].handle = CT_INVALID_ID32;

            if (logfile_set->items[logid].ctrl->block_size == 0 && logfile_set->items[logid].ctrl->size == 0) {
                break;
            }
        }
    }
}

static inline void rst_arch_init_proc_ctx(arch_proc_context_t *proc_ctx, arch_ctrl_t *arch_ctrl)
{
    proc_ctx->last_archived_log_record.asn = arch_ctrl->asn + 1;
    proc_ctx->last_archived_log_record.rst_id = arch_ctrl->rst_id;
    proc_ctx->last_archived_log_record.start_lsn = CT_INVALID_ID64;
    proc_ctx->last_archived_log_record.end_lsn = arch_ctrl->end_lsn;
    proc_ctx->last_archived_log_record.cur_lsn = arch_ctrl->end_lsn;
    CT_LOG_DEBUG_INF("[ARCH] archinit asn[%u], rst_id[%u], end_lsn[%llu]",
        proc_ctx->last_archived_log_record.asn, arch_ctrl->rst_id, arch_ctrl->end_lsn);
}

void dtc_rst_db_init_logfile_ctrl_by_dbstor(knl_session_t *session, uint32 *offset)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    logfile_set_t *logfile_set = NULL;
    for (uint32 i = 0; i < kernel->db.ctrl.core.node_count; i++) {
        logfile_set =  &(kernel->db.logfile_sets[i]);
        for (uint32 logid = 0; logid < CT_MAX_LOG_FILES; logid++) {
            logfile_set->items[logid].ctrl = (log_file_ctrl_t *)db_get_log_ctrl_item(db->ctrl.pages, logid,
                sizeof(log_file_ctrl_t), *offset, i);
            logfile_set->items[logid].handle = CT_INVALID_ID32;
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
    uint32 end_pos = (archived_end + 1) % CT_MAX_ARCH_NUM;
    uint32 recid;
    uint32 id;

    cm_spin_lock(&arch_ctx->record_lock, NULL);
    recid = ++arch_ctx->dtc_archived_recid[inst_id];
    cm_spin_unlock(&arch_ctx->record_lock);

    cm_spin_lock(&proc_ctx->record_lock, NULL);

    if (end_pos == archived_start) {
        arch_ctrl = db_get_arch_ctrl(session, end_pos, inst_id);
        arch_ctrl->recid = 0;
        archived_end = (archived_start + 1) % CT_MAX_ARCH_NUM;
        arch_set_arch_end(session, archived_end, inst_id);
        if (dtc_save_ctrl(session, inst_id) != CT_SUCCESS) {
            cm_spin_unlock(&proc_ctx->record_lock);
            CM_ABORT(0, "[ARCH] ABORT INFO: save core control file failed when record archive info");
        }
    }

    id = archived_end;
    arch_ctrl = db_get_arch_ctrl(session, id, inst_id);
    arch_ctrl_record_info_t arch_ctrl_record_info = {0, dest_id, 0, recid, arch_ctrl, file_name, log_head};
    arch_init_arch_ctrl(session, &arch_ctrl_record_info);

    if (arch_ctx->inst_id == inst_id) {
        proc_ctx->curr_arch_size += (int64)log_head->write_pos;
        if (cm_dbs_is_enable_dbs() == CT_TRUE) {
            rst_arch_init_proc_ctx(proc_ctx, arch_ctrl);
        }
    }
    arch_set_arch_end(session, end_pos, inst_id);

    if (db_save_arch_ctrl(session, id, inst_id) != CT_SUCCESS) {
        cm_spin_unlock(&proc_ctx->record_lock);
        CM_ABORT(0, "[ARCH] ABORT INFO: save core control file failed when record archive info");
        return CT_ERROR;
    }

    CT_LOG_RUN_INF("[ARCH] Record archive log file %s for log [%u-%u-%u] start %u end %u",
                   arch_ctrl->name, inst_id, log_head->rst_id, log_head->asn,
                   archived_start, end_pos);
    cm_spin_unlock(&proc_ctx->record_lock);
    return CT_SUCCESS;
}

status_t dtc_rst_arch_try_record_archinfo(knl_session_t *session, uint32 dest_pos, const char *file_name,
                                          log_file_head_t *head, uint32 inst_id)
{
    if (arch_archive_log_recorded(session, head->rst_id, head->asn, dest_pos, inst_id)) {
        CT_LOG_DEBUG_INF("[RESTORE]  arch file head info : [%u/%llu/%llu/%u], instid[%u]",
                         head->rst_id, head->first_lsn, head->last_lsn, head->asn, inst_id);
        return CT_SUCCESS;
    }
    if (dtc_rst_arch_record_archinfo(session, ARCH_DEFAULT_DEST, file_name, head, inst_id) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
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
    int32 handle = CT_INVALID_HANDLE;
    errno_t ret;

    head->first = CT_INVALID_ID64;
    head->last = CT_INVALID_ID64;
    head->write_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), log_file->block_size);
    head->asn = asn;
    head->block_size = log_file->block_size;
    head->rst_id = core->resetlogs.rst_id;
    log_calc_head_checksum(session, head);
    ret = memset_sp(ctx->logwr_buf, log_file->block_size, 0, log_file->block_size);
    knl_securec_check(ret);
    ret = memcpy_sp(ctx->logwr_buf, sizeof(log_file_head_t), head, sizeof(log_file_head_t));
    knl_securec_check(ret);

    if (cm_open_device(log_file->name, log_file->type, knl_io_flag(session), &handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] failed to open %s", log_file->name);
        return CT_ERROR;
    }

    if (cm_write_device(log_file->type, handle, 0, ctx->logwr_buf,
                        CM_CALC_ALIGN(sizeof(log_file_head_t), log_file->block_size)) != CT_SUCCESS) {
        cm_close_device(log_file->type, &handle);
        CT_LOG_RUN_ERR("[BACKUP] failed to write %s", log_file->name);
        return CT_ERROR;
    }

    cm_close_device(log_file->type, &handle);
    return CT_SUCCESS;
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

        if (curr == CT_INVALID_ID32 || curr == i) {
            curr = i;
            ctrl->log_first = i;
            ctrl->log_last = i;
            logfile->status = LOG_FILE_CURRENT;
        } else {
            logfile->status = LOG_FILE_INACTIVE;
        }
        if (db_save_log_ctrl(session, i, logfile->node_id) != CT_SUCCESS) {
            CM_ABORT(0, "[BACKUP] ABORT INFO: save core control file failed when restore log files");
        }
    }

    knl_panic(curr < ctrl->log_hwm);

    if (dtc_log_set_file_asn(session, asn, inst_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t dtc_rst_amend_ctrlinfo(knl_session_t *session, uint32 last_asn, uint32 file_id, uint32 inst_id)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;

    if (!BAK_IS_DBSOTR(bak)) {
        if (dtc_bak_reset_logfile(session, last_asn, file_id, inst_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    dtc_get_ctrl(session, inst_id)->dw_start = DW_DISTRICT_BEGIN(inst_id);
    dtc_get_ctrl(session, inst_id)->dw_end = DW_DISTRICT_BEGIN(inst_id);
    dtc_get_ctrl(session, inst_id)->scn = ctrlinfo->scn;
    dtc_get_ctrl(session, inst_id)->lrp_point = ctrlinfo->dtc_lrp_point[inst_id];
    CT_LOG_RUN_INF("[DTC RST] save ctrlinfo, the node is %u, lrp_lsn is %llu ", inst_id,
                   ctrlinfo->dtc_lrp_point[inst_id].lsn);
    session->kernel->scn = ctrlinfo->scn;
    if (dtc_save_ctrl(session, inst_id) != CT_SUCCESS) {
        CM_ABORT(0, "[BACKUP] ABORT INFO: save core control file failed when restore log files");
    }

    return CT_SUCCESS;
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
    int32 handle = CT_INVALID_HANDLE;
    log_file_head_t head;
    device_type_t type = cm_device_type(name);
    if (cm_open_device(name, type, O_BINARY | O_SYNC | O_RDWR, &handle) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cm_read_device(type, handle, 0, &head, sizeof(log_file_head_t)) != CT_SUCCESS) {
        cm_close_device(type, &handle);
        return CT_ERROR;
    }
    if ((int64)head.write_pos != cm_device_size(type, handle)) {
        cm_close_device(type, &handle);
        CT_THROW_ERROR(ERR_INVALID_ARCHIVE_LOG, name);
        return CT_ERROR;
    }
    cm_close_device(type, &handle);
    if (dtc_rst_arch_try_record_archinfo(session, ARCH_DEFAULT_DEST, name, &head, inst_id) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static bool32 dtc_rst_check_archive_is_dir(knl_session_t *session, char *file_name, size_t name_len,
    list_t *arch_dir_list)
{
    char temp_name[CT_NAME_BUFFER_SIZE] = {0};
    size_t dest_len = strlen(session->kernel->arch_ctx.arch_proc[ARCH_DEFAULT_DEST - 1].arch_dest) + 1;
    const char *arch_dir_name = NULL;
    errno_t err;

    err = strncpy_s(temp_name, CT_NAME_BUFFER_SIZE, file_name + dest_len, name_len - dest_len);
    knl_securec_check(err);

    uint32 i;
    for (i = 0; i < arch_dir_list->count; ++i) {
        arch_dir_name = (char *)cm_list_get(arch_dir_list, i);
        err = snprintf_s(file_name, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1, "%s/%s", arch_dir_name,
                         temp_name);
        PRTS_RETURN_IFERR(err);

        if (cm_exist_device(cm_device_type(file_name), file_name)) {
            break;
        }
    }

    if (i == arch_dir_list->count) {
        return CT_FALSE;
    }
    return CT_TRUE;
}

status_t get_dbid_from_arch_logfile(knl_session_t *session, uint32 *dbid, const char *name)
{
    int32 handle = CT_INVALID_HANDLE;
    log_file_head_t head;
    device_type_t type = cm_device_type(name);
    if (cm_open_device(name, type, O_BINARY | O_SYNC | O_RDWR, &handle) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cm_read_device(type, handle, 0, &head, sizeof(log_file_head_t)) != CT_SUCCESS) {
        cm_close_device(type, &handle);
        return CT_ERROR;
    }

    *dbid = head.dbid;
    cm_close_device(type, &handle);
    return CT_SUCCESS;
}

status_t dtc_rst_regist_archive_asn_by_dbstor(knl_session_t *session, uint32 *last_archvied_asn,
                                              uint32 rst_id, uint32 inst_id)
{
    status_t status;
    arch_file_name_info_t file_name_info = {rst_id, *last_archvied_asn + 1, inst_id, CT_FILE_NAME_BUFFER_SIZE,
                                            0, 0, NULL};
    uint32 *archive_asn = &file_name_info.asn;
    
    while (CT_TRUE) {
        char file_name[CT_FILE_NAME_BUFFER_SIZE] = {0};
        file_name_info.buf = file_name;
        if (*archive_asn == 1) {
            status = arch_find_first_archfile_rst(session, session->kernel->attr.arch_attr[0].local_path, session->kernel->db.ctrl.core.bak_dbid, &file_name_info);
        } else {
            status = arch_find_archive_asn_log_name(session, session->kernel->attr.arch_attr[0].local_path, session->kernel->db.ctrl.core.bak_dbid, &file_name_info);
        }
        if (status != CT_SUCCESS) {
            break;
        }

        if (dtc_rst_arch_regist_archive(session, file_name, inst_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
        (*archive_asn)++;
    }
    *last_archvied_asn = *archive_asn - 1;
    return CT_SUCCESS;
}

status_t dtc_rst_regist_archive_by_dbstor_skip(knl_session_t *session, uint32 *last_archived_asn, uint32 rst_id,
                                               uint64 start_lsn, uint32 inst_id)
{
    char file_name[CT_FILE_NAME_BUFFER_SIZE] = {0};
    arch_ctrl_t *last = arch_dtc_get_last_log(session, inst_id);
    arch_file_name_info_t file_name_info = {rst_id, 0, inst_id, CT_FILE_NAME_BUFFER_SIZE, 0, 0, file_name};
    file_name_info.start_lsn = last->asn == 0 ? start_lsn + 1 : last->end_lsn + 1;
    uint64 *find_lsn = &file_name_info.start_lsn;

    while (CT_TRUE) {
        status_t status = arch_find_archive_log_name(session, &file_name_info);
        if (status != CT_SUCCESS) {
            return CT_SUCCESS;
        }
        *find_lsn = file_name_info.end_lsn + 1;
        CT_LOG_RUN_INF("[RESTORE] found archfile head info: [%u/%llu/%llu/%u]", rst_id, *find_lsn,
                       file_name_info.end_lsn, file_name_info.asn);
        if (!cm_exist_device(cm_device_type((const char *)file_name), (const char *)file_name)) {
            break;
        }
        if (dtc_rst_arch_regist_archive(session, file_name, inst_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
        *last_archived_asn = file_name_info.asn;
    }
    return CT_SUCCESS;
}

status_t dtc_rst_regist_archive_by_dbstor(knl_session_t *session, uint32 *last_archived_asn, uint32 rst_id,
                                          uint64 start_lsn, uint64 end_lsn, uint32 inst_id)
{
    char file_name[CT_FILE_NAME_BUFFER_SIZE] = {0};
    bool32 is_first = CT_TRUE;
    uint64 find_lsn;
    uint64 next_lsn;
    bool32 found_arch;
    CT_LOG_RUN_INF("[RESTORE] regist archive log for node %u, start lsn %llu, end lsn %llu, last archived asn %u",
        inst_id, start_lsn, end_lsn, *last_archived_asn);
    if (!session->kernel->backup_ctx.bak.prefer_bak_set) {
        return dtc_rst_regist_archive_by_dbstor_skip(session, last_archived_asn, rst_id, start_lsn, inst_id);
    }

    while (CT_TRUE) {
        found_arch = CT_FALSE;
        if (is_first) {
            log_start_end_lsn_t first_find_lsn = {start_lsn, end_lsn, 0};
            arch_info_t first_arch_info = {file_name, &first_find_lsn, &found_arch, last_archived_asn, inst_id, rst_id};
            status_t status = rst_find_first_archfile_with_lsn(session, first_arch_info);
            if (status != CT_SUCCESS) {
                return CT_ERROR;
            }
            find_lsn = first_find_lsn.end_lsn + 1;
            is_first = CT_FALSE;
        } else {
            arch_info_t arch_info = {.buf = file_name, .found_arch = &found_arch,
                                     .last_archived_asn = last_archived_asn, .inst_id = inst_id, .rst_id = rst_id};
            status_t status = rst_find_archfile_name_with_lsn(session, find_lsn, arch_info, &next_lsn);
            if (status != CT_SUCCESS) {
                return CT_ERROR;
            }
            find_lsn = next_lsn + 1;
        }
        if (found_arch != CT_TRUE) {
            break;
        }
        CT_LOG_RUN_INF("[RESTORE] found archfile info %s:[first %u/rst id %u/find lsn %llu/last asn %u], instid[%u]",
                       file_name, is_first, rst_id, find_lsn, *last_archived_asn, inst_id);
        if (!cm_exist_device(cm_device_type((const char *)file_name), (const char *)file_name)) {
            break;
        }
        if (dtc_rst_arch_regist_archive(session, file_name, inst_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t dtc_rst_regist_archive(knl_session_t *session, uint32 *last_archived_asn, uint32 rst_id, int32 inst_id)
{
    uint32 archive_asn = *last_archived_asn + 1;
    char file_name[CT_FILE_NAME_BUFFER_SIZE] = {0};
    list_t arch_dir_list;

    cm_create_list(&arch_dir_list, CT_MAX_PATH_BUFFER_SIZE);
    dtc_load_archive(&arch_dir_list);

    for (;;) {
        arch_set_archive_log_name(session, rst_id, archive_asn, ARCH_DEFAULT_DEST, file_name,
                                  CT_FILE_NAME_BUFFER_SIZE, inst_id);
        if (!cm_exist_device(cm_device_type((const char *)file_name), (const char *)file_name)) {
            if (!dtc_rst_check_archive_is_dir(session, file_name, strlen(file_name), &arch_dir_list)) {
                break;
            }
        }
        arch_file_name_info_t file_name_info = {rst_id, archive_asn, inst_id,
                                                CT_FILE_NAME_BUFFER_SIZE, 0, 0, file_name};
        if (arch_validate_archive_file(session, &file_name_info) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[ARCH] failed to load archive file");
            break;
        }
        if (dtc_rst_arch_regist_archive(session, file_name, inst_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
        archive_asn++;
    }

    *last_archived_asn = archive_asn - 1;
    return CT_SUCCESS;
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

    for (uint32 i = 0; i < CT_MAX_DATA_FILES; i++) {
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
    uint32 last_asn = CT_INVALID_ID32;
    uint32 file_id = CT_INVALID_ID32;
    uint32 last_archived_asn = CT_INVALID_ID32;
    uint64 data_size;
    bool32 is_dbstor = BAK_IS_DBSOTR(bak);
    bak_file_t *file_info;
    uint32 prev_inst_id = CT_INVALID_ID32;
    database_t *db = &session->kernel->db;
    uint32 rst_id = db->ctrl.core.resetlogs.rst_id;

    data_size = db_get_datafiles_size(session) + dtc_rst_db_get_logfiles_size(session);

    bak_set_progress(session, BACKUP_BUILD_STAGE, data_size);
    dtc_rst_update_process_data_size(session, ctx);
    uint32 inst_id;
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;
    uint32 node_count = session->kernel->db.ctrl.core.node_count;
    if (!is_dbstor) {
        for (uint32 i = 0; i < node_count; i++) {
            last_archived_asn = ctrlinfo->dtc_lrp_point[i].asn;
            if (dtc_rst_amend_ctrlinfo(session, last_archived_asn + 1, file_id, i) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    } else {
        if (dtc_rst_amend_ctrlinfo(session, last_archived_asn, file_id, session->kernel->id) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    for (int32 i = file_index; i >= 0; i--) {
        if (bak->files[i].type != BACKUP_ARCH_FILE && bak->files[i].type != BACKUP_LOG_FILE) {
            break;
        }
        inst_id = bak->files[i].inst_id;
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
                                                     file_info->end_lsn, file_info->inst_id) != CT_SUCCESS) {
                    return CT_ERROR;
                }
            } else {
                if (dtc_rst_regist_archive(session, &last_archived_asn, rst_id, inst_id) != CT_SUCCESS) {
                    return CT_ERROR;
                }
            }
            if (last_archived_asn != last_asn) {
                file_id = CT_INVALID_ID32;
            }
        }
        if (dtc_rst_amend_ctrlinfo(session, last_archived_asn + 1, file_id, inst_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    bak->progress.stage = BACKUP_WRITE_FINISHED;
    return CT_SUCCESS;
}

status_t dtc_rst_amend_all_arch_file_dbstor(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    uint32 rst_id = kernel->db.ctrl.core.resetlogs.rst_id;

    for (uint32 i = 0; i < kernel->db.ctrl.core.node_count; i++) {
        arch_ctrl_t *last = arch_dtc_get_last_log(session, i);
        uint32 archive_asn = last->asn;
        knl_panic(rst_id >= last->rst_id);
        if (dtc_rst_regist_archive_asn_by_dbstor(session, &archive_asn, rst_id, i) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t dtc_rst_create_logfiles(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    log_file_ctrl_t *logfile = NULL;
    int32 handle = CT_INVALID_HANDLE;
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
            if (cm_build_device(logfile->name, logfile->type, session->kernel->attr.xpurpose_buf,
                CT_XPURPOSE_BUFFER_SIZE, logfile->size,
                knl_io_flag(session), CT_FALSE, &handle) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[RESTORE] failed to create %s ", logfile->name);
                return CT_ERROR;
            }
            CT_LOG_RUN_INF("[RESTORE] restore build file, src_file:%s, file size :%lld",
                           logfile->name, logfile->size);
            cm_close_device(logfile->type, &handle);
            if (is_dbstor) {
                break;
            }
        }
    }

    return CT_SUCCESS;
}

status_t dtc_bak_set_logfile_ctrl(knl_session_t *session, uint32 curr_file_index, log_file_head_t *head,
                                  bak_ctrl_t *ctrl, bool32 *ignore_data)
{
    knl_instance_t *kernel = session->kernel;
    bak_t *bak = &kernel->backup_ctx.bak;
    bak_file_t *file_info = &bak->files[curr_file_index];
    log_file_ctrl_t *logfile = NULL;
    logfile_set_t *logfile_set = &(kernel->db.logfile_sets[file_info->inst_id]);

    *ignore_data = CT_FALSE;
    ctrl->offset = 0;

    if (file_info->type == BACKUP_LOG_FILE) {
        logfile = logfile_set->items[file_info->id].ctrl;
        ctrl->type = logfile->type;
        /* open when build log files, closed in bak_end => bak_reset_ctrl */
        if (cm_open_device(logfile->name, logfile->type, knl_io_flag(session), &ctrl->handle) != CT_SUCCESS) {
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
        arch_set_archive_log_name(session, head->rst_id, head->asn, ARCH_DEFAULT_DEST, ctrl->name,
                                  CT_FILE_NAME_BUFFER_SIZE, file_info->inst_id);
    }

    ctrl->type = cm_device_type(ctrl->name);
    CT_LOG_DEBUG_INF("[BACKUP] bak_set_logfile_ctrl get archive log %s", ctrl->name);

    if (cm_exist_device(ctrl->type, ctrl->name)) {
        CT_LOG_DEBUG_INF("[BACKUP] Archive log %s exists", ctrl->name);
        if (arch_process_existed_archfile(session, ctrl->name, *head, ignore_data) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (!*ignore_data) {
        if (cm_create_device(ctrl->name, ctrl->type, O_BINARY | O_SYNC | O_RDWR | O_EXCL, &ctrl->handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BACKUP] failed to create %s", ctrl->name);
            return CT_ERROR;
        }
        CT_LOG_RUN_INF("[BACKUP] Create %s", ctrl->name);
    }

    return CT_SUCCESS;
}


status_t dtc_bak_running(knl_session_t *session, uint32 target_id, bool32 *running)
{
    mes_message_head_t head;
    mes_message_t  msg;

    mes_init_send_head(&head, MES_CMD_BAK_RUNNING, sizeof(mes_message_head_t), CT_INVALID_ID32,
                       session->kernel->dtc_attr.inst_id, target_id, session->id, CT_INVALID_ID16);

    if (mes_send_data((void *)&head) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] %s failed", "send bak is running mes ");
        return CT_ERROR;
    }

    if (mes_recv(session->id, &msg, CT_FALSE, CT_INVALID_ID32, BAK_WAIT_TIMEOUT) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] %s failed", "receive bak is running mes ");
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(msg.head->cmd != MES_CMD_BAK_RUNNING_ACK)) {
        mes_release_message_buf(msg.buffer);
        return CT_ERROR;
    }

    *running = *(bool32 *)(msg.buffer + sizeof(mes_message_head_t));
    mes_release_message_buf(msg.buffer);

    return CT_SUCCESS;
}

void dtc_process_running(void *sess, mes_message_t * receive_msg)
{
    CT_LOG_RUN_INF("[BACKUP] process mes cmd bak running start.");
    if (sizeof(mes_message_head_t) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("dtc_process_running msg size is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    mes_message_head_t head;
    knl_session_t *session = (knl_session_t *)sess;
    SYNC_POINT_GLOBAL_START(CANTIAN_BACKUP_REV_PRECHECK_STAT_REQ_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    mes_init_ack_head(receive_msg->head, &head, MES_CMD_BAK_RUNNING_ACK, (sizeof(mes_message_head_t) + sizeof(bool32)), CT_INVALID_ID16);

    mes_release_message_buf(receive_msg->buffer);
    if (mes_send_data2(&head, &session->kernel->backup_ctx.bak_condition) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] %s failed", "send bak is running ack mes ");
        return;
    }
    CT_LOG_RUN_INF("[BACKUP] process mes cmd bak running succ.");
}

uint64 dtc_get_min_lsn_lrp_point(bak_record_t *record)
{
    uint64 min_lsn = CT_INVALID_ID64;
    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        if (record->ctrlinfo.dtc_lrp_point[i].lsn < min_lsn) {
            min_lsn = record->ctrlinfo.dtc_lrp_point[i].lsn;
        }
    }
    return min_lsn;
}

/*
compare two ckpt's rcy->lsn for all nodes:
if the first rcy->lsn is equal to the second rcy->lsn, set ctrlinfo->lsn(kernel->lsn) as base_lsn;
else, set min(ctrlinfo->lsn, the first rcy->lsn) as base_lsn.
*/
void bak_update_ctrlinfo_lsn(knl_session_t *session)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;
    uint64 lsn = CT_INVALID_INT64;
    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        if (ctrlinfo->dtc_rcy_point[i].lsn == bak->rcy_lsn[i]) {
            lsn = MIN(lsn, ctrlinfo->lsn);
        } else {
            lsn = MIN(lsn, ctrlinfo->dtc_rcy_point[i].lsn);
        }
    }
    ctrlinfo->lsn = lsn;
    CT_LOG_RUN_INF("[BACKUP] set ctrlinfo_lsn %llu.", ctrlinfo->lsn);
}

status_t dtc_bak_set_lrp_point(knl_session_t *session)
{
    if (!session->kernel->attr.clustered) {
        return CT_SUCCESS;
    }
    bak_t *bak = &session->kernel->backup_ctx.bak;
    status_t ret = memset_s(bak->ctrl_backup_bak_buf, CT_DFLT_CTRL_BLOCK_SIZE * CT_MAX_INSTANCES, 0,
                            CT_DFLT_CTRL_BLOCK_SIZE * CT_MAX_INSTANCES);
    knl_securec_check(ret);
 
    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        if (SECUREC_UNLIKELY(i == g_dtc->profile.inst_id)) {
            dtc_node_ctrl_t tmp_ctrl;
            tmp_ctrl = *dtc_my_ctrl(session);
            dtc_bak_copy_ctrl_page_2_buf(session, &tmp_ctrl, i);
            continue;
        }
        if (dtc_bak_get_node_ctrl(session, i) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BACKUP] get node %u ctrl data for lrp point failed!", i);
            return CT_ERROR;
        }
    }
    bak_update_lrp_point(session);
    bak_update_ctrlinfo_lsn(session);
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;
    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        if (ctrlinfo->dtc_lrp_point[i].lsn < ctrlinfo->dtc_rcy_point[i].lsn) {
            CT_LOG_RUN_ERR("[BACKUP] node %u has invalid point lsn, rcy lsn %llu, lrp lsn %llu", i,
                           ctrlinfo->dtc_rcy_point[i].lsn, ctrlinfo->dtc_lrp_point[i].lsn);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}
bak_arch_files_t *bak_get_arch_by_index(bak_arch_files_t *arch_buf, uint32 index, log_start_end_asn_t arch_asn)
{
    bak_arch_files_t *arch_file = NULL;
    for (uint32 i = 0; i < arch_asn.end_asn - arch_asn.start_asn + 1; i++) {
        arch_file = (bak_arch_files_t *)(arch_buf + i);
        if (arch_file->asn == index) {
            break;
        }
    }
    return arch_file;
}

status_t bak_get_logfile_by_lsn_dbstor(knl_session_t *session, bak_arch_files_t *arch_file_buf,
                                       log_start_end_asn_t asn, uint32 inst_id)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;
    bak_arch_files_t *arch_file;
    uint64 end_lsn;
    if (asn.start_asn == 0 && asn.end_asn == 0) {
        end_lsn = ctrlinfo->dtc_rcy_point[inst_id].lsn;
        asn.end_asn = asn.max_asn;
    } else {
        arch_file = bak_get_arch_by_index(arch_file_buf, asn.end_asn, asn);
        end_lsn = arch_file->end_lsn;
    }
    uint64 max_lrp_lsn = dtc_bak_get_max_lrp_lsn(ctrlinfo);
    log_start_end_lsn_t node_lsn = {ctrlinfo->dtc_rcy_point[inst_id].lsn,
                                    ctrlinfo->dtc_lrp_point[inst_id].lsn,
                                    max_lrp_lsn};
    if (end_lsn < max_lrp_lsn) {
        arch_file_info_t file_info = {0};
        file_info.arch_file_type = cm_device_type(bak->record.path);
        file_info.start_lsn = end_lsn;
        file_info.inst_id = inst_id;
        file_info.asn = asn.end_asn + 1;
        file_info.logfile.handle = CT_INVALID_HANDLE;
        if (bak_get_logfile_dbstor(session, &file_info, node_lsn) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BACKUP] read arch log from dbstor, asn %u, start lsn %llu, max_lrp_lsn %llu, inst_id %u",
                file_info.asn, file_info.start_lsn, max_lrp_lsn, inst_id);
            return CT_ERROR;
        }
        CT_LOG_RUN_INF("[BACKUP] backup logfile, read arch log from dbstor, "
            "asn %u, start lsn %llu, max_lrp_lsn %llu, inst_id %u",
            file_info.asn, file_info.start_lsn, max_lrp_lsn, inst_id);
    }
    CT_LOG_RUN_INF("[BACKUP] backup logfile from dbstor finished, end_lsn %llu, max_lrp_lsn %llu",
                   end_lsn, max_lrp_lsn);
    return CT_SUCCESS;
}

uint32 log_get_id_from_fileset_by_asn_node_id(logfile_set_t *file_set, uint32 rst_id, uint32 asn)
{
    if (asn == CT_INVALID_ASN) {
        return CT_INVALID_ID32;
    }

    for (uint32 i = 0; i < file_set->logfile_hwm; i++) {
        log_file_t *file = &file_set->items[i];

        if (LOG_IS_DROPPED(file->ctrl->flg)) {
            continue;
        }

        if (file->head.rst_id != rst_id || file->head.asn != asn) {
            continue;
        }

        return i;
    }

    return CT_INVALID_ID32;
}

status_t bak_get_arch_from_redo_prepare(knl_session_t *session, knl_session_t *session_bak,
                                        arch_file_info_t *file_info, dtc_rcy_node_t *rcy_node, logfile_set_t *local_file_set)
{
    errno_t ret;
    ret = memcpy_s((char*)session_bak, sizeof(knl_session_t), (char*)session, sizeof(knl_session_t));
    knl_securec_check(ret);
    session_bak->kernel = (knl_instance_t *)malloc(sizeof(knl_instance_t));
    ret = memcpy_s((char*)session_bak->kernel, sizeof(knl_instance_t), (char*)session->kernel, sizeof(knl_instance_t));
    knl_securec_check(ret);
    session_bak->kernel->attr.xpurpose_buf = cm_aligned_buf(g_instance->xpurpose_buf);
    session_bak->kernel->db.status = DB_STATUS_CLOSED;
    if (cm_aligned_malloc(CT_MAX_BATCH_SIZE, "bak log batch buffer", &file_info->read_buf) != CT_SUCCESS) {
        return CT_ERROR;
    }
    int64 size = (int64)LOG_LGWR_BUF_SIZE(session);
    if (cm_aligned_malloc(size, "bak rcy read buffer", &rcy_node->read_buf) != CT_SUCCESS) {
        return CT_ERROR;
    }
    logfile_set_t *file_set = LOGFILE_SET(session, rcy_node->node_id);
    local_file_set->log_count = file_set->log_count;
    local_file_set->logfile_hwm = file_set->logfile_hwm;
    if (dtc_init_node_logset_for_backup(session, rcy_node->node_id, rcy_node, local_file_set) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void bak_get_arch_from_redo_free(knl_compress_t *compress_ctx, knl_session_t *session, arch_file_info_t *file_info,
                                 dtc_rcy_node_t *rcy_node, logfile_set_t *local_file_set)
{
    CM_FREE_PTR(session->kernel);
    cm_aligned_free(&file_info->read_buf);
    cm_aligned_free(&rcy_node->read_buf);
    for (uint32 i = 0; i <  local_file_set->logfile_hwm; i++) {
        if (rcy_node->handle[i] != CT_INVALID_HANDLE) {
            cm_close_device(local_file_set->items[i].ctrl->type, &rcy_node->handle[i]);
        }
    }
    cm_aligned_free(&rcy_node->read_buf);
}

status_t dtc_bak_get_logfile_by_asn_file(knl_session_t *session, bak_arch_files_t *arch_file_buf,
                                         log_start_end_asn_t asn, uint32 inst_id, log_start_end_asn_t *target_asn)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    dtc_rcy_node_t rcy_node;
    rcy_node.node_id = inst_id;
    logfile_set_t local_file_set;
    arch_file_info_t file_info;
    knl_compress_t compress_ctx;
    knl_session_t session_bak;
    status_t status = CT_SUCCESS;
    if (knl_compress_alloc(DEFAULT_ARCH_COMPRESS_ALGO, &compress_ctx, CT_TRUE) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] Failed to alloc compress context");
        return CT_ERROR;
    }
    if (bak_get_arch_from_redo_prepare(session, &session_bak, &file_info, &rcy_node, &local_file_set) != CT_SUCCESS) {
        knl_compress_free(DEFAULT_ARCH_COMPRESS_ALGO, &compress_ctx, CT_TRUE);
        return CT_ERROR;
    }
    uint32 rst_id = session->kernel->db.ctrl.core.resetlogs.rst_id;
    dtc_node_ctrl_t *node_ctrl = dtc_get_ctrl(session, inst_id);
    log_file_t *curr_logfile = &local_file_set.items[node_ctrl->log_last];
    uint32 tmp_asn = asn.end_asn == 0 ? target_asn->start_asn - 1 : asn.end_asn;
    CT_LOG_RUN_INF("[BACKUP] log_first %llu, log_last %llu, last_asn %llu, curr_asn %llu, asn.end_asn %u, tmp_asn %u.",
                   (uint64)node_ctrl->log_first, (uint64)node_ctrl->log_last, (uint64)node_ctrl->last_asn, (uint64)curr_logfile->head.asn, asn.end_asn, target_asn->start_asn);
    while (tmp_asn < target_asn->end_asn && tmp_asn + 1 <= curr_logfile->head.asn) {
        uint32 file_id = log_get_id_from_fileset_by_asn_node_id(&local_file_set, rst_id, tmp_asn + 1);
        if (file_id == CT_INVALID_ID32) {
            status = CT_ERROR;
            break;
        }
        CT_LOG_RUN_INF("[BACKUP] get next_file_id %u.", file_id);
        log_file_t *logfile = &local_file_set.items[file_id];
        if (logfile->head.write_pos == CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size)) {
            tmp_asn += 1;
            continue;
        }
        file_info.logfile.ctrl = logfile->ctrl;
        file_info.inst_id = inst_id;
        file_info.asn = tmp_asn + 1;
        file_info.arch_file_type = cm_device_type(bak->record.path);
        if (bak_get_logfile_file(session, &file_info, logfile, &compress_ctx) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }
        tmp_asn += 1;
    }
    knl_compress_free(DEFAULT_ARCH_COMPRESS_ALGO, &compress_ctx, CT_TRUE);
    bak_get_arch_from_redo_free(&compress_ctx, &session_bak, &file_info, &rcy_node, &local_file_set);
    CT_LOG_RUN_INF("[BACKUP] backup logfile from file finished, status %u, end_asn %u.", status, tmp_asn);
    return CT_SUCCESS;
}

void bak_set_archfile_info(knl_session_t *session, log_start_end_info_t arch_info,
                           local_arch_file_info_t file_info, bak_arch_files_t *arch_file_buf, char *file_name)
{
    arch_attr_t *arch_attr = &session->kernel->attr.arch_attr[0];
    char *arch_path = arch_attr->local_path;
    bak_arch_files_t *arch_file;
    bool32 arch_need = CT_TRUE;
    uint32 arch_num = *(arch_info.arch_num);

    if (file_info.local_start_lsn < arch_info.target_lsn->start_lsn &&
        file_info.local_end_lsn >= arch_info.target_lsn->start_lsn) {
        arch_info.result_asn->start_asn = file_info.local_asn;
        arch_info.result_asn->end_asn = MAX(arch_info.result_asn->end_asn, file_info.local_asn);
        arch_need = CT_TRUE;
    } else if (file_info.local_start_lsn >= arch_info.target_lsn->start_lsn &&
               file_info.local_end_lsn < arch_info.target_lsn->max_lsn) {
        arch_info.result_asn->end_asn = MAX(arch_info.result_asn->end_asn, file_info.local_asn);
        arch_need = CT_TRUE;
    } else if (file_info.local_start_lsn < arch_info.target_lsn->max_lsn &&
               file_info.local_end_lsn >= arch_info.target_lsn->max_lsn) {
        arch_info.result_asn->end_asn = file_info.local_asn;
        arch_need = CT_TRUE;
    } else {
        arch_need = CT_FALSE;
    }

    if (arch_need) {
        arch_file = (bak_arch_files_t *)(arch_file_buf + arch_num);
        bak_set_file_name(arch_file->arch_file_name, arch_path, file_name);
        arch_file->start_lsn = file_info.local_start_lsn;
        arch_file->end_lsn = file_info.local_end_lsn;
        arch_file->asn = file_info.local_asn;
        *(arch_info.result_end_lsn) = MAX(*(arch_info.result_end_lsn), file_info.local_end_lsn);
        *(arch_info.arch_num) += 1;
        CT_LOG_RUN_INF("[BACKUP] get archived file %s succ, asn %u, start_lsn %llu, end_lsn %llu.",
            arch_file->arch_file_name, file_info.local_asn, file_info.local_start_lsn, file_info.local_end_lsn);
    }
}

status_t bak_set_archfile_info_file(log_start_end_info_t arch_info, local_arch_file_info_t file_info,
                                    bak_arch_files_t *arch_file_buf, char *file_name, log_file_head_t *head)
{
    bak_arch_files_t *arch_file;
    bool32 arch_need = CT_FALSE;
    uint32 arch_num = *(arch_info.arch_num);

    if (file_info.local_asn >= arch_info.target_asn->start_asn &&
        file_info.local_asn <= arch_info.target_asn->end_asn) {
        if (arch_info.result_asn->start_asn ==  0) {
            arch_info.result_asn->start_asn = file_info.local_asn;
        } else {
            arch_info.result_asn->start_asn = MIN(arch_info.result_asn->start_asn, file_info.local_asn);
        }
        arch_info.result_asn->end_asn = MAX(arch_info.result_asn->end_asn, file_info.local_asn);
        arch_need = CT_TRUE;
    }

    if (arch_need) {
        arch_file = (bak_arch_files_t *)(arch_file_buf + arch_num);
        errno_t ret = memcpy_sp(arch_file->arch_file_name, BAK_ARCH_FILE_NAME_MAX_LENGTH, file_name, strlen(file_name));
        knl_securec_check(ret);
        arch_file->asn = file_info.local_asn;
        arch_file->block_size = head->block_size;
        int64 real_file_size;
        if (arch_get_real_size(arch_file->arch_file_name, &real_file_size) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BACKUP] Failed to get arch file size for %s.", arch_file->arch_file_name);
            return CT_ERROR;
        }
        arch_file->file_size = real_file_size;
        *(arch_info.arch_num) += 1;
        CT_LOG_RUN_INF("[BACKUP] get archived file %s succ, asn %u.",
            arch_file->arch_file_name, file_info.local_asn);
    }
    return CT_SUCCESS;
}

status_t bak_get_arch_asn(knl_session_t *session, log_start_end_info_t arch_info, uint32 inst_id,
                          bak_arch_files_t *arch_file_buf)
{
    uint32 rst_id = session->kernel->db.ctrl.core.resetlogs.rst_id;
    local_arch_file_info_t file_info;
    DIR *arch_dir;
    struct dirent *arch_dirent;
    arch_attr_t *arch_attr = &session->kernel->attr.arch_attr[0];
    char *arch_path = arch_attr->local_path;
    bool32 dbid_equal = CT_FALSE;
    if ((arch_dir = opendir(arch_path)) == NULL) {
        return CT_ERROR;
    }
    while ((arch_dirent = readdir(arch_dir)) != NULL) {
        if (bak_convert_archfile_name(arch_dirent->d_name, &file_info, inst_id, rst_id,
                                      BAK_IS_DBSOTR(&session->kernel->backup_ctx.bak) == CT_FALSE)) {
            continue;
        }
        if (bak_check_archfile_dbid(session, arch_path, arch_dirent->d_name, &dbid_equal) != CT_SUCCESS) {
            closedir(arch_dir);
            return CT_ERROR;
        }
        if (dbid_equal != CT_TRUE) {
            continue;
        }
        arch_info.result_asn->max_asn = MAX(arch_info.result_asn->max_asn, file_info.local_asn);
        bak_set_archfile_info(session, arch_info, file_info, arch_file_buf, arch_dirent->d_name);
    }
    closedir(arch_dir);
    return CT_SUCCESS;
}

status_t bak_open_logfile_dbstor(knl_session_t *session, log_file_t *logfile, uint32 inst_id)
{
    database_t *db = &session->kernel->db;
    logfile->ctrl = (log_file_ctrl_t *)db_get_log_ctrl_item(db->ctrl.pages, 0, sizeof(log_file_ctrl_t),
                                                            db->ctrl.log_segment, inst_id);
    logfile->head.rst_id = db->ctrl.core.resetlogs.rst_id;
    status_t ret = cm_open_device(logfile->ctrl->name, logfile->ctrl->type,
                                  knl_redo_io_flag(session), &logfile->handle);
    if (ret != CT_SUCCESS || logfile->handle == -1) {
        CT_LOG_RUN_ERR("[BACKUP] failed to open %s ", logfile->ctrl->name);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[BACKUP] open logfile finish for instance %u, handle %u", inst_id, logfile->handle);
    return CT_SUCCESS;
}

status_t bak_flush_archfile_head(knl_session_t *session, arch_file_info_t *file_info)
{
    int32 head_size = CM_CALC_ALIGN(sizeof(log_file_head_t), file_info->logfile.ctrl->block_size);
    log_file_head_t *head = &file_info->arch_file_head;
    head->last = CT_INVALID_ID64;
    head->first_lsn = file_info->start_lsn;
    head->last_lsn = file_info->end_lsn;
    head->rst_id = file_info->logfile.head.rst_id;
    head->asn = file_info->asn;
    head->write_pos = file_info->offset;
    head->cmp_algorithm = COMPRESS_NONE;
    head->block_size = head_size;
    head->dbid = session->kernel->db.ctrl.core.dbid;
    status_t ret = memset_sp(head->unused, CT_LOG_HEAD_RESERVED_BYTES, 0, CT_LOG_HEAD_RESERVED_BYTES);
    knl_securec_check(ret);

    log_calc_head_checksum(session, head);
    file_info->tmp_file_handle = -1;
    if (cm_open_device(file_info->tmp_file_name, file_info->arch_file_type, O_BINARY | O_SYNC | O_RDWR, &file_info->tmp_file_handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] open %s failed.", file_info->tmp_file_name);
        return CT_ERROR;
    }
    if (cm_write_device(file_info->arch_file_type, file_info->tmp_file_handle, 0, head, head_size) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] flush log file head failed.");
        return CT_ERROR;
    }
    cm_close_device(file_info->arch_file_type, &file_info->tmp_file_handle);
    CT_LOG_RUN_INF("[BACKUP] Flush head start[%llu] end[%llu] asn[%u] rst[%u] fscn[%llu], "
                   "write_pos[%llu] head[%d] dbid[%u]",
                   head->first_lsn, head->last_lsn, head->asn, head->rst_id, head->first, head->write_pos,
                   head->block_size, head->dbid);
    return CT_SUCCESS;
}

status_t bak_prepare_read_logfile_dbstor(knl_session_t *session, log_file_t *logfile, uint64 start_lsn, uint32 inst_id,
                                         uint32 *redo_log_filesize)
{
    if (bak_open_logfile_dbstor(session, logfile, inst_id) != CT_SUCCESS) {
        return CT_ERROR;
    }
    status_t status = cm_device_get_used_cap(logfile->ctrl->type, logfile->handle, start_lsn, redo_log_filesize);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] failed to fetch redolog size from DBStor");
        cm_close_device(logfile->ctrl->type, &logfile->handle);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[BACKUP] get redo log size in dbstor %uk", *redo_log_filesize);
    return CT_SUCCESS;
}

status_t bak_get_log_dbstor(knl_session_t *session, log_start_end_lsn_t *lsn,
                            arch_file_info_t *file_info, uint64 redo_log_file_size)
{
    uint64 start_lsn = file_info->start_lsn + 1;
    uint64 last_lsn = start_lsn;
    uint64 *file_offset = &file_info->offset;
    *file_offset = CM_CALC_ALIGN(sizeof(log_file_head_t), file_info->logfile.ctrl->block_size);
    int32 data_size;
    uint64 redo_log_filesize = redo_log_file_size;
    while (redo_log_filesize > 0) {
        status_t status = cm_device_read_batch(file_info->logfile.ctrl->type, file_info->logfile.handle, start_lsn,
            CT_INVALID_ID64, file_info->read_buf.aligned_buf, file_info->read_buf.buf_size, &data_size, &last_lsn);
        if (status != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BACKUP] fail to read file %s, start lsn %llu, data size %u",
                           file_info->logfile.ctrl->name, start_lsn, data_size);
            return CT_ERROR;
        }
        if (data_size == 0) {
            CT_LOG_RUN_INF("[BACKUP] reach last lsn, left size(%lld), data size(%d), last_lsn(%llu)",
                           redo_log_filesize, data_size, last_lsn);
            break;
        }
        if (arch_check_log_valid(data_size, file_info->read_buf.aligned_buf) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (*file_offset == CM_CALC_ALIGN(sizeof(log_file_head_t), file_info->logfile.ctrl->block_size)) {
            file_info->arch_file_head.first = ((log_batch_t *)(file_info->read_buf.aligned_buf))->scn;
        }
        status = cm_write_device(file_info->arch_file_type, file_info->tmp_file_handle, *file_offset,
            file_info->read_buf.aligned_buf, data_size);
        if (status != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BACKUP] fail to write %s, file offset %llu, data size %u",
                           file_info->tmp_file_name, *file_offset, data_size);
            return CT_ERROR;
        }
        redo_log_filesize -= data_size;
        start_lsn = last_lsn + 1;
        *file_offset += (uint64)data_size;
        if (last_lsn >= lsn->max_lsn) {
            CT_LOG_RUN_INF("[BACKUP] left size(%lld), data size(%d), last_lsn(%llu), end_lsn(%llu), max_lsn(%llu)",
                redo_log_filesize, data_size, last_lsn, lsn->end_lsn, lsn->max_lsn);
            break;
        }
    }
    CT_LOG_RUN_INF("[BACKUP] backup redo log end point: left size(%lld), start_lsn(%llu), last_lsn(%llu), "
        "lrp_lsn(%llu), max_lrp_lsn(%llu), first batch scn(%llu)", redo_log_filesize, file_info->start_lsn + 1,
        last_lsn, lsn->end_lsn, lsn->max_lsn, file_info->arch_file_head.first);
    file_info->end_lsn = last_lsn;
    return CT_SUCCESS;
}

status_t bak_generate_archfile_dbstor(knl_session_t *session, arch_file_info_t *file_info)
{
    if (file_info->offset == CM_CALC_ALIGN(sizeof(log_file_head_t), file_info->logfile.ctrl->block_size)) {
        CT_LOG_RUN_INF("[BACKUP] there is no need to generate new archive file for backup");
        return CT_SUCCESS;
    }
    if (bak_flush_archfile_head(session, file_info) != CT_SUCCESS) {
        return CT_ERROR;
    }
    bak_t *bak = &session->kernel->backup_ctx.bak;
    uint32 rst_id = session->kernel->db.ctrl.core.resetlogs.rst_id;
    char bak_arch_name[CT_FILE_NAME_BUFFER_SIZE] = {0};
    char *bak_path = session->kernel->backup_ctx.bak.record.path;
    bak_record_new_file(bak, BACKUP_ARCH_FILE, file_info->asn, 0, rst_id, CT_FALSE,
                        file_info->start_lsn, file_info->end_lsn);

    uint32 file_index = bak->file_count - 1;
    bak_generate_bak_file(session, bak_path, bak->files[file_index].type, file_index, bak->files[file_index].id, 0,
                          bak_arch_name);
    bak->files[file_index].size = cm_device_size(cm_device_type(file_info->tmp_file_name), file_info->tmp_file_handle);
    status_t status = cm_rename_device(file_info->arch_file_type, file_info->tmp_file_name, bak_arch_name);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] rename tmp file %s to %s failed", file_info->tmp_file_name, bak_arch_name);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[BACKUP] backup logfile %s from dbstor succ", bak_arch_name);
    return CT_SUCCESS;
}

status_t bak_generate_archfile_file(knl_session_t *session, arch_file_info_t *file_info)
{
    if (file_info->offset == CM_CALC_ALIGN(sizeof(log_file_head_t), file_info->logfile.ctrl->block_size)) {
        CT_LOG_RUN_INF("[BACKUP] there is no need to generate new archive file for backup");
        return CT_SUCCESS;
    }
    bak_t *bak = &session->kernel->backup_ctx.bak;
    uint32 rst_id = session->kernel->db.ctrl.core.resetlogs.rst_id;
    char bak_arch_name[CT_FILE_NAME_BUFFER_SIZE] = {0};
    char *bak_path = session->kernel->backup_ctx.bak.record.path;
    bak_record_new_file(bak, BACKUP_ARCH_FILE, file_info->asn, 0, rst_id, CT_FALSE,
                        file_info->start_lsn, file_info->end_lsn);

    uint32 file_index = bak->file_count - 1;
    bak_generate_bak_file(session, bak_path, bak->files[file_index].type, file_index, bak->files[file_index].id, 0,
                          bak_arch_name);
    bak->files[file_index].size = cm_device_size(cm_device_type(file_info->tmp_file_name), file_info->tmp_file_handle);
    status_t status = cm_rename_device(file_info->arch_file_type, file_info->tmp_file_name, bak_arch_name);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] rename tmp file %s to %s failed", file_info->tmp_file_name, bak_arch_name);
        return CT_ERROR;
    }
    CT_LOG_DEBUG_INF("[BACKUP] rename tmp file %s to %s succ.", file_info->tmp_file_name, bak_arch_name);
    CT_LOG_RUN_INF("[BACKUP] backup logfile %s from file succ", bak_arch_name);
    return CT_SUCCESS;
}

void bak_free_res_for_get_logfile(arch_file_info_t *file_info)
{
    cm_close_device(file_info->logfile.ctrl->type, &file_info->logfile.handle);
    cm_close_device(file_info->arch_file_type, &file_info->tmp_file_handle);
    cm_aligned_free(&file_info->read_buf);
}

status_t bak_get_logfile_dbstor(knl_session_t *session, arch_file_info_t *file_info, log_start_end_lsn_t lsn)
{
    uint32 redo_log_filesize = 0;
    if (bak_prepare_read_logfile_dbstor(session, &file_info->logfile, file_info->end_lsn + 1,
                                        file_info->inst_id, &redo_log_filesize) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] read prepare failed, start lsn %llu, left log size %u",
            file_info->end_lsn + 1, redo_log_filesize);
        return CT_ERROR;
    }
    if (redo_log_filesize <= 0) {
        cm_close_device(file_info->logfile.ctrl->type, &file_info->logfile.handle);
        return CT_SUCCESS;
    }
    if (cm_aligned_malloc(CT_MAX_BATCH_SIZE, "bak log batch buffer", &file_info->read_buf) != CT_SUCCESS) {
        cm_close_device(file_info->logfile.ctrl->type, &file_info->logfile.handle);
        return CT_ERROR;
    }
    if (bak_create_tmp_archfile(session, file_info->tmp_file_name, file_info->arch_file_type,
                                &file_info->tmp_file_handle)) {
        cm_close_device(file_info->logfile.ctrl->type, &file_info->logfile.handle);
        cm_aligned_free(&file_info->read_buf);
        return CT_ERROR;
    }
    if (bak_get_log_dbstor(session, &lsn, file_info, SIZE_K_U64(redo_log_filesize)) != CT_SUCCESS) {
        bak_free_res_for_get_logfile(file_info);
        CT_LOG_RUN_ERR("[BACKUP] dtc fetch start end arch log file asn failed");
        return CT_ERROR;
    }
    if (file_info->end_lsn < lsn.end_lsn) {
        bak_free_res_for_get_logfile(file_info);
        CT_LOG_RUN_ERR("[BACKUP] backup redo log end point must be after its own lrp lsn");
        return CT_ERROR;
    }
    if (bak_generate_archfile_dbstor(session, file_info) != CT_SUCCESS) {
        bak_free_res_for_get_logfile(file_info);
        CT_LOG_RUN_ERR("[BACKUP] generate log file failed");
        return CT_ERROR;
    }
    bak_free_res_for_get_logfile(file_info);
    return CT_SUCCESS;
}

status_t bak_get_logfile_file(knl_session_t *session, arch_file_info_t *file_info,
                              log_file_t *logfile, knl_compress_t *compress_ctx)
{
    bak_set_tmp_archfile_name(session, file_info->tmp_file_name);
    CT_LOG_DEBUG_INF("[BACKUP] set tmp_archfile_name %s.", file_info->tmp_file_name);
    if (arch_archive_file(session, file_info->read_buf, logfile, file_info->tmp_file_name, compress_ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (bak_generate_archfile_file(session, file_info) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] generate log file failed");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t bak_get_arch_start_and_end_point_dbstor(knl_session_t *session, uint32 inst_id,
                                                 log_start_end_asn_t *asn, bak_arch_files_t *arch_file_buf)
{
    knl_instance_t *kernel = session->kernel;
    bak_context_t *ctx = &kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;
    uint64 end_lsn = 0;
    uint32 arch_num = 0;

    log_start_end_lsn_t lsn = {ctrlinfo->dtc_rcy_point[inst_id].lsn,
                               ctrlinfo->dtc_lrp_point[inst_id].lsn,
                               dtc_bak_get_max_lrp_lsn(ctrlinfo)};
    CT_LOG_RUN_INF("[BACKUP] backup logfile, dtc_rcy_point lsn %llu, dtc_lrp_point %llu, max_lrp_lsn %llu",
        lsn.start_lsn, lsn.end_lsn, lsn.max_lsn);
    log_start_end_asn_t target_asn = {0};
    log_start_end_info_t arch_info = {asn, &target_asn, &lsn, &end_lsn, &arch_num};
    if (bak_get_arch_asn(session, arch_info, inst_id, arch_file_buf) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] dtc fetch start and end arch log file asn failed");
        return CT_ERROR;
    }
    if (arch_num != 0) {
        if (asn->start_asn == 0 || asn->end_asn == 0 || arch_num != asn->end_asn - asn->start_asn + 1) {
            CT_LOG_RUN_ERR("[BACKUP] start or end arch log file asn invalid, "
                           "arch num %u, start asn %u, end asn %u, max asn %u",
                           arch_num, asn->start_asn, asn->end_asn, asn->max_asn);
            CT_LOG_RUN_WAR("[BACKUP] check whether the lastest archive files are lost before backup task");
            return CT_ERROR;
        }
        for (int i = asn->start_asn; i <= asn->end_asn; i++) {
            bak_arch_files_t *arch_file = (bak_arch_files_t *)(arch_file_buf + (i - asn->start_asn));
            CT_LOG_RUN_INF("[BACKUP] arch file name %s, start lsn %llu, end lsn %llu",
                arch_file->arch_file_name, arch_file->start_lsn, arch_file->end_lsn);
        }
    }
    CT_LOG_RUN_INF("[BACKUP] get arch log files in dir, start asn %u end asn %u instid %u, end lsn %llu",
                   asn->start_asn, asn->end_asn, inst_id, end_lsn);
    // some redo logs that need to be restored are not archived, get if from dbstor.
    return CT_SUCCESS;
}

status_t rst_remove_duplicate_batch_archfile(device_type_t type, uint32 arch_handle, uint32 tmp_arch_handle,
                                             aligned_buf_t read_buf, log_file_head_t *head, uint64 end_lsn)
{
    uint64 offset_read = head->block_size;
    uint64 offset_write = head->block_size;
    log_batch_t *batch = NULL;

    while (CT_TRUE) {
        if (cm_read_device(type, arch_handle, offset_read, read_buf.aligned_buf, sizeof(log_batch_t)) != CT_SUCCESS) {
            return CT_ERROR;
        }
        batch = (log_batch_t *)(read_buf.aligned_buf);
        if (batch->lsn <= end_lsn) {
            offset_read += batch->space_size;
            continue;
        }
        head->first = batch->scn;
        break;
    }
    int32 read_size = 0;
    while (offset_read < head->write_pos) {
        if (cm_read_device_nocheck(type, arch_handle, offset_read,
                                   read_buf.aligned_buf, read_buf.buf_size, &read_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (cm_write_device(type, tmp_arch_handle, offset_write, read_buf.aligned_buf, read_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
        offset_read += read_size;
        offset_write += read_size;
    }
    head->write_pos = offset_write;
    CT_LOG_RUN_INF("[RESTORE] remove duplicates batchs to lsn %llu, scn %llu", batch->lsn, batch->scn);
    return CT_SUCCESS;
}

status_t rst_generate_deduplicate_archfile(knl_session_t *session, log_file_head_t *head,
                                           char *tmp_arch_name, int32 tmp_arch_handle, arch_info_t first_arch_info)
{
    device_type_t type = cm_device_type(tmp_arch_name);
    log_calc_head_checksum(session, head);
    if (cm_write_device(type, tmp_arch_handle, 0, head, sizeof(log_file_head_t)) != CT_SUCCESS) {
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[RESTORE] Flush head start[%llu] end[%llu] asn[%u] rst[%u] fscn[%llu], write_pos[%llu] dbid[%u].",
                   head->first_lsn, head->last_lsn, head->asn, head->rst_id, head->first, head->write_pos, head->dbid);
    arch_attr_t *arch_attr = &session->kernel->attr.arch_attr[0];
    char *arch_path = arch_attr->local_path;
    char dst_arch_name[CT_FILE_NAME_BUFFER_SIZE] = {0};
    local_arch_file_info_t file_info = {head->rst_id, first_arch_info.inst_id,
                                        head->first_lsn, head->last_lsn, head->asn};
    bak_set_archfile_name_with_lsn(session, dst_arch_name, arch_path, CT_FILE_NAME_BUFFER_SIZE, file_info);
    if (cm_rename_device(type, tmp_arch_name, dst_arch_name) != CT_SUCCESS) {
        return CT_ERROR;
    }
    status_t ret = memcpy_sp(first_arch_info.buf, CT_FILE_NAME_BUFFER_SIZE, dst_arch_name, CT_FILE_NAME_BUFFER_SIZE);
    knl_securec_check(ret);
    return CT_SUCCESS;
}

status_t rst_modify_archfile_content(knl_session_t *session, log_start_end_lsn_t *local_lsn,
                                     arch_info_t first_arch_info)
{
    char *file_name = first_arch_info.buf;
    log_start_end_lsn_t *lsn = first_arch_info.find_lsn;
    int32 handle = CT_INVALID_HANDLE;
    log_file_head_t head;
    device_type_t type = cm_device_type(file_name);
    aligned_buf_t read_buf;
    char tmp_file_name[CT_FILE_NAME_BUFFER_SIZE] = {0};
    int32 tmp_arch_handle = CT_INVALID_HANDLE;
    if (rst_prepare_modify_archfile(file_name, &handle, tmp_file_name, &tmp_arch_handle, &read_buf) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] prepare for modify archive log file failed");
        return CT_ERROR;
    }
    if (cm_read_device(type, handle, 0, &head, sizeof(log_file_head_t)) != CT_SUCCESS) {
        rst_release_modify_resource(type, &handle, tmp_file_name, &tmp_arch_handle, &read_buf);
        return CT_ERROR;
    }

    if (rst_remove_duplicate_batch_archfile(type, handle, tmp_arch_handle,
                                            read_buf, &head, lsn->end_lsn) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] remove duplicates batchs failed.");
        rst_release_modify_resource(type, &handle, tmp_file_name, &tmp_arch_handle, &read_buf);
        return CT_ERROR;
    }
    *(first_arch_info.last_archived_asn) += 1;
    head.first_lsn = lsn->end_lsn;
    head.last_lsn = local_lsn->end_lsn;
    head.asn = *(first_arch_info.last_archived_asn);
    // after that, the asn of the log batch may not match the asn of the archive file in which it is located.
    if (rst_generate_deduplicate_archfile(session, &head, tmp_file_name, tmp_arch_handle,
                                          first_arch_info) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] generate new archive log file failed.");
        rst_release_modify_resource(type, &handle, tmp_file_name, &tmp_arch_handle, &read_buf);
        return CT_ERROR;
    }
    rst_release_modify_resource(type, &handle, tmp_file_name, &tmp_arch_handle, &read_buf);
    return CT_SUCCESS;
}

status_t rst_modify_archfile_name(knl_session_t *session, arch_info_t first_arch_info)
{
    char *arch_buf = first_arch_info.buf;
    char tmp_buf[CT_FILE_NAME_BUFFER_SIZE] = {0};
    int32 handle = CT_INVALID_HANDLE;
    arch_attr_t *arch_attr = &session->kernel->attr.arch_attr[0];
    char *arch_path = arch_attr->local_path;
    log_file_head_t head;
    device_type_t type = cm_device_type(arch_buf);
    if (cm_open_device(arch_buf, type, O_BINARY | O_SYNC | O_RDWR, &handle) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cm_read_device(type, handle, 0, &head, sizeof(log_file_head_t)) != CT_SUCCESS) {
        cm_close_device(type, &handle);
        return CT_ERROR;
    }
    *(first_arch_info.last_archived_asn) += 1;
    if (head.asn == *(first_arch_info.last_archived_asn)) {
        cm_close_device(type, &handle);
        return CT_SUCCESS;
    }
    head.asn = *(first_arch_info.last_archived_asn);
    log_calc_head_checksum(session, &head);
    if (cm_write_device(type, handle, 0, &head, sizeof(log_file_head_t)) != CT_SUCCESS) {
        cm_close_device(type, &handle);
        return CT_ERROR;
    }
    cm_close_device(type, &handle);
    CT_LOG_RUN_INF("[RESTORE] Flush head start[%llu] end[%llu] asn[%u] rst[%u] fscn[%llu], write_pos[%llu] dbid[%u]",
                   head.first_lsn, head.last_lsn, head.asn, head.rst_id, head.first, head.write_pos, head.dbid);
    local_arch_file_info_t file_info = {head.rst_id, first_arch_info.inst_id,
                                        head.first_lsn, head.last_lsn, head.asn};
    bak_set_archfile_name_with_lsn(session, tmp_buf, arch_path, CT_FILE_NAME_BUFFER_SIZE, file_info);
    if (cm_rename_device(type, arch_buf, tmp_buf) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t rst_reset_first_archfile(knl_session_t *session, log_start_end_lsn_t *local_lsn, arch_info_t first_arch_info)
{
    log_start_end_lsn_t *lsn = first_arch_info.find_lsn;
    if (local_lsn->end_lsn != 0 && local_lsn->start_lsn != lsn->end_lsn) {
        CT_LOG_RUN_INF("[RESTORE] duplicates batchs archive log %s, start lsn %llu, end lsn %llu, find lsn %llu",
                       first_arch_info.buf, local_lsn->start_lsn, local_lsn->end_lsn, lsn->end_lsn);
        if (rst_modify_archfile_content(session, local_lsn, first_arch_info) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RESTORE] reset duplicates batchs archive log file failed.");
            return CT_ERROR;
        }
        lsn->start_lsn = lsn->end_lsn;
        lsn->end_lsn = local_lsn->end_lsn;
        *(first_arch_info.found_arch) = CT_TRUE;
    } else if (local_lsn->end_lsn != 0) {
        CT_LOG_RUN_INF("[RESTORE] no duplicates batchs archive log %s, start lsn %llu, end lsn %llu, find lsn %llu",
                       first_arch_info.buf, local_lsn->start_lsn, local_lsn->end_lsn, lsn->end_lsn);
        if (rst_modify_archfile_name(session, first_arch_info) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RESTORE] reset no duplicates batchs archive log file failed.");
            return CT_ERROR;
        }
        lsn->start_lsn = local_lsn->start_lsn;
        lsn->end_lsn = local_lsn->end_lsn;
        *(first_arch_info.found_arch) = CT_TRUE;
    }
    return CT_SUCCESS;
}

status_t rst_find_first_archfile_with_lsn(knl_session_t *session, arch_info_t first_arch_info)
{
    local_arch_file_info_t file_info;
    log_start_end_lsn_t found_local_lsn = {0};
    DIR *arch_dir;
    struct dirent *arch_dirent;
    char *arch_path = session->kernel->attr.arch_attr[0].local_path;
    bool32 dbid_equal = CT_FALSE;
    if ((arch_dir = opendir(arch_path)) == NULL) {
        return CT_ERROR;
    }
    while ((arch_dirent = readdir(arch_dir)) != NULL) {
        if (bak_convert_archfile_name(arch_dirent->d_name, &file_info, first_arch_info.inst_id, first_arch_info.rst_id,
                                      BAK_IS_DBSOTR(&session->kernel->backup_ctx.bak) == CT_FALSE)) {
            continue;
        }
        if (bak_check_archfile_dbid(session, arch_path, arch_dirent->d_name, &dbid_equal) != CT_SUCCESS) {
            closedir(arch_dir);
            return CT_ERROR;
        }
        if (dbid_equal != CT_TRUE) {
            continue;
        }
        if (file_info.local_end_lsn > first_arch_info.find_lsn->end_lsn &&
            file_info.local_start_lsn <= first_arch_info.find_lsn->end_lsn) {
            bak_set_file_name(first_arch_info.buf, arch_path, arch_dirent->d_name);
            found_local_lsn.start_lsn = file_info.local_start_lsn;
            found_local_lsn.end_lsn = file_info.local_end_lsn;
            CT_LOG_RUN_INF("[RESTORE] found archive log %s, start lsn %llu, end lsn %llu, asn %u",
                first_arch_info.buf, file_info.local_start_lsn, file_info.local_end_lsn, file_info.local_asn);
            break;
        }
    }
    if (rst_reset_first_archfile(session, &found_local_lsn, first_arch_info) != CT_SUCCESS) {
        closedir(arch_dir);
        CT_LOG_RUN_ERR("[RESTORE] reset first archive log file failed.");
        return CT_ERROR;
    }
    closedir(arch_dir);
    return CT_SUCCESS;
}

status_t rst_rename_archfile_by_asn(knl_session_t *session, arch_info_t arch_info, char *arch_name, bool32 *dbid_equal)
{
    char tmp_buf[CT_FILE_NAME_BUFFER_SIZE] = {0};
    int32 handle = CT_INVALID_HANDLE;
    arch_attr_t *arch_attr = &session->kernel->attr.arch_attr[0];
    char *arch_path = arch_attr->local_path;
    log_file_head_t head;
    device_type_t type = cm_device_type(arch_name);
    bak_set_file_name(tmp_buf, arch_path, arch_name);
    if (cm_open_device(tmp_buf, type, O_BINARY | O_SYNC | O_RDWR, &handle) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cm_read_device(type, handle, 0, &head, sizeof(log_file_head_t)) != CT_SUCCESS) {
        cm_close_device(type, &handle);
        return CT_ERROR;
    }
    if (head.dbid != session->kernel->db.ctrl.core.dbid) {
        cm_close_device(type, &handle);
        *dbid_equal = CT_FALSE;
        return CT_SUCCESS;
    }
    *dbid_equal = CT_TRUE;
    *(arch_info.last_archived_asn) += 1;
    if (head.asn == *(arch_info.last_archived_asn)) {
        cm_close_device(type, &handle);
        return CT_SUCCESS;
    }
    head.asn = *(arch_info.last_archived_asn);
    log_calc_head_checksum(session, &head);
    if (cm_write_device(type, handle, 0, &head, sizeof(log_file_head_t)) != CT_SUCCESS) {
        cm_close_device(type, &handle);
        return CT_ERROR;
    }
    cm_close_device(type, &handle);
    CT_LOG_RUN_INF("[RESTORE] Flush head start[%llu] end[%llu] asn[%u] rst[%u] fscn[%llu], write_pos[%llu] dbid[%u]",
                   head.first_lsn, head.last_lsn, head.asn, head.rst_id, head.first, head.write_pos, head.dbid);
    local_arch_file_info_t file_info = {head.rst_id, arch_info.inst_id, head.first_lsn, head.last_lsn, head.asn};
    bak_set_archfile_name_with_lsn(session, arch_info.buf, arch_path, CT_FILE_NAME_BUFFER_SIZE, file_info);
    if (cm_rename_device(type, tmp_buf, arch_info.buf) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t rst_find_archfile_name_with_lsn(knl_session_t *session, uint64 lsn, arch_info_t arch_info, uint64 *out_lsn)
{
    DIR *arch_dir;
    struct dirent *arch_dirent;
    arch_attr_t *arch_attr = &session->kernel->attr.arch_attr[0];
    char *arch_path = arch_attr->local_path;
    local_arch_file_info_t file_info;
    if ((arch_dir = opendir(arch_path)) == NULL) {
        return CT_ERROR;
    }
    while ((arch_dirent = readdir(arch_dir)) != NULL) {
        if (bak_convert_archfile_name(arch_dirent->d_name, &file_info, arch_info.inst_id, arch_info.rst_id,
                                      BAK_IS_DBSOTR(&session->kernel->backup_ctx.bak)) == CT_FALSE) {
            continue;
        }
        if (lsn > file_info.local_start_lsn && lsn <= file_info.local_end_lsn) {
            bool32 dbid_equal;
            if (rst_rename_archfile_by_asn(session, arch_info, arch_dirent->d_name, &dbid_equal) != CT_SUCCESS) {
                closedir(arch_dir);
                return CT_ERROR;
            }
            if (dbid_equal == CT_TRUE) {
                *out_lsn = file_info.local_end_lsn;
                *(arch_info.found_arch) = CT_TRUE;
                break;
            }
        }
    }
    closedir(arch_dir);
    return CT_SUCCESS;
}

status_t rst_prepare_modify_archfile(char *arch_file_name, int32 *arch_file_handle,
                                     char *tmp_arch_file_name, int32 *tmp_arch_file_handle, aligned_buf_t *read_buf)
{
    device_type_t type = cm_device_type(arch_file_name);
    if (cm_open_device(arch_file_name, type, O_BINARY | O_SYNC | O_RDWR, arch_file_handle) != CT_SUCCESS) {
        return CT_ERROR;
    }
    status_t status = strcat_s(tmp_arch_file_name, CT_FILE_NAME_BUFFER_SIZE, "_tmp");
    knl_securec_check(status);
    if (cm_open_device(tmp_arch_file_name, type, O_CREAT | O_BINARY | O_SYNC | O_RDWR,
                       tmp_arch_file_handle) != CT_SUCCESS) {
        cm_close_device(type, arch_file_handle);
        return CT_ERROR;
    }
    if (cm_aligned_malloc(CT_MAX_BATCH_SIZE, "bak log batch buffer", read_buf) != CT_SUCCESS) {
        cm_close_device(type, arch_file_handle);
        cm_close_device(type, tmp_arch_file_handle);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void rst_release_modify_resource(device_type_t type, int32 *arch_handle,
                                 char *tmp_arch_name, int32 *tmp_arch_handle, aligned_buf_t *read_buf)
{
    cm_close_device(type, arch_handle);
    cm_close_device(type, tmp_arch_handle);
    cm_aligned_free(read_buf);
    if (cm_exist_device(type, tmp_arch_name)) {
        (void)cm_remove_device(type, tmp_arch_name);
    }
}
bool32 bak_convert_archfile_name(char *arch_file_name, local_arch_file_info_t *file_info,
                                 uint32 inst_id, uint32 rst_id, bool32 is_dbstor)
{
    char *file_name = arch_file_name;
    char *pos;
    uint32 name_length = strlen(file_name);
    if (name_length <= g_arch_suffix_length ||
        strcmp(file_name + name_length - g_arch_suffix_length, g_arch_suffix_name) != 0) {
        return CT_FALSE;
    }
    while (*file_name != '_' && *file_name != '\0') {
        file_name++;
    }
    file_name++;
    if (arch_convert_file_name_id_rst(file_name, &pos,
                                      &file_info->local_node_id, &file_info->local_rst_id) != CT_SUCCESS) {
        return CT_FALSE;
    }
    CT_LOG_DEBUG_INF("[lBACKUP] name %s, rst_id %u-%u, node_id %u-%u.", file_name, rst_id, file_info->local_rst_id,
                     inst_id, file_info->local_node_id);
    if (inst_id != file_info->local_node_id || rst_id != file_info->local_rst_id) {
        return CT_FALSE;
    }
    file_name = pos + 1;
    if (is_dbstor) {
        if (arch_convert_file_name(file_name, &file_info->local_asn,
                                   &file_info->local_start_lsn, &file_info->local_end_lsn) != CT_SUCCESS) {
            return CT_FALSE;
        }
    } else {
        if (arch_convert_file_name_asn(file_name, &file_info->local_asn) != CT_SUCCESS) {
            return CT_FALSE;
        }
    }
    return CT_TRUE;
}

status_t bak_check_archfile_dbid(knl_session_t *session, const char *arch_path, char *arch_name, bool32 *dbid_equal)
{
    char tmp_buf[CT_FILE_NAME_BUFFER_SIZE] = {0};
    uint32 arch_file_dbid = 0;
    status_t ret = memset_s(tmp_buf, CT_FILE_NAME_BUFFER_SIZE, 0, CT_FILE_NAME_BUFFER_SIZE);
    knl_securec_check(ret);
    bak_set_file_name(tmp_buf, arch_path, arch_name);
    if (get_dbid_from_arch_logfile(session, &arch_file_dbid, tmp_buf) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] get dbid from arch file %s failed.", tmp_buf);
        return CT_ERROR;
    }
    if (arch_file_dbid == session->kernel->db.ctrl.core.dbid) {
        *dbid_equal = CT_TRUE;
    } else {
        CT_LOG_RUN_WAR("[BACKUP] the dbid %u of archive logfile %s is different from the bak dbid %u",
            arch_file_dbid, tmp_buf, session->kernel->db.ctrl.core.dbid);
        *dbid_equal = CT_FALSE;
    }
    return CT_SUCCESS;
}

void bak_set_file_name(char *buf, const char *arch_path, const char *file_name)
{
    int32 print_num;
    print_num = sprintf_s(buf, CT_FILE_NAME_BUFFER_SIZE, "%s/%s", arch_path, file_name);
    knl_securec_check_ss(print_num);
    return;
}

void bak_set_arch_name_format(local_arch_file_info_t file_info, char *cur_pos, size_t offset, int32 *print_num,
                              char *buf, uint32 buf_size)
{
    switch (*cur_pos) {
        case 's':
        case 'S': {
            *print_num = snprintf_s(buf + offset, buf_size - offset, CT_MAX_UINT32_PREC, "%u", file_info.local_asn);
            knl_securec_check_ss(*print_num);
            break;
        }
        case 't':
        case 'T': {
            *print_num = snprintf_s(buf + offset, buf_size - offset, CT_MAX_UINT32_PREC, "%u", file_info.local_node_id);
            knl_securec_check_ss(*print_num);
            break;
        }
        case 'r':
        case 'R': {
            *print_num = snprintf_s(buf + offset, buf_size - offset, CT_MAX_UINT32_PREC, "%u", file_info.local_rst_id);
            knl_securec_check_ss(*print_num);
            break;
        }
        case 'd':
        case 'D': {
            *print_num = snprintf_s(buf + offset, buf_size - offset, CT_MAX_UINT64_PREC, "%llx",
                                    file_info.local_start_lsn);
            knl_securec_check_ss(*print_num);
            break;
        }
        case 'e':
        case 'E': {
            *print_num = snprintf_s(buf + offset, buf_size - offset, CT_MAX_UINT64_PREC, "%llx",
                                    file_info.local_end_lsn);
            knl_securec_check_ss(*print_num);
            break;
        }
        default: {
            return;
        }
    }
    return;
}

void bak_set_tmp_archfile_name(knl_session_t *session, char *tmp_file_name)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    status_t status = strcpy_s(tmp_file_name, CT_FILE_NAME_BUFFER_SIZE, bak->record.path);
    knl_securec_check(status);
    status = strcat_s(tmp_file_name, CT_FILE_NAME_BUFFER_SIZE, "/arch_tmp_file");
    knl_securec_check(status);
}

status_t bak_create_tmp_archfile(knl_session_t *session, char *tmp_file_name, device_type_t arch_file_type,
                                 int32 *tmp_file_handle)
{
    bak_set_tmp_archfile_name(session, tmp_file_name);
    bool32 exist_tmp_file = cm_exist_device(arch_file_type, tmp_file_name);
    if (exist_tmp_file) {
        if (cm_remove_device(arch_file_type, tmp_file_name) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    if (cm_create_device(tmp_file_name, arch_file_type, knl_io_flag(session), tmp_file_handle) != CT_SUCCESS) {
        return CT_ERROR;
    }
 
    return CT_SUCCESS;
}

void bak_set_archfile_name_with_lsn(knl_session_t *session,
                                    char *buf, char *arch_path, uint32 buf_size, local_arch_file_info_t file_info)
{
    char *current_pos = session->kernel->arch_ctx.arch_format;
    char *last_pos = current_pos;
    size_t dest_len;
    size_t remain_buf_size = buf_size;
    size_t offset = 0;
    errno_t ret;

    dest_len = strlen(arch_path);
    ret = strncpy_s(buf, remain_buf_size, arch_path, dest_len);
    knl_securec_check(ret);
    offset += strlen(arch_path);
    buf[offset] = '/';
    offset++;

    while (*current_pos != '\0') {
        int32 print_num = 0;
        while (*current_pos != '%' && *current_pos != '\0') {
            current_pos++;
        }
        if (*current_pos == '\0' && current_pos == last_pos) {
            break;
        }
        remain_buf_size = buf_size - offset;
        dest_len = current_pos - last_pos;
        ret = strncpy_s(buf + offset, remain_buf_size, last_pos, dest_len);
        knl_securec_check(ret);
        offset += (current_pos - last_pos);
        last_pos = current_pos;
        if (*current_pos == '\0') {
            break;
        }
        current_pos++;
        bak_set_arch_name_format(file_info, current_pos, offset, &print_num, buf, buf_size);
        offset += print_num;
        current_pos++;
        last_pos = current_pos;
    }
}