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
 * dtc_backup.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_backup.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef DTC_BACKUP_H
#define DTC_BACKUP_H

#include "cm_types.h"
#include "mes_func.h"
#include "dtc_database.h"
#include "srv_instance.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BAK_WAIT_TIMEOUT    (5000)  //ms
#define ARCHIVE_FILENAME "archive.conf"

extern instance_t *g_instance;

typedef struct st_msg_block_file {
    uint32 file_id;
    uint32 sec_id;
    uint64 start;
    uint64 end;
} msg_block_file_t;

typedef struct st_msg_block_file_bcast {
    mes_message_head_t head;
    msg_block_file_t block;
} msg_block_file_bcast_t;

typedef struct st_msg_pre_bak_check {
    bool32 is_archive;
    bool32 is_switching;
} msg_pre_bak_check_t;

typedef struct st_msg_log_ctrl {
    char name[GS_FILE_NAME_BUFFER_SIZE];
    uint32 file_id;
    uint64 file_size;
    device_type_t type;
    uint32 block_size;
    bool32 is_archivelog;
    status_t status;
    uint64 start_lsn;
    uint64 end_lsn;
} msg_log_ctrl_t;

typedef struct st_bak_log_file_info {
    uint32 asn;
    uint32 backup_type;
} bak_log_file_info_t;

uint32 dtc_get_mes_sent_success_cnt(uint64 success_inst_left);
void dtc_bak_file_blocking(knl_session_t *session, uint32 file_id, uint32 sec_id, uint64 start, uint64 end, uint64 *success_inst);
void dtc_bak_file_unblocking(knl_session_t *session, uint32 file_id, uint32 sec_id);
EXTER_ATTACK void bak_process_block_file(void *sess, mes_message_t *msg);
EXTER_ATTACK void bak_process_unblock_file(void *sess, mes_message_t *msg);
status_t dtc_bak_read_logfiles(knl_session_t *session, uint32 inst_id);
status_t dtc_bak_set_log_ctrl(knl_session_t *session, bak_process_t *process, uint32 asn, uint32 *block_size,
                              uint32 target_id);
EXTER_ATTACK void dtc_bak_process_set_log_ctrl(void *sess, mes_message_t *receive_msg);
status_t dtc_bak_precheck(knl_session_t *session, uint32 target_id, msg_pre_bak_check_t *pre_check);
EXTER_ATTACK void bak_process_precheck(void *sess, mes_message_t *receive_msg);
status_t dtc_ctbak_unlatch_logfile(knl_session_t *session, bak_process_t *process, uint32 target_id);
EXTER_ATTACK void dtc_process_unlatch_logfile(void *sess, mes_message_t *receive_msg);
status_t dtc_bak_set_lsn(knl_session_t *session, bak_t *bak);
void dtc_process_set_lsn_for_dbstor(knl_session_t *session, mes_message_t *receive_msg);
void dtc_process_set_lsn_for_file(knl_session_t *session, mes_message_t *receive_msg);
EXTER_ATTACK void dtc_process_set_lsn(void *sess, mes_message_t *receive_msg);
status_t dtc_bak_set_log_point(knl_session_t *session, bak_ctrlinfo_t *ctrlinfo,
                               bool32 update, bool32 force_switch);
status_t dtc_bak_get_ctrl(knl_session_t *session, uint32 target_id, dtc_node_ctrl_t *node_ctrl);
status_t dtc_bak_read_all_logfiles(knl_session_t *session);
status_t dtc_bak_get_node_ctrl_by_node_id(knl_session_t *session, uint32 node_id);
status_t dtc_bak_get_ctrl_all(knl_session_t *session);
EXTER_ATTACK void dtc_process_bak_get_ctrl(void *sess, mes_message_t *receive_msg);
void dtc_rst_arch_set_arch_start_and_end(knl_session_t *session);
void dtc_rst_db_init_logfile_ctrl(knl_session_t *session, uint32 *offset);
status_t dtc_rst_arch_try_record_archinfo(knl_session_t *session, uint32 dest_pos, const char *file_name,
                                          log_file_head_t *head, uint32 inst_id);
status_t dtc_rst_amend_files(knl_session_t *session, int32 file_index);
status_t dtc_rst_create_logfiles(knl_session_t *session);
status_t dtc_bak_set_logfile_ctrl(knl_session_t *session, uint32 curr_file_index, log_file_head_t *head,
                                  bak_ctrl_t *ctrl, bool32 *ignore_data);
void dtc_rst_update_process_data_size(knl_session_t *session, bak_context_t *ctx);
status_t dtc_bak_running(knl_session_t *session, uint32 target_id, bool32 *running);
EXTER_ATTACK void dtc_process_running(void *sess, mes_message_t *receive_msg);
void dtc_set_record_lsn(bak_record_t *record);
uint64 dtc_get_min_lsn_lrp_point(knl_session_t *session, bak_record_t *record);
status_t dtc_get_record_lsn_by_nodeid(bak_record_t *record, uint32_t node_id, uint64_t *lsn);
status_t dtc_get_record_all_lsn(bak_record_t *record, bak_record_lsn_info *lsninfo, uint32_t node_number);
status_t dtc_rst_amend_all_arch_file_dbstor(knl_session_t *session);
status_t dtc_rst_regist_archive(knl_session_t *session, uint32 *last_archived_asn, uint32 rst_id, int32 inst_id);
status_t dtc_rst_arch_regist_archive(knl_session_t *session, const char *name, uint32 inst_id);
status_t dtc_rst_regist_archive_by_dbstor(knl_session_t *session, uint32 *last_archived_asn, uint32 rst_id,
                                          uint64 start_lsn, uint64 end_lsn, uint32 inst_id);
status_t dtc_rst_regist_archive_asn_by_dbstor(knl_session_t *session, uint32 *last_archied_asn,
                                              uint32 rst_id, uint32 inst_id);
status_t get_dbid_from_arch_logfile(knl_session_t *session, uint32 *dbid, const char *name);
status_t dtc_bak_force_arch(knl_session_t *session, bak_ctrlinfo_t *ctrlinfo, uint64 lsn);
uint64 dtc_bak_get_max_lrp_lsn(bak_ctrlinfo_t *ctrlinfo);
status_t dtc_bak_force_arch_local(knl_session_t *session, uint64 lsn);
status_t dtc_bak_force_arch_by_instid(knl_session_t *session, uint64 lsn, uint32 inst_id);
status_t dtc_bak_handle_cluster_arch(knl_session_t *session);
status_t dtc_bak_handle_log_switch(knl_session_t *session);
void dtc_bak_copy_ctrl_buf_2_send(knl_session_t *session);
void dtc_bak_scn_broadcast(knl_session_t *session);
void dtc_rst_db_init_logfile_ctrl_by_dbstor(knl_session_t *session, uint32 *offset);
bool8 knl_backup_database_can_retry(knl_session_t *session, knl_backup_t *param);
#ifdef __cplusplus
}
#endif

#endif
