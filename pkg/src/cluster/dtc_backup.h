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

#include <dirent.h>
#include "cm_types.h"
#include "mes_func.h"
#include "dtc_database.h"
#include "dtc_log.h"
#include "srv_instance.h"
#include "bak_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BAK_WAIT_TIMEOUT    (5000)  //ms
#define ARCHIVE_FILENAME "archive.conf"
#define BAK_ARCH_FILE_NAME_MAX_LENGTH 256
#define BAK_ARCH_FILE_MAX_NUM 50

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
    char name[CT_FILE_NAME_BUFFER_SIZE];
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

typedef struct st_arch_file_info {
    uint32 asn;
    uint64 start_lsn;
    uint64 end_lsn;
    uint64 offset;
    log_file_head_t arch_file_head;
    uint32 inst_id;
    log_file_t logfile;
    char tmp_file_name[CT_FILE_NAME_BUFFER_SIZE];
    int32 tmp_file_handle;
    device_type_t arch_file_type;
    aligned_buf_t read_buf;
} arch_file_info_t;
 
typedef struct st_bak_arch_files {
    char arch_file_name[BAK_ARCH_FILE_NAME_MAX_LENGTH];
    uint32 asn;
    uint32 block_size;
    uint64 start_lsn;
    uint64 end_lsn;
    uint64 file_size;
} bak_arch_files_t;

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
status_t dtc_bak_unlatch_logfile(knl_session_t *session, bak_process_t *process, uint32 target_id);
EXTER_ATTACK void dtc_process_unlatch_logfile(void *sess, mes_message_t *receive_msg);
status_t dtc_bak_set_lsn(knl_session_t *session, bak_t *bak);
void dtc_process_set_lsn_for_dbstor(knl_session_t *session, mes_message_t *receive_msg);
void dtc_process_set_lsn_for_file(knl_session_t *session, mes_message_t *receive_msg);
EXTER_ATTACK void dtc_process_set_lsn(void *sess, mes_message_t *receive_msg);
status_t dtc_bak_set_log_point(knl_session_t *session, bak_ctrlinfo_t *ctrlinfo,
                               bool32 update, bool32 force_switch);
status_t dtc_bak_get_node_ctrl_by_instance(knl_session_t *session, uint32 target_id, dtc_node_ctrl_t *node_ctrl);
status_t dtc_bak_read_all_logfiles(knl_session_t *session);
status_t dtc_bak_get_node_ctrl_by_device(knl_session_t *session, uint32 node_id);
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
uint64 dtc_get_min_lsn_lrp_point(bak_record_t *record);
status_t dtc_get_record_lsn_by_nodeid(bak_record_t *record, uint32_t node_id, uint64_t *lsn);
status_t dtc_get_record_all_lsn(bak_record_t *record, bak_record_lsn_info *lsninfo, uint32_t node_number);
status_t dtc_rst_amend_all_arch_file_dbstor(knl_session_t *session);
status_t dtc_rst_regist_archive(knl_session_t *session, uint32 *last_archived_asn, uint32 rst_id, int32 inst_id);
status_t dtc_rst_arch_regist_archive(knl_session_t *session, const char *name, uint32 inst_id);
status_t dtc_rst_regist_archive_by_dbstor(knl_session_t *session, uint32 *last_archived_asn, uint32 rst_id,
                                          uint64 start_lsn, uint64 end_lsn, uint32 inst_id);
status_t dtc_rst_regist_archive_asn_by_dbstor(knl_session_t *session, uint32 *last_archvied_asn,
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
status_t dtc_bak_get_node_ctrl(knl_session_t *session, uint32 node_id);
status_t dtc_bak_set_lrp_point(knl_session_t *session);
void dtc_bak_copy_ctrl_page_2_buf(knl_session_t *session, dtc_node_ctrl_t *node_ctrl, uint32 inst_id);
status_t dtc_bak_set_node_lsn(knl_session_t *session, bak_ctrlinfo_t *ctrlinfo, uint64 *curr_lsn, uint32 inst_id);
status_t dtc_bak_log_ckpt_trigger_by_instid(knl_session_t *session, bak_ctrlinfo_t *ctrlinfo, uint32 inst_id,
                                            bool32 update, bool32 force_switch);
status_t dtc_bak_log_ckpt_trigger_local(knl_session_t *session, bak_ctrlinfo_t *ctrlinfo, uint32 inst_id,
                                        bool32 update, bool32 force_switch);
status_t dtc_bak_read_logfiles_dbstor(knl_session_t *session, uint32 inst_id);
status_t dtc_bak_set_log_ctrl_dbstor(knl_session_t *session, bak_process_t *process,
                                     uint32 *block_size, uint32 target_id, bak_arch_files_t *arch_file);
status_t dtc_bak_get_arch_start_and_end_point(knl_session_t *session, uint32 inst_id, bak_arch_files_t *arch_file_buf,
                                              log_start_end_asn_t *local_arch_file_asn, log_start_end_asn_t *target_asn);
void bak_set_archfile_info(knl_session_t *session, log_start_end_info_t arch_info,
                           local_arch_file_info_t file_info, bak_arch_files_t *arch_file_buf, char *file_name);
status_t bak_open_logfile_dbstor(knl_session_t *session, log_file_t *logfile, uint32 inst_id);
status_t bak_flush_archfile_head(knl_session_t *session, arch_file_info_t *file_info);
status_t bak_prepare_read_logfile_dbstor(knl_session_t *session, log_file_t *logfile, uint64 start_lsn, uint32 inst_id,
                                         uint32 *redo_log_filesize);
status_t bak_get_log_dbstor(knl_session_t *session, log_start_end_lsn_t *lsn,
                            arch_file_info_t *file_info, uint64 redo_log_file_size);
status_t bak_generate_archfile_dbstor(knl_session_t *session, arch_file_info_t *file_info);
status_t bak_get_logfile_dbstor(knl_session_t *session, arch_file_info_t *file_info, log_start_end_lsn_t lsn);
status_t bak_get_arch_start_and_end_point_dbstor(knl_session_t *session, uint32 inst_id,
                                                 log_start_end_asn_t *asn, bak_arch_files_t *arch_file_buf);
status_t bak_get_logfile_by_lsn_dbstor(knl_session_t *session, bak_arch_files_t *arch_file_buf,
                                       log_start_end_asn_t asn, uint32 inst_id);
status_t bak_get_arch_asn(knl_session_t *session, log_start_end_info_t arch_info, uint32 inst_id,
                          bak_arch_files_t *arch_file_buf);
void bak_free_res_for_get_logfile(arch_file_info_t *file_info);
status_t bak_get_arch_start_and_end_point(knl_session_t *session, uint32 *start_asn, uint32 *end_asn);
bak_arch_files_t *bak_get_arch_by_index(bak_arch_files_t *arch_buf, uint32 index, log_start_end_asn_t arch_asn);
bool32 dtc_bak_read_log_check_param(knl_session_t *session, uint32 *curr_asn, uint32 inst_id);
status_t dtc_bak_read_logfile_data(knl_session_t *session, bak_process_t *proc, uint32 block_size, uint32 inst_id);
status_t dtc_bak_fetch_last_log(knl_session_t *session, bak_t *bak, uint32 *last_asn, uint32 inst_id);

status_t dtc_rst_regist_archive_by_dbstor_skip(knl_session_t *session, uint32 *last_archived_asn, uint32 rst_id,
                                               uint64 start_lsn, uint32 inst_id);
status_t rst_remove_duplicate_batch_archfile(device_type_t type, uint32 arch_handle, uint32 tmp_arch_handle,
                                             aligned_buf_t read_buf, log_file_head_t *head, uint64 end_lsn);
status_t rst_generate_deduplicate_archfile(knl_session_t *session, log_file_head_t *head,
                                           char *tmp_arch_name, int32 tmp_arch_handle, arch_info_t first_arch_info);
status_t rst_modify_archfile_content(knl_session_t *session, log_start_end_lsn_t *local_lsn,
                                     arch_info_t first_arch_info);
status_t rst_modify_archfile_name(knl_session_t *session, arch_info_t first_arch_info);
status_t rst_reset_first_archfile(knl_session_t *session, log_start_end_lsn_t *local_lsn, arch_info_t first_arch_info);
status_t rst_find_first_archfile_with_lsn(knl_session_t *session, arch_info_t first_arch_info);
status_t rst_rename_archfile_by_asn(knl_session_t *session, arch_info_t arch_info, char *arch_name, bool32 *dbid_equal);
status_t rst_find_archfile_name_with_lsn(knl_session_t *session, uint64 lsn, arch_info_t arch_info, uint64 *out_lsn);
status_t rst_prepare_modify_archfile(char *arch_file_name, int32 *arch_file_handle,
                                     char *tmp_arch_file_name, int32 *tmp_arch_file_handle, aligned_buf_t *read_buf);
void rst_release_modify_resource(device_type_t type, int32 *arch_handle,
                                 char *tmp_arch_name, int32 *tmp_arch_handle, aligned_buf_t *read_buf);
bool32 bak_convert_archfile_name(char *arch_file_name, local_arch_file_info_t *file_info,
                                 uint32 inst_id, uint32 rst_id, bool32 is_dbstor);
status_t bak_check_archfile_dbid(knl_session_t *session, const char *arch_path, char *arch_name, bool32 *dbid_equal);
void bak_set_file_name(char *buf, const char *arch_path, const char *file_name);
void bak_set_arch_name_format(local_arch_file_info_t file_info, char *cur_pos, size_t offset, int32 *print_num,
                              char *buf, uint32 buf_size);
void bak_set_tmp_archfile_name(knl_session_t *session, char *tmp_file_name);
status_t bak_create_tmp_archfile(knl_session_t *session, char *tmp_file_name, device_type_t arch_file_type,
                                 int32 *tmp_file_handle);
void bak_set_archfile_name_with_lsn(knl_session_t *session,
                                    char *buf, char *arch_path, uint32 buf_size, local_arch_file_info_t file_info);
EXTER_ATTACK void dtc_bak_init_log_ctrl(msg_log_ctrl_t *log_ctrl, arch_ctrl_t *arch_ctrl);
EXTER_ATTACK uint32 dtc_bak_get_rst_id(uint32 data_type, uint32 asn, reset_log_t *rst_log);
status_t bak_cpy_file_name(log_file_t *file, msg_log_ctrl_t *log_ctrl);
status_t bak_check_log_file(bak_log_file_info_t *log_file);
void bak_update_ctrlinfo_lsn(knl_session_t *session);
status_t dtc_bak_force_arch_local_file(knl_session_t *session);
status_t bak_set_archfile_info_file(log_start_end_info_t arch_info, local_arch_file_info_t file_info,
                                    bak_arch_files_t *arch_file_buf, char *file_name, log_file_head_t *head);
status_t dtc_bak_get_logfile_by_asn_file(knl_session_t *session, bak_arch_files_t *arch_file_buf,
                                         log_start_end_asn_t asn, uint32 inst_id, log_start_end_asn_t *target_asn);
status_t bak_get_logfile_file(knl_session_t *session, knl_session_t *session_bak, arch_file_info_t *file_info,
                              log_file_t *logfile, knl_compress_t *compress_ctx);
status_t dtc_bak_get_arch_ctrl(knl_session_t *session, bak_process_t *process, uint32 asn, uint32 *block_size, bak_arch_files_t *arch_file);
status_t bak_get_arch_asn_file(knl_session_t *session, log_start_end_info_t arch_info, uint32 inst_id,
                               bak_arch_files_t *arch_file_buf);
status_t dtc_bak_reset_logfile(knl_session_t *session, uint32 asn, uint32 file_id, uint32 inst_id);

#ifdef __cplusplus
}
#endif

#endif
