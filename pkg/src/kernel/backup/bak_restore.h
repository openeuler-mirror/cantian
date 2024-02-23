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
 * bak_restore.h
 *
 *
 * IDENTIFICATION
 * src/kernel/backup/bak_restore.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __BAK_RESTORE_H__
#define __BAK_RESTORE_H__

#include "knl_database.h"
#include "bak_common.h"
#include "knl_backup.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_rst_assist {
    int64 file_offset;
    uint32 page_count;
    page_id_t page_id;
    datafile_t *datafile;
} rst_assist_t;

status_t rst_check_backupset_path(knl_restore_t *param);
void rst_close_ctrl_file(ctrlfile_set_t *ctrlfiles);
void rst_close_log_files(knl_session_t *session);
status_t rst_read_data(bak_context_t *ctx, void *buf, int32 buf_size, int32 *read_size, bool32 *end,
                       uint64 file_offset);
status_t rst_wait_ctrlfile_ready(bak_t *bak);
status_t rst_wait_agent_process(bak_t *bak);
void rst_wait_write_end(bak_t *ctrl);
status_t rst_set_head(knl_session_t *session, bak_head_t *head, bool32 set_config);
status_t rst_read_file(knl_session_t *session, uint32 file_index);
status_t rst_restore_config_param(knl_session_t *session);
status_t rst_start_write_thread(bak_process_t *common_proc);
status_t rst_set_logfile_ctrl(knl_session_t *session, uint32 curr_file_index, log_file_head_t *head,
                              bak_ctrl_t *ctrl, bool32 *ignore_data);
char *rst_fetch_filename(bak_t *bak);
status_t rst_fill_file_gap(device_type_t type, int32 handle, int64 start, int64 end, const char *buf, uint32 buf_size);
status_t rst_restore_datafile(knl_session_t *session, bak_t *bak, bak_process_t *ctx, char *buf, const char *filename);
status_t rst_write_data(knl_session_t *session, bak_ctrl_t *ctrl, const char *buf, int32 size);
status_t rst_read_check_size(int32 read_size, int32 expect_size, const char* file_name);
status_t rst_delete_track_file(knl_session_t *session, bak_t *bak, bool32 allow_not_exist);
status_t rst_stream_read_file(knl_session_t *session);
status_t rst_extend_database_file(knl_session_t *session, bak_context_t *ctx, const char *name, device_type_t type,
                                  int64 size);
status_t arch_find_archive_log_name(knl_session_t *session, arch_file_name_info_t *file_name_info);
status_t dtc_log_prepare_for_pitr(knl_session_t *se);
status_t arch_try_regist_archive_by_dbstor(knl_session_t *session, uint32 *asn, uint32 rst_id,
                                           uint64 start_lsn, uint64 end_lsn, uint32 inst_id);
status_t log_prepare_for_pitr_dbstor(knl_session_t *se);
uint32 rst_get_db_main_version_len(char *db_version);
void rst_update_process_data_size(knl_session_t *session, bak_context_t *ctx);
status_t rst_create_datafiles(knl_session_t *session, bak_process_t *ctx);
status_t rst_create_logfiles(knl_session_t *session);
status_t rst_db_version_check(knl_session_t *session, bak_t *bak, bak_head_t *head);
status_t rst_process_existed_datafile(bak_process_t *ctx, datafile_ctrl_t *df, uint32 i);
status_t rst_find_duplicative_archfile(knl_session_t *session, bak_file_t *file, bool32 *found_duplicate);
bool32 rst_skip_for_duplicative_archfile(knl_session_t *session, bak_file_t *cur_file, bak_file_t *next_file);
status_t rst_init_paral_proc_resource(bak_process_t *common_proc, bak_process_t *proc, bak_context_t *ctx, uint32 i);

#ifdef __cplusplus
}
#endif

#endif
