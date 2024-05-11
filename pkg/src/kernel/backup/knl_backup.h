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
 * knl_backup.h
 *
 *
 * IDENTIFICATION
 * src/kernel/backup/knl_backup.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef KNL_BACKUP_H
#define KNL_BACKUP_H

#include "bak_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_bak_columns {
    BAK_COL_RECID = 0,
    BAK_COL_TYPE = 1,
    BAK_COL_STAGE = 2,
    BAK_COL_STATUS = 3,
    BAK_COL_LEVEL = 4,
    BAK_COL_TAG = 5,
    BAK_COL_SCN = 6,
    BAK_COL_LSN = 7,
    BAK_COL_DEVICE_TYPE = 8,
    BAK_COL_BASE_TAG = 9,
    BAK_COL_DIR = 10,
    BAK_COL_RESETLOGS = 11,
    BAK_COL_POLICY = 12,
    BAK_COL_RCY_ASN = 13,
    BAK_COL_RCY_OFFSET = 14,
    BAK_COL_RCY_LFN = 15,
    BAK_COL_LRP_ASN = 16,
    BAK_COL_LRP_OFFSET = 17,
    BAK_COL_LRP_LFN = 18,
    BAK_COL_START_TIME = 19,
    BAK_COL_COMPLETION_TIME = 20,
    BAK_COL_MAX_BUFFER_SIZE = 21,
    BAK_COL_DB_VERSION = 22,
    BAK_COL_RCY_LSN = 23,
} bak_columns_t;

#define BAK_DEFAULT_SECTION_THRESHOLD (SIZE_M(128))
#define BAK_MAX_RETRY_TIMES_FOR_REFORM 1
#define WAIT_REFORM_START_TIMEOUT (15000)   // ms

status_t bak_backup_database(knl_session_t *session, knl_backup_t *param);
status_t bak_get_last_rcy_point(knl_session_t *session, log_point_t *point);
void bak_print_log_point(knl_session_t *session, bak_context_t *ctx);
status_t bak_backup_proc(knl_session_t *session);
status_t bak_precheck(knl_session_t *session);
status_t bak_paral_create_bakfile(knl_session_t *session, uint32 file_index, bak_assignment_t *assign_ctrl);
status_t bak_local_write(bak_local_t *local, const void *buf, int32 size, bak_t *bak, int64 offset);
status_t bak_read_datafile(knl_session_t *session, bak_process_t *bak_proc, bool32 to_disk);
status_t bak_read_logfile(knl_session_t *session, bak_context_t *ctx, bak_process_t *bak_proc,
    uint32 block_size, bool32 to_disk, bool32 *arch_compressed);
void bak_read_prepare(knl_session_t *session, bak_process_t *process, datafile_t *datafile, uint32 sec_id);
void bak_reset_fileinfo(bak_assignment_t *assign_ctrl);
void bak_update_progress(bak_t *bak, uint64 size);
void bak_close(knl_session_t *session);
bool32 bak_logfile_not_backed(knl_session_t *session, uint32 asn);
status_t bak_load_tablespaces(knl_session_t *session);
void bak_unload_tablespace(knl_session_t *session);
void bak_record_new_file(bak_t *bak, bak_file_type_t file_type, uint32 file_id, uint32 sec_id, uint32 rst_id,
                         bool32 is_paral_log_proc, uint64 start_lsn, uint64 end_lsn);
status_t bak_read_datafile_pages(knl_session_t *session, bak_process_t *bak_proc);
status_t bak_load_log_batch(knl_session_t *session, log_point_t *point, uint32 *data_size,
    aligned_buf_t *buf, uint32 *block_size);
status_t bak_wait_write(bak_t *bak);
status_t dtc_log_prepare_pitr(knl_session_t *se);
status_t bak_init_reform_check(bak_t *bak);
void bak_free_check_reform(knl_session_t *session);
status_t bak_wait_write_ctrl(bak_t *bak, uint32 page_count);
bool8 bak_backup_database_need_retry(knl_session_t *session);
status_t bak_delete_backupset_for_retry(knl_backup_t *param);
status_t bak_wait_reform_finish(void);
void bak_calc_log_head_checksum(knl_session_t *session, bak_assignment_t *assign_ctrl, log_file_head_t *head);
status_t bak_read_data(bak_process_t *bak_proc, bak_ctrl_t *ctrl, log_file_head_t *buf, int32 size);
status_t bak_verify_log_head_checksum(knl_session_t *session, bak_process_t *bak_proc, bak_ctrl_t *ctrl,
    log_file_head_t *head, int32 head_len);
status_t bak_end_check(knl_session_t *session);
status_t bak_write_proc(knl_session_t *session, bak_context_t *ctx);
status_t bak_record(knl_session_t *session);
status_t bak_start(knl_session_t *session);
status_t bak_write(bak_t *bak, bak_process_t *proc, char *buf, int32 size);
status_t bak_fsync_and_close(bak_t *bak, device_type_t type, int32 *handle);
void bak_fetch_read_range(knl_session_t *session, bak_process_t *bak_proc);
status_t bak_read_logfile_with_proc(bak_process_t *bak_proc, bak_ctrl_t *ctrl, log_file_head_t *buf, int32 size);
status_t bak_write_logfile_with_proc(bak_context_t *ctx, bak_process_t *bak_proc, char *buf, int32 size,
    bool32 arch_compressed);
status_t bak_get_datafile_size(knl_session_t *session, datafile_ctrl_t *ctrl, datafile_t *df,
    uint64_t *datafile_size);
char *bak_get_ctrl_datafile_item(knl_session_t *session, ctrl_page_t *pages, uint32 id);
status_t bak_update_datafile_size(knl_session_t *session, bak_t *bak);
status_t bak_check_increment_type(knl_session_t *session, knl_backup_t *param);
void bak_record_init(bak_t *bak, knl_backup_t *param);
void bak_update_rcy_point(knl_session_t *session);
void bak_update_lrp_point(knl_session_t *session);
bool32 bak_point_need_archfile(knl_session_t *session, bak_t *bak, uint32 node_id);
void bak_filter_pages(knl_session_t *session, bak_process_t *ctx, bak_buf_data_t *data_buf);
status_t bak_write_datafile(bak_process_t *bak_proc, bak_context_t *bak_ctx, bool32 to_disk);
void bak_write_datafile_wait(bak_process_t *bak_proc, bak_context_t *bak_ctx, bool32 to_disk);
status_t bak_init_paral_proc_resource(bak_process_t *proc, bak_context_t *ctx, uint32 i);
status_t bak_deal_datafile_pages_read(knl_session_t *session, bak_process_t *bak_proc, bool32 to_disk);
status_t bak_write_to_write_buf(bak_context_t *ctx, const void *buf, int32 size);
void bak_free_reform_veiw_buffer(bak_t *bak);
status_t bak_read_end_check(knl_session_t *session, bak_process_t *bak_proc);
status_t bak_set_increment_unblock(knl_session_t *session);
status_t bak_check_increment_unblock(knl_session_t *session, bool32 *unblock);

#ifdef __cplusplus
}
#endif

#endif
