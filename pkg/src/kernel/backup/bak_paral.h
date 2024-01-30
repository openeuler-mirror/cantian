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
 * bak_paral.h
 *
 *
 * IDENTIFICATION
 * src/kernel/backup/bak_paral.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __BAK_PARAL_H__
#define __BAK_PARAL_H__

#include "bak_common.h"

#ifdef __cplusplus
extern "C" {
#endif

void bak_unlatch_logfile_if_necessary(knl_session_t *session, bak_process_t *process);
status_t bak_paral_backup_datafile(knl_session_t *session, bak_assignment_t *assign_ctrl,
    datafile_t *datafile, uint64 data_size);
void bak_assign_stream_backup_task(knl_session_t *session, device_type_t device_type, const char *file_name,
    bool32 arch_compressed, uint32 file_id, uint64 hwm_size, uint32 hwm_start);
status_t bak_write_to_local_disk(bak_context_t *ctx, bak_process_t *bak_proc, char *buf, int32 size,
    bool32 stream_end, bool32 arch_compressed);
status_t bak_task_prepare(knl_session_t *session, bak_assignment_t *assign_ctrl, uint32 *bak_id);
status_t bak_assign_backup_task(knl_session_t *session, bak_process_t *proc,
    uint64 datafile_size, bool32 paral_log_backup);
status_t bak_assign_restore_task(knl_session_t *session, bak_process_t *proc);
status_t rst_paral_open_bakfile(knl_session_t *session, bak_file_type_t file_type, uint32 file_index,
    uint32 file_id, uint32 sec_id);
uint32 bak_datafile_count_sec(knl_session_t *session, uint64 file_size_input, uint32 hwm_start,
    uint64 *sec_size, bool32 *diveded);
status_t bak_get_section_threshold(knl_session_t *session);
void bak_paral_task_proc(thread_t *thread);
void bak_paral_backup_task(knl_session_t *session, bak_process_t *proc);
void bak_paral_restore_task(knl_session_t *session, bak_process_t *proc);
void bak_paral_extend_task(knl_session_t *session, bak_process_t *proc);
status_t bak_paral_backup(knl_session_t *session, bak_process_t *proc);
void bak_paral_task_write_proc(thread_t *thread);
void rst_paral_task_write_proc(thread_t *thread);
status_t rst_paral_write_data(bak_t *bak, bak_process_t *proc);
status_t rst_write_remain_buff(knl_session_t *session, bak_t *bak, bak_process_t *proc, bool32 arch_compress);
status_t rst_paral_restore_end(bak_process_t *proc, bak_t *bak, uint64 file_offset, bool32 ignore_logfile);
status_t rst_paral_restore_file(knl_session_t *session, bak_process_t *proc, uint32 blk_size,
    bool32 ignore_logfile, bool32 arch_compress);
status_t bak_deal_datafile_pages_write(knl_session_t *session, bak_process_t *bak_proc);
void bak_paral_task_write_proc(thread_t *thread);
void rst_paral_task_write_proc(thread_t *thread);
bool32 rst_file_need_decompress(compress_algo_e compress, bak_file_type_t type, bak_t *bak,
    bool32 arch_compressed);
status_t rst_paral_decompress_to_disk(bak_process_t *process, uint32 read_size,
    bool32 read_end, uint64 file_offset, char *use_buf);
status_t rst_paral_write_to_disk(bak_process_t *ctx, char *use_buf,
    int32 buf_size, uint64 file_offset, int32 *write_size);
status_t rst_paral_restore_prepare(knl_session_t *session, bak_process_t *proc, bak_t *bak, uint32 blk_size,
                                   bool32 arch_compress);
#ifdef __cplusplus
}
#endif

#endif

