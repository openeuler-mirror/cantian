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
 * bak_build.h
 *
 *
 * IDENTIFICATION
 * src/kernel/backup/bak_build.h
 *
 * -------------------------------------------------------------------------
 */
 
#ifndef __BAK_BUILD_H__
#define __BAK_BUILD_H__

#include "bak_common.h"
#include "knl_database.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BUILD_ALY_MAX_FILE 10
#define BUILD_ALY_MAX_BUCKET_PER_FILE (uint64) SIZE_K(80)
#define BUILD_ALY_BUCKET_AVERAGE_NUM 5
#define BUILD_ALY_MAX_ITEM (BUILD_ALY_MAX_FILE * BUILD_ALY_MAX_BUCKET_PER_FILE * BUILD_ALY_BUCKET_AVERAGE_NUM)
#define BUILD_ALY_MAX_ITEM_SIZE (BUILD_ALY_MAX_ITEM * sizeof(build_analyse_item_t))
#define BUILD_ALY_MAX_PAGE_SIZE (BUILD_ALY_MAX_ITEM * sizeof(page_id_t))
#define BUILD_ALY_MAX_BUCKET_SIZE (BUILD_ALY_MAX_FILE * BUILD_ALY_MAX_BUCKET_PER_FILE * sizeof(build_analyse_bucket_t))
#define BUILD_MAX_RETRY 3

status_t bak_build_restore(knl_session_t *session, build_param_ctrl_t *ctrl);
status_t bak_build_backup(knl_session_t *session, cs_pipe_t *pipe, cs_packet_t *send_pack, cs_packet_t *recv_pack);
status_t rst_build_update_logfiles(knl_session_t *session, bak_process_t *ctx);
void bak_build_end(knl_session_t *session);
void bak_stream_read_prepare(knl_session_t *session, bak_process_t *process, datafile_t *datafile, uint32 sec_id);
status_t bak_send_stream_data(knl_session_t *session, bak_t *bak, bak_assignment_t *assign_ctrl);
void bak_init_send_stream(bak_t *bak, uint32 start, uint64 filesize, uint32 file_id);
status_t bak_stream_send_end(bak_t *bak, bak_stream_buf_t *stream_buf);
void rst_assign_stream_restore_task(knl_session_t *session, bak_ctrl_t *init_ctrl);
void rst_init_recv_stream(bak_t *bak);
status_t rst_stream_read_prepare(knl_session_t *session, rst_stream_buf_t *recv_stream, log_file_head_t *head,
                                 bool32 *ignore_logfile);
status_t rst_recv_stream_data(knl_session_t *session, bool32 ignore_data);
bool32 knl_brain_repair_check(knl_session_t *session);
bool32 rst_db_files_not_changed(knl_session_t *session, ctrl_page_t *new_ctrl);
bool32 bak_parameter_is_valid(build_progress_t *build_progress);

void brain_repair_filer_page_from_remote(knl_session_t *session, page_head_t *page, uint32 page_count);

#ifdef __cplusplus
}
#endif

#endif
