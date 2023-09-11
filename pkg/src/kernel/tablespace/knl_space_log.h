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
 * knl_space_log.h
 *
 *
 * IDENTIFICATION
 * src/kernel/tablespace/knl_space_log.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_SPACE_LOG_H__
#define __KNL_SPACE_LOG_H__

#include "knl_space_base.h"

#ifdef __cplusplus
extern "C" {
#endif

void rd_spc_create_space(knl_session_t *session, log_entry_t *log);
void rd_spc_remove_space(knl_session_t *session, log_entry_t *log);
void rd_spc_create_datafile(knl_session_t *session, log_entry_t *log);
void rd_spc_remove_datafile(knl_session_t *session, log_entry_t *log);
void rd_spc_change_segment(knl_session_t *session, log_entry_t *log);
void rd_spc_update_head(knl_session_t *session, log_entry_t *log);
void rd_spc_update_hwm(knl_session_t *session, log_entry_t *log);
void rd_spc_alloc_extent(knl_session_t *session, log_entry_t *log);
void rd_spc_free_extent(knl_session_t *session, log_entry_t *log);
void rd_spc_concat_extent(knl_session_t *session, log_entry_t *log);
void rd_spc_free_page(knl_session_t *session, log_entry_t *log);
void rd_spc_set_autoextend(knl_session_t *session, log_entry_t *log);
void rd_spc_rename_space(knl_session_t *session, log_entry_t *log);
void rd_spc_set_flag(knl_session_t *session, log_entry_t *log);
void rd_spc_shrink_ckpt(knl_session_t *session, log_entry_t *log);
void rd_spc_extend_undo_segments(knl_session_t *session, log_entry_t *log);
void rd_spc_punch_extents(knl_session_t *session, log_entry_t *log);
void rd_spc_punch_format_page(knl_session_t *session, log_entry_t *log);

void print_spc_create_space(log_entry_t *log);
void print_spc_remove_space(log_entry_t *log);
void print_spc_create_datafile(log_entry_t *log);
void print_spc_remove_datafile(log_entry_t *log);
void print_spc_change_segment(log_entry_t *log);
void print_spc_update_head(log_entry_t *log);
void print_spc_update_hwm(log_entry_t *log);
void print_spc_alloc_extent(log_entry_t *log);
void print_spc_free_extent(log_entry_t *log);
void print_spc_concat_extent(log_entry_t *log);
void print_spc_set_autoextend(log_entry_t *log);
void print_spc_set_flag(log_entry_t *log);
void print_spc_rename_space(log_entry_t *log);
void print_spc_shrink_ckpt(log_entry_t *log);
void print_spc_free_page(log_entry_t *log);
void print_spc_extend_undo_segments(log_entry_t *log);
void print_spc_punch_extents(log_entry_t *log);
void print_spc_punch_format_hole(log_entry_t *log);

void rd_df_init_map_head(knl_session_t *session, log_entry_t *log);
void rd_df_add_map_group(knl_session_t *session, log_entry_t *log);
void rd_df_init_map_page(knl_session_t *session, log_entry_t *log);
void rd_df_change_map(knl_session_t *session, log_entry_t *log);

void print_df_init_map_head(log_entry_t *log);
void print_df_add_map_group(log_entry_t *log);
void print_df_init_map_page(log_entry_t *log);
void print_df_change_map(log_entry_t *log);

void rd_spc_extend_datafile(knl_session_t *session, log_entry_t *log);
void rd_spc_truncate_datafile(knl_session_t *session, log_entry_t *log);
void rd_spc_extend_datafile_daac(knl_session_t *session, log_entry_t *log);
void rd_spc_truncate_datafile_daac(knl_session_t *session, log_entry_t *log);
void rd_spc_change_autoextend(knl_session_t *session, log_entry_t *log);
void rd_spc_change_autoextend_daac(knl_session_t *session, log_entry_t *log);

void print_spc_extend_datafile(log_entry_t *log);
void print_spc_truncate_datafile(log_entry_t *log);
void print_spc_extend_datafile_daac(log_entry_t *log);
void print_spc_truncate_datafile_daac(log_entry_t *log);
void print_spc_change_autoextend(log_entry_t *log);
void print_spc_change_autoextend_daac(log_entry_t *log);

void gbp_aly_spc_extend_datafile(knl_session_t *session, log_entry_t *log, uint64 lsn);
bool32 format_page_redo_type(uint8 type);
void punch_page_skip_recovery_log(knl_session_t *session, log_entry_t *log, bool32 *need_replay);
void format_page_must_recovery_log(knl_session_t *session, log_entry_t *log, bool32 *need_replay);

void rd_spc_create_space_ctdb(knl_session_t *session, log_entry_t *log);
void rd_spc_remove_space_ctdb(knl_session_t *session, log_entry_t *log);
void rd_spc_create_datafile_ctdb(knl_session_t *session, log_entry_t *log);
void rd_spc_remove_datafile_ctdb(knl_session_t *session, log_entry_t *log);
void rd_spc_set_autoextend_ctdb(knl_session_t *session, log_entry_t *log);
void rd_spc_rename_space_ctdb(knl_session_t *session, log_entry_t *log);
void rd_spc_set_flag_ctdb(knl_session_t *session, log_entry_t *log);

void print_spc_create_space_ctdb(log_entry_t *log);
void print_spc_remove_space_ctdb(log_entry_t *log);
void print_spc_create_datafile_ctdb(log_entry_t *log);
void print_spc_remove_datafile_ctdb(log_entry_t *log);
void print_spc_set_autoextend_ctdb(log_entry_t *log);
void print_spc_set_flag_ctdb(log_entry_t *log);
void print_spc_rename_space_ctdb(log_entry_t *log);

#ifdef __cplusplus
}
#endif

#endif

