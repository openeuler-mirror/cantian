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
 * bak_log_paral.h
 *
 *
 * IDENTIFICATION
 * src/kernel/backup/bak_log_paral.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __BAK_LOG_PARAL_H__
#define __BAK_LOG_PARAL_H__

#include "bak_common.h"
#include "knl_context.h"
#include "bak_paral.h"

#ifdef __cplusplus
extern "C" {
#endif

void bak_set_head_for_paral_log(bak_t *bak);
status_t bak_found_archived_log(knl_session_t *session, uint32 rst_id, uint32 asn, arch_ctrl_t **arch_ctrl,
    bool32 is_paral_log_proc);
status_t bak_set_log_ctrl(knl_session_t *session, bak_process_t *process, uint32 asn,
                          uint32 *block_size, bool32 *compressed);
status_t bak_set_archived_log_ctrl(knl_session_t *session, bak_process_t *process, uint32 asn, uint32 *block_size,
                                   bool32 *compressed, bool32 is_paral_log_proc);
status_t bak_check_datafiles_num(knl_session_t *session, bool32 update_device);
status_t bak_check_bak_device(bak_t *bak, datafile_t *datafile, bak_assignment_t *assign_ctrl);
void bak_try_reset_file_size(bak_t *bak, bak_assignment_t *assign_ctrl);
void bak_try_wait_paral_log_proc(bak_t *bak);
uint32 bak_get_log_slot(bak_t *bak, bool32 is_paral_log_proc);
status_t bak_try_merge_bak_info(bak_t *bak, uint32 last_asn, uint32 *start_asn);
bool32 bak_equal_last_asn(knl_session_t *session, uint32 last_asn);
void bak_log_read_proc(thread_t *thread);

#ifdef __cplusplus
}
#endif

#endif

