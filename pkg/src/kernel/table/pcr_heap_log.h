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
 * pcr_heap_log.h
 *
 *
 * IDENTIFICATION
 * src/kernel/table/pcr_heap_log.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_PCR_HEAP_LOG_H__
#define __KNL_PCR_HEAP_LOG_H__

#include "pcr_heap.h"

#ifdef __cplusplus
extern "C" {
#endif

void rd_pcrh_init_itls(knl_session_t *session, log_entry_t *log);
void rd_pcrh_new_itl(knl_session_t *session, log_entry_t *log);
void rd_pcrh_reuse_itl(knl_session_t *session, log_entry_t *log);
void rd_pcrh_clean_itl(knl_session_t *session, log_entry_t *log);
void rd_pcrh_lock_row(knl_session_t *session, log_entry_t *log);
void rd_pcrh_update_link_ssn(knl_session_t *session, log_entry_t *log);
void rd_pcrh_insert(knl_session_t *session, log_entry_t *log);
void rd_pcrh_update_inplace(knl_session_t *session, log_entry_t *log);
void rd_pcrh_update_inpage(knl_session_t *session, log_entry_t *log);
void rd_pcrh_delete(knl_session_t *session, log_entry_t *log);
void rd_pcrh_convert_link(knl_session_t *session, log_entry_t *log);
void rd_pcrh_update_next_rid(knl_session_t *session, log_entry_t *log);
void rd_pcrh_undo_itl(knl_session_t *session, log_entry_t *log);
void rd_pcrh_undo_insert(knl_session_t *session, log_entry_t *log);
void rd_pcrh_undo_delete(knl_session_t *session, log_entry_t *log);
void rd_pcrh_undo_update(knl_session_t *session, log_entry_t *log);
void rd_pcrh_undo_lock_link(knl_session_t *session, log_entry_t *log);
void rd_pcrh_undo_update_link_ssn(knl_session_t *session, log_entry_t *log);
void rd_pcrh_undo_update_next_rid(knl_session_t *session, log_entry_t *log);
void rd_pcrh_reset_self_change(knl_session_t *session, log_entry_t *log);

void rd_logic_rep_head_log(knl_session_t *session, log_entry_t *log);

void print_pcrh_init_itls(log_entry_t *log);
void print_pcrh_new_itl(log_entry_t *log);
void print_pcrh_reuse_itl(log_entry_t *log);
void print_pcrh_clean_itl(log_entry_t *log);
void print_pcrh_lock_row(log_entry_t *log);
void print_pcrh_update_link_ssn(log_entry_t *log);
void print_pcrh_insert(log_entry_t *log);
void print_pcrh_update_inplace(log_entry_t *log);
void print_pcrh_update_inpage(log_entry_t *log);
void print_pcrh_delete(log_entry_t *log);
void print_pcrh_convert_link(log_entry_t *log);
void print_pcrh_update_next_rid(log_entry_t *log);
void print_pcrh_undo_itl(log_entry_t *log);
void print_pcrh_undo_insert(log_entry_t *log);
void print_pcrh_undo_delete(log_entry_t *log);
void print_pcrh_undo_update(log_entry_t *log);
void print_pcrh_undo_lock_link(log_entry_t *log);
void print_pcrh_undo_update_link_ssn(log_entry_t *log);
void print_pcrh_undo_update_next_rid(log_entry_t *log);
void print_pcrh_reset_self_change(log_entry_t *log);

#ifdef __cplusplus
}
#endif

#endif

