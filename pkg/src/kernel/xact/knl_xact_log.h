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
 * knl_xact_log.h
 *
 *
 * IDENTIFICATION
 * src/kernel/xact/knl_xact_log.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_XACT_LOG_H__
#define __KNL_XACT_LOG_H__

#include "knl_undo.h"

#ifdef __cplusplus
extern "C" {
#endif

void rd_undo_change_segment(knl_session_t *session, log_entry_t *log);
void rd_undo_change_txn(knl_session_t *session, log_entry_t *log);
void rd_undo_format_page(knl_session_t *session, log_entry_t *log);
void rd_undo_change_page(knl_session_t *session, log_entry_t *log);
void rd_undo_write(knl_session_t *session, log_entry_t *log);
void rd_undo_clean(knl_session_t *session, log_entry_t *log);
void rd_undo_cipher_reserve(knl_session_t *session, log_entry_t *log);

void print_undo_change_segment(log_entry_t *log);
void print_undo_change_txn(log_entry_t *log);
void print_undo_format_page(log_entry_t *log);
void print_undo_change_page(log_entry_t *log);
void print_undo_write(log_entry_t *log);
void print_undo_clean(log_entry_t *log);
void print_undo_cipher_reserve(log_entry_t *log);

void gbp_undo_format_txn(knl_session_t *session, log_entry_t *log, uint64 lsn);
void gbp_aly_undo_change_txn(knl_session_t *session, log_entry_t *log, uint64 lsn);

void rd_tx_begin(knl_session_t *session, log_entry_t *log);
void rd_tx_end(knl_session_t *session, log_entry_t *log);
void print_tx_begin(log_entry_t *log);
void print_tx_end(log_entry_t *log);

void rd_xa_phase1(knl_session_t *session, log_entry_t *log);
void rd_xa_rollback_phase2(knl_session_t *session, log_entry_t *log);
void print_xa_rollback_phase2(log_entry_t *log);
void print_xa_phase1(log_entry_t *log);

void gbp_aly_tx_begin(knl_session_t *session, log_entry_t *log, uint64 lsn);
void gbp_aly_xa_phase1(knl_session_t *session, log_entry_t *log, uint64 lsn);
void gbp_aly_xa_rollback_phase2(knl_session_t *session, log_entry_t *log, uint64 lsn);
void gbp_aly_tx_end(knl_session_t *session, log_entry_t *log, uint64 lsn);

void rd_undo_alloc_segment(knl_session_t *session, log_entry_t *log);
void rd_undo_create_segment(knl_session_t *session, log_entry_t *log);
void rd_undo_extend_txn(knl_session_t *session, log_entry_t *log);
void rd_undo_format_txn(knl_session_t *session, log_entry_t *log);
void rd_switch_undo_space(knl_session_t *session, log_entry_t *log);
void rd_undo_move_txn(knl_session_t *session, log_entry_t *log);
void rd_undo_nologging_write(knl_session_t *session, log_entry_t *log);


void print_undo_alloc_segment(log_entry_t *log);
void print_undo_create_segment(log_entry_t *log);
void print_undo_extend_txn(log_entry_t *log);
void print_undo_format_txn(log_entry_t *log);
void print_switch_undo_space(log_entry_t *log);
void print_undo_move_txn(log_entry_t *log);
void print_undo_nologging_write(log_entry_t *log);

void update_undo_ctx_active_workers(undo_context_t *ctx, undo_set_t *undo_set);

#ifdef __cplusplus
}
#endif

#endif
