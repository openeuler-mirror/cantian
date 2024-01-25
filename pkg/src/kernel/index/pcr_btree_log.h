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
 * pcr_btree_log.h
 *
 *
 * IDENTIFICATION
 * src/kernel/index/pcr_btree_log.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PCR_BTREE_LOG_H__
#define __PCR_BTREE_LOG_H__

#include "pcr_btree.h"

#ifdef __cplusplus
extern "C" {
#endif

void rd_pcrb_new_itl(knl_session_t *session, log_entry_t *log);
void rd_pcrb_reuse_itl(knl_session_t *session, log_entry_t *log);
void rd_pcrb_clean_itl(knl_session_t *session, log_entry_t *log);
void rd_pcrb_insert(knl_session_t *session, log_entry_t *log);
void rd_pcrb_delete(knl_session_t *session, log_entry_t *log);
void rd_pcrb_compact_page(knl_session_t *session, log_entry_t *log);
void rd_pcrb_copy_itl(knl_session_t *session, log_entry_t *log);
void rd_pcrb_copy_key(knl_session_t *session, log_entry_t *log);
void rd_pcrb_set_scn(knl_session_t *session, log_entry_t *log);
void rd_pcrb_set_copy_itl(knl_session_t *session, log_entry_t *log);
void rd_pcrb_clean_keys(knl_session_t *session, log_entry_t *log);
void rd_pcrb_undo_itl(knl_session_t *session, log_entry_t *log);
void rd_pcrb_undo_insert(knl_session_t *session, log_entry_t *log);
void rd_pcrb_undo_delete(knl_session_t *session, log_entry_t *log);
void rd_pcrb_clean_key(knl_session_t *session, log_entry_t *log);

void print_pcrb_new_itl(log_entry_t *log);
void print_pcrb_reuse_itl(log_entry_t *log);
void print_pcrb_clean_itl(log_entry_t *log);
void print_pcrb_insert(log_entry_t *log);
void print_pcrb_delete(log_entry_t *log);
void print_pcrb_compact_page(log_entry_t *log);
void print_pcrb_copy_itl(log_entry_t *log);
void print_pcrb_copy_key(log_entry_t *log);
void print_pcrb_set_scn(log_entry_t *log);
void print_pcrb_set_copy_itl(log_entry_t *log);
void print_pcrb_clean_keys(log_entry_t *log);
void print_pcrb_undo_itl(log_entry_t *log);
void print_pcrb_undo_insert(log_entry_t *log);
void print_pcrb_undo_delete(log_entry_t *log);
void print_pcrb_clean_key(log_entry_t *log);

#ifdef __cplusplus
}
#endif

#endif
