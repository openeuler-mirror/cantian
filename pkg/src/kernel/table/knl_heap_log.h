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
 * knl_heap_log.h
 *
 *
 * IDENTIFICATION
 * src/kernel/table/knl_heap_log.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_HEAP_LOG_H__
#define __KNL_HEAP_LOG_H__

#include "knl_heap.h"

#ifdef __cplusplus
extern "C" {
#endif

void rd_heap_insert(knl_session_t *session, log_entry_t *log);
void rd_heap_update_inplace(knl_session_t *session, log_entry_t *log);
void rd_heap_update_inpage(knl_session_t *session, log_entry_t *log);
void rd_heap_set_link(knl_session_t *session, log_entry_t *log);
void rd_heap_insert_migr(knl_session_t *session, log_entry_t *log);
void rd_heap_remove_migr(knl_session_t *session, log_entry_t *log);
void rd_heap_delete(knl_session_t *session, log_entry_t *log);
void rd_heap_delete_link(knl_session_t *session, log_entry_t *log);

void rd_heap_change_dir(knl_session_t *session, log_entry_t *log);
void rd_heap_lock_row(knl_session_t *session, log_entry_t *log);
void rd_heap_new_itl(knl_session_t *session, log_entry_t *log);
void rd_heap_reuse_itl(knl_session_t *session, log_entry_t *log);
void rd_heap_clean_itl(knl_session_t *session, log_entry_t *log);

void rd_heap_undo_change_dir(knl_session_t *session, log_entry_t *log);
void rd_heap_undo_insert(knl_session_t *session, log_entry_t *log);
void rd_heap_undo_update(knl_session_t *session, log_entry_t *log);
void rd_heap_undo_update_full(knl_session_t *session, log_entry_t *log);
void rd_heap_undo_delete(knl_session_t *session, log_entry_t *log);
void rd_heap_undo_delete_link(knl_session_t *session, log_entry_t *log);
void rd_heap_init_itls(knl_session_t *session, log_entry_t *log);
void rd_heap_undo_insert_link(knl_session_t *session, log_entry_t *log);
void rd_heap_delete_migr(knl_session_t *session, log_entry_t *log);
void rd_heap_undo_update_linkrid(knl_session_t *session, log_entry_t *log);

void print_heap_change_dir(log_entry_t *log);
void print_heap_insert(log_entry_t *log);
void print_heap_update_inplace(log_entry_t *log);
void print_heap_update_inpage(log_entry_t *log);
void print_heap_insert_migr(log_entry_t *log);
void print_heap_set_link(log_entry_t *log);
void print_heap_remove_migr(log_entry_t *log);
void print_heap_delete(log_entry_t *log);
void print_heap_delete_link(log_entry_t *log);
void print_heap_lock_row(log_entry_t *log);
void print_heap_new_itl(log_entry_t *log);
void print_heap_reuse_itl(log_entry_t *log);
void print_heap_clean_itl(log_entry_t *log);
void print_heap_undo_change_dir(log_entry_t *log);
void print_heap_undo_insert(log_entry_t *log);
void print_heap_undo_update(log_entry_t *log);
void print_heap_undo_update_full(log_entry_t *log);
void print_heap_undo_delete(log_entry_t *log);
void print_heap_undo_delete_link(log_entry_t *log);
void print_heap_init_itls(log_entry_t *log);
void print_heap_undo_insert_link(log_entry_t *log);
void print_heap_delete_migr(log_entry_t *log);
void print_heap_undo_update_linkrid(log_entry_t *log);

#ifdef __cplusplus
}
#endif

#endif

