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
 * rcr_btree_log.h
 *
 *
 * IDENTIFICATION
 * src/kernel/index/rcr_btree_log.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __RCR_BTREE_LOG_H__
#define __RCR_BTREE_LOG_H__

#include "rcr_btree.h"

#ifdef __cplusplus
extern "C" {
#endif

void print_btree_init_segment(log_entry_t *log);
void print_btree_format_page(log_entry_t *log);
void print_btree_change_seg(log_entry_t *log);
void print_btree_change_chain(log_entry_t *log);
void print_btree_delete(log_entry_t *log);
void print_btree_compact(log_entry_t *log);
void print_btree_new_itl(log_entry_t *log);
void print_btree_reuse_itl(log_entry_t *log);
void print_btree_clean_itl(log_entry_t *log);
void print_btree_clean_moved_keys(log_entry_t *log);
void print_btree_insert(log_entry_t *log);
void print_btree_copy_itl(log_entry_t *log);
void print_btree_copy_key(log_entry_t *log);
void print_btree_undo_insert(log_entry_t *log);
void print_btree_undo_delete(log_entry_t *log);
void print_btree_init_entry(log_entry_t *log);
void print_btree_clean_key(log_entry_t *log);
void print_bt_put_recycle(log_entry_t *log);
void print_bt_recycle_page(log_entry_t *log);
void print_bt_concat_remove_page(log_entry_t *log);
void print_btree_next_del_page(log_entry_t *log);
void print_update_btree_partid(log_entry_t *log);
void rd_btree_init_segment(knl_session_t *session, log_entry_t *log);
void rd_btree_init_entry(knl_session_t *session, log_entry_t *log);
void rd_btree_format_page(knl_session_t *session, log_entry_t *log);
void rd_btree_change_seg(knl_session_t *session, log_entry_t *log);
void rd_btree_delete(knl_session_t *session, log_entry_t *log);
void rd_btree_compact(knl_session_t *session, log_entry_t *log);
void rd_btree_insert(knl_session_t *session, log_entry_t *log);
void rd_btree_clean_moved_keys(knl_session_t *session, log_entry_t *log);
void rd_btree_new_itl(knl_session_t *session, log_entry_t *log);
void rd_btree_reuse_itl(knl_session_t *session, log_entry_t *log);
void rd_btree_extent_itl(knl_session_t *session, log_entry_t *log);
void rd_btree_clean_itl(knl_session_t *session, log_entry_t *log);
void rd_btree_undo_insert(knl_session_t *session, log_entry_t *log);
void rd_btree_undo_delete(knl_session_t *session, log_entry_t *log);
void rd_btree_change_chain(knl_session_t *session, log_entry_t *log);
void rd_btree_copy_itl(knl_session_t *session, log_entry_t *log);
void rd_btree_copy_key(knl_session_t *session, log_entry_t *log);
void rd_btree_construct_page(knl_session_t *session, log_entry_t *log);
void rd_btree_change_itl_copied(knl_session_t *session, log_entry_t *log);
void rd_btree_clean_key(knl_session_t *session, log_entry_t *log);
void rd_btree_set_recycle(knl_session_t *session, log_entry_t *log);
void rd_bt_recycle_page(knl_session_t *session, log_entry_t *log);
void rd_bt_concat_remove_page(knl_session_t *session, log_entry_t *log);
void rd_btree_next_del_page(knl_session_t *session, log_entry_t *log);
void rd_btree_update_partid(knl_session_t *session, log_entry_t *log);

#ifdef __cplusplus
}
#endif

#endif
