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
 * knl_map_log.h
 *
 *
 * IDENTIFICATION
 * src/kernel/table/knl_map_log.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_MAP_LOG_H__
#define __KNL_MAP_LOG_H__

#include "knl_map.h"

#ifdef __cplusplus
extern "C" {
#endif

void rd_heap_format_page(knl_session_t *session, log_entry_t *log);
void rd_heap_concat_page(knl_session_t *session, log_entry_t *log);
void rd_heap_format_map(knl_session_t *session, log_entry_t *log);
void rd_heap_format_entry(knl_session_t *session, log_entry_t *log);
void rd_heap_alloc_map_node(knl_session_t *session, log_entry_t *log);
void rd_heap_change_seg(knl_session_t *session, log_entry_t *log);
void rd_heap_set_map(knl_session_t *session, log_entry_t *log);
void rd_heap_change_map(knl_session_t *session, log_entry_t *log);
void rd_heap_change_list(knl_session_t *session, log_entry_t *log);
void rd_heap_shrink_map(knl_session_t *session, log_entry_t *log);

void print_heap_format_page(log_entry_t *log);
void print_heap_concat_page(log_entry_t *log);
void print_heap_format_map(log_entry_t *log);
void print_heap_format_entry(log_entry_t *log);
void print_heap_alloc_map_node(log_entry_t *log);
void print_heap_change_seg(log_entry_t *log);
void print_heap_set_map(log_entry_t *log);
void print_heap_change_map(log_entry_t *log);
void print_heap_change_list(log_entry_t *log);
void print_heap_shrink_map(log_entry_t *log);

#ifdef __cplusplus
}
#endif

#endif
