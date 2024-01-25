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
 * lob_log.h
 *
 *
 * IDENTIFICATION
 * src/kernel/lob/lob_log.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __LOB_LOG_H
#define __LOB_LOG_H

#include "knl_log.h"

#ifdef __cplusplus
extern "C" {
#endif

void rd_lob_put_chunk(knl_session_t *session, log_entry_t *log);
void rd_lob_page_init(knl_session_t *session, log_entry_t *log);
void rd_lob_change_seg(knl_session_t *session, log_entry_t *log);
void rd_lob_change_chunk(knl_session_t *session, log_entry_t *log);
void rd_lob_change_page_free(knl_session_t *session, log_entry_t *log);
void rd_lob_page_ext_init(knl_session_t *session, log_entry_t *log);
void print_lob_put_chunk(log_entry_t *log);
void print_lob_page_init(log_entry_t *log);
void print_lob_change_seg(log_entry_t *log);
void print_lob_change_chunk(log_entry_t *log);
void print_lob_change_page_free(log_entry_t *log);
void print_lob_page_ext_init(log_entry_t *log);


#ifdef __cplusplus
}
#endif

#endif
