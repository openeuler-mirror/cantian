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
 * knl_buffer_log.h
 *
 *
 * IDENTIFICATION
 * src/kernel/buffer/knl_buffer_log.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_BUFFER_LOG_H__
#define __KNL_BUFFER_LOG_H__

#include "knl_buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

void rd_enter_page(knl_session_t *session, log_entry_t *log);
void rd_leave_page(knl_session_t *session, log_entry_t *log);

void print_enter_page(log_entry_t *log);
void print_leave_page(log_entry_t *log);

void gbp_aly_enter_page(knl_session_t *session, log_entry_t *log, uint64 lsn);
void gbp_aly_leave_page(knl_session_t *session, log_entry_t *log, uint64 lsn);

#ifdef __cplusplus
}
#endif

#endif
