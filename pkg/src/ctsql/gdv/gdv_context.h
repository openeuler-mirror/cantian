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
 * gdv_context.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/gdv/gdv_context.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GDV_CONTEXT_H__
#define __GDV_CONTEXT_H__

#include "srv_session.h"
#include "ctsql_stmt.h"

typedef enum en_gdvsql_mode {
    GDVSQL_PREP = 1,
    GDVSQL_FETCH = 2,
} gdvsql_mode_t;

void gdv_init_sender(session_t *session);
status_t gdv_send_result_success(session_t *session);
status_t gdv_send_result_error(session_t *session);
status_t gdv_send_exec_begin(sql_stmt_t *stmt);
void gdv_send_exec_end(sql_stmt_t *stmt);
status_t gdv_send_fetch_begin(sql_stmt_t *stmt);
void gdv_send_fetch_end(sql_stmt_t *stmt);
void gdv_init_sender_row(sql_stmt_t *stmt, char *buffer, uint32 size, uint32 column_count);
status_t gdv_send_row_begin(sql_stmt_t *stmt, uint32 column_count);
status_t gdv_send_row_end(sql_stmt_t *stmt, bool32 *is_full);
status_t gdv_send_row_entire(sql_stmt_t *stmt, char *row);
status_t gdv_send_parsed_stmt(sql_stmt_t *stmt);
bool32 gdv_is_active_db(knl_handle_t se, uint32 inst_id);

#endif
