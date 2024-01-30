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
 * pl_context.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/pl_context.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_CONTEXT_H__
#define __PL_CONTEXT_H__

#include "srv_session.h"
#include "ctsql_stmt.h"

#ifdef __cplusplus
extern "C" {
#endif

void pl_init_sender(session_t *session);
void pl_init_sender_row(sql_stmt_t *stmt, char *buffer, uint32 size, uint32 column_count); // for materialize
void pl_send_exec_end(sql_stmt_t *stmt);
status_t pl_send_import_rows(sql_stmt_t *stmt);
void pl_send_fetch_end(sql_stmt_t *stmt);
status_t pl_send_row_end(sql_stmt_t *stmt, bool32 *is_full);
status_t pl_send_result_success(session_t *session);
status_t pl_send_result_error(session_t *session);
status_t pl_send_parsed_stmt(sql_stmt_t *stmt);
status_t pl_send_exec_begin(sql_stmt_t *stmt);
status_t pl_send_fetch_begin(sql_stmt_t *stmt);
status_t pl_send_returning_begin(sql_stmt_t *stmt);
status_t pl_send_row_entire(sql_stmt_t *stmt, char *row, bool32 *is_full);
status_t pl_send_row_begin(sql_stmt_t *stmt, uint32 column_count);
status_t pl_send_column_null(sql_stmt_t *stmt, uint32 type);
status_t pl_send_column_uint32(sql_stmt_t *stmt, uint32 v);
status_t pl_send_column_int32(sql_stmt_t *stmt, int32 v);
status_t pl_send_column_int64(sql_stmt_t *stmt, int64 v);
status_t pl_send_column_dsinterval(sql_stmt_t *stmt, interval_ds_t v);
status_t pl_send_column_yminterval(sql_stmt_t *stmt, interval_ym_t v);
status_t pl_send_column_real(sql_stmt_t *stmt, double v);
status_t pl_send_column_date(sql_stmt_t *stmt, date_t v);
status_t pl_send_column_ts(sql_stmt_t *stmt, date_t v);
status_t pl_send_column_tstz(sql_stmt_t *stmt, timestamp_tz_t *v);
status_t pl_send_column_tsltz(sql_stmt_t *stmt, timestamp_ltz_t v);
status_t pl_send_column_str(sql_stmt_t *stmt, char *str);
status_t pl_send_column_text(sql_stmt_t *stmt, text_t *text);
status_t pl_send_column_bin(sql_stmt_t *stmt, binary_t *bin);
status_t pl_send_column_raw(sql_stmt_t *stmt, binary_t *bin);
status_t pl_send_column_decimal(sql_stmt_t *stmt, dec8_t *dec);
status_t pl_send_column_clob(sql_stmt_t *stmt, var_lob_t *bin);
status_t pl_send_column_blob(sql_stmt_t *stmt, var_lob_t *bin);
status_t pl_send_serveroutput(sql_stmt_t *stmt, text_t *output);
status_t pl_send_return_result(sql_stmt_t *stmt, uint32 stmt_id);
status_t pl_send_column_cursor(sql_stmt_t *stmt, cursor_t *cursor);
status_t pl_send_column_def(sql_stmt_t *stmt, cursor_t *cursor);
status_t pl_send_column_array(sql_stmt_t *stmt, var_array_t *v);
status_t pl_send_return_value(sql_stmt_t *stmt, ct_type_t type, typmode_t *typmod, variant_t *v);
status_t pl_send_nls_feedback(sql_stmt_t *stmt, nlsparam_id_t id, text_t *value);
status_t pl_send_session_tz_feedback(sql_stmt_t *stmt, timezone_info_t client_timezone);

// definition depends on cs_packet_t !!!
typedef struct st_plc_cs_packet {
    uint32 offset;  // for reading
    uint32 options; // options
    cs_packet_head_t *head;
    uint32 max_buf_size; // MAX_ALLOWED_PACKET
    uint32 buf_size;
    char *buf;
    char *init_buf;
} plc_cs_packet_t;

#ifdef __cplusplus
}
#endif

#endif
