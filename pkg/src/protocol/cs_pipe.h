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
 * cs_pipe.h
 *
 *
 * IDENTIFICATION
 * src/protocol/cs_pipe.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CS_PIPE_H__
#define __CS_PIPE_H__

#include "cm_defs.h"
#include "cm_decimal.h"
#include "cm_binary.h"
#include "cs_tcp.h"
#include "cs_packet.h"
#include "cm_interval.h"
#include "var_inc.h"
#include "cs_ssl.h"
#include "cs_uds.h"
#include "cs_rdma.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_cs_pipe_type {
    CS_TYPE_NONE = 0,
    CS_TYPE_TCP = 1,
    CS_TYPE_IPC = 2,
    CS_TYPE_DOMAIN_SCOKET = 3,
    CS_TYPE_SSL = 4,
    CS_TYPE_EMBEDDED = 5, /* embedded mode, reserved */
    CS_TYPE_DIRECT = 6,   /* direct mode, reserved */
    CS_TYPE_RSOCKET = 7,  /* rdma socket mode with rdma_cm library */
    CS_TYPE_RDMA   = 8,   /* direct mode, reserved */
    CS_TYPE_UC   = 9,
    CS_TYPE_UC_RDMA = 10,
    CS_TYPE_CEIL
} cs_pipe_type_t;

typedef union un_cs_link {
    tcp_link_t tcp;
    ssl_link_t ssl;
    uds_link_t uds;
    rdma_link_t rdma;
    // other links can be added later
} cs_link_t;

typedef struct st_cs_pipe {
    cs_pipe_type_t type;
    cs_link_t link;
    uint32 options;
    uint32 version;
    int32 connect_timeout;  // ms
    int32 socket_timeout;   // ms
    int32 l_onoff;
    int32 l_linger;
    cs_shd_node_type_t node_type;   // node type for sharding , cn/dn/gts
} cs_pipe_t;

typedef struct st_link_ready_ack {
    uint8 endian;
    uint8 handshake_version;  // handshake version [23,255]
    union {
        uint8 reserved[2];
        uint16 flags;  // since CS_VERSION_2
    };
} link_ready_ack_t;

extern const text_t g_pipe_type_names[CS_TYPE_CEIL];

typedef bool32 (*check_inst_alive_func)(uint32_t dst_id);

status_t cs_connect(const char *url, cs_pipe_t *pipe, const char *bind_host,
                    const char *server_path, const char *client_path);
void     cs_disconnect(cs_pipe_t *pipe);
void     cs_shutdown(cs_pipe_t *pipe);
status_t cs_wait(cs_pipe_t *pipe, uint32 wait_for, int32 timeout, bool32 *ready);
EXTER_ATTACK status_t cs_read(cs_pipe_t *pipe, cs_packet_t *pack, bool32 cs_client);
EXTER_ATTACK status_t cs_read_bytes(cs_pipe_t *pipe, char *buf, uint32 max_size, int32 *size);
EXTER_ATTACK status_t cs_read_fixed_size(cs_pipe_t *pipe, char *buf, int32 size);
EXTER_ATTACK status_t cs_send_fixed_size(cs_pipe_t *pipe, char *buf, int32 size, uint32_t dst_id,
                                         check_inst_alive_func check_dst_alive);
EXTER_ATTACK status_t cs_write_stream(cs_pipe_t *pipe, const char *buf, uint32 size, int32 max_pkg_size);
EXTER_ATTACK status_t cs_write_stream_timeout(cs_pipe_t *pipe, const char *buf, uint32 size, int32 max_pkg_size,
                                              uint32 timeout);
EXTER_ATTACK status_t cs_read_stream(cs_pipe_t *pipe, char *buf, uint32 timeout, uint32 max_size, int32 *size);
EXTER_ATTACK status_t cs_send_bytes(cs_pipe_t *pipe, const char *buf, uint32 size);
EXTER_ATTACK status_t cs_write(cs_pipe_t *pipe, cs_packet_t *pack);
socket_t cs_get_socket_fd(cs_pipe_t *pipe);
status_t cs_call(cs_pipe_t *pipe, cs_packet_t *req, cs_packet_t *ack);
status_t cs_call_ex(cs_pipe_t *pipe, cs_packet_t *req, cs_packet_t *ack);

/* This function build SSL channel using a accepted socket */
status_t cs_ssl_accept(ssl_ctx_t *fd, cs_pipe_t *pipe);
/* This function build SSL channel using a connected socket */
status_t cs_ssl_connect(ssl_ctx_t *fd, cs_pipe_t *pipe);

typedef void (*init_sender_t)(void *session);
typedef status_t (*send_result_success_t)(void *session);
typedef status_t (*send_result_error_t)(void *session);
typedef status_t (*send_fetch_begin_t)(void *stmt);
typedef void (*send_fetch_end_t)(void *stmt);
typedef status_t (*send_exec_begin_t)(void *stmt);
typedef void (*send_exec_end_t)(void *stmt);
typedef status_t (*send_parsed_stmt_t)(void *stmt);  // send description of the last parsed statement
typedef status_t (*send_row_data_t)(void *stmt, char *row, bool32 *is_full);
typedef status_t (*send_row_begin_t)(void *stmt, uint32 column_count);
typedef status_t(*send_row_end_t)(void *stmt, bool32 *is_full);
typedef void (*init_sender_row_t)(void *stmt, char *buffer, uint32 size, uint32 column_count);  // for rs materialize
typedef status_t (*send_column_null_t)(void *stmt, uint32 type);
typedef status_t (*send_column_uint32_t)(void *stmt, uint32 v);
typedef status_t (*send_column_int32_t)(void *stmt, int32 v);
typedef status_t (*send_column_int64_t)(void *stmt, int64 v);
typedef status_t (*send_column_real_t)(void *stmt, double v);
typedef status_t (*send_column_date_t)(void *stmt, date_t v);
typedef status_t (*send_column_ts_t)(void *stmt, date_t v);
typedef status_t (*send_column_ts_tz_t)(void *stmt, timestamp_tz_t *v);
typedef status_t (*send_column_ts_ltz_t)(void *stmt, timestamp_ltz_t v);
typedef status_t (*send_column_decimal_t)(void *stmt, dec8_t *v);
typedef status_t (*send_column_decimal2_t)(void *stmt, dec8_t *v);
typedef status_t (*send_column_str_t)(void *stmt, char *v);
typedef status_t (*send_column_text_t)(void *stmt, text_t *v);
typedef status_t (*send_column_bin_t)(void *stmt, binary_t *v);
typedef status_t (*send_column_bool_t)(void *stmt, bool32 v);
typedef status_t (*send_column_lob_t)(void *stmt, var_lob_t *v);
typedef status_t (*send_column_bin_t)(void *stmt, binary_t *v);
typedef status_t (*send_column_ymitvl_t)(void *stmt, interval_ym_t v);
typedef status_t (*send_column_dsitvl_t)(void *stmt, interval_ds_t v);
typedef status_t (*send_serveroutput_t)(void *stmt, text_t *output);
typedef status_t (*send_return_result_t)(void *stmt, uint32 stmt_id);
typedef status_t (*send_column_cursor_t)(void *stmt, cursor_t *v);
typedef status_t (*send_column_struct_t)(void *stmt, var_record_t *v);
typedef void (*send_column_def_t)(void *stmt, void *cursor);
typedef status_t (*send_column_array_t)(void *stmt, var_array_t *v);
typedef status_t (*send_return_value_t)(void *stmt, ct_type_t type, typmode_t *typmod, variant_t *v);
typedef status_t (*send_import_rows_t)(void *stmt);
typedef status_t (*send_nls_feedback_t)(void *stmt, nlsparam_id_t id, text_t *value);
typedef status_t (*send_session_tz_feedback_t)(void *stmt, timezone_info_t client_timezone);


typedef struct st_ack_sender {
    init_sender_t init;
    init_sender_row_t init_row;
    uint32 pad[10]; // cacheline number
    send_result_success_t send_result_success;
    send_result_error_t send_result_error;
    send_parsed_stmt_t send_parsed_stmt;
    send_exec_begin_t send_exec_begin;
    send_exec_end_t send_exec_end;
    send_exec_begin_t send_fetch_begin;
    send_exec_end_t send_fetch_end;
    send_row_data_t send_row_data;
    send_row_begin_t send_row_begin;
    send_row_end_t send_row_end;
    send_column_null_t send_column_null;
    send_column_uint32_t  send_column_uint32;
    send_column_int32_t send_column_int32;
    send_column_int64_t send_column_int64;
    send_column_real_t send_column_real;
    send_column_date_t send_column_date;
    send_column_ts_t send_column_ts;
    send_column_ts_tz_t   send_column_tstz;
    send_column_ts_ltz_t  send_column_tsltz;
    send_column_str_t send_column_str;
    send_column_bin_t send_column_bin;
    send_column_text_t send_column_text;
    send_column_decimal_t send_column_decimal;
    send_column_decimal2_t send_column_decimal2;
    send_column_bool_t send_column_bool;
    send_column_lob_t send_column_clob;
    send_column_lob_t send_column_blob;
    send_column_ymitvl_t send_column_ymitvl;
    send_column_dsitvl_t send_column_dsitvl;
    send_serveroutput_t send_serveroutput;
    send_return_result_t send_return_result;
    send_column_cursor_t send_column_cursor;
    send_column_bin_t send_column_raw;
    send_column_def_t send_column_def;
    send_column_array_t send_column_array;
    send_return_value_t send_return_value;
    send_import_rows_t send_import_rows;
    send_nls_feedback_t send_nls_feedback;
    send_session_tz_feedback_t send_session_tz_feedback;
} ack_sender_t;

#ifdef __cplusplus
}
#endif

#endif
