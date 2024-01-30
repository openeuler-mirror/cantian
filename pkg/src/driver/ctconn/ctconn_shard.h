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
* ctconn_shard.h
*
*
* IDENTIFICATION
* src/driver/ctconn/ctconn_shard.h
*
* -------------------------------------------------------------------------
*/
#ifndef __CTCONN_SHARD_H__
#define __CTCONN_SHARD_H__

#include "cm_text.h"
#include "ctconn_common.h"

#ifdef __cplusplus
extern "C" {
#endif

int32 ctconn_fetch_raw(ctconn_stmt_t pstmt);

int32 ctconn_fetch_data(ctconn_stmt_t pstmt, uint32 *rows);
int32 ctconn_fetch_data_ack(ctconn_stmt_t pstmt, char **data, uint32 *size);
int32 ctconn_fetch_data_attr_ack(ctconn_stmt_t pstmt, uint32 *options, uint32 *return_rows);

int32 ctconn_init_paramset_length(ctconn_stmt_t pstmt);
int32 ctconn_bind_by_pos_batch(ctconn_stmt_t pstmt, uint32 pos, int32 type, const void *data, uint32 size, bool32 is_null);
int32 ctconn_init_params(ctconn_stmt_t pstmt, uint32 param_count, bool32 is_batch);
void ctconn_paramset_size_inc(ctconn_stmt_t pstmt);

int32 ctconn_pe_prepare(ctconn_stmt_t pstmt, const char *sql, uint64 *scn);
int32 ctconn_pe_async_execute(ctconn_stmt_t pstmt, uint32 *more_param);
int32 ctconn_pe_async_execute_ack(ctconn_stmt_t pstmt, const char *sql, uint64 *ack_scn);
int32 ctconn_async_execute(ctconn_stmt_t pstmt, bool32 *more_param, uint64 *scn);
int32 ctconn_async_execute_ack(ctconn_stmt_t pstmt, uint64 *ack_scn);

int32 ctconn_async_commit(ctconn_conn_t pconn);
int32 ctconn_async_commit_ack(ctconn_conn_t pconn);
int32 ctconn_async_rollback(ctconn_conn_t pconn);
int32 ctconn_async_rollback_ack(ctconn_conn_t pconn);

int32 ctconn_async_xa_rollback(ctconn_conn_t conn, const text_t *xid, uint64 flags);
int32 ctconn_async_xa_prepare(ctconn_conn_t conn, const text_t *xid, uint64 flags, uint64 *scn);
int32 ctconn_async_xa_commit(ctconn_conn_t conn, const text_t *xid, uint64 flags, uint64 *scn);
int32 ctconn_async_xa_rollback_ack(ctconn_conn_t conn);
int32 ctconn_async_xa_prepare_ack(ctconn_conn_t conn, uint64 *ack_scn);
int32 ctconn_async_xa_commit_ack(ctconn_conn_t conn, uint64 *ack_scn);

int32 ctconn_statement_rollback(ctconn_conn_t pconn, uint32 dml_id);
int32 ctconn_gts(ctconn_conn_t pconn, uint64 *scn);

int32 ctconn_shard_prepare(ctconn_stmt_t pstmt, const char *sql);
int32 ctconn_shard_execute(ctconn_stmt_t pstmt);

int32 ctconn_fetch_sequence(ctconn_stmt_t pstmt, text_t *user, text_t *seq_name, ctconn_sequence_t *ctconn_seq);
int32 ctconn_set_sequence_nextval(ctconn_stmt_t pstmt, text_t *user, text_t *seq_name, int64 currval);
int32 ctconn_get_sequence_nextval(ctconn_stmt_t pstmt, text_t *user, text_t *seq_name, int64 *value);
int32 ctconn_get_cn_nextval(ctconn_stmt_t pstmt, text_t *user, text_t *seq_name, bool32 *empty_cache, int64 *value);
int32 ctconn_notify_cn_update_cache(ctconn_stmt_t pstmt, text_t *user, text_t *seq_name);

/*
    Definition: Single shard transaction commit
    Incoming parameter:
        conn: connection object
        time_stamp: cn delivers the timestamp, the ordinary transaction time_stamp is NULL, and the single shard is the
   CN timestamp. return value: Description: Single shard transaction commit, CN and DN do clock synchronization, common
   transaction commit is equivalent to ctconn_rollback
*/
int32 ctconn_commit_with_ts(ctconn_conn_t pconn, uint64 *scn);

int32 ctconn_set_pipe_timeout(ctconn_conn_t conn, uint32 timeout);
void ctconn_reset_pipe_timeout(ctconn_conn_t conn);
void ctconn_force_close_pipe(ctconn_conn_t conn);
void ctconn_shutdown_pipe(ctconn_conn_t conn);
cli_db_role_t ctconn_get_db_role(ctconn_conn_t conn);

#define CTCONN_INIT_PREP_EXEC_PARAM(_exe_param, _stmt)               \
    do {                                                          \
        (_exe_param)->paramset_size = 0;                          \
        (_exe_param)->prefetch_rows = (_stmt)->prefetch_rows;     \
        (_exe_param)->auto_commit = ((_stmt)->conn->auto_commit); \
        (_exe_param)->reserved[0] = 0;                            \
        (_exe_param)->reserved[1] = 0;                            \
        (_exe_param)->reserved[2] = 0;                            \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif
