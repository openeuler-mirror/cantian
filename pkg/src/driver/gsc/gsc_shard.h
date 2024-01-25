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
 * gsc_shard.h
 *
 *
 * IDENTIFICATION
 * src/driver/gsc/gsc_shard.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __GSC_SHARD_H__
#define __GSC_SHARD_H__

#include "cm_text.h"
#include "gsc_common.h"

#ifdef __cplusplus
extern "C" {
#endif

int32 gsc_fetch_raw(gsc_stmt_t pstmt);

int32 gsc_fetch_data(gsc_stmt_t pstmt, uint32 *rows);
int32 gsc_fetch_data_ack(gsc_stmt_t pstmt, char **data, uint32 *size);
int32 gsc_fetch_data_attr_ack(gsc_stmt_t pstmt, uint32 *options, uint32 *return_rows);

int32 gsc_init_paramset_length(gsc_stmt_t pstmt);
int32 gsc_bind_by_pos_batch(gsc_stmt_t pstmt, uint32 pos, int32 type, const void *data, uint32 size, bool32 is_null);
int32 gsc_init_params(gsc_stmt_t pstmt, uint32 param_count, bool32 is_batch);
void gsc_paramset_size_inc(gsc_stmt_t pstmt);

int32 gsc_pe_prepare(gsc_stmt_t pstmt, const char *sql, uint64 *scn);
int32 gsc_pe_async_execute(gsc_stmt_t pstmt, uint32 *more_param);
int32 gsc_pe_async_execute_ack(gsc_stmt_t pstmt, const char *sql, uint64 *ack_scn);
int32 gsc_async_execute(gsc_stmt_t pstmt, bool32 *more_param, uint64 *scn);
int32 gsc_async_execute_ack(gsc_stmt_t pstmt, uint64 *ack_scn);

int32 gsc_async_commit(gsc_conn_t pconn);
int32 gsc_async_commit_ack(gsc_conn_t pconn);
int32 gsc_async_rollback(gsc_conn_t pconn);
int32 gsc_async_rollback_ack(gsc_conn_t pconn);

int32 gsc_async_xa_rollback(gsc_conn_t conn, const text_t *xid, uint64 flags);
int32 gsc_async_xa_prepare(gsc_conn_t conn, const text_t *xid, uint64 flags, uint64 *scn);
int32 gsc_async_xa_commit(gsc_conn_t conn, const text_t *xid, uint64 flags, uint64 *scn);
int32 gsc_async_xa_rollback_ack(gsc_conn_t conn);
int32 gsc_async_xa_prepare_ack(gsc_conn_t conn, uint64 *ack_scn);
int32 gsc_async_xa_commit_ack(gsc_conn_t conn, uint64 *ack_scn);

int32 gsc_statement_rollback(gsc_conn_t pconn, uint32 dml_id);
int32 gsc_gts(gsc_conn_t pconn, uint64 *scn);

int32 gsc_shard_prepare(gsc_stmt_t pstmt, const char *sql);
int32 gsc_shard_execute(gsc_stmt_t pstmt);

int32 gsc_fetch_sequence(gsc_stmt_t pstmt, text_t *user, text_t *seq_name, gsc_sequence_t *gsc_seq);
int32 gsc_set_sequence_nextval(gsc_stmt_t pstmt, text_t *user, text_t *seq_name, int64 currval);
int32 gsc_get_sequence_nextval(gsc_stmt_t pstmt, text_t *user, text_t *seq_name, int64 *value);
int32 gsc_get_cn_nextval(gsc_stmt_t pstmt, text_t *user, text_t *seq_name, bool32 *empty_cache, int64 *value);
int32 gsc_notify_cn_update_cache(gsc_stmt_t pstmt, text_t *user, text_t *seq_name);

/*
    Definition: Single shard transaction commit
    Incoming parameter:
        conn: connection object
        time_stamp: cn delivers the timestamp, the ordinary transaction time_stamp is NULL, and the single shard is the
   CN timestamp. return value: Description: Single shard transaction commit, CN and DN do clock synchronization, common
   transaction commit is equivalent to gsc_rollback
*/
int32 gsc_commit_with_ts(gsc_conn_t pconn, uint64 *scn);

int32 gsc_set_pipe_timeout(gsc_conn_t conn, uint32 timeout);
void gsc_reset_pipe_timeout(gsc_conn_t conn);
void gsc_force_close_pipe(gsc_conn_t conn);
void gsc_shutdown_pipe(gsc_conn_t conn);
cli_db_role_t gsc_get_db_role(gsc_conn_t conn);

#define GSC_INIT_PREP_EXEC_PARAM(_exe_param, _stmt)               \
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
