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
 * repl_arch_fetch.h
 *
 *
 * IDENTIFICATION
 * src/kernel/replication/repl_arch_fetch.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __REPL_ARCH_FETCH_H__
#define __REPL_ARCH_FETCH_H__

#include "cm_thread.h"
#include "cm_spinlock.h"
#include "cm_utils.h"
#include "cs_pipe.h"
#include "knl_archive.h"
#include "knl_log.h"
#include "knl_session.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LFTC_MAX_TASK 4

typedef struct st_lftc_cmp_ctx {
    uint32 buf_size;
    aligned_buf_t compress_buf;
    uint32 data_size;
} lftc_cmp_ctx_t;

typedef struct st_lftc_clt_req {
    uint32 rst_id;
    uint32 asn;
    uint64 offset;
} lftc_clt_req_t;

typedef struct st_lftc_file_ctx {
    char file_name[CT_FILE_NAME_BUFFER_SIZE];
    cs_pipe_t *pipe;
    aligned_buf_t msg_buf;
    uint32 msg_buf_size;
    uint64 offset;
    uint64 write_pos;
    int32 handle;
    int32 timeout;
    log_file_head_t log_head;
} lftc_file_ctx_t;

typedef struct st_lftc_srv_ctx {
    thread_t thread;
    cs_pipe_t *pipe;
    knl_session_t *session;
    lftc_file_ctx_t file_ctx;
    lftc_cmp_ctx_t cmp_ctx;
    compress_algo_e compress_alg;
} lftc_srv_ctx_t;

typedef struct st_lftc_clt_task_t {
    char file_name[CT_FILE_NAME_BUFFER_SIZE];
    char tmp_file_name[CT_FILE_NAME_BUFFER_SIZE + 4]; /* 4 bytes for ".tmp" */
    spinlock_t lock;
    thread_t thread;
    cs_pipe_t pipe;
    uint32 id;
    uint32 rst_id;
    uint32 asn;
    bool32 is_running;
    cs_packet_t send_pack;
    cs_packet_t recv_pack;
    knl_session_t *session;
    aligned_buf_t msg_buf;
    uint32 msg_buf_size;
    uint64 offset;
    int32 handle;
    int32 timeout;
    log_file_head_t log_head;
    lftc_cmp_ctx_t cmp_ctx;
    bool32 canceled;
    uint64 origin_size;
} lftc_clt_task_t;

typedef struct st_lftc_clt_ctx {
    spinlock_t lock;
    lftc_clt_task_t tasks[LFTC_MAX_TASK];
    uint32 hwm;
    bool32 arch_lost;
} lftc_clt_ctx_t;

typedef struct st_lftc_task_handle {
    uint32 task_id;
    uint32 rst_id;
    uint32 asn;
} lftc_task_handle_t;

status_t lftc_srv_ctx_alloc(lftc_srv_ctx_t **lftc_srv_ctx);
status_t lftc_srv_proc(knl_session_t *session, lftc_srv_ctx_t *lftc_srv_ctx);
void lftc_clt_close(knl_session_t *session);
status_t lftc_clt_create_task(knl_session_t *session, uint32 rst_id, uint32 asn,
    const char *arch_name, lftc_task_handle_t *handle);
bool32 lftc_clt_task_running(knl_session_t *session, lftc_task_handle_t *handle, bool32 *is_done);
#ifdef __cplusplus
}
#endif

#endif
