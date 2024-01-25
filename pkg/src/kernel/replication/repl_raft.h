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
 * repl_raft.h
 *
 *
 * IDENTIFICATION
 * src/kernel/replication/repl_raft.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __REPL_RAFT_H__
#define __REPL_RAFT_H__

#include "cm_defs.h"
#include "cm_raft.h"
#include "cm_log.h"
#include "knl_log.h"
#include "knl_session.h"
#include "knl_database.h"
#include "knl_interface.h"


#define RAFT_ASYNC_BUFFER_MARGIN      32
#define RAFT_ASYNC_LOG_NEXT(ctx, pos) (((pos) + 1) % (ctx)->logwr_async_buf_num)


#ifndef WIN32
#define DB_IS_RAFT_ENABLED(kernel) ((kernel)->attr.enable_raft)
#else
#define DB_IS_RAFT_ENABLED(kernel) (CT_FALSE)
#endif

#define RAFT_IS_RESTORE_PRIMARY(kernel) (DB_IS_RAFT_ENABLED(kernel) && (kernel)->attr.raft_start_mode == 1)
#define RAFT_DEFAULT_INDEX              5
#define DB_IS_RAFT_INITED(kernel)       (DB_IS_RAFT_ENABLED(kernel) && (kernel)->raft_ctx.status >= RAFT_STATUS_INITED)

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_raft_status {
    RAFT_STATUS_STARTING = 0,
    RAFT_STATUS_INITED = 1,
    RAFT_STATUS_CLOSING = 2,
} raft_status_t;

typedef struct st_raft_context {
    raft_status_t status;
    uint16 log_block_size;

    log_point_t recv_point;
    raft_point_t raft_recv_point;

    log_point_t flush_point;
    raft_point_t raft_flush_point;
    raft_point_t saved_raft_flush_point;

    uint64 commit_lfn;
    uint64 sent_lfn;

    char *logwr_async_buf;                      // for log flush async
    char *logwr_head_buf;                       // flush file head
    volatile uint32 logwr_async_buf_flush_pos;  // wait to be flushed to disk
    volatile uint32 logwr_async_buf_raft_pos;   // wait to be consensus by raft
    volatile uint32 logwr_async_buf_write_pos;  // wait to be async write to
    uint32 logwr_async_buf_size;                // total async buffer size
    uint32 logwr_async_buf_num;                 // async buffer number in slot size
    uint32 logwr_async_buf_slot_size;           // async buffer slot size
    uint32 logwr_head_buf_size;                 // buffer to hold file ctrl head
    spinlock_t raft_lock;                       // for raft callback synchronization
    spinlock_t raft_write_disk_lock;            // for raft to write to disk
    raft_procs_t raft_proc;
    cm_thread_cond_t cond;
    repl_role_t old_role;
    char priority_type[CT_FILE_NAME_BUFFER_SIZE];
    char priority_level[CT_FILE_NAME_BUFFER_SIZE];
    char layout_info[CT_FILE_NAME_BUFFER_SIZE];
} raft_context_t;

status_t raft_flush_log(knl_session_t *session, log_batch_t *batch);
status_t raft_db_start_follower(knl_session_t *session, repl_role_t old_role);
status_t raft_db_start_leader(knl_session_t *session);
void raft_pending_switch_request(knl_session_t *session, switch_ctrl_t *ctrl);
void raft_stop_consistency(knl_session_t *session);

void log_async_proc(thread_t *thread);
void raft_reset_async_buffer(raft_context_t *raft_ctx);
void raft_wait_for_log_flush(knl_session_t *session, uint64 end_lfn);
status_t raft_write_to_async_buffer_num(knl_session_t *session, log_batch_t *batch, log_batch_t **new_batch);
void raft_wait_for_batch_commit_in_raft(knl_session_t *session, uint64 lfn);
void raft_async_log_buf_init(knl_session_t *session);
void raft_log_flush_async_head(raft_context_t *raft_ctx, log_file_t *file);
bool32 raft_is_primary_alive(knl_session_t *session);
status_t raft_load(knl_session_t *session);
void log_flush_init_for_raft(knl_session_t *session, uint32 batch_size);
status_t raft_check_log_size(knl_session_t *session);

#ifdef __cplusplus
}
#endif

#endif
