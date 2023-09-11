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
 * repl_log_send.h
 *
 *
 * IDENTIFICATION
 * src/kernel/replication/repl_log_send.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __REPL_LOG_SEND_H__
#define __REPL_LOG_SEND_H__

#include "cm_defs.h"
#include "cs_pipe.h"
#include "knl_log.h"
#include "repl_msg.h"
#include "knl_archive.h"
#include "knl_page.h"
#include "bak_common.h"
#include "knl_buffer_access.h"

#define REMAIN_BUFSZ(buf)       ((buf)->read_buf.buf_size - (buf)->write_pos)
#define INVALID_FILE_HANDLE     (-1)
#define INVALID_FLUSH_LAG       (-1)
#define ABR_MAX_TIMEOUT         3600

typedef enum en_lsnd_status {
    LSND_DISCONNECTED = 0,
    LSND_STATUS_QUERYING = 1,
    LSND_LOG_SHIFTING = 2,
} lsnd_status_e;

typedef struct st_lsnd_arch_file {
    int32 handle;
    uint32 asn;
    char file_name[GS_FILE_NAME_BUFFER_SIZE];
    uint32 block_size;
    uint64 write_pos;
} lsnd_arch_file_t;

typedef struct st_dest_info {
    uint32 attr_idx; // identify the index in all of LOG_ARCHIVE_DEST_n
    char local_host[GS_HOST_NAME_BUFFER_SIZE];
    char peer_host[GS_HOST_NAME_BUFFER_SIZE];
    uint16 peer_port;
    net_trans_mode_t sync_mode;
    arch_affirm_t affirm_mode;
    compress_algo_e compress_alg;
} dest_info_t;

typedef struct st_lsnd_bak_task {
    spinlock_t lock;
    rep_bak_task_t task;
    bak_record_t record;
} lsnd_bak_task_t;

typedef struct st_compress_ctx {
    ZSTD_CCtx *zstd_cctx;
    uint32 buf_size;
    aligned_buf_t compress_buf;
    uint32 data_size;
} compress_ctx;

typedef struct st_lsnd_abr_task_t {
    spinlock_t lock;
    uint16 lsnd_id;
    uint16 file;
    uint32 page;
    char *buf;
    uint32 buf_size;
    bool32 running;
    bool32 executing;
    bool32 succeeded;
    time_t timestamp;
} lsnd_abr_task_t;

typedef struct st_lsnd {
    spinlock_t lock;
    uint32 id;
    thread_t thread;
    cm_thread_cond_t cond;
    cs_pipe_t pipe;
    log_point_t send_point;
    log_point_t last_put_point;
    log_point_t peer_flush_point;
    log_point_t peer_contflush_point;
    log_point_t peer_rcy_point;
    uint64 peer_replay_lsn;
    knl_scn_t peer_flush_scn;
    knl_scn_t peer_current_scn;
    rep_buffer_t send_buf;
    compress_ctx c_ctx;
    rep_buffer_t recv_buf;
    char *extra_head;       // only for async log send: rep_msg_header_t + rep_batch_req_t)
    uint32 header_size;     // sizeof(rep_msg_header_t) + sizeof(rep_batch_req_t)
    cs_packet_t recv_pack;  // only for login
    cs_packet_t send_pack;  // only for login
    knl_session_t *session;
    volatile lsnd_status_e status;
    rep_state_t state;
    dest_info_t dest_info;
    uint32 timeout;
    bool32 flush_completed;
    bool32 in_async;
    volatile bool32 tmp_async;
    time_t last_send_time;
    time_t last_recv_time;
    int32 log_handle[GS_MAX_LOG_FILES];
    lsnd_arch_file_t arch_file;
    int32 last_read_file_id;
    uint32 last_read_asn;
    bool32 resetid_changed_reconnect;
    bool32 host_changed_reconnect;
    bool32 is_deferred;  // if true, this log sender will be closed
    lsnd_abr_task_t abr_task;
    lsnd_bak_task_t bak_task;
    bool32 peer_is_building;
    volatile bool32 is_disable;
    log_point_t wait_point;
    bool32 notify_repair; // if true, primary will notify standby to set need repair
} lsnd_t;

typedef struct st_lsnd_context {
    latch_t latch;
    uint16 standby_num;
    uint16 est_standby_num;
    uint16 est_sync_standby_num;
    uint16 affirm_standy_num; // all the standby set with sync & affirm
    uint16 est_affirm_standy_num; // established standby set with sync & affirm
    uint32 quorum_any;
    lsnd_t *lsnd[GS_MAX_PHYSICAL_STANDBY];
    cm_thread_eventfd_t eventfd;
} lsnd_context_t;

static void inline lsnd_eventfd_init(lsnd_context_t *ctx)
{
    ctx->eventfd.efd = -1;
    ctx->eventfd.epfd = -1;
}

status_t lsnd_init(knl_session_t *session);
void lsnd_close_disabled_thread(knl_session_t *session);
void lsnd_close_all_thread(knl_session_t *session);

void lsnd_wait(knl_session_t *session, uint64 curr_lfn, uint64 *quorum_lfn);
void lsnd_flush_log(knl_session_t *session, log_context_t *redo_ctx, log_file_t *file, log_batch_t *batch);

status_t lsnd_open_specified_logfile(knl_session_t *session, uint32 slot);
void lsnd_close_specified_logfile(knl_session_t *session, uint32 slot);
void lsnd_get_min_contflush_point(lsnd_context_t *ctx, log_point_t *cont_point);
void lsnd_get_max_flush_point(knl_session_t *session, log_point_t *max_flush_point, bool32 need_lock);
void lsnd_mark_reconnect(knl_session_t *session, bool32 resetid_changed, bool32 host_changed);
void lsnd_get_sync_info(knl_session_t *session, ha_sync_info_t *ha_sync_info);
void lsnd_reset_state(knl_session_t *session);
void lsnd_trigger_task_response(knl_session_t *session, uint32 lsnd_id, bool32 failed);

status_t lsnd_check_protection_standby_num(knl_session_t *session);

#endif
