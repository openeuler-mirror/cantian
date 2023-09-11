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
 * repl_msg.h
 *
 *
 * IDENTIFICATION
 * src/kernel/replication/repl_msg.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __REPL_MSG_H__
#define __REPL_MSG_H__

#include "cm_defs.h"
#include "cm_utils.h"
#include "cm_encrypt.h"
#include "cs_pipe.h"
#include "knl_log.h"

#ifdef __cplusplus
extern "C" {
#endif

#define REPL_HEART_BEAT_CHECK   (uint32)1 /* 1s -> 1000000 us */
#define REPL_RECV_TIMEOUT       (uint32)(15 * MILLISECS_PER_SECOND) /* 15s in ms */
#define REPL_WAIT_MULTI         (uint32)2
#define REPL_CONNECT_TIMEOUT    (uint32)10000 /* mill-seconds */
#define REPL_SOCKET_TIMEOUT     (uint32)60000 /* mill-seconds */

typedef enum e_rep_msg_type {
    REP_LOGIN_REQ = 0,
    REP_LOGIN_RESP = 1,
    REP_QUERY_STATUS_REQ = 2,
    REP_QUERY_STATUS_RESP = 3,
    REP_BATCH_REQ = 4,
    REP_BATCH_RESP = 5,
    REP_HEART_BEAT_REQ = 6,
    REP_HEART_BEAT_RESP = 7,
    REP_ARCH_REQ = 8,
    REP_ARCH_HEAD = 9,
    REP_ARCH_DATA = 10,
    REP_ARCH_TAIL = 11,
    REP_SWITCH_REQ = 12,
    REP_SWITCH_RESP = 13,
    REP_ARCH_LOST = 14,
    REP_ABR_REQ = 15,
    REP_ABR_RESP = 16,
    REP_RECORD_BACKUPSET_REQ = 17,
    REP_RECORD_BACKUPSET_RESP = 18,
    REP_LFTC_LZ4_DATA = 19,
    REP_LFTC_ZSTD_DATA = 20,
    REP_LOG_SWITCH_WAIT_REQ = 21 // from standby to primary
} rep_msg_type_t;

typedef enum e_rep_state {
    REP_STATE_NORMAL = 0,
    REP_STATE_DEMOTE_REQUEST = 1,
    REP_STATE_WAITING_DEMOTE = 2,
    REP_STATE_PRIMARY_DEMOTING = 3,
    REP_STATE_PROMOTE_APPROVE = 4,
    REP_STATE_STANDBY_PROMOTING = 5,
    REP_STATE_DEMOTE_FAILED = 6,
    REP_STATE_REJECTED = 7,
} rep_state_t;

typedef enum e_rep_login_type {
    REP_LOGIN_REPL = 0,
    REP_LOGIN_LFTC = 1,
    REP_LOGIN_BACKUP = 2,
} rep_login_type_t;

typedef enum en_query_status_version {
    ST_VERSION_0 = 0,
    ST_VERSION_1 = 1, // from this version, primary can notify standby of setting need repair
} query_status_version_t;

typedef struct st_rep_msg_header {
    uint32 size;
    uint32 type;
} rep_msg_header_t;

typedef struct st_rep_batch_req {
    uint32 log_file_id;
    log_point_t log_point;
    log_point_t curr_point;
    knl_scn_t scn;
    compress_algo_e compress_alg;
} rep_batch_req_t;

typedef struct st_rep_batch_resp {
    log_point_t flush_point;
    log_point_t rcy_point;
    uint64 replay_lsn;
    knl_scn_t flush_scn;
    knl_scn_t current_scn;
    log_point_t contflush_point;
} rep_batch_resp_t;

typedef struct st_rep_query_status_req {
    reset_log_t rst_log;
    log_point_t curr_point;
    uint32 log_num;
    bool32 is_standby;  // If true, peer will be set cascaded standby
    uint16 repl_port;   // sent to peer and be kept, used for lftc & build to connect
    uint16 version;
    uint32 dbid;
    bool32 notify_repair; // If true, peer will be set need repair
    uint32 reserved_field;
    knl_scn_t reset_log_scn;
    uint64 reserved[6];
} rep_query_status_req_t;

typedef struct st_rep_query_status_resp {
    log_point_t flush_point;
    log_point_t rcy_point;
    uint64 replay_lsn;
    bool32 is_ready;
    bool32 is_building_cascaded;  // whether is cascaded standby & is building
    bool32 is_building; // whether is building, do not care the build type is auto or specified
} rep_query_status_resp_t;

typedef struct st_rep_hb_resp {
    log_point_t flush_point;
    log_point_t rcy_point;
    uint64 replay_lsn;
    knl_scn_t flush_scn;
    knl_scn_t current_scn;
    log_point_t contflush_point;
} rep_hb_resp_t;

typedef struct st_rep_switch_resp {
    rep_state_t state;
} rep_switch_resp_t;

typedef struct st_rep_buffer {
    aligned_buf_t read_buf;
    volatile uint32 write_pos;
    volatile uint32 read_pos;
    uint32 illusion_count;
} rep_buffer_t;

typedef struct st_rep_abr_req {
    uint16 lsnd_id;
    uint16 file;
    uint32 page;
    uint32 blk_size;
} rep_abr_req_t;

typedef struct st_rep_abr_resp {
    uint16 lsnd_id;
    uint16 file;
    uint32 page;
} rep_abr_resp_t;

typedef enum en_rep_bak_status {
    BAK_TASK_DONE = 0,
    BAK_TASK_WAIT_PROCESS = 1,
    BAK_TASK_WAIT_RESPONSE = 2,
} rep_bak_status_t;

typedef struct st_rep_bak_task_t {
    volatile rep_bak_status_t status;
    bool32 failed;
    gs_errno_t error_no;
} rep_bak_task_t;

typedef struct st_rep_log_switch_wait {
    log_point_t wait_point;
    uint64 reserved[8];
} rep_log_switch_wait_t;

status_t knl_login(knl_session_t *session, cs_pipe_t *pipe, rep_login_type_t rep_type,
    const char *local_host, int32 *login_err);

/*
 * @\purpose close a established tcp/ssl connection and free SSL context
 * @\praval pipe TCP/SSL communication channel
 * @\retval none
 */
void knl_disconnect(cs_pipe_t *pipe);
status_t knl_encrypt_login_passwd(const char *plain_text, text_t *scramble_key, uint32 iter_count,
                                  salt_cipher_t *salt_cipher);
status_t knl_try_update_repl_cipher(knl_session_t *session, const char *plain);


#ifdef __cplusplus
}
#endif

#endif

