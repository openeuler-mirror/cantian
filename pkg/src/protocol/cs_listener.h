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
 * cs_listener.h
 *
 *
 * IDENTIFICATION
 * src/protocol/cs_listener.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CS_LISTENER_H__
#define __CS_LISTENER_H__

#include "cm_defs.h"
#include "cm_thread.h"
#include "cs_tcp.h"
#include "cs_ipc.h"
#include "cs_pipe.h"
#include "cs_uds.h"
#include "cs_rdma.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_lsnr_type {
    LSNR_TYPE_MANAGER,
    LSNR_TYPE_SERVICE,
    LSNR_TYPE_REPLICA,
    LSNR_TYPE_UDS,
    LSNR_TYPE_MES,
    LSNR_TYPE_ALL,
} lsnr_type_t;

typedef enum en_lsnr_status {
    LSNR_STATUS_RUNNING,
    LSNR_STATUS_PAUSING,
    LSNR_STATUS_PAUSED,
    LSNR_STATUS_STOPPED,
} lsnr_status_t;

typedef struct st_tcp_lsnr tcp_lsnr_t;
typedef status_t (*connect_action_t)(tcp_lsnr_t *lsnr, cs_pipe_t *pipe);

typedef struct st_tcp_lsnr {
    spinlock_t lock;
    lsnr_type_t type;
    lsnr_status_t status;
    char host[GS_MAX_LSNR_HOST_COUNT][CM_MAX_IP_LEN];
    uint16 port;
    int epoll_fd;       // for listened sockets
    atomic_t sock_count;  // may listen on multiple IP address
    socket_t socks[GS_MAX_LSNR_HOST_COUNT];
    thread_t thread;
    connect_action_t action;  // action when a connect accepted
} tcp_lsnr_t;

typedef struct st_rdma_lsnr rdma_lsnr_t;
typedef status_t(*rdma_connect_action_t)(rdma_lsnr_t *lsnr, cs_pipe_t *pipe);

typedef struct st_rdma_lsnr {
    spinlock_t lock;
    lsnr_type_t type;
    lsnr_status_t status;
    char host[CM_MAX_IP_LEN]; // only support one listenning host ip
    uint16 port;
    socket_t sock;
    thread_t thread;
    rdma_connect_action_t action;  // action when a connect accepted
} rdma_lsnr_t;

typedef struct st_ipc_lsnr {
    thread_t lsnr_thr;
    thread_t smon_thr;

    ipc_shm_t shm;

    ipc_lsnr_ctrl_t *ctrl;
    ipc_app_t *apps;
    ipc_room_t *rooms;
    uint64 gpid; /* global pipe id */
} ipc_lsnr_t;

typedef struct st_uds_lsnr uds_lsnr_t;
typedef status_t (*uds_connect_action_t)(uds_lsnr_t *lsnr, cs_pipe_t *pipe);
typedef struct st_uds_lsnr {
    lsnr_type_t type;
    thread_t thread;
    int epoll_fd;
    lsnr_status_t status;
    char names[GS_MAX_LSNR_HOST_COUNT][GS_UNIX_PATH_MAX];
    socket_t socks[GS_MAX_LSNR_HOST_COUNT];
    uint32 permissions;
    atomic_t sock_count;  // may listen on multiple uds file
    uds_connect_action_t action;  // action when a connect accepted
    bool32 is_emerg;
} uds_lsnr_t;

status_t cs_start_tcp_lsnr(tcp_lsnr_t *lsnr, connect_action_t action, bool32 is_replica);
status_t cs_start_ssl_lsnr(tcp_lsnr_t *lsnr, connect_action_t action, bool32 is_replica);
void cs_stop_tcp_lsnr(tcp_lsnr_t *lsnr);
void cs_resume_tcp_lsnr(tcp_lsnr_t *lsnr);

// 1. set the status of listener to LSNR_STATUS_PAUSING
// 2. it is the duty of routine to set the status to LSNR_STATUS_PAUSED
// 3. wait until status is set to LSNR_STATUS_PAUSED
void cs_pause_tcp_lsnr(tcp_lsnr_t *lsnr);
status_t cs_add_lsnr_ipaddr(tcp_lsnr_t *lsnr, const char* ip_addr, int32 *slot_id);
status_t cs_delete_lsnr_slot(tcp_lsnr_t *lsnr, int32 slot_id);
status_t cs_strcat_host(tcp_lsnr_t* lsnr, char* str_output, int32 str_len);
status_t cs_create_lsnr_socks(tcp_lsnr_t *lsnr, bool32 is_replica);
status_t cs_lsnr_init_epoll_fd(tcp_lsnr_t *lsnr);
void cs_close_lsnr_socks(tcp_lsnr_t *lsnr);
void cs_try_tcp_accept(tcp_lsnr_t *lsnr, cs_pipe_t *pipe);

status_t cs_start_uds_lsnr(uds_lsnr_t *lsnr, uds_connect_action_t action);
void cs_pause_uds_lsnr(uds_lsnr_t *lsnr);
void cs_resume_uds_lsnr(uds_lsnr_t *lsnr);
void cs_stop_uds_lsnr(uds_lsnr_t *lsnr);

status_t cs_create_rdma_lsnr(rdma_lsnr_t *lsnr);
void cs_close_rdma_lsnr(rdma_lsnr_t *lsnr);
void cs_try_rdma_accept(rdma_lsnr_t *lsnr, cs_pipe_t *pipe);

#ifdef __cplusplus
}
#endif

#endif
