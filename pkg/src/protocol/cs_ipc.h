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
 * cs_ipc.h
 *
 *
 * IDENTIFICATION
 * src/protocol/cs_ipc.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CS_IPC_H__
#define __CS_IPC_H__

#include <stdio.h>
#include <errno.h>

#ifdef WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>
#endif

#include "cm_defs.h"
#include "cm_list.h"
#include "cm_thread.h"
#include "cs_packet.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IPC_SEM_WIN32_HANDLES 2 /* server/client */

typedef enum en_ipc_side {
    IPC_SIDE_SERVER = 0,
    IPC_SIDE_CLIENT = 1,
} ipc_side_t;

typedef struct st_ipc_sem {
#ifdef WIN32
    uint32 id;
    HANDLE handles[IPC_SEM_WIN32_HANDLES]; /* 1 handle for client,  1 handle for server */
#else
    pthread_mutex_t mutex;
#endif
} ipc_sem_t;

typedef struct st_ipc_shm {
    int32 id;
    char *addr;
} ipc_shm_t;

typedef enum st_ipc_status {
    IPC_STATUS_CLOSED = 0, /* have not init, or already closed */
    IPC_STATUS_IDLE,       /* idle */
    IPC_STATUS_BUSY,       /* busy */
} ipc_status_t;

typedef struct st_ipc_room {
    uint64 gpid;
    ipc_status_t status;
    bool32 is_timeout;
    bool32 used;
    uint32 app_id;
    void *node; /* address of node of service in server */
    ipc_sem_t server_sem;
    ipc_sem_t client_sem;
    char buf[CT_MAX_PACKET_SIZE];
} ipc_room_t;

typedef struct st_ipc_link_t {
    uint32 id;
    uint64 gpid; /* global pipe id */
    ipc_side_t side;
    volatile ipc_status_t status;
    ipc_room_t *room;
    void *master;
} ipc_link_t;

typedef struct st_ipc_token {
    uint64 gpid;
    int32 code;
    uint32 room_id;
    uint32 offset;
    char message[CT_MESSAGE_BUFFER_SIZE];
} ipc_token_t;

typedef struct st_ipc_process {
    uint64 pid;                          /* process id */
    char name[CT_FILE_NAME_BUFFER_SIZE]; /* process name */
    int64 start_time;                    /* the start time of the process */
} ipc_process_t;

typedef struct st_ipc_lsnr_request {
    uint32 cmd;
    uint32 app_id;
    ipc_process_t client_info;
} ipc_lsnr_request_t;

typedef struct tagcs_ipc_lsnr_ctrl {
    spinlock_t lock;
    ipc_process_t server_info; /* information of the server process */
    volatile uint32 lock_ticks;
    volatile uint32 server_ticks;
    ipc_sem_t lsnr_sem;
    ipc_sem_t ntfy_sem;
    ipc_lsnr_request_t request;
    ipc_token_t token;
    bool32 ready;
} ipc_lsnr_ctrl_t;

typedef struct st_ipc_app {
    volatile uint32 status;
    volatile uint32 last_ticks;
    volatile uint32 curr_ticks;
    ipc_process_t client_info; /* information of the client process */
} ipc_app_t;

typedef struct st_ipc_context {
    spinlock_t lock;
    bool32 initialized;
    uint32 busy_flag;
    uint32 link_count;
    list_t links;
    thread_t monitor;
    uint32 app_id;
    int64 server_pid; /* record the pid to check the server alive */
    int64 start_time; /* the time(wpageows)/ticks(linux) when server starting */
    ipc_shm_t lsnr_shm;
    ipc_lsnr_ctrl_t *lsnr_ctrl;
    ipc_app_t *app;
} ipc_context_t;

#define IPC_NOTIFY_TIMEOUT 10

#define IPC_LSNR_REG_APP    1
#define IPC_LSNR_UNREG_APP  2
#define IPC_LSNR_ALLOC_LINK 3

#define IPC_CHECK_TICKS         3
#define IPC_TICK_INTEVAL        10
#define IPC_EXPECTED_PEER_TICKS 1
#define IPC_SPIN_DELAY          3000
#define IPC_SHM_ID              1

int32 cs_ipc_connect(ipc_link_t *link, const char *ipc_name);
int32 cs_ipc_read_pack(ipc_link_t *link, cs_packet_t *pack, uint32 timeout);
int32 cs_ipc_write_pack(ipc_link_t *link, cs_packet_t *pack, uint32 timeout);
void cs_ipc_disconnect(ipc_link_t *link);
void cs_ipc_close_notify(ipc_link_t *link);

int32 cs_create_sem(ipc_sem_t *sem, ipc_side_t  side);
void cs_destroy_sem(ipc_sem_t *sem, ipc_side_t  side);
int32 cs_attach_sem(ipc_sem_t *sem, ipc_side_t  side);
void cs_detach_sem(ipc_sem_t *sem, ipc_side_t  side);
void cs_sem_p(ipc_sem_t *sem, ipc_side_t  side);
bool32 cs_sem_timed_p(ipc_sem_t *sem, ipc_side_t  side, uint32 timeout);
void cs_sem_v(ipc_sem_t *sem, ipc_side_t  side);

status_t cs_create_shm(ipc_shm_t *shm, const char *ipc_name);
void cs_destroy_shm(ipc_shm_t *shm);
int32 cs_attach_shm(ipc_shm_t *shm, const char *ipc_name);
void cs_detach_shm(ipc_shm_t *shm);

#ifdef __cplusplus
}
#endif

#endif
