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
 * cs_rdma.h
 *
 *
 * IDENTIFICATION
 * src/protocol/cs_rdma.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CS_RDMA_H__
#define __CS_RDMA_H__

#include <stdio.h>
#include <errno.h>
#include "cm_defs.h"
#include "cm_rdma.h"

#ifdef WIN32

#else
#include <netdb.h>
#include <memory.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <fcntl.h>
#endif

#include "cs_packet.h"
#include "cm_ip.h"

#ifdef __cplusplus
extern "C" {
#endif

#define cs_close_rdma_socket            cm_rdma_close
#define RDMA_HOST_PREFIX                "RDMA@"
#define RDMA_HOST_PREFIX_LEN            5
/* rscoket ping is very low and gbp start at most 16 rsocket connections, so set buffer size small */
#define GS_RSOCKET_DEFAULT_BUFFER_SIZE  SIZE_K(128)
/* RSOCKET link cannot closed by system when process exit, so set keep idle short and reset peer state early */
#define GS_RSOCKET_KEEP_IDLE            (uint32)2
#define GS_RSOCKET_KEEP_INTERVAL        (uint32)1
#define GS_RSOCKET_KEEP_COUNT           (uint32)2

typedef struct st_rdma_link {
    socket_t sock; // need to be first!
    bool32 closed; // need to be second!
    sock_addr_t remote;
    sock_addr_t local;
} rdma_link_t;

typedef int32 rdma_option_t;

void cs_rdma_set_io_mode(socket_t sock, bool32 nonblock, bool32 nodelay);
void cs_rdma_set_buffer_size(socket_t sock, uint32 send_size, uint32 recv_size);
void cs_rdma_set_keep_alive(socket_t sock, uint32 idle, uint32 interval, uint32 count);
void cs_rdma_set_linger(socket_t sock);

status_t cs_create_rdma_socket(int ai_family, socket_t *sock);
status_t cs_rdma_connect(const char *host, uint16 port, rdma_link_t *link);
bool32 cs_rdma_try_connect(const char *host, uint16 port);
void cs_rdma_disconnect(rdma_link_t *link);
status_t cs_rdma_send(rdma_link_t *link, const char *buf, uint32 size, int32 *send_size);
status_t cs_rdma_send_timed(rdma_link_t *link, const char *buf, uint32 size, uint32 timeout);
status_t cs_rdma_recv(rdma_link_t *link, char *buf, uint32 size, int32 *recv_size, uint32 *wait_event);
status_t cs_rdma_recv_timed(rdma_link_t *link, char *buf, uint32 size, uint32 timeout);
status_t cs_rdma_wait(rdma_link_t *link, uint32 wait_for, int32 timeout, bool32 *ready);


#ifdef __cplusplus
}
#endif

#endif
