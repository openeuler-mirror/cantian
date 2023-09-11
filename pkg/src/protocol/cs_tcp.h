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
 * cs_tcp.h
 *
 *
 * IDENTIFICATION
 * src/protocol/cs_tcp.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CS_TCP_H__
#define __CS_TCP_H__

#include <stdio.h>
#include <errno.h>
#include "cm_defs.h"

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <mstcpip.h>
#include <Ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#define cs_close_socket   closesocket
#define cs_ioctl_socket   ioctlsocket
#define CS_INVALID_SOCKET ((socket_t)INVALID_SOCKET)
typedef ulong tcp_option_t;
typedef int32 socklen_t;
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
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/un.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <net/if.h>

#define cs_close_socket   close
#define cs_ioctl_socket   ioctl
#define CS_INVALID_SOCKET (-1)
typedef int32 tcp_option_t;
#endif

#include "cs_packet.h"
#include "cm_ip.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct st_tcp_link {
    socket_t sock; // need to be first!
    bool32 closed; // need to be second!
    sock_addr_t remote;
    sock_addr_t local;
} tcp_link_t;

typedef struct st_socket_attr_t {
    int32 connect_timeout;
    int32 l_onoff;
    int32 l_linger;
} socket_attr_t;

void cs_set_io_mode(socket_t sock, bool32 nonblock, bool32 nodelay);
void cs_set_buffer_size(socket_t sock, uint32 send_size, uint32 recv_size);
void cs_set_keep_alive(socket_t sock, uint32 idle, uint32 interval, uint32 count);
void cs_set_linger(socket_t sock, int32 l_onoff, int32 l_linger);

status_t cs_create_socket(int ai_family, socket_t *sock);
status_t cs_tcp_connect(const char *host, uint16 port, tcp_link_t *link, const char *bind_host, socket_attr_t *sock_attr);
bool32 cs_tcp_try_connect(const char *host, uint16 port);
void cs_tcp_disconnect(tcp_link_t *link);
void cs_shutdown_socket(socket_t sock);
status_t cs_tcp_send(tcp_link_t *link, const char *buf, uint32 size, int32 *send_size);
status_t cs_tcp_send_timed(tcp_link_t *link, const char *buf, uint32 size, uint32 timeout);
status_t cs_tcp_recv(tcp_link_t *link, char *buf, uint32 size, int32 *recv_size, uint32 *wait_event);
status_t cs_tcp_recv_timed(tcp_link_t *link, char *buf, uint32 size, uint32 timeout);
status_t cs_tcp_wait(tcp_link_t *link, uint32 wait_for, int32 timeout, bool32 *ready);
status_t cs_tcp_init(void);
status_t cs_tcp_poll(struct pollfd *fds, uint32 nfds, int32 timeout);
void cs_set_socket_timeout(socket_t sock, int32 timeout_left);
void cs_reset_socket_timeout(socket_t sock);
#ifdef __cplusplus
}
#endif

#endif
