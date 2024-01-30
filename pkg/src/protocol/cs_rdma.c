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
 * cs_rdma.c
 *
 *
 * IDENTIFICATION
 * src/protocol/cs_rdma.c
 *
 * -------------------------------------------------------------------------
 */

#include "cs_rdma.h"
#include "cs_pipe.h"
#include "cm_signal.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WIN32

// IPPROTO_RDMA
// RDMA_NODELAY
void cs_rdma_set_io_mode(socket_t sock, bool32 nonblock, bool32 nodelay)
{
    rdma_option_t option;
    if (nonblock == 1) {
        cm_rdma_fcntl(sock, F_SETFL, O_NONBLOCK);
    }

    option = nodelay ? 1 : 0;
    (void)cm_rdma_setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&option, sizeof(option));
}

void cs_rdma_set_buffer_size(socket_t sock, uint32 send_size, uint32 recv_size)
{
    (void)cm_rdma_setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&send_size, sizeof(uint32));
    (void)cm_rdma_setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *)&recv_size, sizeof(uint32));
}

void cs_rdma_set_keep_alive(socket_t sock, uint32 idle, uint32 interval, uint32 count)
{
    rdma_option_t option;
    option = 1;

    (void)cm_rdma_setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&option, sizeof(int32));
    (void)cm_rdma_setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, (void *)&idle, sizeof(int32));
    (void)cm_rdma_setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, (void *)&interval, sizeof(int32));
    (void)cm_rdma_setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, (void *)&count, sizeof(int32));
}

void cs_rdma_set_linger(socket_t sock)
{
    struct linger so_linger;
    so_linger.l_onoff = 1;
    so_linger.l_linger = 1;
    (void)cm_rdma_setsockopt(sock, SOL_SOCKET, SO_LINGER, (char *)&so_linger, sizeof(struct linger));
}

int32 cs_rdma_poll(struct pollfd *fds, uint32 nfds, int32 timeout)
{
    int32 ret = cm_rdma_poll(fds, nfds, timeout);
    if (ret < 0 && EINTR == errno) {
        return 0;
    }
    return ret;
}

status_t cs_create_rdma_socket(int ai_family, socket_t *sock)
{
    /* try init signal for (SIGPIPE,SIG_IGN) */
    CT_RETURN_IFERR(cs_tcp_init());

    *sock = (socket_t)cm_rdma_socket(ai_family, SOCK_STREAM, 0);
    if (*sock == CS_INVALID_SOCKET) {
        CT_THROW_ERROR(ERR_CREATE_SOCKET, errno);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cs_rdma_connect(const char *host, uint16 port, rdma_link_t *link)
{
    CM_POINTER2(host, link);

    CT_RETURN_IFERR(cm_ipport_to_sockaddr(host, port, &link->remote));
    if (cs_create_rdma_socket(SOCKADDR_FAMILY(&link->remote), &link->sock) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cs_rdma_set_buffer_size(link->sock, CT_RSOCKET_DEFAULT_BUFFER_SIZE, CT_RSOCKET_DEFAULT_BUFFER_SIZE);
    if (0 != cm_rdma_connect(link->sock, SOCKADDR(&link->remote), link->remote.salen)) {
        cs_close_rdma_socket(link->sock);
        link->sock = CS_INVALID_SOCKET;
        link->closed = CT_TRUE;

        CT_THROW_ERROR(ERR_ESTABLISH_TCP_CONNECTION, host, (uint32)port, cm_get_os_error());
        return CT_ERROR;
    }

    cs_rdma_set_keep_alive(link->sock, CT_RSOCKET_KEEP_IDLE, CT_RSOCKET_KEEP_INTERVAL, CT_RSOCKET_KEEP_COUNT);
    cs_rdma_set_io_mode(link->sock, CT_TRUE, CT_TRUE);
    cs_rdma_set_linger(link->sock); /* it is likely that no use for rsocket */
    link->closed = CT_FALSE;
    return CT_SUCCESS;
}

bool32 cs_rdma_try_connect(const char *host, uint16 port)
{
    socket_t sock;
    bool32 result;
    sock_addr_t sock_addr;

    CM_POINTER(host);

    if (strlen(host) == 0) {
        return CT_FALSE;
    }

    if (cm_ipport_to_sockaddr(host, port, &sock_addr) != CT_SUCCESS) {
        return CT_FALSE;
    }

    sock = (socket_t)cm_rdma_socket(SOCKADDR_FAMILY(&sock_addr), SOCK_STREAM, 0);
    if (sock == CS_INVALID_SOCKET) {
        CT_THROW_ERROR(ERR_CREATE_SOCKET, errno);
        return CT_FALSE;
    }

    result = (0 == cm_rdma_connect(sock, SOCKADDR(&sock_addr), sock_addr.salen));
    cs_close_rdma_socket(sock);

    return result;
}

void cs_rdma_disconnect(rdma_link_t *link)
{
    CM_POINTER(link);

    if (link->closed) {
        CM_ASSERT(link->sock == CS_INVALID_SOCKET);
        return;
    }

    (void)cs_close_rdma_socket(link->sock);
    link->closed = CT_TRUE;
    link->sock = CS_INVALID_SOCKET;
}

status_t cs_rdma_wait(rdma_link_t *link, uint32 wait_for, int32 timeout, bool32 *ready)
{
    struct pollfd fd;
    int32 ret;
    int32 tv;

    if (ready != NULL) {
        *ready = CT_FALSE;
    }

    if (link->closed) {
        CT_THROW_ERROR(ERR_PEER_CLOSED, "rdma");
        return CT_ERROR;
    }

    tv = (timeout < 0 ? -1 : timeout);

    fd.fd = link->sock;
    fd.revents = 0;
    if (wait_for == CS_WAIT_FOR_WRITE) {
        fd.events = POLLOUT;
    } else {
        fd.events = POLLIN;
    }

    ret = cs_rdma_poll(&fd, 1, tv);
    if (ret > 0 && ((uint16)fd.revents & (POLLERR | POLLHUP))) {
        if (errno != EINTR) {
            CT_THROW_ERROR(ERR_PEER_CLOSED, "rdma");
            return CT_ERROR;
        }
        return CT_SUCCESS;
    } else if (ret >= 0) {
        if (ready != NULL) {
            // 'ready' doesn't change when 0 == ret and errno != EINTR
            *ready = (ret > 0 || (0 == ret && errno == EINTR));
        }
        return CT_SUCCESS;
    } else {
        CT_THROW_ERROR(ERR_PEER_CLOSED, "rdma");
        return CT_ERROR;
    }
}

status_t cs_rdma_send(rdma_link_t *link, const char *buf, uint32 size, int32 *send_size)
{
    int code;

    if (size == 0) {
        *send_size = 0;
        return CT_SUCCESS;
    }

    *send_size = cm_rdma_send(link->sock, buf, size, MSG_DONTWAIT);
    if (*send_size <= 0) {
        code = errno;
        if (errno == EWOULDBLOCK) {
            *send_size = 0;
            return CT_SUCCESS;
        }
        CT_THROW_ERROR(ERR_PEER_CLOSED_REASON, "rdma socket", code);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cs_rdma_send_timed(rdma_link_t *link, const char *buf, uint32 size, uint32 timeout)
{
    uint32 remain_size, offset;
    int32  writen_size;
    uint32 wait_interval = 0;
    bool32 ready;

    if (link->closed) {
        CT_THROW_ERROR(ERR_PEER_CLOSED, "rdma socket");
        return CT_ERROR;
    }

    /* must do wait, because rsocket only check peer status here, if peer is closed, wiil return ERROR here */
    if (cs_rdma_wait(link, CS_WAIT_FOR_WRITE, CT_POLL_WAIT, &ready) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* for most cases, all data are written by the following call */
    if (cs_rdma_send(link, buf, size, &writen_size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    remain_size = size - writen_size;
    offset = (uint32)writen_size;

    while (remain_size > 0) {
        if (cs_rdma_wait(link, CS_WAIT_FOR_WRITE, CT_POLL_WAIT, &ready) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!ready) {
            wait_interval += CT_POLL_WAIT;
            if (wait_interval >= timeout) {
                CT_THROW_ERROR(ERR_TCP_TIMEOUT, "rdma send data");
                return CT_ERROR;
            }

            continue;
        }

        if (cs_rdma_send(link, buf + offset, remain_size, &writen_size) != CT_SUCCESS) {
            return CT_ERROR;
        }

        remain_size -= writen_size;
        offset += writen_size;
    }

    return CT_SUCCESS;
}

/* cs_rdma_recv must following cs_rdma_wait */
status_t cs_rdma_recv(rdma_link_t *link, char *buf, uint32 size, int32 *recv_size, uint32 *wait_event)
{
    int32 rsize;

    if (size == 0) {
        *recv_size = 0;
        return CT_SUCCESS;
    }

    for (;;) {
        rsize = cm_rdma_recv(link->sock, buf, size, 0);
        if (rsize > 0) {
            break;
        }
        if (rsize == 0) {
            CT_THROW_ERROR(ERR_PEER_CLOSED, "rdma socket");
            return CT_ERROR;
        }
        if (cm_get_sock_error() == EINTR || cm_get_sock_error() == EAGAIN) {
            continue;
        }
        CT_THROW_ERROR(ERR_TCP_RECV, "rdma socket", cm_get_sock_error());
        return CT_ERROR;
    }
    *recv_size = rsize;
    return CT_SUCCESS;
}

/* cs_rdma_recv_timed must following cs_rdma_wait */
status_t cs_rdma_recv_timed(rdma_link_t *link, char *buf, uint32 size, uint32 timeout)
{
    uint32 remain_size, offset;
    uint32 wait_interval = 0;
    int32 recv_size;
    bool32 ready;

    remain_size = size;
    offset = 0;

    /* must do wait, because rsocket only check peer status here, if peer is closed, wiil return ERROR here */
    if (cs_rdma_wait(link, CS_WAIT_FOR_READ, CT_POLL_WAIT, &ready) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cs_rdma_recv(link, buf + offset, remain_size, &recv_size, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }

    remain_size -= recv_size;
    offset += recv_size;

    while (remain_size > 0) {
        if (cs_rdma_wait(link, CS_WAIT_FOR_READ, CT_POLL_WAIT, &ready) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!ready) {
            wait_interval += CT_POLL_WAIT;
            if (wait_interval >= timeout) {
                CT_THROW_ERROR(ERR_TCP_TIMEOUT, "rdma recv data");
                return CT_ERROR;
            }

            continue;
        }

        if (cs_rdma_recv(link, buf + offset, remain_size, &recv_size, NULL) != CT_SUCCESS) {
            return CT_ERROR;
        }

        remain_size -= recv_size;
        offset += recv_size;
    }

    return CT_SUCCESS;
}

#else

void cs_rdma_set_io_mode(socket_t sock, bool32 nonblock, bool32 nodelay)
{
    return;
}

void cs_rdma_set_buffer_size(socket_t sock, uint32 send_size, uint32 recv_size)
{
    return;
}

void cs_rdma_set_keep_alive(socket_t sock, uint32 idle, uint32 interval, uint32 count)
{
    return;
}

void cs_rdma_set_linger(socket_t sock)
{
    return;
}

status_t cs_create_rdma_socket(int ai_family, socket_t *sock)
{
    return CT_SUCCESS;
}

status_t cs_rdma_connect(const char *host, uint16 port, rdma_link_t *link)
{
    return CT_SUCCESS;
}

bool32 cs_rdma_try_connect(const char *host, uint16 port)
{
    return CT_TRUE;
}

void cs_rdma_disconnect(rdma_link_t *link)
{
    return;
}

status_t cs_rdma_send(rdma_link_t *link, const char *buf, uint32 size, int32 *send_size)
{
    return CT_SUCCESS;
}

status_t cs_rdma_send_timed(rdma_link_t *link, const char *buf, uint32 size, uint32 timeout)
{
    return CT_SUCCESS;
}

status_t cs_rdma_recv(rdma_link_t *link, char *buf, uint32 size, int32 *recv_size, uint32 *wait_event)
{
    return CT_SUCCESS;
}

status_t cs_rdma_recv_timed(rdma_link_t *link, char *buf, uint32 size, uint32 timeout)
{
    return CT_SUCCESS;
}

status_t cs_rdma_wait(rdma_link_t *link, uint32 wait_for, int32 timeout, bool32 *ready)
{
    return CT_SUCCESS;
}


#endif      // win32

#ifdef __cplusplus
}
#endif
