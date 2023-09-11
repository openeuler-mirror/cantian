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
 * cs_tcp.c
 *
 *
 * IDENTIFICATION
 * src/protocol/cs_tcp.c
 *
 * -------------------------------------------------------------------------
 */
#include "cs_tcp.h"
#include "cs_pipe.h"
#include "cm_signal.h"

#ifdef __cplusplus
extern "C" {
#endif


static spinlock_t g_tcp_init_lock = 0;
static volatile bool32 g_tcp_inlockized = 0;

#ifdef WIN32
#define NEED_RECHECK_TCP(error_no) ((error_no) == EINPROGRESS || (error_no) == EINTR || (error_no) == EWOULDBLOCK ||  \
    (error_no) == WSAEWOULDBLOCK)
#else
#define NEED_RECHECK_TCP(error_no) ((error_no) == EINPROGRESS || (error_no) == EINTR)
#endif

status_t cs_tcp_init(void)
{
    GS_RETSUC_IFTRUE(g_tcp_inlockized);

    cm_spin_lock(&g_tcp_init_lock, NULL);

    if (g_tcp_inlockized) {
        cm_spin_unlock(&g_tcp_init_lock);
        return GS_SUCCESS;
    }

#ifdef WIN32
    struct WSAData wd;
    uint16 version = MAKEWORD(1, 1);
    if (0 != WSAStartup(version, &wd)) {
        cm_spin_unlock(&g_tcp_init_lock);
        GS_THROW_ERROR(ERR_INIT_NETWORK_ENV, "failed to start up Windows Sockets Asynchronous");
        return GS_ERROR;
    }

#else
    if (GS_SUCCESS != cm_regist_signal(SIGPIPE, SIG_IGN)) {
        cm_spin_unlock(&g_tcp_init_lock);
        GS_THROW_ERROR(ERR_INIT_NETWORK_ENV, "can't assign function for SIGPIPE ");
        return GS_ERROR;
    }
#endif
    g_tcp_inlockized = GS_TRUE;
    cm_spin_unlock(&g_tcp_init_lock);
    return GS_SUCCESS;
}

void cs_set_io_mode(socket_t sock, bool32 nonblock, bool32 nodelay)
{
    tcp_option_t option;
    option = nonblock ? 1 : 0;
    (void)cs_ioctl_socket(sock, FIONBIO, &option);

    option = nodelay ? 1 : 0;
    (void)setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&option, sizeof(option));
}

void cs_set_buffer_size(socket_t sock, uint32 send_size, uint32 recv_size)
{
    (void)setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&send_size, sizeof(uint32));
    (void)setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *)&recv_size, sizeof(uint32));
}

void cs_set_socket_timeout(socket_t sock, int32 timeout_left)
{
    int32 time_out = timeout_left;
    if (time_out == -1 || time_out == 0) {
        return;
    }
    time_out = time_out / GS_TIME_THOUSAND_UN;

    struct timeval tv = { time_out, 0 };
    (void)setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));
    (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
}

void cs_reset_socket_timeout(socket_t sock)
{
    struct timeval tv = { 0, 0 };
    (void)setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));
    (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
}

void cs_set_keep_alive(socket_t sock, uint32 idle, uint32 interval, uint32 count)
{
#ifdef WIN32
    struct tcp_keepalive vals;
    DWORD bytes;

    vals.keepaliveinterval = interval * MILLISECS_PER_SECOND;
    vals.keepalivetime = idle * MILLISECS_PER_SECOND;
    vals.onoff = 1;
    (void)WSAIoctl(sock, SIO_KEEPALIVE_VALS, &vals, sizeof(vals), NULL, 0, &bytes, NULL, NULL);
#else
    tcp_option_t option;
    option = 1;

    (void)setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&option, sizeof(int32));
    (void)setsockopt(sock, SOL_TCP, TCP_KEEPIDLE, (void *)&idle, sizeof(int32));
    (void)setsockopt(sock, SOL_TCP, TCP_KEEPINTVL, (void *)&interval, sizeof(int32));
    (void)setsockopt(sock, SOL_TCP, TCP_KEEPCNT, (void *)&count, sizeof(int32));

#endif
}

void cs_set_linger(socket_t sock, int32 l_onoff, int32 l_linger)
{
    struct linger so_linger;
    so_linger.l_onoff = l_onoff;
    so_linger.l_linger = l_linger;
    (void)setsockopt(sock, SOL_SOCKET, SO_LINGER, (char *)&so_linger, sizeof(struct linger));
}

void cs_tcp_poll_set_fd(struct pollfd *fds, uint32 nfds, fd_set *wfds, fd_set *rfds, fd_set *efds)
{
    uint32 i = 0;
    struct pollfd *pfds = fds;
    for (i = 0; i < nfds; i++, pfds++) {
        if ((uint16)(pfds->events) & POLLIN) {
            FD_SET(pfds->fd, rfds);
        }

        if ((uint16)(pfds->events) & POLLOUT) {
            FD_SET(pfds->fd, wfds);
        }

        FD_SET(pfds->fd, efds);
    }
}

void cs_tcp_poll_set_event(struct pollfd *pfds, uint32 nfds, fd_set *wfds, fd_set *rfds, fd_set *efds)
{
    uint32 i = 0;
    for (i = 0; i < nfds; i++, pfds++) {
        pfds->revents = 0;
        if ((uint16)(pfds->events) & POLLIN) {
            if (FD_ISSET(pfds->fd, rfds)) {
                pfds->revents = (uint16)(pfds->events) | POLLIN;
            }
        }

        if ((uint16)(pfds->events) & POLLOUT) {
            if (FD_ISSET(pfds->fd, wfds)) {
                pfds->revents = (uint16)(pfds->events) | POLLOUT;
            }
        }

        if (FD_ISSET(pfds->fd, efds)) {
            pfds->revents = POLLERR;
        }
    }
}

int32 cs_tcp_poll(struct pollfd *fds, uint32 nfds, int32 timeout)
{
#ifndef WIN32
    int32 ret = poll(fds, nfds, timeout);
    if (ret < 0 && EINTR == errno) {
        return 0;
    }
    return ret;
#else
    int32 ret = 0;
    fd_set wfds;
    fd_set rfds;
    fd_set efds;
    uint32 i = 0;
    struct pollfd *pfds = fds;
    struct timeval tv, *tvptr = NULL;
    if (nfds >= FD_SETSIZE) {
        GS_THROW_ERROR_EX(ERR_ASSERT_ERROR, "nfds(%u) < FD_SETSIZE(%u)", nfds, (uint32)FD_SETSIZE);
        return GS_ERROR;
    }

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&efds);
    if (timeout >= 0) {
        tv.tv_sec = timeout / GS_TIME_THOUSAND_UN;
        tv.tv_usec = (timeout % GS_TIME_THOUSAND_UN) * GS_TIME_THOUSAND_UN;
        tvptr = &tv;
    }

    cs_tcp_poll_set_fd(pfds, nfds, &wfds, &rfds, &efds);

    ret = select(0, &rfds, &wfds, &efds, tvptr);
    if (ret <= 0) {
        return (ret < 0 && EINTR == errno) ? 0 : ret;
    }

    pfds = fds;
    cs_tcp_poll_set_event(pfds, nfds, &wfds, &rfds, &efds);
    return ret;
#endif
}

status_t cs_create_socket(int ai_family, socket_t *sock)
{
    GS_RETURN_IFERR(cs_tcp_init());

    *sock = (socket_t)socket(ai_family, SOCK_STREAM, 0);
    if (*sock == CS_INVALID_SOCKET) {
        GS_THROW_ERROR(ERR_CREATE_SOCKET, errno);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

int32 cs_socket_poll_check(struct pollfd *fds, uint32 nfds, int32 timeout)
{
#ifndef WIN32
    return poll(fds, nfds, timeout);
#else
    fd_set wfds;
    fd_set rfds;
    fd_set efds;
    struct pollfd *pfds = fds;
    struct timeval tv, *tvptr = NULL;

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&efds);
    if (timeout >= 0) {
        tv.tv_sec = timeout / GS_TIME_THOUSAND_UN;
        tv.tv_usec = (timeout % GS_TIME_THOUSAND_UN) * GS_TIME_THOUSAND_UN;
        tvptr = &tv;
    }

    cs_tcp_poll_set_fd(pfds, nfds, &wfds, &rfds, &efds);

    return (int32)select(pfds->fd + 1, &rfds, &wfds, &efds, tvptr);
#endif
}

int32 cs_tcp_poll_check(tcp_link_t *link, uint32 wait_for, time_t end_time)
{
    struct pollfd fd;
    int32 tv;
    time_t now = cm_current_time();

    if (end_time < 0) {
        tv = -1;
    } else {
        if (end_time > now) {
            tv = (int32)((end_time - now) * MILLISECS_PER_SECOND);
        } else {
            tv = 0;
        }
    }

    fd.fd = link->sock;
    fd.revents = 0;
    if (wait_for == CS_WAIT_FOR_WRITE) {
        fd.events = POLLOUT;
    } else {
        fd.events = POLLIN;
    }

    return cs_socket_poll_check(&fd, 1, tv);
}

status_t cs_tcp_connect_wait(tcp_link_t *link, int32 error_no, time_t end_time)
{
    int32 ret = -1;
    int32 opt_val;
    int32 opt_len = sizeof(opt_val);
    if (NEED_RECHECK_TCP(error_no)) {
        do {
            ret = cs_tcp_poll_check(link, CS_WAIT_FOR_WRITE, end_time);
        } while (ret < 0 && errno == EINTR);
    }
    if (ret <= 0) {
        return GS_ERROR;
    }
    ret = getsockopt(link->sock, SOL_SOCKET, SO_ERROR, (char *)&opt_val, (socklen_t *)&opt_len);
    if (ret < 0 || opt_val != 0) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t cs_tcp_connect_core(tcp_link_t *link, socket_attr_t *sock_attr)
{
    int32 ret;
    int32 error_no;
    time_t end_time;
    ret = connect(link->sock, SOCKADDR(&link->remote), link->remote.salen);
    if (ret < 0) {
        if (sock_attr->connect_timeout < 0) {
            end_time = -1;
        } else {
            end_time = cm_current_time() + sock_attr->connect_timeout / MILLISECS_PER_SECOND;
        }
        error_no = cm_get_os_error();
        if (cs_tcp_connect_wait(link, error_no, end_time) == GS_SUCCESS) {
            ret = 0;
        }
    }
    
    return ret == 0 ? GS_SUCCESS : GS_ERROR;
}

status_t cs_tcp_connect(const char *host, uint16 port, tcp_link_t *link, const char *bind_host,
    socket_attr_t *sock_attr)
{
    CM_POINTER2(host, link);

    GS_RETURN_IFERR(cm_ipport_to_sockaddr(host, port, &link->remote));

    GS_RETURN_IFERR(cs_create_socket(SOCKADDR_FAMILY(&link->remote), &link->sock));

    if (bind_host != NULL && bind_host[0] != '\0') {
        if (cm_ipport_to_sockaddr(bind_host, 0, &link->local) != GS_SUCCESS) {
            cs_close_socket(link->sock);
            link->sock = CS_INVALID_SOCKET;
            link->closed = GS_TRUE;
            return GS_ERROR;
        }

        if (bind(link->sock, SOCKADDR(&link->local), link->local.salen) != 0) {
            cs_close_socket(link->sock);
            link->sock = CS_INVALID_SOCKET;
            link->closed = GS_TRUE;
            GS_THROW_ERROR(ERR_SOCKET_BIND, bind_host, (uint32)0, cm_get_os_error());
            return GS_ERROR;
        }
    }

    cs_set_buffer_size(link->sock, GS_TCP_DEFAULT_BUFFER_SIZE, GS_TCP_DEFAULT_BUFFER_SIZE);
    cs_set_socket_timeout(link->sock, sock_attr->connect_timeout);
    cs_set_io_mode(link->sock, GS_TRUE, GS_TRUE);

    if (cs_tcp_connect_core(link, sock_attr) != GS_SUCCESS) {
        cs_close_socket(link->sock);
        link->sock = CS_INVALID_SOCKET;
        link->closed = GS_TRUE;
        GS_THROW_ERROR(ERR_ESTABLISH_TCP_CONNECTION, host, (uint32)port, cm_get_os_error());
        return GS_ERROR;
    }

    cs_reset_socket_timeout(link->sock);

    cs_set_keep_alive(link->sock, GS_TCP_KEEP_IDLE, GS_TCP_KEEP_INTERVAL, GS_TCP_KEEP_COUNT);
    cs_set_linger(link->sock, sock_attr->l_onoff, sock_attr->l_linger);
    link->closed = GS_FALSE;
    return GS_SUCCESS;
}

bool32 cs_tcp_try_connect(const char *host, uint16 port)
{
    socket_t sock = CS_INVALID_SOCKET;
    bool32 result;
    sock_addr_t sock_addr;

    CM_POINTER(host);

    if (strlen(host) == 0) {
        host = "127.0.0.1";
    }

    GS_RETVALUE_IFTRUE(cm_ipport_to_sockaddr(host, port, &sock_addr) != GS_SUCCESS, GS_FALSE);

    sock = (socket_t)socket(SOCKADDR_FAMILY(&sock_addr), SOCK_STREAM, 0);
    if (sock == CS_INVALID_SOCKET) {
        GS_THROW_ERROR(ERR_CREATE_SOCKET, errno);
        return GS_FALSE;
    }

    result = (0 == connect(sock, SOCKADDR(&sock_addr), sock_addr.salen));
    cs_close_socket(sock);

    return result;
}

void cs_tcp_disconnect(tcp_link_t *link)
{
    CM_POINTER(link);

    if (link->closed) {
        CM_ASSERT(link->sock == CS_INVALID_SOCKET);
        return;
    }

    (void)cs_close_socket(link->sock);
    link->closed = GS_TRUE;
    link->sock = CS_INVALID_SOCKET;
}

void cs_shutdown_socket(socket_t sock)
{
#ifdef WIN32
    (void)shutdown(sock, SD_BOTH);
#else
    (void)shutdown(sock, SHUT_RDWR);
#endif
}

status_t cs_tcp_wait(tcp_link_t *link, uint32 wait_for, int32 timeout, bool32 *ready)
{
    struct pollfd fd;
    int32 ret;
    int32 tv;

    if (ready != NULL) {
        *ready = GS_FALSE;
    }

    if (link->closed) {
        GS_THROW_ERROR(ERR_PEER_CLOSED, "tcp");
        return GS_ERROR;
    }

    tv = (timeout < 0 ? -1 : timeout);

    fd.fd = link->sock;
    fd.revents = 0;
    if (wait_for == CS_WAIT_FOR_WRITE) {
        fd.events = POLLOUT;
    } else {
        fd.events = POLLIN;
    }

    ret = cs_tcp_poll(&fd, 1, tv);
    if (ret >= 0) {
        if (ready != NULL) {
            *ready = ((ret == 0 && errno == EINTR) || ret > 0);
        }
        return GS_SUCCESS;
    }

    if (errno != EINTR) {
        GS_THROW_ERROR(ERR_PEER_CLOSED, "tcp");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t cs_tcp_send(tcp_link_t *link, const char *buf, uint32 size, int32 *send_size)
{
    int code;

    if (size == 0) {
        *send_size = 0;
        return GS_SUCCESS;
    }

    *send_size = send(link->sock, buf, size, 0);
    if (*send_size <= 0) {
#ifdef WIN32
        code = WSAGetLastError();
        if (code == WSAEWOULDBLOCK) {
#else
        code = errno;
        if (errno == EWOULDBLOCK) {
#endif
            *send_size = 0;
            return GS_SUCCESS;
        }

        GS_THROW_ERROR(ERR_PEER_CLOSED_REASON, "tcp", code);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t cs_tcp_send_timed(tcp_link_t *link, const char *buf, uint32 size, uint32 timeout)
{
    uint32 remain_size, offset;
    int32 writen_size;
    uint32 wait_interval = 0;
    bool32 ready = GS_FALSE;

    if (link->closed) {
        GS_THROW_ERROR(ERR_PEER_CLOSED, "tcp");
        return GS_ERROR;
    }

    /* for most cases, all data are written by the following call */
    GS_RETURN_IFERR(cs_tcp_send(link, buf, size, &writen_size));
    remain_size = size - writen_size;
    offset = (uint32)writen_size;

    while (remain_size > 0) {
        GS_RETURN_IFERR(cs_tcp_wait(link, CS_WAIT_FOR_WRITE, GS_POLL_WAIT, &ready));

        if (!ready) {
            wait_interval += GS_POLL_WAIT;
            if (wait_interval >= timeout) {
                GS_THROW_ERROR(ERR_TCP_TIMEOUT, "send data");
                return GS_ERROR;
            }

            continue;
        }

        GS_RETURN_IFERR(cs_tcp_send(link, buf + offset, remain_size, &writen_size));
        remain_size -= writen_size;
        offset += writen_size;
    }

    return GS_SUCCESS;
}

/* cs_tcp_recv must following cs_tcp_wait */
status_t cs_tcp_recv(tcp_link_t *link, char *buf, uint32 size, int32 *recv_size, uint32 *wait_event)
{
    int32 rsize = 0;
    int32 code;

    if (size == 0) {
        *recv_size = 0;
        return GS_SUCCESS;
    }

    for (;;) {
        rsize = recv(link->sock, buf, size, 0);
        if (rsize > 0) {
            break;
        }
        if (rsize == 0) {
            GS_THROW_ERROR(ERR_PEER_CLOSED, "tcp");
            return GS_ERROR;
        }
        code = cm_get_sock_error();
#ifdef WIN32
        if (code == WSAEWOULDBLOCK) {
            continue;
        }
#endif
        if (code == EINTR || code == EAGAIN) {
            continue;
        }

        GS_THROW_ERROR(ERR_TCP_RECV, "tcp", code);
        return GS_ERROR;
    }
    *recv_size = rsize;
    return GS_SUCCESS;
}

status_t cs_tcp_recv_remain(tcp_link_t *link, char *buf, uint32 offset_left,
                            uint32 remain_size_left, uint32 timeout)
{
    int32 recv_size;
    uint32 wait_interval = 0;
    bool32 ready = GS_FALSE;
    uint32 remain_size = remain_size_left;
    uint32 offset = offset_left;
    while (remain_size > 0) {
        GS_RETURN_IFERR(cs_tcp_wait(link, CS_WAIT_FOR_READ, GS_POLL_WAIT, &ready));

        if (!ready) {
            wait_interval += GS_POLL_WAIT;
            if (wait_interval >= timeout) {
                GS_THROW_ERROR(ERR_TCP_TIMEOUT, "recv data");
                return GS_ERROR;
            }

            continue;
        }

        GS_RETURN_IFERR(cs_tcp_recv(link, buf + offset, remain_size, &recv_size, NULL));
        remain_size -= recv_size;
        offset += recv_size;
    }

    return GS_SUCCESS;
}

/* cs_tcp_recv_timed must following cs_tcp_wait */
status_t cs_tcp_recv_timed(tcp_link_t *link, char *buf, uint32 size, uint32 timeout)
{
    uint32 remain_size, offset;
    int32 recv_size;

    remain_size = size;
    offset = 0;

    GS_RETURN_IFERR(cs_tcp_recv(link, buf + offset, remain_size, &recv_size, NULL));

    if (recv_size > 0) {
        remain_size -= recv_size;
        offset += recv_size;
    }

    return cs_tcp_recv_remain(link, buf, offset, remain_size, timeout);
}

#ifdef __cplusplus
}
#endif