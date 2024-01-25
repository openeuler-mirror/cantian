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
 * cs_listener.c
 *
 *
 * IDENTIFICATION
 * src/protocol/cs_listener.c
 *
 * -------------------------------------------------------------------------
 */
#include "cs_protocol_module.h"
#include "cs_listener.h"
#include "cm_epoll.h"
#include "cm_file.h"
#include "cm_device.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline void cs_check_file_error(void)
{
    if (g_check_file_error != NULL) {
        g_check_file_error();
    }
}

static bool32 cs_create_tcp_link(socket_t sock_ready, cs_pipe_t *pipe)
{
    tcp_link_t *link = &pipe->link.tcp;

    link->local.salen = sizeof(link->local.addr);
    (void)getsockname(sock_ready, (struct sockaddr *)&link->local.addr, (socklen_t *)&link->local.salen);

    link->remote.salen = sizeof(link->remote.addr);
    link->sock = (socket_t)accept4(sock_ready,
                                   SOCKADDR(&link->remote),
                                   &link->remote.salen,
                                   SOCK_CLOEXEC);
    
    char ipstr_remote[CM_MAX_IP_LEN];
    char ipstr_local[CM_MAX_IP_LEN];
    CT_LOG_DEBUG_INF("[LSNR] Get remote tcp message from host %s by local %s",
                     cm_inet_ntop((struct sockaddr *)&link->remote.addr, ipstr_remote, CM_MAX_IP_LEN),
                     cm_inet_ntop((struct sockaddr *)&link->local.addr, ipstr_local, CM_MAX_IP_LEN));

    if (link->sock == CS_INVALID_SOCKET) {
        cs_check_file_error();
        CT_LOG_RUN_INF("Failed to accept connection request, OS error:%d", cm_get_os_error());
        return CT_FALSE;
    }

    /* set default options of sock */
    cs_set_io_mode(link->sock, CT_TRUE, CT_TRUE);
    cs_set_buffer_size(link->sock, CT_TCP_DEFAULT_BUFFER_SIZE, CT_TCP_DEFAULT_BUFFER_SIZE);
    cs_set_keep_alive(link->sock, CT_TCP_KEEP_IDLE, CT_TCP_KEEP_INTERVAL, CT_TCP_KEEP_COUNT);
    cs_set_linger(link->sock, 1, 1);
    
    link->closed = CT_FALSE;
    return CT_TRUE;
}

static bool32 cs_create_ssl_link(socket_t sock_ready, cs_pipe_t *pipe)
{
    ssl_link_t *link = &pipe->link.ssl;

    link->tcp.local.salen = sizeof(link->tcp.local.addr);
    (void)getsockname(sock_ready, (struct sockaddr *)&link->tcp.local.addr, (socklen_t *)&link->tcp.local.salen);

    link->tcp.remote.salen = sizeof(link->tcp.remote.addr);
    link->tcp.sock = (socket_t)accept4(sock_ready, SOCKADDR(&link->tcp.remote), &link->tcp.remote.salen, SOCK_CLOEXEC);
    
    char ipstr_remote[CM_MAX_IP_LEN];
    char ipstr_local[CM_MAX_IP_LEN];
    CT_LOG_DEBUG_INF("[LSNR] Get remote tcp message from host %s by local %s",
                     cm_inet_ntop((struct sockaddr *)&link->tcp.remote.addr, ipstr_remote, CM_MAX_IP_LEN),
                     cm_inet_ntop((struct sockaddr *)&link->tcp.local.addr, ipstr_local, CM_MAX_IP_LEN));

    if (link->tcp.sock == CS_INVALID_SOCKET) {
        cs_check_file_error();
        CT_LOG_RUN_INF("Failed to accept connection request, OS error:%d", cm_get_os_error());
        return CT_FALSE;
    }

    /* set default options of sock */
    cs_set_io_mode(link->tcp.sock, CT_TRUE, CT_TRUE);
    cs_set_buffer_size(link->tcp.sock, CT_TCP_DEFAULT_BUFFER_SIZE, CT_TCP_DEFAULT_BUFFER_SIZE);
    cs_set_keep_alive(link->tcp.sock, CT_TCP_KEEP_IDLE, CT_TCP_KEEP_INTERVAL, CT_TCP_KEEP_COUNT);
    cs_set_linger(link->tcp.sock, 1, 1);
    
    link->tcp.closed = CT_FALSE;
    return CT_TRUE;
}

static bool32 cs_create_rdma_link(socket_t sock_ready, cs_pipe_t *pipe)
{
    rdma_link_t *link = &pipe->link.rdma;
    CM_ASSERT(pipe->type == CS_TYPE_RSOCKET);

    link->local.salen = sizeof(link->local.addr);
    (void)getsockname(sock_ready, (struct sockaddr *)&link->local.addr, (socklen_t *)&link->local.salen);

    link->remote.salen = sizeof(link->remote.addr);
    link->sock = (socket_t)cm_rdma_accept(sock_ready, SOCKADDR(&link->remote), &link->remote.salen);

    if (link->sock == CS_INVALID_SOCKET) {
        cs_check_file_error();
        CT_LOG_RUN_INF("Failed to accept RDMA connection request, OS error:%d",
                       cm_get_os_error());
        return CT_FALSE;
    }

    /* set default options of sock */
    cs_rdma_set_io_mode(link->sock, CT_TRUE, CT_TRUE);
    cs_rdma_set_buffer_size(link->sock, CT_RSOCKET_DEFAULT_BUFFER_SIZE, CT_RSOCKET_DEFAULT_BUFFER_SIZE);
    cs_rdma_set_keep_alive(link->sock, CT_RSOCKET_KEEP_IDLE, CT_RSOCKET_KEEP_INTERVAL, CT_RSOCKET_KEEP_COUNT);
    cs_rdma_set_linger(link->sock);

    link->closed = CT_FALSE;
    return CT_TRUE;
}

void cs_try_ssl_accept(tcp_lsnr_t *lsnr, cs_pipe_t *pipe)
{
    socket_t sock_ready;
    int32 loop;
    int32 ret;
    struct epoll_event evnts[CT_MAX_LSNR_HOST_COUNT];

    ret = epoll_wait(lsnr->epoll_fd, evnts, (int)lsnr->sock_count, CT_POLL_WAIT);
    if (ret == 0) {
        return;
    }
    if (ret < 0) {
        if (cm_get_os_error() != EINTR) {
            CT_LOG_RUN_ERR("Failed to wait for connection request, OS error:%d", cm_get_os_error());
        }
        return;
    }

    if (ret > CT_MAX_LSNR_HOST_COUNT) {
        CT_LOG_RUN_ERR("the ret %d is illegal!", ret);
        return;
    }

    for (loop = 0; loop < ret; ++loop) {
        sock_ready = evnts[loop].data.fd;
        if (!cs_create_ssl_link(sock_ready, pipe)) {
            continue;
        }
        if (lsnr->status != LSNR_STATUS_RUNNING) {
            cs_tcp_disconnect(&pipe->link.ssl.tcp);
            continue;
        }
        (void)lsnr->action(lsnr, pipe);
    }
}

void cs_try_tcp_accept(tcp_lsnr_t *lsnr, cs_pipe_t *pipe)
{
    socket_t sock_ready;
    int32 loop;
    int32 ret;
    struct epoll_event evnts[CT_MAX_LSNR_HOST_COUNT];

    ret = epoll_wait(lsnr->epoll_fd, evnts, (int)lsnr->sock_count, CT_POLL_WAIT);
    if (ret == 0) {
        return;
    }
    if (ret < 0) {
        if (cm_get_os_error() != EINTR) {
            CT_LOG_RUN_ERR("Failed to wait for connection request, OS error:%d", cm_get_os_error());
        }
        return;
    }

    for (loop = 0; loop < ret; ++loop) {
        sock_ready = evnts[loop].data.fd;
        if (!cs_create_tcp_link(sock_ready, pipe)) {
            continue;
        }
        if (lsnr->status != LSNR_STATUS_RUNNING) {
            cs_tcp_disconnect(&pipe->link.tcp);
            continue;
        }
        (void)lsnr->action(lsnr, pipe);
    }
}

void cs_try_rdma_accept(rdma_lsnr_t *lsnr, cs_pipe_t *pipe)
{
    socket_t sock_ready;
    struct pollfd rdma_fd;
    int32 ret;

    CM_ASSERT(pipe->type == CS_TYPE_RSOCKET);
    // for RDMA, multiple listenning sockets are not supported now
    rdma_fd.fd = lsnr->sock;
    rdma_fd.events = POLLIN;

    /* try poll one connect request in time CT_POLL_WAIT */
    ret = cm_rdma_poll(&rdma_fd, 1, CT_POLL_WAIT);
    if (ret > 0 && ((uint16)rdma_fd.revents & (POLLERR | POLLHUP))) {
        CT_LOG_DEBUG_ERR("Failed to poll RDMA connection");
        return;
    }

    /* no connect request, return */
    if (ret == 0) {
        return;
    }

    if (ret < 0) {
        if (cm_get_os_error() != EINTR) {
            /* some error occured when poll */
            CT_LOG_RUN_ERR("Failed to wait for RDMA connection request, OS error:%d", cm_get_os_error());
        }
        return;
    }

    sock_ready = rdma_fd.fd;
    if (!cs_create_rdma_link(sock_ready, pipe)) {
        return;
    }

    if (lsnr->status != LSNR_STATUS_RUNNING) {
        cs_rdma_disconnect(&pipe->link.rdma);
        CT_LOG_RUN_WAR("RDMA listener not in running status");
        return;
    }
    (void)lsnr->action(lsnr, pipe);
}

static void srv_ssl_lsnr_proc(thread_t *thread)
{
    cs_pipe_t pipe;
    tcp_lsnr_t *lsnr = NULL;
    errno_t rc_memzero;

    CM_POINTER(thread);
    if (thread == NULL) {
        CT_LOG_RUN_ERR("thread is null!");
        return;
    }
    lsnr = (tcp_lsnr_t *)thread->argument;
    rc_memzero = memset_s(&pipe, sizeof(cs_pipe_t), 0, sizeof(cs_pipe_t));
    MEMS_RETVOID_IFERR(rc_memzero);

    pipe.type = CS_TYPE_SSL;
    pipe.version = CS_LOCAL_VERSION;
    cm_set_thread_name("ssl-lsnr");
    CT_LOG_RUN_INF("ssl-lsnr thread started");

    while (!thread->closed) {
        cs_try_ssl_accept(lsnr, &pipe);
        if (lsnr->status == LSNR_STATUS_PAUSING) {
            lsnr->status = LSNR_STATUS_PAUSED;
        }
    }
    CT_LOG_RUN_INF("ssl-lsnr thread closed");
}

static void srv_tcp_lsnr_proc(thread_t *thread)
{
    cs_pipe_t pipe;
    tcp_lsnr_t *lsnr = NULL;
    errno_t rc_memzero;

    CM_POINTER(thread);
    lsnr = (tcp_lsnr_t *)thread->argument;
    rc_memzero = memset_s(&pipe, sizeof(cs_pipe_t), 0, sizeof(cs_pipe_t));
    MEMS_RETVOID_IFERR(rc_memzero);

    pipe.type = CS_TYPE_TCP;
    pipe.version = CS_LOCAL_VERSION;
    cm_set_thread_name("tcp-lsnr");
    CT_LOG_RUN_INF("tcp-lsnr thread started");

    while (!thread->closed) {
        cs_try_tcp_accept(lsnr, &pipe);
        if (lsnr->status == LSNR_STATUS_PAUSING) {
            lsnr->status = LSNR_STATUS_PAUSED;
        }
    }

    CT_LOG_RUN_INF("tcp-lsnr thread closed");
}

status_t cs_strcat_host(tcp_lsnr_t *lsnr, char *str_output, int32 str_len)
{
    int32 loop = 0;
    int32 valid_count = 0;
    errno_t errcode;

    for (loop = 0; loop < CT_MAX_LSNR_HOST_COUNT; loop++) {
        if (lsnr->socks[loop] != CS_INVALID_SOCKET) {
            valid_count++;
            errcode = strcat_s(str_output, str_len, lsnr->host[loop]);
            if (errcode != EOK) {
                CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
                return CT_ERROR;
            }
            if (valid_count != lsnr->sock_count) {
                errcode = strcat_s(str_output, str_len, ",");
                if (errcode != EOK) {
                    CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
                    return CT_ERROR;
                }
            }
        }
    }
    return CT_SUCCESS;
}

static inline status_t cs_alloc_sock_slot(tcp_lsnr_t *lsnr, int32 *slot_id)
{
    for (uint32 loop = 0; loop < CT_MAX_LSNR_HOST_COUNT; ++loop) {
        if (lsnr->socks[loop] == CS_INVALID_SOCKET) {
            *slot_id = loop;
            return CT_SUCCESS;
        }
    }

    CT_THROW_ERROR(ERR_IPADDRESS_NUM_EXCEED, (uint32)CT_MAX_LSNR_HOST_COUNT);
    return CT_ERROR;
}

static status_t cs_create_one_lsnr_sock(tcp_lsnr_t *lsnr, const char *host, int32 *slot_id, bool32 is_replica)
{
    socket_t *sock = NULL;
    tcp_option_t option;
    int32 code;
    sock_addr_t sock_addr;

    if (lsnr->sock_count == CT_MAX_LSNR_HOST_COUNT) {
        CT_THROW_ERROR(ERR_IPADDRESS_NUM_EXCEED, (uint32)CT_MAX_LSNR_HOST_COUNT);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(cm_ipport_to_sockaddr(host, lsnr->port, &sock_addr));
    
    CT_RETURN_IFERR(cs_alloc_sock_slot(lsnr, slot_id));
    sock = &lsnr->socks[*slot_id];
    if (cs_create_socket(SOCKADDR_FAMILY(&sock_addr), sock) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (is_replica) {
        cs_set_buffer_size(*sock, CT_TCP_DEFAULT_BUFFER_SIZE, CT_TCP_DEFAULT_BUFFER_SIZE);
    }
    cs_set_io_mode(*sock, CT_TRUE, CT_TRUE);

    /************************************************************************
        When a process is killed, the address bound by the process can not be bound
        by other process immediately, this situation is unacceptable, so we use the
        SO_REUSEADDR parameter which allows the socket to be bound to an address
        that is already in use.
        ************************************************************************/
    option = 1;
    code = setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, (char *)&option, sizeof(uint32));
    if (-1 == code) {
        cs_close_socket(*sock);
        *sock = CS_INVALID_SOCKET;
        CT_THROW_ERROR(ERR_SET_SOCKET_OPTION);
        return CT_ERROR;
    }

    /************************************************************************
        Because of two processes could bpage to the same address, so we need check
        whether the address has been bound before bpage to it.
        ************************************************************************/
    if (cs_tcp_try_connect(host, lsnr->port)) {
        cs_close_socket(*sock);
        *sock = CS_INVALID_SOCKET;
        CT_THROW_ERROR(ERR_TCP_PORT_CONFLICTED, host, (uint32)lsnr->port);
        return CT_ERROR;
    }

    code = bind(*sock, SOCKADDR(&sock_addr), sock_addr.salen);
    if (code != 0) {
        cs_close_socket(*sock);
        *sock = CS_INVALID_SOCKET;
        CT_THROW_ERROR(ERR_SOCKET_BIND, host, (uint32)lsnr->port, cm_get_os_error());
        return CT_ERROR;
    }

    code = listen(*sock, SOMAXCONN);
    if (code != 0) {
        cs_close_socket(*sock);
        *sock = CS_INVALID_SOCKET;
        CT_THROW_ERROR(ERR_SOCKET_LISTEN, "listen socket", cm_get_os_error());
        return CT_ERROR;
    }
    
    (void)cm_atomic_inc(&lsnr->sock_count);
    return CT_SUCCESS;
}

static status_t cs_create_rdma_lsnr_sock(rdma_lsnr_t *lsnr, const char *host)
{
    socket_t *sock = NULL;
    tcp_option_t option;
    int32 code;
    sock_addr_t sock_addr;

    CT_RETURN_IFERR(cm_ipport_to_sockaddr(host, lsnr->port, &sock_addr));
    sock = &lsnr->sock;
    *sock = CS_INVALID_SOCKET;

    if (cs_create_rdma_socket(SOCKADDR_FAMILY(&sock_addr), sock) != CT_SUCCESS) {
        return CT_ERROR;
    }
    cs_rdma_set_io_mode(*sock, CT_TRUE, CT_TRUE);
    option = 1;

    code = cm_rdma_setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, (char *)&option, sizeof(uint32));
    if (code == -1) {
        cs_close_rdma_socket(*sock);
        *sock = CS_INVALID_SOCKET;
        CT_THROW_ERROR(ERR_SET_SOCKET_OPTION);
        return CT_ERROR;
    }

    if (cs_rdma_try_connect(host, lsnr->port)) {
        cs_close_rdma_socket(*sock);
        *sock = CS_INVALID_SOCKET;
        CT_THROW_ERROR(ERR_TCP_PORT_CONFLICTED, host, (uint32)lsnr->port);
        return CT_ERROR;
    }

    code = cm_rdma_bind(*sock, SOCKADDR(&sock_addr), sock_addr.salen);
    if (code != 0) {
        cs_close_rdma_socket(*sock);
        *sock = CS_INVALID_SOCKET;
        CT_THROW_ERROR(ERR_SOCKET_BIND, host, (uint32)lsnr->port, cm_get_os_error());
        return CT_ERROR;
    }

    code = cm_rdma_listen(*sock, SOMAXCONN);
    if (code != 0) {
        cs_close_rdma_socket(*sock);
        *sock = CS_INVALID_SOCKET;
        CT_THROW_ERROR(ERR_SOCKET_LISTEN, "listen socket", cm_get_os_error());
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void cs_close_lsnr_socks(tcp_lsnr_t *lsnr)
{
    uint32 loop;
    for (loop = 0; loop < CT_MAX_LSNR_HOST_COUNT; ++loop) {
        if (lsnr->socks[loop] != CS_INVALID_SOCKET) {
            cs_close_socket(lsnr->socks[loop]);
            lsnr->socks[loop] = CS_INVALID_SOCKET;
        }
    }
    (void)cm_atomic_set(&lsnr->sock_count, 0);
}

void cs_close_rdma_lsnr(rdma_lsnr_t *lsnr)
{
    if (lsnr->sock != CS_INVALID_SOCKET) {
        cs_close_rdma_socket(lsnr->sock);
        lsnr->sock = CS_INVALID_SOCKET;
    }
}

status_t cs_add_lsnr_ipaddr(tcp_lsnr_t *lsnr, const char *ip_addr, int32 *slot_id)
{
    char(*host)[CM_MAX_IP_LEN] = lsnr->host;
    struct epoll_event ev;
    errno_t errcode;
    *slot_id = CT_MAX_LSNR_HOST_COUNT;
    if (cs_create_one_lsnr_sock(lsnr, ip_addr, slot_id, CT_FALSE) != CT_SUCCESS) {
        if (*slot_id != CT_MAX_LSNR_HOST_COUNT) {
            cs_close_socket(lsnr->socks[*slot_id]);
            lsnr->socks[*slot_id] = CS_INVALID_SOCKET;
        }
        return CT_ERROR;
    }

    ev.events = EPOLLIN;
    ev.data.fd = (int)lsnr->socks[*slot_id];
    if (0 != epoll_ctl(lsnr->epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev)) {
        CT_THROW_ERROR(ERR_SOCKET_LISTEN, "add socket for listening to epool fd", cm_get_os_error());
        cs_close_socket(lsnr->socks[*slot_id]);
        lsnr->socks[*slot_id] = CS_INVALID_SOCKET;
        (void)cm_atomic_dec(&lsnr->sock_count);
        return CT_ERROR;
    }
    
    errcode = strncpy_s(host[*slot_id], CM_MAX_IP_LEN, ip_addr, strlen(ip_addr));
    if (errcode != EOK) {
        (void)cs_delete_lsnr_slot(lsnr, *slot_id);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }

    CT_LOG_RUN_INF("[LSNR] add lsnr ip %s, current valid listening sock count = %lld", lsnr->host[*slot_id],
                   lsnr->sock_count);
    return CT_SUCCESS;
}

status_t cs_delete_lsnr_slot(tcp_lsnr_t *lsnr, int32 slot_id)
{
    if (0 != epoll_ctl(lsnr->epoll_fd, EPOLL_CTL_DEL, (int)lsnr->socks[slot_id], NULL)) {
        CT_THROW_ERROR(ERR_SOCKET_LISTEN, "delete socket for listening to epool fd", cm_get_os_error());
        return CT_ERROR;
    }
    cs_close_socket(lsnr->socks[slot_id]);
    lsnr->socks[slot_id] = CS_INVALID_SOCKET;
    (void)cm_atomic_dec(&lsnr->sock_count);
    CT_LOG_RUN_INF("[LSNR] delete lsnr ip %s, leave valid listening sock count = %lld", lsnr->host[slot_id],
                   lsnr->sock_count);
    return CT_SUCCESS;
}

status_t cs_create_lsnr_socks(tcp_lsnr_t *lsnr, bool32 is_replica)
{
    int32 loop = 0;
    char(*host)[CM_MAX_IP_LEN] = lsnr->host;
    int32 slot_id;
    lsnr->sock_count = 0;

    for (loop = 0; loop < CT_MAX_LSNR_HOST_COUNT; loop++) {
        if (host[loop][0] != '\0') {
            if (cs_create_one_lsnr_sock(lsnr, host[loop], &slot_id, is_replica) != CT_SUCCESS) {
                cs_close_lsnr_socks(lsnr);
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

status_t cs_create_rdma_lsnr(rdma_lsnr_t *lsnr)
{
    char *host = lsnr->host;

    // for RDMA, multiple listenning sockets are not supported now
    if (host[0] != '\0') {
        if (cs_create_rdma_lsnr_sock(lsnr, host) != CT_SUCCESS) {
            cs_close_rdma_lsnr(lsnr);
            return CT_ERROR;
        }
    } else {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cs_lsnr_init_epoll_fd(tcp_lsnr_t *lsnr)
{
    struct epoll_event ev;
    uint32 loop;

    lsnr->epoll_fd = epoll_create1(0);
    if (-1 == lsnr->epoll_fd) {
        CT_THROW_ERROR(ERR_SOCKET_LISTEN, "create epoll fd for listener", cm_get_os_error());
        return CT_ERROR;
    }

    ev.events = EPOLLIN;
    for (loop = 0; loop < CT_MAX_LSNR_HOST_COUNT; ++loop) {
        if (lsnr->socks[loop] == CS_INVALID_SOCKET) {
            continue;
        }
        ev.data.fd = (int)lsnr->socks[loop];
        if (0 != epoll_ctl(lsnr->epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev)) {
            cm_close_file(lsnr->epoll_fd);
            CT_THROW_ERROR(ERR_SOCKET_LISTEN, "add socket for listening to epool fd", cm_get_os_error());
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t cs_start_ssl_lsnr(tcp_lsnr_t *lsnr, connect_action_t action, bool32 is_replica)
{
    CM_POINTER(lsnr);
    if (lsnr == NULL) {
        CT_LOG_RUN_ERR("lsnr is null!");
        return CT_ERROR;
    }
    int32 loop;
    lsnr->status = LSNR_STATUS_STOPPED;
    lsnr->action = action;
    
    for (loop = 0; loop < CT_MAX_LSNR_HOST_COUNT; loop++) {
        lsnr->socks[loop] = CS_INVALID_SOCKET;
    }

    if (cs_create_lsnr_socks(lsnr, is_replica) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("failed to create lsnr sockets for listener type %d", lsnr->type);
        return CT_ERROR;
    }

    if (cs_lsnr_init_epoll_fd(lsnr) != CT_SUCCESS) {
        cs_close_lsnr_socks(lsnr);
        CT_LOG_RUN_ERR("failed to init epoll fd for listener type %d", lsnr->type);
        return CT_ERROR;
    }

    lsnr->status = LSNR_STATUS_RUNNING;
    if (cm_create_thread(srv_ssl_lsnr_proc, 0, lsnr, &lsnr->thread) != CT_SUCCESS) {
        cs_close_lsnr_socks(lsnr);
        (void)epoll_close(lsnr->epoll_fd);
        lsnr->status = LSNR_STATUS_STOPPED;
        CT_LOG_RUN_ERR("failed to create accept thread for listener type %d", lsnr->type);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cs_start_tcp_lsnr(tcp_lsnr_t *lsnr, connect_action_t action, bool32 is_replica)
{
    CM_POINTER(lsnr);
    int32 loop;
    lsnr->status = LSNR_STATUS_STOPPED;
    lsnr->action = action;
    
    for (loop = 0; loop < CT_MAX_LSNR_HOST_COUNT; loop++) {
        lsnr->socks[loop] = CS_INVALID_SOCKET;
    }

    if (cs_create_lsnr_socks(lsnr, is_replica) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("failed to create lsnr sockets for listener type %d", lsnr->type);
        return CT_ERROR;
    }

    if (cs_lsnr_init_epoll_fd(lsnr) != CT_SUCCESS) {
        cs_close_lsnr_socks(lsnr);
        CT_LOG_RUN_ERR("failed to init epoll fd for listener type %d", lsnr->type);
        return CT_ERROR;
    }

    lsnr->status = LSNR_STATUS_RUNNING;
    if (cm_create_thread(srv_tcp_lsnr_proc, 0, lsnr, &lsnr->thread) != CT_SUCCESS) {
        cs_close_lsnr_socks(lsnr);
        (void)epoll_close(lsnr->epoll_fd);
        lsnr->status = LSNR_STATUS_STOPPED;
        CT_LOG_RUN_ERR("failed to create accept thread for listener type %d", lsnr->type);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void cs_stop_tcp_lsnr(tcp_lsnr_t *lsnr)
{
    cm_close_thread(&lsnr->thread);
    cs_close_lsnr_socks(lsnr);
    (void)epoll_close(lsnr->epoll_fd);
}

void cs_resume_tcp_lsnr(tcp_lsnr_t *lsnr)
{
    lsnr->status = LSNR_STATUS_RUNNING;
}

void cs_pause_tcp_lsnr(tcp_lsnr_t *lsnr)
{
    lsnr->status = LSNR_STATUS_PAUSING;
    while (lsnr->status != LSNR_STATUS_PAUSED && !lsnr->thread.closed) {
        cm_sleep(5);
    }
}

void cs_pause_uds_lsnr(uds_lsnr_t *lsnr)
{
    lsnr->status = LSNR_STATUS_PAUSING;
    while (lsnr->status != LSNR_STATUS_PAUSED && !lsnr->thread.closed) {
        cm_sleep(5);
    }
}

void cs_resume_uds_lsnr(uds_lsnr_t *lsnr)
{
    lsnr->status = LSNR_STATUS_RUNNING;
}

static void cs_close_uds_socks(uds_lsnr_t *lsnr)
{
    uint32 loop;
    for (loop = 0; loop < lsnr->sock_count; ++loop) {
        if (lsnr->socks[loop] != CS_INVALID_SOCKET) {
            cs_uds_socket_close(&lsnr->socks[loop]);
        }
    }
    lsnr->sock_count = 0;
}

void cs_stop_uds_lsnr(uds_lsnr_t *lsnr)
{
    cm_close_thread(&lsnr->thread);
    cs_close_uds_socks(lsnr);
    (void)epoll_close(lsnr->epoll_fd);
}

static bool32 cs_uds_create_link(socket_t sock_ready, cs_pipe_t *pipe)
{
    uds_link_t *link = &pipe->link.uds;

    link->local.salen = sizeof(link->local.addr);
    (void)cs_uds_getsockname(sock_ready, &link->local);

    link->remote.salen = sizeof(link->remote.addr);
    link->sock = (socket_t)accept(sock_ready,
                                  SOCKADDR(&link->remote),
                                  &link->remote.salen);
    
    if (link->sock == CS_INVALID_SOCKET) {
        cs_check_file_error();
        CT_LOG_RUN_INF("Failed to accept connection request, OS error:%d", cm_get_os_error());
        return CT_FALSE;
    }

    /* set default options of sock */
    cs_set_io_mode(link->sock, CT_TRUE, CT_TRUE);
    cs_set_buffer_size(link->sock, CT_TCP_DEFAULT_BUFFER_SIZE, CT_TCP_DEFAULT_BUFFER_SIZE);
    cs_set_keep_alive(link->sock, CT_TCP_KEEP_IDLE, CT_TCP_KEEP_INTERVAL, CT_TCP_KEEP_COUNT);
    cs_set_linger(link->sock, 1, 1);
    link->closed = CT_FALSE;
    return CT_TRUE;
}

static void cs_try_uds_accept(uds_lsnr_t *lsnr, cs_pipe_t *pipe)
{
    socket_t sock_ready;
    int32 ret;
    int32 loop = 0;
    struct epoll_event evnts[CT_MAX_LSNR_HOST_COUNT];

    ret = epoll_wait(lsnr->epoll_fd, evnts, (int)lsnr->sock_count, CT_POLL_WAIT);
    if (ret == 0) {
        return;
    }
    if (ret < 0) {
        if (cm_get_os_error() != EINTR) {
            CT_LOG_RUN_ERR("Failed to wait for connection request, OS error:%d", cm_get_os_error());
        }
        return;
    }

    for (loop = 0; loop < ret; loop++) {
        sock_ready = evnts[loop].data.fd;
        if (!cs_uds_create_link(sock_ready, pipe)) {
            continue;
        }
        if (lsnr->status != LSNR_STATUS_RUNNING) {
            cs_uds_disconnect(&pipe->link.uds);
            continue;
        }
        lsnr->is_emerg = (sock_ready == lsnr->socks[0]);
        (void)lsnr->action(lsnr, pipe);
    }
}

static void cs_uds_lsnr_proc(thread_t *thread)
{
    cs_pipe_t pipe;
    uds_lsnr_t *lsnr = NULL;
    errno_t errcode;

    CM_POINTER(thread);
    lsnr = (uds_lsnr_t *)thread->argument;
    /* thread entry function, str */
    errcode = memset_s(&pipe, sizeof(cs_pipe_t), 0, sizeof(cs_pipe_t));
    if (errcode != EOK) {
        thread->closed = CT_TRUE;
        CT_LOG_RUN_INF("uds-lsnr thread start failed");
        return;
    }

    pipe.type = CS_TYPE_DOMAIN_SCOKET;
    pipe.version = CS_LOCAL_VERSION;
    cm_set_thread_name("uds-lsnr");
    CT_LOG_RUN_INF("uds-lsnr thread started");

    while (!thread->closed) {
        cs_try_uds_accept(lsnr, &pipe);
        if (lsnr->status == LSNR_STATUS_PAUSING) {
            lsnr->status = LSNR_STATUS_PAUSED;
        }
    }

    CT_LOG_RUN_INF("uds-lsnr thread closed");
}


static status_t cs_uds_lsnr_init_epoll_fd(uds_lsnr_t *lsnr)
{
    struct epoll_event ev;
    uint32 loop;

    lsnr->epoll_fd = epoll_create1(0);
    if (lsnr->epoll_fd == -1) {
        CT_THROW_ERROR(ERR_SOCKET_LISTEN, "create epoll fd for listener", cm_get_os_error());
        return CT_ERROR;
    }
    
    for (loop = 0; loop < lsnr->sock_count; loop++) {
        ev.events = EPOLLIN;
        ev.data.fd = (int)lsnr->socks[loop];
        if (0 != epoll_ctl(lsnr->epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev)) {
            cm_close_file(lsnr->epoll_fd);
            CT_THROW_ERROR(ERR_SOCKET_LISTEN, "add socket for listening to epool fd", cm_get_os_error());
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t cs_create_uds_socks(uds_lsnr_t *lsnr)
{
    int32 loop = 0;
    char(*name)[CT_UNIX_PATH_MAX] = lsnr->names;

    lsnr->sock_count = 0;
    for (loop = 0; loop < CT_MAX_LSNR_HOST_COUNT; loop++) {
        if (name[loop][0] != '\0') {
            if (cs_uds_create_listener(lsnr->names[loop], &lsnr->socks[loop],
                lsnr->permissions) != CT_SUCCESS) {
                cs_close_uds_socks(lsnr);
                return CT_ERROR;
            }
            (void)cm_atomic_inc(&lsnr->sock_count);
        }
    }

    return CT_SUCCESS;
}

status_t cs_start_uds_lsnr(uds_lsnr_t *lsnr, uds_connect_action_t action)
{
    CM_POINTER(lsnr);
    status_t status;
    lsnr->status = LSNR_STATUS_STOPPED;
    lsnr->action = action;
    
    for (uint32 loop = 0; loop < CT_MAX_LSNR_HOST_COUNT; loop++) {
        lsnr->socks[loop] = CS_INVALID_SOCKET;
    }

    status = cs_create_uds_socks(lsnr);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("create domain socket failed. error code is %d.", cm_get_os_error());
        return CT_ERROR;
    }

    if (cs_uds_lsnr_init_epoll_fd(lsnr) != CT_SUCCESS) {
        cs_close_uds_socks(lsnr);
        CT_LOG_RUN_ERR("failed to init epoll fd");
        return CT_ERROR;
    }

    lsnr->status = LSNR_STATUS_RUNNING;
    if (cm_create_thread(cs_uds_lsnr_proc, 0, lsnr, &lsnr->thread) != CT_SUCCESS) {
        cs_close_uds_socks(lsnr);
        (void)epoll_close(lsnr->epoll_fd);

        lsnr->status = LSNR_STATUS_STOPPED;
        CT_LOG_RUN_ERR("failed to create accept thread");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}


#ifdef __cplusplus
}
#endif
