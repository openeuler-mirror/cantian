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
 * cs_uds.c
 *
 *
 * IDENTIFICATION
 * src/protocol/cs_uds.c
 *
 * -------------------------------------------------------------------------
 */
#include "cs_uds.h"
#include "cs_pipe.h"
#include "cm_file.h"
#include "cm_signal.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t cs_uds_init(void)
{
    return cs_tcp_init();
}

status_t cs_create_uds_socket(socket_t *sock)
{
    CT_RETURN_IFERR(cs_uds_init());
#ifndef WIN32
    *sock = (socket_t)socket(AF_UNIX, SOCK_STREAM, 0);
    if (*sock == CS_INVALID_SOCKET) {
        CT_THROW_ERROR(ERR_CREATE_SOCKET, errno);
        return CT_ERROR;
    }
#endif

    return CT_SUCCESS;
}

status_t cs_uds_connect(const char *server_path, const char *client_path, uds_link_t *uds_link,
                        socket_attr_t *sock_attr)
{
    if (CM_IS_EMPTY_STR(server_path) || uds_link == NULL) {
        return CT_ERROR;
    }

#ifdef WIN32
    int port = 0;
    FILE *hFile = fopen(server_path, "r");
    if (NULL == hFile) {
        return CT_ERROR;
    }

    if (fscanf_s(hFile, "%d", &port) < 0) {
        fclose(hFile);
        return CT_ERROR;
    }
    fclose(hFile);
    
    if (cs_tcp_connect("127.0.0.1", port, (tcp_link_t *)uds_link, NULL, sock_attr) != CT_SUCCESS) {
        return CT_ERROR;
    }
    
#else
    if (!CM_IS_EMPTY_STR(client_path)) {
        cs_uds_build_addr(&uds_link->local, client_path);
        unlink(uds_link->local.addr.sun_path);
        if (bind(uds_link->sock, SOCKADDR(&uds_link->local), uds_link->local.salen) < 0) {
            CT_THROW_ERROR(ERR_UDS_BIND, client_path, cm_get_os_error());
            return CT_ERROR;
        }
        (void)chmod(client_path, SERVICE_FILE_PERMISSIONS);
    }

    cs_uds_build_addr(&uds_link->remote, server_path);
    cs_set_buffer_size(uds_link->sock, CT_TCP_DEFAULT_BUFFER_SIZE, CT_TCP_DEFAULT_BUFFER_SIZE);
    cs_set_socket_timeout(uds_link->sock, sock_attr->connect_timeout);
    if (connect(uds_link->sock, SOCKADDR(&uds_link->remote), uds_link->remote.salen) != 0) {
        CT_THROW_ERROR(ERR_ESTABLISH_UDS_CONNECTION, server_path, errno);
        return CT_ERROR;
    }

    cs_set_io_mode(uds_link->sock, CT_TRUE, CT_TRUE);
    cs_set_keep_alive(uds_link->sock, CT_TCP_KEEP_IDLE, CT_TCP_KEEP_INTERVAL, CT_TCP_KEEP_COUNT);
    cs_set_linger(uds_link->sock, sock_attr->l_onoff, sock_attr->l_linger);
#endif
    uds_link->closed = CT_FALSE;

    return CT_SUCCESS;
}

void cs_uds_disconnect(uds_link_t *uds_link)
{
    CM_POINTER(uds_link);
    if (uds_link->closed) {
        CM_ASSERT(uds_link->sock == CS_INVALID_SOCKET);
        return;
    }
#ifdef WIN32
    cs_close_socket(uds_link->sock);
    uds_link->sock = CS_INVALID_SOCKET;
#else
    cs_uds_socket_close(&uds_link->sock);
#endif
    uds_link->closed = CT_TRUE;
}

status_t cs_uds_wait_win(uds_link_t *uds_link, uint32 wait_for, int32 timeout, bool32 *ready)
{
    int32 count;
    fd_set socket_set;
    struct timeval *tv_ptr = NULL;
    struct timeval tv;

    if (ready != NULL) {
        *ready = CT_FALSE;
    }

    if (uds_link->closed) {
        CT_THROW_ERROR(ERR_PEER_CLOSED, "uds");
        return CT_ERROR;
    }

    FD_ZERO(&socket_set);
    FD_SET(uds_link->sock, &socket_set);

    if (timeout != 0) {
        tv.tv_sec = timeout / CT_TIME_THOUSAND_UN;
        tv.tv_usec = ((long)timeout - tv.tv_sec * CT_TIME_THOUSAND_UN) * (long)CT_TIME_THOUSAND_UN;
        tv_ptr = &tv;
    } else {
        tv_ptr = NULL;
    }

    if (wait_for == CS_WAIT_FOR_WRITE) {
        count = select((int)uds_link->sock + 1, NULL, &socket_set, NULL, tv_ptr);
    } else {
        count = select((int)uds_link->sock + 1, &socket_set, NULL, NULL, tv_ptr);
    }

    if (count >= 0) {
        if (ready != NULL) {
            *ready = (count > 0);
        }

        return CT_SUCCESS;
    }

    if (errno != EINTR) {
        CT_THROW_ERROR(ERR_PEER_CLOSED, "uds");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cs_uds_wait(uds_link_t *uds_link, uint32 wait_for, int32 timeout, bool32 *ready)
{
#ifdef WIN32
    if (cs_uds_wait_win(uds_link, wait_for, timeout, ready) != CT_SUCCESS) {
        return CT_ERROR;
    }
#else
    struct pollfd fd;
    int32 ret;
    int32 tv;

    if (ready != NULL) {
        *ready = CT_FALSE;
    }

    if (uds_link->closed) {
        CT_THROW_ERROR(ERR_PEER_CLOSED, "uds");
        return CT_ERROR;
    }

    tv = (timeout == 0 ? -1 : timeout);

    fd.fd = uds_link->sock;
    fd.revents = 0;
    if (wait_for == CS_WAIT_FOR_WRITE) {
        fd.events = POLLOUT;
    } else {
        fd.events = POLLIN;
    }

    ret = poll(&fd, 1, tv);
    if (ret == 0) {
        if (ready != NULL) {
            *ready = CT_FALSE;
        }
        return CT_SUCCESS;
    }

    if (ret > 0) {
        if (ready != NULL) {
            *ready = CT_TRUE;
        }

        return CT_SUCCESS;
    }

    if (errno != EINTR) {
        CT_THROW_ERROR(ERR_PEER_CLOSED, "uds");
        return CT_ERROR;
    }
#endif

    return CT_SUCCESS;
}

status_t cs_uds_send(uds_link_t *uds_link, const char *buf, uint32 size, int32 *send_size)
{
    int code;

    if (size == 0) {
        *send_size = 0;
        return CT_SUCCESS;
    }

    *send_size = send(uds_link->sock, buf, size, 0);
    if (*send_size <= 0) {
#ifdef WIN32
        code = WSAGetLastError();
        if (code == WSAEWOULDBLOCK) {
#else
        code = errno;
        if (errno == EWOULDBLOCK) {
#endif
            *send_size = 0;
            return CT_SUCCESS;
        }
        CT_THROW_ERROR(ERR_PEER_CLOSED_REASON, "uds", code);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cs_uds_send_timed(uds_link_t *uds_link, const char *buf, uint32 size, uint32 timeout)
{
    int32 remain_size, offset, writen_size;
    uint32 wait_interval = 0;
    bool32 ready = CT_FALSE;

    if (uds_link->closed) {
        CT_THROW_ERROR(ERR_PEER_CLOSED, "uds");
        return CT_ERROR;
    }

    /* for most cases, all data are written by the following call */
    if (cs_uds_send(uds_link, buf, size, &writen_size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    remain_size = size - writen_size;
    offset = writen_size;

    while (remain_size > 0) {
        if (cs_uds_wait(uds_link, CS_WAIT_FOR_WRITE, CT_POLL_WAIT, &ready) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!ready) {
            wait_interval += CT_POLL_WAIT;
            if (wait_interval >= timeout) {
                CT_THROW_ERROR(ERR_TCP_TIMEOUT, "send data");
                return CT_ERROR;
            }

            continue;
        }

        if (cs_uds_send(uds_link, buf + offset, remain_size, &writen_size) != CT_SUCCESS) {
            return CT_ERROR;
        }

        remain_size -= writen_size;
        offset += writen_size;
    }

    return CT_SUCCESS;
}

/* cs_tcp_recv must following cs_tcp_wait */
status_t cs_uds_recv(uds_link_t *uds_link, char *buf, uint32 size, int32 *recv_size, uint32 *wait_event)
{
    int32 rsize = 0;

    if (size == 0) {
        *recv_size = 0;
        return CT_SUCCESS;
    }

    for (;;) {
        rsize = recv(uds_link->sock, buf, size, 0);
        if (rsize > 0) {
            break;
        }
        if (rsize == 0) {
            CT_THROW_ERROR(ERR_PEER_CLOSED, "uds");
            return CT_ERROR;
        }
        if (cm_get_sock_error() == EINTR || cm_get_sock_error() == EAGAIN) {
            continue;
        }
        CT_THROW_ERROR(ERR_TCP_RECV, "uds", cm_get_sock_error());
        return CT_ERROR;
    }
    *recv_size = rsize;
    return CT_SUCCESS;
}

status_t cs_uds_recv_timed(uds_link_t *uds_link, char *buf, uint32 size, uint32 timeout)
{
    int32 remain_size, offset;
    uint32 wait_interval = 0;
    int32 recv_size = 0;
    bool32 ready = CT_FALSE;

    remain_size = size;
    offset = 0;

    if (cs_uds_recv(uds_link, buf + offset, remain_size, &recv_size, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }

    remain_size -= recv_size;
    offset += recv_size;

    while (remain_size > 0) {
        if (cs_uds_wait(uds_link, CS_WAIT_FOR_READ, CT_POLL_WAIT, &ready) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!ready) {
            wait_interval += CT_POLL_WAIT;
            if (wait_interval >= timeout) {
                CT_THROW_ERROR(ERR_TCP_TIMEOUT, "recv data");
                return CT_ERROR;
            }

            continue;
        }

        if (cs_uds_recv(uds_link, buf + offset, remain_size, &recv_size, NULL) != CT_SUCCESS) {
            return CT_ERROR;
        }

        remain_size -= recv_size;
        offset += recv_size;
    }

    return CT_SUCCESS;
}

#ifndef WIN32
static bool32 cs_uds_try_connect(const char *path)
{
    status_t status;
    socket_t sock = CS_INVALID_SOCKET;
    cs_sockaddr_un_t un;
    bool32 result = CT_FALSE;
    CM_POINTER(path);
    
    status = cs_create_uds_socket(&sock);
    if (status != CT_SUCCESS) {
        return CT_FALSE;
    }
    
    cs_uds_build_addr(&un, path);
    result = (0 == connect(sock, SOCKADDR(&un), un.salen));
    cs_close_socket(sock);
    return result;
}
#endif

status_t cs_uds_create_listener(const char *name, socket_t *sock, uint16 permissions)
{
#ifdef WIN32
    char port[32];
    DWORD bytes;
    int32 code;
    sock_addr_t sock_addr;
    tcp_option_t option;
    OVERLAPPED ovp;
    HANDLE hFile = CreateFile(name, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, 0, NULL);    // | TRUNCATE_EXISTING
    if (INVALID_HANDLE_VALUE == hFile) {
        return CT_ERROR;
    }
    
    /* random to choose listen port  */
    if (cm_ip_to_sockaddr("127.0.0.1", &sock_addr) != CT_SUCCESS) {
        CloseHandle(hFile);
        return CT_ERROR;
    }

    if (cs_create_socket(SOCKADDR_FAMILY(&sock_addr), sock) != CT_SUCCESS) {
        CloseHandle(hFile);
        return CT_ERROR;
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
        CloseHandle(hFile);
        CT_THROW_ERROR(ERR_SET_SOCKET_OPTION);
        return CT_ERROR;
    }

    code = bind(*sock, SOCKADDR(&sock_addr), sock_addr.salen);
    if (code != 0) {
        cs_close_socket(*sock);
        *sock = CS_INVALID_SOCKET;
        CloseHandle(hFile);
        CT_THROW_ERROR(ERR_SOCKET_BIND, "127.0.0.1", 0, cm_get_os_error());
        return CT_ERROR;
    }
    
    sock_addr_t sockname;
    sockname.salen = sizeof(sockname.addr);

    (void)getsockname(*sock, SOCKADDR(&sockname), &sockname.salen);
    int iret_snprintf = snprintf_s(port, sizeof(port), sizeof(port) - 1, "%u", ntohs(SOCKADDR_PORT(&sockname)));
    if (iret_snprintf == -1) {
        cs_close_socket(*sock);
        *sock = CS_INVALID_SOCKET;
        CloseHandle(hFile);
        return CT_ERROR;
    }
    /* save the listen port to domain socket file */
    WriteFile(hFile, port, (DWORD)strlen(port), &bytes, NULL);
    FlushFileBuffers(hFile);
    code = memset_s(&ovp, sizeof(ovp), 0, sizeof(ovp));
    if (code != 0) {
        cs_close_socket(*sock);
        *sock = CS_INVALID_SOCKET;
        CloseHandle(hFile);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, code);
        return CT_ERROR;
    }
    if (!LockFileEx(hFile, LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ovp)) {
        CloseHandle(hFile);
        cs_close_socket(*sock);
        *sock = CS_INVALID_SOCKET;
        return CT_ERROR;
    }
    
    code = listen(*sock, 20);
    if (code != 0) {
        CloseHandle(hFile);
        cs_close_socket(*sock);
        *sock = CS_INVALID_SOCKET;
        CT_THROW_ERROR(ERR_SOCKET_LISTEN, "listen socket", cm_get_os_error());
        return CT_ERROR;
    }
    
#else
    status_t status;
    cs_sockaddr_un_t un;

    /************************************************************************
     TRY TO TEST IF DOMAIN SOCKET LISTEN EXIST.
    ************************************************************************/
    if (cs_uds_try_connect(name)) {
        CT_THROW_ERROR(ERR_UDS_CONFLICTED, name);
        return CT_ERROR;
    }
    
    status = cs_create_uds_socket(sock);
    CT_RETURN_IFERR(status);
    cs_uds_build_addr(&un, name);

    unlink(un.addr.sun_path);
    /* bind the name to the descriptor */
    if (bind(*sock, SOCKADDR(&un), un.salen) < 0) {
        cs_uds_socket_close(sock);
        CT_THROW_ERROR(ERR_UDS_BIND, name, cm_get_os_error());
        return CT_ERROR;
    }

    if (listen(*sock, 20) < 0) {
        cs_uds_socket_close(sock);
        CT_THROW_ERROR(ERR_SOCKET_LISTEN, "listen uds socket", cm_get_os_error());
        return CT_ERROR;
    }
    
    (void)chmod(name, permissions);

#endif
    return CT_SUCCESS;
}

int32 cs_uds_getsockname(socket_t sock_ready, cs_sockaddr_un_t *un)
{
    int ret = getsockname(sock_ready, SOCKADDR(un), &un->salen);
    if (ret < 0) {
        return ret;
    }
#ifndef WIN32
    if (un->salen >= sizeof(struct sockaddr_un)) {
        un->salen = sizeof(struct sockaddr_un) - 1;
    }

    un->addr.sun_path[sizeof_sun_path(un->salen)] = 0;
#endif

    return ret;
}

void cs_uds_socket_close(socket_t *sockfd)
{
    cs_sockaddr_un_t un;
    un.salen = sizeof(un.addr);
    (void)cs_uds_getsockname(*sockfd, &un);

    cs_close_socket(*sockfd);
    *sockfd = CS_INVALID_SOCKET;
    return;
}

#ifdef __cplusplus
}
#endif