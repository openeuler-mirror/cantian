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
 * cms_socket.c
 *
 *
 * IDENTIFICATION
 * src/cms/interface/cms_socket.c
 *
 * -------------------------------------------------------------------------
 */
#include "cms_log_module.h"
#include "cm_defs.h"
#include "cm_file.h"
#include "cms_comm.h"
#include "cm_ip.h"
#include "cs_packet.h"
#include "cs_tcp.h"
#include "cms_client.h"
#include "cs_uds.h"
#include "securec.h"
#include "cms_socket.h"

status_t cms_socket_init(void)
{
#ifdef WIN32
    WORD wVersionRequested;
    WSADATA wsaData;
    wVersionRequested = MAKEWORD(1, 1);
    if (WSAStartup(wVersionRequested, &wsaData) != 0) {
        return CT_ERROR;
    }
#endif
    return CT_SUCCESS;
}

int32 cms_socket_error(void)
{
#ifdef WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

status_t cms_socket_open(socket_t* sock_out)
{
    socket_t sock = -1;

    while (CT_TRUE) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock == CS_INVALID_SOCKET) {
            CT_LOG_RUN_ERR("create socket failed, errno %d[%s]", errno, strerror(errno));
            return CT_ERROR;
        }
#ifndef _WIN32
        if (sock != STDIN_FILENO &&
           sock != STDOUT_FILENO &&
           sock != STDERR_FILENO) {
            break;
        }
#else
        break;
#endif
    }

    int32 size = SIZE_M(64);
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&size, sizeof(size));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&size, sizeof(size));
    cms_socket_setopt_blocking(sock, CT_FALSE);
    cms_socket_setopt_close_exec(sock);

    *sock_out = sock;

    return CT_SUCCESS;
}

void cms_socket_close(socket_t sock)
{
    cs_close_socket(sock);
}

status_t cms_socket_setopt_blocking(socket_t sockfd, bool32 flag)
{
#ifdef WIN32
    unsigned long block = flag ? 0 : 1;
    return ioctlsocket(sockfd, FIONBIO, &block);
#else
    int32 nDelayFlag = fcntl(sockfd, F_GETFL, 0);
    if (nDelayFlag == -1) {
        CT_LOG_RUN_ERR("socket getfl error, sock %d, errno %d[%s]", sockfd, errno, strerror(errno));
        return CT_ERROR;
    }
    nDelayFlag = flag ? nDelayFlag & (~O_NONBLOCK) : nDelayFlag | O_NONBLOCK;
    return fcntl(sockfd, F_SETFL, nDelayFlag);
#endif
}

status_t cms_socket_setopt_close_exec(socket_t sockfd)
{
#ifndef WIN32
    int32 flags = fcntl(sockfd, F_GETFD);
    if (flags == -1) {
        CT_LOG_RUN_ERR("socket getfd error, sock %d, errno %d[%s]", sockfd, errno, strerror(errno));
        return CT_ERROR;
    }
    flags |= FD_CLOEXEC;
    if (fcntl(sockfd, F_SETFD, flags) == -1) {
        return CT_ERROR;
    }
#endif
    return CT_SUCCESS;
}
status_t cms_socket_setopt_reuse(socket_t sockfd, bool32 flag)
{
    int32 option = flag ? 1 : 0;
    return setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char*)&option, sizeof(option));
}

status_t cms_socket_wait(socket_t sock, uint32 wait_for, int32 timeout, bool32* ready)
{
    struct pollfd fd;
    int32 ret;
    int32 tv;

    if (ready != NULL) {
        *ready = CT_FALSE;
    }

    tv = (timeout < 0 ? -1 : timeout);

    fd.fd = sock;
    fd.revents = 0;
    if (wait_for == CS_WAIT_FOR_WRITE) {
        fd.events = POLLOUT;
    } else {
        fd.events = POLLIN;
    }

    ret = cs_tcp_poll(&fd, 1, tv);
    if (ret >= 0) {
        if (ready != NULL) {
            *ready = (ret > 0);
        }
        return CT_SUCCESS;
    }

    if (errno != EINTR) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cms_uds_build_addr(cms_sockaddr_un_t* addr, const char* pszName, int32* len)
{
    errno_t ret = memset_s(addr, sizeof(cms_sockaddr_un_t), 0, sizeof(cms_sockaddr_un_t));
    MEMS_RETURN_IFERR(ret);
    addr->sun_family = AF_UNIX;
    ret = strncpy_s(addr->sun_path, sizeof(addr->sun_path), pszName, strlen(pszName));
    MEMS_RETURN_IFERR(ret);
    *len = sizeof_addr_un(*addr);
    return CT_SUCCESS;
}

status_t cms_uds_create_listener(const char* pszName, socket_t* sock_out)
{
    int32 len = 0;
    struct sockaddr_un un;
    status_t ret = CT_SUCCESS;
    socket_t sock = CMS_IO_INVALID_SOCKET;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        CT_LOG_RUN_ERR("socket failed, sock %d, errno %d[%s]", sock, errno, strerror(errno));
        return CT_ERROR;
    }

    status_t status = cms_uds_build_addr(&un, pszName, &len);
    if (status == CT_ERROR) {
        CT_LOG_RUN_ERR("build uds address failed, sock %d, errno %d[%s]", sock, errno, strerror(errno));
        cms_socket_close(sock);
        return CT_ERROR;
    }
    unlink(un.sun_path);

    ret = bind(sock, (struct sockaddr*)&un, (socklen_t)len);
    if (ret < 0) {
        CT_LOG_RUN_ERR("bind failed, ret %d, sun path %s, sock %d, errno %d[%s]", ret, un.sun_path,
            sock, errno, strerror(errno));
        cms_socket_close(sock);
        return CT_ERROR;
    }
    (void)chmod(pszName, S_IRUSR | S_IWUSR);

    ret = listen(sock, CMS_UDS_LISTEN_BACKLOG);
    if (ret < 0) {
        CT_LOG_RUN_ERR("listen failed, ret %d, sock %d, errno %d[%s]", ret, sock, errno, strerror(errno));
        cms_socket_close(sock);
        return CT_ERROR;
    }
    *sock_out = sock;

    return CT_SUCCESS;
}

status_t cms_uds_connect(const char* pszName, socket_t* sock_out)
{
    int32 len;
    struct sockaddr_un un;
    status_t ret;
    socket_t sock;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        CT_LOG_RUN_ERR("socket failed, sock %d, uds path %s, errno %d[%s]", sock, pszName, errno, strerror(errno));
        return CT_ERROR;
    }

    errno_t err = memset_s(&un, sizeof(un), 0, sizeof(un));
    MEMS_RETURN_IFERR(err);
    un.sun_family = AF_UNIX;
    err = strcpy_sp(un.sun_path, sizeof(un.sun_path), pszName);
    MEMS_RETURN_IFERR(err);
    len = offsetof(struct sockaddr_un, sun_path) + strlen(un.sun_path);

    ret = connect(sock, (struct sockaddr*)&un, (size_t)len);
    if (ret < 0) {
        CT_LOG_RUN_ERR("connect failed, ret %d, uds path %s, errno %d[%s]", ret, un.sun_path, errno, strerror(errno));
        (void)cms_socket_close(sock);
        return CT_ERROR;
    }
    *sock_out = sock;

    return CT_SUCCESS;
}

status_t cms_socket_accept(socket_t sockfd, int32 timeout_ms, socket_t* sock)
{
    if (timeout_ms >= 0) {
        cms_socket_wait(sockfd, CS_WAIT_FOR_READ, timeout_ms, NULL);
    }

    *sock = accept(sockfd, 0, 0);
    if (*sock == CS_INVALID_SOCKET) {
        CT_LOG_RUN_ERR("accept failed, errno %d[%s].", errno, strerror(errno));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cms_socket_send_bytes(socket_t sockfd, const char* data, int32* dlen, int32 timeout_ms)
{
    int32 cc = 0;
    int32 counter = 0;
    int32 snd_bytes = *dlen;
    if (sockfd < 0) {
        *dlen = counter;
        return CT_ERROR;
    }

    while (counter < snd_bytes) {
        cms_socket_wait(sockfd, CS_WAIT_FOR_WRITE, timeout_ms, NULL);
        cc = send(sockfd, data + counter, (size_t)(snd_bytes - counter), 0);
        if (cc > 0) {
            counter += cc;
            continue;
        }

        if (0 == cc) {
            *dlen = counter;
            CT_LOG_RUN_ERR("send failed, errno %d[%s].", errno, strerror(errno));
            return CT_ERROR;
        }

        if (errno != EINTR) {
            *dlen = counter;
            CT_LOG_RUN_ERR("send failed, ret %d, errno %d[%s].", cc, errno, strerror(errno));
            return CT_ERROR;
        }
    }

    *dlen = counter;
    return CT_SUCCESS;
}

status_t cms_socket_recv_bytes(socket_t sockfd, char* buf, int32* buf_len, int32 timeout_ms, bool32 is_retry_conn)
{
    char* pdata = buf;
    int32 cc = 0;
    int32 counter = 0;
    int32 rcv_bytes = *buf_len;
    status_t ret = CT_SUCCESS;
    if (sockfd < 0) {
        CT_LOG_RUN_ERR("recv failed, sockfd is invalid, sockfd %d.", sockfd);
        *buf_len = counter;
        return CT_ERROR;
    }

    if (is_retry_conn) {
        struct timeval timeout_recv = {CMS_LINUX_RECV_TMOUNT_SEC_RETRY, CMS_LINUX_RECV_TMOUNT_MS};
        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout_recv, sizeof(struct timeval)) < 0) {
            CT_LOG_RUN_ERR("setsockopt failed");
            return CT_ERROR;
        }
    }
    while (counter < rcv_bytes) {
        ret = cms_socket_wait(sockfd, CS_WAIT_FOR_READ, timeout_ms, NULL);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("socket wait failed, ret = %d", ret);
            return ret;
        }
        cc = recv(sockfd, pdata + counter, (size_t)(rcv_bytes - counter), 0);
        if (cc > 0) {
            counter += cc;
            continue;
        }

        if (0 == cc || errno == ECONNRESET) {
            *buf_len = counter;
            CT_LOG_RUN_INF("connection is closed by peer, sock %d.", sockfd);
            return CT_ERROR_CONN_CLOSED;
        }

        if (errno != EINTR) {
            *buf_len = counter;
            CT_LOG_RUN_ERR("recv failed, ret %d, sock %d, errno %d[%s].", cc, sockfd, errno, strerror(errno));
            return CT_ERROR;
        }
    }

    *buf_len = counter;
    return CT_SUCCESS;
}

status_t cms_socket_recv_header(socket_t sockfd, char* buf, int32 size, int32 timeout_ms, bool32 is_retry_conn)
{
    status_t ret = CT_SUCCESS;
    int32 header_len = sizeof(cms_packet_head_t);

    if (size < header_len) {
        CT_LOG_RUN_ERR("message buffer is not enough.");
        return CT_ERROR;
    }

    ret = cms_socket_recv_bytes(sockfd, buf, &header_len, timeout_ms, is_retry_conn);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("recv msg failed, ret %d, len %d.", ret, header_len);
        return ret;
    }
    return CT_SUCCESS;
}

status_t cms_socket_recv_body(socket_t sockfd, char* buf, int32 size, int32 timeout_ms)
{
    status_t ret = CT_SUCCESS;
    int32 body_len = size;

    ret = cms_socket_recv_bytes(sockfd, buf, &body_len, timeout_ms, CT_FALSE);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("recv msg failed, ret %d, len %d", ret, body_len);
        return ret;
    }
    return CT_SUCCESS;
}

status_t cms_socket_recv(socket_t sockfd, cms_packet_head_t* msg, int32 size, int32 timeout_ms, bool32 is_retry_conn)
{
    status_t ret = CT_SUCCESS;
    int32 body_len = 0;

    ret = cms_socket_recv_header(sockfd, (char*)msg, size, timeout_ms, is_retry_conn);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("recv msg header failed, ret %d", ret);
        return ret;
    }

    body_len = msg->msg_size - sizeof(cms_packet_head_t);
    if (body_len > size - sizeof(cms_packet_head_t)) {
        CT_LOG_RUN_ERR("message buffer is not enough, msg type %u, msg req %llu, src msg req %llu, msg size %u, "
            "body len %d", (int32)msg->msg_type, msg->msg_seq, msg->src_msg_seq, msg->msg_size, body_len);
        return CT_ERROR;
    }

    ret = cms_socket_recv_body(sockfd, (char*)msg + sizeof(cms_packet_head_t), body_len, timeout_ms);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("recv msg body failed, ret %d, msg type %u, msg req %llu, src msg req %llu, msg size %u, "
            "body len %d, sock %d", ret, (int32)msg->msg_type, msg->msg_seq, msg->src_msg_seq, msg->msg_size,
            body_len, sockfd);
        return ret;
    }

    if (is_retry_conn) {
        struct timeval recv_timeout = { CMS_LINUX_RECV_TMOUNT_SEC, CMS_LINUX_RECV_TMOUNT_MS };
        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&recv_timeout, sizeof(struct timeval)) < 0) {
            CT_LOG_RUN_ERR("setsockopt failed");
            return CT_ERROR;
        }
    }

    CMS_LOG_MSG(CT_LOG_DEBUG_INF, "receive msg succeed", msg);
    return CT_SUCCESS;
}

status_t cms_socket_send(socket_t sockfd, cms_packet_head_t* msg, int32 timeout_ms)
{
    int32 size = msg->msg_size;
    CT_RETURN_IFERR(cms_socket_send_bytes(sockfd, (char*)msg, &size, timeout_ms));

    CMS_LOG_MSG(CT_LOG_DEBUG_INF, "send msg succeed", msg);

    return CT_SUCCESS;
}
