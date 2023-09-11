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
 * cm_rdma.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_rdma.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CM_RDMA_H__
#define __CM_RDMA_H__

#include "cm_defs.h"

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <mstcpip.h>
#include <Ws2tcpip.h>
#else
#include <sys/socket.h>
#include <poll.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/time.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WIN32

typedef int (*rsocket_func_t)(int domain, int type, int protocol);
typedef int (*rbind_func_t)(int socket, const struct sockaddr *addr, socklen_t addrlen);
typedef int (*rlisten_func_t)(int socket, int backlog);
typedef int (*raccept_func_t)(int socket, struct sockaddr *addr, socklen_t *addrlen);
typedef int (*rconnect_func_t)(int socket, const struct sockaddr *addr, socklen_t addrlen);
typedef int (*rshutdown_func_t)(int socket, int how);
typedef int (*rclose_func_t)(int socket);

typedef ssize_t (*rrecv_func_t)(int socket, void *buf, size_t len, int flags);
typedef ssize_t (*rrecvfrom_func_t)(int socket, void *buf, size_t len, int flags,
                                    struct sockaddr *src_addr, socklen_t *addrlen);
typedef ssize_t (*rrecvmsg_func_t)(int socket, struct msghdr *msg, int flags);
typedef ssize_t (*rsend_func_t)(int socket, const void *buf, size_t len, int flags);
typedef ssize_t (*rsendto_func_t)(int socket, const void *buf, size_t len, int flags,
                                  const struct sockaddr *dest_addr, socklen_t addrlen);
typedef ssize_t (*rsendmsg_func_t)(int socket, const struct msghdr *msg, int flags);
typedef ssize_t (*rread_func_t)(int socket, void *buf, size_t count);
typedef ssize_t (*rreadv_func_t)(int socket, const struct iovec *iov, int iovcnt);
typedef ssize_t (*rwrite_func_t)(int socket, const void *buf, size_t count);
typedef ssize_t (*rwritev_func_t)(int socket, const struct iovec *iov, int iovcnt);

typedef int (*rpoll_func_t)(struct pollfd *fds, nfds_t nfds, int timeout);
typedef int (*rselect_func_t)(int nfds, fd_set *readfds, fd_set *writefds,
                              fd_set *exceptfds, struct timeval *timeout);

typedef int (*rgetpeername_func_t)(int socket, struct sockaddr *addr, socklen_t *addrlen);
typedef int (*rgetsockname_func_t)(int socket, struct sockaddr *addr, socklen_t *addrlen);

typedef int (*rsetsockopt_func_t)(int socket, int level, int optname,
                                  const void *optval, socklen_t optlen);
typedef int (*rgetsockopt_func_t)(int socket, int level, int optname,
                                  void *optval, socklen_t *optlen);
typedef int (*rfcntl_func_t)(int socket, int cmd, ... /* arg */);

typedef off_t (*riomap_func_t)(int socket, void *buf, size_t len, int prot, int flags, off_t offset);
typedef int (*riounmap_func_t)(int socket, void *buf, size_t len);
typedef size_t (*riowrite_func_t)(int socket, const void *buf, size_t count, off_t offset, int flags);

typedef struct st_rdma_socket_procs {
    bool32 rdma_useble;
    void *rdma_handle;          // librdmacm.so
    rsocket_func_t socket;
    rbind_func_t bind;
    rlisten_func_t listen;
    raccept_func_t accept;
    rconnect_func_t connect;
    rshutdown_func_t shutdown;
    rclose_func_t close;
    rrecv_func_t recv;
    rrecvfrom_func_t recvfrom;
    rrecvmsg_func_t recvmsg;
    rsend_func_t send;
    rsendto_func_t sendto;
    rsendmsg_func_t sendmsg;
    rread_func_t read;
    rreadv_func_t readv;
    rwrite_func_t write;
    rwritev_func_t writev;
    rpoll_func_t poll;
    rselect_func_t select;
    rgetpeername_func_t getpeername;
    rgetsockname_func_t getsockname;
    rsetsockopt_func_t setsockopt;
    rgetsockopt_func_t getsockopt;
    rfcntl_func_t fcntl;
    riomap_func_t iomap;
    riounmap_func_t iounmap;
    riowrite_func_t iowrite;
} rdma_socket_procs_t;

rdma_socket_procs_t *rdma_global_handle(void);

static inline bool32 rdma_is_inited(rdma_socket_procs_t *rdma_procs)
{
    return (rdma_procs->rdma_handle != NULL);
}

static inline int32 cm_rdma_socket(int32 domain, int32 type, int32 protocol)
{
    return rdma_global_handle()->socket(domain, type, protocol);
}

static inline int32 cm_rdma_bind(socket_t socket, const struct sockaddr *addr, socklen_t addrlen)
{
    return rdma_global_handle()->bind(socket, addr, addrlen);
}

static inline int32 cm_rdma_listen(socket_t socket, int32 backlog)
{
    return rdma_global_handle()->listen(socket, backlog);
}

static inline int32 cm_rdma_accept(socket_t socket, struct sockaddr *addr, socklen_t *addrlen)
{
    return rdma_global_handle()->accept(socket, addr, addrlen);
}

static inline int32 cm_rdma_connect(socket_t socket, const struct sockaddr *addr, socklen_t addrlen)
{
    return rdma_global_handle()->connect(socket, addr, addrlen);
}

static inline int32 cm_rdma_shutdown(socket_t socket, int32 how)
{
    return rdma_global_handle()->shutdown(socket, how);
}

static inline int32 cm_rdma_close(socket_t socket)
{
    return rdma_global_handle()->close(socket);
}

static inline int32 cm_rdma_recv(socket_t socket, void *buf, size_t len, int32 flags)
{
    return rdma_global_handle()->recv(socket, buf, len, flags);
}

static inline int32 cm_rdma_recvfrom(socket_t socket, void *buf, size_t len, int32 flags,
                                     struct sockaddr *src_addr, socklen_t *addrlen)
{
    return rdma_global_handle()->recvfrom(socket, buf, len, flags, src_addr, addrlen);
}

static inline int32 cm_rdma_recvmsg(socket_t socket, struct msghdr *msg, int32 flags)
{
    return rdma_global_handle()->recvmsg(socket, msg, flags);
}

static inline int32 cm_rdma_send(socket_t socket, const void *buf, size_t len, int32 flags)
{
    return rdma_global_handle()->send(socket, buf, len, flags);
}

static inline int32 cm_rdma_sendto(socket_t socket, const void *buf, size_t len, int32 flags,
                                   const struct sockaddr *dest_addr, socklen_t addrlen)
{
    return rdma_global_handle()->sendto(socket, buf, len, flags, dest_addr, addrlen);
}

static inline int32 cm_rdma_sendmsg(socket_t socket, const struct msghdr *msg, int32 flags)
{
    return rdma_global_handle()->sendmsg(socket, msg, flags);
}

static inline int32 cm_rdma_read(socket_t socket, void *buf, size_t count)
{
    return rdma_global_handle()->read(socket, buf, count);
}

static inline int32 cm_rdma_readv(socket_t socket, const struct iovec *iov, int32 iovcnt)
{
    return rdma_global_handle()->readv(socket, iov, iovcnt);
}

static inline int32 cm_rdma_write(socket_t socket, const void *buf, size_t count)
{
    return rdma_global_handle()->write(socket, buf, count);
}

static inline int32 cm_rdma_writev(socket_t socket, const struct iovec *iov, int32 iovcnt)
{
    return rdma_global_handle()->writev(socket, iov, iovcnt);
}

static inline int32 cm_rdma_poll(struct pollfd *fds, int32 nfds, int32 timeout)
{
    return rdma_global_handle()->poll(fds, nfds, timeout);
}

static inline int32 cm_rdma_select(int32 nfds, fd_set *readfds, fd_set *writefds,
                                   fd_set *exceptfds, struct timeval *timeout)
{
    return rdma_global_handle()->select(nfds, readfds, writefds, exceptfds, timeout);
}

static inline int32 cm_rdma_getpeername(socket_t socket, struct sockaddr *addr, socklen_t *addrlen)
{
    return rdma_global_handle()->getpeername(socket, addr, addrlen);
}

static inline int32 cm_rdma_getsockname(socket_t socket, struct sockaddr *addr, socklen_t *addrlen)
{
    return rdma_global_handle()->getsockname(socket, addr, addrlen);
}

static inline int32 cm_rdma_setsockopt(socket_t socket, int32 level, int32 optname,
                                       const void *optval, socklen_t optlen)
{
    return rdma_global_handle()->setsockopt(socket, level, optname, optval, optlen);
}

static inline int32 cm_rdma_getsockopt(socket_t socket, int32 level, int32 optname,
                                       void *optval, socklen_t *optlen)
{
    return rdma_global_handle()->getsockopt(socket, level, optname, optval, optlen);
}

static inline int32 cm_rdma_fcntl(socket_t socket, int32 cmd, ...)
{
    int32 res;
    va_list args;
    va_start(args, cmd);
    res = rdma_global_handle()->fcntl(socket, cmd, args);
    va_end(args);
    return res;
}

#else

static inline int32 cm_rdma_socket(int32 domain, int32 type, int32 protocol)
{
    return GS_INVALID_ID32;
}

static inline int32 cm_rdma_bind(socket_t socket, const struct sockaddr *addr, int addrlen)
{
    return GS_INVALID_ID32;
}

static inline int32 cm_rdma_listen(socket_t socket, int32 backlog)
{
    return GS_INVALID_ID32;
}

static inline int32 cm_rdma_accept(socket_t socket, struct sockaddr *addr, int *addrlen)
{
    return GS_INVALID_ID32;
}

static inline int32 cm_rdma_connect(socket_t socket, const struct sockaddr *addr, int addrlen)
{
    return GS_INVALID_ID32;
}

static inline int32 cm_rdma_shutdown(socket_t socket, int32 how)
{
    return GS_INVALID_ID32;
}

static inline int32 cm_rdma_close(socket_t socket)
{
    return GS_INVALID_ID32;
}

static inline int32 cm_rdma_recv(socket_t socket, void *buf, size_t len, int32 flags)
{
    return GS_INVALID_ID32;
}

static inline int32 cm_rdma_recvfrom(socket_t socket, void *buf, size_t len, int32 flags, struct sockaddr *src_addr,
                                     int *addrlen)
{
    return GS_INVALID_ID32;
}

static inline int32 cm_rdma_recvmsg(socket_t socket, struct msghdr *msg, int32 flags)
{
    return GS_INVALID_ID32;
}

static inline int32 cm_rdma_send(socket_t socket, const void *buf, size_t len, int32 flags)
{
    return GS_INVALID_ID32;
}

static inline int32 cm_rdma_sendto(socket_t socket, const void *buf, size_t len, int32 flags,
                                   const struct sockaddr *dest_addr, int addrlen)
{
    return GS_INVALID_ID32;
}

static inline int32 cm_rdma_sendmsg(socket_t socket, const struct msghdr *msg, int32 flags)
{
    return GS_INVALID_ID32;
}

static inline int32 cm_rdma_read(socket_t socket, void *buf, size_t count)
{
    return GS_INVALID_ID32;
}

static inline int32 cm_rdma_readv(socket_t socket, const struct iovec *iov, int32 iovcnt)
{
    return GS_INVALID_ID32;
}

static inline int32 cm_rdma_write(socket_t socket, const void *buf, size_t count)
{
    return GS_INVALID_ID32;
}

static inline int32 cm_rdma_writev(socket_t socket, const struct iovec *iov, int32 iovcnt)
{
    return GS_INVALID_ID32;
}

static inline int32 cm_rdma_poll(struct pollfd *fds, int32 nfds, int32 timeout)
{
    return GS_INVALID_ID32;
}

static inline int32 cm_rdma_select(int32 nfds, fd_set *readfds, fd_set *writefds,
                                   fd_set *exceptfds, struct timeval *timeout)
{
    return GS_INVALID_ID32;
}

static inline int32 cm_rdma_getpeername(socket_t socket, struct sockaddr *addr, int *addrlen)
{
    return GS_INVALID_ID32;
}

static inline int32 cm_rdma_getsockname(socket_t socket, struct sockaddr *addr, int *addrlen)
{
    return GS_INVALID_ID32;
}

static inline int32 cm_rdma_setsockopt(socket_t socket, int32 level, int32 optname, const void *optval,
                                       int optlen)
{
    return GS_INVALID_ID32;
}

static inline int32 cm_rdma_getsockopt(socket_t socket, int32 level, int32 optname, void *optval, int *optlen)
{
    return GS_INVALID_ID32;
}

static inline int32 cm_rdma_fcntl(socket_t socket, int32 cmd, ...)
{
    return GS_INVALID_ID32;
}

#endif

status_t rdma_init_lib(void);
void rdma_close_lib(void);

#ifdef __cplusplus
}
#endif

#endif
