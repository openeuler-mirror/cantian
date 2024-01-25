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
 * cs_uds.h
 *
 *
 * IDENTIFICATION
 * src/protocol/cs_uds.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CS_UDS_H__
#define __CS_UDS_H__

#include "cs_tcp.h"
#include "cm_ip.h"
#ifndef WIN32
#include <sys/un.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
typedef sock_addr_t cs_sockaddr_un_t;
#else
typedef struct st_cs_sockaddr_un {
    struct sockaddr_un addr;
    socklen_t salen;
} cs_sockaddr_un_t;
#endif


typedef struct st_uds_link {
    socket_t sock; // need to be first!
    bool32 closed; // need to be second!
    cs_sockaddr_un_t remote;
    cs_sockaddr_un_t local;
} uds_link_t;


#ifndef WIN32
#define sizeof_addr_un(x)   (OFFSET_OF(struct sockaddr_un, sun_path) + strlen((x).sun_path))
#define sizeof_sun_path(x)  ((x) - OFFSET_OF(struct sockaddr_un, sun_path))
#define SERVICE_FILE_PERMISSIONS 384

static inline void cs_uds_build_addr(cs_sockaddr_un_t *un, const char *name)
{
    errno_t errcode;
    errcode = memset_s(un, sizeof(cs_sockaddr_un_t), 0, sizeof(cs_sockaddr_un_t));
    MEMS_RETVOID_IFERR(errcode);
    un->addr.sun_family = AF_UNIX;
    errcode = strncpy_s(un->addr.sun_path, CT_UNIX_PATH_MAX, name, strlen(name));
    MEMS_RETVOID_IFERR(errcode);
    un->salen = sizeof_addr_un(un->addr);
}
#endif

status_t cs_create_uds_socket(socket_t *sock);
status_t cs_uds_connect(const char *server_path, const char *client_path, uds_link_t *uds_link,
                        socket_attr_t *sock_attr);
void cs_uds_disconnect(uds_link_t *uds_link);
status_t cs_uds_send(uds_link_t *uds_link, const char *buf, uint32 size, int32 *send_size);
status_t cs_uds_send_timed(uds_link_t *uds_link, const char *buf, uint32 size, uint32 timeout);
status_t cs_uds_recv(uds_link_t *uds_link, char *buf, uint32 size, int32 *recv_size, uint32 *wait_event);
status_t cs_uds_recv_timed(uds_link_t *uds_link, char *buf, uint32 size, uint32 timeout);
status_t cs_uds_wait(uds_link_t *uds_link, uint32 wait_for, int32 timeout, bool32 *ready);
status_t cs_uds_create_listener(const char *name, socket_t *sock, uint16 permissions);
int32 cs_uds_getsockname(socket_t sock_ready, cs_sockaddr_un_t *un);
void cs_uds_socket_close(socket_t *sockfd);

#ifdef __cplusplus
}
#endif

#endif
