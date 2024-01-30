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
 * cms_socket.h
 *
 *
 * IDENTIFICATION
 * src/cms/interface/cms_socket.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMS_SOCKET_H
#define CMS_SOCKET_H

#include "cm_defs.h"
#include "cms_client.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CT_ERROR_CONN_CLOSED      (-2)
#define CMS_RETRY_CONN_COUNT      5
#define CMS_RETRY_CONN_INTERVAL   1000
#define CMS_UDS_LISTEN_BACKLOG    20
#define CMS_CLI_UDS_SEND_TMOUT    1000
#define CMS_CLI_UDS_RECV_TMOUT    4000
#define CMS_CLI_RETRY_RECV_TMOUT  1000
#define CMS_IO_INVALID_SOCKET     (-1)
#define CMS_LINUX_RECV_TMOUNT_SEC 0
#define CMS_LINUX_RECV_TMOUNT_SEC_RETRY 1
#define CMS_LINUX_RECV_TMOUNT_MS  0
typedef struct sockaddr_un cms_sockaddr_un_t;

status_t cms_socket_init(void);
status_t cms_socket_open(socket_t* sock_out);
void cms_socket_close(socket_t sock);
int32 cms_socket_error(void);
status_t cms_socket_wait(socket_t sock, uint32 wait_for, int32 timeout, bool32* ready);
status_t cms_socket_setopt_blocking(socket_t sockfd, bool32 flag);
status_t cms_socket_setopt_reuse(socket_t sockfd, bool32 flag);
status_t cms_socket_setopt_close_exec(socket_t sockfd);

status_t cms_uds_build_addr(cms_sockaddr_un_t* addr, const char* pszName, int32* len);
status_t cms_uds_create_listener(const char* pszName, socket_t* sock_out);
status_t cms_socket_accept(socket_t sockfd, int32 timeout_ms, socket_t* sock);
status_t cms_uds_connect(const char* pszName, socket_t* sock_out);
status_t cms_socket_recv_bytes(socket_t sockfd, char* buf, int32* buf_len, int32 timeout_ms, bool32 is_retry_conn);
status_t cms_socket_send_bytes(socket_t sockfd, const char* data, int32* dlen, int32 timeout_ms);
status_t cms_socket_recv_header(socket_t sockfd, char* buf, int32 size, int32 timeout_ms, bool32 is_retry_conn);
status_t cms_socket_recv_body(socket_t sockfd, char* buf, int32 size, int32 timeout_ms);
status_t cms_socket_recv(socket_t sockfd, cms_packet_head_t* msg, int32 size, int32 timeout_ms, bool32 is_retry_conn);
status_t cms_socket_send(socket_t sockfd, cms_packet_head_t* msg, int32 timeout_ms);

#ifdef __cplusplus
}
#endif

#endif
