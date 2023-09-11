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
 * cs_pipe.c
 *
 *
 * IDENTIFICATION
 * src/protocol/cs_pipe.c
 *
 * -------------------------------------------------------------------------
 */
#include "cs_pipe.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef status_t (*recv_func_t)(void *link, char *buf, uint32 size, int32 *recv_size, uint32 *wait_event);
typedef status_t (*send_func_t)(void *link, const char *buf, uint32 size, int32 *send_size);
typedef status_t (*recv_timed_func_t)(void *link, char *buf, uint32 size, uint32 timeout);
typedef status_t (*send_timed_func_t)(void *link, const char *buf, uint32 size, uint32 timeout);
typedef status_t (*wait_func_t)(void *link, uint32 wait_for, int32 timeout, bool32 *ready);

const text_t g_pipe_type_names[CS_TYPE_CEIL] = {
    { "UNKNOWN", 7 },
    { "TCP", 3 },
    { "IPC", 3 },
    { "UDS", 3 },
    { "SSL", 3 },
    { "EMBEDDED", 8 },
    { "DIRECT", 6 },
    { "RDMA", 4 },
};

typedef struct st_vio {
    recv_func_t vio_recv;
    send_func_t vio_send;
    wait_func_t vio_wait;
    recv_timed_func_t vio_recv_timed;
    send_timed_func_t vio_send_timed;
} vio_t;


static const vio_t g_vio_list[] = {
    { NULL, NULL, NULL, NULL, NULL },

    // TCP io functions
    { (recv_func_t)cs_tcp_recv, (send_func_t)cs_tcp_send, (wait_func_t)cs_tcp_wait,
      (recv_timed_func_t)cs_tcp_recv_timed, (send_timed_func_t)cs_tcp_send_timed },

    // IPC not implemented
    { NULL, NULL, NULL, NULL, NULL },

    // UDS io functions
    { (recv_func_t)cs_uds_recv, (send_func_t)cs_uds_send, (wait_func_t)cs_uds_wait,
      (recv_timed_func_t)cs_uds_recv_timed, (send_timed_func_t)cs_uds_send_timed },

    // SSL io functions
    { (recv_func_t)cs_ssl_recv, (send_func_t)cs_ssl_send, (wait_func_t)cs_ssl_wait,
      (recv_timed_func_t)cs_ssl_recv_timed, (send_timed_func_t)cs_ssl_send_timed },

    // CS_TYPE_EMBEDDED not implemented
    { NULL, NULL, NULL, NULL, NULL },

    // CS_TYPE_DIRECT not implemented
    { NULL, NULL, NULL, NULL, NULL },

    // RDMA socket io functions
    { (recv_func_t)cs_rdma_recv, (send_func_t)cs_rdma_send, (wait_func_t)cs_rdma_wait,
      (recv_timed_func_t)cs_rdma_recv_timed, (send_timed_func_t)cs_rdma_send_timed },
};

/*
  Macro definitions for pipe I/O operations
  @note
    Performance sensitive, the pipe->type should be guaranteed by the caller.
      e.g. CS_TYPE_TCP, CS_TYPE_SSL, CS_TYPE_DOMAIN_SOCKET
*/
#define GET_VIO(pipe) \
    (&g_vio_list[MIN((pipe)->type, CS_TYPE_CEIL - 1)])

#define VIO_SEND(pipe, buf, size, len) \
    GET_VIO(pipe)->vio_send(&(pipe)->link, buf, size, len)

#define VIO_SEND_TIMED(pipe, buf, size, timeout) \
    GET_VIO(pipe)->vio_send_timed(&(pipe)->link, buf, size, timeout)

#define VIO_RECV(pipe, buf, size, len, wait_event) \
    GET_VIO(pipe)->vio_recv(&(pipe)->link, buf, size, len, wait_event)

#define VIO_RECV_TIMED(pipe, buf, size, timeout) \
    GET_VIO(pipe)->vio_recv_timed(&(pipe)->link, buf, size, timeout)

#define VIO_WAIT(pipe, ev, timeout, ready) \
    GET_VIO(pipe)->vio_wait(&(pipe)->link, ev, timeout, ready)


/* before call cs_read_tcp_packet(), cs_tcp_wait() is called */
status_t cs_read_packet(cs_pipe_t *pipe, cs_packet_t *pack, bool32 cs_client)
{
    int32 remain_size;
    int32 head_size = sizeof(cs_packet_head_t);
    int32 err_code = 0;
    status_t ret_chk;

    ret_chk = VIO_RECV_TIMED(pipe, pack->buf, head_size, GS_NETWORK_IO_TIMEOUT);
    if (ret_chk != GS_SUCCESS) {
        err_code = cm_get_error_code();
        if (err_code == (int32)ERR_TCP_TIMEOUT) {
            GS_THROW_ERROR(ERR_TCP_TIMEOUT,
                cs_client ? "read head wait for server response" : "read head wait for client request");
        }
        return GS_ERROR;
    }

    if (CS_DIFFERENT_ENDIAN(pack->options)) {
        pack->head->size = cs_reverse_int32(pack->head->size);
        pack->head->flags = cs_reverse_int16(pack->head->flags);
        pack->head->serial_number = cs_reverse_int32(pack->head->serial_number);
    }

    GS_RETURN_IFERR(cs_try_realloc_packet_buffer(pack, head_size));

    remain_size = (int32)pack->head->size - head_size;
    if (remain_size <= 0) {
        return GS_SUCCESS;
    }

    ret_chk = VIO_RECV_TIMED(pipe, pack->buf + head_size, remain_size, GS_NETWORK_IO_TIMEOUT);
    if (ret_chk != GS_SUCCESS) {
        err_code = cm_get_error_code();
        if (err_code == (int32)ERR_TCP_TIMEOUT) {
            GS_THROW_ERROR(ERR_TCP_TIMEOUT,
                cs_client ? "read body wait for server response" : "read body wait for client request");
        }
    }
    return ret_chk;
}

status_t cs_write_packet(cs_pipe_t *pipe, cs_packet_t *pack)
{
    uint32 size = pack->head->size;

    if (CS_DIFFERENT_ENDIAN(pack->options)) {
        pack->head->size = cs_reverse_int32(pack->head->size);
        pack->head->flags = cs_reverse_int16(pack->head->flags);
    }

    if (VIO_SEND_TIMED(pipe, pack->buf, size, GS_DEFAULT_NULL_VALUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t cs_open_tcp_link(const char *host, uint16 port, cs_pipe_t *pipe, link_ready_ack_t *ack,
                                 const char *bind_host)
{
    tcp_link_t *link = NULL;
    bool32 ready = GS_FALSE;
    uint32 proto_code = GS_PROTO_CODE;
    uint8 local_endian;
    socket_attr_t sock_attr = {.connect_timeout = pipe->connect_timeout,
        .l_onoff = pipe->l_onoff, .l_linger = pipe->l_linger };

    link = &pipe->link.tcp;

    /* create socket */
    GS_RETURN_IFERR(cs_tcp_connect(host, port, link, bind_host, &sock_attr));
    do {
        GS_BREAK_IF_ERROR(cs_tcp_send_timed(link, (char *)&proto_code, sizeof(proto_code), GS_NETWORK_IO_TIMEOUT));

        GS_BREAK_IF_ERROR(cs_tcp_wait(link, CS_WAIT_FOR_READ, pipe->connect_timeout, &ready));

        if (!ready) {
            GS_THROW_ERROR(ERR_TCP_TIMEOUT, "connect wait for server response");
            break;
        }

        // read link_ready_ack
        GS_BREAK_IF_ERROR(cs_tcp_recv_timed(link, (char *)ack, sizeof(link_ready_ack_t), GS_NETWORK_IO_TIMEOUT));

        // reverse if endian is different
        local_endian = (IS_BIG_ENDIAN ? (uint8)1 : (uint8)0);
        if (local_endian != ack->endian) {
            ack->flags = cs_reverse_int16(ack->flags);
        }

        return GS_SUCCESS;
    } while (0);

    /* close socket */
    cs_close_socket(link->sock);
    link->sock = CS_INVALID_SOCKET;
    link->closed = GS_TRUE;
    return GS_ERROR;
}

static status_t cs_open_uds_link(const char *server_path, const char *client_path,
                                 cs_pipe_t *pipe, link_ready_ack_t *ack)
{
    uds_link_t *link = NULL;
    bool32 ready = GS_FALSE;
    uint32 proto_code = GS_PROTO_CODE;
    uint8 local_endian;
    socket_attr_t sock_attr = {.connect_timeout = pipe->connect_timeout,
        .l_onoff = pipe->l_onoff, .l_linger = pipe->l_linger };

    link = &pipe->link.uds;

    if (cs_create_uds_socket(&link->sock) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    if (cs_uds_connect(server_path, client_path, link, &sock_attr) != GS_SUCCESS) {
        goto error;
    }

    if (cs_uds_send_timed(link, (char *)&proto_code, sizeof(proto_code), GS_NETWORK_IO_TIMEOUT) != GS_SUCCESS) {
        goto error;
    }

    if (cs_uds_wait(link, CS_WAIT_FOR_READ, pipe->connect_timeout, &ready) != GS_SUCCESS) {
        goto error;
    }

    if (!ready) {
        GS_THROW_ERROR(ERR_TCP_TIMEOUT, "connect wait for server response");
        goto error;
    }

    // read link_ready_ack
    if (cs_uds_recv_timed(link, (char *)ack, sizeof(link_ready_ack_t), GS_NETWORK_IO_TIMEOUT) != GS_SUCCESS) {
        goto error;
    }

    // reverse if endian is different
    local_endian = (IS_BIG_ENDIAN ? (uint8)1 : (uint8)0);
    if (local_endian != ack->endian) {
        ack->flags = cs_reverse_int16(ack->flags);
    }
    return GS_SUCCESS;
error:
    cs_uds_socket_close(&link->sock);
    link->closed = GS_TRUE;
    return GS_ERROR;
}

static status_t cs_open_rdma_link(const char *host, uint16 port, cs_pipe_t *pipe, link_ready_ack_t *ack)
{
    rdma_link_t *link = NULL;
    bool32 ready = GS_FALSE;
    uint32 proto_code = GS_PROTO_CODE;
    uint8 local_endian;

    link = &pipe->link.rdma;

    if (cs_rdma_connect(host, port, link) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cs_rdma_send_timed(link, (char *)&proto_code, sizeof(proto_code), GS_NETWORK_IO_TIMEOUT) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cs_rdma_wait(link, CS_WAIT_FOR_READ, pipe->connect_timeout, &ready) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!ready) {
        GS_THROW_ERROR(ERR_TCP_TIMEOUT, "rdma socket wait for server response");
        return GS_ERROR;
    }

    // read link_ready_ack
    GS_RETURN_IFERR(cs_rdma_recv_timed(link, (char *)ack, sizeof(link_ready_ack_t), GS_NETWORK_IO_TIMEOUT));

    // reverse if endian is different
    local_endian = (IS_BIG_ENDIAN ? (uint8)1 : (uint8)0);
    if (local_endian != ack->endian) {
        ack->flags = cs_reverse_int16(ack->flags);
    }
    return GS_SUCCESS;
}

/* URL SAMPLE:
TCP x.x.x.x:port, database_server1:port
RDMA: RDMA@x.x.x.x:port
IPC:/home/gsdb
UDS:/home/gsdb */
typedef struct st_server_info {
    cs_pipe_type_t type;
    char path[GS_FILE_NAME_BUFFER_SIZE]; /* host name(TCP) or home path(IPC) or domain socket file (uds) */
    uint16 port;
} server_info_t;

static status_t cs_parse_url(const char *url, server_info_t *server)
{
    text_t text, part1, part2;
    text_t ipc = { "IPC", 3 };
    text_t uds = { "UDS", 3 };
    
    cm_str2text((char *)url, &text);
    (void)cm_split_rtext(&text, ':', '\0', &part1, &part2);
   
    if (cm_text_equal_ins(&part1, &ipc)) {
        server->type = CS_TYPE_IPC;
        GS_RETURN_IFERR(cm_text2str(&part2, server->path, GS_FILE_NAME_BUFFER_SIZE));
        if (part2.len == 0) {
            GS_THROW_ERROR(ERR_CLT_INVALID_ATTR, "URL", url);
            return GS_ERROR;
        }
    } else if (cm_text_equal_ins(&part1, &uds)) {
        server->type = CS_TYPE_DOMAIN_SCOKET;
    } else if (cm_text_str_contain_equal_ins(&part1, RDMA_HOST_PREFIX, RDMA_HOST_PREFIX_LEN)) {
        text_t prefix;
        (void)cm_fetch_text(&part1, '@', '\0', &prefix); /* remove prefix "RDMA@" */
        server->type = CS_TYPE_RSOCKET;
        cm_text2str(&part1, server->path, GS_FILE_NAME_BUFFER_SIZE);

        if (!cm_is_short(&part2)) {
            GS_THROW_ERROR(ERR_CLT_INVALID_ATTR, "rdma URL", url);
            return GS_ERROR;
        }

        if (cm_text2uint16(&part2, &server->port) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        server->type = CS_TYPE_TCP;
        GS_RETURN_IFERR(cm_text2str(&part1, server->path, GS_FILE_NAME_BUFFER_SIZE));
        if (!cm_is_short(&part2)) {
            GS_THROW_ERROR(ERR_CLT_INVALID_ATTR, "URL", url);
            return GS_ERROR;
        }

        if (cm_text2uint16(&part2, &server->port) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t cs_connect(const char *url, cs_pipe_t *pipe, const char *bind_host,
                    const char *server_path, const char *client_path)
{
    uint8 local_endian;
    link_ready_ack_t ack;
    server_info_t server;

    CM_POINTER2(url, pipe);

    /* parse url and get pipe type */
    GS_RETURN_IFERR(cs_parse_url(url, &server));
    pipe->type = server.type;

    // init the sign of node type
    pipe->node_type = CS_RESERVED;

    /* create socket to server */
    if (pipe->type == CS_TYPE_TCP) {
        GS_RETURN_IFERR(cs_open_tcp_link(server.path, server.port, pipe, &ack, bind_host));
    } else if (pipe->type == CS_TYPE_DOMAIN_SCOKET) {
        if (CM_IS_EMPTY_STR(server_path)) {
            GS_THROW_ERROR(ERR_CLT_UDS_FILE_EMPTY);
            return GS_ERROR;
        }
        GS_RETURN_IFERR(cs_open_uds_link(server_path, client_path, pipe, &ack));
    } else if (pipe->type == CS_TYPE_RSOCKET) {
        GS_RETURN_IFERR(cs_open_rdma_link(server.path, server.port, pipe, &ack));
    } else {
        GS_THROW_ERROR(ERR_PROTOCOL_NOT_SUPPORT);
        return GS_ERROR;
    }

    local_endian = (IS_BIG_ENDIAN ? (uint8)1 : (uint8)0);
    if (local_endian != ack.endian) {
        pipe->options |= CSO_DIFFERENT_ENDIAN;
    }

    /* disable SSL if the server protocol version < v5.0 */
    if ((ack.flags & CS_FLAG_CLIENT_SSL) && ack.handshake_version >= CS_VERSION_5) {
        pipe->options |= CSO_CLIENT_SSL;
    } else {
        pipe->options &= ~CSO_CLIENT_SSL;
    }

    if (ack.flags & CS_FLAG_CN_CONN) {
        pipe->node_type = CS_TYPE_CN;
    } else if (ack.flags & CS_FLAG_DN_CONN) {
        pipe->node_type = CS_TYPE_DN;
    }
    /* SSL before handshake since v9.0 */
    pipe->version = ack.handshake_version;
    return GS_SUCCESS;
}

void cs_disconnect(cs_pipe_t *pipe)
{
    CM_POINTER(pipe);
    if (pipe->type == CS_TYPE_TCP) {
        cs_tcp_disconnect(&pipe->link.tcp);
    }
    if (pipe->type == CS_TYPE_SSL) {
        cs_ssl_disconnect(&pipe->link.ssl);
    }
    
    if (pipe->type == CS_TYPE_DOMAIN_SCOKET) {
        cs_uds_disconnect(&pipe->link.uds);
    }

    if (pipe->type == CS_TYPE_RSOCKET) {
        cs_rdma_disconnect(&pipe->link.rdma);
    }
}

void cs_shutdown(cs_pipe_t *pipe)
{
    switch (pipe->type) {
        case CS_TYPE_TCP:
            cs_shutdown_socket(pipe->link.tcp.sock);
            break;
        case CS_TYPE_SSL:
            cs_shutdown_socket(pipe->link.ssl.tcp.sock);
            break;
        case CS_TYPE_DOMAIN_SCOKET:
            cs_shutdown_socket(pipe->link.uds.sock);
            break;
        case CS_TYPE_RSOCKET:
            cs_shutdown_socket(pipe->link.rdma.sock);
            break;
        default:
            break;
    }
}

status_t cs_read(cs_pipe_t *pipe, cs_packet_t *pack, bool32 cs_client)
{
    CM_POINTER2(pipe, pack);
    pack->options = pipe->options;

    return cs_read_packet(pipe, pack, cs_client);
}

status_t cs_read_bytes(cs_pipe_t *pipe, char *buf, uint32 max_size, int32 *size)
{
    CM_POINTER(pipe);
    uint32 wait_event;
    if (cs_wait(pipe, CS_WAIT_FOR_READ, GS_NETWORK_IO_TIMEOUT, NULL) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return VIO_RECV(pipe, buf, max_size, size, &wait_event);
}

status_t cs_read_fixed_size(cs_pipe_t *pipe, char *buf, int32 size)
{
    bool32 ready;
    int32  read_size;
    int32  remain_size = size;
    char *read_buf = buf;

    if (size == 0) {
        return GS_SUCCESS;
    }
    if (pipe->type == CS_TYPE_SSL) {
        if (cs_ssl_read_buffer(&pipe->link.ssl, buf, remain_size, &read_size) == GS_SUCCESS) {
            read_buf += read_size;
            remain_size -= read_size;
        }
    }

    if (remain_size == 0) {
        return GS_SUCCESS;
    }

    if (cs_read_bytes(pipe, read_buf, remain_size, &read_size) != GS_SUCCESS) {
        return GS_ERROR;
    }

    read_buf    += read_size;
    remain_size -= read_size;

    while (remain_size > 0) {
        if (cs_wait(pipe, CS_WAIT_FOR_READ, GS_NETWORK_IO_TIMEOUT, &ready) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!ready) {
            continue;
        }

        if (cs_read_bytes(pipe, read_buf, remain_size, &read_size) != GS_SUCCESS) {
            return GS_ERROR;
        }

        read_buf    += read_size;
        remain_size -= read_size;
    }

    return GS_SUCCESS;
}

status_t cs_send_fixed_size(cs_pipe_t *pipe, char *buf, int32 size, uint32_t dst_id,
                            check_inst_alive_func check_dst_alive)
{
    bool32 ready;
    int32  send_size;
    int32  remain_size = size;
    char *send_buf = buf;

    if (VIO_SEND(pipe, send_buf, remain_size, &send_size) != GS_SUCCESS) {
        return GS_ERROR;
    }

    send_buf    += send_size;
    remain_size -= send_size;

    while (remain_size > 0) {
        if (cs_wait(pipe, CS_WAIT_FOR_WRITE, GS_NETWORK_WAIT_TIMEOUT, &ready) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!ready) {
            if (check_dst_alive != NULL && !check_dst_alive(dst_id)) {
                return GS_ERROR;
            }
            continue;
        }

        if (VIO_SEND(pipe, send_buf, remain_size, &send_size) != GS_SUCCESS) {
            return GS_ERROR;
        }

        send_buf    += send_size;
        remain_size -= send_size;
    }

    return GS_SUCCESS;
}

status_t cs_send_bytes(cs_pipe_t *pipe, const char *buf, uint32 size)
{
    CM_POINTER2(pipe, buf);

    return VIO_SEND_TIMED(pipe, buf, size, GS_NETWORK_IO_TIMEOUT);
}

status_t cs_write(cs_pipe_t *pipe, cs_packet_t *pack)
{
    CM_POINTER2(pipe, pack);
    pack->options = pipe->options;

    return cs_write_packet(pipe, pack);
}

status_t cs_wait(cs_pipe_t *pipe, uint32 wait_for, int32 timeout, bool32 *ready)
{
    if (pipe->type == CS_TYPE_TCP) {
        return cs_tcp_wait(&pipe->link.tcp, wait_for, timeout, ready);
    }
    if (pipe->type == CS_TYPE_SSL) {
        return cs_ssl_wait(&pipe->link.ssl, wait_for, timeout, ready);
    }
    if (pipe->type == CS_TYPE_DOMAIN_SCOKET) {
        return cs_uds_wait(&pipe->link.uds, wait_for, timeout, ready);
    }
    if (pipe->type == CS_TYPE_RSOCKET) {
        return cs_rdma_wait(&pipe->link.rdma, wait_for, timeout, ready);
    }

    GS_THROW_ERROR(ERR_CLT_INVALID_VALUE, "pipe type", (uint32)pipe->type);
    return GS_ERROR;
}

status_t cs_call(cs_pipe_t *pipe, cs_packet_t *req, cs_packet_t *ack)
{
    if (cs_write(pipe, req) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cs_wait(pipe, CS_WAIT_FOR_READ, -1, NULL) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return cs_read(pipe, ack, GS_FALSE);
}

/* only for client which contains socket timeout and ready check */
status_t cs_call_ex(cs_pipe_t *pipe, cs_packet_t *req, cs_packet_t *ack)
{
    bool32 ready = GS_FALSE;

    if (cs_write(pipe, req) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cs_wait(pipe, CS_WAIT_FOR_READ, pipe->socket_timeout, &ready) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!ready) {
        GS_THROW_ERROR(ERR_SOCKET_TIMEOUT, pipe->socket_timeout / GS_TIME_THOUSAND_UN);
        return GS_ERROR;
    }

    return cs_read(pipe, ack, GS_TRUE);
}

status_t cs_write_stream(cs_pipe_t *pipe, const char *buf, uint32 size, int32 max_pkg_size)
{
    int32 offset = 0;
    int32 remain_size = (int32)size;
    int32 data_size;

    CM_POINTER2(pipe, buf);

    if (max_pkg_size == 0) {
        return VIO_SEND_TIMED(pipe, buf, size, GS_REPL_SEND_TIMEOUT);
    }

    while (remain_size > 0) {
        data_size = remain_size > max_pkg_size ? max_pkg_size : remain_size;

        if (VIO_SEND_TIMED(pipe, buf + offset, data_size, GS_REPL_SEND_TIMEOUT) != GS_SUCCESS) {
            return GS_ERROR;
        }

        offset += data_size;
        remain_size -= data_size;
    }

    return GS_SUCCESS;
}

status_t cs_write_stream_timeout(cs_pipe_t *pipe, const char *buf, uint32 size, int32 max_pkg_size, uint32 timeout)
{
    int32 offset = 0;
    int32 remain_size = (int32)size;
    int32 data_size;

    CM_POINTER2(pipe, buf);

    if (max_pkg_size == 0) {
        return VIO_SEND_TIMED(pipe, buf, size, timeout);
    }

    while (remain_size > 0) {
        data_size = remain_size > max_pkg_size ? max_pkg_size : remain_size;

        if (VIO_SEND_TIMED(pipe, buf + offset, data_size, timeout) != GS_SUCCESS) {
            return GS_ERROR;
        }

        offset += data_size;
        remain_size -= data_size;
    }

    return GS_SUCCESS;
}

status_t cs_read_stream(cs_pipe_t *pipe, char *buf, uint32 timeout, uint32 max_size, int32 *size)
{
    bool32 ready = GS_FALSE;
    uint32 read_size, recv_size, new_timeout, retry_count;
    uint32 wait_event = 0;
    CM_POINTER2(pipe, buf);

    read_size = 0;
    recv_size = 0;
    retry_count = 0;
    new_timeout = timeout;

    if (pipe->type == CS_TYPE_SSL) {
        if (VIO_RECV(pipe, buf, max_size, (int32 *)&recv_size, &wait_event) != GS_SUCCESS) {
            return GS_ERROR;
        }
        read_size = recv_size;
    }
    wait_event = (wait_event == 0) ? CS_WAIT_FOR_READ : wait_event;
    while (read_size < max_size) {
        if (VIO_WAIT(pipe, wait_event, new_timeout, &ready) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (!ready) {
            // Already received part of message, need to receive the rest.
            if (read_size > 0) {
                retry_count++;
                if (retry_count > GS_MAX_REP_RETRY_COUNT) {
                    // Return error if failed to receive the complete message in GS_MAX_REP_RETRY_COUNT times
                    GS_THROW_ERROR (ERR_TCP_TIMEOUT_REMAIN, (int32)(max_size - read_size));
                    return GS_ERROR;
                }

                // Reset timeout value in case of 0 timeout
                new_timeout = (timeout == 0) ? GS_POLL_WAIT : timeout;
                continue;
            }
            break;
        }

        if (VIO_RECV(pipe, buf + read_size, max_size - read_size, (int32 *)&recv_size, &wait_event) != GS_SUCCESS) {
            return GS_ERROR;
        }
        read_size += recv_size;
    }

    (*size) = read_size;

    return GS_SUCCESS;
}

status_t cs_ssl_accept(ssl_ctx_t *fd, cs_pipe_t *pipe)
{
    ssl_link_t *link = NULL;
    link = &pipe->link.ssl;
    link->ssl_ctx = fd;
    if (cs_ssl_accept_socket(link, pipe->link.tcp.sock, GS_SSL_IO_TIMEOUT) != GS_SUCCESS) {
        return GS_ERROR;
    }
    pipe->type = CS_TYPE_SSL;
    return GS_SUCCESS;
}

status_t cs_ssl_connect(ssl_ctx_t *fd, cs_pipe_t *pipe)
{
    ssl_link_t *link = NULL;
    link = &pipe->link.ssl;
    link->ssl_ctx = fd;
    if (cs_ssl_connect_socket(link, pipe->link.tcp.sock, GS_SSL_IO_TIMEOUT) != GS_SUCCESS) {
        return GS_ERROR;
    }
    pipe->type = CS_TYPE_SSL;
    return GS_SUCCESS;
}

socket_t cs_get_socket_fd(cs_pipe_t* pipe)
{
    if (pipe->type == CS_TYPE_TCP) {
        return pipe->link.tcp.sock;
    } else if (pipe->type == CS_TYPE_SSL) {
        return pipe->link.ssl.tcp.sock;
    } else if (pipe->type == CS_TYPE_RSOCKET) {
        return pipe->link.rdma.sock;
    } else {
        return CS_INVALID_SOCKET;
    }
}

#ifdef __cplusplus
}
#endif
