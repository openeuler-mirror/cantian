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
 * mes_tcp.c
 *
 *
 * IDENTIFICATION
 * src/mec/mes_tcp.c
 *
 * -------------------------------------------------------------------------
 */
#include "mes_log_module.h"
#include "cm_ip.h"
#include "cm_memory.h"
#include "cm_timer.h"
#include "cm_spinlock.h"
#include "cm_sync.h"
#include "cm_malloc.h"
#include "cs_tcp.h"
#include "mes_msg_pool.h"
#include "rc_reform.h"
#include "mes_tcp.h"

#define MES_HOST_NAME(id) ((char *)g_mes.profile.inst_arr[id].ip)

#define MES_CHANNEL_TIMEOUT (50)

#define MES_SESSION_TO_CHANNEL_ID(sid) (uint8)((sid) % g_mes.profile.channel_num)

// pipe
static void mes_close_send_pipe(mes_channel_t *channel)
{
    cm_thread_lock(&channel->lock);
    if (!channel->send_pipe_active) {
        CT_LOG_RUN_WAR("[mes] close send pipe[not active], channel id %u,"
            "send pipe socket %d closed %d, recv pipe socket %d closed %d",
            channel->id, channel->send_pipe.link.tcp.sock, channel->send_pipe.link.tcp.closed,
            channel->recv_pipe.link.tcp.sock, channel->recv_pipe.link.tcp.closed);
        cm_thread_unlock(&channel->lock);
        return;
    }
    CT_LOG_RUN_WAR("[mes] close send pipe, channel id %u,"
        "send pipe socket %d closed %d, recv pipe socket %d closed %d",
        channel->id, channel->send_pipe.link.tcp.sock, channel->send_pipe.link.tcp.closed,
        channel->recv_pipe.link.tcp.sock, channel->recv_pipe.link.tcp.closed);
    cs_disconnect(&channel->send_pipe);
    channel->send_pipe_active = CT_FALSE;
    cm_thread_unlock(&channel->lock);
    return;
}

static void mes_close_recv_pipe(mes_channel_t *channel)
{
    cm_thread_lock(&channel->lock);
    if (!channel->recv_pipe_active) {
        CT_LOG_RUN_WAR("[mes] close recv pipe[not active], channel id %u,"
            "send pipe socket %d closed %d, recv pipe socket %d closed %d",
            channel->id, channel->send_pipe.link.tcp.sock, channel->send_pipe.link.tcp.closed,
            channel->recv_pipe.link.tcp.sock, channel->recv_pipe.link.tcp.closed);
        cm_thread_unlock(&channel->lock);
        return;
    }
    CT_LOG_RUN_WAR("[mes] close recv pipe, channel id %u,"
        "send pipe socket %d closed %d, recv pipe socket %d closed %d",
        channel->id, channel->send_pipe.link.tcp.sock, channel->send_pipe.link.tcp.closed,
        channel->recv_pipe.link.tcp.sock, channel->recv_pipe.link.tcp.closed);
    cs_disconnect(&channel->recv_pipe);
    channel->recv_pipe_active = CT_FALSE;
    cm_thread_unlock(&channel->lock);
    return;
}

static void mes_close_channel(mes_channel_t *channel)
{
    mes_close_send_pipe(channel);
    cm_thread_lock(&channel->recv_pipe_lock);
    mes_close_recv_pipe(channel);
    cm_thread_unlock(&channel->recv_pipe_lock);
}

// channel
static status_t mes_alloc_channels(void)
{
    errno_t ret;
    uint32 alloc_size;
    char *temp_buf;
    uint32 i, j;
    mes_channel_t *channel;

    // alloc channel
    if (g_mes.profile.channel_num == 0) {
        CT_THROW_ERROR_EX(ERR_MES_CREATE_AREA, "channel_num %u is invalid", g_mes.profile.channel_num);
        return CT_ERROR;
    }

    alloc_size = sizeof(mes_channel_t *) * CT_MAX_INSTANCES +
                 sizeof(mes_channel_t) * CT_MAX_INSTANCES * g_mes.profile.channel_num;
    temp_buf = (char *)malloc(alloc_size);
    if (temp_buf == NULL) {
        CT_THROW_ERROR_EX(ERR_MES_CREATE_AREA, "allocate mes_channel_t failed, channel_num %u alloc size %u",
                          g_mes.profile.channel_num, alloc_size);
        return CT_ERROR;
    }
    ret = memset_sp(temp_buf, alloc_size, 0, alloc_size);
    if (ret != EOK) {
        cm_free(temp_buf);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    g_mes.mes_ctx.channels = (mes_channel_t **)temp_buf;
    temp_buf += (sizeof(mes_channel_t *) * CT_MAX_INSTANCES);
    for (i = 0; i < CT_MAX_INSTANCES; i++) {
        g_mes.mes_ctx.channels[i] = (mes_channel_t *)temp_buf;
        temp_buf += sizeof(mes_channel_t) * g_mes.profile.channel_num;
    }

    // init channel
    for (i = 0; i < CT_MAX_INSTANCES; i++) {
        for (j = 0; j < g_mes.profile.channel_num; j++) {
            channel = &g_mes.mes_ctx.channels[i][j];
            cm_init_thread_lock(&channel->lock);
            cm_init_thread_lock(&channel->recv_pipe_lock);
            init_msgqueue(&channel->msg_queue);
        }
    }

    return CT_SUCCESS;
}

static void mes_free_channels(void)
{
    if (g_mes.mes_ctx.channels != NULL) {
        free(g_mes.mes_ctx.channels);
        g_mes.mes_ctx.channels = NULL;
    }
}

static status_t mes_init_channels(void)
{
    // alloc channel
    if (mes_alloc_channels() != CT_SUCCESS) {
        CT_LOG_RUN_ERR("mes_alloc_channels failed.");
        return CT_ERROR;
    }

    // init msgqueue
    init_msgqueue(&g_mes.mq_ctx.local_queue);

    return CT_SUCCESS;
}

static void mes_stop_channels(void)
{
    uint32 i;
    if (g_mes.profile.channel_num == 0) {
        CT_LOG_RUN_ERR("channel_num %u is invalid", g_mes.profile.channel_num);
        return;
    }
    for (i = 0; i < g_mes.profile.inst_count; i++) {
        mes_tcp_disconnect(i);
    }
}

static void mes_destroy_channels(void)
{
    mes_stop_channels();
    mes_free_channels();
}

// listener
static status_t mes_init_pipe(cs_pipe_t *pipe)
{
    link_ready_ack_t ack;
    uint32 proto_code = 0;
    int32 size;

    if (cs_read_bytes(pipe, (char *)&proto_code, sizeof(proto_code), &size) != CT_SUCCESS) {
        cs_disconnect(pipe);
        CT_LOG_RUN_ERR("[mes]:cs_read_bytes failed.");
        return CT_ERROR;
    }

    if (sizeof(proto_code) != size || proto_code != CT_PROTO_CODE) {
        CT_THROW_ERROR(ERR_INVALID_PROTOCOL);
        return CT_ERROR;
    }

    ack.endian = (IS_BIG_ENDIAN ? (uint8)1 : (uint8)0);
    ack.handshake_version = CS_LOCAL_VERSION;
    ack.flags = 0;

    if (cs_send_bytes(pipe, (char *)&ack, sizeof(link_ready_ack_t)) != CT_SUCCESS) {
        cs_disconnect(pipe);
        CT_LOG_RUN_ERR("[mes]:cs_read_bytes failed.");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t mes_read_message(cs_pipe_t *pipe, mes_message_t *msg)
{
    char *buf;

    if (cs_read_fixed_size(pipe, msg->buffer, sizeof(mes_message_head_t)) != CT_SUCCESS) {
        cs_disconnect(pipe);
        CT_LOG_RUN_ERR("mes read message head failed.");
        return CT_ERROR;
    }

    if (mes_check_msg_head(msg->head) != CT_SUCCESS) {
        CT_THROW_ERROR_EX(ERR_MES_ILEGAL_MESSAGE, "message length %u, cmd=%u, rsn=%u, src_inst=%u, dst_inst=%u,"
            " src_sid=%u, dst_sid=%u.", msg->head->size, msg->head->cmd, msg->head->rsn, msg->head->src_inst,
            msg->head->dst_inst, msg->head->src_sid, msg->head->dst_sid);
        return CT_ERROR;
    }

    buf = msg->buffer + sizeof(mes_message_head_t);
    if (cs_read_fixed_size(pipe, buf, msg->head->size - sizeof(mes_message_head_t)) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("mes read message body failed.");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t mes_ssl_inner_accept(cs_pipe_t *pipe)
{
    mes_message_t msg;
    bool32 ready;
    mes_channel_t *channel;
    char msg_buf[MES_128K_MESSAGE_BUFFER_SIZE];

    status_t err = cs_ssl_accept(g_mes.mes_ctx.recv_ctx, pipe);
    if (err == CT_ERROR) {
        CT_LOG_RUN_ERR("[mes] ssl accept failed.");
        return CT_ERROR;
    }

    MES_MESSAGE_ATTACH(&msg, msg_buf);

    if (cs_wait(pipe, CS_WAIT_FOR_READ, CT_CONNECT_TIMEOUT, &ready) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[mes]: wait failed.");
        return CT_ERROR;
    }

    if (mes_read_message(pipe, &msg) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[mes]: read message failed.");
        return CT_ERROR;
    }

    if (msg.head->cmd != (uint8)MES_CMD_CONNECT) {
        CT_THROW_ERROR_EX(ERR_MES_INVALID_CMD, "when building connection type %u", msg.head->cmd);
        return CT_ERROR;
    }
    if (msg.head->src_sid >= g_mes.profile.channel_num) {
        CT_THROW_ERROR_EX(ERR_MES_ILEGAL_MESSAGE, "when building connection src_sid invalid %u", msg.head->src_sid);
        return CT_ERROR;
    }

    channel = &g_mes.mes_ctx.channels[msg.head->src_inst][msg.head->src_sid];
    cm_thread_lock(&channel->recv_pipe_lock);
    mes_close_recv_pipe(channel);
    cm_thread_lock(&channel->lock);

    channel->recv_pipe = *pipe;
    channel->recv_pipe_active = CT_TRUE;

    cm_thread_unlock(&channel->lock);
    cm_thread_unlock(&channel->recv_pipe_lock);
    CM_MFENCE;

    CT_LOG_RUN_INF("[mes] mes_accept: channel id %u receive ok,"
        "send pipe socket %d closed state %d, recv pipe socket %d closed state %d",
        channel->id, channel->send_pipe.link.ssl.tcp.sock, channel->send_pipe.link.ssl.tcp.closed,
        channel->recv_pipe.link.ssl.tcp.sock, channel->recv_pipe.link.ssl.tcp.closed);

    return CT_SUCCESS;
}

static status_t mes_accept(cs_pipe_t *pipe)
{
    mes_message_t msg;
    bool32 ready;
    mes_channel_t *channel;
    char msg_buf[MES_128K_MESSAGE_BUFFER_SIZE];

    if (mes_init_pipe(pipe) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[mes]: init pipe failed.");
        return CT_ERROR;
    }

    MES_MESSAGE_ATTACH(&msg, msg_buf);

    if (cs_wait(pipe, CS_WAIT_FOR_READ, CT_CONNECT_TIMEOUT, &ready) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[mes]: wait failed.");
        return CT_ERROR;
    }

    if (mes_read_message(pipe, &msg) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[mes]: read message failed.");
        return CT_ERROR;
    }

    if (msg.head->cmd != (uint8)MES_CMD_CONNECT) {
        CT_THROW_ERROR_EX(ERR_MES_INVALID_CMD, "when building connection type %u", msg.head->cmd);
        return CT_ERROR;
    }
    if (msg.head->src_sid >= g_mes.profile.channel_num) {
        CT_THROW_ERROR_EX(ERR_MES_ILEGAL_MESSAGE, "when building connection src_sid invalid %u", msg.head->src_sid);
        return CT_ERROR;
    }

    channel = &g_mes.mes_ctx.channels[msg.head->src_inst][msg.head->src_sid];
    cm_thread_lock(&channel->recv_pipe_lock);
    mes_close_recv_pipe(channel);
    cm_thread_lock(&channel->lock);
    channel->recv_pipe = *pipe;
    channel->recv_pipe_active = CT_TRUE;
    cm_thread_unlock(&channel->lock);
    cm_thread_unlock(&channel->recv_pipe_lock);
    CM_MFENCE;

    CT_LOG_RUN_INF("[mes] mes_accept: channel id %u receive ok,"
        "send pipe socket %d closed state %d, recv pipe socket %d closed state %d",
        channel->id, channel->send_pipe.link.tcp.sock, channel->send_pipe.link.tcp.closed,
        channel->recv_pipe.link.tcp.sock, channel->recv_pipe.link.tcp.closed);

    return CT_SUCCESS;
}

status_t mes_tcp_accept(tcp_lsnr_t *lsnr, cs_pipe_t *pipe)
{
    return mes_accept(pipe);
}

status_t mes_ssl_accept(tcp_lsnr_t *lsnr, cs_pipe_t *pipe)
{
    return mes_ssl_inner_accept(pipe);
}

status_t mes_start_lsnr(void)
{
    char *lsnr_host = MES_HOST_NAME(g_mes.profile.inst_id);
    errno_t ret = strncpy_s(g_mes.mes_ctx.lsnr.tcp.host[0], CM_MAX_IP_LEN, lsnr_host, CM_MAX_IP_LEN);
    MEMS_RETURN_IFERR(ret);
    g_mes.mes_ctx.lsnr.tcp.port = g_mes.profile.inst_arr[g_mes.profile.inst_id].port;
    g_mes.mes_ctx.lsnr.tcp.type = LSNR_TYPE_MES;

    if (!g_mes.profile.use_ssl) {
        if (cs_start_tcp_lsnr(&(g_mes.mes_ctx.lsnr.tcp), mes_tcp_accept, CT_FALSE) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[mes]:Start tcp lsnr failed.");
            return CT_ERROR;
        }
    } else {
        if (cs_start_ssl_lsnr(&(g_mes.mes_ctx.lsnr.tcp), mes_ssl_accept, CT_FALSE) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[mes]:Start ssl lsnr failed.");
            return CT_ERROR;
        }
    }

    printf("MES: LSNR %s:%hu\n", lsnr_host, g_mes.mes_ctx.lsnr.tcp.port);
    CT_LOG_RUN_INF("[mes] MES LSNR %s:%u\n", lsnr_host, g_mes.mes_ctx.lsnr.tcp.port);

    return CT_SUCCESS;
}

static void mes_stop_lsnr(void)
{
    errno_t ret;

    cs_stop_tcp_lsnr(&(g_mes.mes_ctx.lsnr.tcp));
    ret = memset_sp(g_mes.mes_ctx.lsnr.tcp.host[0], CM_MAX_IP_LEN, 0, CM_MAX_IP_LEN);
    MEMS_RETVOID_IFERR(ret);
}

status_t mes_ssl_decode_key_pwd(char *enc_data, uint16 enc_len, char *plain_data, int16 plain_len)
{
    /* encode key password with base64 and decode here, use other encode alg if you need */
    if (EVP_DecodeBlock((uchar *)plain_data, (uchar *)enc_data, enc_len) == CT_ERROR) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t mes_ssl_decode_kmc_pwd(char *plain, uint32 plain_len)
{
    aes_and_kmc_t aes_kmc = { 0 };
    char *enc_pass = mes_get_ssl_auth_file()->key_pwd;
    cm_kmc_set_kmc(&aes_kmc, CT_KMC_SERVER_DOMAIN, KMC_ALGID_AES256_CBC);
    cm_kmc_set_buf(&aes_kmc, plain, plain_len - 1, enc_pass, (uint32)strlen(enc_pass));
    if (cm_kmc_decrypt_pwd(&aes_kmc) != CT_SUCCESS) {
        CT_LOG_RUN_INF("[mes] SSL disabled: decrypt SSL private key password failed.");
        return CT_ERROR;
    }
    plain[aes_kmc.plain_len] = '\0';
    return CT_SUCCESS;
}

status_t mes_init_ssl(void)
{
    ssl_ctx_t *ssl_ctx = NULL;
    if (g_mes.profile.use_ssl) {
        ssl_config_t ssl_config = {0};
        ssl_auth_file_t *auth_file = mes_get_ssl_auth_file();
        ssl_config.ca_file = auth_file->ca_file;
        ssl_config.cert_file = auth_file->cert_file;
        ssl_config.key_file = auth_file->key_file;
        ssl_config.crl_file = auth_file->crl_file;
        ssl_config.verify_peer = g_mes.profile.ssl_verify_peer;
        char plain_pwd[CT_PASSWD_MAX_LEN] = {0};
        if (g_enable_dbstor) {
            char plain[CT_PASSWD_MAX_LEN + CT_AESBLOCKSIZE + 4];
            CT_RETURN_IFERR(mes_ssl_decode_kmc_pwd(plain, sizeof(plain)));
            ssl_config.key_password = plain;
        } else {
            char *enc_pwd = mes_get_ssl_auth_file()->key_pwd;
            if (!CM_IS_EMPTY_STR(enc_pwd)) {
                CT_RETURN_IFERR(mes_ssl_decode_key_pwd(enc_pwd, strlen(enc_pwd), plain_pwd, CT_PASSWD_MAX_LEN));
                ssl_config.key_password = plain_pwd;
            }
        }

        ssl_ctx = cs_ssl_create_acceptor_fd(&ssl_config);
        if (ssl_ctx == NULL) {
            CT_LOG_RUN_ERR("mes init ssl server ctx failed.");
            return CT_ERROR;
        }
        g_mes.mes_ctx.recv_ctx = ssl_ctx;
        CT_LOG_RUN_INF("mes init ssl server ctx success.");
    }
    return CT_SUCCESS;
}

// init
status_t mes_init_tcp(void)
{
    if (mes_init_message_pool() != CT_SUCCESS) {
        CT_LOG_RUN_ERR("mes_init_message_pool failed.");
        return CT_ERROR;
    }

    if (mes_init_channels() != CT_SUCCESS) {
        CT_LOG_RUN_ERR("mes_init_channels failed.");
        return CT_ERROR;
    }

    if (mes_init_ssl() != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (mes_start_lsnr() != CT_SUCCESS) {
        CT_LOG_RUN_ERR("mes_start_lsnr failed.");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void mes_destroy_tcp(void)
{
    // stop listen
    mes_stop_lsnr();

    // destroy channels
    mes_destroy_channels();

    mes_destory_message_pool();

    // free ssl ctx
    if (g_mes.profile.use_ssl) {
        cs_ssl_free_context(g_mes.mes_ctx.recv_ctx);
    }

    return;
}

static status_t mes_ssl_parse_url(const char *url, char *path, uint16 *port)
{
    text_t text, part1, part2;
    cm_str2text((char *)url, &text);
    (void)cm_split_rtext(&text, ':', '\0', &part1, &part2);
    CT_RETURN_IFERR(cm_text2str(&part1, path, CT_FILE_NAME_BUFFER_SIZE));
    if (!cm_is_short(&part2)) {
        CT_THROW_ERROR(ERR_CLT_INVALID_ATTR, "URL", url);
        return CT_ERROR;
    }

    if (cm_text2uint16(&part2, port) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static void mes_ssl_try_connect(mes_channel_t *channel)
{
    char peer_url[MES_URL_BUFFER_SIZE];
    char *remote_host = MES_HOST_NAME(MES_INSTANCE_ID(channel->id));
    mes_message_head_t head = { 0 };

    int32 ret = snprintf_s(peer_url, MES_URL_BUFFER_SIZE, MES_URL_BUFFER_SIZE, "%s:%u", remote_host,
        g_mes.profile.inst_arr[MES_INSTANCE_ID(channel->id)].port);
    if (ret < 0) {
        MES_LOGGING(MES_LOGGING_CONNECT, "snprintf_s error %d", ret);
        return;
    }

    channel->send_pipe.connect_timeout = CT_CONNECT_TIMEOUT;
    channel->send_pipe.l_onoff = 1;
    channel->send_pipe.l_linger = 1;
    ssl_link_t *link = &channel->send_pipe.link.ssl;

    char url_path[CT_FILE_NAME_BUFFER_SIZE];
    uint16 url_port;
    CT_RETVOID_IFERR(mes_ssl_parse_url((const char *)&peer_url[0], url_path, &url_port));

    socket_attr_t sock_attr = {.connect_timeout = channel->send_pipe.connect_timeout,
        .l_onoff = channel->send_pipe.l_onoff, .l_linger = channel->send_pipe.l_linger };

    cm_thread_lock(&channel->lock);
    /* create socket */
    if (cs_tcp_connect(url_path, url_port, &link->tcp, NULL, &sock_attr) != CT_SUCCESS) {
        MES_LOGGING(MES_LOGGING_CONNECT, "can't establish an connection to %s, channel id %u", peer_url, channel->id);
        cm_thread_unlock(&channel->lock);
        return;
    }

    status_t err = cs_ssl_connect(channel->send_ctx, &channel->send_pipe);
    if (err == CT_ERROR) {
        CT_LOG_RUN_ERR("[mes] ssl connect failed, channel id %u", channel->id);
        cm_thread_unlock(&channel->lock);
        return;
    }

    /* send connect info */
    head.cmd = MES_CMD_CONNECT;
    head.src_inst = g_mes.profile.inst_id;
    head.src_sid = MES_CHANNEL_ID(channel->id);  // use sid represent channel id.
    head.size = sizeof(mes_message_head_t);

    if (cs_send_bytes(&channel->send_pipe, (char *)&head, sizeof(mes_message_head_t)) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[mes] cs_send_bytes failed. peer %s channel id %u, send pipe socket %d closed %d, recv pipe socket %d closed %d",
            peer_url, channel->id, channel->send_pipe.link.ssl.tcp.sock, channel->send_pipe.link.ssl.tcp.closed,
            channel->recv_pipe.link.ssl.tcp.sock, channel->recv_pipe.link.ssl.tcp.closed);
        cs_disconnect(&channel->send_pipe);
        cm_thread_unlock(&channel->lock);
        return;
    }

    channel->send_pipe_active = CT_TRUE;
    cm_thread_unlock(&channel->lock);

    printf("mes connect to channel peer %s, success\n", peer_url);
    CT_LOG_RUN_INF("[mes] connect to channel peer %s, success. channel id %u, send pipe socket %d closed %d, recv pipe socket %d closed %d",
        peer_url, channel->id, channel->send_pipe.link.ssl.tcp.sock, channel->send_pipe.link.ssl.tcp.closed,
        channel->recv_pipe.link.ssl.tcp.sock, channel->recv_pipe.link.ssl.tcp.closed);
}

// connect
static void mes_tcp_try_connect(mes_channel_t *channel)
{
    int32 ret;
    char peer_url[MES_URL_BUFFER_SIZE];
    char *remote_host = MES_HOST_NAME(MES_INSTANCE_ID(channel->id));
    mes_message_head_t head = { 0 };

    ret = snprintf_s(peer_url, MES_URL_BUFFER_SIZE, MES_URL_BUFFER_SIZE, "%s:%u", remote_host,
                     g_mes.profile.inst_arr[MES_INSTANCE_ID(channel->id)].port);
    if (ret < 0) {
        MES_LOGGING(MES_LOGGING_CONNECT, "snprintf_s error %d", ret);
        return;
    }

    channel->send_pipe.connect_timeout = CT_CONNECT_TIMEOUT;
    channel->send_pipe.l_onoff = 1;
    channel->send_pipe.l_linger = 1;

    cm_thread_lock(&channel->lock);
    if (cs_connect((const char *)&peer_url[0], &channel->send_pipe, NULL, NULL, NULL) != CT_SUCCESS) {
        cm_thread_unlock(&channel->lock);
        MES_LOGGING(MES_LOGGING_CONNECT, "can't establish an connection to %s, channel id %u", peer_url, channel->id);
        return;
    }

    head.cmd = MES_CMD_CONNECT;
    head.src_inst = g_mes.profile.inst_id;
    head.src_sid = MES_CHANNEL_ID(channel->id);  // use sid represent channel id.
    head.size = sizeof(mes_message_head_t);

    if (cs_send_bytes(&channel->send_pipe, (char *)&head, sizeof(mes_message_head_t)) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cs_send_bytes failed. peer %s channel id %u,"
            "send pipe socket %d closed %d, recv pipe socket %d closed %d",
            peer_url, channel->id, channel->send_pipe.link.tcp.sock, channel->send_pipe.link.tcp.closed,
            channel->recv_pipe.link.tcp.sock, channel->recv_pipe.link.tcp.closed);
        cs_disconnect(&channel->send_pipe);
        cm_thread_unlock(&channel->lock);
        return;
    }

    channel->send_pipe_active = CT_TRUE;
    cm_thread_unlock(&channel->lock);

    printf("mes connect to channel peer %s, success\n", peer_url);
    CT_LOG_RUN_INF("[mes] connect to channel peer %s, success. channel id %u,"
        "send pipe socket %d closed %d, recv pipe socket %d closed %d",
        peer_url, channel->id, channel->send_pipe.link.tcp.sock, channel->send_pipe.link.tcp.closed,
        channel->recv_pipe.link.tcp.sock, channel->recv_pipe.link.tcp.closed);
}

static status_t mes_read_message_head(mes_channel_t *channel, mes_message_head_t *head)
{
    cs_pipe_t *pipe = &channel->recv_pipe;
    if (cs_read_fixed_size(pipe, (char *)head, sizeof(mes_message_head_t)) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("mes read message head failed and disconnect. pipe socket %d closed %d",
            pipe->link.tcp.sock, pipe->link.tcp.closed);
        mes_close_recv_pipe(channel);
        return CT_ERROR;
    }

    MES_LOG_HEAD_AND_PIPE(head, pipe);  // check whether the message read by the TCP is correct.

    if (mes_check_msg_head(head) != CT_SUCCESS) {
        CT_THROW_ERROR_EX(ERR_MES_ILEGAL_MESSAGE, "message length %u excced, cmd=%u, rsn=%u,"
            "channel id %u, src_inst=%u, dst_inst=%u, src_sid=%u, dst_sid=%u, pipe socket %d, closed %d.",
            head->size, channel->id, head->cmd, head->rsn, head->src_inst, head->dst_inst, head->src_sid,
            head->dst_sid, pipe->link.tcp.sock, pipe->link.tcp.closed);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

// recive
EXTER_ATTACK void mes_process_event(mes_channel_t *channel)
{
    mes_message_t msg;
    uint64 stat_time = 0;
    mes_message_head_t head;

    mes_get_consume_time_start(&stat_time);

    if (mes_read_message_head(channel, &head) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[mes]mes_read_message head failed. channel id %u,"
            "send pipe socket %d closed %d, recv pipe socket %d closed %d",
            channel->id, channel->send_pipe.link.tcp.sock, channel->send_pipe.link.tcp.closed,
            channel->recv_pipe.link.tcp.sock, channel->recv_pipe.link.tcp.closed);
        return;
    }

    mes_get_message_buf(&msg, &head);

    errno_t ret = memcpy_s(msg.buffer, sizeof(mes_message_head_t), &head, sizeof(mes_message_head_t));
    MEMS_RETVOID_IFERR(ret);

    if (cs_read_fixed_size(&channel->recv_pipe, msg.buffer + sizeof(mes_message_head_t),
                           msg.head->size - sizeof(mes_message_head_t)) != CT_SUCCESS) {
        mes_release_message_buf(msg.buffer);
        CT_LOG_RUN_ERR("mes read message body failed. channel id %u,"
            "send pipe socket %d closed %d, recv pipe socket %d closed %d",
            channel->id, channel->send_pipe.link.tcp.sock, channel->send_pipe.link.tcp.closed,
            channel->recv_pipe.link.tcp.sock, channel->recv_pipe.link.tcp.closed);
        return;
    }

    mes_consume_with_time(msg.head->cmd, MES_TIME_READ_MES, stat_time);

    cm_atomic_inc(&(channel->recv_count));

    if (g_mes.crc_check_switch) {
        if (mes_message_vertify_cks(&msg) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[mes] check cks failed, cmd=%u, rsn=%u, src_inst=%u, dst_inst=%u", msg.head->cmd,
                msg.head->rsn, msg.head->src_inst, msg.head->dst_sid);
            return;
        }
    }

    mes_process_message(&channel->msg_queue, MES_CHANNEL_ID(channel->id), &msg, stat_time);
    return;
}

static void mes_channel_entry(thread_t *thread)
{
    bool32 ready = CT_FALSE;
    mes_channel_t *channel = (mes_channel_t *)thread->argument;

    CT_LOG_RUN_INF("mes_channel_entry: channel id %u.", channel->id);

    cm_set_thread_name("mes_channel_entry");

    while (!thread->closed) {
        if (!channel->send_pipe_active) {
            if (!g_mes.profile.use_ssl) {
                mes_tcp_try_connect(channel);
            } else {
                mes_ssl_try_connect(channel);
            }
        }

        cm_thread_lock(&channel->recv_pipe_lock);
        if (!channel->recv_pipe_active) {
            cm_thread_unlock(&channel->recv_pipe_lock);
            cm_sleep(MES_CHANNEL_TIMEOUT);
            continue;
        }

        if (cs_wait(&channel->recv_pipe, CS_WAIT_FOR_READ, MES_CHANNEL_TIMEOUT, &ready) != CT_SUCCESS) {
            MES_LOGGING(MES_LOGGING_RECV, "channel id %u recv pipe closed,"
                "send pipe socket %d closed %d, recv pipe socket %d closed %d",
                channel->id, channel->send_pipe.link.tcp.sock, channel->send_pipe.link.tcp.closed,
                channel->recv_pipe.link.tcp.sock, channel->recv_pipe.link.tcp.closed);
            mes_close_recv_pipe(channel);
            cm_thread_unlock(&channel->recv_pipe_lock);
            continue;
        }

        if (!ready) {
            cm_thread_unlock(&channel->recv_pipe_lock);
            continue;
        }

        mes_process_event(channel);
        cm_thread_unlock(&channel->recv_pipe_lock);
    }
    if (!channel->sync_stop) {
        mes_close_channel(channel);
        channel->is_disconnct = CT_FALSE;
    }
    CT_LOG_RUN_WAR("[mes] channel entry thread exit, channel id: %u", channel->id);
}

// connect interface
status_t mes_tcp_connect(uint32 inst_id)
{
    uint32 i;
    mes_channel_t *channel;

    ssl_config_t ssl_config = {0};
    if (g_mes.profile.use_ssl) {
        ssl_auth_file_t *auth_file = mes_get_ssl_auth_file();
        ssl_config.ca_file = auth_file->ca_file;
        ssl_config.cert_file = auth_file->cert_file;
        ssl_config.key_file = auth_file->key_file;
        ssl_config.crl_file = auth_file->crl_file;
        ssl_config.verify_peer = g_mes.profile.ssl_verify_peer;
        if (g_enable_dbstor) {
            char plain[CT_PASSWD_MAX_LEN + CT_AESBLOCKSIZE + 4];
            CT_RETURN_IFERR(mes_ssl_decode_kmc_pwd(plain, sizeof(plain)));
            ssl_config.key_password = plain;
        } else {
            char plain_pwd[CT_PASSWD_MAX_LEN];
            char *enc_pwd = mes_get_ssl_auth_file()->key_pwd;
            if (!CM_IS_EMPTY_STR(enc_pwd)) {
                CT_RETURN_IFERR(mes_ssl_decode_key_pwd(enc_pwd, strlen(enc_pwd), plain_pwd, CT_PASSWD_MAX_LEN));
                ssl_config.key_password = plain_pwd;
            }
        }
    }

    for (i = 0; i < g_mes.profile.channel_num; i++) {
        channel = &g_mes.mes_ctx.channels[inst_id][i];
        channel->id = (inst_id << 8) | i;

        if (g_mes.profile.use_ssl) {
            channel->send_ctx = cs_ssl_create_connector_fd(&ssl_config);
            if (channel->send_ctx == NULL) {
                CT_LOG_RUN_ERR("[mes] init ssl clinet ctx failed.");
                return CT_ERROR;
            }
            CT_LOG_RUN_INF("mes init channel %d ssl send ctx success", channel->id);
        }

        if (cm_create_thread(mes_channel_entry, 0, (void *)channel, &channel->thread) != CT_SUCCESS) {
            CT_THROW_ERROR_EX(ERR_MES_INIT_FAIL, "create thread channel entry failed, node id %u channel id %u",
                              inst_id, i);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

void mes_tcp_disconnect(uint32 inst_id)
{
    uint32 i;
    mes_channel_t *channel;

    for (i = 0; i < g_mes.profile.channel_num; i++) {
        channel = &g_mes.mes_ctx.channels[inst_id][i];
        channel->sync_stop = CT_TRUE;
        cm_close_thread(&channel->thread);
        mes_close_channel(channel);
        if (g_mes.profile.use_ssl) {
            cs_ssl_free_context(channel->send_ctx);
        }
        CT_LOG_RUN_INF("mes disconnect finish");
    }
}

void mes_tcp_disconnect_async(uint32 inst_id)
{
    uint32 i;
    mes_channel_t *channel = NULL;

    CT_LOG_RUN_INF("mes disconnect async start");
    for (i = 0; i < g_mes.profile.channel_num; i++) {
        channel = &g_mes.mes_ctx.channels[inst_id][i];
        channel->sync_stop = CT_FALSE;
        channel->is_disconnct = CT_TRUE;
        cm_close_thread_nowait(&channel->thread);
    }

    for (i = 0; i < g_mes.profile.channel_num; i++) {
        channel = &g_mes.mes_ctx.channels[inst_id][i];
        while ((channel->is_disconnct == CT_TRUE) && (channel->is_send_msg == CT_TRUE)) {
            cm_sleep(1);
        }
    }
    CT_LOG_RUN_INF("mes disconnect async finish");
}

static bool32 mes_check_dst_alive(uint32_t inst_id)
{
    bool32 is_alive = rc_get_check_inst_alive(inst_id);
    CT_LOG_RUN_INF("mes check dest alive :inst %u is alive %u", inst_id, is_alive);
    return is_alive;
}

// send
status_t mes_tcp_send_data(const void *msg_data)
{
    uint64 stat_time = 0;
    mes_message_head_t *head = (mes_message_head_t *)msg_data;
    mes_channel_t *channel = &g_mes.mes_ctx.channels[head->dst_inst][MES_SESSION_TO_CHANNEL_ID(head->src_sid)];

    cm_thread_lock(&channel->lock);
    channel->is_send_msg = CT_TRUE;
    if (channel->is_disconnct == CT_TRUE) {
        channel->is_send_msg = CT_FALSE;
        cm_thread_unlock(&channel->lock);
        CT_LOG_RUN_WAR("[mes]channle(%u) from %u to %u will be closed, cmd=%u, rsn=%u, src_sid=%u, dst_sid=%u",
            channel->id, head->src_inst, head->dst_inst, head->cmd, head->rsn, head->src_sid, head->dst_sid);
        return CT_ERROR;
    }

    if (!channel->send_pipe_active) {
        channel->is_send_msg = CT_FALSE;
        cm_thread_unlock(&channel->lock);
        MES_LOGGING(MES_LOGGING_SEND, "send pipe from %u to %u is not ready,"
            "cmd=%u, rsn=%u, src_sid=%u, dst_sid=%u",
            head->src_inst, head->dst_inst, head->cmd, head->rsn,
            head->src_sid, head->dst_sid);
        return CT_ERROR;
    }

    mes_get_consume_time_start(&stat_time);
    if (cs_send_fixed_size(&channel->send_pipe, (char *)msg_data, head->size, head->dst_inst, mes_check_dst_alive) !=
        CT_SUCCESS) {
        channel->is_send_msg = CT_FALSE;
        cm_thread_unlock(&channel->lock);
        mes_close_send_pipe(channel);
        MES_LOGGING(MES_LOGGING_SEND, "cs send fixed size from %u to %u failed, cmd=%u, rsn=%u, src_sid=%u, dst_sid=%u",
                    head->src_inst, head->dst_inst, head->cmd, head->rsn, head->src_sid, head->dst_sid);
        return CT_ERROR;
    }

    MES_LOG_HEAD_AND_PIPE(head, &channel->send_pipe);

    channel->is_send_msg = CT_FALSE;
    mes_consume_with_time(head->cmd, MES_TIME_SEND_IO, stat_time);

    cm_thread_unlock(&channel->lock);

    cm_atomic_inc(&(channel->send_count));

    return CT_SUCCESS;
}

// cms send
status_t mes_cms_tcp_send_data(const void *msg_data)
{
    uint64 stat_time = 0;
    mes_message_head_t *head = (mes_message_head_t *)msg_data;
    mes_channel_t *channel = &g_mes.mes_ctx.channels[head->dst_inst][MES_SESSION_TO_CHANNEL_ID(head->src_sid)];

    cm_thread_lock(&channel->lock);
    channel->is_send_msg = CT_TRUE;
    if (channel->is_disconnct == CT_TRUE) {
        channel->is_send_msg = CT_FALSE;
        cm_thread_unlock(&channel->lock);
        CT_LOG_RUN_WAR("[mes]channle(%u) from %u to %u will be closed, cmd=%u, rsn=%u, src_sid=%u, dst_sid=%u",
            channel->id, head->src_inst, head->dst_inst, head->cmd, head->rsn, head->src_sid, head->dst_sid);
        return CT_ERROR;
    }

    if (!channel->send_pipe_active) {
        channel->is_send_msg = CT_FALSE;
        cm_thread_unlock(&channel->lock);
        MES_LOGGING(MES_LOGGING_SEND, "send pipe from %u to %u is not ready,"
            "cmd=%u, rsn=%u, src_sid=%u, dst_sid=%u",
            head->src_inst, head->dst_inst, head->cmd, head->rsn,
            head->src_sid, head->dst_sid);
        return CT_ERROR;
    }

    mes_get_consume_time_start(&stat_time);
    if (cs_send_fixed_size(&channel->send_pipe, (char *)msg_data, head->size, head->dst_inst, NULL) !=
        CT_SUCCESS) {
        channel->is_send_msg = CT_FALSE;
        cm_thread_unlock(&channel->lock);
        mes_close_send_pipe(channel);
        MES_LOGGING(MES_LOGGING_SEND, "cs send fixed size from %u to %u failed, cmd=%u, rsn=%u, src_sid=%u, dst_sid=%u",
                    head->src_inst, head->dst_inst, head->cmd, head->rsn, head->src_sid, head->dst_sid);
        return CT_ERROR;
    }

    MES_LOG_HEAD_AND_PIPE(head, &channel->send_pipe);

    channel->is_send_msg = CT_FALSE;
    mes_consume_with_time(head->cmd, MES_TIME_SEND_IO, stat_time);

    cm_thread_unlock(&channel->lock);

    cm_atomic_inc(&(channel->send_count));

    return CT_SUCCESS;
}

status_t mes_tcp_send_bufflist(mes_bufflist_t *buff_list)
{
    uint64 stat_time = 0;
    mes_message_head_t *head = (mes_message_head_t *)(buff_list->buffers[0].buf);
    mes_channel_t *channel = &g_mes.mes_ctx.channels[head->dst_inst][MES_SESSION_TO_CHANNEL_ID(head->src_sid)];

    cm_thread_lock(&channel->lock);
    channel->is_send_msg = CT_TRUE;
    if (channel->is_disconnct == CT_TRUE) {
        channel->is_send_msg = CT_FALSE;
        cm_thread_unlock(&channel->lock);
        CT_LOG_RUN_WAR("[mes]channle(%u) from %u to %u will be closed, cmd=%u, rsn=%u, src_sid=%u, dst_sid=%u",
            channel->id, head->src_inst, head->dst_inst, head->cmd, head->rsn, head->src_sid, head->dst_sid);
        return CT_ERROR;
    }

    if (!channel->send_pipe_active) {
        channel->is_send_msg = CT_FALSE;
        cm_thread_unlock(&channel->lock);
        MES_LOGGING(MES_LOGGING_SEND, "send pipe from %u to %u is not ready, cmd=%u, rsn=%u, src_sid=%u, dst_sid=%u",
                    head->src_inst, head->dst_inst, head->cmd, head->rsn, head->src_sid, head->dst_sid);
        return CT_ERROR;
    }

    mes_get_consume_time_start(&stat_time);
    for (int i = 0; i < buff_list->cnt; i++) {
        if (cs_send_fixed_size(&channel->send_pipe, buff_list->buffers[i].buf, buff_list->buffers[i].len,
                               head->dst_inst, mes_check_dst_alive) != CT_SUCCESS) {
            channel->is_send_msg = CT_FALSE;
            cm_thread_unlock(&channel->lock);
            mes_close_send_pipe(channel);
            MES_LOGGING(MES_LOGGING_SEND,
                        "cs send fixed size from %u to %u failed, cmd=%u, rsn=%u, src_sid=%u, dst_sid=%u",
                        head->src_inst, head->dst_inst, head->cmd, head->rsn, head->src_sid, head->dst_sid);
            return CT_ERROR;
        }
    }

    channel->is_send_msg = CT_FALSE;
    mes_consume_with_time(head->cmd, MES_TIME_SEND_IO, stat_time);

    cm_thread_unlock(&channel->lock);

    cm_atomic_inc(&(channel->send_count));

    return CT_SUCCESS;
}

bool32 mes_tcp_connection_ready(uint32 inst_id)
{
    uint32 i;
    mes_channel_t *channel;

    for (i = 0; i < g_mes.profile.channel_num; i++) {
        channel = &g_mes.mes_ctx.channels[inst_id][i];
        if ((!channel->send_pipe_active) || (!channel->recv_pipe_active) ||
            (channel->send_pipe.link.tcp.closed) || (channel->recv_pipe.link.tcp.closed)) {
            return CT_FALSE;
        }
    }

    return CT_TRUE;
}

mes_channel_stat_t mes_tcp_get_channel_state(uint32 inst_id)
{
    if (mes_tcp_connection_ready(inst_id)) {
        return MES_CHANNEL_CONNECTED;
    }
    return MES_CHANNEL_UNCONNECTED;
}

bool32 mes_ssl_connection_ready(uint32 inst_id)
{
    uint32 i;
    mes_channel_t *channel;

    for (i = 0; i < g_mes.profile.channel_num; i++) {
        channel = &g_mes.mes_ctx.channels[inst_id][i];
        if ((!channel->send_pipe_active) || (!channel->recv_pipe_active) ||
            (channel->send_pipe.link.ssl.tcp.closed) || (channel->recv_pipe.link.ssl.tcp.closed)) {
            return CT_FALSE;
        }
    }
    return CT_TRUE;
}
