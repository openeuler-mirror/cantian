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
 * ctconn_conn.c
 *
 *
 * IDENTIFICATION
 * src/driver/ctconn/ctconn_conn.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctconn_conn.h"
#include "ctconn_balance.h"
#include "ctconn_stmt.h"
#include "ctconn_fetch.h"
#include "ctconn_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Used in free sensitive info string */
#define securec_free(m)                                              \
    do {                                                             \
        if ((m) != NULL) {                                           \
            errno_t rc_memzero = EOK;                                \
            if (strlen(m) > 0) {                                     \
                rc_memzero = memset_s((m), strlen(m), 0, strlen(m)); \
            }                                                        \
            free(m);                                                 \
            (m) = NULL;                                              \
            MEMS_RETURN_IFERR(rc_memzero);                           \
        }                                                            \
    } while (0)

static status_t clt_query(clt_conn_t *conn, const text_t *sql);
static status_t clt_get_conn_attr(clt_conn_t *conn, int32 attr, void *data, uint32 len, uint32 *attr_len);
static inline void clt_load_default_options(clt_options_t *options)
{
    MEMS_RETVOID_IFERR(memset_s(options, sizeof(clt_options_t), 0, sizeof(clt_options_t)));
    options->connect_timeout = (int32)CT_CONNECT_TIMEOUT / CT_TIME_THOUSAND;
    options->socket_timeout = -1;
    options->l_onoff = 1;
    options->l_linger = 1;

    // Enable SSL by default
    options->ssl_mode = CTCONN_SSL_PREFERRED;
    options->client_flag = CS_FLAG_CLIENT_SSL;
}

status_t ctconn_alloc_conn(ctconn_conn_t *pconn)
{
    clt_conn_t **conn = (clt_conn_t **)pconn;
    uint32 malloc_len = sizeof(clt_conn_t);
    clt_conn_t *connection = NULL;

    CTCONN_CHECK_OBJECT_NULL_GS(conn, "connection");

    connection = (clt_conn_t *)malloc(malloc_len);
    if (connection == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)malloc_len, "new connection");
        return CT_ERROR;
    }

    errno_t rc_memzero = memset_s(connection, malloc_len, 0, malloc_len);
    if (rc_memzero != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, rc_memzero);
        free(connection);
        return CT_ERROR;
    }

    cm_ptlist_init(&connection->stmts);
    cm_create_list(&connection->query.ids, sizeof(uint32));

    clt_load_default_options(&connection->options);
    cm_init_session_nlsparams(&connection->nls_params);
    connection->exit_commit = CT_TRUE;
    connection->num_width = (uint32)CT_MAX_DEC_OUTPUT_PREC;
    connection->local_charset = CT_DEFAULT_LOCAL_CHARSET;
    connection->server_version = CS_LOCAL_VERSION;
    connection->call_version = CS_LOCAL_VERSION;
    connection->options.app_kind = (uint16)CLIENT_KIND_CTCONN_GENERIC;
    connection->shd_rw_split = CTCONN_SHD_RW_SPLIT_NONE;
    connection->server_info.server_max_pack_size = CT_MAX_ALLOWED_PACKET_SIZE;
    cm_create_list2(&connection->pack_list, CLT_CONN_PACK_EXTEND_STEP, MAX_LIST_EXTENTS, sizeof(clt_packet_t));

    connection->pipe.connect_timeout = (int32)CT_CONNECT_TIMEOUT;
    connection->pipe.socket_timeout = -1;
    connection->pipe.l_onoff = 1;
    connection->pipe.l_linger = 1;
    connection->pipe.link.tcp.sock = CS_INVALID_SOCKET;
    connection->pipe.link.tcp.closed = CT_TRUE;
    connection->pipe.link.ssl.tcp.sock = CS_INVALID_SOCKET;
    connection->pipe.link.ssl.tcp.closed = CT_TRUE;

    connection->alter_set_info.commit_batch = CT_INVALID_ID16;
    connection->alter_set_info.commit_nowait = CT_INVALID_ID16;
    connection->alter_set_info.lock_wait_timeout = CT_INVALID_ID32;
    connection->alter_set_info.nologging_enable = CT_INVALID_ID8;

    *conn = connection;
    return CT_SUCCESS;
}

static void clt_disconnect(clt_conn_t *conn)
{
    uint32 i;
    clt_stmt_t *stmt = NULL;

    decrease_cluster_count(conn);

    for (i = 0; i < conn->stmts.count; i++) {
        stmt = (clt_stmt_t *)cm_ptlist_get(&conn->stmts, i);
        if (stmt != NULL) {
            clt_free_stmt(stmt);
        }
    }

    // query_stmt != NULL already free it in conn->stmts
    conn->query.query_stmt = NULL;
    conn->query.pos = 0;

    if (conn->ready) {
        // logout
        cs_packet_t *req_pack = &(conn->pack);
        cs_init_set(req_pack, conn->call_version);
        req_pack->head->cmd = CS_CMD_LOGOUT;
        (void)clt_remote_call(conn, req_pack, req_pack);
        conn->ready = CT_FALSE;
        conn->server_version = CS_LOCAL_VERSION;
        conn->call_version = CS_LOCAL_VERSION;
    }

    cs_try_free_packet_buffer(&conn->pack);

    cs_disconnect(&conn->pipe);
    CM_FREE_PTR(conn->options.user);
    CM_FREE_PTR(conn->options.host);
    CM_FREE_PTR(conn->options.server_path);
    CM_FREE_PTR(conn->options.client_path);
}

void ctconn_disconnect(ctconn_conn_t pconn)
{
    clt_conn_t *conn = (clt_conn_t *)pconn;

    if (SECUREC_UNLIKELY(conn == NULL)) {
        CT_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "connection");
        return;
    }

    CT_RETVOID_IFERR(clt_lock_conn(conn));
    clt_disconnect(conn);
    clt_unlock_conn(conn);
    return;
}

static void clt_ssl_free(clt_conn_t *conn)
{
    if (conn->ssl_connector != NULL) {
        cs_ssl_free_context((ssl_ctx_t *)conn->ssl_connector);
        conn->ssl_connector = NULL;
    }

    CM_FREE_PTR(conn->options.ssl_ca);
    CM_FREE_PTR(conn->options.ssl_cert);
    CM_FREE_PTR(conn->options.ssl_key);

    if (conn->options.ssl_keypwd != NULL) {
        size_t len = strlen(conn->options.ssl_keypwd);
        errno_t rc_memzero = memset_s(conn->options.ssl_keypwd, len, 0, len);
        if (rc_memzero != EOK) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, rc_memzero);
        }
        CM_FREE_PTR(conn->options.ssl_keypwd);
    }

    CM_FREE_PTR(conn->options.ssl_crl);
    CM_FREE_PTR(conn->options.ssl_cipher);
}

static void clt_free_pack_list(clt_conn_t *conn)
{
    for (uint32 i = 0; i < conn->pack_list.count; i++) {
        clt_packet_t *clt_pack = (clt_packet_t *)cm_list_get(&conn->pack_list, i);
        cs_try_free_packet_buffer(&clt_pack->pack);
    }
    cm_destroy_list(&conn->pack_list);
}

static void clt_free_conn(clt_conn_t *conn)
{
    if (conn->ready == CT_TRUE) {
        clt_disconnect(conn);
    }

    cm_destroy_ptlist(&conn->stmts);
    cm_destroy_list(&conn->query.ids);
    clt_ssl_free(conn);
    clt_free_pack_list(conn);
    CM_FREE_PTR(conn->options.server_path);
    CM_FREE_PTR(conn->options.client_path);
    CM_FREE_PTR(conn);
}

void ctconn_free_conn(ctconn_conn_t pconn)
{
    clt_conn_t *conn = (clt_conn_t *)pconn;

    if (conn == NULL) {
        return;
    }

    if (clt_lock_conn(conn) != CT_SUCCESS) {
        return;
    }

    clt_free_conn(conn);
    return;
}

static status_t clt_update_conn_opt(clt_conn_t *conn, const char *url, const char *user)
{
    if (conn->pipe.type == CS_TYPE_TCP) {
        text_t text_url, host_part, port_part;
        cm_str2text((char *)url, &text_url);
        (void)cm_split_rtext(&text_url, ':', '\0', &host_part, &port_part);

        conn->options.user = clt_strdup(user);
        if (conn->options.user == NULL) {
            cs_disconnect(&conn->pipe);
            CLT_THROW_ERROR(conn, ERR_CLT_OBJECT_IS_NULL, "user");
            return CT_ERROR;
        }
        CT_RETURN_IFERR(clt_strndup(host_part.str, host_part.len, &(conn->options.host)));
        if (conn->options.host == NULL) {
            cs_disconnect(&conn->pipe);
            CM_FREE_PTR(conn->options.user);
            CLT_THROW_ERROR(conn, ERR_CLT_OBJECT_IS_NULL, "host");
            return CT_ERROR;
        }

        if (cm_text2uint32(&port_part, &conn->options.port) != CT_SUCCESS) {
            cs_disconnect(&conn->pipe);
            CM_FREE_PTR(conn->options.user);
            CM_FREE_PTR(conn->options.host);
            return CT_ERROR;
        }
    }

    if (conn->pipe.type == CS_TYPE_DOMAIN_SCOKET) {
        conn->options.user = clt_strdup(user);
        if (conn->options.user == NULL) {
            cs_disconnect(&conn->pipe);
            CLT_THROW_ERROR(conn, ERR_CLT_OBJECT_IS_NULL, "user");
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

/**
Check if SSL can be establishes.

@param  conn        the connection handle
@retval CT_SUCCESS  success
@retval CT_ERROR    failure
*/
static status_t clt_ssl_check(clt_conn_t *conn)
{
    conn->client_flag = conn->options.client_flag;
    if (conn->pipe.type == CS_TYPE_DOMAIN_SCOKET) {
        conn->client_flag &= ~CS_FLAG_CLIENT_SSL;
        return CT_SUCCESS;
    }
    /* Don't fallback on unencrypted connection if SSL required */
    if (conn->options.ssl_mode >= CTCONN_SSL_REQUIRED && !(conn->server_capabilities & CS_FLAG_CLIENT_SSL)) {
        CLT_THROW_ERROR(conn, ERR_SSL_NOT_SUPPORT);
        return CT_ERROR;
    }

    /*
    If the ssl_mode is VERIFY_CA or VERIFY_IDENTIFY, make sure that the
    connection doesn't succeed without providing the CA certificate.
    */
    if (conn->options.ssl_mode > CTCONN_SSL_REQUIRED && !conn->options.ssl_ca) {
        CLT_THROW_ERROR(conn, ERR_SSL_CA_REQUIRED);
        return CT_ERROR;
    }

    /*
    Attempt SSL connection if ssl_mode != CTCONN_SSL_DISABLED and the
    server supports SSL. Fallback on unencrypted connection otherwise.
    */
    if (conn->options.ssl_mode != CTCONN_SSL_DISABLED && (conn->server_capabilities & CS_FLAG_CLIENT_SSL)) {
        conn->client_flag |= CS_FLAG_CLIENT_SSL;
    } else {
        conn->client_flag &= ~CS_FLAG_CLIENT_SSL;
    }
    return CT_SUCCESS;
}

static status_t clt_remote_wait(clt_conn_t *conn)
{
    bool32 ready = CT_FALSE;
    cs_pipe_t *pipe = &conn->pipe;

    if (cs_wait(pipe, CS_WAIT_FOR_READ, CT_HANDSHAKE_TIMEOUT, &ready) != CT_SUCCESS) {
        clt_copy_local_error(conn);
        return CT_ERROR;
    }

    if (!ready) {
        CLT_THROW_ERROR(conn, ERR_SOCKET_TIMEOUT, CT_HANDSHAKE_TIMEOUT / CT_TIME_THOUSAND_UN);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

/**
Establishes SSL from a connected socket

@param  conn        the connection handle
@retval CT_SUCCESS  success
@retval CT_ERROR    failure
*/
static status_t clt_ssl_establish(clt_conn_t *conn)
{
    ssl_verify_t mode;
    ssl_config_t para;
    ssl_ctx_t *ssl_fd = NULL;
    const char *cert_err = NULL;
    clt_options_t *options = &conn->options;

    MEMS_RETURN_IFERR(memset_s(&para, sizeof(ssl_config_t), 0, sizeof(ssl_config_t)));

    para.ca_file = options->ssl_ca;
    para.cert_file = options->ssl_cert;
    para.key_file = options->ssl_key;
    para.crl_file = options->ssl_crl;
    para.key_password = options->ssl_keypwd;
    para.cipher = options->ssl_cipher;
    para.verify_peer = CT_TRUE;

    /* Check certificate file access permission */
    if (cs_ssl_verify_file_stat(para.ca_file) != CT_SUCCESS) {
        clt_copy_local_error(conn);
        return CT_ERROR;
    }
    if (cs_ssl_verify_file_stat(para.cert_file) != CT_SUCCESS) {
        clt_copy_local_error(conn);
        return CT_ERROR;
    }
    if (cs_ssl_verify_file_stat(para.key_file) != CT_SUCCESS) {
        clt_copy_local_error(conn);
        return CT_ERROR;
    }

    if (cs_ssl_verify_file_stat(para.crl_file) != CT_SUCCESS) {
        clt_copy_local_error(conn);
        return CT_ERROR;
    }

    /* Create the ssl connector - init SSL and load certs */
    ssl_fd = cs_ssl_create_connector_fd(&para);

    /* We should erase it for security issue */
    securec_free(options->ssl_keypwd);

    if (ssl_fd == NULL) {
        clt_copy_local_error(conn);
        return CT_ERROR;
    }
    conn->ssl_connector = (uchar *)ssl_fd;

    /* Connect to the server */
    if (cs_ssl_connect(ssl_fd, &conn->pipe) != CT_SUCCESS) {
        clt_copy_local_error(conn);
        return CT_ERROR;
    }

    /* Verify server cert */
    if (options->ssl_mode > CTCONN_SSL_REQUIRED) {
        mode = (options->ssl_mode == CTCONN_SSL_VERIFY_CA) ? VERIFY_CERT : VERIFY_SUBJECT;
        if (cs_ssl_verify_certificate(&conn->pipe.link.ssl, mode, conn->options.host, &cert_err) != CT_SUCCESS) {
            CLT_THROW_ERROR(conn, ERR_SSL_VERIFY_CERT, cert_err);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

static status_t clt_send_auth_init(clt_conn_t *conn, const char *user, const char *tenant, const uchar *client_key,
    uint32 key_len, uint32 version)
{
    text_t text;
    cs_packet_t *send_pack = &conn->pack;

    cs_init_set(send_pack, version);
    send_pack->head->cmd = CS_CMD_AUTH_INIT;
    send_pack->head->flags = 0;
    if (conn->interactive_clt) {
        send_pack->head->flags |= CS_FLAG_INTERACTIVE_CLT;
    }
    if (conn->client_flag & CS_FLAG_CLIENT_SSL) {
        send_pack->head->flags |= CS_FLAG_CLIENT_SSL;
    }

    // 1. write username
    cm_str2text((char *)user, &text);
    CT_RETURN_IFERR(cs_put_text(send_pack, &text));
    // 2. write client_key
    cm_str2text_safe((char *)client_key, key_len, &text);
    CT_RETURN_IFERR(cs_put_text(send_pack, &text));

    // Attention: if add message in a higher version, please use conn->server_version
    if (conn->server_version >= CS_VERSION_18) {
        // 3. tenant name
        cm_str2text((char *)tenant, &text);
        CT_RETURN_IFERR(cs_put_text(send_pack, &text));
    }

    // send AUTH_INIT request
    if (cs_write(&conn->pipe, send_pack) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t clt_ssl_handshake_safe(clt_conn_t *conn, const char *user, const char *tenant, const uchar *client_key,
    uint32 key_len, uint32 version)
{
    uint32 ssl_notify, size;

    // tell server whether SSL channel is required
    CT_RETURN_IFERR(cs_put_int32(&conn->pack, conn->client_flag));
    if (cs_write(&conn->pipe, &conn->pack) != CT_SUCCESS) {
        clt_copy_local_error(conn);
        return CT_ERROR;
    }

    if (conn->client_flag & CS_FLAG_CLIENT_SSL) {
        // wait for handshake notify
        if (clt_remote_wait(conn) != CT_SUCCESS) {
            return CT_ERROR;
        }
        // read handshake notify
        if (cs_read_bytes(&conn->pipe, (char *)&ssl_notify, sizeof(uint32), (int32 *)&size) != CT_SUCCESS) {
            clt_copy_local_error(conn);
            return CT_ERROR;
        }

        if (sizeof(ssl_notify) != size || ssl_notify == 0) {
            return CT_ERROR;
        }

        CT_RETURN_IFERR(clt_ssl_establish(conn));
    }

    // wait for handshake reply
    if (clt_remote_wait(conn) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // read handshake reply
    if (cs_read(&conn->pipe, &conn->pack, CT_TRUE) != CT_SUCCESS) {
        clt_copy_local_error(conn);
        return CT_ERROR;
    }

    cs_init_get(&conn->pack);
    if (CS_HAS_EXEC_ERROR(&conn->pack)) {
        CT_RETURN_IFERR(cs_get_int32(&conn->pack, &conn->error_code));
        CT_RETURN_IFERR(cs_get_int16(&conn->pack, (int16 *)(&conn->loc.line)));
        CT_RETURN_IFERR(cs_get_int16(&conn->pack, (int16 *)(&conn->loc.column)));
        CT_RETURN_IFERR(clt_get_error_message(conn, &conn->pack, conn->message));
        return CT_ERROR;
    }

    // send auth_init request
    return clt_send_auth_init(conn, user, tenant, client_key, key_len, version);
}

static status_t clt_ssl_handshake(clt_conn_t *conn, const char *user, const uchar *client_key, uint32 key_len)
{
    text_t text;
    uint32 ssl_notify, size;

    // 1. write username
    cm_str2text((char *)user, &text);
    CT_RETURN_IFERR(cs_put_text(&conn->pack, &text));
    // 2. write client_flag
    CT_RETURN_IFERR(cs_put_int32(&conn->pack, conn->client_flag));
    // 3. write client_key
    text.str = (char *)client_key;
    text.len = key_len;
    CT_RETURN_IFERR(cs_put_text(&conn->pack, &text));

    // send handshake packet
    if (cs_write(&conn->pipe, &conn->pack) != CT_SUCCESS) {
        clt_copy_local_error(conn);
        return CT_ERROR;
    }

    // change to SSL layer if supported
    if (conn->client_flag & CS_FLAG_CLIENT_SSL) {
        // wait for handshake notify
        if (clt_remote_wait(conn) != CT_SUCCESS) {
            return CT_ERROR;
        }
        // read handshake notify
        if (cs_read_bytes(&conn->pipe, (char *)&ssl_notify, sizeof(uint32), (int32 *)&size) != CT_SUCCESS) {
            clt_copy_local_error(conn);
            return CT_ERROR;
        }

        if (sizeof(ssl_notify) != size || ssl_notify == 0) {
            return CT_ERROR;
        }

        CT_RETURN_IFERR(clt_ssl_establish(conn));
    }
    return CT_SUCCESS;
}

static status_t clt_encrypt_login_passwd(const char *plain_text, text_t *scramble_key, uint32 iter_count,
    uchar *salted_pwd, uint32 *salted_pwd_len, char *rsp_str, uint32 *rsp_len)
{
    uchar client_scram[2 * CT_MAX_CHALLENGE_LEN + CT_HMAC256MAXSIZE];
    uchar client_key[CT_HMAC256MAXSIZE];
    uchar stored_key[CT_HMAC256MAXSIZE];
    uchar client_sign[CT_HMAC256MAXSIZE];
    uint32 sign_key_len, key_len, stored_key_len;

    // verify scramble data
    sign_key_len = CT_MAX_CHALLENGE_LEN * 2;
    if ((scramble_key->len != sign_key_len + CT_KDF2SALTSIZE) || (*salted_pwd_len < CT_KDF2KEYSIZE)) {
        return CT_ERROR;
    }
    MEMS_RETURN_IFERR(
        memcpy_s(client_scram, 2 * CT_MAX_CHALLENGE_LEN + CT_HMAC256MAXSIZE, scramble_key->str, sign_key_len));

    // salted_pwd
    if (cm_encrypt_KDF2((uchar *)plain_text, (uint32)strlen(plain_text), (uchar *)(scramble_key->str + sign_key_len),
        CT_KDF2SALTSIZE, iter_count, salted_pwd, CT_KDF2KEYSIZE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    *salted_pwd_len = CT_KDF2KEYSIZE;

    // client_key
    key_len = CT_HMAC256MAXSIZE;
    if (cm_encrypt_HMAC(salted_pwd, CT_KDF2KEYSIZE, (uchar *)CT_CLIENT_KEY, (uint32)strlen(CT_CLIENT_KEY), client_key,
        &key_len) != CT_SUCCESS) {
        return CT_ERROR;
    }
    // stored_key
    stored_key_len = CT_HMAC256MAXSIZE;
    if (cm_generate_sha256(client_key, key_len, stored_key, &stored_key_len) != CT_SUCCESS) {
        return CT_ERROR;
    }
    // signature
    key_len = CT_HMAC256MAXSIZE;
    if (cm_encrypt_HMAC(stored_key, stored_key_len, (uchar *)scramble_key->str, sign_key_len, client_sign, &key_len) !=
        CT_SUCCESS) {
        return CT_ERROR;
    }
    // generate client_proof
    for (uint32 i = 0; i < CT_HMAC256MAXSIZE; ++i) {
        client_scram[i + sign_key_len] = (uchar)(client_key[i] ^ client_sign[i]);
    }

    // encode client_proof with base64
    return cm_base64_encode(client_scram, sizeof(client_scram), rsp_str, rsp_len);
}

static status_t clt_do_login(clt_conn_t *conn, const char *user, const char *password, const char *tenant)
{
    text_t text;
    char proc[CT_BUFLEN_1K];

    // 1. user
    cm_str2text((char *)user, &text);
    CT_RETURN_IFERR(cs_put_text(&conn->pack, &text));
    // 2. pwd
    cm_str2text((char *)password, &text);
    CT_RETURN_IFERR(cs_put_text(&conn->pack, &text));
    // 3. hostname
    cm_str2text(cm_sys_host_name(), &text);
    CT_RETURN_IFERR(cs_put_text(&conn->pack, &text));
    // 4. sys user
    cm_str2text(cm_sys_user_name(), &text);
    CT_RETURN_IFERR(cs_put_text(&conn->pack, &text));

    // 5. sys program
    PRTS_RETURN_IFERR(sprintf_s(proc, (CT_BUFLEN_1K - 1), "[%llu]%s", cm_sys_pid(), cm_sys_program_name()));

    cm_str2text(proc, &text);
    CT_RETURN_IFERR(cs_put_text(&conn->pack, &text));

    // 6. is_coord
    if (CS_IS_CN_CONNECTION(conn->pack.options)) {
        CT_RETURN_IFERR(cs_put_int16(&conn->pack, (uint16)CS_IS_CN_CONNECTION(conn->pack.options)));
    } else {
        CT_RETURN_IFERR(cs_put_int16(&conn->pack, (uint16)CS_IS_CN_IN_ALTER_PWD(conn->pack.options)));
    }

    // 7. timezone
    CT_RETURN_IFERR(cs_put_int16(&conn->pack, cm_get_local_tzoffset()));
    conn->local_sessiontz = cm_get_local_tzoffset();

    if (conn->call_version >= CS_VERSION_6) {
        // 8. client kind
        CT_RETURN_IFERR(cs_put_int16(&conn->pack, conn->options.app_kind));
    }

    if (conn->call_version >= CS_VERSION_12) {
        // 9. shard rw split flag
        CT_RETURN_IFERR(cs_put_int16(&conn->pack, (uint16)conn->shd_rw_split));
    }

    if (conn->call_version >= CS_VERSION_18) {
        // 10. tenant name
        cm_str2text((char *)tenant, &text);
        CT_RETURN_IFERR(cs_put_text(&conn->pack, &text));
    }

    return CT_SUCCESS;
}

static status_t clt_login(clt_conn_t *conn, const char *user, const char *password, const char *tenant,
    text_t *server_sign)
{
    cs_init_packet(&conn->pack, conn->pipe.options);
    cs_init_set(&conn->pack, conn->call_version);
    conn->pack.head->cmd = CS_CMD_LOGIN;
    conn->pack.head->flags = conn->interactive_clt ? CS_FLAG_INTERACTIVE_CLT : 0;
    if (conn->remote_as_sysdba) {
        conn->pack.head->flags |= CT_FLAG_REMOTE_AS_SYSDBA;
    }

    CT_RETURN_IFERR(clt_do_login(conn, user, password, tenant));

    CT_RETURN_IFERR(clt_remote_call(conn, &conn->pack, &conn->pack));

    /* erase the security Information */
    cs_init_get(&conn->pack);

    PRTS_RETURN_IFERR(sprintf_s(conn->message, CT_MESSAGE_BUFFER_SIZE, "connected."));
    CT_RETURN_IFERR(cs_get_int32(&conn->pack, (int32 *)&conn->sid));
    CT_RETURN_IFERR(cs_get_int32(&conn->pack, (int32 *)&conn->serial));
    CT_RETURN_IFERR(cs_get_int32(&conn->pack, (int32 *)&conn->server_info.locator_size));
    CT_RETURN_IFERR(cs_get_int32(&conn->pack, (int32 *)&conn->server_info.server_charset));

    if (conn->server_info.server_charset >= CHARSET_MAX) {
        CLT_SET_ERROR(conn, ERR_INVALID_CHARSET, "invalid server charset id: %d", conn->server_info.server_charset);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(clt_set_conn_transcode_func(conn));
    // server signature
    CT_RETURN_IFERR(cs_get_text(&conn->pack, server_sign));

    if (conn->call_version >= CS_VERSION_10) {
        CT_RETURN_IFERR(cs_get_int32(&conn->pack, (int32 *)&conn->server_info.server_max_pack_size));
    }
    conn->pack.max_buf_size = conn->server_info.server_max_pack_size;

    // db role
    if (conn->call_version >= CS_VERSION_15) {
        CT_RETURN_IFERR(cs_get_int32(&conn->pack, (int32 *)&conn->server_info.db_role));
    }

    if (CS_HAS_MORE(&conn->pack)) {
        CT_RETURN_IFERR(clt_get_error_message(conn, &conn->pack, conn->message));
    }

    return CT_SUCCESS;
}

static status_t clt_verify_server_signature(uchar *salted_pwd, uint32 salted_pwd_len, text_t *scramble_key,
    text_t *server_sign)
{
    uchar server_key[CT_HMAC256MAXSIZE];
    uchar c_server_sign[CT_HMAC256MAXSIZE];
    uint32 server_key_len, sign_key_len, key_len;

    sign_key_len = CT_MAX_CHALLENGE_LEN * 2;
    if (scramble_key->len < sign_key_len) {
        return CT_ERROR;
    }
    // server_key
    server_key_len = sizeof(server_key);
    if (cm_encrypt_HMAC(salted_pwd, salted_pwd_len, (uchar *)CT_SERVER_KEY, (uint32)strlen(CT_SERVER_KEY), server_key,
        &server_key_len) != CT_SUCCESS) {
        return CT_ERROR;
    }
    // server_signature
    key_len = sizeof(c_server_sign);
    if (cm_encrypt_HMAC(server_key, server_key_len, (uchar *)scramble_key->str, sign_key_len, c_server_sign,
        &key_len) != CT_SUCCESS) {
        return CT_ERROR;
    }
    // check
    if (key_len != server_sign->len || memcmp(c_server_sign, server_sign->str, key_len) != 0) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t clt_do_handshake(clt_conn_t *conn, const char *user, SENSI_INFO const char *passwd, const char *tenant,
    uint32 version)
{
    text_t scramble_key, server_sign;
    uchar scram_buf[CT_MAX_CHALLENGE_LEN * 2 + CT_KDF2SALTSIZE];
    uchar salted_pwd[CT_SCRAM256KEYSIZE];
    char pwd_cipher[CT_PASSWORD_BUFFER_SIZE];
    uchar client_key[CT_MAX_CHALLENGE_LEN];
    uint32 key_len, salted_pwd_len, iter_count;

    // before handshake set has_auth to false
    conn->has_auth = CT_FALSE;

    // check ssl
    conn->server_capabilities = 0;
    if (conn->pipe.options & CSO_CLIENT_SSL) {
        conn->server_capabilities |= CS_FLAG_CLIENT_SSL;
    }
    CT_RETURN_IFERR(clt_ssl_check(conn));

    // clean up options flags
    conn->pipe.options &= ~CSO_CLIENT_SSL;

    // prepare handshake packet
    cs_init_packet(&conn->pack, conn->pipe.options);
    conn->pack.max_buf_size = conn->server_info.server_max_pack_size;

    cs_init_set(&conn->pack, version);
    conn->pack.head->cmd = CS_CMD_HANDSHAKE;
    conn->pack.head->flags = 0;
    if (conn->interactive_clt) {
        conn->pack.head->flags |= CS_FLAG_INTERACTIVE_CLT;
    }
    if (conn->client_flag & CS_FLAG_CLIENT_SSL) {
        conn->pack.head->flags |= CS_FLAG_CLIENT_SSL;
    }

    // generate client challenge key
    CT_RETURN_IFERR(cm_rand(client_key, CT_MAX_CHALLENGE_LEN));

    // establish SSL channel first since v9.0
    if (conn->server_version >= CS_VERSION_9) {
        CT_RETURN_IFERR(clt_ssl_handshake_safe(conn, user, tenant, client_key, CT_MAX_CHALLENGE_LEN, version));
    } else {
        CT_RETURN_IFERR(clt_ssl_handshake(conn, user, client_key, CT_MAX_CHALLENGE_LEN));
    }

    // wait for handshake/auth_init ack
    if (clt_remote_wait(conn) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // read handshake ack
    if (cs_read(&conn->pipe, &conn->pack, CT_TRUE) != CT_SUCCESS) {
        clt_copy_local_error(conn);
        return CT_ERROR;
    }

    cs_init_get(&conn->pack);
    if (CS_HAS_EXEC_ERROR(&conn->pack)) {
        CT_RETURN_IFERR(cs_get_int32(&conn->pack, &conn->error_code));
        CT_RETURN_IFERR(cs_get_int16(&conn->pack, (int16 *)(&conn->loc.line)));
        CT_RETURN_IFERR(cs_get_int16(&conn->pack, (int16 *)(&conn->loc.column)));
        CT_RETURN_IFERR(clt_get_error_message(conn, &conn->pack, conn->message));
        return CT_ERROR;
    }

    // 1. server_capabilities
    CT_RETURN_IFERR(cs_get_int32(&conn->pack, (int32 *)&conn->server_capabilities));
    // 2. server version
    CT_RETURN_IFERR(cs_get_int32(&conn->pack, (int32 *)&conn->server_version));
    // 3. scramble key
    CT_RETURN_IFERR(cs_get_text(&conn->pack, &scramble_key));
    // 4. iteration
    if (cs_get_int32(&conn->pack, (int32 *)&iter_count) != CT_SUCCESS) {
        cm_reset_error();
        iter_count = CT_KDF2DEFITERATION;
    }
    if (iter_count > CT_KDF2MAXITERATION || iter_count < CT_KDF2MINITERATION) {
        CLT_THROW_ERROR(conn, ERR_INVALID_ENCRYPTION_ITERATION, CT_KDF2MINITERATION, CT_KDF2MAXITERATION);
        return CT_ERROR;
    }

    // verify client key
    if (scramble_key.len < sizeof(client_key) || memcmp(scramble_key.str, client_key, sizeof(client_key)) != 0) {
        CLT_THROW_ERROR(conn, ERR_TCP_PKT_VERIFY, "client key");
        return CT_ERROR;
    }
    // negotiate protocol version
    conn->call_version = (version > conn->server_version) ? conn->server_version : version;

    // before handshake set has_auth to false
    conn->has_auth = CT_TRUE;

    // 5. encrypt pwd with scramble_key
    key_len = sizeof(pwd_cipher);
    salted_pwd_len = sizeof(salted_pwd);
    if (clt_encrypt_login_passwd(passwd, &scramble_key, iter_count, salted_pwd, &salted_pwd_len, pwd_cipher,
        &key_len) != CT_SUCCESS) {
        CLT_THROW_ERROR(conn, ERR_GENERATE_CIPHER);
        return CT_ERROR;
    }
    pwd_cipher[key_len] = '\0';

    // backup scram_key
    if (scramble_key.len != 0) {
        MEMS_RETURN_IFERR(memcpy_s(scram_buf, sizeof(scram_buf), scramble_key.str, scramble_key.len));
    }
    scramble_key.str = (char *)scram_buf;

    // send login request
    CT_RETURN_IFERR(clt_login(conn, user, pwd_cipher, tenant, &server_sign));

    // verify signature
    if (clt_verify_server_signature(salted_pwd, salted_pwd_len, &scramble_key, &server_sign) != CT_SUCCESS) {
        CLT_THROW_ERROR(conn, ERR_TCP_PKT_VERIFY, "server signature");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t clt_connect(clt_conn_t *conn, const char *url, const char *user, const char *password, const char *tenant,
    uint32 version)
{
    /* disconnect conn if was connected */
    if (conn->ready == CT_TRUE) {
        clt_disconnect(conn);
    }

    /* create socket to server */
    if (cs_connect(url, &conn->pipe, NULL, conn->options.server_path, conn->options.client_path) != CT_SUCCESS) {
        clt_copy_local_error(conn);
        return CT_ERROR;
    }
    conn->node_type = conn->pipe.node_type;

    /* update conn options */
    CT_RETURN_IFERR(clt_update_conn_opt(conn, url, user));

    /* do handshake to server with user and pwd */
    if (clt_do_handshake(conn, user, password, tenant, version) != CT_SUCCESS) {
        cs_disconnect(&conn->pipe);
        CM_FREE_PTR(conn->options.user);
        CM_FREE_PTR(conn->options.host);
        return CT_ERROR;
    }

    conn->ready = CT_TRUE;
    return CT_SUCCESS;
}

status_t ctconn_set_shd_socket_timeout(clt_conn_t *conn, const void *data)
{
    status_t status;
    text_t tmp_text;
    text_t sql_text;
    char sql[CT_MAX_ALSET_SOCKET] = { 0 };
    MEMS_RETURN_IFERR(strcat_s(sql, CT_MAX_ALSET_SOCKET, "ALTER SESSION SET SHD_SOCKET_TIMEOUT = "));
    char buf[CT_MAX_INT32_STRLEN + 1];
    tmp_text.str = buf;
    cm_int2text(*(int32 *)data, &tmp_text);
    MEMS_RETURN_IFERR(strcat_s(sql, CT_MAX_ALSET_SOCKET, tmp_text.str));
    cm_str2text(sql, &sql_text);
    status = clt_query(conn, &sql_text);
    return status;
}

/* split url and tenant */
void ctconn_try_fetch_url_tenant(const char *str, text_t *url, text_t *tenant)
{
    cm_str2text((char *)str, tenant);
    (void)cm_fetch_rtext(tenant, '/', 0, url);
}

status_t ctconn_connect_inner(ctconn_conn_t pconn, const char *url, const char *user, const char *password, uint32 version)
{
    status_t status = CT_SUCCESS;
    clt_conn_t *conn = (clt_conn_t *)pconn;
    text_t cls_url = { 0 };
    text_t tenant = { 0 };
    char url_buf[CM_UNIX_DOMAIN_PATH_LEN + CT_STR_RESERVED_LEN];
    char tenant_buf[CT_TENANT_BUFFER_SIZE];

    CTCONN_CHECK_OBJECT_NULL_GS(conn, "connection");

    if (SECUREC_UNLIKELY(url == NULL || user == NULL || CM_IS_EMPTY_STR(password))) {
        CLT_THROW_ERROR(conn, ERR_CLT_OBJECT_IS_NULL, "url or user or password");
        return CT_ERROR;
    }
    ctconn_try_fetch_url_tenant(url, &cls_url, &tenant);
    if (tenant.len > CT_TENANT_NAME_LEN) {
        CLT_THROW_ERROR(conn, ERR_NAME_TOO_LONG, "tenant", tenant.len, CT_TENANT_NAME_LEN);
        return CT_ERROR;
    }
    CT_RETURN_IFERR(cm_text2str(&cls_url, url_buf, CM_UNIX_DOMAIN_PATH_LEN + CT_STR_RESERVED_LEN));
    cm_text2str_with_upper(&tenant, tenant_buf, CT_TENANT_BUFFER_SIZE);

    CT_RETURN_IFERR(clt_lock_conn(conn));
    // cluster url: ip:port,ip:port,ip:port...
    if (cm_char_in_text(',', &cls_url)) {
        char ssl_keypwd[CT_MAX_SSL_KEYPWD] = { 0 };
        if (conn->options.ssl_keypwd != NULL) {
            status = clt_get_conn_attr(conn, CTCONN_ATTR_SSL_KEYPWD, ssl_keypwd, sizeof(ssl_keypwd), NULL);
        }

        if (status == CT_SUCCESS) {
            status = clt_cluster_connect(conn, &cls_url, user, password, ssl_keypwd, tenant_buf);
        }

        if (memset_s(ssl_keypwd, CT_MAX_SSL_KEYPWD, 0, CT_MAX_SSL_KEYPWD) != EOK) {
            status = CT_ERROR;
        }
    } else {
        status = clt_connect(conn, url_buf, user, password, tenant_buf, version);
    }
    if (status == CT_SUCCESS && conn->node_type == CS_TYPE_CN) {
        int32 data = conn->options.socket_timeout;
        if (data != -1) {
            status = ctconn_set_shd_socket_timeout(conn, &data);
        }
    }
    clt_unlock_conn(conn);
    return status;
}

status_t ctconn_connect(ctconn_conn_t pconn, const char *url, const char *user, const char *password)
{
    return ctconn_connect_inner(pconn, url, user, password, CS_LOCAL_VERSION);
}

static inline status_t clt_check_input_onoff_num(clt_conn_t *conn, const void *data, int32 *attr_value)
{
    *attr_value = *(int32 *)data;

    if (*attr_value == 0 || *attr_value == 1) {
        return CT_SUCCESS;
    }

    CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "input number", (uint32)*attr_value);
    return CT_ERROR;
}

static status_t clt_set_conn_local_charset(clt_conn_t *conn, text_t *charset)
{
    uint16 charset_id = cm_get_charset_id_ex(charset);
    if (charset_id == CT_INVALID_ID16) {
        CLT_SET_ERROR(conn, ERR_INVALID_CHARSET, "unsupported charset %.*s", charset->len, charset->str);
        return CT_ERROR;
    }

    conn->local_charset = charset_id;

    return clt_set_conn_transcode_func(conn);
}

static status_t clt_set_conn_nls(clt_conn_t *conn, nlsparam_id_t id, const void *data, uint32 len)
{
    char alter_sql[MAX_SET_NLS_SQL];
    text_t nlsval, sql_text;

    nlsval.str = (char *)data;
    nlsval.len = len;

    cm_trim_text(&nlsval);

    if ((uint32)id >= NLS__MAX_PARAM_NUM) {
        CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "nls param id", (uint32)id);
        return CT_ERROR;
    }

    if (nlsval.len >= MAX_NLS_PARAM_LENGTH) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, g_nlsparam_items[id].key.str);
        return CT_ERROR;
    }
    PRTS_RETURN_IFERR(sprintf_s(alter_sql, MAX_SET_NLS_SQL, "alter session set %s = '%s'", g_nlsparam_items[id].key.str,
        T2S(&nlsval)));

    sql_text.str = alter_sql;
    sql_text.len = (uint32)strlen(alter_sql);

    return clt_query(conn, &sql_text);
}

#define CT_MIN_NUMWIDTH (uint32)6
#define CT_MAX_NUMWIDTH (uint32)CT_MAX_DEC_OUTPUT_ALL_PREC

status_t clt_set_conn_attr(clt_conn_t *conn, int32 attr, const void *data, uint32 len)
{
    uint32 i32_attr;
    int32 attr_value;
    text_t text;

    switch (attr) {
        case CTCONN_ATTR_AUTO_COMMIT:
            CT_RETURN_IFERR(clt_check_input_onoff_num(conn, data, &attr_value));
            conn->auto_commit = (uint8)attr_value;
            break;

        case CTCONN_ATTR_EXIT_COMMIT:
            CT_RETURN_IFERR(clt_check_input_onoff_num(conn, data, &attr_value));
            conn->exit_commit = (uint8)attr_value;
            break;

        case CTCONN_ATTR_SERVEROUTPUT:
            CT_RETURN_IFERR(clt_check_input_onoff_num(conn, data, &attr_value));
            conn->serveroutput = (uint8)attr_value;
            break;

        case CTCONN_ATTR_REMOTE_AS_SYSDBA:
            CT_RETURN_IFERR(clt_check_input_onoff_num(conn, data, &attr_value));
            conn->remote_as_sysdba = (uint8)attr_value;
            break;

        case CTCONN_ATTR_CHARSET_TYPE:
            text.str = (char *)data;
            text.len = len;
            CT_RETURN_IFERR(clt_set_conn_local_charset(conn, &text));
            break;

        case CTCONN_ATTR_NUM_WIDTH:
            i32_attr = *(uint32 *)data;
            if (i32_attr < CT_MIN_NUMWIDTH || i32_attr > CT_MAX_NUMWIDTH) {
                CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "numwidth option", i32_attr);
                return CT_ERROR;
            }
            conn->num_width = i32_attr;
            break;

        case CTCONN_ATTR_NLS_CALENDAR:
        case CTCONN_ATTR_NLS_CHARACTERSET:
        case CTCONN_ATTR_NLS_COMP:
        case CTCONN_ATTR_NLS_CURRENCY:
            return CT_SUCCESS;

        case CTCONN_ATTR_NLS_DATE_FORMAT:
            return clt_set_conn_nls(conn, (nlsparam_id_t)(attr - CTCONN_ATTR_NLS_CALENDAR), data, len);

        case CTCONN_ATTR_NLS_DATE_LANGUAGE:
        case CTCONN_ATTR_NLS_DUAL_CURRENCY:
        case CTCONN_ATTR_NLS_ISO_CURRENCY:
        case CTCONN_ATTR_NLS_LANGUAGE:
        case CTCONN_ATTR_NLS_LENGTH_SEMANTICS:
        case CTCONN_ATTR_NLS_NCHAR_CHARACTERSET:
        case CTCONN_ATTR_NLS_NCHAR_CONV_EXCP:
        case CTCONN_ATTR_NLS_NUMERIC_CHARACTERS:
        case CTCONN_ATTR_NLS_RDBMS_VERSION:
        case CTCONN_ATTR_NLS_SORT:
        case CTCONN_ATTR_NLS_TERRITORY:
            return CT_SUCCESS;

        case CTCONN_ATTR_NLS_TIMESTAMP_FORMAT:
        case CTCONN_ATTR_NLS_TIMESTAMP_TZ_FORMAT:
        case CTCONN_ATTR_NLS_TIME_FORMAT:
        case CTCONN_ATTR_NLS_TIME_TZ_FORMAT:
            return clt_set_conn_nls(conn, (nlsparam_id_t)(attr - CTCONN_ATTR_NLS_CALENDAR), data, len);

        case CTCONN_ATTR_INTERACTIVE_MODE:
            CT_RETURN_IFERR(clt_check_input_onoff_num(conn, data, &attr_value));
            conn->interactive_clt = (uint8)attr_value;
            break;

        case CTCONN_ATTR_SSL_CA:
            CM_FREE_PTR(conn->options.ssl_ca);
            CT_RETURN_IFERR(clt_strndup(data, len, &(conn->options.ssl_ca)));
            break;

        case CTCONN_ATTR_SSL_CERT:
            CM_FREE_PTR(conn->options.ssl_cert);
            CT_RETURN_IFERR(clt_strndup(data, len, &(conn->options.ssl_cert)));
            break;

        case CTCONN_ATTR_SSL_KEY:
            CM_FREE_PTR(conn->options.ssl_key);
            CT_RETURN_IFERR(clt_strndup(data, len, &(conn->options.ssl_key)));
            break;

        case CTCONN_ATTR_SSL_MODE:
            conn->options.ssl_mode = *(ctconn_ssl_mode_t *)data;
            break;

        case CTCONN_ATTR_SSL_CRL:
            CM_FREE_PTR(conn->options.ssl_crl);
            CT_RETURN_IFERR(clt_strndup(data, len, &(conn->options.ssl_crl)));
            break;

        case CTCONN_ATTR_SSL_KEYPWD:
            securec_free(conn->options.ssl_keypwd);
            CT_RETURN_IFERR(clt_strndup(data, len, &(conn->options.ssl_keypwd)));
            break;

        case CTCONN_ATTR_SSL_CIPHER:
            CM_FREE_PTR(conn->options.ssl_cipher);
            CT_RETURN_IFERR(clt_strndup(data, len, &(conn->options.ssl_cipher)));
            break;

        case CTCONN_ATTR_CONNECT_TIMEOUT:
            attr_value = *(int32 *)data;
            if (attr_value < 0 && attr_value != -1) {
                CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "connect timeout value", (uint32)attr_value);
                return CT_ERROR;
            }
            conn->options.connect_timeout = attr_value;
            conn->pipe.connect_timeout = (attr_value == -1) ? attr_value : attr_value * CT_TIME_THOUSAND;
            break;

        case CTCONN_ATTR_SOCKET_TIMEOUT:
            attr_value = *(int32 *)data;
            if (attr_value < 0 && attr_value != -1) {
                CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "socket timeout value", (uint32)attr_value);
                return CT_ERROR;
            }
            conn->options.socket_timeout = attr_value;
            conn->pipe.socket_timeout = (attr_value == -1) ? attr_value : attr_value * CT_TIME_THOUSAND;
            break;

        case CTCONN_ATTR_APP_KIND:
            attr_value = *(int16 *)data;
            if (attr_value <= CLIENT_KIND_UNKNOWN || attr_value >= CLIENT_KIND_TAIL) {
                CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "app kind value", (uint32)attr_value);
                return CT_ERROR;
            }
            conn->options.app_kind = (int16)attr_value;
            break;

        case CTCONN_ATTR_UDS_SERVER_PATH:
            CM_FREE_PTR(conn->options.server_path);
            CT_RETURN_IFERR(clt_strndup(data, len, &(conn->options.server_path)));
            break;

        case CTCONN_ATTR_UDS_CLIENT_PATH:
            CM_FREE_PTR(conn->options.client_path);
            CT_RETURN_IFERR(clt_strndup(data, len, &(conn->options.client_path)));
            break;

        case CTCONN_ATTR_FLAG_WITH_TS:
            CT_RETURN_IFERR(clt_check_input_onoff_num(conn, data, &attr_value));
            conn->flag_with_ts = (uint8)attr_value;
            break;

        case CTCONN_ATTR_SHD_RW_FLAG:
            attr_value = *(int32 *)data;
            if (attr_value < CTCONN_SHD_RW_SPLIT_NONE || attr_value > CTCONN_SHD_RW_SPLIT_ROA) {
                CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "shard rw split flag", (int32)attr_value);
                return CT_ERROR;
            }
            conn->shd_rw_split = (uint8)attr_value;
            break;

        case CTCONN_ATTR_SOCKET_L_ONOFF:
            attr_value = *(int32 *)data;
            conn->options.l_onoff = attr_value;
            conn->pipe.l_onoff = attr_value;
            break;

        case CTCONN_ATTR_SOCKET_L_LINGER:
            attr_value = *(int32 *)data;
            conn->options.l_linger = attr_value;
            conn->pipe.l_linger = attr_value;
            break;

        case CTCONN_ATTR_AUTOTRACE:
            attr_value = *(int32 *)data;
            conn->autotrace = (uint8)attr_value;
            break;

        default:
            CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "connection attribute id", (uint32)attr);
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t ctconn_set_conn_attr(ctconn_conn_t pconn, int32 attr, const void *data, uint32 len)
{
    status_t status;
    clt_conn_t *conn = (clt_conn_t *)pconn;

    CTCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    CTCONN_CHECK_OBJECT_NULL_CLT(conn, data, "value of connection attribute to set");

    CT_RETURN_IFERR(clt_lock_conn(conn));
    status = clt_set_conn_attr(conn, attr, data, len);
    clt_unlock_conn(conn);
    return status;
}

void ctconn_set_autocommit(ctconn_conn_t pconn, bool32 auto_commit)
{
    clt_conn_t *conn = (clt_conn_t *)pconn;
    int32 attr_value;

    CT_RETVOID_IFTRUE(SECUREC_UNLIKELY(conn == NULL));

    CT_RETVOID_IFERR(clt_check_input_onoff_num(conn, &auto_commit, &attr_value));
    conn->auto_commit = (uint8)attr_value;
}

static status_t ctconn_get_conn_nls(clt_conn_t *conn, nlsparam_id_t id, const void *data, uint32 len, uint32 *attr_len)
{
    text_t nlsfmt;
    conn->nls_params.param_geter(&conn->nls_params, id, &nlsfmt);
    if (len <= 1 || len <= nlsfmt.len) {
        CLT_THROW_ERROR(conn, ERR_CLT_BUF_SIZE_TOO_SMALL, "fetch nls fmt");
        return CT_ERROR;
    }
    CT_RETURN_IFERR(cm_text2str(&nlsfmt, (char *)data, len));
    if (attr_len != NULL) {
        *attr_len = nlsfmt.len;
    }
    return CT_SUCCESS;
}

uint32 ctconn_get_call_version(ctconn_conn_t conn)
{
    return (conn == NULL) ? CS_LOCAL_VERSION : ((struct st_clt_conn *)conn)->call_version;
}

uint32 ctconn_get_shd_node_type(ctconn_conn_t conn)
{
    return (conn == NULL) ? CS_RESERVED : ((struct st_clt_conn *)conn)->node_type;
}

static status_t ctconn_get_attr_string(const char *attr, void *data, uint32 len, uint32 *attr_len)
{
    uint32 temp_attr_len;

    if (CM_IS_EMPTY_STR(attr)) {
        temp_attr_len = 0;
    } else {
        temp_attr_len = (uint32)strlen(attr);
        if (temp_attr_len >= len) {
            CT_THROW_ERROR(ERR_CLT_BUF_SIZE_TOO_SMALL, "fetch conn attr data");
            return CT_ERROR;
        }

        MEMS_RETURN_IFERR(strncpy_s((char *)data, len, attr, strlen(attr)));
    }

    if (attr_len != NULL) {
        *attr_len = temp_attr_len;
    }
    *((char *)data + temp_attr_len) = '\0';
    return CT_SUCCESS;
}

static status_t clt_query_conn_dbtimezone(clt_conn_t *conn)
{
    uint32 row = 0;
    char *data = NULL;
    uint32 size = 0;
    uint32 is_null = 0;
    text_t text;

    char *alter_sql = NULL;
    text_t sql_text;
    status_t status = CT_ERROR;
    bool32 src_stmt_null = (conn->query.query_stmt == NULL) ? CT_TRUE : CT_FALSE;

    do {
        if (conn->call_version >= CS_VERSION_8) {
            alter_sql = "SELECT DBTIMEZONE FROM SYS.DV_INSTANCE";
        } else {
            alter_sql = "SELECT DBTIMEZONE FROM SYS.V$INSTANCE";
        }

        sql_text.str = alter_sql;
        sql_text.len = (uint32)strlen(alter_sql);

        if (CT_SUCCESS != clt_query(conn, &sql_text)) {
            cm_reset_error();
            conn->error_code = CT_SUCCESS;
            conn->message[0] = '\0';

            alter_sql = "SELECT DBTIMEZONE";

            sql_text.str = alter_sql;
            sql_text.len = (uint32)strlen(alter_sql);

            CT_BREAK_IF_ERROR(clt_query(conn, &sql_text));
        }

        /* fetch result */
        CT_BREAK_IF_ERROR(clt_fetch(conn->query.query_stmt, &row, CT_FALSE));
        CT_BREAK_IF_ERROR(clt_get_column_by_id(conn->query.query_stmt, 0, (void **)&data, &size, &is_null));

        /* save this value */
        text.str = data;
        text.len = size;

        CT_BREAK_IF_ERROR(cm_text2tzoffset(&text, &conn->server_info.server_dbtimezone));
        status = CT_SUCCESS;
    } while (0);

    if (src_stmt_null) {
        clt_free_stmt(conn->query.query_stmt);
        conn->query.query_stmt = NULL;
    }

    return status;
}

static status_t clt_query_conn_lastinsertid(clt_conn_t *conn)
{
    char *alter_sql = "SELECT LAST_INSERT_ID()";
    text_t sql_text;
    char *data = NULL;
    status_t status = CT_ERROR;
    bool32 src_stmt_null = (conn->query.query_stmt == NULL) ? CT_TRUE : CT_FALSE;

    do {
        sql_text.str = alter_sql;
        sql_text.len = (uint32)strlen(alter_sql);

        CT_BREAK_IF_ERROR(clt_query(conn, &sql_text));

        /* fetch result */
        CT_BREAK_IF_ERROR(clt_fetch(conn->query.query_stmt, NULL, CT_FALSE));
        CT_BREAK_IF_ERROR(clt_get_column_by_id(conn->query.query_stmt, 0, (void **)&data, NULL, NULL));

        conn->last_insert_id = *(int64 *)data;
        status = CT_SUCCESS;
    } while (0);

    if (src_stmt_null) {
        clt_free_stmt(conn->query.query_stmt);
        conn->query.query_stmt = NULL;
    }

    return status;
}

static status_t clt_get_charset_name(clt_conn_t *conn, charset_type_t charset, char *data, uint32 len, uint32 *attr_len)
{
    const char *charset_name = NULL;
    uint32 charset_len;

    if (len < CLT_CHARSET_NAME_SIZE) {
        CLT_THROW_ERROR(conn, ERR_CLT_BUF_SIZE_TOO_SMALL, "fetch charset name");
        return CT_ERROR;
    }

    charset_name = cm_get_charset_name(charset);
    if (data == NULL || charset_name == NULL) {
        CT_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "charset");
        return CT_ERROR;
    }

    charset_len = (uint32)strlen(charset_name);
    MEMS_RETURN_IFERR(strncpy_s(data, len, charset_name, charset_len));

    if (attr_len != NULL) {
        *attr_len = charset_len;
    }
    *(data + charset_len) = '\0';

    return CT_SUCCESS;
}

static status_t clt_get_conn_attr(clt_conn_t *conn, int32 attr, void *data, uint32 len, uint32 *attr_len)
{
    switch (attr) {
        case CTCONN_ATTR_AUTO_COMMIT:
            *(uint32 *)data = conn->auto_commit ? 1 : 0;
            if (attr_len != NULL) {
                *attr_len = sizeof(uint32);
            }
            break;

        case CTCONN_ATTR_XACT_STATUS:
            *(uint32 *)data = conn->xact_status;
            if (attr_len != NULL) {
                *attr_len = sizeof(uint32);
            }
            break;

        case CTCONN_ATTR_EXIT_COMMIT:
            *(uint32 *)data = conn->exit_commit ? 1 : 0;
            if (attr_len != NULL) {
                *attr_len = sizeof(uint32);
            }
            break;

        case CTCONN_ATTR_SERVEROUTPUT:
            *(uint32 *)data = conn->serveroutput ? 1 : 0;
            if (attr_len != NULL) {
                *attr_len = sizeof(uint32);
            }
            break;

        case CTCONN_ATTR_REMOTE_AS_SYSDBA:
            *(uint32 *)data = conn->remote_as_sysdba ? 1 : 0;
            if (attr_len != NULL) {
                *attr_len = sizeof(uint32);
            }
            break;

        case CTCONN_ATTR_CHARSET_TYPE:
            return clt_get_charset_name(conn, (charset_type_t)conn->local_charset, (char *)data, len, attr_len);

        case CTCONN_ATTR_NUM_WIDTH:
            *(uint32 *)data = (uint32)conn->num_width;
            if (attr_len != NULL) {
                *attr_len = sizeof(uint32);
            }
            break;

        case CTCONN_ATTR_NLS_CHARACTERSET:
            if (!conn->ready) {
                CLT_THROW_ERROR(conn, ERR_CLT_INVALID_ATTR, "NLS character set", "connection is not established");
                return CT_ERROR;
            }
            return clt_get_charset_name(conn, (charset_type_t)conn->server_info.server_charset, (char *)data, len,
                attr_len);

        case CTCONN_ATTR_NLS_CALENDAR:
        case CTCONN_ATTR_NLS_COMP:
        case CTCONN_ATTR_NLS_CURRENCY:
            return CT_SUCCESS;

        case CTCONN_ATTR_NLS_DATE_FORMAT:
            return ctconn_get_conn_nls(conn, (nlsparam_id_t)(attr - CTCONN_ATTR_NLS_CALENDAR), data, len, attr_len);

        case CTCONN_ATTR_NLS_DATE_LANGUAGE:
        case CTCONN_ATTR_NLS_DUAL_CURRENCY:
        case CTCONN_ATTR_NLS_ISO_CURRENCY:
        case CTCONN_ATTR_NLS_LANGUAGE:
        case CTCONN_ATTR_NLS_LENGTH_SEMANTICS:
        case CTCONN_ATTR_NLS_NCHAR_CHARACTERSET:
        case CTCONN_ATTR_NLS_NCHAR_CONV_EXCP:
        case CTCONN_ATTR_NLS_NUMERIC_CHARACTERS:
        case CTCONN_ATTR_NLS_RDBMS_VERSION:
        case CTCONN_ATTR_NLS_SORT:
        case CTCONN_ATTR_NLS_TERRITORY:
            return CT_SUCCESS;

        case CTCONN_ATTR_NLS_TIMESTAMP_FORMAT:
        case CTCONN_ATTR_NLS_TIMESTAMP_TZ_FORMAT:
        case CTCONN_ATTR_NLS_TIME_FORMAT:
        case CTCONN_ATTR_NLS_TIME_TZ_FORMAT:
            return ctconn_get_conn_nls(conn, (nlsparam_id_t)(attr - CTCONN_ATTR_NLS_CALENDAR), data, len, attr_len);

        case CTCONN_ATTR_DBTIMEZONE:
            return clt_query_conn_dbtimezone(conn);

        case CTCONN_ATTR_LOB_LOCATOR_SIZE:
            *(uint32 *)data = (uint32)conn->server_info.locator_size;
            if (attr_len != NULL) {
                *attr_len = sizeof(uint32);
            }
            break;

        case CTCONN_ATTR_SSL_CA:
            return ctconn_get_attr_string(conn->options.ssl_ca, data, len, attr_len);
        case CTCONN_ATTR_SSL_CERT:
            return ctconn_get_attr_string(conn->options.ssl_cert, data, len, attr_len);
        case CTCONN_ATTR_SSL_KEY:
            return ctconn_get_attr_string(conn->options.ssl_key, data, len, attr_len);
        case CTCONN_ATTR_SSL_KEYPWD:
            return ctconn_get_attr_string(conn->options.ssl_keypwd, data, len, attr_len);
        case CTCONN_ATTR_SSL_CRL:
            return ctconn_get_attr_string(conn->options.ssl_crl, data, len, attr_len);
        case CTCONN_ATTR_SSL_CIPHER:
            return ctconn_get_attr_string(conn->options.ssl_cipher, data, len, attr_len);
        case CTCONN_ATTR_SSL_MODE:
            *(uint32 *)data = (uint32)conn->options.ssl_mode;
            if (attr_len != NULL) {
                *attr_len = sizeof(uint32);
            }
            break;

        case CTCONN_ATTR_CONNECT_TIMEOUT:
            *(int32 *)data = conn->options.connect_timeout;
            if (attr_len != NULL) {
                *attr_len = sizeof(int32);
            }
            break;

        case CTCONN_ATTR_SOCKET_TIMEOUT:
            *(int32 *)data = conn->options.socket_timeout;
            if (attr_len != NULL) {
                *attr_len = sizeof(int32);
            }
            break;
        case CTCONN_ATTR_APP_KIND:
            *(int16 *)data = conn->options.app_kind;
            if (attr_len != NULL) {
                *attr_len = sizeof(int16);
            }
            break;

        case CTCONN_ATTR_INTERACTIVE_MODE:
            *(uint8 *)data = conn->interactive_clt;
            if (attr_len != NULL) {
                *attr_len = sizeof(uint8);
            }
            break;

        case CTCONN_ATTR_UDS_SERVER_PATH:
            return ctconn_get_attr_string(conn->options.server_path, data, len, attr_len);

        case CTCONN_ATTR_UDS_CLIENT_PATH:
            return ctconn_get_attr_string(conn->options.client_path, data, len, attr_len);

        case CTCONN_ATTR_TIMESTAMP_SIZE:
        case CTCONN_ATTR_TIMESTAMP_LTZ_SIZE:
            *(uint32 *)data = sizeof(timestamp_t);
            if (attr_len != NULL) {
                *attr_len = sizeof(uint32);
            }
            break;

        case CTCONN_ATTR_TIMESTAMP_TZ_SIZE:
            *(uint32 *)data = sizeof(timestamp_tz_t);
            if (attr_len != NULL) {
                *attr_len = sizeof(uint32);
            }
            break;

        case CTCONN_ATTR_FLAG_WITH_TS:
            *(uint32 *)data = conn->flag_with_ts ? 1 : 0;
            if (attr_len != NULL) {
                *attr_len = sizeof(uint32);
            }
            break;

        case CTCONN_ATTR_SHD_RW_FLAG:
            *(uint32 *)data = conn->shd_rw_split;
            if (attr_len != NULL) {
                *attr_len = sizeof(uint32);
            }
            break;

        case CTCONN_ATTR_LAST_INSERT_ID:
            CT_BREAK_IF_ERROR(clt_query_conn_lastinsertid(conn));
            *(int64 *)data = conn->last_insert_id;
            if (attr_len != NULL) {
                *attr_len = sizeof(int64);
            }
            break;

        case CTCONN_ATTR_SOCKET_L_ONOFF:
            *(int32 *)data = conn->options.l_onoff;
            if (attr_len != NULL) {
                *attr_len = sizeof(int32);
            }
            break;

        case CTCONN_ATTR_SOCKET_L_LINGER:
            *(int32 *)data = conn->options.l_linger;
            if (attr_len != NULL) {
                *attr_len = sizeof(int32);
            }
            break;
        case CTCONN_ATTR_AUTOTRACE:
            *(uint32 *)data = conn->autotrace;
            if (attr_len != NULL) {
                *attr_len = sizeof(uint32);
            }
            break;

        default:
            CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "connection attribute id", (uint32)attr);
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t ctconn_get_conn_attr(ctconn_conn_t pconn, int32 attr, void *data, uint32 len, uint32 *attr_len)
{
    status_t status;
    clt_conn_t *conn = (clt_conn_t *)pconn;

    CTCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    CTCONN_CHECK_OBJECT_NULL_CLT(conn, data, "value of connection attribute to get");

    CT_RETURN_IFERR(clt_lock_conn(conn));
    status = clt_get_conn_attr(conn, attr, data, len, attr_len);
    clt_unlock_conn(conn);
    return status;
}

static status_t clt_cancel(clt_conn_t *conn, uint32 sid)
{
    cs_packet_t *req_pack, *ack_pack;

    req_pack = &conn->pack;
    ack_pack = &conn->pack;

    cs_init_set(req_pack, conn->call_version);
    req_pack->head->cmd = CS_CMD_CANCEL;
    CT_RETURN_IFERR(cs_put_int32(req_pack, sid));
    return clt_remote_call(conn, req_pack, ack_pack);
}

status_t ctconn_cancel(ctconn_conn_t pconn, uint32 sid)
{
    status_t status;
    clt_conn_t *conn = (clt_conn_t *)pconn;

    CTCONN_CHECK_OBJECT_NULL_GS(conn, "connection");

    CT_RETURN_IFERR(clt_lock_conn(conn));
    status = clt_cancel(conn, sid);
    clt_unlock_conn(conn);
    return status;
}

static status_t clt_commit(clt_conn_t *conn)
{
    cs_packet_t *req_pack = NULL;
    cs_packet_t *ack_pack = NULL;

    req_pack = &conn->pack;
    ack_pack = &conn->pack;

    cs_init_set(req_pack, conn->call_version);
    req_pack->head->cmd = CS_CMD_COMMIT;

    if (clt_remote_call(conn, req_pack, ack_pack) != CT_SUCCESS) {
        clt_copy_local_error(conn);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t ctconn_commit(ctconn_conn_t pconn)
{
    status_t status;
    clt_conn_t *conn = (clt_conn_t *)pconn;

    CTCONN_CHECK_OBJECT_NULL_GS(conn, "connection");

    CT_RETURN_IFERR(clt_lock_conn(conn));
    status = clt_commit(conn);
    clt_unlock_conn(conn);
    return status;
}

static status_t clt_rollback(clt_conn_t *conn)
{
    cs_packet_t *req_pack = NULL;
    cs_packet_t *ack_pack = NULL;

    req_pack = &conn->pack;
    ack_pack = &conn->pack;

    cs_init_set(req_pack, conn->call_version);
    req_pack->head->cmd = CS_CMD_ROLLBACK;

    return clt_remote_call(conn, req_pack, ack_pack);
}

status_t ctconn_rollback(ctconn_conn_t pconn)
{
    status_t status;
    clt_conn_t *conn = (clt_conn_t *)pconn;

    CTCONN_CHECK_OBJECT_NULL_GS(conn, "connection");

    CT_RETURN_IFERR(clt_lock_conn(conn));
    status = clt_rollback(conn);
    clt_unlock_conn(conn);
    return status;
}

static status_t clt_query_single(clt_stmt_t *stmt, const text_t *sql)
{
    cs_packet_t *req_pack = NULL;
    cs_packet_t *ack_pack = NULL;
    cs_execute_req_t *req = NULL;
    uint32 req_offset;
    uint32 sql_size, total_size;

    req_pack = &stmt->conn->pack;
    ack_pack = &stmt->cache_pack->pack;

    /* request content is "cs_execute_req_t + sql" */
    cs_init_set(req_pack, stmt->conn->call_version);
    req_pack->head->cmd = CS_CMD_QUERY;
    CT_BIT_RESET(req_pack->head->flags, CS_FLAG_WITH_TS);

    CT_RETURN_IFERR(cs_reserve_space(req_pack, sizeof(cs_execute_req_t), &req_offset));
    req = (cs_execute_req_t *)CS_RESERVE_ADDR(req_pack, req_offset);
    req->stmt_id = stmt->stmt_id;
    req->paramset_size = 1;
    req->prefetch_rows = clt_prefetch_rows(stmt);
    req->auto_commit = stmt->conn->auto_commit;
    req->reserved = 0;
    cs_putted_execute_req(req_pack, req_offset);

    total_size = sql_size = sql->len;

    do {
        CT_RETURN_IFERR(ctconn_write_sql(stmt, sql->str, total_size, &sql_size, req_pack));
        CT_RETURN_IFERR(clt_remote_call(stmt->conn, req_pack, ack_pack));

        cs_init_set(req_pack, stmt->conn->call_version);
    } while (sql_size > 0);

    /* response content is "cs_prepare_ack_t + cs_execute_ack_t" */
    CT_RETURN_IFERR(clt_try_receive_pl_proc_data(stmt, ack_pack));

    CT_RETURN_IFERR(clt_get_prepare_ack(stmt, ack_pack, sql));

    CT_RETURN_IFERR(clt_try_process_feedback(stmt, ack_pack));
    CT_RETURN_IFERR(clt_get_execute_ack(stmt));

    stmt->status = CLI_STMT_EXECUTED;
    return CT_SUCCESS;
}

status_t ctconn_query_fetch(ctconn_conn_t pconn, uint32 *rows)
{
    status_t status;
    clt_conn_t *conn = (clt_conn_t *)pconn;
    clt_stmt_t *stmt = NULL;
    uint32 temp_rows = 0;

    CTCONN_CHECK_OBJECT_NULL_GS(conn, "connection");

    stmt = conn->query.query_stmt;
    CTCONN_CHECK_OBJECT_NULL_CLT(conn, stmt, "query statement");

    CT_RETURN_IFERR(clt_lock_conn(conn));

    if (clt_prepare_stmt_pack(stmt) != CT_SUCCESS) {
        clt_unlock_conn(conn);
        return CT_ERROR;
    }

    status = clt_fetch(stmt, &temp_rows, CT_FALSE);

    if (temp_rows == 0) {
        clt_recycle_stmt_pack(stmt);
    }

    if (SECUREC_LIKELY(rows != NULL)) {
        *rows = temp_rows;
    }

    clt_unlock_conn(conn);
    return status;
}

uint32 ctconn_query_get_affected_rows(ctconn_conn_t pconn)
{
    clt_conn_t *conn = (clt_conn_t *)pconn;
    clt_stmt_t *stmt = NULL;

    if (SECUREC_UNLIKELY(conn == NULL)) {
        return 0;
    }

    stmt = conn->query.query_stmt;
    return (stmt != NULL) ? stmt->affected_rows : 0;
}

uint32 ctconn_query_get_column_count(ctconn_conn_t pconn)
{
    clt_conn_t *conn = (clt_conn_t *)pconn;
    clt_stmt_t *stmt = NULL;

    if (SECUREC_UNLIKELY(conn == NULL)) {
        return 0;
    }

    stmt = conn->query.query_stmt;
    return (stmt != NULL) ? stmt->column_count : 0;
}

status_t ctconn_query_describe_column(ctconn_conn_t pconn, uint32 id, ctconn_column_desc_t *desc)
{
    status_t status;
    clt_conn_t *conn = (clt_conn_t *)pconn;
    clt_stmt_t *stmt = NULL;

    CTCONN_CHECK_OBJECT_NULL_GS(conn, "connection");

    stmt = conn->query.query_stmt;
    CTCONN_CHECK_OBJECT_NULL_CLT(conn, stmt, "query statement");

    CT_RETURN_IFERR(clt_lock_conn(conn));
    status = clt_desc_column_by_id(stmt, id, desc);
    clt_unlock_conn(conn);
    return status;
}

status_t ctconn_query_get_column(ctconn_conn_t pconn, uint32 id, void **data, uint32 *size, uint32 *is_null)
{
    status_t status;
    clt_conn_t *conn = (clt_conn_t *)pconn;
    clt_stmt_t *stmt = NULL;

    CTCONN_CHECK_OBJECT_NULL_GS(conn, "connection");

    stmt = conn->query.query_stmt;
    CTCONN_CHECK_OBJECT_NULL_CLT(conn, stmt, "query statement");

    CT_RETURN_IFERR(clt_lock_conn(conn));
    status = clt_get_column_by_id(stmt, id, data, size, is_null);
    clt_unlock_conn(conn);
    return status;
}

static void ctconn_reset_query(clt_conn_t *conn)
{
    clt_query_t *query = &conn->query;
    clt_stmt_t *sub_stmt = NULL;
    uint32 stmt_id, i;

    for (i = 0; i < query->ids.count; i++) {
        stmt_id = *(uint32 *)cm_list_get(&query->ids, i);
        sub_stmt = (clt_stmt_t *)cm_ptlist_get(&conn->stmts, stmt_id);
        if (sub_stmt != NULL) {
            clt_free_stmt(sub_stmt);
        }
    }

    cm_destroy_list(&query->ids);
    cm_create_list(&query->ids, sizeof(uint32));
    query->pos = 0;
}

static status_t clt_query(clt_conn_t *conn, const text_t *sql)
{
    clt_stmt_t *stmt = NULL;

    if (conn->query.ids.count > 0) {
        ctconn_reset_query(conn);
    }

    if (!conn->query.query_stmt) {
        if (clt_alloc_stmt(conn, &stmt) != CT_SUCCESS) {
            return CT_ERROR;
        }
        conn->query.query_stmt = stmt;
    }
    CT_RETURN_IFERR(clt_prepare_stmt_pack(conn->query.query_stmt));
    return clt_query_single(conn->query.query_stmt, sql);
}

status_t ctconn_query(ctconn_conn_t pconn, const char *sql)
{
    status_t status;
    clt_conn_t *conn = (clt_conn_t *)pconn;
    text_t sql_text;

    CTCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    CTCONN_CHECK_OBJECT_NULL_CLT(conn, sql, "sql");

    sql_text.str = (char *)sql;
    sql_text.len = (uint32)strlen(sql);

    CT_RETURN_IFERR(clt_lock_conn(conn));
    status = clt_query(conn, &sql_text);
    clt_unlock_conn(conn);
    return status;
}

static status_t clt_query_multiple(clt_conn_t *conn, const char *sql)
{
    text_t exec_sql;
    text_t sub_sql;
    clt_stmt_t *sub_stmt = NULL;
    bool32 rs_exists = CT_FALSE;
    uint32 *stmt_id = NULL;
    status_t ret = CT_SUCCESS;

    exec_sql.str = (char *)sql;
    exec_sql.len = (uint32)strlen(sql);

    if (conn->query.ids.count > 0) {
        ctconn_reset_query(conn);
    }

    while (cm_fetch_subsql(&exec_sql, &sub_sql)) {
        ret = clt_alloc_stmt(conn, &sub_stmt);
        CT_BREAK_IF_ERROR(ret);

        ret = clt_prepare_stmt_pack(sub_stmt);
        CT_BREAK_IF_ERROR(ret);

        ret = clt_query_single(sub_stmt, &sub_sql);
        CT_BREAK_IF_ERROR(ret);

        ret = clt_get_stmt_attr(sub_stmt, CTCONN_ATTR_RESULTSET_EXISTS, &rs_exists, sizeof(uint32), NULL);
        CT_BREAK_IF_ERROR(ret);

        // keep substmt of select for fetch data after query done
        if (rs_exists) {
            ret = cm_list_new(&conn->query.ids, (void **)&stmt_id);
            CT_BREAK_IF_ERROR(ret);

            *stmt_id = sub_stmt->id;
        } else {
            clt_free_stmt(sub_stmt);
        }

        sub_stmt = NULL;
    }

    if (sub_stmt != NULL) {
        clt_free_stmt(sub_stmt);
    }

    return ret;
}

status_t ctconn_query_multiple(ctconn_conn_t pconn, const char *sql)
{
    status_t status;
    clt_conn_t *conn = (clt_conn_t *)pconn;

    CTCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    CTCONN_CHECK_OBJECT_NULL_CLT(conn, sql, "sql");

    CT_RETURN_IFERR(clt_lock_conn(conn));
    status = clt_query_multiple(conn, sql);
    clt_unlock_conn(conn);
    return status;
}

#ifdef __cplusplus
}
#endif
