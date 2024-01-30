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
 * repl_msg.c
 *
 *
 * IDENTIFICATION
 * src/kernel/replication/repl_msg.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_replication_module.h"
#include "repl_msg.h"
#include "cm_log.h"
#include "cs_protocol.h"
#include "knl_context.h"

#ifdef __cplusplus
extern "C" {
#endif

static ssl_ctx_t *g_ssl_fd = NULL;
static spinlock_t g_ssl_lock = 0;
static uint32 g_ssl_ref = 0;

typedef struct st_signature_info {
    text_t scramble_key;
    uchar scram_buf[CT_MAX_CHALLENGE_LEN + CT_MAX_CHALLENGE_LEN + CT_KDF2SALTSIZE];
    uchar salted_pwd[CT_SCRAM256KEYSIZE];
    uint32 salted_pwd_len;
} signature_info_t;

static char *g_type_name[] = { "REP_LOGIN_REPL", "REP_LOGIN_FAL", "REP_LOGIN_BACKUP" };
static status_t knl_verify_server_signature(signature_info_t *info, text_t *server_sign);
static status_t knl_get_cipher(knl_session_t *session, const char *c_key, cs_pipe_t *pipe, cs_packet_t *pack,
    char *cipher, uint32 clen, signature_info_t *info);

static status_t knl_check_auth_login_result(cs_pipe_t *pipe, cs_packet_t *pack, int32 *login_err)
{
    if (pack->head->result == 0) {
        return CT_SUCCESS;
    }

    if (cs_get_int32(pack, login_err) != CT_SUCCESS) {
        return CT_ERROR;
    }

    char *buf = NULL;
    text_t msg_text;

    if (pipe->version >= CS_VERSION_23) {
        if (cs_get_text(pack, &msg_text) != CT_SUCCESS) {
            return CT_ERROR;
        }
        buf = T2S(&msg_text);
    } else {
        if (cs_get_str(pack, &buf) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    CT_LOG_DEBUG_ERR("[REPL] auth login failed: %s", buf);
    return CT_ERROR;
}

static status_t knl_do_login(cs_pipe_t *pipe, cs_packet_t *pack, const char *user, int32 *login_err)
{
    text_t text;

    cs_init_packet(pack, pipe->options);
    cs_init_set(pack, pipe->version);
    pack->head->cmd = CS_CMD_REP_LOGIN;
    pack->head->flags = 0;
    pack->head->result = 0;

    cm_str2text((char *)user, &text);

    if (cs_put_text(pack, &text) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cs_call_ex(pipe, pack, pack) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cs_init_get(pack);
    if (pack->head->result != 0) {
        char *buf = NULL;
        text_t msg_text;

        if (cs_get_int32(pack, login_err) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (pipe->version >= CS_VERSION_23) {
            if (cs_get_text(pack, &msg_text) != CT_SUCCESS) {
                return CT_ERROR;
            }
            buf = T2S(&msg_text);
        } else {
            if (cs_get_str(pack, &buf) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }

        CT_LOG_DEBUG_ERR("[REPL] login failed: %s", buf);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t knl_do_auth_login(knl_session_t *session, const uchar *client_key, cs_pipe_t *pipe, cs_packet_t *pack,
                                  const char *type, int32 *login_err)
{
    text_t text;
    text_t server_sign;
    char cipher[CT_PASSWORD_BUFFER_SIZE];
    signature_info_t signature_info;

    if (pipe->version < CS_VERSION_19 && session->kernel->attr.repl_scram_auth) {
        CT_LOG_DEBUG_ERR("SCRAM authentication is required, but peer node does not support it");
        return CT_ERROR;
    }

    if (knl_get_cipher(session, (const char *)client_key, pipe, pack, cipher, sizeof(cipher),
                       &signature_info) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cs_init_packet(pack, pipe->options);
    cs_init_set(pack, pipe->version);
    pack->head->cmd = CS_CMD_REPAUTH_LOGIN;
    pack->head->flags = 0;
    pack->head->result = 0;

    // user
    cm_str2text((char *)"sys", &text);
    if (cs_put_text(pack, &text) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // pwd
    cm_str2text((char *)cipher, &text);
    if (cs_put_text(pack, &text) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // repl type
    cm_str2text((char *)type, &text);
    if (cs_put_text(pack, &text) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cs_call_ex(pipe, pack, pack) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cs_init_get(pack);
    if (knl_check_auth_login_result(pipe, pack, login_err) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (pipe->version < CS_VERSION_19) {
        return CT_SUCCESS;
    }

    if (cs_get_text(pack, &server_sign) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return knl_verify_server_signature(&signature_info, &server_sign);
}

static status_t knl_check_repl_host(knl_session_t *session, cs_pipe_t *pipe, const char* local_host, int32 *login_err)
{
    if (pipe->version < CS_VERSION_23) {
        return CT_SUCCESS;
    }

    cs_packet_t pack;
    text_t text;

    cs_init_packet(&pack, pipe->options);
    cs_init_set(&pack, pipe->version);
    pack.head->cmd = CS_CMD_REPL_HOST;
    pack.head->flags = 0;
    pack.head->result = 0;

    cm_str2text((char *)local_host, &text);

    if (cs_put_text(&pack, &text) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cs_call_ex(pipe, &pack, &pack) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cs_init_get(&pack);
    if (pack.head->result != 0) {
        (void)cs_get_int32(&pack, login_err);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t knl_check_repl_auth(knl_session_t *session, cs_pipe_t *pipe)
{
    cs_packet_t pack;

    cs_init_packet(&pack, pipe->options);
    cs_init_set(&pack, pipe->version);
    pack.head->cmd = CS_CMD_AUTH_CHECK;
    pack.head->flags = 0;
    pack.head->result = 0;

    if (cs_put_int32(&pack, session->kernel->attr.repl_auth) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cs_call_ex(pipe, &pack, &pack) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cs_init_get(&pack);
    return (pack.head->result != 0) ? CT_ERROR : CT_SUCCESS;
}

static inline void knl_fetch_signature_info(signature_info_t *info, text_t *scramble_key, salt_cipher_t *cipher)
{
    errno_t err = memcpy_s(info->salted_pwd, sizeof(info->salted_pwd), cipher->salted_pwd, cipher->salted_pwd_len);
    knl_securec_check(err);
    info->salted_pwd_len = cipher->salted_pwd_len;

    err = memcpy_s(info->scram_buf, sizeof(info->scram_buf), scramble_key->str, scramble_key->len);
    knl_securec_check(err);
    info->scramble_key.str = (char *)info->scram_buf;
    info->scramble_key.len = scramble_key->len;
}

static status_t knl_get_cipher(knl_session_t *session, const char *c_key, cs_pipe_t *pipe,
                               cs_packet_t *pack, char *cipher, uint32 clen, signature_info_t *info)
{
    SENSI_INFO char pwd[CT_PASSWORD_BUFFER_SIZE];
    text_t scramble_key;
    uchar salted_pwd[CT_SCRAM256KEYSIZE];
    salt_cipher_t salt_cipher;
    uint32 iter_count;
    int32 capability;
    int16 version;
    errno_t err;

    /* server_capabilities */
    if (cs_get_int32(pack, &capability) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* ssl between primary and standby should be same */
    if ((!g_knl_callback.have_ssl() && ((uint32)capability & CS_FLAG_CLIENT_SSL)) ||
        (g_knl_callback.have_ssl() && !((uint32)capability & CS_FLAG_CLIENT_SSL))) {
        CT_LOG_DEBUG_ERR("SSL should be consistent between primary and standby");
        return CT_ERROR;
    }

    /* server version */
    if (cs_get_int16(pack, &version) != CT_SUCCESS) {
        return CT_ERROR;
    }
    /* scramble key */
    if (cs_get_text(pack, &scramble_key) != CT_SUCCESS) {
        return CT_ERROR;
    }
    /* iteration */
    if (cs_get_int32(pack, (int32 *)&iter_count) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (iter_count < CT_KDF2MINITERATION || iter_count > CT_KDF2MAXITERATION) {
        CT_THROW_ERROR(ERR_INVALID_ENCRYPTION_ITERATION, CT_KDF2MINITERATION, CT_KDF2MAXITERATION);
        return CT_ERROR;
    }

    /* verify client key */
    if (scramble_key.str == NULL || memcmp(scramble_key.str, c_key, CT_MAX_CHALLENGE_LEN) != 0) {
        return CT_ERROR;
    }

    /* get plain passwd */
    if (cm_pwd_fetch_plain(session->kernel->home, pwd, sizeof(pwd)) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_try_update_repl_cipher(session, pwd) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* encrypt pwd with scramble_key */
    salt_cipher.salted_pwd = salted_pwd;
    salt_cipher.salted_pwd_len = sizeof(salted_pwd);
    salt_cipher.cipher = cipher;
    salt_cipher.cipher_len = clen;
    if (knl_encrypt_login_passwd(pwd, &scramble_key, iter_count, &salt_cipher) != CT_SUCCESS) {
        err = memset_sp(pwd, sizeof(pwd), 0, sizeof(pwd));
        knl_securec_check(err);
        return CT_ERROR;
    }

    cipher[salt_cipher.cipher_len] = '\0';
    err = memset_sp(pwd, sizeof(pwd), 0, sizeof(pwd));
    knl_securec_check(err);

    knl_fetch_signature_info(info, &scramble_key, &salt_cipher);
    return CT_SUCCESS;
}

static ssl_ctx_t *knl_init_ssl(config_t *config)
{
    char *verify_peer = NULL;
    char *keypwd_cipher = NULL;
    char keypwd_plain[CT_PASSWD_MAX_LEN + CT_AESBLOCKSIZE + 4]; /* 4 bytes for '\0' */
    errno_t err;
    ssl_config_t ssl_para;

    cm_spin_lock(&g_ssl_lock, NULL);
    if (g_ssl_fd != NULL) {
        g_ssl_ref++;
        cm_spin_unlock(&g_ssl_lock);
        return g_ssl_fd;
    }

    ssl_para.ca_file = cm_get_config_value(config, "SSL_CA");
    ssl_para.cert_file = cm_get_config_value(config, "SSL_CERT");
    ssl_para.key_file = cm_get_config_value(config, "SSL_KEY");
    ssl_para.crl_file = cm_get_config_value(config, "SSL_CRL");
    keypwd_cipher = cm_get_config_value(config, "SSL_KEY_PASSWORD");
    ssl_para.cipher = cm_get_config_value(config, "SSL_CIPHER");
    verify_peer = cm_get_config_value(config, "SSL_VERIFY_PEER");
    ssl_para.verify_peer = cm_str_equal_ins(verify_peer, "TRUE");

    if (CM_IS_EMPTY_STR(ssl_para.ca_file)) {
        ssl_para.verify_peer = CT_FALSE;
    }

    if (!CM_IS_EMPTY_STR(keypwd_cipher) && !CM_IS_EMPTY_STR(ssl_para.key_file)) {
        aes_and_kmc_t aes_kmc = {0};
        cm_kmc_set_aes_key_with_config(&aes_kmc, config);
        cm_kmc_set_kmc(&aes_kmc, CT_KMC_SERVER_DOMAIN, KMC_ALGID_AES256_CBC);
        cm_kmc_set_buf(&aes_kmc, keypwd_plain, sizeof(keypwd_plain) - 1,
            keypwd_cipher, (uint32)strlen(keypwd_cipher));
        if (cm_decrypt_passwd_with_key_by_kmc(&aes_kmc) != CT_SUCCESS) {
            cm_spin_unlock(&g_ssl_lock);
            CT_LOG_DEBUG_ERR("[REPL] decrypt SSL key password failed");
            return NULL;
        }
        keypwd_plain[aes_kmc.plain_len] = '\0';
        ssl_para.key_password = keypwd_plain;
    } else {
        ssl_para.key_password = NULL;
    }

    /* create ssl connector */
    g_ssl_fd = cs_ssl_create_connector_fd(&ssl_para);
    err = memset_sp(keypwd_plain, sizeof(keypwd_plain), 0, sizeof(keypwd_plain));
    if (err != EOK) {
        CT_LOG_RUN_ERR("Secure C lib has thrown an error %d", (err));
        cm_spin_unlock(&g_ssl_lock);
        return NULL;
    }
    if (g_ssl_fd == NULL) {
        cm_spin_unlock(&g_ssl_lock);
        CT_LOG_DEBUG_ERR("[REPL] Unable to create SSL connector");
        return NULL;
    }
    g_ssl_ref = 1;
    cm_spin_unlock(&g_ssl_lock);
    return g_ssl_fd;
}

static status_t knl_send_auth_init(cs_pipe_t *pipe, cs_packet_t *pack, uint16 client_flag,
    const char *user, const uchar *client_key, uint32 key_len)
{
    text_t text;

    cs_init_set(pack, pipe->version);
    pack->head->cmd = CS_CMD_AUTH_INIT;
    pack->head->flags = 0;
    if (client_flag & CS_FLAG_CLIENT_SSL) {
        pack->head->flags |= CS_FLAG_CLIENT_SSL;
    }

    if (cs_get_version(pack) >= CS_VERSION_18) {
        text_t user_text;
        text_t tenant_text = { 0 };

        // 0. split user to tenant and user
        cm_str2text((char*)user, &user_text);
        if (cm_strchr(&user_text, '$') != NULL) {
            (void)cm_fetch_text(&user_text, '$', 0, &tenant_text);
        }

        // 1. write username
        if (cs_put_text(pack, &user_text) != CT_SUCCESS) {
            return CT_ERROR;
        }
        // 2. write client_key
        cm_str2text_safe((char *)client_key, key_len, &text);
        if (cs_put_text(pack, &text) != CT_SUCCESS) {
            return CT_ERROR;
        }
        // 3. tenant name
        if (cs_put_text(pack, &tenant_text) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        // 1. write username
        cm_str2text((char *)user, &text);
        if (cs_put_text(pack, &text) != CT_SUCCESS) {
            return CT_ERROR;
        }
        // 2. write client_key
        cm_str2text_safe((char *)client_key, key_len, &text);
        if (cs_put_text(pack, &text) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    // send AUTH_INIT request
    if (cs_write(pipe, pack) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t knl_repl_wait(cs_pipe_t *pipe)
{
    bool32 ready = CT_FALSE;

    if (cs_wait(pipe, CS_WAIT_FOR_READ, pipe->connect_timeout, &ready) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (!ready) {
        CT_LOG_DEBUG_ERR("[REPL] Socket wait for reply timeout: %dms", pipe->connect_timeout);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}


static status_t knl_ssl_handshake_safe(cs_pipe_t *pipe, cs_packet_t *pack, ssl_ctx_t *ssl_fd,
    uint16 client_flag, const char *user, const uchar *client_key, uint32 key_len)
{
    uint32 ssl_notify, size;

    // tell server whether SSL channel is required
    if (cs_put_int32(pack, client_flag) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cs_write(pipe, pack) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // if SSL supported, change to SSL layer
    if (client_flag & CS_FLAG_CLIENT_SSL) {
        if (knl_repl_wait(pipe) != CT_SUCCESS) {
            return CT_ERROR;
        }
        // read SSL notify
        if (cs_read_bytes(pipe, (char *)&ssl_notify, sizeof(uint32), (int32 *)&size) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (sizeof(ssl_notify) != size || ssl_notify == 0) {
            return CT_ERROR;
        }

        /* connect to server using ssl layer */
        if (cs_ssl_connect(ssl_fd, pipe) != CT_SUCCESS) {
            CT_LOG_DEBUG_ERR("[REPL] Unable to establish SSL connection");
            return CT_ERROR;
        }
    }
    // wait for handshake reply
    if (knl_repl_wait(pipe) != CT_SUCCESS) {
        return CT_ERROR;
    }
    // read handshake reply
    if (cs_read(pipe, pack, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    // check result
    cs_init_get(pack);
    if (pack->head->result != 0) {
        return CT_ERROR;
    }

    // send AUTH_INIT request
    return knl_send_auth_init(pipe, pack, client_flag, user, client_key, key_len);
}

static status_t knl_ssl_handshake(cs_pipe_t *pipe, cs_packet_t *pack, ssl_ctx_t *ssl_fd,
    uint16 client_flag, const char *user, const uchar *client_key, uint32 key_len)
{
    text_t text;
    uint32 ssl_notify, size;

    // 1. username
    cm_str2text((char *)user, &text);
    if (cs_put_text(pack, &text) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // 2. write client_flag
    if (cs_put_int32(pack, (uint32)client_flag) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // 3. write client_key
    text.str = (char *)client_key;
    text.len = key_len;

    if (cs_put_text(pack, &text) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // write handshake packet
    if (cs_write(pipe, pack) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // if SSL supported, change to SSL layer
    if (client_flag & CS_FLAG_CLIENT_SSL) {
        if (knl_repl_wait(pipe) != CT_SUCCESS) {
            return CT_ERROR;
        }
        // read SSL notify
        if (cs_read_bytes(pipe, (char *)&ssl_notify, sizeof(uint32), (int32 *)&size) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (sizeof(ssl_notify) != size || ssl_notify == 0) {
            return CT_ERROR;
        }

        /* connect to server using ssl layer */
        if (cs_ssl_connect(ssl_fd, pipe) != CT_SUCCESS) {
            CT_LOG_DEBUG_ERR("[REPL] Unable to establish SSL connection");
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

static status_t knl_check_handshake_result(cs_pipe_t *pipe, cs_packet_t *pack, int32 *login_err)
{
    // wait for handshake/auth_init ack
    if (knl_repl_wait(pipe) != CT_SUCCESS) {
        return CT_ERROR;
    }
    // read handshake/auth_init ack
    if (cs_read(pipe, pack, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cs_init_get(pack);
    if (pack->head->result != 0) {
        (void)cs_get_int32(pack, login_err);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t knl_do_handshake(knl_session_t *session, cs_pipe_t *pipe, rep_login_type_t rep_type,
    const char* local_host, int32 *login_err)
{
    cs_packet_t pack;
    uchar client_key[CT_MAX_CHALLENGE_LEN];
    uint16 client_flag = 0;
    ssl_ctx_t *ssl_fd = NULL;
    bool32 auth_enable = (bool32)(pipe->version >= CS_VERSION_11 && session->kernel->attr.repl_auth);
    char *user = auth_enable ? "SYS" : g_type_name[rep_type];

    // check if the server supports ssl
    if (g_knl_callback.have_ssl()) {
        ssl_fd = knl_init_ssl(session->kernel->attr.config);
        if (ssl_fd != NULL) {
            client_flag |= CS_FLAG_CLIENT_SSL;
        }
    }
    pipe->options &= ~CS_FLAG_CLIENT_SSL;
    cs_init_packet(&pack, pipe->options);

    cs_init_set(&pack, pipe->version);
    pack.head->cmd = CS_CMD_HANDSHAKE;
    pack.head->flags = client_flag;

    if (cm_rand(client_key, CT_MAX_CHALLENGE_LEN) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (pipe->version >= CS_VERSION_9) {
        if (knl_ssl_handshake_safe(pipe, &pack, ssl_fd, client_flag, user,
            client_key, CT_MAX_CHALLENGE_LEN) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (knl_ssl_handshake(pipe, &pack, ssl_fd, client_flag, user,
            client_key, CT_MAX_CHALLENGE_LEN) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (knl_check_handshake_result(pipe, &pack, login_err) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_check_repl_host(session, pipe, local_host, login_err) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!auth_enable) {
        return knl_do_login(pipe, &pack, user, login_err);
    } else {
        return knl_do_auth_login(session, client_key, pipe, &pack, g_type_name[rep_type], login_err);
    }
}

status_t knl_login(knl_session_t *session, cs_pipe_t *pipe, rep_login_type_t rep_type,
    const char *local_host, int32 *login_err)
{
    int32 retcode = 0;

    if (login_err != NULL) {
        (*login_err) = 0;
    }

    if (session == NULL || pipe == NULL) {
        CT_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "login session or pipe");
        return CT_ERROR;
    }

    if (rep_type > REP_LOGIN_BACKUP) {
        CT_THROW_ERROR(ERR_CLT_INVALID_VALUE, "replication type", (uint32)rep_type);
        return CT_ERROR;
    }

    pipe->link.ssl.ssl_ctx = NULL;
    pipe->link.ssl.ssl_sock = NULL;

    if (pipe->link.tcp.closed) {
        CT_THROW_ERROR(ERR_PEER_CLOSED, "tcp");
        return CT_ERROR;
    }

    /* REPL_AUTH should be same between primary and standby */
    if (pipe->version >= CS_VERSION_11 && knl_check_repl_auth(session, pipe) != CT_SUCCESS) {
        CT_LOG_DEBUG_ERR("parameter REPL_AUTH check failed, local and peer are different");
        knl_disconnect(pipe);
        return CT_ERROR;
    }

    if (knl_do_handshake(session, pipe, rep_type, local_host, &retcode) != CT_SUCCESS) {
        if (login_err != NULL) {
            (*login_err) = retcode;
        }
        knl_disconnect(pipe);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void knl_disconnect(cs_pipe_t *pipe)
{
    cs_disconnect(pipe);

    if (g_ssl_fd != NULL && pipe->link.ssl.ssl_ctx == g_ssl_fd) {
        cm_spin_lock(&g_ssl_lock, NULL);
        if (g_ssl_ref > 0) {
            g_ssl_ref--;
        }
        if (g_ssl_ref == 0 && g_ssl_fd != NULL) {
            cs_ssl_free_context(g_ssl_fd);
            g_ssl_fd = NULL;
        }
        cm_spin_unlock(&g_ssl_lock);
    }
    pipe->link.ssl.ssl_ctx = NULL;
}

status_t knl_encrypt_login_passwd(const char *plain_text, text_t *scramble_key, uint32 iter_count,
                                  salt_cipher_t *salt_cipher)
{
    uchar client_scram[CT_SCRAM256KEYSIZE + CT_HMAC256MAXSIZE];
    uchar client_key[CT_HMAC256MAXSIZE];
    uchar stored_key[CT_HMAC256MAXSIZE];
    uchar client_sign[CT_HMAC256MAXSIZE];
    uint32 sign_key_len, key_len, stored_key_len;
    errno_t err;

    /* verify scramble data */
    sign_key_len = CT_SCRAM256KEYSIZE;
    if ((scramble_key->len != sign_key_len + CT_KDF2SALTSIZE) || (salt_cipher->salted_pwd_len < CT_KDF2KEYSIZE)) {
        return CT_ERROR;
    }
    err = memcpy_sp(client_scram, CT_SCRAM256KEYSIZE + CT_HMAC256MAXSIZE, scramble_key->str, sign_key_len);
    knl_securec_check(err);

    /* salted_pwd */
    if (cm_encrypt_KDF2((uchar *)plain_text, (uint32)strlen(plain_text), (uchar *)(scramble_key->str + sign_key_len),
                        CT_KDF2SALTSIZE, iter_count, salt_cipher->salted_pwd, CT_KDF2KEYSIZE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    salt_cipher->salted_pwd_len = CT_KDF2KEYSIZE;

    /* client_key */
    key_len = CT_HMAC256MAXSIZE;
    if (cm_encrypt_HMAC(salt_cipher->salted_pwd, CT_KDF2KEYSIZE, (uchar *)CT_CLIENT_KEY, (uint32)strlen(CT_CLIENT_KEY),
                        client_key, &key_len) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* stored_key */
    stored_key_len = CT_HMAC256MAXSIZE;
    if (cm_generate_sha256(client_key, key_len, stored_key, &stored_key_len) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* signature */
    key_len = CT_HMAC256MAXSIZE;
    if (cm_encrypt_HMAC(stored_key, stored_key_len, (uchar *)scramble_key->str, sign_key_len, client_sign,
                        &key_len) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* generate client_proof */
    for (uint32 i = 0; i < CT_HMAC256MAXSIZE; ++i) {
        client_scram[i + sign_key_len] = (uchar)(client_key[i] ^ client_sign[i]);
    }

    /* encode client_proof with base64 */
    if (cm_base64_encode(client_scram, sizeof(client_scram), salt_cipher->cipher,
        &salt_cipher->cipher_len) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t knl_generate_repl_key_cipher(knl_session_t *session, const char *plain)
{
    char fkey[CT_AES256KEYSIZE] = { 0 };
    char wkey[CT_MAX_LOCAL_KEY_STR_LEN_DOUBLE + 1] = { 0 };
    char cipher[CT_PASSWORD_BUFFER_SIZE] = { 0 };

    /* Generate factor key and worker key */
    if (cm_generate_repl_key(fkey, sizeof(fkey), wkey, sizeof(wkey)) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* Generate cipher */
    if (cm_generate_repl_cipher(plain, fkey, wkey, cipher, sizeof(cipher)) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* Store keys and cipher */
    if (cm_pwd_store_keys(session->kernel->home, cipher, fkey, wkey) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t knl_try_update_repl_cipher(knl_session_t *session, const char *plain)
{
    status_t st;
    errno_t err;
    char pwd[CT_PASSWORD_BUFFER_SIZE];
    uint32 len = (uint32)strlen(plain);
    if (len >= CT_REPL_PASSWD_MIN_LEN) {
        return CT_SUCCESS;
    }

    err = memset_s(pwd, sizeof(pwd), 0, sizeof(pwd));
    knl_securec_check(err);
    
    err = strcpy_sp(pwd, sizeof(pwd), plain);
    knl_securec_check(err);

    err = strcat_sp(pwd, sizeof(pwd), plain);
    knl_securec_check(err);

    st = knl_generate_repl_key_cipher(session, pwd);
    err = memset_s(pwd, sizeof(pwd), 0, sizeof(pwd));
    knl_securec_check(err);

    CT_LOG_RUN_INF("original password length for replication is %u, double it, status is %d", len, st);
    return st;
}

static status_t knl_verify_server_signature(signature_info_t *info, text_t *server_sign)
{
    uchar server_key[CT_HMAC256MAXSIZE];
    uchar c_server_sign[CT_HMAC256MAXSIZE];
    uint32 server_key_len, sign_key_len, key_len;

    sign_key_len = CT_MAX_CHALLENGE_LEN + CT_MAX_CHALLENGE_LEN;
    if (info->scramble_key.len < sign_key_len) {
        return CT_ERROR;
    }

    /* server_key */
    server_key_len = sizeof(server_key);
    if (cm_encrypt_HMAC(info->salted_pwd, info->salted_pwd_len, (uchar *)CT_SERVER_KEY, (uint32)strlen(CT_SERVER_KEY),
        server_key, &server_key_len) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* server_signature */
    key_len = sizeof(c_server_sign);
    if (cm_encrypt_HMAC(server_key, server_key_len, (uchar *)info->scramble_key.str, sign_key_len,
        c_server_sign, &key_len) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* check */
    if (key_len != server_sign->len || memcmp(c_server_sign, server_sign->str, key_len) != 0) {
        CT_LOG_DEBUG_ERR("SCRAM authentication check server signature failed");
        return CT_ERROR;
    }

    CT_LOG_DEBUG_INF("SCRAM authentication succeeded");
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
