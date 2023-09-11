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
 * srv_sess_security.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_sess_security.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_sess_security.h"
#include "cm_defs.h"
#include "srv_instance.h"
#include "cm_license.h"
#include "knl_user.h"
#include "dc_tenant.h"


static status_t server_get_user_salt_by_user_not_exist(session_t *session, text_t *user_name, uchar *salt,
    uint32 *iter_count)
{
    char rand_and_user[GS_KDF2SALTSIZE + GS_NAME_BUFFER_SIZE] = { 0 };
    uint32 rand_and_user_len = GS_KDF2SALTSIZE + GS_NAME_BUFFER_SIZE;
    uint32 user_len = MIN(user_name->len, GS_NAME_BUFFER_SIZE - 1);

    /* generate salt(md5 value of 16 bytes random value + username) */
    MEMS_RETURN_IFERR(memcpy_s(rand_and_user, rand_and_user_len, g_instance->rand_for_md5, GS_KDF2SALTSIZE));
    if (user_len != 0) {
        MEMS_RETURN_IFERR(
            memcpy_s(rand_and_user + GS_KDF2SALTSIZE, rand_and_user_len - GS_KDF2SALTSIZE, user_name->str, user_len));
    } else {
        GS_LOG_RUN_INF("Account auth failed.");
        GS_THROW_ERROR(ERR_ACCOUNT_AUTH_FAILED);
        return GS_ERROR;
    }
    cm_calc_md5((const uchar *)rand_and_user, user_len + GS_KDF2SALTSIZE, salt);

    /* generate server_key of session(32 bytes of bin2str(salt)) */
    text_t srv_key;
    binary_t bin = {
        .bytes = salt,
        .size = GS_MD5_HASH_SIZE
    };
    cm_str2text_safe((char *)session->server_key, GS_HMAC256MAXSIZE, &srv_key);
    cm_bin2text(&bin, GS_FALSE, &srv_key);

    /* generate iter_count: the value of _ENCRYPTION_ITERATION */
    *iter_count = g_instance->kernel.attr.alg_iter;
    return GS_SUCCESS;
}

static status_t server_get_user_salt(session_t *session, text_t *user_name, uchar *salt, uint32 salt_len,
    uint32 *iter_count)
{
    uint32 len, key_len;
    dc_user_t *dc_user = NULL;
    uchar plain_pwd[GS_PASSWORD_BUFFER_SIZE] = { 0 };
    cm_text_upper(user_name);

    if (cm_text_str_equal(user_name, CM_SYSDBA_USER_NAME) || cm_text_str_equal(user_name, CM_CLSMGR_USER_NAME)) {
        len = cm_base64_decode(GET_SYSDBA_PRIVILEGE, (uint32)strlen(GET_SYSDBA_PRIVILEGE), plain_pwd,
            GS_PASSWORD_BUFFER_SIZE);
    } else if ((session->type == SESSION_TYPE_REPLICA && !cm_text_str_equal(user_name, SYS_USER_NAME))) {
        cm_reset_error();
        return server_get_user_salt_by_user_not_exist(session, user_name, salt, iter_count);
    } else if (dc_open_user_direct(&session->knl_session, user_name, &dc_user) != GS_SUCCESS) {
        cm_reset_error();
        if (!KNL_IS_DATABASE_OPEN(session)) {
            GS_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "Ordinary user login");
            return GS_ERROR;
        }
        return server_get_user_salt_by_user_not_exist(session, user_name, salt, iter_count);
    } else {
        len = cm_base64_decode(dc_user->desc.password, (uint32)strlen(dc_user->desc.password), plain_pwd,
            GS_PASSWORD_BUFFER_SIZE);
    }

    // get server_key for server signature
    if (len == GS_SCRAM256MAXSIZE) {
        scram_data_t *scram_data = (scram_data_t *)plain_pwd;
        MEMS_RETURN_IFERR(memcpy_s(salt, salt_len, scram_data->salt, salt_len));
        MEMS_RETURN_IFERR(memcpy_s(session->server_key, GS_HMAC256MAXSIZE, scram_data->server_key, GS_HMAC256MAXSIZE));
        *iter_count = CM_GET_ITERATION(scram_data);
    } else if (len == GS_KDF2SALTSIZE + GS_KDF2KEYSIZE) {
        MEMS_RETURN_IFERR(memcpy_s(salt, salt_len, plain_pwd, salt_len));
        // server key
        key_len = sizeof(session->server_key);
        if (cm_encrypt_HMAC((uchar *)(plain_pwd + GS_KDF2SALTSIZE), GS_KDF2KEYSIZE, (uchar *)GS_SERVER_KEY,
            (uint32)strlen(GS_SERVER_KEY), session->server_key, &key_len) != GS_SUCCESS) {
            return GS_ERROR;
        }
        *iter_count = GS_KDF2DEFITERATION;
    } else {
        GS_LOG_RUN_INF("Account auth failed.");
        GS_THROW_ERROR(ERR_ACCOUNT_AUTH_FAILED);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t server_ssl_handshake_safe(session_t *session)
{
    uint32 client_flag;
    bool32 ssl_notify = GS_TRUE;
    cs_packet_t *recv_pack = &session->agent->recv_pack;

    // client_flag
    GS_RETURN_IFERR(cs_get_int32(recv_pack, (int32 *)&client_flag));

    if (client_flag & CS_FLAG_CLIENT_SSL) {
        if (session->type == SESSION_TYPE_REPLICA && !IS_SSL_ENABLED) {
            GS_THROW_ERROR(ERR_SSL_CONNECT_FAILED, "SSL is not consistent between primary and standby");
            GS_LOG_DEBUG_ERR("SSL should be consistent between primary and standby");
            return GS_ERROR;
        }

        // notify the client to do SSL handshake
        GS_RETURN_IFERR(cs_send_bytes(session->pipe, (const char *)&ssl_notify, sizeof(bool32)));

        /*
          If client requested SSL then we must stop parsing, try to switch to SSL,
          and wait for the client to send a new handshake packet.
          The client isn't expected to send any more bytes until SSL is initialized.
        */
        GS_LOG_DEBUG_INF("IO layer change in progress...");

        if (cs_ssl_accept(g_instance->ssl_acceptor_fd, session->pipe) != GS_SUCCESS) {
            return GS_ERROR;
        }
        GS_LOG_DEBUG_INF("SSL layer initialized");
    } else {
        if (session->type == SESSION_TYPE_REPLICA && IS_SSL_ENABLED) {
            GS_THROW_ERROR(ERR_SSL_CONNECT_FAILED, "SSL is not consistent between primary and standby");
            GS_LOG_DEBUG_ERR("SSL should be consistent between primary and standby");
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t server_ssl_handshake(session_t *session, text_t *client_user, text_t *client_key)
{
    text_t text;
    uint32 client_flag = 0;
    bool32 ssl_notify = GS_TRUE;
    cs_packet_t *recv_pack = &session->agent->recv_pack;

    // 1. client user
    GS_RETURN_IFERR(cs_get_text(recv_pack, &text));
    MEMS_RETURN_IFERR(memcpy_s(client_user->str, client_user->len, text.str, text.len));
    client_user->len = text.len;
    // 2. client_flag
    GS_RETURN_IFERR(cs_get_int32(recv_pack, (int32 *)&client_flag));
    // 3. client key
    GS_RETURN_IFERR(cs_get_text(recv_pack, &text));
    MEMS_RETURN_IFERR(memcpy_s(client_key->str, client_key->len, text.str, text.len));
    client_key->len = text.len;

    // change to SSL layer if supported
    if (client_flag & CS_FLAG_CLIENT_SSL) {
        if (!IS_SSL_ENABLED) {
            GS_THROW_ERROR(ERR_SSL_NOT_SUPPORT);
            return GS_ERROR;
        }
        // notify the client to do SSL handshake
        if (session->call_version >= CS_VERSION_5) {
            GS_RETURN_IFERR(cs_send_bytes(session->pipe, (const char *)&ssl_notify, sizeof(bool32)));
        }
        /*
          If client requested SSL then we must stop parsing, try to switch to SSL,
          and wait for the client to send a new handshake packet.
          The client isn't expected to send any more bytes until SSL is initialized.
        */
        GS_LOG_DEBUG_INF("IO layer change in progress...");

        if (cs_ssl_accept(g_instance->ssl_acceptor_fd, session->pipe) != GS_SUCCESS) {
            return GS_ERROR;
        }
        GS_LOG_DEBUG_INF("SSL layer initialized");
    }
    return GS_SUCCESS;
}

static status_t server_prep_auth_init_ack(session_t *session, text_t *client_user, text_t *client_key)
{
    text_t text;
    uchar scramble_buf[GS_ENCRYPTION_SIZE] = { 0 };
    uint32 server_capabilities;
    uint32 iter_count = GS_KDF2DEFITERATION;
    cs_packet_t *send_pack = &session->agent->send_pack;

    // upper case user name
    cm_text_upper(client_user);

    // generate s_nonce challenge key
    if (client_key->len != 0) {
        MEMS_RETURN_IFERR(memcpy_s(session->challenge, GS_MAX_CHALLENGE_LEN, client_key->str, client_key->len));
    }
    GS_RETURN_IFERR(cm_rand(session->challenge + GS_MAX_CHALLENGE_LEN, GS_MAX_CHALLENGE_LEN));

    // check if sysdba login is enabled
    if (!GET_ENABLE_SYSDBA_LOGIN && cm_text_str_equal(client_user, CM_SYSDBA_USER_NAME)) {
        GS_THROW_ERROR(ERR_SYSDBA_LOGIN_FAILED);
        return GS_ERROR;
    }

    /*
       handshake ack/auth_init packet contents:
       1. server_capabilities 4 bytes
       2. server_version      4 bytes
       3. scramble_buf        c_nonce(32) + s_nonce(32) + salt(16)
    */
    // 1. server_capabilities
    server_capabilities = 0;
    if (IS_SSL_ENABLED) {
        server_capabilities |= CS_FLAG_CLIENT_SSL;
    }
    GS_RETURN_IFERR(cs_put_int32(send_pack, server_capabilities));
    // 2. server_version
    GS_RETURN_IFERR(cs_put_int32(send_pack, CS_LOCAL_VERSION));

    // 3. scramble_buf
    text.str = (char *)scramble_buf;
    text.len = 0;
    // 3.1 write c_nonce + s_nonce
    MEMS_RETURN_IFERR(memcpy_s(text.str, sizeof(scramble_buf), session->challenge, GS_MAX_CHALLENGE_LEN * 2));
    text.len = GS_MAX_CHALLENGE_LEN * 2;

    // 3.2 write user salt
    GS_RETURN_IFERR(
        server_get_user_salt(session, client_user, (uchar *)(text.str + text.len), GS_KDF2SALTSIZE, &iter_count));
    text.len += GS_KDF2SALTSIZE;
    // 3.3 write scram_key
    GS_RETURN_IFERR(cs_put_text(send_pack, &text));
    // 3.4 write iteration
    GS_RETURN_IFERR(cs_put_int32(send_pack, iter_count));

    session->auth_status = AUTH_STATUS_INIT;
    return GS_SUCCESS;
}

static status_t server_check_hostssl(session_t *session, text_t *client_user)
{
    char db_user[GS_NAME_BUFFER_SIZE] = { 0 };

    if (session->type == SESSION_TYPE_REPLICA) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(cm_text2str(client_user, db_user, GS_NAME_BUFFER_SIZE));
    // WE ALWAYS ALLOW CLSMGR/SYSDBA/UDS LOGIN
    if (cm_str_equal_ins(db_user, "CLSMGR") || cm_str_equal_ins(db_user, "SYSDBA") ||
        (session->pipe->type == CS_TYPE_DOMAIN_SCOKET)) {
        return GS_SUCCESS;
    }

    bool32 hostssl = GS_FALSE;
    // only get hostssl
    cm_check_user(GET_WHITE_CTX, session->os_host, db_user, &hostssl);

    if (IS_SSL_ENABLED && hostssl && session->pipe->type != CS_TYPE_SSL) {
        GS_LOG_RUN_INF("SSL connection for user \"%s\", ip \"%s\" is required, please check zhba.conf", db_user,
            session->os_host);
        GS_THROW_ERROR(ERR_SSL_CONNECT_FAILED, "hostssl client is required");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t server_process_handshake(session_t *session)
{
    text_t client_key, client_user;
    char client_user_str[GS_NAME_BUFFER_SIZE] = { 0 };
    char client_key_buf[GS_MAX_CHALLENGE_LEN];
    cs_packet_t *recv_pack = &session->agent->recv_pack;

    // verify auth_type to avoid repeatly handshaking
    if (session->auth_status != AUTH_STATUS_PROTO) {
        GS_THROW_ERROR(ERR_INVALID_PROTOCOL);
        return GS_ERROR;
    }
    session->auth_status = AUTH_STATUS_CONN;
    session->interactive_info.is_on = ((recv_pack->head->flags & CS_FLAG_INTERACTIVE_CLT) != 0);

    // negotiate packet version
    session->client_version = cs_get_version(recv_pack);
    session->call_version = (session->client_version > CS_LOCAL_VERSION) ? CS_LOCAL_VERSION : session->client_version;

    // SSL only since v9.0
    if (session->client_version >= CS_VERSION_9) {
        return server_ssl_handshake_safe(session);
    }

    client_user.str = client_user_str;
    client_user.len = GS_NAME_BUFFER_SIZE;
    client_key.str = client_key_buf;
    client_key.len = GS_MAX_CHALLENGE_LEN;

    GS_RETURN_IFERR(server_ssl_handshake(session, &client_user, &client_key));
    GS_RETURN_IFERR(server_check_hostssl(session, &client_user));
    GS_RETURN_IFERR(server_prep_auth_init_ack(session, &client_user, &client_key));

    return GS_SUCCESS;
}

status_t server_process_auth_init(session_t *session)
{
    text_t client_user, client_key, client_tenant;
    char buf[GS_NAME_BUFFER_SIZE];

    // HANDSHAKE must be done before AUTH_INIT
    if (session->auth_status != AUTH_STATUS_CONN) {
        GS_THROW_ERROR(ERR_INVALID_PROTOCOL);
        return GS_ERROR;
    }
    cs_packet_t *recv_pack = &session->agent->recv_pack;
    session->interactive_info.is_on = ((recv_pack->head->flags & CS_FLAG_INTERACTIVE_CLT) != 0);

    // CMD_AUTH_INIT is added since v9.0
    if (cs_get_version(recv_pack) < CS_VERSION_9) {
        GS_THROW_ERROR(ERR_PROTOCOL_INCOMPATIBALE);
        return GS_ERROR;
    }

    // 1. get client user
    GS_RETURN_IFERR(cs_get_text(recv_pack, &client_user));
    if (client_user.len > GS_MAX_NAME_LEN || contains_nonnaming_char(T2S(&client_user))) {
        GS_LOG_DEBUG_ERR("Account auth failed.");
        GS_THROW_ERROR(ERR_ACCOUNT_AUTH_FAILED);
        return GS_ERROR;
    }

    // 2. get client key
    GS_RETURN_IFERR(cs_get_text(recv_pack, &client_key));
    // 3. get client tenant since v18.0
    if (cs_get_version(recv_pack) >= CS_VERSION_18) {
        GS_RETURN_IFERR(cs_get_text(recv_pack, &client_tenant));
        if (!CM_IS_EMPTY(&client_tenant) && !cm_text_equal(&client_tenant, &g_tenantroot)) {
            if (client_tenant.len + 1 + client_user.len > GS_MAX_NAME_LEN) {
                GS_LOG_DEBUG_ERR("Account auth failed.");
                GS_THROW_ERROR(ERR_ACCOUNT_AUTH_FAILED);
                return GS_ERROR;
            }
            PRTS_RETURN_IFERR(sprintf_s(buf, GS_NAME_BUFFER_SIZE, "%s$%s", T2S(&client_tenant), T2S_EX(&client_user)));
            cm_str2text(buf, &client_user);
        }
    }

    GS_RETURN_IFERR(server_check_hostssl(session, &client_user));
    GS_RETURN_IFERR(server_prep_auth_init_ack(session, &client_user, &client_key));

    return GS_SUCCESS;
}

bool32 check_login_user(char *user, int size)
{
    char ret_char = '\r';
    char nl_char = '\n'; // newline
    bool32 result = GS_FALSE;
    int i = 0;
    for (; i < size; i++) {
        if ((user[i] == ret_char) || (user[i] == nl_char)) {
            result = GS_TRUE;
            break;
        }
    }
    if (result == GS_TRUE) {
        user[i] = 0;
    }
    return result;
}

status_t server_check_challenge(session_t *session, const char *rsp_str, uchar *pwd_cipher, uint32 *cipher_len)
{
    uchar buf[GS_ENCRYPTION_SIZE] = { 0 };
    uint32 key_len;
    uint32 len;

    // 1. decode base64 encoded cipher response
    len = cm_base64_decode(rsp_str, (uint32)strlen(rsp_str), buf, GS_ENCRYPTION_SIZE);
    if (len == 0) {
        return GS_ERROR;
    }
    key_len = sizeof(session->challenge);

    // 2. check challenge
    if ((len <= key_len) || (*cipher_len < len) || memcmp(session->challenge, buf, key_len) != 0) {
        return GS_ERROR;
    }
    if (len != 0) {
        MEMS_RETURN_IFERR(memcpy_s(pwd_cipher, *cipher_len, buf, len));
    }
    *cipher_len = len;
    pwd_cipher[len] = 0;
    return GS_SUCCESS;
}

static status_t server_check_user(session_t *session, char *user_name, text_t *password)
{
    status_t ret;
    dc_user_t *user = NULL;
    text_t plain_user_name, cipher_password;

    cm_str2text(user_name, &plain_user_name);

    if (dc_open_user_direct(&session->knl_session, &plain_user_name, &user) != GS_SUCCESS) {
        return GS_ERROR;
    }

    cm_str2text(user->desc.password, &cipher_password);

    ret = cm_verify_password(password, &cipher_password);
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_WAR("Account auth failed.");
        /* process login failed scenery */
        GS_THROW_ERROR(ERR_ACCOUNT_AUTH_FAILED);

        return GS_ERROR;
    }

    session->knl_session.uid = user->desc.id;
    session->curr_schema_id = user->desc.id;
    return GS_SUCCESS;
}

status_t server_check_authenticate_sysdba(session_t *session, text_t *password, cs_packet_t *send_pack, char *privilege)
{
    text_t s_cipher;

    if (!cm_str_equal(session->os_user, cm_sys_user_name())) {
        GS_THROW_ERROR(ERR_NO_LOGIN_PRIV);
        return GS_ERROR;
    }

    /* reset session user */
    MEMS_RETURN_IFERR(strncpy_s(session->db_user, GS_NAME_BUFFER_SIZE, SYS_USER_NAME, GS_MAX_NAME_LEN));
    cm_str2text(session->db_user, &session->curr_user);
    if (session->curr_user.len != 0) {
        MEMS_RETURN_IFERR(strncpy_s(session->curr_schema, GS_NAME_BUFFER_SIZE, session->curr_user.str,
            GS_MAX_NAME_LEN)); /* set default schema value */
    }
    session->curr_schema_id = 0;
    session->knl_session.uid = 0;

    /* 1. check client ip */
    if (!cm_is_local_ip(session->os_host)) {
        GS_THROW_ERROR(ERR_NO_LOGIN_PRIV);
        return GS_ERROR;
    }

    /* 2. check privilege */
    cm_str2text(privilege, &s_cipher);

    if (cm_verify_password(password, &s_cipher) != GS_SUCCESS) {
        GS_LOG_RUN_INF("Account auth failed.");
        GS_THROW_ERROR(ERR_ACCOUNT_AUTH_FAILED);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t server_check_authenticate(session_t *session, text_t *password, cs_packet_t *send_pack)
{
    char message[GS_MESSAGE_BUFFER_SIZE] = { 0 };
    uint32 lock_unlock = 0;
    int32 code;

    if (cm_text_str_equal(&session->curr_user, SYS_USER_NAME)) {
        if (!GET_ENABLE_SYS_REMOTE_LOGIN && !cm_is_local_ip(session->os_host)) {
            GS_THROW_ERROR(ERR_NO_LOGIN_PRIV);
            return GS_ERROR;
        }
    }
    if (knl_check_user_lock(&session->knl_session, &session->curr_user) != GS_SUCCESS) {
        const char *msg = NULL;
        cm_get_error(&code, &msg, NULL);
        if (ERR_USER_NOT_EXIST == code) {
            cm_reset_error();
            GS_LOG_RUN_INF("Account auth failed.");
            GS_THROW_ERROR(ERR_ACCOUNT_AUTH_FAILED);
        } else {
            GS_THROW_ERROR(ERR_ACCOUNT_LOCK);
        }

        return GS_ERROR;
    }

    if (server_check_user(session, session->db_user, password) != GS_SUCCESS) {
        const char *msg = NULL;
        cm_get_error(&code, &msg, NULL);
        if (ERR_ACCOUNT_AUTH_FAILED == code) {
            if (knl_process_failed_login(&session->knl_session, &session->curr_user, &lock_unlock) != GS_SUCCESS) {
                cm_reset_error();
                GS_THROW_ERROR(ERR_ACCOUNT_LOCK);
            }
        } else if (ERR_USER_NOT_EXIST == code) {
            cm_reset_error();
            GS_LOG_RUN_INF("Account auth failed.");
            GS_THROW_ERROR(ERR_ACCOUNT_AUTH_FAILED);
        }
        return GS_ERROR;
    }

    if (knl_check_user_expire(&session->knl_session, &session->curr_user, message, GS_MESSAGE_BUFFER_SIZE) !=
        GS_SUCCESS) {
        if (cm_str_equal(message, "The current user has be in the expired status.") &&
            session->client_kind == CLIENT_KIND_ZSQL) {
            send_pack->head->flags |= CS_FLAG_ZSQL_IN_ALTPWD;
            session->knl_session.interactive_altpwd = GS_TRUE;
            return GS_SUCCESS;
        } else {
            GS_THROW_ERROR(ERR_PASSWORD_EXPIRED);
            return GS_ERROR;
        }
    }

    if (message[0] != '\0') {
        GS_RETURN_IFERR(cs_put_err_msg(send_pack, session->call_version, message));
    }

    return GS_SUCCESS;
}

bool32 server_match_restricted_status(session_t *session)
{
    database_t *db = &g_instance->kernel.db;

    if (db->status != DB_STATUS_OPEN && g_instance->logined_count >= 1) {
        GS_THROW_ERROR(ERR_DB_RESTRICT_STATUS, "single user");
        return GS_TRUE;
    }

    if (knl_switchover_triggered(&g_instance->kernel) || knl_failover_triggered(&g_instance->kernel) ||
        knl_open_mode_triggered(&g_instance->kernel)) {
        GS_THROW_ERROR(ERR_DB_RESTRICT_STATUS, "single user");
        return GS_TRUE;
    }

    if (db->open_status >= DB_OPEN_STATUS_RESTRICT) {
        if (g_instance->logined_count >= 1) {
            GS_THROW_ERROR(ERR_DB_RESTRICT_STATUS, "single user");
            return GS_TRUE;
        }
        if (session->knl_session.uid != DB_SYS_USER_ID) {
            GS_THROW_ERROR(ERR_DB_RESTRICT_STATUS, "sys user");
            return GS_TRUE;
        }

        if (session->client_kind != CLIENT_KIND_ZSQL) {
            GS_THROW_ERROR(ERR_DB_RESTRICT_STATUS, "local ctclient client");
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

static status_t server_check_privs(session_t *session)
{
    if (!knl_check_sys_priv_by_uid(&session->knl_session, session->knl_session.uid, CREATE_SESSION)) {
        GS_THROW_ERROR(ERR_LACK_CREATE_SESSION);
        return GS_ERROR;
    }

    // common user connect as sysdba
    if (session->remote_as_sysdba == GS_TRUE) {
        if (!GET_ENABLE_SYSDBA_REMOTE_LOGIN) {
            GS_THROW_ERROR(ERR_SYSDBA_LOGIN_FAILED);
            return GS_ERROR;
        }

        if (!knl_check_sys_priv_by_uid(&session->knl_session, session->knl_session.uid, SYSDBA)) {
            GS_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            return GS_ERROR;
        }

        if (!cm_is_local_ip(session->os_host) && !GET_ENABLE_SYS_REMOTE_LOGIN) {
            GS_THROW_ERROR(ERR_NO_LOGIN_PRIV);
            return GS_ERROR;
        }

        /* reset session user */
        MEMS_RETURN_IFERR(strncpy_s(session->db_user, GS_NAME_BUFFER_SIZE, SYS_USER_NAME, strlen(SYS_USER_NAME)));
        cm_str2text(session->db_user, &session->curr_user);

        MEMS_RETURN_IFERR(strncpy_s(session->curr_schema, GS_NAME_BUFFER_SIZE, SYS_USER_NAME,
            strlen(SYS_USER_NAME))); /* set default schema value */

        session->curr_schema_id = 0;
        session->knl_session.uid = 0;
    }
    return GS_SUCCESS;
}

status_t server_auth_and_check_privs(session_t *session, text_t *password, bool32 is_coord)
{
    cs_packet_t *send_pack = &session->agent->send_pack;

    knl_set_session_scn(&session->knl_session, GS_INVALID_ID64);

    /* public is internal user, can not login outside */
    if (cm_str_equal_ins(session->db_user, "public")) {
        GS_LOG_RUN_INF("Account auth failed.");
        GS_THROW_ERROR(ERR_ACCOUNT_AUTH_FAILED);
        return GS_ERROR;
    }

    // check the correctness of user and pwd
    // check whether the account is locked or the pwd has expired or not
    if (cm_text_str_equal(&session->curr_user, CM_SYSDBA_USER_NAME) ||
        cm_text_str_equal(&session->curr_user, CM_CLSMGR_USER_NAME)) {
        GS_RETURN_IFERR(server_check_authenticate_sysdba(session, password, send_pack, GET_SYSDBA_PRIVILEGE));
    } else {
        GS_RETURN_IFERR(server_check_authenticate(session, password, send_pack));
    }

    return server_check_privs(session);
}

uint32 server_get_user_sessions_count(text_t *username)
{
    uint32 count = 0;
    session_t *session = NULL;
    session_pool_t *pool = &g_instance->session_pool;

    for (uint32 i = g_instance->kernel.reserved_sessions; i < pool->hwm; i++) {
        session = pool->sessions[i];
        if (!session->is_free && session->is_auth && cm_text_equal(username, &session->curr_user)) {
            count++;
        }
    }

    return count;
}

status_t server_process_login(session_t *session)
{
    uint32 count, key_len;
    text_t text, cipher_text;
    char password[GS_PASSWORD_BUFFER_SIZE];
    uchar server_sign[GS_HMAC256MAXSIZE];
    uint16 is_coord;
    status_t status;
    bool32 user_invalid;

    session->is_auth = GS_FALSE;
    session->last_insert_id = 0;
    cs_packet_t *recv_pack = &session->agent->recv_pack;
    cs_packet_t *send_pack = &session->agent->send_pack;
    session->interactive_info.is_on = ((recv_pack->head->flags & CS_FLAG_INTERACTIVE_CLT) != 0);
    session->remote_as_sysdba = ((recv_pack->head->flags & GS_FLAG_REMOTE_AS_SYSDBA) != 0);

    // HANDSHAKE/AUTH_INIT should have been done
    if (session->auth_status != AUTH_STATUS_INIT) {
        GS_THROW_ERROR(ERR_INVALID_PROTOCOL);
        return GS_ERROR;
    }

    // 1. user
    GS_RETURN_IFERR(cs_get_text(recv_pack, &text));
    GS_RETURN_IFERR(cm_text2str(&text, session->db_user, sizeof(session->db_user)));
    // 2. pwd
    GS_RETURN_IFERR(cs_get_text(recv_pack, &text));
    GS_RETURN_IFERR(cm_text2str(&text, password, sizeof(password)));
    // 3. host_name
    GS_RETURN_IFERR(cs_get_text(recv_pack, &text));
    // 4. sys_user
    GS_RETURN_IFERR(cs_get_text(recv_pack, &text));
    GS_RETURN_IFERR(cm_text2str(&text, session->os_user, sizeof(session->os_user)));
    // 5. sys_program
    GS_RETURN_IFERR(cs_get_text(recv_pack, &text));
    GS_RETURN_IFERR(cm_text2str(&text, session->os_prog, sizeof(session->os_prog)));

    // 6. is_coord
    GS_RETURN_IFERR(cs_get_int16(recv_pack, (int16 *)&is_coord));

    // 7. timezone
    GS_RETURN_IFERR(cs_get_int16(recv_pack, &session->nls_params.client_timezone));
    if (!cm_validate_timezone(session->nls_params.client_timezone)) {
        GS_THROW_ERROR(ERR_VALUE_ERROR, "an invalid timezone offset value");
        return GS_ERROR;
    }

    // 8. client kind
    session->client_kind = CLIENT_KIND_UNKNOWN;
    if (session->call_version >= CS_VERSION_6) {
        int16 value;
        GS_RETURN_IFERR(cs_get_int16(recv_pack, &value));
        if (value < CLIENT_KIND_UNKNOWN || value >= CLIENT_KIND_TAIL) {
            GS_THROW_ERROR(ERR_INVALID_PROTOCOL);
            return GS_ERROR;
        }
        session->client_kind = (client_kind_t)value;
    }

    // 10. tenant name
    if (session->call_version >= CS_VERSION_18) {
        GS_RETURN_IFERR(cs_get_text(recv_pack, &text));
        GS_RETURN_IFERR(cm_text2str(&text, session->curr_tenant, sizeof(session->curr_tenant)));

        // set tenant$root as current tenant while connection string dose not set tenant
        if (strlen(session->curr_tenant) == 0) {
            GS_RETURN_IFERR(cm_text2str(&g_tenantroot, session->curr_tenant, sizeof(session->curr_tenant)));
        }
    } else {
        // low version interface set default tenant TENANT$ROOT
        GS_RETURN_IFERR(cm_text2str(&g_tenantroot, session->curr_tenant, sizeof(session->curr_tenant)));
    }
    if (session->pipe->type != CS_TYPE_DOMAIN_SCOKET) {
        bool32 hostssl = GS_FALSE;
        if (!cm_check_ip(GET_WHITE_CTX, session->os_host, session->db_user, &hostssl)) {
            char date[GS_MAX_TIME_STRLEN];
            (void)cm_date2str(g_timer()->now, "yyyy-mm-dd hh24:mi:ss.ff3", date, sizeof(date));
            GS_LOG_RUN_INF("Whitelist rejects connection for user \"%s\", ip \"%s\", current date \"%s\","
                "please check zhba.conf or tcp valid node configuration",
                session->db_user, session->os_host, date);
            GS_THROW_ERROR(ERR_ACCOUNT_AUTH_FAILED);
            return GS_ERROR;
        }
    }

    if (!IS_COMPATIBLE_MYSQL_INST) {
        cm_str_upper(session->db_user);
    }
    cm_str2text(session->db_user, &session->curr_user);
    user_invalid = check_login_user(session->db_user, (int)strlen(session->db_user)); // user can not content \n \r
    if (user_invalid) {
        session->curr_user.len = (uint32)strlen(session->db_user);
        GS_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "user name is invalid");
        return GS_ERROR;
    }
    if (session->curr_user.len != 0) {
        MEMS_RETURN_IFERR(strncpy_s(session->curr_schema, GS_NAME_BUFFER_SIZE, session->curr_user.str,
            session->curr_user.len)); /* set default schema value */
    }
    session->curr_user2[0] = '\0';

    GS_RETURN_IFERR(cs_put_int32(send_pack, session->knl_session.id));
    GS_RETURN_IFERR(cs_put_int32(send_pack, session->knl_session.serial_id));
    GS_RETURN_IFERR(cs_put_int32(send_pack, g_instance->sql.sql_lob_locator_size));
    GS_RETURN_IFERR(cs_put_int32(send_pack, GET_CHARSET_ID));

    // server signature
    key_len = sizeof(server_sign);
    if (cm_encrypt_HMAC(session->server_key, GS_HMAC256MAXSIZE, session->challenge, sizeof(session->challenge),
        server_sign, &key_len) != GS_SUCCESS) {
        return GS_ERROR;
    }
    text.str = (char *)server_sign;
    text.len = key_len;
    GS_RETURN_IFERR(cs_put_text(send_pack, &text));

    // send server's max_allowed_packet to client.
    if (session->call_version >= CS_VERSION_10) {
        GS_RETURN_IFERR(cs_put_int32(send_pack, g_instance->attr.max_allowed_packet));
    }

    // db role
    if (session->call_version >= CS_VERSION_15) {
        GS_RETURN_IFERR(cs_put_int32(send_pack, (uint32)(session->knl_session.kernel->db.ctrl.core.db_role)));
    }

    // check tenant
    if (session->call_version >= CS_VERSION_18) {
        uint32 tenant_id = GS_INVALID_ID32;
        text_t tenant;

        cm_str2text(session->curr_tenant, &tenant);
        if (dc_get_tenant_id(&session->knl_session, &tenant, &tenant_id) != GS_SUCCESS) {
            cm_reset_error();
            GS_LOG_RUN_INF("Account auth failed.");
            GS_THROW_ERROR(ERR_ACCOUNT_AUTH_FAILED);
            return GS_ERROR;
        }
        session->curr_tenant_id = tenant_id;
    }

    /* support pwd encryption since v2 */
    cipher_text.str = password;
    cipher_text.len = sizeof(password);
    if (server_check_challenge(session, password, (uchar *)cipher_text.str, &cipher_text.len) != GS_SUCCESS) {
        GS_LOG_RUN_INF("Account auth failed.");
        GS_THROW_ERROR(ERR_ACCOUNT_AUTH_FAILED);
        return GS_ERROR;
    }

    if (server_auth_and_check_privs(session, &cipher_text, (bool32)is_coord) != GS_SUCCESS) {
        MEMS_RETURN_IFERR(memset_s(password, sizeof(password), 0, sizeof(password)));
        return GS_ERROR;
    }

    if (!cm_text_str_equal_ins(&session->curr_user, CM_SYSDBA_USER_NAME) &&
        !cm_text_str_equal_ins(&session->curr_user, CM_CLSMGR_USER_NAME) &&
        !cm_text_str_equal_ins(&session->curr_user, SYS_USER_NAME)
        ) {
        if (cm_lic_check(LICENSE_VALIDITY_TIME) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_LICENSE_CHECK_FAIL, " effective function license is required.");
            return GS_ERROR;
        }
    }

    MEMS_RETURN_IFERR(memset_s(password, sizeof(password), 0, sizeof(password)));

    if (server_match_restricted_status(session)) {
        return GS_ERROR;
    }

    count = server_get_user_sessions_count(&session->curr_user);
    if (GS_SUCCESS != knl_check_sessions_per_user((knl_handle_t)session, &session->curr_user, count)) {
        return GS_ERROR;
    }

    status = GS_SUCCESS;
    if (status == GS_SUCCESS) {
        if (g_instance->kernel.db.status != DB_STATUS_OPEN) {
            cm_spin_lock(&g_instance->stat_lock, NULL);
            (void)cm_atomic_inc(&g_instance->logined_count);
            if (g_instance->logined_count > 1) {
                (void)cm_atomic_dec(&g_instance->logined_count);
                cm_spin_unlock(&g_instance->stat_lock);
                GS_THROW_ERROR(ERR_DB_RESTRICT_STATUS, "single user");
                GS_LOG_DEBUG_INF("Only one user allowed login when database is not open.");
                return GS_ERROR;
            }
            cm_spin_unlock(&g_instance->stat_lock);
        } else {
            (void)cm_atomic_inc(&g_instance->logined_count);
        }
        (void)cm_atomic_inc(&g_instance->logined_cumu_count);
        session->is_auth = GS_TRUE;
        session->auth_status = AUTH_STATUS_LOGON;
    }
    return status;
}

void server_judge_login_success(char *os_host)
{
    uint32 i;
    mal_ip_context_t *malicious_ctx = GET_MAL_IP_CTX;
    ip_login_t *ip_login_name = NULL;

    if (malicious_ctx->malicious_ip_list.count == 0) {
        return;
    }

    cm_spin_lock(&malicious_ctx->ip_lock, NULL);
    if (malicious_ctx->malicious_ip_list.count == 0) {
        cm_spin_unlock(&malicious_ctx->ip_lock);
        return;
    }

    for (i = 0; i < malicious_ctx->malicious_ip_list.count; i++) {
        ip_login_name = (ip_login_t *)cm_list_get(&malicious_ctx->malicious_ip_list, i);
        if (strcmp(ip_login_name->ip, os_host) == 0) {
            ip_login_name->malicious_ip_count = 0;
            ip_login_name->start_time = 0;
        }
    }
    cm_spin_unlock(&malicious_ctx->ip_lock);
    return;
}

static void server_judge_ip_login_name(ip_login_t *ip_login_name)
{
    if (ip_login_name->malicious_ip_count < GS_MALICIOUS_LOGIN_ALARM &&
        (g_timer()->now - ip_login_name->start_time) <= MICROSECS_PER_MIN) {
        {
            GS_LOG_ALARM(WARN_MALICIOUSLOGIN, "'ip':'%s'}", ip_login_name->ip);
        }
        ip_login_name->malicious_ip_count++;
    }
}

void server_judge_login(session_t *session)
{
    mal_ip_context_t *malicious_ctx = GET_MAL_IP_CTX;
    ip_login_t *ip_login_name = NULL;
    ip_login_t *ip_login_addr = NULL;

    cm_spin_lock(&malicious_ctx->ip_lock, NULL);
    if (malicious_ctx->malicious_ip_list.count > GS_MAX_MALICIOUS_IP_COUNT) {
        cm_destroy_list(&malicious_ctx->malicious_ip_list);
    }
    for (uint32 i = 0; i < malicious_ctx->malicious_ip_list.count; i++) {
        ip_login_name = (ip_login_t *)cm_list_get(&malicious_ctx->malicious_ip_list, i);
        if (strcmp(ip_login_name->ip, session->os_host) == 0) {
            if (ip_login_name->malicious_ip_count < GS_MALICIOUS_LOGIN_COUNT) {
                ip_login_name->malicious_ip_count++;
            } else {
                server_judge_ip_login_name(ip_login_name);
            }
            ip_login_name->last_time = g_timer()->now;
            if (ip_login_name->last_time - ip_login_name->start_time > MICROSECS_PER_MIN) {
                ip_login_name->start_time = g_timer()->now;
                ip_login_name->malicious_ip_count = 1;
            }
            cm_spin_unlock(&malicious_ctx->ip_lock);
            return;
        }
    }

    if (cm_list_new(&malicious_ctx->malicious_ip_list, (void **)&ip_login_addr) != GS_SUCCESS) {
        cm_spin_unlock(&malicious_ctx->ip_lock);
        return;
    }
    errno_t errcode = strcpy_s(ip_login_addr->ip, GS_HOST_NAME_BUFFER_SIZE, session->os_host);
    if (errcode != EOK) {
        cm_spin_unlock(&malicious_ctx->ip_lock);
        return;
    }
    ip_login_addr->malicious_ip_count = 1;
    ip_login_addr->start_time = g_timer()->now;
    cm_spin_unlock(&malicious_ctx->ip_lock);

    return;
}

status_t server_store_sysdba_privilege(const char *privilege, uint32 priv_len, const char *name)
{
    status_t ret = GS_ERROR;
    char file_name[GS_FILE_NAME_BUFFER_SIZE] = { 0 };
    char protect_dir[GS_FILE_NAME_BUFFER_SIZE] = { 0 };
    int32 file_handle;

    PRTS_RETURN_IFERR(snprintf_s(protect_dir, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s/protect/",
        g_instance->home));
    PRTS_RETURN_IFERR(snprintf_s(file_name, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s/protect/%s",
        g_instance->home, name));

    if (!cm_dir_exist(protect_dir)) {
        if (cm_create_dir(protect_dir) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[Privilege] failed to create dir %s", protect_dir);
            return GS_ERROR;
        }
    }

    if (access(file_name, R_OK | F_OK) == 0) {
        (void)chmod(file_name, S_IRUSR | S_IWUSR);
        ret = cm_remove_file(file_name);
        GS_RETURN_IFERR(ret);
    }
    // 1. check privilege file
    ret = cm_open_file_ex(file_name, O_SYNC | O_CREAT | O_RDWR | O_TRUNC | O_BINARY, S_IRUSR, &file_handle);
    GS_RETURN_IFERR(ret);

    ret = cm_write_file(file_handle, (void *)privilege, (int32)priv_len);
    cm_close_file(file_handle);
    GS_RETURN_IFERR(ret);

    return GS_SUCCESS;
}

status_t server_remove_sysdba_privilege()
{
    status_t ret = GS_ERROR;
    char *file_list[] = { GS_KMC_PRIVILEGE };
    int file_num = sizeof(file_list) / sizeof(char *);
    char protect_dir[GS_FILE_NAME_BUFFER_SIZE] = { 0 };

    PRTS_RETURN_IFERR(snprintf_s(protect_dir, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s/protect/",
        g_instance->home));
    if (GS_FALSE == cm_dir_exist(protect_dir)) {
        return GS_SUCCESS;
    }

    for (int i = 0; i < file_num; i++) {
        char file_name[GS_FILE_NAME_BUFFER_SIZE] = { 0 };
        PRTS_RETURN_IFERR(snprintf_s(file_name, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s/protect/%s",
            g_instance->home, file_list[i]));

        if (GS_TRUE == cm_file_exist(file_name)) {
            if (access(file_name, R_OK | F_OK) == 0) {
                (void)chmod(file_name, S_IRUSR | S_IWUSR);
                ret = cm_remove_file(file_name);
                GS_RETURN_IFERR(ret);
            }
        }
    }

    return GS_SUCCESS;
}

status_t server_kmc_encrypt(int domain)
{
    status_t ret;
    binary_t bin;
    char plain[GS_AES256KEYSIZE + 1];
    uchar rand_key[GS_AESBLOCKSIZE + 1];
    uint32 key_len;
    char cipherText[GS_ENCRYPTION_SIZE] = { 0 };
    unsigned int cipherTextLen = sizeof(cipherText);
    MEMS_RETURN_IFERR(memset_s(GET_SYSDBA_PRIVILEGE, sizeof(GET_SYSDBA_PRIVILEGE), 0, sizeof(GET_SYSDBA_PRIVILEGE)));
    GS_RETURN_IFERR(cm_rand((uchar *)rand_key, GS_AESBLOCKSIZE));
    bin.bytes = (uint8 *)rand_key;
    bin.size = GS_AESBLOCKSIZE;
    ret = cm_bin2str(&bin, GS_FALSE, plain, sizeof(plain));
    GS_RETURN_IFERR(ret);

    key_len = sizeof(GET_SYSDBA_PRIVILEGE);
    GS_RETURN_IFERR(cm_generate_scram_sha256(plain, (uint32)strlen(plain), GS_KDF2MINITERATION,
                                             (uchar *)GET_SYSDBA_PRIVILEGE, &key_len));
    unsigned int plainTextLen = (uint32)strlen(plain);

    if (cm_kmc_encrypt(domain, KMC_ALGID_AES256_GCM, plain, plainTextLen,
                       cipherText, &cipherTextLen) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return server_store_sysdba_privilege(cipherText, (uint32)cipherTextLen, GS_KMC_PRIVILEGE);
}

void server_remove_file(char *dirname, char *filename)
{
    char full_name[GS_FILE_NAME_BUFFER_SIZE] = { 0 };
    int iret_snprintf;
    iret_snprintf = snprintf_s(full_name, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s/protect/%s",
        dirname, filename);
    if (iret_snprintf < 0) {
        return;
    }
    if (access(full_name, R_OK | F_OK) == 0) {
        (void)chmod(full_name, S_IRUSR | S_IWUSR);
        (void)cm_remove_file(full_name);
    }
    return;
}

status_t server_init_sysdba_privilege(void)
{
    server_remove_file(g_instance->home, GS_PRIV_FILENAME);
    server_remove_file(g_instance->home, GS_LKEY_FILENAME);
    server_remove_file(g_instance->home, GS_FKEY_FILENAME);
    GS_RETURN_IFERR(server_kmc_encrypt(GS_KMC_SERVER_DOMAIN));
    return GS_SUCCESS;
}

status_t server_refresh_sysdba_privilege(void)
{
    if (GET_ENABLE_SYSDBA_LOGIN) {
        return server_init_sysdba_privilege();
    }
    GS_LOG_RUN_WAR("[SYSDBA PRIVILEGE] sysdba login disabled, skip to refresh privilege.");
    return GS_SUCCESS;
}

status_t server_load_hba(bool32 allow_not_exists)
{
    char file_name[GS_FILE_NAME_BUFFER_SIZE] = { 0 };

    PRTS_RETURN_IFERR(snprintf_s(file_name, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s/cfg/%s",
        g_instance->home, ZHBA_FILENAME));

    if (!cm_file_exist(file_name)) {
        if (!allow_not_exists) {
            GS_THROW_ERROR(ERR_FILE_NOT_EXIST, "hba", file_name);
            return GS_ERROR;
        }
        return GS_SUCCESS;
    }
    if (cm_access_file(file_name, R_OK | W_OK) != GS_SUCCESS) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "%s is not an readable or writable folder", file_name);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(cm_load_hba(GET_WHITE_CTX, file_name));

    return GS_SUCCESS;
}
status_t server_load_pbl(bool32 allow_not_exists)
{
    char file_name[GS_FILE_NAME_BUFFER_SIZE] = { 0 };

    PRTS_RETURN_IFERR(snprintf_s(file_name, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s/cfg/%s",
        g_instance->home, PBL_FILENAME));

    if (!cm_file_exist(file_name)) {
        if (!allow_not_exists) {
            GS_THROW_ERROR(ERR_FILE_NOT_EXIST, "pbl", file_name);
            return GS_ERROR;
        }
        return GS_SUCCESS;
    }
    if (cm_access_file(file_name, R_OK) != GS_SUCCESS) {
        GS_THROW_ERROR_EX(ERR_INVALID_OPERATION, ": %s can't access", file_name);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(cm_load_pbl(GET_PWD_BLACK_CTX, file_name, (uint32)cm_log_param_instance()->max_pbl_file_size));

    return GS_SUCCESS;
}
