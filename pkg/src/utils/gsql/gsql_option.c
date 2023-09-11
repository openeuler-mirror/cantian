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
 * gsql_option.c
 *
 *
 * IDENTIFICATION
 * src/utils/gsql/gsql_option.c
 *
 * -------------------------------------------------------------------------
 */

#include "gsql_option.h"
#include "gsql_export.h"
#include "cm_lex.h"

static void gsql_set_autocommit(text_t *value);
static void gsql_set_exitcommit(text_t *value);
static void gsql_set_charset(text_t *value);
static void gsql_set_heading(text_t *value);
static void gsql_set_serverouput(text_t *value);
static void gsql_set_trimspool(text_t *value);
static void gsql_set_linesize(text_t *value);
static void gsql_set_longsize(text_t *value);
static void gsql_set_numwidth(text_t *value);
static void gsql_set_pagesize(text_t *value);
static void gsql_set_timing(text_t *value);
static void gsql_set_feedback(text_t *value);
static void gsql_set_define_on(text_t *value);
static void gsql_set_oplog(text_t *value);
static void gsql_set_connect_timeout(text_t *value);
static void gsql_set_socket_timeout(text_t *value);
static void gsql_set_scriptoutput(text_t *value);
static void gsql_set_verify_on(text_t *value);
static void gsql_set_termout_on(text_t *value);
static void gsql_set_newpage(text_t *value);
static void gsql_set_colsep(text_t *value);
static void gsql_set_ssl_mode(text_t *value);
static void gsql_set_ssl_ca_file(text_t *value);
static void gsql_set_ssl_cert_file(text_t *value);
static void gsql_set_ssl_key_file(text_t *value);
static void gsql_set_ssl_crl_file(text_t *value);
static void gsql_set_ssl_key_passwd(text_t *value);
static void gsql_set_ssl_cipher(text_t *value);
static void gsql_set_uds_clt_path(text_t *value);
static void gsql_set_uds_srv_path(text_t *value);
static void gsql_set_bindparam_force_on(text_t *value);
static void gsql_set_shd_rw_split(text_t *value);
static void gsql_set_history(text_t *value);
static void gsql_set_autotrace(text_t *value);

static bool8 gsql_show_autocommit(const text_t *value);
static bool8 gsql_show_exitcommit(const text_t *value);
static bool8 gsql_show_charset(const text_t *value);
static bool8 gsql_show_heading(const text_t *value);
static bool8 gsql_show_serverouput(const text_t *value);
static bool8 gsql_show_trimspool(const text_t *value);
static bool8 gsql_show_spool(const text_t *value);
static bool8 gsql_show_linesize(const text_t *value);
static bool8 gsql_show_longsize(const text_t *value);
static bool8 gsql_show_numwidth(const text_t *value);
static bool8 gsql_show_pagesize(const text_t *value);
static bool8 gsql_show_timing(const text_t *value);
static bool8 gsql_show_feedback(const text_t *value);
static bool8 gsql_show_define_on(const text_t *value);
static bool8 gsql_show_oplog(const text_t *value);
static bool8 gsql_show_connect_timeout(const text_t *value);
static bool8 gsql_show_socket_timeout(const text_t *value);
static bool8 gsql_show_scriptoutput(const text_t *value);
static bool8 gsql_show_verify_on(const text_t *value);
static bool8 gsql_show_termout_on(const text_t *value);
static bool8 gsql_show_newpage(const text_t *value);
static bool8 gsql_show_colsep(const text_t *value);
static bool8 gsql_show_ssl_mode(const text_t *value);
static bool8 gsql_show_ssl_ca_file(const text_t *value);
static bool8 gsql_show_ssl_cert_file(const text_t *value);
static bool8 gsql_show_ssl_key_file(const text_t *value);
static bool8 gsql_show_ssl_crl_file(const text_t *value);
static bool8 gsql_show_ssl_key_passwd(const text_t *value);
static bool8 gsql_show_ssl_cipher(const text_t *value);
static bool8 gsql_show_uds_clt_path(const text_t *value);
static bool8 gsql_show_uds_srv_path(const text_t *value);
static bool8 gsql_show_bindparam_force_on(const text_t *value);
static bool8 gsql_show_shd_rw_split(const text_t *value);
static bool8 gsql_show_history(const text_t *value);
static bool8 gsql_show_autotrace(const text_t *value);
static bool8 gsql_show_create_opt(const text_t *value);
static bool8 gsql_show_tenant_opt(const text_t *value);
static bool8 gsql_show_parameters_opt(const text_t *value);
static const char *g_ssl_mode_txt_list[] = { "DISABLED", "PREFERRED", "REQUIRED", "VERIFY_CA", "VERIFY_FULL" };
static const uint32 g_ssl_mode_count = sizeof(g_ssl_mode_txt_list) / sizeof(g_ssl_mode_txt_list[0]);

typedef void (*gsql_set_attr)(text_t *value);
typedef bool8 (*gsql_show_attr)(const text_t *value);
typedef bool32 (*gsql_opt_match_func)(const text_t *text, const char *str, const uint32 less_len);

#define GSQL_MAX_OPTION_NAME (uint32)32
#define GS_MAX_CHARSET_NAME  (uint32)64

typedef struct st_gsql_option {
    char name[GSQL_MAX_OPTION_NAME];
    uint32 set_less_len;
    gsql_set_attr set_att_func;
    uint32 show_less_len;
    gsql_show_attr show_att_func;
    gsql_opt_match_func match_func;
} gsql_option_t;

static gsql_option_t g_options[] = {
    { "AUTOCOMMIT", 4, gsql_set_autocommit, 4, gsql_show_autocommit, cm_text_str_less_equal_ins },
    { "EXITCOMMIT", 5, gsql_set_exitcommit, 5, gsql_show_exitcommit, cm_text_str_less_equal_ins },
    { "CHARSET", 7, gsql_set_charset, 7, gsql_show_charset, cm_text_str_less_equal_ins },
    { "HEADING", 3, gsql_set_heading, 3, gsql_show_heading, cm_text_str_less_equal_ins },
    { "SERVEROUTPUT", 9, gsql_set_serverouput, 9, gsql_show_serverouput, cm_text_str_less_equal_ins },
    { "TRIMSPOOL", 5, gsql_set_trimspool, 5, gsql_show_trimspool, cm_text_str_less_equal_ins },
    { "SPOOL", 4, NULL, 4, gsql_show_spool, cm_text_str_less_equal_ins },
    { "LINESIZE", 3, gsql_set_linesize, 3, gsql_show_linesize, cm_text_str_less_equal_ins },
    { "NUMWIDTH", 3, gsql_set_numwidth, 3, gsql_show_numwidth, cm_text_str_less_equal_ins },
    { "PAGESIZE", 5, gsql_set_pagesize, 5, gsql_show_pagesize, cm_text_str_less_equal_ins },
    { "TIMING", 3, gsql_set_timing, 3, gsql_show_timing, cm_text_str_less_equal_ins },
    { "FEEDBACK", 4, gsql_set_feedback, 4, gsql_show_feedback, cm_text_str_less_equal_ins },
    { "PARAMETERS", 10, NULL, 9, gsql_show_parameters_opt, cm_text_str_contain_equal_ins },
    { "LONG", 4, gsql_set_longsize, 4, gsql_show_longsize, cm_text_str_less_equal_ins },
    { "COLSEP", 6, gsql_set_colsep, 6, gsql_show_colsep, cm_text_str_less_equal_ins },
    { "NEWPAGE", 4, gsql_set_newpage, 4, gsql_show_newpage, cm_text_str_less_equal_ins },
    { "VERIFY", 3, gsql_set_verify_on, 3, gsql_show_verify_on, cm_text_str_less_equal_ins },
    { "TERMOUT", 4, gsql_set_termout_on, 4, gsql_show_termout_on, cm_text_str_less_equal_ins },
    { "DEFINE", 6, gsql_set_define_on, 6, gsql_show_define_on, cm_text_str_less_equal_ins },
    { "ECHO", 4, gsql_set_scriptoutput, 4, gsql_show_scriptoutput, cm_text_str_less_equal_ins },
    { "OPLOG", 5, gsql_set_oplog, 5, gsql_show_oplog, cm_text_str_less_equal_ins },
    { "CONNECT_TIMEOUT", 7, gsql_set_connect_timeout, 7, gsql_show_connect_timeout, cm_text_str_less_equal_ins },
    { "SOCKET_TIMEOUT", 6, gsql_set_socket_timeout, 6, gsql_show_socket_timeout, cm_text_str_less_equal_ins },
    { "CTCLIENT_SSL_MODE", 13, gsql_set_ssl_mode, 3, gsql_show_ssl_mode, cm_text_str_less_equal_ins },
    { "CTCLIENT_SSL_CA", 11, gsql_set_ssl_ca_file, 3, gsql_show_ssl_ca_file, cm_text_str_less_equal_ins },
    { "CTCLIENT_SSL_CERT", 13, gsql_set_ssl_cert_file, 3, gsql_show_ssl_cert_file, cm_text_str_less_equal_ins },
    { "CTCLIENT_SSL_KEY", 12, gsql_set_ssl_key_file, 3, gsql_show_ssl_key_file, cm_text_str_less_equal_ins },
    { "CTCLIENT_SSL_CRL", 12, gsql_set_ssl_crl_file, 3, gsql_show_ssl_crl_file, cm_text_str_less_equal_ins },
    { "CTCLIENT_SSL_KEY_PASSWD", 19, gsql_set_ssl_key_passwd, 3, gsql_show_ssl_key_passwd, cm_text_str_less_equal_ins },
    { "CTCLIENT_SSL_CIPHER", 15, gsql_set_ssl_cipher, 3, gsql_show_ssl_cipher, cm_text_str_less_equal_ins },
    { "UDS_SERVER_PATH", 15, gsql_set_uds_srv_path, 15, gsql_show_uds_srv_path, cm_text_str_less_equal_ins },
    { "UDS_CLIENT_PATH", 15, gsql_set_uds_clt_path, 15, gsql_show_uds_clt_path, cm_text_str_less_equal_ins },
    { "BIND", 4, gsql_set_bindparam_force_on, 4, gsql_show_bindparam_force_on, cm_text_str_less_equal_ins },
    { "SHARD_RW_FLAG", 13, gsql_set_shd_rw_split, 13, gsql_show_shd_rw_split, cm_text_str_less_equal_ins },
    { "CREATE", 6, NULL, 6, gsql_show_create_opt, cm_text_str_contain_equal_ins },
    { "HISTORY", 4, gsql_set_history, 4, gsql_show_history, cm_text_str_less_equal_ins },
    { "AUTOTRACE", 9, gsql_set_autotrace, 9, gsql_show_autotrace, cm_text_str_less_equal_ins },
    { "TENANT_NAME", 11, NULL, 11, gsql_show_tenant_opt, cm_text_str_less_equal_ins },
    { "TENANT_ID", 9, NULL, 9, gsql_show_tenant_opt, cm_text_str_less_equal_ins }
};

typedef enum en_gsql_option_id {
    OPT_AUTOCOMMIT = 0,
    OPT_EXITCOMMIT,
    OPT_CHARSET,
    OPT_HEADING,
    OPT_SERVEROUTPUT,
    OPT_TRIMSPOOL,
    OPT_SPOOL,
    OPT_LINESIZE,
    OPT_NUMWIDTH,
    OPT_PAGESIZE,
    OPT_TIMING,
    OPT_FEEDBACK,
    OPT_PARAMETERS,
    OPT_LONG,
    OPT_COLSEP,
    OPT_NEWPAGE,
    OPT_VERIFY,
    OPT_TERMOUT,
    OPT_DEFINE,
    OPT_SCRIPTOUTPUT,
    OPT_OPLOG,
    OPT_CONNECT_TIMEOUT,
    OPT_SOCKET_TIMEOUT,
    OPT_SSL_MODE,
    OPT_SSL_CA,
    OPT_SSL_CERT,
    OPT_SSL_KEY,
    OPT_SSL_CRL,
    OPT_SSL_KEYPWD,
    OPT_SSL_CIPHER,
    OPT_UDS_SERVER_PATH,
    OPT_UDS_CLIENT_PATH,
    OPT_BINDPARAM_FORCE,
    OPT_SHD_RW_FLAG,
    OPT_CREATE,
    OPT_HISTORY,
    OPT_AUTOTRACE,
    OPT_TENANT_NAME,
    OPT_TENANT_ID,
    OPT_MAX
} gsql_option_id_t;

#define GSQL_OPTION_COUNT (sizeof(g_options) / sizeof(gsql_option_t))

static void gsql_display_set_usage(void)
{
    gsql_printf("Usage:\n");
    gsql_printf("SET AUTO[COMMIT] {ON|OFF}\n");
    gsql_printf("SET EXITC[OMMIT] {ON|OFF}\n");
    gsql_printf("SET CHARSET {GBK|UTF8}\n");
    gsql_printf("SET HEA[DING] {ON|OFF}\n");
    gsql_printf("SET SERVEROUT[PUT] {ON|OFF}\n");
    gsql_printf("SET TRIMS[POOOL] {ON|OFF}\n");
    gsql_printf("SET LIN[ESIZE] {80|n}\n");
    gsql_printf("SET NUM[WIDTH] {10|n}\n");
    gsql_printf("SET PAGES[IZE] {14|n}\n");
    gsql_printf("SET TIM[ING] {ON|OFF}\n");
    gsql_printf("SET FEED[BACK] {n|ON|OFF}\n");
    gsql_printf("SET ECHO {ON|OFF}\n");
    gsql_printf("SET VER[IFY] {ON|OFF}\n");
    gsql_printf("SET TERM[OUT] {ON|OFF}\n");
    gsql_printf("SET NEWP[AGE] {1|n|NONE}\n");
    gsql_printf("SET COLSEP {'text'|\"text\"|text}\n");
    gsql_printf("SET LONG {n}\n");
    gsql_printf("SET DEFINE {ON|OFF|ONE CHAR}\n");
    gsql_printf("SET OPLOG {ON|OFF}\n");
    gsql_printf("SET CONNECT[_TIMEOUT] {-1|n}\n");
    gsql_printf("SET SOCKET[_TIMEOUT] {-1|n}\n");
    gsql_printf("SET CTCLIENT_SSL_CA [=] {ca_file_path}\n");
    gsql_printf("SET CTCLIENT_SSL_CERT [=] {cert_file_path}\n");
    gsql_printf("SET CTCLIENT_SSL_KEY [=] {key_file_path}\n");
    gsql_printf("SET CTCLIENT_SSL_MODE [=] {DISABLED|PREFERRED|REQUIRED|VERIFY_CA|VERIFY_FULL}\n");
    gsql_printf("SET CTCLIENT_SSL_CRL [=] {crl_file_path}\n");
    gsql_printf("SET CTCLIENT_SSL_KEY_PASSWD [=] {ssl_keypwd}\n");
    gsql_printf("SET CTCLIENT_SSL_CIPHER [=] {ssl_cipher}\n");
    gsql_printf("SET UDS_SERVER_PATH [=] {path}\n");
    gsql_printf("SET UDS_CLIENT_PATH [=] {path}\n");
    gsql_printf("SET BIND {ON|OFF}\n");
    gsql_printf("SET SHARD_RW_FLAG {0|1|2|3}\n");
    gsql_printf("SET HIST[ORY] {ON|OFF}\n");
    gsql_printf("SET AUTOTRACE {ON|OFF|TRACEONLY}\n");
}

static bool32 is_match_suffix(const char *str, const char *suffix)
{
    uint32 len = (uint32)strlen(suffix);
    int32 offset = (int32)(strlen(str) - len);
    if (offset <= 0) {
        return GS_FALSE;
    }

    return cm_str_equal(str + offset, suffix) ? GS_TRUE : GS_FALSE;
}

static status_t gsql_check_ssl_file(uint32 opt, const char *env_val, char *path, uint32 path_len)
{
    GS_RETURN_IFERR(realpath_file(env_val, path, path_len));

    if (opt == OPT_SSL_CA || opt == OPT_SSL_CERT) {
        if (!MATCH_CRT_CER_PEM(path)) {
            GS_THROW_ERROR(ERR_PATH_NOT_ALLOWED_TO_ACCESS, path);
            return GS_ERROR;
        }
    } else if (opt == OPT_SSL_KEY) {
        if (!MATCH_KEY_PEM(path)) {
            GS_THROW_ERROR(ERR_PATH_NOT_ALLOWED_TO_ACCESS, path);
            return GS_ERROR;
        }
    } else if (opt == OPT_SSL_CRL) {
        if (!MATCH_CRL_PEM(path)) {
            GS_THROW_ERROR(ERR_PATH_NOT_ALLOWED_TO_ACCESS, path);
            return GS_ERROR;
        }
    } else {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

void gsql_init_ssl_config(void)
{
    char *env_val = NULL;
    char path[GS_FILE_NAME_BUFFER_SIZE] = { 0 };
    errno_t errcode;

    env_val = getenv(g_options[OPT_SSL_CA].name);
    if (!CM_IS_EMPTY_STR(env_val)) {
        if (gsql_check_ssl_file(OPT_SSL_CA, env_val, path, GS_FILE_NAME_BUFFER_SIZE) == GS_SUCCESS) {
            errcode = strncpy_s(g_local_config.ssl_ca, GS_FILE_NAME_BUFFER_SIZE, path, strlen(path));
            if (errcode != EOK) {
                // reset config if error occurs
                GS_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
                g_local_config.ssl_ca[0] = '\0';
            }
        }
    }

    env_val = getenv(g_options[OPT_SSL_CERT].name);
    if (!CM_IS_EMPTY_STR(env_val)) {
        if (gsql_check_ssl_file(OPT_SSL_CERT, env_val, path, GS_FILE_NAME_BUFFER_SIZE) == GS_SUCCESS) {
            errcode = strncpy_s(g_local_config.ssl_cert, GS_FILE_NAME_BUFFER_SIZE, path, strlen(path));
            if (errcode != EOK) {
                // reset config if error occurs
                GS_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
                g_local_config.ssl_cert[0] = '\0';
            }
        }
    }

    env_val = getenv(g_options[OPT_SSL_KEY].name);
    if (!CM_IS_EMPTY_STR(env_val)) {
        if (gsql_check_ssl_file(OPT_SSL_KEY, env_val, path, GS_FILE_NAME_BUFFER_SIZE) == GS_SUCCESS) {
            errcode = strncpy_s(g_local_config.ssl_key, GS_FILE_NAME_BUFFER_SIZE, path, strlen(path));
            if (errcode != EOK) {
                // reset config if error occurs
                GS_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
                g_local_config.ssl_key[0] = '\0';
            }
        }
    }

    env_val = getenv(g_options[OPT_SSL_KEYPWD].name);
    if (!CM_IS_EMPTY_STR(env_val)) {
        errcode = strncpy_s(g_local_config.ssl_keypwd, sizeof(g_local_config.ssl_keypwd), env_val, strlen(env_val));
        if (errcode != EOK) {
            // reset config if error occurs
            GS_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
            g_local_config.ssl_keypwd[0] = '\0';
        }
    }

    env_val = getenv(g_options[OPT_SSL_CRL].name);
    if (!CM_IS_EMPTY_STR(env_val)) {
        if (gsql_check_ssl_file(OPT_SSL_CRL, env_val, path, GS_FILE_NAME_BUFFER_SIZE) == GS_SUCCESS) {
            errcode = strncpy_s(g_local_config.ssl_crl, GS_FILE_NAME_BUFFER_SIZE, path, strlen(path));
            if (errcode != EOK) {
                // reset config if error occurs
                GS_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
                g_local_config.ssl_crl[0] = '\0';
            }
        }
    }

    env_val = getenv(g_options[OPT_SSL_CIPHER].name);
    if (!CM_IS_EMPTY_STR(env_val)) {
        errcode = strncpy_s(g_local_config.ssl_cipher, GS_PARAM_BUFFER_SIZE, env_val, GS_PARAM_BUFFER_SIZE - 1);
        if (errcode != EOK) {
            // reset config if error occurs
            GS_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
            g_local_config.ssl_cipher[0] = '\0';
        }
    }

    env_val = getenv(g_options[OPT_SSL_MODE].name);
    if (!CM_IS_EMPTY_STR(env_val)) {
        for (uint32 i = 0; i < g_ssl_mode_count; ++i) {
            if (cm_str_equal_ins(env_val, g_ssl_mode_txt_list[i])) {
                g_local_config.ssl_mode = (gsc_ssl_mode_t)i;
                break;
            }
        }
    }
}

static uint32 gsql_get_on_off(text_t *value)
{
    if (cm_text_str_equal_ins(value, "ON")) {
        return GS_TRUE;
    } else if (cm_text_str_equal_ins(value, "OFF")) {
        return GS_FALSE;
    } else {
        return GS_INVALID_ID32;
    }
}

static void gsql_set_autocommit(text_t *value)
{
    uint32 autocommit = gsql_get_on_off(value);
    if (autocommit == GS_INVALID_ID32) {
        gsql_printf("unknown set autocommit option.\n");
        gsql_printf("Usage: SET AUTO[COMMIT] {ON|OFF}.\n");
        return;
    }

    g_local_config.auto_commit = autocommit;
    gsc_set_autocommit(CONN, autocommit);
    gsql_printf((autocommit == GS_TRUE) ? "ON" : "OFF");
}

static void gsql_set_exitcommit(text_t *value)
{
    uint32 exitcommit = gsql_get_on_off(value);
    if (exitcommit == GS_INVALID_ID32) {
        gsql_printf("unknown set exitcommit option.\n");
        gsql_printf("Usage: SET EXITC[OMMIT] {ON|OFF}.\n");
        return;
    }

    g_local_config.exit_commit = exitcommit;
    (void)gsc_set_conn_attr(CONN, GSC_ATTR_EXIT_COMMIT, &exitcommit, sizeof(uint32));
    gsql_printf((exitcommit == GS_TRUE) ? "ON" : "OFF");
}

static void gsql_set_charset(text_t *value)
{
    if (value->len >= GS_MAX_CHARSET_NAME) {
        gsql_printf("len of charset to set exceed maxsize(%u).\n", GS_MAX_CHARSET_NAME);
        return;
    }

    CM_NULL_TERM(value);

    uint16 charset_id = cm_get_charset_id((const char *)value->str);
    if (charset_id == GS_INVALID_ID16) {
        gsql_printf("unknown charset option %s.\n", value->str);
        gsql_printf("Usage: SET CHARSET {GBK|UTF8}.\n");
        return;
    }

    g_local_config.charset_id = charset_id;
    (void)gsc_set_conn_attr(CONN, GSC_ATTR_CHARSET_TYPE, value->str, value->len);
    gsql_printf("%s", (char *)cm_get_charset_name((charset_type_t)charset_id));
}

static void gsql_set_history(text_t *value)
{
    uint32 history = gsql_get_on_off(value);
    if (history == GS_INVALID_ID32) {
        gsql_printf("unknown set history option.\n");
        gsql_printf("Usage: SET HIST[ORY] {ON|OFF}.\n");
        return;
    }

    g_local_config.history_on = history;
    gsql_printf((history == GS_TRUE) ? "ON" : "OFF");
}

static void gsql_set_heading(text_t *value)
{
    uint32 heading_on = gsql_get_on_off(value);
    if (heading_on == GS_INVALID_ID32) {
        gsql_printf("unknown set heading option.\n");
        gsql_printf("Usage: SET HEA[DING] {ON|OFF}.\n");
        return;
    }

    g_local_config.heading_on = heading_on;
    gsql_printf((heading_on == GS_TRUE) ? "ON" : "OFF");
}

static void gsql_set_serverouput(text_t *value)
{
    uint32 serverouput_on = gsql_get_on_off(value);
    if (serverouput_on == GS_INVALID_ID32) {
        gsql_printf("unknown set serverouput option.\n");
        gsql_printf("Usage: SET SERVEROUT[PUT] {ON|OFF}.\n");
        return;
    }

    g_local_config.server_ouput = serverouput_on;
    (void)gsc_set_conn_attr(CONN, GSC_ATTR_SERVEROUTPUT, &serverouput_on, sizeof(uint32));
    gsql_printf((serverouput_on == GS_TRUE) ? "ON" : "OFF");
}

static void gsql_set_trimspool(text_t *value)
{
    uint32 trimspool_on = gsql_get_on_off(value);
    if (trimspool_on == GS_INVALID_ID32) {
        gsql_printf("unknown set trimspool option.\n");
        gsql_printf("Usage: SET TRIMS[POOL] {ON|OFF}.\n");
        return;
    }

    g_local_config.trim_spool = trimspool_on;
    gsql_printf((trimspool_on == GS_TRUE) ? "ON" : "OFF");
}

static void gsql_set_linesize(text_t *value)
{
    uint32 line_size;

    if (cm_text2uint32(value, &line_size) != GS_SUCCESS) {
        gsql_printf("linesize option not a valid number.\n");
        return;
    }

    g_local_config.line_size = line_size;
}

static void gsql_set_longsize(text_t *value)
{
    uint32 long_size;

    if (cm_text2uint32(value, &long_size) != GS_SUCCESS) {
        gsql_printf("long_size option not a valid number.\n");
        return;
    }

    g_local_config.long_size = long_size;
}

static void gsql_set_numwidth(text_t *value)
{
    uint32 num_width;

    if (cm_text2uint32(value, &num_width) != GS_SUCCESS) {
        gsql_printf("numwidth option not a valid number.\n");
        return;
    }

    if (gsc_set_conn_attr(CONN, GSC_ATTR_NUM_WIDTH, &num_width, sizeof(uint32)) != GSC_SUCCESS) {
        gsql_print_error(CONN);
        return;
    }
}

static void gsql_set_pagesize(text_t *value)
{
    uint32 page_size = 0;

    if (cm_text2uint32(value, &page_size) != GS_SUCCESS) {
        gsql_printf("pagesize option not a valid number.\n");
        return;
    }

    if (page_size != 0 && page_size < GS_MIN_PAGESIZE) {
        gsql_printf("pagesize option %u must large than %u (0 means display all rows in one page).\n", page_size,
                    GS_MIN_PAGESIZE);
        return;
    }

    g_local_config.page_size = (page_size == 0) ? GS_INVALID_INT32 : page_size;
}

static void gsql_set_timing(text_t *value)
{
    uint32 timing_on = gsql_get_on_off(value);
    if (timing_on == GS_INVALID_ID32) {
        gsql_printf("unknown set timing option.\n");
        gsql_printf("Usage: SET TIM[ING] {ON|OFF}.\n");
        return;
    }

    g_local_config.timer.timing_on = timing_on;
    gsql_printf((timing_on == GS_TRUE) ? "ON" : "OFF");
}

static const char *g_trace_value_list[] = { "OFF", "ON", "TRACEONLY" };

static void gsql_set_autotrace(text_t *value)
{
    uint32 i;
    uint32 trace_mode_count = sizeof(g_trace_value_list) / sizeof(g_trace_value_list[0]);
    for (i = 0; i < trace_mode_count; i++) {
        if (cm_text_str_equal_ins(value, g_trace_value_list[i])) {
            g_local_config.trace_mode = i;
            break;
        }
    }
    if (i >= trace_mode_count) {
        gsql_printf("unknown set autotrace option.\n");
        gsql_printf("Usage: SET AUTOTRACE {ON|OFF|TRACEONLY}.\n");
        return;
    }
    (void)gsc_set_conn_attr(CONN, GSC_ATTR_AUTOTRACE, &i, sizeof(uint32));
    gsql_printf("%s", (char *)g_trace_value_list[i]);
}

static void gsql_set_feedback(text_t *value)
{
    uint32 feedback_on = gsql_get_on_off(value);
    if (feedback_on != GS_INVALID_ID32) {
        g_local_config.feedback.feedback_on = feedback_on;
        gsql_printf((feedback_on == GS_TRUE) ? "ON" : "OFF");
        if (feedback_on == GS_TRUE) {
            g_local_config.feedback.feedback_rows = 1;
        } else {
            g_local_config.feedback.feedback_rows = 0;
        }
    } else {
        if (cm_text2uint32(value, &g_local_config.feedback.feedback_rows) != GS_SUCCESS) {
            gsql_printf("Feedback row option is not a valid number.\n");
            gsql_printf("Usage: SET FEEDBACK {ON|OFF|n}.\n");
            return;
        }
        if (g_local_config.feedback.feedback_rows == 0) {
            g_local_config.feedback.feedback_on = GS_FALSE;
            gsql_printf("Feedback is OFF.\n");
        } else {
            g_local_config.feedback.feedback_on = GS_TRUE;
            gsql_printf("Feedback is ON, and feedback row is %u.\n", g_local_config.feedback.feedback_rows);
        }
    }
    return;
}

static void gsql_set_define_on(text_t *value)
{
    uint32 define_on = gsql_get_on_off(value);
    if (define_on == GS_INVALID_ID32 && value->len > 1) {
        gsql_printf("unknown set define_on option.\n");
        gsql_printf("Usage: SET DEFINE {ON|OFF|one char}.\n");
        return;
    }

    g_local_config.define_on = define_on;
    if (define_on == GS_INVALID_ID32) {
        g_replace_mark = value->str[0];
        g_local_config.define_on = GS_TRUE;
    }

    gsql_printf((define_on == GS_FALSE) ? "OFF" : "ON");
}

static void gsql_set_oplog(text_t *value)
{
    uint32 oplog_on = gsql_get_on_off(value);
    if (oplog_on == GS_INVALID_ID32) {
        gsql_printf("unknown set oplog option.\n");
        gsql_printf("Usage: SET OPLOG {ON|OFF}.\n");
    } else {
        gsql_printf((oplog_on == GS_TRUE) ? "ON" : "OFF");
        if (oplog_on == GS_TRUE) {
            cm_log_param_instance()->log_level |= 0x00000200;
        } else {
            cm_log_param_instance()->log_level &= !(0x00000200);
        }
    }
}

static void gsql_set_connect_timeout(text_t *value)
{
    int32 connect_timeout = 0;

    if (cm_text2int(value, &connect_timeout) != GS_SUCCESS) {
        gsql_printf("connect_timeout option not a valid number.\n");
        return;
    }

    if (connect_timeout < -1) {
        gsql_printf("connect_timeout option must be -1 or positive number.\n");
        return;
    }

    if (gsc_set_conn_attr(CONN, GSC_ATTR_CONNECT_TIMEOUT, &connect_timeout, sizeof(int32)) != GSC_SUCCESS) {
        gsql_print_error(CONN);
        return;
    }
    g_local_config.connect_timeout = connect_timeout;
}

static void gsql_set_socket_timeout(text_t *value)
{
    int32 socket_timeout = 0;

    if (cm_text2int(value, &socket_timeout) != GS_SUCCESS) {
        gsql_printf("socket_timeout option not a valid number.\n");
        return;
    }

    if (socket_timeout < -1) {
        gsql_printf("socket_timeout option must be -1 or positive number.\n");
        return;
    }

    if (gsc_set_conn_attr(CONN, GSC_ATTR_SOCKET_TIMEOUT, &socket_timeout, sizeof(int32)) != GSC_SUCCESS) {
        gsql_print_error(CONN);
        return;
    }
    g_local_config.socket_timeout = socket_timeout;
}

static void gsql_set_scriptoutput(text_t *value)
{
    uint32 script_output = gsql_get_on_off(value);
    if (script_output == GS_INVALID_ID32) {
        gsql_printf("unknown set echo option.\n");
        gsql_printf("Usage: SET ECHO {ON|OFF}.\n");
        return;
    }

    g_local_config.script_output = script_output;
    gsql_printf((script_output == GS_TRUE) ? "ON" : "OFF");
}

static void gsql_set_verify_on(text_t *value)
{
    uint32 verify_on = gsql_get_on_off(value);
    if (verify_on == GS_INVALID_ID32) {
        gsql_printf("unknown set verify option.\n");
        gsql_printf("Usage: SET VERIFY {ON|OFF}.\n");
        return;
    }

    g_local_config.verify_on = verify_on;
    gsql_printf((verify_on == GS_TRUE) ? "ON" : "OFF");
}

static void gsql_set_termout_on(text_t *value)
{
    uint32 termout_on = gsql_get_on_off(value);
    if (termout_on == GS_INVALID_ID32) {
        gsql_printf("unknown set termout option.\n");
        gsql_printf("Usage: SET TERM[OUT] {ON|OFF}.\n");
        return;
    }

    if (termout_on == GS_TRUE) {
        g_local_config.termout_on = GS_FALSE;  // reuse g_local_config.slient_on, GS_FALSE means on
    } else {
        g_local_config.termout_on = GS_TRUE;
    }

    if (g_is_print == GS_TRUE) {  // set term on in sql script
        g_local_config.silent_on = g_local_config.termout_on;
    }
}

static void gsql_set_newpage(text_t *value)
{
    uint32 newpage;
    if (cm_text_str_equal_ins(value, "NONE")) {
        newpage = 0;
    } else if (cm_text2uint32(value, &newpage) != GS_SUCCESS) {
        gsql_printf("unknown set newpage option.\n");
        gsql_printf("Usage: SET NEWP[AGE] {1|n|none}.\n");
        return;
    }

    if (newpage > 999) {
        gsql_printf("Newpage option %u out of range(0~999)", newpage);
        return;
    }

    g_local_config.newpage = newpage;
}

static void gsql_set_colsep(text_t *value)
{
    char buf[GS_BUFLEN_256] = { 0 };
    cm_trim_text(value);
    value->str[value->len] = '\0';
    int32 code;

    if (value->len > GS_BUFLEN_256 - 1 || value->len < 1) {
        gsql_printf("Length of colsep string is %u, it is out of range [1~255]\n", value->len);
        return;
    }

    if (value->str[0] == '\'' && (value->str[value->len - 1] != '\'' || value->len == 1)) {
        gsql_printf("String \"%s\" missing terminating quote (')\n", value->str);
        gsql_printf("Usage: SET colsep {'text'|\"text\"|text}.\n");
        return;
    }

    if (value->str[0] == '"' && (value->str[value->len - 1] != '"' || value->len == 1)) {
        gsql_printf("String \"%s\" missing terminating quote (\")\n", value->str);
        gsql_printf("Usage: SET colsep {'text'|\"text\"|text}.\n");
        return;
    }

    if (GS_SUCCESS != cm_text2str(value, buf, GS_BUFLEN_256)) {
        gsql_printf("SET colsep: failed to convert text to str.\n");
        return;
    }

    if (buf[0] == '"' || buf[0] == '\'') {
        if (strlen(buf) > 2) {
            code = memcpy_s(g_local_config.colsep.colsep_name, MAX_COLSEP_NAME_LEN, buf + 1, strlen(buf) - 2);
            if (code != EOK) {
                gsql_printf("SET colsep: secure C lib has thrown an error %d.\n", code);
                return;
            }
        }
        g_local_config.colsep.colsep_name[strlen(buf) - 2] = '\0';
    } else {
        if (strlen(buf) != 0) {
            code = memcpy_s(g_local_config.colsep.colsep_name, MAX_COLSEP_NAME_LEN, buf, strlen(buf));
            if (code != EOK) {
                gsql_printf("SET colsep: secure C lib has thrown an error %d.\n", code);
                return;
            }
        }
        g_local_config.colsep.colsep_name[strlen(buf)] = '\0';
    }
    return;
}

static void gsql_set_ssl_mode(text_t *value)
{
    cm_trim_text(value);
    if (CM_TEXT_FIRST(value) == '=') {
        CM_REMOVE_FIRST(value);
        cm_trim_text(value);
    }

    if (CM_TEXT_END(value) == ';') {
        CM_REMOVE_LAST(value);
        cm_trim_text(value);
    }

    uint32 i;
    for (i = 0; i < g_ssl_mode_count; ++i) {
        if (cm_text_str_equal_ins(value, g_ssl_mode_txt_list[i])) {
            g_local_config.ssl_mode = (gsc_ssl_mode_t)i;
            break;
        }
    }

    if (i >= g_ssl_mode_count) {
        gsql_printf("unknown set zsql_ssl_mode option.\n");
        gsql_printf("Usage: SET ZSQL_SSL_MODE [=] {DISABLED|PREFERRED|REQUIRED|VERIFY_CA|VERIFY_FULL}.\n");
        return;
    }
    gsql_printf("ZSQL_SSL_MODE = %s\n", g_ssl_mode_txt_list[i]);
}

static int32 gsql_read_file_param(text_t *value, char *buf, uint32 len)
{
    cm_trim_text(value);
    if (CM_TEXT_FIRST(value) == '=') {
        CM_REMOVE_FIRST(value);
        cm_trim_text(value);
    }
    if (CM_TEXT_END(value) == ';') {
        CM_REMOVE_LAST(value);
        cm_trim_text(value);
    }

    if (!CM_IS_EMPTY(value) && CM_IS_ENCLOSED_WITH_CHAR(value, '\'')) {
        CM_REMOVE_ENCLOSED_CHAR(value);
    }

    if (!CM_IS_EMPTY(value) && !cm_text_str_equal_ins(value, "null")) {
        if (value->len > len - 1) {
            gsql_printf("length of file name '%s' exceeds the maximum(%u)\n", T2S(value), len - 1);
            return GS_ERROR;
        }
        GS_RETURN_IFERR(cm_text2str(value, buf, len));

        if (!cm_file_exist(buf) || cm_access_file(buf, R_OK) != GS_SUCCESS) {
            gsql_printf("file '%s' not exist\n", buf);
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

static void gsql_set_ssl_ca_file(text_t *value)
{
    char filepath[GS_FILE_NAME_BUFFER_SIZE] = { 0 };
    errno_t errcode;
    if (GS_SUCCESS != gsql_read_file_param(value, filepath, sizeof(filepath))) {
        return;
    }
    errcode = strncpy_s(g_local_config.ssl_ca, GS_FILE_NAME_BUFFER_SIZE, filepath, strlen(filepath));
    if (errcode != EOK) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return;
    }
    gsql_printf("ZSQL_SSL_CA = %s\n", CM_IS_EMPTY_STR(filepath) ? "<NULL>" : filepath);
}

static void gsql_set_ssl_cert_file(text_t *value)
{
    char filepath[GS_FILE_NAME_BUFFER_SIZE] = { 0 };
    errno_t errcode;
    if (GS_SUCCESS != gsql_read_file_param(value, filepath, sizeof(filepath))) {
        return;
    }
    errcode = strncpy_s(g_local_config.ssl_cert, GS_FILE_NAME_BUFFER_SIZE, filepath, strlen(filepath));
    if (errcode != EOK) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return;
    }
    gsql_printf("ZSQL_SSL_CERT = %s\n", CM_IS_EMPTY_STR(filepath) ? "<NULL>" : filepath);
}

static void gsql_set_ssl_key_file(text_t *value)
{
    char filepath[GS_FILE_NAME_BUFFER_SIZE] = { 0 };
    errno_t errcode;
    if (GS_SUCCESS != gsql_read_file_param(value, filepath, sizeof(filepath))) {
        return;
    }
    errcode = strncpy_s(g_local_config.ssl_key, GS_FILE_NAME_BUFFER_SIZE, filepath, strlen(filepath));
    if (errcode != EOK) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return;
    }
    gsql_printf("ZSQL_SSL_KEY = %s\n", CM_IS_EMPTY_STR(filepath) ? "<NULL>" : filepath);
}

static void gsql_set_ssl_crl_file(text_t *value)
{
    char filepath[GS_FILE_NAME_BUFFER_SIZE] = { 0 };
    errno_t errcode;
    if (GS_SUCCESS != gsql_read_file_param(value, filepath, sizeof(filepath))) {
        return;
    }
    errcode = strncpy_s(g_local_config.ssl_crl, GS_FILE_NAME_BUFFER_SIZE, filepath, strlen(filepath));
    if (errcode != EOK) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return;
    }
    gsql_printf("ZSQL_SSL_CRL = %s\n", CM_IS_EMPTY_STR(filepath) ? "<NULL>" : filepath);
}

static void gsql_set_ssl_key_passwd(text_t *value)
{
    if (CM_IS_EMPTY(value) || cm_text_str_equal_ins(value, "null")) {
        g_local_config.ssl_keypwd[0] = '\0';
        gsql_printf("ZSQL_SSL_KEY_PASSWD = <NULL>\n");
        return;
    }

    if (value->str[0] == '\'') {
        value->str++;
        value->len -= 2;
    }

    if (value->len > GS_MAX_CIPHER_LEN) {
        gsql_printf("invalid key password, maximum length is %d\n", GS_MAX_CIPHER_LEN);
        return;
    }

    (void)cm_text2str(value, g_local_config.ssl_keypwd, sizeof(g_local_config.ssl_keypwd));
    gsql_printf("ZSQL_SSL_KEY_PASSWD = %s\n", g_local_config.ssl_keypwd);
}

static void gsql_set_ssl_cipher(text_t *value)
{
    if (CM_IS_EMPTY(value) || cm_text_str_equal_ins(value, "null")) {
        g_local_config.ssl_cipher[0] = '\0';
        gsql_printf("ZSQL_SSL_CIPHER = <NULL>\n");
        return;
    }

    if (value->str[0] == '\'') {
        value->str++;
        value->len -= 2;
    }

    if (value->len > sizeof(g_local_config.ssl_cipher) - 1) {
        gsql_printf("invalid cipher, maximum length is %zu\n", sizeof(g_local_config.ssl_cipher) - 1);
        return;
    }

    cm_text2str(value, g_local_config.ssl_cipher, sizeof(g_local_config.ssl_cipher));
    gsql_printf("ZSQL_SSL_CIPHER = %s\n", g_local_config.ssl_cipher);
}

static void gsql_set_uds_path(text_t *value, const char *option, char *path, uint32 len, bool32 is_server)
{
    /* uds client can set null */
    if (CM_IS_EMPTY(value) || cm_text_str_equal_ins(value, "null")) {
        if (!is_server) {
            path[0] = '\0';
        }
        gsql_printf("%s = <NULL>\n", option);
        return;
    }

    if (value->len >= GS_UNIX_PATH_MAX) {
        gsql_printf("%s len must less than %u \n", option, GS_UNIX_PATH_MAX);
        return;
    }
    if (value->str[value->len - 1] == '/') {
        gsql_printf("%s needs to be a file\n", option);
        return;
    }

    char full_path[GS_UNIX_PATH_MAX];
    char dir_path[GS_UNIX_PATH_MAX];
    errno_t errcode;

    errcode = memcpy_sp(full_path, GS_UNIX_PATH_MAX, value->str, value->len);
    if (errcode != EOK) {
        gsql_printf("Secure C lib has thrown an error %d", errcode);
        return;
    }

    full_path[value->len] = '\0';

    if (strlen(full_path) == 1 && full_path[0] == '.') {
        gsql_printf("'%s' is invalid \n", full_path);
        return;
    }

    if (cm_check_exist_special_char(full_path, (uint32)strlen(full_path))) {
        gsql_printf("'%s' is invalid \n", full_path);
        return;
    }

    char *temp_path = strrchr(full_path, '/');
    if (temp_path != NULL && strlen(temp_path) != strlen(full_path)) {
        if (strlen(temp_path) == 2 && temp_path[1] == '.') {
            gsql_printf("'%s' is invalid \n", full_path);
            return;
        }
        errcode = memcpy_sp(dir_path, GS_UNIX_PATH_MAX, full_path, strlen(full_path) - strlen(temp_path));
        if (errcode != EOK) {
            gsql_printf("Secure C lib has thrown an error %d", errcode);
            return;
        }

        dir_path[strlen(full_path) - strlen(temp_path)] = '\0';
        if (!cm_dir_exist((const char *)dir_path)) {
            gsql_printf("Directory '%s' not exist\n", dir_path);
            return;
        }
        if (access(dir_path, W_OK | R_OK) != 0) {
            gsql_printf("Directory '%s' is not a readable or writable folder\n", dir_path);
            return;
        }
    }

    (void)cm_text2str(value, path, len);

    gsql_printf("%s = %s\n", option, path);
}

static void gsql_set_uds_clt_path(text_t *value)
{
    gsql_set_uds_path(value, "UDS_CLIENT_PATH", g_local_config.client_path, GS_UNIX_PATH_MAX, GS_FALSE);
}

static void gsql_set_uds_srv_path(text_t *value)
{
    gsql_set_uds_path(value, "UDS_SERVER_PATH", g_local_config.server_path, GS_UNIX_PATH_MAX, GS_TRUE);
}

static void gsql_set_bindparam_force_on(text_t *value)
{
    uint32 bindparam_force_on = gsql_get_on_off(value);
    if (bindparam_force_on == GS_INVALID_ID32) {
        gsql_printf("unknown set bind  option.\n");
        gsql_printf("Usage: SET bind {ON|OFF}, default OFF.\n");
        return;
    }

    if (bindparam_force_on == GS_TRUE) {
        g_local_config.bindparam_force_on = GS_TRUE;
    } else {
        g_local_config.bindparam_force_on = GS_FALSE;
    }
    gsql_printf((bindparam_force_on == GS_TRUE) ? "ON" : "OFF");
}

static void gsql_set_shd_rw_split(text_t *value)
{
    uint32 rw_split_flag;

    if (cm_text2uint32(value, &rw_split_flag) != GS_SUCCESS) {
        gsql_printf("shard_rw_flag option not a valid number.\n");
        return;
    }

    if (rw_split_flag < GSC_SHD_RW_SPLIT_NONE || rw_split_flag > GSC_SHD_RW_SPLIT_ROA) {
        gsql_printf("shard_rw_flag option not in [0,1,2,3].\n");
        return;
    }

    g_local_config.shd_rw_split = (uint8)rw_split_flag;

    gsc_set_conn_attr(CONN, GSC_ATTR_SHD_RW_FLAG, &rw_split_flag, sizeof(uint8));
    gsql_printf("%u", rw_split_flag);
}

status_t gsql_set_option_value(text_t option, text_t value)
{
    for (uint32 opt_idx = OPT_AUTOCOMMIT; opt_idx < OPT_MAX; opt_idx++) {
        if (cm_text_str_less_equal_ins(&option, g_options[opt_idx].name, g_options[opt_idx].set_less_len)) {
            if (g_options[opt_idx].set_att_func != NULL) {
                g_options[opt_idx].set_att_func(&value);
                return GS_SUCCESS;
            } else {
                break;
            }
        }
    }

    return GS_ERROR;
}

status_t gsql_set(text_t *line, text_t *params)
{
    text_t option, value;
    if (params->len == 0) {
        gsql_printf("Set failed.\n\n");
        gsql_display_set_usage();
        return GS_ERROR;
    }

    cm_trim_text(params);
    if (!cm_fetch_text(params, ' ', '\'', &option)) {
        gsql_printf("Set failed.\n\n");
        gsql_display_set_usage();
        return GS_ERROR;
    }
    if (CM_IS_EMPTY(params)) {
        *params = option;
        if (!cm_fetch_text(params, '=', '\'', &option)) {
            gsql_printf("Set failed.\n\n");
            gsql_display_set_usage();
            return GS_ERROR;
        }
    }

    cm_trim_text(&option);
    if (!CM_IS_EMPTY(&option) && CM_TEXT_END(&option) == '=') {
        CM_REMOVE_LAST(&option);
        cm_trim_text(&option);
    }
    cm_trim_text(params);
    if (!CM_IS_EMPTY(params) && CM_TEXT_FIRST(params) == '=') {
        CM_REMOVE_FIRST(params);
        cm_trim_text(params);
    }
    value = *params;

    if (CM_IS_EMPTY(&value)) {
        gsql_printf("Set failed.\n\n");
        gsql_display_set_usage();
        return GS_ERROR;
    }

    if (GS_SUCCESS != gsql_set_option_value(option, value)) {
        // DCL of set command
        return gsql_set_trx_iso_level(line);
    }
    return GS_SUCCESS;
}

static void gsql_display_show_usage(void)
{
    gsql_printf("Usage:\n");
    gsql_printf("SHOW AUTO[COMMIT]\n");
    gsql_printf("SHOW EXITC[OMMIT]\n");
    gsql_printf("SHOW CHARSET\n");
    gsql_printf("SHOW HEA[DING]\n");
    gsql_printf("SHOW SERVEROUT[PUT]\n");
    gsql_printf("SHOW TRIMS[POOL]\n");
    gsql_printf("SHOW SPOO[L]\n");
    gsql_printf("SHOW LIN[ESIZE]\n");
    gsql_printf("SHOW NUM[WIDTH]\n");
    gsql_printf("SHOW PAGES[IZE]\n");
    gsql_printf("SHOW TIM[ING]\n");
    gsql_printf("SHOW FEED[BACK]\n");
    gsql_printf("SHOW ECHO\n");
    gsql_printf("SHOW VER[IFY]\n");
    gsql_printf("SHOW TERM[OUT]\n");
    gsql_printf("SHOW NEWP[AGE]\n");
    gsql_printf("SHOW COLSEP\n");
    gsql_printf("SHOW LONG\n");
    gsql_printf("SHOW PARAMETER[S] [PARAMETER_NAME]\n");
    gsql_printf("SHOW DEFINE\n");
    gsql_printf("SHOW OPLOG\n");
    gsql_printf("SHOW CONNECT[_TIMEOUT]\n");
    gsql_printf("SHOW SOCKET[_TIMEOUT]\n");
    gsql_printf("SHOW ZSQL_SSL[_MODE|_CA|_CERT|_KEY|_CRL|_KEY_PASSWD|_CIPHER]\n");
    gsql_printf("SHOW UDS_SERVER_PATH\n");
    gsql_printf("SHOW UDS_CLIENT_PATH\n");
    gsql_printf("SHOW BIND\n");
    gsql_printf("SHOW SHARD_RW_FLAG\n");
    gsql_printf("SHOW HIST[ORY]\n");
    gsql_printf("SHOW AUTOTRACE\n");
    gsql_printf("SHOW TENANT_NAME\n");
    gsql_printf("SHOW TENANT_ID\n");
    gsql_printf("SHOW CREATE TABLE\n");
}

static void gsql_print_parameters(text_t *params, text_t *base_sql, char *sql_select)
{
    uint32 affected_rows = 0;
    bool32 feedback_on = GS_FALSE;
    uint16 bind_size = 0;
    bool32 temp_trace = GSQL_TRACE_OFF;

    if (params->len == 0) {
        if (base_sql->len >= MAX_SQL_SIZE) {
            return;
        }
        if (base_sql->len != 0) {
            MEMS_RETVOID_IFERR(memcpy_s(g_sql_buf, MAX_SQL_SIZE, base_sql->str, base_sql->len));
        }

        g_sql_buf[base_sql->len] = '\0';
        // output query result
        // sql sent to the server is dml, but show parameter no need trace when autotrace is on
        (void)gsc_set_conn_attr(CONN, GSC_ATTR_AUTOTRACE, &temp_trace, sizeof(uint32));
        if (gsql_execute_sql() == GS_SUCCESS) {
            (void)gsc_get_stmt_attr(STMT, GSC_ATTR_AFFECTED_ROWS, &affected_rows, sizeof(uint32), NULL);
            if (affected_rows > 0) {
                feedback_on = g_local_config.feedback.feedback_on;
                g_local_config.feedback.feedback_on = GS_FALSE;
                gsql_print_result();
                g_local_config.feedback.feedback_on = feedback_on;
            }
        }
        (void)gsc_set_conn_attr(CONN, GSC_ATTR_AUTOTRACE, &g_local_config.trace_mode, sizeof(uint32));
        g_sql_buf[0] = '\0';
    } else {
        bind_size = params->len;
        do {
            (void)gsc_set_conn_attr(CONN, GSC_ATTR_AUTOTRACE, &temp_trace, sizeof(uint32));
            GS_BREAK_IF_ERROR(gsc_prepare(STMT, sql_select));
            GS_BREAK_IF_ERROR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_CHAR, params->str, params->len, &bind_size));
            GS_BREAK_IF_ERROR(gsc_execute(STMT));

            (void)gsc_get_stmt_attr(STMT, GSC_ATTR_AFFECTED_ROWS, &affected_rows, sizeof(uint32), NULL);
            if (affected_rows > 0) {
                feedback_on = g_local_config.feedback.feedback_on;
                g_local_config.feedback.feedback_on = GS_FALSE;
                gsql_print_result();
                g_local_config.feedback.feedback_on = feedback_on;
            }
            (void)gsc_set_conn_attr(CONN, GSC_ATTR_AUTOTRACE, &g_local_config.trace_mode, sizeof(uint32));
            return;
        } while (0);
        (void)gsc_set_conn_attr(CONN, GSC_ATTR_AUTOTRACE, &g_local_config.trace_mode, sizeof(uint32));
        gsql_print_error(CONN);
        return;
    }
}

static void gsql_show_parameters(text_t *params)
{
    text_t param_opt, base_sql;
    char *sql_select = NULL;

    if (!cm_fetch_text(params, ' ', '\0', &param_opt)) {
        return;
    }

    if (!IS_CONN) {
        GSQL_PRINTF(ZSERR_GSQL, "connection is not established");
        return;
    }

    if (gsc_get_call_version(CONN) >= GSQL_COPYRIGHT_VERSION) {
        base_sql.str = (char *)"select NAME, DATATYPE, VALUE, RUNTIME_VALUE, EFFECTIVE from DV_PARAMETERS";
        base_sql.len = (uint32)strlen(base_sql.str);
        sql_select = "select NAME, DATATYPE, VALUE, RUNTIME_VALUE, EFFECTIVE from DV_PARAMETERS where upper(NAME)"
            " like upper('%'|| :1 || '%')";
    } else {
        base_sql.str = (char *)"select NAME, DATATYPE, VALUE, RUNTIME_VALUE, EFFECTIVE from V$PARAMETER";
        base_sql.len = (uint32)strlen(base_sql.str);
        sql_select = "select NAME, DATATYPE, VALUE, RUNTIME_VALUE, EFFECTIVE from V$PARAMETER where upper(NAME)"
            " like upper('%'|| :1 || '%')";
    }

    cm_trim_text(params);

    // generate sql to get parameters and print them
    gsql_print_parameters(params, &base_sql, sql_select);

    return;
}

static void gsql_show_tenant(const text_t *params)
{
    text_t base_sql;
    uint32 affected_rows = 0;
    bool32 feedback_on = GS_FALSE;
    char sql_select[GS_BUFLEN_128];

    if (!IS_CONN) {
        GSQL_PRINTF(ZSERR_GSQL, "connection is not established");
        return;
    }

    if (cm_text_str_equal_ins(params, "TENANT_ID")) {
        PRTS_RETVOID_IFERR(
            sprintf_s(sql_select, GS_BUFLEN_128, "SELECT SYS_CONTEXT('USERENV', 'TENANT_ID') TENANT_ID"));
    } else if (cm_text_str_equal_ins(params, "TENANT_NAME")) {
        PRTS_RETVOID_IFERR(
            sprintf_s(sql_select, GS_BUFLEN_128, "SELECT SYS_CONTEXT('USERENV', 'TENANT_NAME') TENANT_NAME"));
    } else {
        GSQL_PRINTF(ZSERR_GSQL, "cmd error, please check cmd");
        return;
    }

    (void)cm_str2text_safe(sql_select, (uint32)strlen(sql_select), &base_sql);
    MEMS_RETVOID_IFERR(memcpy_s(g_sql_buf, MAX_SQL_SIZE, base_sql.str, base_sql.len));
    g_sql_buf[base_sql.len] = '\0';

    // output query result
    if (gsql_execute_sql() == GS_SUCCESS) {
        (void)gsc_get_stmt_attr(STMT, GSC_ATTR_AFFECTED_ROWS, &affected_rows, sizeof(uint32), NULL);
        if (affected_rows > 0) {
            feedback_on = g_local_config.feedback.feedback_on;
            g_local_config.feedback.feedback_on = GS_FALSE;
            gsql_print_result();
            g_local_config.feedback.feedback_on = feedback_on;
        }
    }

    g_sql_buf[0] = '\0';
}

void gsql_show(text_t *params)
{
    bool8 param_matched = GS_FALSE;

    cm_trim_text(params);

    for (uint32 i = 0; i < OPT_MAX; i++) {
        if (g_options[i].match_func(params, g_options[i].name, g_options[i].show_less_len)) {
            param_matched |= g_options[i].show_att_func(params);
        }
    }

    if (!param_matched) {
        gsql_printf("Show failed.\n\n");
        gsql_display_show_usage();
    }

    return;
}

static bool8 gsql_show_autocommit(const text_t *value)
{
    gsql_printf("autocommit %s.\n", (g_local_config.auto_commit == GS_TRUE) ? "ON" : "OFF");
    return GS_TRUE;
}

static bool8 gsql_show_exitcommit(const text_t *value)
{
    gsql_printf("exitcommit %s.\n", (g_local_config.exit_commit == GS_TRUE) ? "ON" : "OFF");
    return GS_TRUE;
}

static bool8 gsql_show_charset(const text_t *value)
{
    gsql_printf("charset %s.\n", (char *)cm_get_charset_name((charset_type_t)g_local_config.charset_id));
    return GS_TRUE;
}

static bool8 gsql_show_heading(const text_t *value)
{
    gsql_printf("heading %s.\n", (g_local_config.heading_on == GS_TRUE) ? "ON" : "OFF");
    return GS_TRUE;
}

static bool8 gsql_show_serverouput(const text_t *value)
{
    gsql_printf("serveroutput %s.\n", (g_local_config.server_ouput == GS_TRUE) ? "ON" : "OFF");
    return GS_TRUE;
}

static bool8 gsql_show_spool(const text_t *value)
{
    gsql_printf("spool %s.\n", (g_local_config.spool_on == GS_TRUE) ? "ON" : "OFF");
    return GS_TRUE;
}

static bool8 gsql_show_trimspool(const text_t *value)
{
    gsql_printf("trimspool %s.\n", (g_local_config.trim_spool == GS_TRUE) ? "ON" : "OFF");
    return GS_TRUE;
}

static bool8 gsql_show_linesize(const text_t *value)
{
    gsql_printf("linesize %u.\n", g_local_config.line_size);
    return GS_TRUE;
}

static bool8 gsql_show_longsize(const text_t *value)
{
    gsql_printf("long is %u.\n", g_local_config.long_size);
    return GS_TRUE;
}

static bool8 gsql_show_numwidth(const text_t *value)
{
    uint32 num_width = 0;
    uint32 attr_len = 0;
    if (gsc_get_conn_attr(CONN, GSC_ATTR_NUM_WIDTH, &num_width, sizeof(uint32), &attr_len) != GSC_SUCCESS) {
        gsql_print_error(CONN);
        return GS_FALSE;
    }
    gsql_printf("numwidth %u.\n", num_width);
    return GS_TRUE;
}

static bool8 gsql_show_pagesize(const text_t *value)
{
    gsql_printf("pagesize %u.\n", g_local_config.page_size);
    return GS_TRUE;
}

static bool8 gsql_show_timing(const text_t *value)
{
    gsql_printf("timing %s.\n", (g_local_config.timer.timing_on == GS_TRUE) ? "ON" : "OFF");
    return GS_TRUE;
}

static bool8 gsql_show_feedback(const text_t *value)
{
    if (g_local_config.feedback.feedback_on == GS_TRUE) {
        gsql_printf("Feedback is ON, and feedback row is %u.\n", g_local_config.feedback.feedback_rows);
    } else {
        gsql_printf("Feedback is OFF.\n");
    }
    return GS_TRUE;
}

static bool8 gsql_show_define_on(const text_t *value)
{
    if (g_local_config.define_on == GS_FALSE) {
        gsql_printf("replace function is OFF.\n");
    } else {
        gsql_printf("replace fuction is ON and replace mark is %c.\n", g_replace_mark);
    }
    return GS_TRUE;
}

static bool8 gsql_show_oplog(const text_t *value)
{
    if (LOG_OPER_ON) {
        gsql_printf("CTCLIENT OPER LOG is ON.\n");
    } else {
        gsql_printf("CTCLIENT OPER LOG is OFF.\n");
    }
    return GS_TRUE;
}

static bool8 gsql_show_connect_timeout(const text_t *value)
{
    gsql_printf("ctclient connect timeout = %d\n", g_local_config.connect_timeout);
    return GS_TRUE;
}

static bool8 gsql_show_socket_timeout(const text_t *value)
{
    gsql_printf("ctclient socket timeout = %d\n", g_local_config.socket_timeout);
    return GS_TRUE;
}

static bool8 gsql_show_scriptoutput(const text_t *value)
{
    gsql_printf("echo %s.\n", (g_local_config.script_output == GS_TRUE) ? "ON" : "OFF");
    return GS_TRUE;
}

static bool8 gsql_show_verify_on(const text_t *value)
{
    gsql_printf("verify %s.\n", (g_local_config.verify_on == GS_TRUE) ? "ON" : "OFF");
    return GS_TRUE;
}

static bool8 gsql_show_termout_on(const text_t *value)
{
    gsql_printf("termout %s.\n", (g_local_config.termout_on == GS_TRUE) ? "OFF" : "ON");
    return GS_TRUE;
}

static bool8 gsql_show_newpage(const text_t *value)
{
    if (g_local_config.newpage > 0) {
        gsql_printf("newpage is %u.\n", g_local_config.newpage);
    } else {
        gsql_printf("newpage OFF.\n");
    }
    return GS_TRUE;
}

static bool8 gsql_show_colsep(const text_t *value)
{
    gsql_printf("colsep is \"%s\".\n", g_local_config.colsep.colsep_name);
    return GS_TRUE;
}

static bool8 gsql_show_ssl_mode(const text_t *value)
{
    gsql_printf("zsql_ssl_mode    %s\n", g_ssl_mode_txt_list[g_local_config.ssl_mode]);
    return GS_TRUE;
}

static bool8 gsql_show_ssl_ca_file(const text_t *value)
{
    gsql_printf("zsql_ssl_ca      %s\n", CM_IS_EMPTY_STR(g_local_config.ssl_ca) ? "<NULL>" : g_local_config.ssl_ca);
    return GS_TRUE;
}

static bool8 gsql_show_ssl_cert_file(const text_t *value)
{
    gsql_printf("zsql_ssl_cert    %s\n", CM_IS_EMPTY_STR(g_local_config.ssl_cert) ? "<NULL>" : g_local_config.ssl_cert);
    return GS_TRUE;
}

static bool8 gsql_show_ssl_key_file(const text_t *value)
{
    gsql_printf("zsql_ssl_key     %s\n", CM_IS_EMPTY_STR(g_local_config.ssl_key) ? "<NULL>" : g_local_config.ssl_key);
    return GS_TRUE;
}

static bool8 gsql_show_ssl_crl_file(const text_t *value)
{
    gsql_printf("zsql_ssl_crl     %s\n", CM_IS_EMPTY_STR(g_local_config.ssl_crl) ? "<NULL>" : g_local_config.ssl_crl);
    return GS_TRUE;
}

static bool8 gsql_show_ssl_key_passwd(const text_t *value)
{
    gsql_printf("zsql_ssl_key_passwd  %s\n",
                CM_IS_EMPTY_STR(g_local_config.ssl_keypwd) ? "<NULL>" : g_local_config.ssl_keypwd);
    return GS_TRUE;
}

static bool8 gsql_show_ssl_cipher(const text_t *value)
{
    gsql_printf("zsql_ssl_cipher  %s\n",
                CM_IS_EMPTY_STR(g_local_config.ssl_cipher) ? "<NULL>" : g_local_config.ssl_cipher);
    return GS_TRUE;
}

static bool8 gsql_show_uds_clt_path(const text_t *value)
{
    gsql_printf("uds_client_path = %s\n",
                CM_IS_EMPTY_STR(g_local_config.client_path) ? "<NULL>" : g_local_config.client_path);
    return GS_TRUE;
}

static bool8 gsql_show_uds_srv_path(const text_t *value)
{
    gsql_printf("uds_server_path = %s\n",
                CM_IS_EMPTY_STR(g_local_config.server_path) ? "<NULL>" : g_local_config.server_path);
    return GS_TRUE;
}

static bool8 gsql_show_bindparam_force_on(const text_t *value)
{
    gsql_printf("ctclient BIND = %s\n", (g_local_config.bindparam_force_on == GS_TRUE) ? "ON" : "OFF");
    return GS_TRUE;
}

static bool8 gsql_show_shd_rw_split(const text_t *value)
{
    gsql_printf("shard_rw_flag = %u\n", g_local_config.shd_rw_split);
    return GS_TRUE;
}

static bool8 gsql_show_history(const text_t *value)
{
    gsql_printf("history %s.\n", (g_local_config.history_on == GS_TRUE) ? "ON" : "OFF");
    return GS_TRUE;
}

static bool8 gsql_show_autotrace(const text_t *value)
{
    gsql_printf("autotrace %s.\n", g_trace_value_list[g_local_config.trace_mode]);
    return GS_TRUE;
}

/* currently used for create table DDL clause display; further development may extend to display create otherwise */
static status_t gsql_show_create(const text_t *create_table_text)
{
    bool32 show_parse_info = GS_FALSE; /* show create table does NOT display parse progress in exp */
    text_t cmd_sql;
    lex_t lex;
    word_t word;
    char send_cmd[GS_MAX_CMD_LEN] = { 0 };
    char table_name_str[GS_NAME_BUFFER_SIZE] = { 0 };
    sql_text_t sql_text;
    sql_text.value = *create_table_text;
    sql_text.loc.line = 1;
    sql_text.loc.column = 1;
    text_buf_t tbl_name_buf;

    if (!IS_CONN) {
        GSQL_PRINTF(ZSERR_GSQL, "connection is not established");
        return GS_ERROR;
    }

    lex_trim(&sql_text);
    lex_init(&lex, &sql_text);
    lex_init_keywords();

    /* parse cmd keywords for ' create table *table_name* ' */
    if (lex_expected_fetch_word(&lex, "create") != GS_SUCCESS) {
        GSQL_PRINTF(ERR_SQL_SYNTAX_ERROR, "keyword 'create' expected.");
        return GS_ERROR;
    }
    if (lex_expected_fetch_word(&lex, "table") != GS_SUCCESS) {
        GSQL_PRINTF(ERR_SQL_SYNTAX_ERROR, "keyword 'table' expected.");
        return GS_ERROR;
    }

    tbl_name_buf.max_size = MAX_ENTITY_LEN;
    tbl_name_buf.str = g_str_buf;
    tbl_name_buf.len = 0;

    if (lex_expected_fetch_tblname(&lex, &word, &tbl_name_buf) != GS_SUCCESS || lex_expected_end(&lex) != GS_SUCCESS) {
        g_tls_error.loc.line = 0;
        gsql_print_error(NULL);
        gsql_printf("Usage: SHOW CREATE TABLE table_name\n");
        return GS_ERROR;
    }
    CM_NULL_TERM(&tbl_name_buf);

    MEMS_RETURN_IFERR(strncpy_s(table_name_str, GS_NAME_BUFFER_SIZE, tbl_name_buf.str, tbl_name_buf.len));

    MEMS_RETURN_IFERR(strcat_s(send_cmd, GS_MAX_CMD_LEN, "EXPORT SHOW_CREATE_TABLE=Y TABLES="));
    MEMS_RETURN_IFERR(strcat_s(send_cmd, GS_MAX_CMD_LEN, table_name_str));
    MEMS_RETURN_IFERR(strcat_s(send_cmd, GS_MAX_CMD_LEN, " CONTENT=METADATA_ONLY"));
    cm_str2text_safe(send_cmd, (uint32)strlen(send_cmd), &cmd_sql);
    GS_RETURN_IFERR(gsql_export(&cmd_sql, show_parse_info));

    return GS_SUCCESS;
}

static bool8 gsql_show_create_opt(const text_t *value)
{
    (void)gsql_show_create(value);
    return GS_TRUE;
}

static bool8 gsql_show_tenant_opt(const text_t *value)
{
    gsql_show_tenant(value);
    return GS_TRUE;
}

static bool8 gsql_show_parameters_opt(const text_t *value)
{
    uint32 match_len = cm_text_str_get_match_len(value, g_options[OPT_PARAMETERS].name);
    if (value->len == match_len || *(value->str + match_len) == ' ') {
        text_t param = *value;
        gsql_show_parameters(&param);
        return GS_TRUE;
    }
    return GS_FALSE;
}

