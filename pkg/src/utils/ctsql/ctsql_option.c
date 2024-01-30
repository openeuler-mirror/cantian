// Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.

#include "ctsql_option.h"
#include "ctsql_export.h"
#include "cm_lex.h"

static void ctsql_set_autocommit(text_t *value);
static void ctsql_set_exitcommit(text_t *value);
static void ctsql_set_charset(text_t *value);
static void ctsql_set_heading(text_t *value);
static void ctsql_set_serverouput(text_t *value);
static void ctsql_set_trimspool(text_t *value);
static void ctsql_set_linesize(text_t *value);
static void ctsql_set_longsize(text_t *value);
static void ctsql_set_numwidth(text_t *value);
static void ctsql_set_pagesize(text_t *value);
static void ctsql_set_timing(text_t *value);
static void ctsql_set_feedback(text_t *value);
static void ctsql_set_define_on(text_t *value);
static void ctsql_set_oplog(text_t *value);
static void ctsql_set_connect_timeout(text_t *value);
static void ctsql_set_socket_timeout(text_t *value);
static void ctsql_set_scriptoutput(text_t *value);
static void ctsql_set_verify_on(text_t *value);
static void ctsql_set_termout_on(text_t *value);
static void ctsql_set_newpage(text_t *value);
static void ctsql_set_colsep(text_t *value);
static void ctsql_set_ssl_mode(text_t *value);
static void ctsql_set_ssl_ca_file(text_t *value);
static void ctsql_set_ssl_cert_file(text_t *value);
static void ctsql_set_ssl_key_file(text_t *value);
static void ctsql_set_ssl_crl_file(text_t *value);
static void ctsql_set_ssl_key_passwd(text_t *value);
static void ctsql_set_ssl_cipher(text_t *value);
static void ctsql_set_uds_clt_path(text_t *value);
static void ctsql_set_uds_srv_path(text_t *value);
static void ctsql_set_bindparam_force_on(text_t *value);
static void ctsql_set_shd_rw_split(text_t *value);
static void ctsql_set_history(text_t *value);
static void ctsql_set_autotrace(text_t *value);

static bool8 ctsql_show_autocommit(const text_t *value);
static bool8 ctsql_show_exitcommit(const text_t *value);
static bool8 ctsql_show_charset(const text_t *value);
static bool8 ctsql_show_heading(const text_t *value);
static bool8 ctsql_show_serverouput(const text_t *value);
static bool8 ctsql_show_trimspool(const text_t *value);
static bool8 ctsql_show_spool(const text_t *value);
static bool8 ctsql_show_linesize(const text_t *value);
static bool8 ctsql_show_longsize(const text_t *value);
static bool8 ctsql_show_numwidth(const text_t *value);
static bool8 ctsql_show_pagesize(const text_t *value);
static bool8 ctsql_show_timing(const text_t *value);
static bool8 ctsql_show_feedback(const text_t *value);
static bool8 ctsql_show_define_on(const text_t *value);
static bool8 ctsql_show_oplog(const text_t *value);
static bool8 ctsql_show_connect_timeout(const text_t *value);
static bool8 ctsql_show_socket_timeout(const text_t *value);
static bool8 ctsql_show_scriptoutput(const text_t *value);
static bool8 ctsql_show_verify_on(const text_t *value);
static bool8 ctsql_show_termout_on(const text_t *value);
static bool8 ctsql_show_newpage(const text_t *value);
static bool8 ctsql_show_colsep(const text_t *value);
static bool8 ctsql_show_ssl_mode(const text_t *value);
static bool8 ctsql_show_ssl_ca_file(const text_t *value);
static bool8 ctsql_show_ssl_cert_file(const text_t *value);
static bool8 ctsql_show_ssl_key_file(const text_t *value);
static bool8 ctsql_show_ssl_crl_file(const text_t *value);
static bool8 ctsql_show_ssl_key_passwd(const text_t *value);
static bool8 ctsql_show_ssl_cipher(const text_t *value);
static bool8 ctsql_show_uds_clt_path(const text_t *value);
static bool8 ctsql_show_uds_srv_path(const text_t *value);
static bool8 ctsql_show_bindparam_force_on(const text_t *value);
static bool8 ctsql_show_shd_rw_split(const text_t *value);
static bool8 ctsql_show_history(const text_t *value);
static bool8 ctsql_show_autotrace(const text_t *value);
static bool8 ctsql_show_create_opt(const text_t *value);
static bool8 ctsql_show_tenant_opt(const text_t *value);
static bool8 ctsql_show_parameters_opt(const text_t *value);
static const char *g_ssl_mode_txt_list[] = { "DISABLED", "PREFERRED", "REQUIRED", "VERIFY_CA", "VERIFY_FULL" };
static const uint32 g_ssl_mode_count = sizeof(g_ssl_mode_txt_list) / sizeof(g_ssl_mode_txt_list[0]);

typedef void (*ctsql_set_attr)(text_t *value);
typedef bool8 (*ctsql_show_attr)(const text_t *value);
typedef bool32 (*ctsql_opt_match_func)(const text_t *text, const char *str, const uint32 less_len);

#define CTSQL_MAX_OPTION_NAME (uint32)32
#define CT_MAX_CHARSET_NAME  (uint32)64

typedef struct st_ctsql_option {
    char name[CTSQL_MAX_OPTION_NAME];
    uint32 set_less_len;
    ctsql_set_attr set_att_func;
    uint32 show_less_len;
    ctsql_show_attr show_att_func;
    ctsql_opt_match_func match_func;
} ctsql_option_t;

static ctsql_option_t g_options[] = {
    { "AUTOCOMMIT", 4, ctsql_set_autocommit, 4, ctsql_show_autocommit, cm_text_str_less_equal_ins },
    { "EXITCOMMIT", 5, ctsql_set_exitcommit, 5, ctsql_show_exitcommit, cm_text_str_less_equal_ins },
    { "CHARSET", 7, ctsql_set_charset, 7, ctsql_show_charset, cm_text_str_less_equal_ins },
    { "HEADING", 3, ctsql_set_heading, 3, ctsql_show_heading, cm_text_str_less_equal_ins },
    { "SERVEROUTPUT", 9, ctsql_set_serverouput, 9, ctsql_show_serverouput, cm_text_str_less_equal_ins },
    { "TRIMSPOOL", 5, ctsql_set_trimspool, 5, ctsql_show_trimspool, cm_text_str_less_equal_ins },
    { "SPOOL", 4, NULL, 4, ctsql_show_spool, cm_text_str_less_equal_ins },
    { "LINESIZE", 3, ctsql_set_linesize, 3, ctsql_show_linesize, cm_text_str_less_equal_ins },
    { "NUMWIDTH", 3, ctsql_set_numwidth, 3, ctsql_show_numwidth, cm_text_str_less_equal_ins },
    { "PAGESIZE", 5, ctsql_set_pagesize, 5, ctsql_show_pagesize, cm_text_str_less_equal_ins },
    { "TIMING", 3, ctsql_set_timing, 3, ctsql_show_timing, cm_text_str_less_equal_ins },
    { "FEEDBACK", 4, ctsql_set_feedback, 4, ctsql_show_feedback, cm_text_str_less_equal_ins },
    { "PARAMETERS", 10, NULL, 9, ctsql_show_parameters_opt, cm_text_str_contain_equal_ins },
    { "LONG", 4, ctsql_set_longsize, 4, ctsql_show_longsize, cm_text_str_less_equal_ins },
    { "COLSEP", 6, ctsql_set_colsep, 6, ctsql_show_colsep, cm_text_str_less_equal_ins },
    { "NEWPAGE", 4, ctsql_set_newpage, 4, ctsql_show_newpage, cm_text_str_less_equal_ins },
    { "VERIFY", 3, ctsql_set_verify_on, 3, ctsql_show_verify_on, cm_text_str_less_equal_ins },
    { "TERMOUT", 4, ctsql_set_termout_on, 4, ctsql_show_termout_on, cm_text_str_less_equal_ins },
    { "DEFINE", 6, ctsql_set_define_on, 6, ctsql_show_define_on, cm_text_str_less_equal_ins },
    { "ECHO", 4, ctsql_set_scriptoutput, 4, ctsql_show_scriptoutput, cm_text_str_less_equal_ins },
    { "OPLOG", 5, ctsql_set_oplog, 5, ctsql_show_oplog, cm_text_str_less_equal_ins },
    { "CONNECT_TIMEOUT", 7, ctsql_set_connect_timeout, 7, ctsql_show_connect_timeout, cm_text_str_less_equal_ins },
    { "SOCKET_TIMEOUT", 6, ctsql_set_socket_timeout, 6, ctsql_show_socket_timeout, cm_text_str_less_equal_ins },
    { "CTSQL_SSL_MODE", 13, ctsql_set_ssl_mode, 3, ctsql_show_ssl_mode, cm_text_str_less_equal_ins },
    { "CTSQL_SSL_CA", 11, ctsql_set_ssl_ca_file, 3, ctsql_show_ssl_ca_file, cm_text_str_less_equal_ins },
    { "CTSQL_SSL_CERT", 13, ctsql_set_ssl_cert_file, 3, ctsql_show_ssl_cert_file, cm_text_str_less_equal_ins },
    { "CTSQL_SSL_KEY", 12, ctsql_set_ssl_key_file, 3, ctsql_show_ssl_key_file, cm_text_str_less_equal_ins },
    { "CTSQL_SSL_CRL", 12, ctsql_set_ssl_crl_file, 3, ctsql_show_ssl_crl_file, cm_text_str_less_equal_ins },
    { "CTSQL_SSL_KEY_PASSWD", 19, ctsql_set_ssl_key_passwd, 3, ctsql_show_ssl_key_passwd, cm_text_str_less_equal_ins },
    { "CTSQL_SSL_CIPHER", 15, ctsql_set_ssl_cipher, 3, ctsql_show_ssl_cipher, cm_text_str_less_equal_ins },
    { "UDS_SERVER_PATH", 15, ctsql_set_uds_srv_path, 15, ctsql_show_uds_srv_path, cm_text_str_less_equal_ins },
    { "UDS_CLIENT_PATH", 15, ctsql_set_uds_clt_path, 15, ctsql_show_uds_clt_path, cm_text_str_less_equal_ins },
    { "BIND", 4, ctsql_set_bindparam_force_on, 4, ctsql_show_bindparam_force_on, cm_text_str_less_equal_ins },
    { "SHARD_RW_FLAG", 13, ctsql_set_shd_rw_split, 13, ctsql_show_shd_rw_split, cm_text_str_less_equal_ins },
    { "CREATE", 6, NULL, 6, ctsql_show_create_opt, cm_text_str_contain_equal_ins },
    { "HISTORY", 4, ctsql_set_history, 4, ctsql_show_history, cm_text_str_less_equal_ins },
    { "AUTOTRACE", 9, ctsql_set_autotrace, 9, ctsql_show_autotrace, cm_text_str_less_equal_ins },
    { "TENANT_NAME", 11, NULL, 11, ctsql_show_tenant_opt, cm_text_str_less_equal_ins },
    { "TENANT_ID", 9, NULL, 9, ctsql_show_tenant_opt, cm_text_str_less_equal_ins }
};

typedef enum en_ctsql_option_id {
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
} ctsql_option_id_t;

#define CTSQL_OPTION_COUNT (sizeof(g_options) / sizeof(ctsql_option_t))

static void ctsql_display_set_usage(void)
{
    ctsql_printf("Usage:\n");
    ctsql_printf("SET AUTO[COMMIT] {ON|OFF}\n");
    ctsql_printf("SET EXITC[OMMIT] {ON|OFF}\n");
    ctsql_printf("SET CHARSET {GBK|UTF8}\n");
    ctsql_printf("SET HEA[DING] {ON|OFF}\n");
    ctsql_printf("SET SERVEROUT[PUT] {ON|OFF}\n");
    ctsql_printf("SET TRIMS[POOOL] {ON|OFF}\n");
    ctsql_printf("SET LIN[ESIZE] {80|n}\n");
    ctsql_printf("SET NUM[WIDTH] {10|n}\n");
    ctsql_printf("SET PAGES[IZE] {14|n}\n");
    ctsql_printf("SET TIM[ING] {ON|OFF}\n");
    ctsql_printf("SET FEED[BACK] {n|ON|OFF}\n");
    ctsql_printf("SET ECHO {ON|OFF}\n");
    ctsql_printf("SET VER[IFY] {ON|OFF}\n");
    ctsql_printf("SET TERM[OUT] {ON|OFF}\n");
    ctsql_printf("SET NEWP[AGE] {1|n|NONE}\n");
    ctsql_printf("SET COLSEP {'text'|\"text\"|text}\n");
    ctsql_printf("SET LONG {n}\n");
    ctsql_printf("SET DEFINE {ON|OFF|ONE CHAR}\n");
    ctsql_printf("SET OPLOG {ON|OFF}\n");
    ctsql_printf("SET CONNECT[_TIMEOUT] {-1|n}\n");
    ctsql_printf("SET SOCKET[_TIMEOUT] {-1|n}\n");
    ctsql_printf("SET CTSQL_SSL_CA [=] {ca_file_path}\n");
    ctsql_printf("SET CTSQL_SSL_CERT [=] {cert_file_path}\n");
    ctsql_printf("SET CTSQL_SSL_KEY [=] {key_file_path}\n");
    ctsql_printf("SET CTSQL_SSL_MODE [=] {DISABLED|PREFERRED|REQUIRED|VERIFY_CA|VERIFY_FULL}\n");
    ctsql_printf("SET CTSQL_SSL_CRL [=] {crl_file_path}\n");
    ctsql_printf("SET CTSQL_SSL_KEY_PASSWD [=] {ssl_keypwd}\n");
    ctsql_printf("SET CTSQL_SSL_CIPHER [=] {ssl_cipher}\n");
    ctsql_printf("SET UDS_SERVER_PATH [=] {path}\n");
    ctsql_printf("SET UDS_CLIENT_PATH [=] {path}\n");
    ctsql_printf("SET BIND {ON|OFF}\n");
    ctsql_printf("SET SHARD_RW_FLAG {0|1|2|3}\n");
    ctsql_printf("SET HIST[ORY] {ON|OFF}\n");
    ctsql_printf("SET AUTOTRACE {ON|OFF|TRACEONLY}\n");
}

static bool32 is_match_suffix(const char *str, const char *suffix)
{
    uint32 len = (uint32)strlen(suffix);
    int32 offset = (int32)(strlen(str) - len);
    if (offset <= 0) {
        return CT_FALSE;
    }

    return cm_str_equal(str + offset, suffix) ? CT_TRUE : CT_FALSE;
}

static status_t ctsql_check_ssl_file(uint32 opt, const char *env_val, char *path, uint32 path_len)
{
    CT_RETURN_IFERR(realpath_file(env_val, path, path_len));

    if (opt == OPT_SSL_CA || opt == OPT_SSL_CERT) {
        if (!MATCH_CRT_CER_PEM(path)) {
            CT_THROW_ERROR(ERR_PATH_NOT_ALLOWED_TO_ACCESS, path);
            return CT_ERROR;
        }
    } else if (opt == OPT_SSL_KEY) {
        if (!MATCH_KEY_PEM(path)) {
            CT_THROW_ERROR(ERR_PATH_NOT_ALLOWED_TO_ACCESS, path);
            return CT_ERROR;
        }
    } else if (opt == OPT_SSL_CRL) {
        if (!MATCH_CRL_PEM(path)) {
            CT_THROW_ERROR(ERR_PATH_NOT_ALLOWED_TO_ACCESS, path);
            return CT_ERROR;
        }
    } else {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void ctsql_init_ssl_config(void)
{
    char *env_val = NULL;
    char path[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    errno_t errcode;

    env_val = getenv(g_options[OPT_SSL_CA].name);
    if (!CM_IS_EMPTY_STR(env_val)) {
        if (ctsql_check_ssl_file(OPT_SSL_CA, env_val, path, CT_FILE_NAME_BUFFER_SIZE) == CT_SUCCESS) {
            errcode = strncpy_s(g_local_config.ssl_ca, CT_FILE_NAME_BUFFER_SIZE, path, strlen(path));
            if (errcode != EOK) {
                // reset config if error occurs
                CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
                g_local_config.ssl_ca[0] = '\0';
            }
        }
    }

    env_val = getenv(g_options[OPT_SSL_CERT].name);
    if (!CM_IS_EMPTY_STR(env_val)) {
        if (ctsql_check_ssl_file(OPT_SSL_CERT, env_val, path, CT_FILE_NAME_BUFFER_SIZE) == CT_SUCCESS) {
            errcode = strncpy_s(g_local_config.ssl_cert, CT_FILE_NAME_BUFFER_SIZE, path, strlen(path));
            if (errcode != EOK) {
                // reset config if error occurs
                CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
                g_local_config.ssl_cert[0] = '\0';
            }
        }
    }

    env_val = getenv(g_options[OPT_SSL_KEY].name);
    if (!CM_IS_EMPTY_STR(env_val)) {
        if (ctsql_check_ssl_file(OPT_SSL_KEY, env_val, path, CT_FILE_NAME_BUFFER_SIZE) == CT_SUCCESS) {
            errcode = strncpy_s(g_local_config.ssl_key, CT_FILE_NAME_BUFFER_SIZE, path, strlen(path));
            if (errcode != EOK) {
                // reset config if error occurs
                CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
                g_local_config.ssl_key[0] = '\0';
            }
        }
    }

    env_val = getenv(g_options[OPT_SSL_KEYPWD].name);
    if (!CM_IS_EMPTY_STR(env_val)) {
        errcode = strncpy_s(g_local_config.ssl_keypwd, sizeof(g_local_config.ssl_keypwd), env_val, strlen(env_val));
        if (errcode != EOK) {
            // reset config if error occurs
            CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
            g_local_config.ssl_keypwd[0] = '\0';
        }
    }

    env_val = getenv(g_options[OPT_SSL_CRL].name);
    if (!CM_IS_EMPTY_STR(env_val)) {
        if (ctsql_check_ssl_file(OPT_SSL_CRL, env_val, path, CT_FILE_NAME_BUFFER_SIZE) == CT_SUCCESS) {
            errcode = strncpy_s(g_local_config.ssl_crl, CT_FILE_NAME_BUFFER_SIZE, path, strlen(path));
            if (errcode != EOK) {
                // reset config if error occurs
                CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
                g_local_config.ssl_crl[0] = '\0';
            }
        }
    }

    env_val = getenv(g_options[OPT_SSL_CIPHER].name);
    if (!CM_IS_EMPTY_STR(env_val)) {
        errcode = strncpy_s(g_local_config.ssl_cipher, CT_PARAM_BUFFER_SIZE, env_val, CT_PARAM_BUFFER_SIZE - 1);
        if (errcode != EOK) {
            // reset config if error occurs
            CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
            g_local_config.ssl_cipher[0] = '\0';
        }
    }

    env_val = getenv(g_options[OPT_SSL_MODE].name);
    if (!CM_IS_EMPTY_STR(env_val)) {
        for (uint32 i = 0; i < g_ssl_mode_count; ++i) {
            if (cm_str_equal_ins(env_val, g_ssl_mode_txt_list[i])) {
                g_local_config.ssl_mode = (ctconn_ssl_mode_t)i;
                break;
            }
        }
    }
}

static uint32 ctsql_get_on_off(text_t *value)
{
    if (cm_text_str_equal_ins(value, "ON")) {
        return CT_TRUE;
    } else if (cm_text_str_equal_ins(value, "OFF")) {
        return CT_FALSE;
    } else {
        return CT_INVALID_ID32;
    }
}

static void ctsql_set_autocommit(text_t *value)
{
    uint32 autocommit = ctsql_get_on_off(value);
    if (autocommit == CT_INVALID_ID32) {
        ctsql_printf("unknown set autocommit option.\n");
        ctsql_printf("Usage: SET AUTO[COMMIT] {ON|OFF}.\n");
        return;
    }

    g_local_config.auto_commit = autocommit;
    ctconn_set_autocommit(CONN, autocommit);
    ctsql_printf((autocommit == CT_TRUE) ? "ON" : "OFF");
}

static void ctsql_set_exitcommit(text_t *value)
{
    uint32 exitcommit = ctsql_get_on_off(value);
    if (exitcommit == CT_INVALID_ID32) {
        ctsql_printf("unknown set exitcommit option.\n");
        ctsql_printf("Usage: SET EXITC[OMMIT] {ON|OFF}.\n");
        return;
    }

    g_local_config.exit_commit = exitcommit;
    (void)ctconn_set_conn_attr(CONN, CTCONN_ATTR_EXIT_COMMIT, &exitcommit, sizeof(uint32));
    ctsql_printf((exitcommit == CT_TRUE) ? "ON" : "OFF");
}

static void ctsql_set_charset(text_t *value)
{
    if (value->len >= CT_MAX_CHARSET_NAME) {
        ctsql_printf("len of charset to set exceed maxsize(%u).\n", CT_MAX_CHARSET_NAME);
        return;
    }

    CM_NULL_TERM(value);

    uint16 charset_id = cm_get_charset_id((const char *)value->str);
    if (charset_id == CT_INVALID_ID16) {
        ctsql_printf("unknown charset option %s.\n", value->str);
        ctsql_printf("Usage: SET CHARSET {GBK|UTF8}.\n");
        return;
    }

    g_local_config.charset_id = charset_id;
    (void)ctconn_set_conn_attr(CONN, CTCONN_ATTR_CHARSET_TYPE, value->str, value->len);
    ctsql_printf("%s", (char *)cm_get_charset_name((charset_type_t)charset_id));
}

static void ctsql_set_history(text_t *value)
{
    uint32 history = ctsql_get_on_off(value);
    if (history == CT_INVALID_ID32) {
        ctsql_printf("unknown set history option.\n");
        ctsql_printf("Usage: SET HIST[ORY] {ON|OFF}.\n");
        return;
    }

    g_local_config.history_on = history;
    ctsql_printf((history == CT_TRUE) ? "ON" : "OFF");
}

static void ctsql_set_heading(text_t *value)
{
    uint32 heading_on = ctsql_get_on_off(value);
    if (heading_on == CT_INVALID_ID32) {
        ctsql_printf("unknown set heading option.\n");
        ctsql_printf("Usage: SET HEA[DING] {ON|OFF}.\n");
        return;
    }

    g_local_config.heading_on = heading_on;
    ctsql_printf((heading_on == CT_TRUE) ? "ON" : "OFF");
}

static void ctsql_set_serverouput(text_t *value)
{
    uint32 serverouput_on = ctsql_get_on_off(value);
    if (serverouput_on == CT_INVALID_ID32) {
        ctsql_printf("unknown set serverouput option.\n");
        ctsql_printf("Usage: SET SERVEROUT[PUT] {ON|OFF}.\n");
        return;
    }

    g_local_config.server_ouput = serverouput_on;
    (void)ctconn_set_conn_attr(CONN, CTCONN_ATTR_SERVEROUTPUT, &serverouput_on, sizeof(uint32));
    ctsql_printf((serverouput_on == CT_TRUE) ? "ON" : "OFF");
}

static void ctsql_set_trimspool(text_t *value)
{
    uint32 trimspool_on = ctsql_get_on_off(value);
    if (trimspool_on == CT_INVALID_ID32) {
        ctsql_printf("unknown set trimspool option.\n");
        ctsql_printf("Usage: SET TRIMS[POOL] {ON|OFF}.\n");
        return;
    }

    g_local_config.trim_spool = trimspool_on;
    ctsql_printf((trimspool_on == CT_TRUE) ? "ON" : "OFF");
}

static void ctsql_set_linesize(text_t *value)
{
    uint32 line_size;

    if (cm_text2uint32(value, &line_size) != CT_SUCCESS) {
        ctsql_printf("linesize option not a valid number.\n");
        return;
    }

    g_local_config.line_size = line_size;
}

static void ctsql_set_longsize(text_t *value)
{
    uint32 long_size;

    if (cm_text2uint32(value, &long_size) != CT_SUCCESS) {
        ctsql_printf("long_size option not a valid number.\n");
        return;
    }

    g_local_config.long_size = long_size;
}

static void ctsql_set_numwidth(text_t *value)
{
    uint32 num_width;

    if (cm_text2uint32(value, &num_width) != CT_SUCCESS) {
        ctsql_printf("numwidth option not a valid number.\n");
        return;
    }

    if (ctconn_set_conn_attr(CONN, CTCONN_ATTR_NUM_WIDTH, &num_width, sizeof(uint32)) != CTCONN_SUCCESS) {
        ctsql_print_error(CONN);
        return;
    }
}

static void ctsql_set_pagesize(text_t *value)
{
    uint32 page_size = 0;

    if (cm_text2uint32(value, &page_size) != CT_SUCCESS) {
        ctsql_printf("pagesize option not a valid number.\n");
        return;
    }

    if (page_size != 0 && page_size < CT_MIN_PAGESIZE) {
        ctsql_printf("pagesize option %u must large than %u (0 means display all rows in one page).\n", page_size,
                    CT_MIN_PAGESIZE);
        return;
    }

    g_local_config.page_size = (page_size == 0) ? CT_INVALID_INT32 : page_size;
}

static void ctsql_set_timing(text_t *value)
{
    uint32 timing_on = ctsql_get_on_off(value);
    if (timing_on == CT_INVALID_ID32) {
        ctsql_printf("unknown set timing option.\n");
        ctsql_printf("Usage: SET TIM[ING] {ON|OFF}.\n");
        return;
    }

    g_local_config.timer.timing_on = timing_on;
    ctsql_printf((timing_on == CT_TRUE) ? "ON" : "OFF");
}

static const char *g_trace_value_list[] = { "OFF", "ON", "TRACEONLY" };

static void ctsql_set_autotrace(text_t *value)
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
        ctsql_printf("unknown set autotrace option.\n");
        ctsql_printf("Usage: SET AUTOTRACE {ON|OFF|TRACEONLY}.\n");
        return;
    }
    (void)ctconn_set_conn_attr(CONN, CTCONN_ATTR_AUTOTRACE, &i, sizeof(uint32));
    ctsql_printf("%s", (char *)g_trace_value_list[i]);
}

static void ctsql_set_feedback(text_t *value)
{
    uint32 feedback_on = ctsql_get_on_off(value);
    if (feedback_on != CT_INVALID_ID32) {
        g_local_config.feedback.feedback_on = feedback_on;
        ctsql_printf((feedback_on == CT_TRUE) ? "ON" : "OFF");
        if (feedback_on == CT_TRUE) {
            g_local_config.feedback.feedback_rows = 1;
        } else {
            g_local_config.feedback.feedback_rows = 0;
        }
    } else {
        if (cm_text2uint32(value, &g_local_config.feedback.feedback_rows) != CT_SUCCESS) {
            ctsql_printf("Feedback row option is not a valid number.\n");
            ctsql_printf("Usage: SET FEEDBACK {ON|OFF|n}.\n");
            return;
        }
        if (g_local_config.feedback.feedback_rows == 0) {
            g_local_config.feedback.feedback_on = CT_FALSE;
            ctsql_printf("Feedback is OFF.\n");
        } else {
            g_local_config.feedback.feedback_on = CT_TRUE;
            ctsql_printf("Feedback is ON, and feedback row is %u.\n", g_local_config.feedback.feedback_rows);
        }
    }
    return;
}

static void ctsql_set_define_on(text_t *value)
{
    uint32 define_on = ctsql_get_on_off(value);
    if (define_on == CT_INVALID_ID32 && value->len > 1) {
        ctsql_printf("unknown set define_on option.\n");
        ctsql_printf("Usage: SET DEFINE {ON|OFF|one char}.\n");
        return;
    }

    g_local_config.define_on = define_on;
    if (define_on == CT_INVALID_ID32) {
        g_replace_mark = value->str[0];
        g_local_config.define_on = CT_TRUE;
    }

    ctsql_printf((define_on == CT_FALSE) ? "OFF" : "ON");
}

static void ctsql_set_oplog(text_t *value)
{
    uint32 oplog_on = ctsql_get_on_off(value);
    if (oplog_on == CT_INVALID_ID32) {
        ctsql_printf("unknown set oplog option.\n");
        ctsql_printf("Usage: SET OPLOG {ON|OFF}.\n");
    } else {
        ctsql_printf((oplog_on == CT_TRUE) ? "ON" : "OFF");
        if (oplog_on == CT_TRUE) {
            cm_log_param_instance()->log_level |= 0x00000200;
        } else {
            cm_log_param_instance()->log_level &= !(0x00000200);
        }
    }
}

static void ctsql_set_connect_timeout(text_t *value)
{
    int32 connect_timeout = 0;

    if (cm_text2int(value, &connect_timeout) != CT_SUCCESS) {
        ctsql_printf("connect_timeout option not a valid number.\n");
        return;
    }

    if (connect_timeout < -1) {
        ctsql_printf("connect_timeout option must be -1 or positive number.\n");
        return;
    }

    if (ctconn_set_conn_attr(CONN, CTCONN_ATTR_CONNECT_TIMEOUT, &connect_timeout, sizeof(int32)) != CTCONN_SUCCESS) {
        ctsql_print_error(CONN);
        return;
    }
    g_local_config.connect_timeout = connect_timeout;
}

static void ctsql_set_socket_timeout(text_t *value)
{
    int32 socket_timeout = 0;

    if (cm_text2int(value, &socket_timeout) != CT_SUCCESS) {
        ctsql_printf("socket_timeout option not a valid number.\n");
        return;
    }

    if (socket_timeout < -1) {
        ctsql_printf("socket_timeout option must be -1 or positive number.\n");
        return;
    }

    if (ctconn_set_conn_attr(CONN, CTCONN_ATTR_SOCKET_TIMEOUT, &socket_timeout, sizeof(int32)) != CTCONN_SUCCESS) {
        ctsql_print_error(CONN);
        return;
    }
    g_local_config.socket_timeout = socket_timeout;
}

static void ctsql_set_scriptoutput(text_t *value)
{
    uint32 script_output = ctsql_get_on_off(value);
    if (script_output == CT_INVALID_ID32) {
        ctsql_printf("unknown set echo option.\n");
        ctsql_printf("Usage: SET ECHO {ON|OFF}.\n");
        return;
    }

    g_local_config.script_output = script_output;
    ctsql_printf((script_output == CT_TRUE) ? "ON" : "OFF");
}

static void ctsql_set_verify_on(text_t *value)
{
    uint32 verify_on = ctsql_get_on_off(value);
    if (verify_on == CT_INVALID_ID32) {
        ctsql_printf("unknown set verify option.\n");
        ctsql_printf("Usage: SET VERIFY {ON|OFF}.\n");
        return;
    }

    g_local_config.verify_on = verify_on;
    ctsql_printf((verify_on == CT_TRUE) ? "ON" : "OFF");
}

static void ctsql_set_termout_on(text_t *value)
{
    uint32 termout_on = ctsql_get_on_off(value);
    if (termout_on == CT_INVALID_ID32) {
        ctsql_printf("unknown set termout option.\n");
        ctsql_printf("Usage: SET TERM[OUT] {ON|OFF}.\n");
        return;
    }

    if (termout_on == CT_TRUE) {
        g_local_config.termout_on = CT_FALSE;  // reuse g_local_config.slient_on, CT_FALSE means on
    } else {
        g_local_config.termout_on = CT_TRUE;
    }

    if (g_is_print == CT_TRUE) {  // set term on in sql script
        g_local_config.silent_on = g_local_config.termout_on;
    }
}

static void ctsql_set_newpage(text_t *value)
{
    uint32 newpage;
    if (cm_text_str_equal_ins(value, "NONE")) {
        newpage = 0;
    } else if (cm_text2uint32(value, &newpage) != CT_SUCCESS) {
        ctsql_printf("unknown set newpage option.\n");
        ctsql_printf("Usage: SET NEWP[AGE] {1|n|none}.\n");
        return;
    }

    if (newpage > 999) {
        ctsql_printf("Newpage option %u out of range(0~999)", newpage);
        return;
    }

    g_local_config.newpage = newpage;
}

static void ctsql_set_colsep(text_t *value)
{
    char buf[CT_BUFLEN_256] = { 0 };
    cm_trim_text(value);
    value->str[value->len] = '\0';
    int32 code;

    if (value->len > CT_BUFLEN_256 - 1 || value->len < 1) {
        ctsql_printf("Length of colsep string is %u, it is out of range [1~255]\n", value->len);
        return;
    }

    if (value->str[0] == '\'' && (value->str[value->len - 1] != '\'' || value->len == 1)) {
        ctsql_printf("String \"%s\" missing terminating quote (')\n", value->str);
        ctsql_printf("Usage: SET colsep {'text'|\"text\"|text}.\n");
        return;
    }

    if (value->str[0] == '"' && (value->str[value->len - 1] != '"' || value->len == 1)) {
        ctsql_printf("String \"%s\" missing terminating quote (\")\n", value->str);
        ctsql_printf("Usage: SET colsep {'text'|\"text\"|text}.\n");
        return;
    }

    if (CT_SUCCESS != cm_text2str(value, buf, CT_BUFLEN_256)) {
        ctsql_printf("SET colsep: failed to convert text to str.\n");
        return;
    }

    if (buf[0] == '"' || buf[0] == '\'') {
        if (strlen(buf) > 2) {
            code = memcpy_s(g_local_config.colsep.colsep_name, MAX_COLSEP_NAME_LEN, buf + 1, strlen(buf) - 2);
            if (code != EOK) {
                ctsql_printf("SET colsep: secure C lib has thrown an error %d.\n", code);
                return;
            }
        }
        g_local_config.colsep.colsep_name[strlen(buf) - 2] = '\0';
    } else {
        if (strlen(buf) != 0) {
            code = memcpy_s(g_local_config.colsep.colsep_name, MAX_COLSEP_NAME_LEN, buf, strlen(buf));
            if (code != EOK) {
                ctsql_printf("SET colsep: secure C lib has thrown an error %d.\n", code);
                return;
            }
        }
        g_local_config.colsep.colsep_name[strlen(buf)] = '\0';
    }
    return;
}

static void ctsql_set_ssl_mode(text_t *value)
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
            g_local_config.ssl_mode = (ctconn_ssl_mode_t)i;
            break;
        }
    }

    if (i >= g_ssl_mode_count) {
        ctsql_printf("unknown set ctsql_ssl_mode option.\n");
        ctsql_printf("Usage: SET CTSQL_SSL_MODE [=] {DISABLED|PREFERRED|REQUIRED|VERIFY_CA|VERIFY_FULL}.\n");
        return;
    }
    ctsql_printf("CTSQL_SSL_MODE = %s\n", g_ssl_mode_txt_list[i]);
}

static int32 ctsql_read_file_param(text_t *value, char *buf, uint32 len)
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
            ctsql_printf("length of file name '%s' exceeds the maximum(%u)\n", T2S(value), len - 1);
            return CT_ERROR;
        }
        CT_RETURN_IFERR(cm_text2str(value, buf, len));

        if (!cm_file_exist(buf) || cm_access_file(buf, R_OK) != CT_SUCCESS) {
            ctsql_printf("file '%s' not exist\n", buf);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

static void ctsql_set_ssl_ca_file(text_t *value)
{
    char filepath[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    errno_t errcode;
    if (CT_SUCCESS != ctsql_read_file_param(value, filepath, sizeof(filepath))) {
        return;
    }
    errcode = strncpy_s(g_local_config.ssl_ca, CT_FILE_NAME_BUFFER_SIZE, filepath, strlen(filepath));
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return;
    }
    ctsql_printf("CTSQL_SSL_CA = %s\n", CM_IS_EMPTY_STR(filepath) ? "<NULL>" : filepath);
}

static void ctsql_set_ssl_cert_file(text_t *value)
{
    char filepath[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    errno_t errcode;
    if (CT_SUCCESS != ctsql_read_file_param(value, filepath, sizeof(filepath))) {
        return;
    }
    errcode = strncpy_s(g_local_config.ssl_cert, CT_FILE_NAME_BUFFER_SIZE, filepath, strlen(filepath));
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return;
    }
    ctsql_printf("CTSQL_SSL_CERT = %s\n", CM_IS_EMPTY_STR(filepath) ? "<NULL>" : filepath);
}

static void ctsql_set_ssl_key_file(text_t *value)
{
    char filepath[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    errno_t errcode;
    if (CT_SUCCESS != ctsql_read_file_param(value, filepath, sizeof(filepath))) {
        return;
    }
    errcode = strncpy_s(g_local_config.ssl_key, CT_FILE_NAME_BUFFER_SIZE, filepath, strlen(filepath));
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return;
    }
    ctsql_printf("CTSQL_SSL_KEY = %s\n", CM_IS_EMPTY_STR(filepath) ? "<NULL>" : filepath);
}

static void ctsql_set_ssl_crl_file(text_t *value)
{
    char filepath[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    errno_t errcode;
    if (CT_SUCCESS != ctsql_read_file_param(value, filepath, sizeof(filepath))) {
        return;
    }
    errcode = strncpy_s(g_local_config.ssl_crl, CT_FILE_NAME_BUFFER_SIZE, filepath, strlen(filepath));
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return;
    }
    ctsql_printf("CTSQL_SSL_CRL = %s\n", CM_IS_EMPTY_STR(filepath) ? "<NULL>" : filepath);
}

static void ctsql_set_ssl_key_passwd(text_t *value)
{
    if (CM_IS_EMPTY(value) || cm_text_str_equal_ins(value, "null")) {
        g_local_config.ssl_keypwd[0] = '\0';
        ctsql_printf("CTSQL_SSL_KEY_PASSWD = <NULL>\n");
        return;
    }

    if (value->str[0] == '\'') {
        value->str++;
        value->len -= 2;
    }

    if (value->len > CT_MAX_CIPHER_LEN) {
        ctsql_printf("invalid key password, maximum length is %d\n", CT_MAX_CIPHER_LEN);
        return;
    }

    (void)cm_text2str(value, g_local_config.ssl_keypwd, sizeof(g_local_config.ssl_keypwd));
    ctsql_printf("CTSQL_SSL_KEY_PASSWD = %s\n", g_local_config.ssl_keypwd);
}

static void ctsql_set_ssl_cipher(text_t *value)
{
    if (CM_IS_EMPTY(value) || cm_text_str_equal_ins(value, "null")) {
        g_local_config.ssl_cipher[0] = '\0';
        ctsql_printf("CTSQL_SSL_CIPHER = <NULL>\n");
        return;
    }

    if (value->str[0] == '\'') {
        value->str++;
        value->len -= 2;
    }

    if (value->len > sizeof(g_local_config.ssl_cipher) - 1) {
        ctsql_printf("invalid cipher, maximum length is %zu\n", sizeof(g_local_config.ssl_cipher) - 1);
        return;
    }

    cm_text2str(value, g_local_config.ssl_cipher, sizeof(g_local_config.ssl_cipher));
    ctsql_printf("CTSQL_SSL_CIPHER = %s\n", g_local_config.ssl_cipher);
}

static void ctsql_set_uds_path(text_t *value, const char *option, char *path, uint32 len, bool32 is_server)
{
    /* uds client can set null */
    if (CM_IS_EMPTY(value) || cm_text_str_equal_ins(value, "null")) {
        if (!is_server) {
            path[0] = '\0';
        }
        ctsql_printf("%s = <NULL>\n", option);
        return;
    }

    if (value->len >= CT_UNIX_PATH_MAX) {
        ctsql_printf("%s len must less than %u \n", option, CT_UNIX_PATH_MAX);
        return;
    }
    if (value->str[value->len - 1] == '/') {
        ctsql_printf("%s needs to be a file\n", option);
        return;
    }

    char full_path[CT_UNIX_PATH_MAX];
    char dir_path[CT_UNIX_PATH_MAX];
    errno_t errcode;

    errcode = memcpy_sp(full_path, CT_UNIX_PATH_MAX, value->str, value->len);
    if (errcode != EOK) {
        ctsql_printf("Secure C lib has thrown an error %d", errcode);
        return;
    }

    full_path[value->len] = '\0';

    if (strlen(full_path) == 1 && full_path[0] == '.') {
        ctsql_printf("'%s' is invalid \n", full_path);
        return;
    }

    if (cm_check_exist_special_char(full_path, (uint32)strlen(full_path))) {
        ctsql_printf("'%s' is invalid \n", full_path);
        return;
    }

    char *temp_path = strrchr(full_path, '/');
    if (temp_path != NULL && strlen(temp_path) != strlen(full_path)) {
        if (strlen(temp_path) == 2 && temp_path[1] == '.') {
            ctsql_printf("'%s' is invalid \n", full_path);
            return;
        }
        errcode = memcpy_sp(dir_path, CT_UNIX_PATH_MAX, full_path, strlen(full_path) - strlen(temp_path));
        if (errcode != EOK) {
            ctsql_printf("Secure C lib has thrown an error %d", errcode);
            return;
        }

        dir_path[strlen(full_path) - strlen(temp_path)] = '\0';
        if (!cm_dir_exist((const char *)dir_path)) {
            ctsql_printf("Directory '%s' not exist\n", dir_path);
            return;
        }
        if (access(dir_path, W_OK | R_OK) != 0) {
            ctsql_printf("Directory '%s' is not a readable or writable folder\n", dir_path);
            return;
        }
    }

    (void)cm_text2str(value, path, len);

    ctsql_printf("%s = %s\n", option, path);
}

static void ctsql_set_uds_clt_path(text_t *value)
{
    ctsql_set_uds_path(value, "UDS_CLIENT_PATH", g_local_config.client_path, CT_UNIX_PATH_MAX, CT_FALSE);
}

static void ctsql_set_uds_srv_path(text_t *value)
{
    ctsql_set_uds_path(value, "UDS_SERVER_PATH", g_local_config.server_path, CT_UNIX_PATH_MAX, CT_TRUE);
}

static void ctsql_set_bindparam_force_on(text_t *value)
{
    uint32 bindparam_force_on = ctsql_get_on_off(value);
    if (bindparam_force_on == CT_INVALID_ID32) {
        ctsql_printf("unknown set bind  option.\n");
        ctsql_printf("Usage: SET bind {ON|OFF}, default OFF.\n");
        return;
    }

    if (bindparam_force_on == CT_TRUE) {
        g_local_config.bindparam_force_on = CT_TRUE;
    } else {
        g_local_config.bindparam_force_on = CT_FALSE;
    }
    ctsql_printf((bindparam_force_on == CT_TRUE) ? "ON" : "OFF");
}

static void ctsql_set_shd_rw_split(text_t *value)
{
    uint32 rw_split_flag;

    if (cm_text2uint32(value, &rw_split_flag) != CT_SUCCESS) {
        ctsql_printf("shard_rw_flag option not a valid number.\n");
        return;
    }

    if (rw_split_flag < CTCONN_SHD_RW_SPLIT_NONE || rw_split_flag > CTCONN_SHD_RW_SPLIT_ROA) {
        ctsql_printf("shard_rw_flag option not in [0,1,2,3].\n");
        return;
    }

    g_local_config.shd_rw_split = (uint8)rw_split_flag;

    ctconn_set_conn_attr(CONN, CTCONN_ATTR_SHD_RW_FLAG, &rw_split_flag, sizeof(uint8));
    ctsql_printf("%u", rw_split_flag);
}

status_t ctsql_set_option_value(text_t option, text_t value)
{
    for (uint32 opt_idx = OPT_AUTOCOMMIT; opt_idx < OPT_MAX; opt_idx++) {
        if (cm_text_str_less_equal_ins(&option, g_options[opt_idx].name, g_options[opt_idx].set_less_len)) {
            if (g_options[opt_idx].set_att_func != NULL) {
                g_options[opt_idx].set_att_func(&value);
                return CT_SUCCESS;
            } else {
                break;
            }
        }
    }

    return CT_ERROR;
}

status_t ctsql_set(text_t *line, text_t *params)
{
    text_t option, value;
    if (params->len == 0) {
        ctsql_printf("Set failed.\n\n");
        ctsql_display_set_usage();
        return CT_ERROR;
    }

    cm_trim_text(params);
    if (!cm_fetch_text(params, ' ', '\'', &option)) {
        ctsql_printf("Set failed.\n\n");
        ctsql_display_set_usage();
        return CT_ERROR;
    }
    if (CM_IS_EMPTY(params)) {
        *params = option;
        if (!cm_fetch_text(params, '=', '\'', &option)) {
            ctsql_printf("Set failed.\n\n");
            ctsql_display_set_usage();
            return CT_ERROR;
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
        ctsql_printf("Set failed.\n\n");
        ctsql_display_set_usage();
        return CT_ERROR;
    }

    if (CT_SUCCESS != ctsql_set_option_value(option, value)) {
        // DCL of set command
        return ctsql_set_trx_iso_level(line);
    }
    return CT_SUCCESS;
}

static void ctsql_display_show_usage(void)
{
    ctsql_printf("Usage:\n");
    ctsql_printf("SHOW AUTO[COMMIT]\n");
    ctsql_printf("SHOW EXITC[OMMIT]\n");
    ctsql_printf("SHOW CHARSET\n");
    ctsql_printf("SHOW HEA[DING]\n");
    ctsql_printf("SHOW SERVEROUT[PUT]\n");
    ctsql_printf("SHOW TRIMS[POOL]\n");
    ctsql_printf("SHOW SPOO[L]\n");
    ctsql_printf("SHOW LIN[ESIZE]\n");
    ctsql_printf("SHOW NUM[WIDTH]\n");
    ctsql_printf("SHOW PAGES[IZE]\n");
    ctsql_printf("SHOW TIM[ING]\n");
    ctsql_printf("SHOW FEED[BACK]\n");
    ctsql_printf("SHOW ECHO\n");
    ctsql_printf("SHOW VER[IFY]\n");
    ctsql_printf("SHOW TERM[OUT]\n");
    ctsql_printf("SHOW NEWP[AGE]\n");
    ctsql_printf("SHOW COLSEP\n");
    ctsql_printf("SHOW LONG\n");
    ctsql_printf("SHOW PARAMETER[S] [PARAMETER_NAME]\n");
    ctsql_printf("SHOW DEFINE\n");
    ctsql_printf("SHOW OPLOG\n");
    ctsql_printf("SHOW CONNECT[_TIMEOUT]\n");
    ctsql_printf("SHOW SOCKET[_TIMEOUT]\n");
    ctsql_printf("SHOW CTSQL_SSL[_MODE|_CA|_CERT|_KEY|_CRL|_KEY_PASSWD|_CIPHER]\n");
    ctsql_printf("SHOW UDS_SERVER_PATH\n");
    ctsql_printf("SHOW UDS_CLIENT_PATH\n");
    ctsql_printf("SHOW BIND\n");
    ctsql_printf("SHOW SHARD_RW_FLAG\n");
    ctsql_printf("SHOW HIST[ORY]\n");
    ctsql_printf("SHOW AUTOTRACE\n");
    ctsql_printf("SHOW TENANT_NAME\n");
    ctsql_printf("SHOW TENANT_ID\n");
    ctsql_printf("SHOW CREATE TABLE\n");
}

static void ctsql_print_parameters(text_t *params, text_t *base_sql, char *sql_select)
{
    uint32 affected_rows = 0;
    bool32 feedback_on = CT_FALSE;
    uint16 bind_size = 0;
    bool32 temp_trace = CTSQL_TRACE_OFF;

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
        (void)ctconn_set_conn_attr(CONN, CTCONN_ATTR_AUTOTRACE, &temp_trace, sizeof(uint32));
        if (ctsql_execute_sql() == CT_SUCCESS) {
            (void)ctconn_get_stmt_attr(STMT, CTCONN_ATTR_AFFECTED_ROWS, &affected_rows, sizeof(uint32), NULL);
            if (affected_rows > 0) {
                feedback_on = g_local_config.feedback.feedback_on;
                g_local_config.feedback.feedback_on = CT_FALSE;
                ctsql_print_result();
                g_local_config.feedback.feedback_on = feedback_on;
            }
        }
        (void)ctconn_set_conn_attr(CONN, CTCONN_ATTR_AUTOTRACE, &g_local_config.trace_mode, sizeof(uint32));
        g_sql_buf[0] = '\0';
    } else {
        bind_size = params->len;
        do {
            (void)ctconn_set_conn_attr(CONN, CTCONN_ATTR_AUTOTRACE, &temp_trace, sizeof(uint32));
            CT_BREAK_IF_ERROR(ctconn_prepare(STMT, sql_select));
            CT_BREAK_IF_ERROR(ctconn_bind_by_pos(STMT, 0, CTCONN_TYPE_CHAR, params->str, params->len, &bind_size));
            CT_BREAK_IF_ERROR(ctconn_execute(STMT));

            (void)ctconn_get_stmt_attr(STMT, CTCONN_ATTR_AFFECTED_ROWS, &affected_rows, sizeof(uint32), NULL);
            if (affected_rows > 0) {
                feedback_on = g_local_config.feedback.feedback_on;
                g_local_config.feedback.feedback_on = CT_FALSE;
                ctsql_print_result();
                g_local_config.feedback.feedback_on = feedback_on;
            }
            (void)ctconn_set_conn_attr(CONN, CTCONN_ATTR_AUTOTRACE, &g_local_config.trace_mode, sizeof(uint32));
            return;
        } while (0);
        (void)ctconn_set_conn_attr(CONN, CTCONN_ATTR_AUTOTRACE, &g_local_config.trace_mode, sizeof(uint32));
        ctsql_print_error(CONN);
        return;
    }
}

static void ctsql_show_parameters(text_t *params)
{
    text_t param_opt, base_sql;
    char *sql_select = NULL;

    if (!cm_fetch_text(params, ' ', '\0', &param_opt)) {
        return;
    }

    if (!IS_CONN) {
        CTSQL_PRINTF(ZSERR_CTSQL, "connection is not established");
        return;
    }

    if (ctconn_get_call_version(CONN) >= CTSQL_COPYRIGHT_VERSION) {
        base_sql.str = (char *)"select NAME, DATATYPE, VALUE, RUNTIME_VALUE, EFFECTIVE from DV_PARAMETERS";
        base_sql.len = (uint32)strlen(base_sql.str);
        sql_select = "select NAME, DATATYPE, VALUE, RUNTIME_VALUE, EFFECTIVE from DV_PARAMETERS where upper(NAME)"
            " like upper('%'|| :1 || '%') order by NAME";
    } else {
        base_sql.str = (char *)"select NAME, DATATYPE, VALUE, RUNTIME_VALUE, EFFECTIVE from V$PARAMETER";
        base_sql.len = (uint32)strlen(base_sql.str);
        sql_select = "select NAME, DATATYPE, VALUE, RUNTIME_VALUE, EFFECTIVE from V$PARAMETER where upper(NAME)"
            " like upper('%'|| :1 || '%') order by NAME";
    }

    cm_trim_text(params);

    // generate sql to get parameters and print them
    ctsql_print_parameters(params, &base_sql, sql_select);

    return;
}

static void ctsql_show_tenant(const text_t *params)
{
    text_t base_sql;
    uint32 affected_rows = 0;
    bool32 feedback_on = CT_FALSE;
    char sql_select[CT_BUFLEN_128];

    if (!IS_CONN) {
        CTSQL_PRINTF(ZSERR_CTSQL, "connection is not established");
        return;
    }

    if (cm_text_str_equal_ins(params, "TENANT_ID")) {
        PRTS_RETVOID_IFERR(
            sprintf_s(sql_select, CT_BUFLEN_128, "SELECT SYS_CONTEXT('USERENV', 'TENANT_ID') TENANT_ID"));
    } else if (cm_text_str_equal_ins(params, "TENANT_NAME")) {
        PRTS_RETVOID_IFERR(
            sprintf_s(sql_select, CT_BUFLEN_128, "SELECT SYS_CONTEXT('USERENV', 'TENANT_NAME') TENANT_NAME"));
    } else {
        CTSQL_PRINTF(ZSERR_CTSQL, "cmd error, please check cmd");
        return;
    }

    (void)cm_str2text_safe(sql_select, (uint32)strlen(sql_select), &base_sql);
    MEMS_RETVOID_IFERR(memcpy_s(g_sql_buf, MAX_SQL_SIZE, base_sql.str, base_sql.len));
    g_sql_buf[base_sql.len] = '\0';

    // output query result
    if (ctsql_execute_sql() == CT_SUCCESS) {
        (void)ctconn_get_stmt_attr(STMT, CTCONN_ATTR_AFFECTED_ROWS, &affected_rows, sizeof(uint32), NULL);
        if (affected_rows > 0) {
            feedback_on = g_local_config.feedback.feedback_on;
            g_local_config.feedback.feedback_on = CT_FALSE;
            ctsql_print_result();
            g_local_config.feedback.feedback_on = feedback_on;
        }
    }

    g_sql_buf[0] = '\0';
}

void ctsql_show(text_t *params)
{
    bool8 param_matched = CT_FALSE;

    cm_trim_text(params);

    for (uint32 i = 0; i < OPT_MAX; i++) {
        if (g_options[i].match_func(params, g_options[i].name, g_options[i].show_less_len)) {
            param_matched |= g_options[i].show_att_func(params);
        }
    }

    if (!param_matched) {
        ctsql_printf("Show failed.\n\n");
        ctsql_display_show_usage();
    }

    return;
}

static bool8 ctsql_show_autocommit(const text_t *value)
{
    ctsql_printf("autocommit %s.\n", (g_local_config.auto_commit == CT_TRUE) ? "ON" : "OFF");
    return CT_TRUE;
}

static bool8 ctsql_show_exitcommit(const text_t *value)
{
    ctsql_printf("exitcommit %s.\n", (g_local_config.exit_commit == CT_TRUE) ? "ON" : "OFF");
    return CT_TRUE;
}

static bool8 ctsql_show_charset(const text_t *value)
{
    ctsql_printf("charset %s.\n", (char *)cm_get_charset_name((charset_type_t)g_local_config.charset_id));
    return CT_TRUE;
}

static bool8 ctsql_show_heading(const text_t *value)
{
    ctsql_printf("heading %s.\n", (g_local_config.heading_on == CT_TRUE) ? "ON" : "OFF");
    return CT_TRUE;
}

static bool8 ctsql_show_serverouput(const text_t *value)
{
    ctsql_printf("serveroutput %s.\n", (g_local_config.server_ouput == CT_TRUE) ? "ON" : "OFF");
    return CT_TRUE;
}

static bool8 ctsql_show_spool(const text_t *value)
{
    ctsql_printf("spool %s.\n", (g_local_config.spool_on == CT_TRUE) ? "ON" : "OFF");
    return CT_TRUE;
}

static bool8 ctsql_show_trimspool(const text_t *value)
{
    ctsql_printf("trimspool %s.\n", (g_local_config.trim_spool == CT_TRUE) ? "ON" : "OFF");
    return CT_TRUE;
}

static bool8 ctsql_show_linesize(const text_t *value)
{
    ctsql_printf("linesize %u.\n", g_local_config.line_size);
    return CT_TRUE;
}

static bool8 ctsql_show_longsize(const text_t *value)
{
    ctsql_printf("long is %u.\n", g_local_config.long_size);
    return CT_TRUE;
}

static bool8 ctsql_show_numwidth(const text_t *value)
{
    uint32 num_width = 0;
    uint32 attr_len = 0;
    if (ctconn_get_conn_attr(CONN, CTCONN_ATTR_NUM_WIDTH, &num_width, sizeof(uint32), &attr_len) != CTCONN_SUCCESS) {
        ctsql_print_error(CONN);
        return CT_FALSE;
    }
    ctsql_printf("numwidth %u.\n", num_width);
    return CT_TRUE;
}

static bool8 ctsql_show_pagesize(const text_t *value)
{
    ctsql_printf("pagesize %u.\n", g_local_config.page_size);
    return CT_TRUE;
}

static bool8 ctsql_show_timing(const text_t *value)
{
    ctsql_printf("timing %s.\n", (g_local_config.timer.timing_on == CT_TRUE) ? "ON" : "OFF");
    return CT_TRUE;
}

static bool8 ctsql_show_feedback(const text_t *value)
{
    if (g_local_config.feedback.feedback_on == CT_TRUE) {
        ctsql_printf("Feedback is ON, and feedback row is %u.\n", g_local_config.feedback.feedback_rows);
    } else {
        ctsql_printf("Feedback is OFF.\n");
    }
    return CT_TRUE;
}

static bool8 ctsql_show_define_on(const text_t *value)
{
    if (g_local_config.define_on == CT_FALSE) {
        ctsql_printf("replace function is OFF.\n");
    } else {
        ctsql_printf("replace fuction is ON and replace mark is %c.\n", g_replace_mark);
    }
    return CT_TRUE;
}

static bool8 ctsql_show_oplog(const text_t *value)
{
    if (LOG_OPER_ON) {
        ctsql_printf("CTSQL OPER LOG is ON.\n");
    } else {
        ctsql_printf("CTSQL OPER LOG is OFF.\n");
    }
    return CT_TRUE;
}

static bool8 ctsql_show_connect_timeout(const text_t *value)
{
    ctsql_printf("ctsql connect timeout = %d\n", g_local_config.connect_timeout);
    return CT_TRUE;
}

static bool8 ctsql_show_socket_timeout(const text_t *value)
{
    ctsql_printf("ctsql socket timeout = %d\n", g_local_config.socket_timeout);
    return CT_TRUE;
}

static bool8 ctsql_show_scriptoutput(const text_t *value)
{
    ctsql_printf("echo %s.\n", (g_local_config.script_output == CT_TRUE) ? "ON" : "OFF");
    return CT_TRUE;
}

static bool8 ctsql_show_verify_on(const text_t *value)
{
    ctsql_printf("verify %s.\n", (g_local_config.verify_on == CT_TRUE) ? "ON" : "OFF");
    return CT_TRUE;
}

static bool8 ctsql_show_termout_on(const text_t *value)
{
    ctsql_printf("termout %s.\n", (g_local_config.termout_on == CT_TRUE) ? "OFF" : "ON");
    return CT_TRUE;
}

static bool8 ctsql_show_newpage(const text_t *value)
{
    if (g_local_config.newpage > 0) {
        ctsql_printf("newpage is %u.\n", g_local_config.newpage);
    } else {
        ctsql_printf("newpage OFF.\n");
    }
    return CT_TRUE;
}

static bool8 ctsql_show_colsep(const text_t *value)
{
    ctsql_printf("colsep is \"%s\".\n", g_local_config.colsep.colsep_name);
    return CT_TRUE;
}

static bool8 ctsql_show_ssl_mode(const text_t *value)
{
    ctsql_printf("ctsql_ssl_mode    %s\n", g_ssl_mode_txt_list[g_local_config.ssl_mode]);
    return CT_TRUE;
}

static bool8 ctsql_show_ssl_ca_file(const text_t *value)
{
    ctsql_printf("ctsql_ssl_ca      %s\n", CM_IS_EMPTY_STR(g_local_config.ssl_ca) ? "<NULL>" : g_local_config.ssl_ca);
    return CT_TRUE;
}

static bool8 ctsql_show_ssl_cert_file(const text_t *value)
{
    ctsql_printf("ctsql_ssl_cert    %s\n", CM_IS_EMPTY_STR(g_local_config.ssl_cert) ? "<NULL>" : g_local_config.ssl_cert);
    return CT_TRUE;
}

static bool8 ctsql_show_ssl_key_file(const text_t *value)
{
    ctsql_printf("ctsql_ssl_key     %s\n", CM_IS_EMPTY_STR(g_local_config.ssl_key) ? "<NULL>" : g_local_config.ssl_key);
    return CT_TRUE;
}

static bool8 ctsql_show_ssl_crl_file(const text_t *value)
{
    ctsql_printf("ctsql_ssl_crl     %s\n", CM_IS_EMPTY_STR(g_local_config.ssl_crl) ? "<NULL>" : g_local_config.ssl_crl);
    return CT_TRUE;
}

static bool8 ctsql_show_ssl_key_passwd(const text_t *value)
{
    ctsql_printf("ctsql_ssl_key_passwd  %s\n",
                CM_IS_EMPTY_STR(g_local_config.ssl_keypwd) ? "<NULL>" : g_local_config.ssl_keypwd);
    return CT_TRUE;
}

static bool8 ctsql_show_ssl_cipher(const text_t *value)
{
    ctsql_printf("ctsql_ssl_cipher  %s\n",
                CM_IS_EMPTY_STR(g_local_config.ssl_cipher) ? "<NULL>" : g_local_config.ssl_cipher);
    return CT_TRUE;
}

static bool8 ctsql_show_uds_clt_path(const text_t *value)
{
    ctsql_printf("uds_client_path = %s\n",
                CM_IS_EMPTY_STR(g_local_config.client_path) ? "<NULL>" : g_local_config.client_path);
    return CT_TRUE;
}

static bool8 ctsql_show_uds_srv_path(const text_t *value)
{
    ctsql_printf("uds_server_path = %s\n",
                CM_IS_EMPTY_STR(g_local_config.server_path) ? "<NULL>" : g_local_config.server_path);
    return CT_TRUE;
}

static bool8 ctsql_show_bindparam_force_on(const text_t *value)
{
    ctsql_printf("ctsql BIND = %s\n", (g_local_config.bindparam_force_on == CT_TRUE) ? "ON" : "OFF");
    return CT_TRUE;
}

static bool8 ctsql_show_shd_rw_split(const text_t *value)
{
    ctsql_printf("shard_rw_flag = %u\n", g_local_config.shd_rw_split);
    return CT_TRUE;
}

static bool8 ctsql_show_history(const text_t *value)
{
    ctsql_printf("history %s.\n", (g_local_config.history_on == CT_TRUE) ? "ON" : "OFF");
    return CT_TRUE;
}

static bool8 ctsql_show_autotrace(const text_t *value)
{
    ctsql_printf("autotrace %s.\n", g_trace_value_list[g_local_config.trace_mode]);
    return CT_TRUE;
}

/* currently used for create table DDL clause display; further development may extend to display create otherwise */
static status_t ctsql_show_create(const text_t *create_table_text)
{
    bool32 show_parse_info = CT_FALSE; /* show create table does NOT display parse progress in exp */
    text_t cmd_sql;
    lex_t lex;
    word_t word;
    char send_cmd[CT_MAX_CMD_LEN] = { 0 };
    char table_name_str[CT_NAME_BUFFER_SIZE] = { 0 };
    sql_text_t sql_text;
    sql_text.value = *create_table_text;
    sql_text.loc.line = 1;
    sql_text.loc.column = 1;
    text_buf_t tbl_name_buf;

    if (!IS_CONN) {
        CTSQL_PRINTF(ZSERR_CTSQL, "connection is not established");
        return CT_ERROR;
    }

    lex_trim(&sql_text);
    lex_init(&lex, &sql_text);
    lex_init_keywords();

    /* parse cmd keywords for ' create table *table_name* ' */
    if (lex_expected_fetch_word(&lex, "create") != CT_SUCCESS) {
        CTSQL_PRINTF(ERR_SQL_SYNTAX_ERROR, "keyword 'create' expected.");
        return CT_ERROR;
    }
    if (lex_expected_fetch_word(&lex, "table") != CT_SUCCESS) {
        CTSQL_PRINTF(ERR_SQL_SYNTAX_ERROR, "keyword 'table' expected.");
        return CT_ERROR;
    }

    tbl_name_buf.max_size = MAX_ENTITY_LEN;
    tbl_name_buf.str = g_str_buf;
    tbl_name_buf.len = 0;

    if (lex_expected_fetch_tblname(&lex, &word, &tbl_name_buf) != CT_SUCCESS || lex_expected_end(&lex) != CT_SUCCESS) {
        g_tls_error.loc.line = 0;
        ctsql_print_error(NULL);
        ctsql_printf("Usage: SHOW CREATE TABLE table_name\n");
        return CT_ERROR;
    }
    CM_NULL_TERM(&tbl_name_buf);

    MEMS_RETURN_IFERR(strncpy_s(table_name_str, CT_NAME_BUFFER_SIZE, tbl_name_buf.str, tbl_name_buf.len));

    MEMS_RETURN_IFERR(strcat_s(send_cmd, CT_MAX_CMD_LEN, "EXPORT SHOW_CREATE_TABLE=Y TABLES="));
    MEMS_RETURN_IFERR(strcat_s(send_cmd, CT_MAX_CMD_LEN, table_name_str));
    MEMS_RETURN_IFERR(strcat_s(send_cmd, CT_MAX_CMD_LEN, " CONTENT=METADATA_ONLY"));
    cm_str2text_safe(send_cmd, (uint32)strlen(send_cmd), &cmd_sql);
    CT_RETURN_IFERR(ctsql_export(&cmd_sql, show_parse_info));

    return CT_SUCCESS;
}

static bool8 ctsql_show_create_opt(const text_t *value)
{
    (void)ctsql_show_create(value);
    return CT_TRUE;
}

static bool8 ctsql_show_tenant_opt(const text_t *value)
{
    ctsql_show_tenant(value);
    return CT_TRUE;
}

static bool8 ctsql_show_parameters_opt(const text_t *value)
{
    uint32 match_len = cm_text_str_get_match_len(value, g_options[OPT_PARAMETERS].name);
    if (value->len == match_len || *(value->str + match_len) == ' ') {
        text_t param = *value;
        ctsql_show_parameters(&param);
        return CT_TRUE;
    }
    return CT_FALSE;
}

