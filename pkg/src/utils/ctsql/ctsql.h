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
 * ctsql.h
 *
 *
 * IDENTIFICATION
 * src/utils/ctsql/ctsql.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CTSQL_CMD_H
#define CTSQL_CMD_H

#include "cm_defs.h"
#include "cm_text.h"
#include "cm_file.h"
#include "cm_date.h"
#include "cm_binary.h"
#include "cm_decimal.h"
#include "cm_encrypt.h"
#include "ctconn.h"
#include "ctconn_inner.h"
#include "ctconn_client.h"
#include "var_inc.h"
#include "cm_list.h"
#include "cm_charset.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
* @addtogroup CTSQL_CMD
* @brief The API of `ctsql` command interface
* @{ */
#define MAX_ENTITY_LEN                   256
#define MAX_CMD_LEN                      65536
#define SPOOL_BUFFER_SIZE                SIZE_M(1)
#define MAX_COLUMN_WIDTH                 1024
#define MAX_SQL_SIZE                     SIZE_M(1)
#define FILE_BUFFER_SIZE                 SIZE_M(1)
#define CT_MIN_PAGESIZE                  (uint32)4
#define CTSQL_INTERACTION_DEFAULT_TIMEOUT (uint32)5
#define CTSQL_HISTORY_BUF_SIZE            4096
#define CTSQL_MAX_HISTORY_SIZE            20
#define CTSQL_UTF8_CHR_SIZE               6

#define CMD_KEY_ASCII_BS                 8
#define CMD_KEY_ASCII_DEL                127
#define CMD_KEY_ASCII_LF                 10
#define CMD_KEY_ASCII_CR                 13

#define CMD_KEY_ESCAPE                   27
#define CMD_KEY_UP                       65
#define CMD_KEY_DOWN                     66
#define CMD_KEY_DEL                      51

#define CTSQL_IS_STRING_TYPE_EX(type) (CT_IS_STRING_TYPE((type) + CT_TYPE_BASE))
#define CTSQL_IS_BINARY_TYPE_EX(type) (CT_IS_BINARY_TYPE((type) + CT_TYPE_BASE))
#define CTSQL_IS_LOB_TYPE(type)       (CT_IS_LOB_TYPE((type) + CT_TYPE_BASE))
#define CTSQL_IS_ENCLOSED_TYPE(type)  (CT_IS_VARLEN_TYPE((type) + CT_TYPE_BASE) || CTSQL_IS_LOB_TYPE(type))
#define CTSQL_IS_NUMBER_TYPE(type)    (CT_IS_NUMERIC_TYPE((type) + CT_TYPE_BASE))

#define CTSQL_SEC_FILE_NAME "data"
#define CTSQL_COPYRIGHT_VERSION 8

#define CTSQL_CONN_PARAM_COUNT 7
/* The CTSQL cmd-interface may use some function in common and lex module,
 * the error info need to separately process, its errmsg should be printed
 * by ctsql_print_error(NULL) */
typedef enum en_zs_errno {
    ZSERR_ERRNO_DEF = 0,
    ZSERR_CTSQL = 1,
    ZSERR_DUMP = 2,
    ZSERR_LOAD = 3,
    ZSERR_EXPORT = 4,
    ZSERR_IMPORT = 5,
    ZSERR_MAIN = 6,
    ZSERR_WSR = 7,
} zs_errno_t;

typedef enum en_ctsql_cmd {
    CMD_NONE = 0,
    CMD_SQL = 1,
    CMD_EXIT = 2,
    CMD_SHOW = 3,
    CMD_CONN = 4,
    CMD_EXEC = 5,
    CMD_SQLFILE = 8,  // @sqlfile
    CMD_CLEAR = 9,
    CMD_SET = 10,
    CMD_SPOOL = 11,
    CMD_COMMENT = 12,
    CMD_DESC = 13,
    CMD_DUMP = 14,
    CMD_LOAD = 15,
    CMD_COMMAND = 16,  // external cmd must be defined after CMD_LOAD
    CMD_FILE = 17,
    CMD_QUIT = 18,
    CMD_COLUMN = 19,
    CMD_SILENT = 20,
    CMD_SHELL = 21,
    CMD_EXPORT = 22,
    CMD_WHENEVER = 23,
    CMD_PROMPT = 24,
    CMD_AWR = 25,
    CMD_IMPORT = 27,
    CMD_SQLFILE2 = 28,  // @@ sqlfile
    CMD_LIST = 29,
    CMD_MONITOR = 30,
} ctsql_cmd_t;

typedef enum en_ctsql_cmd_mode {
    MODE_SINGLE_LINE,
    MODE_MULTI_LINE,
    MODE_NONE
} ctsql_cmd_mode;

typedef enum en_ctsql_line_tag {
    CTSQL_SINGLE_TAG = 0x0,
    CTSQL_BLOCK_TAG = 0x1,
    CTSQL_BLOCK_END_TAG = 0x2,
    CTSQL_MULTI_TAG = 0x4,
    CTSQL_MULTI_END_TAG = 0x8,
    CTSQL_COMMENT_TAG = 0x10,
    CTSQL_COMMENT_END_TAG = 0x20,
    CTSQL_EMPTY_TAG = 0x40,
} ctsql_line_tag_t;

typedef enum en_ctsql_trace_mode {
    CTSQL_TRACE_OFF = 0,
    CTSQL_TRACE_ON,
    CTSQL_TRACE_ONLY
} ctsql_trace_mode_t;

typedef struct st_ctsql_cmd_def {
    ctsql_cmd_t cmd;
    ctsql_cmd_mode mode;
    char *str;
} ctsql_cmd_def_t;

typedef struct st_ctsql_cmd_history_list {
    uint32 nbytes;
    uint32 nwidths;
    char hist_buf[CTSQL_HISTORY_BUF_SIZE];
} ctsql_cmd_history_list_t;

typedef struct st_ctsql_conn_info_t {
    ctconn_conn_t conn;
    ctconn_stmt_t stmt;
    char username[CT_NAME_BUFFER_SIZE + CT_STR_RESERVED_LEN];
    char schemaname[CT_NAME_BUFFER_SIZE + CT_STR_RESERVED_LEN];
    SENSI_INFO char passwd[CT_PASSWORD_BUFFER_SIZE + CT_STR_RESERVED_LEN];
    char server_url[CM_UNIX_DOMAIN_PATH_LEN + CT_TENANT_BUFFER_SIZE + CT_STR_RESERVED_LEN];
    char home[CT_MAX_PATH_BUFFER_SIZE];
    bool8 connect_by_install_user;
    bool8 is_conn;
    bool8 is_clsmgr;
    bool8 is_working;
} ctsql_conn_info_t;

typedef struct st_ctsql_timing_t {
    bool32 timing_on;
    date_t consumed_time;
} ctsql_timing_t;

typedef struct st_ctsql_feedback_t {
    bool32 feedback_on;
    uint32 feedback_rows;
} ctsql_feedback_t;

typedef struct st_ctsql_column_format_attr_t {
    bool32 is_on;
    uint32 col_width;
    char col_name[CT_MAX_NAME_LEN + 1];
} ctsql_column_format_attr_t;

typedef struct st_whenever_t {
    uint8 is_on;
    uint8 error_type;     // 0:SQLERROR 1:OSERROR
    uint8 continue_type;  // 0:EXIT     1:CONTINUE
    uint8 commit_type;    // 0:ROLLBACK 1:COMMIT
} whenever_t;

#define MAX_COLSEP_NAME_LEN 256
typedef struct st_ctsql_colsep_t {
    char colsep_name[MAX_COLSEP_NAME_LEN];
    uint32 colsep_len;
} ctsql_colsep_t;

typedef struct st_ctsql_local_info_t {
    bool32 auto_commit;  // attention: need add to connection
    bool32 exit_commit;  // attention: need add to connection
    uint32 charset_id;   // attention: need add to connection
    bool32 heading_on;
    bool32 server_ouput;  // attention: need add to connection
    bool32 trim_spool;
    bool32 spool_on;
    uint32 line_size;
    uint32 page_size;
    ctsql_timing_t timer;
    ctsql_feedback_t feedback;
    list_t column_formats;
    bool32 silent_on;
    bool32 print_on;
    whenever_t whenever;
    uint32 long_size;
    ctsql_colsep_t colsep;
    uint32 newpage;
    bool32 verify_on;
    bool32 termout_on;
    bool32 script_output;
    bool32 define_on;
    ctconn_ssl_mode_t ssl_mode;
    char ssl_ca[CT_FILE_NAME_BUFFER_SIZE];   /* PEM CA file */
    char ssl_cert[CT_FILE_NAME_BUFFER_SIZE]; /* PEM cert file */
    char ssl_key[CT_FILE_NAME_BUFFER_SIZE];  /* PEM key file */
    SENSI_INFO char ssl_keypwd[CT_MAX_CIPHER_LEN + 4];  /* PSWD cipher for private key */
    char ssl_crl[CT_FILE_NAME_BUFFER_SIZE];  /* SSL CRL */
    char ssl_cipher[CT_PARAM_BUFFER_SIZE];   /* Algorithm cipher */
    bool32 is_cancel;
    bool32 CTSQL_SSL_QUIET;
    uint32 CTSQL_INTERACTION_TIMEOUT;
    int32 connect_timeout;
    int32 socket_timeout;
    char  server_path[CT_UNIX_PATH_MAX];
    char  client_path[CT_UNIX_PATH_MAX];
    bool32 bindparam_force_on;
    uint8 shd_rw_split;  // attention: need add to connection
    bool32 history_on;
    uint32 trace_mode;
} ctsql_local_config_t;

extern ctsql_local_config_t g_local_config;
extern ctsql_conn_info_t g_conn_info;
extern ctconn_inner_column_desc_t g_columns[CT_MAX_COLUMNS];
extern char g_cmd_buf[MAX_CMD_LEN + 2];
extern char g_sql_buf[MAX_SQL_SIZE + 4];
extern char g_str_buf[CT_MAX_PACKET_SIZE + 1];  // for print a column data
extern char g_replace_mark;
extern bool32 g_is_print;

#define IS_CONN   g_conn_info.is_conn
#define IS_WORKING g_conn_info.is_working
#define CTSQL_CANCELING g_local_config.is_cancel
#define CONN      g_conn_info.conn
#define STMT      g_conn_info.stmt
#define CT_HOME   g_conn_info.home
#define USER_NAME g_conn_info.schemaname
#define STDOUT    1

/* For sharing global memory when data dumping and loading */
#define USE_CTSQL_COLUMN_DESC

extern status_t ctsql_alloc_conn(ctconn_conn_t *pconn);
extern void ctsql_print_error(ctconn_conn_t conn);
extern void ctsql_try_spool_put(const char *fmt, ...);
extern void ctsql_init(int32 argc, char *argv[]);
extern void ctsql_run(FILE *in, bool32 is_file, char *cmd_buf, uint32 max_len);
extern void ctsql_exit(bool32 from_whenever, status_t status);
extern status_t ctsql_connect(text_t *conn_text);
extern uint32 ctsql_print_welcome(uint32 multi_line, uint32 line_no);
extern status_t ctsql_conn_to_server(ctsql_conn_info_t *conn_info, bool8 print_conn, bool8 is_background);
extern void ctsql_free_config(void);
void ctsql_print_result(void);
void ctsql_get_error(ctconn_conn_t conn, int *code, const char **message, source_location_t *loc);
void ctsql_set_error(const char *file, uint32 line, zs_errno_t code, const char *format, ...) CT_CHECK_FMT(4, 5);
status_t ctsql_set_trx_iso_level(text_t *line);
status_t ctsql_execute_sql(void);

#define ctsql_printf(fmt, ...)                   \
    do {                                        \
        if (!g_local_config.silent_on) {        \
            printf(fmt, ##__VA_ARGS__);         \
            fflush(stdout);                     \
        }                                       \
        ctsql_try_spool_put(fmt, ##__VA_ARGS__); \
    } while (0)

#define ctsql_write(len, fmt, ...)                                      \
    do {                                                               \
        if (!g_local_config.silent_on) {                               \
            int ret __attribute__((unused)) = write(STDOUT, fmt, len); \
        }                                                              \
        ctsql_try_spool_put(fmt, ##__VA_ARGS__);                        \
    } while (0)

#define CTSQL_PRINTF(err_no, fmt, ...)                                                   \
    {                                                                                   \
        ctsql_set_error((char *)__FILE__, (uint32)__LINE__, err_no, fmt, ##__VA_ARGS__); \
    }

#define CTSQL_CHECK_MEMS_SECURE(ret)                    \
    do {                                               \
        int32 __code__ = (ret);                        \
        if (SECUREC_UNLIKELY(__code__ != EOK)) {       \
            CT_THROW_ERROR(ERR_SYSTEM_CALL, __code__); \
            return;                                    \
        }                                              \
    } while (0)

static inline void ctsql_print_disconn_error(void)
{
    ctsql_printf("CT-%05d, %s\n", ERR_CLT_CONN_CLOSE, "connect is not established");
}
#define CTSQL_MAX_HIDED_PWD_LEN 1u
/**
 * Erase the from the connection string, and substitute it by
 * stars. Here, pwd_text contains the position and the length of the
 * pswd. It is a part of conn_text.

 */
static inline void ctsql_erase_pwd(text_t *conn_text, text_t *pwd_text)
{
    text_t remain;
    size_t offset;
    errno_t errcode;
    errno_t rc_memmove;

    if (pwd_text->len <= CTSQL_MAX_HIDED_PWD_LEN) {
        (void)cm_text_set(pwd_text, pwd_text->len, '*');
        return;
    }

    (void)cm_text_set(pwd_text, CTSQL_MAX_HIDED_PWD_LEN, '*');

    /* obtain the text after @ip:port */
    remain.str = pwd_text->str + pwd_text->len;
    remain.len = conn_text->len - (uint32)(remain.str - conn_text->str);
    offset = conn_text->len - (pwd_text->str + CTSQL_MAX_HIDED_PWD_LEN - conn_text->str);
    rc_memmove = memmove_s(pwd_text->str + CTSQL_MAX_HIDED_PWD_LEN, offset, remain.str, remain.len);
    if (rc_memmove != EOK) {
        ctsql_printf("Moving remain.str has thrown an error %d", rc_memmove);
        return;
    }
    /* obtain the unused text, reset them to 0 */
    remain.len = pwd_text->len - CTSQL_MAX_HIDED_PWD_LEN;
    remain.str = conn_text->str + conn_text->len - remain.len;
    offset = conn_text->len - (remain.str - conn_text->str);
    if (remain.len != 0) {
        errcode = memset_s(remain.str, offset, 0, remain.len);
        if (errcode != EOK) {
            ctsql_printf("Secure C lib has thrown an error %d", errcode);
            return;
        }
    }
    pwd_text->len = CTSQL_MAX_HIDED_PWD_LEN;
    conn_text->len -= remain.len;
}
/** @} */  // end group CTSQL_CMD

static inline int ctsql_nlsparam_geter(char *nlsbuf, int nls_id, text_t *text)
{
    uint32 fmtlen;
    if (ctconn_get_conn_attr(CONN, ((nls_id) + CTCONN_ATTR_NLS_CALENDAR),
                          (nlsbuf), MAX_NLS_PARAM_LENGTH, &fmtlen) != CTCONN_SUCCESS) {
        ctsql_print_error(CONN);
        return CTCONN_ERROR;
    }
    text->str = nlsbuf;
    text->len = fmtlen;
    return CTCONN_SUCCESS;
}

/* Used to inspect whether the input text is too long  */
#define CTSQL_BUF_RESET_CHAR EOF

/* Reset the single-line command buffer */
static inline void ctsql_reset_cmd_buf(char *cmd_buf, uint32 max_len)
{
    cmd_buf[max_len - 1] = CTSQL_BUF_RESET_CHAR;
    cmd_buf[max_len - 2] = CTSQL_BUF_RESET_CHAR;
    if (memset_s(cmd_buf, max_len, 0, MAX_CMD_LEN) != EOK) {
        return;
    }
}

EXTER_ATTACK status_t ctsql_process_cmd(text_t *line);
EXTER_ATTACK status_t ctsql_execute(text_t *line);
void ctsql_silent(text_t *line);
status_t ctsql_cancel(void);
status_t ctsql_conn_cancel(ctsql_conn_info_t *conn_info);
status_t ctsql_recv_passwd_from_terminal(char *buff, int32 buff_size);
static inline status_t ctsql_reset_charset(uint32 charset_id, uint32 curr_charset_id)
{
    if (charset_id == curr_charset_id) {
        return CT_SUCCESS;
    }
    const char *pcharset_name = cm_get_charset_name((charset_type_t)charset_id);
    if (pcharset_name == NULL) {
        CT_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "charset");
        return CT_ERROR;
    }

    (void)ctconn_set_conn_attr(CONN, CTCONN_ATTR_CHARSET_TYPE, pcharset_name, (uint32)strlen(pcharset_name));

    return CT_SUCCESS;
}

status_t ctsql_get_local_server_kmc_ksf(char *home);
status_t ctsql_get_local_server_kmc_privilege(char *home, char *passwd, uint32 pwd_len, bool32 is_ztrst);
status_t ctsql_init_home(void);

#ifdef __cplusplus
}
#endif

#endif  // end CTSQL_CMD_H
