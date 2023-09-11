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
 * gsql.h
 *
 *
 * IDENTIFICATION
 * src/utils/gsql/gsql.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef GSQL_CMD_H
#define GSQL_CMD_H

#include "cm_defs.h"
#include "cm_text.h"
#include "cm_file.h"
#include "cm_date.h"
#include "cm_binary.h"
#include "cm_decimal.h"
#include "cm_encrypt.h"
#include "gsc.h"
#include "gsc_inner.h"
#include "gsc_client.h"
#include <stdarg.h>
#include "var_inc.h"
#include "cm_list.h"
#include "cm_charset.h"
#include "cm_gts_timestamp.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
* @addtogroup GSQL_CMD
* @brief The API of `gsql` command interface
* @{ */
#define MAX_ENTITY_LEN                   256
#define MAX_CMD_LEN                      65536
#define SPOOL_BUFFER_SIZE                SIZE_M(1)
#define MAX_COLUMN_WIDTH                 1024
#define MAX_SQL_SIZE                     SIZE_M(1)
#define FILE_BUFFER_SIZE                 SIZE_M(1)
#define GS_MIN_PAGESIZE                  (uint32)4
#define ZSQL_INTERACTION_DEFAULT_TIMEOUT (uint32)5
#define GSQL_HISTORY_BUF_SIZE            4096
#define GSQL_MAX_HISTORY_SIZE            20
#define GSQL_UTF8_CHR_SIZE               6

#define CMD_KEY_ASCII_BS                 8
#define CMD_KEY_ASCII_DEL                127
#define CMD_KEY_ASCII_LF                 10
#define CMD_KEY_ASCII_CR                 13

#define CMD_KEY_ESCAPE                   27
#define CMD_KEY_UP                       65
#define CMD_KEY_DOWN                     66
#define CMD_KEY_DEL                      51

#define GSQL_IS_STRING_TYPE_EX(type) (GS_IS_STRING_TYPE((type) + GS_TYPE_BASE))
#define GSQL_IS_BINARY_TYPE_EX(type) (GS_IS_BINARY_TYPE((type) + GS_TYPE_BASE))
#define GSQL_IS_LOB_TYPE(type)       (GS_IS_LOB_TYPE((type) + GS_TYPE_BASE))
#define GSQL_IS_ENCLOSED_TYPE(type)  (GS_IS_VARLEN_TYPE((type) + GS_TYPE_BASE) || GSQL_IS_LOB_TYPE(type))
#define GSQL_IS_NUMBER_TYPE(type)    (GS_IS_NUMERIC_TYPE((type) + GS_TYPE_BASE))

#define GSQL_SEC_FILE_NAME "data"
#define GSQL_COPYRIGHT_VERSION 8

#define GSQL_CONN_PARAM_COUNT 7
/* The ctclient cmd-interface may use some function in common and lex module,
 * the error info need to separately process, its errmsg should be printed
 * by gsql_print_error(NULL) */
typedef enum en_zs_errno {
    ZSERR_ERRNO_DEF = 0,
    ZSERR_GSQL = 1,
    ZSERR_DUMP = 2,
    ZSERR_LOAD = 3,
    ZSERR_EXPORT = 4,
    ZSERR_IMPORT = 5,
    ZSERR_MAIN = 6,
    ZSERR_WSR = 7,
} zs_errno_t;

typedef enum en_gsql_cmd {
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
} gsql_cmd_t;

typedef enum en_gsql_cmd_mode {
    MODE_SINGLE_LINE,
    MODE_MULTI_LINE,
    MODE_NONE
} gsql_cmd_mode;

typedef enum en_gsql_line_tag {
    GSQL_SINGLE_TAG = 0x0,
    GSQL_BLOCK_TAG = 0x1,
    GSQL_BLOCK_END_TAG = 0x2,
    GSQL_MULTI_TAG = 0x4,
    GSQL_MULTI_END_TAG = 0x8,
    GSQL_COMMENT_TAG = 0x10,
    GSQL_COMMENT_END_TAG = 0x20,
    GSQL_EMPTY_TAG = 0x40,
} gsql_line_tag_t;

typedef enum en_gsql_trace_mode {
    GSQL_TRACE_OFF = 0,
    GSQL_TRACE_ON,
    GSQL_TRACE_ONLY
} gsql_trace_mode_t;

typedef struct st_gsql_cmd_def {
    gsql_cmd_t cmd;
    gsql_cmd_mode mode;
    char *str;
} gsql_cmd_def_t;

typedef struct st_gsql_cmd_history_list {
    uint32 nbytes;
    uint32 nwidths;
    char hist_buf[GSQL_HISTORY_BUF_SIZE];
} gsql_cmd_history_list_t;

typedef struct st_gsql_conn_info_t {
    gsc_conn_t conn;
    gsc_stmt_t stmt;
    char username[GS_NAME_BUFFER_SIZE + GS_STR_RESERVED_LEN];
    char schemaname[GS_NAME_BUFFER_SIZE + GS_STR_RESERVED_LEN];
    char passwd[GS_PASSWORD_BUFFER_SIZE + GS_STR_RESERVED_LEN];
    char server_url[CM_UNIX_DOMAIN_PATH_LEN + GS_TENANT_BUFFER_SIZE + GS_STR_RESERVED_LEN];
    char home[GS_MAX_PATH_BUFFER_SIZE];
    bool8 connect_by_install_user;
    bool8 is_conn;
    bool8 is_clsmgr;
    bool8 is_working;
} gsql_conn_info_t;

typedef struct st_gsql_timing_t {
    bool32 timing_on;
    date_t consumed_time;
} gsql_timing_t;

typedef struct st_gsql_feedback_t {
    bool32 feedback_on;
    uint32 feedback_rows;
} gsql_feedback_t;

typedef struct st_gsql_column_format_attr_t {
    bool32 is_on;
    uint32 col_width;
    char col_name[GS_MAX_NAME_LEN + 1];
} gsql_column_format_attr_t;

typedef struct st_whenever_t {
    uint8 is_on;
    uint8 error_type;     // 0:SQLERROR 1:OSERROR
    uint8 continue_type;  // 0:EXIT     1:CONTINUE
    uint8 commit_type;    // 0:ROLLBACK 1:COMMIT
} whenever_t;

#define MAX_COLSEP_NAME_LEN 256
typedef struct st_gsql_colsep_t {
    char colsep_name[MAX_COLSEP_NAME_LEN];
    uint32 colsep_len;
} gsql_colsep_t;

typedef struct st_gsql_local_info_t {
    bool32 auto_commit;  // attention: need add to connection
    bool32 exit_commit;  // attention: need add to connection
    uint32 charset_id;   // attention: need add to connection
    bool32 heading_on;
    bool32 server_ouput;  // attention: need add to connection
    bool32 trim_spool;
    bool32 spool_on;
    uint32 line_size;
    uint32 page_size;
    gsql_timing_t timer;
    gsql_feedback_t feedback;
    list_t column_formats;
    bool32 silent_on;
    bool32 print_on;
    whenever_t whenever;
    uint32 long_size;
    gsql_colsep_t colsep;
    uint32 newpage;
    bool32 verify_on;
    bool32 termout_on;
    bool32 script_output;
    bool32 define_on;
    gsc_ssl_mode_t ssl_mode;
    char ssl_ca[GS_FILE_NAME_BUFFER_SIZE];   /* PEM CA file */
    char ssl_cert[GS_FILE_NAME_BUFFER_SIZE]; /* PEM cert file */
    char ssl_key[GS_FILE_NAME_BUFFER_SIZE];  /* PEM key file */
    char ssl_keypwd[GS_MAX_CIPHER_LEN + 4];  /* PSWD cipher for private key */
    char ssl_crl[GS_FILE_NAME_BUFFER_SIZE];  /* SSL CRL */
    char ssl_cipher[GS_PARAM_BUFFER_SIZE];   /* Algorithm cipher */
    bool32 is_cancel;
    bool32 zsql_ssl_quiet;
    uint32 zsql_interaction_timeout;
    int32 connect_timeout;
    int32 socket_timeout;
    char  server_path[GS_UNIX_PATH_MAX];
    char  client_path[GS_UNIX_PATH_MAX];
    bool32 bindparam_force_on;
    uint8 shd_rw_split;  // attention: need add to connection
    bool32 history_on;
    uint32 trace_mode;
} gsql_local_config_t;

extern gsql_local_config_t g_local_config;
extern gsql_conn_info_t g_conn_info;
extern gsc_inner_column_desc_t g_columns[GS_MAX_COLUMNS];
extern char g_cmd_buf[MAX_CMD_LEN + 2];
extern char g_sql_buf[MAX_SQL_SIZE + 4];
extern char g_str_buf[GS_MAX_PACKET_SIZE + 1];  // for print a column data
extern char g_replace_mark;
extern bool32 g_is_print;

#define IS_CONN   g_conn_info.is_conn
#define IS_WORKING g_conn_info.is_working
#define GSQL_CANCELING g_local_config.is_cancel
#define CONN      g_conn_info.conn
#define STMT      g_conn_info.stmt
#define GS_HOME   g_conn_info.home
#define USER_NAME g_conn_info.schemaname
#define STDOUT    1

/* For sharing global memory when data dumping and loading */
#define USE_GSQL_COLUMN_DESC

extern status_t gsql_alloc_conn(gsc_conn_t *pconn);
extern void gsql_print_error(gsc_conn_t conn);
extern void gsql_try_spool_put(const char *fmt, ...);
extern void gsql_init(int32 argc, char *argv[]);
extern void gsql_run(FILE *in, bool32 is_file, char *cmd_buf, uint32 max_len);
extern void gsql_exit(bool32 from_whenever, status_t status);
extern status_t gsql_connect(text_t *conn_text);
extern uint32 gsql_print_welcome(uint32 multi_line, uint32 line_no);
extern status_t gsql_conn_to_server(gsql_conn_info_t *conn_info, bool8 print_conn, bool8 is_background);
extern void gsql_free_config(void);
void gsql_print_result(void);
void gsql_get_error(gsc_conn_t conn, int *code, const char **message, source_location_t *loc);
void gsql_set_error(const char *file, uint32 line, zs_errno_t code, const char *format, ...) GS_CHECK_FMT(4, 5);
status_t gsql_set_trx_iso_level(text_t *line);
status_t gsql_execute_sql(void);

#define gsql_printf(fmt, ...)                   \
    do {                                        \
        if (!g_local_config.silent_on) {        \
            printf(fmt, ##__VA_ARGS__);         \
            fflush(stdout);                     \
        }                                       \
        gsql_try_spool_put(fmt, ##__VA_ARGS__); \
    } while (0)

#define gsql_write(len, fmt, ...)                                      \
    do {                                                               \
        if (!g_local_config.silent_on) {                               \
            int ret __attribute__((unused)) = write(STDOUT, fmt, len); \
        }                                                              \
        gsql_try_spool_put(fmt, ##__VA_ARGS__);                        \
    } while (0)

#define GSQL_PRINTF(err_no, fmt, ...)                                                   \
    {                                                                                   \
        gsql_set_error((char *)__FILE__, (uint32)__LINE__, err_no, fmt, ##__VA_ARGS__); \
    }

#define GSQL_CHECK_MEMS_SECURE(ret)                    \
    do {                                               \
        int32 __code__ = (ret);                        \
        if (SECUREC_UNLIKELY(__code__ != EOK)) {       \
            GS_THROW_ERROR(ERR_SYSTEM_CALL, __code__); \
            return;                                    \
        }                                              \
    } while (0)

static inline void gsql_print_disconn_error(void)
{
    gsql_printf("CT-%05d, %s\n", ERR_CLT_CONN_CLOSE, "connect is not established");
}
#define GSQL_MAX_HIDED_PWD_LEN 1u
/**
 * Erase the from the connection string, and substitute it by
 * stars. Here, pwd_text contains the position and the length of the
 * pswd. It is a part of conn_text.
 * @author Added, 2018/04/11
 */
static inline void gsql_erase_pwd(text_t *conn_text, text_t *pwd_text)
{
    text_t remain;
    size_t offset;
    errno_t errcode;
    errno_t rc_memmove;

    if (pwd_text->len <= GSQL_MAX_HIDED_PWD_LEN) {
        (void)cm_text_set(pwd_text, pwd_text->len, '*');
        return;
    }

    (void)cm_text_set(pwd_text, GSQL_MAX_HIDED_PWD_LEN, '*');

    /* obtain the text after @ip:port */
    remain.str = pwd_text->str + pwd_text->len;
    remain.len = conn_text->len - (uint32)(remain.str - conn_text->str);
    offset = conn_text->len - (pwd_text->str + GSQL_MAX_HIDED_PWD_LEN - conn_text->str);
    rc_memmove = memmove_s(pwd_text->str + GSQL_MAX_HIDED_PWD_LEN, offset, remain.str, remain.len);
    if (rc_memmove != EOK) {
        gsql_printf("Moving remain.str has thrown an error %d", rc_memmove);
        return;
    }
    /* obtain the unused text, reset them to 0 */
    remain.len = pwd_text->len - GSQL_MAX_HIDED_PWD_LEN;
    remain.str = conn_text->str + conn_text->len - remain.len;
    offset = conn_text->len - (remain.str - conn_text->str);
    if (remain.len != 0) {
        errcode = memset_s(remain.str, offset, 0, remain.len);
        if (errcode != EOK) {
            gsql_printf("Secure C lib has thrown an error %d", errcode);
            return;
        }
    }
    pwd_text->len = GSQL_MAX_HIDED_PWD_LEN;
    conn_text->len -= remain.len;
}
/** @} */  // end group GSQL_CMD

static inline int gsql_nlsparam_geter(char *nlsbuf, int nls_id, text_t *text)
{
    uint32 fmtlen;
    if (gsc_get_conn_attr(CONN, ((nls_id) + GSC_ATTR_NLS_CALENDAR),
                          (nlsbuf), MAX_NLS_PARAM_LENGTH, &fmtlen) != GSC_SUCCESS) {
        gsql_print_error(CONN);
        return GSC_ERROR;
    }
    text->str = nlsbuf;
    text->len = fmtlen;
    return GSC_SUCCESS;
}

/* Used to inspect whether the input text is too long  */
#define GSQL_BUF_RESET_CHAR EOF

/* Reset the single-line command buffer */
static inline void gsql_reset_cmd_buf(char *cmd_buf, uint32 max_len)
{
    cmd_buf[max_len - 1] = GSQL_BUF_RESET_CHAR;
    cmd_buf[max_len - 2] = GSQL_BUF_RESET_CHAR;
    if (memset_s(cmd_buf, max_len, 0, MAX_CMD_LEN) != EOK) {
        return;
    }
}

EXTER_ATTACK status_t gsql_process_cmd(text_t *line);
EXTER_ATTACK status_t gsql_execute(text_t *line);
void gsql_silent(text_t *line);
status_t gsql_cancel(void);
status_t gsql_conn_cancel(gsql_conn_info_t *conn_info);
status_t gsql_recv_passwd_from_terminal(char *buff, int32 buff_size);
static inline status_t gsql_reset_charset(uint32 charset_id, uint32 curr_charset_id)
{
    if (charset_id == curr_charset_id) {
        return GS_SUCCESS;
    }
    const char *pcharset_name = cm_get_charset_name((charset_type_t)charset_id);
    if (pcharset_name == NULL) {
        GS_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "charset");
        return GS_ERROR;
    }

    (void)gsc_set_conn_attr(CONN, GSC_ATTR_CHARSET_TYPE, pcharset_name, (uint32)strlen(pcharset_name));

    return GS_SUCCESS;
}

status_t gsql_get_local_server_kmc_ksf(char *home);
status_t gsql_get_local_server_kmc_privilege(char *home, char *passwd, uint32 pwd_len, bool32 is_ztrst);
status_t gsql_init_home(void);

#ifdef __cplusplus
}
#endif

#endif  // end GSQL_CMD_H
