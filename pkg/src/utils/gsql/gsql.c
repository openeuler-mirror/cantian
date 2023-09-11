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
 * gsql.c
 *
 *
 * IDENTIFICATION
 * src/utils/gsql/gsql.c
 *
 * -------------------------------------------------------------------------
 */
#include <locale.h>
#include "cm_kmc.h"
#include "cm_base.h"
#include "cm_encrypt.h"
#include "gsql_common.h"
#include "gsql.h"
#include "gsql_dump.h"
#include "gsql_wsr.h"
#include "gsql_export.h"
#include "gsql_import.h"
#include "gsql_input_bind_param.h"
#include "gsql_load.h"
#include "gsql_option.h"
#include "cm_config.h"
#include "cm_log.h"
#include "cm_timer.h"
#include "cm_system.h"
#include "cm_utils.h"
#include "cm_util.h"
#include "cm_hash.h"
#include "gsql_wsr_monitor.h"
#include "cm_encrypt.h"

#ifdef WIN32
#include <conio.h>
#include <windows.h>
#else
#include <termios.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
extern char **environ;
#endif
#include "cm_lex.h"

static const gsql_cmd_def_t g_cmd_defs[] = {
    { CMD_EXEC,     MODE_SINGLE_LINE, "/" },
    { CMD_CLEAR,    MODE_SINGLE_LINE, "clear" },
    { CMD_COLUMN,   MODE_SINGLE_LINE, "col" },
    { CMD_COLUMN,   MODE_SINGLE_LINE, "column" },
    { CMD_CONN,     MODE_SINGLE_LINE, "conn" },
    { CMD_CONN,     MODE_SINGLE_LINE, "connect" },
    { CMD_DESC,     MODE_SINGLE_LINE, "desc" },
    { CMD_DESC,     MODE_SINGLE_LINE, "describe" },
    { CMD_DUMP,     MODE_MULTI_LINE,  "dump" },
    { CMD_EXIT,     MODE_SINGLE_LINE, "exit" },
    { CMD_EXPORT,   MODE_MULTI_LINE,  "exp" },
    { CMD_EXPORT,   MODE_MULTI_LINE,  "export" },
    { CMD_IMPORT,   MODE_MULTI_LINE,  "imp" },
    { CMD_IMPORT,   MODE_MULTI_LINE,  "import" },
    { CMD_LOAD,     MODE_MULTI_LINE,  "load" },
    { CMD_MONITOR,  MODE_SINGLE_LINE, "monitor" },
    { CMD_PROMPT,   MODE_SINGLE_LINE, "pro" },
    { CMD_PROMPT,   MODE_SINGLE_LINE, "prompt" },
    { CMD_EXIT,     MODE_SINGLE_LINE, "quit" },
    { CMD_SET,      MODE_SINGLE_LINE, "set" },
    { CMD_SHOW,     MODE_SINGLE_LINE, "show" },
    { CMD_SPOOL,    MODE_SINGLE_LINE, "spool" },
    { CMD_SQLFILE,  MODE_SINGLE_LINE, "start" },  // start sqlfile is same as @sqlfile
    { CMD_WHENEVER, MODE_SINGLE_LINE, "whenever" },
    { CMD_AWR,      MODE_SINGLE_LINE, "wsr" },
};
#define GSQL_CMD_COUNT (sizeof(g_cmd_defs) / sizeof(gsql_cmd_def_t))

/* Three immediate command */
static const gsql_cmd_def_t CMD_NONE_TYPE = { CMD_NONE,     MODE_NONE,        NULL };
static const gsql_cmd_def_t CMD_COMMENT_TYPE = { CMD_COMMENT,  MODE_NONE,        "--" };
static const gsql_cmd_def_t CMD_SQLFILE_TYPE = { CMD_SQLFILE,  MODE_SINGLE_LINE, NULL };
static const gsql_cmd_def_t CMD_SQLFILE_TYPE2 = { CMD_SQLFILE2, MODE_SINGLE_LINE, NULL };
static const gsql_cmd_def_t CMD_SQL_TYPE = { CMD_SQL,      MODE_MULTI_LINE,  NULL };
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
static const gsql_cmd_def_t CMD_SHELL_TYPE = { CMD_SHELL, MODE_SINGLE_LINE, "\\!" };
#endif

#define GSQL_RESET_CMD_TYPE(cmd_type) ((*(cmd_type)) = CMD_NONE_TYPE)

/* Stores the history when the 'HISTORY' is turned on */
static gsql_cmd_history_list_t g_hist_list[GSQL_MAX_HISTORY_SIZE];

config_item_t g_ctclient_parameters[] = {
    // name (30B)                     isdefault readonly  defaultvalue value runtime_value description range  datatype             comment
    // -------------                  --------- --------  ------------ ----- ------------- ----------- -----  ---------            -----
    { "CTCLIENT_SSL_QUIET", GS_TRUE, GS_TRUE, "FALSE", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "CTCLIENT_INTERACTION_TIMEOUT", GS_TRUE, GS_TRUE, "5", NULL, NULL, "-", "-", "GS_TYPE_INTEGER", NULL, 1, EFFECT_REBOOT, CFG_INS, NULL, NULL },
};

config_item_t g_client_parameters[] = {
    // name (30B)                     isdefault readonly  defaultvalue value runtime_value description range  datatype             comment
    // -------------                  --------- --------  ------------ ----- ------------- ----------- -----  --------            -----
    { "LSNR_ADDR", GS_TRUE, GS_TRUE, "127.0.0.1",          NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "LSNR_PORT", GS_TRUE, GS_TRUE, "1611",               NULL, NULL, "-", "-", "GS_TYPE_INTEGER", NULL, 1, EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "LOCAL_KEY", GS_TRUE, GS_TRUE, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 2, EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "KMC_KEY_FILES", GS_TRUE, GS_TRUE, "",               NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 2, EFFECT_REBOOT, CFG_INS, NULL, NULL },
    /* operation log */
    { "LOG_HOME",               GS_TRUE, GS_TRUE,  "",    NULL, NULL, "-", "-",          "GS_TYPE_VARCHAR", NULL, 3, EFFECT_REBOOT,      CFG_INS, NULL, NULL },
    { "_LOG_BACKUP_FILE_COUNT", GS_TRUE, GS_FALSE, "10",  NULL, NULL, "-", "[0,1024]", "GS_TYPE_INTEGER", NULL, 4, EFFECT_IMMEDIATELY, CFG_INS, NULL, NULL },
    { "_LOG_MAX_FILE_SIZE",     GS_TRUE, GS_FALSE, "10M", NULL, NULL, "-", "(0,-)",    "GS_TYPE_INTEGER", NULL, 5, EFFECT_IMMEDIATELY, CFG_INS, NULL, NULL },
    { "_LOG_FILE_PERMISSIONS",  GS_TRUE, GS_FALSE, "640", NULL, NULL, "-", "-",          "GS_TYPE_INTEGER", NULL, 6, EFFECT_IMMEDIATELY, CFG_INS, NULL, NULL },
    { "_LOG_PATH_PERMISSIONS",  GS_TRUE, GS_FALSE, "750", NULL, NULL, "-", "-",          "GS_TYPE_INTEGER", NULL, 7, EFFECT_IMMEDIATELY, CFG_INS, NULL, NULL },
};
#define ZSQL_PARAMS_COUNT (sizeof(g_ctclient_parameters) / sizeof(config_item_t))
#define GSQL_PARAMS_COUNT (sizeof(g_client_parameters) / sizeof(config_item_t))

spinlock_t g_client_parameters_lock = 0;
spinlock_t g_server_config_lock = 0;
config_t *g_zsql_config = NULL;
config_t *g_server_config = NULL;

gsql_local_config_t g_local_config;
gsql_conn_info_t g_conn_info;
const char *g_env_data = "CTDB_DATA";

const char *g_zsql_config_file = "zsql.ini";
const char *g_config_file = "cantiand.ini";
bool32 g_is_print = GS_FALSE;  // Output sql command of executing sql file
char g_replace_mark = '&';

/* Output the results into file, which can be specified by SPOOL command */
static file_t g_spool_file = GS_NULL_FILE;
static char g_spool_buf[SPOOL_BUFFER_SIZE];
/* The maximal single line cmd is MAX_CMD_LEN. Here, the extra two bytes
 * used to reject too long inputs */
char g_cmd_buf[MAX_CMD_LEN + 2];
static uint32 g_column_count = 0;
static uint32 g_display_widths[GS_MAX_COLUMNS];
static bool32 g_col_display[GS_MAX_COLUMNS];
static text_t g_sql_text;
static gsql_cmd_def_t g_cmd_type;
gsc_inner_column_desc_t g_columns[GS_MAX_COLUMNS];
char g_str_buf[GS_MAX_PACKET_SIZE + 1] = { 0 };
char g_array_buf[GS_MAX_PACKET_SIZE + 1] = { 0 };
char g_sql_buf[MAX_SQL_SIZE + 4];
spinlock_t g_cancel_lock = 0;
static int32 g_in_enclosed_char = -1;
static int32 g_in_comment_count = 0;

extern char g_load_pswd[];
extern status_t loader_save_pswd(char *orig_pswd, uint32 orig_len);
extern void loader_save_user(char *orig_user, uint32 orig_len);
extern void gsql_free_user_pswd(void);

static void gsql_print_resultset(void);
static void gsql_describe_columns(void);
static void gsql_print_column_data(void);
static bool32 gsql_fetch_cmd(text_t *line, text_t *sub_cmd);
static void gsql_print_serveroutput(void);
static status_t gsql_process_autotrace_cmd(void);
/* the definition should be the same as the CLIENT_KIND_ZSQL of client_kind_t(cs_protocol.h) */
#define CLIENT_KIND_ZSQL ((int16)3)

#define GSQL_MAX_LONG_SIZE    80
#define GSQL_MAX_LOGFILE_SIZE 10000
#define GSQL_LOG_LEVEL        512

static inline void gsql_reset_in_enclosed_char(void)
{
    g_in_enclosed_char = -1;
}

/* Spool */
void gsql_spool_off(void)
{
    if (g_spool_file == GS_NULL_FILE) {
        gsql_printf("not spooling currently");
        return;
    }

    cm_close_file(g_spool_file);
    g_spool_file = GS_NULL_FILE;
    g_local_config.spool_on = GS_FALSE;
}

status_t gsql_spool_on(const char *file_name)
{
    if (g_spool_file != GS_NULL_FILE) {
        gsql_spool_off();
    }

    if (file_name != NULL) {
        return cm_open_file(file_name, O_CREAT | O_TRUNC | O_RDWR, &g_spool_file);
    }

    return GS_SUCCESS;
}

static inline void gsql_try_spool_directly_put(const char *str)
{
    text_t output_sql;

    if (g_local_config.silent_on) {
        return;
    }

    if (g_spool_file == GS_NULL_FILE) {
        return;
    }

    gsql_regular_match_sensitive(str, strlen(str), &output_sql);
    (void)cm_write_str(g_spool_file, output_sql.str);
}

void gsql_try_spool_put(const char *fmt, ...)
{
    va_list var_list;
    int32 len;
    if (g_spool_file == GS_NULL_FILE) {
        return;
    }

    va_start(var_list, fmt);
    len = vsnprintf_s(g_spool_buf, SPOOL_BUFFER_SIZE, SPOOL_BUFFER_SIZE - 1, fmt, var_list);
    PRTS_RETVOID_IFERR(len);
    va_end(var_list);
    if (len <= 0) {
        return;
    }

    if (g_local_config.trim_spool && g_spool_buf[len - 1] != '\n') {
        text_t trim_spool = { g_spool_buf, len };
        cm_trim_text(&trim_spool);
        len = trim_spool.len;
        (void)cm_write_file(g_spool_file, g_spool_buf, (uint32)len);
    } else {
        (void)cm_write_file(g_spool_file, g_spool_buf, (uint32)len);
    }
}

void gsql_set_error(const char *file, uint32 line, zs_errno_t code, const char *format, ...)
{
    va_list args;
    va_start(args, format);

    int iret;
    char log_msg[GS_MESSAGE_BUFFER_SIZE];

    iret = vsnprintf_s(log_msg, GS_MESSAGE_BUFFER_SIZE, GS_MESSAGE_BUFFER_SIZE - 1, format, args);
    PRTS_RETVOID_IFERR(iret);

    gsql_printf("ZS-%05d: %s\n", code, log_msg);

    va_end(args);
}

void gsql_get_error(gsc_conn_t conn, int *code, const char **message, source_location_t *loc)
{
    if (g_tls_error.code != GS_SUCCESS) {
        cm_get_error(code, message, loc);
        return;
    }

    gsc_get_error(conn, code, message);
    if (loc != NULL) {
        gsc_get_error_position(conn, &loc->line, &loc->column);
    }
}

/**
 * Print the error into GSQL client, if conn is null, the error may occur
 * from GSQL tools, otherwise we get the error message from conn.
 */
void gsql_print_error(gsc_conn_t conn)
{
    int code = 0;
    const char *message = "";
    source_location_t loc;

    gsql_get_error(conn, &code, &message, &loc);

    if (code == GS_SUCCESS) {
        return;
    }

    if (loc.line == 0) {
        gsql_printf("CT-%05d, %s\n", code, message);
    } else {
        gsql_printf("CT-%05d, [%d:%d]%s\n", code, (int)loc.line, (int)loc.column, message);
    }

    cm_reset_error();
}

static bool32 gsql_find_cmd(text_t *line_text, gsql_cmd_def_t *cmdtype)
{
    text_t cmd_text;
    int32 begin_pos, end_pos, mid_pos, cmp_result;
    const gsql_cmd_def_t *def = NULL;

    if (!cm_fetch_text(line_text, ' ', 0, &cmd_text)) {
        return GS_FALSE;
    }
    begin_pos = 0;
    end_pos = GSQL_CMD_COUNT - 1;

    while (end_pos >= begin_pos) {
        mid_pos = (begin_pos + end_pos) / 2;
        def = &g_cmd_defs[mid_pos];

        cmp_result = cm_compare_text_str_ins(&cmd_text, def->str);
        if (cmp_result == 0) {
            if (def->cmd == CMD_EXEC && line_text->len > 0) {
                break;
            }
            *cmdtype = *def;
            return GS_TRUE;
        } else if (cmp_result < 0) {
            end_pos = mid_pos - 1;
        } else {
            begin_pos = mid_pos + 1;
        }
    }

    *cmdtype = CMD_SQL_TYPE;  // the default is SQL_TYPE
    return GS_TRUE;
}

static int32 gsql_get_one_char()
{
#ifdef WIN32
    return _getch();
#else
    int32 char_ascii;
    struct termios oldt;
    struct termios newt;
    (void)tcgetattr(STDIN_FILENO, &oldt);
    MEMS_RETURN_IFERR(memcpy_s(&newt, sizeof(newt), &oldt, sizeof(oldt)));
    newt.c_lflag &= ~(ECHO | ICANON | ECHOE | ECHOK | ECHONL | ICRNL);
    newt.c_cc[VMIN] = 1;
    newt.c_cc[VTIME] = 0;
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    char_ascii = getchar();

    /* Restore the old setting of terminal */
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

    return char_ascii;
#endif
}

status_t gsql_recv_passwd_from_terminal(char *buff, int32 buff_size)
{
    int32 pos = 0;
    char char_ascii;
    int32 key = 0;

    if (buff == NULL) {
        return GS_ERROR;
    }
    do {
        key = gsql_get_one_char();
#ifndef WIN32
        if (key == EOF) {
            GSQL_PRINTF(ZSERR_GSQL, "gsql_get_one_char return -1 \n");
            return GS_ERROR;
        }
#endif
        char_ascii = (char)key;

#ifdef WIN32
        if (char_ascii == KEY_BS) {
#else
        if (char_ascii == KEY_BS || char_ascii == KEY_BS_LNX) {
#endif
            if (pos > 0) {
                buff[pos] = '\0';
                pos--;

                /*
                 * Recv a key of backspace, print a '\b' backing a char
                   and printing
                 * a space replacing the char displayed to screen
                   with the space.
                 */
                gsql_printf("\b");
                gsql_printf(" ");
                gsql_printf("\b");
            } else {
                continue;
            }
        } else if (char_ascii == KEY_LF || char_ascii == KEY_CR) {
            break;
        } else {
            /*
             * Only recv the limited length of pswd characters, on beyond,
             * contine to get a next char entered by user.
             */
            if (pos >= buff_size) {
                continue;
            }

            /* Faking a mask star * */
            gsql_printf("*");
            buff[pos] = char_ascii;
            pos++;
        }
    } while (GS_TRUE);

    buff[pos < buff_size ? pos : buff_size - 1] = '\0';
    gsql_printf("\n");
    return GS_SUCCESS;
}

static status_t gsql_fetch_user_with_quot(text_t *user, text_t *password)
{
    uint32 i, next;
    char quot = password->str[0];  // get double or single quotation marks
    // "@url, connection string only one quot; ""/pwd@url ---username expected at connection string
    if (password->len <= 2 || password->str[1] == quot) {
        GSQL_PRINTF(ZSERR_GSQL, "username expect");
        return GS_ERROR;
    }

    for (i = 1; i < password->len; i++) {
        if (password->str[i] != quot) {
            continue;
        } else {
            user->str = password->str + 1;
            user->len = i - 1;
            break;
        }
    }

    if (i == password->len) {  // "XXXXXX@url, only one quot find from connection string
        GSQL_PRINTF(ZSERR_GSQL, "quotation need to be used in pairs");
        return GS_ERROR;
    }

    next = i + 1;

    // fetch pwd
    if (next == password->len) {  // "user"@url, need input pwd later
        password->len = 0;
        password->str = NULL;
    } else if ((password->str[next]) != '/') {
        // "user"pwd@url, no '/' find after right quot
        GSQL_PRINTF(ZSERR_GSQL, "'/' expect between username and password");
        return GS_ERROR;
    } else {
        if ((i + 2) == password->len) {  // "user"/@url, pwd expected  at connection string
            GSQL_PRINTF(ZSERR_GSQL, "password expect");
            return GS_ERROR;
        } else {  // "user"/pwd@url  get pwd
            password->len = password->len - i - 2;
            password->str = password->str + i + 2;
        }
    }
    return GS_SUCCESS;
}

/* gsql support interactive and command mode to  input pwd */
int32 gsql_try_fetch_user_pwd(char **sql_tmp, gsql_conn_info_t *conn_info)
{
    text_t user;
    text_t password;
    uint32 quot_tag = GS_FALSE;  // if username  with quot or not
    errno_t errcode = 0;

    cm_str2text(sql_tmp[1], &password);
    /* fetch username */
    // if username with quot or not,if username with quot,may be have '/', can not direct split by '/'
    if (password.str[0] == '\"' || password.str[0] == '\'') {
        quot_tag = GS_TRUE;
        if (gsql_fetch_user_with_quot(&user, &password) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        (void)cm_fetch_text(&password, '/', 0, &user);
    }

    if (password.len != 0) {
        cm_text2str_with_upper(&user, conn_info->username, sizeof(conn_info->username));
        /* fetch pswd */
        GS_RETURN_IFERR(cm_text2str(&password, conn_info->passwd, sizeof(conn_info->passwd)));
        /* ignore the pswd */
        GS_RETURN_IFERR(cm_text_set(&password, password.len, '*'));
    } else {
        // if quot_tag is true ,need get name  after trim quot,else direct copy from sql_temp
        if (quot_tag == GS_TRUE) {
            cm_text2str_with_upper(&user, conn_info->username, sizeof(conn_info->username));
        } else {
            errcode = strncpy_s(conn_info->username, sizeof(conn_info->username), sql_tmp[1], strlen(sql_tmp[1]));
            if (errcode != EOK) {
                GS_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
                return GS_ERROR;
            }
            cm_str_upper(conn_info->username);
        }

        /* fetch pswd */
        gsql_printf("Please enter password: \n");
        if (gsql_recv_passwd_from_terminal(conn_info->passwd, sizeof(conn_info->passwd)) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (user.len > GS_NAME_BUFFER_SIZE || password.len > GS_PASSWORD_BUFFER_SIZE) {
        GSQL_PRINTF(ZSERR_GSQL, "user, password or URL overlength");
        return GS_ERROR;
    }
    if (strlen(conn_info->passwd) == 0 && password.len == 0) {
        GSQL_PRINTF(ZSERR_GSQL, "no password supplied");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t gsql_init_home(void)
{
    char *home = NULL;
    bool32 is_home_exist = GS_FALSE;

    char path[GS_MAX_PATH_BUFFER_SIZE] = { 0x00 };
    if (0 == strlen(GS_HOME)) {
        home = getenv(g_env_data);
        if (home == NULL) {
            GS_THROW_ERROR(ERR_HOME_PATH_NOT_FOUND, g_env_data);
            return GS_ERROR;
        }
        GS_RETURN_IFERR(realpath_file(home, path, GS_MAX_PATH_BUFFER_SIZE));
        if (cm_check_exist_special_char(path, (uint32)strlen(path))) {
            GS_THROW_ERROR(ERR_INVALID_DIR, home);
            return GS_ERROR;
        }
        PRTS_RETURN_IFERR(snprintf_s(GS_HOME, GS_MAX_PATH_BUFFER_SIZE, GS_MAX_PATH_BUFFER_SIZE - 1, "%s", home));
    }
    is_home_exist = cm_dir_exist(GS_HOME);
    if (is_home_exist == GS_FALSE) {
        GS_THROW_ERROR(ERR_HOME_PATH_NOT_FOUND, GS_ENV_HOME);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t gsql_get_home(void)
{
    GS_RETURN_IFERR(gsql_init_home());
    if (strlen(GS_HOME) != 0) {
        PRTS_RETURN_IFERR(snprintf_s(g_local_config.server_path, GS_UNIX_PATH_MAX, GS_UNIX_PATH_MAX - 1,
            "%s/protect/%s", GS_HOME, GSDB_UDS_EMERG_SERVER));
    }

    return GS_SUCCESS;
}

static status_t gsql_try_parse_cmd_split_normal(char **sql_tmp, int32 split_num, gsql_conn_info_t *conn_info)
{
    bool32 is_has_sysdba = GS_FALSE;
    bool32 is_has_datadir = GS_FALSE;
    if (split_num == 2) {
        GSQL_PRINTF(ZSERR_GSQL, "DB url is expected");
        return GS_ERROR;
    }

    /* "connect .../... ipc|ip:port|direct [AS SYSDBA]" */
    if (split_num == 4 || split_num >= 8) {
        GSQL_PRINTF(ZSERR_GSQL, "String \"%s\" is redundant", sql_tmp[split_num - 1]);
        return GS_ERROR;
    }

    for (int32 i = 3; i < split_num; i += 2) {
        if ((sql_tmp[i] != NULL) && (sql_tmp[i + 1] != NULL)) {
            if (cm_compare_str_ins(sql_tmp[i], (const char *)"AS") == 0) {
                if (cm_compare_str_ins(sql_tmp[i + 1], (const char *)"SYSDBA") != 0) {
                    GSQL_PRINTF(ZSERR_GSQL, "cmd error, please check cmd after url.");
                    return GS_ERROR;
                }
                if (is_has_sysdba == GS_FALSE) {
                    is_has_sysdba = GS_TRUE;
                } else {
                    GSQL_PRINTF(ZSERR_GSQL, "cmd error, please check cmd after url.");
                    return GS_ERROR;
                }
            } else if (cm_compare_str_ins(sql_tmp[i], (const char *)"-D") == 0) {
                if (!cm_dir_exist(sql_tmp[i + 1])) {
                    GSQL_PRINTF(ZSERR_GSQL, "cmd error, please check cmd after url.");
                    return GS_ERROR;
                }
                if (is_has_datadir == GS_FALSE) {
                    is_has_datadir = GS_TRUE;
                } else {
                    GSQL_PRINTF(ZSERR_GSQL, "cmd error, please check cmd after url.");
                    return GS_ERROR;
                }
            } else {
                GSQL_PRINTF(ZSERR_GSQL, "cmd error, please check cmd after url.");
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

/* check login by install user.
* "conn / as sysdba [host:port] [-D data_dir]"
*/
static status_t gsql_try_parse_cmd_split_dba(char **sql_tmp, int32 split_num, gsql_conn_info_t *conn_info)
{
    text_t text, part1, part2;
    if (split_num <= 3) {
        GSQL_PRINTF(ZSERR_GSQL,
            "\"/ AS SYSDBA [host:port] [-D data_dir] \", or \"/ AS CLSMGR [host:port] [-D data_dir] \" is expected");
        return GS_ERROR;
    }

    if (!cm_str_equal_ins(sql_tmp[1], "/")) {
        GSQL_PRINTF(ZSERR_GSQL,
            "\"/ AS SYSDBA [host:port] [-D data_dir] \", or \"/ AS CLSMGR [host:port] [-D data_dir] \" is expected");
        return GS_ERROR;
    }

    if (!cm_str_equal_ins(sql_tmp[2], "as")) {
        GSQL_PRINTF(ZSERR_GSQL,
            "\"/ AS SYSDBA [host:port] [-D data_dir] \", or \"/ AS CLSMGR [host:port] [-D data_dir] \" is expected");
        return GS_ERROR;
    }

    if (cm_str_equal_ins(sql_tmp[3], CM_SYSDBA_USER_NAME)) {
        MEMS_RETURN_IFERR(strncpy_s(conn_info->username, sizeof(conn_info->username), CM_SYSDBA_USER_NAME,
            strlen(CM_SYSDBA_USER_NAME)));
    } else if (cm_str_equal_ins(sql_tmp[3], CM_CLSMGR_USER_NAME)) {
        MEMS_RETURN_IFERR(strncpy_s(conn_info->username, sizeof(conn_info->username), CM_CLSMGR_USER_NAME,
            strlen(CM_SYSDBA_USER_NAME)));
    } else {
        GSQL_PRINTF(ZSERR_GSQL,
            "\"/ AS SYSDBA [host:port] [-D data_dir] \", or \"/ AS CLSMGR [host:port] [-D data_dir] \" is expected");
        return GS_ERROR;
    }

    conn_info->connect_by_install_user = GS_TRUE;

    for (int32 i = 4; i < split_num; i++) {
        if (cm_str_equal(sql_tmp[i], "-D")) {
            if ((i != split_num - 2) || (sql_tmp[i + 1] == NULL)) {
                GSQL_PRINTF(ZSERR_GSQL,
                    "\"/ AS SYSDBA [host:port] [-D data_dir] \", or \"/ AS CLSMGR [host:port] [-D data_dir] \" is expected");
                return GS_ERROR;
            }
            MEMS_RETURN_IFERR(strncpy_s(conn_info->home, sizeof(conn_info->home),
                sql_tmp[i + 1], strlen(sql_tmp[i + 1])));
            break;
        } else if (cm_utf8_str_like(sql_tmp[i], "%:%")) {
            cm_str2text(sql_tmp[i], &text);
            (void)cm_split_rtext(&text, ':', '\0', &part1, &part2);
            if (part1.len > CM_MAX_IP_LEN || !cm_is_short(&part2)) {
                GSQL_PRINTF(ZSERR_GSQL, "Invalid URL : %s", sql_tmp[i]);
                return GS_ERROR;
            }
        } else {
            GSQL_PRINTF(ZSERR_GSQL,
                "\"/ AS SYSDBA [host:port] [-D data_dir] \", or \"/ AS CLSMGR [host:port] [-D data_dir] \" is expected");
            return GS_ERROR;
        }
    }
    
    return GS_SUCCESS;
}

static status_t gsql_try_parse_cmd_split(char **sql_tmp, int32 split_num, gsql_conn_info_t *conn_info)
{
    if (split_num == 0 || (cm_strcmpni(sql_tmp[0], "conn", strlen("conn")) != 0 &&
        cm_strcmpni(sql_tmp[0], "connect", strlen("connect")) != 0)) {
        GSQL_PRINTF(ZSERR_GSQL, "Keyword \"CONNECT\" is expected");
        return GS_ERROR;
    }

    if (split_num == 1) {
        GSQL_PRINTF(ZSERR_GSQL,
            "\"/ AS SYSDBA [host:port] [-D data_dir] \", \"username@ip:port \", \"username/password@ip:port \", or \"/ AS CLSMGR [host:port] [-D data_dir] \" is expected");
        return GS_ERROR;
    }
    /* check login by install user.
    * "conn / as sysdba [host:port] [-D data_dir]"
    */
    if (sql_tmp[1][0] == '/') {
        return gsql_try_parse_cmd_split_dba(sql_tmp, split_num, conn_info);
    } else {
        return gsql_try_parse_cmd_split_normal(sql_tmp, split_num, conn_info);
    }
}

/************************************************************************/
/* devide sql command by character blank ' ', '\t' or '\n', words in "" */
/* are regard as one word                                               */
/************************************************************************/
static status_t gsql_local_cmd_split(text_t *conn_text,
                                     bool32 enable_mark,
                                     char **sql_split,
                                     int32 max_split_num,
                                     int32 *split_num)
{
    text_t sql_tmp;
    int32 idx = 0;

    if (sql_split == NULL || split_num == NULL) {
        return GS_ERROR;
    }

    for (idx = 0, *split_num = 0; idx < max_split_num; idx++) {
        if (!cm_fetch_text(conn_text, ' ', 0, &sql_tmp)) {
            break;
        }

        CM_NULL_TERM(&sql_tmp);
        sql_split[idx] = sql_tmp.str;

        /* trim the excrescent blank */
        cm_trim_text(conn_text);
    }

    *split_num = idx;
    if (!CM_IS_EMPTY(conn_text)) {
        GSQL_PRINTF(ZSERR_GSQL, "String \"%s\" is redundant", conn_text->str);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t gsql_split_url(text_t *conn_text, text_t *url_text, bool32 *bATFound)
{
    text_t sub_text, sub_text1;
    if (cm_fetch_rtext(conn_text, '@', '\0', &sub_text)) {
        if (conn_text->len == 0) {
            GSQL_PRINTF(ZSERR_GSQL, "no URL found after '@'");
            return GS_ERROR;
        }
        for (uint32 i = 0; i < conn_text->len; i++) {
            if (conn_text->str[i] == '-' && i + 1 <= conn_text->len && conn_text->str[i + 1] == '-') {
                url_text->len -= (conn_text->len - i);
                break;
            }
        }
        *bATFound = GS_TRUE;
        *CM_GET_TAIL(&sub_text) = ' ';
        if (cm_fetch_rtext(&sub_text, ' ', 0, &sub_text1)) {
            if (sub_text.len == 0) {
                gsql_printf("incorrect user or passwd");
                return GS_ERROR;
            }
        } else {
            gsql_printf("incorrect user or passwd");
            return GS_ERROR;
        }
    } else {
        for (uint32 i = 0; i < url_text->len; i++) {
            if (url_text->str[i] == '-' && i + 1 <= url_text->len && url_text->str[i + 1] == '-') {
                url_text->len -= (url_text->len - i);
                break;
            }
        }
    }
    return GS_SUCCESS;
}

static status_t gsql_parse_conn_sql(text_t *conn_text, gsql_conn_info_t *conn_info)
{
    char *sql_tmp[GSQL_CONN_PARAM_COUNT] = { 0 };
    int32 split_num = 0;
    status_t ret;
    bool32 bATFound = GS_FALSE;
    text_t url_text;
    int32 remote_as_sysdba = 0;
    CM_POINTER2(conn_text, conn_info);
    // get full text because it may be truncated in gsql_fetch_cmd() if including "--"
    conn_text->len = (uint32)strlen(conn_text->str);
    cm_trim_text(conn_text);
    url_text = *conn_text;
    if (!CM_IS_EMPTY(conn_text)) {
        GS_RETURN_IFERR(gsql_split_url(conn_text, &url_text, &bATFound));
    } else {
        GSQL_PRINTF(ZSERR_GSQL, "invalid connection string");
        return GS_ERROR;
    }

    ret = gsql_local_cmd_split(&url_text, GS_FALSE, sql_tmp, ELEMENT_COUNT(sql_tmp), &split_num);
    if (ret != GS_SUCCESS) {
        GSQL_PRINTF(ZSERR_GSQL, "invalid connection string");
        return GS_ERROR;
    }

    GS_RETURN_IFERR(gsql_try_parse_cmd_split(sql_tmp, split_num, conn_info));

    if (conn_info->connect_by_install_user) {
        if (cm_str_equal_ins(conn_info->username, CM_CLSMGR_USER_NAME)) {
            conn_info->is_clsmgr = GS_TRUE;
        } else {
            conn_info->is_clsmgr = GS_FALSE;
        }
        (void)gsc_set_conn_attr(conn_info->conn, GSC_ATTR_REMOTE_AS_SYSDBA, &remote_as_sysdba, sizeof(int32));
        return GS_SUCCESS;
    }

    if (!bATFound) {
        GSQL_PRINTF(ZSERR_GSQL, "\"/AS SYSDBA\", \"/ AS SYSDBA\", \"username@ip:port\", or \"/ AS CLSMGR\" is expected");
        return GS_ERROR;
    }

    GS_RETURN_IFERR(gsql_try_fetch_user_pwd(sql_tmp, conn_info));

    /* Get db connection URL */
    if (strlen(sql_tmp[2]) > sizeof(conn_info->server_url)) {
        GSQL_PRINTF(ZSERR_GSQL, "DB URL overlength");
        return GS_ERROR;
    }

    MEMS_RETURN_IFERR(strncpy_s(conn_info->server_url, sizeof(conn_info->server_url), sql_tmp[2], strlen(sql_tmp[2])));

    conn_info->connect_by_install_user = GS_FALSE;
    if ((sql_tmp[3] != NULL) && (sql_tmp[4] != NULL)) {
        if (cm_compare_str_ins(sql_tmp[3], (const char *)"AS") == 0 &&
            cm_compare_str_ins(sql_tmp[4], (const char *)"SYSDBA") == 0) {
            remote_as_sysdba = GS_TRUE;
        }
    }
    (void)gsc_set_conn_attr(conn_info->conn, GSC_ATTR_REMOTE_AS_SYSDBA, &remote_as_sysdba, sizeof(int32));
    return GS_SUCCESS;
}

static status_t gsql_load_local_server_config(void)
{
    char file_name[GS_FILE_NAME_BUFFER_SIZE];
    status_t res;

    cm_spin_lock(&g_server_config_lock, NULL);
    if (g_server_config == NULL) {
        g_server_config = (config_t *)malloc(sizeof(config_t));
        if (g_server_config == NULL) {
            cm_spin_unlock(&g_server_config_lock);
            return GS_ERROR;
        }
    }
    errno_t errcode = snprintf_s(file_name, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s/cfg/%s",
        GS_HOME, g_config_file);
    if (errcode == -1) {
        cm_spin_unlock(&g_server_config_lock);
        GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return GS_ERROR;
    }

    cm_init_config(g_client_parameters, GSQL_PARAMS_COUNT, g_server_config);
    g_server_config->ignore = GS_TRUE; /* ignore unknown parameters */
    if (!cm_file_exist((const char *)file_name)) {
        cm_spin_unlock(&g_server_config_lock);
        return GS_SUCCESS;
    }
    res = cm_read_config((const char *)file_name, g_server_config);
    cm_spin_unlock(&g_server_config_lock);

    return res;
}

static void gsql_load_zsql_config()
{
    uint32 i;
    uint32 count = 0;
    int32 iret_snprintf = -1;
    char app_path[GS_MAX_PATH_BUFFER_SIZE];
    char file_name[GS_FILE_NAME_BUFFER_SIZE];

    if (g_zsql_config == NULL) {
        // if ctclient in /opt/app/bin/ctclient, try load ctclient.ini from /opt/app/cfg/
        text_t text;
        cm_str2text(cm_sys_program_name(), &text);
        for (i = text.len; i > 0 && count < 2; i--) {
            if (text.str[i - 1] == OS_DIRECTORY_SEPARATOR) {
                count++;
            }
        }
        if (count != 2) {
            return;
        }
        text.len = i;
        (void)cm_text2str(&text, app_path, GS_MAX_PATH_BUFFER_SIZE);
        iret_snprintf = snprintf_s(file_name, GS_FILE_NAME_BUFFER_SIZE, GS_MAX_FILE_NAME_LEN, "%s/cfg/%s", app_path,
                                   g_zsql_config_file);
        if (iret_snprintf == -1 || !cm_file_exist((const char *)file_name)) {
            return;
        }

        g_zsql_config = (config_t *)malloc(sizeof(config_t));
        GS_RETVOID_IFERR(g_zsql_config == NULL);
        cm_init_config(g_ctclient_parameters, ZSQL_PARAMS_COUNT, g_zsql_config);
        g_zsql_config->ignore = GS_TRUE; /* ignore unknown parameters */

        if (GS_SUCCESS != cm_read_config((const char *)file_name, g_zsql_config)) {
            cm_free_config_buf(g_zsql_config);
            free(g_zsql_config);
            g_zsql_config = NULL;
        }
    }
}

static void gsql_init_zsql_config(void)
{
    uint32 val_uint32;
    bool32 val_bool32 = GS_FALSE;
    char *env_val = NULL;

    // load ctclient config from env or ctclient.ini
    if (g_zsql_config != NULL) {
        env_val = cm_get_config_value(g_zsql_config, "ZSQL_SSL_QUIET");
    }
    if (env_val == NULL) {
        env_val = getenv("ZSQL_SSL_QUIET");
    }
    if (env_val != NULL && cm_str2bool(env_val, &val_bool32) == GS_SUCCESS) {
        g_local_config.zsql_ssl_quiet = val_bool32;
    }

    if (g_zsql_config != NULL) {
        env_val = cm_get_config_value(g_zsql_config, "ZSQL_INTERACTION_TIMEOUT");
    }
    if (env_val == NULL) {
        env_val = getenv("ZSQL_INTERACTION_TIMEOUT");
    }
    if (env_val != NULL && cm_str2uint32(env_val, &val_uint32) == GS_SUCCESS) {
        g_local_config.zsql_interaction_timeout = val_uint32;
    }
}

static status_t gsql_read_factor_key_file(const char *name, char *key_buf, uint32 key_len)
{
    status_t ret;
    char file_name[GS_FILE_NAME_BUFFER_SIZE] = { 0 };
    int32 handle, file_size;
    uchar file_buf[GS_AESBLOCKSIZE];

    PRTS_RETURN_IFERR(snprintf_s(file_name,
        GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s/dbs/%s", GS_HOME, name));

    GS_RETURN_IFERR(cm_open_file_ex(file_name, O_SYNC | O_RDONLY | O_BINARY, S_IRUSR, &handle));
    ret = cm_read_file(handle, file_buf, sizeof(file_buf), &file_size);
    cm_close_file(handle);
    GS_RETURN_IFERR(ret);

    return cm_base64_encode((uchar *)file_buf, GS_AESBLOCKSIZE, key_buf, &key_len);
}

static status_t gsql_parse_keyfiles(text_t *value, char **files)
{
    text_t name;
    uint32 idx = 0;

    while (GS_TRUE) {
        if (!cm_fetch_text(value, ',', '\0', &name)) {
            break;
        }

        if (idx == GS_KMC_MAX_KEYFILE_NUM) {
            GS_THROW_ERROR(ERR_INVALID_PARAMETER, "KMC_KEY_FILES");
            return GS_ERROR;
        }

        cm_trim_text(&name);
        if (name.str[0] == '\'') {
            name.str++;
            name.len -= 2;
            cm_trim_text(&name);
        }

        if (name.len > GS_FILE_NAME_BUFFER_SIZE - 1) {
            gsql_printf("invalid kmc key file name, maximum length is %u\n", GS_FILE_NAME_BUFFER_SIZE);
            return GS_ERROR;
        }

        cm_convert_os_path(&name);
        PRTS_RETURN_IFERR(snprintf_s(files[idx], GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s", T2S(&name)));
        idx++;
    }

    return GS_SUCCESS;
}

status_t gsql_get_local_server_kmc_ksf(char *home)
{
    char *key_files[GS_KMC_MAX_KEYFILE_NUM] = { 0 };
    char file_name_ksfa[GS_FILE_NAME_BUFFER_SIZE] = { 0 };
    char file_name_ksfb[GS_FILE_NAME_BUFFER_SIZE] = { 0 };

    key_files[0] = file_name_ksfa;
    key_files[1] = file_name_ksfb;

    if (g_server_config == NULL) {
        GSQL_PRINTF(ZSERR_GSQL, "login failed");
        return GS_ERROR;
    }
    char *value = cm_get_config_value(g_server_config, "KMC_KEY_FILES");

    if (CM_IS_EMPTY_STR(value)) {
        PRTS_RETURN_IFERR(snprintf_s(file_name_ksfa, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1,
                                     "%s/protect/%s", home, GS_KMC_FILENAMEA));
        PRTS_RETURN_IFERR(snprintf_s(file_name_ksfb, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1,
                                     "%s/protect/%s", home, GS_KMC_FILENAMEB));
    } else {
        text_t names;
        cm_str2text(value, &names);
        cm_remove_brackets(&names);
        if (gsql_parse_keyfiles(&names, key_files) != GS_SUCCESS) {
            GSQL_PRINTF(ZSERR_GSQL, "sysdba login failed, get kmc keyfiles path failed.invalid keyfiles value %s,"
                "first keyfile %s, second keyfile %s",
                value, file_name_ksfa, file_name_ksfb);
            return GS_ERROR;
        }
    }

    if (cm_kmc_init(GS_CLIENT, (char *)file_name_ksfa, (char *)file_name_ksfb) != GS_SUCCESS) {
        GSQL_PRINTF(ZSERR_GSQL, "sysdba login failed, init key management failed.first keyfile %s, second keyfile %s",
            file_name_ksfa, file_name_ksfb);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t gsql_get_local_server_kmc_privilege(char *home, char *passwd, uint32 pwd_len, bool32 is_ztrst)
{
    int iret_snprintf;
    status_t ret;
    char file_name_priv[GS_FILE_NAME_BUFFER_SIZE] = { 0 };
    uint32 plain_str_len = pwd_len;
    uchar cipherText[GS_ENCRYPTION_SIZE] = { 0 };
    int32 handle = GS_INVALID_HANDLE;
    uint32 cipherTextLen;
    int32 file_size = 0;

    if (!is_ztrst) {
        if (gsql_get_local_server_kmc_ksf(home) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    iret_snprintf = snprintf_s(file_name_priv, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s/protect/%s",
        home, GS_KMC_PRIVILEGE);
    if (iret_snprintf == -1) {
        GSQL_PRINTF(ZSERR_GSQL, "sysdba login failed, get priv file failed");
        return GS_ERROR;
    }
    if (!cm_file_exist((const char *)file_name_priv)) {
        GSQL_PRINTF(ZSERR_GSQL, "sysdba login failed, the priv file does not exist or login as sysdba is prohibited.");
        return GS_ERROR;
    }
    if (cm_open_file_ex(file_name_priv, O_SYNC | O_RDONLY | O_BINARY, S_IRUSR, &handle) != GS_SUCCESS) {
        GSQL_PRINTF(ZSERR_GSQL, "sysdba login failed, open priv failed");
        return GS_ERROR;
    }
    ret = cm_read_file(handle, cipherText, sizeof(cipherText), &file_size);
    cm_close_file(handle);
    GS_RETURN_IFERR(ret);
    cipherTextLen = file_size;
    if (cm_kmc_decrypt(GS_KMC_SERVER_DOMAIN, cipherText, cipherTextLen, passwd, &plain_str_len) != GS_SUCCESS) {
        MEMS_RETURN_IFERR(memset_s(passwd, GS_PASSWORD_BUFFER_SIZE + GS_STR_RESERVED_LEN, 0,
            GS_PASSWORD_BUFFER_SIZE + GS_STR_RESERVED_LEN));
        return GS_ERROR;
    }
    if (cm_kmc_finalize() != GS_SUCCESS) {
        GSQL_PRINTF(ZSERR_GSQL, "sysdba login failed");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}
/* statistic consumed time of sql execute */
static void gsql_reset_timer(void)
{
    g_local_config.timer.consumed_time = 0;
}

static void gsql_get_start_time_for_timer(date_t *start_time)
{
    if (g_local_config.timer.timing_on) {
        *start_time = cm_now();
    }
}

static void gsql_get_consumed_time_for_timer(date_t start_time)
{
    if (g_local_config.timer.timing_on) {
        g_local_config.timer.consumed_time += (cm_now() - start_time);
    }
}

static void gsql_print_timer(void)
{
    if (g_local_config.timer.timing_on) {
        gsql_printf("Elapsed: %0.3f sec\n",
                    (double)g_local_config.timer.consumed_time / (GS_TIME_THOUSAND_UN * GS_TIME_THOUSAND_UN));
    }
}

static status_t gsql_decrypt_ssl_key_passwd(char *cipher, uint32 cipher_len, char *plain, uint32 *plain_len)
{
    char *local_key = NULL;
    char factor_key[GS_MAX_LOCAL_KEY_STR_LEN + 4];

    if (g_server_config == NULL) {
        GSQL_PRINTF(ZSERR_GSQL, "Load LOCAL_KEY failed");
        return GS_ERROR;
    }
    local_key = cm_get_config_value(g_server_config, "LOCAL_KEY");
    if (CM_IS_EMPTY_STR(local_key)) {
        GSQL_PRINTF(ZSERR_GSQL, "Load LOCAL_KEY failed");
        return GS_ERROR;
    }

    if (gsql_read_factor_key_file(GS_FKEY_FILENAME1, factor_key, sizeof(factor_key)) != GS_SUCCESS) {
        GSQL_PRINTF(ZSERR_GSQL, "Load _FACTOR_KEY failed");
        return GS_ERROR;
    }

    aes_and_kmc_t aes_kmc = { 0 };
    aes_kmc.fator = factor_key;
    aes_kmc.local = local_key;
    cm_kmc_set_kmc(&aes_kmc, GS_KMC_SERVER_DOMAIN, KMC_ALGID_AES256_CBC);
    cm_kmc_set_buf(&aes_kmc, plain, *plain_len, cipher, cipher_len);
    if (cm_decrypt_passwd_with_key_by_kmc(&aes_kmc) != GS_SUCCESS) {
        GSQL_PRINTF(ZSERR_GSQL, "Decrypt ssl key password failed");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t gsql_deal_local_srv(gsql_conn_info_t *conn_info, bool8 is_background)
{
    if ((conn_info->connect_by_install_user == GS_TRUE) && (is_background == GS_FALSE)) {
        if (gsql_get_home() != GS_SUCCESS) {
            if (cm_str_equal_ins(conn_info->username, CM_CLSMGR_USER_NAME)) {
                GSQL_PRINTF(ZSERR_GSQL, "\"%s\" login failed, please check -D data_dir", conn_info->username);
            } else {
                GSQL_PRINTF(ZSERR_GSQL, "\"%s\" login failed, please check CTDB_DATA environment variable or -D data_dir",
                    conn_info->username);
            }
            return GS_ERROR;
        }

        MEMS_RETURN_IFERR(strncpy_s(conn_info->server_url, sizeof(conn_info->server_url), "uds", strlen("uds")));
        
        if (gsql_get_local_server_kmc_privilege(GS_HOME, conn_info->passwd,
            GS_PASSWORD_BUFFER_SIZE + GS_STR_RESERVED_LEN, GS_FALSE) != GS_SUCCESS) {
            (void)cm_kmc_finalize();
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

static status_t gsql_set_conn_attr(gsql_conn_info_t *conn_info, bool8 is_background)
{
    /* set ssl attributes */
    (void)gsc_set_conn_attr(conn_info->conn, GSC_ATTR_SSL_MODE, &g_local_config.ssl_mode, sizeof(gsc_ssl_mode_t));
    (void)gsc_set_conn_attr(conn_info->conn, GSC_ATTR_SSL_CA, g_local_config.ssl_ca,
                            (uint32)strlen(g_local_config.ssl_ca));
    (void)gsc_set_conn_attr(conn_info->conn, GSC_ATTR_SSL_CERT, g_local_config.ssl_cert,
                            (uint32)strlen(g_local_config.ssl_cert));
    (void)gsc_set_conn_attr(conn_info->conn, GSC_ATTR_SSL_KEY, g_local_config.ssl_key,
                            (uint32)strlen(g_local_config.ssl_key));
    (void)gsc_set_conn_attr(conn_info->conn, GSC_ATTR_SSL_CRL, g_local_config.ssl_crl,
                            (uint32)strlen(g_local_config.ssl_crl));
    (void)gsc_set_conn_attr(conn_info->conn, GSC_ATTR_SSL_CIPHER, g_local_config.ssl_cipher,
                            (uint32)strlen(g_local_config.ssl_cipher));
    (void)gsc_set_conn_attr(conn_info->conn, GSC_ATTR_CONNECT_TIMEOUT, (void *)&g_local_config.connect_timeout,
                            sizeof(int32));
    (void)gsc_set_conn_attr(conn_info->conn, GSC_ATTR_SOCKET_TIMEOUT, (void *)&g_local_config.socket_timeout,
                            sizeof(int32));

    /* set uds server path, mandatory */
    if (!CM_IS_EMPTY_STR(g_local_config.server_path)) {
        (void)gsc_set_conn_attr(conn_info->conn, GSC_ATTR_UDS_SERVER_PATH,
                                g_local_config.server_path, (uint32)strlen(g_local_config.server_path));
    }
    /* set uds client path, optional */
    if (!CM_IS_EMPTY_STR(g_local_config.client_path) && !is_background) {
        (void)gsc_set_conn_attr(conn_info->conn, GSC_ATTR_UDS_CLIENT_PATH,
                                g_local_config.client_path, (uint32)strlen(g_local_config.client_path));
    }

    if (!CM_IS_EMPTY_STR(g_local_config.ssl_keypwd) && !CM_IS_EMPTY_STR(g_local_config.ssl_key)) {
        // only decrypt the cipher when needed
        char plain[GS_PASSWORD_BUFFER_SIZE];
        uint32 plain_len = GS_PASSWORD_BUFFER_SIZE;
        GS_RETURN_IFERR(gsql_decrypt_ssl_key_passwd(g_local_config.ssl_keypwd,
            (uint32)strlen(g_local_config.ssl_keypwd), plain, &plain_len));
        (void)gsc_set_conn_attr(conn_info->conn, GSC_ATTR_SSL_KEYPWD, plain, plain_len);
        MEMS_RETURN_IFERR(memset_s(plain, GS_PASSWORD_BUFFER_SIZE, 0, GS_PASSWORD_BUFFER_SIZE));
    } else {
        (void)gsc_set_conn_attr(conn_info->conn, GSC_ATTR_SSL_KEYPWD, "", 0);
    }
    return GS_SUCCESS;
}

static void gsql_conn_ssl_interaction()
{
    char confirm[GS_MAX_CMD_LEN];
    confirm[0] = '\0';

    while (GS_TRUE) {
        printf("Warning: SSL connection to server without CA certificate is insecure. Continue anyway? (y/n):");
        (void)fflush(stdout);

        timeval_t tv_begin, tv_end;
        (void)cm_gettimeofday(&tv_begin);

        while (NULL == cm_fgets_nonblock(confirm, sizeof(confirm), stdin)) {
            (void)cm_gettimeofday(&tv_end);
            if (tv_end.tv_sec - tv_begin.tv_sec > (long)g_local_config.zsql_interaction_timeout) {
                printf("\nConfirming SSL connection without CA certificate has timed out.\r\n");
                exit(EXIT_FAILURE);
            }
        }

        if (0 == cm_strcmpni(confirm, "y\n", sizeof("y\n")) ||
            0 == cm_strcmpni(confirm, "yes\n", sizeof("yes\n"))) {
            break;
        } else if (0 == cm_strcmpni(confirm, "n\n", sizeof("n\n")) ||
            0 == cm_strcmpni(confirm, "no\n", sizeof("no\n"))) {
            exit(EXIT_FAILURE);
        } else {
            printf("\n");
        }
    }

    return;
}

static status_t gsql_chk_pwd(char *input)
{
    char  plain_out[GS_ENCRYPTION_SIZE + GS_AESBLOCKSIZE];
    uchar cipher[GS_ENCRYPTION_SIZE] = { 0 };
    /* generate factor_key and work_key */
    char factor_key[GS_MAX_FACTOR_KEY_STR_LEN + 1];
    char work_key[GS_MAX_LOCAL_KEY_STR_LEN_DOUBLE + 1];
    uint32 flen = GS_MAX_FACTOR_KEY_STR_LEN + 1;
    char rand_buf[GS_AESBLOCKSIZE + 1];
    GS_RETURN_IFERR(cm_rand((uchar *)rand_buf, GS_AESBLOCKSIZE));
    GS_RETURN_IFERR(cm_base64_encode((uchar *)rand_buf, GS_AESBLOCKSIZE, factor_key, &flen));
    GS_RETURN_IFERR(cm_generate_work_key(factor_key, work_key, sizeof(work_key)));

    /* if the password has expired, fetch the new password */
    GS_RETURN_IFERR(gsql_recv_passwd_from_terminal(input, GS_PASSWORD_BUFFER_SIZE + 1));
    
    if (strlen(input) == 0) {
        gsql_printf("missing or invalid password \n");
        return GS_ERROR;
    }
    uint32 cipher_len = GS_ENCRYPTION_SIZE - 1;
    if (cm_encrypt_passwd(GS_TRUE, input, (uint32)strlen(input), (char *)cipher, &cipher_len, (char *)work_key,
        (char *)factor_key) != GS_SUCCESS) {
        MEMS_RETURN_IFERR(memset_s(input, GS_PASSWORD_BUFFER_SIZE + 1, 0, GS_PASSWORD_BUFFER_SIZE + 1));
        return GS_ERROR;
    }
    MEMS_RETURN_IFERR(memset_s(input, GS_PASSWORD_BUFFER_SIZE + 1, 0, GS_PASSWORD_BUFFER_SIZE + 1));

    gsql_printf("Retype new password: \n");
    GS_RETURN_IFERR(gsql_recv_passwd_from_terminal(input, GS_PASSWORD_BUFFER_SIZE + 1));

    uint32 plain_len = (uint32)strlen(input) + GS_AESBLOCKSIZE;
    if (cm_decrypt_passwd(GS_TRUE, (char *)cipher, cipher_len, plain_out, &plain_len, (char*)work_key,
        (char*)factor_key) != GS_SUCCESS) {
        MEMS_RETURN_IFERR(memset_s(input, GS_PASSWORD_BUFFER_SIZE + 1, 0, GS_PASSWORD_BUFFER_SIZE + 1));
        return GS_ERROR;
    }

    plain_out[plain_len] = '\0';
    if (!cm_str_equal(input, (const char *)plain_out)) {
        MEMS_RETURN_IFERR(memset_s(input, GS_PASSWORD_BUFFER_SIZE + 1, 0, GS_PASSWORD_BUFFER_SIZE + 1));
        MEMS_RETURN_IFERR(memset_s(plain_out, GS_ENCRYPTION_SIZE, 0, GS_ENCRYPTION_SIZE));
        gsql_printf("Passwords do not match \n");
        return GS_ERROR;
    }

    MEMS_RETURN_IFERR(memset_s(plain_out, GS_ENCRYPTION_SIZE, 0, GS_ENCRYPTION_SIZE));
    if (cm_verify_password_str(g_conn_info.username, input, GS_PASSWD_MIN_LEN) != GS_SUCCESS) {
        MEMS_RETURN_IFERR(memset_s(input, GS_PASSWORD_BUFFER_SIZE + 1, 0, GS_PASSWORD_BUFFER_SIZE + 1));
        gsql_printf("missing or invalid password \n");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t gsql_alt_expire_pwd(clt_conn_t *conn)
{
    text_t line;
    char cmd_sql[GS_MAX_CMD_LEN];
    char input[GS_PASSWORD_BUFFER_SIZE + 1];
    int ret_sprintf;

    gsql_printf("The user password has expired\n");
    gsql_printf("New password : \n");
    if (gsql_chk_pwd((char *)input) != GS_SUCCESS) {
        gsql_printf("Password unchanged \n");
        return GS_ERROR;
    }
    ret_sprintf = snprintf_s(cmd_sql, GS_MAX_CMD_LEN, GS_MAX_CMD_LEN - 1, "%s%s%s%s%s", "ALTER USER ",
        g_conn_info.username, " IDENTIFIED BY ", input, ";");
    if (ret_sprintf == -1) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, ret_sprintf);
        MEMS_RETURN_IFERR(memset_s(input, GS_PASSWORD_BUFFER_SIZE + 1, 0, GS_PASSWORD_BUFFER_SIZE + 1));
        return GS_ERROR;
    }
    MEMS_RETURN_IFERR(memset_s(input, GS_PASSWORD_BUFFER_SIZE + 1, 0, GS_PASSWORD_BUFFER_SIZE + 1));
    cm_str2text((char *)cmd_sql, &line);
    conn->zsql_in_altpwd = GS_TRUE;
    if (gsql_process_cmd(&line) != GS_SUCCESS) {
        conn->zsql_in_altpwd = GS_FALSE;
        return GS_ERROR;
    }

    conn->zsql_in_altpwd = GS_FALSE;
    return GS_SUCCESS;
}

/************************************************************************/
/* gsql connect to server of database                                   */
/* conn_info : connection info                                          */
/* print_conn : GS_TRUE  -- print ssl interaction info and connection   */
/*                          failure error info                          */
/*              GS_FALSE -- not print                                   */
/************************************************************************/
status_t gsql_conn_to_server(gsql_conn_info_t *conn_info, bool8 print_conn, bool8 is_background)
{
    uint32 remote_as_sysdba = GS_FALSE;
    text_t sys_user_name = { .str = SYS_USER_NAME, .len = SYS_USER_NAME_LEN };
    CM_POINTER(conn_info);

    GS_RETURN_IFERR(gsql_deal_local_srv(conn_info, is_background));
    GS_RETURN_IFERR(gsql_set_conn_attr(conn_info, is_background));

    if (print_conn && g_local_config.ssl_mode != GSC_SSL_DISABLED &&
        g_local_config.ssl_ca[0] == '\0' && g_local_config.zsql_ssl_quiet == GS_FALSE) {
        gsql_conn_ssl_interaction();
    }

    if (gsc_connect(conn_info->conn, conn_info->server_url, conn_info->username, conn_info->passwd) != GS_SUCCESS) {
        MEMS_RETURN_IFERR(memset_s(conn_info->passwd, GS_PASSWORD_BUFFER_SIZE + 4, 0, GS_PASSWORD_BUFFER_SIZE + 4));
        gsql_print_error(conn_info->conn);
        return GS_ERROR;
    }

    status_t ret = loader_save_pswd(conn_info->passwd, (uint32)strlen(conn_info->passwd));
    MEMS_RETURN_IFERR(memset_s(conn_info->passwd, GS_PASSWORD_BUFFER_SIZE + 4, 0, GS_PASSWORD_BUFFER_SIZE + 4));
    GS_RETURN_IFERR(ret);

    // if the sysdba is connectted successfully, DN reset the username as sys
    if (GS_TRUE == conn_info->connect_by_install_user) {
        PRTS_RETURN_IFERR(sprintf_s(conn_info->username, GS_NAME_BUFFER_SIZE, "%s", "SYS"));
    }
    MEMS_RETURN_IFERR(memcpy_s(conn_info->schemaname, GS_NAME_BUFFER_SIZE + GS_STR_RESERVED_LEN,
        conn_info->username, GS_NAME_BUFFER_SIZE + GS_STR_RESERVED_LEN));
    (void)gsc_get_conn_attr(conn_info->conn, GSC_ATTR_REMOTE_AS_SYSDBA, &remote_as_sysdba, sizeof(uint32), NULL);
    if (remote_as_sysdba) {
        (void)cm_text2str(&sys_user_name, conn_info->schemaname, GS_NAME_BUFFER_SIZE + GS_STR_RESERVED_LEN);
    }
    loader_save_user(conn_info->username, (uint32)strlen(conn_info->username));

    if (gsc_alloc_stmt(conn_info->conn, &conn_info->stmt) != GS_SUCCESS) {
        gsql_print_error(conn_info->conn);
        gsc_disconnect(conn_info->conn);
        return GS_ERROR;
    }

    conn_info->is_conn = GS_TRUE;

    clt_conn_t *conn = (clt_conn_t *)conn_info->conn;
    if (conn->pack.head->flags & CS_FLAG_ZSQL_IN_ALTPWD) {
        GSQL_RESET_CMD_TYPE(&g_cmd_type);
        if (gsql_alt_expire_pwd(conn) != GS_SUCCESS) {
            gsc_disconnect(conn_info->conn);
            conn_info->is_conn = GS_FALSE;
            return GS_ERROR;
        }
    } else {
        if (print_conn) {
            gsql_printf("%s\n", gsc_get_message(conn_info->conn));
        }
    }

    (void)gsc_get_conn_attr(conn_info->conn, GSC_ATTR_DBTIMEZONE, "DBTIMEZONE", 11, NULL);
    
    return GS_SUCCESS;
}

status_t gsql_connect(text_t *conn_text)
{
    status_t ret;
    gsql_conn_info_t *conn_info = NULL;

    /* 1. get the connect information */
    conn_info = &g_conn_info;
    conn_info->server_url[0] = '\0';
    conn_info->connect_by_install_user = GS_FALSE;
    
    if (IS_CONN) {
        gsc_free_stmt(STMT);
        STMT = NULL;
        gsc_disconnect(CONN);
        IS_CONN = GS_FALSE;
    }

    ret = gsql_parse_conn_sql(conn_text, conn_info);
    GS_RETURN_IFERR(ret);

    ret = gsql_conn_to_server(conn_info, GS_TRUE, GS_FALSE);
    GS_RETURN_IFERR(ret);

    return GS_SUCCESS;
}

static void gsql_get_cmd(text_t line, gsql_cmd_def_t *cmd_type, text_t *params)
{
    cm_trim_text(&line);

    if (CM_TEXT_FIRST(&line) == '-' && CM_TEXT_SECOND(&line) == '-') {
        *cmd_type = CMD_COMMENT_TYPE;
        *params = line;
        return;
    }

    if (CM_TEXT_BEGIN(&line) == '@') {
        if (CM_TEXT_SECOND(&line) == '@') {
            *cmd_type = CMD_SQLFILE_TYPE2;
            CM_REMOVE_FIRST_N(&line, 2);
            cm_trim_text(&line);
        } else {
            *cmd_type = CMD_SQLFILE_TYPE;
            CM_REMOVE_FIRST(&line);
        }

        *params = line;
        return;
    }
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    if (CM_TEXT_BEGIN(&line) == '\\' && CM_TEXT_SECOND(&line) == '!') {
        *cmd_type = CMD_SHELL_TYPE;
        CM_REMOVE_FIRST_N(&line, 2);
        *params = line;
        return;
    }
#endif
    if (CM_TEXT_END(&line) == ';' && g_in_comment_count == 0) {
        if (line.len <= 1) {
            cmd_type->cmd = CMD_EXEC;
            cmd_type->mode = MODE_NONE;
            return;
        } else {
            CM_REMOVE_LAST(&line);
        }
    }

    if (!gsql_find_cmd(&line, cmd_type)) {
        *cmd_type = CMD_NONE_TYPE;
        return;
    }
    *params = line;
}

void gsql_exit(bool32 from_whenever, status_t status)
{
    uint32 exitcommit = GS_FALSE;
    uint32 attr_len = 0;

    if (IS_CONN) {
        (void)gsc_get_conn_attr(CONN, GSC_ATTR_EXIT_COMMIT, &exitcommit, sizeof(int), &attr_len);

        if (exitcommit && !from_whenever) {
            (void)gsc_commit(CONN);
        }

        gsc_free_stmt(STMT);
        gsc_disconnect(CONN);
        gsc_free_conn(CONN);
    }

    if (g_spool_file != GS_NULL_FILE) {
        gsql_spool_off();
    }

    gsql_free_user_pswd();
    exit(status);
}

void gsql_coldesc2typmode(gsc_inner_column_desc_t *dsc, typmode_t *typmod)
{
    typmod->datatype = dsc->type + GS_TYPE_BASE;
    typmod->size = dsc->size;
    typmod->precision = (int8)dsc->precision;
    typmod->scale = (int8)dsc->scale;
    typmod->is_array = dsc->is_array;
    if (GS_IS_STRING_TYPE(typmod->datatype)) {
        typmod->is_char = (uint8)dsc->is_character;
    }
}

static status_t gsql_desc_print(void)
{
    uint32 i;
    uint32 col_name_len;
    typmode_t typmod;

    g_display_widths[0] = 32;  // max column length

    GS_RETURN_IFERR(gsc_get_stmt_attr(STMT, GSC_ATTR_COLUMN_COUNT, &g_column_count, sizeof(uint32), NULL));

    if (g_column_count == 0) {
        GS_THROW_ERROR(ERR_CLT_INVALID_VALUE, "number of columns", g_column_count);
        return GS_ERROR;
    }

    for (i = 0; i < g_column_count; i++) {
        GS_RETURN_IFERR(gsc_desc_inner_column_by_id(STMT, i, &g_columns[i]));
        col_name_len = (uint32)strlen(g_columns[i].name);
        if (g_display_widths[0] < col_name_len) {
            g_display_widths[0] = col_name_len;
        }
    }
    g_display_widths[0] += 3;

    // Step2: print title
    g_display_widths[1] = 8;
    g_display_widths[2] = 36;
    gsql_printf("%-*s%s", g_display_widths[0], "Name", g_local_config.colsep.colsep_name);
    gsql_printf("%-*s%s", g_display_widths[1], "Null?", g_local_config.colsep.colsep_name);
    gsql_printf("%-*s", g_display_widths[2], "Type");
    gsql_printf("\n");

    MEMS_RETURN_IFERR(memset_s(g_str_buf, MAX_COLUMN_WIDTH, '-', g_display_widths[0]));
    g_str_buf[g_display_widths[0]] = '\0';
    gsql_printf("%s%s", g_str_buf, g_local_config.colsep.colsep_name);

    MEMS_RETURN_IFERR(memset_s(g_str_buf, MAX_COLUMN_WIDTH, '-', g_display_widths[1]));
    g_str_buf[g_display_widths[1]] = '\0';
    gsql_printf("%s%s", g_str_buf, g_local_config.colsep.colsep_name);

    MEMS_RETURN_IFERR(memset_s(g_str_buf, MAX_COLUMN_WIDTH, '-', g_display_widths[2]));
    g_str_buf[g_display_widths[2]] = '\0';
    gsql_printf("%s\n", g_str_buf);

    // Step3: print column definition
    for (i = 0; i < g_column_count; i++) {
        gsql_coldesc2typmode(&g_columns[i], &typmod);
        gsql_printf("%-*s%s", g_display_widths[0], g_columns[i].name, g_local_config.colsep.colsep_name);
        gsql_printf("%-*s%s", g_display_widths[1], g_columns[i].nullable ? "" : "NOT NULL",
                    g_local_config.colsep.colsep_name);
        GS_RETURN_IFERR(cm_typmode2str(&typmod, g_columns[i].is_array, g_str_buf, GS_MAX_PACKET_SIZE));
        gsql_printf("%-*s\n", g_display_widths[2], g_str_buf);
    }

    return GS_SUCCESS;
}

typedef struct st_describer {
    gsc_desc_type_t type;
    char *objptr;
} describer_t;

static status_t gsql_parse_describer(text_t *params, describer_t *dsber)
{
    lex_t lex;
    sql_text_t sql_text;
    uint32 match_id;
    sql_text.value = *params;
    sql_text.loc.line = 1;
    sql_text.loc.column = 1;

    lex_init(&lex, &sql_text);
    CM_NULL_TERM(params);
    // the options corresponding to gsc_desc_type_t
    if (lex_try_fetch_1ofn(&lex, &match_id, 2, "-o", "-q") != GS_SUCCESS) {
        gsql_print_error(NULL);
        return GS_ERROR;
    }

    if (match_id == GS_INVALID_ID32 || match_id == 0) {
        word_t word;
        text_buf_t tbl_name_buf;
        tbl_name_buf.max_size = MAX_ENTITY_LEN;
        tbl_name_buf.str = g_str_buf;
        tbl_name_buf.len = 0;

        if (lex_expected_fetch_tblname(&lex, &word, &tbl_name_buf) != GS_SUCCESS ||
            lex_expected_end(&lex) != GS_SUCCESS) {
            g_tls_error.loc.line = 0;
            gsql_print_error(NULL);
            gsql_printf("Usage: DESCRIBE [schema.]object\n");
            return GS_ERROR;
        }

        CM_NULL_TERM(&tbl_name_buf);
        dsber->objptr = tbl_name_buf.str;
        dsber->type = GSC_DESC_OBJ;
        return GS_SUCCESS;
    }

    if (match_id == 1) {
        dsber->objptr = lex.curr_text->str;
        dsber->type = GSC_DESC_QUERY;
    }

    return GS_SUCCESS;
}

static status_t gsql_desc(text_t *params)
{
    int status;
    describer_t describer;

    if (!IS_CONN) {
        GSQL_PRINTF(ZSERR_GSQL, "connection is not established");
        return GS_ERROR;
    }

    cm_trim_text(params);

    if (CM_IS_EMPTY(params)) {
        gsql_printf("Usage: DESCRIBE [schema.]object\n");
        return GS_ERROR;
    }

    if (gsql_parse_describer(params, &describer) != GS_SUCCESS) {
        return GS_ERROR;
    }

    status = gsc_describle(STMT, describer.objptr, describer.type);
    if (status != GSC_SUCCESS) {
        gsql_print_error(CONN);
        return GSC_ERROR;
    }

    status = gsql_desc_print();
    if (status != GSC_SUCCESS) {
        gsql_print_error(CONN);
    }

    return status;
}

static status_t gsql_spool(text_t *params)
{
    cm_trim_text(params);
    if (cm_compare_text_str_ins(params, "OFF") == 0) {
        gsql_spool_off();
    } else {
        char buf[MAX_ENTITY_LEN];
        GS_RETURN_IFERR(cm_text2str(params, buf, MAX_ENTITY_LEN));
        if (gsql_spool_on(buf) != GS_SUCCESS) {
            gsql_print_error(NULL);
            return GS_ERROR;
        } else {
            g_local_config.spool_on = GS_TRUE;
        }
    }
    return GS_SUCCESS;
}

static uint32 gsql_get_print_column_cost(uint32 col_id, uint32 display_len)
{
    if (!g_col_display[col_id]) {
        if (display_len < g_display_widths[col_id]) {
            return g_display_widths[col_id];
        } else {
            return display_len;
        }
    } else {
        return g_display_widths[col_id];
    }
}

static void gsql_print_column_titles_ex_deal(char *temp_name, uint32 p_cost_size, uint32 p_left_size)
{
    errno_t errcode = 0;
    uint32 left_size = p_left_size;
    uint32 cost_size = p_cost_size;
    for (uint32 i = 0; i < g_column_count; i++) {
        cost_size = gsql_get_print_column_cost(i, (uint32)strlen(g_columns[i].name));
        cost_size = MIN(cost_size, left_size - 1);

        if (!g_col_display[i]) {
            MEMS_RETVOID_IFERR(memset_s(temp_name, GS_NAME_BUFFER_SIZE + 1, 0, GS_NAME_BUFFER_SIZE + 1));
            errcode = memcpy_s(temp_name, GS_NAME_BUFFER_SIZE, g_columns[i].name,
                (uint32)strlen(g_columns[i].name));
            if (errcode != EOK) {
                gsql_printf("Copying g_columns[%u].name has thrown an error %d", i, errcode);
                return;
            }
            if (cost_size < strlen(temp_name)) {
                temp_name[cost_size] = '\0';
            }

            if (i == g_column_count - 1) {
                gsql_printf("%-*s", cost_size, temp_name);
            } else {
                gsql_printf("%-*s%s", cost_size, temp_name, g_local_config.colsep.colsep_name);
            }
        } else {
            if (strlen(g_columns[i].name) < cost_size) {
                if (i == g_column_count - 1) {
                    gsql_printf("%-*s", cost_size, g_columns[i].name);
                } else {
                    gsql_printf("%-*s%s", cost_size, g_columns[i].name, g_local_config.colsep.colsep_name);
                }
            } else {
                if (i == g_column_count - 1) {
                    gsql_printf("%-.*s", cost_size, g_columns[i].name);
                } else {
                    gsql_printf("%-.*s%s", cost_size, g_columns[i].name, g_local_config.colsep.colsep_name);
                }
            }
        }

        if (left_size <= (cost_size + 1)) {
            break;
        }
        left_size -= (cost_size + 1);
    }
}

static void gsql_print_column_titles_ex(void)
{
    uint32 cost_size, left_size;
    cost_size = 0;
    char str[MAX_COLUMN_WIDTH + 1];
    char temp_name[GS_NAME_BUFFER_SIZE + 1];
    errno_t errcode = 0;
    left_size = g_local_config.line_size + 1;

    gsql_print_column_titles_ex_deal(temp_name, cost_size, left_size);

    gsql_printf("\n");

    left_size = g_local_config.line_size + 1;

    for (uint32 i = 0; i < g_column_count; i++) {
        if (g_display_widths[i] != 0) {
            errcode = memset_s(str, MAX_COLUMN_WIDTH + 1, '-', g_display_widths[i]);
            if (errcode != EOK) {
                gsql_printf("Secure C lib has thrown an error %d", errcode);
                return;
            }
        }
        str[g_display_widths[i]] = '\0';

        cost_size = MIN(g_display_widths[i], left_size - 1);
        if (cost_size < strlen(str)) {
            str[cost_size] = '\0';
        }

        if (i == g_column_count - 1) {
            gsql_printf("%s", str);
        } else {
            gsql_printf("%s%s", str, g_local_config.colsep.colsep_name);
        }

        if (left_size <= (cost_size + 1)) {
            break;
        }
        left_size -= (cost_size + 1);
    }
}

static void gsql_print_column_titles(void)
{
    uint32 i;
    char str[MAX_COLUMN_WIDTH + 1];
    errno_t errcode;

    if (g_local_config.line_size != 0) {
        gsql_print_column_titles_ex();
        return;
    }

    for (i = 0; i < g_column_count; i++) {
        if (!g_col_display[i]) {
            if (i == g_column_count - 1) {
                gsql_printf("%-*s", g_display_widths[i], g_columns[i].name);
            } else {
                gsql_printf("%-*s%s", g_display_widths[i], g_columns[i].name, g_local_config.colsep.colsep_name);
            }
        } else {
            if (strlen(g_columns[i].name) < g_display_widths[i]) {
                if (i == g_column_count - 1) {
                    gsql_printf("%-*s", g_display_widths[i], g_columns[i].name);
                } else {
                    gsql_printf("%-*s%s", g_display_widths[i], g_columns[i].name, g_local_config.colsep.colsep_name);
                }
            } else {
                if (i == g_column_count - 1) {
                    gsql_printf("%-.*s", g_display_widths[i], g_columns[i].name);
                } else {
                    gsql_printf("%-.*s%s", g_display_widths[i], g_columns[i].name, g_local_config.colsep.colsep_name);
                }
            }
        }
    }

    gsql_printf("\n");

    for (i = 0; i < g_column_count; i++) {
        if (g_display_widths[i] != 0) {
            errcode = memset_s(str, MAX_COLUMN_WIDTH + 1, '-', g_display_widths[i]);
            if (errcode != EOK) {
                gsql_printf("Secure C lib has thrown an error %d", errcode);
                return;
            }
        }
        str[g_display_widths[i]] = '\0';
        if (i == g_column_count - 1) {
            gsql_printf("%s", str);
        } else {
            gsql_printf("%s%s", str, g_local_config.colsep.colsep_name);
        }
    }
}

static gsql_column_format_attr_t *gsql_get_column_attr(text_t *column);

static void gsql_describe_columns_type(uint32 name_len, uint32 p_byte_ratio, uint32 index)
{
    uint32 byte_ratio = p_byte_ratio;
    switch (g_columns[index].type) {
        case GSC_TYPE_BIGINT:
        case GSC_TYPE_REAL:
            g_display_widths[index] = MAX(GS_MAX_UINT64_STRLEN, name_len);
            break;

            // for the case var + null
        case GSC_TYPE_UNKNOWN:
            g_display_widths[index] = MAX(GS_MAX_UINT32_STRLEN, name_len);
            break;

        case GSC_TYPE_INTEGER:
            g_display_widths[index] = MAX(GS_MAX_INT32_STRLEN + 1, name_len);
            break;

        case GSC_TYPE_UINT32:
            g_display_widths[index] = MAX(12, name_len);
            break;
        case GSC_TYPE_BOOLEAN:
            g_display_widths[index] = MAX(GS_MAX_BOOL_STRLEN + 1, name_len);
            break;

        case GSC_TYPE_NUMBER:
        case GSC_TYPE_DECIMAL:
        case GSC_TYPE_NUMBER2: {
            uint32 num_width = GS_MAX_DEC_OUTPUT_PREC;
            (void)gsc_get_conn_attr(CONN, GSC_ATTR_NUM_WIDTH, &num_width, sizeof(uint32), NULL);
            g_display_widths[index] = MAX(num_width, name_len);
            break;
        }

        case GSC_TYPE_DATE:
            g_display_widths[index] = MAX(GS_MAX_DATE_STRLEN, name_len);
            break;

        case GSC_TYPE_TIMESTAMP:
        case GSC_TYPE_TIMESTAMP_TZ_FAKE:
        case GSC_TYPE_TIMESTAMP_LTZ:
            g_display_widths[index] = MAX(GS_MAX_TIMESTAMP_STRLEN, name_len);
            break;

        case GSC_TYPE_INTERVAL_YM:
            g_display_widths[index] = MAX(GS_MAX_YM_INTERVAL_STRLEN, name_len);
            break;

        case GSC_TYPE_INTERVAL_DS:
            g_display_widths[index] = MAX(GS_MAX_DS_INTERVAL_STRLEN, name_len);
            break;

        case GSC_TYPE_TIMESTAMP_TZ:
            g_display_widths[index] = MAX(GS_MAX_TZ_STRLEN, name_len);
            break;

        case GSC_TYPE_VARCHAR:
        case GSC_TYPE_CHAR:
        case GSC_TYPE_STRING:
            byte_ratio = g_columns[index].is_character ? GS_CHAR_TO_BYTES_RATIO : 1;
            g_display_widths[index] = (g_columns[index].size * byte_ratio > GS_MAX_MIN_VALUE_SIZE) ? GS_MAX_MIN_VALUE_SIZE :
                (g_columns[index].size * byte_ratio < name_len) ? name_len : g_columns[index].size * byte_ratio;
            break;

        default:
            g_display_widths[index] = GS_MAX_MIN_VALUE_SIZE;
            break;
    }
}

static void gsql_describe_columns(void)
{
    uint32 i, name_len;
    uint32 byte_ratio = 0;
    text_t column_name;
    gsql_column_format_attr_t *col_attr = NULL;

    (void)gsc_get_stmt_attr(STMT, GSC_ATTR_COLUMN_COUNT, &g_column_count, sizeof(uint32), NULL);
    if (g_column_count > GS_MAX_COLUMNS) {
        return;
    }
    for (i = 0; i < g_column_count; i++) {
        (void)gsc_desc_inner_column_by_id(STMT, i, &g_columns[i]);

        name_len = (uint32)strlen(g_columns[i].name);

        // set display widths if set column info(col column_name for aN)
        column_name.str = g_columns[i].name;
        column_name.len = name_len;
        col_attr = gsql_get_column_attr(&column_name);
        if (col_attr != NULL && col_attr->is_on) {
            g_col_display[i] = GS_TRUE;
            g_display_widths[i] = col_attr->col_width;
            continue;
        } else {
            g_col_display[i] = GS_FALSE;
        }

        if (g_columns[i].is_array) {
            g_display_widths[i] = GS_MAX_MIN_VALUE_SIZE;
            continue;
        }

        gsql_describe_columns_type(name_len, byte_ratio, i);
    }

    if (g_local_config.heading_on) {
        gsql_print_column_titles();
        gsql_printf("\n");
    }
}

static status_t gsql_get_column_as_string(gsc_stmt_t stmt, uint32 col, char *buf, uint32 buf_len)
{
    uint32 i, size;
    void *data = NULL;
    bool32 is_null = GS_FALSE;
    gsc_inner_column_desc_t col_info;

    GS_RETURN_IFERR(gsc_desc_inner_column_by_id(stmt, col, &col_info));

    // binary will be converted to string
    if (col_info.type != GSC_TYPE_STRING || col_info.is_array) {
        return gsc_column_as_string(stmt, col, buf, buf_len);
    }
    GS_RETURN_IFERR(gsc_get_column_by_id(stmt, col, &data, &size, &is_null));

    if (is_null) {
        buf[0] = '\0';
        return GS_SUCCESS;
    }

    size = (size >= buf_len - 1) ? buf_len - 1 : size;
    if (size > 0) {
        MEMS_RETURN_IFERR(memcpy_s(buf, buf_len, data, size));
    }
    buf[size] = '\0';

    for (i = 0; i < size; ++i) {
        if (buf[i] == '\0') {
            buf[i] = ' ';
        }
    }
    return GS_SUCCESS;
}

static void gsql_print_column_data_ex(void)
{
    uint32 i, cost_size;
    uint32 left_size = g_local_config.line_size + 1;

    for (i = 0; i < g_column_count; i++) {
        if (gsql_get_column_as_string(STMT, i, g_str_buf, GS_MAX_PACKET_SIZE) != GS_SUCCESS) {
            GSQL_PRINTF(ZSERR_GSQL, "the %d column print failed", i);
            continue;
        }

        cost_size = gsql_get_print_column_cost(i, (uint32)strlen(g_str_buf));
        cost_size = MIN(cost_size, left_size - 1);

        if (!g_col_display[i]) {
            if (cost_size < strlen(g_str_buf)) {
                g_str_buf[cost_size] = '\0';
            }

            if (i == g_column_count - 1) {
                gsql_printf("%-*s", cost_size, g_str_buf);
            } else {
                gsql_printf("%-*s%s", cost_size, g_str_buf, g_local_config.colsep.colsep_name);
            }
        } else {
            if (strlen(g_str_buf) < cost_size) {
                if (i == g_column_count - 1) {
                    gsql_printf("%-*s", cost_size, g_str_buf);
                } else {
                    gsql_printf("%-*s%s", cost_size, g_str_buf, g_local_config.colsep.colsep_name);
                }
            } else {
                if (i == g_column_count - 1) {
                    gsql_printf("%-.*s", cost_size, g_str_buf);
                } else {
                    gsql_printf("%-.*s%s", cost_size, g_str_buf, g_local_config.colsep.colsep_name);
                }
            }
        }

        if (left_size <= (cost_size + 1)) {
            break;
        }
        left_size -= (cost_size + 1);
    }

    gsql_printf("\n");
}

static void gsql_print_column_data(void)
{
    uint32 i;

    if (g_local_config.line_size != 0) {
        gsql_print_column_data_ex();
        return;
    }

    for (i = 0; i < g_column_count; i++) {
        (void)gsql_get_column_as_string(STMT, i, g_str_buf, GS_MAX_PACKET_SIZE);

        if (!g_col_display[i]) {
            if (i == g_column_count - 1) {
                gsql_printf("%-*s", g_display_widths[i], g_str_buf);
            } else {
                gsql_printf("%-*s%s", g_display_widths[i], g_str_buf, g_local_config.colsep.colsep_name);
            }
        } else {
            if (strlen(g_str_buf) < g_display_widths[i]) {
                if (i == g_column_count - 1) {
                    gsql_printf("%-*s", g_display_widths[i], g_str_buf);
                } else {
                    gsql_printf("%-*s%s", g_display_widths[i], g_str_buf, g_local_config.colsep.colsep_name);
                }
            } else {
                if (i == g_column_count - 1) {
                    gsql_printf("%-.*s", g_display_widths[i], g_str_buf);
                } else {
                    gsql_printf("%-.*s%s", g_display_widths[i], g_str_buf, g_local_config.colsep.colsep_name);
                }
            }
        }
    }

    gsql_printf("\n");
}

static void gsql_print_resultset(void)
{
    uint32 rows;
    uint32 rows_print, rows_one_page;
    uint32 newpage = 0;
    date_t start_time = 0;

    rows_print = 0;
    rows_one_page = g_local_config.page_size - GS_MIN_PAGESIZE + 1;

    gsql_describe_columns();

    gsql_get_start_time_for_timer(&start_time);
    if (gsc_fetch(STMT, &rows) != GS_SUCCESS) {
        gsql_print_error(CONN);
        return;
    }
    gsql_get_consumed_time_for_timer(start_time);

    while (rows > 0) {
        if (GSQL_CANCELING) {
            return;
        }

        gsql_print_column_data();
        rows_print++;

        gsql_get_start_time_for_timer(&start_time);
        if (gsc_fetch(STMT, &rows) != GS_SUCCESS) {
            gsql_print_error(CONN);
            return;
        }
        gsql_get_consumed_time_for_timer(start_time);

        if (rows > 0 && rows_print == rows_one_page) {
            for (newpage = 0; newpage < g_local_config.newpage; newpage++) {
                gsql_printf("\n");
            }

            // already set g_display_widths[GS_MAX_COLUMNS] in gsql_describe_columns
            if (g_local_config.heading_on) {
                gsql_print_column_titles();
                gsql_printf("\n");
            }

            rows_print = 0;
        }
    }
}

#define SQL_COMMAND_LENGTH (MAX_CMD_LEN + 2)
static status_t check_first_character(char input)
{
    if ((input >= 'a' && input <= 'z') ||
        (input >= 'A' && input <= 'Z') ||
        (input >= '0' && input <= '9') ||
        (input == '_')) {
        return GS_TRUE;
    }

    return GS_FALSE;
}

static void gsql_replace_function(text_t *line)
{
    text_t *input = line;
    uint32 i = 0;
    uint32 is_first_mark = 1;
    char replace_info[GS_BUFLEN_128] = { 0 };
    char variable_info[GS_BUFLEN_128] = { 0 };
    char remain[SQL_COMMAND_LENGTH + 1] = { 0 };
    char oldsql[SQL_COMMAND_LENGTH + 1] = { 0 };
    uint32 beg = 0;
    uint32 beg1 = 0;
    uint32 end = 0;
    uint32 copy_len = 0;
    uint32 is_print_old_new = 0;
    errno_t tmp;

    if (input->len > SQL_COMMAND_LENGTH) {
        printf("The length [%u] of the input sql is out of range", input->len);
        return;
    }
    tmp = strncpy_s(oldsql, SQL_COMMAND_LENGTH + 1, input->str, input->len);
    if (tmp != EOK) {
        gsql_printf("Error [%d], max length is [%d], and input length is [%u]",
            tmp, SQL_COMMAND_LENGTH, input->len);
        return;
    }
    oldsql[input->len] = '\0';

    for (i = 0; i < input->len; i++) {
        if ((input->str[i] == g_replace_mark) && (is_first_mark == 1)) {  // find g_replace_mark ,if not match ,continue
            is_first_mark = 0;
            is_print_old_new = 1;
            ++i;
            beg1 = i;
            while (input->str[i] == ' ') {
                i++;
            }
            if (i == input->len || input->str[i] == '\n') {  // protect
                gsql_printf("sql is:%s\n", input->str);
                GSQL_PRINTF(ZSERR_GSQL, "Invalid variable, Replace mark '%c' cannot be at the end of every line", g_replace_mark);
                return;
            }
            if (check_first_character(input->str[i]) == GS_FALSE) {
                GSQL_PRINTF(ZSERR_GSQL, "Invalid variable, variable should be a~z, A~Z, 0~9 or _");
                return;
            }
            beg = i;
        }

        if ((is_first_mark == 0) &&
            (check_first_character(input->str[i]) == GS_FALSE || i == input->len - 1)) {
            if (i == input->len - 1) {
                end = i + 1;
            } else {
                end = i;
            }
            is_first_mark = 1;

            // first
            tmp = memset_s(remain, sizeof(remain), 0, sizeof(remain));
            if (tmp != EOK) {
                gsql_printf("An error [%d] occurred when memset remainning old sql.", tmp);
                return;
            }
            copy_len = input->len - end;
            if (copy_len > SQL_COMMAND_LENGTH) {
                gsql_printf("The length [%u] of the remainning old sql is out of range.", copy_len);
                return;
            }

            if (copy_len > 0) {
                tmp = strncpy_s(remain, sizeof(remain), input->str + end, copy_len);
                if (tmp != EOK) {
                    gsql_printf("Error [%d], max length is [%d], and the length of remainning old sql is [%u].",
                        tmp, SQL_COMMAND_LENGTH, copy_len);
                    return;
                }
            }
            remain[copy_len] = '\0';
            input->len = beg1 - 1;

            // second, show the variable_info
            tmp = memset_s(variable_info, sizeof(variable_info), 0, sizeof(variable_info));
            if (tmp != EOK) {
                gsql_printf("An error occurred when memset variable, error [%d]", tmp);
                return;
            }
            copy_len = end - beg;
            if (copy_len >= GS_BUFLEN_128) {
                gsql_printf("The length [%u] of variable to be replaced is out of range.", copy_len);
                return;
            }

            if (copy_len > 0) {
                tmp = strncpy_s(variable_info, sizeof(variable_info), input->str + beg, copy_len);
                if (tmp != EOK) {
                    gsql_printf("Error [%d], max length is [%d], and the length of the variable being replaced "
                        "is [%u].", tmp, GS_BUFLEN_128 - 1, copy_len);
                    return;
                }
            }
            variable_info[copy_len] = '\0';
            gsql_printf("Enter value for %s:", variable_info);

            // third, waiting for user input
            (void)fflush(stdout);
            if (NULL == fgets(replace_info, sizeof(replace_info), stdin)) {
                return;
            }

            copy_len = (uint32)strlen(replace_info);
            if (copy_len == 0) {
                gsql_printf("The length of the replacement variable cannot be 0.");
                return;
            }

            gsql_printf("\n");
            replace_info[copy_len - 1] = '\0';

            // fourth
            copy_len = (uint32)strlen(replace_info);
            if (copy_len > SQL_COMMAND_LENGTH - input->len) {
                gsql_printf("The length [%u] of the replacement variable is is out of range.", copy_len);
                return;
            }

            if (copy_len != 0) {
                tmp = strncpy_s(input->str + input->len, SQL_COMMAND_LENGTH - input->len, replace_info, copy_len);
                if (tmp != EOK) {
                    gsql_printf("Error %d, the remaining length is [%u], and the actual input length is [%u].",
                        tmp, SQL_COMMAND_LENGTH - input->len, copy_len);
                    return;
                }
            }
            input->len += copy_len;

            // fifth
            i = input->len;
            beg = input->len;
            end = input->len;

            // sixth
            copy_len = (uint32)strlen(remain);
            if (copy_len > SQL_COMMAND_LENGTH - input->len) {
                gsql_printf("The length of the new sql is [%u], which is out of range.", copy_len);
                return;
            }

            if (copy_len != 0) {
                tmp = strncpy_s(input->str + input->len, SQL_COMMAND_LENGTH - input->len, remain, copy_len);
                if (tmp != EOK) {
                    gsql_printf("Error %d, max lenght is [%d], and the length of the new sql is[%u].",
                        tmp, SQL_COMMAND_LENGTH, input->len + copy_len);
                    return;
                }
            }
            input->len += copy_len;
            input->str[input->len] = '\0';
            i--;
        }
    }

    if (is_print_old_new == 1 && g_local_config.verify_on == GS_TRUE) {
        gsql_printf("old sql is : %s\n", oldsql);
        gsql_printf("new sql is : %s\n", line->str);
    }
    return;
}

status_t gsql_execute_sql(void)
{
    uint32 param_count = 0;
    date_t start_time = 0;
    text_t sql_text;
    bool32 seroutput_exists = GS_FALSE;
    uint32 stmt_type = GSC_STMT_NONE;

    if (!IS_CONN) {
        GSQL_PRINTF(ZSERR_GSQL, "connection is not established");
        return GS_ERROR;
    }

    cm_str2text(g_sql_buf, &sql_text);

    if (g_local_config.define_on == GS_TRUE) {
        gsql_replace_function(&sql_text);  // replace function. IforNot GS_RETURN_IFERR
    }

    gsql_get_start_time_for_timer(&start_time);
    if (gsc_prepare(STMT, g_sql_buf) != GS_SUCCESS) {
        gsql_get_consumed_time_for_timer(start_time);
        gsql_print_error(CONN);
        return GS_ERROR;
    }

    gsql_get_consumed_time_for_timer(start_time);

    GS_RETURN_IFERR(gsc_get_stmt_attr(STMT, GSC_ATTR_STMT_TYPE, (const void *)&stmt_type, sizeof(uint32), NULL));

    /* explain stmt do not handle binding parameters */
    if (stmt_type != GSC_STMT_EXPLAIN  || g_local_config.bindparam_force_on) {
        GS_RETURN_IFERR(gsc_get_stmt_attr(STMT, GSC_ATTR_PARAM_COUNT, (const void *)&param_count, sizeof(uint32),
                                          NULL));

        GS_RETURN_IFERR(gsql_bind_param_init(param_count));

        if (gsql_bind_params(STMT, param_count) != GS_SUCCESS) {
            gsql_bind_param_uninit(param_count);
            return GS_ERROR;
        }
    }

    gsql_get_start_time_for_timer(&start_time);
    if (gsc_execute(STMT) != GS_SUCCESS) {
        (void)gsc_get_stmt_attr(STMT, GSC_ATTR_SEROUTPUT_EXISTS, &seroutput_exists, sizeof(uint32), NULL);
        if (seroutput_exists) {
            gsql_print_serveroutput();
        }

        gsql_get_consumed_time_for_timer(start_time);
        gsql_bind_param_uninit(param_count);
        gsql_print_error(CONN);
        return GS_ERROR;
    }
    gsql_get_consumed_time_for_timer(start_time);
    gsql_bind_param_uninit(param_count);
    return GS_SUCCESS;
}

static void gsql_print_serveroutput(void)
{
    char *output_str = NULL;
    uint32 output_len;
    int32 rows;

    rows = gsc_fetch_serveroutput(STMT, &output_str, &output_len);
    while (rows == 1) {
        gsql_printf("%s\n", output_str);

        rows = gsc_fetch_serveroutput(STMT, &output_str, &output_len);
    }
}

static void gsql_print_returnresult(void)
{
    gsc_stmt_t resultset = NULL;
    gsc_stmt_t org_stmt = NULL;
    uint32 pos = 0;

    if (gsc_get_implicit_resultset(STMT, &resultset) != GS_SUCCESS) {
        gsql_print_error(CONN);
        return;
    }

    while (resultset != NULL) {
        pos++;
        gsql_printf("ResultSet #%u\n", pos);
        gsql_printf("\n");

        org_stmt = g_conn_info.stmt;
        g_conn_info.stmt = resultset;
        gsql_print_result();
        g_conn_info.stmt = org_stmt;

        if (gsc_get_implicit_resultset(STMT, &resultset) != GS_SUCCESS) {
            gsql_print_error(CONN);
            return;
        }

        if (resultset != NULL) {
            gsql_printf("\n");
        }
    }
}

static void gsql_print_outparams()
{
    uint32 outparam_count = 0;
    uint32 rows, i;
    gsc_outparam_desc_t def;
    char *data = NULL;
    uint32 size, is_null;
    gsc_stmt_t org_stmt;

    (void)gsc_get_stmt_attr(STMT, GSC_ATTR_OUTPARAM_COUNT, &outparam_count, sizeof(uint32), NULL);
    if (outparam_count == 0) {
        return;
    }

    if (gsc_fetch_outparam(STMT, &rows) != GS_SUCCESS) {
        gsql_print_error(CONN);
        return;
    }

    for (i = 0; i < outparam_count; i++) {
        if (gsc_desc_outparam_by_id(STMT, i, &def) != GSC_SUCCESS ||
            gsc_get_outparam_by_id(STMT, i, (void **)&data, &size, &is_null) != GSC_SUCCESS) {
            gsql_print_error(CONN);
            return;
        }

        gsql_printf("OutParam #%u\n", i + 1);
        gsql_printf("\n");
        gsql_printf("name=[%s]\n", def.name);
        gsql_printf("direction=[%u]\n", def.direction);
        gsql_printf("type=[%s]\n", get_datatype_name_str(def.type + GS_TYPE_BASE));

        if (size == GSC_NULL) {
            gsql_printf("value=[%s]\n", "NULL");
            continue;
        }

        g_str_buf[0] = '\0';
        if (gsc_outparam_as_string_by_id(STMT, i, g_str_buf, GS_MAX_PACKET_SIZE) != GS_SUCCESS) {
            gsql_print_error(CONN);
            return;
        }
        gsql_printf("value=[%s]\n", g_str_buf);

        if (def.type == GSC_TYPE_CURSOR) {
            org_stmt = g_conn_info.stmt;
            g_conn_info.stmt = (gsc_stmt_t)data;
            gsql_print_result();
            g_conn_info.stmt = org_stmt;
        }

        if (i < outparam_count - 1) {
            gsql_printf("\n");
        }
    }
}

static inline void gsql_print_result_DML(bool32 seroutput_exists, bool32 returnresult_exists)
{
    uint32 rows = 0;

    if (seroutput_exists) {
        gsql_print_serveroutput();
        gsql_printf("\n");
    }

    if (returnresult_exists) {
        gsql_print_returnresult();
        gsql_printf("\n");
    }

    if (g_local_config.feedback.feedback_on) {
        (void)gsc_get_stmt_attr(STMT, GSC_ATTR_AFFECTED_ROWS, &rows, sizeof(uint32), NULL);
        gsql_printf("%u rows affected.\n", rows);
        gsql_printf("\n");
    }
}

static inline void gsql_print_result_PL(bool32 seroutput_exists, bool32 returnresult_exists)
{
    uint32 outparam_count = 0;

    (void)gsc_get_stmt_attr(STMT, GSC_ATTR_OUTPARAM_COUNT, &outparam_count, sizeof(uint32), NULL);

    if (seroutput_exists) {
        gsql_print_serveroutput();
        gsql_printf("\n");
    }

    if (g_local_config.feedback.feedback_on) {
        gsql_printf("PL/SQL procedure successfully completed.\n");
        gsql_printf("\n");
    }

    if (outparam_count > 0) {
        gsql_print_outparams();
        gsql_printf("\n");
    }

    if (returnresult_exists) {
        gsql_print_returnresult();
        gsql_printf("\n");
    }
}

void gsql_no_print_result()
{
    bool32 rs_exists = GS_FALSE;
    date_t start_time = 0;
    uint32 rows;

    (void)gsc_get_stmt_attr(STMT, GSC_ATTR_RESULTSET_EXISTS, &rs_exists, sizeof(uint32), NULL);

    if (rs_exists) {
        gsql_get_start_time_for_timer(&start_time);
        if (gsc_fetch(STMT, &rows) != GS_SUCCESS) {
            gsql_print_error(CONN);
            return;
        }
        gsql_get_consumed_time_for_timer(start_time);

        while (rows > 0) {
            if (GSQL_CANCELING) {
                return;
            }

            gsql_get_start_time_for_timer(&start_time);
            if (gsc_fetch(STMT, &rows) != GS_SUCCESS) {
                gsql_print_error(CONN);
                return;
            }
            gsql_get_consumed_time_for_timer(start_time);
        }
    }
}

void gsql_print_result(void)
{
    bool32 rs_exists = GS_FALSE;
    bool32 seroutput_exists = GS_FALSE;
    bool32 returnresult_exists = GS_FALSE;
    uint32 rows = 0;
    uint32 stmt_type = GSC_STMT_NONE;
    char *message = NULL;

    (void)gsc_get_stmt_attr(STMT, GSC_ATTR_RESULTSET_EXISTS, &rs_exists, sizeof(uint32), NULL);
    (void)gsc_get_stmt_attr(STMT, GSC_ATTR_SEROUTPUT_EXISTS, &seroutput_exists, sizeof(uint32), NULL);
    (void)gsc_get_stmt_attr(STMT, GSC_ATTR_RETURNRESULT_EXISTS, &returnresult_exists, sizeof(uint32), NULL);
    (void)gsc_get_stmt_attr(STMT, GSC_ATTR_STMT_TYPE, &stmt_type, sizeof(uint32), NULL);

    if (rs_exists) {
        gsql_print_resultset();
        gsql_printf("\n");
        if (g_local_config.feedback.feedback_on) {
            (void)gsc_get_stmt_attr(STMT, GSC_ATTR_FETCHED_ROWS, &rows, sizeof(uint32), NULL);
            if (g_local_config.feedback.feedback_rows == 1 || rows >= g_local_config.feedback.feedback_rows) {
                gsql_printf("%u rows fetched.\n", rows);
                gsql_printf("\n");
            }
        }
        if (seroutput_exists) {
            gsql_print_serveroutput();
            gsql_printf("\n");
        }
        if (returnresult_exists) {
            gsql_print_returnresult();
            gsql_printf("\n");
        }
    } else if (stmt_type == GSC_STMT_DML) {
        gsql_print_result_DML(seroutput_exists, returnresult_exists);
    } else if (stmt_type == GSC_STMT_PL) {
        gsql_print_result_PL(seroutput_exists, returnresult_exists);
    } else {
        if (g_local_config.feedback.feedback_on) {
            gsql_printf("Succeed.\n");

            message = gsc_get_message(CONN);
            if (stmt_type == GSC_STMT_DDL && message != NULL && message[0] != '\0') {
                gsql_printf("Warning:\n");
                gsql_printf("%s\n", message);
            }

            gsql_printf("\n");
        }
    }
}

static void gsql_exec_whenever()
{
    if (g_local_config.whenever.commit_type == 0) {
        (void)gsc_rollback(CONN);
    } else {
        (void)gsc_commit(CONN);
    }

    if (g_local_config.whenever.continue_type == 0) {
        gsql_exit(GS_TRUE, 0);
    }

    g_local_config.whenever.is_on = GS_FALSE;
}

static inline status_t gsql_concat(text_t *line);

static bool32 gsc_if_need_trace()
{
    uint32 stmt_type = GSC_STMT_NONE;
    bool32 seroutput_exists = GS_FALSE;
    bool32 returnresult_exists = GS_FALSE;

    (void)gsc_get_stmt_attr(STMT, GSC_ATTR_STMT_TYPE, (const void *)&stmt_type, sizeof(uint32), NULL);
    (void)gsc_get_stmt_attr(STMT, GSC_ATTR_SEROUTPUT_EXISTS, &seroutput_exists, sizeof(uint32), NULL);
    (void)gsc_get_stmt_attr(STMT, GSC_ATTR_RETURNRESULT_EXISTS, &returnresult_exists, sizeof(uint32), NULL);

    if (stmt_type != GSC_STMT_DML || seroutput_exists || returnresult_exists) {
        return GS_FALSE;
    }
    return GS_TRUE;
}

status_t gsql_execute(text_t *line)
{
    text_t output_sql;

    if (line != NULL) {
        (void)cm_text_set(&g_sql_text, g_sql_text.len, '\0');
        CM_TEXT_CLEAR(&g_sql_text);
        GS_RETURN_IFERR(gsql_concat(line));
    }

    if (cm_abs64(g_sql_text.str + g_sql_text.len - g_sql_buf) > MAX_SQL_SIZE) {
        GSQL_PRINTF(ZSERR_GSQL, "execute sql length exceed maxsize(%u)", MAX_SQL_SIZE);
        return GS_ERROR;
    }

    CM_NULL_TERM(&g_sql_text);

    if (g_local_config.print_on) {
        gsql_regular_match_sensitive(g_sql_buf, strlen(g_sql_buf), &output_sql);
        gsql_printf("%s;", output_sql.str);
    }

    gsql_printf("\n");
    status_t ret = GS_SUCCESS;

    do {
        if (!IS_CONN) {
            GSQL_PRINTF(ZSERR_GSQL, "connection is not established");
            ret = GS_ERROR;
            break;
        }

        /* execute sql and print result */
        gsql_reset_timer();

        if (gsql_execute_sql() != GS_SUCCESS) {
            gsql_print_timer();

            if (g_local_config.whenever.is_on) {
                gsql_exec_whenever();
            }
            ret = GS_ERROR;
            break;
        }
    } while (0);
    
    MEMS_RETURN_IFERR(memset_s(g_sql_buf, sizeof(g_sql_buf), 0, g_sql_text.len));
    CM_TEXT_CLEAR(&g_sql_text);
    GS_RETURN_IFERR(ret);

    if (g_local_config.trace_mode == GSQL_TRACE_ONLY && gsc_if_need_trace()) {
        gsql_no_print_result();
    } else {
        gsql_print_result();
    }

    gsql_print_timer();
    return GS_SUCCESS;
}

static inline status_t gsql_concat(text_t *line)
{
    if (line->len + g_sql_text.len + 1 > MAX_SQL_SIZE) {
        GSQL_PRINTF(ZSERR_GSQL, "the SQL size too long ( > %u characters)", MAX_SQL_SIZE);
        return GS_ERROR;
    }

    cm_concat_text(&g_sql_text, MAX_SQL_SIZE, line);
    return GS_SUCCESS;
}
static inline status_t gsql_concat_appendlf(text_t *line)
{
    if (line->len + g_sql_text.len + 1 > MAX_SQL_SIZE) {
        GSQL_PRINTF(ZSERR_GSQL, "the SQL size too long ( > %u characters)", MAX_SQL_SIZE);
        return GS_ERROR;
    }

    if (!CM_IS_EMPTY(&g_sql_text)) {
        CM_TEXT_APPEND(&g_sql_text, '\n');
    }

    cm_concat_text(&g_sql_text, MAX_SQL_SIZE, line);
    return GS_SUCCESS;
}

status_t gsql_set_trx_iso_level(text_t *line)
{
    cm_trim_text(line);
    if (CM_TEXT_END(line) == ';') {
        line->len--;
    }

    if (line->len >= MAX_SQL_SIZE) {
        gsql_printf("set content exceed maxsize(%u).\n", MAX_SQL_SIZE);
        return GS_ERROR;
    }

    CM_TEXT_CLEAR(&g_sql_text);
    cm_concat_text(&g_sql_text, MAX_SQL_SIZE, line);
    CM_NULL_TERM(&g_sql_text);

    return gsql_execute(NULL);
}

static void gsql_display_column_usage(void)
{
    gsql_printf("Usage:\n");
    gsql_printf("COL|COLUMN clear\n");
    gsql_printf("COL|COLUMN [{column|expr} [option ...]]\n");
    gsql_printf("where option represents one of the following clauses:\n");
    gsql_printf("ON|OFF\n");
    gsql_printf("FOR[MAT] a|ACOLUMN_WIDTH(example: column F1 for a10)\n");
}

static gsql_column_format_attr_t *gsql_get_column_attr(text_t *column)
{
    uint32 i;
    gsql_column_format_attr_t *col_format = NULL;

    for (i = 0; i < g_local_config.column_formats.count; i++) {
        col_format = (gsql_column_format_attr_t *)cm_list_get(&g_local_config.column_formats, i);
        if (cm_text_str_equal_ins(column, col_format->col_name)) {
            return col_format;
        }
    }

    return NULL;
}

static status_t gsql_column_on_off(text_t *params, text_t *column, bool32 is_on,
                                   gsql_column_format_attr_t *col_attr)
{
    if (col_attr == NULL) {
        column->str[column->len] = '\0';
        gsql_printf("COLUMN '%s' not defined.\n", column->str);
        return GS_ERROR;
    }

    col_attr->is_on = is_on;

    // expect end
    cm_trim_text(params);
    if (params->len != 0) {
        gsql_printf("Column failed.\n\n");
        gsql_display_column_usage();
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t gsql_column_format(text_t *params, text_t *column, gsql_column_format_attr_t *col_format)
{
    gsql_column_format_attr_t *new_col_format = NULL;
    text_t option;
    uint32 col_width;

    cm_trim_text(params);
    if (params->len == 0 || !cm_fetch_text(params, ' ', '\0', &option) || option.len < 1 || (option.str[0] != 'a' &&
            option.str[0] != 'A')) {
        gsql_printf("Column failed.\n\n");
        gsql_display_column_usage();
        return GS_ERROR;
    }

    option.str++;
    option.len--;

    if (option.len == 0 || cm_text2uint32(&option, &col_width) != GS_SUCCESS || col_width == 0) {
        gsql_printf("Illegal FORMAT string.\n");
        return GS_ERROR;
    }

    // expect end
    cm_trim_text(params);
    if (params->len != 0) {
        gsql_printf("unknown COLUMN option, expect end.\n");
        return GS_ERROR;
    }

    if (col_format == NULL) {
        if (cm_list_new(&g_local_config.column_formats, (void **)&new_col_format) != GS_SUCCESS) {
            gsql_printf("alloc space for add column format failed.\n");
            return GS_ERROR;
        }
        col_format = new_col_format;
        if (column->len != 0) {
            MEMS_RETURN_IFERR(memcpy_s(col_format->col_name, GS_MAX_NAME_LEN, column->str, column->len));
        }
    }

    col_format->is_on = GS_TRUE;
    col_format->col_width = col_width;
    return GS_SUCCESS;
}

static status_t gsql_column(text_t *params)
{
    text_t option, column;
    bool32 is_clear = GS_FALSE;
    gsql_column_format_attr_t *col_attr;

    col_attr = NULL;

    cm_trim_text(params);
    if (params->len == 0) {
        gsql_printf("Column failed.\n\n");
        gsql_display_column_usage();
        return GS_ERROR;
    }

    if (!cm_fetch_text(params, ' ', '\0', &option)) {
        gsql_printf("Column failed.\n\n");
        gsql_display_column_usage();
        return GS_ERROR;
    }

    // column clear
    if (cm_text_str_equal_ins(&option, "CLEAR")) {
        is_clear = GS_TRUE;
    }

    cm_trim_text(params);
    if (params->len == 0) {
        if (is_clear) {
            cm_reset_list(&g_local_config.column_formats);
            gsql_printf("Column format cleared.\n\n");
            return GS_SUCCESS;
        } else {
            gsql_printf("Column failed.\n\n");
            gsql_display_column_usage();
            return GS_ERROR;
        }
    }

    // get column name
    column = option;
    col_attr = gsql_get_column_attr(&column);

    // column column_name on|off|format
    if (!cm_fetch_text(params, ' ', '\0', &option)) {
        gsql_printf("Column failed.\n\n");
        gsql_display_column_usage();
        return GS_ERROR;
    }

    if (cm_text_str_equal_ins(&option, "ON")) {
        return gsql_column_on_off(params, &column, GS_TRUE, col_attr);
    } else if (cm_text_str_equal_ins(&option, "OFF")) {
        return gsql_column_on_off(params, &column, GS_FALSE, col_attr);
    } else if (cm_text_str_less_equal_ins(&option, "FORMAT", 3)) {
        return gsql_column_format(params, &column, col_attr);
    } else {
        gsql_printf("Column failed.\n\n");
        gsql_display_column_usage();
        return GS_ERROR;
    }
}

static void gsql_display_whenever_usage(void)
{
    gsql_printf("Usage:\n");
    gsql_printf("WHENEVER SQLERROR\n");
    gsql_printf("{ CONTINUE [ COMMIT | ROLLBACK ]\n");
    gsql_printf("| EXIT [ COMMIT | ROLLBACK ] }\n");
}

static status_t gsql_parse_whenever(text_t *params, whenever_t *whenever)
{
    text_t option;

    // try get sqlerror
    cm_trim_text(params);
    if (params->len == 0 || !cm_fetch_text(params, ' ', '\0', &option) ||
        !cm_text_str_equal_ins(&option, "SQLERROR")) {
        return GS_ERROR;
    }
    whenever->error_type = 0;

    // try get continue|exit
    cm_trim_text(params);
    if (params->len == 0 || !cm_fetch_text(params, ' ', '\0', &option)) {
        return GS_ERROR;
    }

    if (cm_text_str_equal_ins(&option, "CONTINUE")) {
        whenever->continue_type = 1;
    } else if (cm_text_str_equal_ins(&option, "EXIT")) {
        whenever->continue_type = 0;
    } else {
        return GS_ERROR;
    }

    // try get commit|rollback
    cm_trim_text(params);
    if (params->len == 0) {
        whenever->commit_type = 0;
    } else {
        (void)cm_fetch_text(params, ' ', '\0', &option);
        if (cm_text_str_equal_ins(&option, "COMMIT")) {
            whenever->commit_type = 1;
        } else if (cm_text_str_equal_ins(&option, "ROLLBACK")) {
            whenever->commit_type = 0;
        } else {
            return GS_ERROR;
        }
    }

    // expect end
    cm_trim_text(params);
    if (params->len != 0) {
        return GS_ERROR;
    }

    whenever->is_on = GS_TRUE;
    return GS_SUCCESS;
}

static status_t gsql_whenever(text_t *params)
{
    whenever_t whenever;

    if (gsql_parse_whenever(params, &whenever) != GS_SUCCESS) {
        gsql_printf("Whenever failed.\n\n");
        gsql_display_whenever_usage();
        return GS_ERROR;
    }

    g_local_config.whenever = whenever;

    return GS_SUCCESS;
}

static status_t gsql_prompt(text_t *params)
{
    if (params->str == NULL) {
        gsql_printf("%s", "");
        return GS_SUCCESS;
    }

    if (strlen(params->str) > MAX_CMD_LEN) {
        GSQL_PRINTF(ZSERR_GSQL, "Input is too long (> %d characters) - line ignored", MAX_CMD_LEN);
        return GS_ERROR;
    }

    cm_trim_text(params);
    char buf[MAX_CMD_LEN];
    GS_RETURN_IFERR(cm_text2str(params, buf, MAX_CMD_LEN));
    gsql_printf("%s", buf);
    return GS_SUCCESS;
}

static void gsql_replace_LF_with_space(char *buf)
{
    uint32 len = (uint32)strlen(buf);
    uint32 i = 0;

    for (; i < len; i++) {
        if (buf[i] == '\n') {
            buf[i] = ' ';
        }
    }
}

static void gsql_oper_log(char *buf, uint32 len)
{
    char date[GS_MAX_TIME_STRLEN];
    char *log_buf = NULL;
    uint32 log_buf_len, offset;
    text_t oper_log;
    errno_t errcode;
    int32 mattch_type;
    bool32 mattched = GS_FALSE;

    GS_RETVOID_IFTRUE(!LOG_OPER_ON);

    (void)cm_date2str(g_timer()->now, "yyyy-mm-dd hh24:mi:ss.ff3", date, GS_MAX_TIME_STRLEN);
    gsql_replace_LF_with_space(buf);

    oper_log.str = buf;
    oper_log.len = len;

    cm_text_try_map_key2type(&oper_log, &mattch_type, &mattched);
    if (mattched == GS_TRUE) {
        oper_log.str = g_key_pattern[mattch_type].type_desc;
        oper_log.len = (uint32)strlen(g_key_pattern[mattch_type].type_desc);
    }

    offset = (uint32)strlen(date);
    log_buf_len = offset + 6 + oper_log.len + 1;  // date|zsql|cmd

    log_buf = (char *)malloc(log_buf_len);
    GS_RETVOID_IFTRUE(log_buf == NULL);

    do {
        errcode = memcpy_s(log_buf, log_buf_len, date, offset);
        if (errcode != EOK) {
            gsql_printf("Copying date to log_buf failed");
            break;
        }

        errcode = memcpy_s(log_buf + offset, log_buf_len - offset, "|zsql|", strlen("|zsql|"));
        if (errcode != EOK) {
            gsql_printf("Copying string '|zsql|' failed");
            break;
        }

        offset += (uint32)strlen("|zsql|");
        errcode = memcpy_s(log_buf + offset, log_buf_len - offset, oper_log.str, oper_log.len);
        if (errcode != EOK) {
            gsql_printf("Copying message '%s' from oper_log failed", oper_log.str);
            break;
        }

        log_buf[log_buf_len - 1] = '\0';
        cm_write_oper_log(log_buf, log_buf_len - 1);
    } while (0);
    
    CM_FREE_PTR(log_buf);
}

static void print_sql_command(const char *sql_buf, uint32 len)
{
    char *temp = NULL;
    errno_t errcode;
    text_t output_sql;

    if (len == 0) {
        return;
    }

    temp = (char *)malloc(len + 1);
    if (temp == NULL) {
        return;
    }

    errcode = memcpy_s(temp, len + 1, sql_buf, len);
    if (errcode != EOK) {
        CM_FREE_PTR(temp);
        GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return;
    }
    temp[len] = '\0';

    if (g_is_print == GS_TRUE && g_local_config.script_output == GS_TRUE) {
        gsql_regular_match_sensitive(temp, len, &output_sql);
        gsql_printf("%s\n", output_sql.str);
    }

    gsql_oper_log(temp, len);
    (void)memset_s(temp, len + 1, 0, len + 1);
    CM_FREE_PTR(temp);
    return;
}

static inline void cm_text_append_text_head(text_t *text, uint32 len, const text_t head)
{
    uint32 i = len;
    while (i-- > 0) {
        text->str[i + head.len] = text->str[i];
    }
    for (uint32 i = 0; i < head.len; i++) {
        text->str[i] = head.str[i];
    }
    text->len = len + head.len;
}

status_t gsql_process_autotrace_cmd(void)
{
    if (!gsc_if_need_trace()) {
        return GS_SUCCESS;
    }
    if (gsc_get_autotrace_result(STMT) != GS_SUCCESS) {
        gsql_print_error(CONN);
        return GS_ERROR;
    }
    gsql_print_result();
    return GS_SUCCESS;
}

static status_t gsql_exec_multiline_cmd()
{
    text_t sql_text;
    status_t status = GS_SUCCESS;

    sql_text = g_sql_text;
    print_sql_command(g_sql_text.str, g_sql_text.len);
    gsql_reset_in_enclosed_char();

    cm_trim_text(&sql_text);
    if (CM_IS_EMPTY(&sql_text)) {
        GSQL_RESET_CMD_TYPE(&g_cmd_type);
        GSQL_PRINTF(ZSERR_GSQL, "Nothing in SQL buffer to run");
        return status;
    }

    /* Step 1: Re-fetch the type of the command in SQL buffer */
    if (!gsql_find_cmd(&sql_text, &g_cmd_type)) {
        GSQL_RESET_CMD_TYPE(&g_cmd_type);
        GSQL_PRINTF(ZSERR_GSQL, "Nothing in SQL buffer to run");
        return status;
    }

    /* Step 2: Execute multi-line command  */
    sql_text = g_sql_text;

    if (g_cmd_type.cmd == CMD_LOAD) {
        date_t start_time = 0;
        gsql_get_start_time_for_timer(&start_time);
        gsql_reset_timer();

        status = gsql_load(&sql_text);

        gsql_get_consumed_time_for_timer(start_time);
        gsql_print_timer();
    } else if (g_cmd_type.cmd == CMD_DUMP) {
        date_t start_time = 0;
        gsql_get_start_time_for_timer(&start_time);
        gsql_reset_timer();

        status = gsql_dump(&sql_text);

        gsql_get_consumed_time_for_timer(start_time);
        gsql_print_timer();
    } else if (g_cmd_type.cmd == CMD_EXPORT) {
        status = gsql_export(&sql_text, GS_TRUE);
    } else if (g_cmd_type.cmd == CMD_IMPORT) {
        status = gsql_import(&sql_text);
    } else {
        status = gsql_execute(NULL);
        if (status == GS_SUCCESS && !GSQL_CANCELING && g_local_config.trace_mode) {
            status = gsql_process_autotrace_cmd();
        }
    }
    /* Step 3: Clear the SQL buffer and reset the command type */
    GSQL_RESET_CMD_TYPE(&g_cmd_type);
    (void)cm_text_set(&g_sql_text, g_sql_text.len, '\0');
    CM_TEXT_CLEAR(&g_sql_text);
    return status;
}

static status_t gsql_process_multiline_cmd(text_t *line)
{
    bool32 is_end = GS_FALSE;

    cm_trim_text(line);
    if (CM_TEXT_END(line) == ';' && g_in_comment_count == 0) {
        is_end = GS_TRUE;
        line->len--;
    }

    if (gsql_concat_appendlf(line) != GS_SUCCESS) {
        if (is_end) {
            (void)cm_text_set(&g_sql_text, g_sql_text.len, '\0');
            CM_TEXT_CLEAR(&g_sql_text);
        }
        return GS_ERROR;
    }

    /* If the multi-line command terminates */
    if (is_end) {
        if (gsql_exec_multiline_cmd() != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

#ifndef WIN32
#define DEFAULT_SHELL "/bin/sh"
#else
#define DEFAULT_SHELL "cmd.exe"
#endif

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
static bool32 is_match_white_list(const char *shell_name)
{
#ifdef WIN32
    uint32 len = (uint32)strlen(shell_name);
    const char *matcher = "cmd.exe";
    int32 offset = len - (int32)strlen(matcher);
    if (offset < 0) {
        return GS_FALSE;
    }
    if (cm_strcmpi(shell_name + offset, matcher) != 0) {
        return GS_FALSE;
    }
    for (uint32 i = 0; i < len; i++) {
        if (shell_name[i] == ';') {
            return GS_FALSE;
        }
    }
    return GS_TRUE;
#else
    if (cm_strcmpi(shell_name, "/bin/sh") == 0 ||
        cm_strcmpi(shell_name, "/bin/bash") == 0 ||
        cm_strcmpi(shell_name, "/sbin/nologin") == 0 ||
        cm_strcmpi(shell_name, "/usr/bin/sh") == 0 ||
        cm_strcmpi(shell_name, "/usr/bin/bash") == 0 ||
        cm_strcmpi(shell_name, "/usr/sbin/nologin") == 0 ||
        cm_strcmpi(shell_name, "/bin/tcsh") == 0 ||
        cm_strcmpi(shell_name, "/bin/csh") == 0) {
        return GS_TRUE;
    }
    return GS_FALSE;
#endif
}
#endif

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
static status_t gsql_do_shell(text_t *command)
{
    const char *shell_name = NULL;
    char path[GS_FILE_NAME_BUFFER_SIZE] = { 0x00 };
    if (CM_IS_EMPTY(command)) {
        GSQL_PRINTF(ZSERR_GSQL, "shell context is empty");
        return GS_ERROR;
    } else {
        char *cmd = NULL;
#ifdef WIN32
        STARTUPINFO si;
        PROCESS_INFORMATION pi;
        shell_name = getenv("COMSPEC");
        if (shell_name == NULL) {
            shell_name = DEFAULT_SHELL;
        }

        GS_RETURN_IFERR(realpath_file(shell_name, path, GS_FILE_NAME_BUFFER_SIZE));
        // white list
        if (!is_match_white_list(path)) {
            GS_THROW_ERROR(ERR_CMD_NOT_ALLOWED_TO_EXEC, path);
            return GS_ERROR;
        }

        MEMS_RETURN_IFERR(memset_s(&si, sizeof(STARTUPINFO), 0, sizeof(STARTUPINFO)));
        MEMS_RETURN_IFERR(memset_s(&pi, sizeof(PROCESS_INFORMATION), 0, sizeof(PROCESS_INFORMATION)));
        si.cb = sizeof(si);

        size_t len = strlen("/c ") + command->len;
        cmd = (char *)malloc(len + 1);
        if (cmd == NULL) {
            GSQL_PRINTF(ZSERR_GSQL, "failed to alloc memory for tmp cmd");
            return GS_ERROR;
        }

        if (snprintf_s(cmd, len + 1, len, "/c %s", command->str) == -1) {
            CM_FREE_PTR(cmd);
            GSQL_PRINTF(ZSERR_GSQL, "failed to snprintf cmd");
            return GS_ERROR;
        }

        cmd[len] = '\0';

        if (!CreateProcess(path, cmd, NULL, NULL,
                           FALSE, CREATE_DEFAULT_ERROR_MODE, NULL, NULL, &si, &pi)) {
            CM_FREE_PTR(cmd);
            GSQL_PRINTF(ZSERR_GSQL, "\\!: failed, reason %d", GetLastError());
            return GS_ERROR;
        }
        (void)WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
#else
        int status;
        char *args[GS_MAX_CMD_ARGS + 1];
        pid_t child;
        shell_name = getenv("SHELL");
        if (shell_name == NULL) {
            shell_name = DEFAULT_SHELL;
        }

        GS_RETURN_IFERR(realpath_file(shell_name, path, GS_FILE_NAME_BUFFER_SIZE));
        // white list
        if (!is_match_white_list(path)) {
            GS_THROW_ERROR(ERR_CMD_NOT_ALLOWED_TO_EXEC, path);
            return GS_ERROR;
        }

        cmd = (char *)malloc(command->len + 1);
        if (cmd == NULL) {
            GSQL_PRINTF(ZSERR_GSQL, "failed to alloc memory for tmp cmd");
            return GS_ERROR;
        }

        errno_t errcode = memcpy_s(cmd, command->len + 1, command->str, command->len);
        if (errcode != EOK) {
            CM_FREE_PTR(cmd);
            GSQL_PRINTF(ZSERR_GSQL, "failed to copy command to tmp cmd");
            return GS_ERROR;
        }
        cmd[command->len] = '\0';
        args[0] = path;
        args[1] = "-c";
        args[2] = cmd;
        args[3] = NULL;

        child = fork();
        if (child == 0) {
            int ret = execve(path, args, environ);
            if (-1 == ret) {
                CM_FREE_PTR(cmd);
                GSQL_PRINTF(ZSERR_GSQL, "exec %s failed, reason %d", cmd, errno);
                return GS_ERROR;
            }

            return GS_SUCCESS;
        } else if (child < 0) {
            CM_FREE_PTR(cmd);
            GSQL_PRINTF(ZSERR_GSQL, "fork child process failed");
            exit(GS_ERROR);
        }

        if (waitpid(child, &status, 0) != child) {
            CM_FREE_PTR(cmd);
            GSQL_PRINTF(ZSERR_GSQL, "wait child process (%d) failed", child);
            exit(GS_ERROR);
        }
#endif
        CM_FREE_PTR(cmd);
    }

    return GS_SUCCESS;
}
#endif

static status_t gsql_run_normal_sqlfile(text_t *file_name);
static status_t gsql_run_nested_sqlfile(text_t *file_name);

static status_t gsql_exec_singline_cmd(gsql_cmd_def_t *cmdtype, text_t *line, text_t *params)
{
    status_t status = GS_SUCCESS;

    print_sql_command(line->str, line->len);
    gsql_reset_in_enclosed_char();
    gsql_printf("\n");
    switch (cmdtype->cmd) {
        case CMD_NONE:
            break;

        case CMD_EXIT:
            gsql_exit(GS_FALSE, 0);

        case CMD_SHOW:
            gsql_show(params);
            break;

        case CMD_EXEC:
            status = gsql_exec_multiline_cmd();
            break;

        case CMD_CONN:
            g_in_comment_count = 0;
            status = gsql_connect(line);
            break;

        case CMD_DESC:
            status = gsql_desc(params);
            break;

        case CMD_SQLFILE:
            status = gsql_run_normal_sqlfile(params);
            break;

        case CMD_SQLFILE2:
            status = gsql_run_nested_sqlfile(params);
            break;

        case CMD_SPOOL:
            status = gsql_spool(params);
            break;

        case CMD_CLEAR:
#ifdef WIN32
            system("cls");
#else
            gsql_printf("\033[H\033[J");
#endif
            break;

        case CMD_SET:
            status = gsql_set(line, params);
            break;

        case CMD_COLUMN:
            status = gsql_column(params);
            break;

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
        case CMD_SHELL:
            status = gsql_do_shell(params);
            break;
#endif

        case CMD_WHENEVER:
            status = gsql_whenever(params);
            break;

        case CMD_PROMPT:
            status = gsql_prompt(params);
            break;

        case CMD_AWR:
            status = gsql_wsr(params);
            break;

        case CMD_MONITOR:
            status = gsql_monitor(params);
            break;

        default:
            break;
    }
    gsql_printf("\n");
    return status;
}

static status_t encounter_prompt_cmd(const text_t *line)
{
    text_t left, right;
    cm_split_text(line, ' ', 0, &left, &right);

    if (0 == cm_compare_text_str_ins(&left, "prompt") || 0 == cm_compare_text_str_ins(&left, "pro")) {
        return GS_TRUE;
    } else {
        return GS_FALSE;
    }
}

#define GSQL_IS_ENCLOSED_CHAR(c) ((c) == '\'' || (c) == '"' || (c) == '`')
#define GSQL_IS_SPLIT_CHAR(c)    ((c) == ';')

static bool32 gsql_fetch_cmd(text_t *line, text_t *sub_cmd)
{
    uint32 i;
    char c;

    if (CM_IS_EMPTY(line)) {
        CM_TEXT_CLEAR(sub_cmd);
        return GS_FALSE;
    }

    sub_cmd->str = line->str;
    for (i = 0; i < line->len; i++) {
        c = line->str[i];
        /* enclosed char not in comment. */
        if (!g_in_comment_count && GSQL_IS_ENCLOSED_CHAR(c)) {
            if (g_in_enclosed_char < 0) {
                g_in_enclosed_char = c;
            } else if (g_in_enclosed_char == c) {
                g_in_enclosed_char = -1;
            }
            continue;
        }

        if (g_in_enclosed_char > 0) {
            continue;
        }

        if (c == '/' && (i + 1 < line->len) && line->str[i + 1] == '*') {
            g_in_comment_count++;
            i = i + 1;
            continue;
        }

        if (c == '*' && (i + 1 < line->len) && line->str[i + 1] == '/') {
            if (g_in_comment_count > 0) {
                g_in_comment_count = 0;
            }
            i = i + 1;
            continue;
        }

        if (c == '-') {  // if line comment(--) is scanned
            if (!g_in_comment_count && ((i + 1 < line->len) && line->str[i + 1] == '-')) {
                sub_cmd->len = i;
                line->len = 0;
                line->str = NULL;
                return GS_TRUE;
            }
        }

        if (encounter_prompt_cmd(line)) {
            sub_cmd->len = line->len;
            line->len = 0;
            line->str = NULL;
            return GS_TRUE;
        }

        if (!g_in_comment_count && GSQL_IS_SPLIT_CHAR(c)) {  // encounter split CHAR
            sub_cmd->len = i + 1;                            // include the split char
            line->str += i + 1;
            line->len -= (i + 1);
            return GS_TRUE;
        }
    }

    sub_cmd->len = line->len;
    line->len = 0;
    line->str = NULL;
    return GS_TRUE;
}

status_t gsql_process_cmd(text_t *line)
{
    text_t params;
    text_t sub_cmd;
    gsql_cmd_def_t cmdtype;

    cm_reset_error();

    cm_trim_text(line);
    while (gsql_fetch_cmd(line, &sub_cmd)) {
        // handle multiple cmds in One line
        gsql_get_cmd(sub_cmd, &cmdtype, &params);

        if (cmdtype.cmd == CMD_COMMENT) {  // if fetched the line comment
            return GS_SUCCESS;
        } else if (cmdtype.cmd == CMD_EXEC) {
            // the `/` merely used for multi-line cmd
            return gsql_exec_multiline_cmd();
        } else if (cmdtype.cmd == CMD_NONE) {
            return GS_SUCCESS;
        }

        if (g_cmd_type.mode == MODE_NONE) {
            if (cmdtype.mode == MODE_SINGLE_LINE) {
                if (gsql_exec_singline_cmd(&cmdtype, &sub_cmd, &params) != GS_SUCCESS) {
                    return GS_ERROR;
                }
                continue;
            } else {
                g_cmd_type = cmdtype;
            }
        }

        if (gsql_process_multiline_cmd(&sub_cmd) != GS_SUCCESS) {
            return GS_ERROR;
        }

        (void)cm_text_set(&sub_cmd, sub_cmd.len, '\0');
        continue;
    }
    return GS_SUCCESS;
}

static inline void gsql_print_blank_line(void)
{
    gsql_try_spool_directly_put("\n");
}

static text_t *g_curr_sql_dir = NULL;

static status_t gsql_make_nested_filepath(const text_t *txt_fpath, char **str_realpath)
{
    uint32 path_len = 0;
    text_t filepath;
    char pathbuf[GS_MAX_FILE_PATH_LENGH];

    if (g_curr_sql_dir != NULL) {
        path_len += g_curr_sql_dir->len;
    }
    path_len += txt_fpath->len;

    if ((path_len >= GS_MAX_FILE_PATH_LENGH) || (path_len == 0)) {
        GS_THROW_ERROR(ERR_FILE_PATH_TOO_LONG, GS_MAX_FILE_PATH_LENGH);
        return GS_ERROR;
    }

    // Step 1: get the (relative) filepath of nested file
    filepath.str = pathbuf;
    filepath.len = 0;

    if (g_curr_sql_dir != NULL) {
        cm_concat_text(&filepath, MAX_SQL_SIZE, g_curr_sql_dir);
    }
    cm_concat_text(&filepath, MAX_SQL_SIZE, txt_fpath);
    CM_NULL_TERM(&filepath);

    // Step 2: Alloc memory for the absolute filepath of nested file
    *str_realpath = (char *)malloc(GS_MAX_FILE_PATH_LENGH);
    if (*str_realpath == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)GS_MAX_FILE_PATH_LENGH, "make nested file path");
        return GS_ERROR;
    }
    MEMS_RETURN_IFERR(memset_s(*str_realpath, GS_MAX_FILE_PATH_LENGH, 0, GS_MAX_FILE_PATH_LENGH));

    // Step 3: Get the absolute Path
    GS_RETURN_IFERR(realpath_file(pathbuf, *str_realpath, GS_MAX_FILE_PATH_LENGH));

    return GS_SUCCESS;
}

static status_t gsql_make_normal_filepath(text_t *file_name, char **str_fpath)
{
    char file_name2[GS_MAX_FILE_PATH_LENGH];

    if ((file_name->len >= GS_MAX_FILE_PATH_LENGH) || (file_name->len <= 0)) {
        GS_THROW_ERROR(ERR_FILE_PATH_TOO_LONG, GS_MAX_FILE_PATH_LENGH);
        return GS_ERROR;
    }

    *str_fpath = (char *)malloc(GS_MAX_FILE_PATH_LENGH);
    if (*str_fpath == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)GS_MAX_FILE_PATH_LENGH, "make normal file path");
        return GS_ERROR;
    }

    MEMS_RETURN_IFERR(memset_s(*str_fpath, GS_MAX_FILE_PATH_LENGH, 0, GS_MAX_FILE_PATH_LENGH));
    GS_RETURN_IFERR(cm_text2str(file_name, file_name2, GS_MAX_FILE_PATH_LENGH));
    GS_RETURN_IFERR(realpath_file(file_name2, *str_fpath, GS_MAX_FILE_PATH_LENGH));

    file_name->str = *str_fpath;
    file_name->len = (uint32)strlen(*str_fpath);

    return GS_SUCCESS;
}

static inline status_t gsql_set_curr_sql_work_dir(text_t *file_name, text_t **last_sql_dir)
{
    int32 pos = cm_text_rchr2(file_name, "\\/");

    *last_sql_dir = g_curr_sql_dir;
    if (pos < 0) {
        g_curr_sql_dir = NULL;
        return GS_SUCCESS;
    }

    file_name->len = (uint32)pos + 1;
    GS_RETURN_IFERR(cm_text_dup(file_name, &g_curr_sql_dir));
    cm_convert_os_path(g_curr_sql_dir);
    return GS_SUCCESS;
}

static inline void gsql_reset_curr_sql_work_dir(text_t *last_sql_dir)
{
    cm_free_text(g_curr_sql_dir);
    g_curr_sql_dir = last_sql_dir;
}

static inline void gsql_run_sqlfile(FILE *file)
{
    bool32 temp_slient_on = g_local_config.silent_on;
    char cmd_buf[MAX_CMD_LEN + 2];

    g_is_print = GS_TRUE;
    g_local_config.silent_on = g_local_config.termout_on;

    gsql_reset_cmd_buf(cmd_buf, sizeof(cmd_buf));
    gsql_run(file, GS_TRUE, cmd_buf, sizeof(cmd_buf));

    g_local_config.silent_on = temp_slient_on;
    g_is_print = GS_FALSE;
}

static status_t gsql_run_normal_sqlfile(text_t *file_name)
{
    FILE *file = NULL;
    char *str_realpath = NULL;

    text_t *last_sql_dir = NULL;

    cm_trim_text(file_name);
    if (file_name->len > 0 && CM_TEXT_END(file_name) == ';') {
        CM_REMOVE_LAST(file_name);
        if (CM_IS_EMPTY(file_name)) {
            GSQL_PRINTF(ZSERR_GSQL, "File name expected\n");
            return GS_ERROR;
        }
    }

    if (file_name->len == 0) {
        GSQL_PRINTF(ZSERR_GSQL, "START, @ or @@ command has no arguments");
        return GS_ERROR;
    }

    if (gsql_make_normal_filepath(file_name, &str_realpath) != GS_SUCCESS) {
        if (str_realpath != NULL) {
            CM_FREE_PTR(str_realpath);
        }
        return GS_ERROR;
    }

    if (gsql_set_curr_sql_work_dir(file_name, &last_sql_dir) != GS_SUCCESS) {
        GSQL_PRINTF(ZSERR_GSQL, "Not expected file path");
        CM_FREE_PTR(str_realpath);
        return GS_ERROR;
    }

    file = fopen(str_realpath, "r");
    if (file == NULL) {
        GSQL_PRINTF(ZSERR_GSQL, "fail to open file '%s'", str_realpath);
        CM_FREE_PTR(str_realpath);
        gsql_reset_curr_sql_work_dir(last_sql_dir);
        return GS_ERROR;
    }
    gsql_run_sqlfile(file);
    gsql_printf("\n");
    fclose(file);
    CM_FREE_PTR(str_realpath);
    gsql_reset_curr_sql_work_dir(last_sql_dir);
    return GS_SUCCESS;
}

static status_t gsql_run_nested_sqlfile(text_t *file_name)
{
    FILE *file = NULL;
    char *str_realpath = NULL;

    cm_trim_text(file_name);
    if (file_name->len > 0 && CM_TEXT_END(file_name) == ';') {
        CM_REMOVE_LAST(file_name);
        if (CM_IS_EMPTY(file_name)) {
            GSQL_PRINTF(ZSERR_GSQL, "File name expected");
            return GS_ERROR;
        }
    }
    if (file_name->len == 0) {
        GSQL_PRINTF(ZSERR_GSQL, "START, @ or @@ command has no arguments");
        return GS_ERROR;
    }
    // search the file from g_curr_sql_dir
    if (gsql_make_nested_filepath(file_name, &str_realpath) != GS_SUCCESS) {
        if (str_realpath != NULL) {
            CM_FREE_PTR(str_realpath);
        }
        GSQL_PRINTF(ZSERR_GSQL, "Not expected file path");
        return GS_ERROR;
    }

    file = fopen(str_realpath, "r");
    if (file == NULL) {
        GSQL_PRINTF(ZSERR_GSQL, "fail to open file '%s'", str_realpath);
        CM_FREE_PTR(str_realpath);
        return GS_ERROR;
    }
    gsql_run_sqlfile(file);
    gsql_printf("\n");
    fclose(file);
    CM_FREE_PTR(str_realpath);
    return GS_SUCCESS;
}

static void gsql_init_local_config(void)
{
    g_local_config.auto_commit = GS_FALSE;
    g_local_config.exit_commit = GS_TRUE;
    g_local_config.charset_id = CHARSET_UTF8;
    g_local_config.heading_on = GS_TRUE;
    g_local_config.server_ouput = GS_FALSE;
    g_local_config.trim_spool = GS_FALSE;
    g_local_config.spool_on = GS_FALSE;
    g_local_config.line_size = 0;
    g_local_config.page_size = 0;
    g_local_config.timer.timing_on = GS_FALSE;
    g_local_config.timer.consumed_time = 0;
    g_local_config.feedback.feedback_on = GS_TRUE;
    g_local_config.feedback.feedback_rows = 1;
    g_local_config.trace_mode = GSQL_TRACE_OFF;
    cm_create_list(&g_local_config.column_formats, sizeof(gsql_column_format_attr_t));
    g_local_config.silent_on = GS_FALSE;
    g_local_config.print_on = GS_FALSE;
    MEMS_RETVOID_IFERR(memset_s(&g_local_config.whenever, sizeof(whenever_t), 0, sizeof(whenever_t)));
    g_local_config.long_size = GSQL_MAX_LONG_SIZE;
    MEMS_RETVOID_IFERR(memcpy_s(g_local_config.colsep.colsep_name, MAX_COLSEP_NAME_LEN, " ", 1));
    g_local_config.colsep.colsep_len = 1;
    g_local_config.newpage = 1;
    g_local_config.verify_on = GS_TRUE;
    g_local_config.termout_on = GS_FALSE;  // reuse g_local_config.slient_on, GS_FALSE means on
    g_local_config.script_output = GS_FALSE;
    g_local_config.define_on = GS_FALSE;
    g_local_config.ssl_ca[0] = '\0';
    g_local_config.ssl_cert[0] = '\0';
    g_local_config.ssl_key[0] = '\0';
    g_local_config.ssl_mode = GSC_SSL_PREFERRED;
    g_local_config.is_cancel = GS_FALSE;
    g_local_config.zsql_ssl_quiet = GS_FALSE;
    g_local_config.zsql_interaction_timeout = ZSQL_INTERACTION_DEFAULT_TIMEOUT;
    g_local_config.connect_timeout = (int32)GS_CONNECT_TIMEOUT / GS_TIME_THOUSAND_UN;
    g_local_config.socket_timeout = -1;
    g_local_config.server_path[0] = '\0';
    g_local_config.client_path[0] = '\0';
    g_local_config.bindparam_force_on  = GS_FALSE;
    g_local_config.shd_rw_split = GSC_SHD_RW_SPLIT_NONE;
}

static inline void gsql_init_backup_file_count(char *value, log_param_t *log_param)
{
    uint32 val_uint32;
    /* parse and check _LOG_BACKUP_FILE_COUNT */
    value = cm_get_config_value(g_server_config, "_LOG_BACKUP_FILE_COUNT");
    if (value == NULL || cm_str2uint32(value, &val_uint32) != GS_SUCCESS) {
        log_param->log_backup_file_count = 2;
    } else if (val_uint32 > GS_MAX_LOG_FILE_COUNT) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_LOG_BACKUP_FILE_COUNT", (int64)GS_MAX_LOG_FILE_COUNT);
        return;
    } else {
        log_param->log_backup_file_count = val_uint32;
    }

    /* parse and check _AUDIT_BACKUP_FILE_COUNT */
    value = cm_get_config_value(g_server_config, "_AUDIT_BACKUP_FILE_COUNT");
    if (value == NULL || cm_str2uint32(value, &val_uint32) != GS_SUCCESS) {
        log_param->audit_backup_file_count = 2;
    } else if (val_uint32 > GS_MAX_LOG_FILE_COUNT) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_AUDIT_BACKUP_FILE_COUNT", (int64)GS_MAX_LOG_FILE_COUNT);
        return;
    } else {
        log_param->audit_backup_file_count = val_uint32;
    }
}

static inline void gsql_init_max_file_size(char *value, log_param_t *log_param)
{
    int64 val_int64;
    /* parse and check _LOG_MAX_FILE_SIZE */
    log_param->max_log_file_size = GSQL_MAX_LOGFILE_SIZE;
    value = cm_get_config_value(g_server_config, "_LOG_MAX_FILE_SIZE");
    if (value != NULL && cm_str2size(value, &val_int64) == GS_SUCCESS && val_int64 >= 0) {
        log_param->max_log_file_size = (uint64)val_int64;
    }

    /* parse and check _AUDIT_MAX_FILE_SIZE */
    log_param->max_audit_file_size = GSQL_MAX_LOGFILE_SIZE;
    value = cm_get_config_value(g_server_config, "_AUDIT_MAX_FILE_SIZE");
    if (value != NULL && cm_str2size(value, &val_int64) == GS_SUCCESS && val_int64 >= 0) {
        log_param->max_audit_file_size = (uint64)val_int64;
    }
}

static inline void gsql_init_log_permission(char *value)
{
    uint16 val_uint16;
    /* parse and check _LOG_FILE_PERMISSIONS */
    value = cm_get_config_value(g_server_config, "_LOG_FILE_PERMISSIONS");
    if (value == NULL || cm_str2uint16(value, &val_uint16) != GS_SUCCESS) {
        val_uint16 = GS_DEF_LOG_FILE_PERMISSIONS;
    }
    cm_log_set_file_permissions(val_uint16);

    /* parse and check _LOG_PATH_PERMISSIONS */
    value = cm_get_config_value(g_server_config, "_LOG_PATH_PERMISSIONS");
    if (value == NULL || cm_str2uint16(value, &val_uint16) != GS_SUCCESS) {
        val_uint16 = GS_DEF_LOG_PATH_PERMISSIONS;
    }
    cm_log_set_path_permissions(val_uint16);
}

static void gsql_init_loggers(void)
{
    uint32 val_len;
    char *value = NULL;
    char file_name[GS_FILE_NAME_BUFFER_SIZE];
    log_param_t *log_param = cm_log_param_instance();

    /* not record oper log if CTDB_HOME not exist */
    GS_RETVOID_IFERR(gsql_get_home());

    if (gsql_load_local_server_config() != GS_SUCCESS) {
        GSQL_PRINTF(ZSERR_GSQL, "load local server config failed during init loggers");
        return;
    }

    /* parse and check LOG_HOME */
    value = cm_get_config_value(g_server_config, "LOG_HOME");
    val_len = (value == NULL) ? 0 : (uint32)strlen(value);
    if (val_len >= GS_MAX_LOG_HOME_LEN) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "LOG_HOME", (int64)GS_MAX_LOG_HOME_LEN - 1);
        return;
    } else if (val_len > 0) {
        MEMS_RETVOID_IFERR(strncpy_s(log_param->log_home, GS_MAX_PATH_BUFFER_SIZE, value, val_len));
    } else {
        PRTS_RETVOID_IFERR(snprintf_s(log_param->log_home, GS_MAX_PATH_BUFFER_SIZE, GS_MAX_PATH_LEN,
            "%s/log", GS_HOME));
    }

    if (!cm_dir_exist(log_param->log_home) || 0 != access(log_param->log_home, W_OK | R_OK)) {
        GS_THROW_ERROR(ERR_INVALID_DIR, log_param->log_home);
        return;
    }

    gsql_init_backup_file_count(value, log_param);
    gsql_init_max_file_size(value, log_param);
    gsql_init_log_permission(value);

    /* set log_level, set logname. */
    log_param->log_level = GSQL_LOG_LEVEL;
    PRTS_RETVOID_IFERR(snprintf_s(file_name, GS_FILE_NAME_BUFFER_SIZE, GS_MAX_FILE_NAME_LEN, "%s/oper/zsql.olog",
        log_param->log_home));

    cm_log_init(LOG_OPER, (const char *)file_name);
}

static int gsql_find_arg(int argc, char *argv[], const char *find_arg)
{
    for (int i = 1; i < argc; i++) {
        if (cm_str_equal_ins(argv[i], find_arg)) {
            return i;
        }
    }
    return 0;
}

status_t gsql_alloc_conn(gsc_conn_t *pconn)
{
    int16 gsql_kind = CLIENT_KIND_ZSQL;
    GS_RETURN_IFERR(gsc_alloc_conn(pconn));
    GS_RETURN_IFERR(gsc_set_conn_attr((*pconn), GSC_ATTR_APP_KIND, &gsql_kind, sizeof(int16)));
    return GS_SUCCESS;
}

static status_t gsql_init_drbg(void)
{
    return cm_init_drbg();
}

void gsql_init(int32 argc, char *argv[])
{
    int pos;
    errno_t errcode;
    bool32 interactive_clt = GS_TRUE;
    char home[GS_MAX_PATH_BUFFER_SIZE] = { 0x00 };

    // init global conn info
    errcode = memset_s(&g_conn_info, sizeof(gsql_conn_info_t), 0, sizeof(gsql_conn_info_t));
    if (errcode != EOK) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        exit(EXIT_FAILURE);
    }

    pos = gsql_find_arg(argc, argv, "-D");
    if (pos) {
        if (pos + 1 >= argc) {
            GSQL_PRINTF(ZSERR_GSQL, "The specified directory is missing.");
            exit(EXIT_FAILURE);
        }

        if (realpath_file(argv[pos + 1], (char *)home, GS_MAX_PATH_LEN) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
            exit(EXIT_FAILURE);
        }
        if (cm_check_exist_special_char(home, (uint32)strlen(home))) {
            GS_THROW_ERROR(ERR_INVALID_DIR, argv[pos + 1]);
            exit(EXIT_FAILURE);
        }
        errcode = strncpy_s(GS_HOME, GS_MAX_PATH_BUFFER_SIZE, argv[pos + 1], GS_MAX_PATH_LEN);
        if (errcode != EOK) {
            GS_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
            exit(EXIT_FAILURE);
        }
    }

    // start timer thread
    if (cm_start_timer(g_timer()) != GS_SUCCESS) {
        GSQL_PRINTF(ZSERR_GSQL, "aborted due to starting timer thread");
        exit(EXIT_FAILURE);
    }

    if (gsql_init_drbg() != GS_SUCCESS) {
        GSQL_PRINTF(ZSERR_GSQL, "aborted due to initialize ssl drbg");
        exit(EXIT_FAILURE);
    }

    // init local config
    gsql_init_local_config();
    // load zsql config
    gsql_load_zsql_config();
    // load zsql config
    gsql_init_zsql_config();
    // init ssl config
    gsql_init_ssl_config();
    // init loggers
    gsql_init_loggers();

    // alloc global conn
    if (gsql_alloc_conn(&CONN) != GS_SUCCESS) {
        gsql_print_error(NULL);
        exit(EXIT_FAILURE);
    }
    (void)gsc_set_conn_attr(CONN, GSC_ATTR_INTERACTIVE_MODE, (void *)&interactive_clt, 0);
    (void)gsc_set_conn_attr(CONN, GSC_ATTR_CONNECT_TIMEOUT, (void *)&g_local_config.connect_timeout, sizeof(int32));
    (void)gsc_set_conn_attr(CONN, GSC_ATTR_SOCKET_TIMEOUT, (void *)&g_local_config.socket_timeout, sizeof(int32));

    g_sql_text.str = g_sql_buf;
    g_sql_text.len = 0;

    GSQL_RESET_CMD_TYPE(&g_cmd_type);
    gsql_reset_cmd_buf(g_cmd_buf, sizeof(g_cmd_buf));
}

void gsql_silent(text_t *line)
{
    g_local_config.silent_on = GS_TRUE;

    if (line->len != 0) {
        cm_trim_text(line);
        char buf[MAX_ENTITY_LEN];
        (void)cm_text2str(line, buf, MAX_ENTITY_LEN);
        if (cm_open_file((const char *)buf, O_CREAT | O_TRUNC | O_RDWR, &g_spool_file) == GS_SUCCESS) {
            g_local_config.spool_on = GS_TRUE;
        }
    }
}

static void gsql_search_comment_begin(const char *str, int32 p_pos, int32 *ret)
{
    bool32 is_comment_begin = GS_FALSE;
    int32 pos = p_pos;
    /* search comment begin */
    while (pos > 0) {
        is_comment_begin = (str[pos] == '*' && str[pos - 1] == '/');
        if (is_comment_begin) {
            *ret = pos - 2;
            return;
        }
        pos--;
    }
    *ret = -1;
}

#define QUATO_FlAG  0x1
#define DQUATO_FLAG 0x2

static void gsql_skip_comment_line(text_t *line, int32 *pos, int32 end)
{
    int32 check_p = line->len - 1;
    while (check_p > end) {
        if (line->str[check_p] <= ' ') {
            check_p--;
            continue;
        }
        break;
    }

    bool32 is_comment_flag;
    int32 ahead_p, tmp_p;
    for (ahead_p = check_p; ahead_p > 0; ahead_p--) {
        if (line->str[ahead_p] == ';' && g_in_comment_count == 0) {
            *pos = ahead_p;
            return;
        }

        is_comment_flag = (line->str[ahead_p] == '-' && line->str[ahead_p - 1] == '-');
        if (is_comment_flag) {
            /* comment need skip */
            ahead_p = ahead_p - 2;
            check_p = ahead_p;
            // if end symbol encounted in comment line, it's fake
            continue;
        }

        is_comment_flag = (line->str[ahead_p] == '/' && line->str[ahead_p - 1] == '*');
        if (is_comment_flag) {
            gsql_search_comment_begin(line->str, ahead_p - 2, &tmp_p);
            if (tmp_p == -1 || g_in_comment_count == 1) {
                // check_p dedicate a valid begin, if it equal ahead_p, this is only a comment line.
                *pos = (ahead_p == check_p) ? tmp_p : check_p;
                return;
            } else {
                ahead_p = tmp_p;
                check_p = ahead_p;
                continue;
            }
        }
        // only get a begin comment
        is_comment_flag = (line->str[ahead_p] == '*' && line->str[ahead_p - 1] == '/');
        if (is_comment_flag) {
            check_p = ahead_p - 2;
        }
    }

    while (check_p > 0) {
        if (line->str[check_p] <= ' ') {
            check_p--;
            continue;
        }
        break;
    }

    *pos = check_p;
}

static void gsql_if_block(text_t *line, uint32 *flag)
{
    bool32 result = GS_FALSE;
    uint32 matched_id;
    lex_t lex;
    sql_text_t sql_text;
    sql_text.value = *line;
    sql_text.loc.line = 1;
    sql_text.loc.column = 1;

    lex_init(&lex, &sql_text);

    GS_RETVOID_IFTRUE(lex_try_fetch_1of3(&lex, "DECLARE", "BEGIN", "CREATE", &matched_id) != GS_SUCCESS);

    // devil number '0' here means matched "DECLARE"
    if (matched_id == 0) {
        *flag = GSQL_BLOCK_TAG;
        return;
    }

    // devil number '1' here means matched "BEGIN"
    if (matched_id == 1) {
        GS_RETVOID_IFTRUE(lex_try_fetch_char(&lex, ';', &result) != GS_SUCCESS || result == GS_TRUE);

        GS_RETVOID_IFTRUE(lex_try_fetch(&lex, "transaction", &result) != GS_SUCCESS || result == GS_TRUE);

        *flag = GSQL_BLOCK_TAG;
        return;
    }

    // devil number '2' here means matched "CREATE"
    GS_RETVOID_IFTRUE(matched_id != 2);

    // devil number '6' here means behind 6 string match
    GS_RETVOID_IFTRUE(lex_try_fetch_1ofn(&lex, &matched_id, 6,
        "PROCEDURE", "FUNCTION", "TRIGGER", "PACKAGE", "TYPE", "OR") != GS_SUCCESS);    // number of words behind

    // devil number '4' here means matched "PROCEDURE", "FUNCTION", "TRIGGER", "PACKAGE", "TYPE"
    if (matched_id <= 4) {    // match the id of the word
        *flag = GSQL_BLOCK_TAG;
        return;
    }

    // devil number '5' here means matched "OR"
    GS_RETVOID_IFTRUE(matched_id != 5);    // match the id of the word

    GS_RETVOID_IFTRUE(lex_try_fetch(&lex, "REPLACE", &result) != GS_SUCCESS || result == GS_FALSE);

    GS_RETVOID_IFTRUE(lex_try_fetch_1ofn(&lex, &matched_id, 5,
        "PROCEDURE", "FUNCTION", "TRIGGER", "PACKAGE", "TYPE") != GS_SUCCESS);    // number of words behind
        
    // devil number '4' here means matched "PROCEDURE", "FUNCTION", "TRIGGER", "PACKAGE", "TYPE"
    if (matched_id <= 4) {    // match the id of the word
        *flag = GSQL_BLOCK_TAG;
    }
}

static void gsql_if_block_end(text_t *line, uint32 *flag)
{
    int32 count = 0;

    for (uint32 i = 0; i < line->len; i++) {
        if ((line->str[i] > ' ' && line->str[i] != '/') || count > 1) {
            return;
        }
        if (line->str[i] == '/') {
            count++;
        }
    }
    if (count == 1) {
        *flag = GSQL_BLOCK_END_TAG;
    }
}

static void gsql_if_comment_end(text_t *line, uint32 *flag)
{
    uint32 pos;

    for (pos = 0; pos < line->len - 1; pos++) {
        if (line->str[pos] == '*' && line->str[pos + 1] == '/' &&
            (pos == 0 || line->str[pos - 1] != '/')) {
            *flag = GSQL_COMMENT_END_TAG;
            return;
        }
    }
}

uint32 gsql_print_welcome(uint32 multi_line, uint32 line_no)
{
    uint32 nchars = 0;
    if (g_is_print == GS_TRUE &&
        g_local_config.script_output == GS_FALSE &&
        g_local_config.feedback.feedback_on == GS_FALSE) {
        return nchars;
    }

    if (!g_local_config.silent_on) {
        if (multi_line == GSQL_SINGLE_TAG) {
            if (!g_local_config.silent_on) {
                nchars = printf("SQL> ");
                fflush(stdout);
            }
            gsql_try_spool_put("SQL> ");
        } else {
            if (!g_local_config.silent_on) {
                nchars = printf("%3u ", line_no);
                fflush(stdout);
            }
            gsql_try_spool_put("%3d ", line_no);
        }
    }
    return nchars;
}

static bool32 gsql_if_illega_line(FILE *in, char *cmd_buf, uint32 max_len)
{
    char err_info[GS_MAX_CMD_LEN] = { 0 };
    int iret_snprintf = 0;
    int iret_fscanf = 0;

    /* If the single cmd is too long */
    if (cmd_buf[max_len - 1] != GSQL_BUF_RESET_CHAR) {
        iret_fscanf = fscanf_s(in, "%*[^\n]%*c");
        if (iret_fscanf == -1) {
            GS_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
            return GS_FALSE;
        }
        iret_snprintf = snprintf_s(err_info, GS_MAX_CMD_LEN, GS_MAX_CMD_LEN - 1,
                                   "Error: Input is too long (> %d characters) - line ignored.\n", MAX_CMD_LEN);
        if (iret_snprintf == -1) {
            GS_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
            return GS_FALSE;
        } else {
            gsql_printf("%s", err_info);
            gsql_oper_log(err_info, (uint32)strlen(err_info) - 1);  // record oper log, '\n' no need
        }

        gsql_reset_cmd_buf(cmd_buf, max_len);
        return GS_TRUE;
    }
    return GS_FALSE;
}

static void gsql_if_skip_line(text_t *line, int32 pos, bool32 *is_skip_line)
{
    gsql_cmd_def_t cmdtype;
    text_t line_deal;

    int32 right_trim = line->len - 1;
    while (right_trim > pos) {
        if (line->str[pos] <= ' ') {
            right_trim--;
            continue;
        }
        break;
    }

    line_deal.str = line->str + pos;
    line_deal.len = right_trim - pos;

    // attention : now try twice, check line need to be skipped
    if (CM_TEXT_FIRST(&line_deal) == '-' && CM_TEXT_SECOND(&line_deal) == '-') {
        *is_skip_line = GS_TRUE;
        return;
    }

    if (CM_TEXT_FIRST(&line_deal) == '@') {
        *is_skip_line = GS_TRUE;
        return;
    }

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    if (CM_TEXT_FIRST(&line_deal) == '\\' && CM_TEXT_SECOND(&line_deal) == '!') {
        *is_skip_line = GS_TRUE;
        return;
    }
#endif

    if (!gsql_find_cmd(&line_deal, &cmdtype)) {
        *is_skip_line = GS_TRUE;
        return;
    }

    if (cmdtype.mode != MODE_MULTI_LINE) {
        *is_skip_line = GS_TRUE;
    } else {
        *is_skip_line = GS_FALSE;
    }
}

static void gsql_if_multi_line(text_t *line, uint32 *flag)
{
    bool32 is_pl_label = GS_FALSE;
    bool32 is_begin_comment;
    bool32 is_skip_line;
    int32 pos = 0;
    while (pos < (int32)line->len) {
        if (line->str[pos] <= ' ') {
            pos++;
            continue;
        }
        break;
    }

    if (pos == (int32)line->len) {
        *flag = GSQL_EMPTY_TAG;
        return;
    }
    int32 len = (int32)line->len;
    if ((len - pos) > 4) {
        // attention 1: PL LABEL start with <<, check first
        is_pl_label = (line->str[pos] == '<') && (line->str[pos + 1] == '<');
    }
    if (is_pl_label) {
        *flag = GSQL_BLOCK_TAG;
        return;
    }

    // attention 2: some single line command doesn't have semicolon, need skip.
    gsql_if_skip_line(line, pos, &is_skip_line);
    if (is_skip_line) {
        return;
    }

    int32 end_chk;
    // attention 3: skip the comment line, then check line end
    is_begin_comment = pos + 1 < (int32)line->len && line->str[pos] == '/' && line->str[pos + 1] == '*';
    gsql_skip_comment_line(line, &end_chk, pos);
    if (end_chk < 0 && !is_begin_comment) {
        return;
    }

    if (is_begin_comment) {
        *flag = GSQL_COMMENT_TAG;
        return;
    }

    if (line->str[end_chk] == ';' && g_in_comment_count == 0) {
        return;
    }

    *flag = GSQL_MULTI_TAG;
    return;
}

static void gsql_if_multi_line_end(text_t *line, uint32 *flag)
{
    int32 pos;
    gsql_skip_comment_line(line, &pos, 0);
    if (pos < 0) {
        return;
    }
 
    text_t temp_line = { line->str, line->len };
    cm_trim_text(&temp_line);

    if (line->str[pos] == ';' || (temp_line.len == 1 && CM_TEXT_FIRST(&temp_line) == '/')) {
        *flag = GSQL_MULTI_END_TAG;
        return;
    }
}

void gsql_free_config(void)
{
    uint32 i;
    config_item_t *item = NULL;
    
    if (g_server_config != NULL) {
        cm_spin_lock(&g_server_config_lock, NULL);
        cm_free_config_buf(g_server_config);
        free(g_server_config);
        g_server_config = NULL;
        cm_spin_unlock(&g_server_config_lock);
    }

    if (g_zsql_config != NULL) {
        cm_free_config_buf(g_zsql_config);
        free(g_zsql_config);
        g_zsql_config = NULL;
    }

    cm_spin_lock(&g_client_parameters_lock, NULL);
    for (i = 0; i < GSQL_PARAMS_COUNT; i++) {
        item = &g_client_parameters[i];
        item->is_default = GS_TRUE;
        item->value = NULL;
    }
    cm_spin_unlock(&g_client_parameters_lock);
}

void gsql_if_not_enclosed(text_t *line)
{
    uint32 i;
    char c;
    text_t sub_line;

    if (g_in_enclosed_char == -1) {
        return;
    }

    for (i = 0; i < line->len; i++) {
        c = line->str[i];
        if (g_in_enclosed_char == c) {
            if (c == '\'' && (i + 1 < line->len) && line->str[i + 1] == '\'') {
                // consider c&c+1 as '', then skip them
                i++;
                continue;
            }
            g_in_enclosed_char = -1;
            i++;
            break;
        }
    }

    if (i > 0) {
        sub_line.str = line->str;
        sub_line.len = i;

        if (g_in_enclosed_char > 0 && sub_line.str[i - 1] == '\n') {
            // not enclosed yet, remove last LF
            CM_REMOVE_LAST(&sub_line);
        }

        if (GS_SUCCESS != gsql_concat_appendlf(&sub_line)) {
            return;
        }

        CM_REMOVE_FIRST_N(line, i);
    }
}

static uint32 gsql_utf8_chr_widths(char *chr, uint32 c_bytes)
{
    wchar_t wchr;
    uint32 c_widths = 0;
    (void)mbtowc(&wchr, chr, c_bytes);
#ifndef WIN32
    c_widths = (uint32)wcwidth(wchr);
#endif
    return c_widths;
}

void gsql_push_history(uint32 cmd_bytes, uint32 cmd_width, int *hist_count, char *cmd_buf, uint32 max_len)
{
    text_t ignore_passwd_text;
    int32 mattch_type;
    bool32 mattched = GS_FALSE;
    
    if (cmd_bytes == 0) {
        return;
    }

    cm_str2text(cmd_buf, &ignore_passwd_text);
    cm_text_try_map_key2type(&ignore_passwd_text, &mattch_type, &mattched);

    if (mattched == GS_TRUE) {
        return;
    }
    
    if (*hist_count < GSQL_MAX_HISTORY_SIZE - 1) {
        *hist_count += 1;
    }
    for (int i = *hist_count; i > 1; i--) {
        GSQL_CHECK_MEMS_SECURE(memcpy_s(&g_hist_list[i], sizeof(gsql_cmd_history_list_t),
                                        &g_hist_list[i - 1], sizeof(gsql_cmd_history_list_t)));
    }
    GSQL_CHECK_MEMS_SECURE(memcpy_s(g_hist_list[1].hist_buf, GSQL_HISTORY_BUF_SIZE, cmd_buf, GSQL_HISTORY_BUF_SIZE));
    g_hist_list[1].nbytes = cmd_bytes;
    g_hist_list[1].nwidths = cmd_width;
    return;
}

void gsql_cmd_clean_line(uint32 line_widths)
{
    uint32 line_wid = line_widths;
    while (line_wid--) {
        gsql_write(3, "\b \b");
    }
}

/* Calculate the position and total number of spaces used to space at the end of a line */
void gsql_set_endspace(gsql_cmd_history_list_t hist_list, uint32 ws_col, uint32 welcome_width,
                       uint32 *spacenum, bool8 *endspace)
{
    uint32 offset = 0;
    uint32 c_bytes = 0;
    uint32 c_widths = 0;
    uint32 nwidths = 0;
    uint32 space_num = 0;

    GSQL_CHECK_MEMS_SECURE(memset_s(endspace, GSQL_HISTORY_BUF_SIZE, 0, GSQL_HISTORY_BUF_SIZE));
    while (offset < hist_list.nbytes) {
        (void)cm_utf8_chr_bytes(hist_list.hist_buf[offset], &c_bytes);
        c_widths = gsql_utf8_chr_widths(hist_list.hist_buf + offset, c_bytes);
        offset += c_bytes;

        if (c_widths == 2 && (nwidths + space_num + welcome_width + 1) % ws_col == 0) {
            space_num++;
            endspace[(nwidths + space_num + welcome_width + 1) / ws_col] = GS_TRUE;
        }
        nwidths += c_widths;
    }
    *spacenum = space_num;
}

void gsql_hist_turn_up(const int *hist_count, int *list_num, uint32 *nbytes, uint32 *nwidths, uint32 ws_col,
                       uint32 welcome_width, uint32 *spacenum, bool8 *endspace, char *cmd_buf, uint32 max_len)
{
    if (*list_num > *hist_count - 1) {
        return;
    }
    if (*list_num == 0) {
        GSQL_CHECK_MEMS_SECURE(memcpy_s(g_hist_list[0].hist_buf, GSQL_HISTORY_BUF_SIZE, cmd_buf, *nbytes));
        g_hist_list[0].nbytes = *nbytes;
        g_hist_list[0].nwidths = *nwidths;
    }
    gsql_cmd_clean_line(*nwidths + *spacenum);
    (*list_num)++;

    *nbytes = g_hist_list[*list_num].nbytes;
    *nwidths = g_hist_list[*list_num].nwidths;

    GSQL_CHECK_MEMS_SECURE(memcpy_s(cmd_buf, max_len, g_hist_list[*list_num].hist_buf, *nbytes));
    gsql_write(*nbytes, g_hist_list[*list_num].hist_buf);
    gsql_write(2, " \b");
    gsql_set_endspace(g_hist_list[*list_num], ws_col, welcome_width, spacenum, endspace);
}

void gsql_hist_turn_down(int *list_num, uint32 *nbytes, uint32 *nwidths, uint32 ws_col, uint32 welcome_width,
                         uint32 *spacenum, bool8 *endspace, char *cmd_buf, uint32 max_len)
{
    if (*list_num < 1) {
        return;
    }
    gsql_cmd_clean_line(*nwidths + *spacenum);
    (*list_num)--;
        
    *nbytes = g_hist_list[*list_num].nbytes;
    *nwidths = g_hist_list[*list_num].nwidths;

    GSQL_CHECK_MEMS_SECURE(memcpy_s(cmd_buf, max_len, g_hist_list[*list_num].hist_buf, *nbytes));
    gsql_write(*nbytes, g_hist_list[*list_num].hist_buf);
    gsql_write(2, " \b");
    gsql_set_endspace(g_hist_list[*list_num], ws_col, welcome_width, spacenum, endspace);
}

void gsql_fgets_with_history(int *hist_count, int *list_num, uint32 welcome_width, char *cmd_buf, uint32 max_len)
{
    int32 key_char = 0;
    int32 direction_key = 0;

    uint32 c_bytes = 0;
    uint32 c_widths = 0;
    uint32 nbytes = 0;
    uint32 nwidths = 0;
    uint32 spacenum = 0; /* Record the number of spaces filled at the end of the line. */
    bool8 endspace[GSQL_HISTORY_BUF_SIZE]; /* Record the line number with space at the end of the line. */
    char chr[GSQL_UTF8_CHR_SIZE];
    uint32 ws_col = 0;
#ifndef WIN32
    struct winsize size;
    (void)ioctl(0, TIOCGWINSZ, &size);
    ws_col = size.ws_col;
    struct termios oldt;
    struct termios newt;
    (void)tcgetattr(STDIN_FILENO, &oldt);
    GSQL_CHECK_MEMS_SECURE(memcpy_s(&newt, sizeof(newt), &oldt, sizeof(oldt)));
    newt.c_lflag &= ~(ECHO | ICANON | ECHOE | ECHOK | ECHONL | ICRNL);
    newt.c_cc[VMIN] = 1;
    newt.c_cc[VTIME] = 0;
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &newt); /* Set terminal input echo off */
#endif
    GSQL_CHECK_MEMS_SECURE(memset_s(endspace, GSQL_HISTORY_BUF_SIZE, 0, GSQL_HISTORY_BUF_SIZE));
    while (key_char != CMD_KEY_ASCII_LF && key_char != CMD_KEY_ASCII_CR) {
        key_char = getchar();
        switch (key_char) {
            case CMD_KEY_ESCAPE:
                (void)getchar(); // '['
                direction_key = getchar();
                if (direction_key == CMD_KEY_UP) {
                    gsql_hist_turn_up(hist_count, list_num, &nbytes, &nwidths, ws_col, welcome_width, &spacenum,
                                      endspace, cmd_buf, max_len);
                    continue;
                } else if (direction_key == CMD_KEY_DOWN) {
                    gsql_hist_turn_down(list_num, &nbytes, &nwidths, ws_col, welcome_width, &spacenum, endspace,
                                        cmd_buf, max_len);
                    continue;
                } else if (direction_key == CMD_KEY_DEL) {
                    (void)getchar(); // '~'
                } else {
                    continue;
                }
            case CMD_KEY_ASCII_DEL:
            case CMD_KEY_ASCII_BS:
                if (nbytes == 0) {
                    continue;
                }
                (void)cm_utf8_reverse_str_bytes(cmd_buf + nbytes - 1, nbytes, &c_bytes);
                nbytes -= c_bytes;
                GSQL_CHECK_MEMS_SECURE(memcpy_s(chr, GSQL_UTF8_CHR_SIZE, cmd_buf + nbytes, c_bytes));
 
                c_widths = gsql_utf8_chr_widths(chr, c_bytes);
                for (int i = c_widths; i > 0; i--) {
                    gsql_write(3, "\b \b");
                }
                nwidths -= c_widths;
                /* When there is a filled in space at the end of the line, one more space should be deleted. */
                if ((nwidths + spacenum + welcome_width) % ws_col == 0 && c_widths == 2 &&
                    endspace[(nwidths + spacenum + welcome_width) / ws_col] == GS_TRUE) {
                    endspace[(nwidths + spacenum + welcome_width) / ws_col] = GS_FALSE;
                    spacenum--;
                    gsql_write(3, "\b \b");
                }
                continue;

            case CMD_KEY_ASCII_CR:
            case CMD_KEY_ASCII_LF:
                *list_num = 0;
                gsql_write(1, "\n");
                continue;

            default:
                (void)cm_utf8_chr_bytes((uint8)key_char, &c_bytes);
                if (nbytes + c_bytes > GSQL_HISTORY_BUF_SIZE - 2) {
                    continue;
                }
                GSQL_CHECK_MEMS_SECURE(memset_s(chr, GSQL_UTF8_CHR_SIZE, key_char, 1));
                for (uint32 i = 1; i < c_bytes; i++) {
                    key_char = getchar();
                    GSQL_CHECK_MEMS_SECURE(memset_s(chr + i, GSQL_UTF8_CHR_SIZE - i, key_char, 1));
                }
                c_widths = gsql_utf8_chr_widths(chr, c_bytes);
                /* If the char is invisible, skip */
                if (c_widths == -1) {
                    continue;
                }
                GSQL_CHECK_MEMS_SECURE(memcpy_s(cmd_buf + nbytes, MAX_CMD_LEN + 2 - nbytes, chr, c_bytes));
                nbytes += c_bytes;
                gsql_write(c_bytes, chr);
                /* UNIX console standard output requires special handling when the cursor is at the end of the line.
                   When the end of the line is exactly full of characters, the cursor needs to jump to the next line.
                   When there is only one space at the end of the line and the next character is full width, a space
                   needs to be filled in. */
                if (((nwidths + spacenum + welcome_width + 1) % ws_col == 0 && c_widths == 1) ||
                    ((nwidths + spacenum + welcome_width + 2) % ws_col == 0 && c_widths == 2)) {
                    gsql_write(2, " \b");
                } else if ((nwidths + spacenum + welcome_width + 1) % ws_col == 0 && c_widths == 2) {
                    spacenum++;
                    endspace[(nwidths + spacenum + welcome_width + 1) / ws_col] = GS_TRUE;
                }
                nwidths += c_widths;
                continue;
        }
    }
    gsql_push_history(nbytes, nwidths, hist_count, cmd_buf, max_len);
    GSQL_CHECK_MEMS_SECURE(memcpy_s(cmd_buf + nbytes, max_len - nbytes, "\n", 2));
#ifndef WIN32
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &oldt); /* Set terminal input echo on */
#endif
    return;
}

EXTER_ATTACK void gsql_run(FILE *in, bool32 is_file, char *cmd_buf, uint32 max_len)
{
    text_t line;

    uint32 flag = GSQL_SINGLE_TAG;
    uint32 line_no = 0;

    uint32 welcome_width = 0;
    int hist_count = 0;
    int list_num = 0;

    if (is_file == GS_FALSE) {
        for (int i = 0; i < GSQL_MAX_HISTORY_SIZE; i++) {
            GSQL_CHECK_MEMS_SECURE(memset_s(g_hist_list[i].hist_buf, GSQL_HISTORY_BUF_SIZE, 0, GSQL_HISTORY_BUF_SIZE));
        }
    }

    setlocale(LC_CTYPE, "");
#ifndef WIN32
    // Set setvbuf to no buffer to prevent plaintext passwords in Linux.
    (void)setvbuf(in, NULL, _IONBF, 0);
#endif
    while (!feof(in)) {
        welcome_width = gsql_print_welcome(flag & (GSQL_BLOCK_TAG | GSQL_MULTI_TAG | GSQL_COMMENT_TAG), line_no);

        IS_WORKING = GS_FALSE;

#ifndef WIN32
        if (g_local_config.history_on == GS_TRUE && is_file == GS_FALSE) {
            gsql_fgets_with_history(&hist_count, &list_num, welcome_width, cmd_buf, max_len);
        } else {
            if (fgets(cmd_buf, max_len, in) == NULL) {
                break;
            }
        }
#else
        if (fgets(cmd_buf, max_len, in) == NULL) {
            break;
        }
#endif
        IS_WORKING = GS_TRUE;
        g_local_config.is_cancel = GS_FALSE;

        /* If the single cmd is too long */
        if (gsql_if_illega_line(in, cmd_buf, max_len)) {
            continue;
        }

        cm_str2text(cmd_buf, &line);

        /* if got empty line */
        if (line.len == 0) {
            continue;
        }

        if (flag == GSQL_SINGLE_TAG) {
            // Attention: avoid trim input string, since the line-no dedicate in server will mismatch with client.
            gsql_if_multi_line(&line, &flag);
            if (flag == GSQL_EMPTY_TAG) {
                gsql_print_blank_line();
                flag = GSQL_SINGLE_TAG;
                continue;
            }

            // Attention: block input pri higher than multi-line, need check if block
            if (flag != GSQL_BLOCK_TAG && flag != GSQL_COMMENT_TAG) {
                gsql_if_block(&line, &flag);
            }

            if (flag & (GSQL_BLOCK_TAG | GSQL_MULTI_TAG | GSQL_COMMENT_TAG)) {
                line_no = 1;
            }
        }

        gsql_try_spool_directly_put(cmd_buf);
        if (flag == GSQL_SINGLE_TAG) {
            (void)gsql_process_cmd(&line);
        } else if (flag == GSQL_COMMENT_TAG) {
            gsql_if_comment_end(&line, &flag);
            (void)gsql_concat(&line);
            if (flag == GSQL_COMMENT_END_TAG) {
                flag = GSQL_SINGLE_TAG;
            } else {
                line_no++;
            }
        } else if (flag == GSQL_BLOCK_TAG) {
            gsql_if_block_end(&line, &flag);
            (void)gsql_concat(&line);
            if (flag == GSQL_BLOCK_END_TAG) {
                print_sql_command(g_sql_text.str, g_sql_text.len);
                gsql_reset_in_enclosed_char();
                (void)gsql_execute(NULL);
                GSQL_RESET_CMD_TYPE(&g_cmd_type);
                CM_TEXT_CLEAR(&g_sql_text);
                flag = GSQL_SINGLE_TAG;
            } else {
                line_no++;
            }
        } else {
            gsql_if_not_enclosed(&line);
            gsql_if_multi_line_end(&line, &flag);
            (void)gsql_process_cmd(&line);

            if (flag == GSQL_MULTI_END_TAG) {
                flag = GSQL_SINGLE_TAG;
            } else {
                line_no++;
            }
        }

        gsql_reset_cmd_buf(cmd_buf, max_len);
    }
}

status_t gsql_conn_cancel(gsql_conn_info_t *conn_info)
{
    gsql_conn_info_t cancel_conn_info;

    cancel_conn_info = *conn_info;
    cancel_conn_info.stmt = NULL;
    cancel_conn_info.conn = NULL;
    if (gsql_alloc_conn(&cancel_conn_info.conn) != GS_SUCCESS) {
        return GS_ERROR;
    }
    cancel_conn_info.is_conn = GS_FALSE;
    if (gsql_get_saved_pswd(cancel_conn_info.passwd, sizeof(cancel_conn_info.passwd)) != GS_SUCCESS) {
        gsc_free_conn(cancel_conn_info.conn);
        return GS_ERROR;
    }
    cancel_conn_info.connect_by_install_user = conn_info->connect_by_install_user;
    cancel_conn_info.is_clsmgr = conn_info->is_clsmgr;
    (void)gsql_switch_user(&cancel_conn_info);

    if (gsql_conn_to_server(&cancel_conn_info, GS_FALSE, GS_TRUE) != GS_SUCCESS) {
        gsc_free_conn(cancel_conn_info.conn);
        return GS_ERROR;
    }

    if (gsc_cancel(cancel_conn_info.conn, gsc_get_sid(conn_info->conn)) != GSC_SUCCESS) {
        gsc_free_conn(cancel_conn_info.conn);
        return GS_ERROR;
    }

    gsc_free_conn(cancel_conn_info.conn);
    return GSC_SUCCESS;
}

status_t gsql_cancel(void)
{
    status_t ret = GS_SUCCESS;

    g_local_config.is_cancel = GS_TRUE;

    cm_spin_lock(&g_cancel_lock, NULL);
    ret = gsql_conn_cancel(&g_conn_info);
    cm_spin_unlock(&g_cancel_lock);

    return ret;
}