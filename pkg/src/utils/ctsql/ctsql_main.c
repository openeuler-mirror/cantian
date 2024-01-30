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
 * ctsql_main.c
 *
 *
 * IDENTIFICATION
 * src/utils/ctsql/ctsql_main.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_text.h"
#include "ctsql.h"
#include "cm_signal.h"
#include "cm_coredump.h"
#include "cm_log.h"
#include "ctsql_common.h"

#define PRODUCT_NAME "cantian"
#define CTSQL_NAME    "CTSQL"
#define CTSQL_MAX_PARAMETER_CNT   (uint32)10

#ifdef WIN32
const char *ctsql_get_dbversion()
{
    return "NONE";
}
#else
extern const char *ctsql_get_dbversion(void);
#endif

static void ctsql_show_version(void)
{
    ctsql_printf("%s\n", ctsql_get_dbversion());
}

static void ctsql_show_usage(void)
{
    ctsql_printf(PRODUCT_NAME " SQL Developer Command - Line(" CTSQL_NAME ") help\n\n");
    ctsql_printf("Usage 1: ctsql -h | -v \n\n");
    ctsql_printf("    -h, -help     Shows help information.\n");
    ctsql_printf("    -v, -version  Shows version information.\n\n\n");

    ctsql_printf("Usage 2: ctsql \n\n");
    ctsql_printf("    Run ctsql without any parameter to enter the interactive mode,\n");
    ctsql_printf("    Then, run the 'conn user/password@host:port[/tenant]' command to connect to the database.\n\n\n");

    ctsql_printf("Usage 3: ctsql [ <logon> [<options>] [<start>] ] \n\n");
    ctsql_printf("  <logon> allows [ user [ /password ] @{host:port}[,...] [ /tenant ] ] [as sysdba] and [ / as { sysdba | clsmgr } [ host:port ] ]\n");
    ctsql_printf("    user: Name of the user for logging in.\n");
    ctsql_printf("    password: Password of the login user. Enter interactive mode if no password provided.\n"
                "              It is recommended for the reason of security to input password interactively.\n");
    ctsql_printf("    host: IP address for logging in to the database. Currently, IPv4 and IPv6 are both supported.\n");
    ctsql_printf("    port: Port for logging in to the database.\n");
    ctsql_printf("    tenant: Name of the tenant which the user belongs to.The default value is TENANT$ROOT.\n");
    ctsql_printf("    sysdba: Database administrator.\n");
    ctsql_printf("    clsmgr: Cluster administrator.\n");
    ctsql_printf("\n");
    ctsql_printf("  <options> is [-q] [-w <timeout>] [-a] [-D \"data_home_path\"]\n");
    ctsql_printf("    -q: Cancels the SSL login authentication. \n");
    ctsql_printf("    -w: Timeout interval for the client to connect to the database.\n");
    ctsql_printf("    <timeout>: Timeout interval (unit: second). The default value is 60s.\n"
                "               There are also special values. Value -1 indicates that the timeout interval is infinite,\n"
                "               and value 0 indicates no wait.\n");
    ctsql_printf("    -a: Prints an executed SQL statement.\n"
                "        This parameter can be used together with -f, indicating to print and execute the\n"
                "        SQL statements in an SQL script file.\n");
    ctsql_printf("    -D: Specify data home path.\n");
    ctsql_printf("        Connect to cluster node must specify data home path.\n");
    ctsql_printf("\n");
    ctsql_printf("  <start> allows [-c \"execute-sql-command\"], [-f \"execute-sql-file\"], and [-s \"destination-file\"]\n");
    ctsql_printf("          start options can only exists one case at the same time.\n");
    ctsql_printf("    -c: Executes an SQL statement.\n");
    ctsql_printf("    -f: Executes an SQL script file.\n");
    ctsql_printf("    -s: Redirects command prompt and output to a specified file.\n");
    ctsql_printf("\n");
    ctsql_printf("  For example\n");
    ctsql_printf("     ctsql / as sysdba\n"
                "                               Log in to a database as user sys in password-free mode.\n");
    ctsql_printf("     ctsql user/user_pwd@127.0.0.1:1611\n"
                "                               Log in to the database as the specified user through the IP address 127.0.0.1 and port 1611.\n");
    ctsql_printf("     ctsql user/user_pwd@127.0.0.1:1611/tenant\n"
                "                               Log in to the database as the specified user in the specified tenant through the IP address 127.0.0.1 and port 1611.\n");
    ctsql_printf("     ctsql user/user_pwd@127.0.0.1:1611 -c \"SELECT 1 FROM SYS_DUMMY\"\n"
                "                               Log in to the database as the specified user through the IP address 127.0.0.1 and port 1611, \n"
                "                               and then execute the SQL statement \"SELECT 1 FROM SYS_DUMMY\".\n");
    ctsql_printf("     ctsql user/user_pwd@127.0.0.1:1611 -f \"/home/user/example.sql\"\n"
                "                               Log in to the database as the specified user through the IP address 127.0.0.1 and port 1611,\n"
                "                               and then execute the \"/home/user/example.sql\".\n");
    ctsql_printf("     ctsql user/user_pwd@127.0.0.1:1611,127.0.0.1:1612\n"
                "                               Log in to the database as the specified user through the IP address 127.0.0.1 and port 1611 \n"
                "                               or IP address 127.0.0.1 and port 1612.\n");
    ctsql_printf("\n");
}

static void ctsql_show_help(void)
{
    ctsql_show_version();
    ctsql_show_usage();
}

static void ctsql_erase_argv_pwd(char *arg)
{
    text_t conn_text, user_text, pwd_text;
    cm_str2text(arg, &conn_text);

    if (!cm_fetch_text(&conn_text, '/', 0, &user_text)) {
        return;
    }

    if (!cm_fetch_rtext(&conn_text, '@', 0, &pwd_text)) {
        return;
    }
    cm_str2text(arg, &conn_text);
    ctsql_erase_pwd(&conn_text, &pwd_text);
}

static status_t ctsql_execute_cmd(ctsql_cmd_t type, text_t *conn, text_t *cmd)
{
    status_t status = ctsql_process_cmd(conn);
    if (status != CT_SUCCESS) {
        ctconn_disconnect(CONN);
        exit(status);
    }

    ctsql_printf("\n");

    switch (type) {
        case CMD_COMMAND:
            (void)ctsql_print_welcome(CTSQL_SINGLE_TAG, 0);

            if (CM_TEXT_END(cmd) == '/') {
                status = ctsql_execute(cmd);
            } else {
                if (CM_TEXT_END(cmd) != ';') {
                    PRTS_RETURN_IFERR(sprintf_s(g_cmd_buf, MAX_CMD_LEN, "%s;", cmd->str));
                    (void)cm_text_set(cmd, cmd->len, '\0');
                    cm_str2text(g_cmd_buf, cmd);
                }
                status = ctsql_process_cmd(cmd);
            }
            ctsql_exit(CT_FALSE, status);

        case CMD_FILE:
            PRTS_RETURN_IFERR(sprintf_s(g_cmd_buf, MAX_CMD_LEN, "@%s", cmd->str));
            (void)cm_text_set(cmd, cmd->len, '\0');
            cm_str2text(g_cmd_buf, cmd);
            status = ctsql_process_cmd(cmd);
            ctsql_exit(CT_FALSE, status);

        case CMD_SILENT:
            ctsql_silent(cmd);
            break;

        default:
            break;
    }
    return CT_SUCCESS;
}

static status_t ctsql_parse_timeout(int32 argc, char *argv[], uint32 index)
{
    if (index >= (uint32)argc || strlen(argv[index]) == 0) {
        CTSQL_PRINTF(ZSERR_MAIN, "Input connect timeout value is invalid: %s", argv[index]);
        return CT_ERROR;
    }

    if (cm_str2int(argv[index], &g_local_config.connect_timeout) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (g_local_config.connect_timeout < -1) {
        CTSQL_PRINTF(ZSERR_MAIN, "Input connect timeout value is invalid: %s", argv[index]);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t ctsql_parse_conn_args(int32 argc, char *argv[], text_t *conn_text, text_t *cmd, ctsql_cmd_t *cmd_type)
{
    for (uint32 loop = 1; loop < (uint32)argc; ++loop) {
        if (conn_text->len + strlen(argv[loop]) + 1 > MAX_CMD_LEN) {
            CTSQL_PRINTF(ZSERR_MAIN, "Input is too long (> %d characters) - line ignored", MAX_CMD_LEN);
            return CT_ERROR;
        }

        if (cm_str_equal(argv[loop], "-c")) {
            *cmd_type = CMD_COMMAND;
        }

        if (cm_str_equal(argv[loop], "-f")) {
            *cmd_type = CMD_FILE;
        }

        if (cm_str_equal(argv[loop], "-s")) {
            *cmd_type = CMD_SILENT;
        }

        if (cm_str_equal(argv[loop], "-a")) {
            if (loop == 1) {
                return CT_ERROR;
            }
            g_local_config.print_on = CT_TRUE;
            continue;
        }

        if (cm_str_equal(argv[loop], "-q")) {
            if (loop == 1) {
                return CT_ERROR;
            }
            g_local_config.CTSQL_SSL_QUIET = CT_TRUE;
            continue;
        }

        if (cm_str_equal(argv[loop], "-w")) {
            if (loop == 1) {
                return CT_ERROR;
            }
            CT_RETURN_IFERR(ctsql_parse_timeout(argc, argv, ++loop));
            continue;
        }

        if (*cmd_type != CMD_NONE) {
            if (loop != argc - 2) {
                return CT_ERROR;
            }

            cm_str2text(argv[++loop], cmd);
            if (CM_IS_EMPTY(cmd)) {
                return CT_ERROR;
            }

            break;
        }

        CT_RETURN_IFERR(cm_concat_string(conn_text, MAX_CMD_LEN + 2, " "));
        CT_RETURN_IFERR(cm_concat_string(conn_text, MAX_CMD_LEN + 2, argv[loop]));
    }

    return CT_SUCCESS;
}

static status_t ctsql_clone_argv(const text_t *src, char **dest)
{
    status_t errcode;
    *dest = (char *)malloc(sizeof(char) * (src->len + 1));
    if (*dest == NULL) {
        return CT_ERROR;
    }

    errcode = strncpy_s(*dest, src->len + 1, src->str, src->len);
    if (errcode != EOK) {
        CM_FREE_PTR(*dest);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t ctsql_fetch_and_exec_connect(int32 argc, char *argv[])
{
    text_t conn_text = { .str = g_cmd_buf, .len = 0 }, cmd = { 0 };
    ctsql_cmd_t exter_cmd = CMD_NONE;
    status_t ret;
    char *cmd_str = NULL;

    CT_RETURN_IFERR(cm_concat_string(&conn_text, MAX_CMD_LEN + 2, "conn"));
    CT_RETURN_IFERR(ctsql_parse_conn_args(argc, argv, &conn_text, &cmd, &exter_cmd));

    if (exter_cmd == CMD_COMMAND) {
        CT_RETURN_IFERR(ctsql_clone_argv(&cmd, &cmd_str));
        cmd.str = cmd_str;
        ctsql_erase_string(argv[argc - 1]);
        argv[argc - 1][0] = '*';
    }
    
    ctsql_erase_argv_pwd(argv[1]);

    IS_WORKING = CT_TRUE;
    ret = ctsql_execute_cmd(exter_cmd, &conn_text, &cmd);
    IS_WORKING = CT_FALSE;
    (void)cm_text_set(&cmd, cmd.len, '\0');
    ctsql_erase_string(cmd_str);
    CM_FREE_PTR(cmd_str);
    return ret;
}

EXTER_ATTACK status_t ctsql_process_args(int32 argc, char *argv[])
{
    if (cm_str_equal(argv[1], "-v") || cm_str_equal(argv[1], "-version")) {
        ctsql_show_version();
        exit(EXIT_SUCCESS);
    }

    if (cm_str_equal(argv[1], "-h") || cm_str_equal(argv[1], "-help")) {
        ctsql_show_help();
        exit(EXIT_SUCCESS);
    }

    if (argc > CTSQL_MAX_PARAMETER_CNT) {
        ctsql_printf("The current number of ctsql parameters is exceeds %u\n", CTSQL_MAX_PARAMETER_CNT);
        ctsql_show_help();
        exit(EXIT_FAILURE);
    }

    return ctsql_fetch_and_exec_connect(argc, argv);
}

#ifndef WIN32
static void ctsql_handle_sigint(int32 signo)
{
    if (IS_CONN && IS_WORKING) {
        (void)ctsql_cancel();
    }
}
#else

BOOL ctsql_handle_sigint(DWORD fdwCtrlType)
{
    if (IS_CONN && IS_WORKING) {
        if (fdwCtrlType == CTRL_C_EVENT) {
            (void)ctsql_cancel();
        }
    }

    return TRUE;
}
#endif

int32 main(int32 argc, char *argv[])
{
    SET_UNHANDLED_EXECEPTION_FILTER("ctsql");

    cm_init_error_handler(cm_set_clt_error);

    CT_RETURN_IFERR(cm_regist_signal(SIGQUIT, SIG_IGN));
#ifndef WIN32
    CT_RETURN_IFERR(cm_regist_signal(SIGINT, ctsql_handle_sigint));
#else
    if (!SetConsoleCtrlHandler((PHANDLER_ROUTINE)ctsql_handle_sigint, TRUE)) {
        return CT_ERROR;
    }
#endif

    ctsql_init(argc, argv);

    if (argc > 1) {
        if (ctsql_process_args(argc, argv) != CT_SUCCESS) {
            ctsql_show_usage();
            exit(EXIT_FAILURE);
        }
    }

    /* run CTSQL from standard input stream */
    ctsql_run(stdin, CT_FALSE, g_cmd_buf, sizeof(g_cmd_buf));
    ctsql_free_config();
    ctsql_exit(CT_FALSE, 0);
}
