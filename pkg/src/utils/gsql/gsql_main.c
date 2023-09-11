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
 * gsql_main.c
 *
 *
 * IDENTIFICATION
 * src/utils/gsql/gsql_main.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_text.h"
#include "gsql.h"
#include "cm_signal.h"
#include "cm_coredump.h"
#include "cm_log.h"
#include "gsql_common.h"

#define PRODUCT_NAME "cantian"
#define GSQL_NAME    "CTCLIENT"
#define GSQL_MAX_PARAMETER_CNT   (uint32)10

#ifdef WIN32
const char *gsql_get_dbversion()
{
    return "NONE";
}
#else
extern const char *gsql_get_dbversion(void);
#endif

static void gsql_show_version(void)
{
    gsql_printf("%s\n", gsql_get_dbversion());
}

static void gsql_show_usage(void)
{
    gsql_printf(PRODUCT_NAME " SQL Developer Command - Line(" GSQL_NAME ") help\n\n");
    gsql_printf("Usage 1: ctclient -h | -v \n\n");
    gsql_printf("    -h, -help     Shows help information.\n");
    gsql_printf("    -v, -version  Shows version information.\n\n\n");

    gsql_printf("Usage 2: ctclient \n\n");
    gsql_printf("    Run ctclient without any parameter to enter the interactive mode,\n");
    gsql_printf("    Then, run the 'conn user/password@host:port[/tenant]' command to connect to the database.\n\n\n");

    gsql_printf("Usage 3: ctclient [ <logon> [<options>] [<start>] ] \n\n");
    gsql_printf("  <logon> allows [ user [ /password ] @{host:port}[,...] [ /tenant ] ] [as sysdba] and [ / as { sysdba | clsmgr } [ host:port ] ]\n");
    gsql_printf("    user: Name of the user for logging in.\n");
    gsql_printf("    password: Password of the login user. Enter interactive mode if no password provided.\n"
                "              It is recommended for the reason of security to input password interactively.\n");
    gsql_printf("    host: IP address for logging in to the database. Currently, IPv4 and IPv6 are both supported.\n");
    gsql_printf("    port: Port for logging in to the database.\n");
    gsql_printf("    tenant: Name of the tenant which the user belongs to.The default value is TENANT$ROOT.\n");
    gsql_printf("    sysdba: Database administrator.\n");
    gsql_printf("    clsmgr: Cluster administrator.\n");
    gsql_printf("\n");
    gsql_printf("  <options> is [-q] [-w <timeout>] [-a] [-D \"data_home_path\"]\n");
    gsql_printf("    -q: Cancels the SSL login authentication. \n");
    gsql_printf("    -w: Timeout interval for the client to connect to the database.\n");
    gsql_printf("    <timeout>: Timeout interval (unit: second). The default value is 60s.\n"
                "               There are also special values. Value -1 indicates that the timeout interval is infinite,\n"
                "               and value 0 indicates no wait.\n");
    gsql_printf("    -a: Prints an executed SQL statement.\n"
                "        This parameter can be used together with -f, indicating to print and execute the\n"
                "        SQL statements in an SQL script file.\n");
    gsql_printf("    -D: Specify data home path.\n");
    gsql_printf("        Connect to cluster node must specify data home path.\n");
    gsql_printf("\n");
    gsql_printf("  <start> allows [-c \"execute-sql-command\"], [-f \"execute-sql-file\"], and [-s \"destination-file\"]\n");
    gsql_printf("          start options can only exists one case at the same time.\n");
    gsql_printf("    -c: Executes an SQL statement.\n");
    gsql_printf("    -f: Executes an SQL script file.\n");
    gsql_printf("    -s: Redirects command prompt and output to a specified file.\n");
    gsql_printf("\n");
    gsql_printf("  For example\n");
    gsql_printf("     ctclient / as sysdba\n"
                "                               Log in to a database as user sys in password-free mode.\n");
    gsql_printf("     ctclient user/user_pwd@127.0.0.1:1611\n"
                "                               Log in to the database as the specified user through the IP address 127.0.0.1 and port 1611.\n");
    gsql_printf("     ctclient user/user_pwd@127.0.0.1:1611/tenant\n"
                "                               Log in to the database as the specified user in the specified tenant through the IP address 127.0.0.1 and port 1611.\n");
    gsql_printf("     ctclient user/user_pwd@127.0.0.1:1611 -c \"SELECT 1 FROM SYS_DUMMY\"\n"
                "                               Log in to the database as the specified user through the IP address 127.0.0.1 and port 1611, \n"
                "                               and then execute the SQL statement \"SELECT 1 FROM SYS_DUMMY\".\n");
    gsql_printf("     ctclient user/user_pwd@127.0.0.1:1611 -f \"/home/user/example.sql\"\n"
                "                               Log in to the database as the specified user through the IP address 127.0.0.1 and port 1611,\n"
                "                               and then execute the \"/home/user/example.sql\".\n");
    gsql_printf("     ctclient user/user_pwd@127.0.0.1:1611,127.0.0.1:1612\n"
                "                               Log in to the database as the specified user through the IP address 127.0.0.1 and port 1611 \n"
                "                               or IP address 127.0.0.1 and port 1612.\n");
    gsql_printf("\n");
}

static void gsql_show_help(void)
{
    gsql_show_version();
    gsql_show_usage();
}

static void gsql_erase_argv_pwd(char *arg)
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
    gsql_erase_pwd(&conn_text, &pwd_text);
}

static status_t gsql_execute_cmd(gsql_cmd_t type, text_t *conn, text_t *cmd)
{
    status_t status = gsql_process_cmd(conn);
    if (status != GS_SUCCESS) {
        gsc_disconnect(CONN);
        exit(status);
    }

    gsql_printf("\n");

    switch (type) {
        case CMD_COMMAND:
            (void)gsql_print_welcome(GSQL_SINGLE_TAG, 0);

            if (CM_TEXT_END(cmd) == '/') {
                status = gsql_execute(cmd);
            } else {
                if (CM_TEXT_END(cmd) != ';') {
                    PRTS_RETURN_IFERR(sprintf_s(g_cmd_buf, MAX_CMD_LEN, "%s;", cmd->str));
                    (void)cm_text_set(cmd, cmd->len, '\0');
                    cm_str2text(g_cmd_buf, cmd);
                }
                status = gsql_process_cmd(cmd);
            }
            gsql_exit(GS_FALSE, status);

        case CMD_FILE:
            PRTS_RETURN_IFERR(sprintf_s(g_cmd_buf, MAX_CMD_LEN, "@%s", cmd->str));
            (void)cm_text_set(cmd, cmd->len, '\0');
            cm_str2text(g_cmd_buf, cmd);
            status = gsql_process_cmd(cmd);
            gsql_exit(GS_FALSE, status);

        case CMD_SILENT:
            gsql_silent(cmd);
            break;

        default:
            break;
    }
    return GS_SUCCESS;
}

static status_t gsql_parse_timeout(int32 argc, char *argv[], uint32 index)
{
    if (index >= (uint32)argc || strlen(argv[index]) == 0) {
        GSQL_PRINTF(ZSERR_MAIN, "Input connect timeout value is invalid: %s", argv[index]);
        return GS_ERROR;
    }

    if (cm_str2int(argv[index], &g_local_config.connect_timeout) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (g_local_config.connect_timeout < -1) {
        GSQL_PRINTF(ZSERR_MAIN, "Input connect timeout value is invalid: %s", argv[index]);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t gsql_parse_conn_args(int32 argc, char *argv[], text_t *conn_text, text_t *cmd, gsql_cmd_t *cmd_type)
{
    for (uint32 loop = 1; loop < (uint32)argc; ++loop) {
        if (conn_text->len + strlen(argv[loop]) + 1 > MAX_CMD_LEN) {
            GSQL_PRINTF(ZSERR_MAIN, "Input is too long (> %d characters) - line ignored", MAX_CMD_LEN);
            return GS_ERROR;
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
                return GS_ERROR;
            }
            g_local_config.print_on = GS_TRUE;
            continue;
        }

        if (cm_str_equal(argv[loop], "-q")) {
            if (loop == 1) {
                return GS_ERROR;
            }
            g_local_config.zsql_ssl_quiet = GS_TRUE;
            continue;
        }

        if (cm_str_equal(argv[loop], "-w")) {
            if (loop == 1) {
                return GS_ERROR;
            }
            GS_RETURN_IFERR(gsql_parse_timeout(argc, argv, ++loop));
            continue;
        }

        if (*cmd_type != CMD_NONE) {
            if (loop != argc - 2) {
                return GS_ERROR;
            }

            cm_str2text(argv[++loop], cmd);
            if (CM_IS_EMPTY(cmd)) {
                return GS_ERROR;
            }

            break;
        }

        GS_RETURN_IFERR(cm_concat_string(conn_text, MAX_CMD_LEN + 2, " "));
        GS_RETURN_IFERR(cm_concat_string(conn_text, MAX_CMD_LEN + 2, argv[loop]));
    }

    return GS_SUCCESS;
}

static status_t gsql_clone_argv(const text_t *src, char **dest)
{
    status_t errcode;
    *dest = (char *)malloc(sizeof(char) * (src->len + 1));
    if (*dest == NULL) {
        return GS_ERROR;
    }

    errcode = strncpy_s(*dest, src->len + 1, src->str, src->len);
    if (errcode != EOK) {
        CM_FREE_PTR(*dest);
        GS_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t gsql_fetch_and_exec_connect(int32 argc, char *argv[])
{
    text_t conn_text = { .str = g_cmd_buf, .len = 0 }, cmd = { 0 };
    gsql_cmd_t exter_cmd = CMD_NONE;
    status_t ret;
    char *cmd_str = NULL;

    GS_RETURN_IFERR(cm_concat_string(&conn_text, MAX_CMD_LEN + 2, "conn"));
    GS_RETURN_IFERR(gsql_parse_conn_args(argc, argv, &conn_text, &cmd, &exter_cmd));

    if (exter_cmd == CMD_COMMAND) {
        GS_RETURN_IFERR(gsql_clone_argv(&cmd, &cmd_str));
        cmd.str = cmd_str;
        gsql_erase_string(argv[argc - 1]);
        argv[argc - 1][0] = '*';
    }
    
    gsql_erase_argv_pwd(argv[1]);

    IS_WORKING = GS_TRUE;
    ret = gsql_execute_cmd(exter_cmd, &conn_text, &cmd);
    IS_WORKING = GS_FALSE;
    (void)cm_text_set(&cmd, cmd.len, '\0');
    gsql_erase_string(cmd_str);
    CM_FREE_PTR(cmd_str);
    return ret;
}

EXTER_ATTACK status_t gsql_process_args(int32 argc, char *argv[])
{
    if (cm_str_equal(argv[1], "-v") || cm_str_equal(argv[1], "-version")) {
        gsql_show_version();
        exit(EXIT_SUCCESS);
    }

    if (cm_str_equal(argv[1], "-h") || cm_str_equal(argv[1], "-help")) {
        gsql_show_help();
        exit(EXIT_SUCCESS);
    }

    if (argc > GSQL_MAX_PARAMETER_CNT) {
        gsql_printf("The current number of ctclient parameters is exceeds %u\n", GSQL_MAX_PARAMETER_CNT);
        gsql_show_help();
        exit(EXIT_FAILURE);
    }

    return gsql_fetch_and_exec_connect(argc, argv);
}

#ifndef WIN32
static void gsql_handle_sigint(int32 signo)
{
    if (IS_CONN && IS_WORKING) {
        (void)gsql_cancel();
    }
}
#else

BOOL gsql_handle_sigint(DWORD fdwCtrlType)
{
    if (IS_CONN && IS_WORKING) {
        if (fdwCtrlType == CTRL_C_EVENT) {
            (void)gsql_cancel();
        }
    }

    return TRUE;
}
#endif

int32 main(int32 argc, char *argv[])
{
    SET_UNHANDLED_EXECEPTION_FILTER("gsql");

    cm_init_error_handler(cm_set_clt_error);

    GS_RETURN_IFERR(cm_regist_signal(SIGQUIT, SIG_IGN));
#ifndef WIN32
    GS_RETURN_IFERR(cm_regist_signal(SIGINT, gsql_handle_sigint));
#else
    if (!SetConsoleCtrlHandler((PHANDLER_ROUTINE)gsql_handle_sigint, TRUE)) {
        return GS_ERROR;
    }
#endif

    gsql_init(argc, argv);

    if (argc > 1) {
        if (gsql_process_args(argc, argv) != GS_SUCCESS) {
            gsql_show_usage();
            exit(EXIT_FAILURE);
        }
    }

    /* run GSQL from standard input stream */
    gsql_run(stdin, GS_FALSE, g_cmd_buf, sizeof(g_cmd_buf));
    gsql_free_config();
    gsql_exit(GS_FALSE, 0);
}
