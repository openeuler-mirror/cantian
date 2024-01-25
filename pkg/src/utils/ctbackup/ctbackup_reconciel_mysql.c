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
 * ctbackup_reconciel_mysql.c
 *
 *
 * IDENTIFICATION
 * src/utils/ctbackup/ctbackup_reconciel_mysql.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctbackup_module.h"
#include "ctbackup_reconciel_mysql.h"
#include "ctbackup_info.h"
#include "ctbackup_common.h"
#include "cm_defs.h"
#include "ctbackup_mysql_operator.h"

const struct option ctbak_reconciel_mysql_options[] = {
    {CTBAK_LONG_OPTION_RECONCIEL_MYSQL, no_argument, NULL, CTBAK_PARSE_OPTION_COMMON},
    {CTBAK_LONG_OPTION_USER, required_argument, NULL, CTBAK_SHORT_OPTION_USER},
    {CTBAK_LONG_OPTION_HOST, required_argument, NULL, CTBAK_SHORT_OPTION_HOST},
    {CTBAK_LONG_OPTION_PASSWORD, required_argument, NULL, CTBAK_SHORT_OPTION_PASSWORD},
    {CTBAK_LONG_OPTION_PORT, required_argument, NULL, CTBAK_SHORT_OPTION_PORT},
    {CTBAK_LONG_OPTION_SOCKET, required_argument, NULL, CTBAK_SHORT_OPTION_SOCKET},
    {CTBAK_LONG_OPTION_FORCE_DDL, no_argument, NULL, CTBAK_SHORT_OPTION_FORCE_DDL},
    {0, 0, 0, 0}
};

static inline void ctbak_hide_password(char* password)
{
    while (*password) {
        *password++ = 'x';
    }
}

/**
 * 1. Obtaining the Archive Path
 * @param char*
 * @return
 */
status_t set_exec_param(char* exec_param)
{
    char *path = getenv("CTDB_DATA");
    if (path == NULL) {
        printf("[ctbackup]get path for mysql failed!\n");
        return CT_ERROR;
    }
    MEMS_RETURN_IFERR(strcat_s(exec_param, MYSQL_EXE_MAX_STR_LEN, path));
    MEMS_RETURN_IFERR(strcat_s(exec_param, MYSQL_EXE_MAX_STR_LEN, SQL_ARCHIVE_PATH));
    printf("[ctbackup]get path for mysql succeed!\n");
    return CT_SUCCESS;
}

status_t ctbak_parse_reconciel_mysql_args(int32 argc, char** argv, ctbak_param_t* ctbak_param)
{
    int opt_s;
    int opt_index;
    optind = 1;
    while (optind < argc) {
        CT_RETURN_IFERR(check_input_params(argv[optind]));
        opt_s = getopt_long(argc, argv, CTBAK_SHORT_OPTION_EXP, ctbak_reconciel_mysql_options, &opt_index);
        if (opt_s == CTBAK_PARSE_OPTION_ERR) {
            break;
        }
        switch (opt_s) {
            case CTBAK_PARSE_OPTION_COMMON:
                break;
            case CTBAK_SHORT_OPTION_USER:
                CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->user));
                break;
            case CTBAK_SHORT_OPTION_PASSWORD:
                CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->password));
                ctbak_hide_password(optarg);
                break;
            case CTBAK_SHORT_OPTION_HOST:
                CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->host));
                break;
            case CTBAK_SHORT_OPTION_PORT:
                CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->port));
                break;
            case CTBAK_SHORT_OPTION_SOCKET:
                CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->socket));
                break;
            case CTBAK_SHORT_OPTION_FORCE_DDL:
                ctbak_param->is_force_ddl = CT_TRUE;
                break;
            case CTBAK_SHORT_OPTION_UNRECOGNIZED:
            case CTBAK_SHORT_OPTION_NO_ARG:
                printf("[ctbackup]Parse option arguments error!\n");
                return CT_ERROR;
            default:
                break;
        }
    }
    return CT_SUCCESS;
}

status_t fill_params_for_mysql_reconciel(ctbak_param_t* ctbak_param,
                                         char* mysql_option_str, int option_str_len)
{
    if (ctbak_param->host.len > 0) {
        CT_RETURN_IFERR(
            ctbak_append_option_str(mysql_option_str, option_str_len, ctbak_param->host.str, HOST_PARAM_OPTION));
    }
    if (ctbak_param->user.len > 0) {
        CT_RETURN_IFERR(
            ctbak_append_option_str(mysql_option_str, option_str_len, ctbak_param->user.str, USER_PARAM_OPTION));
    }
    if (ctbak_param->password.len > 0) {
        CT_RETURN_IFERR(
            ctbak_append_option_str(mysql_option_str, option_str_len, ctbak_param->password.str, PWD_PARAM_OPTION));
    }
    if (ctbak_param->port.len > 0) {
        CT_RETURN_IFERR(
            ctbak_append_option_str(mysql_option_str, option_str_len, ctbak_param->port.str, PORT_PARAM_OPTION));
    }
    if (ctbak_param->socket.len > 0) {
        CT_RETURN_IFERR(
            ctbak_append_option_str(mysql_option_str, option_str_len, ctbak_param->socket.str, SOCKET_PARAM_OPTION));
    }

    if (ctbak_param->is_force_ddl == CT_TRUE) {
        CT_RETURN_IFERR(
            ctbak_append_option_str(mysql_option_str, option_str_len, NULL, FORCE_DDL_IGNORE_ERROR));
    }

    char exec_param[MYSQL_EXE_MAX_STR_LEN] = {0};
    CT_RETURN_IFERR(set_exec_param((char *)exec_param));
    CT_RETURN_IFERR(ctbak_parse_single_arg((char *)exec_param, &ctbak_param->execute));
    CT_RETURN_IFERR(
        ctbak_append_option_str(mysql_option_str, option_str_len, ctbak_param->execute.str, EXEC_PARAM_OPTION));
    return CT_SUCCESS;
}

/**
 * 1. decode params for mysql reconciel_mysql
 * 2. Mysql execute reconciel_mysql
 * @param ctbak_param
 * @return
 */
status_t ctbak_do_reconciel_for_mysql(ctbak_param_t* ctbak_param)
{
    status_t status;

    printf("[ctbackup]ready to execute reconciel_mysql for mysql!\n");

    char mysql_option_str[MYSQL_EXE_MAX_STR_LEN] = {0};
    CT_RETURN_IFERR(strcpy_s(mysql_option_str, MYSQL_EXE_MAX_STR_LEN, MYSQL_EXE));
    status = fill_params_for_mysql_reconciel(ctbak_param, mysql_option_str, MYSQL_EXE_MAX_STR_LEN);
    if (status != CT_SUCCESS) {
        printf("[ctbackup]fill_params_for_mysql_reconciel_mysql failed!\n");
        return CT_ERROR;
    }
    int child_pid = 0;
    text_t mysql_shell_cmd;
    cm_str2text((char *)mysql_option_str, &mysql_shell_cmd);
    if (ctbak_do_shell_background(&mysql_shell_cmd, &child_pid, 0) != CT_SUCCESS) {
        printf("[ctbackup]ctbackup execute reconciel_mysql for mysql failed!\n");
        return CT_ERROR;
    }

    printf("[ctbackup]ctbackup execute reconciel_mysql for mysql success!\n");

    return CT_SUCCESS;
}

status_t ctbak_do_reconciel(ctbak_param_t* ctbak_param)
{
    if (ctbackup_set_metadata_mode(ctbak_param) != CT_SUCCESS) {
        free_input_params(ctbak_param);
        return CT_ERROR;
    }
    if (ctbak_param->is_mysql_metadata_in_cantian == CT_TRUE) {
        printf("[ctbackup]no need to do reconciel for mysql in mysql_metadata_in_cantian mode\n");
    } else if (ctbak_do_reconciel_for_mysql(ctbak_param) != CT_SUCCESS) {
        free_input_params(ctbak_param);
        return CT_ERROR;
    }
    free_input_params(ctbak_param);
    return CT_SUCCESS;
}

ctbak_cmd_t *ctbak_generate_reconciel_mysql_cmd(void)
{
    ctbak_cmd_t* ctbak_cmd = (ctbak_cmd_t*)malloc(sizeof(ctbak_cmd_t));
    if (ctbak_cmd == NULL) {
        printf("[ctbackup]failed to malloc memory for reconciel-mysql ctbak_cmd!\n");
        return (ctbak_cmd_t *)NULL;
    }
    ctbak_cmd->parse_args = ctbak_parse_reconciel_mysql_args;
    ctbak_cmd->do_exec = ctbak_do_reconciel;
    return ctbak_cmd;
}
