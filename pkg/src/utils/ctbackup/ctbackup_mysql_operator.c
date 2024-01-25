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
 * ctbackup_mysql_operator.c
 *
 *
 * IDENTIFICATION
 * src/utils/ctbackup/ctbackup_mysql_operator.c
 *
 * -------------------------------------------------------------------------
 */
#include <signal.h>
#include <sys/wait.h>
#include "ctbackup_module.h"
#include "ctbackup_mysql_operator.h"

#define MYSQL_BACKUP_UNLOCK_WAIT_TIME 3

int g_ctbak_lock_instance_pid = CT_INVALID_INT32;

status_t ctbak_append_option_str(char* mysql_option_str, int option_str_len, const char* option_value,
                                 char* option_prefix)
{
    if (option_value == NULL) {
        MEMS_RETURN_IFERR(strcat_s(mysql_option_str, option_str_len, " "));
        MEMS_RETURN_IFERR(strcat_s(mysql_option_str, option_str_len, option_prefix));
        return CT_SUCCESS;
    }
    if (strlen(option_value) <= 0) {
        return CT_SUCCESS;
    }
    MEMS_RETURN_IFERR(strcat_s(mysql_option_str, option_str_len, " "));
    if (cm_str_equal(option_prefix, PWD_PARAM_OPTION)) {
        PRTS_RETURN_IFERR(snprintf_s(mysql_option_str, option_str_len, option_str_len - 1, "%s%s%s%s%s",
                                     mysql_option_str, option_prefix, SINGLE_QUOTE, option_value, SINGLE_QUOTE));
        return CT_SUCCESS;
    }
    MEMS_RETURN_IFERR(strcat_s(mysql_option_str, option_str_len, option_prefix));
    MEMS_RETURN_IFERR(strcat_s(mysql_option_str, option_str_len, option_value));
    return CT_SUCCESS;
}

static inline status_t ctbak_join_mysql_option_str(ctbak_param_t* ctbak_param,
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
    return CT_SUCCESS;
}

status_t ctback_lock_mysql_for_backup(ctbak_param_t *ctbak_param)
{
    if (g_ctbak_lock_instance_pid != CT_INVALID_INT32) {
        printf("[ctbackup]lock instance process already executed, do not need execute repeatedly.\n");
        return CT_SUCCESS;
    }
    char mysql_option_str[MYSQL_EXE_MAX_STR_LEN] = {0};
    CT_RETURN_IFERR(strcpy_s(mysql_option_str, MYSQL_EXE_MAX_STR_LEN, MYSQL_EXE));
    if (ctbak_join_mysql_option_str(ctbak_param, mysql_option_str, MYSQL_EXE_MAX_STR_LEN) != CT_SUCCESS) {
        printf("[ctbackup]Failed join mysql options!\n");
        return CT_ERROR;
    }
    CT_RETURN_IFERR(ctbak_append_option_str(mysql_option_str, MYSQL_EXE_MAX_STR_LEN, MYSQL_BACKUP_LOCK_SQL,
                                               MYSQL_EXE_CMD_LONG_OPTION));

    int child_pid = 0;
    text_t mysql_shell_cmd;
    cm_str2text((char *)mysql_option_str, &mysql_shell_cmd);
    if (ctbak_do_shell_background(&mysql_shell_cmd, &child_pid, WNOHANG) != CT_SUCCESS) {
        printf("[ctbackup]Failed to exec lock mysql for backup!\n");
        return CT_ERROR;
    }
    g_ctbak_lock_instance_pid = child_pid;
    return CT_SUCCESS;
}

static inline void ctback_print_wait_pid_status(int status)
{
    if (WIFEXITED((unsigned int)status)) {
        printf("Process exited, exit status is: %d\n", WEXITSTATUS((unsigned int)status));
        return;
    }
    if (WIFSIGNALED((unsigned int)status)) {
        printf("Process signaled, term sig is: %d\n", WTERMSIG((unsigned int)status));
        return;
    }
}

status_t ctback_unlock_mysql_for_backup(void)
{
    if (g_ctbak_lock_instance_pid == CT_INVALID_INT32) {
        printf("[ctbackup]lock instance process not exist!\n");
        return CT_ERROR;
    }
    int status;
    int wait = waitpid(g_ctbak_lock_instance_pid, &status, WNOHANG);
    if (wait < 0) {
        printf("[ctbackup]lock instance process not exist!\n");
        return CT_ERROR;
    }
    if (wait == g_ctbak_lock_instance_pid) {
        printf("[ctbackup]lock instance process already exit!\n");
        ctback_print_wait_pid_status(status);
        return CT_ERROR;
    }
    if (kill(g_ctbak_lock_instance_pid, SIGKILL) != CT_SUCCESS) {
        printf("[ctbackup]unlock instance failed: kill lock process failed!\n");
        return CT_ERROR;
    }
    // wait for kill
    sleep(1);
    wait = waitpid(g_ctbak_lock_instance_pid, &status, WNOHANG);
    if (wait != g_ctbak_lock_instance_pid) {
        printf("[ctbackup]lock instance process kill failed!\n");
        return CT_ERROR;
    }
    sleep(MYSQL_BACKUP_UNLOCK_WAIT_TIME);
    g_ctbak_lock_instance_pid = CT_INVALID_INT32;
    printf("[ctbackup]unlock instance success!\n");
    return CT_SUCCESS;
}
