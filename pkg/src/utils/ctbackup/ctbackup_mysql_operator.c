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
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <signal.h>
#include <fcntl.h>
#include "cm_date.h"
#include "cm_utils.h"
#include "cm_text.h"
#include "ctbackup_module.h"
#include "ctbackup_mysql_operator.h"

#define ELAPSED_BEGIN(elapsed_begin) ((void)cm_gettimeofday(&(elapsed_begin)))
#define ELAPSED_END(elapsed_begin, target) \
    do { \
        timeval_t elapsed_end; \
        (void)cm_gettimeofday(&(elapsed_end)); \
        (target) = TIMEVAL_DIFF_US(&(elapsed_begin), &(elapsed_end)); \
    } while (0)

#define MYSQL_SHELL_EXE "python /opt/cantian/action/cantian_common/mysql_shell.py"
#define MYSQL_SET_DDL_ENABLE_CMD "set @ctc_ddl_enabled=true;"
#define MYSQL_LOCK_INSTANCE_CMD "lock instance for backup;"
#define MYSQL_CMD_SUCCESS_SYMBOL "Query OK, 0 rows affected"
#define MYSQL_CMD_PARAM_OPTION "--mysql_cmd="
#define MYSQL_LOCK_INSTANCE_TIMEOUT 20000000 // us
#define MYSQL_LOCK_INSTANCE_INTERVAL 1000 //ms
#define MYSQL_LOCK_INSTANCE_RETRY_NUM 3
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
    MEMS_RETURN_IFERR(strcat_s(mysql_option_str, option_str_len, " "));
    MEMS_RETURN_IFERR(strcat_s(mysql_option_str, option_str_len, MYSQL_CMD_PARAM_OPTION));
    MEMS_RETURN_IFERR(strcat_s(mysql_option_str, option_str_len, MYSQL_EXE));
    if (ctbak_param->host.len > 0) {
        MEMS_RETURN_IFERR(strcat_s(mysql_option_str, option_str_len, " "));
        MEMS_RETURN_IFERR(strcat_s(mysql_option_str, option_str_len, HOST_PARAM_OPTION));
        MEMS_RETURN_IFERR(strcat_s(mysql_option_str, option_str_len, ctbak_param->host.str));
    }
    if (ctbak_param->user.len > 0) {
        MEMS_RETURN_IFERR(strcat_s(mysql_option_str, option_str_len, " "));
        MEMS_RETURN_IFERR(strcat_s(mysql_option_str, option_str_len, USER_PARAM_OPTION));
        MEMS_RETURN_IFERR(strcat_s(mysql_option_str, option_str_len, ctbak_param->user.str));
    }
    if (ctbak_param->port.len > 0) {
        MEMS_RETURN_IFERR(strcat_s(mysql_option_str, option_str_len, " "));
        MEMS_RETURN_IFERR(strcat_s(mysql_option_str, option_str_len, PORT_PARAM_OPTION));
        MEMS_RETURN_IFERR(strcat_s(mysql_option_str, option_str_len, ctbak_param->port.str));
    }
    if (ctbak_param->socket.len > 0) {
        MEMS_RETURN_IFERR(strcat_s(mysql_option_str, option_str_len, " "));
        MEMS_RETURN_IFERR(strcat_s(mysql_option_str, option_str_len, SOCKET_PARAM_OPTION));
        MEMS_RETURN_IFERR(strcat_s(mysql_option_str, option_str_len, ctbak_param->socket.str));
    }
    return CT_SUCCESS;
}

void ctbak_kill_lock_instance_process(pid_t pid)
{
    errno_t status = 0;
    if (kill(pid, SIGKILL) != CT_SUCCESS) {
        printf("[ctbackup]unlock instance failed: kill lock process failed!\n");
        return;
    }
    cm_sleep(MYSQL_LOCK_INSTANCE_INTERVAL);
    pid_t wait = waitpid(pid, &status, WNOHANG);
    if (wait != pid) {
        printf("[ctbackup]lock instance process kill failed!, ret=%d\n", status);
    }
    return;
}

status_t ctbak_write_mysql_params(int32 pipe_fd, text_t *mysql_passwd)
{
    // 输入密码
    int32 size = write(pipe_fd, mysql_passwd->str, mysql_passwd->len);
    if (size == -1) {
        printf("[ctbackup]input mysql passwd failed!\n");
        return CT_ERROR;
    }
    // 结束密码输入
    size = write(pipe_fd, "\n", 1);
    if (size == -1) {
        printf("[ctbackup]finish to input mysql passwd failed!\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t ctbak_check_mysql_output(FILE *pipe_fp, char *check_cmd)
{
    char output[MAX_STATEMENT_LENGTH] = { 0 };
    timeval_t begin_time = { 0 };
    uint64 use_time = 0;
    bool32 found_cmd = CT_FALSE;
    ELAPSED_BEGIN(begin_time);
    while(use_time < MYSQL_LOCK_INSTANCE_TIMEOUT) {
        if (fgets(output, MAX_STATEMENT_LENGTH, pipe_fp) != NULL) {   
            if (strstr(output, "ERROR") != NULL || strstr(output, "Error") != NULL) {
                printf("%s", output);
                break;
            }
            if (found_cmd == CT_FALSE && strstr(output, check_cmd) != NULL) {
                found_cmd = CT_TRUE;
            }
            if (found_cmd == CT_TRUE && strstr(output, MYSQL_CMD_SUCCESS_SYMBOL) != NULL) {
                return CT_SUCCESS;
            }
        }
        cm_sleep(MYSQL_LOCK_INSTANCE_INTERVAL);
        ELAPSED_END(begin_time, use_time);
    }
    printf("[ctbackup] check mysql cmd output failed!\n");
    return CT_ERROR;
}
void ctbak_execute_lock_instance(int32 pipe_stdout, int32 pipe_stdin, text_t *mysql_passwd, bool32 *lock_succ)
{
    int flags = fcntl(pipe_stdout, F_GETFL, 0);
    fcntl(pipe_stdout, F_SETFL, flags | O_NONBLOCK);
    FILE *pipe_stdout_fp = fdopen(pipe_stdout, "r");
    if (pipe_stdout_fp == NULL) {
        *lock_succ = CT_FALSE;
        printf("[ctbackup]fdopen lock instance process pipe failed!\n");
        return;
    }
    do {
        if (ctbak_write_mysql_params(pipe_stdin, mysql_passwd) != CT_SUCCESS) {
            break;
        }
        if (ctbak_check_mysql_output(pipe_stdout_fp, MYSQL_SET_DDL_ENABLE_CMD) != CT_SUCCESS) {
            break;
        }
        if (ctbak_check_mysql_output(pipe_stdout_fp, MYSQL_LOCK_INSTANCE_CMD) != CT_SUCCESS) {
            break;
        }
        pclose(pipe_stdout_fp);
        *lock_succ = CT_TRUE; 
        return;
    } while (0);
    printf("[ctbackup]check mysql execute output failed!\n");
    *lock_succ = CT_FALSE;
    pclose(pipe_stdout_fp);
    return;
}

status_t ctback_lock_instance_for_backup(char *path, char *params[], text_t *mysql_passwd, pid_t *pid)
{
    errno_t status = 0;
    int32 pipe_stdout[2] = { 0 };
    int32 pipe_stdin[2] = { 0 };
    if (pipe(pipe_stdout) != EOK || pipe(pipe_stdin) != EOK) {
        printf("[ctbackup]create stdout or stdin pipe failed!\n");
        return CT_ERROR;
    }

    pid_t child_pid = fork();
    if (child_pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        close(pipe_stdout[PARENT_ID]);
        dup2(pipe_stdout[CHILD_ID], STD_OUT_ID);
        close(pipe_stdin[CHILD_ID]);
        dup2(pipe_stdin[PARENT_ID], STD_IN_ID);
        status = execv(path, params);
        perror("execv");
        if (status != EOK) {
            printf("[ctbackup]failed to execute command %d:%s\n", errno, strerror(errno));
            exit(CT_ERROR);
        }
    } else if (child_pid < 0) {
        printf("[ctbackup]failed to fork child process with result %d:%s\n", errno, strerror(errno));
        return CT_ERROR;
    }
    close(pipe_stdout[CHILD_ID]);
    close(pipe_stdin[PARENT_ID]);
    bool32 lock_succ = CT_FALSE;
    ctbak_execute_lock_instance(pipe_stdout[PARENT_ID], pipe_stdin[CHILD_ID], mysql_passwd, &lock_succ);
    close(pipe_stdout[PARENT_ID]);
    close(pipe_stdin[CHILD_ID]);

    if (lock_succ == CT_FALSE) {
        ctbak_kill_lock_instance_process(child_pid);
        return CT_ERROR;
    }
    *pid = child_pid;
    printf("[ctbackup]%s execute success and exit with: %d\n", "lock instance", WEXITSTATUS((unsigned int)status));
    return CT_SUCCESS;
}

status_t ctback_lock_instance_for_backup_retry(char *path, char *params[], text_t *mysql_passwd, pid_t *pid)
{
    uint32 retry_num = 0;
    while (retry_num < MYSQL_LOCK_INSTANCE_RETRY_NUM) {
        if (ctback_lock_instance_for_backup(path, params, mysql_passwd, pid) == CT_SUCCESS) {
            return CT_SUCCESS;
        }
        printf("[ctbackup]lock instance for backup retry failed, retry num %u\n", retry_num + 1);
        retry_num++;
    }
    return CT_ERROR;
}

status_t ctback_lock_mysql_for_backup(ctbak_param_t *ctbak_param)
{
    if (g_ctbak_lock_instance_pid != CT_INVALID_INT32) {
        printf("[ctbackup]lock instance process already executed, do not need execute repeatedly.\n");
        return CT_SUCCESS;
    }
    char shell_path[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    const char *shell_name = getenv("SHELL");
    if (shell_name == NULL) {
        shell_name = DEFAULT_SHELL;
    }
    CT_RETURN_IFERR(realpath_file(shell_name, shell_path, CT_FILE_NAME_BUFFER_SIZE));
    if (!cm_file_exist(shell_path)) {
        printf("[ctbackup]the shell file path %s does not exist\n", shell_path);
        return CT_ERROR;
    }
    if (ctbak_param->password.len == 0) {
        printf("[ctbackup]the param '--password' does not exist\n");
        return CT_ERROR;
    }
    text_t *mysql_passwd = &ctbak_param->password;
    char mysql_option_str[MYSQL_EXE_MAX_STR_LEN] = { 0 };
    CT_RETURN_IFERR(strcpy_s(mysql_option_str, MYSQL_EXE_MAX_STR_LEN, MYSQL_SHELL_EXE));
    
    if (ctbak_join_mysql_option_str(ctbak_param, mysql_option_str, MYSQL_EXE_MAX_STR_LEN) != CT_SUCCESS) {
        printf("[ctbackup]Failed join mysql options!\n");
        return CT_ERROR;
    }

    int child_pid = 0;
    char* params[CT_MAX_CMD_ARGS + 1];
    int param_index = 0;
    params[(param_index)++] = shell_path;
    params[(param_index)++] = "-c";
    params[(param_index)++] = mysql_option_str;
    params[(param_index)++] = NULL;

    if (ctback_lock_instance_for_backup_retry(shell_path, params, mysql_passwd, &child_pid) != CT_SUCCESS) {
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
