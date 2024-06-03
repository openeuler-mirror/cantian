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
 * ctbackup_common.c
 *
 *
 * IDENTIFICATION
 * src/utils/ctbackup/ctbackup_common.c
 *
 * -------------------------------------------------------------------------
 */
#include <sys/wait.h>
#include <sys/prctl.h>
#include <signal.h>
#include "ctbackup_module.h"
#include "cm_text.h"
#include "cm_date.h"
#include "cm_utils.h"
#include "cm_error.h"
#include "cm_config.h"
#include "kmc_init.h"
#include "ctbackup_common.h"

#define CANTAIN_BACKUP_TOOL_NAME "ctsql"
#define CTSQL_LOGIN_USER "SYS"
#define CTSQL_LOGIN_USER_FIRST "/"
#define CTSQL_LOGIN_CONN_FIRST "@"
#define CTSQL_LOGIN_CONN_SECOND ":"
#define CTSQL_SSL_LOGIN_AUTHENTICATION_OPTION "-q"
#define CTSQL_EXECUTE_SQL_STATEMENT_OPTION "-c"
#define CTSQL_CHECK_CONN_SHOW  "SHOW CHARSET"

#define CTSQL_INI_FILE_NAME "ctsql.ini"
#define CANTIAND_INI_FILE_MAME "cantiand.ini"
#define CTSQL_INI_SYS_PASSWORD "SYS_PASSWORD"
#define CTSQL_DEC_SYS_PASSWORD "ENABLE_DBSTOR"
#define CANTIAND_INI_LSNR_ADDR "LSNR_ADDR"
#define CANTIAND_INI_LSNR_PORT "LSNR_PORT"
#define CANTIAND_INI_MYSQL_METADATA_IN_CANTIAN "MYSQL_METADATA_IN_CANTIAN"

status_t ctbak_do_shell_background(text_t* command, int* child_pid, int exec_mode)
{
    char path[CT_FILE_NAME_BUFFER_SIZE] = {0};
    if (CM_IS_EMPTY(command)) {
        printf("[ctbackup]shell context is empty\n");
        return CT_ERROR;
    }
    int status;
    int param_index = 0;
    char* args[CT_MAX_CMD_ARGS + 1];
    pid_t child;
    const char* shell_name = getenv("SHELL");
    if (shell_name == NULL) {
        shell_name = DEFAULT_SHELL;
    }

    CT_RETURN_IFERR(realpath_file(shell_name, path, CT_FILE_NAME_BUFFER_SIZE));
    if (!cm_file_exist(path)) {
        printf("[ctbackup]the shell file path %s does not exist\n", path);
        return CT_ERROR;
    }
    args[(param_index)++] = path;
    args[(param_index)++] = "-c";
    args[(param_index)++] = command->str;
    args[(param_index)++] = NULL;

    child = fork();
    if (child == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        int ret = execve(path, args, environ);
        if (ret == -1) {
            printf("[ctbackup]exec %s failed, reason %d\n", command->str, errno);
            exit(CT_ERROR);
        }
        return CT_SUCCESS;
    } else if (child < 0) {
        printf("[ctbackup]fork child process failed\n");
        return CT_ERROR;
    }

    // wait for process
    sleep(1);
    int wait = waitpid(child, &status, exec_mode);
    if (wait == child && WIFEXITED((unsigned int)status) && WEXITSTATUS((unsigned int)status) != 0) {
        printf("[ctbackup]child process exec failed\n");
        return CT_ERROR;
    }
    *child_pid = child;
    return CT_SUCCESS;
}

status_t ctbak_system_call(char *path, char *params[], char* operation)
{
    int result;
    pid_t pid = fork();
    if (pid < 0) {
        printf("[ctbackup]failed to fork child process with result %d:%s\n", errno, strerror(errno));
        return CT_ERROR;
    } else if (pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        result = execv(path, params);
        if (result == -1) {
            printf("[ctbackup]system call failed with result %d:%s\n", errno, strerror(errno));
            exit(CT_ERROR);
        }
    }
    
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED((unsigned int)status) && WEXITSTATUS((unsigned int)status) == 0) {
        printf("[ctbackup]%s execute success and exit with: %d\n", operation, WEXITSTATUS((unsigned int)status));
        return CT_SUCCESS;
    }

    printf("[ctbackup]%s execute failed!\n", operation);
    return CT_ERROR;
}

void free_system_call_params(char *params[], int start_index, int end_index)
{
    for (int i = start_index; i <= end_index; i++) {
        CM_FREE_PTR(params[i]);
    }
}

void free_input_params(ctbak_param_t* ctbak_param)
{
    CM_FREE_PTR(ctbak_param->host.str);
    CM_FREE_PTR(ctbak_param->user.str);
    CM_FREE_PTR(ctbak_param->password.str);
    CM_FREE_PTR(ctbak_param->port.str);
    CM_FREE_PTR(ctbak_param->target_dir.str);
    CM_FREE_PTR(ctbak_param->defaults_file.str);
    CM_FREE_PTR(ctbak_param->socket.str);
    CM_FREE_PTR(ctbak_param->execute.str);
    CM_FREE_PTR(ctbak_param->data_dir.str);
    CM_FREE_PTR(ctbak_param->parallelism.str);
    CM_FREE_PTR(ctbak_param->databases_exclude.str);
    CM_FREE_PTR(ctbak_param->pitr_time.str);
    CM_FREE_PTR(ctbak_param->pitr_scn.str);
    CM_FREE_PTR(ctbak_param->compress_algo.str);
    CM_FREE_PTR(ctbak_param->buffer_size.str);
}

status_t ctbak_parse_single_arg(char *optarg_local, text_t *ctbak_param_option)
{
    if (optarg_local == NULL) {
        return CT_ERROR;
    }
    errno_t ret;
    size_t optarg_size = strlen(optarg_local) + 1;
    if (optarg_size == 0) {
        printf("[ctbackup]The requested memory size is 0\n");
        return CT_ERROR;
    }
    // free in free_input_params() method
    char *param = (char*)malloc(optarg_size);
    if (param == NULL) {
        printf("[ctbackup]failed to malloc memory for param\n");
        return CT_ERROR;
    }

    ret = memset_s(param, optarg_size, 0, optarg_size);
    if (ret != EOK) {
        CM_FREE_PTR(param);
        printf("[ctbackup]failed to set memory for param\n");
        return CT_ERROR;
    }
    ret = strcpy_s(param, optarg_size, optarg_local);
    if (ret != EOK) {
        CM_FREE_PTR(param);
        printf("[ctbackup]failed to copy string for param\n");
        return CT_ERROR;
    }
    cm_str2text_safe(param, (uint32)strlen(param), ctbak_param_option);
    return CT_SUCCESS;
}

status_t check_pitr_params(ctbak_param_t* ctbak_param)
{
    uint64 pitr_scn;
    if (ctbak_param->is_pitr_cancel == CT_TRUE) {
        if (ctbak_param->pitr_time.len > 0 || ctbak_param->pitr_scn.len > 0) {
            printf("[ctbackup]PITR-UNTIL-CANCEL and PITR-TIME/PITR-SCN can not be specified at the same time.\n");
            free_input_params(ctbak_param);
            return CT_ERROR;
        }
    }

    if (ctbak_param->pitr_time.str != NULL && ctbak_param->pitr_scn.str != NULL) {
        printf("[ctbackup]PITR-TIME and PITR-SCN can not be specified at the same time.\n");
        free_input_params(ctbak_param);
        return CT_ERROR;
    }

    if (ctbak_param->pitr_time.str != NULL && ctbak_param->pitr_time.len != 0) {
        date_t date;
        text_t date_fmt1 = { "YYYY-MM-DD HH24:MI:SS", 21 };
        if (cm_text2date(&(ctbak_param->pitr_time), &date_fmt1, &date) != CT_SUCCESS) {
            printf("PITR_TIME param value \'%s\' is invalid.\n", (&(ctbak_param->pitr_time))->str);
            free_input_params(ctbak_param);
            return CT_ERROR;
        }
    }
    
    if (ctbak_param->pitr_scn.str != NULL && ctbak_param->pitr_scn.len != 0) {
        char c = ctbak_param->pitr_scn.str[0];
        if (c == '-') {
            printf("[ctbackup]pitr_scn should be a positive number!\n");
            free_input_params(ctbak_param);
            return CT_ERROR;
        }
        if (cm_str2uint64(ctbak_param->pitr_scn.str, &pitr_scn) != CT_SUCCESS) {
            printf("[ctbackup]convert pitr_scn to uint64 failed!\n");
            free_input_params(ctbak_param);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t check_common_params(ctbak_param_t* ctbak_param)
{
    int32 parallelism_count;
    if (ctbak_param->target_dir.str == NULL || ctbak_param->target_dir.len == 0) {
        printf("[ctbackup]The --target-dir parameter cannot be NULL!\n");
        free_input_params(ctbak_param);
        return CT_ERROR;
    }
    if (ctbak_param->target_dir.len > MAX_TARGET_DIR_LENGTH) {
        printf("[ctbackup]The --target-dir parameter length is too long!\n");
        free_input_params(ctbak_param);
        return CT_ERROR;
    }

    if (ctbak_param->parallelism.str != NULL && ctbak_param->parallelism.len != 0) {
        if (cm_str2int(ctbak_param->parallelism.str, &parallelism_count) != CT_SUCCESS) {
            printf("[ctbackup]convert parallelism to int32 failed!\n");
            free_input_params(ctbak_param);
            return CT_ERROR;
        }

        if (parallelism_count > MAX_PARALLELISM_COUNT || parallelism_count <= 0) {
            printf("[ctbackup]The --parallel parameter value should be in [1, 16].\n");
            free_input_params(ctbak_param);
            return CT_ERROR;
        }
    }
    CT_RETURN_IFERR(check_pitr_params(ctbak_param));
    if (ctbak_param->repair_type.str != NULL && ctbak_param->repair_type.len != 0) {
        if (!cm_str_equal(ctbak_param->repair_type.str, "return_error") &&
            !cm_str_equal(ctbak_param->repair_type.str, "replace_checksum") &&
            !cm_str_equal(ctbak_param->repair_type.str, "discard_badblock")) {
            printf("[ctbackup]The --repair-type value is illegal.\n");
            free_input_params(ctbak_param);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t set_mysql_param_value(char *params[], text_t ctbak_param_option, char *param_prefix, int index)
{
    status_t status;
    status = set_mysql_single_param_value(&params[index], ctbak_param_option, param_prefix);
    if (status != CT_SUCCESS) {
        free_system_call_params(params, START_INDEX_FOR_PARSE_PARAM, index);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t set_mysql_single_param_value(char **param, text_t ctbak_param_option, char *param_prefix)
{
    uint64_t len;
    if (cm_str_equal(param_prefix, CTBAK_ARG_BACKUP) == CT_TRUE
        || cm_str_equal(param_prefix, CTBAK_ARG_COPYBACK) == CT_TRUE) {
        bool32 action_flag = cm_str_equal(param_prefix, CTBAK_ARG_BACKUP) ? CT_TRUE : CT_FALSE;
        len = action_flag ? strlen(CTBAK_ARG_BACKUP) + 1 : strlen(CTBAK_ARG_COPYBACK) + 1;
        *param = (char*)malloc(len);
        CTBAK_RETURN_ERROR_IF_NULL(param);
        if (action_flag) {
            MEMS_RETURN_IFERR(strcpy_s(*param, len, CTBAK_ARG_BACKUP));
        } else {
            MEMS_RETURN_IFERR(strcpy_s(*param, len, CTBAK_ARG_COPYBACK));
        }
        return CT_SUCCESS;
    }

    if (cm_str_equal(param_prefix, TARGET_DIR_PARAM_OPTION)) {
        len = strlen(TARGET_DIR_PARAM_OPTION) + ctbak_param_option.len + strlen(MYSQL_BACKUP_DIR) + 1;
        *param = (char*)malloc(len);
        CTBAK_RETURN_ERROR_IF_NULL(param);
        CTBAK_RETURN_ERROR_IF_NULL(ctbak_param_option.str);
        MEMS_RETURN_IFERR(strcpy_s(*param, strlen(TARGET_DIR_PARAM_OPTION) + 1, TARGET_DIR_PARAM_OPTION));
        MEMS_RETURN_IFERR(strcat_s(*param, len, ctbak_param_option.str));
        MEMS_RETURN_IFERR(strcat_s(*param, len, MYSQL_BACKUP_DIR));
        return CT_SUCCESS;
    }

    len = strlen(param_prefix) + ctbak_param_option.len + 1;
    *param = (char*)malloc(len);
    CTBAK_RETURN_ERROR_IF_NULL(param);
    MEMS_RETURN_IFERR(strcpy_s(*param, strlen(param_prefix) + 1, param_prefix));
    if (ctbak_param_option.len != 0) {
        MEMS_RETURN_IFERR(strcat_s(*param, len, ctbak_param_option.str));
    }
    return CT_SUCCESS;
}

status_t get_ctsql_config(const char *file_name, const char *conf_name, char *conf_value)
{
    char file_buf[CT_MAX_CONFIG_FILE_SIZE] = {0};
    uint32 text_size = sizeof(file_buf);
    if (cm_read_config_file(file_name, file_buf, &text_size, CT_FALSE, CT_FALSE) != CT_SUCCESS) {
        printf("[ctbackup]read config file failed!, the file_name is %s.\n", file_name);
        return CT_ERROR;
    }
    text_t text;
    text_t line;
    text_t name;
    text_t value;
    text.len = text_size;
    text.str = file_buf;
    int line_no = 0;
    
    while (cm_fetch_text(&text, '\n', '\0', &line)) {
        if (line.len == 0) {
            printf("[ctbackup]please confirm ctsql.ini is vaild!\n");
            return CT_ERROR;
        }
        line_no++;
        cm_trim_text(&line);
        if (line.len >= CT_MAX_CONFIG_LINE_SIZE) {
            printf("[ctbackup]the line size is too long!\n");
            return CT_ERROR;
        }
        if (line.len == 0 || *line.str == '#') { /* commentted line */
            continue;
        }

        cm_split_text(&line, '=', '\0', &name, &value);
        cm_trim_text(&value);
        cm_text_upper(&name);  // Case insensitive
        cm_trim_text(&name);
        if (cm_text_str_equal_ins(&name, conf_name)) {
            errno_t ret = strncpy_s(conf_value, CT_PARAM_BUFFER_SIZE, value.str, value.len);
            return ret;
        }
    }
    return CT_ERROR;
}

status_t ctbak_decrypt_password_kmc(SENSI_INFO char *cipherText, SENSI_INFO char *passwd)
{
    status_t ret = 0;
    ret = init_KMC();
    if (ret != CT_SUCCESS) {
        printf("DbsInitKMC failed, ret=(%u).", ret);
        return CT_ERROR;
    }
    char *plainText;
    int32_t plainTextLength = 0;
    int32_t cipherTextLength = (int32_t)strlen(cipherText) + 1;

    ret = KMC_decrypt(0, cipherText, cipherTextLength, &plainText, &plainTextLength);
    if (ret != CT_SUCCESS) {
        printf("[ctbackup]KMC_decrypt failed, ret=(%u).\n", ret);
        ret = KMC_finalize();
        return CT_ERROR;
    }
    errno_t err = strcpy_s(passwd, MAX_PASSWORD_LENGTH, plainText);
    if (err != EOK) {
        printf("[ctbackup]strcpy_s failed when decryptPassword.\n");
        return CT_ERROR;
    }
    memset_s(plainText, plainTextLength, 0, plainTextLength);
    ret = KMC_finalize();
    if (ret != 0) {
        printf("[ctbackup]finalize kmc failed.\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t ctback_read_output_from_pipe_cmd(ctbak_child_info_t child_info, char *cmd_out)
{
    errno_t ret;
    close(child_info.to_child);
    uint32 read_count = 0;
    uint32 read_once = CTSQL_CMD_OUT_BUFFER_SIZE;
    char *cmd_buf = cmd_out;
    while (read_count < CTSQL_CMD_OUT_BUFFER_SIZE) {
        int32 read_size = read(child_info.from_child, cmd_buf, read_once);
        if (read_size == -1) {
            printf("[ctbackup]read ctsql output failed\n");
            close(child_info.from_child);
            return CT_ERROR;
        }

        if (read_size == 0) {
            break;
        }

        read_count = read_count + read_size;
        cmd_buf = cmd_buf + read_size;
        read_once = read_once - read_size;
    }
    close(child_info.from_child);
    int32 wait = waitpid(child_info.child_pid, &ret, 0);
    if (wait == child_info.child_pid && WIFEXITED((unsigned int)ret) && WEXITSTATUS((unsigned int)ret) != 0) {
        printf("[ctbackup]child process exec failed, ret=%d\n", ret);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t ctbak_decrypt_password_custom(SENSI_INFO char *cipherText, SENSI_INFO char *cmd_out_passwd)
{
    error_t ret = 0;
    char cmd_str[MAX_SHELL_CMD_LENGTH] = {0};
    text_t decrypt_cmd;
    ret = snprintf_s(cmd_str, MAX_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH - 1, "%s%s%s",
                     DECRYPT_CMD_ECHO, cipherText, DECRYPT_CMD_BASE64);
    if (ret == -1) {
        printf("[ctbackup]failed to snprintf for decrypt cmd\n");
        return CT_ERROR;
    }

    cm_str2text(cmd_str, &decrypt_cmd);
    if (ctbak_do_shell_get_output(&decrypt_cmd, cmd_out_passwd, ctback_read_output_from_pipe_cmd) != CT_SUCCESS) {
        printf("ctbackup]failed to decrypt password.\n");
        return CT_ERROR;
    }
    // remove '\n' from read pipe
    if (cmd_out_passwd[strlen(cmd_out_passwd) - 1] == '\n') {
        cmd_out_passwd[strlen(cmd_out_passwd) - 1] = '\0';
    }
    return CT_SUCCESS;
}

status_t get_ctsql_passwd(char *ctsql_ini_file_name, char *cantiand_ini_file_name, SENSI_INFO char *plainText)
{
    char cipherText[MAX_PASSWORD_LENGTH] = {0};
    char enable_dbstor[MAX_BOOL_STR_LENGTH] = {0};
    status_t status;
    status = get_ctsql_config(ctsql_ini_file_name, CTSQL_INI_SYS_PASSWORD, cipherText);
    if (status != CT_SUCCESS) {
        printf("[ctbackup]get ctsql config failed!\n");
        return status;
    }
    status = get_ctsql_config(cantiand_ini_file_name, CTSQL_DEC_SYS_PASSWORD, enable_dbstor);
    if (status != CT_SUCCESS) {
        printf("[ctbackup]get cantiand config failed!\n");
        return status;
    }
    bool32 is_dbstor = (strcmp(enable_dbstor, "TRUE") == 0) ? CT_TRUE : CT_FALSE;

    if (is_dbstor) {
        status = kmc_init_lib();
        if (status != CT_SUCCESS) {
            printf("[ctbackup]init kmc library failed!\n");
            return status;
        }
        status = ctbak_decrypt_password_kmc(cipherText, plainText);
        kmc_close_lib();
    } else {
        status = ctbak_decrypt_password_custom(cipherText, plainText);
    }
    if (status != CT_SUCCESS) {
        printf("[ctbackup]decrypt password failed!\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t get_cantiand_ini_file_name(char *cantiand_ini_file_path)
{
    const char *data_path = getenv("CTDB_DATA");
    if (data_path == NULL) {
        printf("[ctbackup]get data dir error!\n");
        return CT_ERROR;
    }
    int32 iret_snprintf;
    iret_snprintf = snprintf_s(cantiand_ini_file_path, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s/cfg/%s",
                               data_path, CANTIAND_INI_FILE_MAME);
    PRTS_RETURN_IFERR(iret_snprintf);
    return CT_SUCCESS;
}

status_t get_ctsql_ini_file_name(char *ctsql_ini_file_name)
{
    const char *data_path = getenv("CTDB_DATA");
    if (data_path == NULL) {
        printf("[ctbackup]get data dir error!\n");
        return CT_ERROR;
    }
    int32 iret_snprintf;
    iret_snprintf = snprintf_s(ctsql_ini_file_name, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s/cfg/%s",
                               data_path, CTSQL_INI_FILE_NAME);
    PRTS_RETURN_IFERR(iret_snprintf);
    return CT_SUCCESS;
}

status_t get_real_addr(char *addr)
{
    char addr_tmp[CT_PARAM_BUFFER_SIZE] = {0};
    error_t ret;
    ret = strcpy_sp(addr_tmp, CT_PARAM_BUFFER_SIZE, addr);
    if (ret != EOK) {
        printf("[ctbackup]strcpy_sp for addr tmp failed!\n");
        return CT_ERROR;
    }
    uint32_t total_len = strlen(addr);
    uint32_t split_index = 0;
    for (uint32_t i = 0; i < total_len; i++) {
        if (addr_tmp[i] == ',') {
            split_index = i;
            break;
        }
    }
    // 只有一个ip
    if (split_index == 0) {
        return CT_SUCCESS;
    }
    // lsrn addr format: 127.0.0.1,x.x.x.x,y.y.y.y
    for (uint32_t i = split_index + 1; i < total_len; i++) {
        if (addr_tmp[i] == ',') {
            addr_tmp[i] = '\0';
            break;
        }
    }
    ret = strcpy_sp(addr, CT_PARAM_BUFFER_SIZE, addr_tmp + split_index + 1);
    if (ret != EOK) {
        printf("[ctbackup]strcpy_sp for addr failed!\n");
        return CT_ERROR;
    }
    addr[total_len - split_index] = '\0';
    return CT_SUCCESS;
}

status_t get_ctsql_lsrn_addr_and_port(const char *cantiand_ini_file_name, char *addr, char *port)
{
    if (get_ctsql_config(cantiand_ini_file_name, CANTIAND_INI_LSNR_ADDR, addr) != CT_SUCCESS) {
        printf("[ctbackup]get ctsql lsrn addr failed!\n");
        return CT_ERROR;
    }
    // lsrn addr format: 127.0.0.1,x.x.x.x
    if (get_real_addr(addr) != CT_SUCCESS) {
        printf("[ctbackup]get ctsql lsrn real addr failed!\n");
        return CT_ERROR;
    }
    if (get_ctsql_config(cantiand_ini_file_name, CANTIAND_INI_LSNR_PORT, port) != CT_SUCCESS) {
        printf("[ctbackup]get ctsql lsrn port failed!\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t get_ctsql_login_for_passwd_addr_port(char **ctsql_login_info, ctbak_ctsql_exec_mode_t ctsql_exec_mode)
{
    char ctsql_ini_file_name[CT_MAX_FILE_PATH_LENGH] = {0};
    char cantiand_ini_file_name[CT_MAX_FILE_PATH_LENGH] = {0};
    if (get_ctsql_ini_file_name(ctsql_ini_file_name) != CT_SUCCESS ||
        get_cantiand_ini_file_name(cantiand_ini_file_name) != CT_SUCCESS) {
        return CT_ERROR;
    }
    char passwd[MAX_PASSWORD_LENGTH] = {0};
    char addr[CT_PARAM_BUFFER_SIZE] = {0};
    char port[CT_PARAM_BUFFER_SIZE] = {0};
    if (ctsql_exec_mode == CTBAK_CTSQL_EXECV_MODE &&
        get_ctsql_passwd(ctsql_ini_file_name, cantiand_ini_file_name, passwd) != CT_SUCCESS) {
        printf("[ctbackup]get ctsql password failed!\n");
        return CT_ERROR;
    }
    if (get_ctsql_lsrn_addr_and_port(cantiand_ini_file_name, addr, port) != CT_SUCCESS) {
        return CT_ERROR;
    }
    uint64_t len = 0;
    if (ctsql_exec_mode == CTBAK_CTSQL_EXECV_MODE) {
        len = strlen(CTSQL_LOGIN_USER) + strlen(CTSQL_LOGIN_USER_FIRST) + strlen(passwd) + strlen(CTSQL_LOGIN_CONN_FIRST) +
              strlen(addr) + strlen(CTSQL_LOGIN_CONN_SECOND) + strlen(port) + 1;
    } else {
        len = strlen(CTSQL_LOGIN_USER) + strlen(CTSQL_LOGIN_CONN_FIRST) + strlen(addr) + strlen(CTSQL_LOGIN_CONN_SECOND) +
              strlen(port) + 1;
    }
    *ctsql_login_info = (char *)malloc(len);
    if (*ctsql_login_info == NULL) {
        printf("[ctbackup]failed to malloc for ctsql_login_info!\n");
        memset_s(passwd, MAX_PASSWORD_LENGTH, 0, MAX_PASSWORD_LENGTH);
        return CT_ERROR;
    }
    errno_t ret;
    if (ctsql_exec_mode == CTBAK_CTSQL_EXECV_MODE) {
        ret = snprintf_s(*ctsql_login_info, len, len - 1, "%s%s%s%s%s%s%s", CTSQL_LOGIN_USER, CTSQL_LOGIN_USER_FIRST,
                         passwd, CTSQL_LOGIN_CONN_FIRST, addr, CTSQL_LOGIN_CONN_SECOND, port);
    } else {
        ret = snprintf_s(*ctsql_login_info, len, len - 1, "%s%s%s%s%s", CTSQL_LOGIN_USER, CTSQL_LOGIN_CONN_FIRST, addr,
                         CTSQL_LOGIN_CONN_SECOND, port);
    }
    
    if (ret == -1) {
        printf("[ctbackup]snprintf_s for ctsql_login_info failed!\n");
        CM_FREE_PTR(*ctsql_login_info);
        memset_s(passwd, MAX_PASSWORD_LENGTH, 0, MAX_PASSWORD_LENGTH);
        return CT_ERROR;
    }
    memset_s(passwd, MAX_PASSWORD_LENGTH, 0, MAX_PASSWORD_LENGTH);
    return CT_SUCCESS;
}

status_t fill_params_for_ctsql_login(char *ct_params[], int* param_index, ctbak_ctsql_exec_mode_t ctsql_exec_mode)
{
    char *ctsql_login_info = NULL;
    char *ctsql_binary_path = NULL;
    if (get_ctsql_login_for_passwd_addr_port(&ctsql_login_info, ctsql_exec_mode) != CT_SUCCESS) {
        printf("[ctbackup]get ctsql_login_info failed!\n");
        return CT_ERROR;
    }
    // The first parameter should be the application name itself
    if (ctsql_exec_mode == CTBAK_CTSQL_EXECV_MODE) {
        ct_params[(*param_index)++] = CANTAIN_BACKUP_TOOL_NAME;
    } else if (get_ctsql_binary_path(&ctsql_binary_path) != CT_SUCCESS) {
        printf("[ctbackup]get ctsql bin path failed!\n");
        return CT_ERROR;
    } else {
        ct_params[(*param_index)++] = ctsql_binary_path;
    }
    ct_params[(*param_index)++] = ctsql_login_info;
    ct_params[(*param_index)++] = CTSQL_SSL_LOGIN_AUTHENTICATION_OPTION;
    ct_params[(*param_index)++] = CTSQL_EXECUTE_SQL_STATEMENT_OPTION;
    return CT_SUCCESS;
}

status_t start_cantiand_server(void)
{
    int child_pid;
    text_t start_server_cmd;
    cm_str2text(START_CANTIAND_SERVER_CMD, &start_server_cmd);
    status_t result = ctbak_do_shell_background(&start_server_cmd, &child_pid, 0);
    if (result != CT_SUCCESS) {
        printf("[ctbackup]start cantiand server failed!\n");
        return CT_ERROR;
    }
    printf("[ctbackup]start cantiand server success!\n");
    return CT_SUCCESS;
}

status_t check_cantiand_status(void)
{
    int child_pid;
    text_t check_cantiand_status_cmd;
    cm_str2text(CHECK_CANTAIND_STATUS_CMD, &check_cantiand_status_cmd);
    status_t result = ctbak_do_shell_background(&check_cantiand_status_cmd, &child_pid, 0);
    if (result != CT_SUCCESS) {
        printf("[ctbackup]cantiand is running, cannot execute restore/recovery/force_archive!\n");
        return CT_ERROR;
    }
    printf("[ctbackup]check cantiand status finished!\n");
    return CT_SUCCESS;
}

status_t stop_cantiand_server(void)
{
    int child_pid;
    text_t stop_cantiand_cmd;
    cm_str2text(STOP_CANTIAND_SERVER_CMD, &stop_cantiand_cmd);
    status_t result = ctbak_do_shell_background(&stop_cantiand_cmd, &child_pid, 0);
    if (result != CT_SUCCESS) {
        printf("[ctbackup]stop cantiand server failed!\n");
        return CT_ERROR;
    }
    printf("[ctbackup]stop cantiand server finished!\n");
    return CT_SUCCESS;
}

status_t get_ctsql_binary_path(char** ctsql_binary_path)
{
    errno_t ret;
    uint64_t len;
    char* ct_install_path = getenv("CTDB_HOME");
    if (ct_install_path == NULL) {
        len = strlen(DEFAULT_CTSQL_PATH) + 1;
    } else {
        if (strlen(ct_install_path) > CT_MAX_PATH_BUFFER_SIZE) {
            printf("[ctbackup]the ct_install_path is too long!\n");
            return CT_ERROR;
        }
        len = strlen(ct_install_path) + strlen(DEFAULT_CTSQL_PATH) + 1;
    }
    *ctsql_binary_path = (char *)malloc(len);
    if (*ctsql_binary_path == NULL) {
        printf("[ctbackup]failed to malloc for ctsql_binary_path!\n");
        return CT_ERROR;
    }
    ret = snprintf_s(*ctsql_binary_path, len, len - 1, "%s%s",
                     ct_install_path == NULL ? "" : ct_install_path, DEFAULT_CTSQL_PATH);
    if (ret == -1) {
        CM_FREE_PTR(*ctsql_binary_path);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t check_input_params(char* params)
{
    if (params[0] == '-' && params[1] == '-') {
        return CT_SUCCESS;
    }
    if (params[0] == '-' && (params[2] == '=' || strlen(params) == 2)) {
        return CT_SUCCESS;
    }
    printf("[ctbackup]param %s is illegal,please confirm!\n", params);
    return CT_ERROR;
}

status_t ctbak_check_data_dir(const char *path)
{
    struct dirent *dirp = NULL;
    DIR *dir = opendir(path);
    if (dir == NULL) {
        printf("[ctbackup]param datadir %s open failed, error code %d\n", path, errno);
        return CT_ERROR;
    }
    while ((dirp = readdir(dir)) != NULL) {
        if (strcmp(dirp->d_name, ".") && strcmp(dirp->d_name, "..")) {
            printf("[ctbackup]param datadir %s is not empty\n", path);
            (void)closedir(dir);
            return CT_ERROR;
        }
    }
    (void)closedir(dir);
    return CT_SUCCESS;
}

status_t ctbak_change_work_dir(const char *path)
{
    if (chdir(path) == -1) {
        printf("[ctbackup]change current work directory to %s failed, error code %d.\n", path, errno);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t ctbak_clear_data_dir(const char *sub_path, const char *src_path)
{
    if (sub_path == NULL || src_path == NULL) {
        return CT_ERROR;
    }
    struct dirent *dirp = NULL;
    char *cwdir = getcwd(NULL, 0);
    if (cwdir == NULL) {
        printf("[ctbackup]get current work directory failed, error code %d.\n", errno);
        return CT_ERROR;
    }
    DIR *dir = opendir(sub_path);
    if (dir == NULL) {
        printf("[ctbackup]param datadir %s open failed, error code %d\n", sub_path, errno);
        free(cwdir);
        return CT_ERROR;
    }
    if (ctbak_change_work_dir(sub_path) == -1) {
        free(cwdir);
        (void)closedir(dir);
        return CT_ERROR;
    }
    while ((dirp = readdir(dir)) != NULL) {
        if ((strcmp(dirp->d_name, ".") == 0) || (strcmp(dirp->d_name, "..") == 0)) {
            continue;
        }
        if (cm_dir_exist(dirp->d_name)) {
            if (ctbak_clear_data_dir(dirp->d_name, src_path) == CT_SUCCESS) {
                continue;
            }
            (void)closedir(dir);
            free(cwdir);
            return CT_ERROR;
        }
        if (remove(dirp->d_name) != 0) {
            printf("[ctbackup]remove file %s failed, error code %d.\n", dirp->d_name, errno);
            (void)closedir(dir);
            free(cwdir);
            return CT_ERROR;
        }
    }
    (void)closedir(dir);
    if (ctbak_change_work_dir(cwdir) == -1) {
        free(cwdir);
        return CT_ERROR;
    }
    free(cwdir);
    if (strcmp(sub_path, src_path) != 0 && remove(sub_path) != 0) {
        printf("[ctbackup]remove dir %s failed, error code %d.\n", sub_path, errno);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t ctbak_get_execve_args(text_t *command, char **args, char *path)
{
    uint32 param_index = 0;
    const char *shell_name = getenv("SHELL");
    if (shell_name == NULL) {
        shell_name = DEFAULT_SHELL;
    }
    CT_RETURN_IFERR(realpath_file(shell_name, path, CT_FILE_NAME_BUFFER_SIZE));
    if (!cm_file_exist(path)) {
        printf("[ctbackup]the shell file path %s does not exist\n", path);
        return CT_ERROR;
    }
    args[(param_index)++] = path;
    args[(param_index)++] = "-c";
    args[(param_index)++] = command->str;
    args[(param_index)++] = NULL;
    return CT_SUCCESS;
}

status_t ctbak_get_ctsql_passwd_for_shell(char *passwd)
{
    errno_t ret;
    char ctsql_ini_file_name[CT_MAX_FILE_PATH_LENGH] = { 0 };
    char cantiand_ini_file_name[CT_MAX_FILE_PATH_LENGH] = { 0 };
    if (get_ctsql_ini_file_name(ctsql_ini_file_name) != CT_SUCCESS) {
        printf("[ctbackup]get ctsql ini file failed!\n");
        return CT_ERROR;
    }
    if (get_cantiand_ini_file_name(cantiand_ini_file_name) != CT_SUCCESS) {
        printf("[ctbackup]get cantiand ini file failed!\n");
        return CT_ERROR;
    }
    if (get_ctsql_passwd(ctsql_ini_file_name, cantiand_ini_file_name, passwd) != CT_SUCCESS) {
        printf("[ctbackup]get ctsql password failed!\n");
        return CT_ERROR;
    }
    ret = strcat_s(passwd, MAX_PASSWORD_LENGTH, "\n");
    if (ret != EOK) {
        memset_s(passwd, MAX_PASSWORD_LENGTH, 0, MAX_PASSWORD_LENGTH);
        printf("[ctbackup]write ctsql password failed!\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t ctback_read_output_from_pipe(ctbak_child_info_t child_info, char *cmd_out)
{
    errno_t ret;
    char passwd[MAX_PASSWORD_LENGTH] = { 0 };
    if (ctbak_get_ctsql_passwd_for_shell(passwd) != CT_SUCCESS) {
        memset_s(passwd, MAX_PASSWORD_LENGTH, 0, MAX_PASSWORD_LENGTH);
        return CT_ERROR;
    }
    int32 write_size = write(child_info.to_child, passwd, MAX_PASSWORD_LENGTH);
    memset_s(passwd, MAX_PASSWORD_LENGTH, 0, MAX_PASSWORD_LENGTH);
    if (write_size == -1) {
        printf("[ctbackup]write ctsql info failed\n");
        return CT_ERROR;
    }
    close(child_info.to_child);
    cm_sleep(100);
    uint32_t read_count = 0;
    uint32_t read_once = CTSQL_CMD_OUT_BUFFER_SIZE;
    char *buf_pos = cmd_out;
    while (read_count < CTSQL_CMD_OUT_BUFFER_SIZE) {
        int32 read_size = read(child_info.from_child, buf_pos, read_once);
        if (read_size == -1) {
            printf("[ctbackup]read ctsql output failed\n");
            close(child_info.from_child);
            return CT_ERROR;
        }
        if (read_size == 0) {
            break;
        }
        read_count = read_count + read_size;
        buf_pos = cmd_out + read_count;
        read_once = read_once - read_size;
    }
    close(child_info.from_child);
    int32 wait = waitpid(child_info.child_pid, &ret, 0);
    if (wait == child_info.child_pid && WIFEXITED((unsigned int)ret) && WEXITSTATUS((unsigned int)ret) != 0) {
        printf("[ctbackup]child process exec failed\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t ctbak_do_shell_get_output(text_t *command, char *cmd_out,
    status_t (*ctback_read_output_from_pipe_fun)(ctbak_child_info_t, char*))
{
    if (CM_IS_EMPTY(command)) {
        printf("[ctbackup]shell context is empty\n");
        return CT_ERROR;
    }
    errno_t status;
    ctbak_child_info_t child_info;
    char *args[CT_MAX_CMD_ARGS + 1];
    char path[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    int32 pipe_stdin[2], pipe_stdout[2];
    if (ctbak_get_execve_args(command, args, path) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (pipe(pipe_stdin) != EOK) {
        printf("[ctbackup]create stdin pipe failed!\n");
        return CT_ERROR;
    }
    if (pipe(pipe_stdout) != EOK) {
        printf("[ctbackup]create stdout pipe failed!\n");
        return CT_ERROR;
    }

    pid_t child_pid = fork();
    if (child_pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        close(pipe_stdin[CHILD_ID]);
        dup2(pipe_stdin[PARENT_ID], STD_IN_ID);
        close(pipe_stdout[PARENT_ID]);
        dup2(pipe_stdout[CHILD_ID], STD_OUT_ID);
        status = execve(path, args, environ);
        perror("execve");
        if (status != EOK) {
            printf("[ctbackup]failed to execute shell command %d:%s\n", errno, strerror(errno));
            exit(CT_ERROR);
        }
        return CT_SUCCESS;
    } else if (child_pid < 0) {
        printf("[ctbackup]failed to fork child process with result %d:%s\n", errno, strerror(errno));
        return CT_ERROR;
    }
    sleep(1);
    child_info.child_pid = child_pid;
    child_info.to_child = pipe_stdin[CHILD_ID];
    child_info.from_child = pipe_stdout[PARENT_ID];
    close(pipe_stdin[PARENT_ID]);
    close(pipe_stdout[CHILD_ID]);
    if (ctback_read_output_from_pipe_fun(child_info, cmd_out) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t fill_params_for_ctsql_cmd(char *ct_params[], char *ctsql_cmd[])
{
    int param_index = 0;
    if (fill_params_for_ctsql_login(ct_params, &param_index, CTBAK_CTSQL_SHELL_MODE) != CT_SUCCESS) {
        printf("[ctbackup]failed to fill params for ctsql login!\n");
        return CT_ERROR;
    }

    for (uint32 i = 0; i < CT_MAX_CMD_ARGS && ctsql_cmd[i] != NULL; i++) {
        ct_params[param_index++] = ctsql_cmd[i];
    }
    ct_params[param_index++] = NULL;
    return CT_SUCCESS;
}

status_t ctbak_get_metadata_mode_by_cfg(char *metadata_mode)
{
    char cantiand_ini_file_name[CT_MAX_FILE_PATH_LENGH] = {0};
    if (get_cantiand_ini_file_name(cantiand_ini_file_name) != CT_SUCCESS) {
        printf("[ctbackup]get cantiand ini file failed!\n");
        return CT_ERROR;
    }

    if (get_ctsql_config(cantiand_ini_file_name, CANTIAND_INI_MYSQL_METADATA_IN_CANTIAN, metadata_mode) != CT_SUCCESS) {
        printf("[ctbackup]get config metadata mode failed!\n");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t ctbackup_set_metadata_mode(ctbak_param_t *ctbak_param)
{
    char metadata_mode[CTSQL_CMD_OUT_BUFFER_SIZE] = { 0 };
    if (ctbak_get_metadata_mode_by_cfg(metadata_mode) != CT_SUCCESS) {
        printf("[ctbackup]get mysql_metadata_in_cantian param failed!\n");
        return CT_ERROR;
    }

    if (strcmp(metadata_mode, "TRUE") == 0) {
        ctbak_param->is_mysql_metadata_in_cantian = CT_TRUE;
    } else if (strcmp(metadata_mode, "FALSE") == 0) {
        ctbak_param->is_mysql_metadata_in_cantian = CT_FALSE;
    } else {
        printf("[ctbackup]invalid mysql_metadata_in_cantian param!\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t ctbak_check_dir_access(const char *path)
{
    if (cm_access_file(path, F_OK) != CT_SUCCESS) {
        printf("[ctbackup] the directory %s can not access!\n", path);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t ctbak_check_ctsql_online(uint32 retry_time)
{
    status_t status;
    char *ct_params[CTBACKUP_MAX_PARAMETER_CNT] = { 0 };
    int32_t param_index = 0;
    status = fill_params_for_ctsql_login(ct_params, &param_index, CTBAK_CTSQL_EXECV_MODE);
    if (status != CT_SUCCESS) {
        printf("[ctbackup]check_ctsql_online failed!\n");
        return CT_ERROR;
    }
    ct_params[param_index++] = CTSQL_CHECK_CONN_SHOW;
    // The last parameter must be NULL
    ct_params[param_index++] = NULL;
    char *ctsql_binary_path = NULL;
    if (get_ctsql_binary_path(&ctsql_binary_path) != CT_SUCCESS) {
        CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
        printf("[ctbackup]check_ctsql_online failed!\n");
        return CT_ERROR;
    }
    struct timeval start_work_time;
    gettimeofday(&start_work_time, NULL);
    struct timeval current_time;
    uint32_t interval_time = 0;
    status = CT_ERROR;
    while (interval_time <= retry_time) {
        if (ctbak_system_call(ctsql_binary_path, ct_params, "check_ctsql_online") == CT_SUCCESS) {
            status = CT_SUCCESS;
            break;
        }
        cm_sleep(CTSQL_CHECK_CONN_SLEEP_TIME_MS);
        gettimeofday(&current_time, NULL);
        interval_time = current_time.tv_sec - start_work_time.tv_sec;
    }
    // free space of heap
    CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
    CM_FREE_PTR(ctsql_binary_path);
    if (status != CT_SUCCESS) {
        printf("[ctbackup]check_ctsql_online failed! try to connect ctsql for %u secs.\n", interval_time);
        return CT_ERROR;
    }
    printf("[ctbackup]check_ctsql_online success\n");
    return CT_SUCCESS;
}

status_t check_ctsql_online(void)
{
    int child_pid;
    text_t try_conn_ctsql_cmd;
    cm_str2text(TRY_CONN_CTSQL_CMD, &try_conn_ctsql_cmd);
    status_t result = ctbak_do_shell_background(&try_conn_ctsql_cmd, &child_pid, 0);
    if (result != CT_SUCCESS) {
        printf("[ctbackup]try conn ctsql failed!\n");
        return CT_ERROR;
    }
    printf("[ctbackup]ctsql now is ready to be connected!\n");
    return CT_SUCCESS;
}