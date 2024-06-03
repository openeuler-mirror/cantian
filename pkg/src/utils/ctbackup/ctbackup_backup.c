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
 * ctbackup_backup.c
 *
 *
 * IDENTIFICATION
 * src/utils/ctbackup/ctbackup_backup.c
 *
 * -------------------------------------------------------------------------
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <signal.h>
#include "ctbackup_module.h"
#include "ctbackup_info.h"
#include "ctbackup.h"
#include "ctbackup_common.h"
#include "unistd.h"
#include "cm_file.h"
#include "ctbackup_mysql_operator.h"
#include "ctbackup_backup.h"

#define CTBAK_BACKUP_RETRY_MAX_NUM 2
#define CTBAK_BACKUP_CECHK_ONLINE_TIME 5

const struct option ctbak_backup_options[] = {
    {CTBAK_LONG_OPTION_BACKUP, no_argument, NULL, CTBAK_PARSE_OPTION_COMMON},
    {CTBAK_LONG_OPTION_USER, required_argument, NULL, CTBAK_SHORT_OPTION_USER},
    {CTBAK_LONG_OPTION_PASSWORD, required_argument, NULL, CTBAK_SHORT_OPTION_PASSWORD},
    {CTBAK_LONG_OPTION_HOST, required_argument, NULL, CTBAK_SHORT_OPTION_HOST},
    {CTBAK_LONG_OPTION_PORT, required_argument, NULL, CTBAK_SHORT_OPTION_PORT},
    {CTBAK_LONG_OPTION_TARGET_DIR, required_argument, NULL, CTBAK_SHORT_OPTION_TARGET_DIR},
    {CTBAK_LONG_OPTION_DEFAULTS_FILE, required_argument, NULL, CTBAK_SHORT_OPTION_DEFAULTS_FILE},
    {CTBAK_LONG_OPTION_SOCKET, required_argument, NULL, CTBAK_SHORT_OPTION_SOCKET},
    {CTBAK_LONG_OPTION_DATA_DIR, required_argument, NULL, CTBAK_SHORT_OPTION_DATA_DIR},
    {CTBAK_LONG_OPTION_INCREMENTAL, no_argument, NULL, CTBAK_SHORT_OPTION_INCREMENTAL},
    {CTBAK_LONG_OPTION_INCREMENTAL_CUMULATIVE, no_argument, NULL, CTBAK_SHORT_OPTION_INCREMENTAL_CUMULATIVE},
    {CTBAK_LONG_OPTION_DATABASESEXCLUDE, required_argument, NULL, CTBAK_SHORT_OPTION_DATABASES_EXCLUDE},
    {CTBAK_LONG_OPTION_PARALLEL, required_argument, NULL, CTBAK_SHORT_OPTION_PARALLEL},
    {CTBAK_LONG_OPTION_COMPRESS, required_argument, NULL, CTBAK_SHORT_OPTION_COMPRESS},
    {CTBAK_LONG_OPTION_BUFFER, required_argument, NULL, CTBAK_SHORT_OPTION_BUFFER},
    {CTBAK_LONG_OPTION_SKIP_BADBLOCK, no_argument, NULL, CTBAK_SHORT_OPTION_SKIP_BADBLOCK},
    {0, 0, 0, 0}
};

#define CTSQL_CONNECT_CLOSED_32 "tcp connection is closed, reason: 32"

status_t convert_database_string_to_cantian(char *database, char *ct_database)
{
    char* ptr = NULL;
    char mid_database[MAX_DATABASE_LENGTH] = {0};
    char *split = strtok_s(database, " ", &ptr);
    if (split == NULL) {
        return CT_ERROR;
    }
    while (split) {
        if (strlen(split) >= MAX_DATABASE_LENGTH) {
            return CT_ERROR;
        }
        MEMS_RETURN_IFERR(strcat_s(mid_database, MAX_DATABASE_LENGTH, split));
        MEMS_RETURN_IFERR(strcat_s(mid_database, MAX_DATABASE_LENGTH, CTSQL_EXCLUDE_SUFFIX));
        MEMS_RETURN_IFERR(strcat_s(mid_database, MAX_DATABASE_LENGTH, ","));
        split = strtok_s(NULL, " ", &ptr);
    }
    MEMS_RETURN_IFERR(memcpy_s(ct_database, MAX_DATABASE_LENGTH, mid_database, strlen(mid_database) - 1));
    return CT_SUCCESS;
}

status_t generate_cantian_backup_dir(char *target_dir, char *ct_backup_dir)
{
    int32 file_fd;
    errno_t ret;
    ret = snprintf_s(ct_backup_dir, CANTIAN_BACKUP_FILE_LENGTH, CANTIAN_BACKUP_FILE_LENGTH - 1,
                     "%s%s", target_dir, CANTIAN_BACKUP_DIR);
    PRTS_RETURN_IFERR(ret);
    if (cm_access_file(ct_backup_dir, F_OK) != CT_SUCCESS) {
        if (cm_create_dir(ct_backup_dir) != CT_SUCCESS) {
            printf("[ctbackup]Failed to create the directory for storing cantian bakcup files, ret is :%d\n", errno);
            return CT_ERROR;
        }
    }
    if (cm_open_file(ct_backup_dir, O_RDONLY, &file_fd) != CT_SUCCESS) {
        printf("[ctbackup]Failed to open the cantian backup files directory. ret is :%d\n", errno);
        return CT_ERROR;
    }
    if (cm_chmod_file(S_IRWXU | S_IRWXG | S_IRWXO, file_fd) != CT_SUCCESS) {
        printf("[ctbackup]Failed to modify the permission on the cantian backup files directory. ret is :%d\n", errno);
        cm_close_file(file_fd);
        return CT_ERROR;
    }
    cm_close_file(file_fd);
    return CT_SUCCESS;
}

status_t fill_params_for_mysql_backup(ctbak_param_t* ctbak_param, char *params[], int *index)
{
    // The first parameter should be the application name itself
    params[0] = MYSQL_BACKUP_TOOL_NAME;
    // If the parameter --defaults-file is not null, it must be the first of the valid parameters
    if (ctbak_param->defaults_file.str != NULL) {
        CT_RETURN_IFERR(set_mysql_param_value(params, ctbak_param->defaults_file,
                                              DEFAULTS_FILE_PARAM_OPTION, (*index)++));
    }
    // The parameter is the action "--backup"
    text_t temp = {NULL, 0};
    CT_RETURN_IFERR(set_mysql_param_value(params, temp, CTBAK_ARG_BACKUP, (*index)++));

    if (ctbak_param->host.str != NULL) {
        CT_RETURN_IFERR(set_mysql_param_value(params, ctbak_param->host, HOST_PARAM_OPTION, (*index)++));
    }
 
    if (ctbak_param->user.str != NULL) {
        CT_RETURN_IFERR(set_mysql_param_value(params, ctbak_param->user, USER_PARAM_OPTION, (*index)++));
    }
 
    if (ctbak_param->password.str != NULL) {
        CT_RETURN_IFERR(set_mysql_param_value(params, ctbak_param->password, PWD_PARAM_OPTION, (*index)++));
    }
 
    if (ctbak_param->port.str != NULL) {
        CT_RETURN_IFERR(set_mysql_param_value(params, ctbak_param->port, PORT_PARAM_OPTION, (*index)++));
    }

    if (ctbak_param->socket.str != NULL) {
        CT_RETURN_IFERR(set_mysql_param_value(params, ctbak_param->socket, SOCKET_PARAM_OPTION, (*index)++));
    }
   
    if (ctbak_param->data_dir.str != NULL) {
        CT_RETURN_IFERR(ctbak_check_dir_access((const char *)ctbak_param->data_dir.str));
        CT_RETURN_IFERR(set_mysql_param_value(params, ctbak_param->data_dir, DATA_DIR_PARAM_OPRION, (*index)++));
    }

    if (ctbak_param->parallelism.str != NULL) {
        CT_RETURN_IFERR(set_mysql_param_value(params, ctbak_param->parallelism, PARALLEL_PARAM_OPTION, (*index)++));
    }

    if (ctbak_param->databases_exclude.str != NULL) {
        CT_RETURN_IFERR(set_mysql_param_value(params, ctbak_param->databases_exclude,
                                              DATABASESEXCLUDE_PARAM_OPTION, (*index)++));
    }

    if (ctbak_param->compress_algo.str != NULL) {
        CT_RETURN_IFERR(set_mysql_param_value(params, ctbak_param->compress_algo, COMPRESS_ALGO_OPTION, (*index)++));
    }

    CT_RETURN_IFERR(ctbak_check_dir_access((const char *)ctbak_param->target_dir.str));
    CT_RETURN_IFERR(set_mysql_param_value(params, ctbak_param->target_dir, TARGET_DIR_PARAM_OPTION, (*index)++));
    CT_RETURN_IFERR(set_mysql_param_value(params, temp, SKIP_LOCK_DDL, (*index)++));
    // The last parameter must be NULL
    params[*index] = NULL;
    return CT_SUCCESS;
}

status_t get_statement_for_cantian(ctbak_param_t* ctbak_param, uint64_t len, char *statement,
    char *databases, char *ct_backup_dir)
{
    errno_t ret;
    if (ctbak_param->is_incremental == CT_TRUE) {
        if (ctbak_param->is_incremental_cumulative == CT_TRUE) {
            ret = snprintf_s(statement, len, len - 1, "%s%s%s", CTSQL_INCREMENT_CUMULATIVE_BACKUP_STATEMENT_PREFIX,
                             ct_backup_dir, CTSQL_STATEMENT_QUOTE);
        } else {
            ret = snprintf_s(statement, len, len - 1, "%s%s%s", CTSQL_INCREMENT_BACKUP_STATEMENT_PREFIX,
                             ct_backup_dir, CTSQL_STATEMENT_QUOTE);
        }
    } else {
        ret = snprintf_s(statement, len, len - 1, "%s%s%s", CTSQL_FULL_BACKUP_STATEMENT_PREFIX,
                         ct_backup_dir, CTSQL_STATEMENT_QUOTE);
    }
    FREE_AND_RETURN_ERROR_IF_SNPRINTF_FAILED(ret, statement);
    if (ctbak_param->compress_algo.str != NULL) {
        ret = snprintf_s(statement, len, len - 1, "%s%s%s%s", statement, CTSQL_COMPRESS_OPTION_PREFIX,
                         ctbak_param->compress_algo.str, CTSQL_COMPRESS_OPTION_SUFFIX);
        FREE_AND_RETURN_ERROR_IF_SNPRINTF_FAILED(ret, statement);
    }
    if (ctbak_param->parallelism.str != NULL) {
        ret = snprintf_s(statement, len, len - 1, "%s%s%s", statement,
                            CTSQL_PARALLELISM_OPTION, ctbak_param->parallelism.str);
        FREE_AND_RETURN_ERROR_IF_SNPRINTF_FAILED(ret, statement);
    }
    if (ctbak_param->databases_exclude.str != NULL) {
        ret = snprintf_s(statement, len, len - 1, "%s%s%s", statement, CTSQL_EXCLUDE_OPTION, databases);
        FREE_AND_RETURN_ERROR_IF_SNPRINTF_FAILED(ret, statement);
    }
    if (ctbak_param->buffer_size.str != NULL) {
        ret = snprintf_s(statement, len, len - 1, "%s%s%s", statement,
                         CTSQL_BUFFER_OPTION, ctbak_param->buffer_size.str);
        FREE_AND_RETURN_ERROR_IF_SNPRINTF_FAILED(ret, statement);
    }
    if (ctbak_param->skip_badblock == CT_TRUE) {
        ret = snprintf_s(statement, len, len - 1, "%s%s", statement, CTSQL_SKIP_BADBLOCK);
        FREE_AND_RETURN_ERROR_IF_SNPRINTF_FAILED(ret, statement);
    }
    ret = snprintf_s(statement, len, len - 1, "%s%s", statement, CTSQL_STATEMENT_END_CHARACTER);
    FREE_AND_RETURN_ERROR_IF_SNPRINTF_FAILED(ret, statement);
    return CT_SUCCESS;
}


status_t fill_params_for_cantian_backup(ctbak_param_t* ctbak_param, char *ct_params[])
{
    int param_index = 0;
    uint64_t len;
    char databases[MAX_DATABASE_LENGTH] = {0};
    if (fill_params_for_ctsql_login(ct_params, &param_index, CTBAK_CTSQL_EXECV_MODE) != CT_SUCCESS) {
        printf("[ctbackup]failed to fill params for ctsql login!\n");
        return CT_ERROR;
    }
    char ct_backup_dir[CANTIAN_BACKUP_FILE_LENGTH] = {0};
    memset_s(ct_backup_dir, CANTIAN_BACKUP_FILE_LENGTH, 0, CANTIAN_BACKUP_FILE_LENGTH);
    if (generate_cantian_backup_dir(ctbak_param->target_dir.str, (char *)ct_backup_dir) != CT_SUCCESS) {
        CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
        printf("[ctbackup]generate_cantian_backup_dir failed!\n");
        return CT_ERROR;
    }
    // must use heap space, because the parameter will be passed to the system call method.
    // we fork a child process to execute the system call method, the space on the stack pointed to
    // by the parent process may be released.
    len = strlen(CTSQL_INCREMENT_BACKUP_STATEMENT_PREFIX);
    len = (ctbak_param->is_incremental == CT_TRUE && ctbak_param->is_incremental_cumulative == CT_TRUE) ?
              strlen(CTSQL_INCREMENT_CUMULATIVE_BACKUP_STATEMENT_PREFIX) : len;
    len = len + strlen(ct_backup_dir) + strlen(CTSQL_STATEMENT_QUOTE) + strlen(CTSQL_STATEMENT_END_CHARACTER) + 1;
    len += ctbak_param->parallelism.str != NULL ? strlen(CTSQL_PARALLELISM_OPTION) + ctbak_param->parallelism.len : 0;
    len += ctbak_param->compress_algo.str != NULL ? strlen(CTSQL_COMPRESS_OPTION_PREFIX) +
                                        ctbak_param->compress_algo.len + strlen(CTSQL_COMPRESS_OPTION_SUFFIX) : 0;
    len += ctbak_param->buffer_size.str != NULL ? strlen(CTSQL_BUFFER_OPTION) + ctbak_param->buffer_size.len : 0;
    len += ctbak_param->skip_badblock == CT_TRUE ? strlen(CTSQL_SKIP_BADBLOCK) : 0;
    if (ctbak_param->databases_exclude.str != NULL) {
        if (convert_database_string_to_cantian(ctbak_param->databases_exclude.str,
            (char *)databases) != CT_SUCCESS) {
            printf("[ctbackup]database convert to cantian failed!\n");
            return CT_ERROR;
        }
        len += strlen(CTSQL_EXCLUDE_OPTION) + strlen(databases);
    }
    char *statement = (char *)malloc(len);
    if (statement == NULL) {
        CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
        printf("[ctbackup]failed to apply storage for cantian backup!\n");
        CTBAK_RETURN_ERROR_IF_NULL(statement);
    }
    if (get_statement_for_cantian(ctbak_param, len, statement, databases, ct_backup_dir) != CT_SUCCESS) {
        CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
        printf("[ctbackup]get statement for cantian failed!\n");
        return CT_ERROR;
    }
    ct_params[param_index++] = statement;
    ct_params[param_index++] = NULL;
    return CT_SUCCESS;
}

status_t ctbak_do_backup_mysql(ctbak_param_t* ctbak_param)
{
    int index = START_INDEX_FOR_PARSE_PARAM;
    char *params[CTBACKUP_MAX_PARAMETER_CNT] = {0};
    if (fill_params_for_mysql_backup(ctbak_param, params, &index) != CT_SUCCESS) {
        printf("[ctbackup]fill_params_for_mysql_backup failed!\n");
        return CT_ERROR;
    }
    status_t status = ctbak_system_call(XTRABACKUP_PATH, params, "mysql backup");
    free_system_call_params(params, START_INDEX_FOR_PARSE_PARAM, index);
    if (status != CT_SUCCESS) {
        printf("[ctbackup]mysql meta data backup failed!\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void ctbak_check_backup_output(char *output, bool32 *need_retry)
{   
    if (strstr(output, CTSQL_CONNECT_CLOSED_32) != NULL) {
        *need_retry = CT_TRUE;
    }
    return;
}
status_t ctbak_do_ctsql_backup(char *path, char *params[], bool32 *retry)
{
    errno_t status = 0;
    int32 pipe_stdout[2] = { 0 };
    if (pipe(pipe_stdout) != EOK) {
        printf("[ctbackup]create stdout pipe failed!\n");
        return CT_ERROR;
    }

    pid_t child_pid = fork();
    if (child_pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        close(pipe_stdout[PARENT_ID]);
        dup2(pipe_stdout[CHILD_ID], STD_OUT_ID);
        status = execv(path, params);
        perror("execve");
        if (status != EOK) {
            printf("[ctbackup]failed to execute shell command %d:%s\n", errno, strerror(errno));
            exit(CT_ERROR);
        }
    } else if (child_pid < 0) {
        printf("[ctbackup]failed to fork child process with result %d:%s\n", errno, strerror(errno));
        return CT_ERROR;
    }
    close(pipe_stdout[CHILD_ID]);
    char output[MAX_STATEMENT_LENGTH];
    bool32 need_retry = CT_FALSE;
    FILE *fp = fdopen(pipe_stdout[PARENT_ID], "r");
    while(fgets(output, MAX_STATEMENT_LENGTH, fp) != NULL) {
        // output ctsql backup result and check the error info
        printf("%s", output);
        ctbak_check_backup_output(output, &need_retry);
    }
    pclose(fp);
    close(pipe_stdout[PARENT_ID]);
    int32 wait = waitpid(child_pid, &status, 0);
    if (wait == child_pid && WIFEXITED((unsigned int)status) && WEXITSTATUS((unsigned int)status) != 0) {
        printf("[ctbackup]child process exec backup failed, ret=%d\n, try to check cantian stat.", status);
        if (need_retry == CT_TRUE &&
            ctbak_check_ctsql_online(CTBAK_BACKUP_CECHK_ONLINE_TIME) == CT_SUCCESS) {
            *retry = CT_TRUE;
        }
        return CT_ERROR;
    }
    printf("[ctbackup]%s execute success and exit with: %d\n", "cantian backup", WEXITSTATUS((unsigned int)status));
    return CT_SUCCESS;
}

status_t ctbak_do_backup_cantian(ctbak_param_t* ctbak_param, bool32 *retry)
{
    char *ct_params[CTBACKUP_MAX_PARAMETER_CNT] = {0};
    status_t status = fill_params_for_cantian_backup(ctbak_param, ct_params);
    if (status != CT_SUCCESS) {
        printf("[ctbackup]fill_params_for_cantian_backup failed!\n");
        return CT_ERROR;
    }
    char *ctsql_binary_path = NULL;
    if (get_ctsql_binary_path(&ctsql_binary_path) != CT_SUCCESS) {
        CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
        CM_FREE_PTR(ct_params[CTSQL_STATEMENT_INDEX]);
        printf("[ctbackup]get_ctsql_binary_path failed!\n");
        return CT_ERROR;
    }
    status = ctbak_do_ctsql_backup(ctsql_binary_path, ct_params, retry);
    // free space of heap
    CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
    CM_FREE_PTR(ct_params[CTSQL_STATEMENT_INDEX]);
    CM_FREE_PTR(ctsql_binary_path);
    if (status != CT_SUCCESS) {
        printf("[ctbackup]cantian data files backup failed!\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t ctback_backup_mysql(ctbak_param_t* ctbak_param)
{
    printf("[ctbackup]ready to backup the meta data of mysql!\n");
    if (ctbak_do_backup_mysql(ctbak_param) != CT_SUCCESS) {
        return CT_ERROR;
    }
    printf("[ctbackup]mysql meta data backup success, ready to backup cantian data files!\n");
    return CT_SUCCESS;
}

/**
 * 1. mysql execute LOCK INSTANCE FOR BACKUP
 * 2. xtrabackup execute backup
 * 3. ctsql execute backup
 * 4. mysql execute UNLOCK INSTANCE
 * @param ctbak_param
 * @return
 */
status_t ctbak_do_backup(ctbak_param_t* ctbak_param)
{
    if (check_common_params(ctbak_param) != CT_SUCCESS) {
        return CT_ERROR;
    }

    uint32 retry_num = 0;
    while (retry_num < CTBAK_BACKUP_RETRY_MAX_NUM) {
        bool32 retry = CT_FALSE;
        if (ctbackup_set_metadata_mode(ctbak_param) != CT_SUCCESS) {
            printf("[ctbackup]set mysql_metadata_in_cantian param failed!\n");
            break;
        }
        if (ctbak_check_data_dir(ctbak_param->target_dir.str) != CT_SUCCESS) {
            printf("[ctbackup]check datadir is empty failed!\n");
            break;
        }
        if (ctback_lock_mysql_for_backup(ctbak_param) != CT_SUCCESS) {
            printf("[ctbackup]call ctback_lock_mysql_for_backup failed!\n");
            break;
        }
        // 元数据归一模式下，不备份mysql数据
        if (ctbak_param->is_mysql_metadata_in_cantian == CT_FALSE &&
            ctback_backup_mysql(ctbak_param) != CT_SUCCESS) {
            ctback_unlock_mysql_for_backup();
            break;
        }
        if (ctbak_do_backup_cantian(ctbak_param, &retry) == CT_SUCCESS) {
            printf("[ctbackup]cantian data files backup success\n");
            CT_RETURN_IFERR(ctback_unlock_mysql_for_backup());
            free_input_params(ctbak_param);
            return CT_SUCCESS;
        }
        CT_RETURN_IFERR(ctback_unlock_mysql_for_backup());
        if (retry != CT_TRUE) {
            break;
        }
        printf("[ctbackup]call ctbak_do_backup_cantian failed, clear targer dir and retry again!\n");
        if (ctbak_clear_data_dir(ctbak_param->target_dir.str, ctbak_param->target_dir.str) != CT_SUCCESS) {
            printf("[ctbackup]clear targer dir %s failed for backup retry!\n", ctbak_param->target_dir.str);
            break;
        }
        retry_num++;
    };
    free_input_params(ctbak_param);
    printf("[ctbackup]cantian backup execute failed!\n");
    return CT_ERROR;
}

static inline void ctbak_hide_password(char* password)
{
    while (*password) {
        *password++ = 'x';
    }
}

status_t ctbak_parse_backup_args(int32 argc, char** argv, ctbak_param_t* ctbak_param)
{
    int opt_s;
    int opt_index;
    optind = 1;
    while (optind < argc) {
        CT_RETURN_IFERR(check_input_params(argv[optind]));
        opt_s = getopt_long(argc, argv, CTBAK_SHORT_OPTION_EXP, ctbak_backup_options, &opt_index);
        if (opt_s == CTBAK_PARSE_OPTION_ERR) {
            break;
        }
        switch (opt_s) {
            case CTBAK_PARSE_OPTION_COMMON:
                break;
            case CTBAK_SHORT_OPTION_TARGET_DIR:
                CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->target_dir));
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
            case CTBAK_SHORT_OPTION_DEFAULTS_FILE:
                CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->defaults_file));
                break;
            case CTBAK_SHORT_OPTION_SOCKET:
                CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->socket));
                break;
            case CTBAK_SHORT_OPTION_DATA_DIR:
                CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->data_dir));
                break;
            case CTBAK_SHORT_OPTION_INCREMENTAL:
                ctbak_param->is_incremental = CT_TRUE;
                break;
            case CTBAK_SHORT_OPTION_INCREMENTAL_CUMULATIVE:
                ctbak_param->is_incremental_cumulative = CT_TRUE;
                break;
            case CTBAK_SHORT_OPTION_DATABASES_EXCLUDE:
                CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->databases_exclude));
                break;
            case CTBAK_SHORT_OPTION_PARALLEL:
                CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->parallelism));
                break;
            case CTBAK_SHORT_OPTION_COMPRESS:
                CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->compress_algo));
                break;
            case CTBAK_SHORT_OPTION_BUFFER:
                CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->buffer_size));
                break;
            case CTBAK_SHORT_OPTION_SKIP_BADBLOCK:
                ctbak_param->skip_badblock = CT_TRUE;
                break;
            case CTBAK_SHORT_OPTION_UNRECOGNIZED:
            case CTBAK_SHORT_OPTION_NO_ARG:
                printf("[ctbackup]Parse option arguments of backup error!\n");
                return CT_ERROR;
            default:
                break;
        }
    }
    return CT_SUCCESS;
}

ctbak_cmd_t *ctbak_generate_backup_cmd(void)
{
    ctbak_cmd_t* ctbak_cmd = (ctbak_cmd_t*)malloc(sizeof(ctbak_cmd_t));
    if (ctbak_cmd == NULL) {
        printf("[ctbackup]failed to malloc memory for backup ctbak_cmd!\n");
        return (ctbak_cmd_t *)NULL;
    }
    printf("[ctbackup]process ctbak_generate_backup_cmd\n");
    ctbak_cmd->do_exec = ctbak_do_backup;
    ctbak_cmd->parse_args = ctbak_parse_backup_args;
    return ctbak_cmd;
};
