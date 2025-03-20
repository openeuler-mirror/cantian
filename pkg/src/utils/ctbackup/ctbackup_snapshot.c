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
 * ctbackup_snapshot.c
 *
 *
 * IDENTIFICATION
 * src/utils/ctbackup/ctbackup_snapshot.c
 *
 * -------------------------------------------------------------------------
 */
#include <pthread.h>
#include "ctbackup_snapshot.h"
#include "ctbackup_common.h"

#define CTBAK_SNAPSHOT_RETRY_MAX_NUM 2
#define CTBAK_SNAPSHOT_CECHK_ONLINE_TIME 5

#define CTSQL_CONNECT_CLOSED_32 "tcp connection is closed, reason: 32"
#define CTBAK_PREVENT_RECYCLE_REDO "prevent"
#define CTBAK_OPEN_RECYCLE_REDO "open"

int32 g_snap_info_handle = 0;
snapshot_backup_info_t g_snapshot_backup_info = {0};
static int32 g_snap_timeout = 8;

typedef struct {
    ctbak_param_t* param;
    status_t result;
} snapshot_thread_arg_t;

const struct option ctbak_snapshot_options[] = {
    {CTBAK_LONG_OPTION_SNAPSHOT, no_argument, NULL, CTBAK_PARSE_OPTION_SNAPSHOT},
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

static status_t fill_params_for_mysql_backup(ctbak_param_t* ctbak_param, char *params[], int *index)
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
        CT_RETURN_IFERR(set_mysql_param_value(params, ctbak_param->host,
                                              HOST_PARAM_OPTION, (*index)++));
    }

    if (ctbak_param->user.str != NULL) {
        CT_RETURN_IFERR(set_mysql_param_value(params, ctbak_param->user,
                                              USER_PARAM_OPTION, (*index)++));
    }

    if (ctbak_param->password.str != NULL) {
        CT_RETURN_IFERR(set_mysql_param_value(params, ctbak_param->password,
                                              PWD_PARAM_OPTION, (*index)++));
    }

    if (ctbak_param->port.str != NULL) {
        CT_RETURN_IFERR(set_mysql_param_value(params, ctbak_param->port,
                                              PORT_PARAM_OPTION, (*index)++));
    }

    if (ctbak_param->socket.str != NULL) {
        CT_RETURN_IFERR(set_mysql_param_value(params, ctbak_param->socket,
                                              SOCKET_PARAM_OPTION, (*index)++));
    }

    if (ctbak_param->data_dir.str != NULL) {
        CT_RETURN_IFERR(ctbak_check_dir_access((const char *)ctbak_param->data_dir.str));
        CT_RETURN_IFERR(set_mysql_param_value(params, ctbak_param->data_dir,
                                              DATA_DIR_PARAM_OPRION, (*index)++));
    }

    if (ctbak_param->parallelism.str != NULL) {
        CT_RETURN_IFERR(set_mysql_param_value(params, ctbak_param->parallelism,
                                              PARALLEL_PARAM_OPTION, (*index)++));
    }

    if (ctbak_param->databases_exclude.str != NULL) {
        CT_RETURN_IFERR(set_mysql_param_value(params, ctbak_param->databases_exclude,
                                              DATABASESEXCLUDE_PARAM_OPTION, (*index)++));
    }

    if (ctbak_param->compress_algo.str != NULL) {
        CT_RETURN_IFERR(set_mysql_param_value(params, ctbak_param->compress_algo,
                                              COMPRESS_ALGO_OPTION, (*index)++));
    }

    CT_RETURN_IFERR(ctbak_check_dir_access((const char *)ctbak_param->target_dir.str));
    CT_RETURN_IFERR(set_mysql_param_value(params, ctbak_param->target_dir,
                                          TARGET_DIR_PARAM_OPTION, (*index)++));
    CT_RETURN_IFERR(set_mysql_param_value(params, temp, SKIP_LOCK_DDL, (*index)++));
    // The last parameter must be NULL
    params[*index] = NULL;
    return CT_SUCCESS;
}

status_t generate_snapshot_info_path(char *fs_name, char *ct_snapshot_info_path)
{
    // int32 file_fd;
    errno_t ret;
    ret = snprintf_s(ct_snapshot_info_path, CANTIAN_SNAPSHOT_FILE_LENGTH, CANTIAN_SNAPSHOT_FILE_LENGTH - 1,
                     "/%s%s", fs_name, SNAPSHOT_INFO_FS_PATH);
    PRTS_RETURN_IFERR(ret);
    return CT_SUCCESS;
}

status_t ctbak_generate_snap_info_file(char *target_dir, char *file_name, int32 *handle)
{
    char snapinfo_file_name[CANTIAN_SNAPSHOT_FILE_LENGTH] = {0};
    errno_t ret;
    ret = snprintf_s((char *)snapinfo_file_name, CANTIAN_SNAPSHOT_FILE_LENGTH, CANTIAN_SNAPSHOT_FILE_LENGTH - 1,
                     "%s/%s", target_dir, file_name);
    PRTS_RETURN_IFERR(ret);
    printf("[ctbackup] snapinfo_file_name is %s\n", snapinfo_file_name);

    if (dbs_create_snapshot_info_file((char *)snapinfo_file_name, handle) != CT_SUCCESS) {
        printf("[ctbackup] Failed to create snapshot info file %s in share_fs\n", snapinfo_file_name);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t get_statement_for_recycle_redo(char* opt, uint64_t len, char *statement)
{
    errno_t ret;
    if (opt == CTBAK_PREVENT_RECYCLE_REDO) {
        ret = snprintf_s(statement, len, len - 1, "%s%s%s", CTSQL_RECYCLE_REDO_STATEMENT_PREFIX,
                         CTSQL_TRUE, CTSQL_STATEMENT_END_CHARACTER);
    } else {
        ret = snprintf_s(statement, len, len - 1, "%s%s%s", CTSQL_RECYCLE_REDO_STATEMENT_PREFIX,
                         CTSQL_FALSE, CTSQL_STATEMENT_END_CHARACTER);
    }
    FREE_AND_RETURN_ERROR_IF_SNPRINTF_FAILED(ret, statement);
    return CT_SUCCESS;
}

status_t fill_params_for_recycle_redo(char* opt, char *ct_params[])
{
    int param_index = 0;
    uint64_t len;
    if (fill_params_for_ctsql_login(ct_params, &param_index, CTBAK_CTSQL_EXECV_MODE) != CT_SUCCESS) {
        printf("[ctbackup]failed to fill params for ctsql login!\n");
        return CT_ERROR;
    }
    len = strlen(CTSQL_RECYCLE_REDO_STATEMENT_PREFIX);
    if (opt == CTBAK_PREVENT_RECYCLE_REDO) {
        len = len + strlen(CTSQL_TRUE) + strlen(CTSQL_STATEMENT_END_CHARACTER) + 1;
    } else {
        len = len + strlen(CTSQL_FALSE) + strlen(CTSQL_STATEMENT_END_CHARACTER) + 1;
    }
    char *statement = (char *)malloc(len);
    if (statement == NULL) {
        CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
        printf("[ctbackup]failed to apply storage for %s recycle redo!\n", opt);
        CTBAK_RETURN_ERROR_IF_NULL(statement);
    }
    if (get_statement_for_recycle_redo(opt, len, statement) != CT_SUCCESS) {
        CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
        printf("[ctbackup]get statement for %s recycle redo failed!\n", opt);
        return CT_ERROR;
    }
    ct_params[param_index++] = statement;
    ct_params[param_index++] = NULL;
    return CT_SUCCESS;
}

static status_t ctbak_do_backup_mysql(ctbak_param_t* ctbak_param)
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

void ctbak_check_recycle_redo_output(char *output, bool32 *need_retry)
{
    if (strstr(output, CTSQL_CONNECT_CLOSED_32) != NULL) {
        *need_retry = CT_TRUE;
    }
    return;
}

status_t ctbak_do_ctsql_recycle_redo(char *opt, char *path, char *params[], bool32 *retry)
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
    char output[MAX_STATEMENT_LENGTH] = { 0 };
    bool32 need_retry = CT_FALSE;
    FILE *fp = fdopen(pipe_stdout[PARENT_ID], "r");
    while(fgets(output, MAX_STATEMENT_LENGTH, fp) != NULL) {
        // output ctsql recycle_redo result and check the error info
        printf("%s", output);
        ctbak_check_recycle_redo_output(output, &need_retry);
    }
    fclose(fp);
    close(pipe_stdout[PARENT_ID]);
    int32 wait = waitpid(child_pid, &status, 0);
    if (wait == child_pid && WIFEXITED((unsigned int)status) && WEXITSTATUS((unsigned int)status) != 0) {
        printf("[ctbackup]child process exec %s snapshot recycle redo failed, ret=%d, try to check cantian stat.\n", opt, status);
        if (need_retry == CT_TRUE &&
            ctbak_check_ctsql_online(CTBAK_SNAPSHOT_CECHK_ONLINE_TIME) == CT_SUCCESS) {
            *retry = CT_TRUE;
        }
        return CT_ERROR;
    }
    printf("[ctbackup]%s %s execute success and exit with: %d\n", opt, "snapshot recycle redo", WEXITSTATUS((unsigned int)status));
    return CT_SUCCESS;
}

status_t ctbak_do_recycle_redo(char* opt, bool32 *retry)
{
    char *ct_params[CTBACKUP_MAX_PARAMETER_CNT] = { 0 };
    status_t status = fill_params_for_recycle_redo(opt, ct_params);
    if (status != CT_SUCCESS) {
        printf("[ctbackup]fill_params_for_%s_recycle_redo failed!\n", opt);
        return CT_ERROR;
    }
    char *ctsql_binary_path = NULL;
    if (get_ctsql_binary_path(&ctsql_binary_path) != CT_SUCCESS) {
        CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
        CM_FREE_PTR(ct_params[CTSQL_STATEMENT_INDEX]);
        printf("[ctbackup]get_ctsql_binary_path failed!\n");
        return CT_ERROR;
    }
    status = ctbak_do_ctsql_recycle_redo(opt, ctsql_binary_path, ct_params, retry);
    // free space of heap
    CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
    CM_FREE_PTR(ct_params[CTSQL_STATEMENT_INDEX]);
    CM_FREE_PTR(ctsql_binary_path);
    if (status != CT_SUCCESS) {
        printf("[ctbackup]ctsql %s recycle redo failed!\n", opt);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t ctback_backup_mysql(ctbak_param_t* ctbak_param)
{
    printf("[ctbackup]ready to backup the meta data of mysql!\n");
    if (ctbak_do_backup_mysql(ctbak_param) != CT_SUCCESS) {
        return CT_ERROR;
    }
    printf("[ctbackup]mysql meta data backup success, ready to backup cantian data files!\n");
    return CT_SUCCESS;
}

status_t ctbak_record_snapshot_info(char* fs_name, snapshot_result_info* src_info, snapshot_result_info* dst_info) {
    errno_t err;
    err = strcpy_s(dst_info->snapName, CSS_MAX_FSNAME_LEN, src_info->snapName);
    if (err != EOK) {
        printf("[ctbackup]Failed to record %s_fs_snap_name, ERRNO: %d\n", fs_name, err);
        return CT_ERROR;
    }
    err = memcpy_s(dst_info->snapUUID, sizeof(dst_info->snapUUID), src_info->snapUUID,sizeof(src_info->snapUUID));
    if (err != EOK) {
        printf("[ctbackup]Failed to record %s_fs_snapUUID, , ERRNO: %d\n", fs_name, err);
        return CT_ERROR;
    }
    dst_info->snapshotID = src_info->snapshotID;
    dst_info->timepoint = src_info->timepoint;
    return CT_SUCCESS;
}

void print_snapshot_info(const char* fs_name, snapshot_result_info snap_info)
{
    printf("[ctbackup]%s_snap_name is %s\n", fs_name, snap_info.snapName);
    printf("[ctbackup]%s_snapUUID is %u\n", fs_name, snap_info.snapshotID);
    printf("[ctbackup]%s_timepoint is %u\n", fs_name, snap_info.timepoint);
    printf("[ctbackup]%s_snapUUID is ", fs_name);
    for(int i = 0; i <= FS_SNAP_UUID_LEN; i++) {
        if (i == FS_SNAP_UUID_LEN) {
            printf("\n");
            break;
        }
        printf("%u", snap_info.snapUUID[i]);
    }
}

status_t ctbak_create_snapshot(ctbak_param_t* ctbak_param) {
    uint32_t page_fs_vstore_id = 0;
    uint32_t log_fs_vstore_id = 0;
    cm_text2uint32(&ctbak_param->page_fs_vstore_id, &page_fs_vstore_id);
    cm_text2uint32(&ctbak_param->log_fs_vstore_id, &log_fs_vstore_id);
    snapshot_result_info snap_info = { 0 };
    // 创建page快照
    printf("[ctbackup]start create page_fs snapshot!\n");
    if (dbs_create_fs_snap(ctbak_param->page_fs_name.str, page_fs_vstore_id, &snap_info) != CT_SUCCESS) {
        printf("[ctbackup]create page fs snap failed!\n");
        return CT_ERROR;
    }
    printf("[ctbackup]create page_fs snapshot success!\n");
    print_snapshot_info(ctbak_param->page_fs_name.str, snap_info);
    // 记录page快照信息
    if (ctbak_record_snapshot_info(ctbak_param->page_fs_name.str, &snap_info,
                                   &g_snapshot_backup_info.page_fs_snap_info)!= CT_SUCCESS) {
        printf("[ctbackup]Failed to record page_snap_info\n");
        return CT_ERROR;
    }

    // 创建redo快照
    errno_t err;
    err = memset_s(&snap_info, sizeof(snapshot_result_info), 0, sizeof(snapshot_result_info));
    if (err != EOK) {
        printf("[ctbackup]Failed to memset snap_info, ERRNO: %d\n", err);
        return CT_ERROR;
    }
    printf("[ctbackup]start create redo_fs snapshot!\n");
    if (dbs_create_fs_snap(ctbak_param->log_fs_name.str, log_fs_vstore_id, &snap_info) != CT_SUCCESS) {
        printf("[ctbackup]create redo fs snap failed!\n");
        if (dbs_delete_fs_snap(ctbak_param->page_fs_name.str, page_fs_vstore_id,
                               &g_snapshot_backup_info.page_fs_snap_info) != CT_SUCCESS) {
            printf("[ctbackup]delete page fs snap failed!\n");
        }
        return CT_ERROR;
    }
    printf("[ctbackup]create redo_fs snapshot success!\n");
    print_snapshot_info(ctbak_param->log_fs_name.str, snap_info);

    // 记录redo快照信息
    if (ctbak_record_snapshot_info(ctbak_param->log_fs_name.str, &snap_info,
                                   &g_snapshot_backup_info.log_fs_snap_info)!= CT_SUCCESS) {
        printf("[ctbackup]Failed to record log_snap_info\n");
        return CT_ERROR;
    }

    // 创建归档快照
    err = memset_s(&snap_info, sizeof(snapshot_result_info), 0, sizeof(snapshot_result_info));
    if (err != EOK) {
        printf("[ctbackup]Failed to memset snap_info, ERRNO: %d\n", err);
        return CT_ERROR;
    }
    printf("[ctbackup]start create redo_fs snapshot!\n");
    if (dbs_create_fs_snap(ctbak_param->archive_fs_name.str, log_fs_vstore_id, &snap_info)!= CT_SUCCESS) {
        printf("[ctbackup]create archive fs snap failed!\n");
        if (dbs_delete_fs_snap(ctbak_param->page_fs_name.str, page_fs_vstore_id,
                               &g_snapshot_backup_info.page_fs_snap_info) != CT_SUCCESS) {
            printf("[ctbackup]delete page fs snap failed!\n");
        }
        if (dbs_delete_fs_snap(ctbak_param->log_fs_name.str, log_fs_vstore_id,
                               &g_snapshot_backup_info.log_fs_snap_info) != CT_SUCCESS) {
            printf("[ctbackup]delete log fs snap failed!\n");
        }
        return CT_ERROR;
    }
    printf("[ctbackup]create archive_fs snapshot success!\n");
    print_snapshot_info(ctbak_param->archive_fs_name.str, snap_info);

    // 记录归档快照信息
    if (ctbak_record_snapshot_info(ctbak_param->archive_fs_name.str, &snap_info,
                                   &g_snapshot_backup_info.archive_fs_snap_info)!= CT_SUCCESS) {
        printf("[ctbackup]Failed to record archive_snap_info\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

// 添加线程执行函数
static void* snapshot_thread_func(void* arg)
{
    snapshot_thread_arg_t* thread_arg = (snapshot_thread_arg_t*)arg;
    thread_arg->result = ctbak_create_snapshot(thread_arg->param);
    return NULL;
}

status_t ctbak_create_snapshot_thread(ctbak_param_t* ctbak_param)
{
    pthread_t snapshot_thread;
    snapshot_thread_arg_t thread_arg = {ctbak_param, CT_ERROR};
    struct timespec start_time, current_time;

    clock_gettime(CLOCK_MONOTONIC, &start_time);

    // 创建快照线程
    if (pthread_create(&snapshot_thread, NULL, snapshot_thread_func, &thread_arg) != 0) {
        printf("[ctbackup]Failed to create snapshot thread\n");
        return CT_ERROR;
    }

    // 等待线程完成或超时
    while (1) {
        usleep(100000); // 每100ms检查一次
        clock_gettime(CLOCK_MONOTONIC, &current_time);

        if (current_time.tv_sec - start_time.tv_sec >= g_snap_timeout) {
            printf("[ctbackup]ERROR: Create snapshot timed out after %d seconds\n", g_snap_timeout);
            pthread_cancel(snapshot_thread);
            pthread_join(snapshot_thread, NULL);
            return CT_ERROR;
        }

        // 检查线程是否完成
        int try_join = pthread_tryjoin_np(snapshot_thread, NULL);
        if (try_join == 0) {
            break; // 线程正常结束
        } else if (try_join != EBUSY) {
            printf("[ctbackup]Error checking snapshot thread status\n");
            pthread_cancel(snapshot_thread);
            pthread_join(snapshot_thread, NULL);
            return CT_ERROR;
        }
    }

    // 检查执行结果
    if (thread_arg.result != CT_SUCCESS) {
        printf("[ctbackup]create_snapshot failed!\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t ctbak_create_snapshot_info_file(ctbak_param_t* ctbak_param) {
    char ct_snapshot_info_path[CANTIAN_SNAPSHOT_FILE_LENGTH] = { 0 };
    if (generate_snapshot_info_path(ctbak_param->share_fs_name.str, (char *)ct_snapshot_info_path) != CT_SUCCESS) {
        printf("[ctbackup]generate_snapshot_info_path failed!\n");
        return CT_ERROR;
    }
    printf("[ctbackup]ct_snapshot_info_path is %s\n", ct_snapshot_info_path);
    if (ctbak_generate_snap_info_file(ct_snapshot_info_path, CTBAK_SNAP_INFO_FILE_NAME,
                                      &g_snap_info_handle) != CT_SUCCESS) {
        printf("[ctbackup]ctbak_generate_snap_info_file failed!\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t ctbak_write_snapshot_info_file() {
    if (dbs_write_snapshot_info_file(g_snap_info_handle, 0, &g_snapshot_backup_info,
                                     sizeof(snapshot_backup_info_t))!= CT_SUCCESS) {
        printf("[ctbackup]write page snapshot info file failed!\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t ctbak_do_snapshot(ctbak_param_t* ctbak_param)
{
    if (check_common_params(ctbak_param) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (check_cantiand_status(CT_TRUE) != CT_SUCCESS) {
        printf("[ctbackup]cantian is not running, please start cantian first!\n");
        return CT_ERROR;
    }

    if (dbs_init(ctbak_param) != CT_SUCCESS) {
        printf("[ctbackup]dbstor init failed!\n");
        return CT_ERROR;
    }

    uint32 retry_num = 0;
    while (retry_num < CTBAK_SNAPSHOT_RETRY_MAX_NUM) {
        bool32 retry = CT_FALSE;
        if (ctbackup_set_metadata_mode(ctbak_param) != CT_SUCCESS) {
            printf("[ctbackup]set mysql_metadata_in_cantian param failed!\n");
            break;
        }

        if (ctbak_check_data_dir(ctbak_param->target_dir.str) != CT_SUCCESS) {
            printf("[ctbackup]check target_dir is empty failed!\n");
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

        if (ctbak_do_recycle_redo(CTBAK_PREVENT_RECYCLE_REDO, &retry) == CT_SUCCESS) {
            printf("[ctbackup]cantian prevent snapshot recycle redo success\n");
            if (ctbak_create_snapshot_thread(ctbak_param) != CT_SUCCESS) {
                printf("[ctbackup]create_snapshot failed!\n");
                return CT_ERROR;
            }
            if (ctbak_create_snapshot_info_file(ctbak_param) != CT_SUCCESS) {
                printf("[ctbackup]create snapshot info file failed!\n");
                return CT_ERROR;
            }
            if (ctbak_write_snapshot_info_file() != CT_SUCCESS) {
                printf("[ctbackup]write snapshot info file failed!\n");
                return CT_ERROR;
            }
            if (ctbak_do_recycle_redo(CTBAK_OPEN_RECYCLE_REDO, &retry) == CT_SUCCESS) {
                printf("[ctbackup]cantian open snapshot recycle redo success\n");
                CT_RETURN_IFERR(ctback_unlock_mysql_for_backup());
                free_input_params(ctbak_param);
                return CT_SUCCESS;
            }
        }
        CT_RETURN_IFERR(ctback_unlock_mysql_for_backup());
        if (retry != CT_TRUE) {
            break;
        }
        printf("[ctbackup]call ctbak_do_snapshot failed, clear targer dir and retry again!\n");
        if (ctbak_clear_data_dir(ctbak_param->target_dir.str, ctbak_param->target_dir.str) != CT_SUCCESS) {
            printf("[ctbackup]clear targer dir %s failed for backup retry!\n", ctbak_param->target_dir.str);
            break;
        }
        retry_num++;
    }
    free_input_params(ctbak_param);
    printf("[ctbackup]cantian snapshot execute failed!\n");
    return CT_ERROR;
}

static inline void ctbak_hide_password(char* password)
{
    while (*password) {
        *password++ = 'x';
    }
}

status_t ctbak_parse_snapshot_args(int32 argc, char** argv, ctbak_param_t* ctbak_param)
{
    int opt_s;
    int opt_index;
    optind = 1;
    while (optind < argc) {
        CT_RETURN_IFERR(check_input_params(argv[optind]));
        opt_s = getopt_long(argc, argv, CTBAK_SHORT_OPTION_EXP, ctbak_snapshot_options, &opt_index);
        if (opt_s == CTBAK_PARSE_OPTION_ERR) {
            break;
        }
        switch (opt_s) {
            case CTBAK_PARSE_OPTION_SNAPSHOT:
                ctbak_param->is_snapshot = CT_TRUE;
                ctbak_param->is_snapshot_backup = CT_FALSE;
                ctbak_param->is_notdelete = CT_FALSE;
                break;
            // MySQL元数据存放路径
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
            case CTBAK_SHORT_OPTION_DATA_DIR:
                CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->data_dir));
                break;
            case CTBAK_SHORT_OPTION_PARALLEL:
                CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->parallelism));
                break;
            case CTBAK_SHORT_OPTION_COMPRESS:
                CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->compress_algo));
                break;
            case CTBAK_SHORT_OPTION_UNRECOGNIZED:
            case CTBAK_SHORT_OPTION_NO_ARG:
                printf("[ctbackup]Parse option arguments of snapshot error!\n");
                return CT_ERROR;
            default:
                break;
        }
    }
    return CT_SUCCESS;
}

ctbak_cmd_t *ctbak_generate_snapshot_cmd(void)
{
    ctbak_cmd_t* ctbak_cmd = (ctbak_cmd_t*)malloc(sizeof(ctbak_cmd_t));
    if (ctbak_cmd == NULL) {
        printf("[ctbackup]failed to malloc memory for snapshot ctbak_cmd!\n");
        return (ctbak_cmd_t *)NULL;
    }
    printf("[ctbackup]process ctbak_generate_snapshot_cmd\n");
    ctbak_cmd->do_exec = ctbak_do_snapshot;
    ctbak_cmd->parse_args = ctbak_parse_snapshot_args;
    return ctbak_cmd;
}