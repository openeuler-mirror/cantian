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
 * ctbackup_common.h
 *
 *
 * IDENTIFICATION
 * src/utils/ctbackup/ctbackup_common.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CANTIANDB_100_CTBACKUP_COMMON_H
#define CANTIANDB_100_CTBACKUP_COMMON_H

#include "dirent.h"
#include "cm_defs.h"
#include "cm_file.h"
#include "ctbackup_info.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CTBACKUP_MAX_PARAMETER_CNT   (uint32)16
#define CTSQL_MAX_PARAMETER_CNT   (uint32)3

#define MYSQL_BACKUP_TOOL_NAME "xtrabackup"
#define MYSQL_EXE_MAX_STR_LEN   (uint32)1000
// MySQL configuration file path option, such as /etc/my.cnf
#define DEFAULTS_FILE_PARAM_OPTION "--defaults-file="
// Socket file path for connecting to MySQL
#define SOCKET_PARAM_OPTION "--socket="
// MySQL executes backup files.
#define EXEC_PARAM_OPTION "< "
// MySQL data directory path
#define DATA_DIR_PARAM_OPRION "--datadir="
#define HOST_PARAM_OPTION "--host="
#define USER_PARAM_OPTION "--user="
#define PWD_PARAM_OPTION "--password="
#define PORT_PARAM_OPTION "--port="
// Parent directory to store the backup files
#define TARGET_DIR_PARAM_OPTION "--target-dir="
#define PARALLEL_PARAM_OPTION "--parallel="
#define COMPRESS_ALGO_OPTION "--compress="
#define DATABASESEXCLUDE_PARAM_OPTION "--databases-exclude="
#define CTBAK_SHORT_OPTION_EXP "u:p:P:h"
#define START_INDEX_FOR_PARSE_PARAM 1
#define CTSQL_STATEMENT_INDEX 4
#define CTSQL_LOGININFO_INDEX 1
#define SKIP_LOCK_DDL "--skip-lock-ddl"
#define FORCE_DDL_IGNORE_ERROR "--force"
#define SKIP_BADBLOCK "--skip-badblock"
#define REPAIR_TYPE "--repair-type="
// LEVEL 0 indicates the baseline incremental backup, equals full backup
#define CTSQL_FULL_BACKUP_STATEMENT_PREFIX "BACKUP DATABASE INCREMENTAL LEVEL 0 FORMAT \'"
#define CTSQL_INCREMENT_BACKUP_STATEMENT_PREFIX "BACKUP DATABASE INCREMENTAL LEVEL 1 FORMAT \'"
#define CTSQL_INCREMENT_CUMULATIVE_BACKUP_STATEMENT_PREFIX "BACKUP DATABASE INCREMENTAL LEVEL 1 CUMULATIVE FORMAT \'"
#define CTSQL_STATEMENT_QUOTE "\'"
#define CTSQL_PARALLELISM_OPTION " PARALLELISM "
#define CTSQL_BUFFER_OPTION " BUFFER SIZE "
#define CTSQL_COMPRESS_OPTION_PREFIX " as "
#define CTSQL_COMPRESS_OPTION_SUFFIX " compressed backupset "
#define CTSQL_STATEMENT_END_CHARACTER ";"
#define CTSQL_EXCLUDE_OPTION " EXCLUDE FOR TABLESPACE "
#define CTSQL_EXCLUDE_SUFFIX "_DB"
#define CTSQL_SKIP_BADBLOCK " SKIP BADBLOCK"
// TARGET_DIR_PARAM_OPTION's next level dir, for store mysql backup files
#define MYSQL_BACKUP_DIR "/mysql"
// TARGET_DIR_PARAM_OPTION's next level dir, for store cantian backup files
#define CANTIAN_BACKUP_DIR "/cantian"
#define CANTIAN_BACKUP_BACKUPSET "/backupset"
#define DECRYPT_CMD_ECHO "echo "
#define DECRYPT_CMD_BASE64 " | openssl base64 -d"
#define CANTIAN_BACKUP_FILE_LENGTH 129
#define MAX_TARGET_DIR_LENGTH 120
#define MAX_PARALLELISM_COUNT 16
#define MAX_STATEMENT_LENGTH 512
#define MAX_DATABASE_LENGTH 2048
#define MAX_DATABASE_NAME_LENGTH 128
#define MAX_PASSWORD_LENGTH 1024
#define MAX_SHELL_CMD_LENGTH (MAX_PASSWORD_LENGTH + 512)

#define CTSQL_CHECK_CONN_MAX_TIME_S 300
#define CTSQL_CHECK_CONN_SLEEP_TIME_MS 1000

#define CHILD_ID 1
#define PARENT_ID 0
#define STD_IN_ID 0
#define STD_OUT_ID 1

// TRUE or FALSE
#define MAX_BOOL_STR_LENGTH 6
#define SINGLE_QUOTE "\'"

#define CTSQL_RESTORE_STATEMENT_PREFIX "RESTORE DATABASE FROM \'"
#define CTSQL_RESTORE_REPAIR_TYPE " REPAIR TYPE "
#define CTSQL_RESTORE_REPAIR_TYPE_RETURN_ERROR "RETURN_ERROR"
#define CTSQL_RESTORE_REPAIR_TYPE_REPLACE_CHECKUSM "REPLACE_CHECKSUM"
#define CTSQL_RESTORE_REPAIR_TYPE_DISCARD_BADBLOCK "DISCARD_BADBLOCK"
#define CTSQL_RESTORE_BAD_BLOCK_FILE "/backupset_bad_block_record"
#define CTSQL_RECOVER_STATEMENT_PREFIX "RECOVER DATABASE "
#define CTSQL_PITR_TIME_OPTION "UNTIL TIME \'"
#define CTSQL_PITR_SCN_OPTION "UNTIL SCN "
#define CTSQL_PITR_CANCEL_OPTION "UNTIL CANCEL "

#define CTSQL_ARCHIVELOG_STATEMENT_PREFIX "alter system switch logfile"
#define CTSQL_GET_LRP_LSN_STATEMENT "SELECT LRP_LSN FROM SYS_BACKUP_SETS"
#define CTSQL_RECOVER_RESET_LOG "ALTER DATABASE OPEN RESETLOGS"
#define CTSQL_PURGE_LOGS "ALTER DATABASE DELETE ARCHIVELOG ABNORMAL"

#define DEFAULT_SHELL "/bin/sh"
#define XTRABACKUP_PATH "/bin/xtrabackup"
#define DEFAULT_CTSQL_PATH "/bin/ctsql"

#define START_CANTIAND_SERVER_CMD "installdb.sh -P tempstartcantiand"
#define CHECK_CANTAIND_STATUS_CMD "installdb.sh -P checkcantiandstatus"
#define STOP_CANTIAND_SERVER_CMD "installdb.sh -P stopcantiand"
#define TRY_CONN_CTSQL_CMD "installdb.sh -P tryconnctsql"

#define CTSQL_QUERY_CANTIAN_PARAMETERS "'SHOW PARAMETERS'"
#define MYSQL_METADATA_IN_CANTIAN_GREP "| grep MYSQL_METADATA_IN_CANTIAN | awk '{print $4}'"

#define CTSQL_FILE_NAME_BUFFER_SIZE   CT_FILE_NAME_BUFFER_SIZE
#define CTSQL_CMD_BUFFER_SIZE         (CTSQL_FILE_NAME_BUFFER_SIZE + MAX_STATEMENT_LENGTH)
#define CTSQL_CMD_OUT_BUFFER_SIZE     (CT_MAX_CMD_LEN + 1)
#define CTSQL_CMD_IN_BUFFER_SIZE      (CT_MAX_CMD_LEN + 1)

#ifndef WIFEXITED
#define WIFEXITED(w)	(((w) & 0XFFFFFF00) == 0)
#define WIFSIGNALED(w)	(!WIFEXITED(w))
#define WEXITSTATUS(w)	(w)
#define WTERMSIG(w)		(w)
#endif // WIFEXITED

#define FREE_AND_RETURN_ERROR_IF_SNPRINTF_FAILED(ret, statement) \
    if ((ret) == -1) {                                           \
        CM_FREE_PTR(statement);                                  \
        return CT_ERROR;                                         \
    }

#define CTBAK_RETURN_ERROR_IF_NULL(ret) \
    do {                                \
        if ((ret) == NULL) {            \
            CT_LOG_DEBUG_INF("RETURN_IF_ERROR[%s,%d]", __FILE__, __LINE__); \
            return CT_ERROR;            \
        }                               \
    } while (0)

typedef enum en_ctbak_ctsql_exec_mode {
    CTBAK_CTSQL_EXECV_MODE,
    CTBAK_CTSQL_SHELL_MODE,
} ctbak_ctsql_exec_mode_t;

typedef struct ctbak_child_info {
    pid_t child_pid;
    int from_child;
    int to_child;
} ctbak_child_info_t;

status_t ctbak_system_call(char *path, char *params[], char *operation);

status_t ctbak_system_popen(char *path, char *params[], char *cmd_out, char* operation);

status_t ctbak_do_shell_background(text_t* command, int* child_pid, int exec_mode);

void free_system_call_params(char *params[], int start_index, int end_index);

void free_input_params(ctbak_param_t* ctbak_param);

status_t fill_params_for_ctsql_login(char *ct_params[], int* param_index, ctbak_ctsql_exec_mode_t ctsql_exec_mode);

status_t ctbak_parse_single_arg(char *optarg_local, text_t *ctbak_param_option);

status_t check_pitr_params(ctbak_param_t* ctbak_param);

status_t check_common_params(ctbak_param_t* ctbak_param);

status_t set_mysql_param_value(char *params[], text_t ctbak_param_option, char *param_prefix, int index);

status_t set_mysql_single_param_value(char **param, text_t ctbak_param_option, char *param_prefix);

status_t start_cantiand_server(void);

status_t check_cantiand_status(void);

status_t stop_cantiand_server(void);

status_t get_ctsql_binary_path(char** ctsql_binary_path);

status_t check_ctsql_online(void);

status_t check_input_params(char *params);

status_t ctbak_check_ctsql_online(uint32 retry_time);

status_t ctbak_check_data_dir(const char *path);

status_t ctbak_clear_data_dir(const char *sub_path, const char *src_path);

status_t ctbak_change_work_dir(const char *path);

status_t ctbackup_set_metadata_mode(ctbak_param_t *ctbak_param);

status_t ctbak_get_ctsql_output_by_shell(char *ctsql_cmd[], char *cmd_out);

status_t ctbak_check_dir_access(const char *path);

status_t ctbak_do_shell_get_output(text_t *command, char *cmd_out,
    status_t (*ctback_read_output_from_pipe_fun)(ctbak_child_info_t, char*));

status_t get_cfg_ini_file_name(char *ctsql_ini_file_name, char *cantiand_ini_file_path);

#ifdef __cplusplus
}
#endif

#endif // CANTIANDB_100_CTBACKUP_COMMON_H