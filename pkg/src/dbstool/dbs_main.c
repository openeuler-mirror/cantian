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
 * dbs_main.c
 *
 *
 * IDENTIFICATION
 * src/dbstool/dbs_main.c
 *
 * -------------------------------------------------------------------------
 */
#include <stdio.h>
#include <dirent.h>
#include <sys/file.h>
#include <string.h>
#include "cm_types.h"
#include "cm_defs.h"
#include "cm_log.h"
#include "cm_error.h"
#include "cm_file.h"
#include "dbs_adp.h"
#include "cm_timer.h"
#include "cm_dbstore.h"

#define DBS_MAX_CMD_PARAM_COUNT 16
#define DBS_LOGFILE_SIZE (10 * 1024 * 1024)
#define DBS_BACKUP_FILE_COUNT 10
#define DBS_TOOL_LOG_PATH "/opt/cantian/dbstor/data/logs/run"
#define DBS_TOOL_LOG_FILE_NAME "dbs_tool.log"

typedef int32(*cmd_pro_func_t)(int32 argc, char* argv[]);

typedef struct {
    char*            param[DBS_MAX_CMD_PARAM_COUNT];
    cmd_pro_func_t   cmd_pro_func;
    char*            desc;
} dbs_cmd_def_t;

status_t cms_init_loggers()
{
    char file_name[CT_FILE_NAME_BUFFER_SIZE];
    log_param_t *log_param = cm_log_param_instance();

    int32 ret = snprintf_s(log_param->log_home, CT_MAX_PATH_BUFFER_SIZE, CT_MAX_PATH_LEN, "%s", DBS_TOOL_LOG_PATH);
    PRTS_RETURN_IFERR(ret);

    if (!cm_dir_exist(log_param->log_home) || 0 != access(log_param->log_home, W_OK | R_OK)) {
        printf("invalid log home dir:%s.\n", log_param->log_home);
        return CT_ERROR;
    }

    log_param->log_backup_file_count = DBS_BACKUP_FILE_COUNT;
    log_param->audit_backup_file_count = DBS_BACKUP_FILE_COUNT;
    log_param->max_log_file_size = DBS_LOGFILE_SIZE;
    log_param->max_audit_file_size = DBS_LOGFILE_SIZE;
    cm_log_set_file_permissions(CT_DEF_LOG_FILE_PERMISSIONS_640);
    cm_log_set_path_permissions(CT_DEF_LOG_PATH_PERMISSIONS_750);
    log_param->log_level = LOG_RUN_INF_LEVEL | LOG_RUN_ERR_LEVEL | LOG_RUN_WAR_LEVEL;

    for (int32 i = 0; i < LOG_COUNT; i++) {
        ret = snprintf_s(file_name, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s/%s",
            log_param->log_home, DBS_TOOL_LOG_FILE_NAME);
        PRTS_RETURN_IFERR(ret);
        cm_log_init(i, file_name);
    }

    if (cm_start_timer(g_timer()) != CT_SUCCESS) {
        printf("Aborted due to starting timer thread.\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

EXTER_ATTACK int32 dbs_cmd_help(int32 argc, char* argv[]);

dbs_cmd_def_t g_dbs_cmd_defs[] = {
    {{"--h"}, dbs_cmd_help, "print dbs command parameters"},
    {{"--help"}, dbs_cmd_help, "print dbs command parameters"},
    {{"--arch-import", "*[PARAM]"}, dbs_arch_import,
        "Usage: import the archive file(s) from source dir.\n"
        "\tparams: --source-dir=* [--arch-file=*] [--fs-name=*]"},
    {{"--arch-export", "*[PARAM]"}, dbs_arch_export,
        "Usage: export the archive file(s) to target dir.\n"
        "\tparams: --target-dir=* [--arch-file=*] [--fs-name=*]"},
    {{"--arch-clean", "*[PARAM]"}, dbs_arch_clean,
        "Usage: clean the archive file(s) in archive dir.\n"
        "\tparams: [--fs-name=*]"},
    {{"--arch-query", "*[PARAM]"}, dbs_arch_query,
        "Usage: query the archive file(s) in archive dir.\n"
        "\tparams: [--fs-name=*]"},
    {{"--ulog-clean", "*[PARAM]"}, dbs_ulog_clean,
        "Usage: clean the ulog data in redo log file system.\n"
        "\tparams: [--fs-name=*] [--cluster-name=*]"},
    {{"--pagepool-clean", "*[PARAM]"}, dbs_pagepool_clean,
        "Usage: clean the page data in data page file system.\n"
        "\tparams: [--fs-name=*] [--cluster-name=*]"},
    {{"--create-file", "*[PARAM]"}, dbs_create_path_or_file,
        "Usage: create/copy the specified dir/file in the file system.\n"
        "\tparams: --fs-name=* --file-name=* [--source-dir=xxx]"},
    {{"--delete-file", "*[PARAM]"}, dbs_delete_path_or_file,
        "Usage: delete the specified dir/file in the file system.\n"
        "\tparams: --fs-name=* --file-name=*"},
    {{"--query-file", "*[PARAM]"}, dbs_query_file,
        "Usage: query the dir in the file system.\n"
        "\tparams: --fs-name=* --file-path=*"},
};

int32 dbs_cmd_help(int32 argc, char* argv[])
{
    for (int32 i = 0; i < sizeof(g_dbs_cmd_defs) / sizeof(dbs_cmd_def_t); i++) {
        dbs_cmd_def_t* cmd_def = &g_dbs_cmd_defs[i];
        for (int32 p = 0; p < DBS_MAX_CMD_PARAM_COUNT; p++) {
            if (cmd_def->param[p] == NULL) {
                break;
            }

            if (cmd_def->param[p][0] == '*') {
                continue;
            } else {
                printf(" %s", cmd_def->param[p]);
            }
        }
        printf(" , %s\n", cmd_def->desc);
    }
    return CT_SUCCESS;
}

EXTER_ATTACK int32 main(int32 argc, char *argv[])
{
    uint32 cmd_count = sizeof(g_dbs_cmd_defs) / sizeof(dbs_cmd_def_t);
    dbs_cmd_def_t* cmd_def = NULL;
    uint32 p = 0;
    uint32 i = 0;
    for (; i < cmd_count; i++) {
        cmd_def = &g_dbs_cmd_defs[i];
        p = 0;
        for (; p < DBS_MAX_CMD_PARAM_COUNT && p + 1 < argc; p++) {
            if (cmd_def->param[p] == NULL) {
                break;
            }

            if (cmd_def->param[p][0] == '*') {
                continue;
            }

            if (strcmp(argv[p + 1], cmd_def->param[p]) != 0) {
                break;
            }
        }

        if (p >= 1 && (cmd_def->param[p] == NULL || cmd_def->param[p][0] == '*')) {
            break;
        }
    }
    if (i == cmd_count) {
        printf("invalid argument\n");
        return CT_ERROR;
    }

    if (cms_init_loggers() != CT_SUCCESS) {
        printf("dbs init loggers failed.\n");
        return CT_ERROR;
    }

    int32 ret = dbstool_init();
    if (ret != CT_SUCCESS) {
        printf("dbstool init failed(%d).\n.", ret);
        return ret;
    }
    ret = cmd_def->cmd_pro_func(argc, argv);
    printf("%s, ret is %d.\n", cmd_def->desc, ret);
    (void)dbs_global_handle()->dbs_client_flush_log();

    return ret;
}
