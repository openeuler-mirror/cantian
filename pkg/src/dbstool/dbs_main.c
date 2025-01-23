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
#include "cm_dbstor.h"

#define DBS_MAX_CMD_PARAM_COUNT 16

typedef int32(*cmd_pro_func_t)(int32 argc, char* argv[]);

typedef struct {
    char*            param[DBS_MAX_CMD_PARAM_COUNT];
    cmd_pro_func_t   cmd_pro_func;
    char*            desc;
} dbs_cmd_def_t;

EXTER_ATTACK int32 dbs_cmd_help(int32 argc, char* argv[]);

dbs_cmd_def_t g_dbs_cmd_defs[] = {
    {{"--h"}, dbs_cmd_help, "\tprint dbs command parameters"},
    {{"--help"}, dbs_cmd_help, "\tprint dbs command parameters"},
    {{"--arch-import", "*[PARAM]"}, dbs_arch_import,
        "\tUsage: import the archive file(s) from source dir.\n"
        "\tparams: --source-dir=* [--arch-file=*] [--fs-name=*]"},
    {{"--arch-export", "*[PARAM]"}, dbs_arch_export,
        "\tUsage: export the archive file(s) to target dir.\n"
        "\tparams: --target-dir=* [--arch-file=*] [--fs-name=*]"},
    {{"--arch-clean", "*[PARAM]"}, dbs_arch_clean,
        "\tUsage: clean the archive file(s) in archive dir.\n"
        "\tparams: [--fs-name=*]"},
    {{"--arch-query", "*[PARAM]"}, dbs_arch_query,
        "\tUsage: query the archive file(s) in archive dir.\n"
        "\tparams: [--fs-name=*]"},
    {{"--ulog-clean", "*[PARAM]"}, dbs_ulog_clean,
        "\tUsage: clean the ulog data in redo log file system.\n"
        "\tparams: [--fs-name=*] [--cluster-name=*]"},
    {{"--pagepool-clean", "*[PARAM]"}, dbs_pagepool_clean,
        "\tUsage: clean the page data in data page file system.\n"
        "\tparams: [--fs-name=*] [--cluster-name=*]"},
    {{"--create-file", "*[PARAM]"}, dbs_create_path_or_file,
        "\tUsage: create/copy the specified dir/file in the file system.\n"
        "\tparams: --fs-name=* [--file-name=*] [--file-dir=xxx]"},
    {{"--copy-file", "--import", "*[PARAM]"}, dbs_copy_file,
        "\tUsage: copy the dir/file to target file system.\n"
        "\tparams: --fs-name=* --source-dir=* --target-dir=* [--file-name=*] [--overwrite]"},
    {{"--copy-file", "--export", "*[PARAM]"}, dbs_copy_file,
        "\tUsage: copy the dir/file in file system to target dir.\n"
        "\tparams: --fs-name=* --source-dir=* --target-dir=* [--file-name=*] [--overwrite]"},
    {{"--delete-file", "*[PARAM]"}, dbs_delete_path_or_file,
        "\tUsage: delete the specified dir/file in the file system.\n"
        "\tparams: --fs-name=* --file-name=*"},
    {{"--query-file", "*[PARAM]"}, dbs_query_file,
        "\tUsage: query the dir in the file system.\n"
        "\tparams: --fs-name=* [--file-dir=*] [--vstore_id=*]"},
    {{"--ulog-data", "*[PARAM]"}, dbs_ulog_export,
        "\tUsage: export ulog file for debug.\n"
        "\tparams: [node] [target-dir] [start-lsn] [len(optional)]"},
    {{"--page-data", "*[PARAM]"}, dbs_page_export,
        "\tUsage: export page file for debug.\n"
        "\tparams: [page-db] [target-dir] [page-id(optional)] [page-num(optional)]"},
    {{"--set-link-timeout", "*[PARAM]"}, dbs_set_link_timeout,
        "\tUsage: set link timeout period, restart to take effect.\n"
        "\tparams: link-timeout"},
    {{"--get-link-timeout"}, dbs_get_link_timeout,
        "\tUsage: get link timeout period.\n"},
    {{"--io-forbidden", "*[PARAM]"}, dbs_set_ns_io_forbidden,
        "\tUsage: set ns io forbidden.\n"
        "\tparams: <0,1>"},
    {{"--io-status"}, dbs_get_ns_io_forbidden_stat,
        "\tUsage: get ns io forbidden state.\n"},
    {{"--dbs-link-check"}, dbs_link_check, "\tUsage: dbstor link check.\n"},
    {{"--query-fs-info", "*[PARAM]"}, dbs_query_fs_info,
        "\tUsage: query the information for file system.\n"
        "\tparams: --fs-name=* --vstore_id=*"},
    {{"--perf-show", "*[PARAM]"}, dbs_perf_show,
        "\tUsage: show dbstor perf.\n"
        "\tparams: [--interval=*] [--times=*]"},
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
        printf("\n %s\n", cmd_def->desc);
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
        dbs_cmd_help(argc, argv);
        return CT_ERROR;
    }

    if (dbs_init_loggers() != CT_SUCCESS) {
        printf("dbs init loggers failed.\n");
        return CT_ERROR;
    }

    int32 ret = dbstool_init();
    if (ret != CT_SUCCESS) {
        printf("dbstool init failed(%d).\n.", ret);
        return ret;
    }
    ret = cmd_def->cmd_pro_func(argc, argv);
    if (ret != 0) {
        dbs_cmd_help(argc, argv);
        printf("Fail to execute command, ret is %d.\n", ret);
    }
    (void)dbs_global_handle()->dbs_client_flush_log();

    return ret;
}
