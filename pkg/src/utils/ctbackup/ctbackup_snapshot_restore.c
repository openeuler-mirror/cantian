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
* src/utils/ctbackup/ctbackup_snapshot_restore.c
*
* -------------------------------------------------------------------------
 */
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <signal.h>
#include "ctbackup.h"
#include "ctbackup_common.h"
#include "unistd.h"
#include "cm_file.h"
#include "ctbackup_mysql_operator.h"
#include "cm_defs.h"
#include "ctbackup_module.h"
#include "ctbackup_dbs_common.h"
#include "ctbackup_snapshot_restore.h"
#include "ctbackup_snapshot_restore_operator.h"

const struct option ctbak_snapshot_restore_options[] = {
    {CTBAK_LONG_OPTION_SNAPSHOT_RESTORE, no_argument, NULL, CTBAK_PARSE_OPTION_SNAPSHOT_RESTORE},
    {CTBAK_LONG_OPTION_TARGET_DIR, required_argument, NULL, CTBAK_SHORT_OPTION_TARGET_DIR},
    {CTBAK_LONG_OPTION_INCREMENTAL, no_argument, NULL, CTBAK_SHORT_OPTION_INCREMENTAL},
    {CTBAK_LONG_OPTION_INCREMENTAL_CUMULATIVE, no_argument, NULL, CTBAK_SHORT_OPTION_INCREMENTAL_CUMULATIVE},
    {CTBAK_LONG_OPTION_PARALLEL, required_argument, NULL, CTBAK_SHORT_OPTION_PARALLEL},
    {0, 0, 0, 0}
};

status_t ctbak_parse_snapshot_restore_args(int32 argc, char** argv, ctbak_param_t* ctbak_param)
{
    int opt_s;
    int opt_index;
    optind = 1;
    while (optind < argc) {
        CT_RETURN_IFERR(check_input_params(argv[optind]));
        opt_s = getopt_long(argc, argv, CTBAK_SHORT_OPTION_EXP, ctbak_snapshot_restore_options, &opt_index);
        if (opt_s == CTBAK_PARSE_OPTION_ERR) {
            break;
        }
        switch (opt_s) {
            case CTBAK_PARSE_OPTION_SNAPSHOT_RESTORE:
                break;
            case CTBAK_SHORT_OPTION_TARGET_DIR:
                CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->target_dir));
                break;
            case CTBAK_SHORT_OPTION_INCREMENTAL:
                ctbak_param->is_incremental = CT_TRUE;
                break;
            case CTBAK_SHORT_OPTION_INCREMENTAL_CUMULATIVE:
                ctbak_param->is_incremental_cumulative = CT_TRUE;
                break;
            case CTBAK_SHORT_OPTION_PARALLEL:
                CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->parallelism));
                break;
            case CTBAK_SHORT_OPTION_UNRECOGNIZED:
            case CTBAK_SHORT_OPTION_NO_ARG:
                printf("[ctbackup]Parse option arguments of snapshot restore error!\n");
                return CT_ERROR;
            default:
                break;
        }
    }
    return CT_SUCCESS;
}

status_t ctbak_do_snapshot_restore(ctbak_param_t* ctbak_param)
{
    printf("[ctbackup]process ctbak_do_snapshot_restore\n");
    if (check_common_params(ctbak_param) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (dbs_init(ctbak_param) != CT_SUCCESS) {
        printf("[ctbackup]dbstor init failed!\n");
        return CT_ERROR;
    }

    if (do_snapshot_restore(ctbak_param) != CT_SUCCESS) {
        printf("[ctbackup]snapshot restore failed!\n");
        return CT_ERROR;
    }

    printf("[ctbackup]snapshot restore success!\n");
    printf("[ctbackup]snapshot restore finished\n");
    return CT_SUCCESS;
}

ctbak_cmd_t *ctbak_generate_snapshot_restore_cmd(void)
{
    ctbak_cmd_t* ctbak_cmd = (ctbak_cmd_t*)malloc(sizeof(ctbak_cmd_t));
    if (ctbak_cmd == NULL) {
        printf("[ctbackup]failed to malloc memory for snapshot restore ctbak_cmd!\n");
        return (ctbak_cmd_t *)NULL;
    }
    printf("[ctbackup]process ctbak_generate_snapshot_restore_cmd\n");
    ctbak_cmd->do_exec = ctbak_do_snapshot_restore;
    ctbak_cmd->parse_args = ctbak_parse_snapshot_restore_args;
    return ctbak_cmd;
}