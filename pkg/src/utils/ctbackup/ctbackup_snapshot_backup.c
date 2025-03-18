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
* src/utils/ctbackup/ctbackup_snapshot_backup.c
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
#include "ctbackup_snapshot_backup.h"
#include "ctbackup_snapshot_backup_operator.h"

typedef struct st_snap_bak_context {
    object_id_t *snapshot_info_file_handle;
} snap_bak_context_t;

const struct option ctbak_snapshot_backup_options[] = {
    {CTBAK_LONG_OPTION_SNAPSHOT_BACKUP, no_argument, NULL, CTBAK_PARSE_OPTION_SNAPSHOT_BACKUP},
    {CTBAK_LONG_OPTION_NOTDELETE, no_argument, NULL, CTBAK_SHORT_OPTION_NOTDELETE},
    {CTBAK_LONG_OPTION_TARGET_DIR, required_argument, NULL, CTBAK_SHORT_OPTION_TARGET_DIR},
    {CTBAK_LONG_OPTION_INCREMENTAL, no_argument, NULL, CTBAK_SHORT_OPTION_INCREMENTAL},
    {CTBAK_LONG_OPTION_INCREMENTAL_CUMULATIVE, no_argument, NULL, CTBAK_SHORT_OPTION_INCREMENTAL_CUMULATIVE},
    {CTBAK_LONG_OPTION_PARALLEL, required_argument, NULL, CTBAK_SHORT_OPTION_PARALLEL},
    {0, 0, 0, 0}
};

status_t ctbak_parse_snapshot_backup_args(int32 argc, char** argv, ctbak_param_t* ctbak_param)
{
    int opt_s;
    int opt_index;
    optind = 1;
    while (optind < argc) {
        CT_RETURN_IFERR(check_input_params(argv[optind]));
        opt_s = getopt_long(argc, argv, CTBAK_SHORT_OPTION_EXP, ctbak_snapshot_backup_options, &opt_index);
        if (opt_s == CTBAK_PARSE_OPTION_ERR) {
            break;
        }
        switch (opt_s) {
            case CTBAK_PARSE_OPTION_SNAPSHOT_BACKUP:
                ctbak_param->is_snapshot = CT_FALSE;
                ctbak_param->is_snapshot_backup = CT_TRUE;
                break;
            case CTBAK_SHORT_OPTION_NOTDELETE:
                ctbak_param->is_notdelete = CT_TRUE;
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
                printf("[ctbackup]Parse option arguments of snapshot backup error!\n");
                return CT_ERROR;
            default:
                break;
        }
    }
    return CT_SUCCESS;
}

static status_t ctbak_read_snapshot_info_file(snapshot_backup_info_t *snapshot_backup_info) {
    object_id_t file_handle;
    status_t ret = ctbak_get_file_handle_from_share_fs("/share/backup", "snap_info", &file_handle);
    if (ret != CT_SUCCESS) {
        printf("[ctbackup]get file handle from share_fs failed!\n");
        return CT_ERROR;
    }

    ret = dbs_read_snapshot_info_file(&file_handle, 0, snapshot_backup_info, sizeof(snapshot_backup_info_t));
    if (ret!= CT_SUCCESS) {
        printf("[ctbackup]read snapshot info file failed!\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t ctbak_delete_snapshot(ctbak_param_t* ctbak_param)
{
    uint32_t page_fs_vstore_id = 0;
    uint32_t log_fs_vstore_id = 0;
    cm_text2uint32(&ctbak_param->page_fs_vstore_id, &page_fs_vstore_id);
    cm_text2uint32(&ctbak_param->log_fs_vstore_id, &log_fs_vstore_id);
    snapshot_backup_info_t snapshot_backup_info = {0};
    if (ctbak_read_snapshot_info_file(&snapshot_backup_info)!= CT_SUCCESS) {
        printf("[ctbackup]Failed to read snapshot info file!\n");
        return CT_ERROR;
    }
    if (dbs_delete_fs_snap(ctbak_param->page_fs_name.str, page_fs_vstore_id, &snapshot_backup_info.page_fs_snap_info) != CT_SUCCESS) {
        printf("[ctbackup]Failed to delete page fs snapshot!\n");
        return CT_ERROR;
    }
    if (dbs_delete_fs_snap(ctbak_param->log_fs_name.str, log_fs_vstore_id, &snapshot_backup_info.log_fs_snap_info)!= CT_SUCCESS) {
        printf("[ctbackup]Failed to delete log fs snapshot!\n");
        return CT_ERROR;
    }
    if (dbs_delete_fs_snap(ctbak_param->archive_fs_name.str, log_fs_vstore_id, &snapshot_backup_info.archive_fs_snap_info)!= CT_SUCCESS) {
        printf("[ctbackup]Failed to delete archive fs snapshot!\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t ctbak_do_snapshot_backup(ctbak_param_t* ctbak_param)
{
    printf("[ctbackup]process ctbak_do_snapshot_backup\n");
    if (check_common_params(ctbak_param) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (dbs_init(ctbak_param) != CT_SUCCESS) {
        printf("[ctbackup]dbstor init failed!\n");
        return CT_ERROR;
    }

    if (do_snapshot_backup(ctbak_param)!= CT_SUCCESS) {
        printf("[ctbackup]snapshot backup failed!\n");
        return CT_ERROR;
    }

    // 删除未标记notdelete的快照
    if (ctbak_param->is_notdelete == CT_FALSE) {
        printf("[ctbackup]Start delete snapshot\n");
        if (ctbak_delete_snapshot(ctbak_param)!= CT_SUCCESS) {
            printf("[ctbackup]Delete snapshot failed!\n");
        }
        printf("[ctbackup]Delete snapshot success!\n");
    }
    printf("[ctbackup]snapshot backup finished\n");
    return CT_SUCCESS;

}

ctbak_cmd_t *ctbak_generate_snapshot_backup_cmd(void)
{
    ctbak_cmd_t* ctbak_cmd = (ctbak_cmd_t*)malloc(sizeof(ctbak_cmd_t));
    if (ctbak_cmd == NULL) {
        printf("[ctbackup]failed to malloc memory for snapshot backup ctbak_cmd!\n");
        return (ctbak_cmd_t *)NULL;
    }
    printf("[ctbackup]process ctbak_generate_snapshot_backup_cmd\n");
    ctbak_cmd->do_exec = ctbak_do_snapshot_backup;
    ctbak_cmd->parse_args = ctbak_parse_snapshot_backup_args;
    return ctbak_cmd;
}
