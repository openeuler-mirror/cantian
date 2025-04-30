/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2025 Huawei Technologies Co.,Ltd.
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
 * ctbackup_snapshot_delete.c
 *
 *
 * IDENTIFICATION
 * src/utils/ctbackup/ctbackup_snapshot_delete.c
 *
 * -------------------------------------------------------------------------
 */

#include "ctbackup_snapshot_delete.h"
#include "ctbackup_common.h"

const struct option ctbak_delete_snapshot_options[] = {
    {CTBAK_LONG_OPTION_DELETE_SNAPSHOT, no_argument, NULL, CTBAK_PARSE_OPTION_DELETE_SNAPSHOT},
    {CTBAK_LONG_OPTION_FS_NAME, required_argument, NULL, CTBAK_SHORT_OPTION_FS_NAME},
    {CTBAK_LONG_OPTION_SNAPSHOT_NAME, required_argument, NULL, CTBAK_SHORT_OPTION_SNAPSHOT_NAME},
    {0, 0, 0, 0}
};

static status_t ctbak_check_fs_name(ctbak_param_t* ctbak_param, uint32_t* fs_vstore_id)
{
    // Check if the fs name is valid
    if (strcmp(ctbak_param->fs_name.str, ctbak_param->page_fs_name.str) == 0) {
        cm_text2uint32(&ctbak_param->page_fs_vstore_id, fs_vstore_id);
        return CT_SUCCESS;
    }
    if (strcmp(ctbak_param->fs_name.str, ctbak_param->log_fs_name.str) == 0) {
        cm_text2uint32(&ctbak_param->log_fs_vstore_id, fs_vstore_id);
        return CT_SUCCESS;
    }
    if (strcmp(ctbak_param->fs_name.str, ctbak_param->archive_fs_name.str) == 0) {
        cm_text2uint32(&ctbak_param->archive_fs_vstore_id, fs_vstore_id);
        return CT_SUCCESS;
    }
    return CT_ERROR;
}

static status_t ctbak_delete_fs_snapshot(ctbak_param_t* ctbak_param)
{

    // Check the file system is valid
    uint32_t fs_vstore_id = 0;
    if (ctbak_check_fs_name(ctbak_param, &fs_vstore_id)!= CT_SUCCESS) {
        printf("[ctbackup]Invalid fs name!\n");
        return CT_ERROR;
    }

    // TODO: Check if the snapshot exists

    // Delete the snapshot
    printf("[ctbackup]Start to delete snapshot %s on fs %s\n", ctbak_param->snapshot_name.str, ctbak_param->fs_name.str);
    snapshot_result_info fs_snap_info = { 0 };
    errno_t err;
    err = strcpy_s(fs_snap_info.snapName, CSS_MAX_FSNAME_LEN, ctbak_param->snapshot_name.str);
    if (err != EOK) {
        printf("[ctbackup]Failed to copy snapshot name!\n");
        return CT_ERROR;
    }
    if (dbs_delete_fs_snap(ctbak_param->fs_name.str, fs_vstore_id, &fs_snap_info) != CT_SUCCESS) {
        printf("[ctbackup]Failed to delete snapshot %s on fs %s!\n", ctbak_param->snapshot_name.str, ctbak_param->fs_name.str);
        return CT_ERROR;
    }

    printf("[ctbackup]Successfully deleted snapshot %s on fs %s!\n", ctbak_param->snapshot_name.str, ctbak_param->fs_name.str);
    return CT_SUCCESS;
}

status_t ctbak_parse_delete_snapshot_args(int32 argc, char** argv, ctbak_param_t* ctbak_param)
{
    int opt_s;
    int opt_index;
    optind = 1;
    while (optind < argc) {
        CT_RETURN_IFERR(check_input_params(argv[optind]));
        opt_s = getopt_long(argc, argv, CTBAK_SHORT_OPTION_EXP, ctbak_delete_snapshot_options, &opt_index);
        if (opt_s == CTBAK_PARSE_OPTION_ERR) {
            break;
        }
        switch (opt_s) {
            case CTBAK_PARSE_OPTION_DELETE_SNAPSHOT:
                break;
            case CTBAK_SHORT_OPTION_FS_NAME:
                CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->fs_name));
                break;
            case CTBAK_SHORT_OPTION_SNAPSHOT_NAME:
                CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->snapshot_name));
                break;
            case CTBAK_SHORT_OPTION_UNRECOGNIZED:
            case CTBAK_SHORT_OPTION_NO_ARG:
                printf("[ctbackup]Parse option arguments of delete snapshot error!\n");
                return CT_ERROR;
            default:
                break;
        }
    }
    return CT_SUCCESS;
}

status_t ctbak_do_delete_snapshot(ctbak_param_t* ctbak_param)
{
    printf("[ctbackup]Process ctbak_do_delete_snapshot\n");

    if (ctbak_param->fs_name.str == NULL || ctbak_param->snapshot_name.str == NULL) {
        printf("[ctbackup]The parameters --fs_name and --snapshot_name cannot be empty!\n");
        return CT_ERROR;
    }

    if (dbs_init(ctbak_param) != CT_SUCCESS) {
        printf("[ctbackup]Dbstor init failed!\n");
        return CT_ERROR;
    }

    if (ctbak_delete_fs_snapshot(ctbak_param) != CT_SUCCESS) {
        printf("[ctbackup]Failed to delete snapshot!\n");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

ctbak_cmd_t *ctbak_generate_delete_snapshot_cmd(void)
{
    ctbak_cmd_t* ctbak_cmd = (ctbak_cmd_t*)malloc(sizeof(ctbak_cmd_t));
    if (ctbak_cmd == NULL) {
        printf("[ctbackup]Failed to malloc memory for delete snapshot ctbak_cmd!\n");
        return (ctbak_cmd_t *)NULL;
    }
    printf("[ctbackup]Process delete snapshot command\n");
    ctbak_cmd->do_exec = ctbak_do_delete_snapshot;
    ctbak_cmd->parse_args = ctbak_parse_delete_snapshot_args;
    return ctbak_cmd;
} 