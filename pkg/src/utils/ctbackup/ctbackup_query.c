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
 * ctbackup_query.c
 *
 *
 * IDENTIFICATION
 * src/utils/ctbackup/ctbackup_query.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctbackup_module.h"
#include "ctbackup_query.h"
#include "ctbackup_info.h"
#include "ctbackup_common.h"

const struct option ctbak_query_options[] = {
    {CTBAK_LONG_OPTION_QUERY, no_argument, NULL, CTBAK_PARSE_OPTION_COMMON},
    {CTBAK_LONG_OPTION_TARGET_DIR, required_argument, NULL, CTBAK_SHORT_OPTION_TARGET_DIR},
    {0, 0, 0, 0}
};

status_t ctbak_parse_query_args(int32 argc, char** argv, ctbak_param_t* ctbak_param)
{
    int opt_s;
    int opt_index = 0;
    optind = 1;
    while (optind < argc) {
        CT_RETURN_IFERR(check_input_params(argv[optind]));
        opt_s = getopt_long(argc, argv, CTBAK_SHORT_OPTION_EXP, ctbak_query_options, &opt_index);
        if (opt_s == CTBAK_PARSE_OPTION_ERR) {
            break;
        }
        switch (opt_s) {
            case CTBAK_PARSE_OPTION_COMMON:
                break;
            case CTBAK_SHORT_OPTION_TARGET_DIR:
                CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->target_dir));
                break;
            case CTBAK_SHORT_OPTION_UNRECOGNIZED:
            case CTBAK_SHORT_OPTION_NO_ARG:
                printf("[ctbackup]Parse option arguments error!\n");
                return CT_ERROR;
            default:
                break;
        }
    }
    return CT_SUCCESS;
}

status_t ctbak_miner_parse_backup_info(const char *input_file, char **read_buf,
    uint32 buf_size, bak_head_t **bak_head)
{
    int32 read_size;
    int32 handle = CT_INVALID_HANDLE;

    if (cm_open_file(input_file, O_RDONLY | O_BINARY | O_SYNC, &handle) != CT_SUCCESS) {
        printf("[ctbackup] open file failed!");
        return CT_ERROR;
    }

    *bak_head = (bak_head_t *)(*read_buf);

    if (cm_read_file(handle, *read_buf, buf_size, &read_size) != CT_SUCCESS) {
        printf("[ctbackup] read file failed!");
        cm_close_file(handle);
        *bak_head = NULL;
        return CT_ERROR;
    }

    if ((uint32)read_size < sizeof(bak_head_t)) {
        printf("[ctbackup]read backupset is incomplete, expected %llu, but actually %llu.",
               (uint64)sizeof(bak_head_t), (uint64)read_size);
        cm_close_file(handle);
        *bak_head = NULL;
        return CT_ERROR;
    }

    cm_close_file(handle);
    return CT_SUCCESS;
}

status_t ctbak_do_query(ctbak_param_t* ctbak_param)
{
    if (check_common_params(ctbak_param) != CT_SUCCESS) {
        return CT_ERROR;
    }
    uint64_t len = strlen(ctbak_param->target_dir.str) + strlen(CANTIAN_BACKUP_DIR) +
                   strlen(CANTIAN_BACKUP_BACKUPSET) + 1;
    if (len > CANTIAN_BACKUP_FILE_LENGTH) {
        printf("[ctbackup]The requested memory size is wrong in fill params for cantian query, please check!\n");
        return CT_ERROR;
    }
    char ct_backup_dir[CANTIAN_BACKUP_FILE_LENGTH] = {0};
    memset_s(ct_backup_dir, CANTIAN_BACKUP_FILE_LENGTH, 0, CANTIAN_BACKUP_FILE_LENGTH);
    errno_t ret = snprintf_s((char *)ct_backup_dir, len, len - 1, "%s%s%s", ctbak_param->target_dir.str,
                             CANTIAN_BACKUP_DIR, CANTIAN_BACKUP_BACKUPSET);
    if (ret == -1) {
        printf("[ctbackup]failed to concatenate strs for ct_backup_dir!\n");
        return CT_ERROR;
    }
    if (cm_access_file((const char *)ct_backup_dir, F_OK) != CT_SUCCESS) {
        printf("[ctbackup]the backupset file not exist!\n");
        return CT_ERROR;
    }
    char *read_buf = (char *)malloc(CT_BACKUP_BUFFER_SIZE);
    bak_head_t *bak_head = NULL;
    status_t status = ctbak_miner_parse_backup_info(ct_backup_dir, &read_buf, CT_BACKUP_BUFFER_SIZE, &bak_head);
    if (status != CT_SUCCESS) {
        CM_FREE_PTR(read_buf);
        printf("[ctbackup]cantian query_incremental_mode failed!\n");
        return CT_ERROR;
    }
    if (bak_head->attr.level == 0) {
        printf("[ctbackup]the backupset is full backup!\n");
    } else {
        printf("[ctbackup]Incrementalmode：[%s].\n", bak_head->attr.backup_type ==
                BACKUP_MODE_INCREMENTAL ? "difference" : "cumulative");
    }
    CM_FREE_PTR(read_buf);
    printf("[ctbackup]cantian query_incremental_mode success.\n");
    return CT_SUCCESS;
}

ctbak_cmd_t *ctbak_generate_query_incremental_mode_cmd(void)
{
    ctbak_cmd_t* ctbak_cmd = (ctbak_cmd_t*)malloc(sizeof(ctbak_cmd_t));
    if (ctbak_cmd == NULL) {
        printf("[ctbackup]failed to malloc memory for reconciel-mysql ctbak_cmd!\n");
        return (ctbak_cmd_t *)NULL;
    }
    ctbak_cmd->parse_args = ctbak_parse_query_args;
    ctbak_cmd->do_exec = ctbak_do_query;
    return ctbak_cmd;
}
