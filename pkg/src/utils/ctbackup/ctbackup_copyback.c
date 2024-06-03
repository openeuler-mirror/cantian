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
 * ctbackup_copyback.c
 *
 *
 * IDENTIFICATION
 * src/utils/ctbackup/ctbackup_copyback.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctbackup_module.h"
#include "ctbackup_copyback.h"
#include "ctbackup_info.h"
#include "ctbackup_common.h"

#define CTBACKUP_COPY_BACK_RETRY_TIME 1
#define CTBACKUP_COPY_BACK_RETRY_WAIT_TIMEOUT 2

const struct option ctbak_copyback_options[] = {
    {CTBAK_LONG_OPTION_COPYBACK, no_argument, NULL, CTBAK_PARSE_OPTION_COMMON},
    {CTBAK_LONG_OPTION_TARGET_DIR, required_argument, NULL, CTBAK_SHORT_OPTION_TARGET_DIR},
    {CTBAK_LONG_OPTION_DEFAULTS_FILE, required_argument, NULL, CTBAK_SHORT_OPTION_DEFAULTS_FILE},
    {CTBAK_LONG_OPTION_DATA_DIR, required_argument, NULL, CTBAK_SHORT_OPTION_DATA_DIR},
    {CTBAK_LONG_OPTION_PARALLEL, required_argument, NULL, CTBAK_SHORT_OPTION_PARALLEL},
    {0, 0, 0, 0}
};

status_t ctbak_parse_copyback_args(int32 argc, char** argv, ctbak_param_t* ctbak_param)
{
    int opt_s;
    int opt_index;
    optind = 1;
    while (optind < argc) {
        CT_RETURN_IFERR(check_input_params(argv[optind]));
        opt_s = getopt_long(argc, argv, CTBAK_SHORT_OPTION_EXP, ctbak_copyback_options, &opt_index);
        if (opt_s == CTBAK_PARSE_OPTION_ERR) {
            break;
        }
        switch (opt_s) {
            case CTBAK_PARSE_OPTION_COMMON:
                break;
            case CTBAK_SHORT_OPTION_TARGET_DIR:
                if (optarg != NULL) {
                    CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->target_dir));
                }
                break;
            case CTBAK_SHORT_OPTION_DEFAULTS_FILE:
                if (optarg != NULL) {
                    CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->defaults_file));
                }
                break;
            case CTBAK_SHORT_OPTION_DATA_DIR:
                if (optarg != NULL) {
                    CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->data_dir));
                }
                break;
            case CTBAK_SHORT_OPTION_PARALLEL:
                if (optarg != NULL) {
                    CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->parallelism));
                }
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

status_t fill_params_for_mysql_copyback(ctbak_param_t* ctbak_param, char *params[], int *index)
{
    // The first parameter should be the application name itself
    params[0] = MYSQL_BACKUP_TOOL_NAME;
    // If the parameter --defaults-file is not null, it must be the first of the valid parameters
    if (ctbak_param->defaults_file.str != NULL) {
        CT_RETURN_IFERR(set_mysql_param_value(params, ctbak_param->defaults_file,
                                              DEFAULTS_FILE_PARAM_OPTION, (*index)++));
    }
    // The parameter is the action "--copy-back"
    text_t temp = {NULL, 0};
    CT_RETURN_IFERR(set_mysql_param_value(params, temp, CTBAK_ARG_COPYBACK, (*index)++));
   
    if (ctbak_param->data_dir.str != NULL) {
        CT_RETURN_IFERR(set_mysql_param_value(params, ctbak_param->data_dir, DATA_DIR_PARAM_OPRION, (*index)++));
    }

    if (ctbak_param->parallelism.str != NULL) {
        CT_RETURN_IFERR(set_mysql_param_value(params, ctbak_param->parallelism, PARALLEL_PARAM_OPTION, (*index)++));
    }

    CT_RETURN_IFERR(set_mysql_param_value(params, ctbak_param->target_dir, TARGET_DIR_PARAM_OPTION, (*index)++));
    // The last parameter must be NULL
    params[*index] = NULL;
    return CT_SUCCESS;
}

/**
 * 1. decode params for mysql copyback
 * 2. xtrabackup execute copyback for mysql
 * @param ctbak_param
 * @return
 */

status_t ctbak_do_copyback_for_mysql(ctbak_param_t* ctbak_param)
{
    status_t status;
    int index = START_INDEX_FOR_PARSE_PARAM;
    uint32 retry_times = 0;
    if (check_common_params(ctbak_param) != CT_SUCCESS) {
        return CT_ERROR;
    }
    printf("[ctbackup]ready to execute copyback for mysql!\n");
    char *params[CTBACKUP_MAX_PARAMETER_CNT] = {0};
    status = fill_params_for_mysql_copyback(ctbak_param, params, &index);
    if (status != CT_SUCCESS) {
        printf("[ctbackup]fill_params_for_mysql_copyback failed!\n");
        return CT_ERROR;
    }
    if (ctbak_check_data_dir(ctbak_param->data_dir.str) != CT_SUCCESS) {
        printf("[ctbackup]check datadir failed!\n");
        free_input_params(ctbak_param);
        return CT_ERROR;
    }
    // copyback retry for the file creation failure may caused by NFS network delay or packet loss in xtrabackup.
    while (CT_TRUE) {
        status = ctbak_system_call(XTRABACKUP_PATH, params, "mysql copyback");
        if (status == CT_SUCCESS || retry_times == CTBACKUP_COPY_BACK_RETRY_TIME) {
            break;
        }
        if (ctbak_clear_data_dir(ctbak_param->data_dir.str, ctbak_param->data_dir.str) != CT_SUCCESS) {
            printf("[ctbackup]clear datadir %s failed for copyback retry!\n", ctbak_param->data_dir.str);
            break;
        }
        retry_times++;
        sleep(CTBACKUP_COPY_BACK_RETRY_WAIT_TIMEOUT);
        printf("[ctbackup]copyback retry, retry_times: %u!\n", retry_times);
    };

    free_input_params(ctbak_param);
    free_system_call_params(params, START_INDEX_FOR_PARSE_PARAM, index);
    if (status != CT_SUCCESS) {
        printf("[ctbackup]xtrabackup execute copyback for mysql failed!\n");
        return CT_ERROR;
    }
    printf("[ctbackup]xtrabackup execute copyback for mysql success!\n");

    return CT_SUCCESS;
}

/**
 * 1. decode params for mysql copyback
 * 2. xtrabackup execute copyback for mysql
 * @param ctbak_param
 * @return
 */
status_t ctbak_do_copyback(ctbak_param_t* ctbak_param)
{
    if (ctbackup_set_metadata_mode(ctbak_param) != CT_SUCCESS) {
        free_input_params(ctbak_param);
        return CT_ERROR;
    }
    if (ctbak_param->is_mysql_metadata_in_cantian == CT_TRUE) {
        printf("[ctbackup]no need to do copyback for mysql in mysql_metadata_in_cantian mode\n");
    } else if (ctbak_do_copyback_for_mysql(ctbak_param) != CT_SUCCESS) {
        free_input_params(ctbak_param);
        return CT_ERROR;
    }
    free_input_params(ctbak_param);
    return CT_SUCCESS;
}

ctbak_cmd_t *ctbak_generate_copyback_cmd(void)
{
    ctbak_cmd_t* ctbak_cmd = (ctbak_cmd_t*)malloc(sizeof(ctbak_cmd_t));
    if (ctbak_cmd == NULL) {
        printf("[ctbackup]failed to malloc memory for copyback ctbak_cmd!\n");
        return (ctbak_cmd_t *)NULL;
    }
    ctbak_cmd->parse_args = ctbak_parse_copyback_args;
    ctbak_cmd->do_exec = ctbak_do_copyback;
    return ctbak_cmd;
};
