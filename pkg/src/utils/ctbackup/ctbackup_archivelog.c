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
 * ctbackup_archivelog.c
 *
 *
 * IDENTIFICATION
 * src/utils/ctbackup/ctbackup_archivelog.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctbackup_module.h"
#include "ctbackup_archivelog.h"
#include "ctbackup_info.h"
#include "ctbackup_common.h"

const struct option ctbak_archivelog_options[] = {
    {CTBAK_LONG_OPTION_ARCHIVELOG, no_argument, NULL, CTBAK_PARSE_OPTION_COMMON},
    {CTBAK_LONG_OPTION_LRP_LSN, no_argument, NULL, CTBAK_SHORT_OPTION_LRP_LSN},
    {CTBAK_LONG_OPTION_FORCE, no_argument, NULL, CTBAK_SHORT_OPTION_FORCE},
    {0, 0, 0, 0}
};

status_t ctbak_parse_archivelog_args(int32 argc, char** argv, ctbak_param_t* ctbak_param)
{
    int opt_s;
    int opt_index = 0;
    optind = 1;
    while (optind < argc) {
        CT_RETURN_IFERR(check_input_params(argv[optind]));
        opt_s = getopt_long(argc, argv, CTBAK_SHORT_OPTION_EXP, ctbak_archivelog_options, &opt_index);
        if (opt_s == CTBAK_PARSE_OPTION_ERR) {
            break;
        }
        switch (opt_s) {
            case CTBAK_PARSE_OPTION_COMMON:
                break;
            case CTBAK_SHORT_OPTION_LRP_LSN:
                ctbak_param->is_get_lrp = CT_TRUE;
                break;
            case CTBAK_SHORT_OPTION_FORCE:
                ctbak_param->is_force_archive = CT_TRUE;
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

status_t ctbak_do_force_archive(char *ct_params[], char *ctsql_binary_path)
{
    status_t status;
    if (check_cantiand_status() != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (start_cantiand_server() != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (ctbak_check_ctsql_online(CTSQL_CHECK_CONN_MAX_TIME_S) != CT_SUCCESS) {
        return CT_ERROR;
    }

    status = ctbak_system_call(ctsql_binary_path, ct_params, "cantian force archive log");
    CT_RETURN_IFERR(stop_cantiand_server());
    if (status != CT_SUCCESS) {
        printf("[ctbackup]cantian force archive log failed!\n");
        return CT_ERROR;
    }
    printf("[ctbackup]cantian force archive log success\n");
    return CT_SUCCESS;
}

/**
 * 1. ctsql execute ALTER DATABASE ARCHIVELOG
 * @param ctbak_param
 * @return
 */
status_t ctbak_do_archivelog(ctbak_param_t* ctbak_param)
{
    status_t status;
    char *ct_params[CTBACKUP_MAX_PARAMETER_CNT] = {0};
    if (ctbak_param->is_get_lrp == CT_TRUE && ctbak_param->is_force_archive == CT_TRUE) {
        printf("[ctbackup]--lrp-lsn and --force can not be specified at the same time.\n");
        return CT_ERROR;
    }
    printf("[ctbackup]ready to archive log for cantian!\n");
    status = fill_params_for_cantian_archive_log(ctbak_param, ct_params);
    if (status != CT_SUCCESS) {
        printf("[ctbackup]fill_params_for_cantian_archive_log failed!\n");
        return CT_ERROR;
    }
    
    char *ctsql_binary_path = NULL;
    if (get_ctsql_binary_path(&ctsql_binary_path) != CT_SUCCESS) {
        CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
        CM_FREE_PTR(ct_params[CTSQL_STATEMENT_INDEX]);
        return CT_ERROR;
    }

    if (ctbak_param->is_force_archive == CT_TRUE) {
        status = ctbak_do_force_archive(ct_params, ctsql_binary_path);
        CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
        CM_FREE_PTR(ct_params[CTSQL_STATEMENT_INDEX]);
        CM_FREE_PTR(ctsql_binary_path);
        return status;
    }

    status = ctbak_system_call(ctsql_binary_path, ct_params, "cantian archive log");
    // free space of heap
    CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
    CM_FREE_PTR(ct_params[CTSQL_STATEMENT_INDEX]);
    CM_FREE_PTR(ctsql_binary_path);
    if (status != CT_SUCCESS) {
        printf("[ctbackup]cantian archive log failed!\n");
        return CT_ERROR;
    }

    printf("[ctbackup]cantian archive log success\n");
    return CT_SUCCESS;
}

status_t fill_params_for_cantian_archive_log(ctbak_param_t* ctbak_param, char *ct_params[])
{
    int param_index = 0;
    uint64_t len;
    errno_t ret;
    if (fill_params_for_ctsql_login(ct_params, &param_index, CTBAK_CTSQL_EXECV_MODE) != CT_SUCCESS) {
        printf("[ctbackup]failed to fill params for ctsql login!\n");
        return CT_ERROR;
    }
    if (ctbak_param->is_get_lrp == CT_TRUE) {
        len = strlen(CTSQL_GET_LRP_LSN_STATEMENT) + strlen(CTSQL_STATEMENT_END_CHARACTER) + 1;
    } else {
        len = strlen(CTSQL_ARCHIVELOG_STATEMENT_PREFIX) + strlen(CTSQL_STATEMENT_END_CHARACTER) + 1;
    }
    // stetement not free here
    char *statement = (char *)malloc(len);
    if (statement == NULL) {
        CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
        printf("[ctbackup]failed to apply storage for archive log!\n");
        CTBAK_RETURN_ERROR_IF_NULL(statement);
    }

    if (ctbak_param->is_get_lrp == CT_TRUE) {
        ret = snprintf_s(statement, len, len - 1, "%s%s", CTSQL_GET_LRP_LSN_STATEMENT, CTSQL_STATEMENT_END_CHARACTER);
    } else {
        ret = snprintf_s(statement, len, len - 1, "%s%s",
                         CTSQL_ARCHIVELOG_STATEMENT_PREFIX, CTSQL_STATEMENT_END_CHARACTER);
    }
    
    if (ret == -1) {
        CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
        CM_FREE_PTR(statement);
        printf("[ctbackup]failed to concatenate strs for archive log!\n");
        return CT_ERROR;
    }
    ct_params[param_index++] = statement;
    // The last parameter must be NULL
    ct_params[param_index++] = NULL;
    return CT_SUCCESS;
}

ctbak_cmd_t *ctbak_generate_archivelog_cmd(void)
{
    ctbak_cmd_t* ctbak_cmd = (ctbak_cmd_t*)malloc(sizeof(ctbak_cmd_t));
    if (ctbak_cmd == NULL) {
        printf("[ctbackup]failed to malloc memory for archivelog ctbak_cmd!\n");
        return (ctbak_cmd_t *)NULL;
    }
    ctbak_cmd->parse_args = ctbak_parse_archivelog_args;
    ctbak_cmd->do_exec = ctbak_do_archivelog;
    return ctbak_cmd;
};
