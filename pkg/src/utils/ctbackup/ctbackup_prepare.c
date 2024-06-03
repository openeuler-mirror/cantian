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
 * ctbackup_prepare.c
 *
 *
 * IDENTIFICATION
 * src/utils/ctbackup/ctbackup_prepare.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctbackup_module.h"
#include "ctbackup_prepare.h"
#include "ctbackup_info.h"
#include "ctbackup_common.h"
#include "cm_file.h"

const struct option ctbak_prepare_options[] = {
    {CTBAK_LONG_OPTION_PREPARE, no_argument, NULL, CTBAK_PARSE_OPTION_COMMON},
    {CTBAK_LONG_OPTION_TARGET_DIR, required_argument, NULL, CTBAK_SHORT_OPTION_TARGET_DIR},
    {CTBAK_LONG_OPTION_PARALLEL, required_argument, NULL, CTBAK_SHORT_OPTION_PARALLEL},
    {CTBAK_LONG_OPTION_DECOMPRESS, no_argument, NULL, CTBAK_SHORT_OPTION_DECOMPRESS},
    {CTBAK_LONG_OPTION_BUFFER, required_argument, NULL, CTBAK_SHORT_OPTION_BUFFER},
    {CTBAK_LONG_OPTION_PITR_TIME, required_argument, NULL, CTBAK_SHORT_OPTION_PITR_TIME},
    {CTBAK_LONG_OPTION_PITR_SCN, required_argument, NULL, CTBAK_SHORT_OPTION_PITR_SCN},
    {CTBAK_LONG_OPTION_PITR_CANCEL, no_argument, NULL, CTBAK_SHORT_OPTION_PITR_CANCEL},
    {CTBAK_LONG_OPTION_PITR_RESTORE, no_argument, NULL, CTBAK_SHORT_OPTION_PITR_RESTORE},
    {CTBAK_LONG_OPTION_PITR_RECOVER, no_argument, NULL, CTBAK_SHORT_OPTION_PITR_RECOVER},
    {CTBAK_LONG_OPTION_REPAIR_TYPE, required_argument, NULL, CTBAK_SHORT_OPTION_REPAIR_TYPE},
    {0, 0, 0, 0}
};

status_t ctbak_parse_prepare_args(int32 argc, char** argv, ctbak_param_t* ctbak_param)
{
    int opt_s;
    int opt_index;
    optind = 1;
    while (optind < argc) {
        CT_RETURN_IFERR(check_input_params(argv[optind]));
        opt_s = getopt_long(argc, argv, CTBAK_SHORT_OPTION_EXP, ctbak_prepare_options, &opt_index);
        if (opt_s == CTBAK_PARSE_OPTION_ERR) {
            break;
        }
        switch (opt_s) {
            case CTBAK_PARSE_OPTION_COMMON:
                break;
            case CTBAK_SHORT_OPTION_TARGET_DIR:
                CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->target_dir));
                break;
            case CTBAK_SHORT_OPTION_PARALLEL:
                CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->parallelism));
                break;
            case CTBAK_SHORT_OPTION_DECOMPRESS:
                ctbak_param->is_decompress = CT_TRUE;
                break;
            case CTBAK_SHORT_OPTION_BUFFER:
                CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->buffer_size));
                break;
            case CTBAK_SHORT_OPTION_PITR_TIME:
                CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->pitr_time));
                break;
            case CTBAK_SHORT_OPTION_PITR_SCN:
                CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->pitr_scn));
                break;
            case CTBAK_SHORT_OPTION_PITR_CANCEL:
                ctbak_param->is_pitr_cancel = CT_TRUE;
                break;
            case CTBAK_SHORT_OPTION_PITR_RESTORE:
                ctbak_param->is_restore = CT_TRUE;
                break;
            case CTBAK_SHORT_OPTION_PITR_RECOVER:
                ctbak_param->is_recover = CT_TRUE;
                break;
            case CTBAK_SHORT_OPTION_REPAIR_TYPE:
                CT_RETURN_IFERR(ctbak_parse_single_arg(optarg, &ctbak_param->repair_type));
                break;
            case CTBAK_SHORT_OPTION_UNRECOGNIZED:
            case CTBAK_SHORT_OPTION_NO_ARG:
                printf("[ctbackup]Parse option arguments of prepare failed!\n");
                return CT_ERROR;
            default:
                break;
        }
    }
    return CT_SUCCESS;
}

status_t fill_params_for_mysql_prepare_or_decompress(ctbak_param_t* ctbak_param, char *params[], char *action)
{
    uint64_t len;
    errno_t ret;
    int index = START_INDEX_FOR_PARSE_PARAM;
    // The first parameter should be the application name itself
    params[0] = MYSQL_BACKUP_TOOL_NAME;
    // action param --prepare or --decompress
    len = cm_str_equal(action, CTBAK_LONG_OPTION_DECOMPRESS) ?
                       strlen(CTBAK_ARG_DECOMPRESS) + 1 : strlen(CTBAK_ARG_PREPARE) + 1;
    params[index] = (char*)malloc(len);
    CTBAK_RETURN_ERROR_IF_NULL(params[index]);
    if (cm_str_equal(action, CTBAK_LONG_OPTION_DECOMPRESS)) {
        ret = strcpy_s(params[index], len, CTBAK_ARG_DECOMPRESS);
    } else {
        ret = strcpy_s(params[index], len, CTBAK_ARG_PREPARE);
    }

    if (ret != EOK) {
        free_system_call_params(params, START_INDEX_FOR_PARSE_PARAM, CTBACKUP_MAX_PARAMETER_CNT - 1);
        return CT_ERROR;
    }

    if (ctbak_param->parallelism.str != NULL) {
        CT_RETURN_IFERR(set_mysql_param_value(params, ctbak_param->parallelism, PARALLEL_PARAM_OPTION, ++index));
    }

    if (cm_str_equal(action, CTBAK_LONG_OPTION_DECOMPRESS)) {
        len = strlen(CTBAK_ARG_REMOVE_ORIGINAL) + 1;
        params[++index] = (char*)malloc(len);
        CTBAK_RETURN_ERROR_IF_NULL(params[index]);
        ret = strcpy_s(params[index], len, CTBAK_ARG_REMOVE_ORIGINAL);
        if (ret != EOK) {
            free_system_call_params(params, START_INDEX_FOR_PARSE_PARAM, CTBACKUP_MAX_PARAMETER_CNT - 1);
            return CT_ERROR;
        }
    }
    // target_dir param
    len = strlen(TARGET_DIR_PARAM_OPTION) + ctbak_param->target_dir.len + strlen(MYSQL_BACKUP_DIR) + 1;
    params[++index] = (char*)malloc(len);
    CTBAK_RETURN_ERROR_IF_NULL(params[index]);
    ret = snprintf_s(params[index], len, len - 1, "%s%s%s", TARGET_DIR_PARAM_OPTION,
                     ctbak_param->target_dir.str, MYSQL_BACKUP_DIR);
    if (ret == CT_ERROR) {
        free_system_call_params(params, START_INDEX_FOR_PARSE_PARAM, CTBACKUP_MAX_PARAMETER_CNT - 1);
        return CT_ERROR;
    }
    // The last parameter must be NULL
    params[++index] = NULL;
    return CT_SUCCESS;
}

status_t ctbak_do_decompress_for_mysql(ctbak_param_t* ctbak_param)
{
    status_t status;
    printf("[ctbackup]ready to execute decompress for mysql!\n");
    char *params[CTBACKUP_MAX_PARAMETER_CNT] = {0};
    status = fill_params_for_mysql_prepare_or_decompress(ctbak_param, params, "decompress");
    if (status != CT_SUCCESS) {
        printf("[ctbackup]fill_params_for_mysql_prepare_or_decompress for mysql decompress failed!\n");
        return CT_ERROR;
    }
    status = ctbak_system_call(XTRABACKUP_PATH, params, "mysql decompress");
    free_system_call_params(params, START_INDEX_FOR_PARSE_PARAM, CTBACKUP_MAX_PARAMETER_CNT - 1);
    if (status != CT_SUCCESS) {
        printf("[ctbackup]xtrabackup execute decompress for mysql failed!\n");
        return CT_ERROR;
    }
    printf("[ctbackup]xtrabackup execute decompress for mysql success!\n");
    return CT_SUCCESS;
}

status_t ctbak_do_prepare_for_mysql(ctbak_param_t* ctbak_param)
{
    status_t status;
    if (ctbak_param->is_decompress == CT_TRUE) {
        CT_RETURN_IFERR(ctbak_do_decompress_for_mysql(ctbak_param));
    }
    printf("[ctbackup]ready to execute prepare for mysql!\n");
    char *params[CTBACKUP_MAX_PARAMETER_CNT] = {0};
    status = fill_params_for_mysql_prepare_or_decompress(ctbak_param, params, "prepare");
    if (status != CT_SUCCESS) {
        printf("[ctbackup]fill_params_for_mysql_prepare_or_decompress for mysql prepare failed!\n");
        return CT_ERROR;
    }
    status = ctbak_system_call(XTRABACKUP_PATH, params, "mysql prepare");
    free_system_call_params(params, START_INDEX_FOR_PARSE_PARAM, CTBACKUP_MAX_PARAMETER_CNT - 1);
    if (status != CT_SUCCESS) {
        printf("[ctbackup]xtrabackup execute prepare for mysql failed!\n");
        return CT_ERROR;
    }
    printf("[ctbackup]xtrabackup execute prepare for mysql success!\n");
    return CT_SUCCESS;
}

/**
 * 1. xtrabackup execute prepare for mysql
 * 2. ctsql execute RESTORE DATABASE
 * 3. ctsql execute RECOVER DATABASE
 * @param ctbak_param
 * @return
 */
status_t ctbak_do_prepare(ctbak_param_t* ctbak_param)
{
    status_t status;
    if (check_common_params(ctbak_param) != CT_SUCCESS) {
        return CT_ERROR;
    }
    CT_RETURN_IFERR(check_cantiand_status());
    CT_RETURN_IFERR(start_cantiand_server());
    CT_RETURN_IFERR(ctbak_check_ctsql_online(CTSQL_CHECK_CONN_MAX_TIME_S));
    if (ctbackup_set_metadata_mode(ctbak_param) != CT_SUCCESS) {
        free_input_params(ctbak_param);
        CT_RETURN_IFERR(stop_cantiand_server());
        return CT_ERROR;
    }
    if (ctbak_param->is_mysql_metadata_in_cantian == CT_FALSE && ctbak_do_prepare_for_mysql(ctbak_param) != CT_SUCCESS) {
        free_input_params(ctbak_param);
        CT_RETURN_IFERR(stop_cantiand_server());
        return CT_ERROR;
    }

    bool32 action_flag = (ctbak_param->is_restore == CT_TRUE && ctbak_param->is_recover != CT_TRUE) ||
            (ctbak_param->is_recover == CT_TRUE && ctbak_param->is_restore != CT_TRUE) ? CT_TRUE : CT_FALSE;
    if (action_flag) {
        status = ctbak_do_restore_or_recover(ctbak_param);
        return status;
    }
    status = ctbak_do_restore(ctbak_param);
    if (status != CT_SUCCESS) {
        free_input_params(ctbak_param);
        CT_RETURN_IFERR(stop_cantiand_server());
        return CT_ERROR;
    }

    status = ctbak_do_recover(ctbak_param);
    free_input_params(ctbak_param);
    CT_RETURN_IFERR(stop_cantiand_server());
    return status;
}

status_t check_badblock_file_for_cantian_restore(ctbak_param_t *ctbak_param, const char *file_directory)
{
    if ((ctbak_param->repair_type.str != NULL) && (!cm_str_equal(ctbak_param->repair_type.str, "return_error"))) {
        uint64_t len = strlen(file_directory) + strlen(CTSQL_RESTORE_BAD_BLOCK_FILE) + 1;
        char *file_path = (char *)malloc(len);
        if (file_path == NULL) {
            printf("[ctbackup] failed to malloc for badblock_file_path!\n");
            return CT_ERROR;
        }
        errno_t ret = snprintf_s(file_path, len, len - 1, "%s%s", file_directory, CTSQL_RESTORE_BAD_BLOCK_FILE);
        if (ret == -1) {
            CM_FREE_PTR(file_path);
            printf("[ctbackup] failed to concatenate strs for badblock_file_path!\n");
            return CT_ERROR;
        }
        if (cm_file_exist(file_path)) {
            printf("[ctbackup] there exist %s, pelase remove it before restore with repair_type!\n", file_path);
            CM_FREE_PTR(file_path);
            return CT_ERROR;
        }
        CM_FREE_PTR(file_path);
    }
    return CT_SUCCESS;
}

status_t fill_repair_type_for_cantian_restore(ctbak_param_t *ctbak_param, uint64_t *option_len, char **option_str)
{
    errno_t ret;
    if (ctbak_param->repair_type.str != NULL) {
        CTBAK_RETURN_ERROR_IF_NULL(*option_str);
        if (cm_str_equal(ctbak_param->repair_type.str, "return_error")) {
            ret = snprintf_s(*option_str, *option_len, *option_len - 1, "%s%s%s",
                             *option_str, CTSQL_RESTORE_REPAIR_TYPE, CTSQL_RESTORE_REPAIR_TYPE_RETURN_ERROR);
        } else if (cm_str_equal(ctbak_param->repair_type.str, "replace_checksum")) {
            ret = snprintf_s(*option_str, *option_len, *option_len - 1, "%s%s%s",
                             *option_str, CTSQL_RESTORE_REPAIR_TYPE, CTSQL_RESTORE_REPAIR_TYPE_REPLACE_CHECKUSM);
        } else if (cm_str_equal(ctbak_param->repair_type.str, "discard_badblock")) {
            ret = snprintf_s(*option_str, *option_len, *option_len - 1, "%s%s%s",
                             *option_str, CTSQL_RESTORE_REPAIR_TYPE, CTSQL_RESTORE_REPAIR_TYPE_DISCARD_BADBLOCK);
        } else {
            printf("[ctbackup]repair_type is illegal!\n");
            return CT_ERROR;
        }
        if (ret == -1) {
            printf("[ctbackup]fill_options_for_cantain_restore concatenate repair_type for option_str failed!\n");
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t fill_options_for_cantian_restore(ctbak_param_t* ctbak_param, uint64_t* option_len, char** option_str)
{
    errno_t ret;
    char *parallelism = NULL;
    *option_len += ctbak_param->parallelism.str != NULL ?
                  strlen(CTSQL_PARALLELISM_OPTION) + ctbak_param->parallelism.len + 1 : 0;
    *option_len += ctbak_param->buffer_size.str != NULL ?
                  strlen(CTSQL_BUFFER_OPTION) + ctbak_param->buffer_size.len + 1 : 0;
    *option_len += ctbak_param->repair_type.str != NULL ?
                  strlen(CTSQL_RESTORE_REPAIR_TYPE) + ctbak_param->repair_type.len + 1 : 0;
    if (*option_len != 0) {
        *option_str = (char *)malloc(*option_len);
        if (*option_str == NULL) {
            printf("[ctbackup]fill_options_for_cantian_restore malloc for option_str failed!\n");
            return CT_ERROR;
        }
        ret = memset_s(*option_str, *option_len, 0, *option_len);
        if (ret != EOK) {
            CM_FREE_PTR(*option_str);
            printf("[ctbackup]failed to set memory for option_str\n");
            return CT_ERROR;
        }
    }
    if (ctbak_param->parallelism.str != NULL) {
        parallelism = ctbak_param->parallelism.str;
        CTBAK_RETURN_ERROR_IF_NULL(*option_str);
        ret = snprintf_s(*option_str, *option_len, *option_len - 1, "%s%s", CTSQL_PARALLELISM_OPTION, parallelism);
        if (ret == -1) {
            CM_FREE_PTR(*option_str);
            printf("[ctbackup]fill_options_for_cantain_restore concatenate parallel for option_str failed!\n");
            return CT_ERROR;
        }
    }

    if (ctbak_param->buffer_size.str != NULL) {
        CTBAK_RETURN_ERROR_IF_NULL(*option_str);
        ret = snprintf_s(*option_str, *option_len, *option_len - 1, "%s%s%s",
                         *option_str, CTSQL_BUFFER_OPTION, ctbak_param->buffer_size.str);
        if (ret == -1) {
            CM_FREE_PTR(*option_str);
            printf("[ctbackup]fill_options_for_cantain_restore concatenate buffer size for option_str failed!\n");
            return CT_ERROR;
        }
    }
    if (fill_repair_type_for_cantian_restore(ctbak_param, option_len, option_str) != CT_SUCCESS) {
        CM_FREE_PTR(*option_str);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t get_statement_for_cantian_restore(char *file_directory, uint64_t option_len,
                                           char *option_str, char **statement)
{
    errno_t ret;
    uint64_t len = strlen(CTSQL_RESTORE_STATEMENT_PREFIX) + strlen(file_directory) + option_len +
                    strlen(CTSQL_STATEMENT_QUOTE) + strlen(CTSQL_STATEMENT_END_CHARACTER) + 1;
    if (len > MAX_STATEMENT_LENGTH) {
        printf("[ctbackup] The requested memory size is wrong in fill params for cantian restore, please check!\n");
        return CT_ERROR;
    }
    // stetement free by outside caller
    *statement = (char *)malloc(len);
    if (*statement == NULL) {
        printf("[ctbackup] failed to malloc for statement when restore!\n");
        return CT_ERROR;
    }

    if (option_str != NULL) {
        ret = snprintf_s(*statement, len, len - 1, "%s%s%s%s%s", CTSQL_RESTORE_STATEMENT_PREFIX, file_directory,
                         CTSQL_STATEMENT_QUOTE, option_str, CTSQL_STATEMENT_END_CHARACTER);
    } else {
        ret = snprintf_s(*statement, len, len - 1, "%s%s%s%s", CTSQL_RESTORE_STATEMENT_PREFIX,
                         file_directory, CTSQL_STATEMENT_QUOTE, CTSQL_STATEMENT_END_CHARACTER);
    }
    if (ret == -1) {
        printf("[ctbackup] snprintf_s failed when fill params for cantian restore!\n");
        CM_FREE_PTR(*statement);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t fill_params_for_cantian_restore(ctbak_param_t* ctbak_param, char *ct_params[])
{
    uint64_t option_len  = 0;
    int   param_index = 0;
    char *option_str  = NULL;
    char *statement = NULL;
    errno_t ret;
    if (fill_params_for_ctsql_login(ct_params, &param_index, CTBAK_CTSQL_EXECV_MODE) != CT_SUCCESS) {
        printf("[ctbackup]failed to fill params for ctsql login!\n");
        return CT_ERROR;
    }
    uint64_t len = strlen(ctbak_param->target_dir.str) + strlen(CANTIAN_BACKUP_DIR) + 1;
    if (len > CANTIAN_BACKUP_FILE_LENGTH) {
        printf("[ctbackup]The requested memory size is wrong in fill params for cantian restore, please check!\n");
        return CT_ERROR;
    }
    char *file_directory = (char *)malloc(len);
    if (file_directory == NULL) {
        CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
        return CT_ERROR;
    }
    ret = snprintf_s(file_directory, len, len - 1, "%s%s", ctbak_param->target_dir.str, CANTIAN_BACKUP_DIR);
    if (ret == -1) {
        CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
        CM_FREE_PTR(file_directory);
        printf("[ctbackup]failed to concatenate strs for file_directory!\n");
        return CT_ERROR;
    }
    if (cm_access_file((const char *)file_directory, F_OK) != CT_SUCCESS) {
        CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
        CM_FREE_PTR(file_directory);
        printf("[ctbackup]the backup directory not exist!\n");
        return CT_ERROR;
    }

    if (fill_options_for_cantian_restore(ctbak_param, &option_len, &option_str) != CT_SUCCESS) {
        CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
        CM_FREE_PTR(file_directory);
        return CT_ERROR;
    }

    if (check_badblock_file_for_cantian_restore(ctbak_param, file_directory) != CT_SUCCESS) {
        CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
        CM_FREE_PTR(file_directory);
        CM_FREE_PTR(option_str);
        return CT_ERROR;
    }

    if (get_statement_for_cantian_restore(file_directory, option_len, option_str, &statement) != CT_SUCCESS) {
        CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
        CM_FREE_PTR(file_directory);
        CM_FREE_PTR(option_str);
        return CT_ERROR;
    }

    ct_params[param_index++] = statement;
    // The last parameter must be NULL
    ct_params[param_index++] = NULL;
    CM_FREE_PTR(file_directory);
    CM_FREE_PTR(option_str);
    return CT_SUCCESS;
}

status_t fill_params_for_cantian_recover(ctbak_param_t* ctbak_param, char *ct_params[])
{
    int param_index = 0;
    uint64_t len;
    errno_t ret;
    if (fill_params_for_ctsql_login(ct_params, &param_index, CTBAK_CTSQL_EXECV_MODE) != CT_SUCCESS) {
        printf("[ctbackup]failed to fill params for ctsql login!\n");
        return CT_ERROR;
    }

    len = strlen(CTSQL_RECOVER_STATEMENT_PREFIX) + strlen(CTSQL_STATEMENT_END_CHARACTER) + 1;
    if (ctbak_param->pitr_time.str != NULL) {
        len += ctbak_param->pitr_time.len + strlen(CTSQL_PITR_TIME_OPTION) + strlen(CTSQL_STATEMENT_QUOTE);
    } else if (ctbak_param->pitr_scn.str != NULL) {
        len += ctbak_param->pitr_scn.len + strlen(CTSQL_PITR_SCN_OPTION);
    } else if (ctbak_param->is_pitr_cancel == CT_TRUE) {
        len += strlen(CTSQL_PITR_CANCEL_OPTION);
    }
    // stetement not free here
    char *statement = (char *)malloc(len);
    if (statement == NULL) {
        CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
        printf("[ctbackup]failed to apply storage for archive log!\n");
        CTBAK_RETURN_ERROR_IF_NULL(statement);
    }
    if (ctbak_param->pitr_time.str != NULL) {
        ret = snprintf_s(statement, len, len - 1, "%s%s%s%s%s", CTSQL_RECOVER_STATEMENT_PREFIX, CTSQL_PITR_TIME_OPTION,
                         ctbak_param->pitr_time.str, CTSQL_STATEMENT_QUOTE, CTSQL_STATEMENT_END_CHARACTER);
    } else if (ctbak_param->pitr_scn.str != NULL) {
        ret = snprintf_s(statement, len, len - 1, "%s%s%s%s", CTSQL_RECOVER_STATEMENT_PREFIX, CTSQL_PITR_SCN_OPTION,
                         ctbak_param->pitr_scn.str, CTSQL_STATEMENT_END_CHARACTER);
    } else if (ctbak_param->is_pitr_cancel == CT_TRUE) {
        ret = snprintf_s(statement, len, len - 1, "%s%s%s", CTSQL_RECOVER_STATEMENT_PREFIX, CTSQL_PITR_CANCEL_OPTION,
                         CTSQL_STATEMENT_END_CHARACTER);
    } else {
        ret = snprintf_s(statement, len, len - 1, "%s%s", CTSQL_RECOVER_STATEMENT_PREFIX, CTSQL_STATEMENT_END_CHARACTER);
    }
    
    if (ret == -1) {
        CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
        CM_FREE_PTR(statement);
        return CT_ERROR;
    }
    ct_params[param_index++] = statement;
    // The last parameter must be NULL
    ct_params[param_index++] = NULL;
    return CT_SUCCESS;
}

status_t fill_params_for_cantian_reset_log(ctbak_param_t* ctbak_param, char *ct_params[])
{
    int param_index = 0;
    uint64_t len;
    errno_t ret;
    if (fill_params_for_ctsql_login(ct_params, &param_index, CTBAK_CTSQL_EXECV_MODE) != CT_SUCCESS) {
        printf("[ctbackup]failed to fill params for ctsql login!\n");
        return CT_ERROR;
    }
    len = strlen(CTSQL_RECOVER_RESET_LOG) + strlen(CTSQL_STATEMENT_END_CHARACTER) + 1;
 
    char *statement = (char *)malloc(len);
    if (statement == NULL) {
        CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
        printf("[ctbackup]failed to apply storage for reset log!\n");
        CTBAK_RETURN_ERROR_IF_NULL(statement);
    }
 
    ret = snprintf_s(statement, len, len - 1, "%s%s", CTSQL_RECOVER_RESET_LOG, CTSQL_STATEMENT_END_CHARACTER);
    if (ret == -1) {
        CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
        CM_FREE_PTR(statement);
        printf("[ctbackup]failed to concatenate strs for reset log!\n");
        return CT_ERROR;
    }
    ct_params[param_index++] = statement;
    ct_params[param_index++] = NULL;
    return CT_SUCCESS;
}

status_t ctbak_do_restore_or_recover(ctbak_param_t* ctbak_param)
{
    status_t status;
    if (ctbak_param->is_restore == CT_TRUE) {
        status = ctbak_do_restore(ctbak_param);
    } else {
        status = ctbak_do_recover(ctbak_param);
    }
    free_input_params(ctbak_param);
    CT_RETURN_IFERR(stop_cantiand_server());
    return status;
}

/**
 * 1. decode restore params from prepare
 * 2. ctsql execute restore
 * @param ctbak_param
 * @return
 */
status_t ctbak_do_restore(ctbak_param_t* ctbak_param)
{
    status_t status;
    char *ct_params[CTBACKUP_MAX_PARAMETER_CNT] = {0};
    printf("[ctbackup]ready to restore cantian!\n");
    status = fill_params_for_cantian_restore(ctbak_param, ct_params);
    if (status != CT_SUCCESS) {
        printf("[ctbackup]fill_params_for_cantian_restore failed!\n");
        return CT_ERROR;
    }
    char *ctsql_binary_path = NULL;
    if (get_ctsql_binary_path(&ctsql_binary_path) != CT_SUCCESS) {
        CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
        CM_FREE_PTR(ct_params[CTSQL_STATEMENT_INDEX]);
        return CT_ERROR;
    }
    status = ctbak_system_call(ctsql_binary_path, ct_params, "cantian restore");
    // free space of heap
    CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
    CM_FREE_PTR(ct_params[CTSQL_STATEMENT_INDEX]);
    CM_FREE_PTR(ctsql_binary_path);
    if (status != CT_SUCCESS) {
        printf("[ctbackup]cantian restore failed!\n");
        return CT_ERROR;
    }

    printf("[ctbackup]cantian restore success\n");
    return CT_SUCCESS;
}

/**
 * 1. decode recovery params from prepare
 * 2. ctsql execute recover
 * @param recover_param
 * @return
 */
status_t ctbak_do_recover(ctbak_param_t* ctbak_param)
{
    status_t status;
    char *ct_params[CTBACKUP_MAX_PARAMETER_CNT] = {0};
    char *ct_params_resetlog[CTBACKUP_MAX_PARAMETER_CNT] = {0};
    printf("[ctbackup]ready to recover cantian!\n");
    status = fill_params_for_cantian_recover(ctbak_param, ct_params);
    if (status != CT_SUCCESS) {
        printf("[ctbackup]fill_params_for_cantian_recover failed!\n");
        return CT_ERROR;
    }
    char *ctsql_binary_path = NULL;
    if (get_ctsql_binary_path(&ctsql_binary_path) != CT_SUCCESS) {
        CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
        CM_FREE_PTR(ct_params[CTSQL_STATEMENT_INDEX]);
        return CT_ERROR;
    }
    status = ctbak_system_call(ctsql_binary_path, ct_params, "cantian recover");
    // free space of heap
    CM_FREE_PTR(ct_params[CTSQL_LOGININFO_INDEX]);
    CM_FREE_PTR(ct_params[CTSQL_STATEMENT_INDEX]);
    if (status != CT_SUCCESS) {
        CM_FREE_PTR(ctsql_binary_path);
        printf("[ctbackup]cantian recover failed!\n");
        return CT_ERROR;
    }

    if (ctbak_param->pitr_time.str != NULL || ctbak_param->pitr_scn.str != NULL) {
        printf("[ctbackup]ready to reset log after recover!\n");
        status = fill_params_for_cantian_reset_log(ctbak_param, ct_params_resetlog);
        if (status != CT_SUCCESS) {
            CM_FREE_PTR(ctsql_binary_path);
            printf("[ctbackup]fill_params_for_cantian_reset_log failed!\n");
            return CT_ERROR;
        }
 
        status = ctbak_system_call(ctsql_binary_path, ct_params_resetlog, "cantian resetlog");
        if (status != CT_SUCCESS) {
            CM_FREE_PTR(ct_params_resetlog[CTSQL_LOGININFO_INDEX]);
            CM_FREE_PTR(ct_params_resetlog[CTSQL_STATEMENT_INDEX]);
            CM_FREE_PTR(ctsql_binary_path);
            printf("[ctbackup]cantian reset log failed!\n");
            return CT_ERROR;
        }
    }
    CM_FREE_PTR(ct_params_resetlog[CTSQL_LOGININFO_INDEX]);
    CM_FREE_PTR(ct_params_resetlog[CTSQL_STATEMENT_INDEX]);
    CM_FREE_PTR(ctsql_binary_path);
    printf("[ctbackup]cantian recover success\n");
    return CT_SUCCESS;
}

ctbak_cmd_t *ctbak_generate_prepare_cmd(void)
{
    ctbak_cmd_t* ctbak_cmd = (ctbak_cmd_t*)malloc(sizeof(ctbak_cmd_t));
    if (ctbak_cmd == NULL) {
        printf("[ctbackup]failed to malloc memory for prepare ctbak_cmd!\n");
        return (ctbak_cmd_t *)NULL;
    }
    ctbak_cmd->parse_args = ctbak_parse_prepare_args;
    ctbak_cmd->do_exec = ctbak_do_prepare;
    return ctbak_cmd;
};
