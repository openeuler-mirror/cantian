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
* ctbackup_dbs_common.c
*
*
* IDENTIFICATION
* src/utils/ctbackup/ctbackup_dbs_common.c
*
* -------------------------------------------------------------------------
 */

#include "ctbackup_dbs_common.h"

#define DBS_CONFIG_FILE_NAME_LEN 32
#define DBS_WAIT_CGW_LINK_INIT_TIME_SECOND 2
#define DBS_WAIT_CONFIG_RETRY_NUM 2
#define DBS_WAIT_CONFIG_INTERVAL_TIME 2000
#define DBS_CLUSTER_UUID_LEN 37
#define DBS_CONFIG_MAX_PARAM 256
#define DBS_QUERY_FILE_PRAMA_NUM 3
#define DBS_QUERY_FILE_CHECK_PRAMA_NUM 1
#define USER_NAME_LEN 32
#define GROUP_NAME_LEN 255
#define MODE_STR_LEN 10
#define TIME_STR_LEN 25
#define BOOL_TRUE_LEN 4
#define DBS_TOOL_PARAM_BOOL_LEN 6
#define DBS_COPY_FILE_PRAMA_NUM 5
#define DBS_COPY_FILE_CHECK_PRAMA_NUM 3
#define DEV_RW_BUFFER_SIZE (1 * 1024 * 1024)
#define NUM_ZERO    0
#define NUM_ONE     1
#define NUM_TWO     2
#define NUM_THREE   3
#define NUM_FOUR    4
#define NUM_FIVE    5
#define NUM_SIX     6
#define NUM_SEVEN   7
#define NUM_EIGHT   8
#define NUM_NINE    9

#define DBS_HOME_PATH "/opt/cantian"
#define DBS_TOOL_CONFIG_PATH "/opt/cantian/dbstor/conf/dbs"
#define DBS_TOOL_PARAM_FS_NAME "--fs-name="
#define DBS_TOOL_PARAM_FILE_DIR "--file-dir="
#define DBS_TOOL_PARAM_VSTORE_ID "--vstore_id="
#define MAX_VALUE_UINT32 "4294967295"
#define DBS_FILE_TYPE_UNKNOWN "unknown"
#define DBS_FILE_TYPE_DIR "dir"
#define DBS_FILE_TYPE_FILE "file"
#define DBS_COPY_FILE_PARAM "--copy-file"
#define DBS_TOOL_PARAM_OVERWRITE "--overwrite"
#define BOOL_TRUE "true"
#define BOOL_FALSE "false"
#define DBS_TOOL_PARAM_FILE_NAME "--file-name="
#define DBS_TOOL_PARAM_SOURCE_DIR "--source-dir="
#define DBS_TOOL_PARAM_TARGET_DIR "--target-dir="
#define DBS_IMPORT_PARAM "--import"
#define DBS_EXPORT_PARAM "--export"

dbs_fs_info_t g_dbs_fs_info = { 0 };
int32 g_lockConfigHandle = CT_INVALID_HANDLE;

typedef enum {
    RETURN_FS_SNAP_OP_OK                  = 0,          /* valid diff, and delta > 0 */
    RETURN_FS_SNAP_OP_NONEXIST            = 1,          /* query finish, valid value, delta number>=0 */
    RETURN_FS_SNAP_OP_INVALID_PARAM       = 2,          /* INVALID_PARAM - param error, invalid result */
    RETURN_FS_SNAP_OP_NEED_RETRY          = 3,          /* retry result, invalid result */
    RETURN_FS_SNAP_OP_NO_RETRY            = 4,          /* no retry result, invalid result */
    RETURN_FS_SNAP_UUID_EXISTS            = 5,          /* uuid has exists */
    RETURN_FS_SNAP_NAME_EXISTS            = 6,          /* name has exists */
    RETURN_FS_SNAP_NUM_FULL               = 7,          /* snap num is full */
    RETURN_FS_SNAP_TP_INCONSISTENT        = 8,          /* tp inconsistent */
    RETURN_FS_SNAP_FS_NOT_EXIST           = 9,          /* filesystem not exist */
    RETURN_FS_SNAP_FS_IS_ROLLBAKING       = 10,         /* snap is rollbacking */
    RETURN_FS_SNAP_IS_SYNCING             = 11,         /* snap is syncing */
    RETURN_FS_SNAP_CREATING_CONFIT_MS_DEL = 12,         /* metro is deleting, can not create snap */

    RETURN_FS_SNAP_OP_BUTT
}RETURN_FS_SNAP_OP_E;

const char* ctbak_snap_error[] = {
    [RETURN_FS_SNAP_OP_OK] = "valid diff, and delta > 0",
    [RETURN_FS_SNAP_OP_NONEXIST] = "query finish, valid value, delta number>=0",
    [RETURN_FS_SNAP_OP_INVALID_PARAM] = "INVALID_PARAM - param error, invalid result",
    [RETURN_FS_SNAP_OP_NEED_RETRY] = "retry result, invalid result",
    [RETURN_FS_SNAP_OP_NO_RETRY] = "no retry result, invalid result",
    [RETURN_FS_SNAP_UUID_EXISTS] = "uuid has exists",
    [RETURN_FS_SNAP_NAME_EXISTS] = "name has exists",
    [RETURN_FS_SNAP_NUM_FULL] = "snap num is full",
    [RETURN_FS_SNAP_TP_INCONSISTENT] = "tp inconsistent",
    [RETURN_FS_SNAP_FS_NOT_EXIST] = "filesystem not exist",
    [RETURN_FS_SNAP_FS_IS_ROLLBAKING] = "snap is rollbacking",
    [RETURN_FS_SNAP_IS_SYNCING] = "snap is syncing",
    [RETURN_FS_SNAP_CREATING_CONFIT_MS_DEL] = "metro is deleting, can not create snap"
};


status_t dbs_get_param_value(char *line, char *value, uint32 length)
{
    char line_cpy[DBS_CONFIG_MAX_PARAM] = { 0 };
    char *context = NULL;
    text_t param = { 0 };
    errno_t ret = strcpy_s(line_cpy, DBS_CONFIG_MAX_PARAM, line);
    if (ret != EOK) {
        CT_LOG_RUN_ERR("strcpy_s line failed %d.", ret);
        return CT_ERROR;
    }
    param.str = strtok_s(line_cpy, "=", &context);
    param.str = strtok_s(NULL, "\n", &context);
    param.len = strlen(param.str);
    cm_trim_text(&param);
    ret = strcpy_s(value, length, param.str);
    if (ret != EOK) {
        CT_LOG_RUN_ERR("strcpy_s value failed %d.", ret);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t dbs_get_uuid_lsid_from_config(char* cfg_name, uint32* lsid, char* uuid)
{
    char file_path[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    char line[DBS_CONFIG_MAX_PARAM] = { 0 };
    errno_t ret = sprintf_s(file_path, CT_FILE_NAME_BUFFER_SIZE, "%s/%s",
                            DBS_TOOL_CONFIG_PATH, cfg_name);
    PRTS_RETURN_IFERR(ret);
    FILE* fp = fopen(file_path, "r");
    if (fp == NULL) {
        CT_LOG_RUN_ERR("Failed to open file %s\n", file_path);
        return CT_ERROR;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *context = NULL;
        if (strstr(line, "INST_ID") != NULL) {
            text_t lsid_t;
            lsid_t.str = strtok_s(line, "=", &context);
            lsid_t.str = strtok_s(NULL, "\n", &context);
            lsid_t.len = strlen(lsid_t.str);
            cm_trim_text(&lsid_t);
            ret = cm_str2uint32((const char *)lsid_t.str, lsid);
            if (ret != CT_SUCCESS) {
                CT_LOG_RUN_ERR("Str2uint32 failed %d.", ret);
                break;
            }
        } else if (strstr(line, "DBS_TOOL_UUID") != NULL) {
            text_t uuid_t;
            uuid_t.str = strtok_s(line, "=", &context);
            uuid_t.str = strtok_s(NULL, "\n", &context);
            uuid_t.len = strlen(uuid_t.str);
            cm_trim_text(&uuid_t);
            ret = strcpy_s(uuid, DBS_CLUSTER_UUID_LEN, uuid_t.str);
            if (ret != CT_SUCCESS) {
                CT_LOG_RUN_ERR("strcpy_s failed %d.", ret);
                break;
            }
        }
    }
    (void)fclose(fp);
    return ret;
}

status_t dbs_get_fs_info_from_config(char* cfg_name)
{
    char file_path[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    char line[DBS_CONFIG_MAX_PARAM] = { 0 };
    errno_t ret = sprintf_s(file_path, CT_FILE_NAME_BUFFER_SIZE, "%s/%s",
                            DBS_TOOL_CONFIG_PATH, cfg_name);
    PRTS_RETURN_IFERR(ret);
    FILE* fp = fopen(file_path, "r");
    if (fp == NULL) {
        CT_LOG_RUN_ERR("Failed to open file %s\n", file_path);
        return CT_ERROR;
    }

    status_t result = CT_SUCCESS;
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strstr(line, "NAMESPACE_FSNAME") != NULL) {
            result = dbs_get_param_value(line, g_dbs_fs_info.log_fs_name, MAX_DBS_FS_NAME_LEN);
        } else if (strstr(line, "NAMESPACE_PAGE_FSNAME") != NULL) {
            result = dbs_get_param_value(line, g_dbs_fs_info.page_fs_name, MAX_DBS_FS_NAME_LEN);
        } else if (strstr(line, "CLUSTER_NAME") != NULL) {
            result = dbs_get_param_value(line, g_dbs_fs_info.cluster_name, MAX_DBS_FILE_NAME_LEN);
        } else if (strstr(line, "LOG_VSTOR") != NULL) {
            result = dbs_get_param_value(line, g_dbs_fs_info.log_fs_vstore_id, MAX_DBS_VSTORE_ID_LEN);
        } else if (strstr(line, "DBS_LOG_PATH") != NULL) {
            result = dbs_get_param_value(line, g_dbs_fs_info.dbs_log_path, MAX_DBS_FS_NAME_LEN);
        } else if (strstr(line, "PAGE_VSTOR") != NULL) {
            result = dbs_get_param_value(line, g_dbs_fs_info.page_fs_vstore_id, MAX_DBS_VSTORE_ID_LEN);
        } else if (strstr(line, "NAMESPACE_SHARE_FSNAME") != NULL) {
            result = dbs_get_param_value(line, g_dbs_fs_info.share_fs_name, MAX_DBS_FS_NAME_LEN);
        } else if (strstr(line, "NAMESPACE_ARCHIVE_FSNAME") != NULL) {
            result = dbs_get_param_value(line, g_dbs_fs_info.archive_fs_name, MAX_DBS_FS_NAME_LEN);
        }
        if (result != CT_SUCCESS) {
            CT_LOG_RUN_ERR("get param value failed, line %s.", line);
            break;
        }
    }
    (void)fclose(fp);
    return result;
}

status_t dbs_get_and_flock_conf_file(char *config_name)
{
    char dbs_conf_dir_path[CT_FILE_NAME_BUFFER_SIZE] = DBS_TOOL_CONFIG_PATH;

    DIR *dir_ptr;
    struct dirent *entry;

    dir_ptr = opendir(dbs_conf_dir_path);
    if (dir_ptr == NULL) {
        printf("open dbs_conf_dir_path failed!\n");
        return CT_ERROR;
    }

    int32 ret = 0;
    char dbs_conf_file_path[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    while ((entry = readdir(dir_ptr)) != NULL) {
        if (strstr(entry->d_name, "tool") == NULL) {
            continue;
        }
        ret = memset_s(dbs_conf_file_path, CT_FILE_NAME_BUFFER_SIZE, 0, CT_FILE_NAME_BUFFER_SIZE);
        if (ret != EOK) {
            printf("memset_s dbs_conf_file_path failed! ERRNO: %d\n", ret);
            break;
        }
        ret = sprintf_s(dbs_conf_file_path, CT_FILE_NAME_BUFFER_SIZE, "%s/%s", dbs_conf_dir_path, entry->d_name);
        if (ret != EOK) {
            printf("Failed to assemble the dbstor conf file path by instance home(%s).\n", dbs_conf_dir_path);
            break;
        }
        if (cm_open_file(dbs_conf_file_path, O_RDWR, &g_lockConfigHandle) != CT_SUCCESS) {
            printf("open dbs_conf_file failed!\n");
            break;
        }
        if (flock(g_lockConfigHandle, LOCK_EX | LOCK_NB) == 0) {
            ret = strcpy_s(config_name, DBS_CONFIG_FILE_NAME_LEN, entry->d_name);
            if (ret != EOK) {
                printf("strcpy_s config_name failed!\n");
                closedir(dir_ptr);
                return CT_ERROR;
            }
            closedir(dir_ptr);
            return CT_SUCCESS;
        }
        cm_close_file(g_lockConfigHandle);
    }

    closedir(dir_ptr);
    return CT_ERROR;
}

status_t dbs_client_init(char* cfg_name)
{
    int64_t start_time = cm_now();
    status_t ret = dbs_init_lib();
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Init dbs lib failed(%d).", ret);
        return ret;
    }

    if (dbs_get_fs_info_from_config(cfg_name) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cms get fs info from config(%s) failed.\n", cfg_name);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("log fs name:%s, page fs name:%s, cluster name %s",
                   g_dbs_fs_info.log_fs_name, g_dbs_fs_info.page_fs_name, g_dbs_fs_info.cluster_name);

    uint32 lsid;
    char uuid[DBS_CLUSTER_UUID_LEN] = { 0 };

    CT_LOG_RUN_INF("dbstor client is inited by config file %s", cfg_name);
    if (dbs_get_uuid_lsid_from_config(cfg_name, &lsid, uuid) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cms get uuid lsid from config(%s) failed.\n", cfg_name);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("uuid:%s, lsid:%u", uuid, lsid);
    cm_set_dbs_uuid_lsid((const char*)uuid, lsid);

    cm_dbs_cfg_s *cfg = cm_dbs_get_cfg();
    cfg->enable = CT_TRUE;

    ret = cm_dbs_init(DBS_HOME_PATH, cfg_name, DBS_RUN_DBS_TOOL);
    if (ret != CT_SUCCESS) {
        (void)dbs_global_handle()->dbs_client_flush_log();
        CT_LOG_RUN_ERR("Dbs init failed(%d).", ret);
    }
    int64_t end_time = cm_now();
    CT_LOG_RUN_INF("dbstor client init time %ld (ns)", end_time - start_time);
    return ret;
}

status_t dbs_alloc_conf_file_retry(char *config_name)
{
    uint32_t retry_num = DBS_WAIT_CONFIG_RETRY_NUM;
    int32_t ret = memset_s(config_name, DBS_CONFIG_FILE_NAME_LEN, 0, DBS_CONFIG_FILE_NAME_LEN);
    if (ret != EOK) {
        CT_LOG_RUN_ERR("memset_s config_name failed! ERRNO: %d\n", ret);
        return CT_ERROR;
    }
    do {
        if (dbs_get_and_flock_conf_file(config_name) == CT_SUCCESS) {
            return CT_SUCCESS;
        }
        retry_num--;
        cm_sleep(DBS_WAIT_CONFIG_INTERVAL_TIME);
    } while (retry_num > 0);

    printf("Get free dbstor config file timeout, please wait a while and try again.\n");
    return CT_ERROR;
}

status_t dbs_init(ctbak_param_t* ctbak_param)
{
    char dbs_cfg_name[DBS_CONFIG_FILE_NAME_LEN] = { 0 };
    if (dbs_alloc_conf_file_retry(dbs_cfg_name) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Init dbs havn't dbs chain.");
        return CT_ERROR;
    }

    if (dbs_client_init(dbs_cfg_name) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Init dbs failed.");
        return CT_ERROR;
    }
    sleep(DBS_WAIT_CGW_LINK_INIT_TIME_SECOND);

    cm_str2text(g_dbs_fs_info.page_fs_vstore_id, &ctbak_param->page_fs_vstore_id);
    cm_str2text(g_dbs_fs_info.page_fs_name, &ctbak_param->page_fs_name);
    cm_str2text(g_dbs_fs_info.share_fs_name, &ctbak_param->share_fs_name);
    cm_str2text(g_dbs_fs_info.log_fs_name, &ctbak_param->log_fs_name);
    cm_str2text(g_dbs_fs_info.log_fs_vstore_id, &ctbak_param->log_fs_vstore_id);
    cm_str2text(g_dbs_fs_info.archive_fs_name, &ctbak_param->archive_fs_name);
    printf("DBstor init success.\n");
    return CT_SUCCESS;
}

// query_file
status_t timestamp_to_readable(uint64_t timestamp, char* readable_time) {
    time_t time = (time_t)timestamp;
    return strftime(readable_time, TIME_STR_LEN, "%Y-%m-%d %H:%M:%S",
                    localtime(&time)) > 0 ? CT_SUCCESS : CT_ERROR;
}

status_t gid_to_groupname(uint32_t gid, char* groupname) {
    struct group* gr = getgrgid(gid);
    if (gr != NULL) {
        MEMS_RETURN_IFERR(strncpy_s(groupname, GROUP_NAME_LEN, gr->gr_name, strlen(gr->gr_name)));
        return CT_SUCCESS;
    }
    return CT_ERROR;
}

status_t uid_to_username(uint32_t uid, char* username) {
    struct passwd* pw = getpwuid(uid);
    if (pw != NULL) {
        MEMS_RETURN_IFERR(strncpy_s(username, USER_NAME_LEN, pw->pw_name, strlen(pw->pw_name)));
        return CT_SUCCESS;
    }
    return CT_ERROR;
}

status_t mode_to_string(uint32_t mode_num, char* mode_str) {
    MEMS_RETURN_IFERR(strncpy_s(mode_str, MODE_STR_LEN, "---------", strlen("---------")));

    // 检查用户（owner）权限
    if (mode_num & 0400) mode_str[NUM_ZERO] = 'r';
    if (mode_num & 0200) mode_str[NUM_ONE] = 'w';
    if (mode_num & 0100) mode_str[NUM_TWO] = 'x';

    // 检查组（group）权限
    if (mode_num & 0040) mode_str[NUM_THREE] = 'r';
    if (mode_num & 0020) mode_str[NUM_FOUR] = 'w';
    if (mode_num & 0010) mode_str[NUM_FIVE] = 'x';

    // 检查其他用户（others）权限
    if (mode_num & 0004) mode_str[NUM_SIX] = 'r';
    if (mode_num & 0002) mode_str[NUM_SEVEN] = 'w';
    if (mode_num & 0001) mode_str[NUM_EIGHT] = 'x';
    mode_str[NUM_NINE] = '\0';
    return CT_SUCCESS;
}

bool32 compare_bool_param(char *argv[], params_list_t *params_list, uint32 i, uint32 j, bool32 *matched)
{
    char *params[] = {DBS_TOOL_PARAM_OVERWRITE};
    uint32 params_len = 1;
    if (strncmp(argv[i], params_list->keys[j], strlen(params_list->keys[j])) == 0) {
        for (uint32 k = 0; k < params_len; k++) {
            if (strncmp(argv[i], params[k], strlen(params[k])) == 0) {
                MEMS_RETURN_IFERR(strncpy_sp(params_list->values[j], params_list->value_len[j],
                                             BOOL_TRUE, BOOL_TRUE_LEN));
                *matched = CT_TRUE;
                return CT_TRUE;
            }
        }
    }
    return CT_FALSE;
}

status_t compare_param(char *argv[], params_list_t *params_list, uint32 i, uint32 j, bool32 *matched)
{
    if (compare_bool_param(argv, params_list, i, j, matched) == CT_TRUE) {
        return CT_SUCCESS;
    }
    if (strncmp(argv[i], params_list->keys[j], strlen(params_list->keys[j])) == 0) {
        if (strlen(argv[i]) - strlen(params_list->keys[j]) >= params_list->value_len[j]) {
            printf("Parameter value is too long for %s.\n", params_list->keys[j]);
            return CT_ERROR;
        }
        MEMS_RETURN_IFERR(strncpy_sp(params_list->values[j], params_list->value_len[j],
                                     argv[i] + strlen(params_list->keys[j]),
                                     strlen(argv[i]) - strlen(params_list->keys[j])));
        *matched = CT_TRUE;
    }
    return CT_SUCCESS;
}

uint32 get_parse_params_init_value(char *argv[])
{
    uint32 i = 1;
    char *params[] = {DBS_COPY_FILE_PARAM};
    uint32 params_len = 1;
    for (uint32 j = 0; j < params_len; j++) {
        if (strncmp(argv[i], params[j], strlen(params[j])) == 0) {
            return i + 2;
        }
    }
    return i + 1;
}

status_t file_info_screen_print(void *file_list, uint32 file_num, char *path, file_info_version_t info_version)
{
    if (file_num == 0) {
        printf("No files found in directory: %s\n", path);
    } else {
        printf("Files in directory %s:\n", path);
        for (uint32 i = 0; i < file_num; i++) {
            char *file_name = NULL;
            if (info_version == DBS_FILE_INFO_VERSION_1) {
                dbstor_file_info *file_info = (dbstor_file_info *)((char *)file_list + i * sizeof(dbstor_file_info));
                file_name = file_info->file_name;
                if (file_name != NULL) {
                    printf("%s\n", file_name);
                }
                continue;
            }
            dbstor_file_info_detail *file_info = (dbstor_file_info_detail *)((char *)file_list +
                                                                             i * sizeof(dbstor_file_info_detail));
            file_name = file_info->file_name;
            if (file_name == NULL || strlen(file_name) == 0) {
                continue;
            }
            uint32_t file_size = file_info->file_size;
            char *file_type = DBS_FILE_TYPE_UNKNOWN;
            if (file_info->type == CS_FILE_TYPE_DIR) {
                file_type = DBS_FILE_TYPE_DIR;
            } else if (file_info->type == CS_FILE_TYPE_FILE) {
                file_type = DBS_FILE_TYPE_FILE;
            }
            char username[USER_NAME_LEN] = {0};
            char groupname[GROUP_NAME_LEN] = {0};
            char mode_str[MODE_STR_LEN] = {0};
            char timr_str[TIME_STR_LEN] = {0};
            PRTS_RETURN_IFERR(mode_to_string(file_info->mode, mode_str));
            PRTS_RETURN_IFERR(uid_to_username(file_info->uid, username));
            PRTS_RETURN_IFERR(gid_to_groupname(file_info->gid, groupname));
            PRTS_RETURN_IFERR(timestamp_to_readable(file_info->mtimeSec, timr_str));
            printf("%s  %s  %s %s  %u  %s  %s\n", mode_str, file_type, username,
                   groupname, file_size, timr_str, file_name);
        }
    }
    return CT_SUCCESS;
}

status_t parse_params_list(int32 argc, char *argv[], params_list_t *params_list)
{
    uint32 i = get_parse_params_init_value(argv);
    for (; i < argc; i++) {
        bool32 matched = CT_FALSE;
        for (uint32 j = 0; j < params_list->params_num; j++) {
            if (compare_param(argv, params_list, i, j, &matched) != CT_SUCCESS) {
                return CT_ERROR;
            }
            if (matched) {
                break;
            }
        }
        if (!matched) {
            printf("Invalid parameter: %s\n", argv[i]);
            return CT_ERROR;
        }
    }
    for (uint32 k = 0; k < params_list->check_num; k++) {
        if (strlen(params_list->check_list[k].value) == 0) {
            printf("%s not specified.\n", params_list->check_list[k].key);
            return CT_ERROR;
        }
        if (strcmp(params_list->check_list[k].key, DBS_TOOL_PARAM_VSTORE_ID) == 0) {
            if (strlen(params_list->check_list[k].value) > strlen(MAX_VALUE_UINT32)) {
                printf("Invalid vstore_id %s.\n", params_list->check_list[k].value);
                return CT_ERROR;
            }
            if ((strlen(params_list->check_list[k].value) == strlen(MAX_VALUE_UINT32)) &&
                (strcmp(params_list->check_list[k].value, MAX_VALUE_UINT32) > 0)) {
                printf("Invalid vstore_id %s.\n", params_list->check_list[k].value);
                return CT_ERROR;
            }
        }
    }
    return CT_SUCCESS;
}

int32 dbs_query_fs_file(int32 argc, char *argv[])
{
    char fs_name[MAX_DBS_FS_NAME_LEN] = {0};
    char file_path[MAX_DBS_FILE_PATH_LEN] = {0};
    char vstore_id[MAX_DBS_VSTORE_ID_LEN] = {0};
    const char *params[] = {DBS_TOOL_PARAM_FS_NAME, DBS_TOOL_PARAM_FILE_DIR, DBS_TOOL_PARAM_VSTORE_ID};
    char *results[] = {fs_name, file_path, vstore_id};
    size_t result_lens[] = {MAX_DBS_FS_NAME_LEN, MAX_DBS_FILE_PATH_LEN, MAX_DBS_VSTORE_ID_LEN};
    params_check_list_t check_list[] = {{DBS_TOOL_PARAM_FS_NAME, fs_name}};
    params_list_t params_list = {params, results, result_lens, check_list, DBS_QUERY_FILE_PRAMA_NUM,DBS_QUERY_FILE_CHECK_PRAMA_NUM};

    if (parse_params_list(argc, argv, &params_list) != CT_SUCCESS) {
        printf("Invalid command.\nUsage: --query-file --fs-name=xxx [--file-dir=xxx] [--vstore-id=*]\n");
        return CT_ERROR;
    }
    char full_path[MAX_DBS_FS_FILE_PATH_LEN] = {0};
    if (strlen(file_path) == 0) {
        PRTS_RETURN_IFERR(snprintf_s(full_path, MAX_DBS_FS_FILE_PATH_LEN,
                                     MAX_DBS_FS_FILE_PATH_LEN - 1, "/%s", fs_name));
    } else {
        PRTS_RETURN_IFERR(snprintf_s(full_path, MAX_DBS_FS_FILE_PATH_LEN,
                                     MAX_DBS_FS_FILE_PATH_LEN - 1, "/%s/%s", fs_name, file_path));
    }
    dbs_device_info_t query_info = { .handle = -1, .type = DEV_TYPE_DBSTOR_FILE, .path = "" };
    MEMS_RETURN_IFERR(strncpy_s(query_info.path, MAX_DBS_FS_FILE_PATH_LEN, full_path, strlen(full_path)));

    void *file_list = NULL;
    uint32 file_num = 0;
    uint32 vstore_id_uint = 0;
    file_info_version_t info_version = DBS_FILE_INFO_VERSION_1;
    if (strlen(vstore_id) > 0) {
        vstore_id_uint = (uint32)atoi(vstore_id);
    }
    if (dbs_global_handle()->dbs_file_get_list_detail != NULL) {
        info_version = DBS_FILE_INFO_VERSION_2;
    }
    if (cm_malloc_file_list_by_version_id(info_version, vstore_id_uint,
                                          &file_list, query_info.path, &file_num) != CT_SUCCESS) {
        printf("Failed to allocate memory for file list.\n");
        return CT_ERROR;
    }
    status_t ret = cm_dbs_query_dir_vstore_id(vstore_id_uint, query_info.path, file_list, &file_num);
    if (ret != CT_SUCCESS) {
        printf("Failed to query files in directory: %s with vstore-id: %u\n", query_info.path, vstore_id_uint);
        cm_free_file_list(&file_list);
        return CT_ERROR;
    }
    MEMS_RETURN_IFERR(file_info_screen_print(file_list, file_num, query_info.path, info_version));
    cm_free_file_list(&file_list);
    return CT_SUCCESS;
}

status_t copy_file(const dbs_device_info_t *src_info, const dbs_device_info_t *dst_info)
{
    aligned_buf_t buf = { 0 };
    if (cm_aligned_malloc(DEV_RW_BUFFER_SIZE, "copy_file_buffer", &buf) != CT_SUCCESS) {
        return CT_ERROR;
    }

    int64 offset_read = 0;
    int64 offset_write = 0;
    int32 read_size = 0;

    while (CT_TRUE) {
        status_t ret = cm_read_device_nocheck(src_info->type, src_info->handle, offset_read, buf.aligned_buf,
                                              buf.buf_size, &read_size);
        if (ret != CT_SUCCESS) {
            cm_aligned_free(&buf);
            printf("Read error from source file\n");
            return CT_ERROR;
        }

        if (read_size == 0) {
            break;  // EOF
        }

        if (cm_write_device(dst_info->type, dst_info->handle, offset_write, buf.aligned_buf, read_size) != CT_SUCCESS) {
            cm_aligned_free(&buf);
            printf("Write error to destination file\n");
            return CT_ERROR;
        }

        offset_read += read_size;
        offset_write += read_size;
    }

    cm_aligned_free(&buf);
    return CT_SUCCESS;
}

status_t check_strcat_path(const char *dir, const char *name, char *strcat_name)
{
    if ((strlen(dir) + strlen(name)) >= MAX_DBS_FS_FILE_PATH_LEN) {
        CT_LOG_RUN_ERR("srch file name is too long. dir is %s, file name is %s.", dir, name);
        return CT_ERROR;
    }
    int32 ret = snprintf_s(strcat_name, MAX_DBS_FS_FILE_PATH_LEN, MAX_DBS_FS_FILE_PATH_LEN - 1, "%s/%s", dir, name);
    PRTS_RETURN_IFERR(ret);
    return CT_SUCCESS;
}

status_t copy_file_by_name(const char *file_name, dbs_device_info_t *src_info,
                           dbs_device_info_t *dst_info, bool32 overwrite)
{
    char src_file_name[MAX_DBS_FS_FILE_PATH_LEN] = {0};
    char dst_file_name[MAX_DBS_FS_FILE_PATH_LEN] = {0};
    if (check_strcat_path(src_info->path, file_name, src_file_name) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cm_exist_device(src_info->type, src_file_name) != CT_TRUE) {
        CT_LOG_RUN_ERR("file not exsit, path is %s.", src_file_name);
        return CT_ERROR;
    }
    if (check_strcat_path(dst_info->path, file_name, dst_file_name) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("file path cat error, file is %s.", file_name);
        return CT_ERROR;
    }
    if (cm_exist_device(dst_info->type, dst_file_name) == CT_TRUE) {
        CT_LOG_RUN_INF("file exsit, path is %s.", dst_file_name);
        if (overwrite) {
            if (cm_remove_device(dst_info->type, dst_file_name) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("Failed to remove file, path is %s.", dst_file_name);
                return CT_ERROR;
            }
        } else{
            printf("File exsit, skip it, path is %s.\n", dst_file_name);
            return CT_SUCCESS;
        }
    }

    if (cm_open_device(src_file_name, src_info->type, O_RDONLY, &src_info->handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to open arch file: %s", src_file_name);
        cm_close_device(src_info->type, &src_info->handle);
        return CT_ERROR;
    }

    if (cm_create_device(dst_file_name, dst_info->type, 0, &dst_info->handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to create dbs file, file path is: %s.", dst_file_name);
        cm_close_device(src_info->type, &src_info->handle);
        cm_close_device(dst_info->type, &dst_info->handle);
        return CT_ERROR;
    }

    if (copy_file(src_info, dst_info) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to copy file from %s to %s.", src_file_name, dst_file_name);
        cm_close_device(src_info->type, &src_info->handle);
        cm_close_device(dst_info->type, &dst_info->handle);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t copy_files_to_target_dir(dbs_device_info_t *src_info, dbs_device_info_t *dst_info,
                                  const char *file_name, bool32 overwrite)
{
    status_t ret;
    uint32 file_num = 0;

    if (file_name != NULL) {
        ret = copy_file_by_name(file_name, src_info, dst_info, overwrite);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("Failed to copy file from source dir, file name is %s, src handle %d, dst handle %d.",
                           file_name, src_info->handle, dst_info->handle);
            return CT_ERROR;
        }
        printf("Copying file: %s\n", file_name);
        return CT_SUCCESS;
    }

    // 没有指定文件名则复制整个目录的所有文件
    void *file_list = NULL;
    if (cm_malloc_file_list(src_info->type, &file_list, src_info->path, &file_num) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to malloc file list.");
        return CT_ERROR;
    }

    ret = cm_query_device(src_info->type, src_info->path, file_list, &file_num);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to get file list, dir is %s.", src_info->path);
        cm_free_file_list(&file_list);
        return CT_ERROR;
    }

    for (uint32 i = 0; i < file_num; i++) {
        char *current_file_name = cm_get_name_from_file_list(src_info->type, file_list, i);
        if (current_file_name == NULL) {
            CT_LOG_RUN_ERR("Failed to get file name, please check info type %d.", src_info->type);
            cm_free_file_list(&file_list);
            return CT_ERROR;
        }
        if (cm_check_dir_type_by_file_list(src_info->type, file_list, i)) {
            continue;
        }

        ret = copy_file_by_name(current_file_name, src_info, dst_info, overwrite);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("Failed to copy file from source dir, file name is %s, src handle %d, dst handle %d.",
                           current_file_name, src_info->handle, dst_info->handle);
            cm_free_file_list(&file_list);
            return CT_ERROR;
        }
        printf("Copying file: %s\n", current_file_name);
        cm_close_device(src_info->type, &src_info->handle);
        cm_close_device(dst_info->type, &dst_info->handle);
    }

    cm_free_file_list(&file_list);

    CT_LOG_RUN_INF("Successfully copied files to %s.", dst_info->path);
    return CT_SUCCESS;
}

status_t check_dir_exist(const char *direction, const char *src_path, const char *dst_path,
                         char *fs_path, const char *fs_name)
{
    if (strncmp(direction, DBS_IMPORT_PARAM, strlen(DBS_IMPORT_PARAM)) == 0) {
        if (cm_dir_exist(src_path) != CT_TRUE) {
            printf("Source directory is does not exist %s\n", src_path);
            return CT_ERROR;
        }

        PRTS_RETURN_IFERR(snprintf_s(fs_path, MAX_DBS_FS_FILE_PATH_LEN,
                                     MAX_DBS_FS_FILE_PATH_LEN - 1, "/%s/%s", fs_name, dst_path));
        return CT_SUCCESS;
    }

    if (strncmp(direction, DBS_EXPORT_PARAM, strlen(DBS_EXPORT_PARAM)) == 0) {
        PRTS_RETURN_IFERR(snprintf_s(fs_path, MAX_DBS_FS_FILE_PATH_LEN,
                                     MAX_DBS_FS_FILE_PATH_LEN - 1, "/%s/%s", fs_name, src_path));
        if (cm_dbs_exist_file(fs_path, DIR_TYPE) != CT_TRUE) {
            printf("Source directory is does not exist %s\n", fs_path);
            return CT_ERROR;
        }
        if (cm_dir_exist(dst_path) != CT_TRUE) {
            printf("Target directory is does not exist %s\n", dst_path);
            return CT_ERROR;
        }

        return CT_SUCCESS;
    }

    return CT_ERROR;
}

status_t dbs_copy_fs_file(int32 argc, char *argv[])
{
    char fs_name[MAX_DBS_FS_NAME_LEN] = {0};
    char file_name[MAX_DBS_FILE_PATH_LEN] = {0};
    char source_dir[MAX_DBS_FS_FILE_PATH_LEN] = {0};
    char target_dir[MAX_DBS_FILE_PATH_LEN] = {0};
    char overwrite[DBS_TOOL_PARAM_BOOL_LEN] = BOOL_FALSE;
    const char *params[] = {DBS_TOOL_PARAM_FS_NAME, DBS_TOOL_PARAM_FILE_NAME, DBS_TOOL_PARAM_SOURCE_DIR,
                             DBS_TOOL_PARAM_TARGET_DIR, DBS_TOOL_PARAM_OVERWRITE};
    char *results[] = {fs_name, file_name, source_dir, target_dir, overwrite};
    size_t result_lens[] = {MAX_DBS_FS_NAME_LEN, MAX_DBS_FILE_PATH_LEN, MAX_DBS_FS_FILE_PATH_LEN, MAX_DBS_FILE_PATH_LEN,
                             DBS_TOOL_PARAM_BOOL_LEN};
    params_check_list_t check_list[] = {{DBS_TOOL_PARAM_FS_NAME, fs_name}, {DBS_TOOL_PARAM_SOURCE_DIR, source_dir},
                                         {DBS_TOOL_PARAM_TARGET_DIR, target_dir}};
    params_list_t params_list = {params, results, result_lens, check_list, DBS_COPY_FILE_PRAMA_NUM,
                                  DBS_COPY_FILE_CHECK_PRAMA_NUM};
    if (parse_params_list(argc, argv, &params_list) != CT_SUCCESS) {
        printf("Invalid command.\nUsage: --copy-file --import --fs-name=xxx --source-dir=* --target-dir=* "
               "[--file-name=*] [--overwrite]\n");
        return CT_ERROR;
    }
    char file_system_path[MAX_DBS_FS_FILE_PATH_LEN] = {0};
    if (check_dir_exist(argv[2], source_dir, target_dir, file_system_path, fs_name) != CT_SUCCESS) {
        return CT_ERROR;
    }
    dbs_device_info_t src_info = {.handle = -1, .path = ""};
    dbs_device_info_t dst_info = {.handle = -1, .path = ""};

    if (strncmp(argv[2], DBS_IMPORT_PARAM, strlen(DBS_IMPORT_PARAM)) == 0) {
        src_info.type = DEV_TYPE_FILE;
        dst_info.type = DEV_TYPE_DBSTOR_FILE;
        MEMS_RETURN_IFERR(strncpy_s(src_info.path, MAX_DBS_FS_FILE_PATH_LEN, source_dir, strlen(source_dir)));
        MEMS_RETURN_IFERR(strncpy_s(dst_info.path, MAX_DBS_FS_FILE_PATH_LEN,
                                    file_system_path, strlen(file_system_path)));
    } else if (strncmp(argv[2], DBS_EXPORT_PARAM, strlen(DBS_EXPORT_PARAM)) == 0) {
        src_info.type = DEV_TYPE_DBSTOR_FILE;
        dst_info.type = DEV_TYPE_FILE;
        MEMS_RETURN_IFERR(strncpy_s(src_info.path, MAX_DBS_FS_FILE_PATH_LEN,
                                    file_system_path, strlen(file_system_path)));
        MEMS_RETURN_IFERR(strncpy_s(dst_info.path, MAX_DBS_FS_FILE_PATH_LEN, target_dir, strlen(target_dir)));
    } else {
        printf("Invalid command, Missing parameters '--import/--export'.\n");
        return CT_ERROR;
    }
    // 将源文件或目录复制到目标目录
    if (copy_files_to_target_dir(&src_info, &dst_info, strlen(file_name) == 0 ? NULL : file_name,
                                 strncmp(overwrite, BOOL_TRUE, strlen(BOOL_TRUE)) == 0
                                     ? CT_TRUE : CT_FALSE) != CT_SUCCESS) {
        printf("Failed to copy files from %s to %s.\n", src_info.path, dst_info.path);
        return CT_ERROR;
    }
    printf("File(s) copied successfully from %s to %s.\n", src_info.path, dst_info.path);
    return CT_SUCCESS;
}

int32 dbs_set_io_forbidden(int32 argc, char *argv[])
{
    if (dbs_global_handle()->dbs_ns_io_forbidden == NULL) {
        printf("dbs_ns_io_forbidden is not support\n");
        return CT_ERROR;
    }

    if (argc != NUM_THREE) {
        printf("Invalid input, arg num %d\n", argc);
        printf("Usage: dbstor --io-forbidden <0, 1>t\n");
        return CT_ERROR;
    }
    bool isForbidden = (bool)atoi(argv[NUM_TWO]);
    status_t ret = dbs_global_handle()->dbs_ns_io_forbidden(g_dbs_fs_info.cluster_name, isForbidden);
    if (ret != CT_SUCCESS) {
        printf("Set ns forbidden failed(%d).\n", ret);
        return ret;
    }
    printf("Set ns forbidden success.\n");
    return ret;
}

status_t dbs_create_fs_snap(char* fsName, uint32_t vstorId, snapshot_result_info* snap_info)
{
    int32 ret;
    ret = dbs_global_handle()->create_fs_snap(fsName, vstorId, snap_info);
    if (ret != 0) {
        printf("Failed to create snapshot from fs %s, %s\n", fsName, ctbak_snap_error[ret]);
        CT_LOG_RUN_ERR("Failed to create snapshot from fs %s, %s", fsName, ctbak_snap_error[ret]);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t dbs_delete_fs_snap(char* fsName, uint32_t vstorId, snapshot_result_info* snap_info)
{
    SNAP_UUID_S snapUUID = {0};
    if (memcpy_s(snapUUID.buf, sizeof(snapUUID.buf), snap_info->snapUUID, sizeof(snap_info->snapUUID)) != EOK) {
        CT_LOG_RUN_ERR("Failed to delete snapshot of fs %s, get snapUUID failed", fsName);
        return CT_ERROR;
    }
    int32 ret;
    ret = dbs_global_handle()->delete_fs_snap(fsName, vstorId, snap_info->snapshotID, snap_info->timepoint, snapUUID);
    if (ret != 0) {
        CT_LOG_RUN_ERR("Failed to delete snapshot of fs %s", fsName);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t dbs_create_snapshot_info_file(const char *file_name, int32 *handle)
{
    if (cm_dbs_create_file(file_name, handle)!= CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to create snapshot_info_file %s", file_name);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t dbs_write_snapshot_info_file(int32 handle, int64 offset, const void *buf, int32 size)
{

    if (cm_dbs_write_file(handle, offset, buf, size) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to write snapshot_info_file");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t dbs_read_snapshot_info_file(object_id_t* handle, uint64 offset, void* buf, uint32 length)
{
    if (cm_read_dbs_file(handle, offset, buf, length)!= CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to read snapshot_info_file");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t ctbak_get_file_handle_from_share_fs(char *file_path, char *file_name, object_id_t *file_handle)
{
    char full_file_path[CT_MAX_FILE_PATH_LENGH] = { 0 };

    int ret = snprintf_s(full_file_path, CT_MAX_FILE_PATH_LENGH, CT_MAX_FILE_PATH_LENGH - 1, "/%s/%s", file_path, file_name);
    if (ret == CT_ERROR) {
        CT_LOG_RUN_ERR("Failed to get full file path");
        return CT_ERROR;
    }

    if (cm_get_dbs_last_file_handle(full_file_path, file_handle)) {
        printf("[ctbackup]Failed to get file handle\n");
        return CT_ERROR;
    }
    printf("[ctbackup]get file from share fs success.\n");
    return CT_SUCCESS;
}