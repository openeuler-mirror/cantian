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
 * dbs_adp.c
 *
 *
 * IDENTIFICATION
 * src/dbstool/dbs_adp.c
 *
 * -------------------------------------------------------------------------
 */

#include <stdio.h>
#include <sys/file.h>
#include <dirent.h>
#include "dbs_adp.h"
#include "cm_date.h"
#include "cm_error.h"
#include "cm_file.h"
#include "cm_dbstore.h"
#include "cm_dbs_defs.h"
#include "cm_log.h"
#include "cm_dbs_intf.h"
#include "cm_config.h"
#include "cm_utils.h"
#include "cm_dbs_file.h"

#define DBS_CONFIG_FILE_NAME_LEN 32
#define DBS_WAIT_CONFIG_RETRY_NUM 2
#define DBS_WAIT_CONFIG_INTERVAL_TIME 2000
#define DBS_CONFIG_MAX_PARAM 256
#define DBS_CLUSTER_UUID_LEN 37

#define DBS_TOOL_CONFIG_PATH "/opt/cantian/dbstor/conf/dbs"
#define DBS_CANTIAN_CONFIG_PATH "/mnt/dbdata/local/cantian/tmp/data/dbstor/conf/dbs/dbstor_config.ini"
#define DBS_CMS_CONFIG_PATH "/opt/cantian/cms/dbstor/conf/dbs/dbstor_config.ini"
#define DBS_HOME_PATH "/opt/cantian"
#define ARCHIVE_DEST_PATH "ARCHIVE_DEST_1"
#define CANTIAND_INI_FILE_NAME "cantiand.ini"
#define DEV_RW_BUFFER_SIZE (1 * 1024 * 1024)
#define DBS_TOOL_PARAM_SOURCE_DIR "--source-dir="
#define DBS_TOOL_PARAM_TARGET_DIR "--target-dir="
#define DBS_TOOL_PARAM_ARCH_FILE "--arch-file="
#define DBS_TOOL_PARAM_FS_NAME "--fs-name="
#define DBS_TOOL_PARAM_CLUSTER_NAME "--cluster-name="
#define DBS_TOOL_PARAM_FILE_NAME "--file-name="
#define DBS_TOOL_PARAM_FILE_PATH "--file-path="
#define DBS_TOOL_PARAM_VSTORE_ID "--vstore_id="
#define MAX_VALUE_UINT32 "4294967295"
#define DBS_LINK_CHECK_CNT "LINK_CHECK_CNT"
#define DBS_LINK_CHECK_PARAM_LEN 64
#define DBS_LINK_TIMEOUT_MIN 3
#define DBS_LINK_TIMEOUT_MAX 10

#define DBS_ARCH_QUERY_PRAMA_NUM 1
#define DBS_ARCH_CLEAN_PRAMA_NUM 1
#define DBS_ARCH_EXPORT_PRAMA_NUM 3
#define DBS_ARCH_IMPORT_PRAMA_NUM 3
#define DBS_ULOG_CLEAN_PRAMA_NUM 3
#define DBS_PGPOOL_CLEAN_PRAMA_NUM 2
#define DBS_CRAETE_FILE_PRAMA_NUM 3
#define DBS_COPY_FILE_PRAMA_NUM 4
#define DBS_DELETE_FILE_PRAMA_NUM 2
#define DBS_QUERY_FILE_PRAMA_NUM 2

#define DBS_NO_CHECK_PRAMA_NUM 0
#define DBS_ARCH_EXPORT_PRAMA_CHECK_NUM 1
#define DBS_ARCH_IMPORT_PRAMA_CHECK_NUM 1
#define DBS_ULOG_CLEAN_CHECK_PRAMA_NUM 3
#define DBS_PGPOOL_CLEAN_CHECK_PRAMA_NUM 2
#define DBS_CRAETE_FILE_CHECK_PRAMA_NUM 2
#define DBS_COPY_FILE_CHECK_PRAMA_NUM 3
#define DBS_DELETE_FILE_CHECK_PRAMA_NUM 2
#define DBS_QUERY_FILE_CHECK_PRAMA_NUM 2

typedef bool32 (*file_filter_func)(const char *);
typedef struct {
    char log_fs_name[MAX_DBS_FS_NAME_LEN];
    char page_fs_name[MAX_DBS_FS_NAME_LEN];
    char cluster_name[MAX_DBS_FILE_NAME_LEN];
    char log_fs_vstore_id[MAX_DBS_VSTORE_ID_LEN];
} dbs_fs_info_t;

dbs_fs_info_t g_dbs_fs_info = { 0 };

int32 g_lockConfigHandle = CT_INVALID_HANDLE;

typedef struct {
    device_type_t type;
    int32 handle;
    char path[MAX_DBS_FS_FILE_PATH_LEN];
} dbs_device_info_t;

typedef struct {
    char *key;
    char *value;
} params_check_list_t;

typedef struct {
    const char **keys;
    char **values;
    size_t *value_len;
    params_check_list_t *check_list;
    uint32 params_num;
    uint32 check_num;
} params_list_t;

status_t get_cantiand_ini_file_name(char *cantiand_ini_file_path)
{
    const char *data_path = getenv("CTDB_DATA");
    if (data_path == NULL) {
        printf("get data dir error!\n");
        return CT_ERROR;
    }
    int32 iret_snprintf;
    iret_snprintf = snprintf_s(cantiand_ini_file_path, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s/cfg/%s",
                               data_path, CANTIAND_INI_FILE_NAME);
    PRTS_RETURN_IFERR(iret_snprintf);
    return CT_SUCCESS;
}

status_t get_archive_location(const char *file_name, const char *conf_name, char *location_value)
{
    char file_buf[CT_MAX_CONFIG_FILE_SIZE] = {0};
    uint32 text_size = sizeof(file_buf);
    if (cm_read_config_file(file_name, file_buf, &text_size, CT_FALSE, CT_FALSE) != CT_SUCCESS) {
        printf("read config file failed!, the file_name is %s.\n", file_name);
        return CT_ERROR;
    }
    text_t text;
    text_t line;
    text_t name;
    text_t value;
    text.len = text_size;
    text.str = file_buf;

    while (cm_fetch_text(&text, '\n', '\0', &line)) {
        cm_trim_text(&line);
        if (line.len == 0 || *line.str == '#') {
            continue;
        }

        cm_split_text(&line, '=', '\0', &name, &value);
        cm_trim_text(&value);
        cm_text_upper(&name);
        cm_trim_text(&name);
        if (cm_text_str_equal_ins(&name, conf_name)) {
            char *location = strstr(value.str, "location=");
            if (location != NULL) {
                location += strlen("location=");
                cm_trim_text(&value);
                errno_t ret = strncpy_s(location_value, CT_PARAM_BUFFER_SIZE, location,
                    value.len - (location - value.str));
                return ret == EOK ? CT_SUCCESS : CT_ERROR;
            }
        }
    }
    return CT_ERROR;
}

status_t get_location_by_cfg(char *location_value)
{
    char cantiand_ini_file_name[CT_MAX_FILE_PATH_LENGH] = {0};
    status_t status = get_cantiand_ini_file_name(cantiand_ini_file_name);
    if (status != CT_SUCCESS) {
        printf("Failed to get cantiand ini file. Status: %d\n", status);
        return CT_ERROR;
    }

    status = get_archive_location(cantiand_ini_file_name, ARCHIVE_DEST_PATH, location_value);
    if (status != CT_SUCCESS) {
        printf("Failed to get archive location from config. Ini file: %s, Status: %d\n",
            cantiand_ini_file_name, status);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t check_data_dir_empty(const char *path)
{
    struct dirent *dirp = NULL;
    DIR *dir = opendir(path);
    if (dir == NULL) {
        printf("param datadir %s open failed, error code %d\n", path, errno);
        return CT_ERROR;
    }
    while ((dirp = readdir(dir)) != NULL) {
        if (strcmp(dirp->d_name, ".") && strcmp(dirp->d_name, "..")) {
            printf("param datadir %s is not empty\n", path);
            (void)closedir(dir);
            return CT_ERROR;
        }
    }
    (void)closedir(dir);
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

status_t copy_file_by_name(const char *file_name, dbs_device_info_t *src_info, dbs_device_info_t *dst_info)
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
        return CT_ERROR;
    }
    if (cm_exist_device(dst_info->type, dst_file_name) == CT_TRUE) {
        CT_LOG_RUN_INF("file exsit, path is %s.", dst_file_name);
        return CT_SUCCESS;
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

status_t copy_arch_files_to_target_dir(dbs_device_info_t *src_info, dbs_device_info_t *dst_info, const char *arch_file)
{
    status_t ret;
    uint32 file_num = 0;

    if (arch_file != NULL) {
        ret = copy_file_by_name(arch_file, src_info, dst_info);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("Failed to copy file from target dir, file name is %s, src handle %d, dst handle %d.",
                           arch_file, src_info->handle, dst_info->handle);
            return CT_ERROR;
        }
        printf("%s\n", arch_file);
        return CT_SUCCESS;
    }

    void *file_list = NULL;
    if (cm_malloc_file_list(src_info->type, &file_list) != CT_SUCCESS) {
        return CT_ERROR;
    }
    
    ret = cm_query_device(src_info->type, src_info->path, file_list, &file_num);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to get file list, dir is %s.", src_info->path);
        cm_free_file_list(&file_list);
        return CT_ERROR;
    }

    for (uint32 i = 0; i < file_num; i++) {
        char *file_name = cm_get_name_from_file_list(src_info->type, file_list, i);
        if (file_name == NULL) {
            CT_LOG_RUN_ERR("Failed to get file name, please check info type %d.", src_info->type);
            cm_free_file_list(&file_list);
            return CT_ERROR;
        }
        if (!cm_match_arch_pattern(file_name)) {
            continue;
        }
        ret = copy_file_by_name(file_name, src_info, dst_info);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("Failed to copy file from target dir, file name is %s, src handle %d, dst handle %d.",
                           file_name, src_info->handle, dst_info->handle);
            cm_free_file_list(&file_list);
            return CT_ERROR;
        }
        printf("%s\n", file_name);
        cm_close_device(src_info->type, &src_info->handle);
        cm_close_device(dst_info->type, &dst_info->handle);
    }
    cm_free_file_list(&file_list);
    
    CT_LOG_RUN_INF("Successfully copied files to %s.", dst_info->path);
    return CT_SUCCESS;
}

status_t copy_files_to_target_dir(dbs_device_info_t *src_info, dbs_device_info_t *dst_info, const char *file_name)
{
    status_t ret;
    uint32 file_num = 0;

    if (file_name != NULL) {
        ret = copy_file_by_name(file_name, src_info, dst_info);
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
    if (cm_malloc_file_list(src_info->type, &file_list) != CT_SUCCESS) {
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

        ret = copy_file_by_name(current_file_name, src_info, dst_info);
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
            printf("memset_s dbs_conf_file_path failed!\n");
            break;
        }
        ret = sprintf_s(dbs_conf_file_path, CT_FILE_NAME_BUFFER_SIZE, "%s/%s", dbs_conf_dir_path, entry->d_name);
        if (ret == -1) {
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

status_t dbs_alloc_conf_file_retry(char *config_name)
{
    uint32_t retry_num = DBS_WAIT_CONFIG_RETRY_NUM;
    do {
        int32_t ret = memset_s(config_name, DBS_CONFIG_FILE_NAME_LEN, 0, DBS_CONFIG_FILE_NAME_LEN);
        if (ret != EOK) {
            CT_LOG_RUN_ERR("memset_s config_name failed!");
            return CT_ERROR;
        }
        if (dbs_get_and_flock_conf_file(config_name) == CT_SUCCESS) {
            return CT_SUCCESS;
        }
        retry_num--;
        cm_sleep(DBS_WAIT_CONFIG_INTERVAL_TIME);
    } while (retry_num > 0);

    printf("Get free dbstor config file timeout, please wait a while and try again.\n");
    return CT_ERROR;
}

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

status_t dbs_get_fs_info_from_config(char* cfg_name)
{
    char file_path[CT_FILE_NAME_BUFFER_SIZE];
    char line[DBS_CONFIG_MAX_PARAM];
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
        }
        if (result != CT_SUCCESS) {
            CT_LOG_RUN_ERR("get param value failed, line %s.", line);
            break;
        }
    }
    (void)fclose(fp);
    return result;
}

status_t dbs_get_uuid_lsid_from_config(char* cfg_name, uint32* lsid, char* uuid)
{
    char file_path[CT_FILE_NAME_BUFFER_SIZE];
    char line[DBS_CONFIG_MAX_PARAM];
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

status_t dbstool_init()
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
    return CT_SUCCESS;
}

status_t compare_param(char *argv[], params_list_t *params_list, uint32 i, uint32 j, bool32 *matched)
{
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

status_t parse_params_list(int32 argc, char *argv[], params_list_t *params_list)
{
    for (uint32 i = 2; i < argc; i++) {
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
        if (strlen(params_list->check_list->value) == 0) {
            printf("%s not specified.\n", params_list->check_list->key);
            return CT_ERROR;
        }
        if (strcmp(params_list->check_list->key, DBS_TOOL_PARAM_VSTORE_ID) == 0) {
            if (strcmp(params_list->check_list->value, MAX_VALUE_UINT32) > 0) {
                printf("Invalid vstore_id %s.\n", params_list->check_list->value);
                return CT_ERROR;
            }
        }
    }
    return CT_SUCCESS;
}

status_t dbs_get_arch_location(char *archive_location, const char *fs_name)
{
    if (strlen(fs_name) == 0) {
        if (get_location_by_cfg(archive_location) != CT_SUCCESS) {
            printf("Failed to get archive location.\n");
            return CT_ERROR;
        }
    } else {
        PRTS_RETURN_IFERR(snprintf_s(archive_location, MAX_DBS_FS_FILE_PATH_LEN,
            MAX_DBS_FS_FILE_PATH_LEN - 1, "/%s/archive", fs_name));
    }
    if (strlen(archive_location) == 0) {
        printf("Failed to get archive location,\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

int32 dbs_arch_import(int32 argc, char *argv[])
{
    char source_dir[MAX_DBS_FS_FILE_PATH_LEN] = {0};
    char arch_file[MAX_DBS_FILE_NAME_LEN] = {0};
    char archive_location[MAX_DBS_FS_FILE_PATH_LEN] = {0};
    char fs_name[MAX_DBS_FS_NAME_LEN] = {0};

    const char *params[] = {DBS_TOOL_PARAM_SOURCE_DIR, DBS_TOOL_PARAM_ARCH_FILE, DBS_TOOL_PARAM_FS_NAME};
    char *results[] = {source_dir, arch_file, fs_name};
    size_t result_lens[] = {MAX_DBS_FS_FILE_PATH_LEN, MAX_DBS_FILE_NAME_LEN, MAX_DBS_FS_NAME_LEN};
    params_check_list_t check_list[] = {{DBS_TOOL_PARAM_SOURCE_DIR, source_dir}};
    params_list_t params_list = {params, results, result_lens, check_list, DBS_ARCH_IMPORT_PRAMA_NUM,
                                 DBS_ARCH_IMPORT_PRAMA_CHECK_NUM};

    if (parse_params_list(argc, argv, &params_list) != CT_SUCCESS) {
        printf("Invalid command.\nUsage: --arch-import --source-dir=xxx [--arch-file=xxx] [--fs-name=xxx]\n");
        return CT_ERROR;
    }

    if (dbs_get_arch_location(archive_location, fs_name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dbs_device_info_t src_info = { .handle = -1, .type = DEV_TYPE_FILE, .path = "" };
    dbs_device_info_t dst_info = { .handle = -1, .type = DEV_TYPE_DBSTOR_FILE, .path = "" };

    MEMS_RETURN_IFERR(strncpy_sp(src_info.path, MAX_DBS_FS_FILE_PATH_LEN, source_dir, strlen(source_dir)));
    MEMS_RETURN_IFERR(strncpy_sp(dst_info.path, MAX_DBS_FS_FILE_PATH_LEN, archive_location, strlen(archive_location)));

    if (copy_arch_files_to_target_dir(&src_info, &dst_info, strlen(arch_file) == 0 ? NULL : arch_file) != CT_SUCCESS) {
        printf("Failed to import archive files.\n");
        return CT_ERROR;
    }

    printf("Archive import successful.\n");
    return CT_SUCCESS;
}

int32 dbs_arch_export(int32 argc, char *argv[])
{
    char target_dir[MAX_DBS_FILE_PATH_LEN] = {0};
    char arch_file[MAX_DBS_FILE_NAME_LEN] = {0};
    char archive_location[MAX_DBS_FILE_PATH_LEN] = {0};
    char fs_name[MAX_DBS_FILE_NAME_LEN] = {0};

    const char *params[] = {DBS_TOOL_PARAM_TARGET_DIR, DBS_TOOL_PARAM_ARCH_FILE, DBS_TOOL_PARAM_FS_NAME};
    char *results[] = {target_dir, arch_file, fs_name};
    size_t result_lens[] = {MAX_DBS_FILE_PATH_LEN, MAX_DBS_FILE_PATH_LEN, MAX_DBS_FILE_NAME_LEN};
    params_check_list_t check_list[] = {{DBS_TOOL_PARAM_TARGET_DIR, target_dir}};
    params_list_t params_list = {params, results, result_lens, check_list, DBS_ARCH_EXPORT_PRAMA_NUM,
                                 DBS_ARCH_EXPORT_PRAMA_CHECK_NUM};

    if (parse_params_list(argc, argv, &params_list) != CT_SUCCESS) {
        printf("Invalid command.\nUsage: --arch-export --target-dir=xxx [--arch-file=xxx] [--fs-name=xxx]\n");
        return CT_ERROR;
    }

    if (check_data_dir_empty(target_dir) != CT_SUCCESS) {
        printf("Target directory is not empty or not exist.\n");
        return CT_ERROR;
    }

    if (dbs_get_arch_location(archive_location, fs_name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dbs_device_info_t src_info = { .handle = -1, .type = DEV_TYPE_DBSTOR_FILE, .path = "" };
    dbs_device_info_t dst_info = { .handle = -1, .type = DEV_TYPE_FILE, .path = "" };
    MEMS_RETURN_IFERR(strncpy_sp(src_info.path, CT_MAX_FILE_PATH_LENGH, archive_location, strlen(archive_location)));
    MEMS_RETURN_IFERR(strncpy_sp(dst_info.path, CT_MAX_FILE_PATH_LENGH, target_dir, strlen(target_dir)));

    if (copy_arch_files_to_target_dir(&src_info, &dst_info, strlen(arch_file) == 0 ? NULL : arch_file) != CT_SUCCESS) {
        printf("Failed to export archive files.\n");
        return CT_ERROR;
    }

    printf("Archive export successful.\n");
    return CT_SUCCESS;
}

status_t dbs_clean_files(dbs_device_info_t *src_info, void *file_list, uint32 file_num, file_filter_func filter_func)
{
    CT_LOG_RUN_INF("[DBSTOR] Removed files in dir %s", src_info->path);
    printf("Remove files list:\n");
    for (uint32 i = 0; i < file_num; i++) {
        char file_path[MAX_DBS_FS_FILE_PATH_LEN] = { 0 };
        char *file_name = cm_get_name_from_file_list(src_info->type, file_list, i);
        if (file_name == NULL) {
            printf("Failed to get file name.\n");
            return CT_ERROR;
        }

        if (filter_func != NULL && filter_func(file_name) == CT_TRUE) {
            continue;
        }

        PRTS_RETURN_IFERR(snprintf_s(file_path, MAX_DBS_FS_FILE_PATH_LEN,
            MAX_DBS_FS_FILE_PATH_LEN - 1, "%s/%s", src_info->path, file_name));

        if (cm_remove_device(src_info->type, file_path) != CT_SUCCESS) {
            printf("remove file failed, file name %s\n", file_name);
            CT_LOG_RUN_ERR("[DBSTOR] remove file failed, file name %s", file_name);
            return CT_ERROR;
        }
        printf("%s\n", file_name);
        CT_LOG_RUN_INF("[DBSTOR] Removed file: %s\n", file_name);
    }
    printf("Remove files successful.\n");
    return CT_SUCCESS;
}

status_t dbs_clean_files_ulog(uint32 vstore_id, dbs_device_info_t *src_info, void *file_list,
                              uint32 file_num, file_filter_func filter_func)
{
    CT_LOG_RUN_INF("[DBSTOR] Removed files in dir %s", src_info->path);
    printf("Remove files list:\n");
    for (uint32 i = 0; i < file_num; i++) {
        char file_path[MAX_DBS_FS_FILE_PATH_LEN] = { 0 };
        char *file_name = cm_get_name_from_file_list(src_info->type, file_list, i);
        if (file_name == NULL) {
            printf("Failed to get file name.\n");
            return CT_ERROR;
        }

        if (filter_func != NULL && filter_func(file_name) == CT_TRUE) {
            continue;
        }

        PRTS_RETURN_IFERR(snprintf_s(file_path, MAX_DBS_FS_FILE_PATH_LEN,
            MAX_DBS_FS_FILE_PATH_LEN - 1, "%s/%s", src_info->path, file_name));

        if (cm_dbs_remove_file_vstore_id(vstore_id, file_path) != CT_SUCCESS) {
            printf("remove file failed, file name %s\n", file_name);
            CT_LOG_RUN_ERR("[DBSTOR] remove file failed, file name %s", file_name);
            return CT_ERROR;
        }
        printf("%s\n", file_name);
        CT_LOG_RUN_INF("[DBSTOR] Removed file: %s\n", file_name);
    }
    printf("Remove files successful.\n");
    return CT_SUCCESS;
}

bool32 arch_file_filter(const char *file_name)
{
    return !cm_match_arch_pattern(file_name) && strstr(file_name, "arch_file.tmp") == NULL;
}

// dbstor --arch-clean [--fs-name=xxx]
int32 dbs_arch_clean(int32 argc, char *argv[])
{
    char fs_name[MAX_DBS_FS_NAME_LEN] = {0};
    char archive_location[MAX_DBS_FS_FILE_PATH_LEN] = {0};

    const char *params[] = {DBS_TOOL_PARAM_FS_NAME};
    char *results[] = {fs_name};
    size_t result_lens[] = {MAX_DBS_FS_NAME_LEN};
    params_list_t params_list = {params, results, result_lens, NULL, DBS_ARCH_CLEAN_PRAMA_NUM, DBS_NO_CHECK_PRAMA_NUM};

    if (parse_params_list(argc, argv, &params_list) != CT_SUCCESS) {
        printf("Invalid command.\nUsage: --arch-clean [--fs-name=xxx]\n");
        return CT_ERROR;
    }

    if (dbs_get_arch_location(archive_location, fs_name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    void *file_list = NULL;
    uint32 file_num = 0;
    dbs_device_info_t src_info = { .handle = -1, .type = DEV_TYPE_DBSTOR_FILE, .path = "" };
    MEMS_RETURN_IFERR(strncpy_s(src_info.path, MAX_DBS_FS_FILE_PATH_LEN, archive_location, strlen(archive_location)));

    if (cm_malloc_file_list(src_info.type, &file_list) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cm_query_device(src_info.type, src_info.path, file_list, &file_num) != CT_SUCCESS) {
        printf("Failed to get file list, dir is %s.\n", src_info.path);
        cm_free_file_list(&file_list);
        return CT_ERROR;
    }

    if (dbs_clean_files(&src_info, file_list, file_num, arch_file_filter) != CT_SUCCESS) {
        printf("Archive files clean failed.\n");
        cm_free_file_list(&file_list);
        return CT_ERROR;
    }

    cm_free_file_list(&file_list);
    printf("Archive files clean successful.\n");
    return CT_SUCCESS;
}

// dbstor --arch-query [--fs-name=xxx]
int32 dbs_arch_query(int32 argc, char *argv[])
{
    char fs_name[MAX_DBS_FS_NAME_LEN] = {0};
    char archive_location[MAX_DBS_FS_FILE_PATH_LEN] = {0};

    const char *params[] = {DBS_TOOL_PARAM_FS_NAME};
    char *results[] = {fs_name};
    size_t result_lens[] = {MAX_DBS_FS_NAME_LEN};
    params_list_t params_list = {params, results, result_lens, NULL, DBS_ARCH_QUERY_PRAMA_NUM, DBS_NO_CHECK_PRAMA_NUM};

    if (parse_params_list(argc, argv, &params_list) != CT_SUCCESS) {
        printf("Invalid command.\nUsage: --arch-query [--fs-name=xxx]\n");
        return CT_ERROR;
    }

    if (dbs_get_arch_location(archive_location, fs_name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    void *file_list = NULL;
    uint32 file_num = 0;
    dbs_device_info_t src_info = { .handle = -1, .type = DEV_TYPE_DBSTOR_FILE, .path = "" };
    MEMS_RETURN_IFERR(strncpy_s(src_info.path, MAX_DBS_FS_FILE_PATH_LEN, archive_location, strlen(archive_location)));

    if (cm_exist_device_dir(src_info.type, src_info.path) != CT_TRUE) {
        printf("Failed to get file list, the archive dir does not exist\n");
        return CT_ERROR;
    }

    if (cm_malloc_file_list(src_info.type, &file_list) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cm_query_device(src_info.type, src_info.path, file_list, &file_num) != CT_SUCCESS) {
        printf("Failed to get file list, dir is %s.\n", src_info.path);
        cm_free_file_list(&file_list);
        return CT_ERROR;
    }

    printf("Archive files list:\n");
    for (uint32 i = 0; i < file_num; i++) {
        char *file_name = cm_get_name_from_file_list(src_info.type, file_list, i);
        if (file_name == NULL) {
            printf("Failed to get file name.\n");
            cm_free_file_list(&file_list);
            return CT_ERROR;
        }
        if (cm_match_arch_pattern(file_name) == CT_FALSE) {
            continue;
        }
        printf("%s\n", file_name);
        CT_LOG_RUN_INF("File: %s\n", file_name);
    }

    cm_free_file_list(&file_list);
    printf("Archive query successful.\n");
    return CT_SUCCESS;
}

bool32 ulog_file_filter(const char *file_name)
{
    return strcmp(file_name, g_dbs_fs_info.cluster_name) == 0;
}

// dbstor --ulog-clean [--fs-name=xxx] [--cluster-name=xxx]
int32 dbs_ulog_clean(int32 argc, char *argv[])
{
    char fs_name[MAX_DBS_FS_NAME_LEN] = {0};
    char cluster_name[MAX_DBS_FILE_PATH_LEN] = {0};
    char vstore_id[MAX_DBS_VSTORE_ID_LEN] = {0};
    MEMS_RETURN_IFERR(strncpy_s(fs_name, MAX_DBS_FS_NAME_LEN, g_dbs_fs_info.log_fs_name,
                                strlen(g_dbs_fs_info.log_fs_name)));
    MEMS_RETURN_IFERR(strncpy_s(cluster_name, MAX_DBS_FILE_PATH_LEN, g_dbs_fs_info.cluster_name,
                                strlen(g_dbs_fs_info.cluster_name)));
    MEMS_RETURN_IFERR(strncpy_s(vstore_id, MAX_DBS_VSTORE_ID_LEN, g_dbs_fs_info.log_fs_vstore_id,
                                strlen(g_dbs_fs_info.log_fs_vstore_id)));

    const char *params[] = {DBS_TOOL_PARAM_FS_NAME, DBS_TOOL_PARAM_CLUSTER_NAME, DBS_TOOL_PARAM_VSTORE_ID};
    char *results[] = {fs_name, cluster_name, vstore_id};
    size_t result_lens[] = {MAX_DBS_FS_NAME_LEN, MAX_DBS_FILE_PATH_LEN, MAX_DBS_VSTORE_ID_LEN};
    params_check_list_t check_list[] = {{DBS_TOOL_PARAM_FS_NAME, fs_name}, {DBS_TOOL_PARAM_CLUSTER_NAME, cluster_name},
                                        {DBS_TOOL_PARAM_VSTORE_ID, vstore_id}};
    params_list_t params_list = {params, results, result_lens, check_list, DBS_ULOG_CLEAN_PRAMA_NUM,
                                 DBS_ULOG_CLEAN_CHECK_PRAMA_NUM};

    if (parse_params_list(argc, argv, &params_list) != CT_SUCCESS) {
        printf("Invalid command.\nUsage: --ulog-clean [--fs-name=xxx] [--cluster-name=xxx] [--vstore_id=xxx]\n");
        return CT_ERROR;
    }
    uint32 vstore_id_uint = (uint32)atoi(vstore_id);
    char ulog_path[MAX_DBS_FS_FILE_PATH_LEN] = {0};
    PRTS_RETURN_IFERR(snprintf_s(ulog_path, MAX_DBS_FS_FILE_PATH_LEN,
        MAX_DBS_FS_FILE_PATH_LEN - 1, "/%s/%s", fs_name, cluster_name));

    void *file_list = NULL;
    uint32 file_num = 0;
    dbs_device_info_t src_info = { .handle = -1, .type = DEV_TYPE_DBSTOR_FILE, .path = "" };
    MEMS_RETURN_IFERR(strncpy_s(src_info.path, MAX_DBS_FS_FILE_PATH_LEN, ulog_path, strlen(ulog_path)));

    if (cm_malloc_file_list(src_info.type, &file_list) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cm_dbs_query_dir_vstore_id(vstore_id_uint, src_info.path, file_list, &file_num) != CT_SUCCESS) {
        printf("Failed to get file list, dir is %s.\n", src_info.path);
        cm_free_file_list(&file_list);
        return CT_ERROR;
    }

    if (dbs_clean_files_ulog(vstore_id_uint, &src_info, file_list, file_num, ulog_file_filter) != CT_SUCCESS) {
        printf("ULOG clean failed.\n");
        cm_free_file_list(&file_list);
        return CT_ERROR;
    }

    cm_free_file_list(&file_list);
    printf("ULOG clean successful.\n");
    return CT_SUCCESS;
}

bool32 page_file_filter(const char *file_name)
{
    return strcmp(file_name, "SplitLsnInfo") == 0;
}

// dbstor --pagepool-clean [--fs-name=xxx] [--cluster-name=xxx]
int32 dbs_pagepool_clean(int32 argc, char *argv[])
{
    char fs_name[MAX_DBS_FS_NAME_LEN] = {0};
    char cluster_name[MAX_DBS_FILE_PATH_LEN] = {0};
    MEMS_RETURN_IFERR(strncpy_s(fs_name, MAX_DBS_FS_NAME_LEN, g_dbs_fs_info.page_fs_name,
                                strlen(g_dbs_fs_info.page_fs_name)));
    MEMS_RETURN_IFERR(strncpy_s(cluster_name, MAX_DBS_FILE_PATH_LEN, g_dbs_fs_info.cluster_name,
                                strlen(g_dbs_fs_info.cluster_name)));

    const char *params[] = {DBS_TOOL_PARAM_FS_NAME, DBS_TOOL_PARAM_CLUSTER_NAME};
    char *results[] = {fs_name, cluster_name};
    size_t result_lens[] = {MAX_DBS_FS_NAME_LEN, MAX_DBS_FILE_PATH_LEN};
    params_check_list_t check_list[] = {{DBS_TOOL_PARAM_FS_NAME, fs_name}, {DBS_TOOL_PARAM_CLUSTER_NAME, cluster_name}};
    params_list_t params_list = {params, results, result_lens, check_list, DBS_PGPOOL_CLEAN_PRAMA_NUM,
                                 DBS_PGPOOL_CLEAN_CHECK_PRAMA_NUM};

    if (parse_params_list(argc, argv, &params_list) != CT_SUCCESS) {
        printf("Invalid command.\nUsage: --pagepool-clean [--fs-name=xxx] [--cluster-name=xxx]\n");
        return CT_ERROR;
    }
    char pagepool_path[MAX_DBS_FS_FILE_PATH_LEN] = {0};
    PRTS_RETURN_IFERR(snprintf_s(pagepool_path, MAX_DBS_FS_FILE_PATH_LEN,
        MAX_DBS_FS_FILE_PATH_LEN - 1, "/%s/%s", fs_name, cluster_name));

    void *file_list = NULL;
    uint32 file_num = 0;
    dbs_device_info_t src_info = { .handle = -1, .type = DEV_TYPE_DBSTOR_FILE, .path = "" };
    MEMS_RETURN_IFERR(strncpy_s(src_info.path, MAX_DBS_FS_FILE_PATH_LEN, pagepool_path, strlen(pagepool_path)));

    if (cm_malloc_file_list(src_info.type, &file_list) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cm_query_device(src_info.type, src_info.path, file_list, &file_num) != CT_SUCCESS) {
        printf("Failed to get file list, dir is %s.\n", src_info.path);
        cm_free_file_list(&file_list);
        return CT_ERROR;
    }

    if (dbs_clean_files(&src_info, file_list, file_num, page_file_filter) != CT_SUCCESS) {
        printf("Pagepool clean failed.\n");
        cm_free_file_list(&file_list);
        return CT_ERROR;
    }

    cm_free_file_list(&file_list);
    printf("Pagepool clean successful.\n");
    return CT_SUCCESS;
}

// dbstor --create-file --fs-name=xxx --file-name=xxx [--source-dir=xxx]
// 创建文件或目录（'/'结尾）。如果指定了 source-dir 参数，则从 source-dir 复制（覆盖）文件内容到目标位置。
int32 dbs_create_path_or_file(int32 argc, char *argv[])
{
    char fs_name[MAX_DBS_FS_NAME_LEN] = {0};
    char file_name[MAX_DBS_FILE_PATH_LEN] = {0};
    char source_dir[MAX_DBS_FS_FILE_PATH_LEN] = {0};

    const char *params[] = {DBS_TOOL_PARAM_FS_NAME, DBS_TOOL_PARAM_FILE_NAME, DBS_TOOL_PARAM_SOURCE_DIR};
    char *results[] = {fs_name, file_name, source_dir};
    size_t result_lens[] = {MAX_DBS_FS_NAME_LEN, MAX_DBS_FILE_PATH_LEN, MAX_DBS_FS_FILE_PATH_LEN};
    params_check_list_t check_list[] = {{DBS_TOOL_PARAM_FS_NAME, fs_name}, {DBS_TOOL_PARAM_FILE_NAME, file_name}};
    params_list_t params_list = {params, results, result_lens, check_list, DBS_CRAETE_FILE_PRAMA_NUM,
                                 DBS_CRAETE_FILE_CHECK_PRAMA_NUM};

    if (parse_params_list(argc, argv, &params_list) != CT_SUCCESS) {
        printf("Invalid command.\nUsage: --creat-file --fs-name=xxx --file-name=xxx [--source-dir=xxx]\n");
        return CT_ERROR;
    }
    char full_path[MAX_DBS_FS_FILE_PATH_LEN] = {0};
    PRTS_RETURN_IFERR(snprintf_s(full_path, MAX_DBS_FS_FILE_PATH_LEN,
                                 MAX_DBS_FS_FILE_PATH_LEN - 1, "/%s/%s", fs_name, file_name));

    dbs_device_info_t dst_info = { .handle = -1, .type = DEV_TYPE_DBSTOR_FILE, .path = "" };
    MEMS_RETURN_IFERR(strncpy_s(dst_info.path, MAX_DBS_FS_FILE_PATH_LEN, full_path, strlen(full_path)));

    status_t ret;

    if (strlen(source_dir) > 0) {
        dbs_device_info_t src_info = { .handle = -1, .type = DEV_TYPE_FILE, .path = "" };
        MEMS_RETURN_IFERR(strncpy_s(src_info.path, MAX_DBS_FS_FILE_PATH_LEN, source_dir, strlen(source_dir)));

        if (cm_exist_device(src_info.type, src_info.path) != CT_TRUE) {
            printf("Source file does not exist: %s\n", src_info.path);
            return CT_ERROR;
        }

        ret = cm_open_device(src_info.path, src_info.type, O_RDONLY, &src_info.handle);
        if (ret != CT_SUCCESS) {
            printf("Failed to open source file: %s\n", src_info.path);
            return CT_ERROR;
        }

        if (cm_exist_device(dst_info.type, dst_info.path) == CT_TRUE) {
            if (cm_remove_device(dst_info.type, dst_info.path) != CT_SUCCESS) {
                printf("Failed to remove existing file: %s\n", dst_info.path);
                cm_close_device(src_info.type, &src_info.handle);
                return CT_ERROR;
            }
        }

        ret = cm_create_device(dst_info.path, dst_info.type, 0, &dst_info.handle);
        if (ret != CT_SUCCESS) {
            printf("Failed to create destination file: %s\n", dst_info.path);
            cm_close_device(src_info.type, &src_info.handle);
            return CT_ERROR;
        }

        ret = copy_file(&src_info, &dst_info);

        cm_close_device(src_info.type, &src_info.handle);
        cm_close_device(dst_info.type, &dst_info.handle);

        if (ret != CT_SUCCESS) {
            printf("Failed to copy file from %s to %s\n", src_info.path, dst_info.path);
            return CT_ERROR;
        }

        printf("File copied successfully from %s to %s\n", src_info.path, dst_info.path);
    } else if (file_name[strlen(file_name) - 1] == '/') {  // 创建目录
        ret = cm_create_device_dir(dst_info.type, dst_info.path);
        if (ret != CT_SUCCESS) {
            printf("Failed to create directory: %s\n", dst_info.path);
            return CT_ERROR;
        }
        printf("Directory created successfully: %s\n", dst_info.path);
    } else { // 创建文件
        ret = cm_create_device(dst_info.path, dst_info.type, 0, &dst_info.handle);
        if (ret != CT_SUCCESS) {
            printf("Failed to create file: %s\n", dst_info.path);
            return CT_ERROR;
        }
        cm_close_device(dst_info.type, &dst_info.handle);
        printf("File created successfully: %s\n", dst_info.path);
    }

    return CT_SUCCESS;
}

// dbstor --copy-file --fs-name=* --source-dir=* --target-dir=* [--file-name=*]
int32 dbs_copy_file(int32 argc, char *argv[])
{
    char source_dir[MAX_DBS_FS_FILE_PATH_LEN] = {0};
    char target_dir[MAX_DBS_FILE_PATH_LEN] = {0};
    char file_name[MAX_DBS_FILE_PATH_LEN] = {0};
    char fs_name[MAX_DBS_FS_NAME_LEN] = {0};

    const char *params[] = {DBS_TOOL_PARAM_SOURCE_DIR, DBS_TOOL_PARAM_TARGET_DIR,
                            DBS_TOOL_PARAM_FILE_NAME, DBS_TOOL_PARAM_FS_NAME};
    char *results[] = {source_dir, target_dir, file_name, fs_name};
    size_t result_lens[] = {MAX_DBS_FS_FILE_PATH_LEN, MAX_DBS_FILE_PATH_LEN,
                            MAX_DBS_FILE_PATH_LEN, MAX_DBS_FS_NAME_LEN};
    params_check_list_t check_list[] = {{DBS_TOOL_PARAM_FS_NAME, fs_name}, {DBS_TOOL_PARAM_TARGET_DIR, target_dir},
                                        {DBS_TOOL_PARAM_SOURCE_DIR, source_dir}};
    params_list_t params_list = {params, results, result_lens, check_list, DBS_COPY_FILE_PRAMA_NUM,
                                 DBS_COPY_FILE_CHECK_PRAMA_NUM};

    if (parse_params_list(argc, argv, &params_list) != CT_SUCCESS) {
        printf("Invalid command.\nUsage: --copy-file --fs-name=* --source-dir=* --target-dir=* --file-name=*\n");
        return CT_ERROR;
    }

    if (cm_dir_exist(target_dir) != CT_TRUE) {
        printf("Target directory is does not exist.\n");
        return CT_ERROR;
    }

    char src_file_path[MAX_DBS_FS_FILE_PATH_LEN] = {0};
    PRTS_RETURN_IFERR(snprintf_s(src_file_path, MAX_DBS_FS_FILE_PATH_LEN,
                                    MAX_DBS_FS_FILE_PATH_LEN - 1, "/%s/%s", fs_name, source_dir));

    dbs_device_info_t src_info = { .handle = -1, .type = DEV_TYPE_DBSTOR_FILE, .path = "" };
    dbs_device_info_t dst_info = { .handle = -1, .type = DEV_TYPE_FILE, .path = "" };

    MEMS_RETURN_IFERR(strncpy_s(src_info.path, MAX_DBS_FS_FILE_PATH_LEN, src_file_path, strlen(src_file_path)));
    MEMS_RETURN_IFERR(strncpy_s(dst_info.path, MAX_DBS_FS_FILE_PATH_LEN, target_dir, strlen(target_dir)));

    // 将源文件或目录复制到目标目录
    if (copy_files_to_target_dir(&src_info, &dst_info, strlen(file_name) == 0 ? NULL : file_name) != CT_SUCCESS) {
        printf("Failed to copy files from %s to %s.\n", src_info.path, dst_info.path);
        return CT_ERROR;
    }

    printf("File(s) copied successfully from %s to %s.\n", src_info.path, dst_info.path);
    return CT_SUCCESS;
}

// dbstor --delete-file --fs-name=xxx --file-name=xxx
int32 dbs_delete_path_or_file(int32 argc, char *argv[])
{
    char fs_name[MAX_DBS_FS_NAME_LEN] = {0};
    char file_name[MAX_DBS_FILE_PATH_LEN] = {0};

    const char *params[] = {DBS_TOOL_PARAM_FS_NAME, DBS_TOOL_PARAM_FILE_NAME};
    char *results[] = {fs_name, file_name};
    size_t result_lens[] = {MAX_DBS_FS_NAME_LEN, MAX_DBS_FILE_PATH_LEN};
    params_check_list_t check_list[] = {{DBS_TOOL_PARAM_FS_NAME, fs_name}, {DBS_TOOL_PARAM_FILE_NAME, file_name}};
    params_list_t params_list = {params, results, result_lens, check_list, DBS_DELETE_FILE_PRAMA_NUM,
                                 DBS_DELETE_FILE_CHECK_PRAMA_NUM};

    if (parse_params_list(argc, argv, &params_list) != CT_SUCCESS) {
        printf("Invalid command.\nUsage: --delete-file --fs-name=xxx --file-name=xxx\n");
        return CT_ERROR;
    }

    char full_path[MAX_DBS_FS_FILE_PATH_LEN] = {0};
    PRTS_RETURN_IFERR(snprintf_s(full_path, MAX_DBS_FS_FILE_PATH_LEN,
                                 MAX_DBS_FS_FILE_PATH_LEN - 1, "/%s/%s", fs_name, file_name));

    dbs_device_info_t dst_info = { .handle = -1, .type = DEV_TYPE_DBSTOR_FILE, .path = "" };
    MEMS_RETURN_IFERR(strncpy_s(dst_info.path, MAX_DBS_FS_FILE_PATH_LEN, full_path, strlen(full_path)));

    if (cm_remove_device(dst_info.type, dst_info.path) != CT_SUCCESS) {
        printf("Failed to delete path or file: %s\n", dst_info.path);
        return CT_ERROR;
    }

    printf("Path or file deleted successfully: %s\n", dst_info.path);
    return CT_SUCCESS;
}

// dbstor --query-file --fs-name=xxx --file-path=xxx
int32 dbs_query_file(int32 argc, char *argv[])
{
    char fs_name[MAX_DBS_FS_NAME_LEN] = {0};
    char file_path[MAX_DBS_FILE_PATH_LEN] = {0};

    const char *params[] = {DBS_TOOL_PARAM_FS_NAME, DBS_TOOL_PARAM_FILE_PATH};
    char *results[] = {fs_name, file_path};
    size_t result_lens[] = {MAX_DBS_FS_NAME_LEN, MAX_DBS_FILE_PATH_LEN};
    params_check_list_t check_list[] = {{DBS_TOOL_PARAM_FS_NAME, fs_name}, {DBS_TOOL_PARAM_FILE_PATH, file_path}};
    params_list_t params_list = {params, results, result_lens, check_list, DBS_QUERY_FILE_PRAMA_NUM,
                                 DBS_QUERY_FILE_CHECK_PRAMA_NUM};

    if (parse_params_list(argc, argv, &params_list) != CT_SUCCESS) {
        printf("Invalid command.\nUsage: --query-file --fs-name=xxx --file-path=xxx\n");
        return CT_ERROR;
    }

    char full_path[MAX_DBS_FS_FILE_PATH_LEN] = {0};
    PRTS_RETURN_IFERR(snprintf_s(full_path, MAX_DBS_FS_FILE_PATH_LEN,
                                 MAX_DBS_FS_FILE_PATH_LEN - 1, "/%s/%s", fs_name, file_path));

    dbs_device_info_t query_info = { .handle = -1, .type = DEV_TYPE_DBSTOR_FILE, .path = "" };
    MEMS_RETURN_IFERR(strncpy_s(query_info.path, MAX_DBS_FS_FILE_PATH_LEN, full_path, strlen(full_path)));

    if (cm_exist_device_dir(query_info.type, query_info.path) != CT_TRUE) {
        printf("Directory does not exist: %s\n", query_info.path);
        return CT_ERROR;
    }

    void *file_list = NULL;
    uint32 file_num = 0;

    if (cm_malloc_file_list(query_info.type, &file_list) != CT_SUCCESS) {
        printf("Failed to allocate memory for file list.\n");
        return CT_ERROR;
    }

    status_t ret = cm_query_device(query_info.type, query_info.path, file_list, &file_num);
    if (ret != CT_SUCCESS) {
        printf("Failed to query files in directory: %s\n", query_info.path);
        cm_free_file_list(&file_list);
        return CT_ERROR;
    }

    if (file_num == 0) {
        printf("No files found in directory: %s\n", query_info.path);
    } else {
        printf("Files in directory %s:\n", query_info.path);
        for (uint32 i = 0; i < file_num; i++) {
            char *file_name = cm_get_name_from_file_list(query_info.type, file_list, i);
            if (file_name != NULL) {
                printf("%s\n", file_name);
            }
        }
    }

    cm_free_file_list(&file_list);
    return CT_SUCCESS;
}

int32 append_to_file(char *directory, char *filename, char *buffer, uint32 buffer_size)
{
    // 构建完整路径
    char path[MAX_DBS_FILE_PATH_LEN];
    if (snprintf_s(path, sizeof(path), sizeof(path) - 1, "%s/%s", directory, filename) < 0) {
        printf("snprintf_s failed. \n");
        return CT_ERROR;
    }

    // 打开文件以追加方式写入
    FILE *file = fopen(path, "a");
    if (file == NULL) {
        // 文件不存在，尝试创建新文件
        file = fopen(path, "w");  // 使用 "w" 模式创建新文件
        if (file == NULL) {
            printf("Error creating file %s\n", path);
            return CT_ERROR;
        }
    }

    // 将缓冲区的数据写入文件
    uint32 bytes_written = fwrite(buffer, 1, buffer_size, file);
    if (bytes_written != buffer_size) {
        printf("Error writing to file %s\n", path);
    } else {
        printf("Data appended to file %s\n", path);
    }

    // 关闭文件
    (void)fclose(file);
    return CT_SUCCESS;
}

int32 get_ulog_handle(uint32 vstore_id, char *fs_name, char *path, object_id_t *ulog_obj_id)
{
    int32 ret = CT_SUCCESS;
    // 获取根目录的句柄
    object_id_t root_obj_id = { 0 };
    ret = dbs_global_handle()->dbs_file_open_root(fs_name, vstore_id, &root_obj_id);
    if (ret != CT_SUCCESS) {
        printf("Failed to dbs_file_open_root(%d), fs name %s\n", ret, fs_name);
        return ret;
    }

    // 获取ulog目录的句柄
    
    ret = dbs_global_handle()->dbs_file_open_by_path(&root_obj_id, path, 0, ulog_obj_id);
    if (ret != CT_SUCCESS) {
        printf("Failed to dbs_file_open_by_path(%d), ulog path %s\n", ret, path);
    }
    return ret;
}

void ulog_export_option_init(ReadBatchLogOption *option, char *cluster_name, uint32 total_log_export_len,
                             uint64 start_lsn)
{
    option->session.nsName = cluster_name;
    option->opcode = ULOG_OP_READ_WITH_LSN;
    option->view = ULOG_VIEW_ONLINE;
    option->partId = CT_INVALID_ID32;
    option->callBack.ctx = NULL;
    option->callBack.callback = NULL;
    option->length = (total_log_export_len >= CT_MAX_BATCH_SIZE) ? (uint32)CT_MAX_BATCH_SIZE
                                                                 : (uint32)total_log_export_len;

    LogLsn lsn = { 0 };
    lsn.startLsn = start_lsn;
    lsn.endLsn = CT_INVALID_ID64;
    option->lsn = lsn;
}

int32 read_log_record_init(LogRecord *logRecord, LogRecordList *record_list, ReadResult *result,
                           aligned_buf_t *read_buf)
{
    (void)memset_s(read_buf, sizeof(aligned_buf_t), 0, sizeof(aligned_buf_t));
    if (cm_aligned_malloc(CT_MAX_BATCH_SIZE, "export ulog buffer", read_buf) != CT_SUCCESS) {
        cm_aligned_free(read_buf);
        return CT_ERROR;
    }
    (void)memset_s(result, sizeof(ReadResult), 0, sizeof(ReadResult));
    (void)memset_s(logRecord, sizeof(LogRecord), 0, sizeof(LogRecord));
    logRecord->type = DBS_DATA_FORMAT_BUFFER;
    logRecord->buf.buf = read_buf->aligned_buf;
    logRecord->buf.len = (uint32)CT_MAX_BATCH_SIZE;
    logRecord->next = NULL;
    record_list->cnt = 1;
    record_list->recordList = logRecord;
    return CT_SUCCESS;
}

int32 ulog_export_handle(char *cluster_name, uint32 total_log_export_len, uint64 start_lsn, object_id_t *ulog_obj_id,
                         char *target_dir)
{
    int32 ret = CT_SUCCESS;
    // 根据输入填充lsn区间
    ReadBatchLogOption option = { 0 };
    ulog_export_option_init(&option, cluster_name, total_log_export_len, start_lsn);
    char log_filename[MAX_DBS_FILE_NAME_LEN];
    PRTS_RETURN_IFERR(snprintf_s(log_filename, sizeof(log_filename), sizeof(log_filename) - 1, "log_file"));

    LogRecord logRecord = { 0 };
    LogRecordList record_list = { 0 };
    ReadResult result = { 0 };
    aligned_buf_t read_buf = { 0 };
    uint32 cur_log_export_len = 0;
    while (cur_log_export_len < total_log_export_len) {
        option.length = ((total_log_export_len - cur_log_export_len) >= CT_MAX_BATCH_SIZE)
                            ? (uint32)CT_MAX_BATCH_SIZE
                            : (uint32)(total_log_export_len - cur_log_export_len);
        read_log_record_init(&logRecord, &record_list, &result, &read_buf);
        ret = dbs_global_handle()->read_ulog_record_list(ulog_obj_id, &option, &record_list, &result);
        if (ret != CT_SUCCESS || result.result != CT_SUCCESS) {
            if (result.result == ULOG_READ_RETURN_LSN_NOT_EXIST) {
                printf("LSN(%lu) not found\n", option.lsn.startLsn);
                ret = CT_SUCCESS;
            } else if (result.result == ULOG_READ_RETURN_REACH_MAX_BUF_LEN) {
                printf("The buffer capacity is insufficient for LSN(%lu)\n", option.lsn.startLsn);
                ret = CT_SUCCESS;
            } else {
                printf("Failed to read ulog ret:%d\n", result.result);
                cm_aligned_free(&read_buf);
                break;
            }
        }
        // 判断是否结束循环
        if (option.lsn.startLsn == result.endLsn || result.outLen == 0) {
            printf("No lsn left, from lsn %lu, to %lu, outlen %u \n\n", option.lsn.startLsn, result.endLsn,
                   result.outLen);
            cm_aligned_free(&read_buf);
            break;
        }

        // 创建并将ulog追加写入到文件
        ret = append_to_file(target_dir, log_filename, record_list.recordList->buf.buf, option.length);
        if (ret != CT_SUCCESS) {
            printf("Failed to append_to_file \n");
            cm_aligned_free(&read_buf);
            break;
        }
        
        printf("Cur batch ulog export finished, from lsn %lu, to %lu, outlen %u \n\n", option.lsn.startLsn,
               result.endLsn, option.length);
        // 更新起始LSN和当前导出的大小
        option.lsn.startLsn = result.endLsn;
        cur_log_export_len += option.length;
        cm_aligned_free(&read_buf);
    }
    printf("Export ulog finished, lsn from %llu, to %lu, cur export len %u\n", start_lsn, result.endLsn,
           cur_log_export_len);
    return ret;
}

// dbstor --ulog-data [node] [target-dir] [start-lsn] [len(optional)]
int32 dbs_ulog_export(int32 argc, char *argv[])
{
    // 检查输入
    if (argc != NUM_FIVE && argc != NUM_SIX) {
        printf("Invalid input, arg num %d.\n", argc);
        printf("dbstor --ulog-data --node==xxx --target-dir=xxx --start-lsn=xxx --len=xxx(optional)\n");
        return CT_ERROR;
    }

    // 参数准备
    int32 ret = CT_SUCCESS;
    char fs_name[MAX_DBS_FILE_NAME_LEN];
    MEMS_RETURN_IFERR(strcpy_s(fs_name, sizeof(fs_name), g_dbs_fs_info.log_fs_name));
    char cluster_name[MAX_DBS_FILE_NAME_LEN];
    MEMS_RETURN_IFERR(strcpy_s(cluster_name, sizeof(cluster_name), g_dbs_fs_info.cluster_name));
    uint32 vstore_id = (uint32)atoi(g_dbs_fs_info.log_fs_vstore_id);

    uint32 node = 0;
    char target_dir[MAX_DBS_FILE_PATH_LEN];
    uint64 start_lsn = 1;
    uint32 total_log_export_len = CT_INVALID_ID32;
    node = (uint32)atoi(argv[NUM_TWO]);
    if (strcpy_s(target_dir, MAX_DBS_FILE_PATH_LEN, argv[NUM_THREE]) != EOK) {
        printf("Failed to strcpy_s target_dir %s \n", target_dir);
        return CT_ERROR;
    }
    start_lsn = (uint64)atoi(argv[NUM_FOUR]);
    if (start_lsn <= 0) {
        printf("start_lsn input error.\n");
        return CT_ERROR;
    }

    if (argc == NUM_SIX) {
        total_log_export_len = (uint32)atoi(argv[NUM_FIVE]);
    }
    char path[MAX_DBS_FILE_PATH_LEN];
    // 根据node的值拼接path
    if (node == 0) {
        PRTS_RETURN_IFERR(snprintf_s(path, sizeof(path), sizeof(path) - 1, "/%s/*redo01.dat/", cluster_name));
    } else if (node == 1) {
        PRTS_RETURN_IFERR(snprintf_s(path, sizeof(path), sizeof(path) - 1, "/%s/*redo11.dat/", cluster_name));
    } else {
        printf("Unsupported node\n");
        return CT_ERROR;
    }
    printf("Fs name %s, cluster name %s, ulog dir %s, start_lsn %llu, total_log_export_len %u \n", fs_name,
           cluster_name, path, start_lsn, total_log_export_len);

    // 获取ulog目录handle
    object_id_t ulog_obj_id = { 0 };
    ret = get_ulog_handle(vstore_id, fs_name, path, &ulog_obj_id);
    if (ret != CT_SUCCESS) {
        printf("Failed to get ulog handle, ret %d, fsname %s, path %s \n", ret, fs_name, path);
        return ret;
    }

    // 导出ulog
    ret = ulog_export_handle(cluster_name, total_log_export_len, start_lsn, &ulog_obj_id, target_dir);
    if (ret != CT_SUCCESS) {
        printf("Failed to export ulog(%d), cluster_name %s, export len %u, start_lsn %llu, target_dir %s \n",
            ret, cluster_name, total_log_export_len, start_lsn, target_dir);
    }
    return ret;
}

void page_export_param_init(DbsPageOption *pgOpt, PageValue *pgValue, char *aligned_buf, uint64 single_batch_page_size)
{
    pgOpt->priority = 0;
    pgOpt->opcode = CS_PAGE_POOL_READ;
    pgOpt->offset = 0;
    pgOpt->lsn = 1;
    pgOpt->callBack.cb = NULL;
    pgOpt->callBack.ctx = NULL;
    pgOpt->length = single_batch_page_size;
    (void)memset_s(&pgOpt->session, sizeof(SessionId), 0, sizeof(SessionId));

    pgValue->buf.buf = aligned_buf;
    pgValue->type = DBS_DATA_FORMAT_BUFFER;
    pgValue->buf.len = single_batch_page_size;
}

int32 page_export_handle(object_id_t *page_pool_id, uint64 start_page_id, uint64 total_export_page_num,
                         uint32_t pageSize, char *target_dir)
{
    int32 ret = CT_SUCCESS;
    if (pageSize == 0) {
        printf("PageSize is zero.\n");
        return CT_ERROR;
    }
    uint64 single_batch_max_page_num = (uint64)CT_MAX_BATCH_SIZE / pageSize;
    uint64 cur_page_export_num = 0;
    uint64 single_batch_page_num = (total_export_page_num >= single_batch_max_page_num)
                                       ? single_batch_max_page_num
                                       : total_export_page_num;
    uint64 single_batch_page_size = single_batch_page_num * pageSize;
    uint64 cur_page_id = start_page_id;
    char page_filename[MAX_DBS_FILE_NAME_LEN];
    PRTS_RETURN_IFERR(snprintf_s(page_filename, MAX_DBS_FILE_NAME_LEN, MAX_DBS_FILE_NAME_LEN - 1, "page_file"));

    DbsPageOption pgOpt = { 0 };
    aligned_buf_t read_buf = { 0 };
    PageValue pgValue = { 0 };
    while (cur_page_export_num < total_export_page_num) {
        if ((total_export_page_num - cur_page_export_num) >= single_batch_max_page_num) {
            single_batch_page_num = single_batch_max_page_num;
            single_batch_page_size = (uint64)CT_MAX_BATCH_SIZE;
        } else {
            single_batch_page_num = total_export_page_num - cur_page_export_num;
            single_batch_page_size = single_batch_page_num * pageSize;
        }
        
        (void)memset_s(&read_buf, sizeof(aligned_buf_t), 0, sizeof(aligned_buf_t));
        if (cm_aligned_malloc(CT_MAX_BATCH_SIZE, "export page buffer", &read_buf) != CT_SUCCESS) {
            cm_aligned_free(&read_buf);
            return CT_ERROR;
        }
        page_export_param_init(&pgOpt, &pgValue, (char *)read_buf.aligned_buf, single_batch_page_size);
        ret = dbs_global_handle()->dbs_mget_page(page_pool_id, cur_page_id, single_batch_page_num, &pgOpt, &pgValue);
        if (ret != CT_SUCCESS) {
            printf("Export page fail(%d), cur_page_id %llu\n", ret, cur_page_id);
            cm_aligned_free(&read_buf);
            break;
        }

        // 将page追加写入到文件
        ret = append_to_file(target_dir, page_filename, pgValue.buf.buf, pgValue.buf.len);
        if (ret != CT_SUCCESS) {
            cm_aligned_free(&read_buf);
            break;
        }
        cm_aligned_free(&read_buf);
        printf("Cur batch page export finished, start page_id %llu, single_batch_page_num %llu, size %llu \n\n",
               cur_page_id, single_batch_page_num, single_batch_page_size);

        // 更新起始page id
        cur_page_id += single_batch_page_num;
        cur_page_export_num += single_batch_page_num;
    }
    printf("Export page finished, start_page_id %llu, export pageNum %llu \n\n", start_page_id, cur_page_export_num);
    return ret;
}

// dbstor --page-data [page-db] [target-dir] [page-id(optional)] [page-num(optional)]
int32 dbs_page_export(int32 argc, char *argv[])
{
    // 检查输入
    if (argc != NUM_FOUR && argc != NUM_FIVE && argc != NUM_SIX) {
        printf("Invalid input, arg num %d\n", argc);
        printf("dbstor --page-data --page-db=xxx --target-dir=xxx --page-id=xxx(optional) --page-num=xxx(optional)\n");
        return CT_ERROR;
    }

    // 参数准备
    char fs_name[MAX_DBS_FILE_NAME_LEN];
    MEMS_RETURN_IFERR(strcpy_s(fs_name, MAX_DBS_FILE_NAME_LEN, g_dbs_fs_info.page_fs_name));
    char cluster_name[MAX_DBS_FILE_NAME_LEN];
    MEMS_RETURN_IFERR(strcpy_s(cluster_name, MAX_DBS_FILE_NAME_LEN, g_dbs_fs_info.cluster_name));

    char page_pool_name[MAX_DBS_FILE_NAME_LEN];
    if (strcpy_s(page_pool_name, MAX_DBS_FILE_PATH_LEN, argv[NUM_TWO]) != EOK) {
        printf("Failed to strcpy_s page_pool_name %s \n", page_pool_name);
        return CT_ERROR;
    }
    char target_dir[MAX_DBS_FILE_PATH_LEN];
    if (strcpy_s(target_dir, MAX_DBS_FILE_PATH_LEN, argv[NUM_THREE]) != EOK) {
        printf("Failed to strcpy_s target_dir %s \n", target_dir);
        return CT_ERROR;
    }
    uint64 start_page_id = 0;
    if (argc == NUM_FIVE) {
        start_page_id = (uint64)atoi(argv[NUM_FOUR]);
    }
    uint64 total_export_page_num = CT_INVALID_ID64;
    if (argc == NUM_SIX) {
        start_page_id = (uint64)atoi(argv[NUM_FOUR]);
        total_export_page_num = (uint64)atoi(argv[NUM_FIVE]);
    }
    printf("Fs name %s, cluster name %s\n", fs_name, cluster_name);

    NameSpaceAttr ns_attr;
    if (dbs_global_handle()->open_namespace((char *)cluster_name, &ns_attr) != CT_SUCCESS) {
        printf("Failed to open namespace %s \n", cluster_name);
        return CT_ERROR;
    }
    // 通过open_pagepool获取句柄
    object_id_t page_pool_id = { 0 };
    PagePoolAttr attr = { 0 };
    MEMS_RETURN_IFERR(strcpy_s(attr.nsName, sizeof(attr.nsName), cluster_name));
    int32 ret = dbs_global_handle()->open_pagepool((char *)page_pool_name, &attr, &page_pool_id);
    if (ret != CT_SUCCESS) {
        printf("Failed to open_pagepool(%d), page pool name %s, fs name %s, cluster name %s\n",
            ret, page_pool_name, fs_name, cluster_name);
        return ret;
    }
    printf("Success to open_pagepool, pagepool name %s, pageSize %u\n\n", page_pool_name, attr.pageSize);

    ret = page_export_handle(&page_pool_id, start_page_id, total_export_page_num, attr.pageSize, target_dir);
    if (ret != CT_SUCCESS) {
        printf("Failed to export page(%d), start_page_id %llu, export num %llu, pageSize %u, target_dir %s \n",
            ret, start_page_id, total_export_page_num, attr.pageSize, target_dir);
    }
    return ret;
}

// 新增链接超时配置
status_t dbs_insert_link_timeout(uint32 linkTimeOut, char *path)
{
    FILE *file = fopen(path, "a");
    if (file == NULL) {
        printf("Open file %s failed\n", path);
        return CT_ERROR;
    }

    // 将缓冲区的数据写入文件
    char buffer[DBS_LINK_CHECK_PARAM_LEN];
    int32 ret = sprintf_s(buffer, DBS_LINK_CHECK_PARAM_LEN, "%s = %u\n", DBS_LINK_CHECK_CNT, linkTimeOut);
    if (ret == CT_ERROR) {
        printf("sprintf_s faild(%d).\n", ret);
        return CT_ERROR;
    }
    size_t bytes_written = fwrite(buffer, 1, strlen(buffer), file);
    if (bytes_written != strlen(buffer)) {
        printf("Writing to file(%s) failed.\n", path);
        ret = CT_ERROR;
    }

    // 关闭文件
    (void)fclose(file);
    return CT_SUCCESS;
}

// 更新链接超时配置
status_t dbs_edit_link_timeout(uint32 linkTimeOut, char *path)
{
    FILE *file = fopen(path, "r+");
    if (file == NULL) {
        printf("Open file %s failed\n", path);
        return CT_ERROR;
    }

    bool isExist = false;
    char buffer[DBS_LINK_CHECK_PARAM_LEN];
    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        if (strstr(buffer, DBS_LINK_CHECK_CNT)) {
            fseek(file, -strlen(buffer), SEEK_CUR);
            fprintf(file, "%s = %u\n", DBS_LINK_CHECK_CNT, linkTimeOut);
            isExist = true;
            break;
        }
    }
    (void)fclose(file);

    int32 ret = CT_SUCCESS;
    if (!isExist) {
        ret = dbs_insert_link_timeout(linkTimeOut, path);
        if (ret != CT_SUCCESS) {
            printf("Insert link timeout(%d).\n", ret);
        }
    }
    return ret;
}

// dbstor --set-link-timeout link-timeout
int32 dbs_set_link_timeout(int32 argc, char *argv[])
{
    if (argc != NUM_THREE) {
        printf("Invalid input, arg num %d\n", argc);
        printf("dbstor --set-link-timeout link-timeout\n");
        return CT_ERROR;
    }

    uint32 linkTimeOut = (uint32)atoi(argv[NUM_TWO]);
    if (linkTimeOut < DBS_LINK_TIMEOUT_MIN || linkTimeOut > DBS_LINK_TIMEOUT_MAX) {
        printf("The link timeout(%u) should be between %u and %u.\n",
            linkTimeOut, DBS_LINK_TIMEOUT_MIN, DBS_LINK_TIMEOUT_MAX);
        return CT_ERROR;
    }

    status_t ret = dbs_edit_link_timeout(linkTimeOut, DBS_CANTIAN_CONFIG_PATH);
    if (ret != CT_SUCCESS) {
        printf("Set link timeout failed(%d).\n", ret);
        return ret;
    }

    ret = dbs_edit_link_timeout(linkTimeOut, DBS_CMS_CONFIG_PATH);
    if (ret != CT_SUCCESS) {
        printf("Set link timeout failed(%d).\n", ret);
        return ret;
    }
    printf("Set link timeout success.\n");
    return ret;
}
