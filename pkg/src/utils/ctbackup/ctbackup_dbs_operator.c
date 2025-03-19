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
* ctbackup_dbs_operator.c
*
*
* IDENTIFICATION
* src/utils/ctbackup/ctbackup_dbs_operator.c
*
* -------------------------------------------------------------------------
 */

#include "ctbackup_dbs_operator.h"
#include "ctbackup_dbs_common.h"

//dbs_fs_info_t g_dbs_fs_info = { 0 };

bool32 ulog_file_filter(const char *file_name)
{
    return (bool32)(strcmp(file_name, g_dbs_fs_info.cluster_name) == 0);
}

bool32 page_file_filter(const char *file_name)
{
    return (bool32)(strcmp(file_name, "SplitLsnInfo") == 0);
}

bool32 arch_file_filter(const char *file_name)
{
    return !cm_match_arch_pattern(file_name) && strstr(file_name, "arch_file.tmp") == NULL;
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

status_t dbs_set_ns_io_forbidden(bool32 isForbidden)
{
    if (dbs_global_handle()->dbs_ns_io_forbidden == NULL) {
        printf("dbs_ns_io_forbidden is not support\n");
        return CT_ERROR;
    }

    status_t ret = dbs_global_handle()->dbs_ns_io_forbidden(g_dbs_fs_info.cluster_name, isForbidden);
    if (ret != CT_SUCCESS) {
        printf("Set ns forbidden failed(%d).\n", ret);
        return ret;
    }
    printf("Set ns forbidden success.\n");
    return ret;
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

// dbstor --pagepool-clean [--fs-name=xxx] [--cluster-name=xxx]
int32 dbs_pagepool_clean()
{
    char fs_name[MAX_DBS_FS_NAME_LEN] = {0};
    char cluster_name[MAX_DBS_FILE_PATH_LEN] = {0};
    MEMS_RETURN_IFERR(strncpy_s(fs_name, MAX_DBS_FS_NAME_LEN, g_dbs_fs_info.page_fs_name,
                                strlen(g_dbs_fs_info.page_fs_name)));
    MEMS_RETURN_IFERR(strncpy_s(cluster_name, MAX_DBS_FILE_PATH_LEN, g_dbs_fs_info.cluster_name,
                                strlen(g_dbs_fs_info.cluster_name)));

    char pagepool_path[MAX_DBS_FS_FILE_PATH_LEN] = {0};
    PRTS_RETURN_IFERR(snprintf_s(pagepool_path, MAX_DBS_FS_FILE_PATH_LEN,
                                 MAX_DBS_FS_FILE_PATH_LEN - 1, "/%s/%s", fs_name, cluster_name));

    void *file_list = NULL;
    uint32 file_num = 0;
    dbs_device_info_t src_info = { .handle = -1, .type = DEV_TYPE_DBSTOR_FILE, .path = "" };
    MEMS_RETURN_IFERR(strncpy_s(src_info.path, MAX_DBS_FS_FILE_PATH_LEN, pagepool_path, strlen(pagepool_path)));

    if (cm_malloc_file_list(src_info.type, &file_list, src_info.path, &file_num) != CT_SUCCESS) {
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

static char *get_file_name_from_list(void *file_list, uint32 index, file_info_version_t info_version)
{
    if (info_version == DBS_FILE_INFO_VERSION_1) {
        dbstor_file_info *file_info = (dbstor_file_info *)((char *)file_list + index * sizeof(dbstor_file_info));
        return file_info->file_name;
    } else {
        dbstor_file_info_detail *file_info = (dbstor_file_info_detail *)((char *)file_list +
                                                                         index * sizeof(dbstor_file_info_detail));
        return file_info->file_name;
    }
}

status_t dbs_clean_files_ulog(uint32 vstore_id, dbs_device_info_t *src_info, void *file_list,
                              uint32 file_num, file_filter_func filter_func)
{
    CT_LOG_RUN_INF("[DBSTOR] Removed files in dir %s", src_info->path);
    printf("Remove files list:\n");
    file_info_version_t info_version = DBS_FILE_INFO_VERSION_1;
    if (dbs_global_handle()->dbs_file_get_list_detail != NULL) {
        info_version = DBS_FILE_INFO_VERSION_2;
    }
    for (uint32 i = 0; i < file_num; i++) {
        char file_path[MAX_DBS_FS_FILE_PATH_LEN] = { 0 };
        char *file_name = get_file_name_from_list(file_list, i, info_version);

        if (file_name == NULL || strlen(file_name) == 0) {
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

// dbstor --ulog-clean [--fs-name=xxx] [--cluster-name=xxx]
int32 dbs_ulog_clean()
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

    uint32 vstore_id_uint = (uint32)atoi(vstore_id);
    char ulog_path[MAX_DBS_FS_FILE_PATH_LEN] = {0};
    PRTS_RETURN_IFERR(snprintf_s(ulog_path, MAX_DBS_FS_FILE_PATH_LEN,
                                 MAX_DBS_FS_FILE_PATH_LEN - 1, "/%s/%s", fs_name, cluster_name));

    void *file_list = NULL;
    uint32 file_num = 0;
    dbs_device_info_t src_info = { .handle = -1, .type = DEV_TYPE_DBSTOR_FILE, .path = "" };
    MEMS_RETURN_IFERR(strncpy_s(src_info.path, MAX_DBS_FS_FILE_PATH_LEN, ulog_path, strlen(ulog_path)));
    file_info_version_t info_version = DBS_FILE_INFO_VERSION_1;
    if (dbs_global_handle()->dbs_file_get_list_detail != NULL) {
        info_version = DBS_FILE_INFO_VERSION_2;
    }
    if (cm_malloc_file_list_by_version_id(info_version, vstore_id_uint,
                                          &file_list, src_info.path, &file_num) != CT_SUCCESS) {
        printf("Failed to allocate memory for file list.\n");
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
// dbstor --arch-clean [--fs-name=xxx]
int32 dbs_arch_clean()
{
    char fs_name[MAX_DBS_FS_NAME_LEN] = {0};
    char archive_location[MAX_DBS_FS_FILE_PATH_LEN] = {0};

    if (dbs_get_arch_location(archive_location, fs_name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    void *file_list = NULL;
    uint32 file_num = 0;
    dbs_device_info_t src_info = { .handle = -1, .type = DEV_TYPE_DBSTOR_FILE, .path = "" };
    MEMS_RETURN_IFERR(strncpy_s(src_info.path, MAX_DBS_FS_FILE_PATH_LEN, archive_location, strlen(archive_location)));

    if (cm_malloc_file_list(src_info.type, &file_list, src_info.path, &file_num) != CT_SUCCESS) {
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

// dbstor --copy-file --import/--export --fs-name=xxx --source-dir=* --target-dir=* [--file-name=*] [--overwrite]
status_t dbs_copy_file(int32 argc, char *argv[])
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
    if (check_dir_exist(argv[DBS_COPY_FILE_OP_PRAMA], source_dir, target_dir, file_system_path, fs_name) != CT_SUCCESS) {
        return CT_ERROR;
    }
    dbs_device_info_t src_info = {.handle = -1, .path = ""};
    dbs_device_info_t dst_info = {.handle = -1, .path = ""};

    if (strncmp(argv[DBS_COPY_FILE_OP_PRAMA], DBS_IMPORT_PARAM, strlen(DBS_IMPORT_PARAM)) == 0) {
        src_info.type = DEV_TYPE_FILE;
        dst_info.type = DEV_TYPE_DBSTOR_FILE;
        MEMS_RETURN_IFERR(strncpy_s(src_info.path, MAX_DBS_FS_FILE_PATH_LEN, source_dir, strlen(source_dir)));
        MEMS_RETURN_IFERR(strncpy_s(dst_info.path, MAX_DBS_FS_FILE_PATH_LEN,
                                    file_system_path, strlen(file_system_path)));
    } else if (strncmp(argv[DBS_COPY_FILE_OP_PRAMA], DBS_EXPORT_PARAM, strlen(DBS_EXPORT_PARAM)) == 0) {
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

status_t dbs_query_file(int32 argc, char *argv[], void **file_list, uint32 *file_num, file_info_version_t *info_version)
{
    printf("start dbs query file\n");
    char fs_name[MAX_DBS_FS_NAME_LEN] = {0};
    char file_path[MAX_DBS_FILE_PATH_LEN] = {0};
    char vstore_id[MAX_DBS_VSTORE_ID_LEN] = {0};
    const char *params[] = {DBS_TOOL_PARAM_FS_NAME, DBS_TOOL_PARAM_FILE_DIR, DBS_TOOL_PARAM_VSTORE_ID};
    char *results[] = {fs_name, file_path, vstore_id};
    size_t result_lens[] = {MAX_DBS_FS_NAME_LEN, MAX_DBS_FILE_PATH_LEN, MAX_DBS_VSTORE_ID_LEN};
    params_check_list_t check_list[] = {{DBS_TOOL_PARAM_FS_NAME, fs_name}};
    params_list_t params_list = {params, results, result_lens, check_list, DBS_QUERY_FILE_PRAMA_NUM,
                                  DBS_QUERY_FILE_CHECK_PRAMA_NUM};

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

    uint32 vstore_id_uint = 0;
    if (strlen(vstore_id) > 0) {
        vstore_id_uint = (uint32)atoi(vstore_id);
    }
    if (dbs_global_handle()->dbs_file_get_list_detail != NULL) {
        *info_version = DBS_FILE_INFO_VERSION_2;
    }
    if (cm_malloc_file_list_by_version_id(*info_version, vstore_id_uint,
                                          file_list, query_info.path, file_num) != CT_SUCCESS) {
        printf("Failed to allocate memory for file list.\n");
        return CT_ERROR;
    }
    status_t ret = cm_dbs_query_dir_vstore_id(vstore_id_uint, query_info.path, *file_list, file_num);
    if (ret != CT_SUCCESS) {
        printf("Failed to query files in directory: %s with vstore-id: %u\n", query_info.path, vstore_id_uint);
        cm_free_file_list(file_list);
        return CT_ERROR;
    }
    printf("finish dbs query file\n");
    return CT_SUCCESS;
}

// dbstor --create-file --fs-name=xxx [--file-dir=xxx] [--file-name=xxx]
// 创建文件或目录（'/'结尾）。如果指定了 source-dir 参数，则从 source-dir 复制（覆盖）文件内容到目标位置。
status_t dbs_create_path_or_file(int32 argc, char *argv[])
{
    char fs_name[MAX_DBS_FS_NAME_LEN] = {0};
    char file_dir[MAX_DBS_FS_FILE_PATH_LEN] = {0};
    char file_name[MAX_DBS_FILE_PATH_LEN] = {0};

    const char *params[] = {DBS_TOOL_PARAM_FS_NAME, DBS_TOOL_PARAM_FILE_NAME, DBS_TOOL_PARAM_FILE_DIR};
    char *results[] = {fs_name, file_name, file_dir};
    size_t result_lens[] = {MAX_DBS_FS_NAME_LEN, MAX_DBS_FILE_PATH_LEN, MAX_DBS_FS_FILE_PATH_LEN};
    params_check_list_t check_list[] = {{DBS_TOOL_PARAM_FS_NAME, fs_name}};
    params_list_t params_list = {params, results, result_lens, check_list, DBS_CRAETE_FILE_PRAMA_NUM,
                                  DBS_CRAETE_FILE_CHECK_PRAMA_NUM};

    if (parse_params_list(argc, argv, &params_list) != CT_SUCCESS) {
        printf("Invalid command.\nUsage: --creat-file --fs-name=xxx [--file-name=xxx] [--file-name=xxx]\n");
        return CT_ERROR;
    }
    if (strlen(file_dir) == 0 && strlen(file_name) == 0) {
        printf("file_dir and file_name both is empty.\n");
        return CT_ERROR;
    }

    char full_path[MAX_DBS_FS_FILE_PATH_LEN] = {0};
    dbs_device_info_t dst_info = { .handle = -1, .type = DEV_TYPE_DBSTOR_FILE, .path = "" };

    if (strlen(file_dir) > 0 && strlen(file_name) == 0) {
        PRTS_RETURN_IFERR(snprintf_s(full_path, MAX_DBS_FS_FILE_PATH_LEN,
                                     MAX_DBS_FS_FILE_PATH_LEN - 1, "/%s/%s", fs_name, file_dir));
        MEMS_RETURN_IFERR(strncpy_s(dst_info.path, MAX_DBS_FS_FILE_PATH_LEN, full_path, strlen(full_path)));
        if (cm_dbs_exist_file(full_path, DIR_TYPE) == CT_TRUE) {
            printf("Target directory is exist, file_path: %s.\n", full_path);
            return CT_SUCCESS;
        }
        status_t ret = cm_create_device_dir(dst_info.type, dst_info.path);
        if (ret != CT_SUCCESS) {
            printf("Failed to create directory: %s\n", dst_info.path);
            return CT_ERROR;
        }
        printf("Directory created successfully: %s\n", dst_info.path);
    } else {
        if (strlen(file_dir) == 0) {
            PRTS_RETURN_IFERR(snprintf_s(full_path, MAX_DBS_FS_FILE_PATH_LEN,
                                         MAX_DBS_FS_FILE_PATH_LEN - 1, "/%s/%s", fs_name, file_name));
        } else {
            PRTS_RETURN_IFERR(snprintf_s(full_path, MAX_DBS_FS_FILE_PATH_LEN,
                                         MAX_DBS_FS_FILE_PATH_LEN - 1, "/%s/%s/%s", fs_name, file_dir, file_name));
        }
        MEMS_RETURN_IFERR(strncpy_s(dst_info.path, MAX_DBS_FS_FILE_PATH_LEN, full_path, strlen(full_path)));
        if (cm_dbs_exist_file(full_path, FILE_TYPE) == CT_TRUE) {
            printf("Target file is exist, file_path: %s.\n", full_path);
            return CT_SUCCESS;
        }
        status_t ret = cm_create_device(dst_info.path, dst_info.type, 0, &dst_info.handle);
        if (ret != CT_SUCCESS) {
            printf("Failed to create file: %s\n", dst_info.path);
            return CT_ERROR;
        }
        cm_close_device(dst_info.type, &dst_info.handle);
        printf("File created successfully: %s\n", dst_info.path);
    }

    return CT_SUCCESS;
}