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
* ctbackup_snapshot_restore_operator.c
*
*
* IDENTIFICATION
* src/utils/ctbackup/ctbackup_snapshot_restore_operator.c
*
* -------------------------------------------------------------------------
 */

#include "ctbackup_snapshot_restore_operator.h"
#include "ctbackup_dbs_operator.h"
#include "ctbackup_dbs_common.h"

static void free_multiple_pointers(int count, ...)
{
    va_list args;
    va_start(args, count);

    for (int i = 0; i < count; i++) {
        void *ptr = va_arg(args, void *);
        CM_FREE_PTR(ptr);
    }

    va_end(args);
}

status_t traverse_directory_handle_dir(char *path, char *fs_path, const char *fs_name,
                                       ctbak_param_t* ctbak_param, cm_file_info *file_list, int index)
{
    // 构建子目录路径
    char *sub_path = (char*)malloc(MAX_DBS_FS_FILE_PATH_LEN);
    if (sub_path == NULL) {
        printf("[ctbackup] sub_path Failed to malloc\n");
        CM_FREE_PTR(file_list);
        return CT_ERROR;
    }
    char *new_fs_path = (char*)malloc(MAX_DBS_FS_FILE_PATH_LEN);
    if (new_fs_path == NULL) {
        printf("[ctbackup]new_fs_path Failed to malloc\n");
        free_multiple_pointers(FREE_POINTER_NUM_ONE, sub_path);
        return CT_ERROR;
    }
    int ret = snprintf_s(sub_path, CT_MAX_FILE_PATH_LENGH,
                         CT_MAX_FILE_PATH_LENGH - 1, "%s/%s", path, file_list[index].file_name);
    if (ret == CT_ERROR) {
        printf("Failed to build sub path.\n");
        free_multiple_pointers(FREE_POINTER_NUM_TWO, sub_path, new_fs_path);
        return CT_ERROR;
    }

    //在文件系统中创建目录
    //"dbstor", "--create-file", "--fs-name", "--file-dir"
    ret = snprintf_s(new_fs_path, MAX_DBS_FS_FILE_PATH_LEN,
                     MAX_DBS_FS_FILE_PATH_LEN - 1, "%s/%s", fs_path, file_list[index].file_name);
    if (ret == CT_ERROR) {
        printf("Failed to build sub path.\n");
        free_multiple_pointers(FREE_POINTER_NUM_TWO, sub_path, new_fs_path);
        return CT_ERROR;
    }

    char *argv[DBS_CREATE_DIR_PRAMA_NUM + 1] = { 0 };
    for (int j = 0; j < DBS_CREATE_DIR_PRAMA_NUM + 1; j++) {
        argv[j] = (char *)malloc(MAX_DBS_FS_FILE_PATH_LEN);
        if (argv[j] == NULL) {
            free_multiple_pointers(FREE_POINTER_NUM_TWO, sub_path, new_fs_path);
            while (--j >= 0) {
                CM_FREE_PTR(argv[j]);
            }
            printf("[ctbackup]traverse_directory Failed to malloc\n");
            return CT_ERROR;
        }
        errno_t err = memset_sp(argv[j], MAX_DBS_FS_FILE_PATH_LEN, 0, MAX_DBS_FS_FILE_PATH_LEN);
        if (err != EOK) {
            free_multiple_pointers(FREE_POINTER_NUM_TWO, sub_path, new_fs_path);
            while (--j >= 0) {
                CM_FREE_PTR(argv[j]);
            }
            printf("[ctbackup]Failed to memset_sp (%d)\n", err);
            return CT_ERROR;
        }
    }

    ret = snprintf_s(argv[DBS_CREATE_DIR_DBSTOR_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                     MAX_DBS_FS_FILE_PATH_LEN - 1, "dbstor");
    if (ret == CT_ERROR) {
        printf("Failed to build sub path.\n");
        free_system_call_params(argv, 0, DBS_CREATE_DIR_PRAMA_NUM);
        free_multiple_pointers(FREE_POINTER_NUM_TWO, sub_path, new_fs_path);
        return CT_ERROR;
    }

    ret = snprintf_s(argv[DBS_CREATE_DIR_CREATE_DIR_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                     MAX_DBS_FS_FILE_PATH_LEN - 1, "--create-file");
    if (ret == CT_ERROR) {
        printf("Failed to build sub path.\n");
        free_system_call_params(argv, 0, DBS_CREATE_DIR_PRAMA_NUM);
        free_multiple_pointers(FREE_POINTER_NUM_TWO, sub_path, new_fs_path);
        return CT_ERROR;
    }

    ret = snprintf_s(argv[DBS_CREATE_DIR_FS_NAME_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                     MAX_DBS_FS_FILE_PATH_LEN - 1, "--fs-name=%s", fs_name);
    if (ret == CT_ERROR) {
        printf("Failed to build sub path.\n");
        free_system_call_params(argv, 0, DBS_CREATE_DIR_PRAMA_NUM);
        free_multiple_pointers(FREE_POINTER_NUM_TWO, sub_path, new_fs_path);
        return CT_ERROR;
    }

    ret = snprintf_s(argv[DBS_CREATE_DIR_FILE_DIR_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                     MAX_DBS_FS_FILE_PATH_LEN - 1, "--file-dir=%s/%s", fs_path, file_list[index].file_name);
    if (ret == CT_ERROR) {
        printf("Failed to build sub path.\n");
        free_system_call_params(argv, 0, DBS_CREATE_DIR_PRAMA_NUM);
        free_multiple_pointers(FREE_POINTER_NUM_TWO, sub_path, new_fs_path);
        return CT_ERROR;
    }

    ret = dbs_create_path_or_file(DBS_CREATE_DIR_PRAMA_NUM + 1, argv);
    if (ret != CT_SUCCESS) {
        printf("Failed to create directory.\n");
        free_system_call_params(argv, 0, DBS_CREATE_DIR_PRAMA_NUM);
        free_multiple_pointers(FREE_POINTER_NUM_TWO, sub_path, new_fs_path);
        return ret;
    }


    // 递归遍历子目录
    free_system_call_params(argv, 0, DBS_CREATE_DIR_PRAMA_NUM);
    if (traverse_directory(sub_path, new_fs_path, fs_name, ctbak_param) != CT_SUCCESS) {
        printf("Failed to traverse sub directory.\n");
        free_multiple_pointers(FREE_POINTER_NUM_TWO, sub_path, new_fs_path);
        return CT_ERROR;
    }
    free_multiple_pointers(FREE_POINTER_NUM_TWO, sub_path, new_fs_path);
    return CT_SUCCESS;
}

status_t traverse_directory_handle_file(char *path, char *fs_path, const char *fs_name,
                                        ctbak_param_t* ctbak_param, cm_file_info *file_list, int index)
{
    CT_LOG_RUN_INF("Found file: %s/%s", path, file_list[index].file_name);

    // "dbstor", "--copy-file", "--import", "--fs-name=", "--source-dir=", "--target-dir="
    char *argv[DBS_COPY_FILE_PRAMA_NUM + 1] = { 0 };
    for (int j = 0; j < DBS_COPY_FILE_PRAMA_NUM + 1; j++) {
        argv[j] = (char *)malloc(MAX_DBS_FS_FILE_PATH_LEN);
        if (argv[j] == NULL) {
            CM_FREE_PTR(file_list);
            while (--j >= 0) {
                CM_FREE_PTR(argv[j]);
            }
            printf("[ctbackup]argv Failed to malloc\n");
            return CT_ERROR;
        }
        errno_t err = memset_sp(argv[j], MAX_DBS_FS_FILE_PATH_LEN, 0, MAX_DBS_FS_FILE_PATH_LEN);
        if (err != EOK) {
            CM_FREE_PTR(file_list);
            while (--j >= 0) {
                CM_FREE_PTR(argv[j]);
            }
            printf("[ctbackup]Failed to memset_sp (%d)\n", err);
            return CT_ERROR;
        }
    }

    status_t ret = snprintf_s(argv[DBS_COPY_FILE_DBSTOR_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                              MAX_DBS_FS_FILE_PATH_LEN - 1, "dbstor");
    if (ret == CT_ERROR) {
        printf("Failed to build sub path.\n");
        free_system_call_params(argv, 0, DBS_COPY_FILE_PRAMA_NUM);
        CM_FREE_PTR(file_list);
        return CT_ERROR;
    }

    ret = snprintf_s(argv[DBS_COPY_FILE_COPY_FILE_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                     MAX_DBS_FS_FILE_PATH_LEN - 1, "--copy-file");
    if (ret == CT_ERROR) {
        printf("Failed to build sub path.\n");
        free_system_call_params(argv, 0, DBS_COPY_FILE_PRAMA_NUM);
        CM_FREE_PTR(file_list);
        return CT_ERROR;
    }

    ret = snprintf_s(argv[DBS_COPY_FILE_OP_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                     MAX_DBS_FS_FILE_PATH_LEN - 1, "--import");
    if (ret == CT_ERROR) {
        printf("Failed to build sub path.\n");
        free_system_call_params(argv, 0, DBS_COPY_FILE_PRAMA_NUM);
        CM_FREE_PTR(file_list);
        return CT_ERROR;
    }

    ret = snprintf_s(argv[DBS_COPY_FILE_FS_NAME_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                     MAX_DBS_FS_FILE_PATH_LEN - 1, "--fs-name=%s", fs_name);
    if (ret == CT_ERROR) {
        printf("Failed to build sub path.\n");
        free_system_call_params(argv, 0, DBS_COPY_FILE_PRAMA_NUM);
        CM_FREE_PTR(file_list);
        return CT_ERROR;
    }

    ret = snprintf_s(argv[DBS_COPY_FILE_SOURCE_DIR_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                     MAX_DBS_FS_FILE_PATH_LEN - 1, "--source-dir=%s", path);
    if (ret == CT_ERROR) {
        printf("Failed to build sub path.\n");
        free_system_call_params(argv, 0, DBS_COPY_FILE_PRAMA_NUM);
        CM_FREE_PTR(file_list);
        return CT_ERROR;
    }

    ret = snprintf_s(argv[DBS_COPY_FILE_TARGET_DIR_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                     MAX_DBS_FS_FILE_PATH_LEN - 1, "--target-dir=%s/", fs_path);
    if (ret == CT_ERROR) {
        printf("Failed to build sub path.\n");
        free_system_call_params(argv, 0, DBS_COPY_FILE_PRAMA_NUM);
        CM_FREE_PTR(file_list);
        return CT_ERROR;
    }

    ret = dbs_copy_file(DBS_COPY_FILE_PRAMA_NUM, argv);
    if (ret != CT_SUCCESS) {
        printf("Failed to restore backup files.\n");
        free_system_call_params(argv, 0, DBS_CREATE_DIR_PRAMA_NUM);
        return ret;
    }

    free_system_call_params(argv, 0, DBS_CREATE_DIR_PRAMA_NUM);
    return CT_SUCCESS;
}

// 递归遍历目录
status_t traverse_directory(char *path, char *fs_path, const char *fs_name, ctbak_param_t* ctbak_param)
{
    uint32 file_num = 0;
    cm_file_info *file_list = (cm_file_info *)malloc(sizeof(cm_file_info) * DBS_DIR_MAX_FILE_NUM);
    bool32 is_copy_file = CT_FALSE;
    if (file_list == NULL) {
        printf("Failed to allocate memory for file list size:%lu.\n", sizeof(cm_file_info) * DBS_DIR_MAX_FILE_NUM);
        return CT_ERROR;
    }

    if (cm_query_file_num(path, &file_num) != CT_SUCCESS) {
        printf("Failed to query file num.\n");
        CM_FREE_PTR(file_list);
        return CT_ERROR;
    }

    if (cm_query_dir(path, file_list, &file_num) != CT_SUCCESS) {
        printf("Failed to query file list.\n");
        CM_FREE_PTR(file_list);
        return CT_ERROR;
    }

    for (uint32 i = 0; i < file_num; i++) {
        if (file_list[i].type == FILE_TYPE_DIR) {
            if (traverse_directory_handle_dir(path, fs_path, fs_name, ctbak_param, file_list, i) != CT_SUCCESS) {
                printf("Failed to traverse directory dir.\n");
                CM_FREE_PTR(file_list);
                return CT_ERROR;
            }
        } else {
            if (is_copy_file == CT_TRUE) {
                continue;
            }
            if (traverse_directory_handle_file(path, fs_path, fs_name, ctbak_param, file_list, i) != CT_SUCCESS) {
                printf("Failed to traverse directory file.\n");
                CM_FREE_PTR(file_list);
                return CT_ERROR;
            }
            is_copy_file = CT_TRUE;
        }
    }
    CM_FREE_PTR(file_list);
    return CT_SUCCESS;
}

status_t do_snapshot_restore_impl(ctbak_param_t* ctbak_param, char *dir_name, char *fs_name)
{
    char file_dir[MAX_DBS_FS_FILE_PATH_LEN] = { 0 };
    char backup_dir[MAX_DBS_FS_FILE_PATH_LEN] = { 0 };
    PRTS_RETURN_IFERR(snprintf_s(file_dir, MAX_DBS_FS_FILE_PATH_LEN,
                                 MAX_DBS_FS_FILE_PATH_LEN - 1, "/"));
    PRTS_RETURN_IFERR(snprintf_s(backup_dir, MAX_DBS_FS_FILE_PATH_LEN,
                                 MAX_DBS_FS_FILE_PATH_LEN - 1, "%s/%s", ctbak_param->target_dir.str, dir_name));
    status_t ret = traverse_directory(backup_dir, file_dir, fs_name, ctbak_param);
    if (ret != CT_SUCCESS) {
        printf("Failed to restore page backup files.\n");
        return ret;
    }
    return CT_SUCCESS;
}

status_t check_fs_empty_impl(const char *fs_name, const char *vstore_id, uint32 *file_num)
{
    char dbs_query_file_argv[DBS_QUERY_FILE_PRAMA_NUM + 1][MAX_DBS_FS_FILE_PATH_LEN] = { 0 };
    char *dbs_query_file_argv_ptr[DBS_QUERY_FILE_PRAMA_NUM + 1] = { 0 };

    for (int j = 0; j < DBS_QUERY_FILE_PRAMA_NUM + 1; j++) {
        dbs_query_file_argv_ptr[j] = dbs_query_file_argv[j];
    }
    void *file_list = NULL;
    file_info_version_t info_version;

    PRTS_RETURN_IFERR(snprintf_s(dbs_query_file_argv[DBS_QUERY_FILE_DBSTOR_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                                 MAX_DBS_FS_FILE_PATH_LEN - 1, "dbstor"));
    PRTS_RETURN_IFERR(snprintf_s(dbs_query_file_argv[DBS_QUERY_FILE_QUERY_FILE_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                                 MAX_DBS_FS_FILE_PATH_LEN - 1, "--query-file"));
    PRTS_RETURN_IFERR(snprintf_s(dbs_query_file_argv[DBS_QUERY_FILE_FS_NAME_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                                 MAX_DBS_FS_FILE_PATH_LEN - 1, "--fs-name=%s", fs_name));
    PRTS_RETURN_IFERR(snprintf_s(dbs_query_file_argv[DBS_QUERY_FILE_VSTORE_ID_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                                 MAX_DBS_FS_FILE_PATH_LEN - 1, "--vstore_id=%s", vstore_id));

    if (strcmp(fs_name, g_dbs_fs_info.archive_fs_name) == 0) {
        PRTS_RETURN_IFERR(snprintf_s(dbs_query_file_argv[DBS_QUERY_FILE_FILE_DIR_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                                     MAX_DBS_FS_FILE_PATH_LEN - 1, "--file-dir=/archive"));
    } else {
        PRTS_RETURN_IFERR(snprintf_s(dbs_query_file_argv[DBS_QUERY_FILE_FILE_DIR_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                                     MAX_DBS_FS_FILE_PATH_LEN - 1, "--file-dir=/%s", g_dbs_fs_info.cluster_name));
    }

    status_t ret = dbs_query_file(DBS_QUERY_FILE_PRAMA_NUM + 1, dbs_query_file_argv_ptr, &file_list, file_num, &info_version);
    if (ret != CT_SUCCESS) {
        printf("Failed to query files in fs: %s\n", fs_name);
    }
    cm_free_file_list(&file_list);
    return ret;
}

status_t check_fs_empty()
{
    printf("start check fs empty impl\n");
    uint32 file_num = 0;
    const char *fs_names[] = {
        g_dbs_fs_info.page_fs_name,
        g_dbs_fs_info.log_fs_name,
        g_dbs_fs_info.archive_fs_name,
    };
    const char *vstore_ids[] = {
        g_dbs_fs_info.page_fs_vstore_id,
        g_dbs_fs_info.log_fs_vstore_id,
        g_dbs_fs_info.archive_fs_vstore_id,
    };
    for (int i = 0; i < sizeof(fs_names) / sizeof(fs_names[0]); i++) {
        file_num = 0;
        if (strlen(fs_names[i]) == 0) {
            printf("fs_name is empty %d\n", i);
            return CT_ERROR;
        }
        if (check_fs_empty_impl(fs_names[i], vstore_ids[i], &file_num)!= CT_SUCCESS) {
            printf("Failed to query files in fs: %s\n", fs_names[i]);
            return CT_ERROR;
        }

        if (strcmp(fs_names[i], g_dbs_fs_info.log_fs_name) == 0 && file_num > 1) {
            printf("log fs not empty, please clean\n");
            return CT_ERROR;
        } else if (strcmp(fs_names[i], g_dbs_fs_info.log_fs_name) != 0 && file_num > 0) {
            printf("page or archive fs not empty, please clean\n");
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t do_snapshot_restore(ctbak_param_t* ctbak_param)
{
    printf("start do snapshot restore\n");
    if (check_fs_empty() != CT_SUCCESS) {
        printf("Failed to check fs empty.\n");
        return CT_ERROR;
    }

    status_t ret = dbs_set_ns_io_forbidden(CT_TRUE);
    if (ret != CT_SUCCESS) {
        printf("Set ns forbidden failed(%d).\n", ret);
        return ret;
    }

    //备份集目录
    ret = do_snapshot_restore_impl(ctbak_param, BACKUP_PAGE_DIR_NAME, g_dbs_fs_info.page_fs_name);
    if (ret != CT_SUCCESS) {
        dbs_set_ns_io_forbidden(CT_FALSE);
        printf("Failed to restore page backup files %s\n", BACKUP_PAGE_DIR_NAME);
        return ret;
    }

    ret = do_snapshot_restore_impl(ctbak_param, BACKUP_REDO_DIR_NAME, g_dbs_fs_info.log_fs_name);
    if (ret != CT_SUCCESS) {
        dbs_set_ns_io_forbidden(CT_FALSE);
        printf("Failed to restore redo backup files %s\n", BACKUP_REDO_DIR_NAME);
        return ret;
    }

    ret = dbs_set_ns_io_forbidden(CT_FALSE);
    if (ret != CT_SUCCESS) {
        printf("Set ns forbidden off failed(%d).\n", ret);
        return ret;
    }
    return CT_SUCCESS;
}
