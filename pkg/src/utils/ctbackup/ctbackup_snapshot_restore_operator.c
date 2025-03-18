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

// 递归遍历目录
status_t traverse_directory(char *path, char *fs_path, const char *fs_name, ctbak_param_t* ctbak_param) {
    uint32 file_num = 0;
    cm_file_info *file_list = (cm_file_info *)malloc(sizeof(cm_file_info) * DBS_DIR_MAX_FILE_NUM);
    if (file_list == NULL) {
        printf("Failed to allocate memory for file list.\n");
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
            printf("Found directory: %s/%s\n", path, file_list[i].file_name);
            // 构建子目录路径
            char *sub_path = (char*)malloc(MAX_DBS_FS_FILE_PATH_LEN);
            char *new_fs_path = (char*)malloc(MAX_DBS_FS_FILE_PATH_LEN);
            if (sub_path == NULL) {
                printf("[ctbackup]Failed to malloc\n");
                CM_FREE_PTR(file_list);
                return CT_ERROR;
            }
            if (new_fs_path == NULL) {
                printf("[ctbackup]Failed to malloc\n");
                CM_FREE_PTR(file_list);
                return CT_ERROR;
            }
            int ret = snprintf_s(sub_path, CT_MAX_FILE_PATH_LENGH,
                                 CT_MAX_FILE_PATH_LENGH - 1, "%s/%s", path, file_list[i].file_name);
            if (ret == CT_ERROR) {
                printf("Failed to build sub path.\n");
                CM_FREE_PTR(sub_path);
                CM_FREE_PTR(new_fs_path);
                CM_FREE_PTR(file_list);
                return CT_ERROR;
            }

            //在文件系统中创建目录
            //"dbstor", "--create-file", "--fs-name", "--file-dir"
            ret = snprintf_s(new_fs_path, MAX_DBS_FS_FILE_PATH_LEN,
                             MAX_DBS_FS_FILE_PATH_LEN - 1, "%s/%s", fs_path, file_list[i].file_name);
            if (ret == CT_ERROR) {
                printf("Failed to build sub path.\n");
                CM_FREE_PTR(sub_path);
                CM_FREE_PTR(new_fs_path);
                CM_FREE_PTR(file_list);
                return CT_ERROR;
            }

            char *argv[DBS_CREATE_DIR_PRAMA_NUM + 1] = {0};
            for (int j = 0; j < DBS_CREATE_DIR_PRAMA_NUM + 1; j++) {
                argv[j] = (char *)malloc(MAX_DBS_FS_FILE_PATH_LEN);
                if (argv[j] == NULL) {
                    CM_FREE_PTR(sub_path);
                    CM_FREE_PTR(new_fs_path);
                    CM_FREE_PTR(file_list);
                    while (--j >= 0) {
                        CM_FREE_PTR(argv[j]);
                    }
                    printf("[ctbackup]Failed to malloc\n");
                    return CT_ERROR;
                }
                errno_t ret1 = memset_sp(argv[j], MAX_DBS_FS_FILE_PATH_LEN, 0, MAX_DBS_FS_FILE_PATH_LEN);
                if (ret1 != EOK) {
                    CM_FREE_PTR(sub_path);
                    CM_FREE_PTR(new_fs_path);
                    CM_FREE_PTR(file_list);
                    while (--j >= 0) {
                        CM_FREE_PTR(argv[j]);
                    }
                    printf("[ctbackup]Failed to memset_sp\n");
                    return CT_ERROR;
                }
            }

            ret = snprintf_s(argv[DBS_CREATE_DIR_DBSTOR_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                             MAX_DBS_FS_FILE_PATH_LEN - 1, "dbstor");
            if (ret == CT_ERROR) {
                printf("Failed to build sub path.\n");
                free_system_call_params(argv, 0, DBS_CREATE_DIR_PRAMA_NUM);
                CM_FREE_PTR(sub_path);
                CM_FREE_PTR(new_fs_path);
                CM_FREE_PTR(file_list);
                return CT_ERROR;
            }

            ret = snprintf_s(argv[DBS_CREATE_DIR_CREATE_DIR_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                             MAX_DBS_FS_FILE_PATH_LEN - 1, "--create-file");
            if (ret == CT_ERROR) {
                printf("Failed to build sub path.\n");
                free_system_call_params(argv, 0, DBS_CREATE_DIR_PRAMA_NUM);
                CM_FREE_PTR(sub_path);
                CM_FREE_PTR(new_fs_path);
                CM_FREE_PTR(file_list);
                return CT_ERROR;
            }

            ret = snprintf_s(argv[DBS_CREATE_DIR_FS_NAME_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                             MAX_DBS_FS_FILE_PATH_LEN - 1, "--fs-name=%s", fs_name);
            if (ret == CT_ERROR) {
                printf("Failed to build sub path.\n");
                free_system_call_params(argv, 0, DBS_CREATE_DIR_PRAMA_NUM);
                CM_FREE_PTR(sub_path);
                CM_FREE_PTR(new_fs_path);
                CM_FREE_PTR(file_list);
                return CT_ERROR;
            }

            ret = snprintf_s(argv[DBS_CREATE_DIR_FILE_DIR_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                             MAX_DBS_FS_FILE_PATH_LEN - 1, "--file-dir=%s/%s", fs_path, file_list[i].file_name);
            if (ret == CT_ERROR) {
                printf("Failed to build sub path.\n");
                free_system_call_params(argv, 0, DBS_CREATE_DIR_PRAMA_NUM);
                CM_FREE_PTR(sub_path);
                CM_FREE_PTR(new_fs_path);
                CM_FREE_PTR(file_list);
                return CT_ERROR;
            }

            ret = dbs_create_path_or_file(DBS_CREATE_DIR_PRAMA_NUM + 1, argv);
            if (ret != CT_SUCCESS) {
                printf("Failed to create directory.\n");
                free_system_call_params(argv, 0, DBS_CREATE_DIR_PRAMA_NUM);
                CM_FREE_PTR(sub_path);
                CM_FREE_PTR(new_fs_path);
                return ret;
            }


            // 递归遍历子目录
            free_system_call_params(argv, 0, DBS_CREATE_DIR_PRAMA_NUM);
            if (traverse_directory(sub_path, new_fs_path, fs_name, ctbak_param) != CT_SUCCESS) {
                printf("Failed to traverse sub directory.\n");
                CM_FREE_PTR(sub_path);
                CM_FREE_PTR(new_fs_path);
                CM_FREE_PTR(file_list);
                return CT_ERROR;
            }
            CM_FREE_PTR(sub_path);
            CM_FREE_PTR(new_fs_path);
        } else {
            printf("Found file: %s/%s", path, file_list[i].file_name);

            // "dbstor", "--copy-file", "--import", "--fs-name=", "--source-dir=", "--target-dir="
            char *argv[DBS_COPY_FILE_PRAMA_NUM + 1] = {0};
            for (int j = 0; j < DBS_COPY_FILE_PRAMA_NUM + 1; j++) {
                argv[j] = (char *)malloc(MAX_DBS_FS_FILE_PATH_LEN);
                if (argv[j] == NULL) {
                    CM_FREE_PTR(file_list);
                    while (--j >= 0) {
                        CM_FREE_PTR(argv[j]);
                    }
                    printf("[ctbackup]Failed to malloc\n");
                    return CT_ERROR;
                }
                errno_t ret1 = memset_sp(argv[j], MAX_DBS_FS_FILE_PATH_LEN, 0, MAX_DBS_FS_FILE_PATH_LEN);
                if (ret1!= EOK) {
                    CM_FREE_PTR(file_list);
                    while (--j >= 0) {
                        CM_FREE_PTR(argv[j]);
                    }
                    printf("[ctbackup]Failed to memset_sp\n");
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
        }
    }
    CM_FREE_PTR(file_list);
    return CT_SUCCESS;
}

status_t do_snapshot_restore_impl(ctbak_param_t* ctbak_param, char *dir_name, char *fs_name){
    char file_dir[MAX_DBS_FS_FILE_PATH_LEN] = {0};
    char backup_dir[MAX_DBS_FS_FILE_PATH_LEN] = {0};
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

status_t do_snapshot_restore(ctbak_param_t* ctbak_param){
    status_t ret = dbs_set_ns_io_forbidden(CT_TRUE);
    if (ret != CT_SUCCESS) {
        printf("Set ns forbidden failed(%d).\n", ret);
        return ret;
    }

    ret = dbs_pagepool_clean();
    if (ret != CT_SUCCESS) {
        dbs_set_ns_io_forbidden(CT_FALSE);
        printf("Pagepool clean failed.\n");
        return ret;
    }

    ret = dbs_ulog_clean();
    if (ret != CT_SUCCESS) {
        dbs_set_ns_io_forbidden(CT_FALSE);
        printf("ulog clean failed.\n");
        return ret;
    }

    ret = dbs_arch_clean();
    if (ret != CT_SUCCESS) {
        dbs_set_ns_io_forbidden(CT_FALSE);
        printf("arch clean failed.\n");
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

