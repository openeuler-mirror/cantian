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
* ctbackup_snapshot_backup_operator.c
*
*
* IDENTIFICATION
* src/utils/ctbackup/ctbackup_snapshot_backup_operator.c
*
* -------------------------------------------------------------------------
 */

#include "ctbackup_snapshot_backup_operator.h"
#include "ctbackup_dbs_common.h"

status_t handle_snapshot_backup_dir(ctbak_param_t* ctbak_param, void **file_list, char *file_name,
                                     char *dbs_query_file_argv[], char *backup_dir, char *file_dir){
    //创建备份集目录
    // create /xxx/backup_dir/-ctrl1/
    char parent_file_dir[MAX_DBS_FS_FILE_PATH_LEN] = { 0 };
    char parent_backup_dir[MAX_DBS_FS_FILE_PATH_LEN] = { 0 };
    status_t ret;

    //备份集父目录 /xxx/backup_dir/
    ret = snprintf_s(parent_backup_dir, MAX_DBS_FS_FILE_PATH_LEN,
                     MAX_DBS_FS_FILE_PATH_LEN - 1, "%s", backup_dir);
    if (ret == CT_ERROR) {
        printf("[ctbackup]Failed to snprintf_s\n");
        return CT_ERROR;
    }

    //备份集子目录    /xxx/backup_dir/-ctrl1/
    ret = snprintf_s(backup_dir, MAX_DBS_FS_FILE_PATH_LEN,
                     MAX_DBS_FS_FILE_PATH_LEN - 1, "%s/%s/", backup_dir, file_name);
    if (ret == CT_ERROR) {
        printf("[ctbackup]Failed to snprintf_s\n");
        return CT_ERROR;
    }
    if (cm_create_dir_ex(backup_dir) != CT_SUCCESS) {
        printf("[ctbackup]Failed to cm_create_dir_ex %s\n", backup_dir);
        return CT_ERROR;
    }

    //文件系统父目录路径
    // /.snapshot/snapshot_name/
    ret = snprintf_s(parent_file_dir, MAX_DBS_FS_FILE_PATH_LEN,
                     MAX_DBS_FS_FILE_PATH_LEN - 1, "%s", file_dir);
    if (ret == CT_ERROR) {
        printf("[ctbackup]Failed to snprintf_s\n");
        return CT_ERROR;
    }

    //文件系统子目录
    // /.snapshot/snapshot_name/-ctrl1
    ret = snprintf_s(file_dir, MAX_DBS_FS_FILE_PATH_LEN,
                     MAX_DBS_FS_FILE_PATH_LEN - 1, "%s/%s/", file_dir, file_name);
    if (ret == CT_ERROR) {
        printf("[ctbackup]Failed to snprintf_s\n");
        return CT_ERROR;
    }
    create_backup_dir(ctbak_param, dbs_query_file_argv, backup_dir, file_dir);

    //还原父目录路径
    ret = snprintf_s(backup_dir, MAX_DBS_FS_FILE_PATH_LEN,
                     MAX_DBS_FS_FILE_PATH_LEN - 1, "%s", parent_backup_dir);
    if (ret == CT_ERROR) {
        printf("[ctbackup]Failed to snprintf_s\n");
        return CT_ERROR;
    }

    ret = snprintf_s(file_dir, MAX_DBS_FS_FILE_PATH_LEN,
                     MAX_DBS_FS_FILE_PATH_LEN - 1, "%s", parent_file_dir);
    if (ret == CT_ERROR) {
        printf("[ctbackup]Failed to snprintf_s\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t handle_snapshot_backup_file(void **file_list, char *file_name,
                                     char *dbs_query_file_argv[], char *backup_dir, char *file_dir) {
    // 将文件系统数据读取上来写入备份集
    // from /.snapshot/snapshot_name/-ctrl1/0/dataObj to /xxx/backup_dir/-ctrl1/0/dataObj
    // "dbstor", "--copy-file", "--export", "--fs-name", "--source-dir","--target-dir", "--file-name"
    status_t ret;
    char *dbs_copy_file_argv[DBS_COPY_FILE_PRAMA_NUM + 1] = { 0 };
    for (int j = 0; j < DBS_COPY_FILE_PRAMA_NUM + 1; j++) {
        dbs_copy_file_argv[j] = (char *)malloc(MAX_DBS_FS_FILE_PATH_LEN);
        if (dbs_copy_file_argv[j] == NULL) {
            while (--j >= 0) {
                CM_FREE_PTR(dbs_copy_file_argv[j]);
            }
            printf("[ctbackup]dbs_copy_file_argv Failed to malloc\n");
            return CT_ERROR;
        }
        errno_t err = memset_sp(dbs_copy_file_argv[j], MAX_DBS_FS_FILE_PATH_LEN, 0, MAX_DBS_FS_FILE_PATH_LEN);
        if (err != EOK) {
            while (--j >= 0) {
                CM_FREE_PTR(dbs_copy_file_argv[j]);
            }
            printf("[ctbackup]Failed to memset_sp (%d)\n", err);
            return CT_ERROR;
        }
    }

    do {
        ret = snprintf_s(dbs_copy_file_argv[DBS_COPY_FILE_DBSTOR_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                         MAX_DBS_FS_FILE_PATH_LEN - 1, "dbstor");
        if (ret == CT_ERROR) {
            printf("[ctbackup]handle_snapshot_backup_file Failed to snprintf_s dbstor\n");
            break;
        }

        ret = snprintf_s(dbs_copy_file_argv[DBS_COPY_FILE_COPY_FILE_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                         MAX_DBS_FS_FILE_PATH_LEN - 1, "--copy-file");
        if (ret == CT_ERROR) {
            printf("[ctbackup]handle_snapshot_backup_file Failed to snprintf_s --copy-file\n");
            break;
        }

        ret = snprintf_s(dbs_copy_file_argv[DBS_COPY_FILE_OP_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                         MAX_DBS_FS_FILE_PATH_LEN - 1, "--export");
        if (ret == CT_ERROR) {
            printf("[ctbackup]handle_snapshot_backup_file Failed to snprintf_s --export\n");
            break;
        }

        ret = snprintf_s(dbs_copy_file_argv[DBS_COPY_FILE_FS_NAME_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                         MAX_DBS_FS_FILE_PATH_LEN - 1, "%s", dbs_query_file_argv[DBS_QUERY_FILE_FS_NAME_PRAMA]);
        if (ret == CT_ERROR) {
            printf("[ctbackup]handle_snapshot_backup_file Failed to snprintf_s DBS_COPY_FILE_FS_NAME_PRAMA\n");
            break;
        }

        ret = snprintf_s(dbs_copy_file_argv[DBS_COPY_FILE_SOURCE_DIR_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                         MAX_DBS_FS_FILE_PATH_LEN - 1, "--source-dir=%s/", file_dir);
        if (ret == CT_ERROR) {
            printf("[ctbackup]handle_snapshot_backup_file Failed to snprintf_s --source-dir\n");
            break;
        }

        ret = snprintf_s(dbs_copy_file_argv[DBS_COPY_FILE_FILE_NAME_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                         MAX_DBS_FS_FILE_PATH_LEN - 1, "--file-name=%s", file_name);
        if (ret == CT_ERROR) {
            printf("[ctbackup]handle_snapshot_backup_file Failed to snprintf_s --file-name\n");
            break;
        }
    } while (0);

    if (ret == CT_ERROR) {
        cm_free_file_list(file_list);
        free_system_call_params(dbs_copy_file_argv, 0, DBS_COPY_FILE_PRAMA_NUM);
        printf("[ctbackup]handle_snapshot_backup_file Failed to snprintf_s\n");
        return CT_ERROR;
    }

    if (backup_dir == NULL) {
        cm_free_file_list(file_list);
        free_system_call_params(dbs_copy_file_argv, 0, DBS_COPY_FILE_PRAMA_NUM);
        printf("[ctbackup]backup_dir is null\n");
        return CT_ERROR;
    }
    ret = snprintf_s(dbs_copy_file_argv[DBS_COPY_FILE_TARGET_DIR_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                     MAX_DBS_FS_FILE_PATH_LEN - 1, "--target-dir=%s", backup_dir);

    if (ret == CT_ERROR) {
        cm_free_file_list(file_list);
        free_system_call_params(dbs_copy_file_argv, 0, DBS_COPY_FILE_PRAMA_NUM);
        printf("[ctbackup]Failed to snprintf_s\n");
        return CT_ERROR;
    }

    ret = dbs_copy_file(DBS_COPY_FILE_PRAMA_NUM + 1, dbs_copy_file_argv);
    if (ret == CT_ERROR) {
        cm_free_file_list(file_list);
        free_system_call_params(dbs_copy_file_argv, 0, DBS_COPY_FILE_PRAMA_NUM);
        printf("[ctbackup]Failed to dbs_copy_file\n");
        return CT_ERROR;
    }

    free_system_call_params(dbs_copy_file_argv, 0, DBS_COPY_FILE_PRAMA_NUM);
    return CT_SUCCESS;
}

status_t create_backup_dir(ctbak_param_t* ctbak_param, char *dbs_query_file_argv[],
                           char *backup_dir, char *file_dir) {
    void *file_list = NULL;
    uint32 file_num = 0;
    file_info_version_t info_version;

    status_t ret = snprintf_s(dbs_query_file_argv[DBS_QUERY_FILE_FILE_DIR_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                              MAX_DBS_FS_FILE_PATH_LEN - 1, "--file-dir=%s", file_dir);
    if (ret == CT_ERROR) {
        printf("[ctbackup]create_backup_dir Failed to snprintf_s\n");
        return CT_ERROR;
    }
    ret = dbs_query_file(DBS_QUERY_FILE_PRAMA_NUM + 1, dbs_query_file_argv, &file_list, &file_num, &info_version);
    if (ret != CT_SUCCESS) {
        cm_free_file_list(&file_list);
        printf("[ctbackup]Failed to dbs_query_file\n");
        return CT_ERROR;
    }

    for (uint32 i = 0; i < file_num; i++) {
        char *file_name = NULL;
        cs_file_type file_type;
        if (info_version == DBS_FILE_INFO_VERSION_1) {
            dbstor_file_info *file_info = (dbstor_file_info *)((char *)file_list + i * sizeof(dbstor_file_info));
            if (file_info == NULL) {
                printf("[ctbackup]file_info is null\n");
                return CT_ERROR;
            }
            file_name = file_info->file_name;
            file_type = file_info->type;
        } else {
            dbstor_file_info_detail *file_info = (dbstor_file_info_detail *)((char *)file_list +
                                                                             i * sizeof(dbstor_file_info_detail));
            if (file_info == NULL) {
                printf("[ctbackup]file_info is null\n");
                return CT_ERROR;
            }
            file_name = file_info->file_name;
            file_type = file_info->type;
        }
        if (file_name == NULL || strlen(file_name) == 0) {
            continue;
        }
        if (file_type == CS_FILE_TYPE_DIR) {
            ret = handle_snapshot_backup_dir(ctbak_param, &file_list, file_name, dbs_query_file_argv, backup_dir, file_dir);
            if (ret!= CT_SUCCESS) {
                cm_free_file_list(&file_list);
                printf("[ctbackup]Failed to handle_snapshot_backup_dir\n");
                return CT_ERROR;
            }
        } else if (file_type == CS_FILE_TYPE_FILE) {
            ret = handle_snapshot_backup_file(&file_list, file_name, dbs_query_file_argv, backup_dir, file_dir);
            if (ret != CT_SUCCESS) {
                cm_free_file_list(&file_list);
                printf("[ctbackup]Failed to handle_snapshot_backup_file\n");
                return CT_ERROR;
            }
        }
    }

    cm_free_file_list(&file_list);
    return CT_SUCCESS;
}

status_t query_fs_dir_and_create_dir_impl(ctbak_param_t* ctbak_param, char *fs_name,
                                          char *vstore_id, char *snapshot_name, char *dir_name,
                                          char *timestamp){
    // 查询文件系统快照目录信息
    char *dbs_query_file_argv[DBS_QUERY_FILE_PRAMA_NUM + 1] = {0};
    char file_dir[MAX_DBS_FS_FILE_PATH_LEN] = {0};
    char backup_dir[MAX_DBS_FS_FILE_PATH_LEN] = {0};

    // "dbstor", "--query-file", "--fs-name", "--file-dir", "--vstore_id"
    for (int i = 0; i < DBS_QUERY_FILE_PRAMA_NUM + 1; i++) {
        dbs_query_file_argv[i] = (char *)malloc(MAX_DBS_FS_FILE_PATH_LEN);
        if (dbs_query_file_argv[i] == NULL) {
            while (i-- >= 0) {
                CM_FREE_PTR(dbs_query_file_argv[i]);
            }
            printf("[ctbackup]dbs_query_file_argv Failed to malloc\n");
            return CT_ERROR;
        }
        errno_t err = memset_sp(dbs_query_file_argv[i], MAX_DBS_FS_FILE_PATH_LEN, 0, MAX_DBS_FS_FILE_PATH_LEN);
        if (err != EOK) {
            while (i-- >= 0) {
                CM_FREE_PTR(dbs_query_file_argv[i]);
            }
            printf("[ctbackup]Failed to memset_sp (%d)\n", err);
            return CT_ERROR;
        }
    }

    PRTS_RETURN_IFERR(snprintf_s(dbs_query_file_argv[DBS_QUERY_FILE_DBSTOR_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                                 MAX_DBS_FS_FILE_PATH_LEN - 1, "dbstor"));
    PRTS_RETURN_IFERR(snprintf_s(dbs_query_file_argv[DBS_QUERY_FILE_QUERY_FILE_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                                 MAX_DBS_FS_FILE_PATH_LEN - 1, "--query-file"));
    PRTS_RETURN_IFERR(snprintf_s(dbs_query_file_argv[DBS_QUERY_FILE_FS_NAME_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                                 MAX_DBS_FS_FILE_PATH_LEN - 1, "--fs-name=%s", fs_name));
    PRTS_RETURN_IFERR(snprintf_s(dbs_query_file_argv[DBS_QUERY_FILE_FILE_DIR_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                                 MAX_DBS_FS_FILE_PATH_LEN - 1, "--file-dir=/.snapshot/%s/%s",
                                 snapshot_name, g_dbs_fs_info.cluster_name));
    PRTS_RETURN_IFERR(snprintf_s(dbs_query_file_argv[DBS_QUERY_FILE_VSTORE_ID_PRAMA], MAX_DBS_FS_FILE_PATH_LEN,
                                 MAX_DBS_FS_FILE_PATH_LEN - 1, "--vstore_id=%s", vstore_id));
    //文件系统快照目录
    PRTS_RETURN_IFERR(snprintf_s(file_dir, MAX_DBS_FS_FILE_PATH_LEN,
                                 MAX_DBS_FS_FILE_PATH_LEN - 1, "/.snapshot/%s/%s",
                                 snapshot_name, g_dbs_fs_info.cluster_name));

    //备份集目录
    PRTS_RETURN_IFERR(snprintf_s(backup_dir, MAX_DBS_FS_FILE_PATH_LEN,
                                 MAX_DBS_FS_FILE_PATH_LEN - 1, "%s/%s/%s/%s",
                                 ctbak_param->target_dir.str, timestamp, dir_name, g_dbs_fs_info.cluster_name));

    if (cm_create_dir_ex(backup_dir) != CT_SUCCESS) {
        printf("[ctbackup]Failed to cm_create_dir_ex %s\n", backup_dir);
        return CT_ERROR;
    }
    status_t ret = create_backup_dir(ctbak_param, dbs_query_file_argv, backup_dir, file_dir);
    if (ret != CT_SUCCESS) {
        printf("[ctbackup]Failed to create_backup_dir\n");
        free_system_call_params(dbs_query_file_argv, 0, DBS_QUERY_FILE_PRAMA_NUM);
        return CT_ERROR;
    }
    free_system_call_params(dbs_query_file_argv, 0, DBS_QUERY_FILE_PRAMA_NUM);
    return CT_SUCCESS;
}

status_t query_fs_dir_and_create_dir(ctbak_param_t* ctbak_param, snapshot_backup_info_t *snapshot_backup_info){
    time_t now = time(NULL);
    struct tm *tm_now = localtime(&now);
    char timestamp[32] = {0};
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_now);

    if (query_fs_dir_and_create_dir_impl(ctbak_param, g_dbs_fs_info.page_fs_name,
                                         g_dbs_fs_info.page_fs_vstore_id, snapshot_backup_info->page_fs_snap_info.snapName,
                                         BACKUP_PAGE_DIR_NAME, timestamp)!= CT_SUCCESS) {
        printf("[ctbackup]Failed to query_fs_dir_and_create_dir %s\n", g_dbs_fs_info.page_fs_name);
        return CT_ERROR;
    }
    if (query_fs_dir_and_create_dir_impl(ctbak_param, g_dbs_fs_info.log_fs_name,
                                         g_dbs_fs_info.log_fs_vstore_id,  snapshot_backup_info->log_fs_snap_info.snapName,
                                         BACKUP_REDO_DIR_NAME, timestamp)!= CT_SUCCESS) {
        printf("[ctbackup]Failed to query_fs_dir_and_create_dir %s\n", g_dbs_fs_info.log_fs_name);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t do_snapshot_backup(ctbak_param_t* ctbak_param){
    // 从share文件系统获取快照名称
    object_id_t snapshot_info_file_handle;
    snapshot_backup_info_t *snapshot_backup_info = (snapshot_backup_info_t *)malloc(sizeof(snapshot_backup_info_t));
    if (snapshot_backup_info == NULL) {
        printf("[ctbackup]snapshot_backup_info Failed to malloc\n");
        return CT_ERROR;
    }

    char file_name[CT_MAX_FILE_PATH_LENGH] = {0};
    status_t ret = snprintf_s(file_name, CT_MAX_FILE_PATH_LENGH,
                     CT_MAX_FILE_PATH_LENGH - 1, "%s/%s", SNAPSHOT_INFO_FS_PATH, CTBAK_SNAP_INFO_FILE_NAME);
    if (ret == CT_ERROR) {
        CM_FREE_PTR(snapshot_backup_info);
        printf("[ctbackup]Failed to snprintf_s\n");
        return CT_ERROR;
    }
    ret = ctbak_get_file_handle_from_share_fs(
        g_dbs_fs_info.share_fs_name, file_name,
        &snapshot_info_file_handle);
    if (ret != CT_SUCCESS) {
        CM_FREE_PTR(snapshot_backup_info);
        printf("[ctbackup]Failed to get file handle\n");
        return CT_ERROR;
    }

    ret = cm_read_dbs_file(&snapshot_info_file_handle
                           , 0, snapshot_backup_info, sizeof(snapshot_backup_info_t));
    if (ret != CT_SUCCESS) {
        CM_FREE_PTR(snapshot_backup_info);
        printf("[ctbackup]Failed to read snap info\n");
        return CT_ERROR;
    }
    // 在本地备份集按照相同格式创建目录并拷贝数据
    ret = query_fs_dir_and_create_dir(ctbak_param, snapshot_backup_info);
    if (ret!= CT_SUCCESS) {
        CM_FREE_PTR(snapshot_backup_info);
        printf("[ctbackup]Failed to query_fs_dir_and_create_dir\n");
        return CT_ERROR;
    }

    CM_FREE_PTR(snapshot_backup_info);
    return CT_SUCCESS;
}