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
* ctbackup_dbs_common.h
*
*
* IDENTIFICATION
* src/utils/ctbackup/ctbackup_dbs_common.h
*
* -------------------------------------------------------------------------
 */

#ifndef CANTIANDB_CTBACKUP_DBS_COMMON_H
#define CANTIANDB_CTBACKUP_DBS_COMMON_H

#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include <sys/file.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include "cm_defs.h"
#include "cm_log.h"
#include "cm_file.h"
#include "cm_date.h"
#include "cm_dbstor.h"
#include "dirent.h"
#include "cm_dbs_defs.h"
#include "cm_dbs_file.h"
#include "cm_utils.h"
#include "ctbackup_module.h"
#include "ctbackup_info.h"

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

typedef struct {
    device_type_t type;
    int32 handle;
    char path[MAX_DBS_FS_FILE_PATH_LEN];
} dbs_device_info_t;

typedef struct {
    char log_fs_name[MAX_DBS_FS_NAME_LEN];
    char page_fs_name[MAX_DBS_FS_NAME_LEN];
    char cluster_name[MAX_DBS_FILE_NAME_LEN];
    char log_fs_vstore_id[MAX_DBS_VSTORE_ID_LEN];
    char dbs_log_path[MAX_DBS_FS_NAME_LEN];
    char page_fs_vstore_id[MAX_DBS_VSTORE_ID_LEN];
    char share_fs_name[MAX_DBS_FS_NAME_LEN];
    char archive_fs_name[MAX_DBS_FS_NAME_LEN];
    char archive_fs_vstore_id[MAX_DBS_VSTORE_ID_LEN];
} dbs_fs_info_t;

status_t dbs_init(ctbak_param_t* ctbak_param);
// dbstor --query-file --fs-name=xxx [--file-dir=xxx] [--vstore_id=*]
int32 dbs_query_fs_file(int32 argc, char *argv[]);
// dbstor --copy-file --import/--export --fs-name=xxx --source-dir=* --target-dir=* [--file-name=*] [--overwrite]
status_t dbs_copy_fs_file(int32 argc, char *argv[]);
// dbstor --io-forbidden <0, 1>
int32 dbs_set_io_forbidden(int32 argc, char *argv[]);
status_t dbs_create_fs_snap(char* fsName, uint32_t vstorId, snapshot_result_info* snap_info);
status_t dbs_delete_fs_snap(char* fsName, uint32_t vstorId, snapshot_result_info* snap_info);
status_t dbs_create_snapshot_info_file(const char *file_name, int32 *handle);
status_t dbs_write_snapshot_info_file(int32 handle, int64 offset, const void *buf, int32 size);
status_t dbs_read_snapshot_info_file(object_id_t* handle, uint64 offset, void* buf, uint32 length);
uint32 get_parse_params_init_value(char *argv[]);
bool32 compare_bool_param(char *argv[], params_list_t *params_list, uint32 i, uint32 j, bool32 *matched);
status_t compare_param(char *argv[], params_list_t *params_list, uint32 i, uint32 j, bool32 *matched);
status_t parse_params_list(int32 argc, char *argv[], params_list_t *params_list);
status_t check_dir_exist(const char *direction, const char *src_path, const char *dst_path,
                         char *fs_path, const char *fs_name);
status_t copy_file(const dbs_device_info_t *src_info, const dbs_device_info_t *dst_info);
status_t check_strcat_path(const char *dir, const char *name, char *strcat_name);
status_t copy_file_by_name(const char *file_name, dbs_device_info_t *src_info,
                           dbs_device_info_t *dst_info, bool32 overwrite);
status_t copy_files_to_target_dir(dbs_device_info_t *src_info, dbs_device_info_t *dst_info,
                                  const char *file_name, bool32 overwrite);
status_t ctbak_get_file_handle_from_share_fs(char *file_path, char *file_name, object_id_t *file_handle);
status_t file_info_screen_print(void *file_list, uint32 file_num, char *path, file_info_version_t info_version);

extern dbs_fs_info_t g_dbs_fs_info;

#endif  // CANTIANDB_CTBACKUP_DBS_COMMON_H
