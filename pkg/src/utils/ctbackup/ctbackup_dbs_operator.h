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
* ctbackup_dbs_operator.h
*
*
* IDENTIFICATION
* src/utils/ctbackup/ctbackup_dbs_operator.h
*
* -------------------------------------------------------------------------
*/

#ifndef CANTIANDB_CTBACKUP_DBS_OPERATOR_H
#define CANTIANDB_CTBACKUP_DBS_OPERATOR_H

#include "cm_defs.h"
#include "ctbackup_info.h"
#include "cm_file.h"
#include "bak_common.h"
#include "cm_dbs_snapshot.h"
#include "ctbackup_common.h"
#include "cm_dbs_file.h"
#include "ctbackup_common.h"
#include "ctbackup_module.h"

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
#define DBS_TOOL_PARAM_FILE_DIR "--file-dir="
#define DBS_TOOL_PARAM_VSTORE_ID "--vstore_id="
#define DBS_PERF_SHOW_INTERVAL "--interval="
#define DBS_PERF_SHOW_TIMES "--times="
#define DBS_TOOL_PARAM_OVERWRITE "--overwrite"
#define MAX_VALUE_UINT32 "4294967295"
#define DBS_LINK_CHECK_CNT "LINK_CHECK_CNT"
#define BOOL_FALSE "false"
#define BOOL_FALSE_LEN 5
#define BOOL_TRUE "true"
#define BOOL_TRUE_LEN 4
#define DBS_FILE_TYPE_DIR "dir"
#define DBS_FILE_TYPE_FILE "file"
#define DBS_FILE_TYPE_UNKNOWN "unknown"
#define DBS_TOOL_PARAM_BOOL_LEN 6
#define DBS_LINK_CHECK_PARAM_LEN 64
#define DBS_LINK_TIMEOUT_MIN 3
#define DBS_LINK_TIMEOUT_MAX 10

#define DBS_COPY_FILE_PARAM "--copy-file"
#define DBS_IMPORT_PARAM "--import"
#define DBS_EXPORT_PARAM "--export"

#define BACKUP_PAGE_DIR_NAME "page"
#define BACKUP_REDO_DIR_NAME "ulog"


#define DBS_ARCH_QUERY_PRAMA_NUM 1
#define DBS_ARCH_CLEAN_PRAMA_NUM 1
#define DBS_ARCH_EXPORT_PRAMA_NUM 3
#define DBS_ARCH_IMPORT_PRAMA_NUM 3
#define DBS_ULOG_CLEAN_PRAMA_NUM 3
#define DBS_PGPOOL_CLEAN_PRAMA_NUM 2
#define DBS_CRAETE_FILE_PRAMA_NUM 3
#define DBS_COPY_FILE_PRAMA_NUM 6
#define DBS_DELETE_FILE_PRAMA_NUM 2
#define DBS_QUERY_FILE_PRAMA_NUM 4
#define DBS_QUERY_FS_INFO_PRAMA_NUM 2
#define DBS_CREATE_DIR_PRAMA_NUM 3


#define DBS_NO_CHECK_PRAMA_NUM 0
#define DBS_ARCH_EXPORT_PRAMA_CHECK_NUM 1
#define DBS_ARCH_IMPORT_PRAMA_CHECK_NUM 1
#define DBS_ULOG_CLEAN_CHECK_PRAMA_NUM 3
#define DBS_PGPOOL_CLEAN_CHECK_PRAMA_NUM 2
#define DBS_CRAETE_FILE_CHECK_PRAMA_NUM 1
#define DBS_COPY_FILE_CHECK_PRAMA_NUM 3
#define DBS_DELETE_FILE_CHECK_PRAMA_NUM 2
#define DBS_QUERY_FS_INFO_CHECK_PRAMA_NUM 2
#define DBS_PERF_SHOW_PRAMA_NUM 2
#define DBS_QUERY_FILE_CHECK_PRAMA_NUM 1

#define MODE_STR_LEN 10
#define USER_NAME_LEN 32
#define GROUP_NAME_LEN 255
#define TIME_STR_LEN 25
#define DBS_WAIT_CGW_LINK_INIT_TIME_SECOND 2

#define DBS_COPY_FILE_DBSTOR_PRAMA 0
#define DBS_COPY_FILE_COPY_FILE_PRAMA 1
#define DBS_COPY_FILE_OP_PRAMA 2
#define DBS_COPY_FILE_FS_NAME_PRAMA 3
#define DBS_COPY_FILE_SOURCE_DIR_PRAMA 4
#define DBS_COPY_FILE_TARGET_DIR_PRAMA 5
#define DBS_COPY_FILE_FILE_NAME_PRAMA 6

#define DBS_QUERY_FILE_DBSTOR_PRAMA 0
#define DBS_QUERY_FILE_QUERY_FILE_PRAMA 1
#define DBS_QUERY_FILE_FS_NAME_PRAMA 2
#define DBS_QUERY_FILE_FILE_DIR_PRAMA 3
#define DBS_QUERY_FILE_VSTORE_ID_PRAMA 4

#define DBS_CREATE_DIR_DBSTOR_PRAMA 0
#define DBS_CREATE_DIR_CREATE_DIR_PRAMA 1
#define DBS_CREATE_DIR_FS_NAME_PRAMA 2
#define DBS_CREATE_DIR_FILE_DIR_PRAMA 3

typedef bool32 (*file_filter_func)(const char *);

//extern dbs_fs_info_t g_dbs_fs_info;

//status_t dbstool_init();
int32 dbs_arch_clean();
int32 dbs_ulog_clean();
int32 dbs_pagepool_clean();
int32 dbs_copy_file(int32 argc, char *argv[]);
status_t dbs_query_file(int32 argc, char *argv[], void **file_list, uint32 *file_num, file_info_version_t *info_version);
status_t dbs_set_ns_io_forbidden(bool32 is_forbidden);
int32 dbs_query_fs_info(int32 argc, char *argv[]);
int32 dbs_perf_show(int32 argc, char *argv[]);
status_t dbs_create_path_or_file(int32 argc, char *argv[]);
#endif  // CANTIANDB_CTBACKUP_DBS_OPERATOR_H
