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
* ctbackup_snapshot_backup_operator.h
*
*
* IDENTIFICATION
* src/utils/ctbackup/ctbackup_snapshot_backup_operator.h
*
* -------------------------------------------------------------------------
 */

#ifndef CANTIANDB_CTBACKUP_SNAPSHOT_BACKUP_OPERATOR_H
#define CANTIANDB_CTBACKUP_SNAPSHOT_BACKUP_OPERATOR_H

#include "cm_defs.h"
#include "ctbackup_info.h"
#include "cm_file.h"
#include "bak_common.h"
#include "cm_dbs_snapshot.h"
#include "ctbackup_common.h"
#include "cm_dbs_file.h"
#include "ctbackup_common.h"
#include "ctbackup_dbs_operator.h"

status_t do_snapshot_backup(ctbak_param_t* ctbak_param);
status_t query_fs_dir_and_create_dir(ctbak_param_t* ctbak_param, snapshot_backup_info_t *snapshot_backup_info);
status_t create_backup_dir(ctbak_param_t* ctbak_param, char *dbs_query_file_argv[],
                           char *backup_dir, char *file_dir);
status_t handle_snapshot_backup_dir(ctbak_param_t* ctbak_param, void **file_list, char *file_name,
                                    char *dbs_query_file_argv[], char *backup_dir, char *file_dir);
#endif  // CANTIANDB_CTBACKUP_SNAPSHOT_BACKUP_OPERATOR_H
