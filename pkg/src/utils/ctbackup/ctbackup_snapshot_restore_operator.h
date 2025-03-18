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
* ctbackup_snapshot_restore_operator.h
*
*
* IDENTIFICATION
* src/utils/ctbackup/ctbackup_snapshot_restore_operator.h
*
* -------------------------------------------------------------------------
 */


#ifndef CANTIANDB_CTBACKUP_SNAPSHOT_RESTORE_OPERATOR_H
#define CANTIANDB_CTBACKUP_SNAPSHOT_RESTORE_OPERATOR_H

#include "cm_defs.h"
#include "ctbackup_info.h"
#include "cm_file.h"
#include "bak_common.h"
#include "cm_dbs_snapshot.h"
#include "ctbackup_common.h"
#include "cm_dbs_file.h"
#include "ctbackup_common.h"

status_t do_snapshot_restore(ctbak_param_t* ctbak_param);
status_t traverse_directory(char *path, char *fs_path, const char *fs_name, ctbak_param_t* ctbak_param);

#endif  // CANTIANDB_CTBACKUP_SNAPSHOT_RESTORE_OPERATOR_H