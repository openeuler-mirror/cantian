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
* ctbackup_snapshot.h
*
*
* IDENTIFICATION
* src/utils/ctbackup/ctbackup_snapshot_restore.h
*
* -------------------------------------------------------------------------
 */

#ifndef CANTIANDB_CTBACKUP_SNAPSHOT_RESTORE_H
#define CANTIANDB_CTBACKUP_SNAPSHOT_RESTORE_H

#include "ctbackup_info.h"

ctbak_cmd_t *ctbak_generate_snapshot_restore_cmd(void);
status_t ctbak_parse_snapshot_restore_args(int32 argc, char** argv, ctbak_param_t* ctbak_param);
status_t ctbak_do_snapshot_restore(ctbak_param_t* ctbak_param);

#endif  // CANTIANDB_CTBACKUP_SNAPSHOT_RESTORE_H
