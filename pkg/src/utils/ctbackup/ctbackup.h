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
 * ctbackup.h
 *
 *
 * IDENTIFICATION
 * src/utils/ctbackup/ctbackup.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CANTIANDB_100_CTBACKUP_H
#define CANTIANDB_100_CTBACKUP_H

#include "ctbackup_info.h"
#include "cm_text.h"
#include "cm_defs.h"
#include "cm_signal.h"
#include "cm_coredump.h"
#include "cm_log.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PRODUCT_NAME "CANTIAN"
#define CTBACKUP_NAME "ctbackup"
#define COMMENT_SPACE 25

void ctbackup_show_help(void);

EXTER_ATTACK status_t ctbak_process_args(int32 argc, char** argv);

#ifdef __cplusplus
}
#endif

#endif // end CANTIANDB_100_CTBACKUP_H