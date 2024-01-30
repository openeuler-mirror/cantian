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
 * ctbackup_query.h
 *
 *
 * IDENTIFICATION
 * src/utils/ctbackup/ctbackup_query.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CTBACKUP_QUERY_H
#define CTBACKUP_QUERY_H
#include <getopt.h>
#include "cm_defs.h"
#include "ctbackup_info.h"
#include "cm_file.h"
#include "bak_common.h"
#include "cm_defs.h"
#ifdef __cplusplus
extern "C" {
#endif

status_t ctbak_parse_query_args(int32 argc, char** argv, ctbak_param_t* ctbak_param);

status_t ctbak_do_query(ctbak_param_t* ctbak_param);

ctbak_cmd_t *ctbak_generate_query_incremental_mode_cmd(void);

#ifdef __cplusplus
}
#endif


#endif  // CTBACKUP_QUERY_H
