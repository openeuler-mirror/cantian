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
 * ctbackup_copyback.h
 *
 *
 * IDENTIFICATION
 * src/utils/ctbackup/ctbackup_copyback.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CANTIANDB_100_CTBACKUP_COPYBACK_H
#define CANTIANDB_100_CTBACKUP_COPYBACK_H

#include <getopt.h>
#include "cm_defs.h"
#include "ctbackup_info.h"
#ifdef __cplusplus
extern "C" {
#endif

ctbak_cmd_t *ctbak_generate_copyback_cmd(void);

status_t ctbak_do_copyback(ctbak_param_t* ctbak_param);

status_t ctbak_do_copyback_for_mysql(ctbak_param_t* ctbak_param);

status_t ctbak_parse_copyback_args(int32 argc, char** argv, ctbak_param_t* ctbak_param);

status_t fill_params_for_mysql_copyback(ctbak_param_t* ctbak_param, char *params[], int *index);


#ifdef __cplusplus
}
#endif

#endif  // CANTIANDB_100_CTBACKUP_COPYBACK_H