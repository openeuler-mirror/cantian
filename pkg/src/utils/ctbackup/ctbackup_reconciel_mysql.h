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
 * ctbackup_reconciel_mysql.h
 *
 *
 * IDENTIFICATION
 * src/utils/ctbackup/ctbackup_reconciel_mysql.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CANTIANDB_100_CTBACKUP_RECONCIEL_MYSQL_H
#define CANTIANDB_100_CTBACKUP_RECONCIEL_MYSQL_H

#include <getopt.h>
#include "cm_defs.h"
#include "ctbackup_info.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SQL_ARCHIVE_PATH "/DDL_DATA.sql"

ctbak_cmd_t *ctbak_generate_reconciel_mysql_cmd(void);

status_t ctbak_do_reconciel(ctbak_param_t* ctbak_param);

status_t ctbak_do_reconciel_for_mysql(ctbak_param_t* ctbak_param);

status_t ctbak_parse_reconciel_mysql_args(int32 argc, char** argv, ctbak_param_t* ctbak_param);

status_t fill_params_for_mysql_reconciel(ctbak_param_t* ctbak_param, char* mysql_option_str, int option_str_len);

status_t  set_exec_param(char* exec_param);

#ifdef __cplusplus
}
#endif

#endif  // CANTIANDB_100_CTBACKUP_RECONCIEL_MYSQL_H
