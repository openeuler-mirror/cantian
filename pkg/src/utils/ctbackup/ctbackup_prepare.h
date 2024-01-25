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
 * ctbackup_prepare.h
 *
 *
 * IDENTIFICATION
 * src/utils/ctbackup/ctbackup_prepare.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CANTIANDB_100_CTBACKUP_PREPARE_H
#define CANTIANDB_100_CTBACKUP_PREPARE_H

#include <getopt.h>
#include "cm_defs.h"
#include "ctbackup_info.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t ctbak_do_prepare(ctbak_param_t* ctbak_param);

status_t ctbak_do_prepare_for_mysql(ctbak_param_t* ctbak_param);

status_t ctbak_do_restore(ctbak_param_t* ctbak_param);

status_t ctbak_do_recover(ctbak_param_t* ctbak_param);

status_t ctbak_do_restore_or_recover(ctbak_param_t* ctbak_param);

status_t ctbak_parse_prepare_args(int32 argc, char** argv, ctbak_param_t* ctbak_param);

status_t fill_params_for_mysql_prepare_or_decompress(ctbak_param_t* ctbak_param, char *params[], char *action);

status_t fill_params_for_cantian_recover(ctbak_param_t *ctbak_param, char *ct_params[]);

status_t fill_params_for_cantian_reset_log(ctbak_param_t *ctbak_param, char *ct_params[]);

status_t check_badblock_file_for_cantian_restore(ctbak_param_t *ctbak_param, const char *file_directory);

status_t get_statement_for_cantian_restore(char *file_directory, uint64_t option_len,
                                           char *option_str, char **statement);

status_t fill_params_for_cantian_restore(ctbak_param_t *ctbak_param, char *ct_params[]);

status_t fill_options_for_cantian_restore(ctbak_param_t* ctbak_param, uint64_t* option_len, char** option_str);

status_t ctbak_do_decompress_for_mysql(ctbak_param_t* ctbak_param);

status_t ctbackup_set_metadata_mode(ctbak_param_t *ctbak_param);

ctbak_cmd_t *ctbak_generate_prepare_cmd(void);

#ifdef __cplusplus
}
#endif

#endif // CANTIANDB_100_CTBACKUP_PREPARE_H