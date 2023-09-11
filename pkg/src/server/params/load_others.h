/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * load_others.h
 *
 *
 * IDENTIFICATION
 * src/server/params/load_others.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SRV_LOAD_OTHER_PARAMS_H__
#define __SRV_LOAD_OTHER_PARAMS_H__

#include "cm_config.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t server_load_params(void);
status_t server_load_agent_params(void);
status_t server_load_stat_params(void);
status_t server_load_arch_params(void);
status_t server_load_lsnr_params(void);
status_t server_load_exet_params(void);
status_t server_load_file_transf_params(void);
status_t server_load_optimum_params(void);
status_t server_load_other_params(void);

extern char *cantiand_get_dbversion(void);
#ifdef __cplusplus
}
#endif

#endif