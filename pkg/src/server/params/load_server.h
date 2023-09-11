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
 * load_server.h
 *
 *
 * IDENTIFICATION
 * src/server/params/load_server.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SRV_LOAD_SERVER_PARAMS_H__
#define __SRV_LOAD_SERVER_PARAMS_H__

#include "cm_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EXPANDED_SESSIONS(sessions) (uint32)(int32)((sessions) * 1.5)
status_t server_load_srv_params(void);
status_t server_load_cluster_params(void);
status_t server_load_gdv_params(void);

#ifdef __cplusplus
}
#endif

#endif
