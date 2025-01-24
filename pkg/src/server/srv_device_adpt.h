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
 * srv_device_adpt.h
 *
 *
 * IDENTIFICATION
 * src/server/srv_device_adpt.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __SS_DEVICE_ADPT_H__
#define __SS_DEVICE_ADPT_H__

#include "cm_defs.h"

typedef enum en_dss_log_level {
    DSS_LOG_LEVEL_ERROR = 0,  // error conditions
    DSS_LOG_LEVEL_WARN,       // warning conditions
    DSS_LOG_LEVEL_INFO,       // informational messages
    DSS_LOG_LEVEL_COUNT,
} dss_log_level_t;

typedef enum en_dss_log_id {
    DSS_LOG_ID_RUN = 0,
    DSS_LOG_ID_DEBUG,
    DSS_LOG_ID_COUNT,
} dss_log_id_t;

status_t srv_device_init(const char *conn_path);

#endif  // __SRV_DEVICE_ADPT_H__