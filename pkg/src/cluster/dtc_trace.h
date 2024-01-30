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
 * dtc_trace.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_trace.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DTC_TRACE_H__
#define __DTC_TRACE_H__

#include "cm_types.h"

#ifdef __cplusplus
extern "C" {
#endif
#if defined(_CANTIAN_LCOV_TEST_) && !defined(_CANTIAN_FUZZ_TEST_)
#define DTC_DCS_DEBUG_INF(format, ...)                                                                          \
    do {                                                                                                        \
        cm_write_normal_log(LOG_DEBUG, LEVEL_INFO, (char *)__FILE__, (uint32)__LINE__, (int)MODULE_ID, CT_TRUE, \
                            format, ##__VA_ARGS__);                                                             \
    } while (0)

#define DTC_DCS_DEBUG_ERR(format, ...)                                                                           \
    do {                                                                                                         \
        cm_write_normal_log(LOG_DEBUG, LEVEL_ERROR, (char *)__FILE__, (uint32)__LINE__, (int)MODULE_ID, CT_TRUE, \
                            format, ##__VA_ARGS__);                                                              \
    } while (0)

#define DTC_DCS_DEBUG(status, format, ...)                                                                    \
    do {                                                                                                      \
        cm_write_normal_log(LOG_DEBUG, ((status) == CT_SUCCESS) ? LEVEL_INFO : LEVEL_ERROR, (char *)__FILE__, \
                            (uint32)__LINE__, (int)MODULE_ID, CT_TRUE, format, ##__VA_ARGS__);                \
    } while (0)

#define DTC_DLS_DEBUG_INF(format, ...)                                                                          \
    do {                                                                                                        \
        cm_write_normal_log(LOG_DEBUG, LEVEL_INFO, (char *)__FILE__, (uint32)__LINE__, (int)MODULE_ID, CT_TRUE, \
                            format, ##__VA_ARGS__);                                                             \
    } while (0)

#define DTC_DLS_DEBUG_ERR(format, ...)                                                                           \
    do {                                                                                                         \
        cm_write_normal_log(LOG_DEBUG, LEVEL_ERROR, (char *)__FILE__, (uint32)__LINE__, (int)MODULE_ID, CT_TRUE, \
                            format, ##__VA_ARGS__);                                                              \
    } while (0)

#define DTC_DRC_DEBUG_INF(format, ...)                                                                          \
    do {                                                                                                        \
        cm_write_normal_log(LOG_DEBUG, LEVEL_INFO, (char *)__FILE__, (uint32)__LINE__, (int)MODULE_ID, CT_TRUE, \
                            format, ##__VA_ARGS__);                                                             \
    } while (0)

#define DTC_DRC_DEBUG_ERR(format, ...)                                                                           \
    do {                                                                                                         \
        cm_write_normal_log(LOG_DEBUG, LEVEL_ERROR, (char *)__FILE__, (uint32)__LINE__, (int)MODULE_ID, CT_TRUE, \
                            format, ##__VA_ARGS__);                                                              \
    } while (0)
#else
#define DTC_DCS_DEBUG_INF(format, ...)                                                                              \
    do {                                                                                                            \
        if (DTC_DCS_LOG_INF_ON) {                                                                                   \
            cm_write_normal_log(LOG_DEBUG, LEVEL_INFO, (char *)__FILE__, (uint32)__LINE__, (int)MODULE_ID, CT_TRUE, \
                                format, ##__VA_ARGS__);                                                             \
        }                                                                                                           \
    } while (0)

#define DTC_DCS_DEBUG_ERR(format, ...)                                                                               \
    do {                                                                                                             \
        if (DTC_DCS_LOG_ERR_ON) {                                                                                    \
            cm_write_normal_log(LOG_DEBUG, LEVEL_ERROR, (char *)__FILE__, (uint32)__LINE__, (int)MODULE_ID, CT_TRUE, \
                                format, ##__VA_ARGS__);                                                              \
        }                                                                                                            \
    } while (0)

#define DTC_DCS_DEBUG(status, format, ...)                                                                        \
    do {                                                                                                          \
        if (DTC_DCS_LOG_INF_ON) {                                                                                 \
            cm_write_normal_log(LOG_DEBUG, ((status) == CT_SUCCESS) ? LEVEL_INFO : LEVEL_ERROR, (char *)__FILE__, \
                                (uint32)__LINE__, (int)MODULE_ID, CT_TRUE, format, ##__VA_ARGS__);                \
        }                                                                                                         \
    } while (0)

#define DTC_DLS_DEBUG_INF(format, ...)                                                                              \
    do {                                                                                                            \
        if (DTC_DLS_LOG_INF_ON) {                                                                                   \
            cm_write_normal_log(LOG_DEBUG, LEVEL_INFO, (char *)__FILE__, (uint32)__LINE__, (int)MODULE_ID, CT_TRUE, \
                                format, ##__VA_ARGS__);                                                             \
        }                                                                                                           \
    } while (0)

#define DTC_DLS_DEBUG_ERR(format, ...)                                                                               \
    do {                                                                                                             \
        if (DTC_DLS_LOG_ERR_ON) {                                                                                    \
            cm_write_normal_log(LOG_DEBUG, LEVEL_ERROR, (char *)__FILE__, (uint32)__LINE__, (int)MODULE_ID, CT_TRUE, \
                                format, ##__VA_ARGS__);                                                              \
        }                                                                                                            \
    } while (0)

#define DTC_DRC_DEBUG_INF(format, ...)                                                                              \
    do {                                                                                                            \
        if (DTC_DRC_LOG_INF_ON) {                                                                                   \
            cm_write_normal_log(LOG_DEBUG, LEVEL_INFO, (char *)__FILE__, (uint32)__LINE__, (int)MODULE_ID, CT_TRUE, \
                                format, ##__VA_ARGS__);                                                             \
        }                                                                                                           \
    } while (0)

#define DTC_DRC_DEBUG_ERR(format, ...)                                                                               \
    do {                                                                                                             \
        if (DTC_DRC_LOG_ERR_ON) {                                                                                    \
            cm_write_normal_log(LOG_DEBUG, LEVEL_ERROR, (char *)__FILE__, (uint32)__LINE__, (int)MODULE_ID, CT_TRUE, \
                                format, ##__VA_ARGS__);                                                              \
        }                                                                                                            \
    } while (0)
#endif
#ifdef __cplusplus
}
#endif

#endif
