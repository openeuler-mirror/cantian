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
 * cms_log.h
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_log.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMS_LOG_H
#define CMS_LOG_H

#include "cm_log.h"
#include "cm_date.h"
#include "cms_msgque.h"

#define CSM_DETECT_LOG_IO_SLOW_TIMEOUT  5000000 // IO is regarded as slow if it takes more than 5 seconds.

#ifdef _CMS_LCOV_TEST_
#define CMS_LOG_ERR(format, ...)                                                                                       \
    do {                                                                                                               \
        cm_write_normal_log(LOG_RUN, LEVEL_ERROR, (char *)__FILE__, (uint32)__LINE__, (int)MODULE_ID, CT_TRUE, format, \
                            ##__VA_ARGS__);                                                                            \
    } while (0)

#define CMS_LOG_ERR_LIMIT(interval, format, ...)                                                                   \
    do {                                                                                                           \
        bool32 bCan = CT_FALSE;                                                                                    \
        CT_LOG_LIMIT_PERIOD(interval, bCan);                                                                       \
        if (bCan == CT_TRUE) {                                                                                     \
            cm_write_normal_log(LOG_RUN, LEVEL_ERROR, (char *)__FILE__, (uint32)__LINE__, (int)MODULE_ID, CT_TRUE, \
                                format, ##__VA_ARGS__);                                                            \
        }                                                                                                          \
    } while (0)

#define CMS_LOG_WAR(format, ...)                                                                                      \
    do {                                                                                                              \
        cm_write_normal_log(LOG_RUN, LEVEL_WARN, (char *)__FILE__, (uint32)__LINE__, (int)MODULE_ID, CT_TRUE, format, \
                            ##__VA_ARGS__);                                                                           \
    } while (0)

#define CMS_LOG_WAR_LIMIT(interval, format, ...)                                                                  \
    do {                                                                                                          \
        bool32 bCan = CT_FALSE;                                                                                   \
        CT_LOG_LIMIT_PERIOD(interval, bCan);                                                                      \
        if (bCan == CT_TRUE) {                                                                                    \
            cm_write_normal_log(LOG_RUN, LEVEL_WARN, (char *)__FILE__, (uint32)__LINE__, (int)MODULE_ID, CT_TRUE, \
                                format, ##__VA_ARGS__);                                                           \
        }                                                                                                         \
    } while (0)

#define CMS_LOG_INF(format, ...)                                                                                      \
    do {                                                                                                              \
        cm_write_normal_log(LOG_RUN, LEVEL_INFO, (char *)__FILE__, (uint32)__LINE__, (int)MODULE_ID, CT_TRUE, format, \
                            ##__VA_ARGS__);                                                                           \
    } while (0)

#define CMS_LOG_INF_LIMIT(interval, format, ...)                                                                  \
    do {                                                                                                          \
        bool32 bCan = CT_FALSE;                                                                                   \
        CT_LOG_LIMIT_PERIOD(interval, bCan);                                                                      \
        if (bCan == CT_TRUE) {                                                                                    \
            cm_write_normal_log(LOG_RUN, LEVEL_INFO, (char *)__FILE__, (uint32)__LINE__, (int)MODULE_ID, CT_TRUE, \
                                format, ##__VA_ARGS__);                                                           \
        }                                                                                                         \
    } while (0)

#define CMS_LOG_DEBUG_ERR(format, ...)                                                                           \
    do {                                                                                                         \
        cm_write_normal_log(LOG_DEBUG, LEVEL_ERROR, (char *)__FILE__, (uint32)__LINE__, (int)MODULE_ID, CT_TRUE, \
                            format, ##__VA_ARGS__);                                                              \
    } while (0)

#define CMS_LOG_DEBUG_WAR(format, ...)                                                                          \
    do {                                                                                                        \
        cm_write_normal_log(LOG_DEBUG, LEVEL_WARN, (char *)__FILE__, (uint32)__LINE__, (int)MODULE_ID, CT_TRUE, \
                            format, ##__VA_ARGS__);                                                             \
    } while (0)

#define CMS_LOG_DEBUG_INF(format, ...)                                                                          \
    do {                                                                                                        \
        cm_write_normal_log(LOG_DEBUG, LEVEL_INFO, (char *)__FILE__, (uint32)__LINE__, (int)MODULE_ID, CT_TRUE, \
                            format, ##__VA_ARGS__);                                                             \
    } while (0)

#define CMS_LOG_TIMER(format, ...)                                                                                \
    do {                                                                                                          \
        cm_write_normal_log(LOG_OPTINFO, LEVEL_INFO, (char *)__FILE__, (uint32)__LINE__, (int)MODULE_ID, CT_TRUE, \
                            format, ##__VA_ARGS__);                                                               \
    } while (0)
#else

#define CMS_LOG_ERR(format, ...)                                                                                \
    do {                                                                                                        \
        date_t log_inner_start_time = cm_now();                                                                 \
        CT_LOG_RUN_ERR(format, ##__VA_ARGS__);                                                                  \
        cms_log_io_time_check(log_inner_start_time);                                                            \
    } while (0)

#define CMS_LOG_ERR_LIMIT(interval, format, ...)                                                                \
    do {                                                                                                        \
        bool32 bCan = CT_FALSE;                                                                                 \
        CT_LOG_LIMIT_PERIOD(interval, bCan);                                                                    \
        if (bCan == CT_TRUE) {                                                                                  \
            date_t log_inner_start_time = cm_now();                                                             \
            CT_LOG_RUN_ERR(format, ##__VA_ARGS__);                                                              \
            cms_log_io_time_check(log_inner_start_time);                                                        \
        }                                                                                                       \
    } while (0)

#define CMS_LOG_WAR(format, ...)                                                                                \
    do {                                                                                                        \
        date_t log_inner_start_time = cm_now();                                                                 \
        CT_LOG_RUN_WAR(format, ##__VA_ARGS__);                                                                  \
        cms_log_io_time_check(log_inner_start_time);                                                            \
    } while (0)

#define CMS_LOG_WAR_LIMIT(interval, format, ...)                                                                \
    do {                                                                                                        \
        bool32 bCan = CT_FALSE;                                                                                 \
        CT_LOG_LIMIT_PERIOD(interval, bCan);                                                                    \
        if (bCan == CT_TRUE) {                                                                                  \
            date_t log_inner_start_time = cm_now();                                                             \
            CT_LOG_RUN_WAR(format, ##__VA_ARGS__);                                                              \
            cms_log_io_time_check(log_inner_start_time);                                                        \
        }                                                                                                       \
    } while (0)

#define CMS_LOG_INF(format, ...)                                                                                \
    do {                                                                                                        \
        date_t log_inner_start_time = cm_now();                                                                 \
        CT_LOG_RUN_INF(format, ##__VA_ARGS__);                                                                  \
        cms_log_io_time_check(log_inner_start_time);                                                            \
    } while (0)

#define CMS_LOG_INF_LIMIT(interval, format, ...)                                                                \
    do {                                                                                                        \
        bool32 bCan = CT_FALSE;                                                                                 \
        CT_LOG_LIMIT_PERIOD(interval, bCan);                                                                    \
        if (bCan == CT_TRUE) {                                                                                  \
            date_t log_inner_start_time = cm_now();                                                             \
            CT_LOG_RUN_INF(format, ##__VA_ARGS__);                                                              \
            cms_log_io_time_check(log_inner_start_time);                                                        \
        }                                                                                                       \
    } while (0)

#define CMS_LOG_DEBUG_ERR(format, ...)                                                                          \
    do {                                                                                                        \
        date_t log_inner_start_time = cm_now();                                                                 \
        CT_LOG_DEBUG_ERR(format, ##__VA_ARGS__);                                                                \
        cms_log_io_time_check(log_inner_start_time);                                                            \
    } while (0)

#define CMS_LOG_DEBUG_WAR(format, ...)                                                                          \
    do {                                                                                                        \
        date_t log_inner_start_time = cm_now();                                                                 \
        CT_LOG_DEBUG_WAR(format, ##__VA_ARGS__);                                                                \
        cms_log_io_time_check(log_inner_start_time);                                                            \
    } while (0)

#define CMS_LOG_DEBUG_INF(format, ...)                                                                          \
    do {                                                                                                        \
        date_t log_inner_start_time = cm_now();                                                                 \
        CT_LOG_DEBUG_INF(format, ##__VA_ARGS__);                                                                \
        cms_log_io_time_check(log_inner_start_time);                                                            \
    } while (0)

#define CMS_LOG_TIMER(format, ...)                                                                              \
    do {                                                                                                        \
        date_t log_inner_start_time = cm_now();                                                                 \
        CT_LOG_OPTINFO(format, ##__VA_ARGS__);                                                                  \
        cms_log_io_time_check(log_inner_start_time);                                                            \
    } while (0)

#endif  // _CMS_LCOV_TEST_

void cms_log_io_time_check(date_t log_inner_start_time);

#endif