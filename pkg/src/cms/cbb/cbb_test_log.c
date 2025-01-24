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
 * cms_test_log.c
 *
 *
 * IDENTIFICATION
 * src/cms/cbb/cbb_test_log.c
 *
 * -------------------------------------------------------------------------
 */
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include "cbb_test_log.h"

#ifdef TEST_LOG_ENABLED
#define LOG_FILE "/opt/cantian/dss/test.log"
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void get_current_time(char *buffer, size_t size) {
    time_t raw_time;
    struct tm *time_info;

    time(&raw_time);
    time_info = localtime(&raw_time);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", time_info);
}
#endif

void write_log_to_file(const char *file, int line, const char *format, ...) {
#ifdef TEST_LOG_ENABLED
    pthread_mutex_lock(&log_mutex);

    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file != NULL) {
        char time_str[20];
        get_current_time(time_str, sizeof(time_str));

        fprintf(log_file, "[%s] (%s:%d) ", time_str, file, line);

        va_list args;
        va_start(args, format);
        vfprintf(log_file, format, args);
        va_end(args);

        fprintf(log_file, "\n");
        fclose(log_file);
    } else {
        fprintf(stderr, "Error opening log file: %s\n", LOG_FILE);
    }

    pthread_mutex_unlock(&log_mutex);
#endif
}