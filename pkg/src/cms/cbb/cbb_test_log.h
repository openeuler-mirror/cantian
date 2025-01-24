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
 * cms_test_log.h
 *
 *
 * IDENTIFICATION
 * src/cms/cbb/cbb_test_log.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CBB_TEST_LOG_H__
#define __CBB_TEST_LOG_H__

#define LOG(format, ...) write_log_to_file(__FILE__, __LINE__, format, ##__VA_ARGS__)

#ifdef TEST_LOG_ENABLED
void get_current_time(char *buffer, size_t size);
#endif
void write_log_to_file(const char *file, int line, const char *format, ...);

#endif