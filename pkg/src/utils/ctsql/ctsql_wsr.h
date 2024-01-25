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
 * ctsql_wsr.h
 *
 *
 * IDENTIFICATION
 * src/utils/ctsql/ctsql_wsr.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CTSQL_WSR_H__
#define __CTSQL_WSR_H__

#include "ctsql.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    EWSR_SQL_HTML_ID = 900,
    EWSR_LONGSQL_HTML_ID = 1000,
} WSR_HTML_ID;

status_t ctsql_wsr(text_t *cmd_text);

#ifdef __cplusplus
}
#endif

#endif