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
 * ctsql_wsr_buffer.h
 *
 *
 * IDENTIFICATION
 * src/utils/ctsql/ctsql_wsr_buffer.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CTSQL_WSR_BUFFER_H__
#define __CTSQL_WSR_BUFFER_H__

#include "ctsql.h"
#include "ctsql_wsr_common.h"

#ifdef __cplusplus
extern "C" {
#endif

int wsr_build_instance_buffer(wsr_options_t *wsr_opts, wsr_info_t *wsr_info);

#ifdef __cplusplus
}
#endif

#endif