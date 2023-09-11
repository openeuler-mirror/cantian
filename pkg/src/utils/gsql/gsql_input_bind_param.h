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
 * gsql_input_bind_param.h
 *
 *
 * IDENTIFICATION
 * src/utils/gsql/gsql_input_bind_param.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __GSQL_INPUT_BIND_PARAM_H__
#define __GSQL_INPUT_BIND_PARAM_H__

#include "cm_defs.h"
#include "cm_text.h"
#include "cm_date.h"

#ifdef __cplusplus
extern "C" {
#endif

uint32 gsql_get_param_count(const char *sql);
status_t gsql_bind_params(gsc_stmt_t stmt, uint32 param_count /* , uint32 *batch_count */);
status_t gsql_bind_param_init(uint32 param_count);
void gsql_bind_param_uninit(uint32 param_count);

/** @} */  // end group GSQL_CMD

#ifdef __cplusplus
}
#endif

#endif  // end __GSQL_INPUT_BIND_PARAM_H__