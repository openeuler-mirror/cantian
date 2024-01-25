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
 * call_cl.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/parser/call_cl.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CALL_CL_H__
#define __CALL_CL_H__

#include "ast.h"
#include "pl_procedure.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t plc_compile_call(pl_compiler_t *compiler, expr_node_t *expr, pl_line_normal_t *line);
status_t plc_compile_language(pl_compiler_t *compiler, function_t *func);

#ifdef __cplusplus
}
#endif

#endif