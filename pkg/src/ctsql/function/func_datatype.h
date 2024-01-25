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
 * func_datatype.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/function/func_datatype.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __FUNCTION_DATATYPE_H__
#define __FUNCTION_DATATYPE_H__

#include "ctsql_expr.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_infer_func_node_datatype(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *func_node, ct_type_t *ct_type);

#ifdef __cplusplus
}
#endif

#endif