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
 * ctsql_jsonb.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/json/ctsql_jsonb.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_JSONB_H__
#define __SQL_JSONB_H__

#include "ctsql_stmt.h"
#include "cm_text.h"
#include "ctsql_expr.h"
#include "ctsql_verifier.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_verify_jsonb_query(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_jsonb_query(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);

status_t sql_verify_jsonb_value(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_jsonb_value(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);

status_t sql_verify_jsonb_exists(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_jsonb_exists(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);

status_t sql_verify_jsonb_mergepatch(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_jsonb_mergepatch(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);

status_t sql_verify_jsonb_set(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_jsonb_set(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);

status_t sql_verify_jsonb_array_length(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_jsonb_array_length(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);

status_t sql_convert_variant_to_jsonb(sql_stmt_t *stmt, variant_t *value);
status_t sql_valiate_jsonb_format(sql_stmt_t *stmt, variant_t *value);

#ifdef __cplusplus
}
#endif

#endif
