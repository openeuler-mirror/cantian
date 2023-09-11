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
 * func_regexp.h
 *
 *
 * IDENTIFICATION
 * src/cmd/function/func_regexp.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __FUNC_REGEXP_H__
#define __FUNC_REGEXP_H__
#include "srv_query.h"

status_t sql_verify_regexp_count(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_regexp_count(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_regexp_instr(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_regexp_instr(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_regexp_substr(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_regexp_substr(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_regexp_replace(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_regexp_replace(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);

#endif
