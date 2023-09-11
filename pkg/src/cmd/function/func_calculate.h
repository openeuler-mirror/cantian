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
 * func_calculate.h
 *
 *
 * IDENTIFICATION
 * src/cmd/function/func_calculate.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __FUNC_CALCULATE_H__
#define __FUNC_CALCULATE_H__
#include "srv_query.h"

status_t sql_func_abs(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_abs(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_sin(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_trigonometric(sql_verifier_t *verifier, expr_node_t *func);
status_t sql_func_cos(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_tan(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_asin(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_acos(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_atan(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_atan2(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_radians(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_atan2(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_tanh(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_tanh(sql_verifier_t *verifier, expr_node_t *func);
status_t sql_func_rand(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_rand(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_bit_and(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_bit_func(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_bit_or(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_bit_xor(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_ceil(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_ceil(sql_verifier_t *verifier, expr_node_t *func);
status_t sql_func_exp(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_exp(sql_verifier_t *verifier, expr_node_t *func);
status_t sql_func_floor(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_floor(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_inet_ntoa(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_inet_ntoa(sql_verifier_t *verifier, expr_node_t *func);
status_t sql_func_ln(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_ln(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_log(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_log(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_mod(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_mod(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_pi(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_pi(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_power(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_power(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_rawtohex(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_rawtohex(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_round(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_trunc(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_round_trunc(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_sign(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_sign(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_sqrt(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_sqrt(sql_verifier_t *verifier, expr_node_t *func);
#endif
