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
 * func_hex.h
 *
 *
 * IDENTIFICATION
 * src/cmd/function/func_hex.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __FUNC_HEX_H__
#define __FUNC_HEX_H__
#include "srv_query.h"

status_t sql_bin2hex(sql_stmt_t *stmt, expr_node_t *func, bool32 hex_prefix, variant_t *result);
status_t sql_func_bin2hex(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_bin2hex(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_hex(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_hex(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_hex2bin(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_hex2bin(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_hextoraw(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_hextoraw(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_unhex(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_unhex(sql_verifier_t *verf, expr_node_t *func);

#endif
