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
 * func_convert.h
 *
 *
 * IDENTIFICATION
 * src/cmd/function/func_convert.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __FUNC_CONVERT_H__
#define __FUNC_CONVERT_H__
#include "srv_query.h"

#define GS_IS_HEX_ELEM(c) (((c) == 'X') || ((c) == 'x'))

status_t sql_func_ascii(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_ascii(sql_verifier_t *verifier, expr_node_t *func);
status_t sql_func_asciistr(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_asciistr(sql_verifier_t *verifier, expr_node_t *func);
status_t sql_func_cast(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_cast(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_chr(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_chr(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_decode(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_decode(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_if(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_if(sql_verifier_t *verf, expr_node_t *func);
status_t sql_verify_ifnull(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_ifnull(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_lnnvl(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_lnnvl(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_nullif(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_nullif(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_nvl(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_nvl(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_nvl2(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_nvl2(sql_verifier_t *verf, expr_node_t *func);
status_t sql_verify_to_int(sql_verifier_t *verf, expr_node_t *func);
status_t sql_verify_to_bigint(sql_verifier_t *verf, expr_node_t *func);
status_t sql_verify_to_number(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_to_int(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_to_bigint(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_to_number(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_to_blob(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_to_blob(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_to_char(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_to_char(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_to_nchar(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_to_nchar(sql_verifier_t *verifier, expr_node_t *func);
status_t sql_func_to_clob(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_to_clob(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_to_multi_byte(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_to_single_or_multi_byte(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_to_single_byte(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
bool32 chk_lnnvl_unsupport_cmp_type(cond_node_t *cond);
status_t sql_adjust_if_type(gs_type_t l_type, gs_type_t r_type, gs_type_t *result_type);
gs_type_t sql_get_ifnull_compatible_datatype(gs_type_t typ1, gs_type_t typ2);
gs_type_t decode_compatible_datatype(expr_node_t *func, expr_node_t *node, gs_type_t typ1, gs_type_t typ2);

#endif
