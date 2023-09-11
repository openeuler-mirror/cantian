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
 * func_string.h
 *
 *
 * IDENTIFICATION
 * src/cmd/function/func_string.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __FUNC_STRING_H__
#define __FUNC_STRING_H__
#include "srv_query.h"

#define SQL_FUNC_LEFT 0
#define SQL_FUNC_RIGHT 1

#define FUNC_TRIM_ARGUMENTS_MAX_NUM 2

status_t sql_func_length_core(sql_stmt_t *stmt, expr_node_t *func, variant_t *result, bool32 is_lob_func);
status_t sql_func_concat(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_concat(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_concat_ws(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_concat_ws(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_repeat(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_repeat(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_empty_blob(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_empty_blob(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_empty_clob(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_empty_clob(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_find_in_set(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_find_in_set(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_insert(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_insert_func(sql_verifier_t *verifier, expr_node_t *func);
status_t sql_func_instr(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_instrb(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_instr(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_inet_aton(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_inet_aton(sql_verifier_t *verifier, expr_node_t *func);
status_t sql_func_left(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_left(sql_verifier_t *verifier, expr_node_t *func);
status_t sql_func_length(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_lengthb(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_length(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_locate(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_locate(sql_verifier_t *verifier, expr_node_t *func);
status_t sql_func_lower(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_lower(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_lpad(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_rpad(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_pad(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_ltrim(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_rtrim(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_trim(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_rltrim(sql_verifier_t *verf, expr_node_t *func);
/* ********************************************************************** */
/* the meaning of argument :                                            */
/* 1st arg : the trim source                                            */
/* 2nd arg : the trim characters set(optional)                          */
/* 3rd arg : the trim type(optional)                                    */
/* ********************************************************************** */
status_t sql_verify_trim(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_replace(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_reverse(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_replace(sql_verifier_t *verf, expr_node_t *func);
status_t sql_verify_reverse(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_right(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_right(sql_verifier_t *verifier, expr_node_t *func);
status_t sql_func_space(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_space(sql_verifier_t *verifier, expr_node_t *func);
status_t sql_func_substr(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_substrb(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_substr(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_substring_index(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_substring_index(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_sys_connect_by_path(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_sys_connect_by_path(sql_verifier_t *verf, expr_node_t *func);
status_t sql_verify_translate(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_translate(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_upper(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_upper(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_concat_string(sql_stmt_t *stmt, text_t *result, text_t *sub, uint32 len);

#endif
