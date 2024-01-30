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
 * func_date.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/function/func_date.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __func_DATE_H__
#define __func_DATE_H__
#include "ctsql_func.h"

status_t sql_func_add_months(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);
status_t sql_verify_add_months(sql_verifier_t *verif, expr_node_t *func);
status_t sql_func_current_timestamp(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);
status_t sql_verify_current_timestamp(sql_verifier_t *verif, expr_node_t *func);
status_t sql_func_extract(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);
status_t sql_verify_extract(sql_verifier_t *verif, expr_node_t *func);
status_t sql_func_from_tz(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);
status_t sql_verify_from_tz(sql_verifier_t *verf, expr_node_t *func);
status_t sql_verify_from_unixtime(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_from_unixtime(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);
status_t sql_verify_utcdate(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_utcdate(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);
status_t sql_func_last_day(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);
status_t sql_verify_last_day(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_localtimestamp(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);
status_t sql_verify_localtimestamp(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_months_between(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);
status_t sql_verify_months_between(sql_verifier_t *verifier, expr_node_t *func);
status_t sql_func_next_day(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);
status_t sql_verify_next_day(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_sys_timestamp(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_sys_extract_utc(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);
status_t sql_verify_sys_extract_utc(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_to_date(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_to_date(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_to_timestamp(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_to_timestamp(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_timestampadd(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);
status_t sql_verify_timestampadd(sql_verifier_t *verif, expr_node_t *func);
status_t sql_func_timestampdiff(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);
status_t sql_verify_timestampdiff(sql_verifier_t *verif, expr_node_t *func);
status_t sql_verify_unix_timestamp(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_unix_timestamp(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);
status_t sql_verify_utctimestamp(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_utctimestamp(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);

#endif