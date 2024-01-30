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
 * func_aggr.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/function/func_aggr.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __FUNC_AGGR_H__
#define __FUNC_AGGR_H__
#include "ctsql_func.h"

status_t sql_func_array_agg(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);
status_t sql_verify_array_agg(sql_verifier_t *verif, expr_node_t *func);
status_t sql_verify_avg(sql_verifier_t *verif, expr_node_t *func);
status_t sql_verify_covar_or_corr(sql_verifier_t *verif, expr_node_t *func);
status_t sql_func_covar_or_corr(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_count(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);
status_t sql_verify_count(sql_verifier_t *verif, expr_node_t *func);
status_t sql_func_cume_dist(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);
status_t sql_verify_cume_dist(sql_verifier_t *verif, expr_node_t *func);
status_t sql_func_dense_rank(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_dense_rank(sql_verifier_t *verif, expr_node_t *func);
status_t sql_verify_listagg(sql_verifier_t *verif, expr_node_t *func);
status_t sql_verify_min_max(sql_verifier_t *verif, expr_node_t *func);
status_t sql_verify_median(sql_verifier_t *verif, expr_node_t *func);
status_t sql_verify_stddev_intern(sql_verifier_t *verif, expr_node_t *func);
status_t sql_verify_sum(sql_verifier_t *verif, expr_node_t *func);
status_t sql_verify_approx_count_distinct(sql_verifier_t *verif, expr_node_t *func);
status_t sql_func_approx_count_distinct(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_normal_aggr(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);

#endif