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
 * func_interval.h
 *
 *
 * IDENTIFICATION
 * src/cmd/function/func_interval.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __func_INTERVAL_H__
#define __func_INTERVAL_H__
#include "srv_query.h"

status_t sql_verify_numtoyminterval(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_numtoyminterval(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_numtodsinterval(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_numtodsinterval(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_func_to_yminterval(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_to_yminterval(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_to_dsinterval(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_to_dsinterval(sql_verifier_t *verf, expr_node_t *func);

#endif
