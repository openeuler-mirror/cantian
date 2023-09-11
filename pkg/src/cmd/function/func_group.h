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
 * func_group.h
 *
 *
 * IDENTIFICATION
 * src/cmd/function/func_group.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __FUNC_GROUP_H__
#define __FUNC_GROUP_H__
#include "srv_query.h"

status_t sql_func_grouping(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_grouping(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_grouping_id(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_grouping_id(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_group_concat(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_group_concat(sql_verifier_t *verf, expr_node_t *func);
#endif
