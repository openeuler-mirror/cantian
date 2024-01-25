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
 * plan_dml.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/plan/plan_dml.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PLAN_DML_H__
#define __PLAN_DML_H__

#include "ctsql_plan.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CT_MAX_VM_VIEW_ROWS 1000000
#define CT_MAX_VM_VIEW_MTRL_COUNT 5

status_t sql_create_subselect_expr_plan(sql_stmt_t *stmt, sql_array_t *ssa, plan_assist_t *plan_ass);
status_t sql_create_subselect_plan(sql_stmt_t *stmt, sql_query_t *query, plan_assist_t *plan_ass);

#ifdef __cplusplus
}
#endif

#endif
