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
 * plan_scan.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/plan/plan_scan.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PLAN_SCAN_H__
#define __PLAN_SCAN_H__

#include "ctsql_plan.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_create_query_scan_plan(sql_stmt_t *stmt, plan_assist_t *plan_ass, plan_node_t **plan);
bool32 sql_has_hash_join_oper(sql_join_node_t *join_node);
#ifdef __cplusplus
}
#endif

#endif