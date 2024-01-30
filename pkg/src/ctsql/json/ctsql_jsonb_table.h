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
 * ctsql_jsonb_table.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/json/ctsql_jsonb_table.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_JSONB_TABLE_H__
#define __SQL_JSONB_TABLE_H__

#include "cm_defs.h"
#include "ctsql_stmt.h"
#include "expr_parser.h"
#include "ctsql_json_utils.h"

status_t sql_func_jsonb_to_jv(json_assist_t *json_ass, expr_tree_t *arg, json_value_t *jv, variant_t *result);

#endif