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
 * sql_json_table.h
 *
 *
 * IDENTIFICATION
 * src/cmd/json/sql_json_table.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_JSON_TABLE_H__
#define __SQL_JSON_TABLE_H__

#include "cm_defs.h"
#include "srv_query.h"
#include "sql_json_utils.h"

typedef status_t (*json_value_visit_func)(sql_stmt_t *stmt, json_value_t *jv, json_table_exec_t *exec, uint32 level,
    bool32 *result);
status_t sql_verify_json_table(sql_verifier_t *verf, sql_query_t *query, sql_table_t *table);
status_t sql_parse_json_table(sql_stmt_t *stmt, sql_table_t *table, word_t *word);
status_t handle_json_table_data_error(json_assist_t *ja, json_error_type_t err_type, bool8 *eof);
status_t sql_calc_json_table_column_result(json_assist_t *ja, rs_column_t *col, json_table_exec_t *exec,
    variant_t *result);
status_t sql_try_switch_json_array_loc(sql_stmt_t *stmt, json_value_t *jv, json_table_exec_t *exec, uint32 temp_level,
    bool32 *switched);
status_t sql_visit_json_value(sql_stmt_t *stmt, json_value_t *jv, json_table_exec_t *exec, uint32 temp_level,
    bool32 *switched, json_value_visit_func visit_func);

#endif
