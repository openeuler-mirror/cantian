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
 * ctsql_json.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/json/ctsql_json.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __SQL_JSON_H__
#define __SQL_JSON_H__

#include "ctsql_stmt.h"
#include "cm_text.h"
#include "ctsql_expr.h"
#include "var_inc.h"
#include "ctsql_verifier.h"

#ifdef __cplusplus
extern "C" {
#endif

#define JSON_MAX_SIZE (g_instance->sql.json_mpool.max_json_dyn_buf)
#define JSON_MAX_FUN_ARGS 128
#define JSON_MAX_STRING_LEN (CT_STRING_BUFFER_SIZE - 1)

typedef struct st_json_mem_pool {
    spinlock_t lock;
    uint64 max_json_dyn_buf;
    uint64 used_json_dyn_buf; // memory used size
} sql_json_mem_pool_t;

status_t sql_build_func_args_json_array(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node, sql_text_t *arg_text);
status_t sql_build_func_args_json_object(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node, sql_text_t *arg_text);
status_t sql_build_func_args_json_retrieve(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node,
    sql_text_t *arg_text);
status_t sql_build_func_args_json_query(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node, sql_text_t *arg_text);
status_t sql_build_func_args_json_set(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node, sql_text_t *arg_text);

status_t sql_func_is_json(sql_stmt_t *stmt, expr_tree_t *node, variant_t *result);

status_t sql_verify_json_value(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_json_value(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);

status_t sql_verify_json_query(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_json_query(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);

status_t sql_verify_json_mergepatch(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_json_mergepatch(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);

status_t sql_verify_json_array(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_json_array(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);

status_t sql_verify_json_array_length(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_json_array_length(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);

status_t sql_verify_json_object(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_json_object(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);

status_t sql_verify_json_exists(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_json_exists(sql_stmt_t *stmt, expr_node_t *func, variant_t *res);

status_t sql_verify_json_set(sql_verifier_t *verf, expr_node_t *func);
status_t sql_func_json_set(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);

#ifdef __cplusplus
}
#endif

#endif
