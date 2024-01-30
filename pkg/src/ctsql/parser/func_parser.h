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
 * func_parser.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser/func_parser.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __FUNC_PARSER_H__
#define __FUNC_PARSER_H__

#include "ctsql_expr.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_convert_to_cast(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word);
status_t sql_build_func_node(sql_stmt_t *stmt, word_t *word, expr_node_t *node);
status_t sql_build_func_over(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word, expr_node_t **node);
status_t sql_try_fetch_func_arg(sql_stmt_t *stmt, text_t *arg_name);
status_t sql_create_const_string_expr(sql_stmt_t *stmt, expr_tree_t **new_expr, const char *char_str);
status_t sql_build_cast_expr(sql_stmt_t *stmt, source_location_t loc, expr_tree_t *expr, typmode_t *type,
                             expr_tree_t **res);


#ifdef __cplusplus
}
#endif

#endif