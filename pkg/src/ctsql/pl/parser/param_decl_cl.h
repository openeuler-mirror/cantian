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
 * param_decl_cl.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/parser/param_decl_cl.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __PARAM_DECL_CL_H__
#define __PARAM_DECL_CL_H__

#include "ast.h"

#ifdef __cplusplus
extern "C" {
#endif

#define INPUT_NAME_BUFFER_SIZE 16
#define CURR_BLOCK_BASE(compiler) (((compiler)->stack.depth == 0) ? NULL : (compiler)->stack.items[0].entry)

status_t plc_convert_param_node(sql_stmt_t *stmt, expr_node_t *node, bool32 is_repeated, uint32 p_nid);
status_t plc_compile_sql_param(pl_compiler_t *compiler, text_t *sql, word_t *word);
status_t plc_find_param_as_expr_left(pl_compiler_t *compiler, word_t *word, plv_decl_t **decl);

#ifdef __cplusplus
}
#endif

#endif