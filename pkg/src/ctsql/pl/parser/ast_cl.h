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
 * ast_cl.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/parser/ast_cl.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __AST_CL_H__
#define __AST_CL_H__

#include "ast.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t plc_alloc_line(pl_compiler_t *compiler, uint32 size, pl_line_type_t type, pl_line_ctrl_t **line);
status_t plc_verify_into_clause(sql_context_t *context, pl_into_t *into, source_location_t loc);
status_t plc_push(pl_compiler_t *compiler, pl_line_ctrl_t *line, const text_t *block_name);
status_t plc_verify_label(pl_compiler_t *compiler);
bool32 plc_expected_end_value_equal(pl_compiler_t *compiler, var_udo_t *obj, word_t *word);
status_t plc_init_galist(pl_compiler_t *compiler, galist_t **decls);
status_t plc_compile_block(pl_compiler_t *compiler, galist_t *decls, var_udo_t *obj, word_t *leader);
status_t plc_verify_out_expr(pl_compiler_t *compiler, expr_tree_t *expr, pl_arg_info_t *arg_info);
status_t plc_try_compile_end_ln(pl_compiler_t *compiler, bool32 *res, var_udo_t *obj, word_t *word);
status_t plc_skip_error_line(pl_compiler_t *compiler, word_t *word);
pl_line_ctrl_t *plc_get_current_beginln(pl_compiler_t *compiler);
status_t plc_pop(pl_compiler_t *compiler, source_location_t loc, pl_block_end_t pbe, pl_line_ctrl_t **res);
status_t plc_expected_end_ln(pl_compiler_t *compiler, bool32 *res, var_udo_t *obj, word_t *word);
status_t plc_push_ctl(pl_compiler_t *compiler, pl_line_ctrl_t *line, const text_t *block_name);
status_t plc_check_decl_as_left(pl_compiler_t *compiler, plv_decl_t *decl, source_location_t loc,
    pl_arg_info_t *arg_info);
status_t plc_check_var_as_left(pl_compiler_t *compiler, expr_node_t *node, source_location_t source_loc,
                               pl_arg_info_t *arg_info);
#ifdef __cplusplus
}
#endif

#endif