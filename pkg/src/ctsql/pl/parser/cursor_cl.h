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
 * cursor_cl.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/parser/cursor_cl.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CURSOR_CL_H__
#define __CURSOR_CL_H__

#include "ast.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t plc_build_open_cursor_args(pl_compiler_t *compiler, word_t *word, galist_t *expr_list);
status_t plc_compile_cursor_def(pl_compiler_t *compiler, galist_t *decls, word_t *word);
status_t plc_compile_for_cursor(pl_compiler_t *compiler, pl_line_for_t *line, word_t *word);
status_t plc_compile_refcur(pl_compiler_t *compiler, word_t *word, plv_decl_t *decl, pl_line_open_t *line);
status_t plc_diagnose_for_is_cursor(pl_compiler_t *compiler, bool8 *is_cur);
status_t plc_expanse_cursor_defs(pl_compiler_t *compiler, galist_t *decls);
status_t plc_verify_cursor_args(pl_compiler_t *compiler, galist_t *expr_list, galist_t *args, source_location_t loc);
status_t plc_compile_syscursor_def(pl_compiler_t *compiler, word_t *word, plv_decl_t *decl);
status_t plc_compile_type_refcur_def(pl_compiler_t *compiler, plv_decl_t *decl, galist_t *decls, word_t *word);
status_t plc_verify_cursor_setval(pl_compiler_t *compiler, expr_tree_t *expr);
status_t plc_verify_using_out_cursor(pl_compiler_t *compiler, expr_tree_t *expr);

#ifdef __cplusplus
}
#endif

#endif