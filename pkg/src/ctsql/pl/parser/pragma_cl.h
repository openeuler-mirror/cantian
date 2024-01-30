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
 * pragma_cl.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/parser/pragma_cl.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PRAGMA_CL_H__
#define __PRAGMA_CL_H__

#include "ast.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t plc_find_line_except(pl_compiler_t *compiler, pl_line_when_t *when_line, pl_exception_t *except_info,
    sql_text_t *except_name);
status_t plc_check_auton_output_valid(pl_compiler_t *compiler, galist_t *decls);
status_t plc_check_except_exists(pl_compiler_t *compiler, galist_t *line_excepts, pl_exception_t *except_info,
    sql_text_t *except_name);
status_t plc_compile_pragma(pl_compiler_t *compiler, galist_t *decls, word_t *word);
status_t plc_try_compile_end_when(pl_compiler_t *compiler, bool32 *result, word_t *word);
status_t plc_compile_excpt_def(pl_compiler_t *compiler, word_t *word, plv_decl_t *decl);

#ifdef __cplusplus
}
#endif

#endif