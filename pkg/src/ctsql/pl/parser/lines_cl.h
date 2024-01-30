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
 * lines_cl.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/parser/lines_cl.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __LINES_CL_H__
#define __LINES_CL_H__

#include "ast.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t plc_compile_lines(pl_compiler_t *compiler, word_t *word);
status_t plc_compile_label(pl_compiler_t *compiler, word_t *word, text_t *label_name);
status_t plc_label_name_verify(pl_compiler_t *compiler, const word_t *word);
status_t plc_compile_into_clause(pl_compiler_t *compiler, pl_into_t *into, word_t *word);
status_t plc_compile_bulk_into_clause(pl_compiler_t *compiler, pl_into_t *into, word_t *word);

#ifdef __cplusplus
}
#endif

#endif