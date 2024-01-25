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
 * dml_cl.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/parser/dml_cl.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DML_CL_H__
#define __DML_CL_H__

#include "ast.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PLC_SAVE_KW_HOOK(compiler) plc_keyword_hook_t __kw_hook__ = (compiler)->keyword_hook
#define PLC_RESTORE_KW_HOOK(compiler) (compiler)->keyword_hook = __kw_hook__

status_t pl_compile_parse_sql(sql_stmt_t *stmt, sql_context_t **ctx, text_t *sql, source_location_t *loc,
    galist_t *sql_list);
status_t plc_compile_sql(pl_compiler_t *compiler, word_t *word);
status_t plc_compile_dml(pl_compiler_t *compiler, text_t *sql, word_t *word, uint32 types, void *usrdef);
status_t plc_compile_select(pl_compiler_t *compiler, text_t *sql, word_t *word, bool32 is_select_into);
status_t plc_compile_sql_variant(void *anchor);
status_t plc_word2var(sql_stmt_t *stmt, word_t *word, expr_node_t *node);

#ifdef __cplusplus
}
#endif

#endif