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
 * trigger_decl_cl.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/parser/trigger_decl_cl.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __TRIGGER_DECL_CL_H__
#define __TRIGGER_DECL_CL_H__

#include "ast.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PLC_IS_TRIGGER_CONTEXT(compiler) ((compiler)->stmt->context->type == CTSQL_TYPE_CREATE_TRIG)
#define PLC_TRIG_NAME_RESERVERD_LEN 5 /* :new.   :old. */
#define TRIG_REAL_COLUMN_TABLE 0
#define TRIG_PSEUDO_COLUMN_TALBE 1
#define TRIG_RES_WORD_ROWID 0
#define TRIG_RES_WORD_ROWSCN 1

#define IS_TRIGGER_WORD_TYPE(word) ((word)->type == WORD_TYPE_PL_NEW_COL || (word)->type == WORD_TYPE_PL_OLD_COL)

status_t plc_verify_trigger_modified_var(pl_compiler_t *compiler, plv_decl_t *decl);
void plc_get_trig_decl_name(pl_compiler_t *compiler, text_t *out, word_t *word, bool32 *is_upper_case);
status_t plc_add_trigger_decl(pl_compiler_t *compiler, uint32 stack_id, word_t *word, uint32 type,
    plv_decl_t **res_decl);
status_t plc_compile_trigger_variant(pl_compiler_t *compiler, text_t *sql, word_t *word);
status_t plc_init_trigger_decls(pl_compiler_t *compiler);
status_t plc_add_modified_new_cols(pl_compiler_t *compiler);

#ifdef __cplusplus
}
#endif

#endif