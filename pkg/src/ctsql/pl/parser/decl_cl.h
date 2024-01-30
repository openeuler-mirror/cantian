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
 * decl_cl.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/parser/decl_cl.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DECL_CL_H__
#define __DECL_CL_H__

#include "ast.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PLC_INIT_VARIANT_NAME(variant, block_name_buf, name_buf, sensitive, types) \
    do {                                                                           \
        (variant)->block_name.str = (block_name_buf);                              \
        (variant)->block_name.len = 0;                                             \
        (variant)->name.str = (name_buf);                                          \
        (variant)->name.len = 0;                                                   \
        (variant)->case_sensitive = (sensitive);                                   \
        (variant)->types = (types);                                                \
    } while (0)

plv_decl_t *plc_find_param_by_id(pl_compiler_t *compiler, plv_id_t plv_id);
plv_decl_t *plc_find_decl_by_id(pl_compiler_t *compiler, plv_id_t plv_id);
void plc_find_label(pl_compiler_t *compiler, text_t *label, pl_line_ctrl_t **line, bool32 *result);
void plc_find_in_begin_block(pl_compiler_t *compiler, uint32 stack_id, plc_variant_name_t *var, uint32 types,
    plv_decl_t **decl);
void plc_find_block_decl(pl_compiler_t *compiler, plc_variant_name_t *variant_name, plv_decl_t **decl);
void plc_find_decl_ex(pl_compiler_t *compiler, word_t *word, uint32 types, plc_var_type_t *var_type, plv_decl_t **decl);
status_t plc_find_decl(pl_compiler_t *compiler, word_t *word, uint32 types, plc_var_type_t *var_type,
    plv_decl_t **decl);
status_t plc_check_datatype(pl_compiler_t *compiler, typmode_t *type, bool32 is_arg);
status_t plc_check_record_datatype(pl_compiler_t *compiler, plv_decl_t *decl, bool32 is_arg);
status_t plc_compile_default_def(pl_compiler_t *compiler, word_t *word, plv_decl_t *decl, bool32 is_arg);
status_t plc_extract_table_column(pl_compiler_t *compiler, word_t *word, var_udo_t *obj, text_t *column);
expr_node_t *plc_get_param_vid(pl_compiler_t *compiler, uint32 p_nid);
status_t plc_compile_decl(pl_compiler_t *compiler, galist_t *decls, word_t *word);
status_t plc_compile_complex_type(pl_compiler_t *compiler, plv_decl_t *decl, plv_decl_t *type_recur);

#ifdef __cplusplus
}
#endif

#endif