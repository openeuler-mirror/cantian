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
 * typedef_cl.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/parser/typedef_cl.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __TYPEDEF_CL_H__
#define __TYPEDEF_CL_H__

#include "ast.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum st_plv_cur_rowtype {
    PLV_CUR_UNKNOWN = -1,
    PLV_CUR_ROWTYPE = 0,
    PLV_CUR_TYPE = 1,
} plv_cur_rowtype_t;

typedef enum en_plc_match_type {
    MATCH_RECORD = 0,
    MATCH_REF,
    MATCH_VARRAY,
    MATCH_TABLE
} plc_match_type_t;

status_t plc_convert_typedecl(pl_compiler_t *compiler, galist_t *decls);
status_t plc_try_find_global_type(pl_compiler_t *compiler, word_t *word, plv_decl_t **decl, bool32 *found);
status_t plc_copy_variant_rowtype(pl_compiler_t *compiler, plv_decl_t *src, plc_var_type_t var_type,
                                  plattr_assist_t *plattr_ass, word_t *word);
status_t plc_compile_type_def(pl_compiler_t *compiler, galist_t *decls, word_t *word);
status_t plc_compile_variant_def(pl_compiler_t *compiler, word_t *word, plv_decl_t *decl, bool32 is_arg,
    galist_t *decls, bool32 need_check);
status_t plc_check_attr_duplicate(pl_compiler_t *compiler, plv_record_t *record, word_t *word);
status_t plc_compile_scalar_attr(pl_compiler_t *compiler, word_t *word, plv_record_attr_t *attr);
status_t plc_check_array_element_size(pl_compiler_t *compiler, plv_decl_t *decl);
status_t plc_compile_global_type_member(pl_compiler_t *compiler, plv_decl_t *decl, word_t *word);
status_t plc_compile_attr_options(pl_compiler_t *compiler, word_t *word, expr_tree_t **def_expr, bool8 *null);
status_t plc_compile_global_udt_attr(pl_compiler_t *compiler, word_t *word, plv_decl_t **udt_fld, int8 *type);
status_t plc_check_object_datatype(pl_compiler_t *compiler, plv_decl_t *decl, bool32 is_arg);

#ifdef __cplusplus
}
#endif

#endif