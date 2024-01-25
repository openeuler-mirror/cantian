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
 * pl_common.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/common/pl_common.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_COMMON_H__
#define __PL_COMMON_H__

#include "pl_defs.h"
#include "ctsql_stmt.h"
#include "ctsql_expr.h"
#include "ctsql_verifier.h"
#ifdef __cplusplus
extern "C" {
#endif


status_t pl_unfound_error(sql_stmt_t *stmt, var_udo_t *udo_obj, src_loc_t *loc, uint32 type);
status_t pl_copy_name_cs(void *entity, text_t *src, text_t *dst, bool32 sensitive);
status_t pl_copy_object_name_ci(void *context, word_type_t type, text_t *src, text_t *dst);
status_t pl_copy_name(void *context, text_t *src, text_t *dst);
status_t pl_copy_text(void *context, text_t *src, text_t *dst);
status_t pl_copy_str(void *context, char *src, text_t *dst);
status_t pl_copy_object_name(void *context, word_type_t type, text_t *src, text_t *dst);
status_t pl_word_as_table(void *stmt_in, word_t *word, var_word_t *var);
status_t pl_decode_object_name(sql_stmt_t *stmt, word_t *word, sql_text_t *user, sql_text_t *name);
typedef status_t (*pl_copy_func_t)(void *context, text_t *src, text_t *dst);
status_t pl_copy_prefix_tenant(void *stmt_in, text_t *src, text_t *dst, pl_copy_func_t pl_copy_func);
uint32 pl_get_obj_type(object_type_t obj_type);
object_type_t pltype_to_objtype(uint32 obj_type);

#ifdef __cplusplus
}
#endif

#endif
