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
 * pl_udt.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/type/pl_udt.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_UDT_H__
#define __PL_UDT_H__

#include "ast.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t udt_address(sql_stmt_t *stmt, var_address_pair_t *addr_pair, expr_node_t *node, variant_t *obj,
                     variant_t *right);
status_t udt_get_addr_node_type(sql_verifier_t *verifier, expr_node_t *node);
status_t udt_var_address(sql_stmt_t *stmt, galist_t *pairs, expr_node_t *node, variant_t *obj, variant_t *right);
status_t check_invalid_var_ref(var_address_pair_t *addr_pair, variant_t *value, variant_t *right);
status_t udt_verify_v_address(sql_verifier_t *verifier, expr_node_t *node);
status_t udt_verify_v_method(sql_verifier_t *verifier, expr_node_t *node);
status_t udt_verify_v_construct(sql_verifier_t *verifier, expr_node_t *node);
status_t udt_exec_v_construct(sql_stmt_t *stmt, expr_node_t *node, variant_t *result);
status_t udt_exec_v_method(sql_stmt_t *stmt, expr_node_t *node, variant_t *result);
status_t udt_exec_v_addr(sql_stmt_t *stmt, expr_node_t *node, variant_t *result, variant_t *right);

status_t udt_into_as_value(sql_stmt_t *stmt, pl_into_t *into, void *exec, variant_t *right);
status_t udt_into_as_coll(sql_stmt_t *stmt, pl_into_t *into, void *exec, variant_t *right);
status_t udt_into_as_record(sql_stmt_t *stmt, pl_into_t *into, void *exec, variant_t *right);
status_t udt_into_as_coll_rec(sql_stmt_t *stmt, pl_into_t *into, void *exec, variant_t *right);
status_t plc_prepare_method_extra(sql_stmt_t *stmt, word_t *word, uint32 *count, ex_text_t extend[]);
status_t plc_try_obj_access_node(sql_stmt_t *stmt, word_t *word, expr_node_t *node);
status_t plc_try_obj_access_bracket(sql_stmt_t *stmt, word_t *word, expr_node_t *node);
status_t plc_recurse_parse_udt_address(sql_stmt_t *stmt, plv_typdef_t *type_def, galist_t *pairs, uint32 *index,
    word_t *ex_word, expr_node_t *node);
status_t plc_add_udt_pair(sql_stmt_t *stmt, galist_t *owner, udt_addr_type_t pair_type, var_address_pair_t **addr_pair);
status_t plc_build_var_address(sql_stmt_t *stmt, plv_decl_t *decl, expr_node_t *node, udt_addr_type_t pair_type);
status_t udt_copy_array(sql_stmt_t *stmt, variant_t *src, expr_node_t *node);
status_t plc_try_obj_access_single(sql_stmt_t *stmt, word_t *word, expr_node_t *node);
status_t udt_build_list_address_single(sql_stmt_t *stmt, galist_t *list, plv_decl_t *decl, udt_addr_type_t pair_type);
plv_decl_t *plm_get_type_decl_by_coll(plv_collection_t *coll_meta);
void pl_init_udt_method(void);
#ifdef __cplusplus
}
#endif

#endif
