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
 * ctsql_expr_verifier.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/verifier/ctsql_expr_verifier.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_EXPR_VERIFIER_H__
#define __SQL_EXPR_VERIFIER_H__

#include "ctsql_verifier.h"


#ifdef __cplusplus
extern "C" {
#endif

#define ROWNODEID_LENGTH 18 /* rownodeid for outer users is a string with a fixed length ROWNODEID_LENGTH. */

status_t sql_verify_func(sql_verifier_t *verif, expr_node_t *node);
status_t sql_try_verify_noarg_func(sql_verifier_t *verif, expr_node_t *node, bool32 *is_found);

bool32 sql_check_has_single_column(sql_verifier_t *verif, expr_node_t *node);

bool32 sql_check_table_column_exists(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node);

status_t sql_try_verify_dbmsconst(sql_verifier_t *verif, expr_node_t *node, bool32 *result);
status_t sql_try_verify_sequence(sql_verifier_t *verif, expr_node_t *node, bool32 *result);
status_t sql_try_verify_rowid(sql_verifier_t *verif, expr_node_t *node, bool32 *result);
status_t sql_try_verify_rowscn(sql_verifier_t *verif, expr_node_t *node, bool32 *result);
status_t sql_try_verify_rownodeid(sql_verifier_t *verf, expr_node_t *node, bool32 *result);
status_t sql_verify_pl_var(sql_verifier_t *verif, plv_id_t vid, expr_node_t *node);
ct_type_t sql_get_case_expr_compatible_datatype(ct_type_t case_datatype, ct_type_t expr_datatype);

#ifdef __cplusplus
}
#endif

#endif