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
 * ctsql_select_verifier.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/verifier/ctsql_select_verifier.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_SELECT_VERIFIER_H__
#define __SQL_SELECT_VERIFIER_H__

#include "ctsql_verifier.h"


#ifdef __cplusplus
extern "C" {
#endif

status_t sql_verify_column_expr(sql_verifier_t *verif, expr_node_t *node);
status_t sql_verify_return_columns(sql_verifier_t *verif, galist_t *ret_columns);
status_t sql_verify_query_columns(sql_verifier_t *verif, sql_query_t *query);

status_t sql_verify_query_joins(sql_verifier_t *verif, sql_query_t *query);
status_t sql_verify_query_unpivot(sql_verifier_t *verif, sql_query_t *query);
status_t sql_normalize_group_sets(sql_stmt_t *stmt, sql_query_t *query);
status_t sql_verify_query_group(sql_verifier_t *verif, sql_query_t *query);
status_t sql_verify_query_having(sql_verifier_t *verif, sql_query_t *query);
status_t sql_verify_query_where(sql_verifier_t *verif, sql_query_t *query);
status_t sql_verify_query_connect(sql_verifier_t *verf, sql_query_t *query);
status_t sql_verify_query_limit(sql_verifier_t *verif, sql_query_t *query);

#ifdef __cplusplus
}
#endif

#endif