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
 * ctsql_insert_verifier.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/verifier/ctsql_insert_verifier.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_INSERT_VERIFIER_H__
#define __SQL_INSERT_VERIFIER_H__

#include "ctsql_verifier.h"


#ifdef __cplusplus
extern "C" {
#endif

status_t sql_verify_insert_pair(sql_verifier_t *verif, sql_table_t *table, column_value_pair_t *pair);
status_t sql_extract_insert_columns(sql_verifier_t *verif, sql_insert_t *insert_ctx);
status_t sql_verify_insert_columns(sql_verifier_t *verif, sql_insert_t *insert_ctx);
status_t sql_verify_insert_tabs(sql_stmt_t *stmt, sql_insert_t *insert_ctx);
status_t sql_verify_insert_context(knl_handle_t session, sql_verifier_t *verif, sql_insert_t *insert_ctx);
status_t sql_verify_insert(sql_stmt_t *stmt, sql_insert_t *insert_ctx);

#ifdef __cplusplus
}
#endif

#endif