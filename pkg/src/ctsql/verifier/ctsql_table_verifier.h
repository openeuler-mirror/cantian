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
 * ctsql_table_verifier.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/verifier/ctsql_table_verifier.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_TABLE_VERIFIER_H__
#define __SQL_TABLE_VERIFIER_H__

#include "ctsql_verifier.h"
#include "pl_trigger.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_get_table_policies(sql_verifier_t *verif, sql_table_t *table, text_t *clause_text, bool32 *exists);
status_t sql_verify_tables(sql_verifier_t *verif, sql_query_t *query);
status_t sql_search_table(sql_verifier_t *verif, expr_node_t *node, text_t *user, text_t *alias, sql_table_t **table,
    uint32 *level);
bool32 sql_search_table_name(sql_table_t *query_table, text_t *user, text_t *alias);
status_t sql_search_table_local(sql_verifier_t *verif, expr_node_t *node, text_t *user, text_t *alias,
    sql_table_t **table, bool32 *is_found);
status_t sql_search_table_parent(sql_verifier_t *verif, expr_node_t *node, text_t *user, text_t *alias,
    sql_table_t **table, uint32 *level, bool32 *is_found);
status_t sql_init_normal_table_dc(sql_stmt_t *stmt, sql_table_t *sql_table, sql_query_t *parent_query);
status_t sql_verify_view_insteadof_trig(sql_stmt_t *stmt, sql_table_t *table, trig_dml_type_t dml_type);
void sql_extract_subslct_projcols(sql_table_t *subslct_tab);
status_t sql_create_project_columns(sql_stmt_t *stmt, sql_table_t *table);

#ifdef __cplusplus
}
#endif

#endif
