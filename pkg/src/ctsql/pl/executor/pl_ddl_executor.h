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
 * pl_ddl_executor.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/executor/pl_ddl_executor.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_DDL_EXECUTOR_H__
#define __PL_DDL_EXECUTOR_H__

#include "pl_defs.h"
#include "knl_defs.h"
#include "ctsql_stmt.h"
#include "pl_dc_util.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t pl_db_drop_triggers(knl_handle_t knl_session, knl_dictionary_t *dc);
status_t pl_drop_object_by_user(knl_handle_t knl_session, uint32 uid);
void pl_drop_triggers_entry(knl_handle_t knl_session, knl_dictionary_t *dc);
status_t pl_execute_create_replace_synonym(sql_stmt_t *stmt);
status_t pl_execute_create_replace_procedure(sql_stmt_t *stmt);
status_t pl_execute_create_replace_package_spec(sql_stmt_t *stmt);
status_t pl_execute_create_replace_package_body(sql_stmt_t *stmt);
status_t pl_execute_create_replace_trigger(sql_stmt_t *stmt);
status_t pl_execute_create_replace_type_spec(sql_stmt_t *stmt);
status_t pl_execute_create_replace_type_body(sql_stmt_t *stmt);
status_t pl_execute_drop_synonym(sql_stmt_t *stmt);
status_t pl_execute_drop_procedure(sql_stmt_t *stmt);
status_t pl_execute_drop_trigger(sql_stmt_t *stmt);
status_t pl_execute_drop_package_spec(sql_stmt_t *stmt);
status_t pl_execute_drop_package_body(sql_stmt_t *stmt);
status_t pl_execute_drop_type_spec(sql_stmt_t *stmt);
status_t pl_execute_drop_type_body(sql_stmt_t *stmt);

#ifdef __cplusplus
}
#endif

#endif
