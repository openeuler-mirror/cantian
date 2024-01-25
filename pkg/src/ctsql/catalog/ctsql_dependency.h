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
 * ctsql_dependency.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/catalog/ctsql_dependency.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef SQL_DEPENDENCY_H
#define SQL_DEPENDENCY_H

#include "cm_defs.h"
#include "ctsql_stmt.h"
#include "knl_interface.h"
#include "knl_context.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32 tab_id;
    uint32 ind_id;
    uint32 status_col_id;
    uint32 oid_size;
} obj_status_table_t;

status_t sql_append_references(galist_t *dest, const sql_context_t *sql_ctx);
bool32 sql_check_ref_exists(galist_t *ref_objects, object_address_t *ref_obj);
status_t sql_apend_dependency_table(sql_stmt_t *stmt, sql_table_t *sql_table);
status_t sql_append_reference_knl_dc(galist_t *dest, knl_dictionary_t *dc);
status_t sql_update_object_status(knl_session_t *session, const obj_info_t *obj, object_status_t obj_status);
status_t sql_update_depender_status(knl_handle_t sess, obj_info_t *obj);

#ifdef __cplusplus
}
#endif

#endif /* SQL_DEPENDENCY_H */
