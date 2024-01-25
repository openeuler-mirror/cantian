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
 * ctsql_merge.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_merge.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_MERGE_H__
#define __SQL_MERGE_H__

#include "dml_executor.h"
#include "ctsql_update.h"
#include "ctsql_insert.h"

status_t sql_execute_merge(sql_stmt_t *stmt);

static inline status_t sql_before_execute_merge(sql_stmt_t *stmt, sql_table_t *table)
{
    sql_merge_t *merge_ctx = (sql_merge_t *)stmt->context->entry;

    if (merge_ctx->insert_ctx != NULL) {
        CT_RETURN_IFERR(sql_execute_insert_triggers(stmt, table, TRIG_BEFORE_STATEMENT, NULL, NULL));
    }

    if (merge_ctx->update_ctx != NULL) {
        upd_object_t *object = (upd_object_t *)cm_galist_get(merge_ctx->update_ctx->objects, 0);
        CT_RETURN_IFERR(sql_execute_update_triggers(stmt, TRIG_BEFORE_STATEMENT, NULL, object));
    }

    return CT_SUCCESS;
}

static inline status_t sql_after_execute_merge(sql_stmt_t *stmt, sql_table_t *table)
{
    sql_merge_t *merge_ctx = (sql_merge_t *)stmt->context->entry;

    if (merge_ctx->update_ctx != NULL) {
        upd_object_t *object = (upd_object_t *)cm_galist_get(merge_ctx->update_ctx->objects, 0);
        CT_RETURN_IFERR(sql_execute_update_triggers(stmt, TRIG_AFTER_STATEMENT, NULL, object));
    }

    if (merge_ctx->insert_ctx != NULL) {
        CT_RETURN_IFERR(sql_execute_insert_triggers(stmt, table, TRIG_AFTER_STATEMENT, NULL, NULL));
    }

    return CT_SUCCESS;
}

#endif