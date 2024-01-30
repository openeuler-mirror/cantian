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
 * ctsql_delete_verifier.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/verifier/ctsql_delete_verifier.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_delete_verifier.h"
#include "ctsql_select_verifier.h"
#include "ctsql_table_verifier.h"
#include "dml_parser.h"
#include "base_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t sql_verify_oper_object(knl_handle_t session, sql_verifier_t *verf, del_object_t *object,
    sql_array_t *tables)
{
    bool32 is_found = CT_FALSE;
    sql_table_t *table = NULL;

    for (uint32 i = 0; i < tables->count; i++) {
        table = (sql_table_t *)sql_array_get(tables, i);
        if (!sql_search_table_name(table, (text_t *)&object->user, (text_t *)&object->name)) {
            continue;
        }

        if (is_found) {
            CT_SRC_THROW_ERROR_EX(object->name.loc, ERR_SQL_SYNTAX_ERROR, "table '%s' ambiguously defined",
                T2S((text_t *)&object->name));
            return CT_ERROR;
        }
        CT_RETURN_IFERR(sql_verify_view_insteadof_trig(verf->stmt, table, TRIG_EVENT_DELETE));
        if ((table->type != NORMAL_TABLE && table->type != VIEW_AS_TABLE) || table->entry->dc.type > DICT_TYPE_VIEW) {
            CT_SRC_THROW_ERROR(object->name.loc, ERR_OPERATIONS_NOT_SUPPORT, "delete table", "view or system table");
            return CT_ERROR;
        }
        if (tables->count > 1 && (table->entry->dc.type != DICT_TYPE_TABLE &&
            table->entry->dc.type != DICT_TYPE_TABLE_NOLOGGING && table->entry->dc.type != DICT_TYPE_VIEW)) {
            CT_SRC_THROW_ERROR(table->name.loc, ERR_OPERATIONS_NOT_SUPPORT, "multi delete", "temp table");
            return CT_ERROR;
        }

        CT_RETURN_IFERR(sql_verify_table_dml_object(session, verf->stmt, object->name.loc, table->entry->dc, CT_TRUE));

        is_found = CT_TRUE;
        if (table->type == VIEW_AS_TABLE) {
            table->view_dml = CT_TRUE;
        }
        object->table = table;
    }

    if (!is_found) {
        CT_SRC_THROW_ERROR_EX(object->name.loc, ERR_SQL_SYNTAX_ERROR, "unknown table %s in multi delete",
            T2S((text_t *)&object->name));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_verify_oper_objects(knl_handle_t session, sql_verifier_t *verf, sql_delete_t *delete_ctx)
{
    del_object_t *object = NULL;

    for (uint32 i = 0; i < delete_ctx->objects->count; i++) {
        object = (del_object_t *)cm_galist_get(delete_ctx->objects, i);
        CT_RETURN_IFERR(sql_verify_oper_object(session, verf, object, &delete_ctx->query->tables));
    }
    return CT_SUCCESS;
}

static status_t sql_verify_delete_return_columns(sql_verifier_t *verf, sql_delete_t *delete_ctx)
{
    if (delete_ctx->ret_columns == NULL) {
        return CT_SUCCESS;
    }

    if (delete_ctx->query->tables.count > 1) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "unexpected returning columns occurs");
        return CT_ERROR;
    }

    verf->tables = &delete_ctx->query->tables;
    return sql_verify_return_columns(verf, delete_ctx->ret_columns);
}

static status_t sql_verify_delete_context(knl_handle_t session, sql_verifier_t *verf, sql_delete_t *delete_ctx)
{
    sql_query_t *query = delete_ctx->query;
    SET_NODE_STACK_CURR_QUERY(verf->stmt, query);
    CT_RETURN_IFERR(sql_verify_tables(verf, query));

    CT_RETURN_IFERR(sql_verify_query_where(verf, query));

    CT_RETURN_IFERR(sql_verify_query_joins(verf, query));

    CT_RETURN_IFERR(sql_verify_query_order(verf, query, query->sort_items, CT_TRUE));

    CT_RETURN_IFERR(sql_verify_oper_objects(session, verf, delete_ctx));

    if (!LIMIT_CLAUSE_OCCUR(&query->limit)) {
        cm_galist_reset(query->sort_items);
    }

    CT_RETURN_IFERR(sql_verify_delete_return_columns(verf, delete_ctx));
    SQL_RESTORE_NODE_STACK(verf->stmt);
    return CT_SUCCESS;
}

status_t sql_verify_delete(sql_stmt_t *stmt, sql_delete_t *delete_ctx)
{
    sql_verifier_t verf = { 0 };

    verf.stmt = stmt;
    verf.context = stmt->context;
    verf.pl_dc_lst = delete_ctx->pl_dc_lst;
    verf.do_expr_optmz = CT_TRUE;

    plc_get_verify_obj(stmt, &verf);
    return sql_verify_delete_context(&stmt->session->knl_session, &verf, delete_ctx);
}

#ifdef __cplusplus
}
#endif
