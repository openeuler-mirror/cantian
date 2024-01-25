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
 * ctsql_insert_verifier.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/verifier/ctsql_insert_verifier.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_insert_verifier.h"
#include "ctsql_select_verifier.h"
#include "ctsql_update_verifier.h"
#include "ctsql_table_verifier.h"
#include "base_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t sql_get_part_key_map(sql_verifier_t *verif, uint32 col_count, sql_insert_t *insert_ctx,
    knl_dictionary_t *dc)
{
    uint16 col_id, partkeys;
    CT_RETURN_IFERR(sql_alloc_mem(verif->context, sizeof(uint16) * col_count, (void **)&insert_ctx->part_key_map));
    MEMS_RETURN_IFERR(memset_s(insert_ctx->part_key_map, sizeof(uint16) * col_count, (int)CT_INVALID_ID16,
        sizeof(uint16) * col_count));
    partkeys = knl_part_key_count(dc->handle);
    for (uint16 i = 0; i < partkeys; i++) {
        col_id = knl_part_key_column_id(dc->handle, i);
        insert_ctx->part_key_map[col_id] = i;
    }
    return CT_SUCCESS;
}

status_t sql_verify_insert_pair(sql_verifier_t *verif, sql_table_t *table, column_value_pair_t *pair)
{
    knl_dictionary_t *dc = &table->entry->dc;

    pair->column_id = knl_get_column_id(dc, (text_t *)&pair->column_name);

    if (CT_INVALID_ID16 == pair->column_id) {
        CT_SRC_THROW_ERROR(pair->column_name.loc, ERR_INVALID_COLUMN_NAME, T2S(&pair->column_name));
        return CT_ERROR;
    }

    pair->column = knl_get_column(dc->handle, pair->column_id);

    if (pair->column->default_text.len != 0) {
        CT_RETURN_IFERR(sql_add_sequence_node(verif->stmt, ((expr_tree_t *)pair->column->default_expr)->root));
    }
    return CT_SUCCESS;
}

status_t sql_verify_insert_columns(sql_verifier_t *verif, sql_insert_t *insert_ctx)
{
    column_value_pair_t *pair = NULL;

    for (uint32 i = 0; i < insert_ctx->pairs->count; i++) {
        pair = (column_value_pair_t *)cm_galist_get(insert_ctx->pairs, i);
        if (sql_verify_insert_pair(verif, insert_ctx->table, pair) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (insert_ctx->col_map[pair->column_id] != CT_INVALID_ID32) {
            CT_SRC_THROW_ERROR(pair->column_name.loc, ERR_DUPLICATE_NAME, "column", pair->column->name);
            return CT_ERROR;
        }

        insert_ctx->col_map[pair->column_id] = i;
    }
    return CT_SUCCESS;
}

status_t sql_extract_insert_columns(sql_verifier_t *verif, sql_insert_t *insert_ctx)
{
    knl_column_t *knl_column = NULL;
    knl_dictionary_t *dc = &insert_ctx->table->entry->dc;
    uint32 column_count;
    uint32 pair_id = 0;
    column_value_pair_t *pair = NULL;
    column_count = knl_get_column_count(dc->handle);

    for (uint32 i = 0; i < column_count; i++) {
        knl_column = knl_get_column(dc->handle, i);
        if (KNL_COLUMN_INVISIBLE(knl_column)) {
            continue;
        }

        if (insert_ctx->select_ctx != NULL && !CT_BIT_TEST(insert_ctx->syntax_flag, INSERT_IS_ALL)) {
            CT_RETURN_IFERR(cm_galist_new(insert_ctx->pairs, sizeof(column_value_pair_t), (void **)&pair));
            pair->exprs = NULL;
        } else {
            if (insert_ctx->pairs->count <= pair_id) {
                CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "too less value expressions");
                return CT_ERROR;
            }

            pair = (column_value_pair_t *)cm_galist_get(insert_ctx->pairs, pair_id);
        }

        if (knl_column->default_text.len != 0) {
            CT_RETURN_IFERR(sql_add_sequence_node(verif->stmt, ((expr_tree_t *)knl_column->default_expr)->root));
        }

        pair->column_id = i;
        pair->column = knl_column;
        insert_ctx->col_map[pair->column_id] = pair_id++;
    }

    if (insert_ctx->pairs->count > pair_id) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "too many value expressions");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_verify_insert_values(sql_verifier_t *verif, sql_insert_t *insert_ctx)
{
    column_value_pair_t *pair = NULL;
    verif->excl_flags = SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_ROWSCN |
        SQL_EXCL_WIN_SORT | SQL_EXCL_GROUPING | SQL_EXCL_ROWNODEID;

    if (verif->merge_insert_status == SQL_MERGE_INSERT_NONE) {
        verif->excl_flags |= SQL_EXCL_COLUMN;
    } else {
        verif->merge_insert_status = SQL_MERGE_INSERT_VALUES;
    }

    for (uint32 i = 0; i < insert_ctx->pairs->count; i++) {
        pair = (column_value_pair_t *)cm_galist_get(insert_ctx->pairs, i);
        if (sql_static_check_dml_pair(verif, pair) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_verify_insert_ignore(sql_insert_t *insert_ctx)
{
    if ((insert_ctx->syntax_flag & INSERT_IS_IGNORE) && insert_ctx->update_ctx != NULL) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "\"UPDATE\" cannot be used when \"IGNORE\" exists");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_insert_tabs(sql_stmt_t *stmt, sql_insert_t *insert_ctx)
{
    sql_table_t *sql_table = insert_ctx->table;

    if (sql_table->type == SUBSELECT_AS_TABLE || sql_table->type == WITH_AS_TABLE) {
        CT_SRC_THROW_ERROR(sql_table->name.loc, ERR_OPERATIONS_NOT_SUPPORT, "insert", "subquery");
        return CT_ERROR;
    }

    if (sql_init_normal_table_dc(stmt, sql_table, NULL) != CT_SUCCESS) {
        cm_reset_error_user(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(&sql_table->user.value), T2S_EX(&sql_table->name.value),
            ERR_TYPE_TABLE_OR_VIEW);
        cm_set_error_loc(sql_table->user.loc);
        return CT_ERROR;
    }

    if (CT_BIT_TEST(insert_ctx->syntax_flag, INSERT_IS_ALL) &&
        (sql_table->type == VIEW_AS_TABLE || stmt->context->has_dblink)) {
        CT_SRC_THROW_ERROR(sql_table->name.loc, ERR_OPERATIONS_NOT_SUPPORT, "insert all", "view or dblink table");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_verify_table_dml_object(&stmt->session->knl_session, stmt, insert_ctx->table->name.loc,
        sql_table->entry->dc, CT_FALSE));
    if (!sql_table->is_distribute_rule) {
        if (sql_table->entry->dc.type > DICT_TYPE_TABLE_EXTERNAL && sql_table->entry->dc.type != DICT_TYPE_VIEW) {
            CT_SRC_THROW_ERROR(sql_table->name.loc, ERR_OPERATIONS_NOT_SUPPORT, "parse table", "view or system table");
            return CT_ERROR;
        }
    } else {
        if (sql_table->entry->dc.type != DICT_TYPE_DISTRIBUTE_RULE) {
            CT_SRC_THROW_ERROR(sql_table->name.loc, ERR_CAPABILITY_NOT_SUPPORT, "rule not in distribute type list");
            return CT_ERROR;
        }
    }

    CT_RETURN_IFERR(sql_verify_view_insteadof_trig(stmt, sql_table, TRIG_EVENT_INSERT));
    if (sql_table->type == VIEW_AS_TABLE) {
        sql_table->view_dml = CT_TRUE;
        CT_RETURN_IFERR(sql_verify_select(stmt, sql_table->select_ctx));
    }
    return CT_SUCCESS;
}

static status_t sql_verify_insert_select_pair_datatype(sql_insert_t *insert_ctx)
{
    rs_column_t *rs_col = NULL;
    column_value_pair_t *pair = NULL;
    galist_t *rs_cols = insert_ctx->select_ctx->first_query->rs_columns;
    galist_t *pairs = insert_ctx->pairs;
    uint32 i;

    if (rs_cols->count != pairs->count) {
        CT_THROW_ERROR((rs_cols->count > pairs->count) ? ERR_TOO_MANY_VALUES : ERR_NOT_ENOUGH_VALUES);
        return CT_ERROR;
    }

    for (i = 0; i < rs_cols->count; i++) {
        rs_col = (rs_column_t *)cm_galist_get(rs_cols, i);
        pair = (column_value_pair_t *)cm_galist_get(pairs, i);
        CT_CHECK_ERROR_MISMATCH(pair->column->datatype, rs_col->datatype);
    }
    return CT_SUCCESS;
}

static status_t sql_verify_insert_return_columns(sql_verifier_t *verif, sql_insert_t *insert_ctx)
{
    if (insert_ctx->ret_columns == NULL) {
        return CT_SUCCESS;
    }

    /* only supports "insert values returning" */
    if (insert_ctx->select_ctx != NULL || insert_ctx->update_ctx != NULL) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "unexpected returning columns occurs");
        return CT_ERROR;
    }

    verif->table = insert_ctx->table;
    return sql_verify_return_columns(verif, insert_ctx->ret_columns);
}

static status_t sql_verify_insall_values_and_select(sql_verifier_t *verif, sql_insert_t *insert_ctx)
{
    CT_RETURN_IFERR(sql_verify_select_context(verif, insert_ctx->select_ctx));
    if (verif->has_ddm_col == CT_TRUE) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", the command references a redacted object");
        return CT_ERROR;
    }
    return sql_verify_insert_values(verif, insert_ctx);
}

static status_t sql_verify_insert_select(sql_verifier_t *verif, sql_insert_t *insert_ctx)
{
    CT_RETURN_IFERR(sql_verify_select_context(verif, insert_ctx->select_ctx));
    if (verif->has_ddm_col == CT_TRUE) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", the command references a redacted object");
        return CT_ERROR;
    }
    return sql_verify_insert_select_pair_datatype(insert_ctx);
}

status_t sql_verify_insert_context(knl_handle_t session, sql_verifier_t *verif, sql_insert_t *insert_ctx)
{
    uint32 col_count;
    knl_dictionary_t *dc = NULL;
    knl_column_t *knl_col = NULL;

    CT_RETURN_IFERR(sql_verify_insert_ignore(insert_ctx));
    CT_RETURN_IFERR(sql_verify_insert_tabs(verif->stmt, insert_ctx));
    dc = &insert_ctx->table->entry->dc;
    col_count = knl_get_column_count(dc->handle);
    if (col_count == 0) {
        CT_THROW_ERROR(ERR_INVALID_DC, T2S(&insert_ctx->table->name));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_alloc_mem(verif->context, sizeof(uint32) * col_count, (void **)&insert_ctx->col_map));

    MEMS_RETURN_IFERR(
        memset_s(insert_ctx->col_map, sizeof(uint32) * col_count, (int)CT_INVALID_ID32, sizeof(uint32) * col_count));
    if (!(insert_ctx->flags & INSERT_COLS_SPECIFIED)) {
        CT_RETURN_IFERR(sql_extract_insert_columns(verif, insert_ctx));
    } else {
        CT_RETURN_IFERR(sql_verify_insert_columns(verif, insert_ctx));

        for (uint32 i = 0; i < col_count; ++i) {
            knl_col = knl_get_column(dc->handle, i);
            if (KNL_COLUMN_INVISIBLE(knl_col)) {
                continue;
            }
            if (knl_col->default_text.len != 0) {
                CT_RETURN_IFERR(sql_add_sequence_node(verif->stmt, ((expr_tree_t *)knl_col->default_expr)->root));
            }
        }
    }

    if (knl_is_part_table(dc->handle)) {
        CT_RETURN_IFERR(sql_get_part_key_map(verif, col_count, insert_ctx, dc));
    }

    if (CT_BIT_TEST(insert_ctx->syntax_flag, INSERT_IS_ALL)) {
        CT_RETURN_IFERR(sql_verify_insall_values_and_select(verif, insert_ctx));
    } else if (insert_ctx->select_ctx) {
        CT_RETURN_IFERR(sql_verify_insert_select(verif, insert_ctx));
    } else {
        CT_RETURN_IFERR(sql_verify_insert_values(verif, insert_ctx));
    }

    if (insert_ctx->update_ctx != NULL) {
        CT_RETURN_IFERR(sql_verify_update_pairs(session, verif, insert_ctx->update_ctx));
    }

    CT_RETURN_IFERR(sql_verify_insert_return_columns(verif, insert_ctx));

    return CT_SUCCESS;
}

status_t sql_verify_normal_insert(sql_stmt_t *stmt, sql_insert_t *insert_ctx)
{
    sql_verifier_t verif = { 0 };
    verif.stmt = stmt;
    verif.table = insert_ctx->table;
    verif.pl_dc_lst = insert_ctx->pl_dc_lst;
    verif.context = stmt->context;
    verif.do_expr_optmz = CT_TRUE;

    plc_get_verify_obj(stmt, &verif);
    return sql_verify_insert_context(&stmt->session->knl_session, &verif, insert_ctx);
}

static status_t sql_check_into_info(sql_stmt_t *stmt, sql_insert_t *insert_ctx)
{
    uint32 cols_num;
    insert_all_t *into_item = NULL;
    sql_table_t *table1 = insert_ctx->table;
    sql_table_t *table2 = NULL;
    column_value_pair_t *col_value1 = NULL;
    column_value_pair_t *col_value2 = NULL;
    status_t result = CT_SUCCESS;

    for (uint32 into_num = 1; into_num < insert_ctx->into_list->count; into_num++) {
        into_item = (insert_all_t *)cm_galist_get(insert_ctx->into_list, into_num);
        table2 = into_item->table;

        if (into_item->pairs_count != 1 || insert_ctx->pairs_count != 1) {
            result = CT_ERROR;
            break;
        }
        if (!cm_text_equal(&table2->user.value, &table1->user.value)) {
            result = CT_ERROR;
            break;
        }
        if (!cm_text_equal(&table2->name.value, &table1->name.value)) {
            result = CT_ERROR;
            break;
        }
        if (!cm_text_equal(&table2->alias.value, &table1->alias.value)) {
            result = CT_ERROR;
            break;
        }

        if (into_item->pairs->count != insert_ctx->pairs->count) {
            result = CT_ERROR;
            break;
        }
        for (cols_num = 0; cols_num < insert_ctx->pairs->count; cols_num++) {
            col_value1 = (column_value_pair_t *)cm_galist_get(insert_ctx->pairs, cols_num);
            col_value2 = (column_value_pair_t *)cm_galist_get(into_item->pairs, cols_num);
            if (!cm_text_equal(&col_value1->column_name.value, &col_value2->column_name.value)) {
                result = CT_ERROR;
                break;
            }
        }
        CT_BREAK_IF_ERROR(result);
    }

    if (result == CT_ERROR) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "Inconsistent user, table, column or value groups");
    }

    return result;
}

static status_t sql_collect_value_pairs(sql_insert_t *insert_ctx)
{
    uint32 col_count = insert_ctx->pairs->count;
    uint32 into_count = insert_ctx->into_list->count;
    insert_all_t *into_item = NULL;
    column_value_pair_t *dst_pair_item = NULL;
    column_value_pair_t *pair_item = NULL;

    for (uint32 i = 1; i < into_count; i++) {
        into_item = (insert_all_t *)cm_galist_get(insert_ctx->into_list, i);
        for (uint32 j = 0; j < col_count; j++) {
            pair_item = (column_value_pair_t *)cm_galist_get(into_item->pairs, j);
            dst_pair_item = (column_value_pair_t *)cm_galist_get(insert_ctx->pairs, j);
            CT_RETURN_IFERR(cm_galist_copy(dst_pair_item->exprs, pair_item->exprs));
        }
    }

    dst_pair_item = (column_value_pair_t *)cm_galist_get(insert_ctx->pairs, 0);
    insert_ctx->pairs_count = dst_pair_item->exprs->count;

    return CT_SUCCESS;
}

status_t sql_verify_insert_all(sql_stmt_t *stmt, sql_insert_t *insert_ctx)
{
    CT_RETURN_IFERR(sql_check_into_info(stmt, insert_ctx));
    CT_RETURN_IFERR(sql_collect_value_pairs(insert_ctx));
    CT_RETURN_IFERR(sql_verify_normal_insert(stmt, insert_ctx));

    return CT_SUCCESS;
}

status_t sql_verify_insert(sql_stmt_t *stmt, sql_insert_t *insert_ctx)
{
    if (CT_BIT_TEST(insert_ctx->syntax_flag, INSERT_IS_ALL)) {
        return sql_verify_insert_all(stmt, insert_ctx);
    }

    return sql_verify_normal_insert(stmt, insert_ctx);
}

#ifdef __cplusplus
}
#endif
