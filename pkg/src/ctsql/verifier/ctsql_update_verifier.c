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
 * ctsql_update_verifier.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/verifier/ctsql_update_verifier.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_update_verifier.h"
#include "ctsql_select_verifier.h"
#include "ctsql_table_verifier.h"
#include "srv_instance.h"
#include "dml_parser.h"
#include "base_compiler.h"
#include "expr_parser.h"

#ifdef __cplusplus
extern "C" {
#endif


static status_t sql_create_update_object(sql_verifier_t *verif, column_value_pair_t *pair, sql_table_t *table,
    sql_update_t *update_ctx)
{
    upd_object_t *upd_ob = NULL;

    CT_RETURN_IFERR(cm_galist_new(update_ctx->objects, sizeof(upd_object_t), (void **)&upd_ob));
    if (table->type == VIEW_AS_TABLE) {
        table->view_dml = CT_TRUE;
    }
    upd_ob->table = table;
    CT_RETURN_IFERR(sql_create_list(verif->stmt, &upd_ob->pairs));
    return cm_galist_insert(upd_ob->pairs, pair);
}

static status_t sql_generate_update_object(sql_verifier_t *verif, column_value_pair_t *pair, sql_table_t *table,
    sql_update_t *update_ctx)
{
    upd_object_t *upd_ob = NULL;

    for (uint32 i = 0; i < update_ctx->objects->count; i++) {
        upd_ob = (upd_object_t *)cm_galist_get(update_ctx->objects, i);
        if (upd_ob->table->id == table->id) {
            return cm_galist_insert(upd_ob->pairs, pair);
        }
    }
    return sql_create_update_object(verif, pair, table, update_ctx);
}

status_t sql_verify_update_pair(knl_handle_t session, sql_verifier_t *verif, column_value_pair_t *pair,
    sql_update_t *update_ctx)
{
    uint32 tab;
    sql_table_t *table = NULL;
    expr_node_t *update_col = pair->column_expr->root;

    if (sql_verify_expr_node(verif, update_col) != CT_SUCCESS) {
        if (update_col->type == EXPR_NODE_COLUMN) {
            cm_reset_error();
            CT_SRC_THROW_ERROR(update_col->loc, ERR_INVALID_COLUMN_NAME, T2S(&update_col->word.column.name));
        }
        return CT_ERROR;
    }
    if (update_col->type != EXPR_NODE_COLUMN) {
        CT_SRC_THROW_ERROR(update_col->loc, ERR_EXPECT_COLUMN_HERE);
        return CT_ERROR;
    }
    pair->column_id = VAR_COL(&update_col->value);

    if (CT_INVALID_ID16 == pair->column_id) {
        CT_SRC_THROW_ERROR(update_col->loc, ERR_INVALID_COLUMN_NAME, T2S(&update_col->word.column.name));
        return CT_ERROR;
    }

    tab = VAR_TAB(&pair->column_expr->root->value);
    table = (sql_table_t *)sql_array_get(verif->tables, tab);
    CT_RETURN_IFERR(sql_verify_view_insteadof_trig(verif->stmt, table, TRIG_EVENT_UPDATE));
    if ((table->type != NORMAL_TABLE && table->type != VIEW_AS_TABLE) || table->entry->dc.type > DICT_TYPE_VIEW) {
        CT_SRC_THROW_ERROR(table->name.loc, ERR_OPERATIONS_NOT_SUPPORT, "update",
            "view, func, join table, json table, subqueries or system table");
        return CT_ERROR;
    }
    if (verif->tables->count > 1 && (table->entry->dc.type != DICT_TYPE_TABLE &&
        table->entry->dc.type != DICT_TYPE_TABLE_NOLOGGING && table->entry->dc.type != DICT_TYPE_VIEW)) {
        CT_SRC_THROW_ERROR(table->name.loc, ERR_OPERATIONS_NOT_SUPPORT, "multi update", "temp table");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_verify_table_dml_object(session, verif->stmt, table->name.loc, table->entry->dc, CT_FALSE));
    pair->column = knl_get_column(DC_ENTITY(&table->entry->dc), pair->column_id);
    if (KNL_COLUMN_IS_ARRAY(pair->column)) {
        if (!is_array_subscript_correct(update_col->word.column.ss_start, update_col->word.column.ss_end)) {
            CT_SRC_THROW_ERROR(update_col->loc, ERR_SQL_SYNTAX_ERROR, "invalid array subscript");
            return CT_ERROR;
        }

        pair->ss_start = update_col->word.column.ss_start;
        pair->ss_end = update_col->word.column.ss_end;
    }
    return sql_generate_update_object(verif, pair, table, update_ctx);
}

static status_t sql_add_update_default_field(sql_stmt_t *stmt, sql_table_t *table, galist_t *pairs, uint32 natts,
    uint16 *add_count, uint32 *col_mask)
{
    uint32 i, j;
    knl_dictionary_t *dc = &table->entry->dc;
    knl_column_t *col = NULL;
    column_value_pair_t *pair = NULL;

    *add_count = 0;
    for (i = 0; i < natts; i++) {
        col = knl_get_column(dc->handle, i);
        if (KNL_COLUMN_INVISIBLE(col)) {
            continue;
        }

        if (KNL_COLUMN_IS_UPDATE_DEFAULT(col)) {
            for (j = 0; j < pairs->count; j++) {
                pair = (column_value_pair_t *)cm_galist_get(pairs, j);
                if (col->id == pair->column_id) {
                    break;
                }
            }

            if (j == pairs->count) {
                col_mask[*add_count] = col->id;
                (*add_count)++;
            }

            if (col->default_text.len != 0) {
                CT_RETURN_IFERR(sql_add_sequence_node(stmt, ((expr_tree_t *)col->default_expr)->root));
            }
        }
    }

    return CT_SUCCESS;
}

static status_t sql_update_column_value_pairs(sql_stmt_t *stmt, sql_table_t *table, galist_t *pairs)
{
    column_value_pair_t *pair = NULL;
    knl_column_t *col = NULL;
    expr_tree_t *expr = NULL;
    uint16 add_count = 0;
    uint32 *col_mask = NULL;
    knl_dictionary_t *dc = &table->entry->dc;
    uint32 natts = knl_get_column_count(dc->handle);

    if (!knl_has_update_default_col(dc->handle)) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_push(stmt, sizeof(uint32) * natts, (void **)&col_mask));
    if (sql_add_update_default_field(stmt, table, pairs, natts, &add_count, col_mask) != CT_SUCCESS) {
        CTSQL_POP(stmt);
        return CT_ERROR;
    }

    for (uint32 i = 0; i < add_count; i++) {
        col = knl_get_column(dc->handle, col_mask[i]);
        if (cm_galist_new(pairs, sizeof(column_value_pair_t), (pointer_t *)&pair) != CT_SUCCESS) {
            CTSQL_POP(stmt);
            return CT_ERROR;
        }

        if (sql_create_list(stmt, &pair->exprs) != CT_SUCCESS) {
            CTSQL_POP(stmt);
            return CT_ERROR;
        }

        if (sql_copy_str(stmt->context, col->name, (text_t *)&pair->column_name.value) != CT_SUCCESS) {
            CTSQL_POP(stmt);
            return CT_ERROR;
        }

        pair->column = col;
        pair->column_id = col->id;

        if (sql_build_column_expr(stmt, col, &pair->column_expr) != CT_SUCCESS) {
            CTSQL_POP(stmt);
            return CT_ERROR;
        }

        if (sql_build_default_reserved_expr(stmt, &expr) != CT_SUCCESS) {
            CTSQL_POP(stmt);
            return CT_ERROR;
        }

        if (cm_galist_insert(pair->exprs, expr) != CT_SUCCESS) {
            CTSQL_POP(stmt);
            return CT_ERROR;
        }
    }
    CTSQL_POP(stmt);
    return CT_SUCCESS;
}
// Verify update multi set pair
static status_t sql_static_check_multi_set_pair(sql_verifier_t *verif, column_value_pair_t *pair)
{
    expr_tree_t *expr = (expr_tree_t *)cm_galist_get(pair->exprs, 0);
    sql_select_t *select_ctx = (sql_select_t *)expr->root->value.v_obj.ptr;
    rs_column_t *rs_col = NULL;
    bool32 verified = select_ctx->first_query->rs_columns->count > 0;

    select_ctx->is_update_value = CT_TRUE;

    // already verified?
    if (!verified) {
        CT_RETURN_IFERR(sql_verify_expr(verif, expr));
    }

    // Columns in a multi set must equal to subquery rs count
    if (pair->rs_no > select_ctx->first_query->rs_columns->count) {
        CT_SRC_THROW_ERROR(expr->loc, ERR_SQL_SYNTAX_ERROR, "too many columns");
        return CT_ERROR;
    }

    rs_col = (rs_column_t *)cm_galist_get(select_ctx->first_query->rs_columns, pair->rs_no - 1);
    if (!var_datatype_matched(pair->column->datatype, rs_col->datatype)) {
        CT_SRC_ERROR_MISMATCH(TREE_LOC(expr), pair->column->datatype, rs_col->datatype);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_pair_cmp(const void *pair1, const void *pair2, int32 *result)
{
    uint32 id1, id2;

    CM_POINTER2(pair1, pair2);

    id1 = ((column_value_pair_t *)pair1)->column_id;
    id2 = ((column_value_pair_t *)pair2)->column_id;

    if (id1 == id2) {
        CT_THROW_ERROR(ERR_DUPLICATE_NAME, "column", ((column_value_pair_t *)pair1)->column->name);
        return CT_ERROR;
    }

    *result = id1 > id2 ? 1 : -1;
    return CT_SUCCESS;
}

static inline status_t sql_sort_pairs(galist_t *pairs)
{
    return cm_galist_sort(pairs, sql_pair_cmp);
}

status_t sql_verify_upd_object_pairs(sql_verifier_t *verif, sql_update_t *update_ctx)
{
    upd_object_t *upd_ob = NULL;

    for (uint32 i = 0; i < update_ctx->objects->count; i++) {
        upd_ob = (upd_object_t *)cm_galist_get(update_ctx->objects, i);
        if (sql_update_column_value_pairs(verif->stmt, upd_ob->table, upd_ob->pairs) != CT_SUCCESS) {
            return CT_ERROR;
        }
        CT_RETURN_IFERR(sql_sort_pairs(upd_ob->pairs));
    }
    return CT_SUCCESS;
}

status_t sql_verify_update_pairs(knl_handle_t session, sql_verifier_t *verif, sql_update_t *update_ctx)
{
    column_value_pair_t *pair = NULL;
    verif->tables = &update_ctx->query->tables;
    verif->excl_flags =
        SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_ROWID | SQL_EXCL_PRIOR | SQL_EXCL_WIN_SORT | SQL_EXCL_GROUPING;

    for (uint32 i = 0; i < update_ctx->pairs->count; i++) {
        pair = (column_value_pair_t *)cm_galist_get(update_ctx->pairs, i);
        if (sql_verify_update_pair(session, verif, pair, update_ctx) != CT_SUCCESS) {
            return CT_ERROR;
        }

        // Check pair in multi set
        if (PAIR_IN_MULTI_SET(pair)) {
            expr_tree_t *expr = NULL;
            expr_tree_t *next_expr = NULL;
            bool32 need_check = CT_TRUE;

            CT_RETURN_IFERR(sql_static_check_multi_set_pair(verif, pair));

            // Columns in a multi set must equal to subquery rs count
            expr = (expr_tree_t *)cm_galist_get(pair->exprs, 0);
            if (i != update_ctx->pairs->count - 1) {
                column_value_pair_t *next_pair = NULL;

                next_pair = (column_value_pair_t *)cm_galist_get(update_ctx->pairs, i + 1);
                next_expr = (expr_tree_t *)cm_galist_get(next_pair->exprs, 0);
                if (expr == next_expr) {
                    need_check = CT_FALSE;
                }
            }
            if (need_check &&
                pair->rs_no != ((sql_select_t *)expr->root->value.v_obj.ptr)->first_query->rs_columns->count) {
                CT_SRC_THROW_ERROR(expr->loc, ERR_SQL_SYNTAX_ERROR, "too many columns");
                return CT_ERROR;
            }
        } else {
            if (sql_static_check_dml_pair(verif, pair) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }
    return sql_verify_upd_object_pairs(verif, update_ctx);
}

static status_t sql_verify_update_return_columns(sql_verifier_t *verif, sql_update_t *update_ctx)
{
    if (update_ctx->ret_columns == NULL) {
        return CT_SUCCESS;
    }

    verif->tables = &update_ctx->query->tables;
    return sql_verify_return_columns(verif, update_ctx->ret_columns);
}

static status_t sql_verify_update_context(knl_handle_t session, sql_verifier_t *verif, sql_update_t *update_ctx)
{
    sql_query_t *query = update_ctx->query;

    CT_RETURN_IFERR(sql_verify_tables(verif, query));

    CT_RETURN_IFERR(sql_verify_query_where(verif, query));

    CT_RETURN_IFERR(sql_verify_query_joins(verif, query));

    CT_RETURN_IFERR(sql_verify_update_pairs(session, verif, update_ctx));

    CT_RETURN_IFERR(sql_verify_update_return_columns(verif, update_ctx));

    return CT_SUCCESS;
}

status_t sql_verify_update(sql_stmt_t *stmt, sql_update_t *update_ctx)
{
    sql_verifier_t verif = { 0 };
    verif.stmt = stmt;
    verif.context = stmt->context;
    verif.pl_dc_lst = update_ctx->pl_dc_lst;
    verif.do_expr_optmz = CT_TRUE;

    plc_get_verify_obj(stmt, &verif);
    CT_RETURN_IFERR(sql_verify_update_context(&stmt->session->knl_session, &verif, update_ctx));
    if (verif.has_ddm_col == CT_TRUE) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", the command references a redacted object");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
