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
 * ctsql_column_verifier.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/verifier/ctsql_column_verifier.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_select_verifier.h"
#include "ctsql_table_verifier.h"
#include "ctsql_expr_verifier.h"
#include "srv_instance.h"
#include "ctsql_table_func.h"
#include "dml_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t sql_verify_array_subscript(expr_node_t *node, knl_column_t *knl_col, var_column_t *v_col)
{
    if (KNL_COLUMN_IS_ARRAY(knl_col)) {
        if (!is_array_subscript_correct(node->word.column.ss_start, node->word.column.ss_end)) {
            CT_SRC_THROW_ERROR(node->loc, ERR_INVALID_SUBSCRIPT);
            return CT_ERROR;
        }

        v_col->ss_start = node->word.column.ss_start;
        v_col->ss_end = node->word.column.ss_end;
        if (VAR_COL_IS_ARRAY_ELEMENT(v_col)) {
            node->typmod.is_array = CT_FALSE;
            v_col->is_array = CT_FALSE;
        } else {
            node->typmod.is_array = CT_TRUE;
            v_col->is_array = CT_TRUE;
        }
    } else {
        if (node->word.column.ss_start != CT_INVALID_ID32) {
            CT_SRC_THROW_ERROR(node->loc, ERR_USE_WRONG_SUBSCRIPT, knl_col->name);
            return CT_ERROR;
        }

        v_col->is_array = CT_FALSE;
        v_col->ss_start = CT_INVALID_ID32;
        v_col->ss_end = CT_INVALID_ID32;
    }

    return CT_SUCCESS;
}

static status_t sql_verify_knl_column_in_knl_table(sql_verifier_t *verif, sql_table_t *table, expr_node_t *node,
    var_column_t *v_col, knl_column_t *knl_col)
{
    rs_column_t *rs_col = NULL;
    galist_t *rs_cols = NULL;

    if (table->type == VIEW_AS_TABLE) {
        rs_cols = table->select_ctx->first_query->rs_columns;
        if (v_col->col >= rs_cols->count) {
            CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "tmp_col_id(%u) < rs_columns->count(%u)", v_col->col,
                rs_cols->count);
            return CT_ERROR;
        }

        rs_col = (rs_column_t *)cm_galist_get(rs_cols, v_col->col);
        v_col->datatype = rs_col->datatype;
        if (!(verif->incl_flags & SQL_INCL_COND_COL)) {
            v_col->is_ddm_col = rs_col->v_col.is_ddm_col;
            verif->has_ddm_col = rs_col->v_col.is_ddm_col;
        }
        node->typmod = rs_col->typmod;
    } else {
        set_ddm_attr(verif, v_col, knl_col);
        v_col->datatype = knl_col->datatype;
        v_col->is_jsonb = KNL_COLUMN_IS_JSONB(knl_col);
        sql_typmod_from_knl_column(&node->typmod, knl_col);
    }

    return CT_SUCCESS;
}

static status_t sql_try_find_column_in_knl_table(sql_verifier_t *verif, sql_table_t *table, expr_node_t *node,
    text_t *column, bool32 *is_found)
{
    uint16 tmp_col_id;
    query_field_t query_fld;
    knl_column_t *knl_col = NULL;
    var_column_t *v_col = VALUE_PTR(var_column_t, &node->value);

    if (table->entry->dc.type == DICT_TYPE_UNKNOWN) {
        return CT_SUCCESS;
    }

    tmp_col_id = knl_get_column_id(&table->entry->dc, column);
    if (CT_INVALID_ID16 == tmp_col_id) {
        return CT_SUCCESS;
    }

    knl_col = knl_get_column(table->entry->dc.handle, tmp_col_id);
    if (KNL_COLUMN_INVISIBLE(knl_col)) {
        return CT_SUCCESS;
    }

    // add sequence from default value
    if (knl_col->default_text.len != 0) {
        CT_RETURN_IFERR(sql_add_sequence_node(verif->stmt, ((expr_tree_t *)knl_col->default_expr)->root));
    }

    v_col->tab = table->id;
    v_col->col = tmp_col_id;

    CT_RETURN_IFERR(sql_verify_knl_column_in_knl_table(verif, table, node, v_col, knl_col));

    if (table->project_col_array != NULL) {
        project_col_info_t *project_col_info = sql_get_project_info_col(table->project_col_array, v_col->col);
        project_col_info->col_name = column;
        project_col_info->col_name_has_quote = KNL_COLUMN_HAS_QUOTE(knl_col) ? CT_TRUE : CT_FALSE;
    }
    *is_found = CT_TRUE;

    /* if the column is an array filed, then verify the subscript */
    if (sql_verify_array_subscript(node, knl_col, v_col) != CT_SUCCESS) {
        return CT_ERROR;
    }

    SQL_SET_QUERY_FIELD_INFO(&query_fld, v_col->datatype, v_col->col, v_col->is_array, v_col->ss_start,
        v_col->ss_end);

    if (verif->incl_flags & SQL_INCL_COND_COL) {
        return sql_table_cache_cond_query_field(verif->stmt, table, &query_fld);
    }

    return sql_table_cache_query_field(verif->stmt, table, &query_fld);
}

static status_t sql_try_find_column_in_table_cast(sql_verifier_t *verif, sql_table_t *table, expr_node_t *node,
    var_column_t *v_col, text_t *column, bool32 *is_found)
{
    uint32 col_id = 0;
    query_field_t query_fld;
    *is_found = CT_FALSE;
    plv_collection_t *plv_col = NULL;
    plv_object_attr_t *attr = NULL;
    plv_col = (plv_collection_t *)table->func.args->next->root->udt_type;
    if (plv_col != NULL && plv_col->attr_type == UDT_OBJECT) {
        for (col_id = 0; col_id < plv_col->elmt_type->typdef.object.count; col_id++) {
            attr = udt_seek_obj_field_byid(&plv_col->elmt_type->typdef.object, col_id);
            if (cm_text_equal_ins(column, &attr->name)) {
                *is_found = CT_TRUE;
                break;
            }
        }
    } else {
        if (cm_text_str_equal_ins(column, table->func.desc->columns[col_id].name)) {
            *is_found = CT_TRUE;
        }
    }

    if (*is_found) {
        if (plv_col != NULL && plv_col->attr_type == UDT_SCALAR) {
            v_col->datatype = plv_col->type_mode.datatype;
            node->typmod = plv_col->type_mode;
        } else if (attr != NULL) {
            v_col->datatype = attr->scalar_field->type_mode.datatype;
            node->typmod = attr->scalar_field->type_mode;
        }
        v_col->tab = table->id;
        v_col->col = col_id;
        v_col->ancestor = 0;
        SQL_SET_QUERY_FIELD_INFO(&query_fld, v_col->datatype, v_col->col, v_col->is_array, v_col->ss_start,
            v_col->ss_end);
        CT_RETURN_IFERR(sql_table_cache_query_field(verif->stmt, table, &query_fld));
        return CT_SUCCESS;
    } else {
        CT_SRC_THROW_ERROR(node->loc, ERR_INVALID_COLUMN_NAME, T2S(column));
        return CT_ERROR;
    }
}

static status_t sql_try_find_column_in_func(sql_verifier_t *verif, sql_table_t *table, expr_node_t *node, text_t *column,
    bool32 *is_found)
{
    uint32 col_id;
    var_column_t *v_col = VALUE_PTR(var_column_t, &node->value);
    query_field_t query_fld;
    *is_found = CT_FALSE;
    if (IS_DYNAMIC_TBL_FUNC(table->func.desc)) {
        CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR,
            "specifying column is not allowed for dynamic table function");
        return CT_ERROR;
    }

    if (cm_text_str_equal_ins(&table->func.name, "CAST")) {
        return sql_try_find_column_in_table_cast(verif, table, node, v_col, column, is_found);
    }

    for (col_id = 0; col_id < table->func.desc->column_count; col_id++) {
        if (cm_text_str_equal_ins(column, table->func.desc->columns[col_id].name)) {
            *is_found = CT_TRUE;
            break;
        }
    }

    if (*is_found) {
        v_col->datatype = table->func.desc->columns[col_id].datatype;
        v_col->is_jsonb = KNL_COLUMN_IS_JSONB(&table->func.desc->columns[col_id]);
        sql_typmod_from_knl_column(&node->typmod, &table->func.desc->columns[col_id]);
        v_col->tab = table->id;
        v_col->col = col_id;
        v_col->ancestor = 0;
        SQL_SET_QUERY_FIELD_INFO(&query_fld, v_col->datatype, v_col->col, v_col->is_array, v_col->ss_start,
            v_col->ss_end);
        CT_RETURN_IFERR(sql_table_cache_query_field(verif->stmt, table, &query_fld));
        return CT_SUCCESS;
    } else {
        CT_SRC_THROW_ERROR(node->loc, ERR_INVALID_COLUMN_NAME, T2S(column));
        return CT_ERROR;
    }
}

static status_t sql_verify_array_col_in_subselect(rs_column_t *rs_col, expr_node_t *node, var_column_t *v_col)
{
    bool8 is_array = CT_FALSE;

    /* check if the subselect result set column is array type */
    if (rs_col->type == RS_COL_COLUMN) {
        v_col->is_ddm_col = rs_col->v_col.is_ddm_col;
        is_array = rs_col->v_col.is_array;
    } else {
        is_array = rs_col->expr->root->typmod.is_array;
    }

    if (is_array == CT_TRUE) {
        if (!is_array_subscript_correct(node->word.column.ss_start, node->word.column.ss_end)) {
            CT_SRC_THROW_ERROR(node->loc, ERR_INVALID_SUBSCRIPT);
            return CT_ERROR;
        }

        if (node->word.column.ss_start > 0 && node->word.column.ss_end == CT_INVALID_ID32) {
            /* single element, is not an array */
            v_col->is_array = CT_FALSE;
        } else {
            v_col->is_array = CT_TRUE;
        }

        v_col->ss_start = node->word.column.ss_start;
        v_col->ss_end = node->word.column.ss_end;
    } else {
        v_col->is_array = CT_FALSE;
        if (node->word.column.ss_start != CT_INVALID_ID32) {
            CT_SRC_THROW_ERROR(node->loc, ERR_USE_WRONG_SUBSCRIPT, T2S(&(rs_col->name)));
            return CT_ERROR;
        }
    }

    node->typmod.is_array = v_col->is_array;
    return CT_SUCCESS;
}

static inline status_t deal_query_field_in_subselect(sql_query_t *query)
{
    query_field_t *query_fld = NULL;
    bilist_node_t *node = NULL;
    sql_table_t *table = NULL;

    for (uint32 i = 0; i < query->tables.count; i++) {
        table = (sql_table_t *)sql_array_get(&query->tables, i);
        node = cm_bilist_head(&table->query_fields);
        for (; node != NULL; node = BINODE_NEXT(node)) {
            query_fld = BILIST_NODE_OF(query_field_t, node, bilist_node);
            if (CT_IS_LOB_TYPE(query_fld->datatype) || query_fld->is_array) {
                continue;
            }
            query_fld->is_cond_col = CT_TRUE;
        }
    }
    return CT_SUCCESS;
}

static status_t sql_try_find_column_in_subselect(sql_verifier_t *verif, sql_table_t *table, expr_node_t *node,
    text_t *column, bool32 *is_found)
{
    uint32 i;
    rs_column_t *rs_col = NULL;
    var_column_t *v_col = VALUE_PTR(var_column_t, &node->value);
    sql_query_t *query = table->select_ctx->first_query;
    query_field_t query_fld;

    for (i = 0; i < query->rs_columns->count; i++) {
        rs_col = (rs_column_t *)cm_galist_get(query->rs_columns, i);
        if (cm_text_equal(&rs_col->name, column)) {
            if (*is_found) {
                CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "column ambiguously defined");
                return CT_ERROR;
            }
            v_col->tab = table->id;
            v_col->col = i;
            v_col->datatype = rs_col->datatype;
            node->typmod = rs_col->typmod;
            *is_found = CT_TRUE;
            if (sql_verify_array_col_in_subselect(rs_col, node, v_col) != CT_SUCCESS) {
                return CT_ERROR;
            }
            if (v_col->is_ddm_col == CT_TRUE) {
                verif->has_ddm_col = CT_TRUE;
            }
            if (table->project_col_array != NULL) {
                project_col_info_t *project_col_info = sql_get_project_info_col(table->project_col_array, v_col->col);
                project_col_info->col_name_has_quote = CT_BIT_TEST(rs_col->rs_flag, RS_HAS_QUOTE) ? CT_TRUE : CT_FALSE;
                project_col_info->col_name = (rs_col->z_alias.len == 0) ? column : &rs_col->z_alias;
            }
            SQL_SET_QUERY_FIELD_INFO(&query_fld, v_col->datatype, v_col->col, v_col->is_array, v_col->ss_start,
                v_col->ss_end);
            CT_RETURN_IFERR(sql_table_cache_query_field(verif->stmt, table, &query_fld));
        }
    }

    if (*is_found) {
        CT_RETURN_IFERR(deal_query_field_in_subselect(query));
    }
    return CT_SUCCESS;
}

static status_t sql_try_find_column_in_json_table(sql_verifier_t *verif, sql_table_t *table, expr_node_t *node,
    text_t *column, bool32 *is_found)
{
    var_column_t *v_col = VALUE_PTR(var_column_t, &node->value);
    rs_column_t *rs_col = NULL;
    query_field_t query_fld;

    for (uint32 i = 0; i < table->json_table_info->columns.count; i++) {
        rs_col = (rs_column_t *)cm_galist_get(&table->json_table_info->columns, i);
        if (cm_text_equal(&rs_col->name, column)) {
            if (*is_found) {
                CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "column ambiguously defined");
                return CT_ERROR;
            }
            v_col->tab = table->id;
            v_col->col = i;
            v_col->datatype = rs_col->datatype;
            node->typmod = rs_col->typmod;
            *is_found = CT_TRUE;
            v_col->is_ddm_col = CT_FALSE;
            v_col->is_array = CT_FALSE;
            SQL_SET_QUERY_FIELD_INFO(&query_fld, v_col->datatype, v_col->col, v_col->is_array, v_col->ss_start,
                v_col->ss_end);
            if (verif->incl_flags & SQL_INCL_COND_COL) {
                CT_RETURN_IFERR(sql_table_cache_cond_query_field(verif->stmt, table, &query_fld));
            }
            CT_RETURN_IFERR(sql_table_cache_query_field(verif->stmt, table, &query_fld));
        }
    }
    return CT_SUCCESS;
}

static status_t sql_try_find_column(sql_verifier_t *verif, sql_table_t *table, expr_node_t *node, text_t *user,
    text_t *column, bool32 *is_found)
{
    if (table == NULL) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not find column:%s", T2S(column));
        return CT_ERROR;
    }
    *is_found = CT_FALSE;

    if (user->len > 0 && !cm_text_equal((text_t *)&table->user, user)) {
        return CT_SUCCESS;
    }

    switch (table->type) {
        case SUBSELECT_AS_TABLE:
        case WITH_AS_TABLE:
            return sql_try_find_column_in_subselect(verif, table, node, column, is_found);
        case FUNC_AS_TABLE:
            return sql_try_find_column_in_func(verif, table, node, column, is_found);
        case JSON_TABLE:
            return sql_try_find_column_in_json_table(verif, table, node, column, is_found);
        default:
            return sql_try_find_column_in_knl_table(verif, table, node, column, is_found);
    }
}

// search the column in the table to check whether this column is in this table
static status_t sql_search_column_with_local_table(sql_verifier_t *verif, expr_node_t *node, text_t *user, text_t *alias,
    text_t *column, bool32 *is_found)
{
    sql_table_t *table = NULL;

    CT_RETURN_IFERR(sql_search_table_local(verif, node, user, alias, &table, is_found));
    if (!(*is_found)) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_try_find_column(verif, table, node, user, column, is_found));
    if (!(*is_found)) {
        CT_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "invalid column name %s", T2S(column));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_search_column_with_parent_table(sql_verifier_t *verif, expr_node_t *node, text_t *user,
    text_t *alias, text_t *column, uint32 *level)
{
    sql_table_t *table = NULL;
    bool32 is_found = CT_FALSE;

    CT_RETURN_IFERR(sql_search_table_parent(verif, node, user, alias, &table, level, &is_found));
    if (!is_found) {
        CT_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "invalid table alias '%s'", T2S(alias));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_try_find_column(verif, table, node, user, column, &is_found));
    if (!is_found) {
        CT_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "invalid column name %s", T2S(column));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_search_column_with_table(sql_verifier_t *verif, expr_node_t *node, text_t *user, text_t *alias,
    text_t *column)
{
    uint32 level = 0;
    bool32 is_found = CT_FALSE;
    var_column_t *v_col = VALUE_PTR(var_column_t, &node->value);

    do {
        if (verif->tables != NULL || verif->table != NULL) {
            CT_RETURN_IFERR(sql_search_column_with_local_table(verif, node, user, alias, column, &is_found));
            if (is_found) {
                break;
            }
        }

        CT_RETURN_IFERR(sql_try_verify_noarg_func(verif, node, &is_found));
        if (is_found) {
            return CT_SUCCESS;
        }

        // reserved return false
        if (node->type == EXPR_NODE_RESERVED) {
            CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR,
                "Aggregate function does not support father child Association.");
            return CT_ERROR;
        }

        CT_RETURN_IFERR(sql_search_column_with_parent_table(verif, node, user, alias, column, &level));
        if ((level > 0 && (verif->excl_flags & SQL_EXCL_PARENT) != 0)) {
            CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR,
                "Aggregate function does not support father child Association.");
            return CT_ERROR;
        }
    } while (0);
    v_col->ancestor = level;

    if (level > 0) {
        verif->has_acstor_col = CT_TRUE;
    }
    return CT_SUCCESS;
}

static status_t sql_search_column_in_table_list(sql_verifier_t *verif, sql_array_t *tables, expr_node_t *node,
    text_t *user, text_t *column, bool32 *is_found)
{
    bool32 tmp_is_found = CT_FALSE;

    for (uint32 i = 0; i < tables->count; i++) {
        sql_table_t *tmp_table = (sql_table_t *)sql_array_get(tables, i);

        if (sql_try_find_column(verif, tmp_table, node, user, column, &tmp_is_found) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!tmp_is_found) {
            continue;
        }

        if (*is_found) {
            CT_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "column '%s' ambiguously defined", T2S(column));
            return CT_ERROR;
        }
        *is_found = CT_TRUE;
        if (verif->join_tab_id == CT_INVALID_ID32) {
            verif->join_tab_id = tmp_table->id;
        } else if (verif->join_tab_id != tmp_table->id) {
            verif->same_join_tab = CT_FALSE;
        }
    }
    return CT_SUCCESS;
}

static status_t sql_search_column_local(sql_verifier_t *verif, expr_node_t *node, text_t *user, text_t *column,
    bool32 *is_found)
{
    if (verif->tables == NULL) { // for non select
        return sql_try_find_column(verif, verif->table, node, user, column, is_found);
    }

    return sql_search_column_in_table_list(verif, verif->tables, node, user, column, is_found);
}

static status_t sql_search_column_parent(sql_verifier_t *verif, expr_node_t *node, text_t *user, text_t *column,
    bool32 *is_found, uint32 *level)
{
    sql_select_t *prev_ctx = verif->select_ctx;
    sql_verifier_t *parent_verf = verif->parent;

    if (prev_ctx == NULL) {
        return CT_SUCCESS;
    }
    verif->incl_flags |= SQL_INCL_PRNT_OR_ANCSTR;

    sql_query_t *parent = prev_ctx->parent;

    while (parent_verf != NULL && parent != NULL) {
        (*level)++;
        if (parent_verf->tables != NULL) {
            CT_RETURN_IFERR(sql_search_column_in_table_list(verif, parent_verf->tables, node, user, column, is_found));
        }
        if (*is_found || parent->owner == NULL) {
            if (*is_found) {
                CT_RETURN_IFERR(sql_add_parent_refs(verif->stmt, prev_ctx->parent_refs, NODE_TAB(node), node));
            }
            break;
        }
        prev_ctx = parent->owner;
        parent = prev_ctx->parent;
        parent_verf = parent_verf->parent;
    }
    sql_set_ancestor_level(verif->select_ctx, *level);
    return CT_SUCCESS;
}

static status_t sql_search_column(sql_verifier_t *verif, expr_node_t *node, text_t *user, text_t *column)
{
    uint32 level = 0;
    bool32 is_found = CT_FALSE;
    var_column_t *v_col = VALUE_PTR(var_column_t, &node->value);

    do {
        if (verif->table != NULL || verif->tables != NULL) {
            CT_RETURN_IFERR(sql_search_column_local(verif, node, user, column, &is_found));
            if (is_found) {
                break;
            }
        }

        CT_RETURN_IFERR(sql_try_verify_noarg_func(verif, node, &is_found));
        if (is_found) {
            return CT_SUCCESS;
        }

        // reserved return false
        if (node->type == EXPR_NODE_RESERVED) {
            CT_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "invalid column name '%s'", T2S(column));
            return CT_ERROR;
        }

        CT_RETURN_IFERR(sql_search_column_parent(verif, node, user, column, &is_found, &level));

        if (!is_found) {
            CT_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "invalid column name '%s'", T2S(column));
            return CT_ERROR;
        }
    } while (0);

    v_col->ancestor = level;

    if (level > 0) {
        verif->has_acstor_col = CT_TRUE;
    }

    return CT_SUCCESS;
}

static status_t sql_search_column_in_entity_obj(sql_stmt_t *stmt, sql_verifier_t *verif, expr_node_t *node,
    text_t *column_name)
{
    uint32 i;
    knl_column_t *column = NULL;
    var_column_t *v_col = VALUE_PTR(var_column_t, &node->value);
    v_col->ancestor = 0;

    dc_entity_t *entity = (dc_entity_t *)verif->dc_entity;
    text_t temp_col_name;

    for (i = 0; i < entity->table.desc.column_count; i++) {
        column = knl_get_column(verif->dc_entity, i);
        temp_col_name.str = column->name;
        temp_col_name.len = (uint32)strlen(column->name);
        if (!KNL_COLUMN_IS_DELETED(column) && !cm_compare_text(column_name, &temp_col_name)) {
            v_col->tab = 0;
            v_col->col = i;
            v_col->datatype = column->datatype;
            v_col->is_jsonb = KNL_COLUMN_IS_JSONB(column);
            sql_typmod_from_knl_column(&node->typmod, column);
            break;
        }
    }

    if (i == entity->table.desc.column_count) {
        CT_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "invalid column name '%s'", T2S(column_name));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_search_column_in_table_def(sql_stmt_t *stmt, sql_verifier_t *verif, knl_table_def_t *table,
    expr_node_t *node, text_t *column_name)
{
    uint32 i;
    knl_column_def_t *col_def = NULL;
    var_column_t *v_col = VALUE_PTR(var_column_t, &node->value);
    v_col->ancestor = 0;

    for (i = 0; i < table->columns.count; i++) {
        col_def = (knl_column_def_t *)cm_galist_get(&table->columns, i);
        if (!cm_compare_text(column_name, &col_def->name)) {
            v_col->tab = 0;
            v_col->col = i;
            v_col->datatype = col_def->datatype;
            node->typmod = col_def->typmod;
            break;
        }
    }

    if (i == table->columns.count) {
        CT_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "invalid column name '%s'", T2S(column_name));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_search_column_in_kernel_tab(sql_stmt_t *stmt, sql_verifier_t *verif, knl_column_def_t *column,
    expr_node_t *node, text_t *column_name)
{
    uint16 tmp_col_id;
    var_column_t *v_col = VALUE_PTR(var_column_t, &node->value);
    knl_column_t *knl_col = NULL;
    sql_table_entry_t *table = (sql_table_entry_t *)cm_galist_get(stmt->context->tables, 0);

    v_col->tab = 0;
    tmp_col_id = knl_get_column_id(&table->dc, column_name);
    if (column != NULL) {
        if (CT_INVALID_ID16 == tmp_col_id) {
            tmp_col_id = knl_get_column_count(table->dc.handle) + column->col_id;
        }
        v_col->col = tmp_col_id;
        v_col->datatype = column->datatype;
        node->typmod = column->typmod;
    } else {
        tmp_col_id = knl_get_column_id(&table->dc, column_name);
        if (CT_INVALID_ID16 == tmp_col_id) {
            CT_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "invalid column name '%s'", T2S(column_name));
            return CT_ERROR;
        }
        knl_col = knl_get_column(table->dc.handle, tmp_col_id);
        v_col->col = tmp_col_id;
        if (verif->typmode == NULL) {
            v_col->datatype = knl_col->datatype;
            node->datatype = knl_col->datatype;
            node->size = knl_col->size;
            node->typmod.is_array = KNL_COLUMN_IS_ARRAY(knl_col);
        } else {
            v_col->datatype = verif->typmode->datatype;
            node->datatype = verif->typmode->datatype;
            node->size = verif->typmode->size;
            // function index will not indexed on array filed
            node->typmod.is_array = CT_FALSE;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_search_column_with_check_cons(sql_verifier_t *verif, expr_node_t *node, text_t *user, text_t *alias,
    text_t *column_name)
{
    status_t status;
    knl_column_def_t *column = verif->column;
    knl_table_def_t *table = verif->table_def;
    sql_stmt_t *stmt = verif->stmt;
    sql_context_t *context = verif->context;

    if (column != NULL) {
        if (!CM_IS_EMPTY(user) || !CM_IS_EMPTY(alias) || cm_compare_text(column_name, &column->name)) {
            CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR,
                "inline constraint can not reference with other column");
            return CT_ERROR;
        }
    }

    switch (context->type) {
        case CTSQL_TYPE_CREATE_TABLE:
        case CTSQL_TYPE_CREATE_DISTRIBUTE_RULE:
            status = sql_search_column_in_table_def(stmt, verif, table, node, column_name);
            break;
        case CTSQL_TYPE_ALTER_TABLE:
        case CTSQL_TYPE_CREATE_INDEX:
        case CTSQL_TYPE_CREATE_INDEXES:
            status = sql_search_column_in_kernel_tab(stmt, verif, column, node, column_name);
            break;
        case CTSQL_TYPE_CREATE_CHECK_FROM_TEXT:
            status = sql_search_column_in_entity_obj(stmt, verif, node, column_name);
            break;
        default:
            CT_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "invalid sql type (%d)", context->type);
            return CT_ERROR;
    }

    if (status == CT_SUCCESS) {
        node->type = EXPR_NODE_DIRECT_COLUMN;
    }
    return status;
}

/*
 * if the sequence appeared in the target list of a subquery or the subset of a union query,
 * report an error
 */
static status_t sql_verify_sequence_in_right_place(sql_verifier_t *verif, expr_node_t *node)
{
    sql_select_t *select_ctx = verif->select_ctx;
    bool32 wrong_place = CT_FALSE;

    if ((node->type != EXPR_NODE_SEQUENCE) || (select_ctx == NULL)) {
        return CT_SUCCESS;
    }

    wrong_place = (bool32)((select_ctx->type == SELECT_AS_TABLE) || (select_ctx->type == SELECT_AS_LIST) ||
        (select_ctx->type == SELECT_AS_VARIANT));
    if (!wrong_place) {
        if ((select_ctx->type == SELECT_AS_RESULT) && (select_ctx->chain.count > 0)) {
            uint32 i;
            select_node_t *select_node = NULL;

            for (i = 0, select_node = select_ctx->chain.first; i < select_ctx->chain.count; i++) {
                if ((select_node->type == SELECT_NODE_UNION) || (select_node->type == SELECT_NODE_UNION_ALL) ||
                    (select_node->type == SELECT_NODE_MINUS) || (select_node->type == SELECT_NODE_INTERSECT) ||
                    (select_node->type == SELECT_NODE_INTERSECT_ALL) || (select_node->type == SELECT_NODE_EXCEPT_ALL) ||
                    (select_node->type == SELECT_NODE_EXCEPT)) {
                    wrong_place = CT_TRUE;
                    break;
                }
                select_node = select_node->next;
            }
        }
    }

    if (wrong_place) {
        CT_SRC_THROW_ERROR(node->loc, ERR_SEQUENCE_NOT_ALLOWED);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_try_verify_column(sql_verifier_t *verif, expr_node_t *node)
{
    bool32 result = CT_FALSE;
    sql_text_t *user = NULL;
    sql_text_t *table = NULL;
    column_word_t *col = NULL;

    if ((verif->excl_flags & SQL_EXCL_COLUMN) != 0) {
        CT_RETURN_IFERR(sql_try_verify_noarg_func(verif, node, &result));
        if (result) {
            return CT_SUCCESS;
        }
        CT_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "invalid column name '%s'",
            T2S(&node->word.column.name.value));
        return CT_ERROR;
    }

    col = &node->word.column;
    user = &col->user;
    table = &col->table;

    if (verif->is_check_cons) {
        return sql_search_column_with_check_cons(verif, node, &user->value, &table->value, &col->name.value);
    }

    if (table->len > 0) {
        CT_RETURN_IFERR(sql_search_column_with_table(verif, node, &user->value, &table->value, &col->name.value));
    } else {
        CT_RETURN_IFERR(sql_search_column(verif, node, &user->value, &col->name.value));
    }

    return CT_SUCCESS;
}

status_t sql_verify_column_expr(sql_verifier_t *verif, expr_node_t *node)
{
    column_word_t *col = NULL;
    bool32 result = CT_FALSE;

    /* verify dbms const, such as DBE_STATS.AUTO_SAMPLE_SIZE */
    CT_RETURN_IFERR(sql_try_verify_dbmsconst(verif, node, &result));
    if (result) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_try_verify_sequence(verif, node, &result));
    if (result) {
        CT_RETURN_IFERR(sql_verify_sequence_in_right_place(verif, node));
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_try_verify_rowid(verif, node, &result));
    if (result) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_try_verify_rowscn(verif, node, &result));
    if (result) {
        return CT_SUCCESS;
    }

    if (result) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_try_verify_column(verif, node));

    col = &node->word.column;
    if (verif->merge_insert_status != SQL_MERGE_INSERT_NONE && node->type != EXPR_NODE_USER_FUNC &&
        node->value.v_col.tab == 0) {
        if (verif->merge_insert_status == SQL_MERGE_INSERT_VALUES) {
            CT_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "invalid column in the INSERT VALUES clause: %s",
                T2S(&col->name.value));
        } else {
            CT_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "invalid column in the INSERT WHERE clause: %s",
                T2S(&col->name.value));
        }
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_match_group_columns(sql_stmt_t *stmt, sql_query_t *query, rs_column_t *rs_col)
{
    uint32 i, j;
    group_set_t *group_set = NULL;
    expr_tree_t *group_expr = NULL;

    if (query->group_sets->count == 0) {
        return CT_SUCCESS;
    }

    if (rs_col->v_col.ancestor > 0) {
        return CT_SUCCESS;
    }

    for (i = 0; i < query->group_sets->count; i++) {
        group_set = (group_set_t *)cm_galist_get(query->group_sets, i);
        for (j = 0; j < group_set->items->count; j++) {
            group_expr = (expr_tree_t *)cm_galist_get(group_set->items, j);
            if (group_expr->root->type != EXPR_NODE_COLUMN || VAR_ANCESTOR(&group_expr->root->value) > 0) {
                continue;
            }

            if (rs_col->v_col.tab == EXPR_TAB(group_expr) && rs_col->v_col.col == EXPR_COL(group_expr) &&
                rs_col->v_col.ss_start == group_expr->root->value.v_col.ss_start &&
                rs_col->v_col.ss_end == group_expr->root->value.v_col.ss_end) {
                if (sql_alloc_mem(stmt->context, sizeof(expr_tree_t), (void **)&rs_col->expr) != CT_SUCCESS) {
                    return CT_ERROR;
                }
                rs_col->expr->owner = stmt->context;

                if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&rs_col->expr->root) != CT_SUCCESS) {
                    return CT_ERROR;
                }

                rs_col->type = RS_COL_CALC;
                rs_col->expr->root->typmod = rs_col->typmod;
                return sql_set_group_expr_node(stmt, rs_col->expr->root, j, i, 0, group_expr->root);
            }
        }
    }

    CT_THROW_ERROR(ERR_EXPR_NOT_IN_GROUP_LIST);
    return CT_ERROR;
}

static inline void sql_set_rs_col_array_subscript(rs_column_t *rs_column, rs_column_t *sub_column)
{
    if (rs_column->v_col.is_array) {
        if (sub_column->v_col.ss_end != CT_INVALID_ID32 && sub_column->v_col.ss_start != CT_INVALID_ID32) {
            rs_column->v_col.ss_start = 1; // the subscript of mid rs array should start from 1
            rs_column->v_col.ss_end = sub_column->v_col.ss_end - sub_column->v_col.ss_start + 1;
        } else {
            rs_column->v_col.ss_start = sub_column->v_col.ss_start;
            rs_column->v_col.ss_end = sub_column->v_col.ss_end;
        }
    } else {
        rs_column->v_col.ss_start = CT_INVALID_ID32;
        rs_column->v_col.ss_end = CT_INVALID_ID32;
    }
}

static status_t sql_extract_subselect_columns(sql_verifier_t *verif, sql_query_t *query, sql_table_t *table,
    expr_node_t *node)
{
    uint32 i;
    rs_column_t *rs_col = NULL;
    rs_column_t *sub_column = NULL;
    galist_t *sub_columns = NULL;
    query_field_t query_fld;

    CM_ASSERT(table != NULL);
    sub_columns = table->select_ctx->first_query->rs_columns;
    for (i = 0; i < sub_columns->count; i++) {
        sub_column = (rs_column_t *)cm_galist_get(sub_columns, i);
        if (CT_IS_LOB_TYPE(sub_column->datatype) && ((verif->excl_flags & SQL_EXCL_LOB_COL) != 0)) {
            CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected lob column occurs");
            return CT_ERROR;
        }

        if (cm_galist_new(query->rs_columns, sizeof(rs_column_t), (void **)&rs_col) != CT_SUCCESS) {
            return CT_ERROR;
        }

        rs_col->type = RS_COL_COLUMN;
        rs_col->name = sub_column->name;
        rs_col->z_alias = sub_column->z_alias;
        rs_col->typmod = sub_column->typmod;
        rs_col->v_col.datatype = sub_column->datatype;
        rs_col->v_col.tab = table->id;
        rs_col->v_col.col = i;
        rs_col->rs_flag = sub_column->rs_flag;
        CT_BIT_SET(rs_col->rs_flag, RS_SINGLE_COL);

        if (sub_column->type == RS_COL_CALC) {
            rs_col->v_col.is_array = sub_column->expr->root->typmod.is_array;
            rs_col->v_col.ss_start = CT_INVALID_ID32;
            rs_col->v_col.ss_end = CT_INVALID_ID32;
        } else {
            rs_col->v_col.is_array = sub_column->v_col.is_array;
            rs_col->v_col.is_jsonb = sub_column->v_col.is_jsonb;
            sql_set_rs_col_array_subscript(rs_col, sub_column);
        }

        SQL_SET_QUERY_FIELD_INFO(&query_fld, rs_col->v_col.datatype, rs_col->v_col.col,
            rs_col->v_col.is_array, rs_col->v_col.ss_start, rs_col->v_col.ss_end);
        CT_RETURN_IFERR(sql_table_cache_query_field(verif->stmt, table, &query_fld));
    }

    return CT_SUCCESS;
}

static status_t sql_extract_table_column(sql_verifier_t *verif, rs_column_t *rs_col, sql_table_t *table,
    knl_column_t *knl_col, uint32 col_id, bool32 always_null)
{
    galist_t *sub_columns = NULL;
    rs_column_t *sub_col = NULL;
    project_col_info_t *project_col_info = NULL;

    rs_col->type = RS_COL_COLUMN;
    rs_col->name.str = knl_col->name;
    rs_col->name.len = (uint32)strlen(knl_col->name);
    rs_col->v_col.tab = table->id;
    rs_col->v_col.col = col_id;
    set_ddm_attr(verif, &rs_col->v_col, knl_col);
    rs_col->v_col.is_array = KNL_COLUMN_IS_ARRAY(knl_col);
    rs_col->v_col.is_jsonb = KNL_COLUMN_IS_JSONB(knl_col);
    rs_col->v_col.ss_start = CT_INVALID_ID32;
    rs_col->v_col.ss_end = CT_INVALID_ID32;

    if (table->type == VIEW_AS_TABLE) {
        sub_columns = table->select_ctx->first_query->rs_columns;
        if (col_id >= sub_columns->count) {
            CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "i(%u) < sub_columns->count(%u)", col_id, sub_columns->count);
            return CT_ERROR;
        }
        sub_col = (rs_column_t *)cm_galist_get(sub_columns, col_id);

        rs_col->typmod = sub_col->typmod;
        rs_col->v_col.datatype = sub_col->datatype;
        rs_col->rs_flag = sub_col->rs_flag;
    } else {
        CT_BIT_RESET(rs_col->rs_flag, RS_EXIST_ALIAS);
        RS_SET_FLAG(always_null || knl_col->nullable, rs_col, RS_NULLABLE);
        sql_typmod_from_knl_column(&rs_col->typmod, knl_col);
        rs_col->v_col.datatype = knl_col->datatype;
    }

    RS_SET_FLAG(KNL_COLUMN_HAS_QUOTE(knl_col), rs_col, RS_HAS_QUOTE);
    RS_SET_FLAG(KNL_COLUMN_IS_SERIAL(knl_col), rs_col, RS_IS_SERIAL);
    CT_BIT_SET(rs_col->rs_flag, RS_SINGLE_COL);
    project_col_info = sql_get_project_info_col(table->project_col_array, col_id);
    project_col_info->col_name = (rs_col->z_alias.len == 0) ? &rs_col->name : &rs_col->z_alias;
    project_col_info->col_name_has_quote = CT_BIT_TEST(rs_col->rs_flag, RS_HAS_QUOTE) ? CT_TRUE : CT_FALSE;

    return CT_SUCCESS;
}

static status_t sql_extract_table_columns(sql_verifier_t *verif, sql_query_t *query, sql_table_t *table,
    expr_node_t *node)
{
    uint32 i, cols;
    knl_column_t *knl_col = NULL;
    rs_column_t *rs_col = NULL;
    bool32 always_null = verif->select_ctx->root->type != SELECT_NODE_QUERY;

    query_field_t query_fld;
    CM_ASSERT(table != NULL);
    cols = knl_get_column_count(table->entry->dc.handle);

    // for: select * from tab;
    if ((query->tables.count == 1) && (query->columns->count == 1) && (query->ssa.count == 0)) {
        table->ret_full_fields = CT_TRUE;
    }

    for (i = 0; i < cols; i++) {
        knl_col = knl_get_column(table->entry->dc.handle, i);
        if (KNL_COLUMN_INVISIBLE(knl_col)) {
            continue;
        }

        if (CT_IS_LOB_TYPE(knl_col->datatype) && ((verif->excl_flags & SQL_EXCL_LOB_COL) != 0)) {
            CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected lob column occurs");
            return CT_ERROR;
        }

        if (cm_galist_new(query->rs_columns, sizeof(rs_column_t), (void **)&rs_col) != CT_SUCCESS) {
            return CT_ERROR;
        }

        CT_RETURN_IFERR(sql_extract_table_column(verif, rs_col, table, knl_col, i, always_null));

        SQL_SET_QUERY_FIELD_INFO(&query_fld, rs_col->v_col.datatype, rs_col->v_col.col, rs_col->v_col.is_array,
            rs_col->v_col.ss_start, rs_col->v_col.ss_end);
        CT_RETURN_IFERR(sql_table_cache_query_field(verif->stmt, table, &query_fld));
    }
    return CT_SUCCESS;
}

static status_t sql_extract_func_normal_column(sql_verifier_t *verif, sql_query_t *query, sql_table_t *table,
    knl_dictionary_t *dc, uint32 col)
{
    rs_column_t *rs_col = NULL;
    knl_column_t *knl_col = NULL;
    query_field_t query_fld;
    bool32 always_null = verif->select_ctx->root->type != SELECT_NODE_QUERY;

    knl_col = knl_get_column(dc->handle, col);
    if (KNL_COLUMN_INVISIBLE(knl_col)) {
        table->has_hidden_columns = CT_TRUE;
        return CT_SUCCESS;
    }

    if (CT_IS_LOB_TYPE(knl_col->datatype) && ((verif->excl_flags & SQL_EXCL_LOB_COL) != 0)) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "unexpected lob column occurs");
        return CT_ERROR;
    }

    if (cm_galist_new(query->rs_columns, sizeof(rs_column_t), (void **)&rs_col) != CT_SUCCESS) {
        return CT_ERROR;
    }

    rs_col->type = RS_COL_COLUMN;
    rs_col->name.str = knl_col->name;
    rs_col->name.len = (uint32)strlen(knl_col->name);
    rs_col->v_col.tab = table->id;
    rs_col->v_col.col = col;
    rs_col->v_col.is_array = KNL_COLUMN_IS_ARRAY(knl_col);
    rs_col->v_col.is_jsonb = KNL_COLUMN_IS_JSONB(knl_col);
    rs_col->v_col.ss_start = CT_INVALID_ID32;
    rs_col->v_col.ss_end = CT_INVALID_ID32;
    CT_BIT_SET(rs_col->rs_flag, RS_SINGLE_COL);
    CT_BIT_RESET(rs_col->rs_flag, RS_EXIST_ALIAS);
    RS_SET_FLAG(always_null || knl_col->nullable, rs_col, RS_NULLABLE);
    sql_typmod_from_knl_column(&rs_col->typmod, knl_col);

    rs_col->v_col.datatype = knl_col->datatype;
    SQL_SET_QUERY_FIELD_INFO(&query_fld, rs_col->v_col.datatype, rs_col->v_col.col, rs_col->v_col.is_array,
        rs_col->v_col.ss_start, rs_col->v_col.ss_end);
    return sql_table_cache_query_field(verif->stmt, table, &query_fld);
}

status_t sql_extract_func_normal_columns(sql_verifier_t *verif, sql_query_t *query, sql_table_t *table,
    expr_node_t *node)
{
    knl_dictionary_t dc;
    if (knl_open_dc(KNL_SESSION(verif->stmt), &table->user.value, &table->name.value, &dc) != CT_SUCCESS) {
        sql_check_user_priv(verif->stmt, &table->user.value);
        return CT_ERROR;
    }
    if (dc.type != DICT_TYPE_TABLE && dc.type != DICT_TYPE_TABLE_NOLOGGING) {
        knl_close_dc(&dc);
        CT_THROW_ERROR(ERR_INVALID_TABFUNC_1ST_ARG);
        return CT_ERROR;
    }

    uint32 cols = knl_get_column_count(dc.handle);
    table->has_hidden_columns = CT_FALSE;
    for (uint32 i = 0; i < cols; i++) {
        if (sql_extract_func_normal_column(verif, query, table, &dc, i) != CT_SUCCESS) {
            cm_set_error_loc(node->loc);
            knl_close_dc(&dc);
            return CT_ERROR;
        }
    }
    knl_close_dc(&dc);
    return CT_SUCCESS;
}

static status_t sql_generate_object_rs_col(sql_verifier_t *verif, plv_object_attr_t *attr, rs_column_t *rs_col,
    expr_node_t *node)
{
    if (attr->type != UDT_SCALAR) {
        CT_THROW_ERROR(ERR_PLSQL_VALUE_ERROR_FMT, "the 2nd-arg's data type in cast func is not supported");
        return CT_ERROR;
    }
    if (CT_IS_LOB_TYPE(attr->scalar_field->type_mode.datatype) && ((verif->excl_flags & SQL_EXCL_LOB_COL) != 0)) {
        CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected lob column occurs");
        return CT_ERROR;
    }
    rs_col->name.str = attr->name.str;
    rs_col->name.len = attr->name.len;
    RS_SET_FLAG(attr->nullable, rs_col, RS_NULLABLE);
    rs_col->typmod = attr->scalar_field->type_mode;
    return CT_SUCCESS;
}

static status_t sql_generate_kernel_rs_col(sql_verifier_t *verif, knl_column_t *knl_col, rs_column_t *rs_col,
    expr_node_t *node)
{
    if (CT_IS_LOB_TYPE(knl_col->datatype) && ((verif->excl_flags & SQL_EXCL_LOB_COL) != 0)) {
        CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected lob column occurs");
        return CT_ERROR;
    }
    RS_SET_FLAG(knl_col->nullable, rs_col, RS_NULLABLE);
    rs_col->name.str = knl_col->name;
    rs_col->name.len = (uint32)strlen(knl_col->name);
    return CT_SUCCESS;
}

status_t sql_extract_func_columns_object(sql_verifier_t *verif, sql_query_t *query, sql_table_t *table,
    expr_node_t *node, plv_collection_t *plv_col)
{
    uint32 cols = 1; // cast collection with scalar only has one row
    rs_column_t *rs_col = NULL;
    knl_column_t *knl_col = NULL;
    query_field_t query_fld;
    plv_object_t *object = NULL;
    if (plv_col->attr_type == UDT_OBJECT) {
        object = &plv_col->elmt_type->typdef.object;
        cols = object->count;
    }

    for (uint32 i = 0; i < cols; i++) {
        CT_RETURN_IFERR(cm_galist_new(query->rs_columns, sizeof(rs_column_t), (void **)&rs_col));
        rs_col->type = RS_COL_COLUMN;
        CT_BIT_SET(rs_col->rs_flag, RS_SINGLE_COL);
        CT_BIT_RESET(rs_col->rs_flag, RS_EXIST_ALIAS);
        if (object != NULL) {
            plv_object_attr_t *attr = udt_seek_obj_field_byid(object, i);
            CT_RETURN_IFERR(sql_generate_object_rs_col(verif, attr, rs_col, node));
        } else {
            knl_col = &table->func.desc->columns[i];
            CT_RETURN_IFERR(sql_generate_kernel_rs_col(verif, knl_col, rs_col, node));
            rs_col->typmod = plv_col->type_mode;
        }
        if (query->owner->root->type != SELECT_NODE_QUERY) {
            RS_SET_FLAG(CT_TRUE, rs_col, RS_NULLABLE);
        }
        rs_col->v_col.datatype = rs_col->typmod.datatype;
        rs_col->v_col.tab = table->id;
        rs_col->v_col.col = i;
        SQL_SET_QUERY_FIELD_INFO(&query_fld, rs_col->v_col.datatype, rs_col->v_col.col, rs_col->v_col.is_array,
            rs_col->v_col.ss_start, rs_col->v_col.ss_end);
        CT_RETURN_IFERR(sql_table_cache_query_field(verif->stmt, table, &query_fld));
    }
    return CT_SUCCESS;
}

status_t sql_extract_cast_func_columns(sql_verifier_t *verif, sql_query_t *query, sql_table_t *table, expr_node_t *node)
{
    table_func_t *func = &table->func;
    expr_tree_t *arg2 = NULL;
    arg2 = func->args->next;
    if (arg2->root->datatype != CT_TYPE_COLLECTION) {
        // 2 indicates the second parameter
        CT_THROW_ERROR(ERR_FUNC_ARGUMENT_WRONG_TYPE, 2, "global collection");
        return CT_ERROR;
    }
    plv_collection_t *plv_col = (plv_collection_t *)arg2->root->udt_type;
    return sql_extract_func_columns_object(verif, query, table, node, plv_col);
}

status_t sql_extract_func_columns_core(sql_verifier_t *verif, sql_query_t *query, sql_table_t *table, expr_node_t *node)
{
    uint32 i, cols;
    knl_column_t *knl_col = NULL;
    rs_column_t *rs_col = NULL;
    bool32 always_null = query->owner->root->type != SELECT_NODE_QUERY;
    query_field_t query_fld;
    cols = table->func.desc->column_count;
    for (i = 0; i < cols; i++) {
        knl_col = &table->func.desc->columns[i];

        if (CT_IS_LOB_TYPE(knl_col->datatype) && ((verif->excl_flags & SQL_EXCL_LOB_COL) != 0)) {
            CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected lob column occurs");
            return CT_ERROR;
        }

        if (cm_galist_new(query->rs_columns, sizeof(rs_column_t), (void **)&rs_col) != CT_SUCCESS) {
            return CT_ERROR;
        }

        rs_col->type = RS_COL_COLUMN;
        rs_col->name.str = knl_col->name;
        rs_col->name.len = (uint32)strlen(knl_col->name);
        CT_BIT_SET(rs_col->rs_flag, RS_SINGLE_COL);
        CT_BIT_RESET(rs_col->rs_flag, RS_EXIST_ALIAS);
        RS_SET_FLAG(always_null || knl_col->nullable, rs_col, RS_NULLABLE);
        rs_col->v_col.is_jsonb = KNL_COLUMN_IS_JSONB(knl_col);
        sql_typmod_from_knl_column(&rs_col->typmod, knl_col);

        if (cm_text_str_equal(&table->func.name, "CAST")) {
            plv_collection_t *plv_col = (plv_collection_t *)table->func.args->next->root->udt_type;
            rs_col->v_col.datatype = plv_col->type_mode.datatype;
        } else {
            rs_col->v_col.datatype = knl_col->datatype;
        }
        rs_col->v_col.tab = table->id;
        rs_col->v_col.col = i;
        SQL_SET_QUERY_FIELD_INFO(&query_fld, rs_col->v_col.datatype, rs_col->v_col.col, rs_col->v_col.is_array,
            rs_col->v_col.ss_start, rs_col->v_col.ss_end);
        CT_RETURN_IFERR(sql_table_cache_query_field(verif->stmt, table, &query_fld));
    }
    return CT_SUCCESS;
}

status_t sql_extract_func_columns(sql_verifier_t *verif, sql_query_t *query, sql_table_t *table, expr_node_t *node)
{
    text_t name = { "CAST", 4 };

    CM_ASSERT(table != NULL);
    // Special Implement for cast table function using in PL
    if (cm_compare_text_ins(&table->func.name, &name) == 0) {
        return sql_extract_cast_func_columns(verif, query, table, node);
    }
    // Implementing a common Table query using table function
    if (IS_DYNAMIC_TBL_FUNC(table->func.desc)) {
        return sql_extract_func_normal_columns(verif, query, table, node);
    }
    return sql_extract_func_columns_core(verif, query, table, node);
}

static status_t sql_extract_json_table_columns(sql_verifier_t *verif, sql_query_t *query, sql_table_t *table,
    expr_node_t *node)
{
    rs_column_t *table_column = NULL;
    rs_column_t *query_col = NULL;
    query_field_t query_fld;

    for (uint32 i = 0; i < table->json_table_info->columns.count; i++) {
        table_column = (rs_column_t *)cm_galist_get(&table->json_table_info->columns, i);
        if (CT_IS_LOB_TYPE(table_column->datatype) && (verif->excl_flags & SQL_EXCL_LOB_COL)) {
            CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected lob column occurs");
            return CT_ERROR;
        }
        CT_RETURN_IFERR(cm_galist_new(query->rs_columns, sizeof(rs_column_t), (void **)&query_col));
        query_col->z_alias = table_column->z_alias;
        query_col->typmod = table_column->typmod;
        query_col->name = table_column->name;
        query_col->rs_flag = table_column->rs_flag;
        query_col->type = RS_COL_COLUMN;
        query_col->v_col.tab = table->id;
        query_col->v_col.col = i;
        query_col->v_col.datatype = table_column->datatype;
        CT_BIT_SET(query_col->rs_flag, RS_SINGLE_COL);
        query_col->v_col.is_array = table_column->expr->root->typmod.is_array;
        query_col->v_col.ss_start = CT_INVALID_ID32;
        query_col->v_col.ss_end = CT_INVALID_ID32;
        SQL_SET_QUERY_FIELD_INFO(&query_fld, query_col->v_col.datatype, query_col->v_col.col,
            query_col->v_col.is_array, query_col->v_col.ss_start, query_col->v_col.ss_end);
        CT_RETURN_IFERR(sql_table_cache_query_field(verif->stmt, table, &query_fld));
    }
    return CT_SUCCESS;
}

static status_t sql_extract_columns(sql_verifier_t *verif, sql_query_t *query, sql_table_t *table, expr_node_t *node)
{
    switch (table->type) {
        case SUBSELECT_AS_TABLE:
        case WITH_AS_TABLE:
            CT_RETURN_IFERR(sql_extract_subselect_columns(verif, query, table, node));
            sql_extract_subslct_projcols(table);
            break;
        case FUNC_AS_TABLE:
            CT_RETURN_IFERR(sql_extract_func_columns(verif, query, table, node));
            break;
        case JSON_TABLE:
            CT_RETURN_IFERR(sql_extract_json_table_columns(verif, query, table, node));
            break;
        case NORMAL_TABLE:
        case VIEW_AS_TABLE:
        default:
            CT_RETURN_IFERR(sql_extract_table_columns(verif, query, table, node));
            break;
    }
    return CT_SUCCESS;
}

static status_t sql_expand_star(sql_verifier_t *verif, sql_query_t *query, expr_node_t *node)
{
    table_word_t *word = &node->word.table;
    sql_table_t *table = NULL;
    bool32 is_found = CT_FALSE;

    if (word->name.len != 0) {
        CT_RETURN_IFERR(
            sql_search_table_local(verif, node, (text_t *)&word->user, (text_t *)&word->name, &table, &is_found));
        if (!is_found) {
            CT_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "invalid table '%s'", T2S((text_t *)&word->name));
            return CT_ERROR;
        }
        node->value.v_col.tab = table->id;
        return sql_extract_columns(verif, query, table, node);
    }

    for (uint32 i = 0; i < query->tables.count; i++) {
        table = (sql_table_t *)sql_array_get(&query->tables, i);
        CT_RETURN_IFERR(sql_extract_columns(verif, query, table, node));
    }

    return CT_SUCCESS;
}

static void sql_get_normal_column_desc(sql_verifier_t *verif, rs_column_t *rs_col)
{
    sql_table_t *table = NULL;
    galist_t *sub_columns = NULL;
    rs_column_t *sub_col = NULL;
    knl_column_t *knl_col = NULL;
    bool32 always_null = CT_FALSE;
    bool32 nullable = CT_FALSE;

    // In a sub-select, and reference to parent query
    // precision,scale,nullable derivation have no use
    // use thread very->query->select_ctx->parent to find the right table
    if (rs_col->v_col.ancestor != 0 || verif->curr_query == NULL || verif->select_ctx == NULL) {
        return;
    }

    table = (sql_table_t *)sql_array_get(&verif->curr_query->tables, rs_col->v_col.tab);
    always_null = verif->select_ctx->root->type != SELECT_NODE_QUERY;
    switch (table->type) {
        case SUBSELECT_AS_TABLE:
        case VIEW_AS_TABLE:
        case WITH_AS_TABLE:
            sub_columns = table->select_ctx->first_query->rs_columns;
            sub_col = (rs_column_t *)cm_galist_get(sub_columns, rs_col->v_col.col);
            nullable = always_null || table->rs_nullable || CT_BIT_TEST(sub_col->rs_flag, RS_NULLABLE);
            RS_SET_FLAG(nullable, rs_col, RS_NULLABLE);
            RS_SET_FLAG(CT_BIT_TEST(sub_col->rs_flag, RS_HAS_QUOTE), rs_col, RS_HAS_QUOTE);
            RS_SET_FLAG(CT_BIT_TEST(sub_col->rs_flag, RS_IS_SERIAL), rs_col, RS_IS_SERIAL);
            break;

        case FUNC_AS_TABLE:
            // cast has only one column, rs_cols count may greater than 1
            if (cm_text_str_equal_ins(&table->func.desc->name, "cast")) {
                knl_col = &table->func.desc->columns[0];
            } else {
                knl_col = &table->func.desc->columns[rs_col->v_col.col];
            }
            nullable = always_null || table->rs_nullable || knl_col->nullable;
            RS_SET_FLAG(nullable, rs_col, RS_NULLABLE);
            break;

        case JSON_TABLE:
            sub_columns = &table->json_table_info->columns;
            sub_col = (rs_column_t *)cm_galist_get(sub_columns, rs_col->v_col.col);
            RS_SET_FLAG(CT_TRUE, rs_col, RS_NULLABLE);
            RS_SET_FLAG(CT_BIT_TEST(sub_col->rs_flag, RS_HAS_QUOTE), rs_col, RS_HAS_QUOTE);
            RS_SET_FLAG(CT_BIT_TEST(sub_col->rs_flag, RS_IS_SERIAL), rs_col, RS_IS_SERIAL);
            break;

        case NORMAL_TABLE:
        default:
            knl_col = knl_get_column(table->entry->dc.handle, rs_col->v_col.col);
            nullable = always_null || table->rs_nullable || knl_col->nullable;
            RS_SET_FLAG(nullable, rs_col, RS_NULLABLE);
            RS_SET_FLAG(KNL_COLUMN_HAS_QUOTE(knl_col), rs_col, RS_HAS_QUOTE);
            RS_SET_FLAG(KNL_COLUMN_IS_SERIAL(knl_col), rs_col, RS_IS_SERIAL);
            break;
    }
}

static status_t sql_gen_column_z_alias(sql_stmt_t *stmt, query_column_t *column, uint32 col_id)
{
    if (column->exist_alias || IS_LOCAL_COLUMN(column->expr)) {
        column->z_alias.str = NULL;
        column->z_alias.len = 0;
        return CT_SUCCESS;
    }

    char buff[CT_MAX_NAME_LEN];
    PRTS_RETURN_IFERR(snprintf_s(buff, CT_MAX_NAME_LEN, CT_MAX_NAME_LEN - 1, "Z_ALIAS_%u", col_id));
    text_t txt = {
        .str = buff
    };
    txt.len = (uint32)strlen(buff);
    CT_RETURN_IFERR(sql_copy_name(stmt->context, &txt, &column->z_alias));
    return CT_SUCCESS;
}

static status_t sql_gen_rs_column(sql_verifier_t *verif, query_column_t *column, expr_node_t *node, rs_column_t *rs_col)
{
    var_column_t *v_col = NULL;

    rs_col->name = column->alias;
    rs_col->z_alias = column->z_alias;
    rs_col->typmod = node->typmod;
    RS_SET_FLAG(column->exist_alias, rs_col, RS_EXIST_ALIAS);

    if (CT_BIT_TEST(verif->incl_flags, SQL_INCL_ROWNUM)) {
        CT_BIT_SET(rs_col->rs_flag, RS_HAS_ROWNUM);
    }

    if (CT_BIT_TEST(verif->incl_flags, SQL_COND_UNABLE_INCL)) {
        CT_BIT_SET(rs_col->rs_flag, RS_COND_UNABLE);
    } else {
        CT_BIT_RESET(rs_col->rs_flag, RS_COND_UNABLE);
    }

    if (IS_NORMAL_COLUMN(column->expr) && EXPR_ANCESTOR(column->expr) == 0) {
        v_col = VALUE_PTR(var_column_t, &node->value);
        rs_col->type = RS_COL_COLUMN;
        CT_BIT_SET(rs_col->rs_flag, RS_SINGLE_COL);
        rs_col->v_col = *v_col;
        sql_get_normal_column_desc(verif, rs_col);
    } else {
        rs_col->type = RS_COL_CALC;
        CT_BIT_RESET(rs_col->rs_flag, RS_SINGLE_COL);
        rs_col->expr = column->expr;
        CT_BIT_SET(rs_col->rs_flag, RS_NULLABLE);
    }

    return CT_SUCCESS;
}

static status_t sql_verify_query_column(sql_verifier_t *verif, query_column_t *column)
{
    expr_node_t *node = NULL;
    rs_column_t *rs_col = NULL;
    sql_query_t *query = verif->curr_query;
    bool32 exists_rownum = CT_BIT_TEST(verif->incl_flags, SQL_INCL_ROWNUM);

    verif->aggr_flags = SQL_GEN_AGGR_FROM_COLUMN;
    node = column->expr->root;

    if (node->type == EXPR_NODE_STAR) {
        if ((verif->excl_flags & SQL_EXCL_STAR) != 0) {
            CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected '*'");
            return CT_ERROR;
        }

        if (column->expr->root->type == EXPR_NODE_PRIOR) {
            CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected 'prior'");
            return CT_ERROR;
        }

        return sql_expand_star(verif, query, node);
    }

    CT_BIT_RESET(verif->incl_flags, SQL_INCL_ROWNUM);
    CT_RETURN_IFERR(sql_verify_expr(verif, column->expr));
    CT_RETURN_IFERR(sql_gen_column_z_alias(verif->stmt, column, query->rs_columns->count));

    CT_RETURN_IFERR(cm_galist_new(query->rs_columns, sizeof(rs_column_t), (pointer_t *)&rs_col));
    CT_RETURN_IFERR(sql_gen_rs_column(verif, column, node, rs_col));

    if (exists_rownum) {
        CT_BIT_SET(verif->incl_flags, SQL_INCL_ROWNUM);
    }

    verif->aggr_flags = 0;
    return CT_SUCCESS;
}

static status_t sql_rs_columns_match_group(sql_stmt_t *stmt, sql_query_t *query)
{
    uint32 i;
    rs_column_t *rs_col = NULL;

    if (query->group_sets->count == 0) {
        return CT_SUCCESS;
    }

    for (i = 0; i < query->rs_columns->count; i++) {
        rs_col = (rs_column_t *)cm_galist_get(query->rs_columns, i);
        if (rs_col->type == RS_COL_COLUMN) {
            CT_RETURN_IFERR(sql_match_group_columns(stmt, query, rs_col));
        } else {
            CT_RETURN_IFERR(sql_match_group_expr(stmt, query, rs_col->expr));
        }
    }
    return CT_SUCCESS;
}

static inline void sql_set_query_incl_flags(sql_verifier_t *verif, sql_query_t *query)
{
    if (verif->incl_flags & SQL_INCL_PRNT_OR_ANCSTR) {
        query->incl_flags |= RS_INCL_PRNT_OR_ANCSTR;
    }

    if (verif->incl_flags & SQL_INCL_SUBSLCT) {
        query->incl_flags |= RS_INCL_SUBSLCT;
    }

    if (verif->incl_flags & SQL_INCL_GROUPING) {
        query->incl_flags |= RS_INCL_GROUPING;
    }

    if (verif->incl_flags & SQL_INCL_ARRAY) {
        query->incl_flags |= RS_INCL_ARRAY;
    }
}

static status_t sql_verify_qry_col_inside(sql_verifier_t *verif, sql_query_t *query, uint32 *aggrs_expr_count,
    bool32 *has_single_column)
{
    query_column_t *column = NULL;

    verif->tables = &query->tables;
    verif->aggrs = query->aggrs;
    verif->cntdis_columns = query->cntdis_columns;
    verif->curr_query = query;
    verif->excl_flags = SQL_EXCL_DEFAULT | SQL_EXCL_JOIN;
    verif->has_excl_const = CT_FALSE;

    if (verif->has_union || verif->has_minus || verif->has_except_intersect) {
        verif->excl_flags |= SQL_EXCL_LOB_COL;
    }
    if (verif->stmt->context->type == CTSQL_TYPE_CREATE_VIEW) {
        verif->excl_flags |= SQL_EXCL_SEQUENCE;
    }

    for (uint32 i = 0; i < query->columns->count; i++) {
        verif->excl_flags |= query->has_distinct ? SQL_EXCL_LOB_COL : 0;
        verif->incl_flags = 0;

        column = (query_column_t *)cm_galist_get(query->columns, i);

        CT_RETURN_IFERR(sql_verify_query_column(verif, column));

        if (verif->incl_flags & SQL_INCL_AGGR) {
            (*aggrs_expr_count)++;

            // like substr(f1, 1, count(f2)), f1 is single column
            if (sql_check_has_single_column(verif, column->expr->root)) {
                *has_single_column = CT_TRUE;
            }
        } else if (sql_check_table_column_exists(verif->stmt, query, column->expr->root)) {
            verif->has_excl_const = CT_TRUE;
        }

        // set rs incl flags
        sql_set_query_incl_flags(verif, query);
    }
    if (query->path_func_nodes->count > 0) {
        // sys_connect_by_path is not a const
        verif->has_excl_const = CT_TRUE;
    }

    return CT_SUCCESS;
}

static inline status_t remove_group_const_exprs(sql_query_t *query)
{
    if (query->group_sets->count != 1 || CT_BIT_TEST(query->incl_flags, RS_INCL_GROUPING)) {
        return CT_SUCCESS;
    }

    group_set_t *group_set = (group_set_t *)cm_galist_get(query->group_sets, 0);
    for (uint32 i = group_set->items->count; i > 0; i--) {
        expr_tree_t *expr = (expr_tree_t *)cm_galist_get(group_set->items, i - 1);
        if (TREE_IS_CONST(expr) || TREE_IS_RES_NULL(expr)) {
            cm_galist_delete(group_set->items, i - 1);
            group_set->count--;
        }
    }
    if (group_set->items->count == 0) {
        group_set->count = group_set->items->count = 1;
    }
    return CT_SUCCESS;
}

status_t sql_verify_query_columns(sql_verifier_t *verif, sql_query_t *query)
{
    uint32 aggrs_expr_count = 0;
    bool32 has_single_column = CT_FALSE;
    bool32 is_true = CT_FALSE;

    CT_RETURN_IFERR(sql_verify_qry_col_inside(verif, query, &aggrs_expr_count, &has_single_column));

    // verify columns with group by
    // case 1: has no group by
    is_true = (aggrs_expr_count > 0 && query->group_sets->count == 0);
    is_true = is_true && ((aggrs_expr_count != query->columns->count && verif->has_excl_const) || has_single_column);
    if (is_true) {
        // not ok: select f1, count(f2) from t1
        // not ok: select substr(f1, count(f2)), case when 1=1 then f1 else count(f2) end, f1+count(f2), 123 from t1
        // ok:     select 1, :p1, 1+:p2, count(f1) from t1
        CT_THROW_ERROR(ERR_EXPR_NOT_IN_GROUP_LIST);
        return CT_ERROR;
    }

    // remove const group exprs
    CT_RETURN_IFERR(remove_group_const_exprs(query));

    // case 2: has group by
    CT_RETURN_IFERR(sql_rs_columns_match_group(verif->stmt, query));

    // case 3: has winsort node
    if (query->winsort_list->count > 0) {
        set_winsort_rs_node_flag(query);
        CT_RETURN_IFERR(sql_gen_winsort_rs_columns(verif->stmt, query));
    }

    if (query->owner->type == SELECT_AS_VARIANT) {
        if (query->rs_columns->count > 1) {
            CT_SRC_THROW_ERROR(query->loc, ERR_SQL_SYNTAX_ERROR, "too many columns");
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t sql_verify_return_columns(sql_verifier_t *verif, galist_t *ret_columns)
{
    uint32 i;
    query_column_t *column = NULL;
    rs_column_t *rs_col = NULL;

    verif->excl_flags = SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_BIND_PARAM;

    galist_t *rs_columns = NULL;
    CT_RETURN_IFERR(sql_create_list(verif->stmt, &rs_columns));

    for (i = 0; i < ret_columns->count; i++) {
        column = (query_column_t *)cm_galist_get(ret_columns, i);
        CT_RETURN_IFERR(sql_verify_expr(verif, column->expr));
        CT_RETURN_IFERR(sql_gen_column_z_alias(verif->stmt, column, i));

        CT_RETURN_IFERR(cm_galist_new(rs_columns, sizeof(rs_column_t), (pointer_t *)&rs_col));
        CT_RETURN_IFERR(sql_gen_rs_column(verif, column, column->expr->root, rs_col));
    }

    verif->context->rs_columns = rs_columns;
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
