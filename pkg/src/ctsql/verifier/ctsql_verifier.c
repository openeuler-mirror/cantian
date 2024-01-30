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
 * ctsql_verifier.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/verifier/ctsql_verifier.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_verifier.h"
#include "ctsql_insert_verifier.h"
#include "ctsql_update_verifier.h"
#include "ctsql_delete_verifier.h"
#include "ctsql_merge_verifier.h"
#include "ctsql_replace_verifier.h"
#include "srv_instance.h"
#include "dml_parser.h"
#include "ctsql_func.h"
#include "ctsql_winsort.h"

#ifdef __cplusplus
extern "C" {
#endif

void sql_init_aggr_node(expr_node_t *node, uint32 fun_id, uint32 ofun_id)
{
    node->unary = UNARY_OPER_NONE;
    node->value.type = CT_TYPE_INTEGER;
    node->value.v_func.pack_id = CT_INVALID_ID32;
    node->value.v_func.func_id = fun_id;
    node->value.v_func.orig_func_id = ofun_id;
    node->value.v_func.is_proc = CT_FALSE;
    node->value.v_func.aggr_ref_count = 1;
}

bool32 sql_check_user_exists(knl_handle_t session, text_t *name)
{
    uint32 uid;
    return knl_get_user_id(session, name, &uid);
}

void sql_init_udo(var_udo_t *udo_obj)
{
    udo_obj->user = CM_NULL_TEXT;
    udo_obj->pack = CM_NULL_TEXT;
    udo_obj->name = CM_NULL_TEXT;
    udo_obj->name_sensitive = CT_FALSE;
    udo_obj->pack_sensitive = CT_FALSE;
}

void sql_init_udo_with_str(var_udo_t *udo_obj, char *user, char *pack, char *name)
{
    udo_obj->user.str = user;
    udo_obj->user.len = 0;
    udo_obj->pack.str = pack;
    udo_obj->pack.len = 0;
    udo_obj->name.str = name;
    udo_obj->name.len = 0;
    udo_obj->unused = 0;
    udo_obj->name_sensitive = CT_FALSE;
    udo_obj->pack_sensitive = CT_FALSE;
    udo_obj->user_explicit = CT_FALSE;
}

void sql_init_udo_with_text(var_udo_t *udo_obj, text_t *user, text_t *pack, text_t *name)
{
    udo_obj->user = *user;
    udo_obj->pack = *pack;
    udo_obj->name = *name;
    udo_obj->name_sensitive = CT_FALSE;
    udo_obj->pack_sensitive = CT_FALSE;
}

void set_ddm_attr(sql_verifier_t *verif, var_column_t *v_col, knl_column_t *knl_col)
{
    v_col->is_ddm_col = CT_FALSE;
    if (knl_col->ddm_expr != NULL) {
        if (!(verif->incl_flags & SQL_INCL_COND_COL)) {
            v_col->is_ddm_col = CT_TRUE;
            verif->has_ddm_col = CT_TRUE;
        }
    }
}

static bool32 if_idx_col_find_in_list(sql_query_t *query, galist_t *list, uint32 col_id)
{
    for (uint32 i = 0; i < list->count; i++) {
        if (query->has_distinct) {
            rs_column_t *rs_col = (rs_column_t *)cm_galist_get(list, i);
            if (rs_col->type == RS_COL_COLUMN && rs_col->v_col.ancestor == 0 && rs_col->v_col.col == col_id) {
                return CT_TRUE;
            }
            expr_node_t *node = rs_col->type == RS_COL_CALC ? sql_get_origin_ref(rs_col->expr->root) : NULL;
            if (node != NULL && node->type == EXPR_NODE_COLUMN && NODE_ANCESTOR(node) == 0 &&
                NODE_COL(node) == col_id) {
                return CT_TRUE;
            }
        } else {
            expr_tree_t *group_expr = (expr_tree_t *)cm_galist_get(list, i);
            if (EXPR_COL(group_expr) == col_id) {
                return CT_TRUE;
            }
        }
    }
    return CT_FALSE;
}

static inline bool32 if_all_idx_cols_in_list(sql_query_t *query, galist_t *list, knl_index_desc_t *index_desc)
{
    if (index_desc->column_count > list->count) {
        return CT_FALSE;
    }

    for (uint32 i = 0; i < index_desc->column_count; i++) {
        if (!if_idx_col_find_in_list(query, list, index_desc->columns[i])) {
            return CT_FALSE;
        }
    }
    return CT_TRUE;
}

static inline bool32 if_all_unique_cols_not_null(sql_table_t *table, knl_index_desc_t *index_desc)
{
    for (uint32 i = 0; i < index_desc->column_count; i++) {
        knl_column_t *column = knl_get_column(table->entry->dc.handle, index_desc->columns[i]);
        if (column->nullable) {
            return CT_FALSE;
        }
    }
    return CT_TRUE;
}

bool32 if_unqiue_idx_in_list(sql_query_t *query, sql_table_t *table, galist_t *list)
{
    uint32 count;
    knl_index_desc_t *index_desc = NULL;
    count = knl_get_index_count(table->entry->dc.handle);
    for (uint32 i = 0; i < count; i++) {
        index_desc = knl_get_index(table->entry->dc.handle, i);
        if (index_desc->part_idx_invalid) {
            continue;
        }
        if (index_desc->primary && if_all_idx_cols_in_list(query, list, index_desc)) {
            return CT_TRUE;
        }
        if (index_desc->unique && if_all_unique_cols_not_null(table, index_desc) &&
            if_all_idx_cols_in_list(query, list, index_desc)) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

bool32 if_query_distinct_can_eliminate(sql_verifier_t *verif, sql_query_t *query)
{
    if (verif->has_union || verif->has_minus || (query->aggrs->count > 0 && query->group_sets->count == 0)) {
        return CT_TRUE;
    }

    if (!query->has_distinct || query->tables.count > 1 || query->connect_by_cond != NULL ||
        query->group_sets->count > 1) {
        return CT_FALSE;
    }

    sql_table_t *table = (sql_table_t *)sql_array_get(&query->tables, 0);
    if (table->type != NORMAL_TABLE) {
        return CT_FALSE;
    }
    return if_unqiue_idx_in_list(query, table, query->rs_columns);
}

static status_t pl_add_seq_node(sql_stmt_t *stmt, expr_node_t *seq_node)
{
    sql_seq_t *seq_item = NULL;
    pl_entity_t *entity = (pl_entity_t *)stmt->pl_context;

    for (uint32 i = 0; i < entity->sequences.count; ++i) {
        seq_item = (sql_seq_t *)cm_galist_get(&entity->sequences, i);
        seq_item->seq.mode = seq_node->value.v_seq.mode;
        if (var_seq_equal(&seq_node->value.v_seq, &seq_item->seq)) {
            seq_item->flags |= (uint32)seq_node->value.v_seq.mode;
            break;
        }
        seq_item = NULL;
    }

    if (seq_item == NULL) {
        CT_RETURN_IFERR(cm_galist_new(&entity->sequences, sizeof(sql_seq_t), (void **)&seq_item));
        seq_item->seq = seq_node->value.v_seq;
        seq_item->flags = seq_node->value.v_seq.mode;
        seq_item->processed = CT_FALSE;
        seq_item->value = 0;
    }

    return CT_SUCCESS;
}

status_t sql_add_sequence_node(sql_stmt_t *stmt, expr_node_t *node)
{
    sql_seq_t *seq_item = NULL;
    expr_node_t *seq_node = NULL;

    if (node->type == EXPR_NODE_SEQUENCE) {
        stmt->context->unsinkable = CT_TRUE;
        seq_node = node;
    } else if (node->type == EXPR_NODE_FUNC) {
        seq_node = node->argument->root;
    } else {
        seq_node = NULL;
    }

    if (seq_node == NULL || seq_node->type != EXPR_NODE_SEQUENCE) {
        return CT_SUCCESS;
    }

    if (stmt->pl_context != NULL) {
        return pl_add_seq_node(stmt, seq_node);
    }

    if (stmt->context->sequences == NULL) {
        CT_RETURN_IFERR(sql_create_list(stmt, &stmt->context->sequences));
    }

    for (uint32 i = 0; i < stmt->context->sequences->count; ++i) {
        seq_item = (sql_seq_t *)cm_galist_get(stmt->context->sequences, i);
        seq_item->seq.mode = seq_node->value.v_seq.mode;
        if (var_seq_equal(&seq_node->value.v_seq, &seq_item->seq)) {
            seq_item->flags |= (uint32)seq_node->value.v_seq.mode;
            break;
        }
        seq_item = NULL;
    }

    if (seq_item == NULL) {
        CT_RETURN_IFERR(cm_galist_new(stmt->context->sequences, sizeof(sql_seq_t), (void **)&seq_item));
        seq_item->seq = seq_node->value.v_seq;
        seq_item->flags = seq_node->value.v_seq.mode;
        seq_item->processed = CT_FALSE;
        seq_item->value = 0;
    }
    return CT_SUCCESS;
}

static inline bool32 if_need_add_func_node(sql_verifier_t *verif, expr_node_t *node)
{
    if (!g_instance->sql.enable_func_idx_only || node->type != EXPR_NODE_FUNC || verif->stmt == NULL ||
        verif->stmt->context == NULL) {
        return CT_FALSE;
    }

    sql_type_t type = verif->stmt->context->type;
    if ((type == CTSQL_TYPE_SELECT || type == CTSQL_TYPE_INSERT || type == CTSQL_TYPE_CREATE_TABLE) &&
        verif->select_ctx != NULL) {
        return CT_TRUE;
    }

    return CT_FALSE;
}

status_t sql_add_ref_func_node(sql_verifier_t *verif, expr_node_t *node)
{
    expr_node_t *dst = NULL;
    sql_table_t *table = NULL;
    sql_query_t *query = NULL;
    sql_query_t *parent_query = NULL;
    uint16 tab = CT_INVALID_ID16;
    uint32 ancestor;

    if (NODE_IS_RES_ROWNUM(node) && (verif->excl_flags & SQL_EXCL_ROWNUM)) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "unexpected rownum occurs");
        return CT_ERROR;
    }

    if (!if_need_add_func_node(verif, node)) {
        return CT_SUCCESS;
    }

    sql_func_t *func = sql_get_func(&node->value.v_func);
    if (!func->indexable) {
        return CT_SUCCESS;
    }

    /* can not create an index on different table columns */
    CT_RETURN_IFERR(sql_get_expr_unique_table(verif->stmt, node, &tab, &ancestor));
    if (tab == CT_INVALID_ID16) {
        return CT_SUCCESS;
    }

    query = CTSQL_CURR_NODE(verif->stmt);
    if (query == NULL) {
        return CT_SUCCESS;
    }

    parent_query = sql_get_ancestor_query(query, ancestor);
    table = sql_array_get(&parent_query->tables, tab);
    if (table->type != NORMAL_TABLE) {
        return CT_SUCCESS;
    }

    func_expr_t *func_node = NULL;
    CT_RETURN_IFERR(sql_alloc_mem(verif->context, sizeof(func_expr_t), (void **)&func_node));
    CT_RETURN_IFERR(sql_clone_expr_node(verif->context, node, &dst, sql_alloc_mem));
    func_node->expr = dst;
    cm_bilist_add_tail(&func_node->bilist_node, &table->func_expr);
    return CT_SUCCESS;
}

/* if F is an array filed, array subscript rules :
    F[1]    -> start = 1, end = CT_INVALID_ID32
    F[1:2]  -> start = 1, end = 2
    F       -> start = CT_INVALID_ID32, end = CT_INVALID_ID32
    F[3:2]  -> invalid
    F[-3:0] -> invalid
*/
bool32 is_array_subscript_correct(int32 start, int32 end)
{
    if (start == CT_INVALID_ID32 && end == CT_INVALID_ID32) {
        return CT_TRUE;
    }

    if (start > 0 && (end == CT_INVALID_ID32 || end >= start)) {
        return CT_TRUE;
    }

    return CT_FALSE;
}

static bool32 sql_check_same_rs_column(var_column_t *var_col1, var_column_t *var_col2)
{
    if (var_col1->tab != var_col2->tab || var_col1->col != var_col2->col || var_col1->ancestor != var_col2->ancestor) {
        return CT_FALSE;
    }

    if (var_col1->is_array == CT_FALSE && var_col2->is_array == CT_FALSE) {
        if (!VAR_COL_IS_ARRAY_ELEMENT(var_col1) || var_col1->ss_start == var_col2->ss_start) {
            return CT_TRUE;
        }
    } else if (var_col1->is_array == var_col2->is_array && var_col1->ss_start == var_col2->ss_start &&
        var_col1->ss_end == var_col2->ss_end) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

static uint32 sql_find_winsort_rs_column(galist_t *rs_cols, var_column_t *v_col)
{
    for (uint32 i = 0; i < rs_cols->count; i++) {
        rs_column_t *rs_col = (rs_column_t *)cm_galist_get(rs_cols, i);
        if (rs_col->type != RS_COL_COLUMN) {
            continue;
        }
        if (sql_check_same_rs_column(&rs_col->v_col, v_col)) {
            return i;
        }
    }
    return CT_INVALID_ID32;
}

static inline status_t sql_gen_col_winsort_rs_col(galist_t *columns, var_column_t *v_col, typmode_t typmod, uint32 *id)
{
    rs_column_t *rs_cols = NULL;
    *id = sql_find_winsort_rs_column(columns, v_col);
    if (*id == CT_INVALID_ID32) {
        CT_RETURN_IFERR(cm_galist_new(columns, sizeof(rs_column_t), (pointer_t *)&rs_cols));
        rs_cols->type = RS_COL_COLUMN;
        rs_cols->datatype = v_col->datatype;
        rs_cols->typmod = typmod;
        rs_cols->v_col = *v_col;
        rs_cols->win_rs_refs = 1;
        *id = columns->count - 1;
    } else {
        rs_cols = (rs_column_t *)cm_galist_get(columns, *id);
        rs_cols->win_rs_refs++;
    }
    return CT_SUCCESS;
}

static inline status_t sql_gen_calc_winsort_rs_col(sql_stmt_t *stmt, galist_t *columns, expr_node_t *expr_node,
    uint32 *id)
{
    rs_column_t *rs_cols = NULL;

    CT_RETURN_IFERR(cm_galist_new(columns, sizeof(rs_column_t), (pointer_t *)&rs_cols));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(expr_tree_t), (void **)&rs_cols->expr));
    CT_RETURN_IFERR(sql_clone_expr_node((void *)stmt->context, expr_node, &rs_cols->expr->root, sql_alloc_mem));
    rs_cols->typmod = expr_node->typmod;
    rs_cols->type = RS_COL_CALC;
    *id = columns->count - 1;
    return CT_SUCCESS;
}

static inline status_t sql_gen_winsort_rs_col_by_cond(sql_stmt_t *stmt, sql_query_t *query, cond_node_t *cond);

static inline status_t sql_gen_winsort_rs_col_by_func(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node)
{
    uint32 id;
    sql_func_t *func = NULL;

    if (node->type == EXPR_NODE_FUNC) {
        func = sql_get_func(&node->value.v_func);
        if (func->builtin_func_id == ID_FUNC_ITEM_GROUPING || func->builtin_func_id == ID_FUNC_ITEM_GROUPING_ID ||
            func->builtin_func_id == ID_FUNC_ITEM_SYS_CONNECT_BY_PATH) {
            CT_RETURN_IFERR(sql_gen_calc_winsort_rs_col(stmt, query->winsort_rs_columns, node, &id));
            return sql_set_group_expr_node(stmt, node, id, 0, 0, NULL);
        }
        if ((func->builtin_func_id == ID_FUNC_ITEM_IF || func->builtin_func_id == ID_FUNC_ITEM_LNNVL) &&
            node->cond_arg != NULL) {
            CT_RETURN_IFERR(sql_gen_winsort_rs_col_by_cond(stmt, query, node->cond_arg->root));
        }
    }

    return sql_gen_winsort_rs_col_by_expr_tree(stmt, query, node->argument);
}

static inline status_t sql_gen_winsort_rs_col_by_case(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node)
{
    case_expr_t *case_expr = NULL;
    case_pair_t *pair = NULL;

    case_expr = (case_expr_t *)VALUE(pointer_t, &node->value);
    if (!case_expr->is_cond) {
        CT_RETURN_IFERR(sql_gen_winsort_rs_col_by_expr_tree(stmt, query, case_expr->expr));
    }

    for (uint32 i = 0; i < case_expr->pairs.count; i++) {
        pair = (case_pair_t *)cm_galist_get(&case_expr->pairs, i);
        if (!case_expr->is_cond) {
            CT_RETURN_IFERR(sql_gen_winsort_rs_col_by_expr_tree(stmt, query, pair->when_expr));
        } else {
            CT_RETURN_IFERR(sql_gen_winsort_rs_col_by_cond(stmt, query, pair->when_cond->root));
        }
        CT_RETURN_IFERR(sql_gen_winsort_rs_col_by_expr_tree(stmt, query, pair->value));
    }

    if (case_expr->default_expr != NULL) {
        return sql_gen_winsort_rs_col_by_expr_tree(stmt, query, case_expr->default_expr);
    }
    return CT_SUCCESS;
}

static inline void sql_winsort_calc_data_precision(expr_node_t *node1, expr_tree_t *expr)
{
    expr_node_t *node2 = NULL;
    if (expr == NULL || expr->root == NULL) {
        return;
    }
    node2 = expr->root;
    if (node1->datatype != node2->datatype) {
        return;
    }
    switch (node1->datatype) {
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_TZ:
        case CT_TYPE_TIMESTAMP_LTZ:
        case CT_TYPE_DATE:
        case CT_TYPE_INTERVAL:
        case CT_TYPE_INTERVAL_YM:
        case CT_TYPE_INTERVAL_DS: {
            node1->typmod = node2->typmod;
            break;
        }
        default:
            break;
    }
    return;
}

static inline status_t sql_gen_winsort_rs_col_by_over(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node)
{
    uint32 id;
    expr_node_t *func_node = node->argument->root;

    CT_RETURN_IFERR(sql_gen_winsort_rs_col_by_expr_tree(stmt, query, func_node->argument));
    CT_RETURN_IFERR(sql_gen_calc_winsort_rs_col(stmt, query->winsort_rs_columns, node, &id));
    sql_winsort_calc_data_precision(node, func_node->argument);
    VALUE(uint32, &node->value) = id;
    return CT_SUCCESS;
}

static status_t sql_gen_winsort_rs_col_by_ref_col(sql_stmt_t *stmt, galist_t *rs_col, expr_node_t *ref_col)
{
    uint32 id;
    uint32 ancestor = 0;

    if (ref_col->type == EXPR_NODE_GROUP && ref_col->value.v_vm_col.ancestor == 0) {
        return CT_SUCCESS;
    }

    if (ref_col->type == EXPR_NODE_COLUMN) {
        var_column_t parent_col = VALUE(var_column_t, &ref_col->value);
        ancestor = parent_col.ancestor;
        parent_col.ancestor = 0;
        CT_RETURN_IFERR(sql_gen_col_winsort_rs_col(rs_col, &parent_col, ref_col->typmod, &id));
    } else {
        expr_node_t *temp_expr = NULL;

        if (ref_col->type == EXPR_NODE_GROUP) {
            ancestor = NODE_VM_ANCESTOR(ref_col);
            VALUE_PTR(var_vm_col_t, &ref_col->value)->ancestor = 0;
        } else if (ref_col->type == EXPR_NODE_RESERVED && (ref_col)->value.v_int == RES_WORD_ROWID) {
            ancestor = ROWID_NODE_ANCESTOR(ref_col);
            VALUE_PTR(var_rowid_t, &ref_col->value)->ancestor = 0;
        }
        CT_RETURN_IFERR(sql_clone_expr_node(stmt->context, ref_col, &temp_expr, sql_alloc_mem));
        CT_RETURN_IFERR(sql_gen_calc_winsort_rs_col(stmt, rs_col, temp_expr, &id));
    }
    return sql_set_group_expr_node(stmt, ref_col, id, 0, ancestor, NULL);
}

static inline status_t sql_gen_winsort_rs_col_by_ref_columns(sql_stmt_t *stmt, galist_t *rs_col, galist_t *ref_columns)
{
    expr_node_t *ref_col = NULL;
    uint32 ref_count = ref_columns->count;
    for (uint32 i = 0; i < ref_count; i++) {
        ref_col = (expr_node_t *)cm_galist_get(ref_columns, i);
        CT_RETURN_IFERR(sql_gen_winsort_rs_col_by_ref_col(stmt, rs_col, ref_col));
    }
    return CT_SUCCESS;
}

status_t sql_gen_group_rs_col_by_subselect(sql_stmt_t *stmt, galist_t *rs_col, expr_node_t *node)
{
    sql_select_t *sub_ctx = (sql_select_t *)node->value.v_obj.ptr;
    parent_ref_t *parent_ref = NULL;
    SET_NODE_STACK_CURR_QUERY(stmt, sub_ctx->root->query);
    for (uint32 i = 0; i < sub_ctx->parent_refs->count; i++) {
        parent_ref = (parent_ref_t *)cm_galist_get(sub_ctx->parent_refs, i);
        CT_RETURN_IFERR(sql_gen_winsort_rs_col_by_ref_columns(stmt, rs_col, parent_ref->ref_columns));
    }
    SQL_RESTORE_NODE_STACK(stmt);
    return CT_SUCCESS;
}

status_t sql_gen_group_rs_by_expr(sql_stmt_t *stmt, galist_t *rs_col, expr_node_t *node)
{
    return sql_gen_winsort_rs_col_by_ref_col(stmt, rs_col, node);
}

static inline status_t sql_gen_winsort_rs_col_by_array(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node)
{
    return sql_gen_winsort_rs_col_by_expr_tree(stmt, query, node->argument);
}

static inline status_t sql_gen_winsort_rs_col_by_column(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node)
{
    uint32 id;
    var_column_t *v_col = NULL;
    v_col = VALUE_PTR(var_column_t, &node->value);
    if (v_col->ancestor > 0) {
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(sql_gen_col_winsort_rs_col(query->winsort_rs_columns, v_col, node->typmod, &id));
    return sql_set_group_expr_node(stmt, node, id, 0, 0, NULL);
}

status_t sql_gen_winsort_rs_col_by_expr(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node)
{
    CT_RETURN_IFERR(sql_stack_safe(stmt));
    uint32 id;
    if (node->has_verified) {
        return CT_SUCCESS;
    }
    switch (node->type) {
        case EXPR_NODE_ADD:
        case EXPR_NODE_SUB:
        case EXPR_NODE_MUL:
        case EXPR_NODE_DIV:
        case EXPR_NODE_MOD:
        case EXPR_NODE_CAT:
        case EXPR_NODE_BITAND:
        case EXPR_NODE_BITOR:
        case EXPR_NODE_BITXOR:
        case EXPR_NODE_LSHIFT:
        case EXPR_NODE_RSHIFT:
            CT_RETURN_IFERR(sql_gen_winsort_rs_col_by_expr(stmt, query, node->left));
            return sql_gen_winsort_rs_col_by_expr(stmt, query, node->right);
        case EXPR_NODE_NEGATIVE:
            return sql_gen_winsort_rs_col_by_expr(stmt, query, node->right);
        case EXPR_NODE_FUNC:
        case EXPR_NODE_USER_FUNC:
            return sql_gen_winsort_rs_col_by_func(stmt, query, node);
        case EXPR_NODE_COLUMN:
            return sql_gen_winsort_rs_col_by_column(stmt, query, node);
        case EXPR_NODE_CASE:
            return sql_gen_winsort_rs_col_by_case(stmt, query, node);
        case EXPR_NODE_OVER:
            return sql_gen_winsort_rs_col_by_over(stmt, query, node);
        case EXPR_NODE_CONST:
        case EXPR_NODE_PARAM:
            return CT_SUCCESS;
        case EXPR_NODE_SELECT:
            return sql_gen_group_rs_col_by_subselect(stmt, query->winsort_rs_columns, node);
        case EXPR_NODE_ARRAY:
            return sql_gen_winsort_rs_col_by_array(stmt, query, node);
        case EXPR_NODE_RESERVED:
            if (!IS_WINSORT_SUPPORT_RESERVED(VAR_RES_ID(&node->value))) {
                return CT_SUCCESS;
            }
            // fall through
        case EXPR_NODE_SEQUENCE:
        default:
            CT_RETURN_IFERR(sql_gen_calc_winsort_rs_col(stmt, query->winsort_rs_columns, node, &id));
            return sql_set_group_expr_node(stmt, node, id, 0, 0, NULL);
    }
}

status_t sql_gen_winsort_rs_col_by_expr_tree(sql_stmt_t *stmt, sql_query_t *query, expr_tree_t *expr)
{
    while (expr != NULL && expr->root != NULL) {
        CT_RETURN_IFERR(sql_gen_winsort_rs_col_by_expr(stmt, query, expr->root));
        expr = expr->next;
    };
    return CT_SUCCESS;
}

static inline status_t sql_gen_winsort_rs_col_by_cond(sql_stmt_t *stmt, sql_query_t *query, cond_node_t *cond)
{
    CT_RETURN_IFERR(sql_stack_safe(stmt));
    if (cond == NULL) {
        return CT_SUCCESS;
    }

    switch (cond->type) {
        case COND_NODE_COMPARE:
            CT_RETURN_IFERR(sql_gen_winsort_rs_col_by_expr_tree(stmt, query, cond->cmp->left));
            return sql_gen_winsort_rs_col_by_expr_tree(stmt, query, cond->cmp->right);

        case COND_NODE_OR:
        case COND_NODE_AND:
            CT_RETURN_IFERR(sql_gen_winsort_rs_col_by_cond(stmt, query, cond->left));
            return sql_gen_winsort_rs_col_by_cond(stmt, query, cond->right);

        default:
            return CT_SUCCESS;
    }
}

status_t sql_gen_winsort_rs_column(sql_stmt_t *stmt, sql_query_t *query, rs_column_t *rs_column)
{
    uint32 id;
    expr_node_t *origin_ref = NULL;
    SET_NODE_STACK_CURR_QUERY(stmt, query);
    if (rs_column->type == RS_COL_CALC) {
        CT_RETURN_IFERR(sql_gen_winsort_rs_col_by_expr_tree(stmt, query, rs_column->expr));
        rs_column->typmod = rs_column->expr->root->typmod;
        SQL_RESTORE_NODE_STACK(stmt);
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_generate_origin_ref(stmt, rs_column, &origin_ref));
    CT_RETURN_IFERR(sql_gen_col_winsort_rs_col(query->winsort_rs_columns, &rs_column->v_col, rs_column->typmod, &id));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(expr_tree_t), (void **)&rs_column->expr));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&rs_column->expr->root));
    rs_column->type = RS_COL_CALC;
    rs_column->expr->owner = stmt->context;
    rs_column->expr->root->typmod = rs_column->typmod;
    CT_RETURN_IFERR(sql_set_group_expr_node(stmt, rs_column->expr->root, id, 0, 0, origin_ref));
    SQL_RESTORE_NODE_STACK(stmt);
    return CT_SUCCESS;
}

status_t sql_gen_winsort_rs_columns(sql_stmt_t *stmt, sql_query_t *query)
{
    rs_column_t *rs_column = NULL;

    for (uint32 i = 0; i < query->rs_columns->count; i++) {
        rs_column = (rs_column_t *)cm_galist_get(query->rs_columns, i);
        CT_RETURN_IFERR(sql_gen_winsort_rs_column(stmt, query, rs_column));
    }
    return CT_SUCCESS;
}

void set_winsort_rs_node_flag(sql_query_t *query)
{
    expr_node_t *winsort_node = NULL;
    for (uint32 i = 0; i < query->winsort_list->count; i++) {
        winsort_node = (expr_node_t *)cm_galist_get(query->winsort_list, i);
        if (winsort_node->win_args->sort_items != NULL) {
            winsort_node->win_args->is_rs_node = CT_TRUE;
            return;
        }
    }
    winsort_node = (expr_node_t *)cm_galist_get(query->winsort_list, 0);
    winsort_node->win_args->is_rs_node = CT_TRUE;
}

/**
 * static check the inconsistency of two datatypes in UPDATE and INSERT
 * statements.

 */
status_t sql_static_check_dml_pair(sql_verifier_t *verif, const column_value_pair_t *pair)
{
    expr_tree_t *expr = NULL;
    expr_tree_t *ele_expr = NULL;
    uint32 i;

    for (i = 0; i < pair->exprs->count; i++) {
        expr = (expr_tree_t *)cm_galist_get(pair->exprs, i);
        if (expr->root->type == EXPR_NODE_SELECT) {
            ((sql_select_t *)expr->root->value.v_obj.ptr)->is_update_value = CT_TRUE;
        }

        // verify expr
        CT_RETURN_IFERR(sql_verify_expr(verif, expr));

        // check the inconsistency of datatype
        if (sql_is_skipped_expr(expr)) {
            continue;
        }

        if (TREE_EXPR_TYPE(expr) == EXPR_NODE_CSR_PARAM) {
            expr->root->datatype = pair->column->datatype;
        } else if (TREE_EXPR_TYPE(expr) == EXPR_NODE_ARRAY) {
            if (expr->root->argument == NULL) {
                return CT_SUCCESS;
            }

            ele_expr = expr->root->argument;
            if (!var_datatype_matched(pair->column->datatype, TREE_DATATYPE(ele_expr))) {
                CT_SRC_ERROR_MISMATCH(TREE_LOC(expr), pair->column->datatype, TREE_DATATYPE(ele_expr));
                return CT_ERROR;
            }
        } else {
            if (!var_datatype_matched(pair->column->datatype, TREE_DATATYPE(expr))) {
                CT_SRC_ERROR_MISMATCH(TREE_LOC(expr), pair->column->datatype, TREE_DATATYPE(expr));
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

status_t sql_verify_table_dml_object(knl_handle_t session, sql_stmt_t *stmt, source_location_t loc, knl_dictionary_t dc,
    bool32 is_delete)
{
    knl_session_t *se = (knl_session_t *)session;
    uint32 uid = se->uid;

    if (stmt->session->switched_schema) {
        uid = stmt->session->curr_schema_id;
    }

    if (!DB_IS_MAINTENANCE(se) && IS_SYS_DC(&dc)) {
        // only sys can delete from sys_audit
        if ((dc.oid != SYS_AUDIT_ID) || (is_delete != CT_TRUE) || (uid != 0)) {
            CT_SRC_THROW_ERROR(loc, ERR_OPERATIONS_NOT_SUPPORT, "dml", "view or system table");
            return CT_ERROR;
        }
    }

    if (dc.type == DICT_TYPE_TABLE_EXTERNAL) {
        CT_SRC_THROW_ERROR(loc, ERR_OPERATIONS_NOT_SUPPORT, "dml", "external organized table");
        return CT_ERROR;
    }

    if (DB_IS_READONLY(se)) {
        CT_SRC_THROW_ERROR(loc, ERR_DATABASE_ROLE, "dml", "in read only mode");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

#ifdef Z_SHARDING
static status_t sql_extract_route_columns(sql_verifier_t *verif, sql_route_t *route_ctx)
{
    knl_column_t *knl_column = NULL;
    knl_dictionary_t *dc = &route_ctx->rule->entry->dc;
    uint32 col_count;
    uint32 pair_id = 0;
    column_value_pair_t *pair = NULL;
    col_count = knl_get_column_count(dc->handle);

    for (uint32 i = 0; i < col_count; i++) {
        knl_column = knl_get_column(dc->handle, i);
        if (KNL_COLUMN_INVISIBLE(knl_column)) {
            continue;
        }

        if (route_ctx->pairs->count <= pair_id) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "too less value expressions");
            return CT_ERROR;
        }

        pair = cm_galist_get(route_ctx->pairs, pair_id);

        pair->column_id = i;
        pair->column = knl_column;
        route_ctx->col_map[pair->column_id] = pair_id++;
    }

    if (route_ctx->pairs->count > pair_id) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "too many value expressions");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_verify_route_columns(sql_verifier_t *verif, sql_route_t *route_ctx)
{
    column_value_pair_t *pair = NULL;

    for (uint32 i = 0; i < route_ctx->pairs->count; i++) {
        pair = (column_value_pair_t *)cm_galist_get(route_ctx->pairs, i);
        if (sql_verify_insert_pair(verif, route_ctx->rule, pair) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (route_ctx->col_map[pair->column_id] != CT_INVALID_ID32) {
            CT_SRC_THROW_ERROR(pair->column_name.loc, ERR_DUPLICATE_NAME, "column", pair->column->name);
            return CT_ERROR;
        }

        route_ctx->col_map[pair->column_id] = i;
    }
    return CT_SUCCESS;
}

static status_t sql_verify_route_values(sql_verifier_t *verif, sql_route_t *route_ctx)
{
    column_value_pair_t *pair = NULL;
    verif->excl_flags = SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_ROWSCN |
        SQL_EXCL_GROUPING | SQL_EXCL_ROWNODEID;

    if (verif->merge_insert_status == SQL_MERGE_INSERT_NONE) {
        verif->excl_flags |= SQL_EXCL_COLUMN;
    }

    for (uint32 i = 0; i < route_ctx->pairs->count; i++) {
        pair = (column_value_pair_t *)cm_galist_get(route_ctx->pairs, i);
        if (sql_static_check_dml_pair(verif, pair) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_verify_route_context(sql_verifier_t *verif, sql_route_t *route_ctx)
{
    status_t status;
    uint32 col_count = knl_get_column_count(route_ctx->rule->entry->dc.handle);
    if (col_count == 0) {
        CT_THROW_ERROR(ERR_INVALID_DC, T2S(&route_ctx->rule->name));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_alloc_mem(verif->context, sizeof(uint32) * col_count, (void **)&route_ctx->col_map));

    MEMS_RETURN_IFERR(
        memset_s(route_ctx->col_map, sizeof(uint32) * col_count, (int)CT_INVALID_ID32, sizeof(uint32) * col_count));
    if (!route_ctx->cols_specified) {
        status = sql_extract_route_columns(verif, route_ctx);
    } else {
        status = sql_verify_route_columns(verif, route_ctx);
    }

    if (status != CT_SUCCESS) {
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_verify_route_values(verif, route_ctx));

    return CT_SUCCESS;
}

status_t sql_verify_route(sql_stmt_t *stmt, sql_route_t *route_ctx)
{
    sql_verifier_t verif = { 0 };

    verif.stmt = stmt;
    verif.table = route_ctx->rule;
    verif.context = stmt->context;

    return sql_verify_route_context(&verif, route_ctx);
}

status_t shd_verify_user_function(sql_verifier_t *verif, expr_node_t *node)
{
    if (verif == NULL || node == NULL) {
        return CT_SUCCESS;
    }

    if (node->type != EXPR_NODE_USER_FUNC) {
        return CT_SUCCESS;
    }

    if (!verif->stmt->context->has_sharding_tab) {
        return CT_SUCCESS;
    }

    if (verif->verify_tables == CT_TRUE && verif->context != NULL && verif->context->type == CTSQL_TYPE_SELECT &&
        verif->for_update == CT_FALSE && verif->select_ctx != NULL &&
        (verif->select_ctx->type == SELECT_AS_RESULT || verif->select_ctx->type == SELECT_AS_TABLE) &&
        verif->select_ctx->root->query != NULL && verif->select_ctx->root->query->tables.count == 1 &&
        ((sql_table_t *)sql_array_get(&verif->select_ctx->root->query->tables, 0))->type == FUNC_AS_TABLE) {
        return CT_SUCCESS;
    }

    char err_buf[CT_MAX_NAME_LEN + CT_MAX_NAME_LEN];
    uint32 max_len = CT_MAX_NAME_LEN + CT_MAX_NAME_LEN - 1; // reserve memory for '\0' at text end
    text_t err;
    err.len = 0;
    err.str = err_buf;
    cm_concat_string(&err, max_len, "user function(");
    var_udo_t *func = sql_node_get_obj(node);
    cm_concat_text(&err, max_len, (const text_t *)(&func->name));
    cm_concat_string(&err, max_len, ") on CN is");
    CM_NULL_TERM(&err);

    CT_SRC_THROW_ERROR(node->loc, ERR_CAPABILITY_NOT_SUPPORT, err.str);

    return CT_ERROR;
}

#endif

status_t sql_verify(sql_stmt_t *stmt)
{
    void *entry = stmt->context->entry;
    cm_reset_error_loc();
    if (stmt->context->params->count > CT_MAX_SQL_PARAM_COUNT) {
        CT_THROW_ERROR(ERR_TOO_MANY_BIND, stmt->context->params->count, CT_MAX_SQL_PARAM_COUNT);
        return CT_ERROR;
    }
    SAVE_AND_RESET_NODE_STACK(stmt);
    if (stmt->context->type == CTSQL_TYPE_SELECT) {
        CT_RETURN_IFERR(sql_verify_select(stmt, (sql_select_t *)entry));
    } else if (stmt->context->type == CTSQL_TYPE_UPDATE) {
        CT_RETURN_IFERR(sql_verify_update(stmt, (sql_update_t *)entry));
    } else if (stmt->context->type == CTSQL_TYPE_INSERT) {
        CT_RETURN_IFERR(sql_verify_insert(stmt, (sql_insert_t *)entry));
    } else if (stmt->context->type == CTSQL_TYPE_DELETE) {
        CT_RETURN_IFERR(sql_verify_delete(stmt, (sql_delete_t *)entry));
    } else if (stmt->context->type == CTSQL_TYPE_MERGE) {
        CT_RETURN_IFERR(sql_verify_merge(stmt, (sql_merge_t *)entry));
    } else if (stmt->context->type == CTSQL_TYPE_REPLACE) {
        CT_RETURN_IFERR(sql_verify_replace_into(stmt, (sql_replace_t *)entry));
    } else {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "semantic error");
        return CT_ERROR;
    }
    SQL_RESTORE_NODE_STACK(stmt);
    return CT_SUCCESS;
}

void sql_set_ancestor_level(sql_select_t *select_ctx, uint32 temp_level)
{
    sql_select_t *curr_ctx = select_ctx;
    uint32 level = temp_level;
    while (level > 0 && curr_ctx != NULL) {
        SET_ANCESTOR_LEVEL(curr_ctx, level);
        curr_ctx = (curr_ctx->parent != NULL) ? curr_ctx->parent->owner : NULL;
        level--;
    }
}

#ifdef __cplusplus
}
#endif
