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
 * plan_range.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/plan/plan_range.c
 *
 * -------------------------------------------------------------------------
 */
#include "plan_range.h"
#include "ctsql_verifier.h"
#include "plan_rbo.h"
#include "srv_instance.h"
#include "dml_executor.h"

static inline void sql_make_left_infinite_range(expr_tree_t *expr, plan_range_t *plan_range, bool32 right_closed)
{
    plan_range->type = RANGE_SECTION;
    plan_range->left.type = BORDER_INFINITE_LEFT;
    plan_range->left.expr = NULL;
    plan_range->left.closed = CT_FALSE;

    plan_range->right.type = SQL_GET_BORDER_TYPE(expr->root->type);
    plan_range->right.closed = right_closed;
    plan_range->right.expr = expr;
}

static inline void sql_make_right_infinite_range(expr_tree_t *expr, plan_range_t *plan_range, bool32 left_closed)
{
    plan_range->type = RANGE_SECTION;
    plan_range->left.type = SQL_GET_BORDER_TYPE(expr->root->type);
    plan_range->left.closed = left_closed;
    plan_range->left.expr = expr;

    plan_range->right.type = BORDER_INFINITE_RIGHT;
    plan_range->right.expr = NULL;
    plan_range->right.closed = CT_FALSE;
}

static inline void sql_make_border_equal_range(expr_tree_t *expr, plan_range_t *plan_range, range_type_t range_type,
    border_type_t border_type)
{
    plan_range->type = range_type;
    plan_range->left.type = border_type;
    plan_range->left.expr = expr;
    plan_range->left.closed = CT_TRUE;
    plan_range->right = plan_range->left;
}

void sql_make_range(cmp_type_t cmp_type, expr_tree_t *expr, plan_range_t *plan_range)
{
    switch (cmp_type) {
        case CMP_TYPE_EQUAL:
        case CMP_TYPE_EQUAL_ALL:
            sql_make_border_equal_range(expr, plan_range, RANGE_POINT, SQL_GET_BORDER_TYPE(expr->root->type));
            break;

        case CMP_TYPE_LESS:
            sql_make_left_infinite_range(expr, plan_range, CT_FALSE);
            break;

        case CMP_TYPE_LESS_EQUAL:
            sql_make_left_infinite_range(expr, plan_range, CT_TRUE);
            break;

        case CMP_TYPE_GREAT_EQUAL:
            sql_make_right_infinite_range(expr, plan_range, CT_TRUE);
            break;

        case CMP_TYPE_GREAT:
            sql_make_right_infinite_range(expr, plan_range, CT_FALSE);
            break;

        case CMP_TYPE_IN:
        case CMP_TYPE_EQUAL_ANY:
            sql_make_border_equal_range(expr, plan_range, RANGE_LIST, BORDER_CALC);
            break;

        case CMP_TYPE_LIKE:
            sql_make_border_equal_range(expr, plan_range, RANGE_LIKE, SQL_GET_BORDER_TYPE(expr->root->type));
            break;

        case CMP_TYPE_BETWEEN:
            plan_range->type = RANGE_SECTION;
            plan_range->left.type = SQL_GET_BORDER_TYPE(expr->root->type);
            plan_range->left.expr = expr;
            plan_range->left.closed = CT_TRUE;

            plan_range->right.type = SQL_GET_BORDER_TYPE(expr->next->root->type);
            plan_range->right.expr = expr->next;
            plan_range->right.closed = CT_TRUE;
            break;

        case CMP_TYPE_IS_NULL:
            sql_make_border_equal_range(NULL, plan_range, RANGE_SECTION, BORDER_IS_NULL);
            break;

        default:
            break;
    }
}

static status_t sql_create_column_range(sql_stmt_t *stmt, plan_assist_t *pa, expr_node_t *match_node,
    cmp_node_t *cmp_node, plan_range_t **plan_range)
{
    if (sql_alloc_mem(stmt->context, sizeof(plan_range_t), (void **)plan_range) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cmp_type_t cmp_type = cmp_node->type;
    (*plan_range)->datatype = match_node->datatype;
    if (sql_expr_node_matched(stmt, cmp_node->left, match_node)) {
        sql_make_range(cmp_type, cmp_node->right, *plan_range);
    } else {
        // for 'in', 'like', 'exist, 'between', column must be the left operand of comparison
        // so cmp_node->type is reversible
        cmp_type = sql_reverse_cmp(cmp_type);
        sql_make_range(cmp_type, cmp_node->left, *plan_range);
    }

    return CT_SUCCESS;
}

status_t sql_append_plan_range(sql_stmt_t *stmt, plan_range_list_t *set, plan_range_t *plan_range)
{
    plan_range_t *range_item = NULL;
    expr_tree_t *expr = NULL;
    expr_tree_t *expr_item = NULL;

    CM_POINTER3(stmt, set, plan_range);
    if (set->type == RANGE_LIST_FULL) {
        return CT_SUCCESS;
    }

    if (plan_range->type == RANGE_EMPTY) {
        return CT_SUCCESS;
    }

    if (plan_range->left.type == BORDER_INFINITE_LEFT && plan_range->right.type == BORDER_INFINITE_RIGHT) {
        set->type = RANGE_LIST_FULL;
        return CT_SUCCESS;
    }

    if (plan_range->type != RANGE_LIST) {
        CT_RETURN_IFERR(cm_galist_insert(set->items, plan_range));
        set->type = RANGE_LIST_NORMAL;
        return CT_SUCCESS;
    }

    expr = plan_range->left.expr;

    while (expr != NULL) {
        CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(expr_tree_t), (void **)&expr_item));

        expr_item->chain.count = 1;
        expr_item->root = expr->root;
        expr_item->chain.first = expr->root;
        expr_item->chain.last = NULL;

        CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(plan_range_t), (void **)&range_item));

        range_item->type = RANGE_POINT;
        range_item->left.type = SQL_GET_BORDER_TYPE(expr_item->root->type);
        range_item->left.closed = CT_TRUE;
        range_item->left.expr = expr_item;
        range_item->right = range_item->left;

        CT_RETURN_IFERR(cm_galist_insert(set->items, range_item));
        expr = expr->next;
    }

    set->type = RANGE_LIST_NORMAL;
    return CT_SUCCESS;
}

static uint32 sql_get_like_range_size(text_t *text, bool8 has_escape, char escape)
{
    uint32 length = 0;
    for (uint32 i = 0; i < text->len; ++i) {
        if (has_escape && text->str[i] == escape) {
            continue;
        }
        if (text->str[i] == '%' || text->str[i] == '_') {
            break;
        }
        length++;
    }
    return length;
}

static status_t sql_inter_range_like(sql_stmt_t *stmt, plan_range_t *range1, plan_range_t *range2, plan_range_t *result)
{
    uint32 l_len, r_len;
    expr_node_t *left_node = range1->left.expr->root;
    expr_node_t *right_node = range2->left.expr->root;
    expr_tree_t *l_escape_expr = range1->left.expr->next;
    expr_tree_t *r_escape_expr = range2->left.expr->next;
    bool8 l_has_escape = CT_FALSE;
    bool8 r_has_escape = CT_FALSE;
    char l_escape = CT_INVALID_INT8;
    char r_escape = CT_INVALID_INT8;
    result->type = RANGE_LIKE;

    if (!CT_IS_STRING_TYPE(left_node->datatype)) {
        *result = *range2;
        return CT_SUCCESS;
    }

    if (l_escape_expr != NULL && l_escape_expr->root->type == EXPR_NODE_CONST &&
        CT_IS_STRING_TYPE(l_escape_expr->root->datatype)) {
        l_has_escape = CT_TRUE;
        l_escape = l_escape_expr->root->value.v_text.str[0];
    }

    if (!CT_IS_STRING_TYPE(right_node->datatype)) {
        *result = *range1;
        return CT_SUCCESS;
    }

    if (r_escape_expr != NULL && r_escape_expr->root->type == EXPR_NODE_CONST &&
        CT_IS_STRING_TYPE(r_escape_expr->root->datatype)) {
        r_has_escape = CT_TRUE;
        r_escape = r_escape_expr->root->value.v_text.str[0];
    }

    l_len = sql_get_like_range_size(&left_node->value.v_text, l_has_escape, l_escape);
    r_len = sql_get_like_range_size(&right_node->value.v_text, r_has_escape, r_escape);
    if (l_len > r_len) {
        *result = *range1;
    } else {
        *result = *range2;
    }
    return CT_SUCCESS;
}

status_t sql_verify_const_range(sql_stmt_t *stmt, plan_range_t *result)
{
    int32 cmp_result;
    variant_t l_var, r_var;
    expr_node_t *left_node = result->left.expr->root;
    expr_node_t *right_node = result->right.expr->root;
    /* should convert left & right border datatype to the compatible datatype before compare */
    ct_type_t l_cmp_type = get_cmp_datatype(NODE_DATATYPE(left_node), result->datatype);
    ct_type_t r_cmp_type = get_cmp_datatype(NODE_DATATYPE(right_node), result->datatype);
    if (l_cmp_type != r_cmp_type) {
        return CT_SUCCESS;
    }
    CTSQL_SAVE_STACK(stmt);
    var_copy(&left_node->value, &l_var);
    if (sql_convert_variant(stmt, &l_var, l_cmp_type) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    sql_keep_stack_variant(stmt, &l_var);
    var_copy(&right_node->value, &r_var);
    if (sql_convert_variant(stmt, &r_var, r_cmp_type) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    sql_keep_stack_variant(stmt, &r_var);
    if (sql_compare_variant(stmt, &l_var, &r_var, &cmp_result) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    CTSQL_RESTORE_STACK(stmt);

    if (cmp_result > 0) {
        result->type = RANGE_EMPTY;
    } else if (cmp_result == 0) {
        if (result->left.closed && result->right.closed) {
            result->type = RANGE_POINT;
        } else {
            result->type = RANGE_EMPTY;
        }
    }

    return CT_SUCCESS;
}

bool32 sql_inter_const_range(sql_stmt_t *stmt, plan_border_t *border1, plan_border_t *border2, bool32 is_left,
    plan_border_t *result)
{
    if (border1->type != BORDER_CONST || border2->type != BORDER_CONST) {
        return CT_FALSE;
    }

    int32 cmp_result;
    // compatible with previous logic, return false when compare func return error
    if (sql_compare_variant(stmt, &border1->expr->root->value, &border2->expr->root->value, &cmp_result) !=
        CT_SUCCESS) {
        cm_reset_error();
        return CT_FALSE;
    }

    if (cmp_result == 0) {
        *result = border1->closed ? *border2 : *border1;
        return CT_TRUE;
    }

    if (is_left) {
        *result = cmp_result > 0 ? *border1 : *border2;
    } else {
        *result = cmp_result < 0 ? *border1 : *border2;
    }
    return CT_TRUE;
}

static inline status_t sql_inter_plan_range_like(sql_stmt_t *stmt, plan_range_t *range1, plan_range_t *range2,
    plan_range_t *result)
{
    if (range1->type < range2->type) {
        *result = *range1;
        return CT_SUCCESS;
    }
    if (range1->type > range2->type) {
        *result = *range2;
        return CT_SUCCESS;
    }
    if (range1->left.type == BORDER_CONST && range2->left.type == BORDER_CONST) {
        return sql_inter_range_like(stmt, range1, range2, result);
    } else {
        *result = (range1->left.type > range2->left.type) ? *range1 : *range2;
    }
    return CT_SUCCESS;
}

static inline void sql_check_left_right_border(sql_stmt_t *stmt, plan_range_t *range1, plan_range_t *range2,
    plan_range_t *res)
{
    if (!sql_inter_const_range(stmt, &range1->left, &range2->left, CT_TRUE, &res->left)) {
        if (range1->left.type > range2->left.type) {
            res->left = range1->left;
        } else {
            res->left = range2->left;
        }
    }

    if (!sql_inter_const_range(stmt, &range1->right, &range2->right, CT_FALSE, &res->right)) {
        if (range1->right.type > range2->right.type) {
            res->right = range1->right;
        } else {
            res->right = range2->right;
        }
    }
}

static status_t sql_inter_plan_range(sql_stmt_t *stmt, plan_range_t *range1, plan_range_t *range2, plan_range_t *res)
{
    CM_POINTER3(range1, range2, res);

    if (range1->left.type == BORDER_IS_NULL && range2->left.type == BORDER_IS_NULL) {
        *res = *range1;
        return CT_SUCCESS;
    }

    if (range1->left.type == BORDER_IS_NULL || range2->left.type == BORDER_IS_NULL) {
        res->type = RANGE_EMPTY;
        return CT_SUCCESS;
    }

    if (range1->type == RANGE_LIKE || range2->type == RANGE_LIKE) {
        return sql_inter_plan_range_like(stmt, range1, range2, res);
    }

    sql_check_left_right_border(stmt, range1, range2, res);

    res->type = RANGE_SECTION;

    if (res->left.type == BORDER_CONST && res->right.type == BORDER_CONST) {
        CT_RETURN_IFERR(sql_verify_const_range(stmt, res));
    }

    if (res->type == RANGE_SECTION) {
        if (range1->type == RANGE_POINT) {
            *res = *range1;
        } else if (range2->type == RANGE_POINT) {
            *res = *range2;
        }
    }
    return CT_SUCCESS;
}

static inline bool32 sql_inter_point_range_impl(plan_range_list_t *set1, plan_range_list_t *set2,
    plan_range_list_t *result)
{
    if (set1->items->count == 1 && set2->items->count > 1) {
        plan_range_t *plan_range = (plan_range_t *)cm_galist_get(set1->items, 0);
        if (plan_range->type == RANGE_POINT) {
            *result = *set1;
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

static inline bool32 sql_inter_point_range(plan_range_list_t *set1, plan_range_list_t *set2, plan_range_list_t *result)
{
    if (sql_inter_point_range_impl(set1, set2, result)) {
        return CT_TRUE;
    }

    return sql_inter_point_range_impl(set2, set1, result);
}

static status_t sql_inter_plan_list(sql_stmt_t *stmt, plan_range_list_t *set1, plan_range_list_t *set2,
    plan_range_list_t *result)
{
    uint32 i, j;
    plan_range_t *inter_range = NULL;
    plan_range_t *range1 = NULL;
    plan_range_t *range2 = NULL;

    if (set1->type == RANGE_LIST_EMPTY || set2->type == RANGE_LIST_EMPTY) {
        result->type = RANGE_LIST_EMPTY;
        return CT_SUCCESS;
    }

    if (set1->type == RANGE_LIST_FULL) {
        *result = *set2;
        return CT_SUCCESS;
    }

    if (set2->type == RANGE_LIST_FULL) {
        *result = *set1;
        return CT_SUCCESS;
    }

    if (set1->items->count * set2->items->count > CT_MAX_PLAN_RANGE_COUNT) {
        *result = set1->items->count > set2->items->count ? *set2 : *set1;
        return CT_SUCCESS;
    }

    if (sql_inter_point_range(set1, set2, result)) {
        return CT_SUCCESS;
    }

    result->type = RANGE_LIST_EMPTY;

    for (i = 0; i < set1->items->count; i++) {
        range1 = (plan_range_t *)cm_galist_get(set1->items, i);

        for (j = 0; j < set2->items->count; j++) {
            range2 = (plan_range_t *)cm_galist_get(set2->items, j);
            CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(plan_range_t), (void **)&inter_range));
            inter_range->datatype = result->typmode.datatype;
            CT_RETURN_IFERR(sql_inter_plan_range(stmt, range1, range2, inter_range));
            CT_RETURN_IFERR(sql_append_plan_range(stmt, result, inter_range));
        }
    }

    return CT_SUCCESS;
}

status_t sql_union_plan_list(sql_stmt_t *stmt, plan_range_list_t *list1, plan_range_list_t *list2,
    plan_range_list_t *result)
{
    uint32 i;
    plan_range_t *plan_range = NULL;

    CM_POINTER4(stmt, list1, list2, result);
    if (list1->type == RANGE_LIST_FULL || list2->type == RANGE_LIST_FULL) {
        result->type = RANGE_LIST_FULL;
        return CT_SUCCESS;
    }

    if (list1->type == RANGE_LIST_EMPTY) {
        *result = *list2;
        return CT_SUCCESS;
    }

    if (list2->type == RANGE_LIST_EMPTY) {
        *result = *list1;
        return CT_SUCCESS;
    }

    *result = *list1;
    for (i = 0; i < list2->items->count; i++) {
        plan_range = (plan_range_t *)cm_galist_get(list2->items, i);
        CM_POINTER(plan_range);
        if (sql_append_plan_range(stmt, result, plan_range) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_init_plan_range_list(sql_stmt_t *stmt, ct_type_t datatype, knl_column_t *knl_col,
    plan_range_list_t *list)
{
    list->type = RANGE_LIST_EMPTY;
    if (sql_alloc_mem(stmt->context, sizeof(galist_t), (void **)&list->items) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cm_galist_init(list->items, stmt->context, sql_alloc_mem);

    // list->typmode.size's max value is CT_INVALID_ID16(0xFFFF)
    // now index can not be built at lob column.
    if (knl_col->size >= (uint32)CT_INVALID_ID16) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "knl_col->size(%u) < (uint32)CT_INVALID_ID16(%u)", knl_col->size,
            (uint32)CT_INVALID_ID16);
        return CT_ERROR;
    }
    list->typmode.size = (uint16)knl_col->size;
    list->typmode.is_char = KNL_COLUMN_IS_CHARACTER(knl_col);
    list->typmode.datatype = datatype;
    return CT_SUCCESS;
}

bool32 sql_cmp_range_usable(plan_assist_t *pa, cmp_node_t *node, expr_node_t *match_node)
{
    return CT_FALSE;
}

status_t sql_create_range_list(sql_stmt_t *stmt, plan_assist_t *pa, expr_node_t *match_node, knl_column_t *knl_col,
    cond_node_t *node, plan_range_list_t **list, bool32 index_reverse, bool32 index_first_col)
{
    cmp_node_t *cmp_node = NULL;
    plan_range_list_t *l_list = NULL;
    plan_range_list_t *r_list = NULL;
    plan_range_t *plan_range = NULL;

    CT_RETURN_IFERR(sql_stack_safe(stmt));

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(plan_range_list_t), (void **)list));

    CT_RETURN_IFERR(sql_init_plan_range_list(stmt, match_node->datatype, knl_col, *list));

    switch (node->type) {
        case COND_NODE_AND:
            CT_RETURN_IFERR(sql_create_range_list(stmt, pa, match_node, knl_col, node->left, &l_list, index_reverse,
                index_first_col));
            CT_RETURN_IFERR(sql_create_range_list(stmt, pa, match_node, knl_col, node->right, &r_list, index_reverse,
                index_first_col));
            return sql_inter_plan_list(stmt, l_list, r_list, *list);

        case COND_NODE_OR:
            CT_RETURN_IFERR(sql_create_range_list(stmt, pa, match_node, knl_col, node->left, &l_list, index_reverse,
                index_first_col));
            CT_RETURN_IFERR(sql_create_range_list(stmt, pa, match_node, knl_col, node->right, &r_list, index_reverse,
                index_first_col));
            return sql_union_plan_list(stmt, l_list, r_list, *list);

        case COND_NODE_TRUE:
            (*list)->type = RANGE_LIST_FULL;
            return CT_SUCCESS;

        case COND_NODE_FALSE:
            (*list)->type = RANGE_LIST_EMPTY;
            return CT_SUCCESS;

        case COND_NODE_COMPARE:
            cmp_node = node->cmp;
            if (!sql_cmp_range_usable(pa, cmp_node, match_node)) {
                (*list)->type = RANGE_LIST_FULL;
                return CT_SUCCESS;
            }

            CT_RETURN_IFERR(sql_create_column_range(stmt, pa, match_node, cmp_node, &plan_range));
            if (index_reverse && plan_range->type != RANGE_POINT && !(index_first_col && plan_range->type == RANGE_LIST)) {
                // reverse index only can point scan
                // if the first column of index's scan range is RANGE_LIST, the scan range will be deal as multi point
                // if the other column of index's scan range is RANGE_LIST, the scan range will be deal as range
                plan_range->type = RANGE_FULL;
            }
            return sql_append_plan_range(stmt, *list, plan_range);

        default:
            return CT_SUCCESS;
    }
}

static status_t sql_create_range_list_by_cond(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table,
    sql_array_t *array, knl_column_t *knl_col, uint16 col_id, bool32 index_first_col)
{
    plan_range_list_t *list = NULL;
    expr_node_t col_node;
    expr_node_t *node = NULL;

    if (table->cond == NULL) {
        CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(plan_range_list_t), (void **)&list));
        CT_RETURN_IFERR(sql_init_plan_range_list(stmt, knl_col->datatype, knl_col, list));
        list->type = RANGE_LIST_FULL;
    } else {
        CTSQL_SAVE_STACK(stmt);
        CT_RETURN_IFERR(sql_get_index_col_node(stmt, knl_col, &col_node, &node, table->id, col_id));

        if (sql_create_range_list(stmt, pa, node, knl_col, table->cond->root, &list, table->index->is_reverse,
            index_first_col) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }
        CTSQL_RESTORE_STACK(stmt);
    }

    return sql_array_put(array, list);
}

static status_t sql_create_index_scan_ranges(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table,
    sql_array_t *array)
{
    uint32 i;
    uint16 col_id;
    query_field_t query_field;
    knl_column_t *knl_col = NULL;

    if (table->scan_mode != SCAN_MODE_INDEX) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_create_array(stmt->context, array, "INDEX RANGE", CT_MAX_INDEX_COLUMNS));

    for (i = 0; i < table->index->column_count; i++) {
        col_id = table->index->columns[i];
        knl_col = knl_get_column(table->entry->dc.handle, col_id);

        CT_RETURN_IFERR(sql_create_range_list_by_cond(stmt, pa, table, array, knl_col, col_id, (bool32)(i == 0)));

        if (!KNL_COLUMN_IS_VIRTUAL(knl_col)) {
            SQL_SET_QUERY_FIELD_INFO(&query_field, knl_col->datatype, col_id, CT_FALSE, CT_INVALID_ID32,
                CT_INVALID_ID32);
            CT_RETURN_IFERR(sql_table_cache_query_field(stmt, table, &query_field));
            continue;
        }
        for (uint32 j = 0; j < table->index->columns_info[i].arg_count; ++j) {
            col_id = table->index->columns_info[i].arg_cols[j];
            knl_col = knl_get_column(table->entry->dc.handle, col_id);
            SQL_SET_QUERY_FIELD_INFO(&query_field, knl_col->datatype, col_id, CT_FALSE, CT_INVALID_ID32,
                CT_INVALID_ID32);
            CT_RETURN_IFERR(sql_table_cache_query_field(stmt, table, &query_field));
        }
    }

    if (table->index->is_func && INDEX_ONLY_SCAN(table->scan_flag)) {
        stmt->context->has_func_index = CT_TRUE;
    }

    return CT_SUCCESS;
}

static status_t sql_create_partition_range_list(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_table_t *table,
    sql_array_t *part_array, bool32 is_sub_part)
{
    uint16 col_id;
    expr_node_t expr_node;
    knl_column_t *knl_col = NULL;
    plan_range_list_t *list = NULL;

    if (plan_ass->cond == NULL) {
        return CT_SUCCESS;
    }
    uint16 key_count =
        is_sub_part ? knl_subpart_key_count(table->entry->dc.handle) : knl_part_key_count(table->entry->dc.handle);

    for (uint16 i = 0; i < key_count; i++) {
        col_id = is_sub_part ? knl_subpart_key_column_id(table->entry->dc.handle, i) :
                               knl_part_key_column_id(table->entry->dc.handle, i);
        knl_col = knl_get_column(table->entry->dc.handle, col_id);
        expr_node.value.v_col.tab = table->id;
        expr_node.value.v_col.col = col_id;
        expr_node.value.v_col.datatype = knl_col->datatype;
        expr_node.value.v_col.ancestor = 0;
        expr_node.value.v_col.ss_start = CT_INVALID_ID32;
        expr_node.value.v_col.ss_end = CT_INVALID_ID32;
        expr_node.datatype = knl_col->datatype;
        expr_node.unary = UNARY_OPER_NONE;
        expr_node.type = EXPR_NODE_COLUMN;
        expr_node.left = expr_node.right = NULL;

        if (sql_create_range_list(stmt, plan_ass, &expr_node, knl_col, plan_ass->cond->root,
                                  &list, CT_FALSE, CT_FALSE) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (sql_array_put(part_array, list) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t sql_create_subpart_scan_ranges(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_table_t *table,
    sql_array_t *subpart_array)
{
    if (sql_create_array(stmt->context, subpart_array, "SUBPARTITION RANGE", CT_MAX_PARTKEY_COLUMNS) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return sql_create_partition_range_list(stmt, plan_ass, table, subpart_array, CT_TRUE);
}

status_t sql_create_part_scan_ranges(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_table_t *table, sql_array_t *array)
{
    // common table not need create part scan range
    if (!knl_is_part_table(table->entry->dc.handle)) {
        return CT_SUCCESS;
    }

    if (sql_create_array(stmt->context, array, "PARTITION RANGE", CT_MAX_PARTKEY_COLUMNS) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_create_partition_range_list(stmt, plan_ass, table, array, CT_FALSE);
}

static void check_multi_parts_index_scan(sql_table_t *table, sql_query_t *query)
{
    if (!(table->scan_flag & RBO_INDEX_SORT_FLAG) || query->sort_items->count == 0 || !table->index->parted) {
        table->multi_parts_scan = CT_FALSE;
        return;
    }

    knl_handle_t handle = table->entry->dc.handle;
    uint32 part_key_count = knl_part_key_count(handle);
    part_type_t part_type = knl_part_table_type(handle);
    if (part_type != PART_TYPE_RANGE ||
        !chk_part_key_match_index(handle, part_key_count, table->index, table->idx_equal_to)) {
        table->multi_parts_scan = CT_TRUE;
        return;
    }
    table->multi_parts_scan = CT_FALSE;
}

status_t sql_create_scan_ranges(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_table_t *table, scan_plan_t *scan_plan)
{
    // not need create scan range while have no where clause or subselect or view
    if (table->type != NORMAL_TABLE) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_create_index_scan_ranges(stmt, plan_ass, table, &scan_plan->index_array));
    CT_RETURN_IFERR(sql_create_part_scan_ranges(stmt, plan_ass, table, &scan_plan->part_array));
    // common table not need create part scan range
    if (knl_is_compart_table(table->entry->dc.handle)) {
        CT_RETURN_IFERR(sql_create_subpart_scan_ranges(stmt, plan_ass, table, &scan_plan->subpart_array));
    }

    check_multi_parts_index_scan(table, plan_ass->query);

    return CT_SUCCESS;
}

status_t sql_check_border_variant(sql_stmt_t *stmt, variant_t *var, ct_type_t datatype, uint32 size)
{
    char *buf = NULL;

    if (var->type == CT_TYPE_CHAR && datatype == CT_TYPE_CHAR) {
        if (size > var->v_text.len) {
            if (sql_push(stmt, size, (void **)&buf) != CT_SUCCESS) {
                return CT_ERROR;
            }
            if (var->v_text.len != 0) {
                MEMS_RETURN_IFERR(memcpy_s(buf, size, var->v_text.str, var->v_text.len));
            }
            MEMS_RETURN_IFERR(memset_s(buf + var->v_text.len, size - var->v_text.len, ' ', size - var->v_text.len));
            var->v_text.len = size;
            var->v_text.str = buf;
            return CT_SUCCESS;
        }

        while (size < var->v_text.len) {
            if (var->v_text.str[var->v_text.len - 1] != ' ') {
                break;
            }
            var->v_text.len--;
        }
    }

    return CT_SUCCESS;
}

static inline status_t sql_make_string_border(sql_stmt_t *stmt, scan_border_t *border, ct_type_t datatype, uint32 size)
{
    if (!CT_IS_STRING_TYPE(border->var.type)) {
        return CT_ERROR;
    }

    border->var.type = datatype;
    if (datatype == CT_TYPE_CHAR) {
        return CT_SUCCESS;
    }
    return sql_check_border_variant(stmt, &border->var, datatype, size);
}

static inline status_t sql_make_binary_border(sql_stmt_t *stmt, scan_border_t *border, const nlsparams_t *nlsparams)
{
    text_buf_t buffer;

    if (CT_IS_BINARY_TYPE(border->var.type) || CT_IS_RAW_TYPE(border->var.type) ||
        CT_IS_STRING_TYPE(border->var.type)) {
        return var_as_binary(nlsparams, &border->var, NULL);
    }

    CT_RETURN_IFERR(sql_push_textbuf(stmt, CT_CONVERT_BUFFER_SIZE, &buffer));
    return var_as_binary(nlsparams, &border->var, &buffer);
}

static inline status_t sql_make_raw_border(sql_stmt_t *stmt, scan_border_t *border)
{
    if (CT_IS_RAW_TYPE(border->var.type) || CT_IS_BINARY_TYPE(border->var.type)) {
        return var_as_raw(&border->var, NULL, 0);
    }

    if (CT_IS_STRING_TYPE(border->var.type)) {
        char *buf = NULL;

        CT_RETURN_IFERR(sql_push(stmt, CT_CONVERT_BUFFER_SIZE, (void **)&buf));
        return var_as_raw(&border->var, buf, CT_CONVERT_BUFFER_SIZE);
    }
    return CT_ERROR;
}

static bool32 sql_border_is_overflow(sql_stmt_t *stmt, variant_t *var, ct_type_t datatype, border_wise_t wise)
{
    variant_t v2;
    int32 result;
    v2.is_null = CT_FALSE;
    v2.type = CT_TYPE_BIGINT;

    switch (datatype) {
        case CT_TYPE_UINT32:
            v2.v_bigint = (wise == WISE_LEFT) ? CT_MAX_UINT32 : CT_MIN_UINT32;
            break;
        case CT_TYPE_INTEGER:
            v2.v_bigint = (wise == WISE_LEFT) ? CT_MAX_INT32 : CT_MIN_INT32;
            break;
        case CT_TYPE_BIGINT:
            v2.v_bigint = (wise == WISE_LEFT) ? CT_MAX_INT64 : CT_MIN_INT64;
            break;
        default:
            return CT_FALSE;
    }
    if (sql_compare_variant(stmt, var, &v2, &result) != CT_SUCCESS) {
        cm_reset_error();
        return CT_FALSE;
    }

    return ((wise == WISE_LEFT && result > 0) || (wise == WISE_RIGHT && result < 0));
}

static inline void sql_make_difftype_border(sql_stmt_t *stmt, scan_border_t *border, ct_type_t datatype, uint32 size,
    border_wise_t wise)
{
    status_t status;
    const nlsparams_t *nlsparams = SESSION_NLS(stmt);

    // indexed column compare with different datatype
    switch (datatype) {
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
            status = sql_make_string_border(stmt, border, datatype, size);
            break;

        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
            status = sql_make_binary_border(stmt, border, nlsparams);
            break;

        case CT_TYPE_RAW:
            status = sql_make_raw_border(stmt, border);
            break;

        case CT_TYPE_CLOB:
        case CT_TYPE_BLOB:
        case CT_TYPE_IMAGE:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
        case CT_TYPE_TIMESTAMP_TZ:
            status = CT_ERROR;
            break;

        default:
            status = var_convert(nlsparams, &border->var, datatype, NULL);
            break;
    }

    if (status != CT_SUCCESS) {
        if (CT_ERRNO == ERR_TYPE_OVERFLOW && sql_border_is_overflow(stmt, &border->var, datatype, wise)) {
            border->type = (wise == WISE_LEFT) ? BORDER_INFINITE_RIGHT : BORDER_INFINITE_LEFT;
        } else {
            border->type = (wise == WISE_LEFT) ? BORDER_INFINITE_LEFT : BORDER_INFINITE_RIGHT;
            cm_reset_error();
        }
    }
}

status_t sql_convert_part_key_l(sql_stmt_t *stmt, knl_index_desc_t *index_desc, scan_border_t *border,
    ct_type_t datatype, uint32 cid, void *part_key)
{
    knl_part_key_t *key = (knl_part_key_t *)part_key;

    if (border == NULL || border->type == BORDER_INFINITE_LEFT) {
        part_put_min(key->key);
        key->closed[cid] = CT_FALSE;
        return CT_SUCCESS;
    }

    key->closed[cid] = border->closed;
    if (border->type == BORDER_IS_NULL) {
        part_put_null(key->key);
        return CT_SUCCESS;
    }
    return sql_part_put_scan_key(stmt, &border->var, datatype, key->key);
}

static status_t sql_convert_part_key_r(sql_stmt_t *stmt, knl_index_desc_t *index_desc, scan_border_t *border,
    ct_type_t datatype, uint32 cid, void *part_key)
{
    knl_part_key_t *key = (knl_part_key_t *)part_key;

    if (border == NULL || border->type == BORDER_INFINITE_RIGHT) {
        part_put_max(key->key);
        key->closed[cid] = CT_FALSE;
        return CT_SUCCESS;
    }

    key->closed[cid] = border->closed;
    if (border->type == BORDER_IS_NULL) {
        part_put_null(key->key);
        return CT_SUCCESS;
    }
    return sql_part_put_scan_key(stmt, &border->var, datatype, key->key);
}

static void sql_merge_part_scan_key(part_scan_key_t *new_scan_key, part_assist_t *part_ass);
status_t sql_make_border_point(sql_stmt_t *stmt, knl_handle_t handle, scan_list_array_t *ar, uint32 part_key_id,
    knl_part_key_t *part_key, part_assist_t *pa, part_scan_key_t *part_scan_key)
{
    scan_range_list_t *list = &ar->items[part_key_id];
    scan_range_t *range = NULL;
    part_key_t old_part_key = *part_key->key;

    for (uint32 i = 0; i < list->count; i++) {
        range = list->ranges[i];
        CT_RETURN_IFERR(sql_convert_part_key_l(stmt, NULL, &range->left, list->datatype, part_key_id, part_key));
        if (part_key_id + 1 == ar->count) {
            if (part_scan_key->parent_partno == CT_INVALID_ID32) {
                part_scan_key->left = knl_locate_part_key(handle, part_key->key);
            } else {
                part_scan_key->left = knl_locate_subpart_key(handle, part_scan_key->parent_partno, part_key->key);
            }
            if (part_scan_key->left != CT_INVALID_ID32) {
                part_scan_key->right = part_scan_key->left + 1;
                sql_merge_part_scan_key(part_scan_key, pa);
            }
            part_scan_key->left = CT_INVALID_ID32;
        } else {
            CT_RETURN_IFERR(sql_make_border_point(stmt, handle, ar, part_key_id + 1, part_key, pa, part_scan_key));
        }
        *part_key->key = old_part_key;
    }
    return CT_SUCCESS;
}

/*
uint32 rid: the range id of first range list
*/
status_t sql_make_border_l(sql_stmt_t *stmt, knl_index_desc_t *index_desc, scan_list_array_t *ar, uint32 rid, void *key,
    bool32 *closed, sql_convert_border_t sql_convert_border_func)
{
    scan_range_list_t *list = &ar->items[0];
    scan_range_t *range = list->ranges[rid];

    *closed = range->left.closed ? CT_TRUE : CT_FALSE;
    CT_RETURN_IFERR(sql_convert_border_func(stmt, index_desc, &range->left, list->datatype, 0, key));

    for (uint32 i = 1; i < ar->count; i++) {
        list = &ar->items[i];

        /*  if not the first column, left border is always from ranges[0]
        ex: where f1 > 1 and f1 < 10 and (f2 > 100 and f2 < 200 or f2 > 300 and f2 < 500)
        the range is (1:20, 10:500)  */
        range = list->ranges[0];
        *closed = range->left.closed ? *closed : CT_FALSE;
        CT_RETURN_IFERR(sql_convert_border_func(stmt, index_desc, &range->left, list->datatype, i, key));
    }
    return CT_SUCCESS;
}

/**
 * uint32 rid: the range id of first range list
 * for part key, there is no need to pass arg 2(index)
 */
status_t sql_make_border_r(sql_stmt_t *stmt, knl_index_desc_t *index_desc, scan_list_array_t *ar, uint32 rid, void *key,
    bool32 *closed, bool32 *equal, sql_convert_border_t sql_convert_border_func)
{
    scan_range_list_t *list = &ar->items[0];
    scan_range_t *range = list->ranges[rid];

    *closed = range->right.closed ? CT_TRUE : CT_FALSE;
    *equal = range->type == RANGE_POINT ? CT_TRUE : CT_FALSE;
    CT_RETURN_IFERR(sql_convert_border_func(stmt, index_desc, &range->right, list->datatype, 0, key));

    for (uint32 i = 1; i < ar->count; i++) {
        list = &ar->items[i];
        range = list->ranges[list->count - 1];
        *closed = range->right.closed ? *closed : CT_FALSE;
        *equal = (list->count == 1 && range->type == RANGE_POINT) ? *equal : CT_FALSE;
        CT_RETURN_IFERR(sql_convert_border_func(stmt, index_desc, &range->right, list->datatype, i, key));
    }
    return CT_SUCCESS;
}

static status_t sql_calc_point_part(sql_stmt_t *stmt, knl_handle_t handle, scan_list_array_t *ar, part_assist_t *pa,
    knl_part_key_t *part_key, part_scan_key_t *part_scan_key)
{
    scan_range_list_t *list = &ar->items[0];

    part_scan_key->left = CT_INVALID_ID32;
    if (list->type == RANGE_LIST_FULL) {
        part_scan_key->left = 0;
        if (part_scan_key->parent_partno == CT_INVALID_ID32) {
            part_scan_key->right = knl_part_count(handle);
        } else {
            part_scan_key->right = knl_subpart_count(handle, part_scan_key->parent_partno);
        }
        sql_merge_part_scan_key(part_scan_key, pa);
    } else {
        part_key_init(part_key->key, ar->count);
        CT_RETURN_IFERR(sql_make_border_point(stmt, handle, ar, 0, part_key, pa, part_scan_key));
    }
    return CT_SUCCESS;
}

static status_t sql_calc_range_part(sql_stmt_t *stmt, knl_handle_t handle, scan_list_array_t *ar, uint32 rid,
    knl_part_key_t *part_key, part_scan_key_t *part_scan_key)
{
    uint32 right;
    bool32 is_subpart = (part_scan_key->parent_partno != CT_INVALID_ID32);
    bool32 equal = CT_FALSE;
    bool32 closed = CT_FALSE;

    // left border
    part_key_init(part_key->key, ar->count);
    CT_RETURN_IFERR(sql_make_border_l(stmt, NULL, ar, rid, part_key, &closed, sql_convert_part_key_l));

    if (!is_subpart) {
        part_scan_key->left = knl_locate_part_border(&stmt->session->knl_session, handle, part_key, CT_TRUE);
    } else {
        part_scan_key->left = knl_locate_subpart_border(&stmt->session->knl_session, handle, part_key,
            part_scan_key->parent_partno, CT_TRUE);
    }
    if (part_scan_key->left == CT_INVALID_ID32) {
        return CT_SUCCESS;
    }
    // right border
    part_key_init(part_key->key, ar->count);
    CT_RETURN_IFERR(sql_make_border_r(stmt, NULL, ar, rid, part_key, &closed, &equal, sql_convert_part_key_r));

    if (!is_subpart) {
        right = knl_locate_part_border(&stmt->session->knl_session, handle, part_key, CT_FALSE);
    } else {
        right = knl_locate_subpart_border(&stmt->session->knl_session, handle, part_key, part_scan_key->parent_partno,
            CT_FALSE);
    }
    if (right != CT_INVALID_ID32) {
        part_scan_key->right = right + 1;
    } else {
        part_scan_key->right =
            is_subpart ? knl_subpart_count(handle, part_scan_key->parent_partno) : knl_part_count(handle);
    }
    return CT_SUCCESS;
}

static void sql_part_assist_add(part_scan_key_t *part_scan_key, part_assist_t *part_ass, uint32 pos)
{
    for (uint32 i = part_ass->count; i > pos; i--) {
        part_ass->scan_key[i] = part_ass->scan_key[i - 1];
    }
    part_ass->scan_key[pos] = *part_scan_key;
    part_ass->count++;
}

static void sql_part_assist_del(part_assist_t *part_ass, uint32 pos)
{
    for (uint32 i = pos; i < part_ass->count; i++) {
        part_ass->scan_key[i] = part_ass->scan_key[i + 1];
    }
    part_ass->count--;
}

static void sql_merge_part_scan_key(part_scan_key_t *new_scan_key, part_assist_t *part_ass)
{
    uint32 loop = 0;

    while (loop < part_ass->count) {
        if (new_scan_key->left == part_ass->scan_key[loop].left) {
            new_scan_key->right = MAX(new_scan_key->right, part_ass->scan_key[loop].right);
            sql_part_assist_del(part_ass, loop);
            continue;
        }

        if (new_scan_key->left < part_ass->scan_key[loop].left) {
            if (new_scan_key->right >= part_ass->scan_key[loop].left) {
                new_scan_key->right = MAX(new_scan_key->right, part_ass->scan_key[loop].right);
                sql_part_assist_del(part_ass, loop);
                continue;
            }
            sql_part_assist_add(new_scan_key, part_ass, loop);
            return;
        }

        if (new_scan_key->left <= part_ass->scan_key[loop].right) {
            new_scan_key->left = part_ass->scan_key[loop].left;
            new_scan_key->right = MAX(new_scan_key->right, part_ass->scan_key[loop].right);
            sql_part_assist_del(part_ass, loop);
            continue;
        }
        loop++;
    }
    sql_part_assist_add(new_scan_key, part_ass, part_ass->count);
}

status_t sql_decode_list_value(part_decode_key_t *decoder, uint32 id, variant_t *value)
{
    uint32 len = decoder->lens[id];
    char *ptr = decoder->buf + decoder->offsets[id];

    value->is_null = (len == PART_KEY_NULL_LEN);
    CT_RETSUC_IFTRUE(value->is_null);

    switch (value->type) {
        case CT_TYPE_UINT32:
            VALUE(uint32, value) = *(uint32 *)ptr;
            return CT_SUCCESS;
        case CT_TYPE_INTEGER:
            VALUE(int32, value) = *(int32 *)ptr;
            return CT_SUCCESS;
        case CT_TYPE_BIGINT:
            if (len == sizeof(int32)) {
                VALUE(int64, value) = (int64)(*(int32 *)ptr);
                return CT_SUCCESS;
            }
            // fall through
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
            VALUE(int64, value) = *(int64 *)ptr;
            return CT_SUCCESS;
        case CT_TYPE_REAL:
            VALUE(double, value) = *(double *)ptr;
            return CT_SUCCESS;
        case CT_TYPE_STRING:
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
            VALUE_PTR(text_t, value)->str = ptr;
            VALUE_PTR(text_t, value)->len = len;
            return CT_SUCCESS;
        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
            (void)cm_dec_4_to_8(VALUE_PTR(dec8_t, value), (dec4_t *)ptr, len);
            return CT_SUCCESS;
        case CT_TYPE_INTERVAL_DS:
            VALUE(interval_ds_t, value) = *(interval_ds_t *)ptr;
            return CT_SUCCESS;
        case CT_TYPE_INTERVAL_YM:
            VALUE(interval_ym_t, value) = *(interval_ym_t *)ptr;
            return CT_SUCCESS;
        case CT_TYPE_RAW:
        case CT_TYPE_BINARY:
            VALUE_PTR(binary_t, value)->bytes = (uint8 *)ptr;
            VALUE_PTR(binary_t, value)->size = len;
            VALUE_PTR(binary_t, value)->is_hex_const = CT_FALSE;
            return CT_SUCCESS;
        case CT_TYPE_NUMBER2:
            return cm_dec_2_to_8(VALUE_PTR(dec8_t, value), (const payload_t *)ptr, len);
        default:
            CT_THROW_ERROR(ERR_ASSERT_ERROR, "unsupport partition key type");
            return CT_ERROR;
    }
}

status_t check_list_value_in_point_range(sql_stmt_t *stmt, scan_range_t *range, variant_t *value, bool32 *in_scan_range)
{
    int32 cmp_result;
    CT_RETURN_IFERR(sql_compare_variant(stmt, &range->left.var, value, &cmp_result));
    *in_scan_range = (cmp_result == 0);
    return CT_SUCCESS;
}

status_t check_list_value_in_section_range(sql_stmt_t *stmt, scan_range_t *range, variant_t *value,
    bool32 *in_scan_range)
{
    int32 cmp_result;
    if (range->left.type == BORDER_IS_NULL && range->right.type == BORDER_IS_NULL) {
        // when null is in (is null) cond, then range.left.type = BORDER_IS_NULL and range->right.type = BORDER_IS_NULL
        // when null is in other scale condition, then range->type = RANGE_EMPTY, this range should not be here
        *in_scan_range = value->is_null;
        return CT_SUCCESS;
    }
    if (range->left.type != BORDER_INFINITE_LEFT) {
        CT_RETURN_IFERR(sql_compare_variant(stmt, &range->left.var, value, &cmp_result));
        if (cmp_result > 0 || (cmp_result == 0 && !range->left.closed)) {
            return CT_SUCCESS;
        }
    }
    if (range->right.type != BORDER_INFINITE_RIGHT) {
        CT_RETURN_IFERR(sql_compare_variant(stmt, &range->right.var, value, &cmp_result));
        if (cmp_result < 0 || (cmp_result == 0 && !range->right.closed)) {
            return CT_SUCCESS;
        }
    }
    *in_scan_range = CT_TRUE;
    return CT_SUCCESS;
}

status_t check_list_value_in_scan_list(sql_stmt_t *stmt, scan_range_list_t *range_list, variant_t *value,
    bool32 *in_scan_list)
{
    scan_range_t *range = NULL;
    bool32 in_scan_range = CT_FALSE;
    for (uint32 range_id = 0; range_id < range_list->count; range_id++) {
        range = range_list->ranges[range_id];
        in_scan_range = CT_FALSE;
        switch (range->type) {
            case RANGE_SECTION:
                CT_RETURN_IFERR(check_list_value_in_section_range(stmt, range, value, &in_scan_range));
                break;
            case RANGE_POINT:
                CT_RETURN_IFERR(check_list_value_in_point_range(stmt, range, value, &in_scan_range));
                break;
            case RANGE_EMPTY:
                break;
            case RANGE_FULL:
            default:
                in_scan_range = CT_TRUE;
        }
        CT_BREAK_IF_TRUE(in_scan_range);
    }
    *in_scan_list = in_scan_range;
    return CT_SUCCESS;
}

status_t check_list_group_in_scan_list_array(sql_stmt_t *stmt, part_decode_key_t *decoder, scan_list_array_t *ar,
    part_table_t *part_table, bool32 is_subpart, bool32 *in_scan_list_array)
{
    bool32 in_scan_list = CT_FALSE;
    variant_t value;
    scan_range_list_t *range_list = NULL;

    for (uint32 part_key_id = 0; part_key_id < decoder->count; part_key_id++) {
        if (decoder->lens[part_key_id] == PART_KEY_DEFAULT_LEN) {
            *in_scan_list_array = CT_TRUE;
            return CT_SUCCESS;
        }
        value.type =
            is_subpart ? part_table->sub_keycols[part_key_id].datatype : part_table->keycols[part_key_id].datatype;
        CT_RETURN_IFERR(sql_decode_list_value(decoder, part_key_id, &value));
        range_list = &ar->items[part_key_id];
        CT_RETURN_IFERR(check_list_value_in_scan_list(stmt, range_list, &value, &in_scan_list));
        // if one list value does not exists in scan list, this list group does not match scan_list_array
        CT_BREAK_IF_TRUE(!in_scan_list);
    }
    *in_scan_list_array = in_scan_list;
    return CT_SUCCESS;
}

status_t sql_calc_list_part_by_range_cond(sql_stmt_t *stmt, knl_handle_t handle, scan_list_array_t *ar,
    part_assist_t *pa, uint32 parent_partnum)
{
    bool32 is_subpart = (parent_partnum != CT_INVALID_ID32);
    bool32 in_scan_list_array = CT_FALSE;
    uint32 part_count = is_subpart ? knl_subpart_count(handle, parent_partnum) : knl_part_count(handle);
    table_part_t *part = NULL;
    part_table_t *part_table = ((dc_entity_t *)handle)->table.part_table;
    part_decode_key_t *decode_key = NULL;
    part_scan_key_t part_scan_key;
    part_scan_key_t *new_part_scan_key = NULL;
    galist_t scan_key_list;

    cm_galist_init(&scan_key_list, stmt, (ga_alloc_func_t)sql_push);
    part_scan_key.sub_scan_key = NULL;
    part_scan_key.parent_partno = parent_partnum;
    part_scan_key.left = 0;
    part_scan_key.right = 0;

    for (uint32 part_id = 0; part_id < part_count; part_id++) {
        if (!is_subpart) {
            part = PART_GET_ENTITY(part_table, part_id);
        } else {
            part = PART_GET_ENTITY(part_table, parent_partnum);
            part = PART_GET_SUBENTITY(part_table, part->subparts[part_id]);
        }
        for (uint32 list_group_id = 0; list_group_id < part->desc.groupcnt; list_group_id++) {
            decode_key = &part->desc.groups[list_group_id];
            CT_RETURN_IFERR(
                check_list_group_in_scan_list_array(stmt, decode_key, ar, part_table, is_subpart, &in_scan_list_array));
            CT_BREAK_IF_TRUE(in_scan_list_array);
        }
        if (in_scan_list_array) {
            part_scan_key.right = part_id + 1;
            if (part_id + 1 != part_count) {
                continue;
            }
        }
        if (part_scan_key.left < part_scan_key.right) {
            CT_RETURN_IFERR(cm_galist_new(&scan_key_list, sizeof(part_scan_key_t), (void **)&new_part_scan_key));
            *new_part_scan_key = part_scan_key;
        }
        part_scan_key.left = part_id + 1;
    }
    pa->count = scan_key_list.count;
    CT_RETSUC_IFTRUE(scan_key_list.count == 0);
    CT_RETURN_IFERR(sql_push(stmt, sizeof(part_scan_key_t) * scan_key_list.count, (void **)&pa->scan_key));
    for (uint32 i = 0; i < scan_key_list.count; i++) {
        new_part_scan_key = (part_scan_key_t *)cm_galist_get(&scan_key_list, i);
        pa->scan_key[i] = *new_part_scan_key;
    }
    return CT_SUCCESS;
}

status_t sql_generate_part_scan_key(sql_stmt_t *stmt, knl_handle_t handle, scan_list_array_t *ar, part_assist_t *pa,
    uint32 parent_partno, bool32 *full_scan)
{
    knl_part_key_t part_key;
    scan_range_list_t *list = &ar->items[0];
    part_type_t part_type =
        (parent_partno == CT_INVALID_ID32) ? knl_part_table_type(handle) : knl_subpart_table_type(handle);
    if (part_type == PART_TYPE_LIST && (ar->flags & LIST_EXIST_RANGE_UNEQUAL)) {
        if (sql_calc_list_part_by_range_cond(stmt, handle, ar, pa, parent_partno) != CT_SUCCESS) {
            cm_reset_error();
            *full_scan = CT_TRUE;
        }
        return CT_SUCCESS;
    }

    part_scan_key_t part_scan_key;
    part_scan_key.sub_scan_key = NULL;
    part_scan_key.parent_partno = parent_partno;
    if (part_type == PART_TYPE_LIST || part_type == PART_TYPE_HASH) {
        uint32 max_part_count = list->count;
        for (uint32 i = 1; i < ar->count; i++) {
            list = &ar->items[i];
            if (CT_INVALID_ID32 / max_part_count <= list->count) {
                *full_scan = CT_TRUE;
                return CT_SUCCESS;
            }
            max_part_count *= list->count;
        }
        CT_RETURN_IFERR(sql_push(stmt, CT_MAX_COLUMN_SIZE, (void **)&part_key.key));
        CT_RETURN_IFERR(sql_push(stmt, max_part_count * sizeof(part_scan_key_t), (void **)&pa->scan_key));
        return sql_calc_point_part(stmt, handle, ar, pa, &part_key, &part_scan_key);
    }

    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_COLUMN_SIZE, (void **)&part_key.key));
    CT_RETURN_IFERR(sql_push(stmt, list->count * sizeof(part_scan_key_t), (void **)&pa->scan_key));
    for (uint32 i = 0; i < list->count; i++) {
        CT_RETURN_IFERR(sql_calc_range_part(stmt, handle, ar, i, &part_key, &part_scan_key));
        if (part_scan_key.left == CT_INVALID_ID32) {
            continue;
        }
        sql_merge_part_scan_key(&part_scan_key, pa);
    }
    return CT_SUCCESS;
}

static status_t sql_finalize_range_list_full(sql_stmt_t *stmt, scan_range_list_t *scan_list)
{
    scan_range_t *scan_range = NULL;

    CT_RETURN_IFERR(sql_push(stmt, sizeof(pointer_t), (void **)&scan_list->ranges));

    CT_RETURN_IFERR(sql_push(stmt, sizeof(scan_range_t), (void **)&scan_range));

    scan_range->type = RANGE_FULL;
    scan_range->left.type = BORDER_INFINITE_LEFT;
    scan_range->right.type = BORDER_INFINITE_RIGHT;
    scan_list->ranges[0] = scan_range;
    scan_list->count = 1;

    return CT_SUCCESS;
}

static status_t check_expr_node_contains_param(visit_assist_t *va, expr_node_t **node)
{
    if (va->result0 == CT_TRUE) {
        return CT_SUCCESS;
    }
    if ((*node)->type == EXPR_NODE_PARAM || (*node)->type == EXPR_NODE_CSR_PARAM) {
        va->result0 = CT_TRUE;
    }
    return CT_SUCCESS;
}

static bool32 check_expr_tree_contains_param(sql_stmt_t *stmt, expr_node_t *node)
{
    visit_assist_t va;
    sql_init_visit_assist(&va, stmt, NULL);
    va.result0 = CT_FALSE;
    if (visit_expr_node(&va, &node, check_expr_node_contains_param) != CT_SUCCESS) {
        cm_reset_error();
        return CT_TRUE;
    }
    return va.result0;
}

static inline bool32 can_exec_expr_in_explain(sql_stmt_t *stmt, expr_node_t *node)
{
    return (node->type == EXPR_NODE_CONST) ||
        (NODE_IS_FIRST_EXECUTABLE(node) && !check_expr_tree_contains_param(stmt, node));
}

static status_t sql_make_range_left(sql_stmt_t *stmt, plan_range_t *plan_range, scan_range_t *scan_range,
    ct_type_t datatype, uint32 size, calc_mode_t calc_mode)
{
    if (plan_range->left.type == BORDER_INFINITE_LEFT || plan_range->left.type == BORDER_IS_NULL) {
        scan_range->left.type = plan_range->left.type;
        return CT_SUCCESS;
    }

    if (stmt->is_explain && !can_exec_expr_in_explain(stmt, plan_range->left.expr->root)) {
        scan_range->left.type = BORDER_INFINITE_LEFT;
        return CT_SUCCESS;
    }
    scan_range->left.type = BORDER_CONST;

    if (calc_mode == CALC_IN_EXEC || calc_mode == CALC_IN_EXEC_PART_KEY ||
        sql_is_const_expr_node(plan_range->left.expr->root)) {
        CT_RETURN_IFERR(sql_exec_expr_node(stmt, plan_range->left.expr->root, &scan_range->left.var));
    } else {
        if (plan_range->type == RANGE_POINT) {
            scan_range->type = RANGE_ANY;
        } else {
            scan_range->type = RANGE_UNKNOWN;
        }
        return CT_SUCCESS;
    }
    sql_keep_stack_variant(stmt, &scan_range->left.var);

    variant_t *var = &scan_range->left.var;

    if (var->is_null) {
        scan_range->type = RANGE_EMPTY;
        return CT_SUCCESS;
    }

    scan_range->left.type = BORDER_CONST;

    if (datatype != var->type) {
        sql_make_difftype_border(stmt, &scan_range->left, datatype, size, WISE_LEFT);

        if (scan_range->left.type == BORDER_INFINITE_RIGHT) {
            scan_range->type = RANGE_EMPTY;
            return CT_SUCCESS;
        }
    } else {
        if (sql_check_border_variant(stmt, var, datatype, size) != CT_SUCCESS) {
            scan_range->left.type = BORDER_INFINITE_LEFT;
        }
    }

    return CT_SUCCESS;
}

static void sql_finalize_like_value(text_t *src, text_t *dst, char escape, bool32 has_escape)
{
    for (uint32 i = 0; i < src->len; i++) {
        if (has_escape && src->str[i] == escape) {
            if (i == src->len - 1) {
                break;
            }
            dst->str[dst->len++] = src->str[++i];
            continue;
        }
        if (src->str[i] == '%' || src->str[i] == '_') {
            break;
        }
        dst->str[dst->len++] = src->str[i];
    }
}

static status_t sql_finalize_like_range(sql_stmt_t *stmt, scan_range_t *scan_range, uint32 size, char escape,
    bool32 has_escape)
{
    uint32 padding;
    variant_t *var_l = NULL;
    variant_t *var_r = NULL;
    text_t v_text = {
        .str = NULL,
        .len = 0
    };

    scan_range->type = RANGE_FULL;
    scan_range->right.type = BORDER_INFINITE_RIGHT;

    if (scan_range->left.type == BORDER_INFINITE_LEFT) {
        return CT_SUCCESS;
    }

    if (!CT_IS_STRING_TYPE(scan_range->left.var.type)) {
        scan_range->left.type = BORDER_INFINITE_LEFT;
        return CT_SUCCESS;
    }

    var_l = &scan_range->left.var;
    CT_RETURN_IFERR(sql_push(stmt, var_l->v_text.len, (void **)&v_text.str));
    sql_finalize_like_value(&var_l->v_text, &v_text, escape, has_escape);
    var_l->v_text = v_text;

    if (var_l->v_text.len == 0) {
        scan_range->left.type = BORDER_INFINITE_LEFT;
        return CT_SUCCESS;
    }

    if (var_l->v_text.len > size) {
        scan_range->type = RANGE_EMPTY;
        return CT_SUCCESS;
    }

    scan_range->right = scan_range->left;
    if (var_l->v_text.len == size) {
        scan_range->type = RANGE_POINT;
        return CT_SUCCESS;
    }

    padding = (var_l->v_text.len == size - 1) ? 1 : 2;

    var_r = &scan_range->right.var;
    CT_RETURN_IFERR(sql_push(stmt, var_l->v_text.len + padding, (void **)&var_r->v_text.str));
    CT_RETURN_IFERR(cm_text_copy(&var_r->v_text, var_l->v_text.len + padding, &var_l->v_text));

    for (uint32 i = 0; i < padding; i++) {
        CM_TEXT_APPEND(&var_r->v_text, (char)255);
    }
    scan_range->type = RANGE_SECTION;
    return CT_SUCCESS;
}

static inline bool32 sql_quick_compare_border(scan_border_t *border1, scan_border_t *border2, int32 *result)
{
    if (border1->type == BORDER_INFINITE_LEFT) {
        *result = -1;
        return CT_TRUE;
    }

    if (border1->type == BORDER_INFINITE_RIGHT) {
        *result = 1;
        return CT_TRUE;
    }

    if (border2->type == BORDER_INFINITE_LEFT) {
        *result = 1;
        return CT_TRUE;
    }

    if (border2->type == BORDER_INFINITE_RIGHT) {
        *result = -1;
        return CT_TRUE;
    }

    if (border1->type == BORDER_IS_NULL) {
        *result = border2->type == BORDER_IS_NULL ? 0 : 1;
        return CT_TRUE;
    }

    if (border2->type == BORDER_IS_NULL) {
        *result = -1;
        return CT_TRUE;
    }
    return CT_FALSE;
}

static inline status_t sql_compare_right_border(scan_border_t *border1, scan_border_t *border2, int32 *result)
{
    if (sql_quick_compare_border(border1, border2, result)) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(var_compare_same_type(&border1->var, &border2->var, result));

    if (*result != 0) {
        return CT_SUCCESS;
    }

    if (border1->closed) {
        *result = border2->closed ? 0 : 1;
    } else {
        *result = border2->closed ? -1 : 0;
    }

    return CT_SUCCESS;
}

static inline status_t sql_compare_left_border(scan_border_t *border1, scan_border_t *border2, int32 *result)
{
    if (sql_quick_compare_border(border1, border2, result)) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(var_compare_same_type(&border1->var, &border2->var, result));

    if (*result != 0) {
        return CT_SUCCESS;
    }

    if (border1->closed) {
        *result = border2->closed ? 0 : -1;
    } else {
        *result = border2->closed ? 1 : 0;
    }

    return CT_SUCCESS;
}

// with this compare rule, if border1 is '1)' and border2 is '[1', they are equal.
static inline status_t sql_compare_border_with_relaxed_rule(scan_border_t *border1, scan_border_t *border2,
    int32 *result)
{
    if (sql_quick_compare_border(border1, border2, result)) {
        return CT_SUCCESS;
    }

    return var_compare_same_type(&border1->var, &border2->var, result);
}

static inline bool32 sql_check_range_right_datatype(sql_stmt_t *stmt, scan_range_t *scan_range, variant_t *var,
    ct_type_t datatype, uint32 size)
{
    if (datatype != var->type) {
        sql_make_difftype_border(stmt, &scan_range->right, datatype, size, WISE_RIGHT);

        if (scan_range->left.type == BORDER_INFINITE_LEFT && scan_range->right.type == BORDER_INFINITE_RIGHT) {
            scan_range->type = RANGE_FULL;
            return CT_TRUE;
        }
        if (scan_range->right.type == BORDER_INFINITE_LEFT) {
            scan_range->type = RANGE_EMPTY;
            return CT_TRUE;
        }
    } else {
        if (sql_check_border_variant(stmt, var, datatype, size) != CT_SUCCESS) {
            cm_reset_error();
            scan_range->right.type = BORDER_INFINITE_RIGHT;
        }
    }

    return CT_FALSE;
}

static status_t sql_make_range_right(sql_stmt_t *stmt, plan_range_t *plan_range, scan_range_t *scan_range,
    ct_type_t data_type, uint32 size, calc_mode_t calc_mode)
{
    int32 res;
    variant_t *var = &scan_range->right.var;

    if (plan_range->right.type == BORDER_INFINITE_RIGHT) {
        scan_range->right.type = BORDER_INFINITE_RIGHT;
    } else if (plan_range->right.type == BORDER_IS_NULL) {
        scan_range->right.type = BORDER_IS_NULL;
    } else {
        if (stmt->is_explain && !can_exec_expr_in_explain(stmt, plan_range->right.expr->root)) {
            scan_range->right.type = BORDER_INFINITE_RIGHT;
            return CT_SUCCESS;
        }

        if (calc_mode == CALC_IN_EXEC || calc_mode == CALC_IN_EXEC_PART_KEY ||
            sql_is_const_expr_node(plan_range->right.expr->root)) {
            CT_RETURN_IFERR(sql_exec_expr_node(stmt, plan_range->right.expr->root, &scan_range->right.var));
        } else {
            if (plan_range->type == RANGE_POINT) {
                scan_range->type = RANGE_ANY;
            } else {
                scan_range->type = RANGE_UNKNOWN;
            }
            return CT_SUCCESS;
        }

        sql_keep_stack_variant(stmt, &scan_range->right.var);

        scan_range->right.type = BORDER_CONST;

        if (var->is_null) {
            scan_range->type = RANGE_EMPTY;
            return CT_SUCCESS;
        }

        CT_RETSUC_IFTRUE(sql_check_range_right_datatype(stmt, scan_range, var, data_type, size));
    }

    CT_RETURN_IFERR(sql_compare_right_border(&scan_range->right, &scan_range->left, &res));

    scan_range->type = res < 0 ? RANGE_EMPTY : RANGE_SECTION;
    return CT_SUCCESS;
}

static status_t sql_finalize_range(sql_stmt_t *stmt, ct_type_t datatype, uint32 size, plan_range_t *plan_range,
    scan_range_t *scan_range, calc_mode_t calc_mode)
{
    scan_range->type = (range_type_t)plan_range->type;
    scan_range->left.closed = plan_range->left.closed;
    scan_range->right.closed = plan_range->right.closed;

    if (scan_range->type == RANGE_EMPTY || scan_range->type == RANGE_FULL) {
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(sql_make_range_left(stmt, plan_range, scan_range, datatype, size, calc_mode));

    if (scan_range->type == RANGE_EMPTY || // compare with null in sql_make_range_left
        scan_range->type == RANGE_UNKNOWN || scan_range->type == RANGE_ANY) {
        return CT_SUCCESS;
    }

    if (scan_range->type == RANGE_POINT) {
        if (scan_range->left.type == BORDER_INFINITE_LEFT) {
            scan_range->right.type = BORDER_INFINITE_RIGHT;
            scan_range->type = RANGE_FULL;
            return CT_SUCCESS;
        }

        scan_range->right.var = scan_range->left.var;
        scan_range->right.type = BORDER_CONST;
        return CT_SUCCESS;
    }

    if (scan_range->type == RANGE_LIKE) {
        bool8 has_escape = (plan_range->left.expr->next != NULL);
        char escape = CT_INVALID_INT8;
        if (has_escape) {
            variant_t escape_var;
            CT_RETURN_IFERR(sql_exec_expr(stmt, plan_range->left.expr->next, &escape_var));
            CT_RETURN_IFERR(sql_exec_escape_character(plan_range->left.expr->next, &escape_var, &escape));
        }
        return sql_finalize_like_range(stmt, scan_range, size, escape, has_escape);
    }
    return sql_make_range_right(stmt, plan_range, scan_range, datatype, size, calc_mode);
}

static bool32 sql_finalize_string_range(ct_type_t datatype, plan_range_list_t *plan_list, scan_range_t *scan_range)
{
    scan_border_t *border = NULL;
    uint32 left_var_len;

    if (scan_range->type == RANGE_EMPTY || scan_range->type == RANGE_FULL) {
        return CT_TRUE;
    }

    if (!CT_IS_STRING_TYPE(datatype)) {
        return CT_TRUE;
    }

    if (scan_range->left.type == BORDER_IS_NULL) {
        return CT_TRUE;
    }

    if (scan_range->type == RANGE_POINT) {
        // if left value size is larger than column define size,set range to empty.
        if (plan_list->typmode.is_char) { /* is char */
            if (CT_SUCCESS == GET_DATABASE_CHARSET->length(&scan_range->left.var.v_text, &left_var_len) &&
                left_var_len > (uint32)plan_list->typmode.size) {
                scan_range->type = RANGE_EMPTY;
                return CT_FALSE;
            }
        } else if (scan_range->left.var.v_text.len > (uint32)plan_list->typmode.size) { /* is byte */
            scan_range->type = RANGE_EMPTY;
            return CT_FALSE;
        }
        return CT_TRUE;
    }

    border = &scan_range->left;
    if (border->type != BORDER_INFINITE_LEFT && border->var.v_text.len > (uint32)plan_list->typmode.size) {
        border->var.v_text.len = (uint32)plan_list->typmode.size;
    }

    border = &scan_range->right;
    if (border->type != BORDER_INFINITE_RIGHT && border->var.v_text.len > (uint32)plan_list->typmode.size) {
        border->closed = CT_TRUE;
        border->var.v_text.len = (uint32)plan_list->typmode.size;
    }
    return CT_TRUE;
}

static inline void sql_insert_scan_range(scan_range_list_t *scan_range_list, uint32 id, scan_range_t *range)
{
    for (uint32 i = scan_range_list->count; i > id; i--) {
        scan_range_list->ranges[i] = scan_range_list->ranges[i - 1];
    }

    scan_range_list->ranges[id] = range;
    scan_range_list->count++;
}

typedef enum en_range_merge_mode {
    MERGE_EQUAL,      // range.left == list[i].left
    MERGE_LESS_GREAT, // range.left < list[i].left && range.right >= list[i].left
    MERGE_GREAT_LESS  // range.left > list[i].left && range.left <= list[i].right
} range_merge_mode_t;

static status_t sql_merge_scan_range(scan_range_list_t *scan_range_list, uint32 id, scan_range_t *range,
                                     range_merge_mode_t mode)
{
    uint32 i, merge_count;
    int32 result;
    scan_range_t *merge_range = NULL;

    if (mode == MERGE_LESS_GREAT) {
        scan_range_list->ranges[id]->type = RANGE_SECTION;
        scan_range_list->ranges[id]->left = range->left;
    }

    if (sql_compare_right_border(&range->right, &scan_range_list->ranges[id]->right, &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (result <= 0) {
        return CT_SUCCESS;
    }

    // if exists extra ranges need to merging
    // sample: put (20, 100) into [(30, 50), (60, 80), (110, 200)] <=> [(20, 100), (110, 200)]
    merge_count = 0;

    for (i = id + 1; i < scan_range_list->count; i++) {
        if (sql_compare_border_with_relaxed_rule(&range->right, &scan_range_list->ranges[i]->left, &result) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (result < 0) {
            break;
        }

        merge_count++;
    }

    merge_range = scan_range_list->ranges[id + merge_count];

    if (sql_compare_right_border(&range->right, &merge_range->right, &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    scan_range_list->ranges[id]->type = RANGE_SECTION;
    scan_range_list->ranges[id]->right = result >= 0 ? range->right : merge_range->right;

    // remove extra merged ranges
    for (i = id + 1; i < scan_range_list->count - merge_count; i++) {
        scan_range_list->ranges[i] = scan_range_list->ranges[i + merge_count];
    }

    scan_range_list->count -= merge_count;
    return CT_SUCCESS;
}

static status_t sql_put_scan_range(scan_range_list_t *list, scan_range_t *range)
{
    int32 result;

    if (range->type == RANGE_EMPTY || range->type == RANGE_UNKNOWN || range->type == RANGE_ANY) {
        return CT_SUCCESS;
    }

    if (range->type == RANGE_FULL) {
        list->type = RANGE_LIST_FULL;
        return CT_SUCCESS;
    }

    if (list->count == 0) {
        list->type = RANGE_LIST_NORMAL;
        list->ranges[0] = range;
        list->count = 1;
        return CT_SUCCESS;
    }

    for (uint32 i = 0; i < list->count; i++) {
        CT_RETURN_IFERR(sql_compare_left_border(&range->left, &list->ranges[i]->left, &result));

        if (result == 0) {
            return sql_merge_scan_range(list, i, range, MERGE_EQUAL);
        }

        if (result < 0) {
            CT_RETURN_IFERR(sql_compare_border_with_relaxed_rule(&range->right, &list->ranges[i]->left, &result));

            if (result >= 0) {
                return sql_merge_scan_range(list, i, range, MERGE_LESS_GREAT);
            }

            sql_insert_scan_range(list, i, range);
            return CT_SUCCESS;
        }

        CT_RETURN_IFERR(sql_compare_border_with_relaxed_rule(&range->left, &list->ranges[i]->right, &result));

        if (result <= 0) {
            return sql_merge_scan_range(list, i, range, MERGE_GREAT_LESS);
        }
    }

    sql_insert_scan_range(list, list->count, range);
    return CT_SUCCESS;
}

static bool32 if_need_finalize_range(sql_stmt_t *stmt, plan_range_list_t *plan_list, scan_range_list_t *scan_list,
    status_t *status)
{
    scan_list->type = plan_list->type;
    scan_list->datatype = plan_list->typmode.datatype;
    scan_list->count = 0;
    scan_list->rid = 0;
    *status = CT_SUCCESS;

    if (scan_list->type == RANGE_LIST_EMPTY) {
        return CT_FALSE;
    }

    if (scan_list->type == RANGE_LIST_FULL) {
        *status = sql_finalize_range_list_full(stmt, scan_list);
        return CT_FALSE;
    }

    if (sql_push(stmt, plan_list->items->count * sizeof(pointer_t), (void **)&scan_list->ranges) != CT_SUCCESS) {
        *status = CT_ERROR;
        return CT_FALSE;
    }

    return CT_TRUE;
}

static inline bool32 if_range_result_can_cache(plan_range_t *plan_range)
{
    if (plan_range->left.type != BORDER_INFINITE_LEFT && plan_range->left.type != BORDER_INFINITE_RIGHT &&
        plan_range->left.type != BORDER_CONST && plan_range->left.type != BORDER_IS_NULL) {
        return CT_FALSE;
    }

    if (plan_range->right.type != BORDER_INFINITE_LEFT && plan_range->right.type != BORDER_INFINITE_RIGHT &&
        plan_range->right.type != BORDER_CONST && plan_range->right.type != BORDER_IS_NULL) {
        return CT_FALSE;
    }

    return CT_TRUE;
}

static inline bool32 sql_set_list_flag(range_type_t type, uint32 *list_flag)
{
    switch (type) {
        case RANGE_UNKNOWN:
            *list_flag |= LIST_EXIST_LIST_UNKNOWN;
            return CT_TRUE;
        case RANGE_ANY:
            if (*list_flag & LIST_EXIST_LIST_ANY) {
                *list_flag |= LIST_EXIST_LIST_UNKNOWN;
            } else {
                *list_flag |= LIST_EXIST_LIST_ANY;
            }
            return CT_TRUE;
        default:
            break;
    }
    return CT_FALSE;
}

static bool32 sql_find_cache_range(galist_t *index_scan_range_ar, plan_range_list_t *plan_list,
    scan_list_info **scan_list_item_result, sql_table_t *table, uint32 ar_countid, calc_mode_t calc_mode)
{
    if (index_scan_range_ar == NULL) {
        return CT_FALSE;
    }

    // the parameter '_INDEX_SACN_RANGE_CACHE' control this optimization's switch
    if (g_instance->sql.index_scan_range_cache == 0 ||
        plan_list->items->count < g_instance->sql.index_scan_range_cache) {
        return CT_FALSE;
    }

    scan_list_info *tmp = NULL;

    for (uint32 i = 0; i < index_scan_range_ar->count; i++) {
        tmp = (scan_list_info *)cm_galist_get(index_scan_range_ar, i);
        if (calc_mode == CALC_IN_EXEC_PART_KEY && tmp->tab_id == table->id && tmp->ar_countid == ar_countid) {
            *scan_list_item_result = tmp;
            return CT_TRUE;
        }
        if (calc_mode == CALC_IN_EXEC && tmp->tab_id == table->id && tmp->index_id == table->index->id &&
            tmp->ar_countid == ar_countid) {
            *scan_list_item_result = tmp;
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

status_t inline clone_buff_consuming_type(vmc_t *vmc, scan_border_t *dest, scan_border_t *src)
{
    if (src->type == BORDER_INFINITE_LEFT || src->type == BORDER_INFINITE_RIGHT || src->type == BORDER_IS_NULL ||
        src->var.is_null == CT_TRUE || src->var.v_text.len == 0) {
        return CT_SUCCESS;
    }

    if (CT_IS_BUFF_CONSUMING_TYPE(src->var.type)) {
        CT_RETURN_IFERR(vmc_alloc(vmc, dest->var.v_text.len, (void **)&(dest->var.v_text.str)));
        MEMS_RETURN_IFERR(
            memcpy_s(dest->var.v_text.str, dest->var.v_text.len, src->var.v_text.str, src->var.v_text.len));
    }

    return CT_SUCCESS;
}

status_t sql_clone_scan_list_ranges(vmc_t *vmc, scan_range_t **list_range, scan_range_t *src_range)
{
    CT_RETURN_IFERR(vmc_alloc(vmc, sizeof(scan_range_t), (void **)list_range));
    (*list_range)->left = src_range->left;
    (*list_range)->right = src_range->right;
    CT_RETURN_IFERR(clone_buff_consuming_type(vmc, &(*list_range)->left, &src_range->left));
    CT_RETURN_IFERR(clone_buff_consuming_type(vmc, &(*list_range)->right, &src_range->right));
    (*list_range)->type = src_range->type;

    return CT_SUCCESS;
}

status_t sql_clone_scan_list(vmc_t *vmc, scan_range_list_t *src_scan_list, scan_range_list_t **dest_scan_list)
{
    scan_range_list_t *list = NULL;

    CT_RETURN_IFERR(vmc_alloc(vmc, sizeof(scan_range_list_t), (void **)&list));
    list->type = src_scan_list->type;
    list->count = src_scan_list->count;
    list->datatype = src_scan_list->datatype;
    list->rid = src_scan_list->rid;
    CT_RETURN_IFERR(vmc_alloc(vmc, src_scan_list->count * sizeof(pointer_t), (void **)&(list->ranges)));

    for (uint32 i = 0; i < src_scan_list->count; i++) {
        sql_clone_scan_list_ranges(vmc, &(list->ranges[i]), src_scan_list->ranges[i]);
    }
    *dest_scan_list = list;

    return CT_SUCCESS;
}

status_t inline sql_init_index_scan_range_ar(vmc_t *vmc, galist_t **range_ar)
{
    if (*range_ar == NULL) {
        CT_RETURN_IFERR(vmc_alloc(vmc, sizeof(galist_t), (void **)range_ar));
        cm_galist_init(*range_ar, vmc, vmc_alloc);
    }

    return CT_SUCCESS;
}

static inline void sql_get_cache_range(scan_list_array_t *ar, scan_range_list_t *dest_scan_list,
    scan_list_info *scan_list_item_result)
{
    *dest_scan_list = *scan_list_item_result->scan_list;
    ar->flags = scan_list_item_result->flags;
}

status_t sql_cache_range(galist_t **list, scan_list_array_t *ar, scan_range_list_t *scan_range_list, vmc_t *vmc,
    sql_table_t *table, uint32 ar_countid, calc_mode_t calc_mode)
{
    scan_range_list_t *scan_list_copy = NULL;
    scan_list_info *scan_list_item = NULL;

    if ((*list) != NULL && (*list)->count > MAX_CACHE_COUNT) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_clone_scan_list(vmc, scan_range_list, &scan_list_copy));
    CT_RETURN_IFERR(vmc_alloc(vmc, sizeof(scan_list_info), (void **)&scan_list_item));
    scan_list_item->scan_list = scan_list_copy;
    scan_list_item->tab_id = table->id;
    if (calc_mode == CALC_IN_EXEC) {
        scan_list_item->index_id = table->index->id;
    }
    scan_list_item->ar_countid = ar_countid;
    scan_list_item->flags = ar->flags;
    CT_RETURN_IFERR(sql_init_index_scan_range_ar(vmc, list));
    return cm_galist_insert(*list, scan_list_item);
}


status_t sql_finalize_range_list(sql_stmt_t *stmt, plan_range_list_t *plan_list, scan_range_list_t *scan_range_list,
    uint32 *list_flag, calc_mode_t calc_mode, uint32 *is_optm)
{
    plan_range_t *plan_range = NULL;
    scan_range_t *scan_range = NULL;
    status_t status;
    uint32 i;

    // the parameter '_INDEX_SACN_RANGE_CACHE' control this optimization's switch
    if (g_instance->sql.index_scan_range_cache == 0 ||
        plan_list->items->count < g_instance->sql.index_scan_range_cache) {
        *is_optm = CT_FALSE;
    }

    if (!if_need_finalize_range(stmt, plan_list, scan_range_list, &status)) {
        return status;
    }

    for (i = 0; i < plan_list->items->count; i++) {
        plan_range = (plan_range_t *)cm_galist_get(plan_list->items, i);
        if (*is_optm == CT_TRUE && !if_range_result_can_cache(plan_range)) {
            *is_optm = CT_FALSE;
        }

        if (cm_stack_alloc(stmt->session->stack, sizeof(scan_range_t), (void **)&scan_range) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_STACK_OVERFLOW);
            return CT_ERROR;
        }

        if (sql_finalize_range(stmt, scan_range_list->datatype, (uint32)plan_list->typmode.size, plan_range, scan_range,
            calc_mode) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (sql_set_list_flag(scan_range->type, list_flag)) {
            return CT_SUCCESS;
        }

        if (!sql_finalize_string_range(scan_range_list->datatype, plan_list, scan_range)) {
            continue;
        }

        CT_RETURN_IFERR(sql_put_scan_range(scan_range_list, scan_range));

        if (scan_range_list->type == RANGE_LIST_FULL) {
            return sql_finalize_range_list_full(stmt, scan_range_list);
        }

        if (scan_range->type != RANGE_POINT) {
            *list_flag |= LIST_EXIST_RANGE_UNEQUAL;
        }
    }

    if (scan_range_list->count == 0) {
        scan_range_list->type = RANGE_LIST_EMPTY;
    } else if (scan_range_list->count > 1) {
        *list_flag |= LIST_EXIST_MULTI_RANGES;
    }

    return CT_SUCCESS;
}

status_t sql_finalize_scan_range(sql_stmt_t *stmt, sql_array_t *plan_ranges, scan_list_array_t *ar, sql_table_t *table,
    sql_cursor_t *cursor, galist_t **list, calc_mode_t calc_mode)
{
    plan_range_list_t *plan_list = NULL;
    scan_list_info *scan_list_item_result = NULL;

    if (sql_push(stmt, ar->count * sizeof(scan_range_list_t), (void **)&ar->items) != CT_SUCCESS) {
        return CT_ERROR;
    }

    for (uint32 i = 0; i < ar->count; i++) {
        plan_list = (plan_range_list_t *)plan_ranges->items[i];

        if (cursor != NULL && sql_find_cache_range(*list, plan_list, &scan_list_item_result, table, i, calc_mode)) {
            sql_get_cache_range(ar, &ar->items[i], scan_list_item_result);
        } else {
            bool32 is_optm = CT_TRUE;
            if (sql_finalize_range_list(stmt, plan_list, &ar->items[i], &ar->flags, calc_mode, &is_optm) !=
                CT_SUCCESS) {
                return CT_ERROR;
            }
            if (cursor != NULL && is_optm) {
                CT_RETURN_IFERR(sql_cache_range(list, ar, &ar->items[i], &cursor->vmc, table, i, calc_mode));
            }
        }

        if (ar->items[i].type == RANGE_LIST_EMPTY) {
            ar->flags |= LIST_EXIST_LIST_EMPTY;
            return CT_SUCCESS;
        }
        if (ar->items[i].type == RANGE_LIST_FULL) {
            ar->flags |= LIST_EXIST_LIST_FULL;
        }
        ar->total_ranges = i == 0 ? ar->items[i].count : ar->items[i].count * ar->total_ranges;
    }
    return CT_SUCCESS;
}
