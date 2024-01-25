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
 * plan_rbo.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/plan/plan_rbo.c
 *
 * -------------------------------------------------------------------------
 */
#include "plan_rbo.h"
#include "ctsql_verifier.h"
#include "ctsql_func.h"
#include "dml_parser.h"
#include "knl_dc.h"
#include "cbo_base.h"
#include "ctsql_scan.h"
#include "srv_instance.h"
#include "plan_query.h"

#ifdef __cplusplus
extern "C" {
#endif
static inline void sql_set_func_arg_name(expr_node_t *column, expr_node_t *func)
{
    expr_tree_t *arg = func->argument;

    while (arg != NULL) {
        if (arg->root != NULL && arg->root->type == EXPR_NODE_COLUMN &&
            arg->root->value.v_col.col == column->value.v_col.col) {
            arg->root->word = column->word;
            break;
        }
        arg = arg->next;
    }
}

bool32 rbo_find_column_in_func_args(query_field_t *query_field, knl_index_desc_t *index, uint16 idx_id)
{
    knl_icol_info_t *col_info = &index->columns_info[idx_id];
    for (uint16 j = 0; j < col_info->arg_count; j++) {
        if (col_info->arg_cols[j] == query_field->col_id) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

bool32 rbo_find_column_in_func_index(query_field_t *query_field, knl_index_desc_t *index, sql_table_t *table)
{
    for (uint16 i = 0; i < index->column_count; i++) {
        if (index->columns[i] < DC_VIRTUAL_COL_START) {
            if (index->columns[i] == query_field->col_id) {
                return CT_TRUE;
            }
        } else if (rbo_find_column_in_func_args(query_field, index, i)) {
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

static inline status_t sql_get_col_ref_count(visit_assist_t *visit_ass, expr_node_t **node)
{
    uint32 *col_ref_map = (uint32 *)(visit_ass->param0);
    if ((*node)->type == EXPR_NODE_COLUMN) {
        col_ref_map[NODE_COL(*node)]++;
    }

    return CT_SUCCESS;
}

static inline bool32 can_use_func_index_only(sql_query_t *query)
{
    if (!g_instance->sql.enable_func_idx_only || query->winsort_list->count > 0) {
        return CT_FALSE;
    }

    for (uint32 i = 0; i < query->tables.count; i++) {
        sql_table_t *table = sql_array_get(&query->tables, i);
        if (table->type != NORMAL_TABLE) {
            return CT_FALSE;
        }
    }

    return CT_TRUE;
}

bool32 chk_part_key_match_index(dc_entity_t *entity, uint32 part_key_count, knl_index_desc_t *index, uint16 equal_to)
{
    return CT_FALSE;
}

static inline status_t sql_de_adjust_node_type(visit_assist_t *visit_ass, expr_node_t **node)
{
    if ((*node)->type == EXPR_NODE_DIRECT_COLUMN) {
        (*node)->value.v_col.tab = (uint16)visit_ass->result0;
        (*node)->type = EXPR_NODE_COLUMN;
    }

    return CT_SUCCESS;
}

void rbo_update_column_in_func(sql_stmt_t *stmt, expr_node_t **node, uint32 table_id)
{
    visit_assist_t visit_ass;
    sql_init_visit_assist(&visit_ass, stmt, NULL);
    visit_ass.result0 = table_id;
    (void)visit_expr_node(&visit_ass, node, sql_de_adjust_node_type);
}

status_t sql_get_index_col_node(sql_stmt_t *stmt, knl_column_t *knl_col, expr_node_t *column_node, expr_node_t **node,
    uint32 table_id, uint32 col_id)
{
    if (!KNL_COLUMN_IS_VIRTUAL(knl_col)) {
        column_node->value.v_col.ancestor = 0;
        column_node->value.v_col.tab = table_id;
        column_node->value.v_col.col = (uint16)col_id;
        column_node->value.v_col.datatype = knl_col->datatype;
        column_node->datatype = knl_col->datatype;
        column_node->type = EXPR_NODE_COLUMN;
        column_node->unary = UNARY_OPER_NONE;
        *node = column_node;
    } else {
        CT_RETURN_IFERR(
            sql_clone_expr_node((void *)stmt, ((expr_tree_t *)knl_col->default_expr)->root, node, sql_stack_alloc));
        rbo_update_column_in_func(stmt, node, table_id);
    }
    return CT_SUCCESS;
}

/* !
 * \brief Covert a variant into ROWNUM type. When a ROWNUM is in comparison operation,
 * we need to convert another operand into rownum type. The default ROWNUM type is
 * INT32, however, some users may provides a double type for ROWNUM comparison.
 *
 */
static inline status_t var_as_rownum(variant_t *var, ct_type_t type)
{
    if (type == CT_TYPE_REAL) {
        return var_as_real(var);
    } else {
        return var_as_integer(var);
    }
}

#define CONVER_VAR_TO_ROWNUM_TYPE(var, type)      \
    if (var_as_rownum(var, type) != CT_SUCCESS) { \
        return CT_ERROR;                          \
    }

status_t rbo_try_rownum_optmz(sql_stmt_t *stmt, cond_node_t *node, uint32 *max_rownum, bool8 *rnum_pending)
{
    return CT_SUCCESS;
}

static inline void rbo_get_opt_full_scan_flag(plan_assist_t *pa, sql_table_t *table, knl_index_desc_t **opt_index,
    uint16 *opt_scan_flag, uint8 *opt_index_dsc)
{
    *opt_index = NULL;
    *opt_scan_flag = *opt_index_dsc = 0;
}


#ifdef __cplusplus
}
#endif
