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
 * ctsql_expr.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/node/ctsql_expr.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_EXPR_H__
#define __SQL_EXPR_H__

#include "cm_defs.h"
#include "cm_list.h"
#include "var_inc.h"
#include "cm_lex.h"
#include "ctsql_stmt.h"
#include "ctsql_expr_def.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline ct_type_t sql_get_func_arg1_datatype(const expr_node_t *func_node)
{
    CM_POINTER3(func_node, func_node->argument, func_node->argument->root);
    return func_node->argument->root->datatype;
}

static inline ct_type_t sql_get_func_arg2_datatype(const expr_node_t *func_node)
{
    CM_POINTER2(func_node, func_node->argument);
    CM_POINTER2(func_node->argument->root, func_node->argument->next->root);
    return func_node->argument->next->root->datatype;
}

void sql_init_visit_assist(visit_assist_t *visit_ass, sql_stmt_t *stmt, sql_query_t *query);
const text_t *sql_get_nodetype_text(expr_node_type_t node_type);
typedef status_t (*visit_func_t)(visit_assist_t *va, expr_node_t **node);
status_t visit_expr_node(visit_assist_t *visit_ass, expr_node_t **node, visit_func_t visit_func);
status_t visit_expr_tree(visit_assist_t *visit_ass, expr_tree_t *tree, visit_func_t visit_func);
status_t visit_func_node(visit_assist_t *visit_ass, expr_node_t *node, visit_func_t visit_func);

bool32 sql_expr_tree_equal(sql_stmt_t *stmt, expr_tree_t *tree1, expr_tree_t *tree2, uint32 *tab_map);
status_t sql_get_reserved_value(sql_stmt_t *stmt, expr_node_t *node, variant_t *val);
status_t sql_convert_to_scn(sql_stmt_t *stmt, void *expr, bool32 scn_type, uint64 *scn);
status_t sql_exec_expr_node(sql_stmt_t *stmt, expr_node_t *node, variant_t *result);
bool32 sql_expr_node_exist_table(expr_node_t *node, uint32 table_id);
bool32 sql_expr_node_exist_ancestor_table(expr_node_t *node, uint32 table_id, uint32 is_ancestor);
#define sql_expr_exist_table(expr, table_id) sql_expr_node_exist_table((expr)->root, table_id)
#define sql_expr_exist_ancestor_table(expr, table_id, is_ancestor) \
    sql_expr_node_exist_ancestor_table((expr)->root, table_id, is_ancestor)

bool32 sql_is_const_expr_node(const expr_node_t *node);
bool32 sql_is_const_expr_tree(expr_tree_t *expr);
bool32 sql_expr_tree_in_tab_list(sql_array_t *tables, expr_tree_t *expr_tree, bool32 use_remote_id, bool32 *exist_col);
status_t sql_try_optimize_const_expr(sql_stmt_t *stmt, expr_node_t *node);
status_t sql_get_serial_value(sql_stmt_t *stmt, knl_dictionary_t *dc, variant_t *value);
status_t sql_expr_tree_walker(sql_stmt_t *stmt, expr_tree_t *expr_tree,
    status_t (*fetch)(sql_stmt_t *stmt, expr_node_t *node, void *context), void *context);
status_t sql_expr_node_walker(sql_stmt_t *stmt, expr_node_t *node,
    status_t (*fetch)(sql_stmt_t *stmt, expr_node_t *node, void *context), void *context);
status_t sql_exec_oper(sql_stmt_t *stmt, expr_node_t *node, variant_t *result);
void sql_copy_first_exec_var(sql_stmt_t *stmt, variant_t *src, variant_t *dst);

static status_t inline sql_exec_expr(sql_stmt_t *stmt, expr_tree_t *expr, variant_t *result)
{
    return sql_exec_expr_node(stmt, expr->root, result);
}

static inline uint32 sql_expr_list_len(expr_tree_t *list)
{
    uint32 len = 1;
    while (list->next != NULL) {
        len++;
        list = list->next;
    }

    return len;
}

static inline expr_tree_t *sql_expr_list_last(expr_tree_t *list)
{
    expr_tree_t *expr = list;
    while (expr->next != NULL) {
        expr = expr->next;
    }

    return expr;
}

static inline status_t sql_compare_expr(sql_stmt_t *stmt, expr_tree_t *expr1, expr_tree_t *expr2, int32 *result)
{
    variant_t var1, var2;

    if (sql_exec_expr(stmt, expr1, &var1) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (sql_exec_expr(stmt, expr2, &var2) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (sql_compare_variant(stmt, &var1, &var2, result) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_exec_default(void *stmt, void *default_expr, variant_t *val);
status_t sql_get_func_index_expr_size(knl_handle_t session, text_t *default_text, typmode_t *typmode);
bool32 sql_compare_index_expr(knl_handle_t session, text_t *func_text1, text_t *func_text2);
status_t sql_exec_index_col_func(knl_handle_t sess, knl_handle_t knl_cursor, ct_type_t datatype, void *expr,
    variant_t *result, bool32 is_new);
/* The following rules describe the skipped expr type, that do not make
 * static-checking */
static inline bool32 sql_is_skipped_expr(const expr_tree_t *expr)
{
    if (TREE_IS_RES_NULL(expr) || TREE_IS_RES_DEFAULT(expr)) {
        return CT_TRUE;
    }

    if (TREE_IS_BINDING_PARAM(expr)) {
        return CT_TRUE;
    }

    if (CT_TYPE_UNKNOWN == TREE_DATATYPE(expr)) {
        return CT_TRUE;
    }

    return CT_FALSE;
}


status_t sql_exec_concat(sql_stmt_t *stmt, variant_t *l_var, variant_t *r_var, variant_t *result);
status_t sql_exec_unary(expr_node_t *node, variant_t *var);

static inline bool32 sql_is_single_column(expr_node_t *expr_node)
{
    return (expr_node->type == EXPR_NODE_COLUMN);
}

static inline bool32 sql_is_single_const_or_param(expr_node_t *expr_node)
{
    return (bool32)(NODE_IS_CONST(expr_node) || NODE_IS_PARAM(expr_node) || NODE_IS_CSR_PARAM(expr_node));
}

static inline bool32 sql_is_single_const(expr_node_t *expr_node)
{
    return NODE_IS_CONST(expr_node);
}

static inline bool32 sql_expr_tree_belong_tab_list(sql_array_t *tables, expr_tree_t *expr_tree, bool32 use_remote_id)
{
    bool32 exist_col = CT_FALSE;
    return (bool32)(sql_expr_tree_in_tab_list(tables, expr_tree, use_remote_id, &exist_col) && exist_col);
}

static inline void sql_convert_lob_type(expr_node_t *node, ct_type_t datatype)
{
    if (datatype == CT_TYPE_CLOB || datatype == CT_TYPE_IMAGE) {
        node->typmod.datatype = CT_TYPE_STRING;
    } else if (datatype == CT_TYPE_BLOB) {
        node->typmod.datatype = CT_TYPE_RAW;
    }
}

status_t sql_clone_expr_tree(void *ctx, expr_tree_t *src_expr_tree, expr_tree_t **dest_expr_tree,
    ga_alloc_func_t alloc_mem_func);
status_t sql_clone_expr_node(void *ctx, expr_node_t *src_node, expr_node_t **dest_expr_node,
                             ga_alloc_func_t alloc_mem_func);
status_t sql_clone_var_column(void *ctx, var_column_t *src, var_column_t *dest_col, ga_alloc_func_t alloc_mem_func);
bool32 sql_expr_node_equal(sql_stmt_t *stmt, expr_node_t *node1, expr_node_t *node2, uint32 *table_map);
status_t sql_get_lob_value_from_knl(sql_stmt_t *stmt, variant_t *res);
status_t sql_get_lob_value_from_vm(sql_stmt_t *stmt, variant_t *result);
status_t sql_get_lob_value(sql_stmt_t *stmt, variant_t *result);
status_t sql_get_lob_value_from_normal(sql_stmt_t *stmt, variant_t *res);
status_t sql_get_expr_datatype(sql_stmt_t *stmt, expr_tree_t *expr, ct_type_t *type);
status_t sql_get_param_value(sql_stmt_t *stmt, uint32 id, variant_t *result);
status_t sql_get_expr_unique_table(sql_stmt_t *stmt, expr_node_t *node, uint16 *tab, uint32 *ancestor);
status_t sql_get_subarray_to_value(array_assist_t *array_ass, vm_lob_t *src, int32 start, int32 end, ct_type_t type,
                                   variant_t *value);
status_t sql_get_element_to_value(sql_stmt_t *stmt, array_assist_t *array_ass, vm_lob_t *src, int32 start, int32 end,
                                  ct_type_t type, variant_t *value);
status_t sql_exec_array_element(sql_stmt_t *stmt, array_assist_t *aa, uint32 subscript, variant_t *element_val,
                                bool32 last, vm_lob_t *vlob);
expr_node_t *sql_find_column_in_func(expr_node_t *node);

extern cols_used_t g_cols_used_init;

static inline void init_cols_used(cols_used_t *cols_used)
{
    uint32 loop;

    *cols_used = g_cols_used_init;
    cols_used->collect_sub_select = CT_TRUE;
    for (loop = 0; loop < RELATION_LEVELS; ++loop) {
        biqueue_init(&cols_used->cols_que[loop]);
    }
}

void sql_collect_cols_in_expr_tree(expr_tree_t *tree, cols_used_t *used_cols);
void sql_collect_cols_in_expr_node(expr_node_t *node, cols_used_t *used_cols);
status_t add_node_2_parent_ref_core(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node, uint32 tab,
    uint32 temp_ancestor);

// in case include ctsql_cond.h
void sql_collect_cols_in_cond(void *cond_node, cols_used_t *used_cols);

static inline expr_node_t *sql_any_self_col_node(cols_used_t *cols_used)
{
    expr_node_t *col_node = OBJECT_OF(expr_node_t, biqueue_first(&cols_used->cols_que[SELF_IDX]));
    return col_node;
}

static inline bool32 sql_is_same_tab(expr_node_t *l_col, expr_node_t *r_col, uint32 *tab1, uint32 *tab2)
{
    uint32 l_tab = TAB_OF_NODE(l_col);
    uint32 r_tab = TAB_OF_NODE(r_col);

    if (tab1 != NULL) {
        *tab1 = l_tab;
    }

    if (tab2 != NULL) {
        *tab2 = r_tab;
    }
    return (l_tab == r_tab);
}

static inline bool32 sql_can_equal_used_by_hash(cols_used_t *l_cols_used, cols_used_t *r_cols_used, uint32 *tab1,
    uint32 *tab2)
{
    // make sure each side has not sub-query use parent and ancestor columns
    // this constraint can be broken when sub-query use only ancestor columns
    // or use the columns of same table that other columns used in the expr
    if (HAS_DYNAMIC_SUBSLCT(l_cols_used) || HAS_DYNAMIC_SUBSLCT(r_cols_used)) {
        return CT_FALSE;
    }

    // make sure each side have only self columns, and belong to one table
    if (!HAS_ONLY_SELF_COLS(l_cols_used->flags) || !HAS_ONLY_SELF_COLS(r_cols_used->flags) ||
        HAS_DIFF_TABS(l_cols_used, SELF_IDX) || HAS_DIFF_TABS(r_cols_used, SELF_IDX)) {
        return CT_FALSE;
    }

    // make sure no prior expr node
    if (HAS_ROWNUM(l_cols_used) || HAS_PRIOR(l_cols_used) || HAS_ROWNUM(r_cols_used) || HAS_PRIOR(r_cols_used)) {
        return CT_FALSE;
    }

    expr_node_t *l_col = sql_any_self_col_node(l_cols_used);
    expr_node_t *r_col = sql_any_self_col_node(r_cols_used);
    return !sql_is_same_tab(l_col, r_col, tab1, tab2);
}

static inline bool32 sql_can_equal_used_by_hash2(cols_used_t *l_cols_used, cols_used_t *r_cols_used)
{
    uint32 l_idx, r_idx;

    // make sure one side has self columns and one side has parent columns
    if ((!HAS_ONLY_SELF_COLS(l_cols_used->flags) || !HAS_ONLY_PARENT_COLS(r_cols_used->flags)) &&
        (!HAS_ONLY_SELF_COLS(r_cols_used->flags) || !HAS_ONLY_PARENT_COLS(l_cols_used->flags))) {
        return CT_FALSE;
    }

    l_idx = HAS_SELF_COLS(l_cols_used->flags) ? (r_idx = PARENT_IDX, SELF_IDX) : (r_idx = SELF_IDX, PARENT_IDX);

    uint8 left_ret = HAS_DIFF_TABS(l_cols_used, l_idx);
    uint8 right_ret = HAS_DIFF_TABS(r_cols_used, r_idx);
    return (bool32)(!left_ret && !right_ret);
}

status_t sql_check_not_support_reserved_value_shard(reserved_wid_t type);

static inline status_t sql_generate_origin_ref(sql_stmt_t *stmt, rs_column_t *rs_col, expr_node_t **origin_ref)
{
    SAVE_AND_RESET_NODE_STACK(stmt);
    if (rs_col->type == RS_COL_CALC) {
        CT_RETURN_IFERR(sql_clone_expr_node(stmt->context, rs_col->expr->root, origin_ref, sql_alloc_mem));
    } else {
        CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)origin_ref));
        (*origin_ref)->type = EXPR_NODE_COLUMN;
        (*origin_ref)->typmod = rs_col->typmod;
        CT_RETURN_IFERR(
            sql_clone_var_column(stmt->context, &rs_col->v_col, &((*origin_ref)->value.v_col), sql_alloc_mem));
    }
    SQL_RESTORE_NODE_STACK(stmt);
    return CT_SUCCESS;
}

static inline expr_node_t *sql_get_origin_ref(expr_node_t *expr_node)
{
    if (expr_node->type != EXPR_NODE_GROUP) {
        return expr_node;
    }
    return sql_get_origin_ref((expr_node_t *)expr_node->value.v_vm_col.origin_ref);
}

static inline void sql_set_expr_node_ancestor(expr_node_t *expr_node, uint32 ancestor)
{
    if (expr_node->type == EXPR_NODE_COLUMN) {
        NODE_ANCESTOR(expr_node) = ancestor;
    } else if (expr_node->type == EXPR_NODE_GROUP) {
        NODE_VM_ANCESTOR(expr_node) = ancestor;
    } else if (expr_node->type == EXPR_NODE_RESERVED && (expr_node)->value.v_int == RES_WORD_ROWID) {
        ROWID_NODE_ANCESTOR(expr_node) = ancestor;
    }
}

static inline status_t sql_set_group_expr_node(sql_stmt_t *stmt, expr_node_t *node, uint32 id, uint32 group_id,
    uint32 ancestor, expr_node_t *origin_ref)
{
    SAVE_AND_RESET_NODE_STACK(stmt);
    if (origin_ref == NULL) {
        CT_RETURN_IFERR(sql_clone_expr_node(stmt->context, node, &origin_ref, sql_alloc_mem));
    }
    node->type = EXPR_NODE_GROUP;
    node->value.type = CT_TYPE_INTEGER;
    VALUE_PTR(var_vm_col_t, &node->value)->id = (uint16)id;
    VALUE_PTR(var_vm_col_t, &node->value)->group_id = (uint16)group_id;
    VALUE_PTR(var_vm_col_t, &node->value)->ancestor = ancestor;
    VALUE_PTR(var_vm_col_t, &node->value)->is_ddm_col = CT_FALSE;
    VALUE_PTR(var_vm_col_t, &node->value)->origin_ref = origin_ref;
    if ((origin_ref->type == EXPR_NODE_COLUMN) && (origin_ref->value.v_col.is_ddm_col == CT_TRUE)) {
        VALUE_PTR(var_vm_col_t, &node->value)->is_ddm_col = CT_TRUE;
        origin_ref->value.v_col.is_ddm_col = CT_FALSE;
    }
    SQL_RESTORE_NODE_STACK(stmt);
    return CT_SUCCESS;
}

static inline status_t sql_slct_add_ref_node(void *owner, expr_node_t *node, ga_alloc_func_t alloc_mem_func)
{
    if (node->type != EXPR_NODE_SELECT) {
        return CT_SUCCESS;
    }

    sql_select_t *slct = (sql_select_t *)node->value.v_obj.ptr;
    if (slct->ref_nodes == NULL) {
        CT_RETURN_IFERR(alloc_mem_func(owner, sizeof(galist_t), (void **)&slct->ref_nodes));
        cm_galist_init(slct->ref_nodes, owner, alloc_mem_func);
    }

    return cm_galist_insert(slct->ref_nodes, node);
}

static inline void sql_slct_del_ref_node(sql_stmt_t *stmt, expr_node_t *node)
{
    if (node->type != EXPR_NODE_SELECT) {
        return;
    }

    sql_select_t *slct = (sql_select_t *)node->value.v_obj.ptr;
    if (slct->ref_nodes != NULL) {
        for (uint32 i = 0; i < slct->ref_nodes->count;) {
            if (node == cm_galist_get(slct->ref_nodes, i)) {
                cm_galist_delete(slct->ref_nodes, i);
                continue;
            }
            i++;
        }
    }
    return;
}

static inline status_t sql_modify_ref_nodes_subslct(sql_stmt_t *stmt, sql_select_t *old_slct, sql_select_t *new_slct)
{
    if (old_slct->ref_nodes == NULL) {
        return CT_SUCCESS;
    }

    if (new_slct->ref_nodes == NULL) {
        CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(galist_t), (void **)&new_slct->ref_nodes));
        cm_galist_init(new_slct->ref_nodes, stmt->context, sql_alloc_mem);
    }

    expr_node_t *node = NULL;
    for (uint32 i = 0; i < old_slct->ref_nodes->count; i++) {
        node = (expr_node_t *)cm_galist_get(old_slct->ref_nodes, i);
        if (node->type != EXPR_NODE_SELECT) {
            continue;
        }
        node->value.v_obj.ptr = new_slct;
        CT_RETURN_IFERR(cm_galist_insert(new_slct->ref_nodes, node));
    }
    return CT_SUCCESS;
}

status_t sql_exec_concat_lob_value(sql_stmt_t *stmt, const char *buf, uint32 size, vm_lob_t *vlob);
status_t sql_get_sequence_value(sql_stmt_t *stmt, var_seq_t *vseq, variant_t *val);
status_t sql_create_rowid_expr(sql_stmt_t *stmt, uint32 tab, expr_tree_t **expr);

extern node_func_tab_t *g_expr_calc_funcs[];
static inline node_func_tab_t *sql_get_node_func(sql_node_type_t type)
{
    return &g_expr_calc_funcs[(type / EXPR_NODE_CONST)][(type % EXPR_NODE_CONST)];
}

static inline status_t sql_get_expr_node_value(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    return sql_get_node_func((sql_node_type_t)node->type)->invoke(stmt, node, result);
}

static inline var_address_pair_t *sql_get_last_addr_pair(expr_node_t *addr)
{
    galist_t *pairs = addr->value.v_address.pairs;
    if (pairs->count == 0) {
        return NULL;
    }
    return (var_address_pair_t *)cm_galist_get(pairs, pairs->count - 1);
}

static inline bool32 sql_pair_type_is_plvar(expr_node_t *node)
{
    CM_ASSERT(node->type == EXPR_NODE_V_ADDR);
    return (node->value.v_address.pairs->count == 1);
}

bool32 chk_has_sharding_tab(sql_stmt_t *stmt);
status_t sql_clone_text(void *ctx, text_t *src, text_t *dest, ga_alloc_func_t alloc_mem_func);
status_t sql_set_pl_dc_for_user_func(void *verify_in, expr_node_t *node, pointer_t pl_dc_in);
var_udo_t *sql_node_get_obj(expr_node_t *node);
#ifdef __cplusplus
}
#endif

#endif
