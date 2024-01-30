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
 * ctsql_cond.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/node/ctsql_cond.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_COND_H__
#define __SQL_COND_H__

#include "ctsql_expr.h"
#include "cm_bilist.h"

/*
CAUTION!!!: don't change the value of cond_node_type
in column default value / check constraint, the id is stored in system table COLUMN$
*/
typedef enum en_cond_node_type {
    COND_NODE_UNKNOWN = 0, /* init status */
    COND_NODE_COMPARE = 1,
    COND_NODE_OR = 2,    /* logic OR  */
    COND_NODE_AND = 3,   /* logic AND */
    COND_NODE_NOT = 4,   /* logic NOT, it will be converted to COND_NODE_COMPARE in parsing phase */
    COND_NODE_TRUE = 5,  /* logic NOT, it will be converted to COND_NODE_COMPARE in parsing phase */
    COND_NODE_FALSE = 6, /* logic NOT, it will be converted to COND_NODE_COMPARE in parsing phase */
} cond_node_type_t;

typedef struct st_cmp_node {
    int32 join_type;
    cmp_type_t type;    /* = <>, >, <, like, in, is, is not, not like, not in, */
    expr_tree_t *left;  /* expr of left variant */
    expr_tree_t *right; /* expr of right variant */
    bool8 rnum_pending;
    bool8 has_conflict_chain; // f1 = f2 and f1 = 10
    bool8 anti_join_cond;     // anti join cond can not eliminate outer join
    bool8 unused;
} cmp_node_t;

typedef struct st_join_symbol_cmp {
    cmp_node_t *cmp_node; /* t1.f1 = t3.f1(+) */
    uint32 right_tab;     /* t1 */
    uint32 left_tab;      /* t3 */
} join_symbol_cmp_t;

typedef struct st_cond_node {
    cond_node_type_t type;
    bool32 processed;
    struct st_cond_node *left;
    struct st_cond_node *right;
    cmp_node_t *cmp; /* only used for node type is COND_NODE_COMPARE */

    // don't change the definition order of prev and next
    // so cond_node_t can be change to biqueue_node_t by macro QUEUE_NODE_OF
    // and be added to a biqueue
    struct st_cond_node *prev;
    struct st_cond_node *next;
} cond_node_t;

#define CONSTRUCT_COND_TREE(cond_node, add_left, cond_ori_child, cond_new_child) \
    if (add_left) {                                                              \
        (cond_node)->left = (cond_new_child);                                    \
        (cond_node)->right = (cond_ori_child);                                   \
    } else {                                                                     \
        (cond_node)->left = (cond_ori_child);                                    \
        (cond_node)->right = (cond_new_child);                                   \
    }

typedef struct st_cond_chain {
    cond_node_t *first;
    cond_node_t *last;
    uint32 count;
} cond_chain_t;

typedef struct st_cond_tree {
    void *owner;
    ga_alloc_func_t alloc_func;
    cond_node_t *root;
    uint32 incl_flags;
    source_location_t loc;
    cond_chain_t chain;
    /* max_rownum records the upper rownum in the condition tree.
     * It can be used for ROWNUM optimization
     * The default value of max_rownum is infinity
     */
    uint32 rownum_upper;
    bool8 rownum_pending;
    bool8 unused[3];
    struct st_cond_tree *clone_src;
} cond_tree_t;

typedef struct st_join_cond {
    bilist_node_t bilist_node;
    uint32 table1;
    uint32 table2;
    galist_t cmp_nodes;

    // below for outer join
    bool8 is_new_add;
    sql_join_type_t join_type;
    cond_tree_t *filter;
    cond_tree_t *join_cond;
} join_cond_t;
/* * Evaluate an expression tree of a compare node */

#define SQL_EXEC_CMP_OPERAND(expr, var, res, pending, stmt)       \
    do {                                                          \
        if (sql_exec_expr((stmt), (expr), (var)) != CT_SUCCESS) { \
            return CT_ERROR;                                      \
        }                                                         \
        if ((var)->type == CT_TYPE_COLUMN) {                      \
            (*(res)) = COND_TRUE;                                 \
            (*(pending)) = CT_TRUE;                               \
            return CT_SUCCESS;                                    \
        }                                                         \
        if (CT_IS_LOB_TYPE((var)->type)) {                        \
            CT_RETURN_IFERR(sql_get_lob_value((stmt), (var)));    \
        }                                                         \
    } while (0)

/* * Evaluate an expression tree of a compare node, and filter NULL value.
 * * Additionally, the result variant is kept in stack for later using.  */
#define SQL_EXEC_CMP_OPERAND_EX(expr, var, res, pending, stmt)         \
    do {                                                               \
        SQL_EXEC_CMP_OPERAND((expr), (var), (res), (pending), (stmt)); \
        sql_keep_stack_variant((stmt), (var));                           \
    } while (0)

/* for dml cond check, unknown means false */
status_t sql_match_cond(void *arg, bool32 *result);
status_t sql_match_cond_node(sql_stmt_t *stmt, cond_node_t *node, bool32 *result);
status_t sql_match_cond_argument(sql_stmt_t *stmt, cond_node_t *node, bool32 *pending, cond_result_t *res);
status_t sql_match_cond_tree(void *stmt, void *node, cond_result_t *result);
status_t sql_split_filter_cond(sql_stmt_t *stmt, cond_node_t *src, cond_tree_t **dst_tree);
status_t sql_create_cond_tree(sql_context_t *context, cond_tree_t **cond);
status_t sql_merge_cond_tree(cond_tree_t *orign_cond, cond_node_t *from_node);
status_t sql_clone_cond_tree(void *ctx, cond_tree_t *src, cond_tree_t **dst, ga_alloc_func_t alloc_mem_func);
status_t sql_clone_cond_node(void *ctx, cond_node_t *src, cond_node_t **dst, ga_alloc_func_t alloc_mem_func);
status_t sql_clone_cmp_node(void *ctx, cmp_node_t *src, cmp_node_t **dst, ga_alloc_func_t alloc_mem_func);
status_t sql_add_cond_node_left(cond_tree_t *orign_cond, cond_node_t *node);
status_t sql_add_cond_node(cond_tree_t *orign_cond, cond_node_t *node);
status_t sql_add_cond_node_core(cond_tree_t *orign_cond, cond_node_t *node, bool8 add_left);
status_t sql_get_cond_node_pos(cond_node_t *root_cond, cmp_node_t *cmp_node, cond_node_t **node_pos);
bool32 sql_cond_node_in_tab_list(sql_array_t *tables, cond_node_t *cond_node, bool32 use_remote_id, bool32 *exist_col);
bool32 sql_cond_node_exist_table(cond_node_t *cond_node, uint32 table_id);
bool32 sql_cond_node_has_prior(cond_node_t *cond_node);
status_t sql_extract_join_from_cond(cond_node_t *cond_node, uint32 table1, uint32 table2, galist_t *join_nodes,
    bool32 *has_join_cond);
status_t sql_cond_tree_walker(sql_stmt_t *stmt, cond_tree_t *cond_tree,
    status_t (*fetch)(sql_stmt_t *stmt, expr_node_t *node, void *context), void *context);
void sql_convert_match_result(cmp_type_t cmp_type, int32 cmp_result, bool32 *res);
status_t sql_exec_expr_list(sql_stmt_t *stmt, expr_tree_t *list, uint32 count, variant_t *vars, bool32 *pending,
    expr_tree_t **last);
#ifdef Z_SHARDING
bool32 sql_check_where_cond_has_subquery(cond_node_t *cond);
bool32 sql_ancestor_tables_in_cond_node(sql_array_t *tables, cond_node_t *cond_node);
#endif
status_t try_eval_compare_node(sql_stmt_t *stmt, cond_node_t *node, uint32 *rnum_upper, bool8 *rnum_pending);
void try_eval_logic_and(cond_node_t *cond_node);
void try_eval_logic_or(cond_node_t *cond_node);

extern status_t rbo_try_rownum_optmz(sql_stmt_t *stmt, cond_node_t *node, uint32 *max_rownum, bool8 *rnum_pending);

status_t sql_split_cond(sql_stmt_t *stmt, sql_array_t *tables, cond_tree_t **cond_tree_result, cond_tree_t *cond_tree,
    bool32 use_remote_id);
status_t sql_rebuild_cond(sql_stmt_t *stmt, cond_tree_t **cond_tree_result, cond_tree_t *cond_tree, bool32 *ignore);
status_t sql_extract_filter_cond(sql_stmt_t *stmt, sql_array_t *tables, cond_tree_t **dst_tree, cond_node_t *cond_node);
bool32 sql_chk_cond_degrade_join(cond_node_t *cond, sql_join_node_t *join_node, bool32 is_right_node,
    bool32 is_outer_right, bool32 *not_null);
status_t sql_adjust_inner_join_cond(sql_stmt_t *stmt, sql_join_node_t *join_node, cond_tree_t **cond_tree);
status_t sql_merge_cond_tree_shallow(cond_tree_t *orign_cond, cond_node_t *from_node);
status_t sql_union_cond_node(sql_context_t *context, cond_tree_t **dst, cond_node_t *from_node);
bool32 sql_cond_node_equal(sql_stmt_t *stmt, cond_node_t *cond1, cond_node_t *cond2, uint32 *tab_map);
bool32 sql_cmp_node_equal(sql_stmt_t *stmt, cmp_node_t *cmp1, cmp_node_t *cmp2, uint32 *tab_map);
void sql_set_exists_query_flag(sql_stmt_t *stmt, select_node_t *select_node);
status_t sql_match_pivot_list(sql_stmt_t *stmt, expr_tree_t *for_expr, expr_tree_t *in_expr, int32 *index);
status_t visit_cond_node(visit_assist_t *va, cond_node_t *cond, visit_func_t visit_func);
bool32 sql_cond_has_acstor_col(sql_stmt_t *stmt, cond_tree_t *cond, sql_query_t *subqry);
status_t visit_join_node_cond(visit_assist_t *va, sql_join_node_t *join_node, visit_func_t visit_func);
bool32 sql_is_join_node(cond_node_t *cond_node, uint32 table1, uint32 table2);
status_t sql_exec_escape_character(expr_tree_t *expr, variant_t *var, char *escape);
status_t sql_try_simplify_new_cond(sql_stmt_t *stmt, cond_node_t *cond);

// compare node can be pushed up and used as join condition:
// 1.expr1 (flag==HAS_PARENT_COLS) = expr2(flag==HAS_SELF_COLS)
// compare node can be pushed up and used as filter condition:
#define FIRST_NOT_AND_NODE(cond) ((cond)->next ? (cond)->next : (cond))
static inline void add_node_2_chain(cond_node_t *root, cond_node_t *node)
{
    if (root == node) {
        return;
    }
    if (root->prev != NULL) {
        root->prev->next = node;
        node->prev = root->prev;
        root->prev = node;
        node->next = NULL;
        return;
    }
    root->prev = node;
    root->next = node;
    node->prev = node->next = NULL;
}

static inline status_t visit_cmp_node(visit_assist_t *va, cmp_node_t *cmp, visit_func_t visit_func)
{
    CT_RETURN_IFERR(visit_expr_tree(va, cmp->left, visit_func));
    return visit_expr_tree(va, cmp->right, visit_func);
}

static inline void reorganize_cond_tree(cond_node_t *root);
static inline void reorganize_cond_tree_node(cond_node_t *root, cond_node_t *cond)
{
    switch (cond->type) {
        case COND_NODE_AND:
            reorganize_cond_tree_node(root, cond->left);
            reorganize_cond_tree_node(root, cond->right);
            break;
        case COND_NODE_OR:
            reorganize_cond_tree(cond->left);
            reorganize_cond_tree(cond->right);
            add_node_2_chain(root, cond);
            break;
        default:
            add_node_2_chain(root, cond);
            break;
    }
}

static inline void reorganize_cond_tree(cond_node_t *root)
{
    root->prev = root->next = NULL;
    reorganize_cond_tree_node(root, root);
}

static inline status_t try_eval_logic_cond(sql_stmt_t *stmt, cond_node_t *node)
{
    CT_RETURN_IFERR(sql_stack_safe(stmt));

    switch (node->type) {
        case COND_NODE_OR:
            CT_RETURN_IFERR(try_eval_logic_cond(stmt, node->left));
            CT_RETURN_IFERR(try_eval_logic_cond(stmt, node->right));
            try_eval_logic_or(node);
            break;
        case COND_NODE_AND:
            CT_RETURN_IFERR(try_eval_logic_cond(stmt, node->left));
            CT_RETURN_IFERR(try_eval_logic_cond(stmt, node->right));
            try_eval_logic_and(node);
            break;
        default:
            break;
    }
    return CT_SUCCESS;
}

static inline void sql_init_cond_tree(void *owner, cond_tree_t *cond, ga_alloc_func_t alloc_func)
{
    CM_POINTER2(owner, cond);
    MEMS_RETVOID_IFERR(memset_s(cond, sizeof(cond_tree_t), 0, sizeof(cond_tree_t)));
    cond->owner = owner;
    cond->alloc_func = alloc_func;
    cond->rownum_upper = CT_INFINITE32;
    cond->rownum_pending = CT_FALSE;
}

#endif