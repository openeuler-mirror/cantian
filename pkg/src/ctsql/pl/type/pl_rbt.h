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
 * pl_rbt.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/type/pl_rbt.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef _PL_RBT_H
#define _PL_RBT_H

#include "ctsql_stmt.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RBT_RED 0
#define RBT_BLACK 1

typedef struct st_rbt_node {
    mtrl_rowid_t parent;
    mtrl_rowid_t right;
    mtrl_rowid_t left;
    int32 color;
} rbt_node_t;

typedef status_t (*rbt_key_cmp_t)(sql_stmt_t *, mtrl_rowid_t, variant_t *, int32 *);
typedef status_t (*rbt_node_cmp_t)(sql_stmt_t *, mtrl_rowid_t, mtrl_rowid_t, int32 *);

typedef struct st_rbt_tree {
    mtrl_rowid_t root;
    mtrl_rowid_t nil_node;
    uint32 node_count;
    rbt_key_cmp_t key_cmp;
    rbt_node_cmp_t node_cmp;
} rbt_tree_t;

#define RBT_INIT_NODE(node)               \
    do {                                  \
        (node)->parent = g_invalid_entry; \
        (node)->left = g_invalid_entry;   \
        (node)->right = g_invalid_entry;  \
        (node)->color = RBT_RED;          \
    } while (0)

/* This macro is used to scan red-black tree from head. User can continue,
 * break or return in scan loop, but user can't delete node in scan loop.
 */
#define RBT_SCAN(stmt, rbt_tree, node)                                             \
    for (rbt_first_node((stmt), (rbt_tree), (node)); IS_VALID_MTRL_ROWID(*(node)); \
        rbt_next_node((stmt), (rbt_tree), (*(node)), (node)))

/* This macro is used to scan red-black tree by inorder traversal.
 * User can continue, break or return in scan loop, and also user can delete node in scan loop.
 */
#define RBT_INORDER_SCAN(stmt, rbt_tree, curr_rowid, nex_rowid)          \
    for (rbt_first_node((stmt), (rbt_tree), (curr_rowid)),               \
        rbt_next_node((stmt), (rbt_tree), (*(curr_rowid)), (nex_rowid)); \
        IS_VALID_MTRL_ROWID(*(curr_rowid));                              \
        (*(curr_rowid)) = (*(nex_rowid)), rbt_next_node((stmt), (rbt_tree), (*(nex_rowid)), (nex_rowid)))

#define RBT_BACK_SCAN(stmt, rbt_tree, curr_rowid, nex_rowid)              \
    for (rbt_last_node((stmt), (rbt_tree), (curr_rowid)),                 \
        rbt_prior_node((stmt), (rbt_tree), (*(curr_rowid)), (nex_rowid)); \
        IS_VALID_MTRL_ROWID(*(curr_rowid));                               \
        (*(curr_rowid)) = (*(nex_rowid)), rbt_prior_node((stmt), (rbt_tree), (*(nex_rowid)), (nex_rowid)))

status_t rbt_left_rotate_node(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, mtrl_rowid_t node_x);
status_t rbt_right_rotate_node(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, mtrl_rowid_t node_y);
status_t rbt_search_node(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, variant_t *index, mtrl_rowid_t *parent,
    mtrl_rowid_t *result);
status_t rbt_get_rowid_by_key(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, variant_t *index, mtrl_rowid_t *result);
status_t rbt_insert_node(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, mtrl_rowid_t *parent, mtrl_rowid_t new_node,
    bool8 flag);
status_t rbt_delete_node(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, mtrl_rowid_t tmp_del_node);
status_t rbt_first_node(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, mtrl_rowid_t *result);
status_t rbt_last_node(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, mtrl_rowid_t *result);
status_t rbt_next_node(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, mtrl_rowid_t tmp_node, mtrl_rowid_t *result);
status_t rbt_prior_node(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, mtrl_rowid_t tmp_node, mtrl_rowid_t *result);

#ifdef __cplusplus
}
#endif

#endif
