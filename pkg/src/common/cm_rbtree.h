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
 * cm_rbtree.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_rbtree.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_RBTREE_H__
#define __CM_RBTREE_H__
#include "cm_defs.h"
#include "cm_types.h"
#include "cm_bilist.h"
#include "cm_error.h"

#define RB_RED      0
#define RB_BLACK    1
#define RBTREE_NODE_OF(type, node, field) ((type *)((char *)(node)-OFFSET_OF(type, field)))

typedef struct st_rb_node {
    struct st_rb_node *left;
    struct st_rb_node *right;
    struct st_rb_node *parent;
    uint32 color;
} rb_node_t;

typedef int32(*rb_cmp_func_t)(rb_node_t* left_val, rb_node_t* right_val);
typedef void(*rb_free_func_t)(void* ptr);

typedef struct st_rbtree {
    rb_node_t *root;
    rb_node_t nil_node;
    uint32 node_count;
    rb_cmp_func_t cmp_func;
} rb_tree_t;

#define RB_TREE_SCAN(rb_tree, rb_node)                                 \
    for ((rb_node) = cm_rbtree_first_node(rb_tree); (rb_node) != NULL; \
         (rb_node) = cm_rbtree_next_node((rb_tree), (rb_node)))

#define RB_TREE_BACK_SCAN(rb_tree, rb_node)                             \
    for ((rb_node) = cm_rbtree_last_node((rb_tree)); (rb_node) != NULL; \
         (rb_node) = cm_rbtree_prev_node((rb_tree), (rb_node)))

void cm_rbtree_init(rb_tree_t *rb_tree, rb_cmp_func_t cmp_func);
status_t cm_rbtree_insert_node(rb_tree_t *rb_tree, rb_node_t *new_node);
void cm_rbtree_delete_node(rb_tree_t *rb_tree, rb_node_t *node);
rb_node_t *cm_rbtree_search_node(rb_tree_t *rb_tree, rb_node_t *key_node);
rb_node_t *cm_rbtree_first_node(rb_tree_t *rb_tree);
rb_node_t *cm_rbtree_next_node(rb_tree_t *rb_tree, rb_node_t *node);
rb_node_t *cm_rbtree_last_node(rb_tree_t *rb_tree);
rb_node_t *cm_rbtree_prev_node(rb_tree_t *rb_tree, rb_node_t *node);
void cm_rbtree_free_tree(rb_tree_t *rb_tree, rb_free_func_t free_func);

#endif