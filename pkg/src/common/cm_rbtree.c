/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * cm_rbtree.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_rbtree.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_rbtree.h"

#define NIL_NODE(rb_tree)             (&(rb_tree)->nil_node)
#define ROOT_NODE(rb_tree)            ((rb_tree)->root)
#define IS_LEFT_CHILD_NODE(node)      (node)->parent->left == (node)
#define IS_BLACK_NODE(node)           (node)->color == RB_BLACK
#define IS_RED_NODE(node)             (node)->color == RB_RED
 
void cm_rbtree_init(rb_tree_t *rb_tree, rb_cmp_func_t cmp_func)
{
    rb_tree->node_count = 0;
    rb_tree->nil_node.color = RB_BLACK;
    rb_tree->nil_node.left = NULL;
    rb_tree->nil_node.right = NULL;
    rb_tree->nil_node.parent = NULL;
    rb_tree->root = &(rb_tree->nil_node);
    rb_tree->cmp_func = cmp_func;
}

static void cm_rbtree_left_rotate_node(rb_tree_t *rb_tree, rb_node_t *node_x)
{
    /*
    *   x                       y
    *  / \                     / \
    * lx  y      ----->       x  ry
    *    / \                 / \
    *   ly ry               lx ly
    */
    rb_node_t *node_y = NULL;
    rb_node_t *nil_parent = NULL;

    CM_ASSERT(rb_tree != NULL);
    CM_ASSERT(node_x != NULL);

    nil_parent = NIL_NODE(rb_tree)->parent;
    node_y = node_x->right;

    node_x->right = node_y->left;
    node_y->left->parent = node_x;
    
    node_y->parent = node_x->parent;

    if (node_x->parent == NIL_NODE(rb_tree)) {
        rb_tree->root = node_y;
    } else {
        if (IS_LEFT_CHILD_NODE(node_x)) {
            node_x->parent->left = node_y;
        } else {
            node_x->parent->right = node_y;
        }
    }
    
    node_x->parent = node_y;
    node_y->left = node_x;

    NIL_NODE(rb_tree)->parent = nil_parent;
}


static void cm_rbtree_right_rotate_node(rb_tree_t *rb_tree, rb_node_t *node_y)
{
    /*
    *      y                   x
    *     / \                 / \
    *    x  ry   ----->      lx  y
    *   / \                     / \
    * lx  rx                   rx ry
    */
    rb_node_t *node_x = NULL;
    rb_node_t *nil_parent = NULL;

    CM_ASSERT(rb_tree != NULL);
    CM_ASSERT(node_y != NULL);

    nil_parent = NIL_NODE(rb_tree)->parent;
    node_x = node_y->left;
    
    node_y->left = node_x->right;
    node_x->right->parent = node_y;

    node_x->parent = node_y->parent;

    if (node_y->parent == NIL_NODE(rb_tree)) {
        rb_tree->root = node_x;
    } else {
        if (IS_LEFT_CHILD_NODE(node_y)) {
            node_y->parent->left = node_x;
        } else {
            node_y->parent->right = node_x;
        }
    }

    node_y->parent = node_x;
    node_x->right = node_y;
    
    NIL_NODE(rb_tree)->parent = nil_parent;
}

static void cm_rbtree_insert_node_fixup(rb_tree_t *rb_tree, rb_node_t *node)
{
    rb_node_t *grandp_node = NULL;
    rb_node_t *parent_node = NULL;
    rb_node_t *uncle_node = NULL;

    while (node->parent->color == RB_RED) {
        parent_node = node->parent;
        grandp_node = parent_node->parent;

        if (grandp_node->left == parent_node) {
            uncle_node = grandp_node->right;
            if (uncle_node->color == RB_RED) {
                uncle_node->color = RB_BLACK;
                parent_node->color = RB_BLACK;
                grandp_node->color = RB_RED;
                node = grandp_node;
                continue;
            }

            if (parent_node->right == node) {
                node = parent_node;
                cm_rbtree_left_rotate_node(rb_tree, node);
            }

            node->parent->color = RB_BLACK;
            grandp_node->color = RB_RED;
            cm_rbtree_right_rotate_node(rb_tree, grandp_node);
        } else {
            uncle_node = grandp_node->left;
            if (IS_RED_NODE(uncle_node)) {
                uncle_node->color = RB_BLACK;
                parent_node->color = RB_BLACK;
                grandp_node->color = RB_RED;
                node = grandp_node;
                continue;
            }

            if (parent_node->left == node) {
                node = parent_node;
                cm_rbtree_right_rotate_node(rb_tree, node);
            }

            node->parent->color = RB_BLACK;
            grandp_node->color = RB_RED;
            cm_rbtree_left_rotate_node(rb_tree, grandp_node);
        }
    }

    rb_tree->root->color = RB_BLACK;
}

status_t cm_rbtree_insert_node(rb_tree_t *rb_tree, rb_node_t *new_node)
{
    rb_node_t *cur_node = NULL;
    rb_node_t *temp_node = NULL;
    int32 cmp_res;
    
    CM_ASSERT(rb_tree != NULL);
    CM_ASSERT(rb_tree->root != NULL);
    CM_ASSERT(new_node != NULL);
    
    temp_node = ROOT_NODE(rb_tree);
    
    while (temp_node != NIL_NODE(rb_tree)) {
        cur_node = temp_node;
        cmp_res = rb_tree->cmp_func((void*)temp_node, (void*)new_node);
        if (cmp_res > 0) {
            temp_node = temp_node->left;
        } else if (cmp_res < 0) {
            temp_node = temp_node->right;
        } else {
            GS_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "this red black tree node is existent");
            return GS_ERROR;
        }
    }
    
    if (cur_node == NULL) {
        new_node->parent = NIL_NODE(rb_tree);
        rb_tree->root = new_node;
    } else {
        new_node->parent = cur_node;
        cmp_res = rb_tree->cmp_func((void*)cur_node, (void*)new_node);
        if (cmp_res > 0) {
            cur_node->left = new_node;
        } else {
            cur_node->right = new_node;
        }
    }

    new_node->color = RB_RED;
    new_node->left = NIL_NODE(rb_tree);
    new_node->right = NIL_NODE(rb_tree);
    cm_rbtree_insert_node_fixup(rb_tree, new_node);
    rb_tree->node_count++;
    
    return GS_SUCCESS;
}

static void cm_rbtree_delete_node_fixup_left(rb_tree_t *rb_tree, rb_node_t **curr_node)
{
    rb_node_t *node = *curr_node;
    rb_node_t *bro_node = node->parent->right;

    if (IS_RED_NODE(bro_node)) {
        bro_node->color = RB_BLACK;
        node->parent->color = RB_RED;
        cm_rbtree_left_rotate_node(rb_tree, node->parent);
        bro_node = node->parent->right;
    }

    if (IS_BLACK_NODE(bro_node->left) && IS_BLACK_NODE(bro_node->right)) {
        bro_node->color = RB_RED;
        node = node->parent;
    } else {
        if (IS_BLACK_NODE(bro_node->right)) {
            bro_node->left->color = RB_BLACK;
            bro_node->color = RB_RED;
            cm_rbtree_right_rotate_node(rb_tree, bro_node);
            bro_node = node->parent->right;
        }

        bro_node->color = node->parent->color;
        node->parent->color = RB_BLACK;
        bro_node->right->color = RB_BLACK;
        cm_rbtree_left_rotate_node(rb_tree, node->parent);
        node = rb_tree->root;
    }

    *curr_node = node;
}

static void cm_rbtree_delete_node_fixup_right(rb_tree_t *rb_tree, rb_node_t **curr_node)
{
    rb_node_t *node = *curr_node;
    rb_node_t *bro_node = node->parent->left;
    if (IS_RED_NODE(bro_node)) {
        bro_node->color = RB_BLACK;
        node->parent->color = RB_RED;
        cm_rbtree_right_rotate_node(rb_tree, node->parent);
        bro_node = node->parent->left;
    }

    if (IS_BLACK_NODE(bro_node->left) && IS_BLACK_NODE(bro_node->right)) {
        bro_node->color = RB_RED;
        node = node->parent;
    } else {
        if (IS_BLACK_NODE(bro_node->left)) {
            bro_node->right->color = RB_BLACK;
            bro_node->color = RB_RED;
            cm_rbtree_left_rotate_node(rb_tree, bro_node);
            bro_node = node->parent->left;
        }
        bro_node->color = node->parent->color;
        node->parent->color = RB_BLACK;
        bro_node->left->color = RB_BLACK;
        cm_rbtree_right_rotate_node(rb_tree, node->parent);
        node = rb_tree->root;
    }

    *curr_node = node;
}


static void cm_rbtree_delete_node_fixup(rb_tree_t *rb_tree, rb_node_t *node)
{
    while (node != rb_tree->root && IS_BLACK_NODE(node)) {
        if (IS_LEFT_CHILD_NODE(node)) {
            cm_rbtree_delete_node_fixup_left(rb_tree, &node);
        } else {
            cm_rbtree_delete_node_fixup_right(rb_tree, &node);
        }
    }

    node->color = RB_BLACK;
}

static void cm_rbtree_delete_leaf_node(rb_tree_t *rb_tree, rb_node_t *node)
{
    rb_node_t *child_node = node->left != NIL_NODE(rb_tree) ? node->left : node->right;
    child_node->parent = node->parent;

    if (node->parent == NIL_NODE(rb_tree)) {
        rb_tree->root = child_node;
    } else {
        if (IS_LEFT_CHILD_NODE(node)) {
            node->parent->left = child_node;
        } else {
            node->parent->right = child_node;
        }
    }

    if (IS_BLACK_NODE(node)) {
        cm_rbtree_delete_node_fixup(rb_tree, child_node);
    }
    rb_tree->node_count--;
}

void cm_rbtree_delete_node(rb_tree_t *rb_tree, rb_node_t *node)
{
    rb_node_t *child_node = NULL;
    rb_node_t *del_node = NULL;
    uint32 color;
    
    CM_ASSERT(rb_tree != NULL);
    CM_ASSERT(node != NULL);

    if (node->left == NIL_NODE(rb_tree) || node->right == NIL_NODE(rb_tree)) {
        cm_rbtree_delete_leaf_node(rb_tree, node);
        return;
    }

    del_node = node;
    node = node->right;
    
    while (node->left != NIL_NODE(rb_tree)) {
        node = node->left;
    }

    child_node = node->right;
    color = node->color;
    child_node->parent = node->parent;

    if (node->parent == NIL_NODE(rb_tree)) {
        rb_tree->root = child_node;
    } else {
        if (IS_LEFT_CHILD_NODE(node)) {
            node->parent->left = child_node;
        } else {
            node->parent->right = child_node;
        }
    }

    *node = *del_node;
    if (del_node->parent == NIL_NODE(rb_tree)) {
        rb_tree->root = node;
    } else {
        if (IS_LEFT_CHILD_NODE(del_node)) {
            del_node->parent->left = node;
        } else {
            del_node->parent->right = node;
        }
    }

    del_node->left->parent = node;
    del_node->right->parent = node;

    if (color == RB_BLACK) {
        cm_rbtree_delete_node_fixup(rb_tree, child_node);
    }
    rb_tree->node_count--;

    return;
}

rb_node_t *cm_rbtree_search_node(rb_tree_t *rb_tree, rb_node_t *key_node)
{
    rb_node_t *curr_node = NULL;
    rb_node_t *result_node = NULL;
    int32 cmp_res;

    CM_ASSERT(rb_tree != NULL);
    CM_ASSERT(rb_tree->root != NULL);
    CM_ASSERT(key_node != NULL);
    
    curr_node = rb_tree->root;

    while (curr_node != NIL_NODE(rb_tree)) {
        cmp_res = rb_tree->cmp_func(curr_node, key_node);
        if (cmp_res > 0) {
            curr_node = curr_node->left;
        } else if (cmp_res < 0) {
            curr_node = curr_node->right;
        } else {
            result_node = curr_node;
            break;
        }
    }

    return result_node;
}

rb_node_t *cm_rbtree_first_node(rb_tree_t *rb_tree)
{
    rb_node_t *curr_node = NULL;

    CM_ASSERT(rb_tree != NULL);
    CM_ASSERT(rb_tree->root != NULL);
    
    curr_node = ROOT_NODE(rb_tree);

    if (curr_node == NIL_NODE(rb_tree)) {
        return NULL;
    }
    
    while (curr_node->left != NIL_NODE(rb_tree)) {
        curr_node = curr_node->left;
    }

    return curr_node;
}

rb_node_t *cm_rbtree_next_node(rb_tree_t *rb_tree, rb_node_t *node)
{
    rb_node_t *parent_node = NULL;
    rb_node_t *res_node = NULL;
    rb_node_t *curr_node = node;
    
    CM_ASSERT(rb_tree != NULL);
    CM_ASSERT(curr_node != NULL);
    CM_ASSERT(rb_tree->root != NULL);
        
    if (curr_node->right != NIL_NODE(rb_tree)) {
        curr_node = curr_node->right;
        while (curr_node->left != NIL_NODE(rb_tree)) {
            curr_node = curr_node->left;
        }
        res_node = curr_node;
        return res_node;
    }

    parent_node = curr_node->parent;

    while (parent_node != NIL_NODE(rb_tree) && parent_node->right == curr_node) {
        curr_node = parent_node;
        parent_node = parent_node->parent;
    }

    res_node = (parent_node == NIL_NODE(rb_tree)) ? NULL : parent_node;

    return res_node;
}

rb_node_t *cm_rbtree_last_node(rb_tree_t *rb_tree)
{
    rb_node_t *curr_node = NULL;
    
    CM_ASSERT(rb_tree != NULL);
    CM_ASSERT(rb_tree->root != NULL);

    curr_node = ROOT_NODE(rb_tree);
    if (curr_node == NIL_NODE(rb_tree)) {
        return NULL;
    }

    while ((curr_node->right != NIL_NODE(rb_tree))) {
        curr_node = curr_node->right;
    }

    return curr_node;
}

rb_node_t *cm_rbtree_prev_node(rb_tree_t *rb_tree, rb_node_t *node)
{
    rb_node_t *parent_node = NULL;
    rb_node_t *res_node = NULL;
    rb_node_t *curr_node = node;
    
    CM_ASSERT(rb_tree != NULL);
    CM_ASSERT(rb_tree->root != NULL);
    CM_ASSERT(curr_node != NULL);

    if (curr_node->left != NIL_NODE(rb_tree)) {
        curr_node = curr_node->left;
        while (curr_node->right != NIL_NODE(rb_tree)) {
            curr_node = curr_node->right;
        }
        res_node = curr_node;
        return res_node;
    }

    parent_node = node->parent;
    while (parent_node != NIL_NODE(rb_tree) && curr_node == parent_node->left) {
        curr_node = parent_node;
        parent_node = parent_node->parent;
    }

    res_node = parent_node == NIL_NODE(rb_tree) ? NULL : parent_node;

    return res_node;
}

void cm_rbtree_free_tree(rb_tree_t *rb_tree, rb_free_func_t free_func)
{
    rb_node_t *curr_node = NULL;
    rb_node_t *prev_node = NULL;

    CM_ASSERT(rb_tree != NULL);
    CM_ASSERT(rb_tree->root != NULL);
    CM_ASSERT(free_func != NULL);
    
    if (rb_tree->root == NIL_NODE(rb_tree)) {
        return;
    }

    curr_node = rb_tree->root;
    prev_node = NIL_NODE(rb_tree);

    while (curr_node != NIL_NODE(rb_tree)) {
        while (curr_node->left != NIL_NODE(rb_tree)) {
            curr_node = curr_node->left;
        }

        if (curr_node->right == NIL_NODE(rb_tree)) {
            if (IS_LEFT_CHILD_NODE(curr_node)) {
                curr_node->parent->left = NIL_NODE(rb_tree);
            } else {
                curr_node->parent->right = NIL_NODE(rb_tree);
            }

            prev_node = curr_node->parent;
            free_func((void*)curr_node);
            curr_node = prev_node;
        } else {
            curr_node = curr_node->right;
        }
    }

    return;
}

