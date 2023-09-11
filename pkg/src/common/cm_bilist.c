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
 * cm_bilist.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_bilist.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_bilist.h"

void cm_bilist_del_tail(bilist_t *bilist)
{
    (void)cm_bilist_remove_tail(bilist);
}

bilist_node_t* cm_bilist_remove_tail(bilist_t *bilist)
{
    if (bilist->count == 0) {
        return NULL;
    }

    bilist_node_t *tail = bilist->tail;

    if (bilist->head != bilist->tail) {
        bilist->tail = bilist->tail->prev;
        bilist->tail->next = NULL;
    } else {
        bilist->head = NULL;
        bilist->tail = NULL;
    }
    bilist->count--;
    tail->next = NULL;
    tail->prev = NULL;

    return tail;
}

void cm_bilist_del_head(bilist_t *bilist)
{
    (void)cm_bilist_remove_head(bilist);
}

bilist_node_t* cm_bilist_remove_head(bilist_t *bilist)
{
    if (bilist->count == 0) {
        return NULL;
    }

    bilist_node_t *head = bilist->head;

    if (bilist->head != bilist->tail) {
        bilist->head = bilist->head->next;
        bilist->head->prev = NULL;
    } else {
        bilist->head = NULL;
        bilist->tail = NULL;
    }
    bilist->count--;
    head->next = NULL;
    head->prev = NULL;

    return head;
}

void cm_bilist_insert_check(bilist_t *bilist, bilist_node_t *node)
{
    bilist_node_t *tmp_node = bilist->head;

    while (tmp_node != NULL) {
        if (tmp_node == node) {
            CM_NEVER;
        }
        tmp_node = BINODE_NEXT(tmp_node);
    }
}

void cm_bilist_delete_check(bilist_t *bilist, bilist_node_t *node)
{
    bilist_node_t *tmp_node = bilist->head;
    uint32 node_cnt = 0;

    while (tmp_node != NULL) {
        if (tmp_node == node) {
            node_cnt++;
        }
        tmp_node = BINODE_NEXT(tmp_node);
    }

    CM_ASSERT(node_cnt == 1);
}

void cm_bilist_del(bilist_node_t *node, bilist_t *bilist)
{
#ifdef _DEBUG
    cm_bilist_delete_check(bilist, node);
#endif

    if (node == bilist->head) {
        cm_bilist_del_head(bilist);
        return;
    }

    if (node == bilist->tail) {
        cm_bilist_del_tail(bilist);
        return;
    }

    if (node->prev == NULL || node->next == NULL) {
        return;
    }
    CM_ASSERT(bilist->count > 0);
    node->prev->next = node->next;
    node->next->prev = node->prev;
    node->prev = NULL;
    node->next = NULL;
    bilist->count--;
}

void cm_bilist_add_tail(bilist_node_t *node, bilist_t *bilist)
{
#ifdef _DEBUG
    cm_bilist_insert_check(bilist, node);
#endif

    if (bilist->tail != NULL) {
        node->prev = bilist->tail;
        node->next = NULL;
        bilist->tail->next = node;
        bilist->tail = node;
    } else {
        node->next = NULL;
        node->prev = NULL;
        bilist->head = node;
        bilist->tail = node;
    }
    bilist->count++;
}

void cm_bilist_add_head(bilist_node_t *node, bilist_t *bilist)
{
#ifdef _DEBUG
    cm_bilist_insert_check(bilist, node);
#endif

    if (bilist->head != NULL) {
        node->next = bilist->head;
        node->prev = NULL;
        bilist->head->prev = node;
        bilist->head = node;
    } else {
        node->next = NULL;
        node->prev = NULL;
        bilist->head = node;
        bilist->tail = node;
    }
    bilist->count++;
}

void cm_bilist_add_prev(bilist_node_t *node, bilist_node_t *where, bilist_t *bilist)
{
#ifdef _DEBUG
    cm_bilist_insert_check(bilist, node);
#endif

    if (where == bilist->head) {
        cm_bilist_add_head(node, bilist);
        return;
    }
    node->prev = where->prev;
    node->next = where;
    where->prev = node;
    node->prev->next = node;
    bilist->count++;
}

void cm_bilist_add_next(bilist_node_t *node, bilist_node_t *where, bilist_t *bilist)
{
#ifdef _DEBUG
    cm_bilist_insert_check(bilist, node);
#endif

    if (where == bilist->tail) {
        cm_bilist_add_tail(node, bilist);
        return;
    }
    node->next = where->next;
    node->prev = where;
    where->next = node;
    node->next->prev = node;
    bilist->count++;
}

bilist_node_t *cm_bilist_get(bilist_t *bilist, uint32 index)
{
    bilist_node_t *node = NULL;

    if (index >= bilist->count) {
        return NULL;
    }

    node = bilist->head;
    for (uint32 i = 0; i < index; i++) {
        node = BINODE_NEXT(node);
    }

    return node;
}