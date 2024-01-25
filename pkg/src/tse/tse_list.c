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
 * tse_list.c
 *
 *
 * IDENTIFICATION
 * src/tse/tse_list.c
 *
 * -------------------------------------------------------------------------
 */
#include "tse_module.h"
#include "tse_list.h"
#include "cm_defs.h"
#include "cm_debug.h"
#include "cm_log.h"
#include "cm_error.h"
#include "cm_debug.h"
#include "knl_common.h"

/*
sizeof(tse_context_t) == 72
按照这个宏定义，每个每个mysql的每个list可能缓存2000*72字节
整个参天极限上限为mysql实例数6 * 每个实例的list数量CTC_CTX_LIST_CNT（32） * 每个list的内存 = 26M内存，还好
*/
#define TSE_LIST_DELETE_CACHE_CNT (2000)  // 删除的节点累计到2000会加锁读写锁，清理一次链表
void init_list_node(tse_list_node_t *node)
{
    node->is_delete = false;
    (void)cm_atomic_set(&node->next, 0);
}

static void tse_list_reset(tse_list_t *list)
{
    knl_panic(list != NULL);
    (void)cm_atomic_set(&list->size, 0);
    (void)cm_atomic_set(&list->delete_cnt, 0);
    cm_atomic_set(&list->head, 0);
}

void tse_list_init(tse_list_t *list, void (*free_function)(uint64_t))
{
    knl_panic(list != NULL);
    tse_list_reset(list);
    pthread_rwlock_init(&list->rw_lock, NULL);
    list->free_function = free_function;
}

static uint64_t tse_list_calc_size(tse_list_t *list)
{
    uint64_t size = 0;
    tse_list_node_t *node = (tse_list_node_t *)cm_atomic_get(&list->head);
    while (node != NULL) {
        if (node->is_delete == false) {
            size++;
        }
        node = (tse_list_node_t *)cm_atomic_get(&node->next);
    }
    return size;
}

void triger_tse_list_raw_delete_all(tse_list_t *list)
{
    uint64_t real_del_cnt = 0;  // 实际删除的节点数量
    uint64_t real_size = 0;     // 实际剩余的节点，用于校验删除的过程中有无丢失节点
    (void)pthread_rwlock_wrlock(&list->rw_lock);
    uint64_t size = cm_atomic_get(&list->size);
    uint64_t delete_cnt = cm_atomic_get(&list->delete_cnt);
    tse_list_node_t *node = (tse_list_node_t *)cm_atomic_get(&list->head);
    tse_list_node_t *node_next = NULL;
    while (node != NULL) {
        node_next = (tse_list_node_t *)cm_atomic_get(&node->next);
        if (node->is_delete == false) {
            real_size++;
        } else {
            real_del_cnt++;
        }
        if (list->free_function) {
            list->free_function((uint64_t)node);
        }
        node = node_next;
    }
    tse_list_reset(list);
    
    CM_ASSERT(real_size == size);
    CM_ASSERT(real_del_cnt == delete_cnt);
    (void)pthread_rwlock_unlock(&list->rw_lock);
    CT_LOG_DEBUG_INF("[TSE_LIST]:triger_tse_list_raw_delete_all delete_cnt:%lu, size:%lu", delete_cnt, size);
}

void triger_tse_list_raw_delete(tse_list_t *list)
{
    uint64_t real_del_cnt = 0;  // 实际删除的节点数量
    uint64_t real_size = 0;     // 实际剩余的节点，用于校验删除的过程中有无丢失节点
    tse_list_node_t new_list;
    init_list_node(&new_list);
    tse_list_node_t *node_next = NULL;
    tse_list_node_t *new_list_tail = &new_list;

    (void)pthread_rwlock_wrlock(&list->rw_lock);
    uint64_t size = cm_atomic_get(&list->size);
    uint64_t delete_cnt = cm_atomic_get(&list->delete_cnt);
    tse_list_node_t *node = (tse_list_node_t *)cm_atomic_get(&list->head);
    while (node != NULL) {
        node_next = (tse_list_node_t *)cm_atomic_get(&node->next);
        // 没有删除的节点，重新挂回链表去
        if (node->is_delete == false) {
            cm_atomic_set(&new_list_tail->next, (int64_t)node);
            new_list_tail = node;
            cm_atomic_set(&new_list_tail->next, 0);
            real_size++;
        } else {
            real_del_cnt++;
            if (list->free_function) {
                list->free_function((uint64_t)node);
            }
        }
        node = node_next;
    }
    CM_ASSERT(real_size == size);
    CM_ASSERT(real_del_cnt == delete_cnt);
    cm_atomic_set(&list->delete_cnt, 0);
    cm_atomic_set(&list->head, cm_atomic_get(&new_list.next));
    CM_ASSERT(real_size == tse_list_calc_size(list));
    (void)pthread_rwlock_unlock(&list->rw_lock);
    CT_LOG_DEBUG_INF("[TSE_LIST]:triger_tse_list_raw_delete: delete_cnt:%lu,size:%lu", delete_cnt, size);
}

uint64_t tse_list_size(tse_list_t *list)
{
    knl_panic(list != NULL);
    return cm_atomic32_get(&list->size);
}

void tse_list_clear(tse_list_t *list)
{
    knl_panic(list != NULL);
    triger_tse_list_raw_delete_all(list);
}

void tse_list_insert(tse_list_t *list, uint64_t search_key)
{
    knl_panic(list != NULL);
    knl_panic(search_key != 0);
    tse_list_node_t *node = (tse_list_node_t *)search_key;
    node->is_delete = false;
    (void)pthread_rwlock_rdlock(&list->rw_lock);
    // 使用CAS保证 将node->next指向list->head 和 将list->head替换为node是原子发生的
    tse_list_node_t *head = NULL;
    do {
        head = (tse_list_node_t *)cm_atomic_get(&list->head);
        cm_atomic_set(&node->next, (uint64_t)head);
    } while (!cm_atomic_cas(&list->head, (int64_t)head, (int64_t)node));
    (void)cm_atomic_inc(&list->size);
    (void)pthread_rwlock_unlock(&list->rw_lock);
}

void tse_list_delete(tse_list_t *list, uint64_t search_key)
{
    knl_panic(list != NULL);
    knl_panic(search_key != 0);
    tse_list_node_t *node = (tse_list_node_t *)search_key;
    (void)pthread_rwlock_rdlock(&list->rw_lock);
    knl_panic(node->is_delete == false);
    node->is_delete = true;  // 标记删除
    (void)cm_atomic_inc(&list->delete_cnt);
    CM_ASSERT(cm_atomic_get(&list->size) > 0);
    (void)cm_atomic_dec(&list->size);
    (void)pthread_rwlock_unlock(&list->rw_lock);

    uint64_t delete_cnt = cm_atomic_get(&list->delete_cnt);
    if (delete_cnt >= TSE_LIST_DELETE_CACHE_CNT) {
        triger_tse_list_raw_delete(list);
    }
}
