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
 * tse_list.h
 *
 *
 * IDENTIFICATION
 * src/tse/tse_list.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __TSE_LIST_H__
#define __TSE_LIST_H__
#include <stdbool.h>
#include <pthread.h>
#include "cm_atomic.h"
#ifdef __cplusplus
extern "C" {
#endif
/*
list上放原子变量计数，rw锁
插入只往开头插入，加读锁
删除只标记不释放，增加原子计数，加读锁
计数达到一定值以后清理释放空间，，变量清零，加写锁
实例失败清理整个链表，加写锁
*/
typedef struct tag_tse_list_node {
    // 该节点是否已经删除
    bool is_delete;
    atomic_t next;
} tse_list_node_t;

typedef struct tag_tse_list {
    atomic_t head;
    pthread_rwlock_t rw_lock;
    atomic_t size;
    atomic_t delete_cnt;              // 已经删除的节点计数，删除节点达到一定数量会触发gc流程
    void (*free_function)(uint64_t);  // node的清理指针
} tse_list_t;

void init_list_node(tse_list_node_t *node);
void tse_list_init(tse_list_t *list, void (*free_function)(uint64_t));
void tse_list_clear(tse_list_t *list);
/*
    特别注意search_key的指针指向的结构体，一定要把tse_list_node_t放在结构体的首部，
    tse_list内部会直接把search_key转换成一个tse_list_node_t*指针，用于把该节点挂在list内部
*/
void tse_list_insert(tse_list_t *list, uint64_t search_key);
void tse_list_delete(tse_list_t *list, uint64_t search_key);
uint64_t tse_list_size(tse_list_t *list);

#ifdef __cplusplus
}
#endif
#endif  // #ifndef __TSE_LIST_H__
