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
 * cms_msgque.h
 *
 *
 * IDENTIFICATION
 * src/cms/interface/cms_msgque.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMS_MSG_QUE_H
#define CMS_MSG_QUE_H

#include "cm_queue.h"
#include "cms_sync.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CMS_QUE_PRIORITY_COUNT    2
#define CMS_QUE_PRIORITY_HIGH     0
#define CMS_QUE_PRIORITY_NORMAL   1
#define CMS_QUE_DEQUEUE_WAIT_TIME 500

typedef struct st_cms_msgque_t {
    biqueue_t que[CMS_QUE_PRIORITY_COUNT];
    cms_sync_t sync;
    uint64 count;
}cms_que_t;

#define cms_que_node_data(node) (((char*)(node)) + sizeof(biqueue_node_t))

int32 cms_init_que(cms_que_t* que);
biqueue_node_t* cms_que_alloc_node_ex(char* data, uint32 data_size);
biqueue_node_t* cms_que_alloc_node(uint32 data_size);
void cms_que_free_node(biqueue_node_t* node);
void cms_enque(cms_que_t* que, biqueue_node_t* node);
void cms_enque_ex(cms_que_t* que, biqueue_node_t* node, uint32 priority);
biqueue_node_t* cms_deque(cms_que_t* que);
biqueue_node_t* cms_deque_ex(cms_que_t* que, uint32 priority);

#ifdef __cplusplus
}
#endif
#endif
