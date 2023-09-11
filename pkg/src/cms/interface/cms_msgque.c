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
 * cms_msgque.c
 *
 *
 * IDENTIFICATION
 * src/cms/interface/cms_msgque.c
 *
 * -------------------------------------------------------------------------
 */

#include "cms_msgque.h"

int32 cms_init_que(cms_que_t* que)
{
    for (int32 i = 0; i < CMS_QUE_PRIORITY_COUNT; i++) {
        biqueue_init(&que->que[i]);
    }
    que->count = 0;
    return cms_sync_init(&que->sync);
}

biqueue_node_t* cms_que_alloc_node_ex(char* data, uint32 data_size)
{
    char* buff = malloc(sizeof(biqueue_node_t) + data_size);
    if (buff == NULL) {
        return NULL;
    }

    errno_t err = memset_s(buff, sizeof(biqueue_node_t) + data_size, 0, sizeof(biqueue_node_t) + data_size);
    if (err != EOK) {
        CM_FREE_PTR(buff);
        return NULL;
    }

    err = memcpy_s(buff + sizeof(biqueue_node_t), data_size, data, data_size);
    if (err != EOK) {
        CM_FREE_PTR(buff);
        return NULL;
    }

    return (biqueue_node_t*)buff;
}

biqueue_node_t* cms_que_alloc_node(uint32 data_size)
{
    char* buff = malloc(sizeof(biqueue_node_t) + data_size);
    if (buff == NULL) {
        return NULL;
    }

    errno_t err = memset_s(buff, sizeof(biqueue_node_t) + data_size, 0, sizeof(biqueue_node_t) + data_size);
    if (err != EOK) {
        CM_FREE_PTR(buff);
        return NULL;
    }

    return (biqueue_node_t*)buff;
}

void cms_que_free_node(biqueue_node_t *node)
{
    free(node);
}

void cms_enque_ex(cms_que_t* que, biqueue_node_t *node, uint32 priority)
{
    CM_ASSERT(priority < CMS_QUE_PRIORITY_COUNT);

    cms_sync_lock(&que->sync);
    biqueue_add_tail(&que->que[priority], node);
    que->count++;
    cms_sync_unlock(&que->sync);
    cms_sync_notify(&que->sync);
}

void cms_enque(cms_que_t* que, biqueue_node_t* node)
{
    cms_enque_ex(que, node, CMS_QUE_PRIORITY_NORMAL);
}

biqueue_node_t* cms_deque(cms_que_t* que)
{
    biqueue_node_t* node = NULL;

    cms_sync_lock(&que->sync);
    while (1) {
        for (int32 que_id = 0; que_id < CMS_QUE_PRIORITY_COUNT; que_id++) {
            node = biqueue_del_head(&que->que[que_id]);
            if (node != NULL) {
                que->count--;
                break;
            }
        }

        if (node != NULL || cms_sync_wait(&que->sync, CMS_QUE_DEQUEUE_WAIT_TIME) != GS_SUCCESS) {
            break;
        }
    }
    cms_sync_unlock(&que->sync);

    return node;
}

biqueue_node_t* cms_deque_ex(cms_que_t* que, uint32 priority)
{
    biqueue_node_t* node = NULL;

    cms_sync_lock(&que->sync);
    while (1) {
        node = biqueue_del_head(&que->que[priority]);
        if (node != NULL) {
            que->count--;
            break;
        } else {
            if (cms_sync_wait(&que->sync, CMS_QUE_DEQUEUE_WAIT_TIME) != GS_SUCCESS) {
                break;
            }
        }
    }
    cms_sync_unlock(&que->sync);

    return node;
}
