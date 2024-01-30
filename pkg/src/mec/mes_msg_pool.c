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
 * mes_msg_pool.c
 *
 *
 * IDENTIFICATION
 * src/mec/mes_msg_pool.c
 *
 * -------------------------------------------------------------------------
 */
#include "mes_log_module.h"
#include "mes_func.h"

message_pool_t *g_send_pool;
message_pool_t *g_recv_pool;

status_t mes_init_message_pool(void)
{
    status_t ret;

    if ((g_mes.profile.buffer_pool_attr.pool_count == 0) ||
        (g_mes.profile.buffer_pool_attr.pool_count > MES_MAX_BUFFER_STEP_NUM)) {
        CT_THROW_ERROR_EX(ERR_MES_PARAMETER, "[mes] pool_count %u is invalid, legal scope is [1, %u].",
                          g_mes.profile.buffer_pool_attr.pool_count, MES_MAX_BUFFER_STEP_NUM);
        return CT_ERROR;
    }

    for (uint32 i = 0; i < g_mes.profile.buffer_pool_attr.pool_count; i++) {
        ret = mes_create_buffer_chunk(&g_mes.mes_ctx.msg_pool.chunk[i], i, &g_mes.profile.buffer_pool_attr.buf_attr[i]);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[mes]: create buf chunk failed.");
            return CT_ERROR;
        }
    }

    g_mes.mes_ctx.msg_pool.count = g_mes.profile.buffer_pool_attr.pool_count;

    return CT_SUCCESS;
}

void mes_destory_message_pool(void)
{
    for (uint32 i = 0; i < g_mes.profile.buffer_pool_attr.pool_count; i++) {
        mes_destory_buffer_chunk(&g_mes.mes_ctx.msg_pool.chunk[i]);
    }

    return;
}

// new buffer pool
void mes_init_buf_queue(mes_buf_queue_t *queue)
{
    queue->lock = 0;
    queue->first = NULL;
    queue->last = NULL;
    queue->count = 0;
    queue->addr = NULL;
}

status_t mes_create_buffer_queue(mes_buf_queue_t *queue, uint8 chunk_no, uint8 queue_no, uint32 buf_size,
                                 uint32 buf_count)
{
    uint64 mem_size;
    mes_buffer_item_t *buf_node;
    mes_buffer_item_t *buf_node_next;
    uint32 buf_item_size;
    char *temp_buffer;

    if (buf_count == 0) {
        CT_THROW_ERROR_EX(ERR_MES_CREATE_AREA, "mes_pool_size should greater than 0.");
        return CT_ERROR;
    }

    // init queue
    mes_init_buf_queue(queue);
    queue->chunk_no = chunk_no;
    queue->queue_no = queue_no;
    queue->buf_size = buf_size;
    queue->count = buf_count;

    // alloc memery
    buf_item_size = sizeof(mes_buffer_item_t) - MES_MIN_BUFFER_SIZE + buf_size;
    mem_size = (uint64)buf_count * (uint64)buf_item_size;
    queue->addr = malloc(mem_size);
    if (queue->addr == NULL) {
        CT_THROW_ERROR_EX(ERR_MES_CREATE_AREA, "allocate memory size %llu for MES msg pool failed", mem_size);
        return CT_ERROR;
    }

    // init queue list
    temp_buffer = queue->addr;
    buf_node = (mes_buffer_item_t *)temp_buffer;
    queue->first = buf_node;
    for (uint32 i = 1; i < buf_count; i++) {
        temp_buffer += buf_item_size;
        buf_node_next = (mes_buffer_item_t *)temp_buffer;
        buf_node->chunk_no = chunk_no;
        buf_node->queue_no = queue_no;
        buf_node->next = buf_node_next;
        buf_node = buf_node_next;
    }
    buf_node->chunk_no = chunk_no;
    buf_node->queue_no = queue_no;
    buf_node->next = NULL;
    queue->last = buf_node;

    return CT_SUCCESS;
}

void mes_destory_buffer_queue(mes_buf_queue_t *queue)
{
    if (queue == NULL || queue->addr == NULL) {
        return;
    }

    free(queue->addr);
    queue->addr = NULL;
}

void mes_set_buffer_queue_count(mes_buf_chunk_t *chunk, uint32 queue_num, uint32 tatol_count)
{
    uint32 buf_count;
    uint32 buf_leftover;
    if (queue_num == 0) {
        return;
    }

    buf_count = tatol_count / queue_num;
    buf_leftover = tatol_count % queue_num;

    for (uint32 i = 0; i < queue_num; i++) {
        chunk->queues[i].count = buf_count;
    }

    for (uint32 i = 0; i < buf_leftover; i++) {
        chunk->queues[i].count++;
    }

    return;
}

status_t mes_create_buffer_chunk(mes_buf_chunk_t *chunk, uint32 chunk_no, mes_buffer_attr_t *buf_attr)
{
    errno_t ret;
    uint32 queues_size;
    uint32 queue_num = buf_attr->queue_count;

    if (queue_num == 0 || queue_num > MES_MAX_BUFFER_QUEUE_NUM) {
        CT_THROW_ERROR_EX(ERR_MES_PARAMETER, "[mes] pool_count %u is invalid, legal scope is [1, %u].", queue_num,
                          MES_MAX_BUFFER_STEP_NUM);
        return CT_ERROR;
    }

    queues_size = queue_num * sizeof(mes_buf_queue_t);
    chunk->queues = (mes_buf_queue_t *)malloc(queues_size);
    if (chunk->queues == NULL) {
        CT_THROW_ERROR_EX(ERR_MES_CREATE_AREA, "allocate memory queue_num %u failed", queue_num);
        return CT_ERROR;
    }
    ret = memset_sp(chunk->queues, queues_size, 0, queues_size);
    MEMS_RETURN_IFERR(ret);

    chunk->chunk_no = (uint8)chunk_no;
    chunk->buf_size = buf_attr->size;
    chunk->queue_num = queue_num;
    chunk->current_no = 0;

    mes_set_buffer_queue_count(chunk, queue_num, buf_attr->count);

    for (uint32 i = 0; i < queue_num; i++) {
        if (mes_create_buffer_queue(&chunk->queues[i], chunk_no, i, buf_attr->size, chunk->queues[i].count) !=
            CT_SUCCESS) {
            CT_LOG_RUN_ERR("[mes]: create buf queue failed.");
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

void mes_destory_buffer_chunk(mes_buf_chunk_t *chunk)
{
    if (chunk == NULL || chunk->queues == NULL) {
        return;
    }

    for (uint32 i = 0; i < chunk->queue_num; i++) {
        mes_destory_buffer_queue(&chunk->queues[i]);
    }

    free(chunk->queues);
    chunk->queues = NULL;

    return;
}

static inline mes_buf_chunk_t *mes_get_buffer_chunk(uint32 len)
{
    mes_buf_chunk_t *chunk;

    for (uint32 i = 0; i < g_mes.mes_ctx.msg_pool.count; i++) {
        chunk = &g_mes.mes_ctx.msg_pool.chunk[i];
        if (len <= chunk->buf_size) {
            return chunk;
        }
    }

    CT_LOG_RUN_ERR("[mes]: There is not long enough buffer pool for %u.", len);

    return NULL;
}

static inline mes_buf_queue_t *mes_get_buffer_queue(mes_buf_chunk_t *chunk)
{
    mes_buf_queue_t *queue = NULL;

    queue = &chunk->queues[chunk->current_no % chunk->queue_num];
    chunk->current_no++;

    return queue;
}

void print_no_buffer_log(void)
{
    int32 deal_count = 0;
    uint32 queue_len = 0;
    MES_LOGGING(MES_LOGGING_GET_BUF, "[mes]: There is no buffer, sleep and try again.");
    // 查看哪条消息占用了buffer
    for (uint32 cmd_loop = 1; cmd_loop < MES_CMD_CEIL; cmd_loop++) {
        deal_count = mes_get_stat_dealing_count(cmd_loop);
        if (deal_count > 0) {
            MES_CMD_LOGGING(cmd_loop, "There is no buffer, cmd = %u, deal_count = %d", cmd_loop, deal_count);
        }
    }
    // 查看group队列的长度
    for (uint32 group_id = 0; group_id < MES_TASK_GROUP_ALL; group_id++) {
        queue_len = mes_get_msg_queue_length(group_id);
        if (queue_len > 0) {
            MES_GROUP_LOGGING(group_id, "There is no buffer, group = %u, queue_len = %d", group_id, queue_len);
        }
    }
}

char *mes_alloc_buf_item(uint32 len)
{
    mes_buf_chunk_t *chunk = NULL;
    mes_buf_queue_t *queue = NULL;
    mes_buffer_item_t *buf_node = NULL;
    uint32 find_times = 0;

    chunk = mes_get_buffer_chunk(len);
    if (chunk == NULL  || chunk->queues == NULL) {
        CT_LOG_RUN_ERR("[mes]: Get buffer failed.");
        return NULL;
    }

    do {
        queue = mes_get_buffer_queue(chunk);
        cm_spin_lock(&queue->lock, NULL);
        if (queue->count > 0) {
            buf_node = queue->first;
            queue->first = buf_node->next;
            queue->count--;
            buf_node->next = NULL;
            cm_spin_unlock(&queue->lock);
            break;
        } else {
            cm_spin_unlock(&queue->lock);
            find_times++;
            if ((find_times % chunk->queue_num) == 0) {
                print_no_buffer_log();
                cm_sleep(1);
            }
        }
    } while (buf_node == NULL);

    return buf_node->data;
}

void mes_free_buf_item(char *buffer)
{
    mes_buffer_item_t *buf_item = (mes_buffer_item_t *)(buffer - MES_BUFFER_ITEM_SIZE);
    mes_buf_chunk_t *chunk = &g_mes.mes_ctx.msg_pool.chunk[buf_item->chunk_no];
    mes_buf_queue_t *queue = &chunk->queues[buf_item->queue_no];

    cm_spin_lock(&queue->lock, NULL);
    if (queue->count > 0) {
        queue->last->next = buf_item;
        queue->last = buf_item;
    } else {
        queue->first = buf_item;
        queue->last = buf_item;
    }
    queue->count++;
    cm_spin_unlock(&queue->lock);

    return;
}

void mes_destory_buf_pool(message_pool_t *pool)
{
    if (pool->buffer != NULL) {
        free(pool->buffer);
        pool->buffer = NULL;
    }

    return;
}

char *mes_alloc_pool_buf(message_pool_t *pool)
{
    char *msg_buf;
    uint32 id = pool->get_no % pool->size;  // TODO: id can protect by lock

    cm_spin_lock(&pool->lock, NULL);
    while (pool->items[id] == NULL) {
        cm_spin_unlock(&pool->lock);
        cm_spin_sleep();
        pool->get_no++;
        id = pool->get_no % pool->size;
        cm_spin_lock(&pool->lock, NULL);
    }

    pool->get_no++;
    msg_buf = pool->items[id];
    pool->items[id] = NULL;
    cm_spin_unlock(&pool->lock);

    // mes_elapsed_stat(MES_TIME_GET_BUF);
    return msg_buf;
}

void mes_release_pool_buf(message_pool_t *pool, const char *msg_buf)
{
    uint32 id;

    cm_spin_lock(&pool->lock, NULL);
    id = *(uint32 *)(msg_buf - sizeof(uint32));
    CM_ASSERT(pool->items[id] == NULL);
    pool->items[id] = (char *)msg_buf;
    cm_spin_unlock(&pool->lock);

    return;
}

// common send and recv buffer
void mes_init_send_recv_buf_pool(void)
{
    if (g_mes.profile.pipe_type == CS_TYPE_TCP) {
        g_send_pool = &g_mes.mes_ctx.msg_pool.big_pool;
        g_recv_pool = &g_mes.mes_ctx.msg_pool.big_pool;
    } else if (g_mes.profile.pipe_type == CS_TYPE_UC || g_mes.profile.pipe_type == CS_TYPE_UC_RDMA) {
        g_send_pool = &g_mes.mes_ctx.msg_pool.big_pool;
        g_recv_pool = &g_mes.mes_ctx.msg_pool.big_pool;
    } else {
        CT_THROW_ERROR_EX(ERR_MES_PARAMETER, "pipe_type %u is invalid", g_mes.profile.pipe_type);
        return;
    }

    return;
}

char *mes_alloc_send_buf(void)
{
    return mes_alloc_pool_buf(g_send_pool);
}

void mes_release_send_buf(const char *buffer)
{
    return mes_release_pool_buf(g_send_pool, buffer);
}

char *mes_alloc_recv_buf(void)
{
    return mes_alloc_pool_buf(g_recv_pool);
}

void mes_release_buf_stat(const char *msg_buf)
{
    mes_message_head_t *head = (mes_message_head_t *)msg_buf;

    mes_elapsed_stat(head->cmd, MES_TIME_PUT_BUF);

    MES_LOG_HEAD_BUF(head, msg_buf);

    return;
}

void mes_release_recv_buf(const char *buffer)
{
    mes_release_buf_stat(buffer);

    mes_release_pool_buf(g_recv_pool, buffer);

    return;
}