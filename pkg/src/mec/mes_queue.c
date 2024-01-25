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
 * mes_queue.c
 *
 *
 * IDENTIFICATION
 * src/mec/mes_queue.c
 *
 * -------------------------------------------------------------------------
 */
#include "mes_log_module.h"
#include "mes_queue.h"
#include "srv_instance.h"
#include "dtc_context.h"
#include "mes_func.h"
#include "tms_monitor.h"

#define MES_QUEUE_LOG_LENGTH (1024)

void put_msgitem_nolock(dtc_msgqueue_t *queue, dtc_msgitem_t *msgitem)
{
    if (queue->count == 0) {
        queue->first = msgitem;
        queue->last = msgitem;
        msgitem->next = NULL;
    } else {
        queue->last->next = msgitem;
        queue->last = msgitem;
    }
    queue->count++;
}

void put_msgitem(dtc_msgqueue_t *queue, dtc_msgitem_t *msgitem)
{
    cm_spin_lock(&queue->lock, NULL);
    if (queue->count == 0) {
        queue->first = msgitem;
        queue->last = msgitem;
        msgitem->next = NULL;
    } else {
        queue->last->next = msgitem;
        queue->last = msgitem;
    }
    queue->count++;
    cm_spin_unlock(&queue->lock);
}

dtc_msgitem_t *mes_alloc_msgitem_nolock(dtc_msgqueue_t *queue)
{
    dtc_msgitem_t *ret = NULL;

    if (queue->count == 0) {
        if (alloc_msgitems(&g_mes.mq_ctx.pool, queue) != CT_SUCCESS) {
            CT_THROW_ERROR_EX(ERR_MES_CREATE_AREA, "alloc msg item failed");
            return NULL;
        }
    }

    if (queue->count > 0) {
        ret = queue->first;
        queue->first = ret->next;
        queue->count--;
    }

    return ret;
}

dtc_msgitem_t *get_msgitem(dtc_msgqueue_t *queue)
{
    dtc_msgitem_t *ret = NULL;

    cm_spin_lock(&queue->lock, NULL);
    if (queue->count > 0) {
        ret = queue->first;
        queue->first = ret->next;
        queue->count--;
    }
    cm_spin_unlock(&queue->lock);
    return ret;
}

status_t alloc_msgitems(dtc_msgitem_pool_t *pool, dtc_msgqueue_t *msgitems)
{
    dtc_msgitem_t *item;

    cm_spin_lock(&pool->free_list.lock, NULL);
    if (pool->free_list.count == 0) {
        cm_spin_unlock(&pool->free_list.lock);
        cm_spin_lock(&pool->lock, NULL);
        if (pool->buf_idx == CT_INVALID_ID16 || pool->hwm >= INIT_MSGITEM_BUFFER_SIZE) {
            pool->buf_idx++;
            if (pool->buf_idx >= MAX_POOL_BUFFER_COUNT) {
                cm_spin_unlock(&pool->lock);
                CT_LOG_RUN_ERR("pool->buf_idx exceed.");
                return CT_ERROR;
            }
            pool->hwm = 0;
            pool->buffer[pool->buf_idx] = (dtc_msgitem_t *)malloc(INIT_MSGITEM_BUFFER_SIZE * sizeof(dtc_msgitem_t));
            if (pool->buffer[pool->buf_idx] == NULL) {
                cm_spin_unlock(&pool->lock);
                return CT_ERROR;
            }
        }
        item = (dtc_msgitem_t *)(pool->buffer[pool->buf_idx] + pool->hwm);
        pool->hwm += MSG_ITEM_BATCH_SIZE;
        cm_spin_unlock(&pool->lock);

        msgitems->first = item;
        for (uint32 loop = 0; loop < MSG_ITEM_BATCH_SIZE - 1; loop++) {
            item->next = item + 1;
            item = item->next;
        }
        item->next = NULL;
        msgitems->last = item;
        msgitems->count = MSG_ITEM_BATCH_SIZE;
        return CT_SUCCESS;
    }

    knl_panic(pool->free_list.count >= MSG_ITEM_BATCH_SIZE);

    msgitems->first = pool->free_list.first;
    for (uint32 loop = 0; loop < MSG_ITEM_BATCH_SIZE - 1; loop++) {
        pool->free_list.first = pool->free_list.first->next;
    }

    msgitems->last = pool->free_list.first;
    pool->free_list.first = pool->free_list.first->next;
    msgitems->last->next = NULL;
    msgitems->count = MSG_ITEM_BATCH_SIZE;

    pool->free_list.count -= MSG_ITEM_BATCH_SIZE;
    if (pool->free_list.count == 0) {
        pool->free_list.last = NULL;
    }

    cm_spin_unlock(&pool->free_list.lock);

    return CT_SUCCESS;
}

void free_msgitems(dtc_msgitem_pool_t *pool, dtc_msgqueue_t *msgitems)
{
    cm_spin_lock(&pool->free_list.lock, NULL);
    if (pool->free_list.count > 0) {
        pool->free_list.last->next = msgitems->first;
        pool->free_list.last = msgitems->last;
        pool->free_list.count += msgitems->count;
    } else {
        pool->free_list.first = msgitems->first;
        pool->free_list.last = msgitems->last;
        pool->free_list.count = msgitems->count;
    }
    cm_spin_unlock(&pool->free_list.lock);
    init_msgqueue(msgitems);
}

dtc_msgitem_t *mes_alloc_msgitem(dtc_msgqueue_t *queue)
{
    dtc_msgitem_t *item = NULL;

    cm_spin_lock(&queue->lock, NULL);
    if (queue->count == 0) {
        if (alloc_msgitems(&g_mes.mq_ctx.pool, queue) != CT_SUCCESS) {
            cm_spin_unlock(&queue->lock);
            CT_THROW_ERROR_EX(ERR_MES_CREATE_AREA, "alloc msg item failed");
            return NULL;
        }
    }

    item = queue->first;
    queue->first = item->next;
    queue->count--;
    cm_spin_unlock(&queue->lock);

    return item;
}

void init_msgqueue(dtc_msgqueue_t *queue)
{
    queue->lock = 0;
    queue->first = NULL;
    queue->last = NULL;
    queue->count = 0;
}

void init_msgitem_pool(dtc_msgitem_pool_t *pool)
{
    pool->lock = 0;
    pool->buf_idx = CT_INVALID_ID16;
    pool->hwm = 0;
    init_msgqueue(&pool->free_list);
}

void free_msgitem_pool(dtc_msgitem_pool_t *pool)
{
    if (pool->buf_idx == CT_INVALID_ID16) {
        return;
    }

    for (uint16 i = 0; i <= pool->buf_idx; i++) {
        CM_FREE_PTR(pool->buffer[i]);
    }
}

uint32 dtc_get_rand_value(void)
{
    uint32 randvalue;

    randvalue = cm_random(1024 * 1024);

    return randvalue;
}

dtc_msgitem_t *mes_get_task_msg(mes_task_group_t *group)
{
    dtc_msgqueue_t *group_queue = &group->queue;
    dtc_msgitem_t *msgitem;

    if (group_queue->count != 0) {
        msgitem = get_msgitem(group_queue);
        if (msgitem != NULL) {
            return msgitem;
        }
    }

    if (group->queue.count > 100) {
        MES_LOGGING(MES_LOGGING_GET_QUEUE, "[mes]: group %u queue length num %u.", group->group_id, group->queue.count);
    }

    return NULL;
}

void dtc_task_proc(thread_t *thread)
{
    uint32 index = *(uint32 *)thread->argument;
    dtc_msgitem_t *msgitem;
    mes_task_group_t *group;

    cm_set_thread_name("dtc_task_proc");

    dtc_msgqueue_t finished_msgitem_queue;
    init_msgqueue(&finished_msgitem_queue);

    group = mes_get_task_group(index);
    if (group == NULL) {
        CT_THROW_ERROR_EX(ERR_MES_PARAMETER, "[mes]: task index %u not belong any group.", index);
        return;
    }

    tms_monitor_handle monitor_handler =
        tms_sig_event_reg("dtc_task_proc", tms_monitor_cb, TMS_MONITOR_DEFAULT_STEP);
    if (monitor_handler == NULL) {
        CT_LOG_RUN_ERR("[mes]: task regist monitor event failed.");
        return;
    }
    tms_monitor_t *monitor_event = (tms_monitor_t *)monitor_handler;

    while (!thread->closed) {
        msgitem = mes_get_task_msg(group);
        if (msgitem == NULL) {
            monitor_event->monitor_is_running = CT_FALSE;
            cm_wait_cond_no_timeout(&group->work_thread_cond);
            continue;
        }
        tms_update_monitor_start_time(monitor_handler);
        monitor_event->monitor_is_running = CT_TRUE;

        if (msgitem->msg.head->src_inst != msgitem->msg.head->dst_inst) {  // ignores the consume time of message send
                                                                           // inter, shoule use a new view if need
            mes_consume_with_time(msgitem->msg.head->cmd, MES_TIME_GET_QUEUE, msgitem->start_time);
        }

        MES_LOG_DEBUG(
            msgitem->msg.head->cmd,
            "[mes]cmd=%u, rsn=%u, src_inst=%u, dst_inst=%u, src_sid=%u, dst_sid=%u, start_time=%llu, thread_id=%u, group_id=%u, queue_len=%u.",
            msgitem->msg.head->cmd, msgitem->msg.head->rsn, msgitem->msg.head->src_inst, msgitem->msg.head->dst_inst,
            msgitem->msg.head->src_sid, msgitem->msg.head->dst_sid, msgitem->start_time, index, group->group_id,
            g_mes.mq_ctx.group.task_group[group->group_id].queue.count);

        g_mes.proc(index, &msgitem->msg);

        if (msgitem->msg.head->src_inst != msgitem->msg.head->dst_inst) {
            mes_consume_with_time(msgitem->msg.head->cmd, MES_TIME_QUEUE_PROC, msgitem->start_time);
        }

        put_msgitem_nolock(&finished_msgitem_queue, msgitem);
        if (MSG_ITEM_BATCH_SIZE == finished_msgitem_queue.count) {
            free_msgitems(&g_mes.mq_ctx.pool, &finished_msgitem_queue);
        }
        tms_update_monitor_end_time(monitor_handler);
    }
}

status_t init_dtc_mq_instance(void)
{
    uint32 loop;

    for (loop = 0; loop < DTC_MSG_QUEUE_NUM; loop++) {
        init_msgqueue(&g_mes.mq_ctx.queue[loop]);
    }

    for (loop = 0; loop < CT_DTC_MAX_TASK_NUM; loop++) {
        init_msgqueue(&g_mes.mq_ctx.tasks[loop].queue);
        g_mes.mq_ctx.tasks[loop].choice = 0;
    }

    for (loop = 0; loop < MES_TASK_GROUP_ALL; loop++) {
        init_msgqueue(&g_mes.mq_ctx.group.task_group[loop].queue);
        cm_init_cond(&g_mes.mq_ctx.group.task_group[loop].work_thread_cond);
    }

    init_msgitem_pool(&g_mes.mq_ctx.pool);

    for (loop = 0; loop < g_mes.profile.work_thread_num; loop++) {
        g_mes.mes_ctx.work_thread_idx[loop] = loop;
        if (CT_SUCCESS != cm_create_thread(dtc_task_proc, 0, &g_mes.mes_ctx.work_thread_idx[loop],
                                           &g_mes.mq_ctx.tasks[loop].thread)) {
            CT_LOG_RUN_ERR("create work thread %u failed.", loop);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

void free_dtc_mq_instance(void)
{
    uint32 loop;

    for (loop = 0; loop < g_mes.profile.work_thread_num; loop++) {
        g_mes.mq_ctx.tasks[loop].thread.closed = CT_TRUE;
    }

    for (loop = 0; loop < MES_TASK_GROUP_ALL; loop++) {
        cm_release_cond(&g_mes.mq_ctx.group.task_group[loop].work_thread_cond);
    }

    for (loop = 0; loop < g_mes.profile.work_thread_num; loop++) {
        cm_close_thread(&g_mes.mq_ctx.tasks[loop].thread);
    }

    for (loop = 0; loop < MES_TASK_GROUP_ALL; loop++) {
        cm_destory_cond(&g_mes.mq_ctx.group.task_group[loop].work_thread_cond);
    }

    free_msgitem_pool(&g_mes.mq_ctx.pool);
}

status_t mes_put_inter_msg(mes_message_t *msg)
{
    dtc_msgitem_t *msgitem;

    msgitem = mes_alloc_msgitem(&g_mes.mq_ctx.local_queue);
    if (msgitem == NULL) {
        CT_LOG_RUN_ERR("mes_alloc_msgitem failed.");
        return CT_ERROR;
    }
    uint64 start_time = 0;
    mes_get_consume_time_start(&start_time);

    MES_LOG_WITH_MSG(msg);

    msgitem->msg.head = msg->head;
    msgitem->msg.buffer = msg->buffer;
    msgitem->start_time = start_time;

    mes_put_msgitem(msgitem);
    return CT_SUCCESS;
}

void mes_put_msgitem(dtc_msgitem_t *msgitem)
{
    mes_task_group_id_t group_id = g_mes.mq_ctx.command_attr[msgitem->msg.head->cmd].group_id;
    dtc_msgqueue_t *queue = &g_mes.mq_ctx.group.task_group[group_id].queue;

    put_msgitem(queue, msgitem);

    cm_release_cond_signal(&g_mes.mq_ctx.group.task_group[group_id].work_thread_cond);

    return;
}

void mes_set_command_task_group(mes_command_t command, mes_task_group_id_t group_id)
{
    g_mes.mq_ctx.command_attr[command].group_id = group_id;
}

status_t mes_set_group_task_num(mes_task_group_id_t group_id, uint32 task_num)
{
    mes_task_group_t *task_group = &g_mes.mq_ctx.group.task_group[group_id];

    if (task_num == 0) {
        CT_THROW_ERROR_EX(ERR_MES_PARAMETER, "[mes]: group_id %u can't set task_num 0.", group_id);
        return CT_ERROR;
    }

    if (task_group->is_set) {
        CT_THROW_ERROR_EX(ERR_MES_PARAMETER, "[mes]: group_id %u has been set already.", group_id);
        return CT_ERROR;
    }

    if ((g_mes.mq_ctx.group.assign_task_idx + task_num) > g_mes.mq_ctx.task_num) {
        CT_THROW_ERROR_EX(ERR_MES_PARAMETER, "[mes]: group %u task num %u has excced total task num.", group_id,
                          task_num);
        return CT_ERROR;
    }

    task_group->group_id = group_id;
    task_group->task_num = task_num;
    task_group->start_task_idx = g_mes.mq_ctx.group.assign_task_idx;
    g_mes.mq_ctx.group.assign_task_idx += task_num;
    task_group->is_set = CT_TRUE;

    CT_LOG_DEBUG_INF("[mes] set group %u start_task_idx %u task num %u.", group_id, task_group->start_task_idx,
        task_num);
    return CT_SUCCESS;
}

mes_task_group_t *mes_get_task_group(uint32 task_index)
{
    mes_task_group_t *group;

    for (uint32 i = 0; i < MES_TASK_GROUP_ALL; i++) {
        group = &g_mes.mq_ctx.group.task_group[i];
        if (task_index < (group->start_task_idx + group->task_num)) {
            return group;
        }
    }

    return NULL;
}
