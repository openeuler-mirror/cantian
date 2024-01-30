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
 * mes_queue.h
 *
 *
 * IDENTIFICATION
 * src/mec/mes_queue.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef DTC_MQ_H__
#define DTC_MQ_H__

#include "knl_session.h"
#include "cm_defs.h"
#include "mes_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DTC_MAX_BACKGROUND_SESSION_TASK (16)
#define MES_TASK_QUEUE_CHOICE (4)
#define MES_VERSION (0)

typedef enum en_mes_task_group_id_t {
    MES_TASK_GROUP_ZERO = 0,
    MES_TASK_GROUP_ONE,
    MES_TASK_GROUP_TWO,
    MES_TASK_GROUP_THREE,
    MES_TASK_GROUP_FOUR,
    MES_TASK_GROUP_ALL
} mes_task_group_id_t;

typedef struct st_mes_message_head {
    uint16 head_cks; // head crc num
    uint8 version;
    uint8 cmd;       // command
    uint16 src_sid;  // from session
    uint16 dst_sid;  // to session
    uint32 size;
    uint32 rsn;
    uint64 req_start_time;
    uint64 start_time;
    uint8 src_inst;  // from instance
    uint8 dst_inst;  // to instance
    uint16 extend_size; // enable the receiver to get the message body address for the mes_send_data3 interface.
    uint16 body_cks;    // body crc num
    int8 status;
    uint8 flags;
    uint64 unused;
} mes_message_head_t;

typedef struct st_mes_message {
    mes_message_head_t *head;
    char *buffer;
} mes_message_t;

typedef struct st_dtc_msgitem {
    mes_message_t msg;
    uint64 start_time;
    struct st_dtc_msgitem *next;
} dtc_msgitem_t;

#ifdef WIN32
typedef struct st_dtc_msgqueue
#else
typedef struct __attribute__((aligned(128))) st_dtc_msgqueue
#endif
{
    spinlock_t lock;
    volatile uint32 count;
    dtc_msgitem_t *first;
    dtc_msgitem_t *last;
} dtc_msgqueue_t;

void init_msgqueue(dtc_msgqueue_t *queue);

#define MSG_ITEM_BATCH_SIZE 32
#define INIT_MSGITEM_BUFFER_SIZE 8192
#define MAX_POOL_BUFFER_COUNT 8192

typedef struct st_dtc_msgitem_pool {
    spinlock_t lock;
    dtc_msgitem_t *buffer[MAX_POOL_BUFFER_COUNT];
    uint16 buf_idx;
    uint16 hwm;
    uint16 unused;
    dtc_msgqueue_t free_list;
} dtc_msgitem_pool_t;

void init_msgitem_pool(dtc_msgitem_pool_t *pool);
void free_msgitem_pool(dtc_msgitem_pool_t *pool);

#define DTC_MSG_QUEUE_NUM (1)

typedef struct st_mes_task_context {
    thread_t thread;
    uint8 choice;
    uint8 reserved[3];
    dtc_msgqueue_t queue;
} mes_task_context_t;

typedef struct st_mes_task_group {
    uint8 is_set;
    uint32 task_num;
    uint32 start_task_idx;
    uint8 reserved;
    mes_task_group_id_t group_id;
    dtc_msgqueue_t queue;
    cm_thread_cond_t work_thread_cond;
} mes_task_group_t;

typedef struct st_mes_mq_group {
    uint32 assign_task_idx;  // task index assigned to group.
    mes_task_group_t task_group[MES_TASK_GROUP_ALL];
} mes_mq_group_t;

typedef struct st_mes_command_attr {
    mes_task_group_id_t group_id;
} mes_command_attr_t;

typedef struct st_mq_context_t {
    uint32 task_num;
    mes_task_context_t tasks[CT_DTC_MAX_TASK_NUM];  // dtc task thread
    dtc_msgqueue_t queue[DTC_MSG_QUEUE_NUM];        // msg queue for session background task, multiple queue to reduce
                                                    // contention
    mes_command_attr_t command_attr[MES_CMD_CEIL];
    mes_mq_group_t group;
    dtc_msgitem_pool_t pool;
    dtc_msgqueue_t local_queue;  // used for local message
    dtc_msgqueue_t **channel_private_queue;
} mq_context_t;

status_t alloc_msgitems(dtc_msgitem_pool_t *pool, dtc_msgqueue_t *msgitems);
dtc_msgitem_t *mes_alloc_msgitem_nolock(dtc_msgqueue_t *queue);
dtc_msgitem_t *mes_alloc_msgitem(dtc_msgqueue_t *queue);
void put_msgitem(dtc_msgqueue_t *queue, dtc_msgitem_t *msgitem);

void dtc_task_proc(thread_t *thread);
status_t init_dtc_mq_instance(void);
void free_dtc_mq_instance(void);

uint32 dtc_get_rand_value(void);
status_t mes_put_inter_msg(mes_message_t *msg);
void mes_put_msgitem(dtc_msgitem_t *msgitem);
void mes_set_command_task_group(mes_command_t command, mes_task_group_id_t group_id);
status_t mes_set_group_task_num(mes_task_group_id_t group_id, uint32 task_num);
mes_task_group_t *mes_get_task_group(uint32 task_index);

#ifdef __cplusplus
}
#endif

#endif
