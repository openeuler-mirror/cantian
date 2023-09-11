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
 * mes_msg_pool.h
 *
 *
 * IDENTIFICATION
 * src/mec/mes_msg_pool.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __MES_MSG_POOL_H__
#define __MES_MSG_POOL_H__

#include "cm_defs.h"
#include "cm_spinlock.h"
#include "cm_spinlock.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MES_MIN_BUFFER_SIZE (4)
#define MES_MAX_BUFFER_STEP_NUM (8)
#define MES_MAX_BUFFER_QUEUE_NUM (0xFF)

typedef struct st_mes_buffer_item {
    struct st_mes_buffer_item *next;
    uint8 chunk_no;
    uint8 queue_no;
    uint8 reserved[2];
    char data[MES_MIN_BUFFER_SIZE];
} mes_buffer_item_t;

#define MES_BUFFER_ITEM_SIZE (offsetof(mes_buffer_item_t, data))

typedef struct __attribute__((aligned(128))) st_mes_buf_queue {
    spinlock_t lock;
    uint8 chunk_no;
    uint8 queue_no;
    uint8 reserved[2];
    uint32 buf_size;
    uint32 count;
    mes_buffer_item_t *first;
    mes_buffer_item_t *last;
    char *addr;
} mes_buf_queue_t;

typedef struct st_mes_buf_chunk {
    uint32 buf_size;
    uint8 chunk_no;
    volatile uint8 queue_num;
    volatile uint8 current_no;
    uint8 reserved;
    mes_buf_queue_t *queues;
} mes_buf_chunk_t;

typedef struct st_mes_buffer_attr {
    uint32 queue_count;
    uint32 size;
    uint32 count;
} mes_buffer_attr_t;

typedef struct st_mes_buffer_pool_attr {
    uint32 pool_count;
    mes_buffer_attr_t buf_attr[MES_MAX_BUFFER_STEP_NUM];
} mes_buffer_pool_attr_t;

typedef struct st_message_pool {
    spinlock_t lock;
    spinlock_t *lock_arr;
    char *buffer;
    char *real_buffer;
    char **items;
    int64 get_no;
    uint32 buffer_size;
    uint32 size;
} message_pool_t;

typedef struct st_mes_pool {
    message_pool_t small_pool;
    message_pool_t big_pool;
    uint32 count;
    mes_buf_chunk_t chunk[MES_MAX_BUFFER_STEP_NUM];
} mes_pool_t;

status_t mes_init_message_pool(void);
void mes_destory_message_pool(void);

void mes_init_send_recv_buf_pool(void);
char *mes_alloc_send_buf(void);
void mes_release_send_buf(const char *buffer);
char *mes_alloc_recv_buf(void);
void mes_release_recv_buf(const char *buffer);

void mes_release_buf_stat(const char *msg_buf);

void mes_init_buf_queue(mes_buf_queue_t *queue);
status_t mes_create_buffer_queue(mes_buf_queue_t *queue, uint8 chunk_no, uint8 queue_no, uint32 buf_size,
                                 uint32 buf_count);
void mes_destory_buffer_queue(mes_buf_queue_t *queue);
status_t mes_create_buffer_chunk(mes_buf_chunk_t *chunk, uint32 chunk_no, mes_buffer_attr_t *buf_attr);
void mes_destory_buffer_chunk(mes_buf_chunk_t *chunk);
char *mes_alloc_buf_item(uint32 len);
void mes_free_buf_item(char *buffer);

#ifdef __cplusplus
}
#endif

#endif
