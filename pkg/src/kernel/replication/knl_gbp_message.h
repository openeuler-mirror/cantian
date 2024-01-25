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
 * knl_gbp_message.h
 *
 *
 * IDENTIFICATION
 * src/kernel/replication/knl_gbp_message.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __KNL_GBP_MESSAGE_H__
#define __KNL_GBP_MESSAGE_H__

#include "knl_interface.h"
#include "knl_log.h"

#define GBP_BATCH_PAGE_NUM  100
#define GBP_PAGE_SIZE       8192
#define GBP_MSG_LEN         64
#define GBP_BUFFER_COUNT    8

/* The message protocol format between Kernel and GBP */
typedef struct st_gbp_msg_hdr {
    uint32 msg_type;
    uint32 msg_length; /* length of the message header plus message content */
    uint32 queue_id;
    int32 msg_fd;
} gbp_msg_hdr_t;

typedef struct st_gbp_msg_ack {
    gbp_msg_hdr_t header;
    uint32 ack_type;
    uint32 ack_data;
} gbp_msg_ack_t;

#define GBP_SET_MSG_HEADER(msgptr, type, length, fd)   \
    do { \
        ((gbp_msg_hdr_t*) (msgptr))->msg_type = (type);     \
        ((gbp_msg_hdr_t*) (msgptr))->msg_length = (length); \
        ((gbp_msg_hdr_t*) (msgptr))->msg_fd = (int32)(fd);         \
    } while (0)

#define GBP_MSG_TYPE(msgptr) \
    (((const gbp_msg_hdr_t*)(msgptr))->msg_type)

/* Kernel request message to GBP */
#define GBP_REQ_PAGE_READ           20000   /* Kernel read page from GBP */
#define GBP_REQ_PAGE_WRITE          20100   /* Kernel write page to GBP */
#define GBP_REQ_BATCH_PAGE_READ     21000   /* background worker read batch page from GBP */
#define GBP_REQ_READ_CKPT           31000   /* get gbp recover point */
#define GBP_REQ_NOTIFY_MSG          41000
#define GBP_REQ_SHAKE_HAND          51000
#define GBP_REQ_CLOSE_CONN          61000

/* read gbp result status values */
#define GBP_READ_RESULT_OK          0
#define GBP_READ_RESULT_NOPAGE      1
#define GBP_READ_RESULT_ERROR       2

typedef struct st_gbp_page_item {
    page_id_t page_id;
    uint32 session_id;
    uint32 reserved;
    log_point_t gbp_trunc_point;
    log_point_t gbp_lrp_point;
    char block[GBP_PAGE_SIZE];  /* page content */
} gbp_page_item_t;

/* Kernel read page from GBP */
typedef struct st_gbp_read_req {
    gbp_msg_hdr_t header;
    page_id_t page_id;
    uint16 buf_pool_id;
    uint16 reserved[3];
} gbp_read_req_t;

/* background worker read page from GBP */
typedef struct st_gbp_batch_read_req {
    gbp_msg_hdr_t header;
    log_point_t gbp_skip_point;  // we only pull gbp pages which lrp_point >= gbp_skip_point
} gbp_batch_read_req_t;

/* Kernel write page to GBP */
typedef struct st_gbp_write_req {
    gbp_msg_hdr_t header;
    uint32 page_num;
    log_point_t batch_begin_point;
    log_point_t batch_trunc_point;
    log_point_t batch_lrp_point;
    gbp_page_item_t pages[GBP_BATCH_PAGE_NUM];
    uint32 page_num_tail;   // for validate page_num, page_num_tail must equel page_num
} gbp_write_req_t;

typedef struct st_gbp_read_ckpt_req {
    gbp_msg_hdr_t header;
    bool32 check_end_point;
    log_point_t aly_end_point;  /* the redo analysis end point */
} gbp_read_ckpt_req_t;


typedef struct st_gbp_read_resp {
    gbp_msg_hdr_t header;
    uint32 result;         /* GBP_READ_RESULT_XXX */
    uint32 unused;
    page_id_t pageid;
    log_point_t gbp_trunc_point;
    char block[GBP_PAGE_SIZE];  /* used for GBP to send page */
} gbp_read_resp_t;

typedef struct st_gbp_batch_read_resp {
    gbp_msg_hdr_t header;
    uint32 result;         /* GBP_READ_RESULT_XXX */
    uint32 count;
    char msg[GBP_MSG_LEN];
    gbp_page_item_t pages[GBP_BATCH_PAGE_NUM];
} gbp_batch_read_resp_t;

typedef struct st_gbp_read_ckpt_resp {
    gbp_msg_hdr_t header;
    bool32 gbp_unsafe;
    log_point_t begin_point;
    log_point_t rcy_point;
    log_point_t lrp_point;
    uint64 max_lsn;
    char unsafe_reason[GBP_MSG_LEN];
} gbp_read_ckpt_resp_t;

typedef enum en_gbp_notify_msg {
    MSG_GBP_INVALID = 0,
    MSG_GBP_READ_BEGIN,
    MSG_GBP_READ_END,
    MSG_GBP_HEART_BEAT,
} gbp_notify_msg_e;

typedef enum en_gbp_notify_ack {
    ACK_GBP_INVALID = 0,
    ACK_GBP_READ_BEGIN,
} gbp_notify_ack_e;

typedef struct st_gbp_db_status {
    char local_host[CM_MAX_IP_LEN];
    repl_role_t db_role;
    db_status_t db_open;
} gbp_db_status_t;

typedef struct st_gbp_notify_req {
    gbp_msg_hdr_t header;
    gbp_notify_msg_e msg;
    gbp_db_status_t db_stat;
} gbp_notify_req_t;

typedef struct st_gbp_shake_hand_req {
    gbp_msg_hdr_t header;
    uint32 queue_id;
    bool32 is_temp;
    bool32 is_standby;
    uint32 unused;
} gbp_shake_hand_req_t;

typedef struct st_gbp_shake_hand_resp {
    gbp_msg_hdr_t header;
    uint32 queue_id;
    bool32 is_temp;
} gbp_shake_hand_resp_t;

#endif
