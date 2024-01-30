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
 * cms_mes.h
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_mes.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMS_MES_H
#define CMS_MES_H
#include "cm_spinlock.h"
#include "cms_client.h"
#include "cm_types.h"
#include "cms_msg_def.h"
#include "mes_queue.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CMS_MAX_LATCH_STACK_DEPTH  8
#define CMS_MES_THREAD_NUM 5
#define CMS_MES_WAIT_MAX_TIME 5000
#define MES_MAX_SESSION_NUM 40
#define MES_MESSAGE_POOL_SIZE 256
#define MES_MESSAGE_POOL_COUNT 1
#define MES_MESSAGE_QUEUE_COUNT 1
#define MES_MESSAGE_BUFF_COUNT (4 * 1024)
#define MES_MESSAGE_CHANNEL_NUM 1
#define CMS_MSG_MAX_LEN 1000

typedef void(*cms_message_proc_t)(mes_message_t *message);
typedef struct st_cms_processor {
    cms_message_proc_t  proc;
    bool32              is_enqueue;
    char                name[CT_MAX_NAME_LEN];
} cms_processor_t;

typedef enum en_cms_mes_command {
    CMS_MES_MSG,
    CMS_MES_MSG_WITH_ACK,
    CMS_MES_CMD_CEIL
} cms_mes_command_t;

typedef struct st_cms_session {
    uint32 id;
    bool32 is_closed;
} cms_session_t;

typedef struct st_cms_session_ctrl {
    spinlock_t lock;
    uint32     total;
    uint32     used_count;
    cms_session_t *sessions;
} cms_session_ctrl_t;

typedef struct st_cms_mes_msg {
    mes_message_head_t head;
    char cms_msg[CMS_MSG_MAX_LEN];
} cms_mes_msg_t;

status_t cms_init_session(void);
void cms_free_mes_session(void);
status_t cms_create_session(cms_session_t **session);
void cms_destroy_session(cms_session_t *session);
cms_session_ctrl_t *get_session_ctrl(void);
cms_processor_t *get_g_cms_processors(void);
void cms_msg_enque(cms_packet_head_t *head);
EXTER_ATTACK void cms_process_message(uint32 work_idx, mes_message_t *msg);
status_t cms_register_proc_func(cms_mes_command_t command_type, cms_message_proc_t proc, bool32 is_enqueue,
                                const char *func_name);
status_t cms_register_proc(void);
status_t cms_set_mes_profile(void);
EXTER_ATTACK void cms_mes_process_msg_ack(mes_message_t *msg);
EXTER_ATTACK void mes_proc_recv_msg(mes_message_t *mes_msg);
status_t cms_startup_mes(void);
status_t cms_mes_send_data(cms_packet_head_t* cms_msg, cms_packet_head_t* res, cms_session_t *session,
    uint32 timeout_ms, bool32 request_ack);
status_t cms_mes_send_to(cms_packet_head_t* cms_msg);
status_t cms_mes_request(cms_packet_head_t* req, cms_packet_head_t* res, uint32 timeout_ms);
status_t cms_mes_send_cmd_to_other(cms_packet_head_t* req, cms_packet_head_t* res, uint16 node_id);
status_t init_mes_send_msg(cms_packet_head_t* cms_msg, uint32 sid, bool32 request_ack, cms_mes_msg_t *mes_msg);
status_t creat_mes_recv_msg(mes_message_t *mes_res, cms_packet_head_t* res);
void cms_mes_wakeup_rooms(void);
void cms_mes_send_entry(thread_t* thread);

#ifdef __cplusplus
}
#endif
#endif
