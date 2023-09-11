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
 * mes_func_mock.h
 *
 *
 * IDENTIFICATION
 * src/mec/mes_func_mock.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef DTC_MES_MOCK_H__
#define DTC_MES_MOCK_H__

#include "cm_defs.h"
#include "cm_thread.h"
#include "cm_timer.h"
#include "cs_pipe.h"
#include "cs_listener.h"
#include "mes_func.h"

#define GET_MSG_HEAD(pack) (pack)->msg.head
#define GET_MSG_BUFF(pack) (pack)->msg.buffer

typedef void (*msg_proc_t)(void *ctx, mes_message_t *message);

typedef struct st_msg_processor {
    mes_command_t cmd;
    msg_proc_t proc;
    bool32 is_enqueue;
    char name[GS_NAME_BUFFER_SIZE];
} msg_processor_t;

typedef enum en_mes_mod { MES_MOD_CLUSTER = 0, MES_MOD_EXTPROC, MES_MOD_CEIL } mes_mod_t;

typedef struct st_mes_ex_message {
    mes_message_t msg;
    uint32 buf_size;
    uint32 offset;   // for reading
    uint32 options;  // options
} mes_message_ex_t;

void mes_set_msg_enqueue2(mes_command_t command, bool32 is_enqueue, mes_profile_t *profile);

bool32 mes_connection_ready2(uint32 inst_id, mes_mod_t module);

void mes_destory_inst(mes_mod_t module);

void mes_lock_channel(mes_mod_t module);

void mes_unlock_channel(mes_mod_t module);

void mes_reset_channels(mes_mod_t module);

status_t mes_create_inst(mes_profile_t *profile);

#endif
