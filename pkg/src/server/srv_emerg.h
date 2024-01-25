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
 * srv_emerg.h
 *
 *
 * IDENTIFICATION
 * src/server/srv_emerg.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SRV_EMERG_H__
#define __SRV_EMERG_H__

#include "srv_session.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_sql_emerg_pool {
    spinlock_t lock;
    uint32 max_sessions;
    session_t *sessions[CT_MAX_EMERG_SESSIONS];
    biqueue_t idle_sessions;
    atomic_t service_count;
    uint32 is_log : 1;
    uint32 reserved : 31;
} sql_emerg_pool_t;

status_t srv_create_emerg_session(cs_pipe_t *pipe);
status_t srv_init_emerg_sessions(void);
void srv_close_emerg_agents(void);

#ifdef __cplusplus
}
#endif

#endif
