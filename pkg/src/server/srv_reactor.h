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
 * srv_reactor.h
 *
 *
 * IDENTIFICATION
 * src/server/srv_reactor.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SRV_REACTOR_H__
#define __SRV_REACTOR_H__

#include "cm_defs.h"
#include "cm_thread.h"
#include "cm_queue.h"
#include "cm_spinlock.h"
#include "cm_epoll.h"
#include "srv_agent.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_reactor_status {
    REACTOR_STATUS_RUNNING,
    REACTOR_STATUS_PAUSING,
    REACTOR_STATUS_PAUSED,
    REACTOR_STATUS_STOPPED,
} reactor_status_t;

// one reactor will occupy 8 * (GS_MAX_SESSIONS + 1) bytes approximately equal to 128k
// the number of reactors may not be much, so it does not matter
// the benefit is that there will not be block when adding a session killed event to reactor
#define REACTOR_MAX_KILL_EVENTS (GS_MAX_SESSIONS + 1)

// one consumer, multi producer
typedef struct st_kill_event_queue {
    uint32 r_pos;
    uint32 w_pos;
    spinlock_t w_lock;
    session_t *sesses[REACTOR_MAX_KILL_EVENTS];
} kill_event_queue_t;

typedef struct st_reactor {
    uint32 id;
    thread_t thread;
    int epollfd;
    atomic32_t session_count;
    agent_pool_t agent_pool;
    agent_pool_t priv_agent_pool;
    reactor_status_t status;
    kill_event_queue_t kill_events;
} reactor_t;

typedef struct st_reactor_pool {
    uint32 reactor_count;
    uint32 roudroubin;
    uint32 roudroubin2;
    uint32 agents_shrink_threshold;
    reactor_t *reactors;
} reactor_pool_t;

struct st_session;

#define REACTOR_STATUS_INVALID_FOR_RETURN(reactor)                                     \
    {                                                                                  \
        if ((reactor)->status != REACTOR_STATUS_RUNNING || (reactor)->thread.closed) { \
            return GS_SUCCESS;                                                         \
        }                                                                              \
    }

void reactor_entry(thread_t *thread);
status_t reactor_set_oneshot(session_t *session);
void reactor_add_kill_event(session_t *sess);
status_t reactor_register_session(session_t *session);
status_t reactor_create_pool(void);
void reactor_destroy_pool(void);
void reactor_pause_pool(void);
void reactor_resume_pool(void);
void reactor_unregister_session(session_t *session);
static inline bool32 reactor_in_dedicated_mode(reactor_t *reactor)
{
    return reactor->agent_pool.curr_count >= (uint32)reactor->session_count;
}
status_t reactor_add_epoll_session(session_t *session);

#ifdef __cplusplus
}
#endif

#endif