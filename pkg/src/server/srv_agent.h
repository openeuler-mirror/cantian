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
 * srv_agent.h
 *
 *
 * IDENTIFICATION
 * src/server/srv_agent.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SRV_AGENT_H__
#define __SRV_AGENT_H__

#include "cm_defs.h"
#include "cm_thread.h"
#include "cm_spinlock.h"
#include "cs_pipe.h"
#include "srv_session.h"
#include "cm_sync.h"
#include "srv_job.h"

#ifdef __cplusplus
extern "C" {
#endif

// threshlold_secs seconds, 5ms sleep so multi 200
#define AGENT_SHRINK_THRESHOLD(threshlold_secs) (1000 * (uint32)(threshlold_secs))
#define AGENT_EXTEND_STEP 4

struct st_reactor;
typedef struct st_agent {
    struct st_reactor *reactor;
    session_t *session; // current session
    thread_t thread;
    char *area_buf;
    char *plog_buf;
    char *update_buf; // area for update_info->columns, offsets, lens and data
    char *page_buf;
    cm_stack_t stack;
    cm_event_t event;
    lex_t *lex;
#ifndef WIN32
    bool32 iconv_ready;
    iconv_t env[2];
#endif

    union {
        cs_packet_t recv_pack; /* packet  receive from client when work as pipe mode */
        job_info_t job_info;   /* job info when work as background mode to process job */
    };
    cs_packet_t send_pack;
    bool8 is_extend;
    bool8 priv;
    uint8 unused[2]; // for 4 bytes align
    cpu_set_t cpuset;
    struct st_agent *prev;
    struct st_agent *next;
} agent_t;

typedef struct st_agent_pool {
    struct st_reactor *reactor;
    struct st_agent *agents;
    struct st_extend_agent *ext_agents;
    spinlock_t lock_idle; // lock for idle queue
    biqueue_t idle_agents;
    uint32 idle_count;
    spinlock_t lock_new;    // lock for creating new agent
    biqueue_t blank_agents; // agents not initialized (for example: private memory not allocated, etc.)
    uint32 blank_count;
    uint32 curr_count; // agent pool has create thread num
    uint32 optimized_count;
    uint32 max_count;
    cm_event_t idle_evnt;        // when an session detached from agent, this event will be triggered.
    uint32 extended_count;       //
    atomic32_t shrink_hit_count; // when session < optimized_count, increase
    bool32 priv;
} agent_pool_t;

typedef struct st_extend_agent {
    struct st_agent *slot_agents;
    uint32 slot_agent_count;
} extend_agent_t;

void free_extend_agent(agent_pool_t *agent_pool);
void srv_shutdown_agent_pool(agent_pool_t *agent_pool);
void srv_get_stack_base(thread_t *thread, agent_t **agent);
status_t srv_start_agent(agent_t *agent, thread_entry_t entry);


status_t srv_create_agent_pool(agent_pool_t *agent_pool, bool8 priv);
void srv_destroy_agent_pool(agent_pool_t *agent_pool);
void srv_destroy_agent_pool_nowait(agent_pool_t *agent_pool);
status_t srv_attach_agent(session_t *session, agent_t **agent, bool32 nowait);
void srv_bind_sess_agent(session_t *session, agent_t *agent);
void srv_unbind_sess_agent(session_t *session, agent_t *agent);
void srv_detach_dedicated_agent(session_t *session);
void srv_shrink_agent_pool(agent_pool_t *agent_pool);
void shrink_pool_core(agent_pool_t *agent_pool);
void close_extend_agent(agent_pool_t *agent_pool);
status_t srv_diag_proto_type(session_t *session);
status_t srv_process_single_session_cs_wait(session_t *session, bool32 *ready);
status_t srv_process_single_session(session_t *session);
status_t srv_alloc_agent_res(agent_t *agent);
void srv_free_agent_res(agent_t *agent, bool32 free_pack);
void srv_free_dedicated_agent_res(agent_t *agent);
agent_t *srv_create_dedicated_agent(void);
status_t srv_create_agent_private_area(agent_t *agent);
#ifdef __cplusplus
}
#endif

#endif
