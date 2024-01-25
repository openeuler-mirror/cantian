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
 * srv_emerg.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_emerg.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "srv_emerg.h"
#include "srv_instance.h"
#include "srv_session.h"
#include "srv_stat.h"

#ifdef __cplusplus
extern "C" {
#endif

inline static void srv_bind_dedicated_agent(session_t *session, agent_t *agent)
{
    session->agent = agent;
    cm_stack_reset(session->stack);
    session->recv_pack = &agent->recv_pack;
    session->send_pack = &agent->send_pack;
    agent->session = session;
    KNL_SESSION_SET_CURR_THREADID(&session->knl_session, cm_get_current_thread_id());
}

void srv_detach_dedicated_agent(session_t *session)
{
    agent_t *agent = session->agent;

    agent->session = NULL;
    session->agent = NULL;
    session->recv_pack = NULL;
    session->send_pack = NULL;
    KNL_SESSION_CLEAR_THREADID(&session->knl_session);
    /* status might still be ACTIVE while being detached from agent, so need to reset */
    session->knl_session.status = SESSION_INACTIVE;

    CT_LOG_DEBUG_INF("[agent] detach session %u from dedicated agent %lu success, current user %s.",
        session->knl_session.id, agent->thread.id, session->db_user);
}

static void srv_return_emerg_pool(session_t *session)
{
    sql_emerg_pool_t *pool = &g_instance->sql_emerg_pool;

    session->is_free = CT_TRUE;
    session->reactor = NULL;

    cm_spin_lock(&pool->lock, NULL);
    biqueue_add_tail(&pool->idle_sessions, QUEUE_NODE_OF(session));
    cm_spin_unlock(&pool->lock);
    (void)cm_atomic_dec(&pool->service_count);
}

void srv_release_emerg_session(session_t *session)
{
    srv_deinit_session(session);
    CM_MFENCE;
    /* should put last position */
    srv_return_emerg_pool(session);
}

static void srv_dedicated_agent_entry(thread_t *thread)
{
    status_t ret = CT_ERROR;
    agent_t *agent = (agent_t *)thread->argument;
    session_t *session = agent->session;
    uint32 id = session->knl_session.id;
    /* set the start stack address of this thread */
    srv_get_stack_base(thread, &agent);

    cs_init_packet(&agent->recv_pack, CT_FALSE);
    cs_init_packet(&agent->send_pack, CT_FALSE);

    /* set agent's max packet size when startup. */
    agent->recv_pack.max_buf_size = g_instance->attr.max_allowed_packet;
    agent->send_pack.max_buf_size = g_instance->attr.max_allowed_packet;

    cm_set_thread_name("dedicated-agent");
    knl_set_curr_sess2tls((void *)session);
    KNL_SESSION_SET_CURR_THREADID(&session->knl_session, cm_get_current_thread_id());
    cm_log_set_session_id(session->knl_session.id);
    CT_LOG_DEBUG_INF("dedicated agent thread started");
    while (!thread->closed) {
        ret = srv_process_single_session(session);
        if (ret != CT_SUCCESS || session->is_log_out) {
            if (session->is_auth) {
                (void)cm_atomic_dec(&g_instance->logined_count);
            }
            break;
        }
    }

    sql_audit_init(&session->sql_audit);
    session->sql_audit.action = SQL_AUDIT_ACTION_DISCONNECT;
    sql_record_audit_log(session, CT_SUCCESS, CT_TRUE);

    srv_deinit_session(session);
    srv_detach_dedicated_agent(session);
    CM_MFENCE;
    srv_return_emerg_pool(session);
    /* Caution: can not operation session */
    CT_LOG_DEBUG_INF("[agent] free dedicated-mode session %u successfully.", id);

    CT_LOG_DEBUG_INF("dedicated agent thread closed");
    cm_release_thread(thread);
    srv_free_dedicated_agent_res(agent);
    CM_FREE_PTR(agent);
}

status_t srv_attach_dedicated_agent(session_t *session)
{
    status_t status;
    agent_t *agent = NULL;

    do {
        agent = srv_create_dedicated_agent();
        if (agent == NULL) {
            status = CT_ERROR;
            break;
        }
        srv_bind_dedicated_agent(session, agent);
        status = srv_start_agent(agent, srv_dedicated_agent_entry);
    } while (0);

    if (status == CT_SUCCESS) {
        return CT_SUCCESS;
    }
    if (agent == NULL) {
        srv_release_emerg_session(session);
        return CT_ERROR;
    }

    srv_deinit_session(session);
    if (agent->session != NULL) {
        srv_detach_dedicated_agent(session);
    }
    CM_MFENCE;
    srv_return_emerg_pool(session);
    srv_free_dedicated_agent_res(agent);
    CM_FREE_PTR(agent);
    return CT_ERROR;
}

status_t srv_create_emerg_session(cs_pipe_t *pipe)
{
    session_t *session = NULL;
    biqueue_node_t *node = NULL;
    sql_emerg_pool_t *pool = &g_instance->sql_emerg_pool;
    uint16 stat_id = CT_INVALID_ID16;

    do {
        if (biqueue_empty(&pool->idle_sessions)) {
            break;
        }

        if (srv_alloc_stat(&stat_id) != CT_SUCCESS) {
            return CT_ERROR;
        }

        cm_spin_lock(&pool->lock, NULL);
        node = biqueue_del_head(&pool->idle_sessions);
        cm_spin_unlock(&pool->lock);
    } while (0);

    if (node == NULL) {
        if (stat_id != CT_INVALID_ID16) {
            srv_release_stat(&stat_id);
        }

        if (!pool->is_log) {
            CT_THROW_ERROR(ERR_TOO_MANY_CONNECTIONS, pool->max_sessions);
            CT_LOG_ALARM(WARN_MAXCONNECTIONS, "'max-sessions':'%u'}", pool->max_sessions);
            pool->is_log = CT_TRUE;
        }
        return CT_ERROR;
    }

    if (pool->is_log == CT_TRUE) {
        pool->is_log = CT_FALSE;
        cm_reset_error();
        CT_LOG_RUN_INF("emerg session pool resume idle after exceed maximum");
        CT_LOG_ALARM_RECOVER(WARN_MAXCONNECTIONS, "'max-sessions':'%u'}", pool->max_sessions);
    }

    session = OBJECT_OF(session_t, node);
    session->is_free = CT_FALSE;
    session->knl_session.stat_id = stat_id;
    session->knl_session.stat = g_instance->stat_pool.stats[stat_id];

    (void)cm_atomic_inc(&g_instance->sql_emerg_pool.service_count);
    srv_reset_session(session, pipe);

    knl_securec_check(
        strncpy_s(session->os_host, CT_HOST_NAME_BUFFER_SIZE, LOOPBACK_ADDRESS, strlen(LOOPBACK_ADDRESS)));

#ifndef WIN32
    if (srv_register_zombie_epoll(session) != CT_SUCCESS) {
        srv_release_emerg_session(session);
        return CT_ERROR;
    }
#endif

    return srv_attach_dedicated_agent(session);
}

status_t srv_init_emerg_sessions(void)
{
    uint32 i, id, loop;
    session_t *session = NULL;
    // init sql emerg sessions
    g_instance->sql_emerg_pool.is_log = CT_FALSE;
    g_instance->sql_emerg_pool.lock = 0;
    g_instance->sql_emerg_pool.service_count = 0;

    for (i = 0; i < g_instance->sql_emerg_pool.max_sessions; i++) {
        if (srv_alloc_reserved_session(&id) != CT_SUCCESS) {
            return CT_ERROR;
        }
        g_instance->session_pool.sessions[id]->type = SESSION_TYPE_EMERG;
        g_instance->session_pool.sessions[id]->knl_session.match_cond = sql_match_cond;
        g_instance->sql_emerg_pool.sessions[i] = g_instance->session_pool.sessions[id];
    }
    biqueue_init(&g_instance->sql_emerg_pool.idle_sessions);

    for (loop = 0; loop < g_instance->sql_emerg_pool.max_sessions; ++loop) {
        session = g_instance->sql_emerg_pool.sessions[loop];
        session->is_free = CT_TRUE;
        biqueue_add_tail(&g_instance->sql_emerg_pool.idle_sessions, QUEUE_NODE_OF(session));
    }

    return CT_SUCCESS;
}

void srv_close_emerg_agents(void)
{
    session_t *session = NULL;
    for (uint32 i = 0; i < g_instance->sql_emerg_pool.max_sessions; i++) {
        session = g_instance->sql_emerg_pool.sessions[i];
        if (session != NULL && session->agent != NULL) {
            cm_close_thread_nowait(&session->agent->thread);
        }
    }

    while (g_instance->sql_emerg_pool.service_count > 0) {
        cm_sleep(1);
    }
}

#ifdef __cplusplus
}
#endif
