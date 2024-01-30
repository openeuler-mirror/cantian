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
 * srv_agent.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_agent.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "cs_protocol.h"
#include "cm_atomic.h"
#include "cm_log.h"
#include "srv_agent.h"
#include "srv_param.h"
#include "srv_instance.h"
#include "dml_executor.h"
#include "cm_charset.h"
#include "srv_session.h"
#include "ctsql_service.h"
#include "cm_file.h"

#ifdef __cplusplus
extern "C" {
#endif


static agent_pool_t *srv_get_agent_pool(session_t *session)
{
    if (IS_COORDINATOR || IS_DATANODE) {
        if (session->priv) {
            return &session->reactor->priv_agent_pool;
        }
    }
    return &session->reactor->agent_pool;
}

static inline agent_pool_t *srv_get_self_agent_pool(agent_t *agent)
{
    if (IS_COORDINATOR || IS_DATANODE) {
        if (agent->priv) {
            return &agent->reactor->priv_agent_pool;
        }
    }
    return &agent->reactor->agent_pool;
}

status_t srv_create_agent_pool(agent_pool_t *agent_pool, bool8 priv)
{
    size_t size;
    uint32 loop;
    agent_t *agent = NULL;

    agent_pool->priv = priv;
    agent_pool->curr_count = 0;
    agent_pool->extended_count = 0;
    size = sizeof(agent_t) * agent_pool->optimized_count;
    if (size == 0 || size / sizeof(agent_t) != agent_pool->optimized_count) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, "creating agent pool");
        return CT_ERROR;
    }
    agent_pool->agents = (agent_t *)malloc(size);
    if (agent_pool->agents == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, "creating agent pool");
        return CT_ERROR;
    }
    errno_t ret = memset_s(agent_pool->agents, size, 0, size);
    if (ret != EOK) {
        CM_FREE_PTR(agent_pool->agents);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    agent_pool->lock_idle = 0;
    biqueue_init(&agent_pool->idle_agents);

    agent_pool->lock_new = 0;
    biqueue_init(&agent_pool->blank_agents);
    for (loop = 0; loop < agent_pool->optimized_count; ++loop) {
        agent = &agent_pool->agents[loop];
        agent->reactor = agent_pool->reactor;
        agent->is_extend = CT_FALSE;
        agent->priv = priv;
        biqueue_add_tail(&agent_pool->blank_agents, QUEUE_NODE_OF(agent));
    }
    agent_pool->blank_count = agent_pool->optimized_count;

    if (cm_event_init(&agent_pool->idle_evnt) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_CREATE_EVENT, cm_get_os_error());
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

// when shutdown, free all the memory of extend agents
inline void free_extend_agent(agent_pool_t *agent_pool)
{
    if (agent_pool->ext_agents == NULL) {
        return;
    }

    agent_t *slot_agents = NULL;
    uint32 slot_used_id = CM_ALIGN_CEIL(agent_pool->extended_count, AGENT_EXTEND_STEP);
    CT_LOG_RUN_INF("[agent] [private agent pool[%u]] free extend agents, extended slot count: %d",
        (uint32)agent_pool->priv, slot_used_id);

    for (uint32 i = 0; i < slot_used_id; ++i) {
        slot_agents = agent_pool->ext_agents[i].slot_agents;
        CM_FREE_PTR(slot_agents);
    }
    CM_FREE_PTR(agent_pool->ext_agents);
    agent_pool->extended_count = 0;
}

void srv_destroy_agent_pool(agent_pool_t *agent_pool)
{
    CT_LOG_RUN_INF("[agent] [private agent pool[%u]], begin to destroy agent pool", (uint32)agent_pool->priv);
    srv_shutdown_agent_pool(agent_pool);
    CT_LOG_RUN_INF("[agent] destroy agent pool end");
}

inline status_t srv_diag_proto_type(session_t *session)
{
    link_ready_ack_t ack;
    uint32 proto_code = 0;
    int32 size;

    CT_RETURN_IFERR(cs_read_bytes(session->pipe, (char *)&proto_code, sizeof(proto_code), &size));

    if (sizeof(proto_code) != size || proto_code != CT_PROTO_CODE) {
        CT_THROW_ERROR(ERR_INVALID_PROTOCOL);
        srv_judge_login(session);
        return CT_ERROR;
    }

    sql_init_session(session);
    session->proto_type = PROTO_TYPE_CT;
    session->is_auth = CT_FALSE;
    session->auth_status = AUTH_STATUS_PROTO;

    MEMS_RETURN_IFERR(memset_s(&ack, sizeof(link_ready_ack_t), 0, sizeof(link_ready_ack_t)));

    ack.endian = (IS_BIG_ENDIAN ? (uint8)1 : (uint8)0);
    ack.handshake_version = CS_HANDSHAKE_VERSION;

    if ((session->pipe_entity.type == CS_TYPE_TCP) && IS_SSL_ENABLED) {
        ack.flags |= CS_FLAG_CLIENT_SSL;
    }

    if (IS_COORDINATOR) {
        ack.flags |= CS_FLAG_CN_CONN;
    } else if (IS_DATANODE) {
        ack.flags |= CS_FLAG_DN_CONN;
    }

    return cs_send_bytes(session->pipe, (const char *)&ack, sizeof(link_ready_ack_t));
}

inline status_t srv_process_single_session_cs_wait(session_t *session, bool32 *ready)
{
    if (cs_wait(session->pipe, CS_WAIT_FOR_READ, CT_POLL_WAIT, ready) != CT_SUCCESS) {
        do_rollback(session, NULL);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static inline void srv_session_bind_cpu(session_t *session)
{
    agent_t *agent = session->agent;

    if (session->rsrc_group != NULL) {
        if (!rsrc_cpuset_is_equal(&agent->cpuset, &session->rsrc_group->cpuset)) {
            (void)rsrc_thread_bind_cpu(&agent->thread, &session->rsrc_group->cpuset);
            agent->cpuset = session->rsrc_group->cpuset;
        }
    } else {
        if (!rsrc_cpuset_is_equal(&agent->cpuset, &GET_RSRC_MGR->cpuset)) {
            (void)rsrc_thread_bind_cpu(&agent->thread, &GET_RSRC_MGR->cpuset);
            agent->cpuset = GET_RSRC_MGR->cpuset;
        }
    }
}

status_t srv_process_single_session(session_t *session)
{
    bool32 ready = CT_FALSE;

    /* hit dedicate agent scenary when killed flag true, agent should rollback or commit txn */
    if (IS_LOG_OUT(session)) {
        session->is_log_out = CT_TRUE;
        return CT_SUCCESS;
    }

    knl_begin_session_wait(&session->knl_session, MESSAGE_FROM_CLIENT, CT_TRUE);
    CT_RETURN_IFERR(srv_process_single_session_cs_wait(session, &ready));
    if (!ready) {
        return CT_SUCCESS;
    }
    knl_end_session_wait(&session->knl_session, MESSAGE_FROM_CLIENT);

    /* bind session thread to cpu */
    srv_session_bind_cpu(session);
    init_tls_error();
    /* process request command */
    if (session->proto_type == PROTO_TYPE_UNKNOWN) {
        status_t res = srv_diag_proto_type(session);
        if (res != CT_SUCCESS) {
            cm_log_protocol_error();
        }
        return res;
    } else {
        return srv_process_command(session);
    }
}

static inline bool32 srv_session_dedicate_agent(session_t *session)
{
    rsrc_group_t *group = session->rsrc_group;
    CT_RETVALUE_IFTRUE(group == NULL, CT_TRUE);
    return (bool32)((uint32)group->rsrc_monitor.active_sess < group->max_active_sess);
}

static bool8 srv_session_in_priv_resv(session_t *session)
{
    if (IS_COORDINATOR || IS_DATANODE) {
        // DO care about 'session->client_kind and session->agent->priv', do NOT care about ''session->priv'
        bool8 ret = (session->client_kind == CLIENT_KIND_CN_INNER && session->agent->priv);
        if (ret) {
            CT_LOG_DEBUG_INF("session cmd[%u] and agent is private %u", (uint32)session->agent->recv_pack.head->cmd,
                session->agent->priv);
        }
        return ret;
    } else {
        return CT_FALSE;
    }
}

void srv_unlink_session_agent(session_t *session)
{
    agent_t *agent = session->agent;

    /* session detached from agent, marked as INACTIVE */
    if (session->rsrc_group != NULL && session->is_active) {
        session->is_active = CT_FALSE;
        (void)rsrc_active_sess_dec(session);
    }

    agent->session = NULL;
    session->stack = NULL;
    session->lex = NULL;
    KNL_SESSION_CLEAR_THREADID(&session->knl_session);

    /* status might still be ACTIVE while being detached from agent, so need to reset */
    session->knl_session.status = SESSION_INACTIVE;
    CM_MFENCE;
    session->agent = NULL;
}


static void srv_process_free_session(session_t *session, agent_t *agent)
{
    // the session is marked as killed, then added to reactor's kill-event queue
    // subsequently the reactor will deal the event in the following way:
    // 1.find an idle agent
    // 2.attach the session to it, notify the agent
    // then current branch will be reached.
    // when an agent is detached by a session, it will be attached by another session
    // but the stack of agent is needed when clean a session
    // so first clean the session, then detach it from a agent, at last mark the session as free
    sql_audit_init(&session->sql_audit);
    if (session->interactive_info.is_timeout) {
        session->sql_audit.action = SQL_AUDIT_ACTION_INTERACTIVE_TIMEOUT;
    } else {
        session->sql_audit.action = SQL_AUDIT_ACTION_DISCONNECT;
    }

    sql_record_audit_log(session, CT_SUCCESS, CT_TRUE);

    srv_unlink_session_agent(session);
    srv_release_session(session);
    CT_LOG_DEBUG_INF("[agent][private [%u]] free session %u [private [%u]] successfully.", (uint32)agent->priv,
        session->knl_session.id, (uint32)session->priv);
    return;
}

static void srv_proc_single_sess_fail(session_t *session)
{
    if (g_instance->sql.commit_on_disconn) {
        (void)do_commit(session);
    } else {
        if (srv_session_in_trans(session) && !session->knl_session.force_kill) {
            do_rollback(session, NULL);
        }
    }
    if (knl_alck_have_se_lock(session)) {
        knl_destroy_se_alcks(session);
    }
    srv_mark_user_sess_killed(session, CT_FALSE, session->knl_session.serial_id);
}

static void srv_detach_agent_and_set_oneshot(session_t *session, agent_t *agent)
{
    agent->reactor->agent_pool.shrink_hit_count = 0;
    srv_unlink_session_agent(session);
    // this function should be invoked after session detached from agent
    // otherwise two agent will deal the same session,
    // while a new request arrived and session was attached to a new session
    if (session->knl_session.killed) { // in case raced with reactor_deal_kill_events
        return;
    }

    CM_MFENCE;
    if (CT_SUCCESS != reactor_set_oneshot(session)) {
        CT_LOG_RUN_ERR("[agent] [private [%u]] set oneshot flag of socket failed, "
            "session %d [private [%u]], reactor %lu, os error %d",
            (uint32)agent->priv, session->knl_session.id, (uint32)session->priv, session->reactor->thread.id,
            cm_get_sock_error());
    }
}

static void srv_return_agent(agent_t *agent)
{
    agent_pool_t *agent_pool = srv_get_self_agent_pool(agent);

    cm_spin_lock(&agent_pool->lock_idle, NULL);
    biqueue_add_tail(&agent_pool->idle_agents, QUEUE_NODE_OF(agent));
    agent_pool->idle_count++;
    cm_spin_unlock(&agent_pool->lock_idle);
    cm_event_notify(&agent_pool->idle_evnt);
    /* idle agent is available, notify resource manager */
    cm_event_notify(&GET_RSRC_MGR->event);
}

static void srv_try_process_multi_sessions(agent_t *agent)
{
    session_t *session = NULL;
    status_t ret = CT_SUCCESS;

    for (;;) {
        // event will be set by reactor
        if (CT_SUCCESS == cm_event_timedwait(&agent->event, 50)) {
            break;
        }

        if (agent->thread.closed) {
            return;
        }
    }

    session = agent->session;
    session->knl_session.spid = cm_get_current_thread_id();
    knl_set_curr_sess2tls((void *)session);
    // set session id here, because need consider agent mode, for example, agent mode is AGENT_MODE_SHARED
    cm_log_set_session_id(session->knl_session.id);
    if (session->knl_session.killed == CT_TRUE && !session->is_reg) {
        srv_process_free_session(session, agent);
        srv_return_agent(agent);
        return;
    }

    CT_LOG_DEBUG_INF("[agent][private [%u]] begin to process socket event session %u [private [%u]].",
        (uint32)agent->priv, session->knl_session.id, (uint32)session->priv);

    while (!agent->thread.closed) {
        ret = srv_process_single_session(session);
        if (ret != CT_SUCCESS || session->is_log_out) {
            srv_proc_single_sess_fail(session);
            // must be last, because reactor thread judge sess->agent = NULL,
            // bind another agent to process free session
            srv_unlink_session_agent(session);
            srv_return_agent(agent);
            return;
        } else if (srv_session_in_priv_resv(session)) {
            continue;
        } else if (reactor_in_dedicated_mode(agent->reactor) && srv_session_dedicate_agent(session)) {
            continue;
        } else if (!srv_session_in_trans(session) && !knl_alck_have_se_lock(session)) {
            srv_detach_agent_and_set_oneshot(session, agent);
            // must be last, because reactor thread judge sess->agent = NULL,
            // bind another agent to process free session
            srv_return_agent(agent);
            return;
        }
    }
}


static inline void srv_return_agent2blankqueue(agent_t *agent)
{
    agent_pool_t *agent_pool = srv_get_self_agent_pool(agent);

    // when failed to start an agent, the agent has not be added to idle queue
    // so then pointer 'next' could be null
    if (agent->next != NULL) {
        // remove agent from idle queue
        cm_spin_lock(&agent_pool->lock_idle, NULL);
        if (agent->next != NULL) { // re-check to protect change by reactor thread
            biqueue_del_node(QUEUE_NODE_OF(agent));
            agent_pool->idle_count--;
        }
        cm_spin_unlock(&agent_pool->lock_idle);
    }

    // add agent to blank queue
    cm_spin_lock(&agent_pool->lock_new, NULL);
    biqueue_add_tail(&agent_pool->blank_agents, QUEUE_NODE_OF(agent));
    srv_free_agent_res(agent, CT_TRUE);

    --agent_pool->curr_count;
    agent_pool->blank_count++;
    // can not process agent member after agent back to blank queue, otherwise will core.
    cm_spin_unlock(&agent_pool->lock_new);
}

/*
 * srv_get_stack_base
 *
 * This function is used to get the start stack address of thread.
 */
void srv_get_stack_base(thread_t *thread, agent_t **agent)
{
#ifdef WIN32
    thread->stack_base = (char *)agent;
#else
    pthread_attr_t attr;
    size_t stack_size;
    void *addr = NULL;

    if (pthread_getattr_np(pthread_self(), &attr) != 0 || pthread_attr_getstack(&attr, &addr, &stack_size) != 0) {
        thread->stack_base = (char *)agent;
        return;
    } else {
        if (IS_BIG_ENDIAN) {
            thread->stack_base = (char *)(addr) - (long)(stack_size);
        } else {
            thread->stack_base = (char *)(addr) + (long)(stack_size);
        }
    }

    (void)pthread_attr_destroy(&attr);
#endif
}

void srv_agent_entry(thread_t *thread)
{
    agent_t *agent = (agent_t *)thread->argument;

    /* set the start stack address of this thread */
    srv_get_stack_base(thread, &agent);

    cs_init_packet(&agent->recv_pack, CT_FALSE);
    cs_init_packet(&agent->send_pack, CT_FALSE);

    /* set agent's max packet size when startup. */
    agent->recv_pack.max_buf_size = g_instance->attr.max_allowed_packet;
    agent->send_pack.max_buf_size = g_instance->attr.max_allowed_packet;

    cm_set_thread_name("agent");
    CT_LOG_RUN_INF("agent [private [%u]] thread started, rid:%u, tid:%lu, close:%u", (uint32)agent->priv,
        agent->reactor->id, thread->id, thread->closed);
    while (!thread->closed) {
        srv_try_process_multi_sessions(agent);
    }
    CT_LOG_RUN_INF("agent [private [%u]] thread closed, rid:%u, tid:%lu, close:%u", (uint32)agent->priv,
        agent->reactor->id, thread->id, thread->closed);

    cm_release_thread(thread);
    srv_return_agent2blankqueue(agent);
}

status_t srv_start_agent(agent_t *agent, thread_entry_t entry)
{
    return cm_create_thread(entry, (uint32)g_instance->kernel.attr.thread_stack_size, agent, &agent->thread);
}

// when shutdown, close threads of all the extend agents
inline void close_extend_agent(agent_pool_t *agent_pool)
{
    if (agent_pool->ext_agents == NULL) {
        return;
    }

    agent_t *slot_agents = NULL;
    uint32 slot_used_id = CM_ALIGN_CEIL(agent_pool->extended_count, AGENT_EXTEND_STEP);

    CT_LOG_RUN_INF("[agent] [private agent pool[%u]] close extend agents' thread, extended slot count: %d",
        (uint32)agent_pool->priv, slot_used_id);

    for (uint32 i = 0; i < slot_used_id; ++i) {
        slot_agents = agent_pool->ext_agents[i].slot_agents;
        for (uint16 j = 0; j < agent_pool->ext_agents[i].slot_agent_count; j++) {
            slot_agents[j].thread.closed = CT_TRUE;
        }
    }
}

void srv_shutdown_agent_pool(agent_pool_t *agent_pool)
{
    close_extend_agent(agent_pool);

    if (agent_pool->agents != NULL) {
        for (uint32 i = 0; i < agent_pool->optimized_count; i++) {
            agent_pool->agents[i].thread.closed = CT_TRUE;
        }
    }

    while (agent_pool->curr_count > 0) {
        cm_sleep(1);
    }

    CT_LOG_RUN_INF("[agent] [private agent pool[%u]] all agents' thread have been closed", (uint32)agent_pool->priv);

    biqueue_init(&agent_pool->idle_agents);
    biqueue_init(&agent_pool->blank_agents);
    agent_pool->blank_count = 0;
    agent_pool->idle_count = 0;
    CM_FREE_PTR(agent_pool->agents);
    free_extend_agent(agent_pool);
}

static status_t srv_create_agent_iconv(agent_t *agent)
{
#ifndef WIN32
    agent->iconv_ready = CT_FALSE;

    /* convert multibyte to widechar */
    agent->env[0] = iconv_open("WCHAR_T", cm_get_charset_name(GET_CHARSET_ID));
    if (agent->env[0] == (iconv_t)-1) {
        CT_THROW_ERROR(ERR_CREATE_EVENT, cm_get_os_error());
        return CT_ERROR;
    }

    /* convert widechar to multibyte */
    agent->env[1] = iconv_open(cm_get_charset_name(GET_CHARSET_ID), "WCHAR_T");
    if (agent->env[1] == (iconv_t)-1) {
        CT_THROW_ERROR(ERR_CREATE_EVENT, cm_get_os_error());
        (void)iconv_close(agent->env[0]);
        return CT_ERROR;
    }

    agent->iconv_ready = CT_TRUE;
#endif
    return CT_SUCCESS;
}

static void srv_destory_agent_iconv(agent_t *agent)
{
#ifndef WIN32
    if (agent->iconv_ready) {
        (void)iconv_close(agent->env[0]);
        (void)iconv_close(agent->env[1]);
        agent->iconv_ready = CT_FALSE;
    }
#endif
}

status_t srv_create_agent_private_area(agent_t *agent)
{
    char *buf = NULL;
    instance_attr_t *attr = &g_instance->attr;
    knl_attr_t *knl_attr = &g_instance->kernel.attr;
    uint32 area_size, buf_size, update_buf_size, lex_size;

    if (cm_event_init(&agent->event)) {
        CT_THROW_ERROR(ERR_CREATE_EVENT, cm_get_os_error());
        return CT_ERROR;
    }

    area_size = attr->stack_size;
    if (CT_MAX_UINT32 - area_size < knl_attr->plog_buf_size) {
        CT_THROW_ERROR(ERR_NUM_OVERFLOW);
        return CT_ERROR;
    }
    area_size += g_instance->kernel.attr.plog_buf_size;

    // add space for update info:columns, offsets, lens, data
    update_buf_size = knl_get_update_info_size(knl_attr);
    if (CT_MAX_UINT32 - area_size < update_buf_size) {
        CT_THROW_ERROR(ERR_NUM_OVERFLOW);
        return CT_ERROR;
    }
    area_size += update_buf_size;

    lex_size = sizeof(lex_t);
    if (CT_MAX_UINT32 - area_size < lex_size) {
        CT_THROW_ERROR(ERR_NUM_OVERFLOW);
        return CT_ERROR;
    }
    area_size += lex_size;
    agent->area_buf = (char *)malloc(area_size);
    if (agent->area_buf == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)area_size, "creating agent area");
        return CT_ERROR;
    }
    errno_t ret = memset_s(agent->area_buf, area_size, 0, area_size);
    if (ret != EOK) {
        CM_FREE_PTR(agent->area_buf);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    buf = agent->area_buf;
    buf_size = attr->stack_size;
    cm_stack_init(&agent->stack, buf, attr->stack_size);

    buf = buf + buf_size;
    buf_size = knl_attr->plog_buf_size;
    agent->plog_buf = buf;

    buf = buf + buf_size;
    buf_size = update_buf_size;
    agent->update_buf = buf;

    buf = buf + buf_size;
    buf_size = lex_size;
    agent->lex = (lex_t *)buf;
    return CT_SUCCESS;
}

static inline status_t srv_create_agent(agent_t *agent)
{
    CT_RETURN_IFERR(srv_alloc_agent_res(agent));

    if (srv_start_agent(agent, srv_agent_entry) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[agent] (agent private[%u]), create agent thread failed, os error %d", (uint32)agent->priv,
            cm_get_os_error());
        srv_free_agent_res(agent, CT_TRUE);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

inline void srv_bind_sess_agent(session_t *session, agent_t *agent)
{
    session->agent = agent;
    session->stack = &agent->stack;
    session->lex = agent->lex;
    cm_stack_reset(&agent->stack);
    session->recv_pack = &agent->recv_pack;
    session->send_pack = &agent->send_pack;
    knl_set_logbuf_stack(&g_instance->kernel, session->knl_session.id, agent->plog_buf, &agent->stack);
    agent->session = session;
    KNL_SESSION_SET_CURR_THREADID(&session->knl_session, cm_get_current_thread_id());

    // set update info for kernel session: use the buf allocated from agent
    knl_bind_update_info(&session->knl_session, agent->update_buf);
}

static inline status_t allocate_slot(agent_pool_t *agent_pool)
{
    uint32 buf_size;
    errno_t rc_memzero;

    // allocate slots according to step, then allocate agents() to each slots
    uint32 slot_count = (agent_pool->max_count - agent_pool->optimized_count) / AGENT_EXTEND_STEP + 1;
    CT_LOG_DEBUG_INF("[agent] [private agent pool[%u]] allocate extend slots count: %d", (uint32)agent_pool->priv,
        slot_count);

    buf_size = sizeof(extend_agent_t) * slot_count;
    if (buf_size == 0 || buf_size / sizeof(extend_agent_t) != slot_count) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)buf_size, "extending agent pool, slot allocation failed");
        return CT_ERROR;
    }
    agent_pool->ext_agents = (extend_agent_t *)malloc(buf_size);
    if (agent_pool->ext_agents == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)buf_size, "extending agent pool, slot allocation failed");
        return CT_ERROR;
    }
    rc_memzero = memset_sp(agent_pool->ext_agents, (size_t)buf_size, 0, (size_t)buf_size);
    if (rc_memzero != EOK) {
        CM_FREE_PTR(agent_pool->ext_agents);
        CT_THROW_ERROR(ERR_RESET_MEMORY, "extending agent pool");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static inline status_t extend_agent_pool(agent_pool_t *agent_pool)
{
    uint32 buf_size, slot_id, expansion_count;
    agent_t *new_agents = NULL;
    errno_t rc_memzero;

    if (agent_pool->optimized_count + agent_pool->extended_count == agent_pool->max_count) {
        return CT_SUCCESS;
    }

    if (agent_pool->ext_agents == NULL) {
        CT_RETURN_IFERR(allocate_slot(agent_pool));
    }

    expansion_count =
        MIN(agent_pool->max_count - agent_pool->extended_count - agent_pool->optimized_count, AGENT_EXTEND_STEP);
    slot_id = agent_pool->extended_count / AGENT_EXTEND_STEP;

    CT_LOG_DEBUG_INF("[agent] [private agent pool[%u]] extend agents, expansion_count: %d, slot_id: %d",
        agent_pool->priv, expansion_count, slot_id);

    buf_size = sizeof(agent_t) * expansion_count;
    if (buf_size == 0 || buf_size / sizeof(agent_t) != expansion_count) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)buf_size, "expanding agent pool");
        return CT_ERROR;
    }

    new_agents = (agent_t *)malloc(buf_size);
    if (new_agents == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)buf_size, "expanding agent pool");
        return CT_ERROR;
    }

    rc_memzero = memset_sp(new_agents, (size_t)buf_size, 0, (size_t)buf_size);
    if (rc_memzero != EOK) {
        CM_FREE_PTR(new_agents);
        CT_THROW_ERROR(ERR_RESET_MEMORY, "expanding agent pool");
        return CT_ERROR;
    }

    for (uint32 loop = 0; loop < expansion_count; ++loop) {
        new_agents[loop].reactor = agent_pool->reactor;
        new_agents[loop].is_extend = CT_TRUE;
        new_agents[loop].priv = agent_pool->priv;
        biqueue_add_tail(&agent_pool->blank_agents, QUEUE_NODE_OF(&new_agents[loop]));
        agent_pool->blank_count++;
    }

    agent_pool->ext_agents[slot_id].slot_agents = new_agents;
    agent_pool->ext_agents[slot_id].slot_agent_count = expansion_count;
    agent_pool->extended_count += expansion_count;
    agent_pool->shrink_hit_count = 0;

    return CT_SUCCESS;
}

inline void shrink_pool_core(agent_pool_t *agent_pool)
{
    agent_t *agent = NULL;
    biqueue_node_t *next = NULL;

    if (agent_pool->idle_count == 0) {
        return;
    }

    cm_spin_lock(&agent_pool->lock_idle, NULL);
    biqueue_node_t *curr = biqueue_first(&agent_pool->idle_agents);
    biqueue_node_t *end = biqueue_end(&agent_pool->idle_agents);

    while (curr != end) {
        agent = OBJECT_OF(agent_t, curr);
        next = curr->next;
        if (agent->is_extend == CT_TRUE) {
            // waiting to return to blank list
            cm_spin_lock(&agent_pool->lock_new, NULL); // protect agent-thread return 2 blanklist
            agent->thread.closed = CT_TRUE;
            biqueue_del_node(QUEUE_NODE_OF(agent));
            agent_pool->idle_count--;
            cm_spin_unlock(&agent_pool->lock_new);
        }

        curr = next;
    }

    agent_pool->shrink_hit_count = 0;
    cm_spin_unlock(&agent_pool->lock_idle);
}

void srv_shrink_agent_pool(agent_pool_t *agent_pool)
{
    if (agent_pool->extended_count == 0) {
        return;
    }

    agent_pool->shrink_hit_count++;

    if (agent_pool->shrink_hit_count > (long)AGENT_SHRINK_THRESHOLD(g_instance->reactor_pool.agents_shrink_threshold)) {
        CT_LOG_DEBUG_INF("[agent_pool] [private agent pool[%u]] shrink extend agents ... ", (uint32)agent_pool->priv);
        shrink_pool_core(agent_pool);
        CT_LOG_DEBUG_INF("[agent_pool] [private agent pool[%u]] end of shrink extend agents ... ",
            (uint32)agent_pool->priv);
    }
}

static inline status_t srv_try_create_agent(agent_pool_t *agent_pool, agent_t **agent)
{
    biqueue_node_t *node = NULL;
    bool32 need_create;

    if (agent_pool->curr_count == agent_pool->max_count) {
        *agent = NULL;
        return CT_SUCCESS;
    }

    if (agent_pool->curr_count == agent_pool->optimized_count + agent_pool->extended_count) {
        cm_spin_lock(&agent_pool->lock_new, NULL);
        if (CT_SUCCESS != extend_agent_pool(agent_pool)) {
            cm_spin_unlock(&agent_pool->lock_new);
            CT_LOG_DEBUG_ERR(
                "[agent] try to expand agent pool [private agent pool[%u]] failed, current expanded count: %u.",
                (uint32)agent_pool->priv, agent_pool->extended_count);
            return CT_ERROR;
        }
        cm_spin_unlock(&agent_pool->lock_new);
    }

    // there is no idle agent, and the following two condition are true, then create a new one
    // 1.agent number not reached the optimized value
    // 2.session count greater than current agent count
    //    although this is not accurate, we can make sure that
    //    as long as session count greater than agent count and agent count not reached optimized value
    //    at last new agents will be created
    cm_spin_lock(&agent_pool->lock_new, NULL);
    if (agent_pool->priv && (IS_COORDINATOR || IS_DATANODE)) {
        uint32 curr_count = agent_pool->curr_count + agent_pool->reactor->agent_pool.curr_count;
        need_create = agent_pool->curr_count < agent_pool->optimized_count + agent_pool->extended_count &&
            (uint32)agent_pool->reactor->session_count > curr_count;
    } else {
        need_create = agent_pool->curr_count < agent_pool->optimized_count + agent_pool->extended_count &&
            (uint32)agent_pool->reactor->session_count > agent_pool->curr_count;
    }
    if (!need_create) {
        cm_spin_unlock(&agent_pool->lock_new);
        *agent = NULL;
        return CT_SUCCESS;
    }
    node = biqueue_del_head(&agent_pool->blank_agents);
    ++agent_pool->curr_count;
    agent_pool->blank_count--;
    cm_spin_unlock(&agent_pool->lock_new);

    // maximum count sure to be larger than optimized count, so node must be not null.
    // create a new agent, allocate private memory for it, and start it
    *agent = OBJECT_OF(agent_t, node);
    if (CT_SUCCESS != srv_create_agent(*agent)) {
        srv_return_agent2blankqueue(*agent);
        *agent = NULL;
        CT_LOG_RUN_ERR("[agent] create agent failed, os error %d.", cm_get_os_error());
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t srv_try_attach_agent(session_t *session, agent_t **agent)
{
    status_t status;
    biqueue_node_t *node = NULL;
    agent_pool_t *agent_pool = NULL;
    CM_POINTER(session);

    agent_pool = srv_get_agent_pool(session);
    // if not empty , get agent from idle pool.
    if (!biqueue_empty(&agent_pool->idle_agents)) {
        // try to find a idle agent, if failed, try to create a new one
        cm_spin_lock(&agent_pool->lock_idle, NULL);
        node = biqueue_del_head(&agent_pool->idle_agents);
        if (node != NULL) {
            agent_pool->idle_count--;
        }
        cm_spin_unlock(&agent_pool->lock_idle);

        if (node != NULL) {
            *agent = OBJECT_OF(agent_t, node);
            srv_bind_sess_agent(session, *agent);
            return CT_SUCCESS;
        }
    }

    status = srv_try_create_agent(agent_pool, agent);
    CT_RETURN_IFERR(status);

    if (*agent != NULL) {
        srv_bind_sess_agent(session, *agent);
    }

    return CT_SUCCESS;
}

status_t srv_attach_agent(session_t *session, agent_t **agent, bool32 nowait)
{
    status_t status = CT_ERROR;
    agent_pool_t *agent_pool = NULL;
    uint32 count = 0;
    bool32 is_log = CT_FALSE;
    CM_ASSERT(session->agent == NULL);
    agent_pool = srv_get_agent_pool(session);
    *agent = NULL;
    for (;;) {
        /* hit scenario: enter deadloop, after create agent failed */
        status = srv_try_attach_agent(session, agent);
        CT_RETURN_IFERR(status);

        if (*agent != NULL) {
            if (agent_pool->shrink_hit_count > 0) {
                agent_pool->shrink_hit_count--;
            }

            knl_end_session_wait(&session->knl_session, ATTACH_AGENT);
            if (is_log == CT_TRUE) {
                CT_LOG_ALARM_RECOVER(WARN_AGENT, "'session-id':'%u'}", session->knl_session.id);
            }

            return CT_SUCCESS;
        }

        if (nowait) {
            return CT_ERROR;
        }

        if ((++count % 100) == 0 && !is_log) {
            CT_LOG_DEBUG_WAR("[agent] system busy, wait for idle agent, session id %u [private [%u]], "
                "[private agent pool[%u]] active agent count %u, session count %u",
                session->knl_session.id, (uint32)session->priv, (uint32)agent_pool->priv, agent_pool->curr_count,
                session->reactor->session_count);
            CT_LOG_ALARM(WARN_AGENT, "'session-id':'%u'}", session->knl_session.id);
            is_log = CT_TRUE;
            count = 0;
        }

        agent_pool->shrink_hit_count = 0;
        knl_begin_session_wait(&session->knl_session, ATTACH_AGENT, CT_TRUE);
        cm_event_wait(&agent_pool->idle_evnt);

        REACTOR_STATUS_INVALID_FOR_RETURN(session->reactor);
    }
}

void srv_unbind_sess_agent(session_t *session, agent_t *agent)
{
    agent->session = NULL;
    session->stack = NULL;
    session->agent = NULL;
    session->lex = NULL;
    KNL_SESSION_CLEAR_THREADID(&session->knl_session);

    /* status might still be ACTIVE while being detached from agent, so need to reset */
    session->knl_session.status = SESSION_INACTIVE;
}

status_t srv_alloc_agent_res(agent_t *agent)
{
    if (srv_create_agent_iconv(agent) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (srv_create_agent_private_area(agent) != CT_SUCCESS) {
        srv_destory_agent_iconv(agent);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void srv_free_agent_res(agent_t *agent, bool32 free_pack)
{
    if (free_pack) {
        cs_free_packet_buffer(&agent->send_pack);
        cs_free_packet_buffer(&agent->recv_pack);
    }

    srv_destory_agent_iconv(agent);
    CM_FREE_PTR(agent->area_buf);
    agent->plog_buf = NULL;
    agent->update_buf = NULL;
    agent->lex = NULL;
}

void srv_free_dedicated_agent_res(agent_t *agent)
{
    cs_free_packet_buffer(&agent->send_pack);
    cs_free_packet_buffer(&agent->recv_pack);

    srv_destory_agent_iconv(agent);
}

agent_t *srv_create_dedicated_agent(void)
{
    agent_t *agent = (agent_t *)malloc(sizeof(agent_t));
    if (agent == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(agent_t), "dedicated agent");
        return NULL;
    }

    errno_t ret = memset_s(agent, sizeof(agent_t), 0, sizeof(agent_t));
    if (ret != EOK) {
        CM_FREE_PTR(agent);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return NULL;
    }

    if (srv_create_agent_iconv(agent) != CT_SUCCESS) {
        CM_FREE_PTR(agent);
        return NULL;
    }
    return agent;
}


#ifdef __cplusplus
}
#endif
