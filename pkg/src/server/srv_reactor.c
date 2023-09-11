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
 * srv_reactor.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_reactor.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_reactor.h"
#include "srv_instance.h"

#define POLL_TIME_OUT 5
#define SYS_AGENT_REVERSED_NUM 5
#define SLEEP_TIME 5
#define WAIT_TIME 50

status_t reactor_work(reactor_t *reactor)
{
    if (cm_create_thread(reactor_entry, (uint32)g_instance->kernel.attr.reactor_thread_stack_size, reactor,
        &reactor->thread) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[reactor] failed to create reactor thread, errno %d", cm_get_os_error());
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t reactor_deal_kill_events(reactor_t *reactor)
{
    status_t status;
    uint32 last_w_pos, last_r_pos, r_pos;
    session_t *sess = NULL;
    agent_t *agent = NULL;

    kill_event_queue_t *kill_events = &reactor->kill_events;
    last_w_pos = kill_events->w_pos;
    last_r_pos = kill_events->r_pos;
    r_pos = kill_events->r_pos;

    if (SECUREC_LIKELY(last_w_pos == last_r_pos)) {
        return GS_SUCCESS;
    }

    // not necessary and don't add kill_events->w_lock here !
    while (r_pos != last_w_pos) {
        sess = kill_events->sesses[r_pos];
        // some request of this session still processing by an agent
        if (sess->agent != NULL) {
            r_pos = (r_pos + 1) % REACTOR_MAX_KILL_EVENTS;
            GS_LOG_DEBUG_INF("[reactor] deal kill events session[%u][private [%u]] agent is not null, "
                "last_w_pos %u, last_r_pos %u, r_pos %u",
                sess->knl_session.id, (uint32)sess->priv, last_w_pos, last_r_pos, r_pos);
            continue;
        }

        status = server_attach_agent(sess, &agent, GS_FALSE);
        if (status != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[reactor] deal kill events failed, sid [%u][private [%u]], os error %d, "
                "last_w_pos %u, last_r_pos %u, r_pos %u",
                sess->knl_session.id, (uint32)sess->priv, cm_get_os_error(), last_w_pos, last_r_pos, r_pos);
            kill_events->r_pos = last_r_pos;
            return GS_ERROR;
        }

        if (agent != NULL) {
            /*
                l_r_p                   l_w_p
                ^                         ^
                |          r_p-->         |
                ----------------------------
                | s1 | s2 | s3 | s4 | s5 |  |
                ----------------------------
                if s1 is still active, traverse to find first inactive session s3,
                and bind a agent to process free session

                       l_r_p            l_w_p
                       ^                  ^
                       |        r_p       |
                ----------------------------
                NULL | s2 | s1 | s4 | s5 |  |
                ----------------------------

                             l_r_p        l_w_p
                             ^              ^
                             |         r_p  |
                -----------------------------
                NULL  NULL   s1 | s2 | s5 |  |
                -----------------------------
                                l_r_p      l_w_p
                                 ^           ^
                                 |        r_p|
                -----------------------------
                NULL  NUL  NULL | s2 | s1 |  |
                -----------------------------
            */
            kill_events->sesses[r_pos] = kill_events->sesses[last_r_pos];
            kill_events->sesses[last_r_pos] = NULL;

            last_r_pos = (last_r_pos + 1) % REACTOR_MAX_KILL_EVENTS;
            r_pos = (r_pos + 1) % REACTOR_MAX_KILL_EVENTS;

            GS_LOG_DEBUG_INF("[reactor] attached agent to process session release, "
                "sid [%u][private [%u]], last_w_pos %u, last_r_pos %u, r_pos %u",
                sess->knl_session.id, (uint32)sess->priv, last_w_pos, last_r_pos, r_pos);
            reactor_unregister_session(sess);
            cm_event_notify(&agent->event);
        }
    }
    kill_events->r_pos = last_r_pos;

    return GS_SUCCESS;
}

static status_t server_attach_private_agent(session_t *sess, agent_t **agent)
{
    status_t status = GS_ERROR;
    return status;
}

static void reactor_wait_for_events(reactor_t *reactor)
{
    int32 code;
    const char *message = NULL;
    session_t *sess = NULL;
    agent_t *agent = NULL;
    int loop, nfds;
    struct epoll_event events[GS_EV_WAIT_NUM];
    struct epoll_event *ev = NULL;

    // first deal with session killed
    status_t status = reactor_deal_kill_events(reactor);
    if (status != GS_SUCCESS) {
        cm_get_error(&code, &message, NULL);
        if (code == ERR_ALLOC_MEMORY || code == ERR_CREATE_THREAD) {
            cm_sleep(WAIT_TIME);
        }
        return;
    }

    if (reactor->status != REACTOR_STATUS_RUNNING) {
        return;
    }

    nfds = epoll_wait(reactor->epollfd, events, GS_EV_WAIT_NUM, GS_EV_WAIT_TIMEOUT);
    if (nfds == -1) {
        if (errno != EINTR) {
            GS_LOG_RUN_ERR("Failed to wait for connection request, OS error:%d", cm_get_os_error());
        }
        return;
    }
    if (nfds == 0) {
        return;
    }

    for (loop = 0; loop < nfds; ++loop) {
        ev = &events[loop];
        sess = (session_t *)ev->data.ptr;

        if (reactor->status != REACTOR_STATUS_RUNNING) {
            if (GS_SUCCESS != reactor_set_oneshot(sess)) {
                GS_LOG_RUN_ERR("[reactor] set oneshot flag of socket failed, session %d[private [%u]], "
                    "reactor %lu, os error %d, event %u",
                    sess->knl_session.id, (uint32)sess->priv, reactor->thread.id, cm_get_sock_error(), ev->events);
            }

            continue;
        }

        if (sess->knl_session.killed) {
            continue;
        }

        status = server_attach_agent(sess, &agent, GS_FALSE);
        if (status != GS_SUCCESS) {
            // decrement the active session if failed to attach agent
            {
                status = server_attach_private_agent(sess, &agent);
            }

            if (status != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[reactor] attach agent failed, sid [%u][private [%u]], "
                    "reactor %lu, os error %d",
                    sess->knl_session.id, (uint32)sess->priv, reactor->thread.id, cm_get_sock_error());
                cm_get_error(&code, &message, NULL);
                if (code == ERR_ALLOC_MEMORY || code == ERR_CREATE_THREAD) {
                    cm_sleep(WAIT_TIME);
                }
                return;
            }
        }

        if (agent != NULL) {
            GS_LOG_DEBUG_INF("[reactor] receive message from session %d[private [%u]], "
                "attached agent %lu[private [%u]], event %u",
                sess->knl_session.id, (uint32)sess->priv, agent->thread.id, (uint32)agent->priv, ev->events);
            cm_event_notify(&agent->event);
        }
    }
}

static void reactor_handle_events(reactor_t *reactor)
{
    reactor_wait_for_events(reactor);

    if (reactor_in_dedicated_mode(reactor)) {
        cm_sleep(SLEEP_TIME);
        server_shrink_agent_pool(&reactor->agent_pool);

    }
}

void reactor_entry(thread_t *thread)
{
    reactor_t *reactor = (reactor_t *)thread->argument;

    cm_set_thread_name("reactor");
    GS_LOG_RUN_INF("reactor thread started");
    while (!thread->closed) {
        reactor_handle_events(reactor);
        if (reactor->status == REACTOR_STATUS_PAUSING) {
            reactor->status = REACTOR_STATUS_PAUSED;
        }
    }
    GS_LOG_RUN_INF("reactor thread closed");
    (void)epoll_close(reactor->epollfd);
}

#define AVG_ROUND_CEIL(a, b) (((a) + (b)-1) / (b))

static inline void reactor_init_kill_events(reactor_t *reactor)
{
    kill_event_queue_t *queue = &reactor->kill_events;
    queue->r_pos = 0;
    queue->w_pos = 0;
    queue->w_lock = 0;
}

static inline status_t reactor_start(reactor_t *reactor, uint32 optimized_count, uint32 max_count)
{
    reactor->status = REACTOR_STATUS_RUNNING;
    reactor->epollfd = epoll_create1(0);
    reactor_init_kill_events(reactor);

    reactor->agent_pool.reactor = reactor;
    reactor->agent_pool.max_count = max_count;
    reactor->agent_pool.optimized_count = optimized_count;
    GS_RETURN_IFERR(server_create_agent_pool(&reactor->agent_pool, GS_FALSE));

    return reactor_work(reactor);
}

static status_t reactor_start_pool(void)
{
    reactor_t *reactor = NULL;
    uint32 size;
    uint32 loop;
    uint32 max_agents, remainder1, avg_magents;
    uint32 optimized_agents, remainder2, avg_oagents;

    reactor_pool_t *pool = &g_instance->reactor_pool;
    size = pool->reactor_count;
    max_agents = g_instance->attr.max_worker_count / pool->reactor_count;
    remainder1 = g_instance->attr.max_worker_count % pool->reactor_count;

    optimized_agents = g_instance->attr.optimized_worker_count / pool->reactor_count;
    remainder2 = g_instance->attr.optimized_worker_count % pool->reactor_count;

    for (loop = 0; loop < size; loop++) {
        reactor = &pool->reactors[loop];
        reactor->id = loop;
        avg_magents = max_agents + (loop < remainder1 ? 1 : 0);
        avg_oagents = optimized_agents + (loop < remainder2 ? 1 : 0);
        GS_RETURN_IFERR(reactor_start(reactor, avg_oagents, avg_magents));
    }

    return GS_SUCCESS;
}

status_t reactor_set_oneshot(session_t *session)
{
    struct epoll_event ev;
    int fd = (int)session->pipe->link.tcp.sock;

    ev.events = EPOLLIN | EPOLLONESHOT;
    ev.data.ptr = session;

    if (epoll_ctl(session->reactor->epollfd, EPOLL_CTL_MOD, fd, &ev) != 0) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

void reactor_add_kill_event(session_t *sess)
{
    uint32 next_w_pos;

    // when a session is registered to a reactor and is not added to kill-event queue
    // it will not be destroyed, and its reactor pointer can not be null
    reactor_t *reactor = sess->reactor;
    kill_event_queue_t *kill_events = &reactor->kill_events;
    for (;;) {
        cm_spin_lock(&kill_events->w_lock, NULL);
        next_w_pos = (kill_events->w_pos + 1) % REACTOR_MAX_KILL_EVENTS;
        if (next_w_pos != kill_events->r_pos) {
            break;
        }
        cm_spin_unlock(&kill_events->w_lock);
        cm_sleep(SLEEP_TIME);
    }
    kill_events->sesses[kill_events->w_pos] = sess;
    CM_MFENCE;
    kill_events->w_pos = next_w_pos;
    cm_spin_unlock(&kill_events->w_lock);
    GS_LOG_DEBUG_INF("[reactor] add session %u[private [%u]] "
        "to kill event queue [w_pos %u, r_pos %u] success.",
        sess->knl_session.id, (uint32)sess->priv, reactor->kill_events.w_pos, reactor->kill_events.r_pos);
}

status_t reactor_add_epoll_session(session_t *session)
{
    reactor_t *reactor = session->reactor;
    struct epoll_event ev;
    int fd = (int)session->pipe->link.tcp.sock;

    CM_ASSERT(session->agent == NULL);
    (void)cm_atomic32_inc(&reactor->session_count);
    ev.events = EPOLLIN | EPOLLONESHOT;
    ev.data.ptr = session;
    if (epoll_ctl(reactor->epollfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        GS_LOG_RUN_ERR("[reactor] register session to reactor failed, session %u[private [%u]], reactor %lu, "
            "active agent num %u, os error %d",
            session->knl_session.id, (uint32)session->priv, reactor->thread.id, reactor->agent_pool.curr_count,
            cm_get_sock_error());
        (void)cm_atomic32_dec(&reactor->session_count);
        return GS_ERROR;
    }

    session->is_reg = GS_TRUE;
    GS_LOG_DEBUG_INF(
        "[reactor] register session %u[private [%u]] to reactor %lu sucessfully, current session count %ld",
        session->knl_session.id, (uint32)session->priv, reactor->thread.id, (long)reactor->session_count);

    return GS_SUCCESS;
}

status_t reactor_register_session(session_t *session)
{
    reactor_pool_t *pool = &g_instance->reactor_pool;
    reactor_t *reactor = NULL;
    uint32 count = 0;

    // dispatch by load
    while (1) {
        ++count;
        reactor = &pool->reactors[pool->roudroubin++ % pool->reactor_count];
        /* agent pool no idle thread, continue to check */
        if (reactor_in_dedicated_mode(reactor)) {
            break;
        }

        if (count == pool->reactor_count) {
            reactor = &pool->reactors[pool->roudroubin2++ % pool->reactor_count];
            break;
        }
    }

    session->reactor = reactor;
    CM_MFENCE;

    return reactor_add_epoll_session(session);
}

void reactor_unregister_session(session_t *session)
{
    int fd = (int)session->pipe->link.tcp.sock;
    reactor_t *reactor = session->reactor;

    if (epoll_ctl(reactor->epollfd, EPOLL_CTL_DEL, fd, NULL) != 0) {
        GS_LOG_RUN_ERR("[reactor] unregister session from reactor failed, session %d[private [%u]], "
            "reactor %lu, os error %d",
            session->knl_session.id, (uint32)session->priv, reactor->thread.id, cm_get_sock_error());
        return;
    }

    (void)cm_atomic32_dec(&reactor->session_count);
    session->is_reg = GS_FALSE;
    GS_LOG_DEBUG_INF("[reactor] unregister session %d[private [%u]] from reactor %lu, "
        "current session count %ld",
        session->knl_session.id, (uint32)session->priv, reactor->thread.id, (long)reactor->session_count);
}

status_t reactor_create_pool(void)
{
    size_t size;
    reactor_pool_t *pool = &g_instance->reactor_pool;
    errno_t rc_memzero;

    pool->roudroubin = 0;
    pool->roudroubin2 = 0;
    size = sizeof(reactor_t) * pool->reactor_count;

    if (size == 0 || size / sizeof(reactor_t) != pool->reactor_count) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)0, "creating reactor pool");
        return GS_ERROR;
    }
    pool->reactors = (reactor_t *)malloc(size);
    if (pool->reactors == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, "creating reactor pool");
        return GS_ERROR;
    }

    rc_memzero = memset_s(pool->reactors, size, 0, size);
    if (rc_memzero != EOK) {
        CM_FREE_PTR(pool->reactors);
        GS_THROW_ERROR(ERR_SYSTEM_CALL, (rc_memzero));
        return GS_ERROR;
    }
    if (reactor_start_pool() != GS_SUCCESS) {
        reactor_destroy_pool();
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void reactor_destroy_pool(void)
{
    reactor_t *reactor = NULL;
    size_t loop;
    size_t size;

    reactor_pool_t *pool = &g_instance->reactor_pool;
    size = pool->reactor_count;

    for (loop = 0; loop < size; loop++) {
        reactor = &pool->reactors[loop];
        cm_close_thread(&reactor->thread);

        server_destroy_agent_pool(&reactor->agent_pool);
        reactor->status = REACTOR_STATUS_STOPPED;
    }
    pool->reactor_count = 0;
    CM_FREE_PTR(pool->reactors);
}

void reactor_pause_pool(void)
{
    reactor_pool_t *pool = &g_instance->reactor_pool;
    reactor_t *reactor = NULL;
    for (uint32 loop = 0; loop < pool->reactor_count; loop++) {
        reactor = &pool->reactors[loop];
        reactor->status = REACTOR_STATUS_PAUSING;
        while (reactor->status != REACTOR_STATUS_PAUSED && !reactor->thread.closed) {
            cm_sleep(5);
        }
    }
}

void reactor_resume_pool(void)
{
    reactor_pool_t *pool = &g_instance->reactor_pool;
    reactor_t *reactor = NULL;

    for (uint32 loop = 0; loop < pool->reactor_count; loop++) {
        reactor = &pool->reactors[loop];
        reactor->status = REACTOR_STATUS_RUNNING;
    }
}
