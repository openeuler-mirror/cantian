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
 * srv_session.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_session.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "cm_kmc.h"
#include "cm_log.h"
#include "cm_ip.h"
#include "srv_instance.h"
#include "srv_session.h"
#include "srv_agent.h"
#include "dml_executor.h"
#include "ctsql_audit.h"
#include "srv_stat.h"
#include "dtc_dmon.h"
#include "cm_io_record.h"

static sql_stat_t g_stat_info_4_init = { 0 };
static knl_stat_t g_knl_stat_info_4_init = { 0 };

void *srv_stack_mem_alloc(size_t size)
{
    char *buf = NULL;
    session_t *sess = (session_t *)knl_get_curr_sess();
    if (CT_SUCCESS != sql_push(sess->current_stmt, (uint32)size, (void **)&buf)) {
        CT_LOG_DEBUG_ERR("Failed to allocate %u bytes from stack, session id = %d", (uint32)size, sess->knl_session.id);
        return NULL;
    }
    return buf;
}

void srv_stack_mem_free(void *ptr)
{
    // nothing to do, memory allocated from stack
}

static status_t srv_attach_reactor(session_t *session)
{
    CM_POINTER(session);
    return reactor_register_session(session);
}

static inline void srv_set_session_pipe(session_t *session, cs_pipe_t *pipe)
{
    if (pipe != NULL) {
        session->pipe_entity = *pipe;
        session->pipe = &session->pipe_entity;
    } else {
        session->pipe = NULL;
    }
}

void srv_reset_session(session_t *session, cs_pipe_t *pipe)
{
    srv_set_session_pipe(session, pipe);

    session->logon_time = g_timer()->now;
    session->interval_time = cm_monotonic_now();
    session->is_log_out = CT_FALSE;
    session->knl_session.status = SESSION_INACTIVE;
    session->knl_session.serial_id += 1;
    session->knl_session.canceled = CT_FALSE;
    session->knl_session.force_kill = CT_FALSE;
    session->knl_session.killed = CT_FALSE;
    session->knl_session.trig_ui = NULL;
    session->knl_session.lock_wait_timeout = g_instance->kernel.attr.lock_wait_timeout;
    session->knl_session.thread_shared = CT_FALSE;
    session->interactive_info.is_on = CT_FALSE;
    session->interactive_info.is_timeout = CT_FALSE;
    session->interactive_info.response_time = 0;
    session->knl_session.interactive_altpwd = CT_FALSE;
    cm_init_session_nlsparams(&(session->nls_params));
    session->triggers_disable = CT_FALSE;
    session->switched_schema = CT_FALSE;
    session->nologging_enable = CT_FALSE;
    session->optinfo_enable = CT_FALSE;
    session->pl_cursors = NULL;
    session->rsrc_group = NULL;
    session->rsrc_attr_id = CT_INVALID_INT32;
    session->plan_display_format = 0;
    session->client_kind = CLIENT_KIND_UNKNOWN;
    session->outer_join_optimization = PARAM_INIT;
    session->cbo_param.cbo_index_caching = CT_INVALID_ID32;
    session->cbo_param.cbo_index_cost_adj = CT_INVALID_ID32;
    session->withas_subquery = WITHAS_UNSET;
    session->cursor_sharing = PARAM_INIT;
    session->knl_session.dtc_session_type = DTC_TYPE_NONE;
    session->knl_session.user_locked_ddl = CT_FALSE;
    session->knl_session.user_locked_lst = NULL;
    MEMS_RETVOID_IFERR(memset_s(session->challenge, 2 * CT_MAX_CHALLENGE_LEN, 0, 2 * CT_MAX_CHALLENGE_LEN));

    CT_INIT_SPIN_LOCK(session->dbg_ctl_lock);

    if (session->priv_upgrade) {
        session->priv = CT_FALSE;
        session->priv_upgrade = CT_FALSE;
    }

    CT_LOG_DEBUG_INF("reset session %u [private [%u]]", session->knl_session.id, session->priv);

    CM_ASSERT(session->knl_session.page_stack.depth == 0);
}

static status_t srv_try_reuse_session(session_t **session, cs_pipe_t *pipe, bool32 *reused)
{
    session_pool_t *pool = &g_instance->session_pool;
    biqueue_node_t *node = NULL;
    uint16 stat_id = CT_INVALID_ID16;

    *session = NULL;
    *reused = CT_FALSE;

    if (biqueue_empty(&pool->idle_sessions)) {
        return CT_SUCCESS;
    }

    if (srv_alloc_stat(&stat_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cm_spin_lock(&pool->lock, NULL);
    node = biqueue_del_head(&pool->idle_sessions);
    if (node == NULL) {
        cm_spin_unlock(&pool->lock);
        srv_release_stat(&stat_id);
        return CT_SUCCESS;
    }
    *session = OBJECT_OF(session_t, node);
    (*session)->is_free = CT_FALSE;
    (*session)->knl_session.stat_id = stat_id;
    (*session)->knl_session.stat = g_instance->stat_pool.stats[stat_id];
    cm_spin_unlock(&pool->lock);

    srv_reset_session(*session, pipe);
    *reused = CT_TRUE;
    return CT_SUCCESS;
}

static status_t srv_try_reuse_priv_session(session_t **session, cs_pipe_t *pipe, bool32 *reused)
{
    session_pool_t *pool = &g_instance->session_pool;
    biqueue_node_t *node = NULL;
    uint16 stat_id = CT_INVALID_ID16;

    *session = NULL;
    *reused = CT_FALSE;

    if (IS_COORDINATOR || IS_DATANODE) {
        if (pipe && (pipe->type == CS_TYPE_TCP || pipe->type == CS_TYPE_SSL)) {
            if (biqueue_empty(&pool->priv_idle_sessions)) {
                return CT_SUCCESS;
            }

            if (srv_alloc_stat(&stat_id) != CT_SUCCESS) {
                return CT_ERROR;
            }

            cm_spin_lock(&pool->lock, NULL);
            node = biqueue_del_head(&pool->priv_idle_sessions);
            if (node == NULL) {
                cm_spin_unlock(&pool->lock);
                srv_release_stat(&stat_id);
                return CT_SUCCESS;
            }
            *session = OBJECT_OF(session_t, node);
            (*session)->is_free = CT_FALSE;
            (*session)->knl_session.stat_id = stat_id;
            (*session)->knl_session.stat = g_instance->stat_pool.stats[stat_id];
            cm_spin_unlock(&pool->lock);

            srv_reset_session(*session, pipe);
            *reused = CT_TRUE;
            return CT_SUCCESS;
        }
    }
    return CT_SUCCESS;
}

void srv_return_session(session_t *session)
{
    session_pool_t *sess_pool = &g_instance->session_pool;

    session->is_free = CT_TRUE;
    session->stack = NULL;
    session->knl_session.stack = NULL;
    session->reactor = NULL;
    session->interactive_info.is_timeout = CT_FALSE;
    if (session->priv_upgrade) {
        CT_LOG_DEBUG_INF("try return private session [%d] by upgrade", session->knl_session.id);
        session->priv = CT_FALSE;
        session->priv_upgrade = CT_FALSE;
    }

    CT_LOG_DEBUG_INF("try return session %u [private [%u]]", session->knl_session.id, session->priv);
    cm_spin_lock(&sess_pool->lock, NULL);
    if (session->priv && (IS_COORDINATOR || IS_DATANODE)) {
        biqueue_add_tail(&sess_pool->priv_idle_sessions, QUEUE_NODE_OF(session));
    } else {
        biqueue_add_tail(&sess_pool->idle_sessions, QUEUE_NODE_OF(session));
    }
    cm_spin_unlock(&sess_pool->lock);
    (void)cm_atomic_dec(&g_instance->session_pool.service_count);
}

status_t srv_init_sql_cur_pools(void)
{
    uint32 sql_cur_size = CM_ALIGN8(OBJECT_HEAD_SIZE + sizeof(sql_cursor_t));
    uint32 init_sql_cursors =
        g_instance->attr.reserved_sql_cursors + g_instance->attr.sql_cursors_each_sess * CT_SYS_SESSIONS;
    uint32 mem_size = init_sql_cursors * sql_cur_size;
    errno_t rc_memzero;
    if (mem_size == 0 || init_sql_cursors != mem_size / sql_cur_size) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)mem_size, "creating sql cursors");
        return CT_ERROR;
    }
    char *buf = (char *)malloc(mem_size);
    if (buf == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)mem_size, "creating sql cursors");
        return CT_ERROR;
    }
    rc_memzero = memset_s(buf, mem_size, 0, mem_size);
    if (rc_memzero != EOK) {
        CM_FREE_PTR(buf);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, rc_memzero);
        return CT_ERROR;
    }
    opool_attach(buf, mem_size, sql_cur_size, &g_instance->sql_cur_pool.pool);
    g_instance->sql_cur_pool.cnt += init_sql_cursors;
    return CT_SUCCESS;
}

status_t srv_init_session_sql_curs(session_t *session)
{
    uint32 i;
    object_t *object = NULL;
    for (i = 0; i < g_instance->attr.sql_cursors_each_sess; i++) {
        CT_RETURN_IFERR(sql_alloc_global_sql_cursor(&object));
        olist_concat_single(&session->sql_cur_pool.free_objects, object);
    }
    return CT_SUCCESS;
}

static status_t srv_alloc_session_memory(session_t **session_out)
{
    uint32 mem_size, buf_size, len;
    uint32 knl_cur_size = OBJECT_HEAD_SIZE + g_instance->kernel.attr.cursor_size;
    uint16 rmid, stat_id;
    errno_t rc_memzero;
    session_t *session = NULL;

    mem_size = sizeof(session_t);

    len = g_instance->attr.init_cursors * (knl_cur_size);
    // max init_cursors (45568+1272+16*2)*256 = 11999232
    if (CT_MAX_UINT32 - mem_size < len) {
        CT_THROW_ERROR(ERR_NUM_OVERFLOW);
        return CT_ERROR;
    }
    mem_size += len;

    len = sizeof(mtrl_context_t) +
        sizeof(mtrl_segment_t) * (g_instance->kernel.attr.max_temp_tables * 2 - CT_MAX_MATERIALS);
    if (CT_MAX_UINT32 - mem_size < len) {
        CT_THROW_ERROR(ERR_NUM_OVERFLOW);
        return CT_ERROR;
    }

    mem_size += len;
    len = sizeof(knl_temp_cache_t) * g_instance->kernel.attr.max_temp_tables;
    if (CT_MAX_UINT32 - mem_size < len) {
        CT_THROW_ERROR(ERR_NUM_OVERFLOW);
        return CT_ERROR;
    }
    mem_size += len;
    len = sizeof(void *) * g_instance->kernel.attr.max_temp_tables;
    if (CT_MAX_UINT32 - mem_size < len) {
        CT_THROW_ERROR(ERR_NUM_OVERFLOW);
        return CT_ERROR;
    }
    mem_size += len;

    len = sizeof(void *) * g_instance->kernel.attr.max_link_tables;
    if (CT_MAX_UINT32 - mem_size < len) {
        CT_THROW_ERROR(ERR_NUM_OVERFLOW);
        return CT_ERROR;
    }
    mem_size += len;

    char *buf = (char *)malloc(mem_size);
    if (buf == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)mem_size, "creating session");
        return CT_ERROR;
    }

    rc_memzero = memset_s(buf, mem_size, 0, mem_size);
    if (rc_memzero != EOK) {
        CM_FREE_PTR(buf);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, rc_memzero);
        return CT_ERROR;
    }
    session = (session_t *)buf;
    buf_size = sizeof(session_t);

    if (srv_init_session_sql_curs(session) != CT_SUCCESS) {
        CM_FREE_PTR(buf);
        return CT_ERROR;
    }

    if (srv_alloc_rm(&rmid) != CT_SUCCESS) {
        CM_FREE_PTR(buf);
        return CT_ERROR;
    }

    if (srv_alloc_stat(&stat_id) != CT_SUCCESS) {
        srv_release_rm(rmid);
        CM_FREE_PTR(buf);
        return CT_ERROR;
    }

    buf = buf + buf_size;
    buf_size = knl_cur_size * g_instance->attr.init_cursors;
    opool_attach(buf, buf_size, knl_cur_size, &(session)->knl_cur_pool);

    buf = buf + buf_size;

    session->knl_session.temp_mtrl = (mtrl_context_t *)buf;
    buf += sizeof(mtrl_context_t) +
        sizeof(mtrl_segment_t) * (g_instance->kernel.attr.max_temp_tables * 2 - CT_MAX_MATERIALS);
    session->knl_session.temp_table_cache = (knl_temp_cache_t *)buf;
    session->knl_session.temp_table_capacity = g_instance->kernel.attr.max_temp_tables;

    buf += sizeof(knl_temp_cache_t) * g_instance->kernel.attr.max_temp_tables;
    session->knl_session.temp_dc_entries = (void *)buf;

    buf += sizeof(void *) * g_instance->kernel.attr.max_temp_tables;
    session->knl_session.lnk_tab_entries = (void *)buf;
    session->knl_session.lnk_tab_capacity = g_instance->kernel.attr.max_link_tables;

    /* set rm to session before session init, init rm later */
    session->knl_session.rmid = rmid;
    session->knl_session.rm = g_instance->rm_pool.rms[rmid];

    session->knl_session.stat_id = stat_id;
    session->knl_session.stat = g_instance->stat_pool.stats[stat_id];

    *session_out = session;

    return CT_SUCCESS;
}

static bool8 is_srv_session_priv_resv(session_pool_t *pool, session_t *session)
{
    return CT_FALSE;
}

static void srv_init_new_session(cs_pipe_t *pipe, session_t *session)
{
    session_pool_t *pool = &g_instance->session_pool;
    uint32 sid;

    srv_set_session_pipe(session, pipe);

    session->knl_session.id = CT_INVALID_ID32;
    session->knl_session.status = SESSION_INACTIVE;
    session->knl_session.trig_ui = NULL;
    session->knl_session.user_locked_ddl = CT_FALSE;
    session->kill_lock = 0;
    session->interactive_info.is_on = CT_FALSE;
    session->interactive_info.is_timeout = CT_FALSE;
    session->interactive_info.response_time = 0;
    CT_INIT_SPIN_LOCK(session->map_lock);
    cm_oamap_init_mem(&session->cursor_map);
    cm_oamap_init(&session->cursor_map, 0, cm_oamap_ptr_compare);
    session->total_cursor_num = 0;
    session->tse_inst_id = CT_INFINITE32;
    session->tse_thd_id = CT_INFINITE32;
    session->query_id = CT_INVALID_INT64;

    CT_INIT_SPIN_LOCK(session->dbg_ctl_lock);

    MEMS_RETVOID_IFERR(memset_sp(session->knl_session.datafiles, CT_MAX_DATA_FILES * sizeof(int32), 0xFF,
        CT_MAX_DATA_FILES * sizeof(int32)));

    cm_create_list2(&session->stmts, SESSION_STMT_EXT_STEP, SESSION_STMT_EXT_MAX, sizeof(sql_stmt_t));

    CT_RETVOID_IFERR(vmp_create(&g_instance->sga.vma, 0, &session->vmp));
    CT_RETVOID_IFERR(vmp_create(&g_instance->sga.vma, 0, &session->vms));
    knl_init_session(&g_instance->kernel, &session->knl_session, session->knl_session.uid, NULL, NULL);

    session->stat = g_stat_info_4_init;
    session->pl_cursors = NULL;
    session->stmts_cnt = 0;
    session->active_stmts_cnt = 0;
    session->triggers_disable = CT_FALSE;
    session->switched_schema = CT_FALSE;
    session->nologging_enable = CT_FALSE;
    session->optinfo_enable = CT_FALSE;
    session->plan_display_format = 0;
    session->priv_upgrade = CT_FALSE;
    session->client_kind = CLIENT_KIND_UNKNOWN;
    session->outer_join_optimization = PARAM_INIT;
    session->cbo_param.cbo_index_caching = CT_INVALID_ID32;
    session->cbo_param.cbo_index_cost_adj = CT_INVALID_ID32;
    session->withas_subquery = WITHAS_UNSET;
    session->cursor_sharing = PARAM_INIT;
    cm_init_session_nlsparams(&(session->nls_params));

    cm_spin_lock(&pool->lock, NULL);
    sid = pool->hwm;
    session->knl_session.id = sid;
    pool->sessions[sid] = session;
    g_instance->kernel.sessions[sid] = &session->knl_session;
    knl_init_sess_ex(&g_instance->kernel, &session->knl_session);
    session->priv = is_srv_session_priv_resv(pool, session);
#if defined(__arm__) || defined(__aarch64__)
    CM_MFENCE;
#endif
    pool->hwm++;
    g_instance->kernel.assigned_sessions++;
    cm_spin_unlock(&pool->lock);

    CT_LOG_DEBUG_INF("init new session %u [private [%u]]", session->knl_session.id, session->priv);
}

static bool8 is_srv_session_over_max_limit(session_pool_t *pool, cs_pipe_t *pipe)
{
    {
        return (pool->hwm >= pool->max_sessions);
    }
}

status_t srv_new_session(cs_pipe_t *pipe, session_t **session)
{
    session_pool_t *pool = &g_instance->session_pool;

    if (is_srv_session_over_max_limit(pool, pipe)) {
        if (!pool->is_log) {
            cm_reset_error();
            CT_LOG_RUN_WAR("too many connections[%d] exceed pool maximum", pool->hwm);
            CT_LOG_ALARM(WARN_MAXCONNECTIONS, "'max-sessions':'%u'}", g_instance->session_pool.max_sessions);
            pool->is_log = CT_TRUE;
        }
        CT_THROW_ERROR(ERR_TOO_MANY_CONNECTIONS);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_alloc_session_memory(session));


    srv_init_new_session(pipe, *session);
    return CT_SUCCESS;
}

status_t srv_alloc_session(session_t **session, cs_pipe_t *pipe, session_type_e type)
{
    bool32 reused = CT_FALSE;

    if (srv_try_reuse_session(session, pipe, &reused) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!reused) {
        if (srv_try_reuse_priv_session(session, pipe, &reused) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!reused) {
            if (srv_new_session(pipe, session) != CT_SUCCESS) {
                return CT_ERROR;
            }

            (*session)->logon_time = g_timer()->now;
            (*session)->interval_time = cm_monotonic_now();
        }
    }

    if (g_instance->session_pool.is_log == CT_TRUE) {
        g_instance->session_pool.is_log = CT_FALSE;
        cm_reset_error();
        CT_LOG_RUN_INF("session pool resume idle after exceed maximum");
        CT_LOG_ALARM_RECOVER(WARN_MAXCONNECTIONS, "'max-sessions':'%u'}", g_instance->session_pool.max_sessions);
    }

    (void)cm_atomic_inc(&g_instance->session_pool.service_count);
    (*session)->type = type;
    (*session)->knl_session.spid =
        cm_get_current_thread_id(); /* the newly-created session's spid should be calculated ,
                                        when the session reused from pool, the spid should be refreshed */

    return CT_SUCCESS;
}

status_t srv_alloc_knl_session(bool32 knl_reserved, knl_handle_t *knl_session)
{
    session_t *session = NULL;
    agent_t *agent = (agent_t *)malloc(sizeof(agent_t));

    if (agent == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(agent_t), "kernel agent");
        return CT_ERROR;
    }

    errno_t ret = memset_s(agent, sizeof(agent_t), 0, sizeof(agent_t));
    if (ret != EOK) {
        CM_FREE_PTR(agent);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    if (srv_alloc_session(&session, NULL, knl_reserved ? SESSION_TYPE_KERNEL_RESERVE : SESSION_TYPE_KERNEL_PAR) !=
        CT_SUCCESS) {
        CM_FREE_PTR(agent);
        return CT_ERROR;
    }

    if (srv_alloc_agent_res(agent) != CT_SUCCESS) {
        CM_FREE_PTR(agent);
        return CT_ERROR;
    }

    srv_bind_sess_agent(session, agent);
    *knl_session = &session->knl_session;

    return CT_SUCCESS;
}

void srv_release_knl_session(knl_handle_t sess)
{
    session_t *session = (session_t *)sess;
    agent_t *agent = session->agent;
    srv_unbind_sess_agent(session, agent);

    srv_release_session(session);
    srv_free_agent_res(agent, CT_TRUE);
    CM_FREE_PTR(agent);
}

status_t srv_register_zombie_epoll(session_t *session)
{
    struct epoll_event ev;
    int fd = (int)session->pipe->link.tcp.sock;

    ev.events = EPOLLRDHUP;
    ev.data.ptr = session;

    if (epoll_ctl(g_instance->session_pool.epollfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        CT_LOG_RUN_ERR(" register zombie epoll failed ");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void srv_unregister_zombie_epoll(session_t *session)
{
    int fd = (int)session->pipe->link.tcp.sock;

    if (epoll_ctl(g_instance->session_pool.epollfd, EPOLL_CTL_DEL, fd, NULL) != 0) {
        CT_LOG_RUN_ERR("[MAIN] epoll remove fd failed, session %d, os error %d", session->knl_session.id,
            cm_get_sock_error());
    }
}

static void srv_save_remote_host(cs_pipe_t *pipe, session_t *session)
{
    if (pipe->type == CS_TYPE_TCP) {
        (void)cm_inet_ntop((struct sockaddr *)&pipe->link.tcp.remote.addr, session->os_host, CT_HOST_NAME_BUFFER_SIZE);
    } else if (pipe->type == CS_TYPE_DOMAIN_SCOKET) {
        knl_securec_check(
            strncpy_s(session->os_host, CT_HOST_NAME_BUFFER_SIZE, LOOPBACK_ADDRESS, strlen(LOOPBACK_ADDRESS)));
    }
    return;
}
status_t srv_create_session(cs_pipe_t *pipe)
{
    session_t *session = NULL;

    CM_POINTER(pipe);

    // allocate a session
    // try to reuse free session, if failed, create a new one
    if (srv_alloc_session(&session, pipe, SESSION_TYPE_USER) != CT_SUCCESS) {
        return CT_ERROR;
    }

#ifndef WIN32
    if (srv_register_zombie_epoll(session) != CT_SUCCESS) {
        srv_release_session(session);
        return CT_ERROR;
    }
#endif

    srv_save_remote_host(pipe, session);

    if (srv_attach_reactor(session) != CT_SUCCESS) {
        CT_LOG_RUN_WAR("session(%u) attach reactor failed", session->knl_session.id);
        srv_release_session(session);
        return CT_ERROR;
    }

    session->disable_soft_parse = g_instance->kernel.attr.disable_soft_parse;
    return CT_SUCCESS;
}

static void srv_accutmate_stat(session_t *session)
{
    uint32 i;
    uint64 *knl_stats = (uint64 *)&g_instance->kernel.stat;
    uint64 *sql_stats = (uint64 *)&g_instance->sql.stat;
    uint64 *session_sql_stats = (uint64 *)&session->stat;
    uint64 *session_knl_stats = (uint64 *)session->knl_session.stat;
    uint16 stat_id = session->knl_session.stat->id;
    uint16 next = session->knl_session.stat->next;

    cm_spin_lock(&g_instance->stat_lock, NULL);
    for (i = 0; i < sizeof(knl_stat_t) / sizeof(uint64); i++) {
        knl_stats[i] += session_knl_stats[i];
    }

    for (i = 0; i < sizeof(sql_stat_t) / sizeof(uint64); i++) {
        sql_stats[i] += session_sql_stats[i];
    }
    cm_spin_unlock(&g_instance->stat_lock);

    *session->knl_session.stat = g_knl_stat_info_4_init;
    session->knl_session.stat->id = stat_id;
    session->knl_session.stat->next = next;
    session->stat = g_stat_info_4_init;
    errno_t ret = memset_s(session->knl_session.wait_pool, WAIT_EVENT_COUNT * sizeof(wait_event_t), 0,
        WAIT_EVENT_COUNT * sizeof(wait_event_t));
    knl_securec_check(ret);
}

static void srv_release_trans(session_t *session)
{
    do {
        if (srv_session_in_trans(session)) {
            CT_LOG_DEBUG_WAR("The transaction is not over. session id = %u", session->knl_session.id);
            do_rollback(session, NULL);
        }

        unlock_tables_directly(&session->knl_session);
        (void)srv_release_auton_rm(session);
    } while (KNL_IS_AUTON_SE(&session->knl_session));
}

void srv_deinit_session(session_t *session)
{
    uint32 i;
    sql_stmt_t *sql_stmt = NULL;

    srv_release_trans(session);
    srv_accutmate_stat(session);
    knl_close_temp_tables(&session->knl_session, DICT_TYPE_TEMP_TABLE_SESSION);
    knl_release_temp_dc(&session->knl_session);
    if (session->knl_session.page_stack.depth != 0) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "session->knl_session.page_stack.depth(%u) == 0",
            session->knl_session.page_stack.depth);
    }

    /* detach from resource control group */
    srv_detach_ctrl_group(session);
    /* release stmts resource */
    cm_spin_lock(&session->sess_lock, NULL);
    session->current_sql = CM_NULL_TEXT;
    session->sql_id = 0;

    for (i = 0; i < session->stmts.count; i++) {
        sql_stmt = (sql_stmt_t *)cm_list_get(&session->stmts, i);
        sql_free_stmt(sql_stmt);
    }

    session->current_stmt = NULL;
    session->unnamed_stmt = NULL;

    cm_reset_list(&session->stmts);
    session->stmts_cnt = 0;
    session->active_stmts_cnt = 0;

    cm_spin_unlock(&session->sess_lock);

    if (session->dbg_ctl != NULL) {
        spinlock_t *target_lock =
            (session->dbg_ctl->type == DEBUG_SESSION) ? session->dbg_ctl->target_lock : &session->dbg_ctl_lock;
        spinlock_t *debug_lock = (session->dbg_ctl->type == DEBUG_SESSION) ? &session->dbg_ctl_lock : NULL;
        cm_spin_lock_if_exists(target_lock, NULL);
        cm_spin_lock_if_exists(debug_lock, NULL);
        srv_free_dbg_ctl(session);
        cm_spin_unlock_if_exists(debug_lock);
        cm_spin_unlock_if_exists(target_lock);
    }

    /* close pipe */
    if (session->pipe != NULL) {
#ifndef WIN32
        if (session->type == SESSION_TYPE_USER || session->type == SESSION_TYPE_EMERG) {
            srv_unregister_zombie_epoll(session);
        }
#endif

        cs_disconnect(session->pipe);
    }

    // notice: session status must be reset at last.
    session->knl_session.ssn = 0;
    session->proto_type = PROTO_TYPE_UNKNOWN;
    session->is_auth = CT_FALSE;
    session->auth_status = AUTH_STATUS_NONE;
    session->is_reg = CT_FALSE;

    // this flag can only assigned to false in session initialize phase
    // to make sure that not be killed more than once in following scenario:
    // 1.session is being between releasing and reusing, and a kill-session request come
    session->knl_session.canceled = CT_FALSE;
    session->knl_session.force_kill = CT_FALSE;
    session->knl_session.status = SESSION_INACTIVE;
    session->knl_session.trig_ui = NULL;
    session->knl_session.spid = 0;
    session->knl_session.thread_shared = CT_FALSE;
    session->knl_session.autotrace = CT_FALSE;
    session->knl_session.interactive_altpwd = CT_FALSE;
    session->knl_session.user_locked_ddl = CT_FALSE;
    session->knl_session.user_locked_lst = NULL;
    for (uint16 file_id = 0; file_id < CT_MAX_DATA_FILES; file_id++) {
        datafile_t *df = &session->knl_session.kernel->db.datafiles[file_id];
        cm_close_device(df->ctrl->type, &session->knl_session.datafiles[file_id]);
    }
    knl_destroy_se_alcks(session);

    session->stat = g_stat_info_4_init;
    session->os_prog[0] = '\0';
    session->os_host[0] = '\0';
    session->os_user[0] = '\0';
    session->db_user[0] = '\0';
    session->curr_schema[0] = '\0';
    session->curr_user2[0] = '\0';
    session->curr_user.len = 0;

#ifdef DB_DEBUG_VERSION
    knl_clear_syncpoint_action(&session->knl_session);
#endif /* DB_DEBUG_VERSION */

    vmp_destory(&session->vmp);
    vmp_destory(&session->vms);

    srv_release_stat(&session->knl_session.stat_id);
}

void srv_release_session(session_t *session)
{
    srv_deinit_session(session);
    CM_MFENCE;
    /* should put last position */
    srv_return_session(session);
}

status_t srv_return_error(session_t *session)
{
    status_t ret = session->sender->send_result_error(session);
    if (ret != CT_SUCCESS) {
        CT_LOG_DEBUG_ERR("send result error failed, close this session");
    }
    return ret;
}

status_t srv_return_success(session_t *session)
{
    status_t ret = session->sender->send_result_success(session);
    if (ret != CT_SUCCESS) {
        CT_LOG_DEBUG_ERR("send result success failed, close this session");
    }
    return ret;
}

EXTER_ATTACK status_t srv_process_logout(session_t *session)
{
    // detach resource control group when logout
    srv_detach_ctrl_group(session);
    session->sql_audit.action = SQL_AUDIT_ACTION_LOGOUT;
    session->is_log_out = CT_TRUE;
    return CT_SUCCESS;
}

EXTER_ATTACK status_t srv_process_cancel(session_t *session)
{
    uint32 sid;

    CM_POINTER(session);
    session->sql_audit.action = SQL_AUDIT_ACTION_CANCEL;
    session->sql_audit.audit_type = SQL_AUDIT_DML;

    cs_packet_t *recv_pack = &session->agent->recv_pack;

    cs_init_get(recv_pack);
    CT_RETURN_IFERR(cs_get_int32(recv_pack, (int32 *)&sid));
    if (sid >= CT_MAX_SESSIONS) {
        CT_THROW_ERROR(ERR_CLT_INVALID_VALUE, "session id", sid);
        return CT_ERROR;
    }

    session_t *spec_session = g_instance->session_pool.sessions[sid];
    if (spec_session != NULL) {
        /* verify : user can NOT cancel other's current operation */
        if (!cm_text_equal_ins(&session->curr_user, &spec_session->curr_user)) {
            CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "(cancel current operation of other user)");
            return CT_ERROR;
        }

        cm_spin_lock(&session->kill_lock, NULL);
        // AVOID TO GET A UNSTABLE SID.
        spec_session->knl_session.canceled = CT_TRUE;
        cm_spin_unlock(&session->kill_lock);
    }
    return CT_SUCCESS;
}

static void srv_return_error_when_packet_overflow(session_t *session)
{
    int32 err_code = 0;
    const char *err_message = NULL;
    cm_get_error(&err_code, &err_message, NULL);
    if (err_code == ERR_TCP_TIMEOUT) {
        CT_LOG_RUN_INF("session %d will be killed,because receive data timeout", session->knl_session.id);
    } else {
        (void)srv_return_error(session);
    }
}

static void srv_proc_auth_failed(session_t *session)
{
    srv_judge_login(session);
    session->is_auth = CT_FALSE;
    session->auth_status = AUTH_STATUS_NONE;
    session->is_log_out = CT_TRUE;
}

static void sql_proc_prepare_failed(session_t *session)
{
    if (session->knl_session.interactive_altpwd) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "illegal sql text.");
        session->is_log_out = CT_TRUE;
    }
}

static cmd_handler_t g_server_cmd_hander[] = {
    [ CS_CMD_LOGIN ]         = { srv_process_login,         srv_proc_auth_failed },
    [ CS_CMD_FREE_STMT ]     = { sql_process_free_stmt,     NULL },
    [ CS_CMD_PREPARE ]       = { sql_process_prepare,       sql_proc_prepare_failed },
    [ CS_CMD_EXECUTE ]       = { sql_process_execute,       NULL },
    [ CS_CMD_FETCH ]         = { sql_process_fetch,         NULL },
    [ CS_CMD_COMMIT ]        = { sql_process_commit,        NULL },
    [ CS_CMD_ROLLBACK ]      = { sql_process_rollback,      NULL },
    [ CS_CMD_LOGOUT ]        = { srv_process_logout,        NULL },
    [ CS_CMD_CANCEL ]        = { srv_process_cancel,        NULL },
    [ CS_CMD_QUERY ]         = { sql_process_query,         NULL },
    [ CS_CMD_PREP_AND_EXEC ] = { sql_process_prep_and_exec, NULL },
    [ CS_CMD_LOB_READ ]      = { sql_process_lob_read,      NULL },
    [ CS_CMD_LOB_WRITE ]     = { sql_process_lob_write,     NULL },
    [ CS_CMD_XA_PREPARE ]    = { sql_process_xa_prepare,    NULL },
    [ CS_CMD_XA_COMMIT ]     = { sql_process_xa_commit,     NULL },
    [ CS_CMD_XA_ROLLBACK ]   = { sql_process_xa_rollback,   NULL },
    [ CS_CMD_HANDSHAKE ]     = { srv_process_handshake,     srv_proc_auth_failed },
    [ CS_CMD_AUTH_INIT ]     = { srv_process_auth_init,     srv_proc_auth_failed },
    [ CS_CMD_XA_START ]      = { sql_process_xa_start,      NULL },
    [ CS_CMD_XA_END ]        = { sql_process_xa_end,        NULL },
    [ CS_CMD_XA_STATUS ]     = { sql_process_xa_status,     NULL },
    [ CS_CMD_LOAD ]          = { sql_process_load,          NULL },
    [ CS_CMD_EXE_MULTI_SQL ] = { sql_process_pre_exec_multi_sql, NULL },
    [ CS_CMD_CEIL ]          = { NULL, NULL},
};


EXTER_ATTACK status_t srv_process_command_core(session_t *session, uint8 cmd)
{
    status_t status;

    if (cmd >= ARRAY_NUM(g_server_cmd_hander)) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "the req cmd is not valid");
        return CT_ERROR;
    }

    /* reset audit sql */
    sql_reset_audit_sql(&session->sql_audit);

    cmd_handler_t *handle = &g_server_cmd_hander[cmd];
    if (handle->func == NULL) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "the req cmd is not valid");
        return CT_ERROR;
    }
    status = handle->func(session);
    if (status != CT_SUCCESS && handle->func2 != NULL) {
        handle->func2(session);
    }

    /* record audit log after process cmd */
    sql_record_audit_log(session, status, CT_FALSE);

    /* try free temp stmt if process cmd failed: CS_CMD_PREP_AND_EXEC CS_CMD_LOB_WRITE CS_CMD_PREPARE CS_CMD_QUERY */
    if (session->current_stmt != NULL) {
        if (session->current_stmt->is_temp_alloc) {
            if (status == CT_ERROR) {
                sql_free_stmt(session->current_stmt);
            } else {
                session->current_stmt->is_temp_alloc = CT_FALSE;
            }
        }
        session->current_stmt->last_sql_active_time = g_timer()->now;
    }

    if (status == CT_SUCCESS && cmd == CS_CMD_LOGIN) {
        if (g_instance->kernel.db.status == DB_STATUS_OPEN) {
            srv_judge_login_success(session->os_host);
        }
    }

    return status;
}

EXTER_ATTACK status_t srv_read_packet(session_t *session)
{
    if (cs_read(session->pipe, &session->agent->recv_pack, CT_FALSE) != CT_SUCCESS) {
        srv_return_error_when_packet_overflow(session);
        cm_stack_reset(session->stack);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t srv_process_command_check(session_t *session, uint32 cmd)
{
    do {
        if (cmd != CS_CMD_HANDSHAKE && cmd != CS_CMD_LOGIN && cmd != CS_CMD_AUTH_INIT) {
            if (!session->is_auth) {
                CT_LOG_RUN_INF("Account auth failed.");
                CT_THROW_ERROR(ERR_ACCOUNT_AUTH_FAILED);
            } else if (cmd < CS_CMD_LOGIN || cmd > CS_CMD_CEIL ||
                cs_get_version(&session->agent->recv_pack) != session->call_version) {
                CT_THROW_ERROR(ERR_INVALID_PROTOCOL);
                srv_judge_login(session);
            } else if ((session->rsrc_group != NULL && !session->rsrc_group->plan->is_valid) ||
                (session->rsrc_group == NULL && GET_RSRC_MGR->plan != NULL)) {
                /* resource plan changed, re-attach to the new group */
                CT_BREAK_IF_TRUE(srv_attach_ctrl_group(session) == CT_SUCCESS);
            } else {
                break;
            }

            /* inactive session and reset session stack */
            (void)srv_return_error(session);
            session->knl_session.status = SESSION_INACTIVE;
            cm_stack_reset(session->stack);
            return CT_ERROR;
        }
    } while (0);

    return CT_SUCCESS;
}

static status_t srv_process_init_session(session_t *session)
{
    sql_audit_init(&session->sql_audit);
    session->knl_session.status = SESSION_ACTIVE;
    session->knl_session.canceled = CT_FALSE;
    session->exec_prev_stat.stat_level = 0;
    session->current_stmt = NULL;
    session->prefix_tenant_flag = CT_TRUE;
    if (session->recv_pack == NULL || session->send_pack == NULL) {
        CT_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "recv_pack or send_pack");
        return CT_ERROR;
    }
    cs_init_get(session->recv_pack);
    cs_init_set(session->send_pack, CS_LOCAL_VERSION);
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    /* reset packet memory to find pointer from context to packet memory */
    (void)memset_s(session->agent->recv_pack.buf, session->agent->recv_pack.buf_size, 'Z',
        session->agent->recv_pack.buf_size);
#endif
    return CT_SUCCESS;
}

EXTER_ATTACK status_t srv_process_command(session_t *session)
{
    uint32 cmd;
    status_t ret;
    timeval_t tv_begin;

    (void)cm_gettimeofday(&tv_begin);
    cm_reset_error();
    CT_RETURN_IFERR(srv_process_init_session(session));

    CT_RETURN_IFERR(srv_read_packet(session));

    /* process request command */
    cmd = (uint32)session->agent->recv_pack.head->cmd;
    sql_begin_exec_stat((void *)session);
    /* check whether is not logging or invalid cmd or invalid call_version */
    CT_RETURN_IFERR(srv_process_command_check(session, cmd));

    ret = srv_process_command_core(session, cmd);


    /* send response command */
    if (ret != CT_SUCCESS) {
        ret = srv_return_error(session);
    } else {
        ret = srv_return_success(session);
    }

    /* inactive session and reset session stack */
    session->knl_session.status = SESSION_INACTIVE;

    /* when killed flag true, agent should rollback or commit txn */
    if (IS_LOG_OUT(session)) {
        session->is_log_out = CT_TRUE;
    }

    /* try record last response time for interactive timeout check */
    if (session->interactive_info.is_on) {
        session->interactive_info.response_time = cm_monotonic_now();
    }
    sql_end_exec_stat((void *)session);
    cm_stack_reset(session->stack);
    vmp_free(&session->vmp, g_instance->kernel.attr.vmp_cache_pages);
    vmp_free(&session->vms, g_instance->kernel.attr.vmp_cache_pages);
    return ret;
}

status_t srv_wait_for_more_data(session_t *session)
{
    bool32 ready = CT_FALSE;
    while (!ready) {
        if (cs_wait(session->pipe, CS_WAIT_FOR_READ, CT_POLL_WAIT, &ready) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (session->knl_session.killed) {
            CT_THROW_ERROR(ERR_OPERATION_KILLED);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static inline status_t srv_check_all_session_free(uint32 sid)
{
    uint32 i;
    session_pool_t *pool = &g_instance->session_pool;

    for (i = g_instance->kernel.reserved_sessions; i < pool->hwm; i++) {
        if (i == sid) { // skip current session
            continue;
        }

        if (srv_is_kernel_reserve_session(pool->sessions[i]->type)) { // skip kernel reserve sessions
            continue;
        }

        if (!pool->sessions[i]->is_free) {
            CT_LOG_DEBUG_INF("[shutdown] session %u still not free, tid %u", pool->sessions[i]->knl_session.id,
                cm_get_current_thread_id());
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t srv_wait_all_session_be_killed(session_t *session)
{
    bool32 ready = CT_FALSE;

    for (;;) {
        if (srv_check_all_session_free(session->knl_session.id) == CT_SUCCESS) {
            CT_LOG_RUN_INF("wait all session be killed end");
            return CT_SUCCESS;
        }

        if (cs_wait(session->pipe, CS_WAIT_FOR_READ, CT_POLL_WAIT, &ready) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_IN_SHUTDOWN_CANCELED);
            return CT_ERROR;
        }
        cm_sleep(50);
    }
}

void srv_wait_all_session_free(void)
{
    uint32 i;
    session_pool_t *pool = &g_instance->session_pool;

    for (;;) {
        /* hit scenario instance startup failed, session can not be freed by srv_instance_loop funtion
         */
        for (i = g_instance->kernel.reserved_sessions; i < pool->hwm; i++) {
            if (srv_is_kernel_reserve_session(pool->sessions[i]->type)) { // skip kernel reserve sessions
                continue;
            }
            if (!pool->sessions[i]->is_free) {
                break;
            }
        }

        if (i >= pool->hwm) {
            /* all session is free */
            break;
        }

        cm_sleep(50);
    }
}

void srv_kill_session_byhost(const char *addr_ip)
{
    session_pool_t *pool = &g_instance->session_pool;
    session_t *session = NULL;
    uint32 i;
    char os_server_ip[CM_MAX_IP_LEN] = {0};
    for (i = g_instance->kernel.reserved_sessions; i < pool->hwm; i++) {
        session = pool->sessions[i];
        CT_CONTINUE_IFTRUE(session == NULL || session->is_free || session->pipe == NULL);
        (void)cm_inet_ntop((struct sockaddr *)&session->pipe->link.tcp.local.addr, os_server_ip, CM_MAX_IP_LEN);
        text_t server_ip = { os_server_ip, (uint32)strlen(os_server_ip) };
        if (cm_text_str_equal(&server_ip, addr_ip)) {
            srv_mark_sess_killed(session, CT_FALSE, session->knl_session.serial_id);
        }
    }
}

void srv_wait_session_free_byhost(uint32 current_sid, const char *addr_ip)
{
    uint32 i;
    session_t *session = NULL;
    char os_server_ip[CM_MAX_IP_LEN] = {0};
    session_pool_t *pool = &g_instance->session_pool;

    for (;;) {
        for (i = g_instance->kernel.reserved_sessions; i < pool->hwm; i++) {
            CT_CONTINUE_IFTRUE(i == current_sid);
            session = pool->sessions[i];
            CT_CONTINUE_IFTRUE(session->pipe == NULL);
            (void)cm_inet_ntop((struct sockaddr *)&session->pipe->link.tcp.local.addr, os_server_ip, CM_MAX_IP_LEN);
            text_t server_ip = { os_server_ip, (uint32)strlen(os_server_ip) };
            if (cm_text_str_equal(&server_ip, addr_ip) && !pool->sessions[i]->is_free) {
                break;
            }
        }
        if (i >= pool->hwm) {
            break;
        }
        cm_sleep(50);
    }
}

void srv_kill_all_session(session_t *session, bool32 is_force)
{
    uint32 i;
    session_pool_t *pool = &g_instance->session_pool;
    knl_session_t *job_session = g_instance->kernel.sessions[SESSION_ID_JOB];
    knl_session_t *synctime_session = g_instance->kernel.sessions[SESSION_ID_SYNC_TIME];

    /* mark job session to be killed, and make sure no new job created. */
    job_session->killed = CT_TRUE;
    job_session->force_kill = is_force;
    CT_LOG_RUN_INF("start close jobmaster thread");

    do {
        if (job_session->status == SESSION_INACTIVE) {
            CT_LOG_RUN_INF("jobmaster thread closed");
            break;
        }
        cm_sleep(100);
    } while (1);

    /* mark sync timer session to be killed, and make sure no new sync timer created. */
    synctime_session->killed = CT_TRUE;
    synctime_session->force_kill = is_force;
    CT_LOG_RUN_INF("start close synctimer thread");

    do {
        if (synctime_session->status == SESSION_INACTIVE) {
            CT_LOG_RUN_INF("synctimer thread closed");
            break;
        }
        cm_sleep(100);
    } while (1);

    /* kill all user session */
    for (i = g_instance->kernel.reserved_sessions; i < pool->hwm; i++) {
        if ((session != NULL && i == session->knl_session.id) || pool->sessions[i]->is_free ||
            srv_is_kernel_reserve_session(pool->sessions[i]->type)) { // skip current and kerenl reserve session
            continue;
        }

        srv_mark_sess_killed(pool->sessions[i], is_force, pool->sessions[i]->knl_session.serial_id);
    }
    CT_LOG_RUN_INF("kill all session end");
}

bool32 sql_try_inc_par_threads(sql_cursor_t *cursor)
{
    bool32 result = CT_TRUE;
    uint32 parallel = cursor->par_ctx.par_parallel;
    sql_par_pool_t *sql_par_pool = &g_instance->sql_par_pool;

    parallel = MIN(parallel, CT_MAX_QUERY_PARALLELISM);

    cm_spin_lock(&sql_par_pool->lock, NULL);
    if (sql_par_pool->used_sessions + parallel > sql_par_pool->max_sessions) {
        result = CT_FALSE;
    } else {
        result = CT_TRUE;
        sql_par_pool->used_sessions += parallel;
        cursor->par_ctx.par_threads_inuse = CT_TRUE;
    }
    cm_spin_unlock(&g_instance->sql_par_pool.lock);

    return result;
}

void sql_dec_par_threads(sql_cursor_t *cursor)
{
    uint32 parallel = cursor->par_ctx.par_parallel;
    sql_par_pool_t *sql_par_pool = &g_instance->sql_par_pool;

    parallel = MIN(parallel, CT_MAX_QUERY_PARALLELISM);

    cm_spin_lock(&g_instance->sql_par_pool.lock, NULL);
    sql_par_pool->used_sessions -= parallel;
    cm_spin_unlock(&g_instance->sql_par_pool.lock);

    cursor->par_ctx.par_threads_inuse = CT_FALSE;
}

status_t srv_alloc_par_session(session_t **session_handle)
{
    sql_par_pool_t *pool;
    uint32 i;

    pool = &g_instance->sql_par_pool;

    cm_spin_lock(&pool->lock, NULL);

    for (i = 0; i < pool->max_sessions; i++) {
        if (pool->sessions[i]->knl_session.status == SESSION_INACTIVE) {
            pool->sessions[i]->knl_session.status = SESSION_ACTIVE;
            pool->sessions[i]->knl_session.killed = CT_FALSE;
            pool->sessions[i]->knl_session.canceled = CT_FALSE;
            pool->sessions[i]->knl_session.serial_id += 1;
            pool->sessions[i]->type = SESSION_TYPE_SQL_PAR;

            *session_handle = pool->sessions[i];
            cm_spin_unlock(&pool->lock);
            return CT_SUCCESS;
        }
    }

    cm_spin_unlock(&pool->lock);

    return CT_ERROR;
}

/**
 * release an sql parallel session
 * @param session handle
 */
void srv_release_par_session(session_t *session_handle)
{
    sql_stmt_t *sql_stmt = NULL;
    uint32 i;

    cm_spin_lock(&session_handle->sess_lock, NULL);

    for (i = 0; i < session_handle->stmts.count; i++) {
        sql_stmt = (sql_stmt_t *)cm_list_get(&session_handle->stmts, i);
        sql_free_stmt(sql_stmt);
    }

    cm_reset_list(&session_handle->stmts);
    session_handle->stmts_cnt = 0;
    session_handle->active_stmts_cnt = 0;

    cm_spin_unlock(&session_handle->sess_lock);

    session_handle->parent = NULL;
    session_handle->current_stmt = NULL;
    session_handle->unnamed_stmt = NULL;
    session_handle->knl_session.ssn = 0; // SQL SEQUENCE NUMBER
    session_handle->knl_session.drop_uid = CT_INVALID_ID32;
    session_handle->knl_session.killed = CT_FALSE;
    session_handle->knl_session.canceled = CT_FALSE;
    session_handle->knl_session.spid = 0;
    session_handle->knl_session.status = SESSION_INACTIVE;

    vmp_destory(&session_handle->vmp);
    vmp_destory(&session_handle->vms);
}

bool32 srv_whether_login_with_user(text_t *username)
{
    uint32 i;
    session_t *session = NULL;
    session_pool_t *pool = &g_instance->session_pool;

    cm_spin_lock(&pool->lock, NULL);
    for (i = g_instance->kernel.reserved_sessions; i < pool->hwm; i++) {
        session = pool->sessions[i];
        if (session == NULL) {
            continue;
        }

        if (cm_text_equal(username, &session->curr_user) &&
            (session->is_reg || (session->knl_session.status >= SESSION_SUSPENSION))) {
            cm_spin_unlock(&pool->lock);
            return CT_TRUE;
        }
    }
    cm_spin_unlock(&pool->lock);

    return CT_FALSE;
}

bool32 srv_session_in_trans(session_t *session)
{
    if (session->knl_session.rm == NULL) {
        return CT_FALSE;
    }

    return (knl_xact_status(&session->knl_session) != XACT_END || knl_xa_xid_valid(&session->knl_session.rm->xa_xid) ||
        session->knl_session.rm->query_scn != CT_INVALID_ID64 || session->knl_session.rm->svpt_count > 0);
}

status_t srv_reset_statistic(session_t *session)
{
    uint32 i;
    knl_stat_t *knl_stat = NULL;
    sql_stat_t *sql_stat = NULL;
    session_t *se = NULL;
    log_context_t *redo = &g_instance->kernel.redo_ctx;
    ckpt_context_t *ckpt = &g_instance->kernel.ckpt_ctx;
    bak_context_t *backup = &g_instance->kernel.backup_ctx;

    for (i = 0; i <= g_instance->session_pool.hwm; i++) {
        if (i == g_instance->session_pool.hwm) {
            sql_stat = &g_instance->sql.stat;
            knl_stat = &g_instance->kernel.stat;
        } else {
            se = g_instance->session_pool.sessions[i];
            uint16 stat_id = se->knl_session.stat_id;
            if (se->is_free || stat_id == CT_INVALID_ID16) {
                continue;
            }
            CM_MFENCE;
            sql_stat = &se->stat;
            knl_stat = g_instance->stat_pool.stats[stat_id];
        }

        *sql_stat = g_stat_info_4_init;
        uint32 len = sizeof(knl_stat_t) - sizeof(uint32);
        MEMS_RETURN_IFERR(memset_s((char *)knl_stat + sizeof(uint32), len, 0, len));
    }

    MEMS_RETURN_IFERR(memset_s(&redo->stat, sizeof(log_stat_t), 0, sizeof(log_stat_t)));
    MEMS_RETURN_IFERR(memset_s(&ckpt->stat, sizeof(ckpt_stat_t), 0, sizeof(ckpt_stat_t)));
    MEMS_RETURN_IFERR(memset_s(&backup->bak.stat, sizeof(bak_stat_t), 0, sizeof(bak_stat_t)));
    cm_atomic_set(&g_instance->logined_cumu_count, 0);

    mes_init_stat();
    record_io_stat_reset();
    return CT_SUCCESS;
}

status_t srv_kill_session(session_t *session, knl_alter_sys_def_t *def)
{
    uint32 sid = def->session_id;
    session_pool_t *pool = &g_instance->session_pool;

    if (def->node_id != 0) {
        // kill other CN's session,not itself
        return CT_SUCCESS;
    }

    if (sid == session->knl_session.id) {
        CT_THROW_ERROR(ERR_CANT_KILL_CURR_SESS);
        return CT_ERROR;
    }

    if (sid >= pool->hwm || sid < g_instance->kernel.reserved_sessions) {
        CT_THROW_ERROR(ERR_INVALID_SESSION_ID);
        return CT_ERROR;
    }

    session_t *sess_killed = pool->sessions[sid];
    if (sess_killed->knl_session.serial_id != def->serial_id || sess_killed->is_free) {
        CT_THROW_ERROR(ERR_INVALID_SESSION_ID);
        return CT_ERROR;
    }
    if (!(sess_killed->type == SESSION_TYPE_USER || sess_killed->type == SESSION_TYPE_JOB ||
        sess_killed->type == SESSION_TYPE_EMERG)) {
        CT_THROW_ERROR(ERR_INVALID_SESSION_TYPE);
        return CT_ERROR;
    }
    srv_mark_sess_killed(sess_killed, CT_FALSE, def->serial_id);
    return CT_SUCCESS;
}

void clean_open_cursors(void *session_handle, uint64 lsn)
{
    session_t *session = (session_t *)session_handle;
    knl_cursor_t *knl_cur = NULL;
    object_t *object = NULL;
    sql_stmt_t *sql_stmt = NULL;

    for (uint32 i = 0; i < session->stmts.count; i++) {
        sql_stmt = (sql_stmt_t *)cm_list_get(&session->stmts, i);

        object = sql_stmt->knl_curs.first;
        for (uint32 j = 0; j < sql_stmt->knl_curs.count; j++) {
            knl_cur = (knl_cursor_t *)object->data;

            // only invalidate opened cursor after the savepoint lsn
            if (knl_cur->is_valid && knl_cur->query_lsn > lsn) {
                knl_cur->is_valid = CT_FALSE;
            }
            object = object->next;
        }
    }
}


void clean_open_temp_cursors(void *session_handle, void *temp_cache)
{
    session_t *session = (session_t *)session_handle;
    knl_cursor_t *knl_cur = NULL;
    object_t *object = NULL;
    sql_stmt_t *sql_stmt = NULL;

    for (uint32 i = 0; i < session->stmts.count; i++) {
        sql_stmt = (sql_stmt_t *)cm_list_get(&session->stmts, i);

        object = sql_stmt->knl_curs.first;
        for (uint32 j = 0; j < sql_stmt->knl_curs.count; j++) {
            knl_cur = (knl_cursor_t *)object->data;

            if (knl_cur->is_valid && knl_cur->temp_cache == (knl_temp_cache_t *)temp_cache) {
                knl_cur->is_valid = CT_FALSE;
            }
            object = object->next;
        }
    }
}

void invalidate_tablespaces(uint32 space_id)
{
    datafile_t *df = NULL;
    session_pool_t *pool = &g_instance->session_pool;
    knl_session_t *session = NULL;
    uint32 session_id, file_id;
    ckpt_context_t *ckpt = &g_instance->kernel.ckpt_ctx;
    dbwr_context_t *dbwr_ctx = NULL;

    space_t *space = &g_instance->kernel.db.spaces[space_id];

    for (file_id = 0; file_id < CT_MAX_SPACE_FILES; file_id++) {
        if (CT_INVALID_ID32 == space->ctrl->files[file_id]) {
            continue;
        }

        df = &g_instance->kernel.db.datafiles[space->ctrl->files[file_id]];

        if (DF_FILENO_IS_INVAILD(df) || !DATAFILE_IS_ONLINE(df)) {
            continue;
        }

        if (df->space_id != space->ctrl->id) {
            CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "df->space_id(%u) == space->ctrl->id(%u)", df->space_id,
                space->ctrl->id);
        }
        if (df->file_no != file_id) {
            CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "df->file_no(%u) == file_id(%u)", df->file_no, file_id);
        }
        if (df->ctrl->id != space->ctrl->files[file_id]) {
            CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "df->space_id(%u) == space->ctrl->files[file_id](%u)", df->ctrl->id,
                space->ctrl->files[file_id]);
        }

        for (session_id = 0; session_id < g_instance->session_pool.hwm; session_id++) {
            session = &pool->sessions[session_id]->knl_session;
            if (*DATAFILE_FD(session, df->ctrl->id) != -1) {
                cm_close_device(df->ctrl->type, DATAFILE_FD(session, df->ctrl->id));
            }
        }

        for (uint32 i = 0; i < ckpt->dbwr_count; i++) {
            dbwr_ctx = &ckpt->dbwr[i];

            if (dbwr_ctx->datafiles[df->ctrl->id] != -1) {
                cm_close_device(df->ctrl->type, &dbwr_ctx->datafiles[df->ctrl->id]);
            }
        }
    }
    return;
}

void srv_init_ip_white(void)
{
    white_context_t *ctx = GET_WHITE_CTX;

    CT_INIT_SPIN_LOCK(ctx->lock);
    ctx->iwl_enabled = CT_FALSE;
    cm_create_list(&ctx->ip_white_list, sizeof(cidr_t));
    cm_create_list(&ctx->ip_black_list, sizeof(cidr_t));
    cm_create_list(&ctx->user_white_list, sizeof(uwl_entry_t));
}

void srv_init_pwd_black(void)
{
    black_context_t *ctx = GET_PWD_BLACK_CTX;
    CT_INIT_SPIN_LOCK(ctx->lock);
    cm_create_list(&ctx->user_pwd_black_list, sizeof(pbl_entry_t));
}

void srv_init_ip_login_addr(void)
{
    mal_ip_context_t *malicious_ctx = GET_MAL_IP_CTX;

    CT_INIT_SPIN_LOCK(malicious_ctx->ip_lock);
    cm_create_list(&malicious_ctx->malicious_ip_list, sizeof(ip_login_t));
}

static void srv_expire_unauth_session(session_t *session)
{
    session_pool_t *pool = &g_instance->session_pool;

    if (!session->is_auth) {
        uint32 elapse_timeout = (uint32)((cm_monotonic_now() - session->interval_time) / MICROSECS_PER_SECOND);
        bool32 timeout = elapse_timeout > pool->unauth_session_expire_time;
        if (timeout) {
            CT_LOG_RUN_WAR("[main] unauthenticated session will be expired, sid=[%d], timeout=[%us]",
                session->knl_session.id, elapse_timeout);
            srv_mark_sess_killed(session, CT_FALSE, session->knl_session.serial_id);
        }
    }
}

static void srv_interactive_timeout(session_t *session)
{
    if (!session->interactive_info.is_on || session->interactive_info.response_time == 0 ||
        session->knl_session.status >= SESSION_SUSPENSION) {
        return;
    }

    uint32 elapse_timeout =
        (uint32)((cm_monotonic_now() - session->interactive_info.response_time) / MICROSECS_PER_SECOND);

    bool32 timeout = elapse_timeout > g_instance->sql.interactive_timeout;

    if (timeout && !session->interactive_info.is_timeout) {
        session->interactive_info.response_time = 0;
        session->interactive_info.is_timeout = CT_TRUE;

        CT_LOG_RUN_WAR("[main] inactive session is timeout and will be disconnect, sid=[%u], "
            "clt_ip=[%s], user=[%s], timeout=[%us]",
            session->knl_session.id, session->os_host, session->db_user, elapse_timeout);
        srv_mark_sess_killed(session, CT_FALSE, session->knl_session.serial_id);
    }

    return;
}

void srv_expire_unauth_timeout_session(void)
{
    session_t *session = NULL;
    session_pool_t *pool = &g_instance->session_pool;
    for (uint32 i = g_instance->kernel.reserved_sessions; i < pool->hwm; i++) {
        session = pool->sessions[i];

        if (session != NULL && session->type == SESSION_TYPE_USER && !session->is_free && session->is_reg &&
            !session->knl_session.killed) {
            srv_expire_unauth_session(session);
            srv_interactive_timeout(session);
        }
    }
}

void srv_mark_user_sess_killed(session_t *session, bool32 force, uint32 serial_id)
{
    // hit scenarios:
    // 1.session created by listener, but not registered to reactor
    // wait until session registered, intermediate state is_reg false, and killed false
    // 2.while two kill-session request arrived at the same time, one thread has release session.
    // but session have not been used, avoid deadloop, if session->knl_session.killed is true, break loop
    while (!session->is_reg) {
        if (session->knl_session.killed) {
            return;
        }
        cm_sleep(5);
    }

    cm_spin_lock(&session->kill_lock, NULL);
    if (session->knl_session.killed) {
        cm_spin_unlock(&session->kill_lock);
        return;
    }

    // a session is killed, destroyed, and reused
    if (serial_id != session->knl_session.serial_id) {
        cm_spin_unlock(&session->kill_lock);
        return;
    }

    session->knl_session.killed = CT_TRUE;
    session->knl_session.force_kill = force;
    cm_spin_unlock(&session->kill_lock);

    // remove killed session from group session queue
    if (session->rsrc_group != NULL && session->queued_time != 0) {
        cm_spin_lock(&session->rsrc_group->lock, NULL);
        if (session->next != NULL && session->prev != NULL) {
            biqueue_del_node(QUEUE_NODE_OF(session));
            rsrc_queue_length_dec(session);
            session->queued_time = 0;
        }
        cm_spin_unlock(&session->rsrc_group->lock);
        srv_detach_ctrl_group(session);
    }
    if (session->is_auth) {
        (void)cm_atomic_dec(&g_instance->logined_count);
    }
    reactor_add_kill_event(session);
}

status_t srv_get_sql_text(uint32 sessionid, text_t *sql)
{
    text_t *sql_text;

    if (sql->len <= 1) {
        return CT_ERROR;
    }
    session_t *target_session = g_instance->session_pool.sessions[sessionid];
    cm_spin_lock(&target_session->sess_lock, NULL);
    if (target_session == NULL || target_session->is_free || target_session->knl_session.killed) {
        cm_spin_unlock(&target_session->sess_lock);
        return CT_ERROR;
    }

    if (CM_IS_EMPTY(&target_session->current_sql)) {
        cm_spin_unlock(&target_session->sess_lock);
        return CT_ERROR;
    }
    sql_text = &target_session->current_sql;

    uint32 offset = sql->len <= sql_text->len ? sql->len - 1 : sql_text->len;
    int32 code = memcpy_sp(sql->str, (size_t)offset, sql_text->str, (size_t)offset);

    cm_spin_unlock(&target_session->sess_lock);
    MEMS_RETURN_IFERR(code);
    sql->str[offset] = '\0';
    sql->len = offset;

    return CT_SUCCESS;
}

void get_session_min_local_scn(knl_session_t *knl_sess, knl_scn_t *local_scn)
{
    session_t *sess = (session_t *)knl_sess;
    sql_stmt_t *stmt = NULL;
    knl_scn_t min_local_scn = *local_scn;

    cm_spin_lock(&sess->sess_lock, NULL);

    if (sess->is_tse && (sess->total_cursor_num > 0 || sess->total_cursor_num_stack > 0)) {
        if (!CT_INVALID_SCN(knl_sess->query_scn)) {
            min_local_scn = MIN(knl_sess->query_scn, min_local_scn);
        }
    } else if (sess->active_stmts_cnt > 0) {
        if (sess->type == SESSION_TYPE_JOB && knl_sess->temp_table_count > 0) {
            *local_scn = DB_CURR_SCN(knl_sess);
            cm_spin_unlock(&sess->sess_lock);
            return;
        }
        if (!CT_INVALID_SCN(knl_sess->query_scn)) {
            min_local_scn = MIN(knl_sess->query_scn, min_local_scn);
        }
    }

    for (uint32 i = 0; i < sess->stmts.count; i++) {
        stmt = (sql_stmt_t *)cm_list_get(&sess->stmts, i);
        CT_CONTINUE_IFTRUE(stmt->status == STMT_STATUS_FREE || stmt->status == STMT_STATUS_IDLE || stmt->is_explain);
        cm_spin_lock(&stmt->stmt_lock, NULL);
        if (stmt->status == STMT_STATUS_FREE || stmt->status == STMT_STATUS_IDLE || stmt->is_explain) {
            cm_spin_unlock(&stmt->stmt_lock);
            continue;
        }
 
        if (!CT_INVALID_SCN(stmt->query_scn)) {
            min_local_scn = MIN(stmt->query_scn, min_local_scn);
        }
        cm_spin_unlock(&stmt->stmt_lock);
    }
    cm_spin_unlock(&sess->sess_lock);

    *local_scn = min_local_scn;
}

static void get_min_local_scn(knl_session_t *session, knl_scn_t *scn)
{
    knl_scn_t min_scn = DB_CURR_SCN(session);
    knl_session_t *knl_sess = NULL;

    for (uint32 i = CT_SYS_SESSIONS; i < CT_MAX_SESSIONS; i++) {
        knl_sess = session->kernel->sessions[i];
        CT_CONTINUE_IFTRUE(knl_sess == NULL);

        get_session_min_local_scn(knl_sess, &min_scn);
    }

    *scn = min_scn;
}

void srv_set_min_scn(knl_handle_t sess)
{
    knl_scn_t min_local_scn;
    knl_session_t *knl_sess = (knl_session_t *)sess;

    get_min_local_scn(knl_sess, &min_local_scn);
    KNL_SET_SCN(&knl_sess->kernel->local_min_scn, min_local_scn);

    if (DB_IS_CLUSTER(knl_sess)) {
        min_local_scn = dtc_get_min_scn(min_local_scn);
    }

    {
        // console app or SHARDING without GTS
        KNL_SET_SCN(&knl_sess->kernel->min_scn, min_local_scn);
    }
}

bool32 srv_get_debug_info(uint32 session_id, debug_control_t **dbg_ctl, spinlock_t **dbg_ctl_lock)
{
    session_t *session = g_instance->session_pool.sessions[session_id];
    if (session == NULL || session->dbg_ctl == NULL) {
        return CT_FALSE;
    }
    *dbg_ctl = session->dbg_ctl;
    if (dbg_ctl_lock != NULL) {
        *dbg_ctl_lock = &session->dbg_ctl_lock;
    }
    return CT_TRUE;
}

status_t srv_alloc_dbg_ctl(uint32 brkpoint_count, uint32 callstack_depth, debug_control_t **dbg_ctl)
{
    errno_t rc_memzero;
    // brkpoint_count and callstack_depth has limited, not overflow
    uint32 total_size = CM_ALIGN8(sizeof(debug_control_t) + brkpoint_count * sizeof(dbg_break_info_t) +
        callstack_depth * sizeof(dbg_callstack_info_t));

    *dbg_ctl = (debug_control_t *)malloc(total_size);
    if (*dbg_ctl == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint32)sizeof(debug_control_t), "create debug control");
        return CT_ERROR;
    }
    rc_memzero = memset_s(*dbg_ctl, total_size, 0, total_size);
    if (rc_memzero != EOK) {
        CM_FREE_PTR(*dbg_ctl);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, rc_memzero);
        return CT_ERROR;
    }
    // if the session is debug session, we need make brk_info and callstack_info pointer to the malloced memory
    if (brkpoint_count != 0) {
        (*dbg_ctl)->brk_info = (dbg_break_info_t *)((char *)(*dbg_ctl) + sizeof(debug_control_t));
        (*dbg_ctl)->callstack_info = (dbg_callstack_info_t *)((char *)(*dbg_ctl) + sizeof(debug_control_t) +
            brkpoint_count * sizeof(dbg_break_info_t));
    }
    return CT_SUCCESS;
}

void srv_free_dbg_ctl(session_t *session)
{
    if (session->dbg_ctl != NULL) {
        if (session->dbg_ctl->type == DEBUG_SESSION) {
            debug_control_t *target_ctl = NULL;
            if ((srv_get_debug_info(session->dbg_ctl->target_id, &target_ctl, NULL))) {
                target_ctl->brk_info = NULL;
                target_ctl->callstack_info = NULL;
                target_ctl->debug_lock = NULL;
                target_ctl->debug_id = CT_INVALID_ID32;
                target_ctl->curr_count = target_ctl->timeout;
                target_ctl->is_attached = CT_FALSE;
            }
        }
        CM_FREE_PTR(session->dbg_ctl);
    }
}

void srv_destory_session()
{
    session_t *session = NULL;
    uint32 i;

    for (i = g_instance->kernel.reserved_sessions; i < g_instance->session_pool.hwm; i++) {
        session = g_instance->session_pool.sessions[i];
        if (session != NULL) {
            knl_destroy_session(&g_instance->kernel, i);
            if (session->type == SESSION_TYPE_EMERG) {
                CM_FREE_PTR(session->stack);
            }
            CM_FREE_PTR(session);
            g_instance->session_pool.sessions[i] = NULL;
        }
    }

    for (i = 0; i < g_instance->rm_pool.page_count; i++) {
        CM_FREE_PTR(g_instance->rm_pool.pages[i]);
    }

    for (uint32 page_id = 0; page_id < g_instance->stat_pool.page_count; page_id++) {
        CM_FREE_PTR(g_instance->stat_pool.pages[page_id]);
    }

    (void)epoll_close(g_instance->session_pool.epollfd);
}


typedef struct st_sess_buff_assist {
    uint32 stack_size;
    uint32 plog_size;
    uint32 buf_size;
    uint32 update_buf_size;
    uint32 lex_size;
} sess_buff_assist_t;

static status_t srv_get_sess_buff_len(sess_buff_assist_t *assist)
{
    assist->stack_size = g_instance->attr.stack_size;
    assist->buf_size = sizeof(cm_stack_t);

    if (CT_MAX_UINT32 - assist->buf_size < assist->stack_size) {
        return CT_ERROR;
    }
    assist->buf_size += assist->stack_size;

    assist->plog_size = g_instance->kernel.attr.page_size * CT_PLOG_PAGES;
    if (CT_MAX_UINT32 - assist->buf_size < assist->plog_size) {
        return CT_ERROR;
    }

    assist->buf_size += assist->plog_size;

    assist->update_buf_size = knl_get_update_info_size(&g_instance->kernel.attr);
    if (CT_MAX_UINT32 - assist->buf_size < assist->update_buf_size) {
        return CT_ERROR;
    }
    assist->buf_size += assist->update_buf_size;

    assist->lex_size = sizeof(lex_t);
    if (CT_MAX_UINT32 - assist->buf_size < assist->lex_size) {
        return CT_ERROR;
    }
    assist->buf_size += assist->lex_size;
    return CT_SUCCESS;
}

static status_t srv_alloc_resv_sess_core(session_t *session, char *buf, sess_buff_assist_t *assist)
{
    cm_stack_t *stack = NULL;
    stack = (cm_stack_t *)buf;
    uint32 sid = session->knl_session.id;
    char *stack_buf = buf + sizeof(cm_stack_t);
    char *plog_buf = stack_buf + assist->stack_size;
    char *update_buf = plog_buf + assist->plog_size;
    char *lex_buf = update_buf + assist->update_buf_size;
    cm_stack_init(stack, stack_buf, assist->stack_size);
    session->stack = stack;
    session->is_free = CT_FALSE;
    session->knl_session.uid = 0;
    session->logon_time = g_timer()->now;
    session->interval_time = cm_monotonic_now();
    session->type = SESSION_TYPE_BACKGROUND;
    session->lex = (lex_t *)lex_buf;
    PRTS_RETURN_IFERR(snprintf_s(session->db_user, CT_NAME_BUFFER_SIZE, CT_NAME_BUFFER_SIZE - 1, "%s", "SYS"));
    cm_str2text(session->db_user, &session->curr_user);

    MEMS_RETURN_IFERR(strncpy_s(session->curr_schema, CT_NAME_BUFFER_SIZE, session->db_user, strlen(session->db_user)));

    session->curr_schema_id = 0;
    knl_init_session(&g_instance->kernel, &session->knl_session, 0, plog_buf, stack);
    session->knl_session.id = sid;
    knl_init_sess_ex(&g_instance->kernel, &session->knl_session);

    session->knl_session.update_info.columns = (uint16 *)update_buf; // column_count * sizeof(uint16)
    // column_count * sizeof(uint16)
    session->knl_session.update_info.offsets =
        (uint16 *)(session->knl_session.update_info.columns + g_instance->kernel.attr.max_column_count);
    // column_count * sizeof(uint16)
    session->knl_session.update_info.lens =
        (uint16 *)(session->knl_session.update_info.offsets + g_instance->kernel.attr.max_column_count);
    session->knl_session.update_info.data =
        (char *)(session->knl_session.update_info.lens + g_instance->kernel.attr.max_column_count); // page size
    return CT_SUCCESS;
}

status_t srv_alloc_reserved_session(uint32 *sid)
{
    session_t *session = NULL;
    char *buf = NULL;

    sess_buff_assist_t assist;
    CT_RETURN_IFERR(srv_new_session(NULL, &session));

    *sid = session->knl_session.id;

    if (srv_get_sess_buff_len(&assist) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_NUM_OVERFLOW);
        return CT_ERROR;
    }

    buf = (char *)malloc(assist.buf_size);
    if (buf == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)assist.buf_size, "reserved sessions");
        return CT_ERROR;
    }

    errno_t ret = memset_s(buf, assist.buf_size, 0, assist.buf_size);
    if (ret != EOK) {
        CM_FREE_PTR(buf);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    return srv_alloc_resv_sess_core(session, buf, &assist);
}

#ifdef __cplusplus
}
#endif
