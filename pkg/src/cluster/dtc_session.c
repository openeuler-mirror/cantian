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
 * dtc_session.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_session.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_cluster_module.h"
#include "cm_date.h"
#include "dtc_session.h"
#include "dtc_context.h"
#include "srv_instance.h"
#include "dml_executor.h"

// sql session wait fetch timeout.
// clean some stmt info.
// reference from srv_deinit_session.
void dtc_release_session_res(session_t *session)
{
    cm_spin_lock(&session->sess_lock, NULL);
    uint32 i;
    sql_stmt_t *sql_stmt = NULL;
    for (i = 0; i < session->stmts.count; i++) {
        sql_stmt = (sql_stmt_t *)cm_list_get(&session->stmts, i);
            sql_free_stmt(sql_stmt);
        }

    session->current_stmt = NULL;
    session->unnamed_stmt = NULL;
    session->current_sql.str = NULL;
    session->current_sql.len = 0;
    cm_reset_list(&session->stmts);
    session->active_stmts_cnt = 0;
    cm_spin_unlock(&session->sess_lock);
}

bool32 dtc_check_session_timeout(void)
{
    uint32 i;
    date_t now = cm_monotonic_now();
    session_t *session = NULL;
    dtc_session_pool_t *pool = &g_dtc->session_pool;
    for (i = 0; i < DTC_SQL_SESSION_NUM; i++) {
        session = pool->sessions[i];
        if ((session->gdv_last_time + (g_dtc->profile.gdv_sql_sess_tmout * MICROSECS_PER_SECOND)) < now) { // timeout
            CT_LOG_DEBUG_WAR("GDV sql_session is time out. Clean session res.");
            session->is_free = CT_TRUE;
            dtc_release_session_res(session);
            biqueue_add_tail(&pool->idle_sessions, QUEUE_NODE_OF(session));
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

session_t *dtc_alloc_sql_session()
{
    session_t *session = NULL;
    biqueue_node_t *node = NULL;
    dtc_session_pool_t *pool = &g_dtc->session_pool;

    cm_spin_lock(&pool->lock, NULL);
    if (biqueue_empty(&pool->idle_sessions)) { // if queue is empty, need to check whether some session is timeout.
        if (dtc_check_session_timeout() == CT_FALSE) {
            cm_spin_unlock(&pool->lock);
            CT_LOG_RUN_ERR("Alloc dtc sql session failed.");
            return NULL;
        }
    }
    node = biqueue_del_head(&pool->idle_sessions);
    session = OBJECT_OF(session_t, node);
    session->is_free = CT_FALSE;
    cm_spin_unlock(&pool->lock);
    (void)cm_atomic_inc(&g_dtc->session_pool.service_count);
    return session;
}

void dtc_free_sql_session(session_t *session)
{
    dtc_session_pool_t *pool = &g_dtc->session_pool;

    session->is_free = CT_TRUE;

    cm_spin_lock(&pool->lock, NULL);
    biqueue_add_tail(&pool->idle_sessions, QUEUE_NODE_OF(session));
    cm_spin_unlock(&pool->lock);
}

status_t dtc_init_sql_sessions(void)
{
    uint32 i, id, loop;
    session_t *session = NULL;

    g_dtc->session_pool.lock = 0;
    g_dtc->session_pool.max_sessions = DTC_SQL_SESSION_NUM;
    for (i = 0; i < g_dtc->session_pool.max_sessions; i++) {
        if (srv_alloc_reserved_session(&id) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("srv_alloc_reserved_session failed.");
            return CT_ERROR;
        }
        g_instance->session_pool.sessions[id]->type = SESSION_TYPE_DTC;
        g_instance->session_pool.sessions[id]->knl_session.match_cond = sql_match_cond;
        g_dtc->session_pool.sessions[i] = g_instance->session_pool.sessions[id];
        g_dtc->session_pool.sessions[i]->gdv_last_time = 0;
    }
    biqueue_init(&g_dtc->session_pool.idle_sessions);
    g_dtc->session_pool.service_count = 0;

    for (loop = 0; loop < g_dtc->session_pool.max_sessions; ++loop) {
        session = g_dtc->session_pool.sessions[loop];
        if (vmp_create(&g_instance->sga.vma, 0, &session->vmp) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("vmp_create failed.");
            return CT_ERROR;
        }
        session->is_free = CT_TRUE;
        biqueue_add_tail(&g_dtc->session_pool.idle_sessions, QUEUE_NODE_OF(session));
    }

    return CT_SUCCESS;
}

status_t dtc_init_kernel_sessions(void)
{
    uint32 loop;
    knl_session_t *session;

    for (loop = 0; loop < g_dtc->profile.task_num + g_dtc->profile.channel_num; loop++) {
        if (g_knl_callback.alloc_knl_session(CT_TRUE, (knl_handle_t *)&session) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("alloc_knl_session failed.");
            return CT_ERROR;
        }

        session->dtc_session_type = DTC_WORKER;
        g_dtc->session_pool.kernel_sessions[loop] = session;
    }

    return CT_SUCCESS;
}

status_t dtc_init_proc_sessions(void)
{
    if (dtc_init_sql_sessions() != CT_SUCCESS) {
        CT_LOG_RUN_ERR("dtc_init_sql_sessions failed.");
        return CT_ERROR;
    }

    if (dtc_init_kernel_sessions() != CT_SUCCESS) {
        CT_LOG_RUN_ERR("dtc_init_kernel_sessions failed.");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}
