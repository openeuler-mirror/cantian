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
 * ctsql_resource.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/ctsql_resource.c
 *
 * -------------------------------------------------------------------------
 */

#include "ctsql_resource.h"
#include "srv_instance.h"

rsrc_attr_map_t *rsrc_get_session_rsrc_attr(session_t *session)
{
    if (session->rsrc_attr_id == CT_INVALID_INT32) {
        return NULL;
    }
    return (rsrc_attr_map_t *)cm_galist_get(session->rsrc_group->attr_maps, (uint32)session->rsrc_attr_id);
}

static atomic32_t rsrc_ref_count_inc(session_t *session)
{
    CM_ASSERT(session->rsrc_group != NULL);

    rsrc_attr_map_t *rsrc_map = rsrc_get_session_rsrc_attr(session);
    if (rsrc_map != NULL) {
        (void)cm_atomic32_inc(&rsrc_map->rsrc_monitor.ref_count);
    }

    return cm_atomic32_inc(&session->rsrc_group->rsrc_monitor.ref_count);
}

static atomic32_t rsrc_ref_count_dec(session_t *session)
{
    CM_ASSERT(session->rsrc_group != NULL);

    rsrc_attr_map_t *rsrc_map = rsrc_get_session_rsrc_attr(session);
    if (rsrc_map != NULL) {
        (void)cm_atomic32_dec(&rsrc_map->rsrc_monitor.ref_count);
    }

    return cm_atomic32_dec(&session->rsrc_group->rsrc_monitor.ref_count);
}

atomic32_t rsrc_active_sess_inc(session_t *session)
{
    CM_ASSERT(session->rsrc_group != NULL);

    rsrc_attr_map_t *rsrc_map = rsrc_get_session_rsrc_attr(session);
    if (rsrc_map != NULL) {
        (void)cm_atomic32_inc(&rsrc_map->rsrc_monitor.active_sess);
    }

    return cm_atomic32_inc(&session->rsrc_group->rsrc_monitor.active_sess);
}

atomic32_t rsrc_active_sess_dec(session_t *session)
{
    CM_ASSERT(session->rsrc_group != NULL);

    rsrc_attr_map_t *rsrc_map = rsrc_get_session_rsrc_attr(session);
    if (rsrc_map != NULL) {
        (void)cm_atomic32_dec(&rsrc_map->rsrc_monitor.active_sess);
    }

    return cm_atomic32_dec(&session->rsrc_group->rsrc_monitor.active_sess);
}

void rsrc_cpu_time_add(session_t *session, uint64 value)
{
    CM_ASSERT(session->rsrc_group != NULL);

    rsrc_attr_map_t *rsrc_map = rsrc_get_session_rsrc_attr(session);
    if (rsrc_map != NULL) {
        (void)cm_atomic_add(&rsrc_map->rsrc_monitor.cpu_time, (int64)value);
    }

    (void)cm_atomic_add(&session->rsrc_group->rsrc_monitor.cpu_time, (int64)value);
}

static void rsrc_io_waittime_add(session_t *session, uint64 value)
{
    CM_ASSERT(session->rsrc_group != NULL);

    rsrc_attr_map_t *rsrc_map = rsrc_get_session_rsrc_attr(session);
    if (rsrc_map != NULL) {
        (void)cm_atomic_add(&rsrc_map->rsrc_monitor.io_wait_time, (int64)value);
    }

    (void)cm_atomic_add(&session->rsrc_group->rsrc_monitor.io_wait_time, (int64)value);
}

static void rsrc_io_waits_inc(session_t *session)
{
    CM_ASSERT(session->rsrc_group != NULL);

    rsrc_attr_map_t *rsrc_map = rsrc_get_session_rsrc_attr(session);
    if (rsrc_map != NULL) {
        (void)cm_atomic_inc(&rsrc_map->rsrc_monitor.io_waits);
    }

    (void)cm_atomic_inc(&session->rsrc_group->rsrc_monitor.io_waits);
}

void rsrc_queue_length_inc(session_t *session)
{
    CM_ASSERT(session->rsrc_group != NULL);

    rsrc_attr_map_t *rsrc_map = rsrc_get_session_rsrc_attr(session);
    if (rsrc_map != NULL) {
        rsrc_map->rsrc_monitor.que_length++;
    }
    session->rsrc_group->rsrc_monitor.que_length++;
}

void rsrc_queue_length_dec(session_t *session)
{
    CM_ASSERT(session->rsrc_group != NULL);

    rsrc_attr_map_t *rsrc_map = rsrc_get_session_rsrc_attr(session);
    if (rsrc_map != NULL) {
        rsrc_map->rsrc_monitor.que_length--;
    }
    session->rsrc_group->rsrc_monitor.que_length--;
}

static void rsrc_queue_time_add(session_t *session, uint64 value)
{
    CM_ASSERT(session->rsrc_group != NULL);

    rsrc_attr_map_t *rsrc_map = rsrc_get_session_rsrc_attr(session);
    if (rsrc_map != NULL) {
        rsrc_map->rsrc_monitor.sess_queued_time += value;
    }
    session->rsrc_group->rsrc_monitor.sess_queued_time += value;
}

void rsrc_queue_total_inc(session_t *session)
{
    CM_ASSERT(session->rsrc_group != NULL);

    rsrc_attr_map_t *rsrc_map = rsrc_get_session_rsrc_attr(session);
    if (rsrc_map != NULL) {
        rsrc_map->rsrc_monitor.sess_total_queues++;
    }
    session->rsrc_group->rsrc_monitor.sess_total_queues++;
}

static void rsrc_queue_timeouts_inc(session_t *session)
{
    CM_ASSERT(session->rsrc_group != NULL);

    rsrc_attr_map_t *rsrc_map = rsrc_get_session_rsrc_attr(session);
    if (rsrc_map != NULL) {
        rsrc_map->rsrc_monitor.sess_queue_timeouts++;
    }
    session->rsrc_group->rsrc_monitor.sess_queue_timeouts++;
}

static void rsrc_sess_limit_hit_inc(session_t *session)
{
    CM_ASSERT(session->rsrc_group != NULL);

    rsrc_attr_map_t *rsrc_map = rsrc_get_session_rsrc_attr(session);
    if (rsrc_map != NULL) {
        rsrc_map->rsrc_monitor.session_limit_hit++;
    }
    session->rsrc_group->rsrc_monitor.session_limit_hit++;
}

static void rsrc_disk_reads_inc(session_t *session)
{
    CM_ASSERT(session->rsrc_group != NULL);

    rsrc_attr_map_t *rsrc_map = rsrc_get_session_rsrc_attr(session);
    if (rsrc_map != NULL) {
        (void)cm_atomic_inc(&rsrc_map->rsrc_monitor.io_stat.disk_reads);
    }

    (void)cm_atomic_inc(&session->rsrc_group->rsrc_monitor.io_stat.disk_reads);
}

static void rsrc_commits_inc(session_t *session)
{
    CM_ASSERT(session->rsrc_group != NULL);

    rsrc_attr_map_t *rsrc_map = rsrc_get_session_rsrc_attr(session);
    if (rsrc_map != NULL) {
        (void)cm_atomic_inc(&rsrc_map->rsrc_monitor.io_stat.commits);
    }

    (void)cm_atomic_inc(&session->rsrc_group->rsrc_monitor.io_stat.commits);
}

static status_t rsrc_alloc_group(rsrc_plan_t *plan, rsrc_group_t **group)
{
    errno_t errcode;
    galist_t *attr_maps = NULL;

    if (mctx_alloc(plan->memory, sizeof(rsrc_group_t), (void **)group) != CT_SUCCESS) {
        return CT_ERROR;
    }
    CM_ASSERT(*group != NULL);
    errcode = memset_sp(*group, sizeof(rsrc_group_t), 0, sizeof(rsrc_group_t));
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CT_ERROR;
    }
    if (mctx_alloc(plan->memory, sizeof(galist_t), (void **)&attr_maps) != CT_SUCCESS) {
        return CT_ERROR;
    }
    cm_galist_init(attr_maps, plan->memory, (ga_alloc_func_t)mctx_alloc);
    biqueue_init(&(*group)->sess_que);
    (*group)->rsrc_monitor.que_length = 0;
    (*group)->plan = plan;
    (*group)->attr_maps = attr_maps;
    (*group)->max_cpus = 0;
    (*group)->max_sessions = CT_MAX_UINT32;
    (*group)->max_active_sess = CT_MAX_UINT32;
    (*group)->max_queue_time = CT_MAX_UINT32;
    (*group)->max_est_exec_time = CT_MAX_UINT32;
    (*group)->max_temp_pool = CT_MAX_UINT32;
    (*group)->max_commit_ps = CT_MAX_UINT32;
    (*group)->max_iops = CT_MAX_UINT32;
    return CT_SUCCESS;
}

static status_t rsrc_alloc_plan(rsrc_plan_t **plan)
{
    errno_t errcode;
    dc_context_t *dc_ctx = &g_instance->kernel.dc_ctx;
    memory_context_t *memory = NULL;

    if (dc_create_memory_context(dc_ctx, &memory) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (mctx_alloc(memory, sizeof(rsrc_plan_t), (void **)plan) != CT_SUCCESS) {
        mctx_destroy(memory);
        return CT_ERROR;
    }
    CM_ASSERT(*plan != NULL);
    errcode = memset_sp(*plan, sizeof(rsrc_plan_t), 0, sizeof(rsrc_plan_t));
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        mctx_destroy(memory);
        return CT_ERROR;
    }
    (*plan)->memory = memory;
    return CT_SUCCESS;
}

static inline void rsrc_destory_plan(rsrc_plan_t *plan)
{
    mctx_destroy(plan->memory);
}

static cpu_set_t g_zero_cpuset = { 0 };
static status_t rsrc_proc_bind_cpu(cpu_set_t *cpuset)
{
    if (rsrc_cpuset_is_equal(cpuset, &g_zero_cpuset)) {
        return CT_SUCCESS;
    }

#ifdef WIN32
    HANDLE hProc = GetCurrentProcess();
    if (SetProcessAffinityMask(hProc, *cpuset) == 0) {
        CT_THROW_ERROR(ERR_PROC_BIND_CPU, cm_get_os_error());
        return CT_ERROR;
    }
    return CT_SUCCESS;

#else
    if (sched_setaffinity(cm_sys_pid(), sizeof(cpu_set_t), cpuset) != 0) {
        CT_THROW_ERROR(ERR_PROC_BIND_CPU, cm_get_os_error());
        return CT_ERROR;
    }
    return CT_SUCCESS;
#endif
}

status_t rsrc_thread_bind_cpu(thread_t *thread, cpu_set_t *cpuset)
{
    if (rsrc_cpuset_is_equal(cpuset, &g_zero_cpuset)) {
        return CT_SUCCESS;
    }
#ifdef WIN32
    if (SetThreadAffinityMask(thread->handle, *cpuset) == 0) {
        CT_THROW_ERROR(ERR_PROC_BIND_CPU, cm_get_os_error());
        return CT_ERROR;
    }
    return CT_SUCCESS;
#else
    int32 ret = pthread_setaffinity_np(thread->id, sizeof(cpu_set_t), cpuset);
    if (ret != 0) {
        CT_THROW_ERROR(ERR_PROC_BIND_CPU, ret);
        return CT_ERROR;
    }
    return CT_SUCCESS;
#endif
}

#ifdef WIN32
#define CPU_ZERO(cpuset) (*(cpuset) = 0)
#define CPU_SET(i, cpuset) (*(cpuset) |= (1 << (i)))
#define CPU_ISSET(i, cpuset) ((*(cpuset) & (1 << (i))) != 0)
#endif


static uint32 rsrc_get_cpu_node(rsrc_plan_t *plan, uint32 curr_group, uint32 cpu_low, uint32 cpu_high, uint8 *cpu_refs,
    uint8 *group_refs)
{
    uint32 cpu_id, group_id, cpu_node;
    uint32 cpu_ref, group_ref, temp_ref;
    rsrc_group_t *group = NULL;
    rsrc_group_t *rsrc_group = plan->groups[curr_group];

    cpu_node = cpu_low;
    cpu_ref = CT_MAX_UINT32;
    group_ref = CT_MAX_UINT32;

    for (cpu_id = cpu_low; cpu_id <= cpu_high; cpu_id++) {
        if (CPU_ISSET(cpu_id, &rsrc_group->cpuset) || cpu_ref < cpu_refs[cpu_id]) {
            continue;
        }
        if (cpu_ref > (uint32)cpu_refs[cpu_id]) {
            cpu_ref = cpu_refs[cpu_id];
            cpu_node = cpu_id;
            group_ref = CT_MAX_UINT32;
        }
        if (group_ref == 0) {
            continue;
        }
        temp_ref = 0;
        for (group_id = 0; group_id < curr_group; group_id++) {
            group = plan->groups[group_id];
            if (CPU_ISSET(cpu_id, &group->cpuset)) {
                temp_ref += group_refs[group_id];
            }
        }
        if (group_ref > temp_ref) {
            group_ref = temp_ref;
            cpu_node = cpu_id;
        }
        if (cpu_ref == 0 && group_ref == 0) {
            break;
        }
    }

    for (group_id = 0; group_id < curr_group; group_id++) {
        group = plan->groups[group_id];
        if (CPU_ISSET(cpu_node, &group->cpuset)) {
            group_refs[group_id]++;
        }
    }
    cpu_refs[cpu_node]++;
    return cpu_node;
}

status_t rsrc_calc_cpuset(uint32 cpu_low, uint32 cpu_high, rsrc_plan_t *plan)
{
    uint32 i, j, node;
    cpu_set_t cpuset;
    uint32 cpu_count = cpu_high - cpu_low + 1;
    rsrc_group_t *group = NULL;

    CPU_ZERO(&cpuset);
    for (i = cpu_low; i <= cpu_high; i++) {
        CPU_SET(i, &cpuset);
    }
    GET_RSRC_MGR->cpuset = cpuset;

    if (rsrc_proc_bind_cpu(&cpuset) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (plan == NULL || !plan->is_valid) {
        return CT_SUCCESS;
    }

    if (cpu_high >= CT_MAX_CPUS) {
        CT_THROW_ERROR(ERR_TOO_MANY_CPUS, CT_MAX_CPUS);
        return CT_ERROR;
    }

    uint8 cpu_refs[CT_MAX_CPUS] = { 0 };
    uint8 group_refs[CT_MAX_PLAN_GROUPS];

    for (i = 0; i < plan->group_count; ++i) {
        group = plan->groups[i];
        if (group->max_cpus == cpu_count || group->max_cpus == 0) {
            group->cpuset = cpuset;
        } else {
            CPU_ZERO(&group->cpuset);
            (void)memset_sp(group_refs, sizeof(group_refs), 0, sizeof(group_refs));
            for (j = 0; j < group->max_cpus; j++) {
                node = rsrc_get_cpu_node(plan, i, cpu_low, cpu_high, cpu_refs, group_refs);
                CPU_SET(node, &group->cpuset);
            }
        }
    }
    return CT_SUCCESS;
}

bool32 rsrc_match_group_attr_id(rsrc_group_t *rsrc_group, text_t *key, text_t *value, int *attr_map_id)
{
    rsrc_attr_map_t *rsrc_map = NULL;

    for (uint32 i = 0; i < rsrc_group->attr_maps->count; i++) {
        rsrc_map = (rsrc_attr_map_t *)cm_galist_get(rsrc_group->attr_maps, i);
        if (cm_text_equal_ins(&rsrc_map->key, key) && cm_text_equal_ins(&rsrc_map->value, value)) {
            *attr_map_id = i;
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

static inline status_t rsrc_copy_text(memory_context_t *ctx, text_t *src, text_t *dst)
{
    if (src->len == 0) {
        dst->len = 0;
        return CT_SUCCESS;
    }

    if (mctx_alloc(ctx, src->len, (void **)&dst->str) != CT_SUCCESS) {
        return CT_ERROR;
    }

    MEMS_RETURN_IFERR(memcpy_s(dst->str, src->len, src->str, src->len));
    dst->len = src->len;
    return CT_SUCCESS;
}

status_t rsrc_attach_group_get_attr(knl_handle_t session, rsrc_plan_t *plan, text_t *key, text_t *value)
{
    session_t *sess = (session_t *)session;
    rsrc_group_t *group = NULL;
    bool32 found = CT_FALSE;
    int32 attr_map_id = CT_INVALID_INT32;

    for (uint32 i = 1; i < plan->group_count; i++) {
        group = plan->groups[i];
        if (rsrc_match_group_attr_id(group, key, value, &attr_map_id)) {
            sess->rsrc_group = group;

            // record attr_map_id when plan type is tenant
            if (plan->type == PLAN_TYPE_TENANT) {
                sess->rsrc_attr_id = attr_map_id;
            } else {
                sess->rsrc_attr_id = CT_INVALID_INT32;
            }

            if ((uint32)rsrc_ref_count_inc(sess) > group->max_sessions) {
                (void)rsrc_ref_count_dec(sess);
                (void)rsrc_sess_limit_hit_inc(sess);
                CT_THROW_ERROR(ERR_EXCEED_CGROUP_SESSIONS, group->knl_group.name, group->max_sessions);
                return CT_ERROR;
            }
            found = CT_TRUE;
            break;
        }
    }
    if (!found) { // default group: OTHER GROUP
        group = plan->groups[0];
        sess->rsrc_group = group;
        sess->rsrc_attr_id = CT_INVALID_INT32;
        (void)rsrc_ref_count_inc(sess);
    }

    return CT_SUCCESS;
}

status_t rsrc_attach_group(knl_handle_t session, rsrc_plan_t *plan)
{
    session_t *sess = (session_t *)session;
    text_t key, value;

    /* resource plan not enabled */
    if (plan == NULL || !plan->is_valid) {
        knl_session_t *knl_se = &sess->knl_session;
        knl_se->temp_pool = &knl_se->kernel->temp_pool[knl_se->id % knl_se->kernel->temp_ctx_count];
        knl_se->temp_mtrl->pool = knl_se->temp_pool;
        return CT_SUCCESS;
    }

    // user not login, no resource control
    if (sess->db_user[0] == '\0') {
        sess->rsrc_group = NULL;
        return CT_SUCCESS;
    }
    (void)cm_atomic32_inc(&plan->ref_count);

    if (plan->type == PLAN_TYPE_USER) { // match by db user
        cm_str2text((char *)"db_user", &key);
        cm_str2text(sess->db_user, &value);
#ifdef Z_SHARDING
        if (IS_DATANODE && IS_COORD_CONN(sess) && sess->curr_user2[0] != '\0') {
            // for datanode use curr_user2
            cm_str2text(sess->curr_user2, &value);
        }
#endif // Z_SHARDING
    } else { // match by db tenant
        cm_str2text((char *)"tenant", &key);
        cm_str2text(sess->curr_tenant, &value);
    }

    CT_RETURN_IFERR(rsrc_attach_group_get_attr(sess, plan, &key, &value));
    sess->knl_session.temp_pool = sess->rsrc_group->temp_pool;
    sess->knl_session.temp_mtrl->pool = sess->rsrc_group->temp_pool;
    CT_LOG_DEBUG_INF("session [user:%s] attached to control group[%s], current sessions[%u]", sess->curr_schema,
        sess->rsrc_group->knl_group.name, sess->rsrc_group->rsrc_monitor.ref_count);

    // rebind agent thread cpuset
    if (memcmp(&sess->agent->cpuset, &sess->rsrc_group->cpuset, sizeof(cpu_set_t)) != 0) {
        (void)rsrc_thread_bind_cpu(&sess->agent->thread, &sess->rsrc_group->cpuset);
        sess->agent->cpuset = sess->rsrc_group->cpuset;
    }
    return CT_SUCCESS;
}

void rsrc_detach_group(knl_handle_t session)
{
    session_t *sess = (session_t *)session;
    rsrc_group_t *rsrc_group = sess->rsrc_group;

    if (rsrc_group != NULL) {
        (void)rsrc_ref_count_dec(sess);
        (void)cm_atomic32_dec(&rsrc_group->plan->ref_count);
        CT_LOG_DEBUG_INF("session [db_user:%s] detached from control group[%s], current sessions[%u]", sess->db_user,
            rsrc_group->knl_group.name, rsrc_group->rsrc_monitor.ref_count);
    }
    sess->rsrc_group = NULL;
    sess->rsrc_attr_id = CT_INVALID_INT32;
}

static void rsrc_session_detach_agent(session_t *session)
{
    agent_t *agent = session->agent;
    agent->session = NULL;
    session->agent = NULL;
    session->stack = NULL;
    KNL_SESSION_CLEAR_THREADID(&session->knl_session);
    /* status might still be ACTIVE while being detached from agent, so need to reset */
    session->knl_session.status = SESSION_INACTIVE;
}

static void rsrc_check_group_queued_sessions(rsrc_group_t *rsrc_group, agent_t *agent)
{
    int64 queued_time;
    biqueue_node_t *node = NULL;
    biqueue_node_t *first = NULL;
    biqueue_node_t *last = NULL;
    session_t *session = NULL;

    cm_reset_error();

    cm_spin_lock(&rsrc_group->lock, NULL);
    first = biqueue_first(&rsrc_group->sess_que);
    last = biqueue_end(&rsrc_group->sess_que);

    node = first;

    while (node != last) {
        session = OBJECT_OF(session_t, node);
        queued_time = g_timer()->now - session->queued_time;

        /* check if session was killed */
        if (session->knl_session.killed) {
            // killed session will processed in reactor
            biqueue_del_node(node);
            rsrc_queue_length_dec(session);
            rsrc_queue_time_add(session, (uint64)queued_time);
            session->queued_time = 0;
            cm_spin_unlock(&rsrc_group->lock);
            return;
        }

        /* bind session to agent */
        srv_bind_sess_agent(session, agent);
        cs_init_packet(&agent->recv_pack, CT_FALSE);
        cs_init_packet(&agent->send_pack, CT_FALSE);

        /* check if session was canceled */
        if (session->knl_session.canceled) {
            biqueue_del_node(node);
            rsrc_queue_length_dec(session);
            rsrc_queue_time_add(session, (uint64)queued_time);
            session->queued_time = 0;
            cm_spin_unlock(&rsrc_group->lock);
            CT_THROW_ERROR(ERR_OPERATION_CANCELED);

            /* read packet and get serial number */
            if (srv_read_packet(session) == CT_SUCCESS) {
                (void)srv_return_error(session);
                if (reactor_set_oneshot(session) != CT_SUCCESS) {
                    CT_LOG_RUN_ERR("[agent] set oneshot flag of socket failed, session %d, reactor %lu, os error %d",
                        session->knl_session.id, session->reactor->thread.id, cm_get_sock_error());
                }
            } else {
                srv_mark_sess_killed(session, CT_TRUE, session->knl_session.serial_id);
            }
            rsrc_session_detach_agent(session);
            return;
        }

        /* check if maximum wait time exceeded */
        if ((uint32)(queued_time / MICROSECS_PER_SECOND) >= rsrc_group->max_queue_time) {
            biqueue_del_node(node);
            rsrc_queue_length_dec(session);
            session->queued_time = 0;
            rsrc_queue_timeouts_inc(session);
            rsrc_queue_time_add(session, (uint64)queued_time);
            cm_spin_unlock(&rsrc_group->lock);
            CT_THROW_ERROR(ERR_EXCEED_MAX_WAIT_TIME, rsrc_group->knl_group.name, rsrc_group->max_queue_time);

            /* read packet and get serial number */
            if (srv_read_packet(session) == CT_SUCCESS) {
                (void)srv_return_error(session);
                if (reactor_set_oneshot(session) != CT_SUCCESS) {
                    CT_LOG_RUN_ERR("[agent] set oneshot flag of socket failed, session %d, reactor %lu, os error %d",
                        session->knl_session.id, session->reactor->thread.id, cm_get_sock_error());
                }
            } else {
                CT_LOG_RUN_WAR("read package failed, the session will be killed, sid=[%d], error code=[%d].",
                    session->knl_session.id, cm_get_error_code());
                srv_mark_sess_killed(session, CT_TRUE, session->knl_session.serial_id);
            }
            rsrc_session_detach_agent(session);
            return;
        }
        rsrc_session_detach_agent(session);
        node = node->next;
    }
    cm_spin_unlock(&rsrc_group->lock);
}

static void rsrc_check_queued_sessions(rsrc_plan_t *plan, agent_t *agent)
{
    rsrc_group_t *rsrc_group = NULL;
    for (uint32 i = 0; i < plan->group_count; i++) {
        rsrc_group = plan->groups[i];
        if (biqueue_empty(&rsrc_group->sess_que)) {
            continue;
        }
        rsrc_check_group_queued_sessions(rsrc_group, agent);
    }
}

#define IOPS_CALC_INTERVAL 10 /* unit: second */

static void rsrc_calc_plan_iops(rsrc_plan_t *rsrc_plan)
{
    io_stat_t *snapshot = NULL;
    rsrc_group_t *rsrc_group = NULL;
    int64 read_diff, commit_diff;
    double time_diff;

    for (uint32 i = 0; i < rsrc_plan->group_count; i++) {
        rsrc_group = rsrc_plan->groups[i];
        if (rsrc_group->io_snapshot[0].snap_time == 0) {
            rsrc_group->rsrc_monitor.io_stat.snap_time = g_timer()->now;
            rsrc_group->io_snapshot[0] = rsrc_group->rsrc_monitor.io_stat;
            continue;
        }
        snapshot = (rsrc_group->io_snapshot[1].snap_time != 0) ? &rsrc_group->io_snapshot[1] : &rsrc_group->io_snapshot[0];

        time_diff = (double)(g_timer()->now - snapshot->snap_time) / MICROSECS_PER_SECOND;
        if (time_diff < VAR_DOUBLE_EPSILON) {
            continue;
        }
        read_diff = rsrc_group->rsrc_monitor.io_stat.disk_reads - snapshot->disk_reads;
        rsrc_group->read_iops = (int32)(read_diff / time_diff);

        commit_diff = rsrc_group->rsrc_monitor.io_stat.commits - snapshot->commits;
        rsrc_group->commit_ps = (int32)(commit_diff / time_diff);

        /* snapshot interval: 10 second */
        if (time_diff >= IOPS_CALC_INTERVAL) {
            rsrc_group->io_snapshot[1] = rsrc_group->io_snapshot[0];
            rsrc_group->io_snapshot[0] = rsrc_group->rsrc_monitor.io_stat;
            rsrc_group->io_snapshot[0].snap_time = g_timer()->now;
        }
    }
}

static void rsrc_process_queued_sessions(rsrc_mgr_t *rsrc_mgr, rsrc_plan_t *rsrc_plan, agent_t *agent)
{
    for (;;) {
        if (cm_event_timedwait(&rsrc_mgr->event, 100) == CT_SUCCESS) {
            break;
        }
        if (rsrc_mgr->thread.closed) {
            return;
        }
        /* break to process queued sessions */
        if (!rsrc_plan->is_valid) {
            break;
        }
        rsrc_check_queued_sessions(rsrc_plan, agent);

        /* calc resource plan iops once per second */
        if (g_timer()->now - rsrc_plan->iops_time >= MICROSECS_PER_SECOND) {
            rsrc_calc_plan_iops(rsrc_plan);
            rsrc_plan->iops_time = g_timer()->now;
        }
    }

    // get idle agent
    status_t status;
    bool32 empty = CT_FALSE;
    biqueue_node_t *node = NULL;
    session_t *session = NULL;
    agent_t *idle_agent = NULL;
    rsrc_group_t *group = NULL;
    int64 queued_time;

    /* calc resource plan iops once per second */
    if (g_timer()->now - rsrc_plan->iops_time >= MICROSECS_PER_SECOND) {
        rsrc_calc_plan_iops(rsrc_plan);
        rsrc_plan->iops_time = g_timer()->now;
    }

    do {
        empty = CT_TRUE;
        for (uint32 i = 0; i < rsrc_plan->group_count; i++) {
            group = rsrc_plan->groups[i];
            if (biqueue_empty(&group->sess_que)) {
                continue;
            }
            if ((uint32)group->rsrc_monitor.active_sess >= group->max_active_sess && rsrc_plan->is_valid) {
                continue;
            }

            cm_spin_lock(&group->lock, NULL);
            node = biqueue_del_head(&group->sess_que);
            session = OBJECT_OF(session_t, node);
            rsrc_queue_length_dec(session);
            cm_spin_unlock(&group->lock);

            /* attach agent nowait, to avoid deadloop waiting */
            status = srv_attach_agent(session, &idle_agent, CT_TRUE);
            if (status != CT_SUCCESS) {
                cm_spin_lock(&group->lock, NULL);
                biqueue_add_head(&group->sess_que, node);
                rsrc_queue_length_inc(session);
                cm_spin_unlock(&group->lock);
                cm_sleep(10);
                return;
            }
            (void)rsrc_active_sess_inc(session);
            session->is_active = CT_TRUE;
            queued_time = g_timer()->now - session->queued_time;
            session->queued_time = 0;
            session->stat.res_sess_queue_time += queued_time;
            rsrc_queue_time_add(session, (uint64)queued_time);
            empty = CT_FALSE;
            knl_end_session_waits(&session->knl_session);

            CT_LOG_DEBUG_INF("[resmgr] receive message from session %d, attached agent %lu", session->knl_session.id,
                agent->thread.id);
            cm_event_notify(&idle_agent->event);
        }
        if (empty) {
            cm_sleep(10);
            break;
        }
    } while (CT_TRUE);
}

static void rsrc_release_queued_sessions(rsrc_group_t *rsrc_group, agent_t *agent)
{
    biqueue_node_t *node = NULL;
    session_t *session = NULL;
    rsrc_attr_map_t *attr_map = NULL;

    while (!biqueue_empty(&rsrc_group->sess_que)) {
        node = biqueue_del_head(&rsrc_group->sess_que);
        session = OBJECT_OF(session_t, node);
        srv_bind_sess_agent(session, agent);
        cs_init_packet(&agent->recv_pack, CT_FALSE);
        cs_init_packet(&agent->send_pack, CT_FALSE);
        rsrc_detach_group(session);
        CT_THROW_ERROR(ERR_RSRC_PLAN_INVALIDATED);
        (void)srv_return_error(session);
        rsrc_session_detach_agent(session);
    }
    rsrc_group->rsrc_monitor.que_length = 0;
    for (uint32 i = 0; i < rsrc_group->attr_maps->count; i++) {
        attr_map = (rsrc_attr_map_t *)cm_galist_get(rsrc_group->attr_maps, i);
        attr_map->rsrc_monitor.que_length = 0;
    }
}

static void rsrc_try_release_queued_plan(biqueue_t *plans, agent_t *agent)
{
    rsrc_plan_t *plan = NULL;
    biqueue_node_t *node = NULL;
    rsrc_group_t *rsrc_group = NULL;

    if (biqueue_empty(plans)) {
        return;
    }

    node = biqueue_first(plans);
    plan = OBJECT_OF(rsrc_plan_t, node);

    for (uint32 i = 0; i < plan->group_count; i++) {
        rsrc_group = plan->groups[i];
        if (biqueue_empty(&rsrc_group->sess_que)) {
            continue;
        }
        rsrc_release_queued_sessions(rsrc_group, agent);
    }

    if (plan->ref_count == 0) {
        (void)biqueue_del_head(plans);
        rsrc_destory_plan(plan);
    }
}

agent_t *rsrc_manager_entry_agent_create(void)
{
    agent_t *agent = malloc(sizeof(agent_t));

    if (agent == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(agent_t), "resmgr_agent");
        return NULL;
    }
    errno_t errcode = memset_s(agent, sizeof(agent_t), 0, sizeof(agent_t));
    if (errcode != EOK) {
        CM_FREE_PTR(agent);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return NULL;
    }
    if (srv_alloc_agent_res(agent) != CT_SUCCESS) {
        CM_FREE_PTR(agent);
        return NULL;
    }

    return agent;
}

void rsrc_manager_entry_agent_free(agent_t **agent)
{
    srv_free_agent_res(*agent, CT_TRUE);
    CM_FREE_PTR(*agent);
}

void rsrc_manager_entry(thread_t *thd)
{
    agent_t *agent = NULL;
    rsrc_plan_t *plan = NULL;
    rsrc_mgr_t *rsrc_mgr = (rsrc_mgr_t *)thd->argument;

    cm_spin_lock(&rsrc_mgr->lock, NULL);
    if (rsrc_mgr->started) {
        cm_spin_unlock(&rsrc_mgr->lock);
        return;
    }
    agent = rsrc_manager_entry_agent_create();
    if (agent == NULL) {
        cm_spin_unlock(&rsrc_mgr->lock);
        return;
    }
    srv_get_stack_base(thd, &agent);
    rsrc_mgr->started = CT_TRUE;
    cm_spin_unlock(&rsrc_mgr->lock);

    cm_set_thread_name("resmgr");
    CT_LOG_RUN_INF("resource manager thread started");

    while (!thd->closed) {
        if (!biqueue_empty(&rsrc_mgr->free_plans)) {
            cm_spin_lock(&rsrc_mgr->lock, NULL);
            rsrc_try_release_queued_plan(&rsrc_mgr->free_plans, agent);
            cm_spin_unlock(&rsrc_mgr->lock);
        }
        /* if resource manager disabled, rsrc_mgr->plan will reset to null */
        plan = rsrc_mgr->plan;
        if (plan == NULL) {
            cm_sleep(100);
            continue;
        }
        rsrc_process_queued_sessions(rsrc_mgr, plan, agent);
    }
    CT_LOG_RUN_INF("resource manager thread closed");
    cm_release_thread(thd);
    rsrc_manager_entry_agent_free(&agent);

    cm_spin_lock(&rsrc_mgr->lock, NULL);
    rsrc_mgr->started = CT_FALSE;
    cm_spin_unlock(&rsrc_mgr->lock);
}

status_t rsrc_start_manager(rsrc_mgr_t *rsrc_mgr)
{
    uint32 stack_size = (uint32)g_instance->kernel.attr.thread_stack_size;
    return cm_create_thread(rsrc_manager_entry, stack_size, rsrc_mgr, &rsrc_mgr->thread);
}

void rsrc_stop_manager(rsrc_mgr_t *rsrc_mgr)
{
    if (rsrc_mgr->started) {
        rsrc_mgr->thread.closed = CT_TRUE;
    }
    while (rsrc_mgr->started) {
        cm_sleep(1);
    }
    cm_event_destory(&rsrc_mgr->event);
}

void rsrc_accumate_io(knl_handle_t session, io_type_t type)
{
    session_t *sess = (session_t *)session;
    if (SECUREC_LIKELY(sess->rsrc_group == NULL)) {
        return;
    }

    bool32 need_wait = CT_FALSE;
    rsrc_group_t *rsrc_group = sess->rsrc_group;
    if (type == IO_TYPE_READ) {
        rsrc_disk_reads_inc(sess);
        need_wait = (uint32)rsrc_group->read_iops > rsrc_group->max_iops;
    } else {
        rsrc_commits_inc(sess);
        need_wait = (uint32)rsrc_group->commit_ps > rsrc_group->max_commit_ps;
    }
    if (SECUREC_UNLIKELY(need_wait)) {
        cm_sleep(CT_RES_IO_WAIT);
        sess->knl_session.stat->wait_time[RES_IO_QUANTUM] += CT_RES_IO_WAIT_US;
        sess->knl_session.stat->wait_count[RES_IO_QUANTUM]++;
        sess->stat.res_io_wait_time += CT_RES_IO_WAIT_US;
        sess->stat.res_io_waits++;
        rsrc_io_waittime_add(sess, (uint64)CT_RES_IO_WAIT_US);
        rsrc_io_waits_inc(sess);
    }
}

static vm_pool_t *rsrc_get_temp_pool_by_ref(uint8 *refs)
{
    uint32 i, pos, ref_cnt;
    uint32 pool_cnt = g_instance->kernel.temp_ctx_count;
    pos = 0;
    ref_cnt = refs[0];
    for (i = 1; i < pool_cnt; i++) {
        if (ref_cnt > refs[i]) {
            pos = i;
            ref_cnt = refs[i];
        }
    }
    refs[pos]++;
    return &g_instance->kernel.temp_pool[pos];
}

static inline void rsrc_bind_temp_pool(vm_pool_t *pool, uint8 *refs)
{
    uint32 pool_cnt = g_instance->kernel.temp_ctx_count;
    for (uint32 i = 1; i < pool_cnt; i++) {
        if (pool == &g_instance->kernel.temp_pool[i]) {
            refs[i] = (uint8)-1;
            break;
        }
    }
}

/* resource plan changed, try to reuse the old temp pool */
static void rsrc_attach_temp_pool(rsrc_plan_t *rsrc_plan, rsrc_plan_t *old_plan)
{
    uint32 i, j;
    rsrc_group_t *group = NULL;
    rsrc_group_t *old_group = NULL;
    uint8 refs[CT_MAX_TEMP_POOL_NUM] = { 0 };

    if (old_plan != NULL) {
        for (i = 1; i < rsrc_plan->group_count; i++) {
            group = rsrc_plan->groups[i];
            for (j = 1; j < old_plan->group_count; j++) {
                old_group = old_plan->groups[j];
                if (cm_str_equal(group->knl_group.name, old_group->knl_group.name)) {
                    group->temp_pool = old_group->temp_pool;
                    rsrc_bind_temp_pool(group->temp_pool, refs);
                    break;
                }
            }
        }
    }

    for (i = 0; i < rsrc_plan->group_count; i++) {
        group = rsrc_plan->groups[i];
        if (group->temp_pool == NULL) {
            group->temp_pool = rsrc_get_temp_pool_by_ref(refs);
        }
    }
}

static status_t rsrc_create_attr_map(knl_session_t *session, rsrc_group_t *group, knl_cursor_t *cur)
{
    text_t key, value, name;
    rsrc_attr_map_t *rsrc_map = NULL;
    memory_context_t *ctx = group->plan->memory;

    // control_group
    name.str = CURSOR_COLUMN_DATA(cur, SYS_RSRC_GROUP_MAPPING_COL_GROUP);
    name.len = CURSOR_COLUMN_SIZE(cur, SYS_RSRC_GROUP_MAPPING_COL_GROUP);
    if (name.str == NULL || name.len == CT_NULL_VALUE_LEN || !cm_text_str_equal_ins(&name, group->knl_group.name)) {
        return CT_SUCCESS;
    }

    // attribute
    key.str = CURSOR_COLUMN_DATA(cur, SYS_RSRC_GROUP_MAPPING_COL_ATTRIBUTE);
    key.len = CURSOR_COLUMN_SIZE(cur, SYS_RSRC_GROUP_MAPPING_COL_ATTRIBUTE);
    if (key.str == NULL || key.len == CT_NULL_VALUE_LEN) {
        return CT_SUCCESS;
    }

    // ignore other type
    if ((group->plan->type == PLAN_TYPE_TENANT && !cm_text_str_equal_ins(&key, "tenant")) ||
        (group->plan->type == PLAN_TYPE_USER && !cm_text_str_equal_ins(&key, "db_user"))) {
        return CT_SUCCESS;
    }

    // value
    value.str = CURSOR_COLUMN_DATA(cur, SYS_RSRC_GROUP_MAPPING_COL_VALUE);
    value.len = CURSOR_COLUMN_SIZE(cur, SYS_RSRC_GROUP_MAPPING_COL_VALUE);
    if (value.len == CT_NULL_VALUE_LEN || value.str == NULL) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(cm_galist_new(group->attr_maps, sizeof(rsrc_attr_map_t), (void **)&rsrc_map));
    MEMS_RETURN_IFERR(memset_sp(rsrc_map, sizeof(rsrc_attr_map_t), 0, sizeof(rsrc_attr_map_t)));
    CT_RETURN_IFERR(rsrc_copy_text(ctx, &key, &rsrc_map->key));
    CT_RETURN_IFERR(rsrc_copy_text(ctx, &value, &rsrc_map->value));
    rsrc_map->rsrc_group = group;
    return CT_SUCCESS;
}

static status_t rsrc_load_group_mappings(knl_session_t *session, rsrc_group_t *group)
{
    knl_cursor_t *cursor = NULL;
    status_t status = CT_SUCCESS;

    CM_SAVE_STACK(session->stack);
    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    knl_set_session_scn(session, CT_INVALID_ID64);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_RSRC_GROUP_MAPPING_ID, CT_INVALID_ID32);

    do {
        status = knl_fetch(session, cursor);
        CT_BREAK_IF_ERROR(status);

        if (cursor->eof) {
            break;
        }

        status = rsrc_create_attr_map(session, group, cursor);
        CT_BREAK_IF_ERROR(status);
    } while (CT_TRUE);

    CM_RESTORE_STACK(session->stack);
    return status;
}

static status_t rsrc_load_control_group(knl_session_t *session, text_t *group_name, rsrc_group_t *group)
{
    text_t text;
    knl_cursor_t *cursor = NULL;
    knl_rsrc_group_t *knl_group = &group->knl_group;

    CM_SAVE_STACK(session->stack);
    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_set_session_scn(session, CT_INVALID_ID64);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_RSRC_GROUP_ID, IX_RSRC_GROUP_001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, (void *)group_name->str,
        group_name->len, IX_COL_SYS_RSRC_GROUP001_NAME);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "control group", T2S(group_name));
        return CT_ERROR;
    }

    // 1. id
    knl_group->oid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_RSRC_GROUP_COL_ID);

    // 2. name
    if (cm_text2str(group_name, knl_group->name, CT_NAME_BUFFER_SIZE) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    // 3. description
    text.str = CURSOR_COLUMN_DATA(cursor, SYS_RSRC_GROUP_COL_NAME);
    text.len = CURSOR_COLUMN_SIZE(cursor, SYS_RSRC_GROUP_COL_NAME);
    if (text.str == NULL || text.len == CT_NULL_VALUE_LEN) {
        knl_group->description[0] = '\0';
    } else if (cm_text2str(&text, knl_group->description, CT_COMMENT_SIZE + 1) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    CM_RESTORE_STACK(session->stack);

    // load group mappings
    return rsrc_load_group_mappings(session, group);
}

static status_t rsrc_get_plan_group(knl_session_t *session, rsrc_plan_t *plan, text_t *group_name, rsrc_group_t **group)
{
    for (uint32 i = 0; i < plan->group_count; i++) {
        if (plan->groups[i] != NULL && cm_text_str_equal_ins(group_name, plan->groups[i]->knl_group.name)) {
            *group = plan->groups[i];
            return CT_SUCCESS;
        }
    }

    if (plan->group_count == CT_MAX_PLAN_GROUPS) {
        CT_THROW_ERROR(ERR_TOO_MANY_OBJECTS, CT_MAX_PLAN_GROUPS, "resource plan control groups");
        return CT_ERROR;
    }

    // load control group
    CT_RETURN_IFERR(rsrc_alloc_group(plan, group));
    CT_RETURN_IFERR(rsrc_load_control_group(session, group_name, *group));

    if (cm_text_str_equal(group_name, CT_DEFAULT_GROUP_NAME)) {
        plan->groups[0] = *group;
    } else {
        plan->groups[plan->group_count++] = *group;
    }
    return CT_SUCCESS;
}

#define MAX_CPU_VALUE 100

static status_t rsrc_load_plan_rules(knl_session_t *session, rsrc_plan_t *plan)
{
    text_t text;
    uint32 value;
    double v_real;
    rsrc_group_t *group = NULL;
    knl_cursor_t *cursor = NULL;
    status_t status = CT_SUCCESS;
    cm_str2text((char *)plan->knl_plan.name, &text);

    CM_SAVE_STACK(session->stack);
    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_set_session_scn(session, CT_INVALID_ID64);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_RSRC_PLAN_RULE_ID, IX_RSRC_PLAN_RULE_001_ID);
    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, (void *)text.str, text.len,
        IX_COL_SYS_RSRC_RULE001_PLAN);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_STRING, (void *)text.str, text.len,
        IX_COL_SYS_RSRC_RULE001_PLAN);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_RSRC_RULE001_GROUP);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_RSRC_RULE001_GROUP);

    do {
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }
        if (cursor->eof) {
            break;
        }
        // 1. plan (skip)
        // 2. group
        text.str = CURSOR_COLUMN_DATA(cursor, SYS_RSRC_PLAN_RULE_COL_GROUP);
        text.len = CURSOR_COLUMN_SIZE(cursor, SYS_RSRC_PLAN_RULE_COL_GROUP);
        if (text.str == NULL || text.len == CT_NULL_VALUE_LEN) {
            continue;
        }
        if (rsrc_get_plan_group(session, plan, &text, &group) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }
        // 3. cpu(%)
        text.len = CURSOR_COLUMN_SIZE(cursor, SYS_RSRC_PLAN_RULE_COL_CPU);
        value = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_RSRC_PLAN_RULE_COL_CPU);
        if (value == 0 || value >= MAX_CPU_VALUE) {
            group->max_cpus = plan->total_cpus;
        } else {
            v_real = (double)plan->total_cpus * value / MAX_CPU_VALUE;
            group->max_cpus = (uint32)ceil(v_real);
            group->max_cpus = MAX(1, group->max_cpus); // at least 1 cpu
        }
        // 4. sessions
        text.len = CURSOR_COLUMN_SIZE(cursor, SYS_RSRC_PLAN_RULE_COL_SESSIONS);
        if (text.len != CT_NULL_VALUE_LEN) {
            group->max_sessions = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_RSRC_PLAN_RULE_COL_SESSIONS);
        }
        // 5. active sess
        text.len = CURSOR_COLUMN_SIZE(cursor, SYS_RSRC_PLAN_RULE_COL_ACTIVE_SESS);
        if (text.len != CT_NULL_VALUE_LEN) {
            group->max_active_sess = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_RSRC_PLAN_RULE_COL_ACTIVE_SESS);
        }
        // 6. queue_time
        text.len = CURSOR_COLUMN_SIZE(cursor, SYS_RSRC_PLAN_RULE_COL_QUEUE_TIME);
        if (text.len != CT_NULL_VALUE_LEN) {
            group->max_queue_time = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_RSRC_PLAN_RULE_COL_QUEUE_TIME);
        }

        // 7. max_est_exec_time
        text.len = CURSOR_COLUMN_SIZE(cursor, SYS_RSRC_PLAN_RULE_COL_MAX_EXEC_TIME);
        if (text.len != CT_NULL_VALUE_LEN) {
            group->max_est_exec_time = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_RSRC_PLAN_RULE_COL_MAX_EXEC_TIME);
        }

        // 8. temp_pool
        text.len = CURSOR_COLUMN_SIZE(cursor, SYS_RSRC_PLAN_RULE_COL_TEMP_POOL);
        if (text.len != CT_NULL_VALUE_LEN) {
            group->max_temp_pool = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_RSRC_PLAN_RULE_COL_TEMP_POOL);
        }

        // 9. iops
        text.len = CURSOR_COLUMN_SIZE(cursor, SYS_RSRC_PLAN_RULE_COL_MAX_IOPS);
        if (text.len != CT_NULL_VALUE_LEN) {
            group->max_iops = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_RSRC_PLAN_RULE_COL_MAX_IOPS);
        }

        // 10. commits
        text.len = CURSOR_COLUMN_SIZE(cursor, SYS_RSRC_PLAN_RULE_COL_MAX_COMMITS);
        if (text.len != CT_NULL_VALUE_LEN) {
            group->max_commit_ps = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_RSRC_PLAN_RULE_COL_MAX_COMMITS);
        }
    } while (CT_TRUE);

    CM_RESTORE_STACK(session->stack);
    return status;
}

static status_t rsrc_verify_dc_entries(knl_session_t *session)
{
    dc_user_t *sys_user = NULL;
    CT_RETURN_IFERR(dc_open_user_by_id(session, DB_SYS_USER_ID, &sys_user));

    if (DC_GET_ENTRY(sys_user, SYS_RSRC_PLAN_ID) == NULL) {
        CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, "SYS", "SYS_RSRC_PLANS");
        return CT_ERROR;
    }
    if (DC_GET_ENTRY(sys_user, SYS_RSRC_GROUP_ID) == NULL) {
        CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, "SYS", "SYS_RSRC_CONTROL_GROUPS");
        return CT_ERROR;
    }
    if (DC_GET_ENTRY(sys_user, SYS_RSRC_GROUP_MAPPING_ID) == NULL) {
        CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, "SYS", "SYS_RSRC_GROUP_MAPPINGS");
        return CT_ERROR;
    }
    if (DC_GET_ENTRY(sys_user, SYS_RSRC_PLAN_RULE_ID) == NULL) {
        CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, "SYS", "SYS_RSRC_PLAN_RULES");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t rsrc_verify_vmem_pool(rsrc_plan_t *plan)
{
    uint32 total_mem = 0;
    uint32 min_temp_pool = (uint32)((uint64)CT_MIN_TEMP_BUFFER_SIZE >> 20);
    uint32 max_temp_pool = (uint32)(g_instance->kernel.attr.temp_buf_size >> 20);
    rsrc_group_t *group = NULL;

    for (uint32 i = 1; i < plan->group_count; i++) {
        group = plan->groups[i];
        if (group->max_temp_pool != CT_MAX_UINT32) {
            if (group->max_temp_pool < min_temp_pool) {
                CT_THROW_ERROR(ERR_VM, "temp buffer size of control group is too small");
                return CT_ERROR;
            } else if (total_mem + group->max_temp_pool > max_temp_pool) {
                CT_THROW_ERROR(ERR_VM, "temp buffer size of control group exceeds the maximum");
                return CT_ERROR;
            }
            total_mem += group->max_temp_pool;
        }
    }

    if (total_mem + min_temp_pool > max_temp_pool) {
        CT_THROW_ERROR(ERR_VM, "temp buffer size left for DEFAULT_GROUPS is too small");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static knl_rsrc_group_t g_default_group = {
    .oid = 1,
    .name = CT_DEFAULT_GROUP_NAME,
    .description = "Control group for users not included in any control group",
};

static inline status_t rsrc_create_default_group(rsrc_plan_t *plan, rsrc_group_t **group)
{
    CT_RETURN_IFERR(rsrc_alloc_group(plan, group));
    (*group)->knl_group = g_default_group;
    (*group)->max_cpus = plan->total_cpus;
    return CT_SUCCESS;
}

status_t rsrc_load_plan(knl_handle_t sess, const char *name, rsrc_plan_t **plan)
{
    text_t text;
    knl_rsrc_plan_t *knl_plan = NULL;
    knl_cursor_t *cursor = NULL;
    status_t status = CT_SUCCESS;
    knl_session_t *session = (knl_session_t *)sess;
    knl_attr_t *knl_attr = &session->kernel->attr;

    CT_RETURN_IFERR(rsrc_verify_dc_entries(session));
    cm_str2text((char *)name, &text);
    cm_text_upper(&text);

    CM_SAVE_STACK(session->stack);
    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_set_session_scn(session, CT_INVALID_ID64);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_RSRC_PLAN_ID, IX_RSRC_PLAN_001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_VARCHAR, (void *)text.str, text.len,
        IX_COL_SYS_RSRC_PLAN001_NAME);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "resource plan", name);
        return CT_ERROR;
    }

    if (rsrc_alloc_plan(plan) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    knl_plan = &(*plan)->knl_plan;

    do {
        knl_plan->oid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_RSRC_PLAN_COL_ID);
        text.str = CURSOR_COLUMN_DATA(cursor, SYS_RSRC_PLAN_COL_NAME);
        text.len = CURSOR_COLUMN_SIZE(cursor, SYS_RSRC_PLAN_COL_NAME);
        if (cm_text2str(&text, knl_plan->name, CT_MAX_NAME_LEN) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }
        knl_plan->num_rules = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_RSRC_PLAN_COL_RULES);
        text.str = CURSOR_COLUMN_DATA(cursor, SYS_RSRC_PLAN_COL_COMMENT);
        text.len = CURSOR_COLUMN_SIZE(cursor, SYS_RSRC_PLAN_COL_COMMENT);
        if (text.str == NULL || text.len == CT_NULL_VALUE_LEN) {
            knl_plan->description[0] = '\0';
        } else if (cm_text2str(&text, knl_plan->description, CT_COMMENT_SIZE + 1) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }
        knl_plan->type = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_RSRC_PLAN_COL_TYPE);
    } while (CT_FALSE);

    CM_RESTORE_STACK(session->stack);
    if (status != CT_SUCCESS) {
        rsrc_destory_plan(*plan);
        *plan = NULL;
        return CT_ERROR;
    }

    (*plan)->group_count = 1;
    (*plan)->total_cpus = knl_attr->cpu_count;
    (*plan)->type = knl_plan->type;

    if (rsrc_load_plan_rules(session, *plan) != CT_SUCCESS) {
        rsrc_destory_plan(*plan);
        *plan = NULL;
        return CT_ERROR;
    }

    if ((*plan)->groups[0] == NULL && rsrc_create_default_group(*plan, &(*plan)->groups[0]) != CT_SUCCESS) {
        rsrc_destory_plan(*plan);
        *plan = NULL;
        return CT_ERROR;
    }

    if (rsrc_verify_vmem_pool(*plan) != CT_SUCCESS) {
        rsrc_destory_plan(*plan);
        *plan = NULL;
        return CT_ERROR;
    }
    rsrc_attach_temp_pool(*plan, NULL);

    (*plan)->is_valid = CT_TRUE;
    if (rsrc_calc_cpuset(knl_attr->cpu_bind_lo, knl_attr->cpu_bind_hi, *plan) != CT_SUCCESS) {
        rsrc_destory_plan(*plan);
        *plan = NULL;
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t rsrc_reload_plan(knl_handle_t session, const char *plan_name)
{
    rsrc_plan_t *rsrc_plan = NULL;
    rsrc_plan_t *old_plan = GET_RSRC_MGR->plan;

    if (!CM_IS_EMPTY_STR(plan_name) && rsrc_load_plan(session, plan_name, &rsrc_plan) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (old_plan != NULL) {
        old_plan->is_valid = CT_FALSE;
    }

    /* attach vmem pool */
    if (rsrc_plan != NULL) {
        rsrc_attach_temp_pool(rsrc_plan, old_plan);
    }

    cm_spin_lock(&GET_RSRC_MGR->lock, NULL);
    GET_RSRC_MGR->plan = rsrc_plan;
    if (old_plan != NULL) {
        biqueue_add_tail(&GET_RSRC_MGR->free_plans, QUEUE_NODE_OF(old_plan));
    }
    cm_spin_unlock(&GET_RSRC_MGR->lock);

    if (rsrc_plan != NULL) {
        return rsrc_start_manager(GET_RSRC_MGR);
    }
    return CT_SUCCESS;
}