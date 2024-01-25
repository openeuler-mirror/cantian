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
 * srv_job.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_job.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "srv_job.h"
#include "cm_log.h"
#include "srv_instance.h"
#include "expr_parser.h"
#include "ctsql_package.h"
#include "srv_agent.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_JOB_QUEUE_PROCESS (uint32)100
#define JOB_CHECK_INTERVAL_MS 1000
#define JMGR g_instance->job_mgr

static void job_thread_exit(thread_t *thread, session_t *session)
{
    srv_thread_exit(thread, session);
}

uint32 job_get_max_process(void)
{
    uint32 max_job_processes;

    char *param_value = cm_get_config_value(&g_instance->config, "JOB_THREADS");
    if (param_value == NULL) {
        return DEFAULT_JOB_QUEUE_PROCESS;
    }
    if (cm_str2uint32(param_value, &max_job_processes) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("paramter JOB_THREADS error %s", g_tls_error.message);
        cm_reset_error();
        return DEFAULT_JOB_QUEUE_PROCESS;
    }

    return max_job_processes;
}

/*
 * job_add_running
 *
 * Add job to running list.
 */
static void job_add_running(const int64 job_id, const uint32 session_id, const uint32 serial_id)
{
    cm_spin_lock(&JMGR.lock, NULL);
    JMGR.running_jobs[JMGR.running_count].job_id = job_id;
    JMGR.running_jobs[JMGR.running_count].session_id = session_id;
    JMGR.running_jobs[JMGR.running_count].serial_id = serial_id;
    JMGR.running_count++;
    cm_spin_unlock(&JMGR.lock);
}

/*
 * job_delete_running
 *
 * Delete job from running list.
 */
static void job_delete_running(const int64 job_id)
{
    uint32 i, j;

    cm_spin_lock(&JMGR.lock, NULL);

    for (i = 0; i < JMGR.running_count; i++) {
        if (JMGR.running_jobs[i].job_id == job_id) {
            for (j = i; j < (JMGR.running_count - 1); j++) {
                JMGR.running_jobs[j].job_id = JMGR.running_jobs[j + 1].job_id;
                JMGR.running_jobs[j].session_id = JMGR.running_jobs[j + 1].session_id;
                JMGR.running_jobs[j].serial_id = JMGR.running_jobs[j + 1].serial_id;
            }
            JMGR.running_count--;
            break;
        }
    }

    cm_spin_unlock(&JMGR.lock);
}

status_t job_get_next_date(sql_stmt_t *stmt, char *interval, variant_t *var)
{
    expr_tree_t *interval_expr = NULL;
    sql_text_t interval_txt;
    date_t now_date;
    sql_verifier_t verf = { 0 };

    verf.context = stmt->context;
    verf.stmt = stmt;
    verf.excl_flags = SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_JOIN | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID |
        SQL_EXCL_DEFAULT | SQL_EXCL_SUBSELECT | SQL_EXCL_COLUMN | SQL_EXCL_ROWSCN | SQL_EXCL_GROUPING |
        SQL_EXCL_ROWNODEID;

    now_date = cm_now();
    interval_txt.value.str = interval;
    interval_txt.value.len = (uint32)strlen(interval);
    interval_txt.loc.column = 1;
    interval_txt.loc.line = 1;

    CT_RETURN_IFERR(sql_create_expr_from_text(stmt, &interval_txt, &interval_expr, WORD_FLAG_NONE));
    CT_RETURN_IFERR(sql_verify_expr_node(&verf, interval_expr->root));
    CT_RETURN_IFERR(sql_task_get_nextdate(stmt, interval_expr->root, var));

    if (var->v_bigint <= now_date) {
        CT_THROW_ERROR(ERR_INTERVAL_TOO_EARLY);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t job_init_stmt(sql_stmt_t *stmt)
{
    stmt->auto_commit = CT_FALSE;
    CT_RETURN_IFERR(sql_init_trigger_list(stmt));
    CT_RETURN_IFERR(sql_init_pl_ref_dc(stmt));
    return CT_SUCCESS;
}

static void job_update_after_run(sql_stmt_t *stmt, knl_job_node_t *job, bool32 need_repeated, variant_t *next_date)
{
    date_t now_date;
    status_t status = CT_ERROR;

    if (job->is_success && !need_repeated) {
        status = knl_delete_job(KNL_SESSION(stmt), &stmt->session->curr_user, job->job_id, CT_FALSE);
    } else {
        if (job->is_success && need_repeated) {
            now_date = cm_now();
            job->next_date = next_date->v_bigint < now_date ? now_date : next_date->v_bigint;
            job->failures = 0;
        } else {
            job->failures++;

            /* write alarm log when first error occur */
            if (job->failures == 1) {
                CT_LOG_RUN_ERR("job (" PRINT_FMT_INT64 ") execute error, msg: %s", job->job_id, g_tls_error.message);
                CT_LOG_ALARM(WARN_JOB, "'job-id':'" PRINT_FMT_INT64 "','error-message':'%s'}", job->job_id,
                    g_tls_error.message);
            }
            cm_reset_error();
        }
        status = knl_update_job(KNL_SESSION(stmt), &stmt->session->curr_user, job, CT_FALSE);
    }

    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("finish job (" PRINT_FMT_INT64 ") failed, msg: %s", job->job_id, g_tls_error.message);
        do_rollback(stmt->session, NULL);
    } else {
        (void)do_commit(stmt->session);
    }
}

void job_process_task_session(agent_t *agent)
{
    status_t status = CT_ERROR;
    knl_job_node_t job;
    variant_t next_date;
    session_t *session = agent->session;

    sql_stmt_t *stmt = NULL;
    text_t job_what;
    source_location_t loc = {
        .line = 1,
        .column = 1
    };
    bool32 need_repeated = CT_FALSE;

    if (DB_IS_MAINTENANCE(&session->knl_session) || !DB_IS_PRIMARY(&session->knl_session.kernel->db) ||
        DB_IS_READONLY(&session->knl_session) || session->knl_session.kernel->switch_ctrl.request != SWITCH_REQ_NONE) {
        session->knl_session.status = SESSION_INACTIVE;
        return;
    }

    if (session->knl_session.killed) {
        if (!session->knl_session.force_kill) {
            do_rollback(session, NULL);
        }
        return;
    }

    cm_log_set_session_id(session->knl_session.id);
    knl_set_curr_sess2tls((void *)agent->session);

    sql_init_session(session);
    session->proto_type = PROTO_TYPE_CT;
    session->call_version = cs_get_version(&agent->send_pack);
    session->prefix_tenant_flag = CT_FALSE;
    if (sql_alloc_stmt(session, &session->current_stmt) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("job failed");
        return;
    }
    stmt = session->current_stmt;
    job_what.str = agent->job_info.what;
    job_what.len = (uint32)strlen(job_what.str);

    /* update this date of job */
    job.job_id = agent->job_info.job_id;
    job.node_type = JOB_TYPE_START;
    job.this_date = cm_now();

    if (knl_update_job(KNL_SESSION(stmt), &session->curr_user, &job, CT_TRUE) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("start job (" PRINT_FMT_INT64 ") failed, msg: %s", job.job_id, g_tls_error.message);
        sql_free_stmt(stmt);
        do_rollback(session, NULL);
        return;
    }
    (void)do_commit(session);

    do {
        CT_BREAK_IF_ERROR(job_init_stmt(stmt));

        /* caculate the next date */
        session->lex->flags = LEX_WITH_OWNER | LEX_WITH_ARG;
        if (strlen(agent->job_info.interval) != 0) {
            need_repeated = CT_TRUE;
            CT_BREAK_IF_ERROR(sql_alloc_context(stmt));
            status = job_get_next_date(stmt, agent->job_info.interval, &next_date);
            sql_free_context(stmt->context);
            SET_STMT_CONTEXT(stmt, NULL);
            CT_BREAK_IF_ERROR(status);
        }

        sql_audit_init(&stmt->session->sql_audit);
        session->sql_audit.action = SQL_AUDIT_ACTION_EXECUTE;
        session->sql_audit.audit_type = SQL_AUDIT_PL;
        session->sql_audit.packet_sql = job_what;

        /* parse job what */
        status = sql_parse_job(stmt, &job_what, &loc);
        if (status != CT_SUCCESS) {
            sql_record_audit_log(session, status, CT_FALSE);
            break;
        }

        /* execute job what */
        status = sql_execute(stmt);
        if (status == CT_SUCCESS) {
            (void)do_commit(session);
        } else {
            do_rollback(session, NULL);
        }
        sql_record_audit_log(session, status, CT_FALSE);
    } while (0);

    /* update job info */
    job.node_type = JOB_TYPE_FINISH;
    job.failures = agent->job_info.failures;
    job.is_success = (status == CT_SUCCESS) ? CT_TRUE : CT_FALSE;

    job_update_after_run(stmt, &job, need_repeated, &next_date);
    sql_free_stmt(session->current_stmt);
    session->knl_session.status = SESSION_INACTIVE;
    session->interactive_info.response_time = g_timer()->systime;
    cm_stack_reset(session->stack);
}

static void job_agent_entry(thread_t *thread)
{
    agent_t *agent = thread->argument;
    session_t *session = agent->session;

    session->knl_session.status = SESSION_ACTIVE;
    session->knl_session.canceled = CT_FALSE;
    session->knl_session.spid = cm_get_current_thread_id();

    cm_set_thread_name("job");
    session->exec_prev_stat.stat_level = 0;
    sql_begin_exec_stat((void *)session);

    /* set the start stack address of this thread */
    srv_get_stack_base(thread, &agent);

    cs_init_packet(&agent->send_pack, CT_FALSE);
    cs_init_set(&agent->send_pack, CS_LOCAL_VERSION);

    if (!thread->closed) {
        job_process_task_session(agent);
    }

    job_delete_running(agent->job_info.job_id);

    /* exit and release source */
    sql_end_exec_stat((void *)session);
    job_thread_exit(thread, session);
}

status_t job_init_session_attr(session_t *session, const job_info_t *job)
{
    uint32 length;

    session->recv_pack = NULL;
    session->curr_schema_id = job->powner_id;
    session->knl_session.uid = job->powner_id;
    length = (uint32)strlen(job->powner);
    MEMS_RETURN_IFERR(memcpy_s(session->db_user, CT_NAME_BUFFER_SIZE, job->powner, length));

    session->db_user[length] = '\0';
    MEMS_RETURN_IFERR(memcpy_s(session->curr_schema, CT_NAME_BUFFER_SIZE, job->powner, length));

    session->curr_schema[length] = '\0';

    session->curr_user.str = session->db_user;
    session->curr_user.len = length;
    session->knl_session.uid = job->powner_id;

    return CT_SUCCESS;
}

status_t job_create_task_session(const job_info_t *job)
{
    session_t *session = NULL;
    uint32 stack_size, count;
    status_t status = CT_ERROR;

    agent_t *agent = malloc(sizeof(agent_t));
    if (agent == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(agent_t), "job_agent");
        return CT_ERROR;
    }
    errno_t ret = memset_s(agent, sizeof(agent_t), 0, sizeof(agent_t));
    if (ret != EOK) {
        CM_FREE_PTR(agent);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    do {
        ret = memcpy_s(&agent->job_info, sizeof(job_info_t), job, sizeof(job_info_t));
        if (ret != EOK) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
            break;
        }

        status = srv_alloc_agent_res(agent);
        CT_BREAK_IF_ERROR(status);

        status = srv_alloc_session(&session, NULL, SESSION_TYPE_JOB);
        CT_BREAK_IF_ERROR(status);

        srv_bind_sess_agent(session, agent);

        /* modify the job attribute */
        status = job_init_session_attr(session, job);
        CT_BREAK_IF_ERROR(status);

        /* check the number of user sessions reached SESSIONS_PER_USER or not */
        count = srv_get_user_sessions_count(&session->curr_user);
        status = knl_check_sessions_per_user((knl_handle_t)session, &session->curr_user, count);
        CT_BREAK_IF_ERROR(status);
        /* add this job to running_list */
        job_add_running(job->job_id, session->knl_session.id, session->knl_session.serial_id);

        /* create the job thread */
        stack_size = (uint32)g_instance->kernel.attr.thread_stack_size;
        status = cm_create_thread(job_agent_entry, stack_size, agent, &agent->thread);
    } while (0);

    if (status == CT_SUCCESS) {
        return CT_SUCCESS;
    }
    job_delete_running(job->job_id);
    if (session != NULL) {
        srv_unbind_sess_agent(session, agent);
        srv_release_session(session);
    }
    srv_free_agent_res(agent, CT_FALSE);
    CM_FREE_PTR(agent);
    return CT_ERROR;
}

/*
 * job_check_running
 *
 * Check the job which has this_date timestamp is running or not.
 */
static bool32 job_check_running(const int64 job_id)
{
    uint32 i;
    bool32 is_found = CT_FALSE;

    cm_spin_lock(&JMGR.lock, NULL);
    for (i = 0; i < JMGR.running_count; i++) {
        if (JMGR.running_jobs[i].job_id == job_id) {
            is_found = CT_TRUE;
            break;
        }
    }
    cm_spin_unlock(&JMGR.lock);

    return is_found;
}

/*
 * job_reach_max_count
 *
 * Check reach the max running job count or not.
 *
 */
static bool32 job_reach_max_count(uint32 max_job_processes)
{
    bool32 is_full = CT_FALSE;

    cm_spin_lock(&JMGR.lock, NULL);

    if (JMGR.running_count >= CT_MAX_JOB_THREADS || JMGR.running_count >= max_job_processes) {
        is_full = CT_TRUE;
    }
    cm_spin_unlock(&JMGR.lock);

    return is_full;
}

static void job_run(const job_info_t *def, const int64 start_time)
{
    /* Check job is running or failed. */
    if (job_check_running(def->job_id)) {
        return;
    }

    /*
     * If the job is failed and the time interval is longer than 1 minutes, the job should try run again.
     * This mechanism is same as other database.
     */
    if (CT_INVALID_INT64 != def->this_date &&
        (start_time - def->this_date) < (int64)(MICROSECS_PER_SECOND * SECONDS_PER_MIN)) {
        return;
    }

    /* run this job */
    if (job_create_task_session(def) != CT_SUCCESS) {
        CT_LOG_RUN_WAR("create session for job failed");
        CT_LOG_ALARM(WARN_JOB, "'job-id':'" PRINT_FMT_INT64 "','error-message':'%s'}", def->job_id,
            g_tls_error.message);
        return;
    }
}

static status_t job_get_what(uint32 column_len, const char *ptr, job_info_t *def)
{
    /* check begin ...end exists or not */
    if (!sql_transform_task_content(def->what, WHAT_BUFFER_LENGTH, ptr, column_len)) {
        MEMS_RETURN_IFERR(strncpy_sp(def->what, WHAT_BUFFER_LENGTH, ptr, column_len));
    }
    return CT_SUCCESS;
}

static status_t job_get_task_info(knl_session_t *session, knl_cursor_t *cursor, job_info_t *def)
{
    text_t schema_name;
    uint32 column_len = CURSOR_COLUMN_SIZE(cursor, SYS_JOB_THIS_DATE);
    char *ptr = CURSOR_COLUMN_DATA(cursor, SYS_JOB_POWNER);

    def->job_id = *(int64 *)CURSOR_COLUMN_DATA(cursor, SYS_JOB_JOB_ID);
    def->this_date =
        column_len == CT_NULL_VALUE_LEN ? CT_INVALID_INT64 : *(int64 *)CURSOR_COLUMN_DATA(cursor, SYS_JOB_THIS_DATE);
    def->next_date = *(int64 *)CURSOR_COLUMN_DATA(cursor, SYS_JOB_NEXT_DATE);

    column_len = CURSOR_COLUMN_SIZE(cursor, SYS_JOB_POWNER);
    if (column_len > 0 && column_len <= CT_MAX_NAME_LEN) {
        MEMS_RETURN_IFERR(strncpy_sp(def->powner, CT_NAME_BUFFER_SIZE, ptr, column_len));
        def->powner[column_len] = '\0';
    } else {
        CT_THROW_ERROR(ERR_VALUE_ERROR, "length of powner invalid");
        return CT_ERROR;
    }
    ptr = CURSOR_COLUMN_DATA(cursor, SYS_JOB_COWNER);
    column_len = CURSOR_COLUMN_SIZE(cursor, SYS_JOB_COWNER);
    if (column_len > 0 && column_len <= CT_MAX_NAME_LEN) {
        MEMS_RETURN_IFERR(strncpy_sp(def->cowner, CT_NAME_BUFFER_SIZE, ptr, column_len));
    } else {
        CT_THROW_ERROR(ERR_VALUE_ERROR, "length of cowner invalid");
        return CT_ERROR;
    }
    def->total = *(int32 *)CURSOR_COLUMN_DATA(cursor, SYS_JOB_TOTAL);
    ptr = CURSOR_COLUMN_DATA(cursor, SYS_JOB_INTERVAL);
    column_len = CURSOR_COLUMN_SIZE(cursor, SYS_JOB_INTERVAL);
    if (column_len > 0 && column_len <= MAX_LENGTH_INTERVAL) {
        MEMS_RETURN_IFERR(strncpy_sp(def->interval, INTERVAL_BUFFER_LENGTH, ptr, column_len));
    } else {
        def->interval[0] = '\0';
    }

    def->failures = *(int32 *)CURSOR_COLUMN_DATA(cursor, SYS_JOB_FAILURES);
    def->is_broken = *(int32 *)CURSOR_COLUMN_DATA(cursor, SYS_JOB_FLAG);
    ptr = CURSOR_COLUMN_DATA(cursor, SYS_JOB_WHAT);
    column_len = CURSOR_COLUMN_SIZE(cursor, SYS_JOB_WHAT);
    if (column_len > 0 && column_len <= MAX_LENGTH_WHAT) {
        CT_RETURN_IFERR(job_get_what(column_len, ptr, def));
    } else {
        CT_THROW_ERROR(ERR_VALUE_ERROR, "length of what invalid");
        return CT_ERROR;
    }

    schema_name.str = def->powner;
    schema_name.len = (uint32)strlen(def->powner);
    if (!knl_get_user_id(session, &schema_name, &def->powner_id)) {
        CT_THROW_ERROR(ERR_USER_NOT_EXIST, def->powner);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

bool32 job_check_db_session_invalid(knl_session_t *session)
{
    if (DB_IS_MAINTENANCE(session) || !DB_IS_PRIMARY(&session->kernel->db) || DB_IS_READONLY(session) ||
        session->kernel->db.status != DB_STATUS_OPEN || session->kernel->db.open_status != DB_OPEN_STATUS_NORMAL ||
        session->kernel->switch_ctrl.request != SWITCH_REQ_NONE || !session->kernel->dc_ctx.completed ||
        DB_IN_BG_ROLLBACK(session) || g_instance->shutdown_ctx.phase != SHUTDOWN_PHASE_NOT_BEGIN) {
        return CT_TRUE;
    }
    if (session->killed || session->force_kill || session->canceled) {
        return CT_TRUE;
    }
    return CT_FALSE;
}


/*
 * job_fetch_task
 *
 * Get the task from job$, then check should run or not.
 */
static void job_fetch_task(knl_session_t *session)
{
    knl_cursor_t *cursor = NULL;
    job_info_t def;
    knl_set_session_scn(session, CT_INVALID_ID64);
    int64 start_time = cm_now();
    int64 next_date;
    int32 is_broken;

    CM_SAVE_STACK(session->stack);
    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_JOB_ID, CT_INVALID_ID32);
    do {
        if (job_check_db_session_invalid(session)) {
            CM_RESTORE_STACK(session->stack);
            session->status = SESSION_INACTIVE;
            return;
        }
        if (knl_fetch(session, cursor) != CT_SUCCESS || cursor->eof) {
            CM_RESTORE_STACK(session->stack);
            return;
        }
        next_date = *(int64 *)CURSOR_COLUMN_DATA(cursor, SYS_JOB_NEXT_DATE);
        is_broken = *(int32 *)CURSOR_COLUMN_DATA(cursor, SYS_JOB_FLAG);
        if (start_time < next_date || is_broken) {
            continue;
        }
        uint32 max_job_processes = job_get_max_process();
        if (max_job_processes == 0) {
            CM_RESTORE_STACK(session->stack);
            return;
        }
        if (job_reach_max_count(max_job_processes)) {
            sql_end_exec_stat((session_t *)session);
            cm_sleep(JOB_CHECK_INTERVAL_MS);
            sql_begin_exec_stat((void *)session);
            continue;
        }
        if (job_get_task_info(session, cursor, &def) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return;
        }
        job_run(&def, start_time);
    } while (CT_TRUE);
    return;
}


/*
 * jobs_proc
 *
 * The main thread function of job.
 */
void jobs_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    dc_user_t *sys_user = NULL;

    cm_set_thread_name("jobmaster");
    CT_LOG_RUN_INF("job master thread started");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());
    /* init job manager */
    cm_spin_lock(&JMGR.lock, NULL);
    JMGR.running_count = 0;
    cm_spin_unlock(&JMGR.lock);

    while (!thread->closed) {
        ((session_t *)thread->argument)->exec_prev_stat.stat_level = 0;

        if (job_check_db_session_invalid(session)) {
            session->status = SESSION_INACTIVE;
            cm_sleep(JOB_CHECK_INTERVAL_MS);
            continue;
        }

        if (session->status == SESSION_INACTIVE) {
            session->status = SESSION_ACTIVE;
        }

        // job does not work when JOB_QUEUE_PROCESSES is zero
        if (job_get_max_process() == 0) {
            cm_sleep(JOB_CHECK_INTERVAL_MS * 5);
            continue;
        }

        sql_begin_exec_stat((void *)thread->argument);

        if (dc_open_user_by_id(session, DB_SYS_USER_ID, &sys_user) == CT_SUCCESS &&
            DC_GET_ENTRY(sys_user, SYS_JOB_ID) != NULL) {
            job_fetch_task(session);
        }
        sql_end_exec_stat((session_t *)thread->argument);
        cm_sleep(JOB_CHECK_INTERVAL_MS);
    } // end of while

    CT_LOG_RUN_INF("job master thread closed");
    KNL_SESSION_CLEAR_THREADID(session);
}

#ifdef __cplusplus
}
#endif
