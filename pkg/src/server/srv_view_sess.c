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
 * srv_view_sess.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_view_sess.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "srv_view_sess.h"
#include "srv_instance.h"

// !!!please sync your edits to g_global_session_columns
static knl_column_t g_session_columns[] = {
    // session columns
    { 0, "SID", 0, 0, CT_TYPE_INTEGER, 4, 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "SPID", 0, 0, CT_TYPE_VARCHAR, CT_MAX_UINT32_STRLEN + 1, 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "SERIAL#", 0, 0, CT_TYPE_INTEGER, 4, 0, 0, CT_FALSE, 0, { 0 } },
    { 3, "USER#", 0, 0, CT_TYPE_INTEGER, 4, 0, 0, CT_FALSE, 0, { 0 } },
    { 4, "USERNAME", 0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 5, "CURR_SCHEMA", 0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 6, "PIPE_TYPE", 0, 0, CT_TYPE_VARCHAR, 20, 0, 0, CT_FALSE, 0, { 0 } },
    { 7, "CLIENT_IP", 0, 0, CT_TYPE_VARCHAR, CM_MAX_IP_LEN, 0, 0, CT_TRUE, 0, { 0 } },
    { 8, "CLIENT_PORT", 0, 0, CT_TYPE_VARCHAR, 10, 0, 0, CT_TRUE, 0, { 0 } },
    { 9, "CLIENT_UDS_PATH", 0, 0, CT_TYPE_VARCHAR, CT_UNIX_PATH_MAX, 0, 0, CT_TRUE, 0, { 0 } },
    { 10, "SERVER_IP", 0, 0, CT_TYPE_VARCHAR, CM_MAX_IP_LEN, 0, 0, CT_TRUE, 0, { 0 } },
    { 11, "SERVER_PORT", 0, 0, CT_TYPE_VARCHAR, 10, 0, 0, CT_TRUE, 0, { 0 } },
    { 12, "SERVER_UDS_PATH", 0, 0, CT_TYPE_VARCHAR, CT_UNIX_PATH_MAX, 0, 0, CT_TRUE, 0, { 0 } },
    { 13, "SERVER_MODE", 0, 0, CT_TYPE_VARCHAR, 10, 0, 0, CT_FALSE, 0, { 0 } },
    { 14, "OSUSER", 0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 15, "MACHINE", 0, 0, CT_TYPE_VARCHAR, CM_MAX_IP_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 16, "PROGRAM", 0, 0, CT_TYPE_VARCHAR, 256, 0, 0, CT_FALSE, 0, { 0 } },
    { 17, "AUTO_COMMIT", 0, 0, CT_TYPE_BOOLEAN, sizeof(bool32), 0, 0, CT_FALSE, 0, { 0 } },
    { 18, "CLIENT_VERSION", 0, 0, CT_TYPE_INTEGER, 4, 0, 0, CT_FALSE, 0, { 0 } },
    { 19, "TYPE", 0, 0, CT_TYPE_VARCHAR, 10, 0, 0, CT_FALSE, 0, { 0 } },
    { 20, "LOGON_TIME", 0, 0, CT_TYPE_DATE, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 21, "STATUS", 0, 0, CT_TYPE_VARCHAR, 10, 0, 0, CT_FALSE, 0, { 0 } },
    { 22, "LOCK_WAIT", 0, 0, CT_TYPE_VARCHAR, 4, 0, 0, CT_FALSE, 0, { 0 } },
    { 23, "WAIT_SID", 0, 0, CT_TYPE_INTEGER, 4, 0, 0, CT_TRUE, 0, { 0 } },
    { 24, "EXECUTIONS", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 25, "SIMPLE_QUERIES", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 26, "DISK_READS", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 27, "BUFFER_GETS", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 28, "CR_GETS", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 29, "CURRENT_SQL", 0, 0, CT_TYPE_VARCHAR, CT_BUFLEN_1K, 0, 0, CT_TRUE, 0, { 0 } },
    { 30, "SQL_EXEC_START", 0, 0, CT_TYPE_DATE, 8, 0, 0, CT_TRUE, 0, { 0 } },
    { 31, "SQL_ID", 0, 0, CT_TYPE_VARCHAR, CT_MAX_UINT32_STRLEN, 0, 0, CT_TRUE, 0, { 0 } },
    { 32, "ATOMIC_OPERS", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 33, "REDO_BYTES", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 34, "COMMITS", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 35, "NOWAIT_COMMITS", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 36, "XA_COMMITS", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 37, "ROLLBACKS", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 38, "XA_ROLLBACKS", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 39, "LOCAL_TXN_TIMES", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 40, "XA_TXN_TIMES", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 41, "PARSES", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 42, "HARD_PARSES", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 43, "EVENT#", 0, 0, CT_TYPE_INTEGER, 4, 0, 0, CT_FALSE, 0, { 0 } },
    { 44, "EVENT", 0, 0, CT_TYPE_VARCHAR, 64, 0, 0, CT_FALSE, 0, { 0 } },
    { 45, "SORTS", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 46, "PROCESSED_ROWS", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 47, "IO_WAIT_TIME", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 48, "CON_WAIT_TIME", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 49, "CPU_TIME", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 50, "ELAPSED_TIME", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 51, "ISOLEVEL", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_TRUE, 0, { 0 } },
    { 52, "MODULE", 0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 53, "VMP_PAGES", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 54, "LARGE_VMP_PAGES", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 55, "RES_CONTROL_GROUP", 0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_TRUE, 0, { 0 } },
    { 56, "RES_IO_WAIT_TIME", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 57, "RES_QUEUE_TIME", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 58, "PRIV_FLAG", 0, 0, CT_TYPE_INTEGER, 4, 0, 0, CT_FALSE, 0, { 0 } },
    { 59, "QUERY_SCN", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 60, "STMT_COUNT", 0, 0, CT_TYPE_INTEGER, 4, 0, 0, CT_FALSE, 0, { 0 } },
    { 61, "MIN_SCN", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 62, "PREV_SQL_ID", 0, 0, CT_TYPE_VARCHAR, CT_MAX_UINT32_STRLEN, 0, 0, CT_TRUE, 0, { 0 } },
    { 63, "DCS_BUFFER_GETS", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 64, "DCS_BUFFER_SENDS", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 65, "DCS_CR_GETS", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    { 66, "DCS_CR_SENDS", 0, 0, CT_TYPE_BIGINT, 8, 0, 0, CT_FALSE, 0, { 0 } },
    // !!!please sync your changes to g_global_session_columns
};

static knl_column_t g_session_ex_columns[] = {
    { 0, "SID",             0, 0, CT_TYPE_INTEGER, 4,                        0, 0, CT_FALSE, 0, { 0 } },
    { 1, "SQL_ID",          0, 0, CT_TYPE_VARCHAR, CT_MAX_UINT32_STRLEN,     0, 0, CT_TRUE,  0, { 0 } },
    { 2, "EVENT#",          0, 0, CT_TYPE_INTEGER, 4,                        0, 0, CT_FALSE, 0, { 0 } },
    { 3, "EVENT",           0, 0, CT_TYPE_VARCHAR, 64,                       0, 0, CT_FALSE, 0, { 0 } },
    { 4, "CONN_NODE",       0, 0, CT_TYPE_INTEGER, 4,                        0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_session_wait_columns[] = {
    { 0, "SID",             0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "EVENT#",          0, 0, CT_TYPE_INTEGER, 4,              0, 0, CT_FALSE, 0, { 0 } },
    { 2, "EVENT",           0, 0, CT_TYPE_VARCHAR, 64,             0, 0, CT_FALSE, 0, { 0 } },
    { 3, "P1",              0, 0, CT_TYPE_VARCHAR, 64,             0, 0, CT_FALSE, 0, { 0 } },
    { 4, "WAIT_CLASS",      0, 0, CT_TYPE_VARCHAR, 64,             0, 0, CT_FALSE, 0, { 0 } },
    { 5, "STATE",           0, 0, CT_TYPE_VARCHAR, 64,             0, 0, CT_TRUE,  0, { 0 } },
    { 6, "WAIT_BEGIN_TIME", 0, 0, CT_TYPE_DATE,    sizeof(uint64), 0, 0, CT_TRUE,  0, { 0 } },
    { 7, "WAIT_TIME_MIRCO", 0, 0, CT_TYPE_BIGINT,  sizeof(uint64), 0, 0, CT_TRUE,  0, { 0 } },
    { 8, "SECONDS_IN_WAIT", 0, 0, CT_TYPE_BIGINT,  sizeof(uint64), 0, 0, CT_TRUE,  0, { 0 } },
    { 9, "TENANT_ID",       0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_session_event_columns[] = {
    { 0, "SID",                0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 1, "EVENT#",             0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 2, "EVENT",              0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 3, "P1",                 0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 4, "WAIT_CLASS",         0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 5, "TOTAL_WAITS",        0, 0, CT_TYPE_BIGINT,  sizeof(uint64),  0, 0, CT_FALSE, 0, { 0 } },
    { 6, "TIME_WAITED",        0, 0, CT_TYPE_BIGINT,  sizeof(uint64),  0, 0, CT_FALSE, 0, { 0 } },
    { 7, "TIME_WAITED_MIRCO",  0, 0, CT_TYPE_BIGINT,  sizeof(uint64),  0, 0, CT_FALSE, 0, { 0 } },
    { 8, "AVERAGE_WAIT",       0, 0, CT_TYPE_REAL,    sizeof(double),  0, 0, CT_TRUE,  0, { 0 } },
    { 9, "AVERAGE_WAIT_MIRCO", 0, 0, CT_TYPE_BIGINT,  sizeof(uint64),  0, 0, CT_TRUE,  0, { 0 } },
    { 10, "TENANT_ID",         0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
};

#define SESSION_WAIT_COLS (sizeof(g_session_wait_columns) / sizeof(knl_column_t))
#define SESSION_EVENT_COLS (sizeof(g_session_event_columns) / sizeof(knl_column_t))
#define SESSION_COLS (sizeof(g_session_columns) / sizeof(knl_column_t))
#define SESSION_EX_COLS (sizeof(g_session_ex_columns) / sizeof(knl_column_t))

static void vw_make_session_event_row(knl_session_t *session, knl_cursor_t *cursor, knl_stat_t *stat)
{
    row_assist_t row;
    uint64 event_id = cursor->rowid.vm_slot;
    const wait_event_desc_t *desc = knl_get_event_desc((uint16)event_id);
    uint64 averge_us;
    dc_user_t *user = NULL;

    row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, SESSION_EVENT_COLS);
    CT_RETVOID_IFERR(row_put_int32(&row, (int32)session->id)); // SID
    CT_RETVOID_IFERR(row_put_int32(&row, (int32)event_id));    // EVENT#

    CT_RETVOID_IFERR(row_put_str(&row, desc->name));                                       // EVENT
    CT_RETVOID_IFERR(row_put_str(&row, desc->p1));                                         // P1
    CT_RETVOID_IFERR(row_put_str(&row, desc->wait_class));                                 // WAIT_CLASS
    CT_RETVOID_IFERR(row_put_int64(&row, (int64)stat->wait_count[cursor->rowid.vm_slot])); // TOTAL_WAITS
    // TIME_WAITED   1ms=1000000ns
    CT_RETVOID_IFERR(row_put_int64(&row, (int64)(stat->wait_time[cursor->rowid.vm_slot] / NANOSECS_PER_MILLISEC)));
    // TIME_WAITED_MIRCO
    CT_RETVOID_IFERR(row_put_int64(&row, (int64)stat->wait_time[cursor->rowid.vm_slot]));

    if (stat->wait_count[event_id] == 0) {
        CT_RETVOID_IFERR(row_put_null(&row)); // AVERAGE_WAIT
        CT_RETVOID_IFERR(row_put_null(&row)); // AVERAGE_WAIT_MIRCP
    } else {
        averge_us = stat->wait_time[event_id] / stat->wait_count[event_id];
        CT_RETVOID_IFERR(row_put_real(&row, (double)averge_us / NANOSECS_PER_MILLISEC));
        CT_RETVOID_IFERR(row_put_int64(&row, (int64)averge_us));
    }

    CT_RETVOID_IFERR(dc_open_user_by_id(session, session->uid, &user));
    CT_RETVOID_IFERR(row_put_int32(&row, (int32)user->desc.tenant_id));
    cursor->tenant_id = user->desc.tenant_id;

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
}

static void vw_next_event_session(knl_cursor_t *cursor)
{
    session_t *item = NULL;

    cursor->rowid.vmid++;

    while (cursor->rowid.vmid < g_instance->session_pool.hwm) {
        item = g_instance->session_pool.sessions[cursor->rowid.vmid];

        if (!item->is_free) {
            cursor->rowid.vm_slot = 0;
            break;
        }

        cursor->rowid.vmid++;
    }
}

static status_t vw_session_event_fetch_core(knl_handle_t session, knl_cursor_t *cursor)
{
    session_t *item = NULL;

    for (;;) {
        if (cursor->rowid.vmid >= g_instance->session_pool.hwm) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }

        item = g_instance->session_pool.sessions[cursor->rowid.vmid];

        for (;;) {
            uint16 stat_id = item->knl_session.stat_id;

            if (cursor->rowid.vm_slot >= (uint16)WAIT_EVENT_COUNT || item->is_free || stat_id == CT_INVALID_ID16) {
                vw_next_event_session(cursor);
                break;
            }

            knl_stat_t stat = *g_instance->stat_pool.stats[stat_id];

            if (stat.wait_count[cursor->rowid.vm_slot] == 0) {
                cursor->rowid.vm_slot++;
                continue;
            }

            vw_make_session_event_row(&item->knl_session, cursor, &stat);
            cursor->rowid.vm_slot++;
            return CT_SUCCESS;
        }
    }
}

static status_t vw_session_event_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    return vw_fetch_for_tenant(vw_session_event_fetch_core, session, cursor);
}

static status_t vw_make_session_wait_row(knl_handle_t session, knl_cursor_t *cursor, wait_event_t event)
{
    row_assist_t row;
    session_t *item = NULL;
    knl_session_wait_t wait;
    const wait_event_desc_t *desc = NULL;
    date_t now;
    dc_user_t *user = NULL;

    item = g_instance->session_pool.sessions[cursor->rowid.vmid];
    wait = item->knl_session.wait_pool[event];

    cursor->tenant_id = item->curr_tenant_id;
    row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, SESSION_WAIT_COLS);
    CT_RETURN_IFERR(row_put_int32(&row, (int32)item->knl_session.id));
    CT_RETURN_IFERR(row_put_int32(&row, (int32)wait.event));
    desc = knl_get_event_desc(wait.event);
    CT_RETURN_IFERR(row_put_str(&row, desc->name));
    CT_RETURN_IFERR(row_put_str(&row, desc->p1));
    CT_RETURN_IFERR(row_put_str(&row, desc->wait_class));

    if (wait.event != IDLE_WAIT) {
        CT_RETURN_IFERR(row_put_str(&row, wait.is_waiting ? "WAITING" : "WAITED SHORT TIME"));
        now = cm_now();

        if (wait.is_waiting) {
            CT_RETURN_IFERR(row_put_date(&row, wait.begin_time));
            CT_RETURN_IFERR(row_put_int64(&row, (int64)(now - wait.begin_time)));
            CT_RETURN_IFERR(row_put_int64(&row, (int64)((now - wait.begin_time) / NANOSECS_PER_MILLISEC)));
        } else {
            CT_RETURN_IFERR(row_put_null(&row));
            CT_RETURN_IFERR(row_put_null(&row));
            CT_RETURN_IFERR(row_put_null(&row));
        }
    } else {
        CT_RETURN_IFERR(row_put_null(&row));
        CT_RETURN_IFERR(row_put_null(&row));
        CT_RETURN_IFERR(row_put_null(&row));
        CT_RETURN_IFERR(row_put_null(&row));
    }

    CT_RETURN_IFERR(dc_open_user_by_id(&item->knl_session, item->knl_session.uid, &user));
    CT_RETURN_IFERR(row_put_int32(&row, (int32)user->desc.tenant_id));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    return CT_SUCCESS;
}

static status_t vw_session_wait_fetch_core(knl_handle_t session, knl_cursor_t *cursor)
{
    session_t *item = NULL;
    knl_session_wait_t wait;

    while (cursor->rowid.vmid < g_instance->session_pool.hwm) {
        item = g_instance->session_pool.sessions[cursor->rowid.vmid];
        if (item->is_free || cursor->rowid.vm_slot >= WAIT_EVENT_COUNT) {
            cursor->rowid.vmid++;
            cursor->rowid.vm_slot = 0;
            continue;
        }

        if (cursor->rowid.vm_slot == 0 && !knl_exist_session_wait(&item->knl_session)) {
            if (vw_make_session_wait_row(session, cursor, IDLE_WAIT) != CT_SUCCESS) {
                return CT_ERROR;
            }
            cursor->rowid.vmid++;
            return CT_SUCCESS;
        }

        wait = item->knl_session.wait_pool[cursor->rowid.vm_slot];
        if (wait.event == IDLE_WAIT) {
            cursor->rowid.vm_slot++;
            continue;
        }

        if (vw_make_session_wait_row(session, cursor, wait.event) != CT_SUCCESS) {
            return CT_ERROR;
        }

        cursor->rowid.vm_slot++;
        return CT_SUCCESS;
    }

    cursor->eof = CT_TRUE;
    return CT_SUCCESS;
}

static status_t vw_session_wait_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    return vw_fetch_for_tenant(vw_session_wait_fetch_core, session, cursor);
}

static char *vw_session_status(session_t *session)
{
    if (session->knl_session.canceled) {
        return "CANCELED";
    } else if (session->knl_session.killed) {
        return "KILLED";
    }

    switch (session->knl_session.status) {
        case SESSION_INACTIVE:
            return "INACTIVE";
        case SESSION_ACTIVE:
            return "ACTIVE";
        case SESSION_SUSPENSION:
            return "SUSPENSION";
        default:
            return "UNKNOWN";
    }
}

static char *vw_session_type(session_t *session)
{
    switch (session->type) {
        case SESSION_TYPE_BACKGROUND:
        case SESSION_TYPE_KERNEL_RESERVE:
            return "BACKGROUND";
        case SESSION_TYPE_AUTONOMOUS:
            return "AUTONOMOUS";
        case SESSION_TYPE_REPLICA:
            return "REPLICA";
        case SESSION_TYPE_SQL_PAR:
            return "SQL_PAR";
        case SESSION_TYPE_JOB:
            return "JOB";
        case SESSION_TYPE_EMERG:
            return "EMERG";
        default:
            return "USER";
    }
}

static char *vw_pipe_status(session_t *session)
{
    cs_pipe_t *pipe = SESSION_PIPE(session);
    switch (pipe->type) {
        case CS_TYPE_TCP:
            return "TCP";
        case CS_TYPE_IPC:
            return "IPC";
        case CS_TYPE_DOMAIN_SCOKET:
            return "UDS";
        case CS_TYPE_SSL:
            return "SSL";
        default:
            return "UNKNOWN";
    }
}

static void sql_exec_start(session_t *session, date_t *exec_start)
{
    *exec_start = 0;
    if (CM_IS_EMPTY(&session->current_sql) ||
        (session->ctx_prev_stat.tv_start.tv_sec == 0 && session->ctx_prev_stat.tv_start.tv_usec == 0)) {
        return;
    }

    *exec_start = cm_timeval2realdate(session->ctx_prev_stat.tv_start);
    return;
}

#define FILL_TCP_PIPE_INFO_RET(session, str, row)                                                                     \
    do {                                                                                                              \
        char __ip_str[CM_MAX_IP_LEN] = { 0 };                                                                         \
        PRTS_RETURN_IFERR(sprintf_s(str, sizeof(str), "%s",                                                           \
            cm_inet_ntop((struct sockaddr *)&SESSION_PIPE(session)->link.tcp.remote.addr, __ip_str, CM_MAX_IP_LEN))); \
        CT_RETURN_IFERR(row_put_str(row, str));                                                                       \
        PRTS_RETURN_IFERR(                                                                                            \
            sprintf_s(str, sizeof(str), "%u", ntohs(SOCKADDR_PORT(&SESSION_PIPE(session)->link.tcp.remote))));        \
        CT_RETURN_IFERR(row_put_str(row, str));                                                                       \
        CT_RETURN_IFERR(row_put_null(row));                                                                           \
        PRTS_RETURN_IFERR(sprintf_s(str, sizeof(str), "%s",                                                           \
            cm_inet_ntop((struct sockaddr *)&SESSION_PIPE(session)->link.tcp.local.addr, __ip_str, CM_MAX_IP_LEN)));  \
        CT_RETURN_IFERR(row_put_str(row, str));                                                                       \
        PRTS_RETURN_IFERR(                                                                                            \
            sprintf_s(str, sizeof(str), "%u", ntohs(SOCKADDR_PORT(&SESSION_PIPE(session)->link.tcp.local))));         \
        CT_RETURN_IFERR(row_put_str(row, str));                                                                       \
        CT_RETURN_IFERR(row_put_null(row));                                                                           \
    } while (0)

#define FILL_UDS_PIPE_INFO_RET(session, row)                                                     \
    do {                                                                                         \
        CT_RETURN_IFERR(row_put_null(row));                                                      \
        CT_RETURN_IFERR(row_put_null(row));                                                      \
        CT_RETURN_IFERR(row_put_str(row, SESSION_PIPE(session)->link.uds.remote.addr.sun_path)); \
        CT_RETURN_IFERR(row_put_null(row));                                                      \
        CT_RETURN_IFERR(row_put_null(row));                                                      \
        CT_RETURN_IFERR(row_put_str(row, SESSION_PIPE(session)->link.uds.local.addr.sun_path));  \
    } while (0)

static status_t vw_make_session_row(knl_handle_t curr_session, session_t *session, row_assist_t *row,
    knl_stat_t *knl_stat, wait_event_t event)
{
    char str[CT_BUFLEN_1K];
    date_t exec_start;
    sql_stat_t *sql_stat = &session->stat;
    knl_session_t *knl_session = &session->knl_session;
    uint16 wsid, wrmid;
    text_t spid_txt = { 0 };
    const wait_event_desc_t *desc = NULL;
    rsrc_group_t *group = session->rsrc_group;
    char hash_valstr[CT_MAX_UINT32_STRLEN + 1] = { 0 };

    // SID
    CT_RETURN_IFERR(row_put_int32(row, (int32)(session->knl_session.id)));
    // SPID
    spid_txt.str = str;
    MEMS_RETURN_IFERR(memset_s(spid_txt.str, CT_BUFLEN_1K, 0, CT_MAX_UINT32_STRLEN + 1));
    cm_uint32_to_text(session->knl_session.spid, &spid_txt);
    CT_RETURN_IFERR(row_put_text(row, &spid_txt));

    // SERIAL#
    CT_RETURN_IFERR(row_put_int32(row, (int32)(session->knl_session.serial_id)));
    // USER#
    CT_RETURN_IFERR(row_put_int32(row, (int32)(session->knl_session.uid)));
    // USERNAME
    CT_RETURN_IFERR(row_put_text(row, &session->curr_user));
    // CURRENT SCHEMA
    CT_RETURN_IFERR(row_put_str(row, session->curr_schema));

    // PIPE TYPE
    CT_RETURN_IFERR(row_put_str(row, vw_pipe_status(session)));

    // CLIENT_IP/CLIENT_PORT/CLIENT_UDS_PATH/SERVER_IP/SERVER_PORT/SERVER_UDS_PATH
    if (SESSION_PIPE(session)->type == CS_TYPE_TCP || SESSION_PIPE(session)->type == CS_TYPE_SSL) {
        FILL_TCP_PIPE_INFO_RET(session, str, row);
    } else {
#ifndef WIN32
        FILL_UDS_PIPE_INFO_RET(session, row);
#else
        FILL_TCP_PIPE_INFO_RET(session, str, row);
#endif
    }

    // SERVER_MODE
    CT_RETURN_IFERR(row_put_str(row, "MIXTRUE"));
    // OSUSER
    CT_RETURN_IFERR(row_put_str(row, session->os_user));
    // MACHINE
    CT_RETURN_IFERR(row_put_str(row, session->os_host));
    // PROGRAM
    CT_RETURN_IFERR(row_put_str(row, session->os_prog));
    // AUTO_COMMIT
    CT_RETURN_IFERR(row_put_bool(row, session->auto_commit));
    // CLIENT_VERSION
    CT_RETURN_IFERR(row_put_int32(row, (int32)(session->client_version)));
    // TYPE
    CT_RETURN_IFERR(row_put_str(row, vw_session_type(session)));
    // LOGON_TIME
    CT_RETURN_IFERR(row_put_date(row, session->logon_time));
    // STATUS
    CT_RETURN_IFERR(row_put_str(row, vw_session_status(session)));

    wrmid = session->knl_session.wrmid;
    if (wrmid == CT_INVALID_ID16) {
        CT_RETURN_IFERR(row_put_str(row, "N")); // LOCK_WAIT
        CT_RETURN_IFERR(row_put_null(row));     // WAIT_SID
    } else {
        CT_RETURN_IFERR(row_put_str(row, "Y")); // LOCK_WAIT
        wsid = knl_get_rm_sid(curr_session, wrmid);
        CT_RETURN_IFERR(row_put_int32(row, (int32)wsid)); // WAIT_SID
    }

    CT_RETURN_IFERR(row_put_int64(row, (int64)(sql_stat->exec_count)));                      // EXECUTIONS
    CT_RETURN_IFERR(row_put_int64(row, (int64)(sql_stat->directly_execs)));                  // SIMPLE_QUERIES
    CT_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->disk_reads)));                      // DISK_READS
    CT_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->buffer_gets + knl_stat->cr_gets))); // BUFFER_GETS
    CT_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->cr_gets)));                         // CR_GETS

    sql_exec_start(session, &exec_start);
    cm_spin_lock(&session->sess_lock, NULL);
    (void)cm_text2str(&session->current_sql, str, CT_BUFLEN_1K);
    uint32 sql_id = session->sql_id;
    cm_spin_unlock(&session->sess_lock);

    // CURRENT_SQL SQL_EXEC_START SQL_ID
    if (str[0] == 0) {
        CT_RETURN_IFERR(row_put_null(row));
        CT_RETURN_IFERR(row_put_null(row));
        CT_RETURN_IFERR(row_put_null(row));
    } else {
        CT_RETURN_IFERR(row_put_str(row, str));
        if (exec_start == 0) {
            CT_RETURN_IFERR(row_put_null(row));
        } else {
            CT_RETURN_IFERR(row_put_date(row, exec_start));
        }
        PRTS_RETURN_IFERR(sprintf_s(hash_valstr, (CT_MAX_UINT32_STRLEN + 1), "%010u", sql_id));
        CT_RETURN_IFERR(row_put_str(row, hash_valstr));
    }

    CT_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->atomic_opers)));    // ATOMIC_OPERS
    CT_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->redo_bytes)));      // REDO_BYTES
    CT_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->commits)));         // COMMITS
    CT_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->nowait_commits)));  // NOWAIT_COMMITS
    CT_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->xa_commits)));      // XA_COMMITS
    CT_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->rollbacks)));       // ROLLBACKS
    CT_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->xa_rollbacks)));    // XA_ROLLBACKS
    CT_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->local_txn_times))); // LOCAL_TXN_TIMES
    CT_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->xa_txn_times)));    // XA_TXN_TIMES
    CT_RETURN_IFERR(row_put_int64(row, (int64)(sql_stat->parses)));          // PARSES
    CT_RETURN_IFERR(row_put_int64(row, (int64)(sql_stat->hard_parses)));     // HARD_PARSES

    CT_RETURN_IFERR(row_put_int32(row, (int32)event));  // EVENT#
    desc = knl_get_event_desc(event);
    CT_RETURN_IFERR(row_put_str(row, desc->name));                          // EVENT
    CT_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->sorts)));          // SORTS
    CT_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->processed_rows))); // PROCESSED_ROWS
    CT_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->disk_read_time))); // IO_WAIT_TIME
    CT_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->con_wait_time)));  // CON_WAIT_TIME
    CT_RETURN_IFERR(row_put_int64(row, (int64)(sql_stat->cpu_time)));       // CPU_TIME
    CT_RETURN_IFERR(row_put_int64(row, (int64)(sql_stat->exec_time)));      // ELAPSED_TIME
    if (session->knl_session.rm != NULL) {
        CT_RETURN_IFERR(row_put_int64(row, (int64)(session->knl_session.rm->isolevel))); // ISOLEVEL
    } else {
        CT_RETURN_IFERR(row_put_null(row)); // ISOLEVEL
    }
    CT_RETURN_IFERR(row_put_text(row, (text_t *)cs_get_login_client_name(session->client_kind))); // MODULE

    CT_RETURN_IFERR(row_put_int64(row, (int64)(session->vmp.mpool.page_count)));       // VMP
    CT_RETURN_IFERR(row_put_int64(row, (int64)(session->vmp.large_mpool.page_count))); // LARGE VMP

    // CONTROL_GROUP
    if (group == NULL) {
        CT_RETURN_IFERR(row_put_null(row));
    } else {
        CT_RETURN_IFERR(row_put_str(row, group->knl_group.name));
    }

    CT_RETURN_IFERR(row_put_int64(row, (int64)sql_stat->res_io_wait_time));    // RES_IO_WAIT
    CT_RETURN_IFERR(row_put_int64(row, (int64)sql_stat->res_sess_queue_time)); // RES_QUEUE_TIME

    // PRIV_FLAG
    if (IS_COORDINATOR || IS_DATANODE) {
        CT_RETURN_IFERR(row_put_int32(row, (int32)(session->priv)));
    } else {
        CT_RETURN_IFERR(row_put_int32(row, 0));
    }

    CT_RETURN_IFERR(row_put_int64(row, (int64)(session->knl_session.query_scn))); // QUERY_SCN
    CT_RETURN_IFERR(row_put_int32(row, (int32)session->stmts_cnt));               // STMT_COUNT
    // MIN_SCN
    knl_scn_t min_local_scn = CT_INVALID_ID64;
    get_session_min_local_scn(knl_session, &min_local_scn);
    CT_RETURN_IFERR(row_put_int64(row, (int64)min_local_scn));

    // PREV_SQL_ID
    if (session->prev_sql_id == 0) {
        CT_RETURN_IFERR(row_put_null(row));
    } else {
        PRTS_RETURN_IFERR(sprintf_s(hash_valstr, (CT_MAX_UINT32_STRLEN + 1), "%010u", session->prev_sql_id));
        CT_RETURN_IFERR(row_put_str(row, hash_valstr));
    }

    CT_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->dcs_buffer_gets + knl_stat->dcs_cr_gets))); // DCS_BUFFER_GETS
    CT_RETURN_IFERR(
        row_put_int64(row, (int64)(knl_stat->dcs_buffer_sends + knl_stat->dcs_cr_sends))); // DCS_BUFFER_SENDS
    CT_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->dcs_cr_gets)));                   // DCS_CR_GETS
    CT_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->dcs_cr_sends)));                  // DCS_CR_SENDS

    return CT_SUCCESS;
}

static status_t vw_session_fetch_core(knl_handle_t curr_session, knl_cursor_t *cursor)
{
    uint16 stat_id;
    session_t *session = NULL;
    knl_stat_t stat = { 0 };
    knl_session_wait_t wait;

    while (cursor->rowid.vmid < g_instance->session_pool.hwm) {
        session = g_instance->session_pool.sessions[cursor->rowid.vmid];
        stat_id = session->knl_session.stat_id;
        if (session->is_free || stat_id == CT_INVALID_ID16 || cursor->rowid.vm_slot >= WAIT_EVENT_COUNT) {
            cursor->rowid.vmid++;
            cursor->rowid.vm_slot = 0;
            continue;
        }
        stat = *g_instance->stat_pool.stats[stat_id];
        cursor->tenant_id = session->curr_tenant_id;
        if (cursor->rowid.vm_slot == 0 && !knl_hang_session_wait(&session->knl_session)) {
            row_assist_t row;
            row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, SESSION_COLS);
            if (vw_make_session_row(curr_session, session, &row, &stat, IDLE_WAIT) != CT_SUCCESS) {
                return CT_ERROR;
            }
            cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
            cursor->rowid.vmid++;
            return CT_SUCCESS;
        }
        wait = session->knl_session.wait_pool[cursor->rowid.vm_slot];
        if (!wait.is_waiting) {
            cursor->rowid.vm_slot++;
            continue;
        }
        row_assist_t row;
        row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, SESSION_COLS);
        if (vw_make_session_row(curr_session, session, &row, &stat, wait.event) != CT_SUCCESS) {
            return CT_ERROR;
        }

        cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
        cursor->rowid.vm_slot++;
        return CT_SUCCESS;
    }

    cursor->eof = CT_TRUE;
    return CT_SUCCESS;
}

static status_t vw_session_fetch(knl_handle_t curr_session, knl_cursor_t *cursor)
{
    return vw_fetch_for_tenant(vw_session_fetch_core, curr_session, cursor);
}

static void vw_make_session_ex_row(session_t *session, knl_cursor_t *cursor, wait_event_t event)
{
    row_assist_t row;
    const wait_event_desc_t *desc = NULL;
    char hash_valstr[CT_MAX_UINT32_STRLEN + 1] = { 0 };

    row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, SESSION_EX_COLS);

    (void)row_put_int32(&row, (int32)(session->knl_session.id)); // SID
    if (CM_IS_EMPTY(&session->current_sql)) {
        (void)row_put_null(&row); // SQL_ID
    } else {
        PRTS_RETVOID_IFERR(sprintf_s(hash_valstr, (CT_MAX_UINT32_STRLEN + 1), "%010u", session->sql_id));
        (void)row_put_str(&row, hash_valstr); // SQL_ID
    }

    (void)row_put_int32(&row, (int32)event);  // EVENT#
    desc = knl_get_event_desc(event);
    (void)row_put_str(&row, desc->name); // EVENT


    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    return;
}

static status_t vw_session_ex_fetch_core(knl_handle_t curr_session, knl_cursor_t *cursor)
{
    session_t *session = NULL;
    knl_session_wait_t wait;
    while (cursor->rowid.vmid < g_instance->session_pool.hwm) {
        session = g_instance->session_pool.sessions[cursor->rowid.vmid];
        if (session->is_free || cursor->rowid.vm_slot >= WAIT_EVENT_COUNT) {
            cursor->rowid.vmid++;
            cursor->rowid.vm_slot = 0;
            continue;
        }
        if (cursor->rowid.vm_slot == 0 && !knl_hang_session_wait(&session->knl_session)) {
            vw_make_session_ex_row(session, cursor, IDLE_WAIT);
            cursor->rowid.vmid++;
            return CT_SUCCESS;
        }
        wait = session->knl_session.wait_pool[cursor->rowid.vm_slot];
        if (!wait.is_waiting) {
            cursor->rowid.vm_slot++;
            continue;
        }
        vw_make_session_ex_row(session, cursor, wait.event);
        cursor->rowid.vm_slot++;
        return CT_SUCCESS;
    }
    cursor->eof = CT_TRUE;
    return CT_SUCCESS;
}

static status_t vw_session_ex_fetch(knl_handle_t curr_session, knl_cursor_t *cursor)
{
    return vw_fetch_for_tenant(vw_session_ex_fetch_core, curr_session, cursor);
}

VW_DECL g_dv_session_wait = { "SYS",          "DV_SESSION_WAITS",   SESSION_WAIT_COLS, g_session_wait_columns,
                              vw_common_open, vw_session_wait_fetch };
VW_DECL g_dv_session_event = { "SYS",          "DV_SESSION_EVENTS",   SESSION_EVENT_COLS, g_session_event_columns,
                               vw_common_open, vw_session_event_fetch };
VW_DECL g_dv_session = { "SYS", "DV_SESSIONS", SESSION_COLS, g_session_columns, vw_common_open, vw_session_fetch };
VW_DECL g_dv_session_ex = { "SYS",          "DV_SESSIONS_EX",   SESSION_EX_COLS, g_session_ex_columns,
                            vw_common_open, vw_session_ex_fetch };

dynview_desc_t *vw_describe_session(uint32 id)
{
    switch ((dynview_id_t)id) {
        case DYN_VIEW_SESSION_WAIT:
            return &g_dv_session_wait;
        case DYN_VIEW_SESSION_EVENT:
            return &g_dv_session_event;
        case DYN_VIEW_SESSION:
            return &g_dv_session;
        case DYN_VIEW_SESSION_EX:
            return &g_dv_session_ex;
        default:
            return NULL;
    }
}

