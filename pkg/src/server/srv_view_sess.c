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
 * srv_view_sess.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_view_sess.c
 *
 * -------------------------------------------------------------------------
 */

#include "srv_view_sess.h"
#include "srv_instance.h"

// !!!please sync your edits to g_global_session_columns
static knl_column_t g_session_columns[] = {
    // session columns
    { 0, "SID", 0, 0, GS_TYPE_INTEGER, 4, 0, 0, GS_FALSE, 0, { 0 } },
    { 1, "SPID", 0, 0, GS_TYPE_VARCHAR, GS_MAX_UINT32_STRLEN + 1, 0, 0, GS_FALSE, 0, { 0 } },
    { 2, "SERIAL#", 0, 0, GS_TYPE_INTEGER, 4, 0, 0, GS_FALSE, 0, { 0 } },
    { 3, "USER#", 0, 0, GS_TYPE_INTEGER, 4, 0, 0, GS_FALSE, 0, { 0 } },
    { 4, "USERNAME", 0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN, 0, 0, GS_FALSE, 0, { 0 } },
    { 5, "CURR_SCHEMA", 0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN, 0, 0, GS_FALSE, 0, { 0 } },
    { 6, "PIPE_TYPE", 0, 0, GS_TYPE_VARCHAR, 20, 0, 0, GS_FALSE, 0, { 0 } },
    { 7, "CLIENT_IP", 0, 0, GS_TYPE_VARCHAR, CM_MAX_IP_LEN, 0, 0, GS_TRUE, 0, { 0 } },
    { 8, "CLIENT_PORT", 0, 0, GS_TYPE_VARCHAR, 10, 0, 0, GS_TRUE, 0, { 0 } },
    { 9, "CLIENT_UDS_PATH", 0, 0, GS_TYPE_VARCHAR, GS_UNIX_PATH_MAX, 0, 0, GS_TRUE, 0, { 0 } },
    { 10, "SERVER_IP", 0, 0, GS_TYPE_VARCHAR, CM_MAX_IP_LEN, 0, 0, GS_TRUE, 0, { 0 } },
    { 11, "SERVER_PORT", 0, 0, GS_TYPE_VARCHAR, 10, 0, 0, GS_TRUE, 0, { 0 } },
    { 12, "SERVER_UDS_PATH", 0, 0, GS_TYPE_VARCHAR, GS_UNIX_PATH_MAX, 0, 0, GS_TRUE, 0, { 0 } },
    { 13, "SERVER_MODE", 0, 0, GS_TYPE_VARCHAR, 10, 0, 0, GS_FALSE, 0, { 0 } },
    { 14, "OSUSER", 0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN, 0, 0, GS_FALSE, 0, { 0 } },
    { 15, "MACHINE", 0, 0, GS_TYPE_VARCHAR, CM_MAX_IP_LEN, 0, 0, GS_FALSE, 0, { 0 } },
    { 16, "PROGRAM", 0, 0, GS_TYPE_VARCHAR, 256, 0, 0, GS_FALSE, 0, { 0 } },
    { 17, "AUTO_COMMIT", 0, 0, GS_TYPE_BOOLEAN, sizeof(bool32), 0, 0, GS_FALSE, 0, { 0 } },
    { 18, "CLIENT_VERSION", 0, 0, GS_TYPE_INTEGER, 4, 0, 0, GS_FALSE, 0, { 0 } },
    { 19, "TYPE", 0, 0, GS_TYPE_VARCHAR, 10, 0, 0, GS_FALSE, 0, { 0 } },
    { 20, "LOGON_TIME", 0, 0, GS_TYPE_DATE, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 21, "STATUS", 0, 0, GS_TYPE_VARCHAR, 10, 0, 0, GS_FALSE, 0, { 0 } },
    { 22, "LOCK_WAIT", 0, 0, GS_TYPE_VARCHAR, 4, 0, 0, GS_FALSE, 0, { 0 } },
    { 23, "WAIT_SID", 0, 0, GS_TYPE_INTEGER, 4, 0, 0, GS_TRUE, 0, { 0 } },
    { 24, "EXECUTIONS", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 25, "SIMPLE_QUERIES", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 26, "DISK_READS", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 27, "BUFFER_GETS", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 28, "CR_GETS", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 29, "CURRENT_SQL", 0, 0, GS_TYPE_VARCHAR, GS_BUFLEN_1K, 0, 0, GS_TRUE, 0, { 0 } },
    { 30, "SQL_EXEC_START", 0, 0, GS_TYPE_DATE, 8, 0, 0, GS_TRUE, 0, { 0 } },
    { 31, "SQL_ID", 0, 0, GS_TYPE_VARCHAR, GS_MAX_UINT32_STRLEN, 0, 0, GS_TRUE, 0, { 0 } },
    { 32, "ATOMIC_OPERS", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 33, "REDO_BYTES", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 34, "COMMITS", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 35, "NOWAIT_COMMITS", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 36, "XA_COMMITS", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 37, "ROLLBACKS", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 38, "XA_ROLLBACKS", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 39, "LOCAL_TXN_TIMES", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 40, "XA_TXN_TIMES", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 41, "PARSES", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 42, "HARD_PARSES", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 43, "EVENT#", 0, 0, GS_TYPE_INTEGER, 4, 0, 0, GS_FALSE, 0, { 0 } },
    { 44, "EVENT", 0, 0, GS_TYPE_VARCHAR, 64, 0, 0, GS_FALSE, 0, { 0 } },
    { 45, "SORTS", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 46, "PROCESSED_ROWS", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 47, "IO_WAIT_TIME", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 48, "CON_WAIT_TIME", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 49, "CPU_TIME", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 50, "ELAPSED_TIME", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 51, "ISOLEVEL", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_TRUE, 0, { 0 } },
    { 52, "MODULE", 0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN, 0, 0, GS_FALSE, 0, { 0 } },
    { 53, "VMP_PAGES", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 54, "LARGE_VMP_PAGES", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 55, "RES_CONTROL_GROUP", 0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN, 0, 0, GS_TRUE, 0, { 0 } },
    { 56, "RES_IO_WAIT_TIME", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 57, "RES_QUEUE_TIME", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 58, "PRIV_FLAG", 0, 0, GS_TYPE_INTEGER, 4, 0, 0, GS_FALSE, 0, { 0 } },
    { 59, "QUERY_SCN", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 60, "STMT_COUNT", 0, 0, GS_TYPE_INTEGER, 4, 0, 0, GS_FALSE, 0, { 0 } },
    { 61, "MIN_SCN", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 62, "PREV_SQL_ID", 0, 0, GS_TYPE_VARCHAR, GS_MAX_UINT32_STRLEN, 0, 0, GS_TRUE, 0, { 0 } },
    { 63, "DCS_BUFFER_GETS", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 64, "DCS_BUFFER_SENDS", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 65, "DCS_CR_GETS", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    { 66, "DCS_CR_SENDS", 0, 0, GS_TYPE_BIGINT, 8, 0, 0, GS_FALSE, 0, { 0 } },
    // !!!please sync your changes to g_global_session_columns
};

static knl_column_t g_session_ex_columns[] = {
    { 0, "SID",             0, 0, GS_TYPE_INTEGER, 4,                        0, 0, GS_FALSE, 0, { 0 } },
    { 1, "SQL_ID",          0, 0, GS_TYPE_VARCHAR, GS_MAX_UINT32_STRLEN,     0, 0, GS_TRUE,  0, { 0 } },
    { 2, "EVENT#",          0, 0, GS_TYPE_INTEGER, 4,                        0, 0, GS_FALSE, 0, { 0 } },
    { 3, "EVENT",           0, 0, GS_TYPE_VARCHAR, 64,                       0, 0, GS_FALSE, 0, { 0 } },
    { 4, "CONN_NODE",       0, 0, GS_TYPE_INTEGER, 4,                        0, 0, GS_FALSE, 0, { 0 } },
};

static knl_column_t g_session_wait_columns[] = {
    { 0, "SID",             0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 } },
    { 1, "EVENT#",          0, 0, GS_TYPE_INTEGER, 4,              0, 0, GS_FALSE, 0, { 0 } },
    { 2, "EVENT",           0, 0, GS_TYPE_VARCHAR, 64,             0, 0, GS_FALSE, 0, { 0 } },
    { 3, "P1",              0, 0, GS_TYPE_VARCHAR, 64,             0, 0, GS_FALSE, 0, { 0 } },
    { 4, "WAIT_CLASS",      0, 0, GS_TYPE_VARCHAR, 64,             0, 0, GS_FALSE, 0, { 0 } },
    { 5, "STATE",           0, 0, GS_TYPE_VARCHAR, 64,             0, 0, GS_TRUE,  0, { 0 } },
    { 6, "WAIT_BEGIN_TIME", 0, 0, GS_TYPE_DATE,    sizeof(uint64), 0, 0, GS_TRUE,  0, { 0 } },
    { 7, "WAIT_TIME_MIRCO", 0, 0, GS_TYPE_BIGINT,  sizeof(uint64), 0, 0, GS_TRUE,  0, { 0 } },
    { 8, "SECONDS_IN_WAIT", 0, 0, GS_TYPE_BIGINT,  sizeof(uint64), 0, 0, GS_TRUE,  0, { 0 } },
    { 9, "TENANT_ID",       0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 } },
};

static knl_column_t g_session_event_columns[] = {
    { 0, "SID",                0, 0, GS_TYPE_INTEGER, sizeof(uint32),  0, 0, GS_FALSE, 0, { 0 } },
    { 1, "EVENT#",             0, 0, GS_TYPE_INTEGER, sizeof(uint32),  0, 0, GS_FALSE, 0, { 0 } },
    { 2, "EVENT",              0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN, 0, 0, GS_FALSE, 0, { 0 } },
    { 3, "P1",                 0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN, 0, 0, GS_FALSE, 0, { 0 } },
    { 4, "WAIT_CLASS",         0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN, 0, 0, GS_FALSE, 0, { 0 } },
    { 5, "TOTAL_WAITS",        0, 0, GS_TYPE_BIGINT,  sizeof(uint64),  0, 0, GS_FALSE, 0, { 0 } },
    { 6, "TIME_WAITED",        0, 0, GS_TYPE_BIGINT,  sizeof(uint64),  0, 0, GS_FALSE, 0, { 0 } },
    { 7, "TIME_WAITED_MIRCO",  0, 0, GS_TYPE_BIGINT,  sizeof(uint64),  0, 0, GS_FALSE, 0, { 0 } },
    { 8, "AVERAGE_WAIT",       0, 0, GS_TYPE_REAL,    sizeof(double),  0, 0, GS_TRUE,  0, { 0 } },
    { 9, "AVERAGE_WAIT_MIRCO", 0, 0, GS_TYPE_BIGINT,  sizeof(uint64),  0, 0, GS_TRUE,  0, { 0 } },
    { 10, "TENANT_ID",         0, 0, GS_TYPE_INTEGER, sizeof(uint32),  0, 0, GS_FALSE, 0, { 0 } },
};

#define SESSION_WAIT_COLS (sizeof(g_session_wait_columns) / sizeof(knl_column_t))
#define SESSION_EVENT_COLS (sizeof(g_session_event_columns) / sizeof(knl_column_t))
#define SESSION_COLS (sizeof(g_session_columns) / sizeof(knl_column_t))
#define SESSION_EX_COLS (sizeof(g_session_ex_columns) / sizeof(knl_column_t))

static void vw_make_session_event_row(knl_session_t *session, knl_cursor_t *cur, knl_stat_t *stat)
{
    row_assist_t row;
    uint64 event_id = cur->rowid.vm_slot;
    const wait_event_desc_t *desc = knl_get_event_desc((uint16)event_id);
    uint64 averge_us;
    dc_user_t *user = NULL;

    row_init(&row, (char *)cur->row, GS_MAX_ROW_SIZE, SESSION_EVENT_COLS);
    GS_RETVOID_IFERR(row_put_int32(&row, (int32)session->id)); // SID
    GS_RETVOID_IFERR(row_put_int32(&row, (int32)event_id));    // EVENT#

    GS_RETVOID_IFERR(row_put_str(&row, desc->name));                                       // EVENT
    GS_RETVOID_IFERR(row_put_str(&row, desc->p1));                                         // P1
    GS_RETVOID_IFERR(row_put_str(&row, desc->wait_class));                                 // WAIT_CLASS
    GS_RETVOID_IFERR(row_put_int64(&row, (int64)stat->wait_count[cur->rowid.vm_slot])); // TOTAL_WAITS
    // TIME_WAITED   1ms=1000000ns
    GS_RETVOID_IFERR(row_put_int64(&row, (int64)(stat->wait_time[cur->rowid.vm_slot] / NANOSECS_PER_MILLISEC)));
    // TIME_WAITED_MIRCO
    GS_RETVOID_IFERR(row_put_int64(&row, (int64)stat->wait_time[cur->rowid.vm_slot]));

    if (stat->wait_count[event_id] == 0) {
        GS_RETVOID_IFERR(row_put_null(&row)); // AVERAGE_WAIT
        GS_RETVOID_IFERR(row_put_null(&row)); // AVERAGE_WAIT_MIRCP
    } else {
        averge_us = stat->wait_time[event_id] / stat->wait_count[event_id];
        GS_RETVOID_IFERR(row_put_real(&row, (double)averge_us / NANOSECS_PER_MILLISEC));
        GS_RETVOID_IFERR(row_put_int64(&row, (int64)averge_us));
    }

    GS_RETVOID_IFERR(dc_open_user_by_id(session, session->uid, &user));
    GS_RETVOID_IFERR(row_put_int32(&row, (int32)user->desc.tenant_id));
    cur->tenant_id = user->desc.tenant_id;

    cm_decode_row((char *)cur->row, cur->offsets, cur->lens, &cur->data_size);
}

static void vw_next_event_session(knl_cursor_t *cur)
{
    session_t *item = NULL;

    cur->rowid.vmid++;

    while (cur->rowid.vmid < g_instance->session_pool.hwm) {
        item = g_instance->session_pool.sessions[cur->rowid.vmid];

        if (!item->is_free) {
            cur->rowid.vm_slot = 0;
            break;
        }

        cur->rowid.vmid++;
    }
}

static status_t vw_session_event_fetch_core(knl_handle_t session, knl_cursor_t *cur)
{
    session_t *item = NULL;

    for (;;) {
        if (cur->rowid.vmid >= g_instance->session_pool.hwm) {
            cur->eof = GS_TRUE;
            return GS_SUCCESS;
        }

        item = g_instance->session_pool.sessions[cur->rowid.vmid];

        for (;;) {
            uint16 stat_id = item->knl_session.stat_id;

            if (cur->rowid.vm_slot >= (uint16)WAIT_EVENT_COUNT || item->is_free || stat_id == GS_INVALID_ID16) {
                vw_next_event_session(cur);
                break;
            }

            knl_stat_t stat = *g_instance->stat_pool.stats[stat_id];

            if (stat.wait_count[cur->rowid.vm_slot] == 0) {
                cur->rowid.vm_slot++;
                continue;
            }

            vw_make_session_event_row(&item->knl_session, cur, &stat);
            cur->rowid.vm_slot++;
            return GS_SUCCESS;
        }
    }
}

static status_t vw_session_event_fetch(knl_handle_t session, knl_cursor_t *cur)
{
    return vw_fetch_for_tenant(vw_session_event_fetch_core, session, cur);
}

static status_t vw_session_wait_fetch_one_row(knl_cursor_t *cur)
{
    row_assist_t row;
    session_t *item = NULL;
    knl_session_wait_t wait;
    const wait_event_desc_t *desc = NULL;
    date_t now;
    bool32 is_waiting;
    dc_user_t *user = NULL;

    item = g_instance->session_pool.sessions[cur->rowid.vmid];
    wait = item->knl_session.wait;

    cur->tenant_id = item->curr_tenant_id;
    row_init(&row, (char *)cur->row, GS_MAX_ROW_SIZE, SESSION_WAIT_COLS);
    GS_RETURN_IFERR(row_put_int32(&row, (int32)item->knl_session.id));
    GS_RETURN_IFERR(row_put_int32(&row, (int32)wait.event));
    desc = knl_get_event_desc(wait.event);
    GS_RETURN_IFERR(row_put_str(&row, desc->name));
    GS_RETURN_IFERR(row_put_str(&row, desc->p1));
    GS_RETURN_IFERR(row_put_str(&row, desc->wait_class));

    is_waiting = item->knl_session.is_waiting;
    if (wait.event != IDLE_WAIT) {
        GS_RETURN_IFERR(row_put_str(&row, is_waiting ? "WAITING" : "WAITED SHORT TIME"));
        now = cm_now();

        if (is_waiting) {
            GS_RETURN_IFERR(row_put_date(&row, wait.begin_time));
            GS_RETURN_IFERR(row_put_int64(&row, (int64)(now - wait.begin_time)));
            GS_RETURN_IFERR(row_put_int64(&row, (int64)((now - wait.begin_time) / NANOSECS_PER_MILLISEC)));
        } else {
            GS_RETURN_IFERR(row_put_null(&row));
            GS_RETURN_IFERR(row_put_null(&row));
            GS_RETURN_IFERR(row_put_null(&row));
        }
    } else {
        GS_RETURN_IFERR(row_put_null(&row));
        GS_RETURN_IFERR(row_put_null(&row));
        GS_RETURN_IFERR(row_put_null(&row));
        GS_RETURN_IFERR(row_put_null(&row));
    }

    GS_RETURN_IFERR(dc_open_user_by_id(&item->knl_session, item->knl_session.uid, &user));
    GS_RETURN_IFERR(row_put_int32(&row, (int32)user->desc.tenant_id));

    cm_decode_row((char *)cur->row, cur->offsets, cur->lens, &cur->data_size);
    cur->rowid.vmid++;
    return GS_SUCCESS;
}

static status_t vw_session_wait_fetch_core(knl_handle_t session, knl_cursor_t *cur)
{
    session_t *item = NULL;

    if (cur->rowid.vmid >= g_instance->session_pool.hwm) {
        cur->eof = GS_TRUE;
        return GS_SUCCESS;
    }

    while (cur->rowid.vmid < g_instance->session_pool.hwm) {
        item = g_instance->session_pool.sessions[cur->rowid.vmid];
        if (!item->is_free) {
            break;
        }

        cur->rowid.vmid++;
    }

    if (cur->rowid.vmid >= g_instance->session_pool.hwm) {
        cur->eof = GS_TRUE;
        return GS_SUCCESS;
    }

    return vw_session_wait_fetch_one_row(cur);
}

static status_t vw_session_wait_fetch(knl_handle_t session, knl_cursor_t *cur)
{
    return vw_fetch_for_tenant(vw_session_wait_fetch_core, session, cur);
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

#define FILL_TCP_PIPE_INFO_RET(session, str, row)                                                                     \
    do {                                                                                                              \
        char __ip_str[CM_MAX_IP_LEN] = { 0 };                                                                         \
        PRTS_RETURN_IFERR(sprintf_s(str, sizeof(str), "%s",                                                           \
            cm_inet_ntop((struct sockaddr *)&SESSION_PIPE(session)->link.tcp.remote.addr, __ip_str, CM_MAX_IP_LEN))); \
        GS_RETURN_IFERR(row_put_str(row, str));                                                                       \
        PRTS_RETURN_IFERR(                                                                                            \
            sprintf_s(str, sizeof(str), "%u", ntohs(SOCKADDR_PORT(&SESSION_PIPE(session)->link.tcp.remote))));        \
        GS_RETURN_IFERR(row_put_str(row, str));                                                                       \
        GS_RETURN_IFERR(row_put_null(row));                                                                           \
        PRTS_RETURN_IFERR(sprintf_s(str, sizeof(str), "%s",                                                           \
            cm_inet_ntop((struct sockaddr *)&SESSION_PIPE(session)->link.tcp.local.addr, __ip_str, CM_MAX_IP_LEN)));  \
        GS_RETURN_IFERR(row_put_str(row, str));                                                                       \
        PRTS_RETURN_IFERR(                                                                                            \
            sprintf_s(str, sizeof(str), "%u", ntohs(SOCKADDR_PORT(&SESSION_PIPE(session)->link.tcp.local))));         \
        GS_RETURN_IFERR(row_put_str(row, str));                                                                       \
        GS_RETURN_IFERR(row_put_null(row));                                                                           \
    } while (0)

#define FILL_UDS_PIPE_INFO_RET(session, row)                                                     \
    do {                                                                                         \
        GS_RETURN_IFERR(row_put_null(row));                                                      \
        GS_RETURN_IFERR(row_put_null(row));                                                      \
        GS_RETURN_IFERR(row_put_str(row, SESSION_PIPE(session)->link.uds.remote.addr.sun_path)); \
        GS_RETURN_IFERR(row_put_null(row));                                                      \
        GS_RETURN_IFERR(row_put_null(row));                                                      \
        GS_RETURN_IFERR(row_put_str(row, SESSION_PIPE(session)->link.uds.local.addr.sun_path));  \
    } while (0)

static status_t vw_make_each_session_rows(knl_handle_t curr_sess, session_t *session, row_assist_t *row,
    knl_stat_t *knl_stat)
{
    char str[GS_BUFLEN_1K];
    knl_session_t *knl_session = &session->knl_session;
    uint16 wsid, wrmid;
    text_t spid_txt = { 0 };
    wait_event_t event_no;
    const wait_event_desc_t *desc = NULL;
    char hash_valstr[GS_MAX_UINT32_STRLEN + 1] = { 0 };

    // SID
    GS_RETURN_IFERR(row_put_int32(row, (int32)(session->knl_session.id)));
    // SPID
    spid_txt.str = str;
    MEMS_RETURN_IFERR(memset_s(spid_txt.str, GS_BUFLEN_1K, 0, GS_MAX_UINT32_STRLEN + 1));
    cm_uint32_to_text(session->knl_session.spid, &spid_txt);
    GS_RETURN_IFERR(row_put_text(row, &spid_txt));

    // SERIAL#
    GS_RETURN_IFERR(row_put_int32(row, (int32)(session->knl_session.serial_id)));
    // USER#
    GS_RETURN_IFERR(row_put_int32(row, (int32)(session->knl_session.uid)));
    // USERNAME
    GS_RETURN_IFERR(row_put_text(row, &session->curr_user));
    // CURRENT SCHEMA
    GS_RETURN_IFERR(row_put_str(row, session->curr_schema));

    // PIPE TYPE
    GS_RETURN_IFERR(row_put_str(row, vw_pipe_status(session)));

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
    GS_RETURN_IFERR(row_put_str(row, "MIXTRUE"));
    // OSUSER
    GS_RETURN_IFERR(row_put_str(row, session->os_user));
    // MACHINE
    GS_RETURN_IFERR(row_put_str(row, session->os_host));
    // PROGRAM
    GS_RETURN_IFERR(row_put_str(row, session->os_prog));
    // AUTO_COMMIT
    GS_RETURN_IFERR(row_put_bool(row, session->auto_commit));
    // CLIENT_VERSION
    GS_RETURN_IFERR(row_put_int32(row, (int32)(session->client_version)));
    // TYPE
    GS_RETURN_IFERR(row_put_str(row, vw_session_type(session)));
    // LOGON_TIME
    GS_RETURN_IFERR(row_put_date(row, session->logon_time));
    // STATUS
    GS_RETURN_IFERR(row_put_str(row, vw_session_status(session)));

    wrmid = session->knl_session.wrmid;
    if (wrmid == GS_INVALID_ID16) {
        GS_RETURN_IFERR(row_put_str(row, "N")); // LOCK_WAIT
        GS_RETURN_IFERR(row_put_null(row));     // WAIT_SID
    } else {
        GS_RETURN_IFERR(row_put_str(row, "Y")); // LOCK_WAIT
        wsid = knl_get_rm_sid(curr_sess, wrmid);
        GS_RETURN_IFERR(row_put_int32(row, (int32)wsid)); // WAIT_SID
    }

    GS_RETURN_IFERR(row_put_int64(row, (int64)(0)));                      // EXECUTIONS
    GS_RETURN_IFERR(row_put_int64(row, (int64)(0)));                  // SIMPLE_QUERIES
    GS_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->disk_reads)));                      // DISK_READS
    GS_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->buffer_gets + knl_stat->cr_gets))); // BUFFER_GETS
    GS_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->cr_gets)));                         // CR_GETS

    cm_spin_lock(&session->sess_lock, NULL);
    (void)cm_text2str(&session->current_sql, str, GS_BUFLEN_1K);
    uint32 sql_id = session->sql_id;
    cm_spin_unlock(&session->sess_lock);

    // CURRENT_SQL SQL_EXEC_START SQL_ID
    if (str[0] == 0) {
        GS_RETURN_IFERR(row_put_null(row));
        GS_RETURN_IFERR(row_put_null(row));
        GS_RETURN_IFERR(row_put_null(row));
    } else {
        GS_RETURN_IFERR(row_put_str(row, str));
        GS_RETURN_IFERR(row_put_null(row));
        PRTS_RETURN_IFERR(sprintf_s(hash_valstr, (GS_MAX_UINT32_STRLEN + 1), "%010u", sql_id));
        GS_RETURN_IFERR(row_put_str(row, hash_valstr));
    }

    GS_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->atomic_opers)));    // ATOMIC_OPERS
    GS_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->redo_bytes)));      // REDO_BYTES
    GS_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->commits)));         // COMMITS
    GS_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->nowait_commits)));  // NOWAIT_COMMITS
    GS_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->xa_commits)));      // XA_COMMITS
    GS_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->rollbacks)));       // ROLLBACKS
    GS_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->xa_rollbacks)));    // XA_ROLLBACKS
    GS_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->local_txn_times))); // LOCAL_TXN_TIMES
    GS_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->xa_txn_times)));    // XA_TXN_TIMES
    GS_RETURN_IFERR(row_put_int64(row, (int64)(0)));          // PARSES
    GS_RETURN_IFERR(row_put_int64(row, (int64)(0)));     // HARD_PARSES

    event_no = (session->knl_session.is_waiting) ? session->knl_session.wait.event : IDLE_WAIT;
    GS_RETURN_IFERR(row_put_int32(row, (int32)event_no)); // EVENT#
    desc = knl_get_event_desc(event_no);
    GS_RETURN_IFERR(row_put_str(row, desc->name));                          // EVENT
    GS_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->sorts)));          // SORTS
    GS_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->processed_rows))); // PROCESSED_ROWS
    GS_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->disk_read_time))); // IO_WAIT_TIME
    GS_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->con_wait_time)));  // CON_WAIT_TIME
    GS_RETURN_IFERR(row_put_int64(row, (int64)(0)));       // CPU_TIME
    GS_RETURN_IFERR(row_put_int64(row, (int64)(0)));      // ELAPSED_TIME
    if (session->knl_session.rm != NULL) {
        GS_RETURN_IFERR(row_put_int64(row, (int64)(session->knl_session.rm->isolevel))); // ISOLEVEL
    } else {
        GS_RETURN_IFERR(row_put_null(row)); // ISOLEVEL
    }
    GS_RETURN_IFERR(row_put_text(row, (text_t *)cs_get_login_client_name(session->client_kind))); // MODULE

    GS_RETURN_IFERR(row_put_int64(row, (int64)(session->vmp.mpool.page_count)));       // VMP
    GS_RETURN_IFERR(row_put_int64(row, (int64)(session->vmp.large_mpool.page_count))); // LARGE VMP

    GS_RETURN_IFERR(row_put_null(row));

    GS_RETURN_IFERR(row_put_int64(row, (int64)0));    // RES_IO_WAIT
    GS_RETURN_IFERR(row_put_int64(row, (int64)0)); // RES_QUEUE_TIME

    // PRIV_FLAG
    if (IS_COORDINATOR || IS_DATANODE) {
        GS_RETURN_IFERR(row_put_int32(row, (int32)(session->priv)));
    } else {
        GS_RETURN_IFERR(row_put_int32(row, 0));
    }

    GS_RETURN_IFERR(row_put_int64(row, (int64)(session->knl_session.query_scn))); // QUERY_SCN
    GS_RETURN_IFERR(row_put_int32(row, (int32)session->stmts_cnt));               // STMT_COUNT
    // MIN_SCN
    knl_scn_t min_local_scn = GS_INVALID_ID64;
    get_sess_min_local_scn(knl_session, &min_local_scn);
    GS_RETURN_IFERR(row_put_int64(row, (int64)min_local_scn));

    // PREV_SQL_ID
    if (session->prev_sql_id == 0) {
        GS_RETURN_IFERR(row_put_null(row));
    } else {
        PRTS_RETURN_IFERR(sprintf_s(hash_valstr, (GS_MAX_UINT32_STRLEN + 1), "%010u", session->prev_sql_id));
        GS_RETURN_IFERR(row_put_str(row, hash_valstr));
    }

    GS_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->dcs_buffer_gets + knl_stat->dcs_cr_gets))); // DCS_BUFFER_GETS
    GS_RETURN_IFERR(
        row_put_int64(row, (int64)(knl_stat->dcs_buffer_sends + knl_stat->dcs_cr_sends))); // DCS_BUFFER_SENDS
    GS_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->dcs_cr_gets)));                   // DCS_CR_GETS
    GS_RETURN_IFERR(row_put_int64(row, (int64)(knl_stat->dcs_cr_sends)));                  // DCS_CR_SENDS

    return GS_SUCCESS;
}

static status_t vw_make_session_rows(knl_handle_t curr_sess, knl_cursor_t *cur)
{
    session_t *session = NULL;
    row_assist_t row;
    knl_stat_t stat = { 0 };

    while (GS_TRUE) {
        if (cur->rowid.vmid >= g_instance->session_pool.hwm) {
            cur->eof = GS_TRUE;
            return GS_SUCCESS;
        }

        session = g_instance->session_pool.sessions[cur->rowid.vmid];
        uint16 stat_id = session->knl_session.stat_id;
        if (!session->is_free && stat_id != GS_INVALID_ID16) {
            stat = *g_instance->stat_pool.stats[stat_id];
            break;
        }

        cur->rowid.vmid++;
    }

    row_init(&row, (char *)cur->row, GS_MAX_ROW_SIZE, SESSION_COLS);
    cur->tenant_id = session->curr_tenant_id;
    GS_RETURN_IFERR(vw_make_each_session_rows(curr_sess, session, &row, &stat));
    cm_decode_row((char *)cur->row, cur->offsets, cur->lens, &cur->data_size);
    cur->rowid.vmid++;
    return GS_SUCCESS;
}

static status_t vw_session_fetch(knl_handle_t curr_sess, knl_cursor_t *cur)
{
    return vw_fetch_for_tenant(vw_make_session_rows, curr_sess, cur);
}

static status_t vw_session_ex_fetch(knl_handle_t curr_sess, knl_cursor_t *cur)
{
    row_assist_t row;
    wait_event_t event_no;
    session_t *session = NULL;
    bool32 flag = GS_TRUE;
    const wait_event_desc_t *desc = NULL;
    char hash_valstr[GS_MAX_UINT32_STRLEN + 1] = { 0 };

    while (flag) {
        if (cur->rowid.vmid >= g_instance->session_pool.hwm) {
            cur->eof = GS_TRUE;
            return GS_SUCCESS;
        }

        session = g_instance->session_pool.sessions[cur->rowid.vmid];
        if (!session->is_free) {
            break;
        }

        cur->rowid.vmid++;
    }

    row_init(&row, (char *)cur->row, GS_MAX_ROW_SIZE, SESSION_EX_COLS);

    (void)row_put_int32(&row, (int32)(session->knl_session.id)); // SID
    if (CM_IS_EMPTY(&session->current_sql)) {
        (void)row_put_null(&row); // SQL_ID
    } else {
        PRTS_RETURN_IFERR(sprintf_s(hash_valstr, (GS_MAX_UINT32_STRLEN + 1), "%010u", session->sql_id));
        (void)row_put_str(&row, hash_valstr); // SQL_ID
    }

    event_no = (session->knl_session.is_waiting) ? session->knl_session.wait.event : IDLE_WAIT;
    (void)row_put_int32(&row, (int32)event_no); // EVENT#
    desc = knl_get_event_desc(event_no);
    (void)row_put_str(&row, desc->name); // EVENT

    (void)(row_put_uint32(&row, 0)); // CONN NODE

    cm_decode_row((char *)cur->row, cur->offsets, cur->lens, &cur->data_size);
    cur->rowid.vmid++;
    return GS_SUCCESS;
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

