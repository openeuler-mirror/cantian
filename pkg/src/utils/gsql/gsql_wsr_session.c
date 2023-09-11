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
 * gsql_wsr_session.c
 *
 *
 * IDENTIFICATION
 * src/utils/gsql/gsql_wsr_session.c
 *
 * -------------------------------------------------------------------------
 */
#include "gsql_wsr_session.h"

#define GS_WSR_TOP_EVENT_NUM             (uint32)2

typedef struct st_wsr_session {
    char sid[MAX_WSR_ENTITY_LEN];
    char wait_time[MAX_WSR_ENTITY_LEN];
    char waits[MAX_WSR_ENTITY_LEN];
    char event1[MAX_WSR_ENTITY_LEN];
    char event_wait_time1[MAX_WSR_ENTITY_LEN];
    char event_waits1[MAX_WSR_ENTITY_LEN];
    char event_avg_wait_time1[MAX_WSR_ENTITY_LEN];
    char event2[MAX_WSR_ENTITY_LEN];
    char event_wait_time2[MAX_WSR_ENTITY_LEN];
    char event_waits2[MAX_WSR_ENTITY_LEN];
    char event_avg_wait_time2[MAX_WSR_ENTITY_LEN];
} wsr_session_t;

typedef struct st_wsr_session_sql {
    char elapsed[MAX_WSR_ENTITY_LEN];
    char sid[MAX_WSR_ENTITY_LEN];
    char sql_id[MAX_WSR_ENTITY_LEN];
    char prev_sql_id[MAX_WSR_ENTITY_LEN];
    char curr_schema[MAX_WSR_ENTITY_LEN];
    char client_ip[MAX_WSR_ENTITY_LEN];
    char program[MAX_WSR_ENTITY_LEN];
    char auto_commit[MAX_WSR_ENTITY_LEN];
    char logon_time[MAX_WSR_ENTITY_LEN];
    char wait_sid[MAX_WSR_ENTITY_LEN];
    char sql_exec_start[MAX_WSR_ENTITY_LEN];
    char ctime[MAX_WSR_ENTITY_LEN];
    char module[MAX_WSR_ENTITY_LEN];
    char event[MAX_WSR_ENTITY_LEN];
    char sql_text[MAX_WSR_ENTITY_LEN];
} wsr_session_sql_t;

typedef struct st_wsr_cursor {
    char sid[MAX_WSR_ENTITY_LEN];
    char stmt_id[MAX_WSR_ENTITY_LEN];
    char user_name[MAX_WSR_ENTITY_LEN];
    char sql_text[MAX_WSR_ENTITY_LEN];
    char sql_type[MAX_WSR_ENTITY_LEN];
    char sql_id[MAX_WSR_ENTITY_LEN];
    char status[MAX_WSR_ENTITY_LEN];
    char cursor_type[MAX_WSR_ENTITY_LEN];
    char vm_open_pages[MAX_WSR_ENTITY_LEN];
    char vm_close_pages[MAX_WSR_ENTITY_LEN];
    char vm_swapin_pages[MAX_WSR_ENTITY_LEN];
    char vm_free_pages[MAX_WSR_ENTITY_LEN];
    char query_scn[MAX_WSR_ENTITY_LEN];
    char last_sql_active_time[MAX_WSR_ENTITY_LEN];
} wsr_cursor_t;

int wsr_build_top_session_head_html(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"30007-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Session Statistics %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts, "<font face=\"Courier New, Courier, mono\" color=\"#666\">Session Statistics</font>");
    }
    wsr_write_str2(wsr_opts, "<!-- <h2 class=\"wsr\">Session Statistics</h2> -->");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover\" >");
    wsr_write_str2(wsr_opts, "  <thead><tr>");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a class=\"wsrg\" href=\"#300-%u\">Session ordered by Wait Time</a></td>", wsr_info->dbid);
    wsr_write_str2(wsr_opts, "    </tr><tr>");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        " <td><a class=\"wsrg\" href=\"#310-%u\">Session ordered by Long SQL</a></td>", wsr_info->dbid);
    wsr_write_str2(wsr_opts, "    </tr><tr>");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a class=\"wsrg\" href=\"#320-%u\">Session ordered by Long Transaction</a></td>", wsr_info->dbid);
    wsr_write_str2(wsr_opts, "    </tr><tr>");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a class=\"wsrg\" href=\"#330-%u\">Session ordered by Long Cursor(Start Snap)</a></td>", wsr_info->dbid);
    wsr_write_str2(wsr_opts, "    </tr><tr>");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a class=\"wsrg\" href=\"#340-%u\">Session ordered by Long Cursor(End Snap)</a></td>", wsr_info->dbid);
    wsr_write_str2(wsr_opts, "    </tr><tr>");
    wsr_write_str2(wsr_opts, "      <td><a class=\"wsrg\" href=\"#top\">Back to Top</a></td>");
    wsr_write_str2(wsr_opts, "    </tr></thead></table><p />");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"300-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Session ordered by Wait Time %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Session ordered by Wait Time</font>");
    }
    wsr_write_str2(wsr_opts, "<!-- <h2 class=\"wsr\">Session ordered by Wait Time</h2> -->");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover\"><thead><tr>");
    wsr_write_str2(wsr_opts, "<th>SID</th><th>Wait Time (s)</th>");
    wsr_write_str2(wsr_opts, "<th>Total Waits</th><th>Top 1 Event</th>");
    wsr_write_str2(wsr_opts, "<th>Top 1 Wait Time (s)</th><th>Top 1 Waits</th>");
    wsr_write_str2(wsr_opts, "<th>Top 1 Avg Wait Time (ms)</th><th>Top 2 Event</th>");
    wsr_write_str2(wsr_opts, "<th>Top 2 Wait Time (s)</th><th>Top 2 Waits</th>");
    wsr_write_str2(wsr_opts, "<th>Top 2 Avg Wait Time (ms)</th></tr></thead><tbody>");
    
    return GSC_SUCCESS;
}

int wsr_build_top_session_content_html(wsr_options_t *wsr_opts, wsr_session_t *wsr_session)
{
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "  <td>%s</td>", wsr_session->sid);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "    <td>%s</td>", wsr_session->wait_time);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "    <td>%s</td>", wsr_session->waits);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "    <td>%s</td>", wsr_session->event1);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "    <td>%s</td>", wsr_session->event_wait_time1);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "    <td>%s</td>", wsr_session->event_waits1);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "    <td>%s</td>", wsr_session->event_avg_wait_time1);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "    <td>%s</td>", wsr_session->event2);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "    <td>%s</td>", wsr_session->event_wait_time2);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "    <td>%s</td>", wsr_session->event_waits2);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "    <td>%s</td>", wsr_session->event_avg_wait_time2);
    wsr_write_str2(wsr_opts, "</tr>");
    return GSC_SUCCESS;
}

int wsr_build_top_session_init(wsr_session_t *wsr_session)
{
    MEMS_RETURN_IFERR(strncpy_s(wsr_session->event1, MAX_WSR_ENTITY_LEN, "&nbsp", WSR_HTML_NBSP_LEN));
    MEMS_RETURN_IFERR(strncpy_s(wsr_session->event_wait_time1, MAX_WSR_ENTITY_LEN, "&nbsp", WSR_HTML_NBSP_LEN));
    MEMS_RETURN_IFERR(strncpy_s(wsr_session->event_waits1, MAX_WSR_ENTITY_LEN, "&nbsp", WSR_HTML_NBSP_LEN));
    MEMS_RETURN_IFERR(strncpy_s(wsr_session->event_avg_wait_time1, MAX_WSR_ENTITY_LEN, "&nbsp", WSR_HTML_NBSP_LEN));
    MEMS_RETURN_IFERR(strncpy_s(wsr_session->event2, MAX_WSR_ENTITY_LEN, "&nbsp", WSR_HTML_NBSP_LEN));
    MEMS_RETURN_IFERR(strncpy_s(wsr_session->event_wait_time2, MAX_WSR_ENTITY_LEN, "&nbsp", WSR_HTML_NBSP_LEN));
    MEMS_RETURN_IFERR(strncpy_s(wsr_session->event_waits2, MAX_WSR_ENTITY_LEN, "&nbsp", WSR_HTML_NBSP_LEN));
    MEMS_RETURN_IFERR(strncpy_s(wsr_session->event_avg_wait_time2, MAX_WSR_ENTITY_LEN, "&nbsp", WSR_HTML_NBSP_LEN));

    return GSC_SUCCESS;
}

int wsr_build_top_session_build_row(wsr_session_t *wsr_session, gsc_stmt_t *resultset_event)
{
    uint32 index2;
    uint32 index3;
    status_t ret;
    uint32 rows;

    GS_RETURN_IFERR(gsc_fetch(*resultset_event, &rows));

    index2 = 0;

    if (rows != 0) {
        ret = gsc_column_as_string(*resultset_event, index2++, wsr_session->event1, MAX_WSR_ENTITY_LEN);
        GS_RETURN_IFERR(ret);
        ret = gsc_column_as_string(*resultset_event, index2++, wsr_session->event_wait_time1, MAX_WSR_ENTITY_LEN);
        GS_RETURN_IFERR(ret);
        ret = gsc_column_as_string(*resultset_event, index2++, wsr_session->event_waits1, MAX_WSR_ENTITY_LEN);
        GS_RETURN_IFERR(ret);
        ret = gsc_column_as_string(*resultset_event, index2++, wsr_session->event_avg_wait_time1, MAX_WSR_ENTITY_LEN);
        GS_RETURN_IFERR(ret);
    }

    GS_RETURN_IFERR(gsc_fetch(*resultset_event, &rows));

    index3 = 0;

    if (rows != 0) {
        ret = gsc_column_as_string(*resultset_event, index3++, wsr_session->event2, MAX_WSR_ENTITY_LEN);
        GS_RETURN_IFERR(ret);
        ret = gsc_column_as_string(*resultset_event, index3++, wsr_session->event_wait_time2, MAX_WSR_ENTITY_LEN);
        GS_RETURN_IFERR(ret);
        ret = gsc_column_as_string(*resultset_event, index3++, wsr_session->event_waits2, MAX_WSR_ENTITY_LEN);
        GS_RETURN_IFERR(ret);
        ret = gsc_column_as_string(*resultset_event, index3++, wsr_session->event_avg_wait_time2, MAX_WSR_ENTITY_LEN);
        GS_RETURN_IFERR(ret);
    }
    return GSC_SUCCESS;
}

int wsr_build_top_session(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    uint32 rows;
    gsc_stmt_t resultset;
    gsc_stmt_t resultset_event;
    char cmd_buf[MAX_CMD_LEN + 1];
    gsc_stmt_t stmt2;
    wsr_session_t wsr_session;
    uint32 index1;

    GS_RETURN_IFERR(wsr_build_top_session_head_html(wsr_opts, wsr_info));
    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN, "CALL SYS.WSR$TOPSESSION(%u, %u, %u)",
        wsr_opts->start_snap_id, wsr_opts->end_snap_id, wsr_info->topnsql));

    GS_RETURN_IFERR(gsc_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(wsr_opts->curr_stmt));
    GS_RETURN_IFERR(gsc_get_implicit_resultset(wsr_opts->curr_stmt, &resultset));

    do {
        GS_RETURN_IFERR(gsc_fetch(resultset, &rows));
        if (rows == 0) {
            break;
        }

        index1 = 0;

        GS_RETURN_IFERR(gsc_column_as_string(resultset, index1++, wsr_session.sid, MAX_WSR_ENTITY_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(resultset, index1++, wsr_session.wait_time, MAX_WSR_ENTITY_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(resultset, index1++, wsr_session.waits, MAX_WSR_ENTITY_LEN));

        PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN, "CALL SYS.WSR$TOPSESSION_TOPEVENT(%u, %u, %u, %s)",
            wsr_opts->start_snap_id, wsr_opts->end_snap_id, GS_WSR_TOP_EVENT_NUM, wsr_session.sid));

        GS_RETURN_IFERR(gsc_alloc_stmt(wsr_opts->curr_conn, &stmt2));
        GS_RETURN_IFERR(wsr_build_top_session_init(&wsr_session));
        GS_RETURN_IFERR(gsc_prepare(stmt2, (const char *)cmd_buf));
        GS_RETURN_IFERR(gsc_execute(stmt2));
        GS_RETURN_IFERR(gsc_get_implicit_resultset(stmt2, &resultset_event));
        GS_RETURN_IFERR(wsr_build_top_session_build_row(&wsr_session, &resultset_event));
        GS_RETURN_IFERR(wsr_build_top_session_content_html(wsr_opts, &wsr_session));

        gsc_free_stmt(stmt2);
    } while (GS_TRUE);

    wsr_write_str2(wsr_opts, "</tbody></table><p />");

    return GSC_SUCCESS;
}

int wsr_build_top_session_sql_head(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"310-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Session ordered by Long SQL %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Session ordered by Long SQL</font>");
    }
    wsr_write_str2(wsr_opts, "<!-- <h2 class=\"wsr\">Session ordered by Long SQL</h2> -->");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover\">");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_str2(wsr_opts, "<th>Elapsed Time (s)</th>");
    wsr_write_str2(wsr_opts, "<th>SID</th>");
    wsr_write_str2(wsr_opts, "<th>SQL ID</th>");
    wsr_write_str2(wsr_opts, "<th>PREV_SQL ID</th>");
    wsr_write_str2(wsr_opts, "<th>Schema</th>");
    wsr_write_str2(wsr_opts, "<th>Client IP</th>");
    wsr_write_str2(wsr_opts, "<th>Program</th>");
    wsr_write_str2(wsr_opts, "<th>Auto Commit</th>");
    wsr_write_str2(wsr_opts, "<th>Logon time</th>");
    wsr_write_str2(wsr_opts, "<th>Wait SID</th>");
    wsr_write_str2(wsr_opts, "<th>SQL Exec Start</th>");
    wsr_write_str2(wsr_opts, "<th>Snap Time</th>");
    wsr_write_str2(wsr_opts, "<th>Module</th>");
    wsr_write_str2(wsr_opts, "<th>Event</th>");
    wsr_write_str2(wsr_opts, "<th>SQL Text</th>");
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "<tbody>");

    return GSC_SUCCESS;
}

int wsr_build_top_session_sql_row(wsr_options_t *wsr_opts, wsr_info_t *wsr_info, wsr_session_sql_t *wsr_session_sql)
{
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td>%s</td>", wsr_session_sql->elapsed);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td>%s</td>", wsr_session_sql->sid);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td><a class=\"wsrc\" href=\"#%s-%u\">%s</a></td>",
        wsr_session_sql->sql_id, wsr_info->dbid, wsr_session_sql->sql_id);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td><a class=\"wsrc\" href=\"#%s-%u\">%s</a></td>",
        wsr_session_sql->prev_sql_id, wsr_info->dbid, wsr_session_sql->prev_sql_id);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td>%s</td>", wsr_session_sql->curr_schema);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td>%s</td>", wsr_session_sql->client_ip);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td>%s</td>", wsr_session_sql->program);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td>%s</td>", wsr_session_sql->auto_commit);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td>%s</td>", wsr_session_sql->logon_time);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td>%s</td>", wsr_session_sql->wait_sid);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td>%s</td>", wsr_session_sql->sql_exec_start);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td>%s</td>", wsr_session_sql->ctime);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td>%s</td>", wsr_session_sql->module);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td>%s</td>", wsr_session_sql->event);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td>%s</td>", wsr_session_sql->sql_text);
    wsr_write_str2(wsr_opts, "</tr>");

    return GSC_SUCCESS;
}

int wsr_build_top_session_sql(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    uint32 rows;
    gsc_stmt_t resultset;
    char cmd_buf[MAX_CMD_LEN + 1];
    uint32 index;
    wsr_session_sql_t wsr_session_sql;

    GS_RETURN_IFERR(wsr_build_top_session_sql_head(wsr_opts, wsr_info));

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN, "CALL SYS.WSR$QUERY_TOPSESSION_SQL(%u, %u, %u, '%s', '%s')",
        wsr_opts->start_snap_id, wsr_opts->end_snap_id, wsr_info->topnsql, wsr_info->start_time, wsr_info->end_time));

    GS_RETURN_IFERR(gsc_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(wsr_opts->curr_stmt));
    GS_RETURN_IFERR(gsc_get_implicit_resultset(wsr_opts->curr_stmt, &resultset));

    do {
        GS_RETURN_IFERR(gsc_fetch(resultset, &rows));
        if (rows == 0) {
            break;
        }

        index = 0;

        GS_RETURN_IFERR(gsc_column_as_string(resultset, index++, wsr_session_sql.elapsed, MAX_WSR_ENTITY_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(resultset, index++, wsr_session_sql.sid, MAX_WSR_ENTITY_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(resultset, index++, wsr_session_sql.sql_id, MAX_WSR_ENTITY_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(resultset, index++, wsr_session_sql.prev_sql_id, MAX_WSR_ENTITY_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(resultset, index++, wsr_session_sql.curr_schema, MAX_WSR_ENTITY_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(resultset, index++, wsr_session_sql.client_ip, MAX_WSR_ENTITY_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(resultset, index++, wsr_session_sql.program, MAX_WSR_ENTITY_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(resultset, index++, wsr_session_sql.auto_commit, MAX_WSR_ENTITY_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(resultset, index++, wsr_session_sql.logon_time, MAX_WSR_ENTITY_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(resultset, index++, wsr_session_sql.wait_sid, MAX_WSR_ENTITY_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(resultset, index++, wsr_session_sql.sql_exec_start, WSR_MAX_RECEV_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(resultset, index++, wsr_session_sql.ctime, MAX_WSR_ENTITY_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(resultset, index++, wsr_session_sql.module, MAX_WSR_ENTITY_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(resultset, index++, wsr_session_sql.event, MAX_WSR_ENTITY_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(resultset, index++, wsr_session_sql.sql_text, MAX_WSR_ENTITY_LEN));

        GS_RETURN_IFERR(wsr_insert_sql_list(wsr_opts, wsr_session_sql.sql_id, ""));

        GS_RETURN_IFERR(wsr_build_top_session_sql_row(wsr_opts, wsr_info, &wsr_session_sql));
    } while (GS_TRUE);
    wsr_write_str2(wsr_opts, "</tbody>");
    wsr_write_str2(wsr_opts, "</table><p />");

    return GSC_SUCCESS;
}

static void wsr_build_top_session_trans_write_str(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"320-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Session ordered by Long Transaction %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Session ordered by Long Transaction</font>");
    }
    wsr_write_str2(wsr_opts, "<!-- <h2 class=\"wsr\">Session ordered by Long Transaction</h2> -->");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover\">");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_str2(wsr_opts, "<th>Elapsed Time (s)</th>");
    wsr_write_str2(wsr_opts, "<th>SID</th>");
    wsr_write_str2(wsr_opts, "<th>Undo Count</th>");
    wsr_write_str2(wsr_opts, "<th>Begin Time</th>");
    wsr_write_str2(wsr_opts, "<th>Snap Time</th>");
    wsr_write_str2(wsr_opts, "<th>SQL ID</th>");
    wsr_write_str2(wsr_opts, "<th>SQL Text</th>");
    wsr_write_str2(wsr_opts, "<th>Locked Table</th>");
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "<tbody>");
}

int wsr_build_top_session_trans(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    uint32 rows;
    gsc_stmt_t resultset;
    char elapsed[MAX_WSR_ENTITY_LEN];
    char sid[MAX_WSR_ENTITY_LEN];
    char undo_count[MAX_WSR_ENTITY_LEN];
    char begin_time[MAX_WSR_ENTITY_LEN];
    char snap_time[MAX_WSR_ENTITY_LEN];
    char sql_id[MAX_WSR_ENTITY_LEN];
    char sql_text[MAX_WSR_ENTITY_LEN];
    char cmd_buf[MAX_CMD_LEN + 1];
    char str_buf[WSR_MAX_RECEV_LEN + 1];
    uint32 index;

    wsr_build_top_session_trans_write_str(wsr_opts, wsr_info);

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN, "CALL SYS.WSR$QUERY_TRANSACTION(%u, %u, %u, '%s', '%s')",
        wsr_opts->start_snap_id, wsr_opts->end_snap_id, wsr_info->topnsql, wsr_info->start_time, wsr_info->end_time));

    GS_RETURN_IFERR(gsc_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(wsr_opts->curr_stmt));
    GS_RETURN_IFERR(gsc_get_implicit_resultset(wsr_opts->curr_stmt, &resultset));

    do {
        GS_RETURN_IFERR(gsc_fetch(resultset, &rows));
        if (rows == 0) {
            break;
        }

        index = 0;
        
        GS_RETURN_IFERR(gsc_column_as_string(resultset, index++, elapsed, MAX_WSR_ENTITY_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(resultset, index++, sid, MAX_WSR_ENTITY_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(resultset, index++, undo_count, MAX_WSR_ENTITY_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(resultset, index++, begin_time, MAX_WSR_ENTITY_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(resultset, index++, snap_time, MAX_WSR_ENTITY_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(resultset, index++, sql_id, MAX_WSR_ENTITY_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(resultset, index++, sql_text, MAX_WSR_ENTITY_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(resultset, index++, str_buf, WSR_MAX_RECEV_LEN));

        GS_RETURN_IFERR(wsr_insert_sql_list(wsr_opts, sql_id, ""));

        wsr_write_str2(wsr_opts, "<tr>");
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td>%s</td>", elapsed);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td>%s</td>", sid);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td>%s</td>", undo_count);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td>%s</td>", begin_time);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td>%s</td>", snap_time);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000,
            "<td><a class=\"wsrc\" href=\"#%s-%u\">%s</a></td>", sql_id, wsr_info->dbid, sql_id);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td>%s</td>", sql_text);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td>%s</td>", str_buf);
        wsr_write_str2(wsr_opts, "</tr>");
    } while (GS_TRUE);
    wsr_write_str2(wsr_opts, "</tbody>");
    wsr_write_str2(wsr_opts, "</table><p />");

    return GSC_SUCCESS;
}

static void wsr_build_top_cursors_write_common(wsr_options_t *wsr_opts)
{
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover\">");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_str2(wsr_opts, "<th>SID</th>");
    wsr_write_str2(wsr_opts, "<th>STMT ID</th>");
    wsr_write_str2(wsr_opts, "<th>User Name</th>");
    wsr_write_str2(wsr_opts, "<th>SQL Text</th>");
    wsr_write_str2(wsr_opts, "<th>SQL Type</th>");
    wsr_write_str2(wsr_opts, "<th>SQL ID</th>");
    wsr_write_str2(wsr_opts, "<th>Status</th>");
    wsr_write_str2(wsr_opts, "<th>Cursor Type</th>");
    wsr_write_str2(wsr_opts, "<th>VM Open Pages</th>");
    wsr_write_str2(wsr_opts, "<th>VM Close Pages</th>");
    wsr_write_str2(wsr_opts, "<th>VM Swapin Pages</th>");
    wsr_write_str2(wsr_opts, "<th>VM Free Pages</th>");
    wsr_write_str2(wsr_opts, "<th>Query SCN</th>");
    wsr_write_str2(wsr_opts, "<th>Last SQL Active Time</th>");
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "<tbody>");
}

static void wsr_build_top_cursors_write_start(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"330-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">"
            "Session ordered by Long Cursor(Start Snap) %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">"
            "Session ordered by Long Cursor(Start Snap)</font>");
    }
    wsr_write_str2(wsr_opts, "<!-- <h2 class=\"wsr\">Session ordered by Long Cursor(Start Snap)</h2> -->");
    wsr_build_top_cursors_write_common(wsr_opts);
}

static void wsr_build_top_cursors_write_end(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"340-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">"
            "Session ordered by Long Cursor(End Snap) %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">"
            "Session ordered by Long Cursor(End Snap)</font>");
    }
    wsr_write_str2(wsr_opts, "<!-- <h2 class=\"wsr\">Session ordered by Long Cursor(End Snap)</h2> -->");
    wsr_build_top_cursors_write_common(wsr_opts);
}

int wsr_build_top_session_cursors_query(wsr_options_t *wsr_opts, gsc_stmt_t *resultset, wsr_cursor_t *wsr_cursor)
{
    uint32 i_cnt = 0;

    GS_RETURN_IFERR(gsc_column_as_string(*resultset, i_cnt++, wsr_cursor->sid, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, i_cnt++, wsr_cursor->stmt_id, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, i_cnt++, wsr_cursor->user_name, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, i_cnt++, wsr_cursor->sql_text, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, i_cnt++, wsr_cursor->sql_type, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, i_cnt++, wsr_cursor->sql_id, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, i_cnt++, wsr_cursor->status, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, i_cnt++, wsr_cursor->cursor_type, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, i_cnt++, wsr_cursor->vm_open_pages, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, i_cnt++, wsr_cursor->vm_close_pages, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, i_cnt++, wsr_cursor->vm_swapin_pages, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, i_cnt++, wsr_cursor->vm_free_pages, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, i_cnt++, wsr_cursor->query_scn, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, i_cnt++, wsr_cursor->last_sql_active_time, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(wsr_insert_sql_list(wsr_opts, wsr_cursor->sql_id, ""));
    return GSC_SUCCESS;
}

int wsr_build_top_session_cursors_common(wsr_options_t *wsr_opts, wsr_info_t *wsr_info, uint32 snapid)
{
    uint32 rows;
    gsc_stmt_t resultset;
    wsr_cursor_t wsr_cursor;
    char cmd_buf[MAX_CMD_LEN + 1];

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN, "CALL SYS.WSR$QUERY_LONG_CURSOR(%u, %u)",
        snapid, wsr_info->topnsql));

    GS_RETURN_IFERR(gsc_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(wsr_opts->curr_stmt));
    GS_RETURN_IFERR(gsc_get_implicit_resultset(wsr_opts->curr_stmt, &resultset));

    do {
        GS_RETURN_IFERR(gsc_fetch(resultset, &rows));
        if (rows == 0) {
            break;
        }

        GS_RETURN_IFERR(wsr_build_top_session_cursors_query(wsr_opts, &resultset, &wsr_cursor));

        wsr_write_str2(wsr_opts, "<tr>");
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td>%s</td>", wsr_cursor.sid);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td>%s</td>", wsr_cursor.stmt_id);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td>%s</td>", wsr_cursor.user_name);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td>%s</td>", wsr_cursor.sql_text);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td>%s</td>", wsr_cursor.sql_type);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000,
            "<td><a class=\"wsrc\" href=\"#%s-%u\">%s</a></td>", wsr_cursor.sql_id, wsr_info->dbid,
            wsr_cursor.sql_id);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td>%s</td>", wsr_cursor.status);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td>%s</td>", wsr_cursor.cursor_type);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td>%s</td>", wsr_cursor.vm_open_pages);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td>%s</td>", wsr_cursor.vm_close_pages);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td>%s</td>", wsr_cursor.vm_swapin_pages);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td>%s</td>", wsr_cursor.vm_free_pages);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td>%s</td>", wsr_cursor.query_scn);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td>%s</td>", wsr_cursor.last_sql_active_time);
        wsr_write_str2(wsr_opts, "</tr>");
    } while (GS_TRUE);
    wsr_write_str2(wsr_opts, "</tbody>");
    wsr_write_str2(wsr_opts, "</table><p />");

    return GSC_SUCCESS;
}

int wsr_build_top_session_cursors_start(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    wsr_build_top_cursors_write_start(wsr_opts, wsr_info);
    GS_RETURN_IFERR(wsr_build_top_session_cursors_common(wsr_opts, wsr_info, wsr_opts->start_snap_id));

    return GSC_SUCCESS;
}

int wsr_build_top_session_cursors_end(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    wsr_build_top_cursors_write_end(wsr_opts, wsr_info);
    GS_RETURN_IFERR(wsr_build_top_session_cursors_common(wsr_opts, wsr_info, wsr_opts->end_snap_id));

    return GSC_SUCCESS;
}