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
 * ctsql_wsr_analyse.c
 *
 *
 * IDENTIFICATION
 * src/utils/ctsql/ctsql_wsr_analyse.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_wsr_analyse.h"

#define CT_WSR_DEFAULT_CPU_NUM             (uint32)8
#define CT_WSR_LOAD_RATE_VERY_HIGH         10
#define CT_WSR_LOAD_RATE_HIGH              1
#define CT_WSR_LOAD_RATE_MEDIUM            0.3
#define CT_WSR_LOAD_RATE_LOW               0.1
#define CT_WSR_CAPTURE_RATE                50

static void wsr_build_report_summary_load(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    double loadRate;
    uint32 descId;
    uint32 adviceId;

    if (wsr_info->num_cpu == 0) {
        loadRate = (double)wsr_info->dbtime / WSR_MILLION / wsr_info->elapsed / CT_WSR_DEFAULT_CPU_NUM;
    } else {
        loadRate = (double)wsr_info->dbtime / WSR_MILLION / wsr_info->elapsed / wsr_info->num_cpu;
    }

    adviceId = WSR_ITEM_NO_ADVICE;

    if (loadRate > CT_WSR_LOAD_RATE_VERY_HIGH) {
        descId = WSR_ITEM_VERY_HIGH;
        adviceId = WSR_ITEM_NEED_OPT;
    } else if (loadRate > CT_WSR_LOAD_RATE_HIGH) {
        descId = WSR_ITEM_HIGH;
        adviceId = WSR_ITEM_NEED_OPT;
    } else if (loadRate > CT_WSR_LOAD_RATE_MEDIUM) {
        descId = WSR_ITEM_MEDIUM;
    } else if (loadRate > CT_WSR_LOAD_RATE_LOW) {
        descId = WSR_ITEM_LOW;
    } else {
        descId = WSR_ITEM_VERY_LOW;
    }

    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<tr><td>Average Load</td><td>%s</td><td>%s</td></tr>",
        g_wsrloaddesc[descId], g_wsrloaddesc[adviceId]);
}

static status_t wsr_build_report_sql_capture(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    uint32 rows;
    int64 *data = NULL;
    bool32 is_null = CT_FALSE;
    uint32 size;
    char *cmd_sql = NULL;
    int64 result;
    uint32 adviceId;
    uint32 index = 0;

    cmd_sql = (char *)"SELECT CAST(SUM(B.ELAPSED_TIME - NVL(A.ELAPSED_TIME, 0)) / :p1 * 100 AS BINARY_BIGINT) "
        "FROM(SELECT * FROM ADM_HIST_SQLAREA WHERE SNAP_ID = :p2) B "
        "LEFT JOIN ADM_HIST_SQLAREA A "
        "ON A.SNAP_ID = :p3 AND A.SQL_ID = B.SQL_ID";

    CT_RETURN_IFERR(ctconn_prepare(wsr_opts->curr_stmt, cmd_sql));

    CT_RETURN_IFERR(ctconn_bind_by_pos(wsr_opts->curr_stmt, index++, CTCONN_TYPE_BIGINT,
        &wsr_info->dbtime, sizeof(uint64), NULL));
    CT_RETURN_IFERR(ctconn_bind_by_pos(wsr_opts->curr_stmt, index++, CTCONN_TYPE_INTEGER,
        &wsr_opts->end_snap_id, sizeof(uint32), NULL));
    CT_RETURN_IFERR(ctconn_bind_by_pos(wsr_opts->curr_stmt, index++, CTCONN_TYPE_INTEGER,
        &wsr_opts->start_snap_id, sizeof(uint32), NULL));
    CT_RETURN_IFERR(ctconn_execute(wsr_opts->curr_stmt));

    CT_RETURN_IFERR(ctconn_fetch(wsr_opts->curr_stmt, &rows));
    if (rows == 0) {
        result = 0;
        return CTCONN_SUCCESS;
    }

    if (ctconn_get_column_by_id(wsr_opts->curr_stmt, 0, (void **)&data, &size, &is_null) != CT_SUCCESS) {
        ctsql_print_error(wsr_opts->curr_conn);
        return CTCONN_ERROR;
    }

    result = (is_null || (*data) < 0) ? 0 : *data;
    adviceId = WSR_ITEM_NO_ADVICE;

    if (result < CT_WSR_CAPTURE_RATE) {
        adviceId = WSR_ITEM_SQL_CAPTURE;
    }

    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<tr><td>SQL Capture Rate</td><td>%lld%%</td><td>%s</td></tr>",
        result, g_wsrloaddesc[adviceId]);
    return CTCONN_SUCCESS;
}

static int wsr_build_report_event_analyse(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    char cmd_buf[MAX_CMD_LEN + 2];
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover\" ><thead>");
    wsr_write_str2(wsr_opts, "<tr><th>Instance performance bottleneck</th><th></th><th></th></tr>");
    wsr_write_str2(wsr_opts, "<tr><th>Event</th><th>% DB time</th><th>Recommendations</th></tr></thead><tbody>");

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN,
        "SELECT EVENT, PERCENT FROM ( SELECT B.EVENT, ROUND((B.TIME_WAITED_MIRCO - A.TIME_WAITED_MIRCO)/"
        "(SELECT NVL(SUM(B.TIME_WAITED_MIRCO - A.TIME_WAITED_MIRCO), 1) "
        "FROM ADM_HIST_SYSTEM_EVENT A, ADM_HIST_SYSTEM_EVENT B "
        "WHERE A.SNAP_ID = %u AND B.SNAP_ID = %u AND A.EVENT# = B.EVENT# "
        "AND NVL(B.TOTAL_WAITS - A.TOTAL_WAITS, -1) <> 0 "
        "AND (B.WAIT_CLASS <> 'Idle' OR B.WAIT_CLASS IS NULL)) * 100, 2) PERCENT "
        "FROM ADM_HIST_SYSTEM_EVENT A, ADM_HIST_SYSTEM_EVENT B "
        "WHERE A.SNAP_ID = %u AND B.SNAP_ID = %u AND A.EVENT# = B.EVENT# "
        "AND NVL(B.TOTAL_WAITS - A.TOTAL_WAITS, -1) <> 0 AND (B.WAIT_CLASS <> 'Idle' OR B.WAIT_CLASS IS NULL) "
        "ORDER BY 2 DESC) WHERE PERCENT > 10 ", wsr_opts->start_snap_id, wsr_opts->end_snap_id,
        wsr_opts->start_snap_id, wsr_opts->end_snap_id));

    CT_RETURN_IFERR(ctconn_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    CT_RETURN_IFERR(ctconn_execute(wsr_opts->curr_stmt));

    uint32 rows;
    char event[MAX_WSR_ENTITY_LEN];
    char dbtime_percent[MAX_WSR_ENTITY_LEN];
    uint32 adviceId;
    wsr_info->top_event_num = 0;

    do {
        CT_RETURN_IFERR(ctconn_fetch(wsr_opts->curr_stmt, &rows));
        if (rows == 0) {
            break;
        }

        CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, 0, event, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, 1, dbtime_percent, MAX_WSR_ENTITY_LEN));

        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<tr><td>%s</td>", event);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<td>%s</td>", dbtime_percent);
        adviceId = WSR_EVENT_NO_ADVICE;

        for (int i = 1; i < WSR_EVENT_COUNT; i++) {
            if (cm_str_equal(g_wsreventname[i], (const char *)event)) {
                adviceId = i;
                wsr_info->top_events[wsr_info->top_event_num] = i;
                wsr_info->top_event_num++;
                break;
            }
        }

        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td>%s</td></tr>", g_wsreventdesc[adviceId]);
    } while (CT_TRUE);

    wsr_write_str2(wsr_opts, "</tbody></table>");
    return CTCONN_SUCCESS;
}

static void wsr_build_report_sql_analyse_html(wsr_options_t *wsr_opts)
{
    wsr_write_str2(wsr_opts, "            <table class=\"table table-hover\" >");
    wsr_write_str2(wsr_opts, "              <thead>");
    wsr_write_str2(wsr_opts, "                <tr><th>Top SQL ANALYSE</th><th></th><th></th>");
    wsr_write_str2(wsr_opts, "<th></th><th></th><th></th><th></th><th></th><th></th><th></th>");
    wsr_write_str2(wsr_opts, "<th></th><th></th><th></th><th></th><th></th><th></th><th></th>");
    wsr_write_str2(wsr_opts, "<th></th><th></th><th></th><th></th></tr>");
    wsr_write_str2(wsr_opts, "                <tr>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Recommendations</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Elapsed Time (s)</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Executions</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Executings</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Elapsed Time per Exec (s) </th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">%Total</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">%CPU</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">%NET</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">%IO</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Parse time</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Wait time</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Gets per Exec</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">CR Gets per Exec</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Reads per Exec</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Rows per Exec</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">SQL Id</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">SQL Module</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Schema</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Procedure</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Line</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">VM Pages used(128K) per Exec</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">SQL Text</th>");
    wsr_write_str2(wsr_opts, "                </tr>");
    wsr_write_str2(wsr_opts, "              </thead>");
    wsr_write_str2(wsr_opts, "              <tbody>");
}

static void wsr_build_report_sql_write_line(wsr_options_t *wsr_opts, wsr_info_t *wsr_info,
    const wsr_sql_info_t *sql_info)
{
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_10000, "<tr><td  class='wsrc'>%s</td>", sql_info->recommendations);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", sql_info->elapsed_time);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", sql_info->executions);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", sql_info->executings);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", sql_info->elapsed_per_exec);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", sql_info->total_percent);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", sql_info->cpu_percent);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", sql_info->net_percent);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", sql_info->io_percent);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", sql_info->parse_time);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", sql_info->wait_time);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", sql_info->buffer_gets_per);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", sql_info->cr_gets_per);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", sql_info->disk_reads_per);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", sql_info->row_processed_per);
    wsr_write_str2(wsr_opts, "<td scope=\"row\" class='wsrc'>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<a class=\"wsrc\" href=\"#%s-%u\">%s</a>",
        sql_info->sql_id, wsr_info->dbid, sql_info->sql_id);
    wsr_write_str2(wsr_opts, "</td>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", sql_info->sql_module);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", sql_info->schema);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td>", sql_info->procedure);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", sql_info->line);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", sql_info->vm_pages_used);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td></tr>", sql_info->sql_text_part);
}

static int wsr_build_report_sql_analyse(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    uint32 rows;
    wsr_sql_info_t sqlinfo;
    char cmd_buf[MAX_CMD_LEN + 1];
    uint32 index;

    wsr_build_report_sql_analyse_html(wsr_opts);

    ctconn_stmt_t resultset;
    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN, "CALL SYS.WSR$TOPSQL_ANALYSE(%u, %u, %llu)",
        wsr_opts->start_snap_id, wsr_opts->end_snap_id, wsr_info->dbtime));

    CT_RETURN_IFERR(ctconn_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    CT_RETURN_IFERR(ctconn_execute(wsr_opts->curr_stmt));
    CT_RETURN_IFERR(ctconn_get_implicit_resultset(wsr_opts->curr_stmt, &resultset));

    do {
        CT_RETURN_IFERR(ctconn_fetch(resultset, &rows));
        if (rows == 0) {
            break;
        }

        index = 0;

        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sqlinfo.recommendations, WSR_FMT_SIZE_10000));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sqlinfo.elapsed_time, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sqlinfo.executions, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sqlinfo.executings, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sqlinfo.elapsed_per_exec, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sqlinfo.total_percent, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sqlinfo.cpu_percent, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sqlinfo.net_percent, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sqlinfo.io_percent, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sqlinfo.sql_text_part, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sqlinfo.sql_id, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sqlinfo.sql_module, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sqlinfo.buffer_gets_per, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sqlinfo.disk_reads_per, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sqlinfo.row_processed_per, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sqlinfo.parse_time, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sqlinfo.cr_gets_per, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sqlinfo.schema, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sqlinfo.line, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sqlinfo.procedure, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sqlinfo.wait_time, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sqlinfo.vm_pages_used, MAX_WSR_ENTITY_LEN));

        wsr_build_report_sql_write_line(wsr_opts, wsr_info, &sqlinfo);
    } while (CT_TRUE);

    wsr_write_str2(wsr_opts, "</tbody></table>");
    return CTCONN_SUCCESS;
}

status_t wsr_build_report_summary(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"31001-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Report Summary %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts, "<font face=\"Courier New, Courier, mono\" color=\"#666\">Report Summary</font>");
    }

    wsr_write_str2(wsr_opts, "            <table class=\"table table-hover\" >");
    wsr_write_str2(wsr_opts, "              <thead>");
    wsr_write_str2(wsr_opts, "                <tr><th>Overall load</th><th></th><th></th></tr>");
    wsr_write_str2(wsr_opts, "                <tr>");
    wsr_write_str2(wsr_opts, "                  <th>Attribute</th>");
    wsr_write_str2(wsr_opts, "                  <th>Status</th>");
    wsr_write_str2(wsr_opts, "                  <th>Recommendations</th>");
    wsr_write_str2(wsr_opts, "                </tr>");
    wsr_write_str2(wsr_opts, "              </thead>");
    wsr_write_str2(wsr_opts, "              <tbody>");

    wsr_build_report_summary_load(wsr_opts, wsr_info);
    CT_RETURN_IFERR(wsr_build_report_sql_capture(wsr_opts, wsr_info));
    CT_RETURN_IFERR(wsr_build_report_event_analyse(wsr_opts, wsr_info));
    CT_RETURN_IFERR(wsr_build_report_sql_analyse(wsr_opts, wsr_info));

    wsr_write_str2(wsr_opts, "              </tbody>");
    wsr_write_str2(wsr_opts, "            </table>");

    return CTCONN_SUCCESS;
}