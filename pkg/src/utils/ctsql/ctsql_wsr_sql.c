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
 * ctsql_wsr_sql.c
 *
 *
 * IDENTIFICATION
 * src/utils/ctsql/ctsql_wsr_sql.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_wsr_sql.h"

typedef struct st_wsr_sql {
    char elapsed_time[MAX_WSR_ENTITY_LEN];
    char executions[MAX_WSR_ENTITY_LEN];
    char executings[MAX_WSR_ENTITY_LEN];
    char elapsed_per_exec[MAX_WSR_ENTITY_LEN];
    char total_percent[MAX_WSR_ENTITY_LEN];
    char cpu_percent[MAX_WSR_ENTITY_LEN];
    char io_percent[MAX_WSR_ENTITY_LEN];
    char sql_id[MAX_WSR_ENTITY_LEN];
    char sql_module[MAX_WSR_ENTITY_LEN];
    char sql_text_part[MAX_WSR_ENTITY_LEN];
    char buffer_gets_per[MAX_WSR_ENTITY_LEN];
    char disk_reads_per[MAX_WSR_ENTITY_LEN];
    char row_processed_per[MAX_WSR_ENTITY_LEN];
    char parse_time[MAX_WSR_ENTITY_LEN];
    char cr_gets_per[MAX_WSR_ENTITY_LEN];
    char schema[MAX_WSR_ENTITY_LEN];
    char procedure[MAX_WSR_ENTITY_LEN];
    char line[MAX_WSR_ENTITY_LEN];
    char wait_time[MAX_WSR_ENTITY_LEN];
    char vm_pages_used[MAX_WSR_ENTITY_LEN];
    char net_percent[MAX_WSR_ENTITY_LEN];
    char str_buf[WSR_MAX_RECEV_LEN + 1];
} wsr_sql_t;

typedef struct st_wsr_longsql {
    char executions[MAX_WSR_ENTITY_LEN];
    char elapsed_time[MAX_WSR_ENTITY_LEN];
    char max_exec_time[MAX_WSR_ENTITY_LEN];
    char parses[MAX_WSR_ENTITY_LEN];
    char parse_time[MAX_WSR_ENTITY_LEN];
    char fetch[MAX_WSR_ENTITY_LEN];
    char fetch_time[MAX_WSR_ENTITY_LEN];
    char sql_text_part[MAX_WSR_ENTITY_LEN];
    char sql_id[MAX_WSR_ENTITY_LEN];
    char str_buf[WSR_MAX_RECEV_LEN + 1];
} wsr_longsql_t;

typedef struct st_wsr_sql_common {
    char total[MAX_WSR_ENTITY_LEN];
    char executions[MAX_WSR_ENTITY_LEN];
    char executings[MAX_WSR_ENTITY_LEN];
    char per_exec[MAX_WSR_ENTITY_LEN];
    char total_percent[MAX_WSR_ENTITY_LEN];
    char elapsed_time[MAX_WSR_ENTITY_LEN];
    char cpu_percent[MAX_WSR_ENTITY_LEN];
    char io_percent[MAX_WSR_ENTITY_LEN];
    char sql_id[MAX_WSR_ENTITY_LEN];
    char sql_module[MAX_WSR_ENTITY_LEN];
    char sql_text_part[MAX_WSR_ENTITY_LEN];
    char str_buf[WSR_MAX_RECEV_LEN + 1];
} wsr_sql_common_t;

typedef struct st_wsr_sql_letters {
    char sql_text_part[MAX_WSR_ENTITY_LEN];
    char elapsed_time[MAX_WSR_ENTITY_LEN];
    char cpu_time[MAX_WSR_ENTITY_LEN];
    char io_time[MAX_WSR_ENTITY_LEN];
    char executions[MAX_WSR_ENTITY_LEN];
    char buffer_gets[MAX_WSR_ENTITY_LEN];
    char disk_reads[MAX_WSR_ENTITY_LEN];
    char elapsed_time_rate[MAX_WSR_ENTITY_LEN];
} wsr_sql_l_t;

int wsr_build_sql_head(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"30008-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">SQL Statistics %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts, "<font face=\"Courier New, Courier, mono\" color=\"#666\">SQL Statistics</font>");
    }
    wsr_write_str2(wsr_opts, "<!-- <h2 class=\"wsr\">SQL Statistics</h2> -->");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover\" ><thead><tr>");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a class=\"wsrg\" href=\"#400-%u\">SQL ordered by Elapsed Time</a></td></tr><tr>", wsr_info->dbid);
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a class=\"wsrg\" href=\"#410-%u\">Long SQL ordered by Elapsed Time</a></td></tr><tr>", wsr_info->dbid);
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a  class=\"wsrg\"href=\"#500-%u\">SQL ordered by CPU Time</a></td></tr><tr>", wsr_info->dbid);
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a class=\"wsrg\" href=\"#550-%u\">SQL ordered by User I/O Wait Time</a></td></tr><tr>", wsr_info->dbid);
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a class=\"wsrg\" href=\"#600-%u\">SQL ordered by Gets</a></td></tr><tr>", wsr_info->dbid);
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a class=\"wsrg\" href=\"#700-%u\">SQL ordered by Reads</a></td></tr><tr>", wsr_info->dbid);
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a class=\"wsrg\"href=\"#800-%u\">SQL ordered by Executions</a></td></tr><tr>", wsr_info->dbid);
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a  class=\"wsrg\"href=\"#900-%u\">SQL ordered by Parse Calls</a></td></tr><tr>", wsr_info->dbid);
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a  class=\"wsrg\"href=\"#906-%u\">SQL ordered by first 6 letters</a></td></tr><tr>", wsr_info->dbid);
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a  class=\"wsrg\"href=\"#910-%u\">SQL ordered by first 10 letters</a></td></tr><tr>", wsr_info->dbid);
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a class=\"wsrg\"href=\"#915-%u\">SQL ordered by first 15 letters</a></td></tr><tr>", wsr_info->dbid);
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a class=\"wsrg\"href=\"#920-%u\">SQL ordered by first 20 letters</a></td></tr><tr>", wsr_info->dbid);
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a class=\"wsrg\" href=\"#930-%u\">SQL ordered by first 30 letters</a></td>", wsr_info->dbid);
    wsr_write_str2(wsr_opts, "</tr><tr>");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a class=\"wsrg\" href=\"#1015-%u\">Long SQL ordered by first 15 letters</a></td>", wsr_info->dbid);
    wsr_write_str2(wsr_opts, "</tr><tr>");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a class=\"wsrg\" href=\"#1030-%u\">Long SQL ordered by first 30 letters</a></td>", wsr_info->dbid);
    wsr_write_str2(wsr_opts, "</tr><tr><td><a class=\"wsrg\" href=\"#top\">Back to Top</a></td>");
    wsr_write_str2(wsr_opts, "</tr></thead></table><p />");
    return CTCONN_SUCCESS;
}

int wsr_build_sql_elapsed_head(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"400-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">SQL ordered by Elapsed Time %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">SQL ordered by Elapsed Time</font>");
    }
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover\">");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr>");
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
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "<tbody>");
    return CTCONN_SUCCESS;
}

int wsr_build_sql_elapsed_row(wsr_options_t *wsr_opts, wsr_info_t *wsr_info, wsr_sql_t *wsr_sql)
{
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", wsr_sql->elapsed_time);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", wsr_sql->executions);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", wsr_sql->executings);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", wsr_sql->elapsed_per_exec);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", wsr_sql->total_percent);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", wsr_sql->cpu_percent);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", wsr_sql->net_percent);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", wsr_sql->io_percent);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", wsr_sql->parse_time);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", wsr_sql->wait_time);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", wsr_sql->buffer_gets_per);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", wsr_sql->cr_gets_per);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", wsr_sql->disk_reads_per);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", wsr_sql->row_processed_per);
    wsr_write_str2(wsr_opts, "<td scope=\"row\" class='wsrc'>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<a class=\"wsrc\" href=\"#%s-%u\">%s</a>",
        wsr_sql->sql_id, wsr_info->dbid, wsr_sql->sql_id);
    wsr_write_str2(wsr_opts, "</td>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", wsr_sql->sql_module);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", wsr_sql->schema);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td>", wsr_sql->procedure);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", wsr_sql->line);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", wsr_sql->vm_pages_used);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td>", wsr_sql->sql_text_part);
    wsr_write_str2(wsr_opts, "</tr>");
    return CTCONN_SUCCESS;
}

int wsr_build_sql_elapsed(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    uint32 rows;
    wsr_sql_t wsr_sql;
    char cmd_buf[MAX_CMD_LEN + 1];
    uint32 index;
    ctconn_stmt_t resultset;

    CT_RETURN_IFERR(wsr_build_sql_head(wsr_opts, wsr_info));
    CT_RETURN_IFERR(wsr_build_sql_elapsed_head(wsr_opts, wsr_info));

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN, "CALL SYS.WSR$TOPSQL_ELAPSED_TIME(%u, %u, %llu, %u)",
        wsr_opts->start_snap_id, wsr_opts->end_snap_id, wsr_info->dbtime, wsr_info->topnsql));

    CT_RETURN_IFERR(ctconn_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    CT_RETURN_IFERR(ctconn_execute(wsr_opts->curr_stmt));
    CT_RETURN_IFERR(ctconn_get_implicit_resultset(wsr_opts->curr_stmt, &resultset));

    do {
        CT_RETURN_IFERR(ctconn_fetch(resultset, &rows));
        if (rows == 0) {
            break;
        }

        index = 0;

        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql.elapsed_time, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql.executions, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql.executings, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql.elapsed_per_exec, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql.total_percent, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql.cpu_percent, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql.net_percent, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql.io_percent, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql.sql_text_part, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql.sql_id, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql.sql_module, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql.str_buf, WSR_MAX_RECEV_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql.buffer_gets_per, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql.disk_reads_per, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql.row_processed_per, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql.parse_time, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql.cr_gets_per, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql.schema, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql.line, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql.procedure, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql.wait_time, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql.vm_pages_used, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(wsr_insert_sql_list(wsr_opts, wsr_sql.sql_id, wsr_sql.str_buf));

        CT_RETURN_IFERR(wsr_build_sql_elapsed_row(wsr_opts, wsr_info, &wsr_sql));
    } while (CT_TRUE);

    wsr_write_str2(wsr_opts, "</tbody></table><p />");
    return CTCONN_SUCCESS;
}

int wsr_build_longsql_time_head(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"410-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Long SQL ordered by Elapsed Time %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Long SQL ordered by Elapsed Time</font>");
    }
    wsr_write_str2(wsr_opts, "<!-- <h2 class=\"wsr\">Long SQL ordered by Elapsed Time</h2> -->");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover\" >");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_str2(wsr_opts, "<td>Resources reported long SQL.</td>");
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "</table>");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover\">");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Executions</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Execution Time(s)</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Max Execution Time (s)</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Parses</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Parse Time (s)</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Fetchs</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Fetch Time (s)</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">SQL Id</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">SQL Text</th>");
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "<tbody>");
    return CTCONN_SUCCESS;
}

int wsr_build_longsql_time_row(wsr_options_t *wsr_opts, wsr_info_t *wsr_info, wsr_longsql_t *wsr_longsql)
{
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td class='wsrc'>%s</td>", wsr_longsql->executions);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td class='wsrc'>%s</td>", wsr_longsql->elapsed_time);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td class='wsrc'>%s</td>", wsr_longsql->max_exec_time);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td class='wsrc'>%s</td>", wsr_longsql->parses);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td class='wsrc'>%s</td>", wsr_longsql->parse_time);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td class='wsrc'>%s</td>", wsr_longsql->fetch);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td class='wsrc'>%s</td>", wsr_longsql->fetch_time);
    wsr_write_str2(wsr_opts, "<td scope=\"row\" class='wsrc'>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<a class=\"wsrc\" href=\"#%s-%u\">%s</a>", wsr_longsql->sql_id,
        wsr_info->dbid, wsr_longsql->sql_id);
    wsr_write_str2(wsr_opts, "</td>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td class='wsrc'>%s</td>", wsr_longsql->sql_text_part);
    wsr_write_str2(wsr_opts, "</tr>");
    return CTCONN_SUCCESS;
}

int wsr_build_longsql_time(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    uint32 rows;
    char cmd_buf[MAX_CMD_LEN + 1];
    wsr_longsql_t wsr_longsql;
    uint32 index;
    ctconn_stmt_t resultset;

    CT_RETURN_IFERR(wsr_build_longsql_time_head(wsr_opts, wsr_info));

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN, "CALL SYS.WSR$TOPSQL_LONGSQL_TIME(%u, %u, %u)",
        wsr_opts->start_snap_id, wsr_opts->end_snap_id, wsr_info->topnsql));

    CT_RETURN_IFERR(ctconn_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    CT_RETURN_IFERR(ctconn_execute(wsr_opts->curr_stmt));
    CT_RETURN_IFERR(ctconn_get_implicit_resultset(wsr_opts->curr_stmt, &resultset));

    do {
        CT_RETURN_IFERR(ctconn_fetch(resultset, &rows));
        if (rows == 0) {
            break;
        }

        index = 0;

        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_longsql.executions, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_longsql.elapsed_time, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_longsql.max_exec_time, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_longsql.parses, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_longsql.parse_time, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_longsql.fetch, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_longsql.fetch_time, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_longsql.sql_id, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_longsql.sql_text_part, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_longsql.str_buf, WSR_MAX_RECEV_LEN));

        CT_RETURN_IFERR(wsr_insert_sql_list(wsr_opts, wsr_longsql.sql_id, wsr_longsql.str_buf));

        CT_RETURN_IFERR(wsr_build_longsql_time_row(wsr_opts, wsr_info, &wsr_longsql));
    } while (CT_TRUE);
    wsr_write_str2(wsr_opts, "</tbody></table><p />");

    return CTCONN_SUCCESS;
}

static int wsr_build_common(ctconn_stmt_t resultset, wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    uint32 rows;
    uint32 index;
    wsr_sql_common_t wsr_sql_common;

    do {
        CT_RETURN_IFERR(ctconn_fetch(resultset, &rows));
        if (rows == 0) {
            break;
        }

        index = 0;

        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql_common.total, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql_common.executions, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql_common.executings, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql_common.per_exec, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql_common.total_percent, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql_common.elapsed_time, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql_common.cpu_percent, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql_common.io_percent, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql_common.sql_text_part, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql_common.sql_id, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql_common.sql_module, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, wsr_sql_common.str_buf, WSR_MAX_RECEV_LEN));

        CT_RETURN_IFERR(wsr_insert_sql_list(wsr_opts, wsr_sql_common.sql_id, wsr_sql_common.str_buf));

        wsr_write_str2(wsr_opts, "<tr>");
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td  class='wsrc'>%s</td>", wsr_sql_common.total);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td  class='wsrc'>%s</td>", wsr_sql_common.executions);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td  class='wsrc'>%s</td>", wsr_sql_common.executings);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td  class='wsrc'>%s</td>", wsr_sql_common.per_exec);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td  class='wsrc'>%s</td>", wsr_sql_common.total_percent);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td  class='wsrc'>%s</td>", wsr_sql_common.elapsed_time);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td  class='wsrc'>%s</td>", wsr_sql_common.cpu_percent);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td  class='wsrc'>%s</td>", wsr_sql_common.io_percent);
        wsr_write_str2(wsr_opts, "<td scope=\"row\" class='wsrc'>");
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000,
            "<a class=\"wsrc\" href=\"#%s-%u\">%s</a>", wsr_sql_common.sql_id, wsr_info->dbid, wsr_sql_common.sql_id);
        wsr_write_str2(wsr_opts, "</td>");
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td  class='wsrc'>%s</td>", wsr_sql_common.sql_module);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td class='wsrc'>%s</td>", wsr_sql_common.sql_text_part);
        wsr_write_str2(wsr_opts, "</tr>");
    } while (CT_TRUE);
    return CT_SUCCESS;
}

int wsr_build_cpu_time(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    char cmd_buf[MAX_CMD_LEN + 1];
    ctconn_stmt_t resultset;

    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"500-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">SQL ordered by CPU Time %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">SQL ordered by CPU Time</font>");
    }
    wsr_write_str2(wsr_opts, "<!-- <h2 class=\"wsr\">SQL ordered by CPU Time</h2> -->");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover\">");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">CPU Time (s)</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Executions</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Executings</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">CPU per Exec (s)</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">%Total</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Elapsed Time (s)</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">%CPU</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">%IO</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">SQL Id</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">SQL Module</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">SQL Text</th>");
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "<tbody>");

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN, "CALL SYS.WSR$TOPSQL_CPU_TIME(%u, %u, %llu, %u)",
        wsr_opts->start_snap_id, wsr_opts->end_snap_id, wsr_info->cputime, wsr_info->topnsql));

    CT_RETURN_IFERR(ctconn_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    CT_RETURN_IFERR(ctconn_execute(wsr_opts->curr_stmt));
    CT_RETURN_IFERR(ctconn_get_implicit_resultset(wsr_opts->curr_stmt, &resultset));
    CT_RETURN_IFERR(wsr_build_common(resultset, wsr_opts, wsr_info));

    wsr_write_str2(wsr_opts, "</tbody>");
    wsr_write_str2(wsr_opts, "</table><p/>");

    return CTCONN_SUCCESS;
}

int wsr_build_io_wait(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    char cmd_buf[MAX_CMD_LEN + 1];
    ctconn_stmt_t resultset;

    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"550-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">SQL ordered by User I/O Wait Time %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">SQL ordered by User I/O Wait Time</font>");
    }
    wsr_write_str2(wsr_opts, "<!-- <h2 class=\"wsr\">SQL ordered by User I/O Wait Time</h2> -->");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover\">");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">User I/O Time (s)</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Executions </th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Executings</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">UIO per Exec (s)</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">%Total</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Elapsed Time (s)</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">%CPU</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">%IO</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\"> SQL Id</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">SQL Module</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">SQL Text</th>");
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "<tbody>");

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN, "CALL SYS.WSR$TOPSQL_IO_WAIT(%u, %u, %llu, %u)",
        wsr_opts->start_snap_id, wsr_opts->end_snap_id, wsr_info->disk_read_time, wsr_info->topnsql));

    CT_RETURN_IFERR(ctconn_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    CT_RETURN_IFERR(ctconn_execute(wsr_opts->curr_stmt));
    CT_RETURN_IFERR(ctconn_get_implicit_resultset(wsr_opts->curr_stmt, &resultset));

    CT_RETURN_IFERR(wsr_build_common(resultset, wsr_opts, wsr_info));

    wsr_write_str2(wsr_opts, "</tbody>");
    wsr_write_str2(wsr_opts, "</table><p/>");

    return CTCONN_SUCCESS;
}

int wsr_build_sql_gets(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    char cmd_buf[MAX_CMD_LEN + 1];
    ctconn_stmt_t resultset;

    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"600-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">SQL ordered by User Gets %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">SQL ordered by User Gets</font>");
    }
    wsr_write_str2(wsr_opts, "<!-- <h2 class=\"wsr\">SQL ordered by User Gets</h2> -->");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover\">");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Buffer Gets</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Executions </th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Executings</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Gets per Exec</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">%Total</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Elapsed Time (s)</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">%CPU</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">%IO</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\"> SQL Id</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">SQL Module</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">SQL Text</th>");
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "<tbody>");

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN, "CALL SYS.WSR$TOPSQL_GETS(%u, %u, %llu, %u)",
        wsr_opts->start_snap_id, wsr_opts->end_snap_id, wsr_info->buffer_gets, wsr_info->topnsql));

    CT_RETURN_IFERR(ctconn_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    CT_RETURN_IFERR(ctconn_execute(wsr_opts->curr_stmt));
    CT_RETURN_IFERR(ctconn_get_implicit_resultset(wsr_opts->curr_stmt, &resultset));

    CT_RETURN_IFERR(wsr_build_common(resultset, wsr_opts, wsr_info));

    wsr_write_str2(wsr_opts, "</tbody>");
    wsr_write_str2(wsr_opts, "</table><p />");

    return CTCONN_SUCCESS;
}

int wsr_build_sql_reads(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    char cmd_buf[MAX_CMD_LEN + 1];
    ctconn_stmt_t resultset;

    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"700-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">SQL ordered by Reads %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">SQL ordered by Reads</font>");
    }
    wsr_write_str2(wsr_opts, "<!-- <h2 class=\"wsr\">SQL ordered by Reads</h2> -->");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover\">");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Physical Reads</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Executions </th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Executings</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Reads per Exec</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">%Total</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Elapsed Time (s)</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">%CPU</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">%IO</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\"> SQL Id</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">SQL Module</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">SQL Text</th>");
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "<tbody>");

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN, "CALL SYS.WSR$TOPSQL_READS(%u, %u, %llu, %u)",
        wsr_opts->start_snap_id, wsr_opts->end_snap_id, wsr_info->disk_reads, wsr_info->topnsql));

    CT_RETURN_IFERR(ctconn_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    CT_RETURN_IFERR(ctconn_execute(wsr_opts->curr_stmt));
    CT_RETURN_IFERR(ctconn_get_implicit_resultset(wsr_opts->curr_stmt, &resultset));

    CT_RETURN_IFERR(wsr_build_common(resultset, wsr_opts, wsr_info));

    wsr_write_str2(wsr_opts, "</tbody>");
    wsr_write_str2(wsr_opts, "</table><p />");

    return CTCONN_SUCCESS;
}

static int wsr_build_sql_executions_write_str(wsr_options_t *wsr_opts, wsr_info_t *wsr_info, ctconn_stmt_t *resultset)
{
    char cmd_buf[MAX_CMD_LEN + 1];
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"800-%u\"></a>", wsr_info->dbid);

    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">SQL ordered by Executions %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">SQL ordered by Executions</font>");
    }
    wsr_write_str2(wsr_opts, "<!-- <h2 class=\"wsr\">SQL ordered by Executions</h2> -->");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover\">");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Executions</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Rows Processed</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Rows per Exec</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Elapsed Time (s)</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">%CPU</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">%IO</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">SQL Id</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">SQL Module</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">SQL Text</th>");
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "<tbody>");

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN, "CALL SYS.WSR$TOPSQL_EXECUTIONS(%u, %u, %u)",
        wsr_opts->start_snap_id, wsr_opts->end_snap_id, wsr_info->topnsql));

    CT_RETURN_IFERR(ctconn_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    CT_RETURN_IFERR(ctconn_execute(wsr_opts->curr_stmt));
    CT_RETURN_IFERR(ctconn_get_implicit_resultset(wsr_opts->curr_stmt, resultset));
    return CTCONN_SUCCESS;
}

int wsr_build_sql_executions(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    uint32 rows;
    char executions[MAX_WSR_ENTITY_LEN];
    char processed_rows[MAX_WSR_ENTITY_LEN];
    char rows_per_exec[MAX_WSR_ENTITY_LEN];
    char elapsed_time[MAX_WSR_ENTITY_LEN];
    char cpu_percent[MAX_WSR_ENTITY_LEN];
    char io_percent[MAX_WSR_ENTITY_LEN];
    char sql_id[MAX_WSR_ENTITY_LEN];
    char sql_module[MAX_WSR_ENTITY_LEN];
    char sql_text_part[MAX_WSR_ENTITY_LEN];
    char str_buf[WSR_MAX_RECEV_LEN + 1];
    ctconn_stmt_t resultset;
    uint32 index;

    CT_RETURN_IFERR(wsr_build_sql_executions_write_str(wsr_opts, wsr_info, &resultset));

    do {
        CT_RETURN_IFERR(ctconn_fetch(resultset, &rows));
        if (rows == 0) {
            break;
        }

        index = 0;

        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, executions, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, processed_rows, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, rows_per_exec, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, elapsed_time, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, cpu_percent, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, io_percent, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sql_text_part, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sql_id, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sql_module, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, str_buf, WSR_MAX_RECEV_LEN));

        CT_RETURN_IFERR(wsr_insert_sql_list(wsr_opts, sql_id, str_buf));

        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<tr><td class='wsrc'>%s</td>", executions);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td  class='wsrc'>%s</td>", processed_rows);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td  class='wsrc'>%s</td>", rows_per_exec);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td  class='wsrc'>%s</td>", elapsed_time);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td  class='wsrc'>%s</td>", cpu_percent);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td  class='wsrc'>%s</td>", io_percent);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td scope=\"row\" class='wsrc'>");
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<a class=\"wsrc\" href=\"#%s-%u\">%s</a></td>", sql_id,
            wsr_info->dbid, sql_id);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td  class='wsrc'>%s</td>", sql_module);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td class='wsrc'>%s</td></tr>", sql_text_part);
    } while (CT_TRUE);
    wsr_write_str2(wsr_opts, "</tbody></table><p />");

    return CTCONN_SUCCESS;
}

static void wsr_build_sql_parses_write_str(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"900-%u\"></a>", wsr_info->dbid);

    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">SQL ordered by Parse Calls %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">SQL ordered by Parse Calls</font>");
    }
    wsr_write_str2(wsr_opts, "<!-- <h2 class=\"wsr\">SQL ordered by Parse Calls</h2> -->");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover table-striped\">");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Parse Calls</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Executions </th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">% Total Parses</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\"> SQL Id</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">SQL Module</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">SQL Text</th>");
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "<tbody>");
}

int wsr_build_sql_parses(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    uint32 rows;
    char parse_calls[MAX_WSR_ENTITY_LEN];
    char executions[MAX_WSR_ENTITY_LEN];
    char total_percent[MAX_WSR_ENTITY_LEN];
    char sql_id[MAX_WSR_ENTITY_LEN];
    char sql_module[MAX_WSR_ENTITY_LEN];
    char sql_text_part[MAX_WSR_ENTITY_LEN];
    char cmd_buf[MAX_CMD_LEN + 1];
    char str_buf[WSR_MAX_RECEV_LEN + 1];
    ctconn_stmt_t resultset;
    uint32 index;

    wsr_build_sql_parses_write_str(wsr_opts, wsr_info);

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN, "CALL SYS.WSR$TOPSQL_PARSES(%u, %u, %llu, %u)",
        wsr_opts->start_snap_id, wsr_opts->end_snap_id, wsr_info->sql_parses, wsr_info->topnsql));

    CT_RETURN_IFERR(ctconn_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    CT_RETURN_IFERR(ctconn_execute(wsr_opts->curr_stmt));
    CT_RETURN_IFERR(ctconn_get_implicit_resultset(wsr_opts->curr_stmt, &resultset));
    do {
        CT_RETURN_IFERR(ctconn_fetch(resultset, &rows));
        if (rows == 0) {
            break;
        }

        index = 0;

        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, parse_calls, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, executions, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, total_percent, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sql_text_part, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sql_id, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sql_module, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, str_buf, WSR_MAX_RECEV_LEN));

        CT_RETURN_IFERR(wsr_insert_sql_list(wsr_opts, sql_id, str_buf));

        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<tr><td  class='wsrc'>%s</td>", parse_calls);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td  class='wsrc'>%s</td>", executions);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td  class='wsrc'>%s</td>", total_percent);
        wsr_write_str2(wsr_opts, "<td scope=\"row\" class='wsrc'>");
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<a class=\"wsrc\" href=\"#%s-%u\">%s</a>", sql_id, wsr_info->dbid, sql_id);
        wsr_write_str2(wsr_opts, "</td>");
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td  class='wsrc'>%s</td>", sql_module);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td class='wsrc'>%s</td></tr>", sql_text_part);
        wsr_write_str2(wsr_opts, "");
    } while (CT_TRUE);

    wsr_write_str2(wsr_opts, "</tbody></table><p />");

    return CTCONN_SUCCESS;
}

int wsr_build_sql_first_letters_head(wsr_options_t *wsr_opts, wsr_info_t *wsr_info, uint32 letter_num)
{
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<a class=\"wsr\" name=\"%u-%u\"></a>",
        EWSR_SQL_HTML_ID + letter_num, wsr_info->dbid);

    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">SQL ordered by first %u letters %s</font>",
            letter_num, wsr_info->node_name);
    } else {
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">SQL ordered by first %u letters</font>",
            letter_num);
    }
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<!-- <h2 class=\"wsr\">SQL ordered by first %u letters</h2> -->",
        letter_num);
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover table-striped\">");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">SQL prefix</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Elapsed Time (s)</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">CPU Time (s)</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">IO Wait Time(s)</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Executions</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Buffer Gets</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Physical Reads</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">%Total</th>");
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "<tbody>");
    return CTCONN_SUCCESS;
}

int wsr_build_sql_first_letters_row(wsr_options_t *wsr_opts, wsr_sql_l_t *wsr_sql_letters)
{
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<tr><td align=\"left\" class='wsrc'>%s</td>",
        wsr_sql_letters->sql_text_part);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", wsr_sql_letters->elapsed_time);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", wsr_sql_letters->cpu_time);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", wsr_sql_letters->io_time);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", wsr_sql_letters->executions);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", wsr_sql_letters->buffer_gets);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", wsr_sql_letters->disk_reads);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td></tr>", wsr_sql_letters->elapsed_time_rate);
    return CTCONN_SUCCESS;
}

int wsr_build_sql_first_letters(wsr_options_t *wsr_opts, wsr_info_t *wsr_info, uint32 letter_num)
{
    uint32 rows;
    char cmd_buf[MAX_CMD_LEN + 1];
    uint32 cnt;
    wsr_sql_l_t wsr_sql_l;

    CT_RETURN_IFERR(wsr_build_sql_first_letters_head(wsr_opts, wsr_info, letter_num));

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN,
        "SELECT SUBSTRB(SQL_TEXT, 1, %u), TO_CHAR(SUM(ELAPSED_TIME) / 1000000, 'FM99999999999999999990.000'), "
        "TO_CHAR(SUM(CPU_TIME) / 1000000, 'FM99999999999999999990.000'), "
        "TO_CHAR(SUM(IO_TIME) / 1000000, 'FM99999999999999999990.000'), "
        "SUM(EXECUTIONS), SUM(BUFFER_GETS), SUM(DISK_READS), "
        "TO_CHAR(DECODE(%llu, 0, 0 :: BINARY_BIGINT, SUM(ELAPSED_TIME)/%llu*100), 'FM99999999999999999990.000') "
        "FROM(SELECT * FROM(  SELECT B.ELAPSED_TIME - NVL(A.ELAPSED_TIME, 0) ELAPSED_TIME, "
        "    B.EXECUTIONS - NVL(A.EXECUTIONS, 0) EXECUTIONS, B.CPU_TIME - NVL(A.CPU_TIME, 0) CPU_TIME, "
        "    B.IO_WAIT_TIME - NVL(A.IO_WAIT_TIME, 0) IO_TIME, B.SQL_TEXT, "
        "   B.BUFFER_GETS - NVL(A.BUFFER_GETS, 0) BUFFER_GETS, B.DISK_READS - NVL(A.DISK_READS, 0) DISK_READS "
        "    FROM(SELECT * FROM SYS." WSR_TB_SQLAREA " WHERE SNAP_ID = %u) B LEFT JOIN SYS." WSR_TB_SQLAREA " A "
        "    ON A.SNAP_ID = %u AND A.SQL_ID = B.SQL_ID  ) WHERE ELAPSED_TIME > 0) "
        "GROUP BY SUBSTRB(SQL_TEXT, 1, %u) ORDER BY SUM(ELAPSED_TIME) DESC  LIMIT %u",
        letter_num, wsr_info->dbtime, wsr_info->dbtime, wsr_opts->end_snap_id,
        wsr_opts->start_snap_id, letter_num, wsr_info->topnsql));

    CT_RETURN_IFERR(ctconn_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    CT_RETURN_IFERR(ctconn_execute(wsr_opts->curr_stmt));

    do {
        CT_RETURN_IFERR(ctconn_fetch(wsr_opts->curr_stmt, &rows));
        if (rows == 0) {
            break;
        }

        cnt = 0;

        CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, cnt++, wsr_sql_l.sql_text_part,
            MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, cnt++, wsr_sql_l.elapsed_time,
            MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, cnt++, wsr_sql_l.cpu_time, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, cnt++, wsr_sql_l.io_time, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, cnt++, wsr_sql_l.executions, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, cnt++, wsr_sql_l.buffer_gets, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, cnt++, wsr_sql_l.disk_reads, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, cnt++, wsr_sql_l.elapsed_time_rate,
            MAX_WSR_ENTITY_LEN));

        CT_RETURN_IFERR(wsr_build_sql_first_letters_row(wsr_opts, &wsr_sql_l));
    } while (CT_TRUE);
    wsr_write_str2(wsr_opts, "</tbody></table><p />");

    return CTCONN_SUCCESS;
}

static void wsr_build_long_sql_first_letters_write_str(wsr_options_t *wsr_opts,
    wsr_info_t *wsr_info, uint32 letter_num)
{
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<a class=\"wsr\" name=\"%u-%u\"></a>",
        EWSR_LONGSQL_HTML_ID + letter_num, wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Long SQL ordered by first %u letters %s</font>",
            letter_num, wsr_info->node_name);
    } else {
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Long SQL ordered by first %u letters</font>",
            letter_num);
    }
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<!-- <h2 class=\"wsr\">Long SQL ordered by first %u letters</h2> -->",
        letter_num);
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover\">");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">SQL prefix</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Executions</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Execution Time(s)</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Max Execution Time (s)</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Parses</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Parse Time (s)</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Fetchs</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Fetch Time (s)</th>");
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "<tbody>");
}

int wsr_build_long_sql_first_letters(wsr_options_t *wsr_opts, wsr_info_t *wsr_info, uint32 letter_num)
{
    uint32 rows;
    char executions[MAX_WSR_ENTITY_LEN];
    char elapsed_time[MAX_WSR_ENTITY_LEN];
    char max_exec_time[MAX_WSR_ENTITY_LEN];
    char parses[MAX_WSR_ENTITY_LEN];
    char parse_time[MAX_WSR_ENTITY_LEN];
    char fetch[MAX_WSR_ENTITY_LEN];
    char fetch_time[MAX_WSR_ENTITY_LEN];
    char sql_text_part[MAX_WSR_ENTITY_LEN];
    char cmd_buf[MAX_CMD_LEN + 1];
    ctconn_stmt_t resultset;
    uint32 index;

    wsr_build_long_sql_first_letters_write_str(wsr_opts, wsr_info, letter_num);

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN, "CALL SYS.WSR$TOPSQL_LONGSQL_TIME_PREFIX(%u, %u, %u, %u)",
        wsr_opts->start_snap_id, wsr_opts->end_snap_id, wsr_info->topnsql, letter_num));

    CT_RETURN_IFERR(ctconn_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    CT_RETURN_IFERR(ctconn_execute(wsr_opts->curr_stmt));
    CT_RETURN_IFERR(ctconn_get_implicit_resultset(wsr_opts->curr_stmt, &resultset));

    do {
        CT_RETURN_IFERR(ctconn_fetch(resultset, &rows));
        if (rows == 0) {
            break;
        }

        index = 0;

        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, executions, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, elapsed_time, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, max_exec_time, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, parses, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, parse_time, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, fetch, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, fetch_time, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(resultset, index++, sql_text_part, MAX_WSR_ENTITY_LEN));

        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<tr><td align=\"left\" class='wsrc'>%s</td>", sql_text_part);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", executions);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", elapsed_time);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", max_exec_time);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", parses);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", parse_time);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", fetch);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td></tr>", fetch_time);
    } while (CT_TRUE);
    wsr_write_str2(wsr_opts, "</tbody></table><p />");

    return CTCONN_SUCCESS;
}

int wsr_build_sql_content_head(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"30009-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Complete List of SQL Text %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Complete List of SQL Text</font>");
    }
    wsr_write_str2(wsr_opts, "<!-- <h2 class=\"wsr\">Complete List of SQL Text</h2> -->");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover table-striped\">");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">SQL Id</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">SQL Text</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">PushDown SQL Id</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">ELAPSED(s)</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">SQL Plan</th>");
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "<tbody>");

    return CTCONN_SUCCESS;
}

int wsr_build_sql_content(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    uint32 rows;
    char sql_id[MAX_WSR_ENTITY_LEN];
    char pdown_sql_id[MAX_WSR_ENTITY_LEN];
    char elapsed_time[MAX_WSR_ENTITY_LEN];
    char cmd_buf[MAX_CMD_LEN + 1];
    char str_buf[WSR_MAX_RECEV_LEN + 1];
    uint32 index;

    CT_RETURN_IFERR(wsr_build_sql_content_head(wsr_opts, wsr_info));

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN,
        "SELECT A.SQL_ID, SQL_TEXT, NVL(PDOWN_SQL_ID, '&nbsp'),  "
        "NVL(TO_CHAR(ELAPSED_TIME/1000, 'FM99999999999999999990.000'), '&nbsp'), NVL(EXPLAIN_TEXT, '&nbsp') "
        "  FROM SYS." WSR_TB_SQL_LIST " A LEFT JOIN SYS." WSR_TB_SQL_LIST_PLAN " B"
        " ON A.SQL_ID = B.SQL_ID ORDER BY A.SQL_ID "));
    CT_RETURN_IFERR(ctconn_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    CT_RETURN_IFERR(ctconn_execute(wsr_opts->curr_stmt));

    do {
        CT_RETURN_IFERR(ctconn_fetch(wsr_opts->curr_stmt, &rows));
        if (rows == 0) {
            break;
        }

        index = 0;

        CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, index++, sql_id, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, index++, str_buf, WSR_MAX_RECEV_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, index++, pdown_sql_id, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, index++, elapsed_time, MAX_WSR_ENTITY_LEN));

        wsr_write_str2(wsr_opts, "<tr>");
        wsr_write_str2(wsr_opts, "<td scope=\"row\" class='wsrc'>");
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<a class=\"wsr\" name=\"%s-%u\"></a>%s</td>",
            sql_id, wsr_info->dbid, sql_id);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_10000, "<td class='wsrc'>%s</td>", str_buf);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td class='wsrc'>%s</td>", pdown_sql_id);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td class='wsrc'>%s</td>", elapsed_time);
        CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, index++, str_buf, WSR_MAX_RECEV_LEN));
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_10000, "<td class='wsrc'><pre>%s<pre/></td></tr>", str_buf);
    } while (CT_TRUE);
    wsr_write_str2(wsr_opts, "</tbody>");
    wsr_write_str2(wsr_opts, "</table><p />");

    if (ctconn_commit(wsr_opts->curr_conn) == CT_SUCCESS) {
        return CTCONN_SUCCESS;
    }

    return CTCONN_ERROR;
}