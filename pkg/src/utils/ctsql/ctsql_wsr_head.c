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
 * ctsql_wsr_head.c
 *
 *
 * IDENTIFICATION
 * src/utils/ctsql/ctsql_wsr_head.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_wsr_head.h"

int wsr_get_dbinfo_basic(wsr_options_t *wsr_opts, wsr_info_t *wsr_info, uint32 *index)
{
    uint32 *data = NULL;
    uint32 size;
    bool32 is_null = CT_FALSE;
    char str_buf[WSR_MAX_RECEV_LEN + 1] = { 0 };
    errno_t errcode;

    CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, (*index)++, str_buf, WSR_MAX_RECEV_LEN));
    errcode = strncpy_s(wsr_info->dbname, MAX_WSR_ENTITY_LEN, str_buf, WSR_MAX_RECEV_LEN);
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(ctconn_get_column_by_id(wsr_opts->curr_stmt, (*index)++, (void **)&data, &size, &is_null));
    wsr_info->dbid = *data;

    CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, (*index)++, str_buf, WSR_MAX_RECEV_LEN));
    errcode = strncpy_s(wsr_info->instance_name, MAX_WSR_ENTITY_LEN, str_buf, WSR_MAX_RECEV_LEN);
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(ctconn_get_column_by_id(wsr_opts->curr_stmt, (*index)++, (void **)&data, &size, &is_null));
    wsr_info->instance_id = *data;

    CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, (*index)++, str_buf, WSR_MAX_RECEV_LEN));
    errcode = strncpy_s(wsr_info->version, MAX_WSR_ENTITY_LEN, str_buf, WSR_MAX_RECEV_LEN);
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }

    return CTCONN_SUCCESS;
}

int wsr_get_dbinfo_host(wsr_options_t *wsr_opts, wsr_info_t *wsr_info, uint32 *index)
{
    uint32 *data = NULL;
    uint32 size;
    bool32 is_null = CT_FALSE;
    char str_buf[WSR_MAX_RECEV_LEN + 1] = { 0 };
    errno_t errcode;

    CT_RETURN_IFERR(ctconn_get_column_by_id(wsr_opts->curr_stmt, (*index)++, (void **)&data, &size, &is_null));
    wsr_info->num_cpu = is_null ? 0 : *data;

    CT_RETURN_IFERR(ctconn_get_column_by_id(wsr_opts->curr_stmt, (*index)++, (void **)&data, &size, &is_null));
    wsr_info->num_core = is_null ? 0 : *data;

    CT_RETURN_IFERR(ctconn_get_column_by_id(wsr_opts->curr_stmt, (*index)++, (void **)&data, &size, &is_null));
    wsr_info->num_cpu_socket = is_null ? 0 : *data;

    CT_RETURN_IFERR(ctconn_get_column_by_id(wsr_opts->curr_stmt, (*index)++, (void **)&data, &size, &is_null));
    wsr_info->memory = is_null ? 0 : *data;

    CT_RETURN_IFERR(ctconn_get_column_by_id(wsr_opts->curr_stmt, (*index)++, (void **)&data, &size, &is_null));
    wsr_info->elapsed = is_null ? 0 : *data;

    CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, (*index)++, str_buf, WSR_MAX_RECEV_LEN));
    errcode = strncpy_s(wsr_info->instance_status, MAX_WSR_ENTITY_LEN, str_buf, WSR_MAX_RECEV_LEN);
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, (*index)++, str_buf, WSR_MAX_RECEV_LEN));
    errcode = strncpy_s(wsr_info->database_role, MAX_WSR_ENTITY_LEN, str_buf, WSR_MAX_RECEV_LEN);
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, (*index)++, str_buf, WSR_MAX_RECEV_LEN));
    errcode = strncpy_s(wsr_info->copy_status, MAX_WSR_ENTITY_LEN, str_buf, WSR_MAX_RECEV_LEN);
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, (*index)++, str_buf, WSR_MAX_RECEV_LEN));
    errcode = strncpy_s(wsr_info->log_mode, MAX_WSR_ENTITY_LEN, str_buf, WSR_MAX_RECEV_LEN);
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(ctconn_get_column_by_id(wsr_opts->curr_stmt, (*index)++, (void **)&data, &size, &is_null));
    wsr_info->topnsql = is_null ? 0 : *data;

    return CTCONN_SUCCESS;
}

int wsr_get_dbinfo_other(wsr_options_t *wsr_opts, wsr_info_t *wsr_info, uint32 *index)
{
    char str_buf[WSR_MAX_RECEV_LEN + 1] = { 0 };
    errno_t errcode;
    char *ptr1 = wsr_info->db_startup_time;
    char *ptr2 = str_buf;

    CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, (*index)++, str_buf, WSR_MAX_RECEV_LEN));
    errcode = strncpy_s(wsr_info->db_startup_time, MAX_WSR_DATE_LEN, str_buf, WSR_MAX_RECEV_LEN);
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, (*index)++, str_buf, WSR_MAX_RECEV_LEN));

    if (!cm_str_equal_ins(ptr1, ptr2)) {
        CT_THROW_ERROR(ERR_CLT_WSR_ERR, "Database restarts in the middle of two snapshots.");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, (*index)++, str_buf, WSR_MAX_RECEV_LEN));
    errcode = strncpy_s(wsr_info->host_name, MAX_WSR_ENTITY_LEN, str_buf, WSR_MAX_RECEV_LEN);
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, (*index)++, str_buf, WSR_MAX_RECEV_LEN));
    errcode = strncpy_s(wsr_info->platform, MAX_WSR_ENTITY_LEN, str_buf, WSR_MAX_RECEV_LEN);
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }
    return CTCONN_SUCCESS;
}

int wsr_get_dbinfo_session(wsr_options_t *wsr_opts, wsr_info_t *wsr_info, uint32 *index)
{
    uint32 *data = NULL;
    uint32 size;
    bool32 is_null = CT_FALSE;

    CT_RETURN_IFERR(ctconn_get_column_by_id(wsr_opts->curr_stmt, (*index)++, (void **)&data, &size, &is_null));
    wsr_info->sessions_start = is_null ? 0 : *data;

    CT_RETURN_IFERR(ctconn_get_column_by_id(wsr_opts->curr_stmt, (*index)++, (void **)&data, &size, &is_null));
    wsr_info->sessions_end = is_null ? 0 : *data;

    CT_RETURN_IFERR(ctconn_get_column_by_id(wsr_opts->curr_stmt, (*index)++, (void **)&data, &size, &is_null));
    wsr_info->cursors_start = is_null ? 0 : *data;

    CT_RETURN_IFERR(ctconn_get_column_by_id(wsr_opts->curr_stmt, (*index)++, (void **)&data, &size, &is_null));
    wsr_info->cursors_end = is_null ? 0 : *data;

    return CTCONN_SUCCESS;
}

int wsr_get_dbinfo(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    uint32 rows;
    char cmd_buf[MAX_CMD_LEN + 1];
    uint32 index = 0;

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN,
        "SELECT A.NAME, A.DBID, B.INSTANCE_NAME, B.INSTANCE_ID, VERSION(), "
        "(SELECT CAST(VALUE AS BINARY_INTEGER) FROM DV_SYSTEM WHERE NAME = 'NUM_CPUS'), "
        "(SELECT CAST(VALUE AS BINARY_INTEGER) FROM DV_SYSTEM WHERE NAME = 'NUM_CPU_CORES'), "
        "(SELECT CAST(VALUE AS BINARY_INTEGER) FROM DV_SYSTEM WHERE NAME = 'NUM_CPU_SOCKETS'), "
        "(SELECT CAST(TRUNC(VALUE / 1024 / 1024) AS BINARY_INTEGER)"
        "  FROM DV_SYSTEM WHERE NAME = 'PHYSICAL_MEMORY_BYTES'), "
        "CAST ((CAST(D.SNAP_TIME AS DATE)- CAST(C.SNAP_TIME AS DATE))*86400 AS BINARY_INTEGER), "
        "B.STATUS, A.DATABASE_ROLE, A.DATABASE_CONDITION, A.LOG_MODE, "
        "(SELECT CAST(TOPNSQL AS BINARY_INTEGER) FROM ADM_HIST_WR_CONTROL), "
        "TO_CHAR(C.STARTUP_TIME, 'YYYY-MM-DD HH24:MI:SS'), TO_CHAR(D.STARTUP_TIME, 'YYYY-MM-DD HH24:MI:SS'), "
        "B.HOST_NAME, B.PLATFORM_NAME, C.SESSIONS, D.SESSIONS, C.CURSORS, D.CURSORS "
        "FROM DV_DATABASE A CROSS JOIN DV_INSTANCE B "
        "LEFT JOIN ADM_HIST_SNAPSHOT C ON C.SNAP_ID = %u "
        "LEFT JOIN ADM_HIST_SNAPSHOT D ON D.SNAP_ID = %u",
        wsr_opts->start_snap_id, wsr_opts->end_snap_id));

    CT_RETURN_IFERR(ctconn_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    CT_RETURN_IFERR(ctconn_execute(wsr_opts->curr_stmt));

    CT_RETURN_IFERR(ctconn_fetch(wsr_opts->curr_stmt, &rows));
    if (rows == 0) {
        return CT_ERROR;
    }

    CT_RETURN_IFERR(wsr_get_dbinfo_basic(wsr_opts, wsr_info, &index));
    CT_RETURN_IFERR(wsr_get_dbinfo_host(wsr_opts, wsr_info, &index));
    CT_RETURN_IFERR(wsr_get_dbinfo_other(wsr_opts, wsr_info, &index));
    CT_RETURN_IFERR(wsr_get_dbinfo_session(wsr_opts, wsr_info, &index));

    return CTCONN_SUCCESS;
}

static int wsr_get_sysstat(wsr_options_t *wsr_opts, const char *stat_name, uint64 *stat_value)
{
    uint32 rows;
    uint64 *data = NULL;
    bool32 is_null = CT_FALSE;
    uint32 size;
    char *cmd_sql = NULL;
    uint32 index = 0;

    cmd_sql = (char *)"SELECT CAST (B.VALUE - A.VALUE AS BINARY_BIGINT) "
        "FROM ADM_HIST_SYSSTAT A, ADM_HIST_SYSSTAT B "
        "WHERE A.SNAP_ID = :p1 AND B.SNAP_ID= :p2 AND A.STAT_NAME = :p3 AND B.STAT_NAME = :p4";

    CT_RETURN_IFERR(ctconn_prepare(wsr_opts->curr_stmt, cmd_sql));
    CT_RETURN_IFERR(ctconn_bind_by_pos(wsr_opts->curr_stmt, index++, CTCONN_TYPE_INTEGER,
        &wsr_opts->start_snap_id, sizeof(uint32), NULL));
    CT_RETURN_IFERR(ctconn_bind_by_pos(wsr_opts->curr_stmt, index++, CTCONN_TYPE_INTEGER,
        &wsr_opts->end_snap_id, sizeof(uint32), NULL));
    CT_RETURN_IFERR(ctconn_bind_by_pos(wsr_opts->curr_stmt, index++, CTCONN_TYPE_STRING,
        stat_name, (int32)strlen(stat_name), NULL));
    CT_RETURN_IFERR(ctconn_bind_by_pos(wsr_opts->curr_stmt, index++, CTCONN_TYPE_STRING,
        stat_name, (int32)strlen(stat_name), NULL));
    CT_RETURN_IFERR(ctconn_execute(wsr_opts->curr_stmt));

    CT_RETURN_IFERR(ctconn_fetch(wsr_opts->curr_stmt, &rows));
    if (rows == 0) {
        *stat_value = 0;
        return CTCONN_SUCCESS;
    }

    if (ctconn_get_column_by_id(wsr_opts->curr_stmt, 0, (void **)&data, &size, &is_null) != CT_SUCCESS) {
        ctsql_print_error(wsr_opts->curr_conn);
        return CTCONN_ERROR;
    }

    *stat_value = is_null ? 0 : *data;

    return CTCONN_SUCCESS;
}

int wsr_build_wsr_info_t(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "sql executions", &wsr_info->executions));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "sql execution total time", &wsr_info->dbtime));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "sql execution cpu time", &wsr_info->cputime));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "sql parses", &wsr_info->sql_parses));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "sql hard parses", &wsr_info->hard_parse));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "disk reads", &wsr_info->disk_reads));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "disk read time", &wsr_info->disk_read_time));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "buffer gets", &wsr_info->buffer_gets));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "sorts", &wsr_info->sorts));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "sort on disk", &wsr_info->sort_on_disk));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "redo write size", &wsr_info->redo_size));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "commits", &wsr_info->transactions));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "rollbacks", &wsr_info->rollbacks));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "DBWR disk writes", &wsr_info->dbwr_disk_writes));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "user calls", &wsr_info->user_calls));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "sql parses time", &wsr_info->sql_parse_time));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "user logons cumulation", &wsr_info->user_logins));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "db block changes", &wsr_info->block_changes));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "redo writes", &wsr_info->redo_writes));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "redo space requests", &wsr_info->redo_space_requests));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "SELECT executions", &wsr_info->select_executions));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "SELECT execution time", &wsr_info->select_execution_time));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "UPDATE executions", &wsr_info->update_executions));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "UPDATE execution time", &wsr_info->update_execution_time));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "INSERT executions", &wsr_info->insert_executions));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "INSERT execution time", &wsr_info->insert_execution_time));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "DELETE executions", &wsr_info->delete_executions));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "DELETE execution time", &wsr_info->delete_execution_time));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "fetched counts", &wsr_info->fetched_counts));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "fetched rows", &wsr_info->fetched_rows));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "processed rows", &wsr_info->processed_rows));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "temporary tablespace allocates", &wsr_info->temp_allocates));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "cr gets", &wsr_info->cr_gets));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "DBWR disk writes", &wsr_info->dbwr_disk_writes));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "DBWR disk write time", &wsr_info->disk_write_time));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "redo write time", &wsr_info->redo_write_time));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "total table creates", &wsr_info->table_create));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "total table drops", &wsr_info->table_drop));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "total table alters", &wsr_info->table_alter));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "total table part drops", &wsr_info->table_part_drop));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "total table subpart drops", &wsr_info->table_subpart_drop));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "total histgram inserts", &wsr_info->histgram_insert));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "total histgram updates", &wsr_info->histgram_update));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "total histgram deletes", &wsr_info->histgram_delete));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "undo buffer reads", &wsr_info->undo_buffer_reads));
    CT_RETURN_IFERR(wsr_get_sysstat(wsr_opts, "undo disk reads", &wsr_info->undo_disk_reads));
    return CTCONN_SUCCESS;
}

static void wsr_build_html_header(wsr_options_t *wsr_opts)
{
    wsr_write_str2(wsr_opts, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    wsr_write_str2(wsr_opts, "<HTML lang=\"en\"><HEAD>");
    wsr_write_str2(wsr_opts, "        <META content=\"IE=5.0000\" http-equiv=\"X-UA-Compatible\">");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<TITLE>Workload Statistics Report Snaps: %u-%u</TITLE> ",
        wsr_opts->start_snap_id, wsr_opts->end_snap_id);
    wsr_write_str2(wsr_opts, "        <META http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\">");
    wsr_write_str2(wsr_opts, "        <style type=\"text/css\"></style><STYLE type=\"text/css\">");
    wsr_write_str2(wsr_opts, "            body.wsr {font: normal 13pt Arial, Helvetica, Geneva, sans-serif;");
    wsr_write_str2(wsr_opts, "                color: black;background-color: #f1f1f1;}");
    wsr_write_str2(wsr_opts, "            table{table-layout: auto;}");
    wsr_write_str2(wsr_opts, "            .table tr {height: 30px;}");
    wsr_write_str2(wsr_opts, "            .table td{border:1px solid #ddd;");
    wsr_write_str2(wsr_opts, "                white-space: nowrap;overflow: hidden;text-overflow: ellipsis;}");
    wsr_write_str2(wsr_opts, "            .table th{text-align:left;");
    wsr_write_str2(wsr_opts, "                background:#ddd;border-collapse:collapse;");
    wsr_write_str2(wsr_opts, "                white-space: nowrap;overflow: hidden;text-overflow: ellipsis;}");
    wsr_write_str2(wsr_opts, "            h1{font: bold 16pt Arial,Helvetica,Geneva,sans-serif;");
    wsr_write_str2(wsr_opts, "                    color: white;background-color: black;");
    wsr_write_str2(wsr_opts, "                    border-bottom: 1px solid black;");
    wsr_write_str2(wsr_opts, "                    margin-top: -6pt;margin-bottom: 0pt;");
    wsr_write_str2(wsr_opts, "                    padding: 15px 0px 15px 0px;");
    wsr_write_str2(wsr_opts, "                    display: block;margin-block-start: 0.67em;");
    wsr_write_str2(wsr_opts, "                    margin-block-end: 0.67em;margin-inline-start: 0px;");
    wsr_write_str2(wsr_opts, "                    margin-inline-end: 0px;margin-left:20px;}");
    wsr_write_str2(wsr_opts, "            .title{background-color: black;}");
    wsr_write_str2(wsr_opts, "            .wsrg{color:black;font-weight: bold;} a{color:black;}");
    wsr_write_str2(wsr_opts, "            p {background-color: #ffffff;padding: 20px;");
    wsr_write_str2(wsr_opts, "                box-shadow: 0 0 20px 5px rgba(0, 0, 0, .05);");
    wsr_write_str2(wsr_opts, "                border-radius: 3px;display: block;");
    wsr_write_str2(wsr_opts, "                margin-block-start: 1em;margin-block-end: 1em;");
    wsr_write_str2(wsr_opts, "                margin-inline-start: 0px;margin-inline-end: 0px;");
    wsr_write_str2(wsr_opts, "                border:1px solid #ddd;}");
    wsr_write_str2(wsr_opts, "            .hidden {position: absolute;");
    wsr_write_str2(wsr_opts, "                left: -10000px;top: auto;width: 1px;height: 1px;");
    wsr_write_str2(wsr_opts, "                overflow: hidden;width: 100%;}");
    wsr_write_str2(wsr_opts, "            .table {width:97.5%;max-width:90%;margin-top: 10px;");
    wsr_write_str2(wsr_opts, "                font-size: 14px;border:1px solid #ddd;");
    wsr_write_str2(wsr_opts, "                -ms-border-collapse:collapse;}");
    wsr_write_str2(wsr_opts, "            table.wsrdiff {width: -webkit-fill-available;}");
    wsr_write_str2(wsr_opts, "            font {font-weight: bold;font-size: 18px;");
    wsr_write_str2(wsr_opts, "                font-family: \"Microsoft Yahei\", Arial, Tahoma, Verdana, SimSun;");
    wsr_write_str2(wsr_opts, "                color:#666;}");
    wsr_write_str2(wsr_opts, "            .pad {margin-left: 17px;} .doublepad {margin-left: 34px;}");
    wsr_write_str2(wsr_opts, "td.wsrc{font-size: 14px;font-weight: normal;height: 40px;padding-top: 10px;");
    wsr_write_str2(wsr_opts, "color:black;background:white; vertical-align:top;}</STYLE>");
    wsr_write_str2(wsr_opts, "        <META name=\"GENERATOR\" content=\"MSHTML 11.00.9600.19236\"></HEAD>");
}

int wsr_build_header_db(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    wsr_opts->header_len = wsr_opts->wsr_txtbuf.len;

    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "    <div class=\"wsr\" id=\"%s\">", wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts, "    <BODY class=\"wsr\">");
    }

    wsr_write_str2(wsr_opts, "        <div class=\"title\">");
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<H1 class=\"wsr\">Workload Statistics Report-%s</H1>", wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts, "<H1 class=\"wsr\">Workload Statistics Report</H1>");
    }
    wsr_write_str2(wsr_opts, "        </div><P>");
    wsr_write_str2(wsr_opts, "<font face=\"Courier New, Courier, mono\" color=\"#666\">Database Information</font>");
    wsr_write_str2(wsr_opts, "            <table class=\"table table-hover\" >");
    wsr_write_str2(wsr_opts, "              <thead>");
    wsr_write_str2(wsr_opts, "                <tr>");
    wsr_write_str2(wsr_opts, "                  <th>DB Name</th>");
    wsr_write_str2(wsr_opts, "                  <th>DB Id</th>");
    wsr_write_str2(wsr_opts, "                  <th>DB Role</th>");
    wsr_write_str2(wsr_opts, "                  <th>Log Mode</th>");
    wsr_write_str2(wsr_opts, "                  <th>Sharding</th>");
    wsr_write_str2(wsr_opts, "                  <th>Version</th>");
    wsr_write_str2(wsr_opts, "                </tr>");
    wsr_write_str2(wsr_opts, "              </thead>");
    wsr_write_str2(wsr_opts, "              <tbody>");
    wsr_write_str2(wsr_opts, "                <tr>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                  <td>%s</td>", wsr_info->dbname);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                  <td>%u</td>", wsr_info->dbid);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                  <td>%s</td>", wsr_info->database_role);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                  <td>%s</td>", wsr_info->log_mode);
    wsr_write_str2(wsr_opts, "                  <td>NO</td>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                  <td>%s</td>", wsr_info->version);
    wsr_write_str2(wsr_opts, "                </tr> ");
    wsr_write_str2(wsr_opts, "              </tbody>");
    wsr_write_str2(wsr_opts, "            </table>");
    wsr_write_str2(wsr_opts, "        <P>");
    return CTCONN_SUCCESS;
}

int wsr_build_header_instance(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    wsr_write_str2(wsr_opts, "<font face=\"Courier New, Courier, mono\" color=\"#666\">Instance Information </font>");
    wsr_write_str2(wsr_opts, "            <table class=\"table table-hover\" >");
    wsr_write_str2(wsr_opts, "              <thead>");
    wsr_write_str2(wsr_opts, "                <tr>");
    wsr_write_str2(wsr_opts, "                  <th>Instance Name</th>");
    wsr_write_str2(wsr_opts, "                  <th>Instance Id</th>");
    wsr_write_str2(wsr_opts, "                  <th>Copy Status</th>");
    wsr_write_str2(wsr_opts, "                  <th>Instance Startup</th>");
    wsr_write_str2(wsr_opts, "                </tr>");
    wsr_write_str2(wsr_opts, "              </thead>");
    wsr_write_str2(wsr_opts, "              <tbody>");
    wsr_write_str2(wsr_opts, "                   <tr>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                     <td>%s</td>", wsr_info->instance_name);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                     <td>%u</td>", wsr_info->instance_id);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                     <td>%s</td>", wsr_info->copy_status);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                     <td>%s</td>", wsr_info->db_startup_time);
    wsr_write_str2(wsr_opts, "                   </tr>");
    wsr_write_str2(wsr_opts, "               </tbody>");
    wsr_write_str2(wsr_opts, "                </table>");
    wsr_write_str2(wsr_opts, "        <P>");
    return CTCONN_SUCCESS;
}

int wsr_build_header_host(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    wsr_write_str2(wsr_opts, "<font face=\"Courier New, Courier, mono\" color=\"#666\">Host Information </font>");
    wsr_write_str2(wsr_opts, "            <table class=\"table table-hover\" >");
    wsr_write_str2(wsr_opts, "              <thead>");
    wsr_write_str2(wsr_opts, "                <tr>");
    wsr_write_str2(wsr_opts, "                  <th>Host Name</th>");
    wsr_write_str2(wsr_opts, "                  <th>Operating System</th>");
    wsr_write_str2(wsr_opts, "                  <th>CPUs</th>");
    wsr_write_str2(wsr_opts, "                  <th>CPU Cores</th>");
    wsr_write_str2(wsr_opts, "                  <th>CPU Sockets</th>");
    wsr_write_str2(wsr_opts, "                  <th>Memory (MB)</th>");
    wsr_write_str2(wsr_opts, "                </tr>");
    wsr_write_str2(wsr_opts, "              </thead>");
    wsr_write_str2(wsr_opts, "              <tbody>");
    wsr_write_str2(wsr_opts, "                <tr>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                  <td>%s</td>", wsr_info->host_name);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                  <td>%s</td>", wsr_info->platform);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                  <td>%u</td>", wsr_info->num_cpu);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                  <td>%u</td>", wsr_info->num_core);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                  <td>%u</td>", wsr_info->num_cpu_socket);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                  <td>%u</td>", wsr_info->memory);
    wsr_write_str2(wsr_opts, "                </tr>");
    wsr_write_str2(wsr_opts, "              </tbody>");
    wsr_write_str2(wsr_opts, "            </table>    ");
    wsr_write_str2(wsr_opts, "        <p>");
    return CTCONN_SUCCESS;
}

int wsr_build_header(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    wsr_build_html_header(wsr_opts);
    CT_RETURN_IFERR(wsr_build_header_db(wsr_opts, wsr_info));
    CT_RETURN_IFERR(wsr_build_header_instance(wsr_opts, wsr_info));
    CT_RETURN_IFERR(wsr_build_header_host(wsr_opts, wsr_info));

    wsr_write_str2(wsr_opts, " <font face=\"Courier New, Courier, mono\" color=\"#666\">Snap Information</font>");
    wsr_write_str2(wsr_opts, "            <table class=\"table table-hover\" >");
    wsr_write_str2(wsr_opts, "              <thead>");
    wsr_write_str2(wsr_opts, "                <tr>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">Elapsed Time</div></th>",
        g_wsritemdesc[WSR_ITEM_ElAPSED]);

    if (wsr_opts->input_snap_id) {
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">DB Time</div></th>",
            g_wsritemdesc[WSR_ITEM_DBTIME]);
    }

    wsr_write_str2(wsr_opts, "</tr></thead><tbody><tr>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<td>%12.2f (mins)</td>", (float)wsr_info->elapsed / WSR_UNIT_SIXTY);

    if (wsr_opts->input_snap_id) {
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<td>%12.2f (mins)</td>",
            (double)wsr_info->dbtime / WSR_MILLION / WSR_UNIT_SIXTY);
    }
    wsr_write_str2(wsr_opts, "</tr></tbody></table>");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover\" ><thead><tr><th>Snap Id</th><th>Snap Time</th>");
    wsr_write_str2(wsr_opts, "<th>Sessions</th><th>Cursors</th></tr></thead><tbody>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<tr><td>%u</td>", wsr_opts->start_snap_id);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<td>%s</td>", wsr_info->start_time);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<td>%u</td><td>%u</td></tr>", wsr_info->sessions_start,
        wsr_info->cursors_start);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<tr><td>%u</td>", wsr_opts->end_snap_id);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<td>%s</td>", wsr_info->end_time);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<td>%u</td><td>%u</td>", wsr_info->sessions_end, wsr_info->cursors_end);
    wsr_write_str2(wsr_opts, "</tr></tbody></table><p/>");

    return CTCONN_SUCCESS;
}

int wsr_build_load_profile_head(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover\" ><thead><tr>");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a class=\"wsrg\" href=\"#31001-%u\">Report Summary</a></td></tr>", wsr_info->dbid);
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<tr><td><a class=\"wsrg\" href=\"#30001-%u\">Database Load</a></td></tr>", wsr_info->dbid);
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<tr><td><a class=\"wsrg\" href=\"#30002-%u\">Instance Efficiency </a></td></tr>", wsr_info->dbid);
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<tr><td><a class=\"wsrg\" href=\"#30003-%u\">Top 10 Events by Total Wait Time</a></td>", wsr_info->dbid);
    wsr_write_str2(wsr_opts, "                </tr>");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<tr><td><a class=\"wsrg\" href=\"#30004-%u\">Host CPU</a></td>",
        wsr_info->dbid);
    wsr_write_str2(wsr_opts, "</tr><tr>");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<td><a class=\"wsrg\" href=\"#30005-%u\">Host Memory</a></td>",
        wsr_info->dbid);
    wsr_write_str2(wsr_opts, "</tr><tr>");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<td><a class=\"wsrg\" href=\"#30006-%u\">Instance Statistics</a></td>",
        wsr_info->dbid);
    wsr_write_str2(wsr_opts, "</tr><tr>");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<td><a class=\"wsrg\" href=\"#30007-%u\">Session Statistics</a></td>",
        wsr_info->dbid);
    wsr_write_str2(wsr_opts, "</tr><tr>");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<td><a class=\"wsrg\" href=\"#30008-%u\">SQL Statistics</a></td>",
        wsr_info->dbid);
    wsr_write_str2(wsr_opts, "</tr><tr>");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a class=\"wsrg\" href=\"#30009-%u\">Complete List of SQL Text</a></td></tr><tr>", wsr_info->dbid);
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<td><a class=\"wsrg\" href=\"#30010-%u\">Segment Statistics</a></td>",
        wsr_info->dbid);
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<tr><td><a class=\"wsrg\" href=\"#30011-%u\">Instance Parameters</a></td>", wsr_info->dbid);
    wsr_write_str2(wsr_opts, "</tr></thead></table><p />");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"30001-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Database Load %s</font>", wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts, "<font face=\"Courier New, Courier, mono\" color=\"#666\">Database Load</font>");
    }
    wsr_write_str2(wsr_opts, "<!-- <h2 class=\"wsr\">Database Load</h2> -->");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover\" >");
    wsr_write_str2(wsr_opts, "<thead><tr><th>Attribute</th>");
    wsr_write_str2(wsr_opts, "<th>Total</th><th>Per Second</th><th>Per Transaction</th>");
    wsr_write_str2(wsr_opts, "<th>Per Exec</th></tr></thead><tbody>");
    return CTCONN_SUCCESS;
}

int wsr_build_load_profile(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    CT_RETURN_IFERR(wsr_build_load_profile_head(wsr_opts, wsr_info));
    wsr_write_per_profile(wsr_opts, wsr_info, "DB Time(s)", wsr_info->dbtime / WSR_MILLION,
        g_wsritemdesc[WSR_ITEM_DBTIME]);
    wsr_write_per_profile(wsr_opts, wsr_info, "DB CPU(s)", wsr_info->cputime / WSR_MILLION, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Redo size (bytes)", wsr_info->redo_size, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Redo write time", wsr_info->redo_write_time / WSR_MILLION, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Redo writes", wsr_info->redo_writes, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Logical read", wsr_info->buffer_gets, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "CR gets", wsr_info->cr_gets, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Page changes", wsr_info->block_changes, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Physical read", wsr_info->disk_reads, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "DBWR disk writes", wsr_info->dbwr_disk_writes, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "DBWR disk write time", wsr_info->disk_write_time / WSR_MILLION, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "User calls", wsr_info->user_calls, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "SQL parse time", wsr_info->sql_parse_time / WSR_MILLION, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Parses (SQL)", wsr_info->sql_parses, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Hard parses (SQL)", wsr_info->hard_parse, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Logons", wsr_info->user_logins, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Executes (SQL)", wsr_info->executions, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Rollbacks", wsr_info->rollbacks, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Transactions", wsr_info->transactions, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Select executions", wsr_info->select_executions, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Select execution time",
        wsr_info->select_execution_time / WSR_MILLION, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Insert executions", wsr_info->insert_executions, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Insert execution time",
        wsr_info->insert_execution_time / WSR_MILLION, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Update executions", wsr_info->update_executions, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Update execution time",
        wsr_info->update_execution_time / WSR_MILLION, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Delete executions", wsr_info->delete_executions, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Delete execution time",
        wsr_info->delete_execution_time / WSR_MILLION, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Fetched counts", wsr_info->fetched_counts, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Fetched rows", wsr_info->fetched_rows, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Processed rows", wsr_info->processed_rows, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Sorts", wsr_info->sorts, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Sort on disk", wsr_info->sort_on_disk, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Temp allocates", wsr_info->temp_allocates, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Table create", wsr_info->table_create,
        g_wsrheadloaddesc[WSR_LOAD_TABLE_CREATE]);
    wsr_write_per_profile(wsr_opts, wsr_info, "Table drop", wsr_info->table_drop,
        g_wsrheadloaddesc[WSR_LOAD_TABLE_DROP]);
    wsr_write_per_profile(wsr_opts, wsr_info, "Table alter", wsr_info->table_alter,
        g_wsrheadloaddesc[WSR_LOAD_TABLE_ALTER]);
    wsr_write_per_profile(wsr_opts, wsr_info, "Table part drop", wsr_info->table_part_drop,
        g_wsrheadloaddesc[WSR_LOAD_TABLE_PART_DROP]);
    wsr_write_per_profile(wsr_opts, wsr_info, "Table subpart drop", wsr_info->table_subpart_drop,
        g_wsrheadloaddesc[WSR_LOAD_TABLE_SUBPART_DROP]);
    wsr_write_per_profile(wsr_opts, wsr_info, "Histgram insert rows", wsr_info->histgram_insert,
        g_wsrheadloaddesc[WSR_LOAD_HISTGRAM_INSERT]);
    wsr_write_per_profile(wsr_opts, wsr_info, "Histgram update rows", wsr_info->histgram_update,
        g_wsrheadloaddesc[WSR_LOAD_HISTGRAM_UPDATE]);
    wsr_write_per_profile(wsr_opts, wsr_info, "Histgram delete rows", wsr_info->histgram_delete,
        g_wsrheadloaddesc[WSR_LOAD_HISTGRAM_DELETE]);
    wsr_write_per_profile(wsr_opts, wsr_info, "Undo logical read", wsr_info->undo_buffer_reads, "");
    wsr_write_per_profile(wsr_opts, wsr_info, "Undo physical read", wsr_info->undo_disk_reads, "");
    wsr_write_str2(wsr_opts, "</tbody></table><p />");

    return CTCONN_SUCCESS;
}

int wsr_build_efficiency_html(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"30002-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Instance Efficiency %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Instance Efficiency</font>");
    }
    wsr_write_str2(wsr_opts, "            <!-- <h2 class=\"wsr\">Instance Efficiency</h2> -->");
    wsr_write_str2(wsr_opts, "            <table class=\"table table-hover\" >");
    wsr_write_str2(wsr_opts, "              <tbody>");
    wsr_write_str2(wsr_opts, "                   <tr>");
    wsr_write_str2(wsr_opts, "                     <td>Buffer Nowait %:</td>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                     <td>%s</td>", wsr_info->buffer_nowait);
    wsr_write_str2(wsr_opts, "                     <td>Redo NoWait %:</td>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                     <td>%12.2f</td>",
        wsr_per_rate(wsr_info->redo_space_requests, wsr_info->redo_entries));
    wsr_write_str2(wsr_opts, "                   </tr>");
    wsr_write_str2(wsr_opts, "                   <tr>");
    wsr_write_str2(wsr_opts, "                     <td>Buffer Hit %:</td>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                     <td>%12.2f</td>",
        wsr_per_rate(wsr_info->disk_reads, wsr_info->buffer_gets));
    wsr_write_str2(wsr_opts, "                     <td>In-memory Sort %:</td>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                     <td>%12.2f</td>",
        wsr_per_rate(wsr_info->sort_on_disk, wsr_info->sorts));
    wsr_write_str2(wsr_opts, "                   </tr>");
    wsr_write_str2(wsr_opts, "                   <tr>");
    wsr_write_str2(wsr_opts, "                     <td>Library Hit %:</td>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                     <td>%s</td>", wsr_info->library_hit);
    wsr_write_str2(wsr_opts, "                     <td>Soft Parse %:</td>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                     <td>%12.2f</td>",
        wsr_per_rate(wsr_info->hard_parse, wsr_info->sql_parses));
    wsr_write_str2(wsr_opts, "                   </tr>");
    wsr_write_str2(wsr_opts, "                   <tr>");
    wsr_write_str2(wsr_opts, "                     <td>Execute to Parse %:</td>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                     <td>%12.2f</td>",
        wsr_rate_percent(wsr_info->executions, wsr_info->sql_parses));
    wsr_write_str2(wsr_opts, "                     <td>Latch Hit %:</td>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                     <td>%s</td>", wsr_info->latch_hit);
    wsr_write_str2(wsr_opts, "                   </tr>");
    wsr_write_str2(wsr_opts, "               </tbody>");
    wsr_write_str2(wsr_opts, "            </table>        ");
    wsr_write_str2(wsr_opts, "            <p />");
    return CTCONN_SUCCESS;
}

int wsr_build_efficiency_latchhit(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    uint32 rows;
    int iret_sprintf;
    char cmd_buf[MAX_CMD_LEN + 1];
    ctconn_stmt_t curr_stmt = wsr_opts->curr_stmt;

    // Latch Hit
    iret_sprintf = sprintf_s(cmd_buf, MAX_CMD_LEN,
        "SELECT TO_CHAR((1-(MISSES_NEW-MISSES_OLD)/DECODE((GETS_NEW-GETS_OLD), 0, "
        "1 :: BINARY_BIGINT , (GETS_NEW-GETS_OLD)))*100, 'FM99999999999999999990.00') FROM "
        " (SELECT SUM(MISSES) MISSES_OLD, SUM(GETS) GETS_OLD "
        "FROM SYS." WSR_TB_LATCH " WHERE SNAP_ID = %u) A, "
        " (SELECT SUM(MISSES) MISSES_NEW, SUM(GETS) GETS_NEW "
        "FROM SYS." WSR_TB_LATCH " WHERE SNAP_ID = %u) B ",
        wsr_opts->start_snap_id, wsr_opts->end_snap_id);

    PRTS_RETURN_IFERR(iret_sprintf);
    CT_RETURN_IFERR(wsr_execute_sql(curr_stmt, &rows, cmd_buf));
    CT_RETURN_IFERR(ctconn_column_as_string(curr_stmt, 0, wsr_info->latch_hit, MAX_WSR_DATE_LEN));
    return CTCONN_SUCCESS;
}

int wsr_build_efficiency_buffernowait(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    uint32 rows;
    int iret_sprintf;
    char cmd_buf[MAX_CMD_LEN + 1];
    ctconn_stmt_t curr_stmt = wsr_opts->curr_stmt;

    // Buffer Nowait
    iret_sprintf = sprintf_s(cmd_buf, MAX_CMD_LEN,
        "SELECT TO_CHAR((1 - BUSY / DECODE(%llu, 0, 1 :: BINARY_BIGINT, %llu)) * 100, "
        "'FM99999999999999999990.00') "
        "FROM( "
        " SELECT SUM(DECODE(SNAP_ID, %u, COUNT, 0)) - SUM(DECODE(SNAP_ID, %u, COUNT, 0)) BUSY "
        " FROM SYS." WSR_TB_WAITSTAT " "
        " WHERE CLASS IN('DATA BLOCK', 'SEGMENT HEADER', 'UNDO HEADER', 'UNDO BLOCK') "
        " AND SNAP_ID IN(%u, %u) "
        ")",
        wsr_info->buffer_gets, wsr_info->buffer_gets, wsr_opts->end_snap_id,
        wsr_opts->start_snap_id,
        wsr_opts->start_snap_id, wsr_opts->end_snap_id);

    PRTS_RETURN_IFERR(iret_sprintf);
    CT_RETURN_IFERR(wsr_execute_sql(curr_stmt, &rows, cmd_buf));
    CT_RETURN_IFERR(ctconn_column_as_string(curr_stmt, 0, wsr_info->buffer_nowait, MAX_WSR_DATE_LEN));
    return CTCONN_SUCCESS;
}

int wsr_build_efficiency_libraryhit(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    uint32 rows;
    int iret_sprintf;
    char cmd_buf[MAX_CMD_LEN + 1];
    ctconn_stmt_t curr_stmt = wsr_opts->curr_stmt;

    // Library Hit
    iret_sprintf = sprintf_s(cmd_buf, MAX_CMD_LEN,
        "SELECT TO_CHAR(PINHITS / DECODE(PINS, 0, 1 :: BINARY_BIGINT, PINS) * 100, 'FM99999999999999999990.00') "
        "FROM( "
        "    SELECT SUM(DECODE(SNAP_ID, %u, PINHITS, 0)) - SUM(DECODE(SNAP_ID, %u, PINHITS, 0)) PINHITS, "
        "    SUM(DECODE(SNAP_ID, %u, PINS, 0)) - SUM(DECODE(SNAP_ID, %u, PINS, 0)) PINS "
        "    FROM SYS." WSR_TB_LIBRARYCACHE " "
        "    WHERE SNAP_ID IN(%u, %u) "
        ") ",
        wsr_opts->end_snap_id, wsr_opts->start_snap_id, wsr_opts->end_snap_id, wsr_opts->start_snap_id,
        wsr_opts->end_snap_id, wsr_opts->start_snap_id);

    PRTS_RETURN_IFERR(iret_sprintf);
    CT_RETURN_IFERR(wsr_execute_sql(curr_stmt, &rows, cmd_buf));
    CT_RETURN_IFERR(ctconn_column_as_string(curr_stmt, 0, wsr_info->library_hit, MAX_WSR_DATE_LEN));
    return CTCONN_SUCCESS;
}

int wsr_build_efficiency(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    CT_RETURN_IFERR(wsr_build_efficiency_latchhit(wsr_opts, wsr_info));
    CT_RETURN_IFERR(wsr_build_efficiency_buffernowait(wsr_opts, wsr_info));
    CT_RETURN_IFERR(wsr_build_efficiency_libraryhit(wsr_opts, wsr_info));
    CT_RETURN_IFERR(wsr_build_efficiency_html(wsr_opts, wsr_info));
    return CTCONN_SUCCESS;
}

int wsr_build_top_events(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    char cmd_buf[MAX_CMD_LEN + 2];
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"30003-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Top 10 Events by Total Wait Time %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Top 10 Events by Total Wait Time</font>");
    }
    wsr_write_str2(wsr_opts, "            <!-- <h2 class=\"wsr\">Top 10 Events by Total Wait Time</h2> -->");
    wsr_write_str2(wsr_opts, "            <table class=\"table table - hover\" >");
    wsr_write_str2(wsr_opts, "              <thead>");
    wsr_write_str2(wsr_opts, "                <tr>");
    wsr_write_str2(wsr_opts, "                  <th>Event</th>");
    wsr_write_str2(wsr_opts, "                  <th>Waits</th>");
    wsr_write_str2(wsr_opts, "                  <th>Total Wait Time (sec)</th>");
    wsr_write_str2(wsr_opts, "                  <th>Wait Avg(ms)</th>");
    wsr_write_str2(wsr_opts, "                  <th>% DB time</th>");
    wsr_write_str2(wsr_opts, "                  <th>Wait Class</th>");
    wsr_write_str2(wsr_opts, "                </tr>");
    wsr_write_str2(wsr_opts, "              </thead>");
    wsr_write_str2(wsr_opts, "              <tbody>");

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN,
        "SELECT B.EVENT, NVL(TO_CHAR(B.TOTAL_WAITS - A.TOTAL_WAITS), '&nbsp'), B.TIME_WAITED - A.TIME_WAITED ,"
        "NVL(TO_CHAR((B.TIME_WAITED_MIRCO - A.TIME_WAITED_MIRCO) / "
        "(B.TOTAL_WAITS - A.TOTAL_WAITS) / 1000, 'FM99999999999999999990.000'), '&nbsp') ,"
        "ROUND((B.TIME_WAITED_MIRCO - A.TIME_WAITED_MIRCO)/"
        "(SELECT NVL(SUM(B.TIME_WAITED_MIRCO - A.TIME_WAITED_MIRCO), 1) "
        "FROM ADM_HIST_SYSTEM_EVENT A, ADM_HIST_SYSTEM_EVENT B WHERE A.SNAP_ID = %u AND B.SNAP_ID = %u "
        "AND A.EVENT# = B.EVENT# "
        "AND NVL(B.TOTAL_WAITS - A.TOTAL_WAITS, -1) <> 0 AND (B.WAIT_CLASS <> 'Idle' "
        "OR B.WAIT_CLASS IS NULL)) * 100, 2), "
        "NVL(B.WAIT_CLASS, '&nbsp') "
        "FROM ADM_HIST_SYSTEM_EVENT A, ADM_HIST_SYSTEM_EVENT B "
        "WHERE A.SNAP_ID = %u AND B.SNAP_ID = %u AND A.EVENT# = B.EVENT# "
        "AND NVL(B.TOTAL_WAITS - A.TOTAL_WAITS, -1) <> 0 AND (B.WAIT_CLASS <> 'Idle' OR B.WAIT_CLASS IS NULL) "
        "ORDER BY 5 DESC, 3 DESC LIMIT 10 ", wsr_opts->start_snap_id, wsr_opts->end_snap_id,
        wsr_opts->start_snap_id, wsr_opts->end_snap_id));

    CT_RETURN_IFERR(ctconn_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    CT_RETURN_IFERR(ctconn_execute(wsr_opts->curr_stmt));

    CT_RETURN_IFERR(wsr_build_top_events_deal(wsr_opts));

    wsr_write_str2(wsr_opts, "</tbody>");
    wsr_write_str2(wsr_opts, "</table><p />");

    return CTCONN_SUCCESS;
}

int wsr_build_host_cpu(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    uint32 rows;
    char cmd_buf[MAX_CMD_LEN + 1];

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN,
        "SELECT NVL(TO_CHAR(DECODE(TOTAL, 0, 0 :: BINARY_BIGINT, (B.VALUE - A.VALUE)/TOTAL * 100), "
        "'FM99999999999999999990.000') , '&nbsp') "
        "FROM( SELECT SUM(B.VALUE - A.VALUE) TOTAL FROM ADM_HIST_SYSTEM A, ADM_HIST_SYSTEM B "
        "WHERE A.SNAP_ID = %u AND B.SNAP_ID = %u AND A.STAT_ID = B.STAT_ID "
        "AND A.STAT_ID BETWEEN 3 AND 8 ), ADM_HIST_SYSTEM A, ADM_HIST_SYSTEM B "
        "WHERE A.SNAP_ID = %u AND B.SNAP_ID = %u AND A.STAT_ID = B.STAT_ID "
        "AND A.STAT_ID IN(3, 5, 6, 7) ORDER BY A.STAT_ID ",
        wsr_opts->start_snap_id, wsr_opts->end_snap_id, wsr_opts->start_snap_id, wsr_opts->end_snap_id));

    CT_RETURN_IFERR(ctconn_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    CT_RETURN_IFERR(ctconn_execute(wsr_opts->curr_stmt));

    CT_RETURN_IFERR(ctconn_fetch(wsr_opts->curr_stmt, &rows));

    if (rows == 0) {
        return CTCONN_ERROR;
    }

    CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, 0, wsr_info->cpu_idle, MAX_WSR_DATE_LEN));

    CT_RETURN_IFERR(ctconn_fetch(wsr_opts->curr_stmt, &rows));

    if (rows == 0) {
        return CTCONN_ERROR;
    }

    CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, 0, wsr_info->cpu_user, MAX_WSR_DATE_LEN));

    CT_RETURN_IFERR(ctconn_fetch(wsr_opts->curr_stmt, &rows));

    if (rows == 0) {
        return CTCONN_ERROR;
    }

    CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, 0, wsr_info->cpu_system, MAX_WSR_DATE_LEN));

    CT_RETURN_IFERR(ctconn_fetch(wsr_opts->curr_stmt, &rows));

    if (rows == 0) {
        return CTCONN_ERROR;
    }

    CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, 0, wsr_info->cpu_wio, MAX_WSR_DATE_LEN));

    wsr_build_host_cpu_write_str(wsr_opts, wsr_info);

    return CTCONN_SUCCESS;
}

int wsr_build_host_mem(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    uint64 vm_page_in_bytes;
    uint64 vm_page_out_bytes;

    CT_RETURN_IFERR(wsr_get_system(wsr_opts, "VM_PAGE_IN_BYTES", &vm_page_in_bytes));
    CT_RETURN_IFERR(wsr_get_system(wsr_opts, "VM_PAGE_OUT_BYTES", &vm_page_out_bytes));
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "            <a class=\"wsr\" name=\"30005-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Host Memory %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts, "<font face=\"Courier New, Courier, mono\" color=\"#666\">Host Memory</font>");
    }
    wsr_write_str2(wsr_opts, "            <!-- <h2 class=\"wsr\">Host Memory</h2> -->");
    wsr_write_str2(wsr_opts, "            <table class=\"table table-hover\" >");
    wsr_write_str2(wsr_opts, "              <thead>");
    wsr_write_str2(wsr_opts, "                <tr>");
    wsr_write_str2(wsr_opts, "                  <th>VM_PAGE_IN_BYTES</th>");
    wsr_write_str2(wsr_opts, "                  <th>VM_PAGE_OUT_BYTES</th>");
    wsr_write_str2(wsr_opts, "                </tr>");
    wsr_write_str2(wsr_opts, "              </thead>");
    wsr_write_str2(wsr_opts, "              <tbody>");
    wsr_write_str2(wsr_opts, "                <tr>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<td>%llu</td>", vm_page_in_bytes);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<td>%llu</td>", vm_page_out_bytes);
    wsr_write_str2(wsr_opts, "                </tr>");
    wsr_write_str2(wsr_opts, "              </tbody>");
    wsr_write_str2(wsr_opts, "            </table>");
    wsr_write_str2(wsr_opts, "            <p />");

    return CTCONN_SUCCESS;
}