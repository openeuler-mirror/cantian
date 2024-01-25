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
 * ctsql_wsr_segment.c
 *
 *
 * IDENTIFICATION
 * src/utils/ctsql/ctsql_wsr_segment.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_wsr_segment.h"

typedef enum {
    EWSR_SGEMENT_PHYSICALREAD,
    EWSR_SGEMENT_PHYSICALWRITE,
    EWSR_SGEMENT_LOGICALREAD,
    EWSR_SGEMENT_ITLWAIT,
    EWSR_SGEMENT_BUFFERBUSYWAIT,
    EWSR_SGEMENT_ROWLOCK
} monitor_item_t;

static int wsr_build_sql_query_segment_total(wsr_options_t *wsr_opts, wsr_info_t *wsr_info, uint32 statistics_id,
    uint64 *totalvalue)
{
    uint32 rows;
    int iret_sprintf;
    uint64 *data = NULL;
    bool32 is_null = CT_FALSE;
    uint32 size;
    char cmd_buf[MAX_CMD_LEN + 1];

    iret_sprintf = sprintf_s(cmd_buf, MAX_CMD_LEN,
        "SELECT/*+USE_HASH(X,Y)*/ CAST(SUM(X.VALUE - NVL(Y.VALUE, 0)) AS BINARY_BIGINT) "
        "FROM( "
        "    SELECT SNAP_ID, OWNER, OBJECT_NAME, NVL(SUBOBJECT_NAME, ' ') SUBOBJECT_NAME, "
        "TS#, OBJECT_TYPE, STATISTIC#, VALUE "
        "    FROM SYS." WSR_TB_SEGMENT " A "
        "    WHERE A.SNAP_ID = %u "
        "    AND STATISTIC#   = %u "
        ") X LEFT OUTER JOIN "
        "( "
        "    SELECT SNAP_ID, OWNER, OBJECT_NAME, NVL(SUBOBJECT_NAME, ' ') SUBOBJECT_NAME, TS#, "
        "OBJECT_TYPE, STATISTIC#, VALUE "
        "    FROM SYS." WSR_TB_SEGMENT " A "
        "    WHERE A.SNAP_ID = %u "
        "    AND STATISTIC#   = %u "
        ") Y "
        "ON Y.OWNER = X.OWNER AND Y.OBJECT_NAME = X.OBJECT_NAME AND Y.SUBOBJECT_NAME = X.SUBOBJECT_NAME "
        "AND Y.OBJECT_TYPE= X.OBJECT_TYPE WHERE X.VALUE - NVL(Y.VALUE, 0) > 0 ",
        wsr_opts->end_snap_id, statistics_id, wsr_opts->start_snap_id, statistics_id);
    if (iret_sprintf == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(ctconn_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    CT_RETURN_IFERR(ctconn_execute(wsr_opts->curr_stmt));

    CT_RETURN_IFERR(ctconn_fetch(wsr_opts->curr_stmt, &rows));

    if (rows == 0) {
        return CT_ERROR;
    }

    if (ctconn_get_column_by_id(wsr_opts->curr_stmt, 0, (void **)&data, &size, &is_null) != CT_SUCCESS) {
        ctsql_print_error(wsr_opts->curr_conn);
        return CTCONN_ERROR;
    }

    *totalvalue = is_null ? 0 : *data;

    return CTCONN_SUCCESS;
}

static int wsr_build_sql_query_segment(wsr_options_t *wsr_opts, wsr_info_t *wsr_info, uint32 statistics_id,
    uint64 total_value)
{
    int iret_sprintf;
    char cmd_buf[MAX_CMD_LEN + 1];

    iret_sprintf = sprintf_s(cmd_buf, MAX_CMD_LEN,
        "SELECT X.SNAP_ID, X.OWNER, X.OBJECT_NAME, X.SUBOBJECT_NAME, "
        "(SELECT NAME FROM DV_TABLESPACES WHERE ID = X.TS#), "
        "X.OBJECT_TYPE, X.VALUE - NVL(Y.VALUE, 0), "
        "TO_CHAR((X.VALUE - NVL(Y.VALUE, 0))/%llu*100, 'FM99999999999999999990.000') "
        "FROM( "
        "    SELECT SNAP_ID, OWNER, OBJECT_NAME, NVL(SUBOBJECT_NAME, '&nbsp') SUBOBJECT_NAME, "
        "TS#, OBJECT_TYPE, STATISTIC#, VALUE "
        "    FROM SYS." WSR_TB_SEGMENT " A "
        "    WHERE A.SNAP_ID = %u "
        "    AND STATISTIC#   = %u "
        ") X LEFT OUTER JOIN "
        "( "
        "    SELECT SNAP_ID, OWNER, OBJECT_NAME, NVL(SUBOBJECT_NAME, '&nbsp') SUBOBJECT_NAME, "
        "TS#, OBJECT_TYPE, STATISTIC#, VALUE "
        "    FROM SYS." WSR_TB_SEGMENT " A "
        "    WHERE A.SNAP_ID = %u "
        "    AND STATISTIC#   = %u "
        ") Y "
        "ON Y.OWNER = X.OWNER AND Y.OBJECT_NAME = X.OBJECT_NAME AND Y.SUBOBJECT_NAME = X.SUBOBJECT_NAME "
        "AND Y.OBJECT_TYPE= X.OBJECT_TYPE WHERE X.VALUE - NVL(Y.VALUE, 0) > 0 "
        "ORDER BY 7 DESC "
        "LIMIT %u",
        total_value, wsr_opts->end_snap_id, statistics_id, wsr_opts->start_snap_id, statistics_id, wsr_info->topnsql);
    if (iret_sprintf == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(ctconn_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    CT_RETURN_IFERR(ctconn_execute(wsr_opts->curr_stmt));

    return CTCONN_SUCCESS;
}

static int wsr_build_segment_one_row(wsr_options_t *wsr_opts, wsr_segment_info_t* wsr_segment_info)
{
    uint32 index = 1;
    CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, index++, wsr_segment_info->owner, MAX_WSR_ENTITY_LEN));
    CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, index++, wsr_segment_info->object_name,
        MAX_WSR_ENTITY_LEN));
    CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, index++,
        wsr_segment_info->subobject_name, MAX_WSR_ENTITY_LEN));
    CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, index++,
        wsr_segment_info->tablespace_name, MAX_WSR_ENTITY_LEN));
    CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, index++, wsr_segment_info->object_type,
        MAX_WSR_ENTITY_LEN));
    CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, index++, wsr_segment_info->value, MAX_WSR_ENTITY_LEN));
    CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, index++, wsr_segment_info->rate, MAX_WSR_ENTITY_LEN));

    return CTCONN_SUCCESS;
}

static int wsr_build_segment_logicread_head(wsr_options_t *wsr_opts, wsr_info_t *wsr_info, uint64 total_value)
{
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"4000-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Segments by Logical Reads %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Segments by Logical Reads</font>");
    }
    wsr_write_str2(wsr_opts, "<!-- <h2 class=\"wsr\">Segments by Logical Reads</h2> -->");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover\" >");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<td>Total Logical Reads : %llu </td>", total_value);
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "</table>");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover table-striped\">");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr><th class=\"wsrbg\" scope=\"col\">Owner</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Tablespace Name</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Object Name</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Partition Name</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Obj. Type</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Logical Reads</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">%Total</th></tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "<tbody>");
    return CTCONN_SUCCESS;
}

static int wsr_build_segment_logicread(wsr_options_t *wsr_opts,
    wsr_info_t *wsr_info, wsr_segment_info_t *wsr_segment_info)
{
    uint32 rows;
    uint64 total_value;
    uint32 statistics_id = EWSR_SGEMENT_LOGICALREAD;

    CT_RETURN_IFERR(wsr_build_sql_query_segment_total(wsr_opts, wsr_info, statistics_id, &total_value));

    CT_RETURN_IFERR(wsr_build_segment_logicread_head(wsr_opts, wsr_info, total_value));

    if (total_value == 0) {
        wsr_write_str2(wsr_opts, "</tbody>");
        wsr_write_str2(wsr_opts, "</table><p />");
        return CTCONN_SUCCESS;
    }

    CT_RETURN_IFERR(wsr_build_sql_query_segment(wsr_opts, wsr_info, statistics_id, total_value));

    do {
        CT_RETURN_IFERR(ctconn_fetch(wsr_opts->curr_stmt, &rows));
        if (rows == 0) {
            break;
        }

        CT_RETURN_IFERR(wsr_build_segment_one_row(wsr_opts, wsr_segment_info));

        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<tr><td class='wsrc'>%s</td>", wsr_segment_info->owner);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td>", wsr_segment_info->tablespace_name);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000,
            "<td scope=\"row\" class='wsrc'>%s</td>", wsr_segment_info->object_name);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td>", wsr_segment_info->subobject_name);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td>", wsr_segment_info->object_type);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td>", wsr_segment_info->value);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td></tr>", wsr_segment_info->rate);
    } while (CT_TRUE);

    wsr_write_str2(wsr_opts, "</tbody>");
    wsr_write_str2(wsr_opts, "</table><p />");

    return CTCONN_SUCCESS;
}

static int wsr_build_segment_physicalread_head(wsr_options_t *wsr_opts, wsr_info_t *wsr_info, uint64 total_value)
{
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"4100-%u\"></a>", wsr_info->dbid);

    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Segments by Physical Reads %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Segments by Physical Reads</font>");
    }

    wsr_write_str2(wsr_opts, "<!-- <h2 class=\"wsr\">Segments by Physical Reads</h2> -->");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover\">");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<td>Total Physical Reads : %llu</td>", total_value);
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "</table>");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover table-striped\">");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr><th class=\"wsrbg\" scope=\"col\">Owner</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Tablespace Name</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Object Name</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Partition Name</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Obj. Type</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Physical Reads</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">%Total</th></tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "<tbody>");

    return CTCONN_SUCCESS;
}

static int wsr_build_segment_physicalread(wsr_options_t *wsr_opts,
    wsr_info_t *wsr_info, wsr_segment_info_t *wsr_segment_info)
{
    uint32 rows;
    uint64 total_value;
    uint32 statistics_id = EWSR_SGEMENT_PHYSICALREAD;

    CT_RETURN_IFERR(wsr_build_sql_query_segment_total(wsr_opts, wsr_info, statistics_id, &total_value));

    CT_RETURN_IFERR(wsr_build_segment_physicalread_head(wsr_opts, wsr_info, total_value));

    if (total_value == 0) {
        wsr_write_str2(wsr_opts, "</tbody>");
        wsr_write_str2(wsr_opts, "</table><p />");
        return CTCONN_SUCCESS;
    }

    CT_RETURN_IFERR(wsr_build_sql_query_segment(wsr_opts, wsr_info, statistics_id, total_value));

    do {
        CT_RETURN_IFERR(ctconn_fetch(wsr_opts->curr_stmt, &rows));
        if (rows == 0) {
            break;
        }

        CT_RETURN_IFERR(wsr_build_segment_one_row(wsr_opts, wsr_segment_info));

        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<tr><td class='wsrc'>%s</td>", wsr_segment_info->owner);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td>", wsr_segment_info->tablespace_name);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000,
            "<td scope=\"row\" class='wsrc'>%s</td>", wsr_segment_info->object_name);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td>", wsr_segment_info->subobject_name);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td>", wsr_segment_info->object_type);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td>", wsr_segment_info->value);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td  class='wsrc'>%s</td></tr>", wsr_segment_info->rate);
    } while (CT_TRUE);

    wsr_write_str2(wsr_opts, "</tbody>");
    wsr_write_str2(wsr_opts, "</table><p />");

    return CTCONN_SUCCESS;
}

static int wsr_build_segment_physicalwrite_head(wsr_options_t *wsr_opts, wsr_info_t *wsr_info, uint64 total_value)
{
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"4120-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Segments by Physical Writes %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Segments by Physical Writes</font>");
    }
    wsr_write_str2(wsr_opts, "<!-- <h2 class=\"wsr\">Segments by Physical Writes</h2> -->");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover\">");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<td>Total Physical Writes : %llu</td>", total_value);
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "</table>");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover table-striped\">");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr><th class=\"wsrbg\" scope=\"col\">Owner</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Tablespace Name</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Object Name</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Partition Name</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Obj. Type</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Physical Reads</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">%Total</th></tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "<tbody>");
    return CTCONN_SUCCESS;
}

static int wsr_build_segment_physicalwrite(wsr_options_t *wsr_opts,
    wsr_info_t *wsr_info, wsr_segment_info_t *wsr_segment_info)
{
    uint32 rows;
    uint64 total_value;
    uint32 statistics_id = EWSR_SGEMENT_PHYSICALWRITE;

    CT_RETURN_IFERR(wsr_build_sql_query_segment_total(wsr_opts, wsr_info, statistics_id, &total_value));

    CT_RETURN_IFERR(wsr_build_segment_physicalwrite_head(wsr_opts, wsr_info, total_value));

    if (total_value == 0) {
        wsr_write_str2(wsr_opts, "</tbody>");
        wsr_write_str2(wsr_opts, "</table><p />");
        return CTCONN_SUCCESS;
    }

    CT_RETURN_IFERR(wsr_build_sql_query_segment(wsr_opts, wsr_info, statistics_id, total_value));

    do {
        CT_RETURN_IFERR(ctconn_fetch(wsr_opts->curr_stmt, &rows));
        if (rows == 0) {
            break;
        }

        CT_RETURN_IFERR(wsr_build_segment_one_row(wsr_opts, wsr_segment_info));

        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<tr><td class='wsrc'>%s</td>", wsr_segment_info->owner);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td>", wsr_segment_info->tablespace_name);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td scope=\"row\" class='wsrc'>%s</td>",
            wsr_segment_info->object_name);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td>", wsr_segment_info->subobject_name);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td>", wsr_segment_info->object_type);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td>", wsr_segment_info->value);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td></tr>", wsr_segment_info->rate);
    } while (CT_TRUE);

    wsr_write_str2(wsr_opts, "</table><p />");

    return CTCONN_SUCCESS;
}

static int wsr_build_segment_rowlock_head(wsr_options_t *wsr_opts, wsr_info_t *wsr_info, uint64 total_value)
{
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"4200-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Segments by Row Lock Waits %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Segments by Row Lock Waits</font>");
    }
    wsr_write_str2(wsr_opts, "<!-- <h2 class=\"wsr\">Segments by Row Lock Waits</h2> -->");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover\">");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<td>Total Row Lock Waits : %llu</td>", total_value);
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "</table>");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover table-striped\">");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr><th class=\"wsrbg\" scope=\"col\">Owner</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Tablespace Name</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Object Name</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Partition Name</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Obj. Type</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Row Lock Waits</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">%Total</th></tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "<tbody>");

    return CTCONN_SUCCESS;
}

static int wsr_build_segment_rowlock(wsr_options_t *wsr_opts, wsr_info_t *wsr_info,
    wsr_segment_info_t *wsr_segment_info)
{
    uint32 rows;
    uint64 total_value;
    uint32 statistics_id = EWSR_SGEMENT_ROWLOCK;

    CT_RETURN_IFERR(wsr_build_sql_query_segment_total(wsr_opts, wsr_info, statistics_id, &total_value));
    CT_RETURN_IFERR(wsr_build_segment_rowlock_head(wsr_opts, wsr_info, total_value));

    if (total_value == 0) {
        wsr_write_str2(wsr_opts, "</tbody>");
        wsr_write_str2(wsr_opts, "</table><p />");
        return CTCONN_SUCCESS;
    }

    CT_RETURN_IFERR(wsr_build_sql_query_segment(wsr_opts, wsr_info, statistics_id, total_value));

    do {
        CT_RETURN_IFERR(ctconn_fetch(wsr_opts->curr_stmt, &rows));
        if (rows == 0) {
            break;
        }

        CT_RETURN_IFERR(wsr_build_segment_one_row(wsr_opts, wsr_segment_info));

        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<tr><td class='wsrc'>%s</td>", wsr_segment_info->owner);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td>", wsr_segment_info->tablespace_name);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td scope=\"row\" class='wsrc'>%s</td>",
            wsr_segment_info->object_name);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td>", wsr_segment_info->subobject_name);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td>", wsr_segment_info->object_type);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td>", wsr_segment_info->value);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td></tr>", wsr_segment_info->rate);
    } while (CT_TRUE);

    wsr_write_str2(wsr_opts, "</tbody>");
    wsr_write_str2(wsr_opts, "</table><p />");

    return CTCONN_SUCCESS;
}

static int wsr_build_segment_itlwait_head(wsr_options_t *wsr_opts, wsr_info_t *wsr_info, uint64 total_value)
{
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"4300-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Segments by Page Lock Waits %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Segments by Page Lock Waits</font>");
    }
    wsr_write_str2(wsr_opts, "<!-- <h2 class=\"wsr\">Segments by Page Lock Waits</h2> -->");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover\">");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<td>Total Page Lock Waits : %llu</td>", total_value);
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "</table>");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover table-striped\">");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr><th class=\"wsrbg\" scope=\"col\">Owner</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Tablespace Name</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Object Name</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Partition Name</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Obj. Type</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Page Lock Waits</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">%Total</th></tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "<tbody>");
    return CTCONN_SUCCESS;
}

static int wsr_build_segment_itlwait(wsr_options_t *wsr_opts,
    wsr_info_t *wsr_info, wsr_segment_info_t *wsr_segment_info)
{
    uint32 rows;
    uint64 total_value;
    uint32 statistics_id = EWSR_SGEMENT_ITLWAIT;

    CT_RETURN_IFERR(wsr_build_sql_query_segment_total(wsr_opts, wsr_info, statistics_id, &total_value));
    CT_RETURN_IFERR(wsr_build_segment_itlwait_head(wsr_opts, wsr_info, total_value));

    if (total_value == 0) {
        wsr_write_str2(wsr_opts, "</tbody>");
        wsr_write_str2(wsr_opts, "</table><p />");
        return CTCONN_SUCCESS;
    }

    CT_RETURN_IFERR(wsr_build_sql_query_segment(wsr_opts, wsr_info, statistics_id, total_value));

    do {
        CT_RETURN_IFERR(ctconn_fetch(wsr_opts->curr_stmt, &rows));
        if (rows == 0) {
            break;
        }

        CT_RETURN_IFERR(wsr_build_segment_one_row(wsr_opts, wsr_segment_info));

        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<tr><td class='wsrc'>%s</td>", wsr_segment_info->owner);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td>", wsr_segment_info->tablespace_name);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000,
            "<td scope=\"row\" class='wsrc'>%s</td>", wsr_segment_info->object_name);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td>", wsr_segment_info->subobject_name);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td>", wsr_segment_info->object_type);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td>", wsr_segment_info->value);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td></tr>", wsr_segment_info->rate);
    } while (CT_TRUE);

    wsr_write_str2(wsr_opts, "</tbody>");
    wsr_write_str2(wsr_opts, "</table><p />");

    return CTCONN_SUCCESS;
}

static int wsr_build_segment_bufferbusywait_head(wsr_options_t *wsr_opts, wsr_info_t *wsr_info, uint64 total_value)
{
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"4400-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Buffer Busy Waits %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Buffer Busy Waits</font>");
    }
    wsr_write_str2(wsr_opts, "<!-- <h2 class=\"wsr\">Buffer Busy Waits</h2> -->");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover\">");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<td>Total Buffer Busy Waits : %llu</td>", total_value);
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "</table>");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover table-striped\">");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr><th class=\"wsrbg\" scope=\"col\">Owner</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Tablespace Name</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Object Name</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Partition Name</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Obj. Type</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Buffer Busy Waits</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">%Total</th></tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "<tbody>");

    return CTCONN_SUCCESS;
}

static int wsr_build_segment_bufferbusywait(wsr_options_t *wsr_opts,
    wsr_info_t *wsr_info, wsr_segment_info_t *wsr_segment_info)
{
    uint32 rows;
    uint64 total_value;
    uint32 statistics_id = EWSR_SGEMENT_BUFFERBUSYWAIT;

    CT_RETURN_IFERR(wsr_build_sql_query_segment_total(wsr_opts, wsr_info, statistics_id, &total_value));
    CT_RETURN_IFERR(wsr_build_segment_bufferbusywait_head(wsr_opts, wsr_info, total_value));

    if (total_value == 0) {
        wsr_write_str2(wsr_opts, "</tbody>");
        wsr_write_str2(wsr_opts, "</table><p />");
        return CTCONN_SUCCESS;
    }

    CT_RETURN_IFERR(wsr_build_sql_query_segment(wsr_opts, wsr_info, statistics_id, total_value));

    do {
        CT_RETURN_IFERR(ctconn_fetch(wsr_opts->curr_stmt, &rows));
        if (rows == 0) {
            break;
        }

        CT_RETURN_IFERR(wsr_build_segment_one_row(wsr_opts, wsr_segment_info));

        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<tr><td class='wsrc'>%s</td>", wsr_segment_info->owner);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td>", wsr_segment_info->tablespace_name);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td scope=\"row\" class='wsrc'>%s</td>",
            wsr_segment_info->object_name);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td>", wsr_segment_info->subobject_name);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td>", wsr_segment_info->object_type);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td>", wsr_segment_info->value);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_1000, "<td class='wsrc'>%s</td></tr>", wsr_segment_info->rate);
    } while (CT_TRUE);

    wsr_write_str2(wsr_opts, "</tbody>");
    wsr_write_str2(wsr_opts, "</table><p />");

    return CTCONN_SUCCESS;
}

static void wsr_build_segment_html(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class = \"wsr\" name=\"30010-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Segment Statistics %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Segment Statistics</font>");
    }
    wsr_write_str2(wsr_opts, "<!-- <h2 class=\"wsr\">Segment Statistics</h2> -->");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover\" >");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a class=\"wsrg\" href=\"#4000-%u\">Segments by Logical Reads</a></td>", wsr_info->dbid);
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a class=\"wsrg\" href=\"#4100-%u\">Segments by Physical Reads</a></td>", wsr_info->dbid);
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a class=\"wsrg\" href=\"#4120-%u\">Segments by Physical Writes</a></td>", wsr_info->dbid);
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a class=\"wsrg\" href=\"#4200-%u\">Segments by Row Lock Waits</a></td>", wsr_info->dbid);
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a class=\"wsrg\" href=\"#4300-%u\">Segments by Page Lock Waits</a></td>", wsr_info->dbid);
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a class=\"wsrg\" href=\"#4400-%u\">Segments by Buffer Busy Waits</a></td>", wsr_info->dbid);
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a class=\"wsrg\" href=\"#4500-%u\">Segments by Segment Space</a></td>", wsr_info->dbid);
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "<tr>");
    wsr_write_str2(wsr_opts, "<td><a class=\"wsrg\" href=\"#top\">Back to Top</a></td>");
    wsr_write_str2(wsr_opts, "</tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "</table>");
    wsr_write_str2(wsr_opts, "<p />");
}

int wsr_build_segment_stat(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    wsr_segment_info_t wsr_segment_info_t;
    wsr_build_segment_html(wsr_opts, wsr_info);
    CT_RETURN_IFERR(wsr_build_segment_logicread(wsr_opts, wsr_info, &wsr_segment_info_t));
    CT_RETURN_IFERR(wsr_build_segment_physicalread(wsr_opts, wsr_info, &wsr_segment_info_t));
    CT_RETURN_IFERR(wsr_build_segment_physicalwrite(wsr_opts, wsr_info, &wsr_segment_info_t));
    CT_RETURN_IFERR(wsr_build_segment_rowlock(wsr_opts, wsr_info, &wsr_segment_info_t));
    CT_RETURN_IFERR(wsr_build_segment_itlwait(wsr_opts, wsr_info, &wsr_segment_info_t));
    CT_RETURN_IFERR(wsr_build_segment_bufferbusywait(wsr_opts, wsr_info, &wsr_segment_info_t));

    return CTCONN_SUCCESS;
}