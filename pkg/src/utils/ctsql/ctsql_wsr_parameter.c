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
 * ctsql_wsr_parameter.c
 *
 *
 * IDENTIFICATION
 * src/utils/ctsql/ctsql_wsr_parameter.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_wsr_parameter.h"

int wsr_build_parameter_head(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"30011-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Instance Parameters %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Instance Parameters</font>");
    }
    wsr_write_str2(wsr_opts, "<!-- <h2 class=\"wsr\">Instance Parameters</h2> -->");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover table-striped\">");
    wsr_write_str2(wsr_opts, "<thead>");
    wsr_write_str2(wsr_opts, "<tr><th class=\"wsrbg\" scope=\"col\">Parameter Name</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">Begin value</th>");
    wsr_write_str2(wsr_opts, "<th class=\"wsrbg\" scope=\"col\">End value (if different)</th></tr>");
    wsr_write_str2(wsr_opts, "</thead>");
    wsr_write_str2(wsr_opts, "<tbody>");

    return CTCONN_SUCCESS;
}

int wsr_build_parameter(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    uint32 rows;
    char para_name[MAX_WSR_ENTITY_LEN];
    char begin_value[MAX_WSR_ENTITY_LEN];
    char end_value[MAX_WSR_ENTITY_LEN];
    char cmd_buf[MAX_CMD_LEN + 1];
    uint32 index;

    CT_RETURN_IFERR(wsr_build_parameter_head(wsr_opts, wsr_info));

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN,
        "SELECT A.NAME, NVL(TRIM(A.VALUE),'&nbsp'), NVL(DECODE(B.VALUE, A.VALUE, NULL, B.VALUE),'&nbsp')  "
        "FROM ADM_HIST_PARAMETER A, ADM_HIST_PARAMETER B "
        "WHERE A.SNAP_ID = %u AND B.SNAP_ID = %u "
        "AND A.NAME = B.NAME AND (A.ISDEFAULT = 'FALSE' OR B.ISDEFAULT = 'FALSE') "
        "AND A.NAME NOT IN ('_SYS_PASSWORD', 'LOCAL_KEY', 'SSL_KEY_PASSWORD', '_FACTOR_KEY') ORDER BY 1",
        wsr_opts->start_snap_id, wsr_opts->end_snap_id));

    CT_RETURN_IFERR(ctconn_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    CT_RETURN_IFERR(ctconn_execute(wsr_opts->curr_stmt));

    do {
        index = 0;

        CT_RETURN_IFERR(ctconn_fetch(wsr_opts->curr_stmt, &rows));
        if (rows == 0) {
            break;
        }

        CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, index++, para_name, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, index++, begin_value, MAX_WSR_ENTITY_LEN));
        CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, index++, end_value, MAX_WSR_ENTITY_LEN));

        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<tr><td scope=\"row\" class='wsrc'>%s</td>", para_name);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td class='wsrc'>%s</td>", begin_value);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "<td class='wsrc'>%s</td></tr>", end_value);
    } while (CT_TRUE);

    wsr_write_str2(wsr_opts, "</tbody>");
    wsr_write_str2(wsr_opts, "</table><p />");
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_str2(wsr_opts, "    </div>");
    } else {
        wsr_write_str2(wsr_opts, "    </BODY>");
    }

    return CTCONN_SUCCESS;
}