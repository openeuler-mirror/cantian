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
 * ctsql_wsr_buffer.c
 *
 *
 * IDENTIFICATION
 * src/utils/ctsql/ctsql_wsr_buffer.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_wsr_buffer.h"

typedef struct st_wsr_buffer {
    char snap_time[MAX_WSR_ENTITY_LEN];
    char datadirty[MAX_WSR_ENTITY_LEN];
    char datapin[MAX_WSR_ENTITY_LEN];
    char datafree[MAX_WSR_ENTITY_LEN];
    char tempfree[MAX_WSR_ENTITY_LEN];
    char temphwm[MAX_WSR_ENTITY_LEN];
    char tempswap[MAX_WSR_ENTITY_LEN];
    char bufferdetail[MAX_WSR_DETAIL_LEN];
} wsr_buffer_t;

static void wsr_build_instance_buffer_head_memory(wsr_options_t *wsr_opts)
{
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">Snap Time</div></th>",
        g_wsritemdesc[WSR_ITEM_DIRTY_DATA]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">DataDirty</div></th>",
        g_wsritemdesc[WSR_ITEM_DIRTY_DATA]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">DataPin</div></th>",
        g_wsritemdesc[WSR_ITEM_PIN_DATA]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">DataFree</div></th>",
        g_wsritemdesc[WSR_ITEM_FREE_DATA]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">TempFree</div></th>",
        g_wsritemdesc[WSR_ITEM_FREE_TEMP]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">TempHWM</div></th>",
        g_wsritemdesc[WSR_ITEM_TEMP_HWM]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">TempSwap</div></th>",
        g_wsritemdesc[WSR_ITEM_TEMP_SWAP]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_10000, "<th><div title=\"%s\">DataBufferDetail(Type Total:Dirty)</div></th>",
        g_wsritemdesc[WSR_ITEM_TEMP_SWAP]);
}

static int wsr_build_instance_buffer_head(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"101-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Data Buffer & Temp Buffer %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Data Buffer & Temp Buffer</font>");
    }
    wsr_write_str2(wsr_opts, "            <table class=\"table table-hover\" >");
    wsr_write_str2(wsr_opts, "              <thead>");
    wsr_write_str2(wsr_opts, "                <tr>");
    wsr_build_instance_buffer_head_memory(wsr_opts);
    wsr_write_str2(wsr_opts, "                </tr>");
    wsr_write_str2(wsr_opts, "              </thead>");
    wsr_write_str2(wsr_opts, "              <tbody>");

    return CTCONN_SUCCESS;
}

int wsr_build_instance_memory(wsr_options_t *wsr_opts, ctconn_stmt_t *resultset, wsr_buffer_t *wsr_buffer,
    int *i_cnt)
{
    CT_RETURN_IFERR(ctconn_column_as_string(*resultset, (*i_cnt)++, wsr_buffer->snap_time, MAX_WSR_ENTITY_LEN));
    CT_RETURN_IFERR(ctconn_column_as_string(*resultset, (*i_cnt)++, wsr_buffer->datadirty, MAX_WSR_ENTITY_LEN));
    CT_RETURN_IFERR(ctconn_column_as_string(*resultset, (*i_cnt)++, wsr_buffer->datapin, MAX_WSR_ENTITY_LEN));
    CT_RETURN_IFERR(ctconn_column_as_string(*resultset, (*i_cnt)++, wsr_buffer->datafree, MAX_WSR_ENTITY_LEN));
    CT_RETURN_IFERR(ctconn_column_as_string(*resultset, (*i_cnt)++, wsr_buffer->tempfree, MAX_WSR_ENTITY_LEN));
    CT_RETURN_IFERR(ctconn_column_as_string(*resultset, (*i_cnt)++, wsr_buffer->temphwm, MAX_WSR_ENTITY_LEN));
    CT_RETURN_IFERR(ctconn_column_as_string(*resultset, (*i_cnt)++, wsr_buffer->tempswap, MAX_WSR_ENTITY_LEN));
    CT_RETURN_IFERR(ctconn_column_as_string(*resultset, (*i_cnt)++, wsr_buffer->bufferdetail, MAX_WSR_DETAIL_LEN));

    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_buffer->snap_time);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_buffer->datadirty);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_buffer->datapin);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_buffer->datafree);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_buffer->tempfree);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_buffer->temphwm);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_buffer->tempswap);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_10000, "    <td>%s</td>", wsr_buffer->bufferdetail);
    return CTCONN_SUCCESS;
}

int wsr_build_instance_buffer(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    uint32 rows;
    char cmd_buf[MAX_CMD_LEN + 1];
    int i_cnt;
    ctconn_stmt_t resultset;
    wsr_buffer_t wsr_buffer;

    CT_RETURN_IFERR(wsr_build_instance_buffer_head(wsr_opts, wsr_info));

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN, "CALL SYS.WSR$INSTANCE_BUFFER(%u, %u, '%s', '%s')",
        wsr_opts->start_snap_id, wsr_opts->end_snap_id, wsr_info->start_time, wsr_info->end_time));

    CT_RETURN_IFERR(ctconn_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    CT_RETURN_IFERR(ctconn_execute(wsr_opts->curr_stmt));

    CT_RETURN_IFERR(ctconn_get_implicit_resultset(wsr_opts->curr_stmt, &resultset));

    do {
        CT_RETURN_IFERR(ctconn_fetch(resultset, &rows));
        if (rows == 0) {
            break;
        }

        i_cnt = 0;

        wsr_write_str2(wsr_opts, "<tr>");

        PRTS_RETURN_IFERR(wsr_build_instance_memory(wsr_opts, &resultset, &wsr_buffer, &i_cnt));

        wsr_write_str2(wsr_opts, "</tr>");
    } while (CT_TRUE);

    wsr_write_str2(wsr_opts, "</tbody>");
    wsr_write_str2(wsr_opts, "</table><p />");

    return CTCONN_SUCCESS;
}