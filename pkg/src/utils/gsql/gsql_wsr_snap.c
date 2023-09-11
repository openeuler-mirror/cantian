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
 * gsql_wsr_snap.c
 *
 *
 * IDENTIFICATION
 * src/utils/gsql/gsql_wsr_snap.c
 *
 * -------------------------------------------------------------------------
 */
#include "gsql_wsr_snap.h"

typedef struct st_wsr_snap {
    char snap_time[MAX_WSR_ENTITY_LEN];
    char cpu_user[MAX_WSR_ENTITY_LEN];
    char cpu_system[MAX_WSR_ENTITY_LEN];
    char iowait[MAX_WSR_ENTITY_LEN];
    char idle[MAX_WSR_ENTITY_LEN];
    char sessions[MAX_WSR_ENTITY_LEN];
    char activesess[MAX_WSR_ENTITY_LEN];
    char trans[MAX_WSR_ENTITY_LEN];
    char longsql[MAX_WSR_ENTITY_LEN];
    char longtrans[MAX_WSR_ENTITY_LEN];
    char physical[MAX_WSR_ENTITY_LEN];
    char logical[MAX_WSR_ENTITY_LEN];
    char commit[MAX_WSR_ENTITY_LEN];
    char rollback[MAX_WSR_ENTITY_LEN];
    char redosize[MAX_WSR_ENTITY_LEN];
    char execute[MAX_WSR_ENTITY_LEN];
    char fetch[MAX_WSR_ENTITY_LEN];
    char login[MAX_WSR_ENTITY_LEN];
    char hardparse[MAX_WSR_ENTITY_LEN];
    char dbwrpages[MAX_WSR_ENTITY_LEN];
    char dbwrtime[MAX_WSR_ENTITY_LEN];
    char minlog[MAX_WSR_ENTITY_LEN];
    char minsyreply[MAX_WSR_ENTITY_LEN];
    char maxlog[MAX_WSR_ENTITY_LEN];
    char maxsyreply[MAX_WSR_ENTITY_LEN];
    char minlgreply[MAX_WSR_ENTITY_LEN];
    char maxlgreply[MAX_WSR_ENTITY_LEN];
    char txn_pages[MAX_WSR_ENTITY_LEN];
    char undo_pages[MAX_WSR_ENTITY_LEN];
    char system[MAX_WSR_ENTITY_LEN];
    char sysaux[MAX_WSR_ENTITY_LEN];
    char users[MAX_WSR_ENTITY_LEN];
    char arch_logs[MAX_WSR_ENTITY_LEN];
    char latch_data[MAX_WSR_ENTITY_LEN];
    char filesync[MAX_WSR_ENTITY_LEN];
    char busywaits[MAX_WSR_ENTITY_LEN];
    char txrowlock[MAX_WSR_ENTITY_LEN];
    char scattered[MAX_WSR_ENTITY_LEN];
    char sequential[MAX_WSR_ENTITY_LEN];
    char readother[MAX_WSR_ENTITY_LEN];
    char archneeded[MAX_WSR_ENTITY_LEN];
    char adlock[MAX_WSR_ENTITY_LEN];
    char tableslock[MAX_WSR_ENTITY_LEN];
    char switchin[MAX_WSR_ENTITY_LEN];
    char itl_enq[MAX_WSR_ENTITY_LEN];
    char redo_switch_count[MAX_WSR_ENTITY_LEN];
    char pcr_construct_count[MAX_WSR_ENTITY_LEN];
    char bcr_construct_count[MAX_WSR_ENTITY_LEN];
} wsr_snap_t;

static void wsr_build_instance_snap_head_host(wsr_options_t *wsr_opts)
{
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">%%user</div></th>",
        g_wsritemdesc[WSR_ITEM_CPU_USER]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">%%system</div></th>",
        g_wsritemdesc[WSR_ITEM_CPU_SYSTEM]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">%%iowait</div></th>",
        g_wsritemdesc[WSR_ITEM_IOWAIT]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">%%idle</div></th>",
        g_wsritemdesc[WSR_ITEM_IDLE]);
}

static void wsr_build_instance_snap_head_session(wsr_options_t *wsr_opts)
{
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">Sessions</div></th>",
        g_wsritemdesc[WSR_ITEM_SESSIONS]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">ActiveSess</div></th>",
        g_wsritemdesc[WSR_ITEM_ACTIVE_SESSIONS]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">Trans</div></th>",
        g_wsritemdesc[WSR_ITEM_TRANSACTIONS]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">LongSQL</div></th>",
        g_wsritemdesc[WSR_ITEM_LONG_SQL]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">LongTrans</div></th>",
        g_wsritemdesc[WSR_ITEM_LONG_TRANS]);
}

static void wsr_build_instance_snap_head_perf(wsr_options_t *wsr_opts)
{
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">Physical</div></th>",
        g_wsritemdesc[WSR_ITEM_PHYSICAL_READ]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">Logical</div></th>",
        g_wsritemdesc[WSR_ITEM_LOGICAL_READ]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">Commit</div></th>",
        g_wsritemdesc[WSR_ITEM_COMMITS]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">Rollback</div></th>",
        g_wsritemdesc[WSR_ITEM_ROLLBACKS]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">RedoSize</div></th>",
        g_wsritemdesc[WSR_ITEM_REDO_SIZE]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">Execute</div></th>",
        g_wsritemdesc[WSR_ITEM_EXECUTIONS]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">Fetch</div></th>",
        g_wsritemdesc[WSR_ITEM_FETCHS]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">Login</div></th>",
        g_wsritemdesc[WSR_ITEM_LOGINS]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">HardParse</div></th>",
        g_wsritemdesc[WSR_ITEM_HARD_PARSES]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">DBWRPages</div></th>",
        g_wsritemdesc[WSR_ITEM_DBWR_PAGES]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">DBWRTime</div></th>",
        g_wsritemdesc[WSR_ITEM_DBWR_TIME]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">RedoSwitchCount</div></th>",
        g_wsritemdesc[WSR_ITEM_REDO_SWITCH_COUNT]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">PcrConstructCount</div></th>",
        g_wsritemdesc[WSR_ITEM_PCR_CONSTRUCT_COUNT]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">BcrConstructCount</div></th>",
        g_wsritemdesc[WSR_ITEM_BCR_CONSTRUCT_COUNT]);
}

static void wsr_build_instance_snap_head_sync(wsr_options_t *wsr_opts)
{
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">MinLog</div></th>",
        g_wsritemdesc[WSR_ITEM_MIN_REDO_SYNC]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">MinSyReply</div></th>",
        g_wsritemdesc[WSR_ITEM_MIN_REDO_REPLY]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">MaxLog</div></th>",
        g_wsritemdesc[WSR_ITEM_MAX_REDO_SYNC]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">MaxSyReply</div></th>",
        g_wsritemdesc[WSR_ITEM_MAX_REDO_REPLY]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">MinLgReply</div></th>",
        g_wsritemdesc[WSR_ITEM_MIN_LOGICAL_DELAY]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">MaxLgReply</div></th>",
        g_wsritemdesc[WSR_ITEM_MIN_LOGICAL_DELAY]);
}

static void wsr_build_instance_snap_head_ts(wsr_options_t *wsr_opts)
{
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">TXN_Pages</div></th>",
        g_wsritemdesc[WSR_ITEM_TXN_PAGES]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">Undo_Pages</div></th>",
        g_wsritemdesc[WSR_ITEM_UNDO_PAGES]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">System</div></th>",
        g_wsritemdesc[WSR_ITEM_SYSTEM_TABLESPACE]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">Sysaux</div></th>",
        g_wsritemdesc[WSR_ITEM_SYSAUX_TABLESPACE]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">Users</div></th>",
        g_wsritemdesc[WSR_ITEM_USER_TABLESPACE]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">ArchLogs</div></th>",
        g_wsritemdesc[WSR_ITEM_ARCH_LOGS]);
}

static void wsr_build_instance_snap_head_event(wsr_options_t *wsr_opts)
{
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">Latch_Data</div></th>",
        g_wsritemdesc[WSR_ITEM_EVENT_LATCH_DATA]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">FileSync</div></th>",
        g_wsritemdesc[WSR_ITEM_EVENT_FILE_SYNC]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">BusyWaits</div></th>",
        g_wsritemdesc[WSR_ITEM_EVENT_BUFFER_BUSY]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">TXRowLock</div></th>",
        g_wsritemdesc[WSR_ITEM_EVENT_TX_LOCK]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">Scattered</div></th>",
        g_wsritemdesc[WSR_ITEM_EVENT_SCATTER_READ]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">Sequential</div></th>",
        g_wsritemdesc[WSR_ITEM_EVENT_SEQ_READ]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">ReadOther</div></th>",
        g_wsritemdesc[WSR_ITEM_EVENT_READ_BY_OTHER]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">ArchNeeded</div></th>",
        g_wsritemdesc[WSR_ITEM_EVENT_ARCH_NEEDED]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">AdLock</div></th>",
        g_wsritemdesc[WSR_ITEM_EVENT_ADVISE_LOCK]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">TableSLock</div></th>",
        g_wsritemdesc[WSR_ITEM_EVENT_TABLE_S_LOCK]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">SwitchIn</div></th>",
        g_wsritemdesc[WSR_ITEM_EVENT_REDO_SWITCH]);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "<th><div title=\"%s\">ITL_Enq</div></th>",
        g_wsritemdesc[WSR_ITEM_EVENT_ITL_ENQ]);
}

static int wsr_build_instance_snap_head(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "            <a class=\"wsr\" name=\"30006-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Instance Snap %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts, "<font face=\"Courier New, Courier, mono\" color=\"#666\">Instance Statistics</font>");
    }

    wsr_write_str2(wsr_opts, "<!-- <h2 class=\"wsr\">Instance Statistics</h2> -->");
    wsr_write_str2(wsr_opts, "<table class=\"table table-hover\" >");
    wsr_write_str2(wsr_opts, "  <thead><tr>");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a class=\"wsrg\" href=\"#100-%u\">Instance Snap</a></td>", wsr_info->dbid);
    wsr_write_str2(wsr_opts, "    </tr><tr>");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
        "<td><a class=\"wsrg\" href=\"#101-%u\">Data Buffer & Temp Buffer</a></td>", wsr_info->dbid);
    wsr_write_str2(wsr_opts, "    </tr><tr>");
    wsr_write_str2(wsr_opts, "      <td><a class=\"wsrg\" href=\"#top\">Back to Top</a></td>");
    wsr_write_str2(wsr_opts, "    </tr></thead></table><p />");
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "<a class=\"wsr\" name=\"100-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Instance Snap %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Instance Snap</font>");
    }
    wsr_write_str2(wsr_opts, "            <table class=\"table table-hover\" >");
    wsr_write_str2(wsr_opts, "              <thead>");
    wsr_write_str2(wsr_opts, "                <tr>");
    wsr_write_str2(wsr_opts, "                  <th>Snap Time</th>");
    wsr_build_instance_snap_head_host(wsr_opts);
    wsr_build_instance_snap_head_session(wsr_opts);
    wsr_build_instance_snap_head_perf(wsr_opts);
    wsr_build_instance_snap_head_sync(wsr_opts);
    wsr_build_instance_snap_head_ts(wsr_opts);
    wsr_build_instance_snap_head_event(wsr_opts);
    wsr_write_str2(wsr_opts, "                </tr>");
    wsr_write_str2(wsr_opts, "              </thead>");
    wsr_write_str2(wsr_opts, "              <tbody>");

    return GSC_SUCCESS;
}

int wsr_build_instance_snap_host(wsr_options_t *wsr_opts, gsc_stmt_t *resultset, wsr_snap_t *wsr_snap,
    int *i_cnt)
{
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->snap_time, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->cpu_user, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->cpu_system, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->iowait, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->idle, MAX_WSR_ENTITY_LEN));

    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->snap_time);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->cpu_user);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->cpu_system);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->iowait);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->idle);
    return GSC_SUCCESS;
}

int wsr_build_instance_snap_session(wsr_options_t *wsr_opts, gsc_stmt_t *resultset, wsr_snap_t *wsr_snap,
    int *i_cnt)
{
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->sessions, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->activesess, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->trans, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->longsql, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->longtrans, MAX_WSR_ENTITY_LEN));

    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->sessions);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->activesess);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->trans);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->longsql);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->longtrans);
    return GSC_SUCCESS;
}

int wsr_build_instance_snap_perf(wsr_options_t *wsr_opts, gsc_stmt_t *resultset, wsr_snap_t *wsr_snap,
    int *i_cnt)
{
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->physical, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->logical, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->commit, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->rollback, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->redosize, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->execute, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->fetch, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->login, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->hardparse, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->dbwrpages, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->dbwrtime, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->redo_switch_count, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->pcr_construct_count, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->bcr_construct_count, MAX_WSR_ENTITY_LEN));
    
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->physical);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->logical);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->commit);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->rollback);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->redosize);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->execute);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->fetch);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->login);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->hardparse);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->dbwrpages);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->dbwrtime);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->redo_switch_count);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->pcr_construct_count);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->bcr_construct_count);
    return GSC_SUCCESS;
}

int wsr_build_instance_snap_sync(wsr_options_t *wsr_opts, gsc_stmt_t *resultset, wsr_snap_t *wsr_snap,
    int *i_cnt)
{
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->minlog, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->minsyreply, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->maxlog, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->maxsyreply, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->minlgreply, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->maxlgreply, MAX_WSR_ENTITY_LEN));

    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->minlog);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->minsyreply);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->maxlog);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->maxsyreply);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->minlgreply);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->maxlgreply);
    return GSC_SUCCESS;
}

int wsr_build_instance_snap_ts(wsr_options_t *wsr_opts, gsc_stmt_t *resultset, wsr_snap_t *wsr_snap,
    int *i_cnt)
{
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->txn_pages, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->undo_pages, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->system, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->sysaux, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->users, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->arch_logs, MAX_WSR_ENTITY_LEN));

    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->txn_pages);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->undo_pages);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->system);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->sysaux);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->users);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->arch_logs);
    return GSC_SUCCESS;
}

int wsr_build_instance_snap_event(wsr_options_t *wsr_opts, gsc_stmt_t *resultset, wsr_snap_t *wsr_snap,
    int *i_cnt)
{
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->latch_data, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->filesync, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->busywaits, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->txrowlock, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->scattered, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->sequential, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->readother, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->archneeded, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->adlock, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->tableslock, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->switchin, MAX_WSR_ENTITY_LEN));
    GS_RETURN_IFERR(gsc_column_as_string(*resultset, (*i_cnt)++, wsr_snap->itl_enq, MAX_WSR_ENTITY_LEN));

    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->latch_data);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->filesync);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->busywaits);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->txrowlock);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->scattered);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->sequential);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->readother);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->archneeded);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->adlock);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->tableslock);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->switchin);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_2000, "    <td>%s</td>", wsr_snap->itl_enq);
    return GSC_SUCCESS;
}

int wsr_build_instance_snap(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    uint32 rows;
    char cmd_buf[MAX_CMD_LEN + 1];
    int i_cnt;
    gsc_stmt_t resultset;
    wsr_snap_t wsr_snap;

    GS_RETURN_IFERR(wsr_build_instance_snap_head(wsr_opts, wsr_info));

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN, "CALL SYS.WSR$INSTANCE_SNAP(%u, %u, '%s', '%s')",
        wsr_opts->start_snap_id, wsr_opts->end_snap_id, wsr_info->start_time, wsr_info->end_time));

    GS_RETURN_IFERR(gsc_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(wsr_opts->curr_stmt));

    GS_RETURN_IFERR(gsc_get_implicit_resultset(wsr_opts->curr_stmt, &resultset));

    do {
        GS_RETURN_IFERR(gsc_fetch(resultset, &rows));
        if (rows == 0) {
            break;
        }

        i_cnt = 0;

        wsr_write_str2(wsr_opts, "<tr>");
        PRTS_RETURN_IFERR(wsr_build_instance_snap_host(wsr_opts, &resultset, &wsr_snap, &i_cnt));
        PRTS_RETURN_IFERR(wsr_build_instance_snap_session(wsr_opts, &resultset, &wsr_snap, &i_cnt));
        PRTS_RETURN_IFERR(wsr_build_instance_snap_perf(wsr_opts, &resultset, &wsr_snap, &i_cnt));
        PRTS_RETURN_IFERR(wsr_build_instance_snap_sync(wsr_opts, &resultset, &wsr_snap, &i_cnt));
        PRTS_RETURN_IFERR(wsr_build_instance_snap_ts(wsr_opts, &resultset, &wsr_snap, &i_cnt));
        PRTS_RETURN_IFERR(wsr_build_instance_snap_event(wsr_opts, &resultset, &wsr_snap, &i_cnt));

        wsr_write_str2(wsr_opts, "</tr>");
    } while (GS_TRUE);

    wsr_write_str2(wsr_opts, "</tbody>");
    wsr_write_str2(wsr_opts, "</table><p />");

    return GSC_SUCCESS;
}