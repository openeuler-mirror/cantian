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
 * gsql_wsr_common.c
 *
 *
 * IDENTIFICATION
 * src/utils/gsql/gsql_wsr_common.c
 *
 * -------------------------------------------------------------------------
 */
#include "gsql_wsr_common.h"

const char *g_wsritemdesc[] = {
    [WSR_ITEM_DBTIME] = "db time = cpu time + wait time (excluding idle waiting time). \n"
    "The db time is the recorded time spent by the server on database "
    "operations(non - background processes) and waiting(non - idle waiting).\n"
    "If the value of DB Time is much smaller than the value of Elapsed Time , "
    "it indicates that the database is idle.",
    [WSR_ITEM_ElAPSED] = "Interval between two snapshots.",
    [WSR_ITEM_CPU_USER] = "Average CPU usage of user processes in a monitoring period. [ADM_HIST_SYSTEM]",
    [WSR_ITEM_CPU_SYSTEM] = "Average CPU usage of system processes in a monitoring period. [ADM_HIST_SYSTEM]",
    [WSR_ITEM_IOWAIT] = "Average I/O waiting ratio in a monitoring period. [ADM_HIST_SYSTEM]",
    [WSR_ITEM_IDLE] = "Average CPU idle rate in a monitoring period. [ADM_HIST_SYSTEM]",
    [WSR_ITEM_SESSIONS] = "Total number of current sessions. [DV_SESSIONS]",
    [WSR_ITEM_ACTIVE_SESSIONS] = "Number of Active Sessions. [DV_SESSIONS]",
    [WSR_ITEM_TRANSACTIONS] = "Number of current uncommitted transactions. [DV_TRANSACTIONS]",
    [WSR_ITEM_LONG_SQL] = "Execution time of the longest SQL in the current sessions. [DV_SESSIONS]",
    [WSR_ITEM_LONG_TRANS] = "Maximum duration of current uncommitted transactions. [DV_TRANSACTIONS]",
    [WSR_ITEM_DIRTY_DATA] = "Number of dirty pages in the data buffer. [DV_BUFFER_POOL_STATS.CNUM_WRITE]",
    [WSR_ITEM_PIN_DATA] = "Number of resident pages in the data buffer. [DV_BUFFER_POOL_STATS.CNUM_PINNED]",
    [WSR_ITEM_FREE_DATA] = "Number of unused pages in the data buffer. [DV_BUFFER_POOL_STATS.CNUM_FREE]",
    [WSR_ITEM_FREE_TEMP] = "Current idle page of the tempbuffer. [DV_TEMP_POOLS.FREE_PAGES]",
    [WSR_ITEM_TEMP_HWM] = "High watermark of the current page used by the tempbuffer. [DV_TEMP_POOLS.PAGE_HWM]",
    [WSR_ITEM_TEMP_SWAP] = "Number of vmpages that have been swapped out to temporary tablespaces "
    "in the tempbuffer. [DV_TEMP_POOLS.SWAP_COUNT]",
    [WSR_ITEM_PHYSICAL_READ] = "Number of physical reads in a monitoring period. [DV_SYS_STATS:disk reads]",
    [WSR_ITEM_LOGICAL_READ] = "Number of logical reads in a monitoring period. [DV_SYS_STATS:buffer gets]",
    [WSR_ITEM_COMMITS] = "Number of commits in a monitoring period. [DV_SYS_STATS:commits]",
    [WSR_ITEM_ROLLBACKS] = "Number of rollbacks in a monitoring period. [DV_SYS_STATS:rollbacks]",
    [WSR_ITEM_REDO_SIZE] = "Size of redo files generated in a monitoring period. [DV_SYS_STATS:redo write size]",
    [WSR_ITEM_EXECUTIONS] = "Number of SQL statements executed in a monitoring period. "
    "[DV_SYS_STATS:sql executions]",
    [WSR_ITEM_FETCHS] = "Number of fetch rows in a monitoring period. [DV_SYS_STATS:fetched rows]",
    [WSR_ITEM_LOGINS] = "Number of login times in a monitoring period. [DV_SYS_STATS:user logons cumulation]",
    [WSR_ITEM_HARD_PARSES] = "Number of hardparse times in a monitoring period. [DV_SYS_STATS:sql hard parses]",
    [WSR_ITEM_MIN_REDO_SYNC] = "Indicates the minimum delay for receiving logs from the peer end. "
    "[DV_HA_SYNC_INFO.FLUSH_LAG]",
    [WSR_ITEM_MIN_REDO_REPLY] = "Indicates the minimum delay for replaying logs of the peer end. "
    "[DV_HA_SYNC_INFO.REPLAY_LAG]",
    [WSR_ITEM_MAX_REDO_SYNC] = "Indicates the maximum delay for receiving logs from the peer end. "
    "[DV_HA_SYNC_INFO.FLUSH_LAG]",
    [WSR_ITEM_MAX_REDO_REPLY] = "Maximum delay for replaying logs of the peer end of physical replication. "
    "[DV_HA_SYNC_INFO.REPLAY_LAG]",
    [WSR_ITEM_MIN_LOGICAL_DELAY] = "Indicates the minimum delay for replaying logs of the peer "
    "logical replication. [LOGICREP_PROGRESS.COMMITTED_TX_TIME]",
    [WSR_ITEM_MAX_LOGICAL_DELAY] = "Maximum delay for replaying logs at the peer end of logical replication. "
    "[LOGICREP_PROGRESS.COMMITTED_TX_TIME]",
    [WSR_ITEM_TXN_PAGES] = "Number of TXN PAGEs held by UNDO_SEGMENT. [DV_UNDO_SEGMENTS.TXN_PAGES]",
    [WSR_ITEM_UNDO_PAGES] = "Number of idle UNDO pages held by UNDO_SEGMENT, excluding pages with uncommitted transactions.. [DV_UNDO_SEGMENTS.UNDO_PAGES]",
    [WSR_ITEM_SYSTEM_TABLESPACE] = "Remaining space of the current SYSTEM tablespace. [ADM_TABLESPACES]",
    [WSR_ITEM_SYSAUX_TABLESPACE] = "Remaining space of the SYSAUX tablespace. [ADM_TABLESPACES]",
    [WSR_ITEM_USER_TABLESPACE] = "Remaining space of the current service tablespace. [ADM_TABLESPACES]",
    [WSR_ITEM_ARCH_LOGS] = "Total size of archived logs. [DV_ARCHIVED_LOGS:SUM(BLOCKS * BLOCK_SIZE)]",
    [WSR_ITEM_EVENT_LATCH_DATA] = "The total wait time of latch : data buffer pool in a monitoring period. "
    "[DV_SYS_EVENTS:latch: data buffer pool]",
    [WSR_ITEM_EVENT_FILE_SYNC] = "The total wait time of log file sync in a monitoring period. "
    "[DV_SYS_EVENTS:latch: log file sync]",
    [WSR_ITEM_EVENT_BUFFER_BUSY] = "The total wait time of buffer busy waits in a monitoring period. "
    "[DV_SYS_EVENTS:latch: buffer busy waits]",
    [WSR_ITEM_EVENT_TX_LOCK] = "The total wait time of enq : TX row lock contention in a monitoring period. "
    "[DV_SYS_EVENTS:enq: TX row lock contention]",
    [WSR_ITEM_EVENT_SCATTER_READ] = "The total wait time of db file scattered read in a monitoring period. "
    "[DV_SYS_EVENTS:db file scattered read]",
    [WSR_ITEM_EVENT_SEQ_READ] = "The total wait time of db file sequential read in a monitoring period. "
    "[DV_SYS_EVENTS:db file sequential read]",
    [WSR_ITEM_EVENT_READ_BY_OTHER] = "The total wait time of read by other session in a monitoring period. "
    "[DV_SYS_EVENTS:read by other session]",
    [WSR_ITEM_EVENT_ARCH_NEEDED] = "The total wait time of log file switch (archiving needed) in a "
    "monitoring period. [DV_SYS_EVENTS:log file switch(archiving needed)]",
    [WSR_ITEM_EVENT_ADVISE_LOCK] = "The total wait time of advisory lock wait time in a monitoring period. "
    "[DV_SYS_EVENTS:advisory lock wait time]",
    [WSR_ITEM_EVENT_TABLE_S_LOCK] = "The total wait time of enq : TX table lock S in a monitoring period. "
    "[DV_SYS_EVENTS:enq: TX table lock S]",
    [WSR_ITEM_EVENT_REDO_SWITCH] = "The total wait time of log file switch (checkpoint incomplete) "
    "in a monitoring period. [DV_SYS_EVENTS:log file switch(checkpoint incomplete)]",
    [WSR_ITEM_EVENT_ITL_ENQ] = "The total wait time of enq : TX alloc itl entry in a monitoring period. "
    "[DV_SYS_EVENTS:enq: TX alloc itl entry]",
    [WSR_ITEM_DBWR_PAGES] = "Number of flushed data pages in a monitoring period. [DV_SYS_STATS:DBWR disk writes]",
    [WSR_ITEM_DBWR_TIME] = "Time for flushing data pages in a monitoring period. [DV_SYS_STATS:DBWR disk write time]",
    [WSR_ITEM_REDO_SWITCH_COUNT] = "Redo log switch times in a monitoring period. [DV_SYS_STATS:redo log switch count]",
    [WSR_ITEM_PCR_CONSTRUCT_COUNT] = "Heap page construct times in a monitoring period. "
    "[DV_SYS_STATS:pcr construct count]",
    [WSR_ITEM_BCR_CONSTRUCT_COUNT] = "Btree page construct times in a monitoring period."
    "[DV_SYS_STATS:bcr construct count]",
    [WSR_ITEM_UNDO_PHYSICAL_READ] = "Number of undo physical reads in a monitoring period. [DV_SYS_STATS:undo disk reads]",
    [WSR_ITEM_UNDO_LOGICAL_READ] = "Number of undo logical reads in a monitoring period. [DV_SYS_STATS:undo buffer reads]",
};

const char *g_wsrloaddesc[] = {
    [WSR_ITEM_NO_ADVICE] = "No optimization advice",
    [WSR_ITEM_VERY_HIGH] = "Very high",
    [WSR_ITEM_HIGH] = "High",
    [WSR_ITEM_MEDIUM] = "Medium",
    [WSR_ITEM_LOW] = "Low",
    [WSR_ITEM_VERY_LOW] = "Very low",
    [WSR_ITEM_NEED_OPT] = "Necessary for optimization",
    [WSR_ITEM_SQL_CAPTURE] = "Most SQLs are obsolete. The time span of reporting needs to "
    "be shortened or the shared pool needs to be increased."
};

const char *g_wsrheadloaddesc[] = {
    [WSR_LOAD_TABLE_CREATE] = "Number of times that a table is created.",
    [WSR_LOAD_TABLE_DROP] = "Number of times that a table is dropped.",
    [WSR_LOAD_TABLE_ALTER] = "Number of times the table is modified.",
    [WSR_LOAD_TABLE_PART_DROP] = "Number of times table partitions are dropped.",
    [WSR_LOAD_TABLE_SUBPART_DROP] = "Number of times table subpartitions are dropped.",
    [WSR_LOAD_HISTGRAM_INSERT] = "Number of rows inserted by histogram.",
    [WSR_LOAD_HISTGRAM_UPDATE] = "Number of rows updated by histogram.",
    [WSR_LOAD_HISTGRAM_DELETE] = "Number of rows deleted by histogram."
};

const char *g_wsreventdesc[] = {
    [WSR_EVENT_NO_ADVICE] = "No optimization advice",
    [WSR_EVENT_CPU] = "Pay attention to SQL statements and objects with high logical read rates. "
    "Incorrect indexes or full table scanning may be performed.",
    [WSR_EVENT_LATCH_BUFFER_POOL] = "The data buffer has a large contention. You are advised to "
    "increase the values of BUF_POOL_NUM and DATA_BUFFER_SIZE.",
    [WSR_EVENT_LOG_FILE_SYNC] = "You are advised to perform batch commit to reduce the commit "
    "frequency or deploy redo on an independent disk with high performance.",
    [WSR_EVENT_BUFFER_BUSY_WAITS] = "If the same page is read and written at the same time, "
    "you are advised to use the hash partition to separate data. If the index is faulty, "
    "you can create the RCR mode.",
    [WSR_EVENT_TX_ROW_LOCK] = "For row lock waiting problems, analyze SQL statements "
    "and segments that have many row lock waiting problems.",
    [WSR_EVENT_TX_ALLOC_ITL] = "The cause of this problem is that there are too many "
    "concurrent transactions, and all the free space on the page is used up by the update. "
    "Pay attention to the segment that has a long waiting time. "
    "It is recommended that the initial initrans of the segment or increase the value of pctfree.",
    [WSR_EVENT_SCATTERED_READ] = "This problem is caused by full table scanning "
    "or a large number of UNDO scanning. Pay attention to SQL and segment with high physical read rate. "
    "It is recommended that SQL be optimized to avoid full table scanning on large tables.",
    [WSR_EVENT_SEQUENTIAL_READ] = "This problem is caused by a large number of index scanning. "
    "Pay attention to SQL and segment with high physical read performance. "
    "You are advised to optimize the SQL to avoid using indexes with low efficiency.",
    [WSR_EVENT_CHECKPOINT_INCOMPLETE] = "If the online redo needs to be switched "
    "but the current redo data has not been completely written to disks, "
    "you are advised to increase the size and number of online redos.",
    [WSR_EVENT_ARCHIVING_NEEDED] = "If the online redo needs to be switched but the current "
    "redo is not archived, the waiting is generated. In this case, you need to check whether "
    "the configured archive log path has sufficient space or whether the disk I/O performance is normal.",
    [WSR_EVENT_READ_BY_OTHER_SESSION] = "When a session is performing a physical read, "
    "another session needs to read the same page. In this case, focus on the SQL and segment"
    " with high physical read rate. You are advised to optimize the SQL to avoid scanning a large number of pages.",
    [WSR_EVENT_ADVISORY_LOCK] = "Check whether the consultation lock is properly used by the service.",
};

const char *g_wsreventname[] = {
    [WSR_EVENT_NO_ADVICE] = "NULL",
    [WSR_EVENT_CPU] = "CPU",
    [WSR_EVENT_LATCH_BUFFER_POOL] = "latch: data buffer pool",
    [WSR_EVENT_LOG_FILE_SYNC] = "log file sync",
    [WSR_EVENT_BUFFER_BUSY_WAITS] = "buffer busy waits",
    [WSR_EVENT_TX_ROW_LOCK] = "enq: TX row lock contention",
    [WSR_EVENT_TX_ALLOC_ITL] = "enq: TX alloc itl entry",
    [WSR_EVENT_SCATTERED_READ] = "db file scattered read",
    [WSR_EVENT_SEQUENTIAL_READ] = "db file sequential read",
    [WSR_EVENT_CHECKPOINT_INCOMPLETE] = "log file switch(checkpoint incomplete)",
    [WSR_EVENT_ARCHIVING_NEEDED] = "log file switch(archiving needed)",
    [WSR_EVENT_READ_BY_OTHER_SESSION] = "read by other session",
    [WSR_EVENT_ADVISORY_LOCK] = "advisory lock wait time",
};

void wsr_writer(wsr_options_t *wsr_opts, char *buf, uint32 size)
{
    buf[size] = 0;
    if (wsr_opts->wsr_dpfile == NULL) {
        gsql_printf("%s", buf);
    } else {
        (void)fwrite(buf, 1, size, wsr_opts->wsr_dpfile);
    }
}

float wsr_per_second(const wsr_info_t *wsr_info, uint64 value)
{
    float result;

    if (wsr_info->elapsed == 0) {
        return 0.0;
    } else {
        result = (float)value / wsr_info->elapsed;
        return result;
    }
}

float wsr_per_tran(const wsr_info_t *wsr_info, uint64 value)
{
    if (wsr_info->transactions == 0) {
        return 0.0;
    } else {
        return (float)value / wsr_info->transactions;
    }
}

float wsr_per_exec(const wsr_info_t *wsr_info, uint64 value)
{
    if (wsr_info->executions == 0) {
        return 0.0;
    } else {
        return (float)value / wsr_info->executions;
    }
}

void wsr_write_str(wsr_options_t *wsr_opts, const char *str)
{
    text_t text;
    cm_str2text((char *)str, &text);
    wsr_write_text(wsr_opts, &text);
}

void wsr_write_str2(wsr_options_t *wsr_opts, const char *str)
{
    wsr_write_str(wsr_opts, str);
    wsr_write_str(wsr_opts, "\n");
}

void wsr_write_fmt(wsr_options_t *wsr_opts, uint32 max_fmt_sz, const char *fmt, ...)
{
    int32 len;
    text_t text;
    va_list var_list;
    va_start(var_list, fmt);
    char sql_buf[MAX_SQL_SIZE_WSR + 1];

    len = vsnprintf_s(sql_buf, MAX_SQL_SIZE_WSR, max_fmt_sz, fmt, var_list);
    va_end(var_list);
    if (len < 0) {
        gsql_printf("Copy var_list to EXP_FMT_BUFER failed under using wsr tool.\n");
        return;
    }
    text.str = sql_buf;
    text.len = (uint32)len;
    wsr_write_text(wsr_opts, &text);
}

void wsr_write_fmt2(wsr_options_t *wsr_opts, uint32 max_fmt_sz, const char *fmt, ...)
{
    int32 len;
    text_t text;
    va_list var_list;
    va_start(var_list, fmt);
    char sql_buf[MAX_SQL_SIZE_WSR + 4];

    len = vsnprintf_s(sql_buf, MAX_SQL_SIZE_WSR, max_fmt_sz, fmt, var_list);
    va_end(var_list);
    if (len < 0) {
        gsql_printf("Copy var_list to EXP_FMT_BUFER failed under using wsr tool.\n");
        return;
    }
    text.str = sql_buf;
    text.len = (uint32)len;
    wsr_write_text(wsr_opts, &text);
    wsr_write_str(wsr_opts, "\n");
}

void wsr_write_per_profile(wsr_options_t *wsr_opts, const wsr_info_t *wsr_info,
    const char *title, uint64 value, const char *comment)
{
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500,
        "<tr><td><div title=\"%s\">%s:</a></td><td>%llu</td><td>%12.2f</td><td>%12.2f</td><td>%12.2f</td></tr>",
        comment, title, value, wsr_per_second(wsr_info, value),
        wsr_per_tran(wsr_info, value), wsr_per_exec(wsr_info, value));
    return;
}

int wsr_execute_sql(gsc_stmt_t curr_stmt, uint32 *rows, const char *cmd_buf)
{
    GS_RETURN_IFERR(gsc_prepare(curr_stmt, cmd_buf));
    GS_RETURN_IFERR(gsc_execute(curr_stmt));
    GS_RETURN_IFERR(gsc_fetch(curr_stmt, rows));

    return GSC_SUCCESS;
}

float wsr_per_rate(uint64 value, uint64 total)
{
    if (total == 0) {
        return WSR_PER_RATE;
    } else {
        return (1 - (float)value / total) * WSR_ONE_HUNDRED;
    }
}

float wsr_rate_percent(uint64 value, uint64 total)
{
    if (total == 0) {
        return WSR_PER_RATE;
    } else {
        return (float)value / total * WSR_ONE_HUNDRED;
    }
}

int wsr_build_top_events_deal(wsr_options_t *wsr_opts)
{
    uint32 rows;
    char event[MAX_WSR_ENTITY_LEN];
    char total_waits[MAX_WSR_ENTITY_LEN];
    char time_waited[MAX_WSR_ENTITY_LEN];
    char dbtime_per_wait[MAX_WSR_ENTITY_LEN];
    char dbtime_percent[MAX_WSR_ENTITY_LEN];
    char wait_class[MAX_WSR_ENTITY_LEN];
    uint32 index;

    do {
        GS_RETURN_IFERR(gsc_fetch(wsr_opts->curr_stmt, &rows));
        if (rows == 0) {
            break;
        }

        index = 0;

        GS_RETURN_IFERR(gsc_column_as_string(wsr_opts->curr_stmt, index++, event, MAX_WSR_ENTITY_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(wsr_opts->curr_stmt, index++, total_waits, MAX_WSR_ENTITY_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(wsr_opts->curr_stmt, index++, time_waited, MAX_WSR_ENTITY_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(wsr_opts->curr_stmt, index++, dbtime_per_wait, MAX_WSR_ENTITY_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(wsr_opts->curr_stmt, index++, dbtime_percent, MAX_WSR_ENTITY_LEN));
        GS_RETURN_IFERR(gsc_column_as_string(wsr_opts->curr_stmt, index++, wait_class, MAX_WSR_ENTITY_LEN));

        wsr_write_str2(wsr_opts, "                <tr>");
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                  <td>%s</td>", event);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                  <td>%s</td>", total_waits);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                  <td>%s</td>", time_waited);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                  <td>%s</td>", dbtime_per_wait);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                  <td>%s</td>", dbtime_percent);
        wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                  <td>%s</td>", wait_class);
        wsr_write_str2(wsr_opts, "                </tr>");
    } while (GS_TRUE);
    return GS_SUCCESS;
}

void wsr_build_host_cpu_write_str(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500, "            <a class=\"wsr\" name=\"30004-%u\"></a>", wsr_info->dbid);
    if (wsr_opts->switch_shd_off && wsr_info->node_name != NULL) {
        wsr_write_fmt2(wsr_opts, WSR_FMT_SIZE_500,
            "<font face=\"Courier New, Courier, mono\" color=\"#666\">Host CPU %s</font>",
            wsr_info->node_name);
    } else {
        wsr_write_str2(wsr_opts, "<font face=\"Courier New, Courier, mono\" color=\"#666\">Host CPU</font>");
    }
    wsr_write_str2(wsr_opts, "            <!-- <h2 class=\"wsr\">Host CPU</h2> -->");
    wsr_write_str2(wsr_opts, "            <table class=\"table table-hover\" >");
    wsr_write_str2(wsr_opts, "              <thead>");
    wsr_write_str2(wsr_opts, "                <tr>");
    wsr_write_str2(wsr_opts, "                  <th>CPUs</th>");
    wsr_write_str2(wsr_opts, "                  <th>Cores</th>");
    wsr_write_str2(wsr_opts, "                  <th>Sockets</th>");
    wsr_write_str2(wsr_opts, "                  <th>%User</th>");
    wsr_write_str2(wsr_opts, "                  <th>%System</th>");
    wsr_write_str2(wsr_opts, "                  <th>%WIO</th>");
    wsr_write_str2(wsr_opts, "                  <th>%Idle</th>");
    wsr_write_str2(wsr_opts, "                </tr>");
    wsr_write_str2(wsr_opts, "              </thead>");
    wsr_write_str2(wsr_opts, "              <tbody>");
    wsr_write_str2(wsr_opts, "                <tr>");
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                  <td>%u</td>", wsr_info->num_cpu);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                  <td>%u</td>", wsr_info->num_core);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                  <td>%u</td>", wsr_info->num_cpu_socket);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                  <td>%s</td>", wsr_info->cpu_user);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                  <td>%s</td>", wsr_info->cpu_system);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                  <td>%s</td>", wsr_info->cpu_wio);
    wsr_write_fmt(wsr_opts, WSR_FMT_SIZE_500, "                  <td>%s</td>", wsr_info->cpu_idle);
    wsr_write_str2(wsr_opts, "                </tr>");
    wsr_write_str2(wsr_opts, "              </tbody>");
    wsr_write_str2(wsr_opts, "            </table>");
    wsr_write_str2(wsr_opts, "            <p />");
}

int wsr_get_system(wsr_options_t *wsr_opts, const char *stat_name, uint64 *stat_value)
{
    uint32 rows;
    uint64 *data = NULL;
    bool32 is_null = GS_FALSE;
    uint32 size;
    char *cmd_sql = NULL;
    uint32 index = 0;

    cmd_sql = (char *)"SELECT CAST (B.VALUE - A.VALUE AS BINARY_BIGINT) "
        "FROM ADM_HIST_SYSTEM A, ADM_HIST_SYSTEM B "
        "WHERE A.SNAP_ID = :p1 AND B.SNAP_ID= :p2 AND A.STAT_NAME = :p3 AND B.STAT_NAME = :p4";

    GS_RETURN_IFERR(gsc_prepare(wsr_opts->curr_stmt, cmd_sql));
    GS_RETURN_IFERR(gsc_bind_by_pos(wsr_opts->curr_stmt, index++, GSC_TYPE_INTEGER,
        &wsr_opts->start_snap_id, sizeof(uint32), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(wsr_opts->curr_stmt, index++, GSC_TYPE_INTEGER,
        &wsr_opts->end_snap_id, sizeof(uint32), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(wsr_opts->curr_stmt, index++, GSC_TYPE_STRING,
        stat_name, (int32)strlen(stat_name), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(wsr_opts->curr_stmt, index++, GSC_TYPE_STRING,
        stat_name, (int32)strlen(stat_name), NULL));
    GS_RETURN_IFERR(gsc_execute(wsr_opts->curr_stmt));

    GS_RETURN_IFERR(gsc_fetch(wsr_opts->curr_stmt, &rows));
    if (rows == 0) {
        *stat_value = 0;
        return GSC_SUCCESS;
    }

    if (gsc_get_column_by_id(wsr_opts->curr_stmt, 0, (void **)&data, &size, &is_null) != GS_SUCCESS) {
        gsql_print_error(wsr_opts->curr_conn);
        return GSC_ERROR;
    }

    *stat_value = is_null ? 0 : *data;

    return GSC_SUCCESS;
}

void wsr_write_text(wsr_options_t *wsr_opts, const text_t *text)
{
    if (cm_buf_append_text(&wsr_opts->wsr_txtbuf, text)) {
        return;
    }

    wsr_opts->wsr_buff_exhaust = GS_TRUE;

    wsr_writer(wsr_opts, wsr_opts->wsr_txtbuf.str, wsr_opts->wsr_txtbuf.len);
    wsr_opts->wsr_txtbuf.len = 0;

    if (text->len < wsr_opts->wsr_txtbuf.max_size) {
        (void)cm_buf_append_text(&wsr_opts->wsr_txtbuf, text);
        return;
    }
    wsr_writer(wsr_opts, text->str, text->len);
}

int wsr_insert_sql_list(wsr_options_t *wsr_opts, const char *sql_id, const char *sql_text)
{
    gsc_stmt_t stmt;
    char cmd_buf[MAX_CMD_LEN + 1];

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN,
        "CALL SYS.WSR$INSERT_SQL_LIST('%s', '%s', '%u', '%u') ",
        sql_id, sql_text, wsr_opts->start_snap_id, wsr_opts->end_snap_id));

    if (gsc_alloc_stmt(wsr_opts->curr_conn, &stmt) != GS_SUCCESS) {
        gsql_print_error(wsr_opts->curr_conn);
        return GSC_ERROR;
    }

    if (gsc_prepare(stmt, (const char *)cmd_buf) != GS_SUCCESS) {
        gsc_free_stmt(stmt);
        return GSC_ERROR;
    }

    if (gsc_execute(stmt) != GS_SUCCESS) {
        gsc_free_stmt(stmt);
        return GSC_ERROR;
    }

    gsc_free_stmt(stmt);

    return GSC_SUCCESS;
}