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
 * ctsql_wsr_common.h
 *
 *
 * IDENTIFICATION
 * src/utils/ctsql/ctsql_wsr_common.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CTSQL_WSR_COMMON_H__
#define __CTSQL_WSR_COMMON_H__

#include "ctsql_common.h"
#include "ctsql_export.h"
#include "cm_base.h"
#include "ctsql_wsr.h"
#include "cm_lex.h"
#include "cm_log.h"
#include "cm_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_WSR_ENTITY_LEN  256
#define MAX_WSR_DETAIL_LEN  8000
#define MAX_WSR_DATE_LEN    30
#define WSR_MAX_FILE_BUF    SIZE_M(1)
#define FILE_MODE_OF_WSR    0400
#define WSR_FMT_SIZE_500    500
#define WSR_FMT_SIZE_1000   1000
#define WSR_FMT_SIZE_2000   2000
#define WSR_FMT_SIZE_10000  10000
#define WSR_PER_RATE        100.00
#define WSR_ONE_HUNDRED     100
#define WSR_HTML_NBSP_LEN   5
#define WSR_MAX_NODE_NAME   128
#define MAX_SQL_SIZE_WSR    (uint32)12000
#define WSR_MAX_RECEV_LEN   (uint32)15000
#define WSR_DEFAULT_LIST_NUM 20
#define WSR_MILLION    1000000
#define WSR_UNIT_SIXTY 60
#define WSR_TB_WAITSTAT       "WSR_WAITSTAT"
#define WSR_TB_LATCH          "WSR_LATCH"
#define WSR_TB_LIBRARYCACHE   "WSR_LIBRARYCACHE"
#define WSR_TB_SEGMENT        "WSR_SEGMENT"
#define WSR_TB_SQL_LIST       "WSR_SQL_LIST"
#define WSR_TB_SQL_LIST_PLAN  "WSR_SQL_LIST_PLAN"
#define WSR_TB_DBA_SEGMENTS   "WSR_DBA_SEGMENTS"
#define WSR_TB_SQLAREA        "WSR_SQLAREA"
#define WSR_SUMMAY_FILE_NAME  "summary.html"
#define WSR_DATA_NODE_AGENT   "SYS_DATA_NODES"
#define WSR_EVENT_COUNT 13

typedef enum En_wsrdesc {
    WSR_ITEM_DBTIME = 0,
    WSR_ITEM_ElAPSED = 1,
    WSR_ITEM_CPU_USER = 2,
    WSR_ITEM_CPU_SYSTEM = 3,
    WSR_ITEM_IOWAIT = 4,
    WSR_ITEM_IDLE = 5,
    WSR_ITEM_SESSIONS = 6,
    WSR_ITEM_ACTIVE_SESSIONS = 7,
    WSR_ITEM_TRANSACTIONS = 8,
    WSR_ITEM_LONG_SQL = 9,
    WSR_ITEM_LONG_TRANS = 10,
    WSR_ITEM_DIRTY_DATA = 11,
    WSR_ITEM_PIN_DATA = 12,
    WSR_ITEM_FREE_DATA = 13,
    WSR_ITEM_FREE_TEMP = 14,
    WSR_ITEM_TEMP_HWM = 15,
    WSR_ITEM_TEMP_SWAP = 16,
    WSR_ITEM_PHYSICAL_READ = 17,
    WSR_ITEM_LOGICAL_READ = 18,
    WSR_ITEM_COMMITS = 19,
    WSR_ITEM_ROLLBACKS = 20,
    WSR_ITEM_REDO_SIZE = 21,
    WSR_ITEM_EXECUTIONS = 22,
    WSR_ITEM_FETCHS = 23,
    WSR_ITEM_LOGINS = 24,
    WSR_ITEM_HARD_PARSES = 25,
    WSR_ITEM_MIN_REDO_SYNC = 26,
    WSR_ITEM_MIN_REDO_REPLY = 27,
    WSR_ITEM_MAX_REDO_SYNC = 28,
    WSR_ITEM_MAX_REDO_REPLY = 29,
    WSR_ITEM_MIN_LOGICAL_DELAY = 30,
    WSR_ITEM_MAX_LOGICAL_DELAY = 31,
    WSR_ITEM_TXN_PAGES = 32,
    WSR_ITEM_UNDO_PAGES = 33,
    WSR_ITEM_SYSTEM_TABLESPACE = 34,
    WSR_ITEM_SYSAUX_TABLESPACE = 35,
    WSR_ITEM_USER_TABLESPACE = 36,
    WSR_ITEM_ARCH_LOGS = 37,
    WSR_ITEM_EVENT_LATCH_DATA = 38,
    WSR_ITEM_EVENT_FILE_SYNC = 39,
    WSR_ITEM_EVENT_BUFFER_BUSY = 40,
    WSR_ITEM_EVENT_TX_LOCK = 41,
    WSR_ITEM_EVENT_SCATTER_READ = 42,
    WSR_ITEM_EVENT_SEQ_READ = 43,
    WSR_ITEM_EVENT_READ_BY_OTHER = 44,
    WSR_ITEM_EVENT_ARCH_NEEDED = 45,
    WSR_ITEM_EVENT_ADVISE_LOCK = 46,
    WSR_ITEM_EVENT_TABLE_S_LOCK = 47,
    WSR_ITEM_EVENT_REDO_SWITCH = 48,
    WSR_ITEM_EVENT_ITL_ENQ = 49,
    WSR_ITEM_DBWR_PAGES = 50,
    WSR_ITEM_DBWR_TIME = 51,
    WSR_ITEM_REDO_SWITCH_COUNT = 52,
    WSR_ITEM_PCR_CONSTRUCT_COUNT = 53,
    WSR_ITEM_BCR_CONSTRUCT_COUNT = 54,
    WSR_ITEM_UNDO_PHYSICAL_READ = 55,
    WSR_ITEM_UNDO_LOGICAL_READ = 56,
} En_wsrdesc_t;

typedef enum En_wsr_head_load_desc {
    WSR_LOAD_TABLE_CREATE,
    WSR_LOAD_TABLE_DROP,
    WSR_LOAD_TABLE_ALTER,
    WSR_LOAD_TABLE_PART_DROP,
    WSR_LOAD_TABLE_SUBPART_DROP,
    WSR_LOAD_HISTGRAM_INSERT,
    WSR_LOAD_HISTGRAM_UPDATE,
    WSR_LOAD_HISTGRAM_DELETE,
} En_wsr_head_load_desc_t;

typedef enum En_wsroptdesc {
    WSR_ITEM_NO_ADVICE = 0,
    WSR_ITEM_VERY_HIGH = 1,
    WSR_ITEM_HIGH = 2,
    WSR_ITEM_MEDIUM = 3,
    WSR_ITEM_LOW = 4,
    WSR_ITEM_VERY_LOW = 5,
    WSR_ITEM_NEED_OPT = 6,
    WSR_ITEM_SQL_CAPTURE = 7,
} En_wsroptdesc_t;

typedef enum En_wsrevent {
    WSR_EVENT_NO_ADVICE = 0,
    WSR_EVENT_CPU = 1,
    WSR_EVENT_LATCH_BUFFER_POOL = 2,
    WSR_EVENT_LOG_FILE_SYNC = 3,
    WSR_EVENT_BUFFER_BUSY_WAITS = 4,
    WSR_EVENT_TX_ROW_LOCK = 5,
    WSR_EVENT_TX_ALLOC_ITL = 6,
    WSR_EVENT_SCATTERED_READ = 7,
    WSR_EVENT_SEQUENTIAL_READ = 8,
    WSR_EVENT_CHECKPOINT_INCOMPLETE = 9,
    WSR_EVENT_ARCHIVING_NEEDED = 10,
    WSR_EVENT_READ_BY_OTHER_SESSION = 11,
    WSR_EVENT_ADVISORY_LOCK = 12,
} En_wsrevent_t;

extern const char *g_wsritemdesc[];
extern const char *g_wsrloaddesc[];
extern const char *g_wsreventdesc[];
extern const char *g_wsreventname[];
extern const char *g_wsrheadloaddesc[];

typedef struct {
    char dbname[MAX_WSR_ENTITY_LEN];
    uint32 dbid;
    char instance_name[MAX_WSR_ENTITY_LEN];
    uint32 instance_id;
    uint32 topnsql;
    char db_startup_time[MAX_WSR_DATE_LEN];
    char version[MAX_WSR_ENTITY_LEN];
    char host_name[MAX_WSR_ENTITY_LEN];
    char platform[MAX_WSR_ENTITY_LEN];
    uint32 num_cpu;
    uint32 num_core;
    uint32 num_cpu_socket;
    uint32 memory;
    char start_time[MAX_WSR_DATE_LEN];
    char end_time[MAX_WSR_DATE_LEN];
    uint32 start_sessions;
    uint32 end_sessions;
    uint32 start_cursors;
    uint32 end_cursors;
    uint32 elapsed;
    uint64 dbtime;
    uint64 cputime;
    char instance_status[MAX_WSR_ENTITY_LEN];
    char database_role[MAX_WSR_ENTITY_LEN];
    char copy_status[MAX_WSR_ENTITY_LEN];
    char log_mode[MAX_WSR_ENTITY_LEN];
    uint64 transactions;
    uint64 executions;
    uint64 redo_size;
    uint64 buffer_gets;      // times
    uint64 block_changes;    // when page changes, +1
    uint64 dbwr_disk_writes; // real disk writes
    uint64 disk_reads;       // times
    uint64 disk_read_time;
    uint64 sql_parses;
    uint64 hard_parse;
    uint64 rollbacks;
    uint64 sorts;
    uint64 sort_on_disk;
    uint64 user_calls;
    uint64 sql_parse_time;
    uint64 user_logins;
    uint64 redo_entries;
    uint64 redo_space_requests;
    uint64 select_executions;
    uint64 select_execution_time;
    uint64 update_executions;
    uint64 update_execution_time;
    uint64 insert_executions;
    uint64 insert_execution_time;
    uint64 delete_executions;
    uint64 delete_execution_time;
    uint64 fetched_counts;
    uint64 fetched_rows;
    uint64 processed_rows;
    uint64 temp_allocates;
    uint64 cr_gets;
    uint64 disk_write_time;
    uint64 redo_writes;
    uint64 redo_write_time;
    uint32 shd_start_timesapce;
    uint32 shd_end_timesapce;
    uint32 top_events[WSR_EVENT_COUNT];
    uint32 top_event_num;
    char *node_name;
    char cpu_user[MAX_WSR_ENTITY_LEN];
    char cpu_system[MAX_WSR_ENTITY_LEN];
    char cpu_wio[MAX_WSR_ENTITY_LEN];
    char cpu_idle[MAX_WSR_ENTITY_LEN];
    char latch_hit[MAX_WSR_DATE_LEN];
    char buffer_nowait[MAX_WSR_DATE_LEN];
    char library_hit[MAX_WSR_DATE_LEN];
    uint64 table_create;
    uint64 table_drop;
    uint64 table_alter;
    uint64 histgram_insert;
    uint64 histgram_update;
    uint64 histgram_delete;
    uint64 table_part_drop;
    uint64 table_subpart_drop;
    uint32 sessions_start;
    uint32 cursors_start;
    uint32 sessions_end;
    uint32 cursors_end;
    uint64 undo_buffer_reads;
    uint64 undo_disk_reads;
} wsr_info_t;

typedef struct {
    char owner[MAX_WSR_ENTITY_LEN];
    char tablespace_name[MAX_WSR_ENTITY_LEN];
    char object_name[MAX_WSR_ENTITY_LEN];
    char subobject_name[MAX_WSR_ENTITY_LEN];
    char object_type[MAX_WSR_ENTITY_LEN];
    char value[MAX_WSR_ENTITY_LEN];
    char rate[MAX_WSR_ENTITY_LEN];
} wsr_segment_info_t;

typedef struct {
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
    char recommendations[WSR_FMT_SIZE_10000];
} wsr_sql_info_t;

typedef struct {
    thread_t thread;
    char node_name[WSR_MAX_NODE_NAME];
    ctsql_conn_info_t node_conn;
} wsr_shd_info_t;

typedef struct {
    uint32 start_snap_id;
    uint32 end_snap_id;
    uint32 header_len;
    FILE *wsr_dpfile;
    ctconn_stmt_t curr_stmt;
    ctconn_conn_t curr_conn;
    bool32 switch_shd_off : 1;
    bool32 wsr_result : 1;
    bool32 wsr_buff_exhaust : 1;
    bool32 reserved : 29;
    char file_name[CT_MAX_FILE_NAME_LEN];
    char *wsr_fbuf;
    text_buf_t wsr_txtbuf;
    bool32 input_snap_id;         // true: snap false: time
} wsr_options_t;

typedef struct {
    wsr_options_t shd_wsr_opt;
    wsr_info_t shd_wsr_info;
} wsr_shd_mess_t;

void wsr_writer(wsr_options_t *wsr_opts, char *buf, uint32 size);
float wsr_per_second(const wsr_info_t *wsr_info, uint64 value);
float wsr_per_tran(const wsr_info_t *wsr_info, uint64 value);
float wsr_per_exec(const wsr_info_t *wsr_info, uint64 value);
void wsr_write_str(wsr_options_t *wsr_opts, const char *str);
void wsr_write_str2(wsr_options_t *wsr_opts, const char *str);
void wsr_write_fmt(wsr_options_t *wsr_opts, uint32 max_fmt_sz, const char *fmt, ...);
void wsr_write_fmt2(wsr_options_t *wsr_opts, uint32 max_fmt_sz, const char *fmt, ...);
void wsr_write_per_profile(wsr_options_t *wsr_opts, const wsr_info_t *wsr_info,
    const char *title, uint64 value, const char *comment);
int wsr_execute_sql(ctconn_stmt_t curr_stmt, uint32 *rows, const char *cmd_buf);
float wsr_per_rate(uint64 value, uint64 total);
float wsr_rate_percent(uint64 value, uint64 total);
int wsr_build_top_events_deal(wsr_options_t *wsr_opts);
void wsr_build_host_cpu_write_str(wsr_options_t *wsr_opts, wsr_info_t *wsr_info);
int wsr_get_system(wsr_options_t *wsr_opts, const char *stat_name, uint64 *stat_value);
void wsr_write_text(wsr_options_t *wsr_opts, const text_t *text);
int wsr_insert_sql_list(wsr_options_t *wsr_opts, const char *sql_id, const char *sql_text);

#ifdef __cplusplus
}
#endif

#endif