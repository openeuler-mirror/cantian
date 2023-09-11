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
 * srv_view_stat.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_view_stat.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_view_stat.h"
#include "srv_instance.h"
#include "srv_query.h"
#include "knl_database.h"
#include "dtc_database.h"
#include "dtc_drc.h"
#include "cm_log.h"
#include "knl_interface.h"
#include "cm_io_record.h"
#include "dtc_context.h"
#include "cse_stats.h"
#include "tse_srv.h"

typedef enum en_sysstat_class {
    STAT_TYPE_SQL,
    STAT_TYPE_KERNEL,
    STAT_TYPE_INSRTANCE,
} sysstat_class_t;

typedef struct stat_item {
    sysstat_class_t type;
    char *name;
} stat_item_t;

typedef struct rf_stat_item {
    char *name;
    char *info;
} rf_stat_item_t;

typedef struct st_mem_stat_row {
    char *area;
    uint64 total;
    uint64 used;
    char used_percentage[11]; // max_size = 100.00000% + '\0'
    char unused;
} mem_stat_row_t;

enum {
    MEM_STAT_DATA_BUF,
    MEM_STAT_SHARED_BUF,
    MEM_STAT_TEMP_BUF,
    MEM_STAT_LOG_BUF,
    MEM_STAT_LARGE_BUF,
    MEM_STAT_WORK_THREADS,
    MEM_STAT_SESSIONS,
    MEM_STAT_STMT,
    MEM_STAT_SEND_PACKET,
    MEM_STAT_RECV_PACKET,
    MEM_STAT_SQL_CURSOR,
    MEM_STAT_VMA_MAREA,
    MEM_STAT_VMA_LARGE_MAREA,
    MEM_STAT_RM_BUF,
    MEM_STAT_JSON_DYN_BUF,
    MEM_STAT_ALCK_ITEMS,
    MEM_STAT_ALCK_MAPS,
    MEM_STAT_SQL_POOL,
    MEM_STAT_DC_POOL,
    MEM_STAT_LOB_POOL,
    MEM_STAT_LOCK_POOL,
    MEM_STAT_BUDDY_POOL,
    MEM_STAT_PMA_MAREA,
    // bottom, please add above.
    MEM_STAT_ROW_COUNT
};

static mem_stat_row_t g_mem_stat_rows[MEM_STAT_ROW_COUNT] = {
    { "data_buf", 0, 0, { 0 }},
    { "shared_buf", 0, 0, { 0 }},
    { "temp_buf", 0, 0, { 0 }},
    { "log_buf", 0, 0, { 0 }},
    { "large_buf", 0, 0, { 0 }},
    { "work_threads", 0, 0, { 0 }},
    { "sessions", 0, 0, { 0 }},
    { "stmt", 0, 0, { 0 }},
    { "send_packet", 0, 0, { 0 }},
    { "recv_packet", 0, 0, { 0 }},
    { "sql_cursor", 0, 0, { 0 }},
    { "vma_marea", 0, 0, { 0 }},
    { "vma_large_marea", 0, 0, { 0 }},
    { "rm_buf", 0, 0, { 0 }},
    { "json_dyn_buf", 0, 0, { 0 }},
    { "advisory_lock_items", 0, 0, { 0 }},
    { "advisory_lock_maps", 0, 0, { 0 }},
    { "sql_pool", 0, 0, { 0 }},
    { "dc_pool", 0, 0, { 0 }},
    { "lob_pool", 0, 0, { 0 }},
    { "lock_pool", 0, 0, { 0 }},
    { "buddy_pool", 0, 0, { 0 }},
    { "private memory area", 0, 0, { 0 }},
};

static knl_column_t g_syncpoint_stat_columns[] = {
    { 0, "NAME", 0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN, 0, 0, GS_FALSE, 0, { 0 } },
    { 1, "FLAG", 0, 0, GS_TYPE_INTEGER, sizeof(uint32),    0, 0, GS_FALSE, 0, { 0 }},
    { 2, "COUNT", 0, 0, GS_TYPE_INTEGER, sizeof(uint32),    0, 0, GS_FALSE, 0, { 0 } },
};
/* view of reform stats
 * Integer values will be shown in VALUE column,
 * other values will be shown in INFO column, like rcy_point
 */

static knl_column_t g_io_stat_record_columns[] = {
    { 0, "STATISTIC#",     0, 0, GS_TYPE_INTEGER, sizeof(uint32),  0, 0, GS_FALSE, 0, { 0 }},
    { 1, "NAME",           0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN, 0, 0, GS_FALSE, 0, { 0 }},
    { 2, "START",          0, 0, GS_TYPE_BIGINT, sizeof(uint64), 0, 0, GS_FALSE, 0, { 0 } },
    { 3, "BACK_GOOD",      0, 0, GS_TYPE_BIGINT, sizeof(uint64), 0, 0, GS_FALSE, 0, { 0 } },
    { 4, "BACK_BAD",       0, 0, GS_TYPE_BIGINT, sizeof(uint64), 0, 0, GS_FALSE, 0, { 0 } },
    { 5, "NOT_BACK",       0, 0, GS_TYPE_BIGINT, sizeof(uint64), 0, 0, GS_FALSE, 0, { 0 } },
    { 6, "AVG_US",         0, 0, GS_TYPE_BIGINT, sizeof(uint64), 0, 0, GS_FALSE, 0, { 0 } },
    { 7, "MAX_US",         0, 0, GS_TYPE_BIGINT, sizeof(uint64), 0, 0, GS_FALSE, 0, { 0 } },
    { 8, "MIN_US",         0, 0, GS_TYPE_BIGINT, sizeof(uint64), 0, 0, GS_FALSE, 0, { 0 } },
    { 9, "TOTAL_US",       0, 0, GS_TYPE_BIGINT, sizeof(uint64), 0, 0, GS_FALSE, 0, { 0 } },
    { 10, "TOTAL_GOOD_US", 0, 0, GS_TYPE_BIGINT, sizeof(uint64), 0, 0, GS_FALSE, 0, { 0 } },
    { 11, "AVG_GOOD_US",   0, 0, GS_TYPE_BIGINT, sizeof(uint64), 0, 0, GS_FALSE, 0, { 0 } },
    { 12, "TOTAL_BAD_US",  0, 0, GS_TYPE_BIGINT, sizeof(uint64), 0, 0, GS_FALSE, 0, { 0 } },
    { 13, "AVG_BAD_US",    0, 0, GS_TYPE_BIGINT, sizeof(uint64), 0, 0, GS_FALSE, 0, { 0 } },
};

static knl_column_t g_rfstat_columns[] = {
    { 0, "STATISTIC#", 0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 } },
    { 1, "NAME", 0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN, 0, 0, GS_FALSE, 0, { 0 } },
    { 2, "VALUE", 0, 0, GS_TYPE_BIGINT, sizeof(uint64), 0, 0, GS_FALSE, 0, { 0 } },
    { 3, "INFO", 0, 0, GS_TYPE_VARCHAR, GS_BUFLEN_1K, 0, 0, GS_FALSE, 0, { 0 } },
};

static knl_column_t g_rfdetail_columns[] = {
    { 0, "STATISTIC#",    0, 0, GS_TYPE_INTEGER, sizeof(uint32),  0, 0, GS_FALSE, 0, { 0 }},
    { 1, "NAME",          0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN, 0, 0, GS_FALSE, 0, { 0 }},
    { 2, "START_TIME",    0, 0, GS_TYPE_VARCHAR, GS_MAX_TIME_STRLEN, 0, 0, GS_FALSE, 0, { 0 }},
    { 3, "FINISH_TIME",   0, 0, GS_TYPE_VARCHAR, GS_MAX_TIME_STRLEN, 0, 0, GS_FALSE, 0, { 0 }},
    { 4, "TIME_COST_US", 0, 0, GS_TYPE_BIGINT, sizeof(uint64),  0, 0, GS_FALSE, 0, { 0 }},
    { 5, "STATUS",        0, 0, GS_TYPE_INTEGER, sizeof(uint32),    0, 0, GS_FALSE, 0, { 0 }},
};

knl_column_t g_system_event_columns[] = {
    { 0, "EVENT#",             0, 0, GS_TYPE_INTEGER, sizeof(uint32),  0, 0, GS_FALSE, 0, { 0 } },
    { 1, "EVENT",              0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN, 0, 0, GS_FALSE, 0, { 0 } },
    { 2, "P1",                 0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN, 0, 0, GS_FALSE, 0, { 0 } },
    { 3, "WAIT_CLASS",         0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN, 0, 0, GS_FALSE, 0, { 0 } },
    { 4, "TOTAL_WAITS",        0, 0, GS_TYPE_BIGINT,  sizeof(uint64),  0, 0, GS_FALSE, 0, { 0 } },
    { 5, "TIME_WAITED",        0, 0, GS_TYPE_BIGINT,  sizeof(uint64),  0, 0, GS_FALSE, 0, { 0 } },
    { 6, "TIME_WAITED_MIRCO",  0, 0, GS_TYPE_BIGINT,  sizeof(uint64),  0, 0, GS_FALSE, 0, { 0 } },
    { 7, "AVERAGE_WAIT",       0, 0, GS_TYPE_REAL,    sizeof(double),  0, 0, GS_TRUE,  0, { 0 } },
    { 8, "AVERAGE_WAIT_MIRCO", 0, 0, GS_TYPE_BIGINT,  sizeof(uint64),  0, 0, GS_TRUE,  0, { 0 } },
};

static knl_column_t g_latch_columns[] = {
    { 0, "ID",        0, 0, GS_TYPE_INTEGER, sizeof(uint32),  0, 0, GS_FALSE, 0, { 0 } },
    { 1, "NAME",      0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN, 0, 0, GS_FALSE, 0, { 0 } },
    { 2, "GETS",      0, 0, GS_TYPE_INTEGER, sizeof(uint32),  0, 0, GS_FALSE, 0, { 0 } },
    { 3, "MISSES",    0, 0, GS_TYPE_INTEGER, sizeof(uint32),  0, 0, GS_FALSE, 0, { 0 } },
    { 4, "SPIN_GETS", 0, 0, GS_TYPE_INTEGER, sizeof(uint32),  0, 0, GS_FALSE, 0, { 0 } },
    { 5, "WAIT_TIME", 0, 0, GS_TYPE_INTEGER, sizeof(uint32),  0, 0, GS_FALSE, 0, { 0 } },
};

static knl_column_t g_waitstat_columns[] = {
    { 0, "CLASS", 0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN, 0, 0, GS_FALSE, 0, { 0 } },
    { 1, "COUNT", 0, 0, GS_TYPE_INTEGER, sizeof(uint32),  0, 0, GS_FALSE, 0, { 0 } },
    { 2, "TIME",  0, 0, GS_TYPE_INTEGER, sizeof(uint32),  0, 0, GS_FALSE, 0, { 0 } },
};

static knl_column_t g_segment_statistics_columns[] = {
    { 0, "OWNER",          0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN, 0, 0, GS_FALSE, 0, { 0 } },
    { 1, "OBJECT_NAME",    0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN, 0, 0, GS_FALSE, 0, { 0 } },
    { 2, "SUBOBJECT_NAME", 0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN, 0, 0, GS_TRUE,  0, { 0 } },
    { 3, "TS#",            0, 0, GS_TYPE_INTEGER, sizeof(uint32),  0, 0, GS_FALSE, 0, { 0 } },
    { 4, "OBJECT_TYPE",    0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN, 0, 0, GS_FALSE, 0, { 0 } },
    { 5, "STATISTIC_NAME", 0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN, 0, 0, GS_FALSE, 0, { 0 } },
    { 6, "STATISTIC#",     0, 0, GS_TYPE_INTEGER, sizeof(uint32),  0, 0, GS_FALSE, 0, { 0 } },
    { 7, "VALUE",          0, 0, GS_TYPE_BIGINT,  sizeof(uint64),  0, 0, GS_FALSE, 0, { 0 } },
};

static knl_column_t g_memstat_columns[] = {
    { 0, "NAME",            0, 0, GS_TYPE_VARCHAR, 20,             0, 0, GS_FALSE, 0, { 0 } },
    { 1, "TOTAL",           0, 0, GS_TYPE_BIGINT,  sizeof(uint64), 0, 0, GS_FALSE, 0, { 0 } },
    { 2, "USED",            0, 0, GS_TYPE_BIGINT,  sizeof(uint64), 0, 0, GS_FALSE, 0, { 0 } },
    { 3, "USED_PERCENTAGE", 0, 0, GS_TYPE_VARCHAR, 10,             0, 0, GS_FALSE, 0, { 0 } },
};
#define MEMSTAT_COLS (sizeof(g_memstat_columns) / sizeof(knl_column_t))

static knl_column_t g_undo_stat_columns[] = {
    { 0,  "BEGIN_TIME",          0, 0, GS_TYPE_DATE,    sizeof(date_t),     0, 0, GS_FALSE,  0, { 0 } },
    { 1,  "END_TIME",            0, 0, GS_TYPE_DATE,    sizeof(date_t),     0, 0, GS_FALSE,  0, { 0 } },
    { 2,  "TOTAL_UNDO_PAGES",    0, 0, GS_TYPE_INTEGER, sizeof(uint32),     0, 0, GS_FALSE,  0, { 0 } },
    { 3,  "REU_XP_PAGES",        0, 0, GS_TYPE_INTEGER, sizeof(uint32),     0, 0, GS_FALSE,  0, { 0 } },
    { 4,  "REU_UNXP_PAGES",      0, 0, GS_TYPE_INTEGER, sizeof(uint32),     0, 0, GS_FALSE,  0, { 0 } },
    { 5,  "USE_SPACE_PAGES",     0, 0, GS_TYPE_INTEGER, sizeof(uint32),     0, 0, GS_FALSE,  0, { 0 } },
    { 6,  "STEAL_XP_PAGES",      0, 0, GS_TYPE_INTEGER, sizeof(uint32),     0, 0, GS_FALSE,  0, { 0 } },
    { 7,  "STEAL_UNXP_PAGES",    0, 0, GS_TYPE_INTEGER, sizeof(uint32),     0, 0, GS_FALSE,  0, { 0 } },
    { 8,  "TXN_CNT",             0, 0, GS_TYPE_INTEGER, sizeof(uint32),     0, 0, GS_FALSE,  0, { 0 } },
    { 9,  "LONGEST_SQL_TIME",    0, 0, GS_TYPE_BIGINT,  sizeof(uint64),     0, 0, GS_FALSE,  0, { 0 } },
    { 10, "BUF_BUSY_WAITS",      0, 0, GS_TYPE_BIGINT,  sizeof(uint64),     0, 0, GS_FALSE,  0, { 0 } },
    { 11, "BUSY_WAITS_SEG",      0, 0, GS_TYPE_INTEGER, sizeof(uint32),     0, 0, GS_FALSE,  0, { 0 } },
    { 12, "BUSY_SEG_PAGES",      0, 0, GS_TYPE_INTEGER, sizeof(uint32),     0, 0, GS_FALSE,  0, { 0 } },
    { 13, "RETENTION_TIME",      0, 0, GS_TYPE_INTEGER, sizeof(uint32),     0, 0, GS_FALSE,  0, { 0 } },
};

static knl_column_t g_index_coalesce_columns[] = {
    { 0,  "USER_NAME",           0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN,    0, 0, GS_FALSE,  0, { 0 } },
    { 1,  "TABLE_NAME",          0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN,    0, 0, GS_FALSE,  0, { 0 } },
    { 2,  "INDEX_NAME",          0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN,    0, 0, GS_FALSE,  0, { 0 } },
    { 3,  "INDEX_PART_NAME",     0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN,    0, 0, GS_TRUE,   0, { 0 } },
    { 4,  "INDEX_SUBPART_NAME",  0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN,    0, 0, GS_TRUE,   0, { 0 } },
    { 5,  "NEED_RECYCLE",        0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN,    0, 0, GS_TRUE,   0, { 0 } },
    { 6,  "GARBAGE_RATIO",       0, 0, GS_TYPE_BIGINT,  sizeof(uint64),     0, 0, GS_TRUE,   0, { 0 } },
    { 7,  "GARBAGE_SIZE",        0, 0, GS_TYPE_BIGINT,  sizeof(uint64),     0, 0, GS_TRUE,   0, { 0 } },
    { 8,  "EMPTY_RATIO",         0, 0, GS_TYPE_BIGINT,  sizeof(uint64),     0, 0, GS_TRUE,   0, { 0 } },
    { 9,  "EMPTY_SIZE",          0, 0, GS_TYPE_BIGINT,  sizeof(uint64),     0, 0, GS_TRUE,   0, { 0 } },
    { 10, "FIRST_CHILD_EMPTY_SIZE", 0, 0, GS_TYPE_BIGINT,  sizeof(uint64),  0, 0, GS_TRUE,   0, { 0 } },
    { 11, "RECYCLE_STAT",        0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN,    0, 0, GS_TRUE,   0, { 0 } },
    { 12, "SEGMENT_SIZE",        0, 0, GS_TYPE_BIGINT,  sizeof(uint64),     0, 0, GS_TRUE,   0, { 0 } },
    { 13, "RECYCLED_SIZE",       0, 0, GS_TYPE_BIGINT,  sizeof(uint64),     0, 0, GS_TRUE,   0, { 0 } },
    { 14, "RECYCLED_REUSABLE",   0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN,    0, 0, GS_TRUE,   0, { 0 } },
    { 15, "FIRST_RECYCLE_SCN",   0, 0, GS_TYPE_BIGINT,  sizeof(uint64),     0, 0, GS_TRUE,   0, { 0 } },
    { 16, "LAST_RECYCLE_SCN",    0, 0, GS_TYPE_BIGINT,  sizeof(uint64),     0, 0, GS_TRUE,   0, { 0 } },
    { 17, "OW_DEL_SCN",          0, 0, GS_TYPE_BIGINT,  sizeof(uint64),     0, 0, GS_TRUE,   0, { 0 } },
    { 18, "OW_RECYCLE_SCN",      0, 0, GS_TYPE_BIGINT,  sizeof(uint64),     0, 0, GS_TRUE,   0, { 0 } },
    { 19, "DELETE_SIZE",         0, 0, GS_TYPE_BIGINT,  sizeof(uint64),     0, 0, GS_TRUE,   0, { 0 } },
    { 20, "INSERT_SIZE",         0, 0, GS_TYPE_BIGINT,  sizeof(uint64),     0, 0, GS_TRUE,   0, { 0 } },
    { 21, "ALLOC_PAGES",         0, 0, GS_TYPE_BIGINT,  sizeof(uint64),     0, 0, GS_TRUE,   0, { 0 } },
    { 22, "SEGMENT_SCN",         0, 0, GS_TYPE_BIGINT,  sizeof(uint64),     0, 0, GS_TRUE,   0, { 0 } },
    { 23, "BTREE_LEVEL",         0, 0, GS_TYPE_BIGINT,  sizeof(uint64),     0, 0, GS_TRUE,   0, { 0 } },
};

static knl_column_t g_index_recycle_columns[] = {
    { 0,  "UID",                 0, 0, GS_TYPE_INTEGER, sizeof(uint32),     0, 0, GS_FALSE,  0, { 0 } },
    { 1,  "TABLE_ID",            0, 0, GS_TYPE_INTEGER, sizeof(uint32),     0, 0, GS_FALSE,  0, { 0 } },
    { 2,  "INDEX_ID",            0, 0, GS_TYPE_INTEGER, sizeof(uint32),     0, 0, GS_FALSE,  0, { 0 } },
    { 3,  "PART_ORG_SCN",        0, 0, GS_TYPE_BIGINT,  sizeof(uint64),     0, 0, GS_FALSE,  0, { 0 } },
    { 4,  "XID",                 0, 0, GS_TYPE_BIGINT,  sizeof(uint64),     0, 0, GS_FALSE,  0, { 0 } },
    { 5,  "SCN",                 0, 0, GS_TYPE_BIGINT,  sizeof(uint64),     0, 0, GS_FALSE,  0, { 0 } },
    { 6,  "IS_TX_ACTIVE",        0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN,    0, 0, GS_FALSE,  0, { 0 } },
    { 7,  "MIN_SCN",             0, 0, GS_TYPE_BIGINT,  sizeof(uint64),     0, 0, GS_FALSE,  0, { 0 } },
    { 8,  "CUR_SCN",             0, 0, GS_TYPE_BIGINT,  sizeof(uint64),     0, 0, GS_FALSE,  0, { 0 } },
};

static knl_column_t g_index_rebuild_columns[] = {
    { 0,  "UID",                 0, 0, GS_TYPE_INTEGER, sizeof(uint32),     0, 0, GS_FALSE,  0, { 0 } },
    { 1,  "TABLE_ID",            0, 0, GS_TYPE_INTEGER, sizeof(uint32),     0, 0, GS_FALSE,  0, { 0 } },
    { 2,  "ALTER_INDEX_TYPE",    0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN,    0, 0, GS_FALSE,  0, { 0 } },
    { 3,  "INDEX_NAME",          0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN,    0, 0, GS_FALSE,  0, { 0 } },
    { 4,  "INDEX_PART_NAME",     0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN,    0, 0, GS_TRUE,   0, { 0 } },
    { 5,  "STATE",               0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN,    0, 0, GS_FALSE,  0, { 0 } },
    { 6,  "SCN",                 0, 0, GS_TYPE_BIGINT,  sizeof(uint64),     0, 0, GS_FALSE,  0, { 0 } },
};

static knl_column_t g_paral_replay_stat_columns[] = {
    {0, "SID",                  0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 }},
    {1, "DISK_READ",         0, 0, GS_TYPE_BIGINT,  sizeof(uint64), 0, 0, GS_FALSE, 0, { 0 }},
    {2, "DISK_READ_TOTAL_US",  0, 0, GS_TYPE_BIGINT,  sizeof(uint64), 0, 0, GS_FALSE, 0, { 0 }},
    {3, "DISK_READ_AVG_US",    0, 0, GS_TYPE_BIGINT,  sizeof(uint64), 0, 0, GS_FALSE, 0, { 0 }},
    {4, "SESSION_WORK_US",    0, 0, GS_TYPE_BIGINT,  sizeof(uint64), 0, 0, GS_FALSE, 0, { 0 }},
    {5, "SESSION_USED_US",     0, 0, GS_TYPE_BIGINT,  sizeof(uint64), 0, 0, GS_FALSE, 0, { 0 }},
    {6, "SESSION_UTIL_RATE",    0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 }},
    {7, "ADD_BUCKET_SLEEP_US", 0, 0, GS_TYPE_BIGINT,  sizeof(uint64), 0, 0, GS_FALSE, 0, { 0 }},
    {8, "SESSION_REPLAY_LOG_GROUP",  0, 0, GS_TYPE_BIGINT,  sizeof(uint64), 0, 0, GS_FALSE, 0, { 0 }},
};

static knl_column_t g_redo_stat_columns[] = {
    {0, "IDX",                     0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, {0}},
    {1, "TIME_INTERVAL_S",         0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, {0}},
    {2, "REDO_GEN_SIZE_MB",        0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, {0}},
    {3, "REDO_RECY_SIZE_MB",       0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, {0}},
    {4, "REDO_GEN_SPEED_MB/S",     0, 0, GS_TYPE_REAL,    sizeof(double), 0, 0, GS_FALSE, 0, {0}},
    {5, "REDO_RECY_SPEED_MB/S",    0, 0, GS_TYPE_REAL,    sizeof(double), 0, 0, GS_FALSE, 0, {0}},
    {6, "REDO_RECOVERY_SIZE_MB",   0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, {0}},
    {7, "CKPT_QUEUE_FIRST",        0, 0, GS_TYPE_VARCHAR, 16,             0, 0, GS_FALSE, 0, {0}},
    {8, "END_TIME",                0, 0, GS_TYPE_DATE,    sizeof(date_t), 0, 0, GS_FALSE, 0, {0}},
    {9, "LAST_UPDATE_IDX",         0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, {0}},
};

#define SYNCPOINT_STAT_COLS (sizeof(g_syncpoint_stat_columns) / sizeof(knl_column_t))
#define IO_STAT_RECORD_COLS (sizeof(g_io_stat_record_columns) / sizeof(knl_column_t))
#define RFSTAT_COLS (sizeof(g_rfstat_columns) / sizeof(knl_column_t))
#define RFDETAIL_COLS (sizeof(g_rfdetail_columns) / sizeof(knl_column_t))
#define SYSTEM_EVENT_COLS (sizeof(g_system_event_columns) / sizeof(knl_column_t))
#define LATCH_COLS (ELEMENT_COUNT(g_latch_columns))
#define WAITSTAT_COLS (ELEMENT_COUNT(g_waitstat_columns))
#define SEGMENT_STATISTICS_COLS (ELEMENT_COUNT(g_segment_statistics_columns))

#define UNDO_STAT_COLS (ELEMENT_COUNT(g_undo_stat_columns))
#define INDEX_COALESCE_COLS (ELEMENT_COUNT(g_index_coalesce_columns))
#define INDEX_RECYCLE_COLS (ELEMENT_COUNT(g_index_recycle_columns))
#define INDEX_REBUILD_COLS (ELEMENT_COUNT(g_index_rebuild_columns))
#define PARAL_REPALY_STAT_COLS (sizeof(g_paral_replay_stat_columns) / sizeof(knl_column_t))
#define REDO_STAT_COLS (sizeof(g_redo_stat_columns) / sizeof(knl_column_t))

typedef enum en_sysstat_id {
    EXEC_COUNT = 0,
    EXEC_TIME,
    CPU_TIME,
    DCS_NET_TIME,
    IO_WAIT_TIME,
    PARSES,
    HARD_PARSES,
    PARSES_TIME_ELAPSE,
    SELECTS,
    SELECT_TIME,
    UPDATES,
    UPDATE_TIME,
    INSERTS,
    INSERT_TIME,
    DELETES,
    DELETE_TIME,
    FETCHED_COUNT,
    FETCHED_ROWS,
    PROCESSED_ROWS,
    DISK_READS,
    DISK_READ_TIME,
    DB_BLOCK_CHANGES,
    TEMP_ALLOCS,
    BUFFER_GETS,
    CR_GETS,
    CR_READS,
    DCS_CR_READS,
    DCS_BUFFER_GETS,
    DCS_BUFFER_SENDS,
    DCS_CR_GETS,
    DCS_CR_SENDS,
    SORTS,
    DISK_SORTS,
    ATOMIC_OPERS,
    USER_CURR_LOGON,
    USER_CUMU_LOGON,
    USER_CALLS,
    REDO_WRITES,
    REDO_WRITE_TIME,
    REDO_WRITE_SIZE,
    REDO_SPACE_REQUESTS,
    REDO_WRITES_4K,
    REDO_WRITES_8K,
    REDO_WRITES_16K,
    REDO_WRITES_32K,
    REDO_WRITES_64K,
    REDO_WRITES_128K,
    REDO_WRITES_256K,
    REDO_WRITES_512K,
    REDO_WRITES_1M,
    REDO_WRITES_INF,
    COMMITS,
    NOWAIT_COMMITS,
    XA_COMMITS,
    ROLLBACKS,
    XA_ROLLBACKS,
    LOCAL_TXN_TIMES,
    XA_TXN_TIMES,
    CKPT_AVG_MERGE_IO,
    CKPT_LAST_MERGE_IO,
    DOUBLE_WRITES,
    DOUBLE_WRITE_TIME,
    DISK_WRITES,
    DISK_WRITE_TIME,
    TOTAL_READS,
    TOTAL_WRITES,
    PARALLEL_EXECUTIONS,
    PARALLEL_UNREACHABLE_UNDER_TRANS,
    PARALLEL_UNREACHABLE_RESOURCE_LIMITED,
    PARALLEL_UNREACHABLE_BREAK_PROCESS,
    TOTAL_TABLE_CREATES,
    TOTAL_TABLE_DROPS,
    TOTAL_TABLE_ALTERS,
    TOTAL_HISTS_INSERTS,
    TOTAL_HISTS_UPDATES,
    TOTAL_HISTS_DELETES,
    TOTAL_TABLE_PART_DROPS,
    TOTAL_TABLE_SUBPART_DROPS,
    SPC_FREE_EXTS,
    SPC_SHRINK_TIMES,
    UNDO_FREE_PAGES,
    UNDO_SHRINK_TIMES,
    AUTO_TXN_ALLOC_TIMES,
    AUTO_TXN_PAGE_WAITS,
    AUTO_TXN_PAGE_END_WAITS,
    TXN_ALLOC_TIMES,
    TXN_PAGE_WAITS,
    TXN_PAGE_END_WAITS,
    REDO_SWITCH_COUNT,
    PCR_CONSTRUCT_COUNT,
    BCR_CONSTRUCT_COUNT,
    CR_POOL_CAPACITY,
    CR_POOL_USED,
    UNDO_DISK_READS,
    UNDO_BUF_READS,
    BTREE_LEAF_RECYCLED,
    SYSTEM_STAT_COUNT, // ceil
} sysstat_id_t;

static status_t vw_system_event_fetch(knl_handle_t se, knl_cursor_t *cur)
{
    session_t *session = NULL;
    row_assist_t row;
    wait_event_t event = cur->rowid.vmid;
    uint64 wait_time = 0;
    uint64 wait_count = 0;

    if (event == WAIT_EVENT_COUNT) {
        cur->eof = GS_TRUE;
        return GS_SUCCESS;
    }

    for (uint32 i = 0; i < g_instance->session_pool.hwm; i++) {
        session = g_instance->session_pool.sessions[i];

        uint16 stat_id = session->knl_session.stat_id;
        if (session->is_free || stat_id == GS_INVALID_ID16) {
            continue;
        }

        knl_stat_t stat = *g_instance->stat_pool.stats[stat_id];
        wait_time += stat.wait_time[event];
        wait_count += stat.wait_count[event];
    }

    wait_time += g_instance->kernel.stat.wait_time[event];
    wait_count += g_instance->kernel.stat.wait_count[event];
    const wait_event_desc_t *desc = knl_get_event_desc(event);

    row_init(&row, (char *)cur->row, GS_MAX_ROW_SIZE, SYSTEM_EVENT_COLS);
    GS_RETURN_IFERR(row_put_int32(&row, (int32)event));
    GS_RETURN_IFERR(row_put_str(&row, desc->name));
    GS_RETURN_IFERR(row_put_str(&row, desc->p1));
    GS_RETURN_IFERR(row_put_str(&row, desc->wait_class));
    GS_RETURN_IFERR(row_put_int64(&row, (int64)wait_count));
    GS_RETURN_IFERR(row_put_int64(&row, (int64)(wait_time / NANOSECS_PER_MILLISEC)));
    GS_RETURN_IFERR(row_put_int64(&row, (int64)wait_time));

    if (wait_count == 0) {
        GS_RETURN_IFERR(row_put_null(&row));
        GS_RETURN_IFERR(row_put_null(&row));
    } else {
        GS_RETURN_IFERR(row_put_real(&row, (double)wait_time / NANOSECS_PER_MILLISEC / wait_count));
        GS_RETURN_IFERR(row_put_int64(&row, (int64)(wait_time / wait_count)));
    }

    cm_decode_row((char *)cur->row, cur->offsets, cur->lens, &cur->data_size);
    cur->rowid.vmid++;
    return GS_SUCCESS;
}

typedef enum en_rfstat_id {
    RF_REFORM_STATUS = 0,
    RF_REFORM_MODE,
    RF_REFORM_ROLE,
    RF_REFORM_TRIGGER_VERION,
    RF_REFORM_CURRENT_VERION,
    RF_LAST_RCY_LOG_SIZE,
    RF_LAST_RCY_SET_NUM,
    RF_LAST_RCY_IS_FULL_RECOVERY,
    RF_LAST_RCY_ELAPSED,
    RF_LAST_RCY_LOGIC_LOG_GROUP_COUNT,
    RF_LAST_RCY_LOGIC_LOG_ELAPSED,
    RF_LAST_RCY_LOGIC_LOG_WAIT_TIME,
    RF_ACCUM_RCY_LOG_SIZE,
    RF_ACCUM_RCY_SET_NUM,
    RF_ACCUM_RCY_CREATE_ELAPSED,
    RF_ACCUM_RCY_REVISE_ELAPSED,
    RF_ACCUM_RCY_REPLAY_ELAPSED,
    RF_ACCUM_RCY_ELAPSED,
    RF_ACCUM_RCY_TIMES,
    RF_REMASTER_STATUS,
    RF_REMASTER_IN_RECOVERY,
    RF_REMASTER_TASK_NUM,
    RF_REMASTER_COMPLETE_NUM,
    RF_REMASTER_CLEAN_PAGE_NUM,
    RF_REMASTER_CLEAN_LOCK_NUM,
    RF_REMASTER_CLEAN_CONVERT_NUM,
    RF_REMASTER_RCY_PAGE_NUM,
    RF_REMASTER_RCY_LOCK_NUM,
    RF_REMASTER_MIGRATE_BUF_RES_NUM,
    RF_REMASTER_MIGRATE_LOCK_RES_NUM,
    RF_REMASTER_MIGRATE_BUF_MSG_SEND_NUM,
    RF_REMASTER_MIGRATE_LOCK_MSG_SEND_NUM,
    RF_RECOVERY_IN_PROGRESS,
    RF_RECOVERY_PHASE,
    RF_RECOVERY_REPLAY_THREAD_NUM,
    RF_INST_LIST,
    RF_RCY_POINT_LIST,
    RF_LRP_POINT_LIST,
    RF_CURRENT_READ_RCY_POINT_LIST,
    RF_CKPT_TARGET_TRUNCATE_POINT,
    RF_CKPT_CURRENT_TRUNCATE_POINT,
    RF_RECOVERY_STAT_COUNT, // ceil
} rfstat_id_t;

static rf_stat_item_t g_rfstat_items[] = {
    { "reform status", "" },
    { "reform mode", "" },
    { "reform role", "" },
    { "reform tigger version", "" },
    { "reform current version", "" },
    { "last recovery redo log size", "" },
    { "last recovery set number", "" },
    { "last recovery is full recovery", "" },
    { "last recovery time consuming", ""},
    { "last recovery logic log group count", ""},
    { "last recovery logic log elapsed", ""},
    { "last recovery logic log wait time", ""},
    { "accumulate recovery redo log size", "" },
    { "accumulate recovery set number", "" },
    { "accumulate recovery set creation time consuming", "" },
    { "accumulate recovery set revision time consuming", "" },
    { "accumulate recovery replay time consuming", "" },
    { "accumulate recovery time consuming", "" },
    { "accumulate recovery times", "" },
    { "remaster status", "" },
    { "remaster in recovery", "" },
    { "remaster task number", "" },
    { "remaster complete number", "" },
    { "remaster clean page number", "" },
    { "remaster clean lock number", "" },
    { "remaster clean convert q number", "" },
    { "remaster recovery page number", "" },
    { "remaster recovery lock number", "" },
    { "remaster migrate buf res number", "" },
    { "remaster migrate lock res number", "" },
    { "remaster migrate buf msg sent number", "" },
    { "remaster migrate lock msg sent number", "" },
    { "recovery in progress", "" },
    { "recovery phase", "" },
    { "recovery replay thread number", "" },
    { "reform inst list", "" },
    { "recovery rcy point list", "" },
    { "recovery lrp point list", "" },
    { "recovery current read rcy point list", "" },
    { "reform ckpt target truncate point", "" },
    { "reform ckpt current truncate point", "" },
};

void vm_rfstat_value_fetch(uint64 *stat_vals, dtc_rcy_stat_t *rcy_stat, drc_stat_t *drc_stat,
    reform_detail_t *rf_detail)
{
    dtc_rcy_context_t *rcy_ctx = &g_dtc->dtc_rcy_ctx;
    drc_part_mngr_t *remaster_part_mngr = (&g_drc_res_ctx.part_mngr);
    drc_remaster_mngr_t *remaster_mngr = (&g_drc_res_ctx.part_mngr.remaster_mngr);

    stat_vals[RF_REFORM_STATUS] = g_dtc->rf_ctx.status;
    stat_vals[RF_REFORM_MODE] = g_dtc->rf_ctx.mode;
    stat_vals[RF_REFORM_ROLE] = g_dtc->rf_ctx.info.role;
    stat_vals[RF_REFORM_TRIGGER_VERION] = g_dtc->rf_ctx.info.trigger_version;
    stat_vals[RF_REFORM_CURRENT_VERION] = g_dtc->rf_ctx.info.version;
    stat_vals[RF_LAST_RCY_LOG_SIZE] = rcy_stat->last_rcy_log_size;
    stat_vals[RF_LAST_RCY_SET_NUM] = rcy_stat->last_rcy_set_num;
    stat_vals[RF_LAST_RCY_IS_FULL_RECOVERY] = rcy_stat->last_rcy_is_full_recovery;
    stat_vals[RF_LAST_RCY_ELAPSED] = rf_detail->recovery_elapsed.cost_time;
    stat_vals[RF_LAST_RCY_LOGIC_LOG_GROUP_COUNT] = rcy_stat->last_rcy_logic_log_group_count;
    stat_vals[RF_LAST_RCY_LOGIC_LOG_ELAPSED] = rcy_stat->last_rcy_logic_log_elapsed;
    stat_vals[RF_LAST_RCY_LOGIC_LOG_WAIT_TIME] = rcy_stat->latc_rcy_logic_log_wait_time;
    stat_vals[RF_ACCUM_RCY_LOG_SIZE] = rcy_stat->accum_rcy_log_size;
    stat_vals[RF_ACCUM_RCY_SET_NUM] = rcy_stat->accum_rcy_set_num;
    stat_vals[RF_ACCUM_RCY_CREATE_ELAPSED] = rcy_stat->accum_rcy_set_create_elapsed;
    stat_vals[RF_ACCUM_RCY_REVISE_ELAPSED] = rcy_stat->accum_rcy_set_revise_elapsed;
    stat_vals[RF_ACCUM_RCY_REPLAY_ELAPSED] = rcy_stat->accum_rcy_replay_elapsed;
    stat_vals[RF_ACCUM_RCY_ELAPSED] = rcy_stat->accum_rcy_elapsed;
    stat_vals[RF_ACCUM_RCY_TIMES] = rcy_stat->accum_rcy_times;
    stat_vals[RF_REMASTER_STATUS] = remaster_part_mngr->remaster_status;
    stat_vals[RF_REMASTER_IN_RECOVERY] = (g_rc_ctx->status < REFORM_RECOVER_DONE);
    stat_vals[RF_REMASTER_TASK_NUM] = remaster_mngr->task_num;
    stat_vals[RF_REMASTER_COMPLETE_NUM] = remaster_mngr->complete_num;
    stat_vals[RF_REMASTER_CLEAN_PAGE_NUM] = cm_atomic_get(&drc_stat->clean_page_cnt);
    stat_vals[RF_REMASTER_CLEAN_LOCK_NUM] = cm_atomic_get(&drc_stat->clean_lock_cnt);
    stat_vals[RF_REMASTER_CLEAN_CONVERT_NUM] = cm_atomic_get(&drc_stat->clean_convert_cnt);
    stat_vals[RF_REMASTER_RCY_PAGE_NUM] = cm_atomic_get(&drc_stat->rcy_page_cnt);
    stat_vals[RF_REMASTER_RCY_LOCK_NUM] = cm_atomic_get(&drc_stat->rcy_lock_cnt);
    stat_vals[RF_REMASTER_MIGRATE_BUF_RES_NUM] = cm_atomic_get(&drc_stat->mig_buf_cnt);
    stat_vals[RF_REMASTER_MIGRATE_LOCK_RES_NUM] = cm_atomic_get(&drc_stat->mig_lock_cnt);
    stat_vals[RF_REMASTER_MIGRATE_BUF_MSG_SEND_NUM] = cm_atomic_get(&drc_stat->mig_buf_msg_sent_cnt);
    stat_vals[RF_REMASTER_MIGRATE_LOCK_MSG_SEND_NUM] = cm_atomic_get(&drc_stat->mig_lock_msg_sent_cnt);
    stat_vals[RF_RECOVERY_IN_PROGRESS] = rcy_ctx->in_progress;
    stat_vals[RF_RECOVERY_PHASE] = rcy_ctx->phase;
    stat_vals[RF_RECOVERY_REPLAY_THREAD_NUM] = rcy_ctx->replay_thread_num;
}

status_t vw_rfstat_open(knl_handle_t se, knl_cursor_t *cur)
{
    uint64 *stat_vals = (uint64 *)cur->page_buf;
    session_t *session = (session_t *)se;
    dtc_rcy_stat_t *rcy_stat = &g_dtc->dtc_rcy_ctx.rcy_stat;
    reform_detail_t *rf_detail = &g_rc_ctx->reform_detail;
    drc_res_ctx_t *ctx = &g_drc_res_ctx;
    drc_stat_t *drc_stat = &ctx->stat;
    errno_t rc_memzero;

    cur->rowid.vmid = 0;
    cur->rowid.vm_slot = 0;

    rc_memzero = memset_s(stat_vals, DEFAULT_PAGE_SIZE(session), 0, sizeof(uint64) * RF_RECOVERY_STAT_COUNT);
    MEMS_RETURN_IFERR(rc_memzero);

    vm_rfstat_value_fetch(stat_vals, rcy_stat, drc_stat, rf_detail);
    return GS_SUCCESS;
}

static status_t io_record_fetch(row_assist_t *ra, io_record_detail_t detail, knl_cursor_t *cursor)
{
    GS_RETURN_IFERR(row_put_int64(ra, (int64)(detail.start)));
    GS_RETURN_IFERR(row_put_int64(ra, (int64)(detail.back_good)));
    GS_RETURN_IFERR(row_put_int64(ra, (int64)(detail.back_bad)));
    uint64 total_back = detail.back_good + detail.back_bad;
    uint64 not_back = detail.start - total_back;
    GS_RETURN_IFERR(row_put_int64(ra, (int64)not_back));
    if (total_back == 0) {
        row_put_null(ra);
        row_put_null(ra);
        row_put_null(ra);
        row_put_null(ra);
    } else {
        GS_RETURN_IFERR(row_put_int64(ra, (int64)(detail.total_time / total_back)));
        GS_RETURN_IFERR(row_put_int64(ra, (int64)(detail.max_time)));
        GS_RETURN_IFERR(row_put_int64(ra, (int64)(detail.min_time)));
        GS_RETURN_IFERR(row_put_int64(ra, (int64)(detail.total_time)));
    }

    if (detail.back_good == 0) {
        row_put_null(ra);
        row_put_null(ra);
    } else {
        GS_RETURN_IFERR(row_put_int64(ra, (int64)(detail.total_good_time)));
        GS_RETURN_IFERR(row_put_int64(ra, (int64)(detail.total_good_time / detail.back_good)));
    }

    if (detail.back_bad == 0) {
        row_put_null(ra);
        row_put_null(ra);
    } else {
        GS_RETURN_IFERR(row_put_int64(ra, (int64)(detail.total_bad_time)));
        GS_RETURN_IFERR(row_put_int64(ra, (int64)(detail.total_bad_time / detail.back_bad)));
    }

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;
    return GS_SUCCESS;
}

status_t vw_tse_io_fetch(knl_handle_t session, knl_cursor_t *cur)
{
    uint64 id = cur->rowid.vmid;
    while (GS_TRUE) {
        if (id >= TSE_FUNC_TYPE_NUMBER) {
            cur->eof = GS_TRUE;
            return GS_SUCCESS;
        }
        if (g_tse_io_record_event_wait[id].detail.start == 0) {
            cur->rowid.vmid++;
            id = cur->rowid.vmid;
            continue;
        }
        break;
    }
    row_assist_t ra;
    row_init(&ra, (char *)cur->row, GS_MAX_ROW_SIZE, IO_STAT_RECORD_COLS);
    GS_RETURN_IFERR(row_put_int32(&ra, (int32)id));
    GS_RETURN_IFERR(row_put_str(&ra, g_tse_io_record_event_desc[id].name));

    io_record_detail_t detail = g_tse_io_record_event_wait[id].detail;
    return io_record_fetch(&ra, detail, cur);
}

status_t vw_io_stat_record_fetch(knl_handle_t session, knl_cursor_t *cur)
{
    uint64 id = cur->rowid.vmid;

    while (GS_TRUE) {
        if (id >= IO_RECORD_EVENT_COUNT) {
            cur->eof = GS_TRUE;
            return GS_SUCCESS;
        }
        if (g_io_record_event_wait[id].detail.start == 0) {
            cur->rowid.vmid++;
            id = cur->rowid.vmid;
            continue;
        }
        break;
    }

    row_assist_t ra;
    row_init(&ra, (char *)cur->row, GS_MAX_ROW_SIZE, IO_STAT_RECORD_COLS);
    GS_RETURN_IFERR(row_put_int32(&ra, (int32)id));
    GS_RETURN_IFERR(row_put_str(&ra, g_io_record_event_desc[id].name));

    io_record_detail_t detail = g_io_record_event_wait[id].detail;
    return io_record_fetch(&ra, detail, cur);
}

status_t vm_rfstat_fetch_row(row_assist_t *ra, uint64 id, dtc_rcy_context_t *dtc_rcy, dtc_rcy_stat_t *rcy_stat,
    ckpt_context_t *ckpt_ctx)
{
    uint8 j = 0;
    char str[GS_BUFLEN_1K];

    if (RF_RCY_POINT_LIST == id) {
        for (uint8 i = 0; i < rcy_stat->last_rcy_inst_list.inst_id_count; i++) {
            log_point_t rcy_point = rcy_stat->rcy_log_points[i].rcy_point;
            j += sprintf_s(str + j, sizeof(str) - j, "%llu-%llu-%u-%llu-%llu,    ", rcy_point.rst_id, rcy_point.asn,
                rcy_point.block_id, rcy_point.lfn, rcy_point.lsn);
        }
        GS_RETURN_IFERR(row_put_str(ra, str));
    } else if (RF_LRP_POINT_LIST == id) {
        for (uint8 i = 0; i < rcy_stat->last_rcy_inst_list.inst_id_count; i++) {
            log_point_t lrp_point = rcy_stat->rcy_log_points[i].lrp_point;
            j += sprintf_s(str + j, sizeof(str) - j, "%llu-%llu-%u-%llu-%llu,    ", lrp_point.rst_id, lrp_point.asn,
                lrp_point.block_id, lrp_point.lfn, lrp_point.lsn);
        }
        GS_RETURN_IFERR(row_put_str(ra, str));
    } else if (RF_CURRENT_READ_RCY_POINT_LIST == id) {
        for (uint8 i = 0; i < rcy_stat->last_rcy_inst_list.inst_id_count; i++) {
            log_point_t rcy_point = dtc_rcy->rcy_log_points[i].rcy_point;
            j += sprintf_s(str + j, sizeof(str) - j, "%llu-%llu-%u-%llu-%llu,    ", rcy_point.rst_id, rcy_point.asn,
                rcy_point.block_id, rcy_point.lfn, rcy_point.lsn);
        }
        GS_RETURN_IFERR(row_put_str(ra, str));
    } else if (RF_INST_LIST == id) {
        for (uint8 i = 0; i < rcy_stat->last_rcy_inst_list.inst_id_count; i++) {
            j += sprintf_s(str + j, sizeof(str) - j, "%u,      ", rcy_stat->last_rcy_inst_list.inst_id_list[i]);
        }
        GS_RETURN_IFERR(row_put_str(ra, str));
    } else if (RF_CKPT_TARGET_TRUNCATE_POINT == id) {
        PRTS_RETURN_IFERR(sprintf_s(str, sizeof(str), "%llu-%llu-%u-%llu-%llu", g_rc_ctx->prcy_trunc_point.rst_id,
            g_rc_ctx->prcy_trunc_point.asn, g_rc_ctx->prcy_trunc_point.block_id, g_rc_ctx->prcy_trunc_point.lfn,
            g_rc_ctx->prcy_trunc_point.lsn));
        GS_RETURN_IFERR(row_put_str(ra, str));
    } else if (RF_CKPT_CURRENT_TRUNCATE_POINT == id) {
        PRTS_RETURN_IFERR(sprintf_s(str, sizeof(str), "%llu-%llu-%u-%llu-%llu", ckpt_ctx->queue.trunc_point.rst_id,
            ckpt_ctx->queue.trunc_point.asn, ckpt_ctx->queue.trunc_point.block_id, ckpt_ctx->queue.trunc_point.lfn,
            ckpt_ctx->queue.trunc_point.lsn));
        GS_RETURN_IFERR(row_put_str(ra, str));
    } else {
        GS_RETURN_IFERR(row_put_str(ra, g_rfstat_items[id].info));
    }
    return GS_SUCCESS;
}

status_t vw_rfstat_fetch(knl_handle_t session, knl_cursor_t *cur)
{
    knl_session_t *se = (knl_session_t *)session;
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_stat_t *rcy_stat = &dtc_rcy->rcy_stat;
    ckpt_context_t *ckpt_ctx = &se->kernel->ckpt_ctx;
    uint64 id = cur->rowid.vmid;
    uint64 *stat_vals = (uint64 *)cur->page_buf;
    row_assist_t ra;

    if (id >= RF_RECOVERY_STAT_COUNT) {
        cur->eof = GS_TRUE;
        return GS_SUCCESS;
    }

    row_init(&ra, (char *)cur->row, GS_MAX_ROW_SIZE, RFSTAT_COLS);
    GS_RETURN_IFERR(row_put_int32(&ra, (int32)id));
    GS_RETURN_IFERR(row_put_str(&ra, g_rfstat_items[id].name));
    GS_RETURN_IFERR(row_put_int64(&ra, (int64)stat_vals[id]));
    GS_RETURN_IFERR(vm_rfstat_fetch_row(&ra, id, dtc_rcy, rcy_stat, ckpt_ctx));
    cur->rowid.vmid++;
    return GS_SUCCESS;
}

typedef enum en_syncpoint_stat_id {
    SYNCPOINT_STAT_NAME = 0,
    SYNCPOINT_STAT_FLAG,
    SYNCPOINT_STAT_COUNT,
} en_syncpoint_stat_id_t;

status_t vw_syncpoint_stat_open(knl_handle_t se, knl_cursor_t *cur)
{
    cur->rowid.vmid = 0;
    cur->rowid.vm_slot = 0;
    return GS_SUCCESS;
}

status_t vw_syncpoint_stat_fetch(knl_handle_t session, knl_cursor_t *cur)
{
#ifdef DB_DEBUG_VERSION
    uint32 syncpoint_total_count = knl_get_global_syncpoint_total_count();
    uint64 id = cur->rowid.vmid;
    if (id >= syncpoint_total_count) {
        cur->eof = GS_TRUE;
        return GS_SUCCESS;
    }

    row_assist_t ra;
    row_init(&ra, (char *)cur->row, GS_MAX_ROW_SIZE, RFSTAT_COLS);

    GS_RETURN_IFERR(row_put_str(&ra, knl_get_global_syncpoint_name(id)));
    GS_RETURN_IFERR(row_put_int32(&ra, (int32)knl_get_global_syncpoint_flag(id)));
    GS_RETURN_IFERR(row_put_int32(&ra, (int32)knl_get_global_syncpoint_count(id)));

    cur->rowid.vmid++;
    return GS_SUCCESS;
#else
    cur->eof = GS_TRUE;
    return GS_SUCCESS;
#endif
}

typedef enum en_rfdetail_id {
    RF_DETAIL_BUILD_CHANNEL = 0,
    RF_DETAIL_REMASTER,
    RF_DETAIL_REMASTER_PREPARE,
    RF_DETAIL_REMASTER_ASSIGN_TASK,
    RF_DETAIL_REMASTER_MIGRATE,
    RF_DETAIL_REMASTER_RECOVERY,
    RF_DETAIL_REMASTER_PUBLISH,
    RF_DETAIL_RECOVERY,
    RF_DETAIL_RECOVERY_SET_CREATE,
    RF_DETAIL_RECOVERY_SET_REVISE,
    RF_DETAIL_RECOVERY_REPLAY,
    RF_DETAIL_UNDO_ROLLBACK,
    RF_DETAIL_CKPT,
    RF_DETAIL_CLEAN_DDL,
    RF_DETAIL_COUNT,
} rfdetail_id_t;

static rf_stat_item_t g_detail_items[] = {
    { "build channel", "" },
    { "remaster", "" },
    { "remaster prepare", "" },
    { "remaster assign task", "" },
    { "remaster migrate", "" },
    { "remaster recovery", "" },
    { "remaster publish", "" },
    { "recovery", ""  },
    { "recovery set create", "" },
    { "recovery set revise", "" },
    { "recovery replay", "" },
    { "undo rollback", "" },
    { "reform ckpt", "" },
    { "clean ddl", "" },
};

status_t vw_rfdetail_open(knl_handle_t se, knl_cursor_t *cur)
{
    reform_step_t *stat_vals = (reform_step_t *)cur->page_buf;
    session_t *session = (session_t *)se;
    reform_detail_t *rf_detail = &g_dtc->rf_ctx.reform_detail;
    errno_t rc_memzero;

    cur->rowid.vmid = 0;
    cur->rowid.vm_slot = 0;

    rc_memzero = memset_s(stat_vals, DEFAULT_PAGE_SIZE(session), 0, sizeof(reform_step_t) * RF_DETAIL_COUNT);
    MEMS_RETURN_IFERR(rc_memzero);

    stat_vals[RF_DETAIL_BUILD_CHANNEL] = rf_detail->build_channel_elapsed;
    stat_vals[RF_DETAIL_REMASTER] = rf_detail->remaster_elapsed;
    stat_vals[RF_DETAIL_REMASTER_PREPARE] = rf_detail->remaster_prepare_elapsed;
    stat_vals[RF_DETAIL_REMASTER_ASSIGN_TASK] = rf_detail->remaster_assign_task_elapsed;
    stat_vals[RF_DETAIL_REMASTER_MIGRATE] = rf_detail->remaster_migrate_elapsed;
    stat_vals[RF_DETAIL_REMASTER_RECOVERY] = rf_detail->remaster_recovery_elapsed;
    stat_vals[RF_DETAIL_REMASTER_PUBLISH] = rf_detail->remaster_publish_elapsed;
    stat_vals[RF_DETAIL_RECOVERY] = rf_detail->recovery_elapsed;
    stat_vals[RF_DETAIL_RECOVERY_SET_CREATE] = rf_detail->recovery_set_create_elapsed;
    stat_vals[RF_DETAIL_RECOVERY_SET_REVISE] = rf_detail->recovery_set_revise_elapsed;
    stat_vals[RF_DETAIL_RECOVERY_REPLAY] = rf_detail->recovery_replay_elapsed;
    stat_vals[RF_DETAIL_UNDO_ROLLBACK] = rf_detail->deposit_elapsed;
    stat_vals[RF_DETAIL_CKPT] = rf_detail->ckpt_elapsed;
    stat_vals[RF_DETAIL_CLEAN_DDL] = rf_detail->clean_ddp_elapsed;

    return GS_SUCCESS;
}

status_t vw_rfdetail_fetch(knl_handle_t session, knl_cursor_t *cur)
{
    uint64 id = cur->rowid.vmid;
    reform_step_t *stat_vals = (reform_step_t *)cur->page_buf;
    row_assist_t ra;

    while (1) {
        if (id >= RF_DETAIL_COUNT) {
            cur->eof = GS_TRUE;
            return GS_SUCCESS;
        }

        if ((int32)stat_vals[id].run_stat == RC_NOT_RUN) {
            cur->rowid.vmid++;
            id = cur->rowid.vmid;
            continue;
        }
        break;
    }

    row_init(&ra, (char *)cur->row, GS_MAX_ROW_SIZE, RFDETAIL_COLS);
    GS_RETURN_IFERR(row_put_int32(&ra, (int32)id));
    GS_RETURN_IFERR(row_put_str(&ra, g_detail_items[id].name));
    date_t date_time = cm_timeval2date(stat_vals[id].start_time);
    char time_str[GS_MAX_TIME_STRLEN + 1] = { 0 };
    GS_RETURN_IFERR(cm_date2str(date_time, "yyyy-mm-dd hh24:mi:ss.ff3", time_str, GS_MAX_TIME_STRLEN));
    GS_RETURN_IFERR(row_put_str(&ra, time_str));
    if ((int32)stat_vals[id].run_stat == RC_STEP_RUNNING) {
        row_put_null(&ra);
    } else {
        date_time = cm_timeval2date(stat_vals[id].finish_time);
        GS_RETURN_IFERR(cm_date2str(date_time, "yyyy-mm-dd hh24:mi:ss.ff3", time_str, GS_MAX_TIME_STRLEN));
        GS_RETURN_IFERR(row_put_str(&ra, time_str));
    }
    if ((int32)stat_vals[id].run_stat == RC_STEP_RUNNING) {
        row_put_null(&ra);
    } else {
        GS_RETURN_IFERR(row_put_int64(&ra, (int64)stat_vals[id].cost_time));
    }
    GS_RETURN_IFERR(row_put_int32(&ra, (int32)stat_vals[id].run_stat));
    cur->rowid.vmid++;
    return GS_SUCCESS;
}

static uint32 calculate_session_memory(void)
{
    uint32 session_mem_size, len;
    uint32 knl_cur_size = OBJECT_HEAD_SIZE + g_instance->kernel.attr.cursor_size;
    uint32 remote_cur_size = 0;
    session_mem_size = sizeof(session_t);
    len = g_instance->attr.init_cursors * (knl_cur_size + remote_cur_size);
    session_mem_size += len;
    len = sizeof(mtrl_context_t) +
        sizeof(mtrl_segment_t) * (g_instance->kernel.attr.max_temp_tables * 2 - GS_MAX_MATERIALS);
    session_mem_size += len;
    len = sizeof(knl_temp_cache_t) * g_instance->kernel.attr.max_temp_tables;
    session_mem_size += len;
    len = sizeof(void *) * g_instance->kernel.attr.max_temp_tables;
    session_mem_size += len;
    return session_mem_size;
}
uint64 agent_private_size(void)
{
    instance_attr_t *attr = &g_instance->attr;
    knl_attr_t *knl_attr = &g_instance->kernel.attr;
    uint64 area_size, update_buf_size;

    area_size = attr->stack_size;
    area_size += g_instance->kernel.attr.plog_buf_size;
    update_buf_size = knl_get_update_info_size(knl_attr);
    area_size += update_buf_size;
    area_size += g_instance->kernel.attr.thread_stack_size;
    area_size += sizeof(lex_t);
    return area_size;
}
static void calculate_percentage(mem_stat_row_t *mem_stat_rows)
{
    int iret_snprintf;
    double used_percentage = (mem_stat_rows->total == 0) ? 0 : (double)mem_stat_rows->used / mem_stat_rows->total * 100;
    iret_snprintf = snprintf_s(mem_stat_rows->used_percentage, sizeof(mem_stat_rows->used_percentage),
        sizeof(mem_stat_rows->used_percentage) - 1, "%.5f%%", used_percentage);
    if (iret_snprintf == -1) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, (iret_snprintf));
        return;
    }
}

static void vm_buf_pool_stat(knl_session_t *session)
{
    vm_pool_t *pool = NULL;
    knl_attr_t *attr = &session->kernel->attr;
    buf_context_t *buf_ctx = &session->kernel->buf_ctx;
    log_context_t *ctx = &session->kernel->redo_ctx;
    log_dual_buffer_t *section = NULL;

    // data_buf
    g_mem_stat_rows[MEM_STAT_DATA_BUF].used = 0;
    g_mem_stat_rows[MEM_STAT_DATA_BUF].total = attr->data_buf_part_align_size * buf_ctx->buf_set_count;
    for (uint32 i = 0; i < buf_ctx->buf_set_count; i++) {
        g_mem_stat_rows[MEM_STAT_DATA_BUF].used += (uint64)buf_ctx->buf_set[i].hwm *
            (DEFAULT_PAGE_SIZE(session) + BUCKET_TIMES * sizeof(buf_bucket_t) + sizeof(buf_ctrl_t));
    }

    calculate_percentage(&g_mem_stat_rows[MEM_STAT_DATA_BUF]);
    // shared_buf
    memory_area_t *mem_area = &g_instance->sga.shared_area;
    uint64 used_count = mem_area->page_hwm - mem_area->free_pages.count;
    g_mem_stat_rows[MEM_STAT_SHARED_BUF].total = attr->shared_area_size;
    g_mem_stat_rows[MEM_STAT_SHARED_BUF].used = used_count * GS_SHARED_PAGE_SIZE;
    calculate_percentage(&g_mem_stat_rows[MEM_STAT_SHARED_BUF]);
    // temp_buf
    g_mem_stat_rows[MEM_STAT_TEMP_BUF].used = 0;
    g_mem_stat_rows[MEM_STAT_TEMP_BUF].total = attr->temp_buf_inst_align_size * g_instance->kernel.temp_ctx_count;
    for (uint32 i = 0; i < g_instance->kernel.temp_ctx_count; i++) {
        pool = &g_instance->kernel.temp_pool[i];
        used_count = pool->page_hwm - pool->free_pages.count;
        g_mem_stat_rows[MEM_STAT_TEMP_BUF].used += (used_count * GS_VMEM_PAGE_SIZE +
            sizeof(vm_page_t) * (uint64)pool->page_count - sizeof(vm_ctrl_t) * (uint64)pool->free_ctrls.count);
    }
    calculate_percentage(&g_mem_stat_rows[MEM_STAT_TEMP_BUF]);
    // log_buf
    g_mem_stat_rows[MEM_STAT_LOG_BUF].total = attr->log_buf_size;
    g_mem_stat_rows[MEM_STAT_LOG_BUF].used = 0;
    for (uint32 i = 0; i < ctx->buf_count; i++) {
        section = &ctx->bufs[i];
        g_mem_stat_rows[MEM_STAT_LOG_BUF].used += section->members[0].write_pos;
        g_mem_stat_rows[MEM_STAT_LOG_BUF].used += section->members[1].write_pos;
    }
    calculate_percentage(&g_mem_stat_rows[MEM_STAT_LOG_BUF]);
    // large_buf
    g_mem_stat_rows[MEM_STAT_LARGE_BUF].total = attr->large_pool_size;
    used_count = g_instance->sga.large_pool.page_count - g_instance->sga.large_pool.free_pages.count;
    g_mem_stat_rows[MEM_STAT_LARGE_BUF].used = used_count * GS_LARGE_PAGE_SIZE;
    calculate_percentage(&g_mem_stat_rows[MEM_STAT_LARGE_BUF]);
}

static void vm_agent_pool_stat(knl_session_t *session)
{
    agent_pool_t *agent_pool = NULL;
    uint64 reactor_thread_stack_size = g_instance->kernel.attr.reactor_thread_stack_size;
    // agent pool
    g_mem_stat_rows[MEM_STAT_WORK_THREADS].total = 0;
    g_mem_stat_rows[MEM_STAT_WORK_THREADS].used = 0;
    for (uint32 i = 0; i < g_instance->reactor_pool.reactor_count; i++) {
        agent_pool = &g_instance->reactor_pool.reactors[i].agent_pool;
        g_mem_stat_rows[MEM_STAT_WORK_THREADS].total +=
            reactor_thread_stack_size + (uint64)agent_pool->curr_count * (agent_private_size() + sizeof(agent_t));
        g_mem_stat_rows[MEM_STAT_WORK_THREADS].used += reactor_thread_stack_size +
            (uint64)(agent_pool->curr_count - agent_pool->idle_count) * (agent_private_size() + sizeof(agent_t));
    }
    calculate_percentage(&g_mem_stat_rows[MEM_STAT_WORK_THREADS]);
}

static void vm_session_stmt_stat(knl_session_t *session)
{
    session_t *item = NULL;

    // session mem
    g_mem_stat_rows[MEM_STAT_SESSIONS].total = (uint64)g_instance->session_pool.hwm * calculate_session_memory();
    g_mem_stat_rows[MEM_STAT_SESSIONS].used = (uint64)g_instance->session_pool.service_count * calculate_session_memory();
    calculate_percentage(&g_mem_stat_rows[MEM_STAT_SESSIONS]);
    // stmt
    g_mem_stat_rows[MEM_STAT_STMT].total = 0;
    g_mem_stat_rows[MEM_STAT_STMT].used = 0;
    for (uint32 i = g_instance->kernel.reserved_sessions; i < g_instance->session_pool.hwm; i++) {
        item = g_instance->session_pool.sessions[i];
        if (item != NULL) {
            g_mem_stat_rows[MEM_STAT_STMT].total +=
                (uint64)item->stmts.extent_count * item->stmts.extent_step * item->stmts.item_size;
            if (!item->is_free) {
                g_mem_stat_rows[MEM_STAT_STMT].used += (uint64)item->stmts.count * sizeof(sql_stmt_t);
            }
        }
    }
    calculate_percentage(&g_mem_stat_rows[MEM_STAT_STMT]);
}

static void vm_calculate_total_packet(agent_pool_t *agent_pool, uint64 *send_total_cnt, uint64 *recv_total_cnt)
{
    agent_t *agent = NULL;
    uint64 agent_send_total_pk = 0;
    uint64 agent_recv_total_pk = 0;

    for (uint32 i = 0; i < agent_pool->optimized_count; i++) {
        agent = &agent_pool->agents[i];
        if (agent->send_pack.buf_size > SIZE_K(96)) {
            agent_send_total_pk += agent->send_pack.buf_size;
        }
        if (agent->recv_pack.buf_size > SIZE_K(96)) {
            agent_recv_total_pk += agent->recv_pack.buf_size;
        }
    }

    if (agent_pool->ext_agents != NULL) {
        agent_t *slot_agents = NULL;
        uint32 slot_used_id = CM_ALIGN_CEIL(agent_pool->extended_count, AGENT_EXTEND_STEP);

        for (uint32 i = 0; i < slot_used_id; ++i) {
            slot_agents = agent_pool->ext_agents[i].slot_agents;
            for (uint16 j = 0; j < agent_pool->ext_agents[i].slot_agent_count; j++) {
                agent = &slot_agents[j];
                if (agent->send_pack.buf_size > SIZE_K(96)) {
                    agent_send_total_pk += agent->send_pack.buf_size;
                }
                if (agent->recv_pack.buf_size > SIZE_K(96)) {
                    agent_recv_total_pk += agent->recv_pack.buf_size;
                }
            }
        }
    }

    *send_total_cnt = agent_send_total_pk;
    *recv_total_cnt = agent_recv_total_pk;
}

static void vm_calculate_free_packet(agent_pool_t *agent_pool, uint64 *send_free_cnt, uint64 *recv_free_cnt)
{
    agent_t *agent = NULL;
    uint64 agent_send_free_pk = 0;
    uint64 agent_recv_free_pk = 0;
    biqueue_node_t *node = NULL;
    node = agent_pool->idle_agents.dumb.next;
    for (uint32 k = 0; k < agent_pool->idle_count && node != NULL; k++) {
        agent = OBJECT_OF(agent_t, node);
        if (agent->send_pack.buf_size > SIZE_K(96)) {
            agent_send_free_pk += agent->send_pack.buf_size;
        }
        if (agent->recv_pack.buf_size > SIZE_K(96)) {
            agent_recv_free_pk += agent->recv_pack.buf_size;
        }
        node = node->next;
    }

    *send_free_cnt = agent_send_free_pk;
    *recv_free_cnt = agent_recv_free_pk;
}

static void vm_packet_stat(knl_session_t *session)
{
    uint64 agent_send_total_pk = 0;
    uint64 agent_send_free_pk = 0;
    uint64 agent_recv_total_pk = 0;
    uint64 agent_recv_free_pk = 0;
    reactor_t *reactor = NULL;
    // packet
    g_mem_stat_rows[MEM_STAT_SEND_PACKET].total = 0;
    g_mem_stat_rows[MEM_STAT_SEND_PACKET].used = 0;
    g_mem_stat_rows[MEM_STAT_RECV_PACKET].total = 0;
    g_mem_stat_rows[MEM_STAT_RECV_PACKET].used = 0;
    for (uint32 i = 0; i < g_instance->reactor_pool.reactor_count; i++) {
        agent_send_free_pk = 0;
        agent_send_total_pk = 0;
        agent_recv_free_pk = 0;
        agent_recv_total_pk = 0;
        reactor = &g_instance->reactor_pool.reactors[i];
        cm_spin_lock(&reactor->agent_pool.lock_new, NULL);
        vm_calculate_total_packet(&reactor->agent_pool, &agent_send_total_pk, &agent_recv_total_pk);
        cm_spin_unlock(&reactor->agent_pool.lock_new);
        cm_spin_lock(&reactor->agent_pool.lock_idle, NULL);
        vm_calculate_free_packet(&reactor->agent_pool, &agent_send_free_pk, &agent_recv_free_pk);
        cm_spin_unlock(&reactor->agent_pool.lock_idle);

        g_mem_stat_rows[MEM_STAT_SEND_PACKET].total += agent_send_total_pk;
        g_mem_stat_rows[MEM_STAT_SEND_PACKET].used += (agent_send_total_pk - agent_send_free_pk);
        g_mem_stat_rows[MEM_STAT_RECV_PACKET].total += agent_recv_total_pk;
        g_mem_stat_rows[MEM_STAT_RECV_PACKET].used += (agent_recv_total_pk - agent_recv_free_pk);
    }
    calculate_percentage(&g_mem_stat_rows[MEM_STAT_SEND_PACKET]);
    calculate_percentage(&g_mem_stat_rows[MEM_STAT_RECV_PACKET]);
}

static void vm_sql_cursor_stat(knl_session_t *session)
{
    uint32 sql_cur_size = CM_ALIGN8(OBJECT_HEAD_SIZE + sizeof(sql_cursor_t));
    uint64 free_sql_cur_cnt = 0;
    // sql_cursor
    g_mem_stat_rows[MEM_STAT_SQL_CURSOR].total = (uint64)g_instance->sql_cur_pool.cnt * sql_cur_size;

    for (uint32 i = g_instance->kernel.reserved_sessions; i < g_instance->session_pool.hwm; i++) {
        free_sql_cur_cnt += g_instance->session_pool.sessions[i]->sql_cur_pool.free_objects.count;
    }
    uint64 used_count =
        g_instance->sql_cur_pool.cnt - g_instance->sql_cur_pool.pool.free_objects.count - free_sql_cur_cnt;
    g_mem_stat_rows[MEM_STAT_SQL_CURSOR].used = used_count * sql_cur_size;
    calculate_percentage(&g_mem_stat_rows[MEM_STAT_SQL_CURSOR]);
}

static void vm_vma_rm_stat(knl_session_t *session)
{
    knl_attr_t *attr = &session->kernel->attr;
    uint64 used_count = g_instance->sga.vma.marea.page_hwm - g_instance->sga.vma.marea.free_pages.count;
    // vma_marea
    g_mem_stat_rows[MEM_STAT_VMA_MAREA].total = attr->vma_size;
    g_mem_stat_rows[MEM_STAT_VMA_MAREA].used = used_count * GS_VMA_PAGE_SIZE;
    calculate_percentage(&g_mem_stat_rows[MEM_STAT_VMA_MAREA]);
    // vma_large_marea
    g_mem_stat_rows[MEM_STAT_VMA_LARGE_MAREA].total = attr->large_pool_size;
    used_count = g_instance->sga.vma.large_marea.page_hwm - g_instance->sga.vma.large_marea.free_pages.count;
    g_mem_stat_rows[MEM_STAT_VMA_LARGE_MAREA].used = used_count * GS_LARGE_VMA_PAGE_SIZE;
    calculate_percentage(&g_mem_stat_rows[MEM_STAT_VMA_LARGE_MAREA]);

    // rm mem
    g_mem_stat_rows[MEM_STAT_RM_BUF].total = g_instance->rm_pool.capacity * sizeof(knl_rm_t);
    used_count = g_instance->rm_pool.hwm - g_instance->rm_pool.free_list.count;
    g_mem_stat_rows[MEM_STAT_RM_BUF].used = used_count * sizeof(knl_rm_t);
    calculate_percentage(&g_mem_stat_rows[MEM_STAT_RM_BUF]);
}

static void vm_json_dyn_buf_stat(void)
{
    g_mem_stat_rows[MEM_STAT_JSON_DYN_BUF].total = g_instance->sql.json_mpool.max_json_dyn_buf;
    g_mem_stat_rows[MEM_STAT_JSON_DYN_BUF].used = g_instance->sql.json_mpool.used_json_dyn_buf;
    calculate_percentage(&g_mem_stat_rows[MEM_STAT_JSON_DYN_BUF]);
}

static void vm_alck_items_mem_stat(void)
{
    alck_ctx_t *ctx = &g_instance->kernel.alck_ctx;
    uint64 count = ctx->se_ctx.item_pool.capacity + ctx->tx_ctx.item_pool.capacity;
    g_mem_stat_rows[MEM_STAT_ALCK_ITEMS].total = count * sizeof(alck_item_t);
    count = ctx->se_ctx.item_pool.count - ctx->se_ctx.item_pool.free_count + ctx->tx_ctx.item_pool.count -
        ctx->tx_ctx.item_pool.free_count;
    g_mem_stat_rows[MEM_STAT_ALCK_ITEMS].used = count * sizeof(alck_item_t);
    calculate_percentage(&g_mem_stat_rows[MEM_STAT_ALCK_ITEMS]);
}

static void vm_alck_maps_mem_stat(void)
{
    alck_ctx_t *ctx = &g_instance->kernel.alck_ctx;
    g_mem_stat_rows[MEM_STAT_ALCK_MAPS].total =
        (uint64)(ctx->se_ctx.map_pool.capacity + ctx->tx_ctx.map_pool.capacity) * sizeof(alck_map_t);
    g_mem_stat_rows[MEM_STAT_ALCK_MAPS].used = (uint64)(ctx->se_ctx.map_pool.count - ctx->se_ctx.map_pool.free_count +
        ctx->tx_ctx.map_pool.count - ctx->tx_ctx.map_pool.free_count) *
        sizeof(alck_map_t);
    calculate_percentage(&g_mem_stat_rows[MEM_STAT_ALCK_MAPS]);
}

static void vm_mem_pool_stat(void)
{
    memory_pool_t *mem_pool = g_instance->sql.pool->memory;
    uint64 used_count = mem_pool->page_count - mem_pool->free_pages.count;
    // sql pool
    g_mem_stat_rows[MEM_STAT_SQL_POOL].total = (uint64)mem_pool->page_count * mem_pool->page_size;
    g_mem_stat_rows[MEM_STAT_SQL_POOL].used = used_count * mem_pool->page_size;
    calculate_percentage(&g_mem_stat_rows[MEM_STAT_SQL_POOL]);

    // dc pool
    mem_pool = &g_instance->kernel.dc_ctx.pool;
    used_count = mem_pool->page_count - mem_pool->free_pages.count;
    g_mem_stat_rows[MEM_STAT_DC_POOL].total = (uint64)mem_pool->page_count * mem_pool->page_size;
    g_mem_stat_rows[MEM_STAT_DC_POOL].used = used_count * mem_pool->page_size;
    calculate_percentage(&g_mem_stat_rows[MEM_STAT_DC_POOL]);

    // lob pool
    lob_area_t *lob_area = &g_instance->kernel.lob_ctx;
    used_count = lob_area->hwm - lob_area->free_items.count;
    g_mem_stat_rows[MEM_STAT_LOB_POOL].total = (uint64)lob_area->page_count * GS_SHARED_PAGE_SIZE;
    g_mem_stat_rows[MEM_STAT_LOB_POOL].used = used_count * sizeof(lob_item_t);
    calculate_percentage(&g_mem_stat_rows[MEM_STAT_LOB_POOL]);

    // lock pool
    lock_area_t *lock_area = &g_instance->kernel.lock_ctx;
    used_count = lock_area->hwm - lock_area->free_items.count;
    g_mem_stat_rows[MEM_STAT_LOCK_POOL].total = (uint64)lock_area->page_count * GS_SHARED_PAGE_SIZE;
    g_mem_stat_rows[MEM_STAT_LOCK_POOL].used = used_count * sizeof(lock_item_t);
    calculate_percentage(&g_mem_stat_rows[MEM_STAT_LOCK_POOL]);
}

static void vm_buddy_pool_stat(void)
{
    mem_pool_t *buddy_pool = &g_instance->sga.buddy_pool;

    // sql pool
    g_mem_stat_rows[MEM_STAT_BUDDY_POOL].total = buddy_pool->total_size;
    g_mem_stat_rows[MEM_STAT_BUDDY_POOL].used = buddy_pool->used_size;
    calculate_percentage(&g_mem_stat_rows[MEM_STAT_BUDDY_POOL]);
}

static void vm_private_marea_stat(void)
{
    knl_attr_t *attr = &g_instance->kernel.attr;
    uint64 used_count = g_instance->sga.pma.marea.page_hwm - g_instance->sga.pma.marea.free_pages.count;
    // pma_marea
    g_mem_stat_rows[MEM_STAT_PMA_MAREA].total = attr->pma_size;
    g_mem_stat_rows[MEM_STAT_PMA_MAREA].used = used_count * PMA_PAGE_SIZE;
    calculate_percentage(&g_mem_stat_rows[MEM_STAT_PMA_MAREA]);
}

status_t vw_memstat_open(knl_handle_t ses, knl_cursor_t *cur)
{
    cur->rowid.vmid = 0;
    cur->rowid.vm_slot = 0;
    cur->rowid.vm_tag = 0;
    knl_session_t *session = (knl_session_t *)ses;

    vm_buf_pool_stat(session);  // rows index: 0 ~ 4
    vm_agent_pool_stat(session);   // rows index: 5
    vm_session_stmt_stat(session); // rows index: 6 ~ 7
    vm_packet_stat(session);       // rows index: 8 ~ 9
    vm_sql_cursor_stat(session);   // rows index: 10
    vm_vma_rm_stat(session);       // rows index: 11 ~ 13
    vm_json_dyn_buf_stat();        // json dynamic buffer: 14
    vm_alck_items_mem_stat();      // alck item buffer: 15
    vm_alck_maps_mem_stat();       // alck map buffer: 16
    vm_mem_pool_stat();            // sql/dc/lock/lob pool: 17~20
    vm_buddy_pool_stat();          // buddy pool: 21
    vm_private_marea_stat();       // pma: 22
    return GS_SUCCESS;
}

status_t vw_memstat_fetch(knl_handle_t session, knl_cursor_t *cur)
{
    uint64 id;
    row_assist_t ra;

    id = cur->rowid.vmid;
    if (id >= MEM_STAT_ROW_COUNT) {
        cur->eof = GS_TRUE;
        return GS_SUCCESS;
    }

    row_init(&ra, (char *)cur->row, GS_MAX_ROW_SIZE, MEMSTAT_COLS);
    GS_RETURN_IFERR(row_put_str(&ra, g_mem_stat_rows[id].area));
    GS_RETURN_IFERR(row_put_int64(&ra, (int64)g_mem_stat_rows[id].total));
    GS_RETURN_IFERR(row_put_int64(&ra, (int64)g_mem_stat_rows[id].used));
    GS_RETURN_IFERR(row_put_str(&ra, g_mem_stat_rows[id].used_percentage));

    cm_decode_row((char *)cur->row, cur->offsets, cur->lens, &cur->data_size);
    cur->rowid.vmid++;
    return GS_SUCCESS;
}

static char *g_latch_region_map[] = {
    "HEAP LATCH",
    "BTREE LATCH",
    "PAGE LATCH",
    "LOB LATCH",
    "INTERVAL LATCH",
};

typedef enum en_latch_stat_id {
    HEAR_LATCH = 0,
    BTREE_LATCH,
    PAGE_LATCH,
    LOB_LATCH,
    INTERVAL_LATCH,
    LATCH_COUNT,
} latch_stat_id_t;

static status_t vw_latch_open(knl_handle_t session, knl_cursor_t *cur)
{
    knl_session_t *se = NULL;
    latch_statis_t *stats = (latch_statis_t *)cur->page_buf;
    uint32 i;

    cur->rowid.vmid = 0;
    cur->rowid.vm_slot = 0;

    MEMS_RETURN_IFERR(memset_s(stats, DEFAULT_PAGE_SIZE(session), 0, sizeof(latch_statis_t) * LATCH_COUNT));

    for (i = 0; i < g_instance->session_pool.hwm; i++) {
        se = &g_instance->session_pool.sessions[i]->knl_session;
        stats[HEAR_LATCH].hits += se->stat_heap.hits;
        stats[HEAR_LATCH].misses += se->stat_heap.misses;
        stats[HEAR_LATCH].spin_gets += se->stat_heap.spin_gets;
        stats[HEAR_LATCH].s_sleeps += se->stat_heap.s_sleeps + se->stat_heap.x_sleeps + se->stat_heap.ix_sleeps;

        stats[BTREE_LATCH].hits += se->stat_btree.hits;
        stats[BTREE_LATCH].misses += se->stat_btree.misses;
        stats[BTREE_LATCH].spin_gets += se->stat_btree.spin_gets;
        stats[BTREE_LATCH].s_sleeps += se->stat_btree.s_sleeps + se->stat_btree.x_sleeps + se->stat_btree.ix_sleeps;

        stats[PAGE_LATCH].hits += se->stat_page.hits;
        stats[PAGE_LATCH].misses += se->stat_page.misses;
        stats[PAGE_LATCH].spin_gets += se->stat_page.spin_gets;
        stats[PAGE_LATCH].s_sleeps += se->stat_page.s_sleeps + se->stat_page.x_sleeps + se->stat_page.ix_sleeps;

        stats[LOB_LATCH].hits += se->stat_lob.hits;
        stats[LOB_LATCH].misses += se->stat_lob.misses;
        stats[LOB_LATCH].spin_gets += se->stat_lob.spin_gets;
        stats[LOB_LATCH].s_sleeps += se->stat_lob.s_sleeps + se->stat_lob.x_sleeps + se->stat_lob.ix_sleeps;

        stats[INTERVAL_LATCH].hits += se->stat_interval.hits;
        stats[INTERVAL_LATCH].misses += se->stat_interval.misses;
        stats[INTERVAL_LATCH].spin_gets += se->stat_interval.spin_gets;
        stats[INTERVAL_LATCH].s_sleeps +=
            se->stat_interval.s_sleeps + se->stat_interval.x_sleeps + se->stat_interval.ix_sleeps;
    }
    return GS_SUCCESS;
}
static status_t vw_latch_fetch(knl_handle_t session, knl_cursor_t *cur)
{
    uint64 id = cur->rowid.vmid;
    row_assist_t ra;
    latch_statis_t *stats = (latch_statis_t *)cur->page_buf;

    if (id >= LATCH_COUNT) {
        cur->eof = GS_TRUE;
        return GS_SUCCESS;
    }
    row_init(&ra, (char *)cur->row, GS_MAX_ROW_SIZE, LATCH_COLS);
    (void)row_put_int32(&ra, (int32)id); // latch
    (void)row_put_str(&ra, g_latch_region_map[id]);

    stats[id].hits = (stats[id].hits < GS_MAX_INT32) ? stats[id].hits : GS_MAX_INT32;
    (void)row_put_int32(&ra, (int32)stats[id].hits);

    stats[id].misses = (stats[id].misses < GS_MAX_INT32) ? stats[id].misses : GS_MAX_INT32;
    (void)row_put_int32(&ra, (int32)stats[id].misses);

    stats[id].spin_gets = (stats[id].spin_gets < GS_MAX_INT32) ? stats[id].spin_gets : GS_MAX_INT32;
    (void)row_put_int32(&ra, (int32)stats[id].spin_gets);

    stats[id].s_sleeps = (stats[id].s_sleeps < GS_MAX_INT64) ? stats[id].s_sleeps : GS_MAX_INT64;
    (void)row_put_int64(&ra, (int64)stats[id].s_sleeps);

    cur->rowid.vmid++;
    return GS_SUCCESS;
}

static char *g_waitstat_region_map[] = {
    "DATA BLOCK",
    "SEGMENT HEADER",
    "UNDO BLOCK",
    "UNDO HEADER",
    "FREE LIST",
};

static status_t vw_waitstat_open(knl_handle_t session, knl_cursor_t *cur)
{
    knl_session_t *se = NULL;
    knl_buf_wait_t *stats = (knl_buf_wait_t *)cur->page_buf;
    uint32 i;

    cur->rowid.vmid = 0;
    cur->rowid.vm_slot = 0;
    MEMS_RETURN_IFERR(memset_s(stats, DEFAULT_PAGE_SIZE(session), 0, sizeof(knl_buf_wait_t) * WAITSTAT_COUNT));

    for (i = 0; i < g_instance->session_pool.hwm; i++) {
        se = &g_instance->session_pool.sessions[i]->knl_session;
        stats[DATA_BLOCK].wait_time += se->buf_wait[DATA_BLOCK].wait_time;
        stats[DATA_BLOCK].wait_count += se->buf_wait[DATA_BLOCK].wait_count;

        stats[SEGMENT_HEADER].wait_time += se->buf_wait[SEGMENT_HEADER].wait_time;
        stats[SEGMENT_HEADER].wait_count += se->buf_wait[SEGMENT_HEADER].wait_count;

        stats[UNDO_BLOCK].wait_time += se->buf_wait[UNDO_BLOCK].wait_time;
        stats[UNDO_BLOCK].wait_count += se->buf_wait[UNDO_BLOCK].wait_count;

        stats[UNDO_HEADER].wait_time += se->buf_wait[UNDO_HEADER].wait_time;
        stats[UNDO_HEADER].wait_count += se->buf_wait[UNDO_HEADER].wait_count;

        stats[FREE_LIST].wait_time += se->buf_wait[FREE_LIST].wait_time;
        stats[FREE_LIST].wait_count += se->buf_wait[FREE_LIST].wait_count;
    }
    return GS_SUCCESS;
}

static status_t vw_waitstat_fetch(knl_handle_t session, knl_cursor_t *cur)
{
    uint64 id = cur->rowid.vmid;
    knl_buf_wait_t *stats = (knl_buf_wait_t *)cur->page_buf;
    row_assist_t ra;

    if (id >= WAITSTAT_COUNT) {
        cur->eof = GS_TRUE;
        return GS_SUCCESS;
    }

    row_init(&ra, (char *)cur->row, GS_MAX_ROW_SIZE, WAITSTAT_COLS);
    (void)row_put_str(&ra, g_waitstat_region_map[id]);
    (void)row_put_int32(&ra, (int32)(stats[id].wait_count));
    (void)row_put_int64(&ra, (int64)(stats[id].wait_time));

    cur->rowid.vmid++;
    return GS_SUCCESS;
}

typedef enum en_segstat_id {
    PHYSICAL_READS,
    PHYSICAL_WRITE,
    LOGICAL_READS,
    ITL_WAITS,
    BUFFER_BUSY_WAITS,
    ROW_LOCK_WAITS,
    SEGMENT_STAT_COUNT,
} segstat_id_t;

static char *g_seg_stat_name[] = {
    "PHYSICAL READS",
    "PHYSICAL WRITE",
    "LOGICAL READS",
    "ITL WAITS",
    "BUFFER BUSY WAITS",
    "ROW LOCK WAITS",
};

typedef struct st_vw_seg_stat {
    uint32 uid;
    uint32 table_id;
    uint32 tabpart_id;
    uint32 index_id;
    uint32 idxpart_id;
    uint32 stat_id;
    uint64 stat_info[SEGMENT_STAT_COUNT];
} vw_seg_stat_t;

status_t vw_segment_statistics_open(knl_handle_t session, knl_cursor_t *cur)
{
    vw_seg_stat_t *vw_seg_stat = (vw_seg_stat_t *)cur->page_buf;
    MEMS_RETURN_IFERR(memset_s(vw_seg_stat, DEFAULT_PAGE_SIZE(session), 0, sizeof(vw_seg_stat_t)));
    return GS_SUCCESS;
}

static inline bool32 vw_check_valid_entry(knl_handle_t session, vw_seg_stat_t *vw_seg_stat, text_t *user_name,
    text_t *table_name)
{
    dc_group_t *group = NULL;
    dc_user_t *user = NULL;
    dc_entry_t *entry = NULL;

    if (dc_open_user_by_id(session, vw_seg_stat->uid, &user) != GS_SUCCESS) {
        vw_seg_stat->uid++;
        vw_seg_stat->table_id = 0;
        return GS_FALSE;
    }

    if (*user->groups == NULL || vw_seg_stat->table_id >= user->entry_hwm) {
        vw_seg_stat->uid++;
        vw_seg_stat->table_id = 0;
        return GS_FALSE;
    }

    group = user->groups[(vw_seg_stat->table_id) / DC_GROUP_SIZE];
    if (group == NULL) {
        vw_seg_stat->table_id = (vw_seg_stat->table_id / DC_GROUP_SIZE + 1) * DC_GROUP_SIZE;
        return GS_FALSE;
    }

    entry = group->entries[(vw_seg_stat->table_id) % DC_GROUP_SIZE];
    if (entry == NULL || (entry->type != DICT_TYPE_TABLE && entry->type != DICT_TYPE_TABLE_NOLOGGING)) {
        vw_seg_stat->table_id++;
        return GS_FALSE;
    }

    cm_str2text(user->desc.name, user_name);
    cm_str2text(entry->name, table_name);
    return GS_TRUE;
}

static status_t vw_seg_statistics_fetch_core(knl_handle_t session, knl_cursor_t *cur)
{
    dc_entity_t *entity = NULL;
    row_assist_t ra;
    table_t *table = NULL;
    table_part_t *table_part = NULL;
    index_t *index = NULL;
    index_part_t *index_part = NULL;
    vw_seg_stat_t *vw_seg_stat = (vw_seg_stat_t *)cur->page_buf;
    knl_dictionary_t dc;
    text_t user_name, table_name;
    dc.handle = NULL;

    for (;;) {
        if (dc.handle != NULL) {
            knl_close_dc(&dc);
        }

        row_init(&ra, (char *)cur->row, GS_MAX_ROW_SIZE, SEGMENT_STATISTICS_COLS);
        if (vw_seg_stat->uid >= ((knl_session_t *)session)->kernel->dc_ctx.user_hwm) {
            cur->eof = GS_TRUE;
            return GS_SUCCESS;
        }

        if (!vw_check_valid_entry(session, vw_seg_stat, &user_name, &table_name)) {
            continue;
        }

        if (knl_open_dc(session, &user_name, &table_name, &dc) != GS_SUCCESS) {
            dc.handle = NULL;
            vw_seg_stat->table_id++;
            continue;
        }

        entity = (dc_entity_t *)dc.handle;

        table = &entity->table;
        (void)row_put_str(&ra, entity->entry->user->desc.name);
        cur->tenant_id = entity->entry->user->desc.tenant_id;
        if (vw_seg_stat->index_id < table->index_set.count) {
            index = table->index_set.items[vw_seg_stat->index_id];
            if (index != NULL && IS_PART_INDEX(index) && vw_seg_stat->idxpart_id < index->part_index->desc.partcnt) {
                index_part = INDEX_GET_PART(index, vw_seg_stat->idxpart_id);
                if (index_part == NULL) {
                    vw_seg_stat->idxpart_id++;
                    continue;
                }

                vw_seg_stat->stat_info[PHYSICAL_READS] = index_part->btree.stat.physical_reads;
                vw_seg_stat->stat_info[PHYSICAL_WRITE] = index_part->btree.stat.physical_writes;
                vw_seg_stat->stat_info[LOGICAL_READS] = index_part->btree.stat.logic_reads;
                vw_seg_stat->stat_info[ITL_WAITS] = index_part->btree.stat.itl_waits;
                vw_seg_stat->stat_info[BUFFER_BUSY_WAITS] = index_part->btree.stat.buf_busy_waits;
                vw_seg_stat->stat_info[ROW_LOCK_WAITS] = index_part->btree.stat.row_lock_waits;

                if (vw_seg_stat->stat_id < SEGMENT_STAT_COUNT) {
                    (void)row_put_str(&ra, index->desc.name);
                    (void)row_put_str(&ra, index_part->desc.name);
                    (void)row_put_int32(&ra, (int32)index->desc.space_id);
                    (void)row_put_str(&ra, "INDEX PART");
                    (void)row_put_str(&ra, g_seg_stat_name[vw_seg_stat->stat_id]);
                    (void)row_put_int32(&ra, (int32)(vw_seg_stat->stat_id));
                    (void)row_put_int64(&ra, (int64)(vw_seg_stat->stat_info[vw_seg_stat->stat_id]));

                    vw_seg_stat->stat_id++;
                    knl_close_dc(&dc);
                    return GS_SUCCESS;
                }
                vw_seg_stat->idxpart_id++;
                vw_seg_stat->stat_id = 0;
                continue;
            } else {
                if (index == NULL) {
                    vw_seg_stat->index_id++;
                    continue;
                }

                vw_seg_stat->stat_info[PHYSICAL_READS] = index->btree.stat.physical_reads;
                vw_seg_stat->stat_info[PHYSICAL_WRITE] = index->btree.stat.physical_writes;
                vw_seg_stat->stat_info[LOGICAL_READS] = index->btree.stat.logic_reads;
                vw_seg_stat->stat_info[ITL_WAITS] = index->btree.stat.itl_waits;
                vw_seg_stat->stat_info[BUFFER_BUSY_WAITS] = index->btree.stat.buf_busy_waits;
                vw_seg_stat->stat_info[ROW_LOCK_WAITS] = index->btree.stat.row_lock_waits;

                if (vw_seg_stat->stat_id < SEGMENT_STAT_COUNT) {
                    (void)row_put_str(&ra, index->desc.name);
                    (void)row_put_null(&ra);
                    (void)row_put_int32(&ra, (int32)(index->desc.space_id));
                    (void)row_put_str(&ra, "INDEX");
                    (void)row_put_str(&ra, g_seg_stat_name[vw_seg_stat->stat_id]);
                    (void)row_put_int32(&ra, (int32)(vw_seg_stat->stat_id));
                    (void)row_put_int64(&ra, (int64)(vw_seg_stat->stat_info[vw_seg_stat->stat_id]));

                    vw_seg_stat->stat_id++;
                    knl_close_dc(&dc);
                    return GS_SUCCESS;
                }

                vw_seg_stat->index_id++;
                vw_seg_stat->stat_id = 0;
                continue;
            }
        }

        if (IS_PART_TABLE(table) && vw_seg_stat->tabpart_id < table->part_table->desc.partcnt) {
            table_part = TABLE_GET_PART(table, vw_seg_stat->tabpart_id);
            if (!IS_READY_PART(table_part)) {
                vw_seg_stat->tabpart_id++;
                continue;
            }

            vw_seg_stat->stat_info[PHYSICAL_READS] = table_part->heap.stat.physical_reads;
            vw_seg_stat->stat_info[PHYSICAL_WRITE] = table_part->heap.stat.physical_writes;
            vw_seg_stat->stat_info[LOGICAL_READS] = table_part->heap.stat.logic_reads;
            vw_seg_stat->stat_info[ITL_WAITS] = table_part->heap.stat.itl_waits;
            vw_seg_stat->stat_info[BUFFER_BUSY_WAITS] = table_part->heap.stat.buf_busy_waits;
            vw_seg_stat->stat_info[ROW_LOCK_WAITS] = table_part->heap.stat.row_lock_waits;

            if (vw_seg_stat->stat_id < SEGMENT_STAT_COUNT) {
                (void)row_put_str(&ra, table->desc.name);
                (void)row_put_str(&ra, table_part->desc.name);
                (void)row_put_int32(&ra, (int32)(table_part->desc.space_id));
                (void)row_put_str(&ra, "TABLE PART");
                (void)row_put_str(&ra, g_seg_stat_name[vw_seg_stat->stat_id]);
                (void)row_put_int32(&ra, (int32)(vw_seg_stat->stat_id));
                (void)row_put_int64(&ra, (int64)(vw_seg_stat->stat_info[vw_seg_stat->stat_id]));

                vw_seg_stat->stat_id++;
                knl_close_dc(&dc);
                return GS_SUCCESS;
            }

            vw_seg_stat->tabpart_id++;
            vw_seg_stat->stat_id = 0;
            continue;
        } else if (!IS_PART_TABLE(table)) {
            vw_seg_stat->stat_info[PHYSICAL_READS] = table->heap.stat.physical_reads;
            vw_seg_stat->stat_info[PHYSICAL_WRITE] = table->heap.stat.physical_writes;
            vw_seg_stat->stat_info[LOGICAL_READS] = table->heap.stat.logic_reads;
            vw_seg_stat->stat_info[ITL_WAITS] = table->heap.stat.itl_waits;
            vw_seg_stat->stat_info[BUFFER_BUSY_WAITS] = table->heap.stat.buf_busy_waits;
            vw_seg_stat->stat_info[ROW_LOCK_WAITS] = table->heap.stat.row_lock_waits;

            if (vw_seg_stat->stat_id < SEGMENT_STAT_COUNT) {
                (void)row_put_str(&ra, table->desc.name);
                (void)row_put_null(&ra);
                (void)row_put_int32(&ra, (int32)(table->desc.space_id));
                (void)row_put_str(&ra, "TABLE");
                (void)row_put_str(&ra, g_seg_stat_name[vw_seg_stat->stat_id]);
                (void)row_put_int32(&ra, (int32)(vw_seg_stat->stat_id));
                (void)row_put_int64(&ra, (int64)(vw_seg_stat->stat_info[vw_seg_stat->stat_id]));

                vw_seg_stat->stat_id++;
                knl_close_dc(&dc);
                return GS_SUCCESS;
            }

            vw_seg_stat->table_id++;
            vw_seg_stat->index_id = 0;
            vw_seg_stat->idxpart_id = 0;
            vw_seg_stat->tabpart_id = 0;
            vw_seg_stat->stat_id = 0;
            continue;
        }

        vw_seg_stat->table_id++;
        vw_seg_stat->index_id = 0;
        vw_seg_stat->idxpart_id = 0;
        vw_seg_stat->tabpart_id = 0;
        vw_seg_stat->stat_id = 0;
        continue;
    }
}

static status_t vw_segment_statistics_fetch(knl_handle_t session, knl_cursor_t *cur)
{
    return vw_fetch_for_tenant(vw_seg_statistics_fetch_core, session, cur);
}

static status_t vw_undo_stat_fetch_core(knl_handle_t handle, knl_cursor_t *cur)
{
    row_assist_t ra;
    knl_session_t *session = (knl_session_t *)handle;
    undo_context_t *ctx = &session->kernel->undo_ctx;

    if (cur->rowid.vmid >= MIN(GS_MAX_UNDO_STAT_RECORDS, ctx->stat_cnt)) {
        cur->eof = GS_TRUE;
        return GS_SUCCESS;
    }

    uint32 undo_stat_idx = cur->rowid.vm_slot % GS_MAX_UNDO_STAT_RECORDS;
    undo_stat_t undo_stat = ctx->stat[undo_stat_idx];
    row_init(&ra, (char *)cur->row, GS_MAX_ROW_SIZE, UNDO_STAT_COLS);
    cm_spin_lock(&undo_stat.lock, NULL);
    (void)row_put_date(&ra, (int64)undo_stat.begin_time);
    (void)row_put_date(&ra, (int64)undo_stat.end_time);
    (void)row_put_int32(&ra, (int32)undo_stat.total_undo_pages);
    (void)row_put_int32(&ra, (int32)undo_stat.reuse_expire_pages);
    (void)row_put_int32(&ra, (int32)undo_stat.reuse_unexpire_pages);
    (void)row_put_int32(&ra, (int32)undo_stat.use_space_pages);
    (void)row_put_int32(&ra, (int32)undo_stat.steal_expire_pages);
    (void)row_put_int32(&ra, (int32)undo_stat.steal_unexpire_pages);
    (void)row_put_int32(&ra, (int32)undo_stat.txn_cnts);
    (void)row_put_int64(&ra, MIN(GS_MAX_INT64, (int64)undo_stat.longest_sql_time));
    (void)row_put_int64(&ra, MIN(GS_MAX_INT64, (int64)undo_stat.total_buf_busy_waits));
    (void)row_put_int32(&ra, (int32)undo_stat.busy_wait_segment);
    (void)row_put_int32(&ra, (int32)undo_stat.busy_seg_pages);
    (void)row_put_int32(&ra, (int32)session->kernel->attr.undo_retention_time);
    cm_spin_unlock(&undo_stat.lock);

    cm_decode_row((char *)cur->row, cur->offsets, cur->lens, &cur->data_size);
    cur->rowid.vmid++;
    cur->rowid.vm_slot++;

    return GS_SUCCESS;
}

static status_t vw_undo_stat_fetch(knl_handle_t session, knl_cursor_t *cur)
{
    return vw_fetch_for_tenant(vw_undo_stat_fetch_core, session, cur);
}

static status_t vw_undo_stat_open(knl_handle_t session, knl_cursor_t *cur)
{
    knl_session_t *se = (knl_session_t *)session;
    undo_context_t *ctx = &se->kernel->undo_ctx;

    if (ctx->stat_cnt > GS_MAX_UNDO_STAT_RECORDS) {
        cur->rowid.vm_slot = ctx->stat_cnt % GS_MAX_UNDO_STAT_RECORDS;
    } else {
        cur->rowid.vm_slot = 0;
    }

    cur->rowid.vmid = 0;
    cur->rowid.vm_tag = 0;
    return GS_SUCCESS;
}

typedef struct st_vw_idx_coalesce_stat {
    uint32 uid;
    uint32 table_id;
    uint32 index_id;
    uint32 idxpart_id;
    uint32 idx_subpart_id;
} vw_idx_coalesce_stat_t;

typedef enum en_idx_coalesce_stat_inc {
    COALESCE_STAT_UID,
    COALESCE_STAT_TABLE_ID,
    COALESCE_STAT_INDEX_ID,
    COALESCE_STAT_IDXPART_ID,
    COALESCE_STAT_IDX_SUBPART_ID,
} idx_coalesce_stat_inc_t;


void vw_idx_coalesce_stat_inc(vw_idx_coalesce_stat_t *vw_idx_coalesce_stat, idx_coalesce_stat_inc_t inc_type)
{
    switch (inc_type) {
        case COALESCE_STAT_UID:
            vw_idx_coalesce_stat->uid++;
            vw_idx_coalesce_stat->table_id = 0;
            vw_idx_coalesce_stat->index_id = 0;
            vw_idx_coalesce_stat->idxpart_id = 0;
            vw_idx_coalesce_stat->idx_subpart_id = 0;
            break;
        case COALESCE_STAT_TABLE_ID:
            vw_idx_coalesce_stat->table_id++;
            vw_idx_coalesce_stat->index_id = 0;
            vw_idx_coalesce_stat->idxpart_id = 0;
            vw_idx_coalesce_stat->idx_subpart_id = 0;
            break;
        case COALESCE_STAT_INDEX_ID:
            vw_idx_coalesce_stat->index_id++;
            vw_idx_coalesce_stat->idxpart_id = 0;
            vw_idx_coalesce_stat->idx_subpart_id = 0;
            break;
        case COALESCE_STAT_IDXPART_ID:
            vw_idx_coalesce_stat->idxpart_id++;
            vw_idx_coalesce_stat->idx_subpart_id = 0;
            break;
        case COALESCE_STAT_IDX_SUBPART_ID:
            vw_idx_coalesce_stat->idx_subpart_id++;
            break;
        default:
            break;
    }
}

status_t vw_index_coalesce_open(knl_handle_t session, knl_cursor_t *cur)
{
    vw_idx_coalesce_stat_t *vw_idx_coalesce_stat = (vw_idx_coalesce_stat_t *)cur->page_buf;
    MEMS_RETURN_IFERR(memset_s(vw_idx_coalesce_stat, DEFAULT_PAGE_SIZE(session), 0, sizeof(vw_idx_coalesce_stat_t)));
    return GS_SUCCESS;
}

static bool32 vw_idx_coalesce_open_dc(knl_handle_t session, vw_idx_coalesce_stat_t *vw_idx_coalesce_stat,
    knl_dictionary_t *dc)
{
    dc_group_t *group = NULL;
    dc_user_t *user = NULL;
    dc_entry_t *entry = NULL;
    text_t user_name, table_name;

    if (dc_open_user_by_id(session, vw_idx_coalesce_stat->uid, &user) != GS_SUCCESS) {
        vw_idx_coalesce_stat_inc(vw_idx_coalesce_stat, COALESCE_STAT_UID);
        return GS_FALSE;
    }

    if (*user->groups == NULL || vw_idx_coalesce_stat->table_id >= user->entry_hwm) {
        vw_idx_coalesce_stat_inc(vw_idx_coalesce_stat, COALESCE_STAT_UID);
        return GS_FALSE;
    }

    group = user->groups[(vw_idx_coalesce_stat->table_id) / DC_GROUP_SIZE];
    if (group == NULL) {
        vw_idx_coalesce_stat->table_id = (vw_idx_coalesce_stat->table_id / DC_GROUP_SIZE + 1) * DC_GROUP_SIZE;
        vw_idx_coalesce_stat->index_id = 0;
        vw_idx_coalesce_stat->idxpart_id = 0;
        vw_idx_coalesce_stat->idx_subpart_id = 0;
        return GS_FALSE;
    }

    entry = group->entries[(vw_idx_coalesce_stat->table_id) % DC_GROUP_SIZE];
    if (entry == NULL || (entry->type != DICT_TYPE_TABLE && entry->type != DICT_TYPE_TABLE_NOLOGGING)) {
        vw_idx_coalesce_stat_inc(vw_idx_coalesce_stat, COALESCE_STAT_TABLE_ID);
        return GS_FALSE;
    }

    cm_str2text(user->desc.name, &user_name);
    cm_str2text(entry->name, &table_name);
    if (knl_open_dc(session, &user_name, &table_name, dc) != GS_SUCCESS) {
        dc->handle = NULL;
        vw_idx_coalesce_stat_inc(vw_idx_coalesce_stat, COALESCE_STAT_TABLE_ID);
        return GS_FALSE;
    }

    return GS_TRUE;
}

const char *get_recycle_stat(btree_t *btree)
{
    if (btree->is_recycling) {
        return "RECYCLE IN PROGRESS";
    }

    if (btree->wait_recycle) {
        return "RECYCLE WAIT";
    }
    return "RECYCLE END";
}

bool8 dv_idx_coalesce_check_part_valid(dc_entity_t *entity, vw_idx_coalesce_stat_t *vw_idx_coalesce_stat,
    index_part_t **index_part)
{
    index_t *index = entity->table.index_set.items[vw_idx_coalesce_stat->index_id];
    table_part_t *compart = NULL;

    compart = TABLE_GET_PART(&entity->table, vw_idx_coalesce_stat->idxpart_id);
    if (!IS_READY_PART(compart)) {
        return GS_FALSE;
    }

    *index_part = INDEX_GET_PART(index, vw_idx_coalesce_stat->idxpart_id);
    if (*index_part == NULL) {
        return GS_FALSE;
    }

    return GS_TRUE;
}

bool8 dv_idx_coalesce_check_subpart_valid(index_t *index, index_part_t *index_part,
    vw_idx_coalesce_stat_t *vw_idx_coalesce_stat, index_part_t **index_subpart)
{
    *index_subpart = PART_GET_SUBENTITY(index->part_index, index_part->subparts[vw_idx_coalesce_stat->idx_subpart_id]);
    if (*index_subpart == NULL) {
        return GS_FALSE;
    }

    return GS_TRUE;
}

void row_put_for_idx_coalesce(knl_handle_t session, row_assist_t *ra, btree_t *btree, const char *index_part_name,
    const char *index_subpart_name)
{
    idx_recycle_info_t idx_recycle_info = { 0 };
    (void)row_put_str(ra, index_part_name);    // INDEX_PART_NAME
    (void)row_put_str(ra, index_subpart_name); // INDEX_SUBPART_NAME

    if (btree->segment != NULL) {
        // NEED_RECYCLE
        (void)row_put_str(ra, btree_need_recycle(session, btree, &idx_recycle_info) ? "TRUE" : "FALSE");
        (void)row_put_int64(ra, (int64)(idx_recycle_info.garbage_ratio)); // GARBAGE_RATIO
        (void)row_put_int64(ra, (int64)(idx_recycle_info.garbage_size));  // GARBAGE_SIZE
        (void)row_put_int64(ra, (int64)(idx_recycle_info.empty_ratio));   // EMPTY_RATIO
    } else {
        (void)row_put_str(ra, "FALSE"); // NEED_RECYCLE
        (void)row_put_null(ra);
        (void)row_put_null(ra);
        (void)row_put_null(ra);
    }

    (void)row_put_int64(ra, (int64)(btree->chg_stats.empty_size));       // EMPTY_SIZE
    (void)row_put_int64(ra, (int64)(btree->chg_stats.first_empty_size)); // FIRST_EMPTY_SIZE
    (void)row_put_str(ra, get_recycle_stat(btree));                      // RECYCLE_STAT
    if (btree->segment != NULL) {
        (void)row_put_int64(ra, (int64)(idx_recycle_info.segment_size));                // SEGMENT_SIZE
        (void)row_put_int64(ra, (int64)(idx_recycle_info.recycled_size));               // RECYCLED_SIZE
        (void)row_put_str(ra, idx_recycle_info.recycled_reusable ? "TRUE" : "FALSE");   // RECYCLED_REUSABLE
        (void)row_put_int64(ra, (int64)(idx_recycle_info.first_recycle_scn));           // FIRST_RECYCLE_SCN
        (void)row_put_int64(ra, (int64)(idx_recycle_info.last_recycle_scn));            // LAST_RECYCLE_SCN
        (void)row_put_int64(ra, (int64)(KNL_GET_SCN(&btree->chg_stats.ow_del_scn)));    // OW_DEL_SCN
        (void)row_put_int64(ra, (int64)(KNL_GET_SCN(&btree->segment->ow_recycle_scn))); // OW_RECYCLE_SCN
    } else {
        (void)row_put_null(ra);
        (void)row_put_null(ra);
        (void)row_put_str(ra, "FALSE"); // RECYCLED_REUSABLE
        (void)row_put_null(ra);
        (void)row_put_null(ra);
        (void)row_put_int64(ra, (int64)(btree->chg_stats.ow_del_scn)); // OW_DEL_SCN
        (void)row_put_null(ra);
    }

    (void)row_put_int64(ra, (int64)(btree->chg_stats.delete_size)); // DELETE_SIZE
    if (btree->chg_stats.insert_size < 0) {
        (void)row_put_null(ra);
    } else {
        (void)row_put_int64(ra, (int64)(btree->chg_stats.insert_size)); // INSERT_SIZE
    }

    (void)row_put_int64(ra, (int64)(btree->chg_stats.alloc_pages)); // ALLOC_PAGES
    if (btree->segment != NULL) {
        (void)row_put_int64(ra, (int64)(idx_recycle_info.segment_scn)); // SEG_SCN
        (void)row_put_int64(ra, (int64)(idx_recycle_info.btree_level)); // BTREE_LEVEL
    } else {
        (void)row_put_null(ra);
        (void)row_put_null(ra);
    }
}

void row_put_idx_coalesce_common(row_assist_t *ra, dc_entity_t *entity, index_t *index)
{
    (void)row_put_str(ra, entity->entry->user->desc.name); // USER_NAME
    (void)row_put_str(ra, entity->table.desc.name);        // TABLE_NAME
    (void)row_put_str(ra, index->desc.name);               // INDEX_NAME
}

bool8 dv_idx_coalesce_row_put(knl_handle_t session, row_assist_t *ra, knl_dictionary_t *dc,
    vw_idx_coalesce_stat_t *vw_idx_coalesce_stat)
{
    index_t *index = NULL;
    index_part_t *index_part = NULL;
    index_part_t *index_subpart = NULL;
    dc_entity_t *entity = NULL;

    entity = (dc_entity_t *)dc->handle;
    if (vw_idx_coalesce_stat->index_id >= entity->table.index_set.count) {
        vw_idx_coalesce_stat_inc(vw_idx_coalesce_stat, COALESCE_STAT_TABLE_ID);
        return GS_FALSE;
    }

    index = entity->table.index_set.items[vw_idx_coalesce_stat->index_id];
    if (index == NULL) {
        vw_idx_coalesce_stat_inc(vw_idx_coalesce_stat, COALESCE_STAT_INDEX_ID);
        return GS_FALSE;
    }

    row_put_idx_coalesce_common(ra, entity, index);

    if (!IS_PART_INDEX(index)) {
        vw_idx_coalesce_stat_inc(vw_idx_coalesce_stat, COALESCE_STAT_INDEX_ID);
        row_put_for_idx_coalesce(session, ra, &index->btree, "", "");
        return GS_TRUE;
    } else {
        if (vw_idx_coalesce_stat->idxpart_id >= index->part_index->desc.partcnt) {
            vw_idx_coalesce_stat_inc(vw_idx_coalesce_stat, COALESCE_STAT_INDEX_ID);
            return GS_FALSE;
        }
        if (!dv_idx_coalesce_check_part_valid(entity, vw_idx_coalesce_stat, &index_part)) {
            vw_idx_coalesce_stat_inc(vw_idx_coalesce_stat, COALESCE_STAT_IDXPART_ID);
            return GS_FALSE;
        }

        if (IS_PARENT_IDXPART(&index_part->desc)) {
            if (vw_idx_coalesce_stat->idx_subpart_id >= index_part->desc.subpart_cnt) {
                vw_idx_coalesce_stat_inc(vw_idx_coalesce_stat, COALESCE_STAT_IDXPART_ID);
                return GS_FALSE;
            }
            if (!dv_idx_coalesce_check_subpart_valid(index, index_part, vw_idx_coalesce_stat, &index_subpart)) {
                vw_idx_coalesce_stat_inc(vw_idx_coalesce_stat, COALESCE_STAT_IDX_SUBPART_ID);
                return GS_FALSE;
            }
            row_put_for_idx_coalesce(session, ra, &index_subpart->btree, index_part->desc.name,
                index_subpart->desc.name);
            vw_idx_coalesce_stat_inc(vw_idx_coalesce_stat, COALESCE_STAT_IDX_SUBPART_ID);
            return GS_TRUE;
        }

        row_put_for_idx_coalesce(session, ra, &index_part->btree, index_part->desc.name, "");
        vw_idx_coalesce_stat_inc(vw_idx_coalesce_stat, COALESCE_STAT_IDXPART_ID);
        return GS_TRUE;
    }
}

static status_t vw_idx_coalesce_fetch_core(knl_handle_t session, knl_cursor_t *cur)
{
    row_assist_t ra;
    vw_idx_coalesce_stat_t *vw_idx_coalesce_stat = (vw_idx_coalesce_stat_t *)cur->page_buf;
    knl_dictionary_t dc;
    dc.handle = NULL;

    for (;;) {
        if (vw_idx_coalesce_stat->uid >= ((knl_session_t *)session)->kernel->dc_ctx.user_hwm) {
            cur->eof = GS_TRUE;
            return GS_SUCCESS;
        }

        if (!vw_idx_coalesce_open_dc(session, vw_idx_coalesce_stat, &dc)) {
            continue;
        }

        row_init(&ra, (char *)cur->row, GS_MAX_ROW_SIZE, INDEX_COALESCE_COLS);

        if (!dv_idx_coalesce_row_put(session, &ra, &dc, vw_idx_coalesce_stat)) {
            knl_close_dc(&dc);
            continue;
        }

        knl_close_dc(&dc);
        cm_decode_row((char *)cur->row, cur->offsets, cur->lens, &cur->data_size);
        return GS_SUCCESS;
    }
}

static status_t vw_idx_coalesce_fetch(knl_handle_t session, knl_cursor_t *cur)
{
    return vw_fetch_for_tenant(vw_idx_coalesce_fetch_core, session, cur);
}

static status_t vw_idx_recycle_fetch_core(knl_handle_t session, knl_cursor_t *cur)
{
    row_assist_t ra;
    index_recycle_ctx_t *ctx = &((knl_session_t *)session)->kernel->index_ctx.recycle_ctx;

    for (;;) {
        uint32 item_id = (uint32)cur->rowid.vmid;
        if (item_id >= GS_MAX_RECYCLE_INDEXES) {
            cur->eof = GS_TRUE;
            return GS_SUCCESS;
        }
        row_init(&ra, (char *)cur->row, GS_MAX_ROW_SIZE, INDEX_RECYCLE_COLS);

        cm_spin_lock(&ctx->lock, NULL);
        if (ctx->items[item_id].index_id == GS_INVALID_ID32) {
            cur->rowid.vmid++;
            cm_spin_unlock(&ctx->lock);
            continue;
        }
        index_recycle_item_t item = ctx->items[item_id];
        cm_spin_unlock(&ctx->lock);

        (void)row_put_int64(&ra, (int64)(item.uid));      // UID
        (void)row_put_int64(&ra, (int64)(item.table_id)); // TABLE_ID
        (void)row_put_int32(&ra, (int32)(item.index_id)); // INDEX_ID
        if (item.part_org_scn != GS_INVALID_ID64) {
            (void)row_put_int64(&ra, (int64)(item.part_org_scn)); // PART_ORG_SCN
        } else {
            (void)row_put_null(&ra);
        }
        (void)row_put_int64(&ra, (int64)(item.xid.value));                        // XID
        (void)row_put_int64(&ra, (int64)(item.scn));                              // SCN
        (void)row_put_str(&ra, item.is_tx_active ? "TRUE" : "FALSE");             // IS_TX_ACTIVE
        (void)row_put_int64(&ra, (int64)(btree_get_recycle_min_scn(session)));    // MIN_SCN
        (void)row_put_int64(&ra, (int64)(DB_CURR_SCN((knl_session_t *)session))); // CUR_SCN

        cur->rowid.vmid++;
        return GS_SUCCESS;
    }
}

static status_t vw_idx_recycle_fetch(knl_handle_t session, knl_cursor_t *cur)
{
    return vw_fetch_for_tenant(vw_idx_recycle_fetch_core, session, cur);
}

const char *get_alter_index_type(alter_index_type_t type)
{
    switch (type) {
        case ALINDEX_TYPE_REBUILD:
            return "REBUILD";
        case ALINDEX_TYPE_REBUILD_PART:
            return "REBUILD PART";
        case ALINDEX_TYPE_ENABLE:
            return "ENABLE";
        case ALINDEX_TYPE_DISABLE:
            return "DISABLE";
        case ALINDEX_TYPE_RENAME:
            return "RENAME";
        case ALINDEX_TYPE_COALESCE:
            return "COALESCE";
        case ALINDEX_TYPE_MODIFY_PART:
            return "MODIFY PART";
        case ALINDEX_TYPE_UNUSABLE:
            return "UNUSABLE";
        case ALINDEX_TYPE_MODIFY_SUBPART:
            return "MODIFY SUBPART";
        case ALINDEX_TYPE_REBUILD_SUBPART:
            return "REBUILD SUBPART";
        case ALINDEX_TYPE_INITRANS:
            return "INITRANS";
        default:
            return "";
    }
}

const char *get_arebuild_state(arebuild_index_state_t state)
{
    switch (state) {
        case AREBUILD_INDEX_INVALID:
            return "INVALID";
        case AREBUILD_INDEX_WAITTING:
            return "WAITTING";
        case AREBUILD_INDEX_RUNNING:
            return "RUNNING";
        case AREBUILD_INDEX_BUSY:
            return "BUSY";
        default:
            return "";
    }
}

static status_t vw_index_rebuild_fetch_core(knl_handle_t session, knl_cursor_t *cur)
{
    row_assist_t ra;
    auto_rebuild_ctx_t *ctx = &((knl_session_t *)session)->kernel->auto_rebuild_ctx;

    for (;;) {
        uint32 item_id = (uint32)cur->rowid.vmid;
        if (item_id >= GS_MAX_RECYCLE_INDEXES) {
            cur->eof = GS_TRUE;
            return GS_SUCCESS;
        }

        cm_spin_lock(&ctx->lock, NULL);
        if (ctx->items[item_id].state == AREBUILD_INDEX_INVALID) {
            cur->rowid.vmid++;
            cm_spin_unlock(&ctx->lock);
            continue;
        }
        auto_rebuild_item_t item = ctx->items[item_id];
        cm_spin_unlock(&ctx->lock);

        row_init(&ra, (char *)cur->row, GS_MAX_ROW_SIZE, INDEX_REBUILD_COLS);
        (void)row_put_int32(&ra, (int32)(item.uid));             // UID
        (void)row_put_int32(&ra, (int32)(item.oid));             // TABLE_ID
        (void)row_put_str(&ra, get_alter_index_type(item.type)); // ALTER_INDEX_TYPE
        (void)row_put_str(&ra, item.name);                       // index name
        if (item.type == ALINDEX_TYPE_REBUILD_PART || item.type == ALINDEX_TYPE_REBUILD_SUBPART) {
            (void)row_put_str(&ra, item.part_name); // index part name
        } else {
            (void)row_put_null(&ra);
        }
        (void)row_put_str(&ra, get_arebuild_state(item.state)); // STATE
        (void)row_put_int64(&ra, (int64)(item.scn));            // SCN

        cm_decode_row((char *)cur->row, cur->offsets, cur->lens, &cur->data_size);
        cur->rowid.vmid++;
        return GS_SUCCESS;
    }
}

static status_t vw_index_rebuild_fetch(knl_handle_t session, knl_cursor_t *cur)
{
    return vw_fetch_for_tenant(vw_index_rebuild_fetch_core, session, cur);
}

static status_t vw_paral_replay_stat_fetch(knl_handle_t session, knl_cursor_t *cur)
{
    knl_session_t *se = (knl_session_t *)session;
    knl_instance_t *kernel = se->kernel;
    rcy_context_t *rcy = &kernel->rcy_ctx;
    rcy_bucket_t *bucket = NULL;

    uint64 id;
    row_assist_t ra;

    if (!rcy->paral_rcy) {
        cur->eof = GS_TRUE;
        return GS_SUCCESS;
    }

    id = cur->rowid.vmid;
    if (id > rcy->capacity) {
        cur->eof = GS_TRUE;
        return GS_SUCCESS;
    }

    while (cur->rowid.vmid < rcy->capacity) {
        bucket = &rcy->bucket[cur->rowid.vmid];
        if (bucket == NULL || bucket->session == NULL) {
            cur->rowid.vmid++;
            continue;
        }

        row_init(&ra, (char *)cur->row, GS_MAX_ROW_SIZE, PARAL_REPALY_STAT_COLS);
        GS_RETURN_IFERR(row_put_uint32(&ra, (uint32)bucket->rcy_stat.session_id));
        GS_RETURN_IFERR(row_put_int64(&ra, (int64)bucket->rcy_stat.rcy_read_disk_page_num));
        GS_RETURN_IFERR(row_put_int64(&ra, (int64)bucket->rcy_stat.rcy_read_disk_total_time));
        GS_RETURN_IFERR(row_put_int64(&ra, (int64)bucket->rcy_stat.rcy_read_disk_avg_time));
        GS_RETURN_IFERR(row_put_int64(&ra, (int64)bucket->rcy_stat.session_work_time));
        GS_RETURN_IFERR(row_put_int64(&ra, (int64)bucket->rcy_stat.session_used_time));
        GS_RETURN_IFERR(row_put_uint32(&ra, (uint32)bucket->rcy_stat.session_util_rate));
        GS_RETURN_IFERR(row_put_int64(&ra, (int64)bucket->rcy_stat.sleep_time_in_log_add_bucket));
        GS_RETURN_IFERR(row_put_int64(&ra, (int64)bucket->rcy_stat.session_replay_log_group_count));

        cm_decode_row((char *)cur->row, cur->offsets, cur->lens, &cur->data_size);

        cur->rowid.vmid++;
        return GS_SUCCESS;
    }
    if (cur->rowid.vmid == rcy->capacity) {
        cur->eof = GS_TRUE;
    }
    return GS_SUCCESS;
}

static status_t vw_redo_stat_fetch(knl_handle_t session, knl_cursor_t *cur)
{
    rc_redo_stat_t *redo_stat = &g_rc_ctx->redo_stat;
    page_id_t page_id;
    status_t ret = GS_SUCCESS;
    row_assist_t ra;
    uint64 id;
    id = cur->rowid.vmid;
    if (id > redo_stat->redo_stat_cnt) {
        cur->eof = GS_TRUE;
        return GS_SUCCESS;
    }

    row_init(&ra, (char *)cur->row, GS_MAX_ROW_SIZE, REDO_STAT_COLS);
    cm_spin_lock(&redo_stat->lock, NULL);
    rc_redo_stat_list_t *stat_list = &redo_stat->stat_list[id];
    (void)row_put_int32(&ra, (int32)id);
    (void)row_put_int64(&ra, (int64)stat_list->time_interval);
    (void)row_put_int64(&ra, (int64)stat_list->redo_generate_size);
    (void)row_put_int64(&ra, (int64)stat_list->redo_recycle_size);
    (void)row_put_real(&ra, stat_list->redo_generate_speed);
    (void)row_put_real(&ra, stat_list->redo_recycle_speed);
    (void)row_put_int64(&ra, (int64)stat_list->redo_recovery_size);

    char ckpt_queue_first[GS_NAME_BUFFER_SIZE];
    ret = memset_sp(ckpt_queue_first, GS_NAME_BUFFER_SIZE, 0, GS_NAME_BUFFER_SIZE);
    knl_securec_check_ss(ret);
    page_id = stat_list->ckpt_queue_first_page;
    ret =
        snprintf_s(ckpt_queue_first, GS_NAME_BUFFER_SIZE, GS_NAME_BUFFER_SIZE - 1, "%u-%u", page_id.file, page_id.page);
    knl_securec_check_ss(ret);
    (void)row_put_str(&ra, ckpt_queue_first);

    (void)row_put_date(&ra, stat_list->end_time);
    uint32 redo_stat_last_update_ind = 0;
    if (redo_stat->redo_stat_cnt > 1 && redo_stat->redo_stat_cnt < CKPT_LOG_REDO_STAT_COUNT) {
        redo_stat_last_update_ind = redo_stat->redo_stat_cnt - 1;
    } else if (redo_stat->redo_stat_cnt == CKPT_LOG_REDO_STAT_COUNT) {
        redo_stat_last_update_ind = redo_stat->redo_stat_start_ind == 0 ? redo_stat->redo_stat_cnt - 1 :
                                    (redo_stat->redo_stat_start_ind - 1) % CKPT_LOG_REDO_STAT_COUNT;
    }
    (void)row_put_int32(&ra, redo_stat_last_update_ind);
    cm_spin_unlock(&redo_stat->lock);

    cm_decode_row((char *)cur->row, cur->offsets, cur->lens, &cur->data_size);
    cur->rowid.vmid++;

    if (cur->rowid.vmid > redo_stat->redo_stat_cnt) {
        cur->eof = GS_TRUE;
    }
    return GS_SUCCESS;
}

// one node view
VW_DECL dv_memstat = { "SYS", "DV_MEM_STATS", MEMSTAT_COLS, g_memstat_columns, vw_memstat_open, vw_memstat_fetch };
VW_DECL dv_io_stat_record = { "SYS",          "DV_IO_STAT_RECORD",    IO_STAT_RECORD_COLS, g_io_stat_record_columns,
                              vw_common_open, vw_io_stat_record_fetch };
VW_DECL dv_tse_io_stat_record = {
    "SYS", "DV_TSE_IO_STAT_RECORD", IO_STAT_RECORD_COLS, g_io_stat_record_columns, vw_common_open, vw_tse_io_fetch
};
VW_DECL dv_rfstat = { "SYS", "DV_REFORM_STATS", RFSTAT_COLS, g_rfstat_columns, vw_rfstat_open, vw_rfstat_fetch };
VW_DECL dv_rfdetail = {
    "SYS", "DV_REFORM_DETAIL", RFDETAIL_COLS, g_rfdetail_columns, vw_rfdetail_open, vw_rfdetail_fetch
};
VW_DECL dv_system_event = { "SYS",          "DV_SYS_EVENTS",      SYSTEM_EVENT_COLS, g_system_event_columns,
                            vw_common_open, vw_system_event_fetch };
VW_DECL dv_waitstat = {
    "SYS", "DV_WAIT_STATS", WAITSTAT_COLS, g_waitstat_columns, vw_waitstat_open, vw_waitstat_fetch
};
VW_DECL dv_segment_statistics = { "SYS",
                                  "DV_SEGMENT_STATS",
                                  SEGMENT_STATISTICS_COLS,
                                  g_segment_statistics_columns,
                                  vw_segment_statistics_open,
                                  vw_segment_statistics_fetch };
VW_DECL dv_undo_stat = {
    "SYS", "DV_UNDO_STATS", UNDO_STAT_COLS, g_undo_stat_columns, vw_undo_stat_open, vw_undo_stat_fetch
};
VW_DECL dv_index_coalesce = { "SYS",
                              "DV_INDEX_COALESCE",
                              INDEX_COALESCE_COLS,
                              g_index_coalesce_columns,
                              vw_index_coalesce_open,
                              vw_idx_coalesce_fetch };
VW_DECL dv_index_recycle = { "SYS",          "DV_INDEX_RECYCLE",    INDEX_RECYCLE_COLS, g_index_recycle_columns,
                             vw_common_open, vw_idx_recycle_fetch };
VW_DECL dv_index_rebuild = { "SYS",          "DV_INDEX_REBUILD",    INDEX_REBUILD_COLS, g_index_rebuild_columns,
                             vw_common_open, vw_index_rebuild_fetch };
VW_DECL dv_paral_replay_stat = {
    "SYS",          "DV_PARAL_REPLAY_STATS",   PARAL_REPALY_STAT_COLS, g_paral_replay_stat_columns,
    vw_common_open, vw_paral_replay_stat_fetch
};
VW_DECL dv_syncpoint_stat = { "SYS",
                              "DV_SYNCPOINT_STATS",
                              SYNCPOINT_STAT_COLS,
                              g_syncpoint_stat_columns,
                              vw_syncpoint_stat_open,
                              vw_syncpoint_stat_fetch };
VW_DECL dv_redo_stat = {
    "SYS", "DV_REDO_STATS", REDO_STAT_COLS, g_redo_stat_columns, vw_common_open, vw_redo_stat_fetch
};
// multi node view
VW_DECL dv_latch = { "SYS", "DV_LATCHS", LATCH_COLS, g_latch_columns, vw_latch_open, vw_latch_fetch };

dynview_desc_t *vw_describe_stat(uint32 id)
{
    switch ((dynview_id_t)id) {
        case DYN_VIEW_MEMSTAT:
            return &dv_memstat;

        case DYN_VIEW_SYSTEM_EVENT:
            return &dv_system_event;

        case DYN_VIEW_SEGMENT_STATISTICS:
            return &dv_segment_statistics;

        case DYN_VIEW_WAITSTAT:
            return &dv_waitstat;

        case DYN_VIEW_LATCH:
            return &dv_latch;

        case DYN_VIEW_UNDO_STAT:
            return &dv_undo_stat;

        case DYN_VIEW_INDEX_COALESCE:
            return &dv_index_coalesce;

        case DYN_VIEW_INDEX_RECYCLE:
            return &dv_index_recycle;

        case DYN_VIEW_INDEX_REBUILD:
            return &dv_index_rebuild;

        case DYN_VIEW_IO_STAT_RECORD:
            return &dv_io_stat_record;

        case DYN_VIEW_TSE_IO_STAT_RECORD:
            return &dv_tse_io_stat_record;

        case DYN_VIEW_REFORM_STAT:
            return &dv_rfstat;

        case DYN_VIEW_REFORM_DETAIL:
            return &dv_rfdetail;

        case DYN_VIEW_PARAL_REPLAY_STAT:
            return &dv_paral_replay_stat;

        case DYN_VIEW_SYNCPOINT_STAT:
            return &dv_syncpoint_stat;

        case DYN_VIEW_REDO_STAT:
            return &dv_redo_stat;

        default:
            return NULL;
    }
}
