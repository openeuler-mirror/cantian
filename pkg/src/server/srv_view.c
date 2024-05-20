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
 * srv_view.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_view.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "cm_log.h"
#include "cm_system.h"
#include "repl_log_replay.h"
#include "knl_context.h"
#include "knl_mtrl.h"
#include "srv_view.h"
#include "srv_view_sga.h"
#include "srv_view_stat.h"
#include "srv_view_sess.h"
#include "srv_view_lock.h"
#include "srv_instance.h"
#include "dml_executor.h"
#include "knl_xa.h"
#include "ostat_load.h"
#include "srv_view_lock.h"
#include "cm_pbl.h"
#include "pl_lock.h"
#include "knl_space_base.h"
#include "knl_temp_space.h"
#include "dtc_database.h"
#include "dtc_dls.h"
#include "dtc_drc.h"
#include "dtc_view.h"
#include "srv_view_dtc_local.h"

#define MAX_OPEN_CURSOR_SQL_LENGTH 1024
#define MAX_STR_DISPLAY_LEN 8000
#define MAX_LAST_TABLE_NAME_LEN 512

static knl_column_t g_datafile_columns[] = {
    // log file columns
    { 0,  "ID",               0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 1,  "TABLESPACE_ID",    0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 2,  "STATUS",           0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN,    0, 0, CT_FALSE, 0, { 0 } },
    { 3,  "TYPE",             0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN,    0, 0, CT_FALSE, 0, { 0 } },
    { 4,  "FILE_NAME",        0, 0, CT_TYPE_VARCHAR, CT_FILE_NAME_BUFFER_SIZE, 0, 0, CT_FALSE, 0, { 0 } },
    { 5,  "BYTES",            0, 0, CT_TYPE_BIGINT,  sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 6,  "AUTO_EXTEND",      0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN,    0, 0, CT_FALSE, 0, { 0 } },
    { 7,  "AUTO_EXTEND_SIZE", 0, 0, CT_TYPE_BIGINT,  sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 8,  "MAX_SIZE",         0, 0, CT_TYPE_BIGINT,  sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 9,  "HIGH_WATER_MARK",  0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 10, "ALLOC_SIZE",       0, 0, CT_TYPE_BIGINT,  sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 11, "COMPRESSION",      0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN,    0, 0, CT_FALSE, 0, { 0 } },
    { 12, "PUNCHED",          0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN,    0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_logfile_columns[] = {
    // log file columns
    { 0, "INSTANCE", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "ID", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "STATUS", 0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 3, "TYPE", 0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 4, "FILE_NAME", 0, 0, CT_TYPE_VARCHAR, CT_FILE_NAME_BUFFER_SIZE, 0, 0, CT_FALSE, 0, { 0 } },
    { 5, "BYTES", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 6, "WRITE_POS", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 7, "FREE_SIZE", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 8, "RESET_ID", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 9, "ASN", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 10, "BLOCK_SIZE", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 11, "CURRENT_POINT", 0, 0, CT_TYPE_VARCHAR, CT_MAX_NUMBER_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 12, "ARCH_POS", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_library_cache[] = {
    // librarycache file columns
    { 0, "NAMESPACE",    0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "GETS",         0, 0, CT_TYPE_BIGINT,  sizeof(uint64),        0, 0, CT_FALSE, 0, { 0 } },
    { 2, "GETHITS",      0, 0, CT_TYPE_BIGINT,  sizeof(uint64),        0, 0, CT_FALSE, 0, { 0 } },
    { 3, "PINS",         0, 0, CT_TYPE_BIGINT,  sizeof(uint64),        0, 0, CT_FALSE, 0, { 0 } },
    { 4, "PINHITS",      0, 0, CT_TYPE_BIGINT,  sizeof(uint64),        0, 0, CT_FALSE, 0, { 0 } },
    { 5, "RELOADS",      0, 0, CT_TYPE_BIGINT,  sizeof(uint64),        0, 0, CT_FALSE, 0, { 0 } },
    { 6, "INVLIDATIONS", 0, 0, CT_TYPE_BIGINT,  sizeof(uint64),        0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_buffer_pool_columns[] = {
    // buffer columns
    { 0, "ID",           0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 1, "NAME",         0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "PAGE_SIZE",    0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 3, "CURRENT_SIZE", 0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 4, "BUFFERS",      0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 5, "FREE",         0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_buffer_pool_statistics_columns[] = {
    { 0,  "ID",                 0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 1,  "NAME",               0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 2,  "SET_MSIZE",          0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 3,  "CNUM_REPL",          0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 4,  "CNUM_WRITE",         0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 5,  "CNUM_FREE",          0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 6,  "CNUM_PINNED",        0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 7,  "CNUM_RO",            0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 8,  "OLD_LEN",            0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 9,  "STATS_LEN",          0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 10, "RECYCLED",           0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 11, "WRITE_LEN",          0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 12, "RECYCLE_GROUP",      0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 13, "COLD_DIRTY_GROUP",   0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 14, "TOTAL_GROUP",        0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 15, "LOCAL_MASTER",       0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 16, "REMOTE_MASTER",      0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_buffer_page_statistics_columns[] = {
    { 0,  "POOL_ID",      0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 1,  "TYPE",         0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 2,  "CNUM_TOTAL",   0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 3,  "CNUM_CLEAN",   0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 4,  "CNUM_DIRTY",   0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_buffer_index_statistics_columns[] = {
    { 0,  "POOL_ID",  0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 1,  "BLEVEL",   0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 2,  "CNUM",     0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_parameter_columns[] = {
    { 0, "NAME",          0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,        0, 0, CT_FALSE, 0, { 0 } },
    { 1, "VALUE",         0, 0, CT_TYPE_VARCHAR, CT_MAX_UDFLT_VALUE_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "RUNTIME_VALUE", 0, 0, CT_TYPE_VARCHAR, CT_MAX_UDFLT_VALUE_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 3, "DEFAULT_VALUE", 0, 0, CT_TYPE_VARCHAR, CT_MAX_UDFLT_VALUE_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 4, "ISDEFAULT",     0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN,  0, 0, CT_FALSE, 0, { 0 } },
    { 5, "MODIFIABLE",    0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN,  0, 0, CT_FALSE, 0, { 0 } },
    { 6, "DESCRIPTION",   0, 0, CT_TYPE_VARCHAR, CT_MAX_UDFLT_VALUE_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 7, "RANGE",         0, 0, CT_TYPE_VARCHAR, CT_MAX_UDFLT_VALUE_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 8, "DATATYPE",      0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN,  0, 0, CT_FALSE, 0, { 0 } },
    { 9, "EFFECTIVE",     0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN,  0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_debug_parameter_columns[] = {
    { 0, "NAME",          0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,        0, 0, CT_FALSE, 0, { 0 } },
    { 1, "DEFAULT_VALUE", 0, 0, CT_TYPE_VARCHAR, CT_MAX_UDFLT_VALUE_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "CURRENT_VALUE", 0, 0, CT_TYPE_VARCHAR, CT_MAX_UDFLT_VALUE_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 3, "RANGE",         0, 0, CT_TYPE_VARCHAR, CT_MAX_UDFLT_VALUE_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 4, "DATATYPE",      0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN,  0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_db_object_cache[] = {
    { 0, "OWNER",      0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,       0, 0, CT_FALSE, 0, { 0 } },
    { 1, "NAME",       0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,       0, 0, CT_FALSE, 0, { 0 } },
    { 2, "NAMESPACE",  0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 3, "TYPE",       0, 0, CT_TYPE_VARCHAR, 32,                    0, 0, CT_FALSE, 0, { 0 } },
    { 4, "LOADS",      0, 0, CT_TYPE_BOOLEAN, 1,                     0, 0, CT_FALSE, 0, { 0 } },
    { 5, "LOCKS",      0, 0, CT_TYPE_INTEGER, sizeof(uint32),        0, 0, CT_FALSE, 0, { 0 } },
    { 6, "HASH_VALUE", 0, 0, CT_TYPE_INTEGER, sizeof(uint32),        0, 0, CT_FALSE, 0, { 0 } },
    { 7, "LOCK_MODE",  0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 8, "STATUS",     0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN, 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_backup_process_stats[] = {
    { 0, "PROC_ID",         0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "READ_SIZE",       0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "READ_TIME",       0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 3, "READ_SPEED",      0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 4, "ENCODE_TIME",     0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 5, "ENCODE_SPEED",    0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 6, "WRITE_SIZE",      0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 7, "WRITE_TIME",      0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 8, "WRITE_SPEED",     0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_tablespaces_columns[] = {
    { 0, "ID",            0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 1, "NAME",          0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "TEMPORARY",     0, 0, CT_TYPE_VARCHAR, 8,               0, 0, CT_FALSE, 0, { 0 } },
    { 3, "IN_MEMORY",     0, 0, CT_TYPE_VARCHAR, 8,               0, 0, CT_FALSE, 0, { 0 } },
    { 4, "AUTO_PURGE",    0, 0, CT_TYPE_VARCHAR, 8,               0, 0, CT_FALSE, 0, { 0 } },
    { 5, "EXTENT_SIZE",   0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 6, "SEGMENT_COUNT", 0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 7, "FILE_COUNT",    0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 8, "STATUS",        0, 0, CT_TYPE_VARCHAR, 8,               0, 0, CT_FALSE, 0, { 0 } },
    { 9, "AUTO_OFFLINE",  0, 0, CT_TYPE_VARCHAR, 8,               0, 0, CT_FALSE, 0, { 0 } },
    { 10, "EXTENT_MANAGEMENT", 0, 0, CT_TYPE_VARCHAR, 8,          0, 0, CT_FALSE, 0, { 0 } },
    { 11, "EXTENT_ALLOCATION", 0, 0, CT_TYPE_VARCHAR, 8,          0, 0, CT_FALSE, 0, { 0 } },
    { 12, "ENCRYPT",           0, 0, CT_TYPE_VARCHAR, 8,          0, 0, CT_FALSE, 0, { 0 } },
    { 13, "PUNCHED_SIZE", 0, 0, CT_TYPE_BIGINT,  sizeof(uint64),  0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_archived_log_columns[] = {
    { 0,  "RECID",                 0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 1,  "STAMP",                 0, 0, CT_TYPE_DATE,    sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 2,  "NAME",                  0, 0, CT_TYPE_VARCHAR, CT_FILE_NAME_BUFFER_SIZE, 0, 0, CT_FALSE, 0, { 0 } },
    { 3,  "DEST_ID",               0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 4,  "THREAD#",               0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 5,  "SEQUENCE#",             0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 6,  "RESETLOGS_CHANGE#",     0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 7,  "RESETLOGS_TIME",        0, 0, CT_TYPE_DATE,    sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 8,  "RESETLOGS_ID",          0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 9,  "FIRST_CHANGE#",         0, 0, CT_TYPE_BIGINT,  sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 10, "FIRST_TIME",            0, 0, CT_TYPE_DATE,    sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 11, "NEXT_CHANGE#",          0, 0, CT_TYPE_BIGINT,  sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 12, "NEXT_TIME",             0, 0, CT_TYPE_DATE,    sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 13, "BLOCKS",                0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 14, "BLOCK_SIZE",            0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 15, "CREATOR",               0, 0, CT_TYPE_VARCHAR, 8,                        0, 0, CT_FALSE, 0, { 0 } },
    { 16, "REGISTRAR",             0, 0, CT_TYPE_VARCHAR, 8,                        0, 0, CT_FALSE, 0, { 0 } },
    { 17, "STANDBY_DEST",          0, 0, CT_TYPE_VARCHAR, 4,                        0, 0, CT_FALSE, 0, { 0 } },
    { 18, "ARCHIVED",              0, 0, CT_TYPE_VARCHAR, 4,                        0, 0, CT_FALSE, 0, { 0 } },
    { 19, "APPLIED",               0, 0, CT_TYPE_VARCHAR, 4,                        0, 0, CT_FALSE, 0, { 0 } },
    { 20, "DELETED",               0, 0, CT_TYPE_VARCHAR, 4,                        0, 0, CT_FALSE, 0, { 0 } },
    { 21, "STATUS",                0, 0, CT_TYPE_VARCHAR, 4,                        0, 0, CT_FALSE, 0, { 0 } },
    { 22, "COMPLETION_TIME",       0, 0, CT_TYPE_DATE,    sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 23, "DICTIONARY_BEGIN",      0, 0, CT_TYPE_VARCHAR, 4,                        0, 0, CT_FALSE, 0, { 0 } },
    { 24, "DICTIONARY_END",        0, 0, CT_TYPE_VARCHAR, 4,                        0, 0, CT_FALSE, 0, { 0 } },
    { 25, "END_OF_REDO",           0, 0, CT_TYPE_VARCHAR, 4,                        0, 0, CT_FALSE, 0, { 0 } },
    { 26, "BACKUP_COUNT",          0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 27, "ARCHIVAL_THREAD#",      0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 28, "ACTIVATION#",           0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 29, "IS_RECOVERY_DEST_FILE", 0, 0, CT_TYPE_VARCHAR, 4,                        0, 0, CT_FALSE, 0, { 0 } },
    { 30, "COMPRESSED",            0, 0, CT_TYPE_VARCHAR, 4,                        0, 0, CT_FALSE, 0, { 0 } },
    { 31, "FAL",                   0, 0, CT_TYPE_VARCHAR, 4,                        0, 0, CT_FALSE, 0, { 0 } },
    { 32, "END_OF_REDO_TYPE",      0, 0, CT_TYPE_VARCHAR, 10,                       0, 0, CT_FALSE, 0, { 0 } },
    { 33, "BACKED_BY_VSS",         0, 0, CT_TYPE_VARCHAR, 4,                        0, 0, CT_FALSE, 0, { 0 } },
    { 34, "CON_ID",                0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 35, "REAL_SIZE",             0, 0, CT_TYPE_BIGINT,  sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 36, "FIRST_LSN",             0, 0, CT_TYPE_DATE,    sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 37, "LAST_LSN",              0, 0, CT_TYPE_INTEGER, sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_temp_archived_log_columns[] = {
    { 0,  "FILE_PATH",                 0, 0, CT_TYPE_VARCHAR, 256,           0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_archive_gap_columns[] = {
    { 0, "THREAD#",        0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "LOW_SEQUENCE#",  0, 0, CT_TYPE_VARCHAR, 32,             0, 0, CT_FALSE, 0, { 0 } },
    { 2, "HIGH_SEQUENCE#", 0, 0, CT_TYPE_VARCHAR, 32,             0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_archive_process_columns[] = {
    { 0, "PROCESS",      0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "STATUS",       0, 0, CT_TYPE_VARCHAR, 10,             0, 0, CT_FALSE, 0, { 0 } },
    { 2, "LOG_SEQUENCE", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 3, "STATE",        0, 0, CT_TYPE_VARCHAR, 4,              0, 0, CT_FALSE, 0, { 0 } },
    { 4, "ROLES",        0, 0, CT_TYPE_VARCHAR, 36,             0, 0, CT_FALSE, 0, { 0 } },
    { 5, "CON_ID",       0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_archive_status_columns[] = {
    { 0, "DEST_ID",                0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 1, "DEST_NAME",              0, 0, CT_TYPE_VARCHAR, CT_FILE_NAME_BUFFER_SIZE, 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "STATUS",                 0, 0, CT_TYPE_VARCHAR, 9,                        0, 0, CT_FALSE, 0, { 0 } },
    { 3, "TYPE",                   0, 0, CT_TYPE_VARCHAR, 30,                       0, 0, CT_FALSE, 0, { 0 } },
    { 4, "DATABASE_MODE",          0, 0, CT_TYPE_VARCHAR, 11,                       0, 0, CT_FALSE, 0, { 0 } },
    { 5, "PROTECTION_MODE",        0, 0, CT_TYPE_VARCHAR, 20,                       0, 0, CT_FALSE, 0, { 0 } },
    { 6, "DESTINATION",            0, 0, CT_TYPE_VARCHAR, CT_FILE_NAME_BUFFER_SIZE, 0, 0, CT_FALSE, 0, { 0 } },
    { 7, "DB_UNIQUE_NAME",         0, 0, CT_TYPE_VARCHAR, 30,                       0, 0, CT_FALSE, 0, { 0 } },
    { 8, "SYNCHRONIZATION_STATUS", 0, 0, CT_TYPE_VARCHAR, 20,                       0, 0, CT_FALSE, 0, { 0 } },
    { 9, "SYNCHRONIZED",           0, 0, CT_TYPE_VARCHAR, 8,                        0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_database_columns[] = {
    { 0,  "DBID",               0, 0, CT_TYPE_INTEGER, sizeof(uint32),         0, 0, CT_FALSE, 0, { 0 } },
    { 1,  "NAME",               0, 0, CT_TYPE_VARCHAR, CT_DB_NAME_LEN,         0, 0, CT_FALSE, 0, { 0 } },
    { 2,  "STATUS",             0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN,  0, 0, CT_FALSE, 0, { 0 } },
    { 3,  "OPEN_STATUS",        0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN,  0, 0, CT_FALSE, 0, { 0 } },
    { 4,  "OPEN_COUNT",         0, 0, CT_TYPE_INTEGER, sizeof(uint32),         0, 0, CT_FALSE, 0, { 0 } },
    { 5,  "INIT_TIME",          0, 0, CT_TYPE_DATE,    sizeof(date_t),         0, 0, CT_FALSE, 0, { 0 } },
    { 6,  "CURRENT_SCN",        0, 0, CT_TYPE_BIGINT,  sizeof(uint64),         0, 0, CT_FALSE, 0, { 0 } },
    { 7,  "RCY_POINT",          0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN,  0, 0, CT_FALSE, 0, { 0 } },
    { 8,  "LRP_POINT",          0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN,  0, 0, CT_FALSE, 0, { 0 } },
    { 9,  "CKPT_ID",            0, 0, CT_TYPE_BIGINT,  sizeof(uint64),         0, 0, CT_FALSE, 0, { 0 } },
    { 10, "LSN",                0, 0, CT_TYPE_BIGINT,  sizeof(uint64),         0, 0, CT_FALSE, 0, { 0 } },
    { 11, "LFN",                0, 0, CT_TYPE_BIGINT,  sizeof(uint64),         0, 0, CT_FALSE, 0, { 0 } },
    { 12, "LOG_COUNT",          0, 0, CT_TYPE_INTEGER, sizeof(uint32),         0, 0, CT_FALSE, 0, { 0 } },
    { 13, "LOG_FIRST",          0, 0, CT_TYPE_INTEGER, sizeof(uint32),         0, 0, CT_FALSE, 0, { 0 } },
    { 14, "LOG_LAST",           0, 0, CT_TYPE_INTEGER, sizeof(uint32),         0, 0, CT_FALSE, 0, { 0 } },
    { 15, "LOG_FREE_SIZE",      0, 0, CT_TYPE_BIGINT,  sizeof(uint64),         0, 0, CT_FALSE, 0, { 0 } },
    { 16, "LOG_MODE",           0, 0, CT_TYPE_VARCHAR, 30,                     0, 0, CT_FALSE, 0, { 0 } },
    { 17, "SPACE_COUNT",        0, 0, CT_TYPE_INTEGER, sizeof(uint32),         0, 0, CT_FALSE, 0, { 0 } },
    { 18, "DEVICE_COUNT",       0, 0, CT_TYPE_INTEGER, sizeof(uint32),         0, 0, CT_FALSE, 0, { 0 } },
    { 19, "DW_START",           0, 0, CT_TYPE_INTEGER, sizeof(uint32),         0, 0, CT_FALSE, 0, { 0 } },
    { 20, "DW_END",             0, 0, CT_TYPE_INTEGER, sizeof(uint32),         0, 0, CT_FALSE, 0, { 0 } },
    { 21, "PROTECTION_MODE",    0, 0, CT_TYPE_STRING,  CT_DYNVIEW_NORMAL_LEN,  0, 0, CT_FALSE, 0, { 0 } },
    { 22, "DATABASE_ROLE",      0, 0, CT_TYPE_STRING,  30,                     0, 0, CT_FALSE, 0, { 0 } },
    { 23, "DATABASE_CONDITION", 0, 0, CT_TYPE_STRING,  16,                     0, 0, CT_FALSE, 0, { 0 } },
    { 24, "SWITCHOVER_STATUS",  0, 0, CT_TYPE_STRING,  CT_DYNVIEW_NORMAL_LEN,  0, 0, CT_FALSE, 0, { 0 } },
    { 25, "FAILOVER_STATUS",    0, 0, CT_TYPE_STRING,  CT_DYNVIEW_NORMAL_LEN,  0, 0, CT_FALSE, 0, { 0 } },
    { 26, "ARCHIVELOG_CHANGE",  0, 0, CT_TYPE_INTEGER, sizeof(uint32),         0, 0, CT_FALSE, 0, { 0 } },
    { 27, "LREP_POINT",         0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN,  0, 0, CT_FALSE, 0, { 0 } },
    { 28, "LREP_MODE",          0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN,  0, 0, CT_FALSE, 0, { 0 } },
    { 29, "OPEN_INCONSISTENCY", 0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN,  0, 0, CT_FALSE, 0, { 0 } },
    { 30, "CHARACTER_SET",      0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN,  0, 0, CT_FALSE, 0, { 0 } },
    { 31, "COMMIT_SCN",         0, 0, CT_TYPE_BIGINT,  sizeof(uint64),         0, 0, CT_TRUE,  0, { 0 } },
    { 32, "NEED_REPAIR_REASON", 0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN,  0, 0, CT_FALSE, 0, { 0 } },
    { 33, "READONLY_REASON",    0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN,  0, 0, CT_FALSE, 0, { 0 } },
    { 34, "BIN_SYS_VERSION",    0, 0, CT_TYPE_INTEGER, sizeof(uint32),         0, 0, CT_FALSE, 0, { 0 } },
    { 35, "DATA_SYS_VERSION",   0, 0, CT_TYPE_INTEGER, sizeof(uint32),         0, 0, CT_FALSE, 0, { 0 } },
    { 36, "RESETLOG",           0, 0, CT_TYPE_VARCHAR, CT_MAX_NUMBER_LEN,      0, 0, CT_FALSE, 0, { 0 } },
    { 37, "MIN_SCN",            0, 0, CT_TYPE_BIGINT,  sizeof(uint64),         0, 0, CT_FALSE, 0, { 0 } },
    { 38, "ARCHIVELOG_SIZE",    0, 0, CT_TYPE_BIGINT,  sizeof(uint64),         0, 0, CT_FALSE, 0, { 0 } },
    { 39, "DDL_EXEC_STATUS",    0, 0, CT_TYPE_STRING,  CT_DYNVIEW_DDL_STA_LEN, 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_repl_status_columns[] = {
    { 0, "DATABASE_ROLE",      0, 0, CT_TYPE_STRING, 30, 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "DATABASE_CONDITION", 0, 0, CT_TYPE_STRING, 16, 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "SWITCHOVER_STATUS",  0, 0, CT_TYPE_STRING, 20, 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_managed_standby_columns[] = {
    { 0, "PROCESS",            0, 0, CT_TYPE_STRING,  CT_DYNVIEW_NORMAL_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "STATUS",             0, 0, CT_TYPE_STRING,  CT_DYNVIEW_NORMAL_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "RESETLOG_ID",        0, 0, CT_TYPE_INTEGER, sizeof(uint32),        0, 0, CT_FALSE, 0, { 0 } },
    { 3, "THREAD#",            0, 0, CT_TYPE_STRING,  CT_DYNVIEW_NORMAL_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 4, "SEQUENCE#",          0, 0, CT_TYPE_INTEGER, sizeof(uint32),        0, 0, CT_FALSE, 0, { 0 } },
    { 5, "FLUSH_POINT",        0, 0, CT_TYPE_VARCHAR, CT_MAX_NUMBER_LEN,     0, 0, CT_FALSE, 0, { 0 } },
    { 6, "PRIMARY_CURR_POINT", 0, 0, CT_TYPE_VARCHAR, CT_MAX_NUMBER_LEN,     0, 0, CT_FALSE, 0, { 0 } },
    { 7, "REPLAY_POINT",       0, 0, CT_TYPE_VARCHAR, CT_MAX_NUMBER_LEN,     0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_ha_sync_info_columns[] = {
    { 0,  "THREAD#",          0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 1,  "STATUS",           0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN,    0, 0, CT_FALSE, 0, { 0 } },
    { 2,  "LOCAL_HOST",       0, 0, CT_TYPE_VARCHAR, CT_HOST_NAME_BUFFER_SIZE, 0, 0, CT_FALSE, 0, { 0 } },
    { 3,  "ROLE_VALID",       0, 0, CT_TYPE_VARCHAR, CT_MAX_ROLE_VALID_LEN,    0, 0, CT_FALSE, 0, { 0 } },
    { 4,  "NET_MODE",         0, 0, CT_TYPE_VARCHAR, CT_MAX_NET_MODE_LEN,      0, 0, CT_FALSE, 0, { 0 } },
    { 5,  "PEER_HOST",        0, 0, CT_TYPE_VARCHAR, CT_HOST_NAME_BUFFER_SIZE, 0, 0, CT_FALSE, 0, { 0 } },
    { 6,  "PEER_PORT",        0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 7,  "LOCAL_SEND_POINT", 0, 0, CT_TYPE_VARCHAR, CT_MAX_NUMBER_LEN,        0, 0, CT_FALSE, 0, { 0 } },
    { 8,  "PEER_FLUSH_POINT", 0, 0, CT_TYPE_VARCHAR, CT_MAX_NUMBER_LEN,        0, 0, CT_FALSE, 0, { 0 } },
    { 9,  "PEER_CONTFLUSH_POINT", 0, 0, CT_TYPE_VARCHAR, CT_MAX_NUMBER_LEN,    0, 0, CT_FALSE, 0, { 0 } },
    { 10, "PEER_BUILDING",    0, 0, CT_TYPE_VARCHAR, CT_MAX_PEER_BUILDING_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 11, "LOCAL_LFN",        0, 0, CT_TYPE_BIGINT,  sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 12, "LOCAL_LSN",        0, 0, CT_TYPE_BIGINT,  sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 13, "PEER_LFN",         0, 0, CT_TYPE_BIGINT,  sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 14, "PEER_LSN",         0, 0, CT_TYPE_BIGINT,  sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 15, "FLUSH_LAG",        0, 0, CT_TYPE_BIGINT,  sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 16, "REPLAY_LAG",       0, 0, CT_TYPE_BIGINT,  sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 17, "BUILD_TYPE",       0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN,    0, 0, CT_FALSE, 0, { 0 } },
    { 18, "BUILD_PROGRESS",   0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 19, "BUILD_STAGE",      0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN,    0, 0, CT_FALSE, 0, { 0 } },
    { 20, "BUILD_SYNCED_STAGE_SIZE", 0, 0, CT_TYPE_BIGINT, sizeof(uint64),     0, 0, CT_FALSE, 0, { 0 } },
    { 21, "BUILD_TOTAL_STAGE_SIZE",  0, 0, CT_TYPE_BIGINT, sizeof(uint64),     0, 0, CT_FALSE, 0, { 0 } },
    { 22, "BUILD_TIME",       0, 0, CT_TYPE_BIGINT, sizeof(uint64),            0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_me_columns[] = {
    { 0, "SID",         0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 1, "USER_NAME",   0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,          0, 0, CT_FALSE, 0, { 0 } },
    { 2, "USER_ID",     0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 3, "CURR_SCHEMA", 0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,          0, 0, CT_FALSE, 0, { 0 } },
    { 4, "SPID",        0, 0, CT_TYPE_VARCHAR, CT_MAX_UINT32_STRLEN + 1, 0, 0, CT_FALSE, 0, { 0 } },
    { 5, "OS_PROG",     0, 0, CT_TYPE_VARCHAR, CT_FILE_NAME_BUFFER_SIZE, 0, 0, CT_FALSE, 0, { 0 } },
    { 6, "OS_HOST",     0, 0, CT_TYPE_VARCHAR, CT_HOST_NAME_BUFFER_SIZE, 0, 0, CT_FALSE, 0, { 0 } },
    { 7, "OS_USER",     0, 0, CT_TYPE_VARCHAR, CT_NAME_BUFFER_SIZE,      0, 0, CT_FALSE, 0, { 0 } },
    { 8, "CLIENT_IP",   0, 0, CT_TYPE_VARCHAR, CM_MAX_IP_LEN,            0, 0, CT_TRUE,  0, { 0 } },
    { 9, "CLIENT_PORT", 0, 0, CT_TYPE_VARCHAR, CT_MAX_INT32_STRLEN,      0, 0, CT_TRUE,  0, { 0 } },
};

static knl_column_t g_dynamic_view_columns[] = {
    { 0, "USER_NAME", 0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "NAME", 0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "ID", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 3, "COLUMN_COUNT", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_dynamic_view_column_cols[] = {
    { 0, "USER_NAME",      0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "VIEW_NAME",      0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "COLUMN_ID",      0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 3, "COLUMN_NAME",    0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 4, "DATA_TYPE",      0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 5, "DATA_LENGTH",    0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 6, "DATA_PRECISION", 0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_TRUE,  0, { 0 } },
    { 7, "DATA_SCALE",     0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_TRUE,  0, { 0 } },
};

static knl_column_t g_version_columns[] = {
    { 0, "VERSION", 0, 0, CT_TYPE_VARCHAR, 80, 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_transaction_columns[] = {
    { 0, "SEG_ID",      0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 1, "SLOT",        0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 2, "XNUM",        0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 3, "SCN",         0, 0, CT_TYPE_BIGINT,  sizeof(uint64),  0, 0, CT_FALSE, 0, { 0 } },
    { 4, "SID",         0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 5, "STATUS",      0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 6, "UNDO_COUNT",  0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 7, "UNDO_FIRST",  0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 8, "UNDO_LAST",   0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 9, "BEGIN_TIME",  0, 0, CT_TYPE_DATE,    sizeof(date_t),  0, 0, CT_FALSE, 0, { 0 } },
    { 10, "TXN_PAGEID", 0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 11, "RMID",       0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 12, "REMAINED",   0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 13, "EXEC_TIME",  0, 0, CT_TYPE_BIGINT,  sizeof(uint64),  0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_all_transaction_columns[] = {
    { 0, "SEG_ID",     0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 1, "SLOT",       0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 2, "XNUM",       0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 3, "SCN",        0, 0, CT_TYPE_BIGINT,  sizeof(uint64),  0, 0, CT_FALSE, 0, { 0 } },
    { 4, "SID",        0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 5, "STATUS",     0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 6, "UNDO_COUNT", 0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 7, "UNDO_FIRST", 0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 8, "UNDO_LAST",  0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 9, "TXN_PAGEID", 0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 10, "RMID",      0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 11, "REMAINED",  0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_resource_map_columns[] = {
    { 0, "RESOURCE#", 0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 1, "TYPE#",     0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 2, "NAME",      0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } }
};

static knl_column_t g_user_astatus_map_columns[] = {
    { 0, "STATUS#", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "STATUS", 0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_temp_undo_segment_columns[] = {
    { 0, "ID",             0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "SEG_ENTRY",      0, 0, CT_TYPE_BIGINT,  sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "TXN_PAGES",      0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 3, "UNDO_PAGES",     0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 4, "UNDO_FIRST",     0, 0, CT_TYPE_BIGINT,  sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 5, "UNDO_LAST",      0, 0, CT_TYPE_BIGINT,  sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 6, "FIRST_TIME",     0, 0, CT_TYPE_DATE,    sizeof(date_t), 0, 0, CT_TRUE,  0, { 0 } },
    { 7, "LAST_TIME",      0, 0, CT_TYPE_DATE,    sizeof(date_t), 0, 0, CT_TRUE,  0, { 0 } },
    { 8, "RETENTION_TIME", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 9, "OW_SCN",         0, 0, CT_TYPE_BIGINT,  sizeof(uint64), 0, 0, CT_TRUE,  0, { 0 } },
};

static knl_column_t g_undo_segment_columns[] = {
    { 0,  "ID",                 0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 1,  "SEG_ENTRY",          0, 0, CT_TYPE_BIGINT,  sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 2,  "SEG_STATUS",         0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN,    0, 0, CT_FALSE, 0, { 0 } },
    { 3,  "TXN_PAGES",          0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 4,  "TXN_FREE_ITEM_CNT",  0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 5,  "TXN_FIRST",          0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 6,  "TXN_LAST",           0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 7,  "UNDO_PAGES",         0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 8,  "UNDO_FIRST",         0, 0, CT_TYPE_BIGINT,  sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 9,  "UNDO_LAST",          0, 0, CT_TYPE_BIGINT,  sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 10, "FIRST_TIME",         0, 0, CT_TYPE_DATE,    sizeof(date_t),           0, 0, CT_TRUE,  0, { 0 } },
    { 11, "LAST_TIME",          0, 0, CT_TYPE_DATE,    sizeof(date_t),           0, 0, CT_TRUE,  0, { 0 } },
    { 12, "RETENTION_TIME",     0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 13, "OW_SCN",             0, 0, CT_TYPE_BIGINT,  sizeof(uint64),           0, 0, CT_TRUE,  0, { 0 } },
    { 14, "BEGIN_TIME",         0, 0, CT_TYPE_DATE,    sizeof(date_t),           0, 0, CT_FALSE, 0, { 0 } },
    { 15, "TXN_CNT",            0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 16, "REUSE_XP_PAGES",     0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 17, "REU_UNXP_PAGES",     0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 18, "USE_SPACE_PAGES",    0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 19, "STEAL_XP_PAGES",     0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 20, "STEAL_UNXP_PAGES",   0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 21, "STEALED_XP_PAGES",   0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 22, "STEALED_UNXP_PAGES", 0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 23, "BUF_BUSY_WAITS",     0, 0, CT_TYPE_INTEGER, sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_backup_process_columns[] = {
    { 0, "TYPE",           0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,        0, 0, CT_FALSE, 0, { 0 } },
    { 1, "PROGRESS",       0, 0, CT_TYPE_INTEGER, sizeof(uint32),         0, 0, CT_FALSE, 0, { 0 } },
    { 2, "STAGE",          0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,        0, 0, CT_FALSE, 0, { 0 } },
    { 3, "STATUS",         0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,        0, 0, CT_FALSE, 0, { 0 } },
    { 4, "ERR_NO",         0, 0, CT_TYPE_INTEGER, sizeof(uint32),         0, 0, CT_FALSE, 0, { 0 } },
    { 5, "ERR_MSG",        0, 0, CT_TYPE_VARCHAR, CT_MESSAGE_BUFFER_SIZE, 0, 0, CT_FALSE, 0, { 0 } },
    { 6, "TOTAL_PROC",     0, 0, CT_TYPE_INTEGER, sizeof(uint32),         0, 0, CT_FALSE, 0, { 0 } },
    { 7, "FREE_PROC",      0, 0, CT_TYPE_INTEGER, sizeof(uint32),         0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_instance_columns[] = {
    { 0, "INSTANCE_ID",    0, 0, CT_TYPE_INTEGER, sizeof(uint32),           0, 0, CT_FALSE, 0, { 0 } },
    { 1, "INSTANCE_NAME",  0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN,    0, 0, CT_FALSE, 0, { 0 } },
    { 2, "STATUS",         0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN,    0, 0, CT_FALSE, 0, { 0 } },
    { 3, "KERNEL_SCN",     0, 0, CT_TYPE_BIGINT,  sizeof(int64),            0, 0, CT_FALSE, 0, { 0 } },
    { 4, "SHUTDOWN_PHASE", 0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN,    0, 0, CT_FALSE, 0, { 0 } },
    { 5, "STARTUP_TIME",   0, 0, CT_TYPE_DATE,    sizeof(date_t),           0, 0, CT_FALSE, 0, { 0 } },
    { 6, "HOST_NAME",      0, 0, CT_TYPE_VARCHAR, CT_HOST_NAME_BUFFER_SIZE, 0, 0, CT_FALSE, 0, { 0 } },
    { 7, "PLATFORM_NAME",  0, 0, CT_TYPE_STRING,  CT_NAME_BUFFER_SIZE,      0, 0, CT_FALSE, 0, { 0 } },
    { 8, "CONNECT_STATUS", 0, 0, CT_TYPE_STRING,  CT_DYNVIEW_NORMAL_LEN,    0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_open_cursor_columns[] = {
    { 0,  "SESSION_ID",           0, 0, CT_TYPE_INTEGER, sizeof(uint32),       0, 0, CT_FALSE, 0, { 0 } },
    { 1,  "STMT_ID",              0, 0, CT_TYPE_INTEGER, sizeof(uint32),       0, 0, CT_FALSE, 0, { 0 } },
    { 2,  "USER_NAME",            0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,      0, 0, CT_FALSE, 0, { 0 } },
    { 3,  "SQL_TEXT",             0, 0, CT_TYPE_VARCHAR, 1024,                 0, 0, CT_TRUE, 0, { 0 } },
    { 4,  "SQL_TYPE",             0, 0, CT_TYPE_INTEGER, sizeof(uint32),       0, 0, CT_TRUE, 0, { 0 } },
    { 5,  "SQL_ID",               0, 0, CT_TYPE_VARCHAR, CT_MAX_UINT32_STRLEN, 0, 0, CT_TRUE, 0, { 0 } },
    { 6,  "STATUS",               0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,      0, 0, CT_FALSE, 0, { 0 } },
    { 7,  "CURSOR_TYPE",          0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,      0, 0, CT_FALSE, 0, { 0 } },
    { 8,  "VM_OPEN_PAGES",        0, 0, CT_TYPE_BIGINT,  sizeof(uint64),       0, 0, CT_FALSE, 0, { 0 } },
    { 9,  "VM_CLOSE_PAGES",       0, 0, CT_TYPE_BIGINT,  sizeof(uint64),       0, 0, CT_FALSE, 0, { 0 } },
    { 10, "VM_SWAPIN_PAGES",      0, 0, CT_TYPE_BIGINT,  sizeof(uint64),       0, 0, CT_FALSE, 0, { 0 } },
    { 11, "VM_FREE_PAGES",        0, 0, CT_TYPE_BIGINT,  sizeof(uint64),       0, 0, CT_FALSE, 0, { 0 } },
    { 12, "QUERY_SCN",            0, 0, CT_TYPE_BIGINT,  sizeof(uint64),       0, 0, CT_FALSE, 0, { 0 } },
    { 13, "LAST_SQL_ACTIVE_TIME", 0, 0, CT_TYPE_DATE,    sizeof(date_t),       0, 0, CT_TRUE, 0, { 0 } },
    { 14, "VM_ALLOC_PAGES",       0, 0, CT_TYPE_BIGINT,  sizeof(uint64),       0, 0, CT_FALSE, 0, { 0 } },
    { 15, "VM_MAX_OPEN_PAGES",    0, 0, CT_TYPE_BIGINT,  sizeof(uint64),       0, 0, CT_FALSE, 0, { 0 } },
    { 16, "VM_SWAPOUT_PAGES",     0, 0, CT_TYPE_BIGINT,  sizeof(uint64),       0, 0, CT_FALSE, 0, { 0 } },
    { 17, "ELAPSED_TIME",         0, 0, CT_TYPE_BIGINT,  sizeof(uint64),       0, 0, CT_TRUE, 0, { 0 } },
    { 18, "DISK_READS",           0, 0, CT_TYPE_BIGINT,  sizeof(uint64),       0, 0, CT_TRUE, 0, { 0 } },
    { 19, "IO_WAIT_TIME",         0, 0, CT_TYPE_BIGINT,  sizeof(uint64),       0, 0, CT_TRUE, 0, { 0 } },
    { 20, "BUFFER_GETS",          0, 0, CT_TYPE_BIGINT,  sizeof(uint64),       0, 0, CT_TRUE, 0, { 0 } },
    { 21, "CR_GETS",              0, 0, CT_TYPE_BIGINT,  sizeof(uint64),       0, 0, CT_TRUE, 0, { 0 } },
    { 22, "CON_WAIT_TIME",        0, 0, CT_TYPE_BIGINT,  sizeof(uint64),       0, 0, CT_TRUE, 0, { 0 } },
    { 23, "CPU_TIME",             0, 0, CT_TYPE_BIGINT,  sizeof(uint64),       0, 0, CT_TRUE, 0, { 0 } },
};

static knl_column_t g_nls_session_param_columns[] = {
    { 0, "PARAMETER", 0, 0, CT_TYPE_VARCHAR, 30, 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "VALUE", 0, 0, CT_TYPE_VARCHAR, MAX_NLS_PARAM_LENGTH, 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_free_space_columns[] = {
    { 0, "TABLESPACE_NAME", 0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "FILE_ID",         0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 2, "BLOCK_ID",        0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 3, "BYTES",           0, 0, CT_TYPE_BIGINT,  sizeof(uint64),  0, 0, CT_FALSE, 0, { 0 } },
    { 4, "BLOCKS",          0, 0, CT_TYPE_BIGINT,  sizeof(uint64),  0, 0, CT_FALSE, 0, { 0 } },
    { 5, "RELATIVE_FNO",    0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_pl_mngr_columns[] = {
    { 0,  "USER#",         0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 1,  "USER_NAME",     0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 2,  "NAME",          0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 3,  "TYPE",          0, 0, CT_TYPE_VARCHAR, 30,              0, 0, CT_FALSE, 0, { 0 } },
    { 4,  "BUCKET_ID",     0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 5,  "LIST_POS",      0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 6,  "UNUSED",        0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 7,  "TRIG_USER",     0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_TRUE,  0, { 0 } },
    { 8,  "TRIG_TABLE",    0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_TRUE,  0, { 0 } },
    { 9,  "REF_COUNT",     0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 10, "ENTITY",        0, 0, CT_TYPE_BIGINT,  sizeof(uint64),  0, 0, CT_FALSE, 0, { 0 } },
    { 11, "PAGES",         0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 12, "PACKAGE_NAME",  0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_TRUE,  0, { 0 } },
};

#define VW_CONTROLFILE_COL_STATUS_LEN (uint32)16
#define VW_CONTROLFILE_COL_ISRECOVER_LEN (uint32)4

static knl_column_t g_controlfile_columns[] = {
    { 0, "STATUS",                0, 0, CT_TYPE_VARCHAR, VW_CONTROLFILE_COL_STATUS_LEN,    0, 0, CT_TRUE,  0, { 0 } },
    { 1, "NAME",                  0, 0, CT_TYPE_VARCHAR, CT_FILE_NAME_BUFFER_SIZE,         0, 0, CT_FALSE, 0, { 0 } },
    { 2, "IS_RECOVERY_DEST_FILE", 0, 0, CT_TYPE_VARCHAR, VW_CONTROLFILE_COL_ISRECOVER_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 3, "BLOCK_SIZE",            0, 0, CT_TYPE_INTEGER, sizeof(uint32),                   0, 0, CT_FALSE, 0, { 0 } },
    { 4, "FILE_SIZE_BLKS",        0, 0, CT_TYPE_INTEGER, sizeof(uint32),                   0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_hba_columns[] = {
    { 0, "TYPE",      0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,    0, 0, CT_FALSE, 0, { 0 } },
    { 1, "USER_NAME", 0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,    0, 0, CT_FALSE, 0, { 0 } },
    { 2, "ADDRESS",   0, 0, CT_TYPE_VARCHAR, CT_MAX_COLUMN_SIZE, 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_pbl_columns[] = {
    { 0, "USER",       0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,          0, 0, CT_FALSE, 0, { 0 } },
    { 1, "PWD_REGRXP", 0, 0, CT_TYPE_VARCHAR, CT_PBL_PASSWD_MAX_LEN,    0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_rcywait_columns[] = {
    { 0,  "NAME",     0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,    0, 0, CT_FALSE, 0, { 0 } },
    { 1,  "VALUE",    0, 0, CT_TYPE_BIGINT, sizeof(uint64),      0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_whitelist_columns[] = {
    { 0, "HOST_TYPE", 0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "USER_NAME", 0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "ADDRESS",   0, 0, CT_TYPE_VARCHAR, CM_MAX_IP_LEN,   0, 0, CT_FALSE, 0, { 0 } },
    { 3, "IP_TYPE",   0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_pl_refsqls_columns[] = {
    { 0, "USER#",     0, 0, CT_TYPE_INTEGER, sizeof(uint32),       0, 0, CT_FALSE, 0, { 0 } },
    { 1, "USER_NAME", 0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,      0, 0, CT_FALSE, 0, { 0 } },
    { 2, "NAME",      0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,      0, 0, CT_FALSE, 0, { 0 } },
    { 3, "ENTITY",    0, 0, CT_TYPE_BIGINT,  sizeof(uint64),       0, 0, CT_FALSE, 0, { 0 } },
    { 4, "SQL_ID",    0, 0, CT_TYPE_VARCHAR, CT_MAX_UINT32_STRLEN, 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_jobs_running_columns[] = {
    { 0, "JOBNO",      0, 0, CT_TYPE_BIGINT,  sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "SESSION_ID", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "SERIAL_ID",  0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_dc_pool_columns[] = {
    { 0, "POOL_OPT_COUNT",            0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "POOL_PAGE_COUNT",           0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "POOL_FREE_PAGE_COUNT",      0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 3, "LRU_COUNT",                 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 4, "LRU_PAGE_COUNT",            0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 5, "LRU_LOCKED_COUNT",          0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 6, "LRU_LOCKED_PAGE_COUNT",     0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 7, "LRU_RECYCLABLE_COUNT",      0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 8, "LRU_RECYCLABLE_PAGE_COUNT", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_reactor_pool_columns[] = {
    { 0,  "REACTOR_ID",                 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 1,  "EPOLL_FD",                   0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 2,  "REACTOR_STATUS",             0, 0, CT_TYPE_VARCHAR, 10,             0, 0, CT_FALSE, 0, { 0 } },
    { 3,  "SESSION_COUNT",              0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 4,  "KILLEVENT_R_POS",            0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 5,  "KILLEVENT_W_POS",            0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 6,  "ACTIVE_AGENT_COUNT",         0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 7,  "BLANK_AGENT_COUNT",          0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 8,  "IDLE_AGENT_COUNT",           0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 9,  "OPTIMIZED_AGENT_COUNT",      0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 10, "MAX_AGENT_COUNT",            0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 11, "MODE",                       0, 0, CT_TYPE_VARCHAR, 10,             0, 0, CT_FALSE, 0, { 0 } },
    { 12, "DEDICATED_AGENT_COUNT",      0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 13, "FREE_DEDICATED_AGENT_COUNT", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 14, "EMERG_SESSION_COUNT",        0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 15, "BUSY_SCHEDULING_COUNT",      0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 16, "PRIV_ACTIVE_AGENT_COUNT",    0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 17, "PRIV_BLANK_AGENT_COUNT",     0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 18, "PRIV_IDLE_AGENT_COUNT",      0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 19, "PRIV_OPTIMIZED_AGENT_COUNT", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 20, "PRIV_MAX_AGENT_COUNT",       0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_emerg_pool[] = {
    { 0, "MAX_SESSIONS",    0, 0, CT_TYPE_INTEGER, sizeof(uint32),   0, 0, CT_FALSE, 0, { 0 } },
    { 1, "SERVICE_COUNT",   0, 0, CT_TYPE_INTEGER, sizeof(uint32),   0, 0, CT_FALSE, 0, { 0 } },
    { 2, "IDLE_SESSIONS",   0, 0, CT_TYPE_INTEGER, sizeof(uint32),   0, 0, CT_FALSE, 0, { 0 } },
    { 3, "UDS_SERVER_PATH", 0, 0, CT_TYPE_VARCHAR, CT_UNIX_PATH_MAX, 0, 0, CT_FALSE, 0, { 0 } }
};

static knl_column_t g_global_transaction[] = {
    { 0, "GLOBAL_TRAN_ID", 0, 0, CT_TYPE_VARCHAR, CT_MAX_XA_BASE16_GTRID_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "FORMAT_ID",      0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,            0, 0, CT_FALSE, 0, { 0 } },
    { 2, "BRANCH_ID",      0, 0, CT_TYPE_VARCHAR, CT_MAX_XA_BASE16_BQUAL_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 3, "LOCAL_TRAN_ID",  0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,            0, 0, CT_FALSE, 0, { 0 } },
    { 4, "STATUS",         0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,            0, 0, CT_FALSE, 0, { 0 } },
    { 5, "SID",            0, 0, CT_TYPE_INTEGER, sizeof(uint32),             0, 0, CT_FALSE, 0, { 0 } },
    { 6, "RMID",           0, 0, CT_TYPE_INTEGER, sizeof(uint32),             0, 0, CT_FALSE, 0, { 0 } }
};

#define DC_RANKINGS_COL_PAGES 2
#define DC_RANKINGS_COLUMN_COUNT 5
static knl_column_t g_dc_rankings[] = {
    { 0, "USER_NAME",     0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,   0, 0, CT_FALSE, 0, { 0 } },
    { 1, "OBJ_NAME",      0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,   0, 0, CT_FALSE, 0, { 0 } },
    { 2, "PAGES",         0, 0, CT_TYPE_INTEGER, sizeof(uint32),    0, 0, CT_FALSE, 0, { 0 } },
    { 3, "REF_COUNT",     0, 0, CT_TYPE_INTEGER, sizeof(uint32),    0, 0, CT_FALSE, 0, { 0 } },
    { 4, "VALID",         0, 0, CT_TYPE_BOOLEAN, sizeof(bool32),    0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_temptables_columns[] = {
    {0, "SESSION_ID",    0, 0, CT_TYPE_INTEGER, sizeof(uint32),   0, 0, CT_FALSE, 0, { 0 } },
    {1, "OWNER",         0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,  0, 0, CT_FALSE, 0, { 0 } },
    {2, "TABLE_NAME",    0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,  0, 0, CT_FALSE, 0, { 0 } },
    {3, "COLUMNT_COUNT", 0, 0, CT_TYPE_INTEGER, sizeof(uint32),   0, 0, CT_FALSE, 0, { 0 } },
    {4, "INDEX_COUNT",   0, 0, CT_TYPE_INTEGER, sizeof(uint32),   0, 0, CT_FALSE, 0, { 0 } },
    {5, "DATA_PAGES",    0, 0, CT_TYPE_INTEGER, sizeof(uint32),   0, 0, CT_FALSE, 0, { 0 } },
    {6, "INDEX_PAGES",   0, 0, CT_TYPE_INTEGER, sizeof(uint32),   0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_buffer_recycle_stats[] = {
    { 0, "SID",      0, 0, CT_TYPE_INTEGER, sizeof(uint32),   0, 0, CT_FALSE, 0, { 0 } },
    { 1, "TOTAL",    0, 0, CT_TYPE_INTEGER, sizeof(uint32),   0, 0, CT_FALSE, 0, { 0 } },
    { 2, "WAITS",    0, 0, CT_TYPE_INTEGER, sizeof(uint32),   0, 0, CT_FALSE, 0, { 0 } },
    { 3, "AVG_STEP", 0, 0, CT_TYPE_REAL,    sizeof(uint32),   0, 0, CT_FALSE, 0, { 0 } },
    { 4, "SPINS",    0, 0, CT_TYPE_INTEGER, sizeof(uint32),   0, 0, CT_FALSE, 0, { 0 } },
    { 5, "SLEEPS",   0, 0, CT_TYPE_INTEGER, sizeof(uint32),   0, 0, CT_FALSE, 0, { 0 } },
    { 6, "FAILS",    0, 0, CT_TYPE_INTEGER, sizeof(uint32),   0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_buffer_access_stats[] = {
    { 0, "SID",           0, 0, CT_TYPE_INTEGER, sizeof(uint32),   0, 0, CT_FALSE, 0, { 0 } },
    { 1, "TOTAL_ACCESS",  0, 0, CT_TYPE_INTEGER, sizeof(uint32),   0, 0, CT_FALSE, 0, { 0 } },
    { 2, "MISS_COUNT",    0, 0, CT_TYPE_INTEGER, sizeof(uint32),   0, 0, CT_FALSE, 0, { 0 } },
    { 3, "HIT_RATIO",     0, 0, CT_TYPE_REAL, sizeof(uint32),      0, 0, CT_FALSE, 0, { 0 } }
};

static knl_column_t g_temp_table_stats[] = {
    { 0, "USER#", 0, SYS_TABLE_ID, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0 },
    { 1, "ID", 0, SYS_TABLE_ID, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, },
    { 2, "NAME", 0, SYS_TABLE_ID, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, },
    { 3, "NUM_ROWS", 0, SYS_TABLE_ID, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_TRUE, 0 },
    { 4, "BLOCKS", 0, SYS_TABLE_ID, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_TRUE, 0 },
    { 5, "EMPTY_BLOCKS", 0, SYS_TABLE_ID, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_TRUE, 0 },
    { 6, "AVG_ROW_LEN", 0, SYS_TABLE_ID, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_TRUE, 0 },
    { 7, "SAMPLESIZE", 0, SYS_TABLE_ID, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_TRUE, 0 },
    { 8, "ANALYZETIME", 0, SYS_TABLE_ID, CT_TYPE_TIMESTAMP, sizeof(int64), CT_MAX_DATETIME_PRECISION, 0, CT_TRUE, 0, { NULL, 0 } },
};

knl_column_t g_temp_column_stats[] = {
    { 0, "USER#",        0, SYS_COLUMN_ID, CT_TYPE_INTEGER, sizeof(uint32),            0, 0, CT_FALSE, 0, { NULL, 0 } },
    { 1, "TABLE#",       0, SYS_COLUMN_ID, CT_TYPE_INTEGER, sizeof(uint32),            0, 0, CT_FALSE, 0, { NULL, 0 } },
    { 2, "ID",           0, SYS_COLUMN_ID, CT_TYPE_INTEGER, sizeof(uint32),            0, 0, CT_FALSE, 0, { NULL, 0 } },
    { 3, "NAME",         0, SYS_COLUMN_ID, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,           0, 0, CT_FALSE, 0, { NULL, 0 } },
    { 4, "NUM_DISTINCT", 0, SYS_COLUMN_ID, CT_TYPE_INTEGER, sizeof(uint32),            0, 0, CT_TRUE,  0, { NULL, 0 } },
    { 5, "LOW_VALUE",    0, SYS_COLUMN_ID, CT_TYPE_VARCHAR, CT_MAX_MIN_VALUE_SIZE,     0, 0, CT_TRUE,  0, { NULL, 0 } },
    { 6, "HIGH_VALUE",   0, SYS_COLUMN_ID, CT_TYPE_VARCHAR, CT_MAX_MIN_VALUE_SIZE,     0, 0, CT_TRUE,  0, { NULL, 0 } },
    { 7, "HISTOGRAM",    0, SYS_COLUMN_ID, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,           0, 0, CT_TRUE,  0, { NULL, 0 } },
};
knl_column_t g_temp_index_stats[] = {
    { 0,  "USER#",                   0, SYS_INDEX_ID, CT_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         CT_FALSE, 0, { NULL, 0 } },
    { 1,  "TABLE#",                  0, SYS_INDEX_ID, CT_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         CT_FALSE, 0, { NULL, 0 } },
    { 2,  "ID",                      0, SYS_INDEX_ID, CT_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         CT_FALSE, 0, { NULL, 0 } },
    { 3,  "NAME",                    0, SYS_INDEX_ID, CT_TYPE_VARCHAR,   CT_MAX_NAME_LEN,     0,                         0,                         CT_FALSE, 0, { NULL, 0 } },
    { 4,  "BLEVEL",                  0, SYS_INDEX_ID, CT_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         CT_TRUE,  0, { NULL, 0 } },
    { 5,  "LEVEL_BLOCKS",            0, SYS_INDEX_ID, CT_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         CT_TRUE,  0, { NULL, 0 } },
    { 6,  "DISTINCT_KEYS",           0, SYS_INDEX_ID, CT_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         CT_TRUE,  0, { NULL, 0 } },
    { 7,  "AVG_LEAF_BLOCKS_PER_KEY", 0, SYS_INDEX_ID, CT_TYPE_REAL,      sizeof(double),      CT_UNSPECIFIED_REAL_PREC,  CT_UNSPECIFIED_REAL_SCALE, CT_TRUE,  0, { NULL, 0 } },
    { 8,  "AVG_DATA_BLOCKS_PER_KEY", 0, SYS_INDEX_ID, CT_TYPE_REAL,      sizeof(double),      CT_UNSPECIFIED_REAL_PREC,  CT_UNSPECIFIED_REAL_SCALE, CT_TRUE,  0, { NULL, 0 } },
    { 9,  "ANALYZETIME",             0, SYS_INDEX_ID, CT_TYPE_TIMESTAMP, sizeof(uint64),      CT_MAX_DATETIME_PRECISION, 0,                         CT_TRUE,  0, { NULL, 0 } },
    { 10, "EMPTY_LEAF_BLOCKS",       0, SYS_INDEX_ID, CT_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         CT_TRUE,  0, { NULL, 0 } },
    { 11, "CLUFAC",                  0, SYS_INDEX_ID, CT_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         CT_TRUE,  0, { NULL, 0 } },
    { 12, "COMB_COLS_2_NDV",         0, SYS_INDEX_ID, CT_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         CT_TRUE,  0, { NULL, 0 } },
    { 13, "COMB_COLS_3_NDV",         0, SYS_INDEX_ID, CT_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         CT_TRUE,  0, { NULL, 0 } },
    { 14, "COMB_COLS_4_NDV",         0, SYS_INDEX_ID, CT_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         CT_TRUE,  0, { NULL, 0 } },
};

knl_column_t g_datafile_last_table[] = {
    { 0,  "ID",                0, 0, CT_TYPE_INTEGER, sizeof(uint32),               0, 0, CT_FALSE, 0, { 0 } },
    { 1,  "TABLESPACE_ID",     0, 0, CT_TYPE_INTEGER, sizeof(uint32),               0, 0, CT_FALSE, 0, { 0 } },
    { 2,  "FILE_NAME",         0, 0, CT_TYPE_VARCHAR, CT_FILE_NAME_BUFFER_SIZE,     0, 0, CT_FALSE, 0, { 0 } },
    { 3,  "HIGH_WATER_MARK",   0, 0, CT_TYPE_INTEGER, sizeof(uint32),               0, 0, CT_FALSE, 0, { 0 } },
    { 4,  "LAST_TABLE",        0, 0, CT_TYPE_VARCHAR, MAX_LAST_TABLE_NAME_LEN,      0, 0, CT_FALSE, 0, { 0 } },
    { 5,  "LAST_SEG_TYPE",     0, 0, CT_TYPE_VARCHAR, CT_NAME_BUFFER_SIZE,          0, 0, CT_FALSE, 0, { 0 } },
    { 6,  "FIRST_FREE_EXTENT", 0, 0, CT_TYPE_INTEGER, sizeof(uint32),               0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_tenant_tablespaces[] = {
    { 0, "TENANT_NAME", 0, 0, CT_TYPE_VARCHAR, CT_DB_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "TABLESPACE_NAME", 0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_async_shrink_tables[] = {
    { 0, "UID",                  0, 0, CT_TYPE_INTEGER, sizeof(uint32),               0, 0, CT_FALSE, 0, { 0 } },
    { 1, "OID",                  0, 0, CT_TYPE_INTEGER, sizeof(uint32),               0, 0, CT_FALSE, 0, { 0 } },
    { 2, "TABLE_NAME",           0, 0, CT_TYPE_VARCHAR, CT_FILE_NAME_BUFFER_SIZE,     0, 0, CT_FALSE, 0, { 0 } },
    { 3, "STATUS",               0, 0, CT_TYPE_VARCHAR, CT_FILE_NAME_BUFFER_SIZE,     0, 0, CT_FALSE, 0, { 0 } },
    { 4, "SHRINKABLE_SCN",       0, 0, CT_TYPE_BIGINT,  sizeof(uint32),               0, 0, CT_FALSE, 0, { 0 } },
    { 5, "MIN_SCN",              0, 0, CT_TYPE_BIGINT,  sizeof(uint64),               0, 0, CT_FALSE, 0, { 0 } },
    { 6, "BEGIN_TIME",           0, 0, CT_TYPE_DATE,    sizeof(date_t),               0, 0, CT_TRUE,  0, { 0 } },
};

static knl_column_t g_pl_entity_columns[] = {
    { 0,  "UID",       0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 1,  "USER_NAME", 0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 2,  "OID",       0, 0, CT_TYPE_BIGINT,  sizeof(uint64),  0, 0, CT_FALSE, 0, { 0 } },
    { 3,  "NAME",      0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 4,  "TYPE",      0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 5,  "PAGES",     0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 6,  "VAILD",     0, 0, CT_TYPE_BOOLEAN, sizeof(bool32),  0, 0, CT_FALSE, 0, { 0 } },
    { 7,  "REF_COUNT", 0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_ckpt_stats_columns[] = {
    { 0, "TYPE",         0,  0,  CT_TYPE_VARCHAR,    16,                 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "TASK_COUNT",   0,  0,  CT_TYPE_INTEGER,    sizeof(uint64),     0, 0, CT_FALSE, 0, { 0 } },
    { 2, "RUN_TIME",     0,  0,  CT_TYPE_REAL,       sizeof(uint64),     0, 0, CT_FALSE, 0, { 0 } },
    { 3, "FLUSH_PAGES",  0,  0,  CT_TYPE_INTEGER,    sizeof(uint64),     0, 0, CT_FALSE, 0, { 0 } },
    { 4, "CLEAN_EDP",    0,  0,  CT_TYPE_INTEGER,    sizeof(uint64),     0, 0, CT_FALSE, 0, { 0 } },
    { 5, "BEGIN_TIME",   0,  0,  CT_TYPE_DATE,       sizeof(date_t),     0, 0, CT_FALSE, 0, { 0 } },
    { 6, "WAIT_COUNT",   0,  0,  CT_TYPE_INTEGER,    sizeof(uint64),     0, 0, CT_FALSE, 0, { 0 } },
    { 7, "CUR_TRIG",     0,  0,  CT_TYPE_VARCHAR,    16,                 0, 0, CT_FALSE, 0, { 0 } },
    { 8, "CUR_TIMED",    0,  0,  CT_TYPE_VARCHAR,    16,                 0, 0, CT_FALSE, 0, { 0 } },
    { 9, "QUEUE_FIRST",  0,  0,  CT_TYPE_VARCHAR,    16,                 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_users_columns[] = {
    { 0, "USERNAME",              0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "USER_ID",               0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 2, "ACCOUNT_STATUS",        0, 0, CT_TYPE_VARCHAR, 64,              0, 0, CT_FALSE, 0, { 0 } },
    { 3, "FAILED_LOGINS",         0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 4, "CREATE_TIME",           0, 0, CT_TYPE_DATE,    sizeof(date_t),  0, 0, CT_FALSE, 0, { 0 } },
    { 5, "PASSWD_CTIME",          0, 0, CT_TYPE_DATE,    sizeof(date_t),  0, 0, CT_FALSE, 0, { 0 } },
    { 6, "EXPIRE_TIME",           0, 0, CT_TYPE_DATE,    sizeof(date_t),  0, 0, CT_TRUE,  0, { 0 } },
    { 7, "LOCKED_TIME",           0, 0, CT_TYPE_DATE,    sizeof(date_t),  0, 0, CT_TRUE, 0, { 0 } },
    { 8, "PROFILE",               0, 0, CT_TYPE_VARCHAR, 64,              0, 0, CT_FALSE, 0, { 0 } },
    { 9, "DATA_TABLESPACE",       0, 0, CT_TYPE_VARCHAR, 64,              0, 0, CT_FALSE, 0, { 0 } },
    { 10, "TEMPORARY_TABLESPACE", 0, 0, CT_TYPE_VARCHAR, 64,              0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_ckpt_part_stats_columns[] = {
    { 0,  "PART_ID",               0, 0, CT_TYPE_INTEGER, sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 1,  "FLUSH_TIMES",           0, 0, CT_TYPE_INTEGER, sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 2,  "TOTAL_FLUSH_COUNT",     0, 0, CT_TYPE_INTEGER, sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 3,  "AVERAGE_FLUSH_COUNT",   0, 0, CT_TYPE_INTEGER, sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 4,  "MIN_FLUSH_COUNT",       0, 0, CT_TYPE_INTEGER, sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 5,  "MAX_FLUSH_COUNT",       0, 0, CT_TYPE_INTEGER, sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 6,  "ZERO_FLUSH_TIMES",      0, 0, CT_TYPE_INTEGER, sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 7,  "CURR_FLUSH_COUNT",      0, 0, CT_TYPE_INTEGER, sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_lfn_nodes[] = {
    { 0,  "NODE",                  0, 0, CT_TYPE_INTEGER, sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
    { 1,  "LFN",                   0, 0, CT_TYPE_BIGINT,  sizeof(uint64),           0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_lrpl_detail_columns[] = {
    { 0, "DATABASE_ROLE",           0, 0, CT_TYPE_STRING, 30, 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "LRPL_STATUS",             0, 0, CT_TYPE_STRING, 16, 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "REDO_RECOVERY_SIZE_MB",   0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, {0}},
    { 3, "REDO_RECOVERY_TIME_S",    0, 0, CT_TYPE_REAL,    sizeof(double), 0, 0, CT_FALSE, 0, {0}},
};

#define DATAFILE_COLS (ELEMENT_COUNT(g_datafile_columns))
#define LOGFILE_COLS (ELEMENT_COUNT(g_logfile_columns))
#define LIBRARYCACHE_COLS (ELEMENT_COUNT(g_library_cache))
#define BUFFER_POOL_COLS (ELEMENT_COUNT(g_buffer_pool_columns))
#define BUFFER_POOL_STATISTICS_COLS (ELEMENT_COUNT(g_buffer_pool_statistics_columns))
#define BUFFER_PAGE_STATS_COLS (ELEMENT_COUNT(g_buffer_page_statistics_columns))
#define BUFFER_INDEX_STATS_COLS (ELEMENT_COUNT(g_buffer_index_statistics_columns))
#define PARAMETER_COLS (ELEMENT_COUNT(g_parameter_columns))
#define KNL_DEBUG_PARAMETER_COLS (ELEMENT_COUNT(g_debug_parameter_columns))
#define TABLESPACES_COLS (ELEMENT_COUNT(g_tablespaces_columns))
#define ARCHIVED_LOG_COLS (ELEMENT_COUNT(g_archived_log_columns))
#define TEMP_ARCHIVED_LOG_COLS (ELEMENT_COUNT(g_temp_archived_log_columns))
#define ARCHIVE_GAP_COLS (ELEMENT_COUNT(g_archive_gap_columns))
#define ARCHIVE_PROCESS_COLS (ELEMENT_COUNT(g_archive_process_columns))
#define ARCHIVE_STATUS_COLS (ELEMENT_COUNT(g_archive_status_columns))
#define DATABASE_COLS (ELEMENT_COUNT(g_database_columns))
#define CLASS_COLS (ELEMENT_COUNT(g_class_columns))
#define REPL_STATUS_COLS (ELEMENT_COUNT(g_repl_status_columns))
#define MANAGED_STANDBY_COLS (ELEMENT_COUNT(g_managed_standby_columns))
#define HA_SYNC_INFO_COLS (ELEMENT_COUNT(g_ha_sync_info_columns))
#define DBORCL_COLS (ELEMENT_COUNT(g_dborcl_columns))
#define DB_OBJECT_CACHE_COLS (ELEMENT_COUNT(g_db_object_cache))
#define ME_COLS (ELEMENT_COUNT(g_me_columns))
#define DYNAMIC_VIEW_COLS (ELEMENT_COUNT(g_dynamic_view_columns))
#define DYNAMIC_VIEW_COLUMN_COLS (ELEMENT_COUNT(g_dynamic_view_column_cols))
#define VERSION_COLS (ELEMENT_COUNT(g_version_columns))
#define TRANSACTION_COLS (ELEMENT_COUNT(g_transaction_columns))
#define ALL_TRANSACTION_COLS (ELEMENT_COUNT(g_all_transaction_columns))
#define RESOURCE_MAP_COLS (ELEMENT_COUNT(g_resource_map_columns))
#define USER_ASTATUS_MAP_COLS (ELEMENT_COUNT(g_user_astatus_map_columns))
#define UNDO_SEGMENT_COLS (ELEMENT_COUNT(g_undo_segment_columns))
#define TEMP_UNDO_SEGMENT_COLS (ELEMENT_COUNT(g_temp_undo_segment_columns))
#define BACKUP_PROCESS_COLS (ELEMENT_COUNT(g_backup_process_columns))
#define INSTANCE_COLS (ELEMENT_COUNT(g_instance_columns))
#define OPEN_CURSOR_COLS (ELEMENT_COUNT(g_open_cursor_columns))
#define CONTROLFILE_COLS (ELEMENT_COUNT(g_controlfile_columns))
#define NLS_PARAMS_COLS (ELEMENT_COUNT(g_nls_session_param_columns))
#define FREE_SPACE_COLS (sizeof(g_free_space_columns) / sizeof(knl_column_t))
#define PL_MNGR_COLS (ELEMENT_COUNT(g_pl_mngr_columns))
#define HBA_COLS (ELEMENT_COUNT(g_hba_columns))
#define PBL_COLS (ELEMENT_COUNT(g_pbl_columns))
#define WHITELIST_COLS (ELEMENT_COUNT(g_whitelist_columns))
#define PL_REFSQLS_COLS (ELEMENT_COUNT(g_pl_refsqls_columns))
#define JOBS_RUNNING_COLS (ELEMENT_COUNT(g_jobs_running_columns))
#define DC_POOL_COLS (ELEMENT_COUNT(g_dc_pool_columns))
#define REACTOR_POOL_COLS (ELEMENT_COUNT(g_reactor_pool_columns))
#define EMERG_POOL_COLS (ELEMENT_COUNT(g_emerg_pool))
#define GLOBAL_TRANSACTION_COLS (ELEMENT_COUNT(g_global_transaction))
#define RCYWAIT_COLS (ELEMENT_COUNT(g_rcywait_columns))
#define DC_RANKINGS_COLS (ELEMENT_COUNT(g_dc_rankings))
#define GBP_ALY_INFO_COLS (ELEMENT_COUNT(g_gbp_aly_info_columns))
#define TEMPTABLES_COLS (ELEMENT_COUNT(g_temptables_columns))
#define BUFFER_ACCESS_STATS_COLS (ELEMENT_COUNT(g_buffer_access_stats))
#define BUFFER_RECYCLE_STATS_COLS (ELEMENT_COUNT(g_buffer_recycle_stats))
#define BAK_PROCESS_STATS_COLS (ELEMENT_COUNT(g_backup_process_stats))
#define GTS_STATUS_COLS (ELEMENT_COUNT(g_gts_status))
#define TEMP_TABLE_STATS_COLS (ELEMENT_COUNT(g_temp_table_stats))
#define TEMP_COLUMN_STATS_COLS (ELEMENT_COUNT(g_temp_column_stats))
#define TEMP_INDEX_STATS_COLS (ELEMENT_COUNT(g_temp_index_stats))
#define DATAFILE_LAST_TABLE_COLS (ELEMENT_COUNT(g_datafile_last_table))
#define TENANT_TABLESPACES_COLS (ELEMENT_COUNT(g_tenant_tablespaces))
#define ASYNC_SHRINK_TABLES_COLS (ELEMENT_COUNT(g_async_shrink_tables))
#define PL_ENTITY_COLS (ELEMENT_COUNT(g_pl_entity_columns))
#define DV_CKPT_STATS_COLS (ELEMENT_COUNT(g_ckpt_stats_columns))
#define DV_USERS_COLS (ELEMENT_COUNT(g_users_columns))
#define DV_CKPT_PART_COLS (ELEMENT_COUNT(g_ckpt_part_stats_columns))
#define LFN_NODES (ELEMENT_COUNT(g_lfn_nodes))
#define LRPL_DETAIL_COLS (ELEMENT_COUNT(g_lrpl_detail_columns))

#define VM_REPL_STATUS_ROWS 1
#define VM_DATABASE_ROWS 1
#define VM_ME_ROWS 1
#define VM_LOGFILE_ASN_LEN (uint32)1024
#define VM_DATAFILE_RETRY_TIME (2) // ms

static inline bool32 vm_dc_scan_entry(knl_session_t *session, dc_context_t *ctx, knl_cursor_t *cursor)
{
    uint64 group_id, entry_id, user_id;
    dc_entry_t *entry = NULL;
    dc_user_t *user = NULL;
    bool32 is_found;

    user_id = cursor->rowid.vmid;     // vmid record user id
    group_id = cursor->rowid.vm_slot; // vm_slot record group id
    entry_id = cursor->rowid.vm_tag;  // vm_tag record entry id

    if (dc_open_user_by_id(session, (uint32)user_id, &user) != CT_SUCCESS) {
        return CT_FALSE;
    }

    is_found = CT_FALSE;

    while (entry_id < DC_GROUP_SIZE) {
        entry = user->groups[group_id]->entries[entry_id];

        if (entry != NULL) {
            is_found = CT_TRUE;
            break;
        }

        entry_id++;
    }

    cursor->rowid.vm_tag = entry_id; // update cursor content
    return is_found;
}

static inline bool32 vm_dc_scan_group(knl_session_t *session, dc_context_t *ctx, knl_cursor_t *cursor)
{
    uint64 group_id;
    dc_group_t *group = NULL;
    dc_user_t *user = NULL;

    if (dc_open_user_by_id(session, (uint32)cursor->rowid.vmid, &user) != CT_SUCCESS) {
        return CT_FALSE;
    }

    group_id = cursor->rowid.vm_slot;

    while (group_id < DC_GROUP_COUNT) {
        group = user->groups[group_id];
        if (group != NULL) {
            if (vm_dc_scan_entry(session, ctx, cursor)) {
                return CT_TRUE;
            }
        }

        group_id++;                       // fetch next group
        cursor->rowid.vm_slot = group_id; // update cursor content
        cursor->rowid.vm_tag = 0;
    }

    return CT_FALSE;
}

static inline bool32 vm_dc_scan_user(knl_session_t *session, dc_context_t *ctx, knl_cursor_t *cursor)
{
    uint64 user_id;
    dc_user_t *user = NULL;

    user_id = cursor->rowid.vmid;

    while (user_id < CT_MAX_USERS) {
        if (dc_open_user_by_id(session, (uint32)user_id, &user) != CT_SUCCESS) {
            cm_reset_error();
            return CT_FALSE;
        }

        if (user != NULL) {
            if (vm_dc_scan_group(session, ctx, cursor)) {
                return CT_TRUE;
            }
        }

        user_id++;                    // group of user scan update user
        cursor->rowid.vmid = user_id; // update cursor content
        cursor->rowid.vm_slot = 0;    // group id initialize
    }

    return CT_FALSE;
}

status_t vw_common_open(knl_handle_t session, knl_cursor_t *cursor)
{
    cursor->rowid.vmid = 0;
    cursor->rowid.vm_slot = 0;
    cursor->rowid.vm_tag = 0;
    return CT_SUCCESS;
}

status_t vw_tlvdef_open(knl_handle_t session, knl_cursor_t *cursor)
{
    cursor->rowid.file = 0;
    cursor->rowid.page = 0;
    cursor->rowid.slot = 0;
    cursor->rowid.unused1 = 0;
    return CT_SUCCESS;
}

status_t vw_tenant_tablespaces_open(knl_handle_t session, knl_cursor_t *cursor)
{
    cursor->rowid.tenant_id = 1;
    cursor->rowid.curr_ts_num = 0;
    cursor->rowid.ts_id = 0;
    return CT_SUCCESS;
}

static char *vw_device_type_get(device_type_t type)
{
    switch (type) {
        case DEV_TYPE_FILE:
            return "FILE";
        case DEV_TYPE_RAW:
            return "RAW";
        case DEV_TYPE_CFS:
            return "CFS";
        default:
            return "UNKNOWN";
    }
}

static status_t vm_update_ctrl_info(row_assist_t *ra, datafile_ctrl_t *ctrl, uint64_t datafile_size)
{
    CT_RETURN_IFERR(row_put_str(ra, vw_device_type_get(ctrl->type)));
    CT_RETURN_IFERR(row_put_str(ra, ctrl->name));
    CT_RETURN_IFERR(row_put_int64(ra, datafile_size));
    return CT_SUCCESS;
}

static status_t vm_get_datafile_size(knl_session_t *session, datafile_ctrl_t *ctrl, datafile_t *df,
    uint64_t *datafile_size)
{
    int32 *handle = NULL;
    status_t Ret = CT_SUCCESS;
    if (!DB_IS_CLUSTER(session)) {
        return CT_SUCCESS;
    }
    handle = DATAFILE_FD(session, ctrl->id);
    SYNC_POINT_GLOBAL_START(CANTIAN_SPC_OPEN_DATAFILE_FAIL, &Ret, CT_ERROR);
    Ret = spc_open_datafile_no_retry(session, df, handle);
    SYNC_POINT_GLOBAL_END;
    if (*handle == -1 && Ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[SPACE] failed to open file %s", ctrl->name);
        return CT_ERROR;
    }
    *datafile_size =
        ctrl->size > cm_device_size(ctrl->type, *handle) ? ctrl->size : cm_device_size(ctrl->type, *handle);
    spc_close_datafile(df, handle);
    return CT_SUCCESS;
}

static status_t vw_datafile_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    int32 file_hwm = 0;
    row_assist_t ra;
    knl_session_t *session = (knl_session_t *)se;
    database_t *db = &session->kernel->db;
    datafile_ctrl_t *ctrl = NULL;
    datafile_t *df = NULL;
    space_t *space = NULL;
    uint64 id = cursor->rowid.vmid;
    uint64_t datafile_size = 0;

    for (;;) {
        if (id >= CT_MAX_DATA_FILES) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }

        ctrl = db->datafiles[id].ctrl;
        df = &db->datafiles[id];
        space = SPACE_GET(session, df->space_id);
        datafile_size = ctrl->size;
        if (ctrl->used) {
            CT_RETURN_IFERR(vm_get_datafile_size(session, ctrl, df, &datafile_size));
            break;
        }
        id++;
    }

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, DATAFILE_COLS);
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)(ctrl->id)));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)(DATAFILE_GET(session, id)->space_id)));
    CT_RETURN_IFERR(row_put_str(&ra, DATAFILE_IS_ONLINE(df) ? "ONLINE" : "OFFLINE"));
    CT_RETURN_IFERR(vm_update_ctrl_info(&ra, ctrl, datafile_size));
    CT_RETURN_IFERR(row_put_str(&ra, DATAFILE_IS_AUTO_EXTEND(df) ? "TRUE" : "FALSE"));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)(ctrl->auto_extend_size)));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)(ctrl->auto_extend_maxsize)));

    if (db->status == DB_STATUS_OPEN && DATAFILE_IS_ONLINE(df) && space->head != NULL) {
        file_hwm = DF_FILENO_IS_INVAILD(df) ? 0 : (int32)SPACE_HEAD_RESIDENT(session, space)->hwms[df->file_no];
    }
    CT_RETURN_IFERR(row_put_int32(&ra, file_hwm));
#ifndef WIN32
    struct stat stat_info;
    int64 alloc_size;

    cm_file_get_status(ctrl->name, &stat_info);
    alloc_size = ((int64)stat_info.st_blocks) * FILE_BLOCK_SIZE_512;
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)alloc_size));
#else
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)(ctrl->size)));
#endif
    CT_RETURN_IFERR(row_put_str(&ra, DATAFILE_IS_COMPRESS(df) ? "TRUE" : "FALSE"));
    CT_RETURN_IFERR(row_put_str(&ra, df->ctrl->punched ? "TRUE" : "FALSE"));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid = id + 1;
    return CT_SUCCESS;
}

static char *vw_logfile_fetch_status(logfile_status_t status)
{
    switch (status) {
        case LOG_FILE_INACTIVE:
            return "INACTIVE";
        case LOG_FILE_CURRENT:
            return "CURRENT";
        case LOG_FILE_ACTIVE:
            return "ACTIVE";
        default:
            return "UNUSED";
    }
}

static status_t vw_logfile_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    uint64 id;
    row_assist_t ra;
    char *status = NULL;
    char curr_point[CT_MAX_NUMBER_LEN];
    knl_session_t *ss = (knl_session_t *)session;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(ss);
    log_context_t *ctx = &ss->kernel->redo_ctx;

    id = cursor->rowid.vmid;
    while (id < ctx->logfile_hwm && LOG_IS_DROPPED(logfile_set->items[id].ctrl->flg)) {
        id++;
    }

    if (id >= ctx->logfile_hwm) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    status = vw_logfile_fetch_status(logfile_set->items[id].ctrl->status);

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, LOGFILE_COLS);
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)logfile_set->items[id].ctrl->node_id));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)logfile_set->items[id].ctrl->file_id));
    CT_RETURN_IFERR(row_put_str(&ra, status));
    CT_RETURN_IFERR(row_put_str(&ra, "ONLINE"));
    CT_RETURN_IFERR(row_put_str(&ra, logfile_set->items[id].ctrl->name));
    if (cm_dbs_is_enable_dbs() == CT_TRUE) {
        CT_RETURN_IFERR(row_put_int64(&ra, (int64)(logfile_set->items[id].ctrl->size)));
        CT_RETURN_IFERR(row_put_int64(&ra, (int64)(logfile_set->items[id].ctrl->size - ctx->free_size)));
        CT_RETURN_IFERR(row_put_int64(&ra, (int64)(ctx->free_size)));
    } else {
        CT_RETURN_IFERR(row_put_int64(&ra, (int64)(logfile_set->items[id].ctrl->size)));
        CT_RETURN_IFERR(row_put_int64(&ra, (int64)(logfile_set->items[id].head.write_pos)));
        CT_RETURN_IFERR(
            row_put_int64(&ra, (int64)(logfile_set->items[id].ctrl->size - logfile_set->items[id].head.write_pos)));
    }
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)(logfile_set->items[id].head.rst_id)));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)(logfile_set->items[id].head.asn)));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)(logfile_set->items[id].head.block_size)));

    if (logfile_set->items[id].ctrl->status == LOG_FILE_CURRENT) {
        PRTS_RETURN_IFERR(snprintf_s(curr_point, sizeof(curr_point), sizeof(curr_point) - 1, "%llu-%u/%u/%llu",
            ss->kernel->redo_ctx.curr_point.rst_id, ss->kernel->redo_ctx.curr_point.asn,
            ss->kernel->redo_ctx.curr_point.block_id, (uint64)ss->kernel->redo_ctx.curr_point.lfn));
    } else {
        curr_point[0] = '\0';
    }

    CT_RETURN_IFERR(row_put_str(&ra, curr_point));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)(logfile_set->items[id].arch_pos)));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid = id + 1;
    return CT_SUCCESS;
}

static status_t vw_librarycache_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    uint32 id;
    row_assist_t ra;
    uint32 len_lib_arr;
    len_lib_arr = sizeof(g_instance->library_cache_info) / sizeof(st_library_cache_t);
    id = (uint32)cursor->rowid.vmid;

    for (;;) {
        if (id >= len_lib_arr) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        } else {
            if ((uint64)g_instance->library_cache_info[id].hits != 0) {
                cursor->rowid.vmid = id;
                break;
            }
        }
        id++;
    }
    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, LIBRARYCACHE_COLS);
    CT_RETURN_IFERR(row_put_str(&ra, "DML"));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)g_instance->library_cache_info[id].hits));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)g_instance->library_cache_info[id].gethits));
    CT_RETURN_IFERR(row_put_int64(&ra,
        (int64)g_instance->library_cache_info[id].pins + (int64)g_instance->library_cache_info[id].pinhits));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)g_instance->library_cache_info[id].pinhits));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)g_instance->library_cache_info[id].reloads));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)g_instance->library_cache_info[id].invlidations));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

static status_t vw_buffer_pool_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    row_assist_t ra;
    buf_context_t *ctx = &((knl_session_t *)session)->kernel->buf_ctx;

    //  Now only one buffer exists
    if (cursor->rowid.vmid >= ctx->buf_set_count) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    buf_set_t *buf_set = &ctx->buf_set[cursor->rowid.vmid];
    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, BUFFER_POOL_COLS);
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)(cursor->rowid.vmid)));
    CT_RETURN_IFERR(row_put_str(&ra, "DATA BUFFER POOL"));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)(DEFAULT_PAGE_SIZE(session))));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)(buf_set->list[LRU_LIST_MAIN].count)));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)(buf_set->capacity)));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)(buf_set->capacity - buf_set->hwm)));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;

    return CT_SUCCESS;
}

static void vw_buffer_pool_stats_compress(knl_handle_t session, buf_ctrl_t *ctrl, uint32 *recycle_group,
    uint32 *cold_dirty_group, uint32 *group_count)
{
    page_id_t tmp_page_id;
    buf_ctrl_t *tmp_ctrl = NULL;

    (*group_count)++;

    bool32 is_recycle = CT_TRUE;
    bool32 is_cold_dirty = CT_FALSE;
    tmp_page_id.file = ctrl->page_id.file;
    for (uint32 j = 0; j < PAGE_GROUP_COUNT; j++) {
        tmp_page_id.page = ctrl->page_id.page + j;
        tmp_ctrl = buf_find_by_pageid(session, tmp_page_id);
        if (tmp_ctrl == NULL) {
            continue;
        }

        if (!BUF_CAN_EVICT(tmp_ctrl)) {
            is_recycle = CT_FALSE;
        }
        if (tmp_ctrl->is_dirty && !BUF_IS_HOT(tmp_ctrl)) {
            is_cold_dirty = CT_TRUE;
        }
    }

    if (is_recycle) {
        (*recycle_group)++;
    }

    if (is_cold_dirty) {
        (*cold_dirty_group)++;
    }
}


#define BUFF_LIST_NUM 2
static status_t vw_buffer_pool_statistics_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    knl_session_t *se = (knl_session_t *)session;
    buf_context_t *ctx = &se->kernel->buf_ctx;
    uint32 i;
    row_assist_t ra;
    uint32 cnum_write = 0;
    uint32 cnum_pinned = 0;
    uint32 cnum_resident = 0;
    uint32 cnum_ro = 0;
    uint32 local_master = 0;
    uint32 remote_master = 0;
    uint8 master_id = CT_INVALID_ID8;
    uint8 my_instance_id = se->kernel->id;
    buf_ctrl_t *ctrl = NULL;
    uint32 old_list_len = 0;
    bool32 in_hot_list = CT_TRUE;
    uint32 free_ctrls = 0;
    page_head_t *page = NULL;

    uint32 recycle_group = 0;
    uint32 cold_dirty_group = 0;
    uint32 group_count = 0;

    if (cursor->rowid.vmid >= ctx->buf_set_count) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    buf_set_t *buf_set = &ctx->buf_set[cursor->rowid.vmid];

    for (i = 0; i < buf_set->hwm; i++) {
        ctrl = &buf_set->ctrls[i];
        page = ctrl->page;
        if (page == NULL) {
            continue;
        }
        if (ctrl->is_resident) {
            cnum_resident++;
        } else if (ctrl->is_pinned) {
            cnum_pinned++;
        } else if (ctrl->is_dirty || ctrl->is_marked) {
            cnum_write++;
        } else {
            cnum_ro++;
        }

        if (ctrl->bucket_id == CT_INVALID_ID32) {
            free_ctrls++;
        }

        drc_get_page_master_id(ctrl->page_id, &master_id);
        if (master_id == my_instance_id) {
            local_master++;
        } else {
            remote_master++;
        }

        if (BUF_IS_COMPRESS(ctrl) && PAGE_IS_COMPRESS_HEAD(ctrl->page_id)) {
            vw_buffer_pool_stats_compress(session, ctrl, &recycle_group, &cold_dirty_group, &group_count);
        }
    }

    // check LRU list to calculate statistics
    cm_spin_lock(&buf_set->list[LRU_LIST_MAIN].lock, &se->stat->spin_stat.stat_buffer);
    ctrl = buf_set->list[LRU_LIST_MAIN].lru_first;
    for (i = 0; i < buf_set->list[LRU_LIST_MAIN].count; i++) {
        if (ctrl == NULL) {
            break;
        }

        if (buf_set->list[LRU_LIST_MAIN].lru_old == ctrl) {
            in_hot_list = CT_FALSE;
        }

        if (!in_hot_list) {
            old_list_len++;
        }
        if (ctrl->bucket_id != CT_INVALID_ID32 &&
            ctrl->buf_pool_id != buf_get_pool_id(ctrl->page_id, ctx->buf_set_count)) {
            CT_THROW_ERROR_EX(ERR_ASSERT_ERROR,
                "ctrl->bucket_id(%u) == CT_INVALID_ID32(%u) || ctrl->buf_pool_id(%u) == "
                "buf_get_pool_id(ctrl->page_id, ctx->buf_set_count)(%u)",
                ctrl->bucket_id, CT_INVALID_ID32, (uint32)ctrl->buf_pool_id,
                buf_get_pool_id(ctrl->page_id, ctx->buf_set_count));
            cm_spin_unlock(&buf_set->lock);
            return CT_ERROR;
        }
        if (ctrl->bucket_id != CT_INVALID_ID32 && ctrl->buf_pool_id != cursor->rowid.vmid) {
            CT_THROW_ERROR_EX(ERR_ASSERT_ERROR,
                "ctrl->bucket_id(%u) == CT_INVALID_ID32(%u) || ctrl->buf_pool_id(%u) == "
                "cursor->rowid.vmid(%u)",
                ctrl->bucket_id, CT_INVALID_ID32, (uint32)ctrl->buf_pool_id, cursor->rowid.vmid);
            cm_spin_unlock(&buf_set->lock);
            return CT_ERROR;
        }
        if (ctrl->list_id != LRU_LIST_MAIN) {
            CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "ctrl->list_id(%u) != 0", ctrl->list_id);
            cm_spin_unlock(&buf_set->lock);
            return CT_ERROR;
        }
        ctrl = ctrl->next;
    }

    if (buf_set->list[LRU_LIST_MAIN].old_count != old_list_len) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "buf_ctx->old_count(%u) == old_list_len(%u)",
            buf_set->list[LRU_LIST_MAIN].old_count, old_list_len);
        cm_spin_unlock(&buf_set->lock);
        return CT_ERROR;
    }
    cm_spin_unlock(&buf_set->list[LRU_LIST_MAIN].lock);

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, BUFFER_POOL_STATISTICS_COLS);
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)(cursor->rowid.vmid)));
    CT_RETURN_IFERR(row_put_str(&ra, "DATA BUFFER POOL"));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)(buf_set->capacity)));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)(buf_set->main_list.count)));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)cnum_write));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)(buf_set->capacity - buf_set->hwm)));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)(cnum_pinned + cnum_resident)));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)(cnum_ro)));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)(buf_set->main_list.old_count)));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)(buf_set->scan_list.count)));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)(free_ctrls)));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)(buf_set->write_list.count)));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)recycle_group));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)cold_dirty_group));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)group_count));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)(local_master)));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)(remote_master)));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);

    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

static status_t vw_buffer_page_statistics_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    uint32 i;
    row_assist_t ra;
    buf_ctrl_t *ctrl = NULL;
    page_head_t *page = NULL;
    uint32 ctrl_page_type = 0;
    static uint32 type_counts[PAGE_TYPE_END] = { 0 };
    static uint32 type_counts_clean[PAGE_TYPE_END] = { 0 };
    static uint32 type_counts_dirty[PAGE_TYPE_END] = { 0 };
    uint64 id;
    buf_context_t *ctx = &((knl_session_t *)session)->kernel->buf_ctx;

    while (cursor->rowid.vmid < ctx->buf_set_count) {
        id = cursor->rowid.slot;
        buf_set_t *buf_set = &ctx->buf_set[cursor->rowid.vmid];
        if (id == 0) {
            for (i = 0; i < PAGE_TYPE_END; i++) {
                type_counts[i] = 0;
                type_counts_clean[i] = 0;
                type_counts_dirty[i] = 0;
            }
            for (i = 0; i < buf_set->hwm; i++) {
                ctrl = &buf_set->ctrls[i];
                page = ctrl->page;
                if (page == NULL) {
                    continue;
                }

                ctrl_page_type = page->type;
                if (ctrl_page_type >= PAGE_TYPE_END) {
                    CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "page type (%d) is larger than (%d).", ctrl_page_type,
                        PAGE_TYPE_END);
                    return CT_ERROR;
                }

                type_counts[ctrl_page_type]++;
                if (ctrl->is_dirty || ctrl->is_marked) {
                    type_counts_dirty[ctrl_page_type]++;
                } else {
                    type_counts_clean[ctrl_page_type]++;
                }
            }
        }
        while (cursor->rowid.slot < PAGE_TYPE_END && type_counts[cursor->rowid.slot] == 0) {
            cursor->rowid.slot++;
        }
        if (cursor->rowid.slot >= PAGE_TYPE_END) {
            cursor->rowid.slot = 0;
            cursor->rowid.vmid++;
            continue;
        }
        id = cursor->rowid.slot;
        row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, BUFFER_PAGE_STATS_COLS);
        CT_RETURN_IFERR(row_put_int32(&ra, (int32)(cursor->rowid.vmid)));
        CT_RETURN_IFERR(row_put_str(&ra, page_type((uint8)id)));
        CT_RETURN_IFERR(row_put_int32(&ra, (int32)(type_counts[id])));
        CT_RETURN_IFERR(row_put_int32(&ra, (int32)(type_counts_clean[id])));
        CT_RETURN_IFERR(row_put_int32(&ra, (int32)(type_counts_dirty[id])));
        cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);

        cursor->rowid.slot++;
        return CT_SUCCESS;
    }
    if (cursor->rowid.vmid >= ctx->buf_set_count) {
        cursor->eof = CT_TRUE;
    }
    return CT_SUCCESS;
}

static status_t vw_buffer_index_statistics_level(knl_cursor_t *cursor, uint32 *index_levels, buf_context_t *ctx)
{
    buf_set_t *buf_set = &ctx->buf_set[cursor->rowid.vmid];
    for (uint32 i = 0; i < CT_MAX_BTREE_LEVEL; i++) {
        index_levels[i] = 0;
    }
    for (uint32 i = 0; i < buf_set->hwm; i++) {
        buf_ctrl_t *ctrl = &buf_set->ctrls[i];
        page_head_t *page = ctrl->page;
        CT_CONTINUE_IFTRUE(page == NULL);

        uint32 ctrl_page_type = page->type;
        if (ctrl_page_type >= PAGE_TYPE_END) {
            CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "page type (%d) is larger than (%d).", ctrl_page_type, PAGE_TYPE_END);
            return CT_ERROR;
        }

        if (ctrl_page_type == PAGE_TYPE_BTREE_NODE || ctrl_page_type == PAGE_TYPE_PCRB_NODE) {
            uint32 index_level = ((btree_page_t *)page)->level;
            if (index_level >= CT_MAX_BTREE_LEVEL) {
                CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "index level (%d) is larger than (%d).", index_level,
                    CT_MAX_BTREE_LEVEL);
                return CT_ERROR;
            }
            index_levels[index_level]++;
        }
    }
    return CT_SUCCESS;
}

static status_t vw_buffer_index_statistics_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    row_assist_t ra;
    static uint32 index_levels[CT_MAX_BTREE_LEVEL] = { 0 };
    buf_context_t *ctx = &((knl_session_t *)session)->kernel->buf_ctx;

    while (cursor->rowid.vmid < ctx->buf_set_count) {
        uint64 id = cursor->rowid.slot;
        if (id == 0) {
            CT_RETURN_IFERR(vw_buffer_index_statistics_level(cursor, index_levels, ctx));
        }
        while (cursor->rowid.slot < CT_MAX_BTREE_LEVEL && index_levels[cursor->rowid.slot] == 0) {
            cursor->rowid.slot++;
        }
        if (cursor->rowid.slot >= CT_MAX_BTREE_LEVEL) {
            cursor->rowid.slot = 0;
            cursor->rowid.vmid++;
            continue;
        }

        row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, BUFFER_INDEX_STATS_COLS);
        CT_RETURN_IFERR(row_put_int32(&ra, (int32)(cursor->rowid.vmid)));
        CT_RETURN_IFERR(row_put_int32(&ra, (int32)(cursor->rowid.slot)));
        CT_RETURN_IFERR(row_put_int32(&ra, (int32)(index_levels[cursor->rowid.slot])));
        cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
        cursor->rowid.slot++;
        return CT_SUCCESS;
    }
    if (cursor->rowid.vmid >= ctx->buf_set_count) {
        cursor->eof = CT_TRUE;
    }
    return CT_SUCCESS;
}

static inline char *vw_effect_stat(config_effect_t effect)
{
    switch (effect) {
        case EFFECT_IMMEDIATELY:
            return "immediately";
        case EFFECT_RECONNECT:
            return "re-connect";
        case EFFECT_REBOOT:

        default:
            return "reboot";
    }
}

static status_t vm_put_item_value(row_assist_t *ra, config_item_t *item, bool32 is_vm_user)
{
    log_param_t *log_param = cm_log_param_instance();
    char arch_dest[CT_FILE_NAME_BUFFER_SIZE];
    uint32 len = (uint32)strlen("ARCHIVE_DEST_1");

    if (cm_strcmpni(item->name, "ALARM_LOG_DIR", strlen("ALARM_LOG_DIR")) == 0) {
        CT_RETURN_IFERR(row_put_str(ra, g_instance->kernel.alarm_log_dir));
    } else if (cm_strcmpni(item->name, "LOG_HOME", strlen("LOG_HOME")) == 0) {
        CT_RETURN_IFERR(row_put_str(ra, log_param->log_home));
    } else if (strlen(item->name) == len && cm_strcmpni(item->name, "ARCHIVE_DEST_1", len) == 0 && item->is_default) {
        if (!is_vm_user) {
            PRTS_RETURN_IFERR(snprintf_s(arch_dest, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1,
                "%s/archive_log", g_instance->kernel.home));

            CT_RETURN_IFERR(row_put_str(ra, arch_dest));
        }
    } else {
        CT_RETURN_IFERR(row_put_str(ra, item->is_default ? item->default_value : item->value));
    }
    return CT_SUCCESS;
}

status_t vw_param_put_name(row_assist_t *ra, knl_cursor_t *cursor, const char *name)
{
    if (IS_LOG_LEVEL(name)) {
        switch (cursor->rowid.vm_slot) {
            case LOG_LEVEL_MODE_VIEW:
                CT_RETURN_IFERR(row_put_str(ra, "_LOG_LEVEL_MODE"));
                break;
            default:
                CT_RETURN_IFERR(row_put_str(ra, "_LOG_LEVEL"));
                break;
        }
    } else {
        CT_RETURN_IFERR(row_put_str(ra, name));
    }
    return CT_SUCCESS;
}

status_t vw_param_put_on_off(row_assist_t *ra, bool32 is_on)
{
    if (is_on) {
        CT_RETURN_IFERR(row_put_str(ra, "ON"));
    } else {
        CT_RETURN_IFERR(row_put_str(ra, "OFF"));
    }
    return CT_SUCCESS;
}

status_t vw_param_put_log_mode(row_assist_t *ra, uint32 log_level_value_int)
{
    if (LOG_FATAL_ON(log_level_value_int)) {
        CT_RETURN_IFERR(row_put_str(ra, "FATAL"));
    } else if (LOG_DEBUG_ON(log_level_value_int)) {
        CT_RETURN_IFERR(row_put_str(ra, "DEBUG"));
    } else if (LOG_WARN_ON(log_level_value_int)) {
        CT_RETURN_IFERR(row_put_str(ra, "WARN"));
    } else if (LOG_ERROR_ON(log_level_value_int)) {
        CT_RETURN_IFERR(row_put_str(ra, "ERROR"));
    } else if (LOG_RUN_ON(log_level_value_int)) {
        CT_RETURN_IFERR(row_put_str(ra, "RUN"));
    } else {
        CT_RETURN_IFERR(row_put_str(ra, "USER_DEFINE"));
    }
    return CT_SUCCESS;
}

status_t vw_param_put_value(row_assist_t *ra, knl_cursor_t *cursor, config_item_t *item, const char *name,
    const char *value, bool32 is_default_value)
{
    if (IS_LOG_LEVEL(name) && cursor->rowid.vm_slot != 0) {
        uint32 log_level_value_int;
        cm_str2uint32(value, &log_level_value_int);
        switch (cursor->rowid.vm_slot) {
            case LOG_LEVEL_MODE_VIEW:
                CT_RETURN_IFERR(vw_param_put_log_mode(ra, log_level_value_int));
                break;
            default:
                return CT_ERROR;
        }
    } else if (is_default_value) {
        CT_RETURN_IFERR(row_put_str(ra, value));
    } else {
        CT_RETURN_IFERR(vm_put_item_value(ra, item, CT_FALSE));
    }

    return CT_SUCCESS;
}

status_t vw_param_put_range(row_assist_t *ra, knl_cursor_t *cursor, config_item_t *item)
{
    if (IS_LOG_LEVEL(item->name) && cursor->rowid.vm_slot != 0) {
        switch (cursor->rowid.vm_slot) {
            case LOG_LEVEL_MODE_VIEW:
                CT_RETURN_IFERR(row_put_str(ra, "FATAL,DEBUG,ERROR,WARN,RUN,USER_DEFINE"));
                break;
            default:
                return CT_ERROR;
        }
    } else {
        CT_RETURN_IFERR(row_put_str(ra, item->range));
    }
    return CT_SUCCESS;
}

status_t vw_param_put_datatype(row_assist_t *ra, knl_cursor_t *cursor, config_item_t *item)
{
    if (IS_LOG_LEVEL(item->name) && cursor->rowid.vm_slot != 0) {
        switch (cursor->rowid.vm_slot) {
            case LOG_LEVEL_MODE_VIEW:
                CT_RETURN_IFERR(row_put_str(ra, "CT_TYPE_VARCHAR"));
                break;
            default:
                return CT_ERROR;
        }
    } else {
        CT_RETURN_IFERR(row_put_str(ra, item->datatype));
    }
    return CT_SUCCESS;
}

void vw_param_slot_next(config_item_t *item, knl_cursor_t *cursor)
{
    if (IS_LOG_LEVEL(item->name) && cursor->rowid.vm_slot <= LOG_MODE_PARAMETER_COUNT) {
        cursor->rowid.vm_slot++;
    } else {
        if (item->alias != NULL && cursor->rowid.vm_slot == 0) {
            cursor->rowid.vm_slot++;
        } else {
            cursor->rowid.vmid++;
            cursor->rowid.vm_slot = 0;
        }
    }

    if (IS_LOG_LEVEL(item->name) && cursor->rowid.vm_slot > LOG_MODE_PARAMETER_COUNT) {
        cursor->rowid.vmid++;
        cursor->rowid.vm_slot = 0;
    }
}

static status_t vw_parameter_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    uint64 id;
    row_assist_t ra;
    const char *name;
    const char *value;
    knl_session_t *sess = (knl_session_t *)session;
    knl_attr_t *attr = &sess->kernel->attr;
    config_item_t *items = attr->config->items;
    uint32 param_count = attr->config->item_count;
    id = cursor->rowid.vmid;

    if (id >= param_count) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    name = items[id].name;
    value = items[id].is_default ? items[id].default_value : items[id].value;

    while (items[id].attr & ATTR_HIDDEN) {
        cursor->rowid.vmid++;
        id++;
        if (id >= param_count) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }
    }

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, PARAMETER_COLS);
    // hit scenario: ensure compatibility of parameters,
    // ex select * from DV_PARAMETER where name = UPPER('COMMIT_LOGGING')
    if (cursor->rowid.vm_slot == 0) {
        CT_RETURN_IFERR(row_put_str(&ra, items[id].name));
    } else if (IS_LOG_LEVEL(name)) {
        CT_RETURN_IFERR(vw_param_put_name(&ra, cursor, name));
    } else {
        CT_RETURN_IFERR(row_put_str(&ra, items[id].alias));
    }

    CT_RETURN_IFERR(vw_param_put_value(&ra, cursor, &items[id], name, value, CT_FALSE));

    if (items[id].effect == EFFECT_REBOOT && !cm_str_equal(items[id].name, "HAVE_SSL") &&
        !cm_str_equal(items[id].name, "LOG_HOME")) {
        CT_RETURN_IFERR(row_put_str(&ra, items[id].runtime_value));
    } else {
        CT_RETURN_IFERR(vw_param_put_value(&ra, cursor, &items[id], name, value, CT_FALSE));
    }
    CT_RETURN_IFERR(vw_param_put_value(&ra, cursor, &items[id], name, items[id].default_value, CT_TRUE));
    CT_RETURN_IFERR(row_put_str(&ra, items[id].is_default ? "TRUE" : "FALSE"));
    CT_RETURN_IFERR(row_put_str(&ra, (items[id].attr & ATTR_READONLY) ? "FALSE" : "TRUE"));
    CT_RETURN_IFERR(row_put_str(&ra, items[id].description));
    CT_RETURN_IFERR(vw_param_put_range(&ra, cursor, &items[id]));
    CT_RETURN_IFERR(vw_param_put_datatype(&ra, cursor, &items[id]));

    CT_RETURN_IFERR(row_put_str(&ra, vw_effect_stat(items[id].effect)));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    // hit scenario: ensure compatibility of parameters,
    // ex select * from DV_PARAMETER where name = UPPER('COMMIT_LOGGING
    vw_param_slot_next(&items[id], cursor);

    return CT_SUCCESS;
}

static status_t vw_user_parameter_put_row(knl_handle_t session, knl_cursor_t *cursor, uint64 id, config_item_t *items)
{
    row_assist_t ra;

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, PARAMETER_COLS);
    // hit scenario: ensure compatibility of parameters,
    // ex select * from DV_PARAMETER where name = UPPER('COMMIT_LOGGING')
    if (cursor->rowid.vm_slot == 0) {
        CT_RETURN_IFERR(row_put_str(&ra, items[id].name));
    } else {
        CT_RETURN_IFERR(row_put_str(&ra, items[id].alias));
    }

    CT_RETURN_IFERR(vm_put_item_value(&ra, &items[id], CT_TRUE));
    if (items[id].effect == EFFECT_REBOOT && !cm_str_equal(items[id].name, "HAVE_SSL") &&
        !cm_str_equal(items[id].name, "LOG_HOME")) {
        CT_RETURN_IFERR(row_put_str(&ra, items[id].runtime_value));
    } else {
        CT_RETURN_IFERR(vm_put_item_value(&ra, &items[id], CT_TRUE));
    }

    CT_RETURN_IFERR(row_put_str(&ra, items[id].default_value));
    CT_RETURN_IFERR(row_put_str(&ra, items[id].is_default ? "TRUE" : "FALSE"));
    CT_RETURN_IFERR(row_put_str(&ra, (items[id].attr & ATTR_READONLY) ? "FALSE" : "TRUE"));
    CT_RETURN_IFERR(row_put_str(&ra, items[id].description));
    CT_RETURN_IFERR(row_put_str(&ra, items[id].range));
    CT_RETURN_IFERR(row_put_str(&ra, items[id].datatype));
    CT_RETURN_IFERR(row_put_str(&ra, vw_effect_stat(items[id].effect)));

    return CT_SUCCESS;
}

static status_t vw_user_parameter_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    uint64 id = cursor->rowid.vmid;
    knl_session_t *sess = (knl_session_t *)session;
    knl_attr_t *attr = &sess->kernel->attr;
    config_item_t *items = attr->config->items;
    uint32 param_count = attr->config->item_count;

    if (id >= param_count) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    while (!(cm_str_equal(items[id].name, "UPPER_CASE_TABLE_NAMES")) &&
        !(cm_str_equal(items[id].name, "EMPTY_STRING_AS_NULL"))) {
        cursor->rowid.vmid++;
        id++;
        if (id >= param_count) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }
    }

    CT_RETURN_IFERR(vw_user_parameter_put_row(session, cursor, id, items));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    // hit scenario: ensure compatibility of parameters,
    // ex select * from DV_PARAMETER where name = UPPER('COMMIT_LOGGING')
    if (items[id].alias != NULL && cursor->rowid.vm_slot == 0) {
        cursor->rowid.vm_slot++;
    } else {
        cursor->rowid.vmid++;
        cursor->rowid.vm_slot = 0;
    }
    return CT_SUCCESS;
}

static status_t vw_debug_parameter_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    row_assist_t ra;
    uint32 param_count;
    uint64 id = cursor->rowid.vmid;
    debug_config_item_t *items = NULL;

    srv_get_debug_config_info(&items, &param_count);
    if (id >= param_count) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, KNL_DEBUG_PARAMETER_COLS);
    CT_RETURN_IFERR(row_put_str(&ra, items[id].name));
    CT_RETURN_IFERR(row_put_str(&ra, items[id].default_value));
    CT_RETURN_IFERR(row_put_str(&ra, items[id].curr_value));
    CT_RETURN_IFERR(row_put_str(&ra, items[id].range));
    CT_RETURN_IFERR(row_put_str(&ra, items[id].datatype));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);

    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

static status_t vw_db_object_cache_fetch_core(knl_handle_t session, knl_cursor_t *cursor)
{
    uint64 group_id, entry_id;
    uint32 hash;
    dc_user_t *user = NULL;
    row_assist_t ra;
    text_t status, table_name;
    char dict_type[CT_MAX_DCTYPE_STR_LEN] = { '\0' };
    knl_session_t *sess = (knl_session_t *)session;
    dc_context_t *ctx = &sess->kernel->dc_ctx;

    if (!vm_dc_scan_user(session, ctx, cursor)) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    if (dc_open_user_by_id(session, (uint32)cursor->rowid.vmid, &user) != CT_SUCCESS) {
        cm_reset_error();
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    cursor->tenant_id = user->desc.tenant_id;
    group_id = cursor->rowid.vm_slot;
    entry_id = cursor->rowid.vm_tag;
    dc_entry_t *entry = user->groups[group_id]->entries[entry_id];

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, DB_OBJECT_CACHE_COLS);
    CT_RETURN_IFERR(row_put_str(&ra, user->desc.name));
    CT_RETURN_IFERR(row_put_str(&ra, entry->name));
    CT_RETURN_IFERR(row_put_str(&ra, "namespace"));

    const char *dictionary_type = dc_type2name(entry->type);
    if (strlen(dictionary_type) != 0) {
        MEMS_RETURN_IFERR(strcpy_s(dict_type, CT_MAX_DCTYPE_STR_LEN, dictionary_type));
    }

    CT_RETURN_IFERR(row_put_str(&ra, dict_type));

    if (entry->entity == NULL) {
        CT_RETURN_IFERR(row_put_int32(&ra, (int32)CT_FALSE));
        CT_RETURN_IFERR(row_put_int32(&ra, (int32)0));
    } else {
        CT_RETURN_IFERR(row_put_int32(&ra, (int32)CT_TRUE));
        CT_RETURN_IFERR(row_put_int32(&ra, (int32)(entry->entity->ref_count)));
    }

    cm_str2text(entry->name, &table_name);
    hash = dc_hash(&table_name);
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)hash));

    char *lock_mod = lock_mode_string(entry);
    CT_RETURN_IFERR(row_put_str(&ra, lock_mod));

    dc_get_entry_status(entry, &status);
    CT_RETURN_IFERR(row_put_str(&ra, status.str));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vm_slot++;
    return CT_SUCCESS;
}

static status_t vw_db_object_cache_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    return vw_fetch_for_tenant(vw_db_object_cache_fetch_core, session, cursor);
}

static status_t vw_buffer_access_stat_fetch_core(knl_handle_t handle, knl_cursor_t *cursor)
{
    session_t *item = NULL;
    knl_session_t *session = NULL;
    row_assist_t ra;
    knl_stat_t stat;

    MEMS_RETURN_IFERR(memset_s(&stat, sizeof(knl_stat_t), 0, sizeof(knl_stat_t)));

    while (1) {
        if (cursor->rowid.vmid >= g_instance->session_pool.hwm) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }

        item = g_instance->session_pool.sessions[cursor->rowid.vmid];
        session = &item->knl_session;

        uint16 stat_id = session->stat_id;
        if (stat_id == CT_INVALID_ID16) {
            cursor->rowid.vmid++;
            continue;
        }

        stat = *g_instance->stat_pool.stats[stat_id];
        if (stat.buffer_gets != 0) {
            break;
        }
        cursor->rowid.vmid++;
    };

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, BUFFER_ACCESS_STATS_COLS);
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)session->id));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)stat.buffer_gets));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)stat.disk_reads));
    CT_RETURN_IFERR(row_put_real(&ra, 1 - (double)stat.disk_reads / (double)stat.buffer_gets));
    cursor->tenant_id = item->curr_tenant_id;
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;

    return CT_SUCCESS;
}

static status_t vw_buffer_access_stat_fetch(knl_handle_t handle, knl_cursor_t *cursor)
{
    return vw_fetch_for_tenant(vw_buffer_access_stat_fetch_core, handle, cursor);
}

static status_t vw_buffer_recycle_stat_fetch_core(knl_handle_t handle, knl_cursor_t *cursor)
{
    session_t *item = NULL;
    knl_session_t *session = NULL;
    row_assist_t ra;
    knl_stat_t stat;

    MEMS_RETURN_IFERR(memset_s(&stat, sizeof(knl_stat_t), 0, sizeof(knl_stat_t)));

    while (1) {
        if (cursor->rowid.vmid >= g_instance->session_pool.hwm) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }

        item = g_instance->session_pool.sessions[cursor->rowid.vmid];
        session = &item->knl_session;

        uint16 stat_id = session->stat_id;
        if (stat_id == CT_INVALID_ID16) {
            cursor->rowid.vmid++;
            continue;
        }

        stat = *g_instance->stat_pool.stats[stat_id];
        if (stat.buffer_recycle_cnt != 0) {
            break;
        }
        cursor->rowid.vmid++;
    };

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, BUFFER_RECYCLE_STATS_COLS);
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)session->id));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)stat.buffer_recycle_cnt));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)stat.buffer_recycle_wait));
    CT_RETURN_IFERR(row_put_real(&ra, (double)stat.buffer_recycle_step / (double)stat.buffer_recycle_cnt));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)stat.spin_stat.stat_buffer.spins));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)stat.spin_stat.stat_buffer.wait_usecs));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)stat.spin_stat.stat_buffer.fails));
    cursor->tenant_id = item->curr_tenant_id;
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;

    return CT_SUCCESS;
}

static status_t vw_buffer_recycle_stat_fetch(knl_handle_t handle, knl_cursor_t *cursor)
{
    return vw_fetch_for_tenant(vw_buffer_recycle_stat_fetch_core, handle, cursor);
}

static status_t vw_tablespaces_fetch_one_space(knl_handle_t session, knl_cursor_t *cursor, uint32 space_id)
{
    row_assist_t row;
    knl_session_t *sess = (knl_session_t *)session;
    database_t *db = &sess->kernel->db;
    session_t *se = (session_t *)session;
    dc_tenant_t *tenant = NULL;

    space_t *space = &db->spaces[space_id];
    int32 segment_count = 0;
    int32 datafile_count = 0;
    int64 punched_size = 0;

    row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, TABLESPACES_COLS);
    CT_RETURN_IFERR(row_put_int32(&row, (int32)space->ctrl->id));
    CT_RETURN_IFERR(row_put_str(&row, space->ctrl->name));
    CT_RETURN_IFERR(row_put_str(&row, IS_TEMP_SPACE(space) ? "TRUE" : "FALSE"));
    CT_RETURN_IFERR(row_put_str(&row, SPACE_IS_INMEMORY(space) ? "TRUE" : "FALSE"));
    CT_RETURN_IFERR(row_put_str(&row, SPACE_IS_AUTOPURGE(space) ? "TRUE" : "FALSE"));
    CT_RETURN_IFERR(row_put_int32(&row, (int32)space->ctrl->extent_size));

    space_head_t *head = SPACE_HEAD_RESIDENT(session, space);
    if (head != NULL) {
        segment_count = (int32)(head->segment_count);
        datafile_count = (int32)(head->datafile_count);
        punched_size =
            (int64)(spc_get_punch_extents(&se->knl_session, space)) * space->ctrl->extent_size *
            DEFAULT_PAGE_SIZE(session);
    }
    CT_RETURN_IFERR(row_put_int32(&row, segment_count));
    CT_RETURN_IFERR(row_put_int32(&row, datafile_count));
    CT_RETURN_IFERR(row_put_str(&row, SPACE_IS_ONLINE(space) ? "ONLINE" : "OFFLINE"));
    CT_RETURN_IFERR(row_put_str(&row, SPACE_IS_AUTOOFFLINE(space) ? "TRUE" : "FALSE"));
    CT_RETURN_IFERR(row_put_str(&row, SPACE_IS_BITMAPMANAGED(space) ? "MAP" : "NORMAL"));
    CT_RETURN_IFERR(row_put_str(&row, SPACE_IS_AUTOALLOCATE(space) ? "AUTO" : "UNIFORM"));
    CT_RETURN_IFERR(row_put_str(&row, SPACE_IS_ENCRYPT(space) ? "TRUE" : "FALSE"));
    CT_RETURN_IFERR(row_put_int64(&row, punched_size));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    if (IS_DEFAULT_SPACE(space) && space_id != FIXED_USER_SPACE_ID) {
        cursor->tenant_id = se->curr_tenant_id;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(dc_open_tenant_by_id(&se->knl_session, se->curr_tenant_id, &tenant));
    if (dc_get_tenant_tablespace_bitmap(&tenant->desc, space_id)) {
        cursor->tenant_id = se->curr_tenant_id;
    } else {
        cursor->tenant_id = SYS_TENANTROOT_ID;
    }
    dc_close_tenant(&se->knl_session, tenant->desc.id);
    return CT_SUCCESS;
}

static status_t vw_tablespaces_fetch_core(knl_handle_t session, knl_cursor_t *cursor)
{
    knl_session_t *sess = (knl_session_t *)session;
    database_t *db = &sess->kernel->db;
    if (cursor->rowid.vmid >= CT_MAX_SPACES) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    space_t *space = &db->spaces[(cursor->rowid.vmid)];
    dls_spin_lock(sess, &space->lock, &sess->stat->spin_stat.stat_space);
    while (!space->ctrl->used) {
        dls_spin_unlock(sess, &space->lock);
        cursor->rowid.vmid++;
        if (cursor->rowid.vmid >= CT_MAX_SPACES) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }

        space = &db->spaces[(cursor->rowid.vmid)];
        dls_spin_lock(sess, &space->lock, &sess->stat->spin_stat.stat_space);
    }

    CT_RETURN_IFERR(vw_tablespaces_fetch_one_space(session, cursor, (uint32)cursor->rowid.vmid));
    dls_spin_unlock(sess, &space->lock);
    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

static status_t vw_tablespaces_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    return vw_fetch_for_tenant(vw_tablespaces_fetch_core, session, cursor);
}

static status_t vw_archived_log_fetch_row(knl_handle_t session, knl_cursor_t *cursor, arch_ctrl_t *ctrl)
{
    row_assist_t ra;
    struct timeval time_val;
    date_t time = cm_now();

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, ARCHIVED_LOG_COLS);
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)ctrl->recid));   // recid
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)ctrl->stamp));   // stamp
    CT_RETURN_IFERR(row_put_str(&ra, ctrl->name));             // name
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)ctrl->dest_id)); // dest_id
    CT_RETURN_IFERR(row_put_int32(&ra, 0));                    // THREAD#
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)ctrl->asn));     // SEQUENCE#
    CT_RETURN_IFERR(row_put_int32(&ra, 0));                    // RESETLOGS_CHANGE#
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)time));          // RESETLOGS_TIME
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)ctrl->rst_id));  // RESETLOGS_ID
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)ctrl->first));   // FIRST_CHANGE#
    knl_scn_to_timeval(session, ctrl->first, &time_val);
    time = cm_timeval2date(time_val);
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)time));       // FIRST_TIME
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)ctrl->last)); // NEXT_CHANGE#
    knl_scn_to_timeval(session, ctrl->last, &time_val);
    time = cm_timeval2date(time_val);
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)time));                           // NEXT_TIME
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)ctrl->blocks));                   // BLOCKS
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)ctrl->block_size));               // BLOCK_SIZE
    CT_RETURN_IFERR(row_put_str(&ra, "ARCH"));                                  // CREATOR
    CT_RETURN_IFERR(row_put_str(&ra, "ARCH"));                                  // REGISTRAR
    CT_RETURN_IFERR(row_put_str(&ra, "NO"));                                    // STANDBY_DEST
    CT_RETURN_IFERR(row_put_str(&ra, "NO"));                                    // ARCHIVED
    CT_RETURN_IFERR(row_put_str(&ra, "YES"));                                   // APPLIED
    CT_RETURN_IFERR(row_put_str(&ra, "NO"));                                    // DELETED
    CT_RETURN_IFERR(row_put_str(&ra, "U"));                                     // STATUS
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)ctrl->stamp));                    // COMPLETION_TIME
    CT_RETURN_IFERR(row_put_str(&ra, "NO"));                                    // DICTIONARY_BEGIN
    CT_RETURN_IFERR(row_put_str(&ra, "NO"));                                    // DICTIONARY_END
    CT_RETURN_IFERR(row_put_str(&ra, "NO"));                                    // END_OF_REDO
    CT_RETURN_IFERR(row_put_int64(&ra, 0));                                     // BACKUP_COUNT
    CT_RETURN_IFERR(row_put_int32(&ra, 0));                                     // ARCHIVAL_THREAD#
    CT_RETURN_IFERR(row_put_int32(&ra, 0));                                     // ACTIVATION#
    CT_RETURN_IFERR(row_put_str(&ra, "NO"));                                    // IS_RECOVERY_DEST_FILE
    CT_RETURN_IFERR(row_put_str(&ra, arch_is_compressed(ctrl) ? "YES" : "NO")); // COMPRESSED
    CT_RETURN_IFERR(row_put_str(&ra, "NO"));                                    // FAL
    CT_RETURN_IFERR(row_put_str(&ra, ""));                                      // END_OF_REDO_TYPE
    CT_RETURN_IFERR(row_put_str(&ra, "NO"));                                    // BACKED_BY_VSS
    CT_RETURN_IFERR(row_put_int32(&ra, 0));                                     // CON_ID
    CT_RETURN_IFERR(row_put_int64(&ra, arch_get_ctrl_real_size(ctrl)));         // REAL_SIZE
    CT_RETURN_IFERR(row_put_int64(&ra, ctrl->start_lsn));                       // START_LSN
    CT_RETURN_IFERR(row_put_int64(&ra, ctrl->end_lsn));                         // END_LSN

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    return CT_SUCCESS;
}

static status_t vw_archived_log_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    arch_ctrl_t *ctrl = NULL;
    knl_session_t *ss = (knl_session_t *)session;

    if (cursor->rowid.vmid == 0) {
        cursor->rowid.vmid = arch_get_arch_start(ss, ss->kernel->id);
    }

    for (;;) {
        uint32 id = cursor->rowid.vmid % CT_MAX_ARCH_NUM;
        ctrl = db_get_arch_ctrl(ss, id, ss->kernel->id);
        if (id == arch_get_arch_end(ss, ss->kernel->id)) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }

        ctrl = db_get_arch_ctrl(session, id, ss->kernel->id);
        if (ctrl->recid == 0) {
            cursor->rowid.vmid++;
            continue;
        }
        break;
    }

    CT_RETURN_IFERR(vw_archived_log_fetch_row(session, cursor, ctrl));

    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

static status_t vw_temp_archived_log_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    knl_session_t *ss = (knl_session_t *)session;
    row_assist_t ra;
    uint64 id;
    char arch_dest[CT_FILE_NAME_BUFFER_SIZE];

    id = cursor->rowid.vmid;
    if (id >= 1) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }
    PRTS_RETURN_IFERR(snprintf_s(arch_dest, sizeof(arch_dest), sizeof(arch_dest) - 1, "%s/%uarch_file.tmp",
            ss->kernel->arch_ctx.arch_proc[0].arch_dest, ss->kernel->id));
    if (access(arch_dest, F_OK) != CT_SUCCESS) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, TEMP_ARCHIVED_LOG_COLS);
    CT_RETURN_IFERR(row_put_str(&ra, arch_dest));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

static status_t vw_archive_gap_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    uint64 id;
    row_assist_t ra;
    uint32 low_rstid, high_rstid;
    uint32 low_asn, high_asn;
    char low_seq[CT_NAME_BUFFER_SIZE];
    char high_seq[CT_NAME_BUFFER_SIZE];

    if (knl_db_is_primary(session)) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    id = cursor->rowid.vmid;
    if (id >= 1) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    knl_get_low_arch(session, &low_rstid, &low_asn);
    knl_get_high_arch(session, &high_rstid, &high_asn);
    if (low_rstid == high_rstid && low_asn >= high_asn) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    PRTS_RETURN_IFERR(snprintf_s(low_seq, CT_NAME_BUFFER_SIZE, CT_NAME_BUFFER_SIZE - 1, "%u_%u", low_rstid, low_asn));
    PRTS_RETURN_IFERR(
        snprintf_s(high_seq, CT_NAME_BUFFER_SIZE, CT_NAME_BUFFER_SIZE - 1, "%u_%u", high_rstid, high_asn));

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, ARCHIVE_GAP_COLS);
    CT_RETURN_IFERR(row_put_int32(&ra, 1));
    CT_RETURN_IFERR(row_put_str(&ra, low_seq));
    CT_RETURN_IFERR(row_put_str(&ra, high_seq));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;

    return CT_SUCCESS;
}

static status_t vw_archive_processes_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    uint64 id;
    row_assist_t ra;

    id = cursor->rowid.vmid;
    if (id >= CT_MAX_ARCH_DEST) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    arch_context_t *ctx = &((knl_session_t *)session)->kernel->arch_ctx;
    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, ARCHIVE_PROCESS_COLS);
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)id));
    if (ctx->is_archive && ctx->arch_proc[id].enabled) {
        CT_RETURN_IFERR(row_put_str(&ra, "ACTIVE"));
    } else {
        CT_RETURN_IFERR(row_put_str(&ra, "STOPPED"));
    }

    CT_RETURN_IFERR(row_put_int32(&ra, 0)); // LOG_SEQUENCE

    if (ctx->is_archive && ctx->arch_proc[id].enabled) {
        if (ctx->arch_proc[id].alarmed) {
            CT_RETURN_IFERR(row_put_str(&ra, "FAIL")); // STATE
        } else {
            CT_RETURN_IFERR(row_put_str(&ra, "SUCC"));
        }
    } else {
        CT_RETURN_IFERR(row_put_str(&ra, "IDLE"));
    }

    CT_RETURN_IFERR(row_put_str(&ra, "NO_FAL")); // ROLES
    CT_RETURN_IFERR(row_put_int32(&ra, 0));      // CON_ID

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);

    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

static char *vm_get_arch_dest_status(knl_handle_t session, uint32 id, arch_attr_t *arch_attr)
{
    if (id == 0) {
        return "VALID";
    }

    if (knl_db_is_cascaded_standby(session) || !arch_attr->enable) {
        return "INACTIVE";
    }

    if ((knl_db_is_primary(session) && arch_attr->role_valid == VALID_FOR_PRIMARY_ROLE) ||
        (knl_db_is_physical_standby(session) && arch_attr->role_valid == VALID_FOR_STANDBY_ROLE)) {
        return "VALID";
    }

    return "INACTIVE";
}

static char *vm_get_arch_dest_mode(knl_handle_t session, uint32 id, bool32 peer_primary)
{
    if (knl_db_is_primary(session)) {
        if (id == 0) {
            return "READ-WRITE";
        } else {
            return "READ-ONLY";
        }
    } else {
        if (id == 0) {
            return "READ-ONLY";
        } else if (peer_primary) {
            return "READ-WRITE";
        } else {
            return "READ-ONLY";
        }
    }
}

static char *vm_get_instance_name(knl_handle_t session, uint32 id)
{
    uint32 i, param_count;
    knl_attr_t *attr = &((knl_session_t *)session)->kernel->attr;
    config_item_t *items = attr->config->items;

    if (id == 0) {
        param_count = attr->config->item_count;
        for (i = 0; i < param_count; i++) {
            if (!strcmp(items[i].name, "INSTANCE_NAME")) {
                return items[i].value ? items[i].value : items[i].default_value;
            }
        }
    }

    return "";
}

static status_t vw_archive_status_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    uint64 id;
    row_assist_t ra;
    char dest_name[CT_FILE_NAME_BUFFER_SIZE];
    char dest_path[CT_FILE_NAME_BUFFER_SIZE + CT_HOST_NAME_BUFFER_SIZE + 10]; /* 10 bytes for format "[%s:%u] %s" and
                                                                                 port length */
    knl_attr_t *attr = &((knl_session_t *)session)->kernel->attr;
    database_t *db = &((knl_session_t *)session)->kernel->db;
    bool32 peer_primary = CT_FALSE;
    arch_dest_sync_t sync;

    id = cursor->rowid.vmid;
    if (id >= CT_MAX_ARCH_DEST) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, ARCHIVE_STATUS_COLS);
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)id)); // DEST_ID
    PRTS_RETURN_IFERR(
        snprintf_s(dest_name, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1, "ARCHIVE_DEST_%llu", id + 1));

    CT_RETURN_IFERR(row_put_str(&ra, dest_name)); // DEST_NAME
    arch_attr_t *arch_attr = &attr->arch_attr[id];
    CT_RETURN_IFERR(row_put_str(&ra, vm_get_arch_dest_status(session, (uint32)id, arch_attr)));               // STATUS
    CT_RETURN_IFERR(row_put_str(&ra, knl_get_arch_dest_type(session, (uint32)id, arch_attr, &peer_primary))); // TYPE
    CT_RETURN_IFERR(row_put_str(&ra, vm_get_arch_dest_mode(session, (uint32)id, peer_primary))); // DATABASE_MODE
    // PROTECTION_MODE
    CT_RETURN_IFERR(row_put_str(&ra, (db->ctrl.core.protect_mode == MAXIMUM_PROTECTION ?
        "MAXIMUM PROTECTION" :
        (db->ctrl.core.protect_mode == MAXIMUM_AVAILABILITY ? "MAXIMUM AVAILABILITY" : "MAXIMUM PERFORMANCE"))));
    knl_get_arch_dest_path(session, (uint32)id, arch_attr, dest_path,
        CT_FILE_NAME_BUFFER_SIZE + CT_HOST_NAME_BUFFER_SIZE + 10);
    CT_RETURN_IFERR(row_put_str(&ra, dest_path));                                 // DESTINATION
    CT_RETURN_IFERR(row_put_str(&ra, vm_get_instance_name(session, (uint32)id))); // DB_UNIQUE_NAME
    CT_RETURN_IFERR(row_put_str(&ra, knl_get_arch_sync_status(session, (uint32)id, arch_attr,
        &sync)));                                                // SYNCHRONIZATION_STATUS
    CT_RETURN_IFERR(row_put_str(&ra, knl_get_arch_sync(&sync))); // SYNCHRONIZED

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;

    return CT_SUCCESS;
}

const char rcy_page_names[][CT_MAX_NAME_LEN] = {
    "FREE_PAGE",
    "SPACE_HEAD", // space head page
    "HEAP_HEAD",  // heap segment page
    "HEAP_MAP",   // heap map page
    "HEAP_DATA",  // heap page
    "UNDO_HEAD",  // undo segment page
    "TXN_PAGE",   // txn page
    "UNDO_PAGE",  // undo page
    "BTREE_HEAD", // btree segment page
    "BTREE_NODE", // btree page
    "LOB_HEAD",   // lob segment page
    "LOB_DATA",   // lob data page
    "TEMP_HEAP",  // temp heap page
    "TEMP_INDEX", // temp index page
    "NONE_PAGE",
    "FILE_HEAD",
    "CTRL",
    "PCRH_DATA",
    "PCRB_NODE",
    "DF_MAP_HEAD",
    "DF_MAP_DATA",
};

const char rcy_wait_names[][CT_MAX_NAME_LEN] = {
    "TXN_END_WAIT",
    "PRELOAD_DISK_PAGES",
    "PRELOAD_BUFFER_PAGES",
    "LOGIC_GROUP_COUNT",
    "WAIT_RELAPY_COUNT",
    "PRELOAD_NO_READ",
    "PRELOAD_REAMIN",
    "READ_LOG_TIME(ms)",
    "PROC_WAIT_TIME(ms)",
    "GROUP_ANALYZE_TIME(ms)",
    "READ_LOG_SIZE(M)",
    "REPALY_SPEED(M/s)",
    "ADD_PAGE_TIME(ms)",
    "ADD_BUCKET_TIME(ms)",
    "BUCKET_OVERFLOW_COUNT",
    "PRELOAD_WAIT_TIME(ms)",
};

static status_t vw_rcywait_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    uint64 id;
    row_assist_t ra;
    knl_session_t *session = (knl_session_t *)se;
    rcy_context_t *rcy = &session->kernel->rcy_ctx;

    id = cursor->rowid.vmid;
    if (id >= RCY_WAIT_STATS_COUNT) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, RCYWAIT_COLS);

    if (id < PAGE_TYPE_COUNT) {
        CT_RETURN_IFERR(row_put_str(&ra, rcy_page_names[id]));
    } else {
        CT_RETURN_IFERR(row_put_str(&ra, rcy_wait_names[id - PAGE_TYPE_COUNT]));
    }

    if ((int64)rcy->wait_stats_view[id] < 0) {
        rcy->wait_stats_view[id] = 0;
    }
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)rcy->wait_stats_view[id]));

    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

static inline void vw_row_set_database_state(row_assist_t *ra, db_status_t status)
{
    switch (status) {
        case DB_STATUS_CLOSED:
            (void)row_put_str(ra, "CLOSED");
            break;
        case DB_STATUS_NOMOUNT:
            (void)row_put_str(ra, "NOMOUNT");
            break;
        case DB_STATUS_CREATING:
            (void)row_put_str(ra, "CREATING");
            break;
        case DB_STATUS_MOUNT:
            (void)row_put_str(ra, "MOUNT");
            break;
        case DB_STATUS_REDO_ANALYSIS:
            (void)row_put_str(ra, "RECOVERY");
            break;
        case DB_STATUS_RECOVERY:
            (void)row_put_str(ra, "RECOVERY");
            break;
        case DB_STATUS_INIT_PHASE2:
            (void)row_put_str(ra, "INIT_PHASE");
            break;
        case DB_STATUS_WAIT_CLEAN:
            (void)row_put_str(ra, "WAIT CLEAN");
            break;
        case DB_STATUS_OPEN:
            (void)row_put_str(ra, "OPEN");
            break;
        default:
            (void)row_put_str(ra, "UNKNOWN STATE");
            break;
    }
}

static inline void vw_row_set_database_open_state(row_assist_t *ra, database_t *db)
{
    if (db->status == DB_STATUS_OPEN) {
        if (db->open_status >= DB_OPEN_STATUS_UPGRADE) {
            (void)row_put_str(ra, "UPGRADE");
        } else if (db->open_status == DB_OPEN_STATUS_RESTRICT) {
            (void)row_put_str(ra, "RESTRICTED");
        } else if (db->is_readonly) {
            (void)row_put_str(ra, "READ ONLY");
        } else {
            (void)row_put_str(ra, "READ WRITE");
        }
    } else {
        (void)row_put_str(ra, "MOUNTED");
    }
}

static inline void vw_row_set_database_role(row_assist_t *ra, repl_role_t role)
{
    switch (role) {
        case REPL_ROLE_PRIMARY:
            (void)row_put_str(ra, "PRIMARY");
            break;
        case REPL_ROLE_PHYSICAL_STANDBY:
            (void)row_put_str(ra, "PHYSICAL_STANDBY");
            break;
        case REPL_ROLE_CASCADED_PHYSICAL_STANDBY:
            (void)row_put_str(ra, "CASCADED_PHYSICAL_STANDBY");
            break;
        default:
            (void)row_put_str(ra, "UNKNOWN ROLE");
            break;
    }
}

static status_t vw_database_fetch_row(knl_handle_t session, row_assist_t *row, database_t *db)
{
    char str[1024];
    knl_session_t *se = (knl_session_t *)session;
    dtc_node_ctrl_t *dtc_ctrl = dtc_my_ctrl(se);
    log_point_t *point = &dtc_ctrl->rcy_point;
    PRTS_RETURN_IFERR(sprintf_s(str, sizeof(str), "rst_id(%llu)-asn(%llu)-block_id(%u)-lfn(%llu)-lsn(%llu)",
        (uint64)point->rst_id, (uint64)point->asn, point->block_id, (uint64)point->lfn, point->lsn));
    CT_RETURN_IFERR(row_put_str(row, str));
    point = &dtc_ctrl->lrp_point;
    PRTS_RETURN_IFERR(sprintf_s(str, sizeof(str), "rst_id(%llu)-asn(%llu)-block_id(%u)-lfn(%llu)-lsn(%llu)",
        (uint64)point->rst_id, (uint64)point->asn, point->block_id, (uint64)point->lfn, point->lsn));
    CT_RETURN_IFERR(row_put_str(row, str));
    CT_RETURN_IFERR(row_put_int64(row, (int64)dtc_my_ctrl(session)->ckpt_id));
    CT_RETURN_IFERR(row_put_int64(row, (int64)se->kernel->lsn));
    CT_RETURN_IFERR(row_put_int64(row, (int64)se->kernel->lfn));
    CT_RETURN_IFERR(row_put_int32(row, (int32)dtc_my_ctrl(session)->log_count));
    CT_RETURN_IFERR(row_put_int32(row, (int32)dtc_my_ctrl(session)->log_first));
    CT_RETURN_IFERR(row_put_int32(row, (int32)dtc_my_ctrl(session)->log_last));
    CT_RETURN_IFERR(row_put_int64(row, (int64)(se->kernel->redo_ctx.free_size)));
    CT_RETURN_IFERR(row_put_str(row, (db->ctrl.core.log_mode == ARCHIVE_LOG_ON ? "ARCHIVELOG" : "NOARCHIVELOG")));
    CT_RETURN_IFERR(row_put_int32(row, (int32)db->ctrl.core.space_count));
    CT_RETURN_IFERR(row_put_int32(row, (int32)db->ctrl.core.device_count));

    CT_RETURN_IFERR(row_put_int32(row, (int32)se->kernel->ckpt_ctx.dw_ckpt_start));
    CT_RETURN_IFERR(row_put_int32(row, (int32)se->kernel->ckpt_ctx.dw_ckpt_end));
    CT_RETURN_IFERR(row_put_str(row, (db->ctrl.core.protect_mode == MAXIMUM_PROTECTION ?
        "MAXIMUM_PROTECTION" :
        (db->ctrl.core.protect_mode == MAXIMUM_AVAILABILITY ? "MAXIMUM_AVAILABILITY" : "MAXIMUM_PERFORMANCE"))));
    vw_row_set_database_role(row, db->ctrl.core.db_role);
    CT_RETURN_IFERR(row_put_str(row, db_get_condition(session)));
    CT_RETURN_IFERR(row_put_str(row, db_get_switchover_status(session)));
    CT_RETURN_IFERR(row_put_str(row, db_get_failover_status(session)));

    if (se->kernel->redo_ctx.files + se->kernel->redo_ctx.curr_file) {
        CT_RETURN_IFERR(row_put_int32(row,
            (int32)((se->kernel->redo_ctx.files + se->kernel->redo_ctx.curr_file)->head.asn)));
    } else {
        CT_RETURN_IFERR(row_put_int32(row, 0));
    }
    return CT_SUCCESS;
}

static status_t vw_get_node_ctrl_from_disk(knl_handle_t session, ctrl_page_t *page, uint32 id)
{
    knl_session_t *sess = (knl_session_t *)session;
    database_t *db = &(sess->kernel->db);
    ctrlfile_t *ctrlfile = NULL;
    uint32 ctrlfile_count = 0;

    cm_spin_lock(&db->ctrl_lock, NULL);
    while (ctrlfile_count < db->ctrlfiles.count) {
        ctrlfile = &db->ctrlfiles.items[ctrlfile_count];
        if (cm_open_device(ctrlfile->name, ctrlfile->type, knl_io_flag(sess), &ctrlfile->handle) != CT_SUCCESS) {
            ctrlfile_count++;
            continue;
        }

        if (cm_read_device(ctrlfile->type, ctrlfile->handle, (int64)(CTRL_LOG_SEGMENT + id) *
                           ctrlfile->block_size, page, ctrlfile->block_size) == CT_SUCCESS) {
            break;
        }
        ctrlfile_count++;
    }
    cm_spin_unlock(&db->ctrl_lock);

    if (ctrlfile_count >= db->ctrlfiles.count) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t vw_database_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    row_assist_t row;
    ddl_exec_status_t ddl_exec_stat;
    knl_session_t *sess = (knl_session_t *)session;
    database_t *db = &sess->kernel->db;
    char str[1024];
    if (cursor->rowid.vmid > 0) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, DATABASE_COLS);
    CT_RETURN_IFERR(row_put_int32(&row, (int32)db->ctrl.core.dbid));
    CT_RETURN_IFERR(row_put_str(&row, db->ctrl.core.name));
    vw_row_set_database_state(&row, db->status);
    vw_row_set_database_open_state(&row, db);
    CT_RETURN_IFERR(row_put_int32(&row, (int32)(db->ctrl.core.open_count)));
    (void)row_put_date(&row, (int64)cm_time2date(db->ctrl.core.init_time));

    CT_RETURN_IFERR(row_put_int64(&row, (int64)(sess->kernel->scn)));
    CT_RETURN_IFERR(vw_database_fetch_row(session, &row, db));

    char *page_buf = (char *)cm_push(sess->stack, (uint32)CT_DFLT_CTRL_BLOCK_SIZE + (uint32)CT_MAX_ALIGN_SIZE_4K);
    ctrl_page_t *page = (ctrl_page_t *)cm_aligned_buf(page_buf);
    if (vw_get_node_ctrl_from_disk(session, page, sess->kernel->id) != CT_SUCCESS) {
        cm_pop(sess->stack);
        return CT_ERROR;
    }
    uint64 rst_id = ((dtc_node_ctrl_t *)page->buf)->lrep_point.rst_id;
    uint64 asn = ((dtc_node_ctrl_t *)page->buf)->lrep_point.asn;
    uint32 block_id = ((dtc_node_ctrl_t *)page->buf)->lrep_point.block_id;
    uint64 lfn = ((dtc_node_ctrl_t *)page->buf)->lrep_point.lfn;
    cm_pop(sess->stack);

    PRTS_RETURN_IFERR(sprintf_s(str, sizeof(str), "%llu-%llu-%u-%llu", rst_id, asn, block_id, lfn));
    CT_RETURN_IFERR(row_put_str(&row, str));

    CT_RETURN_IFERR(row_put_str(&row, (db->ctrl.core.lrep_mode == LOG_REPLICATION_ON ? "ON" : "OFF")));
    CT_RETURN_IFERR(row_put_str(&row, (dtc_my_ctrl(session)->open_inconsistency == CT_TRUE ? "TRUE" : "FALSE")));
    // charset id must be valid.
    CT_RETURN_IFERR(row_put_str(&row, cm_get_charset_name((charset_type_t)db->ctrl.core.charset_id)));

    int64 commit_scn = cm_atomic_get(&sess->kernel->commit_scn);
    if (DB_IS_PRIMARY(db)) {
        CT_RETURN_IFERR(row_put_int64(&row, commit_scn));
    } else {
        CT_RETURN_IFERR(row_put_null(&row));
    }

    CT_RETURN_IFERR(row_put_str(&row, db_get_needrepair_reason(session)));
    CT_RETURN_IFERR(row_put_str(&row, db_get_readonly_reason(session)));

    CT_RETURN_IFERR(row_put_int32(&row, (int32)CORE_SYSDATA_VERSION));
    CT_RETURN_IFERR(row_put_int32(&row, (int32)db->ctrl.core.sysdata_version));

    PRTS_RETURN_IFERR(sprintf_s(str, sizeof(str), "%u-%u-%llu", db->ctrl.core.resetlogs.rst_id,
        db->ctrl.core.resetlogs.last_asn, db->ctrl.core.resetlogs.last_lfn));
    CT_RETURN_IFERR(row_put_str(&row, str));
    CT_RETURN_IFERR(row_put_int64(&row, (int64)KNL_GET_SCN(&sess->kernel->min_scn)));
    CT_RETURN_IFERR(row_put_int64(&row, sess->kernel->arch_ctx.arch_proc[0].curr_arch_size));
    if (knl_ddl_execute_status(session, CT_TRUE, &ddl_exec_stat) != CT_SUCCESS) {
        cm_reset_error();
    }
    CT_RETURN_IFERR(row_put_str(&row, get_ddl_exec_stat_str(ddl_exec_stat)));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;

    return CT_SUCCESS;
}

static status_t vw_repl_status_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    uint64 id;
    row_assist_t ra;
    database_t *db = &((knl_session_t *)session)->kernel->db;

    id = cursor->rowid.vmid;
    if (id >= VM_REPL_STATUS_ROWS) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, REPL_STATUS_COLS);
    vw_row_set_database_role(&ra, db->ctrl.core.db_role);
    CT_RETURN_IFERR(row_put_str(&ra, db_get_condition(session)));
    CT_RETURN_IFERR(row_put_str(&ra, db_get_switchover_status(session)));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

static status_t vw_lfn_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    row_assist_t ra;
    knl_session_t *sess = (knl_session_t *)session;
    database_t *db = &((knl_session_t *)session)->kernel->db;
    if (cursor->rowid.vmid >= db->ctrl.core.node_count) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    char *page_buf = (char *)cm_push(sess->stack, (uint32)CT_DFLT_CTRL_BLOCK_SIZE + (uint32)CT_MAX_ALIGN_SIZE_4K);
    ctrl_page_t *page = (ctrl_page_t *)cm_aligned_buf(page_buf);

    if (vw_get_node_ctrl_from_disk(session, page, cursor->rowid.vmid) != CT_SUCCESS) {
        cm_pop(sess->stack);
        return CT_ERROR;
    }
    uint64 lfn = ((dtc_node_ctrl_t *)page->buf)->lrp_point.lfn;
    cm_pop(sess->stack);

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, LFN_NODES);

    CT_RETURN_IFERR(row_put_int64(&ra, cursor->rowid.vmid));
    CT_RETURN_IFERR(row_put_int64(&ra, lfn));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

status_t vw_lrpl_detail_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    uint64 id;
    row_assist_t ra;
    database_t *db = &((knl_session_t *)session)->kernel->db;

    id = cursor->rowid.vmid;
    if (id > 0) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }
    
    uint32 redo_recovery_size = 0;
    double redo_recovery_time = 0;
    CT_RETURN_IFERR(dtc_cal_lrpl_redo_size(session, &redo_recovery_size, &redo_recovery_time));

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, LRPL_DETAIL_COLS);
    vw_row_set_database_role(&ra, db->ctrl.core.db_role);
    CT_RETURN_IFERR(row_put_str(&ra, dtc_get_lrpl_status(session)));
    CT_RETURN_IFERR(row_put_uint32(&ra, redo_recovery_size));
    CT_RETURN_IFERR(row_put_real(&ra, redo_recovery_time));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

typedef struct st_managed_standby_row {
    char *name;
    char status[CT_DYNVIEW_NORMAL_LEN];
    uint32 rst_id;
    char thread_id[CT_DYNVIEW_NORMAL_LEN];
    uint32 asn;
    char flush_point[CT_MAX_NUMBER_LEN];
    char primary_curr_point[CT_MAX_NUMBER_LEN];
    char replay_point[CT_MAX_NUMBER_LEN];
} managed_standby_row_t;

static managed_standby_row_t g_managed_standby_rows[] = {
    { "RFS",  { 0 }, 0, { 0 }, 0 },
    { "MRP",  { 0 }, 0, { 0 }, 0 },
    { "ARCH", { 0 }, 0, { 0 }, 0 },
    { "FAL",  { 0 }, 0, { 0 }, 0 },
};

#define MANAGED_STANDBY_ROW_COUNT (sizeof(g_managed_standby_rows) / sizeof(managed_standby_row_t))

static char *vm_get_lrcv_status(knl_session_t *session)
{
    lrcv_context_t *lrcv_ctx = &((knl_session_t *)session)->kernel->lrcv_ctx;
    log_context_t *redo_ctx = &((knl_session_t *)session)->kernel->redo_ctx;

    if (lrcv_ctx->status < LRCV_PREPARE) {
        return "OPEN";
    }

    if (lrcv_ctx->status < LRCV_READY) {
        return "CONNECTED";
    }

    if (redo_ctx->curr_point.rst_id < lrcv_ctx->primary_curr_point.rst_id ||
        (redo_ctx->curr_point.rst_id == lrcv_ctx->primary_curr_point.rst_id &&
        redo_ctx->curr_point.asn < lrcv_ctx->primary_curr_point.asn)) {
        return "CATCHING_UP";
    } else {
        return "STREAMING";
    }
}

static void vw_managed_standby_parameter_fetch(knl_handle_t session)
{
    knl_session_t *se = (knl_session_t *)session;

    if (se->kernel->lrcv_ctx.thread.closed) {
        PRTS_RETVOID_IFERR(snprintf_s(g_managed_standby_rows[0].status, CT_DYNVIEW_NORMAL_LEN,
            CT_DYNVIEW_NORMAL_LEN - 1, "%s", "UNUSED"));
        g_managed_standby_rows[0].rst_id = CT_INVALID_ASN;
        PRTS_RETVOID_IFERR(sprintf_s(g_managed_standby_rows[0].thread_id, CT_DYNVIEW_NORMAL_LEN, "%x", 0));
        g_managed_standby_rows[0].asn = CT_INVALID_ASN;
    } else {
        PRTS_RETVOID_IFERR(snprintf_s(g_managed_standby_rows[0].status, CT_DYNVIEW_NORMAL_LEN,
            CT_DYNVIEW_NORMAL_LEN - 1, "%s", vm_get_lrcv_status(se)));
        g_managed_standby_rows[0].rst_id = (uint32)se->kernel->lrcv_ctx.flush_point.rst_id;
        PRTS_RETVOID_IFERR(sprintf_s(g_managed_standby_rows[0].thread_id, CT_DYNVIEW_NORMAL_LEN, "%llx",
            (uint64)se->kernel->lrcv_ctx.thread.id));
        g_managed_standby_rows[0].asn = se->kernel->lrcv_ctx.flush_point.asn;
    }

    g_managed_standby_rows[0].replay_point[0] = '\0';
    PRTS_RETVOID_IFERR(snprintf_s(g_managed_standby_rows[0].flush_point, sizeof(g_managed_standby_rows[0].flush_point),
        sizeof(g_managed_standby_rows[0].flush_point) - 1, "%llu-%u/%u/%llu", se->kernel->lrcv_ctx.flush_point.rst_id,
        se->kernel->lrcv_ctx.flush_point.asn, se->kernel->lrcv_ctx.flush_point.block_id,
        (uint64)se->kernel->lrcv_ctx.flush_point.lfn));

    PRTS_RETVOID_IFERR(snprintf_s(g_managed_standby_rows[0].primary_curr_point,
        sizeof(g_managed_standby_rows[0].primary_curr_point), sizeof(g_managed_standby_rows[0].primary_curr_point) - 1,
        "%llu-%u/%u/%llu", se->kernel->lrcv_ctx.primary_curr_point.rst_id, se->kernel->lrcv_ctx.primary_curr_point.asn,
        se->kernel->lrcv_ctx.primary_curr_point.block_id, (uint64)se->kernel->lrcv_ctx.primary_curr_point.lfn));

    if (se->kernel->lrpl_ctx.thread.closed) {
        PRTS_RETVOID_IFERR(snprintf_s(g_managed_standby_rows[1].status, CT_DYNVIEW_NORMAL_LEN,
            CT_DYNVIEW_NORMAL_LEN - 1, "%s", "UNUSED"));
        g_managed_standby_rows[1].rst_id = CT_INVALID_ASN;
        PRTS_RETVOID_IFERR(sprintf_s(g_managed_standby_rows[1].thread_id, CT_DYNVIEW_NORMAL_LEN, "%x", 0));
        g_managed_standby_rows[1].asn = CT_INVALID_ASN;
    } else {
        PRTS_RETVOID_IFERR(snprintf_s(g_managed_standby_rows[1].status, CT_DYNVIEW_NORMAL_LEN,
            CT_DYNVIEW_NORMAL_LEN - 1, "%s", "OPEN"));
        g_managed_standby_rows[1].rst_id = (uint32)se->kernel->redo_ctx.curr_point.rst_id;
        PRTS_RETVOID_IFERR(sprintf_s(g_managed_standby_rows[1].thread_id, CT_DYNVIEW_NORMAL_LEN, "%llx",
            (uint64)se->kernel->lrpl_ctx.thread.id));
        g_managed_standby_rows[1].asn = se->kernel->redo_ctx.curr_point.asn;
    }

    g_managed_standby_rows[1].flush_point[0] = '\0';
    g_managed_standby_rows[1].primary_curr_point[0] = '\0';
    PRTS_RETVOID_IFERR(snprintf_s(g_managed_standby_rows[1].replay_point,
        sizeof(g_managed_standby_rows[1].replay_point), sizeof(g_managed_standby_rows[1].replay_point) - 1,
        "%llu-%u/%u/%llu", se->kernel->lrpl_ctx.curr_point.rst_id, se->kernel->lrpl_ctx.curr_point.asn,
        se->kernel->lrpl_ctx.curr_point.block_id, (uint64)se->kernel->lrpl_ctx.curr_point.lfn));

    if (se->kernel->arch_ctx.arch_proc[0].read_thread.closed) {
        PRTS_RETVOID_IFERR(snprintf_s(g_managed_standby_rows[2].status, CT_DYNVIEW_NORMAL_LEN,
            CT_DYNVIEW_NORMAL_LEN - 1, "%s", "UNUSED"));
        g_managed_standby_rows[2].rst_id = CT_INVALID_ASN;
        PRTS_RETVOID_IFERR(sprintf_s(g_managed_standby_rows[2].thread_id, CT_DYNVIEW_NORMAL_LEN, "%x", 0));
        g_managed_standby_rows[2].asn = CT_INVALID_ASN;
    } else {
        PRTS_RETVOID_IFERR(snprintf_s(g_managed_standby_rows[2].status, CT_DYNVIEW_NORMAL_LEN,
            CT_DYNVIEW_NORMAL_LEN - 1, "%s", "OPEN"));
        g_managed_standby_rows[2].rst_id = se->kernel->arch_ctx.arch_proc[0].last_archived_log.rst_id;
        PRTS_RETVOID_IFERR(sprintf_s(g_managed_standby_rows[2].thread_id, CT_DYNVIEW_NORMAL_LEN, "%llx",
            (uint64)se->kernel->arch_ctx.arch_proc[0].read_thread.id));
        g_managed_standby_rows[2].asn = se->kernel->arch_ctx.arch_proc[0].last_archived_log.asn;
    }

    g_managed_standby_rows[2].flush_point[0] = '\0';
    g_managed_standby_rows[2].primary_curr_point[0] = '\0';
    g_managed_standby_rows[2].replay_point[0] = '\0';
}

static status_t vw_managed_standby_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    uint64 id;
    row_assist_t ra;

    if (knl_db_is_primary(session)) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    id = cursor->rowid.vmid;
    if (id >= MANAGED_STANDBY_ROW_COUNT) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    vw_managed_standby_parameter_fetch(session);
    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, MANAGED_STANDBY_COLS);
    CT_RETURN_IFERR(row_put_str(&ra, g_managed_standby_rows[id].name));
    CT_RETURN_IFERR(row_put_str(&ra, g_managed_standby_rows[id].status));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)g_managed_standby_rows[id].rst_id));
    CT_RETURN_IFERR(row_put_str(&ra, g_managed_standby_rows[id].thread_id));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)g_managed_standby_rows[id].asn));
    CT_RETURN_IFERR(row_put_str(&ra, g_managed_standby_rows[id].flush_point));
    CT_RETURN_IFERR(row_put_str(&ra, g_managed_standby_rows[id].primary_curr_point));
    CT_RETURN_IFERR(row_put_str(&ra, g_managed_standby_rows[id].replay_point));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;

    return CT_SUCCESS;
}

static status_t vw_ha_sync_info_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    ha_sync_info_t ha_sync_info;
    uint64 id;
    row_assist_t ra;

    knl_get_sync_info(session, &ha_sync_info);

    id = cursor->rowid.vmid;
    if (id >= ha_sync_info.count) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, HA_SYNC_INFO_COLS);
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)(id + 1)));
    CT_RETURN_IFERR(row_put_str(&ra, ha_sync_info.sync_info[id].status));
    CT_RETURN_IFERR(row_put_str(&ra, ha_sync_info.sync_info[id].local_host));
    CT_RETURN_IFERR(row_put_str(&ra, ha_sync_info.sync_info[id].role_valid));
    CT_RETURN_IFERR(row_put_str(&ra, ha_sync_info.sync_info[id].net_mode));
    CT_RETURN_IFERR(row_put_str(&ra, ha_sync_info.sync_info[id].peer_host));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)ha_sync_info.sync_info[id].peer_port));
    CT_RETURN_IFERR(row_put_str(&ra, ha_sync_info.sync_info[id].local_point));
    CT_RETURN_IFERR(row_put_str(&ra, ha_sync_info.sync_info[id].peer_point));
    CT_RETURN_IFERR(row_put_str(&ra, ha_sync_info.sync_info[id].peer_cont_point));
    CT_RETURN_IFERR(row_put_str(&ra, ha_sync_info.sync_info[id].peer_building));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)ha_sync_info.sync_info[id].local_lfn));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)ha_sync_info.sync_info[id].local_lsn));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)ha_sync_info.sync_info[id].peer_lfn));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)ha_sync_info.sync_info[id].peer_lsn));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)ha_sync_info.sync_info[id].flush_lag));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)ha_sync_info.sync_info[id].replay_lag));
    CT_RETURN_IFERR(row_put_str(&ra, ha_sync_info.sync_info[id].build_type));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)ha_sync_info.sync_info[id].build_progress));
    CT_RETURN_IFERR(row_put_str(&ra, ha_sync_info.sync_info[id].build_stage));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)ha_sync_info.sync_info[id].build_synced_stage_size));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)ha_sync_info.sync_info[id].build_total_stage_size));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)ha_sync_info.sync_info[id].build_time));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);

    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

static status_t vw_me_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    uint64 id;
    row_assist_t ra;
    char addr[CT_NAME_BUFFER_SIZE];
    session_t *se = (session_t *)session;
    text_t spid_txt = { 0 };
    char str[CT_MAX_UINT32_STRLEN + 1] = { 0x00 };
    char ip_str[CM_MAX_IP_LEN] = { 0 };

    id = cursor->rowid.vmid;
    if (id >= VM_ME_ROWS) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, ME_COLS);
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)se->knl_session.id));
    {
        CT_RETURN_IFERR(row_put_text(&ra, &se->curr_user));
        CT_RETURN_IFERR(row_put_int32(&ra, (int32)se->knl_session.uid));
    }
    CT_RETURN_IFERR(row_put_str(&ra, se->curr_schema));
    /* SPID */
    spid_txt.str = str;
    cm_uint32_to_text(se->knl_session.spid, &spid_txt);
    CT_RETURN_IFERR(row_put_text(&ra, &spid_txt));
    CT_RETURN_IFERR(row_put_str(&ra, se->os_prog));

    CT_RETURN_IFERR(row_put_str(&ra, se->os_host));
    CT_RETURN_IFERR(row_put_str(&ra, se->os_user));

    if (se->type == SESSION_TYPE_JOB) {
        CT_RETURN_IFERR(row_put_null(&ra));
        CT_RETURN_IFERR(row_put_null(&ra));
    } else {
        PRTS_RETURN_IFERR(sprintf_s(addr, CT_NAME_BUFFER_SIZE, "%s",
            cm_inet_ntop((struct sockaddr *)&SESSION_PIPE(se)->link.tcp.remote.addr, ip_str, CM_MAX_IP_LEN)));
        CT_RETURN_IFERR(row_put_str(&ra, addr));

        PRTS_RETURN_IFERR(
            sprintf_s(addr, CT_NAME_BUFFER_SIZE, "%u", ntohs(SOCKADDR_PORT(&SESSION_PIPE(se)->link.tcp.remote))));
        CT_RETURN_IFERR(row_put_str(&ra, addr));
    }

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);

    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

static status_t vw_dynamic_view_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    uint64 id;
    row_assist_t ra;
    knl_dynview_t view;
    dynview_desc_t *desc = NULL;

    id = cursor->rowid.vmid;
    if (id > (DYN_VIEW_SELF)) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    view = g_dynamic_views[id];
    desc = view.describe(view.id);

    if (desc != NULL) {
        row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, DYNAMIC_VIEW_COLS);
        CT_RETURN_IFERR(row_put_str(&ra, desc->user));
        CT_RETURN_IFERR(row_put_str(&ra, desc->name));
        CT_RETURN_IFERR(row_put_int32(&ra, (int32)view.id));
        CT_RETURN_IFERR(row_put_int32(&ra, (int32)desc->column_count));
        cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    }
    cursor->rowid.vmid++;

    return CT_SUCCESS;
}

static status_t vw_dynamic_view_column_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    uint64 view_id, col_id;
    row_assist_t ra;
    knl_dynview_t view;
    dynview_desc_t *desc = NULL;

    for (;;) {
        view_id = cursor->rowid.vmid;
        if (view_id > DYN_VIEW_SELF) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }

        view = g_dynamic_views[view_id];
        desc = view.describe(view.id);
        if (cursor->rowid.vm_slot >= desc->column_count) {
            cursor->rowid.vmid++;
            cursor->rowid.vm_slot = 0;
            continue;
        }
        break;
    }

    col_id = (uint32)cursor->rowid.vm_slot;
    knl_column_t *column = &desc->columns[col_id];

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, DYNAMIC_VIEW_COLUMN_COLS);
    CT_RETURN_IFERR(row_put_str(&ra, desc->user));
    CT_RETURN_IFERR(row_put_str(&ra, desc->name));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)col_id));
    CT_RETURN_IFERR(row_put_str(&ra, column->name));
    CT_RETURN_IFERR(row_put_text(&ra, (text_t *)get_datatype_name((int32)column->datatype)));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)column->size));
    row_put_prec_and_scale(&ra, column->datatype, column->precision, column->scale); // precision & scale
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vm_slot++;

    return CT_SUCCESS;
}

status_t vw_version_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    row_assist_t row;
    uint64 id = cursor->rowid.vmid;

    if (id >= VW_VERSION_BOTTOM) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, VERSION_COLS);

    switch (id) {
        case VW_VERSION_GIT:
            CT_RETURN_IFERR(row_put_str(&row, cantiand_get_dbversion()));
            break;
        case VW_VERSION_CANTIAND:
            CT_RETURN_IFERR(row_put_str(&row, VERSION2));
            break;
        case VW_VERSION_PKG:
            CT_RETURN_IFERR(row_put_str(&row, VERSION_PKG));
            break;
        case VW_VERSION_COMMIT:
#ifdef COMMIT_ID
            CT_RETURN_IFERR(row_put_str(&row, COMMIT_ID));
#else
            cursor->eof = CT_TRUE;
#endif
            break;
        default:
            break;
    }

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

static status_t vw_ctrl_version_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    row_assist_t row;
    char str[1024];
    if (cursor->rowid.vmid > 0) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }
    knl_session_t *se = (knl_session_t *)session;
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(se);
    row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, VERSION_COLS);
    PRTS_RETURN_IFERR(sprintf_s(str, sizeof(str), "%hu.%hu.%hu.%hu", core_ctrl->version.main,
                      core_ctrl->version.major, core_ctrl->version.revision, core_ctrl->version.inner));
    CT_RETURN_IFERR(row_put_str(&row, str));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

static void transaction_put_row(knl_session_t *session, knl_cursor_t *cursor)
{
    row_assist_t ra;
    knl_session_t *tx_se = NULL;

    undo_t *undo = &session->kernel->undo_ctx.undos[cursor->rowid.vm_slot];
    tx_item_t *tx_item = &undo->items[cursor->rowid.vmid];
    txn_t *txn = txn_addr(session, tx_item->xmap);
    undo_page_id_t page_id = undo->segment->txn_page[tx_item->xmap.slot / TXN_PER_PAGE(session)];
    uint32 undo_count = txn->undo_pages.count;
    uint32 undo_first = txn->undo_pages.first.value;
    uint32 undo_last = txn->undo_pages.last.value;
    uint16 rmid = tx_item->rmid;
    if (undo_count == 0 && rmid != CT_INVALID_ID16) {
        knl_rm_t *rm = session->kernel->rms[rmid];
        undo_count = rm->noredo_undo_pages.count;
        undo_first = rm->noredo_undo_pages.first.value;
        undo_last = rm->noredo_undo_pages.last.value;
    }

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, TRANSACTION_COLS);
    (void)row_put_int32(&ra, (int32)tx_item->xmap.seg_id);
    (void)row_put_int32(&ra, (int32)tx_item->xmap.slot);
    (void)row_put_int32(&ra, (int32)txn->xnum);
    (void)row_put_int64(&ra, (int64)txn->scn);
    (void)row_put_int32(&ra, (int32)knl_get_rm_sid(session, tx_item->rmid));
    (void)row_put_str(&ra, txn_status((xact_status_t)txn->status));
    (void)row_put_int32(&ra, (int32)undo_count);
    (void)row_put_int32(&ra, (int32)undo_first);
    (void)row_put_int32(&ra, (int32)undo_last);
    (void)row_put_date(&ra, (int64)tx_item->systime);
    (void)row_put_int32(&ra, (int32)page_id.value);
    (void)row_put_int32(&ra, (int32)tx_item->rmid);
    uint16 sid = knl_get_rm_sid(session, tx_item->rmid);
    if (sid != CT_INVALID_ID16) {
        tx_se = session->kernel->sessions[sid];
    }
    if (tx_se != NULL && DB_IS_BG_ROLLBACK_SE(tx_se)) {
        (void)row_put_str(&ra, "TRUE");
    } else {
        (void)row_put_str(&ra, "FALSE");
    }
    (void)row_put_int64(&ra, (KNL_NOW(session) - (int64)tx_item->systime));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);

    cursor->rowid.vmid++;
    if (cursor->rowid.vmid == undo->capacity) {
        cursor->rowid.vm_slot++;
        cursor->rowid.vmid = 0;
    }
}

/**
 * dynamic view for active transaction
 */
static status_t vw_transaction_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    knl_session_t *session = (knl_session_t *)se;
    undo_t *undo = NULL;
    tx_item_t *tx_item = NULL;
    txn_t *txn = NULL;

    if (cursor->rowid.vm_slot >= session->kernel->attr.undo_segments || session->kernel->db.status < DB_STATUS_OPEN ||
        (cm_dbs_is_enable_dbs() && !DB_IS_PRIMARY(&session->kernel->db) && !rc_is_master())) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }
    undo = &session->kernel->undo_ctx.undos[cursor->rowid.vm_slot];

    tx_item = &undo->items[cursor->rowid.vmid];
    txn = txn_addr(session, tx_item->xmap);

    while (txn->status == (uint8)XACT_END) {
        cursor->rowid.vmid++;
        if (cursor->rowid.vmid < undo->capacity) {
            tx_item = &undo->items[cursor->rowid.vmid];
            txn = txn_addr(session, tx_item->xmap);
            continue;
        }

        cursor->rowid.vm_slot++;
        if (cursor->rowid.vm_slot >= session->kernel->attr.undo_segments) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }
        undo = &session->kernel->undo_ctx.undos[cursor->rowid.vm_slot];

        cursor->rowid.vmid = 0;
        tx_item = &undo->items[cursor->rowid.vmid];
        txn = txn_addr(session, tx_item->xmap);
    }

    transaction_put_row(session, cursor);
    return CT_SUCCESS;
}

/**
 * dynamic view for all transaction
 */
static status_t vw_all_transaction_fetch_core(knl_handle_t se, knl_cursor_t *cursor)
{
    knl_session_t *session = (knl_session_t *)se;
    undo_t *undo = NULL;
    tx_item_t *tx_item = NULL;
    txn_t *txn = NULL;
    row_assist_t ra;
    undo_page_id_t page_id;
    uint16 sid;
    knl_session_t *tx_se = NULL;
    session_t *sess = NULL;

    if (cursor->rowid.vm_slot >= session->kernel->attr.undo_segments ||
        (cm_dbs_is_enable_dbs() && !DB_IS_PRIMARY(&session->kernel->db) && !rc_is_master())) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }
    undo = &session->kernel->undo_ctx.undos[cursor->rowid.vm_slot];

    tx_item = &undo->items[cursor->rowid.vmid];
    txn = txn_addr(session, tx_item->xmap);
    page_id = undo->segment->txn_page[tx_item->xmap.slot / TXN_PER_PAGE(session)];

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, ALL_TRANSACTION_COLS);
    (void)row_put_int32(&ra, (int32)tx_item->xmap.seg_id);
    (void)row_put_int32(&ra, (int32)tx_item->xmap.slot);
    (void)row_put_int32(&ra, (int32)txn->xnum);
    (void)row_put_int64(&ra, (int64)txn->scn);
    (void)row_put_int32(&ra, (int32)knl_get_rm_sid(session, tx_item->rmid));
    (void)row_put_str(&ra, txn_status((xact_status_t)txn->status));
    (void)row_put_int32(&ra, (int32)txn->undo_pages.count);
    (void)row_put_int32(&ra, (int32)txn->undo_pages.first.value);
    (void)row_put_int32(&ra, (int32)txn->undo_pages.last.value);
    (void)row_put_int32(&ra, (int32)page_id.value);
    (void)row_put_int32(&ra, (int32)tx_item->rmid);
    sid = knl_get_rm_sid(session, tx_item->rmid);
    if (sid != CT_INVALID_ID16) {
        tx_se = session->kernel->sessions[sid];
    }
    if (tx_se != NULL && DB_IS_BG_ROLLBACK_SE(tx_se)) {
        (void)row_put_str(&ra, "TRUE");
        sess = (session_t *)tx_se;
        cursor->tenant_id = sess->curr_tenant_id;
    } else {
        (void)row_put_str(&ra, "FALSE");
        cursor->tenant_id = SYS_TENANTROOT_ID;
    }
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);

    cursor->rowid.vmid++;
    if (cursor->rowid.vmid == undo->capacity) {
        cursor->rowid.vm_slot++;
        cursor->rowid.vmid = 0;
    }

    return CT_SUCCESS;
}

static status_t vw_all_transaction_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    return vw_fetch_for_tenant(vw_all_transaction_fetch_core, se, cursor);
}

static status_t vw_resource_map_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    row_assist_t row;
    uint64 id = cursor->rowid.vmid;

    if (id >= (sizeof(g_resource_map) / sizeof(g_resource_map[0]))) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, RESOURCE_MAP_COLS);

    CT_RETURN_IFERR(row_put_int32(&row, (int32)id));
    CT_RETURN_IFERR(row_put_int32(&row, (int32)g_resource_map[id].type));
    CT_RETURN_IFERR(row_put_str(&row, g_resource_map[id].name));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;

    return CT_SUCCESS;
}

static status_t vw_user_astatus_map_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    row_assist_t row;
    uint64 id = cursor->rowid.vmid;

    if (id >= (sizeof(g_user_astatus_map) / sizeof(g_user_astatus_map[0]))) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, USER_ASTATUS_MAP_COLS);

    CT_RETURN_IFERR(row_put_int32(&row, (int32)g_user_astatus_map[id].id));
    CT_RETURN_IFERR(row_put_str(&row, g_user_astatus_map[id].name));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;

    return CT_SUCCESS;
}

static status_t vw_undo_fetch_page_info(knl_session_t *session, undo_t *undo, row_assist_t *ra)
{
    page_id_t first, last;
    undo_page_list_t list;
    undo_page_t *page = NULL;

    list = undo->segment->page_list;
    first = PAGID_U2N(list.first);
    last = PAGID_U2N(list.last);
    (void)row_put_int32(ra, (int32)list.count);
    (void)row_put_int64(ra, *(int64 *)&first);
    (void)row_put_int64(ra, *(int64 *)&last);
    if (!IS_INVALID_PAGID(list.first)) {
        if (buf_read_page(session, PAGID_U2N(list.first), LATCH_MODE_S, ENTER_PAGE_NORMAL) != CT_SUCCESS) {
            return CT_ERROR;
        }
        page = (undo_page_t *)CURR_PAGE(session);
        (void)row_put_date(ra, page->ss_time);
        buf_leave_page(session, CT_FALSE);
    } else {
        (void)row_put_null(ra);
    }

    if (!IS_INVALID_PAGID(list.last)) {
        if (buf_read_page(session, PAGID_U2N(list.last), LATCH_MODE_S, ENTER_PAGE_NORMAL) != CT_SUCCESS) {
            return CT_ERROR;
        }
        page = (undo_page_t *)CURR_PAGE(session);
        (void)row_put_date(ra, page->ss_time);
        buf_leave_page(session, CT_FALSE);
    } else {
        (void)row_put_null(ra);
    }

    return CT_SUCCESS;
}

static void vw_undo_fetch_accumu_info(undo_context_t *ctx, undo_t *undo, row_assist_t *ra)
{
    (void)row_put_date(ra, (int64)undo->stat.begin_time);
    (void)row_put_int32(ra, (int32)undo->stat.txn_cnts);
    (void)row_put_int32(ra, (int32)undo->stat.reuse_expire_pages);
    (void)row_put_int32(ra, (int32)undo->stat.reuse_unexpire_pages);
    (void)row_put_int32(ra, (int32)undo->stat.use_space_pages);
    (void)row_put_int32(ra, (int32)undo->stat.steal_expire_pages);
    (void)row_put_int32(ra, (int32)undo->stat.steal_unexpire_pages);
    (void)row_put_int32(ra, (int32)undo->stat.stealed_expire_pages);
    (void)row_put_int32(ra, (int32)undo->stat.stealed_unexpire_pages);
    (void)row_put_int64(ra, MIN(CT_MAX_INT64, (int64)undo->stat.buf_busy_waits));

    return;
}

static status_t vw_undo_segment_fetch(knl_handle_t handle, knl_cursor_t *cursor)
{
    knl_session_t *session = (knl_session_t *)handle;
    undo_context_t *ctx = &session->kernel->undo_ctx;
    row_assist_t ra;

    if (cursor->rowid.vmid >= UNDO_SEGMENT_COUNT(session)) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    undo_t *undo = &ctx->undos[cursor->rowid.vmid];
    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, UNDO_SEGMENT_COLS);
    (void)row_put_int32(&ra, (int32)cursor->rowid.vmid);
    (void)row_put_int64(&ra, (int64)undo->entry.value);
    (void)row_put_str(&ra, (cursor->rowid.vmid < UNDO_ACTIVE_SEGMENT_COUNT(session)) ? "ACTIVE" : "INACTIVE");
    (void)row_put_int32(&ra, (int32)undo->segment->txn_page_count);
    (void)row_put_int32(&ra, (int32)undo->free_items.count);
    (void)row_put_int32(&ra, (int32)undo->free_items.first);
    (void)row_put_int32(&ra, (int32)undo->free_items.last);

    if (vw_undo_fetch_page_info(session, undo, &ra) != CT_SUCCESS) {
        return CT_ERROR;
    }

    (void)row_put_int32(&ra, (int32)session->kernel->attr.undo_retention_time);
    (void)row_put_int64(&ra, (int64)undo->ow_scn);
    vw_undo_fetch_accumu_info(ctx, undo, &ra);

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

static status_t vw_temp_undo_segment_fetch(knl_handle_t handle, knl_cursor_t *cursor)
{
    knl_session_t *session = (knl_session_t *)handle;
    undo_context_t *ctx = &session->kernel->undo_ctx;
    undo_page_list_t list;
    undo_page_t *page = NULL;
    undo_t *undo = NULL;
    row_assist_t ra;
    page_id_t first, last;

    if (cursor->rowid.vmid >= UNDO_SEGMENT_COUNT(session)) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    undo = &ctx->undos[cursor->rowid.vmid];
    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, UNDO_SEGMENT_COLS);
    (void)row_put_int32(&ra, (int32)cursor->rowid.vmid);
    (void)row_put_int64(&ra, (int64)undo->entry.value);
    (void)row_put_int32(&ra, (int32)undo->segment->txn_page_count);

    list = undo->temp_free_page_list;
    first = PAGID_U2N(list.first);
    last = PAGID_U2N(list.last);
    (void)row_put_int32(&ra, (int32)list.count);
    (void)row_put_int64(&ra, *(int64 *)&first);
    (void)row_put_int64(&ra, *(int64 *)&last);

    if (!IS_INVALID_PAGID(list.first)) {
        if (buf_read_page(session, PAGID_U2N(list.first), LATCH_MODE_S, ENTER_PAGE_NORMAL) != CT_SUCCESS) {
            return CT_ERROR;
        }
        page = (undo_page_t *)CURR_PAGE(session);
        (void)row_put_date(&ra, page->ss_time);
        buf_leave_page(session, CT_FALSE);
    } else {
        (void)row_put_null(&ra);
    }

    if (!IS_INVALID_PAGID(list.last)) {
        if (buf_read_page(session, PAGID_U2N(list.last), LATCH_MODE_S, ENTER_PAGE_NORMAL) != CT_SUCCESS) {
            return CT_ERROR;
        }
        page = (undo_page_t *)CURR_PAGE(session);
        (void)row_put_date(&ra, page->ss_time);
        buf_leave_page(session, CT_FALSE);
    } else {
        (void)row_put_null(&ra);
    }

    (void)row_put_int32(&ra, session->kernel->attr.undo_retention_time);

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

static status_t vw_backup_process_stats_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    knl_session_t *session = (knl_session_t *)se;
    bak_context_t *ctx = &session->kernel->backup_ctx;
    uint32 id = (uint32)cursor->rowid.vmid;
    row_assist_t row;
    uint32 proc_count = MIN(ctx->bak.proc_count, CT_MAX_BACKUP_PROCESS - 1);
    if (id > proc_count) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, BAK_PROCESS_STATS_COLS);

    bak_process_stat_t *stat = &ctx->process[id].stat;

    uint64 rd_size = stat->read_size;
    uint64 rd_time = stat->read_time;
    uint64 wt_size = stat->write_size;
    uint64 wt_time = stat->write_time;
    uint64 en_size = stat->encode_size;
    uint64 en_time = stat->encode_time;
    uint64 rd_speed = (rd_time <= MICROSECS_PER_MILLISEC) ? 0 : rd_size * MICROSECS_PER_SECOND_LL / SIZE_M(1) / rd_time;
    uint64 wt_speed = (wt_time <= MICROSECS_PER_MILLISEC) ? 0 : wt_size * MICROSECS_PER_SECOND_LL / SIZE_M(1) / wt_time;
    uint64 en_speed = (en_time <= MICROSECS_PER_MILLISEC) ? 0 : en_size * MICROSECS_PER_SECOND_LL / SIZE_M(1) / en_time;

    CT_RETURN_IFERR(row_put_uint32(&row, id));
    CT_RETURN_IFERR(row_put_uint32(&row, (uint32)(rd_size / SIZE_M(1))));
    CT_RETURN_IFERR(row_put_uint32(&row, (uint32)(rd_time / MICROSECS_PER_MILLISEC)));
    CT_RETURN_IFERR(row_put_uint32(&row, (uint32)rd_speed));
    CT_RETURN_IFERR(row_put_uint32(&row, (uint32)(en_time / MICROSECS_PER_MILLISEC)));
    CT_RETURN_IFERR(row_put_uint32(&row, (uint32)en_speed));
    CT_RETURN_IFERR(row_put_uint32(&row, (uint32)(wt_size / SIZE_M(1))));
    CT_RETURN_IFERR(row_put_uint32(&row, (uint32)(wt_time / MICROSECS_PER_MILLISEC)));
    CT_RETURN_IFERR(row_put_uint32(&row, (uint32)wt_speed));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;

    return CT_SUCCESS;
}

static errno_t vw_backup_copy_stage(bak_progress_t *ctrl, char *stage)
{
    errno_t errcode;
    switch (ctrl->stage) {
        case BACKUP_CTRL_STAGE:
            errcode = strcpy_s(stage, CT_MAX_NAME_LEN, "ctrl file");
            break;
        case BACKUP_HEAD_STAGE:
            errcode = strcpy_s(stage, CT_MAX_NAME_LEN, "summary");
            break;
        case BACKUP_BUILD_STAGE:
            errcode = strcpy_s(stage, CT_MAX_NAME_LEN, "build files");
            break;
        case BACKUP_DATA_STAGE:
            errcode = strcpy_s(stage, CT_MAX_NAME_LEN, "data files");
            break;
        case BACKUP_LOG_STAGE:
            errcode = strcpy_s(stage, CT_MAX_NAME_LEN, "log files");
            break;
        case BACKUP_END:
            errcode = strcpy_s(stage, CT_MAX_NAME_LEN, "end");
            break;
        default:
            errcode = strcpy_s(stage, CT_MAX_NAME_LEN, "start");
            break;
    }
    return errcode;
}


static status_t vw_backup_process_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    knl_session_t *session = (knl_session_t *)se;
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_progress_t *ctrl = &ctx->bak.progress;
    bak_error_t *error_info = &ctx->bak.error_info;
    uint64 id = cursor->rowid.vmid;
    row_assist_t row;
    double complete_rate;
    uint32 base_rate;
    uint32 total_proc = 0;
    uint32 free_proc = 0;
    char stage[CT_MAX_NAME_LEN];
    char status[CT_MAX_NAME_LEN];
    int32 err_code;
    char err_msg[CT_MESSAGE_BUFFER_SIZE];
    errno_t errcode;
    if (id > 0) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, BACKUP_PROCESS_COLS);
    CT_RETURN_IFERR(row_put_str(&row, ctx->bak.restore ? "restore" : "backup"));
    cm_spin_lock(&ctrl->lock, NULL);
    if (BAK_IS_RUNNING(ctx)) {
        if (bak_paral_task_enable(session)) {
            total_proc = ctx->bak.proc_count;
            for (uint32 i = 1; i <= total_proc; i++) {
                free_proc += ctx->process[i].is_free ? 1 : 0;
            }
        } else {
            total_proc = 1;
        }
    }

    base_rate = ctrl->base_rate;
    if (ctrl->processed_size > 0) {
        complete_rate = ctrl->processed_size * 1.0 / ctrl->data_size;
        if (complete_rate >= 1) {
            complete_rate = 1;
        }
        base_rate = ctrl->base_rate + (uint32)(int32)(ctrl->weight * complete_rate);
    }

    if (row_put_int32(&row, (int32)base_rate) != CT_SUCCESS) {
        cm_spin_unlock(&ctrl->lock);
        return CT_ERROR;
    }
    errcode = vw_backup_copy_stage(ctrl, stage);
    cm_spin_unlock(&ctrl->lock);
    MEMS_RETURN_IFERR(errcode);
    CT_RETURN_IFERR(row_put_str(&row, stage));

    switch (ctx->bak.record.status) {
        case BACKUP_SUCCESS:
            errcode = strcpy_s(status, CT_MAX_NAME_LEN, "success");
            break;
        case BACKUP_PROCESSING:
            errcode = strcpy_s(status, CT_MAX_NAME_LEN, "processing");
            break;
        default:
            errcode = strcpy_s(status, CT_MAX_NAME_LEN, "failed");
            break;
    }
    MEMS_RETURN_IFERR(errcode);
    CT_RETURN_IFERR(row_put_str(&row, status));

    cm_spin_lock(&error_info->err_lock, NULL);
    err_code = error_info->err_code;
    if (err_code != CT_SUCCESS) {
        errcode = strcpy_s(err_msg, CT_MESSAGE_BUFFER_SIZE, error_info->err_msg);
        if (errcode != EOK) {
            cm_spin_unlock(&error_info->err_lock);
            CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
            return CT_ERROR;
        }
    } else {
        err_msg[0] = '\0';
    }
    cm_spin_unlock(&error_info->err_lock);

    CT_RETURN_IFERR(row_put_int32(&row, (int32)err_code));
    CT_RETURN_IFERR(row_put_str(&row, err_msg));

    CT_RETURN_IFERR(row_put_int32(&row, (int32)total_proc));
    CT_RETURN_IFERR(row_put_int32(&row, (int32)free_proc));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;

    return CT_SUCCESS;
}

static inline void vw_row_set_shutdown_phase(row_assist_t *ra, shutdown_phase_t status)
{
    switch (status) {
        case SHUTDOWN_PHASE_NOT_BEGIN:
            (void)row_put_str(ra, "NOT_BEGIN");
            break;
        case SHUTDOWN_PHASE_INPROGRESS:
            (void)row_put_str(ra, "INPROGRESS");
            break;
        case SHUTDOWN_PHASE_DONE:
            (void)row_put_str(ra, "DONE");
            break;
        default:
            (void)row_put_str(ra, "UNKNOWN PHASE");
            break;
    }
}

static status_t vw_instance_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    knl_session_t *session = (knl_session_t *)se;
    struct st_knl_instance *kernel = session->kernel;
    database_t *db = &kernel->db;
    uint64 id = cursor->rowid.vmid;
    row_assist_t row;

    if (id > 0) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, INSTANCE_COLS);
    (void)row_put_int32(&row, (int32)g_instance->id);
    (void)row_put_str(&row, kernel->instance_name);
    vw_row_set_database_state(&row, db->status);
    (void)row_put_int64(&row, (int64)kernel->scn);
    vw_row_set_shutdown_phase(&row, g_instance->shutdown_ctx.phase);
    (void)row_put_int64(&row, (int64)kernel->db_startup_time);
    (void)row_put_str(&row, cm_sys_host_name());
    (void)row_put_str(&row, cm_sys_platform_name());
    (void)row_put_str(&row, (kernel->lrcv_ctx.session == NULL) ? "DISCONNECTED" : "CONNECTED");

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;

    return CT_SUCCESS;
}

static char *vw_open_cursor_make_status(uint8 status)
{
    switch (status) {
        case STMT_STATUS_FREE:
            return "STMT_STATUS_FREE";
        case STMT_STATUS_IDLE:
            return "STMT_STATUS_IDLE";
        case STMT_STATUS_PREPARED:
            return "STMT_STATUS_PREPARED";
        case STMT_STATUS_EXECUTING:
            return "STMT_STATUS_EXECUTING";
        case STMT_STATUS_EXECUTED:
            return "STMT_STATUS_EXECUTED";
        case STMT_STATUS_FETCHING:
            return "STMT_STATUS_FETCHING";
        case STMT_STATUS_FETCHED:
            return "STMT_STATUS_FETCHED";
        default:
            return "STMT_STATUS_UNKNOWN";
    }
}

static void vw_open_cursor_fetch_session(knl_cursor_t *cursor, session_t **ret_se)
{
    uint64 id;
    session_t *session = NULL;

    do {
        id = cursor->rowid.vmid;

        if (id >= CT_MAX_SESSIONS) {
            cursor->eof = CT_TRUE;
            cursor->rowid.vm_slot = 0;
            return;
        }

        session = g_instance->session_pool.sessions[id];
        if (session != NULL && cursor->rowid.vm_slot < session->stmts.count) {
            break;
        }

        if (session == NULL) {
            cursor->eof = CT_TRUE;
            cursor->rowid.vm_slot = 0;
            return;
        }

        cursor->rowid.vmid++;
        cursor->rowid.vm_slot = 0;
    } while (CT_TRUE);

    *ret_se = session;
}

// if get stmt, stmt will be locked!!!
static void vw_open_cursor_fetch_stmt(knl_cursor_t *cursor, session_t *session, sql_stmt_t **ret_stmt)
{
    sql_stmt_t *stmt = NULL;
    *ret_stmt = NULL;
    if (session->stmts.count == 0) {
        return;
    }

    do {
        if (cursor->rowid.vm_slot >= session->stmts.count) {
            return;
        }

        stmt = (sql_stmt_t *)cm_list_get(&session->stmts, (uint32)cursor->rowid.vm_slot);
        if (stmt->status != STMT_STATUS_FREE) {
            break;
        }
        cursor->rowid.vm_slot++;
    } while (CT_TRUE);

    *ret_stmt = stmt;
}

static inline char *vw_decode_cursor_type(uint32 type)
{
    switch (type) {
        case PL_EXPLICIT_CURSOR:
            return "PL/SQL DECLARED CURSOR";

        case PL_IMPLICIT_CURSOR:
            return "PL/SQL IMPLICIT CURSOR";

        default:
            return "USER CURSOR";
    }
}

static void vm_open_cursor_fetch_realtime_statistics(sql_stmt_t *stmt, row_assist_t *row)
{
    if (stmt->session->current_stmt == stmt) {
        ctx_prev_stat_t *ctx_pre_stat = &stmt->session->ctx_prev_stat;
        knl_stat_t *knl_stat = stmt->session->knl_session.stat;
        uint64 buffer_gets = knl_stat->buffer_gets - ctx_pre_stat->buffer_gets;
        uint64 cr_gets = knl_stat->cr_gets - ctx_pre_stat->cr_gets;
        uint64 io_wait_time = knl_stat->disk_read_time - ctx_pre_stat->io_wait_time;
        uint64 con_wait_time = knl_stat->con_wait_time - ctx_pre_stat->con_wait_time;
        timeval_t tv_end;

        (void)cm_gettimeofday(&tv_end);
        uint64 elapsed_time = TIMEVAL_DIFF_US(&ctx_pre_stat->tv_start, &tv_end);
        int64 cpu_time = (int64)(elapsed_time - io_wait_time - con_wait_time);

        (void)(row_put_int64(row, (int64)elapsed_time));
        (void)(row_put_int64(row, (int64)(knl_stat->disk_reads - ctx_pre_stat->disk_reads)));
        (void)(row_put_int64(row, (int64)io_wait_time));
        (void)(row_put_int64(row, (int64)(buffer_gets + cr_gets)));
        (void)(row_put_int64(row, (int64)cr_gets));
        (void)(row_put_int64(row, (int64)con_wait_time));
        (void)(row_put_int64(row, cpu_time));
    } else {
        (void)row_put_null(row);
        (void)row_put_null(row);
        (void)row_put_null(row);
        (void)row_put_null(row);
        (void)row_put_null(row);
        (void)row_put_null(row);
        (void)row_put_null(row);
    }
    return;
}

static status_t vm_open_cursor_get_sql(sql_context_t *vw_ctx, row_assist_t *row)
{
    text_t sql;
    char hash_valstr[CT_MAX_UINT32_STRLEN + 1];
    char sql_copy[MAX_OPEN_CURSOR_SQL_LENGTH];
    errno_t errcode = 0;

    // double check after lock, context
    cm_spin_lock(&vw_ctx->ctrl.lock, NULL);
    ctx_read_first_page_text(sql_pool, &vw_ctx->ctrl, &sql);
    if (sql.len >= MAX_OPEN_CURSOR_SQL_LENGTH) {
        sql.len = (MAX_OPEN_CURSOR_SQL_LENGTH - 1);
    }
    if (sql.len != 0) {
        errcode = memcpy_s(sql_copy, sizeof(sql_copy), sql.str, sql.len);
        if (errcode != EOK) {
            cm_spin_unlock(&vw_ctx->ctrl.lock);
            CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
            return CT_ERROR;
        }
        sql.str = sql_copy;
    }
    (void)row_put_text(row, &sql);
    (void)row_put_int32(row, (int32)vw_ctx->type);

    errcode = sprintf_s(hash_valstr, (CT_MAX_UINT32_STRLEN + 1), "%010u", vw_ctx->ctrl.hash_value);
    if (errcode == -1) {
        cm_spin_unlock(&vw_ctx->ctrl.lock);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CT_ERROR;
    }
    if (row_put_str(row, hash_valstr) != CT_SUCCESS) { /* sql_id */
        cm_spin_unlock(&vw_ctx->ctrl.lock);
        return CT_ERROR;
    }

    cm_spin_unlock(&vw_ctx->ctrl.lock);
    return CT_SUCCESS;
}

static status_t vm_open_cursor_get_anonymous(pl_entity_t *pl_ctx, row_assist_t *row)
{
    errno_t errcode;
    text_t copy_text;
    char hash_valstr[CT_MAX_UINT32_STRLEN + 1];
    char sql_copy[MAX_OPEN_CURSOR_SQL_LENGTH];
    anonymous_desc_t *desc = &pl_ctx->anonymous->desc;

    copy_text.len = MIN(MAX_OPEN_CURSOR_SQL_LENGTH - 1, desc->sql.len);

    if (copy_text.len != 0) {
        errcode = memcpy_s(sql_copy, sizeof(sql_copy), desc->sql.str, copy_text.len);
        if (errcode != EOK) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
            return CT_ERROR;
        }
        copy_text.str = sql_copy;
        (void)row_put_text(row, &copy_text);
    } else {
        (void)row_put_null(row);
    }

    (void)row_put_int32(row, (int32)CTSQL_TYPE_ANONYMOUS_BLOCK);

    errcode = sprintf_s(hash_valstr, (CT_MAX_UINT32_STRLEN + 1), "%010u", desc->sql_hash);
    if (errcode == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CT_ERROR;
    }

    (void)row_put_str(row, hash_valstr);
    return CT_SUCCESS;
}

static status_t vm_open_cursor_fetch_core(knl_handle_t se, knl_cursor_t *cursor, session_t *session, sql_stmt_t *stmt)
{
    row_assist_t row;
    sql_context_t *vw_ctx = NULL;
    pl_entity_t *pl_ctx = NULL;

    row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, OPEN_CURSOR_COLS);
    (void)row_put_int32(&row, (int32)session->knl_session.id);
    (void)row_put_int32(&row, (int32)stmt->id);
    (void)row_put_text(&row, &session->curr_user);

    vw_ctx = stmt->context;
    pl_ctx = (pl_entity_t *)stmt->pl_context;
    if (vw_ctx != NULL && vw_ctx->type != CTSQL_TYPE_ANONYMOUS_BLOCK) {
        CT_RETURN_IFERR(vm_open_cursor_get_sql(vw_ctx, &row));
    } else if (pl_ctx != NULL && pl_ctx->valid) {
        CT_RETURN_IFERR(vm_open_cursor_get_anonymous(pl_ctx, &row));
    } else {
        (void)row_put_null(&row);
        (void)row_put_null(&row);
        (void)row_put_null(&row);
    }

    (void)row_put_str(&row, vw_open_cursor_make_status((uint8)stmt->status));
    (void)row_put_str(&row, vw_decode_cursor_type(stmt->cursor_info.type));

    (void)(row_put_int64(&row, (int64)stmt->vm_stat.open_pages));
    (void)(row_put_int64(&row, (int64)stmt->vm_stat.close_pages));
    (void)(row_put_int64(&row, (int64)stmt->vm_stat.swap_in_pages));
    (void)(row_put_int64(&row, (int64)stmt->vm_stat.free_pages));
    (void)(row_put_int64(&row, (int64)stmt->query_scn));
    if (stmt->last_sql_active_time == 0) {
        (void)(row_put_null(&row));
    } else {
        (void)(row_put_int64(&row, (int64)stmt->last_sql_active_time));
    }

    (void)(row_put_int64(&row, (int64)stmt->vm_stat.alloc_pages));
    (void)(row_put_int64(&row, (int64)stmt->vm_stat.max_open_pages));
    (void)(row_put_int64(&row, (int64)stmt->vm_stat.swap_out_pages));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vm_slot++;

    // obtaining elapsed_time, disk_reads, disk_reads, buffer_gets, cr_gets, con_wait_time, cpu_time
    vm_open_cursor_fetch_realtime_statistics(stmt, &row);

    return CT_SUCCESS;
}

static status_t vw_open_cursor_fetch_row(knl_handle_t se, knl_cursor_t *cursor)
{
    session_t *session = NULL;
    sql_stmt_t *stmt = NULL;
    status_t ret = CT_SUCCESS;

    do {
        /* fetch session */
        vw_open_cursor_fetch_session(cursor, &session);
        if (cursor->eof == CT_TRUE) {
            return CT_SUCCESS;
        }

        /* fetch stmt */
        cm_spin_lock(&session->sess_lock, NULL);
        if (cursor->rowid.vm_slot >= session->stmts.count) {
            cm_spin_unlock(&session->sess_lock);
            continue;
        }

        vw_open_cursor_fetch_stmt(cursor, session, &stmt);
        if (stmt == NULL) {
            cm_spin_unlock(&session->sess_lock);
            continue;
        }
        cm_spin_lock(&stmt->stmt_lock, NULL);
        if (stmt->status == STMT_STATUS_FREE) {
            cm_spin_unlock(&stmt->stmt_lock);
            cm_spin_unlock(&session->sess_lock);
            continue;
        }
        /* fetch stmt info */
        ret = vm_open_cursor_fetch_core(se, cursor, session, stmt);
        cursor->tenant_id = session->curr_tenant_id;
        cm_spin_unlock(&stmt->stmt_lock);
        cm_spin_unlock(&session->sess_lock);
        return ret;
    } while (CT_TRUE);
}

static status_t vw_open_cursor_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    return vw_fetch_for_tenant(vw_open_cursor_fetch_row, se, cursor);
}

static status_t vw_controlfile_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    CM_POINTER2(se, cursor);
    knl_session_t *session = (knl_session_t *)se;
    database_t *db = &session->kernel->db;
    uint64 ctlfile_idx;
    row_assist_t ra;

    ctlfile_idx = cursor->rowid.vmid;

    cm_spin_lock(&db->ctrl_lock, NULL);
    if (ctlfile_idx >= db->ctrlfiles.count) {
        cm_spin_unlock(&db->ctrl_lock);
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, CONTROLFILE_COLS);
    /* STATUS */
    if (row_put_null(&ra) != CT_SUCCESS) {
        cm_spin_unlock(&db->ctrl_lock);
        return CT_ERROR;
    }
    /* NAME */
    if (row_put_str(&ra, db->ctrlfiles.items[ctlfile_idx].name) != CT_SUCCESS) {
        cm_spin_unlock(&db->ctrl_lock);
        return CT_ERROR;
    }
    /* IS_RECOVERY_DEST_FILE */
    /* there is no chance that a cantian's control file existed in the flashback zone, so always return "NO" */
    if (row_put_str(&ra, "NO") != CT_SUCCESS) {
        cm_spin_unlock(&db->ctrl_lock);
        return CT_ERROR;
    }
    /* BLOCK_SIZE */
    if (row_put_int32(&ra, (int32)db->ctrlfiles.items[ctlfile_idx].block_size) != CT_SUCCESS) {
        cm_spin_unlock(&db->ctrl_lock);
        return CT_ERROR;
    }
    /* FILE_SIZE_BLKS */
    // there is no way to retrieve the actual size of control file
    // from storage engine currently, fill it with zero for temporary
    if (row_put_int32(&ra, 0) != CT_SUCCESS) {
        cm_spin_unlock(&db->ctrl_lock);
        return CT_ERROR;
    }
    cm_spin_unlock(&db->ctrl_lock);

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++; /* increment the index */

    return CT_SUCCESS;
}

#define row_put_nlsvalue(row, nls, id)           \
    do {                                         \
        text_t value;                            \
        (nls)->param_geter((nls), (id), &value); \
        (void)row_put_text((row), &value);       \
    } while (0)

static status_t vw_nls_session_params_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    session_t *session = (session_t *)se;
    uint64 id = cursor->rowid.vmid;
    row_assist_t row;

    const nlsparam_item_t *nls_item = NULL;

    do {
        if (id >= NLS__MAX_PARAM_NUM) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }
        nls_item = &g_nlsparam_items[id];
        id++;
    } while (!nls_item->ss_used);

    row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, NLS_PARAMS_COLS);

    (void)row_put_text(&row, (text_t *)&nls_item->key);
    row_put_nlsvalue(&row, &session->nls_params, nls_item->id);

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid = id;
    return CT_SUCCESS;
}

static status_t vw_free_space_open(knl_handle_t session, knl_cursor_t *cursor)
{
    page_id_t *page_id = (page_id_t *)cursor->page_buf;
    page_id->page = 0;
    page_id->file = INVALID_FILE_ID;
    page_id->aligned = 0;
    cursor->rowid.vmid = 0;
    cursor->rowid.vm_slot = 0;
    cursor->rowid.vm_tag = 0;

    return CT_SUCCESS;
}

static status_t vw_free_space_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    row_assist_t row;
    space_t *space = NULL;
    page_id_t page_id;
    space_head_t *head = NULL;
    space_ctrl_t *ctrl = NULL;
    knl_session_t *session = &((session_t *)se)->knl_session;
    database_t *db = &session->kernel->db;
    page_id_t *next_page_id = (page_id_t *)cursor->page_buf;

    for (;;) {
        uint64 page_count = 0;
        uint32 page_number = 0;
        uint32 extent_count = 0;
        uint32 file_id = 0;
        bool32 is_swap_space = CT_FALSE;
        bool32 is_last = CT_FALSE;
        bool32 invalid_free_extent = CT_FALSE;

        do {
            if ((uint32)cursor->rowid.vm_slot >= CT_MAX_SPACES) {
                cursor->eof = CT_TRUE;
                return CT_SUCCESS;
            }

            space = &db->spaces[(cursor->rowid.vm_slot)];
            head = SPACE_HEAD_RESIDENT(session, space);
            ctrl = space->ctrl;

            if (ctrl != NULL && ctrl->used && head != NULL) {
                break;
            }

            cursor->rowid.vm_slot++;  // space id
            cursor->rowid.vmid = 0;   // free extents count
            cursor->rowid.vm_tag = 0; // hwms id
        } while (CT_TRUE);

        /* get free space by bitmap in bitmap managed space, otherwise, by free list and hwm */
        for (;;) {
            invalid_free_extent = CT_FALSE;
            if (SPACE_IS_BITMAPMANAGED(space)) {
                // if vm_tag bigger than MAX FILES
                if (cursor->rowid.vm_tag >= CT_MAX_SPACE_FILES) {
                    cursor->rowid.vm_slot++;
                    cursor->rowid.vmid = 0;
                    cursor->rowid.vm_tag = 0;
                    break;
                }

                file_id = space->ctrl->files[cursor->rowid.vm_tag];
                if (file_id == CT_INVALID_ID32) {
                    cursor->rowid.vm_tag++;
                    continue;
                }

                if (knl_get_free_extent(session, file_id, *next_page_id, &page_number, &page_count, &is_last) !=
                    CT_SUCCESS) {
                    cursor->rowid.vm_tag++;
                    *next_page_id = INVALID_PAGID;
                    page_number = 0;
                    page_count = 0;
                    invalid_free_extent = CT_TRUE;
                } else {
                    /*
                     * if this is the last extent of current datafile, switch to next datafile.
                     * otherwise, update start postion and fetch again
                     */
                    if (is_last) {
                        cursor->rowid.vm_tag++;
                        *next_page_id = INVALID_PAGID;
                    } else {
                        next_page_id->page = (uint32)(page_number + page_count);
                        next_page_id->file = file_id;
                    }
                }
            } else {
                if (cursor->rowid.vmid < head->free_extents.count) {
                    dls_spin_lock(session, &space->lock, &session->stat->spin_stat.stat_space);
                    if (IS_INVALID_PAGID(*next_page_id)) {
                        *next_page_id = head->free_extents.first;
                    }

                    page_number = next_page_id->vmid;
                    extent_count = 1;

                    is_swap_space = IS_SWAP_SPACE(space);
                    while (cursor->rowid.vmid++ < head->free_extents.count - 1) {
                        page_id = *next_page_id;
                        *next_page_id = is_swap_space ? spc_try_get_next_temp_ext(session, *next_page_id) :
                                                        spc_get_next_ext(session, *next_page_id);
                        if (IS_INVALID_PAGID(*next_page_id)) {
                            dls_spin_unlock(session, &space->lock);
                            CT_THROW_ERROR(ERR_INVALID_PAGE_ID, ", free extent list of swap space is outdated");
                            return CT_ERROR;
                        }

                        if (page_id.vmid == next_page_id->vmid + ctrl->extent_size) {
                            /* page id descend continuously, record next page id as the starting page id */
                            page_number = next_page_id->vmid;
                        } else if (next_page_id->vmid != page_id.vmid + ctrl->extent_size) {
                            /* page id not continuously, break to make a row */
                            break;
                        }

                        extent_count++;
                    }
                    dls_spin_unlock(session, &space->lock);
                    page_count = (uint64)extent_count * ctrl->extent_size;
                    file_id = next_page_id->file;
                } else {
                    page_number = head->hwms[cursor->rowid.vm_tag];
                    file_id = space->ctrl->files[cursor->rowid.vm_tag];
                    cursor->rowid.vm_tag++;
                    if (file_id == CT_INVALID_ID32) {
                        continue;
                    }
                    page_count = (db->datafiles[file_id].ctrl->size / DEFAULT_PAGE_SIZE(session)) - page_number;
                }
            }
            break;
        }

        if (!invalid_free_extent) {
            row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, FREE_SPACE_COLS);

            /* TABLESPACE_NAME */
            CT_RETURN_IFERR(row_put_str(&row, ctrl->name));
            /* FILE_ID */
            CT_RETURN_IFERR(row_put_int32(&row, (int32)file_id));
            /* BLOCK_ID */
            CT_RETURN_IFERR(row_put_int32(&row, (int32)page_number));
            /* BYTES */
            CT_RETURN_IFERR(row_put_int64(&row, (int64)(page_count * DEFAULT_PAGE_SIZE(session))));
            /* BLOCKS */
            CT_RETURN_IFERR(row_put_int64(&row, (int64)page_count));
            /* RELATIVE_FNO */
            CT_RETURN_IFERR(row_put_int32(&row, (int32)file_id));

            cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
        }
        if (((uint32)cursor->rowid.vmid + 1 >= head->free_extents.count && cursor->rowid.vm_tag >= ctrl->file_hwm) ||
            (is_last && cursor->rowid.vm_tag >= ctrl->file_hwm)) {
            cursor->rowid.vm_slot++;
            cursor->rowid.vmid = 0;
            cursor->rowid.vm_tag = 0;
            next_page_id->page = 0;
            next_page_id->file = INVALID_FILE_ID;
            next_page_id->aligned = 0;
        }

        if (!invalid_free_extent) {
            break;
        }
    }

    return CT_SUCCESS;
}

char *vw_pl_type_str(uint32 type)
{
    switch (type) {
        case PL_PROCEDURE:
            return "PROCEDURE";
        case PL_FUNCTION:
            return "FUNCTION";
        case PL_TRIGGER:
            return "TRIGGER";
        case PL_ANONYMOUS_BLOCK:
            return "ANONYMOUS_BLOCK";
        case PL_PACKAGE_SPEC:
            return "PL_PACKAGE_SPEC";
        case PL_PACKAGE_BODY:
            return "PL_PACKAGE_BODY";
        case PL_TYPE_SPEC:
            return "PL_TYPE_SPEC";
        case PL_TYPE_BODY:
            return "PL_TYPE_BODY";
        case PL_SYS_PACKAGE:
            return "PL_SYS_PACKAGE";
        case PL_SYNONYM:
            return "PL_SYNONYM";
        default:
            return "unknown";
    }
}

static inline status_t vw_make_core_plmngr(knl_handle_t se, knl_cursor_t *cursor, pl_entry_t *entry, uint32 bid,
    uint32 bpos)
{
    row_assist_t row;
    dc_user_t *dc_user = NULL;
    dc_entry_t *dc_entry = NULL;
    knl_session_t *sess = (knl_session_t *)se;

    CT_RETURN_IFERR(dc_open_user_by_id(sess, entry->desc.uid, &dc_user));
    row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, PL_MNGR_COLS);

    (void)row_put_int32(&row, (int32)entry->desc.uid);
    (void)row_put_str(&row, dc_user->desc.name);
    (void)row_put_str(&row, entry->desc.name);
    (void)row_put_str(&row, vw_pl_type_str(entry->desc.type));
    (void)row_put_int32(&row, (int32)bid);
    (void)row_put_int32(&row, (int32)bpos);
    (void)row_put_int32(&row, 0);
    if (entry->desc.type == PL_TRIGGER) {
        uint32 uid = entry->desc.trig_def.obj_uid;
        uint32 oid = (uint32)entry->desc.trig_def.obj_oid;

        CT_RETURN_IFERR(dc_open_user_by_id(sess, uid, &dc_user));
        dc_entry = DC_GET_ENTRY(dc_user, oid);
        if (dc_entry == NULL) {
            (void)(row_put_null(&row));
            (void)(row_put_null(&row));
        } else {
            (void)(row_put_str(&row, dc_user->desc.name));
            (void)(row_put_str(&row, dc_entry->name));
        }
    } else {
        (void)(row_put_null(&row));
        (void)(row_put_null(&row));
    }
    pl_entry_lock(entry);
    if (entry->entity == NULL) {
        (void)row_put_int32(&row, 0);
        (void)row_put_int64(&row, 0);
        (void)row_put_int32(&row, 0);
    } else {
        (void)row_put_int32(&row, entry->entity->ref_count);
        (void)row_put_int64(&row, (int64)entry->entity);
        (void)row_put_int32(&row, (int32)entry->entity->memory->pages.count);
    }
    (void)(row_put_null(&row));
    pl_entry_unlock(entry);

    return CT_SUCCESS;
}

// if it fails, it cannot affect the next row.
// is_continue = TRUE, fetch next row
// is_continue= FALSE, success to fetch current row and return data
static void vw_pl_mngr_address(knl_handle_t se, knl_cursor_t *cursor, pl_entry_t *entry, uint32 bid, uint32 bpos,
    bool8 *is_continue)
{
    *is_continue = CT_TRUE;
    dc_user_t *user = NULL;
    pl_entry_info_t entry_info = {
        .entry = entry,
        .scn = entry->desc.chg_scn
    };

    if (!entry->ready) {
        return;
    }
    if (pl_lock_entry_shared(se, &entry_info) != CT_SUCCESS) {
        return;
    }
    if (vw_make_core_plmngr(se, cursor, entry, bid, bpos) != CT_SUCCESS) {
        pl_unlock_shared(se, entry);
        return;
    }
    CURSOR_SET_TENANT_ID_BY_USER(dc_open_user_by_id((knl_session_t *)se, entry->desc.uid, &user), cursor, user);
    pl_unlock_shared(se, entry);
    *is_continue = CT_FALSE;
    return;
}

static void vw_pl_mngr_make_subobject(knl_handle_t se, knl_cursor_t *cursor, dc_user_t *user, function_t *func,
    text_t *name)
{
    row_assist_t row;
    uint32 bid = cursor->rowid.bucket_id;
    uint32 bpos = cursor->rowid.pos;

    row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, PL_MNGR_COLS);
    (void)row_put_int32(&row, (int32)user->desc.id);
    (void)row_put_str(&row, user->desc.name);
    (void)row_put_str(&row, func->desc.name);
    (void)row_put_str(&row, vw_pl_type_str(func->desc.pl_type));
    (void)row_put_int32(&row, (int32)bid);
    (void)row_put_int32(&row, (int32)bpos);
    (void)row_put_int32(&row, 0);
    (void)row_put_null(&row);
    (void)row_put_null(&row);
    (void)row_put_int32(&row, 0);
    (void)row_put_int64(&row, 0);
    (void)row_put_int32(&row, 0);
    (void)row_put_text(&row, name);
    cursor->tenant_id = user->desc.tenant_id;
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.sub_id++;
}

static status_t vw_pl_mngr_fetch_package_subobject(knl_handle_t se, knl_cursor_t *cursor, uint32 uid, text_t *name)
{
    sql_stmt_t *stmt = ((session_t *)se)->current_stmt;
    pl_dc_assist_t assist = { 0 };
    pl_dc_t pl_dc = { 0 };
    dc_user_t *dc_user = NULL;
    bool32 found = CT_FALSE;
    text_t user;
    uint32 sub_id = cursor->rowid.sub_id;

    if (dc_open_user_by_id(se, uid, &dc_user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cm_str2text(dc_user->desc.name, &user);

    // open package dc, should not check priv,it is display not execute
    pl_dc_open_prepare_for_ignore_priv(&assist, stmt, &user, name, PL_PACKAGE_SPEC);
    if (pl_dc_open(&assist, &pl_dc, &found) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!found) {
        return CT_ERROR;
    }

    if (pl_dc.type != PL_PACKAGE_SPEC) {
        pl_dc_close(&pl_dc);
        return CT_ERROR;
    }

    galist_t *sublist = pl_dc.entity->package_spec->defs;
    if (sub_id > sublist->count) {
        pl_dc_close(&pl_dc);
        return CT_ERROR;
    }

    plv_decl_t *decl = (plv_decl_t *)cm_galist_get(sublist, sub_id - 1);
    function_t *func = decl->func;
    vw_pl_mngr_make_subobject(se, cursor, dc_user, func, name);
    pl_dc_close(&pl_dc);
    return CT_SUCCESS;
}

static status_t vw_pl_mngr_fetch_package(knl_handle_t se, knl_cursor_t *cursor)
{
    pl_manager_t *pl_mngr = GET_PL_MGR;
    uint32 bid = cursor->rowid.bucket_id;
    uint32 bpos = cursor->rowid.pos;
    pl_list_t *entry_list = NULL;
    bilist_node_t *entry_node = NULL;
    pl_entry_t *entry = NULL;
    uint32 uid;
    char name_buf[CT_NAME_BUFFER_SIZE];
    text_t name;

    entry_list = &pl_mngr->entry_oid_buckets[bid];
    if (bpos >= entry_list->lst.count) {
        cursor->rowid.pos = 0;
        cursor->rowid.bucket_id++;
        return CT_ERROR;
    }

    cm_latch_s(&entry_list->latch, CM_THREAD_ID, CT_FALSE, NULL);
    entry_node = cm_bilist_get(&entry_list->lst, bpos);
    if (entry_node == NULL) {
        cm_unlatch(&entry_list->latch, NULL);
        cursor->rowid.pos++;
        return CT_ERROR;
    }
    entry = BILIST_NODE_OF(pl_entry_t, entry_node, oid_link);
    if (!entry->ready || entry->desc.type != PL_PACKAGE_SPEC) {
        cm_unlatch(&entry_list->latch, NULL);
        cursor->rowid.pos++;
        return CT_ERROR;
    }
    uid = entry->desc.uid;
    errno_t err = strcpy_s(name_buf, CT_NAME_BUFFER_SIZE, entry->desc.name);
    if (err != EOK) {
        cm_unlatch(&entry_list->latch, NULL);
        cursor->rowid.pos++;
        return CT_ERROR;
    }
    cm_unlatch(&entry_list->latch, NULL);
    cm_str2text(name_buf, &name);

    if (vw_pl_mngr_fetch_package_subobject(se, cursor, uid, &name) != CT_SUCCESS) {
        cursor->rowid.pos++;
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t vw_pl_mngr_fetch_core(knl_handle_t se, knl_cursor_t *cursor)
{
    pl_manager_t *pl_mngr = GET_PL_MGR;
    pl_list_t *entry_list = NULL;
    bool8 is_continue = CT_FALSE;
    pl_entry_t *entry = NULL;
    bilist_node_t *entry_node = NULL;
    uint32 sub_id = cursor->rowid.sub_id;

    if (sub_id > 0 && vw_pl_mngr_fetch_package(se, cursor) == CT_SUCCESS) {
        return CT_SUCCESS;
    }

    uint32 bid = cursor->rowid.bucket_id;
    uint32 bpos = cursor->rowid.pos;

    while (CT_TRUE) {
        if (bid >= PL_ENTRY_OID_BUCKET_SIZE) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }

        entry_list = &pl_mngr->entry_oid_buckets[bid];
        if (bpos >= entry_list->lst.count) {
            bpos = 0;
            bid++;
            continue;
        }

        cm_latch_s(&entry_list->latch, CM_THREAD_ID, CT_FALSE, NULL);
        entry_node = cm_bilist_get(&entry_list->lst, bpos);
        if (entry_node == NULL) {
            cm_unlatch(&entry_list->latch, NULL);
            bpos = 0;
            bid++;
            continue;
        }
        entry = BILIST_NODE_OF(pl_entry_t, entry_node, oid_link);
        vw_pl_mngr_address(se, cursor, entry, bid, bpos, &is_continue);
        cm_unlatch(&entry_list->latch, NULL);
        if (is_continue) {
            cm_reset_error();
            bpos++;
            continue;
        }
        if (entry->desc.type != PL_PACKAGE_SPEC) {
            cursor->rowid.sub_id = 0;
            bpos++;
        } else {
            cursor->rowid.sub_id = 1;
        }
        break;
    }

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.bucket_id = bid;
    cursor->rowid.pos = bpos;
    return CT_SUCCESS;
}

static status_t vw_pl_mngr_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    return vw_fetch_for_tenant(vw_pl_mngr_fetch_core, se, cursor);
}

static inline bool32 vw_tryfind_sql_text(const char *buffer, uint32 buf_len, uint32 *endPos, const char flag)
{
    for (uint32 i = 0; i < buf_len; i++) {
        if (buffer[i] == flag) {
            *endPos = i;
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

static void vm_make_uwl_entry_string(list_t *cidrs_l, char *cidrs_str, size_t size)
{
    char ip_str[CM_MAX_IP_LEN];
    int offset = 0;
    int count = 0;

    for (uint32 i = 0; i < cidrs_l->count; i++) {
        cidr_t *cidr = (cidr_t *)cm_list_get(cidrs_l, i);

        count = sprintf_s(cidrs_str + offset, (size_t)(size - offset), "%s/%d%s",
            cm_inet_ntop((struct sockaddr *)&cidr->addr, ip_str, CM_MAX_IP_LEN), cidr->mask,
            i != cidrs_l->count - 1 ? "," : "");
        PRTS_RETVOID_IFERR(count);
        offset += count;
    }
}

static status_t vw_hba_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    white_context_t *ctx = GET_WHITE_CTX;
    list_t *uwl = &ctx->user_white_list;
    char cidrs[CT_MAX_COLUMN_SIZE] = { 0 };
    row_assist_t ra;

    cm_spin_lock(&ctx->lock, NULL);
    if (cursor->rowid.vmid >= uwl->count) {
        cm_spin_unlock(&ctx->lock);
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    uwl_entry_t *uwl_entry = (uwl_entry_t *)cm_list_get(uwl, (uint32)cursor->rowid.vmid);
    vm_make_uwl_entry_string(&uwl_entry->white_list, cidrs, CT_MAX_COLUMN_SIZE);

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, HBA_COLS);

    /* TYPE */
    if (uwl_entry->hostssl) {
        (void)row_put_str(&ra, "hostssl");
    } else {
        (void)row_put_str(&ra, "host");
    }

    /* USER */
    (void)row_put_str(&ra, uwl_entry->user);

    /* cidrs */
    (void)row_put_str(&ra, cidrs);

    cm_spin_unlock(&ctx->lock);

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;

    return CT_SUCCESS;
}
static status_t vw_pbl_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    black_context_t *ctx = GET_PWD_BLACK_CTX;
    list_t *pbl = &ctx->user_pwd_black_list;
    row_assist_t ra;

    cm_spin_lock(&ctx->lock, NULL);
    if (cursor->rowid.vmid >= pbl->count) {
        cm_spin_unlock(&ctx->lock);
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }
    pbl_entry_t *pbl_entry = (pbl_entry_t *)cm_list_get(pbl, (uint32)cursor->rowid.vmid);
    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, PBL_COLS);
    (void)row_put_str(&ra, pbl_entry->user);
    (void)row_put_str(&ra, pbl_entry->pwd);
    cm_spin_unlock(&ctx->lock);
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

static void vm_tcp_node_row_put(knl_cursor_t *cursor, bool32 is_white, list_t *ip_list, uint32 idx)
{
    cidr_t *cidr = NULL;
    char cidrs[CM_MAX_IP_LEN] = { 0 };
    char ip_str[CM_MAX_IP_LEN] = { 0 };
    row_assist_t ra;

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, WHITELIST_COLS);

    cidr = (cidr_t *)cm_list_get(ip_list, idx);
    PRTS_RETVOID_IFERR(sprintf_s(cidrs, (size_t)(CM_MAX_IP_LEN), "%s/%d",
        cm_inet_ntop((struct sockaddr *)&cidr->addr, ip_str, CM_MAX_IP_LEN), cidr->mask));

    /* HOST_TYPE */
    (void)row_put_str(&ra, "host");
    /* USER */
    (void)row_put_str(&ra, "*");
    /* cidrs */
    (void)row_put_str(&ra, cidrs);
    /* black or white */
    if (is_white) {
        (void)row_put_str(&ra, "IP_WHITE");
    } else {
        (void)row_put_str(&ra, "IP_BLACK");
    }
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
}

static void vm_whitelist_put_hba_core(knl_cursor_t *cursor, uwl_entry_t *uwl_entry, cidr_t *cidr)
{
    char cidr_str[CM_MAX_IP_LEN] = { 0 };
    char ip_str[CM_MAX_IP_LEN] = { 0 };
    row_assist_t ra;

    PRTS_RETVOID_IFERR(sprintf_s(cidr_str, (size_t)(CM_MAX_IP_LEN), "%s/%d",
        cm_inet_ntop((struct sockaddr *)&cidr->addr, ip_str, CM_MAX_IP_LEN), cidr->mask));

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, WHITELIST_COLS);

    /* HOST_TYPE */
    if (uwl_entry->hostssl) {
        (void)row_put_str(&ra, "hostssl");
    } else {
        (void)row_put_str(&ra, "host");
    }
    /* USER */
    (void)row_put_str(&ra, uwl_entry->user);
    /* cidrs */
    (void)row_put_str(&ra, cidr_str);
    (void)row_put_str(&ra, "HBA_WHITE");
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);

    cursor->rowid.vm_slot++;
}

static void vm_hba_list_row_put(knl_cursor_t *cursor, list_t *uwl, uint32 ip_count)
{
    cidr_t *cidr = NULL;
    uwl_entry_t *uwl_entry = (uwl_entry_t *)cm_list_get(uwl, (uint32)(cursor->rowid.vmid - ip_count));
    if (uwl_entry == NULL || uwl_entry->white_list.count == 0) {
        cursor->rowid.vmid++;
        return;
    }
    cidr = (cidr_t *)cm_list_get(&uwl_entry->white_list, (uint32)cursor->rowid.vm_slot);
    vm_whitelist_put_hba_core(cursor, uwl_entry, cidr);
    if (cursor->rowid.vm_slot == uwl_entry->white_list.count) {
        cursor->rowid.vmid++;
        cursor->rowid.vm_slot = 0;
    }
}

static status_t vw_whitelist_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    white_context_t *ctx = GET_WHITE_CTX;
    list_t *uwl = &ctx->user_white_list;
    list_t *ipwl = &ctx->ip_white_list;
    list_t *ipbl = &ctx->ip_black_list;

    cm_spin_lock(&ctx->lock, NULL);
    uint32 ip_count = ctx->iwl_enabled ? (ipwl->count + ipbl->count) : 0;
    uint64 total_count = ctx->iwl_enabled ? (uwl->count + ip_count) : uwl->count;
    if (cursor->rowid.vmid >= total_count) {
        cm_spin_unlock(&ctx->lock);
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    if (ctx->iwl_enabled && cursor->rowid.vmid < ipbl->count) {
        /* tcp node: black list */
        vm_tcp_node_row_put(cursor, CT_FALSE, ipbl, (uint32)cursor->rowid.vmid);
        cm_spin_unlock(&ctx->lock);
        cursor->rowid.vmid++;
        return CT_SUCCESS;
    }

    if (ctx->iwl_enabled && cursor->rowid.vmid < (ipbl->count + ipwl->count)) {
        /* tcp node: white list */
        vm_tcp_node_row_put(cursor, CT_TRUE, ipwl, (uint32)(cursor->rowid.vmid - ipbl->count));
        cm_spin_unlock(&ctx->lock);
        cursor->rowid.vmid++;
        return CT_SUCCESS;
    }

    if (cursor->rowid.vmid < total_count) {
        /* cthba.conf: user white list */
        vm_hba_list_row_put(cursor, uwl, ip_count);
        cm_spin_unlock(&ctx->lock);
        return CT_SUCCESS;
    }

    cm_spin_unlock(&ctx->lock);
    cursor->eof = CT_TRUE;
    return CT_SUCCESS;
}

static void vw_make_temptable_row(knl_session_t *session, knl_cursor_t *cursor)
{
    knl_temp_cache_t *temp_table = NULL;
    mtrl_segment_t *data_segement = NULL;
    mtrl_segment_t *index_segment = NULL;
    dc_entry_t *entry = NULL;
    row_assist_t ra;
    uint32 data_pages_num = 0;
    uint32 index_pages_num = 0;
    mtrl_context_t *ctx = session->temp_mtrl;

    entry = (dc_entry_t *)session->temp_dc->entries[cursor->rowid.vm_slot];

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, TEMPTABLES_COLS);
    row_put_int32(&ra, session->id);
    row_put_str(&ra, entry->user->desc.name);
    row_put_str(&ra, entry->name);
    row_put_int32(&ra, entry->entity->column_count);
    row_put_int32(&ra, entry->entity->table.index_set.count);

    for (uint32 i = 0; i < session->temp_table_count; i++) {
        temp_table = &session->temp_table_cache[i];
        if (temp_table->table_id == entry->id) {
            data_segement = ctx->segments[temp_table->table_segid];
            data_pages_num = data_segement->vm_list.count;

            if (temp_table->index_segid != CT_INVALID_ID32) {
                index_segment = ctx->segments[temp_table->index_segid];
                index_pages_num = index_segment->vm_list.count;
            }
        }
    }
    row_put_int32(&ra, data_pages_num);
    row_put_int32(&ra, index_pages_num);
}


static status_t vw_temptables_fetch_core(knl_handle_t se, knl_cursor_t *cursor)
{
    session_t *item = NULL;
    knl_session_t *session = NULL;

    while (CT_TRUE) {
        if (cursor->rowid.vmid >= g_instance->session_pool.hwm) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }

        item = g_instance->session_pool.sessions[cursor->rowid.vmid];
        if (((item->type == SESSION_TYPE_USER && item->is_reg) || item->type == SESSION_TYPE_EMERG) && !item->is_free &&
            !item->knl_session.killed) {
            session = &item->knl_session;
            if (session->temp_dc != NULL && cursor->rowid.vm_slot < session->temp_table_capacity) {
                cm_latch_s(&session->ltt_latch, session->id, CT_FALSE, NULL);
                if ((dc_entry_t *)session->temp_dc->entries[cursor->rowid.vm_slot] != NULL) {
                    break;
                }
                cm_unlatch(&session->ltt_latch, NULL);
                cursor->rowid.vm_slot++;
                continue;
            }
        }

        cursor->rowid.vmid++;
        cursor->rowid.vm_slot = 0;
    }

    vw_make_temptable_row(session, cursor);
    cursor->tenant_id = item->curr_tenant_id;
    cm_unlatch(&session->ltt_latch, NULL);
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vm_slot++;
    return CT_SUCCESS;
}

static status_t vw_temptables_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    return vw_fetch_for_tenant(vw_temptables_fetch_core, se, cursor);
}

static inline status_t vw_make_core_refsqls(knl_session_t *sess, row_assist_t *row, knl_cursor_t *cursor,
    pl_entity_t *entity, uint32 sqlpos, pl_entry_t *entry)
{
    char hash_valstr[CT_MAX_UINT32_STRLEN + 1];
    dc_user_t *user = NULL;
    sql_context_t *sql_ln_context = (sql_context_t *)cm_galist_get(&entity->sqls, sqlpos);

    CURSOR_SET_TENANT_ID_BY_USER(dc_open_user_by_id(sess, entry->desc.uid, &user), cursor, user);
    row_init(row, (char *)cursor->row, CT_MAX_ROW_SIZE, PL_REFSQLS_COLS);
    CT_RETURN_IFERR(row_put_int32(row, (int32)entry->desc.uid));
    CT_RETURN_IFERR(row_put_str(row, user->desc.name));
    CT_RETURN_IFERR(row_put_str(row, entry->desc.name));
    CT_RETURN_IFERR(row_put_int64(row, (int64)entry->entity));

    PRTS_RETURN_IFERR(sprintf_s(hash_valstr, (CT_MAX_UINT32_STRLEN + 1), "%010u", sql_ln_context->ctrl.hash_value));
    CT_RETURN_IFERR(row_put_str(row, hash_valstr)); /* sql_id */

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    return CT_SUCCESS;
}

static status_t vw_pl_refsqls_address(knl_handle_t se, knl_cursor_t *cursor, uint32 *bpos, uint32 *sqlpos,
    bool8 *is_break)
{
    row_assist_t row;
    pl_entry_t *entry = NULL;
    pl_manager_t *pl_mngr = GET_PL_MGR;
    pl_list_t *list = NULL;
    bilist_node_t *node = NULL;
    pl_entity_t *pl_entity = NULL;
    uint32 b_pos = *bpos;
    uint32 sql_pos = *sqlpos;
    knl_session_t *sess = (knl_session_t *)se;

    list = &pl_mngr->entry_oid_buckets[cursor->rowid.vmid];
    cm_latch_s(&list->latch, CM_THREAD_ID, CT_FALSE, NULL);
    node = cm_bilist_get(&list->lst, b_pos);
    if (node == NULL) {
        cm_unlatch(&list->latch, NULL);
        return CT_SUCCESS;
    }

    entry = BILIST_NODE_OF(pl_entry_t, node, oid_link);
    pl_entity = entry->entity;
    if (pl_entity == NULL) {
        cursor->rowid.vm_tag = 0;
    } else if (sql_pos >= pl_entity->sqls.count) {
        b_pos = (uint32)cursor->rowid.vm_tag + 1;
        sql_pos = 0;
    } else {
        *bpos = (uint32)cursor->rowid.vm_tag;
        if (vw_make_core_refsqls(sess, &row, cursor, pl_entity, (uint32)sql_pos, entry) != CT_SUCCESS) {
            cm_unlatch(&list->latch, NULL);
            return CT_ERROR;
        }
        cm_unlatch(&list->latch, NULL);
        sql_pos++;
        *sqlpos = sql_pos;
        *is_break = CT_TRUE;
        return CT_SUCCESS;
    }
    cm_unlatch(&list->latch, NULL);

    *bpos = b_pos;
    *sqlpos = sql_pos;
    return CT_SUCCESS;
}

static status_t vw_pl_refsqls_fetch_core(knl_handle_t se, knl_cursor_t *cursor)
{
    uint32 bpos = (uint32)cursor->rowid.vm_tag;
    uint32 sqlpos = (uint32)cursor->rowid.vm_slot;
    bool8 is_break = CT_FALSE;

    for (;;) {
        if (cursor->rowid.vmid >= PL_ENTRY_OID_BUCKET_SIZE) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }
        CT_RETURN_IFERR(vw_pl_refsqls_address(se, cursor, &bpos, &sqlpos, &is_break));
        if (is_break) {
            break;
        }
        cursor->rowid.vmid++;
    }

    cursor->rowid.vm_tag = bpos;
    cursor->rowid.vm_slot = sqlpos;
    return CT_SUCCESS;
}

static status_t vw_pl_refsqls_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    return vw_fetch_for_tenant(vw_pl_refsqls_fetch_core, se, cursor);
}

static status_t vw_running_job_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    row_assist_t row;

    if (cursor->eof == CT_TRUE) {
        return CT_SUCCESS;
    }

    cm_spin_lock(&g_instance->job_mgr.lock, NULL);
    if (cursor->rowid.vm_slot >= g_instance->job_mgr.running_count) {
        cm_spin_unlock(&g_instance->job_mgr.lock);
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, JOBS_RUNNING_COLS);
    (void)row_put_int64(&row, g_instance->job_mgr.running_jobs[cursor->rowid.vm_slot].job_id);
    (void)row_put_int32(&row, (int32)(g_instance->job_mgr.running_jobs[cursor->rowid.vm_slot].session_id));
    (void)row_put_int32(&row, (int32)(g_instance->job_mgr.running_jobs[cursor->rowid.vm_slot].serial_id));

    if (cursor->rowid.vm_slot >= g_instance->job_mgr.running_count) {
        cursor->eof = CT_TRUE;
    }

    cm_spin_unlock(&g_instance->job_mgr.lock);

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vm_slot++;

    return CT_SUCCESS;
}

static void vw_dc_pool_put_row(knl_cursor_t *cursor)
{
    dc_context_t *dc_ctx = &g_instance->kernel.dc_ctx;
    dc_lru_queue_t *queue = dc_ctx->lru_queue;
    row_assist_t row;
    uint64 lru_count, lru_page_count, lru_recyclable_count, lru_recyclable_page_count;
    uint64 lru_locked_count, lru_locked_page_count, lru_all_recyclable_count, lru_all_recyclable_page_count;

    lru_count = queue->count;
    lru_page_count = 0;
    lru_recyclable_count = 0;
    lru_recyclable_page_count = 0;
    lru_all_recyclable_count = 0;
    lru_all_recyclable_page_count = 0;
    lru_locked_count = 0;
    lru_locked_page_count = 0;
    dc_entity_t *head = queue->head;
    dc_entity_t *curr = queue->tail;

    while (curr != NULL) {
        lru_page_count += curr->memory->pages.count;

        if (curr->ref_count == 0 && curr->valid && curr == curr->entry->entity &&
            curr->entry->need_empty_entry == CT_FALSE) {
            lru_all_recyclable_count++;
            lru_all_recyclable_page_count += curr->memory->pages.count;
            if (dc_is_locked(curr->entry)) {
                lru_locked_count++;
                lru_locked_page_count += curr->memory->pages.count;
            }
        }
        if (curr == head) {
            break;
        }
        curr = curr->lru_prev;
    }

    lru_recyclable_count = lru_all_recyclable_count - lru_locked_count;
    lru_recyclable_page_count = lru_all_recyclable_page_count - lru_locked_page_count;

    row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, DC_POOL_COLS);
    (void)row_put_int32(&row, (int32)dc_ctx->pool.opt_count);        // dc pool opt count
    (void)row_put_int32(&row, (int32)dc_ctx->pool.page_count);       // dc pool page count
    (void)row_put_int32(&row, (int32)dc_ctx->pool.free_pages.count); // dc pool free page count
    (void)row_put_int32(&row, (int32)lru_count);                     // dc lru count
    (void)row_put_int32(&row, (int32)lru_page_count);                // dc lru page count
    (void)row_put_int32(&row, (int32)lru_locked_count);              // dc lru locked recyclable count
    (void)row_put_int32(&row, (int32)lru_locked_page_count);         // dc lru locked recyclable page count
    (void)row_put_int32(&row, (int32)lru_recyclable_count);          // dc lru recyclable count
    (void)row_put_int32(&row, (int32)lru_recyclable_page_count);     // dc lru recyclable page count
}

static status_t vw_dc_pool_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    dc_context_t *dc_ctx = &g_instance->kernel.dc_ctx;
    dc_lru_queue_t *queue = dc_ctx->lru_queue;

    if (cursor->rowid.vm_slot > 0) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }
    cm_spin_lock(&queue->lock, NULL);
    if (queue->count == 0) {
        cm_spin_unlock(&queue->lock);
        cursor->eof = CT_TRUE;
        return CT_ERROR;
    }

    vw_dc_pool_put_row(cursor);
    cm_spin_unlock(&queue->lock);

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vm_slot++;

    return CT_SUCCESS;
}

static char *vw_reactor_status(reactor_t *reactor)
{
    switch (reactor->status) {
        case REACTOR_STATUS_RUNNING:
            return "RUNNING";
        case REACTOR_STATUS_PAUSING:
            return "PAUSING";
        case REACTOR_STATUS_PAUSED:
            return "PAUSED";
        default:
            return "STOPPED";
    }
}

static status_t vw_reactor_pool_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    row_assist_t row;
    reactor_pool_t *reactor_pool = &g_instance->reactor_pool;

    if (cursor->rowid.vm_slot >= reactor_pool->reactor_count) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }
    reactor_t *reactor = &reactor_pool->reactors[cursor->rowid.vm_slot];

    row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, REACTOR_POOL_COLS);
    (void)row_put_int32(&row, (int32)cursor->rowid.vm_slot);
    (void)row_put_int32(&row, reactor->epollfd);
    (void)row_put_str(&row, vw_reactor_status(reactor));
    (void)row_put_int32(&row, (int32)reactor->session_count);
    (void)row_put_int32(&row, (int32)reactor->kill_events.r_pos);
    (void)row_put_int32(&row, (int32)reactor->kill_events.w_pos);
    (void)row_put_int32(&row, (int32)reactor->agent_pool.curr_count);
    (void)row_put_int32(&row, (int32)reactor->agent_pool.blank_count);
    (void)row_put_int32(&row, (int32)reactor->agent_pool.idle_count);
    (void)row_put_int32(&row, (int32)reactor->agent_pool.optimized_count);
    (void)row_put_int32(&row, (int32)reactor->agent_pool.max_count);
    (void)row_put_str(&row, reactor_in_dedicated_mode(reactor) ? "dedicate" : "sharing");
    /* abandoned field */
    (void)row_put_int32(&row, (int32)0);
    (void)row_put_int32(&row, (int32)0);
    (void)row_put_int32(&row, (int32)0);
    (void)row_put_int32(&row, (int32)0);

    if (IS_COORDINATOR || IS_DATANODE) {
        (void)row_put_int32(&row, (int32)reactor->priv_agent_pool.curr_count);
        (void)row_put_int32(&row, (int32)reactor->priv_agent_pool.blank_count);
        (void)row_put_int32(&row, (int32)reactor->priv_agent_pool.idle_count);
        (void)row_put_int32(&row, (int32)reactor->priv_agent_pool.optimized_count);
        (void)row_put_int32(&row, (int32)reactor->priv_agent_pool.max_count);
    } else {
        (void)row_put_int32(&row, 0);
        (void)row_put_int32(&row, 0);
        (void)row_put_int32(&row, 0);
        (void)row_put_int32(&row, 0);
        (void)row_put_int32(&row, 0);
    }

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vm_slot++;

    return CT_SUCCESS;
}


static status_t vw_emerg_pool_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    row_assist_t row;
    int32 idle_sessions = 0;

    if (cursor->rowid.vmid > 0) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    MEMS_RETURN_IFERR(memset_s(&row, sizeof(row_assist_t), 0, sizeof(row_assist_t)));
    row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, EMERG_POOL_COLS);
    CT_RETURN_IFERR(row_put_int32(&row, g_instance->sql_emerg_pool.max_sessions));
    CT_RETURN_IFERR(row_put_int32(&row, (int32)g_instance->sql_emerg_pool.service_count));

    cm_spin_lock(&g_instance->sql_emerg_pool.lock, NULL);
    biqueue_node_t *curr = biqueue_first(&g_instance->sql_emerg_pool.idle_sessions);
    biqueue_node_t *end = biqueue_end(&g_instance->sql_emerg_pool.idle_sessions);

    while (curr != end) {
        idle_sessions++;
        curr = curr->next;
    }
    cm_spin_unlock(&g_instance->sql_emerg_pool.lock);
    CT_RETURN_IFERR(row_put_int32(&row, idle_sessions));
    CT_RETURN_IFERR(row_put_str(&row, (const char *)g_instance->lsnr.uds_service.names[0]));
    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

/**
 * dynamic view for global transaction
 */
static status_t vw_global_transaction_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    rm_pool_t *rm_pool = &g_instance->rm_pool;
    knl_rm_t *rm = NULL;
    char str_array[CT_MAX_NAME_LEN] = {0};
    knl_xa_xid_t xa_xid;
    xid_t xid;
    uint8 xa_stat;
    text_t text;
    row_assist_t ra;

    if (cursor->rowid.vmid >= rm_pool->hwm) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    rm = rm_pool->rms[cursor->rowid.vmid];
    xa_xid = rm->xa_xid;
    xa_stat = rm->xa_status;
    xid = rm->xid;

    while (!knl_xa_xid_valid(&xa_xid)) {
        cursor->rowid.vmid++;
        if (cursor->rowid.vmid >= rm_pool->hwm) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }

        rm = rm_pool->rms[cursor->rowid.vmid];
        xa_xid = rm->xa_xid;
        xa_stat = rm->xa_status;
        xid = rm->xid;
    }

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, GLOBAL_TRANSACTION_COLS);
    cm_str2text_safe(xa_xid.gtrid, xa_xid.gtrid_len, &text);
    (void)row_put_text(&ra, &text);
    PRTS_RETURN_IFERR(snprintf_s(str_array, CT_MAX_NAME_LEN, CT_MAX_NAME_LEN - 1, "%llu", xa_xid.fmt_id));
    (void)row_put_str(&ra, str_array);
    cm_str2text_safe(xa_xid.bqual, xa_xid.bqual_len, &text);
    (void)row_put_text(&ra, &text);

    PRTS_RETURN_IFERR(snprintf_s(str_array, CT_MAX_NAME_LEN, CT_MAX_NAME_LEN - 1, "%u.%u.%u", xid.xmap.seg_id,
        xid.xmap.slot, xid.xnum));

    (void)row_put_str(&ra, str_array);
    (void)row_put_str(&ra, xa_status2str((xa_status_t)xa_stat));
    (void)row_put_int32(&ra, (int32)rm->sid);
    (void)row_put_int32(&ra, (int32)cursor->rowid.vmid);
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);

    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

static inline status_t vw_dc_rankings_compare(mtrl_segment_t *segment, char *row1, char *row2, int32 *result)
{
    uint32 *col_id = (uint32 *)segment->cmp_items;
    uint16 offsets[DC_RANKINGS_COLUMN_COUNT], lens[DC_RANKINGS_COLUMN_COUNT];
    char *col1 = NULL;
    char *col2 = NULL;

    cm_decode_row(row1, offsets, lens, NULL);
    col1 = (char *)row1 + offsets[*col_id];

    cm_decode_row(row2, offsets, lens, NULL);
    col2 = (char *)row2 + offsets[*col_id];

    *result = NUM_DATA_CMP(uint32, col1, col2);

    return CT_SUCCESS;
}

static inline status_t vw_dc_rankings_collect(knl_handle_t knl_session, knl_cursor_t *cursor, mtrl_context_t *mtrl_ctx,
    uint32 seg_id, uint32 col_count)
{
    knl_session_t *session = (knl_session_t *)knl_session;
    dc_context_t *dc_ctx = &session->kernel->dc_ctx;
    dc_lru_queue_t *queue = dc_ctx->lru_queue;
    dc_entity_t *head = NULL;
    dc_entity_t *curr = NULL;
    char *buf = NULL;
    mtrl_rowid_t rid;
    row_assist_t ra;

    cm_spin_lock(&queue->lock, NULL);

    if (queue->count == 0) {
        cm_spin_unlock(&queue->lock);
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    head = queue->head;
    curr = queue->tail;

    CM_SAVE_STACK(session->stack);

    buf = (char *)cm_push(session->stack, CT_MAX_ROW_SIZE);

    while (curr != NULL) {
        row_init(&ra, buf, CT_MAX_ROW_SIZE, col_count);
        (void)row_put_str(&ra, curr->entry->user->desc.name); // user name
        (void)row_put_str(&ra, curr->entry->name);            // object name
        (void)row_put_int32(&ra, curr->memory->pages.count);  // page count -- key column
        (void)row_put_int32(&ra, curr->ref_count);            // ref count
        (void)row_put_int32(&ra, curr->valid);                // valid
        if (mtrl_insert_row(mtrl_ctx, seg_id, buf, &rid) != CT_SUCCESS) {
            cm_spin_unlock(&queue->lock);
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (curr == head) {
            break;
        }

        curr = curr->lru_prev;
    }

    cm_spin_unlock(&queue->lock);

    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

/* fill dst page from segment until full */
status_t vw_dc_rankings_fill_page(mtrl_context_t *ctx, mtrl_page_t *dst_page, mtrl_segment_t *segment)
{
    vm_page_t *curr_vm = NULL;
    vm_page_t *prev_vm = NULL;
    mtrl_page_t *src_page = NULL;
    vm_ctrl_t *ctrl = NULL;
    uint32 curr_vmid, list_count;

    mtrl_init_page(dst_page, CT_INVALID_ID32);

    list_count = segment->vm_list.count;
    curr_vmid = segment->vm_list.last;

    if (mtrl_open_page(ctx, curr_vmid, &curr_vm) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* in fact,at most two pages are scanned here */
    for (src_page = (mtrl_page_t *)curr_vm->data; curr_vm->vmid != CT_INVALID_ID32;
        src_page = (mtrl_page_t *)curr_vm->data) {
        if (mtrl_fill_page_up(ctx, dst_page, src_page)) {
            mtrl_close_page(ctx, curr_vmid);
            return CT_SUCCESS;
        }

        mtrl_close_page(ctx, curr_vmid);

        list_count--;

        if (list_count == 0) {
            return CT_SUCCESS;
        }

        ctrl = vm_get_ctrl(ctx->pool, curr_vmid);
        if (ctrl->prev == CT_INVALID_ID32) {
            return CT_SUCCESS;
        }

        if (mtrl_open_page(ctx, ctrl->prev, &prev_vm) != CT_SUCCESS) {
            return CT_ERROR;
        }

        curr_vm = prev_vm;
        curr_vmid = prev_vm->vmid;
    }

    mtrl_close_page(ctx, curr_vmid);

    return CT_SUCCESS;
}

static inline void vw_dc_rankings_init_context(mtrl_context_t *total_mtrl_ctx, knl_session_t *session)
{
    mtrl_init_context(total_mtrl_ctx, session);
    total_mtrl_ctx->sort_cmp = vw_dc_rankings_compare;
}

static status_t vw_dc_rankings_open(knl_handle_t se, knl_cursor_t *cursor)
{
    knl_session_t *session = (knl_session_t *)se;
    uint32 cmp_items = DC_RANKINGS_COL_PAGES;
    mtrl_context_t total_mtrl_ctx = { 0 };
    mtrl_segment_t *segment = NULL;
    uint32 seg_id;
    uint32 vmid;
    status_t status = CT_ERROR;

    /* this vm_page will be released by knl_close_cursor outside */
    if (cursor->vm_page == NULL) {
        CT_RETURN_IFERR(vm_alloc(session, session->temp_pool, &vmid));
        if (vm_open(session, session->temp_pool, vmid, &cursor->vm_page) != CT_SUCCESS) {
            vm_free(session, session->temp_pool, vmid);
            return CT_ERROR;
        }
    } else {
        cursor->rowid.vmid = cursor->vm_page->vmid;
        cursor->rowid.vm_slot = 0;
        return CT_SUCCESS;
    }

    vw_dc_rankings_init_context(&total_mtrl_ctx, session);

    do {
        if (mtrl_create_segment(&total_mtrl_ctx, MTRL_SEGMENT_TEMP, &cmp_items, &seg_id) != CT_SUCCESS) {
            break;
        }
        if (mtrl_open_segment(&total_mtrl_ctx, seg_id) != CT_SUCCESS) {
            break;
        }
        if (vw_dc_rankings_collect(se, cursor, &total_mtrl_ctx, seg_id, DC_RANKINGS_COLS) != CT_SUCCESS) {
            break;
        }

        if (cursor->eof) {
            status = CT_SUCCESS;
            break;
        }

        segment = total_mtrl_ctx.segments[seg_id];
        mtrl_close_segment(&total_mtrl_ctx, seg_id);
        if (mtrl_sort_segment(&total_mtrl_ctx, seg_id) != CT_SUCCESS) {
            break;
        }

        if (vw_dc_rankings_fill_page(&total_mtrl_ctx, (mtrl_page_t *)cursor->vm_page->data, segment) != CT_SUCCESS) {
            break;
        }

        cursor->rowid.vmid = cursor->vm_page->vmid;
        cursor->rowid.vm_slot = 0;
        status = CT_SUCCESS;
    } while (0);

    mtrl_release_context(&total_mtrl_ctx);

    return status;
}

static status_t vw_dc_rankings_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    knl_session_t *session = (knl_session_t *)se;
    mtrl_context_t rank_mtrl_ctx = { 0 };
    mtrl_cursor_t *mtrl_cursor = NULL;
    errno_t ret;

    mtrl_init_context(&rank_mtrl_ctx, se);
    rank_mtrl_ctx.sort_cmp = vw_dc_rankings_compare;

    CM_SAVE_STACK(session->stack);

    mtrl_cursor = cm_push(session->stack, sizeof(mtrl_cursor_t));
    mtrl_cursor->eof = CT_FALSE;
    mtrl_cursor->row.data = NULL;
    mtrl_cursor->rs_vmid = (uint32)cursor->rowid.vmid;
    mtrl_cursor->slot = (uint32)cursor->rowid.vm_slot;
    mtrl_cursor->rs_page = (mtrl_page_t *)cursor->vm_page->data;

    if (mtrl_fetch_rs(&rank_mtrl_ctx, mtrl_cursor, CT_TRUE) != CT_SUCCESS) {
        mtrl_release_context(&rank_mtrl_ctx);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    cursor->rowid.vmid = mtrl_cursor->rs_vmid;
    cursor->rowid.vm_slot = mtrl_cursor->slot;

    if (mtrl_cursor->eof) {
        cursor->eof = CT_TRUE;
        mtrl_release_context(&rank_mtrl_ctx);
        CM_RESTORE_STACK(session->stack);
        return CT_SUCCESS;
    }

    ret = memcpy_sp(cursor->row, HEAP_MAX_ROW_SIZE(session), (row_head_t *)mtrl_cursor->row.data,
        ((row_head_t *)mtrl_cursor->row.data)->size);
    knl_securec_check(ret);

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, NULL);

    mtrl_release_context(&rank_mtrl_ctx);
    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

static status_t vw_table_stats_fetch_core(knl_handle_t se, knl_cursor_t *cursor)
{
    knl_session_t *session = (knl_session_t *)se;
    knl_temp_cache_t *temp_table = NULL;
    knl_dictionary_t dc;
    row_assist_t ra;
    dc_user_t *user = NULL;

    while (cursor->rowid.vmid < session->temp_table_count) {
        temp_table = &session->temp_table_cache[cursor->rowid.vmid];
        if (temp_table->table_id != CT_INVALID_ID32 && temp_table->cbo_stats != NULL) {
            break;
        }

        cursor->rowid.vmid++;
    }

    if (cursor->rowid.vmid >= session->temp_table_count) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    if (knl_open_dc_by_id(se, temp_table->user_id, temp_table->table_id, &dc, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dc_entity_t *entity = (dc_entity_t *)dc.handle;
    cbo_stats_table_t *tab_stats = temp_table->cbo_stats;
    CURSOR_SET_TENANT_ID_BY_USER(dc_open_user_by_id(session, temp_table->user_id, &user), cursor, user);
    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, TEMP_TABLE_STATS_COLS);
    CT_RETURN_IFERR(row_put_int32(&ra, temp_table->user_id));
    CT_RETURN_IFERR(row_put_uint32(&ra, temp_table->table_id));
    CT_RETURN_IFERR(row_put_str(&ra, entity->table.desc.name));
    CT_RETURN_IFERR(row_put_int32(&ra, tab_stats->rows));
    CT_RETURN_IFERR(row_put_int32(&ra, tab_stats->blocks));
    CT_RETURN_IFERR(row_put_int32(&ra, tab_stats->empty_blocks));
    CT_RETURN_IFERR(row_put_int64(&ra, tab_stats->avg_row_len));
    //  this sample size is analyzed rows, so it is smaller than max value of uint32
    CT_RETURN_IFERR(row_put_int32(&ra, (uint32)tab_stats->sample_size));

    if (tab_stats->analyse_time != 0) {
        CT_RETURN_IFERR(row_put_date(&ra, tab_stats->analyse_time));
    } else {
        CT_RETURN_IFERR(row_put_null(&ra));
    }

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;
    dc_close(&dc);
    return CT_SUCCESS;
}

static status_t vw_table_stats_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    return vw_fetch_for_tenant(vw_table_stats_fetch_core, se, cursor);
}

static status_t vm_generate_column_stats_row(knl_cursor_t *cursor, dc_entity_t *entity, knl_column_t *column,
    cbo_stats_column_t *col_stats)
{
    row_assist_t ra;

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, TEMP_COLUMN_STATS_COLS);
    CT_RETURN_IFERR(row_put_int32(&ra, column->uid));
    CT_RETURN_IFERR(row_put_int32(&ra, column->table_id));
    CT_RETURN_IFERR(row_put_int32(&ra, column->id));
    CT_RETURN_IFERR(row_put_str(&ra, column->name));
    CT_RETURN_IFERR(row_put_int32(&ra, col_stats->num_distinct));
    CT_RETURN_IFERR(stats_put_result_value(&ra, &col_stats->low_value, column->datatype));
    CT_RETURN_IFERR(stats_put_result_value(&ra, &col_stats->high_value, column->datatype));

    if (col_stats->hist_type == FREQUENCY) {
        CT_RETURN_IFERR(row_put_str(&ra, "FREQUENCY"));
    } else {
        CT_RETURN_IFERR(row_put_str(&ra, "HEIGHT BALANCED"));
    }

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    return CT_SUCCESS;
}

static status_t vw_find_stats_column(knl_handle_t se, knl_cursor_t *cursor, knl_dictionary_t *dc, knl_column_t **column,
    cbo_stats_column_t **col_stats)
{
    knl_session_t *session = (knl_session_t *)se;
    knl_temp_cache_t *temp_table = NULL;
    dc_entity_t *entity = NULL;

    while (cursor->rowid.vmid < session->temp_table_count) {
        temp_table = &session->temp_table_cache[cursor->rowid.vmid];
        if (temp_table->table_id == CT_INVALID_ID32 || temp_table->cbo_stats == NULL) {
            cursor->rowid.vmid++;
            continue;
        }

        if (knl_open_dc_by_id(se, temp_table->user_id, temp_table->table_id, dc, CT_TRUE) != CT_SUCCESS) {
            return CT_ERROR;
        }

        entity = (dc_entity_t *)dc->handle;
        while (cursor->rowid.vm_slot < entity->table.desc.column_count) {
            *column = dc_get_column(entity, (uint16)cursor->rowid.vm_slot);
            *col_stats = knl_get_cbo_column(se, entity, (*column)->id);

            if (*col_stats != NULL) {
                break;
            }

            cursor->rowid.vm_slot++;
        }

        if (cursor->rowid.vm_slot < entity->table.desc.column_count) {
            break; // find a column with stats
        }

        // this temp table has no column with stats, find next
        cursor->rowid.vmid++;
        cursor->rowid.vm_slot = 0;
        dc_close(dc);
    }

    return CT_SUCCESS;
}

static status_t vw_column_stats_fetch_core(knl_handle_t se, knl_cursor_t *cursor)
{
    knl_session_t *session = (knl_session_t *)se;
    knl_column_t *column = NULL;
    cbo_stats_column_t *col_stats = NULL;
    knl_dictionary_t dc;
    dc_user_t *user = NULL;

    if (vw_find_stats_column(se, cursor, &dc, &column, &col_stats) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cursor->rowid.vmid >= session->temp_table_count) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    dc_entity_t *entity = (dc_entity_t *)dc.handle;
    if (vm_generate_column_stats_row(cursor, entity, column, col_stats) != CT_SUCCESS) {
        dc_close(&dc);
        return CT_ERROR;
    }
    CURSOR_SET_TENANT_ID_BY_USER(dc_open_user_by_id(session, column->uid, &user), cursor, user);
    cursor->rowid.vm_slot++;
    if (cursor->rowid.vm_slot == entity->table.desc.column_count) {
        cursor->rowid.vmid++;
        cursor->rowid.vm_slot = 0;
    }

    dc_close(&dc);
    return CT_SUCCESS;
}

static status_t vw_column_stats_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    return vw_fetch_for_tenant(vw_column_stats_fetch_core, se, cursor);
}

static status_t vm_generate_index_stats_row(knl_cursor_t *cursor, dc_entity_t *entity, index_t *index,
    cbo_stats_index_t *index_stats)
{
    row_assist_t ra;

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, TEMP_INDEX_STATS_COLS);
    CT_RETURN_IFERR(row_put_int32(&ra, index->desc.uid));
    CT_RETURN_IFERR(row_put_int32(&ra, index->desc.table_id));
    CT_RETURN_IFERR(row_put_int32(&ra, index->desc.id));
    CT_RETURN_IFERR(row_put_str(&ra, index->desc.name));
    CT_RETURN_IFERR(row_put_int32(&ra, index_stats->blevel));
    CT_RETURN_IFERR(row_put_int32(&ra, index_stats->leaf_blocks));
    CT_RETURN_IFERR(row_put_int32(&ra, index_stats->distinct_keys));
    CT_RETURN_IFERR(row_put_real(&ra, index_stats->avg_leaf_key));
    CT_RETURN_IFERR(row_put_real(&ra, index_stats->avg_data_key));
    CT_RETURN_IFERR(row_put_date(&ra, index_stats->analyse_time));
    CT_RETURN_IFERR(row_put_int32(&ra, index_stats->empty_leaf_blocks));
    CT_RETURN_IFERR(row_put_int32(&ra, index_stats->clustering_factor));
    CT_RETURN_IFERR(row_put_int32(&ra, index_stats->comb_cols_2_ndv));
    CT_RETURN_IFERR(row_put_int32(&ra, index_stats->comb_cols_3_ndv));
    CT_RETURN_IFERR(row_put_int32(&ra, index_stats->comb_cols_4_ndv));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    return CT_SUCCESS;
}

static status_t vw_find_stats_index(knl_handle_t se, knl_cursor_t *cursor, knl_dictionary_t *dc, index_t **index,
    cbo_stats_index_t **index_stats)
{
    knl_session_t *session = (knl_session_t *)se;
    knl_temp_cache_t *temp_table = NULL;
    dc_entity_t *entity = NULL;

    while (cursor->rowid.vmid < session->temp_table_count) {
        temp_table = &session->temp_table_cache[cursor->rowid.vmid];
        if (temp_table->table_id == CT_INVALID_ID32 || temp_table->cbo_stats == NULL) {
            cursor->rowid.vmid++;
            continue;
        }

        if (knl_open_dc_by_id(se, temp_table->user_id, temp_table->table_id, dc, CT_TRUE) != CT_SUCCESS) {
            return CT_ERROR;
        }

        entity = (dc_entity_t *)dc->handle;
        while (cursor->rowid.vm_slot < entity->table.desc.index_count) {
            *index = entity->table.index_set.items[cursor->rowid.vm_slot];
            *index_stats = knl_get_cbo_index(se, entity, (*index)->desc.id);

            if (*index_stats != NULL) {
                break;
            }

            cursor->rowid.vm_slot++;
        }

        if (cursor->rowid.vm_slot < entity->table.desc.index_count) {
            break; // find a index with stats
        }

        // this temp table has no index with stats, find next table
        cursor->rowid.vmid++;
        cursor->rowid.vm_slot = 0;
        dc_close(dc);
    }

    return CT_SUCCESS;
}

static status_t vw_index_stats_fetch_core(knl_handle_t se, knl_cursor_t *cursor)
{
    knl_session_t *session = (knl_session_t *)se;
    index_t *index = NULL;
    cbo_stats_index_t *index_stats = NULL;
    knl_dictionary_t dc;
    dc_user_t *user = NULL;

    if (vw_find_stats_index(se, cursor, &dc, &index, &index_stats) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cursor->rowid.vmid >= session->temp_table_count) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    dc_entity_t *entity = (dc_entity_t *)dc.handle;
    if (vm_generate_index_stats_row(cursor, entity, index, index_stats) != CT_SUCCESS) {
        dc_close(&dc);
        return CT_ERROR;
    }
    CURSOR_SET_TENANT_ID_BY_USER(dc_open_user_by_id(session, index->desc.uid, &user), cursor, user);
    cursor->rowid.vm_slot++;
    if (cursor->rowid.vm_slot == entity->table.desc.column_count) {
        cursor->rowid.vmid++;
        cursor->rowid.vm_slot = 0;
    }

    dc_close(&dc);
    return CT_SUCCESS;
}

static status_t vw_index_stats_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    return vw_fetch_for_tenant(vw_index_stats_fetch_core, se, cursor);
}

static char *vw_get_last_segment_type(knl_session_t *session, page_id_t pagid)
{
    buf_enter_page(session, pagid, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    page_head_t *page = (page_head_t *)session->curr_page;

    switch (page->type) {
        case PAGE_TYPE_HEAP_HEAD:
        case PAGE_TYPE_HEAP_MAP:
        case PAGE_TYPE_HEAP_DATA:
        case PAGE_TYPE_PCRH_DATA:
            buf_leave_page(session, CT_FALSE);
            return "TABLE";

        case PAGE_TYPE_BTREE_HEAD:
        case PAGE_TYPE_BTREE_NODE:
        case PAGE_TYPE_PCRB_NODE:
            buf_leave_page(session, CT_FALSE);
            return "INDEX";

        case PAGE_TYPE_LOB_HEAD:
        case PAGE_TYPE_LOB_DATA:
            buf_leave_page(session, CT_FALSE);
            return "LOB";

        default:
            buf_leave_page(session, CT_FALSE);
            return "UNKNOWN";
    }
}

static status_t vw_generate_df_lasttable_row(knl_session_t *session, datafile_t *df, space_t *space,
    knl_cursor_t *cursor)
{
    row_assist_t ra;
    database_t *db = &session->kernel->db;

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, DATAFILE_LAST_TABLE_COLS);
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)(df->ctrl->id)));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)(df->space_id)));
    CT_RETURN_IFERR(row_put_str(&ra, df->ctrl->name));

    uint32 file_hwm = 0;
    if (db->status == DB_STATUS_OPEN && DATAFILE_IS_ONLINE(df) && space->head != NULL) {
        file_hwm = DF_FILENO_IS_INVAILD(df) ? 0 : (int32)SPACE_HEAD_RESIDENT(session, space)->hwms[df->file_no];
    }
    CT_RETURN_IFERR(row_put_int32(&ra, file_hwm));

    text_t obj_name;
    CM_SAVE_STACK(session->stack);
    obj_name.str = cm_push(session->stack, MAX_LAST_TABLE_NAME_LEN);
    obj_name.len = MAX_LAST_TABLE_NAME_LEN;
    errno_t ret = memset_sp(obj_name.str, MAX_LAST_TABLE_NAME_LEN, 0, MAX_LAST_TABLE_NAME_LEN);
    knl_securec_check(ret);

    uint32 extent_size = space->ctrl->extent_size;
    page_id_t last_page = {
        .file = df->ctrl->id,
        .page = file_hwm - 1
    };
    page_id_t last_extent = {
        .file = df->ctrl->id,
        .page = file_hwm
    };
    uint32 start_page = spc_first_extent_id(session, space, last_page);
    if (start_page == file_hwm) { // the space is empty
        CT_RETURN_IFERR(row_put_str(&ra, "NULL"));
    } else {
        status_t status = knl_get_table_name(session, last_extent.file, last_extent.page, &obj_name);
        while (status != CT_SUCCESS && last_extent.page > start_page) {
            cm_reset_error();
            last_extent.page -= extent_size;
            status = knl_get_table_name(session, last_extent.file, last_extent.page, &obj_name);
        }

        CT_RETURN_IFERR(row_put_str(&ra, obj_name.str[0] == '\0' ? "NULL" : obj_name.str));
    }

    uint32 first_free_extent = last_extent.page == start_page ? start_page : last_extent.page + extent_size;
    if (obj_name.str[0] == '\0') {
        CT_RETURN_IFERR(row_put_str(&ra, "UNKNOWN"));
    } else {
        CT_RETURN_IFERR(row_put_str(&ra, vw_get_last_segment_type(session, last_extent)));
    }
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)first_free_extent));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

static status_t vw_df_lasttable_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    space_t *space = NULL;
    datafile_t *df = NULL;
    uint64 id = cursor->rowid.vmid;
    knl_session_t *session = (knl_session_t *)se;
    database_t *db = &session->kernel->db;

    for (;;) {
        if (id >= CT_MAX_DATA_FILES) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }

        df = &db->datafiles[id];
        if (df->ctrl->used) {
            space = SPACE_GET(session, df->space_id);
            if (!IS_UNDO_SPACE(space) && !IS_TEMP_SPACE(space)) {
                break;
            }
        }

        id++;
    }

    if (vw_generate_df_lasttable_row(session, df, space, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cursor->rowid.vmid = id + 1;
    return CT_SUCCESS;
}

static status_t vw_tenant_tablespaces_fetch_core(knl_handle_t session, knl_cursor_t *cursor)
{
    row_assist_t row;
    knl_session_t *sess = (knl_session_t *)session;
    database_t *db = &sess->kernel->db;
    dc_context_t *ctx = &sess->kernel->dc_ctx;
    dc_tenant_t *tenant = NULL;
    space_t *space = NULL;

    while (CT_TRUE) {
        if (cursor->rowid.tenant_id >= CT_MAX_TENANTS) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }

        tenant = ctx->tenants[cursor->rowid.tenant_id];
        if (tenant == NULL) {
            cursor->rowid.tenant_id++;
            continue;
        }

        if (tenant->desc.ts_num == cursor->rowid.curr_ts_num) {
            cursor->rowid.curr_ts_num = 0;
            cursor->rowid.ts_id = 0;
            cursor->rowid.tenant_id++;
            continue;
        }

        break;
    }

    while (CT_TRUE) {
        if (dc_get_tenant_tablespace_bitmap(&tenant->desc, cursor->rowid.ts_id)) {
            break;
        }

        cursor->rowid.ts_id++;
    }

    space = &db->spaces[cursor->rowid.ts_id];
    row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, TENANT_TABLESPACES_COLS);
    CT_RETURN_IFERR(row_put_str(&row, tenant->desc.name));
    cursor->tenant_id = tenant->desc.id;
    CT_RETURN_IFERR(row_put_str(&row, space->ctrl->name));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);

    cursor->rowid.curr_ts_num++;
    cursor->rowid.ts_id++;
    return CT_SUCCESS;
}

static status_t vw_tenant_tablespaces_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    return vw_fetch_for_tenant(vw_tenant_tablespaces_fetch_core, session, cursor);
}

static inline char *ashrink_status(ashrink_status_t status)
{
    switch (status) {
        case ASHRINK_END:
            return "END";
        case ASHRINK_COMPACT:
            return "COMPACT";
        case ASHRINK_WAIT_SHRINK:
            return "WAIT SHRINK";
        default:
            return "INVALID";
    }
}

/**
 * dynamic view for aysn shrink tables
 */
static status_t vw_ashrink_tables_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    knl_session_t *session = (knl_session_t *)se;
    ashrink_ctx_t *ctx = &session->kernel->ashrink_ctx;
    knl_dictionary_t dc;
    table_t *table = NULL;

    if (cursor->rowid.vm_slot >= ctx->hwm) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }
    ashrink_item_t item_sap = ctx->array[cursor->rowid.vm_slot];

    while (item_sap.begin_time == CT_INVALID_INT64 || item_sap.uid == CT_INVALID_ID32 ||
        item_sap.oid == CT_INVALID_ID32) {
        cursor->rowid.vm_slot++;
        if (cursor->rowid.vm_slot >= ctx->hwm) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }

        item_sap = ctx->array[cursor->rowid.vm_slot];
    }

    if (knl_open_dc_by_id(session, item_sap.uid, item_sap.oid, &dc, CT_TRUE) == CT_SUCCESS) {
        table = DC_TABLE(&dc);
    }

    row_assist_t ra;
    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, ASYNC_SHRINK_TABLES_COLS);
    (void)row_put_int32(&ra, (int32)item_sap.uid);
    (void)row_put_int32(&ra, (int32)item_sap.oid);
    if (table != NULL) {
        (void)row_put_str(&ra, table->desc.name);
        (void)row_put_str(&ra, ashrink_status(table->ashrink_stat));
        dc_close(&dc);
    } else {
        (void)row_put_str(&ra, "INVALID");
        (void)row_put_str(&ra, "INVALID");
    }
    (void)row_put_int64(&ra, (int64)item_sap.shrinkable_scn);
    (void)row_put_int64(&ra, (int64)KNL_GET_SCN(&session->kernel->min_scn));
    (void)row_put_date(&ra, item_sap.begin_time);
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vm_slot++;

    return CT_SUCCESS;
}

static status_t vw_pl_entity_address(knl_session_t *sess, knl_cursor_t *cursor, bool8 *is_break)
{
    row_assist_t row;
    pl_manager_t *pl_mngr = &g_instance->sql.pl_mngr;
    pl_list_t *lru_list = NULL;
    pl_entity_t *entity = NULL;
    bilist_node_t *node = NULL;
    dc_user_t *user = NULL;

    lru_list = &pl_mngr->pl_entity_lru[cursor->rowid.vmid];
    cm_latch_s(&lru_list->latch, CM_THREAD_ID, CT_FALSE, NULL);

    if (cm_bilist_empty(&lru_list->lst) || cursor->rowid.vm_tag >= lru_list->lst.count) {
        cm_unlatch(&lru_list->latch, NULL);
        cursor->rowid.vm_tag = 0;
        return CT_SUCCESS;
    }

    node = cm_bilist_get(&lru_list->lst, (uint32)cursor->rowid.vm_tag);
    if (node == NULL || BILIST_NODE_OF(pl_entity_t, node, lru_link) == NULL) {
        cm_unlatch(&lru_list->latch, NULL);
        cursor->rowid.vm_tag = 0;
        return CT_SUCCESS;
    }
    entity = BILIST_NODE_OF(pl_entity_t, node, lru_link);
    CURSOR_SET_TENANT_ID_BY_USER(dc_open_user_by_id(sess, entity->entry->desc.uid, &user), cursor, user);
    row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, PL_ENTITY_COLS);
    (void)row_put_int32(&row, entity->entry->desc.uid);
    (void)row_put_text(&row, &entity->def.user);
    (void)row_put_int64(&row, (int64)entity->entry->desc.oid);
    if (CM_IS_EMPTY(&entity->def.pack)) {
        (void)row_put_text(&row, &entity->def.name);
    } else {
        (void)row_put_text(&row, &entity->def.pack);
    }
    (void)row_put_str(&row, vw_pl_type_str(entity->pl_type));
    (void)row_put_int32(&row, entity->memory->pages.count);
    (void)row_put_bool(&row, entity->valid);
    (void)row_put_int32(&row, entity->ref_count);

    cm_unlatch(&lru_list->latch, NULL);
    cursor->rowid.vm_tag++;
    *is_break = CT_TRUE;

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    return CT_SUCCESS;
}

static status_t vw_pl_entity_fetch_core(knl_handle_t session, knl_cursor_t *cursor)
{
    knl_session_t *sess = (knl_session_t *)session;
    bool8 is_break = CT_FALSE;

    for (;;) {
        if (cursor->rowid.vmid >= PL_ENTITY_LRU_SIZE) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }
        CT_RETURN_IFERR(vw_pl_entity_address(sess, cursor, &is_break));
        if (is_break) {
            break;
        }
        cursor->rowid.vmid++;
    }
    return CT_SUCCESS;
}

static status_t vw_pl_entity_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    return vw_fetch_for_tenant(vw_pl_entity_fetch_core, se, cursor);
}

static const char *vw_ckpt_stats_flush_type(uint8 type)
{
    switch (type) {
        case CKPT_MODE_IDLE:
            return "IDLE";
        case CKPT_TRIGGER_INC:
            return "TRIG_INC";
        case CKPT_TRIGGER_FULL:
            return "TRI_FULL";
        case CKPT_TRIGGER_CLEAN:
            return "TRIG_CLEAN";

        case CKPT_TIMED_INC:
            return "TIMED_INC";
        case CKPT_TIMED_CLEAN:
            return "TIMED_CLEAN";
        default:
            return "Invalid";
    }
}

static status_t vw_ckpt_stats_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    row_assist_t ra;
    knl_session_t *sess = (knl_session_t *)session;
    ckpt_context_t *ctx = &sess->kernel->ckpt_ctx;
    page_id_t page_id;
    errno_t ret;
    char ckpt_queue_first[CT_NAME_BUFFER_SIZE] = "NONE";
    if (cursor->rowid.vmid == CKPT_MODE_IDLE) {
        cursor->rowid.vmid++;
    }

    if (cursor->rowid.vmid > CKPT_TIMED_CLEAN) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, DV_CKPT_STATS_COLS);

    int32 id = cursor->rowid.vmid;
    CT_RETURN_IFERR(row_put_str(&ra, vw_ckpt_stats_flush_type((uint8)id)));

    CT_RETURN_IFERR(row_put_int64(&ra, (int64)ctx->stat.task_count[id]));
    CT_RETURN_IFERR(row_put_real(&ra, (double)ctx->stat.task_us[id] / MICROSECS_PER_SECOND));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)ctx->stat.flush_pages[id]));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)ctx->stat.clean_edp_count[id]));
    CT_RETURN_IFERR(row_put_date(&ra, ctx->stat.ckpt_begin_time[id]));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)ctx->stat.proc_wait_cnt));
    CT_RETURN_IFERR(row_put_str(&ra, vw_ckpt_stats_flush_type((uint8)ctx->trigger_task)));
    CT_RETURN_IFERR(row_put_str(&ra, vw_ckpt_stats_flush_type((uint8)ctx->timed_task)));
    cm_spin_lock(&ctx->queue.lock, &sess->stat->spin_stat.stat_ckpt_queue);
    if (ctx->queue.first != NULL) {
        page_id = ctx->queue.first->page_id;
        ret = snprintf_s(ckpt_queue_first, CT_NAME_BUFFER_SIZE, CT_NAME_BUFFER_SIZE - 1, "%u-%u", page_id.file,
            page_id.page);
        knl_securec_check_ss(ret);
    }
    cm_spin_unlock(&ctx->queue.lock);
    CT_RETURN_IFERR(row_put_str(&ra, ckpt_queue_first));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;

    return CT_SUCCESS;
}

static char *vw_get_users_account_status(uint32 status)
{
    for (int i = 0; i < ACCOUNT_STATUS_TOTAL; i++) {
        if (status == g_user_astatus_map[i].id) {
            return g_user_astatus_map[i].name;
        }
    }

    return "UNKNOWN";
}

static status_t vw_users_fetch_core(knl_handle_t session, knl_cursor_t *cursor, dc_user_t *user)
{
    row_assist_t ra;
    knl_user_desc_t *desc = &user->desc;
    knl_session_t *sess = (knl_session_t *)session;
    database_t *db = &sess->kernel->db;
    profile_t *profile = NULL;
    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, DV_USERS_COLS);

    CT_RETURN_IFERR(row_put_str(&ra, desc->name));
    CT_RETURN_IFERR(row_put_int32(&ra, desc->id));
    CT_RETURN_IFERR(row_put_str(&ra, vw_get_users_account_status(desc->astatus)));
    CT_RETURN_IFERR(row_put_int32(&ra, desc->lcount));
    CT_RETURN_IFERR(row_put_date(&ra, desc->ctime));
    CT_RETURN_IFERR(row_put_date(&ra, desc->ptime));
    if (desc->astatus & ACCOUNT_STATUS_EXPIRED) {
        (void)(row_put_date(&ra, desc->exptime));
    } else {
        row_put_null(&ra);
    }
    if (desc->astatus & ACCOUNT_STATUS_LOCK || desc->astatus & ACCOUNT_STATUS_LOCK_TIMED) {
        (void)(row_put_date(&ra, desc->ltime));
    } else {
        row_put_null(&ra);
    }

    if (!profile_find_by_id(sess, desc->profile_id, &profile)) {
        CT_THROW_ERROR(ERR_PROFILE_ID_NOT_EXIST, desc->profile_id);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(row_put_str(&ra, profile->name));

    space_t *space = &db->spaces[desc->data_space_id];
    CT_RETURN_IFERR(row_put_str(&ra, space->ctrl->name));

    space = &db->spaces[desc->temp_space_id];
    CT_RETURN_IFERR(row_put_str(&ra, space->ctrl->name));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;

    return CT_SUCCESS;
}

static status_t vw_users_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    uint32 uid;
    knl_session_t *sess = (knl_session_t *)session;
    dc_context_t *ctx = &sess->kernel->dc_ctx;

    for (uid = cursor->rowid.vmid; uid < CT_MAX_USERS; uid++) {
        if (ctx->users[uid] != NULL) {
            break;
        }
    }
    if (uid == CT_MAX_USERS) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(vw_users_fetch_core(session, cursor, ctx->users[uid]));
    cursor->rowid.vmid = uid + 1;
    return CT_SUCCESS;
}

static status_t vw_ckpt_part_stat_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    row_assist_t ra;
    knl_session_t *sess = (knl_session_t *)session;
    ckpt_context_t *ctx = &sess->kernel->ckpt_ctx;

    if (cursor->rowid.vmid >= ctx->dbwr_count) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    ckpt_part_stat_t *part_stat = &ctx->stat.part_stat[cursor->rowid.vmid];
    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, DV_CKPT_PART_COLS);
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)(cursor->rowid.vmid)));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)(part_stat->flush_times)));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)(part_stat->flush_pagaes)));
    if (part_stat->flush_times == 0) {
        CT_RETURN_IFERR(row_put_int64(&ra, 0));
    } else {
        CT_RETURN_IFERR(row_put_int64(&ra, (int64)(part_stat->flush_pagaes / part_stat->flush_times)));
    }
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)(part_stat->min_flush_pages)));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)(part_stat->max_flush_pages)));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)(part_stat->zero_flush_times)));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)(part_stat->cur_flush_pages)));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;

    return CT_SUCCESS;
}

VW_DECL dv_datafile = { "SYS", "DV_DATA_FILES", DATAFILE_COLS, g_datafile_columns, vw_common_open, vw_datafile_fetch };
VW_DECL dv_logfile = { "SYS", "DV_LOG_FILES", LOGFILE_COLS, g_logfile_columns, vw_common_open, vw_logfile_fetch };
VW_DECL dv_librarycache = { "SYS",           "DV_LIBRARY_CACHE", LIBRARYCACHE_COLS,
                            g_library_cache, vw_common_open,     vw_librarycache_fetch };
VW_DECL dv_buffer_pool = { "SYS",          "DV_BUFFER_POOLS",   BUFFER_POOL_COLS, g_buffer_pool_columns,
                           vw_common_open, vw_buffer_pool_fetch };
VW_DECL dv_buffer_pool_stat = {
    "SYS",          "DV_BUFFER_POOL_STATS",         BUFFER_POOL_STATISTICS_COLS, g_buffer_pool_statistics_columns,
    vw_common_open, vw_buffer_pool_statistics_fetch
};
VW_DECL dv_buffer_page_stat = {
    "SYS",          "DV_BUFFER_PAGE_STATS",         BUFFER_PAGE_STATS_COLS, g_buffer_page_statistics_columns,
    vw_common_open, vw_buffer_page_statistics_fetch
};
VW_DECL dv_buffer_index_stat = {
    "SYS",          "DV_BUFFER_INDEX_STATS",         BUFFER_INDEX_STATS_COLS, g_buffer_index_statistics_columns,
    vw_common_open, vw_buffer_index_statistics_fetch
};
VW_DECL dv_user_parameter = { "SYS",          "DV_USER_PARAMETERS",   PARAMETER_COLS, g_parameter_columns,
                              vw_common_open, vw_user_parameter_fetch };
VW_DECL dv_parameter = {
    "SYS", "DV_PARAMETERS", PARAMETER_COLS, g_parameter_columns, vw_common_open, vw_parameter_fetch
};
VW_DECL dv_object_cache = { "SYS",          "DV_OBJECT_CACHE",       DB_OBJECT_CACHE_COLS, g_db_object_cache,
                            vw_common_open, vw_db_object_cache_fetch };
VW_DECL dv_tablespace = { "SYS",          "DV_TABLESPACES",    TABLESPACES_COLS, g_tablespaces_columns,
                          vw_common_open, vw_tablespaces_fetch };
VW_DECL dv_archive_log = { "SYS",          "DV_ARCHIVED_LOGS",   ARCHIVED_LOG_COLS, g_archived_log_columns,
                           vw_common_open, vw_archived_log_fetch };
VW_DECL dv_temp_archive_log = { "SYS", "DV_TEMP_ARCHIVED_LOGS", TEMP_ARCHIVED_LOG_COLS, g_temp_archived_log_columns,
                                vw_common_open, vw_temp_archived_log_fetch };
VW_DECL dv_archive_gap = { "SYS",          "DV_ARCHIVE_GAPS",   ARCHIVE_GAP_COLS, g_archive_gap_columns,
                           vw_common_open, vw_archive_gap_fetch };
VW_DECL dv_archive_process = {
    "SYS",          "DV_ARCHIVE_THREADS",      ARCHIVE_PROCESS_COLS, g_archive_process_columns,
    vw_common_open, vw_archive_processes_fetch
};
VW_DECL dv_archive_dest_status = {
    "SYS",          "DV_ARCHIVE_DEST_STATUS", ARCHIVE_STATUS_COLS, g_archive_status_columns,
    vw_common_open, vw_archive_status_fetch
};
VW_DECL dv_database = { "SYS", "DV_DATABASE", DATABASE_COLS, g_database_columns, vw_common_open, vw_database_fetch };
VW_DECL dv_repl_status = { "SYS",          "DV_REPL_STATUS",    REPL_STATUS_COLS, g_repl_status_columns,
                           vw_common_open, vw_repl_status_fetch };
VW_DECL dv_managed_standby = { "SYS",          "DV_STANDBYS",           MANAGED_STANDBY_COLS, g_managed_standby_columns,
                               vw_common_open, vw_managed_standby_fetch };
VW_DECL dv_ha_sync_info = { "SYS",          "DV_HA_SYNC_INFO",    HA_SYNC_INFO_COLS, g_ha_sync_info_columns,
                            vw_common_open, vw_ha_sync_info_fetch };
VW_DECL dv_me = { "SYS", "DV_ME", ME_COLS, g_me_columns, vw_common_open, vw_me_fetch };
VW_DECL dv_dynamic_view = { "SYS",          "DV_DYNAMIC_VIEWS",   DYNAMIC_VIEW_COLS, g_dynamic_view_columns,
                            vw_common_open, vw_dynamic_view_fetch };
VW_DECL dv_dynamic_view_column = {
    "SYS",          "DV_DYNAMIC_VIEW_COLS",      DYNAMIC_VIEW_COLUMN_COLS, g_dynamic_view_column_cols,
    vw_common_open, vw_dynamic_view_column_fetch
};
VW_DECL dv_version = { "SYS", "DV_VERSION", VERSION_COLS, g_version_columns, vw_common_open, vw_version_fetch };
VW_DECL dv_ctrl_version = { "SYS", "DV_CTRL_VERSION", VERSION_COLS, g_version_columns, vw_common_open,
                            vw_ctrl_version_fetch };
VW_DECL dv_transaction = { "SYS",          "DV_TRANSACTIONS",   TRANSACTION_COLS, g_transaction_columns,
                           vw_common_open, vw_transaction_fetch };
VW_DECL dv_all_transaction = { "SYS",          "DV_ALL_TRANS",          ALL_TRANSACTION_COLS, g_all_transaction_columns,
                               vw_common_open, vw_all_transaction_fetch };
VW_DECL dv_resource_map = { "SYS",          "DV_RESOURCE_MAP",    RESOURCE_MAP_COLS, g_resource_map_columns,
                            vw_common_open, vw_resource_map_fetch };
VW_DECL dv_user_astatus_map = {
    "SYS",          "DV_USER_ASTATUS_MAP",    USER_ASTATUS_MAP_COLS, g_user_astatus_map_columns,
    vw_common_open, vw_user_astatus_map_fetch
};
VW_DECL dv_undo_segment = { "SYS",          "DV_UNDO_SEGMENTS",   UNDO_SEGMENT_COLS, g_undo_segment_columns,
                            vw_common_open, vw_undo_segment_fetch };
VW_DECL dv_temp_undo_segment = {
    "SYS",          "DV_TEMP_UNDO_SEGMENT",    TEMP_UNDO_SEGMENT_COLS, g_temp_undo_segment_columns,
    vw_common_open, vw_temp_undo_segment_fetch
};
VW_DECL dv_backup_process = { "SYS",          "DV_BACKUP_PROCESSES",  BACKUP_PROCESS_COLS, g_backup_process_columns,
                              vw_common_open, vw_backup_process_fetch };
VW_DECL dv_instance = { "SYS", "DV_INSTANCE", INSTANCE_COLS, g_instance_columns, vw_common_open, vw_instance_fetch };
VW_DECL dv_open_cursor = { "SYS",          "DV_OPEN_CURSORS",   OPEN_CURSOR_COLS, g_open_cursor_columns,
                           vw_tlvdef_open, vw_open_cursor_fetch };
VW_DECL nls_session_parameters = { "SYS",           "NLS_SESSION_PARAMETERS",
                                   NLS_PARAMS_COLS, g_nls_session_param_columns,
                                   vw_common_open,  vw_nls_session_params_fetch };
VW_DECL dv_free_space = {
    "SYS", "DV_FREE_SPACE", FREE_SPACE_COLS, g_free_space_columns, vw_free_space_open, vw_free_space_fetch
};
VW_DECL dv_pl_mngr = { "SYS", "DV_PL_MANAGER", PL_MNGR_COLS, g_pl_mngr_columns, vw_common_open, vw_pl_mngr_fetch };
VW_DECL dv_controlfile = { "SYS",          "DV_CONTROL_FILES",  CONTROLFILE_COLS, g_controlfile_columns,
                           vw_common_open, vw_controlfile_fetch };
VW_DECL dv_hba = { "SYS", "DV_HBA", HBA_COLS, g_hba_columns, vw_common_open, vw_hba_fetch };
VW_DECL dv_pbl = { "SYS", "DV_PBL", PBL_COLS, g_pbl_columns, vw_common_open, vw_pbl_fetch };
VW_DECL dv_pl_refsqls = { "SYS",          "DV_PL_REFSQLS",    PL_REFSQLS_COLS, g_pl_refsqls_columns,
                          vw_common_open, vw_pl_refsqls_fetch };
VW_DECL dv_running_jobs = { "SYS",          "DV_RUNNING_JOBS",   JOBS_RUNNING_COLS, g_jobs_running_columns,
                            vw_common_open, vw_running_job_fetch };
VW_DECL dv_dc_pool = { "SYS", "DV_DC_POOLS", DC_POOL_COLS, g_dc_pool_columns, vw_common_open, vw_dc_pool_fetch };
VW_DECL dv_reactor_pool = { "SYS",          "DV_REACTOR_POOLS",   REACTOR_POOL_COLS, g_reactor_pool_columns,
                            vw_common_open, vw_reactor_pool_fetch };
VW_DECL dv_emerg_pool = { "SYS", "DV_EMERG_POOL", EMERG_POOL_COLS, g_emerg_pool, vw_common_open, vw_emerg_pool_fetch };
VW_DECL dv_global_transaction = {
    "SYS",          "DV_GLOBAL_TRANSACTIONS",   GLOBAL_TRANSACTION_COLS, g_global_transaction,
    vw_common_open, vw_global_transaction_fetch
};
VW_DECL dv_whitelist = {
    "SYS", "DV_WHITELIST", WHITELIST_COLS, g_whitelist_columns, vw_common_open, vw_whitelist_fetch
};
VW_DECL dv_rcywait = { "SYS", "DV_RCY_WAIT", RCYWAIT_COLS, g_rcywait_columns, vw_common_open, vw_rcywait_fetch };
VW_DECL dv_dc_rankings = { "SYS",         "DV_DC_RANKINGS",    DC_RANKINGS_COLS,
                           g_dc_rankings, vw_dc_rankings_open, vw_dc_rankings_fetch };
VW_DECL dv_debug_parameter = {
    "SYS",          "DV_DEBUG_PARAMETERS",   KNL_DEBUG_PARAMETER_COLS, g_debug_parameter_columns,
    vw_common_open, vw_debug_parameter_fetch
};
VW_DECL dv_temptables = { "SYS",          "DV_TEMPTABLES",    TEMPTABLES_COLS, g_temptables_columns,
                          vw_common_open, vw_temptables_fetch };
VW_DECL dv_buffer_access_stats = {
    "SYS",          "DV_BUFFER_ACCESS_STATS",   BUFFER_ACCESS_STATS_COLS, g_buffer_access_stats,
    vw_common_open, vw_buffer_access_stat_fetch
};
VW_DECL dv_buffer_recycle_stats = {
    "SYS",          "DV_BUFFER_RECYCLE_STATS",   BUFFER_RECYCLE_STATS_COLS, g_buffer_recycle_stats,
    vw_common_open, vw_buffer_recycle_stat_fetch
};
VW_DECL g_dv_backup_process_stats = {
    "SYS",          "DV_BACKUP_PROCESS_STATS",    BAK_PROCESS_STATS_COLS, g_backup_process_stats,
    vw_common_open, vw_backup_process_stats_fetch
};
VW_DECL g_dv_temp_table_stats = { "SYS",          "DV_TEMP_TABLE_STATS", TEMP_TABLE_STATS_COLS, g_temp_table_stats,
                                  vw_common_open, vw_table_stats_fetch };
VW_DECL g_dv_temp_column_stats = { "SYS",          "DV_TEMP_COLUMN_STATS", TEMP_COLUMN_STATS_COLS, g_temp_column_stats,
                                   vw_common_open, vw_column_stats_fetch };
VW_DECL g_dv_temp_index_stats = { "SYS",          "DV_TEMP_INDEX_STATS", TEMP_INDEX_STATS_COLS, g_temp_index_stats,
                                  vw_common_open, vw_index_stats_fetch };
VW_DECL g_dv_datafile_last_table = {
    "SYS",          "DV_DATAFILE_LAST_TABLE", DATAFILE_LAST_TABLE_COLS, g_datafile_last_table,
    vw_common_open, vw_df_lasttable_fetch
};
VW_DECL dv_tenant_tablespaces = { "SYS",
                                  "DV_TENANT_TABLESPACES",
                                  TENANT_TABLESPACES_COLS,
                                  g_tenant_tablespaces,
                                  vw_tenant_tablespaces_open,
                                  vw_tenant_tablespaces_fetch };
VW_DECL dv_async_shrink_tables = {
    "SYS",          "DV_ASYNC_SHRINK_TABLES", ASYNC_SHRINK_TABLES_COLS, g_async_shrink_tables,
    vw_common_open, vw_ashrink_tables_fetch
};
VW_DECL dv_pl_entity = {
    "SYS", "DV_PL_ENTITY", PL_ENTITY_COLS, g_pl_entity_columns, vw_common_open, vw_pl_entity_fetch
};
VW_DECL dv_ckpt_stats = { "SYS",          "DV_CKPT_STATS",    DV_CKPT_STATS_COLS, g_ckpt_stats_columns,
                          vw_common_open, vw_ckpt_stats_fetch };
VW_DECL dv_users = { "SYS", "DV_USERS", DV_USERS_COLS, g_users_columns, vw_common_open, vw_users_fetch };
VW_DECL dv_ckpt_part_stats = { "SYS",          "DV_CKPT_PART_STATS",   DV_CKPT_PART_COLS, g_ckpt_part_stats_columns,
                               vw_common_open, vw_ckpt_part_stat_fetch };
VW_DECL dv_lfns = { "SYS", "DV_LFNS", LFN_NODES, g_lfn_nodes, vw_common_open, vw_lfn_fetch };
VW_DECL dv_lrpl_detail = { "SYS",          "DV_LRPL_DETAIL",    LRPL_DETAIL_COLS, g_lrpl_detail_columns,
                           vw_common_open, vw_lrpl_detail_fetch };

dynview_desc_t *vw_describe_local(uint32 id)
{
    switch ((dynview_id_t)id) {
        case DYN_VIEW_LOGFILE:
            return &dv_logfile;

        case DYN_VIEW_LIBRARYCACHE:
            return &dv_librarycache;

        case DYN_VIEW_BUFFER_POOL:
            return &dv_buffer_pool;

        case DYN_VIEW_BUFFER_POOL_STAT:
            return &dv_buffer_pool_stat;

        case DYN_VIEW_BUFFER_PAGE_STAT:
            return &dv_buffer_page_stat;

        case DYN_VIEW_BUFFER_INDEX_STAT:
            return &dv_buffer_index_stat;

        case DYN_VIEW_PARAMETER:
            return &dv_parameter;

        case DYN_VIEW_OBJECT_CACHE:
            return &dv_object_cache;

        case DYN_VIEW_TRANSACTION:
            return &dv_transaction;

        case DYN_VIEW_ALL_TRANSACTION:
            return &dv_all_transaction;

        case DYN_VIEW_ARCHIVE_LOG:
            return &dv_archive_log;

        case DYN_VIEW_TEMP_ARCHVIE_LOG:
            return &dv_temp_archive_log;

        case DYN_VIEW_ARCHIVE_GAP:
            return &dv_archive_gap;

        case DYN_VIEW_ARCHIVE_PROCESS:
            return &dv_archive_process;

        case DYN_VIEW_ARCHIVE_DEST_STATUS:
            return &dv_archive_dest_status;

        case DYN_VIEW_DATABASE:
            return &dv_database;

        case DYN_VIEW_TABLESPACE:
            return &dv_tablespace;

        case DYN_VIEW_REPL_STATUS:
            return &dv_repl_status;

        case DYN_VIEW_MANAGED_STANDBY:
            return &dv_managed_standby;

        case DYN_VIEW_HA_SYNC_INFO:
            return &dv_ha_sync_info;

        case DYN_VIEW_ME:
            return &dv_me;

        case DYN_VIEW_DATAFILE:
            return &dv_datafile;

        case DYN_VIEW_VERSION:
            return &dv_version;

        case DYN_VIEW_RESOURCE_MAP:
            return &dv_resource_map;

        case DYN_VIEW_USER_ASTATUS_MAP:
            return &dv_user_astatus_map;

        case DYN_VIEW_UNDO_SEGMENT:
            return &dv_undo_segment;

        case DYN_VIEW_TEMP_UNDO_SEGMENT:
            return &dv_temp_undo_segment;

        case DYN_VIEW_BACKUP_PROCESS:
            return &dv_backup_process;

        case DYN_VIEW_INSTANCE:
            return &dv_instance;

        case DYN_VIEW_OPEN_CURSOR:
            return &dv_open_cursor;

        case DYN_VIEW_NLS_SESSION_PARAMETERS:
            return &nls_session_parameters;

        case DYN_VIEW_PL_MNGR:
            return &dv_pl_mngr;

        case DYN_VIEW_SELF:
            return &dv_dynamic_view;

        case DYN_VIEW_COLUMN:
            return &dv_dynamic_view_column;

        case DYN_VIEW_USER_PARAMETER:
            return &dv_user_parameter;

        case DYN_VIEW_CONTROLFILE:
            return &dv_controlfile;

        case DYN_VIEW_FREE_SPACE:
            return &dv_free_space;
        case DYN_VIEW_HBA:
            return &dv_hba;

        case DYN_VIEW_PBL:
            return &dv_pbl;

        case DYN_VIEW_PL_REFSQLS:
            return &dv_pl_refsqls;

        case DYN_VIEW_RUNNING_JOBS:
            return &dv_running_jobs;

        case DYN_VIEW_DC_POOL:
            return &dv_dc_pool;

        case DYN_VIEW_REACTOR_POOL:
            return &dv_reactor_pool;

        case DYN_VIEW_EMERG_POOL:
            return &dv_emerg_pool;

        case DYN_VIEW_GLOBAL_TRANSACTION:
            return &dv_global_transaction;

        case DYN_VIEW_WHITELIST:
            return &dv_whitelist;

        case DYN_VIEW_RCY_WAIT:
            return &dv_rcywait;

        case DYN_VIEW_DC_RANKINGS:
            return &dv_dc_rankings;

        case DYN_VIEW_KNL_DEBUG_PARAM:
            return &dv_debug_parameter;

        case DYN_VIEW_TEMPTABLES:
            return &dv_temptables;

        case DYN_VIEW_BUFFER_ACCESS_STATS:
            return &dv_buffer_access_stats;
        case DYN_VIEW_BUFFER_RECYCLE_STATS:
            return &dv_buffer_recycle_stats;

        case DYN_BACKUP_PROCESS_STATS:
            return &g_dv_backup_process_stats;
        case DYN_VIEW_TEMP_TABLE_STATS:
            return &g_dv_temp_table_stats;

        case DYN_VIEW_TEMP_COLUMN_STATS:
            return &g_dv_temp_column_stats;

        case DYN_VIEW_TEMP_INDEX_STATS:
            return &g_dv_temp_index_stats;

        case DYN_VIEW_DATAFILE_LAST_TABLE:
            return &g_dv_datafile_last_table;

        case DYN_VIEW_TENANT_TABLESPACES:
            return &dv_tenant_tablespaces;

        case DYN_VIEW_ASYN_SHRINK_TABLES:
            return &dv_async_shrink_tables;

        case DYN_VIEW_PL_ENTITY:
            return &dv_pl_entity;

        case DYN_VIEW_CKPT_STATS:
            return &dv_ckpt_stats;

        case DYN_VIEW_USERS:
            return &dv_users;

        case DYN_VIEW_CKPT_PART_STAT:
            return &dv_ckpt_part_stats;
        
        case DYN_VIEW_CTRL_VERSION:
            return &dv_ctrl_version;

        case DYN_VIEW_LFN:
            return &dv_lfns;
        case DYN_VIEW_LRPL_DETAIL:
            return &dv_lrpl_detail;
        default:
            return NULL;
    }
}

knl_dynview_t g_dynamic_views[] = {
    { DYN_VIEW_LOGFILE, vw_describe_local },
    { DYN_VIEW_LIBRARYCACHE, vw_describe_local },
    { DYN_VIEW_SESSION, vw_describe_session },
    { DYN_VIEW_BUFFER_POOL, vw_describe_local },
    { DYN_VIEW_BUFFER_POOL_STAT, vw_describe_local },
    { DYN_VIEW_BUFFER_PAGE_STAT, vw_describe_local },
    { DYN_VIEW_BUFFER_INDEX_STAT, vw_describe_local },
    { DYN_VIEW_PARAMETER, vw_describe_local },
    { DYN_VIEW_TEMP_POOL, vw_describe_sga },
    { DYN_VIEW_OBJECT_CACHE, vw_describe_local },
    { DYN_VIEW_LOCK, vw_describe_lock },
    { DYN_VIEW_TABLESPACE, vw_describe_local },
    { DYN_VIEW_SPINLOCK, vw_describe_lock },
    { DYN_VIEW_DLSLOCK, vw_describe_lock },
    { DYN_VIEW_ARCHIVE_LOG, vw_describe_local },
    { DYN_VIEW_TEMP_ARCHVIE_LOG, vw_describe_local },
    { DYN_VIEW_ARCHIVE_GAP, vw_describe_local },
    { DYN_VIEW_ARCHIVE_PROCESS, vw_describe_local },
    { DYN_VIEW_ARCHIVE_DEST_STATUS, vw_describe_local },
    { DYN_VIEW_DATABASE, vw_describe_local },
    { DYN_VIEW_SGA, vw_describe_sga },
    { DYN_VIEW_LOCKED_OBJECT, vw_describe_lock },
    { DYN_VIEW_SQLAREA, vw_describe_sga },
    { DYN_VIEW_REPL_STATUS, vw_describe_local },
    { DYN_VIEW_MANAGED_STANDBY, vw_describe_local },
    { DYN_VIEW_HA_SYNC_INFO, vw_describe_local },
    { DYN_VIEW_VERSION, vw_describe_local },
    { DYN_VIEW_TRANSACTION, vw_describe_local },
    { DYN_VIEW_ALL_TRANSACTION, vw_describe_local },
    { DYN_VIEW_UNDO_SEGMENT, vw_describe_local },
    { DYN_VIEW_TEMP_UNDO_SEGMENT, vw_describe_local },
    { DYN_VIEW_INSTANCE, vw_describe_local },
    { DYN_VIEW_SESSION_WAIT, vw_describe_session },
    { DYN_VIEW_SESSION_EVENT, vw_describe_session },
    { DYN_VIEW_SYSTEM_EVENT, vw_describe_stat },
    { DYN_VIEW_ME, vw_describe_local },
    { DYN_VIEW_DATAFILE, vw_describe_local },
    { DYN_VIEW_SYSSTAT, vw_describe_stat },
    { DYN_VIEW_MEMSTAT, vw_describe_stat },
    { DYN_VIEW_SYSTEM, vw_describe_sga },
    /* RESOURCE MAP */
    { DYN_VIEW_RESOURCE_MAP, vw_describe_local },
    { DYN_VIEW_USER_ASTATUS_MAP, vw_describe_local },
    { DYN_VIEW_BACKUP_PROCESS, vw_describe_local },
    { DYN_VIEW_OPEN_CURSOR, vw_describe_local },
    { DYN_VIEW_NLS_SESSION_PARAMETERS, vw_describe_local },
    { DYN_VIEW_PL_MNGR, vw_describe_local },
    { DYN_VIEW_COLUMN, vw_describe_local },
    { DYN_VIEW_USER_PARAMETER, vw_describe_local },
    { DYN_VIEW_FREE_SPACE, vw_describe_local },
    { DYN_VIEW_CONTROLFILE, vw_describe_local },
    { DYN_VIEW_SGASTAT, vw_describe_sga },
    { DYN_VIEW_HBA, vw_describe_local },
    { DYN_VIEW_SEGMENT_STATISTICS, vw_describe_stat },
    { DYN_VIEW_WAITSTAT, vw_describe_stat },
    { DYN_VIEW_LATCH, vw_describe_stat },
    { DYN_VIEW_VM_FUNC_STACK, vw_describe_sga },
    { DYN_VIEW_PL_REFSQLS, vw_describe_local },
    { DYN_VIEW_SQLPOOL, vw_describe_sga },
    { DYN_VIEW_RUNNING_JOBS, vw_describe_local },
    { DYN_VIEW_DC_POOL, vw_describe_local },
    { DYN_VIEW_REACTOR_POOL, vw_describe_local },
    { DYN_VIEW_SESS_ALOCK, vw_describe_lock },
    { DYN_VIEW_SESS_SHARED_ALOCK, vw_describe_lock },
    { DYN_VIEW_XACT_ALOCK, vw_describe_lock },
    { DYN_VIEW_XACT_SHARED_ALOCK, vw_describe_lock },
    { DYN_VIEW_EMERG_POOL, vw_describe_local },
    { DYN_VIEW_GLOBAL_TRANSACTION, vw_describe_local },
    { DYN_VIEW_DC_RANKINGS, vw_describe_local },
    { DYN_VIEW_WHITELIST, vw_describe_local },
    { DYN_VIEW_RCY_WAIT, vw_describe_local },
    { DYN_VIEW_RSRC_CONTROL_GROUP, vw_describe_stat },
    { DYN_VIEW_KNL_DEBUG_PARAM, vw_describe_local },
    { DYN_VIEW_TEMPTABLES, vw_describe_local },
    { DYN_VIEW_PLSQL_ALOCK, vw_describe_lock },
    { DYN_VIEW_PLSQL_SHARED_ALOCK, vw_describe_lock },
    { DYN_VIEW_BUFFER_ACCESS_STATS, vw_describe_local },
    { DYN_VIEW_BUFFER_RECYCLE_STATS, vw_describe_local },
    { DYN_BACKUP_PROCESS_STATS, vw_describe_local },
    { DYN_VIEW_TEMP_TABLE_STATS, vw_describe_local },
    { DYN_VIEW_TEMP_COLUMN_STATS, vw_describe_local },
    { DYN_VIEW_TEMP_INDEX_STATS, vw_describe_local },
    { DYN_VIEW_SESSION_EX, vw_describe_session },
    { DYN_VIEW_DATAFILE_LAST_TABLE, vw_describe_local },
    { DYN_STATS_RESOURCE, vw_describe_stat },
    { DYN_VIEW_TENANT_TABLESPACES, vw_describe_local },
    { DYN_VIEW_RSRC_MONITOR, vw_describe_stat },
    { DYN_VIEW_PBL, vw_describe_local },
    { DYN_VIEW_USER_ALOCK, vw_describe_lock },
    { DYN_VIEW_ALL_ALOCK, vw_describe_lock },
    { DYN_VIEW_ASYN_SHRINK_TABLES, vw_describe_local },
    { DYN_VIEW_UNDO_STAT, vw_describe_stat },
    { DYN_VIEW_PLAREA, vw_describe_sga },
    { DYN_VIEW_PL_ENTITY, vw_describe_local },
    { DYN_VIEW_CKPT_STATS, vw_describe_local },
    { DYN_VIEW_PL_LOCKS, vw_describe_lock },
    { DYN_VIEW_INDEX_COALESCE, vw_describe_stat },
    { DYN_VIEW_INDEX_RECYCLE, vw_describe_stat },
    { DYN_VIEW_INDEX_REBUILD, vw_describe_stat },
    { DYN_VIEW_USERS, vw_describe_local },
    { DYN_VIEW_DRC_INFO, vw_describe_dtc_local },
    { DYN_VIEW_DRC_BUF_INFO, vw_describe_dtc_local },
    { DYN_VIEW_DRC_RES_RATIO, vw_describe_dtc_local },
    { DYN_VIEW_DRC_GLOBAL_RES, vw_describe_dtc_local },
    { DYN_VIEW_DRC_RES_MAP, vw_describe_dtc_local },
    { DYN_VIEW_BUF_CTRL_INFO, vw_describe_dtc_local },
    { DYN_VIEW_DRC_LOCAL_LOCK_INFO, vw_describe_dtc_local },
    // ===Global dynamic view  for DTC begin===
    { DYN_VIEW_DTC_CONVERTING_PAGE_CNT, vw_describe_dtc },
    { DYN_VIEW_DTC_BUFFER_CTRL, vw_describe_dtc },
    { DYN_VIEW_DTC_MES_STAT, vw_describe_dtc },
    { DYN_VIEW_DTC_MES_ELAPSED, vw_describe_dtc },
    { DYN_VIEW_DTC_MES_QUEUE, vw_describe_dtc },
    { DYN_VIEW_DTC_MES_CHANNEL_STAT, vw_describe_dtc },
    { DYN_VIEW_DTC_NODE_INFO, vw_describe_dtc },
    { DYN_VIEW_DTC_MES_TASK_QUEUE, vw_describe_dtc },
    { DYN_VIEW_BUFFER_ACCESS_STATS, vw_describe_local },
    { DYN_VIEW_BUFFER_RECYCLE_STATS, vw_describe_local },
    // ===Global dynamic view  for DTC end===
    /* ADD NEW VIEW HERE... */
    /* ATENTION PLEASE: DYN_VIEW_SELF MUST BE THE LAST. */
    { DYN_VIEW_IO_STAT_RECORD, vw_describe_stat },
    { DYN_VIEW_TSE_IO_STAT_RECORD, vw_describe_stat},
    { DYN_VIEW_REFORM_STAT, vw_describe_stat },
    { DYN_VIEW_REFORM_DETAIL, vw_describe_stat},
    { DYN_VIEW_PARAL_REPLAY_STAT, vw_describe_stat },
    { DYN_VIEW_SYNCPOINT_STAT, vw_describe_stat },
    { DYN_VIEW_REDO_STAT, vw_describe_stat },
    { DYN_VIEW_CKPT_PART_STAT, vw_describe_local },
    { DYN_VIEW_SELF, vw_describe_local },
    { DYN_VIEW_CTRL_VERSION, vw_describe_local },
    { DYN_VIEW_LFN, vw_describe_local },
    { DYN_VIEW_LRPL_DETAIL, vw_describe_local },
};

knl_dynview_t g_dynamic_views_nomount[] = {
    { DYN_VIEW_SESSION,        vw_describe_session },
    { DYN_VIEW_PARAMETER,      vw_describe_local },
    { DYN_VIEW_SGA,            vw_describe_sga },
    { DYN_VIEW_VERSION,        vw_describe_local },
    { DYN_VIEW_BACKUP_PROCESS, vw_describe_local },
    { DYN_VIEW_INSTANCE,       vw_describe_local },
    { DYN_VIEW_HBA,            vw_describe_local },
    { DYN_VIEW_REACTOR_POOL,   vw_describe_local },
    { DYN_VIEW_EMERG_POOL,     vw_describe_local },
    { DYN_VIEW_KNL_DEBUG_PARAM, vw_describe_local },
    { DYN_BACKUP_PROCESS_STATS, vw_describe_local },
    { DYN_VIEW_SESSION_EX,      vw_describe_session },
    { DYN_VIEW_PBL,            vw_describe_local },
};

knl_dynview_t g_dynamic_views_mount[] = {
    { DYN_VIEW_LOGFILE,             vw_describe_local },
    { DYN_VIEW_DATABASE,            vw_describe_local },
    { DYN_VIEW_DATAFILE,            vw_describe_local },
    { DYN_VIEW_REPL_STATUS,         vw_describe_local },
    { DYN_VIEW_HA_SYNC_INFO,        vw_describe_local },
    { DYN_VIEW_TRANSACTION,         vw_describe_local },
    { DYN_VIEW_CONTROLFILE,         vw_describe_local },
    { DYN_VIEW_RCY_WAIT,            vw_describe_local },
    { DYN_VIEW_TABLESPACE,          vw_describe_local },
    { DYN_VIEW_ARCHIVE_LOG,         vw_describe_local },
    { DYN_VIEW_TEMP_ARCHVIE_LOG,         vw_describe_local },
    { DYN_VIEW_ARCHIVE_GAP,         vw_describe_local },
    { DYN_VIEW_ARCHIVE_PROCESS,     vw_describe_local },
    { DYN_VIEW_ARCHIVE_DEST_STATUS, vw_describe_local },
    { DYN_VIEW_MANAGED_STANDBY,     vw_describe_local },
    { DYN_VIEW_ME,                  vw_describe_local },
    { DYN_VIEW_MEMSTAT,             vw_describe_stat },
    { DYN_VIEW_SYSTEM,              vw_describe_sga },
    { DYN_VIEW_USER_PARAMETER,      vw_describe_local },
    { DYN_VIEW_CTRL_VERSION,        vw_describe_local },
    { DYN_VIEW_LFN,                 vw_describe_local },
};

#define SRV_DYNAMIC_VIEW_COUNT (sizeof(g_dynamic_views) / sizeof(knl_dynview_t))
#define SRV_DYNAMIC_VIEW_COUNT_NOMOUNT (sizeof(g_dynamic_views_nomount) / sizeof(knl_dynview_t))
#define SRV_DYNAMIC_VIEW_COUNT_MOUNT (sizeof(g_dynamic_views_mount) / sizeof(knl_dynview_t))

void srv_regist_dynamic_views(void)
{
    g_instance->kernel.dyn_views = g_dynamic_views;
    g_instance->kernel.dyn_view_count = SRV_DYNAMIC_VIEW_COUNT;
    g_instance->kernel.dyn_views_nomount = g_dynamic_views_nomount;
    g_instance->kernel.dyn_view_nomount_count = SRV_DYNAMIC_VIEW_COUNT_NOMOUNT;
    g_instance->kernel.dyn_views_mount = g_dynamic_views_mount;
    g_instance->kernel.dyn_view_mount_count = SRV_DYNAMIC_VIEW_COUNT_MOUNT;
}

status_t vw_fetch_for_tenant(vw_fetch_func func, knl_handle_t session, knl_cursor_t *cursor)
{
    session_t *se = (session_t *)session;

    while (CT_TRUE) {
        CT_RETURN_IFERR(func(session, cursor));

        if (cursor->eof == CT_TRUE) {
            break;
        }

        if (se->curr_tenant_id == SYS_TENANTROOT_ID || se->curr_tenant_id == cursor->tenant_id) {
            break;
        }
    }
    return CT_SUCCESS;
}

