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
 * knl_ctlg.c
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/knl_ctlg.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_ctlg.h"
#include "knl_table.h"
#include "knl_context.h"
#include "ostat_load.h"
#include "knl_user.h"
#include "index_common.h"
#include "knl_sys_part_defs.h"
#include "dtc_database.h"
#include "dtc_dls.h"
#include "srv_instance.h"

#define GS_SYS_OPT_LEN 16

// definition of core system tables and indexes
knl_column_t g_sys_table_columns[] = {
    { 0,  "USER#",        0, SYS_TABLE_ID, GS_TYPE_INTEGER,   sizeof(uint32),  0,                         0, GS_FALSE, 0, { NULL, 0 } },
    { 1,  "ID",           0, SYS_TABLE_ID, GS_TYPE_INTEGER,   sizeof(uint32),  0,                         0, GS_FALSE, 0, { NULL, 0 } },
    { 2,  "NAME",         0, SYS_TABLE_ID, GS_TYPE_VARCHAR,   GS_MAX_NAME_LEN, 0,                         0, GS_FALSE, 0, { NULL, 0 } },
    { 3,  "SPACE#",       0, SYS_TABLE_ID, GS_TYPE_INTEGER,   sizeof(uint32),  0,                         0, GS_FALSE, 0, { NULL, 0 } },
    { 4,  "ORG_SCN",      0, SYS_TABLE_ID, GS_TYPE_BIGINT,    sizeof(uint64),  0,                         0, GS_FALSE, 0, { NULL, 0 } },  // scn when creating
    { 5,  "CHG_SCN",      0, SYS_TABLE_ID, GS_TYPE_BIGINT,    sizeof(uint64),  0,                         0, GS_FALSE, 0, { NULL, 0 } },  // ddl time
    { 6,  "TYPE",         0, SYS_TABLE_ID, GS_TYPE_INTEGER,   sizeof(uint32),  0,                         0, GS_FALSE, 0, { NULL, 0 } },
    { 7,  "COLS",         0, SYS_TABLE_ID, GS_TYPE_INTEGER,   sizeof(uint32),  0,                         0, GS_FALSE, 0, { NULL, 0 } },
    { 8,  "INDEXES",      0, SYS_TABLE_ID, GS_TYPE_INTEGER,   sizeof(uint32),  0,                         0, GS_FALSE, 0, { NULL, 0 } },
    { 9,  "PARTITIONED",  0, SYS_TABLE_ID, GS_TYPE_INTEGER,   sizeof(uint32),  0,                         0, GS_FALSE, 0, { NULL, 0 } },
    { 10, "ENTRY",        0, SYS_TABLE_ID, GS_TYPE_BIGINT,    sizeof(uint64),  0,                         0, GS_FALSE, 0, { NULL, 0 } },
    { 11, "INITRANS",     0, SYS_TABLE_ID, GS_TYPE_INTEGER,   sizeof(uint32),  0,                         0, GS_FALSE, 0, { NULL, 0 } },
    { 12, "PCTFREE",      0, SYS_TABLE_ID, GS_TYPE_INTEGER,   sizeof(uint32),  0,                         0, GS_FALSE, 0, { NULL, 0 } },
    { 13, "CR_MODE",      0, SYS_TABLE_ID, GS_TYPE_INTEGER,   sizeof(uint32),  0,                         0, GS_FALSE, 0, { NULL, 0 } },
    { 14, "RECYCLED",     0, SYS_TABLE_ID, GS_TYPE_INTEGER,   sizeof(uint32),  0,                         0, GS_FALSE, 0, { NULL, 0 } },
    { 15, "APPENDONLY",   0, SYS_TABLE_ID, GS_TYPE_INTEGER,   sizeof(uint32),  0,                         0, GS_FALSE, 0, { NULL, 0 } },
    { 16, "NUM_ROWS",     0, SYS_TABLE_ID, GS_TYPE_INTEGER,   sizeof(uint32),  0,                         0, GS_TRUE,  0, { NULL, 0 } },
    { 17, "BLOCKS",       0, SYS_TABLE_ID, GS_TYPE_INTEGER,   sizeof(uint32),  0,                         0, GS_TRUE,  0, { NULL, 0 } },
    { 18, "EMPTY_BLOCKS", 0, SYS_TABLE_ID, GS_TYPE_INTEGER,   sizeof(uint32),  0,                         0, GS_TRUE,  0, { NULL, 0 } },
    { 19, "AVG_ROW_LEN",  0, SYS_TABLE_ID, GS_TYPE_BIGINT,    sizeof(uint64),  0,                         0, GS_TRUE,  0, { NULL, 0 } },
    { 20, "SAMPLESIZE",   0, SYS_TABLE_ID, GS_TYPE_INTEGER,   sizeof(uint32),  0,                         0, GS_TRUE,  0, { NULL, 0 } },
    { 21, "ANALYZETIME",  0, SYS_TABLE_ID, GS_TYPE_TIMESTAMP, sizeof(int64),   GS_MAX_DATETIME_PRECISION, 0, GS_TRUE,  0, { NULL, 0 } },
    { 22, "SERIAL_START", 0, SYS_TABLE_ID, GS_TYPE_BIGINT,    sizeof(int64),   0,                         0, GS_FALSE, 0, { NULL, 0 } },
    { 23, "OPTIONS",      0, SYS_TABLE_ID, GS_TYPE_RAW,       GS_SYS_OPT_LEN,  0,                         0, GS_TRUE,  0, { NULL, 0 } },
    { 24, "OBJ#",         0, SYS_TABLE_ID, GS_TYPE_INTEGER,   sizeof(uint32),  0,                         0, GS_TRUE,  0, { NULL, 0 } },
    { 25, "VERSION",      0, SYS_TABLE_ID, GS_TYPE_INTEGER,   sizeof(uint32),  0,                         0, GS_TRUE,  0, { NULL, 0 } },
    { 26, "FLAG",         0, SYS_TABLE_ID, GS_TYPE_INTEGER,   sizeof(uint32),  0,                         0, GS_TRUE,  0, { NULL, 0 } },
};

knl_column_t g_sys_column_columns[] = {
    // syscolumn columns
    { 0,  "USER#",        0, SYS_COLUMN_ID, GS_TYPE_INTEGER, sizeof(uint32),            0, 0, GS_FALSE, 0, { NULL, 0 } },
    { 1,  "TABLE#",       0, SYS_COLUMN_ID, GS_TYPE_INTEGER, sizeof(uint32),            0, 0, GS_FALSE, 0, { NULL, 0 } },
    { 2,  "ID",           0, SYS_COLUMN_ID, GS_TYPE_INTEGER, sizeof(uint32),            0, 0, GS_FALSE, 0, { NULL, 0 } },
    { 3,  "NAME",         0, SYS_COLUMN_ID, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN,           0, 0, GS_FALSE, 0, { NULL, 0 } },
    { 4,  "DATATYPE",     0, SYS_COLUMN_ID, GS_TYPE_INTEGER, sizeof(uint32),            0, 0, GS_FALSE, 0, { NULL, 0 } },
    { 5,  "BYTES",        0, SYS_COLUMN_ID, GS_TYPE_INTEGER, sizeof(uint32),            0, 0, GS_FALSE, 0, { NULL, 0 } },
    { 6,  "PRECISION",    0, SYS_COLUMN_ID, GS_TYPE_INTEGER, sizeof(uint32),            0, 0, GS_TRUE,  0, { NULL, 0 } },
    { 7,  "SCALE",        0, SYS_COLUMN_ID, GS_TYPE_INTEGER, sizeof(uint32),            0, 0, GS_TRUE,  0, { NULL, 0 } },
    { 8,  "NULLABLE",     0, SYS_COLUMN_ID, GS_TYPE_INTEGER, sizeof(uint32),            0, 0, GS_FALSE, 0, { NULL, 0 } },
    { 9,  "FLAGS",        0, SYS_COLUMN_ID, GS_TYPE_INTEGER, sizeof(uint32),            0, 0, GS_FALSE, 0, { NULL, 0 } },
    { 10, "DEFAULT_TEXT", 0, SYS_COLUMN_ID, GS_TYPE_VARCHAR, GS_MAX_DFLT_VALUE_LEN,     0, 0, GS_FALSE, 0, { NULL, 0 } },
    { 11, "DEFAULT_DATA", 0, SYS_COLUMN_ID, GS_TYPE_RAW,     GS_DFLT_VALUE_BUFFER_SIZE, 0, 0, GS_FALSE, 0, { NULL, 0 } },
    { 12, "NUM_DISTINCT", 0, SYS_COLUMN_ID, GS_TYPE_INTEGER, sizeof(uint32),            0, 0, GS_TRUE,  0, { NULL, 0 } },
    { 13, "LOW_VALUE",    0, SYS_COLUMN_ID, GS_TYPE_VARCHAR, GS_MAX_MIN_VALUE_SIZE,     0, 0, GS_TRUE,  0, { NULL, 0 } },
    { 14, "HIGH_VALUE",   0, SYS_COLUMN_ID, GS_TYPE_VARCHAR, GS_MAX_MIN_VALUE_SIZE,     0, 0, GS_TRUE,  0, { NULL, 0 } },
    { 15, "HISTOGRAM",    0, SYS_COLUMN_ID, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN,           0, 0, GS_TRUE,  0, { NULL, 0 } },
    { 16, "OPTIONS",      0, SYS_COLUMN_ID, GS_TYPE_RAW,     GS_SYS_OPT_LEN,            0, 0, GS_TRUE,  0, { NULL, 0 } },
};

knl_column_t g_sys_index_columns[] = {
    // sysindex columns
    { 0,  "USER#",                   0, SYS_INDEX_ID, GS_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         GS_FALSE, 0, { NULL, 0 } },
    { 1,  "TABLE#",                  0, SYS_INDEX_ID, GS_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         GS_FALSE, 0, { NULL, 0 } },
    { 2,  "ID",                      0, SYS_INDEX_ID, GS_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         GS_FALSE, 0, { NULL, 0 } },
    { 3,  "NAME",                    0, SYS_INDEX_ID, GS_TYPE_VARCHAR,   GS_MAX_NAME_LEN,     0,                         0,                         GS_FALSE, 0, { NULL, 0 } },
    { 4,  "SPACE#",                  0, SYS_INDEX_ID, GS_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         GS_FALSE, 0, { NULL, 0 } },
    { 5,  "SEQUENCE#",               0, SYS_INDEX_ID, GS_TYPE_BIGINT,    sizeof(uint64),      0,                         0,                         GS_FALSE, 0, { NULL, 0 } },  // scn when creating
    { 6,  "ENTRY",                   0, SYS_INDEX_ID, GS_TYPE_BIGINT,    sizeof(uint64),      0,                         0,                         GS_FALSE, 0, { NULL, 0 } },
    { 7,  "IS_PRIMARY",              0, SYS_INDEX_ID, GS_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         GS_FALSE, 0, { NULL, 0 } },
    { 8,  "IS_UNIQUE",               0, SYS_INDEX_ID, GS_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         GS_FALSE, 0, { NULL, 0 } },
    { 9,  "TYPE",                    0, SYS_INDEX_ID, GS_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         GS_FALSE, 0, { NULL, 0 } },
    { 10, "COLS",                    0, SYS_INDEX_ID, GS_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         GS_FALSE, 0, { NULL, 0 } },
    { 11, "COL_LIST",                0, SYS_INDEX_ID, GS_TYPE_VARCHAR,   COLUMN_LIST_BUF_LEN, 0,                         0,                         GS_FALSE, 0, { NULL, 0 } },
    { 12, "INITRANS",                0, SYS_INDEX_ID, GS_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         GS_FALSE, 0, { NULL, 0 } },
    { 13, "CR_MODE",                 0, SYS_INDEX_ID, GS_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         GS_FALSE, 0, { NULL, 0 } },
    { 14, "FLAGS",                   0, SYS_INDEX_ID, GS_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         GS_FALSE, 0, { NULL, 0 } },
    { 15, "PARTITIONED",             0, SYS_INDEX_ID, GS_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         GS_FALSE, 0, { NULL, 0 } },
    { 16, "PCTFREE",                 0, SYS_INDEX_ID, GS_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         GS_FALSE, 0, { NULL, 0 } },
    { 17, "BLEVEL",                  0, SYS_INDEX_ID, GS_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         GS_TRUE,  0, { NULL, 0 } },
    { 18, "LEVEL_BLOCKS",            0, SYS_INDEX_ID, GS_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         GS_TRUE,  0, { NULL, 0 } },
    { 19, "DISTINCT_KEYS",           0, SYS_INDEX_ID, GS_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         GS_TRUE,  0, { NULL, 0 } },
    { 20, "AVG_LEAF_BLOCKS_PER_KEY", 0, SYS_INDEX_ID, GS_TYPE_REAL,      sizeof(double),      GS_UNSPECIFIED_REAL_PREC,  GS_UNSPECIFIED_REAL_SCALE, GS_TRUE,  0, { NULL, 0 } },
    { 21, "AVG_DATA_BLOCKS_PER_KEY", 0, SYS_INDEX_ID, GS_TYPE_REAL,      sizeof(double),      GS_UNSPECIFIED_REAL_PREC,  GS_UNSPECIFIED_REAL_SCALE, GS_TRUE,  0, { NULL, 0 } },
    { 22, "ANALYZETIME",             0, SYS_INDEX_ID, GS_TYPE_TIMESTAMP, sizeof(uint64),      GS_MAX_DATETIME_PRECISION, 0,                         GS_TRUE,  0, { NULL, 0 } },
    { 23, "EMPTY_LEAF_BLOCKS",       0, SYS_INDEX_ID, GS_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         GS_TRUE,  0, { NULL, 0 } },
    { 24, "OPTIONS",                 0, SYS_INDEX_ID, GS_TYPE_RAW,       GS_SYS_OPT_LEN,      0,                         0,                         GS_TRUE,  0, { NULL, 0 } },
    { 25, "CLUFAC",                  0, SYS_INDEX_ID, GS_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         GS_TRUE,  0, { NULL, 0 } },
    { 26, "SAMPLESIZE",              0, SYS_INDEX_ID, GS_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         GS_TRUE,  0, { NULL, 0 } },
    { 27, "OBJ#",                    0, SYS_INDEX_ID, GS_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         GS_TRUE,  0, { NULL, 0 } },
    { 28, "COMB_COLS_2_NDV",         0, SYS_INDEX_ID, GS_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         GS_TRUE,  0, { NULL, 0 } },
    { 29, "COMB_COLS_3_NDV",         0, SYS_INDEX_ID, GS_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         GS_TRUE,  0, { NULL, 0 } },
    { 30, "COMB_COLS_4_NDV",         0, SYS_INDEX_ID, GS_TYPE_INTEGER,   sizeof(uint32),      0,                         0,                         GS_TRUE,  0, { NULL, 0 } },
};

#define ID_COLUMN_ID         0
#define NAME_COLUMN_ID       1
#define PASSWORD_COLUMN_ID   2
#define DATA_SPACE_COLUMN_ID 3
#define TEMP_SPACE_COLUMN_ID 4
#define CTIME_COLUMN_ID      5
#define PTIME_COLUMN_ID      6
#define EXPTIME_COLUMN_ID    7
#define LTIME_COLUMN_ID      8
#define PROFILE_COLUMN_ID    9
#define ASTATUS_COLUMN_ID    10
#define LCOUNT_COLUMN_ID     11
#define OPTIONS_COLUMN_ID    12
#define TENANT_ID_COLUMN_ID  13

knl_column_t g_sys_user_columns[] = {
    // sysuser columns
    { 0,  "ID",          0, SYS_USER_ID, GS_TYPE_INTEGER, sizeof(uint32),          0, 0, GS_FALSE, 0, { NULL, 0 } },
    { 1,  "NAME",        0, SYS_USER_ID, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN,         0, 0, GS_FALSE, 0, { NULL, 0 } },
    { 2,  "PASSWORD",    0, SYS_USER_ID, GS_TYPE_RAW,     GS_PASSWORD_BUFFER_SIZE, 0, 0, GS_FALSE, 0, { NULL, 0 } },
    { 3,  "DATA_SPACE#", 0, SYS_USER_ID, GS_TYPE_INTEGER, sizeof(uint32),          0, 0, GS_FALSE, 0, { NULL, 0 } },  // default tablespace
    { 4,  "TEMP_SPACE#", 0, SYS_USER_ID, GS_TYPE_INTEGER, sizeof(uint32),          0, 0, GS_FALSE, 0, { NULL, 0 } },  // temporary space
    { 5,  "CTIME",       0, SYS_USER_ID, GS_TYPE_DATE,    sizeof(date_t),          0, 0, GS_FALSE, 0, { NULL, 0 } },  // user account creation time
    { 6,  "PTIME",       0, SYS_USER_ID, GS_TYPE_DATE,    sizeof(date_t),          0, 0, GS_FALSE, 0, { NULL, 0 } },  // pwd change time
    { 7,  "EXPTIME",     0, SYS_USER_ID, GS_TYPE_DATE,    sizeof(date_t),          0, 0, GS_TRUE,  0, { NULL, 0 } },  // actual pwd expiration time
    { 8,  "LTIME",       0, SYS_USER_ID, GS_TYPE_DATE,    sizeof(date_t),          0, 0, GS_TRUE,  0, { NULL, 0 } },  // time when account is locked
    { 9,  "PROFILE#",    0, SYS_USER_ID, GS_TYPE_INTEGER, sizeof(uint32),          0, 0, GS_FALSE, 0, { NULL, 0 } },  // profile#
    { 10, "ASTATUS",     0, SYS_USER_ID, GS_TYPE_INTEGER, sizeof(uint32),          0, 0, GS_FALSE, 0, { NULL, 0 } },  // status of the account. 0x00 = Open, 0x01 = Locked, 0x02 = Expired
    { 11, "LCOUNT",      0, SYS_USER_ID, GS_TYPE_INTEGER, sizeof(uint32),          0, 0, GS_FALSE, 0, { NULL, 0 } },  // count of failed login attempts
    { 12, "OPTIONS",     0, SYS_USER_ID, GS_TYPE_RAW,     GS_SYS_OPT_LEN,          0, 0, GS_TRUE,  0, { NULL, 0 } },
    { 13, "TENANT_ID",   0, SYS_USER_ID, GS_TYPE_INTEGER, sizeof(uint32),          0, 0, GS_FALSE, 0, { NULL, 0 } },  // tenant id
};

#define SYSTABLE_COLS  (uint32)(sizeof(g_sys_table_columns) / sizeof(knl_column_t))
#define SYSCOLUMN_COLS (uint32)(sizeof(g_sys_column_columns) / sizeof(knl_column_t))
#define SYSINDEX_COLS  (uint32)(sizeof(g_sys_index_columns) / sizeof(knl_column_t))
#define SYSUSER_COLS   (uint32)(sizeof(g_sys_user_columns) / sizeof(knl_column_t))

table_t g_sys_tables[] = {
    { { SYS_TABLE_ID, "SYS_TABLES", 0, SYS_SPACE_ID, SYS_TABLE_ID, 0, 0, 0, TABLE_TYPE_HEAP, SYSTABLE_COLS, 2, 0, { 2 }, GS_INI_TRANS, GS_PCT_FREE, 0, CR_ROW, 0 } },
    { { SYS_COLUMN_ID, "SYS_COLUMNS", 0, SYS_SPACE_ID, SYS_COLUMN_ID, 0, 0, 0, TABLE_TYPE_HEAP, SYSCOLUMN_COLS, 1, 0, { 2 }, GS_INI_TRANS, GS_PCT_FREE, 0, CR_ROW, 0 } },
    { { SYS_INDEX_ID, "SYS_INDEXES", 0, SYS_SPACE_ID, SYS_INDEX_ID, 0, 0, 0, TABLE_TYPE_HEAP, SYSINDEX_COLS, 2, 0, { 2 }, GS_INI_TRANS, GS_PCT_FREE, 0, CR_ROW, 0 } },
    { { SYS_USER_ID, "SYS_USERS", 0, SYS_SPACE_ID, SYS_USER_ID, 0, 0, 0, TABLE_TYPE_HEAP, SYSUSER_COLS, 2, 0, { 2 }, GS_INI_TRANS, GS_PCT_FREE, 0, CR_ROW, 0 } },
};

static index_t g_sys_indexes[] = {
    { { 0, 0, 0, SYS_SPACE_ID, SYS_TABLE_ID, "IX_TABLE$001", 0, 0, { 0 }, GS_FALSE, GS_TRUE, INDEX_TYPE_BTREE, 2, { 0, 2 }, GS_INI_TRANS, CR_ROW, { 0 }, 0, GS_PCT_FREE, GS_FALSE, NULL, GS_MAX_KEY_SIZE} },
    { { 1, 1, 0, SYS_SPACE_ID, SYS_TABLE_ID, "IX_TABLE$002", 0, 0, { 0 }, GS_FALSE, GS_TRUE, INDEX_TYPE_BTREE, 2, { 0, 1 }, GS_INI_TRANS, CR_ROW, { 0 }, 0, GS_PCT_FREE, GS_FALSE, NULL, GS_MAX_KEY_SIZE } },
    { { 0, 0, 0, SYS_SPACE_ID, SYS_COLUMN_ID, "IX_COLUMN$001", 0, 0, { 0 }, GS_FALSE, GS_TRUE, INDEX_TYPE_BTREE, 3, { 0, 1, 2 }, GS_INI_TRANS, CR_ROW, { 0 }, 0, GS_PCT_FREE, GS_FALSE, NULL, GS_MAX_KEY_SIZE } },
    { { 0, 0, 0, SYS_SPACE_ID, SYS_INDEX_ID, "IX_INDEX$001", 0, 0, { 0 }, GS_FALSE, GS_FALSE, INDEX_TYPE_BTREE, 3, { 0, 1, 2 }, GS_INI_TRANS, CR_ROW, { 0 }, 0, GS_PCT_FREE, GS_FALSE, NULL, GS_MAX_KEY_SIZE } },
    { { 1, 1, 0, SYS_SPACE_ID, SYS_INDEX_ID, "IX_INDEX$002", 0, 0, { 0 }, GS_FALSE, GS_TRUE, INDEX_TYPE_BTREE, 3, { 0, 3, 1}, GS_INI_TRANS, CR_ROW, { 0 }, 0, GS_PCT_FREE, GS_FALSE, NULL, GS_MAX_KEY_SIZE } },
    { { 0, 0, 0, SYS_SPACE_ID, SYS_USER_ID, "IX_USER$001", 0, 0, { 0 }, GS_FALSE, GS_TRUE, INDEX_TYPE_BTREE, 1, { 0 }, GS_INI_TRANS, CR_ROW, { 0 }, 0, GS_PCT_FREE, GS_FALSE, NULL, GS_MAX_KEY_SIZE } },
    { { 1, 1, 0, SYS_SPACE_ID, SYS_USER_ID, "IX_USER$002", 0, 0, { 0 }, GS_FALSE, GS_TRUE, INDEX_TYPE_BTREE, 1, { 1 }, GS_INI_TRANS, CR_ROW, { 0 }, 0, GS_PCT_FREE, GS_FALSE, NULL, GS_MAX_KEY_SIZE } },
};

static knl_column_t *g_system_table_columns[] = {
    g_sys_table_columns,
    g_sys_column_columns,
    g_sys_index_columns,
    g_sys_user_columns,
};

table_t *db_sys_table(uint32 id)
{
    return &g_sys_tables[id];
}

index_t *db_sys_index(uint32 id)
{
    return &g_sys_indexes[id];
}

status_t db_write_systable(knl_session_t *session, knl_cursor_t *cursor, knl_table_desc_t *desc)
{
    uint32 max_size;
    row_assist_t ra;
    space_t *space;

    space = SPACE_GET(session, desc->space_id);
    if (!SPACE_IS_ONLINE(space)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "space offline and write to table$ failed");
        return GS_ERROR;
    }

    if (IS_CORE_SYS_TABLE(desc->uid, desc->id)) {
        knl_open_core_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_TABLE_ID);
    } else {
        knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_TABLE_ID, GS_INVALID_ID32);
    }

    max_size = session->kernel->attr.max_row_size;
    row_init(&ra, (char *)cursor->row, max_size, SYSTABLE_COLS);
    (void)row_put_int32(&ra, desc->uid);               // user id
    (void)row_put_int32(&ra, desc->id);                // id
    (void)row_put_str(&ra, desc->name);                // name
    (void)row_put_int32(&ra, desc->space_id);          // table space id
    (void)row_put_int64(&ra, desc->org_scn);           // scn when creating
    (void)row_put_int64(&ra, desc->chg_scn);           // scn when last DDL
    (void)row_put_int32(&ra, desc->type);              // type
    (void)row_put_int32(&ra, desc->column_count);      // column count
    (void)row_put_int32(&ra, desc->index_count);       // index count
    (void)row_put_int32(&ra, desc->parted);            // table partitioned
    (void)row_put_int64(&ra, *(int64 *)&desc->entry);  // entry
    (void)row_put_int32(&ra, desc->initrans);          // init trans
    (void)row_put_int32(&ra, desc->pctfree);           // pct free
    (void)row_put_int32(&ra, desc->cr_mode);           // table CR mode
    (void)row_put_int32(&ra, desc->recycled);          // whether in recycle bin
    (void)row_put_int32(&ra, desc->appendonly);        // appendonly
    /* write statistics column */
    for (uint32 i = 0; i < STATS_SYS_TABLE_COLUMN_COUNT; i++) {
        row_put_null(&ra);
    }

    (void)row_put_uint64(&ra, desc->serial_start);  // auto increment init value
    (void)row_put_null(&ra);                       // options column
    (void)row_put_int32(&ra, desc->oid);           // object id
    (void)row_put_int32(&ra, desc->version);       // table version
    (void)row_put_int32(&ra, desc->flags);

    if (IS_CORE_SYS_TABLE(desc->uid, desc->id)) {
        return TABLE_ACCESSOR(cursor)->do_insert(session, cursor);
    } else {
        return knl_internal_insert(session, cursor);
    }
}

status_t db_write_sysstorage(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t org_scn, knl_storage_desc_t *desc)
{
    uint32 max_size;
    row_assist_t ra;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_STORAGE_ID, GS_INVALID_ID32);

    max_size = session->kernel->attr.max_row_size;
    row_init(&ra, (char *)cursor->row, max_size, SYS_STORAGE_COLUMN_COUNT);
    (void)row_put_int64(&ra, org_scn); // org scn
    
    if (desc->initial > 0) {
        (void)row_put_int32(&ra, desc->initial); // object initial pages
    } else {
        (void)row_put_null(&ra);
    }

    if (desc->max_pages > 0) {
        (void)row_put_int32(&ra, desc->max_pages); // object max pages
    } else {
        (void)row_put_null(&ra);
    }

    return knl_internal_insert(session, cursor);
}

status_t db_write_sysview(knl_session_t *session, knl_cursor_t *cursor, knl_view_t *view, knl_view_def_t *def)
{
    uint32 max_size;
    row_assist_t ra;
    table_t *table = NULL;
    knl_column_t *lob_column = NULL;

    max_size = session->kernel->attr.max_row_size;
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_VIEW_ID, GS_INVALID_ID32);
    table = (table_t *)cursor->table;
    lob_column = knl_get_column(cursor->dc_entity, SYS_VIEW_TEXT_COLUMN);
    row_init(&ra, (char *)cursor->row, max_size, table->desc.column_count);
    (void)row_put_int32(&ra, view->uid);
    (void)row_put_int32(&ra, view->id);
    (void)row_put_str(&ra, view->name);
    (void)row_put_int32(&ra, view->column_count);
    (void)row_put_int32(&ra, view->flags);
    (void)row_put_int64(&ra, view->org_scn);
    (void)row_put_int64(&ra, view->chg_scn);
    (void)row_put_int32(&ra, def->sub_sql.len);

    if (knl_row_put_lob(session, cursor, lob_column, &def->sub_sql, &ra) != GS_SUCCESS) {
        return GS_ERROR;
    }

    (void)row_put_int32(&ra, view->sql_type);

    if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_write_sysrb(knl_session_t *session, knl_rb_desc_t *desc)
{
    table_t *table = NULL;
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_RB_ID, GS_INVALID_ID32);
    table = (table_t *)cursor->table;

    row_init(&ra, (char *)cursor->row, GS_MAX_ROW_SIZE, table->desc.column_count);
    (void)row_put_int64(&ra, desc->id);
    (void)row_put_str(&ra, desc->name);
    (void)row_put_int32(&ra, desc->uid);
    (void)row_put_str(&ra, desc->org_name);

    if (desc->part_name[0] == '\0') {
        row_put_null(&ra);
    } else {
        (void)row_put_str(&ra, desc->part_name);
    }

    (void)row_put_int32(&ra, desc->type);
    (void)row_put_int32(&ra, desc->oper);
    (void)row_put_int32(&ra, desc->space_id);
    (void)row_put_int64(&ra, *(int64 *)&desc->entry);
    (void)row_put_int32(&ra, desc->flags);
    (void)row_put_int64(&ra, desc->org_scn);
    (void)row_put_int64(&ra, desc->rec_scn);

    if (desc->tchg_scn == GS_INVALID_ID64) {
        row_put_null(&ra);
    } else {
        (void)row_put_int64(&ra, desc->tchg_scn);
    }

    (void)row_put_int64(&ra, desc->base_id);
    (void)row_put_int64(&ra, desc->purge_id);

    if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

static void db_make_syscolumn_row(knl_session_t *session, knl_cursor_t *cursor, knl_column_t *column)
{
    uint32 max_size;
    row_assist_t ra;

    max_size = session->kernel->attr.max_row_size;
    row_init(&ra, (char *)cursor->row, max_size, SYSCOLUMN_COLS);
    (void)(row_put_int32(&ra, column->uid));                                          // user id
    (void)(row_put_int32(&ra, column->table_id));                                     // table id
    (void)(row_put_int32(&ra, column->id));                                           // id
    (void)(row_put_str(&ra, column->name));                                           // name
    (void)(row_put_int32(&ra, column->datatype));                                     // data type
    (void)(row_put_int32(&ra, column->size));                                         // size
    row_put_prec_and_scale(&ra, column->datatype, column->precision, column->scale); // precision & scale
    (void)(row_put_int32(&ra, column->nullable));                                     // nullable
    (void)(row_put_int32(&ra, column->flags));                                        // flags
    if (KNL_COLUMN_IS_DEFAULT_NULL(column)) {
        (void)row_put_null(&ra);
    } else {
        (void)(row_put_text(&ra, &column->default_text));  // default value length
    }
    (void)row_put_null(&ra); // default binary data, keep for compitable
    /* write statistics column */
    for (uint32 i = 0; i < STATS_SYS_COLUMN_COLUMN_COUNT; i++) {
        row_put_null(&ra);
    }
}

status_t db_write_syscolumn(knl_session_t *session, knl_cursor_t *cursor, knl_column_t *column)
{
    if (IS_CORE_SYS_TABLE(column->uid, column->table_id)) {
        knl_open_core_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_COLUMN_ID);
    } else {
        knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_COLUMN_ID, GS_INVALID_ID32);
    }
    db_make_syscolumn_row(session, cursor, column);

    if (IS_CORE_SYS_TABLE(column->uid, column->table_id)) {
        return TABLE_ACCESSOR(cursor)->do_insert(session, cursor);
    } else {
        return knl_internal_insert(session, cursor);
    }
}

status_t db_write_sysview_column(knl_session_t *session, knl_cursor_t *cursor, knl_column_t *column)
{
    uint32 max_size;
    row_assist_t ra;
    table_t *table = NULL;

    max_size = session->kernel->attr.max_row_size;
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_VIEWCOL_ID, GS_INVALID_ID32);
    table = (table_t *)cursor->table;
    row_init(&ra, (char *)cursor->row, max_size, table->desc.column_count);
    (void)row_put_int32(&ra, column->uid);                                            // user id
    (void)row_put_int32(&ra, column->table_id);                                       // view id
    (void)row_put_int32(&ra, column->id);                                             // id
    (void)row_put_str(&ra, column->name);                                             // name
    (void)row_put_int32(&ra, column->datatype);                                       // data type
    (void)row_put_int32(&ra, column->size);                                           // size
    row_put_prec_and_scale(&ra, column->datatype, column->precision, column->scale);  // precision & scale
    (void)row_put_int32(&ra, column->nullable);                                       // nullable
    (void)row_put_int32(&ra, column->flags);                                          // flags

    if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t db_insert_syscolumn_rows(knl_session_t *session, knl_cursor_t *cursor, knl_column_t *columns,
                                         uint32 count)
{
    uint32 i, max_size;
    row_assist_t ra;

    max_size = session->kernel->attr.max_row_size;

    for (i = 0; i < count; i++) {
        row_init(&ra, cursor->buf, max_size, SYSCOLUMN_COLS);
        if (db_write_syscolumn(session, cursor, &columns[i]) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_build_sys_column(knl_session_t *session, knl_cursor_t *cursor)
{
    cursor->table = db_sys_table(SYS_COLUMN_ID);

    if (db_insert_syscolumn_rows(session, cursor, g_sys_table_columns, SYSTABLE_COLS) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_insert_syscolumn_rows(session, cursor, g_sys_column_columns, SYSCOLUMN_COLS) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_insert_syscolumn_rows(session, cursor, g_sys_index_columns, SYSINDEX_COLS) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_insert_syscolumn_rows(session, cursor, g_sys_user_columns, SYSUSER_COLS) != GS_SUCCESS) {
        return GS_ERROR;
    }

    knl_commit(session);

    return GS_SUCCESS;
}

status_t db_write_sysindex(knl_session_t *session, knl_cursor_t *cursor, knl_index_desc_t *desc)
{
    row_assist_t ra;
    char buf[COLUMN_LIST_BUF_LEN];
    text_t column_list;

    column_list.str = buf;
    column_list.len = 0;

    space_t *space = SPACE_GET(session, desc->space_id);
    if (!SPACE_IS_ONLINE(space)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "space offline and write to system index failed");
        return GS_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_INDEX_ID, GS_INVALID_ID32);

    for (uint32 i = 0; i < desc->column_count; i++) {
        cm_concat_int32(&column_list, COLUMN_LIST_BUF_LEN, desc->columns[i]);
        if (i + 1 < desc->column_count) {
            if (cm_concat_string(&column_list, COLUMN_LIST_BUF_LEN, ",") != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    row_init(&ra, cursor->buf, KNL_MAX_ROW_SIZE(session), SYSINDEX_COLS);
    (void)(row_put_int32(&ra, desc->uid));       // user
    (void)(row_put_int32(&ra, desc->table_id));  // table
    (void)(row_put_int32(&ra, desc->id));        // id
    (void)(row_put_str(&ra, desc->name));  // name
    (void)(row_put_int32(&ra, desc->space_id));          // space
    (void)(row_put_int64(&ra, desc->org_scn));           // sequence
    (void)(row_put_int64(&ra, *(int64 *)&desc->entry));  // entry
    (void)(row_put_int32(&ra, desc->primary));           // primary key
    (void)(row_put_int32(&ra, desc->unique));            // unique
    (void)(row_put_int32(&ra, desc->type));              // type
    (void)(row_put_int32(&ra, desc->column_count));      // column count
    (void)(row_put_text(&ra, &column_list));             // columns
    (void)(row_put_int32(&ra, desc->initrans));          // initrans
    (void)(row_put_int32(&ra, desc->cr_mode));           // consistent read mode
    (void)(row_put_int32(&ra, desc->flags));             // flags
    (void)(row_put_int32(&ra, desc->parted));            // parted
    (void)(row_put_int32(&ra, desc->pctfree));           // pctfree

    /* write statistics columns */
    for (uint32 j = SYS_INDEX_COLUMN_ID_BLEVEL; j < SYSINDEX_COLS; j++) {
        row_put_null(&ra);
    }

    return knl_internal_insert(session, cursor);
}

status_t db_build_sys_user(knl_session_t *session, knl_cursor_t *cursor)
{
    uint32 max_size;
    row_assist_t ra;
    char rand_buf[GS_PASSWD_MIN_LEN + 1];
    char public_pwd[GS_PASSWORD_BUFFER_SIZE];
    uint32 public_pwd_len = GS_PASSWORD_BUFFER_SIZE;
    char *cipher = NULL;
    date_t date = cm_now();
    errno_t err;

    /* create a random string for public as the password. */
    if (cm_rand((uchar *)rand_buf, GS_PASSWD_MIN_LEN) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_base64_encode((uchar *)rand_buf, GS_PASSWD_MIN_LEN, public_pwd, &public_pwd_len) != GS_SUCCESS) {
        return GS_ERROR;
    }
    err = memset_sp(rand_buf, GS_PASSWD_MIN_LEN + 1, 0, GS_PASSWD_MIN_LEN + 1);
    knl_securec_check(err);
    
    knl_open_core_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_USER_ID);

    max_size = session->kernel->attr.max_row_size;
    cipher = (char *)cm_push(session->stack, GS_PASSWORD_BUFFER_SIZE);

    row_init(&ra, cursor->buf, max_size, SYSUSER_COLS);
    (void)(row_put_int32(&ra, 0));                            // id
    (void)(row_put_str(&ra, "SYS"));                          // name
    (void)(row_put_str(&ra, session->kernel->attr.sys_pwd));  // pwd
    (void)(row_put_int32(&ra, SYS_SPACE_ID));                 // tablespace system
    (void)(row_put_int32(&ra, dtc_my_ctrl(session)->swap_space));  // default tablespace
    (void)(row_put_date(&ra, date));                          // create time
    (void)(row_put_date(&ra, date));                          // pwd change time
    row_put_null(&ra);                                        // expire time
    row_put_null(&ra);                                        // lock time
    (void)(row_put_int32(&ra, 0));                            // profile#, default 0
    (void)(row_put_int32(&ra, ACCOUNT_STATUS_OPEN));          // astatus
    (void)(row_put_int32(&ra, 0));                            // lcount
    row_put_null(&ra);                                        // options
    (void)(row_put_int32(&ra, 0));                            // tenant id
    if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
        cm_pop(session->stack);
        return GS_ERROR;
    }

    err = memset_sp(cipher, GS_PASSWORD_BUFFER_SIZE, 0, GS_PASSWORD_BUFFER_SIZE);
    knl_securec_check(err);
    if (user_encrypt_password((char *)session->kernel->attr.pwd_alg, session->kernel->attr.alg_iter,
                              public_pwd, (uint32)strlen(public_pwd), cipher,
                              GS_PASSWORD_BUFFER_SIZE) != GS_SUCCESS) {
        cm_pop(session->stack);
        return GS_ERROR;
    }

    row_init(&ra, cursor->buf, max_size, SYSUSER_COLS);
    (void)row_put_int32(&ra, 1);                    // id
    (void)row_put_str(&ra, "PUBLIC");               // name
    (void)row_put_str(&ra, cipher);                 // pwd
    (void)row_put_int32(&ra, SYS_SPACE_ID);         // tablespace system
    (void)row_put_int32(&ra, dtc_my_ctrl(session)->swap_space);  // temp tablespace
    (void)row_put_date(&ra, date);                  // create time
    (void)row_put_date(&ra, date);                  // pwd change time
    row_put_null(&ra);                              // expire time
    row_put_null(&ra);                              // lock time
    (void)row_put_int32(&ra, 0);                    // profile#, default 0
    (void)row_put_int32(&ra, ACCOUNT_STATUS_OPEN);  // astatus
    (void)row_put_int32(&ra, 0);                    // lcount
    row_put_null(&ra);                              // options
    (void)(row_put_int32(&ra, 0));                  // tenant id
    if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
        cm_pop(session->stack);
        return GS_ERROR;
    }

    knl_commit(session);
    cm_pop(session->stack);

    return GS_SUCCESS;
}

/*
 * Description     : get indexed column list from index description
 * Input           : list : indexed column id list
 * Output          : desc : index description
 * Return Value    : status
 * History         : 1.2017/4/26,  add description
 */
static void db_get_index_column_list(text_t *list, uint32 list_max_size, knl_index_desc_t *desc)
{
    uint32 i;

    for (i = 0; i < desc->column_count; i++) {
        cm_concat_int32(list, list_max_size, desc->columns[i]);
        if (i + 1 < desc->column_count) {
            (void)cm_concat_string(list, COLUMN_LIST_BUF_LEN, ",");
        }
    }
}

void db_update_core_index(knl_session_t *session, rd_update_core_index_t *redo_index_info)
{
    uint8 i;
    index_t *sys_index = NULL;
    core_ctrl_t *core = &session->kernel->db.ctrl.core;

    for (i = 0; i <= IX_SYS_USER2_ID; i++) {
        sys_index = db_sys_index(i);
        if (sys_index->desc.table_id == redo_index_info->table_id &&
            sys_index->desc.id == redo_index_info->index_id) {
            sys_index->desc.entry = redo_index_info->entry;
        }
    }

    core->ix_sys_table1_entry = db_sys_index(IX_SYS_TABLE1_ID)->desc.entry;
    core->ix_sys_table2_entry = db_sys_index(IX_SYS_TABLE2_ID)->desc.entry;
    core->ix_sys_column_entry = db_sys_index(IX_SYS_COLUMN_ID)->desc.entry;
    core->ix_sys_index1_entry = db_sys_index(IX_SYS_INDEX1_ID)->desc.entry;
    core->ix_sys_index2_entry = db_sys_index(IX_SYS_INDEX2_ID)->desc.entry;
    core->ix_sys_user1_entry = db_sys_index(IX_SYS_USER1_ID)->desc.entry;
    core->ix_sys_user2_entry = db_sys_index(IX_SYS_USER2_ID)->desc.entry;
}

status_t db_build_sys_index(knl_session_t *session, knl_cursor_t *cursor)
{
    uint32 i;
    row_assist_t ra;
    char buf[COLUMN_LIST_BUF_LEN];
    text_t column_list;
    knl_index_desc_t *desc = NULL;
    core_ctrl_t *core = &session->kernel->db.ctrl.core;
    index_t *index = NULL;

    knl_open_core_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_INDEX_ID);

    for (i = 0; i < sizeof(g_sys_indexes) / sizeof(index_t); i++) {
        index = db_sys_index(i);
        if (session->kernel->attr.clustered) {
            index->desc.cr_mode = CR_PAGE;
        }

        if (btree_create_segment(session, index) != GS_SUCCESS) {
            return GS_ERROR;
        }

        column_list.str = buf;
        column_list.len = 0;
        desc = &g_sys_indexes[i].desc;
        db_get_index_column_list(&column_list, COLUMN_LIST_BUF_LEN, desc);

        row_init(&ra, cursor->buf, KNL_MAX_ROW_SIZE(session), SYSINDEX_COLS);
        (void)(row_put_int32(&ra, desc->uid));
        (void)(row_put_int32(&ra, desc->table_id));
        (void)(row_put_int32(&ra, desc->id));
        (void)(row_put_str(&ra, desc->name));
        (void)(row_put_int32(&ra, desc->space_id));
        (void)(row_put_int64(&ra, desc->org_scn));
        (void)(row_put_int64(&ra, *(int64 *)&desc->entry));
        (void)(row_put_int32(&ra, desc->primary));
        (void)(row_put_int32(&ra, desc->unique));
        (void)(row_put_int32(&ra, desc->type));
        (void)(row_put_int32(&ra, desc->column_count));
        (void)(row_put_text(&ra, &column_list));
        (void)(row_put_int32(&ra, desc->initrans));
        (void)(row_put_int32(&ra, desc->cr_mode));
        (void)(row_put_int32(&ra, desc->flags));
        (void)(row_put_int32(&ra, desc->parted));
        (void)(row_put_int32(&ra, desc->pctfree));

        if (TABLE_ACCESSOR(cursor)->do_insert(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    knl_commit(session);
    core->ix_sys_table1_entry = db_sys_index(IX_SYS_TABLE1_ID)->desc.entry;
    core->ix_sys_table2_entry = db_sys_index(IX_SYS_TABLE2_ID)->desc.entry;
    core->ix_sys_column_entry = db_sys_index(IX_SYS_COLUMN_ID)->desc.entry;
    core->ix_sys_index1_entry = db_sys_index(IX_SYS_INDEX1_ID)->desc.entry;
    core->ix_sys_index2_entry = db_sys_index(IX_SYS_INDEX2_ID)->desc.entry;
    core->ix_sys_user1_entry = db_sys_index(IX_SYS_USER1_ID)->desc.entry;
    core->ix_sys_user2_entry = db_sys_index(IX_SYS_USER2_ID)->desc.entry;

    return GS_SUCCESS;
}

static status_t db_fill_indexes_of_table(knl_session_t *session, knl_cursor_t *cursor, uint32 table_id)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, table_id, GS_INVALID_ID32);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (knl_insert_indexes(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t db_build_dual(knl_session_t *session, knl_cursor_t *cursor)
{
    row_assist_t ra;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, DUAL_ID, GS_INVALID_ID32);

    row_init(&ra, cursor->buf, GS_MAX_DUAL_ROW_SIZE, 1);
    (void)(row_put_str(&ra, "X"));
    if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/* in-build role : connect */
status_t db_build_sys_roles(knl_session_t *session, knl_cursor_t *cursor)
{
    errno_t err;
    knl_role_def_t def;
    uint32 max_size;
    row_assist_t ra;

    def.owner_uid = 0;
    def.password[0] = '\0';
    def.is_encrypt = GS_FALSE;

    err = strcpy_sp(def.name, GS_NAME_BUFFER_SIZE, "CONNECT");
    knl_securec_check(err);
    if (user_create_role(session, &def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /* grant create session to connect */
    max_size = session->kernel->attr.max_row_size;
    row_init(&ra, cursor->buf, max_size, 4);
    (void)(row_put_int32(&ra, CONNECT_ROLE_ID));               // grantee id
    (void)(row_put_int32(&ra, PRIVS_GRANTEE_TYPE_ROLE));       // grantee type : role
    (void)(row_put_int32(&ra, CREATE_SESSION));                // privilege
    (void)(row_put_int32(&ra, PRIVS_ADMIN_OPTION_FALSE));      // admin option

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_PRIVS_ID, GS_INVALID_ID32);
    if (GS_SUCCESS != knl_internal_insert(session, cursor)) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_build_sys_privs(knl_session_t *session, knl_cursor_t *cursor)
{
    uint32 priv_id;
    uint32 max_size;
    row_assist_t ra;

    max_size = session->kernel->attr.max_row_size;

    for (priv_id = ALL_PRIVILEGES + 1; priv_id < GS_SYS_PRIVS_COUNT; priv_id++) {
        row_init(&ra, cursor->buf, max_size, 4);
        (void)row_put_int32(&ra, 0);
        (void)row_put_int32(&ra, 0);
        (void)row_put_int32(&ra, priv_id);
        (void)row_put_int32(&ra, 1);

        knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_PRIVS_ID, GS_INVALID_ID32);
        if (GS_SUCCESS != knl_internal_insert(session, cursor)) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

/* in-build user_history sys */
static status_t db_build_user_sys_history(knl_session_t *session, knl_cursor_t *cursor)
{
    uint32 max_size;
    row_assist_t ra;

    max_size = session->kernel->attr.max_row_size;

    /* insert sys user psw history record */
    row_init(&ra, cursor->buf, max_size, SYSUSER_HISTORY_COLS);
    (void)(row_put_int32(&ra, 0));                            // USER#
    (void)(row_put_str(&ra, session->kernel->attr.sys_pwd));  // PASSWORD
    (void)(row_put_date(&ra, cm_now()));                      // PASSWORD_DATE

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_USER_HISTORY_ID, GS_INVALID_ID32);
    if (GS_SUCCESS != knl_internal_insert(session, cursor)) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/* in-build sys_tenants sys */
static status_t db_build_sys_tenants(knl_session_t *session, knl_cursor_t *cursor)
{
    uint32 max_size;
    row_assist_t ra;
    binary_t bin;
    uint8 buf[GS_SPACES_BITMAP_SIZE];
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(session);

    bin.bytes = buf;
    bin.is_hex_const = GS_FALSE;
    bin.size = GS_SPACES_BITMAP_SIZE;

    errno_t ret = memset_sp(buf, GS_SPACES_BITMAP_SIZE, -1, GS_SPACES_BITMAP_SIZE);
    knl_securec_check(ret);

    max_size = session->kernel->attr.max_row_size;

    /* insert sys_tenants */
    row_init(&ra, cursor->buf, max_size, SYS_TENANTS_COLUMN_COUNT);
    (void)(row_put_int32(&ra, 0));                              // tenant_id
    (void)(row_put_str(&ra, T2S(&g_tenantroot)));               // tenant_name
    (void)(row_put_int32(&ra, core_ctrl->user_space));          // default_tablespace
    (void)(row_put_int32(&ra, 0));                              // tablespace_num, 0 :no limitation
    (void)(row_put_bin(&ra, &bin));                             // tablespaces_bitmap
    (void)(row_put_date(&ra, cm_now()));                        // create time
    (void)(row_put_null(&ra));                                  // options

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_TENANTS_ID, GS_INVALID_ID32);
    if (GS_SUCCESS != knl_internal_insert(session, cursor)) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_build_ex_systables(knl_session_t *session)
{
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_set_session_scn(session, GS_INVALID_ID64);

    if (db_build_dual(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_build_sys_privs(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_build_sys_roles(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (profile_build_sysprofile(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_build_user_sys_history(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_build_sys_tenants(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    knl_commit(session);

    return GS_SUCCESS;
}

status_t db_build_completed(knl_session_t *session)
{
    core_ctrl_t *core_ctrl = &session->kernel->db.ctrl.core;

    dtc_my_ctrl(session)->scn = DB_CURR_SCN(session);
    core_ctrl->build_completed = GS_TRUE;

    if (db_save_core_ctrl(session) != GS_SUCCESS) {
        CM_ABORT(0, "[DC] ABORT INFO: save core control file failed when load ex_systables");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_fill_builtin_indexes(knl_session_t *session)
{
    uint32 i;
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    for (i = 0; i <= CORE_SYS_TABLE_CEIL; i++) {
        if (g_sys_tables[i].desc.index_count == 0) {
            continue;
        }

        if (db_fill_indexes_of_table(session, cursor, i) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    knl_commit(session);
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_insert_sys_user(knl_session_t *session, knl_cursor_t *cursor, knl_user_desc_t *desc)
{
    row_assist_t row;
    uint32 max_size;

    max_size = session->kernel->attr.max_row_size;
    row_init(&row, cursor->buf, max_size, SYSUSER_COLS);
    (void)(row_put_int32(&row, desc->id));             // id
    (void)(row_put_str(&row, desc->name));             // name
    (void)(row_put_str(&row, desc->password));         // pwd from create database, encrypt it
    (void)(row_put_int32(&row, desc->data_space_id));  // default tablespace
    (void)(row_put_int32(&row, desc->temp_space_id));  // temp table sapce
    (void)row_put_date(&row, desc->ctime);             // create time
    (void)row_put_date(&row, desc->ptime);             // pwd change time
    if (desc->astatus & ACCOUNT_STATUS_EXPIRED) {
        (void)(row_put_date(&row, desc->exptime));  // expire time
    } else {
        row_put_null(&row);  // expire time
    }

    if (desc->astatus & ACCOUNT_STATUS_LOCK) {
        (void)(row_put_date(&row, desc->ltime));  // lock time
    } else {
        row_put_null(&row);  // lock time
    }
    (void)(row_put_int32(&row, desc->profile_id));  // profile#, default 0
    (void)(row_put_int32(&row, desc->astatus));     // astatus
    (void)(row_put_int32(&row, desc->lcount));      // lcount
    row_put_null(&row);                             // options
    (void)(row_put_int32(&row, desc->tenant_id));   // tenant id
    if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_insert_sys_tenants(knl_session_t *session, knl_cursor_t *cursor, knl_tenant_desc_t *desc)
{
    row_assist_t row;
    uint32 max_size;
    binary_t bin;

    bin.bytes = (uint8 *)desc->ts_bitmap;
    bin.size = GS_SPACES_BITMAP_SIZE;
    bin.is_hex_const = GS_FALSE;

    CM_MAGIC_CHECK(desc, knl_tenant_desc_t);

    max_size = session->kernel->attr.max_row_size;
    row_init(&row, cursor->buf, max_size, SYS_TENANTS_COLUMN_COUNT);
    (void)(row_put_int32(&row, desc->id));                // id
    (void)(row_put_str(&row, desc->name));                // name
    (void)(row_put_int32(&row, desc->ts_id));             // default tablespace
    (void)(row_put_int32(&row, desc->ts_num));            // tablespace num
    (void)(row_put_bin(&row, &bin));                      // tablespace bitmap
    (void)row_put_date(&row, desc->ctime);                // create time
    (void)(row_put_null(&row));                           // options
    if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static void db_alter_user_field_core(knl_user_desc_t *desc, knl_cursor_t *cursor, uint32 update_flag,
    row_assist_t row, uint16 update_cols_input)
{
    uint16 update_cols = update_cols_input;
    if (CHECK_UPDATE_COLUMN(update_flag, UPDATE_PASSWORD_COLUMM)) {
        (void)row_put_str(&row, desc->password);
        cursor->update_info.columns[update_cols++] = PASSWORD_COLUMN_ID;
    }
    if (CHECK_UPDATE_COLUMN(update_flag, UPDATE_DATA_SPACE_COLUMN)) {
        (void)row_put_int32(&row, desc->data_space_id);
        cursor->update_info.columns[update_cols++] = DATA_SPACE_COLUMN_ID;
    }
    if (CHECK_UPDATE_COLUMN(update_flag, UPDATE_TEMP_SPACE_COLUMN)) {
        (void)row_put_int32(&row, desc->temp_space_id);
        cursor->update_info.columns[update_cols++] = TEMP_SPACE_COLUMN_ID;
    }
    if (CHECK_UPDATE_COLUMN(update_flag, UPDATE_CTIME_COLUMN)) {
        (void)row_put_date(&row, desc->ctime);
        cursor->update_info.columns[update_cols++] = CTIME_COLUMN_ID;
    }
    if (CHECK_UPDATE_COLUMN(update_flag, UPDATE_PTIME_COLUMN)) {
        (void)row_put_date(&row, desc->ptime);
        cursor->update_info.columns[update_cols++] = PTIME_COLUMN_ID;
    }

    if (CHECK_UPDATE_COLUMN(update_flag, UPDATE_EXPTIME_COLUMN)) {
        if (desc->exptime == 0) {
            (void)row_put_null(&row);
        } else {
            (void)row_put_date(&row, desc->exptime);
        }
        cursor->update_info.columns[update_cols++] = EXPTIME_COLUMN_ID;
    }

    if (CHECK_UPDATE_COLUMN(update_flag, UPDATE_LTIME_COLUMN)) {
        (void)row_put_date(&row, desc->ltime);
        cursor->update_info.columns[update_cols++] = LTIME_COLUMN_ID;
    }
    if (CHECK_UPDATE_COLUMN(update_flag, UPDATE_PROFILE_COLUMN)) {
        (void)row_put_int32(&row, desc->profile_id);
        cursor->update_info.columns[update_cols++] = PROFILE_COLUMN_ID;
    }
    if (CHECK_UPDATE_COLUMN(update_flag, UPDATE_ASTATUS_COLUMN)) {
        (void)row_put_int32(&row, desc->astatus);
        cursor->update_info.columns[update_cols++] = ASTATUS_COLUMN_ID;
    }
    if (CHECK_UPDATE_COLUMN(update_flag, UPDATE_LCOUNT_COLUMN)) {
        (void)row_put_int32(&row, desc->lcount);
        cursor->update_info.columns[update_cols++] = LCOUNT_COLUMN_ID;
    }

    cursor->update_info.count = update_cols;
}

status_t db_alter_user_field(knl_session_t *session, knl_user_desc_t *desc, knl_cursor_t *cursor, uint32 update_flag)
{
    uint16 update_cols = 0;
    uint32 max_size;
    row_assist_t row;

    max_size = session->kernel->attr.max_row_size;
    row_init(&row, cursor->update_info.data, max_size, SYSUSER_COLS);

    (void)db_alter_user_field_core(desc, cursor, update_flag, row, update_cols);

    return GS_SUCCESS;
}

status_t db_alter_tenant_field(knl_session_t *session, knl_tenant_desc_t *desc)
{
    uint16 update_cols = 0;
    uint32 max_size;
    row_assist_t row;
    binary_t bin;
    knl_cursor_t *cursor;

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TENANTS_ID, IX_SYS_TENANTS_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &desc->id,
        sizeof(uint32), 0);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (cursor->eof) {
        GS_THROW_ERROR(ERR_OBJECT_ID_NOT_EXIST, "tenant", desc->id);
        return GS_ERROR;
    }

    max_size = session->kernel->attr.max_row_size;
    row_init(&row, cursor->update_info.data, max_size, SYS_TENANTS_COLUMN_COUNT);

    (void)row_put_int32(&row, desc->ts_id);
    cursor->update_info.columns[update_cols++] = SYS_TENANTS_COL_TABLESPACE_ID;

    bin.bytes = (uint8 *)desc->ts_bitmap;
    bin.size = GS_SPACES_BITMAP_SIZE;
    bin.is_hex_const = GS_FALSE;

    (void)row_put_int32(&row, desc->ts_num);
    cursor->update_info.columns[update_cols++] = SYS_TENANTS_COL_TABLESPACES_NUM;

    (void)row_put_bin(&row, &bin);
    cursor->update_info.columns[update_cols++] = SYS_TENANTS_COL_TABLESPACES_BITMAP;
    cursor->update_info.count = update_cols;

    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);
    return knl_internal_update(session, cursor);
}

/*
 * Description     : initialize columns of specified core system table for dc
 * Input           : entity : dc entity of table
 * Input           : desc : description of table
 * Output          : entity
 * Return Value    : status
 * History         : 1. 2017/4/26,  add description
 */
static status_t db_init_dc_columns(knl_session_t *session, dc_entity_t *entity, knl_table_desc_t *desc)
{
    uint32 i, hash;
    knl_column_t *column = NULL;
    errno_t err;

    entity->column_count = desc->column_count;

    if (dc_prepare_load_columns(session, entity) != GS_SUCCESS) {
        return GS_ERROR;
    }

    for (i = 0; i < desc->column_count; i++) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory,
                         sizeof(knl_column_t), (void **)&column) != GS_SUCCESS) {
            return GS_ERROR;
        }

        err = memcpy_sp(column, sizeof(knl_column_t), &g_system_table_columns[desc->id][i], sizeof(knl_column_t));
        knl_securec_check(err);
        entity->column_groups[i / DC_COLUMN_GROUP_SIZE].columns[i % DC_COLUMN_GROUP_SIZE] = column;
    }

    for (i = 0; i < entity->column_count; i++) {
        column = dc_get_column(entity, i);
        hash = cm_hash_column_name(column->name, strlen(column->name), entity->column_count, IS_COMPATIBLE_MYSQL_INST);
        column->next = DC_GET_COLUMN_INDEX(entity, hash);
        // the largest value of i is column_count which is smaller 4096, thus, i is smaller than uint16
        entity->column_groups[hash / DC_COLUMN_GROUP_SIZE].column_index[hash % DC_COLUMN_GROUP_SIZE] = (uint16)i;
    }

    return GS_SUCCESS;
}

static status_t db_init_dc_index(knl_session_t *session, dc_entity_t *entity, knl_table_desc_t *desc)
{
    index_t *index = NULL;
    knl_index_desc_t *ix_desc = NULL;
    uint32 i;
    errno_t err;

    for (i = 0; i < sizeof(g_sys_indexes) / sizeof(index_t); i++) {
        ix_desc = &g_sys_indexes[i].desc;
        if (ix_desc->table_id != desc->id) {
            continue;
        }

        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(index_t), (void **)&index) != GS_SUCCESS) {
            return GS_ERROR;
        }

        err = memset_sp(index, sizeof(index_t), 0, sizeof(index_t));
        knl_securec_check(err);
        err = memcpy_sp(&index->desc, sizeof(knl_index_desc_t), ix_desc, sizeof(knl_index_desc_t));
        knl_securec_check(err);

        entity->table.index_set.items[index->desc.id] = index;
        entity->table.index_set.count++;
        entity->table.index_set.total_count++;
        index->btree.index = index;
        index->btree.entry = ix_desc->entry;
        dc_set_index_profile(session, entity, index);
        dc_set_index_accessor(&entity->table, index);
        dls_init_latch2(&index->btree.struct_latch, DR_TYPE_BTREE_LATCH, index->desc.table_id, index->desc.uid,
                        index->desc.id, GS_INVALID_ID32, GS_INVALID_ID32);

        buf_enter_page(session, ix_desc->entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
        index->btree.segment = BTREE_GET_SEGMENT(session);
        bt_put_change_stats(&index->btree);
        buf_leave_page(session, GS_FALSE);

        index->entity = entity;
        index->desc.seg_scn = BTREE_SEGMENT(session, index->btree.entry, index->btree.segment)->seg_scn;
    }

    return GS_SUCCESS;
}

status_t db_load_core_entity_by_id(knl_session_t *session, memory_context_t *memory, table_t *table)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    dc_user_t *user;
    dc_entry_t *entry = NULL;
    dc_entity_t *entity = NULL;
    errno_t err;

    user = ctx->users[0];
    entry = user->groups[0]->entries[table->desc.id];

    if (dc_alloc_mem(ctx, memory, sizeof(dc_entity_t), (void **)&entry->entity) != GS_SUCCESS) {
        return GS_ERROR;
    }

    err = memset_sp(entry->entity, sizeof(dc_entity_t), 0, sizeof(dc_entity_t));
    knl_securec_check(err);

    entry->ref_count = 1;
    entity = entry->entity;
    entity->entry = entry;
    entity->memory = memory;
    entity->valid = GS_TRUE;
    entity->type = DICT_TYPE_TABLE;
    err = memcpy_sp(&entity->table, sizeof(table_t), table, sizeof(table_t));
    knl_securec_check(err);
    entity->table.heap.table = &entity->table;
    dc_set_table_accessor(&entity->table);
    dls_init_spinlock(&entity->table.heap.lock, DR_TYPE_HEAP, table->desc.id, (uint16)table->desc.uid);
    dls_init_latch(&entity->table.heap.latch, DR_TYPE_HEAP_LATCH, table->desc.id, (uint16)table->desc.uid);

    if (db_init_dc_columns(session, entity, &table->desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_init_dc_index(session, entity, &table->desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void db_get_sys_dc(knl_session_t *session, uint32 id, knl_dictionary_t *dc)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    dc_user_t *user;
    dc_entry_t *entry;
    user = ctx->users[0];
    entry = user->groups[0]->entries[id];
    dc->handle = entry->entity;
    dc->uid = 0;
    dc->oid = id;
    dc->type = entry->type;
    dc->chg_scn = 0;
    dc->org_scn = 0;
}

status_t db_fetch_systable_by_start_oid(knl_session_t *session, uint32 uid, uint32 start_oid, knl_cursor_t *cursor)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TABLE_ID, IX_SYS_TABLE_002_ID);
    knl_init_index_scan(cursor, GS_FALSE);

    /* find the tuple by uid and oid */
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key,
                     GS_TYPE_INTEGER, &uid, sizeof(uint32), IX_COL_SYS_TABLE_002_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key,
                     GS_TYPE_INTEGER, &uid, sizeof(uint32), IX_COL_SYS_TABLE_002_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key,
                     GS_TYPE_INTEGER, &start_oid, sizeof(uint32), IX_COL_SYS_TABLE_002_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_TABLE_002_ID);

    return knl_fetch(session, cursor);
}

status_t db_analyze_schema(knl_session_t *session, knl_analyze_schema_def_t *def)
{
    knl_analyze_tab_def_t tab;
    knl_cursor_t *cursor = NULL;
    uint32 uid, oid, start_oid, table_count;
    bool32 is_recycled = GS_FALSE;
    errno_t ret;

    if (!dc_get_user_id(session, &def->owner, &uid)) {
        GS_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&def->owner));
        return GS_ERROR;
    }

    ret = memset_sp(&tab, sizeof(knl_analyze_tab_def_t), 0, sizeof(knl_analyze_tab_def_t));
    knl_securec_check(ret);

    tab.owner = def->owner;
    tab.method_opt = def->method_opt;
    tab.is_default = def->is_default;
    tab.sample_type = def->sample_type;
    start_oid = 0;

    do {
        knl_set_session_scn(session, GS_INVALID_ID64);

        CM_SAVE_STACK(session->stack);

        cursor = knl_push_cursor(session);
        if (db_fetch_systable_by_start_oid(session, uid, start_oid, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        tab.sample_level = def->sample_level;
        tab.sample_ratio = def->sample_ratio;

        table_count = 0;
        while (!cursor->eof) {
            if (session->canceled) {
                GS_THROW_ERROR(ERR_OPERATION_CANCELED);
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }

            if (session->killed) {
                GS_THROW_ERROR(ERR_OPERATION_KILLED);
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }

            oid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, TABLE_TABLE_ID);
            tab.name.str = CURSOR_COLUMN_DATA(cursor, TABLE_NAME);
            tab.name.len = CURSOR_COLUMN_SIZE(cursor, TABLE_NAME);
            is_recycled = *(uint32 *)CURSOR_COLUMN_DATA(cursor, TABLE_RECYCLED);
            /* recycled table will not be analyzed. */
            if (!is_recycled) {
                (void)db_analyze_table(session, &tab, GS_FALSE);
                cm_reset_error();
                table_count++;
            }

            if (table_count > STAT_TABLES_PER_TIME) {
                start_oid = oid + 1;
                break;
            }

            if (GS_SUCCESS != knl_fetch(session, cursor)) {
                int32 err_code = cm_get_error_code();
                if (err_code == ERR_SNAPSHOT_TOO_OLD) {
                    start_oid = oid + 1;
                    break;
                }

                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
        }

        CM_RESTORE_STACK(session->stack);

        if (cursor->eof) {
            break;
        }
    } while (table_count > 0);

    return GS_SUCCESS;
}

status_t db_delete_schema_stats(knl_session_t *session, text_t *schema_name)
{
    status_t status = GS_SUCCESS;
    knl_dictionary_t dc;
    uint32 uid = GS_INVALID_ID32;
    uint32 table_id = GS_INVALID_ID32;
    bool32 eof = GS_FALSE;

    if (DB_IS_READONLY(session)) {
        GS_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "operation on read only mode");
        return GS_ERROR;
    }

    if (!knl_get_user_id(session, schema_name, &uid)) {
        GS_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(schema_name));
        return GS_ERROR;
    }
    
    for (;;) {
        status = GS_SUCCESS;
        if (dc_scan_tables_by_user(session, uid, &table_id, &eof) != GS_SUCCESS) {
            return status;
        }

        if (eof) {
            break;
        }

        if (session->canceled) {
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            return GS_ERROR;
        }

        if (session->killed) {
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            return GS_ERROR;
        }

        if (knl_open_dc_by_id(session, uid, table_id, &dc, GS_TRUE) != GS_SUCCESS) {
            continue;
        }

        if (lock_table_shared_directly(session, &dc) != GS_SUCCESS) {
            status = GS_ERROR;
        } else {
            status = stats_delete_table_stats(session, uid, table_id, GS_FALSE);
        }

        if (status != GS_SUCCESS) {
            knl_rollback(session, NULL);
            cm_reset_error();
        } else {
            knl_commit(session);
        }

        unlock_tables_directly(session);
        dc_close(&dc);
    }

    return GS_SUCCESS;
}

void print_db_update_core_index(log_entry_t *log)
{
    rd_update_core_index_t *redo = (rd_update_core_index_t *)log->data;

    printf("update core index %u.%u entry %u-%u", redo->table_id, redo->index_id, redo->entry.file, redo->entry.page);
}

void rd_db_update_core_index(knl_session_t *session, log_entry_t *log)
{
    rd_update_core_index_t *redo = (rd_update_core_index_t *)log->data;

    db_update_core_index(session, redo);
    if (db_save_core_ctrl(session) != GS_SUCCESS) {
        CM_ABORT(0, "[RD] ABORT INFO: save core control file failed when update core index");
    }
}

static seg_exec_proc g_segment_proc[SEG_OP_CNT];
static seg_executor_t g_segment_executors[] = {
    { HEAP_DROP_SEGMENT,           heap_drop_garbage_segment },
    { HEAP_DROP_PART_SEGMENT,      heap_drop_part_garbage_segment },
    { HEAP_TRUNCATE_SEGMENT,       heap_truncate_garbage_segment },
    { HEAP_TRUNCATE_PART_SEGMENT,  heap_truncate_part_garbage_segment },
    { BTREE_DROP_SEGMENT,          btree_drop_garbage_segment },
    { BTREE_DROP_PART_SEGMENT,     btree_drop_part_garbage_segment },
    { BTREE_TRUNCATE_SEGMENT,      btree_truncate_garbage_segment },
    { BTREE_TRUNCATE_PART_SEGMENT, btree_truncate_part_garbage_segment },
    { LOB_DROP_SEGMENT,            lob_drop_garbage_segment },
    { LOB_DROP_PART_SEGMENT,       lob_drop_part_garbage_segment },
    { LOB_TRUNCATE_SEGMENT,        lob_truncate_garbage_segment },
    { LOB_TRUNCATE_PART_SEGMENT,   lob_truncate_part_garbage_segment },
    { HEAP_PURGE_SEGMENT,          heap_purge_segment},
    { BTREE_PURGE_SEGMENT,         btree_purge_segment},
    { LOB_PURGE_SEGMENT,           lob_purge_segment},
    { BTREE_DELAY_DROP_SEGMENT,    btree_drop_garbage_segment },
    { BTREE_DELAY_DROP_PART_SEGMENT, btree_drop_part_garbage_segment },
};

static inline void db_convert_segment_desc(knl_cursor_t *cursor, knl_seg_desc_t *desc)
{
    desc->uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_GARBAGE_SEGMENT_COL_UID);
    desc->oid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_GARBAGE_SEGMENT_COL_OID);
    desc->index_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_GARBAGE_SEGMENT_COL_INDEX_ID);
    desc->column_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_GARBAGE_SEGMENT_COL_COLUMN_ID);
    desc->space_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_GARBAGE_SEGMENT_COL_SPACE);
    desc->entry = *(page_id_t *)CURSOR_COLUMN_DATA(cursor, SYS_GARBAGE_SEGMENT_COL_ENTRY);
    desc->org_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, SYS_GARBAGE_SEGMENT_COL_ORG_SCN);
    desc->seg_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, SYS_GARBAGE_SEGMENT_COL_SEG_SCN);
    desc->initrans = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_GARBAGE_SEGMENT_COL_INITRANS);
    desc->pctfree = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_GARBAGE_SEGMENT_COL_PCTFREE);
    desc->op_type = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_GARBAGE_SEGMENT_COL_OP_TYPE);
    desc->reuse = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_GARBAGE_SEGMENT_COL_REUSE);
    desc->serial = *(int64 *)CURSOR_COLUMN_DATA(cursor, SYS_GARBAGE_SEGMENT_COL_SERIAL);
}

bool32 db_valid_seg_tablespace(knl_session_t *session, uint32 space_id, page_id_t entry)
{
    if (space_id >= GS_MAX_SPACES) {
        GS_LOG_RUN_INF("space id:%u is invalid.", space_id);
        return GS_FALSE;
    }

    if (!spc_valid_space_object(session, space_id)) {
        GS_LOG_RUN_INF("space id:%u is invalid.", space_id);
        return GS_FALSE;
    }

    if (IS_INVALID_PAGID(entry)) {
        GS_LOG_RUN_INF("entry id:%u is invalid.", (uint32)entry.file);
        return GS_FALSE;
    }

    datafile_t *df = DATAFILE_GET(session, entry.file);
    if (!DATAFILE_IS_ONLINE(df) || df->space_id >= GS_MAX_SPACES ||
        SPACE_GET(session, df->space_id)->is_empty || DF_FILENO_IS_INVAILD(df)) {
        GS_LOG_RUN_INF("invalid df, online:%u, space id:%u, invalid:%u",
            DATAFILE_IS_ONLINE(df), space_id, DF_FILENO_IS_INVAILD(df));
        return GS_FALSE;
    }

    return GS_TRUE;
}

void db_garbage_segment_init(knl_session_t *session)
{
    int i;

    for (i = 0; i < SEG_OP_CNT; i++) {
        g_segment_proc[g_segment_executors[i].type] = g_segment_executors[i].proc;
    }
}

status_t db_garbage_segment_clean(knl_session_t *session)
{
    knl_cursor_t *cursor = NULL;
    knl_seg_desc_t desc;

    if (DB_IS_READONLY(session) || DB_IS_MAINTENANCE(session)) {
        return GS_SUCCESS;
    }
    GS_LOG_RUN_INF("[DB] Clean garbage segment start");
    knl_set_session_scn(session, GS_INVALID_ID64);

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_GARBAGE_SEGMENT_ID, GS_INVALID_ID32);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        db_convert_segment_desc(cursor, &desc);

        /*
        * nologging space will be reset when restart, so don't clean it,
        * and because of nologging space has no log, space->head->segment_count maybe not correct.
        */
        if (SPACE_IS_LOGGING(SPACE_GET(session, desc.space_id))) {
            g_segment_proc[desc.op_type](session, &desc);
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    GS_LOG_RUN_INF("[DB] Clean garbage segment end");

    return GS_SUCCESS;
}

static inline bool32 is_purge_truncate_type(seg_op_t op_type)
{
    return (op_type == HEAP_PURGE_SEGMENT  ||
            op_type == BTREE_PURGE_SEGMENT ||
            op_type == LOB_PURGE_SEGMENT);
}

static status_t db_truncate_garbage_heap(knl_session_t *session, knl_cursor_t *cursor,  uint32 uid, uint32 oid)
{
    knl_seg_desc_t desc;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_GARBAGE_SEGMENT_ID, IX_SYS_GARBAGE_SEGMENT001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
        IX_COL_SYS_GARBAGE_SEGMENT001_UID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &oid, sizeof(uint32),
        IX_COL_SYS_GARBAGE_SEGMENT001_OID);

    for (;;) {
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        db_convert_segment_desc(cursor, &desc);

        if (desc.op_type == HEAP_TRUNCATE_PART_SEGMENT || desc.op_type == HEAP_TRUNCATE_SEGMENT) {
            g_segment_proc[desc.op_type](session, &desc);

            if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }
    return GS_SUCCESS;
}

/**
 * force clean space garbage segment, because space is drop of offline
 */
status_t db_clean_tablespace_garbage_seg(knl_session_t *session, uint32 space_id)
{
    knl_seg_desc_t desc;

    CM_SAVE_STACK(session->stack);
    knl_set_session_scn(session, GS_INVALID_ID64);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_GARBAGE_SEGMENT_ID, GS_INVALID_ID32);
    status_t status = GS_SUCCESS;

    for (;;) {
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            GS_LOG_RUN_WAR("[DB] fetch tablespace %u garbage segment failed.", space_id);
            status = GS_ERROR;
            break;
        }

        if (cursor->eof) {
            break;
        }

        db_convert_segment_desc(cursor, &desc);
        if (desc.space_id != space_id) {
            continue;
        }

        // force clean space's garbage segment, because space is dropped
        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            GS_LOG_RUN_WAR("[DB] Clean tablespace %u garbage segment failed, uid %u, oid %u.",
                space_id, desc.uid, desc.oid);
            status = GS_ERROR;
            continue;
        }
    }

    knl_commit(session);
    CM_RESTORE_STACK(session->stack);
    return status;
}

status_t db_garbage_segment_handle(knl_session_t *session, uint32 uid, uint32 oid, bool32 is_purge_truncate)
{
    knl_cursor_t *cursor = NULL;
    knl_seg_desc_t desc;

    if (DB_IS_READONLY(session) || DB_IS_MAINTENANCE(session)) {
        return GS_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);
    knl_set_session_scn(session, GS_INVALID_ID64);
    cursor = knl_push_cursor(session);
    if (db_truncate_garbage_heap(session, cursor, uid, oid) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_GARBAGE_SEGMENT_ID, IX_SYS_GARBAGE_SEGMENT001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
        IX_COL_SYS_GARBAGE_SEGMENT001_UID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &oid, sizeof(uint32),
        IX_COL_SYS_GARBAGE_SEGMENT001_OID);

    for (;;) {
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        db_convert_segment_desc(cursor, &desc);

        if (is_purge_truncate != is_purge_truncate_type(desc.op_type)) {
            continue;
        }

        if (desc.op_type == BTREE_DELAY_DROP_SEGMENT || desc.op_type == BTREE_DELAY_DROP_PART_SEGMENT) {
            continue;
        }

        g_segment_proc[desc.op_type](session, &desc);

        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    knl_commit(session);
    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

status_t db_write_garbage_segment(knl_session_t *session, knl_seg_desc_t *seg)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    uint32 max_size;

    if (IS_INVALID_PAGID(seg->entry)) {
        return GS_SUCCESS;
    }

    if (DB_IS_MAINTENANCE(session)) {
        g_segment_proc[seg->op_type](session, seg);
        return GS_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_GARBAGE_SEGMENT_ID, IX_SYS_GARBAGE_SEGMENT001_ID);
    max_size = session->kernel->attr.max_row_size;
    row_init(&ra, (char *)cursor->row, max_size, SYS_GARBAGE_SEGMENT_COLS);
    (void)row_put_int32(&ra, seg->uid);
    (void)row_put_int32(&ra, seg->oid);
    (void)row_put_int32(&ra, seg->index_id);
    (void)row_put_int32(&ra, seg->column_id);
    (void)row_put_int32(&ra, seg->space_id);
    (void)row_put_int64(&ra, *(int64 *)&seg->entry);
    (void)row_put_int64(&ra, seg->org_scn);
    (void)row_put_int64(&ra, seg->seg_scn);
    (void)row_put_int32(&ra, seg->initrans);
    (void)row_put_int32(&ra, seg->pctfree);
    (void)row_put_int32(&ra, seg->op_type);
    (void)row_put_int32(&ra, seg->reuse);
    (void)row_put_int64(&ra, seg->serial);

    if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

status_t db_update_garbage_segment_entry(knl_session_t *session, knl_table_desc_t *desc, page_id_t entry)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    uint16 size;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_GARBAGE_SEGMENT_ID, IX_SYS_GARBAGE_SEGMENT001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &desc->uid, sizeof(uint32),
        IX_COL_SYS_GARBAGE_SEGMENT001_UID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &desc->id, sizeof(uint32),
        IX_COL_SYS_GARBAGE_SEGMENT001_OID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
        cursor->update_info.columns[0] = SYS_GARBAGE_SEGMENT_COL_ENTRY;
        (void)row_put_int64(&ra, *(int64 *)&entry);

        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

        if (knl_internal_update(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t db_update_garbage_segment_optype(knl_session_t *session, knl_index_desc_t desc)
{
    row_assist_t ra;
    uint16 size;

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_GARBAGE_SEGMENT_ID, IX_SYS_GARBAGE_SEGMENT001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &desc.uid, sizeof(uint32),
        IX_COL_SYS_GARBAGE_SEGMENT001_UID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &desc.table_id,
        sizeof(uint32), IX_COL_SYS_GARBAGE_SEGMENT001_OID);

    knl_scn_t del_scn = DB_CURR_SCN(session);
    uint32 op_type;
    uint32 index_id;

    for (;;) {
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        index_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_GARBAGE_SEGMENT_COL_INDEX_ID);
        if (index_id != desc.id) {
            continue;
        }

        op_type = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_GARBAGE_SEGMENT_COL_OP_TYPE);
        if (op_type == BTREE_DROP_PART_SEGMENT) {
            op_type = BTREE_DELAY_DROP_PART_SEGMENT;
        } else if (op_type == BTREE_DROP_SEGMENT) {
            op_type = BTREE_DELAY_DROP_SEGMENT;
        } else {
            continue;
        }

        cursor->update_info.count = UPDATE_COLUMN_COUNT_TWO;
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_TWO);
        cursor->update_info.columns[0] = SYS_GARBAGE_SEGMENT_COL_ORG_SCN;
        cursor->update_info.columns[1] = SYS_GARBAGE_SEGMENT_COL_OP_TYPE;
        (void)row_put_int64(&ra, *(int64 *)&del_scn);
        (void)row_put_int32(&ra, *(int32 *)&op_type);
        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

        if (knl_internal_update(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    knl_commit(session);
    return GS_SUCCESS;
}

void db_update_index_clean_option(knl_session_t *session, knl_alindex_def_t *def, knl_index_desc_t desc)
{
    if (def->type != ALINDEX_TYPE_REBUILD && def->type != ALINDEX_TYPE_REBUILD_PART &&
        def->type != ALINDEX_TYPE_REBUILD_SUBPART) {
        return;
    }

    if (!def->rebuild.keep_storage) {
        return;
    }

    if (db_update_garbage_segment_optype(session, desc) == GS_SUCCESS) {
        cm_spin_lock(&session->kernel->rmon_ctx.mark_mutex, NULL);
        session->kernel->rmon_ctx.delay_clean_segments = GS_TRUE;
        cm_spin_unlock(&session->kernel->rmon_ctx.mark_mutex);
    } else {
        knl_rollback(session, NULL);
        GS_LOG_RUN_ERR("[DB] failed to update garbage segment del scn");
    }
}

void db_clean_garbage_partition(knl_session_t *session)
{
    knl_cursor_t *del_cursor = NULL;
    uint32 flags;
    uint32 uid, tid;
    knl_altable_def_t def;
    dc_user_t *user = NULL;
    dc_entry_t *entry = NULL;

    if (DB_IS_READONLY(session)) {
        return;
    }

    CM_SAVE_STACK(session->stack);

    knl_set_session_scn(session, GS_INVALID_ID64);
    del_cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, del_cursor, CURSOR_ACTION_SELECT, SYS_TABLEPART_ID, GS_INVALID_ID32);

    if (knl_fetch(session, del_cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        GS_LOG_RUN_ERR("[DB] failed to purge system TABLEPART");
        return;
    }

    while (!del_cursor->eof) {
        uid = *(uint32 *)CURSOR_COLUMN_DATA(del_cursor, SYS_TABLEPART_COL_USER_ID);
        tid = *(uint32 *)CURSOR_COLUMN_DATA(del_cursor, SYS_TABLEPART_COL_TABLE_ID);
        flags = *(uint32 *)CURSOR_COLUMN_DATA(del_cursor, SYS_TABLEPART_COL_FLAGS);
        def.part_def.name.str = CURSOR_COLUMN_DATA(del_cursor, SYS_TABLEPART_COL_NAME);
        def.part_def.name.len = CURSOR_COLUMN_SIZE(del_cursor, SYS_TABLEPART_COL_NAME);
        def.action = ALTABLE_DROP_PARTITION;
        def.part_def.is_garbage_clean = GS_TRUE;

        if (flags & PARTITON_NOT_READY) { // partition not ready
            if (dc_open_user_by_id(session, uid, &user) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                GS_LOG_RUN_ERR("[DB] failed to open dc when clean garbage partition");
                return;
            }

            entry = DC_GET_ENTRY(user, tid);

            def.user.str = user->desc.name;
            def.user.len = (uint32)strlen(user->desc.name);
            def.name.str = entry->name;
            def.name.len = (uint32)strlen(entry->name);

            if (knl_perform_alter_table(session, NULL, &def, GS_FALSE) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                GS_LOG_RUN_ERR("[DB] failed to delete garbage partition from system TABLEPART");
                return;
            }

            GS_LOG_RUN_INF("[DB] delete one garbage partition from system TABLEPART, the partition name is %s",
                def.part_def.name.str);
        }

        if (knl_fetch(session, del_cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            GS_LOG_RUN_ERR("[DB] failed to purge system TABLEPART");
            return;
        }
    }

    CM_RESTORE_STACK(session->stack);

    return;
}

void db_clean_garbage_subpartition(knl_session_t *session)
{
    uint32 uid, tid, flag;
    knl_altable_def_t def;
    dc_user_t *user = NULL;
    dc_entry_t *entry = NULL;

    if (DB_IS_READONLY(session)) {
        return;
    }

    CM_SAVE_STACK(session->stack);
    knl_set_session_scn(session, GS_INVALID_ID64);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SUB_TABLE_PARTS_ID, GS_INVALID_ID32);
    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        GS_LOG_RUN_ERR("[DB] failed to purge system SUBTABLEPART");
        return;
    }

    while (!cursor->eof) {
        uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLESUBPART_COL_USER_ID);
        tid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLESUBPART_COL_TABLE_ID);
        flag = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLESUBPART_COL_FLAGS);
        def.part_def.name.str = CURSOR_COLUMN_DATA(cursor, SYS_TABLESUBPART_COL_NAME);
        def.part_def.name.len = CURSOR_COLUMN_SIZE(cursor, SYS_TABLESUBPART_COL_NAME);
        def.action = ALTABLE_DROP_SUBPARTITION;
        def.part_def.is_garbage_clean = GS_TRUE;

        if (flag & PARTITON_NOT_READY) {
            if (dc_open_user_by_id(session, uid, &user) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[DB] failed to open dc when clean garbage partition");
                break;
            }

            entry = DC_GET_ENTRY(user, tid);
            def.user.str = user->desc.name;
            def.user.len = (uint32)strlen(user->desc.name);
            def.name.str = entry->name;
            def.name.len = (uint32)strlen(entry->name);

            if (knl_perform_alter_table(session, NULL, &def, GS_FALSE) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[DB] failed to delete garbage partition from system SUBTABLEPART");
                break;
            }

            GS_LOG_RUN_INF("[DB] delete one garbage subpartition from system SUBTABLEPART, the partition name is %s",
                def.part_def.name.str);
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DB] failed to purge system TABLEPART");
            break;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return;
}

void db_delay_clean_segments(knl_session_t *session)
{
    CM_SAVE_STACK(session->stack);
    uint32 timeout = session->kernel->attr.idx_rebuild_keep_storage_time;
    knl_scn_t timeout_scn = db_time_scn(session, timeout, 0);
    knl_set_session_scn(session, GS_INVALID_ID64);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_GARBAGE_SEGMENT_ID, GS_INVALID_ID32);

    uint32 op_type;
    knl_seg_desc_t desc;
    knl_scn_t min_scn, del_scn;
    for (;;) {
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            knl_rollback(session, NULL);
            CM_RESTORE_STACK(session->stack);
            GS_LOG_RUN_ERR("[DB] failed to delay clean GARBAGE_SEGMENT");
            return;
        }

        if (cursor->eof) {
            break;
        }

        op_type = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_GARBAGE_SEGMENT_COL_OP_TYPE);
        min_scn = KNL_GET_SCN(&session->kernel->min_scn);
        if (op_type == BTREE_DELAY_DROP_SEGMENT || op_type == BTREE_DELAY_DROP_PART_SEGMENT) {
            del_scn = *(uint64*)CURSOR_COLUMN_DATA(cursor, SYS_GARBAGE_SEGMENT_COL_ORG_SCN);
        } else {
            del_scn = cursor->scn;
        }

        knl_scn_t cur_scn = DB_CURR_SCN(session);
        if (min_scn <= del_scn) {
            if (GS_INVALID_SCN(timeout_scn) || (cur_scn - del_scn) < timeout_scn) {
                cm_spin_lock(&session->kernel->rmon_ctx.mark_mutex, NULL);
                session->kernel->rmon_ctx.delay_clean_segments = GS_TRUE;
                cm_spin_unlock(&session->kernel->rmon_ctx.mark_mutex);
                continue;
            }
        }

        db_convert_segment_desc(cursor, &desc);
        g_segment_proc[desc.op_type](session, &desc);

        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            knl_rollback(session, NULL);
            CM_RESTORE_STACK(session->stack);
            GS_LOG_RUN_ERR("[DB] failed to delay clean GARBAGE_SEGMENT");
            return;
        }
    }

    knl_commit(session);
    CM_RESTORE_STACK(session->stack);

    return;
}

void db_purge_garbage_segment(knl_session_t *session)
{
    knl_cursor_t *cursor = NULL;

    if (DB_IS_READONLY(session)) {
        return;
    }

    CM_SAVE_STACK(session->stack);

    knl_set_session_scn(session, GS_INVALID_ID64);
    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_GARBAGE_SEGMENT_ID, GS_INVALID_ID32);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        GS_LOG_RUN_ERR("[DB] failed to purge system GARBAGE_SEGMENT");
        return;
    }

    while (!cursor->eof) {
        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            GS_LOG_RUN_ERR("[DB] failed to purge system GARBAGE_SEGMENT");
            return;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            GS_LOG_RUN_ERR("[DB] failed to purge system GARBAGE_SEGMENT");
            return;
        }
    }

    knl_commit(session);
    CM_RESTORE_STACK(session->stack);

    return;
}

static status_t db_repair_syscolumns(knl_session_t *session, uint32 table_id, knl_column_t *columns, uint32 new_cols)
{
    uint32 user_id = 0;
    uint32 old_cols = 0;
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_COLUMN_ID, 0);
    index_t *index = (index_t *)cursor->index;
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(&index->desc, &cursor->scan_range.l_key, GS_TYPE_INTEGER, &user_id, sizeof(uint32),
                     IX_COL_SYS_COLUMN_001_USER_ID);
    knl_set_scan_key(&index->desc, &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table_id, sizeof(uint32),
                     IX_COL_SYS_COLUMN_001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_COLUMN_001_ID);
    knl_set_scan_key(&index->desc, &cursor->scan_range.r_key, GS_TYPE_INTEGER, &user_id, sizeof(uint32),
                     IX_COL_SYS_COLUMN_001_USER_ID);
    knl_set_scan_key(&index->desc, &cursor->scan_range.r_key, GS_TYPE_INTEGER, &table_id, sizeof(uint32),
                     IX_COL_SYS_COLUMN_001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_COLUMN_001_ID);
    for (;;) {
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
        if (cursor->eof) {
            break;
        }
        old_cols++;
    }
    if (old_cols >= new_cols) {
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_COLUMN_ID, GS_INVALID_ID32);
    for (uint32 i = old_cols; i < new_cols; i++) {
        db_make_syscolumn_row(session, cursor, columns + i);
        if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
            knl_rollback(session, NULL);
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }
    knl_commit(session);
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t knl_internal_repair_catalog(knl_session_t *session)
{
    knl_commit(session);
    if (db_repair_syscolumns(session, SYS_TABLE_ID, g_sys_table_columns, SYSTABLE_COLS) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (db_repair_syscolumns(session, SYS_COLUMN_ID, g_sys_column_columns, SYSCOLUMN_COLS) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (db_repair_syscolumns(session, SYS_INDEX_ID, g_sys_index_columns, SYSINDEX_COLS) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (db_repair_syscolumns(session, SYS_USER_ID, g_sys_user_columns, SYSUSER_COLS) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}
