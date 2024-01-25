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
 * cse_stats.c
 *
 *
 * IDENTIFICATION
 * src/tse/cse_stats.c
 *
 * -------------------------------------------------------------------------
 */
#include "tse_module.h"
#include "cm_log.h"
#include "cse_stats.h"

#ifndef FN_CURLIB
#define FN_CURLIB '.' /* ./ is used as abbrev for current dir */
#endif

#ifndef FN_LIBCHAR
#define FN_LIBCHAR '/'
#endif

#define NUMBER_DOUBLE 0.00000001
io_record_wait_t g_tse_io_record_event_wait[TSE_FUNC_TYPE_NUMBER];

io_record_event_desc_t g_tse_io_record_event_desc[TSE_FUNC_TYPE_NUMBER] = {
    {"TSE_FUNC_TYPE_OPEN_TABLE", ""},
    {"TSE_FUNC_TYPE_CLOSE_TABLE", ""},
    {"TSE_FUNC_TYPE_CLOSE_SESSION", ""},
    {"TSE_FUNC_TYPE_WRITE_ROW", ""},
    {"TSE_FUNC_TYPE_WRITE_THROUGH_ROW", ""},
    {"TSE_FUNC_TYPE_UPDATE_ROW", ""},
    {"TSE_FUNC_TYPE_DELETE_ROW", ""},
    {"TSE_FUNC_TYPE_RND_INIT", ""},
    {"TSE_FUNC_TYPE_RND_END", ""},
    {"TSE_FUNC_TYPE_RND_NEXT", ""},
    {"TSE_FUNC_TYPE_RND_PREFETCH", ""},
    {"TSE_FUNC_TYPE_SCAN_RECORDS", ""},
    {"TSE_FUNC_TYPE_TRX_COMMIT", ""},
    {"TSE_FUNC_TYPE_TRX_ROLLBACK", ""},
    {"TSE_FUNC_TYPE_TRX_BEGIN", ""},
    {"TSE_FUNC_TYPE_LOCK_TABLE", ""},
    {"TSE_FUNC_TYPE_UNLOCK_TABLE", ""},
    {"TSE_FUNC_TYPE_INDEX_END", ""},
    {"TSE_FUNC_TYPE_SRV_SET_SAVEPOINT", ""},
    {"TSE_FUNC_TYPE_SRV_ROLLBACK_SAVEPOINT", ""},
    {"TSE_FUNC_TYPE_SRV_RELEASE_SAVEPOINT", ""},
    {"TSE_FUNC_TYPE_GENERAL_FETCH", ""},
    {"TSE_FUNC_TYPE_GENERAL_PREFETCH", ""},
    {"TSE_FUNC_TYPE_FREE_CURSORS", ""},
    {"TSE_FUNC_TYPE_GET_INDEX_NAME", ""},
    {"TSE_FUNC_TYPE_INDEX_READ", ""},
    {"TSE_FUNC_TYPE_RND_POS", ""},
    {"TSE_FUNC_TYPE_POSITION", ""},
    {"TSE_FUNC_TYPE_DELETE_ALL_ROWS", ""},
    {"TSE_FUNC_TYPE_GET_CBO_STATS", ""},
    {"TSE_FUNC_TYPE_GET_HUGE_PART_TABLE_CBO_STATS", ""},
    {"TSE_FUNC_TYPE_WRITE_LOB", ""},
    {"TSE_FUNC_TYPE_READ_LOB", ""},
    {"TSE_FUNC_TYPE_CREATE_TABLE", ""},
    {"TSE_FUNC_TYPE_TRUNCATE_TABLE", ""},
    {"TSE_FUNC_TYPE_TRUNCATE_PARTITION", ""},
    {"TSE_FUNC_TYPE_RENAME_TABLE", ""},
    {"TSE_FUNC_TYPE_ALTER_TABLE", ""},
    {"TSE_FUNC_TYPE_GET_SERIAL_VALUE", ""},
    {"TSE_FUNC_TYPE_DROP_TABLE", ""},
    {"TSE_FUNC_TYPE_EXCUTE_MYSQL_DDL_SQL", ""},
    {"TSE_FUNC_TYPE_BROADCAST_REWRITE_SQL", ""},
    {"TSE_FUNC_TYPE_CREATE_TABLESPACE", ""},
    {"TSE_FUNC_TYPE_ALTER_TABLESPACE", ""},
    {"TSE_FUNC_TYPE_DROP_TABLESPACE", ""},
    {"TSE_FUNC_TYPE_BULK_INSERT", ""},
    {"TSE_FUNC_TYPE_ANALYZE", ""},
    {"TSE_FUNC_TYPE_GET_MAX_SESSIONS", ""},
    {"TSE_FUNC_LOCK_INSTANCE", ""},
    {"TSE_FUNC_UNLOCK_INSTANCE", ""},
    {"TSE_FUNC_CHECK_TABLE_EXIST", ""},
    {"TSE_FUNC_SEARCH_METADATA_SWITCH", ""},
    {"TSE_FUNC_PRE_CREATE_DB", ""},
    {"TSE_FUNC_TYPE_DROP_TABLESPACE_AND_USER", ""},
    {"TSE_FUNC_DROP_DB_PRE_CHECK", ""},
    {"TSE_FUNC_KILL_CONNECTION", ""},
    {"TSE_FUNC_TYPE_INVALIDATE_OBJECT", ""},
    {"TSE_FUNC_TYPE_RECORD_SQL", ""},
    {"TSE_FUNC_TYPE_REGISTER_INSTANCE", ""},
    {"TSE_FUNC_TYPE_WAIT_CONNETOR_STARTUPED", ""},
    {"TSE_FUNC_TYPE_MYSQL_EXECUTE_UPDATE", ""},
    {"TSE_FUNC_TYPE_CLOSE_MYSQL_CONNECTION", ""},
    {"TSE_FUNC_TYPE_LOCK_TABLES", ""},
    {"TSE_FUNC_TYPE_UNLOCK_TABLES", ""},
    {"TSE_FUNC_TYPE_EXECUTE_REWRITE_OPEN_CONN", ""},
    {"TSE_FUNC_TYPE_INVALIDATE_OBJECTS", ""},
};

void tse_record_io_state_reset(void)
{
    status_t ret = CT_SUCCESS;
    io_record_wait_t *event_wait;
    for (uint32 i = 0; i < TSE_FUNC_TYPE_NUMBER; i++) {
        event_wait = &g_tse_io_record_event_wait[i];
        ret = memset_s(&(event_wait->detail), sizeof(io_record_detail_t), 0, sizeof(io_record_detail_t));
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[io record] init tse io record failed, event %u", i);
        }
        event_wait->detail.min_time = CT_INVALID_ID64;
    }
}
