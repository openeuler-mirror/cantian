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
 * src/ctc/cse_stats.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctc_module.h"
#include "cm_log.h"
#include "cse_stats.h"

#ifndef FN_CURLIB
#define FN_CURLIB '.' /* ./ is used as abbrev for current dir */
#endif

#ifndef FN_LIBCHAR
#define FN_LIBCHAR '/'
#endif

#define NUMBER_DOUBLE 0.00000001
io_record_wait_t g_ctc_io_record_event_wait[CTC_FUNC_TYPE_NUMBER][EVENT_TRACKING_GROUP];

io_record_event_desc_t g_ctc_io_record_event_desc[CTC_FUNC_TYPE_NUMBER] = {
    {"CTC_FUNC_TYPE_OPEN_TABLE", ""},
    {"CTC_FUNC_TYPE_CLOSE_TABLE", ""},
    {"CTC_FUNC_TYPE_CLOSE_SESSION", ""},
    {"CTC_FUNC_TYPE_WRITE_ROW", ""},
    {"CTC_FUNC_TYPE_WRITE_UPDATE_JOB", ""},
    {"CTC_FUNC_TYPE_UPDATE_ROW", ""},
    {"CTC_FUNC_TYPE_DELETE_ROW", ""},
    {"CTC_FUNC_TYPE_RND_INIT", ""},
    {"CTC_FUNC_TYPE_RND_END", ""},
    {"CTC_FUNC_TYPE_RND_NEXT", ""},
    {"CTC_FUNC_TYPE_RND_PREFETCH", ""},
    {"CTC_FUNC_TYPE_SCAN_RECORDS", ""},
    {"CTC_FUNC_TYPE_TRX_COMMIT", ""},
    {"CTC_FUNC_TYPE_TRX_ROLLBACK", ""},
    {"CTC_FUNC_TYPE_TRX_BEGIN", ""},
    {"CTC_FUNC_TYPE_LOCK_TABLE", ""},
    {"CTC_FUNC_TYPE_UNLOCK_TABLE", ""},
    {"CTC_FUNC_TYPE_INDEX_END", ""},
    {"CTC_FUNC_TYPE_SRV_SET_SAVEPOINT", ""},
    {"CTC_FUNC_TYPE_SRV_ROLLBACK_SAVEPOINT", ""},
    {"CTC_FUNC_TYPE_SRV_RELEASE_SAVEPOINT", ""},
    {"CTC_FUNC_TYPE_GENERAL_FETCH", ""},
    {"CTC_FUNC_TYPE_GENERAL_PREFETCH", ""},
    {"CTC_FUNC_TYPE_FREE_CURSORS", ""},
    {"CTC_FUNC_TYPE_GET_INDEX_NAME", ""},
    {"CTC_FUNC_TYPE_INDEX_READ", ""},
    {"CTC_FUNC_TYPE_RND_POS", ""},
    {"CTC_FUNC_TYPE_POSITION", ""},
    {"CTC_FUNC_TYPE_DELETE_ALL_ROWS", ""},
    {"CTC_FUNC_TYPE_GET_CBO_STATS", ""},
    {"CTC_FUNC_TYPE_WRITE_LOB", ""},
    {"CTC_FUNC_TYPE_READ_LOB", ""},
    {"CTC_FUNC_TYPE_CREATE_TABLE", ""},
    {"CTC_FUNC_TYPE_TRUNCATE_TABLE", ""},
    {"CTC_FUNC_TYPE_TRUNCATE_PARTITION", ""},
    {"CTC_FUNC_TYPE_RENAME_TABLE", ""},
    {"CTC_FUNC_TYPE_ALTER_TABLE", ""},
    {"CTC_FUNC_TYPE_GET_SERIAL_VALUE", ""},
    {"CTC_FUNC_TYPE_DROP_TABLE", ""},
    {"CTC_FUNC_TYPE_EXCUTE_MYSQL_DDL_SQL", ""},
    {"CTC_FUNC_TYPE_SET_OPT", ""},
    {"CTC_FUNC_TYPE_BROADCAST_REWRITE_SQL", ""},
    {"CTC_FUNC_TYPE_CREATE_TABLESPACE", ""},
    {"CTC_FUNC_TYPE_ALTER_TABLESPACE", ""},
    {"CTC_FUNC_TYPE_DROP_TABLESPACE", ""},
    {"CTC_FUNC_TYPE_BULK_INSERT", ""},
    {"CTC_FUNC_TYPE_ANALYZE", ""},
    {"CTC_FUNC_TYPE_GET_MAX_SESSIONS", ""},
    {"CTC_FUNC_LOCK_INSTANCE", ""},
    {"CTC_FUNC_UNLOCK_INSTANCE", ""},
    {"CTC_FUNC_INIT_MYSQL_LIB", ""},
    {"CTC_FUNC_CHECK_TABLE_EXIST", ""},
    {"CTC_FUNC_SEARCH_METADATA_SWITCH", ""},
    {"CTC_FUNC_QUERY_SHM_USAGE", ""},
    {"CTC_FUNC_QUERY_CLUSTER_ROLE", ""},
    {"CTC_FUNC_SET_CLUSTER_ROLE_BY_CANTIAN", ""},
    {"CTC_FUNC_PRE_CREATE_DB", ""},
    {"CTC_FUNC_TYPE_DROP_TABLESPACE_AND_USER", ""},
    {"CTC_FUNC_DROP_DB_PRE_CHECK", ""},
    {"CTC_FUNC_KILL_CONNECTION", ""},
    {"CTC_FUNC_TYPE_INVALIDATE_OBJECT", ""},
    {"CTC_FUNC_TYPE_RECORD_SQL", ""},
    {"CTC_FUNC_TYPE_GET_PARAL_SCHEDULE", ""},
    {"CTC_FUNC_TYPE_GET_INDEX_PARAL_SCHEDULE", ""},
    {"CTC_FUNC_TYPE_PQ_INDEX_READ", ""},
    {"CTC_FUNC_TYPE_PQ_SET_CURSOR_RANGE", ""},
    {"CTC_FUNC_TYPE_REGISTER_INSTANCE", ""},
    {"CTC_FUNC_QUERY_SHM_FILE_NUM", ""},
    {"CTC_FUNC_TYPE_WAIT_CONNETOR_STARTUPED", ""},
    {"CTC_FUNC_TYPE_MYSQL_EXECUTE_UPDATE", ""},
    {"CTC_FUNC_TYPE_MYSQL_EXECUTE_SET_OPT", ""},
    {"CTC_FUNC_TYPE_CLOSE_MYSQL_CONNECTION", ""},
    {"CTC_FUNC_TYPE_LOCK_TABLES", ""},
    {"CTC_FUNC_TYPE_UNLOCK_TABLES", ""},
    {"CTC_FUNC_TYPE_EXECUTE_REWRITE_OPEN_CONN", ""},
    {"CTC_FUNC_TYPE_INVALIDATE_OBJECTS", ""},
    {"CTC_FUNC_TYPE_INVALIDATE_ALL_OBJECTS", ""},
    {"CTC_FUNC_TYPE_UPDATE_DDCACHE", ""},
};

status_t ctc_record_io_state_reset(void)
{
    status_t ret = CT_SUCCESS;
    io_record_wait_t *event_wait;
    for (uint32 i = 0; i < CTC_FUNC_TYPE_NUMBER; i++) {
        for (uint32 hash_id = 0; hash_id < EVENT_TRACKING_GROUP; hash_id++) {
            event_wait = &g_ctc_io_record_event_wait[i][hash_id];
            ret = memset_s(&(event_wait->detail), sizeof(io_record_detail_t), 0, sizeof(io_record_detail_t));
            if (ret != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[io record] init tse io record failed, event %u", i);
                return ret;
            }
        }
    }
    return ret;
}
