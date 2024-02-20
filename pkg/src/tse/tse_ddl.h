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
 * tse_ddl.h
 *
 *
 * IDENTIFICATION
 * src/tse/tse_ddl.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __TSE_DDL_H__
#define __TSE_DDL_H__

#include "cm_defs.h"
#include "srv_session.h"
#include "ctsql_stmt.h"
#include "protobuf/tc_db.pb-c.h"
#include "knl_dc.h"

#define DATA_FILE_DEFALUT_EXTEND_SIZE SIZE_M(16)
#define PARTITION_MIN_CNT 2
#define TABLESPACE_PATH_MAX_LEN 256
#define EMPTY_DATABASE ""
#define INVALID_PART_ID (uint32)0xFFFFFFFF
#define TSE_DROP_NO_CHECK_FK_FOR_CANTIAN_AND_BROADCAST 0x01000000 // value need equal to "ha_tse_ddl.h" file defined

#define DDL_ATOMIC_TABLE_LOCKED 2

#define TSE_TMP_TABLE 1
#define TSE_INTERNAL_TMP_TABLE 2
#define TSE_TABLE_CONTAINS_VIRCOL 4

#define FILL_BROADCAST_REQ(broadcast_req, _db_name, _sql_str, _user_name, _user_ip, _mysql_inst_id, _sql_command) \
    do {                                                                                                          \
        (broadcast_req).mysql_inst_id = (_mysql_inst_id);                                                         \
        (broadcast_req).sql_command = (_sql_command);                                                             \
        int cpy_ret = strcpy_s((broadcast_req).sql_str, MAX_DDL_SQL_LEN, (_sql_str));                             \
        knl_securec_check(cpy_ret);                                                                               \
        if (!CM_IS_EMPTY_STR((char *)(_db_name))) {                                                               \
            cpy_ret = strcpy_s((broadcast_req).db_name, SMALL_RECORD_SIZE, (_db_name));                           \
            knl_securec_check(cpy_ret);                                                                           \
        }                                                                                                         \
        cpy_ret = strcpy_s((broadcast_req).user_name, SMALL_RECORD_SIZE, (_user_name));                           \
        knl_securec_check(cpy_ret);                                                                               \
        cpy_ret = strcpy_s((broadcast_req).user_ip, SMALL_RECORD_SIZE, (_user_ip));                               \
        knl_securec_check(cpy_ret);                                                                               \
        (broadcast_req).options = 0;                                                                              \
    } while (0)

typedef enum sql_command_filter_op {
    SQLCOM_SELECT = 0,
    SQLCOM_CREATE_INDEX = 2,
    SQLCOM_ALTER_TABLE = 3,
    SQLCOM_DROP_TABLE = 9,
    SQLCOM_DROP_INDEX = 10,
    SQLCOM_SHOW_DATABASES = 11,
    SQLCOM_SHOW_TABLES,
    SQLCOM_SHOW_FIELDS,
    SQLCOM_SHOW_KEYS,
    SQLCOM_SHOW_VARIABLES,
    SQLCOM_SHOW_STATUS,
    SQLCOM_SHOW_ENGINE_LOGS,
    SQLCOM_SHOW_ENGINE_STATUS,
    SQLCOM_SHOW_ENGINE_MUTEX,
    SQLCOM_SHOW_PROCESSLIST,
    SQLCOM_SHOW_MASTER_STAT,
    SQLCOM_SHOW_SLAVE_STAT,
    SQLCOM_SHOW_GRANTS,
    SQLCOM_SHOW_CREATE,
    SQLCOM_SHOW_CHARSETS,
    SQLCOM_SHOW_COLLATIONS,
    SQLCOM_SHOW_CREATE_DB,
    SQLCOM_SHOW_TABLE_STATUS,
    SQLCOM_SHOW_TRIGGERS = 29,
    SQLCOM_SET_OPTION = 31,
    SQLCOM_CREATE_DB = 36,
    SQLCOM_DROP_DB = 37,
    SQLCOM_RENAME_TABLE = 64,
    SQLCOM_SHOW_BINLOGS = 68,
    SQLCOM_SHOW_OPEN_TABLES = 69,
    SQLCOM_SHOW_SLAVE_HOSTS = 73,
    SQLCOM_SHOW_BINLOG_EVENTS = 76,
    SQLCOM_SHOW_WARNS = 78,
    SQLCOM_SHOW_ERRORS = 80,
    SQLCOM_SHOW_STORAGE_ENGINES,
    SQLCOM_SHOW_PRIVILEGES,
    SQLCOM_SHOW_CREATE_PROC = 95,
    SQLCOM_SHOW_CREATE_FUNC,
    SQLCOM_SHOW_STATUS_PROC,
    SQLCOM_SHOW_STATUS_FUNC,
    SQLCOM_SHOW_PROC_CODE = 112,
    SQLCOM_SHOW_FUNC_CODE,
    SQLCOM_SHOW_PLUGINS = 118,
    SQLCOM_SHOW_CREATE_EVENT = 125,
    SQLCOM_SHOW_EVENTS,
    SQLCOM_SHOW_CREATE_TRIGGER,
    SQLCOM_SHOW_PROFILE,
    SQLCOM_SHOW_PROFILES,
    SQLCOM_SHOW_RELAYLOG_EVENTS = 132,
    SQLCOM_SHOW_CREATE_USER = 136,
    SQLCOM_LOCK_INSTANCE = 154,
    SQLCOM_UNLOCK_INSTANCE = 155,
    SQLCOM_END = 159,
} sql_command_filter_op_t;

void unlock_user_ddl(session_t *session);
int tse_close_mysql_connection(tianchi_handler_t *tch);
ct_type_t get_ct_type_from_tse_ddl_type(enum_tse_ddl_field_types tse_type);
void tse_ddl_clear_stmt(sql_stmt_t *stmt);
status_t tse_sql_parse_hash_partition(sql_stmt_t *stmt, knl_part_def_t *part_def);
status_t tse_sql_subpart_parse_partition(sql_stmt_t *stmt, knl_part_def_t *part_def, knl_part_obj_def_t *obj_def);
int fill_alter_part_key(knl_dictionary_t dc, knl_altable_def_t *def, knl_column_t *knl_column);
int fill_alter_subpart_key(knl_dictionary_t dc, knl_altable_def_t *def, knl_column_t *knl_column);
status_t init_ddl_session(session_t *session);
status_t tse_ddl_lock_table(session_t *session, knl_dictionary_t *dc, dc_user_t *user, bool32 is_alter_copy);
void tse_ddl_unlock_table(knl_session_t *knl_session, bool unlock_tables);
bool32 tse_command_type_read(sql_command_filter_op_t cmd);
int tse_ddl_execute_and_broadcast(tianchi_handler_t *tch, tse_ddl_broadcast_request *broadcast_req,
    bool allow_fail, knl_session_t *knl_session);
int tse_update_mysql_ddcache_and_broadcast(char *sql_str, knl_session_t *knl_session);
int tse_invalidate_all_ddcache_and_broadcast(knl_session_t *knl_sess);
int tse_query_cluster_role(bool *is_slave, bool *cantian_cluster_ready);
#endif //__TSE_DDL_H__
