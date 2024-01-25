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
 * sharding_defs.h
 *
 *
 * IDENTIFICATION
 * src/kernel/include/sharding_defs.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_SHARDING_DEFS_H__
#define __KNL_SHARDING_DEFS_H__

#include "knl_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef Z_SHARDING
typedef enum {
    distribute_none = 0,
    distribute_hash = 1,
    distribute_range = 2,
    distribute_list = 3,
    distribute_replication = 4,
    distribute_hash_basic = 5
} distribute_type_t;

typedef enum en_dist_ddl_loginfo_column {
    DIST_DDL_LOGINFO_COL_DDL_ID = 0,
    DIST_DDL_LOGINFO_COL_GROUP_ID = 1,
    DIST_DDL_LOGINFO_COL_NODE_ID = 2,
    DIST_DDL_LOGINFO_COL_DDL = 3,
    DIST_DDL_LOGINFO_COL_CREATE_TIME = 4,
    DIST_DDL_LOGINFO_COL_EXPIRED_TIME = 5,
    DIST_DDL_LOGINFO_COL_RETRY_TIMES = 6,
    DIST_DDL_LOGINFO_COL_STATUS = 7,

    DIST_DDL_LOGINFO_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} dist_ddl_loginfo_column_t;

typedef enum en_sys_consis_hash_strategy_column {
    SYS_CONSIS_HASH_STRATEGY_COL_SLICE_COUNT = 0,
    SYS_CONSIS_HASH_STRATEGY_COL_GROUP_COUNT = 1,
    SYS_CONSIS_HASH_STRATEGY_COL_BUCKETS = 2,
    SYS_CONSIS_HASH_STRATEGY_COLUMN_COUNT,
} sys_consis_hash_strategy_column_t;
#define IX_SYS_CONSISTENT_HASH_STRATEGY001_ID 0
#define IX_COL_SYS_CONSIS_HASH_STRATEGY001_SLICE_COUNT    0
#define IX_COL_SYS_CONSIS_HASH_STRATEGY001_GROUP_COUNT    1

#define BUCKETDATALEN 16384
#define FROZEN_INIT_STATUS 0
#define FROZEN_WORKING_STATUS 1

typedef struct {
    uint32 value_count;
    union {
        uint32 u32_val;     // for hash;
        variant_t var_val;  // for range the only one value of the group;
        variant_t *values;  // for list array of values decode from value expr;
    };
    uint8 group_id;
} routing_group_t;

typedef struct {
    uint16 pos;
    text_t name;
} distribute_column_t;

typedef struct st_dist_expr_columns_t {
    uint16 column_count;
    distribute_column_t columns[CT_DISTRIBUTE_COLUMN_COUNT];
} dist_expr_columns_t;

typedef struct st_dist_info_buf_t {
    unsigned char *buf;
    uint16 capacity;
    uint16 offset;
} dist_info_buf_t;

typedef struct {
    distribute_type_t type;
    uint16 column_count;
    distribute_column_t *columns;  // array of distribute columns;
    uint32 group_count;
    routing_group_t *groups;  // array of group info;
    uint8 *buckets;
    uint32 expr_count;
    uint32 frozen_status;
    void **exprs;  // array of exprs' pointer;
} routing_info_t;

typedef struct {
    text_t name;
    galist_t columns;

    uint32 distribute_type;
    galist_t distribute_groups;
    galist_t distribute_exprs;
    galist_t distribute_values;  // item of galist_t is values of per group (child-list).
    text_t distribute_info;      // distribute info
    binary_t distribute_data;
    binary_t distribute_buckets;
} knl_distribute_rule_def_t;

typedef struct {
    uint32 uid;
    uint32 id;  // rule id
    char name[CT_NAME_BUFFER_SIZE];
    knl_scn_t org_scn;  // original scn
    knl_scn_t chg_scn;  // scn when changed by DDL(alter)
    binary_t col_data;
    binary_t dist_data;
    binary_t buckets;
} knl_distribute_rule_t;

typedef enum {
    REFUSESQL_NONE = 0,
    REFUSESQL_SELECT = 1,
} refusesql_level_t;

typedef enum {
    REFUSETRANS_NONE = 0,
    REFUSETRANS_DIST_TAB = 1,  // refuse trans on distribute table
    REFUSETRANS_CEIL,          // must be last parameter
} refusetrans_level_t;

typedef struct st_knl_node_def {
    uint32 node_id;
    text_t name;
    text_t type; /* added for z_sharding, need to rename */
    text_t host;
    int32 port;
    uint32 group_id;
    uint8 is_primary;
    uint32 weight;                           // default 0, [0,100]
    char username[CT_NAME_BUFFER_SIZE];      // username
    SENSI_INFO char password[CT_PASSWORD_BUFFER_SIZE];  // encrypt pwd
    uint32 min_conn_num;                     // default 10 , [1,4000]
    uint32 max_conn_num;                     // default 200 , [1,4000]
} knl_node_def_t;

typedef struct st_knl_distributed_trans_def {
    text_t global_tran_id;
    timestamp_t trans_prepare_time;
    uint32 trx_status;
    uint32 need_clean;
} knl_distributed_trans_def_t;

typedef enum st_dist_ddl_log_status {
    DIST_DDL_LOG_INIT = 0,
    DIST_DDL_LOG_EXE,
    DIST_DDL_LOG_EXE_ERROR,
    DIST_DDL_LOG_RETRY,
    DIST_DDL_LOG_RETRY_ERROR,
} dist_ddl_log_status_t;

typedef struct st_knl_consis_hash_strategy {
    uint32 slice_cnt;
    uint32 group_cnt;
    binary_t buckets;
} knl_consis_hash_strategy_t;

routing_info_t *knl_get_table_routing_info(knl_handle_t dc_entity);
status_t knl_get_consis_hash_buckets(knl_handle_t handle, knl_consis_hash_strategy_t *strategy, bool32 *is_found);

#ifdef Z_SHARDING
typedef status_t(*knl_parse_distribute_info_t)(void *entity, void *distribute_info);
typedef status_t(*knl_parse_distribute_bkts_t)(knl_handle_t handle, void *entity, void *distribute_info);
typedef status_t(*knl_parse_distribute_from_text_t)(knl_handle_t handle, knl_handle_t entity, text_t *dist_text);
#endif

#endif
#ifdef __cplusplus
}
#endif

#endif
