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
 * ctc_srv.h
 *
 *
 * IDENTIFICATION
 * src/ctc/ctc_srv.h
 *
 * -------------------------------------------------------------------------
 */

/* * @file storage/ctc/ctc_srv.h
The server side adapter for txn API and kernel API. This should be transparent ideally.
Logics like init, mgmt, auth, buffering, queueing, etc should be involved within this module.

Expected call trace:
3rdParty RPC module -> (here) ctc server -> cantian kernel intf.
*/

#ifndef __CTC_SRV_H__
#define __CTC_SRV_H__

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef EXTER_ATTACK
#define EXTER_ATTACK
#endif

#ifndef SENSI_INFO
#define SENSI_INFO
#endif
#define STATS_HISTGRAM_MAX_SIZE 254
#define SMALL_RECORD_SIZE 128  // 表名、库名等长度不会特别大，取128
#define ERROR_MESSAGE_LEN 512
#define MAX_DDL_SQL_LEN_CONTEXT (63488)  //  62kb, 预留2kb
#define MAX_DDL_SQL_LEN (MAX_DDL_SQL_LEN_CONTEXT + 30)  // ddl sql语句的长度 不能超过64kb, 超过了会报错
#define DD_BROADCAST_RECORD_LENGTH (3072)
#define LOCK_TABLE_SQL_FMT_LEN 20
#define MAX_LOCK_TABLE_NAME (MAX_DDL_SQL_LEN - LOCK_TABLE_SQL_FMT_LEN)
#define MAX_KEY_COLUMNS (uint32_t)16  // cantian限制复合索引最大支持字段不超过16
#define FUNC_TEXT_MAX_LEN 128
#define CTC_IDENTIFIER_MAX_LEN 64
#define CANTIAN_DOWN_MASK 0xFFFF  // 参天节点故障
#define MAX_DDL_ERROR_MSG_LEN 1024
#define PART_CURSOR_NUM 8192
#define MAX_SUBPART_NUM 4096    // 参天限制每个一级分区下子分区不超过4096
#define CTC_BUF_LEN (64 * 1024)
#define BIG_RECORD_SIZE CTC_BUF_LEN  // 采用最大长度
#define MAX_RECORD_SIZE (1 * CTC_BUF_LEN)
#define CTC_MAX_KEY_NAME_LENGTH 64
#define CTC_SQL_START_INTERNAL_SAVEPOINT "CTC4CANTIAN_SYS_SV"
#define IS_CTC_PART(part_id) ((part_id) < (PART_CURSOR_NUM))
#define MAX_BULK_INSERT_PART_ROWS 128
#define SESSION_CURSOR_NUM (8192 * 2)
#define MAX_MESSAGE_SIZE 4194304  // 共享内存最大可申请空间大小

// for broadcast_req.options
#define CTC_SET_VARIABLE_PERSIST (0x1 << 8)
#define CTC_SET_VARIABLE_PERSIST_ONLY (0x1 << 7)
#define CTC_OPEN_NO_CHECK_FK_FOR_CURRENT_SQL (0x1 << 6)
#define CTC_CURRENT_SQL_CONTAIN_PLAINTEXT_PASSWORD (0x1 << 5)
#define CTC_NOT_NEED_CANTIAN_EXECUTE (0x1 << 4)
#define CTC_SET_VARIABLE_TO_DEFAULT (0x1 << 3)
#define CTC_SET_VARIABLE_TO_NULL (0x1 << 2)
#define CTC_SET_VARIABLE_WITH_SUBSELECT (0x1 << 0)

#define CTC_AUTOINC_OLD_STYLE_LOCKING 0
#define CTC_AUTOINC_NEW_STYLE_LOCKING 1
#define CTC_AUTOINC_NO_LOCKING 2

typedef int64 date_t;

typedef struct {
    uint32_t inst_id; // instance id, thd_id alone is not sufficient to uniquely identify a ctc session
    uint32_t thd_id;
    uint32_t part_id;
    uint32_t subpart_id;
    int64_t query_id;
    uint64_t sess_addr;
    uint64_t ctx_addr;
    uint64_t cursor_addr;
    uint64_t pre_sess_addr;
    int32_t cursor_ref;
    uint16_t bind_core;
    uint8_t sql_command;
    uint8_t sql_stat_start;
    uint8_t change_data_capture;
    bool cursor_valid;
    bool is_broadcast;
    bool read_only_in_ct;
    void* msg_buf;
} ctc_handler_t;

typedef struct {
    char db_name[SMALL_RECORD_SIZE];
    char table_name[SMALL_RECORD_SIZE];
    char user_name[SMALL_RECORD_SIZE];
    char user_ip[SMALL_RECORD_SIZE];
    int32_t sql_type;
    int32_t mdl_namespace;
} ctc_lock_table_info;

typedef struct cache_st_variant {
    union {
        int v_int;
        unsigned int v_uint32;
        unsigned int v_bool;
        long long v_bigint;
        unsigned long long v_ubigint;
        double v_real;
        date_t v_date;
        char *v_str;
    };
} cache_variant_t;

typedef enum {
    FREQUENCY_HIST = 0,
    HEIGHT_BALANCED_HIST = 1,
} ctc_cbo_hist_type_t;

typedef struct {
    cache_variant_t ep_value;
    int ep_number;
} ctc_cbo_column_hist_t;

typedef struct {
    uint32_t num_null;
    double density;
    ctc_cbo_hist_type_t hist_type;
    uint32_t hist_count;
    ctc_cbo_column_hist_t column_hist[STATS_HISTGRAM_MAX_SIZE];  // Column histogram statistics (array)
    cache_variant_t low_value;
    cache_variant_t high_value;
} ctc_cbo_stats_column_t;

/**
 * cache info that can expand this struct
 * if need more cbo stats cache
 */
typedef struct {
    uint32_t estimate_rows;
    ctc_cbo_stats_column_t *columns;
} ctc_cbo_stats_table_t;

/*
 * statistics information that mysql optimizer need
 * expand this struct if need more cbo stats
 */
typedef struct {
    uint32_t part_cnt;
    uint32_t msg_len;
    uint32_t key_len;
    bool is_updated;
    uint32_t records;
    uint32_t *ndv_keys;
    uint32_t num_str_cols;
    bool *col_type;
    ctc_cbo_stats_table_t *ctc_cbo_stats_table;
} ctc_cbo_stats_t;
#pragma pack()

typedef struct {
    char job_name_str[SMALL_RECORD_SIZE];
    uint32_t job_name_len;
    char user_str[SMALL_RECORD_SIZE];
    uint32_t user_len;
    bool switch_on;
} update_job_info;

typedef struct {
    char error_msg[MAX_DDL_ERROR_MSG_LEN];
    char user_name[SMALL_RECORD_SIZE];
    char user_ip[SMALL_RECORD_SIZE];
    int32_t error_code;
    uint32_t msg_len;
    ctc_handler_t tch;
    uint32_t mysql_inst_id;
    bool is_alter_copy;
    uint32_t table_flags;
} ddl_ctrl_t;

typedef struct {
    int isolation_level;
    uint32_t autocommit;
    uint32_t lock_wait_timeout;
    bool use_exclusive_lock;
} ctc_trx_context_t;

typedef struct {
    char db_name[SMALL_RECORD_SIZE];
    char sql_str[MAX_DDL_SQL_LEN];
    char user_name[SMALL_RECORD_SIZE];
    char user_ip[SMALL_RECORD_SIZE];
    uint32_t mysql_inst_id;
    int err_code;
    uint8_t sql_command;
    uint32_t options;
    char err_msg[ERROR_MESSAGE_LEN];
} ctc_ddl_broadcast_request;

typedef struct {
    char base_name[SMALL_RECORD_SIZE];
    char var_name[SMALL_RECORD_SIZE];
    char var_value[MAX_DDL_SQL_LEN];
    uint32_t options;
    bool var_is_int;
} set_opt_info_t;

typedef struct {
    set_opt_info_t *set_opt_info;
    uint32_t mysql_inst_id;
    uint32_t opt_num;
    int err_code;
    char err_msg[ERROR_MESSAGE_LEN];
} ctc_set_opt_request;

typedef struct {
    uint8_t type;
    char first[SMALL_RECORD_SIZE];
    char second[SMALL_RECORD_SIZE];
} invalidate_obj_entry_t;
 
typedef struct {
    char buff[DD_BROADCAST_RECORD_LENGTH];
    uint32_t buff_len;
    uint32_t mysql_inst_id;
    bool is_dcl;
    int err_code;
} ctc_invalidate_broadcast_request;

typedef struct {
    bool is_key_null;        // 该列数据是否为null
    uint8_t *left_key;       // 指向索引查询条件的左值
    uint8_t *right_key;      // 指向索引查询条件的右值
    uint32_t left_key_len;   // 左值的数据长度
    uint32_t right_key_len;  // 右值的数据长度
} key_info_t;

typedef struct {
    uint8_t *record;
    uint16_t record_len;
    uint16_t *offsets;
    uint16_t *lens;
} record_info_t;

typedef union {
    struct {
        uint32_t nullable : 1;           // 是否允许为空(1允许为空 0不允许)
        uint32_t primary : 1;            // if it is a primary key (主键)
        uint32_t unique : 1;             // 是否唯一
        uint32_t is_serial : 1;          // 自增
        uint32_t is_check : 1;           // 检查列(取值范围)约束
        uint32_t is_ref : 1;             // 指定外键 参考sql_parse_column_ref
        uint32_t is_default : 1;         // 是否有默认值 通过is_default_null default_text来设置默认值
        uint32_t is_update_default : 1;  // sql_parse_column_default
        uint32_t is_comment : 1;         // 是否有注释  sql_parse_column_comment 通过 column->comment 存储注释
        uint32_t is_collate : 1;         // sql_parse_collate 字符串排序用的 跟字符集有关系
        uint32_t has_null : 1;           // not null sql_parse_column_not_null
        uint32_t has_quote : 1;          // if column name wrapped with double quotation 如果列名用双引号括起来
        uint32_t is_dummy : 1;           // if it is a dummy column for index  目前在cantian代码中暂未使用
        uint32_t is_default_null   : 1;  // empty string treat as null or ''
        uint32_t isKey   : 1;            // key关键字
        uint32_t is_default_func   : 1;  // if default value is generated by mysql functions
        uint32_t is_curr_timestamp : 1;  // if default value is current_timestamp
        uint32_t unused_ops : 15;
    };
    uint32_t is_option_set;
} ctc_column_option_set_bit;

typedef enum {
    EXP_CURSOR_ACTION_SELECT = 0,
    EXP_CURSOR_ACTION_UPDATE = 1,
    EXP_CURSOR_ACTION_DELETE = 2,
    EXP_CURSOR_ACTION_INDEX_ONLY = 3,  // covering index scan
} expected_cursor_action_t;

typedef struct {
    bool sorted;
    bool need_init;
    expected_cursor_action_t action;
    uint16_t find_flag;
    uint16_t active_index;
    char index_name[CTC_MAX_KEY_NAME_LENGTH + 1];        // 索引名
    uint16_t key_num;                      // 查询条件覆盖多少列
    key_info_t key_info[MAX_KEY_COLUMNS];  // 索引查询条件数组
    bool index_skip_scan;
} index_key_info_t;

enum CTC_FUNC_TYPE {
    CTC_FUNC_TYPE_OPEN_TABLE = 0,
    CTC_FUNC_TYPE_CLOSE_TABLE,
    CTC_FUNC_TYPE_CLOSE_SESSION,
    CTC_FUNC_TYPE_WRITE_ROW,
    CTC_FUNC_TYPE_UPDATE_JOB,
    CTC_FUNC_TYPE_UPDATE_ROW,
    CTC_FUNC_TYPE_DELETE_ROW,
    CTC_FUNC_TYPE_UPDATE_SAMPLE_SIZE,
    CTC_FUNC_TYPE_GET_SAMPLE_SIZE,
    CTC_FUNC_TYPE_RND_INIT,
    CTC_FUNC_TYPE_RND_END,
    CTC_FUNC_TYPE_RND_NEXT,
    CTC_FUNC_TYPE_RND_PREFETCH,
    CTC_FUNC_TYPE_SCAN_RECORDS,
    CTC_FUNC_TYPE_TRX_COMMIT,
    CTC_FUNC_TYPE_TRX_ROLLBACK,
    CTC_FUNC_TYPE_TRX_BEGIN,
    CTC_FUNC_TYPE_LOCK_TABLE,
    CTC_FUNC_TYPE_UNLOCK_TABLE,
    CTC_FUNC_TYPE_INDEX_END,
    CTC_FUNC_TYPE_SRV_SET_SAVEPOINT,
    CTC_FUNC_TYPE_SRV_ROLLBACK_SAVEPOINT,
    CTC_FUNC_TYPE_SRV_RELEASE_SAVEPOINT,
    CTC_FUNC_TYPE_GENERAL_FETCH,
    CTC_FUNC_TYPE_GENERAL_PREFETCH,
    CTC_FUNC_TYPE_FREE_CURSORS,
    CTC_FUNC_TYPE_GET_INDEX_NAME,
    CTC_FUNC_TYPE_INDEX_READ,
    CTC_FUNC_TYPE_RND_POS,
    CTC_FUNC_TYPE_POSITION,
    CTC_FUNC_TYPE_DELETE_ALL_ROWS,
    CTC_FUNC_TYPE_GET_CBO_STATS,
    CTC_FUNC_TYPE_WRITE_LOB,
    CTC_FUNC_TYPE_READ_LOB,
    CTC_FUNC_TYPE_CREATE_TABLE,
    CTC_FUNC_TYPE_TRUNCATE_TABLE,
    CTC_FUNC_TYPE_TRUNCATE_PARTITION,
    CTC_FUNC_TYPE_RENAME_TABLE,
    CTC_FUNC_TYPE_ALTER_TABLE,
    CTC_FUNC_TYPE_GET_SERIAL_VALUE,
    CTC_FUNC_TYPE_DROP_TABLE,
    CTC_FUNC_TYPE_EXCUTE_MYSQL_DDL_SQL,
    CTC_FUNC_TYPE_SET_OPT,
    CTC_FUNC_TYPE_BROADCAST_REWRITE_SQL,
    CTC_FUNC_TYPE_CREATE_TABLESPACE,
    CTC_FUNC_TYPE_ALTER_TABLESPACE,
    CTC_FUNC_TYPE_DROP_TABLESPACE,
    CTC_FUNC_TYPE_BULK_INSERT,
    CTC_FUNC_TYPE_ANALYZE,
    CTC_FUNC_TYPE_GET_MAX_SESSIONS,
    CTC_FUNC_LOCK_INSTANCE,
    CTC_FUNC_UNLOCK_INSTANCE,
    CTC_FUNC_CHECK_TABLE_EXIST,
    CTC_FUNC_SEARCH_METADATA_SWITCH,
    CTC_FUNC_QUERY_SHM_USAGE,
    CTC_FUNC_QUERY_CLUSTER_ROLE,
    CTC_FUNC_SET_CLUSTER_ROLE_BY_CANTIAN,
    CTC_FUNC_PRE_CREATE_DB,
    CTC_FUNC_TYPE_DROP_TABLESPACE_AND_USER,
    CTC_FUNC_DROP_DB_PRE_CHECK,
    CTC_FUNC_KILL_CONNECTION,
    CTC_FUNC_TYPE_INVALIDATE_OBJECT,
    CTC_FUNC_TYPE_RECORD_SQL,
    CTC_FUNC_TYPE_GET_PARAL_SCHEDULE,
    CTC_FUNC_TYPE_GET_INDEX_PARAL_SCHEDULE,
    CTC_FUNC_TYPE_PQ_INDEX_READ,
    CTC_FUNC_TYPE_PQ_SET_CURSOR_RANGE,
    /* for instance registration, should be the last but before duplex */
    CTC_FUNC_TYPE_REGISTER_INSTANCE,
    CTC_FUNC_QUERY_SHM_FILE_NUM,
    CTC_FUNC_TYPE_WAIT_CONNETOR_STARTUPED,
    /* for duplex channel */
    CTC_FUNC_TYPE_MYSQL_EXECUTE_UPDATE,
    CTC_FUNC_TYPE_MYSQL_EXECUTE_SET_OPT,
    CTC_FUNC_TYPE_CLOSE_MYSQL_CONNECTION,
    CTC_FUNC_TYPE_LOCK_TABLES,
    CTC_FUNC_TYPE_UNLOCK_TABLES,
    CTC_FUNC_TYPE_EXECUTE_REWRITE_OPEN_CONN,
    CTC_FUNC_TYPE_INVALIDATE_OBJECTS,
    CTC_FUNC_TYPE_INVALIDATE_ALL_OBJECTS,
    CTC_FUNC_TYPE_UPDATE_DDCACHE,
    /* the number of total funcs */
    CTC_FUNC_TYPE_NUMBER,
};

typedef enum en_select_mode {
    SELECT_ORDINARY,    /* default behaviour */
    SELECT_SKIP_LOCKED, /* skip the row if row is locked */
    SELECT_NOWAIT       /* return immediately if row is locked */
} ctc_select_mode_t;

typedef enum {
    CTC_DDL_TYPE_UNKNOW = -1,
    CTC_DDL_TYPE_DECIMAL,
    CTC_DDL_TYPE_TINY,
    CTC_DDL_TYPE_SHORT,
    CTC_DDL_TYPE_LONG,
    CTC_DDL_TYPE_FLOAT,
    CTC_DDL_TYPE_DOUBLE,
    CTC_DDL_TYPE_NULL,
    CTC_DDL_TYPE_TIMESTAMP,
    CTC_DDL_TYPE_LONGLONG,
    CTC_DDL_TYPE_INT24,
    CTC_DDL_TYPE_DATE,
    CTC_DDL_TYPE_TIME,
    CTC_DDL_TYPE_DATETIME,
    CTC_DDL_TYPE_YEAR,
    CTC_DDL_TYPE_NEWDATE, /**< Internal to CTC_DDL. Not used in protocol */
    CTC_DDL_TYPE_VARCHAR,
    CTC_DDL_TYPE_BIT,
    CTC_DDL_TYPE_TIMESTAMP2,
    CTC_DDL_TYPE_DATETIME2,   /**< Internal to CTC_DDL. Not used in protocol */
    CTC_DDL_TYPE_TIME2,       /**< Internal to CTC_DDL. Not used in protocol */
    CTC_DDL_TYPE_TYPED_ARRAY, /**< Used for replication only */
    CTC_DDL_TYPE_JSON = 245,
    CTC_DDL_TYPE_NEWDECIMAL = 246,
    CTC_DDL_TYPE_CLOB = 247,
    CTC_DDL_TYPE_TINY_BLOB = 249,
    CTC_DDL_TYPE_MEDIUM_BLOB = 250,
    CTC_DDL_TYPE_LONG_BLOB = 251,
    CTC_DDL_TYPE_BLOB = 252,
    CTC_DDL_TYPE_VAR_STRING = 253,
    CTC_DDL_TYPE_STRING = 254,
} enum_ctc_ddl_field_types;

typedef enum {
    CTC_ALTER_TABLE_DROP_UNKNOW = -1,
    CTC_ALTER_TABLE_DROP_KEY,
    CTC_ALTER_TABLE_DROP_COLUMN,
    CTC_ALTER_TABLE_DROP_FOREIGN_KEY,
    CTC_ALTER_TABLE_DROP_CHECK_CONSTRAINT,
    CTC_ALTER_TABLE_DROP_ANY_CONSTRAINT
} ctc_alter_table_drop_type;

typedef enum {
    CTC_ALTER_COLUMN_UNKNOW = -1,
    CTC_ALTER_COLUMN_SET_DEFAULT,
    CTC_ALTER_COLUMN_DROP_DEFAULT,
    CTC_ALTER_COLUMN_RENAME_COLUMN,
    CTC_ALTER_COLUMN_SET_COLUMN_VISIBLE,
    CTC_ALTER_COLUMN_SET_COLUMN_INVISIBLE
} ctc_alter_column_type;

typedef enum {
    CTC_ALTER_COLUMN_ALTER_MODE_NONE = -1,
    CTC_ALTER_COLUMN_ALTER_ADD_COLUMN = 1,     // 添加列
    CTC_ALTER_COLUMN_ALTER_MODIFY_COLUMN = 2,  // 修改列
} ctc_alter_column_alter_mode;

typedef enum {
    CTC_KEYTYPE_UNKNOW = -1,
    CTC_KEYTYPE_PRIMARY,
    CTC_KEYTYPE_UNIQUE,
    CTC_KEYTYPE_MULTIPLE,
    CTC_KEYTYPE_FULLTEXT,
    CTC_KEYTYPE_SPATIAL,
    CTC_KEYTYPE_FOREIGN
} ctc_key_type;

typedef enum {
    CTC_PART_TYPE_INVALID = 0,
    CTC_PART_TYPE_RANGE = 1,
    CTC_PART_TYPE_LIST = 2,
    CTC_PART_TYPE_HASH = 3,
} ctc_part_type;

typedef enum en_ctc_lock_table_mode {
    CTC_LOCK_MODE_SHARE = 0,  /* SHARE */
    CTC_LOCK_MODE_EXCLUSIVE   /* EXCLUSIVE */
} ctc_lock_table_mode_t;

typedef struct ctc_db_infos {
    char *name;
    uint32_t datafile_size;
    bool datafile_autoextend;
    uint32_t datafile_extend_size;
} ctc_db_infos_t;

typedef enum en_ctc_func_type_t {
    CTC_EQ_FUNC,
    CTC_EQUAL_FUNC,
    CTC_NE_FUNC,
    CTC_LT_FUNC,
    CTC_LE_FUNC,
    CTC_GE_FUNC,
    CTC_GT_FUNC,
    CTC_LIKE_FUNC,
    CTC_ISNULL_FUNC,
    CTC_ISNOTNULL_FUNC,
    CTC_COND_AND_FUNC,
    CTC_COND_OR_FUNC,
    CTC_XOR_FUNC,
    CTC_MOD_FUNC,
    CTC_PLUS_FUNC,
    CTC_MINUS_FUNC,
    CTC_MUL_FUNC,
    CTC_DIV_FUNC,
    CTC_DATE_FUNC,
    CTC_UNKNOWN_FUNC
} ctc_func_type_t;

typedef enum en_ctc_cond_type_t {
    CTC_FIELD_EXPR,
    CTC_CONST_EXPR,
    CTC_NULL_EXPR,
    CTC_LIKE_EXPR,
    CTC_CMP_EXPR,
    CTC_LOGIC_EXPR,
    CTC_ARITHMATIC_EXPR,
    CTC_DATE_EXPR,
    CTC_UNKNOWN_EXPR
} ctc_cond_type_t;

typedef struct en_ctc_cond_field_t {
    uint16_t field_no;
    enum_ctc_ddl_field_types field_type;
    uint16_t field_size;
    void *field_value;
    bool null_value;
    bool is_unsigned;
    uint32_t collate_id;
    bool col_updated;
    bool index_only_invalid_col; // col in cond but not in index while select with index_only
    bool no_backslash;
} ctc_cond_field;

struct en_ctc_cond_list_t;
typedef struct en_ctc_cond_t {
    ctc_cond_type_t cond_type;
    ctc_func_type_t func_type;
    ctc_cond_field field_info;
    struct en_ctc_cond_list_t *cond_list;
    struct en_ctc_cond_t *next;
} ctc_conds;

typedef struct en_ctc_cond_list_t {
    ctc_conds *first;
    ctc_conds *last;
    uint16_t elements;
} ctc_cond_list;


// parallel to knl_scan_key_t
typedef struct en_ctc_scan_key {
    uint8_t flags[CT_MAX_INDEX_COLUMNS]; // should be one of SCAN_KEY_NORMAL, SCAN_KEY_LEFT_INFINITE, .. etc
    uint16_t offsets[CT_MAX_INDEX_COLUMNS]; // the offset of each column from buf[0];
    char *buf;
} ctc_scan_key_t;

typedef union en_ctc_page_id {
    uint32_t vmid;
    struct {
        uint32_t page;
        uint16_t file;
        uint16_t aligned;
    };
} ctc_page_id_t;

typedef struct en_ctc_scan_range {
    union {
        struct {
            char l_buf[CT_KEY_BUF_SIZE];
            char r_buf[CT_KEY_BUF_SIZE];
            char org_buf[CT_KEY_BUF_SIZE];
            ctc_scan_key_t l_key;
            ctc_scan_key_t r_key;
            ctc_scan_key_t org_key;
            uint32_t is_equal;
        };

        struct {
            ctc_page_id_t l_page;
            ctc_page_id_t r_page;
        };
    };
} ctc_scan_range_t;

// by-page scan shall also be wrapped in this as response type
typedef struct en_ctc_index_paral_range {
    uint32_t workers;
    ctc_scan_range_t *index_range[CT_MAX_PARAL_QUERY];
} ctc_index_paral_range_t;

typedef struct {
    uint64_t ignore : 1;
    uint64_t no_foreign_key_check : 1;
    uint64_t no_cascade_check : 1;
    uint64_t dd_update : 1;
    uint64_t is_replace : 1;
    uint64_t dup_update : 1;
    uint64_t no_logging : 1;
    uint64_t auto_inc_used : 1;
    uint64_t has_explicit_autoinc : 1;
    uint64_t auto_increase : 1;
    uint64_t autoinc_lock_mode : 2;
    uint64_t auto_inc_step : 16;
    uint64_t auto_inc_offset : 16;
    uint64_t write_through : 1;
    uint64_t is_create_select : 1;
    uint64_t unused_ops : 18;
} dml_flag_t;

typedef struct {
    uint32_t part_id;
    uint32_t subpart_id;
} ctc_part_t;

typedef int (*ctc_execute_rewrite_open_conn_t)(uint32_t thd_id, ctc_ddl_broadcast_request *broadcast_req);
typedef int (*ctc_ddl_execute_update_t)(uint32_t thd_id, ctc_ddl_broadcast_request *broadcast_req, bool *allow_fail);
typedef int (*ctc_ddl_execute_set_opt_t)(uint32_t thd_id, ctc_set_opt_request *broadcast_req, bool allow_fail);
typedef int (*close_mysql_connection_t)(uint32_t thd_id, uint32_t mysql_inst_id);
typedef int (*ctc_ddl_execute_lock_tables_t)(ctc_handler_t *tch, char *db_name, ctc_lock_table_info *lock_info, int *err_code);
typedef int (*ctc_ddl_execute_unlock_tables_t)(ctc_handler_t *tch, uint32_t mysql_inst_id, ctc_lock_table_info *lock_info);
typedef int (*ctc_invalidate_mysql_dd_cache_t)(ctc_handler_t *tch, ctc_invalidate_broadcast_request *broadcast_req, int *err_code);
typedef int (*ctc_set_cluster_role_by_cantian_t)(bool is_slave);

typedef struct mysql_engine_intf_t {
    ctc_execute_rewrite_open_conn_t ctc_execute_rewrite_open_conn;
    ctc_ddl_execute_update_t ctc_ddl_execute_update;
    ctc_ddl_execute_set_opt_t ctc_ddl_execute_set_opt;
    close_mysql_connection_t close_mysql_connection;
    ctc_ddl_execute_lock_tables_t ctc_ddl_execute_lock_tables;
    ctc_ddl_execute_unlock_tables_t ctc_ddl_execute_unlock_tables;
    ctc_invalidate_mysql_dd_cache_t ctc_invalidate_mysql_dd_cache;
    ctc_set_cluster_role_by_cantian_t ctc_set_cluster_role_by_cantian;
} sql_engine_intf;

/* General Control Interface */
int srv_wait_instance_startuped(void);
int ctc_alloc_inst_id(uint32_t *inst_id);
int ctc_release_inst_id(uint32_t inst_id);

int ctc_open_table(ctc_handler_t *tch, const char *table_name, const char *user_name);
int ctc_close_table(ctc_handler_t *tch);

int ctc_close_session(ctc_handler_t *tch);
void ctc_kill_session(ctc_handler_t *tch);

uint8_t *ctc_alloc_buf(ctc_handler_t *tch, uint32_t buf_size);
void ctc_free_buf(ctc_handler_t *tch, uint8_t *buf);

/* Data Manipulation Language(DML) Related Interface */
int ctc_write_row(ctc_handler_t *tch, const record_info_t *record_info,
                  uint16_t serial_column_offset, uint64_t *last_insert_id, dml_flag_t flag);
int ctc_update_job(update_job_info req_info);
/* This function is for recording slow_log and general_log only. */
int ctc_bulk_write(ctc_handler_t *tch, const record_info_t *record_info, uint64_t rec_num,
                   uint32_t *err_pos, dml_flag_t flag, ctc_part_t *part_ids);
int ctc_update_row(ctc_handler_t *tch, uint16_t new_record_len, const uint8_t *new_record,
                   const uint16_t *upd_cols, uint16_t col_num, dml_flag_t flag);
int ctc_delete_row(ctc_handler_t *tch, uint16_t record_len, dml_flag_t flag);
int ctc_rnd_init(ctc_handler_t *tch, expected_cursor_action_t action,
                 ctc_select_mode_t mode, ctc_conds *cond);
int ctc_rnd_end(ctc_handler_t *tch);
int ctc_rnd_next(ctc_handler_t *tch, record_info_t *record_info);
int ctc_rnd_prefetch(ctc_handler_t *tch, uint8_t *records, uint16_t *record_lens,
                     uint32_t *recNum, uint64_t *rowids, int32_t max_row_size);
int ctc_position(ctc_handler_t *tch, uint8_t *position, uint16_t pos_length);
int ctc_rnd_pos(ctc_handler_t *tch, uint16_t pos_length, uint8_t *position, record_info_t *record_info);
int ctc_delete_all_rows(ctc_handler_t *tch, dml_flag_t flag);
int ctc_scan_records(ctc_handler_t *tch, uint64_t *num_rows, char *index_name);
/* Index Related Interface */
int ctc_index_end(ctc_handler_t *tch);
int ctc_index_read(ctc_handler_t *tch, record_info_t *record_info, index_key_info_t *index_info,
                   ctc_select_mode_t mode, ctc_conds *cond, const bool is_replace);
int ctc_general_fetch(ctc_handler_t *tch, record_info_t *record_info);
int ctc_general_prefetch(ctc_handler_t *tch, uint8_t *records, uint16_t *record_lens,
                         uint32_t *recNum, uint64_t *rowids, int32_t max_row_size);
int ctc_free_session_cursors(ctc_handler_t *tch, uint64_t *cursors, int32_t csize);

/* Parallel Query Interface */
int ctc_get_index_paral_schedule(ctc_handler_t *tch, uint64_t *query_scn, int *worker_count,
    char* index_name, bool reverse, bool is_index_full,
    ctc_scan_range_t *origin_scan_range, ctc_index_paral_range_t *sub_ranges);
int ctc_pq_index_read(ctc_handler_t *tch, record_info_t *record_info,
    index_key_info_t *index_info, ctc_scan_range_t scan_range,
    ctc_select_mode_t mode, ctc_conds *cond, const bool is_replace, uint64_t query_scn);

int ctc_get_paral_schedule(ctc_handler_t *tch, uint64_t *query_scn, uint64_t *ssn, int *worker_count,
    ctc_index_paral_range_t *paral_range);
int ctc_pq_set_cursor_range(ctc_handler_t *tch, ctc_page_id_t l_page, ctc_page_id_t r_page, uint64_t query_scn,
    uint64_t ssn);

/* Transaction Related Interface */
int ctc_trx_begin(ctc_handler_t *tch, ctc_trx_context_t trx_context, bool is_mysql_local);
int ctc_trx_commit(ctc_handler_t *tch, uint64_t *cursors, int32_t csize, bool *is_ddl_commit);
int ctc_trx_rollback(ctc_handler_t *tch, uint64_t *cursors, int32_t csize);

int ctc_srv_set_savepoint(ctc_handler_t *tch, const char *name);
int ctc_srv_rollback_savepoint(ctc_handler_t *tch, uint64_t *cursors, int32_t csize, const char *name);
int ctc_srv_release_savepoint(ctc_handler_t *tch, const char *name);

/* Optimizer Related Interface */
int ctc_analyze_table(ctc_handler_t *tch, const char *db_name, const char *table_name, double sampling_ratio);
int ctc_get_cbo_stats(ctc_handler_t *tch, ctc_cbo_stats_t *stats, ctc_cbo_stats_table_t *ctc_cbo_stats_table, uint32_t first_partid, uint32_t num_part_fetch);
int ctc_get_index_name(ctc_handler_t *tch, char *index_name);

/* Datatype Related Interface */
int ctc_knl_write_lob(ctc_handler_t *tch, char *locator, uint32_t locator_size,
                      int column_id, void *data, uint32_t data_len, bool force_outline);
int ctc_knl_read_lob(ctc_handler_t *tch, char* loc, uint32_t offset,
                     void *buf, uint32_t size, uint32_t *read_size);

/* Data Definition Language(DDL) Related Interface */
int ctc_lock_table(ctc_handler_t *tch, const char *db_name, ctc_lock_table_info *lock_info, int *error_code);
int ctc_unlock_table(ctc_handler_t *tch, uint32_t mysql_inst_id, ctc_lock_table_info *lock_info);

int ctc_lock_instance(bool *is_mysqld_starting, ctc_lock_table_mode_t lock_type, ctc_handler_t *tch);
int ctc_unlock_instance(bool *is_mysqld_starting, ctc_handler_t *tch);

int ctc_drop_tablespace_and_user(ctc_handler_t *tch, const char *db_name,
                                 const char *sql_str, const char *user_name, const char *user_ip,
                                 int *error_code, char *error_message);
int ctc_drop_db_pre_check(ctc_handler_t *tch, const char *db_name, int *error_code, char *error_message);
int ctc_pre_create_db(ctc_handler_t *tch, const char *sql_str, ctc_db_infos_t *db_infos,
                      int *error_code, char *error_message);

int ctc_create_tablespace(void *space_def, ddl_ctrl_t *ddl_ctrl);
int ctc_alter_tablespace(void *space_alter_def, ddl_ctrl_t *ddl_ctrl);
int ctc_drop_tablespace(void *space_drop_def, ddl_ctrl_t *ddl_ctrl);

int ctc_create_table(void *table_def, ddl_ctrl_t *ddl_ctrl);
int ctc_alter_table(void *alter_def, ddl_ctrl_t *ddl_ctrl);
int ctc_truncate_table(void *table_def, ddl_ctrl_t *ddl_ctrl);
int ctc_truncate_partition(void *table_def, ddl_ctrl_t *ddl_ctrl);
int ctc_rename_table(void *alter_def, ddl_ctrl_t *ddl_ctrl);
int ctc_drop_table(void *drop_def, ddl_ctrl_t *ddl_ctrl);

int ctc_update_sample_size(uint32_t sample_size, bool need_persist);
int ctc_get_sample_size(uint32_t *sample_size);
int ctc_get_max_sessions_per_node(uint32_t *max_sessions);
int ctc_get_serial_value(ctc_handler_t *tch, uint64_t *value, dml_flag_t flag);

int close_mysql_connection_intf(uint32_t thd_id, uint32_t mysql_inst_id);
int ctc_ddl_execute_lock_tables_intf(ctc_handler_t *tch, char *db_name, ctc_lock_table_info *lock_info, int *err_code);
int ctc_ddl_execute_unlock_tables_intf(ctc_handler_t *tch, uint32_t mysql_inst_id, ctc_lock_table_info *lock_info);
EXTER_ATTACK int ctc_ddl_execute_update(uint32_t thd_id, ctc_ddl_broadcast_request *broadcast_req, bool *allow_fail);
EXTER_ATTACK int ctc_ddl_execute_set_opt_intf(uint32_t thd_id, ctc_set_opt_request *broadcast_req, bool allow_fail);
EXTER_ATTACK int ctc_execute_mysql_ddl_sql(ctc_handler_t *tch, ctc_ddl_broadcast_request *broadcast_req, bool allow_fail);
EXTER_ATTACK int ctc_execute_set_opt(ctc_handler_t *tch, ctc_set_opt_request *broadcast_req, bool allow_fail);
int ctc_execute_rewrite_open_conn_intf(uint32_t thd_id, ctc_ddl_broadcast_request *broadcast_req);
EXTER_ATTACK int ctc_ddl_execute_update_intf(uint32_t thd_id, ctc_ddl_broadcast_request *broadcast_req, bool *allow_fail);

int ctc_broadcast_rewrite_sql(ctc_handler_t *tch, ctc_ddl_broadcast_request *broadcast_req, bool allow_fail);

/* Metadata Related Interface*/
int ctc_check_db_table_exists(const char *db, const char *name, bool *is_exists);
int ctc_search_metadata_status(bool *cantian_metadata_switch, bool *cantian_cluster_ready);

int ctc_invalidate_mysql_dd_cache_intf(ctc_handler_t *tch, ctc_invalidate_broadcast_request *broadcast_req, int *err_code);
int ctc_broadcast_mysql_dd_invalidate(ctc_handler_t *tch, ctc_invalidate_broadcast_request *broadcast_req);
 
/* Disaster Recovery Related Interface*/
int ctc_set_cluster_role_by_cantian_intf(bool is_slave);

int ctc_record_sql_for_cantian(ctc_handler_t *tch, ctc_ddl_broadcast_request *broadcast_req, bool allow_fail);
int ctc_query_cluster_role(bool *is_slave, bool *cantian_cluster_ready);
int ctc_query_shm_file_num(uint32_t *shm_file_num);
int ctc_query_shm_usage(uint32_t *shm_usage);
#ifdef __cplusplus
}
#endif

#endif
