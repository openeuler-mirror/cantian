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
 * tse_srv.h
 *
 *
 * IDENTIFICATION
 * src/tse/tse_srv.h
 *
 * -------------------------------------------------------------------------
 */

/* * @file storage/tianchi/tse_srv.h
The server side adapter for txn API and kernel API. This should be transparent ideally.
Logics like init, mgmt, auth, buffering, queueing, etc should be involved within this module.

Expected call trace:
3rdParty RPC module -> (here) tse server -> cantian kernel intf.
*/

#ifndef __TSE_SRV_H__
#define __TSE_SRV_H__

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
#define MAX_DDL_SQL_LEN_CONTEXT (129024)  // 126kb, 预留2kb
#define MAX_DDL_SQL_LEN (MAX_DDL_SQL_LEN_CONTEXT + 30)  // ddl sql语句的长度 不能超过128kb, 超过了会报错
#define DD_BROADCAST_RECORD_LENGTH (3072)
#define LOCK_TABLE_SQL_FMT_LEN 20
#define MAX_LOCK_TABLE_NAME (MAX_DDL_SQL_LEN - LOCK_TABLE_SQL_FMT_LEN)
#define MAX_KEY_COLUMNS (uint32_t)16  // cantian限制复合索引最大支持字段不超过16
#define FUNC_TEXT_MAX_LEN 128
#define TSE_IDENTIFIER_MAX_LEN 64
#define CANTIAN_DOWN_MASK 0xFFFF  // 参天节点故障
#define MAX_DDL_ERROR_MSG_LEN 1024
#define PART_CURSOR_NUM 8192
#define MAX_SUBPART_NUM 4096    // 参天限制每个一级分区下子分区不超过4096
#define TSE_BUF_LEN (70 * 1024)
#define BIG_RECORD_SIZE TSE_BUF_LEN  // 采用最大长度
#define MAX_RECORD_SIZE (1 * TSE_BUF_LEN)
#define TSE_MAX_KEY_NAME_LENGTH 64
#define TSE_SQL_START_INTERNAL_SAVEPOINT "TSE4CANTIAN_SYS_SV"
#define IS_TSE_PART(part_id) ((part_id) < (PART_CURSOR_NUM))
#define MAX_BULK_INSERT_PART_ROWS 128
#define SESSION_CURSOR_NUM (8192 * 2)
#define MAX_MESSAGE_SIZE 8200000  // 共享内存最大可申请空间大小

// for broadcast_req.options
#define TSE_SET_VARIABLE_PERSIST (0x1 << 8)
#define TSE_SET_VARIABLE_PERSIST_ONLY (0x1 << 7)
#define TSE_OPEN_NO_CHECK_FK_FOR_CURRENT_SQL (0x1 << 6)
#define TSE_CURRENT_SQL_CONTAIN_PLAINTEXT_PASSWORD (0x1 << 5)
#define TSE_NOT_NEED_CANTIAN_EXECUTE (0x1 << 4)
#define TSE_SET_VARIABLE_TO_DEFAULT (0x1 << 3)
#define TSE_SET_VARIABLE_TO_NULL (0x1 << 2)
#define TSE_SET_VARIABLE_WITH_SUBSELECT (0x1 << 0)

#define CTC_AUTOINC_OLD_STYLE_LOCKING 0
#define CTC_AUTOINC_NEW_STYLE_LOCKING 1
#define CTC_AUTOINC_NO_LOCKING 2

typedef int64 date_t;

typedef struct {
    uint32_t inst_id; // instance id, thd_id alone is not sufficient to uniquely identify a tse session
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
} tianchi_handler_t;

typedef struct {
    char db_name[SMALL_RECORD_SIZE];
    char table_name[SMALL_RECORD_SIZE];
    char user_name[SMALL_RECORD_SIZE];
    char user_ip[SMALL_RECORD_SIZE];
    int32_t sql_type;
    int32_t mdl_namespace;
} tse_lock_table_info;
#pragma pack(4)
typedef struct my_st_text {
    char str[64];
    uint32_t len;
} my_text_t;
#pragma pack()
typedef uint16_t my_c4typ_t;
typedef uint32_t my_cc4typ_t;
#define MY_DEC4_CELL_SIZE (uint8_t)18
typedef my_c4typ_t my_cell4_t[MY_DEC4_CELL_SIZE];
#pragma pack(2)
typedef struct my_st_dec4 {
  union {
    struct {
      uint8_t sign : 1;   /* 0: for positive integer; 1: for negative integer */
      uint8_t ncells : 7; /* number of cells, 0: for unspecified precision */
      int8_t expn;        /* the exponent of the number */
    };
    my_c4typ_t head;
  };
  my_cell4_t cells;
} my_dec4_t;
#pragma pack()
typedef struct cache_st_variant {
    union {
        int v_int;
        unsigned int v_uint32;
        unsigned int v_bool;
        long long v_bigint;
        unsigned long long v_ubigint;
        double v_real;
        date_t v_date;
        my_dec4_t v_dec;
    };
} cache_variant_t;

typedef enum {
    FREQUENCY_HIST = 0,
    HEIGHT_BALANCED_HIST = 1,
} tse_cbo_hist_type_t;

typedef struct {
    cache_variant_t ep_value;
    int ep_number;
} tse_cbo_column_hist_t;

typedef struct {
    uint32_t total_rows;
    uint32_t num_buckets;
    uint32_t num_null;
    double density;
    tse_cbo_hist_type_t hist_type;
    uint32_t hist_count;
    tse_cbo_column_hist_t column_hist[STATS_HISTGRAM_MAX_SIZE];  // Column histogram statistics (array)
    cache_variant_t low_value;
    cache_variant_t high_value;
} tse_cbo_stats_column_t;

/**
 * cache info that can expand this struct
 * if need more cbo stats cache
 */
typedef struct {
    uint32_t estimate_rows;
    tse_cbo_stats_column_t *columns;
} tse_cbo_stats_table_t;

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
    tse_cbo_stats_table_t *tse_cbo_stats_table;
} tianchi_cbo_stats_t;
#pragma pack()

typedef struct {
    char error_msg[MAX_DDL_ERROR_MSG_LEN];
    char user_name[SMALL_RECORD_SIZE];
    char user_ip[SMALL_RECORD_SIZE];
    int32_t error_code;
    uint32_t msg_len;
    tianchi_handler_t tch;
    uint32_t mysql_inst_id;
    bool is_alter_copy;
    uint32_t table_flags;
} ddl_ctrl_t;

typedef struct {
    int isolation_level;
    uint32_t autocommit;
    uint32_t lock_wait_timeout;
    bool use_exclusive_lock;
} tianchi_trx_context_t;

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
} tse_ddl_broadcast_request;

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
} tse_invalidate_broadcast_request;

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
        uint32_t is_dummy : 1;           // if it is a dummy column for index  目前在daac代码中暂未使用
        uint32_t is_default_null   : 1;  // empty string treat as null or ''
        uint32_t isKey   : 1;            // key关键字
        uint32_t is_default_func   : 1;  // if default value is generated by mysql functions
        uint32_t is_curr_timestamp : 1;  // if default value is current_timestamp
        uint32_t unused_ops : 15;
    };
    uint32_t is_option_set;
} tse_column_option_set_bit;

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
    char index_name[TSE_MAX_KEY_NAME_LENGTH + 1];        // 索引名
    uint16_t key_num;                      // 查询条件覆盖多少列
    key_info_t key_info[MAX_KEY_COLUMNS];  // 索引查询条件数组
    bool index_skip_scan;
} index_key_info_t;

enum TSE_FUNC_TYPE {
    TSE_FUNC_TYPE_OPEN_TABLE = 0,
    TSE_FUNC_TYPE_CLOSE_TABLE,
    TSE_FUNC_TYPE_CLOSE_SESSION,
    TSE_FUNC_TYPE_WRITE_ROW,
    TSE_FUNC_TYPE_WRITE_THROUGH_ROW,
    TSE_FUNC_TYPE_UPDATE_ROW,
    TSE_FUNC_TYPE_DELETE_ROW,
    TSE_FUNC_TYPE_RND_INIT,
    TSE_FUNC_TYPE_RND_END,
    TSE_FUNC_TYPE_RND_NEXT,
    TSE_FUNC_TYPE_RND_PREFETCH,
    TSE_FUNC_TYPE_SCAN_RECORDS,
    TSE_FUNC_TYPE_TRX_COMMIT,
    TSE_FUNC_TYPE_TRX_ROLLBACK,
    TSE_FUNC_TYPE_TRX_BEGIN,
    TSE_FUNC_TYPE_LOCK_TABLE,
    TSE_FUNC_TYPE_UNLOCK_TABLE,
    TSE_FUNC_TYPE_INDEX_END,
    TSE_FUNC_TYPE_SRV_SET_SAVEPOINT,
    TSE_FUNC_TYPE_SRV_ROLLBACK_SAVEPOINT,
    TSE_FUNC_TYPE_SRV_RELEASE_SAVEPOINT,
    TSE_FUNC_TYPE_GENERAL_FETCH,
    TSE_FUNC_TYPE_GENERAL_PREFETCH,
    TSE_FUNC_TYPE_FREE_CURSORS,
    TSE_FUNC_TYPE_GET_INDEX_NAME,
    TSE_FUNC_TYPE_INDEX_READ,
    TSE_FUNC_TYPE_RND_POS,
    TSE_FUNC_TYPE_POSITION,
    TSE_FUNC_TYPE_DELETE_ALL_ROWS,
    TSE_FUNC_TYPE_GET_CBO_STATS,
    TSE_FUNC_TYPE_WRITE_LOB,
    TSE_FUNC_TYPE_READ_LOB,
    TSE_FUNC_TYPE_CREATE_TABLE,
    TSE_FUNC_TYPE_TRUNCATE_TABLE,
    TSE_FUNC_TYPE_TRUNCATE_PARTITION,
    TSE_FUNC_TYPE_RENAME_TABLE,
    TSE_FUNC_TYPE_ALTER_TABLE,
    TSE_FUNC_TYPE_GET_SERIAL_VALUE,
    TSE_FUNC_TYPE_DROP_TABLE,
    TSE_FUNC_TYPE_EXCUTE_MYSQL_DDL_SQL,
    TSE_FUNC_TYPE_BROADCAST_REWRITE_SQL,
    TSE_FUNC_TYPE_CREATE_TABLESPACE,
    TSE_FUNC_TYPE_ALTER_TABLESPACE,
    TSE_FUNC_TYPE_DROP_TABLESPACE,
    TSE_FUNC_TYPE_BULK_INSERT,
    TSE_FUNC_TYPE_ANALYZE,
    TSE_FUNC_TYPE_GET_MAX_SESSIONS,
    TSE_FUNC_LOCK_INSTANCE,
    TSE_FUNC_UNLOCK_INSTANCE,
    TSE_FUNC_CHECK_TABLE_EXIST,
    TSE_FUNC_SEARCH_METADATA_SWITCH,
    TSE_FUNC_QUERY_CLUSTER_ROLE,
    TSE_FUNC_SET_CLUSTER_ROLE_BY_CANTIAN,
    TSE_FUNC_PRE_CREATE_DB,
    TSE_FUNC_TYPE_DROP_TABLESPACE_AND_USER,
    TSE_FUNC_DROP_DB_PRE_CHECK,
    TSE_FUNC_KILL_CONNECTION,
    TSE_FUNC_TYPE_INVALIDATE_OBJECT,
    TSE_FUNC_TYPE_RECORD_SQL,
    /* for instance registration, should be the last but before duplex */
    TSE_FUNC_TYPE_REGISTER_INSTANCE,
    TSE_FUNC_TYPE_WAIT_CONNETOR_STARTUPED,
    /* for duplex channel */
    TSE_FUNC_TYPE_MYSQL_EXECUTE_UPDATE,
    TSE_FUNC_TYPE_CLOSE_MYSQL_CONNECTION,
    TSE_FUNC_TYPE_LOCK_TABLES,
    TSE_FUNC_TYPE_UNLOCK_TABLES,
    TSE_FUNC_TYPE_EXECUTE_REWRITE_OPEN_CONN,
    TSE_FUNC_TYPE_INVALIDATE_OBJECTS,
    TSE_FUNC_TYPE_INVALIDATE_ALL_OBJECTS,
    TSE_FUNC_TYPE_UPDATE_DDCACHE,
    /* the number of total funcs */
    TSE_FUNC_TYPE_NUMBER,
};

typedef enum en_select_mode {
    SELECT_ORDINARY,    /* default behaviour */
    SELECT_SKIP_LOCKED, /* skip the row if row is locked */
    SELECT_NOWAIT       /* return immediately if row is locked */
} tse_select_mode_t;

typedef enum {
    TSE_DDL_TYPE_UNKNOW = -1,
    TSE_DDL_TYPE_DECIMAL,
    TSE_DDL_TYPE_TINY,
    TSE_DDL_TYPE_SHORT,
    TSE_DDL_TYPE_LONG,
    TSE_DDL_TYPE_FLOAT,
    TSE_DDL_TYPE_DOUBLE,
    TSE_DDL_TYPE_NULL,
    TSE_DDL_TYPE_TIMESTAMP,
    TSE_DDL_TYPE_LONGLONG,
    TSE_DDL_TYPE_INT24,
    TSE_DDL_TYPE_DATE,
    TSE_DDL_TYPE_TIME,
    TSE_DDL_TYPE_DATETIME,
    TSE_DDL_TYPE_YEAR,
    TSE_DDL_TYPE_NEWDATE, /**< Internal to TSE_DDL. Not used in protocol */
    TSE_DDL_TYPE_VARCHAR,
    TSE_DDL_TYPE_BIT,
    TSE_DDL_TYPE_TIMESTAMP2,
    TSE_DDL_TYPE_DATETIME2,   /**< Internal to TSE_DDL. Not used in protocol */
    TSE_DDL_TYPE_TIME2,       /**< Internal to TSE_DDL. Not used in protocol */
    TSE_DDL_TYPE_TYPED_ARRAY, /**< Used for replication only */
    TSE_DDL_TYPE_JSON = 245,
    TSE_DDL_TYPE_NEWDECIMAL = 246,
    TSE_DDL_TYPE_CLOB = 247,
    TSE_DDL_TYPE_TINY_BLOB = 249,
    TSE_DDL_TYPE_MEDIUM_BLOB = 250,
    TSE_DDL_TYPE_LONG_BLOB = 251,
    TSE_DDL_TYPE_BLOB = 252,
    TSE_DDL_TYPE_VAR_STRING = 253,
    TSE_DDL_TYPE_STRING = 254,
} enum_tse_ddl_field_types;

typedef enum {
    TSE_ALTER_TABLE_DROP_UNKNOW = -1,
    TSE_ALTER_TABLE_DROP_KEY,
    TSE_ALTER_TABLE_DROP_COLUMN,
    TSE_ALTER_TABLE_DROP_FOREIGN_KEY,
    TSE_ALTER_TABLE_DROP_CHECK_CONSTRAINT,
    TSE_ALTER_TABLE_DROP_ANY_CONSTRAINT
} tse_alter_table_drop_type;

typedef enum {
    TSE_ALTER_COLUMN_UNKNOW = -1,
    TSE_ALTER_COLUMN_SET_DEFAULT,
    TSE_ALTER_COLUMN_DROP_DEFAULT,
    TSE_ALTER_COLUMN_RENAME_COLUMN,
    TSE_ALTER_COLUMN_SET_COLUMN_VISIBLE,
    TSE_ALTER_COLUMN_SET_COLUMN_INVISIBLE
} tse_alter_column_type;

typedef enum {
    TSE_ALTER_COLUMN_ALTER_MODE_NONE = -1,
    TSE_ALTER_COLUMN_ALTER_ADD_COLUMN = 1,     // 添加列
    TSE_ALTER_COLUMN_ALTER_MODIFY_COLUMN = 2,  // 修改列
} tse_alter_column_alter_mode;

typedef enum {
    TSE_KEYTYPE_UNKNOW = -1,
    TSE_KEYTYPE_PRIMARY,
    TSE_KEYTYPE_UNIQUE,
    TSE_KEYTYPE_MULTIPLE,
    TSE_KEYTYPE_FULLTEXT,
    TSE_KEYTYPE_SPATIAL,
    TSE_KEYTYPE_FOREIGN
} tse_key_type;

typedef enum {
    TSE_PART_TYPE_INVALID = 0,
    TSE_PART_TYPE_RANGE = 1,
    TSE_PART_TYPE_LIST = 2,
    TSE_PART_TYPE_HASH = 3,
} tse_part_type;

typedef enum en_tse_lock_table_mode {
    TSE_LOCK_MODE_SHARE = 0,  /* SHARE */
    TSE_LOCK_MODE_EXCLUSIVE   /* EXCLUSIVE */
} tse_lock_table_mode_t;

typedef struct tse_db_infos {
    char *name;
    uint32_t datafile_size;
    bool datafile_autoextend;
    uint32_t datafile_extend_size;
} tse_db_infos_t;

typedef enum en_tse_func_type_t {
    TSE_UNKNOWN_FUNC,
    TSE_EQ_FUNC,
    TSE_EQUAL_FUNC,
    TSE_NE_FUNC,
    TSE_LT_FUNC,
    TSE_LE_FUNC,
    TSE_GE_FUNC,
    TSE_GT_FUNC,
    TSE_LIKE_FUNC,
    TSE_ISNULL_FUNC,
    TSE_ISNOTNULL_FUNC,
    TSE_NOT_FUNC,
    TSE_COND_AND_FUNC,
    TSE_COND_OR_FUNC,
    TSE_XOR_FUNC
} tse_func_type_t;

typedef struct en_tse_cond_field_t {
    uint16_t field_no;
    enum_tse_ddl_field_types field_type;
    uint16_t field_size;
    void *field_value;
    bool null_value;
    uint32_t collate_id;
    bool col_updated;
    bool no_backslash;
} tse_cond_field;

struct en_tse_cond_list_t;
typedef struct en_tse_cond_t {
    tse_func_type_t func_type;
    tse_cond_field field_info;
    struct en_tse_cond_list_t *cond_list;
    struct en_tse_cond_t *next;
} tse_conds;

typedef struct en_tse_cond_list_t {
    tse_conds *first;
    tse_conds *last;
    uint16_t elements;
} tse_cond_list;

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

/* General Control Interface */
int srv_wait_instance_startuped(void);
int tse_alloc_inst_id(uint32_t *inst_id);
int tse_release_inst_id(uint32_t inst_id);

int tse_open_table(tianchi_handler_t *tch, const char *table_name, const char *user_name);
int tse_close_table(tianchi_handler_t *tch);

int tse_close_session(tianchi_handler_t *tch);
void tse_kill_session(tianchi_handler_t *tch);

uint8_t *tse_alloc_buf(tianchi_handler_t *tch, uint32_t buf_size);
void tse_free_buf(tianchi_handler_t *tch, uint8_t *buf);

/* Data Manipulation Language(DML) Related Interface */
int tse_write_row(tianchi_handler_t *tch, const record_info_t *record_info,
                  uint16_t serial_column_offset, uint64_t *last_insert_id, dml_flag_t flag);
/* This function is for recording slow_log and general_log only. */
int tse_write_through_row(tianchi_handler_t *tch, const record_info_t *record_info,
                          uint16_t serial_column_offset, uint64_t *last_insert_id, dml_flag_t flag);
int tse_bulk_write(tianchi_handler_t *tch, const record_info_t *record_info, uint64_t rec_num,
                   uint32_t *err_pos, dml_flag_t flag, ctc_part_t *part_ids);
int tse_update_row(tianchi_handler_t *tch, uint16_t new_record_len, const uint8_t *new_record,
                   const uint16_t *upd_cols, uint16_t col_num, dml_flag_t flag);
int tse_delete_row(tianchi_handler_t *tch, uint16_t record_len, dml_flag_t flag);
int tse_rnd_init(tianchi_handler_t *tch, expected_cursor_action_t action,
                 tse_select_mode_t mode, tse_conds *cond);
int tse_rnd_end(tianchi_handler_t *tch);
int tse_rnd_next(tianchi_handler_t *tch, record_info_t *record_info);
int tse_rnd_prefetch(tianchi_handler_t *tch, uint8_t *records, uint16_t *record_lens,
                     uint32_t *recNum, uint64_t *rowids, int32_t max_row_size);
int tse_position(tianchi_handler_t *tch, uint8_t *position, uint16_t pos_length);
int tse_rnd_pos(tianchi_handler_t *tch, uint16_t pos_length, uint8_t *position, record_info_t *record_info);
int tse_delete_all_rows(tianchi_handler_t *tch, dml_flag_t flag);
int tse_scan_records(tianchi_handler_t *tch, uint64_t *num_rows, char *index_name);
/* Index Related Interface */
int tse_index_end(tianchi_handler_t *tch);
int tse_index_read(tianchi_handler_t *tch, record_info_t *record_info, index_key_info_t *index_info,
                   tse_select_mode_t mode, tse_conds *cond, const bool is_replace);
int tse_general_fetch(tianchi_handler_t *tch, record_info_t *record_info);
int tse_general_prefetch(tianchi_handler_t *tch, uint8_t *records, uint16_t *record_lens,
                         uint32_t *recNum, uint64_t *rowids, int32_t max_row_size);
int tse_free_session_cursors(tianchi_handler_t *tch, uint64_t *cursors, int32_t csize);

/* Transaction Related Interface */
int tse_trx_begin(tianchi_handler_t *tch, tianchi_trx_context_t trx_context, bool is_mysql_local);
int tse_trx_commit(tianchi_handler_t *tch, uint64_t *cursors, int32_t csize, bool *is_ddl_commit);
int tse_trx_rollback(tianchi_handler_t *tch, uint64_t *cursors, int32_t csize);

int tse_srv_set_savepoint(tianchi_handler_t *tch, const char *name);
int tse_srv_rollback_savepoint(tianchi_handler_t *tch, uint64_t *cursors, int32_t csize, const char *name);
int tse_srv_release_savepoint(tianchi_handler_t *tch, const char *name);

/* Optimizer Related Interface */
int tse_analyze_table(tianchi_handler_t *tch, const char *db_name, const char *table_name, double sampling_ratio);
int tse_get_cbo_stats(tianchi_handler_t *tch, tianchi_cbo_stats_t *stats, tse_cbo_stats_table_t *tse_cbo_stats_table, uint32_t first_partid, uint32_t num_part_fetch);
int tse_get_index_name(tianchi_handler_t *tch, char *index_name);

/* Datatype Related Interface */
int tse_knl_write_lob(tianchi_handler_t *tch, char *locator, uint32_t locator_size,
                      int column_id, void *data, uint32_t data_len, bool force_outline);
int tse_knl_read_lob(tianchi_handler_t *tch, char* loc, uint32_t offset,
                     void *buf, uint32_t size, uint32_t *read_size);

/* Data Definition Language(DDL) Related Interface */
int tse_lock_table(tianchi_handler_t *tch, const char *db_name, tse_lock_table_info *lock_info, int *error_code);
int tse_unlock_table(tianchi_handler_t *tch, uint32_t mysql_inst_id, tse_lock_table_info *lock_info);

int tse_lock_instance(bool *is_mysqld_starting, tse_lock_table_mode_t lock_type, tianchi_handler_t *tch);
int tse_unlock_instance(bool *is_mysqld_starting, tianchi_handler_t *tch);

int tse_drop_tablespace_and_user(tianchi_handler_t *tch, const char *db_name,
                                 const char *sql_str, const char *user_name, const char *user_ip,
                                 int *error_code, char *error_message);
int tse_drop_db_pre_check(tianchi_handler_t *tch, const char *db_name, int *error_code, char *error_message);
int tse_pre_create_db(tianchi_handler_t *tch, const char *sql_str, tse_db_infos_t *db_infos,
                      int *error_code, char *error_message);

int tse_create_tablespace(void *space_def, ddl_ctrl_t *ddl_ctrl);
int tse_alter_tablespace(void *space_alter_def, ddl_ctrl_t *ddl_ctrl);
int tse_drop_tablespace(void *space_drop_def, ddl_ctrl_t *ddl_ctrl);

int tse_create_table(void *table_def, ddl_ctrl_t *ddl_ctrl);
int tse_alter_table(void *alter_def, ddl_ctrl_t *ddl_ctrl);
int tse_truncate_table(void *table_def, ddl_ctrl_t *ddl_ctrl);
int tse_truncate_partition(void *table_def, ddl_ctrl_t *ddl_ctrl);
int tse_rename_table(void *alter_def, ddl_ctrl_t *ddl_ctrl);
int tse_drop_table(void *drop_def, ddl_ctrl_t *ddl_ctrl);

int tse_get_max_sessions_per_node(uint32_t *max_sessions);
int tse_get_serial_value(tianchi_handler_t *tch, uint64_t *value, dml_flag_t flag);

int close_mysql_connection(uint32_t thd_id, uint32_t mysql_inst_id);
int tse_ddl_execute_lock_tables(tianchi_handler_t *tch, char *db_name, tse_lock_table_info *lock_info, int *err_code);
int tse_ddl_execute_unlock_tables(tianchi_handler_t *tch, uint32_t mysql_inst_id, tse_lock_table_info *lock_info);
EXTER_ATTACK int tse_ddl_execute_update(uint32_t thd_id, tse_ddl_broadcast_request *broadcast_req, bool *allow_fail);
EXTER_ATTACK int tse_execute_mysql_ddl_sql(tianchi_handler_t *tch, tse_ddl_broadcast_request *broadcast_req, bool allow_fail);
int tse_execute_rewrite_open_conn(uint32_t thd_id, tse_ddl_broadcast_request *broadcast_req);
int tse_broadcast_rewrite_sql(tianchi_handler_t *tch, tse_ddl_broadcast_request *broadcast_req, bool allow_fail);

/* Metadata Related Interface*/
int tse_check_db_table_exists(const char *db, const char *name, bool *is_exists);
int tse_search_metadata_status(bool *cantian_metadata_switch, bool *cantian_cluster_ready);

int tse_invalidate_mysql_dd_cache(tianchi_handler_t *tch, tse_invalidate_broadcast_request *broadcast_req, int *err_code);
int tse_broadcast_mysql_dd_invalidate(tianchi_handler_t *tch, tse_invalidate_broadcast_request *broadcast_req);
 
/* Disaster Recovery Related Interface*/
int tse_set_cluster_role_by_cantian(bool is_slave);

int ctc_record_sql_for_cantian(tianchi_handler_t *tch, tse_ddl_broadcast_request *broadcast_req, bool allow_fail);
int tse_query_cluster_role(bool *is_slave, bool *cantian_cluster_ready);
#ifdef __cplusplus
}
#endif

#endif
