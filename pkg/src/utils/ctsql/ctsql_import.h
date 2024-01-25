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
 * ctsql_import.h
 *
 *
 * IDENTIFICATION
 * src/utils/ctsql/ctsql_import.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CTSQL_IMP_H
#define CTSQL_IMP_H

#include "ctsql.h"
#include "cm_row.h"
#include "cm_thread.h"
#include "cm_text.h"
#include "cm_base.h"
#include "ctsql_exp_bin.h"
#include "cm_chan.h"
#include "ctsql_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IMPORT_MAXALLOCSIZE (0x3fffffff) /* 1 gigabyte - 1 */
#define RAW_BUF_SIZE        SIZE_M(10)
#define ROW_MAX_SIZE        SIZE_M(32) /* each column 8000B * 4096 */
#define PAR_IMP_MAX_THREADS 32
#define LOB_SWAP_BUF_SIZE   SIZE_K(4)

#define IMP_INDENT                      "  "
#define IMP_INDENT2                     "    "
#define IMP_TABLES_AGENT                "DB_TABLES"
#define IMP_USERS_AGENT                 "DB_USERS"
#define GET_NEXT_STATUS(ret, next, err) ((ret) == CT_SUCCESS ? (next) : (err))
#define IMP_VALUE(TYPE, v)              (*(TYPE *)(v))
#define IMP_VALUE_PTR(TYPE, v)          ((TYPE *)(v))

#define IMP_DEFAULT_THREADS       1
#define MAX_IMP_DEBUG_PRINTSIZE   50
#define MAX_IMP_BATCH_ROW_CNT     10000
#define MAX_DDL_CHAN_BLOCK_CNT    5
#define MAX_DDL_BLOCK_SEND_TIME   10 // ms
#define MAX_DDL_BLOCK_WAIT_TIME   3  // ms
#define IMP_THREAD_CHECK_TIME     5  // ms
#define IMP_MAX_TABLE_PART_NUMBER 8192

#define IMP_MAX_DETAIL_ERR_LEN    512
#define IMP_MAX_LARGE_BLOCK_SIZE  SIZE_M(20)
#define IMP_MAX_NORMAL_BLOCK_SIZE (SIZE_M(1) + 1)

#define IMP_MAX_ALTER_SCHEMA_SQL_LEN 128

typedef enum {
    IMP_SCHEMA,
    IMP_TABLE,
    IMP_ALL_TABLES,
    IMP_ALL_SCHEMAS,
    IMP_REMAP_SCHEMA,
    IMP_FULL,
    IMP_MAX
} en_imp_type;

typedef enum {
    CT_DATA_ONLY = 0x00000001,
    CT_METADATA_ONLY = 0x00000002,
    CT_ALL = CT_DATA_ONLY | CT_METADATA_ONLY,
} en_imp_content;

typedef enum {
    SCHEMA_NONE,
    SCHEMA_NOT_MATCH,
    SCHEMA_MATCH,
} en_schema_match;

typedef enum {
    WORKER_STATUS_ERR = -1,
    WORKER_STATUS_INIT,
    WORKER_STATUS_RECV,
    WORKER_STATUS_END,
} en_worker_status;

#define imp_filetype_t exp_filetype_t

typedef struct {
    uint16 nameLen;
    char name[CT_MAX_NAME_LEN + 1];
    uint16 type;
    uint16 size;
    uchar is_array;
} field_info_t;

typedef struct {
    uint16 rowTotalLen;
    uint16 offsets[CT_MAX_COLUMNS];
    uint16 lens[CT_MAX_COLUMNS];
} subfile_row_t;

typedef struct {
    uint32 invalidFlag;
    uint64 fileOffset;
    uint32 nameSize;
    char name[CT_MAX_NAME_LEN + 1];
} imp_relob_head_t;

typedef struct {
    uint64 lobFileLen;
    uint16 lobNameLen;
    char lobName[CT_MAX_NAME_LEN];
} imp_lobfile_t;

typedef struct {
    bin_file_fixed_head_t fixed_head;  // sizeof(bin_file_fixed_head_t)
    uint32 commandSize;                // import command info
    uint32 sessionParamSize;           // Session parameters
    bool32 readFlag;
} imp_bin_fd_t;

typedef struct st_imp_bind_info {
    /* data buffer size: ROW_MAX_SIZE */
    char *data_buffer;  // buffer for all bind info

    uint16 *data_ind[CT_MAX_COLUMNS];     // store column bind ind array;
    char *col_data[CT_MAX_COLUMNS];       // store column data pointer
    uint16 bind_buf_len[CT_MAX_COLUMNS];  // each column length
    uint32 column_cnt;
    uint32 max_batch_row;
} imp_bind_info_t;

typedef struct {
    bool8 *end_tag;
    uint64 *record_count;
    en_worker_status *return_code;
} imp_dml_status_param_t;

typedef struct {
    uint16 id;
    volatile bool32 idle;
    volatile bool32 closed;
    char fileName[CT_FILE_NAME_BUFFER_SIZE + 1];
    imp_dml_status_param_t dml_status_param;  // for share information with DDL thread
    char currentSchema[CT_MAX_NAME_LEN + 1];
    void *importer;
    bool32 ignore;
    en_worker_status status;
    bool32 show;
    char *impbin;
    imp_bind_info_t bin_bind_info;  // 'bin' mode bind info for insert data
    ctconn_lob_t lob[CT_MAX_COLUMNS];
    uint16 col_ind[CT_MAX_COLUMNS];
    ctsql_conn_info_t conn_info;
    uint32 allowed_batch_errs;
    FILE *fp;
    imp_filetype_t fileType;
    uint64 fileInsertNum;
    uint32 batchRowCnt;
} imp_dml_worker_t;

typedef struct {
    uint32 max_dml_parallel;
    uint32 dml_parallel;
    bool8 *dml_end_flag;       // for DDL passed to DML thread to modified
    uint64 *dml_record_count;  // for DDL passed to DML thread to modified
    en_worker_status *dml_return;
} imp_dml_status_t;

typedef struct {
    /* when 'chan' is empty and 'inque_cnt' is equal to 'outque_cnt', that means all DDL thread is idle */
    chan_t* chan; // queue of DDL block
    uint32 inque_cnt; // count of block putted into queue
    spinlock_t outqueue_lock; // protect race of modified 'outque_cnt'
    uint32 outque_cnt; // count of block processed from queue.
} ddl_block_queue_t;

typedef struct {
    int32 error_code;
    char  error_msg[CT_MESSAGE_BUFFER_SIZE];
} importer_error_t;

typedef struct {
    uint16 id;
    volatile bool32 idle;
    volatile bool32 closed;
    en_worker_status status;
    ctsql_conn_info_t conn_info;
    ddl_block_queue_t *ddl_queue;
    importer_error_t *error_info;
    void *importer;
    imp_dml_status_t dml_status;  // for sync sub file load.
    char currentSchema[CT_MAX_NAME_LEN + 1];
    char current_table[CT_MAX_NAME_LEN + 1];
} imp_ddl_worker_t;

typedef struct {
    FILE *fp;
    ctconn_z_stream zstream;
    char *swap_buffer;
    uint32 swap_len;
} imp_compress_file_t;

typedef struct {
    imp_bin_fd_t fileHead;
    uint32 schemaNum;
    uint32 seqTotalLen;
    uint32 seqNum;
    uint32 seqLen;
    uint32 tableNum;
    uint32 tableInfoLen;
    uint16 tableNameLen;
    char tableName[CT_MAX_NAME_LEN + 1];
    uint64 recordNum;
    uint16 fieldNum;
    uint32 subFileNum;
    uint16 fileNameLen;
    char subFileName[CT_MAX_NAME_LEN + 1];
    uint32 indexLen;
    uint32 extKeyTotalLen;
    uint32 extKeyNum;
    uint32 extKeyLen;
    uint32 viewNum;
    uint32 viewTotalLen;
    uint32 viewLen;
    uint32 funcNum;
    uint32 funcTotalLen;
    uint32 funcLen;
    uint32 verifyFlag;

    char *binBuf;
    uint64 binBufIndex;
    uint64 binBufLen;
    bool8 compress_flag;
    imp_compress_file_t df_handle; // for bin compress file read.
    imp_compress_file_t lf_handle; // for bin compress lob file read.
    list_t fieldInfo;
} import_bin_t;

typedef struct {
    spinlock_t lock;
    date_t     start_time;
    uint64     seq_num;
    uint64     table_num;
    uint64     table_record_num;
    uint64     ext_key_num;
    uint64     object_num;
    uint64     view_num;
    uint64     synonym_num;
    uint64     package_num;
    uint64     profile_num;
    uint64     type_num;
} importer_stat_t;

typedef enum {
    IMP_BLOCK_END,            // end DDL thread
    IMP_BLOCK_TABLE,          // SQL: drop table, create table
    IMP_BLOCK_DROP_TABLE,
    IMP_BLOCK_TABLE_NAME,
    IMP_BLOCK_SUB_FILE_LIST,
    IMP_BLOCK_SUB_FILE,
    IMP_BLOCK_SUB_FILE_END,
    IMP_BLOCK_TABLE_INDEX,
    IMP_BLOCK_COMPLETE_TABLE,  // block include all table info .
    IMP_BLOCK_EXTKEY,
    IMP_BLOCK_VIEW,
    IMP_BLOCK_SEQ,
    IMP_BLOCK_FUNC,
    IMP_BLOCK_SYNONYM,
    IMP_BLOCK_PACKAGE,
    IMP_BLOCK_PROFILE,
    IMP_BLOCK_TYPE
} en_ddl_block_type;

typedef struct {
    en_ddl_block_type type;
    char schema[CT_MAX_NAME_LEN + 1];
    importer_stat_t* statistic;
    text_t sql_txt;
    uint32 max_size;  // max size of sql_txt buffer.
} import_ddl_block;

#define INCLUDE_SUB_DDL_BLOCK(block)  ((block)->type == IMP_BLOCK_COMPLETE_TABLE \
    || (block)->type == IMP_BLOCK_SUB_FILE_LIST)
#define IS_DATA_BLOCK(block) ((block)->type == IMP_BLOCK_TABLE_NAME || \
    (block)->type == IMP_BLOCK_SUB_FILE_LIST || \
    (block)->type == IMP_BLOCK_SUB_FILE_END)
#define SUB_DDL_BLOCK_COUNT(block)    ((block)->sql_txt.len)
#define SUB_DDL_BLOCK(block, idx)     (((import_ddl_block *)(block)->sql_txt.str)[idx])
#define SUB_DDL_BLOCK_PTR(block, idx) (&(((import_ddl_block *)(block)->sql_txt.str)[idx]))

typedef struct {
    fixed_memory_pool_t ddl_sql_block_pool;
    fixed_memory_pool_t ddl_subfile_pool;
    ddl_block_queue_t ddl_queue;  // for SQL block transfer from 'bin file read thread' to 'DDL thread'
    importer_error_t *ddl_error; // for error message from DDL thread to importer.
    thread_t *dml_threads;
    thread_t *ddl_threads;
    imp_dml_worker_t *dml_workers;
    imp_ddl_worker_t *ddl_workers;
    spinlock_t dml_thread_lock;
    bool8 fatal_error;  // setted by DDL thread

    uint32 imp_type;  /* refer to en_imp_type */
    list_t obj_list; /* if impType = IMP_TABLE, obj_list is table list, otherwise is user list */
    imp_filetype_t file_type;
    char import_file[CT_MAX_FILE_PATH_LENGH];
    char log_file[CT_MAX_FILE_PATH_LENGH];
    char targetObj[CTSQL_MAX_OBJECT_LEN]; /* use for remap */
    bool32 show;
    uint32 feedback;
    uint32 exp_content;
    uint32 content;
    bool32 ignore;
    list_t tblSpaceMaps; /* tablespace map list */

    uint64 fileRows;
    uint64 startLine;
    char *rawBuf; /* use for ignore lines */
    uint64 rawBufLen;
    uint64 rawBufIndex;

    bool8 eof;
    bool8 nologging;
    bool8 tblMatch;
    bool8 tblMatched;
    en_schema_match schemaMatch;
    uint32 schemaNum;
    uint64 fileInsertNum;
    bool32 create_user;
    uint32 parallel;
    uint32 ddl_parallel;
    FILE *impfp;
    char sql_cmd_buf[MAX_SQL_SIZE + 4];
    uint32 sql_index;
    char singleSchema[CT_MAX_NAME_LEN + 1];
    bool32 timing;
    uint32 batchRowCnt;
    bool32 disable_trigger;
    char imp_file_path[CT_MAX_FILE_PATH_LENGH];
    char imp_subfile_path[CT_MAX_FILE_PATH_LENGH];
    crypt_info_t crypt_info;
} importer_t;

typedef struct {
    ctsql_conn_info_t *conn_info; // execute connection
    importer_t *importer; // import opts
} imp_ddl_ctx_t;

typedef void *imp_ddl_ctx_param_t;
typedef status_t(*imp_par_ddl_block_func_t)(imp_ddl_worker_t *worker, import_ddl_block *block);
typedef status_t(*imp_serial_ddl_block_func_t)(imp_ddl_ctx_t *ctx, import_ddl_block *block);

typedef struct {
    en_ddl_block_type type;
    imp_par_ddl_block_func_t par_func;
    imp_serial_ddl_block_func_t serial_func;
} imp_ddl_proc_func_map_t;

typedef enum {
    IMP_SQL_CREATE_USER,
    IMP_SQL_CREATE_PROFILE,
    IMP_SQL_INSERT,
    IMP_SQL_ALTER_SESSION_SET_SCHEMA,
    IMP_SQL_ALTER_SESSION_OTHER,
    IMP_SQL_OTHER
} en_imp_sql_type;

#define IMP_SQL_IS_ALTER_SESSION(sql_type) ((sql_type) == IMP_SQL_ALTER_SESSION_SET_SCHEMA || \
    (sql_type) == IMP_SQL_ALTER_SESSION_OTHER)

typedef struct {
    bool8 got_sql; // got a complete sql
    bool8 is_block_comment; // is comment: -- or /* */
    bool8 is_pl; // is procedure
    bool8 first_line; // is first line
    int32 in_enclosed_char; // enclosed char
    text_t sql; // sql text
} imp_sql_parser_t;

#define GS_RETURN_END_IF_TRUE(ret) \
    if (ret) {                     \
        return IMP_STATUS_END;     \
    }

status_t ctsql_import(text_t *cmd_text);
status_t ctsql_get_saved_pswd(char *password, uint32 len);
void ctsql_get_saved_user(char *user, uint32 len);

#ifdef __cplusplus
}
#endif

#endif