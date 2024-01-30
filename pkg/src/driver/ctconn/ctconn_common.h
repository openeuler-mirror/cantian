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
 * ctconn_common.h
 *
 *
 * IDENTIFICATION
 * src/driver/ctconn/ctconn_common.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CTCONN_COMMON_H__
#define __CTCONN_COMMON_H__

#include "cm_defs.h"
#include "cm_list.h"
#include "ctconn.h"
#include "cm_thread.h"
#include "cs_packet.h"
#include "cs_pipe.h"
#include "cs_protocol.h"
#include "cm_nls.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_cli_stmt_status {
    CLI_STMT_IDLE = 1,
    CLI_STMT_PREPARED = 2,
    CLI_STMT_EXECUTED = 3,
    CLI_STMT_FETCHING = 4,
#ifdef Z_SHARDING
    CLI_STMT_PRE_PARAMS = 5, // preprocessed params in CN
#endif
    CLI_STMT_DESCRIBLE = 6
} cli_stmt_status_t;

typedef enum en_cli_db_role {
    ROLE_PRIMARY = 0,
    ROLE_PHYSICAL_STANDBY = 1,
    ROLE_CASCADED_PHYSICAL_STANDBY = 2,
} cli_db_role_t;

#ifdef DB_DEBUG_VERSION
#define CT_SQL_TYPE_CREATE_USER 40
#else
#define CT_SQL_TYPE_CREATE_USER 39
#endif

#define CTCONN_IS_DATABASE_DATATYPE(type) \
    (CM_IS_DATABASE_DATATYPE((type) + CT_TYPE_BASE) || (type) == CTCONN_TYPE_NATIVE_DATE)
#define CTCONN_IS_STRING_TYPE(type) ((type) == CTCONN_TYPE_CHAR || (type) == CTCONN_TYPE_VARCHAR || (type) == CTCONN_TYPE_STRING)
#define CTCONN_IS_BINARY_TYPE(type) ((type) == CTCONN_TYPE_BINARY || (type) == CTCONN_TYPE_VARBINARY)
#define CTCONN_IS_LOB_TYPE(type) ((type) == CTCONN_TYPE_CLOB || (type) == CTCONN_TYPE_BLOB || (type) == CTCONN_TYPE_IMAGE)
#define CTCONN_IS_DATE_TYPE(type)                                                                     \
    ((type) == CTCONN_TYPE_DATE || (type) == CTCONN_TYPE_TIMESTAMP || (type) == CTCONN_TYPE_TIMESTAMP_TZ || \
        (type) == CTCONN_TYPE_TIMESTAMP_TZ_FAKE)
#define CTCONN_IS_NUMBER_TYPE(type)                                                              \
    ((type) == CTCONN_TYPE_NUMBER || (type) == CTCONN_TYPE_DECIMAL || (type) == CTCONN_TYPE_INTEGER || \
        (type) == CTCONN_TYPE_BIGINT || (type) == CTCONN_TYPE_REAL || (type) == CTCONN_TYPE_BOOLEAN || \
        (type) == CTCONN_TYPE_UINT32 || (type) == CTCONN_TYPE_NUMBER2)
#define CTCONN_IS_TYPE_NEED_EXTRA(type)                                                          \
    ((type) == CTCONN_TYPE_NUMBER || (type) == CTCONN_TYPE_DECIMAL || (type) == CTCONN_TYPE_NUMBER2 || \
        (type) == CTCONN_TYPE_CHAR || (type) == CTCONN_TYPE_VARCHAR || (type) == CTCONN_TYPE_STRING || \
        (type) == CTCONN_TYPE_BINARY || (type) == CTCONN_TYPE_VARBINARY || (type) == CTCONN_TYPE_RAW)

#define CTCONN_CHECK_FETCH_STATUS(stmt)                                                                              \
    do {                                                                                                          \
        if ((stmt)->status == CLI_STMT_DESCRIBLE) {                                                               \
            CLT_THROW_ERROR((stmt)->conn, ERR_CLT_OUT_OF_API_SEQUENCE, "can not fetch data in describling mode"); \
            return CT_ERROR;                                                                                      \
        }                                                                                                         \
    } while (0)

#define CLT_LOB_INLINE(lob) ((lob) != NULL && (lob)->type == CT_LOB_FROM_KERNEL && (!(lob)->is_outline))

#define MAX_SET_NLS_SQL 2048
#define CLT_DATE_BINARY_SIZE 7
#define CLT_CHARSET_NAME_SIZE 5

typedef struct st_clt_lob_head {
    uint32 size;
    uint32 type;
    uint32 is_outline : 1;
    uint32 node_id : 9;
    uint32 unused : 22;
} clt_lob_head_t;

typedef struct st_clt_cache_lob {
    clt_lob_head_t lob_head;
    uint32 fetched_times;
    uint32 column_id;
    uint32 offset;
} clt_cache_lob_t;

#define CTCONN_INLINE_LOB_ENCODE_LEN (uint32)(sizeof(clt_cache_lob_t))

typedef struct st_clt_server_info {
    uint32 locator_size; // lob locator size received from server
    uint16 server_charset;
    int16 server_dbtimezone;
    uint32 server_max_pack_size;
    cli_db_role_t db_role;
} clt_server_info_t;

typedef struct st_clt_options {
    int32 connect_timeout; /* second */
    int32 socket_timeout;  /* second */
    int32 l_onoff;
    int32 l_linger;
    uint32 port;
    uint32 client_flag;
    ctconn_ssl_mode_t ssl_mode;
    char *host;
    char *user;
    char *ssl_key;     /* key file */
    char *ssl_cert;    /* cert file */
    char *ssl_ca;      /* CA file */
    SENSI_INFO char *ssl_keypwd;  /* Private key */
    char *ssl_crl;     /* Certificate revocation list */
    char *ssl_cipher;  /* Algorithm cipher list */
    char *server_path; /* unix domain socket server path, due to simplified url */
    char *client_path; /* unix domain socket client path, due to simplified url */
    int16 app_kind;
    uint8 reserverd[2]; // 4 bytes align
} clt_options_t;

typedef struct st_clt_packet {
    cs_packet_t pack;
    uint32 id;
    bool8 used;
    uint8 reserved[3]; // 4-bytes align
} clt_packet_t;

typedef struct st_clt_serveroutput {
    list_t output_data;  // clt_output_item_t
    uint32 output_count; // count of current serveroutput
    uint32 pos;
} clt_serveroutput_t;

typedef struct st_clt_resultset {
    list_t stmt_ids; // stmt id of multi resultset(clt_rs_stmt_t)
    list_t ids;      // local idx in connection's statement list
    uint32 pos;
} clt_resultset_t;

typedef struct st_clt_batch_errs_t {
    uint32 allowed_count;
    uint32 actual_count;
    list_t err_list; /* item is clt_batch_error_t */
    uint32 pos;      /* record pos to fetch batch_err */
} clt_batch_errs_t;

typedef struct st_cli_buf_ctrl {
    char data[2 * CT_MAX_PACKET_SIZE];
    uint32 size;
    uint32 offset;
} cli_buf_ctrl_t;

typedef struct st_clt_stmt {
    struct st_clt_conn *conn;
    uint16 id;                /* local idx in connection's statement list */
    uint16 stmt_id;           /* remote idx in server session's statement list */
    clt_packet_t *cache_pack; /* for receiving, get pack from connection. */
    cli_stmt_status_t status;

    list_t columns;
    uint32 column_count;
    list_t params;
    uint32 param_count;
    list_t outparams;
    uint32 outparam_count;

    uint32 paramset_size; /* rows of batch bind */
    uint32 fetch_size;    /* rows of batch fetch */
    uint32 prefetch_rows; /* rows returned from server in execute or fetch ack */
    uint32 prefetch_buf;  /* no use */

    uint32 affected_rows; /* rows affected in server */
    uint16 return_rows;   /* rows returned by the last call of ct_execute */
    uint16 stmt_type;
    uint16 sql_type;
    bool8 more_rows; /* has more rows need fetch from server */
    bool8 eof;
    uint8 fetch_mode; /* 0:CS_FETCH_NORMAL, 1:CS_FETCH_WITH_PREP_EXEC, 2:CS_FETCH_WITH_PREP */
    uint8 reserved1[1];

    uint32 fetched_times; /* times of ctconn_fetch called */
    uint32 fetched_rows;  /* rows fetched from client */
    uint32 fetch_pos;     /* pos of batch fetch of once ctconn_fetch */
    uint16 row_index; /* row index of current fetching cache, when row_index equals to return rows, need do remote fetch
                       */
    uint8 reserved2[2];

    clt_serveroutput_t serveroutput; /* put_line of PL */
    clt_resultset_t resultset;       /* return_result of PL */
    clt_batch_errs_t batch_errs;     /* result of batch execute */
    cli_buf_ctrl_t *ctrl;            /* for trans code */
    char *ori_row;

#ifdef Z_SHARDING
    uint64 gts_scn;             /* paramset GTS's SCN for sharding mode */
    uint32 offset;              /* paramset offset */
    uint32 max_batch_buf_size;  /* max batch buffer size of batch_curr_ptr */
    uint32 paramset_len_offset; /* addr offset in batch_bnd_ptr to store paramset size (because of buf realloc) */
    char *batch_bnd_ptr;        /* point to paramsets which stored in batch_buffer, buffer can be extend dynamicly */
                                /* paramsets: | paramset_1 | paramset_2 | ... | paramset_n | */
                                /* paramset : | paramset_length | param_info_1 | param_info_2 | ... | param_info_n | */
                                /* param_info:| cs_param_head_t | param_value (string contains terminator '\0') | */
    char *batch_curr_ptr;
    /* in case of (SQL +  parameters) is large than CT_MAX_PACKET_SIZE to split package from CN to DN */
    bool8 can_read_ack;
    uint32 shard_dml_id; /* used for shard statement-level rollback */
    uint64 scn;
    bool8 is_log_longsql;
    cs_prepare_req_t *req;
#endif
} clt_stmt_t;

typedef struct st_clt_query {
    clt_stmt_t *query_stmt; // for single query
    list_t ids;             // for multiple query, local idx in connection's statement list
    uint32 pos;
} clt_query_t;

typedef struct st_clt_conn {
    spinlock_t parallel_lock; /* lock to ensure message exchange in connection is in Serial */
    uint32 sid;               // session id received from server
    uint32 serial;
    int64 last_insert_id;

    uint16 ready : 1;
    uint16 in_process : 1; /* connection is in calling */
    uint16 auto_commit : 1;
    uint16 exit_commit : 1;
    uint16 serveroutput : 1;
    uint16 interactive_clt : 1;
    uint16 auto_commit_xa_backup : 1; // backup the value of autocommit during opening XA, and restore it during ending
                                      // XA
    uint16 remote_as_sysdba : 1;      // support for remote connect as sysdba.
    uint16 ctsql_in_altpwd : 1;
    uint16 has_auth : 1;
    uint8 shd_rw_split; // flag of CN rw split, 0:not split,1:on master,2:on slave,3:on master or slave
    uint8 autotrace;    // flag of autotrace type, 0:OFF, 1:ON, 2:TRACEONLY
    source_location_t loc;
    int32 error_code;
    char message[CT_MESSAGE_BUFFER_SIZE];
    cs_packet_t pack; // for sending
    list_t pack_list; // 'clt_packet_t' list, for lob write/read, stmt receive.
    cs_pipe_t pipe;
    ptlist_t stmts;
    clt_query_t query;

    /* ssl info */
    clt_options_t options; // consider to move the options above into this structure
    uint32 server_capabilities;
    uint32 client_flag;
    uint32 server_version;
    uchar *ssl_connector; // connector for SSL

    uint32 call_version;       // communicate packet version
    uint32 serial_number_send; // check  conn  sending serial-number

    nlsparams_t nls_params; // equal / synchronize to session_t.nls_params
    ctconn_xact_status_t xact_status;
    uint32 num_width;
    uint16 local_charset;
    int16 local_sessiontz;
    cs_shd_node_type_t node_type; // node type for sharding , cn/dn/gts

    transcode_func_t send_trans_func; // send charset trans function, if same with server, it is NULL
    transcode_func_t recv_trans_func; // recv charset trans function, if same with server, it is NULL

    clt_server_info_t server_info; // information receive from server
    uint8 flag_with_ts;            // send gts_scn to server or not
    char curr_schema[CT_NAME_BUFFER_SIZE];
    void *node;
    alter_set_info_t alter_set_info;
} clt_conn_t;

#define CLT_CONN(conn) ((clt_conn_t *)(conn))

/* client set error */
static inline void clt_set_error(clt_conn_t *conn, const char *file, uint32 line, int32 code, const char *format, ...)
{
    va_list args;

    conn->error_code = code;
    conn->loc.line = 0;
    conn->loc.column = 0;

    va_start(args, format);
    PRTS_RETVOID_IFERR(vsnprintf_s(conn->message, CT_MESSAGE_BUFFER_SIZE, CT_MESSAGE_BUFFER_SIZE - 1, format, args));
    va_end(args);
}

#define CLT_SET_ERROR(conn, err_no, format, ...)                                                \
    {                                                                                           \
        clt_set_error(conn, (char *)__FILE__, (uint32)__LINE__, err_no, format, ##__VA_ARGS__); \
    }
#define CLT_THROW_ERROR(conn, err_no, ...)                                                                    \
    {                                                                                                         \
        clt_set_error(conn, (char *)__FILE__, (uint32)__LINE__, err_no, g_error_desc[err_no], ##__VA_ARGS__); \
    }
#define CLT_SET_LOCAL_ERROR(conn, ret)                  \
    do {                                                \
        status_t _status_ = (ret);                      \
        if (SECUREC_UNLIKELY(_status_ != CT_SUCCESS)) { \
            clt_copy_local_error(conn);                 \
            return _status_;                            \
        }                                               \
    } while (0)
/* check whether is null object */
#define CTCONN_CHECK_OBJECT_NULL_GS(obj_ptr, obj_name)             \
    {                                                           \
        if (SECUREC_UNLIKELY((obj_ptr) == NULL)) {              \
            CT_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, (obj_name)); \
            return CT_ERROR;                                    \
        }                                                       \
    }

#define CTCONN_CHECK_OBJECT_NULL_CLT(conn, obj_ptr, obj_name)             \
    {                                                                  \
        if (SECUREC_UNLIKELY((obj_ptr) == NULL)) {                     \
            CLT_THROW_ERROR(conn, ERR_CLT_OBJECT_IS_NULL, (obj_name)); \
            return CT_ERROR;                                           \
        }                                                              \
    }

// for ctconn check  serial_number
#define CS_SERIAL_NUMBER_INC(conn, req)                          \
    do {                                                         \
        (conn)->serial_number_send++;                            \
        (req)->head->serial_number = (conn)->serial_number_send; \
    } while (0)

typedef struct st_clt_column_desc {
    uint16 size;
    uint8 precision;
    int8 scale;
    uint16 datatype;
    bool8 nullable;
    bool8 auto_increment;
    bool8 is_character;
    bool8 is_array;
    bool8 is_jsonb;
    uint16 name_len;
    char name[CT_NAME_BUFFER_SIZE];
} clt_column_desc_t;

typedef struct st_clt_inline_lob {
    text_t cache_buf; /* clt_cache_lob_t(clt_lob_head_t + fetched_times + column_id + offset) */
    uint32 used_pos;
} clt_inline_lob_t;

struct st_clt_column;
typedef status_t (*copy_col_2_buf_t)(clt_stmt_t *stmt, struct st_clt_column *column);
typedef struct st_clt_column {
    char *ptr; // point to column value in packet
    struct {
        // for batch
        char *bnd_ptr;
        uint16 *ind_ptr;
        copy_col_2_buf_t cp_func;
    };
    uint16 id;
    uint16 size; // size of value fetched
    struct {
        // for batch
        uint16 bnd_size;
        uint8 bnd_type;
    };
    clt_column_desc_t def;
    clt_inline_lob_t inline_lob; // cache inline lob data
} clt_column_t;

typedef struct st_clt_output_item {
    text_t output;
    uint32 cache_len;
} clt_output_item_t;

typedef struct st_clt_param {
    char name[CT_NAME_BUFFER_SIZE];
    uint8 direction;
    uint8 bnd_type;
    bool8 is_W_CType; // false, is ansi type; true is SQL_C_WCHAR
    uint8 reserved;
    uint32 bnd_size;
    char *bnd_ptr;
    uint16 *ind_ptr;
    char *curr_ptr;
    char *lob_ptr;       // for string convert to lob to bind, malloc & free by ctconn
    uint32 lob_ptr_size; // number of vm_lob in lob_ptr
} clt_param_t;

typedef struct st_clt_outparam_desc {
    char name[CT_NAME_BUFFER_SIZE];
    uint16 size;
    uint8 direction;
    uint8 datatype;
} clt_outparam_desc_t;

typedef struct st_clt_outparam {
    clt_outparam_desc_t def;
    uint32 size;          // size of value fetched
    char *ptr;            // ptr of value fetched
    clt_stmt_t *sub_stmt; // for sys_refcursor
} clt_outparam_t;

typedef struct st_clt_rs_stmt {
    uint16 stmt_id; // stmt id
    uint8 fetch_mode;
    uint8 reserved;
} clt_rs_stmt_t;

typedef struct st_clt_batch_err {
    uint32 line;
    int32 err_code;
    char err_message[CT_MESSAGE_BUFFER_SIZE];
} clt_batch_error_t;

typedef struct __ctconn_stmt *ctconn_stmt_t; /* type of statement handle */
int ctconn_transcode_ucs2(ctconn_stmt_t pstmt, const void *src, uint32 *src_len, void *dst, uint32 dst_len, bool32 *eof);
int ctconn_encrypt_password(char *orig_pswd, unsigned int orig_len, char *rand_local_key, char *rand_factor_key,
    char *cipher, unsigned int *cipher_len);
int ctconn_decrypt_password(char *pswd, unsigned int len, char *rand_local_key, char *rand_factor_key, char *cipher,
    unsigned int cipher_len);
int ctconn_set_charset(ctconn_stmt_t pstmt, uint16 charset_id);
void clt_free_pack(clt_conn_t *conn, clt_packet_t *clt_pack);
void clt_copy_local_error(clt_conn_t *conn);
status_t clt_receive_serveroutput(clt_stmt_t *stmt, cs_packet_t *ack);
status_t clt_reset_stmt_transcode_buf(clt_stmt_t *stmt);
status_t clt_alloc_pack(clt_conn_t *conn, clt_packet_t **clt_pack);
status_t ctconn_write_sql(clt_stmt_t *stmt, const char *sql, uint32 total_size, uint32 *curr_size, cs_packet_t *req_pack);
status_t clt_set_conn_transcode_func(clt_conn_t *conn);
status_t clt_get_execute_ack(clt_stmt_t *stmt);
status_t clt_get_prepare_ack(clt_stmt_t *stmt, cs_packet_t *pack, const text_t *sql);
status_t clt_remote_call(clt_conn_t *conn, cs_packet_t *req, cs_packet_t *ack);
status_t clt_desc_column_by_id(clt_stmt_t *stmt, uint32 id, ctconn_column_desc_t *desc);
status_t clt_get_column_by_id(clt_stmt_t *stmt, uint32 id, void **data, uint32 *size, bool32 *is_null);
status_t clt_try_process_feedback(clt_stmt_t *stmt, cs_packet_t *ack);
status_t clt_verify_lob(clt_stmt_t *stmt, uint32 pos, clt_param_t **param);
status_t clt_transcode_column(clt_stmt_t *stmt, char **data, uint32 *size, transcode_func_t transcode_func);
status_t clt_try_get_batch_error(clt_stmt_t *stmt, cs_execute_ack_t *exec_ack, uint32 line_offset);
status_t cs_put_alter_set(cs_packet_t *req_pack, clt_stmt_t *stmt);
status_t clt_read_ack(clt_conn_t *conn, cs_packet_t *ack);
status_t clt_async_get_ack(clt_conn_t *conn, cs_packet_t *ack);
status_t clt_extend_param_list(clt_stmt_t *stmt, uint32 count);

/* lock to ensure message exchange in connection is in Serial */
static inline status_t clt_lock_conn(clt_conn_t *conn)
{
    if (conn->in_process) {
        CLT_THROW_ERROR(conn, ERR_CLT_PARALLEL_LOCK, conn->sid, cm_get_current_thread_id());
        return CT_ERROR;
    }
    /* thread may race here */
    cm_spin_lock(&(conn->parallel_lock), NULL);
    if (conn->in_process) {
        CLT_THROW_ERROR(conn, ERR_CLT_PARALLEL_LOCK, conn->sid, cm_get_current_thread_id());
        cm_spin_unlock(&(conn->parallel_lock));
        return CT_ERROR;
    }
    conn->in_process = CT_TRUE;
    cm_spin_unlock(&(conn->parallel_lock));
    return CT_SUCCESS;
}

static inline void clt_unlock_conn(clt_conn_t *conn)
{
    cm_spin_lock(&(conn->parallel_lock), NULL);
    conn->in_process = CT_FALSE;
    cm_spin_unlock(&(conn->parallel_lock));
}

static inline void clt_reset_error(clt_conn_t *conn)
{
    conn->error_code = ERR_ERRNO_BASE;
    conn->message[0] = '\0';
    cm_reset_error();
}

static inline void clt_reset_lob(ctconn_lob_t *lob)
{
    if (lob == NULL) {
        return;
    }

    lob->size = 0;
    lob->type = CT_LOB_FROM_VMPOOL;
    lob->entry_vmid = CT_INVALID_ID32; // reversing(big/little endian) is not necessary
    lob->last_vmid = CT_INVALID_ID32;  // reversing(big/little endian) is not necessary
}

static inline void clt_reset_batch_lob(ctconn_lob_t *lob, uint32 paramset_size)
{
    uint32 i;

    if (lob == NULL) {
        return;
    }

    for (i = 0; i < paramset_size; i++) {
        clt_reset_lob(&lob[i]);
    }
}

/* malloc dst and copy from src */
static inline status_t clt_strndup(const void *data, uint32 len, char **res)
{
    char *dupstr = NULL;

    if (data == NULL || len == 0 || len == CT_MAX_UINT32) {
        *res = NULL;
        return CT_SUCCESS;
    }

    dupstr = (char *)malloc(len + 1);
    if (dupstr == NULL) {
        CT_THROW_ERROR(ERR_MALLOC_BYTES_MEMORY, len + 1);
        return CT_ERROR;
    }

    if (memcpy_s(dupstr, len, data, len) != EOK) {
        CM_FREE_PTR(dupstr);
        CT_THROW_ERROR(ERR_MALLOC_BYTES_MEMORY, len + 1);
        return CT_ERROR;
    }

    dupstr[len] = '\0';
    *res = dupstr;
    return CT_SUCCESS;
}

static inline char *clt_strdup(const char *s)
{
    char *result = NULL;
    if (s == NULL) {
        return NULL;
    }
    if (clt_strndup((const void *)s, (uint32)strlen(s), &result) != CT_SUCCESS) {
        return NULL;
    }
    return result;
}

/* set or get session NLS parameters */
static inline void clt_session_nlsparam_geter(clt_stmt_t *stmt, nlsparam_id_t id, text_t *text)
{
    const clt_conn_t *conn = stmt->conn;
    conn->nls_params.param_geter(&conn->nls_params, id, text);
}

static inline uint32 clt_prefetch_rows(clt_stmt_t *stmt)
{
    return (stmt->fetch_size > CT_INIT_PREFETCH_ROWS && stmt->fetch_size > stmt->prefetch_rows) ? stmt->fetch_size :
                                                                                                  stmt->prefetch_rows;
}

status_t clt_get_error_message(clt_conn_t *conn, cs_packet_t *pack, char *err_msg);

#ifdef __cplusplus
}
#endif

#endif
