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
 * ctconn.h
 *
 *
 * IDENTIFICATION
 * src/driver/ctconn/ctconn.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CTCONN_H__
#define __CTCONN_H__

#include <stdio.h>
#include <stdlib.h>
#include "cm_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* handle */
struct __ctconn_conn;
struct __ctconn_stmt;
struct __ctconn_desc;
struct __ctconn_datetime;
typedef struct __ctconn_conn *ctconn_conn_t;         /* type of connection handle */
typedef struct __ctconn_stmt *ctconn_stmt_t;         /* type of statement handle */
typedef struct __ctconn_desc *ctconn_desc_t;         /* type of description handle */
typedef struct __ctconn_datetime *ctconn_datetime_t; /* type of dateime handle */

/* data types */
typedef enum en_ctconn_type {
    CTCONN_TYPE_UNKNOWN = 0,            /* invalid value */
    CTCONN_TYPE_INTEGER = 1,            /* native 32 bits integer */
    CTCONN_TYPE_BIGINT = 2,             /* native 64 bits integer */
    CTCONN_TYPE_REAL = 3,               /* native float */
    CTCONN_TYPE_NUMBER = 4,             /* number */
    CTCONN_TYPE_DECIMAL = 5,            /* decimal, internal used */
    CTCONN_TYPE_DATE = 6,               /* datetime, 7 bytes */
    CTCONN_TYPE_TIMESTAMP = 7,          /* timestamp */
    CTCONN_TYPE_CHAR = 8,               /* char(n) */
    CTCONN_TYPE_VARCHAR = 9,            /* varchar, varchar2 */
    CTCONN_TYPE_STRING = 10,            /* native char * */
    CTCONN_TYPE_BINARY = 11,            /* binary */
    CTCONN_TYPE_VARBINARY = 12,         /* varbinary */
    CTCONN_TYPE_CLOB = 13,              /* clob */
    CTCONN_TYPE_BLOB = 14,              /* blob */
    CTCONN_TYPE_CURSOR = 15,            /* resultset, for procedure */
    CTCONN_TYPE_COLUMN = 16,            /* column type, internal used */
    CTCONN_TYPE_BOOLEAN = 17,           /* bool, value can be 1 or 0 */
    CTCONN_TYPE_TIMESTAMP_TZ_FAKE = 18, /* fake, equals to timestamp */
    CTCONN_TYPE_TIMESTAMP_LTZ = 19,     /* timestamp with local time zone */
    CTCONN_TYPE_INTERVAL = 20,          /* interval of pg style */
    CTCONN_TYPE_INTERVAL_YM = 21,       /* interval YEAR TO MONTH */
    CTCONN_TYPE_INTERVAL_DS = 22,       /* interval DAY TO SECOND */
    CTCONN_TYPE_RAW = 23,
    CTCONN_TYPE_IMAGE = 24,        /* image, equals to longblob */
    CTCONN_TYPE_UINT32 = 25,       /* unsigned integer */
    CTCONN_TYPE_TIMESTAMP_TZ = 32, /* timestamp with time zone */
    CTCONN_TYPE_ARRAY = 33,        /* array */
    CTCONN_TYPE_NUMBER2 = 34,      /* number2 */
    CTCONN_TYPE_RECORD = 101,      /* record */
    CTCONN_TYPE_COLLECTION = 102,  /* collection */
    CTCONN_TYPE_OBJECT = 103,      /* object */
    CTCONN_TYPE_NATIVE_DATE = 205, /* native datetime, internal used */
} ctconn_type_t;

/* bound size of special data type needs convert to string buffer */
#define CTCONN_NUMBER_BOUND_SIZE (int)50
#define CTCONN_TIME_BOUND_SIZE (int)60
#define CTCONN_BOOL_BOUND_SIZE (int)6
#define CTCONN_YM_INTERVAL_BOUND_SIZE (int)10
#define CTCONN_DS_INTERVAL_BOUND_SIZE (int)24

/* stmt types */
typedef enum en_ctconn_stmt_type {
    CTCONN_STMT_NONE = 0,
    CTCONN_STMT_DML = 1, /* select/insert/delete/update/merge/replace, etc */
    CTCONN_STMT_DCL = 2,
    CTCONN_STMT_DDL = 3,
    CTCONN_STMT_PL = 4,
    CTCONN_STMT_EXPLAIN = 5, /* explain [plan for] + DML */
} ctconn_stmt_type_t;

/* null value */
#define CTCONN_NULL (unsigned short)0xFFFF

/* direction of bind, default is CTCONN_INPUT */
#define CTCONN_INPUT (unsigned char)1
#define CTCONN_OUTPUT (unsigned char)2
#define CTCONN_INOUT (unsigned char)3

/* description of column */
/* users can use 'ctconn_get_desc_attr' instead of 'ctconn_desc_column_by_id' */
typedef struct st_ctconn_column_desc {
    char *name;
    unsigned short size;
    unsigned char precision;
    char scale;
    unsigned short type;
    unsigned char nullable;
    unsigned char is_character;
} ctconn_column_desc_t;

/* description of output in procedure */
typedef struct st_ctconn_output_desc {
    char *name;
    unsigned short size;
    unsigned char direction;
    unsigned char type;
} ctconn_outparam_desc_t;

/* lob bind value */
typedef struct st_ctconn_lob {
    unsigned int size;
    unsigned int type;
    unsigned int entry_vmid;
    unsigned int last_vmid;
} ctconn_lob_t;

typedef struct st_ctconn_sequence {
    unsigned int group_order;
    unsigned int group_cnt;
    unsigned int size;
#ifdef WIN32
    __int64 start_val;
    __int64 step;
    __int64 end_val;
#else
    long long start_val;
    long long step;
    long long end_val;
#endif
} ctconn_sequence_t;

typedef enum en_ctconn_ssl_mode {
    CTCONN_SSL_DISABLED = 0,
    CTCONN_SSL_PREFERRED,
    CTCONN_SSL_REQUIRED,
    CTCONN_SSL_VERIFY_CA,
    CTCONN_SSL_VERIFY_FULL
} ctconn_ssl_mode_t;

/* description type */
typedef enum en_ctconn_desc_type {
    CTCONN_DESC_OBJ = 0,
    CTCONN_DESC_TABLE,
    CTCONN_DESC_VIEW,
    CTCONN_DESC_SYN,   /* synonym */
    CTCONN_DESC_QUERY, /* query */
    CTCONN_DESC_PROC,  /* procedure */
    CTCONN_DESC_FUNC,  /* function */
    CTCONN_DESC_PKG,   /* package */
    CTCONN_DESC_SEQ,   /* sequence */
} ctconn_desc_type_t;

typedef enum en_ctconn_shd_rw_split {
    CTCONN_SHD_RW_SPLIT_NONE = 0, // shard rw split not set
    CTCONN_SHD_RW_SPLIT_RW,       // read and write
    CTCONN_SHD_RW_SPLIT_ROS,      // read on slave dn
    CTCONN_SHD_RW_SPLIT_ROA       // read on master dn or slave dn
} ctconn_shd_rw_split_t;

/* connection attributes */
#define CTCONN_ATTR_AUTO_COMMIT \
    (int)101 /* specifies auto commit after execute, default is auto commit off , Attribute Datatype: unsigned int */
#define CTCONN_ATTR_XACT_STATUS (int)102 /* currently not enabled */
#define CTCONN_ATTR_EXIT_COMMIT                                                                                      \
    (int)103 /* enable for ctsql, for whether do commit when ctsql is quit, default is enable , Attribute Datatype: \
                unsigned int */
#define CTCONN_ATTR_SERVEROUTPUT                                                                                      \
    (int)104 /* whether enable returns dbe_output.print_line in procedure, default is disable, Attribute Datatype: \
                unsigned int */
#define CTCONN_ATTR_CHARSET_TYPE                                                                                     \
    (int)105 /* set charset type of client, currently supports UTF8 or GBK, default is UTF8 , Attribute Datatype: \
                char*, Length: unsigned int */
#define CTCONN_ATTR_NUM_WIDTH (int)106 /* enable for ctsql, for display numeric value , Attribute Datatype: unsigned int \
                                     */
#define CTCONN_ATTR_INTERACTIVE_MODE                                                                    \
    (int)107 /* whether enable interactive timeout, default is disable. timeout depends on parameter \
                INTERACTIVE_TIMEOUT , Attribute Datatype: unsigned char */
#define CTCONN_ATTR_LOB_LOCATOR_SIZE (int)108 /* specifies the size of LOB locator , Attribute Datatype: unsigned int */
#define CTCONN_ATTR_SSL_CA                                                                                            \
    (int)109 /* file that contains list of trusted SSL Certificate Authorities, Attribute Datatype: char*, Length: \
                unsigned int */
#define CTCONN_ATTR_SSL_CERT \
    (int)110 /* file that contains X.509 certificate, Attribute Datatype: char*, Length: unsigned int */
#define CTCONN_ATTR_SSL_KEY (int)111  /* file that contains X.509 key, Attribute Datatype: char*, Length: unsigned int */
#define CTCONN_ATTR_SSL_MODE (int)112 /* security state of connection to server, Attribute Datatype: unsigned int */
#define CTCONN_ATTR_SSL_CRL \
    (int)113 /* file that contains certificate revocation lists, Attribute Datatype: char*, Length: unsigned int */
#define CTCONN_ATTR_SSL_KEYPWD                                                                                       \
    (int)114 /* the pwd for SSL key file. If the SSL key file is protected by a pass phrase, use the attribute to \
                specify the pwd, Attribute Datatype: char*, Length: unsigned int */
#define CTCONN_ATTR_SSL_CIPHER                                                                                          \
    (int)115 /* list of permitted ciphers for connection encryption, Attribute Datatype: char*, Length: unsigned int \
              */
#define CTCONN_ATTR_CONNECT_TIMEOUT                                                                                       \
    (int)116 /* connection timeout when create socket to server, unit is second, default is 10, -1 means not timeout , \
                Attribute Datatype: int */
#define CTCONN_ATTR_SOCKET_TIMEOUT                                                                                 \
    (int)117 /* socket timeout when execute sql, unit is second, default is -1, -1 means not timeout, Attribute \
                Datatype: int */
#define CTCONN_ATTR_APP_KIND (int)118        /* specifies client type of client, default is 1, Attribute Datatype: short */
#define CTCONN_ATTR_DBTIMEZONE (int)119      /* DBTIMEZONE, Attribute Datatype: short */
#define CTCONN_ATTR_UDS_SERVER_PATH (int)120 /* specifies unix domain socket server file path */
#define CTCONN_ATTR_UDS_CLIENT_PATH (int)121 /* specifies unix domain socket client file path */
#define CTCONN_ATTR_TIMESTAMP_SIZE (int)122  /* get inner timestamp bind size */
#define CTCONN_ATTR_TIMESTAMP_TZ_SIZE (int)123  /* get inner timestamp_tz bind size */
#define CTCONN_ATTR_TIMESTAMP_LTZ_SIZE (int)124 /* get inner timestamp_ltz bind size */
#define CTCONN_ATTR_FLAG_WITH_TS (int)125
#define CTCONN_ATTR_REMOTE_AS_SYSDBA (int)126
#define CTCONN_ATTR_SHD_RW_FLAG (int)127 /* flag of CN rw split, 0:not split,1:on master,2:on slave,3:on master or slave \
                                       */
#define CTCONN_ATTR_LAST_INSERT_ID                                                                                      \
    (int)128 /* the value generated by the AUTO INCREMENT column of the last INSERT statement in the current session \
              */
#define CTCONN_ATTR_SOCKET_L_ONOFF (int)129  /* SO_LINGER l_onoff value */
#define CTCONN_ATTR_SOCKET_L_LINGER (int)130 /* SO_LINGER l_linger value */
#define CTCONN_ATTR_AUTOTRACE (int)131       /* enable autotrace */

/* The order of NLS can not be changed */
#define CTCONN_ATTR_NLS_CALENDAR (int)160
#define CTCONN_ATTR_NLS_CHARACTERSET (int)161
#define CTCONN_ATTR_NLS_COMP (int)162
#define CTCONN_ATTR_NLS_CURRENCY (int)163
#define CTCONN_ATTR_NLS_DATE_FORMAT (int)164
#define CTCONN_ATTR_NLS_DATE_LANGUAGE (int)165
#define CTCONN_ATTR_NLS_DUAL_CURRENCY (int)166
#define CTCONN_ATTR_NLS_ISO_CURRENCY (int)167
#define CTCONN_ATTR_NLS_LANGUAGE (int)168
#define CTCONN_ATTR_NLS_LENGTH_SEMANTICS (int)169
#define CTCONN_ATTR_NLS_NCHAR_CHARACTERSET (int)170
#define CTCONN_ATTR_NLS_NCHAR_CONV_EXCP (int)171
#define CTCONN_ATTR_NLS_NUMERIC_CHARACTERS (int)172
#define CTCONN_ATTR_NLS_RDBMS_VERSION (int)173
#define CTCONN_ATTR_NLS_SORT (int)174
#define CTCONN_ATTR_NLS_TERRITORY (int)175
#define CTCONN_ATTR_NLS_TIMESTAMP_FORMAT (int)176
#define CTCONN_ATTR_NLS_TIMESTAMP_TZ_FORMAT (int)177
#define CTCONN_ATTR_NLS_TIME_FORMAT (int)178
#define CTCONN_ATTR_NLS_TIME_TZ_FORMAT (int)179

/* statement attributes */
#define CTCONN_ATTR_PREFETCH_ROWS (int)201   /* number of top level rows to be prefetched */
#define CTCONN_ATTR_PREFETCH_BUFFER (int)202 /* memory level for top level rows to be prefetched (useless) */
#define CTCONN_ATTR_PARAMSET_SIZE (int)203   /* number of array bind data for batch bind, default is 1 */
#define CTCONN_ATTR_FETCHED_ROWS                                                                                         \
    (int)204 /* indicates the number of rows that were successfully fetched into the user's buffers in the last fetch \
              */
#define CTCONN_ATTR_AFFECTED_ROWS                                                                                     \
    (int)205 /* returns the number of rows processed so far after SELECT statements. For INSERT, UPDATE and DELETE \
                statements, it is the number of rows processed by the most recent statement */
#define CTCONN_ATTR_RESULTSET_EXISTS (int)206 /* returns whether has query result */
#define CTCONN_ATTR_COLUMN_COUNT (int)207     /* returns the columns count of query */
#define CTCONN_ATTR_STMT_TYPE \
    (int)208 /* the type of statement associated with the handle, valid values defined in ctconn_stmt_type_t */
#define CTCONN_ATTR_PARAM_COUNT (int)209 /* returns the params count */
#define CTCONN_ATTR_MORE_ROWS (int)210 /* whether has more query rows or not, 0 means has no more rows, 1 means has more \
                                     */
#define CTCONN_ATTR_STMT_EOF (int)211  /* specifies whether stmt is fetch over or not */
#define CTCONN_ATTR_OUTPARAM_COUNT (int)212 /* count of outparams in procedure */
#define CTCONN_ATTR_SEROUTPUT_EXISTS                                                                                    \
    (int)213 /* whether returns dbe_output.print_line or not, used in procedure. default is disable returns and need \
                use CTCONN_ATTR_SERVEROUTPUT to enable returns */
#define CTCONN_ATTR_RETURNRESULT_EXISTS (int)214 /* whether returns dbe_sql.return_cursor or not, used in procedure */
#define CTCONN_ATTR_ALLOWED_BATCH_ERRS (int)215  /* allowed batch errors when do execute batch */
#define CTCONN_ATTR_ACTUAL_BATCH_ERRS (int)216   /* returns the actual batch errors after execute batch */
#define CTCONN_ATTR_FETCH_SIZE \
    (int)217 /* number of rows to be fetched from the current position for batch fetch, default is 1 */
#define CTCONN_ATTR_SHARD_DML_ID (int)218 /* id of cn dispatch dml to dn */

/* describe attributes */
#define CTCONN_ATTR_NAME (int)301       // column name ,Attribute Datatype: char*, Length: int
#define CTCONN_ATTR_DATA_SIZE (int)302  /* column size ,Attribute Datatype: unsigned short */
#define CTCONN_ATTR_PRECISION (int)303  /* column precision ,Attribute Datatype: unsigned char */
#define CTCONN_ATTR_SCALE (int)304      /* column scale ,Attribute Datatype: unsigned char */
#define CTCONN_ATTR_DATA_TYPE (int)305  /* column data type ,Attribute Datatype: unsigned short */
#define CTCONN_ATTR_NULLABLE (int)306   /* column is nullable ,Attribute Datatype: unsigned char */
#define CTCONN_ATTR_CHAR_USED (int)307  /* column is character ,Attribute Datatype: unsigned char */
#define CTCONN_ATTR_ARRAY_USED (int)308 /* column is array ,Attribute Datatype: unsigned char */

/* return code */
#define CTCONN_SUCCESS (int)0
#define CTCONN_SUCCESS_WITH_INFO (int)1
#define CTCONN_ERROR (int)(-1)

/*
    Definition: create a connection object
    Input_param:
        conn: connection object
    Output_param:
        conn: connection object
    Return value:
        0:   success
        !=0: failed
    Description: Creates a connection object and use it to invoke ctconn_connect to connect to the database
*/
int ctconn_alloc_conn(ctconn_conn_t *pconn);

/*
    Definition: release the connection object
    Input_param:
        conn: connection object
    Return value:
    Description: Releases a connection object. This API is invoked after the ctconn_disconnect (database disconnection)
   operation is performed
*/
void ctconn_free_conn(ctconn_conn_t pconn);

/*
    Definition: set connection attributes
    Input_param:
        conn: connection object
        attr: connection attributes
        data: attribute value
        len:  attribute size
    Return value:
        0:   success
        !=0: failed
    Description: interface is used to set the connection attribute,
                 such as: CTCONN_ATTR_AUTO_COMMIT-transaction commit method (1 means automatic commit, 0 means manual
   commit)
*/
int ctconn_set_conn_attr(ctconn_conn_t pconn, int32 attr, const void *data, uint32 len);

/*
    Definition: get connection attributes
    Input_param:
        conn: connection object
        attr:connection attribute
    Output parameter:
        data: attribute value
        len : attribute size
    Return value:
        0:   success
        !=0: failed
    Description: interface is used to obtain the connection attribute,
                 such as: CTCONN_ATTR_AUTO_COMMIT-transaction commit method (1 indicates automatic commit, 0 indicates
   manual commit)
*/
int ctconn_get_conn_attr(ctconn_conn_t pconn, int32 attr, void *data, uint32 len, uint32 *attr_len);

/*
    Definition: Get error code and error message through connection
    Input_param:
        conn: connection object
    Output parameters:
        code: error code
        message: error message
    Return value:
    Description: Interface used to obtain error codes and error messages by the connection
*/
void ctconn_get_error(ctconn_conn_t pconn, int32 *code, const char **message);

/*
    Definition: Get the location and column information of an error in the execution SQL through a connection
    Input_param:
        conn: connection object
    Output:
        line: error location information
        column: error column information
    Return value:
    Description: interface is used to obtain the location and column information of the error in the execution SQL
   through the connection, used to locate the reason of the SQL error
*/
void ctconn_get_error_position(ctconn_conn_t pconn, uint16 *line, uint16 *column);

/*
    Definition: get error message through connection
    Input_param:
        conn: connection object
    Return value:
        message: error message
    Description: interface is used to obtain the error message by conn. If the passed conn is NULL, the returned message
   is NULL.
*/
char *ctconn_get_message(ctconn_conn_t pconn);

/*
    Definition: Connect to the database
    Input_param:
        conn: connection object
        url:  connection address information
        user: connection username
        pwd:  connection pwd
    Return value:
        0:   success
        !=0: failed
    Description: Connects to the database. The URL format is ip:port and only supports TCP connections
*/
int ctconn_connect(ctconn_conn_t pconn, const char *url, const char *user, const char *password);

/*
    Definition: disconnect the database
    Input_param:
        conn: connection object
    Return value:
    Description: Interface used to disconnect the database
*/
void ctconn_disconnect(ctconn_conn_t pconn);

/*
    Definition: get session ID
    Input_param:
        conn: connection object
    Return value: session ID
    Description: interface is used to obtain the session ID which uniquely identifies a connection. If the conn is NULL,
   returns invalid sid
*/
unsigned int ctconn_get_sid(ctconn_conn_t pconn);

/*
    Definition: cancel the statement being executed
    Input_param:
        conn: connection object
        Sid: session ID
    Return value:
        0 success
        !=0 failed
    Description: interface is used to cancel operations on the connection for the specified session ID
*/
int ctconn_cancel(ctconn_conn_t pconn, uint32 sid);

/*
    Definition: apply handle object
    Input_param:
        conn: connection object
    Output parameter:
        stmt: handle object
    Return value:
        0:  success
        !=0: failed
    Description: interface is used to create a handle object, and then use the handle object to execute SQL.
*/
int ctconn_alloc_stmt(ctconn_conn_t pconn, ctconn_stmt_t *pstmt);

/*
    Definition: release handle object
    Input_param:
        stmt: handle object
    Return value:
    Description: interface is used to release the handle object
*/
void ctconn_free_stmt(ctconn_stmt_t pstmt);

/*
    Definition: Set the handle attribute
    Input_param:
        stmt: handle object
        attr: handle attribute
        data: attribute value
        len:  attribute size
    Return value:
         0: success
        !0: failed
    Description: interface is used to set the handle attribute,
                 such as: CTCONN_ATTR_PREFETCH_ROWS--->number of prefetch records,
                          CTCONN_ATTR_PREFETCH_BUFFER--->prefetch record size,
                          CTCONN_ATTR_PARAMSET_SIZE--->Batch Parameter Bindings
*/
int ctconn_set_stmt_attr(ctconn_stmt_t pstmt, int attr, const void *data, uint32 len);

/*
    Definition: get the handle attribute
    Input_param:
        stmt: handle object
        attr: handle attribute
        data: attribute value
        len:  attribute size
    Return value:
         0: success
        !0: failed
    Description: interface is used to set the handle attribute,
                 such as: CTCONN_ATTR_PREFETCH_ROWS--->number of prefetch records,
                          CTCONN_ATTR_PREFETCH_BUFFER--->prefetch record size,
                          CTCONN_ATTR_PARAMSET_SIZE--->Batch Parameter Bindings
*/
int ctconn_get_stmt_attr(ctconn_stmt_t pstmt, int attr, const void *data, uint32 buf_len, uint32 *len);

/*
    Definition: Preprocessing SQL statements
    Input_param:
        stmt: handle object
         Sql: SQL statement
    Return value:
        0:   success
        !=0: failed
    Description: Interface for preprocessing SQL statements
*/
int ctconn_prepare(ctconn_stmt_t pstmt, const char *sql);

/*
     Definition: parameter binding by parameter position
     Input_param:
        stmt: handle object
        pos:  The position number of the parameter, starting from 0
        type: data type, from type definition ctconn_type_t except CTCONN_TYPE_TIMESTAMP which will be added in next version
        data: Address of data value or address of data array
        size: buffer length
        ind:  length address or length array address
        direction: direction of bind parameter
     Return value:
        0: success
        !=0: failed
     Description: interface is used for parameter binding through the parameter location. The usage of ctconn_bind_by_name
   and ctconn_bind_by_pos is basically the same, but there are some differences. For parameters of the same parameter name,
   you can use ctconn_bind_by_name to bind once, and ctconn_bind_by_pos must bind every parameter. If use ctconn_bind_by_pos,
   default direction is 1(input parameter). If need bind parameter with direction, need use ctconn_bind_by_pos2. Value of
   direction can be 1(input parameter), 2(outut parameter) or 3(inout parameter).
*/
int ctconn_bind_by_pos(ctconn_stmt_t pstmt, uint32 pos, int type, const void *data, int32 size, uint16 *ind);
int ctconn_bind_by_pos2(ctconn_stmt_t pstmt, uint32 pos, int type, const void *data, int32 size, uint16 *ind,
                     int32 direction);

/*
     Definition: parameter binding by parameter position
     Input_param:
        stmt: handle object
        pos:  The position number of the parameter, starting from 0
        type: data type, from type definition ctconn_type_t
        data: Address of data value or address of data array
        size: buffer length
        ind:  length address or length array address
        direction: direction of bind
     Return value:
        0: success
        !=0: failed
    Description: interface is used for parameter binding by parameter name. If NULL is bound, the corresponding ind[i]
   of the data needs to be set to CTCONN_NULL.
*/
int ctconn_bind_by_name(ctconn_stmt_t pstmt, const char *name, int type, const void *data, int32 size, uint16 *ind);
int ctconn_bind_by_name2(ctconn_stmt_t pstmt, const char *name, int type, const void *data, int32 size, uint16 *ind,
                      int32 direction);

/*
    Definition: Get the number of query columns
    Input_param:
        stmt: handle object
    Output_param:
        column_count: the number of query columns
    Return value:
        0: success
        !=0: failed
    Description: interface is used to get the number of query columns, only valid for the query
*/
int ctconn_get_column_count(ctconn_stmt_t pstmt, uint32 *column_count);

/*
    Definition: Get query column description information according to query column serial number
    Input_param:
        stmt: handle object
        Id:   query column serial number, starting from 0
    Output:
        desc: query column description
    Return value:
        0:   success
        !=0: failed
    Description: interface is used to obtain query column description information (column name, column data type, column
   size, etc.) based on the query column ordinal number, valid only for the query.
*/
int ctconn_desc_column_by_id(ctconn_stmt_t pstmt, uint32 id, ctconn_column_desc_t *desc);

/*
    Definition: Get the query column description based on the query name
    Input_param:
        stmt: handle object
        col_name: query column name
    Output:
        desc: query column description
    Return value:
        0: success
        !=0: failed
    Description: interface is used to obtain query column description information (column name, column data type, column
   size, etc.) based on the query name, only valid for the query.
*/
int ctconn_desc_column_by_name(ctconn_stmt_t pstmt, const char *col_name, ctconn_column_desc_t *desc);

/*
    Definition: Get the query column description based on the query attribute
    Input_param:
        stmt: handle object
        id: query column id
        attr: query attribute
    Output:
        data: query data buffer pointer
        len: query data actual length (CTCONN_ATTR_NAME, it means name length)
    Return value:
        0: success
        !=0: failed
    Description: interface is used to obtain query column description information
        (column name, column data type, column size, etc.) based on the query attribute,
        only valid for the query.
*/
int ctconn_get_desc_attr(ctconn_stmt_t pstmt, uint32 id, int32 attr, void *data, uint32 *len);

/*
    Definition: Get the value of a specific query column based on the query column ordinal
    Input_param:
        stmt: handle object
        id: query column serial number, starting from 0
    Output_param:
        data: query column data
        size: query column size
        is_null: query column value is NULL
    Return value:
        0: success
        !=0: failed
    Description: interface is used to obtain the value of a specific query column based on the query column ordinal. It
   is valid only for queries. Size is determined by the column data type. For example, int is 4 bytes, bigint is 8
   bytes, and string is variable length.
*/
int ctconn_get_column_by_id(ctconn_stmt_t pstmt, unsigned int id, void **data, unsigned int *size, bool32 *is_null);

/*
    Definition: Get the value of a specific query column based on the query column name
    Input_param:
        stmt: handle object
        id: query column serial number, starting from 0
    Output_param:
        data: query column data
        size: query column size
        is_null: query column value is NULL
    Return value:
        0: success
        !=0: failed
    Description: interface is used to obtain the value of a specific query column based on the query column ordinal. It
   is valid only for queries.
*/
int ctconn_get_column_by_name(ctconn_stmt_t pstmt, const char *col_name, void **data, uint32 *size, uint32 *is_null);

/*
    Definition: Get the number of rows affected
    Input_param:
        stmt: handle object
    Return value:
        The number of rows affected
    Description: interface is used to obtain the number of rows affected. For insert, delete, and update, affect_rows
   indicates the number of rows inserted, deleted, and updated. For select and explain plan statements, affect_rows
   indicates the number of rows in the current fetch, not the number of rows that can eventually be fetched.
*/
unsigned int ctconn_get_affected_rows(ctconn_stmt_t pstmt);

/*
    Definition: Get the query column value obtained from the query column serial number as a string
    Input_param:
        stmt: handle object
        id: query column serial number, starting from 0
        format: string output format, only for the date and time type query column
        str: store query column value memory address
        buf_size: store query column value memory size
    Return value:
        0: success
        !=0: failed
    Description: interface is used to obtain the query column value obtained from the query column serial number in a
   string manner. For the date and time type column, the output format can also be executed. If not specified, the
   default date_format="YYYY-MM-DD HH24:MI:SS",timestamp_format="YYYY-MM-DD HH24:MI:SS.FF"
*/
int ctconn_column_as_string(ctconn_stmt_t pstmt, uint32 id, char *str, uint32 buf_size);

/*
    Definition: This call specifies additional attributes necessary for a static array define, used in an array of
   structures (multi-row, multi-column) fetch Input_param: stmt: handle object id: query column serial number, starting
   from 0 bind_type: data type expected to get column value bind_size: size of one item of array bind_ptr:  address of
   memory to store query column value ind_ptr:   length address or length array address Return value: 0: success
        !=0: failed
    Description: interface is used to multi-row or multi-column fetch. Number of array of bind_ptr or ind_ptr depends on
   attr CTCONN_ATTR_FETCH_SIZE. Bind_type can be same with data type of column definition or likely, such as number or date
   or string.
*/
int ctconn_bind_column(ctconn_stmt_t pstmt, uint32 id, uint16 bind_type, uint16 bind_size, void *bind_ptr,
                    uint16 *ind_ptr);

/*
    Definition: Execute SQL statement
    Input_param:
        stmt: handle object
    Return value:
        0: success
        !=0: failed
    Description: interface is used to execute the SQL statement. If the connection is an automatic commit method, the
   transaction is committed or rolled back immediately after the operations of inserting, deleting, and updating are
   performed. No need to commit or rollback manually.
*/
int ctconn_execute(ctconn_stmt_t pstmt);

/*
    Definition: Get a query record row
    Input_param:
        stmt: handle object
    The parameter:
        rows: Returns the number of query records
    Return value:
        0: success
        !=0: failed
    Description: interface is used to obtain a query record row, rows value is>=0
*/
int ctconn_fetch(ctconn_stmt_t pstmt, uint32 *rows);

/*
    Definition: Submit a transaction that has not ended
    Input_param:
        conn: connection object
    Return value:
        0: success
        !=0: failed
    Description: Interface used to commit transactions that have not yet ended
*/
int ctconn_commit(ctconn_conn_t pconn);

/*
    Definition: rollback a transaction that has not ended
    Input_param:
        conn: connection object
    Return value:
        0: success
        !=0: failed
    Description: Interface used to rollback transactions that have not yet ended
*/
int ctconn_rollback(ctconn_conn_t pconn);

/*
    Definition: Set whether to automatically commit the transaction after the current operation
    Input_param:
    conn: connection object
    auto_commit: is or not auto
    Return value:
    Description: interface is used to set whether the transaction is committed automatically after the current
   operation. Usage is equivalent to ctconn_set_conn_attr setting CTCONN_ATTR_AUTO_COMMIT
*/
void ctconn_set_autocommit(ctconn_conn_t pconn, bool32 auto_commit);

/*
    Definition: Set batch parameter binding number
    Input_param:
    stmt: handle object
    sz: batch parameter binding number
    Return value:
    Description: interface is used to set the number of batch parameter bindings, usage is equivalent to
   ctconn_set_stmt_attr set CTCONN_ATTR_PARAMSET_SIZE
*/
void ctconn_set_paramset_size(ctconn_stmt_t pstmt, uint32 sz);

/*
    Definition: Query series interface
    Input_param: conn handle object
    Return value:
    Description: interface is used to use connection handle object to execute sql, can use ctconn_get_query_stmt to get
   stmt and get more result
*/
int ctconn_query(ctconn_conn_t pconn, const char *sql);
unsigned int ctconn_query_get_affected_rows(ctconn_conn_t pconn);
unsigned int ctconn_query_get_column_count(ctconn_conn_t pconn);
int ctconn_query_fetch(ctconn_conn_t pconn, uint32 *rows);
int ctconn_query_describe_column(ctconn_conn_t pconn, uint32 id, ctconn_column_desc_t *desc);
int ctconn_query_get_column(ctconn_conn_t pconn, uint32 id, void **data, uint32 *size, uint32 *is_null);
ctconn_stmt_t ctconn_get_query_stmt(ctconn_conn_t pconn);

/*
    Definition: blob or clob or image read and write series interface
    Input_param:
    Return value:
    Description: interface is used to read and write blob or clob or image data
*/
int ctconn_write_blob(ctconn_stmt_t pstmt, uint32 id, const void *data, uint32 size);
int ctconn_write_clob(ctconn_stmt_t pstmt, uint32 id, const void *data, uint32 size, uint32 *nchars);

int ctconn_write_batch_blob(ctconn_stmt_t pstmt, uint32 id, uint32 piece, const void *data, uint32 size);
int ctconn_write_batch_clob(ctconn_stmt_t pstmt, uint32 id, uint32 piece, const void *data, uint32 size, uint32 *nchars);

int ctconn_read_blob_by_id(ctconn_stmt_t pstmt, uint32 id, uint32 offset, void *buffer, uint32 size, uint32 *nbytes,
                        uint32 *eof);
int ctconn_read_blob(ctconn_stmt_t pstmt, void *locator, uint32 offset, void *buffer, uint32 size, uint32 *nbytes,
                  uint32 *eof);

int ctconn_read_clob_by_id(ctconn_stmt_t pstmt, uint32 id, uint32 offset, void *buffer, uint32 size, uint32 *nchars,
                        uint32 *nbytes, uint32 *eof);
int ctconn_read_clob(ctconn_stmt_t pstmt, void *locator, uint32 offset, void *buffer, uint32 size, uint32 *nchars,
                  uint32 *nbytes, uint32 *eof);

/*
    Definition: Get serveroutput information
    Input_param:
        stmt: handle object
    Output parameter:
        data: serveroutput data information
        len:  serveroutput length information
    Return Value:
        0: No server output information
        1: has serveroutput information
    Description: interface is used to obtain the serveroutput information. If and only if the client sets the server
   output switch and the server has serveroutput content output, it will obtain the content.
*/
int ctconn_fetch_serveroutput(ctconn_stmt_t pstmt, char **data, uint32 *len);

/*
    Definition: Get implicit resultset of procedure
    Input_param:
        stmt: handle object
    Output parameter:
        resultset: handle object
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to get implicit resultset of procedure with one by one mode. If resultset is null
   means has no more return result.
*/
int ctconn_get_implicit_resultset(ctconn_stmt_t pstmt, ctconn_stmt_t *resultset);

/*
    Definition: Get the outparam column description information according to outparam column serial number
    Input_param:
        stmt: handle object
        Id:   outparam column serial number, starting from 0
    Output:
        desc: outparam column description
    Return value:
        0:   success
        !=0: failed
    Description: interface is used to obtain outparam column description information (outparam name, outparam data type,
   outparam size, etc.) based on the outparam column ordinal number, valid only for the procedure.
*/
int ctconn_desc_outparam_by_id(ctconn_stmt_t pstmt, uint32 id, ctconn_outparam_desc_t *desc);

/*
    Definition: Get the outparam column description based on the outparam name
    Input_param:
        stmt: handle object
        name: outparam column name
    Output:
        desc: outparam column description
    Return value:
        0:   success
        !=0: failed
    Description: interface is used to obtain outparam column description information (outparam name, outparam data type,
   outparam size, etc.) based on the outparam name, only valid for the procedure.
*/
int ctconn_desc_outparam_by_name(ctconn_stmt_t pstmt, const char *name, ctconn_outparam_desc_t *desc);

/*
    Definition: Get an outparam record row
    Input_param:
        stmt: handle object
    The parameter:
        rows: Returns the number of outparam records
    Return value:
        0:   success
        !=0: failed
    Description: interface is used to obtain a outparam record row, rows value is>=0
*/
int ctconn_fetch_outparam(ctconn_stmt_t pstmt, uint32 *rows);

/*
    Definition: Get the value of a specific outparam column based on the outparam column ordinal
    Input_param:
        stmt: handle object
        id:   outparam column serial number, starting from 0
    Output_param:
        data: outparam column data
        size: outparam column size
        is_null: outparam column value is NULL
    Return value:
        0:   success
        !=0: failed
    Description: interface is used to obtain the value of a specific outparam column based on the outparam column
   ordinal. It is valid only for procedure. If datatype of desc is CTCONN_TYPE_CURSOR, data is handle object of
   sys_refcursor. Size is determined by the column data type. For example, int is 4 bytes, bigint is 8 bytes, and string
   is variable length.
*/
int ctconn_get_outparam_by_id(ctconn_stmt_t pstmt, uint32 id, void **data, uint32 *size, bool32 *is_null);

/*
    Definition: Get the value of a specific outparam column based on the outparam column name
    Input_param:
        stmt: handle object
        name: outparam column name
    Output_param:
        data: outparam column data
        size: outparam column size
        is_null: outparam column value is NULL
    Return value:
        0:   success
        !=0: failed
    Description: interface is used to obtain the value of a specific outparam column based on the outparam column
   ordinal. It is valid only for procedure.
*/
int ctconn_get_outparam_by_name(ctconn_stmt_t pstmt, const char *name, void **data, uint32 *size, uint32 *is_null);

/*
    Definition: Get the outparam column value obtained from the outparam column serial number as a string
    Input_param:
        stmt: handle object
        id:   outparam column serial number, starting from 0
        str:  store outparam column value memory address
        buf_size: store outparam column value memory size
    Return value:
        0:   success
        !=0: failed
    Description: interface is used to obtain the outparam column value obtained from the outparam column serial number
   in a string manner. If datatype of desc is CTCONN_TYPE_CURSOR, must use ctconn_get_outparam_by_id or
   ctconn_get_outparam_by_name to obtain;
*/
int ctconn_outparam_as_string_by_id(ctconn_stmt_t pstmt, uint32 id, char *str, uint32 buf_size);

/*
    Definition: Get the outparam column value obtained from the outparam column based on the outparam name as a string
    Input_param:
        stmt: handle object
        name: outparam column name
        str:  store outparam column value memory address
        buf_size: store outparam column value memory size
    Return value:
        0:   success
        !=0: failed
    Description: interface is used to obtain the outparam column value obtained from the outparam column serial number
   in a string manner. If datatype of desc is CTCONN_TYPE_CURSOR, must use ctconn_get_outparam_by_id or
   ctconn_get_outparam_by_name to obtain;
*/
int ctconn_outparam_as_string_by_name(ctconn_stmt_t pstmt, const char *name, char *str, uint32 buf_size);

/*
    Definition: Convert time information to ctconn_datetime_t construct
    Input_param:
        stmt:      handle object
        datatype:  type of ctconn_datetime_t should be CTCONN_TYPE_TIMESTAMP_TZ_FAKE or CTCONN_TYPE_TIMESTAMP_TZ
        year:  year
        mon: month
        day: day
        hour: hour
        min: minute
        sec: second
        fsec: nanosecond
        timezone: timezone
        timezone_len: length of timezone
    Output_param:
        datetime: ctconn_datetime_t struct
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to convert time information to ctconn_datetime_t construct.
*/
status_t ctconn_datetime_construct(ctconn_stmt_t pstmt, ctconn_datetime_t datetime, int32 datatype, uint16 year, uint8 mon,
    uint8 day, uint8 hour, uint8 min, uint8 sec, uint32 fsec, char *timezone, uint32 timezone_len);

/*
    Definition: Get time information from ctconn_datetime_t construct
    Input_param:
        stmt:      handle object
        datatype:  type of ctconn_datetime_t should be CTCONN_TYPE_TIMESTAMP_TZ_FAKE or CTCONN_TYPE_TIMESTAMP_TZ
        datetime: ctconn_datetime_t struct
    Output_param:
        year:  year
        mon: month
        day: day
        hour: hour
        min: minute
        sec: second
        fsec: nanosecond
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to get time information from ctconn_datetime_t construct.
*/
int ctconn_datetime_deconstruct(ctconn_stmt_t pstmt, ctconn_datetime_t datetime, int32 datatype, uint16 *year, uint8 *mon,
                             uint8 *day, uint8 *hour, uint8 *min, uint8 *sec, uint32 *fsec);

/*
    Definition: Get string timezone information from ctconn_datetime_t construct
    Input_param:
        stmt:      handle object
        datatype:  type of ctconn_datetime_t should be CTCONN_TYPE_TIMESTAMP_TZ_FAKE or CTCONN_TYPE_TIMESTAMP_TZ
        datetime: ctconn_datetime_t struct
        buf_len: buffer length
    Output_param:
        buf: buffer pointer
        buf_len: timezone actual length
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to get string timezone information from ctconn_datetime_t construct.
*/
int ctconn_datetime_get_timezone_name(ctconn_stmt_t pstmt, ctconn_datetime_t datetime, int32 datatype, char *buf,
                                   uint32 *buf_len);

/*
    Definition: Get timezone information from ctconn_datetime_t construct
    Input_param:
        stmt:      handle object
        datatype:  type of ctconn_datetime_t should be CTCONN_TYPE_TIMESTAMP_TZ_FAKE or CTCONN_TYPE_TIMESTAMP_TZ
        datetime: ctconn_datetime_t struct
    Output_param:
        hour: timezone offset hour
        min: timezone offset minute
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to get timezone information from ctconn_datetime_t construct.
*/
int ctconn_datetime_get_timezone_offset(ctconn_stmt_t pstmt, ctconn_datetime_t datetime, int32 datatype, int8 *hour,
                                     int8 *min);

/*
    Definition: Get the description of object
    Input_param:
        stmt:      handle object
        object:    object to desc
        desc_type: type of object
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to desc object, such as table, view, synonym, query, etc.
*/
int ctconn_describle(ctconn_stmt_t pstmt, char *objptr, ctconn_desc_type_t dtype);

/*
    Definition: Get batch error info
    Input_param:
        stmt: handle object
    Output parameter:
        line: pos in batch execute
        err_message: error message
        rows: rows of current batch error
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to get batch error info one by one mode. If rows = 0 means has no more batch error to
   get.
*/
int ctconn_get_batch_error(ctconn_stmt_t pstmt, uint32 *line, char **err_message, uint32 *rows);

/*
    Definition: Get batch error info
    Input_param:
        stmt: handle object
    Output parameter:
        line: pos in batch execute
        code: error code
        err_message: error message
        rows: rows of current batch error
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to get batch error info one by one mode. If rows = 0 means has no more batch error to
   get.
*/
int ctconn_get_batch_error2(ctconn_stmt_t pstmt, unsigned int *line, int *code, char **err_message, unsigned int *rows);

/*
    Definition: Execute multiple sql
    Input_param:
        conn: connection object
        sql:  multiple sql
    Output parameter:
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to execute multiple sql. Do not supports procedure yet and need use comma between
   every sql
*/
int ctconn_query_multiple(ctconn_conn_t pconn, const char *sql);

/*
    Definition: Get multiple resultset of query
    Input_param:
        stmt: handle object
    Output parameter:
        resultset: handle object
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to get multiple resultset of query with one by one mode. If resultset is null means
   has no more resultset.
*/
int ctconn_get_query_resultset(ctconn_conn_t pconn, ctconn_stmt_t *resultset);

/* sign flag of number */
#define CTCONN_NUMBER_SIGNED 0
#define CTCONN_NUMBER_UNSIGNED 1

/*
    Definition: Convert an dec4_t NUMBER type value to integer
    Input_param:
        stmt: handle object
        number: dec4_t value to be converted
        sign_flag: Sign of the output, set CTCONN_NUMBER_SIGNED or CTCONN_NUMBER_UNSIGNED.
        rsl_length: Size of the output, set to 2 or 4 or 8.
    Output parameter:
        rsl: Buffer point to the output.
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to convert NUMBER to short(len = 2),int(len = 4),bigint(len = 8).
*/
int ctconn_number_to_int(ctconn_stmt_t pstmt, void *number, unsigned int sign_flag, unsigned int rsl_length, void *rsl);

/*
    Definition: Convert an dec4_t NUMBER type value to real
    Input_param:
        stmt: handle object
        number: dec4_t value to be converted
        rsl_length: Size of the output, set to 4 or 8.
    Output parameter:
        rsl: Buffer point to the output.
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to convert NUMBER to float(len = 4) or double(len = 8).
*/
int ctconn_number_to_real(ctconn_stmt_t pstmt, void *number, unsigned int rsl_length, void *rsl);

/*
    Definition: Convert an dec4_t NUMBER type value to string
    Input_param:
        stmt: handle object
        number: dec4_t value to be converted
        buf_size: Size of the output,it can be fetched by CTCONN_ATTR_DATA_SIZE.
    Output parameter:
        buf: Buffer point to the output.
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to convert NUMBER to string.
*/
int ctconn_number_to_string(ctconn_stmt_t pstmt, void *number, char *buf, unsigned int buf_size);


typedef struct st_ctconn_xid {
#ifdef WIN32
    unsigned __int64 fmt_id;
#else
    unsigned long long fmt_id;
#endif
    unsigned char gtrid_len; // 1~64 bytes
    unsigned char bqual_len; // 1~64 bytes
    char data[1];            // for VS warning, data[0] not used
} ctconn_xid_t;

typedef enum en_ctconn_xact_status {
    CTCONN_XACT_END = 0,
    CTCONN_XACT_OPEN = 1,
    CTCONN_XACT_PHASE1 = 2,
    CTCONN_XACT_PHASE2 = 3,
} ctconn_xact_status_t;

#define CTCONN_XA_DEFAULT 0x0000
#define CTCONN_XA_NEW 0x0001
#define CTCONN_XA_NOMIGRATE 0x0002
#define CTCONN_XA_SUSPEND 0x0004
#define CTCONN_XA_RESUME 0x0010
#define CTCONN_XA_ONEPHASE 0x0020
#define CTCONN_XA_LGWR_BATCH 0x0040
#define CTCONN_XA_LGWR_IMMED 0x0080
#define CTCONN_XA_LGWR_WAIT 0x0100
#define CTCONN_XA_LGWR_NOWAIT 0x0200

/*
    Definition: start a new or resume an existing global transaction branch
    Input param:
        conn : connection object
        xid : global transaction branch ID
        timeout:
            when CTCONN_XA_RESUME is specified, it is the number of seconds to wait for the transaction branch to be
   available. when CTCONN_XA_NEW is specified, it is the number of seconds the branch can be inactive before it is
   automatically destroyed. flags: CTCONN_XA_NEW : start a new transaction branch CTCONN_XA_RESUME : resume an existing
   transaction branch CTCONN_XA_NOMIGRATE : the transaction branch can not be ended in one session, but resumed in another
   one CTCONN_XA_DEFAULT : CTCONN_XA_NEW|CTCONN_XA_NOMIGRATE Return Value: 0 : success
        !=0 : failed. use ctconn_get_error get latest error information. Typical errors are :
            ERR_XA_ALREADY_IN_LOCAL_TRANS : doing work in a local transaction
            ERR_XA_RESUME_TIMEOUT : timeout when waiting for the transaction branch to be available
            ERR_XA_BRANCH_NOT_EXISTS: specified branch does not exists
    Description: when resume an existing global transaction branch, it must have been ended using ctconn_xa_end.
*/
#ifdef WIN32
int ctconn_xa_start(ctconn_conn_t conn, ctconn_xid_t *xid, unsigned __int64 timeout, unsigned __int64 flags);
#else
int ctconn_xa_start(ctconn_conn_t conn, ctconn_xid_t *xid, uint64 timeout, uint64 flags);
#endif

/*
    Definition: end an global transaction branch
    Input param:
        conn: connection object
        flags:
            CTCONN_XA_DEFAULT
    Return Value:
        0 : success
        !=0 : failed. use ctconn_get_error get latest error information. Typical errors are :
            ERR_XA_BRANCH_NOT_EXISTS : specified branch does not exists
    Description: the ended branch can be resumed by calling ctconn_xa_start, specifying flags with CTCONN_XA_RESUME
*/
#ifdef WIN32
int ctconn_xa_end(ctconn_conn_t conn, unsigned __int64 flags);
#else
int ctconn_xa_end(ctconn_conn_t conn, uint64 flags);
#endif

/*
    Definition: prepare a transaction branch for commit
    Input param:
        conn : connection object
        xid : global transaction branch ID
        flags:
            CTCONN_XA_DEFAULT
        timestamp : current timestamp of TM, used for consistent read
            0 : consistent read not concerned
            !0 : consistent read concerned
    Return Value:
        0 : success
        !=0 : failed. use ctconn_get_error get latest error information. Typical errors are :
            ERR_XA_BRANCH_NOT_EXISTS : specified branch does not exists
            ERR_XA_RDONLY : there is no local transaction, in other words there are no written operations between
   xa_start and xa_end Description: NA
*/
#ifdef WIN32
int ctconn_xa_prepare(ctconn_conn_t conn, ctconn_xid_t *xid, unsigned __int64 flags, struct timeval *timestamp);
#else
int ctconn_xa_prepare(ctconn_conn_t conn, ctconn_xid_t *xid, uint64 flags, struct timeval *ts);
#endif

/*
Definition: commit a transaction branch
Input param:
    conn : connection object
    xid : global transaction branch ID
    flags:
        CTCONN_XA_ONEPHASE : do one-phase commit
        CTCONN_XA_LGWR_BATCH : before being flushed to online redo log files, redo log of current branch is batched with
other branch's. CTCONN_XA_LGWR_WAIT : wait until redo log of current branch is flushed to online redo log files.
        CTCONN_XA_LGWR_NOWAIT : returns without waiting for redo log of current branch flushed to online redo log files.
        CTCONN_XA_LGWR_IMMED : redo log flush is triggered immediately.
        CTCONN_XA_DEFAULT : CTCONN_XA_LGWR_WAIT|CTCONN_XA_LGWR_IMMED and two phase commit
    timestamp : current timestamp of TM, used for consistent read
        0 : consistent read not concerned
        !0 : consistent read concerned
Return Value:
    0 : success
    !=0 : failed. use ctconn_get_error get latest error information. Typical errors are :
        ERR_XA_BRANCH_NOT_EXISTS : specified branch does not exists
Description: NA
*/
#ifdef WIN32
int ctconn_xa_commit(ctconn_conn_t conn, ctconn_xid_t *xid, unsigned __int64 flags, struct timeval *timestamp);
#else
int ctconn_xa_commit(ctconn_conn_t conn, ctconn_xid_t *xid, uint64 flags, struct timeval *ts);
#endif

/*
    Definition: rollback a transaction branch
    Input param:
        conn : connection object
        xid : global transaction branch ID
        flags:
            CTCONN_XA_DEFAULT
    Return Value:
        0 : success
        !=0 : failed. use ctconn_get_error get latest error information.
    Description: NA
*/
#ifdef WIN32
int ctconn_xa_rollback(ctconn_conn_t conn, ctconn_xid_t *xid, unsigned __int64 flags);
#else
int ctconn_xa_rollback(ctconn_conn_t conn, ctconn_xid_t *xid, uint64 flags);
#endif

/*
    Definition: get status of a global transaction branch
    Input_param:
        conn : connection object
        xid : global transaction branch ID
    Output param:
        status : status of the specified transaction branch
    Return Value:
        0 : success
        !=0 : failed. use ctconn_get_error get latest error information.
    Description: NA
*/
int ctconn_xact_status(ctconn_conn_t conn, ctconn_xid_t *xid, ctconn_xact_status_t *status);
char *ctconn_get_typename_by_id(ctconn_type_t ctconn_type);
#ifdef __cplusplus
}
#endif

#endif
