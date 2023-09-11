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
 * gsc.h
 *
 *
 * IDENTIFICATION
 * src/driver/gsc/gsc.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __GSC_H__
#define __GSC_H__

#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* handle */
struct __gsc_conn;
struct __gsc_stmt;
struct __gsc_desc;
struct __gsc_datetime;
typedef struct __gsc_conn *gsc_conn_t;         /* type of connection handle */
typedef struct __gsc_stmt *gsc_stmt_t;         /* type of statement handle */
typedef struct __gsc_desc *gsc_desc_t;         /* type of description handle */
typedef struct __gsc_datetime *gsc_datetime_t; /* type of dateime handle */

/* data types */
typedef enum en_gsc_type {
    GSC_TYPE_UNKNOWN = 0,            /* invalid value */
    GSC_TYPE_INTEGER = 1,            /* native 32 bits integer */
    GSC_TYPE_BIGINT = 2,             /* native 64 bits integer */
    GSC_TYPE_REAL = 3,               /* native float */
    GSC_TYPE_NUMBER = 4,             /* number */
    GSC_TYPE_DECIMAL = 5,            /* decimal, internal used */
    GSC_TYPE_DATE = 6,               /* datetime, 7 bytes */
    GSC_TYPE_TIMESTAMP = 7,          /* timestamp */
    GSC_TYPE_CHAR = 8,               /* char(n) */
    GSC_TYPE_VARCHAR = 9,            /* varchar, varchar2 */
    GSC_TYPE_STRING = 10,            /* native char * */
    GSC_TYPE_BINARY = 11,            /* binary */
    GSC_TYPE_VARBINARY = 12,         /* varbinary */
    GSC_TYPE_CLOB = 13,              /* clob */
    GSC_TYPE_BLOB = 14,              /* blob */
    GSC_TYPE_CURSOR = 15,            /* resultset, for procedure */
    GSC_TYPE_COLUMN = 16,            /* column type, internal used */
    GSC_TYPE_BOOLEAN = 17,           /* bool, value can be 1 or 0 */
    GSC_TYPE_TIMESTAMP_TZ_FAKE = 18, /* fake, equals to timestamp */
    GSC_TYPE_TIMESTAMP_LTZ = 19,     /* timestamp with local time zone */
    GSC_TYPE_INTERVAL = 20,          /* interval of pg style */
    GSC_TYPE_INTERVAL_YM = 21,       /* interval YEAR TO MONTH */
    GSC_TYPE_INTERVAL_DS = 22,       /* interval DAY TO SECOND */
    GSC_TYPE_RAW = 23,
    GSC_TYPE_IMAGE = 24,        /* image, equals to longblob */
    GSC_TYPE_UINT32 = 25,       /* unsigned integer */
    GSC_TYPE_TIMESTAMP_TZ = 32, /* timestamp with time zone */
    GSC_TYPE_ARRAY = 33,        /* array */
    GSC_TYPE_NUMBER2 = 34,      /* number2 */
    GSC_TYPE_RECORD = 101,      /* record */
    GSC_TYPE_COLLECTION = 102,  /* collection */
    GSC_TYPE_OBJECT = 103,      /* object */
    GSC_TYPE_NATIVE_DATE = 205, /* native datetime, internal used */
} gsc_type_t;

/* bound size of special data type needs convert to string buffer */
#define GSC_NUMBER_BOUND_SIZE (int)50
#define GSC_TIME_BOUND_SIZE (int)60
#define GSC_BOOL_BOUND_SIZE (int)6
#define GSC_YM_INTERVAL_BOUND_SIZE (int)10
#define GSC_DS_INTERVAL_BOUND_SIZE (int)24

/* stmt types */
typedef enum en_gsc_stmt_type {
    GSC_STMT_NONE = 0,
    GSC_STMT_DML = 1, /* select/insert/delete/update/merge/replace, etc */
    GSC_STMT_DCL = 2,
    GSC_STMT_DDL = 3,
    GSC_STMT_PL = 4,
    GSC_STMT_EXPLAIN = 5, /* explain [plan for] + DML */
} gsc_stmt_type_t;

/* null value */
#define GSC_NULL (unsigned short)0xFFFF

/* direction of bind, default is GSC_INPUT */
#define GSC_INPUT (unsigned char)1
#define GSC_OUTPUT (unsigned char)2
#define GSC_INOUT (unsigned char)3

/* description of column */
/* users can use 'gsc_get_desc_attr' instead of 'gsc_desc_column_by_id' */
typedef struct st_gsc_column_desc {
    char *name;
    unsigned short size;
    unsigned char precision;
    char scale;
    unsigned short type;
    unsigned char nullable;
    unsigned char is_character;
} gsc_column_desc_t;

/* description of output in procedure */
typedef struct st_gsc_output_desc {
    char *name;
    unsigned short size;
    unsigned char direction;
    unsigned char type;
} gsc_outparam_desc_t;

/* lob bind value */
typedef struct st_gsc_lob {
    unsigned int size;
    unsigned int type;
    unsigned int entry_vmid;
    unsigned int last_vmid;
} gsc_lob_t;

typedef struct st_gsc_sequence {
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
} gsc_sequence_t;

typedef enum en_gsc_ssl_mode {
    GSC_SSL_DISABLED = 0,
    GSC_SSL_PREFERRED,
    GSC_SSL_REQUIRED,
    GSC_SSL_VERIFY_CA,
    GSC_SSL_VERIFY_FULL
} gsc_ssl_mode_t;

/* description type */
typedef enum en_gsc_desc_type {
    GSC_DESC_OBJ = 0,
    GSC_DESC_TABLE,
    GSC_DESC_VIEW,
    GSC_DESC_SYN,   /* synonym */
    GSC_DESC_QUERY, /* query */
    GSC_DESC_PROC,  /* procedure */
    GSC_DESC_FUNC,  /* function */
    GSC_DESC_PKG,   /* package */
    GSC_DESC_SEQ,   /* sequence */
} gsc_desc_type_t;

typedef enum en_gsc_shd_rw_split {
    GSC_SHD_RW_SPLIT_NONE = 0, // shard rw split not set
    GSC_SHD_RW_SPLIT_RW,       // read and write
    GSC_SHD_RW_SPLIT_ROS,      // read on slave dn
    GSC_SHD_RW_SPLIT_ROA       // read on master dn or slave dn
} gsc_shd_rw_split_t;

/* connection attributes */
#define GSC_ATTR_AUTO_COMMIT \
    (int)101 /* specifies auto commit after execute, default is auto commit off , Attribute Datatype: unsigned int */
#define GSC_ATTR_XACT_STATUS (int)102 /* currently not enabled */
#define GSC_ATTR_EXIT_COMMIT                                                                                      \
    (int)103 /* enable for zsql, for whether do commit when zsql is quit, default is enable , Attribute Datatype: \
                unsigned int */
#define GSC_ATTR_SERVEROUTPUT                                                                                      \
    (int)104 /* whether enable returns dbe_output.print_line in procedure, default is disable, Attribute Datatype: \
                unsigned int */
#define GSC_ATTR_CHARSET_TYPE                                                                                     \
    (int)105 /* set charset type of client, currently supports UTF8 or GBK, default is UTF8 , Attribute Datatype: \
                char*, Length: unsigned int */
#define GSC_ATTR_NUM_WIDTH (int)106 /* enable for zsql, for display numeric value , Attribute Datatype: unsigned int \
                                     */
#define GSC_ATTR_INTERACTIVE_MODE                                                                    \
    (int)107 /* whether enable interactive timeout, default is disable. timeout depends on parameter \
                INTERACTIVE_TIMEOUT , Attribute Datatype: unsigned char */
#define GSC_ATTR_LOB_LOCATOR_SIZE (int)108 /* specifies the size of LOB locator , Attribute Datatype: unsigned int */
#define GSC_ATTR_SSL_CA                                                                                            \
    (int)109 /* file that contains list of trusted SSL Certificate Authorities, Attribute Datatype: char*, Length: \
                unsigned int */
#define GSC_ATTR_SSL_CERT \
    (int)110 /* file that contains X.509 certificate, Attribute Datatype: char*, Length: unsigned int */
#define GSC_ATTR_SSL_KEY (int)111  /* file that contains X.509 key, Attribute Datatype: char*, Length: unsigned int */
#define GSC_ATTR_SSL_MODE (int)112 /* security state of connection to server, Attribute Datatype: unsigned int */
#define GSC_ATTR_SSL_CRL \
    (int)113 /* file that contains certificate revocation lists, Attribute Datatype: char*, Length: unsigned int */
#define GSC_ATTR_SSL_KEYPWD                                                                                       \
    (int)114 /* the pwd for SSL key file. If the SSL key file is protected by a pass phrase, use the attribute to \
                specify the pwd, Attribute Datatype: char*, Length: unsigned int */
#define GSC_ATTR_SSL_CIPHER                                                                                          \
    (int)115 /* list of permitted ciphers for connection encryption, Attribute Datatype: char*, Length: unsigned int \
              */
#define GSC_ATTR_CONNECT_TIMEOUT                                                                                       \
    (int)116 /* connection timeout when create socket to server, unit is second, default is 10, -1 means not timeout , \
                Attribute Datatype: int */
#define GSC_ATTR_SOCKET_TIMEOUT                                                                                 \
    (int)117 /* socket timeout when execute sql, unit is second, default is -1, -1 means not timeout, Attribute \
                Datatype: int */
#define GSC_ATTR_APP_KIND (int)118        /* specifies client type of client, default is 1, Attribute Datatype: short */
#define GSC_ATTR_DBTIMEZONE (int)119      /* DBTIMEZONE, Attribute Datatype: short */
#define GSC_ATTR_UDS_SERVER_PATH (int)120 /* specifies unix domain socket server file path */
#define GSC_ATTR_UDS_CLIENT_PATH (int)121 /* specifies unix domain socket client file path */
#define GSC_ATTR_TIMESTAMP_SIZE (int)122  /* get inner timestamp bind size */
#define GSC_ATTR_TIMESTAMP_TZ_SIZE (int)123  /* get inner timestamp_tz bind size */
#define GSC_ATTR_TIMESTAMP_LTZ_SIZE (int)124 /* get inner timestamp_ltz bind size */
#define GSC_ATTR_FLAG_WITH_TS (int)125
#define GSC_ATTR_REMOTE_AS_SYSDBA (int)126
#define GSC_ATTR_SHD_RW_FLAG (int)127 /* flag of CN rw split, 0:not split,1:on master,2:on slave,3:on master or slave \
                                       */
#define GSC_ATTR_LAST_INSERT_ID                                                                                      \
    (int)128 /* the value generated by the AUTO INCREMENT column of the last INSERT statement in the current session \
              */
#define GSC_ATTR_SOCKET_L_ONOFF (int)129  /* SO_LINGER l_onoff value */
#define GSC_ATTR_SOCKET_L_LINGER (int)130 /* SO_LINGER l_linger value */
#define GSC_ATTR_AUTOTRACE (int)131       /* enable autotrace */

/* The order of NLS can not be changed */
#define GSC_ATTR_NLS_CALENDAR (int)160
#define GSC_ATTR_NLS_CHARACTERSET (int)161
#define GSC_ATTR_NLS_COMP (int)162
#define GSC_ATTR_NLS_CURRENCY (int)163
#define GSC_ATTR_NLS_DATE_FORMAT (int)164
#define GSC_ATTR_NLS_DATE_LANGUAGE (int)165
#define GSC_ATTR_NLS_DUAL_CURRENCY (int)166
#define GSC_ATTR_NLS_ISO_CURRENCY (int)167
#define GSC_ATTR_NLS_LANGUAGE (int)168
#define GSC_ATTR_NLS_LENGTH_SEMANTICS (int)169
#define GSC_ATTR_NLS_NCHAR_CHARACTERSET (int)170
#define GSC_ATTR_NLS_NCHAR_CONV_EXCP (int)171
#define GSC_ATTR_NLS_NUMERIC_CHARACTERS (int)172
#define GSC_ATTR_NLS_RDBMS_VERSION (int)173
#define GSC_ATTR_NLS_SORT (int)174
#define GSC_ATTR_NLS_TERRITORY (int)175
#define GSC_ATTR_NLS_TIMESTAMP_FORMAT (int)176
#define GSC_ATTR_NLS_TIMESTAMP_TZ_FORMAT (int)177
#define GSC_ATTR_NLS_TIME_FORMAT (int)178
#define GSC_ATTR_NLS_TIME_TZ_FORMAT (int)179

/* statement attributes */
#define GSC_ATTR_PREFETCH_ROWS (int)201   /* number of top level rows to be prefetched */
#define GSC_ATTR_PREFETCH_BUFFER (int)202 /* memory level for top level rows to be prefetched (useless) */
#define GSC_ATTR_PARAMSET_SIZE (int)203   /* number of array bind data for batch bind, default is 1 */
#define GSC_ATTR_FETCHED_ROWS                                                                                         \
    (int)204 /* indicates the number of rows that were successfully fetched into the user's buffers in the last fetch \
              */
#define GSC_ATTR_AFFECTED_ROWS                                                                                     \
    (int)205 /* returns the number of rows processed so far after SELECT statements. For INSERT, UPDATE and DELETE \
                statements, it is the number of rows processed by the most recent statement */
#define GSC_ATTR_RESULTSET_EXISTS (int)206 /* returns whether has query result */
#define GSC_ATTR_COLUMN_COUNT (int)207     /* returns the columns count of query */
#define GSC_ATTR_STMT_TYPE \
    (int)208 /* the type of statement associated with the handle, valid values defined in gsc_stmt_type_t */
#define GSC_ATTR_PARAM_COUNT (int)209 /* returns the params count */
#define GSC_ATTR_MORE_ROWS (int)210 /* whether has more query rows or not, 0 means has no more rows, 1 means has more \
                                     */
#define GSC_ATTR_STMT_EOF (int)211  /* specifies whether stmt is fetch over or not */
#define GSC_ATTR_OUTPARAM_COUNT (int)212 /* count of outparams in procedure */
#define GSC_ATTR_SEROUTPUT_EXISTS                                                                                    \
    (int)213 /* whether returns dbe_output.print_line or not, used in procedure. default is disable returns and need \
                use GSC_ATTR_SERVEROUTPUT to enable returns */
#define GSC_ATTR_RETURNRESULT_EXISTS (int)214 /* whether returns dbe_sql.return_cursor or not, used in procedure */
#define GSC_ATTR_ALLOWED_BATCH_ERRS (int)215  /* allowed batch errors when do execute batch */
#define GSC_ATTR_ACTUAL_BATCH_ERRS (int)216   /* returns the actual batch errors after execute batch */
#define GSC_ATTR_FETCH_SIZE \
    (int)217 /* number of rows to be fetched from the current position for batch fetch, default is 1 */
#define GSC_ATTR_SHARD_DML_ID (int)218 /* id of cn dispatch dml to dn */

/* describe attributes */
#define GSC_ATTR_NAME (int)301       // column name ,Attribute Datatype: char*, Length: int
#define GSC_ATTR_DATA_SIZE (int)302  /* column size ,Attribute Datatype: unsigned short */
#define GSC_ATTR_PRECISION (int)303  /* column precision ,Attribute Datatype: unsigned char */
#define GSC_ATTR_SCALE (int)304      /* column scale ,Attribute Datatype: unsigned char */
#define GSC_ATTR_DATA_TYPE (int)305  /* column data type ,Attribute Datatype: unsigned short */
#define GSC_ATTR_NULLABLE (int)306   /* column is nullable ,Attribute Datatype: unsigned char */
#define GSC_ATTR_CHAR_USED (int)307  /* column is character ,Attribute Datatype: unsigned char */
#define GSC_ATTR_ARRAY_USED (int)308 /* column is array ,Attribute Datatype: unsigned char */

/* return code */
#define GSC_SUCCESS (int)0
#define GSC_SUCCESS_WITH_INFO (int)1
#define GSC_ERROR (int)(-1)

/*
    Definition: create a connection object
    Input_param:
        conn: connection object
    Output_param:
        conn: connection object
    Return value:
        0:   success
        !=0: failed
    Description: Creates a connection object and use it to invoke gsc_connect to connect to the database
*/
int gsc_alloc_conn(gsc_conn_t *conn);

/*
    Definition: release the connection object
    Input_param:
        conn: connection object
    Return value:
    Description: Releases a connection object. This API is invoked after the gsc_disconnect (database disconnection)
   operation is performed
*/
void gsc_free_conn(gsc_conn_t conn);

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
                 such as: GSC_ATTR_AUTO_COMMIT-transaction commit method (1 means automatic commit, 0 means manual
   commit)
*/
int gsc_set_conn_attr(gsc_conn_t conn, int attr, const void *data, unsigned int len);

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
                 such as: GSC_ATTR_AUTO_COMMIT-transaction commit method (1 indicates automatic commit, 0 indicates
   manual commit)
*/
int gsc_get_conn_attr(gsc_conn_t conn, int attr, void *data, unsigned int len, unsigned int *attr_len);

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
void gsc_get_error(gsc_conn_t conn, int *code, const char **message);

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
void gsc_get_error_position(gsc_conn_t conn, unsigned short *line, unsigned short *column);

/*
    Definition: get error message through connection
    Input_param:
        conn: connection object
    Return value:
        message: error message
    Description: interface is used to obtain the error message by conn. If the passed conn is NULL, the returned message
   is NULL.
*/
char *gsc_get_message(gsc_conn_t conn);

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
int gsc_connect(gsc_conn_t conn, const char *url, const char *user, const char *password);

/*
    Definition: disconnect the database
    Input_param:
        conn: connection object
    Return value:
    Description: Interface used to disconnect the database
*/
void gsc_disconnect(gsc_conn_t conn);

/*
    Definition: get session ID
    Input_param:
        conn: connection object
    Return value: session ID
    Description: interface is used to obtain the session ID which uniquely identifies a connection. If the conn is NULL,
   returns invalid sid
*/
unsigned int gsc_get_sid(gsc_conn_t conn);

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
int gsc_cancel(gsc_conn_t conn, unsigned int sid);

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
int gsc_alloc_stmt(gsc_conn_t conn, gsc_stmt_t *stmt);

/*
    Definition: release handle object
    Input_param:
        stmt: handle object
    Return value:
    Description: interface is used to release the handle object
*/
void gsc_free_stmt(gsc_stmt_t stmt);

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
                 such as: GSC_ATTR_PREFETCH_ROWS--->number of prefetch records,
                          GSC_ATTR_PREFETCH_BUFFER--->prefetch record size,
                          GSC_ATTR_PARAMSET_SIZE--->Batch Parameter Bindings
*/
int gsc_set_stmt_attr(gsc_stmt_t stmt, int attr, const void *data, unsigned int len);

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
                 such as: GSC_ATTR_PREFETCH_ROWS--->number of prefetch records,
                          GSC_ATTR_PREFETCH_BUFFER--->prefetch record size,
                          GSC_ATTR_PARAMSET_SIZE--->Batch Parameter Bindings
*/
int gsc_get_stmt_attr(gsc_stmt_t stmt, int attr, const void *data, unsigned int buf_len, unsigned int *len);

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
int gsc_prepare(gsc_stmt_t stmt, const char *sql);

/*
     Definition: parameter binding by parameter position
     Input_param:
        stmt: handle object
        pos:  The position number of the parameter, starting from 0
        type: data type, from type definition gsc_type_t except GSC_TYPE_TIMESTAMP which will be added in next version
        data: Address of data value or address of data array
        size: buffer length
        ind:  length address or length array address
        direction: direction of bind parameter
     Return value:
        0: success
        !=0: failed
     Description: interface is used for parameter binding through the parameter location. The usage of gsc_bind_by_name
   and gsc_bind_by_pos is basically the same, but there are some differences. For parameters of the same parameter name,
   you can use gsc_bind_by_name to bind once, and gsc_bind_by_pos must bind every parameter. If use gsc_bind_by_pos,
   default direction is 1(input parameter). If need bind parameter with direction, need use gsc_bind_by_pos2. Value of
   direction can be 1(input parameter), 2(outut parameter) or 3(inout parameter).
*/
int gsc_bind_by_pos(gsc_stmt_t stmt, unsigned int pos, int type, const void *data, int size, unsigned short *ind);
int gsc_bind_by_pos2(gsc_stmt_t stmt, unsigned int pos, int type, const void *data, int size, unsigned short *ind,
    int direction);

/*
     Definition: parameter binding by parameter position
     Input_param:
        stmt: handle object
        pos:  The position number of the parameter, starting from 0
        type: data type, from type definition gsc_type_t
        data: Address of data value or address of data array
        size: buffer length
        ind:  length address or length array address
        direction: direction of bind
     Return value:
        0: success
        !=0: failed
    Description: interface is used for parameter binding by parameter name. If NULL is bound, the corresponding ind[i]
   of the data needs to be set to GSC_NULL.
*/
int gsc_bind_by_name(gsc_stmt_t stmt, const char *name, int type, const void *data, int size, unsigned short *ind);
int gsc_bind_by_name2(gsc_stmt_t stmt, const char *name, int type, const void *data, int size, unsigned short *ind,
    int direction);

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
int gsc_get_column_count(gsc_stmt_t stmt, unsigned int *column_count);

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
int gsc_desc_column_by_id(gsc_stmt_t stmt, unsigned int id, gsc_column_desc_t *desc);

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
int gsc_desc_column_by_name(gsc_stmt_t stmt, const char *col_name, gsc_column_desc_t *desc);

/*
    Definition: Get the query column description based on the query attribute
    Input_param:
        stmt: handle object
        id: query column id
        attr: query attribute
    Output:
        data: query data buffer pointer
        len: query data actual length (GSC_ATTR_NAME, it means name length)
    Return value:
        0: success
        !=0: failed
    Description: interface is used to obtain query column description information
        (column name, column data type, column size, etc.) based on the query attribute,
        only valid for the query.
*/
int gsc_get_desc_attr(gsc_stmt_t stmt, unsigned int id, int attr, void *data, unsigned int *len);

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
int gsc_get_column_by_id(gsc_stmt_t stmt, unsigned int id, void **data, unsigned int *size, unsigned int *is_null);

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
int gsc_get_column_by_name(gsc_stmt_t stmt, const char *name, void **data, unsigned int *size, unsigned int *is_null);

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
unsigned int gsc_get_affected_rows(gsc_stmt_t stmt);

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
int gsc_column_as_string(gsc_stmt_t stmt, unsigned int id, char *str, unsigned int buf_size);

/*
    Definition: This call specifies additional attributes necessary for a static array define, used in an array of
   structures (multi-row, multi-column) fetch Input_param: stmt: handle object id: query column serial number, starting
   from 0 bind_type: data type expected to get column value bind_size: size of one item of array bind_ptr:  address of
   memory to store query column value ind_ptr:   length address or length array address Return value: 0: success
        !=0: failed
    Description: interface is used to multi-row or multi-column fetch. Number of array of bind_ptr or ind_ptr depends on
   attr GSC_ATTR_FETCH_SIZE. Bind_type can be same with data type of column definition or likely, such as number or date
   or string.
*/
int gsc_bind_column(gsc_stmt_t stmt, unsigned int id, unsigned short bind_type, unsigned short bind_size,
    void *bind_ptr, unsigned short *ind_ptr);

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
int gsc_execute(gsc_stmt_t stmt);

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
int gsc_fetch(gsc_stmt_t stmt, unsigned int *rows);

/*
    Definition: Submit a transaction that has not ended
    Input_param:
        conn: connection object
    Return value:
        0: success
        !=0: failed
    Description: Interface used to commit transactions that have not yet ended
*/
int gsc_commit(gsc_conn_t conn);

/*
    Definition: rollback a transaction that has not ended
    Input_param:
        conn: connection object
    Return value:
        0: success
        !=0: failed
    Description: Interface used to rollback transactions that have not yet ended
*/
int gsc_rollback(gsc_conn_t conn);

/*
    Definition: Set whether to automatically commit the transaction after the current operation
    Input_param:
    conn: connection object
    auto_commit: is or not auto
    Return value:
    Description: interface is used to set whether the transaction is committed automatically after the current
   operation. Usage is equivalent to gsc_set_conn_attr setting GSC_ATTR_AUTO_COMMIT
*/
void gsc_set_autocommit(gsc_conn_t conn, unsigned int auto_commit);

/*
    Definition: Set batch parameter binding number
    Input_param:
    stmt: handle object
    sz: batch parameter binding number
    Return value:
    Description: interface is used to set the number of batch parameter bindings, usage is equivalent to
   gsc_set_stmt_attr set GSC_ATTR_PARAMSET_SIZE
*/
void gsc_set_paramset_size(gsc_stmt_t stmt, unsigned int sz);

/*
    Definition: Query series interface
    Input_param: conn handle object
    Return value:
    Description: interface is used to use connection handle object to execute sql, can use gsc_get_query_stmt to get
   stmt and get more result
*/
int gsc_query(gsc_conn_t conn, const char *sql);
unsigned int gsc_query_get_affected_rows(gsc_conn_t conn);
unsigned int gsc_query_get_column_count(gsc_conn_t conn);
int gsc_query_fetch(gsc_conn_t conn, unsigned int *rows);
int gsc_query_describe_column(gsc_conn_t conn, unsigned int id, gsc_column_desc_t *desc);
int gsc_query_get_column(gsc_conn_t conn, unsigned int id, void **data, unsigned int *size, unsigned int *is_null);
gsc_stmt_t gsc_get_query_stmt(gsc_conn_t conn);

/*
    Definition: blob or clob or image read and write series interface
    Input_param:
    Return value:
    Description: interface is used to read and write blob or clob or image data
*/
int gsc_write_blob(gsc_stmt_t stmt, unsigned int id, const void *data, unsigned int size);
int gsc_write_clob(gsc_stmt_t stmt, unsigned int id, const void *data, unsigned int size, unsigned int *nchars);

int gsc_write_batch_blob(gsc_stmt_t stmt, unsigned int id, unsigned int piece, const void *data, unsigned int size);
int gsc_write_batch_clob(gsc_stmt_t stmt, unsigned int id, unsigned int piece, const void *data, unsigned int size,
    unsigned int *nchars);

int gsc_read_blob_by_id(gsc_stmt_t stmt, unsigned int id, unsigned int offset, void *buffer, unsigned int size,
    unsigned int *nbytes, unsigned int *eof);
int gsc_read_blob(gsc_stmt_t stmt, void *locator, unsigned int offset, void *buffer, unsigned int size,
    unsigned int *nbytes, unsigned int *eof);

int gsc_read_clob_by_id(gsc_stmt_t stmt, unsigned int id, unsigned int offset, void *buffer, unsigned int size,
    unsigned int *nchars, unsigned int *nbytes, unsigned int *eof);
int gsc_read_clob(gsc_stmt_t stmt, void *locator, unsigned int offset, void *buffer, unsigned int size,
    unsigned int *nchars, unsigned int *nbytes, unsigned int *eof);

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
int gsc_fetch_serveroutput(gsc_stmt_t stmt, char **data, unsigned int *len);

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
int gsc_get_implicit_resultset(gsc_stmt_t stmt, gsc_stmt_t *resultset);

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
int gsc_desc_outparam_by_id(gsc_stmt_t stmt, unsigned int id, gsc_outparam_desc_t *desc);

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
int gsc_desc_outparam_by_name(gsc_stmt_t stmt, const char *name, gsc_outparam_desc_t *desc);

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
int gsc_fetch_outparam(gsc_stmt_t stmt, unsigned int *rows);

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
   ordinal. It is valid only for procedure. If datatype of desc is GSC_TYPE_CURSOR, data is handle object of
   sys_refcursor. Size is determined by the column data type. For example, int is 4 bytes, bigint is 8 bytes, and string
   is variable length.
*/
int gsc_get_outparam_by_id(gsc_stmt_t stmt, unsigned int id, void **data, unsigned int *size, unsigned int *is_null);

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
int gsc_get_outparam_by_name(gsc_stmt_t stmt, const char *name, void **data, unsigned int *size, unsigned int *is_null);

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
   in a string manner. If datatype of desc is GSC_TYPE_CURSOR, must use gsc_get_outparam_by_id or
   gsc_get_outparam_by_name to obtain;
*/
int gsc_outparam_as_string_by_id(gsc_stmt_t stmt, unsigned int id, char *str, unsigned int buf_size);

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
   in a string manner. If datatype of desc is GSC_TYPE_CURSOR, must use gsc_get_outparam_by_id or
   gsc_get_outparam_by_name to obtain;
*/
int gsc_outparam_as_string_by_name(gsc_stmt_t stmt, const char *name, char *str, unsigned int buf_size);

/*
    Definition: Convert time information to gsc_datetime_t construct
    Input_param:
        stmt:      handle object
        datatype:  type of gsc_datetime_t should be GSC_TYPE_TIMESTAMP_TZ_FAKE or GSC_TYPE_TIMESTAMP_TZ
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
        datetime: gsc_datetime_t struct
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to convert time information to gsc_datetime_t construct.
*/
int gsc_datetime_construct(gsc_stmt_t stmt, gsc_datetime_t datetime, int datatype, unsigned short year,
    unsigned char mon, unsigned char day, unsigned char hour, unsigned char min, unsigned char sec, unsigned int fsec,
    char *timezone, unsigned int timezone_len);

/*
    Definition: Get time information from gsc_datetime_t construct
    Input_param:
        stmt:      handle object
        datatype:  type of gsc_datetime_t should be GSC_TYPE_TIMESTAMP_TZ_FAKE or GSC_TYPE_TIMESTAMP_TZ
        datetime: gsc_datetime_t struct
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
    Description: interface is used to get time information from gsc_datetime_t construct.
*/
int gsc_datetime_deconstruct(gsc_stmt_t stmt, gsc_datetime_t datetime, int datatype, unsigned short *year,
    unsigned char *mon, unsigned char *day, unsigned char *hour, unsigned char *min, unsigned char *sec,
    unsigned int *fsec);

/*
    Definition: Get string timezone information from gsc_datetime_t construct
    Input_param:
        stmt:      handle object
        datatype:  type of gsc_datetime_t should be GSC_TYPE_TIMESTAMP_TZ_FAKE or GSC_TYPE_TIMESTAMP_TZ
        datetime: gsc_datetime_t struct
        buf_len: buffer length
    Output_param:
        buf: buffer pointer
        buf_len: timezone actual length
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to get string timezone information from gsc_datetime_t construct.
*/
int gsc_datetime_get_timezone_name(gsc_stmt_t stmt, gsc_datetime_t datetime, int datatype, char *timezone,
    unsigned int *timezone_len);

/*
    Definition: Get timezone information from gsc_datetime_t construct
    Input_param:
        stmt:      handle object
        datatype:  type of gsc_datetime_t should be GSC_TYPE_TIMESTAMP_TZ_FAKE or GSC_TYPE_TIMESTAMP_TZ
        datetime: gsc_datetime_t struct
    Output_param:
        hour: timezone offset hour
        min: timezone offset minute
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to get timezone information from gsc_datetime_t construct.
*/
int gsc_datetime_get_timezone_offset(gsc_stmt_t stmt, gsc_datetime_t datetime, int datatype, char *hour, char *min);

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
int gsc_describle(gsc_stmt_t stmt, char *object, gsc_desc_type_t desc_type);

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
int gsc_get_batch_error(gsc_stmt_t stmt, unsigned int *line, char **err_message, unsigned int *rows);

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
int gsc_get_batch_error2(gsc_stmt_t stmt, unsigned int *line, int *code, char **err_message, unsigned int *rows);

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
int gsc_query_multiple(gsc_conn_t conn, const char *sql);

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
int gsc_get_query_resultset(gsc_conn_t conn, gsc_stmt_t *resultset);

/* sign flag of number */
#define GSC_NUMBER_SIGNED 0
#define GSC_NUMBER_UNSIGNED 1

/*
    Definition: Convert an dec4_t NUMBER type value to integer
    Input_param:
        stmt: handle object
        number: dec4_t value to be converted
        sign_flag: Sign of the output, set GSC_NUMBER_SIGNED or GSC_NUMBER_UNSIGNED.
        rsl_length: Size of the output, set to 2 or 4 or 8.
    Output parameter:
        rsl: Buffer point to the output.
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to convert NUMBER to short(len = 2),int(len = 4),bigint(len = 8).
*/
int gsc_number_to_int(gsc_stmt_t stmt, void *number, unsigned int sign_flag, unsigned int rsl_length, void *rsl);

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
int gsc_number_to_real(gsc_stmt_t stmt, void *number, unsigned int rsl_length, void *rsl);

/*
    Definition: Convert an dec4_t NUMBER type value to string
    Input_param:
        stmt: handle object
        number: dec4_t value to be converted
        buf_size: Size of the output,it can be fetched by GSC_ATTR_DATA_SIZE.
    Output parameter:
        buf: Buffer point to the output.
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to convert NUMBER to string.
*/
int gsc_number_to_string(gsc_stmt_t stmt, void *number, char *buf, unsigned int buf_size);


typedef struct st_gsc_xid {
#ifdef WIN32
    unsigned __int64 fmt_id;
#else
    unsigned long long fmt_id;
#endif
    unsigned char gtrid_len; // 1~64 bytes
    unsigned char bqual_len; // 1~64 bytes
    char data[1];            // for VS warning, data[0] not used
} gsc_xid_t;

typedef enum en_gsc_xact_status {
    GSC_XACT_END = 0,
    GSC_XACT_OPEN = 1,
    GSC_XACT_PHASE1 = 2,
    GSC_XACT_PHASE2 = 3,
} gsc_xact_status_t;

#define GSC_XA_DEFAULT 0x0000
#define GSC_XA_NEW 0x0001
#define GSC_XA_NOMIGRATE 0x0002
#define GSC_XA_SUSPEND 0x0004
#define GSC_XA_RESUME 0x0010
#define GSC_XA_ONEPHASE 0x0020
#define GSC_XA_LGWR_BATCH 0x0040
#define GSC_XA_LGWR_IMMED 0x0080
#define GSC_XA_LGWR_WAIT 0x0100
#define GSC_XA_LGWR_NOWAIT 0x0200

/*
    Definition: start a new or resume an existing global transaction branch
    Input param:
        conn : connection object
        xid : global transaction branch ID
        timeout:
            when GSC_XA_RESUME is specified, it is the number of seconds to wait for the transaction branch to be
   available. when GSC_XA_NEW is specified, it is the number of seconds the branch can be inactive before it is
   automatically destroyed. flags: GSC_XA_NEW : start a new transaction branch GSC_XA_RESUME : resume an existing
   transaction branch GSC_XA_NOMIGRATE : the transaction branch can not be ended in one session, but resumed in another
   one GSC_XA_DEFAULT : GSC_XA_NEW|GSC_XA_NOMIGRATE Return Value: 0 : success
        !=0 : failed. use gsc_get_error get latest error information. Typical errors are :
            ERR_XA_ALREADY_IN_LOCAL_TRANS : doing work in a local transaction
            ERR_XA_RESUME_TIMEOUT : timeout when waiting for the transaction branch to be available
            ERR_XA_BRANCH_NOT_EXISTS: specified branch does not exists
    Description: when resume an existing global transaction branch, it must have been ended using gsc_xa_end.
*/
#ifdef WIN32
int gsc_xa_start(gsc_conn_t conn, gsc_xid_t *xid, unsigned __int64 timeout, unsigned __int64 flags);
#else
int gsc_xa_start(gsc_conn_t conn, gsc_xid_t *xid, unsigned long long timeout, unsigned long long flags);
#endif

/*
    Definition: end an global transaction branch
    Input param:
        conn: connection object
        flags:
            GSC_XA_DEFAULT
    Return Value:
        0 : success
        !=0 : failed. use gsc_get_error get latest error information. Typical errors are :
            ERR_XA_BRANCH_NOT_EXISTS : specified branch does not exists
    Description: the ended branch can be resumed by calling gsc_xa_start, specifying flags with GSC_XA_RESUME
*/
#ifdef WIN32
int gsc_xa_end(gsc_conn_t conn, unsigned __int64 flags);
#else
int gsc_xa_end(gsc_conn_t conn, unsigned long long flags);
#endif

/*
    Definition: prepare a transaction branch for commit
    Input param:
        conn : connection object
        xid : global transaction branch ID
        flags:
            GSC_XA_DEFAULT
        timestamp : current timestamp of TM, used for consistent read
            0 : consistent read not concerned
            !0 : consistent read concerned
    Return Value:
        0 : success
        !=0 : failed. use gsc_get_error get latest error information. Typical errors are :
            ERR_XA_BRANCH_NOT_EXISTS : specified branch does not exists
            ERR_XA_RDONLY : there is no local transaction, in other words there are no written operations between
   xa_start and xa_end Description: NA
*/
#ifdef WIN32
int gsc_xa_prepare(gsc_conn_t conn, gsc_xid_t *xid, unsigned __int64 flags, struct timeval *timestamp);
#else
int gsc_xa_prepare(gsc_conn_t conn, gsc_xid_t *xid, unsigned long long flags, struct timeval *timestamp);
#endif

/*
Definition: commit a transaction branch
Input param:
    conn : connection object
    xid : global transaction branch ID
    flags:
        GSC_XA_ONEPHASE : do one-phase commit
        GSC_XA_LGWR_BATCH : before being flushed to online redo log files, redo log of current branch is batched with
other branch's. GSC_XA_LGWR_WAIT : wait until redo log of current branch is flushed to online redo log files.
        GSC_XA_LGWR_NOWAIT : returns without waiting for redo log of current branch flushed to online redo log files.
        GSC_XA_LGWR_IMMED : redo log flush is triggered immediately.
        GSC_XA_DEFAULT : GSC_XA_LGWR_WAIT|GSC_XA_LGWR_IMMED and two phase commit
    timestamp : current timestamp of TM, used for consistent read
        0 : consistent read not concerned
        !0 : consistent read concerned
Return Value:
    0 : success
    !=0 : failed. use gsc_get_error get latest error information. Typical errors are :
        ERR_XA_BRANCH_NOT_EXISTS : specified branch does not exists
Description: NA
*/
#ifdef WIN32
int gsc_xa_commit(gsc_conn_t conn, gsc_xid_t *xid, unsigned __int64 flags, struct timeval *timestamp);
#else
int gsc_xa_commit(gsc_conn_t conn, gsc_xid_t *xid, unsigned long long flags, struct timeval *timestamp);
#endif

/*
    Definition: rollback a transaction branch
    Input param:
        conn : connection object
        xid : global transaction branch ID
        flags:
            GSC_XA_DEFAULT
    Return Value:
        0 : success
        !=0 : failed. use gsc_get_error get latest error information.
    Description: NA
*/
#ifdef WIN32
int gsc_xa_rollback(gsc_conn_t conn, gsc_xid_t *xid, unsigned __int64 flags);
#else
int gsc_xa_rollback(gsc_conn_t conn, gsc_xid_t *xid, unsigned long long flags);
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
        !=0 : failed. use gsc_get_error get latest error information.
    Description: NA
*/
int gsc_xact_status(gsc_conn_t conn, gsc_xid_t *xid, gsc_xact_status_t *status);
char *gsc_get_typename_by_id(gsc_type_t gsc_type);
#ifdef __cplusplus
}
#endif

#endif
