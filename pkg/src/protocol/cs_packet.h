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
 * cs_packet.h
 *
 *
 * IDENTIFICATION
 * src/protocol/cs_packet.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CT_PACK_H__
#define CT_PACK_H__
#include "cm_base.h"
#ifndef WIN32
#include <string.h>
#endif

#include "cm_defs.h"
#include "cm_text.h"
#include "cm_date.h"
#include "cm_nls.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_cs_timeval {
    uint64 tv_sec;  /* seconds */
    uint64 tv_usec; /* microseconds */
} cs_timeval_t;

typedef struct st_cs_packet_head {
    uint32 size;
    uint8 cmd;    /* command in request packet */
    uint8 result; /* code in response packet, success(0) or error(1) */
    uint16 flags;
    uint8 version;
    uint8 minor_version;
    uint8 major_version;
    bool8 extended; /* already used to extend packet by owner !!! */
    uint32 serial_number;
} cs_packet_head_t;

typedef enum en_cs_packet_version {
    CS_VERSION_0 = 0, /* invalid version */
    CS_VERSION_1 = 1, /* discard pg support permanently, not compatible with previous version */
    CS_VERSION_2,     /* 1. add support ssl socket
                         2. add support login pwd encrypted with RSA public key
                         3. add support client-server version negotiation */
    CS_VERSION_3,     /* support inline lob */
    CS_VERSION_4,     /* support wide table(column count >= 1024) */
    CS_VERSION_5,     /* optimize SSL connection mechanism */
    CS_VERSION_6,     /* support login package client kind like jdbc/ctconn/... */
    CS_VERSION_7,     /* support more efficient encode and decode param */
    CS_VERSION_8,     /* 1. enum value of CT_TYPE_TIMESTAMP_TZ be changed (18->32)
                         2. support copyright, change name of tables or views */
    CS_VERSION_9,     /* establish SSL channel before handshake */
    CS_VERSION_10,    /* 1. support get batch error code
                         2. support array
                         3. support server send max_allowed_packet size to client
                         4. optimize vm lob */
    CS_VERSION_11,    /* 1. support password authentication between primary and standy since here;
                         2. support current schema */
    CS_VERSION_12,    /* support shard rw split */
    CS_VERSION_13,    /* support primary obtains continuous flush log point of standby */
    CS_VERSION_14,    /* support getProcedures(resolve view permissions) */
    CS_VERSION_15,    /* support db role info in connection */
    CS_VERSION_16,    /* support autotrace, only for ctsql client */
    CS_VERSION_17,    /* support shard statement-level rollback */
    CS_VERSION_18,    /* support tenant */
    CS_VERSION_19,    /* support verify server signature between primary and standby */
    CS_VERSION_20,    /* support export subpartion, add DB_PART_TABLES view column */
    CS_VERSION_21,    /* support export and import binary or text format of array datatype */
    CS_VERSION_22,    /* support export and import compress attribution of table or partition table */
    CS_VERSION_23,    /* 1. support send the local IP address after the replication connected
                         2. support cursor sharing and send param name instead of offset and len
                         3. support send message with text format instead of str(login ack or send result error or pl warning)
                         4. support lob storage_clause language when export table define
                         5. support index_partitioning_clauses language when export table indexes */
    CS_VERSION_24,    /* support jsonb
                         1. load: add convert_jsonb parameter
                         2. exp:  print the col_type of jsonb columns is 'JSONB',
                                  and not allowed exp jsonb data with TXT
                         3. support: exp/imp support subpartion format csf */
    CS_VERSION_25,    /* 1. support: exp indexes support nologging attribute */
    /* remember to modify and CS_LOCAL_VERSION if add new version !!! */
} cs_packet_version_t;

#define CS_LOCAL_MAJOR_VER_WEIGHT 1000000
#define CS_LOCAL_MINOR_VER_WEIGHT 1000
#define CS_LOCAL_MAJOR_VERSION    0
#define CS_LOCAL_MINOR_VERSION    0
#define CS_LOCAL_VERSION (uint32) (CS_VERSION_25 + \
                                   CS_LOCAL_MINOR_VERSION * CS_LOCAL_MINOR_VER_WEIGHT + \
                                   CS_LOCAL_MAJOR_VERSION * CS_LOCAL_MAJOR_VER_WEIGHT)

/* support handshake version from CS_VERSION_23, limits [23,255] */
typedef enum en_cs_handshake_version {
    HANDSHAKE_VERSION_1 = 23,
} cs_handshake_version_t;

#define CS_HANDSHAKE_VERSION (uint32) (HANDSHAKE_VERSION_1)

/* every option use one bit of flags in cs_packet_head_t */
#define CS_FLAG_NONE                 0x0000
#define CS_FLAG_MORE_DATA            0x0001  // continue to recv more parse sql in prepare process or not
#define CS_FLAG_PEER_CLOSED          0x0002
#define CS_FLAG_SERVEROUPUT          0x0004 // whether is serveroutput send pack or not
#define CS_FLAG_PL_OUPUT_PARAM       0x0008 // whether has output param data or not
#define CS_FLAG_RETURN_GENERATED_KEY 0x0010
#define CS_FLAG_FEEDBACK             0x0020 // flag whether to recv and proc a feedback message when execute a DDL/DCL
#define CS_FLAG_WITH_TS              0x0040 // with timestamp or not
#define CS_FLAG_INTERACTIVE_CLT      0x0080 // whether is interactive client connect to server or not
#define CS_FLAG_RETURNRESULT         0x0100 // whether is return result send pack or not
#define CS_FLAG_CLIENT_SSL           0x0200 // use SSL encryption for the session, switch to SSL after sending the capability-flags
#define CS_FLAG_CTSQL_IN_ALTPWD       0x0400 // CTSQL supports interactive password change for expired accounts
#define CT_FLAG_CN_USE_ROUTE         0x0800 // CN direct route information
#define CT_FLAG_ALLOWED_BATCH_ERRS   0x1000 // whether has allowed errors or not
#define CT_FLAG_CREATE_TABLE_AS      0x2000 // whether create table as select
#define CT_FLAG_REMOTE_AS_SYSDBA     0x4000 // support for remote connect as sysdba
#define CT_FLAG_EXTEND               0x8000 // already used for extend flag packet

/* The type of feedback message */
typedef enum en_feedback {
    FB_ALTSESSION_SET_NLS,       /* alter session set nls... @see sql_send_nls_feedback */
    FB_ALTSESSION_SET_SESSIONTZ, /* alter session set sessiontz... @see sql_send_session_tz_feedback */
} feedback_t;

#define CS_HAS_FEEDBACK_MSG(head) ((head)->flags & CS_FLAG_FEEDBACK)

#define CS_ALIGN_SIZE 4

#define CS_WAIT_FOR_READ  1
#define CS_WAIT_FOR_WRITE 2

typedef enum en_cs_option {
    CSO_DIFFERENT_ENDIAN = 0x00000001,
    CSO_CN_CONNECTION = 0x00000002,
    CSO_CN_IN_ALTER_PWD = 0x00000004,
    CSO_CLIENT_SSL = 0x00000200,  // support client SSL
    CS_FLAG_CN_CONN = 0x00000400, // the server is CN
    CS_FLAG_DN_CONN = 0x00008000, // the server is DN
} cs_option_t;

typedef struct tagcs_packet {
    uint32 offset;   // for reading
    uint32 options;  // options
    cs_packet_head_t *head;
    uint32 max_buf_size;  // MAX_ALLOWED_PACKET
    uint32 buf_size;
    char *buf;
    char init_buf[CT_MAX_PACKET_SIZE];
} cs_packet_t;

typedef struct {
    int16 commit_batch;
    int16 commit_nowait;
    uint32 lock_wait_timeout;
    uint8 nologging_enable;
    uint8 isolevel;
    uint8 reserved[2];
    char curr_schema[CT_NAME_BUFFER_SIZE];
    char curr_user2[CT_NAME_BUFFER_SIZE];
}alter_set_info_t;

#define CS_PACKET_SIZE(pack)          ((pack)->head->size)
#define CS_WRITE_ADDR(pack)           ((pack)->buf + (pack)->head->size)
#define CS_RESERVE_ADDR(pack, offset) ((pack)->buf + (offset))
#define CS_READ_ADDR(pack)            ((pack)->buf + (pack)->offset)
#define CS_REMAIN_SIZE(pack)          ((int32)((pack)->buf_size - (int32)((pack)->head->size)))
#define CS_HAS_REMAIN(pack, sz)       (((sz) < (pack)->buf_size) && ((pack)->head->size + (sz) <= (pack)->buf_size))
#define CS_DATA_ADDR(pack)            ((pack)->buf + sizeof(cs_packet_head_t))
#define CS_HAS_MORE(pack)             ((pack)->head->size > (pack)->offset)
#define CS_HAS_RECV_REMAIN(pack, sz)  (((sz) < (pack)->head->size) && ((pack)->offset + (sz) <= (pack)->head->size))
#define CS_REMAIN_RECV_SIZE(pack)     ((int32)((pack)->head->size - (int32)((pack)->offset)))
#define CS_HAS_EXEC_ERROR(ack_pack)   ((ack_pack)->head->result != 0)
#define CS_PACKET_OFFSET(pack)        ((pack)->offset)

#define CS_DIFFERENT_ENDIAN(options) ((options) & CSO_DIFFERENT_ENDIAN)
#define CS_IS_CN_CONNECTION(options) ((options) & CSO_CN_CONNECTION)
#define CS_IS_CN_IN_ALTER_PWD(options) ((options) & CSO_CN_IN_ALTER_PWD)
#define CS_XACT_WITH_TS(flags)       ((flags) & CS_FLAG_WITH_TS)
#define CS_CREATE_TABLE_AS(flags)    ((flags) & CT_FLAG_CREATE_TABLE_AS)

/*
 * check the send-buffer size, extend the buffer dynamicly if need.
 * default buffer size is CT_MAX_PACKET_SIZE;
 * if max_buf_size == buf_size == CT_MAX_PACKET_SIZE, use default buffer, not extend;
 * Hint : remember to free the buf if it's extended dynamicly by malloc;
 */
#define CM_REALLOC_SEND_PACK_SIZE(pack, len) ((pack)->head->size + CM_ALIGN_8K(len))

static status_t cs_try_realloc_send_pack(cs_packet_t *pack, uint32 expect_size)
{
    errno_t errcode = 0;
    if (!CS_HAS_REMAIN(pack, expect_size)) {
        if (CT_MAX_UINT32 - pack->head->size < (uint32)CM_ALIGN_8K(expect_size)) {
            CT_THROW_ERROR(ERR_NUM_OVERFLOW);
            return CT_ERROR;
        }
        // extend memory align 8K
        if (CT_MAX_UINT32 - pack->head->size < CM_ALIGN_8K(expect_size)) {
            CT_THROW_ERROR(ERR_NUM_OVERFLOW);
            return CT_ERROR;
        }

        if (pack->head->size + expect_size > pack->max_buf_size) {
            CT_THROW_ERROR(ERR_FULL_PACKET, "send", pack->head->size + expect_size, pack->max_buf_size);
            return CT_ERROR;
        }
        uint32 new_buf_size = MIN(CM_REALLOC_SEND_PACK_SIZE(pack, expect_size), pack->max_buf_size);

        char *new_buf = (char *)malloc(new_buf_size);
        if (new_buf == NULL) {
            CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)new_buf_size, "large packet buffer");
            return CT_ERROR;
        }
        errcode = memcpy_s(new_buf, new_buf_size, pack->buf, pack->head->size);
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            CM_FREE_PTR(new_buf);
            return CT_ERROR;
        }
        if (pack->buf != pack->init_buf) {
            errcode = memset_s(pack->buf, pack->buf_size, 0, pack->head->size);
            if (SECUREC_UNLIKELY(errcode != EOK)) {
                CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
                CM_FREE_PTR(new_buf);
                return CT_ERROR;
            }
            CM_FREE_PTR(pack->buf);
        }

        pack->buf_size = new_buf_size;
        pack->buf = new_buf;
        pack->head = (cs_packet_head_t *)pack->buf;
    }

    return CT_SUCCESS;
}

#define CM_CHECK_SEND_PACK_FREE(pack, len) CT_RETURN_IFERR(cs_try_realloc_send_pack(pack, len))

#define CM_CHECK_RECV_PACK_FREE(pack, len)                                                    \
    {                                                                                         \
        if (!CS_HAS_RECV_REMAIN(pack, len)) {                                                 \
            CT_THROW_ERROR(ERR_PACKET_READ, (pack)->head->size, (pack)->offset, (uint32)(len)); \
            return CT_ERROR;                                                                  \
        }                                                                                     \
    }

static inline uint32 cs_reverse_int32(uint32 value)
{
    uint32 result;
    uint8 *v_bytes = (uint8 *)&value;
    uint8 *r_bytes = (uint8 *)&result;
    r_bytes[0] = v_bytes[3];
    r_bytes[1] = v_bytes[2];
    r_bytes[2] = v_bytes[1];
    r_bytes[3] = v_bytes[0];
    return result;
}

static inline uint32 cs_reverse_uint32(uint32 value)
{
    return cs_reverse_int32(value);
}

static inline uint16 cs_reverse_int16(uint16 value)
{
    uint16 result;
    uint8 *v_bytes = (uint8 *)&value;
    uint8 *r_bytes = (uint8 *)&result;
    r_bytes[0] = v_bytes[1];
    r_bytes[1] = v_bytes[0];
    return result;
}

static inline uint64 cs_reverse_int64(uint64 value)
{
    uint64 result;
    uint32 *v_int32, *r_int32;

    v_int32 = (uint32 *)&value;
    r_int32 = (uint32 *)&result;
    r_int32[1] = cs_reverse_int32(v_int32[0]);
    r_int32[0] = cs_reverse_int32(v_int32[1]);
    return result;
}

static inline double cs_reverse_real(double value)
{
    double tmp_value, result;
    uint16 *v_int16 = (uint16 *)&value;
    uint16 *tmp_int16 = (uint16 *)&tmp_value;
    uint16 *r_int16 = (uint16 *)&result;
    uint32 *tmp_int32 = (uint32 *)&tmp_value;

    tmp_int16[0] = v_int16[0];
    tmp_int16[1] = v_int16[3];
    tmp_int16[2] = v_int16[1];
    tmp_int16[3] = v_int16[2];

    tmp_int32[0] = cs_reverse_int32(tmp_int32[0]);
    tmp_int32[1] = cs_reverse_int32(tmp_int32[1]);

    r_int16[0] = tmp_int16[0];
    r_int16[3] = tmp_int16[1];
    r_int16[1] = tmp_int16[2];
    r_int16[2] = tmp_int16[3];

    return result;
}

#define cs_reverse_date cs_reverse_int64

static inline uint16 cs_format_endian_i16(uint32 options, uint16 i16)
{
    return CS_DIFFERENT_ENDIAN(options) ? cs_reverse_int16(i16) : i16;
}

static inline uint32 cs_format_endian_i32(uint32 options, uint32 i32)
{
    return CS_DIFFERENT_ENDIAN(options) ? cs_reverse_int32(i32) : i32;
}

static inline uint64 cs_format_endian_i64(uint32 options, uint64 i64)
{
    return CS_DIFFERENT_ENDIAN(options) ? cs_reverse_int64(i64) : i64;
}

static inline void cs_init_packet(cs_packet_t *pack, uint32 options)
{
    CM_POINTER(pack);
    pack->offset = 0;
    pack->max_buf_size = CT_MAX_PACKET_SIZE;
    pack->buf_size = CT_MAX_PACKET_SIZE;
    pack->buf = pack->init_buf;
    pack->head = (cs_packet_head_t *)pack->buf;
    pack->options = options;
}

static inline uint32 cs_get_version(cs_packet_t *pack)
{
    return (uint32)pack->head->version +
           (uint32)pack->head->minor_version * CS_LOCAL_MINOR_VER_WEIGHT +
           (uint32)pack->head->major_version * CS_LOCAL_MAJOR_VER_WEIGHT;
}

static inline void cs_set_version(cs_packet_t *pack, uint32 version)
{
    pack->head->version = (uint8)(version % CS_LOCAL_MINOR_VER_WEIGHT);
    pack->head->minor_version = (uint8)((version % CS_LOCAL_MAJOR_VER_WEIGHT) / CS_LOCAL_MINOR_VER_WEIGHT);
    pack->head->major_version = (uint8)(version / CS_LOCAL_MAJOR_VER_WEIGHT);
}

static inline status_t cs_try_realloc_packet_buffer(cs_packet_t *pack, uint32 offset)
{
    errno_t errcode = 0;
    if (pack->head->size > pack->buf_size) {
        uint32 new_buf_size = CM_ALIGN_8K(pack->head->size);  // align with 8K
        if (pack->head->size > pack->max_buf_size || new_buf_size > pack->max_buf_size) {
            CT_THROW_ERROR(ERR_FULL_PACKET, "request", new_buf_size, pack->max_buf_size);
            return CT_ERROR;
        }
        char *new_buf = (char *)malloc(new_buf_size);
        if (new_buf == NULL) {
            CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)new_buf_size, "large packet buffer");
            return CT_ERROR;
        }
        errcode = memcpy_s(new_buf, new_buf_size, pack->buf, offset);
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            CM_FREE_PTR(new_buf);
            return CT_ERROR;
        }

        if (pack->buf != pack->init_buf) {
            CM_FREE_PTR(pack->buf);
        }

        pack->buf_size = new_buf_size;
        pack->buf = new_buf;
        pack->head = (cs_packet_head_t *)pack->buf;
    }

    return CT_SUCCESS;
}

static inline void cs_try_free_packet_buffer(cs_packet_t *pack)
{
    if (pack->buf && pack->buf != pack->init_buf) {
        free(pack->buf);

        pack->buf_size = CT_MAX_PACKET_SIZE;
        pack->buf = pack->init_buf;
        pack->head = (cs_packet_head_t *)pack->buf;
    }
}

static inline void cs_init_get(cs_packet_t *pack)
{
    CM_POINTER(pack);
    pack->offset = sizeof(cs_packet_head_t);
}

static inline void cs_init_set(cs_packet_t *pack, uint32 call_version)
{
    CM_POINTER(pack);
    pack->head->size = sizeof(cs_packet_head_t);
    pack->head->result = 0;
    pack->head->flags = 0;
    cs_set_version(pack, call_version);
    pack->head->extended = 0;
}

/*
   reserve a space with size "size" in the pack
   and use CS_RESERVE_SPACE_ADDR to get the address of reserve space.
*/
static inline status_t cs_reserve_space(cs_packet_t *pack, uint32 size, uint32 *offset)
{
    char *temp_buf = NULL;
    CM_POINTER(pack);
    CM_CHECK_SEND_PACK_FREE(pack, CM_ALIGN4(size));

    temp_buf = CS_WRITE_ADDR(pack);
    pack->head->size += CM_ALIGN4(size);

    if (offset != NULL) {
        *offset = (uint32)(temp_buf - pack->buf);
    }

    return CT_SUCCESS;
}

static inline status_t cs_put_str(cs_packet_t *pack, const char *str)
{
    uint32 size;
    char *addr = NULL;
    CM_POINTER2(pack, str);
    size = (uint32)strlen(str);
    CM_CHECK_SEND_PACK_FREE(pack, CM_ALIGN4(size + 1));

    addr = CS_WRITE_ADDR(pack);
    if (size != 0) {
        MEMS_RETURN_IFERR(memcpy_s(addr, CS_REMAIN_SIZE(pack), str, size));
    }
    CS_WRITE_ADDR(pack)[size] = '\0';
    pack->head->size += CM_ALIGN4(size + 1);

    return CT_SUCCESS;
}

static inline status_t cs_put_data(cs_packet_t *pack, const void *data, uint32 size)
{
    CM_POINTER2(pack, data);
    CM_CHECK_SEND_PACK_FREE(pack, CM_ALIGN4(size));
    if (size != 0) {
        MEMS_RETURN_IFERR(memcpy_s(CS_WRITE_ADDR(pack), CS_REMAIN_SIZE(pack), data, size));
    }
    pack->head->size += CM_ALIGN4(size);
    return CT_SUCCESS;
}

static inline status_t cs_put_int64(cs_packet_t *pack, uint64 value)
{
    CM_POINTER(pack);
    CM_CHECK_SEND_PACK_FREE(pack, sizeof(uint64));

    *(uint64 *)CS_WRITE_ADDR(pack) = CS_DIFFERENT_ENDIAN(pack->options) ? cs_reverse_int64(value) : value;
    pack->head->size += sizeof(uint64);
    return CT_SUCCESS;
}

static inline status_t cs_put_int32(cs_packet_t *pack, uint32 value)
{
    CM_POINTER(pack);
    CM_CHECK_SEND_PACK_FREE(pack, sizeof(uint32));

    *(uint32 *)CS_WRITE_ADDR(pack) = CS_DIFFERENT_ENDIAN(pack->options) ? cs_reverse_int32(value) : value;
    pack->head->size += sizeof(uint32);
    return CT_SUCCESS;
}

static inline status_t cs_put_int16(cs_packet_t *pack, uint16 value)
{
    CM_POINTER(pack);
    CM_CHECK_SEND_PACK_FREE(pack, CS_ALIGN_SIZE);
    *(uint16 *)CS_WRITE_ADDR(pack) = CS_DIFFERENT_ENDIAN(pack->options) ? cs_reverse_int16(value) : value;
    pack->head->size += CS_ALIGN_SIZE;
    return CT_SUCCESS;
}

static inline status_t cs_put_real(cs_packet_t *pack, double value)
{
    CM_POINTER(pack);
    CM_CHECK_SEND_PACK_FREE(pack, sizeof(double));
    *(double *)CS_WRITE_ADDR(pack) = CS_DIFFERENT_ENDIAN(pack->options) ? cs_reverse_real(value) : value;
    pack->head->size += sizeof(double);
    return CT_SUCCESS;
}

static inline status_t cs_put_date(cs_packet_t *pack, date_t value)
{
    CM_POINTER(pack);
    CM_CHECK_SEND_PACK_FREE(pack, sizeof(date_t));
    *(date_t *)CS_WRITE_ADDR(pack) = CS_DIFFERENT_ENDIAN(pack->options) ? cs_reverse_date(value) : value;
    pack->head->size += sizeof(date_t);
    return CT_SUCCESS;
}

static inline status_t cs_put_text(cs_packet_t *pack, text_t *text)
{
    CM_POINTER2(pack, text);
    CM_CHECK_SEND_PACK_FREE(pack, sizeof(uint32) + CM_ALIGN4(text->len));
    /* put the length of text */
    (void)cs_put_int32(pack, text->len);
    if (text->len == 0) {
        return CT_SUCCESS;
    }
    /* put the string of text, and append the terminated sign */
    MEMS_RETURN_IFERR(memcpy_s(CS_WRITE_ADDR(pack), CS_REMAIN_SIZE(pack), text->str, text->len));
    pack->head->size += CM_ALIGN4(text->len);
    return CT_SUCCESS;
}

static inline status_t cs_put_scn(cs_packet_t *pack, uint64* scn)
{
    return cs_put_int64(pack, *scn);
}

static inline status_t cs_put_timestamp(cs_packet_t *pack, const struct timeval *ts)
{
    cs_timeval_t *tmp_tv = NULL;
    uint32        offset;
    CT_RETURN_IFERR(cs_reserve_space(pack, sizeof(cs_timeval_t), &offset));
    tmp_tv = (cs_timeval_t *)CS_RESERVE_ADDR(pack, offset);
#ifdef WIN32
    if (CS_DIFFERENT_ENDIAN(pack->options)) {
        tmp_tv->tv_sec =  (uint64)cs_reverse_int32((uint32)ts->tv_sec);
        tmp_tv->tv_usec = (uint64)cs_reverse_int32((uint32)ts->tv_usec);
    } else {
        tmp_tv->tv_sec = (uint64)ts->tv_sec;
        tmp_tv->tv_usec = (uint64)ts->tv_usec;
    }
#else
    if (CS_DIFFERENT_ENDIAN(pack->options)) {
        tmp_tv->tv_sec = cs_reverse_int64((uint64)ts->tv_sec);
        tmp_tv->tv_usec = cs_reverse_int64((uint64)ts->tv_usec);
    } else {
        tmp_tv->tv_sec = (uint64)ts->tv_sec;
        tmp_tv->tv_usec = (uint64)ts->tv_usec;
    }
#endif
    return CT_SUCCESS;
}

static inline status_t cs_put_err_msg(cs_packet_t *pack, uint32 call_version, const char *err_msg)
{
    text_t msg_text;

    if (call_version >= CS_VERSION_23) {
        msg_text.str = (char *)err_msg;
        msg_text.len = (uint32)strlen(err_msg);
        return cs_put_text(pack, &msg_text);
    } else {
        return cs_put_str(pack, err_msg);
    }
}

static inline status_t cs_inc_head_size(cs_packet_t *pack, uint32 size)
{
    CM_POINTER(pack);
    CM_CHECK_SEND_PACK_FREE(pack, CM_ALIGN4(size));
    pack->head->size += CM_ALIGN4(size);
    return CT_SUCCESS;
}

static inline status_t cs_get_data(cs_packet_t *pack, uint32 size, void **buf)
{
    int64 len;
    char *temp_buf = NULL;
    CM_POINTER(pack);
    len = CM_ALIGN4((uint64)size);
    TO_UINT32_OVERFLOW_CHECK(len, int64);
    CM_CHECK_RECV_PACK_FREE(pack, (uint32)len);
    temp_buf = CS_READ_ADDR(pack);
    pack->offset += CM_ALIGN4(size);
    if (buf != NULL) {
        *buf = (size > 0) ? (void *)temp_buf : NULL;
    }
    return CT_SUCCESS;
}

static inline status_t cs_get_str(cs_packet_t *pack, char **buf)
{
    char *str = NULL;
    int64 len;
    size_t str_len;
    CM_POINTER(pack);

    str = CS_READ_ADDR(pack);
    str_len = strlen(str) + 1;
    
    len = CM_ALIGN4(str_len);
    TO_UINT32_OVERFLOW_CHECK(len, int64);
    CM_CHECK_RECV_PACK_FREE(pack, (uint32) len);
    pack->offset += (uint32)len;
    if (buf != NULL) {
        *buf = str;
    }
    return CT_SUCCESS;
}

static inline status_t cs_get_int64(cs_packet_t *pack, int64 *value)
{
    int64 temp_value;
    CM_POINTER(pack);
    CM_CHECK_RECV_PACK_FREE(pack, sizeof(int64));
    temp_value = *(int64 *)CS_READ_ADDR(pack);
    temp_value = CS_DIFFERENT_ENDIAN(pack->options) ? cs_reverse_int64(temp_value) : temp_value;
    pack->offset += sizeof(int64);
    if (value != NULL) {
        *value = temp_value;
    }
    return CT_SUCCESS;
}

static inline status_t cs_get_int32(cs_packet_t *pack, int32 *value)
{
    int32 temp_value;
    CM_POINTER(pack);
    CM_CHECK_RECV_PACK_FREE(pack, sizeof(int32));
    temp_value = *(int32 *)CS_READ_ADDR(pack);
    pack->offset += sizeof(int32);
    temp_value = CS_DIFFERENT_ENDIAN(pack->options) ? cs_reverse_int32(temp_value) : temp_value;
    if (value != NULL) {
        *value = temp_value;
    }
    return CT_SUCCESS;
}

/* need keep 4-byte align by the caller */
static inline status_t cs_get_int16(cs_packet_t *pack, int16 *value)
{
    int16 temp_value;
    CM_POINTER(pack);
    CM_CHECK_RECV_PACK_FREE(pack, CS_ALIGN_SIZE);

    temp_value = *(int16 *)CS_READ_ADDR(pack);
    pack->offset += CS_ALIGN_SIZE;
    temp_value = CS_DIFFERENT_ENDIAN(pack->options) ? cs_reverse_int16(temp_value) : temp_value;
    if (value != NULL) {
        *value = temp_value;
    }
    return CT_SUCCESS;
}

static inline status_t cs_get_double(cs_packet_t *pack, double *value)
{
    double temp_value;
    CM_POINTER(pack);
    CM_CHECK_RECV_PACK_FREE(pack, sizeof(double));
    temp_value = *(double *)CS_READ_ADDR(pack);
    pack->offset += sizeof(double);
    temp_value = CS_DIFFERENT_ENDIAN(pack->options) ? cs_reverse_real(temp_value) : temp_value;
    if (value != NULL) {
        *value = temp_value;
    }
    return CT_SUCCESS;
}

static inline status_t cs_get_text(cs_packet_t *pack, text_t *text)
{
    CM_POINTER2(pack, text);
    CT_RETURN_IFERR(cs_get_int32(pack, (int32 *)&text->len));
    
    return cs_get_data(pack, text->len, (void **)&(text->str));
}

static inline status_t cs_get_scn(cs_packet_t *pack, uint64 *scn)
{
    return cs_get_int64(pack, (int64 *)scn);
}

static inline status_t cs_get_timestamp(cs_packet_t *pack, struct timeval *ts)
{
    cs_timeval_t *tmp_tv = NULL;
    CT_RETURN_IFERR(cs_get_data(pack, sizeof(cs_timeval_t), (void **)&tmp_tv));
#ifdef WIN32
    if (CS_DIFFERENT_ENDIAN(pack->options)) {
        ts->tv_sec = (long)cs_reverse_int64(tmp_tv->tv_sec);
        ts->tv_usec = (long)cs_reverse_int64(tmp_tv->tv_usec);
    } else {
        ts->tv_sec = (long)tmp_tv->tv_sec;
        ts->tv_usec = (long)tmp_tv->tv_usec;
    }
#else
    if (CS_DIFFERENT_ENDIAN(pack->options)) {
        ts->tv_sec = (time_t)cs_reverse_int64(tmp_tv->tv_sec);
        ts->tv_usec = (suseconds_t)cs_reverse_int64(tmp_tv->tv_usec);
    } else {
        ts->tv_sec = (time_t)tmp_tv->tv_sec;
        ts->tv_usec = (suseconds_t)tmp_tv->tv_usec;
    }
#endif
    return CT_SUCCESS;
}

static inline uint8 cs_get_param_isnull(uint8 flag)
{
    // bit[0] can be 0 1
    return ((flag & 0x01) == 0x01) ? (uint8)CT_TRUE : (uint8)CT_FALSE;
}

static inline uint8 cs_get_param_direction(uint8 flag)
{
    // bit[6]bit[7] can be 00 01 10 11
    if ((flag & 0x40) == 0x40) {
        return ((flag & 0x80) == 0x80) ? CT_INOUT_PARAM : CT_INPUT_PARAM;
    } else {
        return ((flag & 0x80) == 0x80) ? CT_OUTPUT_PARAM : CT_INPUT_PARAM;
    }
}

static inline status_t cs_copy_packet(cs_packet_t *src, cs_packet_t *dst)
{
    uint32 copy_len = CS_PACKET_SIZE(src);
    errno_t errcode;
    dst->offset = src->offset;
    dst->options = src->options;
    // set dst max_extend size
    dst->max_buf_size = src->max_buf_size;

    // copy src packet to dst packet
    dst->head->size = 0;  // reset write offset
    CM_CHECK_SEND_PACK_FREE(dst, copy_len);
    errcode = memcpy_s(dst->buf, dst->buf_size, src->buf, copy_len);
    if (errcode != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static inline void cs_free_packet_buffer(cs_packet_t *pack)
{
    if (pack->buf != NULL && pack->buf != pack->init_buf) {
        CM_FREE_PTR(pack->buf);
        cs_init_packet(pack, 0);
    }
}

#ifdef __cplusplus
}
#endif

#endif

