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
 * cs_protocol.h
 *
 *
 * IDENTIFICATION
 * src/protocol/cs_protocol.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CS_PROTOCOL_H__
#define __CS_PROTOCOL_H__

#include "cm_defs.h"
#include "cm_text.h"
#include "cm_binary.h"
#include "cm_decimal.h"
#include "var_inc.h"
#include "cs_packet.h"
#include "cm_encrypt.h"

#define CS_CMD_UNKONOW       (uint8)0
#define CS_CMD_LOGIN         (uint8)1
#define CS_CMD_FREE_STMT     (uint8)2 /* ct_alloc_stmt() command is included in CS_CMD_PREPARE requestion */
#define CS_CMD_PREPARE       (uint8)3
#define CS_CMD_MORE_DATA     (uint8)4
#define CS_CMD_EXECUTE       (uint8)5
#define CS_CMD_FETCH         (uint8)6
#define CS_CMD_COMMIT        (uint8)7
#define CS_CMD_ROLLBACK      (uint8)8
#define CS_CMD_LOGOUT        (uint8)9
#define CS_CMD_CANCEL        (uint8)10
#define CS_CMD_QUERY         (uint8)11
#define CS_CMD_PREP_AND_EXEC (uint8)12
#define CS_CMD_LOB_READ      (uint8)13
#define CS_CMD_LOB_WRITE     (uint8)14
#define CS_CMD_XA_PREPARE    (uint8)15
#define CS_CMD_XA_COMMIT     (uint8)16
#define CS_CMD_XA_ROLLBACK   (uint8)17
#define CS_CMD_GTS           (uint8)18 /* added for z_sharding */
#define CS_CMD_HANDSHAKE     (uint8)19 /* process before login, added since v2.0; for SSL only since v9.0 */
#define CS_CMD_REP_LOGIN     (uint8)20
#define CS_CMD_AUTH_INIT     (uint8)21 /* request for user auth info, added since v9.0 */

#define CS_CMD_XA_START      (uint8)22
#define CS_CMD_XA_END        (uint8)23
#define CS_CMD_XA_STATUS     (uint8)24

#define CS_CMD_SEQUENCE      (uint8)25 /* added for z_sharding */
#define CS_CMD_AUTH_CHECK    (uint8)26 /* REPL_AUTH for primary and standby must be same */
#define CS_CMD_REPAUTH_LOGIN (uint8)27 /* check cipher when replication login */
#define CS_CMD_LOAD          (uint8)28
#define CS_CMD_STMT_ROLLBACK (uint8)29 /* added for shard statement-level rollback */
#define CS_CMD_EXE_MULTI_SQL (uint8)30
#define CS_CMD_REPL_HOST     (uint8)31 /* send the local IP address to peer instance */

#define CS_CMD_CEIL          (uint8)32 /* the ceil of cmd */

typedef enum en_protocol_type {
    PROTO_TYPE_UNKNOWN = 0,
    PROTO_TYPE_CT = 1,
} protocol_type_t;

typedef enum en_client_kind {
    CLIENT_KIND_UNKNOWN = 0,
    CLIENT_KIND_CTCONN_GENERIC = 1, /* for the most common program which use the ctconn library */
    CLIENT_KIND_JDBC = 2,
    CLIENT_KIND_CTSQL = 3,
    CLIENT_KIND_CN_INNER = 4, // resv for CN private channel
    CLIENT_KIND_TAIL, /* DO NOT ADD new type below CLIENT_KIND_TAIL */
} client_kind_t;

typedef enum en_sequence_mode {
    SEQ_FETCH_CACHE  = 1,
    SEQ_SET_NEXTVAL,
    SEQ_GET_NEXTVAL,
    SEQ_ALTER_NOTIFY,
    SEQ_GET_CN_NEXTVAL,
} sequence_mode_t;

typedef struct st_client_kind_item {
    text_t name;
} client_kind_item_t;

extern const client_kind_item_t g_module_names[CLIENT_KIND_TAIL];

/*
 * get the name (text_t) according to the client kind.
 */
static inline const text_t *cs_get_login_client_name(client_kind_t kind)
{
    return &g_module_names[kind].name;
}

#define CS_PREP_AUTOTRACE 0x0001
#define CS_LOAD_GET_SQL   0x0002
#define CS_LOAD_GET_DATA  0x0004
#define CS_LOAD_EXE_CMD   0x0008
#define CS_CN_DML_ID      0x0010
#define CS_CTSQL_IN_ALTPWD 0x0020

typedef struct st_cs_prepare_req {
    uint16 stmt_id;
    uint16 flags;
} cs_prepare_req_t;

typedef struct st_cs_prepare_ack {
    uint16 stmt_id;
    uint16 stmt_type;
    uint16 column_count;
    uint16 param_count;
} cs_prepare_ack_t;

/* attributes of column flag */
#define CT_COLUMN_FLAG_NULLABLE       0x01
#define CT_COLUMN_FLAG_AUTO_INCREMENT 0x02
#define CT_COLUMN_FLAG_CHARACTER      0x04
#define CT_COLUMN_FLAG_ARRAY          0x08
#define CT_COLUMN_FLAG_JSONB          0x10

#define CT_COLUMN_SET_NULLABLE(col)       (col)->flag |= CT_COLUMN_FLAG_NULLABLE
#define CT_COLUMN_SET_AUTO_INCREMENT(col) (col)->flag |= CT_COLUMN_FLAG_AUTO_INCREMENT
#define CT_COLUMN_SET_CHARACTER(col)      (col)->flag |= CT_COLUMN_FLAG_CHARACTER
#define CT_COLUMN_SET_ARRAY(col)          (col)->flag |= CT_COLUMN_FLAG_ARRAY
#define CT_COLUMN_SET_JSONB(col)          (col)->flag |= CT_COLUMN_FLAG_JSONB

#define CT_COLUMN_IS_NULLABLE(col)       (((col)->flag & CT_COLUMN_FLAG_NULLABLE) != 0)
#define CT_COLUMN_IS_AUTO_INCREMENT(col) (((col)->flag & CT_COLUMN_FLAG_AUTO_INCREMENT) != 0)
#define CT_COLUMN_IS_CHARACTER(col)      (((col)->flag & CT_COLUMN_FLAG_CHARACTER) != 0)
#define CT_COLUMN_IS_ARRAY(col)          (((col)->flag & CT_COLUMN_FLAG_ARRAY) != 0)
#define CT_COLUMN_IS_JSONB(col)          (((col)->flag & CT_COLUMN_FLAG_JSONB) != 0)

typedef struct st_cs_column_def {
    uint16 size;
    uint8 precision;
    int8 scale;
    uint16 datatype;
    uint8 flag;  // nullable,auto_increment,character...
    uint8 reserved[3];
    uint16 name_len;
    // char name[0]; no new vaiable name here, due to byte alignment
} cs_column_def_t;

typedef struct st_cs_final_column_def {
    uint16 col_id;
    uint16 size;
    uint8 precision;
    int8 scale;
    uint16 datatype;
} cs_final_column_def_t;

typedef struct st_cs_param_def {
    uint32 offset;
    uint32 len;
} cs_param_def_t;

typedef struct st_cs_param_def_new {
    uint32 len;
    char   data[0];
} cs_param_def_new_t;

typedef struct st_cs_outparam_def {
    char name[CT_NAME_BUFFER_SIZE];
    uint16 size;
    uint8 direction;
    uint8 datatype;
} cs_outparam_def_t;

typedef struct st_cs_execute_req {
    uint16 stmt_id;
    uint16 paramset_size;
    uint16 prefetch_rows;
    uint8 auto_commit;
    uint8 reserved;
} cs_execute_req_t;

typedef struct st_cs_execute_ack {
    uint32 batch_count;
    uint32 total_rows;  // affected rows
    uint16 batch_rows;  /* number of rows in a batch */
    uint8 rows_more;
    uint8 xact_status;
    uint16 pending_col_count;
    uint16 batch_errs;
    cs_final_column_def_t pending_col_defs[0];
} cs_execute_ack_t;

typedef struct st_cs_prep_exec_param {
    uint16 paramset_size;
    uint16 prefetch_rows;
    uint8 auto_commit;
    uint8 reserved[3];
} cs_prep_exec_param;

typedef struct st_cs_prep_exec_multi_sql {
    uint16 stmt_id;
    uint8 auto_commit;
    uint8 reserved;
    uint32 sql_num;
} cs_prep_exec_multi_sql_t;

typedef struct st_cs_multi_param_info {
    uint16 paramset_size;
    uint16 reserved;
} cs_multi_param_info_t;

typedef struct st_cs_prep_exec_multi_ack {
    uint16 stmt_id;
    uint16 reserved;
    uint32 sql_num;
} cs_prep_exec_multi_ack_t;

typedef struct st_fetch_req {
    uint16 stmt_id;
    uint8 fetch_mode; /* 0, normal fetch; 1, prepare and execute; 2 prepare and fetch */
    uint8 reserved;
} cs_fetch_req_t;

typedef enum en_fetch_mode {
    CS_FETCH_NORMAL = 0,
    CS_FETCH_WITH_PREP_EXEC = 1,  // with prepare and execute
    CS_FETCH_WITH_PREP = 2,       // with prepare
} fetch_mode_t;

typedef struct st_fetch_ack {
    uint32    total_rows;
    uint16    batch_rows;
    uint8     rows_more;
    uint8     reserved;
} cs_fetch_ack_t;

typedef struct st_cs_param_head {
    uint16 len;
    int8 type;
    uint8 flag;  // bit[0] is for is_null, bit[6]bit[7] is for direction
} cs_param_head_t;

#define CS_PARAM_HEAD_SIZE      sizeof(cs_param_head_t)
#define LOB_LOCATOR_BUFFER_SIZE 40

typedef struct st_lob_read_req {
    uint16 stmt_id;
    uint16 reserved;
    uint32 size;
    uint32 offset;
    char locator[0];  // len of locator depends on locator_size in cs_login_ack_t
} lob_read_req_t;

typedef struct st_lob_read_ack {
    uint32 size;
    bool32 eof;
} lob_read_ack_t;

typedef struct st_lob_write_req {
    uint16 stmt_id;
    uint16 reserved;
    uint32 size;
    vm_cli_lob_t vlob;
} lob_write_req_t;

#define ACK_LANG_TYPE(stmt_type)           (((uint16)(stmt_type)) >> 12)
#define ACK_SQL_TYPE(stmt_type)            (((uint16)(stmt_type)) & 0x0FFF)
#define ACK_STMT_TYPE(lang_type, sql_type) ((((uint16)(lang_type)) << 12) | (((uint16)(sql_type)) & 0x0FFF))

void cs_putted_fetch_req(cs_packet_t *pack, uint32 fetch_req_offset);
void cs_putted_execute_req(cs_packet_t *pack, uint32 exec_req_offset);
void cs_putted_prepare_req(cs_packet_t *pack, uint32 prep_req_offset);
void cs_putted_lob_write_req(cs_packet_t *pack, uint32 lob_write_req_offset);
void cs_putted_lob_read_req(cs_packet_t *pack, uint32 lob_read_req_offset);
void cs_putted_param_head(cs_packet_t *pack, uint32 param_head_offset);

status_t cs_get_prepare_ack(cs_packet_t *pack, cs_prepare_ack_t **prepare_ack);
status_t cs_get_param_def(cs_packet_t *pack, cs_param_def_t **param_def);
status_t cs_get_param_def_new(cs_packet_t *pack, cs_param_def_new_t **param_def);
status_t cs_get_column_def(cs_packet_t *pack, cs_column_def_t **column_def);

status_t cs_get_outparam_def(cs_packet_t *pack, cs_outparam_def_t **o_def);

status_t cs_get_exec_ack(cs_packet_t *pack, cs_execute_ack_t **exec_ack);
status_t cs_get_final_column_def(cs_packet_t *pack, cs_final_column_def_t **column_def);

status_t cs_get_fetch_ack(cs_packet_t *pack, cs_fetch_ack_t **fetch_ack);

status_t cs_get_lob_read_ack(cs_packet_t *pack, lob_read_ack_t **lob_read_ack);

#ifdef __cplusplus
extern "C" {
#endif

status_t cs_protocol_compatible(uint32 version);

#ifdef __cplusplus
}
#endif

#endif
