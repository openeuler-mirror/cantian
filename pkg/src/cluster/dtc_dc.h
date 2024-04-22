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
 * dtc_dc.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_dc.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef DTC_DC_H
#define DTC_DC_H
#include "cm_types.h"
#include "cm_defs.h"
#include "knl_session.h"
#include "knl_buffer.h"
#include "mes_func.h"
#include "knl_heap.h"
#include "knl_dc.h"
#include "knl_db_ctrl.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DCS_DDL_REQ_TIMEOUT                 (120000) //ms
#define DCS_DDL_REMOTE_SID                  (0)
#define SYS_CLUSTER_DDL_OP_COLS             3
//#define SYS_CLUSTER_DDL_TABLE               49
#define IX_SYS_CLUSTER_DDL_TABLE_001_ID     0
#define SYS_CLUSTER_DDL_TABLE_LOB_ID        2

typedef enum st_clean_ddl_op {
    DDL_CLEAN_SESSION = 0,
    DDL_REFORM_REPLAY = 1,
    DDL_CLEAN_ALL = 2,
} clean_ddl_op_t;

typedef struct st_ddl_op_desc {
    uint32 sid;
    uint32 log_size;
    uint64 lsn;
    char* logic_log;
} ddl_op_desc_t;

typedef enum st_broadcast_op {
    BTREE_SPLITTING = 0,
    HEAP_EXTEND,
    USER_STATUS,
    INVALIDATE_DC,
    HEAP_EXTEND_STATUS,
    BTREE_SPLIT_STATUS,
    USER_LOCK_STATUS,
    REMOVE_DF_WATCH,
    BROADCAST_END,
} broadcast_op_t;

typedef struct st_msg_broadcast_data {
    mes_message_head_t head;
    uint32 type;
    uint16 data_len;
} msg_broadcast_data_t;

typedef enum en_btree_split_status {
    BTREE_IS_SPLITTING = 1,
    BTREE_IS_SPLITTED = 2,
    BTREE_ABORT_SPLIT = 3,
} btree_split_status_t;

typedef struct st_msg_broadcast_btree_data {
    uint32 table_id;
    uint16 uid;
    uint8 index_id;
    bool8 is_shadow;
    knl_part_locate_t part_loc;
    uint32 split_status;
} msg_broadcast_btree_data_t;

typedef struct st_msg_btree_split_status_t {
    mes_message_head_t head;
    uint32 split_owner;
    bool8 is_splitting;
} msg_btree_split_status_t;

typedef struct st_msg_heap_extend_status_t {
    mes_message_head_t head;
    uint32 extend_owner;
    bool8 is_extending;
} msg_heap_extend_status_t;

typedef struct st_msg_broadcast_heap_data {
    uint32 table_id;
    uint16 uid;
    knl_part_locate_t part_loc;
    bool32 extending;
    bool32 compacting;
} msg_broadcast_heap_data_t;

typedef struct st_msg_broadcast_user_data {
    uint32 uid;
    user_status_t status;
    uint32 user_locked_owner;
} msg_broadcast_user_data_t;

typedef struct st_msg_broadcast_invalidate_dc {
    uint32 uid;
    uint32 oid;
} msg_broadcast_invalidate_dc_t;

typedef struct st_msg_ddl_info {
    mes_message_head_t head;
    knl_scn_t scn;
    uint32 log_len;
} msg_ddl_info_t;

typedef struct st_msg_user_stat_t {
    mes_message_head_t head;
    uint32 uid;
    user_status_t status;
    uint32 user_locked_owner;
} msg_user_stat_t;

typedef struct st_msg_broadcast_upgrade_version_t {
    mes_message_head_t head;
    ctrl_version_t version;
} msg_broadcast_upgrade_version_t;

status_t dtc_sync_ddl_redo(knl_handle_t knl_session, char *redo, uint32 redo_size);
status_t dtc_sync_ddl(knl_handle_t knl_session);
status_t dtc_refresh_ddl(knl_session_t *session, log_entry_t *log);
status_t dtc_broadcast_btree_split(knl_session_t *session, btree_t *btree, knl_part_locate_t part_loc,
                                   bool32 is_splitted);
status_t dtc_broadcast_heap_extend(knl_session_t *session, heap_t *heap, knl_part_locate_t part_loc);
void dtc_broadcast_user_status(knl_session_t *session, uint32 uid, user_status_t status);
EXTER_ATTACK void dtc_process_broadcast_data(void *sess, mes_message_t *msg);
EXTER_ATTACK void dtc_process_check_ddl_enabled(void *sess, mes_message_t *msg);
void dtc_broadcast_invalidate_dc(knl_session_t* session, uint32 uid, uint32 oid);
status_t dtc_get_heap_extend_status(knl_session_t *session, heap_t *heap, knl_part_locate_t part_loc, bool8 *extending);
status_t dtc_get_btree_split_status(knl_session_t *session, btree_t *btree, knl_part_locate_t part_loc,
                                    bool8 *is_splitting);
status_t dtc_ddl_enabled(knl_handle_t knl_session, bool32 forbid_in_rollback);
status_t db_write_ddl_op_internal(knl_session_t* session, char *log, uint32 log_size);
status_t db_write_ddl_op_for_children(knl_session_t* session, table_t* table);
status_t db_write_ddl_op_for_constraints(knl_session_t* session, uint32 uid, uint32 id, galist_t* constraints);
status_t db_write_ddl_op_for_parents(knl_session_t* session, table_t* table);
status_t db_clean_ddl_op(knl_session_t *session, clean_ddl_op_t clean_op);
void db_clean_ddl_op_garbage(knl_session_t *session);

status_t dtc_modify_drop_uid(knl_session_t *knl_session, uint32 uid);
status_t dtc_try_clean_user_lock(knl_session_t *knl_session, dc_user_t *dc_user);
EXTER_ATTACK void dtc_process_get_user_lock_status(knl_session_t *session, mes_message_t *req_msg, char *data);
status_t dtc_process_btree_splitting(knl_session_t *session, char *data, uint8 src_inst);
void dtc_process_btree_split_status(knl_session_t *session, mes_message_t *req_msg, char *data);
status_t dtc_process_heap_extend(knl_session_t *session, char *data, uint8 src_inst);
void dtc_process_heap_extend_status(knl_session_t *session, mes_message_t *req_msg, char *data);
void dtc_process_user_status(knl_session_t *session, char *data);
EXTER_ATTACK void dtc_process_invalidate_dc(knl_session_t *session, char *data);
void dtc_broadcast_data_send_ack(knl_session_t *session, mes_message_t *msg, status_t process_ret);
status_t dtc_sync_ddl_internal(knl_handle_t knl_session, char *logic_log_buf, uint32 logic_log_size);
status_t dtc_sync_upgrade_ctrl_version(knl_handle_t knl_session);
void dtc_process_upgrade_ctrl_version(void *sess, mes_message_t *msg);
status_t dtc_remove_df_watch(knl_session_t *session, uint32 df_id);
status_t dtc_process_remove_df_watch(knl_session_t* session, char* data);
#ifdef __cplusplus
}
#endif

#endif
