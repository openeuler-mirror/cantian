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
 * knl_log_persistent.h
 *
 *
 * IDENTIFICATION
 * src/upgrade_check/knl_log_persistent.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_LOG_PERSISTENT_H__
#define __KNL_LOG_PERSISTENT_H__
 
#ifdef __cplusplus
extern "C" {
#endif
 

typedef enum en_logfile_status {
    LOG_FILE_INACTIVE = 1,
    LOG_FILE_ACTIVE = 2,
    LOG_FILE_CURRENT = 3,
    LOG_FILE_UNUSED = 4,
} logfile_status_t;

typedef struct st_log_file_ctrl {
    char name[CT_FILE_NAME_BUFFER_SIZE];
    int64 size;
    int64 hwm;
    int32 file_id;
    uint32 seq;  // The header write sequence number
    uint16 block_size;
    uint16 flg;
    device_type_t type;
    logfile_status_t status;
    uint16 forward;
    uint16 backward;
    bool8 archived;
    uint8 node_id;   //for clustered database
    uint8 reserved[30];
} log_file_ctrl_t;

typedef struct st_reset_log {
    uint32 rst_id;
    uint32 last_asn;
    uint64 last_lfn;
    uint64 last_lsn;
} reset_log_t;
 
typedef struct st_log_point {
    uint32 asn;  // log file id
    uint32 block_id;
    uint64 rst_id : 18;
    uint64 lfn : 46;
    uint64 lsn;
} log_point_t;
 
typedef struct st_log_batch_id {
    uint64 magic_num;   // for checking batch is completed or not
    log_point_t point;  // log address for batch
} log_batch_id_t;

typedef struct st_log_batch {
    log_batch_id_t head;
    knl_scn_t scn;
    uint32 padding;
    uint32 size;  // batch length, include log_batch_t head size

    uint32 space_size;  // The actual space occupied by the batch
    uint8 part_count;   // a batch contains multiple buffers,less or queue to buffer count
    uint8 version;
    uint16 batch_session_cnt;

    union {
        uint64 raft_index;
        uint64 lsn; // max lsn of log groups inside this batch, clustered database not support PAXOS/RAFT
    };

    uint16 checksum;
    bool8 encrypted : 1;
    uint8 reserve : 7;
    uint8 unused[5];
} log_batch_t;

typedef struct st_logic_op_rep_ddl_head {
    uint16 op_class;
    uint16 op_type;
    uint32 table_oid;
} logic_rep_ddl_head_t;

#ifdef __cplusplus
}
#endif

#endif