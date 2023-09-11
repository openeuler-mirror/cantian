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
 * knl_ctrl_restore.h
 *
 *
 * IDENTIFICATION
 * src/kernel/common/knl_ctrl_restore.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef KNL_CTRL_RESTORE_H
#define KNL_CTRL_RESTORE_H

#include "knl_database.h"
#define CTRL_BACKUP_VERSION_DEFAULT         0
#define CTRL_BACKUP_VERSION_REBUILD_CTRL    DATAFILE_STRUCTURE_VERSION
#define CTRL_LOG_BACKUP_LEVEL(session)    ((session)->kernel->attr.ctrllog_backup_level)

typedef struct st_ctrl_file_items {
    char name[GS_DB_NAME_LEN];
    bool32 is_archive_on;
    galist_t *logfile_list;
    galist_t *datafile_list;
    charset_type_t charset;
}ctrl_file_items_def_t;

typedef struct st_static_core_ctrl_items {
    char name[GS_DB_NAME_LEN];
    time_t init_time;
}static_core_ctrl_items_t;

typedef struct st_sys_table_entries {
    page_id_t sys_table_entry;
    page_id_t ix_sys_table1_entry;
    page_id_t ix_sys_table2_entry;
    page_id_t sys_column_entry;
    page_id_t ix_sys_column_entry;
    page_id_t sys_index_entry;
    page_id_t ix_sys_index1_entry;
    page_id_t ix_sys_index2_entry;
    page_id_t ix_sys_user1_entry;
    page_id_t ix_sys_user2_entry;
    page_id_t sys_user_entry;
}sys_table_entries_t;

typedef struct st_core_ctrl_log_info {
    uint64 lsn;
    uint64 lfn;
    log_point_t rcy_point;
    log_point_t lrp_point;
    knl_scn_t scn;
} core_ctrl_log_info_t;

typedef struct st_log_file_ctrl_bk {
    uint32 version;
    char name[GS_FILE_NAME_BUFFER_SIZE];
    int64 size;
    int64 hwm;
    int32 file_id;
    uint32 seq;
    uint16 block_size;
    uint16 flg;
    device_type_t type;
    logfile_status_t status;
    uint16 forward;
    uint16 backward;
    uint8 unused[GS_RESERVED_BYTES_32];
} log_file_ctrl_bk_t;

typedef struct st_datafile_ctrl_bk {
    uint32 version;
    uint32 id;
    bool32 used;
    char name[GS_FILE_NAME_BUFFER_SIZE];
    int64 size;
    uint16 block_size;
    uint16 flg;
    device_type_t type;
    int64 auto_extend_size;
    int64 auto_extend_maxsize;
    uint8 unused[GS_RESERVED_BYTES_32];
    uint32 file_no;
    uint32 space_id;
} datafile_ctrl_bk_t;

typedef struct st_space_ctrl_bk {
    uint32 id;
    bool32 used;
    char name[GS_NAME_BUFFER_SIZE];
    uint16 flg;
    uint16 block_size;
    uint32 extent_size;  // extent pages count
    uint32 file_hwm;     // max allocated datafile count
    uint32 type;
    knl_scn_t org_scn;
    uint8 encrypt_version;
    uint8 cipher_reserve_size;
    uint8 unused[GS_RESERVED_BYTES_14];
} space_ctrl_bk_t;

status_t ctrl_backup_static_core_items(knl_session_t *session, static_core_ctrl_items_t *items);
status_t ctrl_backup_sys_entries(knl_session_t *session, sys_table_entries_t *entries);
status_t ctrl_backup_log_ctrl(knl_session_t *session, uint32 id);
status_t ctrl_backup_space_ctrl(knl_session_t *session, uint32 space_id);
status_t ctrl_backup_datafile_ctrl(knl_session_t *session, uint32 file_id);
status_t ctrl_rebuild_ctrl_files(knl_session_t *session, knl_rebuild_ctrlfile_def_t *def);
status_t ctrl_backup_core_log_info(knl_session_t *session);
status_t ctrl_backup_ctrl_info(knl_session_t *session);
status_t ctrl_backup_reset_logs(knl_session_t *session);
status_t ctrl_init_logfile_ctrl(knl_session_t *session, log_file_t *logfile);
#endif