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
 * repl_defs.h
 *
 *
 * IDENTIFICATION
 * src/kernel/include/repl_defs.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_REPL_DEFS_H__
#define __KNL_REPL_DEFS_H__

#include "knl_defs.h"

#ifdef __cplusplus
extern "C" {
#endif
   
typedef struct st_file_name_convert {
    char primry_path[CT_FILE_NAME_BUFFER_SIZE];
    char standby_path[CT_FILE_NAME_BUFFER_SIZE];
} file_name_convert_t;

typedef struct st_file_convert {
    bool32 is_convert;
    uint32 count;
    file_name_convert_t convert_list[CT_MAX_FILE_CONVERT_NUM];
} file_convert_t;

typedef enum e_repl_mode {
    MAXIMUM_PERFORMANCE = 0,
    MAXIMUM_AVAILABILITY = 1,
    MAXIMUM_PROTECTION = 2,
} repl_mode_t;

typedef enum e_repl_role {
    REPL_ROLE_PRIMARY = 0,
    REPL_ROLE_PHYSICAL_STANDBY = 1,
    REPL_ROLE_CASCADED_PHYSICAL_STANDBY = 2,
} repl_role_t;

// Database kernel switch control
typedef enum en_switch_state {
    SWITCH_IDLE = 0,
    SWITCH_KILL_SESSIONS,
    SWITCH_WAIT_SESSIONS,
    SWITCH_WAIT_LOG_SYNC,
    SWITCH_WAIT_LOG_ANALYSIS,
    SWITCH_WAIT_RECOVERY,
    SWITCH_WAIT_CKPT,
} switch_state_t;

typedef enum en_switch_req {
    SWITCH_REQ_NONE = 0,
    SWITCH_REQ_DEMOTE,
    SWITCH_REQ_PROMOTE,
    SWITCH_REQ_FAILOVER_PROMOTE,
    SWITCH_REQ_RAFT_PROMOTE_PENDING,
    SWITCH_REQ_RAFT_PROMOTE,
    SWITCH_REQ_READONLY,
    SWITCH_REQ_CANCEL_UPGRADE,
    SWITCH_REQ_FORCE_FAILOVER_PROMOTE,
} switch_req_t;

typedef enum en_build_type {
    BUILD_AUTO = 0,
    BUILD_STANDBY = 1,
    BUILD_CASCADED_STANDBY = 2
} build_type_t;

typedef struct st_build_param_ctrl {
    compress_algo_e compress;
    uint32 compress_level;
    uint32 parallelism;
    bool32 is_increment;
    bool32 is_repair;
    uint64 base_lsn;
    uint32 buffer_size;
} build_param_ctrl_t;

typedef struct st_knl_build_def {
    build_type_t build_type;
    build_param_ctrl_t param_ctrl;
} knl_build_def_t;

typedef enum en_encrypt_algorithm {
    ENCRYPT_NONE = 0,
    AES_256_GCM = 1,
} encrypt_algorithm_t;

typedef struct st_knl_backup_cryptinfo {
    SENSI_INFO char password[CT_PASSWORD_BUFFER_SIZE];
    encrypt_algorithm_t encrypt_alg;
} knl_backup_cryptinfo_t;

typedef enum en_backup_device {
    DEVICE_DISK = 0,
    DEVICE_UDS = 1,
} backup_device_t;

typedef enum en_backup_data_type {
    DATA_TYPE_FILE,
    DATA_TYPE_DBSTOR,
} backup_data_type_t;

typedef enum en_backup_type {
    BACKUP_MODE_INVALID = -1,
    BACKUP_MODE_FULL = 1,
    BACKUP_MODE_INCREMENTAL = 2,
    BACKUP_MODE_FINISH_LOG = 3,
    BACKUP_MODE_ARCHIVELOG = 4,
    BACKUP_MODE_TABLESPACE = 5,
    BACKUP_MODE_INCREMENTAL_CUMULATIVE = 6,
} backup_type_t;

typedef enum en_restore_type {
    RESTORE_MODE_NULL = 0,
    RESTORE_UNITIL_SCN,
    RESTORE_UNITIL_TIME,
    RESTORE_FROM_PATH,  // specified backup set to restore
    RESTORE_BLOCK_RECOVER,  // repair page using backup
    RESTORE_DATAFILE_RECOVER,
} restore_type_t;

typedef enum en_restore_repair_type {
    RESTORE_REPAIR_TYPE_NULL = 0,
    RESTORE_REPAIR_REPLACE_CHECKSUN,
    RESTORE_REPAIR_DISCARD_BADBLOCK,
} restore_repair_type_t;

typedef enum st_knl_backup_target {
    TARGET_ALL = 0,
    TARGET_ARCHIVE = 1,
    TARGET_TABLESPACE = 2,
} knl_backup_target_t;

typedef enum st_knl_backup_arch_mode {
    ARCHIVELOG_ALL = 0,
    ARCHIVELOG_FROM = 1,
} knl_backup_arch_mode_t;

typedef struct st_knl_backup_target_info {
    knl_backup_target_t target;
    knl_backup_arch_mode_t backup_arch_mode;
    galist_t *target_list;
    uint32 backup_begin_asn;
} knl_backup_targetinfo_t;

typedef struct st_knl_backup {
    backup_type_t type;
    backup_device_t device;
    text_t format;
    text_t policy;
    uint32 level;
    bool32 cumulative;
    char tag[CT_NAME_BUFFER_SIZE];
    uint64 finish_scn;
    bool32 prepare;
    uint32 compress_algo;
    uint32 compress_level;
    uint32 parallelism;
    uint64 section_threshold;
    galist_t *exclude_spcs;
    knl_backup_targetinfo_t target_info;
    galist_t *target_list;
    knl_backup_cryptinfo_t crypt_info;
    bool32 force_cancel;
    uint32 buffer_size;
    bool32 log_serial;
    bool32 skip_badblock; // only for datafile
} knl_backup_t;

typedef enum en_rst_file_type {
    RESTORE_ALL = 0,  // restore all database
    RESTORE_CTRL = 1,
    RESTORE_DATAFILE = 2, // restore the specifical datafile and recover
    RESTORE_ARCHFILE = 3,
} rst_file_type_t;

typedef struct st_knl_restore {
    restore_type_t type;
    date_t date;
    uint64 lfn;
    text_t path;
    text_t policy;
    backup_device_t device;
    bool32 disconnect;
    uint32 parallelism;
    page_id_t page_need_repair;
    uint16 file_repair;
    text_t file_repair_name;
    text_t spc_name;
    rst_file_type_t file_type;
    knl_backup_cryptinfo_t crypt_info;
    uint32 buffer_size;
    restore_repair_type_t repair_type;
} knl_restore_t;

typedef enum en_recover_action {
    RECOVER_NORMAL = 1,
    RECOVER_UNTIL_TIME = 2,
    RECOVER_UNTIL_CANCEL = 3,
    RECOVER_UNTIL_SCN = 4,
} recover_action_t;

typedef struct st_knl_recover {
    recover_action_t action;
    struct timeval time;
    knl_scn_t scn;
} knl_recover_t;

typedef struct st_knl_daac_recover {
    uint32 start;
    uint32 count;
    uint32 full;
} knl_daac_recover_t;

typedef enum en_validate_type {
    VALIDATE_BACKUPSET = 0,
    VALIDATE_DATAFILE_PAGE = 1,
} validate_type_t;

typedef struct st_knl_validate {
    text_t path;
    page_id_t page_id;
    validate_type_t validate_type;
} knl_validate_t;

typedef struct st_sync_info {
    char status[CT_DYNVIEW_NORMAL_LEN];
    char local_host[CT_HOST_NAME_BUFFER_SIZE];
    char role_valid[CT_MAX_ROLE_VALID_LEN];
    char net_mode[CT_MAX_NET_MODE_LEN];
    char peer_host[CT_HOST_NAME_BUFFER_SIZE];
    uint32 peer_port;
    char local_point[CT_MAX_NUMBER_LEN];
    char peer_point[CT_MAX_NUMBER_LEN];
    char peer_cont_point[CT_MAX_NUMBER_LEN];
    char peer_building[CT_MAX_PEER_BUILDING_LEN];
    uint64 local_lfn;
    uint64 local_lsn;
    uint64 peer_lfn;
    uint64 peer_lsn;
    int64 flush_lag;
    uint64 replay_lag;
    char build_type[CT_DYNVIEW_NORMAL_LEN];
    uint32 build_progress;
    char build_stage[CT_DYNVIEW_NORMAL_LEN];
    uint64 build_synced_stage_size;
    uint64 build_total_stage_size;
    uint64 build_time;
} sync_info_t;

typedef struct st_ha_sync_info {
    uint32 count;
    sync_info_t sync_info[CT_MAX_PHYSICAL_STANDBY];
} ha_sync_info_t;

status_t knl_build(knl_handle_t session, knl_build_def_t *param);
status_t knl_stop_build(knl_handle_t session);
status_t knl_backup(knl_handle_t session, knl_backup_t *param);
status_t knl_restore(knl_handle_t session, knl_restore_t *param);
status_t knl_recover(knl_handle_t session, knl_recover_t *param);
status_t knl_validate(knl_handle_t session, knl_validate_t *param);
status_t knl_daac_recover(knl_handle_t session, knl_daac_recover_t *param);

void knl_set_repl_timeout(knl_handle_t handle, uint32 val);
bool32 knl_db_is_primary(knl_handle_t session);
bool32 knl_db_is_cascaded_standby(knl_handle_t session);
bool32 knl_db_is_physical_standby(knl_handle_t session);
bool32 knl_failover_triggered(knl_handle_t knl_handle);
bool32 knl_failover_triggered_pending(knl_handle_t knl_handle);
bool32 knl_switchover_triggered(knl_handle_t knl_handle);
bool32 knl_open_mode_triggered(knl_handle_t knl_handle);

status_t knl_raft_add_member(knl_handle_t session, uint64 node_id, char *addr, uint64 timeout, uint64 role);
status_t knl_raft_del_member(knl_handle_t session, uint64 node_id, uint64 timeout);
status_t knl_raft_monitor_info(knl_handle_t session, char **monitor_info);
status_t knl_raft_version(knl_handle_t session, char **version);
status_t knl_raft_set_param(knl_handle_t session, char *param_name, void *value);
status_t knl_raft_query_info(knl_handle_t session, char *type, char **query_info);

void knl_get_sync_info(knl_handle_t session, knl_handle_t sync_info);
void knl_set_replica(knl_handle_t session, uint16 replica_port, bool32 is_start);

status_t knl_get_convert_params(const char *item_name, char *value, file_convert_t *file_convert, const char *home);
#ifdef __cplusplus
}
#endif

#endif
