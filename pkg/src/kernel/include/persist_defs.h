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
 * persist_defs.h
 *
 *
 * IDENTIFICATION
 * src/kernel/include/persist_defs.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_PERSIST_DEFS_H__
#define __KNL_PERSIST_DEFS_H__

#include "knl_defs.h"

#ifdef __cplusplus
extern "C" {
#endif
  
typedef enum en_alter_datafile_mode {
    ALTER_DF_CREATE = 0x00000001,
    ALTER_DF_RENAME = 0x00000002,
    ALTER_DF_ONLINE = 0x00000004,
    ALTER_DF_OFFLINE = 0x00000008,
    ALTER_DF_RESIZE = 0x00000010,
    ALTER_DF_AUTOEXTEND_OFF = 0x00000020,
    ALTER_DF_AUTOEXTEND_ON = 0x00000040,
    ALTER_DF_END = 0x00000080,
    ALTER_DF_DROP = 0x00000100,
} alter_datafile_mode_t;

typedef enum en_altspace_action {
    ALTSPACE_ADD_DATAFILE = 0,
    ALTSPACE_DROP_DATAFILE = 1,
    ALTSPACE_RENAME_DATAFILE = 2,
    ALTSPACE_RENAME_SPACE = 3,
    ALTSPACE_SET_AUTOEXTEND = 4,
    ALTSPACE_SET_AUTOPURGE = 5,
    ALTSPACE_SET_RETENTION = 6,
    ALTSPACE_OFFLINE_DATAFILE = 7,
    ALTSPACE_SHRINK_SPACE = 8,
    ALTSPACE_SET_AUTOOFFLINE = 9,
    ALTSPACE_PUNCH = 10
} altspace_action_t;

/*
 * Kernel support two different types of tablespace management
 */
typedef enum st_space_manage_type {
    SPACE_NORMAL = 0,
    SPACE_BITMAP = 1,
} space_manage_type_t;

typedef struct st_knl_shrink_def {
    int64 keep_size;
    text_t file_name;
} knl_shrink_def_t;

typedef struct st_knl_autoextend_def {
    bool32 enabled; /* is auto extending or not */
    int64 nextsize; /* auto extending size (the value is 16MB by default) */
    int64 maxsize;  /* auto extend max size.
                     * when "enabled" set to true, the 0 value of "maxsize" means
                     * the max possible size of a datafile:
                     *   - the datafile of undo tablespace: max possible size is 64GB
                     *   - the datafile of other tablespace: max possible size is 8TB
                     */
} knl_autoextend_def_t;

typedef struct st_knl_altspace_def {
    altspace_action_t action;
    text_t name;
    bool32 auto_purge;
    bool32 auto_offline;
    bool32 in_shard;
    knl_shrink_def_t shrink;
    knl_autoextend_def_t autoextend;
    galist_t datafiles;
    galist_t rename_datafiles;
    text_t rename_space;
    uint16 undo_segments;
    int64 punch_size;
} knl_altspace_def_t;

// TableSpace contains name [including contents [and/keep datafiles] [cascade constraints]]
typedef enum en_knl_drop_tablespace_dfs_option {
    TABALESPACE_DFS_AND = 0x00000001,
    TABALESPACE_CASCADE = 0x00000002,
    TABALESPACE_INCLUDE = 0x00000004,
} knl_drop_tablespace_dfs_option_t;

// Abstract device type
typedef struct st_knl_device_def {
    text_t name;  // name of the device
    int64 size;   // device size
    int32 block_size;
    knl_autoextend_def_t autoextend;  // the data of the autoextend property of the device
    uint32 node_id;                   // instance id in cluster
    bool32 compress;
} knl_device_def_t;

#define SPC_DROP_CONTENTS(options) ((options) & TABALESPACE_INCLUDE)
#define SPC_DROP_DATAFILE(options) ((options) & TABALESPACE_DFS_AND)
#define SPC_DROP_CASCADE(options)  ((options) & TABALESPACE_CASCADE)

typedef struct st_knl_drop_space_def {
    text_t obj_name;
    uint32 options;
    bool32 in_shard;
    uint8 is_for_create_db;
} knl_drop_space_def_t;


#define SPACE_TYPE_UNDEFINED    0
#define SPACE_TYPE_SYSTEM       0x00000001
#define SPACE_TYPE_SYSAUX       0x00000002
#define SPACE_TYPE_TEMP         0x00000004
#define SPACE_TYPE_UNDO         0x00000008
#define SPACE_TYPE_DEFAULT      0x00000010  // default tablespace, defined by database creating
#define SPACE_TYPE_USERS        0x00000020  // default users tablespace or user defined tablespace
#define SPACE_TYPE_SWAP         0x00000040  // temporary tablespace for VM

// table space definition
typedef struct st_knl_space_def {
    text_t name;          // name of the space
    uint32 type;    // type of the space
    bool32 in_memory;     // if a in-memory space
    bool32 in_shard;      // if data in shard mode
    bool32 autooffline;   // if a auto offline space
    bool32 autoallocate;  // if manage extent size automaticly
    bool32 bitmapmanaged; // if manage extent by bitmap
    uint32 extent_size;   // extent is a sub level of a space
    bool32 encrypt;       // if a encrypt space
    galist_t datafiles;   // datafile list of a space
    uint16 flags;
    uint8 is_for_create_db;
} knl_space_def_t;

typedef struct st_knl_alterdb_logfile {
    galist_t logfiles;          // logfile list
    galist_t changed_logfiles;  // rename logfiles list
} knl_alterdb_logfile_t;

typedef struct st_knl_alterdb_rebuildspc {
    text_t space_name;
} knl_alterdb_rebuildspc_t;

status_t knl_create_space(knl_handle_t session, knl_handle_t stmt, knl_space_def_t *def);
status_t knl_drop_space(knl_handle_t session, knl_handle_t stmt, knl_drop_space_def_t *def);
status_t knl_alter_space(knl_handle_t session, knl_handle_t stmt, knl_altspace_def_t *def);
status_t knl_alter_switch_undo_space(knl_handle_t se, text_t *spc_name);

status_t knl_get_space_size(knl_handle_t se, uint32 space_id, int32 *page_size, knl_handle_t info);
status_t knl_get_space_name(knl_handle_t session, uint32 space_id, text_t *space_name);
uint32 knl_get_dbwrite_file_id(knl_handle_t session);
uint32 knl_get_dbwrite_end(knl_handle_t session);

void knl_get_low_arch(knl_handle_t session, uint32 *rst_id, uint32 *asn);
void knl_get_high_arch(knl_handle_t session, uint32 *rst_id, uint32 *asn);
char *knl_get_arch_dest_type(knl_handle_t session, uint32 id, knl_handle_t attr, bool32 *is_primary);
void knl_get_arch_dest_path(knl_handle_t session, uint32 id, knl_handle_t attr, char *path, uint32 path_size);
char *knl_get_arch_sync_status(knl_handle_t session, uint32 id, knl_handle_t attr, knl_handle_t dest_sync);
char *knl_get_arch_sync(knl_handle_t dest_sync);

typedef enum en_ckpt_type {
    CKPT_TYPE_LOCAL,
    CKPT_TYPE_GLOBAL,
} ckpt_type_t;

typedef enum en_dc_dump_type {
    DC_DUMP_TABLE,
    DC_DUMP_USER,
    DC_DUMP_CONTEXT,
} dc_dump_type_t;

typedef struct st_dc_dump_info {
    dc_dump_type_t dump_type;
    text_t user_name;
    text_t table_name;
    text_t dump_file;
}dc_dump_info_t;

// alter system action type enumeration
typedef enum en_alsys_action {
    ALSYS_SWITCHLOG = 0,
    ALSYS_SET_PARAM,
    ALSYS_LOAD_DC,
    ALSYS_INIT_ENTRY,
    ALSYS_DUMP_PAGE,
    ALSYS_FLUSH_BUFFER,
    ALSYS_FLUSH_SQLPOOL,
    ALSYS_KILL_SESSION,
    ALSYS_RESET_STATISTIC,
    ALSYS_CHECKPOINT,
    ALSYS_RELOAD_HBA,
    ALSYS_REFRESH_SYSDBA,
    ALSYS_ADD_LSNR_ADDR,
    ALSYS_DELETE_LSNR_ADDR,
    ALSYS_ADD_HBA_ENTRY,
    ALSYS_DEL_HBA_ENTRY,
    ALSYS_DUMP_CTRLPAGE,
    ALSYS_DEBUG_MODE,
    ALSYS_MODIFY_REPLICA,
    ALSYS_STOP_REPLICA,
    ALSYS_STOP_BUILD,
    ALSYS_RELOAD_PBL,
    ALSYS_DUMP_DC,
    ALSYS_RECYCLE_SHAREDPOOL,
    ALSYS_REPAIR_CATALOG
} alsys_action_e;

// ctrl log backup level
typedef enum en_ctrllog_backup_level {
    CTRLLOG_BACKUP_LEVEL_NONE = 0,
    CTRLLOG_BACKUP_LEVEL_TYPICAL,
    CTRLLOG_BACKUP_LEVEL_FULL,
} ctrllog_backup_level_t;
    
typedef struct st_knl_alter_sys_def {  // alter table
    alsys_action_e action;
    union {
        // alter system set param = <value> scope=<spfile|memory>
        struct {
            bool32 scope;
            bool32 in_shard;
            bool32 is_coord_conn;
            uint32 param_id;
            char param[GS_NAME_BUFFER_SIZE];
            char value[GS_PARAM_BUFFER_SIZE];
        };

        // alter system kill session
        struct {
            uint32 session_id;
            uint32 serial_id;
            uint32 node_id;
        };

        // alter system insert/del hba entry
        struct {
            char hba_node[HBA_MAX_LINE_SIZE];  // save config node
        };

        // dump datafile page or ctrlfile page
        struct {
            page_id_t page_id;
            text_t out_file;
        };

        // dump dictionary cache for tables
        dc_dump_info_t dump_info;

        ckpt_type_t ckpt_type;
        bool32 force_recycle;  // force recycle shared_pool
    };
} knl_alter_sys_def_t;

status_t knl_checkpoint(knl_handle_t handle, ckpt_type_t type);
status_t knl_switch_log(knl_handle_t session);
status_t knl_flush_buffer(knl_handle_t session, knl_alter_sys_def_t *def);
status_t knl_load_sys_dc(knl_handle_t session, knl_alter_sys_def_t *def);
status_t knl_init_entry(knl_handle_t session, knl_alter_sys_def_t *def);
status_t knl_dump_page(knl_handle_t handle, knl_alter_sys_def_t *def);
status_t knl_dump_ctrl_page(knl_handle_t handle, knl_alter_sys_def_t *def);
status_t knl_dump_dc(knl_handle_t handle, knl_alter_sys_def_t *def);

#ifdef __cplusplus
}
#endif

#endif