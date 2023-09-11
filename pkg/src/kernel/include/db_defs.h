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
 * db_defs.h
 *
 *
 * IDENTIFICATION
 * src/kernel/include/db_defs.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_DB_DEFS_H__
#define __KNL_DB_DEFS_H__

#include "knl_defs.h"
#include "persist_defs.h"

#ifdef __cplusplus
extern "C" {
#endif
  
// Database kernel status enum
typedef enum en_db_status {
    DB_STATUS_CLOSED = 0,
    DB_STATUS_NOMOUNT = 1,
    DB_STATUS_CREATING = 2,
    DB_STATUS_MOUNT = 3,
    DB_STATUS_REDO_ANALYSIS = 4,
    DB_STATUS_RECOVERY = 5,
    DB_STATUS_INIT_PHASE2 = 6, /* from this, db can accept write and generate redo log */
    DB_STATUS_WAIT_CLEAN = 7,  /* from this, tx_rollback and garbage_clean begin to work */
    DB_STATUS_OPEN = 8,        /* open for world */
} db_status_t;

typedef enum en_db_startup_phase {
    STARTUP_NOMOUNT = 1,
    STARTUP_MOUNT = 2,
    STARTUP_OPEN = 3,
} db_startup_phase_t;

typedef enum en_database_action {
    STARTUP_DATABASE_NOMOUNT = 1,
    STARTUP_DATABASE_MOUNT,
    STARTUP_DATABASE_OPEN,
    CREATE_DATAFILE,
    ALTER_DATAFILE,
    ALTER_TEMPFILE,
    MOVE_DATAFILE,
    ACTIVATE_STANDBY_DB,
    MAXIMIZE_STANDBY_DB,
    ALTER_DB_TIMEZONE,
    REGISTER_LOGFILE,
    SWITCHOVER_STANDBY,
    SWITCHOVER_STANDBY_FORCE,
    FAILOVER_STANDBY,
    FAILOVER_STANDBY_FORCE,
    PREPARE_COMMIT_SWITCHOVER,
    START_STANDBY,
    STOP_STANDBY,
    ABORT_STANDBY,
    CONVERT_TO_STANDBY,
    CONVERT_TO_READ_ONLY,
    CONVERT_TO_READ_WRITE,
    DATABASE_ARCHIVELOG,
    DATABASE_NOARCHIVELOG,
    ADD_LOGFILE,
    DROP_LOGFILE,
    ARCHIVE_LOGFILE,
    DELETE_ARCHIVELOG,
    DELETE_BACKUPSET,
    ENABLE_LOGIC_REPLICATION,
    DISABLE_LOGIC_REPLICATION,
    DATABASE_CLEAR_LOGFILE,
    ALTER_CHARSET,
    REBUILD_TABLESPACE,
    UPDATE_MASTER_SERVER_KEY,
    CANCEL_UPGRADE,
    UPDATE_MASTER_KERNEL_KEY,
    UPDATE_MASTER_ALL_KEY,
    UPGRADE_PROCEDURE,
} database_action_t;


typedef enum en_alter_recovery_mode {
    GENERAL_RECOVERY_FULL = 0,
    GENERAL_RECOVERY_PARTIAL = 1,
    GENERAL_RECOVERY_LOGFILE = 2,
    GENERAL_RECOVERY_CONTINUE = 3,
    GENERAL_RECOVERY_CANCEL = 4,
    STANDBY_RECOVERY_LOGFILE = 5,
    STANDBY_RECOVERY_DISCONNECT = 6,
    STANDBY_RECOVERY_NODELAY = 7,
    STANDBY_RECOVERY_UNTIL_CHANGE = 8,
    STANDBY_RECOVERY_UNTIL_CONSISTENT = 9,
    STANDBY_RECOVERY_FINISH = 10,
    STANDBY_RECOVERY_CANCEL = 11,
    LOGICAL_STANDBY_RECOVERY = 12,
} alter_recovery_mode_t;

typedef struct st_knl_alterdb_recovery {
    galist_t datafiles;                         // datafile list
    alter_recovery_mode_t alter_recovery_mode;  // alter database recovery mode
} knl_alterdb_recovery_t;

typedef struct st_knl_alterdb_archivelog {
    bool32 all_delete;
    bool32 force_delete;
    date_t until_time;
} knl_alterdb_archivelog_t;

typedef struct st_knl_alterdb_backupset {
    char tag[GS_NAME_BUFFER_SIZE];
    bool32 force_delete;
} knl_alterdb_backupset_t;

typedef struct st_knl_alterdb_datafile {
    galist_t datafiles; // datafile list (element type: pointer to text_t which stores datafile name)
    galist_t changed_datafiles;                 // rename datafiles list
    alter_datafile_mode_t alter_datafile_mode;  // alter datafile mode
    uint64 size;                                // size in alter datafile
    bool32 is_tempfile;                         // datafile or tempfile
    bool32 is_for_drop;                         // for drop or not in offline
    knl_autoextend_def_t autoextend;            // auto-extend properties of ALTER DATABASE DATAFILE......
} knl_alterdb_datafile_t;

typedef enum en_db_open_status {
    DB_OPEN_STATUS_NORMAL = 0,
    DB_OPEN_STATUS_RESTRICT = 1,
    DB_OPEN_STATUS_UPGRADE = 2,
    DB_OPEN_STATUS_UPGRADE_PHASE_2 = 3,
} db_open_status_t;

typedef enum en_db_readonly_reason {
    PRIMARY_SET = 0,
    PHYSICAL_STANDBY_SET = 1,
    MANUALLY_SET = 2,
    RMON_SET = 3,
    OTHER_SET = 4,
} db_readonly_reason;

typedef enum en_alter_standby_mode {
    ALTER_ACTIVATE_PHYSICAL = 0,
    ALTER_ACTIVATE_LOGICAL = 1,
    ALTER_SET_PROTECTION = 2,
    ALTER_SET_AVAILABILITY = 3,
    ALTER_SET_PERFORMANCE = 4,
    ALTER_REGISTER_PHYSICAL = 5,
    ALTER_REGISTER_LOGICAL = 6,
    ALTER_SWITCHOVER_VERIFY = 7,
    ALTER_SWITCHOVER_FORCE = 8,
    ALTER_SWITCHOVER_PHYSICAL_STANDBY = 9,
    ALTER_SWITCHOVER_PRIMARY = 10,
    ALTER_FAILOVER = 11,
    ALTER_PREPARE_COMMIT = 12,
    ALTER_COMMIT = 13,
    ALTER_START_STANDBY = 14,
    ALTER_STOP_STANDBY = 15,
    ALTER_ABORT_STANDBY = 16,
    ALTER_CONVERT_PHYSICAL = 17,
    ALTER_CONVERT_SNAPSHOT = 18,
} alter_standby_mode_t;

typedef struct st_knl_alterdb_standby {
    galist_t datafiles;                       // datafile list
    alter_standby_mode_t alter_standby_mode;  // alter standby mode
    text_t target_db_name;                    // for switchover / failover
} knl_alterdb_standby_t;

typedef struct st_db_open_opt {
    bool32 is_creating;
    bool32 readonly;
    bool32 resetlogs;
    bool32 ignore_logs;
    bool32 ignore_systime;
    db_open_status_t open_status;
    uint64 lfn;
} db_open_opt_t;

typedef struct st_knl_alterdb_def {
    db_startup_phase_t phase;
    database_action_t action;  // SET, MOUNT, OPEN, ARCHIVELOG, NOARCHIVELOG, DELETE_ARCHIVELOG...
    db_open_opt_t open_options;
    bool32 is_cascaded;  // if true, convert to cascaded physical standby
    bool32 is_named;     // name exists in input
    bool32 is_mount;     // if true, convert db_role only, do not open database
    text_t name;         // name of database
    bool32 force_failover;
    uint32 switchover_timeout; // default 0
    union {
        knl_alterdb_recovery_t recovery;
        knl_alterdb_datafile_t datafile;
        knl_alterdb_logfile_t logfile;
        knl_alterdb_standby_t standby;
        knl_alterdb_archivelog_t dele_arch;
        knl_alterdb_backupset_t dele_bakset;
        knl_alterdb_rebuildspc_t rebuild_spc;
        text_t timezone_offset_name;  // db time zone
        uint32 charset_id; // charset id
        uint32 clear_logfile_id;
    };
} knl_alterdb_def_t;

// database
status_t knl_startup(knl_handle_t kernel);

/*
 * Version       : v 1.0
 * Created       : 2016-10-27 11:31:53
 * Last Modified :
 * Description   :
 */
void knl_construct_oltpdatabase(void);

/*
 * Storage Engine API
 * Created 2016-10-27 11:31:53
 */
void knl_shutdown(knl_handle_t sess, knl_handle_t kernel, bool32 need_ckpt);

status_t knl_alter_database(knl_handle_t session, knl_alterdb_def_t *def);
char *knl_get_db_name(knl_handle_t session);
db_status_t knl_get_db_status(knl_handle_t session);
db_open_status_t knl_get_db_open_status(knl_handle_t session);
status_t knl_get_page_size(knl_handle_t session, uint32 *page_size);
void knl_init_attr(knl_handle_t kernel);
void knl_qos_begin(knl_handle_t session);
void knl_qos_end(knl_handle_t session);

// DBLINK
typedef struct st_knl_database_link_def {
    uint32 owner_id;
    uint32 id;
    uint32 node_id;
    sql_text_t name;
    text_t user;
    text_t url;
    char password[GS_PASSWORD_BUFFER_SIZE];
} knl_dblink_def_t;

typedef struct st_knl_dblink_desc {
    uint32 owner_id;                        /* user id that create the dblink */
    uint32 id;                              /* dblink id */
    uint32 node_id;                         /* datanode id */
    char name[GS_NAME_BUFFER_SIZE];         /* dblink name */
    char user[GS_NAME_BUFFER_SIZE];         /* dblink user */
} knl_dblink_desc_t;

void knl_get_link_name(knl_dictionary_t *dc, text_t *user, text_t *objname);

// Archive mode
typedef enum en_archive_mode {
    ARCHIVE_LOG_OFF = 0,  // archive log off
    ARCHIVE_LOG_ON = 1,   // archive log on
} archive_mode_t;

/*
 * definition of a database kernel, can define more than
 * one database in a single instance.
 */
typedef struct st_knl_database_def {
    text_t name;                                 // name of database
    char sys_password[GS_PASSWORD_BUFFER_SIZE];  // sys pwd of database
    text_t charset;                              // charset of database
    knl_space_def_t system_space;                // system table space handler
    knl_space_def_t user_space;                  // user tablespace handler
    knl_space_def_t temp_space;                  // == OLD VERSION: temp2_space -- nologging tablespace handler
    knl_space_def_t temp_undo_space;            // == OLD VERSION: temp2_undo_space -- nologging undo tablespace handler
    knl_space_def_t sysaux_space;                // sysware table sapce handler(wsr,hist etc.)

    galist_t logfiles;                           // redo log file list
    galist_t ctrlfiles;                          // control file list
    archive_mode_t arch_mode;
    uint32 dw_area_pages;
    knl_device_def_t dwa_dev;
    galist_t nodes;       // node list
    uint32 max_instance;  // max instance number
} knl_database_def_t;

status_t knl_create_database(knl_handle_t session, knl_database_def_t *def, bool32 clustered);
status_t knl_check_user_4mysql(knl_handle_t session, knl_user_def_t *user_def, bool32 *exist);
status_t knl_create_space_internal(knl_handle_t session, knl_handle_t stmt, knl_space_def_t *def);
status_t knl_create_space4mysql(knl_handle_t session, knl_handle_t stmt, knl_space_def_t *def);
status_t knl_create_user_internal(knl_handle_t session, knl_user_def_t *def);
status_t knl_create_user4mysql(knl_handle_t session, knl_user_def_t *def);
status_t knl_create_database4mysql(knl_handle_t session, knl_handle_t stmt, knl_space_def_t *space_def,
                                   knl_user_def_t *user_def);
status_t knl_drop_user_internal(knl_handle_t session, knl_drop_user_t *def);
status_t knl_drop_user4mysql(knl_handle_t session, knl_handle_t stmt, knl_drop_user_t *def);
status_t knl_drop_space_internal(knl_handle_t session, knl_handle_t stmt, knl_drop_space_def_t *def);
status_t knl_drop_space4mysql(knl_handle_t session, knl_handle_t stmt, knl_drop_space_def_t *def);
status_t knl_drop_database4mysql(knl_handle_t session, knl_handle_t stmt, knl_drop_space_def_t *space_def,
                                 knl_drop_user_t *user_def);

#ifdef __cplusplus
}
#endif

#endif
