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
 * ctbackup_info.h
 *
 *
 * IDENTIFICATION
 * src/utils/ctbackup/ctbackup_info.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CANTIANDB_100_CTBACKUP_INFO_H
#define CANTIANDB_100_CTBACKUP_INFO_H

#include "cm_defs.h"
#include "cm_text.h"

#ifdef __cplusplus
extern "C" {
#endif
    
#define CTBAK_CMD_NAME_LENGTH  16
#define CTBAK_ARG_BACKUP  "--backup"
#define CTBAK_ARG_PREPARE  "--prepare"
#define CTBAK_ARG_DECOMPRESS "--decompress"
#define CTBAK_ARG_REMOVE_ORIGINAL "--remove-original"
#define CTBAK_ARG_COPYBACK "--copy-back"
#define CTBAK_ARG_ARCHIVELOG "--archivelog"
#define CTBAK_ARG_RECONCIEL_MYSQL "--reconciel-mysql"
#define CTBAK_ARG_QUERY_INCREMENTAL_MODE "--query-incremental-mode"
#define CTBAK_ARG_PURGE_LOGS "--purge-logs"

#define CTBAK_PARSE_OPTION_COMMON 0
#define CTBAK_PARSE_OPTION_ERR (-1)

// long options for ctbackup
#define CTBAK_LONG_OPTION_BACKUP "backup"
#define CTBAK_LONG_OPTION_PREPARE "prepare"
#define CTBAK_LONG_OPTION_COPYBACK "copy-back"
#define CTBAK_LONG_OPTION_ARCHIVELOG "archivelog"
#define CTBAK_LONG_OPTION_RECONCIEL_MYSQL "reconciel-mysql"
#define CTBAK_LONG_OPTION_QUERY "query-incremental-mode"
#define CTBAK_LONG_OPTION_PURGE_LOGS "purge-logs"
#define CTBAK_LONG_OPTION_TARGET_DIR "target-dir"
#define CTBAK_LONG_OPTION_DEFAULTS_FILE "defaults-file"
#define CTBAK_LONG_OPTION_SOCKET "socket"
#define CTBAK_LONG_OPTION_DATA_DIR "datadir"
#define CTBAK_LONG_OPTION_INCREMENTAL "incremental"
#define CTBAK_LONG_OPTION_INCREMENTAL_CUMULATIVE "cumulative"
#define CTBAK_LONG_OPTION_PARALLEL "parallel"
#define CTBAK_LONG_OPTION_COMPRESS "compress"
#define CTBAK_LONG_OPTION_DECOMPRESS "decompress"
#define CTBAK_LONG_OPTION_BUFFER "buffer"
#define CTBAK_LONG_OPTION_DATABASESEXCLUDE "databases-exclude"
#define CTBAK_LONG_OPTION_PITR_TIME "pitr-time"
#define CTBAK_LONG_OPTION_PITR_SCN "pitr-scn"
#define CTBAK_LONG_OPTION_PITR_CANCEL "until-cancel"
#define CTBAK_LONG_OPTION_PITR_RESTORE "restore"
#define CTBAK_LONG_OPTION_PITR_RECOVER "recover"
#define CTBAK_LONG_OPTION_LRP_LSN "lrp-lsn"
#define CTBAK_LONG_OPTION_FORCE "force"
#define CTBAK_LONG_OPTION_FORCE_DDL "force-ddl"
#define CTBAK_LONG_OPTION_SKIP_BADBLOCK "skip-badblock"
#define CTBAK_LONG_OPTION_REPAIR_TYPE "repair-type"
// long options for mysql
#define CTBAK_LONG_OPTION_USER "user"
#define CTBAK_LONG_OPTION_PASSWORD "password"
#define CTBAK_LONG_OPTION_HOST "host"
#define CTBAK_LONG_OPTION_PORT "port"
#define CTBAK_LONG_OPTION_EXEC "execute"

// short options
#define CTBAK_SHORT_OPTION_UNRECOGNIZED '?'
#define CTBAK_SHORT_OPTION_NO_ARG ':'
#define CTBAK_SHORT_OPTION_USER 'u'
#define CTBAK_SHORT_OPTION_PASSWORD 'p'
#define CTBAK_SHORT_OPTION_HOST 'h'
#define CTBAK_SHORT_OPTION_PORT 'P'
#define CTBAK_SHORT_OPTION_TARGET_DIR 't'
#define CTBAK_SHORT_OPTION_DEFAULTS_FILE 'd'
#define CTBAK_SHORT_OPTION_SOCKET 's'
#define CTBAK_SHORT_OPTION_EXEC 'e'
#define CTBAK_SHORT_OPTION_DATA_DIR 'D'
#define CTBAK_SHORT_OPTION_INCREMENTAL 'i'
#define CTBAK_SHORT_OPTION_INCREMENTAL_CUMULATIVE 'j'
#define CTBAK_SHORT_OPTION_PARALLEL 'L'
#define CTBAK_SHORT_OPTION_COMPRESS 'c'
#define CTBAK_SHORT_OPTION_DECOMPRESS 'E'
#define CTBAK_SHORT_OPTION_DATABASES_EXCLUDE 'x'
#define CTBAK_SHORT_OPTION_BUFFER 'b'
#define CTBAK_SHORT_OPTION_PITR_TIME 'T'
#define CTBAK_SHORT_OPTION_PITR_SCN 'S'
#define CTBAK_SHORT_OPTION_PITR_CANCEL 'C'
#define CTBAK_SHORT_OPTION_PITR_RESTORE 'r'
#define CTBAK_SHORT_OPTION_PITR_RECOVER 'R'
#define CTBAK_SHORT_OPTION_LRP_LSN 'l'
#define CTBAK_SHORT_OPTION_FORCE 'f'
#define CTBAK_SHORT_OPTION_FORCE_DDL 'F'
#define CTBAK_SHORT_OPTION_SKIP_BADBLOCK 'k'
#define CTBAK_SHORT_OPTION_REPAIR_TYPE 'a'

typedef enum en_ctbak_topic {
    CTBAK_INVALID,
    CTBAK_VERSION,
    CTBAK_HELP,
    CTBAK_BACKUP,
    CTBAK_PREPARE,
    CTBAK_COPYBACK,
    CTBAK_ARCHIVE_LOG,
    CTBAK_RECONCIEL_MYSQL,
    CTBAK_QUERY_INCREMENTAL_MODE,
    CTBAK_PURGE_LOGS,
} ctbak_topic_t;

typedef struct ctbak_param {
    text_t host;
    text_t user;
    SENSI_INFO text_t password;
    text_t port;
    text_t target_dir;
    text_t defaults_file;
    text_t socket;
    text_t execute;
    text_t data_dir;
    text_t parallelism;
    text_t pitr_time;
    text_t pitr_scn;
    text_t compress_algo;
    text_t buffer_size;
    text_t repair_type;
    text_t databases_exclude;
    uint8  is_decompress;
    uint8  is_pitr_cancel;
    uint8  is_restore;
    uint8  is_recover;
    uint8  is_incremental;
    uint8  is_incremental_cumulative;
    uint8  is_get_lrp;
    uint8  is_force_archive;
    uint8  is_force_ddl;
    uint8  skip_badblock;
    uint8  is_mysql_metadata_in_cantian;
} ctbak_param_t;

typedef status_t (* ctbak_execute_t)(ctbak_param_t* ctbak_param);

typedef status_t (* ctbak_parse_args_t)(int32 argc, char** argv, ctbak_param_t* ctbak_param);

typedef struct ctbak_cmd {
    ctbak_topic_t ctbak_topic;
    const char* cmd_name;
    ctbak_execute_t do_exec;
    ctbak_parse_args_t parse_args;
    ctbak_param_t* ctbak_param;
} ctbak_cmd_t;

#ifdef __cplusplus
}
#endif

#endif // CANTIANDB_100_CTBACKUP_INFO_H
