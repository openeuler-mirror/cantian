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
 * knl_db_ctrl.h
 *
 *
 * IDENTIFICATION
 * src/kernel/knl_db_ctrl.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_DB_CTRL_H__
#define __KNL_DB_CTRL_H__

#include "cm_defs.h"
#include "cm_latch.h"
#include "cm_utils.h"
#include "knl_log.h"
#include "knl_datafile.h"
#include "knl_interface.h"
#include "knl_session.h"
#include "knl_heap.h"
#include "knl_dc.h"
#include "knl_archive.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CORE_SYSDATA_VERSION  77

#define CORE_VERSION_MAIN     1
#define CORE_VERSION_MAJOR    0
#define CORE_VERSION_REVISION 1
#define CORE_VERSION_INNER    DATAFILE_STRUCTURE_VERSION

#define CTRL_OLD_MAX_PAGE 512
#define CTRL_MAX_PAGES_NONCLUSTERED 640
#define CTRL_MAX_PAGES_CLUSTERED 2190
#define CTRL_MAX_PAGES(session) \
    (uint32)((session)->kernel->attr.clustered ? CTRL_MAX_PAGES_CLUSTERED : CTRL_MAX_PAGES_NONCLUSTERED)
#define CTRL_MAX_BUF_SIZE (GS_DFLT_CTRL_BLOCK_SIZE - sizeof(page_head_t) - sizeof(page_tail_t))

#define CORE_CTRL_PAGE_ID 1
#define CTRL_LOG_SEGMENT  2

typedef struct st_ctrl_version {
    uint16 main;
    uint16 major;
    uint16 revision;
    uint16 inner;
} ctrl_version_t;

typedef struct st_core_ctrl {
    ctrl_version_t version;
    uint32 open_count;  // count of kernel startup times
    uint32 dbid;
    char name[GS_DB_NAME_LEN];
    time_t init_time;

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

    bool32 build_completed;

    archive_mode_t log_mode;
    arch_log_id_t archived_log[GS_MAX_ARCH_DEST];

    repl_role_t db_role;
    repl_mode_t protect_mode;
    uint32 space_count;   // tobe deleted
    uint32 device_count;  // tobe deleted
    uint32 page_size;
    uint32 undo_segments;
    reset_log_t resetlogs;
    lrep_mode_t lrep_mode;
    raft_point_t raft_flush_point;
    log_point_t lrep_point;   // log point when logic replication is turned on.
    uint32 max_column_count;  // column count: 1024, 2048,3072, 4096
    bool32 open_inconsistency;  // todo delete
    uint32 charset_id; // database charset :0 - UTF8,1 - GBK

    uint32 dw_file_id; // dw file id
    uint32 dw_area_pages;
    
    uint32 system_space; // space id
    uint32 sysaux_space;
    uint32 user_space;
    uint32 temp_undo_space;
    uint32 temp_space;
    uint32 sysdata_version;
    bool32 undo_segments_extended;
    knl_scn_t reset_log_scn;
    bool32 is_restored;
    uint32 bak_dbid;
    uint64 ddl_pitr_lsn;

    char reserved[2036];                          // reserved bytes for nonclustered database
    bool32 clustered;                             // is clustered database?
    uint32 node_count;                            // instance nodes
    uint32 max_nodes;                             // max instance nodes number
} core_ctrl_t;

typedef struct st_ctrl_page {
    page_head_t head;
    char buf[CTRL_MAX_BUF_SIZE];
    page_tail_t tail;
} ctrl_page_t;

typedef struct st_database_ctrl {
    core_ctrl_t core;
    ctrl_page_t *pages;
    aligned_buf_t buf;
    uint32 log_segment;
    uint32 datafile_segment;
    uint32 space_segment;
    uint32 arch_segment;
} database_ctrl_t;

typedef struct st_ctrlfile {
    char name[GS_FILE_NAME_BUFFER_SIZE];
    device_type_t type;
    int32 block_size;
    uint32 blocks;
    int32 handle;
} ctrlfile_t;

typedef struct st_ctrlfile_set {
    uint32 count;
    ctrlfile_t items[GS_MAX_CTRL_FILES];
} ctrlfile_set_t;

typedef struct st_logfile_set {
    uint32 logfile_hwm;  // include holes (logfile has been dropped)
    uint32 log_count;
    log_file_t items[GS_MAX_LOG_FILES];
} logfile_set_t;

typedef struct st_switch_ctrl {
    spinlock_t lock;
    switch_state_t state;
    volatile switch_req_t request;
    uint32 keep_sid;
    uint32 switch_asn;
    bool32 handling;
    volatile bool32 is_rmon_set;
    date_t last_log_time;
    bool8 has_logged;
    bool8 reserved;
    uint16 peer_repl_port;
} switch_ctrl_t;

typedef struct st_rd_update_sysdata {
    uint32 op_type;
    uint32 sysdata_version;
} rd_update_sysdata_t;

status_t db_generate_ctrlitems(knl_session_t *session);
status_t db_create_ctrl_file(knl_session_t *session);
status_t db_save_core_ctrl(knl_session_t *session);
status_t db_save_log_ctrl(knl_session_t *session, uint32 id, uint32 node_id);
status_t db_save_datafile_ctrl(knl_session_t *session, uint32 id);
status_t db_save_space_ctrl(knl_session_t *session, uint32 id);
status_t db_save_arch_ctrl(knl_session_t *session, uint32 id, uint32 node_id);
status_t db_load_logfiles(knl_session_t *session);
arch_ctrl_t *db_get_arch_ctrl(knl_session_t *session, uint32 id, uint32 node_id);
void db_init_logfile_ctrl(knl_session_t *session, uint32 *offset);
void db_init_space_ctrl(knl_session_t *session, uint32 *offset);
void db_init_datafile_ctrl(knl_session_t *session, uint32 *offset);
status_t db_load_ctrlspace(knl_session_t *session, text_t *files);
status_t db_check(knl_session_t *session, text_t *ctrlfiles, bool32 *is_found);
void db_update_sysdata_version(knl_session_t *session);
void rd_update_sysdata_version(knl_session_t *session, log_entry_t *log);
void print_update_sysdata_version(log_entry_t *log);
bool32 db_sysdata_version_is_equal(knl_session_t *session, bool32 is_upgrade);
uint32 dbc_generate_dbid(knl_session_t *session);

static inline char *db_get_ctrl_item(ctrl_page_t *pages, uint32 id, uint32 item_size, uint32 offset)
{
    uint32 count = CTRL_MAX_BUF_SIZE / item_size;
    uint32 page_id = offset + id / count;
    uint16 slot = id % count;
    ctrl_page_t *page = pages + page_id;

    return page->buf + slot * item_size;
}

static inline char *db_get_log_ctrl_item(ctrl_page_t *pages, uint32 id, uint32 item_size, uint32 offset, uint32 node_id)
{
    uint32 count = CTRL_MAX_BUF_SIZE / item_size;
    uint32 pages_per_inst = (GS_MAX_LOG_FILES - 1) / count + 1;
    uint32 page_id = offset + pages_per_inst * node_id + id / count;
    uint16 slot = id % count;
    ctrl_page_t *page = pages + page_id;
    return page->buf + slot * item_size;
}

static inline uint32 db_get_log_ctrl_pageid(uint32 id, uint32 offset, uint32 node_id)
{
    uint32 count = CTRL_MAX_BUF_SIZE / sizeof(log_file_ctrl_t);
    uint32 pages_per_inst = (GS_MAX_LOG_FILES - 1) / count + 1;
    uint32 page_id = offset + pages_per_inst * node_id + id / count;
    return page_id;
}

#ifdef __cplusplus
}
#endif

#endif

