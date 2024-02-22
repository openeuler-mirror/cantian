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
#include "knl_ctrl_restore_persist.h"
#define CTRL_BACKUP_VERSION_DEFAULT         0
#define CTRL_BACKUP_VERSION_REBUILD_CTRL    2
#define CTRL_SLEEP_TIME    2
#define CTRL_LOG_BACKUP_LEVEL(session)    ((session)->kernel->attr.ctrllog_backup_level)

typedef struct st_ctrl_file_items {
    char name[CT_DB_NAME_LEN];
    bool32 is_archive_on;
    galist_t *logfile_list;
    galist_t *datafile_list;
    charset_type_t charset;
}ctrl_file_items_def_t;
void ctrl_restore_core_ctrl(knl_session_t *session, page_head_t *page, int handle);
void ctrl_restore_logfile_ctrl(knl_session_t *session, log_file_ctrl_t *logfile_ctrl,
    log_file_ctrl_bk_t *logfile_ctrl_bk, bool32 need_restore_name);
status_t ctrl_backup_static_core_items(knl_session_t *session, static_core_ctrl_items_t *items);
status_t ctrl_backup_sys_entries(knl_session_t *session, sys_table_entries_t *entries);
status_t ctrl_backup_log_ctrl(knl_session_t *session, uint32 id, uint32 node_id);
status_t ctrl_backup_space_ctrl(knl_session_t *session, uint32 space_id);
status_t ctrl_backup_datafile_ctrl(knl_session_t *session, uint32 file_id);
status_t ctrl_rebuild_ctrl_files(knl_session_t *session, knl_rebuild_ctrlfile_def_t *def);
status_t ctrl_backup_core_log_info(knl_session_t *session);
status_t ctrl_backup_ctrl_info(knl_session_t *session);
status_t dbs_ctrl_backup_reset_logs(knl_session_t *session);
status_t ctrl_backup_reset_logs(knl_session_t *session);
status_t ctrl_init_logfile_ctrl(knl_session_t *session, log_file_t *logfile);
status_t ctrl_backup_arch_dest(knl_session_t *session, char *arch_dest);
status_t dbs_ctrl_rebuild_parse_archfile(knl_session_t *session, knl_rebuild_ctrlfile_def_t *def);
void dbs_ctrl_restore_node_ctrl(knl_session_t *session, space_t *space, uint32 *space_count);
status_t dbs_ctrl_restore_space_ctrl(knl_session_t *session, char *page, int handle, uint32 *count);
status_t dbs_ctrl_rebuild_restore_corelog(knl_session_t *session, char *page, uint32 *file_id);
status_t dbs_ctrl_rebuild_parse_datafile(knl_session_t *session, knl_device_def_t *device, uint32 *file_id, uint32 *count);
void dbs_ctrl_rebuild_set_default(knl_session_t *session);
void dbs_ctrl_rebuild_init_doublewrite(knl_session_t *session);
status_t dbs_restore_ctrl_data(knl_session_t *session, knl_rebuild_ctrlfile_def_t *def);
status_t ctrl_restore_charset(knl_session_t *session, knl_rebuild_ctrlfile_def_t *def);
status_t knl_backup_iof_kick_by_ns(knl_session_t *session);
status_t ctrl_backup_write_datafile(knl_session_t *session, datafile_t *datafile, int64 offset, const void *buf,
    uint32 length);
status_t ctrl_backup_log_info(knl_session_t *session);
status_t ctrl_backup_ulog(knl_session_t *session, log_file_ctrl_t *ctrl, uint32 node_id);
status_t ctrl_backup_space_info(knl_session_t *session, uint32 space_id);
status_t ctrl_backup_datafile_info(knl_session_t *session, uint32 file_id);
status_t ctrl_backup_ctrl_dbid(knl_session_t *session, uint32 dbid);
#endif