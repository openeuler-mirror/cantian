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
 * knl_db_alter.h
 *
 *
 * IDENTIFICATION
 * src/kernel/knl_db_alter.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_DB_ALTER_H__
#define __KNL_DB_ALTER_H__

#include "cm_defs.h"
#include "knl_interface.h"
#include "knl_session.h"

#ifdef __cplusplus
extern "C" {
#endif
    
status_t db_alter_convert_to_standby(knl_session_t *session, knl_alterdb_def_t *def);
status_t db_alter_convert_to_readonly(knl_session_t *session);
status_t db_alter_convert_to_readwrite(knl_session_t *session);
status_t db_alter_cancel_upgrade(knl_session_t *session);
status_t db_alter_update_masterkey(knl_session_t *session);
status_t db_alter_update_server_masterkey(knl_session_t *session);
status_t db_alter_update_kernel_masterkey(knl_session_t *session);
status_t db_alter_delete_archivelog(knl_session_t *session, knl_alterdb_def_t *def);
status_t db_alter_delete_backupset(knl_session_t *session, knl_alterdb_def_t *def);
status_t db_alter_clear_logfile(knl_session_t *session, uint32 file_id);
status_t db_alter_rebuild_space(knl_session_t *session, text_t *name);
status_t db_alter_protection_mode(knl_session_t *session, knl_alterdb_def_t *def);
status_t db_alter_failover(knl_session_t *session, knl_alterdb_def_t *def);
status_t db_alter_switchover(knl_session_t *session, knl_alterdb_def_t *def);
status_t db_alter_logicrep(knl_session_t *session, lrep_mode_t logic_mode);
status_t db_alter_archivelog(knl_session_t *session, archive_mode_t archive_mode);
status_t db_alter_charset(knl_session_t *session, uint32 charset_id);
status_t db_alter_datafile(knl_session_t *session, knl_alterdb_datafile_t *def);

#ifdef __cplusplus
}
#endif

#endif