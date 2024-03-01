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
 * dc_log.h
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/dc_log.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_DC_LOG_H__
#define __KNL_DC_LOG_H__

#include "knl_dc.h"
#include "knl_database.h"
#include "knl_context.h"

#ifdef __cplusplus
extern "C" {
#endif

void rd_create_table(knl_session_t *session, log_entry_t *log);
void rd_create_view(knl_session_t *session, log_entry_t *log);
void rd_alter_table(knl_session_t *session, log_entry_t *log);
void rd_rename_table(knl_session_t *session, log_entry_t *log);
void rd_drop_table(knl_session_t *session, log_entry_t *log);
void rd_create_synonym(knl_session_t *session, log_entry_t *log);
void rd_drop_synonym(knl_session_t *session, log_entry_t *log);
void rd_drop_view(knl_session_t *session, log_entry_t *log);
void rd_create_user(knl_session_t *session, log_entry_t *log);
void rd_drop_user(knl_session_t *session, log_entry_t *log);
void rd_alter_user(knl_session_t *session, log_entry_t *log);
void rd_clear_user_priv(dc_context_t *ctx, dc_user_t *user);
void rd_create_role(knl_session_t *session, log_entry_t *log);
void rd_drop_role(knl_session_t *session, log_entry_t *log);
void rd_create_tenant(knl_session_t *session, log_entry_t *log);
void rd_alter_tenant(knl_session_t *session, log_entry_t *log);
void rd_drop_tenant(knl_session_t *session, log_entry_t *log);
void rd_create_distribute_rule(knl_session_t *session, log_entry_t *log);
void rd_drop_distribute_rule(knl_session_t *session, log_entry_t *log);
void rd_create_mk_begin(knl_session_t *session, log_entry_t *log);
void rd_create_mk_data(knl_session_t *session, log_entry_t *log);
void rd_create_mk_end(knl_session_t *session, log_entry_t *log);
void rd_alter_server_mk(knl_session_t *session, log_entry_t *log);
void rd_alter_db_logicrep(knl_session_t *session, log_entry_t *log);
dc_entity_t *rd_invalid_entity(knl_session_t *session, dc_entry_t *entry);
void rd_refresh_dc(knl_session_t *session, log_entry_t *log);
void rd_lock_table_for_mysql_ddl(knl_session_t *session, log_entry_t *log);
void rd_unlock_table_for_mysql_ddl(knl_session_t *session, log_entry_t *log);
void rd_invalid_dd_for_mysql_ddl(knl_session_t *session, log_entry_t *log);

void print_create_table(log_entry_t *log);
void print_create_view(log_entry_t *log);
void print_alter_table(log_entry_t *log);
void print_rename_table(log_entry_t *log);
void print_drop_table(log_entry_t *log);
void print_create_synonym(log_entry_t *log);
void print_drop_synonym(log_entry_t *log);
void print_drop_view(log_entry_t *log);
void print_create_user(log_entry_t *log);
void print_drop_user(log_entry_t *log);
void print_alter_user(log_entry_t *log);
void print_create_role(log_entry_t *log);
void print_drop_role(log_entry_t *log);
void print_create_tenant(log_entry_t *log);
void print_alter_tenant(log_entry_t *log);
void print_drop_tenant(log_entry_t *log);
void print_create_distribute_rule(log_entry_t *log);
void print_drop_distribute_rule(log_entry_t *log);
void print_alter_server_mk(log_entry_t *log);
void print_create_mk_begin(log_entry_t *log);
void print_create_mk_data(log_entry_t *log);
void print_create_mk_end(log_entry_t *log);
void print_alter_db_logicrep(log_entry_t *log);
void print_refresh_dc(log_entry_t *log);
void print_lock_table_for_mysql_ddl(log_entry_t *log);
void print_unlock_table_for_mysql_ddl(log_entry_t *log);
void print_invalid_dd_for_mysql_ddl(log_entry_t *log);


/* handle errors that must be abort during replay */
static inline void rd_check_dc_replay_err(knl_session_t *session)
{
    int32 err_code;

    if (DB_IS_PRIMARY(&session->kernel->db)) {
        return;
    }

    err_code = cm_get_error_code();
    if (err_code == ERR_ALLOC_GA_MEMORY || err_code == ERR_DC_BUFFER_FULL) {
        CM_ABORT(0, "[RD] ABORT INFO: Failed to replay logic log, because of DC_POOL is full");
    }
}


#ifdef __cplusplus
}
#endif

#endif
