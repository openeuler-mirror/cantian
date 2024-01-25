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
 * ctsql_privilege.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_privilege.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_PRIVILEGE_H__
#define __SQL_PRIVILEGE_H__
#include "cm_defs.h"
#include "ctsql_context.h"
#include "ctsql_stmt.h"
#include "knl_interface.h"
#include "knl_privilege.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef status_t (*sys_privs_chk_func)(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid);

typedef struct st_priv_tab_def {
    sys_privs_id base_privid;
    sys_privs_id any_privid;
    sys_privs_chk_func proc;
} priv_tab_def;

typedef struct st_sql_priv_check_t {
    priv_type_def priv_type;
    galist_t *priv_list;
    text_t *objowner;
    text_t *objname;
    object_type_t objtype;
} sql_priv_check_t;

status_t sql_check_trigger_priv(sql_stmt_t *stmt, void *entity_in);
status_t sql_check_privilege(sql_stmt_t *stmt, bool32 need_lock_ctrl);
status_t sql_check_seq_priv(sql_stmt_t *stmt, text_t *user, text_t *seqname);
status_t sql_check_library_priv_core(sql_stmt_t *stmt, text_t *obj_owner, text_t *obj_name, text_t *curr_user);
status_t sql_check_proc_priv_core(sql_stmt_t *stmt, text_t *obj_owner, text_t *obj_name, text_t *curr_user);
status_t sql_check_type_priv_core(sql_stmt_t *stmt, text_t *obj_owner, text_t *obj_name, text_t *curr_user);
status_t sql_check_inherit_priv(sql_stmt_t *stmt, text_t *obj_user);
status_t sql_check_exec_type_priv(sql_stmt_t *stmt, text_t *obj_owner, text_t *obj_name);
status_t sql_check_grant_revoke_priv(sql_stmt_t *stmt, sql_priv_check_t *priv_check);
status_t sql_check_user_select_priv(knl_session_t *session, text_t *checked_user, text_t *owner, text_t *obj_name,
                                    object_type_t obj_type, bool32 for_update);

bool32 sql_user_is_dba(session_t *session);
bool32 sql_check_schema_priv(session_t *session, text_t *obj_schema);
bool32 sql_check_stats_priv(session_t *session, text_t *obj_schema);
bool32 sql_check_policy_exempt(session_t *session);
status_t sql_check_profile_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid);
status_t sql_check_priv(sql_stmt_t *stmt, text_t *curr_user, text_t *object_user, sys_privs_id base_privid,
    sys_privs_id any_privid);
status_t sql_check_table_priv_by_name(sql_stmt_t *stmt, text_t *curr_user, text_t *owner, text_t *obj_name,
                                      uint32 priv_id);
status_t sql_check_user_tenant(knl_session_t *session);
status_t sql_check_xa_priv(knl_session_t *session, xa_xid_t *xa_xid);
status_t sql_check_dump_priv(sql_stmt_t *stmt, knl_alter_sys_def_t *def);
status_t sql_check_pl_dc_lst_priv(sql_stmt_t *stmt, galist_t *pl_dc_lst, text_t *checked_user);
status_t sql_check_create_trig_priv(sql_stmt_t *stmt, text_t *obj_owner, text_t *table_user);
status_t sql_check_ple_dc_priv(sql_stmt_t *stmt, void *pl_dc_in);
status_t sql_check_dml_privs(sql_stmt_t *stmt, bool32 need_lock_ctrl);
#ifdef __cplusplus
}
#endif

#endif /* __SQL_PRIVILEGE_H__ */
