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
 * dc_priv.h
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/dc_priv.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_DC_PRIV_H__
#define __KNL_DC_PRIV_H__

#include "knl_dc.h"
#include "dc_util.h"
#ifdef __cplusplus
extern "C" {
#endif

void dc_clear_all_objprivs(dc_obj_priv_t *obj_privs);
void dc_revoke_objpriv_from_user_by_id(dc_context_t *ctx, dc_user_t *user, dc_obj_priv_item *priv_item,
                                       uint32 privid);
void dc_revoke_userpriv_from_user_by_id(dc_context_t *ctx, dc_user_t *user, uint32 grantee, uint32 privid);
void dc_revoke_objpriv_from_role_by_id(dc_context_t *ctx, dc_role_t *role, dc_obj_priv_item *priv_item,
                                       uint32 privid);
void dc_clear_grantor_objprivs(dc_context_t *ctx, dc_obj_priv_t *obj_privs, uint32 grantee_id, uint32 grantee_type);
void dc_clear_role_priv(knl_session_t *session, dc_role_t *role);
void dc_clear_user_priv(dc_context_t *ctx, dc_user_t *user);
void dc_clear_all_userprivs(dc_user_priv_t *user_privs);
status_t dc_load_sys_privs_by_id(knl_session_t *session, uint32 id, uint32 type);
status_t dc_load_role_privs_by_id(knl_session_t *session, uint32 id, uint32 type);
status_t dc_load_obj_privs_by_id(knl_session_t *session, uint32 id, uint32 type);
status_t dc_load_user_privs_by_id(knl_session_t *session, uint32 uid);
status_t dc_load_privileges(knl_session_t *session, dc_context_t *ctx);
status_t dc_add_user_grant_objpriv(knl_session_t *session, dc_user_t *user, uint32 grantee_type, uint32 grantee_id,
                                   dc_obj_priv_item *priv_item, uint32 priv_id);
void dc_update_user_syspriv_info(dc_user_t *user);
void dc_update_user_objpriv_info(dc_context_t *ctx, dc_user_t *user, dc_obj_priv_item *priv_item);
void dc_update_all_objprivs_info(knl_session_t *session, dc_user_t *user);
void dc_update_user_syspriv_by_role(dc_role_t *role);
void dc_update_user_objpriv_by_role(dc_context_t *ctx, dc_role_t *role, dc_obj_priv_item *priv_item);
void dc_update_all_objprivs_by_role(knl_session_t *session, dc_role_t *role);
void dc_update_objname_for_privs(knl_session_t *session, uint32 uid, char *oldname, text_t *newname, uint32 type);
bool32 dc_has_objpriv_entry(dc_obj_priv_t *obj_privs);
bool32 dc_has_userpriv_entry(dc_user_priv_t *user_privs);
status_t dc_alloc_objpriv_entry(dc_context_t *ctx, dc_obj_priv_t *obj_privs, memory_context_t *memory,
                                uint32 owner_uid, text_t *obj_name, uint32 obj_type, dc_obj_priv_entry_t **dc_entry);
status_t dc_alloc_user_priv_entry(dc_context_t *ctx, dc_user_priv_t *user_privs, memory_context_t *memory,
                                  uint32 grantee, dc_user_priv_entry_t **dc_entry);
void dc_drop_obj_entry(dc_obj_priv_t *obj_priv, dc_obj_priv_entry_t *entry);
bool32 dc_try_reuse_objpriv_entry(dc_obj_priv_t *obj_privs, dc_obj_priv_entry_t **dc_entry);
void dc_drop_user_entry(dc_user_priv_t *user_privs, dc_user_priv_entry_t *entry);
#ifdef __cplusplus
}
#endif

#endif