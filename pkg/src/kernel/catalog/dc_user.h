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
 * dc_user.h
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/dc_user.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_DC_USER_H__
#define __KNL_DC_USER_H__

#include "knl_dc.h"

#ifdef __cplusplus
extern "C" {
#endif
status_t dc_init_table_context(dc_context_t *ctx, dc_user_t *user);
void dc_set_user_hwm(dc_context_t *ctx, uint32 id);
void dc_insert_into_user_index(dc_context_t *ctx, dc_user_t *user);
status_t dc_init_user(dc_context_t *ctx, dc_user_t *user);
status_t dc_init_users(knl_session_t *session, dc_context_t *ctx);
status_t dc_init_sys_user(knl_session_t *session, dc_context_t *ctx);
status_t dc_add_user(dc_context_t *ctx, knl_user_desc_t *desc);
void dc_drop_user(knl_session_t *session, uint32 uid);
void dc_free_user_entry(knl_session_t *session, uint32 uid);
void dc_reuse_user(knl_session_t *session, knl_user_desc_t *desc);
status_t dc_lock_user(knl_session_t *session, dc_user_t *user);
status_t dc_try_create_user(knl_session_t *session, const char *user_name);
status_t dc_init_roles(knl_session_t *session, dc_context_t *ctx);
status_t dc_try_create_role(knl_session_t *session, uint32 id, const char *user_name);
status_t dc_add_role(dc_context_t *ctx, knl_role_desc_t *desc);
status_t dc_drop_role(knl_session_t *session, uint32 rid);
status_t user_drop_core(knl_session_t *session, dc_user_t *user, bool32 purge);

#ifdef __cplusplus
}
#endif

#endif
