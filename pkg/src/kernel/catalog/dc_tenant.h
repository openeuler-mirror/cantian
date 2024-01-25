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
 * dc_tenant.h
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/dc_tenant.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_DC_TENANT_H__
#define __KNL_DC_TENANT_H__

#include "knl_dc.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t dc_init_tenant(dc_context_t *ctx, dc_tenant_t **tenant_out);
status_t dc_init_tenants(knl_session_t *session, dc_context_t *ctx);
status_t dc_add_tenant(dc_context_t *ctx, knl_tenant_desc_t *desc);
status_t dc_try_create_tenant(knl_session_t *session, uint32 id, const char *tenant_name);
void dc_drop_tenant(knl_session_t *session, uint32 tid);
status_t dc_lock_tenant(knl_session_t *session, knl_drop_tenant_t *def, uint32 *tid);
status_t dc_get_tenant_id(knl_session_t *session, const text_t *name, uint32 *tenant_id);
status_t dc_init_root_tenant(knl_handle_t session, dc_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif