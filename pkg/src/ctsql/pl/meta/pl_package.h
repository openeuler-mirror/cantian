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
 * pl_package.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/meta/pl_package.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_PACKAGE_H__
#define __PL_PACKAGE_H__

#include "knl_session.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_package_body {
    galist_t *defs;   // plv_decl_t
    uint32 *meth_map; // eg: meth_map[0] = 2, method 0 in package spec corresponding method 2 in package body
} package_body_t;     //     meth_map[1] = -1, method 1 in package spec has no implementation in body

typedef struct st_package_spec {
    galist_t *defs; // all variables plv_decl_t
} package_spec_t;

status_t pl_load_entity_update_pack_def(knl_session_t *session, void *desc_in, void *entity_in);
status_t pl_load_entity_update_pack_body(knl_session_t *session, void *desc_in, void *entity_in);
#ifdef __cplusplus
}
#endif

#endif
