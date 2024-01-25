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
 * knl_db_create.h
 *
 *
 * IDENTIFICATION
 * src/kernel/knl_db_create.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_DB_CREATE_H__
#define __KNL_DB_CREATE_H__

#include "cm_defs.h"
#include "knl_session.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t dbc_create_database(knl_handle_t session, knl_database_def_t *def, bool32 clustered);
status_t dbc_build_logfiles(knl_session_t *session, galist_t *logfiles, uint8 node_id);

#ifdef __cplusplus
}
#endif

#endif
