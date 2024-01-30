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
 * knl_alter_space.h
 *
 *
 * IDENTIFICATION
 * src/kernel/tablespace/knl_alter_space.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_ALTER_SPACE_H__
#define __KNL_ALTER_SPACE_H__

#include "knl_space_ddl.h"
#include "knl_alter_space_persist.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t spc_set_autoextend(knl_session_t *session, space_t *space, knl_autoextend_def_t *autoextend);
status_t spc_set_autooffline(knl_session_t *session, space_t *space, bool32 auto_offline);
status_t spc_rename_space(knl_session_t *session, space_t *space, text_t *rename_space);
status_t spc_rename_datafiles(knl_session_t *session, space_t *space, galist_t *datafiles, galist_t *new_datafiles);
status_t spc_offline_datafiles(knl_session_t *session, space_t *space, galist_t *datafiles);
status_t spc_drop_offlined_space(knl_session_t *session, knl_handle_t stmt, space_t *space, uint32 options);
status_t spc_set_autopurge(knl_session_t *session, space_t *space, bool32 auto_purge);
bool32 spc_check_space_exists(knl_session_t *session, const text_t *name, bool32 is_for_create_db);

#ifdef __cplusplus
}
#endif

#endif

