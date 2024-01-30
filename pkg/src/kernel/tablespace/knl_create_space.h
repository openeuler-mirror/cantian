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
 * knl_create_space.h
 *
 *
 * IDENTIFICATION
 * src/kernel/tablespace/knl_create_space.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_CREATE_SPACE_H__
#define __KNL_CREATE_SPACE_H__

#include "knl_space_ddl.h"
#include "knl_create_space_persist.h"

#ifdef __cplusplus
extern "C" {
#endif

bool32 spc_try_init_punch_head(knl_session_t *session, space_t *space);
status_t spc_create_space_precheck(knl_session_t *session, knl_space_def_t *def);
status_t spc_create_space(knl_session_t *session, knl_space_def_t *def, uint32 *id);
status_t spc_create_datafiles(knl_session_t *session, space_t *space, knl_altspace_def_t *def);
status_t spc_drop_datafiles(knl_session_t *session, space_t *space, galist_t *datafiles);

#ifdef __cplusplus
}
#endif

#endif

