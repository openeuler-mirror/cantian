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
 * knl_drop_space.h
 *
 *
 * IDENTIFICATION
 * src/kernel/tablespace/knl_drop_space.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_DROP_SPACE_H__
#define __KNL_DROP_SPACE_H__

#include "knl_space_ddl.h"
#include "knl_drop_space_persist.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t spc_check_object_exist(knl_session_t *session, space_t *space);
status_t spc_drop_online_space(knl_session_t *session, knl_handle_t stmt, space_t *space, uint32 options);
void spc_remove_datafile_device(knl_session_t *session, datafile_t *df);
status_t spc_remove_mount_datafile(knl_session_t *session, space_t *space, uint32 id, uint32 options);

#ifdef __cplusplus
}
#endif

#endif

