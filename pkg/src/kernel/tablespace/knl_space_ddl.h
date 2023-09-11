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
 * knl_space_ddl.h
 *
 *
 * IDENTIFICATION
 * src/kernel/tablespace/knl_space_ddl.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_SPACE_DDL_H__
#define __KNL_SPACE_DDL_H__

#include "knl_space_base.h"
#include "knl_context.h"

#ifdef __cplusplus
extern "C" {
#endif

bool32 spc_auto_offline_space(knl_session_t *session, space_t *space, datafile_t *df);
status_t spc_mount_space(knl_session_t *session, space_t *space, bool32 auto_offline);
void spc_umount_space(knl_session_t *session, space_t *space);
void spc_clean_nologging_data(knl_session_t *session);
status_t spc_drop_nologging_table(knl_session_t *session);
void spc_offline_space_files(knl_session_t *session, uint32 *files, uint32 file_hwm);
void spc_update_hwms(knl_session_t *session, space_t *space, uint32 *hwms);

#ifdef __cplusplus
}
#endif

#endif

