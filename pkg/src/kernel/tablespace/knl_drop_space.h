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

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(4)
typedef struct st_rd_remove_space {
    uint32 space_id;
    uint32 options;
    uint64 org_scn;
} rd_remove_space_t;

typedef struct st_rd_remove_space_daac {
    uint32 op_type;
    rd_remove_space_t space;
} rd_remove_space_daac_t;

typedef struct st_rd_remove_datafile {
    uint32 id;        // datafile id in whole database
    uint32 space_id;  // tablespace id
    uint32 file_no;   // sequence number in tablespace
} rd_remove_datafile_t;

typedef struct st_rd_remove_datafile_daac {
    uint32 op_type;
    rd_remove_datafile_t datafile;
} rd_remove_datafile_daac_t;
#pragma pack()

status_t spc_check_object_exist(knl_session_t *session, space_t *space);
status_t spc_drop_online_space(knl_session_t *session, space_t *space, uint32 options);
void spc_remove_datafile_device(knl_session_t *session, datafile_t *df);
status_t spc_remove_mount_datafile(knl_session_t *session, space_t *space, uint32 id, uint32 options);

#ifdef __cplusplus
}
#endif

#endif

