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

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(4)
typedef struct st_rd_create_space {
    uint32 space_id;
    uint32 extent_size;
    uint64 org_scn;
    uint16 flags;
    uint16 block_size;
    char name[GS_NAME_BUFFER_SIZE];
    uint32 type;
    uint8 encrypt_version;
    uint8 cipher_reserve_size;
    uint8 is_for_create_db;
    uint8 reserved2[3];
} rd_create_space_t;

typedef struct st_rd_create_datafile {
    uint32 id;        // datafile id in whole database
    uint32 space_id;  // tablespace id
    uint32 file_no;   // sequence number in tablespace
    uint16 flags;
    uint16 reserve;
    uint64 size;
    int64 auto_extend_size;
    int64 auto_extend_maxsize;
    char name[GS_FILE_NAME_BUFFER_SIZE];
    uint32 type;
} rd_create_datafile_t;

typedef struct st_rd_create_datafile_daac {
    uint32 op_type;
    rd_create_datafile_t datafile;
} rd_create_datafile_daac_t;

typedef struct st_rd_extend_undo {
    uint16 old_undo_segments;
    uint16 undo_segments;
} rd_extend_undo_segments_t;

typedef struct st_rd_update_head {
    page_id_t entry;
    uint16 space_id;  // tablespace id
    uint16 file_no;   // sequence number in tablespace
} rd_update_head_t;

typedef struct st_rd_create_space_daac {
    uint32 op_type;
    rd_create_space_t space;
} rd_create_space_daac_t;

#pragma pack()

bool32 spc_try_init_punch_head(knl_session_t *session, space_t *space);
status_t spc_create_space_precheck(knl_session_t *session, knl_space_def_t *def);
status_t spc_create_space(knl_session_t *session, knl_space_def_t *def, uint32 *id);
status_t spc_create_datafiles(knl_session_t *session, space_t *space, knl_altspace_def_t *def);
status_t spc_drop_datafiles(knl_session_t *session, space_t *space, galist_t *datafiles);

#ifdef __cplusplus
}
#endif

#endif

