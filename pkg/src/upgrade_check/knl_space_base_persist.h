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
 * knl_space_base_persist.h
 *
 *
 * IDENTIFICATION
 * src/upgrade_check/knl_space_base_persist.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_SPACE_BASE_PERSIST_H__
#define __KNL_SPACE_BASE_PERSIST_H__

#ifdef __cplusplus
extern "C" {
#endif
#define CT_SPACE_CTRL_RESERVED_BYTES_13 13
typedef struct st_space_ctrl {
    uint32 id;
    bool32 used;
    char name[CT_NAME_BUFFER_SIZE];
    uint16 flag;
    uint16 block_size;
    uint32 extent_size;  // extent pages count
    uint32 file_hwm;     // max allocated datafile count
    uint32 type;
    knl_scn_t org_scn;
    uint8 encrypt_version;
    uint8 cipher_reserve_size;
    uint8 is_for_create_db;
    uint8 unused[CT_SPACE_CTRL_RESERVED_BYTES_13];

    uint32 files[CT_MAX_SPACE_FILES];  // datafile id array
} space_ctrl_t;

#pragma pack(4)

typedef struct st_rd_update_hwm {
    uint32 file_no;  // sequence number in tablespace
    uint32 file_hwm;
} rd_update_hwm_t;

typedef struct st_rd_punch_extents {
    page_list_t punching_exts;
    page_list_t punched_exts;
} rd_punch_extents_t;

#pragma pack()

#ifdef __cplusplus
}
#endif

#endif