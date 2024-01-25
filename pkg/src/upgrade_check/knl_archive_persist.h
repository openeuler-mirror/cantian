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
 * knl_archive_persist.h
 *
 *
 * IDENTIFICATION
 * src/upgrade_check/knl_archive_persist.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_ARCHIVE_PERSIST_H__
#define __KNL_ARCHIVE_PERSIST_H__
 
#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_force_archive_param {
    bool32 force_archive;
    bool32 force_switch;
    uint64 end_lsn;
    bool32 failed;
    bool32 wait;
} force_archive_param_t;
typedef struct st_archived_info {
    uint32 recid;
    uint32 dest_id;
    uint32 rst_id;
    uint32 asn;
    int64 stamp;
    uint64 start_lsn;
    uint64 end_lsn;
    int32 blocks;
    int32 block_size;
    knl_scn_t first;
    knl_scn_t last;
    int64 real_size;
    uint8 reserve[24];
    char name[CT_FILE_NAME_BUFFER_SIZE];
} arch_ctrl_t;

#ifdef __cplusplus
}
#endif
 
#endif