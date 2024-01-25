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
 * knl_badblock.h
 *
 *
 * IDENTIFICATION
 * src/kernel/backup/knl_badblock.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_BADBLOCK_H__
#define __KNL_BADBLOCK_H__
#include "knl_log.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_badblock_write_file_buffer {
    char *badblock_data_buffer;
} badblock_file_buffer_t;

typedef struct st_badblock_file {
    char name[CT_FILE_NAME_BUFFER_SIZE];  // file name
    int32 handle;                         // file handle
    device_type_t type;
    int64 size;                           // uncomprss file size
} badblock_local_file_t;

typedef struct st_badblock_file_mgr {
    badblock_local_file_t data_file;
    badblock_file_buffer_t file_buffer;
    char path[CT_FILE_NAME_BUFFER_SIZE];
    uint32 file_flags;
    uint32 buffer_offset;
    uint64 file_offset;
    spinlock_t lock;
    uint64 badblock_num;
} badblock_file_mgr;

#define BACKUP_BADBLOCK_FILE_NAME "ct_bad_block_record"
#define RESTORE_BADBLOCK_FILE_NAME "backupset_bad_block_record"
#define RESTORE_BADBLOCK_FILE_TMP "bad_block_tmp"
#ifdef _DEBUG
static const uint32 BADBLOCK_DATA_BUFFER_SIZE = (SIZE_K(64));
#else
static const uint32 BADBLOCK_DATA_BUFFER_SIZE = (SIZE_M(64));
#endif
static const uint32 BADBLOCK_FILE_MGR_SIZE = (SIZE_K(4));
static const uint32 BADBLOCK_BUFFER_BARRIER_SIZE = (8);
#define BADBLOCK_BUFFER_BARRIER_MAGIC (0xDD1DD2DD3DD4DD5D)
#define BADBLOCK_HEAD_BUFFER_SIZE 512

status_t badblock_write_page(knl_session_t *session, page_head_t *head);
status_t badblock_write_page_tmp(knl_session_t *session, void *page, bool32 page_id_damage);
status_t badblock_init(knl_session_t *session);
status_t badblock_end(knl_session_t *session);
#ifdef __cplusplus
}
#endif

#endif