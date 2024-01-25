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
 * knl_datafile.h
 *
 *
 * IDENTIFICATION
 * src/kernel/tablespace/knl_datafile.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef KNL_DATAFILE_H
#define KNL_DATAFILE_H

#include "cm_defs.h"
#include "cm_text.h"
#include "cm_list.h"
#include "cm_device.h"
#include "cm_latch.h"
#include "knl_session.h"
#include "knl_log.h"
#include "knl_page.h"
#include "knl_datafile_persistent.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DATAFILE_FLAG_ONLINE      0x01
#define DATAFILE_FLAG_AUTO_EXTEND 0x02
#define DATAFILE_FLAG_ALARMED     0x04
#define DATAFILE_FLAG_COMPRESS    0x08

#define DATAFILE_IS_PUNCHED(df)     ((df)->ctrl->punched)

#define DATAFILE_IS_COMPRESS(df)    ((df)->ctrl->flag & DATAFILE_FLAG_COMPRESS)
#define DATAFILE_SET_COMPRESS(df)   CM_SET_FLAG((df)->ctrl->flag, DATAFILE_FLAG_COMPRESS)
#define DATAFILE_UNSET_COMPRESS(df)   CM_CLEAN_FLAG((df)->ctrl->flag, DATAFILE_FLAG_COMPRESS)

#define DATAFILE_IS_ONLINE(df)    ((df)->ctrl->flag & DATAFILE_FLAG_ONLINE)
#define DATAFILE_SET_ONLINE(df)   CM_SET_FLAG((df)->ctrl->flag, DATAFILE_FLAG_ONLINE)
#define DATAFILE_UNSET_ONLINE(df) CM_CLEAN_FLAG((df)->ctrl->flag, DATAFILE_FLAG_ONLINE)

#define DATAFILE_IS_AUTO_EXTEND(df)    ((df)->ctrl->flag & DATAFILE_FLAG_AUTO_EXTEND)
#define DATAFILE_SET_AUTO_EXTEND(df)   CM_SET_FLAG((df)->ctrl->flag, DATAFILE_FLAG_AUTO_EXTEND)
#define DATAFILE_UNSET_AUTO_EXTEND(df) CM_CLEAN_FLAG((df)->ctrl->flag, DATAFILE_FLAG_AUTO_EXTEND)

#define DATAFILE_IS_ALARMED(df)     ((df)->ctrl->flag & DATAFILE_FLAG_ALARMED)
#define DATAFILE_SET_ALARMED(df)    CM_SET_FLAG((df)->ctrl->flag, DATAFILE_FLAG_ALARMED)
#define DATAFILE_UNSET_ALARMED(df)  CM_CLEAN_FLAG((df)->ctrl->flag, DATAFILE_FLAG_ALARMED)

#define DATAFILE_TBL_FUNC_BLOCK_NUM       1   // only table func dba_page_corruption
#define DATAFILE_BACKUP_BLOCK_NUM   (CT_MAX_BACKUP_PROCESS - 1)
#define DATAFILE_MAX_BLOCK_NUM      (DATAFILE_BACKUP_BLOCK_NUM + DATAFILE_TBL_FUNC_BLOCK_NUM)
// table func dba_page_corruption will block ckpt by this ID
#define DATAFILE_TABLE_FUNC_BLOCK_ID    (uint32)(DATAFILE_BACKUP_BLOCK_NUM)

#define DATAFILE_CONTAINS_DW(df, dw_file_id)    ((df)->ctrl->id == (dw_file_id)) // double write area file

#define DATAFILE_GET(session, id)         (&(session)->kernel->db.datafiles[id])
#define DATAFILE_FD(session, id)          (&(session)->datafiles[id])
#define MAX_FILE_PAGES(type)     ((type) & SPACE_TYPE_UNDO ? CT_MAX_UNDOFILE_PAGES : CT_MAX_DATAFILE_PAGES)

/** 1, datafile structure version, include:
 *     ctrl_version_t.version.inner
 *     datafile_ctrl_bk_t.version
 *     log_file_ctrl_bk_t.version
 *  2, for ztox version verify, only matched version is support
 *  WARNING: start by one, and everytime datafile structure changes, need increase by one
 * change log:
 *  1 origin version
 *  2 add heap segment page_count, free_page_count, last_ext_size
 */
#define DATAFILE_STRUCTURE_VERSION        2

/*
 * page distribution in datafile with bitmap:
 * ----- ------ ----------------------- ------ --------------------------------------------------
 * |file_head|spc head(reserved)| map head | map pages | data pages|  map pages |  data pages|
 * ----- ------ ----------------------- ------ ---------------------------------------------------
 *    1            1               1           125         ...          128           ...
 */
#define DF_MAP_HEAD_PAGE          2
#define DF_MAP_GROUP_SIZE         128
#define DF_MAP_HWM_START          DF_MAP_GROUP_SIZE
#define DF_MAP_GROUP_INIT_SIZE    (uint8)(DF_MAP_HWM_START - (DF_MAP_HEAD_PAGE + 1))

#define DF_MAP_SIZE(session)               (DEFAULT_PAGE_SIZE(session) - sizeof(df_map_page_t) - sizeof(page_tail_t))
#define DF_BYTE_TO_BITS           8
#define DF_MAP_BIT_CNT(session)            (uint16)(DF_MAP_SIZE(session) * DF_BYTE_TO_BITS)
#define DF_MAX_MAP_GROUP_CNT      (uint32)17

#define DF_MAP_MATCH(bitmap, pos)    (!((bitmap)[(pos) >> 3] & (1 << ((pos) & 0x07))))
#define DF_MAP_UNMATCH(bitmap, pos)  ((bitmap)[(pos) >> 3] & (1 << ((pos) & 0x07)))
#define DF_MAP_SET(bitmap, pos)      ((bitmap)[(pos) >> 3] |= 1 << ((pos) & 0x07))
#define DF_MAP_UNSET(bitmap, pos)    ((bitmap)[(pos) >> 3] &= ~(1 << ((pos) & 0x07)))

/* datafile without bitmap */
#define DF_HWM_START             (uint32)1
#define DF_FIRST_HWM_START       (DF_HWM_START + 1)

#define DF_PAGE_PER_LINE (uint32)(8)
#define DF_PAGE_PER_LINE_COUNT (uint32)(56)
#define DF_PARAL_BUILD_THREAD 8
#define DF_BUILD_PARAL_THRES SIZE_G(1)

#define DF_FILENO_IS_INVAILD(df)     ((df)->file_no == CT_INVALID_ID32)
#define DF_DEFAULD_AUTOEXTEND_SIZE  SIZE_M(16)

typedef struct st_df_map_group {
    page_id_t first_map;    // start page id of bitmap pages of this group
    uint8 page_count;        // count of bitmap pages of this group
    uint8 reserved[DF_MAP_GROUP_RESERVED];
} df_map_group_t;

typedef struct st_df_map_head {
    page_head_t page_head;
    uint16 bit_unit;         // page count that managed by one bit
    uint16 group_count;      // count of bitmap group that already exists
    uint32 reserved;
    df_map_group_t groups[DF_MAX_MAP_GROUP_CNT];
} df_map_head_t;

typedef struct st_df_map_page {
    page_head_t page_head;
    page_id_t first_page;     // first page managed by this bitmap
    uint16 free_begin;        // first free bit
    uint16 free_bits;         // free bits
    uint32 reserved;
    uint8 bitmap[0];           // following is the bitmap
} df_map_page_t;

typedef enum en_df_build_status {
    DF_IS_BUILDING = 0,
    DF_BUILD_SUCCESSED = 1,
    DF_BUILD_FAILED = 2,
} df_build_status_t;

typedef struct st_df_build_ctx {
    thread_t thread;
    knl_session_t *session;
    struct st_datafile *df;
    int64 offset;
    int64 size;
    df_build_status_t status;
    char *buf;
} df_build_ctx_t;

#ifdef WIN32
typedef struct st_datafile {
#else
typedef struct __attribute__((aligned(128))) st_datafile {
#endif
    bool32 in_memory;
    uint32 file_no;  // file number in space datafiles
    uint32 space_id;
    int32 wd;        // file watch descriptor

    datafile_ctrl_t *ctrl;
    char *addr;  // for all in memory device
    datafile_header_t head;
    uint64 block_start[DATAFILE_MAX_BLOCK_NUM];
    uint64 block_end[DATAFILE_MAX_BLOCK_NUM];
    uint32 block_num;
    uint32 reserved;
    latch_t block_latch;

    df_map_head_t *map_head;
    page_id_t map_head_entry;

    df_build_ctx_t build_ctx[DF_PARAL_BUILD_THREAD];
} datafile_t;

status_t spc_open_datafile(knl_session_t *session, datafile_t *df, int32 *handle);
void spc_close_datafile(datafile_t *df, int32 *handle);
void spc_invalidate_datafile(knl_session_t *session, datafile_t *df, bool32 ckpt_disable);
status_t spc_read_datafile(knl_session_t *session, datafile_t *df, int32 *handle, int64 offset, void *buf, uint32 size);
status_t spc_write_datafile(knl_session_t *session, datafile_t *df, int32 *handle,
                            int64 offset, const void *buf, int32 size);
status_t spc_extend_datafile(knl_session_t *session, datafile_t *df, int32 *handle, int64 size, bool32 need_redo);
status_t spc_truncate_datafile(knl_session_t *session, datafile_t *df, int32 *handle, int64 keep_size, bool32 need_redo);
status_t spc_extend_datafile_ddl(knl_session_t *session, datafile_t *df, int32 *handle, int64 size, bool32 need_redo);
status_t spc_truncate_datafile_ddl(knl_session_t *session, datafile_t *df, int32 *handle, int64 keep_size,
                                   bool32 need_redo);
status_t spc_build_datafile(knl_session_t *session, datafile_t *df, int32 *handle);
status_t spc_init_datafile_head(knl_session_t *session, datafile_t *df);
status_t spc_get_datafile_name_bynumber(knl_session_t *session, int32 filenumber, char **filename);
status_t spc_alter_datafile_autoextend(knl_session_t *session, knl_alterdb_datafile_t *def);
status_t spc_alter_datafile_resize(knl_session_t *session, knl_alterdb_datafile_t *def);
EXTER_ATTACK void spc_block_datafile(datafile_t *df, uint32 section_id, uint64 start, uint64 end);
void spc_try_block_datafile(datafile_t *df, uint32 section_id, uint64 start, uint64 end);
EXTER_ATTACK void spc_unblock_datafile(datafile_t *df, uint32 section_id);
bool32 spc_datafile_is_blocked(knl_session_t *session, datafile_t *df, uint64 start, uint64 end);

void df_add_map_group(knl_session_t *session, datafile_t *df, page_id_t page_id, uint8 group_size);
void df_init_map_head(knl_session_t *session, datafile_t *df);
status_t df_alloc_extent(knl_session_t *session, datafile_t *df, uint32 extent_size, page_id_t *extent);
void df_free_extent(knl_session_t *session, datafile_t *df, page_id_t extent);

// for swap space, now it is bimap managed
void df_add_map_group_swap(knl_session_t *session, datafile_t *df, page_id_t page_id, uint8 group_size);
void df_init_swap_map_head(knl_session_t *session, datafile_t *df);
status_t df_alloc_swap_map_extent(knl_session_t *session, datafile_t *df, page_id_t *extent);
void df_free_swap_map_extent(knl_session_t *session, datafile_t *df, page_id_t extent);

uint32 df_get_used_pages(knl_session_t *session, datafile_t *df);
status_t df_get_free_extent(knl_session_t *session, datafile_t *df, page_id_t start, uint32 *extent,
                            uint64 *page_count, bool32 *is_last);
datafile_t *db_get_next_datafile(knl_session_t *session, uint32 *file_id, uint64 *data_size, uint32 *hwm_start);
uint32 df_get_shrink_hwm(knl_session_t *session, datafile_t *df);

/*
 * set the continuous len bits from start in given bitmap
 */
static inline void df_set_bitmap(uint8 *bitmap, uint16 start_input, uint16 len_input)
{
    uint16 start = start_input;
    uint16 len = len_input;
    while (len-- > 0) {
        DF_MAP_SET(bitmap, start);
        start++;
    }
}

/*
 * unset the continuous len bits from start in given bitmap
 */
static inline void df_unset_bitmap(uint8 *bitmap, uint16 start_input, uint16 len_input)
{
    uint16 start = start_input;
    uint16 len = len_input;
    while (len-- > 0) {
        DF_MAP_UNSET(bitmap, start);
        start++;
    }
}

status_t df_dump_map_head_page(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump);
status_t df_dump_map_data_page(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump);

status_t df_verify_page_by_hwm(knl_session_t *session, rowid_t rowid);
status_t df_verify_pageid_by_hwm(knl_session_t *session, page_id_t page_id);
status_t df_verify_pageid_by_size(knl_session_t *session, page_id_t page_id);

status_t df_alter_datafile_precheck_autoextend(knl_session_t *session, datafile_t *df,
        knl_autoextend_def_t *def);

#ifdef __cplusplus
}
#endif

#endif

