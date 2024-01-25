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
 * knl_defs_persistent.h
 *
 *
 * IDENTIFICATION
 * src/upgrade_check/knl_defs_persistent.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_DEFS_PERSISTENT_H__
#define __KNL_DEFS_PERSISTENT_H__
 
#ifdef __cplusplus
extern "C" {
#endif
// Page ID type identify a physical position of a page
#pragma pack(4)
typedef union st_undo_page_id {
    uint32 value;  // total size is 32 bit
    struct {
        uint32 file : 10;
        uint32 page : 22;
    };
} undo_page_id_t;

// Page list type
typedef struct st_undo_page_list {
    uint32 count;
    undo_page_id_t first;
    undo_page_id_t last;
} undo_page_list_t;

// Page list type
typedef struct st_undo_rowid {
    undo_page_id_t page_id;
    uint16 slot;
    uint16 aligned;
} undo_rowid_t;

typedef struct st_undo_page_info {
    undo_rowid_t undo_rid; /* undo page */
    uint32 undo_fs;        /* freespace of urid->page_id */
    bool32 encrypt_enable; /* curr undo page can encrypt */
    bool32 undo_log_encrypt; /* if redolog of curr undorow need encrypt */
} undo_page_info_t;

#define ROWID_FILE_BITS   10
#define ROWID_PAGE_BITS   30
#define ROWID_SLOT_BITS   12
#define ROWID_UNUSED_BITS 12
#define ROWID_VALUE_BITS  52
 
typedef union st_page_id {
    uint32 vmid;
    struct {
        uint32 page;
        uint16 file;
        uint16 aligned;
    };
} page_id_t;

// Page id buffer
typedef char pagid_data_t[6];

// Page list type
typedef struct st_page_list {
    uint32 count;
    page_id_t first;
    page_id_t last;
} page_list_t;

// Row ID type identify a physical position of a row
typedef union st_rowid {
    struct {
        uint64 value : ROWID_VALUE_BITS;
        uint64 unused1 : ROWID_UNUSED_BITS;
    };

    struct {
        uint64 file : ROWID_FILE_BITS;  // file
        uint64 page : ROWID_PAGE_BITS;  // page
        uint64 slot : ROWID_SLOT_BITS;  // slot number
        uint64 unused2 : ROWID_UNUSED_BITS;
    };

    struct {
        uint64 vmid : 32;     // virtual memory page id, dynamic view item, ...
        uint64 vm_slot : 16;  // slot of virtual memory page, sub item
        uint64 vm_tag : 16;
    };

    struct {
        uint32 tenant_id : 16;
        uint32 curr_ts_num : 16;
        uint32 ts_id;
    };

    struct {
        uint32 group_id;
        uint32 attr_id;
    };

    struct {
        uint32 pos;
        uint32 bucket_id : 16;
        uint32 sub_id : 16;
    };
} rowid_t;
#pragma pack()
 
#ifdef __cplusplus
}
#endif
 
#endif