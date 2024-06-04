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
 * knl_lob_persistent.h
 *
 *
 * IDENTIFICATION
 * src/upgrade_check/knl_lob_persistent.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_LOB_PERSISTENT_H__
#define __KNL_LOB_PERSISTENT_H__


#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(4)
typedef struct st_lob_head {
    /* size + type must be defined first!!! */
    uint32 size;
    uint32 type;
    uint32 is_outline : 1;
    uint32 node_id : 9;
    uint32 is_not_temp : 1;
    uint32 unused : 21;
} lob_head_t;

typedef struct st_lob_locator {
    lob_head_t head;
    union {
        struct {
            xid_t xid;
            knl_scn_t org_scn;
            page_id_t first;
            page_id_t last;
        };

        uint8 data[0];
    };
} lob_locator_t;

typedef struct st_lob_chunk {
    xid_t ins_xid;  // xid of session when insert lob data
    xid_t del_xid;  // xid of session when delete lob data
    knl_scn_t org_scn;
    uint32 size;
    page_id_t next;
    page_id_t free_next;
    bool32 is_recycled;
    char data[4];
} lob_chunk_t;

typedef struct st_lob_data_page {
    page_head_t head;
    page_id_t pre_free_page;  // pre free page of segment's free_list
    uint8 reserved[8];  // reserved for future use
    lob_chunk_t chunk;
} lob_data_page_t;

typedef struct st_lob_undo {
    uint32 part_no;
    lob_locator_t locator;
} lob_undo_t;

typedef struct st_lob_del_undo {
    page_id_t prev_page;
    page_id_t first_page;
    page_id_t last_page;
    uint32 chunk_count;
} lob_del_undo_t;

typedef struct st_lob_seg_undo {
    uint32 part_no;
    page_list_t free_list;
    page_id_t entry;
} lob_seg_undo_t;

typedef struct st_lob_seg_recycle_undo {
    uint32 part_no;
    page_list_t free_list;
    page_id_t pre_free_last;
    page_id_t entry;
} lob_seg_recycle_undo_t;

typedef struct st_lob_segment {
    knl_scn_t org_scn;
    knl_scn_t seg_scn;
    uint32 table_id;
    uint16 uid;
    uint16 space_id;
    uint16 column_id;
    uint16 aligned;

    page_list_t extents;
    page_list_t free_list; /* << lob recycle page */
    uint32 ufp_count;      /* free pages left on current free extent */
    page_id_t ufp_first;   /* first free page */
    page_id_t ufp_extent;  /* first unused extent */
    knl_scn_t shrink_scn; /* lob shrink timestamp scn */
} lob_segment_t;

typedef struct st_lob_undo_alloc_page {
    page_id_t first_page;
    knl_scn_t ori_scn;
} lob_undo_alloc_page_t;
typedef struct st_lob_temp_undo_alloc_page {
    page_id_t first_page;
    uint32    lob_segid;
    knl_scn_t ori_scn;
    knl_scn_t seg_scn;
    uint32 uid;
    uint32 table_id;
} lob_temp_undo_alloc_page_t;
#pragma pack()
#ifdef __cplusplus
}
#endif

#endif
