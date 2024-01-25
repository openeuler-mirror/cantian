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
 * pcr_heap_persistent.h
 *
 *
 * IDENTIFICATION
 * src/upgrade_check/pcr_heap_persistent.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PCR_HEAP_PERSISTENT_H__
#define __PCR_HEAP_PERSISTENT_H__

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(4)
typedef struct st_pcrh_undo_itl {
    xid_t xid;
    knl_part_locate_t part_loc;
} pcrh_undo_itl_t;

typedef struct st_rd_pcrh_clean_itl {
    knl_scn_t scn;
    uint8 itl_id;
    uint8 is_owscn;
    uint8 is_fast;
    uint8 aligned;
} rd_pcrh_clean_itl_t;

typedef struct st_rd_pcrh_new_itl {
    uint32 ssn;
    xid_t xid;
    undo_rowid_t undo_rid;
} rd_pcrh_new_itl_t;

typedef struct st_rd_pcrh_reuse_itl {
    uint32 ssn;
    xid_t xid;
    union {
        undo_rowid_t undo_rid;
        struct {
            undo_page_id_t page_id;
            uint16 slot;
            uint16 itl_id;
        };
    };
} rd_pcrh_reuse_itl_t;

typedef struct st_rd_pcrh_insert {
    uint32 ssn;
    undo_page_id_t undo_page;
    uint16 undo_slot;
    uint8  new_dir;
    uint8 aligned;
    char data[4];
} rd_pcrh_insert_t;

typedef struct st_rd_prch_lock_row {
    uint16 slot;
    uint8 itl_id;
    uint8 aligned;
} rd_pcrh_lock_row_t;

typedef struct st_rd_pcrh_update_link_ssn {
    uint32 ssn;
    undo_page_id_t undo_page;
    uint16 undo_slot;
    uint16 slot;
} pcrh_update_link_ssn_t;

typedef struct st_rd_pcrh_delete {
    uint32 ssn;
    undo_page_id_t undo_page;
    uint16 undo_slot;
    uint16 slot;
} rd_pcrh_delete_t;

typedef struct st_rd_pcrh_set_next_rid {
    uint32 ssn;
    undo_page_id_t undo_page;
    uint16 undo_slot;
    uint16 slot;
    rowid_t next_rid;
} pcrh_set_next_rid_t;

typedef struct st_rd_pcrh_update_inplace {
    uint32 ssn;
    undo_page_id_t undo_page;
    uint16 undo_slot;
    uint16 slot;
    uint16 count; /* < update columns */
    uint16 aligned;
    /* ==== above aligned by 4 bytes === */
    uint16 columns[0]; /* < following is update column data */
} rd_pcrh_update_inplace_t;

typedef struct st_rd_pcrh_update_inpage {
    uint32 ssn;
    undo_page_id_t undo_page;
    uint16 undo_slot;
    uint16 slot;
    uint16 new_cols; /* < new columns */
    int16 inc_size;
    uint16 count; /* < update columns */
    uint16 aligned;
    /* ==== above aligned by 4 bytes === */
    uint16 columns[0]; /* < following is update column data */
} rd_pcrh_update_inpage_t;

typedef struct st_rd_pcrh_undo_update {
    uint32 ssn;
    undo_page_id_t undo_page;
    uint16 undo_slot;
    uint16 slot;
    uint8 is_xfirst;
    uint8 type;
    uint16 aligned;
} rd_pcrh_undo_update_t;

typedef struct st_rd_pcrh_undo {
    uint32 ssn;
    undo_page_id_t undo_page;
    uint16 slot;
    uint16 undo_slot : 15;
    uint16 is_xfirst : 1;
} rd_pcrh_undo_t;

typedef struct st_pcrh_batch_undo {
    uint16 slot : 15;
    uint16 is_xfirst : 1;
} pcrh_batch_undo_t;

typedef struct st_pcrh_undo_batch_insert {
    uint16 count;
    uint16 aligned;
    pcrh_batch_undo_t undos[0];
} pcrh_undo_batch_insert_t;
#pragma pack()

#ifdef __cplusplus
}
#endif

#endif