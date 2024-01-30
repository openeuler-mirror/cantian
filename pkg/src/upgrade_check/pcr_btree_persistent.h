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
 * pcr_btree_persistent.h
 *
 *
 * IDENTIFICATION
 * src/upgrade_check/pcr_btree_persistent.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_BTREE_PERSIST_H__
#define __KNL_BTREE_PERSIST_H__

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(4)
/* PCR btree key structure */
typedef struct st_pcrb_key {
    union {
        rowid_t rowid;
        struct {
            uint64 aligned : ROWID_VALUE_BITS;
            uint64 size : ROWID_UNUSED_BITS;
        };
    };

    uint8 is_deleted : 1;
    uint8 is_infinite : 1;
    uint8 is_cleaned : 1;
    uint8 unused : 5;
    uint8 itl_id;
    uint16 bitmap;
    /* === following is key data === */
    /* === child(branch) or part_no(global index)=== */
} pcrb_key_t;

typedef struct st_rd_pcrb_insert {
    uint32 ssn;
    undo_page_id_t undo_page;
    uint16 undo_slot;
    uint16 slot : 15;
    uint16 is_reuse : 1;
    char key[4];
} rd_pcrb_insert_t;

typedef struct st_rd_pcrb_delete {
    uint32 ssn;
    undo_page_id_t undo_page;
    uint16 undo_slot;
    uint16 slot;
    uint8 itl_id;
    uint8 unused1;
    uint16 unused2;
} rd_pcrb_delete_t;

typedef struct st_rd_pcrb_clean_itl {
    knl_scn_t scn;
    uint8 itl_id;
    uint8 is_owscn;
    uint8 is_copied;
    uint8 aligned;
} rd_pcrb_clean_itl_t;

typedef struct st_rd_pcrb_new_itl {
    uint32 ssn;
    xid_t xid;
    undo_rowid_t undo_rid;
} rd_pcrb_new_itl_t;

typedef struct st_rd_pcrb_reuse_itl {
    knl_scn_t min_scn;
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
} rd_pcrb_reuse_itl_t;

typedef struct st_rd_pcrb_undo {
    uint32 ssn;
    undo_page_id_t undo_page;
    uint16 undo_slot : 15;
    uint16 is_xfirst : 1;
    uint16 slot;
} rd_pcrb_undo_t;

typedef struct st_pcrb_undo_batch_insert {
    knl_part_locate_t part_loc;
    uint16 count;
    uint16 aligned;
    char keys[0];
}pcrb_undo_batch_insert_t;
#pragma pack()

#ifdef __cplusplus
}
#endif

#endif