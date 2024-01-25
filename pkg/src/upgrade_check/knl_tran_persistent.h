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
 * knl_tran_persistent.h
 *
 *
 * IDENTIFICATION
 * src/upgrade_check/knl_tran_persistent.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_TRAN_PERSISTENT_H__
#define __KNL_TRAN_PERSISTENT_H__

#pragma pack(4)
typedef struct st_itl {
    knl_scn_t scn;  // commit scn
    xid_t xid;      // txn id
    uint16 fsc;     // free space credit (bytes)

    uint16 is_active : 1;  // committed or not
    uint16 is_owscn : 1;   // txn scn overwrite or not
    uint16 is_copied : 1;  // itl is copied or not
    uint16 unused : 13;    // unused flags
} itl_t;

typedef struct st_pcr_itl {
    union {
        knl_scn_t scn;  // commit scn

        struct {
            uint32 ssn;      // txn ssn
            uint16 fsc;      // free space credit (bytes)
            uint16 aligned;  // aligned
        };
    };

    xid_t xid;                 // txn id
    undo_page_id_t undo_page;  // undo page for current transaction

    union {
        struct {
            uint16 undo_slot;  // undo slot
            uint16 flags;
        };
        struct {
            uint16 aligned1;
            uint16 is_active : 1;  // committed or not
            uint16 is_owscn : 1;   // txn scn overwrite or not
            uint16 is_copied : 1;  // itl is copied or not
            uint16 is_hist : 1;    // itl is historical or not (used in CR rollback)
            uint16 is_fast : 1;    // itl is fast committed or not
            uint16 unused : 11;
        };
    };
} pcr_itl_t;

typedef struct st_rd_tx_end {
    knl_scn_t scn;
    xmap_t xmap;
    uint8 is_auton;   // if is autonomous transaction
    uint8 is_commit;  // if is commit
    uint16 aligned;
} rd_tx_end_t;
#pragma pack()

#endif