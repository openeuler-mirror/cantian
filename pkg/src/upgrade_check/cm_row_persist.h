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
 * cm_row_persist.h
 *
 *
 * IDENTIFICATION
 * src/upgrade_check/cm_row_persist.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_ROW_PERSIST_H__
#define __CM_ROW_PERSIST_H__
 
#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(4)

#define NON_CSF_BITMAP_SIZE 3

// row format
typedef struct st_row_head {
    union {
        struct {
            uint16 size;               // row size, must be the first member variable in row_head_t
            uint16 column_count : 10;  // column count
            uint16 flags : 6;          // total flags
        };

        struct {
            uint16 aligned1;        // aligned row size
            uint16 aligned2 : 10;   // aligned column_count
            uint16 is_deleted : 1;  // deleted flag
            uint16 is_link : 1;     // link flag
            uint16 is_migr : 1;     // migration flag
            uint16 self_chg : 1;    // statement self changed flag for PCR
            uint16 is_changed : 1;  // changed flag after be locked
            uint16 is_csf : 1;      // CSF(Compact Stream Format)
        };
    };

    union {
        struct {
            uint16 sprs_count;     // sparse column count
            uint8 sprs_itl_id;     // sparse itl_id;
            uint8 sprs_bitmap[1];  // sparse bitmap
        };

        struct {
            uint8 itl_id;                       // row itl_id
            uint8 bitmap[NON_CSF_BITMAP_SIZE];  // bitmap is no used for CSF
        };
    };
} row_head_t;  // following is bitmap of column
#pragma pack()

#ifdef __cplusplus
}
#endif
 
#endif