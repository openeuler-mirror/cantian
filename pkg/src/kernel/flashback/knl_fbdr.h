/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * knl_fbdr.h
 *
 *
 * IDENTIFICATION
 * src/kernel/flashback/knl_fbdr.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __KNL_FBDR_H__
#define __KNL_FBDR_H__

#include "knl_interface.h"

typedef struct st_fbdr_handler {
    knl_session_t   *session;
    knl_cursor_t    *cursor;
    knl_scn_t        fbdr_scn;      // scn of flashback to
    knl_scn_t        prev_undo_scn; // undo is overwritten if scn of next undo row larger than current
    rowid_t          undo_rid;      // current undo row
    page_id_t        pagid;         // current heap page id
    knl_scn_t        org_scn;       // for judging if the heap page is reused
    uint32           uid;           // for judging if the heap page is reused
    uint32           oid;           // for judging if the heap page is reused
    page_type_t      page_type;     // for judging if the heap page is reused
    undo_type_t      undo_type;
    uint16           slot;          // current row slot, for RCR
    uint8            itl_id;        // current itl, for PCR
    uint8            unused;
} fbdr_handler_t;

status_t fbdr_prepare(fbdr_handler_t *handler, const text_t *user, const text_t *table_name);
status_t fbdr_fetch(fbdr_handler_t *handler);

#endif
