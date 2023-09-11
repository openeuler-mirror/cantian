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
 * pcr_heap_undo.h
 *
 *
 * IDENTIFICATION
 * src/kernel/table/pcr_heap_undo.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PCR_HEAP_UNDO_H__
#define __PCR_HEAP_UNDO_H__

#include "cm_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

void pcrh_undo_ins(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot);
void pcrh_undo_batch_ins(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot);
void pcrh_undo_del(knl_session_t *ession, undo_row_t *ud_row, undo_page_t *ud_page, int32 slot);
void pcrh_undo_upd(knl_session_t *ession, undo_row_t *ud_row, undo_page_t *ud_page, int32 slot);
void pcrh_undo_upd_link_ssn(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot);
void pcrh_undo_upd_next_rowid(knl_session_t *ession, undo_row_t *ud_row, undo_page_t *ud_page, int32 slot);
void pcrh_ud_itl(knl_session_t *ession, undo_row_t *ud_row, undo_page_t *ud_page, int32 slot,
                   knl_dictionary_t *dc, heap_undo_assist_t *heap_assist);
status_t pcrh_reorganize_with_ud_list(knl_session_t *session, cr_cursor_t *cursor, heap_page_t *page, bool8 *fb_buf);
#ifdef __cplusplus
}
#endif

#endif

