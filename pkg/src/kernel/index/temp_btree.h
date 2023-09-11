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
 * temp_btree.h
 *
 *
 * IDENTIFICATION
 * src/kernel/index/temp_btree.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __TEMP_BTREE_H__
#define __TEMP_BTREE_H__

#include "knl_temp.h"
#include "rcr_btree_scan.h"


#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(4)

typedef struct st_rd_temp_btree_delete {
    uint64 ssn;
    undo_page_id_t undo_page;
    uint16 undo_slot;
    uint16 slot;
    uint8 itl_id;
    uint8 aligned[7];
} rd_temp_btree_delete_t;

typedef struct st_temp_btree_page {
    page_head_t head;
    knl_scn_t seg_scn;  // it is also org_scn on temp btree

    uint16 is_recycled : 1;
    uint16 unused : 15;
    uint16 keys;

    pagid_data_t prev;
    uint8 level;
    uint8 itls;

    pagid_data_t next;
    uint32 free_begin;

    uint32 free_end;
    uint32 free_size;
    uint8 reserved[16];  // reserved for future use
} temp_btree_page_t;

typedef struct st_temp_btree_dir_t {
    uint32 offset;
    uint8 itl_id;
    uint8 unused[3];
} temp_btree_dir_t;
#pragma pack()

#define TEMP_BTREE_CURR_PAGE(session) ((temp_btree_page_t *)buf_curr_temp_page((session))->data)

#define TEMP_BTREE_ITL_ADDR(page) \
    ((itl_t *)((char *)(page) + (uint32)PAGE_SIZE((page)->head) - sizeof(temp_page_tail_t)))

#define TEMP_BTREE_GET_DIR(page, pos) \
    ((temp_btree_dir_t *)((char *)(TEMP_BTREE_ITL_ADDR(page)) - ((pos) + 1) * sizeof(temp_btree_dir_t)))

#define TEMP_BTREE_GET_KEY(page, dir) \
    ((btree_key_t *)((char *)(page) + ((dir)->offset)))

#define TEMP_BTREE_COST_SIZE(key) \
    (((uint16)(key)->size) + sizeof(temp_btree_dir_t))

void temp_btree_init_page(knl_session_t *session, index_t *index, temp_btree_page_t *page,
                          uint32 vmid, uint32 level);
status_t temp_btree_create_segment(knl_session_t *session, index_t *index, knl_temp_cache_t *temp_table);
status_t temp_btree_fetch(knl_handle_t handle, knl_cursor_t *cursor);
status_t temp_btree_insert(knl_session_t *session, knl_cursor_t *cursor);
status_t temp_btree_batch_insert(knl_session_t *session, knl_cursor_t *cursor);
status_t temp_btree_delete(knl_session_t *session, knl_cursor_t *cursor);
status_t temp_db_fill_index(knl_session_t *session, knl_cursor_t *cursor, index_t *index, uint32 paral_count);
void temp_btree_undo_insert(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot,
                            knl_dictionary_t *dc);
void temp_btree_undo_batch_insert(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot,
                                  knl_dictionary_t *dc);
void temp_btree_undo_delete(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot,
                            knl_dictionary_t *dc);
int32 temp_btree_cmp_rowid(btree_key_t *key1, btree_key_t *key2);

#ifdef __cplusplus
}
#endif

#endif
