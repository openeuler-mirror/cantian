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
 * knl_temp.h
 *
 *
 * IDENTIFICATION
 * src/kernel/table/knl_temp.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_TEMP_H__
#define __KNL_TEMP_H__

#include "cm_defs.h"
#include "cm_memory.h"
#include "knl_interface.h"
#include "knl_context.h"
#include "knl_session.h"
#include "knl_mtrl.h"
#include "knl_page.h"
#include "knl_heap.h"
#include "cm_row.h"
#include "cm_log.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef page_tail_t temp_page_tail_t;

#pragma pack(4)

typedef struct st_rd_temp_heap_insert {
    uint64 ssn;
    undo_page_id_t undo_page;
    uint16 undo_slot;
    uint8 new_dir;
    uint8 aligned;
} rd_temp_heap_insert_t;

typedef struct st_temp_heap_page {
    page_head_t head;
    map_index_t map;
    knl_scn_t org_scn;
    knl_scn_t seg_scn;
    uint32 oid;
    uint16 uid;
    uint16 first_free_dir;
    pagid_data_t next;  // next data page
    uint32 free_begin;
    uint32 free_end;
    uint32 free_size;
    uint16 rows;         // row count
    uint16 dirs;         // row directory count
    // ==== above aligned by 4 bytes ===
    uint8 itls;          // itl count
    uint8 reserved[15];  // reserved for extend
} temp_heap_page_t;

typedef struct st_temp_row_dir {
    union {
        struct {
            uint32 offset : 19;                  // offset of row
            uint32 is_owscn : 1;                 // txn scn overwrite or not
uint32 undo_slot : ROWID_SLOT_BITS;  // undo row index
        };
        struct {
            uint32 is_free : 1;     // directory free flag
            uint32 next_slot : 18;  // next free slot id
            uint32 aligned : 13;
        };
    };

    undo_page_id_t undo_page;
    knl_scn_t scn;  // sql sequence number(txn in progress) or commit scn
} temp_row_dir_t;

typedef struct st_temp_heap_extra_undo {
    uint32 uid;
    uint32 table_id;
    knl_scn_t seg_scn;
} temp_heap_extra_undo_t;

typedef struct st_temp_heap_binsert {
    temp_heap_extra_undo_t obj_info;
    uint16 count;
    uint16 begin_slot;
} temp_heap_undo_binsert_t;

typedef struct st_temp_undo_btreeb_insert {
    knl_scn_t seg_scn;
    uint16 count;
    uint16 aligned;
    char keys[0];
} temp_undo_btreeb_insert_t;

#pragma pack()

#define TEMP_PAGE_HEAD(page)    ((page_head_t *)(page))
#define TEMP_PAGE_TAIL(page)    ((temp_page_tail_t *)((char *)(page) + PAGE_SIZE(*(page)) - sizeof(temp_page_tail_t)))
#define TEMP_LOB_TO_CHAR_LENGTH GS_MAX_COLUMN_SIZE
#define FREE_LIST_GETIN_LIMIT   SIZE_K(8)
#define FREE_LIST_GETOUT_LIMIT  SIZE_K(1)
#define TEMP_ESTIMATE_ROW_SIZE_RATIO 0.01
#define TEMP_PAGE_SIZE GS_VMEM_PAGE_SIZE
#define TEMP_HEAP_CURR_PAGE(session)  ((temp_heap_page_t *)buf_curr_temp_page((session))->data)
#define TEMP_HEAP_GET_ROW(page, dir) (row_head_t *)((char *)(page) + (dir)->offset)

static inline temp_row_dir_t *temp_heap_get_dir(temp_heap_page_t *page, uint32 id)
{
    uint32 offset = (uint32)PAGE_SIZE(page->head) - sizeof(temp_page_tail_t);
    knl_panic(page->itls == 0 && id <= page->dirs);
    offset -= (id + 1) * sizeof(temp_row_dir_t);
    return (temp_row_dir_t *)((char *)(page) + offset);
}

#define CURSOR_TEMP_CACHE(cursor) ((knl_temp_cache_t *)((cursor)->temp_cache))
#define TEMP_ESTIMATE_TOTAL_ROW_SIZE(segment, table) \
    ((uint64)(segment)->vm_list.count * (TEMP_PAGE_SIZE - sizeof(temp_heap_page_t) - sizeof(temp_page_tail_t)) * \
        (100 - (table)->desc.pctfree))

void temp_page_init(knl_session_t *session, page_head_t *page, uint32 vmid, page_type_t type);
void temp_mtrl_init_context(knl_session_t *session);
void temp_mtrl_release_context(knl_session_t *session);
status_t temp_create_segment(knl_session_t *session, uint32 *id);
void temp_drop_segment(mtrl_context_t *ctx, uint32 id);
status_t temp_heap_create_segment(knl_session_t *session, knl_temp_cache_t *temp_table_ptr);
status_t temp_heap_fetch_by_rowid(knl_session_t *session, knl_cursor_t *cursor);
status_t temp_heap_delete(knl_session_t *session, knl_cursor_t *cursor);
status_t temp_heap_update(knl_session_t *session, knl_cursor_t *cursor);
status_t temp_heap_insert(knl_session_t *session, knl_cursor_t *cursor);
status_t temp_heap_fetch(knl_handle_t handle, knl_cursor_t *cursor);
status_t temp_heap_rowid_fetch(knl_handle_t session, knl_cursor_t *knl_cur);
void temp_heap_update_inpage(knl_session_t *session, row_head_t *ori_row, uint16 *offsets, uint16 *lens,
                             heap_update_assist_t *ua, temp_heap_page_t *page, uint16 slot);
void temp_heap_undo_batch_insert(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot);
void temp_heap_undo_insert(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot);
void temp_heap_undo_delete(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot);
void temp_heap_undo_update(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot);
status_t buf_enter_temp_page_nolock(knl_session_t *session, uint32 vmid);
void buf_leave_temp_page_nolock(knl_session_t *session, bool32 changed);
vm_page_t *buf_curr_temp_page(knl_session_t *session);
bool32 temp_rowid_valid(knl_handle_t session, const rowid_t *rid);
status_t temp_heap_lock_row(knl_session_t *session, knl_cursor_t *cursor, bool32 *is_locked);
bool32 knl_temp_object_isvalid_by_id(knl_session_t *session, uint32 uid, uint32 oid, knl_scn_t org_scn);
void temp_set_compative_config(bool8 is_compative_mysql);
bool8 temp_is_compative_mysql(void);
#ifdef __cplusplus
}
#endif

#endif
