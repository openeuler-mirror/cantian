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
 * knl_heap.h
 *
 *
 * IDENTIFICATION
 * src/kernel/table/knl_heap.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_HEAP_H__
#define __KNL_HEAP_H__

#include "knl_table_module.h"
#include "cm_defs.h"
#include "cm_row.h"
#include "knl_index.h"
#include "knl_lock.h"
#include "knl_map.h"
#include "knl_page.h"
#include "knl_session.h"
#include "knl_tran.h"
#include "knl_undo.h"
#include "rb_purge.h"
#include "knl_common.h"
#include "knl_shrink.h"
#include "knl_heap_persistent.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HEAP_MIGRATE_OVERHEAD_SIZE       (sizeof(rowid_t))
#define ROW_COL_BITARR_NULL              0x00
#define ROW_COL_BITARR_UINT32            0x01
#define ROW_COL_BITARR_UINT64            0x02
#define ROW_COL_BITARR_VARIA             0x03
#define ROW_COL_BITARR_SIZE(col_count)   (CM_ALIGN16((col_count)) >> 2)
#define ROW_COL_BITARR_BITS              ((uint8)2)
#define ROW_COL_BITARR_ALIGN_SIZE        ((int8)32)
#define ROW_COL_BITARR_MASK              ((int8)0x03)
#define ROW_COL_BITS_PER_BYTE            ((int8)8)
#define ROW_COL_SHIFT_PER_BYTE           ((int16)4)
#define ROW_COL_HEADER_LEN               ((int16)2)
#define KEY_HEADER_ALIGN                 ((int16)4)
#define ROW_COL_SHIFT_DIV_8              ((int16)3)
#define ROW_COL_SHIFT_IN_BYTE(col_id)    ((uint16)(((col_id)&0x03) << 1))
#define GET_COL_MASK(idx)                ((uint8)(((uint32)0x03 << (idx)) << (idx)))
#define ROW_GET_ALIGN_SIZE(size)         (((size) + ROW_COL_HEADER_LEN + 3) & 0xfffc)
#define HEAP_UPDATE_INPAGE_SIZE(cols) \
    (sizeof(rd_heap_update_inpage_t) + CM_ALIGN4(sizeof(uint16) * (cols)))
#define HEAP_UNDO_UPDATE_INFO_SIZE(cols) \
    (sizeof(heap_undo_update_info_t) + CM_ALIGN4(sizeof(uint16) * (cols)))
#define LOGIC_REP_DB_ENABLED(s)          ((s)->kernel->db.ctrl.core.lrep_mode == LOG_REPLICATION_ON)
#define LOGIC_REP_TABLE_ENABLED(s, e)    (((e)->lrep_info.status == LOGICREP_STATUS_ON) && !(s)->rm->is_ddl_op)
#define LOGIC_REP_PART_ENABLED(p)        ((p)->desc.lrep_status == PART_LOGICREP_STATUS_ON)

/* lock row status type */
typedef enum en_lock_row_status {
    ROW_IS_LOCKABLE = 0, /* row is lockable */
    ROW_IS_DELETED = 1,  /* row is deleted, skip */
    ROW_IS_CHANGED = 2,  /* row has changed, need re-read */
    ROW_IS_LOCKED = 3,   /* row is locked successfully */
} lock_row_status_t;

#define HEAP_NO_FREE_DIR 0x7FFF

typedef struct st_ref_cons {
    spinlock_t lock;
    volatile knl_handle_t ref_entity;
    uint16 *cols;
    uint32 col_count;
    uint32 ref_uid;
    uint32 ref_oid;
    uint16 ref_ix;
    uint16 matched_ix;
    knl_refactor_t refactor;
    knl_constraint_state_t cons_state;
    uint32 cons_id;
} ref_cons_t;

typedef struct st_check_cons {
    uint16 *cols;
    uint32 col_count;
    text_t check_text;    // raw cond text
    binary_t check_data;  // compiled and serialized cond
    void *condition;      // cond expr
    knl_constraint_state_t cons_state;
} check_cons_t;

typedef struct st_cons_set {
    check_cons_t *check_cons[CT_MAX_CONSTRAINTS];
    ref_cons_t *ref_cons[CT_MAX_CONSTRAINTS];
    uint32 check_count;
    uint32 ref_count;
    bool32 referenced;
    uint32 max_ref_id;
} cons_set_t;

typedef struct st_shadow_index {
    volatile bool32 is_valid;
    knl_part_locate_t part_loc;
    union {
        index_t index;
        index_part_t index_part;
    };
} shadow_index_t;

typedef status_t (*heap_add_update_info_t)(knl_session_t *session, knl_cursor_t *cursor,
    row_assist_t *ra, uint32 col_id);

#define SHADOW_INDEX_ENTITY(shadow) \
    ((shadow)->part_loc.part_no == CT_INVALID_ID32 ? &(shadow)->index : (shadow)->index_part.btree.index)
#define SHADOW_INDEX_IS_PART(shadow) ((shadow)->part_loc.part_no != CT_INVALID_ID32)

typedef struct st_table {
    knl_table_desc_t desc;        /* < table description */
    index_set_t index_set;        /* < index set */
    cons_set_t cons_set;          /* < constraints on this table */
    policy_set_t policy_set;      /* < policies on this table */
    shadow_index_t *shadow_index; /* < index which is creating or rebuilding online */
    union {
        heap_t heap; /* < table storage entity */
    };
    struct st_part_table *part_table; /* < partition table info */
#ifdef Z_SHARDING
    routing_info_t routing_info;
#endif
    struct st_table_accessor *acsor; /* < table access method */
    volatile uint8 ashrink_stat;
} table_t;

#define IS_PART_TABLE(table)    (((table_t *)(table))->desc.parted)
#define TABLE_GET_PART(table, part_no) PART_GET_ENTITY(((table_t *)(table))->part_table, part_no)
#define IS_TEMP_TABLE_BY_DC(dc) ((dc)->type == DICT_TYPE_TEMP_TABLE_TRANS || (dc)->type == DICT_TYPE_TEMP_TABLE_SESSION)

static inline heap_t *knl_cursor_heap(knl_cursor_t *cursor)
{
    table_t *table = (table_t *)cursor->table;

    if (IS_PART_TABLE(table)) {
        return &((table_part_t *)cursor->table_part)->heap;
    }

    return &table->heap;
}

#define CURSOR_HEAP(cursor) knl_cursor_heap(cursor)

/* if the column value is zero with decimal type in a csf format row */
#define CSF_IS_DECIMAL_ZERO(is_csf, len, type) \
    ((is_csf) && ((len) == 0) && (CT_IS_NUMBER_TYPE(type)))
typedef enum en_heap_update_mode {
    UPDATE_INPLACE = 1,  // column size not changed
    UPDATE_INPAGE = 2,   // current page space is enough
    UPDATE_MIGR = 3,     // need migrate row to another page
} heap_update_mode_t;

// update assist information
typedef struct st_heap_update_assist {
    rowid_t rowid;    // rowid of current update row
    row_head_t *row;  // point to cursor row or temp row buffer
    uint16 *offsets;  // for decoding ori_row
    uint16 *lens;     // for decoding ori_row

    uint16 data_size;  // row data size
    uint16 undo_size;  // undo data size
    int32 inc_size;    // row increased size (not data size)
    uint32 new_size;   // row new size

    uint16 old_cols;  // old column count
    uint16 new_cols;  // new column count

    heap_update_mode_t mode;  // in place, in row, in page, migration
    knl_update_info_t *info;  // information of updating, from sql
} heap_update_assist_t;

typedef struct st_heap_undo_update_info {
    uint16 old_cols;  // old column count
    uint16 count;     // update columns
    uint16 columns[0];  // following is column data before update
} heap_undo_update_info_t;

typedef struct st_chain_row_assist {
    row_head_t *row;  // include link_rid
    rowid_t rid;
    rowid_t owner_rid;
    uint16 col_id;
    uint16 column_count;
} chain_row_assist_t;

typedef struct st_row_chain {
    rowid_t chain_rid;
    rowid_t next_rid;
    rowid_t owner_rid;
    uint16 col_start;
    uint16 col_count;
    uint16 data_size;
    uint16 row_size;
} row_chain_t;

typedef struct st_row_chains_info {
    row_chain_t chains[1];
} row_chains_info_t;

typedef struct st_heap_compact_def {
    uint32 percent;
    uint32 timeout;
    date_t end_time;
} heap_cmp_def_t;

#define HEAP_SEG_HEAD(session)          (heap_segment_t *)((session)->curr_page + PAGE_HEAD_SIZE)
#define HEAP_SEG_DATA(heap)    ((char *)(heap)->segment)
#define HEAP_SEG_SIZE          (sizeof(heap_segment_t))
#define HEAP_MIN_ROW_SIZE      KNL_MIN_ROW_SIZE
#define HEAP_MIN_COST_SIZE     (HEAP_MIN_ROW_SIZE + sizeof(itl_t) + sizeof(row_dir_t))
#define HEAP_MAX_COST_SIZE(session)     (DEFAULT_PAGE_SIZE(session) - sizeof(heap_page_t) - sizeof(page_tail_t))
#define HEAP_MAX_MIGR_ROW_SIZE(session) (HEAP_MAX_COST_SIZE(session) - sizeof(row_dir_t) - sizeof(itl_t))
#define HEAP_MAX_ROW_SIZE(session)      \
    (HEAP_MAX_COST_SIZE(session) - sizeof(row_dir_t) - sizeof(itl_t) - sizeof(rowid_t))
#define HEAP_INSERT_MAX_CHAIN_COUNT 18

#define HEAP_MERGE_CHAIN_COUNT     (CT_MAX_CHAIN_COUNT - PCRH_INSERT_MAX_CHAIN_COUNT + 1)

#define HEAP_GET_ROW(page, dir)      (row_head_t *)((char *)(page) + (dir)->offset)
#define HEAP_ROW_DATA_OFFSET(row) \
    (cm_row_init_size((row)->is_csf, ROW_COLUMN_COUNT(row)) + ((row)->is_migr ? sizeof(rowid_t) : 0))
#define HEAP_LOC_CHAIN_ROW_DATA(row) ((char *)(row) + HEAP_ROW_DATA_OFFSET(row))
#define HEAP_LOC_LINK_RID(row) \
    (rowid_t *)((char *)(row) + ((!((row)->is_migr) && !((row)->is_csf)) ? \
    (sizeof(row_head_t)) : (cm_row_init_size((row)->is_csf, ROW_COLUMN_COUNT(row)))))
#define HEAP_SET_LINK_RID(row, rid)  (*(uint64 *)HEAP_LOC_LINK_RID(row) = (rid))
#define HEAP_COPY_ROW(session, cursor, row)                                                         \
    do {                                                                                   \
        if ((row)->is_link && !(row)->is_deleted) {                                        \
            (cursor)->link_rid = *(rowid_t *)((char *)(row) + ((!((row)->is_csf)) ? \
                (sizeof(row_head_t)) : (cm_row_init_size((row)->is_csf, ROW_COLUMN_COUNT(row)))));         \
            *((cursor)->row) = *(row);                                                     \
        } else {                                                                           \
            errno_t ret = memcpy_sp((cursor)->row, DEFAULT_PAGE_SIZE(session), (row), (row)->size); \
            knl_securec_check(ret);                                                        \
        }                                                                                  \
    } while (0)
#define IS_LAST_CHAIN_ROW(row)             ((*(uint64 *)(HEAP_LOC_LINK_RID(row)) == CT_INVALID_ID64))
#define HEAP_GET_EXT_LINK(chains_info, id) (row_chain_t *)(((row_chains_info_t *)(chains_info))->chains + (id))
#define IS_DUAL_TABLE(tab)                 ((tab)->desc.uid == 0 && (tab)->desc.id == DUAL_ID)
#define HEAP_SEGMENT(session, pageid, segment) \
    ((buf_check_resident_page_version((session), (pageid))) ? ((heap_segment_t *)(segment)) : ((heap_segment_t *)(segment)))

/*
 * rowid_count is not 0 means rowid scan
 * for rowid scan, maybe cursor->rowid is from another table and cause check page fail
 * for rowid scan check page fail, INVALID ROWID error message should be thrown
 */
#define HEAP_CHECKPAGE_ERROR(cursor)                                                           \
    do {                                                                                       \
        if ((cursor)->page_soft_damaged) {                                                     \
            CT_THROW_ERROR(ERR_PAGE_SOFT_DAMAGED, (cursor)->rowid.file, (cursor)->rowid.page); \
        } else if ((cursor)->rowid_count == 0) {                                               \
            CT_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, "table");                               \
        } else {                                                                               \
            knl_panic_log(0, "HEAP_CHECKPAGE_ERROR");                                          \
            CT_THROW_ERROR(ERR_INVALID_ROWID);                                                 \
        }                                                                                      \
    } while (0)


typedef struct st_heap_undo_assist {
    heap_t *heap;
    uint32 rows;
    uint32 need_latch;
    uint8 change_list[HEAP_INSERT_MAX_CHAIN_COUNT + 1];
    page_id_t page_id[HEAP_INSERT_MAX_CHAIN_COUNT + 1];
} heap_undo_assist_t;
#define ACTUAL_COLUMN_SIZE(len, bits) ((int16) CM_ALIGN4(((bits) == COL_BITS_VAR) ? (len) + sizeof(uint16) : (len)))

typedef uint16 (*knl_cal_col_size_t)(row_head_t *row, uint16 *lens, uint16 col_id);
typedef void (*knl_update_inplace_column_t)(row_head_t *row, uint16 col_id, uint16 *offsets, uint16 *lens,
    knl_update_info_t *ua_info, uint16 update_col_id);
typedef void (*knl_put_row_column_t)(row_head_t *src_row, uint16 *src_offsets, uint16 *src_lens,
    uint16 col_id, row_assist_t *dst_ra);
typedef uint16 (*knl_calc_row_head_inc_size_t)(uint32 new_count, uint32 old_count);

static inline void heap_put_csf_row_column(row_head_t *src_row, uint16 *src_offsets, uint16 *src_lens,
                                           uint16 col_id, row_assist_t *dst_ra)
{
    (void)csf_put_column_data(dst_ra, (char *)(src_row) + src_offsets[col_id], src_lens[col_id]);
}

static inline void heap_put_bmp_row_column(row_head_t *src_row, uint16 *src_offsets, uint16 *src_lens,
                                           uint16 col_id, row_assist_t *dst_ra)
{
    uint8 bits;

    bits = row_get_column_bits2(src_row, col_id);
    (void)bmp_put_column_data(dst_ra, bits, (char *)(src_row) + src_offsets[col_id], src_lens[col_id]);
}

static inline uint16 heap_calc_csf_col_actualsize(row_head_t *row, uint16 *lens, uint16 col_id)
{
    uint32 col_actual_size;

    if (lens[col_id] == CT_NULL_VALUE_LEN) {
        return 1;
    }
    col_actual_size = (lens[col_id] < CSF_VARLEN_EX) ?
        (lens[col_id] + CSF_SHORT_COL_DESC_LEN) : (lens[col_id] + CSF_LONG_COL_DESC_LEN);

    return col_actual_size;
}

static inline uint16 heap_calc_bmp_col_actualsize(row_head_t *row, uint16 *lens, uint16 col_id)
{
    uint8 bits;
    uint32 col_actual_size;

    bits = row_get_column_bits2(row, col_id);
    col_actual_size = ACTUAL_COLUMN_SIZE(lens[col_id], bits);

    return col_actual_size;
}

static inline uint16 heap_calc_csf_row_head_inc_size(uint32 new_count, uint32 old_count)
{
    return CSF_ROW_HEAD_SIZE(new_count) - CSF_ROW_HEAD_SIZE(old_count);
}

static inline uint16 heap_calc_bmp_row_head_inc_size(uint32 new_count, uint32 old_count)
{
    return COL_BITMAP_EX_SIZE(new_count) - COL_BITMAP_EX_SIZE(old_count);
}

status_t heap_create_entry(knl_session_t *session, heap_t *heap);
status_t heap_create_part_entry(knl_session_t *session, table_part_t *table_part, knl_part_locate_t part_loc);
status_t heap_create_segment(knl_session_t *session, table_t *table);
status_t heap_create_part_segment(knl_session_t *session, table_part_t *table_part);
void heap_drop_segment(knl_session_t *session, table_t *table);
void heap_drop_part_segment(knl_session_t *session, table_part_t *table_part);
void heap_truncate_segment(knl_session_t *session, knl_table_desc_t *desc, bool32 reuse_storage);
void heap_truncate_part_segment(knl_session_t *session, knl_table_part_desc_t *desc, bool32 reuse_storage);
status_t heap_purge_prepare(knl_session_t *session, knl_rb_desc_t *desc);
void heap_purge_segment(knl_session_t *session, knl_seg_desc_t *desc);
status_t heap_insert(knl_session_t *session, knl_cursor_t *cursor);
status_t heap_delete(knl_session_t *session, knl_cursor_t *cursor);
status_t heap_update(knl_session_t *session, knl_cursor_t *cursor);
status_t heap_prepare_update_overpart(knl_session_t *session, knl_cursor_t *cursor, row_head_t *new_row,
    knl_part_locate_t new_part_loc);
void heap_undo_insert(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot,
                      knl_dictionary_t *dc, heap_undo_assist_t *heap_assist);
void heap_undo_insert_migr(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot,
                           knl_dictionary_t *dc, heap_undo_assist_t *heap_assist);
void heap_undo_delete(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot);
void heap_undo_update(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot,
                      knl_dictionary_t *dc, heap_undo_assist_t *heap_assist);
void heap_undo_update_linkrid(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot);
void heap_undo_delete_migr(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot,
                           knl_dictionary_t *dc, heap_undo_assist_t *heap_assist);
status_t heap_fetch(knl_handle_t handle, knl_cursor_t *cursor);
status_t dual_fetch(knl_session_t *session, knl_cursor_t *cursor);
bool32 heap_check_page(knl_session_t *session, knl_cursor_t *cursor, heap_page_t *page, page_type_t type);
status_t heap_fetch_by_rowid(knl_handle_t handle, knl_cursor_t *cursor);
status_t heap_rowid_fetch(knl_handle_t session, knl_cursor_t *cursor);
status_t heap_try_tx_wait(knl_session_t *session, knl_cursor_t *cursor, bool32 *is_skipped);
status_t heap_lock_row(knl_session_t *session, knl_cursor_t *cursor, bool32 *is_locked);
void heap_clean_lock(knl_session_t *session, lock_item_t *item);
status_t heap_dump_page(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump);
void heap_update_prepare(knl_session_t *session, row_head_t *row, uint16 *offsets, uint16 *lens, uint16 data_size,
                         heap_update_assist_t *ua);
status_t heap_convert_update(knl_session_t *session, knl_cursor_t *cursor, heap_update_assist_t *ua);
status_t heap_convert_insert(knl_session_t *session, knl_cursor_t *cursor, uint32 max_row_len);
void heap_get_update_undo_data(knl_session_t *session, heap_update_assist_t *ua, undo_data_t *undo,
    uint32 undo_buf_size);
void heap_update_inplace(knl_session_t *session, uint16 *offsets, uint16 *lens, knl_update_info_t *ua_info,
                         row_head_t *row);
void heap_reorganize_with_update(row_head_t *row, uint16 *offsets, uint16 *lens,
                                 knl_update_info_t *info, row_assist_t *new_ra);
void heap_merge_chain_row(knl_cursor_t *cursor, row_head_t *row, uint16 col_id_input, uint16 data_size, uint16 *offset);
void heap_reorganize_chain_row(knl_session_t *session, knl_cursor_t *cursor, row_assist_t *ra, uint16 column_count);
void heap_update_serial(knl_session_t *session, heap_t *heap, uint64 value);
void heap_increase_serial(knl_session_t *session, heap_t *heap);
status_t heap_shrink_compact(knl_session_t *session, knl_dictionary_t *dc, knl_part_locate_t part_loc,
    bool32 shrink_hwm, heap_cmp_def_t def);
status_t heap_shrink_compart_compact(knl_session_t *session, knl_dictionary_t *dc, knl_part_locate_t part_loc,
    bool32 shrink_hwm, heap_cmp_def_t def);
status_t heap_shrink_spaces(knl_session_t *session, knl_dictionary_t *dc, bool32 async_shrink);
void heap_append_logic_data(knl_session_t *session, knl_cursor_t *cursor, bool32 cond_need);
void heap_ashrink_update_hwms(knl_session_t *session, knl_dictionary_t *dc,
    knl_part_locate_t part_loc, bool32 *has_valid_hwm);
#ifdef LOG_DIAG
void heap_validate_page(knl_session_t *session, page_head_t *page);
void heap_validate_map(knl_session_t *session, page_head_t *page);
#endif
status_t heap_reorganize_update_info(knl_session_t *session, knl_cursor_t *cursor,
                                     knl_add_update_column_t *add_update_column, heap_add_update_info_t add_func);
bool32 heap_check_deleted_column(knl_cursor_t *cursor, knl_update_info_t *info, row_head_t *row, uint16 *lens);
status_t heap_reorganize_del_column_update_info(knl_session_t *session, knl_cursor_t *cursor,
                                                knl_update_info_t *old_info, knl_update_info_t *new_info);
char *heap_get_col_start(row_head_t *row, uint16 *offsets, uint16 *lens, uint16 col_id);
uint32 heap_table_max_row_len(knl_handle_t handle, uint32 max_col_size, knl_part_locate_t part_loc);
void heap_write_col_size(bool32 is_csf, char *col_start, uint32 col_size);

uint8 heap_new_itl(knl_session_t *session, heap_page_t *page);
void heap_reuse_itl(knl_session_t *session, heap_page_t *page, itl_t *itl, uint8 itl_id);
void heap_insert_into_page(knl_session_t *session, heap_page_t *page, row_head_t *row,
                           undo_data_t *undo, rd_heap_insert_t *rd, uint16 *slot);
void heap_remove_cached_pages(knl_session_t *session, heap_segment_t *segment);
void heap_update_inpage(knl_session_t *session, row_head_t *ori_row, uint16 *offsets, uint16 *lens,
                        heap_update_assist_t *ua, heap_page_t *page, uint16 slot);
void heap_insert_into_page_migr(knl_session_t *session, heap_page_t *page, row_head_t *row,
                                rd_heap_insert_t *rd, uint16 *slot);
void heap_revert_update(knl_session_t *session, heap_undo_update_info_t *undo_info, row_head_t *row,
                        uint16 *offsets, uint16 *lens);
void heap_undo_update_full(knl_session_t *session, row_head_t *row, row_head_t *ud_data, uint32 row_offset);
bool32 heap_use_appendonly(knl_session_t *session, knl_cursor_t *cursor, heap_segment_t *segment);
bool32 heap_cached_invalid(knl_session_t *session, knl_cursor_t *cursor);
void heap_cleanout_page(knl_session_t *session, knl_cursor_t *cursor, page_id_t page_id, bool32 is_pcr);
status_t heap_check_page_belong_table(knl_session_t *session, heap_page_t *page, uint32 uid, uint32 table_id,
                                      bool32 *belong);

status_t heap_table_corruption_verify(knl_session_t *session, knl_dictionary_t *dc, knl_corrupt_info_t *corrupt_info);
status_t heap_page_corruption_scan(knl_session_t *session, heap_segment_t *segment, knl_corrupt_info_t *corrupt_info);
void heap_set_initrans(knl_session_t *session, heap_t *heap, uint32 initrans);

void heap_set_compact_hwm(knl_session_t *session, heap_t *heap, page_id_t cmp_hwm);

static inline row_dir_t *heap_get_dir(heap_page_t *page, uint32 id)
{
    uint32 offset = (uint32)PAGE_SIZE(page->head) - sizeof(page_tail_t);
    offset -= page->itls * sizeof(itl_t);
    offset -= (id + 1) * sizeof(row_dir_t);
    return (row_dir_t *)((char *)(page) + offset);
}

static inline itl_t *heap_get_itl(heap_page_t *page, uint8 id)
{
    uint32 offset = (uint32)PAGE_SIZE(page->head) - sizeof(page_tail_t);
    knl_panic(id < page->itls);
    offset -= (id + 1) * sizeof(itl_t);
    return (itl_t *)((char *)(page) + offset);
}

static inline uint8 page_size_units(uint32 size)
{
    return (uint8)(size / CT_PAGE_UNIT_SIZE);
}

#ifdef __cplusplus
}
#endif

#endif

