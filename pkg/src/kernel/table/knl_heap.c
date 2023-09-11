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
 * knl_heap.c
 *
 *
 * IDENTIFICATION
 * src/kernel/table/knl_heap.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_heap.h"
#include "cm_utils.h"
#include "knl_table.h"
#include "knl_context.h"
#include "pcr_heap.h"
#include "dc_part.h"
#include "dc_subpart.h"
#include "dc_tbl.h"
#include "knl_lob.h"
#include "knl_sys_part_defs.h"
#include "dtc_dls.h"

typedef struct st_split_assist {
    heap_update_assist_t *ua;
    row_head_t *org_row;
    uint16 *lens;
    uint16 *offsets;
    uint16 col_start[HEAP_INSERT_MAX_CHAIN_COUNT + 1];
    uint16 uid_start[HEAP_INSERT_MAX_CHAIN_COUNT + 1];
    uint16 reserve_size;
    uint16 split_count;
} split_assist_t;

typedef struct st_query_snapshot_t {
    uint64 xid;
    rowid_t rowid;
    uint64 ssn;
    knl_scn_t scn;
    knl_scn_t query_scn;
    row_head_t *row;
    uint16 *lens;
    uint16 *offsets;
} query_snapshot_t;

typedef struct st_migr_row_assist {
    rowid_t owner_rid;
    rowid_t old_rid;
    rowid_t next_rid;
    rowid_t new_rid;
    undo_data_t *undo;
    uint16 col_start;
} migr_row_assist_t;

typedef struct st_shrink_pages {
    uint32 shrinked_pages;
    uint32 total_pages;
    uint32 chain_rows;
    uint32 wait_recycled_pages;
    bool32 row_chain_shrink;
    map_path_t path;
    page_id_t cmp_hwm;
} shrink_pages_t;

typedef struct st_shrink_page {
    uint32 shrinked_rows;
    bool32 is_shrinkable;
    page_id_t shrink_id;
} shrink_page_t;

#pragma pack(4)
typedef struct st_dual_row {
    row_head_t head;

    struct {
        uint16 len;
        char value[2];
    };
} dual_row_t;
#pragma pack()

dual_row_t g_dual_row = {
    { .size = 12, .column_count = 1, .flags = 0, .itl_id = GS_INVALID_ID8, .bitmap = { 0xFF, 0, 0 }},
    .len = 1, .value = { 'X', '\0' }
};

static status_t heap_read_by_rowid(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn,
                                   uint8 isolevel, bool32 *is_found);
static inline status_t heap_delete_row(knl_session_t *session, knl_cursor_t *cursor, rowid_t rowid, rowid_t lnk_rid,
                                       bool32 is_org, uint16 data_size, bool32 self_update_check);
static status_t heap_check_restart(knl_session_t *session, knl_cursor_t *cursor);

status_t heap_dump_page(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump)
{
    heap_page_t *page = (heap_page_t *)page_head;

    cm_dump(dump, "heap page information\n");
    cm_dump(dump, "\tmap index info: map %u-%u, lid %u, &lenth %u\n",
        (uint32)page->map.file, (uint32)page->map.page, (uint32)page->map.list_id, (uint32)page->map.slot);
    cm_dump(dump, "\ttable info: uid %u, oid %u, org_scn %llu, seg_scn %llu\n",
        page->uid, page->oid, page->org_scn, page->seg_scn);
    cm_dump(dump, "\tpage info: next_page %u-%u, free_begin %u, free_end %u, free_size %u, first_free_dir %u ",
        AS_PAGID_PTR(page->next)->file, AS_PAGID_PTR(page->next)->page, page->free_begin,
        page->free_end, page->free_size, page->first_free_dir);
    cm_dump(dump, "itls %u, dirs %u, rows %u\n", page->itls, page->dirs, page->rows);
    cm_dump(dump, "itl information on this page\n");

    CM_DUMP_WRITE_FILE(dump);

    for (uint8 slot_itl = 0; slot_itl < page->itls; slot_itl++) {
        itl_t *itl = heap_get_itl(page, slot_itl);
        cm_dump(dump, "\tslot: #%-3u", slot_itl);
        cm_dump(dump, "\tscn: %llu", itl->scn);
        cm_dump(dump, "\txmap: %u-%u", itl->xid.xmap.seg_id, itl->xid.xmap.slot);
        cm_dump(dump, "\txnum: %u", itl->xid.xnum);
        cm_dump(dump, "\tfsc: %u", itl->fsc);
        cm_dump(dump, "\tis_active: %u", itl->is_active);
        cm_dump(dump, "\tis_owscn: %u\n", itl->is_owscn);

        CM_DUMP_WRITE_FILE(dump);
    }

    cm_dump(dump, "row information on this page\n");

    for (uint16 slot_dir = 0; slot_dir < page->dirs; slot_dir++) {
        row_dir_t *dir = heap_get_dir(page, slot_dir);
        cm_dump(dump, "\tslot: #%-3u", slot_dir);
        cm_dump(dump, "\toffset: %-5u", dir->offset);
        cm_dump(dump, "\tscn: %llu", dir->scn);
        cm_dump(dump, "\tis_owscn: %u", dir->is_owscn);
        cm_dump(dump, "\tundo_page: %u-%u", dir->undo_page.file, dir->undo_page.page);
        cm_dump(dump, "\tundo_slot: %u", (uint16)dir->undo_slot);

        if (dir->is_free) {
            cm_dump(dump, "\t(free_dir)\n");
            CM_DUMP_WRITE_FILE(dump);
            continue;
        }

        row_head_t *row = HEAP_GET_ROW(page, dir);
        cm_dump(dump, "\tsize: %u", row->size);
        cm_dump(dump, "\tcols: %u", ROW_COLUMN_COUNT(row));
        cm_dump(dump, "\titl_id: %u", ROW_ITL_ID(row));
        cm_dump(dump, "\tdeleted/link/migr/self_chg/changed %u/%u/%u/%u/%u\n",
            row->is_deleted, row->is_link, row->is_migr, row->self_chg, row->is_changed);

        CM_DUMP_WRITE_FILE(dump);
    }
    return GS_SUCCESS;
}

static inline uint16 heap_calc_null_row_size(row_head_t *row)
{
    return row->is_csf ? (1) : (0);
}

char *heap_get_col_start(row_head_t *row, uint16 *offsets, uint16 *lens, uint16 col_id)
{
    char *copy_row_start = NULL;

    if (row->is_csf) {
        copy_row_start = (char *)((char *)row + offsets[col_id]);
        return (lens[col_id] < CSF_VARLEN_EX) ?
            ((char *)(copy_row_start - CSF_SHORT_COL_DESC_LEN)) : ((char *)(copy_row_start - CSF_LONG_COL_DESC_LEN));
    } else {
        return (char *)((char *)row + offsets[col_id] - sizeof(uint16));
    }
}

void heap_write_col_size(bool32 is_csf, char *col_start, uint32 col_size)
{
    uint16 *col_size_start = NULL;
    if (is_csf) {
        if (col_size < CSF_VARLEN_EX) {
            *col_start = col_size;
        } else {
            *col_start = CSF_VARLEN_EX;
            col_size_start = (uint16 *)(col_start + CSF_SHORT_COL_DESC_LEN);
            *col_size_start = col_size;
        }
    } else {
        col_size_start = (uint16 *)col_start;
        *col_size_start = col_size;
    }
}

static void heap_init_row(knl_session_t *session, row_assist_t *ra, char *buf, uint32 column_count,
    uint8 itl_id, uint16 flags)
{
    if (ra->is_csf) {
        csf_row_init(ra, buf, GS_MAX_ROW_SIZE, column_count);
        ra->head->flags = flags;
        ra->head->is_csf = 1;
    } else {
        row_init(ra, buf, GS_MAX_ROW_SIZE, column_count);
        ra->head->flags = flags;
        ra->head->is_csf = 0;
    }
    ROW_SET_ITL_ID(ra->head, itl_id);
}

static void heap_init_chain_row(knl_session_t *session, row_assist_t *ra, char *buf, uint32 column_count,
    uint8 itl_id, uint16 flags)
{
    if (ra->is_csf) {
        csf_row_init(ra, buf, GS_MAX_ROW_SIZE, column_count);
        ra->head->flags = flags;
        ra->head->is_csf = 1;
    } else {
        row_init(ra, buf, GS_MAX_ROW_SIZE, column_count);
        ra->head->flags = flags;
        ra->head->is_csf = 0;
    }
    ra->head->size += sizeof(rowid_t);  // the max value of ra->head->size is less than DEFAULT_PAGE_SIZE(8192)
    ROW_SET_ITL_ID(ra->head, itl_id);
    ra->head->is_migr = 1;

    *HEAP_LOC_LINK_RID(ra->head) = INVALID_ROWID;
}

/*
 * Compact deleted or free space after update migration, the algorithm is as follow:
 * 1.transfer row slot from row dir into row itself by swap row sprs_count and dir offset,
 *   so we can use row itself to locate its row dir.
 * 2.traverse row one by one, if row has been delete, compact it's space.
 * 3.restore the row sprs_count and dir offset after row compact.
 * we use sprs_count instead of column_count as a temp store, because column_count
 * is 10 bits, can only represent 1024 rows. When page is 32K, it's would out of bound.
 */
static void heap_compact_page(knl_session_t *session, heap_page_t *page)
{
    row_dir_t *dir = NULL;
    itl_t *itl = NULL;
    uint16 i;
    errno_t ret;
    uint16 row_size, copy_size;
    row_head_t *row = NULL;
    row_head_t *free_addr = NULL;
    space_t *space = SPACE_GET(session, DATAFILE_GET(session, AS_PAGID_PTR(page->head.id)->file)->space_id);

    for (i = 0; i < page->dirs; i++) {
        dir = heap_get_dir(page, i);
        if (dir->is_free) {
            continue;
        }

        row = HEAP_GET_ROW(page, dir);
        if (row->is_deleted) {
            knl_panic_log(ROW_ITL_ID(row) != GS_INVALID_ID8, "row_itl_id is invalid, panic info: page %u-%u type %u",
                          AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
            itl = heap_get_itl(page, ROW_ITL_ID(row));
            if (!itl->is_active) {
                ROW_SET_ITL_ID(row, GS_INVALID_ID8);
                dir->scn = itl->scn;
                dir->is_owscn = itl->is_owscn;
                dir->is_free = 1;
                dir->next_slot = page->first_free_dir;
                page->first_free_dir = i;
                continue;
            }
        }

        /*
         * the max page size is 32K(0x8000) which means the max row size in
         * page is less than 32K, and the row->size is 2bytes(max size 64K),
         * so we can temporarily use the high bits as compacting mask
         */
        knl_panic_log((row->size & ROW_COMPACTING_MASK) == 0,
                      "current row is compacting, panic info: page %u-%u type %u",
                      AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
        row->size |= ROW_COMPACTING_MASK;

        /*
         * temporarily save row slot to row->sprs_count, so
         * we can use row itself to find it's dir
         */
        dir->offset = row->sprs_count;
        row->sprs_count = i;
    }

    /* traverse row one by one from first row after heap page head */
    row = (row_head_t *)((char *)page + sizeof(heap_page_t) + space->ctrl->cipher_reserve_size);
    free_addr = row;

    while ((char *)row < (char *)page + page->free_begin) {
        if ((row->size & ROW_COMPACTING_MASK) == 0) {
            /* row has been deleted, compact it's space directly */
            row = (row_head_t *)((char *)row + row->size);
            continue;
        }

        /* don't clear the compacting mask here, just get the actual row size */
        row_size = (row->size & ~ROW_COMPACTING_MASK);

        knl_panic_log(row->sprs_count < page->dirs, "the count of sparse column is more than page's dirs, panic info: "
                      "page %u-%u type %u row's sprs_count %u page's dirs %u", AS_PAGID(page->head.id).file,
                      AS_PAGID(page->head.id).page, page->head.type, row->sprs_count, page->dirs);
        dir = heap_get_dir(page, row->sprs_count);

        /* move current row to the new compacted position */
        copy_size = (row->is_link) ? (uint16)HEAP_MIN_ROW_SIZE : row_size;
        if (row != free_addr && copy_size != 0) {
            ret = memmove_s(free_addr, copy_size, row, copy_size);
            knl_securec_check(ret);
        }

        /* restore the row and its dir */
        free_addr->size = copy_size;
        free_addr->sprs_count = (dir->offset);
        dir->offset = (uint16)((char *)free_addr - (char *)page);

        /* now, handle the next row */
        free_addr = (row_head_t *)((char *)free_addr + copy_size);
        row = (row_head_t *)((char *)row + row_size);
    }
    /*
     * reset the latest page free begin position
     * free_addr - page is less than DEFAULT_PAGE_SIZE(8192)
     */
    page->free_begin = (uint16)((char *)free_addr - (char *)page);
}

bool32 heap_check_page(knl_session_t *session, knl_cursor_t *cursor, heap_page_t *page, page_type_t type)
{
    // page type invalid
    if (SECUREC_UNLIKELY(page->head.type != type)) {
        return GS_FALSE;
    }

    table_t *table = (table_t *)cursor->table;
    space_t *space = SPACE_GET(session, table->desc.space_id);
    if (!spc_valid_space_object(session, space->ctrl->id)) {
        return GS_FALSE;
    }

    if (PAGE_IS_SOFT_DAMAGE((page_head_t*)page)) {
        cursor->page_soft_damaged = GS_TRUE;
        return GS_FALSE;
    }

    if (!IS_PART_TABLE(table)) {
        return (page->seg_scn == table->desc.seg_scn);
    }

    table_part_t *table_part = (table_part_t *)cursor->table_part;

    if (table_part != NULL && table_part->desc.org_scn == page->org_scn) {
        return (page->seg_scn == table_part->desc.seg_scn);
    }

    /* in case of global index scan, the cursor->table_part is null, we should reset it */
    if (!IS_COMPART_TABLE(table->part_table)) {
        table_part = dc_get_table_part(table->part_table, page->org_scn);
    } else {
        table_part = dc_get_table_subpart(table->part_table, page->org_scn);
    }

    if (table_part != NULL) {
        if (SECUREC_UNLIKELY(!table_part->heap.loaded)) {
            if (dc_load_table_part_segment(session, cursor->dc_entity, table_part) != GS_SUCCESS) {
                cm_reset_error();
                return GS_FALSE;
            }
        }

        if (page->seg_scn == table_part->desc.seg_scn) {
            if (IS_SUB_TABPART(&table_part->desc)) {
                table_part_t *compart = PART_GET_ENTITY(table->part_table, table_part->parent_partno);
                knl_panic_log(compart != NULL, "compart is NULL, panic info: page %u-%u type %u table %s",
                              cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                              ((table_t *)cursor->table)->desc.name);
                cursor->part_loc.part_no = compart->part_no;
                cursor->part_loc.subpart_no = table_part->part_no;
            } else {
                cursor->part_loc.part_no = table_part->part_no;
                cursor->part_loc.subpart_no = GS_INVALID_ID32;
            }
            cursor->table_part = table_part;
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

uint8 heap_new_itl(knl_session_t *session, heap_page_t *page)
{
    uint8 itl_id;
    errno_t ret;
    char *dst = NULL;
    char *src = NULL;

    if (page->itls == GS_MAX_TRANS || page->free_size < sizeof(itl_t)) {
        return GS_INVALID_ID8;
    }

    if (page->free_begin + sizeof(itl_t) > page->free_end) {
        heap_compact_page(session, page);
    }

    src = (char *)page + page->free_end;
    dst = src - sizeof(itl_t);

    if (page->dirs != 0) {
        ret = memmove_s(dst, page->dirs * sizeof(row_dir_t), src, page->dirs * sizeof(row_dir_t));
        knl_securec_check(ret);
    }

    itl_id = page->itls;
    page->itls++;
    /* free_end is larger than free_size, free size is larger than sizeof(itl_t) */
    page->free_end -= sizeof(itl_t);
    page->free_size -= sizeof(itl_t);

    return itl_id;
}

void heap_reuse_itl(knl_session_t *session, heap_page_t *page, itl_t *itl, uint8 itl_id)
{
    uint32 i;
    row_dir_t *dir = NULL;
    row_head_t *row = NULL;

    for (i = 0; i < page->dirs; i++) {
        dir = heap_get_dir(page, i);
        if (dir->is_free) {
            continue;
        }

        row = HEAP_GET_ROW(page, dir);
        if (ROW_ITL_ID(row) != itl_id) {
            continue;
        }

        ROW_SET_ITL_ID(row, GS_INVALID_ID8);
        if (!row->is_changed) {
            row->is_changed = 1;
            continue;
        }

        dir->scn = itl->scn;
        dir->is_owscn = itl->is_owscn;
        if (row->is_deleted) {
            dir->is_free = 1;
            dir->next_slot = page->first_free_dir;
            page->first_free_dir = i;
        }
    }
}

static status_t heap_get_reusable_itl(knl_session_t *session, knl_cursor_t *cursor, heap_page_t *page,
                                      itl_t **itl, bool32 *changed)
{
    itl_t *item = NULL;
    txn_info_t txn_info;
    rd_heap_clean_itl_t rd_clean;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);

    for (uint8 i = 0; i < page->itls; i++) {
        item = heap_get_itl(page, i);
        if (item->xid.value == session->rm->xid.value) {
            session->itl_id = i;  // itl already exists
            *itl = item;
            return GS_SUCCESS;
        }

        if (!item->is_active) {
            if (*itl == NULL) {
                session->itl_id = i;
                *itl = item;
            }
            continue;
        }

        tx_get_itl_info(session, GS_FALSE, item, &txn_info);
        if (txn_info.status != (uint8)XACT_END) {
            continue;
        }

        // free_size and itl fsc are both less than DEFAULT_PAGE_SIZE(8192),
        // so the sum is less than max value of uint16
        page->free_size += item->fsc;
        item->fsc = 0;
        item->scn = txn_info.scn;
        item->is_active = 0;
        item->is_owscn = (uint16)txn_info.is_owscn;
        item->xid.value = GS_INVALID_ID64;

        *changed = GS_TRUE;
        if (need_redo && cursor->logging) {
            rd_clean.scn = item->scn;
            rd_clean.is_owscn = (uint8)item->is_owscn;
            rd_clean.itl_id = i;
            rd_clean.aligned = 0;
            log_put(session, RD_HEAP_CLEAN_ITL, &rd_clean, sizeof(rd_heap_clean_itl_t), LOG_ENTRY_FLAG_NONE);
        }

        if (*itl == NULL) {
            session->itl_id = i;
            *itl = item;
        }
    }

    return GS_SUCCESS;
}

static void heap_init_itl(knl_session_t *session, knl_cursor_t *cursor, heap_page_t *page,
    itl_t **itl, bool32 *changed)
{
    rd_heap_alloc_itl_t rd_alloc;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);

    if (*itl == NULL) {
        session->itl_id = heap_new_itl(session, page);
        if (session->itl_id == GS_INVALID_ID8) {
            return;
        }
        *itl = heap_get_itl(page, session->itl_id);
        tx_init_itl(session, *itl, session->rm->xid);
        if (need_redo && cursor->logging) {
            log_put(session, RD_HEAP_NEW_ITL, &session->rm->xid, sizeof(xid_t), LOG_ENTRY_FLAG_NONE);
        }
    } else {
        heap_reuse_itl(session, page, *itl, session->itl_id);

        tx_init_itl(session, *itl, session->rm->xid);
        if (need_redo && cursor->logging) {
            rd_alloc.itl_id = session->itl_id;
            rd_alloc.xid = session->rm->xid;
            rd_alloc.unused1 = 0;
            rd_alloc.unused2 = 0;
            log_put(session, RD_HEAP_REUSE_ITL, &rd_alloc, sizeof(rd_heap_alloc_itl_t), LOG_ENTRY_FLAG_NONE);
        }
    }

    *changed = GS_TRUE;
}

static status_t heap_alloc_itl(knl_session_t *session, knl_cursor_t *cursor, heap_page_t *page,
                               itl_t **itl, bool32 *changed)
{
    *changed = GS_FALSE;
    *itl = NULL;
    session->itl_id = GS_INVALID_ID8;

    if (heap_get_reusable_itl(session, cursor, page, itl, changed) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (*itl != NULL && (*itl)->xid.value == session->rm->xid.value) {
        return GS_SUCCESS;
    }

    heap_init_itl(session, cursor, page, itl, changed);

    if (session->itl_id == GS_INVALID_ID8) {
        return GS_SUCCESS;
    }

    if (DB_NOT_READY(session)) {
        (*itl)->is_active = 0;
        return GS_SUCCESS;
    }

    knl_panic_log(!DB_IS_READONLY(session), "current DB is readonly, panic info: page %u-%u type %u table %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name);

    knl_part_locate_t part_loc;
    if (IS_PART_TABLE(cursor->table)) {
        part_loc = cursor->part_loc;
    } else {
        part_loc.part_no = GS_INVALID_ID24;
        part_loc.subpart_no = GS_INVALID_ID32;
    }

    if (lock_itl(session, *AS_PAGID_PTR(page->head.id), session->itl_id, part_loc,
                 g_invalid_pagid, LOCK_TYPE_RCR_RX) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void heap_make_cond_key(knl_cursor_t *cursor, heap_key_t *key, uint32 *size)
{
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    table_t *table = (table_t *)cursor->table;
    index_t *idx;
    uint32 i, offset;
    errno_t ret;

    idx = table->index_set.items[entity->lrep_info.index_slot_id];
    knl_panic_log(idx != NULL && (idx->desc.primary || idx->desc.unique), "idx is NULL, or idx is neither primary "
                  "nor unique, panic info: page %u-%u type %u table %s", cursor->rowid.file, cursor->rowid.page,
                  ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);

    offset = 0;
    key->col_count = idx->desc.column_count;
    for (i = 0; i < idx->desc.column_count; i++) {
        key->col_id[i] = idx->desc.columns[i];
        key->col_size[i] = CURSOR_COLUMN_SIZE(cursor, key->col_id[i]);
        if (key->col_size[i] != GS_NULL_VALUE_LEN) {
            ret = memcpy_sp(key->col_values + offset, GS_KEY_BUF_SIZE - offset,
                CURSOR_COLUMN_DATA(cursor, key->col_id[i]), key->col_size[i]);
            knl_securec_check(ret);
            offset += key->col_size[i];
        }
    }

    *size = sizeof(heap_key_t) - GS_KEY_BUF_SIZE + offset;
}

void heap_append_logic_data(knl_session_t *session, knl_cursor_t *cursor, bool32 cond_need)
{
    table_t *table = (table_t *)cursor->table;
    rd_heap_logic_data_t logic_data;
    uint32 key_size;

    logic_data.tbl_id = table->desc.id;
    logic_data.tbl_uid = table->desc.uid;
    logic_data.tbl_oid = table->desc.oid;  // oid included

    log_append_data(session, (void *)&logic_data, sizeof(rd_heap_logic_data_t));

    if (cond_need) {
        // system table has no logic key
        if (IS_SYS_TABLE(table)) {
            return;
        }
        heap_key_t *pk = (heap_key_t *)cm_push(session->stack, sizeof(heap_key_t));
        heap_make_cond_key(cursor, pk, &key_size);
        log_append_data(session, (void *)pk, key_size);
        cm_pop(session->stack);
    }
}

static status_t heap_lock_migr(knl_session_t *session, knl_cursor_t *cursor)
{
    heap_t *heap = NULL;
    row_dir_t *dir = NULL;
    itl_t *itl = NULL;
    heap_page_t *page = NULL;
    uint8 owner_list;
    bool32 changed = GS_FALSE;
    rowid_t link_rid, curr_rid;
    row_head_t *row = NULL;
    bool32 is_has_itl = GS_FALSE;  // indicate that whether the txn has a itl on the row

    link_rid = cursor->link_rid;
    heap = CURSOR_HEAP(cursor);

    while (!IS_INVALID_ROWID(link_rid)) {
        is_has_itl = GS_FALSE;
        for (;;) {
            log_atomic_op_begin(session);

            buf_enter_page(session, GET_ROWID_PAGE(link_rid), LATCH_MODE_X, ENTER_PAGE_NORMAL);
            page = (heap_page_t *)CURR_PAGE(session);

            dir = heap_get_dir(page, (uint32)link_rid.slot);
            knl_panic_log(!dir->is_free, "dir is free, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);

            // we can only alloc an itl for a row,
            // and set it's is_changed equal to 0 on the first time when we try to lock the row.
            row = HEAP_GET_ROW(page, dir);
            if (ROW_ITL_ID(row) != GS_INVALID_ID8) {
                itl = heap_get_itl(page, ROW_ITL_ID(row));
                if (itl->xid.value == session->rm->xid.value) {
                    link_rid = *(rowid_t *)HEAP_LOC_LINK_RID(row);
                    buf_leave_page(session, GS_FALSE);
                    log_atomic_op_end(session);
                    is_has_itl = GS_TRUE;
                    break;
                }
            }

            if (heap_alloc_itl(session, cursor, page, &itl, &changed) != GS_SUCCESS) {
                owner_list = heap_get_owner_list(session, (heap_segment_t *)heap->segment, page->free_size);
                session->change_list = owner_list - (uint8)page->map.list_id;
                buf_leave_page(session, changed);
                knl_end_itl_waits(session);
                log_atomic_op_end(session);

                heap_try_change_map(session, heap, GET_ROWID_PAGE(link_rid));
                return GS_ERROR;
            }

            if (itl == NULL) {
                session->wpid = AS_PAGID(page->head.id);
                buf_leave_page(session, GS_FALSE);
                log_atomic_op_end(session);
                if (knl_begin_itl_waits(session, &heap->stat.itl_waits) != GS_SUCCESS) {
                    knl_end_itl_waits(session);
                    return GS_ERROR;
                }
                continue;
            }
            break;
        }
        knl_end_itl_waits(session);

        if (is_has_itl) {
            continue;
        }

        dir = heap_get_dir(page, (uint32)link_rid.slot);
        row = HEAP_GET_ROW(page, dir);
        ROW_SET_ITL_ID(row, session->itl_id);
        row->is_changed = 0;
        dir->scn = 0;
        dir->is_owscn = 0;

        if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
            rd_heap_lock_row_t rd;

            rd.slot = (uint16)link_rid.slot;
            rd.itl_id = session->itl_id;
            rd.scn = 0;
            rd.is_owscn = 0;
            log_put(session, RD_HEAP_LOCK_ROW, &rd, sizeof(rd_heap_lock_row_t), LOG_ENTRY_FLAG_NONE);
        }

        owner_list = heap_get_owner_list(session, (heap_segment_t *)heap->segment, page->free_size);
        session->change_list = owner_list - (uint8)page->map.list_id;
        curr_rid = link_rid;
        link_rid = *(rowid_t *)HEAP_LOC_LINK_RID(row);
        buf_leave_page(session, GS_TRUE);
        log_atomic_op_end(session);

        heap_try_change_map(session, heap, GET_ROWID_PAGE(curr_rid));
    }
    return GS_SUCCESS;
}

static inline bool32 heap_row_is_changed(knl_session_t *session, knl_cursor_t *cursor, row_head_t *row, knl_scn_t scn)
{
    if (scn != cursor->scn) {
        return GS_TRUE;
    }

    if (row->is_link) {
        // if cursor->row is normal
        if (cursor->chain_count == 0 && !cursor->row->is_migr) {
            return GS_TRUE;
        }

        rowid_t lnk_rid = *HEAP_LOC_LINK_RID(row);
        if (!IS_SAME_ROWID(lnk_rid, cursor->link_rid)) {
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

/*
 * different mode of "select * for update" different behavior:
 * wait (seconds): wait for sometime or not, if the row is still locked, then return with error.
 * nowait: if the row is locked, then return with error immediately.
 * skip locked: if the row is locked, then skip this row.
 */
status_t heap_try_tx_wait(knl_session_t *session, knl_cursor_t *cursor, bool32 *is_skipped)
{
    heap_t *heap = CURSOR_HEAP(cursor);
    rowmark_t *rowmark = &cursor->rowmark;

    *is_skipped = GS_FALSE;

    if (cursor->action != CURSOR_ACTION_UPDATE || rowmark->type == ROWMARK_WAIT_BLOCK) {
        heap->stat.row_lock_waits++;
        if (tx_wait(session, session->lock_wait_timeout, ENQ_TX_ROW) != GS_SUCCESS) {
            tx_record_rowid(session->wrid);
            return GS_ERROR;
        }
        return GS_SUCCESS;
    }

    switch (rowmark->type) {
        case ROWMARK_NOWAIT:
            session->wxid.value = GS_INVALID_ID64;
            GS_THROW_ERROR(ERR_ROW_LOCKED_NOWAIT);
            return GS_ERROR;

        case ROWMARK_WAIT_SECOND:
            if (rowmark->wait_seconds == 0) {
                session->wxid.value = GS_INVALID_ID64;
                GS_THROW_ERROR(ERR_LOCK_TIMEOUT);
                return GS_ERROR;
            } else {
                heap->stat.row_lock_waits++;
                if (tx_wait(session, rowmark->wait_seconds * MILLISECS_PER_SECOND, ENQ_TX_ROW) != GS_SUCCESS) {
                    tx_record_rowid(session->wrid);
                    return GS_ERROR;
                }
                return GS_SUCCESS;
            }

        case ROWMARK_SKIP_LOCKED:
            session->wxid.value = GS_INVALID_ID64;
            *is_skipped = GS_TRUE;
            return GS_SUCCESS;

        default:
            session->wxid.value = GS_INVALID_ID64;
            GS_THROW_ERROR(ERR_UNKNOWN_FORUPDATE_MODE);
            return GS_ERROR;
    }
}

static status_t heap_check_lock_row(knl_session_t *session, knl_cursor_t *cursor, heap_page_t *page,
                                    txn_info_t *txn_info, lock_row_status_t *status)
{
    row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    itl_t *itl = NULL;
    rowid_t link_rid;

    dir = heap_get_dir(page, (uint32)cursor->rowid.slot);
    if (dir->is_free) {
        *status = ROW_IS_DELETED;
        return GS_SUCCESS;
    }

    txn_info->is_owscn = (uint8)dir->is_owscn;
    row = HEAP_GET_ROW(page, dir);
    if (ROW_ITL_ID(row) != GS_INVALID_ID8) {
        itl = heap_get_itl(page, ROW_ITL_ID(row));
        if (itl->xid.value == session->rm->xid.value) {
            /* if row is locked but never changed, treat it as first time modification. */
            cursor->is_xfirst = !row->is_changed;

            /*
             * If row is locked by current transaction without change before,
             * we should ensure that the cursor row is the latest version.
             * Make a rough comparison by comparing with dir scn.
             */
            if (!row->is_changed && cursor->scn < dir->scn) {
                *status = ROW_IS_CHANGED;
                return GS_SUCCESS;
            }
            
            /* if the link row is changed in the same ssn sql, we need to get the latest link_rid
             * for locking migr_row, so the status must be set changed.
             */
            if (cursor->row->is_link) {
                link_rid = *HEAP_LOC_LINK_RID(row);
                if (!IS_SAME_ROWID(link_rid, cursor->link_rid)) {
                    *status = ROW_IS_CHANGED;
                    return GS_SUCCESS;
                }
            }
            
            *status = ROW_IS_LOCKED;
            return GS_SUCCESS;
        }

        tx_get_itl_info(session, GS_FALSE, itl, txn_info);
        if (txn_info->status != (uint8)XACT_END) {
            ROWID_COPY(session->wrid, cursor->rowid);
            session->wxid = itl->xid;
            *status = ROW_IS_CHANGED;
            return GS_SUCCESS;
        }

        if (!row->is_changed) {
            txn_info->scn = dir->scn;
        }
    } else {
        txn_info->scn = dir->scn;
    }

    if (cursor->isolevel == (uint8)ISOLATION_SERIALIZABLE && cursor->query_scn < txn_info->scn) {
        GS_THROW_ERROR(ERR_SERIALIZE_ACCESS);
        return GS_ERROR;
    }

    if (row->is_deleted) {
        *status = ROW_IS_DELETED;
        return GS_SUCCESS;
    }

    // row changed by another session, need to fetch the row again
    if (heap_row_is_changed(session, cursor, row, txn_info->scn)) {
        *status = ROW_IS_CHANGED;
        return GS_SUCCESS;
    }

    *status = ROW_IS_LOCKABLE;
    return GS_SUCCESS;
}

static status_t heap_try_lock_row(knl_session_t *session, knl_cursor_t *cursor,
                                  heap_t *heap, lock_row_status_t *status)
{
    heap_page_t *page = NULL;
    row_dir_t *dir = NULL;
    itl_t *itl = NULL;
    txn_info_t txn_info;
    uint8 owner_list;
    bool32 changed = GS_FALSE;
    row_head_t *row = NULL;

    for (;;) {
        log_atomic_op_begin(session);

        buf_enter_page(session, GET_ROWID_PAGE(cursor->rowid), LATCH_MODE_X, ENTER_PAGE_NORMAL);
        page = (heap_page_t *)CURR_PAGE(session);
        if (heap_check_lock_row(session, cursor, page, &txn_info, status) != GS_SUCCESS) {
            buf_leave_page(session, GS_FALSE);
            log_atomic_op_end(session);
            knl_end_itl_waits(session);
            return GS_ERROR;
        }

        if (*status != ROW_IS_LOCKABLE) {
            buf_leave_page(session, GS_FALSE);
            log_atomic_op_end(session);
            knl_end_itl_waits(session);
            return GS_SUCCESS;
        }

        if (heap_alloc_itl(session, cursor, page, &itl, &changed) != GS_SUCCESS) {
            owner_list = heap_get_owner_list(session, (heap_segment_t *)heap->segment, page->free_size);
            session->change_list = owner_list - (uint8)page->map.list_id;
            buf_leave_page(session, changed);
            log_atomic_op_end(session);
            knl_end_itl_waits(session);
            heap_try_change_map(session, heap, GET_ROWID_PAGE(cursor->rowid));
            return GS_ERROR;
        }

        if (itl == NULL) {
            session->wpid = AS_PAGID(page->head.id);
            buf_leave_page(session, GS_FALSE);
            log_atomic_op_end(session);
            if (knl_begin_itl_waits(session, &heap->stat.itl_waits) != GS_SUCCESS) {
                knl_end_itl_waits(session);
                return GS_ERROR;
            }
            knl_end_itl_waits(session);
            continue;
        }
        break;
    }

    dir = heap_get_dir(page, (uint32)cursor->rowid.slot);
    row = HEAP_GET_ROW(page, dir);
    dir->scn = txn_info.scn;
    dir->is_owscn = txn_info.is_owscn;
    ROW_SET_ITL_ID(row, session->itl_id);
    row->is_changed = 0;

    if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        rd_heap_lock_row_t rd;

        rd.slot = (uint16)cursor->rowid.slot;
        rd.itl_id = session->itl_id;
        rd.scn = txn_info.scn;
        rd.is_owscn = txn_info.is_owscn;
        log_put(session, RD_HEAP_LOCK_ROW, &rd, sizeof(rd_heap_lock_row_t), LOG_ENTRY_FLAG_NONE);
    }

    owner_list = heap_get_owner_list(session, (heap_segment_t *)heap->segment, page->free_size);
    session->change_list = owner_list - (uint8)page->map.list_id;
    buf_leave_page(session, GS_TRUE);
    log_atomic_op_end(session);

    heap_try_change_map(session, heap, GET_ROWID_PAGE(cursor->rowid));

    *status = ROW_IS_LOCKED;
    cursor->is_locked = GS_TRUE;
    cursor->is_xfirst = GS_TRUE;

    return GS_SUCCESS;
}

static inline status_t heap_try_check_restart(knl_session_t *session, knl_cursor_t *cursor,
    heap_t *heap, table_t *table, bool32 is_deleted)
{
    if (SECUREC_UNLIKELY(ASHRINK_HEAP(table, heap) && is_deleted && !session->compacting)) {
        if (heap_check_restart(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t heap_lock_row(knl_session_t *session, knl_cursor_t *cursor, bool32 *is_locked)
{
    heap_t *heap = CURSOR_HEAP(cursor);
    table_t *table = (table_t *)cursor->table;
    lock_row_status_t status;
    bool32 is_found = GS_FALSE;
    bool32 is_deleted = GS_FALSE;
    bool32 is_skipped = GS_FALSE;

    if (knl_cursor_ssi_conflict(cursor, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lock_table_shared(session, cursor->dc_entity, LOCK_INF_WAIT) != GS_SUCCESS) {
        return GS_ERROR;
    }

    for (;;) {
        if (heap_try_lock_row(session, cursor, heap, &status) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (status != ROW_IS_CHANGED) {
            is_deleted = (bool32)(status == ROW_IS_DELETED);
            break;
        }

        if (session->wxid.value != GS_INVALID_ID64) {
            if (heap_try_tx_wait(session, cursor, &is_skipped) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (is_skipped) {
                break;
            }
        }

        /* try read the latest committed row version */
        if (heap_read_by_rowid(session, cursor, DB_CURR_SCN(session),
                               (uint8)ISOLATION_CURR_COMMITTED, &is_found) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!is_found) {
            is_deleted = GS_TRUE;
            break;
        }

        if (knl_match_cond(session, cursor, &is_found) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!is_found) {
            break;
        }
    }

    *is_locked = (status == ROW_IS_LOCKED);
    if (*is_locked) {
        if (!IS_INVALID_ROWID(cursor->link_rid) &&
            (cursor->action == CURSOR_ACTION_DELETE || cursor->action == CURSOR_ACTION_UPDATE)) {
            return heap_lock_migr(session, cursor);
        }
    } else {
        if (cursor->isolevel == (uint8)ISOLATION_SERIALIZABLE) {
            GS_THROW_ERROR(ERR_SERIALIZE_ACCESS);
            return GS_ERROR;
        }
    }

    return heap_try_check_restart(session, cursor, heap, table, is_deleted);
}

void heap_clean_lock(knl_session_t *session, lock_item_t *item)
{
    heap_t *heap = NULL;
    heap_page_t *page = NULL;
    itl_t *itl = NULL;
    uint8 owner_list;
    page_id_t page_id;
    seg_stat_t temp_stat;
    uint8 option = !session->kernel->attr.delay_cleanout ? ENTER_PAGE_NORMAL : (ENTER_PAGE_NORMAL | ENTER_PAGE_TRY);

    page_id = MAKE_PAGID(item->file, item->page);
    SEG_STATS_INIT(session, &temp_stat);
    log_atomic_op_begin(session);

    buf_enter_page(session, page_id, LATCH_MODE_X, option);

    if (session->curr_page == NULL) {
        log_atomic_op_end(session);
        return;
    }

    page = (heap_page_t *)CURR_PAGE(session);
    itl = heap_get_itl(page, item->itl);
    if (!itl->is_active || itl->xid.value != session->rm->xid.value) {
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return;
    }

    knl_part_locate_t part_loc;
    part_loc.part_no = item->part_no;
    part_loc.subpart_no = item->subpart_no;
    heap = dc_get_heap(session, page->uid, page->oid, part_loc, NULL);

    // free_size and itl->fsc are both less than DEFAULT_PAGE_SIZE(8192), so the sum is less than max value of uint16
    page->free_size += itl->fsc;
    itl->fsc = 0;
    itl->is_active = 0;
    itl->scn = session->rm->txn->scn;
    itl->xid.value = GS_INVALID_ID64;

    if (SPACE_IS_LOGGING(SPACE_GET(session, heap->table->desc.space_id))) {
        rd_heap_clean_itl_t rd;

        rd.itl_id = item->itl;
        rd.scn = itl->scn;
        rd.is_owscn = 0;
        rd.aligned = 0;
        log_put(session, RD_HEAP_CLEAN_ITL, &rd, sizeof(rd_heap_clean_itl_t), LOG_ENTRY_FLAG_NONE);
    }

    owner_list = heap_get_owner_list(session, (heap_segment_t *)heap->segment, page->free_size);
    session->change_list = owner_list - (uint8)page->map.list_id;
    buf_leave_page(session, GS_TRUE);
    log_atomic_op_end(session);

    heap_try_change_map(session, heap, page_id);
    SEG_STATS_RECORD(session, temp_stat, &heap->stat);
}

static void heap_cleanout_itls(knl_session_t *session, knl_cursor_t *cursor, heap_page_t *page, bool32 *changed)
{
    itl_t *itl = NULL;
    txn_info_t txn_info;
    uint8 i;

    for (i = 0; i < page->itls; i++) {
        itl = heap_get_itl(page, i);
        if (!itl->is_active) {
            continue;
        }

        tx_get_itl_info(session, GS_FALSE, itl, &txn_info);
        if (txn_info.status != (uint8)XACT_END) {
            continue;
        }

        // free_size and itl->fsc are both less than DEFAULT_PAGE_SIZE(8192),
        // so the sum is less than max value of uint16
        page->free_size += itl->fsc;
        itl->fsc = 0;
        itl->is_active = 0;
        itl->scn = txn_info.scn;
        itl->is_owscn = (uint16)txn_info.is_owscn;
        itl->xid.value = GS_INVALID_ID64;

        if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type) && cursor->logging) {
            rd_heap_clean_itl_t rd;

            rd.itl_id = i;
            rd.scn = itl->scn;
            rd.is_owscn = (uint8)itl->is_owscn;
            rd.aligned = 0;
            log_put(session, RD_HEAP_CLEAN_ITL, &rd, sizeof(rd_heap_clean_itl_t), LOG_ENTRY_FLAG_NONE);
        }
        *changed = GS_TRUE;
    }
}

// Delayed page cleanout for heap
void heap_cleanout_page(knl_session_t *session, knl_cursor_t *cursor, page_id_t page_id, bool32 is_pcr)
{
    heap_t *heap = NULL;
    heap_page_t *page = NULL;
    bool32 changed = GS_FALSE;
    bool32 lock_inuse = GS_FALSE;
    uint8 owner_list;

    if (DB_IS_READONLY(session)) {
        return;
    }

    // may be called during rollback, already in atmatic operation
    if (session->atomic_op) {
        return;
    }

    if (!lock_table_without_xact(session, cursor->dc_entity, &lock_inuse)) {
        cm_reset_error();
        return;
    }

    log_atomic_op_begin(session);
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE(session);
    if (page_soft_damaged(&page->head)) {
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        unlock_table_without_xact(session, cursor->dc_entity, lock_inuse);
        return;
    }

    if (!heap_check_page(session, cursor, page, is_pcr ? PAGE_TYPE_PCRH_DATA : PAGE_TYPE_HEAP_DATA)) {
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        unlock_table_without_xact(session, cursor->dc_entity, lock_inuse);
        return;
    }

    if (is_pcr) {
        pcrh_cleanout_itls(session, cursor, page, &changed);
    } else {
        heap_cleanout_itls(session, cursor, page, &changed);
    }

    cursor->cleanout = GS_FALSE;
    heap = CURSOR_HEAP(cursor);
    owner_list = heap_get_owner_list(session, (heap_segment_t *)heap->segment, page->free_size);
    session->change_list = owner_list - (uint8)page->map.list_id;
    buf_leave_page(session, changed);
    log_atomic_op_end(session);

    heap_try_change_map(session, heap, page_id);
    unlock_table_without_xact(session, cursor->dc_entity, lock_inuse);
}

void heap_insert_into_page(knl_session_t *session, heap_page_t *page, row_head_t *row,
                           undo_data_t *undo, rd_heap_insert_t *rd, uint16 *slot)
{
    errno_t ret;
    char *row_addr = NULL;
    row_dir_t *dir = NULL;

    if (page->free_begin + row->size + sizeof(row_dir_t) > page->free_end) {
        heap_compact_page(session, page);
    }

    if (page->first_free_dir == HEAP_NO_FREE_DIR || rd->new_dir) {
        *slot = page->dirs;
        page->dirs++;
        dir = heap_get_dir(page, *slot);
        /* free_end is larger than free_size, free size is larger than sizeof(row_dir_t) */
        page->free_end -= sizeof(row_dir_t);
        page->free_size -= sizeof(row_dir_t);

        undo->snapshot.scn = 0;
        undo->snapshot.is_owscn = 0;
        undo->snapshot.undo_page = INVALID_UNDO_PAGID;
        undo->snapshot.undo_slot = 0;
        undo->snapshot.is_xfirst = GS_TRUE;
        undo->snapshot.contain_subpartno = GS_FALSE;
    } else {
        *slot = page->first_free_dir;
        dir = heap_get_dir(page, *slot);
        page->first_free_dir = dir->next_slot;

        undo->snapshot.scn = dir->scn;
        undo->snapshot.is_owscn = dir->is_owscn;
        undo->snapshot.undo_page = dir->undo_page;
        undo->snapshot.undo_slot = dir->undo_slot;
        undo->snapshot.is_xfirst = GS_TRUE;
        undo->snapshot.contain_subpartno = GS_FALSE;
    }

    dir->undo_page = rd->undo_page;
    dir->undo_slot = rd->undo_slot;
    dir->scn = rd->ssn;
    dir->is_owscn = 0;
    dir->offset = page->free_begin;

    row_addr = (char *)page + dir->offset;
    row->is_changed = 1;
    ret = memcpy_sp(row_addr, page->free_end - dir->offset, row, row->size);
    knl_securec_check(ret);
    // free_begin less than DEFAULT_PAGE_SIZE, row size is less than PCRH_MAX_ROW_SIZE,
    // the sum is less than max value(65535) of uint16
    page->free_begin += row->size;
    page->free_size -= row->size;   // free_size is larger than row->size
    page->rows++;
}

/*
 * heap remove cached pages
 * For shrink hwm, we should cleanout all cached pages of current segment,
 * so insert could re-cache for the segment after shrink hwm.
 * @param kernel session, heap segment
 */
void heap_remove_cached_pages(knl_session_t *session, heap_segment_t *segment)
{
    knl_session_t *se = NULL;
    knl_fsm_cache_t *cached_fsm = NULL;

    /* session->kernel->assigned_sessions will added after session->kernel->sessions[] extended */
    for (uint32 i = 0; i < (uint32)session->kernel->assigned_sessions; i++) {
        se = session->kernel->sessions[i];
        if (se == NULL) {
            continue;
        }

        for (uint8 j = 0; j < KNL_FSM_CACHE_COUNT; j++) {
            cached_fsm = &se->cached_fsms[j];
            if (segment != NULL && segment->seg_scn != cached_fsm->seg_scn) {
                continue;
            }

            cached_fsm->seg_scn = GS_INVALID_ID64;
            cached_fsm->entry = INVALID_PAGID;
            cached_fsm->page_id = INVALID_PAGID;
            cached_fsm->page_count = 0;
        }
    }
}

/*
 * heap calculate insert row cost size
 * @param kernel session, heap segment, insert row
 */
static inline uint32 heap_calc_insert_cost(knl_session_t *session, heap_segment_t *segment,
                                           uint16 row_size, bool32 alloc_itl)
{
    uint32 cost_size = alloc_itl ? sizeof(itl_t) + sizeof(row_dir_t) : sizeof(row_dir_t);
    space_t *space = SPACE_GET(session, segment->space_id);

    if (row_size + segment->list_range[1] < (uint16)HEAP_MAX_ROW_SIZE(session) - space->ctrl->cipher_reserve_size) {
        cost_size += row_size + segment->list_range[1];
    } else {
        cost_size += HEAP_MAX_ROW_SIZE(session) - space->ctrl->cipher_reserve_size;
    }

    return cost_size;
}

static inline uint32 heap_calc_insert_relsize(bool32 itl_needed, row_head_t *row)
{
    return (itl_needed ? row->size + sizeof(itl_t) + sizeof(row_dir_t) : row->size + sizeof(row_dir_t));
}

static inline bool32 heap_insert_size_invalid(heap_page_t *page, uint32 cost_size, uint32 real_size)
{
    return (page->free_size < cost_size && !(page->rows == 0 && page->free_size >= real_size));
}

/*
 * 1. add page one by one of the first extent
 * 2. use appendonly after the first extent ended
 */
bool32 heap_use_appendonly(knl_session_t *session, knl_cursor_t *cursor, heap_segment_t *segment)
{
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    table_t *table = (table_t *)cursor->table;

    if (SECUREC_UNLIKELY(entity == NULL)) {
        return GS_FALSE;
    }

    if (SECUREC_UNLIKELY(session->compacting)) {
        return GS_FALSE;
    }

    if (SECUREC_UNLIKELY(table->ashrink_stat != ASHRINK_END)) {
        return GS_FALSE;
    }

    if (SECUREC_UNLIKELY(segment->extents.count == 1 && !IS_INVALID_PAGID(segment->free_ufp))) {
        return GS_FALSE;
    }

    return  entity->table.desc.appendonly;
}

static inline void heap_init_page_itls(knl_session_t *session, knl_cursor_t *cursor, heap_segment_t *segment,
    heap_page_t *page, uint16 cost_size)
{
    uint32 maxtrans;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);

    maxtrans = (page->free_size - cost_size) / sizeof(itl_t);
    page->itls = (maxtrans < segment->initrans) ? maxtrans : segment->initrans;
    /* free_end and free_size are both larger than page->itls * sizeof(itl_t) for page which page->dirs is 0 */
    page->free_end -= page->itls * sizeof(itl_t);
    page->free_size -= page->itls * sizeof(itl_t);
    if (need_redo && cursor->logging) {
        log_put(session, RD_HEAP_INIT_ITLS, &page->itls, sizeof(uint32), LOG_ENTRY_FLAG_NONE);
    }
}

static status_t heap_enter_insert_page(knl_session_t *session, knl_cursor_t *cursor, bool32 itl_needed,
    row_head_t *row, page_id_t *page_id)
{
    heap_t *heap;
    heap_segment_t *segment;
    itl_t *itl = NULL;
    heap_page_t *page = NULL;
    bool32 appendonly;
    bool32 use_cached;
    uint8 owner_list;
    bool32 changed = GS_FALSE;
    bool32 degrade_mid = GS_FALSE;
    uint8 mid;
    uint32 cost_size;
    uint32 real_size;

    use_cached = GS_TRUE;
    heap = CURSOR_HEAP(cursor);
    segment = HEAP_SEGMENT(session, heap->entry, heap->segment);
    appendonly = heap_use_appendonly(session, cursor, segment);

    // alloc itl later, cost size should include sizeof(itl_t)
    cost_size = heap_calc_insert_cost(session, segment, row->size, itl_needed);
    // list id range is [0, HEAP_FREE_LIST_COUNT-1(5)]
    mid = (uint8)heap_get_target_list(session, segment, cost_size);

    for (;;) {
        if (appendonly) {
            if (GS_SUCCESS != heap_find_appendonly_page(session, heap, g_invalid_part_loc, cost_size, page_id)) {
                knl_end_itl_waits(session);
                GS_THROW_ERROR(ERR_FIND_FREE_SPACE, cost_size);
                return GS_ERROR;
            }
        } else {
            if (GS_SUCCESS !=
                heap_find_free_page(session, heap, g_invalid_part_loc, mid, use_cached, page_id, &degrade_mid)) {
                knl_end_itl_waits(session);
                GS_THROW_ERROR(ERR_FIND_FREE_SPACE, cost_size);
                return GS_ERROR;
            }
        }

        log_atomic_op_begin(session);
        log_set_group_nolog_insert(session, cursor->logging);
        if (buf_read_page(session, *page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
            log_atomic_op_end(session);
            knl_end_itl_waits(session);
            return GS_ERROR;
        }
        page = (heap_page_t *)CURR_PAGE(session);
        if (PAGE_IS_SOFT_DAMAGE((page_head_t*)page)) {
            buf_leave_page(session, GS_FALSE);
            log_atomic_op_end(session);
            knl_end_itl_waits(session);
            GS_THROW_ERROR(ERR_PAGE_SOFT_DAMAGED, page_id->file, page_id->page);
            return GS_ERROR;
        }

        // if the page is not heap page, we should skip it and try again
        if (page->head.type != PAGE_TYPE_HEAP_DATA) {
            buf_leave_page(session, GS_FALSE);
            log_atomic_op_end(session);
            heap_remove_cached_page(session, appendonly);
            knl_end_itl_waits(session);
            use_cached = GS_FALSE;
            continue;
        }

        knl_panic_log(page->oid == segment->oid, "the oid of page and segment are not same, panic info: "
            "page %u-%u type %u oid %u seg_oid %u table %s", cursor->rowid.file, cursor->rowid.page,
            ((page_head_t *)cursor->page_buf)->type, page->oid, segment->oid, ((table_t *)cursor->table)->desc.name);
        knl_panic_log(page->uid == segment->uid, "the uid of page and segment are not same, panic info: "
            "page %u-%u type %u uid %u seg_uid %u table %s", cursor->rowid.file, cursor->rowid.page,
            ((page_head_t *)cursor->page_buf)->type, page->uid, segment->uid, ((table_t *)cursor->table)->desc.name);
        knl_panic_log(page->org_scn == segment->org_scn, "the org_scn of page and segment are not same, panic info: "
                      "page %u-%u type %u table %s org_scn %llu segment's org_scn %llu",
                      cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                      ((table_t *)cursor->table)->desc.name, page->org_scn, segment->org_scn);
        knl_panic_log(page->seg_scn == segment->seg_scn, "the seg_scn of page and segment are not same, panic info: "
                      "page %u-%u type %u table %s seg_scn %llu segment's seg_scn %llu",
                      cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                      ((table_t *)cursor->table)->desc.name, page->seg_scn, segment->seg_scn);

        real_size = heap_calc_insert_relsize(itl_needed, row);
        if (heap_insert_size_invalid(page, cost_size, real_size)) {
            owner_list = heap_get_owner_list(session, segment, page->free_size);
            session->change_list = owner_list - (uint8)page->map.list_id;
            buf_leave_page(session, GS_FALSE);
            log_atomic_op_end(session);
            if (degrade_mid && (owner_list == mid - 1)) {
                heap_degrade_change_map(session, heap, *page_id, owner_list - 1);
            } else {
                heap_try_change_map(session, heap, *page_id);
            }

            heap_remove_cached_page(session, appendonly);
            use_cached = GS_FALSE;
            continue;
        }

        if (!itl_needed) {
            knl_end_itl_waits(session);
            return GS_SUCCESS;
        }

        if (page->itls == 0) {
            heap_init_page_itls(session, cursor, segment, page, cost_size);
        }

        if (heap_alloc_itl(session, cursor, page, &itl, &changed) != GS_SUCCESS) {
            owner_list = heap_get_owner_list(session, segment, page->free_size);
            session->change_list = owner_list - (uint8)page->map.list_id;
            buf_leave_page(session, changed);
            log_atomic_op_end(session);
            knl_end_itl_waits(session);
            heap_try_change_map(session, heap, *page_id);
            return GS_ERROR;
        }

        if (itl == NULL) {
            session->wpid = *page_id;
            buf_leave_page(session, GS_FALSE);
            log_atomic_op_end(session);

            if (knl_begin_itl_waits(session, &heap->stat.itl_waits) != GS_SUCCESS) {
                knl_end_itl_waits(session);
                return GS_ERROR;
            }
            use_cached = GS_FALSE;
            continue;
        }

        knl_end_itl_waits(session);
        return GS_SUCCESS;
    }
}

static uint16 heap_calc_chain_range(knl_session_t *session, knl_cursor_t *cursor,
                                    chain_row_assist_t *cra, bool32 itl_needed)
{
    uint16 i, slot, col_count;
    uint16 cost_size, ex_size;
    row_assist_t ra;
    knl_cal_col_size_t  calc_col_size_func = cursor->row->is_csf ?
        heap_calc_csf_col_actualsize : heap_calc_bmp_col_actualsize;
    knl_calc_row_head_inc_size_t calc_row_head_inc_func = cursor->row->is_csf ?
        heap_calc_csf_row_head_inc_size : heap_calc_bmp_row_head_inc_size;
    heap_t *heap = CURSOR_HEAP(cursor);
    uint8 cipher_reserve_size = heap->cipher_reserve_size;

    slot = 1;
    cost_size = 0;

    cm_attach_row(&ra, (char *)cursor->row);

    if (itl_needed) {
        ex_size = sizeof(itl_t) + sizeof(row_dir_t);
    } else {
        ex_size = sizeof(row_dir_t);
    }

    col_count = ROW_COLUMN_COUNT(cursor->row);

    for (i = 0; i < col_count; i++) {
        if (cra[slot].column_count == 0) {
            cost_size = cm_row_init_size(ra.is_csf, 0) + sizeof(rowid_t);
            cra[slot].col_id = i;
        }

        cost_size += calc_col_size_func(ra.head, cursor->lens, i);
        cost_size += calc_row_head_inc_func(cra[slot].column_count + 1, cra[slot].column_count);
        if ((CM_ALIGN4(cost_size) + ex_size) > (uint16)HEAP_MAX_COST_SIZE(session) - cipher_reserve_size) {
            i--;
            slot++;
            continue;
        } else {
            cra[slot].column_count++;
        }
    }

    return slot;
}

uint16 heap_split_chain_row(knl_session_t *session, knl_cursor_t *cursor, chain_row_assist_t *cra,
                            uint16 cra_len, bool32 itl_needed)
{
    row_assist_t ra;
    uint16 slot, chain_slot;
    uint16 i, col_id;
    knl_put_row_column_t put_col_func = cursor->row->is_csf ? heap_put_csf_row_column : heap_put_bmp_row_column;

    ra.is_csf = cursor->row->is_csf;
    heap_init_row(session, &ra, (char *)cra[0].row, ROW_COLUMN_COUNT(cursor->row), GS_INVALID_ID8, cursor->row->flags);
    cra[0].row->size = HEAP_MIN_ROW_SIZE;
    cra[0].row->is_link = 1;
    HEAP_SET_LINK_RID(cra[0].row, GS_INVALID_ID64);

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, NULL);

    chain_slot = heap_calc_chain_range(session, cursor, cra, itl_needed);
    knl_panic_log(chain_slot < cra_len, "The chain_slot number exceeds the limit, panic info: page %u-%u type %u "
                  "table %s chain_slot %u cra_len %u", cursor->rowid.file, cursor->rowid.page,
                  ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name, chain_slot, cra_len);

    for (slot = 1; slot <= chain_slot; slot++) {
        heap_init_chain_row(session, &ra, (char *)cra[slot].row, cra[slot].column_count, GS_INVALID_ID8, 0);

        for (i = 0; i < cra[slot].column_count; i++) {
            col_id = i + cra[slot].col_id;
            put_col_func(cursor->row, cursor->offsets, cursor->lens, col_id, &ra);
        }
        row_end(&ra);
    }

    return chain_slot;
}

void heap_insert_into_page_migr(knl_session_t *session, heap_page_t *page, row_head_t *row,
                                rd_heap_insert_t *rd, uint16 *slot)
{
    errno_t ret;
    row_dir_t *dir = NULL;
    char *row_addr = NULL;

    if (page->free_begin + row->size + sizeof(row_dir_t) > page->free_end) {
        heap_compact_page(session, page);
    }

    // for migration row always alloc a new row dir
    // extend a new slot
    *slot = page->dirs;
    page->dirs++;
    dir = heap_get_dir(page, *slot);

    /* free_size is larger than sizeof(row_dir_t) + row->size, free_end is larger than free_size */
    page->free_end -= sizeof(row_dir_t);
    page->free_size -= sizeof(row_dir_t);

    dir->undo_page = rd->undo_page;
    dir->undo_slot = rd->undo_slot;
    dir->scn = rd->ssn;
    dir->is_owscn = 0;
    dir->offset = page->free_begin;
    // free_begin less than DEFAULT_PAGE_SIZE, row size less than PCRH_MAX_ROW_SIZE,
    // the sum is less than max value(65535) of uint16
    page->free_begin += row->size;
    page->free_size -= row->size;

    row->is_migr = 1;
    ROW_SET_ITL_ID(row, GS_INVALID_ID8);

    row_addr = (char *)page + dir->offset;
    ret = memcpy_sp(row_addr, page->free_end - dir->offset, row, row->size);
    knl_securec_check(ret);
    page->rows++;
}

static void heap_generate_undo_for_update(knl_session_t *session, knl_cursor_t *cursor, rowid_t rid,
    heap_page_t *page, undo_data_t *undo, heap_update_assist_t *ua)
{
    row_dir_t *dir = NULL;
    row_head_t *row = NULL;

    undo->ssn = (uint32)cursor->ssn;

    dir = heap_get_dir(page, (uint32)rid.slot);
    row = HEAP_GET_ROW(page, dir);

    undo->snapshot.scn = cursor->is_xfirst ? (row->is_migr ? cursor->scn : dir->scn) : DB_CURR_SCN(session);
    undo->snapshot.is_owscn = dir->is_owscn;
    undo->snapshot.undo_page = dir->undo_page;
    undo->snapshot.undo_slot = dir->undo_slot;
    undo->snapshot.is_xfirst = cursor->is_xfirst;

    if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        dir->undo_page = session->rm->undo_page_info.undo_rid.page_id;
        // max undo page size is 32K, so max slot count for undo page is 744, less than uint16:15
        dir->undo_slot = session->rm->undo_page_info.undo_rid.slot;
    } else {
        dir->undo_page = session->rm->noredo_undo_page_info.undo_rid.page_id;
        dir->undo_slot = session->rm->noredo_undo_page_info.undo_rid.slot;
    }
    dir->scn = cursor->ssn;
    dir->is_owscn = 0;
    row->is_changed = 1;

    if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        rd_heap_change_dir_t redo;

        redo.scn = dir->scn;
        redo.slot = (uint16)rid.slot;
        redo.undo_page = dir->undo_page;
        redo.undo_slot = dir->undo_slot;
        log_put(session, RD_HEAP_CHANGE_DIR, &redo, sizeof(rd_heap_change_dir_t), LOG_ENTRY_FLAG_NONE);
    }
    undo_write(session, undo, IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type), GS_FALSE);
}

static void heap_delete_migr_row(knl_session_t *session, knl_cursor_t *cursor, rowid_t old_rid, rowid_t new_rid)
{
    heap_page_t *migr_page = NULL;
    row_dir_t *migr_dir = NULL;
    undo_data_t undo;
    itl_t *itl = NULL;
    rd_heap_change_dir_t rd_chg;
    rd_heap_delete_t rd_del;
    errno_t err;
    row_head_t *migr_row = NULL;
    uint32 partloc_size = undo_part_locate_size(cursor->table);

    if (!IS_SAME_PAGID(old_rid, new_rid)) {
        buf_enter_page(session, GET_ROWID_PAGE(old_rid), LATCH_MODE_X, ENTER_PAGE_NORMAL);
    }

    migr_page = (heap_page_t *)CURR_PAGE(session);
    migr_dir = heap_get_dir(migr_page, (uint32)old_rid.slot);
    migr_row = HEAP_GET_ROW(migr_page, migr_dir);

    undo.type = UNDO_HEAP_DELETE_MIGR;
    /* migr_row->size is less than HEAP_MAX_ROW_SIZE(session), so the sum is less than the max value of uint16 */
    undo.size = migr_row->size + partloc_size + sizeof(rowid_t); /* row + part_no + next_rowid */
    undo.rowid = old_rid;
    // cursor->ssn is from session->xact_ssn(uint32) or stmt->xact_ssn(uint32) for not temp table
    undo.ssn = (uint32)cursor->ssn;

    undo.snapshot.scn = cursor->is_xfirst ? cursor->scn : DB_CURR_SCN(session);
    undo.snapshot.is_owscn = migr_dir->is_owscn;
    undo.snapshot.undo_page = migr_dir->undo_page;
    undo.snapshot.undo_slot = migr_dir->undo_slot;
    undo.snapshot.is_xfirst = cursor->is_xfirst;
    undo.snapshot.contain_subpartno = GS_FALSE;

    if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        migr_dir->undo_page = session->rm->undo_page_info.undo_rid.page_id;
        // max undo page size is 32K, so max slot count for undo page is 744, less than uint16:15
        migr_dir->undo_slot = session->rm->undo_page_info.undo_rid.slot;
    } else {
        migr_dir->undo_page = session->rm->noredo_undo_page_info.undo_rid.page_id;
        migr_dir->undo_slot = session->rm->noredo_undo_page_info.undo_rid.slot;
    }
    migr_dir->scn = cursor->ssn;
    migr_dir->is_owscn = 0;

    if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        rd_chg.undo_page = session->rm->undo_page_info.undo_rid.page_id;
        rd_chg.undo_slot = session->rm->undo_page_info.undo_rid.slot;
    } else {
        rd_chg.undo_page = session->rm->noredo_undo_page_info.undo_rid.page_id;
        rd_chg.undo_slot = session->rm->noredo_undo_page_info.undo_rid.slot;
    }
    rd_chg.slot = (uint16)old_rid.slot;
    rd_chg.scn = cursor->ssn;

    undo.data = (char *)cm_push(session->stack, migr_row->size + partloc_size + sizeof(rowid_t));
    undo.snapshot.contain_subpartno = GS_FALSE;
    table_t *table = (table_t *)cursor->table;
    if (IS_PART_TABLE(table) && IS_COMPART_TABLE(table->part_table)) {
        undo.snapshot.contain_subpartno = GS_TRUE;
        *(knl_part_locate_t *)(undo.data) = cursor->part_loc;
    } else {
        *(uint32 *)(undo.data) = cursor->part_loc.part_no;
    }

    *(uint64 *)((char *)undo.data + partloc_size) = *(uint64 *)&new_rid;
    err = memcpy_sp((char *)undo.data + partloc_size + sizeof(rowid_t), migr_row->size, migr_row, migr_row->size);
    knl_securec_check(err);

    if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        log_put(session, RD_HEAP_CHANGE_DIR, &rd_chg, sizeof(rd_heap_change_dir_t), LOG_ENTRY_FLAG_NONE);
    }
    undo_write(session, &undo, IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type), GS_FALSE);

    knl_panic_log(!migr_row->is_deleted, "migr_row is deleted, panic info: page %u-%u type %u table %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name);
    migr_row->is_deleted = 1;
    migr_row->is_changed = 1;
    migr_page->rows--;

    if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        rd_del.undo_page = session->rm->undo_page_info.undo_rid.page_id;
    } else {
        rd_del.undo_page = session->rm->noredo_undo_page_info.undo_rid.page_id;
    }
    rd_del.undo_slot = rd_chg.undo_slot;
    rd_del.slot = (uint16)old_rid.slot;
    rd_del.ssn = (uint32)cursor->ssn;

    itl = heap_get_itl(migr_page, ROW_ITL_ID(migr_row));
    knl_panic_log(itl->is_active, "itl is inactive, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);
    // row->size and itl->fsc are both less than DEFAULT_PAGE_SIZE(8192), so the sum is less than max value of uint16
    itl->fsc += migr_row->size;

    if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        log_put(session, RD_HEAP_DELETE_MIGR, &rd_del, sizeof(rd_heap_delete_t), LOG_ENTRY_FLAG_NONE);
    }
    if (!IS_SAME_PAGID(old_rid, new_rid)) {
        buf_leave_page(session, GS_TRUE);  // leave old migr_page
    }
    cm_pop(session->stack);
}

static void heap_update_owner_nextrid(knl_session_t *session, knl_cursor_t *cursor, heap_segment_t *segment,
    migr_row_assist_t *migr_assist, int8 *change_list)
{
    heap_page_t *owner_page = NULL;
    row_head_t *owner_row = NULL;
    row_dir_t *owner_dir = NULL;
    rowid_t *new_link_rid = NULL;
    rd_set_link_t rd_set_link;
    uint8 owner_list;

    buf_enter_page(session, GET_ROWID_PAGE(migr_assist->owner_rid), LATCH_MODE_X, ENTER_PAGE_NORMAL);
    owner_page = (heap_page_t *)CURR_PAGE(session);
    // update the owner row as a link row
    owner_dir = heap_get_dir(owner_page, (uint32)migr_assist->owner_rid.slot);
    owner_row = HEAP_GET_ROW(owner_page, owner_dir);
    if (!owner_row->is_link && !owner_row->is_migr) {
        owner_row->is_link = 1;
        // free_size and row->size are both less than DEFAULT_PAGE_SIZE(8192)
        owner_page->free_size += owner_row->size - HEAP_MIN_ROW_SIZE;
    }

    new_link_rid = HEAP_LOC_LINK_RID(owner_row);
    *new_link_rid = migr_assist->new_rid;

    if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        rd_set_link.slot = (uint16)migr_assist->owner_rid.slot;
        rd_set_link.link_rid = migr_assist->new_rid;
        rd_set_link.aligned = 0;
        log_put(session, RD_HEAP_SET_LINK, &rd_set_link, sizeof(rd_set_link), LOG_ENTRY_FLAG_NONE);
    }
    owner_list = heap_get_owner_list(session, segment, owner_page->free_size);
    *change_list = owner_list - (uint8)owner_page->map.list_id;
    buf_leave_page(session, GS_TRUE);  // leave owner_page
}

static void heap_insert_migrate_row(knl_session_t *session, knl_cursor_t *cursor, heap_page_t *migr_page,
    row_head_t *row, migr_row_assist_t *migr_assist, uint32 ssn)
{
    heap_t *heap = CURSOR_HEAP(cursor);
    rd_heap_insert_t rd;
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    bool32 has_logic = LOGIC_REP_DB_ENABLED(session) && dc_replication_enabled(session, entity, cursor->part_loc);
    uint8 entry_flag = has_logic ? LOG_ENTRY_FLAG_WITH_LOGIC_OID : LOG_ENTRY_FLAG_NONE;
    uint16 slot;
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(heap->cipher_reserve_size);

    rd.undo_page = INVALID_UNDO_PAGID;
    rd.undo_slot = 0;
    rd.ssn = ssn;
    rd.aligned = 0;

    // insert into MIGR destination
    heap_insert_into_page_migr(session, migr_page, row, &rd, &slot);
    migr_assist->new_rid.slot = slot;

    if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        log_encrypt_prepare(session, ((page_head_t *)session->curr_page)->type, need_encrypt);
        log_put(session, RD_HEAP_INSERT_MIGR, &rd, OFFSET_OF(rd_heap_insert_t, data), entry_flag);
        log_append_data(session, row, row->size);
        if (has_logic) {
            log_append_data(session, &(migr_assist->col_start), sizeof(uint16));
        }
    }
}

static void heap_remove_migr_row(knl_session_t *session, knl_cursor_t *cursor,
    heap_segment_t *segment, migr_row_assist_t *migr_assist, int8 *change_list)
{
    heap_page_t *migr_page = NULL;
    row_head_t *migr_row = NULL;
    row_dir_t *migr_dir = NULL;
    uint16 slot;
    uint8 owner_list;

    buf_enter_page(session, GET_ROWID_PAGE(migr_assist->old_rid), LATCH_MODE_X, ENTER_PAGE_NORMAL);
    migr_page = (heap_page_t *)CURR_PAGE(session);

    migr_dir = heap_get_dir(migr_page, (uint32)migr_assist->old_rid.slot);
    migr_row = HEAP_GET_ROW(migr_page, migr_dir);
    migr_row->is_deleted = 1;
    migr_dir->is_free = 1;
    migr_page->rows--;
    migr_dir->next_slot = migr_page->first_free_dir;
    migr_page->first_free_dir = (uint16)migr_assist->old_rid.slot;
    // free_size and row->size are both less than DEFAULT_PAGE_SIZE(8192),
    // so the sum is less than max value(65535) of uint16
    migr_page->free_size += migr_row->size;
    slot = (uint16)migr_assist->old_rid.slot;
    if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        log_put(session, RD_HEAP_REMOVE_MIGR, &slot, sizeof(uint16), LOG_ENTRY_FLAG_NONE);
    }
    owner_list = heap_get_owner_list(session, segment, migr_page->free_size);
    *change_list = owner_list - (uint8)migr_page->map.list_id;
    buf_leave_page(session, GS_TRUE);  // leave old migr_page
}

static status_t heap_update_migr_row(knl_session_t *session, knl_cursor_t *cursor,
                                     row_assist_t *ra, migr_row_assist_t *migr_assist)
{
    heap_t *heap = CURSOR_HEAP(cursor);
    heap_segment_t *segment = (heap_segment_t *)heap->segment;
    uint16 cost_size;
    page_id_t page_id;
    heap_page_t *migr_page = NULL;
    uint8 owner_list, mid;
    int8 change_list[3] = {0};   // for row, migration row and old row
    bool32 degrade_mid = GS_FALSE;

    // no need to alloc itl , cost size should not include sizeof(itl_t)
    cost_size = heap_calc_insert_cost(session, segment, ra->head->size, GS_FALSE);
    // list id range is [0, HEAP_FREE_LIST_COUNT-1(5)]
    mid = (uint8)heap_get_target_list(session, segment, cost_size);

    for (;;) {
        if (heap_find_free_page(session, heap, g_invalid_part_loc, mid, GS_FALSE, &page_id, &degrade_mid) !=
            GS_SUCCESS) {
            return GS_ERROR;
        }

        SET_ROWID_PAGE(&migr_assist->new_rid, page_id);
        log_atomic_op_begin(session);

        cm_latch_x(&heap->latch.latch, session->id, &session->stat_heap);

        if (buf_read_page(session, GET_ROWID_PAGE(migr_assist->new_rid),
                          LATCH_MODE_X, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
            cm_unlatch(&heap->latch.latch, &session->stat_heap);
            log_atomic_op_end(session);
            return GS_ERROR;
        }
        migr_page = (heap_page_t *)CURR_PAGE(session);
        if (migr_page->free_size < cost_size && !(migr_page->rows == 0 &&
                                                  migr_page->free_size >= ra->head->size + sizeof(row_dir_t))) {
            owner_list = heap_get_owner_list(session, segment, migr_page->free_size);
            session->change_list = owner_list - (uint8)migr_page->map.list_id;
            buf_leave_page(session, GS_FALSE);  // leave migr_page
            cm_unlatch(&heap->latch.latch, &session->stat_heap);
            log_atomic_op_end(session);

            if (degrade_mid && (owner_list == mid - 1)) {
                heap_degrade_change_map(session, heap, GET_ROWID_PAGE(migr_assist->new_rid), owner_list - 1);
            } else {
                heap_try_change_map(session, heap, GET_ROWID_PAGE(migr_assist->new_rid));
            }
            continue;
        }

        if (migr_page->itls == 0) {
            heap_init_page_itls(session, cursor, segment, migr_page, cost_size);
        }

        heap_insert_migrate_row(session, cursor, migr_page, ra->head, migr_assist, 0);

        owner_list = heap_get_owner_list(session, segment, migr_page->free_size);
        change_list[0] = owner_list - (uint8)migr_page->map.list_id;
        buf_leave_page(session, GS_TRUE);  // leave migr_page

        // owner page
        if (!IS_INVALID_ROWID(migr_assist->owner_rid)) {
            heap_update_owner_nextrid(session, cursor, segment, migr_assist, &change_list[1]);
        }

        // If the is a MIGR row previous, remove old row data
        if (!IS_INVALID_ROWID(migr_assist->old_rid)) {
            heap_remove_migr_row(session, cursor, segment, migr_assist, &change_list[2]);
        }

        cm_unlatch(&heap->latch.latch, &session->stat_heap);
        log_atomic_op_end(session);

        session->change_list = change_list[0];
        heap_try_change_map(session, heap, GET_ROWID_PAGE(migr_assist->new_rid));
        session->change_list = change_list[1];
        heap_try_change_map(session, heap, GET_ROWID_PAGE(migr_assist->owner_rid));
        session->change_list = change_list[2];
        heap_try_change_map(session, heap, GET_ROWID_PAGE(migr_assist->old_rid));

        break;
    }

    return GS_SUCCESS;
}

static status_t heap_update_chain_undo_prepare(knl_session_t *session, knl_cursor_t *cursor,
    migr_row_assist_t *migr_assist, bool32 need_encrypt)
{
    heap_page_t *page = NULL;
    row_head_t *row = NULL;
    row_dir_t *dir = NULL;
    uint32 partloc_size = undo_part_locate_size(cursor->table);

    // If there is a MIGR row previous, set it deleted -- only first split row judge this
    if (!IS_INVALID_ROWID(migr_assist->old_rid)) {
        if (buf_read_page(session, GET_ROWID_PAGE(migr_assist->old_rid),
                          LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
            return GS_ERROR;
        }

        page = (heap_page_t *)CURR_PAGE(session);
        dir = heap_get_dir(page, (uint32)migr_assist->old_rid.slot);
        row = HEAP_GET_ROW(page, dir);
        buf_leave_page(session, GS_FALSE);

        if (undo_prepare(session, row->size + partloc_size + sizeof(rowid_t),
                         IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type), need_encrypt) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        if (undo_prepare(session, partloc_size, IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type), GS_FALSE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t heap_update_chain_row(knl_session_t *session, knl_cursor_t *cursor,
                                      row_assist_t *ra, migr_row_assist_t *migr_assist)
{
    heap_t *heap = CURSOR_HEAP(cursor);
    heap_segment_t *segment = (heap_segment_t *)heap->segment;
    uint16 cost_size;
    page_id_t page_id;
    heap_page_t *migr_page = NULL;
    uint8 owner_list;
    int8 change_list[3] = {0};
    undo_data_t undo;
    bool32 degrade_mid = GS_FALSE;
    uint8 mid;
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(heap->cipher_reserve_size);
    if (heap_update_chain_undo_prepare(session, cursor, migr_assist, need_encrypt) != GS_SUCCESS) {
        return GS_ERROR;
    }

    // no need to alloc itl , cost size should not include sizeof(itl_t)
    cost_size = heap_calc_insert_cost(session, segment, ra->head->size, GS_FALSE);
    // list id range is [0, HEAP_FREE_LIST_COUNT-1(5)]
    mid = (uint8)heap_get_target_list(session, segment, cost_size);

    for (;;) {
        if (heap_find_free_page(session, heap, g_invalid_part_loc, mid, GS_FALSE, &page_id, &degrade_mid) !=
            GS_SUCCESS) {
            return GS_ERROR;
        }

        SET_ROWID_PAGE(&migr_assist->new_rid, page_id);
        log_atomic_op_begin(session);

        cm_latch_x(&heap->latch.latch, session->id, &session->stat_heap);

        if (buf_read_page(session, GET_ROWID_PAGE(migr_assist->new_rid),
                          LATCH_MODE_X, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
            cm_unlatch(&heap->latch.latch, &session->stat_heap);
            log_atomic_op_end(session);
            return GS_ERROR;
        }
        migr_page = (heap_page_t *)CURR_PAGE(session);
        if (migr_page->free_size < cost_size && !(migr_page->rows == 0 &&
                                                 migr_page->free_size >= ra->head->size + sizeof(row_dir_t))) {
            owner_list = heap_get_owner_list(session, segment, migr_page->free_size);
            session->change_list = owner_list - (uint8)migr_page->map.list_id;
            buf_leave_page(session, GS_FALSE);  // leave migr_page
            cm_unlatch(&heap->latch.latch, &session->stat_heap);
            log_atomic_op_end(session);

            if (degrade_mid && (owner_list == mid - 1)) {
                heap_degrade_change_map(session, heap, GET_ROWID_PAGE(migr_assist->new_rid), owner_list - 1);
            } else {
                heap_try_change_map(session, heap, GET_ROWID_PAGE(migr_assist->new_rid));
            }
            continue;
        }

        if (migr_page->itls == 0) {
            heap_init_page_itls(session, cursor, segment, migr_page, cost_size);
        }

        heap_insert_migrate_row(session, cursor, migr_page, ra->head, migr_assist, (uint32)cursor->ssn);
        undo.snapshot.contain_subpartno = GS_FALSE;
        // If there is a MIGR row previous, set it deleted -- only first splited row judge this
        if (!IS_INVALID_ROWID(migr_assist->old_rid)) {
            heap_delete_migr_row(session, cursor, migr_assist->old_rid, migr_assist->new_rid);
        } else {
            table_t *table = (table_t *)cursor->table;
            if (IS_PART_TABLE(table) && IS_COMPART_TABLE(table->part_table)) {
                undo.snapshot.contain_subpartno = GS_TRUE;
            }
            undo.type = UNDO_HEAP_INSERT_MIGR;
            undo.size = undo_part_locate_size(table);
            undo.rowid = migr_assist->new_rid;
            undo.data = (char *)&cursor->part_loc;
            // cursor->ssn is from session->xact_ssn(uint32) or stmt->xact_ssn(uint32) for not temp table
            undo.ssn = (uint32)cursor->ssn;

            undo.snapshot.scn = 0;
            undo.snapshot.is_owscn = 0;
            undo.snapshot.undo_page = INVALID_UNDO_PAGID;

            undo.snapshot.undo_slot = 0;
            undo.snapshot.is_xfirst = cursor->is_xfirst;

            undo_write(session, &undo, IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type), GS_FALSE);
        }

        owner_list = heap_get_owner_list(session, segment, migr_page->free_size);
        change_list[0] = owner_list - (uint8)migr_page->map.list_id;
        buf_leave_page(session, GS_TRUE);  // leave migr_page

        // owner page
        if (!IS_INVALID_ROWID(migr_assist->owner_rid)) {
            heap_update_owner_nextrid(session, cursor, segment, migr_assist, &change_list[1]);
        }

        cm_unlatch(&heap->latch.latch, &session->stat_heap);
        log_atomic_op_end(session);

        session->change_list = change_list[0];
        heap_try_change_map(session, heap, GET_ROWID_PAGE(migr_assist->new_rid));
        session->change_list = change_list[1];
        heap_try_change_map(session, heap, GET_ROWID_PAGE(migr_assist->owner_rid));

        break;
    }

    return GS_SUCCESS;
}

static status_t heap_insert_row(knl_session_t *session, knl_cursor_t *cursor, heap_t *heap, row_head_t *row)
{
    page_id_t page_id;
    rd_heap_insert_t rd;
    undo_data_t undo;
    uint16 slot;
    bool32 has_logic = LOGIC_REP_DB_ENABLED(session) &&
        dc_replication_enabled(session, (dc_entity_t*)cursor->dc_entity, cursor->part_loc) &&
        (!row->is_link);
    uint8 entry_flag = has_logic ? LOG_ENTRY_FLAG_WITH_LOGIC_OID : LOG_ENTRY_FLAG_NONE;
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(heap->cipher_reserve_size);
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);

    if (heap_enter_insert_page(session, cursor, GS_TRUE, row, &page_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    SET_ROWID_PAGE(&cursor->rowid, page_id);
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);

    ROW_SET_ITL_ID(row, session->itl_id);
    rd.ssn = (uint32)cursor->ssn;
    if (need_redo) {
        rd.undo_page = session->rm->undo_page_info.undo_rid.page_id;
        rd.undo_slot = session->rm->undo_page_info.undo_rid.slot;
    } else {
        rd.undo_page = session->rm->noredo_undo_page_info.undo_rid.page_id;
        rd.undo_slot = session->rm->noredo_undo_page_info.undo_rid.slot;
    }

    /*
     * alloc new dir for cross update insert,
     * otherwise,we can not judge if it is self updated row
     */
    rd.new_dir = (cursor->action == CURSOR_ACTION_UPDATE && !row->is_migr);
    rd.aligned = 0;

    heap_insert_into_page(session, page, row, &undo, &rd, &slot);
    cursor->rowid.slot = slot;

    /* do not write undo for bulkload with nologging hint */
    if (cursor->nologging_type != SESSION_LEVEL) {
        table_t *table = (table_t *)cursor->table;
        undo.snapshot.contain_subpartno = (IS_PART_TABLE(table) && IS_COMPART_TABLE(table->part_table));
        undo.type = UNDO_HEAP_INSERT;
        undo.size = undo_part_locate_size(table);
        undo.rowid = cursor->rowid;
        undo.data = (char *)&cursor->part_loc;
        // cursor->ssn is from session->xact_ssn(uint32) or stmt->xact_ssn(uint32) for not temp table
        undo.ssn = (uint32)cursor->ssn;
        undo_write(session, &undo, need_redo, !cursor->logging);
    }

    if (need_redo && cursor->logging) {
        log_encrypt_prepare(session, page->head.type, need_encrypt);
        log_put(session, RD_HEAP_INSERT, &rd, OFFSET_OF(rd_heap_insert_t, data), entry_flag);
        log_append_data(session, row, row->size);
    }
   
    uint8 owner_list = heap_get_owner_list(session, (heap_segment_t *)heap->segment, page->free_size);
    session->change_list = owner_list - (uint8)page->map.list_id;
    buf_leave_page(session, GS_TRUE);

    log_atomic_op_end(session);

    heap_try_change_map(session, heap, page_id);

    return GS_SUCCESS;
}

static status_t heap_enter_chain_pages(knl_session_t *session, knl_cursor_t *cursor,
                                       chain_row_assist_t *cra, uint32 slot, bool32 *diff_page)
{
    row_head_t *row = (row_head_t *)cra[slot].row;
    heap_t *heap = CURSOR_HEAP(cursor);
    heap_segment_t *segment = HEAP_SEGMENT(session, heap->entry, heap->segment);
    uint32 cost_size = heap_calc_insert_cost(session, segment, row->size, GS_FALSE);
    uint32 real_size = heap_calc_insert_relsize(GS_FALSE, row);
    page_id_t prev_pageid = GET_ROWID_PAGE(cra[slot - 1].rid);
    page_id_t page_id;

    for (;;) {
        if (heap_enter_insert_page(session, cursor, GS_FALSE, row, &page_id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);

        if (session->canceled) {
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            return GS_ERROR;
        }

        if (session->killed) {
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            return GS_ERROR;
        }

        log_atomic_op_begin(session);
        log_set_group_nolog_insert(session, cursor->logging);
        *diff_page = !IS_SAME_PAGID(page_id, prev_pageid);
        if (*diff_page) {
            buf_enter_page(session, prev_pageid, LATCH_MODE_X, ENTER_PAGE_NORMAL);
        }

        buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
        heap_page_t *page = (heap_page_t *)CURR_PAGE(session);

        if (heap_insert_size_invalid(page, cost_size, real_size)) {
            buf_leave_page(session, GS_FALSE);
            if (*diff_page) {
                buf_leave_page(session, GS_FALSE);
            }
            log_atomic_op_end(session);
            continue;
        }

        if (page->itls == 0) {
            heap_init_page_itls(session, cursor, segment, page, cost_size);
        }

        SET_ROWID_PAGE(&cra[slot].rid, page_id);
        break;
    }

    return GS_SUCCESS;
}

static status_t heap_insert_chain_row(knl_session_t *session, knl_cursor_t *cursor, heap_t *heap,
                                      chain_row_assist_t *cra, uint32 slot)
{
    rd_set_link_t rd_set_link;
    uint16 insert_slot;
    rd_heap_insert_t rd;
    dc_entity_t *entity = cursor->dc_entity;
    bool32 has_logic = LOGIC_REP_DB_ENABLED(session) && dc_replication_enabled(session, entity, cursor->part_loc);
    uint8 entry_flag = has_logic ? LOG_ENTRY_FLAG_WITH_LOGIC_OID : LOG_ENTRY_FLAG_NONE;
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(heap->cipher_reserve_size);
    bool32 diff_page = GS_FALSE;

    knl_panic_log(slot > 0, "No available slot, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);

    if (heap_enter_chain_pages(session, cursor, cra, slot, &diff_page) != GS_SUCCESS) {
        return GS_ERROR;
    }

    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    rd.undo_page = INVALID_UNDO_PAGID;
    rd.undo_slot = 0;
    rd.ssn = 0;
    rd.aligned = 0;

    row_head_t *row = (row_head_t *)cra[slot].row;
    heap_insert_into_page_migr(session, page, row, &rd, &insert_slot);
    cra[slot].rid.slot = insert_slot;

    if (cursor->logging && IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        log_encrypt_prepare(session, page->head.type, need_encrypt);
        log_put(session, RD_HEAP_INSERT_MIGR, &rd, OFFSET_OF(rd_heap_insert_t, data), entry_flag);
        log_append_data(session, row, row->size);
    }

    uint8 owner_list = heap_get_owner_list(session, (heap_segment_t *)heap->segment, page->free_size);
    session->change_list = owner_list - (uint8)page->map.list_id;
    if (diff_page) {
        buf_leave_page(session, GS_TRUE);
    }

    // set prev link info
    page = (heap_page_t *)CURR_PAGE(session);
    row_dir_t *dir = heap_get_dir(page, (uint32)cra[slot - 1].rid.slot);
    row = HEAP_GET_ROW(page, dir);

    rowid_t *link_rid = (rowid_t *)(HEAP_LOC_LINK_RID(row));
    *link_rid = cra[slot].rid;

    if (cursor->logging && IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        rd_set_link.slot = (uint16)cra[slot - 1].rid.slot;
        rd_set_link.link_rid = cra[slot].rid;
        rd_set_link.aligned = 0;
        log_put(session, RD_HEAP_SET_LINK, &rd_set_link, sizeof(rd_set_link), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);
    log_atomic_op_end(session);

    heap_try_change_map(session, heap, GET_ROWID_PAGE(cra[slot].rid));

    // set cursor chain info
    row_chains_info_t *chain_info = (row_chains_info_t *)cursor->chain_info;
    row_chain_t *chain = &chain_info->chains[slot - 1];
    chain->chain_rid = cra[slot].rid;

    return GS_SUCCESS;
}

status_t heap_chain_insert(knl_session_t *session, knl_cursor_t *cursor)
{
    heap_t *heap = CURSOR_HEAP(cursor);
    row_head_t *row = cursor->row;
    uint16 max_chains;
    chain_row_assist_t cra[HEAP_INSERT_MAX_CHAIN_COUNT + 1];
    errno_t ret;
    uint8 cipher_reserve_size = heap->cipher_reserve_size;

    CM_SAVE_STACK(session->stack);
    ret = memset_sp(cra, sizeof(cra), 0, sizeof(cra));
    knl_securec_check(ret);

    /* worst case is double of the row->size / HEAP_MAX_ROW_SIZE(session) */
    max_chains = (uint16)(row->size / (HEAP_MAX_ROW_SIZE(session) - cipher_reserve_size) + 1) * 2 + 1;

    for (uint16 i = 0; i < max_chains; i++) {
        cra[i].row = (row_head_t *)cm_push(session->stack, HEAP_MAX_MIGR_ROW_SIZE(session));
    }

    cursor->chain_count = (uint8)heap_split_chain_row(session, cursor, cra, max_chains, GS_TRUE);

    // insert the link row
    if (heap_insert_row(session, cursor, heap, cra[0].row) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    cra[0].rid = cursor->rowid;

    // now, insert the following chain rows
    for (uint8 i = 1; i <= cursor->chain_count; i++) {
        if (heap_insert_chain_row(session, cursor, heap, cra, i) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

status_t heap_convert_insert(knl_session_t *session, knl_cursor_t *cursor, uint32 max_row_len)
{
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    uint32 scan_id = 0;

    if (!entity->contain_lob) {
        GS_THROW_ERROR(ERR_RECORD_SIZE_OVERFLOW, "insert row", cursor->row->size, max_row_len);
        return GS_ERROR;
    }

    if (IS_PART_TABLE(cursor->table)) {
        table_part_t *table_part = TABLE_GET_PART((table_t *)(cursor->table), cursor->part_loc.part_no);
        if (IS_PARENT_TABPART(&table_part->desc)) {
            table_part_t *table_subpart = PART_GET_SUBENTITY(((table_t *)(cursor->table))->part_table,
                table_part->subparts[cursor->part_loc.subpart_no]);
            if (!table_subpart->desc.is_csf) {
                GS_THROW_ERROR(ERR_RECORD_SIZE_OVERFLOW, "insert row", cursor->row->size, max_row_len);
                return GS_ERROR;
            }
        } else {
            if (!table_part->desc.is_csf) {
                GS_THROW_ERROR(ERR_RECORD_SIZE_OVERFLOW, "insert row", cursor->row->size, max_row_len);
                return GS_ERROR;
            }
        }
    } else {
        if (!entity->table.desc.is_csf) {
            GS_THROW_ERROR(ERR_RECORD_SIZE_OVERFLOW, "insert row", cursor->row->size, max_row_len);
            return GS_ERROR;
        }
    }

    while (scan_id != entity->column_count - 1) {
        cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, NULL);
        if (knl_reconstruct_lob_row(session, entity, cursor, &scan_id, entity->column_count - 1) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (cursor->row->size < max_row_len) {
            return GS_SUCCESS;
        }
    }

    GS_THROW_ERROR(ERR_RECORD_SIZE_OVERFLOW, "insert row", cursor->row->size, max_row_len);
    return GS_ERROR;
}

static status_t heap_fetch_entry(knl_session_t *session, knl_cursor_t *cursor, heap_t *heap)
{
    if (IS_PART_TABLE(cursor->table)) {
        if (!heap->loaded) {
            if (dc_load_table_part_segment(session, cursor->dc_entity,
                (table_part_t *)cursor->table_part) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (heap->segment == NULL) {
            if (heap_create_part_entry(session, (table_part_t *)cursor->table_part, g_invalid_part_loc) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    } else {
        cursor->part_loc.part_no = GS_INVALID_ID32;
        if (heap->segment == NULL) {
            if (heap_create_entry(session, heap) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

status_t heap_insert(knl_session_t *session, knl_cursor_t *cursor)
{
    heap_t *heap = CURSOR_HEAP(cursor);
    row_head_t *row = cursor->row;
    dc_entity_t *entity = cursor->dc_entity;
    uint16 column_count = ROW_COLUMN_COUNT(row);
    uint32 max_row_len = heap_table_max_row_len(cursor->table, GS_MAX_ROW_SIZE, cursor->part_loc);
    bool32 has_logic = LOGIC_REP_DB_ENABLED(session) && dc_replication_enabled(session, entity, cursor->part_loc);
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);

    CM_ASSERT(!DB_IS_CLUSTER(session));

    SYNC_POINT(session, "SP_B4_HEAP_INSERT");
    knl_panic_log(cursor->is_valid, "cursor is invalid, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);

    if (row->size > max_row_len) {
        if (heap_convert_insert(session, cursor, max_row_len) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    row->size = MAX(row->size, HEAP_MIN_ROW_SIZE);

    if (lock_table_shared(session, cursor->dc_entity, LOCK_INF_WAIT) != GS_SUCCESS) {
        return GS_ERROR;
    }

    cursor->xid = (cursor->xid != session->rm->xid.value) ? session->rm->xid.value : cursor->xid;

    if (heap_fetch_entry(session, cursor, heap) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cursor->nologging_type != SESSION_LEVEL) {
        if (undo_prepare(session, undo_part_locate_size(cursor->table), need_redo,
            GS_FALSE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    SET_ROWID_PAGE(&cursor->link_rid, INVALID_PAGID);
    cursor->chain_count = 0;

    if (has_logic && need_redo) {
        log_atomic_op_begin(session);
        log_put(session, RD_LOGIC_REP_INSERT, &column_count, sizeof(uint16), LOG_ENTRY_FLAG_WITH_LOGIC_OID);
        heap_append_logic_data(session, cursor, GS_FALSE);
        log_atomic_op_end(session);
    }

    if (row->size <= HEAP_MAX_ROW_SIZE(session) - heap->cipher_reserve_size) {
        if (heap_insert_row(session, cursor, heap, row) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        if (heap_chain_insert(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    SYNC_POINT(session, "SP_AFTER_HEAP_INSERT");

    return GS_SUCCESS;
}

static void heap_get_partloc_from_udrow(const undo_row_t *ud_row, knl_part_locate_t *part_loc)
{
    if (ud_row->contain_subpartno) {
        *part_loc = *(knl_part_locate_t *)ud_row->data;
    } else {
        part_loc->part_no = *(uint32 *)ud_row->data;
        part_loc->subpart_no = GS_INVALID_ID32;
    }
}

void heap_undo_insert(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot,
                      knl_dictionary_t *dc, heap_undo_assist_t *heap_assist)
{
    heap_page_t *page = NULL;
    row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    rowid_t rid;
    rd_heap_undo_t redo;
    uint8 owner_list;
    itl_t *itl = NULL;
    rowid_t link_rid;
    uint16 slot;
    uint8 page_count = 0;
    heap_t *heap = NULL;
    knl_part_locate_t part_loc;

    rid = ud_row->rowid;
    heap_get_partloc_from_udrow(ud_row, &part_loc);
    if (!spc_validate_page_id(session, GET_ROWID_PAGE(rid))) {
        heap_assist->rows = 0;
        return;
    }
    buf_enter_page(session, GET_ROWID_PAGE(rid), LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE(session);
    if (page_is_damaged(&page->head)) {
        buf_leave_page(session, GS_FALSE);
        return;
    }

    dir = heap_get_dir(page, (uint32)rid.slot);
    knl_panic_log(IS_SAME_PAGID(dir->undo_page, AS_PAGID(ud_page->head.id)),
                  "dir's undo_page and ud_page are not same, panic info: current page %u-%u type %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
    knl_panic_log(dir->undo_slot == ud_slot, "dir's undo_slot is not equal ud_slot, panic info: "
                  "page %u-%u type %u dir undo_slot %u ud_slot %u", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, dir->undo_slot, ud_slot);
    row = HEAP_GET_ROW(page, dir);
    knl_panic_log(ROW_ITL_ID(row) != GS_INVALID_ID8, "row's itl id is invalid, panic info: page %u-%u type %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);

    heap = dc_get_heap(session, page->uid, page->oid, part_loc, dc);

    bool32 is_link = row->is_link;
    if (is_link) {
        if (!heap_assist->need_latch) {
            heap_assist->heap = heap;
            heap_assist->need_latch = GS_TRUE;
            buf_leave_page(session, GS_FALSE);
            return;
        }
    }

    itl = heap_get_itl(page, ROW_ITL_ID(row));
    knl_panic_log(itl->xid.value == session->rm->xid.value, "the xid of itl and rm are not equal, panic info: "
                  "page %u-%u type %u itl xid %llu rm xid %llu", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, itl->xid.value, session->rm->xid.value);

    // if no other rows followed, we can free the row directly,
    // otherwise, the row space would be free when compacting page.
    if (page->free_begin == dir->offset + row->size) {
        page->free_begin = dir->offset;
    }

    if (is_link) {
        link_rid = *HEAP_LOC_LINK_RID(row);
        // free_size is less than DEFAULT_PAGE_SIZE(8192), so the sum is less than max value(65535) of uint16
        page->free_size += HEAP_MIN_ROW_SIZE;
    } else {
        // free_size and row->size are both less than DEFAULT_PAGE_SIZE(8192),
        // so the sum is less than max value(65535) of uint16
        page->free_size += row->size;
    }

    page->rows--;

    dir->scn = ud_row->scn;
    dir->is_owscn = ud_row->is_owscn;
    dir->undo_page = ud_row->prev_page;
    dir->undo_slot = ud_row->prev_slot;

    ROW_SET_ITL_ID(row, GS_INVALID_ID8);
    row->is_deleted = 1;
    dir->is_free = 1;
    dir->next_slot = page->first_free_dir;
    page->first_free_dir = (uint16)rid.slot;

    redo.slot = (uint16)rid.slot;
    redo.scn = dir->scn;
    redo.is_owscn = (uint8)dir->is_owscn;
    redo.undo_page = dir->undo_page;
    redo.undo_slot = dir->undo_slot;
    redo.aligned = 0;
    if (SPACE_IS_LOGGING(SPACE_GET(session, heap->segment->space_id))) {
        log_put(session, RD_HEAP_UNDO_INSERT, &redo, sizeof(rd_heap_undo_t), LOG_ENTRY_FLAG_NONE);
    }
    owner_list = heap_get_owner_list(session, (heap_segment_t *)heap->segment, page->free_size);
    heap_assist->change_list[page_count] = owner_list - (uint8)page->map.list_id;
    heap_assist->page_id[page_count] = GET_ROWID_PAGE(rid);
    page_count++;
    buf_leave_page(session, GS_TRUE);

    if (is_link) {
        while (!IS_INVALID_ROWID(link_rid)) {
            buf_enter_page(session, GET_ROWID_PAGE(link_rid), LATCH_MODE_X, ENTER_PAGE_NORMAL);
            page = (heap_page_t *)CURR_PAGE(session);
            if (page_is_damaged(&page->head)) {
                buf_leave_page(session, GS_FALSE);
                return;
            }
            dir = heap_get_dir(page, (uint32)link_rid.slot);
            knl_panic_log(!dir->is_free, "dir is free, panic info: page %u-%u type %u", AS_PAGID(page->head.id).file,
                          AS_PAGID(page->head.id).page, page->head.type);
            row = HEAP_GET_ROW(page, dir);

            dir->is_free = 1;
            dir->next_slot = page->first_free_dir;
            // free_size and row->size are both less than DEFAULT_PAGE_SIZE(8192),
            // so the sum is less than max value(65535) of uint16
            page->free_size += row->size;
            page->rows--;
            page->first_free_dir = (uint16)link_rid.slot;

            slot = (uint16)link_rid.slot;
            if (SPACE_IS_LOGGING(SPACE_GET(session, heap->segment->space_id))) {
                log_put(session, RD_HEAP_UNDO_INSERT_LINK, &slot, sizeof(uint16), LOG_ENTRY_FLAG_NONE);
            }
            owner_list = heap_get_owner_list(session, (heap_segment_t *)heap->segment, page->free_size);
            heap_assist->change_list[page_count] = owner_list - (uint8)page->map.list_id;
            heap_assist->page_id[page_count] = GET_ROWID_PAGE(link_rid);
            page_count++;
            link_rid = *(rowid_t *)HEAP_LOC_LINK_RID(row);
            buf_leave_page(session, GS_TRUE);
        }
    }

    heap_assist->heap = heap;
    heap_assist->rows = page_count;
}

void heap_undo_insert_migr(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot,
                           knl_dictionary_t *dc, heap_undo_assist_t *heap_assist)
{
    rd_heap_undo_t redo;
    uint8 page_count = 0;
    rowid_t rid = ud_row->rowid;
    knl_part_locate_t part_loc = { .part_no = GS_INVALID_ID32,
        .subpart_no = GS_INVALID_ID32 };

    heap_get_partloc_from_udrow(ud_row, &part_loc);
    if (!spc_validate_page_id(session, GET_ROWID_PAGE(rid))) {
        heap_assist->rows = 0;
        return;
    }

    buf_enter_page(session, GET_ROWID_PAGE(rid), LATCH_MODE_X, ENTER_PAGE_NORMAL);
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    if (page_is_damaged(&page->head)) {
        buf_leave_page(session, GS_FALSE);
        return;
    }

    row_dir_t *dir = heap_get_dir(page, (uint32)rid.slot);
    row_head_t *row = HEAP_GET_ROW(page, dir);
    heap_t *heap = dc_get_heap(session, page->uid, page->oid, part_loc, dc);

    // if no other rows followed, we can free the row directly,
    // otherwise, the row space would be free when compacting page.
    if (page->free_begin == dir->offset + row->size) {
        page->free_begin = dir->offset;
    }

    // free_size and row->size are both less than DEFAULT_PAGE_SIZE(8192),
    // so the sum is less than max value(65535) of uint16
    page->free_size += row->size;

    page->rows--;

    dir->scn = ud_row->scn;
    dir->is_owscn = ud_row->is_owscn;
    dir->undo_page = ud_row->prev_page;
    dir->undo_slot = ud_row->prev_slot;

    ROW_SET_ITL_ID(row, GS_INVALID_ID8);
    row->is_deleted = 1;
    dir->is_free = 1;
    dir->next_slot = page->first_free_dir;
    page->first_free_dir = (uint16)rid.slot;

    redo.slot = (uint16)rid.slot;
    redo.scn = dir->scn;
    redo.is_owscn = (uint8)dir->is_owscn;
    redo.undo_page = dir->undo_page;
    redo.undo_slot = dir->undo_slot;
    redo.aligned = 0;
    if (SPACE_IS_LOGGING(SPACE_GET(session, heap->segment->space_id))) {
        log_put(session, RD_HEAP_UNDO_INSERT, &redo, sizeof(rd_heap_undo_t), LOG_ENTRY_FLAG_NONE);
    }
    uint8 owner_list = heap_get_owner_list(session, (heap_segment_t *)heap->segment, page->free_size);
    heap_assist->change_list[page_count] = owner_list - (uint8)page->map.list_id;
    heap_assist->page_id[page_count] = GET_ROWID_PAGE(rid);
    page_count++;

    buf_leave_page(session, GS_TRUE);

    heap_assist->heap = heap;
    heap_assist->rows = page_count;
}

void heap_undo_update_linkrid(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot)
{
    rowid_t rid = ud_row->rowid;
    char *undo_data = ud_row->data;
    rd_heap_undo_t redo;
    uint16 ud_data_size = ud_row->data_size;
    page_id_t page_id = GET_ROWID_PAGE(rid);
    if (!spc_validate_page_id(session, page_id)) {
        return;
    }

    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    if (page_is_damaged(&page->head)) {
        buf_leave_page(session, GS_FALSE);
        return;
    }
    row_dir_t *dir = heap_get_dir(page, (uint32)rid.slot);
    knl_panic_log(!dir->is_free, "dir is free, panic info: page %u-%u type %u", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type);
    knl_panic_log(IS_SAME_PAGID(dir->undo_page, AS_PAGID(ud_page->head.id)),
                  "dir's undo_page and ud_page are not same, panic info: current page %u-%u type %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
    knl_panic_log(dir->undo_slot == ud_slot, "dir's undo_slot is not equal ud_slot, panic info: "
                  "page %u-%u type %u dir undo_slot %u ud_slot %u", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, dir->undo_slot, ud_slot);
    row_head_t *row = HEAP_GET_ROW(page, dir);
    if (!row->is_migr) {
        knl_panic_log(ROW_ITL_ID(row) != GS_INVALID_ID8, "row itl id is invalid, panic info: page %u-%u type %u",
                      AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
        itl_t *itl = heap_get_itl(page, ROW_ITL_ID(row));
        knl_panic_log(itl->is_active, "itl is inactive, panic info: page %u-%u type %u", AS_PAGID(page->head.id).file,
                      AS_PAGID(page->head.id).page, page->head.type);
        knl_panic_log(itl->xid.value == session->rm->xid.value, "the xid of itl and rm are not equal, panic info: "
                      "page %u-%u type %u itl xid %llu rm xid %llu", AS_PAGID(page->head.id).file,
                      AS_PAGID(page->head.id).page, page->head.type, itl->xid.value, session->rm->xid.value);
    }

    dir->is_owscn = ud_row->is_owscn;
    dir->undo_page = ud_row->prev_page;
    dir->undo_slot = ud_row->prev_slot;

    if (ud_row->is_xfirst) {
        dir->scn = ud_row->scn;
        ROW_SET_ITL_ID(row, GS_INVALID_ID8);
    } else {
        dir->scn = ud_row->ssn;
    }

    redo.slot = (uint16)rid.slot;
    redo.is_xfirst = (uint8)ud_row->is_xfirst;
    redo.is_owscn = (uint8)dir->is_owscn;
    redo.scn = dir->scn;
    redo.undo_page = dir->undo_page;
    redo.undo_slot = dir->undo_slot;
    redo.aligned = 0;

    if (SPC_IS_LOGGING_BY_PAGEID(session, page_id)) {
        log_put(session, RD_HEAP_UNDO_CHANGE_DIR, &redo, sizeof(rd_heap_undo_t), LOG_ENTRY_FLAG_NONE);
        log_append_data(session, dir, sizeof(row_dir_t));
    }

    *HEAP_LOC_LINK_RID(row) = *(rowid_t *)ud_row->data;

    uint16 slot = (uint16)rid.slot;

    if (SPC_IS_LOGGING_BY_PAGEID(session, page_id)) {
        log_put(session, RD_HEAP_UNDO_UPDATE_LINKRID, &slot, sizeof(uint16), LOG_ENTRY_FLAG_NONE);
        log_append_data(session, undo_data, ud_data_size);
    }

    buf_leave_page(session, GS_TRUE);
}

void heap_undo_delete_migr(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot,
                           knl_dictionary_t *dc, heap_undo_assist_t *heap_assist)
{
    heap_page_t *page = NULL;
    row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    rowid_t rid;
    rd_heap_undo_t redo;
    uint8 owner_list;
    uint8 page_count = 0;
    heap_t *heap = NULL;
    itl_t *itl = NULL;

    knl_part_locate_t part_loc;
    heap_get_partloc_from_udrow(ud_row, &part_loc);
    rid = *(rowid_t *)(ud_row->data + (ud_row->contain_subpartno ? sizeof(knl_part_locate_t) : sizeof(uint32)));
    if (!spc_validate_page_id(session, GET_ROWID_PAGE(rid))) {
        heap_assist->rows = 0;
        return;
    }
    buf_enter_page(session, GET_ROWID_PAGE(rid), LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE(session);
    if (page_is_damaged(&page->head)) {
        buf_leave_page(session, GS_FALSE);
        return;
    }

    dir = heap_get_dir(page, (uint32)rid.slot);
    row = HEAP_GET_ROW(page, dir);

    heap = dc_get_heap(session, page->uid, page->oid, part_loc, dc);

    // if no other rows followed, we can free the row directly,
    // otherwise, the row space would be free when compacting page.
    if (page->free_begin == dir->offset + row->size) {
        page->free_begin = dir->offset;
    }

    // free_size and row->size are both less than DEFAULT_PAGE_SIZE(8192),
    // so the sum is less than max value(65535) of uint16
    page->free_size += row->size;

    page->rows--;

    dir->scn = ud_row->scn;
    dir->is_owscn = 0;
    dir->undo_page = INVALID_UNDO_PAGID;
    dir->undo_slot = 0;

    ROW_SET_ITL_ID(row, GS_INVALID_ID8);
    row->is_deleted = 1;
    dir->is_free = 1;
    dir->next_slot = page->first_free_dir;
    page->first_free_dir = (uint16)rid.slot;

    redo.slot = (uint16)rid.slot;
    redo.scn = dir->scn;
    redo.is_owscn = (uint8)dir->is_owscn;
    redo.undo_page = dir->undo_page;
    redo.undo_slot = dir->undo_slot;
    redo.aligned = 0;
    if (SPACE_IS_LOGGING(SPACE_GET(session, heap->segment->space_id))) {
        log_put(session, RD_HEAP_UNDO_INSERT, &redo, sizeof(rd_heap_undo_t), LOG_ENTRY_FLAG_NONE);
    }
    owner_list = heap_get_owner_list(session, (heap_segment_t *)heap->segment, page->free_size);
    heap_assist->change_list[page_count] = owner_list - (uint8)page->map.list_id;
    heap_assist->page_id[page_count] = GET_ROWID_PAGE(rid);
    page_count++;

    buf_leave_page(session, GS_TRUE);

    heap_assist->heap = heap;
    heap_assist->rows = page_count;

    rid = ud_row->rowid;

    buf_enter_page(session, GET_ROWID_PAGE(rid), LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE(session);
    if (page_is_damaged(&page->head)) {
        buf_leave_page(session, GS_FALSE);
        return;
    }

    dir = heap_get_dir(page, (uint32)rid.slot);
    knl_panic_log(IS_SAME_PAGID(dir->undo_page, AS_PAGID(ud_page->head.id)),
                  "dir's undo_page and ud_page are not same, panic info: current page %u-%u type %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
    knl_panic_log(dir->undo_slot == ud_slot, "dir's undo_slot is not equal ud_slot, panic info: "
                  "page %u-%u type %u dir undo_slot %u ud_slot %u", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, dir->undo_slot, ud_slot);
    row = HEAP_GET_ROW(page, dir);
    knl_panic_log(ROW_ITL_ID(row) != GS_INVALID_ID8, "row's itl id is invalid, panic info: page %u-%u type %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
    itl = heap_get_itl(page, ROW_ITL_ID(row));
    knl_panic_log(itl->is_active, "itl is inactive, panic info: page %u-%u type %u", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type);
    knl_panic_log(itl->xid.value == session->rm->xid.value, "the xid of itl and rm are not same, panic info: "
                  "page %u-%u type %u itl xid %llu rm xid %llu", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, itl->xid.value, session->rm->xid.value);

    dir->is_owscn = ud_row->is_owscn;
    dir->undo_page = ud_row->prev_page;
    dir->undo_slot = ud_row->prev_slot;

    // to keep consistent read, only after rollback, can we set the dir itl_id to invalid.
    if (ud_row->is_xfirst) {
        dir->scn = ud_row->scn;
        ROW_SET_ITL_ID(row, GS_INVALID_ID8);
    } else {
        dir->scn = ud_row->ssn;
    }
    row->is_deleted = 0;
    page->rows++;

    itl->fsc -= row->size;  // itl->fsc is larger than the releated row's size

    redo.slot = (uint16)rid.slot;
    redo.is_xfirst = (uint8)ud_row->is_xfirst;
    redo.is_owscn = (uint8)dir->is_owscn;
    redo.scn = dir->scn;
    redo.undo_page = dir->undo_page;
    redo.undo_slot = dir->undo_slot;
    redo.aligned = 0;
    if (SPACE_IS_LOGGING(SPACE_GET(session, heap->segment->space_id))) {
        log_put(session, RD_HEAP_UNDO_DELETE, &redo, sizeof(rd_heap_undo_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);
}

void heap_update_prepare(knl_session_t *session, row_head_t *row, uint16 *offsets, uint16 *lens,
                         uint16 data_size, heap_update_assist_t *ua)
{
    uint16 i;
    uint16 col_id;
    int16 new_col_size, old_col_size;
    int16 inc_head;
    bool32 inplace = GS_TRUE;
    row_head_t *update_info = NULL;
    uint32 uid = 0;
    knl_cal_col_size_t  calc_col_size_func = row->is_csf ? heap_calc_csf_col_actualsize : heap_calc_bmp_col_actualsize;
    int16 null_col_size = heap_calc_null_row_size(row);
    knl_calc_row_head_inc_size_t calc_row_head_inc_func = row->is_csf ?
        heap_calc_csf_row_head_inc_size : heap_calc_bmp_row_head_inc_size;

    update_info = (row_head_t *)ua->info->data;
    knl_panic_log(row->is_csf == update_info->is_csf, "the csf status are not same about row and update_info, panic "
                  "info: row's csf status %u update_info's csf status %u.", row->is_csf, update_info->is_csf);

    ua->row = row;
    ua->offsets = offsets;
    ua->lens = lens;
    ua->data_size = data_size;

    // column_count, column array, row head, extra bitmap bytes
    ua->inc_size = 0;
    ua->undo_size = (uint16)UNDO_ROW_HEAD_SIZE;
    // the max value of ua->info->count is GS_MAX_COLUMNS(4096)
    ua->undo_size += sizeof(uint16) + ua->info->count * sizeof(uint16);
    ua->undo_size += cm_row_init_size(row->is_csf, ua->info->count);

    for (i = 0; i < ua->info->count; i++) {
        col_id = ua->info->columns[i];
        new_col_size = calc_col_size_func((row_head_t *)ua->info->data, ua->info->lens, i);

        if (col_id >= ua->old_cols) {
            old_col_size = 0;
        } else {
            old_col_size = calc_col_size_func(row, lens, col_id);
            ua->undo_size += old_col_size;

            // inc uid to the begining of new added columns
            uid++;
        }

        if (new_col_size != old_col_size) {
            inplace = GS_FALSE;
            ua->inc_size += new_col_size - old_col_size;
        }
    }

    /*
     * calc null column inc row size for csf
     * null_col_size is 0 for bitmap row, 1 for csf row
     */
    for (i = ua->old_cols; i < ua->new_cols; i++) {
        if (uid < ua->info->count && i == ua->info->columns[uid]) {
            uid++;
            continue;
        } else {
            new_col_size = null_col_size;
            old_col_size = 0;
        }

        if (new_col_size != old_col_size) {
            inplace = GS_FALSE;
            ua->inc_size += new_col_size - old_col_size;
        }
    }

    if (inplace == GS_TRUE) {
        ua->new_size = CM_ALIGN4(data_size);
        ua->mode = UPDATE_INPLACE;
        return;
    }

    inc_head = calc_row_head_inc_func(ua->new_cols, ua->old_cols);
    knl_panic_log(inc_head >= 0, "inc_head is smaller than zero, panic info: inc_head %u", inc_head);

    ua->inc_size += inc_head;
    // update column size is less than GS_MAX_ROW_SIZE(64000),
    // so ua->inc_size will not exceed  GS_MAX_ROW_SIZE, the sum is less than max value of uint32
    ua->new_size = CM_ALIGN4((uint32)(data_size + ua->inc_size));

    if (ua->new_size < PCRH_MIN_ROW_SIZE) {
        ua->inc_size += (PCRH_MIN_ROW_SIZE - ua->new_size);
        ua->new_size = PCRH_MIN_ROW_SIZE;
    }
    ua->mode = UPDATE_INPAGE;
}

void heap_reorganize_with_update(row_head_t *row, uint16 *offsets, uint16 *lens,
                                 knl_update_info_t *info, row_assist_t *new_ra)
{
    uint16 i, uid, col_count;
    knl_put_row_column_t put_col_func = new_ra->is_csf ? heap_put_csf_row_column : heap_put_bmp_row_column;

    knl_panic(new_ra->head != NULL);
    knl_panic(info != NULL);
    knl_panic(info->data != NULL);
    knl_panic(info->lens != NULL);
    knl_panic(info->offsets != NULL);
    knl_panic(row != NULL);
    knl_panic(offsets != NULL);
    knl_panic(lens != NULL);

    uid = 0;
    col_count = ROW_COLUMN_COUNT(new_ra->head);

    for (i = 0; i < col_count; i++) {
        if (uid < info->count && i == info->columns[uid]) {
            put_col_func((row_head_t *)info->data, info->offsets, info->lens, uid, new_ra);
            uid++;
        } else if (i < ROW_COLUMN_COUNT(row)) {
            put_col_func(row, offsets, lens, i, new_ra);
        } else {
            row_put_null(new_ra);
        }
    }

    if (new_ra->head->size < PCRH_MIN_ROW_SIZE) {
        new_ra->head->size = PCRH_MIN_ROW_SIZE;
    }
    row_end(new_ra);
}

static inline void heap_update_inplace_csf_column(row_head_t *row, uint16 col_id, uint16 *offsets, uint16 *lens,
                                                  knl_update_info_t *ua_info, uint16 update_col_id)
{
    errno_t ret;

    // Modify the column length in column header.
    // Notice: only var type can happen, so no need to check the column type.
    if (ua_info->lens[update_col_id] != 0) {
        ret = memcpy_sp((char *)row + offsets[col_id], ua_info->lens[update_col_id],
                        ua_info->data + ua_info->offsets[update_col_id], ua_info->lens[update_col_id]);
        knl_securec_check(ret);
    } else {
        *(uint8 *)((char *)row + offsets[col_id] - 1) = 0;
    }
}

static inline void heap_update_inplace_bmp_column(row_head_t *row, uint16 col_id, uint16 *offsets, uint16 *lens,
                                                  knl_update_info_t *ua_info, uint16 update_col_id)
{
    if (ua_info->lens[update_col_id] != lens[col_id]) {
        knl_panic(CM_ALIGN4(ua_info->lens[update_col_id] + sizeof(uint16)) == CM_ALIGN4(lens[col_id] + sizeof(uint16)));
        *(uint16 *)((char *)row + offsets[col_id] - ROW_COL_HEADER_LEN) = ua_info->lens[update_col_id];
    }

    // Modify the column length in column header.
    // Notice: only var type can happen, so no need to check the column type.
    if (ua_info->lens[update_col_id] != 0) {
        errno_t ret = memcpy_sp((char *)row + offsets[col_id], ua_info->lens[update_col_id],
            ua_info->data + ua_info->offsets[update_col_id], ua_info->lens[update_col_id]);
        knl_securec_check(ret);
    }
}

void heap_update_inplace(knl_session_t *session, uint16 *offsets, uint16 *lens,
                         knl_update_info_t *ua_info, row_head_t *row)
{
    uint16 col_id, i;
    knl_update_inplace_column_t  update_func = row->is_csf ?
        heap_update_inplace_csf_column : heap_update_inplace_bmp_column;

    knl_panic_log(ua_info != NULL, "ua_info is NULL.");
    row->is_changed = 1;

    for (i = 0; i < ua_info->count; i++) {
        col_id = ua_info->columns[i];
        if (ua_info->lens[i] == GS_NULL_VALUE_LEN) {
            /* for csf row format and number column type, zero or null has the same length, but
             * different column flags, it need to update the column flag
             */
            if (row->is_csf) {
                *(uint8 *)((char *)row + offsets[col_id] - 1) = CSF_NULL_FLAG;
            }
            
            continue;  // skip null value
        }
        update_func(row, col_id, offsets, lens, ua_info, i);
    }
}

void heap_update_inpage(knl_session_t *session, row_head_t *ori_row, uint16 *offsets, uint16 *lens,
                        heap_update_assist_t *ua, heap_page_t *page, uint16 slot)
{
    row_assist_t ra;

    row_dir_t *dir = heap_get_dir(page, slot);
    row_head_t *row = HEAP_GET_ROW(page, dir);
    uint8 itl_id = ROW_ITL_ID(row);
    row_head_t old_row = *(row_head_t *)row;
    rowid_t lnk_rid = *HEAP_LOC_LINK_RID(row);
    ra.is_csf = old_row.is_csf;

    if (ua->inc_size > 0) {
        if (page->free_end - page->free_begin < (uint16)ua->new_size) {
            // set row dir to free, so we can reuse the old row space
            dir->is_free = 1;
            heap_compact_page(session, page);
        }

        dir->offset = page->free_begin;

        /* ua->new_size  is less than page size(8192) for update inpage mode */
        page->free_begin += ua->new_size;
        /* ua->inc_size is less than page free_size for update inpage mode */
        page->free_size -= ua->inc_size;
        knl_panic_log(page->free_begin <= page->free_end, "the page's free size begin is more than end, panic info: "
                      "page %u-%u type %u free_begin %u free_end %u", AS_PAGID(page->head.id).file,
                      AS_PAGID(page->head.id).page, page->head.type, page->free_begin, page->free_end);

        row = HEAP_GET_ROW(page, dir);  // relocate the row position
    }

    if ((ori_row->is_migr) || (old_row.is_migr)) {
        if (ori_row->is_migr) {
            lnk_rid = *HEAP_LOC_LINK_RID(ori_row);
        }
        heap_init_chain_row(session, &ra, (char *)row, ua->new_cols, itl_id, old_row.flags);
        *HEAP_LOC_LINK_RID(row) = lnk_rid;
    } else {
        heap_init_row(session, &ra, (char *)row, ua->new_cols, itl_id, old_row.flags);
    }

    heap_reorganize_with_update(ori_row, offsets, lens, ua->info, &ra);

    if (ua->inc_size > 0) {
        knl_panic_log(row->size == ua->new_size, "the row size is incorrect when row increased size is more than zero,"
                      " panic info: page %u-%u type %u row size %u new_size %u", AS_PAGID(page->head.id).file,
                      AS_PAGID(page->head.id).page, page->head.type, row->size, ua->new_size);
        knl_panic_log(row->size > old_row.size, "the row size is incorrect when row increased size is more than zero, "
                      "panic info: page %u-%u type %u row size %u old_row's size %u", AS_PAGID(page->head.id).file,
                      AS_PAGID(page->head.id).page, page->head.type, row->size, old_row.size);
    } else {
        knl_panic_log(row->size <= old_row.size, "row size is incorrect when row increased size is not more than zero,"
                      " panic info: page %u-%u type %u row size %u old_row's size %u", AS_PAGID(page->head.id).file,
                      AS_PAGID(page->head.id).page, page->head.type, row->size, old_row.size);
        row->size = old_row.size;
    }

    row->is_link = 0;
    row->is_changed = 1;
}

void heap_get_update_undo_data(knl_session_t *session, heap_update_assist_t *ua, undo_data_t *undo,
    uint32 undo_buf_size)
{
    uint16 i;
    uint16 col_id, head_size, col_size;
    heap_undo_update_info_t *info;
    row_assist_t ra;
    char *row_buf = NULL;
    errno_t ret;
    knl_put_row_column_t put_func = ua->row->is_csf ? heap_put_csf_row_column : heap_put_bmp_row_column;
    ra.is_csf = ua->row->is_csf;

    info = (heap_undo_update_info_t *)undo->data;
    info->old_cols = ua->old_cols;
    info->count = ua->info->count;
    /* max value of info->count is GS_MAX_COLUMNS(4096) */
    col_size = info->count * sizeof(uint16);
    ret = memcpy_sp(info->columns, undo_buf_size - (uint32)OFFSET_OF(heap_undo_update_info_t, columns),
        ua->info->columns, col_size);
    knl_securec_check(ret);

    head_size = HEAP_UNDO_UPDATE_INFO_SIZE(ua->info->count);
    row_buf = undo->data + head_size;

    heap_init_row(session, &ra, row_buf, ua->info->count, GS_INVALID_ID8, 0);

    for (i = 0; i < ua->info->count; i++) {
        col_id = ua->info->columns[i];

        if (col_id >= ua->old_cols) {
            row_put_null(&ra);
        } else {
            put_func(ua->row, ua->offsets, ua->lens, col_id, &ra);
        }
    }
    row_end(&ra);

    undo->size = head_size + ra.head->size;
}

static void heap_prepare_split_for_update(knl_session_t *session, knl_cursor_t *cursor, split_assist_t *sa)
{
    knl_update_info_t *info = sa->ua->info;
    row_head_t *row = sa->org_row;
    uint16 row_size = cm_row_init_size(row->is_csf, 0) + sizeof(rowid_t);
    heap_t *heap = CURSOR_HEAP(cursor);
    uint8 cipher_reserve_size = heap->cipher_reserve_size;
    uint16 i;
    uint32 uid = 0;
    uint16 col_len;
    uint16 col_count = 0;
    uint32 row_head_incsize;
    knl_cal_col_size_t  calc_col_size_func = row->is_csf ? heap_calc_csf_col_actualsize : heap_calc_bmp_col_actualsize;
    int16 null_col_size = heap_calc_null_row_size(row);
    knl_calc_row_head_inc_size_t calc_row_head_inc_func = row->is_csf ?
        heap_calc_csf_row_head_inc_size : heap_calc_bmp_row_head_inc_size;

    sa->col_start[0] = 0;
    sa->uid_start[0] = 0;
    sa->split_count = 0;

    for (i = 0; i < sa->ua->new_cols; i++) {
        if (uid < info->count && i == info->columns[uid]) {
            col_len = calc_col_size_func((row_head_t *)info->data, info->lens, uid);
        } else if (i < ROW_COLUMN_COUNT(row)) {
            col_len = calc_col_size_func(row, sa->lens, i);
        } else {
            col_len = null_col_size;
        }

        row_size += col_len;
        col_count++;
        row_head_incsize = calc_row_head_inc_func(col_count, 0);
        if ((uint16)CM_ALIGN4(row_size + row_head_incsize) >
            (uint16)HEAP_MAX_MIGR_ROW_SIZE(session) - cipher_reserve_size) {
            sa->col_start[++sa->split_count] = i;
            sa->uid_start[sa->split_count] = uid;
            // the sum of col_len for a row is less than GS_MAX_ROW_SIZE(64000)
            row_size = cm_row_init_size(row->is_csf, 0) + sizeof(rowid_t) + col_len;
            col_count = 1;
        }

        if (uid < info->count && i == info->columns[uid]) {
            uid++;
        }
    }

    sa->split_count++;
}

static void heap_split_for_update(knl_session_t *session, split_assist_t *sa, uint16 split_no,
                                  row_assist_t *sub_ra, char *buf)
{
    knl_update_info_t *info = sa->ua->info;
    row_head_t *row = sa->org_row;
    uint16 col_count;
    uint16 uid;
    uint16 i;
    knl_put_row_column_t put_col_func = sub_ra->is_csf ? heap_put_csf_row_column : heap_put_bmp_row_column;

    knl_panic_log(split_no < sa->split_count, "split_no is more than current split_count, panic info: "
                  "split_no %u split_count %u.", split_no, sa->split_count);

    if (split_no == sa->split_count - 1) {
        col_count = sa->ua->new_cols - sa->col_start[split_no];  // col_start is less than sa->ua->new_cols
    } else {
        col_count = sa->col_start[split_no + 1] - sa->col_start[split_no];
    }

    uid = sa->uid_start[split_no];

    heap_init_chain_row(session, sub_ra, buf, col_count, GS_INVALID_ID8, 0);

    for (i = sa->col_start[split_no]; i < col_count + sa->col_start[split_no]; i++) {
        if (uid < info->count && i == info->columns[uid]) {
            put_col_func((row_head_t *)info->data, info->offsets, info->lens, uid, sub_ra);
            uid++;
        } else if (i < ROW_COLUMN_COUNT(row)) {
            put_col_func(row, sa->offsets, sa->lens, i, sub_ra);
        } else {
            row_put_null(sub_ra);
        }
    }
    row_end(sub_ra);
}

static status_t heap_split_and_update(knl_session_t *session, knl_cursor_t *cursor, split_assist_t *sa,
                                      migr_row_assist_t *migr_assist, bool32 is_chain, rowid_t *next_rid)
{
    rowid_t *link_rid = NULL;
    row_assist_t ra;
    char *buf = NULL;
    migr_row_assist_t new_ma;
    ra.is_csf = cursor->row->is_csf;

    buf = (char *)cm_push(session->stack, HEAP_MAX_MIGR_ROW_SIZE(session));
    for (uint16 i = 0; i < sa->split_count; i++) {
        heap_split_for_update(session, sa, i, &ra, buf);
        link_rid = HEAP_LOC_LINK_RID((row_head_t *)buf);
        *link_rid = migr_assist->next_rid;

        if (i == 0) {
            if (ra.head->size < sa->reserve_size) {
                ra.head->size = sa->reserve_size;
            }
            new_ma.owner_rid = migr_assist->owner_rid;
            new_ma.old_rid = migr_assist->old_rid;
        } else {
            new_ma.old_rid = INVALID_ROWID;
            new_ma.owner_rid = new_ma.new_rid;
        }

        new_ma.undo = migr_assist->undo;
        new_ma.col_start = migr_assist->col_start + sa->col_start[i];

        /* update chain row will write undo
         * update migr row does not write undo here, because undo is generated by original row
         */
        if (is_chain) {
            if (heap_update_chain_row(session, cursor, &ra, &new_ma) != GS_SUCCESS) {
                cm_pop(session->stack);
                return GS_ERROR;
            }
        } else {
            if (heap_update_migr_row(session, cursor, &ra, &new_ma) != GS_SUCCESS) {
                cm_pop(session->stack);
                return GS_ERROR;
            }
        }

        migr_assist->new_rid = new_ma.new_rid;

        // pass the first chain rowid for heap_insert_merged_chain_rows
        if (next_rid != NULL && i == 0) {
            *next_rid = new_ma.new_rid;
        }
    }

    cm_pop(session->stack);

    return GS_SUCCESS;
}

static status_t heap_trigger_migration(knl_session_t *session, knl_cursor_t *cursor, heap_update_assist_t *ua)
{
    row_assist_t ra;
    split_assist_t sa;
    rowid_t next_rid;
    migr_row_assist_t migr_assist;
    heap_t *heap = CURSOR_HEAP(cursor);
    uint8 cipher_reserve_size = heap->cipher_reserve_size;

    CM_SAVE_STACK(session->stack);

    ra.is_csf = cursor->row->is_csf;
    migr_assist.owner_rid = cursor->rowid;
    migr_assist.old_rid = cursor->link_rid;
    migr_assist.next_rid = INVALID_ROWID;
    migr_assist.undo = NULL;
    migr_assist.col_start = 0;
    char *buf = (char *)cm_push(session->stack, ua->new_size);
    heap_init_chain_row(session, &ra, buf, ua->new_cols, GS_INVALID_ID8, 0);

    if (cursor->chain_count > 1) {
        next_rid = ((row_chains_info_t *)(cursor->chain_info))->chains[1].chain_rid;
    } else {
        next_rid = INVALID_ROWID;
    }

    *HEAP_LOC_LINK_RID((row_head_t *)buf) = next_rid;
    heap_reorganize_with_update(cursor->row, cursor->offsets, cursor->lens, ua->info, &ra);
    if (ua->new_size <= HEAP_MAX_ROW_SIZE(session) - cipher_reserve_size) {
        knl_panic_log(ra.head->size == ua->new_size, "the size of row recorded is incorrect, panic info: "
            "ra's size %u new_size %u page %u-%u type %u table %s", ra.head->size, ua->new_size, cursor->rowid.file,
            cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);
        if (heap_update_migr_row(session, cursor, &ra, &migr_assist) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }

    /* 1. first split row should keep rowid, otherwise chain may damaged.
     * 2. size of first split row should large than old size, otherwise
     *    if update is rollbacked, we should make sure page has enoungh
     *    free size to change row backward.
     */
    sa.org_row = ra.head;
    sa.ua = ua;
    /* max value of ua->new_cols is GS_MAX_COLUMNS(4096) */
    sa.offsets = (uint16 *)cm_push(session->stack, ua->new_cols * sizeof(uint16));
    sa.lens = (uint16 *)cm_push(session->stack, ua->new_cols * sizeof(uint16));
    if (cursor->row->is_migr) {
        sa.reserve_size = cursor->row->size;
    } else {
        // row size less than PCRH_MAX_ROW_SIZE, so the sum is less than max value(65535) of uint16
        sa.reserve_size = cursor->row->size + sizeof(rowid_t);
    }
    cm_decode_row(ra.buf, sa.offsets, sa.lens, NULL);

    heap_prepare_split_for_update(session, cursor, &sa);

    if (heap_split_and_update(session, cursor, &sa, &migr_assist, GS_FALSE, NULL) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t heap_migrate_chain_row(knl_session_t *session, knl_cursor_t *cursor, heap_update_assist_t *ua,
                                       row_head_t *row, migr_row_assist_t *migr_assist)
{
    row_assist_t ra;
    char *buf = NULL;
    split_assist_t sa;
    rowid_t *next_link = NULL;
    heap_t *heap = CURSOR_HEAP(cursor);
    uint8 cipher_reserve_size = heap->cipher_reserve_size;

    CM_SAVE_STACK(session->stack);
    ra.is_csf = row->is_csf;

    /* max value of ua->new_cols is GS_MAX_COLUMNS(4096) */
    sa.offsets = (uint16 *)cm_push(session->stack, ua->new_cols * sizeof(uint16));
    sa.lens = (uint16 *)cm_push(session->stack, ua->new_cols * sizeof(uint16));
    cm_decode_row((char *)row, sa.offsets, sa.lens, NULL);
    buf = (char *)cm_push(session->stack, ua->new_size);
    heap_init_chain_row(session, &ra, buf, ua->new_cols, GS_INVALID_ID8, 0);
    next_link = HEAP_LOC_LINK_RID((row_head_t *)buf);
    *next_link = migr_assist->next_rid;

    heap_reorganize_with_update(row, sa.offsets, sa.lens, ua->info, &ra);

    if (ra.head->size <= HEAP_MAX_MIGR_ROW_SIZE(session) - cipher_reserve_size) {
        if (heap_update_chain_row(session, cursor, &ra, migr_assist) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }

    sa.org_row = ra.head;
    sa.ua = ua;
    sa.reserve_size = row->size;
    cm_decode_row((char *)sa.org_row, sa.offsets, sa.lens, NULL);
    heap_prepare_split_for_update(session, cursor, &sa);

    if (heap_split_and_update(session, cursor, &sa, migr_assist, GS_TRUE, NULL) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t heap_update_link_row(knl_session_t *session, knl_cursor_t *cursor, row_chain_t *chain,
                                     heap_update_assist_t *ua, undo_data_t *undo)
{
    heap_t *heap = CURSOR_HEAP(cursor);
    rd_heap_update_inplace_t rd_inplace;
    rd_heap_update_inpage_t rd_inpage;
    heap_page_t *owner_page = NULL;
    heap_page_t *migr_page = NULL;
    row_dir_t *owner_dir = NULL;
    row_dir_t *migr_dir = NULL;
    row_head_t *owner_row = NULL;
    row_head_t *migr_row = NULL;
    uint8 owner_list;
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    bool32 has_logic = LOGIC_REP_DB_ENABLED(session) && dc_replication_enabled(session, entity, cursor->part_loc);
    uint8 entry_flag = has_logic ? LOG_ENTRY_FLAG_WITH_LOGIC_OID : LOG_ENTRY_FLAG_NONE;
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(heap->cipher_reserve_size);

    log_atomic_op_begin(session);

    cm_latch_x(&heap->latch.latch, session->id, &session->stat_heap);

    // Update owner page, write undo, before tx_end, another sessions can get row from undo
    buf_enter_page(session, GET_ROWID_PAGE(cursor->rowid), LATCH_MODE_X, ENTER_PAGE_NORMAL);
    owner_page = (heap_page_t *)CURR_PAGE(session);
    owner_dir = heap_get_dir(owner_page, (uint32)cursor->rowid.slot);
    owner_row = HEAP_GET_ROW(owner_page, owner_dir);
    if (owner_row->is_changed && owner_dir->scn == cursor->ssn) {
        buf_leave_page(session, GS_FALSE);
        cm_unlatch(&heap->latch.latch, &session->stat_heap);
        log_atomic_op_end(session);
        GS_THROW_ERROR(ERR_ROW_SELF_UPDATED);
        return GS_ERROR;
    }

    heap_generate_undo_for_update(session, cursor, cursor->rowid, (heap_page_t *)CURR_PAGE(session), undo, ua);
    buf_leave_page(session, GS_TRUE);  // leave owner_page

    buf_enter_page(session, GET_ROWID_PAGE(cursor->link_rid), LATCH_MODE_X, ENTER_PAGE_NORMAL);
    migr_page = (heap_page_t *)CURR_PAGE(session);
    migr_dir = heap_get_dir(migr_page, (uint32)cursor->link_rid.slot);
    migr_row = HEAP_GET_ROW(migr_page, migr_dir);

    if (ua->mode == UPDATE_INPLACE) {
        rd_inplace.slot = (uint16)cursor->link_rid.slot;
        rd_inplace.count = ua->info->count;
        if (SPACE_IS_LOGGING(SPACE_GET(session, heap->segment->space_id))) {
            log_encrypt_prepare(session, migr_page->head.type, need_encrypt);
            log_put(session, RD_HEAP_UPDATE_INPLACE, &rd_inplace, sizeof(rd_heap_update_inplace_t), entry_flag);
            log_append_data(session, ua->info->columns, sizeof(uint16) * ua->info->count);
            log_append_data(session, ua->info->data, ((row_head_t *)ua->info->data)->size);
        }

        heap_update_inplace(session, cursor->offsets, cursor->lens, ua->info, migr_row);

        buf_leave_page(session, GS_TRUE);  // leave migr_page
        cm_unlatch(&heap->latch.latch, &session->stat_heap);
        log_atomic_op_end(session);

        return GS_SUCCESS;
    }

    // Calculate the accurate inc_size and migration row new_size
    ua->inc_size = ua->new_size - migr_row->size;

    if (ua->inc_size > 0 && (uint16)ua->inc_size > migr_page->free_size) {
        buf_leave_page(session, GS_FALSE);  // leave migr_page
        cm_unlatch(&heap->latch.latch, &session->stat_heap);
        log_atomic_op_end(session);

        return heap_trigger_migration(session, cursor, ua);
    }

    rd_inpage.slot = (uint16)cursor->link_rid.slot;
    rd_inpage.count = ua->info->count;
    rd_inpage.new_cols = ua->new_cols;
    rd_inpage.inc_size = ua->inc_size;
    if (SPACE_IS_LOGGING(SPACE_GET(session, heap->segment->space_id))) {
        log_encrypt_prepare(session, migr_page->head.type, need_encrypt);
        log_put(session, RD_HEAP_UPDATE_INPAGE, &rd_inpage, sizeof(rd_heap_update_inpage_t), entry_flag);
        log_append_data(session, ua->info->columns, sizeof(uint16) * ua->info->count);
        log_append_data(session, ua->info->data, ((row_head_t *)ua->info->data)->size);
    }

    heap_update_inpage(session, cursor->row, cursor->offsets, cursor->lens,
                       ua, migr_page, (uint16)cursor->link_rid.slot);

    owner_list = heap_get_owner_list(session, (heap_segment_t *)heap->segment, migr_page->free_size);
    session->change_list = owner_list - (uint8)migr_page->map.list_id;
    buf_leave_page(session, GS_TRUE);  // leave migr_page
    cm_unlatch(&heap->latch.latch, &session->stat_heap);
    log_atomic_op_end(session);

    heap_try_change_map(session, heap, GET_ROWID_PAGE(cursor->link_rid));
    return GS_SUCCESS;
}

static void heap_reorgnize_chain_update_assist(heap_update_assist_t *ua, uint32 col_end, row_chain_t *chain,
    uint16 data_size)
{
    uint32 i;
    uint32 uid = 0;
    knl_update_info_t *update_info = ua->info;
    bool32 is_csf = ((row_head_t *)update_info->data)->is_csf;
    int16 new_col_size, old_col_size;
    knl_calc_row_head_inc_size_t calc_row_head_inc_func = is_csf ?
        heap_calc_csf_row_head_inc_size : heap_calc_bmp_row_head_inc_size;
    int16 null_col_size = heap_calc_null_row_size((row_head_t *)update_info->data);

    /* set new_cols correct, and calculate bitmap size change */
    ua->old_cols = chain->col_count;
    ua->new_cols = col_end - chain->col_start;  // col_end is larger than chain->col_start

    for (i = 0; i < update_info->count; i++) {
        update_info->columns[i] -= chain->col_start;

        // inc uid to the begining of new added columns
        if (update_info->columns[i] < ua->old_cols) {
            uid++;
        }
    }

    /*
     * calc null column inc row size for csf
     * null_col_size is 0 for bitmap row, 1 for csf row
     */
    for (i = ua->old_cols; i < ua->new_cols; i++) {
        if (uid < ua->info->count && i == ua->info->columns[uid]) {
            uid++;
            continue;
        } else {
            new_col_size = null_col_size;
            old_col_size = 0;
        }
        if (new_col_size != old_col_size) {
            ua->inc_size += new_col_size - old_col_size;
        }
    }

    if (ua->old_cols != ua->new_cols) {
        int16 bitmap_inc = calc_row_head_inc_func(ua->new_cols, ua->old_cols);
        /* inc_size and new_size is less than HEAP_MAX_ROW_SIZE, so the sum is less than max value(65535) of uint16 */
        ua->inc_size += bitmap_inc;
    }

    ua->new_size = CM_ALIGN4((uint32)(data_size + ua->inc_size));
}

static void heap_reorganize_update_assist(knl_session_t *session, knl_cursor_t *cursor, heap_update_assist_t *old_ua,
                                          row_chain_t *chain, uint16 *uid, heap_update_assist_t *new_ua)
{
    knl_update_info_t *old_info = old_ua->info;
    knl_update_info_t *new_info = new_ua->info;
    uint16 i;
    uint16 col_count = 0;
    uint16 uid_start = *uid;
    row_assist_t ra;
    uint16 col_end = IS_INVALID_ROWID(chain->next_rid) ? old_ua->new_cols : (chain->col_start + chain->col_count);
    bool32 is_csf = cursor->row->is_csf;
    knl_put_row_column_t put_col_func = is_csf ? heap_put_csf_row_column : heap_put_bmp_row_column;

    while (uid_start < old_info->count) {
        if (old_info->columns[uid_start] >= col_end) {
            break;
        }
        col_count++;
        uid_start++;
    }

    if (col_count == 0) {
        new_ua->old_cols = chain->col_count;
        new_ua->new_cols = chain->col_count;
        new_ua->new_size = chain->row_size;
        new_ua->inc_size = 0;
        new_ua->mode = UPDATE_INPLACE;
        new_ua->info->count = 0;
        new_ua->undo_size = 0;
        ((row_head_t *)new_ua->info->data)->size = 0;
        return;
    }

    new_info->count = 0;
    cm_row_init(&ra, new_info->data, GS_MAX_ROW_SIZE, col_count, is_csf);
    for (i = uid_start - col_count; i < uid_start; i++) {
        put_col_func((row_head_t *)old_info->data, old_info->offsets, old_info->lens, i, &ra);
        new_info->columns[new_info->count] = old_info->columns[i];
        new_info->count++;
    }
    row_end(&ra);

    knl_panic_log(new_info->count == col_count, "the column count is abnormal, panic info: page %u-%u type %u "
        "table %s new_info_count %u col_count %u", cursor->rowid.file, cursor->rowid.page,
        ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name, new_info->count, col_count);
    cm_decode_row(new_info->data, new_info->offsets, new_info->lens, NULL);
    /* set new_cols to old_cols, in order to calculate data size change, ignore bitmap size change */
    new_ua->old_cols = old_ua->old_cols;
    new_ua->new_cols = old_ua->old_cols;
    ROWID_COPY(new_ua->rowid, chain->chain_rid);
    heap_update_prepare(session, cursor->row, cursor->offsets, cursor->lens, chain->data_size, new_ua);
    heap_reorgnize_chain_update_assist(new_ua, col_end, chain, chain->data_size);

    // new_ua->undo_size is less than EFAULT_PAGE_SIZE(8192), so the sum is less than max value(65535) of uint16
    new_ua->undo_size += sizeof(rowid_t);
    *uid = uid_start;
}

static void heap_get_chain_update_undo(knl_session_t *session, knl_cursor_t *cursor, heap_update_assist_t *ua,
                                       uint16 col_start, rowid_t next_rid, undo_data_t *undo)
{
    uint16 i;
    uint16 col_id, head_size, col_size;
    heap_undo_update_info_t *info;
    row_assist_t ra;
    char *row_buf = NULL;
    errno_t ret;
    ra.is_csf = cursor->row->is_csf;
    knl_put_row_column_t put_col_func = cursor->row->is_csf ? heap_put_csf_row_column : heap_put_bmp_row_column;

    info = (heap_undo_update_info_t *)undo->data;
    info->old_cols = ua->old_cols;
    info->count = ua->info->count;

    knl_panic_log(info->count > 0, "the count of update columns is wrong, panic info: page %u-%u type %u table %s "
                  "count of update columns %u", cursor->rowid.file, cursor->rowid.page,
                  ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name, info->count);
    if (info->count != 0) {
        col_size = info->count * sizeof(uint16);  // the max value of info->count is GS_MAX_COLUMNS(4096)
        ret = memcpy_sp(info->columns, HEAP_MAX_MIGR_ROW_SIZE(session) + sizeof(uint32), ua->info->columns, col_size);
        knl_securec_check(ret);
    }

    head_size = HEAP_UNDO_UPDATE_INFO_SIZE(ua->info->count);
    row_buf = undo->data + head_size;

    heap_init_chain_row(session, &ra, row_buf, ua->info->count, GS_INVALID_ID8, 0);
    HEAP_SET_LINK_RID((row_head_t *)row_buf, next_rid.value);

    for (i = 0; i < ua->info->count; i++) {
        // the max value of ua->info->columns[] and col_start is GS_MAX_COLUMNS(4096)
        col_id = ua->info->columns[i] + col_start;

        if (col_id >= ua->old_cols + col_start) {
            row_put_null(&ra);
        } else {
            put_col_func(cursor->row, cursor->offsets, cursor->lens, col_id, &ra);
        }
    }
    row_end(&ra);

    undo->size = head_size + ra.head->size;
}

static status_t heap_update_chain(knl_session_t *session, knl_cursor_t *cursor, row_chain_t *chain,
                                  heap_update_assist_t *ua, undo_data_t *undo)
{
    heap_t *heap = CURSOR_HEAP(cursor);
    uint8 cipher_reserve_size = heap->cipher_reserve_size;
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(cipher_reserve_size);
    rd_heap_update_inplace_t rd_inplace;
    rd_heap_update_inpage_t rd_inpage;
    migr_row_assist_t migr_assist;
    heap_page_t *migr_page = NULL;
    row_dir_t *migr_dir = NULL;
    row_head_t *migr_row = NULL;
    uint8 owner_list;
    char *migr_buf = NULL;
    uint16 *offsets = NULL;
    uint16 *lens = NULL;
    errno_t ret;
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    bool32 has_logic = LOGIC_REP_DB_ENABLED(session) && dc_replication_enabled(session, entity, cursor->part_loc);
    uint8 entry_flag = has_logic ? LOG_ENTRY_FLAG_WITH_LOGIC_OID : LOG_ENTRY_FLAG_NONE;
    uint16 data_size;
    uint32 partloc_size = undo_part_locate_size(cursor->table);

    if (ua->undo_size > chain->row_size || ua->new_size > HEAP_MAX_ROW_SIZE(session) - cipher_reserve_size) {
        undo->type = UNDO_HEAP_UPDATE_FULL;
        undo->size = chain->row_size + partloc_size;
    } else {
        undo->type = UNDO_HEAP_UPDATE;
        heap_get_chain_update_undo(session, cursor, ua, chain->col_start, chain->next_rid, undo);
        undo->size += partloc_size;
    }

    if (undo_prepare(session, undo->size, IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type), need_encrypt) != GS_SUCCESS) {
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    offsets = (uint16 *)cm_push(session->stack, chain->col_count * sizeof(uint16) * 2);
    lens = offsets + chain->col_count;

    log_atomic_op_begin(session);

    buf_enter_page(session, GET_ROWID_PAGE(chain->chain_rid), LATCH_MODE_X, ENTER_PAGE_NORMAL);
    migr_page = (heap_page_t *)CURR_PAGE(session);
    migr_dir = heap_get_dir(migr_page, (uint32)chain->chain_rid.slot);
    migr_row = HEAP_GET_ROW(migr_page, migr_dir);

    // Calculate the accurate inc_size and migration row new_size
    ua->inc_size = ua->new_size - migr_row->size;

    if ((ua->inc_size > 0 && (uint16)ua->inc_size > migr_page->free_size)) {
        migr_buf = (char *)cm_push(session->stack, migr_row->size);
        ret = memcpy_sp(migr_buf, migr_row->size, migr_row, migr_row->size);
        knl_securec_check(ret);
        buf_leave_page(session, GS_FALSE);  // leave migr_page
        log_atomic_op_end(session);

        migr_assist.owner_rid = chain->owner_rid;
        migr_assist.old_rid = chain->chain_rid;
        migr_assist.next_rid = chain->next_rid;
        migr_assist.undo = undo;
        migr_assist.col_start = chain->col_start;
        if (heap_migrate_chain_row(session, cursor, ua, (row_head_t *)migr_buf, &migr_assist) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        chain->chain_rid = migr_assist.new_rid;
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }

    migr_page = (heap_page_t *)CURR_PAGE(session);
    migr_dir = heap_get_dir(migr_page, (uint32)chain->chain_rid.slot);
    migr_row = HEAP_GET_ROW(migr_page, migr_dir);
    cm_decode_row((char *)migr_row, offsets, lens, &data_size);

    if (undo->type == UNDO_HEAP_UPDATE_FULL) {
        knl_panic_log(undo->size >= data_size + partloc_size, "row data_size is more than undo's size, panic info: "
            "page %u-%u type %u table %s row data_size %u undo size %u", cursor->rowid.file, cursor->rowid.page,
            ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name, data_size, undo->size);
        /*
         * migr row size may be larger than chain->row_size
         * for chain info may get before migr row updated,
         * chain info will not retrieve after update action rollback,
         * rcr will not recovery row size after rollback
         */
        ret = memcpy_sp(undo->data, chain->row_size, (char *)migr_row, chain->row_size);
        knl_securec_check(ret);
        ((row_head_t *)undo->data)->size = chain->row_size;
        table_t *table = (table_t *)cursor->table;
        if (IS_PART_TABLE(table) && IS_COMPART_TABLE(table->part_table)) {
            undo->snapshot.contain_subpartno = GS_TRUE;
            *(knl_part_locate_t *)(undo->data + undo->size - partloc_size) = cursor->part_loc;
        } else if (IS_PART_TABLE(table)) {
            *(uint32 *)(undo->data + undo->size - partloc_size) = cursor->part_loc.part_no;
        } else {
            *(uint32 *)(undo->data + undo->size - partloc_size) = GS_INVALID_ID32;
        }
    }

    if (ua->mode == UPDATE_INPLACE) {
        heap_generate_undo_for_update(session, cursor, chain->chain_rid, migr_page, undo, ua);
        knl_panic_log(ua->info->count > 0, "column count is wrong, panic info: page %u-%u type %u table %s "
                      "column count %u", cursor->rowid.file, cursor->rowid.page,
                      ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name, ua->info->count);

        rd_inplace.slot = (uint16)chain->chain_rid.slot;
        rd_inplace.count = ua->info->count;
        if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
            log_encrypt_prepare(session, migr_page->head.type, need_encrypt);
            log_put(session, RD_HEAP_UPDATE_INPLACE, &rd_inplace, sizeof(rd_heap_update_inplace_t), entry_flag);
            log_append_data(session, ua->info->columns, sizeof(uint16) * ua->info->count);
            log_append_data(session, ua->info->data, ((row_head_t *)ua->info->data)->size);
        }
        heap_update_inplace(session, offsets, lens, ua->info, migr_row);

        buf_leave_page(session, GS_TRUE);  // leave migr_page
        log_atomic_op_end(session);
        CM_RESTORE_STACK(session->stack);

        return GS_SUCCESS;
    }

    heap_generate_undo_for_update(session, cursor, chain->chain_rid, migr_page, undo, ua);

    rd_inpage.slot = (uint16)chain->chain_rid.slot;
    rd_inpage.count = ua->info->count;
    rd_inpage.new_cols = ua->new_cols;
    rd_inpage.inc_size = ua->inc_size;
    if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        log_encrypt_prepare(session, migr_page->head.type, need_encrypt);
        log_put(session, RD_HEAP_UPDATE_INPAGE, &rd_inpage, sizeof(rd_heap_update_inpage_t), entry_flag);
        log_append_data(session, ua->info->columns, sizeof(uint16) * ua->info->count);
        log_append_data(session, ua->info->data, ((row_head_t *)ua->info->data)->size);
    }
    migr_buf = (char *)cm_push(session->stack, migr_row->size);
    ret = memcpy_sp(migr_buf, migr_row->size, migr_row, migr_row->size);
    knl_securec_check(ret);

    heap_update_inpage(session, (row_head_t *)migr_buf, offsets, lens, ua, migr_page, (uint16)chain->chain_rid.slot);
    owner_list = heap_get_owner_list(session, (heap_segment_t *)heap->segment, migr_page->free_size);
    session->change_list = owner_list - (uint8)migr_page->map.list_id;
    buf_leave_page(session, GS_TRUE);  // leave migr_page
    log_atomic_op_end(session);

    heap_try_change_map(session, heap, GET_ROWID_PAGE(chain->chain_rid));

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t heap_generate_undo_for_linkrid(knl_session_t *session, knl_cursor_t *cursor, rowid_t rowid,
                                               heap_update_assist_t *ua, bool32 self_update_check)
{
    undo_data_t undo;
    heap_page_t *page = NULL;
    row_dir_t *dir = NULL;
    row_head_t *row = NULL;

    if (buf_read_page(session, GET_ROWID_PAGE(rowid), LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
        return GS_ERROR;
    }
    page = (heap_page_t *)CURR_PAGE(session);
    dir = heap_get_dir(page, (uint32)rowid.slot);
    row = HEAP_GET_ROW(page, dir);
    if (row->is_changed && self_update_check && dir->scn == cursor->ssn) {
        buf_leave_page(session, GS_FALSE);
        GS_THROW_ERROR(ERR_ROW_SELF_UPDATED);
        return GS_ERROR;
    }

    ROWID_COPY(undo.rowid, rowid);
    undo.data = (char *)cm_push(session->stack, sizeof(rowid_t));
    *(rowid_t *)undo.data = *HEAP_LOC_LINK_RID(row);
    undo.type = UNDO_HEAP_UPDATE_LINKRID;
    undo.size = sizeof(rowid_t);

    buf_leave_page(session, GS_FALSE);

    if (undo_prepare(session, undo.size, IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type), GS_FALSE) != GS_SUCCESS) {
        cm_pop(session->stack);
        return GS_ERROR;
    }

    log_atomic_op_begin(session);
    buf_enter_page(session, GET_ROWID_PAGE(rowid), LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE(session);

    heap_generate_undo_for_update(session, cursor, rowid, page, &undo, ua);

    buf_leave_page(session, GS_TRUE);  // leave owner_page
    log_atomic_op_end(session);
    cm_pop(session->stack);

    return GS_SUCCESS;
}

static status_t heap_update_chain_rows(knl_session_t *session, knl_cursor_t *cursor, heap_update_assist_t *ua)
{
    heap_update_assist_t sub_ua;
    knl_update_info_t new_info;
    row_chain_t *chain = NULL;
    undo_data_t undo;
    int32 i;
    row_chains_info_t *chains_info = (row_chains_info_t *)cursor->chain_info;
    uint16 uid_start = 0;
    rowid_t owner_rid;

    knl_panic_log(cursor->chain_count > 1, "count of row chain is wrong, panic info: page %u-%u type %u table %s "
                  "chain_count %u", cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, cursor->chain_count);
    table_t *table = (table_t *)cursor->table;
    if (heap_generate_undo_for_linkrid(session, cursor, cursor->rowid, ua, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);

    new_info.data = (char *)cm_push(session->stack, ua->new_size);
    CM_PUSH_UPDATE_INFO(session, new_info);
    sub_ua.info = &new_info;
    owner_rid = cursor->rowid;

    for (i = 0; i < cursor->chain_count; i++) {
        chain = chains_info->chains + i;
        chain->owner_rid = owner_rid;

        ROWID_COPY(undo.rowid, chain->chain_rid);

        heap_reorganize_update_assist(session, cursor, ua, chain, &uid_start, &sub_ua);

        if (sub_ua.info->count == 0) {
            if (heap_generate_undo_for_linkrid(session, cursor, chain->chain_rid, ua, GS_FALSE) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
            owner_rid = chain->chain_rid;
            continue;
        }

        undo.data = (char *)cm_push(session->stack, HEAP_MAX_MIGR_ROW_SIZE(session) + undo_part_locate_size(table));
        undo.snapshot.contain_subpartno = GS_FALSE;
        if (heap_update_chain(session, cursor, chain, &sub_ua, &undo) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        cm_pop(session->stack);
        owner_rid = chain->chain_rid;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t heap_insert_merged_chain_rows(knl_session_t *session, knl_cursor_t *cursor,
    heap_update_assist_t *ua, rowid_t *next_rid)
{
    split_assist_t sa;
    migr_row_assist_t migr_assist;

    sa.org_row = ua->row;
    sa.ua = ua;
    sa.offsets = ua->offsets;
    sa.lens = ua->lens;
    sa.reserve_size = 0;

    heap_prepare_split_for_update(session, cursor, &sa);

    /**
     * chain row can't updated to mirate row
     * if chains can merged into one row , we force it seperate to two chains.
     * the last column recorded in one chain independently.
     */
    if (sa.split_count == 1) {
        sa.col_start[0] = 0;
        sa.uid_start[0] = 0;
        sa.col_start[1] = ua->new_cols - 1;
        sa.uid_start[1] = 0;
        sa.split_count = 2;
    }

    /**
     * insert into a new chain
     * this chain should not contact with old chains.
     * the first chain should not contact with link row
     * because a temp status chains only has one chain may be fetched
     */
    migr_assist.owner_rid = INVALID_ROWID;
    migr_assist.old_rid = INVALID_ROWID;
    migr_assist.next_rid = INVALID_ROWID;
    migr_assist.undo = NULL;
    migr_assist.col_start = 0;

    if (heap_split_and_update(session, cursor, &sa, &migr_assist, GS_TRUE, next_rid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static void heap_update_next_rid(knl_session_t *session, knl_cursor_t *cursor, rowid_t rowid, rowid_t next_rid)
{
    heap_page_t *page = NULL;
    row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    rowid_t *new_link_rid = NULL;
    rd_set_link_t rd_set_link;

    log_atomic_op_begin(session);

    buf_enter_page(session, GET_ROWID_PAGE(rowid), LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE(session);
    dir = heap_get_dir(page, (uint32)rowid.slot);
    row = HEAP_GET_ROW(page, dir);

    new_link_rid = HEAP_LOC_LINK_RID(row);
    *new_link_rid = next_rid;

    rd_set_link.slot = (uint16)rowid.slot;
    rd_set_link.link_rid = next_rid;
    rd_set_link.aligned = 0;
    if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        log_put(session, RD_HEAP_SET_LINK, &rd_set_link, sizeof(rd_set_link), LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, GS_TRUE);

    log_atomic_op_end(session);
}

/*
 * heap merge chain update
 * @note insert a new chain delete old chains when chain count exceed HEAP_MERGE_CHAIN_COUNT,
 * otherwise chain count will increase exceed GS_MAX_CHAIN_COUNT after update
 * @param kernel session, kernel cursor, update assist
 */
static status_t heap_merge_chain_update(knl_session_t *session, knl_cursor_t *cursor, heap_update_assist_t *ua)
{
    row_chains_info_t *chain_info = (row_chains_info_t *)cursor->chain_info;
    row_chain_t *chain = NULL;
    rowid_t next_rid;
    int32 i;

    // link row should check first for self update check
    if (heap_generate_undo_for_linkrid(session, cursor, cursor->rowid, ua, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    // insert new chains
    if (heap_insert_merged_chain_rows(session, cursor, ua, &next_rid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    // change next rid of link row
    heap_update_next_rid(session, cursor, cursor->rowid, next_rid);

    // delete old chains
    for (i = 0; i < cursor->chain_count; i++) {
        chain = chain_info->chains + i;

        if (heap_delete_row(session, cursor, chain->chain_rid, INVALID_ROWID,
                            GS_FALSE, chain->data_size, GS_FALSE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static void heap_update_write_logic_log(knl_session_t *session, knl_cursor_t *cursor, bool32 has_logic)
{
    rd_logic_rep_head logic_head;
    if (has_logic && IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        log_atomic_op_begin(session);
        logic_head.col_count = cursor->update_info.count;
        logic_head.is_pcr = GS_FALSE;
        logic_head.unused = 0;
        log_put(session, RD_LOGIC_REP_UPDATE, &logic_head, sizeof(rd_logic_rep_head), LOG_ENTRY_FLAG_WITH_LOGIC_OID);
        log_append_data(session, cursor->update_info.columns, cursor->update_info.count * sizeof(uint16));
        heap_append_logic_data(session, cursor, GS_TRUE);
        log_atomic_op_end(session);
    }
}

static void heap_update_write_inpage_rd(knl_session_t *session, knl_cursor_t *cursor, heap_page_t *page,
                                        bool32 need_encrypt, uint8 entry_flag, heap_update_assist_t *ua)
{
    rd_heap_update_inpage_t rd_inpage;

    rd_inpage.slot = (uint16)cursor->rowid.slot;
    rd_inpage.count = ua->info->count;
    rd_inpage.new_cols = ua->new_cols;
    rd_inpage.inc_size = ua->inc_size;
    if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        log_encrypt_prepare(session, page->head.type, need_encrypt);
        log_put(session, RD_HEAP_UPDATE_INPAGE, &rd_inpage, sizeof(rd_heap_update_inpage_t), entry_flag);
        log_append_data(session, ua->info->columns, sizeof(uint16) * ua->info->count);
        log_append_data(session, ua->info->data, ((row_head_t *)ua->info->data)->size);
    }
}

static void heap_update_write_inplace_rd(knl_session_t *session, knl_cursor_t *cursor, heap_page_t *page,
                                         bool32 need_encrypt, uint8 entry_flag, heap_update_assist_t *ua)
{
    rd_heap_update_inplace_t rd_inplace;
    rd_inplace.slot = (uint16)cursor->rowid.slot;
    rd_inplace.count = ua->info->count;

    if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        log_encrypt_prepare(session, page->head.type, need_encrypt);
        log_put(session, RD_HEAP_UPDATE_INPLACE, &rd_inplace, sizeof(rd_heap_update_inplace_t), entry_flag);
        log_append_data(session, ua->info->columns, sizeof(uint16) * ua->info->count);
        log_append_data(session, ua->info->data, ((row_head_t *)ua->info->data)->size);
    }
}

static void heap_update_prepare_undo_data(knl_session_t *session, knl_cursor_t *cursor, undo_data_t *undo,
                                          heap_update_assist_t *ua, uint8 cipher_reserve_size)
{
    errno_t ret;
    undo->data = (char *)cm_push(session->stack, GS_MAX_ROW_SIZE);
    if (ua->undo_size >= cursor->row->size || ua->new_size > HEAP_MAX_ROW_SIZE(session) - cipher_reserve_size) {
        undo->type = UNDO_HEAP_UPDATE_FULL;
        ret = memcpy_sp(undo->data, GS_MAX_ROW_SIZE, cursor->row, cursor->row->size);
        knl_securec_check(ret);
        undo->size = cursor->row->size;
    } else {
        undo->type = UNDO_HEAP_UPDATE;
        heap_get_update_undo_data(session, ua, undo, GS_MAX_ROW_SIZE);
    }

    /* write part no at tail of undo_data for recyling of splitted page */
    table_t *table = (table_t *)cursor->table;
    if (IS_PART_TABLE(table) && IS_COMPART_TABLE(table->part_table)) {
        undo->snapshot.contain_subpartno = GS_TRUE;
        *(knl_part_locate_t *)(undo->data + undo->size) = cursor->part_loc;
    } else if (IS_PART_TABLE(table)) {
        *(uint32 *)(undo->data + undo->size) = cursor->part_loc.part_no;
    } else {
        *(uint32 *)(undo->data + undo->size) = GS_INVALID_ID32;
    }

    undo->size += undo_part_locate_size(table);
}

static status_t heap_update_if_link_row(knl_session_t *session, knl_cursor_t *cursor, heap_update_assist_t *ua,
                                        undo_data_t *undo)
{
    row_chain_t chain;
    chain.data_size = cursor->data_size;
    chain.chain_rid = cursor->link_rid;
    chain.next_rid = INVALID_ROWID;
    chain.owner_rid = cursor->rowid;
    chain.col_start = 0;
    chain.col_count = ROW_COLUMN_COUNT(cursor->row);
    status_t status = heap_update_link_row(session, cursor, &chain, ua, undo);
    return status;
}

static status_t heap_update_internal(knl_session_t *session, knl_cursor_t *cursor, heap_update_assist_t *ua)
{
    heap_page_t *page = NULL;
    row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    undo_data_t undo;
    status_t status;
    uint8 owner_list;
    itl_t *itl = NULL;
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    bool32 has_logic = LOGIC_REP_DB_ENABLED(session) && dc_replication_enabled(session, entity, cursor->part_loc);
    uint8 entry_flag = has_logic ? LOG_ENTRY_FLAG_WITH_LOGIC_OID : LOG_ENTRY_FLAG_NONE;

    heap_t *heap = CURSOR_HEAP(cursor);
    uint8 cipher_reserve_size = heap->cipher_reserve_size;
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(heap->cipher_reserve_size);

    if (entity->contain_lob) {
        if (lob_update(session, cursor, ua) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    ROWID_COPY(undo.rowid, cursor->rowid);

    heap_update_write_logic_log(session, cursor, has_logic);

    /* if original row is chained */
    if (cursor->chain_count > 1) {
        if (cursor->chain_count < HEAP_MERGE_CHAIN_COUNT) {
            return heap_update_chain_rows(session, cursor, ua);
        } else {
            return heap_merge_chain_update(session, cursor, ua);
        }
    }

    undo.snapshot.contain_subpartno = GS_FALSE;
    heap_update_prepare_undo_data(session, cursor, &undo, ua, cipher_reserve_size);

    if (undo_prepare(session, undo.size, IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type), need_encrypt) != GS_SUCCESS) {
        cm_pop(session->stack);
        return GS_ERROR;
    }

    if (!IS_INVALID_ROWID(cursor->link_rid)) {
        status = heap_update_if_link_row(session, cursor, ua, &undo);
        cm_pop(session->stack);
        return status;
    }

    log_atomic_op_begin(session);

    buf_enter_page(session, GET_ROWID_PAGE(cursor->rowid), LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE(session);
    dir = heap_get_dir(page, (uint32)cursor->rowid.slot);
    row = HEAP_GET_ROW(page, dir);
    itl = heap_get_itl(page, ROW_ITL_ID(row));
    knl_panic_log(itl->is_active, "itl is inactive, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, page->head.type, ((table_t *)cursor->table)->desc.name);

    if (row->is_changed && dir->scn == cursor->ssn) {
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        cm_pop(session->stack);
        GS_THROW_ERROR(ERR_ROW_SELF_UPDATED);
        return GS_ERROR;
    }

    heap_generate_undo_for_update(session, cursor, cursor->rowid, page, &undo, ua);

    if (ua->mode == UPDATE_INPLACE) {
        heap_update_write_inplace_rd(session, cursor, page, need_encrypt, entry_flag, ua);
        heap_update_inplace(session, cursor->offsets, cursor->lens, ua->info, row);
        buf_leave_page(session, GS_TRUE);
        log_atomic_op_end(session);

        cm_pop(session->stack);
        return GS_SUCCESS;
    }

    // Calculate the accurate inc_size and row new_size
    ua->inc_size = ua->new_size - row->size;

    if (((ua->inc_size > 0) && ((uint32)ua->inc_size > page->free_size)) ||
        (ua->new_size > HEAP_MAX_ROW_SIZE(session) - cipher_reserve_size)) {
        buf_leave_page(session, GS_TRUE);
        log_atomic_op_end(session);
        if (!cursor->row->is_migr) {
            ua->new_size += sizeof(rowid_t);
        }
        status = heap_trigger_migration(session, cursor, ua);
        cm_pop(session->stack);
        return status;
    }

    heap_update_write_inpage_rd(session, cursor, page, need_encrypt, entry_flag, ua);

    heap_update_inpage(session, cursor->row, cursor->offsets, cursor->lens, ua, page, (uint16)cursor->rowid.slot);
    owner_list = heap_get_owner_list(session, (heap_segment_t *)heap->segment, page->free_size);
    session->change_list = owner_list - (uint8)page->map.list_id;
    buf_leave_page(session, GS_TRUE);
    log_atomic_op_end(session);

    heap_try_change_map(session, heap, GET_ROWID_PAGE(cursor->rowid));
    cm_pop(session->stack);

    return GS_SUCCESS;
}

uint32 heap_table_max_row_len(knl_handle_t handle, uint32 max_col_size, knl_part_locate_t part_loc)
{
    table_t *table = (table_t *)handle;

    if (table->desc.type != TABLE_TYPE_HEAP && table->desc.type != TABLE_TYPE_NOLOGGING) {
        return max_col_size;
    }

    /* normal table */
    if (!IS_PART_TABLE(table)) {
        return table->desc.is_csf ? (max_col_size - table->desc.csf_dec_rowlen) : max_col_size;
    }

    /* part table */
    table_part_t *table_part = TABLE_GET_PART(table, part_loc.part_no);
    if (!IS_COMPART_TABLE(table->part_table)) {
        return table_part->desc.is_csf ? (max_col_size - table->desc.csf_dec_rowlen) : max_col_size;
    }

    /* composite part table */
    table_part_t *table_subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[part_loc.subpart_no]);
    return table_subpart->desc.is_csf ? (max_col_size - table->desc.csf_dec_rowlen) : max_col_size;
}

static status_t heap_write_delcol_update_info(knl_session_t *session, knl_cursor_t *cursor, row_assist_t *ra,
                                              uint32 col_id)
{
    row_put_null(ra);
    return GS_SUCCESS;
}

status_t heap_reorganize_update_info(knl_session_t *session, knl_cursor_t *cursor,
                                     knl_add_update_column_t *add_update_column, heap_add_update_info_t add_func)
{
    uint32 i = 0;
    uint32 j = 0;
    row_assist_t ra;
    bool32 from_add_info = GS_FALSE;
    knl_update_info_t *old_info = add_update_column->old_info;
    knl_update_info_t *new_info = add_update_column->new_info;
    uint16 *add_cols = add_update_column->add_columns;
    uint16 add_count = add_update_column->add_count;
    bool32 is_csf = ((row_head_t *)old_info->data)->is_csf;
    knl_put_row_column_t put_col_func = is_csf ? heap_put_csf_row_column : heap_put_bmp_row_column;

    new_info->count = 0;
    cm_row_init(&ra, new_info->data, GS_MAX_ROW_SIZE, add_count + old_info->count, is_csf);
    while (i < add_count || j < old_info->count) {
        if (j >= old_info->count) {
            from_add_info = GS_TRUE;
        } else if (i >= add_count) {
            from_add_info = GS_FALSE;
        } else {
            from_add_info = (add_cols[i] < old_info->columns[j]);
        }

        if (from_add_info) {
            new_info->columns[new_info->count] = add_cols[i];

            if (add_func(session, cursor, &ra, add_cols[i]) != GS_SUCCESS) {
                return GS_ERROR;
            }

            i++;
        } else {
            new_info->columns[new_info->count] = old_info->columns[j];
            put_col_func((row_head_t *)old_info->data, old_info->offsets, old_info->lens, j, &ra);
            j++;
        }

        new_info->count++;
    }

    row_end(&ra);
    return GS_SUCCESS;
}

status_t heap_reorganize_del_column_update_info(knl_session_t *session, knl_cursor_t *cursor,
                                                knl_update_info_t *old_info, knl_update_info_t *new_info)
{
    uint32 i;
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    knl_column_t *column = NULL;
    knl_add_update_column_t add_update_column;
    uint32 uid = 0;
    uint16 del_count = 0;
    uint16 *del_cols = NULL;
    errno_t err;

    del_cols = (uint16 *)cm_push(session->stack, entity->column_count * sizeof(uint16));
    err = memset_sp(del_cols, entity->column_count * sizeof(uint16), 0xFF, entity->column_count * sizeof(uint16));
    knl_securec_check(err);

    for (i = 0; i < ROW_COLUMN_COUNT(cursor->row); i++) {
        if (uid < old_info->count && i == old_info->columns[uid]) {
            uid++;
            continue;
        }

        column = dc_get_column(entity, i);
        if (!KNL_COLUMN_IS_DELETED(column)) {
            continue;
        }

        if (cursor->lens[i] == GS_NULL_VALUE_LEN) {
            continue;
        }

        del_cols[del_count] = i;
        del_count++;
    }

    add_update_column.new_info = new_info;
    add_update_column.old_info = old_info;
    add_update_column.add_columns = del_cols;
    add_update_column.add_count = del_count;

    if (heap_reorganize_update_info(session, cursor, &add_update_column,
                                    heap_write_delcol_update_info) != GS_SUCCESS) {
        cm_pop(session->stack);
        return GS_ERROR;
    }

    cm_pop(session->stack);

    cm_decode_row(new_info->data, new_info->offsets, new_info->lens, NULL);

    return GS_SUCCESS;
}


bool32 heap_check_deleted_column(knl_cursor_t *cursor, knl_update_info_t *info, row_head_t *row, uint16 *lens)
{
    knl_column_t *column = NULL;
    uint32 i;
    uint32 uid = 0;
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;

    for (i = 0; i < ROW_COLUMN_COUNT(row); i++) {
        if (uid < info->count && i == info->columns[uid]) {
            uid++;
            continue;
        }

        column = dc_get_column(entity, i);
        if (!KNL_COLUMN_IS_DELETED(column)) {
            continue;
        }

        if (lens[i] != GS_NULL_VALUE_LEN) {
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

/*
 * @note the function should work as follow:
 * 1. try to update deleted column
 * 2. try convert inline lob in update info to outline
 * 3. try convert inline lob not in update info to outline
 * 4. use new update info to do following update
 * @param kernel session, kernel cursor, old update assist
 */
status_t heap_convert_update(knl_session_t *session, knl_cursor_t *cursor, heap_update_assist_t *ua)
{
    dc_entity_t *entity = NULL;
    knl_update_info_t *del_info = NULL;
    knl_update_info_t *lob_info = NULL;
    bool32 is_reorg = GS_FALSE;
    status_t status;
    uint32 max_row_len = heap_table_max_row_len(cursor->table, GS_MAX_ROW_SIZE, cursor->part_loc);

    CM_SAVE_STACK(session->stack);

    entity = (dc_entity_t *)cursor->dc_entity;

    if (heap_check_deleted_column(cursor, &cursor->update_info, cursor->row, cursor->lens)) {
        del_info = (knl_update_info_t *)cm_push(session->stack, sizeof(knl_update_info_t) + GS_MAX_ROW_SIZE);
        del_info->data = (char *)del_info + sizeof(knl_update_info_t);
        CM_PUSH_UPDATE_INFO(session, *del_info);
        heap_reorganize_del_column_update_info(session, cursor, ua->info, del_info);
        ua->info = del_info;
        heap_update_prepare(session, cursor->row, cursor->offsets, cursor->lens, cursor->data_size, ua);
    }

    if (entity->contain_lob && ua->new_size > max_row_len) {
        lob_info = (knl_update_info_t *)cm_push(session->stack, sizeof(knl_update_info_t) + GS_MAX_ROW_SIZE);
        lob_info->data = (char *)lob_info + sizeof(knl_update_info_t);
        CM_PUSH_UPDATE_INFO(session, *lob_info);

        /*
         * lob_reorganize_update_info will check new size and throw ERR_RECORD_SIZE_OVERFLOW when row size overflow
         */
        if (lob_reorganize_columns(session, cursor, ua, lob_info, &is_reorg) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (is_reorg) {
            ua->info = lob_info;
            heap_update_prepare(session, cursor->row, cursor->offsets, cursor->lens, cursor->data_size, ua);
        }
    }

    if (ua->new_size > max_row_len) {
        CM_RESTORE_STACK(session->stack);
        GS_THROW_ERROR(ERR_RECORD_SIZE_OVERFLOW, "update row", ua->new_size, max_row_len);
        return GS_ERROR;
    }

    status = heap_update_internal(session, cursor, ua);

    CM_RESTORE_STACK(session->stack);

    return status;
}

status_t heap_update(knl_session_t *session, knl_cursor_t *cursor)
{
    heap_update_assist_t ua;
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    status_t status;
    uint32 max_row_len = heap_table_max_row_len(cursor->table, GS_MAX_ROW_SIZE, cursor->part_loc);

    CM_ASSERT(!DB_IS_CLUSTER(session));
    SYNC_POINT(session, "SP_B4_HEAP_UPDATE");
    knl_panic_log(cursor->is_valid, "cursor is invalid, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);
    knl_panic_log(cursor->row->is_csf == ((row_head_t *)(cursor->update_info.data))->is_csf,
        "the csf status of row and update data are not same, panic info: page %u-%u type %u table %s "
        "row csf status %u update csf status %u", cursor->rowid.file, cursor->rowid.page,
        ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name, cursor->row->is_csf,
        ((row_head_t *)(cursor->update_info.data))->is_csf);

    if (cursor->xid != session->rm->xid.value) {
        cursor->xid = session->rm->xid.value;
    }

    if (!IS_PART_TABLE(cursor->table)) {
        cursor->part_loc.part_no = GS_INVALID_ID32;
        cursor->part_loc.subpart_no = GS_INVALID_ID32;
    }

    // update assist
    ua.old_cols = ROW_COLUMN_COUNT(cursor->row);
    // column count will not exceed GS_MAX_COLUMNS (4096)
    ua.new_cols = (uint16)entity->column_count;
    ROWID_COPY(ua.rowid, cursor->rowid);
    ua.info = &cursor->update_info;
    heap_update_prepare(session, cursor->row, cursor->offsets, cursor->lens, cursor->data_size, &ua);

    if (ua.new_size <= max_row_len) {
        status = heap_update_internal(session, cursor, &ua);
    } else {
        status = heap_convert_update(session, cursor, &ua);
    }

    SYNC_POINT(session, "SP_AFTER_HEAP_UPDATE");

    return status;
}

static bool32 heap_get_lob_locator(knl_cursor_t *cursor, lob_locator_t **locator, knl_column_t *column,
                                   uint16 *update_id, bool32 *from_update)
{
    knl_update_info_t *update_info = &cursor->update_info;

    if (*update_id < update_info->count && column->id == update_info->columns[*update_id]) {
        if (!COLUMN_IS_LOB(column)) {
            (*update_id)++;
            return GS_FALSE;
        }

        /* if the value of lob is null, skip it */
        if (CURSOR_UPDATE_COLUMN_SIZE(cursor, *update_id) == GS_NULL_VALUE_LEN) {
            (*update_id)++;
            return GS_FALSE;
        }

        *locator = (lob_locator_t *)CURSOR_UPDATE_COLUMN_DATA(cursor, *update_id);
        *from_update = GS_TRUE;
        (*update_id)++;
    } else {
        if (!COLUMN_IS_LOB(column)) {
            return GS_FALSE;
        }

        if (CURSOR_COLUMN_SIZE(cursor, column->id) == GS_NULL_VALUE_LEN) {
            return GS_FALSE;
        }

        *locator = (lob_locator_t *)CURSOR_COLUMN_DATA(cursor, column->id);
        *from_update = GS_FALSE;
    }

    return GS_TRUE;
}

static status_t heap_insert_lob_new_part(knl_session_t *session, knl_cursor_t *cursor, row_head_t *new_row,
    knl_update_info_t *update_info, knl_part_locate_t old_part_loc)
{
    lob_locator_t insert_locator;
    lob_locator_t *locator = NULL;
    knl_column_t *column = NULL;
    lob_t *lob = NULL;
    bool32 lob_from_update = GS_FALSE;

    knl_part_locate_t new_part_loc = cursor->part_loc;
    dc_entity_t *dc_entity = (dc_entity_t *)cursor->dc_entity;
    uint16 column_count = ((table_t *)cursor->table)->desc.column_count;
    uint16 update_id = 0;
    errno_t ret = memset_sp(&insert_locator, sizeof(lob_locator_t), 0xFF, sizeof(lob_locator_t));
    knl_securec_check(ret);
    CM_SAVE_STACK(session->stack);
    uint16 *offsets = (uint16 *)cm_push(session->stack, column_count * sizeof(uint16));
    uint16 *lens = (uint16 *)cm_push(session->stack, column_count * sizeof(uint16));
    cm_decode_row((char *)new_row, offsets, lens, NULL);

    for (uint16 i = 0; i < column_count; i++) {
        column = dc_get_column(dc_entity, i);
        if (!heap_get_lob_locator(cursor, &locator, column, &update_id, &lob_from_update)) {
            continue;
        }

        /* for inline lob, the data is contained in lob locator and it has been update in cursor row,
         * so it need not to be handled here.
         */
        if (!locator->head.is_outline) {
            continue;
        }

        ret = memset_sp(&insert_locator, sizeof(lob_locator_t), 0xFF, sizeof(lob_locator_t));
        knl_securec_check(ret);
        insert_locator.head.is_outline = GS_TRUE;
        insert_locator.head.type = locator->head.type;
        lob = (lob_t *)column->lob;
        if (knl_copy_lob(session, cursor, &insert_locator, locator, column) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        /* delete lob on the update info */
        if (lob_from_update) {
            cursor->part_loc = old_part_loc;
            if (lob_recycle_pages(session, cursor, lob, locator) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
            cursor->part_loc = new_part_loc;
        }

        /* update lob locator for insert cursor */
        ret = memcpy_sp((char*)new_row + offsets[i], GS_MAX_ROW_SIZE, &insert_locator, sizeof(lob_locator_t));
        knl_securec_check(ret);
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

/* update overpart prepare interface. This function reorganize the new row with the old row and update info.
 * and this function insert the lob data which is store outline into the new part. The new part no is store
 * in the new cursor.
 */
status_t heap_prepare_update_overpart(knl_session_t *session, knl_cursor_t *cursor, row_head_t *new_row,
    knl_part_locate_t new_part_loc)
{
    knl_dictionary_t dc;
    table_t *table = NULL;
    dc_entity_t *entity = NULL;
    part_key_t *key = NULL;
    uint16 *offsets = NULL;
    uint16 *lens = NULL;
    part_table_t *part_table = NULL;
    row_assist_t ra;
    bool32 is_csf = cursor->row->is_csf;

    knl_panic_log(cursor->row->is_csf == ((row_head_t *)(cursor->update_info.data))->is_csf,
        "csf status of row and update data are not same, panic info: page %u-%u type %u table %s row csf status %u "
        "update csf status %u", cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
        ((table_t *)cursor->table)->desc.name, cursor->row->is_csf,
        ((row_head_t *)(cursor->update_info.data))->is_csf);

    knl_part_locate_t old_part_loc = cursor->part_loc;
    table = (table_t *)cursor->table;
    entity = (dc_entity_t *)cursor->dc_entity;
    part_table = table->part_table;
    dc.handle = (knl_handle_t)cursor->dc_entity;

    /* reconstruct new row with update info, and put it onto insert cursor */
    CM_SAVE_STACK(session->stack);
    /*
     * use the column count from dc instead of cursor row, since the column count on
     * heap maybe smaller than that of dc after user perform 'add column' operation
     */
    offsets = (uint16 *)cm_push(session->stack, table->desc.column_count * sizeof(uint16));
    lens = (uint16 *)cm_push(session->stack, table->desc.column_count * sizeof(uint16));
    cm_row_init(&ra, (char*)new_row, GS_MAX_ROW_SIZE, table->desc.column_count, is_csf);
    heap_reorganize_with_update(cursor->row, cursor->offsets, cursor->lens, &cursor->update_info, &ra);
    cm_decode_row((char *)new_row, offsets, lens, NULL);

    /* a row can be updated into another new interval part that is not existes now, so it is need to create
     * a new interval part before insert data into it.
     */
    key = (part_key_t *)cm_push(session->stack, GS_MAX_COLUMN_SIZE);
    errno_t ret = memset_sp(key, GS_MAX_COLUMN_SIZE, 0, GS_MAX_COLUMN_SIZE);
    knl_securec_check(ret);
    if (part_generate_part_key(session, new_row, offsets, lens, part_table, key) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (knl_verify_interval_part(entity, new_part_loc.part_no)) {
        if (knl_create_interval_part(session, &dc, new_part_loc.part_no, key) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }
    knl_set_table_part(cursor, new_part_loc);

    /* write the lob data into the new lob part segment and put the lob locator onto insert cursor */
    if (heap_insert_lob_new_part(session, cursor, new_row, &cursor->update_info, old_part_loc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

void heap_revert_update(knl_session_t *session, heap_undo_update_info_t *undo_info, row_head_t *row,
                        uint16 *offsets, uint16 *lens)
{
    row_assist_t new_ra;
    knl_update_info_t info;
    uint16 row_size, col_size;
    char *buf = NULL;
    row_head_t *upd_row = NULL;
    rowid_t *lnk_rid = NULL;
    errno_t ret;

    CM_SAVE_STACK(session->stack);
    CM_PUSH_UPDATE_INFO(session, info);

    buf = (char *)cm_push(session->stack, GS_MAX_ROW_SIZE);
    knl_panic_log(buf != NULL, "current buf is NULL.");

#ifdef LOG_DIAG
    // Random buf may cause inconsistent row memory area when column lens is non-aligned.
    ret = memset_sp(buf, GS_MAX_ROW_SIZE, 0, GS_MAX_ROW_SIZE);
    knl_securec_check(ret);
#endif
    new_ra.is_csf = row->is_csf;
    row_size = row->size;

    info.count = undo_info->count;
    // the max value of info.count is GS_MAX_COLUMNS (4096)
    col_size = info.count * sizeof(uint16);
    if (col_size != 0) {
        ret = memcpy_sp(info.columns, (session)->kernel->attr.max_column_count * sizeof(uint16),
            undo_info->columns, col_size);
        knl_securec_check(ret);
    }

    info.data = (char *)undo_info + HEAP_UNDO_UPDATE_INFO_SIZE(info.count);
    upd_row = (row_head_t *)info.data;

    cm_decode_row(info.data, info.offsets, info.lens, NULL);
    cm_decode_row((char *)row, offsets, lens, NULL);
    if (row->is_migr) {
        heap_init_chain_row(session, &new_ra, buf, undo_info->old_cols, ROW_ITL_ID(row), row->flags);
        lnk_rid = HEAP_LOC_LINK_RID(new_ra.head);
        if (upd_row->is_migr) {
            *lnk_rid = *HEAP_LOC_LINK_RID(upd_row);
        } else {
            *lnk_rid = INVALID_ROWID;
        }
    } else {
        heap_init_row(session, &new_ra, buf, undo_info->old_cols, ROW_ITL_ID(row), row->flags);
    }

    heap_reorganize_with_update(row, offsets, lens, &info, &new_ra);
    knl_panic_log(new_ra.head->size <= row_size,
        "row head is bigger than row_size, panic info: row head %u row_size %u.", new_ra.head->size, row_size);
    ret = memcpy_sp(row, new_ra.head->size, new_ra.buf, new_ra.head->size);
    knl_securec_check(ret);
    row->size = row_size;  // revert update should keep row size

    CM_RESTORE_STACK(session->stack);
}

void heap_undo_update_full(knl_session_t *session, row_head_t *row, row_head_t *ud_data, uint32 row_offset)
{
    uint16 head_size = cm_row_init_size(row->is_csf, ROW_COLUMN_COUNT(ud_data));
    char *dst_data = NULL;
    char *src_data = NULL;
    uint16 row_size = row->size;
    uint16 flags = row->flags;
    uint8 itl_id = ROW_ITL_ID(row);
    rowid_t *next_rid = NULL;
    errno_t ret;

    if (row->is_migr && !ud_data->is_migr) {
        ret = memcpy_sp(row, DEFAULT_PAGE_SIZE(session) - row_offset, ud_data, head_size);
        knl_securec_check(ret);
        dst_data = (char *)row + head_size + sizeof(rowid_t);
        src_data = (char *)ud_data + head_size + (ud_data->is_migr ? sizeof(rowid_t) : 0);
        // ud_data->size>= head_siz +(ud_data->is_migr ? sizeof(rowid_t) : 0 for update full type
        uint16 copy_size = ud_data->size - head_size - (ud_data->is_migr ? sizeof(rowid_t) : 0);
        row->is_migr = 1;
        next_rid = HEAP_LOC_LINK_RID(row);
        *next_rid = INVALID_ROWID;
        if (copy_size != 0) {
            uint32 write_pos = row_offset + head_size + sizeof(rowid_t);
            ret = memcpy_sp(dst_data, DEFAULT_PAGE_SIZE(session) - write_pos, src_data, copy_size);
            knl_securec_check(ret);
        }
    } else {
        ret = memcpy_sp(row, DEFAULT_PAGE_SIZE(session) - row_offset, ud_data, ud_data->size);
        knl_securec_check(ret);
    }

    knl_panic_log(row->size <= row_size, "undo data is wrong, panic info: undo data size %u row_size %u", row->size,
                  row_size);
    ROW_SET_ITL_ID(row, itl_id);
    row->flags = flags;
    row->size = row_size;
}

void heap_undo_link_row(knl_session_t *session, undo_row_t *ud_row, rowid_t *rid,
                        knl_dictionary_t *dc, heap_undo_assist_t *heap_assist)
{
    char *ud_data = ud_row->data;
    knl_update_info_t old_info;
    uint16 slot;
    page_id_t page_id = GET_ROWID_PAGE(*rid);
    uint16 ud_data_size = ud_row->data_size - (ud_row->contain_subpartno ? sizeof(knl_part_locate_t) : sizeof(uint32));

    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    if (page_is_damaged(&page->head)) {
        buf_leave_page(session, GS_FALSE);
        return;
    }

    row_dir_t *dir = heap_get_dir(page, (uint32)rid->slot);
    knl_panic_log(!dir->is_free, "dir is free, panic info: page %u-%u type %u", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type);
    row_head_t *row = HEAP_GET_ROW(page, dir);

    if (ud_row->type == UNDO_HEAP_UPDATE_FULL) {
        heap_undo_update_full(session, row, (row_head_t *)ud_row->data, dir->offset);
        slot = (uint16)rid->slot;
        if (SPC_IS_LOGGING_BY_PAGEID(session, page_id)) {
            log_put(session, RD_HEAP_UNDO_UPDATE_FULL, &slot, sizeof(uint16), LOG_ENTRY_FLAG_NONE);
            log_append_data(session, ud_data, ud_data_size);
        }
    } else {
        CM_SAVE_STACK(session->stack);
        CM_PUSH_UPDATE_INFO(session, old_info);

        heap_revert_update(session, (heap_undo_update_info_t *)ud_row->data, row, old_info.offsets, old_info.lens);
        slot = (uint16)rid->slot;
        if (SPC_IS_LOGGING_BY_PAGEID(session, page_id)) {
            log_put(session, RD_HEAP_UNDO_UPDATE, &slot, sizeof(uint16), LOG_ENTRY_FLAG_NONE);
            log_append_data(session, ud_data, ud_data_size);
        }

        CM_RESTORE_STACK(session->stack);
    }

    buf_leave_page(session, GS_TRUE);
}

void heap_undo_update(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot,
                      knl_dictionary_t *dc, heap_undo_assist_t *heap_assist)
{
    rowid_t rid = ud_row->rowid;
    heap_page_t *page = NULL;
    row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    itl_t *itl = NULL;
    char *undo_data = ud_row->data;
    errno_t ret;
    knl_update_info_t old_info;
    rd_heap_undo_t redo;
    rowid_t link_rid;
    uint16 slot;
    heap_t *heap = NULL;
    page_id_t page_id = GET_ROWID_PAGE(rid);
    uint16 ud_data_size = ud_row->data_size - (ud_row->contain_subpartno ? sizeof(knl_part_locate_t) : sizeof(uint32));

    if (!spc_validate_page_id(session, page_id)) {
        return;
    }

    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE(session);
    if (page_is_damaged((page_head_t *)page)) {
        buf_leave_page(session, GS_FALSE);
        return;
    }

    dir = heap_get_dir(page, (uint32)rid.slot);
    knl_panic_log(!dir->is_free, "dir is free, panic info: page %u-%u type %u", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type);
    knl_panic_log(IS_SAME_PAGID(dir->undo_page, AS_PAGID(ud_page->head.id)),
                  "dir's undo_page and ud_page are not same, panic info: page %u-%u type %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
    knl_panic_log(dir->undo_slot == ud_slot,
        "dir's undo_slot is not equal ud_slot, panic info: page %u-%u type %u dir undo_slot %u ud_slot %u",
        AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, dir->undo_slot, ud_slot);
    row = HEAP_GET_ROW(page, dir);

    bool32 is_link = row->is_link;
    if (is_link) {
        if (!heap_assist->need_latch) {
            knl_part_locate_t part_loc;
            if (ud_row->contain_subpartno) {
                part_loc = *(knl_part_locate_t *)((char *)ud_row->data + ud_data_size);
            } else {
                part_loc.part_no = *(uint32 *)((char *)ud_row->data + ud_data_size);
                part_loc.subpart_no = GS_INVALID_ID32;
            }
            heap = dc_get_heap(session, page->uid, page->oid, part_loc, dc);

            heap_assist->heap = heap;
            heap_assist->need_latch = GS_TRUE;
            buf_leave_page(session, GS_FALSE);
            return;
        }

        link_rid = *HEAP_LOC_LINK_RID(row);
        buf_leave_page(session, GS_FALSE);
        heap_undo_link_row(session, ud_row, &link_rid, dc, heap_assist);

        /* ok, now rollback the origin row */
        buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
        page = (heap_page_t *)CURR_PAGE(session);
        if (page_is_damaged((page_head_t *)page)) {
            buf_leave_page(session, GS_FALSE);
            return;
        }
        dir = heap_get_dir(page, (uint32)rid.slot);
        row = HEAP_GET_ROW(page, dir);
    }

    if (!row->is_migr) {
        knl_panic_log(ROW_ITL_ID(row) != GS_INVALID_ID8, "row_itl_id is invalid, panic info: page %u-%u type %u",
                      AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
        itl = heap_get_itl(page, ROW_ITL_ID(row));
        knl_panic_log(itl->is_active, "itl is inactive, panic info: page %u-%u type %u", AS_PAGID(page->head.id).file,
                      AS_PAGID(page->head.id).page, page->head.type);
        knl_panic_log(itl->xid.value == session->rm->xid.value, "the xid of itl and rm are not equal, panic info: "
                      "page %u-%u type %u itl xid %llu rm xid %llu", AS_PAGID(page->head.id).file,
                      AS_PAGID(page->head.id).page, page->head.type, itl->xid.value, session->rm->xid.value);
    }

    dir->is_owscn = ud_row->is_owscn;
    dir->undo_page = ud_row->prev_page;
    dir->undo_slot = ud_row->prev_slot;

    if (ud_row->is_xfirst) {
        dir->scn = ud_row->scn;
        ROW_SET_ITL_ID(row, GS_INVALID_ID8);
    } else {
        dir->scn = ud_row->ssn;
    }

    redo.slot = (uint16)rid.slot;
    redo.is_xfirst = (uint8)ud_row->is_xfirst;
    redo.is_owscn = (uint8)dir->is_owscn;
    redo.scn = dir->scn;
    redo.undo_page = dir->undo_page;
    redo.undo_slot = dir->undo_slot;
    redo.aligned = 0;
    if (SPC_IS_LOGGING_BY_PAGEID(session, page_id)) {
        log_put(session, RD_HEAP_UNDO_CHANGE_DIR, &redo, sizeof(rd_heap_undo_t), LOG_ENTRY_FLAG_NONE);
        log_append_data(session, dir, sizeof(row_dir_t));
    }

    if (is_link) {
        buf_leave_page(session, GS_TRUE);
        return;
    }

    if (ud_row->type == UNDO_HEAP_UPDATE_FULL) {
        uint16 row_size = row->size;
        uint16 flags = row->flags;
        uint8 itl_id = ROW_ITL_ID(row);

        ret = memcpy_sp(row, DEFAULT_PAGE_SIZE(session) - dir->offset, ud_row->data, ud_data_size);
        knl_securec_check(ret);
        knl_panic_log(row->size <= row_size,
            "ud_row data is wrong, panic info: page %u-%u type %u ud_row data size %u row_size %u",
            AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, row->size, row_size);
        ROW_SET_ITL_ID(row, itl_id);
        row->flags = flags;
        row->size = row_size;
        slot = (uint16)rid.slot;
        if (SPC_IS_LOGGING_BY_PAGEID(session, page_id)) {
            log_put(session, RD_HEAP_UNDO_UPDATE_FULL, &slot, sizeof(uint16), LOG_ENTRY_FLAG_NONE);
            log_append_data(session, undo_data, ud_data_size);
        }
    } else {
        CM_SAVE_STACK(session->stack);
        CM_PUSH_UPDATE_INFO(session, old_info);

        heap_revert_update(session, (heap_undo_update_info_t *)ud_row->data, row, old_info.offsets, old_info.lens);
        slot = (uint16)rid.slot;
        if (SPC_IS_LOGGING_BY_PAGEID(session, page_id)) {
            log_put(session, RD_HEAP_UNDO_UPDATE, &slot, sizeof(uint16), LOG_ENTRY_FLAG_NONE);
            log_append_data(session, undo_data, ud_data_size);
        }

        CM_RESTORE_STACK(session->stack);
    }

    buf_leave_page(session, GS_TRUE);
}

static void heap_delete_link_row(knl_session_t *session, knl_cursor_t *cursor, rowid_t lnk_rid)
{
    heap_page_t *page = NULL;
    row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    itl_t *itl = NULL;

    if (IS_INVALID_ROWID(lnk_rid)) {
        return;
    }

    log_atomic_op_begin(session);
    buf_enter_page(session, GET_ROWID_PAGE(lnk_rid), LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE(session);
    dir = heap_get_dir(page, (uint32)lnk_rid.slot);

    row = HEAP_GET_ROW(page, dir);
    row->is_deleted = 1;
    row->is_changed = 1;
    itl = heap_get_itl(page, ROW_ITL_ID(row));
    knl_panic_log(itl->is_active, "itl is inactive, panic info: page %u-%u type %u table %s", cursor->rowid.file,
        cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);
    // itl->fsc and row->size is less than DEFAULT_PAGE_SIZE(8192) ,
    // so the sum is less than max value(65535) of uint16
    itl->fsc += row->size;
    page->rows--;
    uint16 slot = (uint16)lnk_rid.slot;
    if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        log_put(session, RD_HEAP_DELETE_LINK, &slot, sizeof(uint16), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);
    log_atomic_op_end(session);
}

static status_t heap_delete_row(knl_session_t *session, knl_cursor_t *cursor, rowid_t rowid, rowid_t lnk_rid,
    bool32 is_org, uint16 data_size, bool32 self_update_check)
{
    undo_data_t undo;
    heap_page_t *page = NULL;
    row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    itl_t *itl = NULL;
    rd_heap_delete_t rd;
    heap_t *heap = CURSOR_HEAP(cursor);
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(heap->cipher_reserve_size);
    if (undo_prepare(session, data_size, IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type), need_encrypt) != GS_SUCCESS) {
        return GS_ERROR;
    }

    undo.type = is_org ? UNDO_HEAP_DELETE_ORG : UNDO_HEAP_DELETE;
    if (SECUREC_UNLIKELY(session->compacting)) {
        undo.type = is_org ? UNDO_HEAP_COMPACT_DELETE_ORG : UNDO_HEAP_COMPACT_DELETE;
    }
    undo.size = data_size;
    undo.rowid = rowid;
    // cursor->ssn is from session->xact_ssn(uint32) or stmt->xact_ssn(uint32) for not temp table
    undo.ssn = (uint32)cursor->ssn;

    log_atomic_op_begin(session);

    buf_enter_page(session, GET_ROWID_PAGE(rowid), LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE(session);
    dir = heap_get_dir(page, (uint32)rowid.slot);
    row = HEAP_GET_ROW(page, dir);
    if (row->is_changed && self_update_check && dir->scn == cursor->ssn) {
        cursor->is_found = (row->is_deleted == 0);
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);

        if (cursor->is_found) {
            GS_THROW_ERROR(ERR_ROW_SELF_UPDATED);
            return GS_ERROR;
        } else {
            return GS_SUCCESS;
        }
    }

    undo.snapshot.scn = cursor->is_xfirst ? (row->is_migr ? cursor->scn : dir->scn) : DB_CURR_SCN(session);
    undo.snapshot.is_owscn = dir->is_owscn;
    undo.snapshot.undo_page = dir->undo_page;
    undo.snapshot.undo_slot = dir->undo_slot;
    undo.snapshot.is_xfirst = cursor->is_xfirst;
    undo.snapshot.contain_subpartno = GS_FALSE;

    if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        dir->undo_page = session->rm->undo_page_info.undo_rid.page_id;
        // max undo page size is 32K, so max slot count for undo page is 744, less than uint16:15
        dir->undo_slot = session->rm->undo_page_info.undo_rid.slot;
    } else {
        dir->undo_page = session->rm->noredo_undo_page_info.undo_rid.page_id;
        dir->undo_slot = session->rm->noredo_undo_page_info.undo_rid.slot;
    }
    dir->scn = cursor->ssn;
    dir->is_owscn = 0;

    if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        rd.undo_page = session->rm->undo_page_info.undo_rid.page_id;
        rd.undo_slot = session->rm->undo_page_info.undo_rid.slot;
    } else {
        rd.undo_page = session->rm->noredo_undo_page_info.undo_rid.page_id;
        rd.undo_slot = session->rm->noredo_undo_page_info.undo_rid.slot;
    }
    rd.slot = (uint16)rowid.slot;
    rd.ssn = (uint32)cursor->ssn;

    undo.data = (row->is_migr || is_org) ? (char *)row : (char *)cursor->row;

    undo_write(session, &undo, IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type), GS_FALSE);

    knl_panic_log(!row->is_deleted, "row is deleted, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);
    row->is_deleted = 1;
    row->is_changed = 1;
    page->rows--;

    itl = heap_get_itl(page, ROW_ITL_ID(row));
    knl_panic_log(itl->is_active, "itl is inactive, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);

    // itl->fsc and row->size is less than DEFAULT_PAGE_SIZE(8192) , so the sum is less than max value(65535) of uint16
    itl->fsc += (row->is_link) ? HEAP_MIN_ROW_SIZE : row->size;

    if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        log_put(session, RD_HEAP_DELETE, &rd, sizeof(rd_heap_delete_t), LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, GS_TRUE);
    log_atomic_op_end(session);

    heap_delete_link_row(session, cursor, lnk_rid);

    return GS_SUCCESS;
}

static status_t heap_delete_chain_rows(knl_session_t *session, knl_cursor_t *cursor)
{
    row_chains_info_t *chain_info = (row_chains_info_t *)cursor->chain_info;
    row_chain_t *chain = NULL;
    rowid_t lnk_rid;
    uint8 i;

    lnk_rid = INVALID_ROWID;
    if (heap_delete_row(session, cursor, cursor->rowid, lnk_rid, GS_TRUE, HEAP_MIN_ROW_SIZE, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!cursor->is_found) {
        return GS_SUCCESS;
    }

    for (i = 0; i < cursor->chain_count; i++) {
        chain = chain_info->chains + i;

        if (heap_delete_row(session, cursor, chain->chain_rid, lnk_rid, GS_FALSE,
                            chain->data_size, GS_FALSE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t heap_delete(knl_session_t *session, knl_cursor_t *cursor)
{
    dc_entity_t *entity = NULL;

    SYNC_POINT(session, "SP_B4_HEAP_DELETE");
    knl_panic_log(cursor->is_valid, "cursor is invalid, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);

    CM_ASSERT(!DB_IS_CLUSTER(session));

    if (cursor->xid != session->rm->xid.value) {
        cursor->xid = session->rm->xid.value;
    }

    entity = (dc_entity_t *)cursor->dc_entity;
    bool32 has_logic = LOGIC_REP_DB_ENABLED(session) && dc_replication_enabled(session, entity, cursor->part_loc);
    if (has_logic && IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type) && (!IS_SYS_TABLE(&entity->table))) {
        log_atomic_op_begin(session);
        log_put(session, RD_LOGIC_REP_DELETE, NULL, 0, LOG_ENTRY_FLAG_WITH_LOGIC_OID);
        heap_append_logic_data(session, cursor, GS_TRUE);
        log_atomic_op_end(session);
    }

    if (entity->contain_lob) {
        if (GS_SUCCESS != lob_delete(session, cursor)) {
            return GS_ERROR;
        }
    }

    if (cursor->chain_count > 1) {
        return heap_delete_chain_rows(session, cursor);
    }

    if (heap_delete_row(session, cursor, cursor->rowid, cursor->link_rid, GS_FALSE,
                        cursor->row->size, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void heap_undo_delete_link_row(knl_session_t *session, rowid_t *link_rid)
{
    heap_page_t *page = NULL;
    row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    itl_t *itl = NULL;
    uint16 slot;
    page_id_t page_id = GET_ROWID_PAGE(*link_rid);

    log_atomic_op_begin(session);

    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE(session);
    if (page_is_damaged(&page->head)) {
        buf_leave_page(session, GS_FALSE);
        return;
    }

    dir = heap_get_dir(page, (uint32)link_rid->slot);

    row = HEAP_GET_ROW(page, dir);
    if (row->is_deleted) {
        row->is_deleted = 0;
        page->rows++;

        itl = heap_get_itl(page, ROW_ITL_ID(row));
        itl->fsc -= row->size;  // itl->fsc is larger than releated row's size
        slot = (uint16)link_rid->slot;
        if (SPC_IS_LOGGING_BY_PAGEID(session, page_id)) {
            log_put(session, RD_HEAP_UNDO_DELETE_LINK, &slot, sizeof(uint16), LOG_ENTRY_FLAG_NONE);
        }

        buf_leave_page(session, GS_TRUE);
        log_atomic_op_end(session);

        return;
    }
    buf_leave_page(session, GS_FALSE);

    log_atomic_op_end(session);
}

void heap_undo_delete(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot)
{
    rowid_t rid = ud_row->rowid;
    rowid_t link_rid;
    rd_heap_undo_t redo;
    heap_page_t *page = NULL;
    row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    itl_t *itl = NULL;
    page_id_t page_id = GET_ROWID_PAGE(rid);
    if (!spc_validate_page_id(session, page_id)) {
        return;
    }

    SET_ROWID_PAGE(&link_rid, INVALID_PAGID);

    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE(session);
    if (page_is_damaged((page_head_t *)page)) {
        buf_leave_page(session, GS_FALSE);
        return;
    }

    dir = heap_get_dir(page, (uint32)rid.slot);
    knl_panic_log(IS_SAME_PAGID(dir->undo_page, AS_PAGID(ud_page->head.id)),
                  "dir's undo_page and ud_page are not same, panic info: page %u-%u type %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
    knl_panic_log(dir->undo_slot == ud_slot, "dir's undo_slot is not equal ud_slot, panic info: page %u-%u type %u "
                  "dir undo_slot %u ud_slot %u", AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page,
                  page->head.type, dir->undo_slot, ud_slot);
    row = HEAP_GET_ROW(page, dir);
    knl_panic_log(ROW_ITL_ID(row) != GS_INVALID_ID8, "this row's itl_id is invalid, panic info: page %u-%u type %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);

    if (row->is_link) {
        link_rid = *HEAP_LOC_LINK_RID(row);
        buf_leave_page(session, GS_FALSE);

        log_atomic_op_end(session);

        if (!IS_INVALID_ROWID(link_rid)
            && (ud_row->type == UNDO_HEAP_DELETE || ud_row->type == UNDO_HEAP_COMPACT_DELETE)) {
            heap_undo_delete_link_row(session, &link_rid);
        }

        log_atomic_op_begin(session);

        buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
        page = (heap_page_t *)CURR_PAGE(session);
        if (page_is_damaged((page_head_t *)page)) {
            buf_leave_page(session, GS_FALSE);
            return;
        }
        dir = heap_get_dir(page, (uint32)rid.slot);
        row = HEAP_GET_ROW(page, dir);
    }

    itl = heap_get_itl(page, ROW_ITL_ID(row));
    knl_panic_log(itl->is_active, "itl is inactive, panic info: page %u-%u type %u", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type);
    knl_panic_log(itl->xid.value == session->rm->xid.value, "the xid of itl and rm do not match, panic info: "
                  "page %u-%u type %u itl xid %llu rm xid %llu", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, itl->xid.value, session->rm->xid.value);

    dir->is_owscn = ud_row->is_owscn;
    dir->undo_page = ud_row->prev_page;
    dir->undo_slot = ud_row->prev_slot;

    // to keep consistent read, only after rollback, can we set the dir itl_id to invalid.
    if (ud_row->is_xfirst) {
        dir->scn = ud_row->scn;
        ROW_SET_ITL_ID(row, GS_INVALID_ID8);
    } else {
        dir->scn = ud_row->ssn;
    }

    row->is_deleted = 0;
    page->rows++;

    /* itl->fsc is larger than the releated row's size */
    if (row->is_link) {
        itl->fsc -= HEAP_MIN_ROW_SIZE;
    } else {
        itl->fsc -= row->size;
    }

    redo.slot = (uint16)rid.slot;
    redo.is_xfirst = (uint8)ud_row->is_xfirst;
    redo.is_owscn = (uint8)dir->is_owscn;
    redo.scn = dir->scn;
    redo.undo_page = dir->undo_page;
    redo.undo_slot = dir->undo_slot;
    redo.aligned = 0;
    if (SPC_IS_LOGGING_BY_PAGEID(session, page_id)) {
        log_put(session, RD_HEAP_UNDO_DELETE, &redo, sizeof(rd_heap_undo_t), LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, GS_TRUE);
}

static void heap_reorganize_with_undo(knl_session_t *session, const knl_cursor_t *cursor, query_snapshot_t *query_info,
                                      undo_row_t *ud_row, bool32 *is_found)
{
    errno_t ret;
    *is_found = GS_TRUE;
    table_t *table = (table_t *)cursor->table;
    uint32 partloc_size = undo_part_locate_size(table);

    if (ud_row->type == UNDO_HEAP_UPDATE) {
        knl_panic_log(query_info->row != NULL, "row is NULL, panic info: page %u-%u type %u table %s",
            cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, table->desc.name);
        heap_revert_update(session, (heap_undo_update_info_t *)ud_row->data, query_info->row,
                           query_info->offsets, query_info->lens);
    } else if (ud_row->type == UNDO_HEAP_INSERT) {
        *is_found = GS_FALSE;
    } else if (ud_row->type == UNDO_HEAP_DELETE || ud_row->type == UNDO_HEAP_DELETE_ORG ||
        ud_row->type == UNDO_HEAP_COMPACT_DELETE || ud_row->type == UNDO_HEAP_COMPACT_DELETE_ORG) {
        ret = memcpy_sp(query_info->row, ud_row->data_size, ud_row->data, ud_row->data_size);
        knl_securec_check(ret);
    } else if (ud_row->type == UNDO_HEAP_DELETE_MIGR) {
        row_head_t *org_orw = (row_head_t *)((char *)ud_row->data + partloc_size + sizeof(rowid_t));
        ret = memcpy_sp(query_info->row, org_orw->size, org_orw, org_orw->size);
        knl_securec_check(ret);
    } else if (ud_row->type == UNDO_HEAP_UPDATE_FULL) {
        ret = memcpy_sp(query_info->row, ud_row->data_size - partloc_size, ud_row->data,
                        ud_row->data_size - partloc_size);
        knl_securec_check(ret);
    } else if (ud_row->type == UNDO_HEAP_UPDATE_LINKRID) {
        *HEAP_LOC_LINK_RID(query_info->row) = *(rowid_t *)ud_row->data;
    }
}

static status_t heap_reorganize_with_udss(knl_session_t *session, knl_cursor_t *cursor, query_snapshot_t *query_info,
                                          undo_snapshot_t *snapshot, bool32 *is_found)
{
    if (buf_read_page(session, PAGID_U2N(snapshot->undo_page), LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
        return GS_ERROR;
    }

    undo_page_t *ud_page = (undo_page_t *)CURR_PAGE(session);
    if ((uint16)snapshot->undo_slot >= ud_page->rows) {
        buf_leave_page(session, GS_FALSE);
        tx_record_sql(session);
        GS_LOG_RUN_ERR("snapshot too old, detail: snapshot slot %u, undo rows %u, query scn %llu",
                       (uint32)snapshot->undo_slot, ud_page->rows, query_info->query_scn);
        GS_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
        return GS_ERROR;
    }

    undo_row_t *ud_row = UNDO_ROW(session, ud_page, snapshot->undo_slot);
    if (!snapshot->is_xfirst) {
        if (snapshot->xid != ud_row->xid.value) {
            buf_leave_page(session, GS_FALSE);
            tx_record_sql(session);
            GS_LOG_RUN_ERR("snapshot too old, detail: snapshot xid %llu, undo row xid %llu, query scn %llu",
                           snapshot->xid, ud_row->xid.value, query_info->query_scn);
            GS_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
            return GS_ERROR;
        }
    } else {
        if (snapshot->scn <= ud_row->scn || !IS_SAME_ROWID(ud_row->rowid, query_info->rowid)) {
            buf_leave_page(session, GS_FALSE);
            tx_record_sql(session);
            GS_LOG_RUN_ERR("snapshot too old, detail: snapshot scn %llu, undo row scn %llu, query scn %llu",
                           snapshot->scn, ud_row->scn, query_info->query_scn);
            GS_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
            return GS_ERROR;
        }
    }

    if (ud_row->xid.value == query_info->xid) {
        if (ud_row->ssn < query_info->ssn) {
            // The last undo generated before open cursor.
            // Use undo scn to overwrite snapshot scn to replaceS
            // ud_row->ssn < cursor->ssn judgement.
            knl_panic_log(ud_row->scn <= query_info->query_scn, "ud_row's scn is more than query_info's query_scn, "
                          "panic info: page %u-%u type %u table %s ud_row scn %llu query_scn %llu",
                          cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                          ((table_t *)cursor->table)->desc.name, ud_row->scn, query_info->query_scn);
            *is_found = (ud_row->type != UNDO_HEAP_DELETE && ud_row->type != UNDO_HEAP_DELETE_ORG &&
                         ud_row->type != UNDO_HEAP_DELETE_MIGR && ud_row->type != UNDO_HEAP_COMPACT_DELETE &&
                         ud_row->type != UNDO_HEAP_COMPACT_DELETE_ORG);
            snapshot->scn = ud_row->scn;
            snapshot->is_owscn = GS_FALSE;
            snapshot->is_xfirst = GS_TRUE;
            snapshot->xid = ud_row->xid.value;
            buf_leave_page(session, GS_FALSE);
            return GS_SUCCESS;
        }
    }

    heap_reorganize_with_undo(session, cursor, query_info, ud_row, is_found);

    snapshot->undo_page = ud_row->prev_page;
    if (!query_info->row->is_link && query_info->row->is_migr) {
        if (ud_row->xid.value == query_info->xid) {
            if (IS_INVALID_PAGID(PAGID_U2N(snapshot->undo_page))) {
                *is_found = (ud_row->type == UNDO_HEAP_UPDATE || ud_row->type == UNDO_HEAP_UPDATE_FULL ||
                             ud_row->type == UNDO_HEAP_UPDATE_LINKRID || ud_row->type == UNDO_HEAP_DELETE_MIGR ||
                             ud_row->type == UNDO_HEAP_DELETE || ud_row->type == UNDO_HEAP_COMPACT_DELETE);
                knl_panic_log(*is_found,
                              "ud_row type is abnormal, panic info: page %u-%u type %u table %s ud_row type %u",
                              cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                              ((table_t *)cursor->table)->desc.name, ud_row->type);
                snapshot->scn = ud_row->ssn;
                snapshot->is_owscn = GS_FALSE;
                snapshot->is_xfirst = GS_TRUE;
                snapshot->xid = ud_row->xid.value;
                buf_leave_page(session, GS_FALSE);
                return GS_SUCCESS;
            }
        }
    }

    snapshot->undo_slot = ud_row->prev_slot;
    snapshot->scn = ud_row->scn;
    snapshot->is_owscn = ud_row->is_owscn;
    snapshot->is_xfirst = ud_row->is_xfirst;
    snapshot->xid = ud_row->xid.value;
    buf_leave_page(session, GS_FALSE);

    return GS_SUCCESS;
}

static status_t heap_reorganize_with_undo_list(knl_session_t *session, knl_cursor_t *cursor,
                                               query_snapshot_t *query_ss, undo_snapshot_t *snapshot, bool32 *is_found)
{
    page_id_t page_id;

    for (;;) {
        page_id = PAGID_U2N(snapshot->undo_page);
        if (IS_INVALID_PAGID(page_id)) {
            // row inserted after query starting
            *is_found = GS_FALSE;
            return GS_SUCCESS;
        }

        if (heap_reorganize_with_udss(session, cursor, query_ss, snapshot, is_found) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!snapshot->is_xfirst) {
            continue;
        }

        if (snapshot->scn <= query_ss->query_scn) {
            query_ss->scn = snapshot->scn;
            return GS_SUCCESS;
        }

        if (snapshot->is_owscn) {
            tx_record_sql(session);
            GS_LOG_RUN_ERR("snapshot too old, detail: snapshot owscn %llu, query scn %llu",
                           snapshot->scn, query_ss->query_scn);
            GS_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
            return GS_ERROR;
        }

        if (cursor->isolevel == (uint8)ISOLATION_SERIALIZABLE) {
            cursor->ssi_conflict = GS_TRUE;
        }
    }
}

static status_t heap_check_visible_with_udss(knl_session_t *session, knl_cursor_t *cursor,
    bool32 check_restart, bool32 *is_found)
{
    if (buf_read_page(session, PAGID_U2N(cursor->snapshot.undo_page), LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
        return GS_ERROR;
    }

    undo_page_t *ud_page = (undo_page_t *)CURR_PAGE(session);
    if ((uint16)cursor->snapshot.undo_slot >= ud_page->rows) {
        buf_leave_page(session, GS_FALSE);
        tx_record_sql(session);
        GS_LOG_RUN_ERR("snapshot too old, detail: snapshot slot %u, undo rows %u,"
            " query scn %llu, check_restart %u",
            (uint32)cursor->snapshot.undo_slot, ud_page->rows, cursor->query_scn, (uint32)check_restart);
        GS_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
        return GS_ERROR;
    }

    undo_row_t *ud_row = UNDO_ROW(session, ud_page, (uint16)cursor->snapshot.undo_slot);
    if (!cursor->snapshot.is_xfirst) {
        if (cursor->snapshot.xid != ud_row->xid.value) {
            buf_leave_page(session, GS_FALSE);
            tx_record_sql(session);
            GS_LOG_RUN_ERR("snapshot too old, detail: snapshot xid %llu, undo row xid %llu,"
                " query scn %llu, check_restart %u",
                cursor->snapshot.xid, ud_row->xid.value, cursor->query_scn, (uint32)check_restart);
            GS_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
            return GS_ERROR;
        }
    } else {
        if (cursor->snapshot.scn <= ud_row->scn || !IS_SAME_ROWID(ud_row->rowid, cursor->rowid)) {
            buf_leave_page(session, GS_FALSE);
            tx_record_sql(session);
            GS_LOG_RUN_ERR("snapshot too old, detail: snapshot scn %llu, undo row scn %llu,"
                " query scn %llu, check_restart %u",
                cursor->snapshot.scn, ud_row->scn, cursor->query_scn, (uint32)check_restart);
            GS_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
            return GS_ERROR;
        }
    }

    if (ud_row->xid.value == cursor->xid && ud_row->ssn < cursor->ssn) {
        // The last undo generated before open cursor.
        // Use undo scn to overwrite snapshot scn to replace
        // ud_row->ssn < cursor->ssn judgement.
        knl_panic_log(ud_row->scn <= cursor->query_scn, "ud_row's scn is more than cursor's query_scn, panic info: "
                      "page %u-%u type %u table %s ud_row scn %llu query_scn %llu", cursor->rowid.file,
                      cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                      ((table_t *)cursor->table)->desc.name, ud_row->scn, cursor->query_scn);
        *is_found = (ud_row->type != UNDO_HEAP_DELETE && ud_row->type != UNDO_HEAP_DELETE_ORG &&
                     ud_row->type != UNDO_HEAP_DELETE_MIGR && ud_row->type != UNDO_HEAP_COMPACT_DELETE &&
                     ud_row->type != UNDO_HEAP_COMPACT_DELETE_ORG);
        cursor->snapshot.scn = ud_row->scn;
        cursor->snapshot.is_owscn = GS_FALSE;
        cursor->snapshot.is_xfirst = GS_TRUE;
        cursor->snapshot.xid = ud_row->xid.value;
        buf_leave_page(session, GS_FALSE);
        return GS_SUCCESS;
    }

    if (check_restart) {
        if (ud_row->type == UNDO_HEAP_COMPACT_DELETE || ud_row->type == UNDO_HEAP_COMPACT_DELETE_ORG) {
            buf_leave_page(session, GS_FALSE);
            GS_THROW_ERROR(ERR_NEED_RESTART);
            return GS_ERROR;
        }
    } else {
        *is_found = (ud_row->type != UNDO_HEAP_INSERT);
    }

    cursor->snapshot.undo_page = ud_row->prev_page;
    cursor->snapshot.undo_slot = ud_row->prev_slot;
    cursor->snapshot.scn = ud_row->scn;
    cursor->snapshot.is_owscn = ud_row->is_owscn;
    cursor->snapshot.is_xfirst = ud_row->is_xfirst;
    cursor->snapshot.xid = ud_row->xid.value;
    buf_leave_page(session, GS_FALSE);

    return GS_SUCCESS;
}

/*
 * Check whether the last committed version belongs to current action
 * to keep statement level write consistency.
 *
 * @notes If row has been deleted after our fetch began, the row dir has
 * been reused by other sessions. We should not modify current committed
 * row inserted or modified by following transactions which belongs to us.
 * @param kernel session, kernel cursor, is_found(output)
 */
static status_t heap_check_current_visible(knl_session_t *session, knl_cursor_t *cursor,
    bool32 check_restart, bool32 *is_found)
{
    for (;;) {
        if (IS_INVALID_PAGID(cursor->snapshot.undo_page)) {
            // this would never happened
            *is_found = GS_FALSE;
            return GS_SUCCESS;
        }

        if (heap_check_visible_with_udss(session, cursor, check_restart, is_found) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!cursor->snapshot.is_xfirst) {
            continue;
        }

        if (cursor->snapshot.scn <= cursor->query_scn) {
            return GS_SUCCESS;
        }

        if (cursor->snapshot.is_owscn) {
            tx_record_sql(session);
            GS_LOG_RUN_ERR("snapshot too old, detail: snapshot owscn %llu, query scn %llu, check_restart %u",
                           cursor->snapshot.scn, cursor->query_scn, (uint32)check_restart);
            GS_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
            return GS_ERROR;
        }

        if (check_restart) {
            continue;
        }

        if (!*is_found) {
            // visible row has been deleted
            return GS_SUCCESS;
        }
    }
}

/*
 * reorganize the chain row
 * If row column count are not matched with actual column count, try to
 * adjust the bitmap and row data position
 * @param kernel session, kernel cursor, row assist, column count
 */
void heap_reorganize_chain_row(knl_session_t *session, knl_cursor_t *cursor, row_assist_t *ra, uint16 column_count)
{
    row_head_t *row = cursor->row;
    char *data_addr = NULL;
    char *new_data_addr = NULL;
    uint16 data_size, new_bitmap_size;
    uint16 ext_bitmap, new_ext_bitmap;
    errno_t ret;

    if (row->is_csf) {
        if (ROW_COLUMN_COUNT(row) >= GS_SPRS_COLUMNS && column_count < GS_SPRS_COLUMNS) {
            row->column_count = column_count;
            row->itl_id = row->sprs_itl_id;

            /* calculate row data address and data size */
            data_addr = (char *)row + OFFSET_OF(row_head_t, sprs_bitmap);
            new_data_addr = (char *)row + OFFSET_OF(row_head_t, bitmap);
            data_size = row->size - (uint16)OFFSET_OF(row_head_t, sprs_bitmap);

            ret = memmove_s(new_data_addr, data_size, data_addr, data_size);
            knl_securec_check(ret);
        } else {
            ROW_SET_COLUMN_COUNT(row, column_count);
        }
        return;
    }

    ext_bitmap = ROW_BITMAP_EX_SIZE(row);
    new_ext_bitmap = COL_BITMAP_EX_SIZE(column_count);
    if (ext_bitmap == new_ext_bitmap) {
        /* bitmap not changed, nothing to do */
        return;
    }

    /* calculate row data address and data size */
    data_addr = (char *)row + sizeof(row_head_t) + ext_bitmap;
    new_data_addr = (char *)row + sizeof(row_head_t) + new_ext_bitmap;
    data_size = row->size - sizeof(row_head_t) - ext_bitmap;

    knl_panic_log(sizeof(row_head_t) + new_ext_bitmap + data_size <= GS_MAX_ROW_SIZE, "the row size is more than "
                  "max row size, panic info: page %u-%u type %u table %s new_ext_bitmap %u data_size %u",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, new_ext_bitmap, data_size);
    /*
     * If cursor row is SPRS row, actual row is normal row, we should
     * re-init a new normal row head use current SPRS row, and move
     * bitmap to its new correct address first, than move the row data.
     * Other wise, only move the row data.
     */
    if (ROW_COLUMN_COUNT(row) >= GS_SPRS_COLUMNS && column_count < GS_SPRS_COLUMNS) {
        row->column_count = column_count;
        row->itl_id = row->sprs_itl_id;

        /* calculate row data address and data size */
        char *bitmap_addr = (char *)row + OFFSET_OF(row_head_t, sprs_bitmap);
        new_bitmap_size = sizeof(row_head_t) - (uint16)OFFSET_OF(row_head_t, bitmap) + new_ext_bitmap;
        char *new_bitmap_addr = (char *)row + OFFSET_OF(row_head_t, bitmap);

        ret = memmove_s(new_bitmap_addr, new_bitmap_size, bitmap_addr, new_bitmap_size);
        knl_securec_check(ret);
    } else {
        // reset the column count with the actual row count
        ROW_SET_COLUMN_COUNT(row, column_count);
    }

    ret = memmove_s(new_data_addr, data_size, data_addr, data_size);
    knl_securec_check(ret);

    // data_size is less than HEAP_MAX_ROW_SIZE(session) , so the sum is less than max value(65535) of uint16
    row->size = sizeof(row_head_t) + new_ext_bitmap + data_size;
}

void heap_merge_chain_row(knl_cursor_t *cursor, row_head_t *row, uint16 col_id_input, uint16 data_size, uint16 *offset)
{
    uint16 col_id = col_id_input;
    uint8 bits;
    uint16 copy_size;
    errno_t ret;
    char *data = (char *)cursor->row + *offset;
    char *row_data = NULL;
    uint32 i;
    uint16 col_count;

    col_count = ROW_COLUMN_COUNT(row);

    if (!row->is_csf) {
        for (i = 0; i < col_count; i++) {
            bits = row_get_column_bits2(row, i);
            row_set_column_bits2(cursor->row, bits, col_id++);
        }
    }

    copy_size = data_size - HEAP_ROW_DATA_OFFSET(row);
    if (copy_size != 0) { // all columns are not null
        knl_panic_log(cursor->row->size + copy_size <= GS_VMEM_PAGE_SIZE, "the row size is more than "
                      "the vmem page size, panic info: page %u-%u type %u table %s current row size %u copy_size %u",
                      cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                      ((table_t *)cursor->table)->desc.name, cursor->row->size, copy_size);
        row_data = (char *)HEAP_LOC_CHAIN_ROW_DATA(row);
        ret = memcpy_sp(data, GS_VMEM_PAGE_SIZE - *offset, row_data, copy_size);
        knl_securec_check(ret);
        *offset += copy_size;
        cursor->row->size += copy_size;  // the sum of chain row size is less than GS_MAX_ROW_SIZE(64000)
    }
}

static status_t heap_get_chain_migr_row(knl_session_t *session, knl_cursor_t *cursor, row_head_t *chain_row,
    row_head_t *row)
{
    rowid_t next_rid = *HEAP_LOC_LINK_RID(chain_row);
    if (IS_INVALID_ROWID(next_rid)) {
        return GS_SUCCESS;
    }

    if (buf_read_page(session, GET_ROWID_PAGE(next_rid), LATCH_MODE_FORCE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
        return GS_ERROR;
    }

    heap_page_t *migr_page = (heap_page_t *)CURR_PAGE(session);
    if (!heap_check_page(session, cursor, migr_page, PAGE_TYPE_HEAP_DATA)) {
        buf_leave_page(session, GS_FALSE);
        HEAP_CHECKPAGE_ERROR(cursor);
        return GS_ERROR;
    }

    row_dir_t migr_dir = *heap_get_dir(migr_page, (uint32)next_rid.slot);
    row_head_t *migr_row = HEAP_GET_ROW(migr_page, &migr_dir);
    next_rid = *HEAP_LOC_LINK_RID(migr_row);
    if (IS_INVALID_ROWID(next_rid)) {
        errno_t ret = memcpy_sp(row, HEAP_MAX_MIGR_ROW_SIZE(session), migr_row, migr_row->size);
        knl_securec_check(ret);
    }
    buf_leave_page(session, GS_FALSE);
    return GS_SUCCESS;
}

static void heap_get_chain_row(knl_session_t *session, knl_cursor_t *cursor, row_head_t *row,
    row_head_t **chain_row, rowid_t next_rid, undo_snapshot_t *snapshot, knl_scn_t query_scn)
{
    itl_t *itl = NULL;
    txn_info_t txn_info;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    row_dir_t dir = *heap_get_dir(page, (uint32)next_rid.slot);
    if (dir.is_free) {
        *chain_row = NULL;
    } else {
        *chain_row = HEAP_GET_ROW(page, &dir);
        errno_t ret = memcpy_sp(row, HEAP_MAX_MIGR_ROW_SIZE(session), *chain_row, (*chain_row)->size);
        knl_securec_check(ret);
    }

    if ((*chain_row) == NULL || (ROW_ITL_ID(*chain_row) == GS_INVALID_ID8) || !(*chain_row)->is_changed) {
        txn_info.scn = dir.scn;
        txn_info.is_owscn = (uint8)dir.is_owscn;
        txn_info.status = (uint8)XACT_END;
    } else {
        itl = heap_get_itl(page, ROW_ITL_ID(*chain_row));
        tx_get_itl_info(session, GS_TRUE, itl, &txn_info);
    }

    snapshot->is_valid = GS_FALSE;
    if (txn_info.status == (uint8)XACT_END) {
        if (txn_info.scn > query_scn) {
            snapshot->is_valid = GS_TRUE;
            snapshot->scn = txn_info.scn;
            snapshot->is_xfirst = GS_TRUE;
            snapshot->xid = GS_INVALID_ID64;
        }
    } else {
        if (itl->xid.value != cursor->xid || dir.scn >= cursor->ssn) {
            snapshot->is_valid = GS_TRUE;
            snapshot->scn = DB_CURR_SCN(session);
            snapshot->is_xfirst = GS_FALSE;
            snapshot->xid = itl->xid.value;
        }
    }

    if (!snapshot->is_valid) {
        knl_panic_log(*chain_row != NULL, "chain_row is NULL, panic info: page %u-%u type %u table %s",
                      cursor->rowid.file, cursor->rowid.page, page->head.type, ((table_t *)cursor->table)->desc.name);
        knl_panic_log(!(*chain_row)->is_deleted, "chain_row is deleted, panic info: page %u-%u type %u table %s",
                      cursor->rowid.file, cursor->rowid.page, page->head.type, ((table_t *)cursor->table)->desc.name);
    }

    if (snapshot->is_valid) {
        snapshot->is_owscn = txn_info.is_owscn;
        snapshot->undo_page = dir.undo_page;
        snapshot->undo_slot = dir.undo_slot;
    }
}

static status_t heap_fetch_chain_row(knl_session_t *session, knl_cursor_t *cursor, rowid_t next_rid,
    knl_scn_t query_scn, row_head_t *row, undo_snapshot_t *snapshot)
{
    row_head_t *chain_row = NULL;

    SYNC_POINT(session, "SP_B1_HEAP_GET_CHAIN_ROW");
    SYNC_POINT(session, "SP_B2_HEAP_GET_CHAIN_ROW");

    if (buf_read_page(session, GET_ROWID_PAGE(next_rid), LATCH_MODE_FORCE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
        return GS_ERROR;
    }
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);

    if (!heap_check_page(session, cursor, page, PAGE_TYPE_HEAP_DATA)) {
        buf_leave_page(session, GS_FALSE);
        HEAP_CHECKPAGE_ERROR(cursor);
        return GS_ERROR;
    }

    if ((uint16)next_rid.slot >= page->dirs) {
        buf_leave_page(session, GS_FALSE);
        GS_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, "table");
        return GS_ERROR;
    }

    heap_get_chain_row(session, cursor, row, &chain_row, next_rid, snapshot, query_scn);

    if (chain_row != NULL && chain_row->is_link) {
        if (heap_get_chain_migr_row(session, cursor, chain_row, row) != GS_SUCCESS) {
            buf_leave_page(session, GS_FALSE);
            return GS_ERROR;
        }
    }

    buf_leave_page(session, GS_FALSE);
    return GS_SUCCESS;
}

static status_t heap_fetch_chain_rows(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn)
{
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    row_assist_t ra;
    uint16 size;
    uint16 col_count = 0;
    row_chain_t *chain = NULL;
    rowid_t owner_rid = cursor->rowid;
    query_snapshot_t query_ss;
    undo_snapshot_t snapshot;
    uint16 *offsets = NULL;
    uint16 *lens = NULL;
    rowid_t next_rid;
    row_head_t *row = NULL;
    uint16 data_offset;
    bool32 is_found = GS_FALSE;
    bool32 is_csf = cursor->row->is_csf;
    uint32 max_row_len = heap_table_max_row_len(cursor->table, GS_MAX_ROW_SIZE, cursor->part_loc);

    next_rid = *HEAP_LOC_LINK_RID(cursor->row);
    if (knl_cursor_use_vm(session, cursor, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);

    /* the max value of entity->column_count is GS_MAX_COLUMNS(4096) */
    offsets = (uint16 *)cm_push(session->stack, entity->column_count * sizeof(uint16));
    lens = (uint16 *)cm_push(session->stack, entity->column_count * sizeof(uint16));
    row = (row_head_t *)cm_push(session->stack, HEAP_MAX_MIGR_ROW_SIZE(session));

    query_ss.scn = cursor->scn;
    query_ss.query_scn = query_scn;
    query_ss.ssn = cursor->ssn;
    query_ss.xid = cursor->xid;
    query_ss.row = (row_head_t *)row;

    cm_row_init(&ra, (char *)cursor->row, max_row_len, entity->column_count, is_csf);
    data_offset = cursor->row->size;
    cursor->chain_count = 0;

    do {
        if (heap_fetch_chain_row(session, cursor, next_rid, query_scn, row, &snapshot) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (snapshot.is_valid) {
            query_ss.lens = lens;
            query_ss.offsets = offsets;
            query_ss.rowid = next_rid;
            query_ss.row = (row_head_t *)row;

            if (heap_reorganize_with_undo_list(session, cursor, &query_ss, &snapshot, &is_found) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }

            if (!is_found) {
                GS_THROW_ERROR(ERR_INVALID_ROWID);
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
        }

        cm_decode_row((char *)row, offsets, lens, &size);

        chain = HEAP_GET_EXT_LINK(cursor->chain_info, cursor->chain_count);
        chain->owner_rid = owner_rid;
        chain->chain_rid = next_rid;
        chain->next_rid = *HEAP_LOC_LINK_RID(row);
        chain->col_start = col_count;
        chain->data_size = size;
        chain->row_size = row->size;
        chain->col_count = ROW_COLUMN_COUNT(row);

        heap_merge_chain_row(cursor, row, col_count, size, &data_offset);

        col_count += chain->col_count;  // the sum of each chain's column count is  <= GS_MAX_COLUMNS(4096)
        cursor->chain_count++;
        owner_rid = next_rid;
        next_rid = *HEAP_LOC_LINK_RID(row);
    } while (!IS_INVALID_ROWID(next_rid));

    CM_RESTORE_STACK(session->stack);

    if (col_count != entity->column_count) {
        heap_reorganize_chain_row(session, cursor, &ra, col_count);
    }
    row_end(&ra);

    return GS_SUCCESS;
}

static status_t heap_get_migr_row(knl_session_t *session, knl_cursor_t *cursor, bool32 *is_found)
{
    row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    heap_page_t *page = NULL;
    rowid_t next_rid;
    errno_t ret;

    if (buf_read_page(session, GET_ROWID_PAGE(cursor->link_rid), LATCH_MODE_FORCE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
        return GS_ERROR;
    }
    page = (heap_page_t *)CURR_PAGE(session);
    dir = heap_get_dir(page, (uint32)cursor->link_rid.slot);
    if (dir->is_free) {
        buf_leave_page(session, GS_FALSE);
        return GS_SUCCESS;
    }
    row = HEAP_GET_ROW(page, dir);
    if (!row->is_migr) {
        buf_leave_page(session, GS_FALSE);
        return GS_SUCCESS;
    }
    next_rid = *HEAP_LOC_LINK_RID(row);
    if (IS_INVALID_ROWID(next_rid)) {
        ret = memcpy_sp(cursor->row, row->size, row, row->size);
        knl_securec_check(ret);
        cursor->row->is_link = 1;
        cursor->chain_count = 1;
    }
    buf_leave_page(session, GS_FALSE);
    return GS_SUCCESS;
}

static status_t heap_get_row(knl_session_t *session, knl_cursor_t *cursor, heap_page_t *page,
                             knl_scn_t query_scn, bool32 *is_found)
{
    row_dir_t *dir;
    row_head_t *row = NULL;
    txn_info_t txn_info;
    itl_t *itl = NULL;

    dir = heap_get_dir(page, (uint32)cursor->rowid.slot);
    if (dir->is_free) {
        row = NULL;
    } else {
        row = HEAP_GET_ROW(page, dir);
        if (row->is_migr) {
            session->has_migr = GS_TRUE;
            *is_found = GS_FALSE;
            return GS_SUCCESS;
        }
    }

    if (row == NULL || (ROW_ITL_ID(row) == GS_INVALID_ID8) || !row->is_changed) {
        itl = NULL;
        txn_info.status = (uint8)XACT_END;
        txn_info.is_owscn = (uint8)dir->is_owscn;
        cursor->scn = dir->scn;
    } else {
        itl = heap_get_itl(page, ROW_ITL_ID(row));
        tx_get_itl_info(session, GS_TRUE, itl, &txn_info);
        cursor->scn = txn_info.scn;

        if (itl->is_active && txn_info.status == (uint8)XACT_END) {
            cursor->cleanout = GS_TRUE;
        }
    }

    cursor->snapshot.undo_page = dir->undo_page;
    cursor->snapshot.undo_slot = dir->undo_slot;

    if (txn_info.status == (uint8)XACT_END) {
        cursor->snapshot.scn = cursor->scn;
        cursor->snapshot.is_xfirst = GS_TRUE;
        cursor->snapshot.xid = GS_INVALID_ID64;

        if (cursor->scn <= query_scn) {
            *is_found = ((row != NULL) && !(row->is_deleted));
            if (*is_found) {
                HEAP_COPY_ROW(session, cursor, row);
            }
            return GS_SUCCESS;
        }

        if (txn_info.is_owscn) {
            tx_record_sql(session);
            GS_LOG_RUN_ERR("snapshot too old, detail: dir owscn %llu, query scn %llu", cursor->scn, query_scn);
            GS_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
            return GS_ERROR;
        }

        if (cursor->isolevel == (uint8)ISOLATION_SERIALIZABLE) {
            cursor->ssi_conflict = GS_TRUE;
        }

        if (row != NULL) {
            HEAP_COPY_ROW(session, cursor, row);
        }
    } else {
        cursor->snapshot.scn = DB_CURR_SCN(session);
        cursor->snapshot.is_xfirst = GS_FALSE;
        cursor->snapshot.xid = itl->xid.value;

        if (itl->xid.value == cursor->xid) {
            if (dir->scn < cursor->ssn) {
                *is_found = !(row->is_deleted);
                if (*is_found) {
                    HEAP_COPY_ROW(session, cursor, row);
                }
                return GS_SUCCESS;
            }
        } else {
            if (TX_XA_CONSISTENCY(session) &&
                (txn_info.status == (uint8)XACT_PHASE1 || txn_info.status == (uint8)XACT_PHASE2) &&
                txn_info.scn < query_scn) {
                GS_LOG_DEBUG_INF("need read wait.prepare_scn[%llu] <= query_scn[%llu]", txn_info.scn, query_scn);
                session->wxid = itl->xid;
                ROWID_COPY(session->wrid, cursor->rowid);
                *is_found = GS_FALSE;
                return GS_SUCCESS;
            }
        }

        if (row != NULL) {
            HEAP_COPY_ROW(session, cursor, row);
        }
    }

    *is_found = GS_TRUE;
    cursor->snapshot.is_valid = 1;

    return GS_SUCCESS;
}

static inline void heap_scan_backspace_cursor(knl_cursor_t *cursor)
{
    knl_panic(cursor->rowid.slot != INVALID_SLOT);
    if (cursor->rowid.slot <= 0) {
        cursor->rowid.slot = INVALID_SLOT;
    } else {
        --cursor->rowid.slot;
    }
}

static status_t heap_scan_full_page(knl_session_t *session, knl_cursor_t *cursor, heap_page_t *page,
                                    knl_scn_t query_scn, bool32 *is_found)
{
    *is_found = GS_FALSE;
    cursor->snapshot.is_valid = 0;

    for (;;) {
        SET_ROWID_PAGE(&cursor->link_rid, INVALID_PAGID);
        cursor->chain_count = 0;

        if (cursor->rowid.slot == INVALID_SLOT) {
            cursor->rowid.slot = 0;
        } else {
            cursor->rowid.slot++;
        }

        if (cursor->rowid.slot == page->dirs) {
            if (IS_SAME_PAGID(cursor->scan_range.r_page, AS_PAGID(page->head.id))) {
                SET_ROWID_PAGE(&cursor->rowid, INVALID_PAGID);
            } else {
                SET_ROWID_PAGE(&cursor->rowid, AS_PAGID(page->next));
            }

            cursor->rowid.slot = INVALID_SLOT;

            return GS_SUCCESS;
        }

        if ((uint16)cursor->rowid.slot > page->dirs) {
            GS_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, "table");
            return GS_ERROR;
        }

        if (heap_get_row(session, cursor, page, query_scn, is_found) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (*is_found) {
            return GS_SUCCESS;
        }

        if (SECUREC_UNLIKELY(session->wxid.value != GS_INVALID_ID64)) {
            heap_scan_backspace_cursor(cursor);
            return GS_SUCCESS;
        }
    }
}

static status_t heap_try_fetch_chain_rows(knl_session_t *session, knl_cursor_t *cursor,
    knl_scn_t query_scn, bool32 *is_found)
{
    if (cursor->row->is_link && !cursor->row->is_migr) {
        if (!cursor->snapshot.is_valid) {
            HEAP_SET_LINK_RID(cursor->row, cursor->link_rid.value);
        }

        if (heap_fetch_chain_rows(session, cursor, query_scn) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else if (!cursor->row->is_link && cursor->row->is_migr) {
        *is_found = GS_FALSE;
    }

    return GS_SUCCESS;
}

bool32 heap_cached_invalid(knl_session_t *session, knl_cursor_t *cursor)
{
    date_t timeout;

    if (cursor->rowid.slot != INVALID_SLOT) {
        if (cursor->isolevel != (uint8)ISOLATION_CURR_COMMITTED) {
            return GS_FALSE;
        }

        timeout = (date_t)
            ((uint64)session->kernel->undo_ctx.retention * MICROSECS_PER_SECOND / RETENTION_TIME_PERCENT);

        return (bool32)((KNL_NOW(session) - cursor->cc_cache_time) >= timeout);
    }

    return GS_TRUE;
}

static status_t heap_cache_scan_page(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t *query_scn)
{
    heap_page_t *page = NULL;
    errno_t ret;

    if (session->stat_sample) {
        if (buf_read_page(session, GET_ROWID_PAGE(cursor->rowid), LATCH_MODE_S,
            ENTER_PAGE_NORMAL | ENTER_PAGE_SEQUENTIAL) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        if (buf_read_prefetch_page(session, GET_ROWID_PAGE(cursor->rowid),
            LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    page = (heap_page_t *)CURR_PAGE(session);
    if (!heap_check_page(session, cursor, page, PAGE_TYPE_HEAP_DATA)) {
        buf_leave_page(session, GS_FALSE);
        HEAP_CHECKPAGE_ERROR(cursor);
        return GS_ERROR;
    }

    if (cursor->isolevel == (uint8)ISOLATION_CURR_COMMITTED) {
        cursor->query_scn = DB_CURR_SCN(session);
        *query_scn = cursor->query_scn;
        cursor->cc_cache_time = KNL_NOW(session);
    }

    ret = memcpy_sp(cursor->page_buf, DEFAULT_PAGE_SIZE(session), page, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);
    buf_leave_page(session, GS_FALSE);

    return GS_SUCCESS;
}

static inline void heap_init_query_snapshot(knl_cursor_t *cursor, knl_scn_t query_scn, query_snapshot_t *query_ss)
{
    query_ss->lens = cursor->lens;
    query_ss->offsets = cursor->offsets;
    query_ss->scn = cursor->scn;
    query_ss->query_scn = query_scn;
    query_ss->ssn = cursor->ssn;
    query_ss->row = cursor->row;
    query_ss->rowid = cursor->rowid;
    query_ss->xid = cursor->xid;
}

static status_t heap_fetch_by_page(knl_session_t *session, knl_cursor_t *cursor, bool32 *is_found)
{
    heap_page_t *page = NULL;
    knl_scn_t query_scn;

    for (;;) {
        query_scn = cursor->query_scn;

        if (cursor->action == CURSOR_ACTION_SELECT) {
            if (heap_cached_invalid(session, cursor)) {
                if (heap_cache_scan_page(session, cursor, &query_scn) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            }
            page = (heap_page_t *)cursor->page_buf;

            if (heap_scan_full_page(session, cursor, page, query_scn, is_found) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (SECUREC_UNLIKELY(session->wxid.value != GS_INVALID_ID64)) {
                GS_LOG_DEBUG_INF("fetch row begin read wait.");
                if (tx_wait(session, 0, ENQ_TX_READ_WAIT) != GS_SUCCESS) {
                    tx_record_rowid(session->wrid);
                    return GS_ERROR;
                }
                continue;
            }

            if (!*is_found) {
                return GS_SUCCESS;
            }

            if (!IS_INVALID_ROWID(cursor->link_rid)) {
                return heap_read_by_rowid(session, cursor, query_scn, cursor->isolevel, is_found);
            }
        } else {
            if (buf_read_prefetch_page(session, GET_ROWID_PAGE(cursor->rowid),
                                       LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
                return GS_ERROR;
            }
            page = (heap_page_t *)CURR_PAGE(session);
            if (!heap_check_page(session, cursor, page, PAGE_TYPE_HEAP_DATA)) {
                buf_leave_page(session, GS_FALSE);
                HEAP_CHECKPAGE_ERROR(cursor);
                return GS_ERROR;
            }

            if (cursor->isolevel == (uint8)ISOLATION_CURR_COMMITTED) {
                cursor->query_scn = DB_CURR_SCN(session);
                query_scn = cursor->query_scn;
                cursor->cc_cache_time = KNL_NOW(session);
            }

            if (heap_scan_full_page(session, cursor, page, query_scn, is_found) != GS_SUCCESS) {
                buf_leave_page(session, GS_FALSE);
                return GS_ERROR;
            }

            if (SECUREC_UNLIKELY(session->wxid.value != GS_INVALID_ID64)) {
                buf_leave_page(session, GS_FALSE);
                GS_LOG_DEBUG_INF("fetch row begin read wait.");
                if (tx_wait(session, 0, ENQ_TX_READ_WAIT) != GS_SUCCESS) {
                    tx_record_rowid(session->wrid);
                    return GS_ERROR;
                }
                continue;
            }

            if (*is_found && !IS_INVALID_ROWID(cursor->link_rid)) {
                if (heap_get_migr_row(session, cursor, is_found) != GS_SUCCESS) {
                    buf_leave_page(session, GS_FALSE);
                    return GS_ERROR;
                }
            }

            buf_leave_page(session, GS_FALSE);
        }
        break;
    }

    if (cursor->snapshot.is_valid) {
        query_snapshot_t query_ss;

        heap_init_query_snapshot(cursor, query_scn, &query_ss);
        if (heap_reorganize_with_undo_list(session, cursor, &query_ss, &cursor->snapshot, is_found) != GS_SUCCESS) {
            return GS_ERROR;
        }

        cursor->scn = query_ss.scn;
    }

    if (*is_found) {
        if (heap_try_fetch_chain_rows(session, cursor, query_scn, is_found) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

/*
 * fetch from sys_dummy table: we construct one static row and return, do not fetch from heap
 * the rowid is unique: 000000000084400000 ;
 * @param kernel session, kernel cursor
 */
status_t dual_fetch(knl_session_t *session, knl_cursor_t *cursor)
{
    if (cursor->eof) {
        return GS_SUCCESS;
    }

    if (cursor->rowid.slot != INVALID_SLOT) {
        cursor->eof = GS_TRUE;
        return GS_SUCCESS;
    }

    cursor->is_found = GS_TRUE;
    cursor->rowid.slot = 0;
    cursor->row = (row_head_t *)&g_dual_row;
    cursor->scn = 0;

    if (knl_match_cond(session, cursor, &cursor->is_found) != GS_SUCCESS) {
        return GS_ERROR;
    }

    cursor->eof = !cursor->is_found;

    return GS_SUCCESS;
}

status_t heap_fetch(knl_handle_t handle, knl_cursor_t *cursor)
{
    knl_session_t *session = (knl_session_t *)handle;
    rowid_t row_id;
    heap_t *heap = CURSOR_HEAP(cursor);
    seg_stat_t temp_stat;
    status_t status = GS_SUCCESS;
    CM_ASSERT(!DB_IS_CLUSTER(session));
    knl_panic_log(cursor->is_valid, "cursor is invalid, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);

    if (IS_DUAL_TABLE((table_t *)cursor->table)) {
        return dual_fetch(session, cursor);
    }

    SEG_STATS_INIT(session, &temp_stat);
    
    for (;;) {
        if (IS_INVALID_ROWID(cursor->rowid)) {
            cursor->is_found = GS_FALSE;
            cursor->eof = GS_TRUE;
            return GS_SUCCESS;
        }

        cursor->ssi_conflict = GS_FALSE;
        row_id = cursor->rowid;
        if (heap_fetch_by_page(session, cursor, &cursor->is_found) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        if (!IS_SAME_PAGID_BY_ROWID(row_id, cursor->rowid)) {
            if (session->canceled) {
                GS_THROW_ERROR(ERR_OPERATION_CANCELED);
                status = GS_ERROR;
                break;
            }

            if (session->killed) {
                GS_THROW_ERROR(ERR_OPERATION_KILLED);
                status = GS_ERROR;
                break;
            }

            if (cursor->cleanout) {
                heap_cleanout_page(session, cursor, GET_ROWID_PAGE(row_id), GS_FALSE);
            }
        }

        if (!cursor->is_found) {
            continue;
        }

        if (knl_match_cond(session, cursor, &cursor->is_found) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        if (!cursor->is_found) {
            continue;
        }

        if (cursor->action <= CURSOR_ACTION_SELECT) {
            status = GS_SUCCESS;
            break;
        }

        if (heap_lock_row(session, cursor, &cursor->is_found) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        if (!cursor->is_found) {
            continue;
        }

        status = GS_SUCCESS;
        break;
    }

    SEG_STATS_RECORD(session, temp_stat, &heap->stat);
    return status;
}

static status_t heap_read_by_rowid(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn,
                                   uint8 isolevel, bool32 *is_found)
{
    heap_page_t *page = NULL;

    *is_found = GS_FALSE;
    cursor->snapshot.is_valid = 0;
    SET_ROWID_PAGE(&cursor->link_rid, INVALID_PAGID);
    cursor->chain_count = 0;

    for (;;) {
        if (buf_read_page(session, GET_ROWID_PAGE(cursor->rowid), LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
            return GS_ERROR;
        }
        page = (heap_page_t *)CURR_PAGE(session);
        if (!heap_check_page(session, cursor, page, PAGE_TYPE_HEAP_DATA)) {
            buf_leave_page(session, GS_FALSE);
            HEAP_CHECKPAGE_ERROR(cursor);
            return GS_ERROR;
        }

        if ((uint16)cursor->rowid.slot >= page->dirs) {
            buf_leave_page(session, GS_FALSE);
            GS_THROW_ERROR(ERR_INVALID_ROWID);
            return GS_ERROR;
        }

        if (heap_get_row(session, cursor, page, query_scn, is_found) != GS_SUCCESS) {
            buf_leave_page(session, GS_FALSE);
            return GS_ERROR;
        }

        if (SECUREC_UNLIKELY(session->wxid.value != GS_INVALID_ID64)) {
            buf_leave_page(session, GS_FALSE);
            GS_LOG_DEBUG_INF("read row by rowid begin read wait.");
            if (tx_wait(session, 0, ENQ_TX_READ_WAIT) != GS_SUCCESS) {
                tx_record_rowid(session->wrid);
                return GS_ERROR;
            }
            continue;
        }

        if (*is_found && !IS_INVALID_ROWID(cursor->link_rid)) {
            if (heap_get_migr_row(session, cursor, is_found) != GS_SUCCESS) {
                buf_leave_page(session, GS_FALSE);
                return GS_ERROR;
            }
        }

        buf_leave_page(session, GS_FALSE);
        break;
    }

    if (cursor->snapshot.is_valid) {
        query_snapshot_t query_ss;

        heap_init_query_snapshot(cursor, query_scn, &query_ss);
        if (heap_reorganize_with_undo_list(session, cursor, &query_ss, &cursor->snapshot, is_found) != GS_SUCCESS) {
            return GS_ERROR;
        }

        cursor->scn = query_ss.scn;
    }

    if (*is_found) {
        if (heap_try_fetch_chain_rows(session, cursor, query_scn, is_found) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (!*is_found) {
        return GS_SUCCESS;
    }

    if (isolevel == (uint8)ISOLATION_CURR_COMMITTED &&
        cursor->isolevel != (uint8)ISOLATION_SERIALIZABLE &&
        cursor->snapshot.scn > cursor->query_scn) {
        if (heap_check_current_visible(session, cursor, GS_FALSE, is_found) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t heap_fetch_by_rowid(knl_handle_t handle, knl_cursor_t *cursor)
{
    knl_session_t *session = (knl_session_t *)handle;
    cursor->ssi_conflict = GS_FALSE;
    if (heap_read_by_rowid(session, cursor, cursor->query_scn, cursor->isolevel, &cursor->is_found) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!cursor->is_found) {
        return GS_SUCCESS;
    }

    if (knl_match_cond(session, cursor, &cursor->is_found) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!cursor->is_found || cursor->action <= CURSOR_ACTION_SELECT) {
        return GS_SUCCESS;
    }

    if (heap_lock_row(session, cursor, &cursor->is_found) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/*
 * heap rowid scan fetch interface
 * @Caller must put the scan rowid sets into cursor
 * @param kernel session, kernel cursor
 */
status_t heap_rowid_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    knl_session_t *se = (knl_session_t *)session;
    for (;;) {
        if (cursor->rowid_no == cursor->rowid_count) {
            cursor->eof = GS_TRUE;
            return GS_SUCCESS;
        }

        ROWID_COPY(cursor->rowid, cursor->rowid_array[cursor->rowid_no]);
        cursor->rowid_no++;

        if (!spc_validate_page_id((knl_session_t *)session, GET_ROWID_PAGE(cursor->rowid))) {
            continue;
        }

        if (IS_DUAL_TABLE((table_t *)cursor->table)) {
            cursor->rowid.slot = INVALID_SLOT;
            return dual_fetch((knl_session_t *)session, cursor);
        }

        if (cursor->isolevel == ISOLATION_CURR_COMMITTED) {
            cursor->query_scn = DB_CURR_SCN(se);
            cursor->cc_cache_time = KNL_NOW(se);
        }

        if (heap_fetch_by_rowid(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (cursor->is_found) {
            return GS_SUCCESS;
        }
    }
}

void heap_update_serial(knl_session_t *session, heap_t *heap, uint64 value)
{
    log_atomic_op_begin(session);
    buf_enter_page(session, heap->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    heap->segment->serial = value;
    if (SPACE_IS_LOGGING(SPACE_GET(session, heap->segment->space_id))) {
        log_put(session, RD_HEAP_CHANGE_SEG, (void *)heap->segment, sizeof(heap_segment_t),
            LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, GS_TRUE);
    log_atomic_op_end(session);
}

void heap_increase_serial(knl_session_t *session, heap_t *heap)
{
    log_atomic_op_begin(session);
    buf_enter_page(session, heap->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    heap->segment->serial += (heap->segment->serial == 0) ? 1 + GS_SERIAL_CACHE_COUNT : GS_SERIAL_CACHE_COUNT;
    if (SPACE_IS_LOGGING(SPACE_GET(session, heap->segment->space_id))) {
        log_put(session, RD_HEAP_CHANGE_SEG, (void *)heap->segment, sizeof(heap_segment_t), LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, GS_TRUE);
    log_atomic_op_end(session);
}

static bool32 heap_row_shrinkable(knl_session_t *session, knl_cursor_t *cursor, shrink_pages_t *shrink_pages)
{
    heap_t *heap = CURSOR_HEAP(cursor);
    row_head_t *row = cursor->row;
    map_path_t find_path;
    page_id_t page_id;
    bool32 degrade_mid = GS_FALSE;
    uint32 list_id, cost_size, row_size;
    uint8 cipher_reserve_size = heap->cipher_reserve_size;

    if (shrink_pages->row_chain_shrink) {
        return GS_TRUE;
    }

    if (row->is_migr) {
        row_size = row->size - sizeof(rowid_t);
    } else {
        row_size = row->size;
    }

    heap_segment_t *segment = HEAP_SEGMENT(session, heap->entry, heap->segment);

    if (segment->cr_mode == CR_PAGE) {
        // skip check link row, check it after insert
        if (row_size > PCRH_MAX_ROW_SIZE(session) - cipher_reserve_size) {
            return GS_TRUE;
        }
        cost_size = pcrh_calc_insert_cost(session, segment, row_size);
    } else {
        // skip check link row, check it after insert
        if (row_size > HEAP_MAX_ROW_SIZE(session) - cipher_reserve_size) {
            return GS_TRUE;
        }
        cost_size = heap_calc_insert_cost(session, segment, row_size, GS_TRUE);
    }

    list_id = heap_get_target_list(session, segment, cost_size);
    if (heap_seq_find_map(session, heap, &find_path, list_id, &page_id, &degrade_mid) != GS_SUCCESS) {
        cm_reset_error();
        GS_LOG_RUN_INF("shrink row find free page failed.uid %u oid %u", segment->uid, segment->oid);
        return GS_FALSE;
    }

    if (IS_INVALID_ROWID(page_id)) {
        GS_LOG_RUN_INF("shrink row find invalid free page.uid %u oid %u", segment->uid, segment->oid);
        return GS_FALSE;
    }

    if (heap_compare_map_path(&find_path, &shrink_pages->path) >= 0) {
        GS_LOG_RUN_INF("shrink row find no free page.uid %u oid %u", segment->uid, segment->oid);
        return GS_FALSE;
    }

    return GS_TRUE;
}

static void heap_get_max_row_pagid(knl_session_t *session, knl_cursor_t *cursor, map_path_t *path)
{
    map_path_t cmp_path;
    page_id_t page_id, cmp_id;
    row_chains_info_t *chains_info = NULL;
    row_chain_t *chain = NULL;
    uint8 i;

    page_id = GET_ROWID_PAGE(cursor->rowid);

    heap_get_map_path(session, CURSOR_HEAP(cursor), page_id, path);

    if (cursor->chain_count > 1) {
        chains_info = (row_chains_info_t *)cursor->chain_info;

        for (i = 0; i < cursor->chain_count; i++) {
            chain = &chains_info->chains[i];

            cmp_id = GET_ROWID_PAGE(chain->chain_rid);
            heap_get_map_path(session, CURSOR_HEAP(cursor), cmp_id, &cmp_path);

            if (heap_compare_map_path(path, &cmp_path) < 0) {
                *path = cmp_path;
                page_id = cmp_id;
            }
        }
    } else if (!IS_INVALID_ROWID(cursor->link_rid)) {
        cmp_id = GET_ROWID_PAGE(cursor->link_rid);
        heap_get_map_path(session, CURSOR_HEAP(cursor), cmp_id, &cmp_path);

        if (heap_compare_map_path(path, &cmp_path) < 0) {
            *path = cmp_path;
            page_id = cmp_id;
        }
    }
}

/*
 * heap shrink page
 * shrink one heap page by delete all rows on the page (this would be very slow),
 * insert all valid rows to the frond of heap page lists.
 * @param kernel session, kernel dictionary, current page map path, current shrink page
 */
static status_t heap_shrink_page(knl_session_t *session, knl_dictionary_t *dc, knl_part_locate_t part_loc,
                                 shrink_pages_t *shrink_pages, shrink_page_t *shrink_page)
{
    knl_cursor_t *dcursor = NULL;
    knl_cursor_t *icursor = NULL;
    map_path_t dpath, ipath;
    status_t status;

    shrink_page->is_shrinkable = GS_TRUE;
    CM_SAVE_STACK(session->stack);

    dcursor = knl_push_cursor(session);
    dcursor->action = CURSOR_ACTION_DELETE;
    dcursor->scan_mode = SCAN_MODE_TABLE_FULL;
    dcursor->part_loc = part_loc;

    if (knl_open_cursor(session, dcursor, dc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    dcursor->isolevel = (uint8)ISOLATION_CURR_COMMITTED;
    knl_set_table_scan_range(session, dcursor, shrink_page->shrink_id, shrink_page->shrink_id);

    icursor = knl_push_cursor(session);
    icursor->action = CURSOR_ACTION_INSERT;

    if (knl_open_cursor(session, icursor, dc) != GS_SUCCESS) {
        knl_close_cursor(session, dcursor);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    icursor->row = (row_head_t *)cm_push(session->stack, GS_MAX_ROW_SIZE);

    if (IS_PART_TABLE(icursor->table)) {
        knl_set_table_part(icursor, part_loc);
    }

    for (;;) {
        if (knl_fetch(session, dcursor) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        if (dcursor->eof) {
            knl_rollback(session, NULL);
            status = GS_SUCCESS;
            break;
        }

        if (shrink_pages->row_chain_shrink) {
            if (dcursor->chain_count == 0) {
                continue;
            }
            shrink_pages->chain_rows++;
        }

        if (!heap_row_shrinkable(session, dcursor, shrink_pages)) {
            knl_rollback(session, NULL);
            shrink_page->is_shrinkable = GS_FALSE;
            status = GS_SUCCESS;
            break;
        }

        heap_get_max_row_pagid(session, dcursor, &dpath);

        if (knl_copy_row(session, dcursor, icursor) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        if (knl_internal_delete(session, dcursor) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        if (knl_internal_insert(session, icursor) != GS_SUCCESS) {
            int32 code = cm_get_error_code();
            if (code == ERR_SHRINK_EXTEND) {
                cm_reset_error();
                shrink_page->is_shrinkable = GS_FALSE;
                status = GS_SUCCESS;
                knl_rollback(session, NULL);
                GS_LOG_RUN_INF("shrink page find no free page. uid %u oid %u part_no %d subpart_no %d",
                    dc->uid, dc->oid, part_loc.part_no, part_loc.subpart_no);
                break;
            }
            status = GS_ERROR;
            break;
        }

        heap_get_max_row_pagid(session, icursor, &ipath);

        if (heap_compare_map_path(&dpath, &ipath) <= 0) {
            knl_rollback(session, NULL);
            status = GS_SUCCESS;
            if (!shrink_pages->row_chain_shrink) {
                shrink_page->is_shrinkable = GS_FALSE;
                GS_LOG_RUN_INF("shrink page find no free page. uid %u oid %u part_no %d subpart_no %d",
                    dc->uid, dc->oid, part_loc.part_no, part_loc.subpart_no);
                break;
            }
        } else {
            session->commit_nowait = GS_TRUE;
            knl_commit(session);
            session->commit_nowait = GS_FALSE;
            shrink_page->shrinked_rows++;
        }
    }

    knl_close_cursor(session, dcursor);
    knl_close_cursor(session, icursor);
    CM_RESTORE_STACK(session->stack);
    knl_rollback(session, NULL);
    return status;
}

void heap_set_initrans(knl_session_t *session, heap_t *heap, uint32 initrans)
{
    heap_segment_t *segment = (heap_segment_t *)heap->segment;

    if (segment == NULL) {
        return;
    }

    log_atomic_op_begin(session);

    buf_enter_page(session, heap->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    segment->initrans = initrans;
    if (SPC_IS_LOGGING_BY_PAGEID(session, heap->entry)) {
        log_put(session, RD_HEAP_CHANGE_SEG, segment, HEAP_SEG_SIZE, LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);

    log_atomic_op_end(session);
}

void heap_set_compact_hwm(knl_session_t *session, heap_t *heap, page_id_t cmp_hwm)
{
    heap_segment_t *segment = NULL;

    log_atomic_op_begin(session);

    buf_enter_page(session, heap->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    segment = HEAP_SEG_HEAD(session);
    segment->cmp_hwm = cmp_hwm;
    segment->shrinkable_scn = DB_CURR_SCN(session);
    if (SPC_IS_LOGGING_BY_PAGEID(session, heap->entry)) {
        log_put(session, RD_HEAP_CHANGE_SEG, segment, HEAP_SEG_SIZE, LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, GS_TRUE);

    log_atomic_op_end(session);
}

static inline bool32 heap_shrink_compactable(knl_session_t *session, heap_t *heap, bool32 shrink_hwm)
{
    if (heap->segment == NULL) {
        return GS_FALSE;
    }

    if (shrink_hwm && !IS_INVALID_PAGID(HEAP_SEGMENT(session, heap->entry, heap->segment)->cmp_hwm)) {
        return GS_FALSE;
    }

    return GS_TRUE;
}

static bool32 heap_compact_check_stop(knl_session_t *session, heap_cmp_def_t def,
    shrink_pages_t *shrink_pages, status_t *status)
{
    // convert real to percentage then compare
    if (((double)shrink_pages->shrinked_pages / shrink_pages->total_pages) * 100 >= def.percent) {
        return GS_TRUE;
    }

    if (session->canceled) {
        GS_THROW_ERROR(ERR_OPERATION_CANCELED);
        *status = GS_ERROR;
        return GS_TRUE;
    }

    if (session->killed) {
        GS_THROW_ERROR(ERR_OPERATION_KILLED);
        *status = GS_ERROR;
        return GS_TRUE;
    }

    return GS_FALSE;
}

bool32 is_shrink_row_chain(knl_session_t *session, knl_dictionary_t *dc, knl_part_locate_t part_loc,
    heap_cmp_def_t def, shrink_pages_t *shrink_pages)
{
    knl_attr_t *attr = &session->kernel->attr;
    table_t *table = DC_TABLE(dc);
    bool32 async_shrink = (bool32)(def.timeout != 0);

    if (attr->shrink_wait_recycled_pages == 0) {
        GS_LOG_DEBUG_INF("shrink row chain is closed. uid %u oid %u name %s part_no %d subpart_no %d.",
            dc->uid, dc->oid, table->desc.name, part_loc.part_no, part_loc.subpart_no);
        return GS_FALSE;
    }

    if (shrink_pages->shrinked_pages == 0) {
        GS_LOG_DEBUG_INF("no pages be shrinked. uid %u oid %u name %s part_no %d subpart_no %d",
            dc->uid, dc->oid, table->desc.name, part_loc.part_no, part_loc.subpart_no);
        return GS_FALSE;
    }

    if (async_shrink && (KNL_NOW(session) - def.end_time) / MICROSECS_PER_SECOND > 0) {
        GS_LOG_DEBUG_INF("async shrink timeout. uid %u oid %u name %s part_no %d subpart_no %d.",
            dc->uid, dc->oid, table->desc.name, part_loc.part_no, part_loc.subpart_no);
        return GS_FALSE;
    }

    if (((double)shrink_pages->shrinked_pages / shrink_pages->total_pages) * 100 >= def.percent) {
        GS_LOG_DEBUG_INF("shrink percent has finished. uid %u oid %u name %s part_no %d subpart_no %d",
            dc->uid, dc->oid, table->desc.name, part_loc.part_no, part_loc.subpart_no);
        return GS_FALSE;
    }

    if (shrink_pages->wait_recycled_pages < attr->shrink_wait_recycled_pages) {
        GS_LOG_DEBUG_INF("shrink row chain is not meet threshold condition. uid %u oid %u name %s "
            "part_no %d subpart_no %d wait_recycled_pages %d.", dc->uid, dc->oid, table->desc.name,
            part_loc.part_no, part_loc.subpart_no, shrink_pages->wait_recycled_pages);
        return GS_FALSE;
    }

    GS_LOG_RUN_INF("shrink row chain begin. uid %u oid %u name %s part_no %d subpart_no %d.",
        dc->uid, dc->oid, table->desc.name, part_loc.part_no, part_loc.subpart_no);

    return GS_TRUE;
}

void heap_shrink_pages_update(shrink_page_t shrink_page, shrink_pages_t *shrink_pages)
{
    // keep the last shrink page if all pages is shrinkable
    if (IS_INVALID_PAGID(shrink_pages->cmp_hwm)) {
        shrink_pages->cmp_hwm = shrink_page.shrink_id;
    }

    if (shrink_page.shrinked_rows > 0) {
        shrink_pages->shrinked_pages++;
    }

    if (shrink_pages->row_chain_shrink) {
        GS_LOG_DEBUG_INF("shrink row chain. chain_rows %d.", shrink_pages->chain_rows);
    }
}

static inline void heap_shrink_pages_init(knl_session_t *session, shrink_page_t *shrink_page,
                                          shrink_pages_t *shrink_pages)
{
    shrink_page->shrinked_rows = 0;
    shrink_page->is_shrinkable = GS_FALSE;
    shrink_page->shrink_id = INVALID_PAGID;
    session->has_migr = GS_FALSE;
}

status_t heap_shrink_pages(knl_session_t *session, knl_dictionary_t *dc, knl_part_locate_t part_loc,
    heap_cmp_def_t def, shrink_pages_t *shrink_pages)
{
    status_t status = GS_SUCCESS;
    table_t *table = DC_TABLE(dc);
    shrink_page_t shrink_page;
    page_id_t page_id = shrink_pages->cmp_hwm;
    page_id_t new_hwm = INVALID_PAGID;
    bool32 async_shrink = (bool32)(def.timeout != 0);
    bool32 is_first = shrink_pages->row_chain_shrink;

    heap_shrink_pages_init(session, &shrink_page, shrink_pages);

    for (;;) {
        if (!is_first) {
            heap_traversal_map_for_shrink(session, &shrink_pages->path, &page_id);
        }

        if (IS_INVALID_PAGID(page_id)) {
            break;
        }

        if (async_shrink && (KNL_NOW(session) - def.end_time) / MICROSECS_PER_SECOND > 0) {
            GS_LOG_RUN_INF("async shrink timeout. uid %u oid %u name %s part_no %d subpart_no %d.",
                dc->uid, dc->oid, table->desc.name, part_loc.part_no, part_loc.subpart_no);
            break;
        }

        shrink_page.shrink_id = page_id;
        if (heap_shrink_page(session, dc, part_loc, shrink_pages, &shrink_page) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        if (!shrink_page.is_shrinkable && IS_INVALID_PAGID(shrink_pages->cmp_hwm)) {
            shrink_pages->cmp_hwm = shrink_page.shrink_id;
            break;
        }

        if (!shrink_page.is_shrinkable && shrink_pages->row_chain_shrink) {
            break;
        }

        if (!shrink_pages->row_chain_shrink) {
            if (IS_INVALID_PAGID(new_hwm) && session->has_migr) {
                new_hwm = page_id;
            }
            shrink_pages->wait_recycled_pages += (!IS_INVALID_PAGID(new_hwm)) ? 1 : 0;
        } else {
            is_first = GS_FALSE;
        }

        shrink_page.shrinked_rows = 0;
        shrink_pages->shrinked_pages++;

        if (heap_compact_check_stop(session, def, shrink_pages, &status)) {
            break;
        }
    }

    heap_shrink_pages_update(shrink_page, shrink_pages);
    
    return status;
}

static void heap_shrink_compact_init(knl_session_t *session, heap_t *heap, shrink_pages_t *shrink_pages)
{
    heap_segment_t *segment = HEAP_SEGMENT(session, heap->entry, heap->segment);
    space_t *space = SPACE_GET(session, segment->space_id);
    uint32 total_pages = heap_get_segment_page_count(space, segment);

    heap_shrink_initialize_map_path(session, heap, &shrink_pages->path);

    shrink_pages->total_pages = total_pages;
    shrink_pages->shrinked_pages = 0;
    shrink_pages->chain_rows = 0;
    shrink_pages->wait_recycled_pages = 0;
    shrink_pages->row_chain_shrink = GS_FALSE;
    shrink_pages->cmp_hwm = INVALID_PAGID;
}

static inline heap_t *get_heap_from_table(table_t *table, knl_part_locate_t part_loc)
{
    if (IS_PART_TABLE(table)) {
        table_part_t *table_part = TABLE_GET_PART(table, part_loc.part_no);
        if (IS_PARENT_TABPART(&table_part->desc)) {
            table_part = PART_GET_SUBENTITY(table->part_table, table_part->subparts[part_loc.subpart_no]);
        }

        return &table_part->heap;
    } else {
        return &table->heap;
    }
}

status_t heap_shrink_compact(knl_session_t *session, knl_dictionary_t *dc, knl_part_locate_t part_loc,
    bool32 shrink_hwm, heap_cmp_def_t def)
{
    status_t status;
    table_t *table = DC_TABLE(dc);
    heap_t *heap = get_heap_from_table(table, part_loc);
    shrink_pages_t shrink_pages;
    bool32 async_shrink = (bool32)(def.timeout != 0);

    if (!heap_shrink_compactable(session, heap, shrink_hwm)) {
        heap->ashrink_stat = ASHRINK_END;
        GS_LOG_RUN_INF("shrink uncompactable.uid %u oid %u name %s part_no %u subpart_no %u async_shrink %u.",
            dc->uid, dc->oid, table->desc.name, part_loc.part_no, part_loc.subpart_no, (uint32)async_shrink);
        return GS_SUCCESS;
    }

    dls_spin_lock(session, &heap->lock, NULL);
    if (heap->compacting) {
        dls_spin_unlock(session, &heap->lock);
        GS_THROW_ERROR(ERR_SHRINK_IN_PROGRESS_FMT, DC_ENTRY_USER_NAME(dc), DC_ENTRY_NAME(dc));
        return GS_ERROR;
    }
    heap->compacting = GS_TRUE;
    heap->ashrink_stat = async_shrink ? ASHRINK_COMPACT : ASHRINK_END;
    dls_spin_unlock(session, &heap->lock);
    
    session->compacting = GS_TRUE;

    heap_shrink_compact_init(session, heap, &shrink_pages);

    status = heap_shrink_pages(session, dc, part_loc, def, &shrink_pages);
    if (status == GS_SUCCESS && is_shrink_row_chain(session, dc, part_loc, def, &shrink_pages)) {
        shrink_pages.row_chain_shrink = GS_TRUE;
        status = heap_shrink_pages(session, dc, part_loc, def, &shrink_pages);
    }

    heap_set_compact_hwm(session, heap, shrink_pages.cmp_hwm);
    if (shrink_pages.shrinked_pages == 0 || IS_INVALID_PAGID(shrink_pages.cmp_hwm)) {
        heap->ashrink_stat = ASHRINK_END;
    }
    heap->compacting = GS_FALSE;
    session->compacting = GS_FALSE;
    session->has_migr = GS_FALSE;

    return status;
}

status_t heap_shrink_compart_compact(knl_session_t *session, knl_dictionary_t *dc, knl_part_locate_t part_loc,
    bool32 shrink_hwm, heap_cmp_def_t def)
{
    dc_entity_t *entity = (dc_entity_t *)dc->handle;
    table_t *table = &entity->table;
    table_part_t *table_part = TABLE_GET_PART(table, part_loc.part_no);

    if (!IS_PARENT_TABPART(&table_part->desc)) {
        part_loc.subpart_no = GS_INVALID_ID32;
        if (heap_shrink_compact(session, dc, part_loc, shrink_hwm, def) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        for (uint32 i = 0; i < table_part->desc.subpart_cnt; i++) {
            part_loc.subpart_no = i;
            if (heap_shrink_compact(session, dc, part_loc, shrink_hwm, def) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

void heap_ashrink_update_hwm(knl_session_t *session, knl_dictionary_t *dc, knl_part_locate_t part_loc, page_id_t *hwm)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;
    heap_t *heap = get_heap_from_table(table, part_loc);

    *hwm = INVALID_PAGID;

    if (heap->segment == NULL || heap->ashrink_stat == ASHRINK_END) {
        return;
    }

    heap_segment_t *segment = HEAP_SEGMENT(session, heap->entry, heap->segment);
    if (IS_INVALID_PAGID(segment->cmp_hwm)) {
        return;
    }

    heap_fetch_shrink_hwm(session, segment->cmp_hwm, hwm);
    heap_set_compact_hwm(session, heap, *hwm);
    heap->ashrink_stat = ASHRINK_WAIT_SHRINK;
}

void heap_ashrink_update_hwms(knl_session_t *session, knl_dictionary_t *dc,
    knl_part_locate_t part_loc, bool32 *has_valid_hwm)
{
    table_t *table = DC_TABLE(dc);
    page_id_t new_hwm;

    if (!IS_PART_TABLE(table)) {
        heap_ashrink_update_hwm(session, dc, part_loc, &new_hwm);
        *has_valid_hwm = !IS_INVALID_PAGID(new_hwm);
        return;
    }

    table_part_t *table_part = TABLE_GET_PART(table, part_loc.part_no);
    if (!IS_PARENT_TABPART(&table_part->desc)) {
        heap_ashrink_update_hwm(session, dc, part_loc, &new_hwm);
        *has_valid_hwm = !IS_INVALID_PAGID(new_hwm);
        return;
    }

    for (uint32 i = 0; i < table_part->desc.subpart_cnt; i++) {
        part_loc.subpart_no = i;
        heap_ashrink_update_hwm(session, dc, part_loc, &new_hwm);
        if (!(*has_valid_hwm)) {
            *has_valid_hwm = !IS_INVALID_PAGID(new_hwm);
        }
    }
}

static bool32 heap_check_space_shrinkable(knl_session_t *session, knl_dictionary_t *dc,
    knl_part_locate_t part_loc, heap_t *heap, bool32 async_shrink)
{
    if (heap->segment == NULL) {
        return GS_FALSE;
    }

    heap_segment_t *segment = HEAP_SEGMENT(session, heap->entry, heap->segment);

    if (IS_INVALID_PAGID(segment->cmp_hwm)) {
        return GS_FALSE;
    }

    if (!async_shrink) {
        return GS_TRUE;
    }

    knl_scn_t shrinkable_scn = segment->shrinkable_scn;
    knl_scn_t min_scn = KNL_GET_SCN(&session->kernel->min_scn);

    if (heap->ashrink_stat == ASHRINK_END) {
        return GS_FALSE;
    }

    if (heap->ashrink_stat != ASHRINK_WAIT_SHRINK || shrinkable_scn == GS_INVALID_ID64 || min_scn < shrinkable_scn) {
        GS_LOG_RUN_WAR("heap async shrink invalid scn or status.min_scn %llu shrinkable scn %llu "
            "uid %u oid %u part_no %u subpart_no %u stat %u", min_scn, shrinkable_scn, dc->uid,
            dc->oid, part_loc.part_no, part_loc.subpart_no, (uint32)heap->ashrink_stat);
        return GS_FALSE;
    }

    return GS_TRUE;
}

static status_t heap_shrink_space(knl_session_t *session, knl_dictionary_t *dc,
    knl_part_locate_t part_loc, bool32 async_shrink)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;
    heap_t *heap = get_heap_from_table(table, part_loc);

    if (!heap_check_space_shrinkable(session, dc, part_loc, heap, async_shrink)) {
        heap->ashrink_stat = ASHRINK_END;
        return GS_SUCCESS;
    }

    heap_segment_t *segment = HEAP_SEGMENT(session, heap->entry, heap->segment);
    heap->ashrink_stat = ASHRINK_END;

    heap_remove_cached_pages(session, segment);
    heap_shrink_hwm(session, heap, async_shrink);

    knl_set_session_scn(session, GS_INVALID_ID64);

    if (db_update_table_chgscn(session, &table->desc) != GS_SUCCESS) {
        knl_rollback(session, NULL);
        return GS_ERROR;
    }

    knl_commit(session);

    return GS_SUCCESS;
}

static status_t heap_shrink_compart_space(knl_session_t *session, knl_dictionary_t *dc,
    knl_part_locate_t part_loc, bool32 async_shrink)
{
    dc_entity_t *entity = (dc_entity_t *)dc->handle;
    table_t *table = &entity->table;
    table_part_t *table_part = TABLE_GET_PART(table, part_loc.part_no);

    if (!IS_PARENT_TABPART(&table_part->desc)) {
        part_loc.subpart_no = GS_INVALID_ID32;
        if (heap_shrink_space(session, dc, part_loc, async_shrink) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        for (uint32 i = 0; i < table_part->desc.subpart_cnt; i++) {
            part_loc.subpart_no = i;
            if (heap_shrink_space(session, dc, part_loc, async_shrink) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

status_t heap_shrink_spaces(knl_session_t *session, knl_dictionary_t *dc, bool32 async_shrink)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;
    table_part_t *table_part = NULL;
    knl_part_locate_t part_loc;

    if (!IS_PART_TABLE(table)) {
        part_loc.part_no = 0;
        part_loc.subpart_no = GS_INVALID_ID32;
        if (heap_shrink_space(session, dc, part_loc, async_shrink) != GS_SUCCESS) {
            return GS_ERROR;
        }
        return GS_SUCCESS;
    }

    for (uint32 i = 0; i < table->part_table->desc.partcnt; i++) {
        table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        part_loc.part_no = i;
        if (heap_shrink_compart_space(session, dc, part_loc, async_shrink) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}


#ifdef LOG_DIAG
void heap_validate_page(knl_session_t *session, page_head_t *page)
{
    heap_page_t *copy_page;
    itl_t *itl = NULL;
    row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    row_head_t *pos = NULL;
    space_t *space = SPACE_GET(session, DATAFILE_GET(session, AS_PAGID_PTR(page->id)->file)->space_id);
    uint16 i;
    uint8 j;
    uint32 total_size;
    errno_t ret;
    uint8 itl_id = GS_INVALID_ID8;

    copy_page = (heap_page_t *)cm_push(session->stack, DEFAULT_PAGE_SIZE(session));
    ret = memcpy_sp(copy_page, DEFAULT_PAGE_SIZE(session), page, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);

    // check page itl
    for (j = 0; j < copy_page->itls; j++) {
        itl = heap_get_itl(copy_page, j);
        if (itl->is_active) {
            knl_panic_log(itl->scn == 0, "itl's scn is abnormal, panic info: page %u-%u type %u itl scn %llu",
                AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page, copy_page->head.type, itl->scn);
            knl_panic_log(itl->xid.value != GS_INVALID_ID64,
                          "current itl's xid is invalid, panic info: page %u-%u type %u",
                          AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page, copy_page->head.type);
        }
    }

    // check dir and itl
    for (i = 0; i < copy_page->dirs; i++) {
        dir = heap_get_dir(copy_page, i);
        if (dir->is_free) {
            continue;
        }
        knl_panic_log(dir->offset < copy_page->free_begin,
            "dir's offset is more than the free_begin, panic info: page %u-%u type %u free_begin %u dir offset %u",
            AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page, copy_page->head.type,
            copy_page->free_begin, dir->offset);
        knl_panic_log(dir->offset >= sizeof(heap_page_t) + space->ctrl->cipher_reserve_size,
            "dir's offset is abnormal, panic info: page %u-%u type %u dir offset %u cipher_reserve_size %u",
            AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page, copy_page->head.type,
            dir->offset, space->ctrl->cipher_reserve_size);

        row = HEAP_GET_ROW(copy_page, dir);
        itl_id = ROW_ITL_ID(row);
        knl_panic_log(itl_id == GS_INVALID_ID8 || itl_id < copy_page->itls, "itl_id is abnormal, it is valid "
            "and more than the counts of copy_page's itl, panic info: page %u-%u type %u itl_id %u",
            AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page, copy_page->head.type, itl_id);
    }

    // check row size
    total_size = sizeof(heap_page_t) + space->ctrl->cipher_reserve_size;
    while (total_size < copy_page->free_begin) {
        pos = (row_head_t *)((char *)copy_page + total_size);
        knl_panic_log(pos->size >= HEAP_MIN_ROW_SIZE,
            "the size pointed by pos is smaller than min_row_size, panic info: page %u-%u type %u pos size %u",
            AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page, copy_page->head.type, pos->size);
        if (pos->is_migr) {
            knl_panic_log(pos->size <= HEAP_MAX_MIGR_ROW_SIZE(session) - space->ctrl->cipher_reserve_size,
                "the size pointed by pos is abnormal when row is migr, panic info: page %u-%u type %u pos size %u",
                AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page, copy_page->head.type, pos->size);
        } else {
            knl_panic_log(pos->size <= HEAP_MAX_ROW_SIZE(session) - space->ctrl->cipher_reserve_size,
                "the size pointed by pos is abnormal when row is not migr, panic info: page %u-%u type %u pos size %u",
                AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page, copy_page->head.type, pos->size);
        }
        total_size += pos->size;

        knl_panic_log(total_size <= copy_page->free_begin, "the total_size is more than page's free_begin, "
                      "panic info: page %u-%u type %u free_begin %u total_size %u", AS_PAGID(copy_page->head.id).file,
                      AS_PAGID(copy_page->head.id).page, copy_page->head.type, copy_page->free_begin, total_size);
    };

    // check page size
    heap_compact_page(session, copy_page);
    knl_panic_log(copy_page->free_begin + copy_page->free_size == copy_page->free_end, "page's free size is abnormal, "
                  "panic info: page %u-%u type %u free_begin %u free_size %u free_end %u",
                  AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page, copy_page->head.type,
                  copy_page->free_begin, copy_page->free_size, copy_page->free_end);

    cm_pop(session->stack);
}
#endif

static status_t heap_check_page_belong_subpart(knl_session_t *session, heap_page_t *page, uint32 uid,
    uint32 table_id, bool32 *belong)
{
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SUB_TABLE_PARTS_ID, IX_SYS_TABLESUBPART001_ID);

    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &uid, sizeof(uint32), IX_COL_SYS_TABLESUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &table_id, sizeof(uint32), IX_COL_SYS_TABLESUBPART001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_TABLESUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_TABLESUBPART001_SUB_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                     &uid, sizeof(uint32), IX_COL_SYS_TABLESUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                     &table_id, sizeof(uint32), IX_COL_SYS_TABLESUBPART001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_TABLESUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_TABLESUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    page_id_t entry;
    while (!cursor->eof) {
        entry = *(page_id_t *)CURSOR_COLUMN_DATA(cursor, SYS_TABLESUBPART_COL_ENTRY);
        if (!IS_INVALID_PAGID(entry)) {
            buf_enter_page(session, entry, LATCH_MODE_S, ENTER_PAGE_NORMAL);
            heap_segment_t *segment = HEAP_SEG_HEAD(session);
            if (segment->seg_scn == page->seg_scn) {
                buf_leave_page(session, GS_FALSE);
                *belong = GS_TRUE;
                break;
            }

            buf_leave_page(session, GS_FALSE);
        }

        if (knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t heap_check_page_belong_part(knl_session_t *session, heap_page_t *page, uint32 uid,
    uint32 table_id, bool32 *belong)
{
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TABLEPART_ID, IX_SYS_TABLEPART001_ID);

    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &uid, sizeof(uint32), IX_COL_SYS_TABLEPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &table_id, sizeof(uint32), IX_COL_SYS_TABLEPART001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_TABLEPART001_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                     &uid, sizeof(uint32), IX_COL_SYS_TABLEPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                     &table_id, sizeof(uint32), IX_COL_SYS_TABLEPART001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_TABLEPART001_PART_ID);

    if (knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    page_id_t entry;
    while (!cursor->eof) {
        entry = *(page_id_t *)CURSOR_COLUMN_DATA(cursor, SYS_TABLEPART_COL_ENTRY);
        if (!IS_INVALID_PAGID(entry)) {
            buf_enter_page(session, entry, LATCH_MODE_S, ENTER_PAGE_NORMAL);
            heap_segment_t *segment = HEAP_SEG_HEAD(session);
            if (segment->seg_scn == page->seg_scn) {
                buf_leave_page(session, GS_FALSE);
                *belong = GS_TRUE;
                CM_RESTORE_STACK(session->stack);
                return GS_SUCCESS;
            }

            buf_leave_page(session, GS_FALSE);
        }

        if (knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t heap_check_page_belong_table(knl_session_t *session, heap_page_t *page, uint32 uid,
    uint32 table_id, bool32 *belong)
{
    *belong = GS_FALSE;
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TABLE_ID, IX_SYS_TABLE_002_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid,
                     sizeof(uint32), IX_COL_SYS_TABLE_002_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table_id,
                     sizeof(uint32), IX_COL_SYS_TABLE_002_ID);

    if (knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (cursor->eof) {
        GS_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "table", "");
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    page_id_t entry = *(page_id_t *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_ENTRY);
    CM_RESTORE_STACK(session->stack);
    if (!IS_INVALID_PAGID(entry)) {
        buf_enter_page(session, entry, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        heap_segment_t *segment = HEAP_SEG_HEAD(session);
        if (segment->seg_scn == page->seg_scn) {
            *belong = GS_TRUE;
        }

        buf_leave_page(session, GS_FALSE);

        return GS_SUCCESS;
    }

    if (heap_check_page_belong_part(session, page, uid, table_id, belong) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (*belong) {
        return GS_SUCCESS;
    }

    if (heap_check_page_belong_subpart(session, page, uid, table_id, belong) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t heap_page_corruption_scan(knl_session_t *session, heap_segment_t *segment, knl_corrupt_info_t *corrupt_info)
{
    page_id_t last_pageid = segment->free_ufp;
    page_id_t curr_pageid = segment->extents.first;
    uint32 ext_count = segment->extents.count;

    if (SECUREC_UNLIKELY(IS_INVALID_PAGID(curr_pageid)) || IS_SAME_PAGID(curr_pageid, last_pageid)) {
        return GS_SUCCESS;
    }
    if (buf_read_page(session, curr_pageid, LATCH_MODE_S, ENTER_PAGE_SEQUENTIAL) != GS_SUCCESS) {
        if (GS_ERRNO == ERR_PAGE_CORRUPTED) {
            db_save_corrupt_info(session, curr_pageid, corrupt_info);
        }
        return GS_ERROR;
    }

    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    uint32 ext_size = spc_ext_size_by_id(page->head.ext_size);
    buf_leave_page(session, GS_FALSE);

    for (uint32 i = 0; i < ext_count; i++) {
        for (uint32 j = 0; j < ext_size; j++) {
            if (knl_check_session_status(session) !=  GS_SUCCESS) {
                return GS_ERROR;
            }

            if (SECUREC_UNLIKELY(IS_INVALID_PAGID(curr_pageid)) || IS_SAME_PAGID(curr_pageid, last_pageid)) {
                break;
            }
            if (buf_read_page(session, curr_pageid, LATCH_MODE_S, ENTER_PAGE_SEQUENTIAL) != GS_SUCCESS) {
                if (GS_ERRNO == ERR_PAGE_CORRUPTED) {
                    db_save_corrupt_info(session, curr_pageid, corrupt_info);
                }
                return GS_ERROR;
            }
            curr_pageid.page++;
            if (j == ext_size - 1) {
                page = (heap_page_t *)CURR_PAGE(session);
                ext_size = spc_ext_size_by_id(page->head.ext_size);
                curr_pageid = AS_PAGID(page->head.next_ext);
            }
            buf_leave_page(session, GS_FALSE);
        }
    }
    return GS_SUCCESS;
}

status_t heap_table_corruption_verify(knl_session_t *session, knl_dictionary_t *dc, knl_corrupt_info_t *corrupt_info)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = (table_t *)&entity->table;
    heap_segment_t *segment = (heap_segment_t *)table->heap.segment;
    if (segment != NULL) {
        if (heap_page_corruption_scan(session, segment, corrupt_info) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (!entity->contain_lob) {
        return GS_SUCCESS;
    }

    for (uint32 i = 0; i < table->desc.column_count; i++) {
        knl_column_t *column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }
        lob_t *lob = (lob_t *)column->lob;
        lob_segment_t *lob_segment = (lob_segment_t *)lob->lob_entity.segment;
        if (lob_segment != NULL) {
            if (lob_corruption_scan(session, lob_segment, corrupt_info) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t heap_check_restart(knl_session_t *session, knl_cursor_t *cursor)
{
    bool32 is_found = GS_FALSE;
    heap_t *heap = CURSOR_HEAP(cursor);
    heap_segment_t *segment = HEAP_SEGMENT(session, heap->entry, heap->segment);

    cursor->snapshot.is_valid = 0;
    SET_ROWID_PAGE(&cursor->link_rid, INVALID_PAGID);
    cursor->chain_count = 0;

    if (heap->ashrink_stat == ASHRINK_WAIT_SHRINK && cursor->query_scn >= segment->shrinkable_scn) {
        return GS_SUCCESS;
    }

    if (cursor->for_update_fetch) {
        GS_LOG_DEBUG_INF("select for update checked when shrink table");
        return GS_SUCCESS;
    }

    if (buf_read_page(session, GET_ROWID_PAGE(cursor->rowid), LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
                return GS_ERROR;
    }
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);

    if (!heap_check_page(session, cursor, page, PAGE_TYPE_HEAP_DATA)) {
        buf_leave_page(session, GS_FALSE);
        HEAP_CHECKPAGE_ERROR(cursor);
        return GS_ERROR;
    }

    if ((uint16)cursor->rowid.slot >= page->dirs) {
        buf_leave_page(session, GS_FALSE);
        GS_THROW_ERROR(ERR_INVALID_ROWID);
        return GS_ERROR;
    }

    if (heap_get_row(session, cursor, page, DB_CURR_SCN(session), &is_found) != GS_SUCCESS) {
        buf_leave_page(session, GS_FALSE);
        return GS_ERROR;
    }

    if (SECUREC_UNLIKELY(session->wxid.value != GS_INVALID_ID64)) {
        session->wxid.value = GS_INVALID_ID64;
    }
    buf_leave_page(session, GS_FALSE);

    if (cursor->snapshot.scn > cursor->query_scn) {
        if (heap_check_current_visible(session, cursor, GS_TRUE, &is_found) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

