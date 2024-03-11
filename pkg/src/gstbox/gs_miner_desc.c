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
 * gs_miner_desc.c
 *
 *
 * IDENTIFICATION
 * src/gstbox/gs_miner_desc.c
 *
 * -------------------------------------------------------------------------
 */
#include "gs_tbox_module.h"
#include "gs_miner_desc.h"
#include "pcr_btree.h"
#include "dtc_database.h"

static status_t miner_time2str(time_t time, char *str, uint16 size)
{
    text_t fmt_text, time_text;
    if (strlen("YYYY-MM-DD HH24:MI:SS") >= size) {
        CT_THROW_ERROR(ERR_BUFFER_UNDERFLOW, size, strlen("YYYY-MM-DD HH24:MI:SS"));
        return CT_ERROR;
    }

    cm_str2text("YYYY-MM-DD HH24:MI:SS", &fmt_text);
    time_text.str = str;
    time_text.len = 0;

    return cm_time2text(time, &fmt_text, &time_text, size);
}

static inline void miner_desc_entry(log_entry_t *log, page_id_t page_id)
{
    printf("\tentry: %-20s len: %-4u \tflag: %u \tpage: %u-%u \tdesc: ",
           g_log_desc[log->type].name, (uint32)log->size, log->flag, (uint32)page_id.file, (uint32)page_id.page);

    if (g_log_desc[log->type].desc_proc != NULL) {
        g_log_desc[log->type].desc_proc(log);
    } else {
        printf("<missed desc proc>\n");
    }
}

void miner_desc_group(log_group_t *group)
{
    uint32 offset;
    page_id_t page[KNL_MAX_ATOMIC_PAGES];
    uint32 level;
    log_entry_t *entry = NULL;
    rd_enter_page_t *redo = NULL;

    level = 0;
    page[0] = INVALID_PAGID;
    offset = sizeof(log_group_t);

    printf("group: %llu size: %u rmid: %u nologging insert: %u\n", group->lsn, (uint32)LOG_GROUP_ACTUAL_SIZE(group),
        group->rmid, group->nologging_insert);

    while (offset < LOG_GROUP_ACTUAL_SIZE(group)) {
        entry = (log_entry_t *)((char *)group + offset);

        if (RD_TYPE_IS_ENTER_PAGE(entry->type)) {
            level++;
            redo = (rd_enter_page_t *)entry->data;
            page[level] = MAKE_PAGID(redo->file, redo->page);
        }

        miner_desc_entry(entry, page[level]);

        if (RD_TYPE_IS_LEAVE_PAGE(entry->type) && level > 0) {
            level--;
        }

        /* the max size of log buffer is 64M */
        offset += entry->size;
    }
}

void miner_desc_group_xid(log_group_t *group, bool32 has_xid, tx_msg_t *tx_msg, uint8 xid_cnt)
{
    uint32 offset;
    page_id_t page[KNL_MAX_ATOMIC_PAGES];
    uint32 level;
    log_entry_t *entry = NULL;
    rd_tx_end_t *data = NULL;

    level = 0;
    page[0] = INVALID_PAGID;
    offset = sizeof(log_group_t);

    while (offset < LOG_GROUP_ACTUAL_SIZE(group) {
        entry = (log_entry_t *)((char *)group + offset);

        if (entry->type != RD_TX_BEGIN && entry->type != RD_TX_END) {
            offset += entry->size;
            continue;
        }
        if (entry->type == RD_TX_BEGIN) {
            xid_t cur_xid = *(xid_t *)entry->data;
            for (uint8 i = 0; i < xid_cnt; i++) {
                if (cur_xid.value == tx_msg[i].xid.value) {
                    tx_msg[i].rmid = group->rmid;
                    break;
                }
            }
        }
        if (entry->type == RD_TX_END) {
            for (uint8 i = 0; i < xid_cnt; i++) {
                data = (rd_tx_end_t *)entry->data;
                if ((uint32)data->xmap.seg_id == tx_msg[i].xid.xmap.seg_id &&
                    (uint32)data->xmap.slot == tx_msg[i].xid.xmap.slot && group->rmid == tx_msg[i].rmid) {
                    printf("group: %llu size: %u rmid: %u nologging insert: %u\n",
                        group->lsn, (uint32)LOG_GROUP_ACTUAL_SIZE(group), group->rmid, group->nologging_insert);
                    miner_desc_entry(entry, page[level]);
                    break;
                }
            }
        }
        /* the max size of log buffer is 64M */
        offset += entry->size;
    }
}

static void print_heap_information(heap_page_t *page)
{
    printf("heap page information\n");
    printf("\t{ map.file: %u, map.page: %u, map.list_id: %u, map.slot: %u }\n",
        (uint32)page->map.file, (uint32)page->map.page, (uint32)page->map.list_id, (uint32)page->map.slot);
    printf("\t{ org_scn: %llu }\n", page->org_scn);
    printf("\t{ seg_scn: %llu }\n", page->seg_scn);
    printf("\t{ uid: %u }\n", page->uid);
    printf("\t{ oid: %u }\n", page->oid);
    printf("\t{ first_free_dir: %u }\n", (uint32)(page->first_free_dir));
    printf("\t{ next %u-%u }\n", (uint32)(AS_PAGID_PTR(page->next)->file), (uint32)(AS_PAGID_PTR(page->next)->page));
    printf("\t{ free_begin: %u }\n", (uint32)(page->free_begin));
    printf("\t{ free_end: %u }\n", (uint32)(page->free_end));
    printf("\t{ free_size: %u }\n", (uint32)(page->free_size));
    printf("\t{ rows: %u }\n", page->rows);
    printf("\t{ dirs: %u }\n", page->dirs);
    printf("\t{ itls: %u }\n", page->itls);
    printf("\t{ scn: %llu }\n", page->scn);
}

static void print_heap_itl_information(heap_page_t *page)
{
    itl_t *itl = NULL;
    uint32 slot;
    printf("itl information on this page {\n");
    for (slot = 0; slot < page->itls; slot++) {
        itl = heap_get_itl(page, slot);

        printf("\titls[%u] ", slot);
        printf("\tscn: %-3llu", itl->scn);
        printf("\txid.xmap.seg_id: %u", itl->xid.xmap.seg_id);
        printf("\txid.xmap.slot: %u", itl->xid.xmap.slot);
        printf("\txid.xnum: %u", itl->xid.xnum);
        printf("\tfsc: %u", itl->fsc);
        printf("\tis_active: %u", itl->is_active);
        printf("\tis_owscn: %u", itl->is_owscn);
        printf("\tis_copied: %u\n", itl->is_copied);
    }
    printf("}\n");
}

static void print_heap_row_information(heap_page_t *page)
{
    uint32 slot;
    row_dir_t *dir = NULL;
    row_head_t *row = NULL;

    printf("row information on this page {\n");
    for (slot = 0; slot < page->dirs; slot++) {
        dir = heap_get_dir(page, slot);
        printf("\tdirs[%u] ", slot);
        printf("\toffset: %-5u", dir->offset);
        printf("\tscn: %llu", dir->scn);
        printf("\tis_owscn: %u", dir->is_owscn);
        printf("\tundo_page: %u-%u", (uint32)dir->undo_page.file, (uint32)dir->undo_page.page);
        printf("\tundo_slot: %u", (uint16)dir->undo_slot);

        if (dir->is_free) {
            printf("\tis_free: 1\n");
            continue;
        }

        row = HEAP_GET_ROW(page, dir);
        printf("\trows[%u] ", slot);
        printf("\tsize: %u", row->size);
        if (IS_SPRS_ROW(row)) {
            printf("\tsprs_count: %u", ROW_COLUMN_COUNT(row));
            printf("\tsprs_itl_id: %u", ROW_ITL_ID(row));
        } else {
            printf("\tcolumn_count: %u", ROW_COLUMN_COUNT(row));
            printf("\titl_id: %u", ROW_ITL_ID(row));
        }
        printf("\tis_deleted/is_link/is_migr/self_chg/is_changed %u/%u/%u/%u/%u\n",
            row->is_deleted, row->is_link, row->is_migr, row->self_chg, row->is_changed);
    }
    printf("}\n");
}

void miner_desc_heap_page(heap_page_t *page)
{
    print_heap_information(page);
    print_heap_itl_information(page);
    print_heap_row_information(page);
}

void print_pcr_heap_page_information(heap_page_t *page)
{
    printf("PCR heap page information\n");

    printf("\t{ map.file: %u, map.page: %u, map.list_id: %u, map.slot: %u }\n",
        (uint32)page->map.file, (uint32)page->map.page, (uint32)page->map.list_id, (uint32)page->map.slot);
    printf("\t{ org_scn: %llu }\n", page->org_scn);
    printf("\t{ seg_scn: %llu }\n", page->seg_scn);
    printf("\t{ uid: %u }\n", page->uid);
    printf("\t{ oid: %u }\n", page->oid);
    printf("\t{ first_free_dir: %u }\n", (uint32)(page->first_free_dir));
    printf("\t{ next %u-%u }\n", (uint32)(AS_PAGID_PTR(page->next)->file), (uint32)(AS_PAGID_PTR(page->next)->page));
    printf("\t{ free_begin: %u }\n", (uint32)(page->free_begin));
    printf("\t{ free_end: %u }\n", (uint32)(page->free_end));
    printf("\t{ free_size: %u }\n", (uint32)(page->free_size));
    printf("\t{ rows: %u }\n", page->rows);
    printf("\t{ dirs: %u }\n", page->dirs);
    printf("\t{ itls: %u }\n", page->itls);
    printf("\t{ scn: %llu }\n", page->scn);
}

void print_pcrh_itl_information(heap_page_t *page)
{
    pcr_itl_t *itl = NULL;
    uint32 slot;

    printf("itl information on this page {\n");
    for (slot = 0; slot < page->itls; slot++) {
        itl = pcrh_get_itl(page, slot);

        printf("\titls[%u] ", slot);

        printf("\tis_active: %u", itl->is_active);

        if (itl->is_active) {
            printf("\tssn: %u", itl->ssn);
            printf("\tfsc: %u", itl->fsc);
        } else {
            printf("\tscn: %llu", itl->scn);
            printf("\tis_owscn: %u", itl->is_owscn);
        }

        printf("\txid.xmap.seg_id: %u", itl->xid.xmap.seg_id);
        printf("\txid.xmap.slot: %u", itl->xid.xmap.slot);
        printf("\txid.xnum: %u", itl->xid.xnum);

        printf("\tundo_page: %u-%u", (uint32)itl->undo_page.file, (uint32)itl->undo_page.page);
        printf("\tundo_slot: %u\n", (uint16)itl->undo_slot);
    }
    printf("}\n");
}

void print_pcrh_row_information(heap_page_t *page)
{
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    uint32 slot;

    printf("row information on this page {\n");
    for (slot = 0; slot < page->dirs; slot++) {
        printf("\tdirs[%u] ", slot);

        dir = pcrh_get_dir(page, slot);
        if (PCRH_DIR_IS_FREE(dir)) {
            printf("\tfree dir, next %d\n", PCRH_NEXT_FREE_DIR(dir));
            continue;
        }

        printf("\toffset: %-5u", *dir);

        row = PCRH_GET_ROW(page, dir);
        printf("\trows[%u] ", slot);
        printf("\tsize: %u", row->size);
        if (IS_SPRS_ROW(row)) {
            printf("\tsprs_count: %u", ROW_COLUMN_COUNT(row));
            printf("\tsprs_itl_id: %u", ROW_ITL_ID(row));
        } else {
            printf("\tcolumn_count: %u", ROW_COLUMN_COUNT(row));
            printf("\titl_id: %u", ROW_ITL_ID(row));
        }
        printf("\tis_deleted/is_link/is_migr/self_chg/is_changed %u/%u/%u/%u/%u",
            row->is_deleted, row->is_link, row->is_migr, row->self_chg, row->is_changed);

        if (row->is_link || row->is_migr) {
            rowid_t *rowid = PCRH_NEXT_ROWID(row);
            printf("\tnext_rowid.file: %u", (uint32)rowid->file);
            printf("\tnext_rowid.page: %u", (uint32)rowid->page);
            printf("\tnext_rowid.slot: %u\n", (uint32)rowid->slot);
        } else {
            printf("\n");
        }
    }
    printf("}\n");
}

void miner_desc_pcrh_page(heap_page_t *page)
{
    print_pcr_heap_page_information(page);
    print_pcrh_itl_information(page);
    print_pcrh_row_information(page);
}

void miner_desc_undo_page(undo_page_t *page)
{
    undo_row_t *row = NULL;
    page_id_t seg_id;
    uint32 slot;

    printf("undo page information\n");
    printf("\t{ prev: %u-%u }\n", (uint32)page->prev.file, (uint32)page->prev.page);
    printf("\t{ ss_time: %lld }\n", page->ss_time);
    printf("\t{ rows: %u }\n", page->rows);
    printf("\t{ free_size: %u }\n", page->free_size);
    printf("\t{ free_begin: %u }\n", page->free_begin);
    printf("\t{ begin_slot: %u }\n", page->begin_slot);

    printf("row information on this page {\n");
    for (slot = 0; slot < page->rows; slot++) {
        row = (undo_row_t *)((char *)page + *(uint16 *)((char *)page + PAGE_SIZE(page->head) -
                                                        (sizeof(page_tail_t) + (slot + 1) * sizeof(uint16))));

        printf("rows[%u], type %s, ", slot, undo_type((uint8)row->type));
        printf("is_cleaned %u, is_xfirst %u, scn %llu, is_owscn %u, xid.xmap.seg_id %u, xid.xmap.slot %u, "
               "xid.xnum %u, ssn %u ",
               (uint32)row->is_cleaned, (uint32)row->is_xfirst, (uint64)row->scn, (uint32)row->is_owscn,
               (uint32)row->xid.xmap.seg_id, (uint32)row->xid.xmap.slot, (uint32)row->xid.xnum, row->ssn);

        if (row->type == UNDO_BTREE_INSERT || row->type == UNDO_BTREE_DELETE) {
            seg_id = MAKE_PAGID((uint16)row->seg_file, (uint32)row->seg_page);
            printf("seg_file %u, seg_page %u, index_id %u, is_shadow %d, ", (uint32)seg_id.file, (uint32)seg_id.page,
                   (uint32)row->index_id, (row->index_id == CT_SHADOW_INDEX_ID ? 1 : 0));
        } else if (row->type == UNDO_TEMP_BTREE_INSERT || row->type == UNDO_TEMP_BTREE_DELETE) {
            printf("user_id %u, seg_page(table_id) %u, index_id %u, ", (uint32)row->user_id,
                   (uint32)row->seg_page, (uint32)row->index_id);
        } else {
            printf("rowid.file %u, rowid.page %u, rowid.slot %u, ", (uint32)row->rowid.file,
                   (uint32)row->rowid.page, (uint32)row->rowid.slot);
        }

        printf("prev_page %u-%u, prev_slot %u\n", (uint32)row->prev_page.file,
               (uint32)row->prev_page.page, (uint32)row->prev_slot);
    }
    printf("}\n");
}

void print_btree_information(btree_page_t *page)
{
    printf("btree page information\n");
    printf("\t{ seg_scn: %llu }\n", page->seg_scn);
    printf("\t{ is_recycled: %u }\n", page->is_recycled);
    printf("\t{ prev: %u-%u }\n", (uint32)AS_PAGID_PTR(page->prev)->file, (uint32)AS_PAGID_PTR(page->prev)->page);
    printf("\t{ next: %u-%u }\n", (uint32)AS_PAGID_PTR(page->next)->file, (uint32)AS_PAGID_PTR(page->next)->page);
    printf("\t{ level: %u }\n", page->level);
    printf("\t{ keys: %u }\n", page->keys);
    printf("\t{ itls: %u }\n", page->itls);
    printf("\t{ free_begin: %u }\n", page->free_begin);
    printf("\t{ free_end: %u }\n", page->free_end);
    printf("\t{ free_size: %u }\n", page->free_size);
    printf("\t{ scn: %llu }\n", page->scn);
}

void print_btree_itl_information(btree_page_t *page)
{
    itl_t *itl = NULL;

    printf("itl information on this page {\n");
    for (uint32 slot = 0; slot < page->itls; slot++) {
        itl = BTREE_GET_ITL(page, slot);

        printf("\titls[%u]: ", slot);
        printf("\tscn: %-3llu", itl->scn);
        printf("\txid.xmap.seg_id: %u", itl->xid.xmap.seg_id);
        printf("\txid.xmap.slot: %u", itl->xid.xmap.slot);
        printf("\txid.xnum: %u", itl->xid.xnum);
        printf("\tfsc: %u", itl->fsc);
        printf("\tis_active: %u", itl->is_active);
        printf("\tis_owscn: %u", itl->is_owscn);
        printf("\tis_copied: %u\n", itl->is_copied);
    }
    printf("}\n");
}

void print_btree_key_information(btree_page_t *page)
{
    btree_dir_t *dir = NULL;
    btree_key_t *key = NULL;

    printf("key information on this page {\n");
    for (uint32 slot = 0; slot < page->keys; slot++) {
        dir = BTREE_GET_DIR(page, slot);
        key = BTREE_GET_KEY(page, dir);

        printf("\tdirs[%u] ", slot);
        printf("\toffset: %-5u", dir->offset);
        printf("\titl_id: %u", dir->itl_id);
        printf("\tkeys[%u] ", slot);
        printf("\tscn: %llu", key->scn);
        printf("\tis_owscn/is_infinite/is_deleted/is_cleaned: %u/%u/%u/%u",
            key->is_owscn, key->is_infinite, key->is_deleted, key->is_cleaned);
        printf("\trowid.file: %u", (uint32)key->rowid.file);
        printf("\trowid.page: %u", (uint32)key->rowid.page);
        printf("\trowid.slot: %u", (uint32)key->rowid.slot);
        printf("\tundo_page: %u-%u", (uint32)key->undo_page.file, (uint32)key->undo_page.page);
        printf("\tundo_slot: %u", key->undo_slot);
        printf("\tsize: %u\n", (uint32)key->size);
    }
    printf("}\n");
}

void miner_desc_btree_page(btree_page_t *page)
{
    print_btree_information(page);
    print_btree_itl_information(page);
    print_btree_key_information(page);
}

void print_pcrb_information(btree_page_t *page)
{
    printf("PCR btree page information\n");
    printf("\t{ seg_scn: %llu }\n", page->seg_scn);
    printf("\t{ is_recycled: %u }\n", page->is_recycled);
    printf("\t{ prev: %u-%u }\n", (uint32)AS_PAGID_PTR(page->prev)->file, (uint32)AS_PAGID_PTR(page->prev)->page);
    printf("\t{ next: %u-%u }\n", (uint32)AS_PAGID_PTR(page->next)->file, (uint32)AS_PAGID_PTR(page->next)->page);
    printf("\t{ level: %u }\n", page->level);
    printf("\t{ keys: %u }\n", page->keys);
    printf("\t{ itls: %u }\n", page->itls);
    printf("\t{ free_begin: %u }\n", page->free_begin);
    printf("\t{ free_end: %u }\n", page->free_end);
    printf("\t{ free_size: %u }\n", page->free_size);
}

void print_pcrb_itl_information(btree_page_t *page)
{
    pcr_itl_t *itl = NULL;
    uint32 slot;

    printf("itl information on this page {\n");
    for (slot = 0; slot < page->itls; slot++) {
        itl = pcrb_get_itl(page, slot);

        printf("\titls[%u] ", slot);

        printf("\tis_active: %u", itl->is_active);

        if (itl->is_active) {
            printf("\tssn: %u", itl->ssn);
            printf("\tfsc: %u", itl->fsc);
        } else {
            printf("\tscn: %llu", itl->scn);
            printf("\tis_owscn: %u", itl->is_owscn);
        }

        printf("\txid.xmap.seg_id: %u", itl->xid.xmap.seg_id);
        printf("\txid.xmap.slot: %u", itl->xid.xmap.slot);
        printf("\txid.xnum: %u", itl->xid.xnum);

        printf("\tundo_page: %u-%u", (uint32)itl->undo_page.file, (uint32)itl->undo_page.page);
        printf("\tundo_slot: %u", (uint16)itl->undo_slot);

        printf("\tis_copied: %u\n", itl->is_copied);
    }
    printf("}\n");
}

void print_pcrb_key_information(btree_page_t *page)
{
    pcrb_dir_t *dir = NULL;
    pcrb_key_t *key = NULL;
    page_id_t child;
    uint32 slot;

    printf("key information on this page {\n");
    for (slot = 0; slot < page->keys; slot++) {
        dir = pcrb_get_dir(page, slot);
        key = PCRB_GET_KEY(page, dir);

        printf("\tdirs[%u] ", slot);
        printf("\toffset: %-5u", *dir);
        printf("\tkeys[%u] ", slot);
        printf("\tsize: %u", (uint32)key->size);
        printf("\titl_id: %u", key->itl_id);
        printf("\tis_infinite/is_deleted/is_cleaned: %u/%u/%u",
            key->is_infinite, key->is_deleted, key->is_cleaned);
        printf("\trowid.file: %u", (uint32)key->rowid.file);
        printf("\trowid.page: %u", (uint32)key->rowid.page);
        printf("\trowid.slot: %u", (uint32)key->rowid.slot);

        if (page->level > 0) {
            child = pcrb_get_child(key);
            printf("\tchild: %u-%u", (uint32)child.file, (uint32)child.page);
        }

        printf("\n");
    }
    printf("}\n");
}

void miner_desc_pcrb_page(btree_page_t *page)
{
    print_pcrb_information(page);
    print_pcrb_itl_information(page);
    print_pcrb_key_information(page);
}

void miner_desc_map_page(map_page_t *page)
{
    map_node_t *node = NULL;
    uint32 slot;

    printf("map page information {\n");
    printf("\tmap.file %u, map.page %u, map.slot %u, map.list_id %u }\n",
           (uint32)page->map.file, (uint32)page->map.page, (uint32)page->map.slot, (uint32)page->map.list_id);
    printf("\t{ hwm: %u }\n", page->hwm);

    printf("list information on this page {\n");
    for (slot = 0; slot < HEAP_FREE_LIST_COUNT; slot++) {
        printf("\tlists[%u] ", slot);
        printf("\tcount: #%-3u", page->lists[slot].count);
        printf("\tfirst: %u\n", page->lists[slot].first);
    }
    printf("}\n");

    printf("map information on this page {\n");
    for (slot = 0; slot < (uint32)page->hwm; slot++) {
        node = (map_node_t *)((char *)page + sizeof(map_page_t) + slot * sizeof(map_node_t));
        printf("\tnodes[%u] ", slot);
        printf("\tfile: %-3u", (uint32)node->file);
        printf("\tpage: %u", (uint32)node->page);
        printf("\tprev: %u", (uint32)node->prev);
        printf("\tnext: %u\n", (uint32)node->next);
    }
    printf("}\n");
}

void miner_desc_txn_page(txn_page_t *page)
{
    txn_t *txn = NULL;
    page_id_t first, last;
    uint32 count, slot;

    /* page size if 8192, bigger than sizeof(page_head_t) + sizeof(page_tail_t) */
    count = (PAGE_SIZE(page->head) - sizeof(page_head_t) - sizeof(page_tail_t)) / sizeof(txn_t);

    printf("txn page information {\n");

    for (slot = 0; slot < count; slot++) {
        txn = &page->items[slot];

        first = PAGID_U2N(txn->undo_pages.first);
        last = PAGID_U2N(txn->undo_pages.last);

        printf("\titems[%u] ", slot);
        printf("\txnum: %-3u", txn->xnum);
        printf("\tstatus: %s", txn_status((xact_status_t)txn->status));
        printf("\tscn: %llu", txn->scn);
        printf("\tundo_pages: count %u first %u-%u last %u-%u\n", txn->undo_pages.count,
               (uint32)first.file, (uint32)first.page, (uint32)last.file, (uint32)last.page);
    }
    printf("}\n");
}

status_t miner_desc_page_head_tail(uint32 id, page_head_t *head, uint32 page_size, bool32 is_checksum, bool32 is_force)
{
    page_tail_t *tail = NULL;
    bool32 pass_cks;

    printf("\ninformation of page %u\n", id);
    printf("\tpage head info {\n");
    printf("\tpage_id: %u-%u", AS_PAGID_PTR(head->id)->file, AS_PAGID_PTR(head->id)->page);
    printf("\tlsn: %llu", head->lsn);
    printf("\tpcn: %u", head->pcn);
    printf("\tsize_units: %u", head->size_units);
    printf("\tsize: %d", PAGE_SIZE(*head));
    printf("\ttype: %s", page_type(head->type));
    printf("\text_size: %u", head->ext_size);
    printf("\tencrypted: %u", head->encrypted);
    printf("\tcompressed: %u", head->compressed);
    printf("\tsof_damage: %u", head->soft_damage);
    printf("\thard_damage: %u", head->hard_damage);
    printf("\tnext_ext: %u-%u }\n", AS_PAGID_PTR(head->next_ext)->file, AS_PAGID_PTR(head->next_ext)->page);
    if (page_size != PAGE_SIZE(*head) && !is_force) {
        printf("\tinvalid page size %d,expected %u.\n", PAGE_SIZE(*head), page_size);
        return CT_ERROR;
    }
    if (head->compressed) {
        return CT_SUCCESS;
    }
    tail = (page_tail_t *)((char *)head + PAGE_SIZE(*head) - sizeof(page_tail_t));
    printf("\tpage tail info {\n");
    printf("\tchecksum: %u", tail->checksum);
    if (tail->checksum != CT_INVALID_CHECKSUM) {
        pass_cks = page_verify_checksum(head, page_size);
        printf("\tverify checksum: %s", pass_cks ? "success" : "corrupted");
    }
    printf("\treserve: %u", tail->reserve);
    printf("\tpcn: %u }\n", tail->pcn);
    return CT_SUCCESS;
}

void miner_desc_punch_head(spc_punch_head_t *head)
{
    printf("punch head information\n");
    if (head->punching_exts.count != 0) {
        printf("\t{ punching_exts: count %u first %u-%u last %u-%u }\n", head->punching_exts.count,
            head->punching_exts.first.file, head->punching_exts.first.page,
            head->punching_exts.last.file, head->punching_exts.last.page);
    } else {
        printf("\t{ punching_exts: count 0 invalid page id range}\n");
    }
    if (head->punched_exts.count != 0) {
        printf("\t{ punched_exts: count %u first %u-%u last %u-%u }\n", head->punched_exts.count,
            head->punched_exts.first.file, head->punched_exts.first.page,
            head->punched_exts.last.file, head->punched_exts.last.page);
    } else {
        printf("\t{ punched_exts: count 0 invalid page id range}\n");
    }
}

void miner_desc_space_head(space_head_t *head)
{
    uint32 slot;

    printf("space head information\n");
    printf("\t{ segment_count: %u }\n", head->segment_count);
    printf("\t{ datafile_count: %u }\n", head->datafile_count);
    printf("\t{ free_extents: count %u first %u-%u last %u-%u }\n", head->free_extents.count,
           head->free_extents.first.file, head->free_extents.first.page,
           head->free_extents.last.file, head->free_extents.last.page);
    miner_desc_punch_head((spc_punch_head_t *)((char *)head + sizeof(space_head_t)));
    printf("datafile hwms information {");
    for (slot = 0; slot < CT_MAX_SPACE_FILES; slot++) {
        if (slot % SPACE_FILES_PER_LINE == 0) {
            printf("\n\t");
        }
        printf("%u ", head->hwms[slot]);
    }
    printf(" }\n");
}

void miner_desc_undo_head(undo_segment_t *segment)
{
    uint32 slot;

    printf("undo segment information\n");

    printf("\t{ page lists: count %u first %u-%u last %u-%u }\n", segment->page_list.count,
           segment->page_list.first.file, segment->page_list.first.page,
           segment->page_list.last.file, segment->page_list.last.page);
    printf("\t{ txn_page_count: %u }\n", segment->txn_page_count);

    printf("txn_page information on this page {");

    for (slot = 0; slot < segment->txn_page_count; slot++) {
        if (slot % TXN_PAGE_PER_LINE == 0) {
            printf("\n\t");
        }
        printf("%u-%u ", segment->txn_page[slot].file, segment->txn_page[slot].page);
    }

    printf("}\n");
}

void miner_desc_btree_head(btree_segment_t *segment)
{
    printf("btree segment information\n");
    printf("\t{ tree_info.root %u-%u, tree_info.level %u }\n", (uint32)AS_PAGID(segment->tree_info.root).file,
           (uint32)AS_PAGID(segment->tree_info.root).page, (uint32)segment->tree_info.level);
    printf("\t{ org_scn: %llu }\n", segment->org_scn);
    printf("\t{ seg_scn: %llu }\n", segment->seg_scn);
    printf("\t{ table_id: %u }\n", segment->table_id);
    printf("\t{ uid: %u }\n", segment->uid);
    printf("\t{ index_id: %u }\n", segment->index_id);
    printf("\t{ space_id: %u }\n", segment->space_id);
    printf("\t{ initrans: %u }\n", segment->initrans);
    printf("\t{ cr_mode: %u }\n", segment->cr_mode);
    printf("\t{ del_scn: %llu }\n", segment->del_scn);
    printf("\t{ del_pages: count %u, first %u-%u, last %u-%u\n", segment->del_pages.count,
           segment->del_pages.first.file, segment->del_pages.first.page,
           segment->del_pages.last.file, segment->del_pages.last.page);
    printf("\t{ pctfree: %u }\n", segment->pctfree);
    printf("btree storage information\n");
    printf("\t{ extents: count %u, first %u-%u, last %u-%u }\n", segment->extents.count,
           segment->extents.first.file, segment->extents.first.page,
           segment->extents.last.file, segment->extents.last.page);
    printf("\t{ ufp_count: %u }\n", segment->ufp_count);
    printf("\t{ ufp_first: %u-%u }\n", segment->ufp_first.file, segment->ufp_first.page);
    printf("\t{ ufp_extent: %u-%u }\n", segment->ufp_extent.file, segment->ufp_extent.page);
    printf("\t{ page_count: %u }\n", segment->page_count);
    printf("\t{ garbage_size: %llu }\n", segment->garbage_size);
    printf("\t{ first_recycle_scn: %llu }\n", segment->first_recycle_scn);
    printf("\t{ ow_del_scn: %llu }\n", segment->ow_del_scn);
    printf("\t{ ow_recycle_scn: %lld }\n", segment->ow_recycle_scn);
    printf("\t{ recycle_version_scn: %lld }\n", segment->recycle_ver_scn);
    printf("\t{ last_recycle_scn: %llu }\n", segment->last_recycle_scn);
    printf("\t{ recycled_pages: count %u, first %u-%u, last %u-%u\n", segment->recycled_pages.count,
           segment->recycled_pages.first.file, segment->recycled_pages.first.page,
           segment->recycled_pages.last.file, segment->recycled_pages.last.page);
}

void miner_desc_heap_head(heap_segment_t *segment)
{
    uint32 i;

    printf("heap segment information\n");

    printf("\t{ uid: %u }\n", segment->uid);
    printf("\t{ oid: %u }\n", segment->oid);
    printf("\t{ space_id: %u }\n", segment->space_id);
    printf("\t{ initrans: %u }\n", segment->initrans);
    printf("\t{ org_scn: %llu }\n", segment->org_scn);
    printf("\t{ seg_scn: %llu }\n", segment->seg_scn);
    printf("\t{ cr_mode: %u }\n", segment->cr_mode);
    printf("\t{ serial: %llu }\n", segment->serial);

    printf("heap storage information\n");
    printf("\t{ ufp_count: %u }\n", segment->ufp_count);
    printf("\t{ extents: count %u, first %u-%u, last %u-%u }\n", segment->extents.count,
           segment->extents.first.file, segment->extents.first.page,
           segment->extents.last.file, segment->extents.last.page);
    printf("\t{ free_extents: count %u, first %u-%u, last %u-%u }\n", segment->free_extents.count,
           segment->free_extents.first.file, segment->free_extents.first.page,
           segment->free_extents.last.file, segment->free_extents.last.page);
    printf("\t{ free_ufp: %u-%u }\n", segment->free_ufp.file, segment->free_ufp.page);
    printf("\t{ data_first: %u-%u }\n", segment->data_first.file, segment->data_first.page);
    printf("\t{ data_last: %u-%u }\n", segment->data_last.file, segment->data_last.page);
    printf("\t{ cmp_hwm: %u-%u }\n", segment->cmp_hwm.file, segment->cmp_hwm.page);
    printf("\t{ shrinkable_scn: %llu }\n", segment->shrinkable_scn);
    printf("\t{ page_count: %u }\n", segment->page_count);
    printf("\t{ free_page_count: %u }\n", segment->free_page_count);
    printf("\t{ last_ext_size: %u }\n", (uint32)segment->last_ext_size);
    printf("\t{ compress: %u }\n", (uint32)segment->compress);

    printf("heap map information\n");
    printf("\t{ tree_info.level: %u", (uint32)segment->tree_info.level);
    printf("\ttree_info.root: %u-%u }", (uint32)AS_PAGID(segment->tree_info.root).file,
           (uint32)AS_PAGID(segment->tree_info.root).page);

    printf("\n\tcurr_map { ");
    for (i = 0; i <= (uint32)segment->tree_info.level; i++) {
        printf("%u-%u ", segment->curr_map[i].file, segment->curr_map[i].page);
    }
    printf("}");

    printf("\n\tmap_count { ");
    for (i = 0; i <= (uint32)segment->tree_info.level; i++) {
        printf("%u ", segment->map_count[i]);
    }
    printf("}");
    
    printf("\n\tlist_range { ");
    for (i = 0; i < HEAP_FREE_LIST_COUNT; i++) {
        printf("%u ", segment->list_range[i]);
    }
    printf("}\n");
}

void miner_desc_lob_head(lob_segment_t *segment)
{
    printf("lob segment information\n");
    printf("\t{ table_id: %u }\n", segment->table_id);
    printf("\t{ uid: %u }\n", segment->uid);
    printf("\t{ space_id: %u }\n", segment->space_id);
    printf("\t{ column_id: %u }\n", segment->column_id);
    printf("\t{ org_scn: %llu }\n", segment->org_scn);
    printf("\t{ seg_scn: %llu }\n", segment->seg_scn);
    printf("\t{ shrink_scn: %llu }\n", segment->shrink_scn);

    printf("lob storage information\n");
    printf("\t{ extents: count %u, first %u-%u, last %u-%u }\n", segment->extents.count,
           segment->extents.first.file, segment->extents.first.page,
           segment->extents.last.file, segment->extents.last.page);
    printf("\t{ free_list: count %u, first %u-%u, last %u-%u }\n", segment->free_list.count,
           segment->free_list.first.file, segment->free_list.first.page,
           segment->free_list.last.file, segment->free_list.last.page);
    printf("\t{ ufp_count: %u }\n", segment->ufp_count);
    printf("\t{ ufp_first: %u-%u }\n", segment->ufp_first.file, segment->ufp_first.page);
    printf("\t{ ufp_extent: %u-%u }\n", segment->ufp_extent.file, segment->ufp_extent.page);
}

void miner_desc_lob_data(lob_data_page_t *page)
{
    lob_chunk_t *chunk = &page->chunk;

    printf("lob page chunk information {\n");

    printf("\tinsert_xid: ins_xid.xmap.seg_id %u, ins_xid.xmap.slot %u, ins_xid.xnum %u\n",
           chunk->ins_xid.xmap.seg_id, chunk->ins_xid.xmap.slot, chunk->ins_xid.xnum);
    printf("\tdelete_xid: del_xid.xmap.seg_id %u, del_xid.xmap.slot %u, del_xid.xnum %u\n",
           chunk->del_xid.xmap.seg_id, chunk->del_xid.xmap.slot, chunk->del_xid.xnum);
    printf("\torg_scn %llu", chunk->org_scn);
    printf("\tsize %u", chunk->size);
    printf("\tnext %u-%u", (uint32)chunk->next.file, chunk->next.page);
    printf("\tfree_next %u-%u", (uint32)chunk->free_next.file, chunk->free_next.page);
    printf("\tis_recycle: %u\n", (uint32)chunk->is_recycled);
    printf("}\n");
}

void miner_desc_map_head(const df_map_head_t *page)
{
    printf("datafile dump map head information\n");
    printf("\tbit unit:%u, group count:%u, reserved:%u \n", (uint32)page->bit_unit, (uint32)page->group_count,
        page->reserved);
    printf("datafile group information\n");
    for (uint32 i = 0; i < (uint32)page->group_count; i++) {
        printf("\t page:%u, file:%u, page count:%u \n", page->groups[i].first_map.page,
            (uint32)page->groups[i].first_map.file, (uint32)page->groups[i].page_count);
    }
}

void miner_desc_map_data(df_map_page_t *page, uint32 page_size)
{
    printf("datafile dump map data information\n");
    printf("\t first managed page:%u, file:%u\n", (uint32)page->first_page.page, (uint32)page->first_page.file);
    printf("\t first free_bit:%u, free_bits:%u, reserved:%u \n", (uint32)page->free_begin,
        (uint32)page->free_bits, page->reserved);
    printf("bit map use information(1:use,0:unused)\n");
    uint8 *bitmap = page->bitmap;
    uint32 bit_cnt = (page_size - sizeof(df_map_page_t) - sizeof(page_tail_t)) * DF_BYTE_TO_BITS;
    for (uint32 i = 0; i < bit_cnt; i++) {
        if (!DF_MAP_MATCH(bitmap, i)) {
            printf("1");
        } else {
            printf("0");
        }
        if ((i + 1) % DF_PAGE_PER_LINE == 0) {
            if ((i + 1) % DF_PAGE_PER_LINE_COUNT == 0) {
                printf("\n");
            } else {
                printf("\t ");
            }
        }
    }
}

void miner_desc_page_by_type(char *buf, uint8 type, uint32 page_size)
{
    switch (type) {
        case PAGE_TYPE_SPACE_HEAD:
            miner_desc_space_head((space_head_t *)(buf + sizeof(page_head_t)));
            break;
        case PAGE_TYPE_HEAP_HEAD:
            miner_desc_heap_head((heap_segment_t *)(buf + sizeof(page_head_t)));
            break;
        case PAGE_TYPE_HEAP_MAP:
            miner_desc_map_page((map_page_t *)buf);
            break;
        case PAGE_TYPE_HEAP_DATA:
            miner_desc_heap_page((heap_page_t *)buf);
            break;
        case PAGE_TYPE_UNDO_HEAD:
            miner_desc_undo_head((undo_segment_t *)(buf + sizeof(page_head_t)));
            break;
        case PAGE_TYPE_TXN:
            miner_desc_txn_page((txn_page_t *)buf);
            break;
        case PAGE_TYPE_UNDO:
            miner_desc_undo_page((undo_page_t *)buf);
            break;
        case PAGE_TYPE_BTREE_HEAD:
            miner_desc_btree_head((btree_segment_t *)(buf + sizeof(btree_page_t)));
            break;
        case PAGE_TYPE_BTREE_NODE:
            miner_desc_btree_page((btree_page_t *)buf);
            break;
        case PAGE_TYPE_LOB_HEAD:
            miner_desc_lob_head((lob_segment_t *)(buf + sizeof(page_head_t)));
            break;
        case PAGE_TYPE_LOB_DATA:
            miner_desc_lob_data((lob_data_page_t *)buf);
            break;
        case PAGE_TYPE_PCRH_DATA:
            miner_desc_pcrh_page((heap_page_t *)buf);
            break;
        case PAGE_TYPE_PCRB_NODE:
            miner_desc_pcrb_page((btree_page_t *)buf);
            break;
        case PAGE_TYPE_FILE_HEAD:
            break;
        case PAGE_TYPE_DF_MAP_HEAD:
            miner_desc_map_head((df_map_head_t *)buf);
            break;
        case PAGE_TYPE_DF_MAP_DATA:
            miner_desc_map_data((df_map_page_t *)buf, page_size);
            break;
        case PAGE_TYPE_PUNCH_PAGE:
            printf("This a punch page without information.\n");
            break;
        default:
            printf("unsupported page type\n");
            break;
    }
}

static cipher_ctrl_t *miner_page_cipher_ctrl(page_head_t *page)
{
    uint32 ctrl_offset = 0;
    switch (page->type) {
        case PAGE_TYPE_HEAP_DATA:
        case PAGE_TYPE_PCRH_DATA:
            ctrl_offset = sizeof(heap_page_t);
            break;
        case PAGE_TYPE_BTREE_NODE:
        case PAGE_TYPE_PCRB_NODE:
            ctrl_offset = sizeof(btree_page_t);
            break;
        case PAGE_TYPE_UNDO:
            ctrl_offset = sizeof(undo_page_t);
            break;
        case PAGE_TYPE_LOB_DATA:
            ctrl_offset = PAGE_SIZE(*page) - sizeof(page_tail_t) - sizeof(cipher_ctrl_t);
            break;
        default:
            printf("[miner page encrypt]page type not support.");
            break;
    }
    return (cipher_ctrl_t *)((char *)page + ctrl_offset);
}

static char *miner_page_plain_buf(page_head_t *page, uint8 reserve_size)
{
    char *plain_buf = NULL;
    switch (page->type) {
        case PAGE_TYPE_HEAP_DATA:
        case PAGE_TYPE_PCRH_DATA:
            plain_buf = (char *)page + sizeof(heap_page_t) + reserve_size;
            break;
        case PAGE_TYPE_BTREE_NODE:
        case PAGE_TYPE_PCRB_NODE:
            plain_buf = (char *)page + sizeof(btree_page_t) + reserve_size;
            break;
        case PAGE_TYPE_LOB_DATA:
            plain_buf = (char *)page + sizeof(lob_data_page_t);
            break;
        case PAGE_TYPE_UNDO:
            plain_buf = (char *)page + sizeof(undo_page_t) + reserve_size;
            break;
        default:
            printf("[miner page encrypt]page type not support.");
            break;
    }

    return plain_buf;
}

static uint32 miner_page_plain_len(page_head_t *page, uint8 reserve_size)
{
    uint32 page_meta_size = 0;
    uint32 page_left_size = PAGE_SIZE(*page) - sizeof(page_tail_t) - reserve_size;

    switch (page->type) {
        case PAGE_TYPE_HEAP_DATA:
        case PAGE_TYPE_PCRH_DATA:
            page_meta_size = sizeof(heap_page_t);
            break;
        case PAGE_TYPE_BTREE_NODE:
        case PAGE_TYPE_PCRB_NODE:
            page_meta_size = sizeof(btree_page_t);
            break;
        case PAGE_TYPE_LOB_DATA:
            page_meta_size = sizeof(lob_data_page_t);
            break;
        case PAGE_TYPE_UNDO:
            page_meta_size = sizeof(undo_page_t);
            break;
        default:
            printf("[miner page encrypt]page type not support.");
            break;
    }
    return page_left_size - page_meta_size;
}

status_t miner_decrypt_page(page_head_t *page)
{
    cipher_ctrl_t *cipher_ctrl = miner_page_cipher_ctrl(page);
    char *org_plain_buf = miner_page_plain_buf(page, CIPHER_RESERVE_SIZE);
    uint32 org_plain_len = miner_page_plain_len(page, CIPHER_RESERVE_SIZE);
    uint32 cipher_len = org_plain_len + cipher_ctrl->cipher_expanded_size;
    uint32 MAX_PAGE_SIZE_K = 32;

    char *plain_buf = (char *)malloc(SIZE_K(MAX_PAGE_SIZE_K));
    if (plain_buf == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)(SIZE_K(MAX_PAGE_SIZE_K)), "miner batch page");
        return CT_ERROR;
    }
    uint32 plain_len = PAGE_SIZE(*page);
    if (cm_kmc_decrypt(CT_KMC_KERNEL_DOMAIN, (char *)page + cipher_ctrl->offset, cipher_len, plain_buf, &plain_len) !=
        CT_SUCCESS) {
        printf("[MINER KMC ERROR]page decrypt failed");
        CM_FREE_PTR(plain_buf);
        return CT_ERROR;
    }

    errno_t ret = memcpy_sp(org_plain_buf, PAGE_SIZE(*page), plain_buf, plain_len);
    knl_securec_check(ret);
    CM_FREE_PTR(plain_buf);
    return CT_SUCCESS;
}

void miner_compressed_page(uint32 id, page_head_t *head)
{
    int len = PAGE_SIZE(*head);
    char *compress_algo = NULL;
    uint32 size, algo, gcnt, unused;
    uint16 checksum;
    if (miner_desc_page_head_tail(id, head, len, CT_FALSE, CT_FALSE) != CT_SUCCESS) {
        return;
    }
   
    gcnt = COMPRESS_PAGE_HEAD(head)->group_cnt;
    size = COMPRESS_PAGE_HEAD(head)->compressed_size;
    algo = COMPRESS_PAGE_HEAD(head)->compress_algo;
    checksum = COMPRESS_PAGE_HEAD(head)->checksum;
    unused = COMPRESS_PAGE_HEAD(head)->unused;

    switch (algo) {
        case COMPRESS_NONE:
            compress_algo = "none";
            break;
        case COMPRESS_ZLIB:
            compress_algo = "zlib";
            break;
        case COMPRESS_ZSTD:
            compress_algo = "zstd";
            break;
        case COMPRESS_LZ4:
            compress_algo = "lz4";
            break;
        default:
            compress_algo = "invalid";
            break;
    }
    printf("\tcompress head info {\n");
    printf("\tcompressed_size:%u\t compress_algo:%s\t group_cnt:%u\t checksum: %u\t ",
        size, compress_algo, gcnt, checksum);
    if (checksum != CT_INVALID_CHECKSUM) {
        bool32 pass_cks = page_compress_verify_checksum(head, len);
        printf("verify checksum: %s\t", pass_cks ? "success" : "corrupted");
    }
    printf("unused:%u ", unused);
    printf("}\n");
}

void miner_desc_page(uint32 id, char *buf, uint32 page_size, bool32 is_checksum, bool32 is_force)
{
    page_head_t *head = (page_head_t *)buf;

    if (head->compressed) {
        miner_compressed_page(id, head);
        return;
    }

    if (miner_desc_page_head_tail(id, head, page_size, is_checksum, is_force) != CT_SUCCESS) {
        return;
    }

    if (head->encrypted) {
        if (miner_decrypt_page(head) != CT_SUCCESS) {
            printf("miner page decrypt failed");
            return;
        }
    }

    miner_desc_page_by_type(buf, head->type, page_size);
}

static void miner_desc_ctrlfile_nodes_info(database_ctrl_t *ctrl)
{
    (void)printf("\tnodes information:\n");
    for (uint32 i = 0; i < ctrl->core.node_count; i++) {
        dtc_node_ctrl_t *node_ctrl = (dtc_node_ctrl_t *)ctrl->pages[CTRL_LOG_SEGMENT + i].buf;

        (void)printf("\tnode id:                      %u\n", i);
        (void)printf("\tscn:                          %lld\n", node_ctrl->scn);
        (void)printf("\trcy_point:                    asn(%llu)-block_id(%llu)-rst_id(%llu)-lfn(%llu)-lsn(%llu)\n",
                     (uint64)node_ctrl->rcy_point.asn, (uint64)node_ctrl->rcy_point.block_id,
                     (uint64)node_ctrl->rcy_point.rst_id, (uint64)node_ctrl->rcy_point.lfn, node_ctrl->rcy_point.lsn);
        (void)printf("\tlrp_point:                    asn(%llu)-block_id(%llu)-rst_id(%llu)-lfn(%llu)-lsn(%llu)\n",
                     (uint64)node_ctrl->lrp_point.asn, (uint64)node_ctrl->lrp_point.block_id,
                     (uint64)node_ctrl->lrp_point.rst_id, (uint64)node_ctrl->lrp_point.lfn, node_ctrl->lrp_point.lsn);
        (void)printf("\tckpt_id:                      %llu\n", node_ctrl->ckpt_id);
        (void)printf("\tlsn:                          %lld\n", node_ctrl->lsn);
        (void)printf("\tlfn:                          %lld\n", node_ctrl->lfn);
        (void)printf("\tlog_count:                    %u\n", node_ctrl->log_count);
        (void)printf("\tlog_hwm:                      %u\n", node_ctrl->log_hwm);
        (void)printf("\tlog_first:                    %u\n", node_ctrl->log_first);
        (void)printf("\tlog_last:                     %u\n", node_ctrl->log_last);
        (void)printf("\tshutdown_consistency:         %u\n", node_ctrl->shutdown_consistency);
        (void)printf("\topen_inconsistency:           %u\n", node_ctrl->open_inconsistency);
        (void)printf("\tconsistent_lfn:               %llu\n", node_ctrl->consistent_lfn);
        (void)printf("\tundo_space:                   %u\n", node_ctrl->undo_space);
        (void)printf("\tswap_space:                   %u\n", node_ctrl->swap_space);
        (void)printf("\ttemp_undo_space:              %u\n", node_ctrl->temp_undo_space);
        (void)printf("\tarchived_start:               %u\n", node_ctrl->archived_start);
        (void)printf("\tarchived_end:                 %u\n", node_ctrl->archived_end);
        (void)printf("\tdoublewrite_start:            %u\n", node_ctrl->dw_start);
        (void)printf("\tdoublewrite_end:              %u\n", node_ctrl->dw_end);
        (void)printf("\tlast_asn:                     %u\n", node_ctrl->last_asn);
        (void)printf("\tlast_lfn:                     %u\n", node_ctrl->last_lfn);
        (void)printf("\n");
    }
}

static void miner_desc_ctrlfile_logfile_info(database_ctrl_t *ctrl)
{
    log_file_ctrl_t *logfile = NULL;

    (void)printf("\tlogfiles information:\n");
    for (uint32 i = 0; i < ctrl->core.node_count; i++) {
        (void)printf("\t(id, name, size, hwm, seq, block_size, flg, type, status, forward, backward):\n");
        for (uint32 j = 0; j < CT_MAX_LOG_FILES; j++) {
            logfile = (log_file_ctrl_t *)db_get_log_ctrl_item(ctrl->pages, j, sizeof(log_file_ctrl_t),
                                                              ctrl->log_segment, i);

            (void)printf("\t#%u-%-2u ", i, j);
            (void)printf("\t%-*s ", (int)strlen(logfile->name), NULL_2_STR(logfile->name));
            (void)printf("\t%lld ", logfile->size);
            (void)printf("\t%lld ", logfile->hwm);
            (void)printf("\t%u ", logfile->seq);
            (void)printf("\t%u ", logfile->block_size);
            (void)printf("\t%u ", (uint32)logfile->flg);
            (void)printf("\t%u ", (uint32)logfile->type);
            (void)printf("\t%u ", (uint32)logfile->status);
            (void)printf("\t%u ", (uint32)logfile->forward);
            (void)printf("\t%u\n", (uint32)logfile->backward);
        }
        (void)printf("\n");
    }
}

static void miner_desc_ctrlfile_space_info(database_ctrl_t *ctrl)
{
    space_ctrl_t *space = NULL;

    (void)printf("\tspaces information:\n");
    (void)printf("\t(id, spaceid, used, name, flg, block_size, extent_size, file_hwm, type, org_scn,"
        " encrypt_version, cipher_reserve_size, files):\n");
    for (uint32 i = 0; i < CT_MAX_SPACES; i++) {
        space = (space_ctrl_t *)db_get_ctrl_item(ctrl->pages, i, sizeof(space_ctrl_t), ctrl->space_segment);

        (void)printf("\t#%-2u ", i);
        (void)printf("\t%u ", space->id);
        (void)printf("\t%u ", (uint32)space->used);
        (void)printf("\t%-*s ", (int)strlen(space->name), NULL_2_STR(space->name));
        (void)printf("\t%u ", (uint32)space->flag);
        (void)printf("\t%u ", (uint32)space->block_size);
        (void)printf("\t%u ", space->extent_size);
        (void)printf("\t%u ", space->file_hwm);
        (void)printf("\t%u ", (uint32)space->type);
        (void)printf("\t%llu ", space->org_scn);
        (void)printf("\t%u ", space->encrypt_version);
        (void)printf("\t%u ", space->cipher_reserve_size);
        (void)printf("\t%u", space->files[0]);
        for (uint32 j = 1; j < space->file_hwm; j++) {
            (void)printf(", %u", space->files[j]);
        }
        (void)printf("\n");
    }
}

static void miner_desc_ctrlfile_datafile_info(database_ctrl_t *ctrl)
{
    datafile_ctrl_t *datafile = NULL;

    (void)printf("\tdatafiles information:\n");
    (void)printf("\t(id, dfileid, used, name, size, block_size, flg, type, auto_extend_size, auto_extend_maxsize):\n");
    for (uint32 i = 0; i < CT_MAX_DATA_FILES; i++) {
        datafile = (datafile_ctrl_t *)db_get_ctrl_item(ctrl->pages, i, sizeof(datafile_ctrl_t), ctrl->datafile_segment);

        (void)printf("\t#%-2u ", i);
        (void)printf("\t%u ", datafile->id);
        (void)printf("\t%u ", (uint32)datafile->used);
        (void)printf("\t%-*s ", (int)strlen(datafile->name), NULL_2_STR(datafile->name));
        (void)printf("\t%lld ", datafile->size);
        (void)printf("\t%u ", (uint32)datafile->block_size);
        (void)printf("\t%u ", (uint32)datafile->flag);
        (void)printf("\t%u ", (uint32)datafile->type);
        (void)printf("\t%lld ", datafile->auto_extend_size);
        (void)printf("\t%lld\n", datafile->auto_extend_maxsize);
    }
}

static void miner_desc_ctrlfile_archlog_info(database_ctrl_t *ctrl)
{
    arch_ctrl_t *arch_ctrl = NULL;

    (void)printf("\tarchive log information:\n");
    (void)printf("\t(id, recid, dest_id, rst_id, asn, stamp, blocks, block_size, "
        "logic_size, real_size, first, last, start_lsn, end_lsn, name):\n");
    for (uint32 i = 0; i < ctrl->core.node_count; i++) {
        for (uint32 j = 0; j < CT_MAX_ARCH_NUM; j++) {
            arch_ctrl = (arch_ctrl_t *)db_get_log_ctrl_item(ctrl->pages, j, sizeof(arch_ctrl_t), ctrl->arch_segment, i);

            (void)printf("\t#%u-%-2u ", i, j);
            (void)printf("\t%u ", arch_ctrl->recid);
            (void)printf("\t%u ", arch_ctrl->dest_id);
            (void)printf("\t%u ", arch_ctrl->rst_id);
            (void)printf("\t%u ", arch_ctrl->asn);
            (void)printf("\t%lld", arch_ctrl->stamp);
            (void)printf("\t%d", arch_ctrl->blocks);
            (void)printf("\t%d", arch_ctrl->block_size);
            (void)printf("\t%lld", (int64)arch_ctrl->blocks * arch_ctrl->block_size);
            (void)printf("\t%lld", arch_get_ctrl_real_size(arch_ctrl));
            (void)printf("\t%llu", arch_ctrl->first);
            (void)printf("\t%llu", arch_ctrl->last);
            (void)printf("\t%llu", arch_ctrl->start_lsn);
            (void)printf("\t%llu", arch_ctrl->end_lsn);
            (void)printf("\t%-*s\n", (int)strlen(arch_ctrl->name), NULL_2_STR(arch_ctrl->name));
        }
        (void)printf("\n");
    }
}

void miner_desc_ctrl_core_attribute(database_ctrl_t *ctrl)
{
    char *str = (char *)malloc(CT_MAX_TIME_STRLEN);
    if (str == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)CT_MAX_TIME_STRLEN, "core init time");
        return;
    }
    str[0] = '\0';

    (void)printf("\tversion:              %u-%u-%u-%u\n", ctrl->core.version.main, ctrl->core.version.major,
        ctrl->core.version.revision, ctrl->core.version.inner);
    (void)printf("\tstartup times:        %u\n", ctrl->core.open_count);
    (void)printf("\tdbid times:           %u\n", ctrl->core.dbid);
    (void)printf("\tdatabase name:        %s\n", NULL_2_STR(ctrl->core.name));
    if (miner_time2str(ctrl->core.init_time, str, CT_MAX_TIME_STRLEN) != CT_SUCCESS) {
        (void)printf("\tinit time:            %s\n", "null");
    } else {
        (void)printf("\tinit time:            %s\n", NULL_2_STR(str));
    }
    CM_FREE_PTR(str);
    (void)printf("\tclustered:            %u\n", ctrl->core.clustered);
    (void)printf("\tnode_count:           %u\n", ctrl->core.node_count);
    (void)printf("\tmax_nodes:            %u\n", ctrl->core.max_nodes);
    (void)printf("\ttable$ entry:         %u-%u\n", ctrl->core.sys_table_entry.file, ctrl->core.sys_table_entry.page);
    (void)printf("\tix_table$1 entry:     %u-%u\n", ctrl->core.ix_sys_table1_entry.file, ctrl->core.ix_sys_table1_entry.page);
    (void)printf("\tix_table$2 entry:     %u-%u\n", ctrl->core.ix_sys_table2_entry.file, ctrl->core.ix_sys_table2_entry.page);
    (void)printf("\tcolumn$ entry:        %u-%u\n", ctrl->core.sys_column_entry.file, ctrl->core.sys_column_entry.page);
    (void)printf("\tix_column$ entry:     %u-%u\n", ctrl->core.ix_sys_column_entry.file, ctrl->core.ix_sys_column_entry.page);
    (void)printf("\tindex$ entry:         %u-%u\n", ctrl->core.sys_index_entry.file, ctrl->core.sys_index_entry.page);
    (void)printf("\tix_index$1 entry:     %u-%u\n", ctrl->core.ix_sys_index1_entry.file, ctrl->core.ix_sys_index1_entry.page);
    (void)printf("\tix_index$2 entry:     %u-%u\n", ctrl->core.ix_sys_index2_entry.file, ctrl->core.ix_sys_index2_entry.page);
    (void)printf("\tuser$_entry:          %u-%u\n", ctrl->core.sys_user_entry.file, ctrl->core.sys_user_entry.page);
    (void)printf("\tix_user$1 entry:      %u-%u\n", ctrl->core.ix_sys_user1_entry.file, ctrl->core.ix_sys_user1_entry.page);
    (void)printf("\tix_user$2 entry:      %u-%u\n", ctrl->core.ix_sys_user2_entry.file, ctrl->core.ix_sys_user2_entry.page);
}

void miner_desc_ctrl_core_log_attributes(database_ctrl_t *ctrl)
{
    (void)printf("\traft flush point:     scn(%llu)-lfn(%llu)-raft_index(%llu)\n",
        ctrl->core.raft_flush_point.scn, ctrl->core.raft_flush_point.lfn, ctrl->core.raft_flush_point.raft_index);

    (void)printf("\tbuild completed:      %u\n", (uint32)ctrl->core.build_completed);

    (void)printf("\tarchive mode:         %u\n", (uint32)ctrl->core.log_mode);

    (void)printf("\tarchive logs:         %llu", ctrl->core.archived_log[0].arch_log);
    for (uint32 i = 1; i < CT_MAX_ARCH_DEST; i++) {
        (void)printf("-%llu", ctrl->core.archived_log[i].arch_log);
    }
    (void)printf("\n");
}

void miner_desc_ctrl_core_space_attributes(database_ctrl_t *ctrl)
{
    (void)printf("\tdb_role:              %u\n", (uint32)ctrl->core.db_role);
    (void)printf("\tprotect mode:         %u\n", (uint32)ctrl->core.protect_mode);
    (void)printf("\tspace count:          %u\n", ctrl->core.space_count);
    (void)printf("\tdevice count:         %u\n", ctrl->core.device_count);
    (void)printf("\tpage size:            %u\n", ctrl->core.page_size);
    (void)printf("\tundo segments:        %u\n", ctrl->core.undo_segments);
    (void)printf("\tundo segments extend: %u\n", ctrl->core.undo_segments_extended);
    (void)printf("\treset logs:           %u-%u-%llu\n",
        ctrl->core.resetlogs.rst_id, ctrl->core.resetlogs.last_asn, ctrl->core.resetlogs.last_lfn);

    (void)printf("\tlogic replication mode:  %u\n", (uint32)ctrl->core.lrep_mode);
    (void)printf("\tmax column count:        %u\n", ctrl->core.max_column_count);
    (void)printf("\topen inconsistency:      %u\n", ctrl->core.open_inconsistency);
    (void)printf("\tcharacter set id:        %u\n", ctrl->core.charset_id);
    (void)printf("\tdouble write file_id:    %u\n", ctrl->core.dw_file_id);
    (void)printf("\tdouble write area pages: %u\n", ctrl->core.dw_area_pages);
    (void)printf("\tsystem space:            %u\n", ctrl->core.system_space);
    (void)printf("\tsysaux space:            %u\n", ctrl->core.sysaux_space);
    //    (void)printf("\tswap space:              %u\n", ctrl->core.swap_space);
    //    (void)printf("\tundo space:              %u\n", ctrl->core.undo_space);
    (void)printf("\tuser space:              %u\n", ctrl->core.user_space);
    (void)printf("\ttemp undo_space:         %u\n", ctrl->core.temp_undo_space);
    (void)printf("\ttemp space:              %u\n", ctrl->core.temp_space);
    (void)printf("\tsystem data version:     %u\n", ctrl->core.sysdata_version);
}

void miner_desc_ctrlfile(database_ctrl_t *ctrl)
{
    (void)printf("core information:\n");
    miner_desc_ctrl_core_attribute(ctrl);
    miner_desc_ctrl_core_log_attributes(ctrl);
    miner_desc_ctrl_core_space_attributes(ctrl);
    
    (void)printf("storage information:\n");
    miner_desc_ctrlfile_nodes_info(ctrl);
    miner_desc_ctrlfile_logfile_info(ctrl);
    miner_desc_ctrlfile_space_info(ctrl);
    miner_desc_ctrlfile_datafile_info(ctrl);
    miner_desc_ctrlfile_archlog_info(ctrl);
}

void print_bakcup_time_str(time_t time, const char *name)
{
    char str[CT_MAX_TIME_STRLEN] = { 0 };
    if (miner_time2str(time, str, CT_MAX_TIME_STRLEN) != CT_SUCCESS) {
        (void)printf("\t%s%s\n", name, "null");
    } else {
        (void)printf("\t%s%s\n", name, NULL_2_STR(str));
    }
}

void print_backup_information(bak_head_t *bak_head)
{
    printf("backupset information\n");
    printf("\tversion:              %u.%u.%u\n", bak_head->version.major_ver, bak_head->version.min_ver,
        bak_head->version.magic);
    printf("\ttag:                  %s\n", bak_head->attr.tag);
    printf("\tbase_lsn:             %llu\n", bak_head->attr.base_lsn);

    printf("\tbase_tag:             %s\n", bak_head->attr.base_tag);
    printf("\tbackup_type:          %u\n", bak_head->attr.backup_type);

    printf("\tlevel:                %u\n", bak_head->attr.level);
    printf("\tcompress:             %u\n", bak_head->attr.compress);
    printf("\thead_checksum:        %u\n", (uint32)bak_head->attr.head_checksum);
    printf("\tfile_checksum:        %u\n", (uint32)bak_head->attr.file_checksum);
    printf("\tcompress_func:        %s\n", bak_head->attr.compress_func);
    printf("\trcy_point:            [%llu-%u-%u] lfn %llu\n", (uint64)bak_head->ctrlinfo.rcy_point.rst_id,
        bak_head->ctrlinfo.rcy_point.asn, bak_head->ctrlinfo.rcy_point.block_id,
        (uint64)bak_head->ctrlinfo.rcy_point.lfn);
    printf("\tlrp_point:            [%llu-%u-%u] lfn %llu\n", (uint64)bak_head->ctrlinfo.lrp_point.rst_id,
        bak_head->ctrlinfo.lrp_point.asn, bak_head->ctrlinfo.lrp_point.block_id,
        (uint64)bak_head->ctrlinfo.lrp_point.lfn);
    printf("\tscn:                  %llu\n", (uint64)bak_head->ctrlinfo.scn);

    timeval_t time_val;
    KNL_SCN_TO_TIME(bak_head->ctrlinfo.scn, &time_val, bak_head->db_init_time);
    time_t scn_time = cm_date2time(cm_timeval2date(time_val));
    print_bakcup_time_str(scn_time, "scn_time:             ");
    printf("\tlsn:                  %llu\n", bak_head->ctrlinfo.lsn);
    printf("\tfile_count:           %u\n", bak_head->file_count);
    printf("\tdepend_num:           %u\n", bak_head->depend_num);
    time_t start_time = cm_date2time((date_t)bak_head->start_time);
    print_bakcup_time_str(start_time, "start_time:           ");
    time_t completion_time = cm_date2time((date_t)bak_head->completion_time);
    print_bakcup_time_str(completion_time, "completion_time:      ");
    printf("\tlog_fisrt_slot:       %u\n", bak_head->log_fisrt_slot);
    printf("\tdb_id:                %u\n", bak_head->db_id);
    print_bakcup_time_str(bak_head->db_init_time, "db_init_time:         ");
    printf("\tdb_role:              %u\n", bak_head->db_role);
    printf("\tdb_name:              %s\n", bak_head->db_name);
    printf("\tdb_version:           %s\n", bak_head->db_version);
    printf("\ttbox_version:         %u\n", bak_head->df_struc_version);
}

void print_backup_file_information(bak_head_t *bak_head, const char *read_buf, uint32 *offset)
{
    bak_file_t *bak_files = (bak_file_t *)(read_buf + (*offset));
    bak_file_t *file = NULL;
    /* If file is corrupted, bak_head->file_count may be too large. */
    bak_head->file_count = MIN(bak_head->file_count, BAK_MAX_FILE_NUM);
    *offset += bak_head->file_count * sizeof(bak_file_t);

    for (uint32 i = 0; i < bak_head->file_count; i++) {
        file = &bak_files[i];
        printf("backup file %u information\n", i);
        printf("\ttype:             %u\n", file->type);
        printf("\tid:               %u\n", file->id);
        printf("\tsec_id:           %u\n", file->sec_id);

        printf("\tsize:             %llu\n", file->size);
        printf("\tsec_start:        %llu\n", file->sec_start);
        printf("\tsec_end:          %llu\n", file->sec_end);
    }
}

void print_backup_dependency(bak_head_t *bak_head, const char *read_buf, uint32 offset)
{
    bak_dependence_t *bak_depends = (bak_dependence_t *)(read_buf + offset);
    bak_dependence_t *depend = NULL;
    /* If file is corrupted, bak_head->depend_num may be too large. */
    bak_head->depend_num = MIN(bak_head->depend_num, BAK_MAX_DEPEND_NUM);

    for (uint32 i = 0; i < bak_head->depend_num; i++) {
        depend = &bak_depends[i];
        printf("backup depentdence %u information\n", i);
        printf("\tdevice:           %u\n", depend->device);
        printf("\tpolicy:           %s\n", depend->policy);
        printf("\tfile_dest:        %s\n", depend->file_dest);
    }
}

void miner_desc_backup_info(bak_head_t *bak_head, const char *read_buf, uint32 offset)
{
    print_backup_information(bak_head);
    print_backup_file_information(bak_head, read_buf, &offset);
    print_backup_dependency(bak_head, read_buf, offset);
}
