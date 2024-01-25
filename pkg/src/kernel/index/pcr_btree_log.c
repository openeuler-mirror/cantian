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
 * pcr_btree_log.c
 *
 *
 * IDENTIFICATION
 * src/kernel/index/pcr_btree_log.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_index_module.h"
#include "pcr_btree_log.h"
#include "knl_context.h"
#include "index_common.h"

void rd_pcrb_new_itl(knl_session_t *session, log_entry_t *log)
{
    rd_pcrb_new_itl_t *redo;
    btree_page_t *page;
    pcr_itl_t *itl;
    uint8 itl_id;

    page = BTREE_CURR_PAGE(session);
    redo = (rd_pcrb_new_itl_t *)log->data;
    itl_id = pcrb_new_itl(session, page);
    itl = pcrb_get_itl(page, itl_id);

    tx_init_pcr_itl(session, itl, &redo->undo_rid, redo->xid, redo->ssn);
}

void rd_pcrb_reuse_itl(knl_session_t *session, log_entry_t *log)
{
    rd_pcrb_reuse_itl_t *redo;
    btree_page_t *page;
    pcr_itl_t *itl;

    page = BTREE_CURR_PAGE(session);
    redo = (rd_pcrb_reuse_itl_t *)log->data;
    itl = pcrb_get_itl(page, (uint8)redo->itl_id);

    pcrb_reuse_itl(session, page, itl, (uint8)redo->itl_id, redo->min_scn);
    tx_init_pcr_itl(session, itl, &redo->undo_rid, redo->xid, redo->ssn);
}

void rd_pcrb_clean_itl(knl_session_t *session, log_entry_t *log)
{
    rd_pcrb_clean_itl_t *redo;
    btree_page_t *page;
    pcr_itl_t *itl;

    page = BTREE_CURR_PAGE(session);
    redo = (rd_pcrb_clean_itl_t *)log->data;
    itl = pcrb_get_itl(page, redo->itl_id);

    if (page->scn < redo->scn) {
        page->scn = redo->scn;
    }

    itl->is_active = 0;
    itl->scn = redo->scn;
    itl->is_owscn = redo->is_owscn;
    itl->is_copied = redo->is_copied;
}

void rd_pcrb_insert(knl_session_t *session, log_entry_t *log)
{
    rd_pcrb_insert_t *redo;
    btree_page_t *page;
    pcr_itl_t *itl = NULL;
    pcrb_key_t *key;

    page = BTREE_CURR_PAGE(session);
    redo = (rd_pcrb_insert_t *)log->data;
    key = (pcrb_key_t *)(log->data + OFFSET_OF(rd_pcrb_insert_t, key));
    if (key->itl_id != CT_INVALID_ID8) {
        itl = pcrb_get_itl(page, key->itl_id);
        itl->undo_page = redo->undo_page;
        itl->undo_slot = redo->undo_slot;
        itl->ssn = redo->ssn;
    }

    pcrb_insert_into_page(session, page, key, redo);
}

void rd_pcrb_delete(knl_session_t *session, log_entry_t *log)
{
    rd_pcrb_delete_t *redo;
    btree_page_t *page;
    pcr_itl_t *itl = NULL;
    pcrb_dir_t *dir = NULL;
    pcrb_key_t *key;

    page = BTREE_CURR_PAGE(session);
    redo = (rd_pcrb_delete_t *)log->data;

    dir = pcrb_get_dir(page, redo->slot);
    key = PCRB_GET_KEY(page, dir);
    knl_panic_log(!key->is_deleted, "the key is deleted, panic info: page %u-%u type %u", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type);

    itl = pcrb_get_itl(page, redo->itl_id);
    itl->undo_page = redo->undo_page;
    itl->undo_slot = redo->undo_slot;
    itl->ssn = redo->ssn;

    key->itl_id = redo->itl_id;
    key->is_deleted = CT_TRUE;
}

void rd_pcrb_compact_page(knl_session_t *session, log_entry_t *log)
{
    btree_page_t *page;
    knl_scn_t min_scn;

    page = BTREE_CURR_PAGE(session);
    min_scn = *(knl_scn_t *)log->data;

    if (log->size > sizeof(knl_scn_t) + LOG_ENTRY_SIZE) {
        rd_btree_info_t btree_info;
        btree_info = *(rd_btree_info_t *)log->data;
        btree_rd_set_scn(session, btree_info, NULL);
    }
    pcrb_compact_page(session, page, min_scn);
}

void rd_pcrb_copy_itl(knl_session_t *session, log_entry_t *log)
{
    pcr_itl_t *itl = (pcr_itl_t *)log->data;

    (void)pcrb_copy_itl(session, itl, BTREE_CURR_PAGE(session));
}

void rd_pcrb_copy_key(knl_session_t *session, log_entry_t *log)
{
    pcrb_key_t *src_key;
    pcrb_dir_t *dir = NULL;
    pcrb_key_t *key;
    btree_page_t *page;
    errno_t err;

    page = BTREE_CURR_PAGE(session);
    src_key = (pcrb_key_t *)log->data;

    key = (pcrb_key_t *)((char *)page + page->free_begin);
    err = memcpy_sp(key, CT_KEY_BUF_SIZE, src_key, (size_t)src_key->size);
    knl_securec_check(err);

    dir = pcrb_get_dir(page, page->keys);
    *dir = page->free_begin;

    page->free_begin += (uint16)key->size;
    page->free_end -= sizeof(pcrb_dir_t);
    page->free_size -= ((uint16)key->size + sizeof(pcrb_dir_t));
    page->keys++;
}
void rd_pcrb_set_scn(knl_session_t *session, log_entry_t *log)
{
    btree_page_t *page;
    knl_scn_t scn;

    page = BTREE_CURR_PAGE(session);
    scn = *(knl_scn_t *)log->data;

    page->scn = scn;
}

void rd_pcrb_set_copy_itl(knl_session_t *session, log_entry_t *log)
{
    btree_page_t *page;
    uint8 *itl_map = NULL;
    pcr_itl_t *itl = NULL;
    uint8 i;

    page = BTREE_CURR_PAGE(session);
    itl_map = (uint8 *)log->data;

    for (i = 0; i < page->itls; i++) {
        if (itl_map[i] != CT_INVALID_ID8) {
            itl = pcrb_get_itl(page, i);
            itl->is_copied = 1;
        }
    }
}

void rd_pcrb_clean_keys(knl_session_t *session, log_entry_t *log)
{
    rd_btree_clean_keys_t *redo;
    btree_page_t *page;
    pcrb_dir_t *dir = NULL;
    pcrb_key_t *key = NULL;
    uint16 i;

    page = BTREE_CURR_PAGE(session);
    redo = (rd_btree_clean_keys_t *)log->data;

    for (i = redo->keys; i < page->keys; i++) {
        dir = pcrb_get_dir(page, i);
        key = PCRB_GET_KEY(page, dir);
        if (!key->is_cleaned) {
            key->is_cleaned = (uint16)CT_TRUE;
        }
    }

    dir = pcrb_get_dir(page, redo->keys - 1);

    page->keys = redo->keys;
    page->free_size = redo->free_size;
    page->free_end = (uint16)((char *)dir - (char *)page);
}

void rd_pcrb_undo_itl(knl_session_t *session, log_entry_t *log)
{
    btree_page_t *page;
    pcr_itl_t *itl;
    pcr_itl_t *redo;
    uint8 itl_id;

    page = BTREE_CURR_PAGE(session);
    redo = (pcr_itl_t *)log->data;
    itl_id = *(uint8 *)(log->data + sizeof(pcr_itl_t));

    itl = pcrb_get_itl(page, itl_id);
    *itl = *redo;
}

void rd_pcrb_undo_insert(knl_session_t *session, log_entry_t *log)
{
    btree_page_t *page;
    pcrb_dir_t *dir = NULL;
    pcrb_key_t *key;
    pcrb_key_t *ud_key;
    pcr_itl_t *itl = NULL;
    rd_pcrb_undo_t *redo;

    page = BTREE_CURR_PAGE(session);
    redo = (rd_pcrb_undo_t *)log->data;
    ud_key = (pcrb_key_t *)(log->data + sizeof(rd_pcrb_undo_t));

    dir = pcrb_get_dir(page, redo->slot);
    key = PCRB_GET_KEY(page, dir);
    knl_panic_log(key->itl_id != CT_INVALID_ID8, "key's itl_id is invalid, panic info: page %u-%u type %u itl_id %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, key->itl_id);
    knl_panic_log(!key->is_deleted, "the key is deleted, panic info: page %u-%u type %u", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type);

    itl = pcrb_get_itl(page, key->itl_id);

    pcrb_copy_data(key, ud_key);
    key->is_deleted = 1;

    if (redo->is_xfirst) {
        key->itl_id = CT_INVALID_ID8;
    }

    itl->ssn = redo->ssn;
    itl->undo_page = redo->undo_page;
    itl->undo_slot = redo->undo_slot;
}

void rd_pcrb_undo_delete(knl_session_t *session, log_entry_t *log)
{
    btree_page_t *page;
    pcrb_dir_t *dir = NULL;
    pcrb_key_t *key;
    pcr_itl_t *itl = NULL;
    rd_pcrb_undo_t *redo;

    page = BTREE_CURR_PAGE(session);
    redo = (rd_pcrb_undo_t *)log->data;

    dir = pcrb_get_dir(page, redo->slot);
    key = PCRB_GET_KEY(page, dir);
    knl_panic_log(key->itl_id != CT_INVALID_ID8, "key's itl_id is invalid, panic info: page %u-%u type %u itl_id %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, key->itl_id);
    knl_panic_log(key->is_deleted, "the key is not deleted, panic info: page %u-%u type %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);

    itl = pcrb_get_itl(page, key->itl_id);

    key->is_deleted = 0;

    if (redo->is_xfirst) {
        key->itl_id = CT_INVALID_ID8;
    }

    itl->ssn = redo->ssn;
    itl->undo_page = redo->undo_page;
    itl->undo_slot = redo->undo_slot;
}

void rd_pcrb_clean_key(knl_session_t *session, log_entry_t *log)
{
    uint16 redo_dir = *(uint16 *)log->data;
    btree_page_t *page = BTREE_CURR_PAGE(session);

    pcrb_clean_key(session, page, redo_dir);
}

void print_pcrb_new_itl(log_entry_t *log)
{
    rd_pcrb_new_itl_t *redo = (rd_pcrb_new_itl_t *)log->data;

    printf("ssn %u, xid %u-%u-%u, undo_rowid %u-%u-%u\n", redo->ssn, (uint32)redo->xid.xmap.seg_id,
           (uint32)redo->xid.xmap.slot, redo->xid.xnum,
           (uint32)redo->undo_rid.page_id.file, (uint32)redo->undo_rid.page_id.page, (uint32)redo->undo_rid.slot);
}

void print_pcrb_reuse_itl(log_entry_t *log)
{
    rd_pcrb_reuse_itl_t *redo = (rd_pcrb_reuse_itl_t *)log->data;

    printf("min_scn %llu, ssn %u, xid %u-%u-%u, undo_rowid %u-%u-%u\n", (uint64)redo->min_scn, redo->ssn,
           (uint32)redo->xid.xmap.seg_id, (uint32)redo->xid.xmap.slot,
           redo->xid.xnum, (uint32)redo->undo_rid.page_id.file,
           (uint32)redo->undo_rid.page_id.page, (uint32)redo->undo_rid.slot);
}

void print_pcrb_clean_itl(log_entry_t *log)
{
    rd_pcrb_clean_itl_t *redo = (rd_pcrb_clean_itl_t *)log->data;

    printf("itl_id %u, scn %llu, is_owscn %u, is_copied %u\n", (uint32)redo->itl_id, (uint64)redo->scn,
           (uint32)redo->is_owscn, (uint32)redo->is_copied);
}

void print_pcrb_insert(log_entry_t *log)
{
    rd_pcrb_insert_t *redo = (rd_pcrb_insert_t *)log->data;
    pcrb_key_t *key = (pcrb_key_t *)redo->key;

    printf("ssn %u, undo_rowid %u-%u-%u, slot %u, is_reuse %u ", redo->ssn, (uint32)redo->undo_page.file,
           (uint32)redo->undo_page.page, (uint32)redo->undo_slot, (uint32)redo->slot, (uint32)redo->is_reuse);
    printf("key: size %u, itl_id %u, deleted/infinite/cleaned %u/%u/%u, ",
           (uint32)key->size, key->itl_id, (uint32)key->is_deleted, (uint32)key->is_infinite, (uint32)key->is_cleaned);
    printf("heap_page %u-%u, heap_slot %u\n",
           (uint32)key->rowid.file, (uint32)key->rowid.page, (uint32)key->rowid.slot);
}

void print_pcrb_delete(log_entry_t *log)
{
    rd_pcrb_delete_t *redo = (rd_pcrb_delete_t *)log->data;

    printf("slot %u, ssn %u, itl_id %u, undo_page %u-%u, undo_slot %u\n", (uint32)redo->slot, redo->ssn,
           (uint32)redo->itl_id, (uint32)redo->undo_page.file, (uint32)redo->undo_page.page, (uint32)redo->undo_slot);
}

void print_pcrb_compact_page(log_entry_t *log)
{
    knl_scn_t min_scn = *(knl_scn_t *)log->data;

    printf("min_scn %llu \n", (uint64)min_scn);
}

void print_pcrb_copy_itl(log_entry_t *log)
{
    pcr_itl_t *redo = (pcr_itl_t *)log->data;

    printf("scn %llu, is_owscn %u, xid: %u-%u-%u, undo_page %u-%u, undo_slot %u\n", (uint64)redo->scn,
           (uint32)redo->is_owscn,
           (uint32)redo->xid.xmap.seg_id, (uint32)redo->xid.xmap.slot, redo->xid.xnum,
           (uint32)redo->undo_page.file, (uint32)redo->undo_page.page, (uint32)redo->undo_slot);
}

void print_pcrb_copy_key(log_entry_t *log)
{
    pcrb_key_t *key = (pcrb_key_t *)log->data;

    printf("key: size %u, itl_id %u, deleted/infinite/cleaned %u/%u/%u, ",
           (uint32)key->size, key->itl_id, (uint32)key->is_deleted, (uint32)key->is_infinite, (uint32)key->is_cleaned);
    printf("heap_page %u-%u, heap_slot %u\n",
           (uint32)key->rowid.file, (uint32)key->rowid.page, (uint32)key->rowid.slot);
}

void print_pcrb_set_scn(log_entry_t *log)
{
    knl_scn_t scn = *(knl_scn_t *)log->data;

    printf("scn %llu\n", (uint64)scn);
}

void print_pcrb_set_copy_itl(log_entry_t *log)
{
    uint8 itl_map = *(uint8 *)log->data;
    printf("itl_map %u\n", (uint32)itl_map);
}

void print_pcrb_clean_keys(log_entry_t *log)
{
    rd_btree_clean_keys_t *redo = (rd_btree_clean_keys_t *)log->data;

    printf("keys %u, free_size %u\n", redo->keys, redo->free_size);
}

void print_pcrb_undo_itl(log_entry_t *log)
{
    pcr_itl_t *redo = (pcr_itl_t *)log->data;
    uint8 itl_id = *(uint8 *)(log->data + sizeof(pcr_itl_t));

    printf("itl_id %u, scn %llu, is_owscn %u, xid: %u-%u-%u, undo_page %u-%u, undo_slot %u\n", itl_id, redo->scn,
           (uint32)redo->is_owscn,
           (uint32)redo->xid.xmap.seg_id, (uint32)redo->xid.xmap.slot, redo->xid.xnum,
           (uint32)redo->undo_page.file, (uint32)redo->undo_page.page, (uint32)redo->undo_slot);
}

void print_pcrb_undo_insert(log_entry_t *log)
{
    rd_pcrb_undo_t *redo = (rd_pcrb_undo_t *)log->data;
    pcrb_key_t *key = (pcrb_key_t *)(log->data + sizeof(rd_pcrb_undo_t));

    printf("slot %u, ssn %u, undo_page: %u-%u, undo_slot %u, is_xfirst %u\n",
           (uint32)redo->slot, redo->ssn, (uint32)redo->undo_page.file, (uint32)redo->undo_page.page,
           (uint16)redo->undo_slot, (uint16)redo->is_xfirst);
    printf("key: size %u, itl_id %u, deleted/infinite/cleaned %u/%u/%u, ",
           (uint32)key->size, key->itl_id, (uint32)key->is_deleted, (uint32)key->is_infinite,
           (uint32)key->is_cleaned);
    printf("heap_page %u-%u, heap_slot %u\n",
           (uint32)key->rowid.file, (uint32)key->rowid.page, (uint32)key->rowid.slot);
}

void print_pcrb_undo_delete(log_entry_t *log)
{
    rd_pcrb_undo_t *redo = (rd_pcrb_undo_t *)log->data;
    pcrb_key_t *key = (pcrb_key_t *)(log->data + sizeof(rd_pcrb_undo_t));

    printf("slot %u, ssn %u, undo_page: %u-%u, undo_slot %u, is_xfirst %u\n",
           (uint32)redo->slot, redo->ssn, (uint32)redo->undo_page.file, (uint32)redo->undo_page.page,
           (uint16)redo->undo_slot, (uint16)redo->is_xfirst);
    printf("key: size %u, itl_id %u, deleted/infinite/cleaned %u/%u/%u, ",
           (uint32)key->size, key->itl_id, (uint32)key->is_deleted, (uint32)key->is_infinite,
           (uint32)key->is_cleaned);
    printf("heap_page %u-%u, heap_slot %u\n",
           (uint32)key->rowid.file, (uint32)key->rowid.page, (uint32)key->rowid.slot);
}

void print_pcrb_clean_key(log_entry_t *log)
{
    uint16 dir_id = *(uint16 *)log->data;

    printf("slot %u\n", dir_id);
}

