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
 * knl_heap_log.c
 *
 *
 * IDENTIFICATION
 * src/kernel/table/knl_heap_log.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_heap_log.h"
#include "knl_context.h"

void rd_heap_new_itl(knl_session_t *session, log_entry_t *log)
{
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    xid_t xid = *(xid_t *)log->data;
    uint8 itl_id = heap_new_itl(session, page);
    itl_t *itl = heap_get_itl(page, itl_id);

    tx_init_itl(session, itl, xid);
}

void print_heap_new_itl(log_entry_t *log)
{
    xid_t xid = *(xid_t *)log->data;
    printf("xmap %u-%u, xnum %u\n", (uint32)xid.xmap.seg_id, (uint32)xid.xmap.slot, xid.xnum);
}

void rd_heap_reuse_itl(knl_session_t *session, log_entry_t *log)
{
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    rd_heap_alloc_itl_t *rd = (rd_heap_alloc_itl_t *)log->data;
    itl_t *itl = heap_get_itl(page, rd->itl_id);

    heap_reuse_itl(session, page, itl, rd->itl_id);
    tx_init_itl(session, itl, rd->xid);
}

void print_heap_reuse_itl(log_entry_t *log)
{
    rd_heap_alloc_itl_t *rd = (rd_heap_alloc_itl_t *)log->data;
    printf("xmap %u-%u, xnum %u, itl_id %u\n",
           (uint32)rd->xid.xmap.seg_id, (uint32)rd->xid.xmap.slot, rd->xid.xnum, (uint32)rd->itl_id);
}

void rd_heap_clean_itl(knl_session_t *session, log_entry_t *log)
{
    rd_heap_clean_itl_t *rd = (rd_heap_clean_itl_t *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    itl_t *itl = NULL;

    if (page->itls == 0) {
        return;
    }
    itl = heap_get_itl(page, rd->itl_id);
    // free_size and itl->fsc are both less than DEFAULT_PAGE_SIZE(8192), so the sum is less than max value of uint16
    page->free_size += itl->fsc;
    itl->fsc = 0;
    itl->is_active = 0;
    itl->scn = rd->scn;
    itl->is_owscn = rd->is_owscn;
    itl->xid.value = GS_INVALID_ID64;
}

void print_heap_clean_itl(log_entry_t *log)
{
    rd_heap_clean_itl_t *rd = (rd_heap_clean_itl_t *)log->data;
    printf("itl_id %u, scn %llu, is_owscn %u\n", (uint32)rd->itl_id, rd->scn, (uint32)rd->is_owscn);
}

void rd_heap_lock_row(knl_session_t *session, log_entry_t *log)
{
    rd_heap_lock_row_t *rd = (rd_heap_lock_row_t *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    row_dir_t *dir = heap_get_dir(page, rd->slot);
    row_head_t *row = HEAP_GET_ROW(page, dir);

    dir->scn = rd->scn;
    dir->is_owscn = rd->is_owscn;
    ROW_SET_ITL_ID(row, rd->itl_id);
    row->is_changed = 0;
}

void print_heap_lock_row(log_entry_t *log)
{
    rd_heap_lock_row_t *rd = (rd_heap_lock_row_t *)log->data;
    printf("slot %u, scn %llu, is_owscn %u, itl_id %u\n",
           (uint32)rd->slot, rd->scn, (uint32)rd->itl_id, (uint32)rd->is_owscn);
}

void rd_heap_insert(knl_session_t *session, log_entry_t *log)
{
    rd_heap_insert_t *redo = (rd_heap_insert_t *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    undo_data_t undo;
    uint16 slot;

    heap_insert_into_page(session, page, (row_head_t *)redo->data, &undo, redo, &slot);
}

void print_heap_insert(log_entry_t *log)
{
    rd_heap_insert_t *redo = (rd_heap_insert_t *)log->data;
    row_head_t *row = (row_head_t *)redo->data;
    printf("ssn %u, undo_page %u-%u, undo_slot %u, itl_id %u ",
           redo->ssn, (uint32)redo->undo_page.file, (uint32)redo->undo_page.page,
           (uint32)redo->undo_slot, (uint32)ROW_ITL_ID(row));
    printf("size %u, cols %u, deleted/link/migr/changed/self_chg %u/%u/%u/%u/%u\n",
           (uint32)row->size, (uint32)ROW_COLUMN_COUNT(row), (uint32)row->is_deleted,
           (uint32)row->is_link, (uint32)row->is_migr, (uint32)row->is_changed, (uint32)row->self_chg);
}

void rd_heap_change_dir(knl_session_t *session, log_entry_t *log)
{
    rd_heap_change_dir_t *redo = (rd_heap_change_dir_t *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    row_dir_t *dir = heap_get_dir(page, redo->slot);
    row_head_t *row = HEAP_GET_ROW(page, dir);

    dir->undo_page = redo->undo_page;
    dir->undo_slot = redo->undo_slot;
    dir->scn = redo->scn;
    dir->is_owscn = 0;
    row->is_changed = 1;
}

void print_heap_change_dir(log_entry_t *log)
{
    rd_heap_change_dir_t *redo = (rd_heap_change_dir_t *)log->data;
    printf("slot %u scn %llu undo_page %u-%u undo_slot %u\n", (uint32)redo->slot, redo->scn,
           (uint32)redo->undo_page.file, (uint32)redo->undo_page.page, (uint32)redo->undo_slot);
}

void rd_heap_update_inplace(knl_session_t *session, log_entry_t *log)
{
    rd_heap_update_inplace_t *rd = (rd_heap_update_inplace_t *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    row_dir_t *dir = heap_get_dir(page, rd->slot);
    row_head_t *row = HEAP_GET_ROW(page, dir);
    knl_update_info_t info;
    uint16 *offsets = NULL;
    uint16 *lens = NULL;
    uint16 col_size;
    errno_t ret;

    CM_SAVE_STACK(session->stack);
    CM_PUSH_UPDATE_INFO(session, info);

    info.count = rd->count;
    info.data = log->data + OFFSET_OF(rd_heap_update_inplace_t, columns) + CM_ALIGN4(sizeof(uint16) * rd->count);
    col_size = sizeof(uint16) * rd->count; // the max value of rd->count is GS_MAX_COLUMNS(4096)
    ret = memcpy_sp(info.columns, (session)->kernel->attr.max_column_count * sizeof(uint16), rd->columns, col_size);
    knl_securec_check(ret);

    /* allocate memory of offsets and lens from session stack to decode row */
    offsets = (uint16 *)cm_push(session->stack, sizeof(uint16) * session->kernel->attr.max_column_count * 2);
    lens = (uint16 *)((char *)offsets + sizeof(uint16) * session->kernel->attr.max_column_count);
    cm_decode_row((char *)row, offsets, lens, NULL);
    cm_decode_row(info.data, info.offsets, info.lens, NULL);

    heap_update_inplace(session, offsets, lens, &info, row);

    CM_RESTORE_STACK(session->stack);
}

void print_heap_update_inplace(log_entry_t *log)
{
    rd_heap_update_inplace_t *rd = (rd_heap_update_inplace_t *)log->data;
    uint16 *columns = (uint16 *)rd->columns;
    uint16 i;

    printf("slot %u, count %u, columns %u", (uint32)rd->slot, (uint32)rd->count, (uint32)rd->columns[0]);
    for (i = 1; i < rd->count; i++) {
        printf(", %u", (uint32)columns[i]);
    }
    printf("\n");
}

void rd_heap_update_inpage(knl_session_t *session, log_entry_t *log)
{
    rd_heap_update_inpage_t *rd = (rd_heap_update_inpage_t *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    row_dir_t *dir = heap_get_dir(page, rd->slot);
    row_head_t *row = HEAP_GET_ROW(page, dir);
    row_head_t *copy_row = NULL;
    heap_update_assist_t ua;
    knl_update_info_t info;
    uint16 *offsets = NULL;
    uint16 *lens = NULL;
    uint16 data_size, col_size;
    errno_t ret;

    CM_SAVE_STACK(session->stack);
    copy_row = (row_head_t *)cm_push(session->stack, HEAP_MAX_MIGR_ROW_SIZE(session));
    CM_PUSH_UPDATE_INFO(session, info);

    info.count = rd->count;
    ua.new_cols = rd->new_cols;
    ua.inc_size = rd->inc_size;
    // row->size and inc_size is less than DEFAULT_PAGE_SIZE(8192), so the sum is less than max value(65535) of uint16
    ua.new_size = row->size + ua.inc_size;
    ua.info = &info;
    info.data = log->data + HEAP_UPDATE_INPAGE_SIZE(rd->count);
    col_size = sizeof(uint16) * rd->count;                      // the max value of rd->count is GS_MAX_COLUMNS(4096)
    ret = memcpy_sp(info.columns, (session)->kernel->attr.max_column_count * sizeof(uint16), rd->columns, col_size);
    knl_securec_check(ret);
    ret = memcpy_sp(copy_row, HEAP_MAX_MIGR_ROW_SIZE(session), row, row->size);
    knl_securec_check(ret);

    /** max column count of table is GS_MAX_COLUMNS(4096) */
    offsets = (uint16 *)cm_push(session->stack, sizeof(uint16 *) * session->kernel->attr.max_column_count * 2);
    lens = (uint16 *)((char *)offsets + sizeof(uint16 *) * session->kernel->attr.max_column_count);
    cm_decode_row((char *)copy_row, offsets, lens, &data_size);
    cm_decode_row(info.data, info.offsets, info.lens, NULL);
    heap_update_inpage(session, copy_row, offsets, lens, &ua, page, rd->slot);
    CM_RESTORE_STACK(session->stack);
}

void print_heap_update_inpage(log_entry_t *log)
{
    rd_heap_update_inpage_t *rd = (rd_heap_update_inpage_t *)log->data;
    uint16 *columns = (uint16 *)rd->columns;
    uint16 i;

    printf("slot %u, count %u, cols %u, inc_size %d, columns %u",
           (uint32)rd->slot, (uint32)rd->count, (uint32)rd->new_cols, (int32)rd->inc_size, (uint32)columns[0]);
    for (i = 1; i < rd->count; i++) {
        printf(", %u", (uint32)columns[i]);
    }
    printf("\n");
}

void rd_heap_insert_migr(knl_session_t *session, log_entry_t *log)
{
    rd_heap_insert_t *redo = (rd_heap_insert_t *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    uint16 slot;

    heap_insert_into_page_migr(session, page, (row_head_t *)redo->data, redo, &slot);
}

void print_heap_insert_migr(log_entry_t *log)
{
    rd_heap_insert_t *redo = (rd_heap_insert_t *)log->data;
    row_head_t *row = (row_head_t *)redo->data;
    printf("ssn %u, undo_page %u-%u, undo_slot %u, itl_id %u ",
           redo->ssn, (uint32)redo->undo_page.file, (uint32)redo->undo_page.page,
           (uint32)redo->undo_slot, (uint32)ROW_ITL_ID(row));
    printf("size %u, cols %u, deleted/link/migr/changed/self_chg %u/%u/%u/%u/%u\n",
           (uint32)row->size, (uint32)ROW_COLUMN_COUNT(row), (uint32)row->is_deleted,
           (uint32)row->is_link, (uint32)row->is_migr, (uint32)row->is_changed, (uint32)row->self_chg);
}

void rd_heap_set_link(knl_session_t *session, log_entry_t *log)
{
    rd_set_link_t *redo = (rd_set_link_t *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    row_dir_t *dir = heap_get_dir(page, redo->slot);
    row_head_t *row = HEAP_GET_ROW(page, dir);
    rowid_t *link_rid = NULL;

    if (!row->is_link && !row->is_migr) {
        row->is_link = 1;
        // free_size and row size is less than DEFAULT_PAGE_SIZE(8192),
        // so the sum is less than max value(65535) of uint16
        page->free_size += row->size - HEAP_MIN_ROW_SIZE;
    }

    link_rid = (rowid_t *)(HEAP_LOC_LINK_RID(row));
    *link_rid = redo->link_rid;
}

void print_heap_set_link(log_entry_t *log)
{
    rd_set_link_t *redo = (rd_set_link_t *)log->data;
    printf("slot %u, next rowid %u-%u-%u\n",
           redo->slot, (uint32)redo->link_rid.file, (uint32)redo->link_rid.page, (uint32)redo->link_rid.slot);
}

void rd_heap_remove_migr(knl_session_t *session, log_entry_t *log)
{
    uint16 slot = *(uint16 *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    row_dir_t *dir = heap_get_dir(page, slot);
    row_head_t *row = HEAP_GET_ROW(page, dir);

    row->is_deleted = 1;
    dir->is_free = 1;
    page->rows--;
    dir->next_slot = page->first_free_dir;
    page->first_free_dir = slot;
    // free_size and row size is less than DEFAULT_PAGE_SIZE(8192), so the sum is less than max value(65535) of uint16
    page->free_size += row->size;
}

void print_heap_remove_migr(log_entry_t *log)
{
    uint16 slot = *(uint16 *)log->data;
    printf("slot %u \n", slot);
}

void rd_heap_delete(knl_session_t *session, log_entry_t *log)
{
    rd_heap_delete_t *redo = (rd_heap_delete_t *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    row_dir_t *dir = heap_get_dir(page, redo->slot);
    row_head_t *row = HEAP_GET_ROW(page, dir);
    itl_t *itl = heap_get_itl(page, ROW_ITL_ID(row));

    dir->undo_page = redo->undo_page;

    /*  redo->undo_slot is from dir->undo_slot */
    dir->undo_slot = redo->undo_slot;
    dir->scn = redo->ssn;
    dir->is_owscn = 0;

    row->is_deleted = 1;
    row->is_changed = 1;
    page->rows--;

    // free_size and itl->fsc are both less than DEFAULT_PAGE_SIZE(8192), so the sum is less than max value of uint16
    if (row->is_link) {
        itl->fsc += HEAP_MIN_ROW_SIZE;
    } else {
        itl->fsc += row->size;
    }
}

void print_heap_delete(log_entry_t *log)
{
    rd_heap_delete_t *redo = (rd_heap_delete_t *)log->data;
    printf("slot %u, ssn %u, undo_page: %u-%u, undo_slot %u \n",
           (uint32)redo->slot, redo->ssn, (uint32)redo->undo_page.file,
           (uint32)redo->undo_page.page, (uint32)redo->undo_slot);
}

void rd_heap_delete_link(knl_session_t *session, log_entry_t *log)
{
    uint16 slot = *(uint16 *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    row_dir_t *dir = heap_get_dir(page, slot);
    row_head_t *row = HEAP_GET_ROW(page, dir);
    itl_t *itl = heap_get_itl(page, ROW_ITL_ID(row));

    row->is_deleted = 1;
    row->is_changed = 1;
    page->rows--;

    /* row size and itl->fsc are both less than DEFAULT_PAGE_SIZE(8192), so the sum is less than max value of uint16 */
    itl->fsc += row->size;
}

void print_heap_delete_link(log_entry_t *log)
{
    uint16 slot = *(uint16 *)log->data;
    printf("slot %u\n", (uint32)slot);
}

void rd_heap_undo_insert(knl_session_t *session, log_entry_t *log)
{
    rd_heap_undo_t *redo = (rd_heap_undo_t *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    row_dir_t *dir = heap_get_dir(page, redo->slot);
    row_head_t *row = HEAP_GET_ROW(page, dir);

    if (page->free_begin == dir->offset + row->size) {
        page->free_begin = dir->offset;
    }

    /* row size and free_size are both less than DEFAULT_PAGE_SIZE(8192), so the sum is less than max value of uint16 */
    if (row->is_link) {
        page->free_size += HEAP_MIN_ROW_SIZE;
    } else {
        page->free_size += row->size;
    }

    page->rows--;

    dir->scn = redo->scn;
    dir->is_owscn = redo->is_owscn;
    dir->undo_page = redo->undo_page;
    /* redo->undo_slot is from dir->undo_slot */
    dir->undo_slot = redo->undo_slot;

    ROW_SET_ITL_ID(row, GS_INVALID_ID8);
    row->is_deleted = 1;
    dir->is_free = 1;
    dir->next_slot = page->first_free_dir;
    page->first_free_dir = redo->slot;
}

void print_heap_undo_insert(log_entry_t *log)
{
    rd_heap_undo_t *redo = (rd_heap_undo_t *)log->data;
    printf("slot %u, scn %llu, is_owscn %u, undo_page: %u-%u, undo_slot %u\n", (uint32)redo->slot, redo->scn,
           (uint32)redo->is_owscn, (uint32)redo->undo_page.file, (uint32)redo->undo_page.page, (uint32)redo->undo_slot);
}

void rd_heap_undo_change_dir(knl_session_t *session, log_entry_t *log)
{
    rd_heap_undo_t *redo = (rd_heap_undo_t *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    row_dir_t *dir = heap_get_dir(page, redo->slot);
    row_head_t *row = HEAP_GET_ROW(page, dir);

    dir->scn = redo->scn;
    dir->is_owscn = redo->is_owscn;
    dir->undo_page = redo->undo_page;
    dir->undo_slot = redo->undo_slot;
    if (redo->is_xfirst) {
        ROW_SET_ITL_ID(row, GS_INVALID_ID8);
    }
}

void print_heap_undo_change_dir(log_entry_t *log)
{
    rd_heap_undo_t *redo = (rd_heap_undo_t *)log->data;
    printf("slot %u, is_xfirst %u, scn %llu, is_owscn %u, undo_page: %u-%u, undo_slot %u\n",
           (uint32)redo->slot, (uint32)redo->is_xfirst, redo->scn, (uint32)redo->is_owscn,
           (uint32)redo->undo_page.file, (uint32)redo->undo_page.page, (uint32)redo->undo_slot);
}

void rd_heap_undo_update(knl_session_t *session, log_entry_t *log)
{
    uint16 slot = *(uint16 *)log->data;
    heap_undo_update_info_t *undo_info = (heap_undo_update_info_t *)(log->data + CM_ALIGN4(sizeof(uint16)));
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    row_dir_t *dir = heap_get_dir(page, slot);
    row_head_t *row = HEAP_GET_ROW(page, dir);
    knl_update_info_t info;

    CM_SAVE_STACK(session->stack);
    CM_PUSH_UPDATE_INFO(session, info);

    heap_revert_update(session, undo_info, row, info.offsets, info.lens);

    CM_RESTORE_STACK(session->stack);
}

void print_heap_undo_update(log_entry_t *log)
{
    uint16 slot = *(uint16 *)log->data;
    heap_undo_update_info_t *undo_info = (heap_undo_update_info_t *)(log->data + CM_ALIGN4(sizeof(uint16)));
    uint16 *columns = (uint16 *)undo_info->columns;
    uint16 i;

    printf("slot %u, count %u, columns %u", (uint32)slot, (uint32)undo_info->count, (uint32)undo_info->columns[0]);
    for (i = 1; i < undo_info->count; i++) {
        printf(", %u", (uint32)columns[i]);
    }
    printf("\n");
}

void rd_heap_undo_update_full(knl_session_t *session, log_entry_t *log)
{
    uint16 slot = *(uint16 *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    row_head_t *ud_row = (row_head_t *)(log->data + CM_ALIGN4(sizeof(uint16)));
    row_dir_t *dir = heap_get_dir(page, slot);
    row_head_t *row = HEAP_GET_ROW(page, dir);

    heap_undo_update_full(session, row, ud_row, dir->offset);
}

void print_heap_undo_update_full(log_entry_t *log)
{
    uint16 slot = *(uint16 *)log->data;
    row_head_t *ud_row = (row_head_t *)(log->data + CM_ALIGN4(sizeof(uint16)));
    printf("slot %u, itl_id %u ", (uint32)slot, (uint32)ROW_ITL_ID(ud_row));
    printf("row: size %u, cols %u, deleted/link/migr/changed/self_chg %u/%u/%u/%u/%u\n",
           (uint32)ud_row->size, (uint32)ROW_COLUMN_COUNT(ud_row), (uint32)ud_row->is_deleted,
           (uint32)ud_row->is_link, (uint32)ud_row->is_migr, (uint32)ud_row->is_changed, (uint32)ud_row->self_chg);
}

void rd_heap_undo_delete(knl_session_t *session, log_entry_t *log)
{
    rd_heap_undo_t *redo = (rd_heap_undo_t *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    row_dir_t *dir = heap_get_dir(page, redo->slot);
    row_head_t *row = HEAP_GET_ROW(page, dir);
    itl_t *itl = heap_get_itl(page, ROW_ITL_ID(row));

    dir->scn = redo->scn;
    dir->is_owscn = redo->is_owscn;
    dir->undo_page = redo->undo_page;
    // max undo page size is 32K, so max slot count for undo page is 744, less than uint16:15
    dir->undo_slot = redo->undo_slot;

    if (redo->is_xfirst) {
        ROW_SET_ITL_ID(row, GS_INVALID_ID8);
    }
    row->is_deleted = 0;
    page->rows++;
    /* itl->fsc is larger than the releated row's size */
    if (row->is_link) {
        itl->fsc -= HEAP_MIN_ROW_SIZE;
    } else {
        itl->fsc -= row->size;
    }
}

void print_heap_undo_delete(log_entry_t *log)
{
    rd_heap_undo_t *redo = (rd_heap_undo_t *)log->data;
    printf("slot %u, is_xfirst %u, scn %llu, is_owscn %u, undo_page: %u-%u, undo_slot %u\n",
           (uint32)redo->slot, (uint32)redo->is_xfirst, redo->scn, (uint32)redo->is_owscn,
           (uint32)redo->undo_page.file, (uint32)redo->undo_page.page, (uint32)redo->undo_slot);
}

void rd_heap_undo_delete_link(knl_session_t *session, log_entry_t *log)
{
    uint16 slot = *(uint16 *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    row_dir_t *dir = heap_get_dir(page, slot);
    row_head_t *row = HEAP_GET_ROW(page, dir);
    itl_t *itl = heap_get_itl(page, ROW_ITL_ID(row));
    /* itl->fsc is larger than the releated row's size */
    itl->fsc -= row->size;
    row->is_deleted = 0;
    page->rows++;
}

void print_heap_undo_delete_link(log_entry_t *log)
{
    uint16 slot = *(uint16 *)log->data;
    printf("slot %u\n", (uint32)slot);
}

void rd_heap_init_itls(knl_session_t *session, log_entry_t *log)
{
    uint32 itls = *(uint32 *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);

    page->itls = (uint8)itls;

    /* free_end and free size is larger than itls * sizeof(itl_t) for this action */
    page->free_end -= (uint16)(itls * sizeof(itl_t));
    page->free_size -= (uint16)(itls * sizeof(itl_t));
}

void print_heap_init_itls(log_entry_t *log)
{
    uint32 itls = *(uint32 *)log->data;
    printf("itls %u\n", itls);
}

void rd_heap_undo_insert_link(knl_session_t *session, log_entry_t *log)
{
    uint16 slot = *(uint16 *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    row_dir_t *dir = heap_get_dir(page, slot);
    row_head_t *row = HEAP_GET_ROW(page, dir);

    dir->is_free = 1;
    dir->next_slot = page->first_free_dir;
    // free_size and row size are both less than DEFAULT_PAGE_SIZE(8192),
    // so the sum is less than max value(65535) of uint16
    page->free_size += row->size;
    page->rows--;
    page->first_free_dir = (uint16)slot;
}

void print_heap_undo_insert_link(log_entry_t *log)
{
    uint16 slot = *(uint16 *)log->data;
    printf("slot %u\n", (uint32)slot);
}

void rd_heap_delete_migr(knl_session_t *session, log_entry_t *log)
{
    rd_heap_delete_t *redo = (rd_heap_delete_t *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    row_dir_t *dir = heap_get_dir(page, redo->slot);
    row_head_t *row = HEAP_GET_ROW(page, dir);
    itl_t *itl = NULL;

    row->is_deleted = 1;
    row->is_changed = 1;
    page->rows--;

    itl = heap_get_itl(page, ROW_ITL_ID(row));
    knl_panic_log(itl->is_active, "the itl is inactive, panic info: page %u-%u type %u", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type);
    // itl->fsc and row->size are both less than DEFAULT_PAGE_SIZE(8192),
    // so the sum is less than max value(65535) of uint16
    itl->fsc += row->size;
}

void print_heap_delete_migr(log_entry_t *log)
{
    uint16 slot = *(uint16 *)log->data;
    printf("slot %u \n", slot);
}

void rd_heap_undo_update_linkrid(knl_session_t *session, log_entry_t *log)
{
    uint16 slot = *(uint16 *)log->data;
    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);
    row_dir_t *dir = heap_get_dir(page, slot);
    row_head_t *row = HEAP_GET_ROW(page, dir);
    rowid_t rid = *(rowid_t *)(log->data + CM_ALIGN4(sizeof(uint16)));

    *HEAP_LOC_LINK_RID(row) = rid;
}

void print_heap_undo_update_linkrid(log_entry_t *log)
{
    uint16 slot = *(uint16 *)log->data;
    rowid_t rid = *(rowid_t *)(log->data + CM_ALIGN4(sizeof(uint16)));

    printf("slot %u, next rowid %u-%u-%u\n", (uint32)slot, (uint32)rid.file, (uint32)rid.page, (uint32)rid.slot);
}
