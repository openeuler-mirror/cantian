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
 * knl_lob.c
 *
 *
 * IDENTIFICATION
 * src/kernel/lob/knl_lob.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_lob.h"
#include "knl_context.h"
#include "knl_table.h"
#include "knl_sys_part_defs.h"
#include "knl_space_manage.h"
#include "dtc_dls.h"
#include "dtc_tran.h"
#include "dtc_dc.h"

void lob_area_init(knl_session_t *session)
{
    memory_area_t *shared_pool = session->kernel->attr.shared_area;
    lob_area_t *area = &session->kernel->lob_ctx;
    char *buf = NULL;
    uint32 i;

    (void)mpool_create(shared_pool, "lob pool", GS_MIN_LOB_ITEMS_PAGES, MAX_LOB_ITEMS_PAGES, &area->pool);
    buf = marea_page_addr(shared_pool, area->pool.free_pages.first);
    area->lock = 0;
    area->capacity = GS_MIN_LOB_ITEMS_PAGES * LOB_ITEM_PAGE_CAPACITY;
    area->hwm = 0;
    area->free_items.count = 0;
    area->free_items.first = GS_INVALID_ID32;
    area->free_items.last = GS_INVALID_ID32;
    area->page_count = GS_MIN_LOB_ITEMS_PAGES;

    for (i = 0; i < GS_MIN_LOB_ITEMS_PAGES; i++) {
        area->pages[i] = buf + i * shared_pool->page_size;
    }
}

static status_t lob_area_extend(knl_session_t *session)
{
    mem_extent_t extent;
    memory_area_t *shared_pool = session->kernel->attr.shared_area;
    lob_area_t *area = &session->kernel->lob_ctx;
    uint32 i, page_count, area_pages;

    if (area->page_count >= MAX_LOB_ITEMS_PAGES) {
        GS_THROW_ERROR(ERR_NO_MORE_LOB_ITEMS);
        return GS_ERROR;
    }

    page_count = mpool_get_extend_page_count(MAX_LOB_ITEMS_PAGES, area->page_count);
    if (mpool_extend(&area->pool, page_count, &extent) != GS_SUCCESS) {
        return GS_ERROR;
    }

    area_pages = area->page_count;

    for (i = 0; i < extent.count; i++) {
        if (area_pages + i >= MAX_LOB_ITEMS_PAGES) {
            GS_THROW_ERROR(ERR_NO_MORE_LOB_ITEMS);
            return GS_ERROR;
        }

        area->pages[area_pages + i] = marea_page_addr(shared_pool, extent.pages[i]);
    }

    area->page_count += extent.count;
    /* extent.count <=4 and lob_item_page_capacity GS_SHARED_PAGE_SIZE / sizeof(lob_item_t) */
    /* area->page_count max is 1024, so area->capacity max is (1024 * 16 * 1024 / sizeof(lob_item_t)) */
    area->capacity += LOB_ITEM_PAGE_CAPACITY * extent.count;
    return GS_SUCCESS;
}

static status_t lob_area_alloc(knl_session_t *session, uint32 *item_id)
{
    lob_area_t *area = &session->kernel->lob_ctx;
    lob_item_t *item = NULL;
    errno_t ret;

    cm_spin_lock(&area->lock, NULL);

    // no more free lob items, try to extend from shared pool, to do
    if (area->hwm == area->capacity && area->free_items.count == 0) {
        if (lob_area_extend(session) != GS_SUCCESS) {
            cm_spin_unlock(&area->lock);
            return GS_ERROR;
        }
    }

    if (area->free_items.count == 0) {
        *item_id = area->hwm;
        item = lob_item_addr(area, *item_id);
        ret = memset_sp(item, sizeof(lob_item_t), 0, sizeof(lob_item_t));
        knl_securec_check(ret);
        item->next = GS_INVALID_ID32;
        item->item_id = *item_id;
        area->hwm++;
    } else {
        *item_id = area->free_items.first;
        item = lob_item_addr(area, *item_id);
        area->free_items.first = item->next;
        area->free_items.count--;
        ret = memset_sp(item, sizeof(lob_item_t), 0, sizeof(lob_item_t));
        knl_securec_check(ret);
        item->item_id = *item_id;

        if (area->free_items.count == 0) {
            area->free_items.first = GS_INVALID_ID32;
            area->free_items.last = GS_INVALID_ID32;
        }
    }

    cm_spin_unlock(&area->lock);
    return GS_SUCCESS;
}

static bool32 lob_item_find(knl_session_t *session, page_id_t entry, lob_item_t **lob_item)
{
    knl_rm_t *rm = session->rm;
    lob_item_t *item = NULL;

    if (rm->lob_items.count == 0) {
        return GS_FALSE;
    }

    item = rm->lob_items.first;

    while (item != NULL) {
        if (IS_SAME_PAGID(item->pages_info.entry, entry)) {
            *lob_item = item;
            return GS_TRUE;
        }

        item = item->next_item;
    }

    return GS_FALSE;
}

static void lob_item_add(lob_item_list_t *item_list, lob_item_t *lob_item)
{
    if (item_list->count == 0) {
        item_list->first = lob_item;
    } else {
        item_list->last->next = lob_item->item_id;
        knl_panic(item_list->last->next_item == NULL);
        item_list->last->next_item = lob_item;
    }

    item_list->last = lob_item;
    item_list->count++;
}

static status_t lob_item_alloc(knl_session_t *session, lob_t *lob, knl_part_locate_t part_loc, lob_item_t **lob_item)
{
    lob_area_t *area = &session->kernel->lob_ctx;
    lob_pages_info_t lob_pages;
    lob_part_t *lob_part = NULL;
    uint32 id;
    uint32 size_pages_info;
    errno_t ret;

    if (lob_area_alloc(session, &id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    size_pages_info = sizeof(lob_pages_info_t);
    ret = memset_sp(&lob_pages, size_pages_info, 0, size_pages_info);
    knl_securec_check(ret);
    lob_pages.col_id = lob->desc.column_id;
    lob_pages.table_id = lob->desc.table_id;
    lob_pages.uid = lob->desc.uid;
    lob_pages.part_loc = part_loc;
    if (part_loc.part_no == GS_INVALID_ID32) {
        lob_pages.entry = lob->lob_entity.entry;
    } else {
        lob_part = LOB_GET_PART(lob, part_loc.part_no);
        if (IS_PARENT_LOBPART(&lob_part->desc)) {
            lob_part = PART_GET_SUBENTITY(lob->part_lob, lob_part->subparts[part_loc.subpart_no]);
        }
        lob_pages.entry = lob_part->lob_entity.entry;
    }

    *lob_item = lob_item_addr(area, id);
    (*lob_item)->next = GS_INVALID_ID32;
    (*lob_item)->next_item = NULL;
    ret = memcpy_sp(&(*lob_item)->pages_info, size_pages_info, &lob_pages, size_pages_info);
    knl_securec_check(ret);

    return GS_SUCCESS;
}

void lob_items_reset(knl_rm_t *rm)
{
    lob_item_list_t *free_list = &rm->lob_items;
    free_list->count = 0;
    free_list->first = NULL;
    free_list->last = NULL;
}

void lob_items_free(knl_session_t *session)
{
    lob_area_t *area = &session->kernel->lob_ctx;
    knl_rm_t *rm = session->rm;
    lob_item_list_t *free_list = NULL;

    if (rm->lob_items.count == 0) {
        return;
    }

    free_list = &rm->lob_items;

    cm_spin_lock(&area->lock, NULL);

    if (area->free_items.count == 0) {
        area->free_items.count = free_list->count;
        area->free_items.first = free_list->first->item_id;
        area->free_items.last = free_list->last->item_id;
        knl_panic(area->free_items.first != GS_INVALID_ID32);
    } else {
        free_list->last->next = area->free_items.first;
        area->free_items.first = free_list->first->item_id;
        /* area->free_items max is 1024 * 16 * 1024 / sizeof(lob_item_t) = 264144 */
        area->free_items.count += free_list->count;
        knl_panic(area->free_items.first != GS_INVALID_ID32);
    }

    cm_spin_unlock(&area->lock);
}

void lob_reset_svpt(knl_session_t *session, knl_savepoint_t *savepoint)
{
    lob_item_list_t needless_items;
    knl_rm_t *rm = session->rm;
    uint32 svpt_count = savepoint->lob_items.count;
    uint32 se_count = rm->lob_items.count;

    if (savepoint->lob_items.count == 0) {
        lob_items_free(session);
        lob_items_reset(rm);
        return;
    } else {
        if (svpt_count == se_count) {
            return;
        }

        knl_panic(se_count > svpt_count);
        if (svpt_count < se_count) {
            needless_items.count = rm->lob_items.count - savepoint->lob_items.count;
            needless_items.first = savepoint->lob_items.last->next_item; /* last item of svpt_list can't be released */
            needless_items.last = rm->lob_items.last;

            rm->lob_items = needless_items;
            lob_items_free(session);
            rm->lob_items = savepoint->lob_items; /* reset to savepoint lob items list */
            rm->lob_items.last->next = GS_INVALID_ID32;
            rm->lob_items.last->next_item = NULL;
        }
    }
}

uint32 knl_lob_size(knl_handle_t locator)
{
    return ((lob_locator_t *)locator)->head.size;
}

bool32 knl_lob_is_inline(knl_handle_t locator)
{
    return !((lob_locator_t *)locator)->head.is_outline;
}

char *knl_inline_lob_data(knl_handle_t locator)
{
    return (char *)((lob_locator_t *)locator)->data;
}

static void lob_write_inline(lob_locator_t *locator, uint32 len, const char *data)
{
    errno_t err;

    locator->head.is_outline = GS_FALSE;
    locator->head.type = GS_LOB_FROM_KERNEL;
    locator->head.size = len;

    if (len == 0) {
        return;
    }

    err = memcpy_sp(locator->data, LOB_MAX_INLIINE_SIZE, data, len);
    knl_securec_check(err);
}

static bool32 lob_need_force_outline(knl_cursor_t *cursor, knl_column_t *column, row_assist_t *ra,
    text_t *data)
{
    uint32 lob_size = knl_lob_inline_size(cursor->row->is_csf, data->len, GS_TRUE);
    if (ra->head->size + lob_size > ra->max_size) {
        return GS_TRUE;
    }

    return GS_FALSE;
}

status_t knl_row_put_lob(knl_handle_t session, knl_cursor_t *cursor, knl_column_t *column, void *data,
                         knl_handle_t ra)
{
    knl_session_t *knl_session = (knl_session_t *)session;
    binary_t bin;
    lob_locator_t *lob_locator;
    errno_t err;
    bool32 force_outline;

    force_outline = lob_need_force_outline(cursor, column, (row_assist_t *)ra, (text_t *)data);

    lob_locator = (lob_locator_t *)cm_push(knl_session->stack, GS_LOB_LOCATOR_BUF_SIZE);
    err = memset_sp(lob_locator, GS_LOB_LOCATOR_BUF_SIZE, 0xFF, sizeof(lob_locator_t));
    knl_securec_check(err);

    if (knl_write_lob(session, cursor, (char *)lob_locator, column, force_outline, data) != GS_SUCCESS) {
        cm_pop(knl_session->stack);
        return GS_ERROR;
    }

    bin.bytes = (uint8 *)lob_locator;
    bin.size = knl_lob_locator_size(lob_locator);

    if (row_put_bin((row_assist_t *)ra, &bin) != GS_SUCCESS) {
        cm_pop(knl_session->stack);
        return GS_ERROR;
    }

    if (!lob_locator->head.is_outline) {
        cursor->lob_inline_num++;
    }

    cm_pop(knl_session->stack);
    return GS_SUCCESS;
}

status_t knl_copy_lob(knl_session_t *session, knl_cursor_t *dst_cursor, lob_locator_t *dst_locator,
                      lob_locator_t *src_locator, knl_column_t *column)
{
    uint32 reserve_size = 0;
    if (src_locator->head.is_outline) {
        bool8 is_part = IS_PART_TABLE(dst_cursor->table);
        space_t *dst_space = is_part ? SPACE_GET(session, ((table_part_t *)dst_cursor->table_part)->desc.space_id) :
                             SPACE_GET(session, ((table_t *)dst_cursor->table)->desc.space_id);

        reserve_size = dst_space->ctrl->cipher_reserve_size;
    }
    const uint32 buffer_size = LOB_MAX_CHUNK_SIZE(session) - reserve_size;
    binary_t piece;
    uint32 remain_size;
    uint32 offset = 0;
    bool32 force_outline;

    remain_size = knl_lob_size(src_locator);
    piece.bytes = (uint8 *)cm_push(session->stack, LOB_MAX_CHUNK_SIZE(session));
    piece.size = 0;
    force_outline = src_locator->head.is_outline;

    if (remain_size == 0) {
        status_t status = knl_write_lob(session, dst_cursor, (char *)dst_locator, column, force_outline, &piece);
        cm_pop(session->stack);
        return status;
    }

    while (remain_size > 0) {
        if (knl_read_lob(session, src_locator, offset, (void *)piece.bytes, buffer_size, &piece.size) != GS_SUCCESS) {
            cm_pop(session->stack);
            return GS_ERROR;
        }

        remain_size -= piece.size;
        offset += piece.size;

        if (knl_write_lob(session, dst_cursor, (char *)dst_locator, column, force_outline, &piece) != GS_SUCCESS) {
            cm_pop(session->stack);
            return GS_ERROR;
        }
    }

    cm_pop(session->stack);

    return GS_SUCCESS;
}

status_t knl_row_move_lob(knl_handle_t session, knl_cursor_t *cursor, knl_column_t *column,
                          knl_handle_t src_locator, knl_handle_t ra)
{
    knl_session_t *knl_session = (knl_session_t *)session;
    binary_t dst_bin;
    lob_locator_t *dst_locator = NULL;
    var_lob_t lob;
    errno_t err;

    dst_locator = (lob_locator_t *)cm_push(knl_session->stack, GS_LOB_LOCATOR_BUF_SIZE);
    err = memset_sp(dst_locator, sizeof(lob_locator_t), 0xFF, sizeof(lob_locator_t));
    knl_securec_check(err);

    if (knl_copy_lob(knl_session, cursor, dst_locator, (lob_locator_t *)src_locator, column) != GS_SUCCESS) {
        cm_pop(knl_session->stack);
        return GS_ERROR;
    }

    /*
     * If the lob is stored inline, call row_put_bin to put bin data into the row,
     * else, call row_put_lob to write the locator of the lob into the row.
     * As for how to save, according to the src_locator.
     */
    if (dst_locator->head.is_outline) {
        lob.knl_lob.bytes = (uint8 *)dst_locator;
        lob.knl_lob.size = knl_lob_locator_size(dst_locator);
        lob.type = GS_LOB_FROM_KERNEL;

        if (row_put_lob((row_assist_t *)ra, sizeof(lob_locator_t), &lob) != GS_SUCCESS) {
            cm_pop(knl_session->stack);
            return GS_ERROR;
        }
    } else {
        dst_bin.bytes = (uint8 *)dst_locator;
        dst_bin.size = knl_lob_locator_size(dst_locator);
        if (row_put_bin((row_assist_t *)ra, &dst_bin) != GS_SUCCESS) {
            cm_pop(knl_session->stack);
            return GS_ERROR;
        }
        cursor->lob_inline_num++;
    }

    cm_pop(knl_session->stack);
    return GS_SUCCESS;
}

void lob_init_page(knl_session_t *session, page_id_t page_id, page_type_t type, bool32 init_head)
{
    lob_data_page_t *data = NULL;
    page_head_t *page;

    page = (page_head_t *)CURR_PAGE(session);
    if (init_head) {
        page_init(session, page, page_id, type);
    } else {
        page->type = type;
    }

    if (type == PAGE_TYPE_LOB_DATA) {
        data = LOB_CURR_DATA_PAGE(session);
        data->chunk.next = INVALID_PAGID;
        data->chunk.free_next = INVALID_PAGID;
        data->chunk.is_recycled = GS_FALSE;
        data->pre_free_page = INVALID_PAGID;
    }
}

static void lob_init_segment(knl_session_t *session, knl_lob_desc_t *desc, page_list_t extents,
                             page_id_t ufp_extent)
{
    lob_segment_t *segment = NULL;
    space_t *space = SPACE_GET(session, desc->space_id);
    page_list_t free_list;
    errno_t ret;

    free_list.count = 0;
    free_list.first = INVALID_PAGID;
    free_list.last = INVALID_PAGID;

    segment = LOB_SEG_HEAD(session);
    ret = memset_sp(segment, sizeof(lob_segment_t), 0, sizeof(lob_segment_t));
    knl_securec_check(ret);
    segment->org_scn = desc->org_scn;
    segment->seg_scn = db_inc_scn(session);
    segment->shrink_scn = 0;
    segment->uid = (uint16)desc->uid;
    segment->table_id = desc->table_id;
    segment->column_id = (uint16)desc->column_id;
    segment->space_id = (uint16)desc->space_id;
    segment->extents.count = extents.count;
    segment->extents.first = extents.first;
    segment->extents.last = extents.last;
    segment->ufp_count = space->ctrl->extent_size - 1;
    segment->ufp_first = extents.first;
    segment->ufp_first.page++;
    segment->ufp_extent = ufp_extent;
    segment->free_list = free_list;
    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_LOB_CHANGE_SEG, segment, sizeof(lob_segment_t), LOG_ENTRY_FLAG_NONE);
    }
}

static void lob_init_part_segment(knl_session_t *session, knl_lob_part_desc_t *desc, page_list_t extents,
                                  page_id_t ufp_extent)
{
    lob_segment_t *segment = NULL;
    space_t *space = SPACE_GET(session, desc->space_id);
    page_list_t free_list;
    errno_t ret;

    free_list.count = 0;
    free_list.first = INVALID_PAGID;
    free_list.last = INVALID_PAGID;

    segment = LOB_SEG_HEAD(session);
    ret = memset_sp(segment, sizeof(lob_segment_t), 0, sizeof(lob_segment_t));
    knl_securec_check(ret);
    segment->org_scn = desc->org_scn;
    segment->seg_scn = db_inc_scn(session);
    segment->shrink_scn = 0;
    segment->uid = (uint16)desc->uid;
    segment->table_id = desc->table_id;
    segment->column_id = (uint16)desc->column_id;
    segment->space_id = (uint16)desc->space_id;
    segment->extents.count = extents.count;
    segment->extents.first = extents.first;
    segment->extents.last = extents.last;
    segment->ufp_count = space->ctrl->extent_size - 1;
    segment->ufp_first = extents.first;
    segment->ufp_first.page++;
    segment->ufp_extent = ufp_extent;
    segment->free_list = free_list;
    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_LOB_CHANGE_SEG, segment, sizeof(lob_segment_t), LOG_ENTRY_FLAG_NONE);
    }
}

status_t lob_generate_create_undo(knl_session_t *session, page_id_t entry, uint32 space_id, bool32 need_redo)
{
    undo_data_t undo;
    undo_lob_create_t ud_create;

    if (undo_prepare(session, sizeof(undo_lob_create_t), need_redo, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    log_atomic_op_begin(session);
    ud_create.entry = entry;
    ud_create.space_id = space_id;

    undo.snapshot.is_xfirst = GS_TRUE;
    undo.snapshot.scn = 0;
    undo.data = (char *)&ud_create;
    undo.size = sizeof(undo_lob_create_t);
    undo.ssn = session->rm->ssn;
    undo.type = UNDO_CREATE_LOB;
    undo_write(session, &undo, need_redo, GS_FALSE);
    log_atomic_op_end(session);

    return GS_SUCCESS;
}

void lob_undo_create_part(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot)
{
    lob_segment_t *segment = NULL;
    undo_lob_create_t *undo;
    page_list_t extents;
    page_head_t *head = NULL;
    buf_ctrl_t *ctrl = NULL;
    space_t *space = NULL;

    undo = (undo_lob_create_t *)ud_row->data;
    if (!spc_validate_page_id(session, undo->entry)) {
        return;
    }

    if (DB_IS_BG_ROLLBACK_SE(session) && !SPC_IS_LOGGING_BY_PAGEID(session, undo->entry)) {
        return;
    }

    space = SPACE_GET(session, undo->space_id);
    buf_enter_page(session, undo->entry, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    head = (page_head_t *)CURR_PAGE(session);
    ctrl = session->curr_page_ctrl;
    segment = LOB_SEG_HEAD(session);
    extents = segment->extents;
    page_free(session, head);
    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_SPC_FREE_PAGE, NULL, 0, LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);
    buf_unreside(session, ctrl);

    spc_free_extents(session, space, &extents);
    spc_drop_segment(session, space);
    GS_LOG_DEBUG_INF("[LOB] undo create hash partition lob, spaceid=%u, file=%u, pageid=%u", undo->space_id,
                     undo->entry.file, undo->entry.page);
}

status_t lob_create_segment(knl_session_t *session, lob_t *lob)
{
    page_id_t extent;
    page_id_t ufp_extent;
    space_t *space = SPACE_GET(session, lob->desc.space_id);
    lob_segment_t *segment = NULL;
    page_list_t extents;

    if (!spc_valid_space_object(session, space->ctrl->id)) {
        GS_THROW_ERROR(ERR_SPACE_HAS_REPLACED, space->ctrl->name, space->ctrl->name);
        return GS_ERROR;
    }

    log_atomic_op_begin(session);
    if (GS_SUCCESS != spc_alloc_extent(session, space, space->ctrl->extent_size, &extent, GS_FALSE)) {
        GS_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
        log_atomic_op_end(session);
        return GS_ERROR;
    }

    spc_create_segment(session, space);

    lob->lob_entity.entry = extent;
    lob->desc.entry = extent;
    lob->lob_entity.cipher_reserve_size = space->ctrl->cipher_reserve_size;

    ufp_extent = INVALID_PAGID;

    extents.count = 1;
    extents.first = extent;
    extents.last = extent;

    buf_enter_page(session, extent, LATCH_MODE_X, ENTER_PAGE_RESIDENT | ENTER_PAGE_NO_READ);
    segment = LOB_SEG_HEAD(session);
    lob_init_page(session, extents.first, PAGE_TYPE_LOB_HEAD, GS_TRUE);
    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_LOB_PAGE_INIT, (page_head_t *)CURR_PAGE(session), sizeof(page_head_t), LOG_ENTRY_FLAG_NONE);
    }

    lob_init_segment(session, &lob->desc, extents, ufp_extent);
    buf_leave_page(session, GS_TRUE);

    lob->desc.seg_scn = segment->seg_scn;

    log_atomic_op_end(session);

    return GS_SUCCESS;
}

status_t lob_create_part_segment(knl_session_t *session, lob_part_t *lob_part)
{
    space_t *space = SPACE_GET(session, lob_part->desc.space_id);
    lob_segment_t *segment = NULL;
    page_id_t extent;
    page_id_t ufp_extent;
    page_list_t extents;

    if (!spc_valid_space_object(session, space->ctrl->id)) {
        GS_THROW_ERROR(ERR_SPACE_HAS_REPLACED, space->ctrl->name, space->ctrl->name);
        return GS_ERROR;
    }

    log_atomic_op_begin(session);
    if (GS_SUCCESS != spc_alloc_extent(session, space, space->ctrl->extent_size, &extent, GS_FALSE)) {
        GS_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
        log_atomic_op_end(session);
        return GS_ERROR;
    }

    spc_create_segment(session, space);

    lob_part->lob_entity.entry = extent;
    lob_part->desc.entry = extent;
    lob_part->lob_entity.cipher_reserve_size = space->ctrl->cipher_reserve_size;

    ufp_extent = INVALID_PAGID;

    extents.count = 1;
    extents.first = extent;
    extents.last = extent;

    buf_enter_page(session, extent, LATCH_MODE_X, ENTER_PAGE_RESIDENT | ENTER_PAGE_NO_READ);
    segment = LOB_SEG_HEAD(session);
    lob_init_page(session, extents.first, PAGE_TYPE_LOB_HEAD, GS_TRUE);
    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_LOB_PAGE_INIT, (page_head_t *)CURR_PAGE(session), sizeof(page_head_t), LOG_ENTRY_FLAG_NONE);
    }

    lob_init_part_segment(session, &lob_part->desc, extents, ufp_extent);
    buf_leave_page(session, GS_TRUE);

    lob_part->desc.seg_scn = segment->seg_scn;

    log_atomic_op_end(session);

    return GS_SUCCESS;
}

void lob_drop_segment(knl_session_t *session, lob_t *lob)
{
    lob_entity_t *lob_entity = &lob->lob_entity;
    space_t *space;
    buf_ctrl_t *ctrl = NULL;
    page_head_t *head = NULL;
    lob_segment_t *segment = NULL;
    page_list_t extents;

    space = SPACE_GET(session, lob->desc.space_id);
    if (!SPACE_IS_ONLINE(space) || !space->ctrl->used) {
        return;
    }

    if (IS_INVALID_PAGID(lob_entity->entry)) {
        return;
    }

    log_atomic_op_begin(session);
    buf_enter_page(session, lob_entity->entry, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    head = (page_head_t *)CURR_PAGE(session);
    segment = LOB_SEG_HEAD(session);
    lob->desc.entry = INVALID_PAGID;
    lob_entity->segment = NULL;
    if (head->type != PAGE_TYPE_LOB_HEAD || segment->org_scn != lob->desc.org_scn) {
        // lob segment has been released
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return;
    }

    ctrl = session->curr_page_ctrl;
    extents = segment->extents;

    page_free(session, (page_head_t *)CURR_PAGE(session));
    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_SPC_FREE_PAGE, NULL, 0, LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);

    buf_unreside(session, ctrl);
    spc_free_extents(session, space, &extents);
    spc_drop_segment(session, space);

    log_atomic_op_end(session);
}

void lob_drop_garbage_segment(knl_session_t *session, knl_seg_desc_t *seg)
{
    space_t *space = NULL;
    buf_ctrl_t *ctrl = NULL;
    page_head_t *head = NULL;
    lob_segment_t *segment = NULL;
    page_list_t extents;

    if (!db_valid_seg_tablespace(session, seg->space_id, seg->entry)) {
        return;
    }

    space = SPACE_GET(session, seg->space_id);

    log_atomic_op_begin(session);
    buf_enter_page(session, seg->entry, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    head = (page_head_t *)CURR_PAGE(session);
    segment = LOB_SEG_HEAD(session);
    if (head->type != PAGE_TYPE_LOB_HEAD || segment->org_scn != seg->org_scn) {
        // lob segment has been released
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return;
    }

    ctrl = session->curr_page_ctrl;
    extents = segment->extents;

    page_free(session, (page_head_t *)CURR_PAGE(session));
    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_SPC_FREE_PAGE, NULL, 0, LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);

    buf_unreside(session, ctrl);
    spc_free_extents(session, space, &extents);
    spc_drop_segment(session, space);

    log_atomic_op_end(session);
}

void lob_drop_part_segment(knl_session_t *session, lob_part_t *lob_part)
{
    lob_entity_t *lob_entity = &lob_part->lob_entity;
    space_t *space;
    buf_ctrl_t *ctrl = NULL;
    page_head_t *head = NULL;
    lob_segment_t *segment = NULL;
    page_list_t extents;

    space = SPACE_GET(session, lob_part->desc.space_id);
    if (!SPACE_IS_ONLINE(space) || !space->ctrl->used) {
        return;
    }

    if (IS_INVALID_PAGID(lob_entity->entry)) {
        return;
    }

    log_atomic_op_begin(session);
    buf_enter_page(session, lob_entity->entry, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    head = (page_head_t *)CURR_PAGE(session);
    segment = LOB_SEG_HEAD(session);
    lob_part->desc.entry = INVALID_PAGID;
    lob_entity->segment = NULL;
    if (head->type != PAGE_TYPE_LOB_HEAD || segment->org_scn != lob_part->desc.org_scn) {
        // lob segment has been released
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return;
    }

    ctrl = session->curr_page_ctrl;
    extents = segment->extents;

    page_free(session, (page_head_t *)CURR_PAGE(session));
    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_SPC_FREE_PAGE, NULL, 0, LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);

    buf_unreside(session, ctrl);
    spc_free_extents(session, space, &extents);
    spc_drop_segment(session, space);

    log_atomic_op_end(session);
}

void lob_drop_part_garbage_segment(knl_session_t *session, knl_seg_desc_t *seg)
{
    space_t *space = NULL;
    buf_ctrl_t *ctrl = NULL;
    page_head_t *head = NULL;
    lob_segment_t *segment = NULL;
    page_list_t extents;

    if (!db_valid_seg_tablespace(session, seg->space_id, seg->entry)) {
        return;
    }

    space = SPACE_GET(session, seg->space_id);

    log_atomic_op_begin(session);
    buf_enter_page(session, seg->entry, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    head = (page_head_t *)CURR_PAGE(session);
    segment = LOB_SEG_HEAD(session);
    if (head->type != PAGE_TYPE_LOB_HEAD || segment->org_scn != seg->org_scn) {
        // lob segment has been released
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return;
    }

    ctrl = session->curr_page_ctrl;
    extents = segment->extents;

    page_free(session, (page_head_t *)CURR_PAGE(session));
    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_SPC_FREE_PAGE, NULL, 0, LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);

    buf_unreside(session, ctrl);
    spc_free_extents(session, space, &extents);
    spc_drop_segment(session, space);

    log_atomic_op_end(session);
}

void lob_clean_sub_default_segments(knl_session_t *session, lob_t *lob, uint32 subpart_cnt, lob_part_t *lob_part)
{
    lob_part_t *sub_part = NULL;

    for (uint32 j = 0; j < subpart_cnt; j++) {
        sub_part = PART_GET_SUBENTITY(lob->part_lob, lob_part->subparts[j]);
        lob_drop_part_segment(session, sub_part);
    }
}

void lob_clean_all_default_segments(knl_session_t *session, knl_handle_t entity, uint32 old_col_count)
{
    dc_entity_t *dc_entity = (dc_entity_t*)entity;
    uint32 new_col_count = knl_get_column_count(dc_entity);
    knl_column_t *column = NULL;
    table_t *table = &dc_entity->table;
    for (uint32 i = old_col_count; i < new_col_count; i++) {
        column = knl_get_column(dc_entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        lob_t *lob = column->lob;
        if (!IS_PART_TABLE(table)) {
            lob_drop_segment(session, lob);
            continue;
        }

        uint32 real_partcnt = table->part_table->desc.partcnt + table->part_table->desc.not_ready_partcnt;
        for (uint32 j = 0; j < real_partcnt; j++) {
            table_part_t *table_part = TABLE_GET_PART(table, j);
            if (!IS_READY_PART(table_part)) {
                continue;
            }

            lob_part_t *lob_part = LOB_GET_PART(lob, j);

            if (!IS_PARENT_TABPART(&table_part->desc)) {
                lob_drop_part_segment(session, lob_part);
                continue;
            }
           
            lob_clean_sub_default_segments(session, lob, table_part->desc.subpart_cnt, lob_part);
        }
    }
}

status_t lob_purge_prepare(knl_session_t *session, knl_rb_desc_t *desc)
{
    space_t *space = SPACE_GET(session, desc->space_id);
    if (!SPACE_IS_ONLINE(space) || !space->ctrl->used) {
        return GS_SUCCESS;
    }

    if (IS_INVALID_PAGID(desc->entry)) {
        return GS_SUCCESS;
    }

    buf_enter_page(session, desc->entry, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    lob_segment_t *segment = LOB_SEG_HEAD(session);
    knl_seg_desc_t seg;
    seg.uid = segment->uid;
    seg.oid = segment->table_id;
    seg.index_id = GS_INVALID_ID32;
    seg.column_id = GS_INVALID_ID32;
    seg.space_id = segment->space_id;
    seg.entry = desc->entry;
    seg.org_scn = segment->org_scn;
    seg.seg_scn = segment->seg_scn;
    seg.initrans = 0;
    seg.pctfree = 0;
    seg.op_type = LOB_PURGE_SEGMENT;
    seg.reuse = GS_FALSE;
    seg.serial = 0;
    buf_leave_page(session, GS_FALSE);

    if (db_write_garbage_segment(session, &seg) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void lob_purge_segment(knl_session_t *session, knl_seg_desc_t *desc)
{
    lob_segment_t *segment = NULL;
    page_list_t extents;
    page_head_t *head = NULL;

    if (!db_valid_seg_tablespace(session, desc->space_id, desc->entry)) {
        return;
    }

    space_t *space = SPACE_GET(session, desc->space_id);
    log_atomic_op_begin(session);

    buf_enter_page(session, desc->entry, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    head = (page_head_t *)CURR_PAGE(session);
    segment = LOB_SEG_HEAD(session);
    if (head->type != PAGE_TYPE_LOB_HEAD || segment->seg_scn != desc->seg_scn) {
        // lob segment has been released
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return;
    }

    extents = segment->extents;
    page_free(session, head);
    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_SPC_FREE_PAGE, NULL, 0, LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);

    buf_unreside(session, session->curr_page_ctrl);

    spc_free_extents(session, space, &extents);
    spc_drop_segment(session, space);
    log_atomic_op_end(session);
}

void lob_truncate_segment(knl_session_t *session, knl_lob_desc_t *desc, bool32 reuse_storage)
{
    page_head_t *page = NULL;
    page_list_t extents;
    page_id_t ufp_extent;
    lob_segment_t *segment = NULL;

    if (!db_valid_seg_tablespace(session, desc->space_id, desc->entry)) {
        return;
    }

    space_t *space = SPACE_GET(session, desc->space_id);
    log_atomic_op_begin(session);
    buf_enter_page(session, desc->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    page = (page_head_t *)CURR_PAGE(session);
    segment = LOB_SEG_HEAD(session);
    ufp_extent = INVALID_PAGID;

    if (page->type != PAGE_TYPE_LOB_HEAD || segment->seg_scn != desc->seg_scn) {
        // LOB segment has been released
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return;
    }

    if (!reuse_storage) {
        if (segment->extents.count > 1) {
            extents.count = segment->extents.count - 1;
            extents.first = AS_PAGID(page->next_ext);
            extents.last = segment->extents.last;
            spc_free_extents(session, space, &extents);
        }
        extents.count = 1;
        extents.first = segment->extents.first;
        extents.last = segment->extents.first;
        TO_PAGID_DATA(INVALID_PAGID, page->next_ext);
        lob_init_page(session, desc->entry, PAGE_TYPE_LOB_HEAD, GS_TRUE);
        if (SPACE_IS_LOGGING(space)) {
            log_put(session, RD_LOB_PAGE_INIT, CURR_PAGE(session), sizeof(page_head_t), LOG_ENTRY_FLAG_NONE);
        }
    } else {
        extents = segment->extents;

        if (segment->extents.count > 1) {
            ufp_extent = AS_PAGID(page->next_ext);
        }

        lob_init_page(session, desc->entry, PAGE_TYPE_LOB_HEAD, GS_FALSE);
        if (SPACE_IS_LOGGING(space)) {
            log_put(session, RD_LOB_PAGE_EXT_INIT, CURR_PAGE(session), sizeof(page_head_t), LOG_ENTRY_FLAG_NONE);
        }
    }

    lob_init_segment(session, desc, extents, ufp_extent);
    buf_leave_page(session, GS_TRUE);
    log_atomic_op_end(session);
}

void lob_truncate_garbage_segment(knl_session_t *session, knl_seg_desc_t *seg)
{
    knl_lob_desc_t desc;

    desc.uid = seg->uid;
    desc.table_id = seg->oid;
    desc.column_id = seg->column_id;
    desc.space_id = seg->space_id;
    desc.org_scn = seg->org_scn;
    desc.seg_scn = seg->seg_scn;
    desc.entry = seg->entry;

    lob_truncate_segment(session, &desc, seg->reuse);
}

void lob_truncate_part_segment(knl_session_t *session, knl_lob_part_desc_t *desc, bool32 reuse_storage)
{
    page_head_t *page = NULL;
    page_list_t extents;
    page_id_t ufp_extent;
    lob_segment_t *segment = NULL;

    if (!db_valid_seg_tablespace(session, desc->space_id, desc->entry)) {
        return;
    }

    space_t *space = SPACE_GET(session, desc->space_id);
    log_atomic_op_begin(session);
    buf_enter_page(session, desc->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    page = (page_head_t *)CURR_PAGE(session);
    segment = LOB_SEG_HEAD(session);
    ufp_extent = INVALID_PAGID;
    if (page->type != PAGE_TYPE_LOB_HEAD || segment->seg_scn != desc->seg_scn) {
        // LOB segment has been released
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return;
    }

    if (!reuse_storage) {
        if (segment->extents.count > 1) {
            extents.count = segment->extents.count - 1;
            extents.first = AS_PAGID(page->next_ext);
            extents.last = segment->extents.last;
            spc_free_extents(session, space, &extents);
        }
        extents.count = 1;
        extents.first = segment->extents.first;
        extents.last = segment->extents.first;
        TO_PAGID_DATA(INVALID_PAGID, page->next_ext);
        lob_init_page(session, desc->entry, PAGE_TYPE_LOB_HEAD, GS_TRUE);
        if (SPACE_IS_LOGGING(space)) {
            log_put(session, RD_LOB_PAGE_INIT, CURR_PAGE(session), sizeof(page_head_t), LOG_ENTRY_FLAG_NONE);
        }
    } else {
        extents = segment->extents;

        if (segment->extents.count > 1) {
            ufp_extent = AS_PAGID(page->next_ext);
        }

        lob_init_page(session, desc->entry, PAGE_TYPE_LOB_HEAD, GS_FALSE);
        if (SPACE_IS_LOGGING(space)) {
            log_put(session, RD_LOB_PAGE_EXT_INIT, CURR_PAGE(session), sizeof(page_head_t), LOG_ENTRY_FLAG_NONE);
        }
    }

    lob_init_part_segment(session, desc, extents, ufp_extent);
    buf_leave_page(session, GS_TRUE);

    log_atomic_op_end(session);
}

void lob_truncate_part_garbage_segment(knl_session_t *session, knl_seg_desc_t *seg)
{
    knl_lob_part_desc_t desc;

    desc.uid = seg->uid;
    desc.table_id = seg->oid;
    desc.column_id = seg->column_id;
    desc.space_id = seg->space_id;
    desc.seg_scn = seg->seg_scn;
    desc.org_scn = seg->org_scn;
    desc.entry = seg->entry;

    lob_truncate_part_segment(session, &desc, seg->reuse);
}

status_t lob_set_column_default(knl_session_t *session, knl_cursor_t *cursor, lob_locator_t *locator, void *data,
                                knl_column_t *column, void *stmt)
{
    lob_entity_t *lob_entity = NULL;
    lob_t *lob = (lob_t *)column->lob;

    if (IS_PART_TABLE(cursor->table)) {
        knl_panic_log(cursor->part_loc.part_no != GS_INVALID_ID32, "the part_no is invalid, panic info: "
                      "page %u-%u type %u table %s", cursor->rowid.file, cursor->rowid.page,
                      ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);
        lob_part_t *lob_part = LOB_GET_PART(lob, cursor->part_loc.part_no);
        if (IS_PARENT_LOBPART(&lob_part->desc)) {
            knl_panic_log(cursor->part_loc.subpart_no != GS_INVALID_ID32, "the subpart_no is invalid, panic info: "
                          "page %u-%u type %u table %s", cursor->rowid.file, cursor->rowid.page,
                          ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);
            lob_part = PART_GET_SUBENTITY(lob->part_lob, lob_part->subparts[cursor->part_loc.subpart_no]);
        }
        lob_entity = &lob_part->lob_entity;
        dls_latch_x(session, &lob_entity->seg_latch, session->id, &session->stat_lob);

        if (lob_entity->segment == NULL) {
            if (lob_create_part_segment(session, lob_part) != GS_SUCCESS) {
                dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);
                return GS_ERROR;
            }

            if (IS_SUB_LOBPART(&lob_part->desc)) {
                if (db_update_sublobpart_entry(session, &lob_part->desc, lob_part->desc.entry) != GS_SUCCESS) {
                    lob_drop_part_segment(session, lob_part);
                    dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);
                    return GS_ERROR;
                }
            } else {
                if (db_update_lob_part_entry(session, &lob_part->desc, lob_part->desc.entry) != GS_SUCCESS) {
                    lob_drop_part_segment(session, lob_part);
                    dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);
                    return GS_ERROR;
                }
            }

            buf_enter_page(session, lob_part->desc.entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
            lob_entity->segment = LOB_SEG_HEAD(session);
            buf_leave_page(session, GS_FALSE);
        }
        dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);
    } else {
        lob_entity = &lob->lob_entity;
        dls_latch_x(session, &lob_entity->seg_latch, session->id, &session->stat_lob);

        if (lob_entity->segment == NULL) {
            if (lob_create_segment(session, lob) != GS_SUCCESS) {
                dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);
                return GS_ERROR;
            }

            if (db_update_lob_entry(session, &lob->desc, lob->desc.entry) != GS_SUCCESS) {
                lob_drop_segment(session, lob);
                dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);
                return GS_ERROR;
            }

            buf_enter_page(session, lob->desc.entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
            lob_entity->segment = LOB_SEG_HEAD(session);
            buf_leave_page(session, GS_FALSE);
        }
        dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);
    }
    if (((variant_t *)data)->v_lob.type == GS_LOB_FROM_VMPOOL) {
        if (g_knl_callback.set_vm_lob_to_knl(stmt, cursor, column, data, (char *)locator) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else if (knl_write_lob(session, cursor, (char *)locator, column, GS_FALSE,
                             &((variant_t *)data)->v_lob.normal_lob.value) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t lob_alloc_from_space(knl_session_t *session, lob_entity_t *lob_entity, page_id_t *page_id)
{
    lob_segment_t *seg = NULL;
    space_t *space = NULL;
    page_id_t extent;
    bool32 init_head = GS_FALSE;

    dls_latch_x(session, &lob_entity->seg_latch, session->id, &session->stat_lob);
    seg = LOB_SEGMENT(session, lob_entity->entry, lob_entity->segment);
    space = SPACE_GET(session, seg->space_id);

    if (seg->ufp_count == 0 && IS_INVALID_PAGID(seg->ufp_extent)) {
        if (spc_alloc_extent(session, space, space->ctrl->extent_size, &extent, GS_FALSE) != GS_SUCCESS) {
            dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);
            GS_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
            return GS_ERROR;
        }

        buf_enter_page(session, lob_entity->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
        seg = LOB_SEG_HEAD(session);
        // entry of lob is same to extents last page of segment when  extents count is 1
        if (seg->extents.count == 1) {
            buf_leave_page(session, GS_FALSE);
            spc_concat_extent(session, seg->extents.last, extent);
            buf_enter_page(session, lob_entity->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
            seg = LOB_SEG_HEAD(session);
        } else {
            spc_concat_extent(session, seg->extents.last, extent);
        }

        seg->extents.count++;
        seg->extents.last = extent;
        seg->ufp_count = space->ctrl->extent_size - 1;
        seg->ufp_first = extent;
        *page_id = seg->ufp_first;
        seg->ufp_first.page++;
        init_head = GS_TRUE;
    } else {
        if (seg->ufp_count > 0) {
            buf_enter_page(session, lob_entity->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
            *page_id = seg->ufp_first;
            seg->ufp_first.page++;
            seg->ufp_count--;
            init_head = GS_TRUE;
        } else {
            buf_enter_page(session, lob_entity->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
            buf_enter_page(session, seg->ufp_extent, LATCH_MODE_S, ENTER_PAGE_NORMAL);
            seg->ufp_first = seg->ufp_extent;
            seg->ufp_extent = AS_PAGID(((page_head_t *)CURR_PAGE(session))->next_ext);
            buf_leave_page(session, GS_FALSE);
            seg->ufp_count = space->ctrl->extent_size - 1;
            *page_id = seg->ufp_first;
            seg->ufp_first.page++;
            init_head = GS_FALSE;
        }
    }

    dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);

    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_LOB_CHANGE_SEG, seg, sizeof(lob_segment_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);

    buf_enter_page(session, *page_id, LATCH_MODE_X, init_head ? ENTER_PAGE_NO_READ : ENTER_PAGE_NORMAL);
    lob_init_page(session, *page_id, PAGE_TYPE_LOB_DATA, init_head);

    if (SPACE_IS_LOGGING(space)) {
        if (init_head) {
            log_put(session, RD_LOB_PAGE_INIT, (page_head_t *)CURR_PAGE(session),
                    sizeof(page_head_t), LOG_ENTRY_FLAG_NONE);
        } else {
            log_put(session, RD_LOB_PAGE_EXT_INIT, (page_head_t *)CURR_PAGE(session),
                    sizeof(page_head_t), LOG_ENTRY_FLAG_NONE);
        }
    }

    buf_leave_page(session, GS_TRUE);
    return GS_SUCCESS;
}

static bool32 lob_need_reuse_page(knl_session_t *session, lob_entity_t *lob_entity)
{
    if (lob_entity->shrinking) {
        return GS_FALSE;
    }

    uint64 lob_reuse_count = session->kernel->attr.lob_reuse_threshold / DEFAULT_PAGE_SIZE(session);
    lob_segment_t *seg = LOB_SEGMENT(session, lob_entity->entry, lob_entity->segment);
    space_t *space = SPACE_GET(session, seg->space_id);
    uint64 lob_page_count = (uint64)(seg->extents.count) * space->ctrl->extent_size;
    uint32 lob_free_pages = seg->free_list.count;
    knl_panic(seg->free_list.count <= lob_page_count);
    if (lob_page_count < lob_reuse_count) {
        return GS_FALSE;
    }

    double pct_ratio = LOB_PCT_RATIO(lob_free_pages, lob_page_count);
    if (pct_ratio < lob_entity->lob->desc.pctversion) {
        return GS_FALSE;
    }

    return GS_TRUE;
}

static bool32 lob_check_page_exact(knl_session_t *session, bool32 *is_soft_disabled)
{
    lob_chunk_t *chunk = LOB_GET_CHUNK(session);
    txn_info_t txn_info;

    if (page_soft_damaged((page_head_t*)CURR_PAGE(session))) {
        *is_soft_disabled = GS_TRUE;
        return GS_FALSE;
    }

    // judge transaction that delete lob data is end or not,
    // locator first page of delete  is marked xid of  session when delete lob data
    if (chunk->del_xid.value != GS_INVALID_ID64) {
        if (DB_IS_CLUSTER(session)) {
            dtc_get_txn_info(session, 0, chunk->del_xid, &txn_info);
        } else {
            tx_get_info(session, GS_FALSE, chunk->del_xid, &txn_info);
        }
        if (txn_info.status != (uint8)XACT_END && txn_info.xid.xnum == chunk->del_xid.xnum) {
            return GS_FALSE;
        }
    }

    if (chunk->ins_xid.value != GS_INVALID_ID64) {
        // judge transaction that ins lob data is end or not
        if (DB_IS_CLUSTER(session)) {
            dtc_get_txn_info(session, 0, chunk->ins_xid, &txn_info);
        } else {
            tx_get_info(session, GS_FALSE, chunk->ins_xid, &txn_info);
        }
        if (txn_info.status != (uint8)XACT_END && txn_info.xid.xnum == chunk->ins_xid.xnum) {
            return GS_FALSE;
        }
    }

    return GS_TRUE;
}

static bool32 lob_try_reuse_page(knl_session_t *session, lob_entity_t *lob_entity, page_id_t *page_id,
    bool32 *soft_damaged)
{
    lob_segment_t *seg = NULL;
    lob_chunk_t *chunk = NULL;

    if (!lob_need_reuse_page(session, lob_entity)) {
        return GS_FALSE;
    }

    dls_latch_x(session, &lob_entity->seg_latch, session->id, &session->stat_lob);

    if (!lob_need_reuse_page(session, lob_entity)) {
        dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);
        return GS_FALSE;
    }

    buf_enter_page(session, lob_entity->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    seg = LOB_SEG_HEAD(session);
    *page_id = seg->free_list.first;
    knl_panic(!IS_INVALID_PAGID(seg->free_list.first));
    dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);
    buf_enter_page(session, *page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
   
    if (!lob_check_page_exact(session, soft_damaged)) {
        buf_leave_page(session, GS_FALSE);
        buf_leave_page(session, GS_FALSE);
        return GS_FALSE;
    }

    chunk = LOB_GET_CHUNK(session);
    seg->free_list.first = chunk->free_next;
    seg->free_list.count--;

    lob_init_page(session, *page_id, PAGE_TYPE_LOB_DATA, GS_FALSE);

    space_t *space = SPACE_GET(session, seg->space_id);

    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_LOB_PAGE_EXT_INIT, (page_head_t *)CURR_PAGE(session),
                sizeof(page_head_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);

    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_LOB_CHANGE_SEG, seg, sizeof(lob_segment_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);
    return GS_TRUE;
}

static void lob_gen_undo_alloc_page(knl_session_t *session, knl_cursor_t *cur, lob_entity_t *lob_enty,
                                    lob_undo_alloc_page_t *lob_undo)
{
    undo_data_t undo;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cur->dc_type);
    if (need_redo) {
        undo.snapshot.undo_page = session->rm->undo_page_info.undo_rid.page_id;
        undo.snapshot.undo_slot = session->rm->undo_page_info.undo_rid.slot;
    } else {
        undo.snapshot.undo_page = session->rm->noredo_undo_page_info.undo_rid.page_id;
        undo.snapshot.undo_slot = session->rm->noredo_undo_page_info.undo_rid.slot;
    }

    undo.snapshot.is_xfirst = cur->is_xfirst;
    undo.snapshot.scn = 0;
    undo.ssn = (uint32)cur->ssn;
    undo.size = sizeof(lob_undo_alloc_page_t);
    undo.seg_file = lob_enty->entry.file;
    undo.seg_page = lob_enty->entry.page;
    undo.data = (char *)lob_undo;
    undo.type = UNDO_LOB_ALLOC_PAGE;
    undo_write(session, &undo, need_redo, !cur->logging);
}

static status_t lob_alloc_page(knl_session_t *session, knl_cursor_t *cursor, lob_entity_t *lob_entity,
    lob_alloc_assist_t *lob_assist)
{
    lob_undo_alloc_page_t lob_undo;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);
    bool32 soft_damage = GS_FALSE;

    if (cursor->nologging_type != SESSION_LEVEL && lob_assist->generate_undo) {
        if (undo_prepare(session, sizeof(lob_undo_alloc_page_t), need_redo,
            GS_FALSE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    log_atomic_op_begin(session);
    if (!lob_try_reuse_page(session, lob_entity, lob_assist->lob_page_id, &soft_damage)) {
        if (soft_damage) {
            log_atomic_op_end(session);
            GS_THROW_ERROR(ERR_PAGE_SOFT_DAMAGED, lob_assist->lob_page_id->file, lob_assist->lob_page_id->page);
            return GS_ERROR;
        }

        if (lob_alloc_from_space(session, lob_entity, lob_assist->lob_page_id) != GS_SUCCESS) {
            log_atomic_op_end(session);
            return GS_ERROR;
        }
    }

    lob_undo.first_page = *lob_assist->lob_page_id;
    lob_undo.ori_scn = lob_assist->org_scn;
    if (cursor->nologging_type != SESSION_LEVEL && lob_assist->generate_undo) {
        lob_gen_undo_alloc_page(session, cursor, lob_entity, &lob_undo);
    }

    log_atomic_op_end(session);
    return GS_SUCCESS;
}

static status_t lob_create_entry(knl_session_t *session, lob_entity_t *lob_entity)
{
    lob_t *lob = lob_entity->lob;

    dls_latch_x(session, &lob_entity->seg_latch, session->id, &session->stat_lob);

    if (lob_entity->segment != NULL) {
        dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);
        return GS_SUCCESS;
    }

    if (lob_create_segment(session, lob) != GS_SUCCESS) {
        dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);
        return GS_ERROR;
    }

    if (knl_begin_auton_rm(session) != GS_SUCCESS) {
        lob_drop_segment(session, lob);
        dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);
        return GS_ERROR;
    }

    if (db_update_lob_entry(session, &lob->desc, lob->desc.entry) != GS_SUCCESS) {
        knl_end_auton_rm(session, GS_ERROR);
        lob_drop_segment(session, lob);
        dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);
        return GS_ERROR;
    }

    rd_create_lob_entry_t redo;
    redo.tab_op.op_type = RD_CREATE_LOB_ENTRY;
    redo.tab_op.uid = lob->desc.uid;
    redo.tab_op.oid = lob->desc.table_id;
    redo.part_loc.part_no = GS_INVALID_ID32;
    redo.entry = lob->desc.entry;
    redo.column_id = lob->desc.column_id;
    if (SPC_IS_LOGGING_BY_PAGEID(session, lob->desc.entry)) {
        log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_create_lob_entry_t), LOG_ENTRY_FLAG_NONE);
    }

    knl_end_auton_rm(session, GS_SUCCESS);

    buf_enter_page(session, lob->desc.entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
    lob_entity->segment = LOB_SEG_HEAD(session);
    buf_leave_page(session, GS_FALSE);

    dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);

    return GS_SUCCESS;
}

static status_t lob_create_part_entry(knl_session_t *session, lob_entity_t *lob_entity, knl_part_locate_t part_loc)
{
    dls_latch_x(session, &lob_entity->seg_latch, session->id, &session->stat_lob);

    if (lob_entity->segment != NULL) {
        dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);
        return GS_SUCCESS;
    }

    lob_part_t *lob_part = LOB_GET_PART(lob_entity->lob, part_loc.part_no);
    if (IS_PARENT_LOBPART(&lob_part->desc)) {
        knl_panic(part_loc.subpart_no != GS_INVALID_ID32);
        lob_part = PART_GET_SUBENTITY(lob_entity->lob->part_lob, lob_part->subparts[part_loc.subpart_no]);
    }

    if (lob_create_part_segment(session, lob_part) != GS_SUCCESS) {
        dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);
        return GS_ERROR;
    }

    if (knl_begin_auton_rm(session) != GS_SUCCESS) {
        lob_drop_part_segment(session, lob_part);
        dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);
        return GS_ERROR;
    }

    status_t ret = GS_SUCCESS;
    if (IS_SUB_LOBPART(&lob_part->desc)) {
        ret = db_update_sublobpart_entry(session, &lob_part->desc, lob_part->desc.entry);
    } else {
        ret = db_update_lob_part_entry(session, &lob_part->desc, lob_part->desc.entry);
    }

    if (ret != GS_SUCCESS) {
        knl_end_auton_rm(session, GS_ERROR);
        lob_drop_part_segment(session, lob_part);
        dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);
        return GS_ERROR;
    }

    rd_create_lob_entry_t redo;
    redo.tab_op.op_type = RD_CREATE_LOB_ENTRY;
    redo.tab_op.uid = lob_part->desc.uid;
    redo.tab_op.oid = lob_part->desc.table_id;
    redo.part_loc = part_loc;
    redo.entry = lob_part->desc.entry;
    redo.column_id = lob_part->desc.column_id;
    if (SPC_IS_LOGGING_BY_PAGEID(session, lob_part->desc.entry)) {
        log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_create_lob_entry_t), LOG_ENTRY_FLAG_NONE);
    }

    knl_end_auton_rm(session, GS_SUCCESS);

    buf_enter_page(session, lob_part->desc.entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
    lob_entity->segment = LOB_SEG_HEAD(session);
    buf_leave_page(session, GS_FALSE);

    dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);

    return GS_SUCCESS;
}

static void lob_generate_undo_delete(knl_session_t *session, knl_cursor_t *cursor, lob_entity_t *lob_entity,
    lob_del_undo_t lob_del_undo)
{
    undo_data_t undo;

    if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        undo.snapshot.undo_page = session->rm->undo_page_info.undo_rid.page_id;
        undo.snapshot.undo_slot = session->rm->undo_page_info.undo_rid.slot;
    } else {
        undo.snapshot.undo_page = session->rm->noredo_undo_page_info.undo_rid.page_id;
        undo.snapshot.undo_slot = session->rm->noredo_undo_page_info.undo_rid.slot;
    }
    undo.snapshot.is_xfirst = cursor->is_xfirst;
    undo.snapshot.scn = 0;
    undo.ssn = (uint32)cursor->ssn;
    undo.size = sizeof(lob_del_undo_t);
    undo.seg_file = lob_entity->entry.file;
    undo.seg_page = lob_entity->entry.page;
    undo.data = (char *)&lob_del_undo;
    undo.type = UNDO_LOB_DELETE;
    undo_write(session, &undo, IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type), GS_FALSE);
}

static void lob_generate_undo_delete_commit(knl_session_t *session, lob_pages_info_t page_info, bool32 need_redo)
{
    lob_seg_recycle_undo_t lob_seg_undo;
    lob_segment_t *segment = NULL;
    undo_data_t undo;

    segment = LOB_SEG_HEAD(session);
    lob_seg_undo.free_list = page_info.del_pages;
    lob_seg_undo.pre_free_last = segment->free_list.last;
    lob_seg_undo.entry = page_info.entry;
    if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
        undo.snapshot.undo_page = session->rm->undo_page_info.undo_rid.page_id;
        undo.snapshot.undo_slot = session->rm->undo_page_info.undo_rid.slot;
    } else {
        undo.snapshot.undo_page = session->rm->noredo_undo_page_info.undo_rid.page_id;
        undo.snapshot.undo_slot = session->rm->noredo_undo_page_info.undo_rid.slot;
    }
    undo.snapshot.is_xfirst = GS_FALSE;
    undo.snapshot.scn = 0;
    undo.ssn = session->rm->ssn;
    undo.size = sizeof(lob_seg_recycle_undo_t);
    undo.data = (char *)&lob_seg_undo;
    undo.type = UNDO_LOB_DELETE_COMMIT_RECYCLE;
    undo_write(session, &undo, need_redo, GS_FALSE);
}

static status_t lob_write_chunk(knl_session_t *session, knl_cursor_t *cursor, lob_entity_t *lob_entity,
                                lob_locator_t *locator, char *data_ptr, page_id_t *first_chunk_page)
{
    page_id_t lob_page_id, next_page_id;
    uint32 left_size, chunk_size;
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    bool32 has_logic = LOGIC_REP_DB_ENABLED(session) && dc_replication_enabled(session, entity, cursor->part_loc);
    uint8 entry_flag = has_logic ? LOG_ENTRY_FLAG_WITH_LOGIC_OID : LOG_ENTRY_FLAG_NONE;
    lob_page_id = *first_chunk_page;
    left_size = locator->head.size;
    uint8 cipher_reserve_size = lob_entity->cipher_reserve_size;
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(cipher_reserve_size);
    lob_alloc_assist_t lob_assist = { 0 };

    while (left_size > 0) {
        chunk_size = left_size > LOB_MAX_CHUNK_SIZE(session) - cipher_reserve_size ?
            LOB_MAX_CHUNK_SIZE(session) - cipher_reserve_size : left_size;
        /* locator->head.size max_size 4g, chunk_size max is 8k */
        left_size -= chunk_size;

        if (left_size > 0) {
            lob_init_assist(&lob_assist, &next_page_id, locator->org_scn, GS_FALSE);
            if (lob_alloc_page(session, cursor, lob_entity, &lob_assist) != GS_SUCCESS) {
                return GS_ERROR;
            }
        } else {
            locator->last = lob_page_id;
            next_page_id = INVALID_PAGID;
        }

        log_atomic_op_begin(session);
        buf_enter_page(session, lob_page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
        lob_chunk_t *chunk = LOB_GET_CHUNK(session);
        chunk->size = chunk_size;
        chunk->next = next_page_id;
        chunk->ins_xid = locator->xid;
        chunk->del_xid.value = GS_INVALID_ID64;
        chunk->org_scn = locator->org_scn;
        chunk->free_next = chunk->next;
        chunk->is_recycled = GS_FALSE;
        errno_t ret = memcpy_sp(chunk->data, chunk_size, data_ptr, chunk_size);
        knl_securec_check(ret);
        log_set_group_nolog_insert(session, cursor->logging);
        if (cursor->logging && IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
            log_encrypt_prepare(session, ((page_head_t *)session->curr_page)->type, need_encrypt);
            log_put(session, RD_LOB_PUT_CHUNK, chunk, OFFSET_OF(lob_chunk_t, data), entry_flag);
            log_append_data(session, chunk->data, chunk->size);
        }
        buf_leave_page(session, GS_TRUE);
        data_ptr += chunk_size;
        lob_page_id = next_page_id;
        log_atomic_op_end(session);
    }

    return GS_SUCCESS;
}

static status_t lob_append_chunk(knl_session_t *session, knl_cursor_t *cursor, lob_entity_t *lob_entity,
                                 lob_locator_t *locator, char *data_ptr, uint32 left_chunk_size)
{
    page_id_t lob_page_id, next_page_id;
    uint32 left_size, chunk_size, ori_chunk_size;
    lob_chunk_t *chunk = NULL;
    errno_t ret;
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    bool32 has_logic = LOGIC_REP_DB_ENABLED(session) && dc_replication_enabled(session, entity, cursor->part_loc);
    uint8 entry_flag = has_logic ? LOG_ENTRY_FLAG_WITH_LOGIC_OID : LOG_ENTRY_FLAG_NONE;
    lob_alloc_assist_t lob_assist = { 0 };

    left_size = locator->head.size;
    chunk_size = left_size > left_chunk_size ? left_chunk_size : left_size;
    left_size -= chunk_size;
    uint8 cipher_reserve_size = lob_entity->cipher_reserve_size;
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(cipher_reserve_size);
   
    if (left_size > 0) {
        lob_init_assist(&lob_assist, &lob_page_id, locator->org_scn, GS_FALSE);
        if (lob_alloc_page(session, cursor, lob_entity, &lob_assist) != GS_SUCCESS) {
            return GS_ERROR;
        }
        log_atomic_op_begin(session);
        // add lob data to page of locator
        buf_enter_page(session, locator->last, LATCH_MODE_X, ENTER_PAGE_NORMAL);
        if (PAGE_IS_SOFT_DAMAGE((page_head_t*)CURR_PAGE(session))) {
            buf_leave_page(session, GS_FALSE);
            log_atomic_op_end(session);
            GS_THROW_ERROR(ERR_PAGE_SOFT_DAMAGED, locator->last.file, locator->last.page);
            return GS_ERROR;
        }

        chunk = LOB_GET_CHUNK(session);
        ori_chunk_size = chunk->size;
        chunk->size += chunk_size;
        chunk->next = lob_page_id;
        chunk->free_next = chunk->next;
        ret = memcpy_sp(chunk->data + ori_chunk_size,
            LOB_MAX_CHUNK_SIZE(session) - cipher_reserve_size - ori_chunk_size, data_ptr, chunk_size);
        knl_securec_check(ret);
        log_set_group_nolog_insert(session, cursor->logging);
        if (cursor->logging && IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
            log_encrypt_prepare(session, ((page_head_t *)session->curr_page)->type, need_encrypt);
            log_put(session, RD_LOB_PUT_CHUNK, chunk, OFFSET_OF(lob_chunk_t, data), entry_flag);
            log_append_data(session, chunk->data, chunk->size);
        }
        buf_leave_page(session, GS_TRUE);
        log_atomic_op_end(session);
    } else {
        log_atomic_op_begin(session);
        buf_enter_page(session, locator->last, LATCH_MODE_X, ENTER_PAGE_NORMAL);
        if (PAGE_IS_SOFT_DAMAGE((page_head_t*)CURR_PAGE(session))) {
            buf_leave_page(session, GS_FALSE);
            log_atomic_op_end(session);
            GS_THROW_ERROR(ERR_PAGE_SOFT_DAMAGED, locator->last.file, locator->last.page);
            return GS_ERROR;
        }

        chunk = LOB_GET_CHUNK(session);
        ori_chunk_size = chunk->size;
        chunk->size += chunk_size;
        knl_panic_log(IS_INVALID_PAGID(chunk->next), "current chunk's next page id is valid, panic info: "
                      "next page %u-%u locator last page %u-%u type %u", chunk->next.file, chunk->next.page,
                      locator->last.file, locator->last.page, ((page_head_t *)CURR_PAGE(session))->type);
        ret = memcpy_sp(chunk->data + ori_chunk_size,
            LOB_MAX_CHUNK_SIZE(session) - cipher_reserve_size - ori_chunk_size, data_ptr, chunk_size);
        knl_securec_check(ret);
        log_set_group_nolog_insert(session, cursor->logging);
        if (cursor->logging && IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
            log_encrypt_prepare(session, ((page_head_t *)session->curr_page)->type, need_encrypt);
            log_put(session, RD_LOB_PUT_CHUNK, chunk, OFFSET_OF(lob_chunk_t, data), entry_flag);
            log_append_data(session, chunk->data, chunk->size);
        }
        buf_leave_page(session, GS_TRUE);
        log_atomic_op_end(session);
        return GS_SUCCESS;
    }

    data_ptr += chunk_size;

    while (left_size > 0) {
        chunk_size = left_size > LOB_MAX_CHUNK_SIZE(session) - cipher_reserve_size ?
            LOB_MAX_CHUNK_SIZE(session) - cipher_reserve_size : left_size;
        left_size -= chunk_size;

        if (left_size > 0) {
            lob_init_assist(&lob_assist, &next_page_id, locator->org_scn, GS_FALSE);
            if (lob_alloc_page(session, cursor, lob_entity, &lob_assist) != GS_SUCCESS) {
                return GS_ERROR;
            }
        } else {
            locator->last = lob_page_id;
            next_page_id = INVALID_PAGID;
        }

        log_atomic_op_begin(session);
        buf_enter_page(session, lob_page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
        chunk = LOB_GET_CHUNK(session);
        chunk->size = chunk_size;
        chunk->next = next_page_id;
        chunk->ins_xid = locator->xid;
        chunk->del_xid.value = GS_INVALID_ID64;
        chunk->org_scn = locator->org_scn;
        chunk->free_next = chunk->next;
        chunk->is_recycled = GS_FALSE;
        ret = memcpy_sp(chunk->data, LOB_MAX_CHUNK_SIZE(session) - cipher_reserve_size, data_ptr, chunk_size);
        knl_securec_check(ret);
        log_set_group_nolog_insert(session, cursor->logging);
        if (cursor->logging && IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
            log_encrypt_prepare(session, ((page_head_t *)session->curr_page)->type, need_encrypt);
            log_put(session, RD_LOB_PUT_CHUNK, chunk, OFFSET_OF(lob_chunk_t, data), entry_flag);
            log_append_data(session, chunk->data, chunk->size);
        }
        buf_leave_page(session, GS_TRUE);
        data_ptr += chunk_size;
        lob_page_id = next_page_id;
        log_atomic_op_end(session);
    }

    return GS_SUCCESS;
}

status_t lob_write_data(knl_session_t *session, knl_cursor_t *cursor, lob_entity_t *lob_entity,
                        lob_locator_t *locator, char *data)
{
    uint32 left_size, chunk_left_size;
    page_id_t lob_page_id;
    lob_chunk_t *chunk = NULL;
    char *data_ptr = data;
    uint8 cipher_reserve_size = lob_entity->cipher_reserve_size;
    lob_alloc_assist_t lob_assist = { 0 };
    left_size = locator->head.size;

    if (left_size == 0) {
        locator->first = INVALID_PAGID;
        locator->last = locator->first;
        return GS_SUCCESS;
    }
    
    if (IS_INVALID_PAGID(locator->first)) {
        lob_init_assist(&lob_assist, &locator->first, locator->org_scn, GS_TRUE);
        if (lob_alloc_page(session, cursor, lob_entity, &lob_assist) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (lob_write_chunk(session, cursor, lob_entity, locator, data_ptr, lob_assist.lob_page_id) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        buf_enter_page(session, locator->last, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        chunk = LOB_GET_CHUNK(session);
        if (chunk->size == LOB_MAX_CHUNK_SIZE(session) - cipher_reserve_size) {
            buf_leave_page(session, GS_FALSE);

            // add to locator last page
            lob_init_assist(&lob_assist, &lob_page_id, locator->org_scn, GS_FALSE);
            if (lob_alloc_page(session, cursor, lob_entity, &lob_assist) != GS_SUCCESS) {
                return GS_ERROR;
            }

            log_atomic_op_begin(session);
            buf_enter_page(session, locator->last, LATCH_MODE_X, ENTER_PAGE_NORMAL);
            if (PAGE_IS_SOFT_DAMAGE((page_head_t*)CURR_PAGE(session))) {
                buf_leave_page(session, GS_FALSE);
                log_atomic_op_end(session);
                GS_THROW_ERROR(ERR_PAGE_SOFT_DAMAGED, locator->last.file, locator->last.page);
                return GS_ERROR;
            }
            chunk = LOB_GET_CHUNK(session);
            chunk->next = lob_page_id;
            chunk->free_next = chunk->next;
            log_set_group_nolog_insert(session, cursor->logging);
            if (cursor->logging && IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
                log_put(session, RD_LOB_CHANGE_CHUNK, chunk, sizeof(lob_chunk_t), LOG_ENTRY_FLAG_NONE);
            }

            buf_leave_page(session, GS_TRUE);
            log_atomic_op_end(session);

            if (lob_write_chunk(session, cursor, lob_entity, locator, data_ptr, &lob_page_id) != GS_SUCCESS) {
                return GS_ERROR;
            }
        } else {
            chunk_left_size = LOB_MAX_CHUNK_SIZE(session) - cipher_reserve_size - chunk->size;
            buf_leave_page(session, GS_FALSE);
            if (lob_append_chunk(session, cursor, lob_entity, locator, data_ptr, chunk_left_size) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }
    if (DB_IS_CLUSTER(session) && (session->rm->logic_log_size >= KNL_LOGIC_LOG_FLUSH_SIZE)) {
        tx_copy_logic_log(session);
        if (db_write_ddl_op(session) != GS_SUCCESS) {
            knl_panic_log(0, "[DDL]can't record logical log for session(%d)", session->id);
        }
        dtc_sync_ddl(session);
    }

    return GS_SUCCESS;
}

status_t lob_internal_write(knl_session_t *session, knl_cursor_t *cursor, lob_locator_t *locator,
                            knl_column_t *column, char *data)
{
    lob_t *lob = (lob_t *)column->lob;
    lob_part_t *lob_part = NULL;
    lob_entity_t *lob_entity = NULL;
    dc_entity_t *entity;

    entity = (dc_entity_t *)cursor->dc_entity;

    if (lock_table_shared(session, entity, LOCK_INF_WAIT) != GS_SUCCESS) {
        return GS_ERROR;
    }

    locator->xid = session->rm->xid;
    locator->head.is_outline = GS_TRUE;
    locator->head.unused = 0;

    if (IS_PART_TABLE(cursor->table)) {
        knl_panic_log(cursor->part_loc.part_no != GS_INVALID_ID32,
                      "the part_no is invalid, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                      cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, entity->table.desc.name);
        lob_part = LOB_GET_PART(lob, cursor->part_loc.part_no);
        if (IS_PARENT_LOBPART(&lob_part->desc)) {
            uint32 subpart_no = cursor->part_loc.subpart_no;
            knl_panic_log(subpart_no != GS_INVALID_ID32, "the subpart_no is invalid, panic info: "
                          "page %u-%u type %u table %s", cursor->rowid.file, cursor->rowid.page,
                          ((page_head_t *)cursor->page_buf)->type, entity->table.desc.name);
            lob_part_t *lob_subpart = PART_GET_SUBENTITY(lob->part_lob, lob_part->subparts[subpart_no]);
            lob_entity = &lob_subpart->lob_entity;
            locator->org_scn = lob_subpart->desc.org_scn;
        } else {
            lob_entity = &lob_part->lob_entity;
            locator->org_scn = lob_part->desc.org_scn;
        }

        if (lob_entity->segment == NULL) {
            if (lob_create_part_entry(session, lob_entity, cursor->part_loc) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    } else {
        lob_entity = &lob->lob_entity;
        locator->org_scn = lob->desc.org_scn;

        if (lob_entity->segment == NULL) {
            if (lob_create_entry(session, lob_entity) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    if (lob_write_data(session, cursor, lob_entity, locator, data) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/*
 * kernel write lob interface
 * @note new locator should be memset as 0xFF
 * @param kernel session, cursor, locator, lob column, data
 */
status_t knl_write_lob(knl_handle_t se, knl_cursor_t *cursor, char *locator, knl_column_t *column,
                       bool32 force_outline, void *data)
{
    lob_locator_t tmp_locator;
    lob_locator_t *ori_locator = NULL;
    text_t lob;
    uint64 writed_lob_size;
    knl_session_t *session = (knl_session_t *)se;
    errno_t ret;

    if (column->datatype == GS_TYPE_CLOB || column->datatype == GS_TYPE_IMAGE) {
        lob.str = ((text_t *)data)->str;
        lob.len = ((text_t *)data)->len;
    } else {
        lob.str = (char *)(((binary_t *)data)->bytes);
        lob.len = ((binary_t *)data)->size;
    }

    if (!force_outline && ((lob_t *)column->lob)->desc.is_inrow && lob.len <= LOB_MAX_INLIINE_SIZE) {
        lob_write_inline((lob_locator_t *)locator, lob.len, lob.str);
        return GS_SUCCESS;
    }

    ret = memcpy_sp(&tmp_locator, sizeof(lob_locator_t), locator, sizeof(lob_locator_t));
    knl_securec_check(ret);
    tmp_locator.head.size = lob.len;

    if (lob_internal_write(session, cursor, &tmp_locator, column, lob.str) != GS_SUCCESS) {
        return GS_ERROR;
    }

    ori_locator = LOB_GET_LOCATOR(locator);
    ori_locator->head.type = GS_LOB_FROM_KERNEL;
    ori_locator->head.is_outline = GS_TRUE;
    ori_locator->first = tmp_locator.first;
    ori_locator->last = tmp_locator.last;
    ori_locator->xid = tmp_locator.xid;
    ori_locator->org_scn = tmp_locator.org_scn;

    if (ori_locator->head.size == GS_INVALID_ID32) {
        ori_locator->head.size = tmp_locator.head.size;
    } else {
        writed_lob_size = (uint64)ori_locator->head.size + (uint64)tmp_locator.head.size;
        if (writed_lob_size >= GS_MAX_LOB_SIZE) {
            GS_THROW_ERROR(ERR_LOB_SIZE_TOO_LARGE, "4294967295 bytes");
            return GS_ERROR;
        }
        ori_locator->head.size = (uint32)writed_lob_size;
    }

    return GS_SUCCESS;
}

status_t knl_read_lob_chk(knl_session_t *session, page_id_t page_id, lob_locator_t *loc)
{
    lob_data_page_t *data = NULL;
    lob_chunk_t *chunk = NULL;

    if (page_is_damaged((page_head_t *)CURR_PAGE(session))) {
        GS_THROW_ERROR(ERR_PAGE_SOFT_DAMAGED, page_id.file, page_id.page);
        return GS_ERROR;
    }

    data = LOB_CURR_DATA_PAGE(session);
    if (data->head.type != PAGE_TYPE_LOB_DATA) {
        GS_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, "table");
        return GS_ERROR;
    }

    chunk = LOB_GET_CHUNK(session);
    if (!LOB_CHECK_XID(loc, chunk)) {
        tx_record_sql(session);
        GS_LOG_RUN_ERR("snapshot too old, detail: lob data is invalid");
        GS_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
        return GS_ERROR;
    }

    if (!LOB_CHECK_ORG_SCN(loc, data)) {
        GS_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, "table");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t knl_read_lob(knl_handle_t se, knl_handle_t loc, uint32 offset_input, void *buf, uint32 size, uint32 *read_size)
{
    page_id_t chunk_page_id;
    lob_chunk_t *chunk = NULL;
    uint32 curr_len = 0;
    uint32 len;
    uint32 copy_len;
    uint32 offset = offset_input;
    knl_session_t *session = (knl_session_t *)se;
    lob_locator_t *locator = (lob_locator_t *)loc;
    errno_t ret;

    // for gsdb sql engine, locator which lob size is 0 is not filtered in gsdb sql engine
    if (locator->head.size == 0 || offset >= locator->head.size) {
        if (read_size != NULL) {
            *read_size = 0;
        }
        return GS_SUCCESS;
    }

    if (size == GS_INVALID_ID32 || size > locator->head.size) {
        len = locator->head.size - offset;
    } else {
        len = size;
    }

    if (!locator->head.is_outline) {
        curr_len = MIN(locator->head.size - offset, len);
        ret = memcpy_sp(buf, curr_len, (char *)locator->data + offset, curr_len);
        knl_securec_check(ret);

        if (read_size != NULL) {
            *read_size = curr_len;
        }

        return GS_SUCCESS;
    }

    chunk_page_id = locator->first;

    for (;;) {
        if (buf_read_page(session, chunk_page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (knl_read_lob_chk(session, chunk_page_id, locator) != GS_SUCCESS) {
            buf_leave_page(session, GS_FALSE);
            return GS_ERROR;
        }

        chunk = LOB_GET_CHUNK(session);
        if (offset < chunk->size) {
            copy_len = MIN(chunk->size - offset, len);
            ret = memcpy_s((char *)buf + curr_len, copy_len, chunk->data + offset, copy_len);
            knl_securec_check(ret);
            curr_len += copy_len;
            len -= copy_len;

            if (len == 0) {
                buf_leave_page(session, GS_FALSE);
                break;
            } else {
                offset = 0;
            }
        } else {
            offset -= chunk->size;
        }

        if (IS_INVALID_PAGID(chunk->next)) {
            buf_leave_page(session, GS_FALSE);
            break;
        }

        chunk_page_id = chunk->next;
        buf_leave_page(session, GS_FALSE);
    }

    if (read_size != NULL) {
        *read_size = curr_len;
    }

    return GS_SUCCESS;
}

void lob_update_unused_list(knl_session_t *session, lob_seg_recycle_undo_t *lob_undo, page_id_t page_id)
{
    lob_segment_t *segment = LOB_SEG_HEAD(session);

    if (IS_SAME_PAGID(segment->free_list.last, lob_undo->free_list.last)) {
        segment->free_list.last = page_id;
    }
    knl_panic_log(segment->free_list.count >= lob_undo->free_list.count,
                  "the free list's count of segment and lob_undo are not equal, panic info: segment free list's last "
                  "page %u-%u free list count %u lob_undo free list's last page %u-%u free list count %u",
                  segment->free_list.last.file, segment->free_list.last.page, segment->free_list.count,
                  lob_undo->free_list.last.file, lob_undo->free_list.last.page, lob_undo->free_list.count);
    segment->free_list.count -= lob_undo->free_list.count;

    if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
        log_put(session, RD_LOB_CHANGE_SEG, segment, sizeof(lob_segment_t), LOG_ENTRY_FLAG_NONE);
    }
}

void lob_change_pre_free_page(knl_session_t *session, lob_segment_t *segment, page_id_t change_page,
    page_id_t curr_pre_free_page, page_id_t *ori_page)
{
    if (!IS_INVALID_PAGID(change_page)) {
        buf_enter_page(session, change_page, LATCH_MODE_X, ENTER_PAGE_NORMAL);
        if (ori_page != NULL) {
            *ori_page = (LOB_CURR_DATA_PAGE(session))->pre_free_page;
        }
        (LOB_CURR_DATA_PAGE(session))->pre_free_page = curr_pre_free_page;
        if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
            log_put(session, RD_LOB_CHANGE_PAGE_FREE, &(LOB_CURR_DATA_PAGE(session))->pre_free_page, sizeof(page_id_t),
                LOG_ENTRY_FLAG_NONE);
        }
        buf_leave_page(session, GS_TRUE);
    }
}

void lob_undo_delete_commit_recycle(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot)
{
    lob_seg_recycle_undo_t *lob_undo;
    page_id_t lob_entry;
    lob_chunk_t *chunk = NULL;
    page_id_t last_free_page;

    lob_undo = (lob_seg_recycle_undo_t *)ud_row->data;
    lob_entry = lob_undo->entry;
    if (!spc_validate_page_id(session, lob_entry)) {
        return;
    }
    buf_enter_page(session, lob_entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    lob_segment_t *segment = LOB_SEG_HEAD(session);

    buf_enter_page(session, lob_undo->free_list.last, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    if (page_is_damaged((page_head_t *)CURR_PAGE(session))) {
        buf_leave_page(session, GS_FALSE);
        buf_leave_page(session, GS_FALSE);
        return;
    }

    chunk = LOB_GET_CHUNK(session);
    chunk->is_recycled = GS_FALSE;
    chunk->del_xid.value = GS_INVALID_ID64;
    last_free_page = chunk->free_next;
    chunk->free_next = INVALID_PAGID;
    if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
        log_put(session, RD_LOB_CHANGE_CHUNK, chunk, sizeof(lob_chunk_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);

    // if free list last is invalid page id, it means free list has no pages when add child free chain.
    if (IS_INVALID_PAGID(lob_undo->pre_free_last)) {
        segment->free_list.first = last_free_page;
        lob_update_unused_list(session, lob_undo, lob_undo->pre_free_last);
        buf_leave_page(session, GS_TRUE);
        return;
    }

    buf_enter_page(session, lob_undo->pre_free_last, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    if (page_is_damaged((page_head_t *)CURR_PAGE(session))) {
        buf_leave_page(session, GS_FALSE);
        buf_leave_page(session, GS_FALSE);
        return;
    }

    chunk = LOB_GET_CHUNK(session);
    page_id_t pre_free_last = lob_undo->pre_free_last;
/*  if the undo->free_list'first not same to the undo->pre_free_last:
    1. get first->pre_free.
    2. if first->pre_free is valid, change the undo pre to first->pre_free.
    3. if first->pre_free is invalid, still use undo pre_free_last and do nothing.
*/
    if (!IS_SAME_PAGID(chunk->free_next, lob_undo->free_list.first)) {
        buf_leave_page(session, GS_FALSE);
        page_id_t ori_pre_free_last = lob_undo->pre_free_last;
        lob_change_pre_free_page(session, segment, lob_undo->free_list.first, INVALID_PAGID, &pre_free_last);
        if (IS_INVALID_PAGID(pre_free_last)) {
            pre_free_last = ori_pre_free_last;
        }

        buf_enter_page(session, pre_free_last, LATCH_MODE_X, ENTER_PAGE_NORMAL);
        if (page_is_damaged((page_head_t *)CURR_PAGE(session))) {
            buf_leave_page(session, GS_FALSE);
            buf_leave_page(session, GS_FALSE);
            return;
        }
        chunk = LOB_GET_CHUNK(session);
    }

    // lob_undo->pre_free_last is not reused
    if (IS_SAME_PAGID(chunk->free_next, lob_undo->free_list.first)) {
        chunk->free_next = last_free_page;
        if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
            log_put(session, RD_LOB_CHANGE_CHUNK, chunk, sizeof(lob_chunk_t), LOG_ENTRY_FLAG_NONE);
        }
        /* if the chunk->free_next is vaild, change chunk->free_next'page_data->pre_free to the current pre_free */
        lob_change_pre_free_page(session, segment, chunk->free_next, pre_free_last, NULL);
        buf_leave_page(session, GS_TRUE);
    } else {
        // chunk need not to modify,leave current page
        buf_leave_page(session, GS_FALSE);
        knl_panic_log(IS_SAME_PAGID(segment->free_list.first, lob_undo->free_list.first),
                      "the free list's first page of segment and lob_undo are not same, panic info: "
                      "segment page %u-%u lob_undo page %u-%u", segment->free_list.first.file,
                      segment->free_list.first.page, lob_undo->free_list.first.file, lob_undo->free_list.first.page);
        segment->free_list.first = last_free_page;
    }

    lob_update_unused_list(session, lob_undo, pre_free_last);
    buf_leave_page(session, GS_TRUE);
}

void lob_undo_delete_commit(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot)
{
    lob_seg_undo_t *lob_undo;
    page_id_t lob_entry;
    lob_segment_t *segment = NULL;
    page_id_t free_last_page;
    lob_chunk_t *chunk = NULL;
    errno_t ret;

    lob_undo = (lob_seg_undo_t *)ud_row->data;
    lob_entry = lob_undo->entry;
    if (!spc_validate_page_id(session, lob_entry)) {
        return;
    }
    buf_enter_page(session, lob_entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    segment = LOB_SEG_HEAD(session);
    ret = memcpy_sp(&segment->free_list, sizeof(page_list_t), &lob_undo->free_list, sizeof(page_list_t));
    knl_securec_check(ret);
    // free list last page may be changed when record lob undo delete,but undo page just record information of free list
    // and do not record change of last page,so we need to recover status of last page before last page changed
    if (segment->free_list.count != 0) {
        free_last_page = segment->free_list.last;
        buf_enter_page(session, free_last_page, LATCH_MODE_X, ENTER_PAGE_NORMAL);
        if (page_is_damaged((page_head_t *)CURR_PAGE(session))) {
            buf_leave_page(session, GS_FALSE);
            buf_leave_page(session, GS_FALSE);
            return;
        }

        chunk = LOB_GET_CHUNK(session);
        chunk->free_next = INVALID_PAGID;
        if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
            log_put(session, RD_LOB_CHANGE_CHUNK, chunk, sizeof(lob_chunk_t), LOG_ENTRY_FLAG_NONE);
        }
        buf_leave_page(session, GS_TRUE);
    }

    if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
        log_put(session, RD_LOB_CHANGE_SEG, segment, sizeof(lob_segment_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);
}


void lob_free_delete_pages(knl_session_t *session)
{
    lob_item_t *lob_item = NULL;
    lob_segment_t *segment = NULL;
    page_id_t page_id;
    lob_chunk_t *chunk = NULL;
    lob_t *lob = NULL;
    lob_part_t *lob_part = NULL;
    lob_entity_t *lob_entity = NULL;
    lob_pages_info_t pages_info;
    dc_user_t *user = NULL;
    dc_entity_t *entity = NULL;
    dc_entry_t *entry = NULL;
    errno_t ret;
    uint64 free_pages;

    if (session->rm->lob_items.count == 0) {
        return;
    }

    lob_item = session->rm->lob_items.first;

    for (;;) {
        if (lob_item == NULL) {
            break;
        }

        pages_info = lob_item->pages_info;

        if (pages_info.del_pages.count == 0) {
            lob_item = lob_item->next_item;
            continue;
        }

        user = session->kernel->dc_ctx.users[pages_info.uid];
        entry = DC_GET_ENTRY(user, pages_info.table_id);
        entity = entry->entity;
        lob = (lob_t *)dc_get_column(entity, pages_info.col_id)->lob;
        if (IS_PART_TABLE(&entity->table)) {
            knl_panic_log(pages_info.part_loc.part_no != GS_INVALID_ID32,
                          "the part_no is invalid, panic info: table %s", entity->table.desc.name);
            lob_part = LOB_GET_PART(lob, pages_info.part_loc.part_no);
            if (IS_PARENT_LOBPART(&lob_part->desc)) {
                knl_panic_log(pages_info.part_loc.subpart_no != GS_INVALID_ID32,
                              "the subpart_no is invalid, panic info: table %s", entity->table.desc.name);
                lob_part = PART_GET_SUBENTITY(lob->part_lob, lob_part->subparts[pages_info.part_loc.subpart_no]);
            }
            lob_entity = &lob_part->lob_entity;
        } else {
            lob_entity = &lob->lob_entity;
        }

        if (undo_prepare(session, sizeof(lob_seg_recycle_undo_t),
            SPACE_IS_LOGGING(SPACE_GET(session, lob->desc.space_id)), GS_FALSE) != GS_SUCCESS) {
            continue;
        }

        log_atomic_op_begin(session);
        dls_latch_x(session, &lob_entity->seg_latch, session->id, &session->stat_lob);
        buf_enter_page(session, pages_info.entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
        lob_generate_undo_delete_commit(session, pages_info, SPACE_IS_LOGGING(SPACE_GET(session, lob->desc.space_id)));
        segment = LOB_SEG_HEAD(session);

        /* segment->free_list.count > INVALID_32 */
        free_pages = (uint64)segment->free_list.count + pages_info.del_pages.count;
        if (free_pages > GS_MAX_UINT32) {
            GS_LOG_RUN_ERR("user-%d,table-%d,column-%d,part(%d-%d), too much free delete pages %lld",
                pages_info.uid, pages_info.table_id, pages_info.col_id, pages_info.part_loc.part_no,
                pages_info.part_loc.subpart_no, free_pages);
            buf_leave_page(session, GS_FALSE);
            dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);
            log_atomic_op_end(session);
            lob_item = lob_item->next_item;
            continue;
        }

        if (segment->free_list.count == 0) {
            ret = memcpy_sp(&segment->free_list, sizeof(page_list_t), &pages_info.del_pages, sizeof(page_list_t));
            knl_securec_check(ret);
        } else {
            page_id = segment->free_list.last;
            buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
            chunk = LOB_GET_CHUNK(session);
            knl_panic_log(IS_INVALID_PAGID(chunk->free_next),
                          "the next free page is valid, panic info: page %u-%u type %u table %s",
                          page_id.file, page_id.page, ((page_head_t *)CURR_PAGE(session))->type,
                          entity->table.desc.name);
            chunk->free_next = pages_info.del_pages.first;
            if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
                log_put(session, RD_LOB_CHANGE_CHUNK, chunk, sizeof(lob_chunk_t), LOG_ENTRY_FLAG_NONE);
            }
            buf_leave_page(session, GS_TRUE);

            segment->free_list.last = pages_info.del_pages.last;
            segment->free_list.count += pages_info.del_pages.count;
        }

        if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
            log_put(session, RD_LOB_CHANGE_SEG, segment, sizeof(lob_segment_t), LOG_ENTRY_FLAG_NONE);
        }
        buf_leave_page(session, GS_TRUE);

        dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);
        log_atomic_op_end(session);
        lob_item = lob_item->next_item;
    }
}

status_t lob_chk_chunk(knl_session_t *session, knl_cursor_t *cur, lob_locator_t *loc, lob_entity_t *lob_enty)
{
    lob_data_page_t *data = NULL;
    lob_chunk_t *chunk = NULL;

    data = LOB_CURR_DATA_PAGE(session);
    chunk = LOB_GET_CHUNK(session);
    if (PAGE_IS_SOFT_DAMAGE(&data->head)) {
        GS_THROW_ERROR(ERR_PAGE_SOFT_DAMAGED, AS_PAGID(&data->head).file, AS_PAGID(&data->head).page);
        return GS_ERROR;
    }
    // if lob has been shrink,chunk may be used by others.
    if (data->head.type != PAGE_TYPE_LOB_DATA || !LOB_CHECK_XID(loc, chunk) || !LOB_CHECK_ORG_SCN(loc, data)) {
        if (cur->query_scn < lob_enty->segment->shrink_scn) {
            tx_record_sql(session);
            GS_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
            return GS_ERROR;
        }

        knl_panic_log(data->head.type == PAGE_TYPE_LOB_DATA,
                      "the data type is abnormal, panic info: page %u-%u type %u "
                      "table %s data_type %u", loc->first.file, loc->first.page,
                      ((page_head_t *)CURR_PAGE(session))->type,
                      ((table_t *)cur->table)->desc.name, data->head.type);
        knl_panic_log(loc->xid.value == chunk->ins_xid.value,
                      "the lob chunk xid is abnormal, panic info: page %u-%u type %u "
                      "table %s lob xid %u-%u-%u", loc->first.file, loc->first.page,
                      ((page_head_t *)CURR_PAGE(session))->type,
                      ((table_t *)cur->table)->desc.name, chunk->ins_xid.xmap.seg_id,
                      chunk->ins_xid.xmap.slot, chunk->ins_xid.xnum);
        knl_panic_log(loc->org_scn == chunk->org_scn,
                      "the lob chunk org_scn is abnormal, panic info: page %u-%u type %u "
                      "table %s lob scn %llu", loc->first.file, loc->first.page,
                      ((page_head_t *)CURR_PAGE(session))->type,
                      ((table_t *)cur->table)->desc.name, chunk->org_scn);
    }

    return GS_SUCCESS;
}

static status_t lob_internal_delete(knl_session_t *session, knl_cursor_t *cursor,
                                    lob_entity_t *lob_entity, lob_locator_t *locator)
{
    lob_item_t *lob_item = NULL;
    page_id_t first_page, last_page;
    lob_chunk_t *chunk = NULL;
    uint32 chunk_count;
    bool32 is_found;
    lob_item_list_t *item_list = NULL;
    lob_del_undo_t lob_del_undo;
    uint64 lob_delete_pages;
    knl_part_locate_t part_loc = { .part_no = GS_INVALID_ID32,
        .subpart_no = GS_INVALID_ID32 };

    is_found = lob_item_find(session, lob_entity->entry, &lob_item);
    if (!is_found) {
        if (IS_PART_TABLE(cursor->table)) {
            part_loc = cursor->part_loc;
        }

        if (lob_item_alloc(session, lob_entity->lob, part_loc, &lob_item) != GS_SUCCESS) {
            return GS_ERROR;
        }

        item_list = &session->rm->lob_items;
        lob_item_add(item_list, lob_item);
    }

    if (undo_prepare(session, sizeof(lob_del_undo_t), IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type),
        GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    log_atomic_op_begin(session);
    cm_spin_lock(&lob_item->lock, NULL);

    first_page = locator->first;
    last_page = locator->last;

    buf_enter_page(session, first_page, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    if (lob_chk_chunk(session, cursor, locator, lob_entity) != GS_SUCCESS) {
        buf_leave_page(session, GS_FALSE);
        cm_spin_unlock(&lob_item->lock);
        log_atomic_op_end(session);
        return GS_ERROR;
    }

    chunk = LOB_GET_CHUNK(session);
    // judge locator page in lob item del_pages list or ins_pages
    if (chunk->is_recycled) {
        buf_leave_page(session, GS_FALSE);
        cm_spin_unlock(&lob_item->lock);
        log_atomic_op_end(session);
        return GS_SUCCESS;
    } else {
        chunk = LOB_GET_CHUNK(session);
        chunk->is_recycled = GS_TRUE;
        chunk->del_xid = session->rm->xid;
        if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
            log_put(session, RD_LOB_CHANGE_CHUNK, chunk, sizeof(lob_chunk_t), LOG_ENTRY_FLAG_NONE);
        }
        buf_leave_page(session, GS_TRUE);
    }

    if (lob_item->pages_info.del_pages.count == 0) {
        lob_item->pages_info.del_pages.first = first_page;
        lob_del_undo.prev_page = INVALID_PAGID;
    } else {
        buf_enter_page(session, lob_item->pages_info.del_pages.last, LATCH_MODE_X, ENTER_PAGE_NORMAL);
        chunk = LOB_GET_CHUNK(session);
        knl_panic_log(IS_INVALID_PAGID(chunk->free_next), "the next free page is valid, panic info: page %u-%u "
            "type %u table %s", lob_item->pages_info.del_pages.last.file, lob_item->pages_info.del_pages.last.page,
            ((page_head_t *)CURR_PAGE(session))->type, ((table_t *)cursor->table)->desc.name);
        chunk->free_next = first_page;
        if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
            log_put(session, RD_LOB_CHANGE_CHUNK, chunk, sizeof(lob_chunk_t), LOG_ENTRY_FLAG_NONE);
        }
        buf_leave_page(session, GS_TRUE);
        lob_del_undo.prev_page = lob_item->pages_info.del_pages.last;
    }

    chunk_count = LOB_GET_CHUNK_COUNT(session, locator);
    /*
     *  if DEL_PAGES.count > invalid_32 error
     */
    lob_delete_pages = (uint64)lob_item->pages_info.del_pages.count + chunk_count;

    if (lob_delete_pages >= GS_MAX_UINT32) {
        cm_spin_unlock(&lob_item->lock);
        log_atomic_op_end(session);
        GS_THROW_ERROR(ERR_TOO_MANY_OBJECTS, GS_MAX_UINT32, "lob pages deleted");
        return GS_ERROR;
    }

    lob_item->pages_info.del_pages.count += chunk_count;
    lob_item->pages_info.del_pages.last = last_page;
    lob_del_undo.first_page = first_page;
    lob_del_undo.last_page = last_page;
    lob_del_undo.chunk_count = chunk_count;

    lob_generate_undo_delete(session, cursor, lob_entity, lob_del_undo);
    cm_spin_unlock(&lob_item->lock);
    log_atomic_op_end(session);

    return GS_SUCCESS;
}

status_t lob_delete(knl_session_t *session, knl_cursor_t *cursor)
{
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    uint32 i;
    lob_t *lob = NULL;
    lob_part_t *lob_part = NULL;
    lob_entity_t *lob_entity = NULL;
    lob_locator_t *locator = NULL;
    knl_column_t *column = NULL;

    for (i = 0; i < entity->column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column) && !KNL_COLUMN_IS_ARRAY(column)) {
            continue;
        }

        if (CURSOR_COLUMN_SIZE(cursor, i) == GS_NULL_VALUE_LEN) {
            continue;
        }

        locator = (lob_locator_t *)CURSOR_COLUMN_DATA(cursor, i);
        if (locator->head.size == 0) {
            continue;
        }

        if (!locator->head.is_outline) {
            continue;
        }

        lob = (lob_t *)dc_get_column(entity, i)->lob;
        if (IS_PART_TABLE(cursor->table)) {
            lob_part = LOB_GET_PART(lob, cursor->part_loc.part_no);
            if (IS_PARENT_LOBPART(&lob_part->desc)) {
                lob_part = PART_GET_SUBENTITY(lob->part_lob, lob_part->subparts[cursor->part_loc.subpart_no]);
            }
            lob_entity = &lob_part->lob_entity;
        } else {
            lob_entity = &lob->lob_entity;
        }

        if (lob_internal_delete(session, cursor, lob_entity, locator) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t lob_internal_update(knl_session_t *session, knl_cursor_t *cursor, lob_locator_t *locator,
                                    uint16 col_id)
{
    dc_entity_t *entity = NULL;
    lob_t *lob = NULL;
    lob_part_t *lob_part = NULL;
    lob_entity_t *lob_entity = NULL;

    if (locator == NULL || locator->head.size == 0) {
        return GS_SUCCESS;
    }

    entity = (dc_entity_t *)cursor->dc_entity;
    lob = (lob_t *)dc_get_column(entity, col_id)->lob;

    if (IS_PART_TABLE(cursor->table)) {
        lob_part = LOB_GET_PART(lob, cursor->part_loc.part_no);
        if (IS_PARENT_LOBPART(&lob_part->desc)) {
            lob_part = PART_GET_SUBENTITY(lob->part_lob, lob_part->subparts[cursor->part_loc.subpart_no]);
        }
        lob_entity = &lob_part->lob_entity;
    } else {
        lob_entity = &lob->lob_entity;
    }

    if (lob_internal_delete(session, cursor, lob_entity, locator) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static bool32 lob_check_update_column(knl_session_t *session, knl_cursor_t *cursor,
    heap_update_assist_t *ua)
{
    dc_entity_t *entity;
    knl_column_t *column = NULL;
    uint16 i, col_id;

    entity = (dc_entity_t *)cursor->dc_entity;

    for (i = 0; i < ua->info->count; i++) {
        col_id = ua->info->columns[i];
        column = dc_get_column(entity, col_id);
        if (COLUMN_IS_LOB(column)) {
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

static bool32 lob_check_locator(knl_cursor_t *cursor, lob_t *lob, lob_locator_t *locator)
{
    lob_part_t *lob_part = NULL;

    if (IS_PART_TABLE(cursor->table)) {
        knl_panic_log(cursor->part_loc.part_no != GS_INVALID_ID32, "the part_no is invalid, panic info: "
                      "page %u-%u type %u table %s", cursor->rowid.file, cursor->rowid.page,
                      ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);
        lob_part = LOB_GET_PART(lob, cursor->part_loc.part_no);
        if (IS_PARENT_LOBPART(&lob_part->desc)) {
            knl_panic_log(cursor->part_loc.subpart_no != GS_INVALID_ID32, "the subpart_no is invalid, panic info: "
                          "page %u-%u type %u table %s", cursor->rowid.file, cursor->rowid.page,
                          ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);
            lob_part = PART_GET_SUBENTITY(lob->part_lob, lob_part->subparts[cursor->part_loc.subpart_no]);
        }
        if (locator->org_scn != lob_part->desc.org_scn) {
            return GS_FALSE;
        }
    } else {
        if (locator->org_scn != lob->desc.org_scn) {
            return GS_FALSE;
        }
    }

    return GS_TRUE;
}

status_t lob_update(knl_session_t *session, knl_cursor_t *cursor, heap_update_assist_t *ua)
{
    uint16 i;
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    knl_column_t *column = NULL;
    lob_locator_t *locator = NULL;
    uint16 col_id;
    lob_t *lob = NULL;

    if (!lob_check_update_column(session, cursor, ua)) {
        return GS_SUCCESS;
    }

    if (cursor->set_default) {
        return GS_SUCCESS;
    }

    for (i = 0; i < ua->info->count; i++) {
        col_id = ua->info->columns[i];
        column = dc_get_column(entity, col_id);
        if (COLUMN_IS_LOB(column)) {
            lob = (lob_t *)column->lob;
            if (CURSOR_COLUMN_SIZE(cursor, col_id) == GS_NULL_VALUE_LEN) {
                continue;
            }

            locator = (lob_locator_t *)CURSOR_COLUMN_DATA(cursor, col_id);
            if (!locator->head.is_outline) {
                continue;
            }

            if (!lob_check_locator(cursor, lob, locator)) {
                continue;
            }

            if (lob_internal_update(session, cursor, locator, col_id) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

void lob_free_insert_pages(knl_session_t *session, page_id_t lob_entry, uint32 part_no,
    lob_locator_t *locator)
{
    page_id_t first_page;
    page_id_t last_page;
    page_id_t free_last_page = INVALID_PAGID;
    lob_chunk_t *chunk = NULL;
    uint32 chunk_count = 0;
    lob_segment_t *segment = NULL;
    uint64 free_pages;

    first_page = locator->first;
    last_page = first_page;

    for (;;) {
        buf_enter_page(session, last_page, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        if (page_soft_damaged((page_head_t*)CURR_PAGE(session))) {
            buf_leave_page(session, GS_FALSE);
            return;
        }

        chunk = LOB_GET_CHUNK(session);
        chunk_count++;

        if (IS_INVALID_PAGID(chunk->next)) {
            buf_leave_page(session, GS_FALSE);
            break;
        }

        last_page = LOB_NEXT_DATA_PAGE(session);
        buf_leave_page(session, GS_FALSE);
    }

    buf_enter_page(session, lob_entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    page_head_t *page = (page_head_t *)CURR_PAGE(session);
    segment = LOB_SEG_HEAD(session);
    /* for modify lob column or add lob column failed, segment will be release before rollback. */
    if (page->type != PAGE_TYPE_LOB_HEAD || segment->org_scn != locator->org_scn) {
        buf_leave_page(session, GS_FALSE);
        return;
    }
    
    /* segment->free_list.count > INVALID_32 */
    free_pages = (uint64)segment->free_list.count + chunk_count;
    if (free_pages > GS_MAX_UINT32) {
        GS_LOG_RUN_ERR("user-%d,table-%d,column-%d,part:(%d),too much free insert pages %lld", segment->uid,
                       segment->table_id, segment->column_id, part_no, free_pages);
        buf_leave_page(session, GS_FALSE);
        return;
    }

    buf_enter_page(session, first_page, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    chunk = LOB_GET_CHUNK(session);
    // lob pages of recycle only exist in ins_pages or  only exist in dele_pages
    // is_recycle is used to mark this locator pages in recycle pages(ins_pages or dele_pages) or not
    if (chunk->is_recycled) {
        buf_leave_page(session, GS_FALSE);
        buf_leave_page(session, GS_FALSE);
        return;
    } else {
        chunk = LOB_GET_CHUNK(session);
        chunk->is_recycled = GS_TRUE;
        if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
            log_put(session, RD_LOB_CHANGE_CHUNK, chunk, sizeof(lob_chunk_t), LOG_ENTRY_FLAG_NONE);
        }
        buf_leave_page(session, GS_TRUE);
    }

    if (segment->free_list.count == 0) {
        segment->free_list.first = first_page;
    } else {
        free_last_page = segment->free_list.last;
        buf_enter_page(session, free_last_page, LATCH_MODE_X, ENTER_PAGE_NORMAL);
        if (page_soft_damaged((page_head_t*)CURR_PAGE(session))) {
            buf_leave_page(session, GS_FALSE);
            buf_leave_page(session, GS_FALSE);
            return;
        }
        chunk = LOB_GET_CHUNK(session);
        knl_panic_log(IS_INVALID_PAGID(chunk->free_next),
                      "the next free page is valid, panic info: free_last_page %u-%u type %u", free_last_page.file,
                      free_last_page.page, ((page_head_t *)CURR_PAGE(session))->type);
        chunk->free_next = first_page;
        if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
            log_put(session, RD_LOB_CHANGE_CHUNK, chunk, sizeof(lob_chunk_t), LOG_ENTRY_FLAG_NONE);
        }

        buf_leave_page(session, GS_TRUE);
    }

    segment->free_list.last = last_page;
    segment->free_list.count += chunk_count;
    if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
        log_put(session, RD_LOB_CHANGE_SEG, segment, sizeof(lob_segment_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);
}

uint32 lob_get_chunk_cnt(knl_session_t *session, page_id_t *page_id, bool32 *is_soft_disabled)
{
    lob_chunk_t *chunk = NULL;
    uint32 chunk_count = 0;

    for (;;) {
        buf_enter_page(session, *page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        if (page_soft_damaged((page_head_t*)CURR_PAGE(session))) {
            *is_soft_disabled = GS_TRUE;
            buf_leave_page(session, GS_FALSE);
            return chunk_count;
        }

        chunk = LOB_GET_CHUNK(session);
        chunk_count++;

        if (IS_INVALID_PAGID(chunk->next)) {
            buf_leave_page(session, GS_FALSE);
            break;
        }

        *page_id = LOB_NEXT_DATA_PAGE(session);
        buf_leave_page(session, GS_FALSE);
    }

    return chunk_count;
}

void lob_release_alloc_page(knl_session_t *session, page_id_t page_id, lob_undo_alloc_page_t *lob_undo)
{
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    page_head_t *page = (page_head_t *)CURR_PAGE(session);
    lob_segment_t *segment = LOB_SEG_HEAD(session);
    /* for modify lob column or add lob column failed, segment will be release before rollback. */
    if (page->type != PAGE_TYPE_LOB_HEAD || segment->org_scn != lob_undo->ori_scn) {
        buf_leave_page(session, GS_FALSE);
        return;
    }

    page_id_t last_page = lob_undo->first_page;
    bool32 soft_damaged = GS_FALSE;
    uint32 chunk_count = lob_get_chunk_cnt(session, &last_page, &soft_damaged);
    if (soft_damaged) {
        buf_leave_page(session, GS_FALSE);
        return;
    }

    uint64 free_pages = (uint64)segment->free_list.count + chunk_count;
    if (free_pages > GS_MAX_UINT32) {
        GS_LOG_RUN_ERR("user-%d,table-%d,column-%d, entry %u-%u,too much free insert pages %lld", segment->uid,
            segment->table_id, segment->column_id, page_id.file, page_id.page, free_pages);
        buf_leave_page(session, GS_FALSE);
        return;
    }

    buf_enter_page(session, lob_undo->first_page, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    lob_chunk_t *chunk = LOB_GET_CHUNK(session);
    // lob pages of recycle only exist in ins_pages or  only exist in dele_pages
    // is_recycle is used to mark this locator pages in recycle pages(ins_pages or dele_pages) or not
    if (chunk->is_recycled) {
        buf_leave_page(session, GS_FALSE);
        buf_leave_page(session, GS_FALSE);
        return;
    } else {
        chunk = LOB_GET_CHUNK(session);
        chunk->is_recycled = GS_TRUE;
        if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
            log_put(session, RD_LOB_CHANGE_CHUNK, chunk, sizeof(lob_chunk_t), LOG_ENTRY_FLAG_NONE);
        }
        buf_leave_page(session, GS_TRUE);
    }

    if (segment->free_list.count == 0) {
        segment->free_list.first = lob_undo->first_page;
    } else {
        page_id_t free_last_page = segment->free_list.last;
        buf_enter_page(session, free_last_page, LATCH_MODE_X, ENTER_PAGE_NORMAL);
        if (page_soft_damaged((page_head_t*)CURR_PAGE(session))) {
            buf_leave_page(session, GS_FALSE);
            buf_leave_page(session, GS_FALSE);
            return;
        }

        chunk = LOB_GET_CHUNK(session);
        knl_panic_log(IS_INVALID_PAGID(chunk->free_next),
            "the next free page is valid, panic info: free_last_page %u-%u type %u", free_last_page.file,
            free_last_page.page, ((page_head_t *)CURR_PAGE(session))->type);
        chunk->free_next = lob_undo->first_page;
        if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
            log_put(session, RD_LOB_CHANGE_CHUNK, chunk, sizeof(lob_chunk_t), LOG_ENTRY_FLAG_NONE);
        }

        buf_leave_page(session, GS_TRUE);
    }

    segment->free_list.last = last_page;
    segment->free_list.count += chunk_count;
    if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
        log_put(session, RD_LOB_CHANGE_SEG, segment, sizeof(lob_segment_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);
}

void lob_undo_delete(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot)
{
    lob_del_undo_t *del_undo;
    lob_chunk_t *chunk = NULL;
    page_id_t page_id;
    bool32 is_found = GS_FALSE;
    lob_item_t *lob_item = NULL;

    del_undo = (lob_del_undo_t *)ud_row->data;

    page_id = MAKE_PAGID((uint16)ud_row->seg_file, (uint32)ud_row->seg_page);
    if (!spc_validate_page_id(session, page_id)) {
        return;
    }

    // savepoint exist, we must recycle session's delete pages list to status before delete this locator
    if (session->rm->lob_items.count != 0) {
        is_found = lob_item_find(session, page_id, &lob_item);
        knl_panic_log(is_found, "lob_item is not found, panic info: page %u-%u", page_id.file, page_id.page);
        CM_ABORT(is_found, "[LOB] ABORT INFO: cannot find lob item while doing undo delete");

        cm_spin_lock(&lob_item->lock, NULL);
        lob_item->pages_info.del_pages.last = del_undo->prev_page;
        lob_item->pages_info.del_pages.count -= del_undo->chunk_count;
        cm_spin_unlock(&lob_item->lock);

        if (IS_INVALID_PAGID(lob_item->pages_info.del_pages.last)) {
            knl_panic_log(lob_item->pages_info.del_pages.count == 0, "the deleted counts of lob page is incorrect, "
                "panic info: del_undo first_page %u-%u del_pages's first %u-%u del_pages's count %u",
                del_undo->first_page.file, del_undo->first_page.page, lob_item->pages_info.del_pages.first.file,
                lob_item->pages_info.del_pages.first.page, lob_item->pages_info.del_pages.count);
            knl_panic_log(IS_SAME_PAGID(del_undo->first_page, lob_item->pages_info.del_pages.first),
                          "del_undo's first_page and lob del_pages's first are not same, panic info: "
                          "ud_page %u-%u type %u del_undo first_page %u-%u lob del_pages's first %u-%u",
                          AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type,
                          del_undo->first_page.file, del_undo->first_page.page,
                          lob_item->pages_info.del_pages.first.file, lob_item->pages_info.del_pages.first.page);
            lob_item->pages_info.del_pages.first = INVALID_PAGID;
        } else {
            // for set free next of session's delete pages list last page to invalid
            buf_enter_page(session, lob_item->pages_info.del_pages.last, LATCH_MODE_X, ENTER_PAGE_NORMAL);
            chunk = LOB_GET_CHUNK(session);
            if (page_is_damaged((page_head_t *)CURR_PAGE(session))) {
                buf_leave_page(session, GS_FALSE);
                return;
            }
            chunk->free_next = INVALID_PAGID;
            if (SPC_IS_LOGGING_BY_PAGEID(session, lob_item->pages_info.del_pages.last)) {
                log_put(session, RD_LOB_CHANGE_CHUNK, chunk, sizeof(lob_chunk_t), LOG_ENTRY_FLAG_NONE);
            }
            buf_leave_page(session, GS_TRUE);
        }
    }
    /* check del_xid before change chunk */
    if (IS_SAME_PAGID(del_undo->first_page, del_undo->last_page)) {
        buf_enter_page(session, del_undo->first_page, LATCH_MODE_X, ENTER_PAGE_NORMAL);
        chunk = LOB_GET_CHUNK(session);
        /* check del_xid in case of double delete and rollback */
        if (page_is_damaged((page_head_t *)CURR_PAGE(session)) || (chunk->del_xid.value != ud_row->xid.value)) {
            buf_leave_page(session, GS_FALSE);
            return;
        }

        chunk->is_recycled = GS_FALSE;
        chunk->free_next = INVALID_PAGID;
        chunk->del_xid.value = GS_INVALID_ID64;
        if (SPC_IS_LOGGING_BY_PAGEID(session, del_undo->first_page)) {
            log_put(session, RD_LOB_CHANGE_CHUNK, chunk, sizeof(lob_chunk_t), LOG_ENTRY_FLAG_NONE);
        }

        buf_leave_page(session, GS_TRUE);
    } else {
        buf_enter_page(session, del_undo->first_page, LATCH_MODE_X, ENTER_PAGE_NORMAL);
        chunk = LOB_GET_CHUNK(session);
        if (page_is_damaged((page_head_t *)CURR_PAGE(session)) || (chunk->del_xid.value != ud_row->xid.value)) {
            buf_leave_page(session, GS_FALSE);
            return;
        }

        chunk->is_recycled = GS_FALSE;
        chunk->del_xid.value = GS_INVALID_ID64;
        if (SPC_IS_LOGGING_BY_PAGEID(session, del_undo->first_page)) {
            log_put(session, RD_LOB_CHANGE_CHUNK, chunk, sizeof(lob_chunk_t), LOG_ENTRY_FLAG_NONE);
        }

        buf_leave_page(session, GS_TRUE);

        buf_enter_page(session, del_undo->last_page, LATCH_MODE_X, ENTER_PAGE_NORMAL);

        if (page_is_damaged((page_head_t *)CURR_PAGE(session))) {
            buf_leave_page(session, GS_FALSE);
            return;
        }

        chunk = LOB_GET_CHUNK(session);
        if (IS_INVALID_PAGID(chunk->free_next)) {
            buf_leave_page(session, GS_FALSE);
        } else {
            chunk->free_next = INVALID_PAGID;
            if (SPC_IS_LOGGING_BY_PAGEID(session, del_undo->last_page)) {
                log_put(session, RD_LOB_CHANGE_CHUNK, chunk, sizeof(lob_chunk_t), LOG_ENTRY_FLAG_NONE);
            }

            buf_leave_page(session, GS_TRUE);
        }
    }
}

void lob_undo_insert(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot,
                     knl_dictionary_t *dc)
{
    lob_undo_t *lob_undo;
    lob_locator_t *locator;
    page_id_t page_id;

    lob_undo = (lob_undo_t *)ud_row->data;
    locator = &lob_undo->locator;
    page_id = MAKE_PAGID((uint16)ud_row->seg_file, (uint32)ud_row->seg_page);
    if (!spc_validate_page_id(session, page_id)) {
        return;
    }

    knl_panic_log(locator->head.size != 0, "locator size is zero, panic info: page %u-%u", page_id.file, page_id.page);

    lob_free_insert_pages(session, page_id, lob_undo->part_no, locator);
}

void lob_undo_write_page(knl_session_t *session, undo_row_t *undo_row)
{
    page_id_t lob_entry;
    lob_undo_alloc_page_t *lob_undo;

    lob_undo = (lob_undo_alloc_page_t *)undo_row->data;
    lob_entry = MAKE_PAGID((uint16)undo_row->seg_file, (uint32)undo_row->seg_page);
    if (!spc_validate_page_id(session, lob_entry)) {
        return;
    }

    lob_release_alloc_page(session, lob_entry, lob_undo);
}

status_t lob_write_2pc_buff(knl_session_t *session, binary_t *buf, uint32 max_size)
{
    lob_item_list_t item_list = session->rm->lob_items;
    lob_item_t *lob_item = NULL;
    errno_t ret;

    if (item_list.count == 0) {
        return GS_SUCCESS;
    }

    lob_item = item_list.first;

    while (lob_item != NULL) {
        if (buf->size >= max_size) {
            GS_THROW_ERROR(ERR_TOO_MANY_OBJECTS, buf->size, "XA extend buffer size");
            return GS_ERROR;
        }

        ret = memcpy_sp(buf->bytes + buf->size, sizeof(lob_pages_info_t),
                        &lob_item->pages_info, sizeof(lob_pages_info_t));
        knl_securec_check(ret);
        buf->size += sizeof(lob_pages_info_t);
        lob_item = lob_item->next_item;
    }

    return GS_SUCCESS;
}

status_t lob_create_2pc_items(knl_session_t *session, uint8 *buf, uint32 buf_size, lob_item_list_t *item_list)
{
    lob_item_t *lob_item = NULL;
    lob_pages_info_t pages_info;
    uint32 offset = 0;
    lob_t *lob = NULL;
    knl_dictionary_t dc;
    dc_entity_t *entity = NULL;
    errno_t ret;

    knl_panic(item_list->count == 0);
    if (buf_size == 0) {
        return GS_SUCCESS;
    }

    while (offset != buf_size) {
        ret = memcpy_sp(&pages_info, sizeof(lob_pages_info_t), buf + offset, sizeof(lob_pages_info_t));
        knl_securec_check(ret);
        if (knl_open_dc_by_id((knl_handle_t)session, pages_info.uid, pages_info.table_id, &dc,
                              GS_TRUE) != GS_SUCCESS) {
            return GS_ERROR;
        }

        entity = DC_ENTITY(&dc);
        lob = (lob_t *)dc_get_column(entity, pages_info.col_id)->lob;
        if (lob_item_alloc(session, lob, pages_info.part_loc, &lob_item) != GS_SUCCESS) {
            dc_close(&dc);
            return GS_ERROR;
        }

        lob_item->pages_info.del_pages = pages_info.del_pages;
        lob_item_add(item_list, lob_item);

        offset += sizeof(lob_pages_info_t);
        dc_close(&dc);
    }

    return GS_SUCCESS;
}

static bool32 lob_find_max_column(uint16 *lob_cols, uint32 columns, uint32 col_id)
{
    uint32 j = 0;

    for (j = 0; j < columns; j++) {
        if (lob_cols[j] == col_id) {
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

static uint32 lob_max_lob_column(knl_cursor_t *cursor, knl_update_info_t *info, uint32 *max_col_size,
                                 uint16 *lob_cols)
{
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    knl_column_t *column = NULL;
    uint32 col_id = GS_INVALID_ID32;
    uint32 i;
    uint16 max_size = 0;
    uint16 col_size;
    lob_locator_t *locator = NULL;
    uint32 uid = 0;
    knl_cal_col_size_t  calc_col_size_func = cursor->row->is_csf ?
        heap_calc_csf_col_actualsize : heap_calc_bmp_col_actualsize;

    for (i = 0; i < entity->column_count; i++) {
        column = dc_get_column(entity, i);
        if (uid < info->count && column->id == info->columns[uid]) {
            uid++;
            continue;
        }

        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        if (CURSOR_COLUMN_SIZE(cursor, i) == GS_NULL_VALUE_LEN) {
            continue;
        }

        locator = (lob_locator_t *)((char *)cursor->row + cursor->offsets[i]);
        if (!LOB_IS_INLINE(locator)) {
            continue;
        }

        if (CURSOR_COLUMN_SIZE(cursor, i) <= sizeof(lob_locator_t)) {
            continue;
        }

        if (lob_find_max_column(lob_cols, entity->column_count, i)) {
            continue;
        }

        col_size = calc_col_size_func(cursor->row, cursor->lens, i);
        if (max_size <= col_size) {
            col_id = i;
            max_size = col_size;
        }
    }

    *max_col_size = max_size;

    return col_id;
}

static uint32 lob_max_update_column(dc_entity_t *entity, knl_update_info_t *info, uint32 *max_col_size)
{
    knl_column_t *column = NULL;
    uint32 col_id = GS_INVALID_ID32;
    uint32 i;
    uint16 max_size = 0;
    uint16 col_size;
    lob_locator_t *locator = NULL;

    for (i = 0; i < info->count; i++) {
        column = dc_get_column(entity, info->columns[i]);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        if (info->lens[i] == GS_NULL_VALUE_LEN) {
            continue;
        }

        locator = (lob_locator_t *)((char *)info->data + info->offsets[i]);
        if (!LOB_IS_INLINE(locator)) {
            continue;
        }

        col_size = CM_ALIGN4(info->lens[i] + sizeof(uint16));
        if (max_size < col_size) {
            col_id = i;
            max_size = col_size;
        }
    }

    *max_col_size = max_size;

    return col_id;
}

static void lob_sort_reorganize_clos(uint16 *lob_cols, uint16 size)
{
    uint16 j, k, temp;

    for (uint16 i = 1; i < size; i++) {
        j = 0;
        while ((lob_cols[j] < lob_cols[i]) && (j < i)) {
            j++;
        }

        if (i != j) {
            temp = lob_cols[i];

            for (k = i; k > j; k--) {
                lob_cols[k] = lob_cols[k - 1];
            }
            lob_cols[j] = temp;
        }
    }
}

static status_t lob_force_write_outline(knl_session_t *session, knl_cursor_t *cursor, row_assist_t *ra, uint32 col_id)
{
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    errno_t err;
    lob_locator_t new_locator;
    binary_t locator_bin;
    text_t lob;
    lob_locator_t *src_locator = NULL;

    src_locator = (lob_locator_t *)((char *)cursor->row + cursor->offsets[col_id]);
    locator_bin.size = sizeof(lob_locator_t);
    locator_bin.bytes = (uint8 *)&new_locator;

    err = memset_sp(&new_locator, sizeof(lob_locator_t), 0xFF, sizeof(lob_locator_t));
    knl_securec_check(err);
    lob.len = src_locator->head.size;
    lob.str = LOB_INLINE_DATA(src_locator);
    if (knl_write_lob(session, cursor, (char *)&new_locator, dc_get_column(entity, col_id), GS_TRUE,
                      &lob) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (row_put_bin(ra, &locator_bin) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t lob_reorganize_update_info(knl_session_t *session, knl_cursor_t *cursor,
                                           knl_update_info_t *old_info, uint32 size, knl_update_info_t *new_info)
{
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    uint32 max_size;
    uint32 new_size = size;
    uint32 col_id = GS_INVALID_ID32;
    knl_add_update_column_t add_update_column;
    uint16 lob_count = 0;
    uint16 *lob_cols = NULL;
    errno_t err;
    bool32 is_csf = ((row_head_t *)old_info->data)->is_csf;
    uint32 max_row_len = heap_table_max_row_len(cursor->table, GS_MAX_ROW_SIZE, cursor->part_loc);

    lob_cols = (uint16 *)cm_push(session->stack, entity->column_count * sizeof(uint16));

    err = memset_sp(lob_cols, entity->column_count * sizeof(uint16), 0xFF, entity->column_count * sizeof(uint16));
    knl_securec_check(err);

    while (CM_ALIGN4(new_size) > max_row_len) {
        col_id = lob_max_lob_column(cursor, old_info, &max_size, lob_cols);
        if (col_id == GS_INVALID_ID32) {
            cm_pop(session->stack);
            GS_THROW_ERROR(ERR_RECORD_SIZE_OVERFLOW, "update row", size, max_row_len);
            return GS_ERROR;
        }

        lob_cols[lob_count] = col_id;
        lob_count++;
        new_size -= max_size - knl_lob_outline_size(is_csf);
    }
    /* we reorganize row(change inline lobs to outline lobs),must ensure array of lob columns order by desc */
    lob_sort_reorganize_clos(lob_cols, lob_count);

    add_update_column.new_info = new_info;
    add_update_column.old_info = old_info;
    add_update_column.add_columns = lob_cols;
    add_update_column.add_count = lob_count;

    if (heap_reorganize_update_info(session, cursor, &add_update_column, lob_force_write_outline) != GS_SUCCESS) {
        cm_pop(session->stack);
        return GS_ERROR;
    }

    cm_pop(session->stack);

    return GS_SUCCESS;
}

status_t lob_reorganize_columns(knl_session_t *session, knl_cursor_t *cursor, heap_update_assist_t *ua,
                                knl_update_info_t *lob_info, bool32 *changed)
{
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    knl_update_info_t *old_info = ua->info;
    knl_column_t *column = NULL;
    uint32 uid, col_id;
    uint32 max_size;
    lob_locator_t dst_locator;
    lob_locator_t *src_locator = NULL;
    lob_locator_t *new_locator = NULL;
    char *copy_row_dest = NULL;
    char *copy_row_src = NULL;
    char *copy_row_start = NULL;
    uint16 copy_size;
    text_t lob;
    errno_t err;
    bool32 is_csf = ((row_head_t *)old_info->data)->is_csf;
    uint32 max_row_len = heap_table_max_row_len(cursor->table, GS_MAX_ROW_SIZE, cursor->part_loc);
    uint16 update_info_size;

    for (;;) {
        uid = lob_max_update_column(entity, old_info, &max_size);
        if (uid == GS_INVALID_ID32) {
            break;
        }
        err = memset_sp(&dst_locator, sizeof(lob_locator_t), 0xFF, sizeof(lob_locator_t));
        knl_securec_check(err);
        src_locator = (lob_locator_t *)((char *)old_info->data + old_info->offsets[uid]);
        col_id = old_info->columns[uid];
        column = dc_get_column(entity, col_id);

        lob.len = src_locator->head.size;
        lob.str = LOB_INLINE_DATA(src_locator);

        if (knl_write_lob(session, cursor, (char *)&dst_locator, column, GS_TRUE, (void *)&lob) != GS_SUCCESS) {
            return GS_ERROR;
        }

        copy_row_start = heap_get_col_start((row_head_t *)old_info->data, old_info->offsets, old_info->lens, uid);
        copy_row_dest = copy_row_start + knl_lob_outline_size(is_csf);
        copy_row_src = copy_row_start + knl_lob_inline_size(is_csf, src_locator->head.size, GS_TRUE);

        new_locator =  knl_lob_col_new_start(is_csf, src_locator, lob.len);

        copy_size = (uint16)(((row_head_t *)old_info->data)->size - old_info->offsets[uid] -
            knl_lob_inline_size(is_csf, src_locator->head.size, GS_FALSE));
        heap_write_col_size(is_csf, copy_row_start, KNL_LOB_LOCATOR_SIZE);

        if (copy_size != 0) {
            err = memmove_s(copy_row_dest, copy_size, copy_row_src, copy_size);
            knl_securec_check(err);
        }

        err = memcpy_sp(new_locator, sizeof(lob_locator_t), &dst_locator, sizeof(lob_locator_t));
        knl_securec_check(err);

        cm_decode_row(old_info->data, old_info->offsets, old_info->lens, &update_info_size);
        ((row_head_t *)(old_info->data))->size = CM_ALIGN4(update_info_size);

        heap_update_prepare(session, cursor->row, cursor->offsets, cursor->lens, cursor->data_size, ua);
        if (ua->new_size <= max_row_len) {
            *changed = GS_FALSE;
            return GS_SUCCESS;
        }
    }

    /* no lob is updated to inline, then we try to move inline lob (which is not to be updated) outline */
    if (lob_reorganize_update_info(session, cursor, ua->info, cursor->data_size + ua->inc_size, lob_info) !=
        GS_SUCCESS) {
        return GS_ERROR;
    }

    cm_decode_row(lob_info->data, lob_info->offsets, lob_info->lens, NULL);
    *changed = GS_TRUE;

    return GS_SUCCESS;
}

void lob_update_seg_free_list(knl_session_t *session, lob_segment_t *segment, page_id_t first_page,
                              page_id_t last_page, uint32 chunk_count)
{
    page_id_t free_last_page = INVALID_PAGID;
    lob_chunk_t *chunk = NULL;

    if (segment->free_list.count == 0) {
        segment->free_list.first = first_page;
    } else {
        free_last_page = segment->free_list.last;
        buf_enter_page(session, free_last_page, LATCH_MODE_X, ENTER_PAGE_NORMAL);
        chunk = LOB_GET_CHUNK(session);
        knl_panic_log(IS_INVALID_PAGID(chunk->free_next),
                      "the chunk's free_next page is valid, panic info: free_last_page %u-%u type %u",
                      free_last_page.file, free_last_page.page, ((page_head_t *)CURR_PAGE(session))->type);
        chunk->free_next = first_page;
        if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
            log_put(session, RD_LOB_CHANGE_CHUNK, chunk, sizeof(lob_chunk_t), LOG_ENTRY_FLAG_NONE);
        }

        buf_leave_page(session, GS_TRUE);
    }

    segment->free_list.last = last_page;
    segment->free_list.count += chunk_count;

    if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
        log_put(session, RD_LOB_CHANGE_SEG, segment, sizeof(lob_segment_t), LOG_ENTRY_FLAG_NONE);
    }
}

/*
* this interface only use for recycle lob pages for sql engine, we must recycle inserted lob pages when insert failed
* result from primary key or unique key  violation using sql "on duplicate key" or reorganize update_info including
* lob columns
*/
status_t lob_recycle_pages(knl_session_t *session, knl_cursor_t *cursor, lob_t *lob,
                           lob_locator_t *locator)
{
    page_id_t first_page;
    page_id_t last_page;
    lob_chunk_t *chunk = NULL;
    uint32 chunk_count = 0;
    lob_segment_t *segment = NULL;
    uint64 free_pages;
    lob_entity_t  *lob_entity = NULL;
    lob_part_t    *lob_part = NULL;

    if (locator->head.size == 0) {
        return GS_SUCCESS;
    }

    first_page = locator->first;
    last_page = first_page;

    if (IS_PART_TABLE(cursor->table)) {
        lob_part = LOB_GET_PART(lob, cursor->part_loc.part_no);
        if (IS_PARENT_LOBPART(&lob_part->desc)) {
            lob_part = PART_GET_SUBENTITY(lob->part_lob, lob_part->subparts[cursor->part_loc.subpart_no]);
        }
        lob_entity = &lob_part->lob_entity;
    } else {
        lob_entity = &lob->lob_entity;
    }

    for (;;) {
        buf_enter_page(session, last_page, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        chunk = LOB_GET_CHUNK(session);
        chunk_count++;

        if (IS_INVALID_PAGID(chunk->next)) {
            buf_leave_page(session, GS_FALSE);
            break;
        }
        
        last_page = LOB_NEXT_DATA_PAGE(session);
        buf_leave_page(session, GS_FALSE);
    }
    log_atomic_op_begin(session);
    buf_enter_page(session, lob_entity->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    segment = LOB_SEG_HEAD(session);

    /*
     * check segment->free_list.count is bigger than INVALID_32 or not
     */
    free_pages = (uint64)segment->free_list.count + chunk_count;
    if (free_pages > GS_MAX_UINT32) {
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        GS_LOG_RUN_ERR("user-%d,table-%d,column-%d,part(%d-%d),too much free insert or update pages %lld", segment->uid,
                       segment->table_id, segment->column_id, cursor->part_loc.part_no, cursor->part_loc.subpart_no,
                       free_pages);
        GS_THROW_ERROR(ERR_TOO_MANY_OBJECTS, GS_MAX_UINT32, "lob free pages");
        return GS_ERROR;
    }

    buf_enter_page(session, first_page, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    chunk = LOB_GET_CHUNK(session);
    /*
     * lob pages of recycle only exist in ins_pages or  only exist in dele_pages
     * is_recycle is used to mark this locator pages in recycle pages(ins_pages or dele_pages) or not
     */
    if (chunk->is_recycled) {
        buf_leave_page(session, GS_FALSE);
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return GS_SUCCESS;
    } else {
        chunk = LOB_GET_CHUNK(session);
        chunk->is_recycled = GS_TRUE;
        if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
            log_put(session, RD_LOB_CHANGE_CHUNK, chunk, sizeof(lob_chunk_t), LOG_ENTRY_FLAG_NONE);
        }
        buf_leave_page(session, GS_TRUE);
    }

    lob_update_seg_free_list(session, segment, first_page, last_page, chunk_count);
    buf_leave_page(session, GS_TRUE);

    log_atomic_op_end(session);
    return GS_SUCCESS;
}

static bool32 lob_is_insert_before_shrink(knl_session_t *session, lob_segment_t *segment,
                                          lob_shrink_assist_t *assist, page_id_t pagid, xid_t xid)
{
    txn_info_t txn_info;
    space_t *space = SPACE_GET(session, segment->space_id);
    page_id_t first_page;
    page_id_t extent;
    page_head_t *page = NULL;
    itl_t itl;

    itl.is_active = GS_TRUE;
    itl.xid = xid;

    tx_get_itl_info(session, GS_TRUE, &itl, &txn_info);

    if (txn_info.scn <= assist->min_scn) {
        return GS_TRUE;
    }

    if (!txn_info.is_owscn) {
        return GS_FALSE;
    }

    first_page = spc_get_extent_first(session, space, pagid);
    extent = assist->new_extent;

    for (;;) {
        if (IS_SAME_PAGID(first_page, extent)) {
            return GS_FALSE;
        }

        if (IS_SAME_PAGID(extent, segment->extents.last)) {
            return GS_TRUE;
        }

        buf_enter_page(session, extent, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        page = (page_head_t *)CURR_PAGE(session);
        extent = AS_PAGID(page->next_ext);
        buf_leave_page(session, GS_FALSE);
    }

    return GS_TRUE;
}

static void lob_compact_extents(knl_session_t *session, lob_entity_t *lob_entity,
                                lob_shrink_assist_t *assist, uint32 new_free_count)
{
    lob_segment_t *segment = LOB_SEGMENT(session, lob_entity->entry, lob_entity->segment);
    page_id_t free_pagid = lob_entity->entry;
    space_t *space = SPACE_GET(session, segment->space_id);
    lob_chunk_t *chunk = NULL;
    bool32 need_log = SPACE_IS_LOGGING(space);
    page_list_t free_extents = assist->extents;
    page_head_t *page = NULL;
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(lob_entity->cipher_reserve_size);

    free_pagid.page++;

    for (uint32 i = 1; i < space->ctrl->extent_size; i++) {
        log_atomic_op_begin(session);
        buf_enter_page(session, free_pagid, LATCH_MODE_X, ENTER_PAGE_NO_READ);
        lob_init_page(session, free_pagid, PAGE_TYPE_LOB_DATA, GS_TRUE);

        if (need_log) {
            log_put(session, RD_LOB_PAGE_INIT, CURR_PAGE(session), sizeof(page_head_t), LOG_ENTRY_FLAG_NONE);
        }

        free_pagid.page++;
        chunk = LOB_GET_CHUNK(session);
        chunk->is_recycled = GS_TRUE;
        chunk->del_xid.value = GS_INVALID_ID64;
        chunk->ins_xid = session->rm->xid;
        chunk->size = 0;
        chunk->free_next = (i == space->ctrl->extent_size - 1) ? INVALID_PAGID : free_pagid;
        if (need_log) {
            log_encrypt_prepare(session, ((page_head_t *)session->curr_page)->type, need_encrypt);
            log_put(session, RD_LOB_PUT_CHUNK, chunk, sizeof(lob_chunk_t), LOG_ENTRY_FLAG_NONE);
        }
        buf_leave_page(session, GS_TRUE);
        log_atomic_op_end(session);
    }

    free_pagid = lob_entity->entry;
    free_pagid.page++;

    log_atomic_op_begin(session);
    dls_latch_x(session, &lob_entity->seg_latch, session->id, &session->stat_lob);
    buf_enter_page(session, lob_entity->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    segment = LOB_SEG_HEAD(session);
    page = (page_head_t *)CURR_PAGE(session);
    /* skip first extent of lob segment, which will not be shrinked. */
    free_extents.count--;
    free_extents.first = AS_PAGID(page->next_ext);
    /* assist->free_count contains first page of new extent which should keep in free list */
    segment->free_list.count -= new_free_count + assist->free_count - space->ctrl->extent_size;
    buf_enter_page(session, segment->free_list.last, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    chunk = LOB_GET_CHUNK(session);
    chunk->free_next = free_pagid;

    if (need_log) {
        log_put(session, RD_LOB_CHANGE_CHUNK, chunk, sizeof(lob_chunk_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);
    segment->free_list.first = assist->new_extent;
    segment->free_list.last = spc_get_extent_last(session, space, lob_entity->entry);

    segment->extents.count -= free_extents.count;

    if (free_extents.count > 0) {
        buf_enter_page(session, free_extents.last, LATCH_MODE_X, ENTER_PAGE_NORMAL);
        lob_init_page(session, free_extents.last, PAGE_TYPE_LOB_DATA, GS_TRUE);

        if (need_log) {
            log_put(session, RD_LOB_PAGE_INIT, (page_head_t *)CURR_PAGE(session),
                    sizeof(page_head_t), LOG_ENTRY_FLAG_NONE);
        }

        buf_leave_page(session, GS_TRUE);
        spc_free_extents(session, space, &free_extents);
    }

    /* concat new extent list to first extents, remove old extents */
    TO_PAGID_DATA(assist->new_extent, page->next_ext);
    segment->shrink_scn = db_inc_scn(session);
    if (need_log) {
        log_put(session, RD_LOB_CHANGE_SEG, segment, sizeof(lob_segment_t), LOG_ENTRY_FLAG_NONE);
        log_put(session, RD_SPC_CONCAT_EXTENT, &assist->new_extent, sizeof(page_id_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);
    dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);

    log_atomic_op_end(session);
}

static status_t lob_reorganize_free_list(knl_session_t *session, lob_entity_t *lob_entity, lob_shrink_assist_t *assist)
{
    lob_segment_t *segment = LOB_SEGMENT(session, lob_entity->entry, lob_entity->segment);
    page_id_t free_pagid;
    lob_chunk_t *chunk = NULL;
    page_id_t prev_pagid;
    page_id_t last_pagid;
    page_id_t next_pagid = INVALID_PAGID;
    uint32    skipped_pages = 0;
    space_t *space = SPACE_GET(session, segment->space_id);
    bool32    need_log = SPACE_IS_LOGGING(space);
    xid_t     ins_xid;
    status_t status = GS_SUCCESS;

    log_atomic_op_begin(session);
    dls_latch_x(session, &lob_entity->seg_latch, session->id, &session->stat_lob);

    /*
     * if segment->free_list == assist->free_count, there is no lob pages added to free_list
     * after shrink begin, no need to reorganize free list.
     */
    if (segment->free_list.count == assist->free_count) {
        dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);
        log_atomic_op_end(session);
        lob_compact_extents(session, lob_entity, assist, 0);
        return GS_SUCCESS;
    }

    if (buf_read_page(session, assist->last_free_pagid, LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
        dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);
        log_atomic_op_end(session);
        return GS_ERROR;
    }

    chunk = LOB_GET_CHUNK(session);
    free_pagid = chunk->free_next;
    buf_leave_page(session, GS_FALSE);
    prev_pagid = assist->last_free_pagid;
    last_pagid = segment->free_list.last;
    dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);
    log_atomic_op_end(session);

    for (;;) {
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

        if (buf_read_page(session, free_pagid, LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }
        chunk = LOB_GET_CHUNK(session);
        ins_xid = chunk->ins_xid;
        next_pagid = chunk->free_next;
        buf_leave_page(session, GS_FALSE);

        if (lob_is_insert_before_shrink(session, segment, assist, free_pagid, ins_xid)) {
            skipped_pages++;
            log_atomic_op_begin(session);
            dls_latch_x(session, &lob_entity->seg_latch, session->id, &session->stat_lob);
            buf_enter_page(session, lob_entity->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);

            buf_enter_page(session, prev_pagid, LATCH_MODE_X, ENTER_PAGE_NORMAL);
            chunk = LOB_GET_CHUNK(session);
            chunk->free_next = next_pagid;

            if (need_log) {
                log_put(session, RD_LOB_CHANGE_CHUNK, (const void *)chunk, sizeof(lob_chunk_t), LOG_ENTRY_FLAG_NONE);
            }
            buf_leave_page(session, GS_TRUE);

            buf_enter_page(session, free_pagid, LATCH_MODE_X, ENTER_PAGE_NORMAL);
            chunk = LOB_GET_CHUNK(session);
            chunk->free_next = segment->free_list.first;
            if (need_log) {
                log_put(session, RD_LOB_CHANGE_CHUNK, (const void *)chunk, sizeof(lob_chunk_t), LOG_ENTRY_FLAG_NONE);
            }
            buf_leave_page(session, GS_TRUE);

            segment->free_list.first = free_pagid;

            if (IS_SAME_PAGID(free_pagid, segment->free_list.last)) {
                segment->free_list.last = prev_pagid;
            }

            if (need_log) {
                log_put(session, RD_LOB_CHANGE_SEG, (const void *)segment, sizeof(lob_segment_t), LOG_ENTRY_FLAG_NONE);
            }
            buf_leave_page(session, GS_TRUE);
            dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);
            log_atomic_op_end(session);
        } else {
            prev_pagid = free_pagid;
        }

        if (IS_SAME_PAGID(free_pagid, last_pagid)) {
            break;
        }

        free_pagid = next_pagid;
    }

    if (status != GS_SUCCESS) {
        return GS_ERROR;
    }

    lob_compact_extents(session, lob_entity, assist, skipped_pages);

    return GS_SUCCESS;
}

status_t lob_prepare_shrink(knl_session_t *session, knl_cursor_t *cursor, lob_entity_t *lob_entity,
    lob_shrink_assist_t *assist)
{
    lob_segment_t *segment = NULL;
    space_t *space = NULL;
    lob_chunk_t *chunk = NULL;
    bool32 need_redo = GS_TRUE;

    segment = LOB_SEGMENT(session, lob_entity->entry, lob_entity->segment);

    space = SPACE_GET(session, segment->space_id);
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(lob_entity->cipher_reserve_size);
    need_redo = SPACE_IS_LOGGING(space);

    log_atomic_op_begin(session);

    if (spc_alloc_extent(session, space, space->ctrl->extent_size, &assist->new_extent, GS_FALSE) != GS_SUCCESS) {
        log_atomic_op_end(session);
        return GS_ERROR;
    }

    buf_enter_page(session, assist->new_extent, LATCH_MODE_X, ENTER_PAGE_NO_READ);
    lob_init_page(session, assist->new_extent, PAGE_TYPE_LOB_DATA, GS_TRUE);

    if (need_redo) {
        log_put(session, RD_LOB_PAGE_INIT, (page_head_t *)CURR_PAGE(session), sizeof(page_head_t), LOG_ENTRY_FLAG_NONE);
    }

    chunk = LOB_GET_CHUNK(session);
    chunk->is_recycled = GS_TRUE;
    chunk->del_xid.value = GS_INVALID_ID64;
    chunk->ins_xid.value = GS_INVALID_ID64;
    chunk->size = 0;
    chunk->free_next = INVALID_PAGID;

    if (need_redo) {
        log_encrypt_prepare(session, ((page_head_t *)session->curr_page)->type, need_encrypt);
        log_put(session, RD_LOB_PUT_CHUNK, chunk, sizeof(lob_chunk_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);

    dls_latch_x(session, &lob_entity->seg_latch, session->id, &session->stat_lob);
    assist->extents = segment->extents;
    assist->min_scn = DB_CURR_SCN(session);
    lob_entity->shrinking = GS_TRUE;
    spc_concat_extent(session, segment->extents.last, assist->new_extent);
    buf_enter_page(session, lob_entity->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    /* set first page of new extent recycled, and set second page of new extent as ufp first */
    segment->ufp_count = space->ctrl->extent_size - 1;
    segment->ufp_first = assist->new_extent;
    segment->ufp_first.page++;
    segment->ufp_extent = INVALID_PAGID;
    segment->extents.count++;
    segment->extents.last = assist->new_extent;

    buf_enter_page(session, segment->free_list.last, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    chunk = LOB_GET_CHUNK(session);
    chunk->free_next = assist->new_extent;

    if (need_redo) {
        log_put(session, RD_LOB_CHANGE_CHUNK, (const void *)chunk, sizeof(lob_chunk_t), LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, GS_TRUE);

    segment->free_list.last = assist->new_extent;
    segment->free_list.count++;

    if (need_redo) {
        log_put(session, RD_LOB_CHANGE_SEG, segment, sizeof(lob_segment_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);

    assist->free_count = segment->free_list.count;
    assist->last_free_pagid = segment->free_list.last;

    dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);
    log_atomic_op_end(session);

    return GS_SUCCESS;
}

static status_t lob_shrink_segment(knl_session_t *session, knl_cursor_t *cursor, knl_column_t *column,
                                   lob_entity_t *lob_entity, lob_shrink_assist_t *assist)
{
    lob_segment_t *segment = NULL;
    lob_locator_t *locator = NULL;
    uint16 len;
    row_assist_t ra;
    status_t status = GS_SUCCESS;
    bool32 is_csf = knl_is_table_csf(cursor->dc_entity, cursor->part_loc);

    segment = LOB_SEGMENT(session, lob_entity->entry, lob_entity->segment);
    if (segment == NULL) {
        return GS_SUCCESS;
    }

    for (;;) {
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

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        if (cursor->eof) {
            break;
        }

        len = CURSOR_COLUMN_SIZE(cursor, column->id);
        if (len == GS_NULL_VALUE_LEN) {
            continue;
        }

        locator = (lob_locator_t *)CURSOR_COLUMN_DATA(cursor, column->id);
        if (!locator->head.is_outline || locator->head.size == 0) {
            continue;
        }

        cm_row_init(&ra, cursor->update_info.data, DEFAULT_PAGE_SIZE(session), 1, is_csf);

        if (knl_row_move_lob(session, cursor, column, (knl_handle_t)locator,
            (knl_handle_t)&ra) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        row_end(&ra);

        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);

        if (knl_internal_update(session, cursor) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        knl_commit(session);
    }

    if (status != GS_SUCCESS) {
        dls_latch_x(session, &lob_entity->seg_latch, session->id, &session->stat_lob);
        lob_entity->shrinking = GS_FALSE;
        dls_unlatch(session, &lob_entity->seg_latch, &session->stat_lob);
        knl_rollback(session, NULL);
        return status;
    }

    knl_commit(session);
    return GS_SUCCESS;
}

status_t lob_shrink_space(knl_session_t *session, knl_cursor_t *cursor, knl_column_t *column)
{
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    lob_shrink_assist_t assist = {0};
    table_t *table = (table_t *)cursor->table;
    lob_entity_t *lob_entity = NULL;
    table_part_t *table_part = NULL;
    lob_part_t *lob_part = NULL;
    part_lob_t *part_lob = ((lob_t *)column->lob)->part_lob;
    status_t status = GS_SUCCESS;

    if (IS_PART_TABLE(table)) {
        table_part = TABLE_GET_PART(table, cursor->part_loc.part_no);
        if (!IS_READY_PART(table_part)) {
            return GS_SUCCESS;
        }

        lob_part = LOB_GET_PART(column->lob, cursor->part_loc.part_no);
        if (lob_part == NULL) {
            return GS_SUCCESS;
        }

        if (IS_PARENT_TABPART(&table_part->desc) && cursor->part_loc.subpart_no != GS_INVALID_ID32) {
            lob_part = PART_GET_SUBENTITY(part_lob, lob_part->subparts[cursor->part_loc.subpart_no]);
            if (lob_part == NULL) {
                return GS_SUCCESS;
            }
        }
        lob_entity = &lob_part->lob_entity;
    } else {
        lob_entity = &((lob_t *)column->lob)->lob_entity;
    }

    if (lob_entity->segment == NULL) {
        return GS_SUCCESS;
    }

    if (LOB_SEGMENT(session, lob_entity->entry, lob_entity->segment)->extents.count < LOB_MIN_SHRINK_EXTENTS ||
        LOB_SEGMENT(session, lob_entity->entry, lob_entity->segment)->free_list.count == 0) {
        return GS_SUCCESS;
    }

    lob_entity->shrinking = GS_TRUE;

    for (;;) {
        if (lob_prepare_shrink(session, cursor, lob_entity, &assist) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        /* degrade table lock because shrink segment may cost a lot of time */
        lock_degrade_table_lock(session, entity);

        if (lob_shrink_segment(session, cursor, column, lob_entity, &assist) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        /* upgrade table lock to wait for concurrent transacitons end */
        if (lock_upgrade_table_lock(session, entity, LOCK_INF_WAIT) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        /* degrade table lock because reorganize free list may cost a lot of time */
        lock_degrade_table_lock(session, entity);

        status = lob_reorganize_free_list(session, lob_entity, &assist);

        /* upgrade table lock to invalid dc */
        if (lock_upgrade_table_lock(session, entity, LOCK_INF_WAIT) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        knl_set_session_scn(session, GS_INVALID_ID64);
        
        if (db_update_table_chgscn(session, &table->desc) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        knl_commit(session);
        break;
    }

    lob_entity->shrinking = GS_FALSE;
    return status;
}

status_t lob_dump_page(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump)
{
    lob_data_page_t *page = (lob_data_page_t *)page_head;
    lob_chunk_t *chunk = &page->chunk;
    cm_dump(dump, "lob page chunk information:\n");
    cm_dump(dump, "\tinsert_xid: xmap %u-%u, xnum %u\n",
        (uint32)chunk->ins_xid.xmap.seg_id, (uint32)chunk->ins_xid.xmap.slot, chunk->ins_xid.xnum);
    cm_dump(dump, "\tdelete_xid: xmap %u-%u, xnum %u\n",
        (uint32)chunk->del_xid.xmap.seg_id, (uint32)chunk->del_xid.xmap.slot, chunk->del_xid.xnum);
    cm_dump(dump, "\torg_scn: %llu\n ", chunk->org_scn);
    cm_dump(dump, "\tsize: %u\n", chunk->size);
    cm_dump(dump, "\tnext: %u-%u\n", (uint32)chunk->next.file, (uint32)chunk->next.page);
    cm_dump(dump, "\tfree_next: %u-%u\n",
        (uint32)chunk->free_next.file, (uint32)chunk->free_next.page);
    cm_dump(dump, "\tis_recycled: %u\n", (uint32)chunk->is_recycled);
    CM_DUMP_WRITE_FILE(dump);

    return GS_SUCCESS;
}

status_t lob_segment_dump(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump)
{
    lob_segment_t *segment = LOB_SEG_HEAD(session);
    cm_dump(dump, "lob segment information\n");
    cm_dump(dump, "\ttable info: uid %u, table_id %u, space_id %u\n",
        segment->uid, segment->table_id, segment->space_id);
    cm_dump(dump, "\torg_scn: %llu", segment->org_scn);
    cm_dump(dump, "\tseg_scn: %llu\n", segment->seg_scn);
    cm_dump(dump, "\tshrink_scn: %llu\n", segment->shrink_scn);
    CM_DUMP_WRITE_FILE(dump);

    cm_dump(dump, "lob storage information\n");
    cm_dump(dump, "\textents: count %u, first %u-%u, last %u-%u\n", segment->extents.count,
        segment->extents.first.file, segment->extents.first.page,
        segment->extents.last.file, segment->extents.last.page);
    cm_dump(dump, "\tfree_list: count %u, first %u-%u, last %u-%u\n",
        segment->free_list.count,
        segment->free_list.first.file, segment->free_list.first.page,
        segment->free_list.last.file, segment->free_list.last.page);
    cm_dump(dump, "\tufp_count: %u\n", segment->ufp_count);
    cm_dump(dump, "\tufp_first: %u-%u\n", segment->ufp_first.file, segment->ufp_first.page);
    cm_dump(dump, "\tufp_extent: %u-%u\n", segment->ufp_extent.file, segment->ufp_extent.page);
    CM_DUMP_WRITE_FILE(dump);

    return GS_SUCCESS;
}

status_t lob_check_page_belong_subpart(knl_session_t *session, lob_data_page_t *lob_page, uint32 *table_id,
    uint32 *uid, bool32 *belong)
{
    knl_scn_t org_scn;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SUB_LOB_PARTS_ID, GS_INVALID_ID32);
    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        org_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, SYS_LOBSUBPART_COL_ORG_SCN);
        if (org_scn == lob_page->chunk.org_scn) {
            *uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_LOBSUBPART_COL_USER_ID);
            *table_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_LOBSUBPART_COL_TABLE_ID);
            *belong = GS_TRUE;
            break;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t lob_check_page_belong_part(knl_session_t *session, lob_data_page_t *lob_page, uint32 *table_id,
    uint32 *uid, bool32 *belong)
{
    knl_scn_t org_scn;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_LOBPART_ID, GS_INVALID_ID32);
    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        org_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, SYS_LOBPART_COL_ORG_SCN);
        if (org_scn == lob_page->chunk.org_scn) {
            *uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_LOBPART_COL_USER_ID);
            *table_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_LOBPART_COL_TABLE_ID);
            *belong = GS_TRUE;
            break;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t lob_check_page_belong_table(knl_session_t *session, lob_data_page_t *lob_page, uint32 *table_id,
    uint32 *uid, bool32 *belong)
{
    knl_scn_t org_scn;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_LOB_ID, GS_INVALID_ID32);
    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        org_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, SYS_LOB_COL_ORG_SCN);
        if (org_scn == lob_page->chunk.org_scn) {
            *uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_LOB_COL_USER_ID);
            *table_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_LOB_COL_TABLE_ID);
            *belong = GS_TRUE;
            break;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t lob_get_table_by_page(knl_session_t *session, page_head_t *page, uint32 *uid, uint32 *table_id)
{
    bool32 belong = GS_FALSE;
    lob_data_page_t *lob_page = (lob_data_page_t *)page;

    if (lob_page->chunk.is_recycled) {
        GS_THROW_ERROR(ERR_PAGE_NOT_BELONG_TABLE, page_type(lob_page->head.type));
        return GS_ERROR;
    }

    if (lob_check_page_belong_table(session, lob_page, table_id, uid, &belong) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_PAGE_NOT_BELONG_TABLE, page_type(lob_page->head.type));
        return GS_ERROR;
    }

    if (belong) {
        return GS_SUCCESS;
    }
    
    if (lob_check_page_belong_part(session, lob_page, table_id, uid, &belong) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_PAGE_NOT_BELONG_TABLE, page_type(lob_page->head.type));
        return GS_ERROR;
    }

    if (belong) {
        return GS_SUCCESS;
    }

    if (lob_check_page_belong_subpart(session, lob_page, table_id, uid, &belong) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_PAGE_NOT_BELONG_TABLE, page_type(lob_page->head.type));
        return GS_ERROR;
    }

    if (!belong) {
        GS_THROW_ERROR(ERR_PAGE_NOT_BELONG_TABLE, page_type(lob_page->head.type));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t lob_corruption_scan(knl_session_t *session, lob_segment_t *segment, knl_corrupt_info_t *corrupt_info)
{
    heap_page_t *page = NULL;
    page_id_t last_pageid = segment->ufp_extent;
    page_id_t curr_pageid = segment->extents.first;
    uint32 ext_size = ((space_t*)SPACE_GET(session, segment->space_id))->ctrl->extent_size;

    for (uint32 i = 0; i < segment->extents.count; i++) {
        for (uint32 j = 0; j < ext_size; j++) {
            if (knl_check_session_status(session) != GS_SUCCESS) {
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
                curr_pageid = AS_PAGID(page->head.next_ext);
            }
            buf_leave_page(session, GS_FALSE);
        }
    }

    return GS_SUCCESS;
}

status_t lob_check_space(knl_session_t *session, table_t *table, uint32 space_id)
{
    space_t *space = NULL;

    space = SPACE_GET(session, space_id);
    if (IS_SWAP_SPACE(space)) {
        GS_THROW_ERROR(ERR_PERMANENTOBJ_IN_TEMPSPACE);
        return GS_ERROR;
    }

    if (IS_UNDO_SPACE(space)) {
        GS_THROW_ERROR(ERR_MISUSE_UNDO_SPACE, space->ctrl->name);
        return GS_ERROR;
    }

    if (table->desc.type == TABLE_TYPE_NOLOGGING) {
        if (SPACE_IS_LOGGING(space)) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create logging lob", "nologging table");
            return GS_ERROR;
        }
    } else {
        if (SPACE_IS_NOLOGGING(space)) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create nologging lob", "logging table");
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

#ifdef LOG_DIAG
void lob_validate_page(knl_session_t *session, page_head_t *page)
{
    space_t *space = SPACE_GET(session, DATAFILE_GET(session, AS_PAGID_PTR(page->id)->file)->space_id);

    CM_SAVE_STACK(session->stack);
    lob_data_page_t *copy_page = (lob_data_page_t *)cm_push(session->stack, DEFAULT_PAGE_SIZE(session));
    errno_t ret = memcpy_sp(copy_page, DEFAULT_PAGE_SIZE(session), page, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);

    // check chunk size
    lob_chunk_t *chunk = &copy_page->chunk;
    knl_panic_log(chunk->size <= LOB_MAX_CHUNK_SIZE(session) - space->ctrl->cipher_reserve_size,
                  "chunk size is abnormal, "
                  "panic info: page %u-%u type %u chunk size %u cipher_reserve_size %u", AS_PAGID(page->id).file,
                  AS_PAGID(page->id).page, page->type, chunk->size, space->ctrl->cipher_reserve_size);

    // check page size
    knl_panic_log(sizeof(lob_data_page_t) + chunk->size <= DEFAULT_PAGE_SIZE(session) - sizeof(page_tail_t) -
        space->ctrl->cipher_reserve_size, "chunk size is abnormal, panic info: page %u-%u type %u chunk size %u "
        "cipher_reserve_size %u", AS_PAGID(page->id).file, AS_PAGID(page->id).page, page->type, chunk->size,
        space->ctrl->cipher_reserve_size);

    CM_RESTORE_STACK(session->stack);
}
#endif
