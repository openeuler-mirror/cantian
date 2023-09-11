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
 * knl_map.c
 *
 *
 * IDENTIFICATION
 * src/kernel/table/knl_map.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_map.h"
#include "knl_heap.h"
#include "pcr_heap.h"
#include "knl_context.h"
#include "knl_table.h"
#include "knl_space_manage.h"
#include "dtc_dls.h"
#include "dtc_dc.h"
#include "rc_reform.h"

static inline void heap_insert_into_list(map_page_t *page, map_list_t *list, uint16 slot);
static inline void heap_format_page(knl_session_t *session, heap_segment_t *segment, heap_page_t *page,
                                    page_id_t page_id, uint32 extent_size);

static inline uint32 heap_get_next_ext_size(knl_session_t *session, heap_segment_t *segment)
{
    return spc_get_ext_size(SPACE_GET(session, segment->space_id), segment->extents.count);
}

static inline uint32 heap_get_curr_ext_size(space_t *space, heap_segment_t *segment)
{
    // if page_count > 0, master be bitmap and degrade happened.
    if (segment->page_count != 0) {
        knl_panic(SPACE_IS_AUTOALLOCATE(space));
        return spc_ext_size_by_id(segment->last_ext_size);
    }
    return spc_get_ext_size(space, segment->extents.count - 1);
}

static void heap_init_segment_page_count(space_t *space, heap_segment_t *segment, uint32 origin_page_count,
    uint32 free_page_count)
{
    // free_extents count is 0 means only keep one extent in extents
    // page_count(origin_page_count) is 0 means no degrade happened, just reset
    if (segment->free_extents.count == 0 || origin_page_count == 0) {
        heap_reset_page_count(segment);
    } else {
        segment->page_count = space->ctrl->extent_size;
        segment->free_page_count = free_page_count;
        // only 1 extent in segment extents, it is original size
        segment->last_ext_size = space->ctrl->extent_size;
    }
    return;
}

/*
 * init map list range
 * using user defined pctfree to init each map list range
 * @param kernel session, heap segment, pctfree
 */
void heap_set_pctfree(knl_session_t *session, heap_segment_t *segment, uint32 pctfree)
{
    uint32 reserve_size;
    uint32 request_size;
    uint32 free_size;
    space_t *space = SPACE_GET(session, segment->space_id);

    // the max value of pctfree is 80, so the max percent of free space is 80%.
    reserve_size = pctfree * DEFAULT_PAGE_SIZE(session) / 100;

    if (segment->cr_mode == CR_PAGE) {
        request_size = PCRH_MAX_ROW_SIZE(session) + sizeof(pcr_row_dir_t) + sizeof(pcr_itl_t);
    } else {
        request_size = HEAP_MAX_ROW_SIZE(session) + sizeof(row_dir_t) + sizeof(itl_t);
    }

    free_size = request_size - reserve_size - space->ctrl->cipher_reserve_size;

    /*
     * the available space of one unused page will be devided into 4 parts.
     */
    segment->list_range[0] = 0;
    segment->list_range[1] = reserve_size;
    segment->list_range[2] = segment->list_range[1] + free_size / MAP_LIST_EQUAL_DIVISON_NUM;
    segment->list_range[3] = segment->list_range[2] + free_size / MAP_LIST_EQUAL_DIVISON_NUM;
    segment->list_range[4] = segment->list_range[3] + free_size / MAP_LIST_EQUAL_DIVISON_NUM;
    segment->list_range[5] = request_size;
}

static void heap_init_segment(knl_session_t *session, knl_table_desc_t *desc, page_list_t *free_extents,
    uint32 free_page_count, bool32 add_extent, bool32 reverve_flag)
{
    space_t *space = SPACE_GET(session, desc->space_id);
    heap_segment_t *segment = HEAP_SEG_HEAD(session);
    page_head_t *page_head = (page_head_t *)CURR_PAGE(session);
    rd_heap_format_page_t redo;
    uint32 extent_size = space->ctrl->extent_size;
    page_id_t extent = desc->entry;
    bool32 is_compress = GS_FALSE;
    uint32 add_cnt;

    // used by update page count
    uint32 origin_page_count = segment->page_count;
    if (reverve_flag) {
        is_compress = segment->compress;
    } else {
        is_compress = desc->compress;
    }
    add_cnt = is_compress ? (PAGE_GROUP_COUNT - 1) : HEAP_SEGMENT_MIN_PAGES;

    page_init(session, (page_head_t *)CURR_PAGE(session), extent, PAGE_TYPE_HEAP_HEAD);
    page_head->ext_size = spc_ext_id_by_size(extent_size);
    if (SPACE_IS_LOGGING(space)) {
        redo.page_id = extent;
        redo.extent_size = extent_size;
        log_put(session, RD_HEAP_FORMAT_ENTRY, &redo, sizeof(rd_heap_format_page_t), LOG_ENTRY_FLAG_NONE);
    }

    segment->uid = (uint16)desc->uid;  // the max value of uid is GS_MAX_USERS(15000)
    segment->oid = desc->id;
    segment->org_scn = desc->org_scn;
    segment->seg_scn = db_inc_scn(session);
    knl_panic(segment->seg_scn > segment->org_scn);
    segment->initrans = (uint8)desc->initrans;
    segment->space_id = desc->space_id;
    segment->serial = desc->serial_start;
    segment->cr_mode = desc->cr_mode;
    knl_panic(desc->cr_mode == CR_PAGE || desc->cr_mode == CR_ROW);

    segment->extents.count = 1;
    segment->extents.first = extent;
    segment->extents.last = extent;
    segment->free_extents = *free_extents;
    segment->free_ufp = INVALID_PAGID;
    segment->ufp_count = extent_size - 1;

    segment->data_first = INVALID_PAGID;
    segment->data_last = INVALID_PAGID;
    segment->cmp_hwm = INVALID_PAGID;
    segment->shrinkable_scn = GS_INVALID_ID64;
    segment->compress = is_compress;

    segment->tree_info.level = 0;
    TO_PAGID_DATA(INVALID_PAGID, segment->tree_info.root);
    segment->curr_map[0] = INVALID_PAGID;

    heap_set_pctfree(session, segment, desc->pctfree);

    extent.page++;

    /*
     * The first page of the first segment has been set to segment page
     * Add two pages this time , one is for map page , the other one is heap page
     */
    if (add_extent) {
        add_cnt = (extent_size - 1) > HEAP_PAGE_FORMAT_UNIT ? HEAP_PAGE_FORMAT_UNIT : (extent_size - 1);
    }

    knl_panic(!is_compress || add_cnt == PAGE_GROUP_COUNT - 1);
    heap_add_ufp(session, segment, extent, add_cnt, !is_compress);
    extent.page += add_cnt;
    segment->ufp_count -= add_cnt;
    segment->free_ufp = (segment->ufp_count == 0) ? INVALID_PAGID : extent;

    // update segment page count
    heap_init_segment_page_count(space, segment, origin_page_count, free_page_count);

    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_HEAP_CHANGE_SEG, segment, HEAP_SEG_SIZE, LOG_ENTRY_FLAG_NONE);
    }
}

// update segment page count and free page count
// WARNING need to be done after buf enter page
static inline void heap_try_update_segment_pagecount(heap_segment_t *segment, uint32 ext_size)
{
    // 0 means still use calcation logic, firstly calc the page count, than update.
    if (segment->page_count == 0) {
        return;
    }

    segment->page_count += ext_size;
    segment->last_ext_size = spc_ext_id_by_size(ext_size);
}

static inline void heap_del_segment_free_count(heap_segment_t *segment, uint32 free_size)
{
    // page_count 0 means still use calcation logic, firstly calc the page count, than update.
    // same sa update segment page count
    if (segment->page_count == 0) {
        return;
    }
    knl_panic(free_size != 0);
    knl_panic(segment->free_page_count >= free_size);
    segment->free_page_count -= free_size;
}

static void heap_try_init_segment_pagecount(space_t *space, heap_segment_t *segment)
{
    if (segment->page_count == 0) {
        // print log when first degrade happened
        GS_LOG_RUN_INF("heap segment degraded alloc extent, space id: %u, uid: %u, oid: %u.",
            (uint32)segment->space_id, (uint32)segment->uid, segment->oid);
        segment->page_count = spc_pages_by_ext_cnt(space, segment->extents.count, PAGE_TYPE_HEAP_HEAD);
    }
}

static status_t heap_extend_segment(knl_session_t *session, heap_t *heap, page_id_t *extent)
{
    heap_segment_t *segment = NULL;
    heap_page_t *page = NULL;
    page_id_t last_ext;
    uint32 extent_size;
    log_atomic_op_begin(session);

    buf_enter_page(session, heap->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    segment = HEAP_SEG_HEAD(session);
    space_t *space = SPACE_GET(session, segment->space_id);

    if (!IS_INVALID_PAGID(segment->free_ufp)) {
        // use last unformatted extent.
        *extent = segment->free_ufp;
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return GS_SUCCESS;
    } else if (segment->free_extents.count > 0) {
        // alloc extent from heap free_extents list.
        *extent = segment->free_extents.first;
        segment->free_extents.count--;

        buf_enter_page(session, *extent, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        page = (heap_page_t *)CURR_PAGE(session);
        segment->ufp_count = spc_ext_size_by_id((uint8)page->head.ext_size);
        extent_size = segment->ufp_count;

        if (segment->free_extents.count == 0) {
            segment->free_extents.first = INVALID_PAGID;
            segment->free_extents.last = INVALID_PAGID;
        } else {
            knl_panic_log(!IS_INVALID_PAGID(AS_PAGID(page->head.next_ext)),
                          "next extent is invalid, panic info: page %u-%u type %u",
                          AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
            segment->free_extents.first = AS_PAGID(page->head.next_ext);
        }

        heap_del_segment_free_count(segment, extent_size);
        buf_leave_page(session, GS_FALSE);
    } else {
        // alloc new extent
        extent_size = heap_get_next_ext_size(session, segment);
        // 1, get current page count
        // 2, add extent_size to get purpose page count, if bigger the max, return error.
        uint32 next_page_count = heap_get_segment_page_count(space, segment) + extent_size;
        buf_leave_page(session, GS_FALSE);

        uint32 max_pages = (heap->max_pages != 0) ? MIN(heap->max_pages, MAX_SEG_PAGES) : MAX_SEG_PAGES;
        if ((heap->max_pages != 0 && next_page_count > heap->max_pages) || (next_page_count >= MAX_SEG_PAGES)) {
            GS_THROW_ERROR(ERR_MAX_SEGMENT_SIZE, next_page_count, max_pages);
            log_atomic_op_end(session);
            return GS_ERROR;
        }

        // alloc new extent from space.
        // try alloc extent by estimate size, if can not, degrade size
        bool32 is_degrade = GS_FALSE;
        if (spc_try_alloc_extent(session, space, extent, &extent_size, &is_degrade, segment->compress) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
            log_atomic_op_end(session);
            return GS_ERROR;
        }

        buf_enter_page(session, heap->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
        segment->ufp_count = extent_size;
        if (is_degrade) {
            heap_try_init_segment_pagecount(space, segment);
        }
    }

    last_ext = segment->extents.last;
    segment->free_ufp = *extent;
    segment->extents.last = *extent;
    segment->extents.count++;
    heap_try_update_segment_pagecount(segment, extent_size);

    if (!IS_SAME_PAGID(last_ext, heap->entry)) {
        buf_enter_page(session, last_ext, LATCH_MODE_X, ENTER_PAGE_NORMAL);
        page = (heap_page_t *)CURR_PAGE(session);
        TO_PAGID_DATA(*extent, page->head.next_ext);
        if (SPACE_IS_LOGGING(space)) {
            log_put(session, RD_SPC_CONCAT_EXTENT, extent, sizeof(page_id_t), LOG_ENTRY_FLAG_NONE);
        }
        buf_leave_page(session, GS_TRUE);
    } else {
        page = (heap_page_t *)CURR_PAGE(session);
        TO_PAGID_DATA(*extent, page->head.next_ext);
        if (SPACE_IS_LOGGING(space)) {
            log_put(session, RD_SPC_CONCAT_EXTENT, extent, sizeof(page_id_t), LOG_ENTRY_FLAG_NONE);
        }
    }

    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_HEAP_CHANGE_SEG, segment, HEAP_SEG_SIZE, LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);

    log_atomic_op_end(session);

    return GS_SUCCESS;
}

/*
 * format pages in extent
 * 1.add page one by one of the first extent
 * 2.add 128 pages once of other extents if possible.
 * heap in normal space judge ufps with calculating extent last,but in bitmap space
 * heap record ufps with ufp_count on segment.so need to handle different situation.
 */
static void heap_add_extent(knl_session_t *session, heap_t *heap, page_id_t extent, uint32 *add_page_count)
{
    space_t *space = NULL;
    heap_segment_t *segment = NULL;
    uint32 add_cnt, left_cnt;
    page_id_t ext_last;

    log_atomic_op_begin(session);
    buf_enter_page(session, heap->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);

    segment = HEAP_SEG_HEAD(session);
    space = SPACE_GET(session, segment->space_id);
    add_cnt = segment->compress ? PAGE_GROUP_COUNT : ((segment->extents.count == 1) ? 1 : HEAP_PAGE_FORMAT_UNIT);

    if (SPACE_IS_BITMAPMANAGED(space)) {
        left_cnt = segment->ufp_count;
    } else {
        ext_last = spc_get_extent_last(session, space, segment->free_ufp);
        left_cnt = ext_last.page - extent.page + 1;
    }

    add_cnt = add_cnt > left_cnt ? left_cnt : add_cnt;
    if (add_page_count != NULL) {
        *add_page_count = add_cnt;
    }

    knl_panic(!segment->compress || add_cnt == PAGE_GROUP_COUNT);
    heap_add_ufp(session, segment, extent, add_cnt, GS_TRUE);
    left_cnt -= add_cnt;

    if (left_cnt == 0) {
        segment->free_ufp = INVALID_PAGID;
        segment->ufp_count = 0;
    } else {
        extent.page += add_cnt;
        segment->free_ufp = extent;
        if (SPACE_IS_BITMAPMANAGED(space)) {
            segment->ufp_count -= add_cnt;
        }
    }

    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_HEAP_CHANGE_SEG, segment, HEAP_SEG_SIZE, LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, GS_TRUE);
    log_atomic_op_end(session);
}

status_t heap_generate_create_undo(knl_session_t *session, page_id_t entry, uint32 space_id, bool32 need_redo)
{
    undo_data_t undo;
    undo_heap_create_t ud_create;

    if (undo_prepare(session, sizeof(undo_heap_create_t), need_redo, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    log_atomic_op_begin(session);
    ud_create.entry = entry;
    ud_create.space_id = space_id;

    undo.snapshot.is_xfirst = GS_TRUE;
    undo.snapshot.scn = 0;
    undo.data = (char *)&ud_create;
    undo.size = sizeof(undo_heap_create_t);
    undo.ssn = session->rm->ssn;
    undo.type = UNDO_CREATE_HEAP;
    undo_write(session, &undo, need_redo, GS_FALSE);
    log_atomic_op_end(session);

    return GS_SUCCESS;
}

void heap_undo_create_part(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot)
{
    heap_segment_t *segment = NULL;
    undo_heap_create_t *undo;
    page_list_t extents;
    page_list_t free_extents;
    page_head_t *head = NULL;
    buf_ctrl_t *ctrl = NULL;
    space_t *space = NULL;

    undo = (undo_heap_create_t *)ud_row->data;
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
    segment = HEAP_SEG_HEAD(session);
    extents = segment->extents;
    free_extents = segment->free_extents;
    heap_format_free_ufp(session, segment);
    page_free(session, head);
    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_SPC_FREE_PAGE, NULL, 0, LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);
    buf_unreside(session, ctrl);

    if (free_extents.count > 0) {
        // call spc_concat_extent instead of spc_free_extents to avoid dead lock
        spc_concat_extents(session, &extents, &free_extents);
    }

    spc_free_extents(session, space, &extents);
    spc_drop_segment(session, space);
    GS_LOG_DEBUG_INF("[HEAP] undo create hash partition heap, spaceid=%u, file=%u, pageid=%u", undo->space_id,
                     undo->entry.file, undo->entry.page);
}

status_t heap_create_segment(knl_session_t *session, table_t *table)
{
    heap_t *heap = &table->heap;
    knl_table_desc_t *desc = &table->desc;
    space_t *space = SPACE_GET(session, desc->space_id);
    heap_segment_t *segment = NULL;
    page_list_t free_extents;
    page_id_t extent;
    bool32 add_extents = GS_FALSE;

    if (!spc_valid_space_object(session, space->ctrl->id)) {
        GS_THROW_ERROR(ERR_SPACE_HAS_REPLACED, space->ctrl->name, space->ctrl->name);
        return GS_ERROR;
    }
    
    if (table->desc.storage_desc.initial > 0) {
        add_extents = GS_TRUE;
    }

    log_atomic_op_begin(session);

    if (GS_SUCCESS != spc_alloc_extent(session, space, space->ctrl->extent_size, &extent, desc->compress)) {
        GS_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
        log_atomic_op_end(session);
        return GS_ERROR;
    }

    spc_create_segment(session, space);

    desc->entry = extent;
    heap->entry = extent;
    heap->cipher_reserve_size = space->ctrl->cipher_reserve_size;

    free_extents.count = 0;
    free_extents.first = INVALID_PAGID;
    free_extents.last = INVALID_PAGID;

    buf_enter_page(session, extent, LATCH_MODE_X, desc->compress ? ENTER_PAGE_RESIDENT :
        (ENTER_PAGE_RESIDENT | ENTER_PAGE_NO_READ));
    segment = HEAP_SEG_HEAD(session);

    heap_init_segment(session, desc, &free_extents, 0, add_extents, GS_FALSE);
    buf_leave_page(session, GS_TRUE);

    desc->seg_scn = segment->seg_scn;

    log_atomic_op_end(session);

    // add the first extent when create segment
    while (add_extents && !IS_INVALID_PAGID(segment->free_ufp)) {
        if (heap_extend_segment(session, heap, &extent) != GS_SUCCESS) {
            heap->extending = GS_FALSE;
            return GS_ERROR;
        }
        heap_add_extent(session, heap, extent, NULL);
        heap->extending = GS_FALSE;
    }

    return GS_SUCCESS;
}

void heap_format_free_ufp(knl_session_t *session, heap_segment_t *segment)
{
    heap_page_t *page = NULL;
    page_id_t page_id;
    page_id_t first;
    uint32 count = 1;

    if (IS_INVALID_PAGID(segment->free_ufp) || segment->extents.count <= 1) {
        return;
    }

    space_t *space = SPACE_GET(session, segment->space_id);

    if (segment->compress) {
        count = PAGE_GROUP_COUNT;
    }

    first = page_first_group_id(session, segment->free_ufp);
    page_id = first;
    for (uint32 i = 0; i < count; i++) {
        buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NO_READ);
        page = (heap_page_t *)CURR_PAGE(session);
        heap_format_page(session, segment, page, page_id, heap_get_curr_ext_size(space, segment));
        if (SPACE_IS_LOGGING(space)) {
            log_put(session, RD_HEAP_FORMAT_PAGE, page, (uint32)OFFSET_OF(heap_page_t, reserved), LOG_ENTRY_FLAG_NONE);
        }
        buf_leave_page(session, GS_TRUE);
        page_id.page++;
    }
}

void heap_drop_segment(knl_session_t *session, table_t *table)
{
    heap_t *heap = &table->heap;
    space_t *space = NULL;
    heap_segment_t *segment = NULL;
    page_list_t extents;
    page_list_t free_extents;
    page_head_t *head = NULL;
    buf_ctrl_t *ctrl = NULL;

    if (!db_valid_seg_tablespace(session, table->desc.space_id, heap->entry)) {
        return;
    }

    space = SPACE_GET(session, table->desc.space_id);
    log_atomic_op_begin(session);
    buf_enter_page(session, heap->entry, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    head = (page_head_t *)CURR_PAGE(session);
    segment = HEAP_SEG_HEAD(session);
    table->desc.entry = INVALID_PAGID;
    heap->entry = INVALID_PAGID;
    heap->segment = NULL;

    if (head->type != PAGE_TYPE_HEAP_HEAD || segment->org_scn != table->desc.org_scn) {
        // heap segment has been released
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return;
    }

    ctrl = session->curr_page_ctrl;
    extents = segment->extents;
    free_extents = segment->free_extents;
    heap_format_free_ufp(session, segment);

    page_free(session, head);
    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_SPC_FREE_PAGE, NULL, 0, LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, GS_TRUE);

    buf_unreside(session, ctrl);

    if (free_extents.count > 0) {
        // call spc_concat_extent instead of spc_free_extents to avoid dead lock
        spc_concat_extents(session, &extents, &free_extents);
    }

    spc_free_extents(session, space, &extents);
    spc_drop_segment(session, space);

    log_atomic_op_end(session);
}

void heap_drop_garbage_segment(knl_session_t *session, knl_seg_desc_t *seg)
{
    table_t table;

    table.desc.space_id = seg->space_id;
    table.heap.entry = seg->entry;
    table.desc.org_scn = seg->org_scn;

    heap_drop_segment(session, &table);
}

status_t heap_purge_prepare(knl_session_t *session, knl_rb_desc_t *desc)
{
    space_t *space = SPACE_GET(session, desc->space_id);
    if (!SPACE_IS_ONLINE(space) || !space->ctrl->used) {
        return GS_SUCCESS;
    }

    if (IS_INVALID_PAGID(desc->entry)) {
        return GS_SUCCESS;
    }

    buf_enter_page(session, desc->entry, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    heap_segment_t *segment = HEAP_SEG_HEAD(session);
    knl_seg_desc_t seg;
    seg.uid = segment->uid;
    seg.oid = segment->oid;
    seg.index_id = GS_INVALID_ID32;
    seg.column_id = GS_INVALID_ID32;
    seg.space_id = segment->space_id;
    seg.entry = desc->entry;
    seg.org_scn = segment->org_scn;
    seg.seg_scn = segment->seg_scn;
    seg.initrans = segment->initrans;
    seg.pctfree = 0;
    seg.op_type = HEAP_PURGE_SEGMENT;
    seg.reuse = GS_FALSE;
    seg.serial = segment->serial;
    buf_leave_page(session, GS_FALSE);

    if (db_write_garbage_segment(session, &seg) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    return GS_SUCCESS;
}

void heap_purge_segment(knl_session_t *session, knl_seg_desc_t *desc)
{
    heap_segment_t *segment = NULL;
    page_list_t extents;
    page_list_t free_extents;
    page_head_t *head = NULL;

    if (!db_valid_seg_tablespace(session, desc->space_id, desc->entry)) {
        return;
    }

    space_t *space = SPACE_GET(session, desc->space_id);
    log_atomic_op_begin(session);

    buf_enter_page(session, desc->entry, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    head = (page_head_t *)CURR_PAGE(session);
    segment = HEAP_SEG_HEAD(session);
    if (head->type != PAGE_TYPE_HEAP_HEAD || segment->seg_scn != desc->seg_scn) {
        // heap segment has been released
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return;
    }

    extents = segment->extents;
    free_extents = segment->free_extents;
    heap_format_free_ufp(session, segment);

    page_free(session, head);
    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_SPC_FREE_PAGE, NULL, 0, LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);

    buf_unreside(session, session->curr_page_ctrl);

    if (free_extents.count > 0) {
        spc_concat_extents(session, &extents, &free_extents);
    }

    spc_free_extents(session, space, &extents);
    
    spc_drop_segment(session, space);

    log_atomic_op_end(session);
}

void heap_truncate_segment(knl_session_t *session, knl_table_desc_t *desc, bool32 reuse_storage)
{
    page_list_t extents;

    if (!db_valid_seg_tablespace(session, desc->space_id, desc->entry)) {
        return;
    }
    
    space_t *space = SPACE_GET(session, desc->space_id);
    log_atomic_op_begin(session);

    buf_enter_page(session, desc->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    page_head_t *page = (page_head_t *)CURR_PAGE(session);
    heap_segment_t *segment = HEAP_SEG_HEAD(session);
    if (page->type != PAGE_TYPE_HEAP_HEAD || segment->seg_scn != desc->seg_scn) {
        // HEAP segment has been released
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return;
    }

    heap_format_free_ufp(session, segment);
    extents = segment->free_extents;
    if (segment->extents.count > 1) {
        if (extents.count == 0) {
            extents.last = segment->extents.last;
        } else {
            spc_concat_extent(session, segment->extents.last, extents.first);
        }

        extents.first = AS_PAGID(page->next_ext);
        // if free extents is not empty, need add origin free extents count
        extents.count += segment->extents.count - 1;
    }
    
    if (!reuse_storage) {
        if (extents.count > 0) {
            spc_free_extents(session, space, &extents);
        }

        extents.count = 0;
        extents.first = INVALID_PAGID;
        extents.last = INVALID_PAGID;
    }

    desc->cr_mode = segment->cr_mode;
    uint32 ext_page_count = 0;
    if (HEAP_SEG_BITMAP_IS_DEGRADE(segment)) {
        ext_page_count = segment->free_page_count + segment->page_count - space->ctrl->extent_size;
    }
    heap_init_segment(session, desc, &extents, ext_page_count, GS_FALSE, GS_TRUE);
    buf_leave_page(session, GS_TRUE);

    log_atomic_op_end(session);
}

void heap_truncate_garbage_segment(knl_session_t *session, knl_seg_desc_t *seg)
{
    knl_table_desc_t desc;

    desc.uid = seg->uid;
    desc.id = seg->oid;
    desc.space_id = seg->space_id;
    desc.org_scn = seg->org_scn;
    desc.seg_scn = seg->seg_scn;
    desc.entry = seg->entry;
    desc.initrans = seg->initrans;
    desc.pctfree = seg->pctfree;
    desc.serial_start = seg->serial;

    heap_truncate_segment(session, &desc, seg->reuse);
}

static void heap_init_part_segment_inner(knl_session_t *session, knl_table_part_desc_t *desc,
    heap_segment_t *segment)
{
    segment->uid = (uint16)desc->uid;
    segment->oid = desc->table_id;
    segment->org_scn = desc->org_scn;
    segment->seg_scn = db_inc_scn(session);
    segment->initrans = (uint8)desc->initrans;
    segment->space_id = desc->space_id;
    segment->cr_mode = desc->cr_mode;
    knl_panic(desc->cr_mode == CR_PAGE || desc->cr_mode == CR_ROW);

    segment->data_first = INVALID_PAGID;
    segment->data_last = INVALID_PAGID;
    segment->cmp_hwm = INVALID_PAGID;
    segment->shrinkable_scn = GS_INVALID_ID64;
}

static void heap_init_part_segment(knl_session_t *session, knl_table_part_desc_t *desc, page_list_t *free_extents,
    uint32 free_page_count, bool32 add_extent, bool32 reserve_flag)
{
    space_t *space = SPACE_GET(session, desc->space_id);
    rd_heap_format_page_t redo;
    heap_segment_t *segment = HEAP_SEG_HEAD(session);
    page_id_t extent = desc->entry;
    bool32 is_compress;
    uint32 add_cnt;

    // used by update page count
    uint32 origin_page_count = segment->page_count;
    if (reserve_flag) {
        is_compress = segment->compress;
    } else {
        is_compress = desc->compress;
    }
    add_cnt = is_compress ? (PAGE_GROUP_COUNT - 1) : HEAP_SEGMENT_MIN_PAGES;

    uint16 extent_size = space->ctrl->extent_size;
    page_head_t *page_head = (page_head_t *)CURR_PAGE(session);
    page_init(session, page_head, extent, PAGE_TYPE_HEAP_HEAD);
    page_head->ext_size = spc_ext_id_by_size(extent_size);
    if (SPACE_IS_LOGGING(space)) {
        redo.page_id = extent;
        redo.extent_size = extent_size;
        log_put(session, RD_HEAP_FORMAT_ENTRY, &redo, sizeof(rd_heap_format_page_t), LOG_ENTRY_FLAG_NONE);
    }

    // init segment's basic info from table desc
    heap_init_part_segment_inner(session, desc, segment);

    segment->extents.count = 1;
    segment->extents.first = extent;
    segment->extents.last = extent;
    segment->free_extents = *free_extents;
    segment->free_ufp = INVALID_PAGID;
    segment->ufp_count = extent_size - 1;
    segment->compress = is_compress;
    segment->tree_info.level = 0;
    TO_PAGID_DATA(INVALID_PAGID, segment->tree_info.root);
    segment->curr_map[0] = INVALID_PAGID;

    heap_set_pctfree(session, segment, desc->pctfree);

    extent.page++;

    /*
     * It is meaningful to add heap pages one page at a time when extents size larger than 3.
     * for the first extent of heap segment, the first page is segment page, the secend page is map page
     */
    if (add_extent) {
        add_cnt = (extent_size - 1) > HEAP_PAGE_FORMAT_UNIT ? HEAP_PAGE_FORMAT_UNIT : (extent_size - 1);
    }

    knl_panic(!is_compress || add_cnt == PAGE_GROUP_COUNT - 1);
    heap_add_ufp(session, segment, extent, add_cnt, !is_compress);
    extent.page += add_cnt;
    segment->ufp_count -= add_cnt;
    segment->free_ufp = (segment->ufp_count == 0) ? INVALID_PAGID : extent;

    // update segment page count
    heap_init_segment_page_count(space, segment, origin_page_count, free_page_count);

    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_HEAP_CHANGE_SEG, segment, HEAP_SEG_SIZE, LOG_ENTRY_FLAG_NONE);
    }
}

static inline void heap_truncate_part_segment_inner(knl_session_t *session, page_head_t *page, heap_segment_t *segment,
                                                    page_list_t *extents, space_t *space, bool32 reuse)
{
    heap_format_free_ufp(session, segment);

    *extents = segment->free_extents;
    if (segment->extents.count > 1) {
        if (extents->count == 0) {
            extents->last = segment->extents.last;
        } else {
            spc_concat_extent(session, segment->extents.last, extents->first);
        }

        extents->first = AS_PAGID(page->next_ext);
        extents->count += segment->extents.count - 1;
    }
    
    if (!reuse) {
        if (extents->count > 0) {
            spc_free_extents(session, space, extents);
        }

        extents->count = 0;
        extents->first = INVALID_PAGID;
        extents->last = INVALID_PAGID;
    }
}

void heap_truncate_part_segment(knl_session_t *session, knl_table_part_desc_t *desc, bool32 reuse_storage)
{
    heap_segment_t *segment = NULL;
    page_head_t *page = NULL;
    page_list_t extents;

    if (!db_valid_seg_tablespace(session, desc->space_id, desc->entry)) {
        return;
    }

    space_t *space = SPACE_GET(session, desc->space_id);
    log_atomic_op_begin(session);

    buf_enter_page(session, desc->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    page = (page_head_t *)CURR_PAGE(session);
    segment = HEAP_SEG_HEAD(session);
    if (page->type != PAGE_TYPE_HEAP_HEAD || segment->seg_scn != desc->seg_scn) {
        // HEAP segment has been released
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return;
    }

    heap_truncate_part_segment_inner(session, page, segment, &extents, space, reuse_storage);

    desc->cr_mode = segment->cr_mode;

    uint32 ext_page_count = 0;
    if (HEAP_SEG_BITMAP_IS_DEGRADE(segment)) {
        ext_page_count = segment->free_page_count + segment->page_count - space->ctrl->extent_size;
    }
    heap_init_part_segment(session, desc, &extents, ext_page_count, GS_FALSE, GS_TRUE);

    buf_leave_page(session, GS_TRUE);
    log_atomic_op_end(session);
}

void heap_truncate_part_garbage_segment(knl_session_t *session, knl_seg_desc_t *seg)
{
    knl_table_part_desc_t desc;

    desc.uid = seg->uid;
    desc.table_id = seg->oid;
    desc.space_id = seg->space_id;
    desc.org_scn = seg->org_scn;
    desc.seg_scn = seg->seg_scn;
    desc.entry = seg->entry;
    desc.initrans = seg->initrans;
    desc.pctfree = seg->pctfree;

    heap_truncate_part_segment(session, &desc, seg->reuse);
}

status_t heap_create_part_segment(knl_session_t *session, table_part_t *table_part)
{
    heap_t *heap = &table_part->heap;
    knl_table_part_desc_t *desc = &table_part->desc;
    space_t *space = SPACE_GET(session, desc->space_id);
    heap_segment_t *segment = NULL;
    page_list_t free_extents;
    page_id_t extent;
    bool32 add_extents = GS_FALSE;
    
    if (!spc_valid_space_object(session, space->ctrl->id)) {
        GS_THROW_ERROR(ERR_SPACE_HAS_REPLACED, space->ctrl->name, space->ctrl->name);
        return GS_ERROR;
    }
    
    if (table_part->desc.storage_desc.initial > 0) {
        add_extents = GS_TRUE;
    }

    log_atomic_op_begin(session);

    if (GS_SUCCESS != spc_alloc_extent(session, space, space->ctrl->extent_size, &extent, desc->compress)) {
        GS_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
        log_atomic_op_end(session);
        return GS_ERROR;
    }

    spc_create_segment(session, space);

    desc->entry = extent;
    heap->entry = extent;
    heap->cipher_reserve_size = space->ctrl->cipher_reserve_size;

    free_extents.count = 0;
    free_extents.first = INVALID_PAGID;
    free_extents.last = INVALID_PAGID;

    buf_enter_page(session, extent, LATCH_MODE_X, desc->compress ? ENTER_PAGE_RESIDENT :
        (ENTER_PAGE_RESIDENT | ENTER_PAGE_NO_READ));
    segment = HEAP_SEG_HEAD(session);
    heap_init_part_segment(session, desc, &free_extents, 0, add_extents, GS_FALSE);
    buf_leave_page(session, GS_TRUE);

    desc->seg_scn = segment->seg_scn;
    table_part->heap.loaded = GS_TRUE;

    log_atomic_op_end(session);

    // add the first extent when create segment
    while (add_extents && !IS_INVALID_PAGID(segment->free_ufp)) {
        if (heap_extend_segment(session, heap, &extent) != GS_SUCCESS) {
            heap->extending = GS_FALSE;
            return GS_ERROR;
        }
        heap_add_extent(session, heap, extent, NULL);
        heap->extending = GS_FALSE;
    }

    return GS_SUCCESS;
}

void heap_drop_part_segment(knl_session_t *session, table_part_t *table_part)
{
    heap_t *heap = &table_part->heap;
    space_t *space = NULL;
    heap_segment_t *segment = NULL;
    page_list_t extents;
    page_list_t free_extents;
    page_head_t *head = NULL;
    buf_ctrl_t *ctrl = NULL;

    if (!db_valid_seg_tablespace(session, table_part->desc.space_id, heap->entry)) {
        return;
    }

    space = SPACE_GET(session, table_part->desc.space_id);
    log_atomic_op_begin(session);

    buf_enter_page(session, heap->entry, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    head = (page_head_t *)CURR_PAGE(session);
    segment = HEAP_SEG_HEAD(session);
    table_part->desc.entry = INVALID_PAGID;
    heap->entry = INVALID_PAGID;
    heap->segment = NULL;

    if (head->type != PAGE_TYPE_HEAP_HEAD || segment->org_scn != table_part->desc.org_scn) {
        // heap segment has been released
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return;
    }

    ctrl = session->curr_page_ctrl;
    extents = segment->extents;
    free_extents = segment->free_extents;
    heap_format_free_ufp(session, segment);

    page_free(session, head);
    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_SPC_FREE_PAGE, NULL, 0, LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);

    buf_unreside(session, ctrl);

    if (free_extents.count > 0) {
        // call spc_concat_extent instead of spc_free_extents to avoid dead lock
        spc_concat_extents(session, &extents, &free_extents);
    }

    spc_free_extents(session, space, &extents);
    spc_drop_segment(session, space);

    log_atomic_op_end(session);
}

void heap_drop_part_garbage_segment(knl_session_t *session, knl_seg_desc_t *seg)
{
    table_part_t table_part;

    table_part.desc.space_id = seg->space_id;
    table_part.heap.entry = seg->entry;
    table_part.desc.org_scn = seg->org_scn;

    heap_drop_part_segment(session, &table_part);
}

static void heap_try_clean_extend_status(knl_session_t *session, heap_t *heap, knl_part_locate_t part_loc)
{
    heap->wait_ticks++;
    cm_spin_sleep();
    if (heap->wait_ticks > MAX_WAIT_TICKS && heap->extend_owner != session->kernel->id) {
        cluster_view_t view;
        rc_get_cluster_view(&view, GS_TRUE);
        uint64 alive_inst = view.bitmap;
        bool8 need_clean = GS_FALSE;
        if (!rc_bitmap64_exist(&alive_inst, heap->extend_owner)) {
            need_clean = heap->extending;
        } else {
            bool8 is_extending = GS_FALSE;
            status_t status = dtc_get_heap_extend_status(session, heap, part_loc, &is_extending);
            need_clean = (status == GS_SUCCESS) && (is_extending == 0);
        }
        if (need_clean) {
            heap->extending = GS_FALSE;
            heap->wait_ticks = 0;
            (void)dtc_broadcast_heap_extend(session, heap, part_loc);
            heap->extend_owner = GS_INVALID_ID8;
        }
    }
}

/*
 * Check if segment has been extended by other session or not, check from the max
 * lid 'cause if someone has just added pages to map tree, we can find it immediately.
 * When find the needed map list or someone is extending now, recheck the map tree.
 */
static bool32 heap_prepare_extend(knl_session_t *session, heap_t *heap, uint32 mid, knl_part_locate_t part_loc)
{
    knl_tree_info_t tree_info;
    map_page_t *map_page = NULL;
    page_id_t map_id;
    uint32 lid;

    for (;;) {
        dls_spin_lock(session, &heap->lock, NULL);
        if (!heap->extending) {
            heap->extending = GS_TRUE;
            if (DB_IS_CLUSTER(session)) {
                status_t ret = dtc_broadcast_heap_extend(session, heap, part_loc);
                if (ret != GS_SUCCESS) {
                    heap->extending = GS_FALSE;
                    dls_spin_unlock(session, &heap->lock);
                    cm_spin_sleep_and_stat2(1);
                    GS_LOG_RUN_ERR(
                        "prepare extend, heap failed to broadcast heap extending info, "
                        "uid/table_id/part/subpart:[%u-%u-%u-%u], extending:%d, compacting:%d",
                        heap->table->desc.uid, heap->table->desc.id, part_loc.part_no, part_loc.subpart_no,
                        heap->extending, heap->compacting);
                    continue;
                }
            }
            dls_spin_unlock(session, &heap->lock);
            return GS_TRUE;
        }

        heap_try_clean_extend_status(session, heap, part_loc);
        dls_spin_unlock(session, &heap->lock);

        // wait other session to finish extending map
        knl_try_begin_session_wait(session, ENQ_SEGMENT_EXTEND, GS_TRUE);
        cm_spin_sleep_and_stat2(1);
        knl_try_end_session_wait(session, ENQ_SEGMENT_EXTEND);

        if (mid < HEAP_FREE_LIST_COUNT) {
            tree_info.value = cm_atomic_get(&HEAP_SEGMENT(session, heap->entry, heap->segment)->tree_info.value);
            map_id = AS_PAGID(tree_info.root);

            buf_enter_page(session, map_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
            map_page = (map_page_t *)CURR_PAGE(session);

            for (lid = HEAP_FREE_LIST_COUNT - 1; lid >= mid; lid--) {
                if (map_page->lists[lid].count > 0) {
                    buf_leave_page(session, GS_FALSE);
                    return GS_FALSE;
                }
            }

            buf_leave_page(session, GS_FALSE);
        }
    }
}

static void heap_unset_extend_flag(knl_session_t *session, heap_t *heap, knl_part_locate_t part_loc)
{
    if (!DB_IS_CLUSTER(session)) {
        heap->extending = GS_FALSE;
        return;
    }
    
    SYNC_POINT_GLOBAL_START(CANTIAN_HEAP_EXTEND_UNSET_BEFORE_BCAST_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    dls_spin_lock(session, &heap->lock, NULL);
    heap->extending = GS_FALSE;
    status_t ret = dtc_broadcast_heap_extend(session, heap, part_loc);
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_ERR(
            "heap failed to broadcast heap extending info, abort, uid/table_id/part/subpart:[%u-%u-%u-%u], extending:%d, compacting:%d",
            heap->table->desc.uid, heap->table->desc.id, part_loc.part_no, part_loc.subpart_no, heap->extending,
            heap->compacting);
    }
    dls_spin_unlock(session, &heap->lock);
}

static status_t heap_create_initial(knl_session_t *session, heap_t *heap, knl_part_locate_t part_loc, uint32 extcount)
{
    page_id_t extent;
    while (heap->segment->extents.count < extcount ||
        (heap->segment->extents.count == extcount && !IS_INVALID_PAGID(heap->segment->free_ufp))) {
        if (!heap_prepare_extend(session, heap, HEAP_FREE_LIST_COUNT, part_loc)) {
            continue;
        }
        if (heap_extend_segment(session, heap, &extent) != GS_SUCCESS) {
            heap_unset_extend_flag(session, heap, part_loc);
            return GS_ERROR;
        }
        heap_add_extent(session, heap, extent, NULL);
        heap_unset_extend_flag(session, heap, part_loc);
    }

    return GS_SUCCESS;
}

status_t heap_create_part_entry(knl_session_t *session, table_part_t *table_part, knl_part_locate_t part_loc)
{
    heap_t *heap = &table_part->heap;
    status_t status;
    
    dls_latch_x(session, &heap->latch, session->id, &session->stat_heap);
    if (heap->segment != NULL) {
        dls_unlatch(session, &heap->latch, &session->stat_heap);
        return GS_SUCCESS;
    }

    if (heap_create_part_segment(session, table_part) != GS_SUCCESS) {
        dls_unlatch(session, &heap->latch, &session->stat_heap);
        return GS_ERROR;
    }

    if (knl_begin_auton_rm(session) != GS_SUCCESS) {
        heap_drop_part_segment(session, table_part);
        dls_unlatch(session, &heap->latch, &session->stat_heap);
        return GS_ERROR;
    }

    if (IS_SUB_TABPART(&table_part->desc)) {
        status = db_update_subtabpart_entry(session, &table_part->desc, table_part->desc.entry);
    } else {
        status = db_update_table_part_entry(session, &table_part->desc, table_part->desc.entry);
    }

    if (status != GS_SUCCESS) {
        knl_end_auton_rm(session, GS_ERROR);
        heap_drop_part_segment(session, table_part);
        dls_unlatch(session, &heap->latch, &session->stat_heap);
        return GS_ERROR;
    }
    
    if (SPACE_IS_LOGGING(SPACE_GET(session, table_part->desc.space_id))) {
        rd_create_heap_entry_t redo;
        redo.tab_op.op_type = RD_CREATE_HEAP_ENTRY;
        redo.tab_op.uid = table_part->desc.uid;
        redo.tab_op.oid = table_part->desc.table_id;
        redo.part_loc = part_loc;
        redo.entry = heap->entry;
        log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_create_heap_entry_t), LOG_ENTRY_FLAG_NONE);
    }

    knl_end_auton_rm(session, GS_SUCCESS);

    buf_enter_page(session, table_part->desc.entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
    heap->segment = HEAP_SEG_HEAD(session);
    buf_leave_page(session, GS_FALSE);
    dls_unlatch(session, &heap->latch, &session->stat_heap);

    if (table_part->desc.storage_desc.initial > 0) {
        space_t *space = SPACE_GET(session, table_part->desc.space_id);
        uint32 extcount = spc_ext_cnt_by_pages(space, table_part->desc.storage_desc.initial);
        if (heap_create_initial(session, heap, part_loc, extcount) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t heap_create_entry(knl_session_t *session, heap_t *heap)
{
    table_t *table = heap->table;

    dls_latch_x(session, &heap->latch, session->id, &session->stat_heap);

    if (heap->segment != NULL) {
        dls_unlatch(session, &heap->latch, &session->stat_heap);
        return GS_SUCCESS;
    }

    if (heap_create_segment(session, table) != GS_SUCCESS) {
        dls_unlatch(session, &heap->latch, &session->stat_heap);
        return GS_ERROR;
    }

    if (knl_begin_auton_rm(session) != GS_SUCCESS) {
        heap_drop_segment(session, table);
        dls_unlatch(session, &heap->latch, &session->stat_heap);
        return GS_ERROR;
    }

    if (db_update_table_entry(session, &table->desc, table->desc.entry) != GS_SUCCESS) {
        knl_end_auton_rm(session, GS_ERROR);
        heap_drop_segment(session, table);
        dls_unlatch(session, &heap->latch, &session->stat_heap);
        return GS_ERROR;
    }

    if (SPACE_IS_LOGGING(SPACE_GET(session, table->desc.space_id))) {
        rd_create_heap_entry_t redo;
        redo.tab_op.op_type = RD_CREATE_HEAP_ENTRY;
        redo.tab_op.uid = table->desc.uid;
        redo.tab_op.oid = table->desc.id;
        redo.part_loc.part_no = GS_INVALID_ID32;
        redo.entry = heap->entry;
        log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_create_heap_entry_t), LOG_ENTRY_FLAG_NONE);
    }
    knl_end_auton_rm(session, GS_SUCCESS);

    buf_enter_page(session, table->desc.entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
    heap->segment = HEAP_SEG_HEAD(session);
    buf_leave_page(session, GS_FALSE);
    dls_unlatch(session, &heap->latch, &session->stat_heap);

    if (table->desc.storage_desc.initial > 0) {
        space_t *space = SPACE_GET(session, table->desc.space_id);
        uint32 extcount = spc_ext_cnt_by_pages(space, table->desc.storage_desc.initial);
        if (heap_create_initial(session, heap, g_invalid_part_loc, extcount) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

/*
 * calculate the free page list this heap page belongs to.
 * @param kernel session, page free size
 * @note Page size(8192) pctfree size(512) example:
 * show the owner list of each free_size
 * lid 0 range: 1    - 511      1    ~ 1/16
 * lid 1 range: 512  - 1023     1/16 ~ 1/8
 * lid 2 range: 1024 - 2047     1/8  ~ 1/4
 * lid 3 range: 2048 - 4095     1/4  ~ 1/2
 * lid 4 range: 4096 - 7999     1/2  ~ max request size
 * lid 5 range: max request size ~
 * because segment->list_range[] will not change after create database, don not need to do buf_check_resident_page_version
 */
uint8 heap_get_owner_list(knl_session_t *session, heap_segment_t *segment, uint32 free_size)
{
    if (free_size >= segment->list_range[3]) {
        if (free_size < segment->list_range[4]) {
            return 3;
        } else {
            return (uint32)(free_size >= segment->list_range[5] ? 5 : 4);
        }
    } else {
        if (free_size >= segment->list_range[2]) {
            return 2;
        } else {
            return (uint32)(free_size < segment->list_range[1] ? 0 : 1);
        }
    }
}

/*
 * calculate the target page list in which pages have free size than requested
 * @param kernel session, request size
 * @note Page size(8192) pctfree size(512) example:
 * show the target list of each quest size
 * lid 1 range: 1    - 512      1    ~ 1/16
 * lid 2 range: 513  - 1024     1/16 ~ 1/ 8
 * lid 3 range: 1025 - 2048     1/8  ~ 1/4
 * lid 4 range: 2049 - 4096     1/4  ~ 1/2
 * lid 5 range: 4097 - ~        1/2  ~ max request size
 */
uint32 heap_get_target_list(knl_session_t *session, heap_segment_t *segment, uint32 size)
{
    if (size > segment->list_range[3]) {
        return (uint32)(size <= segment->list_range[4] ? 4 : 5);
    } else {
        if (size > segment->list_range[2]) {
            return 3;
        } else {
            return (uint32)(size <= segment->list_range[1] ? 1 : 2);
        }
    }
}

static inline void heap_format_page(knl_session_t *session, heap_segment_t *segment, heap_page_t *page,
                                    page_id_t page_id, uint32 extent_size)
{
    space_t *space = SPACE_GET(session, segment->space_id);
    page_init(session, &page->head, page_id,
              ((segment->cr_mode == CR_PAGE) ? PAGE_TYPE_PCRH_DATA : PAGE_TYPE_HEAP_DATA));

    TO_PAGID_DATA(INVALID_PAGID, page->next);
    page->head.ext_size = spc_ext_id_by_size(extent_size);
    // itls will be set before alloc itl in update/insert
    page->itls = 0;
    page->first_free_dir = (segment->cr_mode == CR_PAGE) ? PCRH_NO_FREE_DIR : HEAP_NO_FREE_DIR;
    page->free_begin = sizeof(heap_page_t) + space->ctrl->cipher_reserve_size;
    // the max value of PAGESIZE is DEFAULT_PAGE_SIZE(8192), so the sum is less than max value(65535) of uint16
    page->free_end = (uint16)(PAGE_SIZE(page->head) - sizeof(page_tail_t));
    page->free_size = page->free_end - page->free_begin;
    page->oid = segment->oid;
    page->uid = segment->uid;
    page->seg_scn = segment->seg_scn;
    page->org_scn = segment->org_scn;
}

/*
 * change the current map list to new map list
 * new id: target id, level: map level
 */
void heap_change_map(knl_session_t *session, heap_segment_t *segment, map_index_t *map, uint8 new_id, uint32 level)
{
    map_page_t *map_page = NULL;
    uint8 last_lid;

    buf_enter_page(session, MAKE_PAGID((uint16)map->file, (uint32)map->page), LATCH_MODE_X, ENTER_PAGE_NORMAL);
    map_page = (map_page_t *)CURR_PAGE(session);

    knl_panic_log(map->slot < map_page->hwm, "current map slot is more than hwm, panic info: page %u-%u type %u "
                  "slot %u hwm %u", AS_PAGID(map_page->head.id).file, AS_PAGID(map_page->head.id).page,
                  map_page->head.type, map->slot, map_page->hwm);

    heap_remove_from_list(map_page, &map_page->lists[map->list_id], (uint16)map->slot);
    heap_insert_into_list(map_page, &map_page->lists[new_id], (uint16)map->slot);

    if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
        rd_change_map_t redo;

        redo.slot = (uint16)map->slot;
        redo.old_lid = (uint8)map->list_id;
        redo.new_lid = new_id;
        log_put(session, RD_HEAP_CHANGE_MAP, &redo, sizeof(rd_change_map_t), LOG_ENTRY_FLAG_NONE);
    }

    last_lid = heap_find_last_list(map_page);
    if (last_lid != map_page->map.list_id && level < segment->tree_info.level) {
        heap_change_map(session, segment, &map_page->map, last_lid, level + 1);
    }

    buf_leave_page(session, GS_TRUE);

    map->list_id = new_id;
    if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
        log_put(session, RD_HEAP_CHANGE_LIST, &new_id, sizeof(uint8), LOG_ENTRY_FLAG_NONE);
    }
}

/*
 * heap try change map
 * try to change the map list of current heap page to a new map list
 * If the new change list is different from the previous calculation after enter page,
 * we need to give up current change attempt and other session would change the map instead if
 * necessary.
 * @param kernel session, heap handle, heap page
 */
void heap_try_change_map(knl_session_t *session, knl_handle_t heap_handle, page_id_t page_id)
{
    heap_t *heap = NULL;
    heap_segment_t *segment = NULL;
    heap_page_t *page = NULL;
    int8 new_id;

    if (session->change_list == 0) {
        return;
    }

    heap = (heap_t *)heap_handle;
    segment = HEAP_SEGMENT(session, heap->entry, heap->segment);

    log_atomic_op_begin(session);

    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE(session);

    new_id = (int8)heap_get_owner_list(session, segment, page->free_size);
    if (new_id - (int8)page->map.list_id != session->change_list) {
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return;
    }

    heap_change_map(session, segment, &page->map, (uint8)new_id, 0);
    buf_leave_page(session, GS_TRUE);

    log_atomic_op_end(session);
}

/*
 * heap degrade change map
 * when degrade seached page free size is not enough
 * Just change map list id to lower list,
 * @param kernel session, heap handle, heap page, new list id
 */
void heap_degrade_change_map(knl_session_t *session, knl_handle_t heap_handle, page_id_t page_id, uint8 new_id)
{
    heap_t *heap = NULL;
    heap_segment_t *segment = NULL;
    heap_page_t *page = NULL;
    uint8 owner_list;

    heap = (heap_t *)heap_handle;
    segment = HEAP_SEGMENT(session, heap->entry, heap->segment);

    log_atomic_op_begin(session);

    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE(session);
    
    owner_list = heap_get_owner_list(session, segment, page->free_size);
    // just degrade list id from new_id + 1 to new id
    if (new_id != owner_list - 1) {
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return;
    }

    heap_change_map(session, segment, &page->map, new_id, 0);
    buf_leave_page(session, GS_TRUE);

    log_atomic_op_end(session);
}


/*
 * alloc map node for new map page
 * @note we put it into the list 0 'cause no next level page was added to it.
 * This would not cause the change of the last list of current map, no need to change map.
 * @param kernel session, heap segment, map page, current level
 */
static void heap_alloc_mp_for_map(knl_session_t *session, heap_segment_t *segment, map_page_t *page, uint32 level)
{
    map_page_t *map_page = NULL;
    map_node_t *node = NULL;

    buf_enter_page(session, segment->curr_map[level], LATCH_MODE_X, ENTER_PAGE_NORMAL);
    map_page = (map_page_t *)CURR_PAGE(session);

    page->map.file = AS_PAGID_PTR(map_page->head.id)->file;
    page->map.page = AS_PAGID_PTR(map_page->head.id)->page;
    page->map.slot = map_page->hwm;
    page->map.list_id = 0;

    heap_insert_into_list(map_page, &map_page->lists[0], map_page->hwm);
    node = heap_get_map_node(CURR_PAGE(session), map_page->hwm);
    node->file = AS_PAGID_PTR(page->head.id)->file;
    node->page = AS_PAGID_PTR(page->head.id)->page;
    map_page->hwm++;

    if (map_page->hwm >= session->kernel->attr.max_map_nodes) {
        segment->curr_map[level] = INVALID_PAGID;
    }

    if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
        rd_alloc_map_node_t redo;

        redo.lid = 0;
        redo.file = AS_PAGID_PTR(page->head.id)->file;
        redo.page = AS_PAGID_PTR(page->head.id)->page;
        redo.aligned = 0;
        log_put(session, RD_HEAP_ALLOC_MAP_NODE, &redo, sizeof(rd_alloc_map_node_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);

    if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
        log_put(session, RD_HEAP_SET_MAP, &page->map, sizeof(map_index_t), LOG_ENTRY_FLAG_NONE);
    }
}

/*
 * alloc map node for new heap page
 * If the last lid change in current map after adding the new heap page, we should
 * change the high level map recursively, so other session can see it from map tree.
 * @param kernel session, heap segment, heap page
 */
static void heap_alloc_mp_for_page(knl_session_t *session, heap_segment_t *segment, heap_page_t *page)
{
    map_node_t *node = NULL;
    map_page_t *map_page = NULL;
    uint8 last_lid;
    uint8 owner_lid;

    owner_lid = heap_get_owner_list(session, segment, page->free_size);

    buf_enter_page(session, segment->curr_map[0], LATCH_MODE_X, ENTER_PAGE_NORMAL);
    map_page = (map_page_t *)CURR_PAGE(session);

    last_lid = heap_find_last_list(map_page);
    page->map.file = AS_PAGID_PTR(map_page->head.id)->file;
    page->map.page = AS_PAGID_PTR(map_page->head.id)->page;
    page->map.slot = map_page->hwm;
    page->map.list_id = owner_lid;

    heap_insert_into_list(map_page, &map_page->lists[owner_lid], map_page->hwm);
    node = heap_get_map_node(CURR_PAGE(session), map_page->hwm);
    node->file = AS_PAGID_PTR(page->head.id)->file;
    node->page = AS_PAGID_PTR(page->head.id)->page;
    map_page->hwm++;

    if (map_page->hwm >= session->kernel->attr.max_map_nodes) {
        segment->curr_map[0] = INVALID_PAGID;
    }

    if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
        rd_alloc_map_node_t redo;

        redo.lid = owner_lid;
        redo.file = AS_PAGID_PTR(page->head.id)->file;
        redo.page = AS_PAGID_PTR(page->head.id)->page;
        redo.aligned = 0;
        log_put(session, RD_HEAP_ALLOC_MAP_NODE, &redo, sizeof(rd_alloc_map_node_t), LOG_ENTRY_FLAG_NONE);
    }

    if (last_lid < owner_lid && segment->tree_info.level > 0) {
        heap_change_map(session, segment, &map_page->map, owner_lid, 1);
    }

    buf_leave_page(session, GS_TRUE);

    if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
        log_put(session, RD_HEAP_SET_MAP, &page->map, sizeof(map_index_t), LOG_ENTRY_FLAG_NONE);
    }
}

static void heap_convert_root(knl_session_t *session, heap_segment_t *segment, map_page_t *page)
{
    knl_tree_info_t tree_info = {0};
    map_page_t *root_map = NULL;
    map_node_t *node = NULL;
    uint8 lid;

    if (IS_INVALID_PAGID(AS_PAGID(segment->tree_info.root))) {
        TO_PAGID_DATA(AS_PAGID(page->head.id), segment->tree_info.root);
        segment->tree_info.level = 0;
        segment->curr_map[0] = AS_PAGID(page->head.id);
        segment->map_count[0] = 1;
        return;
    }

    buf_enter_page(session, AS_PAGID(segment->tree_info.root), LATCH_MODE_X, ENTER_PAGE_NORMAL);
    root_map = (map_page_t *)CURR_PAGE(session);
    lid = heap_find_last_list(root_map);
    root_map->map.file = AS_PAGID_PTR(page->head.id)->file;
    root_map->map.page = AS_PAGID_PTR(page->head.id)->page;
    root_map->map.slot = page->hwm;
    root_map->map.list_id = lid;
    if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
        log_put(session, RD_HEAP_SET_MAP, &root_map->map, sizeof(map_index_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);

    heap_insert_into_list(page, &page->lists[lid], page->hwm);
    node = heap_get_map_node((char *)page, page->hwm);
    node->file = AS_PAGID_PTR(segment->tree_info.root)->file;
    node->page = AS_PAGID_PTR(segment->tree_info.root)->page;
    page->hwm++;

    if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
        rd_alloc_map_node_t redo;

        redo.file = (uint16)node->file;
        redo.page = (uint32)node->page;
        redo.lid = lid;
        redo.aligned = 0;
        log_put(session, RD_HEAP_ALLOC_MAP_NODE, &redo, sizeof(rd_alloc_map_node_t), LOG_ENTRY_FLAG_NONE);
    }

    TO_PAGID_DATA(AS_PAGID(page->head.id), tree_info.root);
    tree_info.level = segment->tree_info.level + 1;  // the max value of tree level is 2

    (void)cm_atomic_set(&segment->tree_info.value, tree_info.value);
    segment->curr_map[tree_info.level] = AS_PAGID(page->head.id);
    segment->map_count[tree_info.level] = 1;
}

static void heap_convert_map(knl_session_t *session, heap_segment_t *segment, map_page_t *page, uint32 level)
{
    if (level == segment->tree_info.level) {
        heap_convert_root(session, segment, page);
        return;
    }

    if (IS_INVALID_PAGID(segment->curr_map[level + 1])) {
        heap_convert_map(session, segment, page, level + 1);
        return;
    }

    heap_alloc_mp_for_map(session, segment, page, level + 1);

    segment->curr_map[level] = AS_PAGID(page->head.id);
    segment->map_count[level]++;
}

void heap_add_ufp(knl_session_t *session, heap_segment_t *segment, page_id_t page_id, uint32 count, bool32 need_noread)
{
    heap_page_t *page = NULL;
    heap_page_t *last_page = NULL;
    map_page_t *map_page = NULL;
    uint32 i, extent_size;
    rd_heap_format_page_t redo;

    // Latch the last page first, to avoid deadlock with change map.
    // The buffer would be released in during formating pages.
    if (!IS_INVALID_PAGID(segment->data_last)) {
        buf_enter_page(session, segment->data_last, LATCH_MODE_X, ENTER_PAGE_NORMAL);
        last_page = (heap_page_t *)CURR_PAGE(session);
    } else {
        last_page = NULL;
    }

    extent_size = heap_get_curr_ext_size(SPACE_GET(session, segment->space_id), segment);

    for (i = 0; i < count; i++) {
        // If the map page 0 is invalid, we need convert current page to map page.
        // Maybe after the first time conversion, the map page 0 is still invalid,
        // the page was convert to high level map page to keep the structure of map tree.
        if (IS_INVALID_PAGID(segment->curr_map[0])) {
            buf_enter_page(session, page_id, LATCH_MODE_X, need_noread ? ENTER_PAGE_NO_READ : ENTER_PAGE_NORMAL);
            map_page = (map_page_t *)CURR_PAGE(session);
            heap_format_map(session, map_page, page_id, extent_size);
            if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
                redo.extent_size = extent_size;
                redo.page_id = page_id;
                log_put(session, RD_HEAP_FORMAT_MAP, &redo, sizeof(rd_heap_format_page_t), LOG_ENTRY_FLAG_NONE);
            }
            heap_convert_map(session, segment, map_page, 0);
            buf_leave_page(session, GS_TRUE);

            page_id.page++;
            continue;
        }

        buf_enter_page(session, page_id, LATCH_MODE_X, need_noread ? ENTER_PAGE_NO_READ : ENTER_PAGE_NORMAL);
        page = (heap_page_t *)CURR_PAGE(session);
        heap_format_page(session, segment, page, page_id, extent_size);
        if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
            log_put(session, RD_HEAP_FORMAT_PAGE, page, (uint32)OFFSET_OF(heap_page_t, reserved), LOG_ENTRY_FLAG_NONE);
        }
        heap_alloc_mp_for_page(session, segment, page);
        buf_leave_page(session, GS_TRUE);

        if (last_page != NULL) {
            TO_PAGID_DATA(page_id, last_page->next);
            last_page = NULL;
            if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
                log_put(session, RD_HEAP_CONCAT_PAGE, &page_id, sizeof(page_id_t), LOG_ENTRY_FLAG_NONE);
            }
            buf_leave_page(session, GS_TRUE);
        } else if (!IS_INVALID_PAGID(segment->data_last)) {
            buf_enter_page(session, segment->data_last, LATCH_MODE_X, ENTER_PAGE_NORMAL);
            TO_PAGID_DATA(page_id, ((heap_page_t *)CURR_PAGE(session))->next);
            if (SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id))) {
                log_put(session, RD_HEAP_CONCAT_PAGE, &page_id, sizeof(page_id_t), LOG_ENTRY_FLAG_NONE);
            }
            buf_leave_page(session, GS_TRUE);
        } else {
            segment->data_first = page_id;
        }

        segment->data_last = page_id;
        page_id.page++;
    }

    // No heap pages added, release the last data page we holded at the beginning.
    if (last_page != NULL) {
        buf_leave_page(session, GS_FALSE);
    }
}

// Search from the root map of current segment level by level.
// Do a hash search on all the pages which fulfill the requirement on each level.
static status_t heap_find_map(knl_session_t *session, heap_t *heap, uint32 mid_input, page_id_t *page_id,
                              bool32 *degrade_mid)
{
    knl_tree_info_t tree_info;
    uint32 mid = mid_input;
    uint32 level, page_count;
    uint32 lid, cid;
    map_page_t *page = NULL;
    map_node_t *node = NULL;
    page_id_t map_id;
    *degrade_mid = GS_FALSE;

FIND_MAP:
    tree_info.value = cm_atomic_get(&HEAP_SEGMENT(session, heap->entry, heap->segment)->tree_info.value);
    map_id = AS_PAGID(tree_info.root);
    level = tree_info.level;

    for (;;) {
        if (buf_read_page(session, map_id, LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
            return GS_ERROR;
        }
        page = (map_page_t *)CURR_PAGE(session);

        page_count = 0;
        for (lid = mid; lid < HEAP_FREE_LIST_COUNT; lid++) {
            page_count += page->lists[lid].count;
        }

        if (page_count == 0) {
            if (level == tree_info.level) {
                if (session->kernel->attr.enable_degrade_search &&
                    mid == (HEAP_FREE_LIST_COUNT - 1) && !(*degrade_mid)) {
                    mid--;
                    for (lid = mid; lid < HEAP_FREE_LIST_COUNT; lid++) {
                        page_count += page->lists[lid].count;
                    }
                    *degrade_mid = GS_TRUE;
                }
                if (page_count == 0) {
                    buf_leave_page(session, GS_FALSE);
                    *page_id = INVALID_PAGID;
                    return GS_SUCCESS;
                }
            }

            if (page_count == 0) {
                buf_leave_page(session, GS_FALSE);
                /* someone is trying to change map, wait a while */
                knl_try_begin_session_wait(session, ENQ_HEAP_MAP, GS_FALSE);
                cm_spin_sleep_and_stat2(1);
                knl_try_end_session_wait(session, ENQ_HEAP_MAP);
                goto FIND_MAP;
            }
        }

        cid = session->id % page_count;
        for (lid = mid; lid < HEAP_FREE_LIST_COUNT; lid++) {
            if (cid < page->lists[lid].count) {
                break;
            }
            cid -= page->lists[lid].count;
        }

        knl_panic(lid < HEAP_FREE_LIST_COUNT);
        node = heap_get_map_node((char *)page, page->lists[lid].first);
        while (cid > 0) {
            node = heap_get_map_node((char *)page, (uint16)node->next);
            cid--;
        }

        if (level > 0) {
            level--;
            map_id.file = (uint16)node->file;
            map_id.page = (uint32)node->page;
            map_id.aligned = 0;
            buf_leave_page(session, GS_FALSE);
            continue;
        }

        page_id->file = (uint16)node->file;
        page_id->page = (uint32)node->page;
        page_id->aligned = 0;
        buf_leave_page(session, GS_FALSE);
        return GS_SUCCESS;
    }
}

static inline void heap_add_cached_page(knl_session_t *session, heap_t *heap, page_id_t page_id, uint32 page_count)
{
    session->curr_fsm = (session->curr_fsm + 1) % KNL_FSM_CACHE_COUNT;
    session->cached_fsms[session->curr_fsm].entry = heap->entry;
    session->cached_fsms[session->curr_fsm].seg_scn = HEAP_SEGMENT(session, heap->entry, heap->segment)->seg_scn;
    session->cached_fsms[session->curr_fsm].page_id = page_id;
    session->cached_fsms[session->curr_fsm].page_count = page_count;
}

static inline bool32 heap_find_cached_page(knl_session_t *session, heap_t *heap, page_id_t *page_id)
{
    knl_fsm_cache_t *cached_page = NULL;
    uint8 i, id;

    for (i = 0; i < KNL_FSM_CACHE_COUNT; i++) {
        id = (session->curr_fsm + i) % KNL_FSM_CACHE_COUNT;
        cached_page = &session->cached_fsms[id];

        if (IS_SAME_PAGID(heap->entry, cached_page->entry) &&
            HEAP_SEGMENT(session, heap->entry, heap->segment)->seg_scn == cached_page->seg_scn) {
            session->curr_fsm = id;
            *page_id = cached_page->page_id;
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

/*
 * remove page from cache
 * @param:
 *     appendonly: if the cached page id indicate an extent
 * @note
 *     For non-appendonly, just remove page from cache
 *     For appendonly,  cached page indicate an extent,  cached page may be a map page .
 *     So , if cached page is not the last page of format unit, just add next page of this extent to cache.
 * @attention
 *     For segment which extents count is 1, pages of the first extents has not all added into segment.
 *     So, we should not remove cached page by appendonly mode for segment which extents count is 1.
 */
void heap_remove_cached_page(knl_session_t *session, bool32 appendonly)
{
    knl_fsm_cache_t *cached_page = &session->cached_fsms[session->curr_fsm];

    if (appendonly && cached_page->page_count > 1) {
        cached_page->page_id.page++;
        cached_page->page_count--;
        return;
    }

    cached_page->seg_scn = GS_INVALID_ID64;
    cached_page->entry = INVALID_PAGID;
    cached_page->page_id = INVALID_PAGID;
    cached_page->page_count = 0;

    session->curr_fsm = (session->curr_fsm + 1) % KNL_FSM_CACHE_COUNT;
}

static void heap_set_max_compact_hwm(knl_session_t *session, heap_t *heap,
    map_path_t *new_hwm_path, page_id_t new_hwm)
{
    heap_segment_t *segment = HEAP_SEGMENT(session, heap->entry, heap->segment);
    page_id_t hwm = segment->cmp_hwm;
    map_path_t hwm_path;

    if (IS_INVALID_PAGID(hwm)) {
        return;
    }

    if (!IS_INVALID_PAGID(new_hwm)) {
        heap_get_map_path(session, heap, hwm, &hwm_path);
        if (heap_compare_map_path(new_hwm_path, &hwm_path) <= 0) {
            return;
        }
    }

    log_atomic_op_begin(session);

    buf_enter_page(session, heap->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    segment = HEAP_SEG_HEAD(session);
    hwm = segment->cmp_hwm;

    if (IS_INVALID_PAGID(hwm)) {
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return;
    }

    if (!IS_INVALID_PAGID(new_hwm)) {
        heap_get_map_path(session, heap, segment->cmp_hwm, &hwm_path);
        if (heap_compare_map_path(new_hwm_path, &hwm_path) <= 0) {
            buf_leave_page(session, GS_FALSE);
            log_atomic_op_end(session);
            return;
        }
    }

    segment->cmp_hwm = new_hwm;
    if (SPC_IS_LOGGING_BY_PAGEID(session, heap->entry)) {
        log_put(session, RD_HEAP_CHANGE_SEG, segment, HEAP_SEG_SIZE, LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, GS_TRUE);
    log_atomic_op_end(session);
}

static status_t heap_extend_free_page(knl_session_t *session, heap_t *heap, knl_part_locate_t part_loc,
                                      bool32 async_shrink, uint8 mid, page_id_t *page_id, bool32 compacting)
{
    if (compacting) {
        GS_THROW_ERROR(ERR_SHRINK_EXTEND);
        return GS_ERROR;
    }

    // notify async shrink skip this heap
    if (SECUREC_UNLIKELY(async_shrink && heap->table->ashrink_stat == ASHRINK_WAIT_SHRINK)) {
        heap_set_max_compact_hwm(session, heap, NULL, INVALID_PAGID);
    }

    if (!heap_prepare_extend(session, heap, mid, part_loc)) {
        return GS_SUCCESS;
    }

    if (heap_extend_segment(session, heap, page_id) != GS_SUCCESS) {
        heap_unset_extend_flag(session, heap, part_loc);
        return GS_ERROR;
    }

    heap_add_extent(session, heap, *page_id, NULL);
    heap_unset_extend_flag(session, heap, part_loc);
    return GS_SUCCESS;
}

/*
 * find a free page for insert or update migration
 * For insert, use session cached page to accelerate bulk load if possible.
 * For update, find free page from map tree directly.
 * @param kernel session, heap, data size, use cached or not, page id (output)
 */
status_t heap_find_free_page(knl_session_t *session, knl_handle_t heap_handle, knl_part_locate_t part_loc, uint8 mid,
                             bool32 use_cached, page_id_t *page_id, bool32 *degrade_mid)
{
    heap_t *heap = (heap_t *)heap_handle;
    heap_segment_t *segment = HEAP_SEGMENT(session, heap->entry, heap->segment);
    map_path_t path;
    bool32 compacting = heap->compacting && session->compacting;
    table_t *table = heap->table;
    bool32 async_shrink = GS_FALSE;
    map_path_t *path_p = NULL;

    if (SECUREC_UNLIKELY(ASHRINK_HEAP(table, heap) && !session->compacting)) {
        if (heap->ashrink_stat != ASHRINK_WAIT_SHRINK || !IS_INVALID_PAGID(segment->cmp_hwm)) {
            async_shrink = GS_TRUE;
            path_p = &path;
        }
    }

    if (use_cached && !compacting && !async_shrink) {
        if (heap_find_cached_page(session, heap, page_id)) {
            return GS_SUCCESS;
        }
    }

    for (;;) {
        if (compacting || (segment->extents.count == 1 || async_shrink)) {
            if (heap_seq_find_map(session, heap, path_p, mid, page_id, degrade_mid) != GS_SUCCESS) {
                return GS_ERROR;
            }
        } else {
            if (heap_find_map(session, heap, mid, page_id, degrade_mid) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (!IS_INVALID_PAGID(*page_id)) {
            break;
        }

        if (heap_extend_free_page(session, heap, part_loc, async_shrink, mid, page_id, compacting) != GS_SUCCESS) {
            return GS_ERROR;
        }

        async_shrink = GS_FALSE;
    }

    if (SECUREC_UNLIKELY(async_shrink && table->ashrink_stat == ASHRINK_WAIT_SHRINK)) {
        heap_set_max_compact_hwm(session, heap, path_p, *page_id);
    }

    heap_add_cached_page(session, heap, *page_id, 1);

    return GS_SUCCESS;
}

/*
 * add a page from delete row into transaction free page list
 */
void heap_add_tx_free_page(knl_session_t *session, knl_handle_t heap_handle,
    page_id_t page_id, uint8 itl_id, xid_t xid, knl_scn_t seg_scn)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    heap_t *heap = (heap_t *)heap_handle;
    uint8 tx_fpl_idx = 0;

    if (kernel->attr.enable_tx_free_page_list == GS_FALSE) {
        session->tx_fpl.index = 0;
        session->tx_fpl.count = 0;
        return;
    }

    tx_fpl_idx = (session->tx_fpl.index + 1) % KNL_TX_FPL_COUNT;

    session->tx_fpl.pages[tx_fpl_idx].entry = heap->entry;
    session->tx_fpl.pages[tx_fpl_idx].seg_scn = seg_scn;
    session->tx_fpl.pages[tx_fpl_idx].page_id = page_id;
    session->tx_fpl.pages[tx_fpl_idx].itl_id = itl_id;
    session->tx_fpl.pages[tx_fpl_idx].xid = xid;

    session->tx_fpl.index = tx_fpl_idx;
    session->tx_fpl.count++;

    if (session->tx_fpl.count > KNL_TX_FPL_COUNT) {
        session->tx_fpl.count = KNL_TX_FPL_COUNT;
    }
}


/*
 * find a free page for insert from transaction free page list
 */
int32 heap_find_tx_free_page_index(knl_session_t *session, knl_handle_t heap_handle, uint8 *next, uint8 *count)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    knl_tx_fpl_node_t *cached_page = NULL;
    heap_t *heap = (heap_t *)heap_handle;
    int32 curr_index = 0;

    if (kernel->attr.enable_tx_free_page_list == GS_FALSE) {
        session->tx_fpl.index = 0;
        session->tx_fpl.count = 0;
        return -1;
    }

    if (heap->compacting && session->compacting) {
        return -1;
    }

    if (*count > KNL_TX_FPL_COUNT) {
        *count = KNL_TX_FPL_COUNT;
    }

    while (*count > 0) {
        (*count)--;
        curr_index = (*next) % KNL_TX_FPL_COUNT;
        // from last to old item
        if (*next == 0) {
            *next = *next + KNL_TX_FPL_COUNT;
        }
        (*next)--;

        cached_page = &session->tx_fpl.pages[curr_index];
        if (IS_SAME_PAGID(heap->entry, cached_page->entry) &&
            HEAP_SEGMENT(session, heap->entry, heap->segment)->seg_scn == cached_page->seg_scn &&
            session->rm != NULL &&
            session->rm->xid.value == cached_page->xid.value) {
            return curr_index;
        }
    }

    // search end
    return -1;
}

/*
 * find page in appendonly mode for insert
 * use session cached page to accelerate bulk load if possible.
 * @param kernel session, heap, data size, use cached or not, page id (output)
 */
status_t heap_find_appendonly_page(knl_session_t *session, knl_handle_t heap_handle, knl_part_locate_t part_loc,
                                   uint32 data_size, page_id_t *page_id)
{
    heap_t *heap = (heap_t *)heap_handle;
    uint32 mid = HEAP_FREE_LIST_COUNT;
    uint32 page_count;

    if (heap_find_cached_page(session, heap, page_id)) {
        return GS_SUCCESS;
    }

    for (;;) {
        if (!heap_prepare_extend(session, heap, mid, part_loc)) {
            continue;
        }

        if (heap_extend_segment(session, heap, page_id) != GS_SUCCESS) {
            heap_unset_extend_flag(session, heap, part_loc);
            return GS_ERROR;
        }

        heap_add_extent(session, heap, *page_id, &page_count);
        heap_unset_extend_flag(session, heap, part_loc);
        break;
    }

    heap_add_cached_page(session, heap, *page_id, page_count);

    return GS_SUCCESS;
}

/*
 * heap init map path for parallel query
 * @param map path, map page_id, map level
 */
static void heap_paral_init_map_path(map_path_t *path, page_id_t map_id, uint32 map_level)
{
    map_index_t *index = NULL;
    uint32 i;

    path->level = map_level;

    index = &path->index[path->level];
    index->file = map_id.file;
    index->page = map_id.page;
    index->slot = 0;

    for (i = 0; i < path->level; i++) {
        index = &path->index[i];
        index->slot = INVALID_SLOT;
    }
}

/*
 * heap traversal map for parallel query
 * Get the next heap page_id using the current map path and interval.
 * @param kernel session, map path, interval, page_id(output)
 */
static void heap_paral_traversal_map(knl_session_t *session, map_path_t *path, uint32 interval, page_id_t *page_id)
{
    map_index_t *index = NULL;
    map_page_t *page = NULL;
    map_node_t *node = NULL;
    page_id_t map_id;
    uint32 steps[HEAP_MAX_MAP_LEVEL];
    uint32 map_nodes, curr;
    uint32 level = 0;
    int32 ret;

    map_nodes = session->kernel->attr.max_map_nodes;
    ret = memset_sp(steps, sizeof(uint32) * HEAP_MAX_MAP_LEVEL, 0, sizeof(uint32) * HEAP_MAX_MAP_LEVEL);
    knl_securec_check(ret);
    steps[0] = interval;

    for (;;) {
        if (level > path->level) {
            *page_id = INVALID_PAGID;
            return;
        }

        index = &path->index[level];

        if (index->slot == INVALID_SLOT) {
            level++;
            continue;
        }

        map_id.file = (uint16)index->file;
        map_id.page = (uint32)index->page;
        map_id.aligned = 0;

        buf_enter_page(session, map_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        page = (map_page_t *)CURR_PAGE(session);
        if (page->head.type != PAGE_TYPE_HEAP_MAP) {
            *page_id = INVALID_PAGID;
            buf_leave_page(session, GS_FALSE);
            return;
        }

        curr = (uint32)index->slot + steps[level];
        if (curr >= (uint32)page->hwm) {
            if ((uint32)page->hwm != map_nodes || level == path->level) {
                *page_id = INVALID_PAGID;
                buf_leave_page(session, GS_FALSE);
                return;
            }

            steps[level + 1] = (curr - (uint32)page->hwm) / map_nodes + 1;
            steps[level] = (curr - (uint32)page->hwm) % map_nodes;
            index->slot = 0;

            buf_leave_page(session, GS_FALSE);
            level++;
            continue;
        }

        node = heap_get_map_node((char *)page, (uint16)curr);
        index->slot = (uint64)curr;

        if (level > 0) {
            level--;
            index = &path->index[level];
            index->file = node->file;
            index->page = node->page;

            if (index->slot == INVALID_SLOT) {
                index->slot = 0;
            }
            buf_leave_page(session, GS_FALSE);
            continue;
        }

        page_id->file = (uint16)node->file;
        page_id->page = (uint32)node->page;
        page_id->aligned = 0;
        buf_leave_page(session, GS_FALSE);
        return;
    }
}

/*
 * heap get parallel range
 * Get every parallel range left and right boundary by traversal the map
 * tree in the special way.
 * @note we set the last valid range's right boundary as half open interval, so
 * we would not miss any pages which would be added after the parallel calculation.
 * @param kernel session, map page_id, map level, page count, parallel range
 */
static void heap_get_paral_range(knl_session_t *session, page_id_t map_id, uint32 level,
                                 uint32 pages, knl_paral_range_t *range)
{
    map_path_t path;
    page_id_t page_id;
    uint32 interval;
    uint32 i;

    knl_panic_log(range->workers > 0, "current workers is invalid, panic info: page %u-%u workers %u", map_id.file,
                  map_id.page, range->workers);
    interval = pages / range->workers - 1;
    heap_paral_init_map_path(&path, map_id, level);

    for (i = 0; i < range->workers; i++) {
        heap_paral_traversal_map(session, &path, (i == 0) ? 0 : 1, &page_id);
        range->l_page[i] = page_id;

        if (IS_INVALID_PAGID(page_id)) {
            range->workers = i;
            break;
        }

        heap_paral_traversal_map(session, &path, interval, &page_id);
        range->r_page[i] = page_id;

        if (IS_INVALID_PAGID(page_id)) {
            range->workers = i + 1;
            break;
        }
    }

    if (range->workers > 0) {
        range->r_page[range->workers - 1] = INVALID_PAGID;
    }
}

/*
 * heap get parallel schedule
 * We divide the estimated pages into each parallel worker uniformly.
 * Notes we would adjust the workers count if it's too large.
 * @param kernel session, heap, org_scn, expected worker count, parallel range
 */
void heap_get_paral_schedule(knl_session_t *session, knl_handle_t heap_handle, knl_scn_t org_scn,
                             uint32 workers, knl_paral_range_t *range)
{
    heap_t *heap = (heap_t *)heap_handle;
    heap_segment_t *segment = NULL;
    page_head_t *head = NULL;
    space_t *space = NULL;
    page_id_t map_id;
    uint32 level, extents;
    uint64 pages, map_nodes;

    if (workers == 0 || IS_INVALID_PAGID(heap->entry)) {
        range->workers = 0;
        return;
    }

    map_nodes = (uint64)session->kernel->attr.max_map_nodes;

    buf_enter_page(session, heap->entry, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    head = (page_head_t *)CURR_PAGE(session);
    segment = HEAP_SEG_HEAD(session);
    if (head->type != PAGE_TYPE_HEAP_HEAD || segment->org_scn != org_scn) {
        buf_leave_page(session, GS_FALSE);
        range->workers = 0;
        return;
    }

    map_id = AS_PAGID(segment->tree_info.root);
    level = segment->tree_info.level;
    space = SPACE_GET(session, segment->space_id);
    extents = segment->extents.count;

    // this is an estimate (exclude map level 0)
    range->workers = (extents < workers) ? extents : workers;
    pages = (uint64)heap_get_segment_page_count(space, segment) * map_nodes / (map_nodes + 1);
    buf_leave_page(session, GS_FALSE);

    heap_get_paral_range(session, map_id, level, (uint32)pages, range);
}

/*
 * heap get min map slot
 * Get the min map slot in current map page which satisfied the min list lid.
 * @param map page, min list lid.
 */
static uint16 heap_get_min_map_slot(map_page_t *page, uint32 mid)
{
    map_node_t *node = NULL;
    uint32 lid;
    uint16 curr, slot;

    slot = INVALID_SLOT;

    for (lid = HEAP_FREE_LIST_COUNT - 1; lid >= mid; lid--) {
        if (page->lists[lid].count == 0) {
            continue;
        }

        curr = page->lists[lid].first;

        while (curr != INVALID_SLOT) {
            node = heap_get_map_node((char *)page, curr);

            if (curr < slot) {
                slot = curr;
            }

            curr = (uint16)node->next;
        }
    }

    return slot;
}

/*
 * heap seq find map
 * Find map seq scan , same like heap find map,
 * but a little different. Here we find page from the front the segment page list
 * @param kernel session, heap, map path, min list id, page_id(output)
 */
status_t heap_seq_find_map(knl_session_t *session, knl_handle_t heap_handle, map_path_t *path,
                           uint32 mid_input, page_id_t *page_id, bool32 *degrade_mid)
{
    heap_t *heap = (heap_t *)heap_handle;
    knl_tree_info_t tree_info;
    map_page_t *page = NULL;
    map_node_t *node = NULL;
    uint32 mid = mid_input;
    page_id_t map_id;
    uint32 level;
    uint16 slot;
    errno_t ret;
    *degrade_mid = GS_FALSE;

SEQ_FIND_MAP:
    tree_info.value = cm_atomic_get(&HEAP_SEGMENT(session, heap->entry, heap->segment)->tree_info.value);
    map_id = AS_PAGID(tree_info.root);
    level = tree_info.level;

    if (path != NULL) {
        ret = memset_sp(path, sizeof(map_path_t), 0, sizeof(map_path_t));
        knl_securec_check(ret);
        path->level = level;
    }
    
    /*
     * search area include lower lid for shrink insert
     */
    if (session->kernel->attr.enable_degrade_search && mid == (HEAP_FREE_LIST_COUNT - 1)) {
        mid--;
        *degrade_mid = GS_TRUE;
    }

    for (;;) {
        if (buf_read_page(session, map_id, LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
            return GS_ERROR;
        }
        page = (map_page_t *)CURR_PAGE(session);

        slot = heap_get_min_map_slot(page, mid);
        if (slot == INVALID_SLOT) {
            buf_leave_page(session, GS_FALSE);

            if (level == tree_info.level) {
                *page_id = INVALID_PAGID;
                return GS_SUCCESS;
            }

            /** someone is trying to change map, wait a while */
            knl_try_begin_session_wait(session, ENQ_HEAP_MAP, GS_FALSE);
            cm_spin_sleep_and_stat2(1);
            knl_try_end_session_wait(session, ENQ_HEAP_MAP);
            goto SEQ_FIND_MAP;
        }

        node = heap_get_map_node((char *)page, slot);

        if (path != NULL) {
            path->index[level].file = map_id.file;
            path->index[level].page = map_id.page;
            path->index[level].slot = slot;
        }

        if (level > 0) {
            level--;
            map_id.file = (uint16)node->file;
            map_id.page = (uint32)node->page;
            map_id.aligned = 0;
            buf_leave_page(session, GS_FALSE);
            continue;
        }

        page_id->file = (uint16)node->file;
        page_id->page = (uint32)node->page;
        page_id->aligned = 0;
        buf_leave_page(session, GS_FALSE);
        return GS_SUCCESS;
    }
}

/*
 * heap compare two map path
 * @param left map path, right map path
 */
int32 heap_compare_map_path(map_path_t *left, map_path_t *right)
{
    int32 i;

    for (i = HEAP_MAX_MAP_LEVEL - 1; i >= 0; i--) {
        if (left->index[i].slot == right->index[i].slot) {
            continue;
        }

        return (left->index[i].slot > right->index[i].slot) ? 1 : -1;
    }

    return 0;
}

/*
 * heap get map path
 * Get the map path of the given heap page
 * @param kernel session, heap, heap page_id, map path
 */
void heap_get_map_path(knl_session_t *session, knl_handle_t heap_handle, page_id_t page_id, map_path_t *path)
{
    map_page_t *page = NULL;
    uint32 level = 0;
    errno_t ret;

    ret = memset_sp(path, sizeof(map_path_t), 0, sizeof(map_path_t));
    knl_securec_check(ret);

    for (;;) {
        buf_enter_page(session, page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        page = (map_page_t *)CURR_PAGE(session);
        if (page->map.file == INVALID_FILE_ID) {
            knl_panic_log(level > 0, "current level is invalid, panic info: page %u-%u type %u level %u",
                          AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, level);
            path->level = level - 1;
            buf_leave_page(session, GS_FALSE);
            return;
        } else {
            path->index[level].file = page->map.file;
            path->index[level].page = page->map.page;
            path->index[level].slot = page->map.slot;
        }

        page_id.file = (uint16)page->map.file;
        page_id.page = (uint32)page->map.page;
        page_id.aligned = 0;
        buf_leave_page(session, GS_FALSE);

        level++;
    }
}

#ifdef LOG_DIAG
/*
 * heap validate map
 * Validate very slot on very list in current map page.
 * @param kernel session, map page
 */
void heap_validate_map(knl_session_t *session, page_head_t *page)
{
    map_page_t *map_page;
    map_node_t *node = NULL;
    map_node_t *prev = NULL;
    map_node_t *next = NULL;
    uint16 lid;
    uint16 slot;
    uint16 count;
    uint16 total;

    total = 0;
    map_page = (map_page_t *)page;

    for (lid = 0; lid < HEAP_FREE_LIST_COUNT; lid++) {
        slot = map_page->lists[lid].first;

        if (map_page->lists[lid].count == 0) {
            knl_panic_log(slot == INVALID_SLOT,
                "current map page slot is valid, panic info: page %u-%u type %u slot %u",
                AS_PAGID(map_page->head.id).file, AS_PAGID(map_page->head.id).page, map_page->head.type, slot);
            continue;
        }

        count = 0;

        while (slot != INVALID_SLOT) {
            knl_panic_log(slot < map_page->hwm, "current map page is more than map_page's hwm, panic info: "
                          "page %u-%u type %u slot %u hwm %u", AS_PAGID(map_page->head.id).file,
                          AS_PAGID(map_page->head.id).page, map_page->head.type, slot, map_page->hwm);

            node = heap_get_map_node((char *)page, slot);
            if (node->prev != INVALID_SLOT) {
                prev = heap_get_map_node((char *)page, (uint16)node->prev);
                knl_panic_log(prev->next == slot, "prev node's next is not pointing to the current map page, panic "
                    "info: page %u-%u type %u prev's next %u current map slot %u", AS_PAGID(map_page->head.id).file,
                    AS_PAGID(map_page->head.id).page, map_page->head.type, prev->next, slot);
            }

            if (node->next != INVALID_SLOT) {
                next = heap_get_map_node((char *)page, (uint16)node->next);
                knl_panic_log(next->prev == slot, "next node's prev is not pointing to the current map page, panic "
                    "info: page %u-%u type %u next's prev %u current map slot %u", AS_PAGID(map_page->head.id).file,
                    AS_PAGID(map_page->head.id).page, map_page->head.type, next->prev, slot);
            }

            slot = (uint16)node->next;

            count++;
        }

        knl_panic_log(count == map_page->lists[lid].count, "the map_page count is abnormal, panic info: "
                      "page %u-%u type %u curr count %u map_page_count %u", AS_PAGID(map_page->head.id).file,
                      AS_PAGID(map_page->head.id).page, map_page->head.type, count, map_page->lists[lid].count);
        total += count;
    }

    knl_panic_log(map_page->hwm == total,
                  "the hwm is abnormal, panic info: map_page hwm %u total %u page %u-%u type %u", map_page->hwm, total,
                  AS_PAGID(map_page->head.id).file, AS_PAGID(map_page->head.id).page, map_page->head.type);
}
#endif  // LOG_DIAG

status_t map_dump_page(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump)
{
    map_page_t *page = (map_page_t *)page_head;

    cm_dump(dump, "map page information\n");
    cm_dump(dump, "\tmap.file %u, mape.page %u, map.slot %u map.list_id %u\n",
        (uint32)page->map.file, (uint32)page->map.page, (uint32)page->map.slot, (uint32)page->map.list_id);
    cm_dump(dump, "\thwm: %u\n", page->hwm);

    cm_dump(dump, "list information on this page\n");
    CM_DUMP_WRITE_FILE(dump);
    for (uint32 slot = 0; slot < HEAP_FREE_LIST_COUNT; slot++) {
        cm_dump(dump, "\tlists[%u] ", slot);
        cm_dump(dump, "\tcount: #%-3u", page->lists[slot].count);
        cm_dump(dump, "\tfirst: %u\n", page->lists[slot].first);
        CM_DUMP_WRITE_FILE(dump);
    }

    cm_dump(dump, "map information on this page\n");
    CM_DUMP_WRITE_FILE(dump);

    map_node_t *node = NULL;
    for (uint32 slot = 0; slot < (uint32)page->hwm; slot++) {
        node = (map_node_t *)((char *)page + sizeof(map_page_t) + slot * sizeof(map_node_t));
        cm_dump(dump, "\tnodes[%u] ", slot);
        cm_dump(dump, "\tfile: %-3u", (uint32)node->file);
        cm_dump(dump, "\tpage: %u", (uint32)node->page);
        cm_dump(dump, "\tprev: %u", (uint32)node->prev);
        cm_dump(dump, "\tnext: %u\n", (uint32)node->next);
        CM_DUMP_WRITE_FILE(dump);
    }

    return GS_SUCCESS;
}

status_t map_segment_dump(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump)
{
    heap_segment_t *segment = HEAP_SEG_HEAD(session);

    cm_dump(dump, "heap segment information\n");
    cm_dump(dump, "\tuid %u, oid %u, space_id %u\n", segment->uid,
        segment->oid, segment->space_id);
    cm_dump(dump, "\tinitrans: %u", segment->initrans);
    cm_dump(dump, "\torg_scn: %llu", segment->org_scn);
    cm_dump(dump, "\tseg_scn: %llu", segment->seg_scn);
    cm_dump(dump, "\tcrmode: %u", segment->cr_mode);
    cm_dump(dump, "\tserial: %llu\n", segment->serial);
    CM_DUMP_WRITE_FILE(dump);
    cm_dump(dump, "heap storage information\n");
    cm_dump(dump, "\textents: count %u, first %u-%u, last %u-%u\n", segment->extents.count,
        segment->extents.first.file, segment->extents.first.page,
        segment->extents.last.file, segment->extents.last.page);
    cm_dump(dump, "\tfree_extents: count %u, first %u-%u, last %u-%u\n",
        segment->extents.count,
        segment->free_extents.first.file, segment->free_extents.first.page,
        segment->free_extents.last.file, segment->free_extents.last.page);
    cm_dump(dump, "\tfree_ufp: %u-%u\n", segment->free_ufp.file, segment->free_ufp.page);
    cm_dump(dump, "\tdata_first: %u-%u\n", segment->data_first.file, segment->data_first.page);
    cm_dump(dump, "\tdata_last: %u-%u\n", segment->data_last.file, segment->data_last.page);
    cm_dump(dump, "\tcmp_hwm: %u-%u\n", segment->cmp_hwm.file, segment->cmp_hwm.page);
    cm_dump(dump, "\tshrinkable_scn: %llu\n", segment->shrinkable_scn);
    CM_DUMP_WRITE_FILE(dump);
    cm_dump(dump, "heap map information\n");
    cm_dump(dump, "\ttree_info.level: %u\n", (uint32)segment->tree_info.level);
    cm_dump(dump, "\ttree_info.root: %u-%u", (uint32)AS_PAGID(segment->tree_info.root).file,
        (uint32)AS_PAGID(segment->tree_info.root).page);
    cm_dump(dump, "\n\tcurr_map: ");
    CM_DUMP_WRITE_FILE(dump);
    for (uint32 i = 0; i <= (uint32)segment->tree_info.level; i++) {
        cm_dump(dump, "%u-%u ", segment->curr_map[i].file, segment->curr_map[i].page);
        CM_DUMP_WRITE_FILE(dump);
    }

    cm_dump(dump, "\n\tmap_count: ");
    CM_DUMP_WRITE_FILE(dump);
    for (uint32 i = 0; i <= (uint32)segment->tree_info.level; i++) {
        cm_dump(dump, "%u ", segment->map_count[i]);
        CM_DUMP_WRITE_FILE(dump);
    }

    cm_dump(dump, "\n\tlist_range: ");
    CM_DUMP_WRITE_FILE(dump);
    for (uint32 i = 0; i < HEAP_FREE_LIST_COUNT; i++) {
        cm_dump(dump, "%u ", segment->list_range[i]);
        CM_DUMP_WRITE_FILE(dump);
    }

    return GS_SUCCESS;
}
