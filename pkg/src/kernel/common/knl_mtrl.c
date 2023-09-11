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
 * knl_mtrl.c
 *
 *
 * IDENTIFICATION
 * src/kernel/common/knl_mtrl.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_mtrl.h"
#include "rcr_btree.h"
#include "pcr_btree.h"
#include "knl_context.h"
#include "index_common.h"

#define MTRL_SESSION(ctx)                   ((ctx)->session)
#define MTRL_POOL(ctx)                      ((ctx)->pool)

#define MTRL_ROW_SIZE(segment, row) mtrl_row_size(segment, row)

#ifdef __cplusplus
extern "C" {
#endif

static inline uint16 mtrl_row_size(mtrl_segment_t *segment, const char *row)
{
    switch (segment->type) {
        case MTRL_SEGMENT_RCR_BTREE:
            return (uint16)((btree_key_t *)row)->size;

        case MTRL_SEGMENT_PCR_BTREE:
            return (uint16)((pcrb_key_t *)row)->size;

        default:
            return (uint16)((row_head_t *)row)->size;
    }
}

/*
 * Description     : open materialized page
 * Input           : vmid: vm page id
 * Output          : page: vm page
 * Return Value    : status_t
 */
status_t mtrl_open_page(mtrl_context_t *ctx, uint32 vmid, vm_page_t **page)
{
    uint32 i;
    uint32 id = GS_INVALID_ID32;
    cm_spin_lock(&ctx->lock, NULL);
    uint32 max_pos = ctx->open_hwm + 1 > GS_MAX_MTRL_OPEN_PAGES ? GS_MAX_MTRL_OPEN_PAGES : ctx->open_hwm + 1;
    for (i = 0; i < max_pos; i++) {
        if (ctx->open_pages[i] == vmid) {
            id = i;
            break;
        }

        if (ctx->open_pages[i] == GS_INVALID_ID32 && id == GS_INVALID_ID32) {
            id = i;
            // don't break in case there exists the vmid afterwards.
        }
    }

    if (id == GS_INVALID_ID32) {
        GS_THROW_ERROR(ERR_VM, "fail to open vm page, the pages are already full");
        cm_spin_unlock(&ctx->lock);
        return GS_ERROR;
    }

    if (vm_open(MTRL_SESSION(ctx), MTRL_POOL(ctx), vmid, page) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_VM, "fail to open the vm");
        cm_spin_unlock(&ctx->lock);
        return GS_ERROR;
    }
    knl_panic((*page)->vmid == vmid);

    if (id + 1 > ctx->open_hwm) {
        ctx->open_hwm = id + 1;
    }

    ctx->open_pages[id] = vmid;
    cm_spin_unlock(&ctx->lock);
    return GS_SUCCESS;
}

/*
 * Description     : close materialized page
 * Input           : need_free : if we need to free this vm page
 * Output          : NA
 * Return Value    : void
 */
void mtrl_close_page(mtrl_context_t *ctx, uint32 vmid)
{
    uint32 i;
    uint32 ref_num = 0;
    vm_ctrl_t *ctrl = NULL;

    cm_spin_lock(&ctx->lock, NULL);
    for (i = 0; i < ctx->open_hwm; i++) {
        if (ctx->open_pages[i] == vmid) {
            ctrl = vm_get_ctrl(MTRL_POOL(ctx), vmid);
            ref_num = ctrl->ref_num;

            vm_close(MTRL_SESSION(ctx), MTRL_POOL(ctx), vmid, VM_ENQUE_TAIL);

            if (ref_num <= 1) {
                ctx->open_pages[i] = GS_INVALID_ID32;
            }
            break;
        }
    }

    while (GS_TRUE) {
        if (ctx->open_hwm == 0) {
            break;
        }

        if (ctx->open_pages[ctx->open_hwm - 1] == GS_INVALID_ID32) {
            --ctx->open_hwm;
        } else {
            break;
        }
    }

    cm_spin_unlock(&ctx->lock);
}

/*
 * Description     : init materialized page
 * Input           : page : vm page
 * Input           : id : vm page id
 * Output          : NA
 * Return Value    : void
 */
void mtrl_release_segment(mtrl_context_t *ctx, uint32 id)
{
    if (ctx->segments[id] != NULL && ctx->segments[id]->is_used) {
        CM_ASSERT(ctx->segments[id]->curr_page == NULL);
        vm_free_list(MTRL_SESSION(ctx), MTRL_POOL(ctx), &ctx->segments[id]->vm_list);
        ctx->segments[id]->is_used = GS_FALSE;
        ctx->seg_count--;
    }
}

static inline void mtrl_reset_segments(mtrl_context_t *ctx)
{
    for (uint32 i = 0; i < GS_MAX_MATERIALS; i++) {
        ctx->segments[i] = NULL;
    }
}

static inline void mtrl_reset_open_pages(mtrl_context_t *ctx)
{
    MEMS_RETVOID_IFERR(memset_sp(ctx->open_pages, sizeof(ctx->open_pages), 0xFF, sizeof(ctx->open_pages)));
}

void mtrl_init_context(mtrl_context_t *ctx, handle_t sess)
{
    ctx->seg_count = 0;
    ctx->lock = 0;
    mtrl_reset_open_pages(ctx);

    ctx->session = sess;
    ctx->pool = ((knl_session_t *)sess)->temp_pool;
    mtrl_reset_segments(ctx);
    g_knl_callback.init_vmc((handle_t)ctx);

    ctx->print_page = NULL;
    ctx->open_hwm = 0;
    ctx->err_msg = g_tls_error.message;
}

void mtrl_release_context(mtrl_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mtrl_reset_open_pages(ctx);
    if (ctx->seg_count == 0) {
        mtrl_reset_segments(ctx);
        vmc_free(&ctx->vmc);
        return;
    }

    for (uint32 i = 0; i < GS_MAX_MATERIALS; i++) {
        if (ctx->segments[i] != NULL) {
            ctx->segments[i]->curr_page = NULL;
            mtrl_release_segment(ctx, i);
            ctx->segments[i] = NULL;
        }
    }

    ctx->seg_count = 0;
    ctx->open_hwm = 0;
    vmc_free(&ctx->vmc);
}

status_t mtrl_recreate_segment(mtrl_context_t *ctx, mtrl_segment_t *curr_seg, mtrl_segment_t *segment)
{
    uint32 vmid;

    segment->vm_list.count = 0;

    if (vm_alloc(MTRL_SESSION(ctx), MTRL_POOL(ctx), &vmid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    segment->vm_list.count = 1;
    segment->vm_list.first = vmid;
    segment->vm_list.last = vmid;
    segment->cmp_items = curr_seg->cmp_items;
    segment->type = curr_seg->type;
    segment->level = 0;
    segment->pending_type_buf = NULL;
    return GS_SUCCESS;
}

static mtrl_segment_t *mtrl_get_idle_segment(mtrl_context_t *ctx, uint32 *id)
{
    uint32 i;

    if (ctx->seg_count >= GS_MAX_MATERIALS) {
        GS_THROW_ERROR(ERR_SQL_TOO_COMPLEX);
        return NULL;
    }

    for (i = 0; i < GS_MAX_MATERIALS; ++i) {
        if (ctx->segments[i] == NULL) {
            if (vmc_alloc_mem(&ctx->vmc, sizeof(mtrl_segment_t), (void **)&ctx->segments[i]) != GS_SUCCESS) {
                return NULL;
            }
        }
        if (!ctx->segments[i]->is_used) {
            ctx->segments[i]->is_used = GS_TRUE;
            ctx->seg_count++;
            *id = i;
            return ctx->segments[i];
        }
    }

    GS_THROW_ERROR(ERR_SQL_TOO_COMPLEX);
    return NULL;
}

static void mtrl_set_segment_sort_type(mtrl_segment_t *segment)
{
    switch (segment->type) {
        case MTRL_SEGMENT_PCR_BTREE:
        case MTRL_SEGMENT_RCR_BTREE:
        case MTRL_SEGMENT_DISTINCT:
        case MTRL_SEGMENT_GROUP:
        case MTRL_SEGMENT_RS:
        case MTRL_SEGMENT_QUERY_SORT:
        case MTRL_SEGMENT_SELECT_SORT:
        case MTRL_SEGMENT_AGGR:
        case MTRL_SEGMENT_WINSORT:
        case MTRL_SEGMENT_CONCAT_SORT:
        case MTRL_SEGMENT_SORT_SEG:
        case MTRL_SEGMENT_SIBL_SORT:
            segment->sort_type = MTRL_SORT_TYPE_ADAPTIVE_SORT;
            break;
        default:
            break;
    }
}

status_t mtrl_create_segment(mtrl_context_t *ctx, mtrl_segment_type_t type, handle_t cmp_items, uint32 *id)
{
    mtrl_segment_t *segment = mtrl_get_idle_segment(ctx, id);

    if (segment == NULL) {
        GS_LOG_RUN_ERR("[MTRL] failed to get idle segment");
        return GS_ERROR;
    }

    mtrl_init_segment(segment, type, cmp_items);
    if (cmp_items != NULL) {
        mtrl_set_segment_sort_type(segment);
    }
    return vm_alloc_and_append(MTRL_SESSION(ctx), MTRL_POOL(ctx), &segment->vm_list);
}

void mtrl_set_sort_type(mtrl_segment_t *segment, mtrl_sort_type_t sort_type)
{
    segment->sort_type = sort_type;
}

status_t mtrl_extend_segment(mtrl_context_t *ctx, mtrl_segment_t *segment)
{
    vm_page_t *page = NULL;

    GS_RETURN_IFERR(vm_alloc_and_append(MTRL_SESSION(ctx), MTRL_POOL(ctx), &segment->vm_list));
    if (segment->vm_list.count < segment->pages_hold) {
        return vm_open(MTRL_SESSION(ctx), MTRL_POOL(ctx), segment->vm_list.last, &page);
    }
    return GS_SUCCESS;
}

status_t mtrl_open_segment(mtrl_context_t *ctx, uint32 seg_id)
{
    return mtrl_open_segment2(ctx, ctx->segments[seg_id]);
}

status_t mtrl_open_segment2(mtrl_context_t *ctx, mtrl_segment_t *segment)
{
    uint32 vmid = segment->vm_list.last;
    mtrl_page_t *page = NULL;

    if (mtrl_open_page(ctx, vmid, &segment->curr_page) != GS_SUCCESS) {
        return GS_ERROR;
    }

    page = (mtrl_page_t *)segment->curr_page->data;
    mtrl_init_page(page, segment->vm_list.last);
    return GS_SUCCESS;
}

void mtrl_reset_sort_type(mtrl_context_t *ctx, uint32 id)
{
    mtrl_segment_t *segment = ctx->segments[id];
    segment->sort_type = MTRL_SORT_TYPE_INSERT;
}

static status_t mtrl_sort_single_page(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_page_t *page)
{
    if (page->is_sorted) {
        return GS_SUCCESS;
    }
    page->is_sorted = GS_TRUE;

    switch (segment->sort_type) {
        case MTRL_SORT_TYPE_INSERT:
            break;
        case MTRL_SORT_TYPE_QSORT:
            return mtrl_sort_page(ctx, segment, page);
        case MTRL_SORT_TYPE_ADAPTIVE_SORT:
            return mtrl_adaptive_sort_page(ctx, segment, page);
        default:
            GS_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "unexpect sort type");
            return GS_ERROR;
    }
    return GS_SUCCESS;
}

// page free when: 1.page has no part info 2.page has part info, and page is not occupied by another part
static inline bool32 mtrl_sort_need_free_page(mtrl_page_t *page)
{
    return (!page->has_part_info || !page->page_occupied);
}

static void mtrl_free_sorted_page(mtrl_context_t *ctx, mtrl_sort_cursor_t *cursor)
{
    if (!mtrl_sort_need_free_page(cursor->page)) {
        // when page has part info and occupied, don't free page but change the page_occupied status
        cursor->page->page_occupied = GS_FALSE;
        return;
    }

    /* Page with part info may open 2 times by cursor1 and cursor2. In that case, page ref_num is 2.
       Change ref_num = 1 to make sure to close page in function mtrl_close_page. */
    vm_ctrl_t *ctrl = vm_get_ctrl(MTRL_POOL(ctx), cursor->vmid);
    CM_ASSERT(ctrl->ref_num >= 1);
    ctrl->ref_num = 1;
    mtrl_close_page(ctx, cursor->vmid);
    vm_remove(MTRL_POOL(ctx), &cursor->segment->vm_list, cursor->vmid);
    vm_free(MTRL_SESSION(ctx), MTRL_POOL(ctx), cursor->vmid);
}

void mtrl_close_sorted_page(mtrl_context_t *ctx, mtrl_sort_cursor_t *cursor)
{
    mtrl_close_page(ctx, cursor->vmid);
}

static status_t mtrl_locate_sort_part(mtrl_context_t *ctx, mtrl_sort_cursor_t *cursor, uint32 level)
{
    vm_page_t *page = NULL;
    vm_ctrl_t *ctrl = NULL;
    uint32 next;

    if (level == 0) {
        cursor->part.next.vmid = vm_get_ctrl(MTRL_POOL(ctx), cursor->vmid)->prev;
        cursor->part.next.slot = 0;
        cursor->part.rows = cursor->page->rows;
        cursor->row = MTRL_GET_ROW(cursor->page, cursor->slot);
        cursor->slot++;
        return GS_SUCCESS;
    }

    cursor->part = *(mtrl_part_t *)MTRL_GET_ROW(cursor->page, cursor->slot);
    cursor->slot++;

    if (cursor->slot < (uint32)cursor->page->rows) {
        cursor->row = MTRL_GET_ROW(cursor->page, cursor->slot);
        cursor->slot++;
        return GS_SUCCESS;
    }

    ctrl = vm_get_ctrl(MTRL_POOL(ctx), cursor->vmid);
    next = ctrl->next;
    mtrl_free_sorted_page(ctx, cursor);
    cursor->vmid = GS_INVALID_ID32;

    if (mtrl_open_page(ctx, next, &page) != GS_SUCCESS) {
        return GS_ERROR;
    }

    cursor->page = (mtrl_page_t *)page->data;
    cursor->vmid = next;
    cursor->row = MTRL_GET_ROW(cursor->page, 0);
    cursor->slot = 1;
    return GS_SUCCESS;
}

status_t mtrl_move_sort_cursor(mtrl_context_t *ctx, mtrl_sort_cursor_t *cursor, mtrl_close_page_func_t close_func)
{
    vm_page_t *page = NULL;
    vm_ctrl_t *ctrl = NULL;
    uint32 next;

    if (cursor->slot < (uint32)cursor->page->rows) {
        if (cursor->rownum <= cursor->part.rows) {
            cursor->row = MTRL_GET_ROW(cursor->page, cursor->slot);
            cursor->slot++;
            return GS_SUCCESS;
        } else {
            close_func(ctx, cursor);
            cursor->vmid = GS_INVALID_ID32;
            cursor->row = NULL;
            return GS_SUCCESS;
        }
    }

    ctrl = vm_get_ctrl(MTRL_POOL(ctx), cursor->vmid);
    next = ctrl->next;
    close_func(ctx, cursor);
    cursor->vmid = GS_INVALID_ID32;
    cursor->row = NULL;

    if (next == GS_INVALID_ID32) {
        return GS_SUCCESS;
    }

    if (cursor->rownum > cursor->part.rows) {
        return GS_SUCCESS;
    }

    if (mtrl_open_page(ctx, next, &page) != GS_SUCCESS) {
        return GS_ERROR;
    }

    cursor->page = (mtrl_page_t *)page->data;
    cursor->vmid = next;
    cursor->row = MTRL_GET_ROW(cursor->page, 0);
    cursor->slot = 1;
    return GS_SUCCESS;
}

status_t mtrl_move_group_cursor(mtrl_context_t *ctx, mtrl_sort_cursor_t *cursor)
{
    vm_page_t *page = NULL;
    vm_ctrl_t *ctrl = NULL;

    cursor->rownum++;
    if (cursor->slot < cursor->page->rows) {
        cursor->slot++;
        return GS_SUCCESS;
    }

    ctrl = vm_get_ctrl(MTRL_POOL(ctx), cursor->vmid);
    if (ctrl->next == GS_INVALID_ID32) {
        return GS_SUCCESS;
    }

    if (mtrl_open_page(ctx, ctrl->next, &page) != GS_SUCCESS) {
        return GS_ERROR;
    }

    cursor->page = (mtrl_page_t *)page->data;
    cursor->vmid = ctrl->next;
    cursor->slot = 1;
    return GS_SUCCESS;
}

static status_t mtrl_fetch_group_row(mtrl_context_t *ctx, mtrl_sort_cursor_t *cursor, bool32 *group_changed,
                                     bool32 *eof)
{
    char *next_row = NULL;
    int32 result;

    *eof = GS_FALSE;
    *group_changed = GS_FALSE;

    if (cursor->rownum > cursor->part.rows) {
        *eof = GS_TRUE;
        return GS_SUCCESS;
    }

    if (cursor->last_vmid != cursor->vmid) {
        mtrl_close_page(ctx, cursor->last_vmid);
    }

    cursor->row = MTRL_GET_ROW(cursor->page, cursor->slot - 1);
    cursor->last_vmid = cursor->vmid;

    if (mtrl_move_group_cursor(ctx, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cursor->rownum > cursor->part.rows) {
        *group_changed = GS_TRUE;
        return GS_SUCCESS;
    }

    next_row = MTRL_GET_ROW(cursor->page, cursor->slot - 1);
    if (ctx->sort_cmp(cursor->segment, next_row, cursor->row, &result) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (result != 0) {
        *group_changed = GS_TRUE;
    }

    return GS_SUCCESS;
}

static status_t mtrl_fetch_winsort_key(mtrl_context_t *ctx, mtrl_sort_cursor_t *cursor, uint32 cmp_flag,
                                       bool32 *grp_chged, bool32 *ord_chged, bool32 *eof)
{
    char *next_row = NULL;
    int32 result;

    *eof = GS_FALSE;
    *grp_chged = GS_FALSE;
    *ord_chged = GS_FALSE;

    if (cursor->rownum > cursor->part.rows) {
        *eof = GS_TRUE;
        return GS_SUCCESS;
    }

    if (cursor->last_vmid != cursor->vmid) {
        mtrl_close_page(ctx, cursor->last_vmid);
    }

    cursor->row = MTRL_GET_ROW(cursor->page, cursor->slot - 1);
    cursor->last_vmid = cursor->vmid;

    if (mtrl_move_group_cursor(ctx, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cursor->rownum > cursor->part.rows) {
        return GS_SUCCESS;
    }

    if (cmp_flag & WINSORT_PART) {
        next_row = MTRL_GET_ROW(cursor->page, cursor->slot - 1);
        cursor->segment->cmp_flag = WINSORT_PART;

        if (ctx->sort_cmp(cursor->segment, next_row, cursor->row, &result) != GS_SUCCESS) {
            return GS_ERROR;
        }
        *grp_chged = (result != 0);
        if (!(*grp_chged) && (cmp_flag & WINSORT_ORDER)) {
            cursor->segment->cmp_flag = WINSORT_ORDER;
            if (ctx->sort_cmp(cursor->segment, next_row, cursor->row, &result) != GS_SUCCESS) {
                return GS_ERROR;
            }
            *ord_chged = (result != 0);
        }
    }
    return GS_SUCCESS;
}

static inline void mtrl_insert_into_page(mtrl_page_t *page, const char *row, uint16 row_size, uint32 *slot)
{
    char *ptr = (char *)page + page->free_begin;
    uint32 *dir = MTRL_GET_DIR(page, page->rows);
    errno_t ret;

    *dir = page->free_begin;
    // sizeof(uint32) means insert row's dir size
    ret = memcpy_sp(ptr, MTRL_PAGE_FREE_SIZE(page) - sizeof(uint32), row, row_size);
    knl_securec_check(ret);

    if (slot != NULL) {
        *slot = (uint32)page->rows;
    }

    page->rows++;
    page->free_begin += row_size;
}

status_t mtrl_merge_compare(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_sort_cursor_t *cursor1,
                            mtrl_sort_cursor_t *cursor2, mtrl_sort_cursor_t **result_cur)
{
    int32 result;

    if (cursor1->rownum > cursor1->part.rows) {
        *result_cur = (cursor2->rownum > cursor2->part.rows) ? NULL : cursor2;
        return GS_SUCCESS;
    }

    if (cursor2->rownum > cursor2->part.rows) {
        *result_cur = (cursor1->rownum > cursor1->part.rows) ? NULL : cursor1;
        return GS_SUCCESS;
    }

    if (ctx->sort_cmp(segment, cursor1->row, cursor2->row, &result) != GS_SUCCESS) {
        return GS_ERROR;
    }

    *result_cur = (result <= 0) ? cursor1 : cursor2;
    return GS_SUCCESS;
}

static status_t mtrl_insert_into_segment(mtrl_context_t *ctx, mtrl_segment_t *segment, const char *row,
                                         uint16 row_size, bool32 is_part, mtrl_rowid_t *rid)
{
    mtrl_page_t *page;
    page = (mtrl_page_t *)segment->curr_page->data;

    if (page->free_begin + row_size + sizeof(uint32) > GS_VMEM_PAGE_SIZE - MTRL_DIR_SIZE(page)) {
        page->is_sorted = GS_TRUE;
        mtrl_close_page(ctx, segment->vm_list.last);
        segment->curr_page = NULL;
        if (mtrl_extend_segment(ctx, segment) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (mtrl_open_page(ctx, segment->vm_list.last, &segment->curr_page) != GS_SUCCESS) {
            return GS_ERROR;
        }

        page = (mtrl_page_t *)segment->curr_page->data;
        mtrl_init_page(page, segment->vm_list.last);
    }

    rid->vmid = segment->vm_list.last;
    mtrl_insert_into_page(page, row, row_size, &rid->slot);
    if (is_part) {
        page->has_part_info = GS_TRUE;
        if (rid->slot != 0) {
            page->page_occupied = GS_TRUE;
        }
    }

    return GS_SUCCESS;
}

static status_t mtrl_merge_2cursors(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_sort_cursor_t *cursor1,
                                    mtrl_sort_cursor_t *cursor2, mtrl_rowid_t *srid)
{
    mtrl_part_t part;
    mtrl_rowid_t rid;
    uint16 row_size;
    mtrl_sort_cursor_t *result_cur = NULL;
    uint32 rows = 0;

    part.size = sizeof(mtrl_part_t);
    part.rows = cursor1->part.rows + cursor2->part.rows;
    part.next.vmid = GS_INVALID_ID32;
    part.next.slot = GS_INVALID_ID16;

    if (mtrl_insert_into_segment(ctx, segment, (char *)&part, part.size, GS_TRUE, srid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (mtrl_merge_compare(ctx, segment, cursor1, cursor2, &result_cur) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (result_cur != NULL) {
        row_size = MTRL_ROW_SIZE(segment, result_cur->row);
        if (mtrl_insert_into_segment(ctx, segment, result_cur->row, row_size, GS_FALSE, &rid) != GS_SUCCESS) {
            return GS_ERROR;
        }

        rows++;

        result_cur->rownum++;

        if (mtrl_move_sort_cursor(ctx, result_cur, mtrl_free_sorted_page) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (mtrl_merge_compare(ctx, segment, cursor1, cursor2, &result_cur) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    knl_panic(rows == part.rows); // segment0->vm_list.last will be used for next part, so we could not close it here.

    return GS_SUCCESS;
}

static status_t mtrl_merge_1cursor(mtrl_context_t *ctx,
                                   mtrl_segment_t *segment, mtrl_sort_cursor_t *cursor, mtrl_rowid_t *srid)
{
    mtrl_part_t part;
    mtrl_rowid_t rid;
    uint16 row_size;

    part.size = sizeof(mtrl_part_t);
    part.rows = cursor->part.rows;
    part.next.vmid = GS_INVALID_ID32;
    part.next.slot = GS_INVALID_ID16;

    if (mtrl_insert_into_segment(ctx, segment, (char *)&part, part.size, GS_TRUE, srid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (cursor->rownum <= part.rows) {
        row_size = MTRL_ROW_SIZE(segment, cursor->row);
        if (mtrl_insert_into_segment(ctx, segment, cursor->row, row_size, GS_FALSE, &rid) != GS_SUCCESS) {
            return GS_ERROR;
        }

        cursor->rownum++;

        if (mtrl_move_sort_cursor(ctx, cursor, mtrl_free_sorted_page) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

static status_t mtrl_init_sort_cursor(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_rowid_t *rid,
    uint32 level, mtrl_sort_cursor_t *cursor, vm_page_t *page)
{
    cursor->segment = segment;
    cursor->vmid = rid->vmid;
    cursor->last_vmid = rid->vmid;
    cursor->slot = rid->slot;
    cursor->page = (mtrl_page_t *)page->data;
    cursor->rownum = 1;

    return mtrl_locate_sort_part(ctx, cursor, level);
}

status_t mtrl_open_sort_cursor(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_rowid_t *rid,
                               uint32 level, mtrl_sort_cursor_t *cursor)
{
    vm_page_t *page = NULL;

    if (mtrl_open_page(ctx, rid->vmid, &page) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return mtrl_init_sort_cursor(ctx, segment, rid, level, cursor, page);
}

void mtrl_close_sort_cursor(mtrl_context_t *ctx, mtrl_sort_cursor_t *cursor)
{
    if (cursor->vmid != GS_INVALID_ID32) {
        mtrl_close_page(ctx, cursor->vmid);
        if (cursor->last_vmid != cursor->vmid && cursor->last_vmid != GS_INVALID_ID32) {
            mtrl_close_page(ctx, cursor->last_vmid);
            cursor->last_vmid = GS_INVALID_ID32;
        }
        cursor->vmid = GS_INVALID_ID32;
    }
    cursor->segment = NULL;
}

/* set srid->next = ex_srid, in order to merge from tail part to head part in the next level. */
static status_t mtrl_concat_part_info(mtrl_context_t *ctx, mtrl_rowid_t *ex_srid, mtrl_rowid_t *srid)
{
    mtrl_page_t *page = NULL;
    vm_page_t *vm_page = NULL;
    mtrl_part_t *part = NULL;

    if (mtrl_open_page(ctx, srid->vmid, &vm_page) != GS_SUCCESS) {
        return GS_ERROR;
    }

    page = (mtrl_page_t *)vm_page->data;
    part = (mtrl_part_t *)MTRL_GET_ROW(page, srid->slot);
    part->next = *ex_srid;
    mtrl_close_page(ctx, srid->vmid);
    
    return GS_SUCCESS;
}

/* always merge from tail part to head part in current level, to reduce vm swap. */
static status_t mtrl_merge_sort(mtrl_context_t *ctx, mtrl_segment_t *curr_seg, mtrl_segment_t *segment,
                                uint32 level, mtrl_rowid_t *start_rid, bool32 *finished)
{
    uint32 parts;
    mtrl_sort_cursor_t cursor1, cursor2;
    mtrl_rowid_t ex_srid, srid;  // part rowid
    knl_session_t *session = (knl_session_t *)ctx->session;
    mtrl_page_t *page = NULL;

    if (mtrl_recreate_segment(ctx, curr_seg, segment) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (mtrl_open_segment2(ctx, segment) != GS_SUCCESS) {
        return GS_ERROR;
    }

    parts = 0;
    ex_srid.vmid = GS_INVALID_ID32;
    ex_srid.slot = GS_INVALID_ID16;
    srid.vmid = start_rid->vmid;
    srid.slot = start_rid->slot;

    while (srid.vmid != GS_INVALID_ID32) {
        if (knl_check_session_status(session) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (mtrl_open_sort_cursor(ctx, curr_seg, &srid, level, &cursor1) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (cursor1.part.next.vmid == GS_INVALID_ID32) {
            if (mtrl_merge_1cursor(ctx, segment, &cursor1, &srid) != GS_SUCCESS) {
                mtrl_close_sort_cursor(ctx, &cursor1);
                return GS_ERROR;
            }

            if (mtrl_concat_part_info(ctx, &ex_srid, &srid) != GS_SUCCESS) {
                mtrl_close_sort_cursor(ctx, &cursor1);
                return GS_ERROR;
            }

            CM_ASSERT(cursor1.vmid == GS_INVALID_ID32);
            mtrl_close_sort_cursor(ctx, &cursor1);
            *start_rid = srid;
            page = (mtrl_page_t *)segment->curr_page->data;
            page->is_sorted = GS_TRUE;
            mtrl_close_page(ctx, segment->vm_list.last);
            segment->curr_page = NULL;
            *finished = GS_FALSE;
            return GS_SUCCESS;
        }

        if (mtrl_open_sort_cursor(ctx, curr_seg, &cursor1.part.next, level, &cursor2) != GS_SUCCESS) {
            mtrl_close_sort_cursor(ctx, &cursor1);
            return GS_ERROR;
        }

        if (mtrl_merge_2cursors(ctx, segment, &cursor1, &cursor2, &srid) != GS_SUCCESS) {
            mtrl_close_sort_cursor(ctx, &cursor1);
            mtrl_close_sort_cursor(ctx, &cursor2);
            return GS_ERROR;
        }

        if (mtrl_concat_part_info(ctx, &ex_srid, &srid) != GS_SUCCESS) {
            mtrl_close_sort_cursor(ctx, &cursor1);
            mtrl_close_sort_cursor(ctx, &cursor2);
            return GS_ERROR;
        }

        *start_rid = srid;
        ex_srid = srid;
        srid = cursor2.part.next;
        CM_ASSERT(cursor1.vmid == GS_INVALID_ID32);
        CM_ASSERT(cursor2.vmid == GS_INVALID_ID32);
        mtrl_close_sort_cursor(ctx, &cursor1);
        mtrl_close_sort_cursor(ctx, &cursor2);
        parts++;
    }
    page = (mtrl_page_t *)segment->curr_page->data;
    page->is_sorted = GS_TRUE;
    mtrl_close_page(ctx, segment->vm_list.last);
    segment->curr_page = NULL;
    *finished = (parts == 1);
    return GS_SUCCESS;
}

status_t mtrl_split_segment(mtrl_context_t *ctx, uint32 seg_id, uint32 *new_seg_id)
{
    mtrl_segment_t *cur_seg = ctx->segments[seg_id];
    mtrl_segment_t *new_seg = NULL;
    uint32 page_count1, page_count2, vmid;
    vm_ctrl_t *vm_ctrl = NULL;

    new_seg = mtrl_get_idle_segment(ctx, new_seg_id);
    if (new_seg == NULL) {
        GS_LOG_RUN_ERR("[MTRL] failed to get idle segment");
        return GS_ERROR;
    }

    page_count1 = cur_seg->vm_list.count / 2;
    page_count2 = cur_seg->vm_list.count - page_count1;

    vmid = cur_seg->vm_list.first;
    for (uint32 i = 1; i < page_count1; i++) {
        vm_ctrl = vm_get_ctrl(MTRL_POOL(ctx), vmid);
        vmid = vm_ctrl->next;
    }
    vm_ctrl = vm_get_ctrl(MTRL_POOL(ctx), vmid);

    cur_seg->vm_list.count = page_count1;
    new_seg->vm_list.count = page_count2;
    new_seg->vm_list.first = vm_ctrl->next;
    new_seg->vm_list.last = cur_seg->vm_list.last;
    cur_seg->vm_list.last = vmid;
    vm_ctrl->next = GS_INVALID_ID32;
    vm_ctrl = vm_get_ctrl(MTRL_POOL(ctx), new_seg->vm_list.first);
    vm_ctrl->prev = GS_INVALID_ID32;

    new_seg->type = cur_seg->type;
    new_seg->sort_type = cur_seg->sort_type;
    new_seg->cmp_items = cur_seg->cmp_items;
    new_seg->curr_page = NULL;
    new_seg->level = cur_seg->level;

    return GS_SUCCESS;
}

status_t mtrl_merge_2segments(mtrl_context_t *ctx, uint32 seg_id1, uint32 seg_id2)
{
    mtrl_segment_t *segment1 = ctx->segments[seg_id1];
    mtrl_segment_t *segment2 = ctx->segments[seg_id2];
    vm_page_t *page1 = NULL;
    mtrl_part_t *part1 = NULL;
    vm_ctrl_t *vm_ctrl = NULL;

    if (mtrl_open_page(ctx, segment1->vm_list.first, &page1) != GS_SUCCESS) {
        return GS_ERROR;
    }
    part1 = (mtrl_part_t *)MTRL_GET_ROW(page1->data, 0);

    part1->next.vmid = segment2->vm_list.first;
    part1->next.slot = 0;

    mtrl_close_page(ctx, segment1->vm_list.first);

    vm_ctrl = vm_get_ctrl(MTRL_POOL(ctx), segment1->vm_list.last);
    vm_ctrl->next = segment2->vm_list.first;
    vm_ctrl = vm_get_ctrl(MTRL_POOL(ctx), segment2->vm_list.first);
    vm_ctrl->prev = segment1->vm_list.last;

    segment1->vm_list.count += segment2->vm_list.count;
    segment1->vm_list.last = segment2->vm_list.last;
    segment2->vm_list.count = 0;
    segment2->is_used = GS_FALSE;
    ctx->seg_count--;

    return GS_SUCCESS;
}

void mtrl_sort_segment_proc(thread_t *thread)
{
    mtrl_sort_ctrl_t *ctrl = (mtrl_sort_ctrl_t *)thread->argument;
    thread->result = mtrl_sort_segment(ctrl->ctx, ctrl->cur_seg_id);
}

static status_t mtrl_merge_2pools_cursor(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_sort_cursor_t *cursor1,
    mtrl_sort_cursor_t *cursor2)
{
    mtrl_part_t part;
    mtrl_rowid_t rid;
    uint16 row_size;
    mtrl_sort_cursor_t *result_cur = NULL;
    uint64 rows = 0;
    knl_session_t *session = (knl_session_t *)ctx->session;

    part.size = sizeof(mtrl_part_t);
    part.rows = cursor1->part.rows + cursor2->part.rows;
    part.next.vmid = GS_INVALID_ID32;
    part.next.slot = GS_INVALID_ID16;

    if (mtrl_insert_into_segment(ctx, segment, (char *)&part, part.size, GS_TRUE, &rid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (mtrl_merge_compare(ctx, segment, cursor1, cursor2, &result_cur) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (rows != cursor1->part.rows + cursor2->part.rows) {
        row_size = MTRL_ROW_SIZE(segment, result_cur->row);
        if (mtrl_insert_into_segment(ctx, segment, result_cur->row, row_size, GS_FALSE, &rid) != GS_SUCCESS) {
            return GS_ERROR;
        }

        result_cur->rownum++;
        rows++;
        if (mtrl_move_sort_cursor(result_cur->ctx, result_cur, mtrl_close_sorted_page) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (mtrl_merge_compare(ctx, segment, cursor1, cursor2, &result_cur) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (knl_check_session_status(session) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    segment->level++;
    return GS_SUCCESS;
}

status_t mtrl_merge_2pools(knl_handle_t paral_ctx, uint32 id1, uint32 id2)
{
    idx_paral_sort_ctx_t *ctx = (idx_paral_sort_ctx_t *)paral_ctx;
    idx_sort_worker_t *pool1 = &ctx->workers[id1];
    idx_sort_worker_t *pool2 = &ctx->workers[id2];
    mtrl_sort_cursor_t cursor1, cursor2;
    knl_session_t *session = (knl_session_t *)pool1->mtrl_ctx->session;
    mtrl_segment_t segment = *pool1->segment;
    mtrl_rowid_t rid1 = { 0, 0 };
    mtrl_rowid_t rid2 = { 0, 0 };
    status_t status = GS_SUCCESS;

    rid1.vmid = segment.vm_list.first;
    rid2.vmid = pool2->segment->vm_list.first;
    for (;;) {
        if (mtrl_recreate_segment(pool1->mtrl_ctx, &segment, pool1->segment) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        if (mtrl_open_segment2(pool1->mtrl_ctx, pool1->segment) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        if (mtrl_open_sort_cursor(pool1->mtrl_ctx, &segment, &rid1, segment.level, &cursor1) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        cursor1.ctx = pool1->mtrl_ctx;
        if (mtrl_open_sort_cursor(pool2->mtrl_ctx, pool2->segment, &rid2, pool2->segment->level, &cursor2) != GS_SUCCESS) {
            mtrl_close_sort_cursor(pool1->mtrl_ctx, &cursor1);
            status = GS_ERROR;
            break;
        }

        cursor2.ctx = pool2->mtrl_ctx;
        if (mtrl_merge_2pools_cursor(pool1->mtrl_ctx, pool1->segment, &cursor1, &cursor2) != GS_SUCCESS) {
            mtrl_close_sort_cursor(pool1->mtrl_ctx, &cursor1);
            mtrl_close_sort_cursor(pool2->mtrl_ctx, &cursor2);
            status = GS_ERROR;
            break;
        }

        mtrl_close_sort_cursor(pool1->mtrl_ctx, &cursor1);
        mtrl_close_sort_cursor(pool2->mtrl_ctx, &cursor2);
        break;
    }

    mtrl_close_page(pool1->mtrl_ctx, segment.vm_list.last);
    segment.curr_page = NULL;
    vm_free_list(session, pool1->mtrl_ctx->pool, &segment.vm_list);
    vm_free_list(session, pool2->mtrl_ctx->pool, &pool2->segment->vm_list);
    return status;
}

status_t mtrl_sort_segment_parallel(mtrl_sort_ctrl_t *sort_ctrl, mtrl_context_t *ctx, uint32 seg_id)
{
    uint32 new_seg_id;

    if (mtrl_split_segment(ctx, seg_id, &new_seg_id) != GS_SUCCESS) {
        return GS_ERROR;
    }
    sort_ctrl->cur_seg_id = seg_id;

    if (cm_create_thread(mtrl_sort_segment_proc, 0, sort_ctrl, &sort_ctrl->threads[0]) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (mtrl_sort_segment(ctx, new_seg_id) != GS_SUCCESS) {
        cm_close_thread(&sort_ctrl->threads[0]);
        return GS_ERROR;
    }
    cm_close_thread(&sort_ctrl->threads[0]);

    if (sort_ctrl->threads[0].result != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_BUILD_INDEX_PARALLEL, ctx->err_msg);
        return GS_ERROR;
    }

    if (mtrl_merge_2segments(ctx, seg_id, new_seg_id) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (mtrl_sort_segment(ctx, seg_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t mtrl_sort_seg_last_page(mtrl_context_t *context, mtrl_segment_t *seg)
{
    if (seg->sort_type == MTRL_SORT_TYPE_INSERT) {
        return GS_SUCCESS;
    }
    vm_page_t *page = NULL;
    uint32 vmid = seg->vm_list.last;
    if (mtrl_open_page(context, vmid, &page) != GS_SUCCESS) {
        return GS_ERROR;
    }
    status_t ret = mtrl_sort_single_page(context, seg, (mtrl_page_t *)page->data);
    mtrl_close_page(context, vmid);
    return ret;
}

status_t mtrl_sort_segment2(mtrl_context_t *ctx, mtrl_segment_t *segment)
{
    status_t status;
    uint32 level;
    bool32 finished = GS_FALSE;
    mtrl_segment_t curr_seg;
    knl_session_t *session = (knl_session_t *)MTRL_SESSION(ctx);
    uint64 pre_temp_allocs = session->stat->temp_allocs;
    int32 err_code;
    const char *err_msg = NULL;
    errno_t ret;

    // AT THE BEGINING, WE SHOULD INIT THE VAL TO AVOID TIDY WARNING.
    mtrl_rowid_t start_rid = { 0, 0 };

    if (mtrl_sort_seg_last_page(ctx, segment) != GS_SUCCESS) {
        return GS_ERROR;
    }
    session->stat->sorts++;
    level = segment->level;

    if (level == 0) {
        start_rid.vmid = segment->vm_list.last;
    } else {
        start_rid.vmid = segment->vm_list.first;
    }

    if (segment->vm_list.count == 1) {
        segment->level = 0;
        return GS_SUCCESS;
    }

    knl_begin_session_wait(session, MTRL_SEGMENT_SORT, GS_TRUE);
    while (!finished) {
        curr_seg = *segment;
        status = mtrl_merge_sort(ctx, &curr_seg, segment, level, &start_rid, &finished);
        vm_free_list(MTRL_SESSION(ctx), MTRL_POOL(ctx), &curr_seg.vm_list);

        if (status != GS_SUCCESS) {
            cm_get_error(&err_code, &err_msg, NULL);
            ret = memcpy_sp(ctx->err_msg, GS_MESSAGE_BUFFER_SIZE, err_msg, GS_MESSAGE_BUFFER_SIZE);
            knl_securec_check(ret);
            knl_end_session_wait(session);
            return GS_ERROR;
        }

        level++;
    }

    if (pre_temp_allocs != session->stat->temp_allocs) {
        session->stat->disk_sorts++;
    }

    knl_end_session_wait(session);
    segment->level = level;
    return GS_SUCCESS;
}

status_t mtrl_sort_segment(mtrl_context_t *ctx, uint32 seg_id)
{
    return mtrl_sort_segment2(ctx, ctx->segments[seg_id]);
}

void mtrl_close_segment2(mtrl_context_t *ctx, mtrl_segment_t *segment)
{
    if (segment->curr_page != NULL) {
        mtrl_close_page(ctx, segment->curr_page->vmid);
        segment->curr_page = NULL;
    }
}

void mtrl_close_segment(mtrl_context_t *ctx, uint32 seg_id)
{
    mtrl_segment_t *segment = ctx->segments[seg_id];
    
    if (segment != NULL && segment->curr_page != NULL) {
        mtrl_close_page(ctx, segment->curr_page->vmid);
        segment->curr_page = NULL;
    }
}

/*
 * kernel interface for sort data in mtrl page
 */
status_t mtrl_insert_row(mtrl_context_t *ctx, uint32 seg_id, char *row, mtrl_rowid_t *rid)
{
    return mtrl_insert_row2(ctx, ctx->segments[seg_id], row, rid);
}

status_t mtrl_insert_row2(mtrl_context_t *ctx, mtrl_segment_t *segment, char *row, mtrl_rowid_t *rid)
{
    if (SECUREC_UNLIKELY(segment->curr_page->vmid != segment->vm_list.last)) {
        mtrl_close_page(ctx, segment->curr_page->vmid);
        segment->curr_page = NULL;
        if (mtrl_open_page(ctx, segment->vm_list.last, &segment->curr_page) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    mtrl_page_t *page = (mtrl_page_t *)segment->curr_page->data;
    uint16 row_size = MTRL_ROW_SIZE(segment, row);
    if (page->free_begin + row_size + sizeof(uint32) > GS_VMEM_PAGE_SIZE - MTRL_DIR_SIZE(page)) {
        if (segment->cmp_items != NULL) {
            if (mtrl_sort_single_page(ctx, segment, page) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
        mtrl_close_page(ctx, segment->vm_list.last);
        segment->curr_page = NULL;
        if (mtrl_extend_segment(ctx, segment) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (mtrl_open_page(ctx, segment->vm_list.last, &segment->curr_page) != GS_SUCCESS) {
            return GS_ERROR;
        }

        page = (mtrl_page_t *)segment->curr_page->data;
        mtrl_init_page(page, segment->vm_list.last);
    }

    rid->vmid = segment->vm_list.last;

    if (segment->cmp_items != NULL && segment->sort_type == MTRL_SORT_TYPE_INSERT) {
        return mtrl_insert_sorted_page(ctx, segment, page, row, row_size, &rid->slot);
    }

    mtrl_insert_into_page(page, row, row_size, &rid->slot);
    return GS_SUCCESS;
}

status_t mtrl_ins_row_in_page(mtrl_context_t *ctx, uint32 page_id, const char *row, bool32 *is_full)
{
    uint32 slot;
    vm_page_t *vm_page = NULL;
    if (vm_open(ctx->session, ctx->pool, page_id, &vm_page) != GS_SUCCESS) {
        return GS_ERROR;
    }
    mtrl_page_t *page = (mtrl_page_t *)vm_page->data;
    uint16 row_size = (uint16)((row_head_t *)row)->size;
    if (page->free_begin + row_size + sizeof(uint32) > GS_VMEM_PAGE_SIZE - MTRL_DIR_SIZE(page)) {
        *is_full = GS_TRUE;
        vm_close(ctx->session, ctx->pool, page_id, VM_ENQUE_TAIL);
        return GS_SUCCESS;
    }
    *is_full = GS_FALSE;
    mtrl_insert_into_page(page, row, row_size, &slot);
    vm_close(ctx->session, ctx->pool, page_id, VM_ENQUE_TAIL);
    return GS_SUCCESS;
}

vm_page_t *mtrl_sort_queue_pop(mtrl_sort_ctrl_t *ctrl)
{
    vm_ctrl_t *vm_ctrl;

    vm_ctrl = vm_get_ctrl(ctrl->ctx->pool, ctrl->sort_pages.first);
    ctrl->sort_pages.first = vm_ctrl->sort_next;
    ctrl->sort_pages.count--;

    return vm_get_cpid_page(ctrl->ctx->pool, vm_ctrl->cpid);
}

void mtrl_sort_proc(thread_t *thread)
{
    mtrl_sort_ctrl_t *ctrl = (mtrl_sort_ctrl_t *)thread->argument;
    vm_page_t *page = NULL;
    thread->result = GS_SUCCESS;

    while (!thread->closed) {
        cm_spin_lock(&ctrl->lock, NULL);
        if (ctrl->sort_pages.count == 0) {
            cm_spin_unlock(&ctrl->lock);
            cm_sleep(1);
            continue;
        }

        page = mtrl_sort_queue_pop(ctrl);
        cm_spin_unlock(&ctrl->lock);

        knl_panic(page != NULL);
        if (mtrl_sort_page(ctrl->ctx, ctrl->segment, (mtrl_page_t *)page->data) != GS_SUCCESS) {
            thread->result = GS_ERROR;
            return;
        }

        mtrl_close_page(ctrl->ctx, page->vmid);
    }
}

status_t mtrl_sort_from_queue(mtrl_sort_ctrl_t *ctrl)
{
    vm_page_t *page = NULL;

    cm_spin_lock(&ctrl->lock, NULL);
    if (ctrl->sort_pages.count == 0) {
        cm_spin_unlock(&ctrl->lock);
        return GS_SUCCESS;
    }
    page = mtrl_sort_queue_pop(ctrl);
    cm_spin_unlock(&ctrl->lock);

    knl_panic(page != NULL);

    if (mtrl_sort_page(ctrl->ctx, ctrl->segment, (mtrl_page_t *)page->data) != GS_SUCCESS) {
        return GS_ERROR;
    }

    mtrl_close_page(ctrl->ctx, page->vmid);
    return GS_SUCCESS;
}

static uint32 mtrl_get_part_table_pages(knl_session_t *session, index_t *index, knl_part_locate_t part_loc)
{
    uint32 count = 0;
    space_t *space = NULL;
    heap_segment_t *segment = NULL;
    table_part_t *table_part = NULL;
    table_part_t *table_subpart = NULL;
    table_t *table = &index->entity->table;
    
    if (IS_PART_INDEX(index)) {    // part index and part table
        table_part = TABLE_GET_PART(table, part_loc.part_no);
        if (IS_PARENT_TABPART(&table_part->desc)) {
            table_part = PART_GET_SUBENTITY(table->part_table, table_part->subparts[part_loc.subpart_no]);
        }
        
        segment = (heap_segment_t*)table_part->heap.segment;
        space = SPACE_GET(session, table_part->desc.space_id);
        if (segment != NULL) {
            count = heap_get_segment_page_count(space, segment) - segment->ufp_count;
        }

        return count;
    }

    /* global index and part table */
    uint32 partcnt = table->part_table->desc.partcnt;
    for (uint32 i = 0; i < partcnt; i++) {
        table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        if (!IS_PARENT_TABPART(&table_part->desc)) {
            segment = (heap_segment_t*)table_part->heap.segment;
            space = SPACE_GET(session, table_part->desc.space_id);
            if (segment != NULL) {
                count += heap_get_segment_page_count(space, segment) - segment->ufp_count;
            }

            continue;
        }

        for (uint32 j = 0; j < table_part->desc.subpart_cnt; j++) {
            table_subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[j]);
            if (table_subpart == NULL) {
                continue;
            }

            segment = (heap_segment_t*)table_subpart->heap.segment;
            space = SPACE_GET(session, table_subpart->desc.space_id);
            if (segment != NULL) {
                count += heap_get_segment_page_count(space, segment) - segment->ufp_count;
            }
        }
    }

    return count;
}

uint32 mtrl_heap_pages_by_ext(knl_session_t *session, index_t *index, knl_part_locate_t part_loc)
{
    uint32 count = 0;
    space_t *space = NULL;
    heap_segment_t *segment = NULL;
    table_t *table = &index->entity->table;

    if (!IS_PART_TABLE(table)) {
        // normal index, normal table
        segment = HEAP_SEGMENT(session, table->heap.entry, table->heap.segment);
        space = SPACE_GET(session, table->desc.space_id);
        if (segment != NULL) {
            count = heap_get_segment_page_count(space, segment) - segment->ufp_count;
        }
    } else {
        count = mtrl_get_part_table_pages(session, index, part_loc);
    }
       
    return count;
}

status_t mtrl_sort_init(knl_session_t *session, index_t *index, knl_part_locate_t part_loc,
    mtrl_sort_ctrl_t *sort_ctrl)
{
    uint32 cpu_count = session->kernel->attr.cpu_count;
    errno_t ret = memset_sp(sort_ctrl, sizeof(mtrl_sort_ctrl_t), 0, sizeof(mtrl_sort_ctrl_t));
    knl_securec_check(ret);
    sort_ctrl->initialized = GS_TRUE;

    uint32 count = mtrl_heap_pages_by_ext(session, index, part_loc);
    if (cpu_count <= 1 || count < MIN_MTRL_SORT_EXTENTS) {
        sort_ctrl->use_parallel = GS_FALSE;
        return GS_SUCCESS;
    }

    session->thread_shared = GS_TRUE;
    sort_ctrl->use_parallel = GS_TRUE;
    sort_ctrl->thread_count = cpu_count - 1;
    if (sort_ctrl->thread_count > MAX_MTRL_SORT_THREADS) {
        sort_ctrl->thread_count = MAX_MTRL_SORT_THREADS;
    }

    for (uint32 i = 0; i < sort_ctrl->thread_count; i++) {
        if (cm_create_thread(mtrl_sort_proc, 0, sort_ctrl, &sort_ctrl->threads[i]) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t mtrl_sort_clean(mtrl_sort_ctrl_t *sort_ctrl)
{
    status_t status = GS_SUCCESS;

    if (!sort_ctrl->use_parallel) {
        return status;
    }

    if (!sort_ctrl->initialized) {
        return status;
    }

    while (sort_ctrl->sort_pages.count > 0) {
        if (mtrl_sort_from_queue(sort_ctrl) != GS_SUCCESS) {
            status = GS_ERROR;
        }
    }

    for (uint32 i = 0; i < sort_ctrl->thread_count; i++) {
        cm_close_thread(&sort_ctrl->threads[i]);
        if (sort_ctrl->threads[i].result != GS_SUCCESS) {
            status = GS_ERROR;
            GS_THROW_ERROR(ERR_DUPLICATE_KEY, "");
            continue;
        }
    }

    sort_ctrl->initialized = GS_FALSE;
    sort_ctrl->insert_complete = GS_TRUE;

    return status;
}

void mtrl_sort_page_enqueue(mtrl_sort_ctrl_t *sort_ctrl, vm_page_t *vm_page)
{
    vm_ctrl_t *vm_ctrl = NULL;

    if (vm_page == NULL) {
        return;
    }
    cm_spin_lock(&sort_ctrl->lock, NULL);
    if (sort_ctrl->sort_pages.count == 0) {
        sort_ctrl->sort_pages.first = vm_page->vmid;
        sort_ctrl->sort_pages.last = vm_page->vmid;
        sort_ctrl->sort_pages.count = 1;
    } else {
        vm_ctrl = vm_get_ctrl(sort_ctrl->ctx->pool, sort_ctrl->sort_pages.last);
        vm_ctrl->sort_next = vm_page->vmid;
        sort_ctrl->sort_pages.last = vm_page->vmid;
        sort_ctrl->sort_pages.count++;
    }
    cm_spin_unlock(&sort_ctrl->lock);
}

status_t mtrl_insert_row_parallel(mtrl_context_t *ctx, uint32 seg_id, const char *row, mtrl_sort_ctrl_t *sort_ctrl,
                                  mtrl_rowid_t *rid)
{
    mtrl_segment_t *segment = ctx->segments[seg_id];
    vm_page_t *vm_page = segment->curr_page;
    mtrl_page_t *page = (mtrl_page_t *)vm_page->data;
    uint16 row_size = MTRL_ROW_SIZE(segment, row);

    sort_ctrl->ctx = ctx;
    sort_ctrl->segment = segment;

    if (page->free_begin + row_size + sizeof(uint32) > GS_VMEM_PAGE_SIZE - MTRL_DIR_SIZE(page)) {
        if (segment->cmp_items != NULL) {
            mtrl_sort_page_enqueue(sort_ctrl, vm_page);
        }

        while (sort_ctrl->sort_pages.count + sort_ctrl->thread_count >= GS_MAX_MTRL_OPEN_PAGES) {
            if (mtrl_sort_from_queue(sort_ctrl) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (mtrl_extend_segment(ctx, segment) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (mtrl_open_page(ctx, segment->vm_list.last, &segment->curr_page) != GS_SUCCESS) {
            return GS_ERROR;
        }

        page = (mtrl_page_t *)segment->curr_page->data;
        mtrl_init_page(page, segment->vm_list.last);
    }

    rid->vmid = segment->vm_list.last;
    mtrl_insert_into_page(page, row, row_size, &rid->slot);
    return GS_SUCCESS;
}

static inline status_t mtrl_get_array_value(gs_type_t datatype, char *ptr, uint32 len, variant_t *value)
{
    /* lob value is "size + type + others" */
    uint32 lob_type = *(uint32 *)(ptr + sizeof(uint32));
    array_head_t *head = NULL;

    value->type = GS_TYPE_ARRAY;
    value->v_array.type = datatype;
    value->v_array.count = 1;
    value->v_array.value.type = lob_type;

    switch (lob_type) {
        case GS_LOB_FROM_KERNEL:
            value->v_array.value.knl_lob.bytes = (uint8 *)ptr;
            value->v_array.value.knl_lob.size = len;
            value->v_array.value.knl_lob.is_hex_const = GS_FALSE;
            head = (array_head_t *)(ptr + sizeof(lob_head_t));
            value->v_array.count = head->count;
            return GS_SUCCESS;
        case GS_LOB_FROM_VMPOOL:
            value->v_array.value.vm_lob = *(vm_lob_t *)ptr;
            knl_session_t *knl_session = (knl_session_t *)knl_get_curr_sess();
            return cm_update_mtrl_array_count(knl_session, knl_session->temp_pool, &value->v_array);
        default:
            GS_THROW_ERROR(ERR_UNKNOWN_LOB_TYPE, "get array value");
            return GS_ERROR;
    }
}

status_t mtrl_get_column_value(mtrl_row_assist_t *row, bool32 eof, uint32 id, gs_type_t datatype, bool8 is_array,
    variant_t *value)
{
    char *ptr = NULL;
    uint32 len, lob_type;

    if (eof) {
        value->type = datatype;
        value->is_null = GS_TRUE;
        return GS_SUCCESS;
    }

    len = row->lens[id];
    ptr = row->data + row->offsets[id];

    value->type = datatype;
    value->is_null = GS_FALSE;

    if (len == GS_NULL_VALUE_LEN) {
        value->is_null = GS_TRUE;
        return GS_SUCCESS;
    }

    if (SECUREC_UNLIKELY(is_array == GS_TRUE)) {
        return mtrl_get_array_value(datatype, ptr, len, value);
    }

    switch (datatype) {
        case GS_TYPE_BOOLEAN:
            VALUE(bool32, value) = *(bool32 *)ptr;
            break;

        case GS_TYPE_UINT32:
            VALUE(uint32, value) = *(uint32*)ptr;
            break;
        case GS_TYPE_INTEGER:
            VALUE(int32, value) = *(int32 *)ptr;
            break;

        case GS_TYPE_UINT64:
            VALUE(uint64, value) = *(uint64*)ptr;
            break;

        case GS_TYPE_BIGINT:
        case GS_TYPE_DATE:
        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_TIMESTAMP_TZ_FAKE:
        case GS_TYPE_TIMESTAMP_LTZ:
            VALUE(int64, value) = *(int64 *)ptr;
            break;
        
        case GS_TYPE_TIMESTAMP_TZ:
            VALUE(timestamp_tz_t, value) = *(timestamp_tz_t*)ptr;
            break;

        case GS_TYPE_REAL:
            VALUE(double, value) = *(double *)ptr;
            break;

        case GS_TYPE_INTERVAL_DS:
            value->v_itvl_ds = *(interval_ds_t *)ptr;
            break;

        case GS_TYPE_INTERVAL_YM:
            value->v_itvl_ym = *(interval_ym_t *)ptr;
            break;

        case GS_TYPE_NUMBER:
        case GS_TYPE_NUMBER3:
        case GS_TYPE_DECIMAL:
            if (cm_dec_4_to_8(VALUE_PTR(dec8_t, value), (dec4_t *)ptr, len) != GS_SUCCESS) {
                return GS_ERROR;
            }
            break;
        case GS_TYPE_NUMBER2:
            if (cm_dec_2_to_8(VALUE_PTR(dec8_t, value), (const payload_t *)ptr, len) != GS_SUCCESS) {
                return GS_ERROR;
            }
            break;

        case GS_TYPE_CHAR:
        case GS_TYPE_STRING:
        case GS_TYPE_VARCHAR:
            VALUE_PTR(text_t, value)->str = ptr;
            VALUE_PTR(text_t, value)->len = len;
            break;

        case GS_TYPE_CLOB:
        case GS_TYPE_BLOB:
        case GS_TYPE_IMAGE: {
            lob_type = *(uint32 *)(ptr + sizeof(uint32));
            VALUE_PTR(var_lob_t, value)->type = lob_type;
            if (lob_type == GS_LOB_FROM_KERNEL) {
                VALUE_PTR(var_lob_t, value)->knl_lob.bytes = (uint8 *)ptr;
                VALUE_PTR(var_lob_t, value)->knl_lob.size = len;
            } else if (lob_type == GS_LOB_FROM_VMPOOL) {
                VALUE_PTR(var_lob_t, value)->vm_lob = *(vm_lob_t *)ptr;
            } else {
                GS_THROW_ERROR(ERR_UNKNOWN_LOB_TYPE, "do get column value from mtrl");
                return GS_ERROR;
            }
            break;
        }

        default:
            VALUE_PTR(binary_t, value)->bytes = (uint8 *)ptr;
            VALUE_PTR(binary_t, value)->size = len;
            break;
    }

    return GS_SUCCESS;
}

void mtrl_init_mtrl_rowid(mtrl_rowid_t *rid)
{
    rid->vmid = GS_INVALID_ID32;
    rid->slot = GS_INVALID_ID32;
}

status_t mtrl_init_cursor(mtrl_cursor_t *cursor)
{
    cursor->row.data = NULL;
    cursor->rs_vmid = GS_INVALID_ID32;
    cursor->rs_page = NULL;
    cursor->eof = GS_FALSE;
    cursor->count = 0;
    cursor->slot = 0;
    cursor->type = MTRL_CURSOR_OTHERS;
    mtrl_init_mtrl_rowid(&cursor->pre_cursor_rid);
    mtrl_init_mtrl_rowid(&cursor->next_cursor_rid);
    mtrl_init_mtrl_rowid(&cursor->curr_cursor_rid);
    return GS_SUCCESS;
}

status_t mtrl_open_cursor2(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_cursor_t *cursor)
{
    mtrl_rowid_t rid;

    rid.vmid = segment->vm_list.first;
    rid.slot = 0;

    if (mtrl_open_sort_cursor(ctx, segment, &rid, segment->level, &cursor->sort) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return mtrl_init_cursor(cursor);
}

status_t mtrl_open_cursor(mtrl_context_t *ctx, uint32 sort_seg, mtrl_cursor_t *cursor)
{
    return mtrl_open_cursor2(ctx, ctx->segments[sort_seg], cursor);
}

status_t mtrl_open_rs_cursor(mtrl_context_t *ctx, uint32 sort_seg, mtrl_cursor_t *cursor)
{
    vm_page_t *page = NULL;
    mtrl_segment_t *segment = ctx->segments[sort_seg];
    uint32 vmid = segment->vm_list.first;

    if (mtrl_open_page(ctx, vmid, &page) != GS_SUCCESS) {
        return GS_ERROR;
    }
    cursor->slot = 0;
    cursor->eof = GS_FALSE;
    cursor->row.data = NULL;
    cursor->rs_vmid = vmid;
    cursor->rs_page = (mtrl_page_t *)page->data;

    return GS_SUCCESS;
}

void mtrl_close_history_page(mtrl_context_t *ctx, mtrl_cursor_t *cursor)
{
    for (uint32 i = 0; i < cursor->count; i++) {
        mtrl_close_page(ctx, cursor->history[i]);
    }
    cursor->count = 0;
}

void mtrl_close_cursor(mtrl_context_t *ctx, mtrl_cursor_t *cursor)
{
    mtrl_close_sort_cursor(ctx, &cursor->sort);
    if (cursor->rs_vmid != GS_INVALID_ID32) {
        mtrl_close_page(ctx, cursor->rs_vmid);
        cursor->rs_vmid = GS_INVALID_ID32;
    }

    mtrl_close_history_page(ctx, cursor);
}

status_t mtrl_fetch_sort_key(mtrl_context_t *ctx, mtrl_cursor_t *cursor)
{
    if (cursor->sort.rownum > cursor->sort.part.rows) {
        mtrl_close_cursor(ctx, cursor);
        cursor->eof = GS_TRUE;
        return GS_SUCCESS;
    }

    if (cursor->sort.rownum > 1) {
        if (mtrl_move_sort_cursor(ctx, &cursor->sort, mtrl_close_sorted_page) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    cursor->sort.rownum++;

    return GS_SUCCESS;
}

status_t mtrl_fetch_winsort_rid(mtrl_context_t *ctx, mtrl_cursor_t *cursor, uint32 cmp_flag, bool32 *grp_chged,
                                bool32 *ord_chged)
{
    mtrl_rowid_t *rid = NULL;
    vm_page_t *vm_page = NULL;
    uint16 row_size;
    mtrl_sort_cursor_t *sort = &cursor->sort;

    if (mtrl_fetch_winsort_key(ctx, &cursor->sort, cmp_flag, grp_chged, ord_chged, &cursor->eof) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cursor->eof == GS_TRUE) {
        return GS_SUCCESS;
    }

    row_size = ((row_head_t *)sort->row)->size;
    rid = (mtrl_rowid_t *)(sort->row + row_size - sizeof(mtrl_rowid_t));

    if (rid->vmid != cursor->rs_vmid) {
        if (cursor->rs_vmid != GS_INVALID_ID32) {
            mtrl_close_page(ctx, cursor->rs_vmid);
            cursor->rs_vmid = GS_INVALID_ID32;
        }

        if (mtrl_open_page(ctx, rid->vmid, &vm_page) != GS_SUCCESS) {
            return GS_ERROR;
        }

        cursor->rs_vmid = rid->vmid;
        cursor->rs_page = (mtrl_page_t *)vm_page->data;
    }

    cursor->row.data = MTRL_GET_ROW(cursor->rs_page, rid->slot);
    cm_decode_row(cursor->row.data, cursor->row.offsets, cursor->row.lens, NULL);
    return GS_SUCCESS;
}

status_t mtrl_move_rs_cursor(mtrl_context_t *ctx, mtrl_cursor_t *cursor)
{
    vm_page_t *page = NULL;
    vm_ctrl_t *ctrl = NULL;
    uint32 next;

    if (cursor->slot < (uint32)cursor->rs_page->rows) {
        cursor->row.data = MTRL_GET_ROW(cursor->rs_page, cursor->slot);
        cursor->slot++;
        return GS_SUCCESS;
    }

    ctrl = vm_get_ctrl(MTRL_POOL(ctx), cursor->rs_vmid);
    next = ctrl->next;
    mtrl_close_page(ctx, cursor->rs_vmid);
    cursor->rs_vmid = next;

    if (next == GS_INVALID_ID32) {
        cursor->eof = GS_TRUE;
        return GS_SUCCESS;
    }

    if (mtrl_open_page(ctx, next, &page) != GS_SUCCESS) {
        return GS_ERROR;
    }

    cursor->rs_page = (mtrl_page_t *)page->data;
    cursor->row.data = MTRL_GET_ROW(cursor->rs_page, 0);
    cursor->slot = 1;
    return GS_SUCCESS;
}

status_t mtrl_fetch_rs(mtrl_context_t *ctx, mtrl_cursor_t *cursor, bool32 decode)
{
    if (mtrl_move_rs_cursor(ctx, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cursor->eof) {
        return GS_SUCCESS;
    }

    if (decode == GS_TRUE) {
        cm_decode_row(cursor->row.data, cursor->row.offsets, cursor->row.lens, NULL);
    }

    return GS_SUCCESS;
}

status_t mtrl_fetch_sort(mtrl_context_t *ctx, mtrl_cursor_t *cursor)
{
    char *row = NULL;
    mtrl_rowid_t *rid = NULL;
    vm_page_t *vm_page = NULL;
    uint16 row_size;

    if (mtrl_fetch_sort_key(ctx, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cursor->eof) {
        return GS_SUCCESS;
    }

    row = cursor->sort.row;
    row_size = ((row_head_t *)row)->size;
    rid = (mtrl_rowid_t *)(row + row_size - sizeof(mtrl_rowid_t));

    if (rid->vmid != cursor->rs_vmid) {
        if (cursor->rs_vmid != GS_INVALID_ID32) {
            mtrl_close_page(ctx, cursor->rs_vmid);
            cursor->rs_vmid = GS_INVALID_ID32;
        }

        if (mtrl_open_page(ctx, rid->vmid, &vm_page) != GS_SUCCESS) {
            return GS_ERROR;
        }

        cursor->rs_vmid = rid->vmid;
        cursor->rs_page = (mtrl_page_t *)vm_page->data;
    }

    cursor->row.data = MTRL_GET_ROW(cursor->rs_page, rid->slot);
    cm_decode_row(cursor->row.data, cursor->row.offsets, cursor->row.lens, NULL);
    return GS_SUCCESS;
}

// each row of materialized data in the sorting segment as follows:
// sort_key|rs_rowid|rowid of sub-segment for non-leaf node
status_t mtrl_fetch_sibl_sort(mtrl_context_t *ctx, mtrl_cursor_t *cursor, mtrl_cursor_t *curr_level_cursor,
    sibl_sort_row_t *sibl_row)
{
    char *row = NULL;
    vm_page_t *vm_page = NULL;
    uint16 row_size;

    if (mtrl_fetch_sort_key(ctx, curr_level_cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (curr_level_cursor->eof) {
        return GS_SUCCESS;
    }

    row = curr_level_cursor->sort.row;
    row_size = ((row_head_t *)row)->size;
    *sibl_row = *(sibl_sort_row_t *)(row + row_size - sizeof(sibl_sort_row_t));

    if (sibl_row->rs_rid.vmid != cursor->rs_vmid) {
        if (cursor->rs_vmid != GS_INVALID_ID32) {
            mtrl_close_page(ctx, cursor->rs_vmid);
            cursor->rs_vmid = GS_INVALID_ID32;
        }

        if (mtrl_open_page(ctx, sibl_row->rs_rid.vmid, &vm_page) != GS_SUCCESS) {
            return GS_ERROR;
        }

        cursor->rs_vmid = sibl_row->rs_rid.vmid;
        cursor->rs_page = (mtrl_page_t *)vm_page->data;
    }

    cursor->row.data = MTRL_GET_ROW(cursor->rs_page, sibl_row->rs_rid.slot);
    cm_decode_row(cursor->row.data, cursor->row.offsets, cursor->row.lens, NULL);

    return GS_SUCCESS;
}

status_t mtrl_fetch_group(mtrl_context_t *ctx, mtrl_cursor_t *cursor, bool32 *group_changed)
{
    if (mtrl_fetch_group_row(ctx, &cursor->sort, group_changed, &cursor->eof) != GS_SUCCESS) {
        mtrl_close_cursor(ctx, cursor);
        return GS_ERROR;
    }

    if (cursor->eof) {
        mtrl_close_cursor(ctx, cursor);
        return GS_SUCCESS;
    }

    cursor->row.data = cursor->sort.row;
    cm_decode_row(cursor->sort.row, cursor->row.offsets, cursor->row.lens, NULL);

    return GS_SUCCESS;
}

mtrl_page_t *mtrl_curr_page(mtrl_context_t *ctx, uint32 seg_id)
{
    return (mtrl_page_t *)ctx->segments[seg_id]->curr_page->data;
}

static status_t mtrl_fetch_multi_row(mtrl_context_t *ctx, mtrl_cursor_t *cursor, row_addr_t *rows, uint32 count)
{
    char *key_row = NULL;
    char *rs_row = NULL;
    mtrl_rowid_t *rid = NULL;
    vm_page_t *vm_page = NULL;
    uint16 row_size, rs_row_size;

    key_row = cursor->sort.row;
    row_size = ((row_head_t *)key_row)->size;

    mtrl_close_history_page(ctx, cursor);

    for (uint32 i = 0; i < count; i++) {
        rid = (mtrl_rowid_t *)(key_row + row_size - (i + 1) * sizeof(mtrl_rowid_t));

        if (rid->vmid != cursor->rs_vmid) {
            if (cursor->rs_vmid != GS_INVALID_ID32) {
                cursor->history[cursor->count++] = cursor->rs_vmid;
            }

            if (mtrl_open_page(ctx, rid->vmid, &vm_page) != GS_SUCCESS) {
                return GS_ERROR;
            }

            cursor->rs_vmid = rid->vmid;
            cursor->rs_page = (mtrl_page_t *)vm_page->data;
        }
        rs_row = MTRL_GET_ROW(cursor->rs_page, rid->slot);
        *(rows[i].data) = rs_row;
        cm_decode_row(rs_row, rows[i].offset, rows[i].len, NULL);
        rs_row_size = ((row_head_t *)rs_row)->size;
        // read table rowid into mtrl
        if (rows[i].rowid != NULL) {
            *(rows[i].rowid) = *(rowid_t *)(rs_row + rs_row_size - KNL_ROWID_LEN);
        }
    }
    return GS_SUCCESS;
}

status_t mtrl_fetch_merge_sort_row(mtrl_context_t *ctx, mtrl_cursor_t *cursor, row_addr_t *rows, uint32 count,
                                   bool32 *eof)
{
    if (mtrl_fetch_sort_key(ctx, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }
    *eof = cursor->eof;
    if (*eof) {
        return GS_SUCCESS;
    }
    return mtrl_fetch_multi_row(ctx, cursor, rows, count);
}

static status_t mtrl_open_savepoint(mtrl_context_t *ctx, uint32 sort_seg, mtrl_savepoint_t *savepoint,
                                    mtrl_cursor_t *cursor)
{
    vm_page_t *page = NULL;

    if (cursor->sort.vmid != savepoint->vm_row_id.vmid) {
        if (cursor->sort.vmid != GS_INVALID_ID32) {
            mtrl_close_page(ctx, cursor->sort.vmid);
            cursor->sort.vmid = GS_INVALID_ID32;
        }
        if (mtrl_open_page(ctx, savepoint->vm_row_id.vmid, &page) != GS_SUCCESS) {
            return GS_ERROR;
        }
        cursor->sort.page = (mtrl_page_t *)page->data;
        cursor->sort.vmid = savepoint->vm_row_id.vmid;
        cursor->sort.last_vmid = savepoint->vm_row_id.vmid;
    }
    cursor->sort.slot = savepoint->vm_row_id.slot;
    cursor->sort.rownum = savepoint->rownum;
    cursor->sort.row = MTRL_GET_ROW(cursor->sort.page, cursor->sort.slot);
    cursor->sort.slot++;
    cursor->eof = GS_FALSE;
    return GS_SUCCESS;
}

status_t mtrl_fetch_savepoint(mtrl_context_t *ctx, uint32 sort_seg, mtrl_savepoint_t *savepoint,
                              mtrl_cursor_t *cursor, row_addr_t *rows, uint32 count)
{
    if (mtrl_open_savepoint(ctx, sort_seg, savepoint, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return mtrl_fetch_multi_row(ctx, cursor, rows, count);
}

static status_t mtrl_ensure_page_size(mtrl_context_t *ctx, mtrl_segment_t *segment,
    uint16 size, bool32 need_close)
{
    mtrl_page_t *page = (mtrl_page_t *)segment->curr_page->data;

    if (page->free_begin + size + sizeof(uint32) > GS_VMEM_PAGE_SIZE - MTRL_DIR_SIZE(page)) {
        if (need_close) {
            mtrl_close_page(ctx, segment->vm_list.last);
            segment->curr_page = NULL;
        }
        if (mtrl_extend_segment(ctx, segment) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (mtrl_open_page(ctx, segment->vm_list.last, &segment->curr_page) != GS_SUCCESS) {
            return GS_ERROR;
        }
        page = (mtrl_page_t *)segment->curr_page->data;
        mtrl_init_page(page, segment->vm_list.last);
    }
    return GS_SUCCESS;
}

status_t mtrl_win_aggr_alloc(mtrl_context_t *ctx, uint32 seg_id, void **var, uint32 var_size,
                             mtrl_rowid_t *rid, bool32 need_close)
{
    mtrl_page_t *page = NULL;
    mtrl_segment_t *segment = ctx->segments[seg_id];

    if (mtrl_ensure_page_size(ctx, segment, var_size, need_close) != GS_SUCCESS) {
        return GS_ERROR;
    }
    page = (mtrl_page_t *)segment->curr_page->data;
    *var = (void *)((char *)page + page->free_begin);
    *MTRL_GET_DIR(page, page->rows) = page->free_begin;

    rid->vmid = segment->vm_list.last;
    rid->slot = (uint32)page->rows;

    page->rows++;
    page->free_begin += var_size;
    return GS_SUCCESS;
}

void  mtrl_win_release_segment(mtrl_context_t *ctx, uint32 seg_id, uint32 *maps, uint32 max_count)
{
    mtrl_segment_t *segment = ctx->segments[seg_id];

    for (uint32 i = 0; i < max_count; i++) {
        if (maps[i] != GS_INVALID_ID32) {
            mtrl_close_page(ctx, maps[i]);
        }
    }

    segment->curr_page = NULL;
    mtrl_release_segment(ctx, seg_id);
}

bool32 mtrl_win_cur_page_is_enough(mtrl_context_t *ctx, uint32 seg_id, uint32 size)
{
    mtrl_segment_t *segment = ctx->segments[seg_id];
    mtrl_page_t *page = (mtrl_page_t *)segment->curr_page->data;

    return (page->free_begin + size <= GS_VMEM_PAGE_SIZE - MTRL_DIR_SIZE(page));
}

status_t mtrl_win_aggr_append_data(mtrl_context_t *ctx, uint32 seg_id, const char *data, uint32 size)
{
    mtrl_segment_t *segment = ctx->segments[seg_id];
    mtrl_page_t *page = (mtrl_page_t *)segment->curr_page->data;

    if (page->free_begin + size > GS_VMEM_PAGE_SIZE - MTRL_DIR_SIZE(page)) {
        return GS_ERROR;
    }
    if (size > 0) {
        errno_t ret = memcpy_sp((char *)page + page->free_begin, size, data, size);
        knl_securec_check(ret);
    }

    page->free_begin += size;
    return GS_SUCCESS;
}

status_t mtrl_win_aggr_get(mtrl_context_t *ctx, uint32 seg_id, char **row, mtrl_rowid_t *rid, bool32 need_close)
{
    mtrl_segment_t *segment = ctx->segments[seg_id];
    mtrl_page_t *page = (mtrl_page_t *)segment->curr_page->data;

    if (segment->curr_page->vmid != rid->vmid) {
        if (need_close) {
            mtrl_close_page(ctx, segment->curr_page->vmid);
            segment->curr_page = NULL;
        }
        
        if (mtrl_open_page(ctx, rid->vmid, &segment->curr_page) != GS_SUCCESS) {
            return GS_ERROR;
        }
        page = (mtrl_page_t *)segment->curr_page->data;
    }
    *row = MTRL_GET_ROW(page, rid->slot);
    return GS_SUCCESS;
}

bool32 mtrl_fill_page_up(mtrl_context_t *ctx, mtrl_page_t *dst_page, mtrl_page_t *src_page)
{
    row_head_t *src_row = NULL;

    for (uint16 i = src_page->rows; i > 0; i--) {
        src_row = (row_head_t *)MTRL_GET_ROW((char *)src_page, i - 1);
        if (dst_page->free_begin + src_row->size + sizeof(uint32) > GS_VMEM_PAGE_SIZE - MTRL_DIR_SIZE(dst_page)) {
            return GS_TRUE;
        }
        mtrl_insert_into_page(dst_page, (char *)src_row, src_row->size, NULL);
    }

    return GS_FALSE;
}

#ifdef __cplusplus
}
#endif
