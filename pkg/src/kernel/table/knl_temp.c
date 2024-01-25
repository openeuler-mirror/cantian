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
 * knl_temp.c
 *
 *
 * IDENTIFICATION
 * src/kernel/table/knl_temp.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_table_module.h"
#include "knl_temp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TEMP_CT_MAX_ROW_SIZE 8000

bool8 g_temp_tablename_compative_mysql = CT_FALSE;

status_t temp_heap_alloc_page(knl_session_t *session, knl_temp_cache_t *temp_cache, uint32 *curr_vmid);
static void temp_heap_revert_update(knl_session_t *session, undo_row_t *undo_row, row_head_t *row,
                                    uint16 *offsets, uint16 *lens);

bool32 knl_temp_object_isvalid_by_id(knl_session_t *session, uint32 uid, uint32 oid, knl_scn_t org_scn)
{
    knl_dictionary_t dc;

    if (knl_open_dc_by_id(session, uid, oid, &dc, CT_TRUE) != CT_SUCCESS) {
        int32 code = cm_get_error_code();
        if (code == ERR_TABLE_OR_VIEW_NOT_EXIST) {
            return CT_FALSE;
        }

        return CT_TRUE;
    }

    if (dc.org_scn != org_scn) {
        dc_close(&dc);
        return CT_FALSE;
    }

    dc_close(&dc);
    return CT_TRUE;
}

void temp_mtrl_init_context(knl_session_t *session)
{
    uint32 i;
    mtrl_context_t *ctx = session->temp_mtrl;
    errno_t ret;

    ctx->seg_count = 0;
    ctx->lock = 0;
    for (i = 0; i < CT_MAX_MTRL_OPEN_PAGES; i++) {
        ctx->open_pages[i] = CT_INVALID_ID32;
    }

    /* one for temp heap, one for temp index */
    for (i = 0; i < session->temp_table_capacity * 2; i++) {
        ctx->segments[i] = NULL;
    }

    ctx->print_page = NULL;
    ctx->sort_cmp = NULL;

    ctx->session = (handle_t)session;
    ctx->pool = NULL; /* assign value after getting session->temp_pool in knl_init_session_2 */
    g_knl_callback.init_vmc((handle_t)ctx);

    session->temp_table_count = 0;
    ret = memset_sp(session->temp_table_cache, sizeof(knl_temp_cache_t) * session->temp_table_capacity,
                    0, sizeof(knl_temp_cache_t) * session->temp_table_capacity);
    knl_securec_check(ret);
}

void temp_mtrl_release_context(knl_session_t *session)
{
    uint32 i;
    mtrl_context_t *ctx = session->temp_mtrl;

    if (ctx->seg_count == 0) {
        int32 ret = memset_sp(ctx->segments, sizeof(ctx->segments), 0, sizeof(ctx->segments));
        knl_securec_check(ret);
        vmc_free(&ctx->vmc);
        return;
    }

    for (i = 0; i < CT_MAX_MTRL_OPEN_PAGES; i++) {
        if (ctx->open_pages[i] != CT_INVALID_ID32) {
            // don't use vm_close_and_free, because the page will be freed in mtrl_release_segment
            // and page can only be freed once
            vm_close(ctx->session, ctx->pool, ctx->open_pages[i], VM_ENQUE_HEAD);
            ctx->open_pages[i] = CT_INVALID_ID32;
        }
    }

    /* one for temp heap, one for temp index */
    for (i = 0; i < session->temp_table_capacity * 2; i++) {
        if (ctx->segments[i] != NULL) {
            ctx->segments[i]->curr_page = NULL;
            mtrl_release_segment(ctx, i);
        }
        ctx->segments[i] = NULL;
    }

    ctx->seg_count = 0;
    ctx->open_hwm = 0;

    session->temp_table_count = 0;
    vmc_free(&ctx->vmc);
}

vm_page_t *buf_curr_temp_page(knl_session_t *session)
{
    knl_panic_log(session->temp_page_stack.depth > 0, "temp_page_stack's depth abnormal, panic info: depth %u",
                  session->temp_page_stack.depth);
    return session->temp_page_stack.pages[session->temp_page_stack.depth - 1];
}

static inline void buf_push_temp_page(knl_session_t *session, vm_page_t *page)
{
    knl_panic_log(session->temp_page_stack.depth < KNL_MAX_PAGE_STACK_DEPTH,
                  "temp_page_stack's depth abnormal, panic info: depth %u", session->temp_page_stack.depth);
    session->temp_page_stack.pages[session->temp_page_stack.depth] = page;
    session->temp_page_stack.depth++;
}

static inline void buf_pop_temp_page(knl_session_t *session)
{
    knl_panic_log(session->temp_page_stack.depth > 0, "temp_page_stack's depth abnormal, panic info: depth %u",
                  session->temp_page_stack.depth);
    session->temp_page_stack.depth--;
}

void temp_page_init(knl_session_t *session, page_head_t *page, uint32 vmid, page_type_t type)
{
    temp_page_tail_t *tail = NULL;
    errno_t ret;

    ret = memset_sp((char *)page, TEMP_PAGE_SIZE, 0, TEMP_PAGE_SIZE);
    knl_securec_check(ret);
    AS_PAGID_PTR(page->id)->vmid = vmid;
    page->size_units = page_size_units(TEMP_PAGE_SIZE);
    page->type = type;
    AS_PAGID_PTR(page->next_ext)->vmid = CT_INVALID_ID32;

    tail = TEMP_PAGE_TAIL(page);
    tail->pcn = 0;
}

#ifdef LOG_DIAG
static void temp_heap_validate_page(knl_session_t *session, vm_page_t *vm_page)
{
    temp_heap_page_t *page = (temp_heap_page_t *)vm_page->data;
    if (page->head.type != PAGE_TYPE_TEMP_HEAP) {
        return;
    }

    knl_panic_log(page->free_begin >= sizeof(temp_heap_page_t), "page's free size begin is smaller than the size of "
                  "temp heap page's size, panic info: page %u-%u type %u free_begin %u", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, page->free_begin);
    knl_panic_log(page->free_begin <= page->free_end, "page's free size begin is more than end, panic info: "
                  "page %u-%u type %u free_begin %u free_end %u", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, page->free_begin, page->free_end);
    knl_panic_log(page->itls == 0, "page's itls is abnormal, panic info: page %u-%u type %u itls %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, page->itls);

    // check dir
    for (uint16 i = 0; i < page->dirs; i++) {
        temp_row_dir_t *dir = temp_heap_get_dir(page, i);
        if (dir->is_free) {
            continue;
        }
        knl_panic_log(dir->offset >= sizeof(temp_heap_page_t),
                      "dir's offset is abnormal, panic info: page %u-%u type %u dir offset %u",
                      AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, dir->offset);
        knl_panic_log(dir->offset < page->free_begin, "dir's offset is more than page's free_begin, panic info: "
                      "page %u-%u type %u free_begin %u dir offset %u", AS_PAGID(page->head.id).file,
                      AS_PAGID(page->head.id).page, page->head.type, page->free_begin, dir->offset);
        row_head_t *row = TEMP_HEAP_GET_ROW(page, dir);
        /* means row->is_link == 0 && row->is_migr == 1 or row->is_link == 1 && row->is_migr == 0 */
        knl_panic_log(row->is_link + row->is_migr < 2, "row is both link and migr, panic info: page %u-%u type %u",
                      AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
        knl_panic_log(ROW_ITL_ID(row) == CT_INVALID_ID8, "row itl id is valid, panic info: page %u-%u type %u",
                      AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
    }

    // check row size
    uint32 total_size = sizeof(temp_heap_page_t);
    while (total_size < page->free_begin) {
        row_head_t *pos = (row_head_t *)((char *)page + total_size);
        knl_panic_log(pos->size >= HEAP_MIN_ROW_SIZE, "the size pointed by pos is smaller than the min limit, "
                      "panic info: page %u-%u type %u pos size %u",
                      AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, pos->size);
        knl_panic_log(pos->size <= TEMP_CT_MAX_ROW_SIZE,
                      "the size pointed by pos is more than the max limit, panic info: page %u-%u type %u pos size %u",
                      AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, pos->size);
        total_size += pos->size;

        knl_panic_log(total_size <= page->free_begin,
            "total_size is more than page's free_begin, panic info: page %u-%u type %u free_begin %u total_size %u",
            AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, page->free_begin, total_size);
    }
}

#endif

status_t buf_enter_temp_page_nolock(knl_session_t *session, uint32 vmid)
{
    vm_page_t *vm_page = NULL;

    if (vmid == CT_INVALID_ID32) {
        CT_LOG_RUN_ERR("invalid vm id when buffer enter temp page with nolock");
        CT_THROW_ERROR(ERR_INVALID_PAGE_ID, "");
        return CT_ERROR;
    }

    if (mtrl_open_page(session->temp_mtrl, vmid, &vm_page) != CT_SUCCESS) {
        return CT_ERROR;
    }
    buf_push_temp_page(session, vm_page);
    return CT_SUCCESS;
}

void buf_leave_temp_page_nolock(knl_session_t *session, bool32 changed)
{
    vm_page_t *vm_page = NULL;
    page_head_t *head;
    vm_page = buf_curr_temp_page(session);
    head = (page_head_t *)(vm_page->data);

    buf_pop_temp_page(session);

    knl_panic_log(AS_PAGID_PTR(head->id)->vmid == vm_page->vmid,
                  "vmid is abnormal, panic info: the vmid record on head %u the vmid record on vm page %u",
                  AS_PAGID_PTR(head->id)->vmid, vm_page->vmid);

#ifdef LOG_DIAG
    temp_heap_validate_page(session, vm_page);
#endif

    if (changed) {
        head->pcn++;
        TEMP_PAGE_TAIL(head)->pcn++;
    }

    mtrl_close_page(session->temp_mtrl, vm_page->vmid);
}

static void temp_heap_format_page(knl_session_t *session, knl_temp_cache_t *temp_cache,
    temp_heap_page_t *page, uint32 id)
{
    temp_page_init(session, &page->head, id, PAGE_TYPE_TEMP_HEAP);

    AS_PAGID_PTR(page->next)->vmid = CT_INVALID_ID32;
    page->itls = 0;
    page->first_free_dir = HEAP_NO_FREE_DIR;
    page->free_begin = sizeof(temp_heap_page_t);
    page->free_end = (uint32)PAGE_SIZE(page->head) - sizeof(temp_page_tail_t);
    page->free_size = page->free_end - page->free_begin;
    page->oid = CT_INVALID_ID32;
    page->uid = CT_INVALID_ID16;
    page->seg_scn = CT_INVALID_ID64;
    page->org_scn = temp_cache->org_scn;
    page->rows = 0;
    page->dirs = 0;
}

static inline void temp_heap_init_row(knl_session_t *session, row_assist_t *ra, char *buf, uint32 column_count,
                                      uint16 flags)
{
    row_init(ra, buf, KNL_MAX_ROW_SIZE(session),
             column_count);
    ROW_SET_ITL_ID(ra->head, CT_INVALID_ID8);

    ra->head->flags = flags;
}

status_t temp_create_segment(knl_session_t *session, uint32 *id)
{
    mtrl_context_t *ctx = session->temp_mtrl;
    mtrl_segment_t *segment = NULL;
    uint32 i;

    for (i = 0; i < ctx->seg_count; i++) {
        segment = ctx->segments[i];
        if (segment->level == CT_INVALID_ID32) {
            knl_panic_log(!segment->is_used, "current segment is used.");
            break;
        }
    }

    /* one for heap, one for index */
    if (i >= session->temp_table_capacity * 2) {
        CT_THROW_ERROR(ERR_TOO_MANY_OBJECTS, session->temp_table_capacity * 2, "temp segments");
        return CT_ERROR;
    }

    if (i >= ctx->seg_count) {
        ctx->seg_count++;
    }

    CT_RETURN_IFERR(vmc_alloc_mem(&ctx->vmc, sizeof(mtrl_segment_t), (void **)&ctx->segments[i]));
    segment = ctx->segments[i];
    segment->vm_list.count = 0;
    segment->cmp_items = NULL;
    segment->type = MTRL_SEGMENT_TEMP;
    segment->level = 0;
    segment->is_used = CT_TRUE;

    *id = i;
    return CT_SUCCESS;
}

void temp_drop_segment(mtrl_context_t *ctx, uint32 id)
{
    knl_panic_log(ctx->segments[id]->is_used, "current segment is not used, panic info: id %u", id);
    vm_free_list(ctx->session, ctx->pool, &ctx->segments[id]->vm_list);
    ctx->segments[id]->is_used = CT_FALSE;
    ctx->segments[id]->level = CT_INVALID_ID32;
}

status_t temp_heap_create_segment(knl_session_t *session, knl_temp_cache_t *temp_table_ptr)
{
    uint32 table_segid;
    mtrl_segment_t *segment = NULL;
    uint32 vmid = CT_INVALID_ID32;

    if (temp_create_segment(session, &table_segid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    temp_table_ptr->table_segid = table_segid;
    segment = session->temp_mtrl->segments[table_segid];

    if (temp_heap_alloc_page(session, temp_table_ptr, &vmid) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to alloc page in heap create segment.");
        return CT_ERROR;
    }

    knl_panic_log(segment->vm_list.last == vmid, "the vm list is abnormal, panic info: vm_list's last %u vmid %u.",
                  segment->vm_list.last, vmid);
    knl_panic_log(segment->vm_list.count > 0, "the count of vm list is abnormal, panic info: vm_list's count %u",
                  segment->vm_list.count);
    return CT_SUCCESS;
}


bool32 temp_heap_check_page(knl_session_t *session, knl_cursor_t *cursor, temp_heap_page_t *page, page_type_t type)
{
    table_t *table = NULL;

    // page type invalid
    if (page->head.type != type) {
        return CT_FALSE;
    }

    table = (table_t *)cursor->table;

    return (page->org_scn == table->desc.org_scn);
}


void temp_heap_insert_into_page(knl_cursor_t *cursor, temp_heap_page_t *page, row_head_t *row,
                                undo_data_t *undo, rd_temp_heap_insert_t *rd, uint16 *slot)
{
    temp_row_dir_t *dir = NULL;
    char *row_addr = NULL;
    uint16 row_size = row->size;
    errno_t ret;

    if (page->first_free_dir == HEAP_NO_FREE_DIR || rd->new_dir) {
        *slot = page->dirs;
        page->dirs++;
        dir = temp_heap_get_dir(page, *slot);
        page->free_end -= sizeof(temp_row_dir_t);
        page->free_size -= sizeof(temp_row_dir_t);

        undo->snapshot.scn = 0;
        undo->snapshot.is_owscn = 0;
        undo->snapshot.undo_page = INVALID_UNDO_PAGID;
        undo->snapshot.undo_slot = INVALID_SLOT;
    } else {
        *slot = page->first_free_dir;
        dir = temp_heap_get_dir(page, *slot);
        page->first_free_dir = dir->next_slot;

        undo->snapshot.scn = dir->scn;
        undo->snapshot.is_owscn = dir->is_owscn;
        undo->snapshot.undo_page = dir->undo_page;
        undo->snapshot.undo_slot = dir->undo_slot;
    }

    dir->undo_page = rd->undo_page;
    dir->undo_slot = rd->undo_slot;
    dir->scn = rd->ssn;
    dir->is_owscn = 0;
    dir->offset = page->free_begin;

    row_addr = (char *)page + dir->offset;
    row->flags = 0;
    ROW_SET_ITL_ID(row, CT_INVALID_ID8);
    row->is_changed = 0;
    ret = memcpy_sp(row_addr, page->free_size, row, row_size);
    knl_securec_check(ret);

    page->free_begin += row_size;
    page->free_size -= row_size;
    page->rows++;
    knl_panic_log(page->free_begin <= page->free_end, "page's free size begin is more than end, panic info: "
                  "page %u-%u type %u table %s free_begin %u free_end %u", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, ((table_t *)cursor->table)->desc.name,
                  page->free_begin, page->free_end);
}

static status_t temp_heap_get_row(knl_session_t *session, knl_cursor_t *cursor, temp_heap_page_t *page,
                                  bool32 *is_found)
{
    temp_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    *is_found = CT_FALSE;

    dir = temp_heap_get_dir(page, (uint32)cursor->rowid.vm_slot);
    if (dir->is_free || cursor->ssn < dir->scn) {
        *is_found = CT_FALSE;
        return CT_SUCCESS;
    }

    if (cursor->ssn == dir->scn && cursor->action <= CURSOR_ACTION_SELECT) {
        *is_found = CT_FALSE;
        return CT_SUCCESS;
    }

    row = TEMP_HEAP_GET_ROW(page, dir);
    if (row->is_migr) {
        *is_found = CT_FALSE;
        return CT_SUCCESS;
    }

    if (cursor->ssn == dir->scn && row->is_changed == 0) {
        *is_found = CT_FALSE;
        return CT_SUCCESS;
    }

    *is_found = !row->is_deleted;
    cursor->eof = *is_found ? 0 : 1;
    if (*is_found) {
        HEAP_COPY_ROW(session, cursor, row);
    }

    knl_panic_log(ROW_ITL_ID(row) == CT_INVALID_ID8, "row itl id is valid, panic info: page %u-%u type %u table %s",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type,
                  ((table_t *)cursor->table)->desc.name);
    /* means row->is_link == 0 && row->is_migr == 1 or row->is_link == 1 && row->is_migr == 0 */
    knl_panic_log(row->is_link + row->is_migr < 2,
                  "row is both link and migr, panic info: page %u-%u type %u table %s", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, ((table_t *)cursor->table)->desc.name);
    return CT_SUCCESS;
}

static status_t temp_heap_scan_full_page(knl_session_t *session, knl_cursor_t *cursor, temp_heap_page_t *page,
                                         bool32 *is_found)
{
    vm_ctrl_t *ctrl = NULL;
    *is_found = CT_FALSE;

    for (;;) {
        cursor->link_rid.vmid = CT_INVALID_ID32;
        if (cursor->rowid.vm_slot == CT_INVALID_ID16) {
            cursor->rowid.vm_slot = 0;
        } else {
            cursor->rowid.vm_slot++;
        }

        if (cursor->rowid.vm_slot == page->dirs) {
            ctrl = vm_get_ctrl(session->temp_mtrl->pool, (uint32)cursor->rowid.vmid);
            if (session->stat_sample) {
                cursor->rowid.vmid = CT_INVALID_ID32;
            } else {
                cursor->rowid.vmid = ctrl->next;
            }

            cursor->rowid.vm_slot = CT_INVALID_ID16;
            return CT_SUCCESS;
        }

        cursor->rowid_pos.file = cursor->rowid.file;
        cursor->rowid_pos.page = cursor->rowid.page;
        cursor->rowid_pos.vmid = cursor->rowid.vmid;
        cursor->rowid_pos.vm_slot = cursor->rowid.vm_slot;

        if (temp_heap_get_row(session, cursor, page, is_found) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (*is_found) {
            return CT_SUCCESS;
        }
    }
}

static status_t temp_heap_get_migr_row(knl_session_t *session, knl_cursor_t *cursor)
{
    temp_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    temp_heap_page_t *page = NULL;
    int32 ret;

    if (buf_enter_temp_page_nolock(session, (uint32)cursor->link_rid.vmid) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to open heap migr vm page (%u).", cursor->link_rid.vmid);
        return CT_ERROR;
    }
    page = TEMP_HEAP_CURR_PAGE(session);
    if (!temp_heap_check_page(session, cursor, page, PAGE_TYPE_TEMP_HEAP)) {
        buf_leave_temp_page_nolock(session, CT_FALSE);
        CT_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, "temp table");
        return CT_ERROR;
    }

    dir = temp_heap_get_dir(page, (uint32)cursor->link_rid.vm_slot);
    knl_panic_log(dir->is_free == 0, "dir is free, panic info: page %u-%u type %u table %s",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type,
                  ((table_t *)cursor->table)->desc.name);
    row = TEMP_HEAP_GET_ROW(page, dir);
    knl_panic_log(row->is_migr == 1, "row is not migr, panic info: page %u-%u type %u table %s",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type,
                  ((table_t *)cursor->table)->desc.name);
    knl_panic_log(cursor->link_rid.vmid != CT_INVALID_ID32,
                  "the vm id is invalid, panic info: page %u-%u type %u table %s", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, ((table_t *)cursor->table)->desc.name);

    if (row->size != 0) {
        ret = memcpy_sp(cursor->row, TEMP_CT_MAX_ROW_SIZE, row, row->size);
        knl_securec_check(ret);
    }

    cursor->row->is_migr = 0;
    buf_leave_temp_page_nolock(session, CT_FALSE);
    return CT_SUCCESS;
}

static status_t temp_heap_read_by_rowid(knl_session_t *session, knl_cursor_t *cursor, bool32 *is_found)
{
    temp_heap_page_t *page = NULL;

    *is_found = CT_FALSE;
    cursor->snapshot.is_valid = 0;
    cursor->snapshot.undo_page = INVALID_UNDO_PAGID;
    cursor->snapshot.undo_slot = INVALID_SLOT;
    cursor->link_rid.vmid = CT_INVALID_ID32;

    if (buf_enter_temp_page_nolock(session, (uint32)cursor->rowid.vmid) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to open heap rowid vm page (%u).", cursor->rowid.vmid);
        return CT_ERROR;
    }

    page = TEMP_HEAP_CURR_PAGE(session);
    if (!temp_heap_check_page(session, cursor, page, PAGE_TYPE_TEMP_HEAP)) {
        buf_leave_temp_page_nolock(session, CT_FALSE);
        CT_THROW_ERROR(ERR_INVALID_ROWID);
        return CT_ERROR;
    }

    if (cursor->rowid.vm_slot >= page->dirs) {
        buf_leave_temp_page_nolock(session, CT_FALSE);
        CT_THROW_ERROR(ERR_INVALID_ROWID);
        return CT_ERROR;
    }

    if (temp_heap_get_row(session, cursor, page, is_found) != CT_SUCCESS) {
        buf_leave_temp_page_nolock(session, CT_FALSE);
        return CT_ERROR;
    }

    if (*is_found && cursor->link_rid.vmid != CT_INVALID_ID32) {
        if (temp_heap_get_migr_row(session, cursor) != CT_SUCCESS) {
            buf_leave_temp_page_nolock(session, CT_FALSE);
            return CT_ERROR;
        }
    }

    buf_leave_temp_page_nolock(session, CT_FALSE);

    return CT_SUCCESS;
}

static status_t temp_heap_fetch_by_page(knl_session_t *session, knl_cursor_t *cursor, bool32 *is_found)
{
    temp_heap_page_t *page = NULL;
    *is_found = CT_FALSE;

    if (buf_enter_temp_page_nolock(session, (uint32)cursor->rowid.vmid) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to open heap fetch vm page (%u).", cursor->rowid.vmid);
        return CT_ERROR;
    }
    page = TEMP_HEAP_CURR_PAGE(session);
    if (!temp_heap_check_page(session, cursor, page, PAGE_TYPE_TEMP_HEAP)) {
        buf_leave_temp_page_nolock(session, CT_FALSE);
        CT_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, "temp table");
        return CT_ERROR;
    }

    if (temp_heap_scan_full_page(session, cursor, page, is_found) != CT_SUCCESS) {
        buf_leave_temp_page_nolock(session, CT_FALSE);
        return CT_ERROR;
    }

    if (*is_found && cursor->link_rid.vmid != CT_INVALID_ID32) {
        if (temp_heap_get_migr_row(session, cursor) != CT_SUCCESS) {
            buf_leave_temp_page_nolock(session, CT_FALSE);
            return CT_ERROR;
        }
    }

    buf_leave_temp_page_nolock(session, CT_FALSE);
    return CT_SUCCESS;
}

static status_t temp_heap_try_lock_row(knl_session_t *session, knl_cursor_t *cursor)
{
    temp_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    temp_heap_page_t *page = NULL;

    if (buf_enter_temp_page_nolock(session, (uint32)cursor->rowid.vmid) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to open heap fetch vm page (%u).", cursor->rowid.vmid);
        return CT_ERROR;
    }
    page = TEMP_HEAP_CURR_PAGE(session);

    dir = temp_heap_get_dir(page, (uint32)cursor->rowid.vm_slot);

    knl_panic_log(!dir->is_free, "dir is free, panic info: page %u-%u type %u table %s", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, ((table_t *)cursor->table)->desc.name);

    row = TEMP_HEAP_GET_ROW(page, dir);

    knl_panic_log(!row->is_deleted, "row is deleted, panic info: page %u-%u type %u table %s",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type,
                  ((table_t *)cursor->table)->desc.name);

    if (dir->scn >= cursor->ssn) {
        buf_leave_temp_page_nolock(session, CT_FALSE);
        CT_THROW_ERROR(ERR_ROW_SELF_UPDATED);
        return CT_ERROR;
    }
    buf_leave_temp_page_nolock(session, CT_FALSE);
    return CT_SUCCESS;
}

status_t temp_heap_lock_row(knl_session_t *session, knl_cursor_t *cursor, bool32 *is_locked)
{
    if (lock_table_shared(session, cursor->dc_entity, LOCK_INF_WAIT) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (temp_heap_try_lock_row(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    *is_locked = CT_TRUE;
    return CT_SUCCESS;
}

status_t temp_heap_fetch(knl_handle_t handle, knl_cursor_t *cursor)
{
    knl_session_t *session = (knl_session_t *)handle;

    if (cursor->temp_cache == NULL || CURSOR_TEMP_CACHE(cursor)->table_segid == CT_INVALID_ID32) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    /* one tx can not see any row of the temp table which belong to another tx */
    knl_temp_cache_t *temp_table = (knl_temp_cache_t *)cursor->temp_cache;
    if (temp_table->table_type == DICT_TYPE_TEMP_TABLE_TRANS &&
        temp_table->hold_rmid != CT_INVALID_ID32 && session->rmid != temp_table->hold_rmid) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }
        
    for (;;) {
        if (cursor->rowid.vmid == CT_INVALID_ID32) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }
        if (cursor->eof) {
            return CT_SUCCESS;
        }

        if (temp_heap_fetch_by_page(session, cursor, &cursor->is_found) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!cursor->is_found) {
            continue;
        }

        if (knl_match_cond(session, cursor, &cursor->is_found) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!cursor->is_found) {
            continue;
        }

        if (cursor->action <= CURSOR_ACTION_SELECT) {
            return CT_SUCCESS;
        }

        if (temp_heap_lock_row(session, cursor, &cursor->is_found) != CT_SUCCESS) {
            return CT_ERROR;
        }
        return CT_SUCCESS;
    }
}

inline bool32 temp_rowid_valid(knl_handle_t session, const rowid_t *rid)
{
    knl_session_t *se = (knl_session_t*)session;
    vm_pool_t *pool = se->temp_mtrl->pool;

    if (rid->vmid >= pool->ctrl_hwm) {
        return CT_FALSE;
    }

    return CT_TRUE;
}

status_t temp_heap_rowid_fetch(knl_handle_t session, knl_cursor_t *knl_cur)
{
    if (knl_cur->temp_cache == NULL || CURSOR_TEMP_CACHE(knl_cur)->table_segid == CT_INVALID_ID32) {
        knl_cur->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    for (;;) {
        if (knl_cur->rowid_no == knl_cur->rowid_count) {
            knl_cur->eof = CT_TRUE;
            return CT_SUCCESS;
        }

        knl_cur->rowid = knl_cur->rowid_array[knl_cur->rowid_no];
        knl_cur->rowid_no++;

        if (temp_heap_fetch_by_rowid((knl_session_t *)session, knl_cur) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (knl_cur->is_found) {
            return CT_SUCCESS;
        }
    }

    return CT_ERROR;
}

status_t temp_heap_fetch_by_rowid(knl_session_t *session, knl_cursor_t *cursor)
{
    if (!temp_rowid_valid((knl_session_t *)session, &cursor->rowid)) {
        CT_THROW_ERROR(ERR_INVALID_ROWID);
        return CT_ERROR;
    }

    if (temp_heap_read_by_rowid(session, cursor, &cursor->is_found) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!cursor->is_found) {
        return CT_SUCCESS;
    }

    if (knl_match_cond(session, cursor, &cursor->is_found) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!cursor->is_found || cursor->action <= CURSOR_ACTION_SELECT) {
        return CT_SUCCESS;
    }

    if (temp_heap_lock_row(session, cursor, &cursor->is_found) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t temp_heap_alloc_page(knl_session_t *session, knl_temp_cache_t *temp_cache, uint32 *curr_vmid)
{
    temp_heap_page_t *page = NULL;
    vm_page_t *vm_page = NULL;
    mtrl_segment_t *segment = NULL;
    mtrl_context_t *ctx = session->temp_mtrl;
    uint32 vmid;

    if (temp_cache == NULL || temp_cache->table_segid == CT_INVALID_ID32) {
        CT_LOG_RUN_ERR("[TEMP] failed to alloc page");
        return CT_ERROR;
    }

    segment = session->temp_mtrl->segments[temp_cache->table_segid];

    if (vm_alloc(ctx->session, ctx->pool, &vmid) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to extend segment when heap alloc page.");
        return CT_ERROR;
    }

    if (buf_enter_temp_page_nolock(session, vmid) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to open extend vm (%d) when heap alloc page.", vmid);
        return CT_ERROR;
    }

    vm_page = buf_curr_temp_page(session);
    page = (temp_heap_page_t *)vm_page->data;
    temp_heap_format_page(session, temp_cache, page, vmid);
    buf_leave_temp_page_nolock(session, CT_TRUE);
    vm_append(ctx->pool, &segment->vm_list, vmid);
    
    *curr_vmid = vmid;

    knl_panic_log(segment->vm_list.last == vmid,
        "list's last is not equal to vmid, panic info: page %u-%u type %u vm_list's last %u vmid %u",
        AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, segment->vm_list.last, vmid);
    return CT_SUCCESS;
}

status_t temp_enter_heap_insert(knl_session_t *session, knl_cursor_t *cursor, uint32 cost_size, uint32 *alloc_vmid)
{
    temp_heap_page_t *page = NULL;
    vm_page_t *vm_page = NULL;
    uint32 vmid;
    uint64 pct_free_size = ((table_t *)cursor->table)->desc.pctfree * TEMP_PAGE_SIZE / 100;

    vmid = session->temp_mtrl->segments[CURSOR_TEMP_CACHE(cursor)->table_segid]->vm_list.last;
    if (buf_enter_temp_page_nolock(session, vmid) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to open vm page (%u) when enter heap insert.", vmid);
        return CT_ERROR;
    }

    vm_page = buf_curr_temp_page(session);
    page = (temp_heap_page_t *)vm_page->data;
    knl_panic_log(page->head.type == PAGE_TYPE_TEMP_HEAP,
                  "page type is abnormal, panic info: page %u-%u type %u table %s", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, ((table_t *)cursor->table)->desc.name);

    if (page->free_end < cost_size + page->free_begin + pct_free_size) {
        buf_leave_temp_page_nolock(session, CT_FALSE);

        if (CT_SUCCESS != temp_heap_alloc_page(session, cursor->temp_cache, &vmid)) {
            CT_LOG_RUN_ERR("failed to find free temp buffer page for enter insert size : %u.", cost_size);
            return CT_ERROR;
        }

        if (buf_enter_temp_page_nolock(session, vmid) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("Fail to open new allocated page (%d) when enter heap insert.", vmid);
            return CT_ERROR;
        }

        vm_page = buf_curr_temp_page(session);
        page = (temp_heap_page_t *)vm_page->data;
        knl_panic_log(page->free_end >= cost_size + page->free_begin, "page's free size is abnormal, panic info: "
                      "page %u-%u type %u table %s free_end %u free_begin %u cost_size %u",
                      AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type,
                      ((table_t *)cursor->table)->desc.name, page->free_end, page->free_begin, cost_size);
    }

    *alloc_vmid = vmid;
    return CT_SUCCESS;
}

static void temp_batch_insert_rows(knl_session_t *session, knl_cursor_t *cursor,
    undo_data_t *undo, uint16 *rows_size)
{
    rd_temp_heap_insert_t rd;
    row_head_t *row = cursor->row;
    uint16 vm_slot;

    vm_page_t *vm_page = buf_curr_temp_page(session);
    temp_heap_page_t *page = (temp_heap_page_t *)vm_page->data;

    ROW_SET_ITL_ID(row, CT_INVALID_ID8);
    rd.ssn = cursor->ssn;
    if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)){
        rd.undo_page = session->rm->undo_page_info.undo_rid.page_id;
        rd.undo_slot = session->rm->undo_page_info.undo_rid.slot;
    } else {
        rd.undo_page = session->rm->noredo_undo_page_info.undo_rid.page_id;
        rd.undo_slot = session->rm->noredo_undo_page_info.undo_rid.slot;
    }
    rd.new_dir = CT_TRUE;

    temp_heap_undo_binsert_t *batch_undo = (temp_heap_undo_binsert_t *)undo->data;
    batch_undo->obj_info.uid = CURSOR_TEMP_CACHE(cursor)->user_id;
    batch_undo->obj_info.table_id = CURSOR_TEMP_CACHE(cursor)->table_id;
    batch_undo->obj_info.seg_scn = CURSOR_TEMP_CACHE(cursor)->seg_scn;
    batch_undo->count = 0;
    batch_undo->begin_slot = page->dirs;

    uint32 row_count = MIN(cursor->rowid_count - cursor->rowid_no, KNL_ROWID_ARRAY_SIZE);
    uint64 pct_free_size = ((table_t *)cursor->table)->desc.pctfree * TEMP_PAGE_SIZE / 100;

    for (uint32 i = 0; i < row_count; i++) {
        temp_heap_insert_into_page(cursor, page, row, undo, &rd, &vm_slot);

        cursor->rowid.vm_slot = vm_slot;
        cursor->rowid_array[cursor->rowid_no].vmid = cursor->rowid.vmid;
        cursor->rowid_array[cursor->rowid_no].vm_slot = vm_slot;
        cursor->rowid_no++;
        batch_undo->count++;
        CURSOR_TEMP_CACHE(cursor)->rows++;

        row = (row_head_t *)((char *)row + row->size);
        if (i == row_count - 1) {
            break;
        }

        uint32 max_cost_size = row->size + sizeof(temp_row_dir_t);
        if (row->size > TEMP_CT_MAX_ROW_SIZE ||
            page->free_end < page->free_begin + max_cost_size + pct_free_size) {
            break;
        }
    }

    *rows_size = (uint16)((char *)row - (char *)cursor->row);
    knl_panic_log(page->dirs - batch_undo->begin_slot == batch_undo->count,
                  "invalid temp heap batch insert dirs %u, begin slot %u, batch count %u",
                  (uint32)page->dirs, (uint32)batch_undo->begin_slot, (uint32)batch_undo->count);
    knl_panic_log(*rows_size != 0, "invalid temp heap batch insert rows_size %u", (uint32)(*rows_size));

    undo->snapshot.is_xfirst = cursor->is_xfirst;
    undo->type = UNDO_TEMP_HEAP_BINSERT;
    undo->rowid = cursor->rowid;
}

static status_t temp_heap_try_batch_insert(knl_session_t *session, knl_cursor_t *cursor, uint16 *rows_size)
{
    row_head_t *row = cursor->row;
    uint32 vmid = CT_INVALID_ID32;
    undo_data_t undo = { 0 };
    bool32 need_redo = IS_TEMPTABLE_HAS_REDO(session);

    if (row->size > TEMP_CT_MAX_ROW_SIZE) {
        CT_THROW_ERROR(ERR_RECORD_SIZE_OVERFLOW, "insert row", row->size, TEMP_CT_MAX_ROW_SIZE);
        return CT_ERROR;
    }

    knl_panic_log(cursor->rowid_no <= cursor->rowid_count, "invalid temp heap batch insert rowid no %u, rowid count %u",
                  (uint32)cursor->rowid_no, (uint32)cursor->rowid_count);
    undo.size = sizeof(temp_heap_undo_binsert_t);
    if (undo_prepare(session, undo.size, need_redo, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    *rows_size = 0;
    cursor->is_xfirst = CT_TRUE;
    session->rm->temp_has_undo = CT_TRUE;
    uint32 max_cost_size = row->size + sizeof(temp_row_dir_t);
    if (temp_enter_heap_insert(session, cursor, max_cost_size, &vmid) != CT_SUCCESS) {
        return CT_ERROR;
    }
    cursor->rowid.vmid = vmid;

    CM_SAVE_STACK(session->stack);
    temp_heap_undo_binsert_t *batch_undo = (temp_heap_undo_binsert_t *)cm_push(session->stack, undo.size);
    undo.data = (char *)batch_undo;

    temp_batch_insert_rows(session, cursor, &undo, rows_size);

    log_atomic_op_begin(session);
    undo_write(session, &undo, need_redo, CT_FALSE);
    log_atomic_op_end(session);
    CM_RESTORE_STACK(session->stack);

    buf_leave_temp_page_nolock(session, CT_TRUE);
    return CT_SUCCESS;
}

static status_t temp_heap_batch_insert(knl_session_t *session, knl_cursor_t *cursor)
{
    status_t status;
    row_head_t *row_addr = cursor->row;
    uint16 offset = 0;
    cursor->rowid_no = 0;

    do {
        status = temp_heap_try_batch_insert(session, cursor, &offset);
        cursor->row = (row_head_t *)((char *)cursor->row + offset);
    } while (cursor->rowid_count > cursor->rowid_no && status == CT_SUCCESS);

    cursor->rowid_no = 0;
    cursor->row_offset = 0;
    cursor->row = row_addr;
    return status;
}

static status_t temp_simple_insert(knl_session_t *session, knl_cursor_t *cursor)
{
    temp_heap_page_t *page = NULL;
    vm_page_t *vm_page = NULL;
    row_head_t *row = cursor->row;
    uint32 vmid = CT_INVALID_ID32;
    rd_temp_heap_insert_t rd;
    uint16 vm_slot;
    undo_data_t undo = { 0 };
    bool32 need_redo = IS_TEMPTABLE_HAS_REDO(session);
    undo_page_info_t *undo_page_info = UNDO_GET_PAGE_INFO(session, need_redo);

    undo.size = sizeof(temp_heap_extra_undo_t);

    if (undo_prepare(session, undo.size, need_redo, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cursor->is_xfirst = CT_TRUE;
    session->rm->temp_has_undo = CT_TRUE;

    uint32 max_cost_size = row->size + sizeof(temp_row_dir_t);

    // try last page, then pages in free list
    knl_panic_log(session->temp_mtrl->segments[CURSOR_TEMP_CACHE(cursor)->table_segid]->vm_list.count > 0,
                  "vm page count is abnormal, panic info: page %u-%u type %u table %s vm_list's count %u",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name,
                  session->temp_mtrl->segments[CURSOR_TEMP_CACHE(cursor)->table_segid]->vm_list.count);

    if (temp_enter_heap_insert(session, cursor, max_cost_size, &vmid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cursor->rowid.vmid = vmid;
    vm_page = buf_curr_temp_page(session);
    page = (temp_heap_page_t *)vm_page->data;

    ROW_SET_ITL_ID(row, CT_INVALID_ID8);
    rd.ssn = cursor->ssn;
    rd.undo_page = undo_page_info->undo_rid.page_id;
    rd.undo_slot = undo_page_info->undo_rid.slot;

    rd.new_dir = CT_FALSE;

    temp_heap_insert_into_page(cursor, page, cursor->row, &undo, &rd, &vm_slot);
    cursor->rowid.vm_slot = vm_slot;

    undo.data = (char *)cm_push(session->stack, undo.size);
    undo.snapshot.is_xfirst = cursor->is_xfirst;
    undo.type = UNDO_TEMP_HEAP_INSERT;
    undo.rowid = cursor->rowid;
    temp_heap_extra_undo_t *extra_undo =
        (temp_heap_extra_undo_t *)(undo.data + undo.size - sizeof(temp_heap_extra_undo_t));
    extra_undo->uid = CURSOR_TEMP_CACHE(cursor)->user_id;
    extra_undo->table_id = CURSOR_TEMP_CACHE(cursor)->table_id;
    extra_undo->seg_scn = CURSOR_TEMP_CACHE(cursor)->seg_scn;

    log_atomic_op_begin(session);
    undo_write(session, &undo, need_redo, CT_FALSE);
    log_atomic_op_end(session);
    cm_pop(session->stack);

    buf_leave_temp_page_nolock(session, CT_TRUE);

    CURSOR_TEMP_CACHE(cursor)->rows++;
    return CT_SUCCESS;
}

status_t temp_heap_insert(knl_session_t *session, knl_cursor_t *cursor)
{
    row_head_t *row = cursor->row;

    knl_panic_log(cursor->is_valid, "current cursor is invalid, panic info: page %u-%u type %u table %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name);
    cursor->link_rid.vmid = CT_INVALID_ID32;

    if (row->size > TEMP_CT_MAX_ROW_SIZE) {
        CT_THROW_ERROR(ERR_RECORD_SIZE_OVERFLOW, "insert row", row->size, TEMP_CT_MAX_ROW_SIZE);
        return CT_ERROR;
    }

    if (row->size < HEAP_MIN_ROW_SIZE) {
        row->size = HEAP_MIN_ROW_SIZE;
    }

    if (lock_table_shared(session, cursor->dc_entity, LOCK_INF_WAIT) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cursor->xid != session->rm->xid.value) {
        cursor->xid = session->rm->xid.value;
    }

    cursor->part_loc.part_no = CT_INVALID_ID32;

    if (SECUREC_UNLIKELY(cursor->rowid_count > 0)) {
        return temp_heap_batch_insert(session, cursor);
    }

    return temp_simple_insert(session, cursor);
}

static void temp_heap_batch_free_dirs(knl_session_t *session, temp_heap_page_t *page, uint16 begin, uint16 end)
{
    uint32 src_count = page->dirs - end;
    uint32 free_count = end - begin;
    temp_row_dir_t *dir = NULL;

    for (uint32 i = end; i < page->dirs; i++) {
        dir = temp_heap_get_dir(page, i);
        row_head_t *row = TEMP_HEAP_GET_ROW(page, dir);
        if (!row->is_link && row->is_migr) {
            return;
        }
    }

    knl_panic_log(free_count >= 1, "temp heap batch insert finish one row at least.");

    if (src_count > 0) {
        temp_row_dir_t *src_dir = temp_heap_get_dir(page, page->dirs - 1);
        temp_row_dir_t *dst_dir = temp_heap_get_dir(page, begin + src_count - 1);
        temp_row_dir_t *free_dir = temp_heap_get_dir(page, end - 1);
        knl_panic_log(free_dir->is_free, "temp heap batch insert invalid dir.");
        
        uint32 copy_size = src_count * sizeof(temp_row_dir_t);
        errno_t ret = memmove_s(dst_dir, copy_size, src_dir, copy_size);
        knl_securec_check(ret);
    }

    page->dirs -= free_count;
    page->free_size += free_count * sizeof(temp_row_dir_t);
    page->free_end += free_count * sizeof(temp_row_dir_t);

    if (page->first_free_dir == HEAP_NO_FREE_DIR) {
        return;
    }

    if (page->first_free_dir >= end) {
        page->first_free_dir = page->first_free_dir - free_count;
    }
    knl_panic_log(page->first_free_dir < page->dirs, "temp page invalid first free dir %u, page dirs %u.",
                  (uint32)page->first_free_dir, (uint32)page->dirs);
    dir = temp_heap_get_dir(page, page->first_free_dir);

    while (dir->next_slot != HEAP_NO_FREE_DIR) {
        if (dir->next_slot >= end) {
            dir->next_slot -= free_count;
        }
        knl_panic_log(dir->next_slot == HEAP_NO_FREE_DIR || dir->next_slot < page->dirs,
                      "temp page invalid next slot %u, page dirs %u.", (uint32)dir->next_slot,
                      (uint32)page->dirs);
        dir = temp_heap_get_dir(page, dir->next_slot);
    }
}

static void temp_heap_undo_insert_row(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page,
                                      int32 ud_slot, uint32 vm_slot)
{
    vm_page_t *vm_page = buf_curr_temp_page(session);
    temp_heap_page_t *page = (temp_heap_page_t *)vm_page->data;
    knl_panic_log(page->head.type == PAGE_TYPE_TEMP_HEAP, "page type is abnormal, panic info: page %u-%u type %u",
        AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
    temp_row_dir_t *dir = temp_heap_get_dir(page, vm_slot);
    knl_panic_log(IS_SAME_PAGID(dir->undo_page, AS_PAGID(ud_page->head.id)),
        "dir's undo_page and ud_page are not same, panic info: page %u-%u type %u",
        AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
    knl_panic_log(dir->undo_slot == ud_slot,
        "dir's undo_slot is not equal ud_slot, panic info: page %u-%u type %u dir undo_slot %u ud_slot %u",
        AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, dir->undo_slot, ud_slot);
    row_head_t *row = TEMP_HEAP_GET_ROW(page, dir);
    knl_panic_log(ROW_ITL_ID(row) == CT_INVALID_ID8, "row itl is valid, panic info: page %u-%u type %u",
        AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);

    if (page->free_begin == dir->offset + row->size) {
        page->free_begin = dir->offset;
    }

    if (row->is_link) {
        page->free_size += HEAP_MIN_ROW_SIZE;
    } else {
        page->free_size += row->size;
    }

    page->rows--;

    dir->scn = ud_row->scn;
    dir->is_owscn = 0;
    dir->undo_page = ud_row->prev_page;
    dir->undo_slot = ud_row->prev_slot;

    ROW_SET_ITL_ID(row, CT_INVALID_ID8);
    row->is_deleted = 1;
    dir->is_free = 1;
    dir->next_slot = page->first_free_dir;
    page->first_free_dir = (uint16)vm_slot;
}

status_t temp_undo_enter_page(knl_session_t *session, uint32 vmid)
{
    status_t status = CT_SUCCESS;
    knl_begin_session_wait(session, TEMP_ENTER_PAGE, CT_TRUE);
    for (;;) {
        if (buf_enter_temp_page_nolock(session, vmid) == CT_SUCCESS) {
            break;
        }

        if (cm_get_error_code() != ERR_NO_FREE_VMEM) {
            status = CT_ERROR;
            break;
        }

        cm_reset_error();
        cm_spin_sleep_and_stat2(1);
    }

    knl_end_session_wait(session, TEMP_ENTER_PAGE);
    return status;
}

void temp_heap_undo_insert(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot)
{
    rowid_t rid = ud_row->rowid;

    if (DB_IS_BG_ROLLBACK_SE(session)) {
        return;
    }

    temp_heap_extra_undo_t *extra_undo =
        (temp_heap_extra_undo_t *)(ud_row->data + ud_row->data_size - sizeof(temp_heap_extra_undo_t));
    knl_temp_cache_t *knl_temp_cache = knl_get_temp_cache(session, extra_undo->uid, extra_undo->table_id);

    if (knl_temp_cache == NULL || knl_temp_cache->seg_scn != extra_undo->seg_scn) {
        return;
    }

    if (temp_undo_enter_page(session, (uint32)rid.vmid) != CT_SUCCESS) {
        knl_panic_log(0, "temp heap undo insert enter link vmid %u failed.", (uint32)rid.vmid);
        return;
    }

    temp_heap_undo_insert_row(session, ud_row, ud_page, ud_slot, (uint32)rid.vm_slot);

    buf_leave_temp_page_nolock(session, CT_TRUE);

    knl_temp_cache->rows--;
}

void temp_heap_undo_batch_insert(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot)
{
    rowid_t rid = ud_row->rowid;

    if (DB_IS_BG_ROLLBACK_SE(session)) {
        return;
    }

    temp_heap_undo_binsert_t *batch_undo = (temp_heap_undo_binsert_t *)ud_row->data;
    knl_temp_cache_t *knl_temp_cache = knl_get_temp_cache(session, batch_undo->obj_info.uid,
                                                          batch_undo->obj_info.table_id);

    if (knl_temp_cache == NULL || knl_temp_cache->seg_scn != batch_undo->obj_info.seg_scn) {
        return;
    }

    if (temp_undo_enter_page(session, (uint32)rid.vmid) != CT_SUCCESS) {
        knl_panic_log(0, "temp heap undo batch insert enter vmid %u failed.", (uint32)rid.vmid);
        return;
    }

    vm_page_t *vm_page = buf_curr_temp_page(session);
    temp_heap_page_t *page = (temp_heap_page_t *)vm_page->data;
    knl_panic_log(page->head.type == PAGE_TYPE_TEMP_HEAP, "invalid temp page type %u",
                  (uint32)page->head.type);

    uint16 first_free_dir = page->first_free_dir;
    uint16 begin_slot = batch_undo->begin_slot;
    uint16 end_slot = batch_undo->count + begin_slot;

    for (uint32 slot = end_slot - 1; slot >= begin_slot; slot--) {
        temp_heap_undo_insert_row(session, ud_row, ud_page, ud_slot, slot);
        if (slot == 0) {
            break;
        }
    }

    page->first_free_dir = first_free_dir;
    temp_heap_batch_free_dirs(session, page, begin_slot, end_slot);
    buf_leave_temp_page_nolock(session, CT_TRUE);
}

status_t temp_heap_delete(knl_session_t *session, knl_cursor_t *cursor)
{
    vm_page_t *vm_page = NULL;
    temp_heap_page_t *page = NULL;
    row_head_t *row = NULL;
    temp_row_dir_t *dir = NULL;
    undo_data_t undo = { 0 };
    errno_t ret;
    dc_entity_t *entity = NULL;
    bool32 need_redo = IS_TEMPTABLE_HAS_REDO(session);
    undo_page_info_t *undo_page_info = UNDO_GET_PAGE_INFO(session, need_redo);

    knl_panic_log(cursor->is_valid, "current cursor is invalid, panic info: page %u-%u type %u table %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name);

    if (cursor->xid != session->rm->xid.value) {
        cursor->xid = session->rm->xid.value;
    }

    entity = (dc_entity_t *)cursor->dc_entity;
    if (entity->contain_lob) {
        if (CT_SUCCESS != lob_delete(session, cursor)) {
            return CT_ERROR;
        }
    }

    undo.size = cursor->row->size + sizeof(temp_heap_extra_undo_t);
    if (CT_SUCCESS != undo_prepare(session, undo.size, need_redo, CT_FALSE)) {
        return CT_ERROR;
    }

    session->rm->temp_has_undo = CT_TRUE;

    undo.data = (char *)cm_push(session->stack, undo.size);
    ret = memcpy_sp(undo.data, undo.size, cursor->row, cursor->row->size);
    knl_securec_check(ret);

    temp_heap_extra_undo_t *extra_undo =
        (temp_heap_extra_undo_t *)(undo.data + undo.size - sizeof(temp_heap_extra_undo_t));
    extra_undo->uid = CURSOR_TEMP_CACHE(cursor)->user_id;
    extra_undo->table_id = CURSOR_TEMP_CACHE(cursor)->table_id;
    extra_undo->seg_scn = CURSOR_TEMP_CACHE(cursor)->seg_scn;
    undo.type = UNDO_TEMP_HEAP_DELETE;
    undo.rowid = cursor->rowid;

    if (buf_enter_temp_page_nolock(session, (uint32)cursor->rowid.vmid) != CT_SUCCESS) {
        cm_pop(session->stack);
        CT_LOG_RUN_ERR("Fail to open vm page (%u) in heap delete.", cursor->rowid.vmid);
        return CT_ERROR;
    }

    vm_page = buf_curr_temp_page(session);
    page = (temp_heap_page_t *)vm_page->data;
    knl_panic_log(page->head.type == PAGE_TYPE_TEMP_HEAP,
                  "page type is abnormal, panic info: page %u-%u type %u table %s", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, ((table_t *)cursor->table)->desc.name);
    dir = temp_heap_get_dir(page, (uint32)cursor->rowid.vm_slot);
    undo.snapshot.scn = dir->scn;
    undo.snapshot.is_owscn = 0;
    undo.snapshot.undo_page = dir->undo_page;
    undo.snapshot.undo_slot = dir->undo_slot;
    undo.snapshot.is_xfirst = cursor->is_xfirst;

    dir->undo_page = undo_page_info->undo_rid.page_id;
    dir->undo_slot = undo_page_info->undo_rid.slot;
    dir->scn = cursor->ssn;
    dir->is_owscn = 0;

    row = (row_head_t *)TEMP_HEAP_GET_ROW(page, dir);

    log_atomic_op_begin(session);
    undo_write(session, &undo, need_redo, CT_FALSE);
    log_atomic_op_end(session);
    cm_pop(session->stack);

    knl_panic_log(!row->is_deleted, "row is deleted, panic info: page %u-%u type %u table %s",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type,
                  ((table_t *)cursor->table)->desc.name);
    row->is_deleted = 1;
    row->is_changed = 1;
    page->rows--;

    if (row->is_link) {
        page->free_size += HEAP_MIN_ROW_SIZE;
        knl_panic_log(row->is_migr == 0, "row is migr, panic info: page %u-%u type %u table %s",
                      AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type,
                      ((table_t *)cursor->table)->desc.name);
    } else {
        page->free_size += row->size;
    }

    buf_leave_temp_page_nolock(session, CT_TRUE);

    if (cursor->link_rid.vmid != CT_INVALID_ID32) {
        if (buf_enter_temp_page_nolock(session, (uint32)cursor->link_rid.vmid) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("Fail to open link_rid vm page (%u) in heap delete.", cursor->link_rid.vmid);
            return CT_ERROR;
        }
        vm_page = buf_curr_temp_page(session);
        page = (temp_heap_page_t *)vm_page->data;
        knl_panic_log(page->head.type == PAGE_TYPE_TEMP_HEAP,
                      "page type is abnormal, panic info: page %u-%u type %u table %s", AS_PAGID(page->head.id).file,
                      AS_PAGID(page->head.id).page, page->head.type, ((table_t *)cursor->table)->desc.name);
        dir = temp_heap_get_dir(page, (uint32)cursor->link_rid.vm_slot);
        row = TEMP_HEAP_GET_ROW(page, dir);
        knl_panic_log(!row->is_deleted, "row is deleted, panic info: page %u-%u type %u table %s",
                      AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type,
                      ((table_t *)cursor->table)->desc.name);
        row->is_deleted = 1;
        row->is_changed = 1;
        page->free_size += row->size;
        page->rows--;
        buf_leave_temp_page_nolock(session, CT_TRUE);
    }

    CURSOR_TEMP_CACHE(cursor)->rows--;
    return CT_SUCCESS;
}

void temp_heap_undo_delete(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot)
{
    temp_heap_page_t *page = NULL;
    temp_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    rowid_t rid = ud_row->rowid;
    rowid_t link_rid;
    errno_t ret;

    if (DB_IS_BG_ROLLBACK_SE(session)) {
        return;
    }

    temp_heap_extra_undo_t *extra_undo =
        (temp_heap_extra_undo_t *)(ud_row->data + ud_row->data_size - sizeof(temp_heap_extra_undo_t));
    knl_temp_cache_t *knl_temp_cache = knl_get_temp_cache(session, extra_undo->uid, extra_undo->table_id);

    if (knl_temp_cache == NULL || knl_temp_cache->seg_scn != extra_undo->seg_scn) {
        return;
    }

    link_rid.vmid = CT_INVALID_ID32;

    if (temp_undo_enter_page(session, (uint32)rid.vmid) != CT_SUCCESS) {
        knl_panic_log(0, "temp heap undo delete enter vmid %u failed.", (uint32)rid.vmid);
        return;
    }
    page = TEMP_HEAP_CURR_PAGE(session);
    knl_panic_log(page->head.type == PAGE_TYPE_TEMP_HEAP, "page type is abnormal, panic info: page %u-%u type %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
    dir = temp_heap_get_dir(page, (uint32)rid.vm_slot);
    knl_panic_log(IS_SAME_PAGID(dir->undo_page, AS_PAGID(ud_page->head.id)),
                  "dir's undo_page and ud_page are not same, panic info: page %u-%u type %u, ud_page %u-%u type %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type,
                  AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type);
    knl_panic_log(dir->undo_slot == ud_slot,
        "dir's undo_slot is not equal to ud_slot, panic info: page %u-%u type %u dir undo_slot %u ud_slot %u",
        AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, dir->undo_slot, ud_slot);
    row = TEMP_HEAP_GET_ROW(page, dir);
    knl_panic_log(ROW_ITL_ID(row) == CT_INVALID_ID8, "row itl is valid, panic info: page %u-%u type %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
    knl_panic_log(row->is_deleted == 1, "row is not deleted, panic info: page %u-%u type %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);

    dir->is_owscn = 0;
    dir->undo_page = ud_row->prev_page;
    dir->undo_slot = ud_row->prev_slot;
    dir->scn = ud_row->scn;
    row->is_deleted = 0;
    page->rows++;

    if (row->is_link) {
        ret = memcpy_sp(&link_rid, sizeof(rowid_t), (char *)row + sizeof(row_head_t), sizeof(rowid_t));
        knl_securec_check(ret);
        page->free_size -= HEAP_MIN_ROW_SIZE;
    } else {
        page->free_size -= row->size;
    }

    buf_leave_temp_page_nolock(session, CT_TRUE);

    if (link_rid.vmid != CT_INVALID_ID32) {
        if (temp_undo_enter_page(session, (uint32)link_rid.vmid) != CT_SUCCESS) {
            knl_panic_log(0, "temp heap undo delete enter link vmid %u failed.", (uint32)link_rid.vmid);
            return;
        }
        page = TEMP_HEAP_CURR_PAGE(session);
        knl_panic_log(page->head.type == PAGE_TYPE_TEMP_HEAP, "page type is abnormal, panic info: page %u-%u type %u",
                      AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
        dir = temp_heap_get_dir(page, (uint32)link_rid.vm_slot);
        row = TEMP_HEAP_GET_ROW(page, dir);
        row->is_deleted = 0;
        page->rows++;
        page->free_size -= row->size;
        buf_leave_temp_page_nolock(session, CT_TRUE);
    }

    knl_temp_cache->rows++;
}

static void temp_heap_insert_into_page_migr(knl_session_t *session, temp_heap_page_t *page, row_head_t *row,
                                            uint16 *slot)
{
    temp_row_dir_t *dir = NULL;
    char *row_addr = NULL;
    errno_t ret;

    *slot = page->dirs;
    page->dirs++;
    dir = temp_heap_get_dir(page, *slot);
    page->free_end -= sizeof(temp_row_dir_t);
    page->free_size -= sizeof(temp_row_dir_t);

    dir->scn = 0;
    dir->is_owscn = 0;
    dir->undo_page = INVALID_UNDO_PAGID;
    dir->undo_slot = INVALID_SLOT;

    dir->offset = page->free_begin;
    page->free_begin += row->size;
    page->free_size -= row->size;

    row->is_migr = 1;
    ROW_SET_ITL_ID(row, CT_INVALID_ID8);

    row_addr = (char *)page + dir->offset;
    ret = memcpy_sp(row_addr, page->free_size, row, row->size);
    knl_securec_check(ret);
    page->rows++;
    knl_panic_log(page->free_begin <= page->free_end,
                  "page's free size begin is more than end, panic info: page %u-%u type %u free_begin %u free_end %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, page->free_begin,
                  page->free_end);
}

void temp_heap_reorganize_with_update(row_head_t *row, uint16 *offsets, uint16 *lens, knl_update_info_t *info,
                                      row_assist_t *new_ra)
{
    uint32 i, uid;
    uint8 bits;

    uid = 0;
    for (i = 0; i < ROW_COLUMN_COUNT(new_ra->head); i++) {
        if (uid < info->count && i == info->columns[uid]) {
            bits = row_get_column_bits2((row_head_t *)info->data, uid);
            row_put_column_data(new_ra, bits, info->data + info->offsets[uid], info->lens[uid]);
            uid++;
        } else if (i < ROW_COLUMN_COUNT(row)) {
            bits = row_get_column_bits2(row, i);
            row_put_column_data(new_ra, bits, (char *)row + offsets[i], lens[i]);
        } else {
            row_put_null(new_ra);
        }
    }
}

static status_t temp_heap_update_migr(knl_session_t *session, knl_cursor_t *cursor, heap_update_assist_t *ua,
                                      undo_data_t *undo)
{
    vm_page_t *owner_vm_page = NULL;
    vm_page_t *migr_vm_page = NULL;
    vm_page_t *old_migr_vm_page = NULL;
    temp_heap_page_t *owner_page = NULL;
    temp_heap_page_t *migr_page = NULL;
    temp_heap_page_t *old_migr_page = NULL;
    temp_row_dir_t *owner_dir = NULL;
    temp_row_dir_t *old_migr_dir = NULL;
    row_head_t *owner_row = NULL;
    row_head_t *old_migr_row = NULL;
    rowid_t old_link_rid;
    uint16 cost_size;
    uint16 vm_slot;
    uint32 vmid;
    char *buf = NULL;
    row_assist_t ra;
    errno_t ret;

    old_link_rid = cursor->link_rid;
    knl_panic_log(ua->inc_size > 0, "row increased size is abnormal, panic info: page %u-%u type %u table %s "
                  "inc_size %u", cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, ua->inc_size);

    cost_size = (uint16)(ua->new_size + sizeof(temp_row_dir_t));
    buf = (char *)cm_push(session->stack, ua->new_size);

    temp_heap_init_row(session, &ra, buf, ua->new_cols, 0);
    temp_heap_reorganize_with_update(cursor->row, cursor->offsets, cursor->lens, ua->info, &ra);
    knl_panic_log(ra.head->size == ua->new_size, "ra's size and ua's new_size are not equal, panic info: "
        "page %u-%u type %u table %s ra size %u new_size %u", cursor->rowid.file, cursor->rowid.page,
        ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name, ra.head->size, ua->new_size);

    // update record across page
    if (temp_enter_heap_insert(session, cursor, cost_size, &vmid) != CT_SUCCESS) {
        cm_pop(session->stack);
        return CT_ERROR;
    }

    cursor->link_rid.vmid = vmid;
    migr_vm_page = buf_curr_temp_page(session);
    migr_page = (temp_heap_page_t *)migr_vm_page->data;
    knl_panic_log(migr_page->head.type == PAGE_TYPE_TEMP_HEAP,
                  "migr_page type is abnormal, panic info: migr_page %u-%u type %u",
                  AS_PAGID(migr_page->head.id).file, AS_PAGID(migr_page->head.id).page, migr_page->head.type);
    knl_panic_log(migr_page->free_end - migr_page->free_begin >= cost_size, "migr_page's free size is abnormal, "
                  "panic info: migr_page %u-%u type %u free_end %u free_begin %u cost_size %u",
                  AS_PAGID(migr_page->head.id).file, AS_PAGID(migr_page->head.id).page, migr_page->head.type,
                  migr_page->free_end, migr_page->free_begin, cost_size);

    temp_heap_insert_into_page_migr(session, migr_page, ra.head, &vm_slot);
    cursor->link_rid.vm_slot = vm_slot;

    buf_leave_temp_page_nolock(session, CT_TRUE);

    if (buf_enter_temp_page_nolock(session, (uint32)cursor->rowid.vmid) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to open owner vm page (%u) in heap update migr.", cursor->rowid.vmid);
        cm_pop(session->stack);
        return CT_ERROR;
    }
    owner_vm_page = buf_curr_temp_page(session);
    owner_page = (temp_heap_page_t *)owner_vm_page->data;
    knl_panic_log(owner_page->head.type == PAGE_TYPE_TEMP_HEAP,
                  "owner_page type is abnormal, panic info: owner_page %u-%u type %u",
                  AS_PAGID(owner_page->head.id).file, AS_PAGID(owner_page->head.id).page, owner_page->head.type);
    owner_dir = temp_heap_get_dir(owner_page, (uint32)cursor->rowid.vm_slot);
    owner_row = TEMP_HEAP_GET_ROW(owner_page, owner_dir);
    if (!owner_row->is_link) {
        owner_row->is_link = 1;
        owner_page->free_size += owner_row->size - HEAP_MIN_ROW_SIZE;
    }

    ret = memcpy_sp((char *)owner_row + sizeof(row_head_t), sizeof(rowid_t), &cursor->link_rid, sizeof(rowid_t));
    knl_securec_check(ret);
    buf_leave_temp_page_nolock(session, CT_TRUE);

    if (old_link_rid.vmid != CT_INVALID_ID32) {
        if (buf_enter_temp_page_nolock(session, (uint32)old_link_rid.vmid) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("Fail to open old_link vm page (%d) in heap update migr.", old_link_rid.vmid);
            cm_pop(session->stack);
            return CT_ERROR;
        }
        old_migr_vm_page = buf_curr_temp_page(session);
        old_migr_page = (temp_heap_page_t *)old_migr_vm_page->data;
        knl_panic_log(old_migr_page->head.type == PAGE_TYPE_TEMP_HEAP,
            "old_migr_page type is abnormal, panic info: old_migr_page %u-%u type %u",
            AS_PAGID(old_migr_page->head.id).file, AS_PAGID(old_migr_page->head.id).page, old_migr_page->head.type);

        old_migr_dir = temp_heap_get_dir(old_migr_page, (uint32)old_link_rid.vm_slot);
        old_migr_row = TEMP_HEAP_GET_ROW(old_migr_page, old_migr_dir);
        old_migr_row->is_deleted = 1;
        old_migr_dir->is_free = 1;
        old_migr_page->rows--;
        old_migr_dir->next_slot = old_migr_page->first_free_dir;
        old_migr_page->first_free_dir = (uint16)old_link_rid.vm_slot;
        old_migr_page->free_size += old_migr_row->size;
        buf_leave_temp_page_nolock(session, CT_TRUE);
    }

    cm_pop(session->stack);
    return CT_SUCCESS;
}

static void temp_heap_generate_undo_for_update(knl_session_t *session, knl_cursor_t *cursor,
    temp_heap_page_t *page, undo_data_t *undo)
{
    temp_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    bool32 need_redo = IS_TEMPTABLE_HAS_REDO(session);
    undo_page_info_t *undo_page_info = UNDO_GET_PAGE_INFO(session, need_redo);

    knl_panic_log(undo->size <= TEMP_CT_MAX_ROW_SIZE, "undo size is more than the max limit, panic info: "
                  "page %u-%u type %u table %s undo size %u", cursor->rowid.file, cursor->rowid.page,
                  ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name, undo->size);
    dir = temp_heap_get_dir(page, (uint32)cursor->rowid.vm_slot);
    row = TEMP_HEAP_GET_ROW(page, dir);

    undo->snapshot.scn = dir->scn;
    undo->snapshot.is_owscn = 0;
    undo->snapshot.undo_page = dir->undo_page;
    undo->snapshot.undo_slot = dir->undo_slot;
    undo->snapshot.is_xfirst = cursor->is_xfirst;

    dir->undo_page = undo_page_info->undo_rid.page_id;
    dir->undo_slot = undo_page_info->undo_rid.slot;
    dir->scn = cursor->ssn;
    dir->is_owscn = 0;
    row->is_changed = 1;

    temp_heap_extra_undo_t *extra_undo =
        (temp_heap_extra_undo_t *)(undo->data + undo->size - sizeof(temp_heap_extra_undo_t));
    extra_undo->uid = CURSOR_TEMP_CACHE(cursor)->user_id;
    extra_undo->table_id = CURSOR_TEMP_CACHE(cursor)->table_id;
    extra_undo->seg_scn = CURSOR_TEMP_CACHE(cursor)->seg_scn;

    log_atomic_op_begin(session);
    undo_write(session, undo, need_redo, CT_FALSE);
    log_atomic_op_end(session);
}

static status_t temp_heap_update_link_row(knl_session_t *session, knl_cursor_t *cursor, heap_update_assist_t *ua,
                                          undo_data_t *undo)
{
    vm_page_t *migr_vm_page = NULL;
    temp_heap_page_t *migr_page = NULL;
    temp_heap_page_t *page = NULL;
    temp_row_dir_t *migr_dir = NULL;
    row_head_t *migr_row = NULL;

    if (buf_enter_temp_page_nolock(session, (uint32)cursor->rowid.vmid) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to open vm page (%u) in heap update link row.", cursor->rowid.vmid);
        return CT_ERROR;
    }
    page = TEMP_HEAP_CURR_PAGE(session);
    knl_panic_log(page->head.type == PAGE_TYPE_TEMP_HEAP,
                  "page type is abnormal, panic info: page %u-%u type %u table %s", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, ((table_t *)cursor->table)->desc.name);
    temp_heap_generate_undo_for_update(session, cursor, page, undo);
    buf_leave_temp_page_nolock(session, CT_TRUE);

    if (buf_enter_temp_page_nolock(session, (uint32)cursor->link_rid.vmid) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to open link_rid vm page (%u) in heap update link row.", cursor->link_rid.vmid);
        return CT_ERROR;
    }
    migr_vm_page = buf_curr_temp_page(session);
    migr_page = (temp_heap_page_t *)migr_vm_page->data;
    migr_dir = temp_heap_get_dir(migr_page, (uint32)cursor->link_rid.vm_slot);
    migr_row = TEMP_HEAP_GET_ROW(migr_page, migr_dir);

    if (ua->mode == UPDATE_INPLACE) {
        heap_update_inplace(session, cursor->offsets, cursor->lens, ua->info, migr_row);
        buf_leave_temp_page_nolock(session, CT_TRUE);
        return CT_SUCCESS;
    }

    ua->inc_size -= (int32)(migr_row->size - cursor->data_size);

    if (ua->inc_size > 0 && ua->new_size > migr_page->free_end - migr_page->free_begin) {
        buf_leave_temp_page_nolock(session, CT_FALSE);
        return temp_heap_update_migr(session, cursor, ua, undo);
    }

    temp_heap_update_inpage(session, cursor->row, cursor->offsets, cursor->lens, ua, migr_page,
                            (uint16)cursor->link_rid.vm_slot);
    buf_leave_temp_page_nolock(session, CT_TRUE);
    return CT_SUCCESS;
}

status_t temp_heap_update(knl_session_t *session, knl_cursor_t *cursor)
{
    heap_update_assist_t ua;
    row_head_t *row = NULL;
    temp_row_dir_t *dir = NULL;
    dc_entity_t *entity = NULL;
    vm_page_t *vm_page = NULL;
    temp_heap_page_t *page = NULL;
    undo_data_t undo = { 0 };
    status_t status;
    errno_t ret;

    knl_panic_log(cursor->is_valid, "current cursor is invalid, panic info: page %u-%u type %u table %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name);

    if (cursor->xid != session->rm->xid.value) {
        cursor->xid = session->rm->xid.value;
    }

    cursor->part_loc.part_no = CT_INVALID_ID32;

    entity = (dc_entity_t *)cursor->dc_entity;

    ua.old_cols = ROW_COLUMN_COUNT(cursor->row);
    ua.new_cols = entity->column_count;
    ROWID_COPY(ua.rowid, cursor->rowid);
    ua.info = &cursor->update_info;
    heap_update_prepare(session, cursor->row, cursor->offsets, cursor->lens, cursor->data_size, &ua);

    if (entity->contain_lob) {
        if (lob_update(session, cursor, &ua) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (ua.new_size > TEMP_CT_MAX_ROW_SIZE) {
        CT_THROW_ERROR(ERR_RECORD_SIZE_OVERFLOW, "update row", ua.new_size, TEMP_CT_MAX_ROW_SIZE);
        return CT_ERROR;
    }

    undo.data = (char *)cm_push(session->stack, TEMP_CT_MAX_ROW_SIZE);
    undo.rowid = cursor->rowid;

    /* record two id in temp undo */
    if (ua.undo_size >= cursor->row->size + 2 * sizeof(uint32)) {
        undo.type = UNDO_TEMP_HEAP_UPDATE_FULL;
        ret = memcpy_sp(undo.data, TEMP_CT_MAX_ROW_SIZE, cursor->row, cursor->row->size);
        knl_securec_check(ret);
        undo.size = cursor->row->size;
    } else {
        undo.type = UNDO_TEMP_HEAP_UPDATE;
        heap_get_update_undo_data(session, &ua, &undo, TEMP_CT_MAX_ROW_SIZE);
    }

    undo.size += sizeof(temp_heap_extra_undo_t);
    if (undo_prepare(session, undo.size, IS_TEMPTABLE_HAS_REDO(session), CT_FALSE) != CT_SUCCESS) {
        cm_pop(session->stack);
        return CT_ERROR;
    }

    session->rm->temp_has_undo = CT_TRUE;

    if (cursor->link_rid.vmid != CT_INVALID_ID32) {
        status = temp_heap_update_link_row(session, cursor, &ua, &undo);
        cm_pop(session->stack);
        return status;
    }

    if (buf_enter_temp_page_nolock(session, (uint32)cursor->rowid.vmid) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to open vm page (%u) in heap update.", cursor->rowid.vmid);
        cm_pop(session->stack);
        return CT_ERROR;
    }
    vm_page = buf_curr_temp_page(session);
    page = (temp_heap_page_t *)vm_page->data;
    knl_panic_log(page->head.type == PAGE_TYPE_TEMP_HEAP, "page type is abnormal, panic info: page %u-%u type %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
    dir = temp_heap_get_dir(page, (uint32)cursor->rowid.vm_slot);
    row = (row_head_t *)TEMP_HEAP_GET_ROW(page, dir);
    knl_panic_log(ROW_ITL_ID(row) == CT_INVALID_ID8, "row's itl is valid, panic info: page %u-%u type %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);

    temp_heap_generate_undo_for_update(session, cursor, page, &undo);

    if (ua.mode == UPDATE_INPLACE) {
        heap_update_inplace(session, cursor->offsets, cursor->lens, ua.info, row);
        buf_leave_temp_page_nolock(session, CT_TRUE);
        cm_pop(session->stack);
        return CT_SUCCESS;
    }

    ua.inc_size -= (int32)(row->size - cursor->data_size);

    if (ua.inc_size > 0 && ua.new_size > page->free_end - page->free_begin) {
        buf_leave_temp_page_nolock(session, CT_FALSE);

        status = temp_heap_update_migr(session, cursor, &ua, &undo);
        cm_pop(session->stack);
        return status;
    }

    temp_heap_update_inpage(session, cursor->row, cursor->offsets, cursor->lens, &ua, page,
                            (uint16)cursor->rowid.vm_slot);
    buf_leave_temp_page_nolock(session, CT_TRUE);

    cm_pop(session->stack);
    return CT_SUCCESS;
}

// there is no LINK_RID in migration row, bypass it for temp table
static inline void temp_cm_decode_row(char *ptr, uint16 *offsets, uint16 *lens, uint16 *size)
{
    row_head_t *row;
    uint16 old_flag;

    row = (row_head_t *)ptr;
    old_flag = row->is_migr;
    row->is_migr = 0;
    cm_decode_row(ptr, offsets, lens, size);
    row->is_migr = old_flag;
}

static void temp_heap_revert_update(knl_session_t *session, undo_row_t *undo_row, row_head_t *row,
                                    uint16 *offsets, uint16 *lens)
{
    row_assist_t new_ra;
    knl_update_info_t info;
    heap_undo_update_info_t *undo_info = NULL;
    uint16 row_size;
    char *buf = NULL;
    errno_t err;

    CM_SAVE_STACK(session->stack);
    CM_PUSH_UPDATE_INFO(session, info);

    buf = (char *)cm_push(session->stack, TEMP_CT_MAX_ROW_SIZE);
    undo_info = (heap_undo_update_info_t *)cm_push(session->stack, TEMP_CT_MAX_ROW_SIZE);

#ifdef LOG_DIAG
    err = memset_sp(buf, TEMP_CT_MAX_ROW_SIZE, 0, TEMP_CT_MAX_ROW_SIZE);
    knl_securec_check(err);
#endif

    err = memcpy_sp(undo_info, TEMP_CT_MAX_ROW_SIZE, undo_row->data, undo_row->data_size);
    knl_securec_check(err);

    row_size = row->size;
    info.count = undo_info->count;

    err = memcpy_sp(info.columns, session->kernel->attr.max_column_count, undo_info->columns,
                    info.count * sizeof(uint16));
    knl_securec_check(err);
    info.data = (char *)undo_info + HEAP_UNDO_UPDATE_INFO_SIZE(info.count);

    temp_cm_decode_row(info.data, info.offsets, info.lens, NULL);
    temp_cm_decode_row((char *)row, offsets, lens, NULL);

    temp_heap_init_row(session, &new_ra, buf, undo_info->old_cols, row->flags);
    temp_heap_reorganize_with_update(row, offsets, lens, &info, &new_ra);
    knl_panic_log(new_ra.head->size <= row_size,
                  "the new_ra's size is more than row_size, panic info: new_ra size %u row_size %u",
                  new_ra.head->size, row_size);
    err = memcpy_sp(row, row_size, new_ra.buf, new_ra.head->size);
    knl_securec_check(err);
    row->size = row_size;

    CM_RESTORE_STACK(session->stack);
}

void temp_heap_undo_link_row(knl_session_t *session, undo_row_t *ud_row, rowid_t *rid, uint16 ud_row_size)
{
    temp_heap_page_t *page = NULL;
    temp_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    knl_update_info_t old_info;
    errno_t ret;

    if (temp_undo_enter_page(session, (uint32)rid->vmid) != CT_SUCCESS) {
        knl_panic_log(0, "temp heap undo link row enter vmid %u failed.", (uint32)rid->vmid);
        return;
    }

    page = TEMP_HEAP_CURR_PAGE(session);
    knl_panic_log(page->head.type == PAGE_TYPE_TEMP_HEAP, "page type is abnormal, panic info: page %u-%u type %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
    dir = temp_heap_get_dir(page, (uint32)rid->vm_slot);
    row = TEMP_HEAP_GET_ROW(page, dir);

    if (ud_row->type == UNDO_TEMP_HEAP_UPDATE_FULL) {
        uint16 row_size = row->size;
        uint16 flags = row->flags;

        if (ud_row_size != 0) {
            ret = memcpy_sp(row, row_size, ud_row->data, (size_t)ud_row_size);
            knl_securec_check(ret);
        }

        knl_panic_log(row->size <= row_size,
            "row size is abnormal, panic info: page %u-%u type %u row's size %u row_size %u",
            AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, row->size, row_size);
        row->flags = flags;
        ROW_SET_ITL_ID(row, CT_INVALID_ID8);
        row->size = row_size;
    } else {
        CM_SAVE_STACK(session->stack);
        CM_PUSH_UPDATE_INFO(session, old_info);
        temp_heap_revert_update(session, ud_row, row, old_info.offsets, old_info.lens);
        CM_RESTORE_STACK(session->stack);
    }

    buf_leave_temp_page_nolock(session, CT_TRUE);
}

void temp_heap_undo_update(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot)
{
    rowid_t rid = ud_row->rowid;
    temp_heap_page_t *page = NULL;
    temp_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    knl_update_info_t old_info;
    rowid_t link_rid;
    errno_t ret;
    uint16 ud_row_size;

    if (DB_IS_BG_ROLLBACK_SE(session)) {
        return;
    }

    temp_heap_extra_undo_t *extra_undo =
        (temp_heap_extra_undo_t *)(ud_row->data + ud_row->data_size - sizeof(temp_heap_extra_undo_t));
    knl_temp_cache_t *knl_temp_cache = knl_get_temp_cache(session, extra_undo->uid, extra_undo->table_id);
    
    ud_row_size = ud_row->data_size - sizeof(temp_heap_extra_undo_t);
    if (knl_temp_cache == NULL || knl_temp_cache->seg_scn != extra_undo->seg_scn) {
        return;
    }

    if (temp_undo_enter_page(session, (uint32)rid.vmid) != CT_SUCCESS) {
        knl_panic_log(0, "temp heap undo update enter vmid %u failed.", (uint32)rid.vmid);
        return;
    }

    page = TEMP_HEAP_CURR_PAGE(session);
    knl_panic_log(page->head.type == PAGE_TYPE_TEMP_HEAP, "page type is abnormal, panic info: page %u-%u type %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
    dir = temp_heap_get_dir(page, (uint32)rid.vm_slot);
    knl_panic_log(IS_SAME_PAGID(dir->undo_page, AS_PAGID(ud_page->head.id)),
                  "dir's undo_page and ud_page are not same, panic info: page %u-%u type %u",
                  AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type);
    knl_panic_log(dir->undo_slot == ud_slot,
        "the undo_slot is abnormal, panic info: page %u-%u type %u dir's undo_slot %u ud_slot %u",
        AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, dir->undo_slot, ud_slot);
    row = TEMP_HEAP_GET_ROW(page, dir);
    knl_panic_log(ROW_ITL_ID(row) == CT_INVALID_ID8, "row's itl is valid, panic info: page %u-%u type %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
    knl_panic_log(!dir->is_free, " the dir is free, panic info: page %u-%u type %u", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type);

    dir->is_owscn = 0;
    dir->undo_page = ud_row->prev_page;
    dir->undo_slot = ud_row->prev_slot;
    dir->scn = ud_row->scn;

    if (row->is_link) {
        ret = memcpy_sp(&link_rid, sizeof(rowid_t), (char *)row + sizeof(row_head_t), sizeof(rowid_t));
        knl_securec_check(ret);
        buf_leave_temp_page_nolock(session, CT_FALSE);
        temp_heap_undo_link_row(session, ud_row, &link_rid, ud_row_size);
        return;
    }

    if (ud_row->type == UNDO_TEMP_HEAP_UPDATE_FULL) {
        uint16 row_size = row->size;
        uint16 flags = row->flags;

        ret = memcpy_sp(row, TEMP_CT_MAX_ROW_SIZE, ud_row->data, ud_row_size);
        knl_securec_check(ret);
        knl_panic_log(row->size <= row_size, "row size is abnormal, panic info: page %u-%u type %u row's size %u "
                      "row_size %u", AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type,
                      row->size, row_size);
        row->flags = flags;
        ROW_SET_ITL_ID(row, CT_INVALID_ID8);
        row->size = row_size;
    } else {
        CM_SAVE_STACK(session->stack);
        CM_PUSH_UPDATE_INFO(session, old_info);
        temp_heap_revert_update(session, ud_row, row, old_info.offsets, old_info.lens);
        CM_RESTORE_STACK(session->stack);
    }

    buf_leave_temp_page_nolock(session, CT_TRUE);
}

void temp_heap_update_inpage(knl_session_t *session, row_head_t *ori_row, uint16 *offsets, uint16 *lens,
                             heap_update_assist_t *ua, temp_heap_page_t *page, uint16 slot)
{
    row_assist_t ra;
    uint16 flags, old_size;
    row_head_t *row = NULL;
    temp_row_dir_t *dir = NULL;

    knl_panic_log(page->head.type == PAGE_TYPE_TEMP_HEAP, "the page type is abnormal, panic info: page %u-%u type %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
    dir = temp_heap_get_dir(page, slot);
    row = TEMP_HEAP_GET_ROW(page, dir);
    flags = row->flags;
    old_size = row->size;
    knl_panic_log(ROW_ITL_ID(row) == CT_INVALID_ID8, "row's itl is valid, panic info: page %u-%u type %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);

    if (ua->inc_size > 0) {
        knl_panic_log(page->free_end - page->free_begin >= ua->new_size, "page's free size is abnormal, panic info: "
            "page %u-%u type %u free_end %u free_begin %u ua's new_size %u", AS_PAGID(page->head.id).file,
            AS_PAGID(page->head.id).page, page->head.type, page->free_end, page->free_begin, ua->new_size);

        dir->offset = page->free_begin;
        page->free_begin += ua->new_size;
        page->free_size -= ua->inc_size;
        knl_panic_log(dir->offset < page->free_begin, "the dir's offset is more than the page's free_begin, "
                      "panic info: page %u-%u type %u dir offset %u free_begin %u", AS_PAGID(page->head.id).file,
                      AS_PAGID(page->head.id).page, page->head.type, dir->offset, page->free_begin);
        knl_panic_log(page->free_begin <= page->free_end, "the page's free size begin is more than end, panic info: "
                      "page %u-%u type %u free_begin %u free_end %u", AS_PAGID(page->head.id).file,
                      AS_PAGID(page->head.id).page, page->head.type, page->free_begin, page->free_end);
        row = TEMP_HEAP_GET_ROW(page, dir);

        temp_heap_init_row(session, &ra, (char *)row, ua->new_cols, flags);
        temp_heap_reorganize_with_update(ori_row, offsets, lens, ua->info, &ra);
        knl_panic_log(ra.head->size > old_size, "current row_size is bigger than old_size when row increased size is "
            "bigger than 0, panic info: page %u-%u type %u r's size %u old_size %u",
            AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, ra.head->size, old_size);
    } else {
        temp_heap_init_row(session, &ra, (char *)row, ua->new_cols, flags);
        temp_heap_reorganize_with_update(ori_row, offsets, lens, ua->info, &ra);
        knl_panic_log(ra.head->size <= old_size, "current row_size is bigger than old_size when row increased size "
            "is not bigger than 0, panic info: page %u-%u type %u ra's size %u old_size %u",
            AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, ra.head->size, old_size);
        row->size = old_size;
        knl_panic_log(dir->offset < page->free_begin, "the dir's offset is more than the page's free_begin, "
                      "panic info: page %u-%u type %u dir offset %u free_begin %u", AS_PAGID(page->head.id).file,
                      AS_PAGID(page->head.id).page, page->head.type, dir->offset, page->free_begin);
        knl_panic_log(page->free_begin <= page->free_end, "the page's free size begin is more than end, panic info: "
                      "page %u-%u type %u free_begin %u free_end %u", AS_PAGID(page->head.id).file,
                      AS_PAGID(page->head.id).page, page->head.type, page->free_begin, page->free_end);
    }
}

void temp_set_compative_config(bool8 is_compative_mysql)
{
    g_temp_tablename_compative_mysql = is_compative_mysql;
}

bool8 temp_is_compative_mysql(void)
{
    return g_temp_tablename_compative_mysql;
}

#ifdef __cplusplus
}
#endif
