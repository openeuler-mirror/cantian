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
 * knl_temp_space.c
 *
 *
 * IDENTIFICATION
 * src/kernel/tablespace/knl_temp_space.c
 *
 * -------------------------------------------------------------------------
 */

#include "knl_temp_space.h"
#include "knl_context.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline void spc_alloc_datafile_temp_extent(knl_session_t *session, space_t *space, uint32 id,
    page_id_t *extent, uint32 extent_size)
{
    knl_panic_log(IS_SWAP_SPACE(space), "space is not swap, panic info: page %u-%u", extent->file, extent->page);

    extent->page = SPACE_HEAD_RESIDENT(session, space)->hwms[id];
    extent->file = space->ctrl->files[id];
    space->head->hwms[id] += extent_size;  // the maximum page hwm of a datafile is 2^30
}

static status_t spc_extend_temp_extent(knl_session_t *session, space_t *space, page_id_t *extent)
{
    knl_panic_log(IS_SWAP_SPACE(space), "space is not swap, panic info: page %u-%u", extent->file, extent->page);
    datafile_t *df = NULL;
    int32 *handle = NULL;
    int64 size, extent_size, unused_size;
    uint32 file_no, id, hwm;

    size = 0;
    file_no = GS_INVALID_ID32;
    extent_size = (int64)space->ctrl->extent_size * DEFAULT_PAGE_SIZE(session);

    for (id = 0; id < space->ctrl->file_hwm; id++) {
        if (GS_INVALID_ID32 == space->ctrl->files[id]) {
            continue;
        }

        df = DATAFILE_GET(session, space->ctrl->files[id]);
        hwm = SPACE_HEAD_RESIDENT(session, space)->hwms[id];
        unused_size = df->ctrl->size - (int64)hwm * DEFAULT_PAGE_SIZE(session);
        if (unused_size < extent_size) {
            if (DATAFILE_IS_AUTO_EXTEND(df) && (df->ctrl->size < size || size == 0)) {
                /* extend one extent at least */
                if (df->ctrl->size + extent_size - unused_size > df->ctrl->auto_extend_maxsize) {
                    continue;
                }

                file_no = id;
                size = df->ctrl->size;
            }
            continue;
        }

        if (hwm + space->ctrl->extent_size > MAX_FILE_PAGES(space->ctrl->type)) {
            continue;
        }

        buf_enter_temp_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
        spc_alloc_datafile_temp_extent(session, space, id, extent, space->ctrl->extent_size);
        buf_leave_temp_page(session);
        return GS_SUCCESS;
    }

    if (GS_INVALID_ID32 == file_no) {
        GS_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
        return GS_ERROR;
    }

    hwm = SPACE_HEAD_RESIDENT(session, space)->hwms[file_no];
    if (hwm + space->ctrl->extent_size > MAX_FILE_PAGES(space->ctrl->type)) {
        GS_THROW_ERROR(ERR_MAX_DATAFILE_PAGES, hwm, MAX_FILE_PAGES(space->ctrl->type), space->ctrl->name);
        return GS_ERROR;
    }

    df = DATAFILE_GET(session, space->ctrl->files[file_no]);
    handle = DATAFILE_FD(session, space->ctrl->files[file_no]);
    unused_size = df->ctrl->size - (int64)hwm * DEFAULT_PAGE_SIZE(session);
    if (df->ctrl->size + df->ctrl->auto_extend_size > df->ctrl->auto_extend_maxsize) {
        size = df->ctrl->auto_extend_maxsize - df->ctrl->size;
    } else {
        size = df->ctrl->auto_extend_size;
    }

    if (size + unused_size < extent_size) {
        size = extent_size - unused_size;
    }

    if (GS_SUCCESS != spc_extend_datafile(session, df, handle, size, GS_FALSE)) {
        return GS_ERROR;
    }

    buf_enter_temp_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    spc_alloc_datafile_temp_extent(session, space, file_no, extent, space->ctrl->extent_size);
    buf_leave_temp_page(session);

    return GS_SUCCESS;
}

static status_t spc_load_temp_page_header(knl_session_t *session, page_id_t page_id, page_head_t *page)
{
    datafile_t *df = NULL;
    int32 *handle = NULL;
    int64 offset;

    if (IS_INVALID_PAGID(page_id)) {
        GS_LOG_RUN_ERR("invalid page id in getting temp page cache");
        knl_panic_log(0, "panic info: page %u-%u type %u", page_id.file, page_id.page, page->type);
    }

    df = DATAFILE_GET(session, page_id.file);
    handle = DATAFILE_FD(session, page_id.file);
    offset = (int64)page_id.page * DEFAULT_PAGE_SIZE(session);  // the maximum offset is 2^30 * 2^13
    if (spc_read_datafile(session, df, handle, offset, page, DEFAULT_PAGE_SIZE(session)) != GS_SUCCESS) {
        spc_close_datafile(df, handle);
        GS_LOG_RUN_ERR("[BUFFER] failed to open datafile %s", df->ctrl->name);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

page_id_t spc_get_next_temp_ext(knl_session_t *session, page_id_t extent_input)
{
    page_id_t extent = extent_input;
    char *alloc_buffer = (char *)cm_push(session->stack, (uint32)(DEFAULT_PAGE_SIZE(session) + GS_MAX_ALIGN_SIZE_4K));
    char *buffer = (char *)cm_aligned_buf(alloc_buffer);
    page_head_t *last_page;

    last_page = (page_head_t *)buffer;
    if (GS_SUCCESS != spc_load_temp_page_header(session, extent, last_page)) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to load temparory page %u-%u", extent.file, extent.page);
    }
    extent = AS_PAGID(last_page->next_ext);

    knl_panic_log(!IS_INVALID_PAGID(extent), "get next temp extent error, page id %u-%u.",
        extent.file, extent.page);
    knl_panic_log(IS_SWAP_SPACE(SPACE_GET(session, DATAFILE_GET(session, extent.file)->space_id)),
        "get next temp extent error, page id %u-%u.", extent.file, extent.page);

    cm_pop(session->stack);
    return extent;
}

static void spc_alloc_free_temp_extent(knl_session_t *session, space_t *space, page_id_t *extent)
{
    buf_enter_temp_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    *extent = space->head->free_extents.first;
    space->head->free_extents.count--;
    
    knl_panic_log(!IS_INVALID_PAGID(*extent), "extent is invalid page, panic info: page %u-%u", extent->file,
                  extent->page);
    
    if (space->head->free_extents.count == 0) {
        space->head->free_extents.first = INVALID_PAGID;
        space->head->free_extents.last = INVALID_PAGID;
    } else {
        page_id_t next_ext = spc_get_next_temp_ext(session, *extent);
        knl_panic_log(!IS_INVALID_PAGID(next_ext), "next extent is invalid page, panic info: next extent %u-%u",
                      next_ext.file, next_ext.page);
        space->head->free_extents.first = next_ext;
        knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.first),
                      "the first of free_extents is invalid page, panic info: first page of extents %u-%u",
                      space->head->free_extents.first.file, space->head->free_extents.first.page);
    }

    buf_leave_temp_page(session);
}

status_t spc_alloc_swap_extent_normal(knl_session_t *session, space_t *space, page_id_t *extent)
{
    knl_panic_log(IS_SWAP_SPACE(space), "[SPACE] space %u is not swap space, type is %u.",
        space->ctrl->id, space->ctrl->type);
    CM_POINTER3(session, space, extent);

    cm_spin_lock(&space->lock.lock, &session->stat->spin_stat.stat_space);
    for (;;) {
        if (space->head->free_extents.count == 0) {
            if (GS_SUCCESS != spc_extend_temp_extent(session, space, extent)) {
                cm_spin_unlock(&space->lock.lock);
                return GS_ERROR;
            }
            cm_spin_unlock(&space->lock.lock);
            return GS_SUCCESS;
        }

        spc_alloc_free_temp_extent(session, space, extent);
        if (extent->page >= space->head->hwms[DATAFILE_GET(session, extent->file)->file_no]) {
            GS_LOG_RUN_INF("ignore invalid extent(%u-%d), space %s, file no %u",
                           extent->file, extent->page, space->ctrl->name, DATAFILE_GET(session, extent->file)->file_no);
            continue;
        }
        break;
    }

    cm_spin_unlock(&space->lock.lock);
    return GS_SUCCESS;
}

static void spc_try_update_swap_hwm(knl_session_t *session, space_t *space, uint32 file_no, uint32 hwm)
{
    /* update file hwm in space head */
    buf_enter_temp_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    if (hwm > space->head->hwms[file_no]) {
        space->head->hwms[file_no] = hwm;
    }
    buf_leave_temp_page(session);
}

status_t spc_alloc_swap_map_extent(knl_session_t *session, space_t *space, uint32 extent_size, page_id_t *extent)
{
    datafile_t *df = NULL;
    uint32 id;

    for (id = 0; id < space->ctrl->file_hwm; id++) {
        if (space->ctrl->files[id] == GS_INVALID_ID32) {
            continue;
        }

        df = DATAFILE_GET(session, space->ctrl->files[id]);
        if (!DATAFILE_IS_ONLINE(df)) {
            continue;
        }

        if (df_alloc_swap_map_extent(session, df, extent) != GS_SUCCESS) {
            continue;
        }

        spc_try_update_swap_hwm(session, space, id, extent->page + extent_size);

        return GS_SUCCESS;
    }
    // caller will print error log
    return GS_ERROR;
}

status_t spc_extend_swap_datafile_map(knl_session_t *session, space_t *space, uint32 extent_size, page_id_t *extent)
{
    datafile_t *df = NULL;
    int64 size;
    uint32 file_no = GS_INVALID_ID32;
    page_id_t page_id;
    bool32 new_group = GS_FALSE;

    for (;;) {
        if (spc_find_extend_file(session, space, extent_size, &file_no, GS_FALSE) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
            return GS_ERROR;
        }

        df = DATAFILE_GET(session, space->ctrl->files[file_no]);
        size = spc_get_extend_size(session, df, extent_size, &new_group);
        if (spc_extend_datafile(session, df, DATAFILE_FD(session, df->ctrl->id), size, GS_FALSE) != GS_SUCCESS) {
            // will print log inside
            return GS_ERROR;
        }

        if (new_group) {
            page_id.file = df->ctrl->id;
            page_id.page = space->head->hwms[file_no];
            page_id.aligned = 0;
            df_add_map_group_swap(session, df, page_id, DF_MAP_GROUP_SIZE);
        }

        if (df_alloc_swap_map_extent(session, df, extent) != GS_SUCCESS) {
            continue;
        }

        spc_try_update_swap_hwm(session, space, file_no, extent->page + extent_size);
        return GS_SUCCESS;
    }
}

status_t spc_alloc_swap_extent_map(knl_session_t *session, space_t *space, page_id_t *extent)
{
    knl_panic_log(IS_SWAP_SPACE(space), "[SPACE] space %u is not swap space, type is %u.",
        space->ctrl->id, space->ctrl->type);
    cm_spin_lock(&space->lock.lock, &session->stat->spin_stat.stat_space);

    if (spc_alloc_swap_map_extent(session, space, space->ctrl->extent_size, extent) == GS_SUCCESS) {
        knl_panic_log(!IS_INVALID_PAGID(*extent),
            "alloc bitmap extent (%u-%u) error, page id is invalid.", extent->file, extent->page);
        cm_spin_unlock(&space->lock.lock);
        return GS_SUCCESS;
    }

    if (spc_extend_swap_datafile_map(session, space, space->ctrl->extent_size, extent) != GS_SUCCESS) {
        cm_spin_unlock(&space->lock.lock);
        GS_LOG_RUN_ERR("[SPACE] space %u extend datafile failed, extend size is %u.",
            space->ctrl->id, space->ctrl->extent_size);
        return GS_ERROR;
    }

    knl_panic(!IS_INVALID_PAGID(*extent));
    cm_spin_unlock(&space->lock.lock);
    return GS_SUCCESS;
}

status_t spc_alloc_swap_extent(knl_session_t *session, space_t *space, page_id_t *extent)
{
    if (SECUREC_LIKELY(SPACE_SWAP_BITMAP(space))) {
        return spc_alloc_swap_extent_map(session, space, extent);
    } else {
        return spc_alloc_swap_extent_normal(session, space, extent);
    }
}

static status_t spc_write_temp_page_header(knl_session_t *session, page_id_t page_id, page_head_t *page)
{
    datafile_t *df = NULL;
    int32 *handle = NULL;
    int64 offset;

    if (IS_INVALID_PAGID(page_id)) {
        GS_LOG_RUN_ERR("invalid page id in getting temp page cache");
        knl_panic_log(0, "panic info: page %u-%u type %u", page_id.file, page_id.page, page->type);
    }

    df = DATAFILE_GET(session, page_id.file);
    handle = DATAFILE_FD(session, page_id.file);
    offset = (int64)page_id.page * DEFAULT_PAGE_SIZE(session);  // the maximum offset is 2^30 * 2^13
    if (spc_write_datafile(session, df, handle, offset, page, (int32)DEFAULT_PAGE_SIZE(session)) != GS_SUCCESS) {
        spc_close_datafile(df, handle);
        GS_LOG_RUN_ERR("[BUFFER] failed to write datafile %s", df->ctrl->name);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

void spc_concat_temp_extent(knl_session_t *session, page_id_t last_ext, page_id_t ext)
{
    char *alloc_buffer = (char *)cm_push(session->stack, (uint32)(DEFAULT_PAGE_SIZE(session) + GS_MAX_ALIGN_SIZE_4K));
    char *buffer = (char *)cm_aligned_buf(alloc_buffer);
    page_head_t *head;

    head = (page_head_t *)buffer;
    if (GS_SUCCESS != spc_load_temp_page_header(session, last_ext, head)) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to load temporary page %u-%u", last_ext.file, last_ext.page);
    }

    TO_PAGID_DATA(ext, head->next_ext);

    if (GS_SUCCESS != spc_write_temp_page_header(session, last_ext, head)) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to write temporary page %u-%u", last_ext.file, last_ext.page);
    }

    cm_pop(session->stack);
}

void spc_free_temp_extent_normal(knl_session_t *session, space_t *space, page_id_t extent)
{
    knl_panic_log(IS_SWAP_SPACE(space), "space is not swap, panic info: page %u-%u", extent.file, extent.page);
    CM_POINTER2(session, space);

    knl_panic_log(!IS_INVALID_PAGID(extent), "current extent is invalid, panic info: extent page %u-%u", extent.file,
                  extent.page);

    cm_spin_lock(&space->lock.lock, &session->stat->spin_stat.stat_space);

    buf_enter_temp_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    if (space->head->free_extents.count == 0) {
        space->head->free_extents.first = extent;
        space->head->free_extents.last = extent;
    } else {
        knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.first),
                      "the first of free_extents is invalid, panic info: first page of extents %u-%u",
                      space->head->free_extents.first.file, space->head->free_extents.first.page);
        knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.last),
                      "the last of free_extents is invalid, panic info: last page of extents %u-%u",
                      space->head->free_extents.last.file, space->head->free_extents.last.page);
        spc_concat_temp_extent(session, space->head->free_extents.last, extent);
        space->head->free_extents.last = extent;
    }
    space->head->free_extents.count++;
    buf_leave_temp_page(session);
    cm_spin_unlock(&space->lock.lock);
}

void spc_free_temp_extent_map(knl_session_t *session, space_t *space, page_id_t extent)
{
    knl_panic_log(IS_SWAP_SPACE(space), "[SPACE] space %u is not swap space, type is %u.",
        space->ctrl->id, space->ctrl->type);
    CM_POINTER2(session, space);
    knl_panic_log(!IS_INVALID_PAGID(extent),
        "alloc bitmap extent (%u-%u) error, page id is invalid.", extent.file, extent.page);

    cm_spin_lock(&space->lock.lock, &session->stat->spin_stat.stat_space);
    df_free_swap_map_extent(session, DATAFILE_GET(session, extent.file), extent);
    cm_spin_unlock(&space->lock.lock);
}

void spc_free_temp_extent(knl_session_t *session, space_t *space, page_id_t extent)
{
    if (SECUREC_LIKELY(SPACE_SWAP_BITMAP(space))) {
        spc_free_temp_extent_map(session, space, extent);
    } else {
        spc_free_temp_extent_normal(session, space, extent);
    }
}

page_id_t spc_try_get_next_temp_ext(knl_session_t *session, page_id_t extent)
{
    datafile_t *df = NULL;
    space_t *space = NULL;

    if (IS_INVALID_PAGID(extent)) {
        return g_invalid_pagid;
    }

    df = DATAFILE_GET(session, extent.file);
    space = SPACE_GET(session, df->space_id);
    if (!IS_SWAP_SPACE(space) || !df->ctrl->used || !DATAFILE_IS_ONLINE(df)) {
        return g_invalid_pagid;
    }

    return spc_get_next_temp_ext(session, extent);
}

space_t *spc_get_temp_undo(knl_session_t *session)
{
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(session);

    if (core_ctrl->temp_undo_space == 0) {
        return NULL;
    }

    return SPACE_GET(session, core_ctrl->temp_undo_space);
}

#ifdef __cplusplus
}
#endif

