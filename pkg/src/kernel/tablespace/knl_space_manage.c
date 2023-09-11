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
 * knl_space_manage.c
 *
 *
 * IDENTIFICATION
 * src/kernel/tablespace/knl_space_manage.c
 *
 * -------------------------------------------------------------------------
 */

#include "knl_space_manage.h"
#include "knl_context.h"
#include "dtc_dls.h"

#ifdef __cplusplus
extern "C" {
#endif

void spc_alloc_datafile_hwm_extent(knl_session_t *session, space_t *space,
    uint32 id, page_id_t *extent, uint32 extent_size)
{
    rd_update_hwm_t *redo = NULL;
    bool32 need_redo = SPACE_IS_LOGGING(space);

    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);

    extent->page = space->head->hwms[id];
    extent->file = space->ctrl->files[id];
    extent->aligned = 0;
    space->head->hwms[id] += extent_size;  // the max page high water mark of a datafile is 2^30

    redo = (rd_update_hwm_t *)cm_push(session->stack, sizeof(rd_update_hwm_t));
    knl_panic(redo != NULL);
    redo->file_no = id;
    redo->file_hwm = space->head->hwms[id];

    if (need_redo) {
        log_put(session, RD_SPC_UPDATE_HWM, redo, sizeof(rd_update_hwm_t), LOG_ENTRY_FLAG_NONE);
    }

    cm_pop(session->stack);

    buf_leave_page(session, GS_TRUE);
}

/*
 * update file hwm on space head if needed after alloc extent from map
 */
static void spc_try_update_hwm(knl_session_t *session, space_t *space, uint32 file_no, uint32 hwm)
{
    rd_update_hwm_t redo;

    /* update file hwm in space head */
    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    if (hwm > space->head->hwms[file_no]) {
        space->head->hwms[file_no] = hwm;
        redo.file_no = file_no;
        redo.file_hwm = space->head->hwms[file_no];
        log_put(session, RD_SPC_UPDATE_HWM, &redo, sizeof(rd_update_hwm_t), LOG_ENTRY_FLAG_NONE);
        buf_leave_page(session, GS_TRUE);
    } else {
        buf_leave_page(session, GS_FALSE);
    }
}

/**
 * atomic operation and space lock need to be done
 *  ->atomic_op
 *  ---> space->lock
 **/
void spc_do_free_extent_list(knl_session_t *session, space_t *space)
{
    page_id_t page_id = SPACE_HEAD_RESIDENT(session, space)->free_extents.first;
    df_free_extent(session, DATAFILE_GET(session, page_id.file), page_id);

    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    space->head->free_extents.count--;

    if (space->head->free_extents.count == 0) {
        space->head->free_extents.first = INVALID_PAGID;
        space->head->free_extents.last = INVALID_PAGID;
    } else {
        space->head->free_extents.first = spc_get_next_ext(session, page_id);
    }

    log_put(session, RD_SPC_ALLOC_EXTENT, &space->head->free_extents, sizeof(page_list_t), LOG_ENTRY_FLAG_NONE);
    buf_leave_page(session, GS_TRUE);
}

// the function need to be done under SPACE -> LOCK
bool32 spc_try_free_extent_list(knl_session_t *session, space_t *space)
{
    log_atomic_op_begin(session);

    if (SPACE_HEAD_RESIDENT(session, space)->free_extents.count == 0) {
        dls_spin_unlock(session, &space->lock);
        log_atomic_op_end(session);
        return GS_FALSE;
    }

    spc_do_free_extent_list(session, space);

    log_atomic_op_end(session);
    return GS_TRUE;
}

/*
 * space auto purge
 * Check recycle bin to see if there are any objects that we can purge using current scn.
 * If object founded, we should release space spin lock we hold and end the atomic process
 * so that we can start an autonomous session to purge the object we found.
 * @param kernel session, space
 */
static bool32 spc_auto_purge(knl_session_t *session, space_t *space)
{
    knl_rb_desc_t desc;
    bool32 found = GS_FALSE;
    int32 code;
    const char *msg = NULL;
    bool32 is_free = GS_FALSE;

    if (!SPACE_IS_AUTOPURGE(space) || DB_IN_BG_ROLLBACK(session)) {
        return GS_FALSE;
    }

    knl_panic(!DB_IS_CLUSTER(session));

    if (rb_purge_fetch_space(session, space->ctrl->id, &desc, &found) != GS_SUCCESS) {
        cm_get_error(&code, &msg, NULL);
        GS_LOG_RUN_ERR("[SPACE] failed to fetch space autopurge: CT-%05d: %s", code, msg);
        cm_reset_error();
        return GS_FALSE;
    }

    if (found) {
        space->purging = GS_TRUE;
        dls_spin_unlock(session, &space->lock);

        log_atomic_op_end(session);

        if (rb_purge(session, &desc) != GS_SUCCESS) {
            code = cm_get_error_code();
            if (code != ERR_RECYCLE_OBJ_NOT_EXIST && code != ERR_RESOURCE_BUSY && code != ERR_DC_INVALIDATED) {
                GS_LOG_RUN_ERR("[SPACE] failed to purge space autopurge: CT-%05d: %s", code, msg);
            }
            cm_reset_error();
        }

        log_atomic_op_begin(session);

        dls_spin_lock(session, &space->lock, &session->stat->spin_stat.stat_space);
        space->purging = GS_FALSE;
        GS_LOG_RUN_INF("[SPACE] auto purge space %s", space->ctrl->name);
        return GS_TRUE;
    } else {
        if (!SPACE_IS_BITMAPMANAGED(space)) {
            return GS_FALSE;
        }

        if (SPACE_HEAD_RESIDENT(session, space)->free_extents.count == 0) {
            return GS_FALSE;
        }

        log_atomic_op_end(session);
        is_free = spc_try_free_extent_list(session, space);
        log_atomic_op_begin(session);
    }
    return is_free;
}

/*
 * extend datafile and add a new bitmap group if needed
 * 1.extend a extent at least, including bitmap group additional if needed.
 * 2.extend to maxsize if exceed maxsize after extend auto_extend_size.
 * 3.alloc extent maybe failed after extending because of bit aligned.
 */
status_t spc_extend_datafile_map(knl_session_t *session, space_t *space, uint32 extent_size, page_id_t *extent,
    bool32 is_compress)
{
    datafile_t *df = NULL;
    int64 size;
    uint32 file_no = GS_INVALID_ID32;
    page_id_t page_id;
    bool32 new_group;

    for (;;) {
        if (spc_find_extend_file(session, space, extent_size, &file_no, is_compress) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
            return GS_ERROR;
        }

        df = DATAFILE_GET(session, space->ctrl->files[file_no]);
        size = spc_get_extend_size(session, df, extent_size, &new_group);
        if (spc_extend_datafile(session, df, DATAFILE_FD(session, df->ctrl->id), size, GS_TRUE) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (new_group) {
            page_id.file = df->ctrl->id;
            page_id.page = space->head->hwms[file_no];
            page_id.aligned = 0;
            df_add_map_group(session, df, page_id, DF_MAP_GROUP_SIZE);
        }

        if (df_alloc_extent(session, df, extent_size, extent) != GS_SUCCESS) {
            continue;
        }

        spc_try_update_hwm(session, space, file_no, extent->page + extent_size);
        return GS_SUCCESS;
    }
}

/*
 * search bitmap of datafile one by one for extent
 */
status_t spc_alloc_datafile_map_extent(knl_session_t *session, space_t *space, uint32 extent_size, page_id_t *extent,
    bool32 is_compress)
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

        if (!is_compress != !DATAFILE_IS_COMPRESS(df)) {
            continue;
        }

        if (df_alloc_extent(session, df, extent_size, extent) != GS_SUCCESS) {
            continue;
        }

        spc_try_update_hwm(session, space, id, extent->page + extent_size);
        return GS_SUCCESS;
    }
    return GS_ERROR;
}

/*
 * strategy to allocate extent in space with map:
 * 1.alloc extent from datafile bitmap.
 * 2.try free extent list to bitmap pages and re-allocate from bitmap
 * 3.try recycle space object from recycle bin and re-allocate from bitmap.
 * 4.try extend space datafile when auto-extend is allowed and allocate from bitmap.
 * after purging recyclebin, we also need to extend datafile because extents may not free to bitmap immediately.
 */
status_t spc_alloc_extent_with_map(knl_session_t *session, space_t *space, uint32 extent_size, page_id_t *extent,
    bool32 is_compress)
{
    dls_spin_lock(session, &space->lock, &session->stat->spin_stat.stat_space);

    for (;;) {
        if (spc_alloc_datafile_map_extent(session, space, extent_size, extent, is_compress) == GS_SUCCESS) {
            dls_spin_unlock(session, &space->lock);
            knl_panic_log(!IS_INVALID_PAGID(*extent), "alloce bitmap extent (%u-%u) assert, "
                "datafile id is out of range.", extent->file, extent->page);
            // page 0 is datafile head, allow can not be 0. verified when alloc success. same as below
            knl_panic_log((extent->page != 0), "alloce bitmap extent (%u-%u) assert, 0 should be datafile head page.",
                extent->file, extent->page);
            return GS_SUCCESS;
        }

        // other sessions come here and find space->purging is true, do not wait for purging completed
        if (space->purging) {
            break;
        }

        if (!spc_auto_purge(session, space)) {
            break;
        }
    }

    if (spc_extend_datafile_map(session, space, extent_size, extent, is_compress) != GS_SUCCESS) {
        dls_spin_unlock(session, &space->lock);
        return GS_ERROR;
    }

    dls_spin_unlock(session, &space->lock);
    knl_panic_log(!IS_INVALID_PAGID(*extent), "alloce bitmap extent (%u-%u) assert, datafile id is out of range.",
        extent->file, extent->page);
    knl_panic_log((extent->page != 0), "alloce bitmap extent (%u-%u) assert, 0 should be datafile head page.",
        extent->file, extent->page);
    return GS_SUCCESS;
}

/*
 * Extend current space we use two strategies to handle this
 * step 1: try to allocate extent from the hwm in any space files.
 * step 2: in the worst case, try to extend file in device level.
 */
static status_t spc_extend_extent(knl_session_t *session, space_t *space, page_id_t *extent)
{
    datafile_t *df = NULL;
    int32 *handle = NULL;
    int64 size, extent_size, unused_size, max_size;
    uint32 file_no, id, hwm;

    size = 0;
    file_no = GS_INVALID_ID32;
    extent_size = (int64)space->ctrl->extent_size * DEFAULT_PAGE_SIZE(session);

    for (id = 0; id < space->ctrl->file_hwm; id++) {
        if (space->ctrl->files[id] == GS_INVALID_ID32) {
            continue;
        }

        df = DATAFILE_GET(session, space->ctrl->files[id]);
        hwm = SPACE_HEAD_RESIDENT(session, space)->hwms[id];

        if (!DATAFILE_IS_ONLINE(df)) {
            continue;
        }

        unused_size = df->ctrl->size - (int64)hwm * DEFAULT_PAGE_SIZE(session);
        if (DB_IS_CLUSTER(session) && unused_size < extent_size) {
            handle = DATAFILE_FD(session, space->ctrl->files[id]);
            /* open file if hendle is -1 which means it's not open */
            if (*handle == -1 && spc_open_datafile(session, df, handle) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[SPACE] failed to open file %s", df->ctrl->name);
                return GS_ERROR;
            }
 
            /* sync file size from device */
            df->ctrl->size = cm_device_size(df->ctrl->type, *handle);
            unused_size = df->ctrl->size - (int64)hwm * DEFAULT_PAGE_SIZE(session);
        }
        if (unused_size < extent_size) {
            if (DATAFILE_IS_AUTO_EXTEND(df) && (df->ctrl->size < size || size == 0)) {
                if (df->ctrl->auto_extend_maxsize == 0 ||
                    df->ctrl->auto_extend_maxsize > (int64)MAX_FILE_PAGES(space->ctrl->type) *
                    DEFAULT_PAGE_SIZE(session)) {
                    max_size = (int64)MAX_FILE_PAGES(space->ctrl->type) * DEFAULT_PAGE_SIZE(session);
                } else {
                    max_size = df->ctrl->auto_extend_maxsize;
                }

                /* guarantee that can alloc an extent at lease after extend */
                if (df->ctrl->size + extent_size - unused_size > max_size) {
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

        spc_alloc_datafile_hwm_extent(session, space, id, extent, space->ctrl->extent_size);

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

    if (spc_extend_datafile(session, df, handle, size, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    spc_alloc_datafile_hwm_extent(session, space, file_no, extent, space->ctrl->extent_size);

    return GS_SUCCESS;
}

static bool32 spc_alloc_hwm_extent(knl_session_t *session, space_t *space, page_id_t *extent)
{
    datafile_t *df = NULL;
    uint32 hwm;
    uint32 id;

    for (id = 0; id < space->ctrl->file_hwm; id++) {
        if (GS_INVALID_ID32 == space->ctrl->files[id]) {
            continue;
        }

        df = DATAFILE_GET(session, space->ctrl->files[id]);
        hwm = SPACE_HEAD_RESIDENT(session, space)->hwms[id];

        if (!DATAFILE_IS_ONLINE(df)) {
            continue;
        }

        if (df->ctrl->size < (int64)(hwm + space->ctrl->extent_size) * space->ctrl->block_size) {
            continue;
        }

        if (hwm + space->ctrl->extent_size > MAX_FILE_PAGES(space->ctrl->type)) {
            continue;
        }

        spc_alloc_datafile_hwm_extent(session, space, id, extent, space->ctrl->extent_size);

        return GS_TRUE;
    }

    return GS_FALSE;
}

/*
 * strategies to allocate extent from space whose extent is managed by hwm and free list:
 *
 * 1.alloc extent from space free extent lists.
 * 2.alloc extent from high water mark.
 * 3.try recycle space object from recycle bin.
 * 4.try extend space datafile when auto-extend is allowed.
 *
 * @note Causing autonomous session maybe called, so do not call
 * this interface when entered some pages or generated redo logs.
 */
status_t spc_alloc_extent_normal(knl_session_t *session, space_t *space, page_id_t *extent)
{
    CM_POINTER3(session, space, extent);

    for (;;) {
        // incase: drop space-> drop table, and table expand when insert concurrently
        if (dls_spin_try_lock(session, &space->lock)) {
            break;
        }

        if (!space->ctrl->used || !SPACE_IS_ONLINE(space)) {
            GS_THROW_ERROR(ERR_OBJECT_ID_NOT_EXIST, "tablespace", space->ctrl->id);
            return GS_ERROR;
        }

        cm_sleep(2);
    }

    for (;;) {
        if (SPACE_HEAD_RESIDENT(session, space)->free_extents.count > 0) {
            spc_alloc_free_extent(session, space, extent);
            if (extent->page >= space->head->hwms[DATAFILE_GET(session, extent->file)->file_no]) {
                GS_LOG_RUN_INF("ignore invalid extent(%u-%d), space %s, file no %u", extent->file,
                               extent->page, space->ctrl->name, DATAFILE_GET(session, extent->file)->file_no);
                continue;
            }
            extent->aligned = 0;
            dls_spin_unlock(session, &space->lock);
            // page 0 is datafile head, allow can not be 0. verified when alloc success. same as below
            knl_panic_log((extent->page != 0), "alloce normal extent (%u-%u) assert, 0 should be datafile head page.",
                extent->file, extent->page);
            return GS_SUCCESS;
        }

        if (spc_alloc_hwm_extent(session, space, extent)) {
            dls_spin_unlock(session, &space->lock);
            knl_panic_log((extent->page != 0), "alloce normal extent (%u-%u) assert, 0 should be datafile head page.",
                extent->file, extent->page);
            return GS_SUCCESS;
        }

        // other sessions come here and find space->purging is true, do not wait for purging completed
        if (space->purging) {
            break;
        }

        if (!spc_auto_purge(session, space)) {
            break;
        }
    }

    if (spc_extend_extent(session, space, extent) != GS_SUCCESS) {
        dls_spin_unlock(session, &space->lock);
        return GS_ERROR;
    }

    dls_spin_unlock(session, &space->lock);
    knl_panic_log((extent->page != 0), "alloce normal extent (%u-%u) assert, 0 should be datafile head page.",
        extent->file, extent->page);
    return GS_SUCCESS;
}

/*
 * we maintain two types tablespace with different extent management method:
 * 1.manage extent with hwm and free list, which only supports uniformed extent size
 * 2.manage extent with datafile bitmap, which can support dynamic extent size
 */
status_t spc_alloc_extent(knl_session_t *session, space_t *space, uint32 extent_size, page_id_t *extent,
    bool32 is_compress)
{
    if (SPACE_IS_BITMAPMANAGED(space)) {
        return spc_alloc_extent_with_map(session, space, extent_size, extent, is_compress);
    } else {
        if (is_compress) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "allocate compress extent from normal tablespace");
        }
        return spc_alloc_extent_normal(session, space, extent);
    }
}

uint32 spc_degrade_extent_size(space_t *space, uint32 size)
{
    // there are 2 Scenarios:
    // 1. bitmap try degrade, should not degrade then init exten_size;
    // 2. normal space, should not try degrade (equals here), return 0, will terminate degrade
    if (space->ctrl->extent_size == size) {
        return 0;
    }

    if (size == EXT_SIZE_8192) {
        return EXT_SIZE_1024;
    } else if (size == EXT_SIZE_1024) {
        return EXT_SIZE_128;
    } else if (size == EXT_SIZE_128) {
        return EXT_SIZE_8;
    }
    return 0;
}

// try to alloc extent with bitmap, if cant, degrade and try again
status_t spc_try_alloc_extent(knl_session_t *session, space_t *space, page_id_t *extent,
    uint32 *extent_size, bool32 *is_degrade, bool32 is_compress)
{
    uint32 size = *extent_size;
    status_t status = GS_ERROR;

    while (size != 0) {
        status = spc_alloc_extent(session, space, size, extent, is_compress);
        if (status == GS_SUCCESS) {
            break;
        }

        if (cm_get_error_code() != ERR_ALLOC_EXTENT) {
            break;
        }

        size = spc_degrade_extent_size(space, size);
        *is_degrade = GS_TRUE;
    }

    if (status == GS_SUCCESS && size != *extent_size) {
        cm_reset_error();
        GS_LOG_DEBUG_INF("alloc extent degrades, expect size: %u, degrade size: %u", *extent_size, size);
    }

    *extent_size = size;
    return status;
}

status_t spc_df_alloc_extent_normal(knl_session_t *session, space_t *space, uint32 extent_size, page_id_t *extent,
    datafile_t *df)
{
    bool32 need_extend = GS_FALSE;
    int64 size, extent_bytes, unused_size, max_size;
    int32 *handle = NULL;
    uint32 hwm;

    extent_bytes = (int64)space->ctrl->extent_size * DEFAULT_PAGE_SIZE(session);

    for (;;) {
        if (need_extend) {
            if (!DATAFILE_IS_AUTO_EXTEND(df)) {
                GS_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
                return GS_ERROR;
            }

            if (df->ctrl->auto_extend_maxsize == 0 ||
                df->ctrl->auto_extend_maxsize > (int64)MAX_FILE_PAGES(space->ctrl->type) * DEFAULT_PAGE_SIZE(session)) {
                max_size = (int64)MAX_FILE_PAGES(space->ctrl->type) * DEFAULT_PAGE_SIZE(session);
            } else {
                max_size = df->ctrl->auto_extend_maxsize;
            }

            unused_size = df->ctrl->size - (int64)hwm * DEFAULT_PAGE_SIZE(session);
            if (df->ctrl->size - unused_size + extent_bytes > max_size) {
                GS_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
                return GS_ERROR;
            }

            if (df->ctrl->size + df->ctrl->auto_extend_size > max_size) {
                size = max_size - df->ctrl->size;
            } else {
                size = df->ctrl->auto_extend_size;
            }

            if (size + unused_size < extent_bytes) {
                size = extent_bytes - unused_size;
            }

            handle = DATAFILE_FD(session, space->ctrl->files[df->file_no]);
            if (spc_extend_datafile(session, df, handle, size, GS_TRUE) != GS_SUCCESS) {
                return GS_ERROR;
            }

            need_extend = GS_FALSE;
        }

        hwm = SPACE_HEAD_RESIDENT(session, space)->hwms[df->file_no];
        if (hwm + space->ctrl->extent_size > MAX_FILE_PAGES(space->ctrl->type)) {
            GS_THROW_ERROR(ERR_MAX_DATAFILE_PAGES, hwm, MAX_FILE_PAGES(space->ctrl->type), space->ctrl->name);
            return GS_ERROR;
        }

        if (df->ctrl->size < (int64)(hwm + space->ctrl->extent_size) * space->ctrl->block_size) {
            need_extend = GS_TRUE;
            continue;
        }

        spc_alloc_datafile_hwm_extent(session, space, df->file_no, extent, extent_size);

        break;
    }

    return GS_SUCCESS;
}

/* This function only used in restrict now!! So we don't consider concurrency here. */
status_t spc_df_alloc_extent(knl_session_t *session, space_t *space, uint32 extent_size, page_id_t *extent,
    datafile_t *df)
{
    if (!DATAFILE_IS_ONLINE(df)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "extend undo segments failed");
        return GS_ERROR;
    }

    if (!DB_IS_RESTRICT(session)) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in restrict mode");
        return GS_ERROR;
    }

    if (SPACE_IS_BITMAPMANAGED(space)) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in normal space");
        return GS_ERROR;
    }

    return spc_df_alloc_extent_normal(session, space, extent_size, extent, df);
}

/*
 * Try to extend undo extent like space extend extent, but without errmsg.
 */
static bool32 spc_extend_undo_extent(knl_session_t *session, space_t *space, uint32 extents, page_id_t *extent)
{
    datafile_t *df = NULL;
    int32 *handle = NULL;
    int64 size, extent_size, unused_size;
    uint32 file_no, id, hwm;

    size = 0;
    file_no = GS_INVALID_ID32;
    extent_size = (int64)extents * DEFAULT_PAGE_SIZE(session);

    for (id = 0; id < space->ctrl->file_hwm; id++) {
        if (GS_INVALID_ID32 == space->ctrl->files[id]) {
            continue;
        }

        df = DATAFILE_GET(session, space->ctrl->files[id]);
        hwm = SPACE_HEAD_RESIDENT(session, space)->hwms[id];

        if (!DATAFILE_IS_ONLINE(df)) {
            continue;
        }

        unused_size = df->ctrl->size - (int64)hwm * DEFAULT_PAGE_SIZE(session);
        if (unused_size  < extent_size) {
            if (DATAFILE_IS_AUTO_EXTEND(df) && (df->ctrl->size < size || size == 0)) {
                /* guarantee that can alloc an extent at lease after extend */
                if (df->ctrl->size + extent_size - unused_size > df->ctrl->auto_extend_maxsize) {
                    continue;
                }
                file_no = id;
                size = df->ctrl->size;
            }
            continue;
        }

        if (hwm + GS_EXTENT_SIZE > MAX_FILE_PAGES(space->ctrl->type)) {
            continue;
        }

        spc_alloc_datafile_hwm_extent(session, space, id, extent, GS_EXTENT_SIZE);

        return GS_TRUE;
    }

    if (GS_INVALID_ID32 == file_no) {
        space->allow_extend = GS_FALSE;
        GS_LOG_RUN_INF("invalid undo file number,disable undo space extend.");
        return GS_FALSE;
    }

    hwm = SPACE_HEAD_RESIDENT(session, space)->hwms[file_no];
    if (hwm + GS_EXTENT_SIZE > MAX_FILE_PAGES(space->ctrl->type)) {
        space->allow_extend = GS_FALSE;
        GS_LOG_RUN_INF("undo file[%u] no free space,disable undo space extend.", file_no);
        return GS_FALSE;
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

    if (spc_extend_datafile(session, df, handle, size, GS_TRUE) != GS_SUCCESS) {
        return GS_FALSE;
    }

    spc_alloc_datafile_hwm_extent(session, space, file_no, extent, GS_EXTENT_SIZE);

    return GS_TRUE;
}

page_id_t spc_get_next_undo_ext_prefetch(knl_session_t *session, page_id_t extent_input)
{
    page_id_t extent = extent_input;
    page_head_t *last_page = NULL;

    buf_enter_prefetch_page_num(session, extent, session->kernel->attr.undo_prefetch_page_num, LATCH_MODE_S,
                                ENTER_PAGE_HIGH_AGE);
    last_page = (page_head_t *)session->curr_page;
    extent = AS_PAGID(last_page->next_ext);
    buf_leave_page(session, GS_FALSE);
    return extent;
}

static void spc_alloc_undo_from_space(knl_session_t *session, space_t *space, page_id_t *extent, bool32 need_redo)
{
    *extent = space->head->free_extents.first;
    space->head->free_extents.count--;
    
    if (space->head->free_extents.count == 0) {
        space->head->free_extents.first = INVALID_PAGID;
        space->head->free_extents.last = INVALID_PAGID;
    } else {
        space->head->free_extents.first = spc_get_next_undo_ext_prefetch(session, *extent);
        knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.first),
                      "the first of free_extents is invalid page, panic info: first page of extents %u-%u",
                      space->head->free_extents.first.file, space->head->free_extents.first.page);
        knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.last),
                      "the last of free_extents is invalid page, panic info: last page of extents %u-%u",
                      space->head->free_extents.last.file, space->head->free_extents.last.page);
    }
    
    if (need_redo) {
        log_put(session, RD_SPC_ALLOC_EXTENT, &space->head->free_extents, sizeof(page_list_t), LOG_ENTRY_FLAG_NONE);
    }

    return;
}

#ifdef DB_DEBUG_VERSION
void spc_validate_extents(knl_session_t *session, page_list_t *extents)
{
    page_id_t page_id;
    uint32 count;

    knl_panic_log(extents->count != 0, "extents's count is zero.");

    count = 0;
    page_id = extents->first;

    while (!IS_INVALID_PAGID(page_id)) {
        count++;

        knl_panic_log(!(page_id.file == 0 && page_id.page == 0), "page_id is abnormal, panic info: page %u-%u",
                      page_id.file, page_id.page);

        if (IS_SAME_PAGID(page_id, extents->last)) {
            break;
        }

        buf_enter_page(session, page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        page_id = AS_PAGID(((page_head_t *)CURR_PAGE(session))->next_ext);
        buf_leave_page(session, GS_FALSE);
    }

    knl_panic_log(count == extents->count, "The current record extents count is not as expected, panic info: "
                  "count %u extents count %u", count, extents->count);
}

void spc_validate_undo_extents(knl_session_t *session, undo_page_list_t *extents)
{
    page_id_t page_id, pageid_last;
    uint32 count;

    knl_panic_log(extents->count != 0, "extents's count is zero.");

    count = 0;
    page_id = PAGID_U2N(extents->first);

    while (!IS_INVALID_PAGID(page_id)) {
        count++;
        knl_panic_log(!(page_id.file == 0 && page_id.page == 0), "page_id is abnormal, panic info: page %u-%u",
                      page_id.file, page_id.page);

        pageid_last = PAGID_U2N(extents->last);
        if (IS_SAME_PAGID(page_id, pageid_last)) {
            break;
        }

        buf_enter_page(session, page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        page_id = AS_PAGID(((page_head_t *)CURR_PAGE(session))->next_ext);
        buf_leave_page(session, GS_FALSE);
    }

    knl_panic_log(count == extents->count, "The current record extents count is not as expected, panic info: "
                  "current count %u extents count %u", count, extents->count);
}
#endif

/*
 * Used for undo alloc pages for txn, pages are linked on space head free extent.
 * When try to extend extent, alloc extent in GS_EXTENT_SIZE steps as normal
 * space without error msg.
 */
bool32 spc_alloc_undo_extent(knl_session_t *session, space_t *space, page_id_t *extent, uint32 *extent_size)
{
    bool32 need_redo = SPACE_IS_LOGGING(space);

    CM_POINTER4(session, space, extent, extent_size);

    // take a quick glance at undo space with optimistic lock.
    if (!space->allow_extend && SPACE_HEAD_RESIDENT(session, space)->free_extents.count == 0) {
        *extent_size = 0;
        return GS_FALSE;
    }

    cm_spin_lock(&space->lock.lock, &session->stat->spin_stat.stat_space);
    if (!space->allow_extend && SPACE_HEAD_RESIDENT(session, space)->free_extents.count == 0) {
        *extent_size = 0;
        cm_spin_unlock(&space->lock.lock);
        return GS_FALSE;
    }

    for (;;) {
        if (SPACE_HEAD_RESIDENT(session, space)->free_extents.count == 0) {
            *extent_size = GS_EXTENT_SIZE;
            bool32 result = spc_extend_undo_extent(session, space, *extent_size, extent);
            cm_spin_unlock(&space->lock.lock);
            return result;
        }

        buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
        spc_alloc_undo_from_space(session, space, extent, need_redo);
        buf_leave_page(session, GS_TRUE);

        if (extent->page >= space->head->hwms[DATAFILE_GET(session, extent->file)->file_no]) {
            GS_LOG_RUN_INF("ignore invalid extent(%u-%d), space %s, file no %u",
                           extent->file, extent->page, space->ctrl->name, DATAFILE_GET(session, extent->file)->file_no);
            continue;
        }
        break;
    }

    *extent_size = space->ctrl->extent_size;
    cm_spin_unlock(&space->lock.lock);

    return GS_TRUE;
}

void spc_free_extent(knl_session_t *session, space_t *space, page_id_t extent)
{
    knl_panic_log(!IS_INVALID_PAGID(extent), "extent is invalid page, panic info: page %u-%u", extent.file,
                  extent.page);
    CM_POINTER2(session, space);

    bool32 need_redo = SPACE_IS_LOGGING(space);

    dls_spin_lock(session, &space->lock, &session->stat->spin_stat.stat_space);

    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);

    if (space->head->free_extents.count == 0) {
        space->head->free_extents.first = extent;
        space->head->free_extents.last = extent;
    } else {
        knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.first),
                      "the first of free_extents is invalid page, panic info: first page of extents %u-%u",
                      space->head->free_extents.first.file, space->head->free_extents.first.page);
        knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.last),
                      "the last of free_extents is invalid page, panic info: last page of extents %u-%u",
                      space->head->free_extents.last.file, space->head->free_extents.last.page);
        spc_concat_extent(session, extent, space->head->free_extents.first);
        space->head->free_extents.first = extent;
    }
    space->head->free_extents.count++;

    if (need_redo) {
        log_put(session, RD_SPC_FREE_EXTENT, &space->head->free_extents, sizeof(page_list_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);

    dls_spin_unlock(session, &space->lock);
}

void spc_free_extents(knl_session_t *session, space_t *space, page_list_t *extents)
{
    bool32 need_redo = SPACE_IS_LOGGING(space);

    knl_panic_log(!IS_INVALID_PAGID(extents->first),
                  "the first of extents is invalid page, panic info: first page of extents %u-%u",
                  space->head->free_extents.first.file, space->head->free_extents.first.page);
    knl_panic_log(!IS_INVALID_PAGID(extents->last),
                  "the last of extents is invalid page, panic info: last page of extents %u-%u",
                  space->head->free_extents.last.file, space->head->free_extents.last.page);
    CM_POINTER3(session, space, extents);

    dls_spin_lock(session, &space->lock, &session->stat->spin_stat.stat_space);

#ifdef DB_DEBUG_VERSION
    spc_validate_extents(session, extents);
#endif

    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);

    if (space->head->free_extents.count == 0) {
        space->head->free_extents = *extents;
    } else {
        knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.first),
                      "the first of free_extents is invalid page, panic info: first page of extents %u-%u",
                      space->head->free_extents.first.file, space->head->free_extents.first.page);
        knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.last),
                      "the last of free_extents is invalid page, panic info: last page of extents %u-%u",
                      space->head->free_extents.last.file, space->head->free_extents.last.page);
        spc_concat_extent(session, extents->last, space->head->free_extents.first);
        space->head->free_extents.first = extents->first;
        space->head->free_extents.count += extents->count;
    }

    if (need_redo) {
        log_put(session, RD_SPC_FREE_EXTENT, &space->head->free_extents, sizeof(page_list_t), LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, GS_TRUE);

    dls_spin_unlock(session, &space->lock);
}

/*
 * free extents on space free list back to bitmap
 */
status_t spc_free_extent_from_list(knl_session_t *session, space_t *space, const char *oper)
{
    log_atomic_op_begin(session);

    if (!dls_spin_try_lock(session, &space->lock)) {
        if (oper != NULL) {
            GS_THROW_ERROR_EX(ERR_OPERATIONS_NOT_ALLOW, "%s when space %s is being locked",
                oper, space->ctrl->name);
        }
        log_atomic_op_end(session);
        return GS_ERROR;
    }

    /* space has been dropped or no free page when been reused */
    if (!SPACE_IS_ONLINE(space)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "bitmap space free extents failed");
        dls_spin_unlock(session, &space->lock);
        log_atomic_op_end(session);
        return GS_ERROR;
    }

    if (SPACE_HEAD_RESIDENT(session, space)->free_extents.count == 0) {
        dls_spin_unlock(session, &space->lock);
        log_atomic_op_end(session);
        return GS_SUCCESS;
    }

    spc_do_free_extent_list(session, space);

    dls_spin_unlock(session, &space->lock);
    log_atomic_op_end(session);
    return GS_SUCCESS;
}

void spc_free_undo_extents(knl_session_t *session, space_t *space, undo_page_list_t *extents)
{
    bool32 need_redo = SPACE_IS_LOGGING(space);

    knl_panic_log(!IS_INVALID_PAGID(extents->first),
                  "the first of extents is invalid page, panic info: first page of extents %u-%u",
                  space->head->free_extents.first.file, space->head->free_extents.first.page);
    knl_panic_log(!IS_INVALID_PAGID(extents->last),
                  "the last of extents is invalid page, panic info: last page of extents %u-%u",
                  space->head->free_extents.last.file, space->head->free_extents.last.page);
    CM_POINTER3(session, space, extents);

    cm_spin_lock(&space->lock.lock, &session->stat->spin_stat.stat_space);

#ifdef DB_DEBUG_VERSION
    spc_validate_undo_extents(session, extents);
#endif

    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);

    if (space->head->free_extents.count == 0) {
        space->head->free_extents.first = PAGID_U2N(extents->first);
        space->head->free_extents.last = PAGID_U2N(extents->last);
        space->head->free_extents.count = extents->count;
    } else {
        knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.first),
                      "the first of free_extents is invalid page, panic info: first page of extents %u-%u",
                      space->head->free_extents.first.file, space->head->free_extents.first.page);
        knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.last),
                      "the last of free_extents is invalid page, panic info: last page of extents %u-%u",
                      space->head->free_extents.last.file, space->head->free_extents.last.page);
        spc_concat_extent(session, PAGID_U2N(extents->last), space->head->free_extents.first);
        space->head->free_extents.first = PAGID_U2N(extents->first);
        space->head->free_extents.count += extents->count;
    }

    if (need_redo) {
        log_put(session, RD_SPC_FREE_EXTENT, &space->head->free_extents, sizeof(page_list_t), LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, GS_TRUE);

    cm_spin_unlock(&space->lock.lock);
}

void spc_create_segment(knl_session_t *session, space_t *space)
{
    bool32 need_redo = SPACE_IS_LOGGING(space);

    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    space->head->segment_count++;
    if (need_redo) {
        log_put(session, RD_SPC_CHANGE_SEGMENT, &space->head->segment_count, sizeof(uint32), LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, GS_TRUE);
}

void spc_drop_segment(knl_session_t *session, space_t *space)
{
    bool32 need_redo = SPACE_IS_LOGGING(space);

    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    knl_panic_log(space->head->segment_count > 0,
                  "segment_count abnormal, panic info: page %u-%u type %u segment_count %u", space->entry.file,
                  space->entry.page, ((page_head_t *)CURR_PAGE(session))->type, space->head->segment_count);
    space->head->segment_count--;
    if (need_redo) {
        log_put(session, RD_SPC_CHANGE_SEGMENT, &space->head->segment_count, sizeof(uint32), LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, GS_TRUE);
}

#ifdef __cplusplus
}
#endif

