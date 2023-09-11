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
 * knl_shrink_space.c
 *
 *
 * IDENTIFICATION
 * src/kernel/tablespace/knl_shrink_space.c
 *
 * -------------------------------------------------------------------------
 */

#include "knl_shrink_space.h"
#include "knl_context.h"
#include "knl_space_manage.h"
#include "dtc_dls.h"
#include "dtc_database.h"

#ifdef __cplusplus
extern "C" {
#endif

static void spc_clean_free_list(knl_session_t *session, space_t *space)
{
    bool32 need_redo = SPACE_IS_LOGGING(space);

    log_atomic_op_begin(session);

    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    if (space->head->free_extents.count == 0) {
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return;
    }

    space->head->free_extents.first = INVALID_PAGID;
    space->head->free_extents.last = INVALID_PAGID;
    space->head->free_extents.count = 0;

    if (need_redo) {
        log_put(session, RD_SPC_FREE_EXTENT, &space->head->free_extents, sizeof(page_list_t), LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, GS_TRUE);

    log_atomic_op_end(session);
}

static void spc_shrink_checkpoint(knl_session_t *session, space_t *space)
{
    ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_FULL);
    if (SPACE_IS_LOGGING(space)) {
        log_atomic_op_begin(session);
        rd_shrink_space_t redo;
        redo.op_type = RD_SPC_SHRINK_CKPT;
        redo.space_id = space->ctrl->id;
        redo.flags = 0;
        log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_shrink_space_t), LOG_ENTRY_FLAG_NONE);
        log_atomic_op_end(session);
        log_commit(session);
    }
}

static void spc_shrink_files_prepare(knl_session_t *session, space_t *space, knl_shrink_def_t *shrink,
    uint64 *spc_shrink_size, bool32 *need_shrink)
{
    uint64 spc_total_size = 0;
    uint64 spc_used_size = 0;
    *need_shrink = GS_TRUE;
    uint64 min_file_size;

    min_file_size = spc_get_datafile_minsize_byspace(session, space);

    spc_shrink_checkpoint(session, space);

    dls_spin_lock(session, &space->lock, &session->stat->spin_stat.stat_space);

    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        if (space->ctrl->files[i] == GS_INVALID_ID32) {
            continue;
        }

        datafile_t *df = DATAFILE_GET(session, space->ctrl->files[i]);
        if (!df->ctrl->used || !DATAFILE_IS_ONLINE(df)) {
            dls_spin_unlock(session, &space->lock);
            GS_LOG_RUN_WAR("space %s file %u is offline,can not shrink", space->ctrl->name, space->ctrl->files[i]);
            *need_shrink = GS_FALSE;
            return;
        }

        uint64 df_used_size = (uint64)SPACE_HEAD_RESIDENT(session, space)->hwms[i] * DEFAULT_PAGE_SIZE(session);
        spc_used_size += (df_used_size > min_file_size) ? df_used_size : min_file_size;
        spc_total_size += (uint64)DATAFILE_GET(session, space->ctrl->files[i])->ctrl->size;
    }
    dls_spin_unlock(session, &space->lock);

    if (spc_total_size <= (uint64)shrink->keep_size || spc_total_size <= spc_used_size) {
        GS_LOG_RUN_INF("no need shrink to keep size %llu because space total size %llu, space non-shrinkable size %llu",
            (uint64)shrink->keep_size, spc_total_size, spc_used_size);
        *need_shrink = GS_FALSE;
        return;
    }

    *spc_shrink_size = spc_total_size - shrink->keep_size;

    if (spc_used_size > (uint64)shrink->keep_size) {
        GS_LOG_RUN_INF("can not shrink to keep size %llu because space non-shrinkable size %llu",
            (uint64)shrink->keep_size, spc_used_size);
    }
}

static status_t spc_shrink_files_check(knl_session_t *session, space_t *space, datafile_t *df)
{
    if (!df->ctrl->used || !DATAFILE_IS_ONLINE(df)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "shrink space found datafile offline");
        return GS_ERROR;
    }

    if (session->canceled) {
        GS_THROW_ERROR(ERR_OPERATION_CANCELED);
        return GS_ERROR;
    }

    if (session->killed) {
        GS_THROW_ERROR(ERR_OPERATION_KILLED);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t spc_shrink_files(knl_session_t *session, space_t *space, knl_shrink_def_t *shrink)
{
    uint64 spc_shrink_size;
    bool32 need_shrink = GS_TRUE;
    uint64 min_file_size;

    min_file_size = spc_get_datafile_minsize_byspace(session, space);
    spc_shrink_files_prepare(session, space, shrink, &spc_shrink_size, &need_shrink);
    if (!need_shrink) {
        return GS_SUCCESS;
    }

    dls_spin_lock(session, &space->lock, &session->stat->spin_stat.stat_space);
    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        if (space->ctrl->files[i] == GS_INVALID_ID32) {
            continue;
        }

        if (spc_shrink_size <= 0) {
            break;
        }

        datafile_t *df = DATAFILE_GET(session, space->ctrl->files[i]);
        if (spc_shrink_files_check(session, space, df) != GS_SUCCESS) {
            dls_spin_unlock(session, &space->lock);
            return GS_ERROR;
        }

        uint64 df_size = (uint64)DATAFILE_GET(session, space->ctrl->files[i])->ctrl->size;
        uint64 df_keep_size = (uint64)SPACE_HEAD_RESIDENT(session, space)->hwms[i] * DEFAULT_PAGE_SIZE(session);
        df_keep_size = (df_keep_size > min_file_size) ? df_keep_size : min_file_size;
        uint64 df_shrink_size = (df_size > df_keep_size) ? (df_size - df_keep_size) : 0;
        df_shrink_size = (spc_shrink_size > df_shrink_size) ? df_shrink_size : spc_shrink_size;
        df_keep_size = df_size - df_shrink_size;
        spc_shrink_size = (spc_shrink_size > df_shrink_size) ? (spc_shrink_size - df_shrink_size) : 0;

        if (df_keep_size >= df_size) {
            continue;
        }

        ckpt_disable(session);
        if (spc_truncate_datafile_ddl(session, df, DATAFILE_FD(session, space->ctrl->files[i]), df_keep_size,
            GS_TRUE) != GS_SUCCESS) {
            ckpt_enable(session);
            dls_spin_unlock(session, &space->lock);
            return GS_ERROR;
        }
        ckpt_enable(session);
        GS_LOG_RUN_INF("shrink file size of file %u from %llu to %llu", space->ctrl->files[i], df_size, df_keep_size);
    }

    dls_spin_unlock(session, &space->lock);
    GS_LOG_RUN_INF("finish shrink space %s files", space->ctrl->name);
    return GS_SUCCESS;
}

status_t spc_rebuild_undo_space(knl_session_t *session, space_t *space, knl_shrink_def_t *shrink)
{
    uint32 *hwms = NULL;
    errno_t err;

    if (!DB_IS_RESTRICT(session)) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in restrict mode");
        return GS_ERROR;
    }

    /*
     * There must has no active transaction
     * for undo data will be cleaned for undo shrink
     */
    if (undo_check_active_transaction(session)) {
        GS_THROW_ERROR(ERR_TXN_IN_PROGRESS, "end all transaction before action");
        return GS_ERROR;
    }

    hwms = (uint32 *)cm_push(session->stack, sizeof(uint32) * GS_MAX_SPACE_FILES);
    knl_panic_log(hwms != NULL, "hwms is NULL.");
    err = memset_sp(hwms, sizeof(uint32) * GS_MAX_SPACE_FILES, 0, sizeof(uint32) * GS_MAX_SPACE_FILES);
    knl_securec_check(err);

    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        if (GS_INVALID_ID32 == space->ctrl->files[i]) {
            continue;
        }
        hwms[i] = (i == 0) ? DF_FIRST_HWM_START : DF_HWM_START;
    }

    /*
     * get max page id of txn page for each datafile
     */
    undo_get_txn_hwms(session, space, hwms);
    spc_shrink_checkpoint(session, space);

    cm_spin_lock(&space->lock.lock, &session->stat->spin_stat.stat_space);
    /*
     * clean undo segment page list
     * clean undo space free list
     */
    undo_clean_segment_pagelist(session, space);
    GS_LOG_RUN_INF("finish clean undo segments");
    spc_clean_free_list(session, space);
    GS_LOG_RUN_INF("finish clean undo free list");

    /*
     * update datafile hwmjust keep txn area
     */
    spc_update_hwms(session, space, hwms);
    GS_LOG_RUN_INF("finish update undo hwms");

    cm_pop(session->stack);
    cm_spin_unlock(&space->lock.lock);

    if (spc_shrink_files(session, space, shrink) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (undo_preload(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static void spc_release_mpool_pages(knl_session_t *session, uint32 *mpool_pages, uint32 total_pages)
{
    for (uint32 i = 0; i < total_pages; i++) {
        if (mpool_pages[i] == GS_INVALID_ID32) {
            continue;
        }
        mpool_free_page(session->kernel->attr.large_pool, mpool_pages[i]);
        mpool_pages[i] = GS_INVALID_ID32;
    }
}

static status_t spc_alloc_mpool_pages(knl_session_t *session, uint32 total_pages, uint32 *mpool_pages,
    uint8 **page_bufs)
{
    for (uint32 i = 0; i < total_pages; i++) {
        mpool_pages[i] = GS_INVALID_ID32;
        if (!mpool_try_alloc_page(session->kernel->attr.large_pool, &mpool_pages[i])) {
            spc_release_mpool_pages(session, mpool_pages, i);
            GS_THROW_ERROR(ERR_ALLOC_MEMORY, i, "mpool try alloc page");
            return GS_ERROR;
        }

        if (session->canceled) {
            spc_release_mpool_pages(session, mpool_pages, i);
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            return GS_ERROR;
        }

        if (session->killed) {
            spc_release_mpool_pages(session, mpool_pages, i);
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            return GS_ERROR;
        }

        page_bufs[i] = (uint8 *)mpool_page_addr(session->kernel->attr.large_pool, mpool_pages[i]);
        errno_t ret = memset_sp(page_bufs[i], GS_LARGE_PAGE_SIZE, 0, GS_LARGE_PAGE_SIZE);
        knl_securec_check(ret);
    }

    return GS_SUCCESS;
}

static void spc_try_remove_invalid_extent(knl_session_t *session, space_t *space, uint32 *hwms,
    page_id_t *prev_ext, page_id_t *curr_ext)
{
    page_id_t next;
    if (curr_ext->page < hwms[DATAFILE_GET(session, curr_ext->file)->file_no]) {
        next = spc_get_next_ext(session, *curr_ext);
        *prev_ext = *curr_ext;
        *curr_ext = next;
        return;
    }

    page_list_t *free_extents = &(SPACE_HEAD_RESIDENT(session, space)->free_extents);
    if (IS_SAME_PAGID(*curr_ext, free_extents->first)) {
        knl_panic_log(!IS_INVALID_PAGID(*curr_ext), "curr_ext is invalid, panic info: page %u-%u", curr_ext->file,
                      curr_ext->page);
        log_atomic_op_begin(session);
        page_id_t tmp;
        spc_alloc_free_extent(session, space, &tmp);
        log_atomic_op_end(session);
        *curr_ext = free_extents->first;
        *prev_ext = *curr_ext;
        return;
    }

    next = spc_get_next_ext(session, *curr_ext);
    log_atomic_op_begin(session);
    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    space->head->free_extents.count--;
    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_SPC_ALLOC_EXTENT, &space->head->free_extents, sizeof(page_list_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);
    spc_concat_extent(session, *prev_ext, next);
    log_atomic_op_end(session);

    *curr_ext = next;
}

static status_t spc_filter_free_lists(knl_session_t *session, space_t *space, uint32 *start_hwms, uint32 *new_hwms)
{
    uint32 i;
    for (i = 0; i < space->ctrl->file_hwm; i++) {
        if (start_hwms[i] != new_hwms[i]) {
            break;
        }
    }

    /* all file hwms are start hwms */
    if (i == space->ctrl->file_hwm) {
        spc_clean_free_list(session, space);
        return GS_SUCCESS;
    }

    page_list_t *free_extents = &(SPACE_HEAD_RESIDENT(session, space)->free_extents);
    page_id_t curr = free_extents->first;
    page_id_t prev = curr;
    uint32 count = free_extents->count;

    while (count > 0) {
        if (session->canceled) {
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            return GS_ERROR;
        }

        if (session->killed) {
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            return GS_ERROR;
        }

        spc_try_remove_invalid_extent(session, space, new_hwms, &prev, &curr);
        count--;
    }

    return GS_SUCCESS;
}

static status_t spc_shrink_hwms_prepare(knl_session_t *session, space_t *space, uint32 *new_hwms,
    uint32 *start_hwms, uint64 *prev_extents)
{
    prev_extents[0] = 0;
    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        if (space->ctrl->files[i] == GS_INVALID_ID32) {
            start_hwms[i] = GS_INVALID_ID32;
            new_hwms[i] = start_hwms[i];
            prev_extents[i + 1] = prev_extents[i];
            continue;
        }

        datafile_t *df  = DATAFILE_GET(session, space->ctrl->files[i]);
        if (!df->ctrl->used || !DATAFILE_IS_ONLINE(df)) {
            GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "shrink space found datafile offline");
            return GS_ERROR;
        }

        start_hwms[i] = spc_get_hwm_start(session, space, df);
        new_hwms[i] = start_hwms[i];
        uint32 extents = (SPACE_HEAD_RESIDENT(session, space)->hwms[i] - start_hwms[i]) / space->ctrl->extent_size;
        prev_extents[i + 1] = prev_extents[i] + extents;
    }

    uint64 spc_total_extents = prev_extents[space->ctrl->file_hwm];
    if (spc_total_extents > 0) {
        return GS_SUCCESS;
    }

    /* space total extents is zero, all files are start hwms, free extents list should be empty */
    if (!SPACE_IS_BITMAPMANAGED(space)) {
        spc_clean_free_list(session, space);
    }

    return GS_SUCCESS;
}

static uint32 spc_free_extents_from_bits(uint8 **page_bufs, uint64 start, uint64 end)
{
    uint64 page_idx, map_id;
    uint8 *bitmap = NULL;

    for (uint64 i = end; i > start; i--) {
        page_idx = i / UINT8_BITS / GS_LARGE_PAGE_SIZE;
        bitmap = page_bufs[page_idx];
        map_id = i / UINT8_BITS % GS_LARGE_PAGE_SIZE;
        bool8 free = (bool8)(bitmap[map_id] >> (i % UINT8_BITS)) & (bool8)0x01;
        if (!free) {
            return (uint32)(end - i);
        }
    }

    return (uint32)(end - start);
}

static status_t spc_get_shrink_hwms(knl_session_t *session, space_t *space, uint32 *new_hwms)
{
    uint32 curr_hwm;
    datafile_t *df = NULL;
    database_t *db = &session->kernel->db;

    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        if (space->ctrl->files[i] == GS_INVALID_ID32) {
            continue;
        }

        df = &db->datafiles[space->ctrl->files[i]];
        if (!df->ctrl->used) {
            continue;
        }

        if (session->canceled) {
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            return GS_ERROR;
        }

        if (session->killed) {
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            return GS_ERROR;
        }

        curr_hwm = df_get_shrink_hwm(session, df);
        if (new_hwms[i] < curr_hwm) {
            new_hwms[i] = curr_hwm;
        }
    }

    return GS_SUCCESS;
}

static status_t spc_set_free_extents_bits(knl_session_t *session, space_t *space, uint32 *start_hwms,
    uint64 *prev_extents, uint8 **page_bufs)
{
    uint64 page_idx, map_id;
    uint8 *bitmap = NULL;
    page_list_t *free_extents = &(SPACE_HEAD_RESIDENT(session, space)->free_extents);
    page_id_t curr = free_extents->first;
    uint64 begin_time = KNL_NOW(session);

    for (uint32 i = 0; i < free_extents->count; i++) {
        knl_panic_log(!IS_INVALID_PAGID(curr), "curr page is invalid, panic info: page %u-%u", curr.file, curr.page);
        if (session->canceled) {
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            return GS_ERROR;
        }

        if (session->killed) {
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            return GS_ERROR;
        }

        uint32 file_idx = DATAFILE_GET(session, curr.file)->file_no;
        /* ignore invalid extent */
        if (curr.page >= SPACE_HEAD_RESIDENT(session, space)->hwms[file_idx]) {
            continue;
        }

        uint64 extents = (curr.page - start_hwms[file_idx]) / space->ctrl->extent_size + 1;
        extents += prev_extents[file_idx];
        page_idx = extents / UINT8_BITS / GS_LARGE_PAGE_SIZE;
        bitmap = page_bufs[page_idx];
        map_id = extents / UINT8_BITS % GS_LARGE_PAGE_SIZE;

        bitmap[map_id] |= (0x01 << (extents % UINT8_BITS));
        curr = spc_get_next_ext(session, curr);

        session->kernel->stat.spc_free_exts++;
        session->kernel->stat.spc_shrink_times += (KNL_NOW(session) - begin_time);
    }

    return GS_SUCCESS;
}

static status_t spc_get_new_hwms(knl_session_t *session, space_t *space, uint32 *start_hwms, uint64 *prev_extents,
    uint32 *new_hwms)
{
    if (SPACE_IS_BITMAPMANAGED(space)) {
        return spc_get_shrink_hwms(session, space, new_hwms);
    }

    CM_SAVE_STACK(session->stack);

    uint32 total_pages = (uint32)(prev_extents[space->ctrl->file_hwm] / UINT8_BITS / GS_LARGE_PAGE_SIZE + 1);
    uint32 *mpool_pages = (uint32 *)cm_push(session->stack, sizeof(uint32) * total_pages);
    knl_panic(mpool_pages != NULL);
    uint8 **page_bufs = (uint8 **)cm_push(session->stack, sizeof(uint8 *) * total_pages);
    knl_panic(page_bufs != NULL);

    if (spc_alloc_mpool_pages(session, total_pages, mpool_pages, page_bufs) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (spc_set_free_extents_bits(session, space, start_hwms, prev_extents, page_bufs) != GS_SUCCESS) {
        spc_release_mpool_pages(session, mpool_pages, total_pages);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    status_t status = GS_SUCCESS;

    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        if (GS_INVALID_ID32 == space->ctrl->files[i]) {
            continue;
        }

        if (session->canceled) {
            status = GS_ERROR;
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            break;
        }

        if (session->killed) {
            status = GS_ERROR;
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            break;
        }

        uint32 curr_hwm = SPACE_HEAD_RESIDENT(session, space)->hwms[i];
        uint32 free_extents = spc_free_extents_from_bits(page_bufs, prev_extents[i], prev_extents[i + 1]);
        uint32 free_pages = free_extents * space->ctrl->extent_size;
        uint32 new_hwm = curr_hwm - free_pages;

        if (new_hwm > new_hwms[i]) {
            new_hwms[i] = new_hwm;
        }
    }

    spc_release_mpool_pages(session, mpool_pages, total_pages);
    CM_RESTORE_STACK(session->stack);
    return status;
}

static bool32 spc_shrink_hwms_anable(knl_session_t *session, space_t *space, uint64 spc_total_extents)
{
    if (!SPACE_IS_BITMAPMANAGED(space)) {
        if (SPACE_HEAD_RESIDENT(session, space)->free_extents.count == 0) {
            return GS_FALSE;
        }
    }

    if (spc_total_extents == 0) {
        return GS_FALSE;
    }

    return GS_TRUE;
}

static status_t spc_shrink_hwms(knl_session_t *session, space_t *space)
{
    spc_shrink_checkpoint(session, space);

    dls_spin_lock(session, &space->lock, &session->stat->spin_stat.stat_space);
    CM_SAVE_STACK(session->stack);

    uint32 file_hwm = space->ctrl->file_hwm;
    uint32 *new_hwms = (uint32 *)cm_push(session->stack, sizeof(uint32) * file_hwm);
    uint32 *start_hwms = (uint32 *)cm_push(session->stack, sizeof(uint32) * file_hwm);
    uint64 *prev_extents = (uint64 *)cm_push(session->stack, sizeof(uint64) * (file_hwm + 1));

    if (spc_shrink_hwms_prepare(session, space, new_hwms, start_hwms, prev_extents) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        dls_spin_unlock(session, &space->lock);
        return GS_ERROR;
    }

    if (!spc_shrink_hwms_anable(session, space, prev_extents[space->ctrl->file_hwm])) {
        CM_RESTORE_STACK(session->stack);
        dls_spin_unlock(session, &space->lock);
        return GS_SUCCESS;
    }

    if (spc_get_new_hwms(session, space, start_hwms, prev_extents, new_hwms) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        dls_spin_unlock(session, &space->lock);
        return GS_ERROR;
    }

    spc_update_hwms(session, space, new_hwms);

    if (!SPACE_IS_BITMAPMANAGED(space)) {
        if (spc_filter_free_lists(session, space, start_hwms, new_hwms) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            dls_spin_unlock(session, &space->lock);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    dls_spin_unlock(session, &space->lock);

    GS_LOG_RUN_INF("finish shrink space %s hwms", space->ctrl->name);
    return GS_SUCCESS;
}

static status_t spc_shrink_space_prepare(knl_session_t *session, space_t *space)
{
    if (!SPACE_IS_ONLINE(space)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "shrink space");
        return GS_ERROR;
    }

    if (!DB_IS_OPEN(session)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "space shrink on non-open mode");
        return GS_ERROR;
    }

    if (DB_IS_CLUSTER(session) && IS_UNDO_SPACE(space)) {
        space_t *my_undo_space = session->kernel->undo_ctx.space;
        if (my_undo_space != space) {
            GS_THROW_ERROR(ERR_INVALID_OPERATION, "undo space can only be shrinked on its own node");
            return GS_ERROR;
        }
    }

    if (space->ctrl->id == dtc_my_ctrl(session)->undo_space) {
        undo_shrink_segments(session);
    }

    if (SPACE_IS_BITMAPMANAGED(space)) {
        while (SPACE_HEAD_RESIDENT(session, space)->free_extents.count != 0) {
            if (spc_free_extent_from_list(session, space, "shink space") != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    if (rb_purge_space(session, space->ctrl->id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_clean_tablespace_garbage_seg(session, space->ctrl->id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t spc_shrink_temp_space(knl_session_t *session, space_t *space, knl_shrink_def_t *shrink)
{
    knl_panic(IS_SWAP_SPACE(space));

    if (!DB_IS_RESTRICT(session)) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in restrict mode");
        return GS_ERROR;
    }

    return spc_shrink_files(session, space, shrink);
}

status_t spc_verify_shrink_space(knl_session_t *session, space_t *space, knl_shrink_def_t *shrink)
{
    uint64 min_file_size;
    uint64 min_space_size;
    uint32 file_count = 0;
    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        if (space->ctrl->files[i] == GS_INVALID_ID32) {
            continue;
        }
        file_count += 1;
    }

    min_file_size = spc_get_datafile_minsize_byspace(session, space);
    min_space_size = min_file_size * file_count;

    if ((uint64)shrink->keep_size < min_space_size) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "size value is smaller than minimum(%llu) required", min_space_size);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/**
 * shrink space
 * Only shrink temporary space
 * @param session, space, shrink_def
 */
status_t spc_shrink_space(knl_session_t *session, space_t *space, knl_shrink_def_t *shrink)
{
    if (!DB_ATTR_ENABLE_HWM_CHANGE(session)) {
        GS_LOG_RUN_ERR("shrink space is closed");
        return GS_ERROR;
    }
    if (spc_is_punching(session, space, "shrink space")) {
        return GS_ERROR;
    }

    if (spc_verify_shrink_space(session, space, shrink) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (DB_IS_RESTRICT(session)) {
        if (space->ctrl->id == dtc_my_ctrl(session)->undo_space) {
            return spc_rebuild_undo_space(session, space, shrink);
        }
    }

    if (IS_SWAP_SPACE(space)) {
        if (spc_shrink_temp_space(session, space, shrink) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (spc_shrink_space_prepare(session, space) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (spc_shrink_hwms(session, space) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (spc_shrink_files(session, space, shrink) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

#ifdef __cplusplus
}
#endif

