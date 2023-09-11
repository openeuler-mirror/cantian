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
 * knl_abr.c
 *
 *
 * IDENTIFICATION
 * src/kernel/persist/knl_abr.c
 *
 * -------------------------------------------------------------------------
 */

#include "knl_abr.h"
#include "cm_file.h"
#include "cs_protocol.h"
#include "knl_context.h"
#include "knl_buffer.h"
#include "repl_log_send.h"
#include "dtc_database.h"

// MUST call this function with task lock held.
static inline void abr_set_task(lsnd_abr_task_t *task, uint16 file, uint32 page, char *buf, uint32 buf_size)
{
    task->file = file;
    task->page = page;
    task->buf = buf;
    task->buf_size = buf_size;
    task->running = GS_TRUE;
    task->timestamp = cm_current_time();
}

bool32 abr_create_task(knl_session_t *session, buf_ctrl_t *ctrl, lsnd_abr_task_t *task)
{
    uint16 file = ctrl->page_id.file;
    uint32 page = ctrl->page_id.page;
    char *buf = (char *)ctrl->page;

    cm_spin_lock(&task->lock, NULL);
    if (!task->running && !task->succeeded) {
        abr_set_task(task, file, page, buf, DEFAULT_PAGE_SIZE(session));

        GS_LOG_RUN_INF("[ABR] create ABR task for file %u page %u with lsnd id %u", file, page, task->lsnd_id);
        cm_spin_unlock(&task->lock);
        return GS_TRUE;
    }

    cm_spin_unlock(&task->lock);
    return GS_FALSE;
}

void abr_finish_task(lsnd_abr_task_t *task, bool32 succeeded, const char *buf, uint32 buf_size)
{
    errno_t err;

    cm_spin_lock(&task->lock, NULL);
    if (!task->running) {
        cm_spin_unlock(&task->lock);
        return;
    }
    knl_panic(task->executing);

    if (succeeded && buf != NULL) {
        err = memcpy_sp(task->buf, task->buf_size, buf, buf_size);
        knl_securec_check(err);
    }
    task->succeeded = succeeded;
    task->executing = GS_FALSE;
    task->running = GS_FALSE;
    GS_LOG_RUN_INF("[ABR] finish ABR task state %d for file %u page %u with lsnd id %u",
                   succeeded, task->file, task->page, task->lsnd_id);
    cm_spin_unlock(&task->lock);
}

bool32 abr_notify_task(knl_session_t *session, buf_ctrl_t *ctrl, lsnd_abr_task_t **task_handle)
{
    lsnd_context_t *lsnd_ctx = &session->kernel->lsnd_ctx;
    lsnd_t *lsnd = NULL;
    uint64 curr_lfn = (uint64)session->kernel->lfn;
    time_t now = cm_current_time();
    time_t abr_timeout = (time_t)session->kernel->attr.abr_timeout;
    bool32 notified = GS_FALSE;
    uint16 file = ctrl->page_id.file;
    uint32 page = ctrl->page_id.page;

    if (!session->kernel->attr.enable_abr) {
        GS_LOG_RUN_INF("[ABR] failed to create ABR task for file %u page %u due to abr disabled", file, page);
        return GS_FALSE;
    }

    if (lsnd_ctx->est_standby_num == 0) {
        GS_LOG_RUN_INF("[ABR] failed to create ABR task for file %u page %u due to no valid standby", file, page);
        return GS_FALSE;
    }

    while (cm_current_time() - now < abr_timeout) {
        cm_latch_s(&lsnd_ctx->latch, SESSION_ID_LSND, GS_FALSE, NULL);

        if (lsnd_ctx->est_standby_num == 0) {
            cm_unlatch(&lsnd_ctx->latch, NULL);
            return GS_FALSE;
        }

        for (uint32 i = 0; i < lsnd_ctx->standby_num; i++) {
            lsnd = lsnd_ctx->lsnd[i];
            if (lsnd == NULL || lsnd->is_disable || lsnd->status < LSND_STATUS_QUERYING) {
                continue;
            }

            if (lsnd->peer_rcy_point.lfn >= curr_lfn) {
                *task_handle = &lsnd->abr_task;
                notified = abr_create_task(session, ctrl, *task_handle);
                break;
            }
        }

        cm_unlatch(&lsnd_ctx->latch, NULL);

        if (notified) {
            break;
        }

        if (session->killed || session->canceled || session->force_kill || !session->kernel->attr.enable_abr) {
            GS_LOG_RUN_INF("[ABR] failed to notify for file %u page %u due to session killed %d or abr disabled %d",
                           file, page, (session->killed || session->canceled), !session->kernel->attr.enable_abr);
            return GS_FALSE;
        }

        cm_sleep(10);
    }

    if (!notified) {
        GS_LOG_RUN_INF("[ABR] failed to notify ABR for file %u page %u due to timeout", file, page);
    }

    return notified;
}

bool32 abr_wait_task_done(knl_session_t *session, lsnd_abr_task_t *task_handle)
{
    lsnd_context_t *lsnd_ctx = &session->kernel->lsnd_ctx;
    lsnd_abr_task_t *task = task_handle;
    time_t abr_time_out = (time_t)session->kernel->attr.abr_timeout;
    time_t now = cm_current_time();
    bool32 is_succeed = GS_FALSE;

    while (cm_current_time() - now < abr_time_out) {
        cm_latch_s(&lsnd_ctx->latch, SESSION_ID_LSND, GS_FALSE, NULL);
        cm_spin_lock(&task->lock, NULL);
        if (!task->running) {
            is_succeed = task->succeeded;
            task->succeeded = GS_FALSE;
            cm_spin_unlock(&task->lock);
            cm_unlatch(&lsnd_ctx->latch, NULL);
            return is_succeed;
        }
        cm_spin_unlock(&task->lock);
        cm_unlatch(&lsnd_ctx->latch, NULL);

        if (session->killed || session->canceled || session->force_kill || !session->kernel->attr.enable_abr) {
            GS_LOG_RUN_INF("[ABR] failed to wait ABR task done due to session killed %d or abr disabled %d",
                           (session->killed || session->canceled), !session->kernel->attr.enable_abr);
            abr_finish_task(task, GS_FALSE, NULL, GS_INVALID_ID32);
            return GS_FALSE;
        }
        cm_sleep(10);
    }
    GS_LOG_RUN_INF("[ABR] failed to wait ABR task done due to timeout");
    abr_finish_task(task, GS_FALSE, NULL, GS_INVALID_ID32);
    return GS_FALSE;
}

void abr_try_save_page(knl_session_t *session, page_head_t *page)
{
    page_id_t *page_id = AS_PAGID_PTR(page->id);
    datafile_t *df = DATAFILE_GET(session, page_id->file);
    int32 *handle = DATAFILE_FD(session, page_id->file);
    int64 offset = (int64)page_id->page * PAGE_SIZE(*page);

    knl_panic_log(PAGE_SIZE(*page) > 0, "page size is incorrect, panic info: page %u-%u type %u", page_id->file,
                  page_id->page, page->type);
    knl_panic_log(CHECK_PAGE_PCN(page), "page pcn is abnormal, panic info: page %u-%u type %u", page_id->file,
                  page_id->page, page->type);

    page_calc_checksum(page, DEFAULT_PAGE_SIZE(session));

    if (spc_write_datafile(session, df, handle, offset, page, PAGE_SIZE(*page)) != GS_SUCCESS) {
        spc_close_datafile(df, handle);
        GS_LOG_RUN_WAR("[ABR] failed to write page (file %u, page %u) to datafile %s",
                       (uint32)page_id->file, page_id->page, df->ctrl->name);
    }

    if (db_fdatasync_file(session, *handle) != GS_SUCCESS) {
        GS_LOG_RUN_WAR("[ABR] failed to fdatasync datafile %s", df->ctrl->name);
        spc_close_datafile(df, handle);
    }
}

status_t abr_send_page_fetch_req(lsnd_t *lsnd, lsnd_abr_task_t *task)
{
    rep_msg_header_t rep_msg_header;
    rep_abr_req_t abr_req;
    time_t now = cm_current_time();

    rep_msg_header.size = sizeof(rep_msg_header_t) + sizeof(rep_abr_req_t);
    rep_msg_header.type = REP_ABR_REQ;

    abr_req.lsnd_id = task->lsnd_id;
    abr_req.file = task->file;
    abr_req.page = task->page;
    abr_req.blk_size = task->buf_size;

    lsnd->last_send_time = now;

    if (cs_write_stream(&lsnd->pipe, (char *)&rep_msg_header, sizeof(rep_msg_header_t),
                        (int32)cm_atomic_get(&lsnd->session->kernel->attr.repl_pkg_size)) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[ABR] failed to send abr request header to standby");
        return GS_ERROR;
    }

    if (cs_write_stream(&lsnd->pipe, (char *)&abr_req, sizeof(rep_abr_req_t),
                        (int32)cm_atomic_get(&lsnd->session->kernel->attr.repl_pkg_size)) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[ABR] failed to send abr request data to standby");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

bool32 abr_repair_page_from_standy(knl_session_t *session, buf_ctrl_t *ctrl)
{
    lsnd_abr_task_t *handle = NULL;

    if (!abr_notify_task(session, ctrl, &handle)) {
        return GS_FALSE;
    }

    GS_LOG_RUN_WAR("[ABR] find corrupted page(file %u, page %u)", ctrl->page_id.file, ctrl->page_id.page);
    if (abr_wait_task_done(session, handle)) {
        if (CHECK_PAGE_PCN(ctrl->page)) {
            abr_try_save_page(session, ctrl->page);
            GS_LOG_RUN_WAR("[ABR] corrupted page(file %u, page %u) has been fixed successfully",
                           ctrl->page_id.file, ctrl->page_id.page);
            return GS_TRUE;
        } else {
            GS_LOG_RUN_ERR("[ABR] failed to fix corrupted page(file %u, page %u)",
                           ctrl->page_id.file, ctrl->page_id.page);
        }
    }

    return GS_FALSE;
}

status_t abr_wait_paral_rcy_compelte(knl_session_t *session)
{
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    uint64 curr_wait_count = rcy->wait_stats_view[WAIT_RELAPY_COUNT];
    uint32 abr_timeout = session->kernel->attr.abr_timeout;

    if (!rcy->paral_rcy) {
        return GS_SUCCESS;
    }

    // need wait current paral replay completed
    while (rcy->wait_stats_view[WAIT_RELAPY_COUNT] == curr_wait_count) {
        uint32 replay_completed = GS_TRUE;
        for (uint32 i = 0; i < rcy->capacity; i++) {
            if (rcy->bucket[i].head != rcy->bucket[i].tail) {
                replay_completed = GS_FALSE;
            }
        }

        if (replay_completed) {
            return GS_SUCCESS;
        }

        if (abr_timeout == 0) {
            GS_LOG_RUN_ERR("[Log Receiver] ABR standby wait replay timeout");
            return GS_ERROR;
        }
        cm_sleep(MILLISECS_PER_SECOND);
        abr_timeout--;
    }
    return GS_SUCCESS;
}

bool32 abr_verify_pageid(knl_session_t *session, page_id_t page_id)
{
    datafile_t *df = NULL;
    space_t *space = NULL;
    uint32 dw_file_id = session->kernel->db.ctrl.core.dw_file_id;

    knl_panic_log(!IS_INVALID_PAGID(page_id) && page_id.page != 0, "page_id is invalid, panic info: page %u-%u",
                  page_id.file, page_id.page);

    // double write page id
    if (page_id.file == dw_file_id && page_id.page > SPACE_ENTRY_PAGE && page_id.page < DW_SPC_HWM_START) {
        GS_THROW_ERROR(ERR_INVALID_PAGE_ID, ", double write page is unsupported");
        return GS_FALSE;
    }

    df = DATAFILE_GET(session, page_id.file);
    if (!df->ctrl->used || !DATAFILE_IS_ONLINE(df)) {
        GS_THROW_ERROR(ERR_INVALID_PAGE_ID, ", datafile is unused");
        return GS_FALSE;
    }

    if (session->kernel->db.status == DB_STATUS_MOUNT) {
        spc_set_space_id(session);
    }

    if (DF_FILENO_IS_INVAILD(df)) {
        GS_THROW_ERROR(ERR_INVALID_PAGE_ID, ", datafile is unused");
        return GS_FALSE;
    }

    space = SPACE_GET(session, df->space_id);
    if (!SPACE_IS_ONLINE(space) || !space->ctrl->used) {
        GS_THROW_ERROR(ERR_INVALID_PAGE_ID, ", datafile is unused");
        return GS_FALSE;
    }

    if (SPACE_IS_NOLOGGING(space)) {
        if (page_id.page != SPACE_ENTRY_PAGE || df->file_no != 0) { // space head repairing is supported
            GS_THROW_ERROR(ERR_INVALID_PAGE_ID, ", temporary or nologging tablespace page is unsupported");
            return GS_FALSE;
        }
    }

    if ((uint64)df->ctrl->size < (uint64)(page_id.page + 1) * DEFAULT_PAGE_SIZE(session)) {
        GS_THROW_ERROR(ERR_INVALID_PAGE_ID, ", block offset is out of datafile's size");
        return GS_FALSE;
    }

    return GS_TRUE;
}

/*
 * Because we only replay one page when page repairing, datafile can not be created or deleted.
 * When replay rd_spc_create_data_file or rd_spc_remove_datafile, we just init page to zero.
 */
void abr_clear_page(knl_session_t *session, uint32 file_id)
{
    buf_ctrl_t *page_ctrl = session->kernel->rcy_ctx.abr_ctrl;
    errno_t ret;

    if (page_ctrl->page_id.file == file_id) {
        ret = memset_sp(page_ctrl->page, DEFAULT_PAGE_SIZE(session), 0, DEFAULT_PAGE_SIZE(session));
        knl_securec_check(ret);
    }
}

static status_t abr_decompress_and_search_bakfile(bak_t *bak, bak_page_search_t *search_ctx, bool32 last_package,
                                                  uint32 read_size, bool32 *find)
{
    knl_compress_t *compress_ctx = &bak->compress_ctx;
    char *compress_buf = bak->compress_buf;
    char *read_buf = search_ctx->read_buf.aligned_buf;
    uint32 page_size = search_ctx->page_size;
    uint32 left_size = 0;
    uint32 page_index;
    uint32 page_count;
    page_id_t tmp_page_id;
    page_head_t *tmp_page = NULL;
    errno_t ret;

    *find = GS_FALSE;
    knl_compress_set_input(bak->record.attr.compress, compress_ctx, read_buf, read_size);

    for (;;) {
        if (knl_decompress(bak->record.attr.compress, compress_ctx, last_package, compress_buf + left_size,
            BACKUP_BUFFER_SIZE(bak) - left_size) != GS_SUCCESS) {
            return GS_ERROR;
        }

        page_count = compress_ctx->write_len / page_size;
        left_size = compress_ctx->write_len % page_size;

        for (page_index = 0; page_index < page_count; page_index++) {
            tmp_page = (page_head_t *)(compress_buf + page_index * page_size);
            tmp_page_id = AS_PAGID(tmp_page->id);
            if (IS_SAME_PAGID(tmp_page_id, search_ctx->page_id)) {
                *find = GS_TRUE;
                ret = memcpy_sp(read_buf, BACKUP_BUFFER_SIZE(bak), compress_buf + page_index * page_size, page_size);
                knl_securec_check(ret);
                return GS_SUCCESS;
            }
        }
        /* move left data to compress_buf head */
        if (left_size > 0) {
            ret = memmove_s(compress_buf, BACKUP_BUFFER_SIZE(bak), compress_buf + page_count * page_size, left_size);
            knl_securec_check(ret);
        }

        if (compress_ctx->finished) {
            break;
        }
    }
    return GS_SUCCESS;
}

static status_t abr_search_page_from_compress(knl_session_t *session, bak_page_search_t *search_ctx, bool32 *find)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bool32 last_package = GS_FALSE;
    int32 read_size;
    status_t status = GS_SUCCESS;
    uint32 offset = 0;

    *find = GS_FALSE;

    bak->compress_ctx.finished = GS_FALSE;
    bak->compress_ctx.write_len = 0;

    if (knl_compress_init(bak->record.attr.compress, &bak->compress_ctx, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (!last_package) {
        if (cm_read_device_nocheck(search_ctx->file_type, search_ctx->handle, offset, search_ctx->read_buf.aligned_buf, BACKUP_BUFFER_SIZE(bak),
            &read_size) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        last_package = (uint32)read_size < BACKUP_BUFFER_SIZE(bak);
        if (abr_decompress_and_search_bakfile(bak, search_ctx, last_package, (uint32)read_size, find) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }
    offset += read_size;
        if (*find) {
            status = GS_SUCCESS;
            break;
        }
    }

    knl_compress_end(bak->record.attr.compress, &bak->compress_ctx, GS_FALSE);
    return status;
}

static status_t abr_get_disk_page_id(bak_page_search_t *search_ctx, int64 offset, page_id_t *page_id)
{
    page_head_t *page = (page_head_t *)search_ctx->read_buf.aligned_buf;
    int32 handle = search_ctx->handle;
    int64 file_size = cm_file_size(handle);
    if (file_size == -1) {
        GS_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_END, errno);
        return GS_ERROR;
    }

    if (offset < 0 || offset >= file_size) {
        return GS_ERROR;
    }

    if (cm_read_device(search_ctx->file_type, handle, offset, page, search_ctx->page_size) != GS_SUCCESS) {
        *page_id = INVALID_PAGID;
        return GS_ERROR;
    }

    *page_id = AS_PAGID(page->id);
    return GS_SUCCESS;
}

/*
 * In incremental buckup file, pages are sorted incrementally, we can use binary search
 * Can not use to full backup, because it may contain zero-page
 */
static status_t abr_binary_search_bakfile(knl_session_t *session, bak_page_search_t *search_ctx, bool32 *find)
{
    int32 handle = search_ctx->handle;
    uint32 page_size = search_ctx->page_size;
    int64 file_size = cm_file_size(handle);
    int64 high_offset = file_size / (int32)DEFAULT_PAGE_SIZE(session) - 1;
    int64 low_offset = 0;
    int64 mid_offset = (high_offset - low_offset) / 2; /* Binary search, need calculate mid position */
    page_id_t page_id = search_ctx->page_id;
    page_id_t tmp_page_id;

    *find = GS_FALSE;
    if (file_size == 0) {
        return GS_SUCCESS;
    }

    if (file_size < 0) {
        GS_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_END, errno);
        return GS_ERROR;
    }

    knl_panic_log((uint64)file_size % DEFAULT_PAGE_SIZE(session) == 0,
        "file_size is abnormal, panic info: page %u-%u file_size %llu", page_id.file, page_id.page, (uint64)file_size);

    while (low_offset <= high_offset) {
        /* Binary search, need calculate mid position */
        mid_offset = (high_offset + low_offset) / 2;
        if (abr_get_disk_page_id(search_ctx, mid_offset * page_size, &tmp_page_id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (PAGID_LT(tmp_page_id, page_id)) {
            low_offset = mid_offset + 1;
        } else if (PAGID_GT(tmp_page_id, page_id)) {
            high_offset = mid_offset - 1;
        } else {
            if (cm_read_device(search_ctx->file_type, search_ctx->handle, mid_offset * page_size,
                               (void *)search_ctx->read_buf.aligned_buf, page_size) != GS_SUCCESS) {
                return GS_ERROR;
            }
            *find = GS_TRUE;
            return GS_SUCCESS;
        }
    }

    return GS_SUCCESS;
}

/* Replace corrupted page as repaired page */
static status_t abr_flush_repaired_page(knl_session_t *session, page_head_t *page_repaired)
{
    page_id_t page_id = AS_PAGID(page_repaired->id);
    char file_name[GS_FILE_NAME_BUFFER_SIZE] = { 0 };
    uint32 cks_level = session->kernel->attr.db_block_checksum;
    int32 handle = GS_INVALID_HANDLE;
    errno_t errcode;

    if (cks_level == (uint32)CKS_OFF) {
        PAGE_CHECKSUM(page_repaired, DEFAULT_PAGE_SIZE(session)) = GS_INVALID_CHECKSUM;
    } else {
        if (PAGE_SIZE(*page_repaired) != 0) {
            knl_panic_log(PAGE_SIZE(*page_repaired) == DEFAULT_PAGE_SIZE(session), "page_repaired's size is incorrect, "
                          "panic info: page %u-%u type %u", page_id.file, page_id.page, page_repaired->type);
            page_calc_checksum(page_repaired, DEFAULT_PAGE_SIZE(session));
        }
    }

    if (PAGE_SIZE(*page_repaired) == DEFAULT_PAGE_SIZE(session)) {
        knl_panic_log(CHECK_PAGE_PCN(page_repaired), "page_repaired pcn is abnormal, panic info: page %u-%u type %u",
                      page_id.file, page_id.page, page_repaired->type);
    }

    errcode = snprintf_s(file_name, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s/data/page_%u_%u",
                         session->kernel->home, page_id.file, page_id.page);
    knl_securec_check_ss(errcode);

    if (cm_create_file(file_name, O_BINARY | O_SYNC | O_RDWR | O_EXCL, &handle) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_write_file(handle, page_repaired, (int32)DEFAULT_PAGE_SIZE(session)) != GS_SUCCESS) {
        cm_close_file(handle);
        return GS_ERROR;
    }

    cm_close_file(handle);
    return GS_SUCCESS;
}

static status_t abr_replay_page_to_latest(knl_session_t *session, log_point_t curr_point, page_id_t page_id,
                                          page_head_t *page_backup)
{
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    bak_t *bak = &session->kernel->backup_ctx.bak;
    log_point_t lrp_point = { 0 };
    log_batch_t *batch = NULL;
    buf_ctrl_t ctrl;
    bool32 need_more_log = GS_FALSE;
    uint32 data_size = 0;
    errno_t ret;
    uint32 block_size;

    if (PAGE_SIZE(*page_backup) != 0) {
        knl_panic_log(IS_SAME_PAGID(page_id, AS_PAGID(page_backup->id)), "page_id and page_backup's id are not same, "
                      "panic info: page_backup %u-%u page_id %u-%u type %u", AS_PAGID(page_backup->id).file,
                      AS_PAGID(page_backup->id).page, page_id.file, page_id.page, page_backup->type);
    }

    ret = memset_sp(&ctrl, sizeof(ctrl), 0, sizeof(ctrl));
    knl_securec_check(ret);

    GS_LOG_RUN_INF("[ABR] begine to relplay page (%u-%u) from log file:%u, block id:%u, lfn:%llu\n",
                   (uint32)page_id.file, page_id.page, curr_point.asn, curr_point.block_id, (uint64)curr_point.lfn);

    if (bak->lfn > 0) {
        rcy->abr_db_status = DB_STATUS_OPEN;
        lrp_point.lfn = bak->lfn;
    } else {
        rcy->abr_db_status = DB_STATUS_MOUNT;
        lrp_point = dtc_my_ctrl(session)->lrp_point;
    }

    GS_LOG_RUN_INF("[ABR] recovery expected least end with file:%u,point:%u,lfn:%llu",
                   lrp_point.asn, lrp_point.block_id, (uint64)lrp_point.lfn);

    if (log_load(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    session->kernel->db.status = DB_STATUS_RECOVERY;
    session->kernel->redo_ctx.lfn = curr_point.lfn;

    ctrl.page = page_backup;
    ctrl.page_id = page_id;
    rcy->abr_ctrl = &ctrl;
    rcy->abr_rcy_flag = GS_TRUE;
    rcy->rcy_end = GS_FALSE;
    rcy->paral_rcy = GS_FALSE;
    rcy->is_first_arch_file = GS_TRUE;

    while (rcy_load(session, &curr_point, &data_size, &block_size) == GS_SUCCESS) {
        batch = (log_batch_t*)rcy->read_buf.aligned_buf;
        if (log_need_realloc_buf(batch, &rcy->read_buf, "rcy", GS_MAX_BATCH_SIZE)) {
            continue;
        }

        if (rcy_replay(session, &curr_point, data_size, batch, block_size, &need_more_log, NULL, GS_FALSE) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (session->killed || session->force_kill || session->canceled) {
            rcy->is_working = GS_FALSE;
            session->kernel->db.status = DB_STATUS_MOUNT;
            return GS_ERROR;
        }

        if (!need_more_log) {
            break;
        }
    }

    session->kernel->rcy_ctx.is_working = GS_FALSE;
    session->kernel->db.status = DB_STATUS_MOUNT;
    GS_LOG_RUN_INF("[ABR] replay real end with point [%llu-%u-%u] lfn: %llu",
                   (uint64)curr_point.rst_id, curr_point.asn, curr_point.block_id, (uint64)curr_point.lfn);

    if (curr_point.lfn < lrp_point.lfn) {
        GS_THROW_ERROR(ERR_INVALID_RCV_END_POINT,
                       curr_point.asn, curr_point.block_id, lrp_point.asn, lrp_point.block_id);
        return GS_ERROR;
    }

    if (PAGE_SIZE(*page_backup) == 0 && page_backup->lsn == 0) {
        GS_LOG_RUN_ERR("[ABR] input page is not found in backup or redo log");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static uint32 abr_bak_index_contain_page(knl_session_t *session, bak_t *bak, bak_head_t *head,
                                         page_id_t page_id, uint32 page_size)
{
    uint64 offset = (uint64)page_id.page * page_size;
    uint32 dw_file_id = knl_get_dbwrite_file_id(session);

    for (uint32 id = 0; id < head->file_count; id++) {
        if (bak->files[id].type != BACKUP_DATA_FILE || bak->files[id].id != page_id.file) {
            continue;
        }

        if (bak->is_noparal_version || bak->files[id].sec_end == 0) {
            bak->files[id].sec_start = 0;
            bak->files[id].sec_id = 0;
            if (head->attr.compress != COMPRESS_NONE) {
                bak->files[id].sec_end = SIZE_T(8); // max datafile size
            } else {
                bak->files[id].sec_end = bak->files[id].size;
                uint64 fill_page_num = (page_id.file == dw_file_id) ? (DW_SPC_HWM_START - 1) : 1;
                bak->files[id].sec_end += fill_page_num * page_size;
            }
        }

        if (offset < bak->files[id].sec_start || offset >= bak->files[id].sec_end) {
            continue;
        }

        return id;
    }

    return GS_INVALID_ID32;
}

status_t abr_open_bak_file(knl_session_t *session, const char *path, bak_local_t *bak_file, bak_file_type_t file_type,
                           uint32 index, uint32 file_id, uint32 sec_id)
{
    bak_generate_bak_file(session, path, file_type, index, file_id, sec_id, bak_file->name);
    if (cm_open_device(bak_file->name, cm_device_type(bak_file->name), O_BINARY | O_SYNC | O_RDWR, &bak_file->handle) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] failed to open backupset file, path is %s", path);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

/*
 * get rcy point of backup and find backup datafile for corrupted page
 */
static status_t abr_bakfile_contain_page(knl_session_t *session, bak_page_search_t *search_ctx, const char *path,
                                         bak_dependence_t *next_depend)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_local_t *bak_handle = &bak->local;
    bak_head_t *bak_head = NULL;

    /* open backup head file */
    GS_LOG_DEBUG_INF("[ABR] backupset path is %s", path);

    if (abr_open_bak_file(session, path, bak_handle, BACKUP_HEAD_FILE, 0, 0, 0) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (rst_restore_backupset_head(session, GS_TRUE) != GS_SUCCESS) {
        cm_close_device(cm_device_type(bak_handle->name), &bak_handle->handle);
        bak_handle->handle = GS_INVALID_HANDLE;
        return GS_ERROR;
    }
    cm_close_device(cm_device_type(bak_handle->name), &bak_handle->handle);
    bak_handle->handle = GS_INVALID_HANDLE;

    bak_head = (bak_head_t *)bak->backup_buf;
    if (bak_head->depend_num > 0) {
        *next_depend = bak->depends[0];
    } else {
        next_depend->file_dest[0] = '\0';
    }

    uint32 id = abr_bak_index_contain_page(session, bak, bak_head, search_ctx->page_id, search_ctx->page_size);
    if (id != GS_INVALID_ID32) {
        search_ctx->sec_start = bak->files[id].sec_start;
        if (abr_open_bak_file(session, path, bak_handle, BACKUP_DATA_FILE, id,
                              bak->files[id].id, bak->files[id].sec_id) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    cm_close_device(search_ctx->file_type, &search_ctx->handle);       // try to close last bakfile handle
    search_ctx->handle = bak_handle->handle; // search_ctx->handle is closed at abr_clean_search_context
    bak_handle->handle = GS_INVALID_HANDLE;  // bak_handle->handle will not be used
    search_ctx->rcy_point = bak_head->ctrlinfo.rcy_point;

    if (search_ctx->max_rcy_point.asn == GS_INVALID_ASN) {
        knl_panic(bak_head->ctrlinfo.rcy_point.asn != GS_INVALID_ASN);
        search_ctx->max_rcy_point = bak_head->ctrlinfo.rcy_point;
    }

    GS_LOG_RUN_INF("[ABR] backup rcy point [%llu-%u-%u] lfn:%llu in backup %s",
                   (uint64)bak_head->ctrlinfo.rcy_point.rst_id, bak_head->ctrlinfo.rcy_point.asn,
                   bak_head->ctrlinfo.rcy_point.block_id, (uint64)bak_head->ctrlinfo.rcy_point.lfn, path);
    return GS_SUCCESS;
}

static status_t abr_search_page_from_bakfile(knl_session_t *session, bak_page_search_t *search_ctx, bool32 *find)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    int64 file_size;
    uint64 skip_size;
    uint64 offset;
    page_head_t *page_head = NULL;
    uint32 dw_file_id = knl_get_dbwrite_file_id(session);

    if (bak->record.attr.compress != COMPRESS_NONE) {
        if (abr_search_page_from_compress(session, search_ctx, find) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[ABR] failed to search page from compressed file");
            return GS_ERROR;
        }
    } else if (bak->record.attr.level == 1) {
        if (abr_binary_search_bakfile(session, search_ctx, find) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[ABR] failed to binary search page from buckup file");
            return GS_ERROR;
        }
    } else {
        skip_size = (search_ctx->sec_start == 0) ? search_ctx->page_size : search_ctx->sec_start;
        if (search_ctx->page_id.file == dw_file_id && search_ctx->page_id.page != SPACE_ENTRY_PAGE &&
            search_ctx->sec_start == 0) {
            skip_size = (uint64)(DW_SPC_HWM_START - 1) * search_ctx->page_size;
        }
        offset = (uint64)search_ctx->page_id.page * search_ctx->page_size - skip_size;
        file_size = cm_file_size(search_ctx->handle);
        if (file_size < 0 || (offset + search_ctx->page_size) > (uint64)file_size) {
            GS_LOG_RUN_ERR("[ABR] invalid backup file size %lld, page offset is %llu", file_size, offset);
            return GS_ERROR;
        }

        if (cm_read_device(search_ctx->file_type, search_ctx->handle, offset, (void *)search_ctx->read_buf.aligned_buf,
                           search_ctx->page_size) != GS_SUCCESS) {
            return GS_ERROR;
        }
        GS_LOG_DEBUG_INF("[ABR] search_ctx->sec_start %llu, offset %llu", search_ctx->sec_start, offset);

        page_head = (page_head_t *)search_ctx->read_buf.aligned_buf;
        if (page_head->size_units == 0 && AS_PAGID(page_head->id).file == 0 && AS_PAGID(page_head->id).page == 0) {
            /* This page is zero page in full backup, need set find to FALSE */
            *find = GS_FALSE;
        } else {
            *find = GS_TRUE;
        }
    }

    return GS_SUCCESS;
}

status_t abr_search_page_from_backupset(knl_session_t *session, bak_page_search_t *search_ctx, bool32 *find,
                                        const char *bak_path)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_dependence_t next_incr_backup;
    date_t start_time;
    char path[GS_FILE_NAME_BUFFER_SIZE] = { 0 };
    errno_t ret;

    *find = GS_FALSE;
    ret = strcpy_sp(path, GS_FILE_NAME_BUFFER_SIZE, bak_path);
    knl_securec_check(ret);

    while (!(*find)) {
        start_time = cm_now();
        if (abr_bakfile_contain_page(session, search_ctx, path, &next_incr_backup) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (search_ctx->handle != GS_INVALID_HANDLE) {
            if (abr_search_page_from_bakfile(session, search_ctx, find) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
        GS_LOG_RUN_INF("[ABR] page search time %lldms, is found %u, backupset %s",
                       (cm_now() - start_time) / (int32)MICROSECS_PER_MILLISEC, (uint32)(*find), path);

        if (CM_IS_EMPTY_STR(next_incr_backup.file_dest)) {
            break; // no more previous increment backup, current backup is full backup (level 0)
        }
        ret = strcpy_sp(path, GS_FILE_NAME_BUFFER_SIZE, next_incr_backup.file_dest);
        knl_securec_check(ret);
    }

    if (!(*find)) {
        search_ctx->rcy_point = search_ctx->max_rcy_point; // not found in all backups, select max rcy point of backups
    }

    if (abr_open_bak_file(session, bak_path, &bak->local, BACKUP_HEAD_FILE, 0, 0, 0) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (rst_restore_backupset_head(session, GS_TRUE) != GS_SUCCESS) {
        cm_close_file(bak->local.handle);
        bak->local.handle = GS_INVALID_HANDLE;
        return GS_ERROR;
    }
    cm_close_file(bak->local.handle);
    bak->local.handle = GS_INVALID_HANDLE;

    return GS_SUCCESS;
}

/*
 * If input corrupted page is not zero page and its checksum is not 0, we verify its checksum firstly.
 * If failed, we continue repair, otherwise, return GS_SUCCESS
 */
bool32 abr_precheck_corrupted_page(knl_session_t *session, page_id_t page_id)
{
    datafile_t *df = DATAFILE_GET(session, page_id.file);
    int32 handle = GS_INVALID_HANDLE;
    int64 offset = (int64)page_id.page * DEFAULT_PAGE_SIZE(session);
    char *buf = (char *)cm_push(session->stack, (uint32)(DEFAULT_PAGE_SIZE(session) + GS_MAX_ALIGN_SIZE_4K));
    page_head_t *page = (page_head_t *)cm_aligned_buf(buf);

    if (spc_read_datafile(session, df, &handle, offset, page, DEFAULT_PAGE_SIZE(session)) != GS_SUCCESS) {
        spc_close_datafile(df, &handle);
        cm_pop(session->stack);
        return GS_FALSE;
    }
    spc_close_datafile(df, &handle);

    if (PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session)) != GS_INVALID_CHECKSUM &&
        page_verify_checksum(page, DEFAULT_PAGE_SIZE(session))) {
        GS_LOG_RUN_WAR("[ABR] input page is not corrupted, block recover will not continue");
        cm_pop(session->stack);
        return GS_TRUE;
    }

    cm_pop(session->stack);
    return GS_FALSE;
}

status_t abr_repair_page_from_backup(knl_session_t *session, bak_page_search_t *search_ctx, const char *path)
{
    page_id_t page_id;
    page_head_t *page = (page_head_t *)search_ctx->read_buf.aligned_buf;
    log_point_t rcy_point;
    bool32 find = GS_FALSE;
    date_t start_time = cm_now();
    errno_t ret;

    if (abr_search_page_from_backupset(session, search_ctx, &find, path) != GS_SUCCESS) {
        return GS_ERROR;
    }

    page_id = search_ctx->page_id;
    rcy_point = search_ctx->rcy_point;

    GS_LOG_RUN_INF("[ABR] total search time %lldms, is found %u",
                   (cm_now() - start_time) / (int32)MICROSECS_PER_MILLISEC, (uint32)find);

    if (find) {
        if (PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session)) != GS_INVALID_CHECKSUM &&
            !page_verify_checksum(page, DEFAULT_PAGE_SIZE(session))) {
            GS_THROW_ERROR(ERR_CHECKSUM_FAILED, path);
            return GS_ERROR;
        }

        knl_panic_log(IS_SAME_PAGID(AS_PAGID(page->id), page_id),
                      "page's id and page_id are not same, panic info: page's id %u-%u page_id %u-%u type %u",
                      AS_PAGID(page->id).file, AS_PAGID(page->id).page, page_id.file, page_id.page, page->type);
        GS_LOG_RUN_INF("[ABR] find page (%u-%u) in backup", page_id.file, page_id.page);
    } else {
        ret = memset_sp(page, DEFAULT_PAGE_SIZE(session), 0, DEFAULT_PAGE_SIZE(session));
        knl_securec_check(ret);
        GS_LOG_RUN_INF("[ABR] dose not find page (%u-%u) in backup", page_id.file, page_id.page);
    }

    start_time = cm_now();
    if (abr_replay_page_to_latest(session, rcy_point, page_id, page) != GS_SUCCESS) {
        return GS_ERROR;
    }
    GS_LOG_RUN_INF("[ABR] page replay time %lldms, from point [%llu-%u-%u] lfn: %llu",
                   (cm_now() - start_time) / (int32)MICROSECS_PER_MILLISEC, (uint64)rcy_point.rst_id, rcy_point.asn,
                   rcy_point.block_id, (uint64)rcy_point.lfn);

    if (abr_flush_repaired_page(session, page) != GS_SUCCESS) {
        return GS_ERROR;
    }

    GS_LOG_RUN_INF("[ABR] page (%u-%u) repair succesefully, lsn %llu, checksum %u",
                   page_id.file, page_id.page, page->lsn, PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session)));
    return GS_SUCCESS;
}

static void abr_clear_search_context(knl_session_t *session, bak_page_search_t *search_ctx)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;

    cm_close_file(search_ctx->handle);
    search_ctx->handle = GS_INVALID_HANDLE;

    cm_aligned_free(&search_ctx->read_buf);

    if (bak->backup_buf != NULL) {
        free(bak->backup_buf);
        bak->backup_buf = NULL;
        bak->depends = NULL;
        bak->compress_buf = NULL;
        bak->ctrl_backup_buf = NULL;
    }
}

status_t abr_restore_block_recover(knl_session_t *session, knl_restore_t *param)
{
    page_id_t page_id = param->page_need_repair;
    bak_t *bak = &session->kernel->backup_ctx.bak;
    bak_page_search_t search_ctx;

    if (!cm_spin_try_lock(&session->kernel->lock)) {
        GS_THROW_ERROR(ERR_DB_START_IN_PROGRESS);
        return GS_ERROR;
    }

    bak->lfn = param->lfn;
    bak->is_building = GS_FALSE;
    bak->is_first_link = GS_TRUE;
    bak->backup_buf_size = GS_MIN_BACKUP_BUF_SIZE;

    if (cm_text2str(&param->path, bak->record.path, GS_FILE_NAME_BUFFER_SIZE) != GS_SUCCESS) {
        cm_spin_unlock(&session->kernel->lock);
        return GS_ERROR;
    }

    GS_LOG_RUN_INF("[ABR] start reparing corrupted page (file %u, page %u), buckupset path:%s",
                   page_id.file, page_id.page, bak->record.path);

    search_ctx.handle = GS_INVALID_HANDLE;
    search_ctx.page_id = page_id;
    search_ctx.page_size = DEFAULT_PAGE_SIZE(session);
    search_ctx.max_rcy_point.asn = GS_INVALID_ASN;

    if (cm_aligned_malloc((int64)BACKUP_BUFFER_SIZE(bak), "ABR", &search_ctx.read_buf) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)(BACKUP_BUFFER_SIZE(bak)), "page repair");
        GS_LOG_RUN_ERR("[ABR] failed to malloc read buffer");
        cm_spin_unlock(&session->kernel->lock);
        return GS_ERROR;
    }

    if (rst_alloc_resource(session, bak) != GS_SUCCESS) {
        abr_clear_search_context(session, &search_ctx);
        cm_spin_unlock(&session->kernel->lock);
        return GS_ERROR;
    }

    spc_set_space_id(session); // ztrst instance is started as mount, set df->space_id in mount status
    if (abr_repair_page_from_backup(session, &search_ctx, bak->record.path) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[ABR] failed to repair page");
        abr_clear_search_context(session, &search_ctx);
        cm_spin_unlock(&session->kernel->lock);
        return GS_ERROR;
    }

    abr_clear_search_context(session, &search_ctx);
    cm_spin_unlock(&session->kernel->lock);
    return GS_SUCCESS;
}

static status_t abr_replay_file_log(knl_session_t *session, log_point_t rcy_point)
{
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    log_batch_t *batch = NULL;
    bool32 need_more_log = GS_FALSE;
    uint32 data_size;
    uint32 block_size;
    log_point_t curr_point = rcy_point;
    log_point_t lrp_point = dtc_my_ctrl(session)->lrp_point;
    bool32 origin_paral_rcy = rcy->paral_rcy;
    status_t status = GS_SUCCESS;

    session->kernel->db.status = DB_STATUS_RECOVERY;
    session->kernel->redo_ctx.lfn = rcy_point.lfn;
    rcy->paral_rcy = GS_FALSE;
    rcy->is_first_arch_file = GS_TRUE;

    while (rcy_load(session, &curr_point, &data_size, &block_size) == GS_SUCCESS) {
        batch = (log_batch_t*)rcy->read_buf.aligned_buf;
        if (log_need_realloc_buf(batch, &rcy->read_buf, "rcy", GS_MAX_BATCH_SIZE)) {
            continue;
        }
        if (rcy_replay(session, &curr_point, data_size, batch, block_size, &need_more_log,
                       NULL, GS_FALSE) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        if (session->killed || session->force_kill || session->canceled) {
            status = GS_ERROR;
            break;
        }

        if (!need_more_log) {
            break;
        }
    }

    session->kernel->rcy_ctx.is_working = GS_FALSE;
    session->kernel->db.status = DB_STATUS_MOUNT;
    rcy->paral_rcy = origin_paral_rcy;

    if (status == GS_ERROR) {
        return GS_ERROR;
    }

    GS_LOG_RUN_INF("[ABR] replay real end with point [%llu-%u-%u] lfn: %llu",
        (uint64)curr_point.rst_id, curr_point.asn, curr_point.block_id, (uint64)curr_point.lfn);

    if (curr_point.lfn < lrp_point.lfn) {
        GS_THROW_ERROR(ERR_INVALID_RCV_END_POINT,
            curr_point.asn, curr_point.block_id, lrp_point.asn, lrp_point.block_id);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t abr_recover_file_lastest(knl_session_t *session, knl_restore_t *param)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;

    if (bak->record.device == DEVICE_DISK) {
        if (abr_open_bak_file(session, bak->record.path, &bak->local, BACKUP_HEAD_FILE, 0, 0, 0) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (rst_restore_backupset_head(session, GS_FALSE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    log_point_t rcy_point = bak->rst_file.rcy_point;
    log_point_t lrp_point = dtc_my_ctrl(session)->lrp_point;

    GS_LOG_RUN_INF("[ABR] begin to recover file: id %u, from log file:%u, block id:%u, lfn:%llu\n",
        bak->rst_file.file_id, rcy_point.asn, rcy_point.block_id, (uint64)rcy_point.lfn);

    GS_LOG_RUN_INF("[ABR] recovery file: id %u, expected least end with file:%u,point:%u,lfn:%llu",
        bak->rst_file.file_id, lrp_point.asn, lrp_point.block_id, (uint64)lrp_point.lfn);

    if (log_load(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    session->kernel->rcy_ctx.repair_file_id = bak->rst_file.file_id;
    session->kernel->rcy_ctx.is_file_repair = GS_TRUE;
    if (abr_replay_file_log(session, rcy_point) != GS_SUCCESS) {
        session->kernel->rcy_ctx.is_file_repair = GS_FALSE;
        return GS_ERROR;
    }

    session->kernel->rcy_ctx.is_file_repair = GS_FALSE;
    return GS_SUCCESS;
}

static datafile_ctrl_t* abr_get_fileid_by_name(knl_session_t *session, text_t *file_name)
{
    database_ctrl_t *ctrl = (database_ctrl_t *)&session->kernel->db.ctrl;
    datafile_ctrl_t *df_ctrl = NULL;

    for (uint32 i = 0; i < GS_MAX_DATA_FILES; i++) {
        df_ctrl = (datafile_ctrl_t *)db_get_ctrl_item(ctrl->pages, i, sizeof(datafile_ctrl_t),
                                                      ctrl->datafile_segment);
        if (cm_filename_equal(file_name, df_ctrl->name)) {
            return df_ctrl;
        }
    }

    return df_ctrl;
}

static status_t abr_init_rst_info(knl_session_t *session, bak_context_t *ctx, knl_restore_t *param)
{
    datafile_ctrl_t *df_ctrl = NULL;

    if (param->file_repair == GS_INVALID_FILEID) {
        df_ctrl = abr_get_fileid_by_name(session, &param->file_repair_name);
        if (df_ctrl == NULL) {
            GS_THROW_ERROR(ERR_FILE_NOT_EXIST, "database", "specifical");
            return GS_ERROR;
        }

        ctx->bak.rst_file.file_id = df_ctrl->id;
    } else {
        ctx->bak.rst_file.file_id = param->file_repair;
    }

    ctx->bak.rst_file.file_type = RESTORE_DATAFILE;
    ctx->bak.rst_file.exist_repair_file = GS_FALSE;

    return GS_SUCCESS;
}

static inline status_t abr_set_build_completed(knl_session_t *session, bak_t *bak, bool32 is_completed)
{
    session->kernel->db.ctrl.core.build_completed = is_completed;
    if (db_save_core_ctrl(session) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[RESTORE] set build completed failed when repair file: %d", bak->rst_file.file_id);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static inline void abr_recover_fail_clean(knl_session_t *session)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;

    buf_expire_datafile_pages(session, bak->rst_file.file_id);
    bak_unload_tablespace(session);
    bak_end(session, GS_TRUE);
}

static inline void abr_save_recover_file(knl_session_t *session)
{
    session->kernel->db.status = DB_STATUS_RECOVERY;
    session->kernel->rcy_ctx.is_file_repair = GS_TRUE;
    ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_FULL);
    session->kernel->db.status = DB_STATUS_MOUNT;
    session->kernel->rcy_ctx.is_file_repair = GS_FALSE;
}

status_t abr_restore_file_recover(knl_session_t *session, knl_restore_t *param)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    uint32 paral_count = param->parallelism == 0 ? BAK_DEFAULT_PARALLELISM : param->parallelism;

    if (bak_set_running(session, ctx) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_BACKUP_IN_PROGRESS, "restore");
        return GS_ERROR;
    }

    if (abr_init_rst_info(session, ctx, param) != GS_SUCCESS) {
        bak_unset_running(session, ctx);
        return GS_ERROR;
    }

    GS_LOG_RUN_INF("[RESTORE] restore file: %d start, device:%d, policy:%s, paral count %u, path:%s",
        bak->rst_file.file_id, param->device, T2S(&param->policy), paral_count, T2S_EX(&param->path));

    if (abr_set_build_completed(session, bak, GS_FALSE) != GS_SUCCESS) {
        bak_unset_running(session, ctx);
        return GS_ERROR;
    }

    if (rst_prepare(session, param) != GS_SUCCESS) {
        bak_end(session, GS_TRUE);
        return GS_ERROR;
    }

    if (rst_proc(session) != GS_SUCCESS) {
        bak_end(session, GS_TRUE);
        return GS_ERROR;
    }

    GS_LOG_RUN_INF("[RESTORE] recover file: %u start, device:%d, policy:%s, path:%s",
        bak->rst_file.file_id, param->device, T2S(&param->policy), T2S_EX(&param->path));

    if (bak_load_tablespaces(session) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[RECOVERY] recover file %u failed when load tablespace in mount mode", bak->rst_file.file_id);
        abr_recover_fail_clean(session);
        return GS_ERROR;
    }

    if (abr_recover_file_lastest(session, param) != GS_SUCCESS) {
        abr_recover_fail_clean(session);
        return GS_ERROR;
    }

    if (abr_set_build_completed(session, bak, GS_TRUE) != GS_SUCCESS) {
        abr_recover_fail_clean(session);
        return GS_ERROR;
    }

    GS_LOG_RUN_INF("[RECOVERY] recovery file %u success", bak->rst_file.file_id);
    abr_save_recover_file(session);
    bak_unload_tablespace(session);
    bak_end(session, GS_TRUE);
    return GS_SUCCESS;
}

static bool32 ctabr_page_support_log_type(log_type_t log_type)
{
    if (RD_TYPE_IS_ENTER_PAGE(log_type) || RD_TYPE_IS_LEAVE_PAGE(log_type)) {
        return GS_TRUE;
    }

    switch (log_type) {
        case RD_SPC_CREATE_SPACE:
        case RD_SPC_CREATE_DATAFILE:
        case RD_SPC_INIT_MAP_HEAD:
        case RD_SPC_INIT_MAP_PAGE:
        case RD_SPC_CONCAT_EXTENT:
        case RD_HEAP_CHANGE_LIST:
        case RD_HEAP_SET_MAP:
        case RD_HEAP_CONCAT_PAGE:
        case RD_HEAP_FORMAT_PAGE:
        case RD_HEAP_FORMAT_MAP:
        case RD_HEAP_FORMAT_ENTRY:
        case RD_BTREE_FORMAT_PAGE:
        case RD_BTREE_INIT_ENTRY:
        case RD_BTREE_CHANGE_CHAIN:
        case RD_BTREE_NEXT_DEL_PAGE:
        case RD_BTREE_SET_RECYCLE:
        case RD_BTREE_RECYCLE_PAGE:
        case RD_BTREE_CONCAT_DEL_PAGE:
        case RD_LOB_PAGE_INIT:
        case RD_LOB_PAGE_EXT_INIT:
        case RD_LOGIC_OPERATION:
        case RD_PUNCH_FORMAT_PAGE:
        case RD_UNDO_CREATE_SEGMENT:
        case RD_UNDO_FORMAT_TXN:
        case RD_UNDO_FORMAT_PAGE:
            return GS_TRUE;
        default:
            return GS_FALSE;
    }

    return GS_FALSE;
}

void ctabr_page_rcy_need_replay(knl_session_t *ct_se, log_entry_t *log_entry, bool32 *replay)
{
    knl_panic(ctabr_page_support_log_type(log_entry->type));

    *replay = TRUE;
}

void ctabr_page_rcy_skip_replay(knl_session_t *ct_se, log_entry_t *log_entry, bool32 *replay)
{
    if (ct_se->curr_page == NULL || ct_se->page_stack.depth == 0) {
        *replay = TRUE;
        return;
    }

    if (!page_type_suport_nolog_insert(((page_head_t*)ct_se->curr_page)->type)) {
        *replay = TRUE;
        return;
    }

    if (!PAGE_IS_SOFT_DAMAGE((page_head_t*)ct_se->curr_page)) {
        *replay = TRUE;
        return;
    }

    knl_panic(page_type_suport_nolog_insert(((page_head_t*)ct_se->curr_page)->type));
    *replay = FALSE;
    return;
}
