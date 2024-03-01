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
 * knl_buffer_access.c
 *
 *
 * IDENTIFICATION
 * src/kernel/buffer/knl_buffer_access.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_buffer_module.h"
#include "knl_buffer_access.h"
#include "knl_buflatch.h"
#include "pcr_heap_scan.h"
#include "knl_abr.h"
#include "dtc_buffer.h"
#include "dtc_drc.h"
#include "dtc_dcs.h"
#include "dtc_context.h"
#include "dtc_recovery.h"
#include "dtc_database.h"

static inline void buf_free_iocb(knl_aio_iocbs_t *buf_iocbs, buf_iocb_t *buf_iocb);

/*
 * initialize async io when kernel starting up
 */
status_t buf_aio_init(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    buf_aio_ctx_t *buf_aio_ctx = &kernel->buf_aio_ctx;
    knl_aio_iocbs_t *knl_iocbs = &kernel->buf_aio_ctx.buf_aio_iocbs;
    buf_iocb_t *buf_iocb = NULL;
    errno_t ret;
    uint32 i;

    /* setup aio context */
    ret = memset_sp(buf_aio_ctx, sizeof(buf_aio_ctx_t), 0, sizeof(buf_aio_ctx_t));
    knl_securec_check(ret);

    if (cm_aio_setup(&kernel->aio_lib, BUF_IOCBS_MAX_NUM, &buf_aio_ctx->io_ctx) != CT_SUCCESS) {
        CT_LOG_RUN_WAR("[BUFFER]: setup asynchronous I/O context failed, errno %d", errno);
        return CT_ERROR;
    }

    /* allocate and initialize kernel iocbs */
    knl_iocbs->iocbs = (buf_iocb_t *)kernel->attr.buf_iocbs;
    ret = memset_sp(knl_iocbs->iocbs, sizeof(buf_iocb_t) * BUF_IOCBS_MAX_NUM, 0,
                    sizeof(buf_iocb_t) * BUF_IOCBS_MAX_NUM);
    knl_securec_check(ret);

    cm_spin_lock(&knl_iocbs->lock, NULL);
    for (i = 0; i < BUF_IOCBS_MAX_NUM - 1; i++) {
        buf_iocb = &knl_iocbs->iocbs[i];
        buf_iocb->next = &knl_iocbs->iocbs[i + 1];
    }
    knl_iocbs->last = &knl_iocbs->iocbs[BUF_IOCBS_MAX_NUM - 1];
    knl_iocbs->first = knl_iocbs->iocbs;
    knl_iocbs->count = BUF_IOCBS_MAX_NUM;
    cm_spin_unlock(&knl_iocbs->lock);

    return CT_SUCCESS;
}

/*
 * async io thread processing, waiting async io event completely and handle it
 */
void buf_aio_proc(thread_t *thread)
{
    knl_instance_t *kernel = (knl_instance_t *)thread->argument;
    buf_aio_ctx_t *buf_aio_ctx = &kernel->buf_aio_ctx;
    knl_aio_iocbs_t *buf_iocbs = &buf_aio_ctx->buf_aio_iocbs;
    cm_io_event_t *events = NULL;
    buf_iocb_t *buf_iocb = NULL;
    int32 aio_ret, i;
    uint32 size;

    cm_set_thread_name("buf async prefetch");
    CT_LOG_RUN_INF("buffer async io thread started");

    size = sizeof(cm_io_event_t) * BUF_IOCBS_MAX_NUM;
    events = (cm_io_event_t *)malloc(size);
    if (events == NULL) {
        CT_LOG_RUN_WAR("[BUFFER]failed to allocate memory for aio events");
        return;
    }

    while (!thread->closed) {
        if (cm_aio_getevents(&kernel->aio_lib, buf_aio_ctx->io_ctx, 1, BUF_IOCBS_MAX_NUM,
                             events, &aio_ret) != CT_SUCCESS) {
            continue;
        }

        for (i = 0; i < aio_ret; i++) {
            /* read of a iocb completely, handle event */
            buf_iocb = (buf_iocb_t *)events[i].obj;
            ((cm_io_callback_t)(events[i].data))(buf_aio_ctx->io_ctx, events[i].obj, events[i].res, events[i].res2);

            /* release buffer iocb and large pool page */
            if (buf_iocb->large_pool_id != CT_INVALID_ID32) {
                mpool_free_page(kernel->attr.large_pool, buf_iocb->large_pool_id);
            }
            buf_free_iocb(buf_iocbs, buf_iocb);
        }
    }
    free(events);
    cm_aio_destroy(&kernel->aio_lib, buf_aio_ctx->io_ctx);
    CT_LOG_RUN_INF("buffer async io thread closed");
}

static inline bool32 buf_changed_verifiable(knl_session_t *session, buf_ctrl_t *ctrl, latch_mode_t mode,
                                            uint8 options)
{
    return (bool32)((mode == LATCH_MODE_X) && !ctrl->is_readonly && !(options & ENTER_PAGE_NO_READ));
}

static bool32 buf_verify_checksum(knl_session_t *session, page_head_t *page, page_id_t page_id)
{
    datafile_t *df = NULL;
    space_t *space = NULL;

    /* curr page may be all zero page,can't use PAGE_TAIL or PAGE_SIZE */
    if (PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session)) == CT_INVALID_CHECKSUM) {
        return CT_TRUE;
    }

    /*
     * nologging table has no redo, so its page maybe partial when db restart and crc maybe not match,
     * but it does not matter, because we will discard its data, so skip crc check.
     */
    if (!SPC_IS_LOGGING_BY_PAGEID(session, page_id)) {
        return CT_TRUE;
    }

    if (!page_verify_checksum(page, DEFAULT_PAGE_SIZE(session))) {
        df = DATAFILE_GET(session, page_id.file);
        space = SPACE_GET(session, df->space_id);
        CT_LOG_RUN_ERR("[BUFFER] page %u-%u corrupted: "
                       "checksum level %s, checksum %u, page size %u, "
                       "page type %s, space name %s, datafile name %s",
                       page_id.file, page_id.page, knl_checksum_level(g_cks_level),
                       PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session)), PAGE_SIZE(*page),
                       page_type(page->type), space->ctrl->name, df->ctrl->name);
        return CT_FALSE;
    }

    return CT_TRUE;
}

static bool32 buf_verify_compress_checksum(knl_session_t *session, page_head_t *page, page_id_t page_id)
{
    datafile_t *df = NULL;
    space_t *space = NULL;

    /* curr page may be all zero page,can't use checksum */
    if (COMPRESS_PAGE_HEAD(page)->checksum == CT_INVALID_CHECKSUM) {
        return CT_TRUE;
    }

    if (!page_compress_verify_checksum(page, DEFAULT_PAGE_SIZE(session))) {
        df = DATAFILE_GET(session, page_id.file);
        space = SPACE_GET(session, df->space_id);
        CT_LOG_RUN_ERR("[BUFFER] page %u-%u corrupted: "
                       "checksum level %s, checksum %u, page size %u, "
                       "page type %s, space name %s, datafile name %s",
                       page_id.file, page_id.page, knl_checksum_level(g_cks_level),
                       COMPRESS_PAGE_HEAD(page)->checksum, PAGE_SIZE(*page),
                       page_type(page->type), space->ctrl->name, df->ctrl->name);
        return CT_FALSE;
    }

    return CT_TRUE;
}


bool32 buf_check_load_page(knl_session_t *session, page_head_t *page, page_id_t page_id, bool32 is_backup_process)
{
    if (!DB_IS_CHECKSUM_OFF(session) && !buf_verify_checksum(session, page, page_id)) {
        CT_LOG_RUN_ERR("[BUFFER] page checksum failed when load page");
        return CT_FALSE;
    }

    /* nothing to do for zero page */
    if (PAGE_SIZE(*page) == 0 && page->lsn == 0) {
        return CT_TRUE;
    }

    if (page->pcn != PAGE_TAIL(page)->pcn) {
        CT_LOG_RUN_ERR("[BUFFER] page_head pcn %u doesn't match with page_tail pcn %u",
                       (uint32)page->pcn, (uint32)PAGE_TAIL(page)->pcn);
        return CT_FALSE;
    }

    if (!IS_SAME_PAGID(AS_PAGID(page->id), page_id)) {
        CT_LOG_RUN_ERR("[BUFFER] read page_id %u-%u doesn't match with expected page_id %u-%u",
                       (uint32)AS_PAGID(page->id).file, (uint32)AS_PAGID(page->id).page,
                       (uint32)page_id.file, (uint32)page_id.page);
        return CT_FALSE;
    }

    /* must after checksum verify */
    if (!is_backup_process && page->encrypted) {
        if (page_decrypt(session, page) != CT_SUCCESS) {
            return CT_FALSE;
        }
    }
    return CT_TRUE;
}

bool32 buf_check_remote_root_page(knl_session_t *session, page_head_t *page)
{
    if (PAGE_SIZE(*page) > DEFAULT_PAGE_SIZE(session)) {
        return CT_FALSE;
    }

    if (page->pcn != PAGE_TAIL(page)->pcn) {
        CT_LOG_RUN_ERR("[BUFFER] page_head pcn %u doesn't match with page_tail pcn %u",
                       (uint32)page->pcn, (uint32)PAGE_TAIL(page)->pcn);
        return CT_FALSE;
    }
    return CT_TRUE;
}

status_t buf_load_page_from_disk(knl_session_t *session, buf_ctrl_t *ctrl, page_id_t page_id)
{
    datafile_t *df = DATAFILE_GET(session, page_id.file);
    int32 *handle = DATAFILE_FD(session, page_id.file);
    space_t *space = SPACE_GET(session, df->space_id);
    int64 offset;
    uint64 lsn = dtc_get_ctrl_lsn(ctrl);

    if (!DATAFILE_IS_ONLINE(df) || df->space_id >= CT_MAX_SPACES ||
        DF_FILENO_IS_INVAILD(df) || space->is_empty) {
        tx_record_sql(session);
        CT_LOG_RUN_ERR("[BUFFER] offlined tablespace %u or datafile of page_id %u-%u",
                       df->space_id, (uint32)page_id.file, (uint32)page_id.page);
        char *space_name = df->space_id >= CT_MAX_SPACES ? "invalid space" : space->ctrl->name;
        CT_THROW_ERROR(ERR_SPACE_OFFLINE, space_name, "buf load page failed");
        return CT_ERROR;
    }

    offset = (int64)page_id.page * DEFAULT_PAGE_SIZE(session);
    knl_begin_session_wait(session, DB_FILE_SEQUENTIAL_READ, CT_TRUE);

    if (spc_read_datafile(session, df, handle, offset, ctrl->page, DEFAULT_PAGE_SIZE(session)) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BUFFER] failed to read datafile %s, offset %lld, size %u, error code %d",
                       df->ctrl->name, offset, DEFAULT_PAGE_SIZE(session), errno);
        spc_close_datafile(df, handle);
        knl_end_session_wait(session, DB_FILE_SEQUENTIAL_READ);
        return CT_ERROR;
    }

    knl_end_session_wait(session, DB_FILE_SEQUENTIAL_READ);

    /* generally, one session can not wait for more than 0xffffffffffffffff us */
    session->stat->disk_read_time += session->wait_pool[DB_FILE_SEQUENTIAL_READ].usecs;
    session->stat->disk_reads++;

    if (SECUREC_UNLIKELY(ctrl->page->type == PAGE_TYPE_UNDO)) {
        session->stat->undo_disk_reads++;
    }

    cm_atomic_inc(&session->kernel->total_io_read);
    g_knl_callback.accumate_io(session, IO_TYPE_READ);

    if (!buf_check_load_page(session, ctrl->page, page_id, CT_FALSE)) {
        /* record alarm log if repair failed */
        CT_LOG_ALARM(WARN_PAGECORRUPTED, "{'page-type':'%s','space-name':'%s','file-name':'%s'}",
            page_type(ctrl->page->type), space->ctrl->name, df->ctrl->name);

        if (PAGE_IS_HARD_DAMAGE(ctrl->page)) {
            ctrl->page->lsn = 0;
        }
        CT_THROW_ERROR(ERR_PAGE_CORRUPTED, page_id.file, page_id.page);
        return CT_ERROR;
    }

    knl_panic(lsn <= ctrl->page->lsn || DAAC_SESSION_IN_RECOVERY(session));

    return CT_SUCCESS;
}

bool32 buf_check_load_compress_page(knl_session_t *session, page_head_t *page, page_id_t page_id)
{
    if (!DB_IS_CHECKSUM_OFF(session) && !buf_verify_compress_checksum(session, page, page_id)) {
        CT_LOG_RUN_ERR("[BUFFER] page checksum failed when load compress page");
        return CT_FALSE;
    }

    /* nothing to do for zero page */
    if (PAGE_SIZE(*page) == 0 && page->lsn == 0) {
        return CT_TRUE;
    }

    if (!IS_SAME_PAGID(AS_PAGID(page->id), page_id)) {
        CT_LOG_RUN_ERR("[BUFFER] read page_id %u-%u doesn't match with expected page_id %u-%u",
                       (uint32)AS_PAGID(page->id).file, (uint32)AS_PAGID(page->id).page,
                       (uint32)page_id.file, (uint32)page_id.page);
        return CT_FALSE;
    }

    return CT_TRUE;
}

status_t buf_decompress_group(knl_session_t *session, char *dst, const char *src, uint32 *size)
{
    size_t actual_size;
    uint32 remaining_size, zsize;
    uint32 dst_offset, src_offset;
    compress_page_head_t group_head = { 0 };
    errno_t ret;
    pcb_assist_t pcb_assist;

    if (pcb_get_buf(session, &pcb_assist) != CT_SUCCESS) {
        return CT_ERROR;
    }
    group_head.compressed_size = COMPRESS_PAGE_HEAD(src)->compressed_size;
    group_head.compress_algo = COMPRESS_PAGE_HEAD(src)->compress_algo;
    group_head.group_cnt = COMPRESS_PAGE_HEAD(src)->group_cnt;
    remaining_size = group_head.compressed_size;
    zsize = COMPRESS_PAGE_VALID_SIZE(session);
    dst_offset = 0;
    src_offset = DEFAULT_PAGE_SIZE(session) - zsize;
    *size = 0;
    do {
        if (remaining_size > zsize) {
            actual_size = zsize;
        } else {
            actual_size = remaining_size;
        }

        ret = memcpy_sp((char *)pcb_assist.aligned_buf + dst_offset, DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT,
            (char *)src + src_offset, actual_size);
        knl_securec_check(ret);
        remaining_size -= actual_size;
        dst_offset += actual_size;
        src_offset += actual_size + DEFAULT_PAGE_SIZE(session) - zsize;
    } while (remaining_size != 0);

    if (group_head.compress_algo == COMPRESS_ZSTD) {
        actual_size = ZSTD_decompress(dst, DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT, pcb_assist.aligned_buf,
            group_head.compressed_size);
        if (ZSTD_isError(actual_size)) {
            CT_LOG_RUN_ERR("[BUFFER] failed to decompress(zstd) group, first page %u-%u, error code: %lu, reason: %s",
                AS_PAGID_PTR(((page_head_t *)src)->id)->file, AS_PAGID_PTR(((page_head_t *)src)->id)->page,
                actual_size, ZSTD_getErrorName(actual_size));
            CT_THROW_ERROR(ERR_DECOMPRESS_ERROR, "zstd", actual_size, ZSTD_getErrorName(actual_size));
            return CT_ERROR;
        }
    } else {
        knl_panic_log(CT_FALSE, "compress algorithm %d not supported", group_head.compress_algo);
    }

    pcb_release_buf(session, &pcb_assist);
    *size = (uint32)actual_size; // decompress size always equals 64K，convert is safe
    return CT_SUCCESS;
}

static status_t buf_construct_group_members(knl_session_t *session, buf_ctrl_t *head_ctrl, const char *src)
{
    datafile_t *df = DATAFILE_GET(session, head_ctrl->page_id.file);
    space_t *space = SPACE_GET(session, df->space_id);
    status_t status = CT_SUCCESS;
    buf_ctrl_t *ctrl = NULL;

    for (int32 i = (PAGE_GROUP_COUNT - 1); i >= 0; i--) {
        ctrl = head_ctrl->compress_group[i];

        BUF_UNPROTECT_PAGE(ctrl->page);
        errno_t ret = memcpy_sp(ctrl->page, DEFAULT_PAGE_SIZE(session),
            src + i * DEFAULT_PAGE_SIZE(session), DEFAULT_PAGE_SIZE(session));
        knl_securec_check(ret);
        ctrl->page->compressed = 0;

        if (!buf_check_load_page(session, ctrl->page, ctrl->page_id, CT_FALSE)) {
            if (!abr_repair_page_from_standy(session, ctrl)) {
                /* record alarm log if repair failed */
                CT_LOG_ALARM(WARN_PAGECORRUPTED, "{'page-type':'%s','space-name':'%s','file-name':'%s'}",
                    page_type(ctrl->page->type), space->ctrl->name, df->ctrl->name);
                CT_THROW_ERROR(ERR_PAGE_CORRUPTED, ctrl->page_id.file, ctrl->page_id.page);
                status = CT_ERROR;
                continue; // continue to look other pages' result
            }
        }

#if defined(__arm__) || defined(__aarch64__)
        CM_MFENCE;
#endif

        BUF_PROTECT_PAGE(ctrl->page);
    }

    return status;
}

static status_t buf_construct_group(knl_session_t *session, buf_ctrl_t *head_ctrl, char *read_buf)
{
    pcb_assist_t unzip_pcb_assist;
    bool32 really_compressed;
    char *src = NULL;
    uint32 size;

    /* we need to rely on the actual compression properties of the page
    * to determine whether it needs to be decompressed */
    really_compressed = ((page_head_t *)read_buf)->compressed;
    if (pcb_get_buf(session, &unzip_pcb_assist) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(!really_compressed)) {
        /* Pages are plainly written without compression for some reason */
        src = read_buf;
    } else {
        if (buf_decompress_group(session, unzip_pcb_assist.aligned_buf, read_buf, &size) != CT_SUCCESS) {
            pcb_release_buf(session, &unzip_pcb_assist);
            return CT_ERROR;
        }
        knl_panic_log(size == DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT, "decompress size %u incorrect", size);
        src = unzip_pcb_assist.aligned_buf;
    }

    if (buf_construct_group_members(session, head_ctrl, src) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BUFFER] construct compress group failed");
        pcb_release_buf(session, &unzip_pcb_assist);
        return CT_ERROR;
    }

    pcb_release_buf(session, &unzip_pcb_assist);
    return CT_SUCCESS;
}

status_t buf_check_load_compress_group(knl_session_t *session, page_id_t head_page_id, const char *read_buf)
{
    datafile_t *df = DATAFILE_GET(session, head_page_id.file);
    space_t *space = SPACE_GET(session, df->space_id);
    page_head_t *compress_page = NULL;
    page_id_t page_id = head_page_id;
    status_t status = CT_SUCCESS;

    /* we only verify compress page here */
    if (!((page_head_t *)read_buf)->compressed) {
        return status;
    }

    for (uint16 i = 0; i < PAGE_GROUP_COUNT; i++) {
        compress_page = (page_head_t *)((char *)read_buf + i * DEFAULT_PAGE_SIZE(session));
        if (!buf_check_load_compress_page(session, compress_page, page_id)) {
            CT_THROW_ERROR(ERR_PAGE_CORRUPTED, page_id.file, page_id.page);
            CT_LOG_ALARM(WARN_PAGECORRUPTED, "{'page-type':'%s','space-name':'%s','file-name':'%s'}",
                page_type(compress_page->type), space->ctrl->name, df->ctrl->name);
            status = CT_ERROR;
        }
        page_id.page++;
    }

    return status;
}

static status_t buf_read_and_construct(knl_session_t *session, buf_ctrl_t *head_ctrl)
{
    pcb_assist_t pcb_assist;
    page_id_t head_page = head_ctrl->page_id;
    datafile_t *df = DATAFILE_GET(session, head_page.file);
    int32 *handle = DATAFILE_FD(session, head_page.file);
    int64 offset  = (int64)head_page.page * DEFAULT_PAGE_SIZE(session);

    space_t *space = SPACE_GET(session, df->space_id);
    if (!SPACE_IS_ONLINE(space) || !DATAFILE_IS_ONLINE(df)) {
        CT_LOG_RUN_ERR("[BUFFER] offlined tablespace or datafile of page_id %u-%u",
            (uint32)head_page.file, (uint32)head_page.page);
        CT_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "buf load page failed");
        return CT_ERROR;
    }

    if (pcb_get_buf(session, &pcb_assist) != CT_SUCCESS) {
        return CT_ERROR;
    }

    knl_begin_session_wait(session, DB_FILE_SCATTERED_READ, CT_TRUE);
    if (spc_read_datafile(session, df, handle, offset, pcb_assist.aligned_buf,
                          DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BUFFER] failed to read datafile %s, offset %lld, size %u, error code %d",
            df->ctrl->name, offset, DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT, errno);
        spc_close_datafile(df, handle);
        knl_end_session_wait(session, DB_FILE_SCATTERED_READ);
        pcb_release_buf(session, &pcb_assist);
        return CT_ERROR;
    }
    knl_end_session_wait(session, DB_FILE_SCATTERED_READ);

    session->stat->disk_read_time += session->wait_pool[DB_FILE_SCATTERED_READ].usecs;
    session->stat->disk_reads++;

    if (SECUREC_UNLIKELY(head_ctrl->page->type == PAGE_TYPE_UNDO)) {
        session->stat->undo_disk_reads++;
    }

    cm_atomic_inc(&session->kernel->total_io_read);
    g_knl_callback.accumate_io(session, IO_TYPE_READ);

    if (buf_check_load_compress_group(session, head_ctrl->page_id, pcb_assist.aligned_buf) != CT_SUCCESS) {
        pcb_release_buf(session, &pcb_assist);
        return CT_ERROR;
    }

    if (buf_construct_group(session, head_ctrl, pcb_assist.aligned_buf) != CT_SUCCESS) {
        pcb_release_buf(session, &pcb_assist);
        return CT_ERROR;
    }

    pcb_release_buf(session, &pcb_assist);
    return CT_SUCCESS;
}

static inline void buf_load_update_status(knl_session_t *session, buf_ctrl_t *head_ctrl, status_t read_status)
{
    if (SECUREC_UNLIKELY(read_status != CT_SUCCESS)) {
        for (int32 i = PAGE_GROUP_COUNT - 1; i >= 0; i--) {
            head_ctrl->compress_group[i]->load_status = BUF_LOAD_FAILED;
        }
    } else {
        for (int32 i = PAGE_GROUP_COUNT - 1; i >= 0; i--) {
            head_ctrl->compress_group[i]->load_status = BUF_IS_LOADED;
            head_ctrl->compress_group[i]->force_request = 0;
        }
    }
}

inline status_t buf_load_group(knl_session_t *session, buf_ctrl_t *ctrl)
{
    status_t status;
    buf_ctrl_t *head_ctrl = ctrl->compress_group[0];

    status = buf_read_and_construct(session, head_ctrl);
    buf_load_update_status(session, head_ctrl, status);
    return status;
}

void buf_aio_prefetch_compress(knl_session_t *session, char *read_buf, buf_ctrl_t *head_ctrl, uint32 large_pool_id,
    bool8 is_completed)
{
    status_t status;
    knl_panic_log(PAGE_IS_COMPRESS_HEAD(head_ctrl->page_id),
                  "invalid next extent page id in bitmap file, file:%d, page:%d.",
                  head_ctrl->page_id.file, head_ctrl->page_id.page);

    if (large_pool_id == CT_INVALID_ID32 || !is_completed) {
        status = CT_ERROR;
    } else if (buf_check_load_compress_group(session, head_ctrl->page_id, read_buf) != CT_SUCCESS) {
        status = CT_ERROR;
    } else {
        status = buf_construct_group(session, head_ctrl, read_buf);
    }
    buf_load_update_status(session, head_ctrl, status);

    BUF_PROTECT_PAGE(head_ctrl->page);
    buf_unlatch(session, head_ctrl, CT_TRUE);
}

void buf_aio_prefetch_normal(knl_session_t *session, const char *read_buf, buf_ctrl_t *ctrl, uint32 large_pool_id,
    bool8 is_completed)
{
    errno_t ret;

    if (large_pool_id == CT_INVALID_ID32 || !is_completed) {
        ctrl->load_status = (uint8)BUF_LOAD_FAILED;
        buf_unlatch(session, ctrl, CT_TRUE);
        return;
    }

    BUF_UNPROTECT_PAGE(ctrl->page);
    ret = memcpy_sp(ctrl->page, DEFAULT_PAGE_SIZE(session), read_buf, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);

    if (!buf_check_load_page(session, ctrl->page, ctrl->page_id, CT_FALSE)) {
        if (!abr_repair_page_from_standy(session, ctrl)) {
            ctrl->load_status = (uint8)BUF_LOAD_FAILED;
            buf_unlatch(session, ctrl, CT_TRUE);
            return;
        }
    }

    BUF_PROTECT_PAGE(ctrl->page);
    ctrl->load_status = (uint8)BUF_IS_LOADED;
    ctrl->force_request = 0;
    buf_unlatch(session, ctrl, CT_TRUE);
}

/*
 * async prefetch callback function
 * if read completely, copy page from large pool to data buffer
 */
void buf_aio_prefetch_ext_callback(cm_io_context_t ctx, cm_iocb_t *iocb, long res, long res2)
{
    buf_iocb_t *buf_iocb = (buf_iocb_t *)iocb;
    knl_session_t *session = buf_iocb->session;
    char *read_buf = buf_iocb->large_buf;
    buf_ctrl_t **ctrls = buf_iocb->ctrls;
    uint32 i, skip;
    bool8 is_completed = CT_TRUE;

    if (res != buf_iocb->page_cnt * DEFAULT_PAGE_SIZE(session)) {
        CT_LOG_RUN_WAR("[BUFFER] failed to read page by async io: res: %ld, error code: %d, page_id:%u-%u",
            res, errno, (uint32)ctrls[0]->page_id.file, ctrls[0]->page_id.page);
        is_completed = CT_FALSE;
    }

    for (i = 0; i < buf_iocb->page_cnt; i += skip) {
        skip = 1;
        if (ctrls[i] == NULL) {
            continue;
        }

        if (page_compress(session, ctrls[i]->page_id)) {
            buf_aio_prefetch_compress(session, read_buf + i * DEFAULT_PAGE_SIZE(session),
                                      ctrls[i], buf_iocb->large_pool_id, is_completed);
            skip = PAGE_GROUP_COUNT; // skip all the group
        } else {
            buf_aio_prefetch_normal(session, read_buf + i * DEFAULT_PAGE_SIZE(session),
                                    ctrls[i], buf_iocb->large_pool_id, is_completed);
        }
    }
}

#define BUF_AIO_TRY_TIMES 1000
static buf_iocb_t* buf_alloc_iocb(knl_aio_iocbs_t *iocbs)
{
    buf_iocb_t *iocb = NULL;
    uint32 count = 0;

    for (;;) {
        cm_spin_lock(&iocbs->lock, NULL);
        if (iocbs->count <= 1) {
            cm_spin_unlock(&iocbs->lock);

            if (SECUREC_UNLIKELY(count > BUF_AIO_TRY_TIMES)) {
                break;
            }
            cm_spin_sleep();
            count++;
            continue;
        }
        iocb = iocbs->first;
        iocb->used = 1;
        iocbs->first = iocbs->first->next;
        iocbs->count--;
        iocb->next = NULL;
        cm_spin_unlock(&iocbs->lock);
        break;
    }
    return iocb;
}

static void buf_aio_prefetch_ext_prepare(knl_session_t *session, buf_iocb_t *buf_iocb, page_id_t curr_page,
                                         uint32 count, char *read_buf)
{
    cm_aio_prep_read(&buf_iocb->iocb, *DATAFILE_FD(session, curr_page.file), read_buf,
                     count * DEFAULT_PAGE_SIZE(session), (uint64)(curr_page.page) * DEFAULT_PAGE_SIZE(session));
    cm_aio_set_callback(&buf_iocb->iocb, buf_aio_prefetch_ext_callback);

    buf_iocb->large_buf = read_buf;
    buf_iocb->page_id.file = curr_page.file;
    buf_iocb->page_id.page = curr_page.page;
    buf_iocb->page_cnt = count;
    buf_iocb->session = session->kernel->sessions[SESSION_ID_AIO];
}

static inline void buf_free_iocb(knl_aio_iocbs_t *buf_iocbs, buf_iocb_t *buf_iocb)
{
    cm_spin_lock(&buf_iocbs->lock, NULL);
    buf_iocb->used = 0;
    buf_iocbs->last->next = buf_iocb;
    buf_iocbs->last = buf_iocb;
    buf_iocbs->count++;
    cm_spin_unlock(&buf_iocbs->lock);
}

static void buf_aio_prefetch_clean_status(knl_session_t *session, buf_ctrl_t *ctrl, uint32 *skip)
{
    if (ctrl->load_status != (uint8)BUF_IS_LOADED) {
        if (page_compress(session, ctrl->page_id)) {
            *skip = PAGE_GROUP_COUNT;
            buf_load_update_status(session, ctrl, CT_ERROR);
        } else {
            ctrl->load_status = (uint8)BUF_LOAD_FAILED;
        }
    }
    buf_unlatch(session, ctrl, CT_TRUE);
}

/*
 * if prefetch failed, we need to release large pages and buffer ctrls that have been allocated
 */
static void buf_aio_prefetch_clean(knl_session_t *session, uint32 *mpool_pages, cm_iocb_t **iocbs,
    uint32 read_times, uint32 page_cnt_per_time, buf_ctrl_t *first_ctrl)
{
    buf_iocb_t *iocb = NULL;
    buf_ctrl_t *ctrl = NULL;
    uint32 i, j, skip;

    for (i = 0; i < read_times; i++) {
        if (mpool_pages != NULL) {
            mpool_free_page(session->kernel->attr.large_pool, mpool_pages[i]);
        }

        iocb = (buf_iocb_t *)iocbs[i];
        for (j = 0; j < page_cnt_per_time; j += skip) {
            skip = 1;
            ctrl = iocb->ctrls[j];
            /* skip the first page in the extent */
            if (ctrl == NULL || ctrl->page == first_ctrl->page) {
                continue;
            }

            buf_aio_prefetch_clean_status(session, ctrl, &skip);
        }

        buf_free_iocb(&session->kernel->buf_aio_ctx.buf_aio_iocbs, iocb);
    }
}

static status_t buf_aio_submit(knl_session_t *session, datafile_t *df, uint32 read_times, cm_iocb_t **iocbs)
{
    space_t *space = SPACE_GET(session, df->space_id);
    if (!SPACE_IS_ONLINE(space) || !DATAFILE_IS_ONLINE(df)) {
        CT_LOG_RUN_WAR("[BUFFER] tablespace has been dropped");
        return CT_ERROR;
    }

    /* submit prefetch request */
    if (cm_aio_submit(&session->kernel->aio_lib, session->kernel->buf_aio_ctx.io_ctx,
        (int32)read_times, iocbs) != CT_SUCCESS) {
        CT_LOG_RUN_WAR("[BUFFER] failed to submit aio, error code: %d", errno);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static void buf_aio_alloc_ctrls(knl_session_t *session, buf_ctrl_t *ctrl, page_id_t curr_page,
    uint32 page_cnt_per_time, buf_iocb_t *buf_iocb)
{
    page_id_t page_id = curr_page;

    if (page_compress(session, ctrl->page_id)) {
        knl_panic_log(PAGE_IS_COMPRESS_HEAD(ctrl->page_id),
            "Invalid next extent page id in bitmap file, file:%u, page:%u.", ctrl->page_id.file, ctrl->page_id.page);
        knl_panic_log(page_cnt_per_time % PAGE_GROUP_COUNT == 0,
            "Invalid bitmap file extent size %u.", page_cnt_per_time);
        for (uint32 j = 0; j < page_cnt_per_time; j++) {
            page_id.page = curr_page.page + j;
            if (page_id.page == ctrl->page_id.page) {
                buf_iocb->ctrls[j] = ctrl;
            } else if (PAGE_IS_COMPRESS_HEAD(page_id)) {
                buf_iocb->ctrls[j] = buf_try_alloc_compress(session, page_id, LATCH_MODE_S,
                    ENTER_PAGE_NORMAL, BUF_ADD_OLD);
            } else {
                buf_iocb->ctrls[j] = NULL;  // we only store the ctrl of group-head-page
            }
        }
    } else {
        for (uint32 j = 0; j < page_cnt_per_time; j++) {
            page_id.page = curr_page.page + j;
            if (page_id.page == ctrl->page_id.page) {
                buf_iocb->ctrls[j] = ctrl;
            } else {
                buf_iocb->ctrls[j] = buf_try_alloc_ctrl(session, page_id, LATCH_MODE_S,
                    ENTER_PAGE_NORMAL, BUF_ADD_OLD);
            }
        }
    }
}

/*
 * prefetch extent in background with async io, including 3 steps:
 * 1.partition extent to several prefetch uints, each of which is manged by a buffer iocb.
 * 2.for each buffer iocb, allocate large pool page and buffer ctrls, setup prefetch info and callback function.
 * 3.submit all async read at the same time.
 */
static status_t buf_aio_prefetch_ext(knl_session_t *session, buf_ctrl_t *ctrl, uint32 extent_size)
{
    datafile_t *df = DATAFILE_GET(session, ctrl->page_id.file);
    buf_iocb_t *buf_iocb = NULL;
    uint32 max_cnt = CT_LARGE_PAGE_SIZE / DEFAULT_PAGE_SIZE(session);
    uint32 page_cnt_per_time = extent_size < max_cnt ? extent_size : max_cnt;
    uint32 read_times = extent_size / page_cnt_per_time;
    
    if (spc_open_datafile(session, df, DATAFILE_FD(session, ctrl->page_id.file)) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[SPACE] failed to open datafile %s", df->ctrl->name);
        return CT_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    uint32 *mpool_pages = (uint32 *)cm_push(session->stack, sizeof(uint32) * read_times);
    char **read_buf = (char **)cm_push(session->stack, sizeof(char*) * read_times);
    cm_iocb_t **iocbs = (cm_iocb_t **)cm_push(session->stack, sizeof(struct iocb*) * read_times);

    page_id_t curr_page = ctrl->page_id;
    for (uint32 i = 0; i < read_times; i++) {
        /* alloc read buffer from large pool */
        mpool_pages[i] = CT_INVALID_ID32;
        if (!mpool_try_alloc_page(session->kernel->attr.large_pool, &mpool_pages[i])) {
            CT_LOG_DEBUG_WAR("[BUFFER] no large pool page available");
            buf_aio_prefetch_clean(session, mpool_pages, iocbs, i, page_cnt_per_time, ctrl);
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
        read_buf[i] = mpool_page_addr(session->kernel->attr.large_pool, mpool_pages[i]);

        buf_iocb = buf_alloc_iocb(&session->kernel->buf_aio_ctx.buf_aio_iocbs);
        if (buf_iocb == NULL) {
            CT_LOG_DEBUG_WAR("[BUFFER] no aio resource available");
            buf_aio_prefetch_clean(session, mpool_pages, iocbs, i, page_cnt_per_time, ctrl);
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
        buf_iocb->large_pool_id = mpool_pages[i];
        iocbs[i] = &buf_iocb->iocb;
        buf_aio_prefetch_ext_prepare(session, buf_iocb, curr_page, page_cnt_per_time, read_buf[i]);
        session->stat->aio_reads++;

        /* allocate buffer ctrl for prefetch page */
        buf_aio_alloc_ctrls(session, ctrl, curr_page, page_cnt_per_time, buf_iocb);

        curr_page.page += page_cnt_per_time;
    }

    /* submit prefetch request */
    if (buf_aio_submit(session, df, read_times, iocbs) != CT_SUCCESS) {
        buf_aio_prefetch_clean(session, mpool_pages, iocbs, read_times, page_cnt_per_time, ctrl);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

static status_t buf_aio_prefetch_page(knl_session_t *session, buf_ctrl_t *ctrl)
{
    knl_instance_t *kernel = session->kernel;
    cm_iocb_t **iocbs = (cm_iocb_t **)cm_push(session->stack, sizeof(struct iocb*));

    buf_iocb_t *buf_iocb = buf_alloc_iocb(&kernel->buf_aio_ctx.buf_aio_iocbs);
    if (buf_iocb == NULL) {
        cm_pop(session->stack);
        return CT_ERROR;
    }

    buf_iocb->large_pool_id = CT_INVALID_ID32;
    iocbs[0] = &buf_iocb->iocb;
    buf_iocb->ctrls[0] = ctrl;

    BUF_UNPROTECT_PAGE(ctrl->page);
    buf_aio_prefetch_ext_prepare(session, buf_iocb, ctrl->page_id, 1, (char *)ctrl->page);
    session->stat->aio_reads++;
    
    datafile_t *df = DATAFILE_GET(session, ctrl->page_id.file);
    space_t *space = SPACE_GET(session, df->space_id);
    if (!SPACE_IS_ONLINE(space) || !DATAFILE_IS_ONLINE(df)) {
        buf_aio_prefetch_clean(session, NULL, iocbs, 1, 1, ctrl);
        cm_pop(session->stack);
        return CT_ERROR;
    }

    /* submit prefetch request */
    if (cm_aio_submit(&kernel->aio_lib, kernel->buf_aio_ctx.io_ctx, 1, iocbs) != CT_SUCCESS) {
        buf_aio_prefetch_clean(session, NULL, iocbs, 1, 1, ctrl);
        cm_pop(session->stack);
        return CT_ERROR;
    }

    cm_pop(session->stack);
    return CT_SUCCESS;
}

status_t buf_read_page_asynch(knl_session_t *session, page_id_t page_id)
{
    buf_ctrl_t *ctrl = NULL;
    page_id_t head;
    bool32 is_compress = page_compress(session, page_id);

    if (!session->kernel->attr.enable_asynch) {
        return CT_SUCCESS;
    }

    if (is_compress) {
        head = page_first_group_id(session, page_id);
        ctrl = buf_try_alloc_compress(session, head, LATCH_MODE_S, ENTER_PAGE_NORMAL, BUF_ADD_COLD);
    } else {
        ctrl = buf_try_alloc_ctrl(session, page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL, BUF_ADD_COLD);
    }
    if (ctrl == NULL) {
        return CT_SUCCESS;
    }

    if (ctrl->load_status == (uint8)BUF_IS_LOADED) {
        buf_unlatch(session, ctrl, CT_TRUE);
        return CT_SUCCESS;
    }

    if (is_compress) {
        if (buf_aio_prefetch_ext(session, ctrl, PAGE_GROUP_COUNT) != CT_SUCCESS) {
            if (ctrl->load_status != (uint8)BUF_IS_LOADED) {
                buf_load_update_status(session, ctrl, CT_ERROR);
            }
            buf_unlatch(session, ctrl, CT_TRUE);
            return CT_ERROR;
        }
    } else {
        if (buf_aio_prefetch_page(session, ctrl) != CT_SUCCESS) {
            if (ctrl->load_status != (uint8)BUF_IS_LOADED) {
                ctrl->load_status = (uint8)BUF_LOAD_FAILED;
            }
            buf_unlatch(session, ctrl, CT_TRUE);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}
/*
 * skip prefetch if next extent is invalid or extent has already loaded
 */
status_t buf_try_prefetch_next_ext(knl_session_t *session, buf_ctrl_t *ctrl)
{
    datafile_t *df = DATAFILE_GET(session, ctrl->page_id.file);
    space_t *space = SPACE_GET(session, df->space_id);
    page_id_t next_ext = AS_PAGID(ctrl->page->next_ext);
    buf_ctrl_t *next_ctrl = NULL;
    uint32 extent_size;
    uint32 hwm = space->head->hwms[df->file_no];

    if (SPACE_IS_BITMAPMANAGED(space)) {
        if (IS_INVALID_PAGID(next_ext)) {
            return CT_SUCCESS;
        }
    } else {
        if (!spc_is_extent_first(session, space, ctrl->page_id) || IS_INVALID_PAGID(next_ext)) {
            return CT_SUCCESS;
        }
    }

    if (page_compress(session, next_ext)) {
        next_ctrl = buf_try_alloc_compress(session, next_ext, LATCH_MODE_S, ENTER_PAGE_SEQUENTIAL, BUF_ADD_OLD);
    } else {
        next_ctrl = buf_try_alloc_ctrl(session, next_ext, LATCH_MODE_S, ENTER_PAGE_SEQUENTIAL, BUF_ADD_OLD);
    }
    if (next_ctrl == NULL) {
        return CT_SUCCESS;
    }

    if (next_ctrl->load_status == (uint8)BUF_IS_LOADED) {
        buf_unlatch(session, next_ctrl, CT_TRUE);
        return CT_SUCCESS;
    }

    if (SPACE_IS_BITMAPMANAGED(space)) {
        extent_size = spc_ext_size_by_id((uint8)ctrl->page->ext_size);
        if (SECUREC_UNLIKELY(next_ctrl->page_id.page + extent_size > hwm)) {
            extent_size = spc_ext_size_by_id(0);
        }
    } else {
        extent_size = space->ctrl->extent_size;
    }

    if (buf_aio_prefetch_ext(session, next_ctrl, extent_size) != CT_SUCCESS) {
        if (next_ctrl->load_status != (uint8)BUF_IS_LOADED) {
            if (page_compress(session, next_ctrl->page_id)) {
                buf_load_update_status(session, next_ctrl, CT_ERROR);
            } else {
                next_ctrl->load_status = (uint8)BUF_LOAD_FAILED;
            }
        }
        buf_unlatch(session, next_ctrl, CT_TRUE);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/*
 * When DB recover with gbp, buf_load_page will try load page from GBP at first.
 * If page cannot be loaded from GBP, it will be loaded from disk
 */
static status_t buf_load_page_from_GBP(knl_session_t *session, buf_ctrl_t *ctrl, page_id_t page_id)
{
    gbp_context_t *gbp_ctx = &session->kernel->gbp_context;
    gbp_page_status_e status;
    uint32 lock_id = page_id.page % CT_GBP_RD_LOCK_COUNT;

    cm_spin_lock(&gbp_ctx->buf_read_lock[lock_id], NULL);
    if (!KNL_RECOVERY_WITH_GBP(session->kernel)) {
        cm_spin_unlock(&gbp_ctx->buf_read_lock[lock_id]);
        return CT_ERROR; /* recheck rcy_with_gbp flag, if CT_FALSE, all GBP pages are pulled to local buffer */
    }

    knl_begin_session_wait(session, DB_FILE_GBP_READ, CT_TRUE);
    status = knl_read_page_from_gbp(session, ctrl);
    ctrl->gbp_ctrl->page_status = status;
    knl_end_session_wait(session, DB_FILE_GBP_READ);
    cm_spin_unlock(&gbp_ctx->buf_read_lock[lock_id]);

    if (status == GBP_PAGE_MISS || status == GBP_PAGE_OLD || status == GBP_PAGE_AHEAD) {
        /* page not exists on gbp */
        return CT_ERROR;
    } else {
        knl_panic_log(CHECK_PAGE_PCN(ctrl->page), "page pcn is abnormal, panic info: ctrl_page %u-%u type %u",
                      ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);
        return CT_SUCCESS;
    }
}

/*
 * When DB recover with gbp, current session whether need read page from GBP
 * log analysis session always read page from local disk
 * gbp backround always read page from disk because of it has already pulled page from gbp
 */
static inline bool32 session_need_read_gbp(knl_session_t *session)
{
    if (SESSION_IS_LOG_ANALYZE(session) || SESSION_IS_GBP_BG(session)) {
        return CT_FALSE;
    } else {
        return CT_TRUE;
    }
}

/* If failover with GBP, try load page from GBP. If page is not exists on GBP, load page from disk */
status_t buf_load_page(knl_session_t *session, buf_ctrl_t *ctrl, page_id_t page_id)
{
    status_t status = CT_ERROR;

    knl_panic(!(ctrl->is_edp || ctrl->is_dirty) && (!DB_IS_CLUSTER(session) || DCS_BUF_CTRL_IS_OWNER(session, ctrl)));

    if (SECUREC_UNLIKELY(KNL_RECOVERY_WITH_GBP(session->kernel)) && session_need_read_gbp(session)) {
        ctrl->page->lsn = CT_INVALID_LSN; // reset page lsn to 0 here, because it is not loaded from disk
        status = buf_load_page_from_GBP(session, ctrl, page_id);
    }

    if (status != CT_SUCCESS) {
        status = buf_load_page_from_disk(session, ctrl, page_id);
    }

    if (status != CT_SUCCESS) {
        ctrl->load_status = (uint8)BUF_LOAD_FAILED;
        CT_LOG_RUN_ERR("[BUFFER][%u-%u][buf load page] failed, load_status:%d, lock_mode:%d",
            ctrl->page_id.file, ctrl->page_id.page, ctrl->load_status, ctrl->lock_mode);
    } else {
        ctrl->load_status = (uint8)BUF_IS_LOADED;
        ctrl->force_request = 0;
    }

    return status;
}

static status_t buf_batch_load_pages(knl_session_t *session, char *read_buf, buf_ctrl_t *ctrl, page_id_t begin,
                                     uint32 count, uint8 options)
{
    datafile_t *df = DATAFILE_GET(session, begin.file);
    int32 *handle = DATAFILE_FD(session, begin.file);
    space_t *space = SPACE_GET(session, df->space_id);
    page_id_t page_id = begin;
    buf_ctrl_t **ctrl_array = NULL;
    status_t status = CT_SUCCESS;
    int64 offset;
    uint32 i;
    errno_t ret;

    ctrl_array = (buf_ctrl_t **)cm_push(session->stack, sizeof(buf_ctrl_t *) * count);

    for (i = 0; i < count; i++) {
        page_id.page = begin.page + i;
        if (page_id.page == ctrl->page_id.page) {
            ctrl_array[i] = ctrl;
            continue;
        }

        ctrl_array[i] = buf_try_alloc_ctrl(session, page_id, LATCH_MODE_S, ENTER_PAGE_SEQUENTIAL, BUF_ADD_OLD);
        if (ctrl_array[i] != NULL) {
            knl_panic_log(IS_SAME_PAGID(page_id, ctrl_array[i]->page_id), "the page_id and current ctrl page are not "
                          "same, panic info: ctrl_page %u-%u type %u, page %u-%u", ctrl_array[i]->page_id.file,
                          ctrl_array[i]->page_id.page, ctrl_array[i]->page->type, page_id.file, page_id.page);
        }
    }

    if (DB_IS_CLUSTER(session)) {
        if (dtc_get_share_owner_pages(session, ctrl_array, ctrl, count) != CT_SUCCESS) {
            cm_pop(session->stack);
            CT_LOG_RUN_ERR("[BUFFER][%u-%u][dtc get owner pages] failed", ctrl->page_id.file, ctrl->page_id.page);
            return CT_ERROR;
        }
    }

    do {
        if (options & ENTER_PAGE_NO_READ) {
            break;
        }

        if (!SPACE_IS_ONLINE(space) || !DATAFILE_IS_ONLINE(df)) {
            CT_LOG_RUN_ERR("[BUFFER] offlined tablespace or datafile of page_id %u-%u",
                (uint32)begin.file, (uint32)begin.page);
            CT_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "buf load page failed");
            status = CT_ERROR;
            break;
        }

        offset = (int64)begin.page * DEFAULT_PAGE_SIZE(session);
        knl_begin_session_wait(session, DB_FILE_SCATTERED_READ, CT_TRUE);

        if (spc_read_datafile(session, df, handle, offset, read_buf,
                              DEFAULT_PAGE_SIZE(session) * count) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BUFFER] failed to read datafile %s, offset %lld, size %u, error code %d",
                           df->ctrl->name, offset, DEFAULT_PAGE_SIZE(session) * count, errno);
            spc_close_datafile(df, handle);
            knl_end_session_wait(session, DB_FILE_SCATTERED_READ);
            status = CT_ERROR;
            break;
        }

        knl_end_session_wait(session, DB_FILE_SCATTERED_READ);

        /* generally, one session can not wait for more than 0xffffffffffffffff us */
        session->stat->disk_read_time += session->wait_pool[DB_FILE_SCATTERED_READ].usecs;
        session->stat->disk_reads++;

        if (SECUREC_UNLIKELY(ctrl->page->type == PAGE_TYPE_UNDO)) {
            session->stat->undo_disk_reads++;
        }

        cm_atomic_inc(&session->kernel->total_io_read);
        g_knl_callback.accumate_io(session, IO_TYPE_READ);

        for (i = 0; i < count; i++) {
            if (ctrl_array[i] == NULL) {
                continue;
            }

            knl_panic((!(ctrl_array[i]->is_edp || ctrl_array[i]->is_dirty) &&
                       (ctrl_array[i]->load_status == (uint8)BUF_NEED_LOAD)) &&
                      (!DB_IS_CLUSTER(session) || DCS_BUF_CTRL_IS_OWNER(session, ctrl_array[i])));

            BUF_UNPROTECT_PAGE(ctrl_array[i]->page);
            ret = memcpy_sp(ctrl_array[i]->page, DEFAULT_PAGE_SIZE(session),
                read_buf + i * DEFAULT_PAGE_SIZE(session), DEFAULT_PAGE_SIZE(session));
            knl_securec_check(ret);

            if (!buf_check_load_page(session, ctrl_array[i]->page, ctrl_array[i]->page_id, CT_FALSE)) {
                if (!abr_repair_page_from_standy(session, ctrl_array[i])) {
                    if (ctrl_array[i]->page_id.page == ctrl->page_id.page) {
                        /* record alarm log if repair failed */
                        CT_LOG_ALARM(WARN_PAGECORRUPTED, "{'page-type':'%s','space-name':'%s','file-name':'%s'}",
                            page_type(ctrl->page->type), space->ctrl->name, df->ctrl->name);
                        CT_THROW_ERROR(ERR_PAGE_CORRUPTED, ctrl->page_id.file, ctrl->page_id.page);
                        status = CT_ERROR;
                    }
                    continue;
                }
            }

#if defined(__arm__) || defined(__aarch64__)
            CM_MFENCE;
#endif

            BUF_PROTECT_PAGE(ctrl_array[i]->page);
            ctrl_array[i]->force_request = 0;
            ctrl_array[i]->load_status = (uint8)BUF_IS_LOADED;
        }
    } while (0);

    /* set load status and unlatch batch load buffer */
    for (i = 0; i < count; i++) {
        if (ctrl_array[i] == NULL) {
            continue;
        }

        if (ctrl_array[i]->load_status != (uint8)BUF_IS_LOADED) {
            ctrl_array[i]->load_status = (uint8)BUF_LOAD_FAILED;
        }

        /* For the incoming ctrl we do not un_latch it, since the caller wil handl the latch */
        if (ctrl_array[i]->page_id.page != ctrl->page_id.page) {
            buf_unlatch(session, ctrl_array[i], CT_TRUE);
        }
    }

    cm_pop(session->stack);
    return status;
}

/*
 * load pages in batch
 * @param kernel session, current page ctrl, page_id(start load), load count
 * @note only if fail to load current page, can we throw error to caller
 */
static status_t buf_load_pages(knl_session_t *session, buf_ctrl_t *ctrl, page_id_t begin, uint32 total_count_input,
                               uint8 options)
{
    uint32 total_count = total_count_input;
    page_id_t page_id = begin;
    uint32 mpool_page_id;
    uint32 count;

    /* read single page when failed to alloc large page */
    if (total_count == 1 || !mpool_try_alloc_page(session->kernel->attr.large_pool, &mpool_page_id)) {
        return buf_load_page(session, ctrl, ctrl->page_id);
    }

    char *read_buf = mpool_page_addr(session->kernel->attr.large_pool, mpool_page_id);
    uint32 max_count = CT_LARGE_PAGE_SIZE / DEFAULT_PAGE_SIZE(session);
    knl_panic(max_count <= BUF_MAX_PREFETCH_NUM);

    while (total_count > 0) {
        count = total_count < max_count ? total_count : max_count;

        if (buf_batch_load_pages(session, read_buf, ctrl, page_id, count, options) != CT_SUCCESS) {
            mpool_free_page(session->kernel->attr.large_pool, mpool_page_id);
            return CT_ERROR;
        }

        total_count -= count;
        page_id.page += count;
    }

    mpool_free_page(session->kernel->attr.large_pool, mpool_page_id);
    return CT_SUCCESS;
}

static inline uint32 buf_log_entry_length(knl_session_t *session)
{
    uint32 size = session->page_stack.log_begin[session->page_stack.depth - 1];
    size += sizeof(rd_enter_page_t);
    size += LOG_ENTRY_SIZE;
    return size;
}

void buf_clean_log(knl_session_t *session)
{
    uint32 enter_page_size = LOG_ENTRY_SIZE + CM_ALIGN4(sizeof(rd_enter_page_t));
    log_group_t *group = (log_group_t *)(session->log_buf);
    log_entry_t *entry = (log_entry_t *)(session->log_buf + group->size - enter_page_size);

    knl_panic(entry->size == enter_page_size && RD_TYPE_IS_ENTER_PAGE(entry->type));
    group->size -= enter_page_size;
}

static inline bool32 buf_log_is_nolog_insert(knl_session_t *session, bool32 changed)
{
    log_group_t *group = (log_group_t *)session->log_buf;
    return SECUREC_UNLIKELY(group->nologging_insert && changed &&
        (session->rm->nolog_type == TABLE_LEVEL) &&
        page_type_suport_nolog_insert(((page_head_t*)CURR_PAGE(session))->type));
}

#ifdef LOG_DIAG
static void buf_validate_page(knl_session_t *session, buf_ctrl_t *ctrl, bool32 changed)
{
    page_head_t *page = (page_head_t *)session->curr_page;
    char *copy_page = NULL;
    log_group_t *group = NULL;
    uint32 depth;
    errno_t ret;

    switch (page->type) {
        case PAGE_TYPE_HEAP_MAP:
            heap_validate_map(session, page);
            break;

        case PAGE_TYPE_HEAP_DATA:
            heap_validate_page(session, page);
            break;

        case PAGE_TYPE_PCRH_DATA:
            pcrh_validate_page(session, page);
            break;

        case PAGE_TYPE_BTREE_NODE:
            btree_validate_page(session, page);
            break;

        case PAGE_TYPE_PCRB_NODE:
            pcrb_validate_page(session, page, NULL);
            break;

        case PAGE_TYPE_LOB_DATA:
            lob_validate_page(session, page);
            break;

        default:
            break;  // missed validate function
    }

    if (DB_NOT_READY(session) || DB_IS_READONLY(session) || DAAC_PARTIAL_RECOVER_SESSION(session)) {
        return;
    }

    /* daac swap_space maybe changed, but no redo, no dirty, skip it */
    if (DATAFILE_GET(session, ctrl->page_id.file)->space_id == dtc_my_ctrl(session)->swap_space) {
        return;
    }

    if (KNL_RECOVERY_WITH_GBP(session->kernel) && SESSION_IS_GBP_BG(session)) {
        return;
    }

    /* page first load from gbp */
    if (KNL_RECOVERY_WITH_GBP(session->kernel) && ctrl->gbp_ctrl->is_from_gbp && ctrl->is_dirty &&
        ctrl->gbp_ctrl->gbp_read_version == KNL_GBP_READ_VER(session->kernel) && !changed) {
        return;
    }

    depth = session->page_stack.depth - 1;

    if (!changed) {
        if (memcmp(session->log_diag_page[depth] + sizeof(page_head_t), session->curr_page + sizeof(page_head_t),
                   PAGE_VALID_SIZE(session)) != 0) {
            CT_LOG_DEBUG_WAR("WARNING: leave page with no change, but changed [file: %d, page: %d, type: %d].\n",
                             (uint32)AS_PAGID_PTR(page->id)->file,
                             (uint32)AS_PAGID_PTR(page->id)->page, (uint32)page->type);
            knl_panic(0);
        }
        return;
    }

    /* nologging table maybe changed but has no redo, so skip it */
    if (!SPC_IS_LOGGING_BY_PAGEID(session, ctrl->page_id) || !session->rm->logging) {
        return;
    }

    group = (log_group_t *)(session->log_buf);
    if (buf_log_entry_length(session) >= group->size && !group->nologging_insert) {
        CT_LOG_DEBUG_WAR("WARNING: leave page with change, but no log [file: %d, page: %d, type: %d].\n",
                         (uint32)AS_PAGID_PTR(page->id)->file,
                         (uint32)AS_PAGID_PTR(page->id)->page, (uint32)page->type);
        knl_panic(0);
    }

    // Check redo log.
    copy_page = (char *)cm_push(session->stack, DEFAULT_PAGE_SIZE(session));
    ret = memcpy_sp(copy_page, DEFAULT_PAGE_SIZE(session), session->log_diag_page[depth], DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);

    log_diag_page(session);

    if (memcmp(session->log_diag_page[depth], session->curr_page, DEFAULT_PAGE_SIZE(session)) != 0) {
        if (memcmp(session->log_diag_page[depth], copy_page, DEFAULT_PAGE_SIZE(session)) == 0) {
            CT_LOG_DEBUG_WAR("WARNING: loss log for page [file: %d, page: %d, type: %d].\n",
                             (uint32)AS_PAGID_PTR(page->id)->file,
                             (uint32)AS_PAGID_PTR(page->id)->page, (uint32)page->type);
            knl_panic(0);
        } else {
            CT_LOG_DEBUG_WAR("WARNING: diagnose log failed for page [file: %d, page: %d, type: %d].\n",
                             (uint32)AS_PAGID_PTR(page->id)->file,
                             (uint32)AS_PAGID_PTR(page->id)->page, (uint32)page->type);
            knl_panic(0);
        }
    }
    cm_pop(session->stack);
}
#endif

void buf_log_enter_page(knl_session_t *session, buf_ctrl_t *ctrl, latch_mode_t mode, uint8 options)
{
    if (DB_NOT_READY(session)) {
        return;
    }

    if (SECUREC_UNLIKELY(KNL_RECOVERY_WITH_GBP(session->kernel)) && SESSION_IS_GBP_BG(session)) {
        return;
    }

    session->page_stack.log_begin[session->page_stack.depth - 1] = ((log_group_t *)session->log_buf)->size;
#ifdef LOG_DIAG
    errno_t ret;
    ret = memcpy_sp(session->log_diag_page[session->page_stack.depth - 1], DEFAULT_PAGE_SIZE(session), ctrl->page,
                    DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);
#endif
    lrpl_context_t *lrpl = &session->kernel->lrpl_ctx;
    if ((DB_IS_READONLY(session) && !lrpl->is_promoting) || DAAC_SESSION_IN_RECOVERY(session)) {
        return;
    }

    if (mode == LATCH_MODE_X) {
        rd_enter_page_t redo;

        redo.page = ctrl->page_id.page;
        redo.file = ctrl->page_id.file;
        redo.pcn = ctrl->page->pcn;
        redo.options = options;

        /* because we replay txn page when do log analysis on standby(gbp enabled), we should identify it */
        if (ctrl->is_resident && ctrl->page->type == PAGE_TYPE_TXN) {
            log_put(session, RD_ENTER_TXN_PAGE, &redo, sizeof(rd_enter_page_t), LOG_ENTRY_FLAG_NONE);
        } else {
            log_put(session, RD_ENTER_PAGE, &redo, sizeof(rd_enter_page_t), LOG_ENTRY_FLAG_NONE);
        }
    }
}

static void buf_log_leave_page(knl_session_t *session, buf_ctrl_t *ctrl, bool32 changed)
{
    log_group_t *group = NULL;
    lrpl_context_t *lrpl = &session->kernel->lrpl_ctx;

    if (SECUREC_UNLIKELY(DB_NOT_READY(session) || (DB_IS_READONLY(session) && !lrpl->is_promoting) || DAAC_SESSION_IN_RECOVERY(session))) {
        return;
    }

    if (SECUREC_UNLIKELY(KNL_RECOVERY_WITH_GBP(session->kernel)) && SESSION_IS_GBP_BG(session)) {
        return;
    }

    if (session->page_stack.latch_modes[session->page_stack.depth - 1] == LATCH_MODE_X) {
        group = (log_group_t *)(session->log_buf);
        if (SECUREC_LIKELY(buf_log_entry_length(session) != group->size) ||
            SECUREC_LIKELY(buf_log_is_nolog_insert(session, changed))) {
#ifdef LOG_DIAG
            /* skip space entry page, because we always record log for entry page even it's nologging */
            if (ctrl->page_id.page > SPACE_ENTRY_PAGE) {
                knl_panic_log(SPC_IS_LOGGING_BY_PAGEID(session, ctrl->page_id),
                              "the space is not logging table space, panic info: page %u-%u type %u",
                              ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);
            }
#endif
            /* there is some other log entry behind RD_ENTER_PAGE, it means the page changed */
            if (ctrl->is_resident && ctrl->page->type == PAGE_TYPE_TXN) {
                /* because we replay txn page when do log analysis on standby(gbp enabled), we should identify it */
                log_put(session, RD_LEAVE_TXN_PAGE, &changed, sizeof(bool32), LOG_ENTRY_FLAG_NONE);
            } else {
                log_put(session, RD_LEAVE_PAGE, &changed, sizeof(bool32), LOG_ENTRY_FLAG_NONE);
            }
        } else {
            /* nologging table maybe changed but has no redo, so skip it */
            if (SPC_IS_LOGGING_BY_PAGEID(session, ctrl->page_id) && session->rm->logging) {
                knl_panic_log(!changed, "the page is changed, panic info: page %u-%u type %u", ctrl->page_id.file,
                              ctrl->page_id.page, ctrl->page->type);
            }
            /* there is only RD_ENTER_PAGE in group, it means the page not changed, we can clean it */
            buf_clean_log(session);
        }
    } else {
        knl_panic_log(!changed, "the page is changed, panic info: page %u-%u type %u", ctrl->page_id.file,
                      ctrl->page_id.page, ctrl->page->type);
    }
}

/**
 * This fucnction is used before repair page using backup
 * If page id is not supported or page is not corrupted on disk, we do not repair
 */
status_t buf_validate_corrupted_page(knl_session_t *session, knl_validate_t *param)
{
    page_id_t page_id = param->page_id;

    if (!abr_verify_pageid(session, page_id)) {
        return CT_ERROR;
    }

    if (session->kernel->db.status == DB_STATUS_OPEN) {
        /* If read page successfully, page is not corrupted */
        if (buf_read_page(session, page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL) == CT_SUCCESS) {
            buf_leave_page(session, CT_FALSE);
            return CT_SUCCESS;
        }
    }

    /**
     * When database status is open, we need check disk page again.
     * Because CRC mode if is FULL, disk page may not be corrupted. We can not repair it
     */
    if (!abr_precheck_corrupted_page(session, page_id)) {
        CT_THROW_ERROR(ERR_PAGE_CORRUPTED, page_id.file, page_id.page);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

bool32 buf_check_loaded_page_checksum(knl_session_t *session, buf_ctrl_t *ctrl, latch_mode_t mode, uint8 options)
{
    if (g_cks_level != CKS_FULL) {
        return CT_TRUE;
    }

    if (!buf_changed_verifiable(session, ctrl, mode, options)) {
        return CT_TRUE;
    }

    return buf_verify_checksum(session, ctrl->page, ctrl->page_id);
}

static inline void buf_try_read_gbp_page(knl_session_t *session, buf_ctrl_t *ctrl)
{
    if (ctrl->gbp_ctrl->page_status == GBP_PAGE_NOREAD) {
        ctrl->page->lsn = CT_INVALID_LSN; // page is not loaded, set lsn to 0
        ctrl->gbp_ctrl->page_status = GBP_PAGE_NONE;
    }

    if (session_need_read_gbp(session)) {
        buf_check_page_version(session, ctrl); // if local page is old, read page from gbp
    }
}

static inline void buf_read_compress_update_no_read(knl_session_t *session, buf_ctrl_t *head_ctrl)
{
    for (int32 i = PAGE_GROUP_COUNT - 1; i >= 0; i--) {
        head_ctrl->compress_group[i]->page->type = PAGE_TYPE_FREE_PAGE; // to avoid delayed read to member page
            // that does't hold x lock, but is set to loaded and not formated.
        CM_MFENCE;
        head_ctrl->compress_group[i]->load_status = BUF_IS_LOADED;
        if (SECUREC_UNLIKELY(KNL_GBP_ENABLE(session->kernel))) {
            head_ctrl->compress_group[i]->gbp_ctrl->page_status = GBP_PAGE_NOREAD;
        }
    }
}

static status_t buf_read_compress(knl_session_t *session, buf_ctrl_t *ctrl, page_id_t page_id,
    latch_mode_t mode, uint8 options)
{
    if (ctrl->load_status == (uint8)BUF_NEED_LOAD) {
        if (options & ENTER_PAGE_NO_READ) {
            knl_panic_log(PAGE_IS_COMPRESS_HEAD(ctrl->page_id), "buf_read_compress er: non head");
            buf_read_compress_update_no_read(session, ctrl);
            return CT_SUCCESS;
        }

        if (buf_load_group(session, ctrl) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (!buf_check_loaded_page_checksum(session, ctrl, mode, options)) {
            CT_THROW_ERROR(ERR_PAGE_CORRUPTED, ctrl->page_id.file, ctrl->page_id.page);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t buf_read_normal(knl_session_t *session, buf_ctrl_t *ctrl, page_id_t page_id,
    latch_mode_t mode, uint8 options)
{
    if (ctrl->load_status == (uint8)BUF_NEED_LOAD) {
        if (options & ENTER_PAGE_NO_READ) {
            ctrl->load_status = (uint8)BUF_IS_LOADED;
            if (SECUREC_UNLIKELY(KNL_GBP_ENABLE(session->kernel))) {
                ctrl->gbp_ctrl->page_status = GBP_PAGE_NOREAD;
            }
            return CT_SUCCESS;
        }

        if (buf_load_page(session, ctrl, page_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (!buf_check_loaded_page_checksum(session, ctrl, mode, options)) {
            CT_THROW_ERROR(ERR_PAGE_CORRUPTED, ctrl->page_id.file, ctrl->page_id.page);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t buf_read_page(knl_session_t *session, page_id_t page_id, latch_mode_t mode, uint8 options)
{
    buf_ctrl_t *ctrl = NULL;
    knl_buf_wait_t temp_stat;
    status_t status;

    if (SECUREC_UNLIKELY(IS_INVALID_PAGID(page_id))) {
        CT_LOG_RUN_ERR("[BUFFER] invalid page_id %u-%u", (uint32)page_id.file, (uint32)page_id.page);
        CM_ASSERT(0);
        CT_THROW_ERROR(ERR_INVALID_PAGE_ID, "");
        return CT_ERROR;
    }

    if (DB_IS_CLUSTER(session)) {
        buf_read_assist_t ra;
        dtc_read_init(&ra, page_id, mode, options, CT_INVALID_ID64, DTC_BUF_READ_ONE);
        return dtc_read_page(session, &ra);
    }

    stats_buf_init(session, &temp_stat);

    ctrl = page_compress(session, page_id) ? buf_alloc_compress(session, page_id, mode, options) :
                                             buf_alloc_ctrl(session, page_id, mode, options);
    if (SECUREC_UNLIKELY(ctrl == NULL)) {
        knl_panic_log(options & ENTER_PAGE_TRY, "options is invalid, panic info: page %u-%u type %u",
                      ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);
        session->curr_page = NULL;
        session->curr_page_ctrl = NULL;
        return CT_SUCCESS;
    }

    BUF_UNPROTECT_PAGE(ctrl->page);
    status = page_compress(session, page_id) ? buf_read_compress(session, ctrl, page_id, mode, options) :
                                               buf_read_normal(session, ctrl, page_id, mode, options);
    if (status != CT_SUCCESS) {
        buf_unlatch(session, ctrl, CT_TRUE);
        return CT_ERROR;
    }

    knl_panic_log(IS_SAME_PAGID(page_id, ctrl->page_id),
                  "page_id and ctrl's page_id are not same, panic info: page %u-%u ctrl page %u-%u type %u",
                  page_id.file, page_id.page, ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);

    if (SECUREC_UNLIKELY(KNL_GBP_ENABLE(session->kernel))) {
        buf_try_read_gbp_page(session, ctrl);
    }

    session->curr_page = (char *)ctrl->page;
    session->curr_page_ctrl = ctrl;
    session->stat->buffer_gets++;

    if (SECUREC_UNLIKELY(ctrl->page->type == PAGE_TYPE_UNDO)) {
        session->stat->undo_buf_reads++;
    }

#ifdef __PROTECT_BUF__
    if (mode != LATCH_MODE_X && !ctrl->is_readonly) {
        BUF_PROTECT_PAGE(ctrl->page);
    }
#endif

    stats_buf_record(session, &temp_stat, ctrl);
    buf_push_page(session, ctrl, mode);
    buf_log_enter_page(session, ctrl, mode, options);

    return CT_SUCCESS;
}

static status_t buf_read_prefetch_compress(knl_session_t *session, buf_ctrl_t *ctrl, page_id_t page_id,
    latch_mode_t mode, uint8 options)
{
    return buf_read_compress(session, ctrl, page_id,  mode, options);
}

status_t buf_read_prefetch_normal(knl_session_t *session, buf_ctrl_t *ctrl, page_id_t page_id, latch_mode_t mode,
                                  uint8 options)
{
    datafile_t *df = DATAFILE_GET(session, page_id.file);
    space_t *space = SPACE_GET(session, df->space_id);
    uint32 start_id = spc_first_extent_id(session, space, page_id);
    page_id_t first = page_id;
    uint32 load_count;
    uint32 prefetch_num = MIN(space->ctrl->extent_size, BUF_MAX_PREFETCH_NUM);

    if (page_id.page >= start_id) {
        first.page = page_id.page - ((page_id.page - start_id) % prefetch_num);
        first.aligned = 0;
        load_count = prefetch_num;
    } else {
        load_count = 1;
    }

    if (ctrl->load_status == (uint8)BUF_NEED_LOAD) {
        if (buf_load_pages(session, ctrl, first, load_count, options) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (!buf_check_loaded_page_checksum(session, ctrl, mode, options)) {
            CT_THROW_ERROR(ERR_PAGE_CORRUPTED, ctrl->page_id.file, ctrl->page_id.page);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}
status_t buf_read_prefetch_page(knl_session_t *session, page_id_t page_id, latch_mode_t mode, uint8 options)
{
    knl_panic_log(!(options & ENTER_PAGE_NO_READ), "buf_read_prefetch_page er:not no read");
    buf_ctrl_t *ctrl = NULL;
    knl_buf_wait_t temp_stat;
    status_t status;

    if (SECUREC_UNLIKELY(IS_INVALID_PAGID(page_id))) {
        CT_LOG_RUN_ERR("[BUFFER] invalid page_id %u-%u", (uint32)page_id.file, (uint32)page_id.page);
        CT_THROW_ERROR(ERR_INVALID_PAGE_ID, "");
        return CT_ERROR;
    }

    /* RTO = 0, disable prefetch when db is recovery from GBP */
    if (KNL_RECOVERY_WITH_GBP(session->kernel)) {
        return buf_read_page(session, page_id, mode, options);
    }

    if (DB_IS_CLUSTER(session)) {
        buf_read_assist_t ra;
        dtc_read_init(&ra, page_id, mode, options, CT_INVALID_ID64, DTC_BUF_PREFETCH_EXT_NUM);
        return dtc_read_page(session, &ra);
    }

    stats_buf_init(session, &temp_stat);

    if (page_compress(session, page_id)) {
        ctrl = buf_alloc_compress(session, page_id, mode, options);
        knl_panic_log(ctrl != NULL, "ctrl alloc failed, panic info: page %u-%u", page_id.file, page_id.page);
        status = buf_read_prefetch_compress(session, ctrl, page_id, mode, options);
    } else {
        ctrl = buf_alloc_ctrl(session, page_id, mode, options);
        knl_panic_log(ctrl != NULL, "ctrl alloc failed, panic info: page %u-%u", page_id.file, page_id.page);
        status = buf_read_prefetch_normal(session, ctrl, page_id, mode, options);
    }

    if (status != CT_SUCCESS) {
        buf_unlatch(session, ctrl, CT_TRUE);
        CT_LOG_RUN_ERR("[BUFFER][%u-%u][buf read prefetch] failed, load_status:%d, mode:%d",
            ctrl->page_id.file, ctrl->page_id.page, ctrl->load_status, mode);
        return CT_ERROR;
    }

    knl_panic_log(IS_SAME_PAGID(page_id, ctrl->page_id),
                  "page_id and ctrl's page_id are not same, panic info: page %u-%u ctrl page %u-%u type %u",
                  page_id.file, page_id.page, ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);

    session->curr_page = (char *)ctrl->page;
    session->curr_page_ctrl = ctrl;
    session->stat->buffer_gets++;

    if (SECUREC_UNLIKELY(ctrl->page->type == PAGE_TYPE_UNDO)) {
        session->stat->undo_buf_reads++;
    }

    stats_buf_record(session, &temp_stat, ctrl);
    buf_push_page(session, ctrl, mode);
    buf_log_enter_page(session, ctrl, mode, options);

    if (session->kernel->attr.enable_asynch) {
        if (buf_try_prefetch_next_ext(session, ctrl) != CT_SUCCESS) {
            CT_LOG_DEBUG_WAR("[BUFFER] failed to prefetch next extent file : %u , page: %llu",
                (uint32)ctrl->page_id.file, (uint64)ctrl->page_id.page);
        }
    }

    return CT_SUCCESS;
}

status_t buf_read_prefetch_num_normal(knl_session_t *session, buf_ctrl_t *ctrl, page_id_t page_id,
                                      uint32 prefetch_number, latch_mode_t mode, uint8 options)
{
    uint32 prefetch_num = prefetch_number;
    datafile_t *df = DATAFILE_GET(session, page_id.file);
    space_t *space = SPACE_GET(session, df->space_id);
    uint32 hwm = space->head->hwms[df->file_no];  // do not need SPACE_HEAD_RESIDENT

    if (prefetch_num > BUF_MAX_PREFETCH_NUM) {
        prefetch_num = BUF_MAX_PREFETCH_NUM;
    }

    /* the page no is less than hwm forever */
    if (page_id.page + prefetch_num > hwm) {
        prefetch_num = hwm - page_id.page;
    }

    if (ctrl->load_status == (uint8)BUF_NEED_LOAD) {
        if (buf_load_pages(session, ctrl, page_id, prefetch_num, options) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (!buf_check_loaded_page_checksum(session, ctrl, mode, options)) {
            CT_THROW_ERROR(ERR_PAGE_CORRUPTED, ctrl->page_id.file, ctrl->page_id.page);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t buf_read_prefetch_page_num(knl_session_t *session, page_id_t page_id, uint32 prefetch_num,
                                    latch_mode_t mode, uint8 options)
{
    buf_ctrl_t *ctrl = NULL;
    knl_buf_wait_t temp_stat;

    if (SECUREC_UNLIKELY(IS_INVALID_PAGID(page_id))) {
        CT_LOG_RUN_ERR("[BUFFER] invalid page_id %u-%u", (uint32)page_id.file, (uint32)page_id.page);
        CT_THROW_ERROR(ERR_INVALID_PAGE_ID, "");
        return CT_ERROR;
    }

    /* RTO = 0, disable prefetch when db is recovery from GBP */
    if (KNL_RECOVERY_WITH_GBP(session->kernel)) {
        return buf_read_page(session, page_id, mode, options);
    }

    if (DB_IS_CLUSTER(session)) {
        buf_read_assist_t ra;
        // prefetch_num less than BUF_MAX_PREFETCH_NUM(128)
        dtc_read_init(&ra, page_id, mode, options, CT_INVALID_ID64, (uint16)prefetch_num);
        return dtc_read_page(session, &ra);
    }

    stats_buf_init(session, &temp_stat);

    ctrl = buf_alloc_ctrl(session, page_id, mode, options);
    knl_panic_log(ctrl != NULL, "ctrl alloc failed, panic info: page %u-%u", page_id.file, page_id.page);

    if (ctrl->load_status == (uint8)BUF_NEED_LOAD) {
        if (!buf_read_prefetch_num_normal(session, ctrl, page_id, prefetch_num, mode, options)) {
            buf_unlatch(session, ctrl, CT_TRUE);
            return CT_ERROR;
        }
    } else {
        if (!buf_check_loaded_page_checksum(session, ctrl, mode, options)) {
            CT_THROW_ERROR(ERR_PAGE_CORRUPTED, ctrl->page_id.file, ctrl->page_id.page);
            buf_unlatch(session, ctrl, CT_TRUE);
            return CT_ERROR;
        }
    }

    knl_panic_log(IS_SAME_PAGID(page_id, ctrl->page_id),
                  "page_id and ctrl's page_id are not same, panic info: page %u-%u ctrl_page %u-%u type %u",
                  page_id.file, page_id.page, ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);

    session->curr_page = (char *)ctrl->page;
    session->curr_page_ctrl = ctrl;
    session->stat->buffer_gets++;

    if (SECUREC_UNLIKELY(ctrl->page->type == PAGE_TYPE_UNDO)) {
        session->stat->undo_buf_reads++;
    }

    stats_buf_record(session, &temp_stat, ctrl);
    buf_push_page(session, ctrl, mode);
    buf_log_enter_page(session, ctrl, mode, options);

    return CT_SUCCESS;
}

/*
 * log_set_page_lsn is the last time modify for page when db is open,
 * but it's not the list time modify when db rcy,need checksum again when redo change page
 */
static inline void buf_calc_checksum(knl_session_t *session, buf_ctrl_t *ctrl)
{
    // checksum is invalid if page has changed
    knl_panic_log(PAGE_SIZE(*ctrl->page) != 0, "the page size is abnormal, panic info: page %u-%u type %u size %u",
                  ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type, PAGE_SIZE(*ctrl->page));
    PAGE_CHECKSUM(ctrl->page, PAGE_SIZE(*ctrl->page)) = CT_INVALID_CHECKSUM;

    if (!DB_IS_CHECKSUM_FULL(session)) {
        return;
    }

    page_calc_checksum(ctrl->page, PAGE_SIZE(*ctrl->page));
}

void buf_leave_page(knl_session_t *session, bool32 changed)
{
    buf_ctrl_t *ctrl = buf_curr_page(session);

    if (SECUREC_UNLIKELY(ctrl == NULL)) {
        buf_pop_page(session);
        return;
    }

    /* if page is allocated without initialized, then page->size_units=0 */
    if (DB_TO_RECOVERY(session) && ctrl->page->size_units != 0) {
        knl_panic_log(CHECK_PAGE_PCN(ctrl->page), "page pcn is abnormal, panic info: page %u-%u type %u",
                      ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);
    }

#ifdef LOG_DIAG
    buf_validate_page(session, ctrl, changed);
#endif

    if (changed && !PAGE_IS_HARD_DAMAGE_ZERO(ctrl->page)) {
        knl_panic_log(PAGE_SIZE(*ctrl->page) != 0,
            "the page size is abnormal, panic info: page %u-%u type %u size %u",
            ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type, PAGE_SIZE(*ctrl->page));

        ctrl->page->pcn++;
        PAGE_TAIL(ctrl->page)->pcn++;

        if (!ctrl->is_dirty) {
            ctrl->is_dirty = 1;
            if (session->dirty_count > 0) {
                session->dirty_pages[session->dirty_count - 1]->ckpt_next = ctrl;
                ctrl->ckpt_prev = session->dirty_pages[session->dirty_count - 1];
            }
            session->dirty_pages[session->dirty_count++] = ctrl;
        }

        if (!ctrl->is_readonly) {
            ctrl->is_readonly = 1;
            session->changed_pages[session->changed_count++] = ctrl;
            knl_panic_log(session->changed_count <= KNL_MAX_ATOMIC_PAGES, "the changed page count of current session "
                          "is abnormal, panic info: page %u-%u type %u changed_count %u",
                          ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type, session->changed_count);
        }

        if (SECUREC_UNLIKELY(KNL_GBP_ENABLE(session->kernel))) {
            ctrl->gbp_ctrl->page_status = GBP_PAGE_NONE;
            if (!ctrl->gbp_ctrl->is_gbpdirty && DB_IS_PRIMARY(&session->kernel->db)) {
                ctrl->gbp_ctrl->is_gbpdirty = CT_TRUE;
                session->gbp_dirty_pages[session->gbp_dirty_count++] = ctrl;
                knl_panic_log(session->gbp_dirty_count <= KNL_MAX_ATOMIC_PAGES,
                              "gbp_dirty_count is abnormal, panic info: page %u-%u type %u gbp_dirty_count %u",
                              ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type, session->gbp_dirty_count);
            }
        }

        if (SECUREC_UNLIKELY(DB_NOT_READY(session))) {
            buf_calc_checksum(session, ctrl);
        }

        session->stat->db_block_changes++;
    }

    buf_log_leave_page(session, ctrl, changed);
    buf_unlatch(session, ctrl, CT_TRUE);
    buf_pop_page(session);
}

void buf_unreside(knl_session_t *session, buf_ctrl_t *ctrl)
{
    buf_set_t *set = &session->kernel->buf_ctx.buf_set[ctrl->buf_pool_id];
    buf_bucket_t *bucket = BUF_GET_BUCKET(set, ctrl->bucket_id);

    cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
    if (ctrl->is_resident) {
        ctrl->is_resident = 0;
    }
    cm_spin_unlock(&bucket->lock);
}

void buf_unreside_page(knl_session_t *session, page_id_t page_id)
{
    buf_ctrl_t *ctrl = NULL;

    if (IS_INVALID_PAGID(page_id)) {
        return;
    }

    if (buf_read_page(session, page_id, LATCH_MODE_S, ENTER_PAGE_RESIDENT) != CT_SUCCESS) {
        return;
    }
    ctrl = session->curr_page_ctrl;
    buf_leave_page(session, CT_FALSE);
    buf_unreside(session, ctrl);
}

/*
 * for temp page in buf_enter_temp_page
 * 1) we don't record redo log
 * 2) we don't read page
 */
void buf_enter_temp_page(knl_session_t *session, page_id_t page_id, latch_mode_t mode, uint8 options)
{
    buf_ctrl_t *ctrl = NULL;

    if (SECUREC_UNLIKELY(page_id.page == CT_INVALID_ID32)) {
        knl_panic_log(0, "page number is invalid, panic info: page %u-%u", page_id.file, page_id.page);
    }

    knl_panic(DB_NOT_READY(session) ||
              DATAFILE_GET(session, page_id.file)->space_id == dtc_my_ctrl(session)->swap_space);

    ctrl = buf_alloc_ctrl(session, page_id, mode, options);
    knl_panic_log(ctrl != NULL, "ctrl alloc failed, panic info: page %u-%u", page_id.file, page_id.page);

    if (ctrl->load_status != (uint8)BUF_IS_LOADED) {
        ctrl->load_status = (uint8)BUF_IS_LOADED;
    }

    session->curr_page = (char *)ctrl->page;
    session->curr_page_ctrl = ctrl;

    buf_push_page(session, ctrl, mode);

#ifdef __PROTECT_BUF__
    if (mode == LATCH_MODE_X) {
        BUF_UNPROTECT_PAGE(ctrl->page);
    }
#endif
}

/*
 * for temp page in buf_leave_temp_page
 * 1) we don't record redo log
 */
void buf_leave_temp_page(knl_session_t *session)
{
    buf_ctrl_t *ctrl = buf_curr_page(session);
    if (ctrl == NULL) {
        buf_pop_page(session);
        return;
    }

    knl_panic(DB_NOT_READY(session) ||
              DATAFILE_GET(session, ctrl->page_id.file)->space_id == dtc_my_ctrl(session)->swap_space);
    BUF_PROTECT_PAGE(ctrl->page);

    buf_unlatch(session, ctrl, CT_TRUE);
    buf_pop_page(session);
}

status_t buf_invalidate_page_with_version(knl_session_t *session, page_id_t page_id, uint64 req_version)
{
    buf_ctrl_t *ctrl = buf_try_latchx_page(session, page_id, CT_TRUE);
    if (ctrl == NULL) {
        CT_LOG_DEBUG_WAR("[buffer][%u-%u][buf_invalidate_page]: not found in memory", page_id.file, page_id.page);
        return CT_SUCCESS;
    }

    CT_LOG_DEBUG_INF(
        "[buffer][%u-%u][buf_invalidate_page]: ctrl_dirty=%u, ctrl_remote_dirty=%u, ctrl_readonly=%u, "
        "in ckpt=%u, ctrl_lock_mode=%u, edp=%d",
        ctrl->page_id.file, ctrl->page_id.page, ctrl->is_dirty, ctrl->is_remote_dirty, ctrl->is_readonly, ctrl->in_ckpt,
        ctrl->lock_mode, ctrl->is_edp);

    SYNC_POINT_GLOBAL_START(CANTIAN_DCS_INVALID_REQ_OTHER_ABORT, (int32 *)session, 0);
    SYNC_POINT_GLOBAL_END;
    if (DRC_STOP_DCS_IO_FOR_REFORMING(req_version, session)) {
        CT_LOG_RUN_ERR(
            "[buffer][%u-%u][reforming, buf_invalidate_page failed]: ctrl_dirty=%u, ctrl_remote_dirty=%u, "
            "ctrl_readonly=%u, in ckpt=%u, ctrl_lock_mode=%u, edp=%d",
            ctrl->page_id.file, ctrl->page_id.page, ctrl->is_dirty, ctrl->is_remote_dirty,
            ctrl->is_readonly, ctrl->in_ckpt,
            ctrl->lock_mode, ctrl->is_edp);
        buf_unlatch_page(session, ctrl);
        return CT_ERROR;
    }

    if (!DCS_BUF_CTRL_NOT_OWNER(session, ctrl)) {
        CT_LOG_RUN_ERR(
            "[buffer][%u-%u][buf_invalidate_page failed]: is owner ctrl_lock_mode=%u",
            ctrl->page_id.file, ctrl->page_id.page, ctrl->lock_mode);
        buf_unlatch_page(session, ctrl);
        return CT_ERROR;
    }

    // If multiple S-readings come later, BUF_LOAD_FAILED can ensure only one invokes DCS page request.
    ctrl->load_status = BUF_LOAD_FAILED;
    ctrl->lock_mode = DRC_LOCK_NULL;

    buf_unlatch_page(session, ctrl);
    return CT_SUCCESS;
}

status_t buf_invalidate_page(knl_session_t *session, page_id_t page_id)
{
    buf_ctrl_t *ctrl = buf_try_latchx_page(session, page_id, CT_TRUE);
    if (ctrl == NULL) {
        CT_LOG_DEBUG_WAR("[buffer][%u-%u][buf_invalidate_page]: not found in memory", page_id.file, page_id.page);
        return CT_SUCCESS;
    }

    CT_LOG_DEBUG_INF(
        "[buffer][%u-%u][buf_invalidate_page]: ctrl_dirty=%u, ctrl_remote_dirty=%u, ctrl_readonly=%u, in ckpt=%u, ctrl_lock_mode=%u, edp=%d",
        ctrl->page_id.file, ctrl->page_id.page, ctrl->is_dirty, ctrl->is_remote_dirty, ctrl->is_readonly, ctrl->in_ckpt,
        ctrl->lock_mode, ctrl->is_edp);

    knl_panic(DCS_BUF_CTRL_NOT_OWNER(session, ctrl));

    // If multiple S-readings come later, BUF_LOAD_FAILED can ensure only one invokes DCS page request.
    ctrl->load_status = BUF_LOAD_FAILED;
    ctrl->lock_mode = DRC_LOCK_NULL;

    buf_unlatch_page(session, ctrl);
    return CT_SUCCESS;
}

status_t buf_invalidate_page_owner(knl_session_t *session, page_id_t page_id, uint64 req_version)
{
    buf_bucket_t *bucket = buf_find_bucket(session, page_id);
    cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
    buf_ctrl_t *ctrl = buf_find_from_bucket(bucket, page_id);
    if (!ctrl) {
        cm_spin_unlock(&bucket->lock);
        CT_LOG_DEBUG_INF("[buffer][%u-%u][buf_invalidate_page_owner]: fast check, not found in memory", page_id.file,
                         page_id.page);
        return CT_SUCCESS;
    }
    if (!BUF_CAN_EVICT(ctrl)) {
        cm_spin_unlock(&bucket->lock);
        CT_LOG_DEBUG_INF(
            "[buffer][%u-%u][buf_invalidate_page_owner]: fast check, not recyclable and return, ctrl_dirty=%u, ctrl_remote_dirty=%u, ctrl_readonly=%u, in ckpt=%u, ctrl_lock_mode=%u, edp=%d",
            ctrl->page_id.file, ctrl->page_id.page, ctrl->is_dirty, ctrl->is_remote_dirty, ctrl->is_readonly,
            ctrl->in_ckpt, ctrl->lock_mode, ctrl->is_edp);
        return CT_ERROR;
    }
    cm_spin_unlock(&bucket->lock);

    ctrl = buf_try_latchx_page(session, page_id, CT_TRUE);
    if (ctrl == NULL) {
        CT_LOG_DEBUG_INF("[buffer][%u-%u][buf_invalidate_page_owner]: not found in memory", page_id.file, page_id.page);
        return CT_SUCCESS;
    }

    CT_LOG_DEBUG_INF(
        "[buffer][%u-%u][buf_invalidate_page_owner]: ctrl_dirty=%u, ctrl_remote_dirty=%u, ctrl_readonly=%u, in ckpt=%u, ctrl_lock_mode=%u, edp=%d",
        ctrl->page_id.file, ctrl->page_id.page, ctrl->is_dirty, ctrl->is_remote_dirty, ctrl->is_readonly, ctrl->in_ckpt,
        ctrl->lock_mode, ctrl->is_edp);

    if (ctrl->lock_mode == DRC_LOCK_NULL) {
        buf_unlatch_page(session, ctrl);
        CT_LOG_DEBUG_INF(
            "[buffer][%u-%u][buf_invalidate_page_owner]: already invalidated, ctrl_dirty=%u, ctrl_remote_dirty=%u, ctrl_readonly=%u, in ckpt=%u, ctrl_lock_mode=%u, edp=%d",
            ctrl->page_id.file, ctrl->page_id.page, ctrl->is_dirty, ctrl->is_remote_dirty, ctrl->is_readonly,
            ctrl->in_ckpt, ctrl->lock_mode, ctrl->is_edp);
        return CT_SUCCESS;
    }

    if (!BUF_IN_USE_IS_RECYCLABLE(ctrl) || ctrl->is_resident || (ctrl->ref_num != 1)) {
        buf_unlatch_page(session, ctrl);
        CT_LOG_DEBUG_INF(
            "[buffer][%u-%u][buf_invalidate_page_owner]: not recyclable and return, ctrl_dirty=%u, ctrl_remote_dirty=%u, ctrl_readonly=%u, in ckpt=%u, ctrl_lock_mode=%u, edp=%d",
            ctrl->page_id.file, ctrl->page_id.page, ctrl->is_dirty, ctrl->is_remote_dirty, ctrl->is_readonly,
            ctrl->in_ckpt, ctrl->lock_mode, ctrl->is_edp);
        return CT_ERROR;
    }

    if (DRC_STOP_DCS_IO_FOR_REFORMING(req_version, session)) {
        CT_LOG_RUN_ERR(
            "[buffer][%u-%u][reforming, buf_invalidate_page page failed]: ctrl_dirty=%u, ctrl_remote_dirty=%u, "
            "ctrl_readonly=%u, in ckpt=%u, ctrl_lock_mode=%u, edp=%d",
            ctrl->page_id.file, ctrl->page_id.page, ctrl->is_dirty, ctrl->is_remote_dirty,
            ctrl->is_readonly, ctrl->in_ckpt,
            ctrl->lock_mode, ctrl->is_edp);
        buf_unlatch_page(session, ctrl);
        return CT_ERROR;
    }

    if (!DCS_BUF_CTRL_IS_OWNER(session, ctrl)) {
        CT_LOG_RUN_ERR(
            "[buffer][%u-%u][buf_invalidate_page failed]: is not owner ctrl_lock_mode=%u",
            ctrl->page_id.file, ctrl->page_id.page, ctrl->lock_mode);
        buf_unlatch_page(session, ctrl);
        return CT_ERROR;
    }

    ctrl->load_status = BUF_LOAD_FAILED;
    ctrl->lock_mode = DRC_LOCK_NULL;

    buf_unlatch_page(session, ctrl);

    CT_LOG_DEBUG_INF(
        "[buffer][%u-%u][buf_invalidate_page_owner]: invalidate page owner, ctrl_dirty=%u, ctrl_remote_dirty=%u, ctrl_readonly=%u, in ckpt=%u, ctrl_lock_mode=%u, edp=%d, page type=%d",
        ctrl->page_id.file, ctrl->page_id.page, ctrl->is_dirty, ctrl->is_remote_dirty, ctrl->is_readonly, ctrl->in_ckpt,
        ctrl->lock_mode, ctrl->is_edp, ctrl->page->type);
    return CT_SUCCESS;
}

bool32 buf_clean_edp(knl_session_t *session, edp_page_info_t page)
{
    bool32 latched;
    page_id_t page_id = page.page;
    buf_ctrl_t *ctrl = buf_try_latch_ckpt_page(session, page_id, &latched);
    if (ctrl == NULL) {
        CT_LOG_DEBUG_WAR("[buffer][%u-%u][buf clean edp]: not found in memory", page_id.file, page_id.page);
        return CT_TRUE;
    }

    if (!latched) {
        buf_dec_ref(session, ctrl);
        CT_LOG_DEBUG_WAR("[buffer][%u-%u][buf clean edp]: can't latch page, will retry later", page_id.file,
                         page_id.page);
        return CT_FALSE;
    }
    CT_LOG_DEBUG_INF("[buffer][%u-%u][clean buf edp]: ctrl_dirty=%u, ctrl_remote_dirty=%u, ctrl_readonly=%u, in "
        "ckpt=%u, ctrl_lock_mode=%u, edp=%d, ack lsn=%llu",
        ctrl->page_id.file, ctrl->page_id.page, ctrl->is_dirty, ctrl->is_remote_dirty, ctrl->is_readonly, ctrl->in_ckpt,
        ctrl->lock_mode, ctrl->is_edp, page.lsn);

    if (ctrl->is_edp == 0) {
        buf_unlatch_page(session, ctrl);
        CT_LOG_DEBUG_WAR(
            "[buffer][%u-%u][clean buf edp]: not edp now, ctrl_dirty=%u, ctrl_remote_dirty=%u, ctrl_readonly=%u, in ckpt=%u, ctrl_lock_mode=%u, edp=%d",
            ctrl->page_id.file, ctrl->page_id.page, ctrl->is_dirty, ctrl->is_remote_dirty, ctrl->is_readonly,
            ctrl->in_ckpt, ctrl->lock_mode, ctrl->is_edp);
        return CT_TRUE;
    }

    if (page.lsn == CT_INVALID_ID64) {
        /* On previous owner node, the ctrl is not in memory which may be a clean shared copy ctrl from remote dirty
          owner node and has been swapped out. You can't juge if local dirty page can be cleared.
        */
        buf_ctrl_t *tmp_ctrl =
            (buf_ctrl_t *)cm_push(session->stack,
                                  sizeof(buf_ctrl_t) + (uint32)(DEFAULT_PAGE_SIZE(session) + CT_MAX_ALIGN_SIZE_4K));
        *tmp_ctrl = *ctrl;
        tmp_ctrl->lock_mode = DRC_LOCK_SHARE;
        tmp_ctrl->is_edp = 0;
        tmp_ctrl->is_dirty = 0;
        tmp_ctrl->page = (page_head_t *)cm_aligned_buf((char *)tmp_ctrl + (uint64)sizeof(buf_ctrl_t));
        tmp_ctrl->page->lsn = 0;
        if (buf_load_page(session, tmp_ctrl, tmp_ctrl->page_id) != CT_SUCCESS) {
            tmp_ctrl->load_status = (uint8)BUF_LOAD_FAILED;
            knl_panic_log(0, "[DCS]buf clean edp page[%u-%u] (lsn:%lld) load from disk failed", ctrl->page_id.file,
                          ctrl->page_id.page, ctrl->page->lsn);
        }
        CT_LOG_RUN_WAR("[DCS]buf clean edp page[%u-%u] with invalid ack lsn, page lsn (%lld) and disk page(%lld).",
                       ctrl->page_id.file, ctrl->page_id.page, ctrl->page->lsn, tmp_ctrl->page->lsn);
        page.lsn = dtc_get_ctrl_lsn(tmp_ctrl);
        cm_pop(session->stack);
    }

    if (page.lsn >= ctrl->page->lsn) {
        dcs_buf_clean_ctrl_edp(session, ctrl, CT_TRUE);
    } else {
        CT_LOG_DEBUG_WAR(
            "[buffer][%u-%u][clean buf edp]: ignore clean edp, request edp lsn (%llu) is smaller than "
            "page lsn (%llu), ctrl_dirty=%u, ctrl_remote_dirty=%u, ctrl_readonly=%u, in ckpt=%u, ctrl_lock_mode=%u,"
            " edp=%d",
            ctrl->page_id.file, ctrl->page_id.page, page.lsn, ctrl->page->lsn, ctrl->is_dirty, ctrl->is_remote_dirty,
            ctrl->is_readonly, ctrl->in_ckpt, ctrl->lock_mode, ctrl->is_edp);
    }

    buf_unlatch_page(session, ctrl);
    return CT_TRUE;
}

buf_ctrl_t *buf_try_latch_ckpt_page(knl_session_t *session, page_id_t page_id, bool32 *latched)
{
    buf_bucket_t *bucket = buf_find_bucket(session, page_id);
    buf_ctrl_t *ctrl = NULL;

    cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
    ctrl = buf_find_from_bucket(bucket, page_id);
    if (ctrl == NULL) {
        cm_spin_unlock(&bucket->lock);
        *latched = CT_FALSE;
        return NULL;
    }
    ctrl->ref_num++;
    if (ctrl->load_status == (uint8)BUF_NEED_LOAD) {
        cm_spin_unlock(&bucket->lock);
        *latched = CT_FALSE;
        return ctrl;
    }
    cm_spin_unlock(&bucket->lock);

    if (!ckpt_try_latch_ctrl(session, ctrl)) {
        CT_LOG_DEBUG_INF("[CKPT] try latch page find gap [%u-%u]", ctrl->page_id.file, ctrl->page_id.page);
        *latched = CT_FALSE;
        return ctrl;
    }

    *latched = CT_TRUE;
    return ctrl;
}

/* This function is only used to latch a page and modify its memory state, not to modify page content.
   for buf_clean_edp and dcs_ckpt_remote_edp_parepare, will try to use ckpt_try_latch */
buf_ctrl_t *buf_try_latchx_page(knl_session_t *session, page_id_t page_id, bool32 check_io)
{
    buf_ctrl_t *ctrl = NULL;
    knl_buf_wait_t temp_stat;

    knl_panic(!IS_INVALID_PAGID(page_id));

    stats_buf_init(session, &temp_stat);

    for (;;) {
        ctrl = buf_alloc_ctrl(session, page_id, LATCH_MODE_X, ENTER_PAGE_TRY);
        if (ctrl == NULL) {
            return NULL;
        }

        if (ctrl->load_status == (uint8)BUF_NEED_LOAD) {
            ctrl->load_status = (uint8)BUF_LOAD_FAILED;
        }

        knl_panic(IS_SAME_PAGID(page_id, ctrl->page_id));

        if (!check_io) {
            break;
        }

        uint32 times = 0;
        uint32 wait_ticks = 0;
        while (ctrl->is_marked) {
            if (wait_ticks >= CKPT_LATCH_WAIT) {
                break;
            }
            times++;
            if (times > CT_SPIN_COUNT) {
                times = 0;
                cm_spin_sleep();
                wait_ticks++;
                continue;
            }
        }

        if (!ctrl->is_marked) {
            break;
        }

        buf_unlatch_page(session, ctrl);
        cm_spin_sleep();
    }

    knl_panic(!check_io || !ctrl->is_marked);
    session->stat->buffer_gets++;
    stats_buf_record(session, &temp_stat, ctrl);

    return ctrl;
}

void buf_unlatch_page(knl_session_t *session, buf_ctrl_t *ctrl)
{
    buf_unlatch(session, ctrl, CT_TRUE);
}

void buf_dec_ref(knl_session_t *session, buf_ctrl_t *ctrl)
{
    buf_set_t *set;
    buf_bucket_t *bucket;
    set = &session->kernel->buf_ctx.buf_set[ctrl->buf_pool_id];
    bucket = BUF_GET_BUCKET(set, ctrl->bucket_id);
    cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
    knl_panic(ctrl->ref_num > 0);
    ctrl->ref_num--;
    cm_spin_unlock(&bucket->lock);
}

void buf_set_force_request(knl_session_t *session, page_id_t page_id)
{
    buf_ctrl_t *ctrl = NULL;
    knl_panic(!IS_INVALID_PAGID(page_id));

    ctrl = buf_alloc_ctrl(session, page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    knl_panic_log(ctrl != NULL, "ctrl alloc failed, panic info: page %u-%u", page_id.file, page_id.page);

    ctrl->force_request = 1;
    if (ctrl->load_status == (uint8)BUF_NEED_LOAD) {
        ctrl->load_status = (uint8)BUF_LOAD_FAILED;
    }
    knl_panic(IS_SAME_PAGID(page_id, ctrl->page_id));

    buf_unlatch(session, ctrl, CT_TRUE);
}
