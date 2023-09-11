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
 * knl_buffer_access.h
 *
 *
 * IDENTIFICATION
 * src/kernel/buffer/knl_buffer_access.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_BUFFER_ACCESS_H__
#define __KNL_BUFFER_ACCESS_H__

#include "knl_buffer.h"
#include "knl_interface.h"
#ifdef __PROTECT_BUF__
#include  <sys/mman.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __PROTECT_BUF__
// large page mode in the Redhat system does not support mprotect
#ifdef REDHAT
#define BUF_PROTECT_PAGE(page)
#define BUF_UNPROTECT_PAGE(page)
#else
#define BUF_PROTECT_PAGE(page) \
    do { \
        if (mprotect(page, DEFAULT_PAGE_SIZE(session), PROT_READ) != 0) { \
            CM_ASSERT(0); \
        } \
    } while (0);

#define BUF_UNPROTECT_PAGE(page) \
    do { \
        if (mprotect(page, DEFAULT_PAGE_SIZE(session), PROT_READ | PROT_WRITE) != 0) { \
            CM_ASSERT(0); \
        } \
    } while (0);
#endif
#else
#define BUF_PROTECT_PAGE(page)
#define BUF_UNPROTECT_PAGE(page)
#endif

status_t buf_aio_init(knl_session_t *session);
void buf_aio_proc(thread_t *thread);

status_t buf_load_page(knl_session_t *session, buf_ctrl_t *ctrl, page_id_t page_id);
status_t buf_read_page(knl_session_t *session, page_id_t page_id, latch_mode_t mode, uint8 options);
status_t buf_read_prefetch_page(knl_session_t *session, page_id_t page_id, latch_mode_t mode, uint8 options);
status_t buf_read_prefetch_normal(knl_session_t *session, buf_ctrl_t *ctrl, page_id_t page_id, latch_mode_t mode,
                                  uint8 options);
status_t buf_read_prefetch_page_num(knl_session_t *session, page_id_t page_id, uint32 prefetch_num,
                                    latch_mode_t mode, uint8 options);
status_t buf_read_prefetch_num_normal(knl_session_t *session, buf_ctrl_t *ctrl, page_id_t page_id,
                                      uint32 prefetch_number, latch_mode_t mode, uint8 options);
status_t buf_validate_corrupted_page(knl_session_t *session, knl_validate_t *param);
status_t buf_read_page_asynch(knl_session_t *session, page_id_t page_id);

void buf_leave_page(knl_session_t *session, bool32 changed);
void buf_unreside_page(knl_session_t *session, page_id_t page_id);
void buf_unreside(knl_session_t *session, buf_ctrl_t *ctrl);

void buf_enter_temp_page(knl_session_t *session, page_id_t page_id, latch_mode_t mode, uint8 options);
void buf_leave_temp_page(knl_session_t *session);
status_t buf_load_page_from_disk(knl_session_t *session, buf_ctrl_t *ctrl, page_id_t page_id);
status_t buf_load_group(knl_session_t *session, buf_ctrl_t *ctrl);
status_t buf_decompress_group(knl_session_t *session, char *dst, const char *src, uint32 *size);
status_t buf_check_load_compress_group(knl_session_t *session, page_id_t head_page_id, const char *read_buf);
bool32 buf_check_load_page(knl_session_t *session, page_head_t *page, page_id_t page_id, bool32 is_backup_process);

static inline void buf_enter_page(knl_session_t *session, page_id_t page_id, latch_mode_t mode, uint8 options)
{
    if (buf_read_page(session, page_id, mode, options) != GS_SUCCESS) {
        CM_ABORT(0, "[BUFFER] ABORT INFO: failed to read page %u-%u", page_id.file, page_id.page);
    }
}

static inline void buf_enter_prefetch_page(knl_session_t *session, page_id_t page_id, latch_mode_t mode, uint8 options)
{
    if (buf_read_prefetch_page(session, page_id, mode, options) != GS_SUCCESS) {
        CM_ABORT(0, "[BUFFER] ABORT INFO: failed to read prefetch page %u-%u", page_id.file, page_id.page);
    }
}

static inline void buf_enter_prefetch_page_num(knl_session_t *session, page_id_t page_id, uint32 prefetch_num,
                                               latch_mode_t mode, uint8 options)
{
    if (buf_read_prefetch_page_num(session, page_id, prefetch_num, mode, options) != GS_SUCCESS) {
        CM_ABORT(0, "[BUFFER] ABORT INFO: failed to read prefetch page %u-%u, prefetch_num %u",
                 page_id.file, page_id.page, prefetch_num);
    }
}

static inline void buf_push_page(knl_session_t *session, buf_ctrl_t *page, latch_mode_t mode)
{
    knl_panic(session->page_stack.depth < KNL_MAX_PAGE_STACK_DEPTH);
    session->page_stack.pages[session->page_stack.depth] = page;
    session->page_stack.latch_modes[session->page_stack.depth] = mode;
    session->page_stack.depth++;
}

static inline buf_ctrl_t *buf_curr_page(knl_session_t *session)
{
    knl_panic(session->page_stack.depth > 0);
    return session->page_stack.pages[session->page_stack.depth - 1];
}

static inline void buf_pop_page(knl_session_t *session)
{
    buf_ctrl_t *ctrl = NULL;

    knl_panic(session->page_stack.depth > 0);
    session->page_stack.depth--;

    if (session->page_stack.depth > 0) {
        ctrl = buf_curr_page(session);
        session->curr_page = (ctrl == NULL) ? NULL : ((char *)ctrl->page);
        session->curr_page_ctrl = ctrl;
    }
}

void buf_log_enter_page(knl_session_t *session, buf_ctrl_t *ctrl, latch_mode_t mode, uint8 options);
status_t buf_try_prefetch_next_ext(knl_session_t *session, buf_ctrl_t *ctrl);
bool32 buf_check_loaded_page_checksum(knl_session_t *session, buf_ctrl_t *ctrl, latch_mode_t mode, uint8 options);

#ifdef __cplusplus
}
#endif

#endif
