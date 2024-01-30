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
 * knl_badblock.c
 *
 *
 * IDENTIFICATION
 * src/kernel/backup/knl_badblock.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_backup_module.h"
#include "knl_badblock.h"
#include "cm_log.h"
#include "cm_file.h"
#include "cm_checksum.h"
#include "cm_kmc.h"
#include "knl_context.h"
#include "knl_session.h"


void badblock_append_head_state(char *buffer, char *badblock_head, int32 badblock_head_len)
{
    errno_t ret = memcpy_sp(buffer, badblock_head_len, badblock_head, badblock_head_len);
    knl_securec_check(ret);
}

status_t badblock_convert_head_info_to_char(page_head_t *head, char *buf, uint32 *buffer_len)
{
    char *head_info_buf = (char *)malloc(BADBLOCK_HEAD_BUFFER_SIZE);
    if (head_info_buf == NULL) {
        CT_LOG_RUN_ERR("[RESTORE] malloc data_buffer failed!.");
        return CT_ERROR;
    }
    errno_t err = memset_s(head_info_buf, BADBLOCK_HEAD_BUFFER_SIZE, 0, BADBLOCK_HEAD_BUFFER_SIZE);
    knl_securec_check(err);
    char *page_head_info = "\tpage head info {\n"
                           "\tpage_id: %u-%u"
                           "\tlsn: %llu"
                           "\tpcn: %u"
                           "\tsize_units: %u"
                           "\tsize: %d"
                           "\ttype: %s"
                           "\text_size: %u"
                           "\tencrypted: %u"
                           "\tcompressed: %u"
                           "\tsof_damage: %u"
                           "\thard_damage: %u"
                           "\tnext_ext: %u-%u }\n";
    err = snprintf_s(head_info_buf, BADBLOCK_HEAD_BUFFER_SIZE, BADBLOCK_HEAD_BUFFER_SIZE - 1, page_head_info,
                     AS_PAGID_PTR(head->id)->file, AS_PAGID_PTR(head->id)->page,
                     head->lsn,
                     head->pcn,
                     head->size_units,
                     PAGE_SIZE(*head),
                     page_type(head->type),
                     head->ext_size,
                     head->encrypted,
                     head->compressed,
                     head->soft_damage,
                     head->hard_damage,
                     AS_PAGID_PTR(head->next_ext)->file, AS_PAGID_PTR(head->next_ext)->page);
    knl_securec_check_ss(err);
    *buffer_len += strlen(head_info_buf);
    err = strcat_s(buf, BADBLOCK_HEAD_BUFFER_SIZE, head_info_buf);
    CM_FREE_PTR(head_info_buf);
    knl_securec_check(err);
    return CT_SUCCESS;
}

status_t badblock_convert_head_tail_to_char(page_head_t *head, char *buf, uint32 *buffer_len)
{
    page_tail_t *tail = NULL;
    if (head->compressed) {
        return CT_SUCCESS;
    }
    char *head_tail_buf = (char *)malloc(BADBLOCK_HEAD_BUFFER_SIZE);
    if (head_tail_buf == NULL) {
        CT_LOG_RUN_ERR("[RESTORE] malloc data_buffer failed!.");
        return CT_ERROR;
    }
    errno_t err = memset_s(head_tail_buf, BADBLOCK_HEAD_BUFFER_SIZE, 0, BADBLOCK_HEAD_BUFFER_SIZE);
    knl_securec_check(err);
    tail = (page_tail_t *)((char *)head + PAGE_SIZE(*head) - sizeof(page_tail_t));
    char *page_head_tail = "\tpage tail info {\n"
                           "\tchecksum: %u"
                           "\treserve: %u"
                           "\tpcn: %u }\n\n";
    err = snprintf_s(head_tail_buf, BADBLOCK_HEAD_BUFFER_SIZE, BADBLOCK_HEAD_BUFFER_SIZE - 1, page_head_tail,
                     tail->checksum,
                     tail->reserve,
                     tail->pcn);
    knl_securec_check_ss(err);
    *buffer_len += strlen(head_tail_buf);
    err = strcat_s(buf, BADBLOCK_HEAD_BUFFER_SIZE, head_tail_buf);
    CM_FREE_PTR(head_tail_buf);
    knl_securec_check(err);
    return CT_SUCCESS;
}

status_t badblock_write_file_local(badblock_local_file_t *local, const void *buf, int32 size, int64 offset)
{
    if (size == 0) {
        return CT_SUCCESS;
    }
    if (cm_write_device(local->type, local->handle, offset, buf, size) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_WRITE_FILE, local->name);
        return CT_ERROR;
    }
    local->size += size;
    return CT_SUCCESS;
}

status_t badblock_write_data_stub(badblock_file_mgr *file_mgr, void *buf, uint32 buffer_len)
{
    char *data_buffer = NULL;
    if (file_mgr->buffer_offset + buffer_len > BADBLOCK_DATA_BUFFER_SIZE) {
        data_buffer = (char*)malloc(sizeof(char) * BADBLOCK_DATA_BUFFER_SIZE);
        if (data_buffer == NULL) {
            CT_LOG_RUN_ERR("[RESTORE] malloc data_buffer failed!.");
            return CT_ERROR;
        }
    }
    cm_spin_lock(&file_mgr->lock, NULL);
    uint32 buffer_offset = file_mgr->buffer_offset;
    uint64 file_offset = file_mgr->file_offset;
    uint32 cur_buffer_offset = 0;
    file_mgr->badblock_num++;

    if (file_mgr->buffer_offset + buffer_len <= BADBLOCK_DATA_BUFFER_SIZE) {
        file_mgr->buffer_offset += buffer_len;
        cm_spin_unlock(&file_mgr->lock);
        badblock_append_head_state(file_mgr->file_buffer.badblock_data_buffer + buffer_offset,
                                   (char *)buf, buffer_len);
    } else {
        errno_t ret = memcpy_sp(data_buffer, BADBLOCK_DATA_BUFFER_SIZE, file_mgr->file_buffer.badblock_data_buffer,
                                BADBLOCK_DATA_BUFFER_SIZE);
        knl_securec_check(ret);
        cur_buffer_offset = file_mgr->buffer_offset;

        file_mgr->buffer_offset = buffer_len;
        file_mgr->file_offset += cur_buffer_offset;
        cm_spin_unlock(&file_mgr->lock);
        if (badblock_write_file_local(&(file_mgr->data_file), data_buffer, cur_buffer_offset,
                                      file_offset) != CT_SUCCESS) {
            CM_FREE_PTR(data_buffer);
            return CT_ERROR;
        }
        badblock_append_head_state(file_mgr->file_buffer.badblock_data_buffer, (char *)buf, buffer_len);
    }
    CM_FREE_PTR(data_buffer);
    return CT_SUCCESS;
}

status_t badblock_write_data(badblock_file_mgr *file_mgr, page_head_t *head)
{
    if (head == NULL) {
        CT_LOG_RUN_ERR("[BACKUP] the page_head is null!");
        return CT_ERROR;
    }
    char *buf = (char *)malloc(BADBLOCK_HEAD_BUFFER_SIZE);
    if (buf == NULL) {
        CT_LOG_RUN_ERR("[RESTORE] malloc data_buffer failed!.");
        return CT_ERROR;
    }
    errno_t err = memset_s(buf, BADBLOCK_HEAD_BUFFER_SIZE, 0, BADBLOCK_HEAD_BUFFER_SIZE);
    knl_securec_check(err);
    uint32 buffer_len = 0;
    if (badblock_convert_head_info_to_char(head, buf, &buffer_len) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] failed to convert head to char.");
        CM_FREE_PTR(buf);
        return CT_ERROR;
    }
    if (badblock_convert_head_tail_to_char(head, buf, &buffer_len) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] failed to convert tail to char.");
        CM_FREE_PTR(buf);
        return CT_ERROR;
    }
    if (badblock_write_data_stub(file_mgr, (void *)buf, buffer_len) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] failed to write %s", file_mgr->data_file.name);
        CM_FREE_PTR(buf);
        return CT_ERROR;
    }
    CM_FREE_PTR(buf);
    return CT_SUCCESS;
}

status_t badblock_write_page(knl_session_t *session, page_head_t *head)
{
    if (head == NULL) {
        CT_LOG_RUN_ERR("[BACKUP] the page_head is null!.");
        return CT_ERROR;
    }
    badblock_file_mgr *file_mgr = (badblock_file_mgr *)(session->kernel->badblock_file_mgr.aligned_buf);
    return badblock_write_data(file_mgr, head);
}

status_t badblock_write_buffer(knl_session_t *session)
{
    if ((!session->kernel->backup_ctx.bak.restore) && (!session->kernel->backup_ctx.bak.skip_badblock)) {
        return CT_SUCCESS;
    }
    if ((session->kernel->backup_ctx.bak.restore) &&
        (session->kernel->backup_ctx.bak.repair_type == RESTORE_REPAIR_TYPE_NULL)) {
        return CT_SUCCESS;
    }
    badblock_file_mgr *file_mgr = (badblock_file_mgr *)(session->kernel->badblock_file_mgr.aligned_buf);
    if (file_mgr == NULL) {
        return CT_SUCCESS;
    }
    // write last buffer to file
    status_t status = badblock_write_file_local(&(file_mgr->data_file), file_mgr->file_buffer.badblock_data_buffer,
                                                file_mgr->buffer_offset, file_mgr->file_offset);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] failed to write %s", file_mgr->data_file.name);
        return status;
    }
    file_mgr->buffer_offset = 0;
    return CT_SUCCESS;
}

status_t badblock_generate_file(badblock_file_mgr *mgr, badblock_local_file_t *local_file, char *name)
{
    int ret = snprintf_s(local_file->name, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN,
                         "%s/%s", mgr->path, name);
    PRTS_RETURN_IFERR(ret);
    local_file->type = cm_device_type(local_file->name);
    local_file->handle = CT_INVALID_HANDLE;

    if (cm_exist_device(local_file->type, local_file->name)) {
        if (strcmp(RESTORE_BADBLOCK_FILE_TMP, name) == 0) {
            if (cm_remove_device(local_file->type, local_file->name) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[BACKUP] failed to remove archive file %s", local_file->name);
                return CT_ERROR;
            }
            CT_LOG_RUN_INF("[BACKUP] remove file %s succ.", local_file->name);
        } else {
            CT_LOG_RUN_ERR("[BACKUP] file %s exists!", local_file->name);
            return CT_ERROR;
        }
    }
    if (cm_create_device(local_file->name, local_file->type,
                         O_BINARY | O_SYNC | O_RDWR, &(local_file->handle)) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] failed to create %s.", local_file->name);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[BACKUP] create file name %s, type %u", local_file->name, (uint32)local_file->type);
    local_file->size = 0;
    if (cm_open_device(local_file->name, local_file->type, mgr->file_flags, &(local_file->handle)) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] failed to open %s", local_file->name);
        local_file->handle = CT_INVALID_HANDLE;
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t badblock_init_file(knl_session_t *session, badblock_file_mgr *mgr, char *file_name)
{
    errno_t err = strcpy_s(mgr->path, CT_FILE_NAME_BUFFER_SIZE, session->kernel->backup_ctx.bak.record.path);
    knl_securec_check(err);
    if (badblock_generate_file(mgr, &(mgr->data_file), file_name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

// badblock_data_buffer is behind the badblock_file_mgr
static void badblock_set_log_buffer(char *pre_addr, uint32 pre_length, char **addr)
{
    char *magic_addr = pre_addr + pre_length;
    // set magic, magic size is 8B
    *(uint64 *)(magic_addr) = BADBLOCK_BUFFER_BARRIER_MAGIC;
    // set addr
    *addr = magic_addr + BADBLOCK_BUFFER_BARRIER_SIZE;
}

status_t badblock_init_file_mgr(knl_session_t *session, aligned_buf_t *badblock_mgr_buf, char *file_name)
{
    if (cm_aligned_malloc((uint64)(BADBLOCK_DATA_BUFFER_SIZE + BADBLOCK_FILE_MGR_SIZE),
                          "badblock write file", badblock_mgr_buf) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY,
            ((uint64)(BADBLOCK_DATA_BUFFER_SIZE + BADBLOCK_FILE_MGR_SIZE)),
            "badblock write file");
        return CT_ERROR;
    }
    badblock_file_mgr *file_mgr = (badblock_file_mgr *)(badblock_mgr_buf->aligned_buf);
    badblock_set_log_buffer(badblock_mgr_buf->aligned_buf, sizeof(badblock_file_mgr),
                            &(file_mgr->file_buffer.badblock_data_buffer));
    file_mgr->buffer_offset = 0;
    file_mgr->file_flags = knl_io_flag(session);
    file_mgr->file_offset = 0;
    file_mgr->badblock_num = 0;
    if (badblock_init_file(session, file_mgr, file_name) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] failed to init %s", file_name);
        cm_aligned_free(&(session->kernel->badblock_file_mgr));
        return CT_ERROR;
    }
    file_mgr->lock = 0;
    return CT_SUCCESS;
}

status_t badblock_init(knl_session_t *session)
{
    bool32 is_backup = !(session->kernel->backup_ctx.bak.restore);
    if (is_backup  && (!session->kernel->backup_ctx.bak.skip_badblock)) {
        return CT_SUCCESS;
    }
    if (!is_backup && (session->kernel->backup_ctx.bak.repair_type == RESTORE_REPAIR_TYPE_NULL)) {
        return CT_SUCCESS;
    }
    aligned_buf_t *badblock_mgr_buf = &(session->kernel->badblock_file_mgr);
    char *file_name = is_backup ? BACKUP_BADBLOCK_FILE_NAME : RESTORE_BADBLOCK_FILE_TMP;
    return badblock_init_file_mgr(session, badblock_mgr_buf, file_name);
}

void badblock_file_backup_end(knl_session_t *session)
{
    if (!session->kernel->backup_ctx.bak.skip_badblock) {
        return;
    }
    badblock_file_mgr *file_mgr = (badblock_file_mgr *)(session->kernel->badblock_file_mgr.aligned_buf);
    if (file_mgr == NULL) {
        return;
    }
    cm_close_device(file_mgr->data_file.type, &(file_mgr->data_file.handle));
    if (file_mgr->badblock_num == 0) {
        CT_LOG_RUN_INF("[BACKUP] there exist no badblock, remove %s", file_mgr->data_file.name);
        cm_remove_device(file_mgr->data_file.type, file_mgr->data_file.name);
    } else {
        session->kernel->backup_ctx.bak.has_badblock = CT_TRUE;
        CT_LOG_RUN_INF("[BACKUP] there exists %llu badblocks in datafiles.", file_mgr->badblock_num);
        CT_SET_HINT("[BACKUP] there exists %llu badblocks in datafiles, details see %s.", file_mgr->badblock_num, file_mgr->data_file.name);
    }
    cm_aligned_free(&(session->kernel->badblock_file_mgr));
}

status_t badblock_write_page_tmp(knl_session_t *session, void *page, bool32 page_id_damage)
{
    badblock_file_mgr *file_mgr = (badblock_file_mgr *)(session->kernel->badblock_file_mgr.aligned_buf);
    uint32 buffer_len = DEFAULT_PAGE_SIZE(session);
    if (badblock_write_data_stub(file_mgr, (void *)page, buffer_len) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] failed to write %s", file_mgr->data_file.name);
        return CT_ERROR;
    }
    uint32 buffer_len2 = sizeof(bool32);
    if (badblock_write_data_stub(file_mgr, (void *)(&page_id_damage), buffer_len2) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] failed to write %s", file_mgr->data_file.name);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t badblock_confirm_badblock(knl_session_t *session, page_head_t *page, bool32 *page_valid_confirm)
{
    page_id_t *page_id = AS_PAGID_PTR(page->id);
    datafile_t *datafile = DATAFILE_GET(session, page_id->file);
    int32 *handle = DATAFILE_FD(session, datafile->ctrl->id);
    if (spc_open_datafile(session, datafile, handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] failed to open datafile %s", datafile->ctrl->name);
        return CT_ERROR;
    }
    int64 file_offset = (int64)page_id->page * DEFAULT_PAGE_SIZE(session);
    int32 data_size = 0;
    int32 read_size = DEFAULT_PAGE_SIZE(session);
    page_head_t *page_curr;
    char *buf = (char *)malloc(read_size);
    if (buf == NULL) {
        CT_LOG_RUN_ERR("[RESTORE] malloc buf failed!.");
        return CT_ERROR;
    }
    if (cm_read_device_nocheck(datafile->ctrl->type, *handle, file_offset, buf, read_size,
                               &data_size) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] failed to read buf from tmp_file.");
        spc_close_datafile(datafile, handle);
        CM_FREE_PTR(buf);
        return CT_ERROR;
    }
    page_curr = (page_head_t *)buf;
    *page_valid_confirm = !page_curr->hard_damage;
    spc_close_datafile(datafile, handle);
    CM_FREE_PTR(buf);
    return CT_SUCCESS;
}

status_t badblock_restore_handle(knl_session_t *session, aligned_buf_t *tmp_buf, badblock_file_mgr *dst_file_mgr,
                                 int32 data_size)
{
    page_head_t *page = NULL;
    uint32 page_len = DEFAULT_PAGE_SIZE(session) + sizeof(bool32);
    uint32 page_count = (uint32)data_size / page_len;
    bool32 *is_page_id_damage = NULL;
    bool32 need_confirm = (!session->kernel->backup_ctx.bak.failed) &&
                          (session->kernel->backup_ctx.bak.repair_type == RESTORE_REPAIR_DISCARD_BADBLOCK);
    bool32 page_valid_confirm = CT_FALSE;
    for (uint32 i = 0; i < page_count; i++) {
        page = (page_head_t *)(tmp_buf->aligned_buf + i * page_len);
        is_page_id_damage = (bool32 *)((char *)page + DEFAULT_PAGE_SIZE(session));
        if (need_confirm && (*is_page_id_damage == CT_FALSE)) {
            if (badblock_confirm_badblock(session, page, &page_valid_confirm) != CT_SUCCESS) {
                return CT_ERROR;
            }
            if (page_valid_confirm) {
                CT_LOG_RUN_WAR("[RESTORE] page[%u-%u] is valid after confirm.",
                               AS_PAGID_PTR(page->id)->file, AS_PAGID_PTR(page->id)->page);
                continue;
            }
        }
        
        if (badblock_write_data(dst_file_mgr, page) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RESTORE] failed to write buf.");
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}
 
status_t badblock_convert_stub(knl_session_t *session, badblock_file_mgr *source_file_mgr,
                               badblock_file_mgr *dst_file_mgr)
{
    aligned_buf_t tmp_buf;
    if (cm_aligned_malloc((uint64)(BADBLOCK_DATA_BUFFER_SIZE + BADBLOCK_FILE_MGR_SIZE),
                          "badblock write tmp", &tmp_buf) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY,
            ((uint64)(BADBLOCK_DATA_BUFFER_SIZE + BADBLOCK_FILE_MGR_SIZE)),
            "badblock write tmp");
        return CT_ERROR;
    }
    uint64 left_size = source_file_mgr->data_file.size;
    int32 read_size;
    int32 data_size;
    int64 file_offset = 0;
    while (left_size > 0) {
        read_size = (int32)((left_size > BADBLOCK_DATA_BUFFER_SIZE) ? BADBLOCK_DATA_BUFFER_SIZE : left_size);
        if (cm_read_device_nocheck(source_file_mgr->data_file.type, source_file_mgr->data_file.handle,
                                   file_offset, tmp_buf.aligned_buf, read_size, &data_size) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RESTORE] failed to read buf from tmp_file.");
            cm_aligned_free(&tmp_buf);
            return CT_ERROR;
        }
        CT_LOG_RUN_INF("[RESTORE] read buf from %s, file_offset[%llu], data_size[%llu], "
                       "read_size[%llu], left_size[%llu].",
                       source_file_mgr->data_file.name, (uint64)file_offset, (uint64)data_size,
                       (uint64)read_size, (uint64)left_size);
        if (data_size == 0) {
            break;
        }
        left_size -= (uint64)data_size;
        file_offset += (uint64)data_size;
        if (badblock_restore_handle(session, &tmp_buf, dst_file_mgr, data_size) != CT_SUCCESS) {
            cm_aligned_free(&tmp_buf);
            return CT_ERROR;
        }
    }
    cm_aligned_free(&tmp_buf);
    return CT_SUCCESS;
}
 
status_t badblock_convert_tmp_file(knl_session_t *session, uint64 *badblock_num)
{
    aligned_buf_t dst_buf;
    if (badblock_init_file_mgr(session, &dst_buf, RESTORE_BADBLOCK_FILE_NAME) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] failed to init file_mgr.");
        return CT_ERROR;
    }
    badblock_file_mgr *source_file_mgr = (badblock_file_mgr *)(session->kernel->badblock_file_mgr.aligned_buf);
    badblock_file_mgr *dst_file_mgr = (badblock_file_mgr *)(dst_buf.aligned_buf);
    if (badblock_convert_stub(session, source_file_mgr, dst_file_mgr) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] failed to convert bad_block_tmp to backupset_bad_block_record.");
        cm_close_device(dst_file_mgr->data_file.type, &(dst_file_mgr->data_file.handle));
        cm_aligned_free(&dst_buf);
        return CT_ERROR;
    }
    if (badblock_write_file_local(&(dst_file_mgr->data_file), dst_file_mgr->file_buffer.badblock_data_buffer,
                                  dst_file_mgr->buffer_offset, dst_file_mgr->file_offset) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RESTORE] failed to write buf to backupset_bad_block_record.");
        cm_close_device(dst_file_mgr->data_file.type, &(dst_file_mgr->data_file.handle));
        cm_aligned_free(&dst_buf);
        return CT_ERROR;
    }
    *badblock_num = dst_file_mgr->badblock_num;
    cm_close_device(dst_file_mgr->data_file.type, &(dst_file_mgr->data_file.handle));
    cm_aligned_free(&dst_buf);
    return CT_SUCCESS;
}
 
status_t badblock_file_restore_end(knl_session_t *session)
{
    if (session->kernel->backup_ctx.bak.repair_type == RESTORE_REPAIR_TYPE_NULL) {
        return CT_SUCCESS;
    }
    status_t status = CT_SUCCESS;
    badblock_file_mgr *file_mgr = (badblock_file_mgr *)(session->kernel->badblock_file_mgr.aligned_buf);
    if (file_mgr == NULL) {
        return CT_SUCCESS;
    }
    if (file_mgr->badblock_num == 0) {
        CT_LOG_RUN_INF("[RESTORE] there exist no badblock, remove %s", file_mgr->data_file.name);
    } else {
        session->kernel->backup_ctx.bak.has_badblock = CT_TRUE;
        uint64 badblock_num = 0;
        status = badblock_convert_tmp_file(session, &badblock_num);
        if (status == CT_SUCCESS) {
            CT_LOG_RUN_INF("[RESTORE] after confirm, there exists %llu badblocks in datafiles.", badblock_num);
            if (badblock_num > 0) {
                CT_SET_HINT("[RESTORE] there exists %llu badblocks in datafiles, details see %s/%s.",
                            badblock_num, session->kernel->backup_ctx.bak.record.path, RESTORE_BADBLOCK_FILE_NAME);
            }
        }
    }
    cm_close_device(file_mgr->data_file.type, &(file_mgr->data_file.handle));
    cm_remove_device(file_mgr->data_file.type, file_mgr->data_file.name);
    cm_aligned_free(&(session->kernel->badblock_file_mgr));
    return status;
}

status_t badblock_end(knl_session_t *session)
{
    status_t status = badblock_write_buffer(session);
    if ((session->kernel->backup_ctx.bak.restore)) {
        if (badblock_file_restore_end(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
        return status;
    } else {
        badblock_file_backup_end(session);
        return status;
    }
}
