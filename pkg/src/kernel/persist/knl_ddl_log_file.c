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
 * knl_ddl_log_file.c
 *
 *
 * IDENTIFICATION
 * src/kernel/persist/knl_ddl_log_file.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_persist_module.h"
#include "knl_ddl_log_file.h"
#include "cm_log.h"
#include "cm_file.h"
#include "cm_checksum.h"
#include "cm_kmc.h"
#include "knl_context.h"
#include "knl_session.h"

#ifdef _DEBUG
static const uint32 LOG_DDL_DATA_BUFFER_SIZE = (SIZE_K(64));
#else
static const uint32 LOG_DDL_DATA_BUFFER_SIZE = (SIZE_M(64));
#endif
static const uint32 LOG_DDL_FILE_MGR_SIZE = (SIZE_K(4));
static const uint32 LOG_DDL_BUFFER_BARRIER_SIZE = (8);
#define LOG_DDL_BUFFER_BARRIER_MAGIC (0xDD1DD2DD3DD4DD5D)
#define LOG_DDL_TERM_SIZE (7)
#define LOG_DDL_TERM_DATA "/!*!/;\n"
#define LOG_DDL_SET_LOCAL_ENABLE "set @ctc_ddl_local_enabled=true;\n"
#define LOG_DDL_SET_REPALY_ENABLE "set @ctc_replay_ddl=true;\n"
#define LOG_DDL_SET_END_IDENTIFIER "delimiter /!*!/;\n"

status_t log_ddl_generate_file(logic_ddl_file_mgr *mgr, logic_ddl_local_file_t *local_file,
                               char* name_prefix)
{
    int ret = snprintf_s(local_file->name, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN,
                         "%s/%s.sql", mgr->path, name_prefix);
    PRTS_RETURN_IFERR(ret);
    status_t status;
    local_file->type = cm_device_type(local_file->name);
    CT_LOG_RUN_INF("[DDL] create file name %s, type %u", local_file->name, (uint32)local_file->type);
    if (cm_exist_device(local_file->type, local_file->name)) {
        status = cm_remove_device(local_file->type, local_file->name);
        if (status != CT_SUCCESS) {
            return status;
        }
    }
    status = cm_create_device(local_file->name, local_file->type,
                              O_BINARY | O_SYNC | O_RDWR, &(local_file->handle));
    if (status != CT_SUCCESS) {
        return status;
    }
    local_file->size = 0;
    return log_ddl_open_file(local_file, mgr->file_flags);
}

static void log_ddl_securec_check(errno_t ret)
{
    if (ret != EOK) {
        CT_LOG_RUN_ERR("Secure C lib has thrown an error %d", ret);
        cm_fync_logfile();
        *((uint32 *)NULL) = 1;
    }
}

static void log_ddl_append_data(char *buf, char *data, int32 size)
{
    errno_t ret = memcpy_sp(buf, size, data, size);
    log_ddl_securec_check(ret);
}

status_t log_ddl_open_file(logic_ddl_local_file_t *local_file, uint32 flags)
{
    if (cm_open_device(local_file->name, local_file->type, flags, &(local_file->handle)) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] failed to open %s", local_file->name);
        local_file->handle = -1;
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void log_ddl_close_file(logic_ddl_local_file_t *local_file)
{
    return cm_close_device(local_file->type, &local_file->handle);
}

static void log_ddl_append_ddl_state(char *buffer, char *ddl, int32 ddl_len)
{
    log_ddl_append_data(buffer, ddl, ddl_len);
    log_ddl_append_data(buffer + ddl_len, LOG_DDL_TERM_DATA, LOG_DDL_TERM_SIZE);
}

status_t log_ddl_write_file_local(logic_ddl_local_file_t *local, const void *buf, int32 size, int64 offset)
{
    if (size == 0) {
        return CT_SUCCESS;
    }
    if (cm_write_device(local->type, local->handle, offset, buf, size) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[LOG] failed to write %s", local->name);
        return CT_ERROR;
    }
    local->size += size;
    return CT_SUCCESS;
}

void log_ddl_write_init_info(logic_ddl_file_mgr *file_mgr, logic_rep_ddl_head_t *sql_head,
                             char *sql_text, uint32 sql_len)
{
    uint32 buffer_offset = file_mgr->buffer_offset;
    log_ddl_append_data(file_mgr->file_buffer.ddl_data_buffer + buffer_offset, sql_text, sql_len);
    file_mgr->buffer_offset += sql_len;
}

status_t log_ddl_write_data(logic_ddl_file_mgr *file_mgr, logic_rep_ddl_head_t *sql_head,
                            char *sql_text, uint32 sql_len)
{
    uint32 buffer_offset = file_mgr->buffer_offset;
    uint64 file_offset = file_mgr->file_offset;
    int32 total_size = sql_len + LOG_DDL_TERM_SIZE;

    if (file_mgr->buffer_offset + total_size <= LOG_DDL_DATA_BUFFER_SIZE) {
        log_ddl_append_ddl_state(file_mgr->file_buffer.ddl_data_buffer + buffer_offset,
                                 sql_text, sql_len);
        file_mgr->buffer_offset += total_size;
    } else {
        log_ddl_write_file_local(&(file_mgr->data_file), file_mgr->file_buffer.ddl_data_buffer,
                                 file_mgr->buffer_offset, file_offset);
        file_mgr->file_offset += file_mgr->buffer_offset;
        memset_s(file_mgr->file_buffer.ddl_data_buffer,
                 LOG_DDL_DATA_BUFFER_SIZE, 0, LOG_DDL_DATA_BUFFER_SIZE);
        log_ddl_append_ddl_state(file_mgr->file_buffer.ddl_data_buffer, sql_text, sql_len);
        file_mgr->buffer_offset = total_size;
    }
    return CT_SUCCESS;
}

status_t log_ddl_write_file(knl_session_t *session, logic_rep_ddl_head_t *sql_head, char *sql_text, uint32 sql_len)
{
    logic_ddl_file_mgr *file_mgr = (logic_ddl_file_mgr *)(session->kernel->ddl_file_mgr.aligned_buf);
    if (file_mgr == NULL) {
        return CT_SUCCESS;
    }
    if (session->ddl_lsn_pitr >= session->curr_lsn) {
        return CT_SUCCESS;
    }
    return log_ddl_write_data(file_mgr, sql_head, sql_text, sql_len);
}

status_t log_ddl_write_buffer(knl_session_t *session)
{
    logic_ddl_file_mgr *file_mgr = (logic_ddl_file_mgr *)(session->kernel->ddl_file_mgr.aligned_buf);
    if (file_mgr == NULL) {
        return CT_SUCCESS;
    }
    // write last ddl data buffer to data file
    status_t status = log_ddl_write_file_local(&(file_mgr->data_file), file_mgr->file_buffer.ddl_data_buffer,
                                               file_mgr->buffer_offset, file_mgr->file_offset);
    if (status != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_WRITE_FILE, file_mgr->data_file.name);
        return status;
    }
    file_mgr->buffer_offset = 0;
    log_ddl_close_file(&(file_mgr->data_file));
    return CT_SUCCESS;
}

void log_ddl_init_path(knl_session_t *session, logic_ddl_file_mgr *mgr)
{
    errno_t err = strcpy_s(mgr->path, CT_FILE_NAME_BUFFER_SIZE, session->kernel->home);
    MEMS_RETVOID_IFERR(err);
}

static void log_ddl_init_file_memory(logic_ddl_local_file_t *local_file)
{
    local_file->handle = -1;
    local_file->size = 0;
}

static status_t log_ddl_init_file(knl_session_t *session, logic_ddl_file_mgr *mgr)
{
    log_ddl_init_path(session, mgr);
    log_ddl_init_file_memory(&(mgr->data_file));
    status_t status = log_ddl_generate_file(mgr, &(mgr->data_file), LOG_DDL_DATA_FILE_NAME_PREPIX);
    if (status != CT_SUCCESS) {
        return status;
    }
    log_ddl_write_init_info(mgr, NULL, LOG_DDL_SET_LOCAL_ENABLE, strlen(LOG_DDL_SET_LOCAL_ENABLE));
    log_ddl_write_init_info(mgr, NULL, LOG_DDL_SET_REPALY_ENABLE, strlen(LOG_DDL_SET_REPALY_ENABLE));
    log_ddl_write_init_info(mgr, NULL, LOG_DDL_SET_END_IDENTIFIER, strlen(LOG_DDL_SET_END_IDENTIFIER));
    return CT_SUCCESS;
}

static void log_ddl_set_log_buffer(char *pre_addr, uint32 pre_length, char **addr)
{
    char *magic_addr = pre_addr + pre_length;
    // set magic, magic size is 8B
    *(uint64 *)(magic_addr) = LOG_DDL_BUFFER_BARRIER_MAGIC;
    // set addr
    *addr = magic_addr + LOG_DDL_BUFFER_BARRIER_SIZE;
}

status_t log_ddl_init_file_mgr(knl_session_t *session)
{
    aligned_buf_t *ddl_mgr_buf = &(session->kernel->ddl_file_mgr);
    if (cm_aligned_malloc((uint64)(LOG_DDL_DATA_BUFFER_SIZE + LOG_DDL_FILE_MGR_SIZE),
                          "ddl write file", ddl_mgr_buf) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY,
            ((uint64)(LOG_DDL_DATA_BUFFER_SIZE + LOG_DDL_FILE_MGR_SIZE)),
            "ddl write file");
        return CT_ERROR;
    }
    // set file_mgr addr
    logic_ddl_file_mgr *file_mgr = (logic_ddl_file_mgr *)(ddl_mgr_buf->aligned_buf);
    log_ddl_set_log_buffer(ddl_mgr_buf->aligned_buf, sizeof(logic_ddl_file_mgr),
                           &(file_mgr->file_buffer.ddl_data_buffer));
    file_mgr->buffer_offset = 0;
    file_mgr->file_flags = knl_io_flag(session);
    file_mgr->file_offset = 0;
    if (log_ddl_init_file(session, file_mgr) != CT_SUCCESS) {
        cm_aligned_free(&(session->kernel->ddl_file_mgr));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void log_ddl_file_end(knl_session_t *session)
{
    return cm_aligned_free(&(session->kernel->ddl_file_mgr));
}