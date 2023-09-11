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
 * knl_archive.c
 *
 *
 * IDENTIFICATION
 * src/kernel/persist/knl_archive.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_archive.h"
#include "cm_file.h"
#include "knl_context.h"
#include "knl_ctrl_restore.h"
#include "dtc_database.h"
#include "cm_dbs_ulog.h"
#include "srv_param_common.h"
#include "dirent.h"
#include "dtc_recovery.h"
#include "dtc_backup.h"
#define GS_MIN_FREE_LOGS 2

// LOG_ARCHIVE_FORMAT contains %s %r %t, need to reserve enough space for the integers
#define GS_ARCH_RESERVED_FORMAT_LEN (uint32)(GS_MAX_UINT32_PREC * 2 + GS_MAX_UINT64_PREC - 6)
#define ARCH_READ_BATCH_RETRY_TIMES 3
#define CT_SUCCESS 0

typedef struct st_arch_file_attr {
    const char *src_name;
    const char *arch_file_name;
    int32 src_file;
    int32 dst_file;
} arch_file_attr_t;

typedef struct st_arch_read_batch_attr {
    const char *src_name;
    uint64 start_lsn;
    uint64 *last_lsn;
    int32 *data_size;
} arch_read_batch_attr_t;

uint32 arch_get_arch_start(knl_session_t *session, uint32 node_id)
{
    return dtc_get_ctrl(session, node_id)->archived_start;
}

uint32 arch_get_arch_end(knl_session_t *session, uint32 node_id)
{
    return dtc_get_ctrl(session, node_id)->archived_end;
}

void arch_set_arch_start(knl_session_t *session, uint32 start, uint32 node_id)
{
    dtc_get_ctrl(session, node_id)->archived_start = start;
}

void arch_set_arch_end(knl_session_t *session, uint32 end, uint32 node_id)
{
    dtc_get_ctrl(session, node_id)->archived_end = end;
}

static status_t arch_save_ctrl(knl_session_t *session, uint32 node_id)
{
    if (session->kernel->attr.clustered) {
        return dtc_save_ctrl(session, node_id);
    }

    if (db_save_core_ctrl(session) != GS_SUCCESS) {
        CM_ABORT(0, "[CKPT] ABORT INFO: save core control file failed when perform checkpoint");
    }

    return GS_SUCCESS;
}

void arch_reset_file_id(knl_session_t *session, uint32 dest_pos)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    arch_proc_context_t *proc_ctx = &arch_ctx->arch_proc[dest_pos - 1];

    proc_ctx->last_file_id = GS_INVALID_ID32;
    proc_ctx->next_file_id = GS_INVALID_ID32;
}

bool32 arch_need_archive_dbstor(arch_proc_context_t *proc_ctx, log_context_t *redo_ctx)
{
    status_t status;
    uint32 redo_log_filesize = 0;
    uint64 used_time, used_intf_time;
    bool32 need_arch = GS_FALSE;
    log_file_t* logfile = redo_ctx->files + redo_ctx->curr_file;
    proc_ctx->next_file_id = redo_ctx->curr_file;
    ELAPSED_END(proc_ctx->arch_record_time.start_time, used_time);
    ELAPSED_END(proc_ctx->arch_record_time.start_intf_time, used_intf_time);

    knl_session_t *session = proc_ctx->session;
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    uint64 used_cap_intf_interval = arch_ctx->arch_time / ARCH_TRY_CAP_INTERVAL;

    bool32 force_archive = arch_ctx->force_archive_param.force_archive;
    if (force_archive) {
        proc_ctx->is_force_archive = GS_TRUE;
        need_arch = GS_TRUE;
    }

    if (used_intf_time < used_cap_intf_interval && !need_arch) {
        return GS_FALSE;
    }

    uint64 start_lsn = proc_ctx->last_archived_log_record.cur_lsn + 1;
    SYNC_POINT_GLOBAL_START(CANTIAN_ARCH_GET_LOG_CAPACITY_FAIL, &status, GS_ERROR);
    status = cm_device_get_used_cap(logfile->ctrl->type, logfile->handle, start_lsn, &redo_log_filesize);
    SYNC_POINT_GLOBAL_END;
    if (status != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[ARCH] failed to fetch redolog size from DBStor");
        return GS_FALSE;
    }
    ELAPSED_BEGIN(proc_ctx->arch_record_time.start_intf_time);
    proc_ctx->redo_log_filesize = SIZE_K_U64(redo_log_filesize);
    GS_LOG_DEBUG_INF("[ARCH] logfile handle (%d) lsn (%llu) size(%u)", logfile->handle, start_lsn, redo_log_filesize);
    if (need_arch) {
        return GS_TRUE;
    }

    if (redo_log_filesize == 0) {
        GS_LOG_DEBUG_INF("[ARCH] redo_log_filesize no need arch!");
        return GS_FALSE;
    }

    // the global arch_size for archive
    uint32_t arch_size = proc_ctx->session->kernel->arch_ctx.arch_size;
    GS_LOG_DEBUG_INF("[ARCH] size(%u) arch size(%u) used_time(%llu) arch_time(%llu)",
                     redo_log_filesize, arch_size, used_time, arch_ctx->arch_time);
    if (proc_ctx->redo_log_filesize < arch_size && used_time < arch_ctx->arch_time) {
        return GS_FALSE;
    }

    return GS_TRUE;
}

bool32 arch_need_archive(arch_proc_context_t *proc_ctx, log_context_t *redo_ctx)
{
    log_file_t *file = NULL;
    uint32 file_id = proc_ctx->last_file_id;
    uint32 ori_file_id = proc_ctx->last_file_id;

    proc_ctx->next_file_id = GS_INVALID_ID32;

    log_lock_logfile(proc_ctx->session);

    if (file_id == GS_INVALID_ID32) {
        file_id = redo_ctx->active_file;
    } else {
        log_get_next_file(proc_ctx->session, &file_id, GS_FALSE);
    }

    file = redo_ctx->files + file_id;

    /*
     * log file is current log file, no need to archive, and last_file_id = GS_INVALID_ID32 is needed.
     * Consider the scenario as follows: standby logfile is skipped and proc_ctx->last_file_id's next
     * is current file, will lead to active file can not be archived.
     *
     * 3 logfile, asn 7(file 0) is archived, asn 8~24 is skipped, asn 26(file 1) has been archived,
     * asn 27(file 2) is current file, asd asn 25(file 0) can not be archive, last_file_id is 1.
     */
    if (file_id == redo_ctx->curr_file) {
        log_unlock_logfile(proc_ctx->session);
        proc_ctx->last_file_id = DB_IS_PRIMARY(&proc_ctx->session->kernel->db) ? ori_file_id : GS_INVALID_ID32;
        return GS_FALSE;
    }

    /*
     * log file is invalid, need to check the next one.
     * On standby or cascade standby, log switch skip and this routine could run concurrently. Skipped
     * file will set GS_INVALID_ASN, and last_file_id will be push backwards slowly. This will lead to
     * some active file can not be archived immediately.
     */
    if (file->head.asn == GS_INVALID_ASN) {
        // Just skip this log file
        log_unlock_logfile(proc_ctx->session);
        proc_ctx->last_file_id = DB_IS_PRIMARY(&proc_ctx->session->kernel->db) ? file_id : GS_INVALID_ID32;
        return GS_FALSE;
    }

    // log file is valid, need to check whether it is archived
    if (file->ctrl->archived) {
        // already archived, skip it
        log_unlock_logfile(proc_ctx->session);
        proc_ctx->last_file_id = file_id;
        return GS_FALSE;
    } else {
        // need to archive this log file
        log_unlock_logfile(proc_ctx->session);
        proc_ctx->next_file_id = file_id;
        return GS_TRUE;
    }
}

void arch_set_archive_log_name_with_lsn(knl_session_t *session, uint32 rst_id, uint32 asn,
    uint32 dest_pos, char *buf, uint32 buf_size, uint32 node_id, uint64 start, uint64 end)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    arch_proc_context_t *proc_ctx = &arch_ctx->arch_proc[dest_pos - 1];
    char *cur_pos = arch_ctx->arch_format;
    char *last_pos = cur_pos;
    size_t dest_len;
    size_t remain_buf_size = buf_size;
    size_t offset = 0;
    errno_t ret;

    dest_len = strlen(proc_ctx->arch_dest);
    ret = strncpy_s(buf, remain_buf_size, proc_ctx->arch_dest, dest_len);
    knl_securec_check(ret);
    offset += strlen(proc_ctx->arch_dest);
    buf[offset] = '/';
    offset++;

    while (*cur_pos != '\0') {
        int32 print_num = 0;
        while (*cur_pos != '%' && *cur_pos != '\0') {
            // literal char, just move to next char
            cur_pos++;
        }

        if (*cur_pos == '\0' && cur_pos == last_pos) {
            break;
        }

        remain_buf_size = buf_size - offset;
        dest_len = cur_pos - last_pos;
        ret = strncpy_s(buf + offset, remain_buf_size, last_pos, dest_len);
        knl_securec_check(ret);
        offset += (cur_pos - last_pos);
        last_pos = cur_pos;

        if (*cur_pos == '\0') {
            break;
        }
        cur_pos++;

        // here we got a valid option, process it
        switch (*cur_pos) {
            case 's':
            case 'S': {
                print_num = snprintf_s(buf + offset, buf_size - offset, GS_MAX_UINT32_PREC, "%u", asn);
                knl_securec_check_ss(print_num);
                break;
            }
            case 't':
            case 'T': {
                print_num = snprintf_s(buf + offset, buf_size - offset, GS_MAX_UINT32_PREC, "%u", node_id);
                knl_securec_check_ss(print_num);
                break;
            }
            case 'r':
            case 'R': {
                print_num = snprintf_s(buf + offset, buf_size - offset, GS_MAX_UINT32_PREC, "%u", rst_id);
                knl_securec_check_ss(print_num);
                break;
            }
            case 'd':
            case 'D': {
                print_num = snprintf_s(buf + offset, buf_size - offset, GS_MAX_UINT64_PREC, "%llx", start);
                knl_securec_check_ss(print_num);
                break;
            }
            case 'e':
            case 'E': {
                print_num = snprintf_s(buf + offset, buf_size - offset, GS_MAX_UINT64_PREC, "%llx", end);
                knl_securec_check_ss(print_num);
                break;
            }
            default: {
                // Invalid format, just ignore.
                CM_ABORT(0, "[ARCH] ABORT INFO: ARCHIVE_FORMAT '%s' has wrong format '%c' for ARCHIVE_FORMAT",
                         arch_ctx->arch_format, *cur_pos);
                return;
            }
        }

        offset += print_num;
        cur_pos++;
        last_pos = cur_pos;
    }
}

void arch_set_archive_log_name(knl_session_t *session, uint32 rst_id, uint32 asn, uint32 dest_pos, char *buf,
                               uint32 buf_size, uint32 node_id)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    arch_proc_context_t *proc_ctx = &arch_ctx->arch_proc[dest_pos - 1];
    char *cur_pos = arch_ctx->arch_format;
    char *last_pos = cur_pos;
    size_t dest_len;
    size_t remain_buf_size = buf_size;
    size_t offset = 0;
    errno_t ret;

    dest_len = strlen(proc_ctx->arch_dest);
    ret = strncpy_s(buf, remain_buf_size, proc_ctx->arch_dest, dest_len);
    knl_securec_check(ret);
    offset += strlen(proc_ctx->arch_dest);
    buf[offset] = '/';
    offset++;

    while (*cur_pos != '\0') {
        int32 print_num = 0;
        while (*cur_pos != '%' && *cur_pos != '\0') {
            // literal char, just move to next char
            cur_pos++;
        }

        if (*cur_pos == '\0' && cur_pos == last_pos) {
            break;
        }

        remain_buf_size = buf_size - offset;
        dest_len = cur_pos - last_pos;
        ret = strncpy_s(buf + offset, remain_buf_size, last_pos, dest_len);
        knl_securec_check(ret);
        offset += (cur_pos - last_pos);
        last_pos = cur_pos;

        if (*cur_pos == '\0') {
            break;
        }
        cur_pos++;

        // here we got a valid option, process it
        switch (*cur_pos) {
            case 's':
            case 'S': {
                print_num = snprintf_s(buf + offset, buf_size - offset, GS_MAX_UINT32_PREC, "%u", asn);
                knl_securec_check_ss(print_num);
                break;
            }
            case 't':
            case 'T': {
                print_num = snprintf_s(buf + offset, buf_size - offset, GS_MAX_UINT64_PREC, "%lu", node_id);
                knl_securec_check_ss(print_num);
                break;
            }
            case 'r':
            case 'R': {
                print_num = snprintf_s(buf + offset, buf_size - offset, GS_MAX_UINT32_PREC, "%u", rst_id);
                knl_securec_check_ss(print_num);
                break;
            }
            default: {
                // Invalid format, just ignore.
                CM_ABORT(0, "[ARCH] ABORT INFO: ARCHIVE_FORMAT '%s' has wrong format '%c' for ARCHIVE_FORMAT",
                         arch_ctx->arch_format, *cur_pos);
                return;
            }
        }

        offset += print_num;
        cur_pos++;
        last_pos = cur_pos;
    }
}

void wait_archive_finished(knl_session_t *session)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    while (arch_ctx->force_archive_param.force_archive == GS_TRUE) {
        cm_sleep(100);
    }
    return;
}

status_t arch_force_archive_trigger(knl_session_t *session, uint64 end_lsn, bool32 wait)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    if (wait) {
        GS_LOG_RUN_INF("[ARCH] waiting for the end of the last archive");
        wait_archive_finished(session);
        GS_LOG_RUN_INF("[ARCH] start a new force archive");
    }
    arch_ctx->force_archive_param.force_archive = GS_TRUE;
    arch_ctx->force_archive_param.end_lsn = end_lsn;
    if (!wait) {
        GS_LOG_RUN_INF("force arch file, no need wait, end(%llu)", arch_ctx->force_archive_param.end_lsn);
        return GS_SUCCESS;
    }
    wait_archive_finished(session);
    GS_LOG_RUN_INF("[ARCH] force arch file, end wait lsn (%llu)", arch_ctx->force_archive_param.end_lsn);
    return GS_SUCCESS;
}

status_t arch_switch_archfile_trigger(knl_session_t *session, bool32 wait)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    arch_ctx->force_archive_param.force_archive = GS_TRUE;
    arch_ctx->force_archive_param.end_lsn = GS_INVALID_ID64;
    if (!wait) {
        GS_LOG_RUN_INF("switch file,no need wait");
        return GS_SUCCESS;
    }
    GS_LOG_RUN_INF("switch file, need wait");
    wait_archive_finished(session);
    return GS_SUCCESS;
}

void arch_get_files_num(knl_session_t *session, uint32 dest_id, uint32 node_id, uint32 *arch_num)
{
    uint32 archived_start = arch_get_arch_start(session, node_id);
    uint32 archived_end = arch_get_arch_end(session, node_id);

    *arch_num = (archived_end - archived_start + GS_MAX_ARCH_NUM) % GS_MAX_ARCH_NUM;
}

status_t arch_lsn_asn_convert(knl_session_t *session, uint64 lsn, uint32 *asn)
{
    uint32 node_id = session->kernel->id;
    bool32 find_arch = GS_FALSE;
    arch_ctrl_t *arch_ctrl = NULL;
    uint32 archived_start = arch_get_arch_start(session, node_id);
    uint32 archived_end = arch_get_arch_end(session, node_id);
    uint32 arch_locator;
    uint32 arch_num;
    uint32 i;
    uint32 rst_id = session->kernel->db.ctrl.core.resetlogs.rst_id;
    arch_get_files_num(session, ARCH_DEFAULT_DEST, node_id, &arch_num);
    for (i = 0; i < arch_num; i++) {
        arch_locator = (archived_start + i) % GS_MAX_ARCH_NUM;
        arch_ctrl = db_get_arch_ctrl(session, arch_locator, node_id);
        if (arch_ctrl->rst_id != rst_id) {
            continue;
        }

        GS_LOG_DEBUG_INF("arch_lsn_asn num (%u) start(%u) end(%u), locator(%u) start(%llu) end(%llu), lsn(%llu)",
            arch_num, archived_start, archived_end, arch_locator, arch_ctrl->start_lsn, arch_ctrl->end_lsn, lsn);
        if (lsn >= arch_ctrl->start_lsn && lsn <= arch_ctrl->end_lsn) {
            *asn = arch_ctrl->asn;
            find_arch = GS_TRUE;
            break;
        }
    }
    if (!find_arch) {
        arch_locator = (archived_start + arch_num - 1) % GS_MAX_ARCH_NUM;
        arch_ctrl = db_get_arch_ctrl(session, arch_locator, node_id);
        if (arch_ctrl->rst_id == rst_id) {
            *asn = arch_ctrl->asn;
            find_arch = GS_TRUE;
            GS_LOG_RUN_INF("can not find arch_ctrl->end_lsn >= lsn(%llu), choose lastest one, asn(%u).", lsn, *asn);
        }
    }
    if (arch_ctrl != NULL) {
        GS_LOG_DEBUG_INF("start(%llu) end(%llu) lsn(%llu) asn(%u)",
            arch_ctrl->start_lsn, arch_ctrl->end_lsn, lsn, *asn);
    }
    return find_arch ? GS_SUCCESS : GS_ERROR;
}

static inline status_t arch_clear_tmp_file(device_type_t arch_file_type, char *file_name)
{
    bool32 exist_tmp_file = cm_exist_device(arch_file_type, file_name);
    if (exist_tmp_file) {
        if (cm_remove_device(arch_file_type, file_name) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[ARCHIVE] failed to create temp archive log file %s", file_name);
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

static inline status_t arch_handle_fault(arch_proc_context_t *proc_ctx, char *file_name)
{
    device_type_t arch_file_type = cm_device_type(proc_ctx->arch_dest);
    if (proc_ctx->last_archived_log_record.start_lsn == GS_INVALID_ID64) {
        if (arch_clear_tmp_file(arch_file_type, file_name) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[ARCHIVE] failed to remove temp archive log file %s", TMP_ARCH_FILE_NAME);
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t arch_create_open_file(arch_proc_context_t *proc_ctx, const char *file_name,
    device_type_t arch_file_type, int32 *dst_file)
{
    knl_session_t *session = proc_ctx->session;
    bool32 exist_tmp_file = cm_exist_device(arch_file_type, file_name);
    if (!exist_tmp_file) {
        if (cm_create_device(file_name, arch_file_type, knl_io_flag(session), dst_file) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[ARCH] failed to create temp archive log file %s", file_name);
            return GS_ERROR;
        }
        cm_close_device(arch_file_type, dst_file);
    }

    if (cm_open_device(file_name, arch_file_type, knl_io_flag(session), dst_file) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[ARCH] failed to open archive log file %s", file_name);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

void arch_set_first_scn(void *buf, knl_scn_t *scn)
{
    log_batch_t *batch = (log_batch_t *)(buf);
    if (batch == NULL) {
        GS_LOG_RUN_ERR("[DTC RCY] batch is null");
        return;
    }
    if (!dtc_rcy_validate_batch(batch)) {
        return;
    }
    *scn = batch->scn;
    return;
}

status_t arch_check_log_valid(int32 data_size, char *buf)
{
    int32 buffer_size = data_size;
    uint32 invalide_size = 0;
    log_batch_t *batch = NULL;
    while (buffer_size >= sizeof(log_batch_t)) {
        batch = (log_batch_t *)(buf + invalide_size);
        if (batch == NULL) {
            GS_LOG_RUN_ERR("[ARCH] batch is null, read_size[%d], invalide_size[%u]",
                data_size, invalide_size);
            return GS_ERROR;
        }
        if (buffer_size < batch->size) {
            break;
        }
        if (!dtc_rcy_validate_batch(batch)) {
            GS_LOG_RUN_ERR("[ARCH] batch is invalidate, read_size[%d], invalide_size[%u]",
                data_size, invalide_size);
            return GS_ERROR;
        }
        invalide_size += batch->space_size;
        buffer_size -= batch->space_size;
    }
    return GS_SUCCESS;
}

static status_t arch_read_batch(log_file_t *logfile, arch_proc_context_t *proc_ctx,
    arch_read_batch_attr_t read_batch_attr)
{
    int32 src_file = logfile->handle;
    aligned_buf_t *arch_buf = &proc_ctx->arch_buf;
    status_t status;
    for (uint32 i = 0; i < ARCH_READ_BATCH_RETRY_TIMES; i++) {
        SYNC_POINT_GLOBAL_START(CANTIAN_ARCH_GET_LOG_FAIL, &status, GS_ERROR);
        status = cm_device_read_batch(logfile->ctrl->type, src_file, read_batch_attr.start_lsn, GS_INVALID_ID64,
            arch_buf->aligned_buf, arch_buf->buf_size, read_batch_attr.data_size, read_batch_attr.last_lsn);
        SYNC_POINT_GLOBAL_END;
        if (status != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[ARCH] fail to read log file %s lsn %llu read size %u", read_batch_attr.src_name,
                           read_batch_attr.start_lsn, *read_batch_attr.data_size);
            return GS_ERROR;
        }
        
        if (proc_ctx->session->kernel->attr.arch_log_check &&
            arch_check_log_valid(*read_batch_attr.data_size, arch_buf->aligned_buf) != GS_SUCCESS) {
            if (i < (ARCH_READ_BATCH_RETRY_TIMES - 1)) {
                continue;
            } else if (cm_dbs_is_enable_dbs() == GS_TRUE) {
                GS_LOG_RUN_ERR("[ARCH] fail to check log file.");
                return GS_ERROR;
            }
        } else {
            break;
        }
    }
    return GS_SUCCESS;
}

static void arch_get_first_scn(arch_proc_context_t *proc_ctx, log_file_t *logfile)
{
    aligned_buf_t *arch_buf = &proc_ctx->arch_buf;
    log_batch_t *batch = (log_batch_t *)(arch_buf->aligned_buf);
    proc_ctx->first_scn = batch->scn;
    GS_LOG_RUN_INF("[ARCH] get the first scn(%llu) succ", proc_ctx->first_scn);
}

status_t arch_write_file(const char *src_name, const char *dst_name, device_type_t arch_file_type,
    log_file_t *logfile, arch_proc_context_t *proc_ctx, uint64 start_lsn_input, uint64 end_lsn)
{
    uint64 start_lsn = start_lsn_input;
    int32 dst_file = GS_INVALID_HANDLE;
    int32 data_size;
    int64 left_size = (int64)proc_ctx->redo_log_filesize;
    uint64 *file_offset = &proc_ctx->last_archived_log_record.offset;
    uint64 *cur_lsn = &proc_ctx->last_archived_log_record.cur_lsn;
    uint64 last_lsn = *cur_lsn;
    aligned_buf_t *arch_buf = &proc_ctx->arch_buf;
    status_t status;
    arch_read_batch_attr_t read_batch_attr;

    if (arch_create_open_file(proc_ctx, dst_name, arch_file_type, &dst_file) != GS_SUCCESS) {
        return GS_ERROR;
    }

    read_batch_attr.src_name = src_name;
    read_batch_attr.last_lsn = &last_lsn;
    read_batch_attr.data_size = &data_size;

    do {
        read_batch_attr.start_lsn = start_lsn;
        if (arch_read_batch(logfile, proc_ctx, read_batch_attr) != GS_SUCCESS) {
            cm_close_device(arch_file_type, &dst_file);
            GS_LOG_RUN_ERR("[ARCH] fail to read log file");
            return GS_ERROR;
        }

        if (data_size == 0) {
            proc_ctx->redo_log_filesize = 0;
            GS_LOG_RUN_INF("[ARCH] reach last lsn, left size(%lld), data size(%d), last_lsn(%llu)",
                           left_size, data_size, last_lsn);
            break;
        }

        if (*file_offset == CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size)) {
            arch_get_first_scn(proc_ctx, logfile);
        }
        SYNC_POINT_GLOBAL_START(CANTIAN_ARCH_WRITE_LOG_TO_FILE_FAIL, &status, GS_ERROR);
        status = cm_write_device(arch_file_type, dst_file, *file_offset, arch_buf->aligned_buf, data_size);
        SYNC_POINT_GLOBAL_END;
        if (status != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[ARCH] fail to write arch %s lsn %llu write size %u", dst_name, *file_offset, data_size);
            cm_close_device(arch_file_type, &dst_file);
            return GS_ERROR;
        }
        
        left_size -= data_size;
        proc_ctx->redo_log_filesize -= data_size;
        start_lsn  = last_lsn + 1;
        *cur_lsn   = last_lsn;
        *file_offset += (uint64)data_size;
        GS_LOG_DEBUG_INF("[ARCH] left size(%lld), data size(%d), last_lsn(%llu)", left_size, data_size, last_lsn);
        if (last_lsn >= end_lsn) {
            proc_ctx->redo_log_filesize = 0;
            GS_LOG_RUN_INF("[ARCH] left size(%lld), data size(%d), last_lsn(%llu), end_lsn(%llu)",
                left_size, data_size, last_lsn, end_lsn);
            break;
        }
        if (*file_offset >= proc_ctx->session->kernel->arch_ctx.arch_file_size) {
            break;
        }
    } while (left_size > 0);
    proc_ctx->last_archived_log_record.start_lsn = proc_ctx->last_archived_log_record.end_lsn;
    GS_LOG_DEBUG_INF("[ARCH] start %llu cur %llu size %llu", proc_ctx->last_archived_log_record.start_lsn,
                     *cur_lsn, *file_offset);

    cm_close_device(arch_file_type, &dst_file);
    return GS_SUCCESS;
}
 
status_t arch_flush_head(device_type_t arch_file_type, const char *dst_name, arch_proc_context_t *proc_ctx,
                         log_file_t *file, log_file_head_t *head)
{
    knl_session_t *session = proc_ctx->session;
    int32 head_size = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
    int32 dst_file = GS_INVALID_HANDLE;
    aligned_buf_t *arch_buf = &proc_ctx->arch_buf;

    if (cm_open_device(dst_name, arch_file_type, knl_io_flag(session), &dst_file) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[ARCHIVE] failed to open archive log file %s", dst_name);
        return GS_ERROR;
    }
    status_t ret = memset_sp(arch_buf->aligned_buf, arch_buf->buf_size, 0, arch_buf->buf_size);
    knl_securec_check(ret);

    head->first = proc_ctx->first_scn;
    head->last = GS_INVALID_ID64;
    head->first_lsn = proc_ctx->last_archived_log_record.start_lsn;
    head->last_lsn = proc_ctx->last_archived_log_record.end_lsn;
    head->rst_id = file->head.rst_id;
    head->asn = proc_ctx->last_archived_log_record.asn;
    head->write_pos = proc_ctx->last_archived_log_record.offset;
    head->cmp_algorithm = COMPRESS_NONE;
    head->block_size = head_size;
    head->dbid = session->kernel->db.ctrl.core.dbid;
    ret = memset_sp(head->unused, GS_LOG_HEAD_RESERVED_BYTES, 0, GS_LOG_HEAD_RESERVED_BYTES);
    knl_securec_check(ret);

    log_calc_head_checksum(session, head);
    if (cm_write_device(arch_file_type, dst_file, 0, head, head_size) != GS_SUCCESS) {
        cm_close_device(arch_file_type, &dst_file);
        GS_LOG_ALARM(WARN_FLUSHREDO, "%s", dst_name);
        CM_ABORT(0, "[LOG] ABORT INFO: flush head:%s, offset:%u, size:%d failed.", dst_name, 0, head_size);
    }
    GS_LOG_RUN_INF("Flush head start[%llu] end[%llu] asn[%u] rst[%u] fscn[%llu], write_pos[%llu] head[%d] dbid[%u]",
                   head->first_lsn, head->last_lsn, head->asn, head->rst_id, head->first, head->write_pos,
                   head->block_size, head->dbid);
    cm_close_device(arch_file_type, &dst_file);
    return GS_SUCCESS;
}

static inline void arch_dbstor_update_progress(log_file_t *logfile, arch_proc_context_t *proc_ctx)
{
    proc_ctx->last_archived_log_record.end_lsn = proc_ctx->last_archived_log_record.cur_lsn;
    // next file offset start from log_head.
    if (proc_ctx->last_archived_log_record.rst_id < logfile->head.rst_id) {
        // pitr rst_id change, need reset asn to 1.
        proc_ctx->last_archived_log_record.rst_id = logfile->head.rst_id;
        proc_ctx->last_archived_log_record.asn = 1;
    }
}


static void arch_set_tmp_filename(char *file_name, arch_proc_context_t *proc_ctx, uint32 node_id)
{
    errno_t ret;
    size_t dest_len;
    char *buf = file_name;
    dest_len = strlen(proc_ctx->arch_dest);
    ret = strncpy_s(file_name, GS_FILE_NAME_BUFFER_SIZE, proc_ctx->arch_dest, dest_len);
    knl_securec_check(ret);
    file_name[dest_len] = '/';
    ret = snprintf_s(buf + strlen(proc_ctx->arch_dest) + 1, GS_FILE_NAME_BUFFER_SIZE - strlen(proc_ctx->arch_dest) - 1,
                     GS_MAX_UINT32_PREC, "%u", node_id);
    knl_securec_check_ss(ret);
    ret = strcat_s(file_name, GS_FILE_NAME_BUFFER_SIZE, TMP_ARCH_FILE_NAME);
    knl_securec_check(ret);
}

void arch_set_force_endlsn(bool32 force_archive, arch_proc_context_t *proc_ctx, uint64 *end_lsn)
{
    arch_context_t *arch_ctx = &proc_ctx->session->kernel->arch_ctx;
    if (force_archive && proc_ctx->is_force_archive && arch_ctx->force_archive_param.end_lsn != GS_INVALID_ID64) {
        *end_lsn = arch_ctx->force_archive_param.end_lsn;
        GS_LOG_RUN_INF("[ARCH] set end_lsn %llu for force archive!", arch_ctx->force_archive_param.end_lsn);
    }
}

status_t arch_dbstor_archive_file(const char *src_name, char *arch_file_name, log_file_t *logfile,
                                  log_file_head_t *head, arch_proc_context_t *proc_ctx)
{
    uint64 start_lsn = proc_ctx->last_archived_log_record.cur_lsn + 1;
    uint64 end_lsn = GS_INVALID_ID64;
    uint32 *asn = &proc_ctx->last_archived_log_record.asn;
    uint64 left_size = proc_ctx->redo_log_filesize;
    arch_context_t *arch_ctx = &proc_ctx->session->kernel->arch_ctx;
    bool32 force_archive = arch_ctx->force_archive_param.force_archive;
    uint64 arch_file_size = arch_ctx->arch_file_size;
    char tmp_file_name[GS_FILE_NAME_BUFFER_SIZE];
    device_type_t arch_file_type = cm_device_type(proc_ctx->arch_dest);
    uint64 cur_arch_file_size = proc_ctx->last_archived_log_record.offset;
    status_t status;
    if (cur_arch_file_size == 0) {
        proc_ctx->last_archived_log_record.offset = CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size);
    }
    if (force_archive || left_size + cur_arch_file_size >= arch_file_size) {
        GS_LOG_RUN_INF("[ARCH] force %d, left_size %llu, cur_size %llu, file_size %llu, start_lsn %llu", force_archive,
                       left_size, cur_arch_file_size, arch_file_size, start_lsn);
        proc_ctx->need_file_archive = GS_TRUE;
    }
    arch_set_tmp_filename(tmp_file_name, proc_ctx, proc_ctx->session->kernel->id);
    if (arch_handle_fault(proc_ctx, tmp_file_name) != GS_SUCCESS) {
        return GS_ERROR;
    }
    arch_set_force_endlsn(force_archive, proc_ctx, &end_lsn);
    if (arch_write_file(src_name, tmp_file_name, arch_file_type, logfile, proc_ctx, start_lsn, end_lsn) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (proc_ctx->need_file_archive) {
        if (proc_ctx->last_archived_log_record.end_lsn == proc_ctx->last_archived_log_record.cur_lsn) {
            proc_ctx->need_file_archive = GS_FALSE; // no log when force archive, need clear.
            GS_LOG_RUN_ERR("[ARCH] empty file no need to archive %s", tmp_file_name);
            return GS_ERROR;
        }
        arch_dbstor_update_progress(logfile, proc_ctx);
        if (arch_flush_head(arch_file_type, tmp_file_name, proc_ctx, logfile, head) != GS_SUCCESS) {
            return GS_ERROR;
        }
        proc_ctx->last_archived_log_record.offset = CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size);
        arch_set_archive_log_name_with_lsn(proc_ctx->session, logfile->head.rst_id, *asn,
            ARCH_DEFAULT_DEST, arch_file_name, GS_FILE_NAME_BUFFER_SIZE, proc_ctx->session->kernel->id,
            proc_ctx->last_archived_log_record.start_lsn, proc_ctx->last_archived_log_record.end_lsn);

        SYNC_POINT_GLOBAL_START(CANTIAN_ARCH_RENAME_TMP_FILE_FAIL, &status, GS_ERROR);
        status = cm_rename_device(arch_file_type, tmp_file_name, arch_file_name);
        SYNC_POINT_GLOBAL_END;
        if (status != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[ARCH] rename tmp file %s to %s failed", tmp_file_name, arch_file_name);
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

static status_t ctarch_write_archfile(knl_session_t *ct_se, aligned_buf_t write_buf, log_file_t *logfile,
    arch_file_attr_t *arch_attr, knl_compress_t *cmpr_ctx)
{
    return CT_SUCCESS;
}

static status_t arch_archive_tmp_file(knl_session_t *session, aligned_buf_t buf, char *tmp_arch_file_name,
    log_file_t *logfile, const char *src_name, const char *arch_file_name, knl_compress_t *compress_ctx)
{
    arch_file_attr_t arch_files;
    arch_files.arch_file_name = arch_file_name;
    arch_files.src_name = src_name;
    bool32 compress = session->kernel->attr.enable_arch_compress;
    device_type_t arch_file_type = cm_device_type(arch_file_name);
    if (cm_exist_device(arch_file_type, tmp_arch_file_name) &&
        cm_remove_device(arch_file_type, tmp_arch_file_name) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[ARCH] failed to remove remained temp archived log file %s", tmp_arch_file_name);
        return GS_ERROR;
    }

    arch_files.src_file = -1;
    if (cm_open_device(logfile->ctrl->name, logfile->ctrl->type, knl_redo_io_flag(session),
        &arch_files.src_file) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[ARCH] failed to open log file %s", logfile->ctrl->name);
        return GS_ERROR;
    }

    arch_files.dst_file = -1;
    if (cm_build_device(tmp_arch_file_name, logfile->ctrl->type, session->kernel->attr.xpurpose_buf,
        GS_XPURPOSE_BUFFER_SIZE, CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size),
        knl_arch_io_flag(session, compress), GS_FALSE, &arch_files.dst_file) != GS_SUCCESS) {
        cm_close_device(logfile->ctrl->type, &arch_files.src_file);
        return GS_ERROR;
    }

    if (cm_open_device(tmp_arch_file_name, logfile->ctrl->type, knl_arch_io_flag(session, compress),
        &arch_files.dst_file) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[ARCH] failed to create temp archive log file %s", tmp_arch_file_name);
        cm_close_device(logfile->ctrl->type, &arch_files.src_file);
        return GS_ERROR;
    }

    status_t status = ctarch_write_archfile(session, buf, logfile, &arch_files, compress_ctx);

    cm_close_device(logfile->ctrl->type, &arch_files.src_file);
    cm_close_device(logfile->ctrl->type, &arch_files.dst_file);
    return status;
}

status_t arch_archive_file(knl_session_t *session, aligned_buf_t buf, log_file_t *logfile,
    const char *arch_file_name, knl_compress_t *compress_ctx)
{
    const char *src_name = logfile->ctrl->name;
    char tmp_arch_file_name[GS_FILE_NAME_BUFFER_SIZE + 4] = {0}; /* 4 bytes for ".tmp" */
    uint64 left_size = logfile->head.write_pos;
    int32 ret;
    device_type_t arch_file_type = cm_device_type(arch_file_name);
    if (cm_exist_device(arch_file_type, arch_file_name)) {
        GS_LOG_RUN_INF("[ARCH] Archived log file %s already exits", arch_file_name);
        return GS_SUCCESS;
    } else {
        knl_panic(left_size > CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size));
    }

    ret = sprintf_s(tmp_arch_file_name, GS_FILE_NAME_BUFFER_SIZE + 4, "%s.tmp", arch_file_name);
    knl_securec_check_ss(ret);
    if (arch_archive_tmp_file(session, buf, tmp_arch_file_name, logfile, src_name,
        arch_file_name, compress_ctx) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_rename_device(arch_file_type, tmp_arch_file_name, arch_file_name) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[ARCH] failed to rename temp archive log file %s to %s", tmp_arch_file_name, arch_file_name);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void arch_init_arch_ctrl(knl_session_t *session, arch_ctrl_t *arch_ctrl, uint32 recid, uint32 dest_id,
                         const char *file_name, log_file_head_t *log_head)
{
    size_t file_name_size = strlen(file_name) + 1;
    errno_t ret;

    arch_ctrl->recid = recid;
    arch_ctrl->dest_id = dest_id;
    arch_ctrl->stamp = session->kernel->attr.timer->now;

    ret = memcpy_sp(arch_ctrl->name, GS_FILE_NAME_BUFFER_SIZE, file_name, file_name_size);
    knl_securec_check(ret);
    arch_ctrl->block_size = log_head->block_size;
    /* log_head->write_pos / log_head->block_size < max int32, cannont overflow */
    arch_ctrl->blocks = (int32)(log_head->write_pos / log_head->block_size);
    arch_ctrl->first = log_head->first;
    arch_ctrl->last = log_head->last;
    arch_ctrl->rst_id = log_head->rst_id;
    arch_ctrl->asn = log_head->asn;
    bool32 is_dbstor = knl_dbs_is_enable_dbs();
    if (is_dbstor) {
        arch_ctrl->start_lsn = log_head->first_lsn;
        arch_ctrl->end_lsn = log_head->last_lsn;
    }
}

int64 ctarch_get_arch_ctrl_size(arch_ctrl_t *ct_arch_ctrl)
{
    return 0;
}

bool32 ctarch_check_cmpr(arch_ctrl_t *ct_arch_ctrl)
{
    return FALSE;
}

static status_t ctarch_get_atch_file_size(const char *arch_file_name, int64 *file_size)
{
    return CT_SUCCESS;
}

void arch_record_arch_ctrl(arch_ctrl_t *arch_ctrl, knl_session_t *session, uint32 dest_id,
    const char *file_name, log_file_head_t *log_head, int64 real_file_size)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    arch_ctrl->recid = arch_ctx->archived_recid;
    arch_ctrl->dest_id = dest_id;
    arch_ctrl->stamp = session->kernel->attr.timer->now;
    size_t file_name_size = strlen(file_name) + 1;
    errno_t ret = memcpy_sp(arch_ctrl->name, GS_FILE_NAME_BUFFER_SIZE, file_name, file_name_size);
    knl_securec_check(ret);
    arch_ctrl->block_size = log_head->block_size;
    /* log_head->write_pos / log_head->block_size < max int32, cannont overflow */
    arch_ctrl->blocks = (int32)(log_head->write_pos / (uint32)log_head->block_size);
    arch_ctrl->first = log_head->first;
    arch_ctrl->last = log_head->last;
    arch_ctrl->rst_id = log_head->rst_id;
    arch_ctrl->asn = log_head->asn;
    arch_ctrl->real_size = real_file_size;
    if (cm_dbs_is_enable_dbs() == GS_TRUE) {
        arch_ctrl->start_lsn = log_head->first_lsn;
        arch_ctrl->end_lsn = log_head->last_lsn;
    }
}

status_t arch_record_archinfo(knl_session_t *session, uint32 dest_pos, const char *file_name, log_file_head_t *log_head,
                              uint32 node_id)
{
    arch_ctrl_t *arch_ctrl = NULL;
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    uint32 dest_id = dest_pos - 1;
    arch_proc_context_t *proc_ctx = &arch_ctx->arch_proc[dest_id];
    uint32 archived_start = arch_get_arch_start(session, node_id);
    uint32 archived_end = arch_get_arch_end(session, node_id);
    uint32 end_pos = (archived_end + 1) % GS_MAX_ARCH_NUM;
    int64 real_file_size = 0;
    uint32 recid;
    uint32 id;
    dtc_node_ctrl_t *node_ctrl = dtc_my_ctrl(session);

    if (ctarch_get_atch_file_size(file_name, &real_file_size) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[ARCH] Failed to record archive log file %s for log [%u-%u] start %u end %u", file_name,
                       log_head->rst_id, log_head->asn, node_ctrl->archived_start, node_ctrl->archived_end);
        return GS_ERROR;
    }

    cm_spin_lock(&arch_ctx->record_lock, NULL);
    recid = ++arch_ctx->archived_recid;
    cm_spin_unlock(&arch_ctx->record_lock);

    cm_spin_lock(&proc_ctx->record_lock, NULL);

    if (end_pos == archived_start) {
        arch_ctrl = db_get_arch_ctrl(session, end_pos, node_id);
        arch_ctrl->recid = recid;
        archived_end = (archived_start + 1) % GS_MAX_ARCH_NUM;
        arch_set_arch_end(session, archived_end, node_id);
        // only save node ctrl
        if (arch_save_ctrl(session, node_id) != GS_SUCCESS) {
            cm_spin_unlock(&proc_ctx->record_lock);
            CM_ABORT(0,
                     "[ARCH] ABORT INFO: save core control file failed when record archive log file %s for "
                     "log [%u-%u] start %u end %u",
                     file_name, log_head->rst_id, log_head->asn, node_ctrl->archived_start, node_ctrl->archived_end);
        }
    }

    id = archived_end;
    arch_ctrl = db_get_arch_ctrl(session, id, node_id);
    arch_record_arch_ctrl(arch_ctrl, session, dest_id, file_name, log_head, real_file_size);

    proc_ctx->curr_arch_size += real_file_size;
    arch_set_arch_end(session, end_pos, node_id);

    if (proc_ctx->last_archived_log.rst_id < log_head->rst_id ||
        (proc_ctx->last_archived_log.rst_id == log_head->rst_id && proc_ctx->last_archived_log.asn < log_head->asn)) {
        proc_ctx->last_archived_log.rst_id = log_head->rst_id;
        proc_ctx->last_archived_log.asn = log_head->asn;
        GS_LOG_DEBUG_INF("[ARCH] Set last_arch_log [%u-%u]", proc_ctx->last_archived_log.rst_id,
                         proc_ctx->last_archived_log.asn);
    }

    // save node ctrl and arch ctrl
    if (db_save_arch_ctrl(session, id, node_id) != GS_SUCCESS) {
        cm_spin_unlock(&proc_ctx->record_lock);
        CM_ABORT(0,
                 "[ARCH] ABORT INFO: save arch control file failed when record archive log file %s for "
                 "log [%u-%u] start %u end %u",
                 file_name, log_head->rst_id, log_head->asn, node_ctrl->archived_start, node_ctrl->archived_end);
    }

    GS_LOG_RUN_INF("[ARCH] Record archive log file %s for log [%u-%u] start %u end %u size %llu real size %lld",
                   arch_ctrl->name, log_head->rst_id, log_head->asn, archived_start, end_pos, log_head->write_pos,
                   real_file_size);
    cm_spin_unlock(&proc_ctx->record_lock);
    return GS_SUCCESS;
}

status_t ctarch_do_arch_info_record(knl_session_t *ct_se, uint32 arch_dest, const char *arch_file_name,
    log_file_head_t *log_head)
{
    return CT_SUCCESS;
}

arch_ctrl_t *arch_get_archived_log_info(knl_session_t *session, uint32 rst_id, uint32 asn, uint32 dest_pos,
                                        uint32 node_id)
{
    uint32 arch_num = 0;
    arch_ctrl_t *arch_ctrl = NULL;
    uint32 arch_locator = 0;
    uint32 archived_start = arch_get_arch_start(session, node_id);

    arch_get_files_num(session, dest_pos - 1, node_id, &arch_num);
    for (uint32 i = 0; i < arch_num; i++) {
        arch_locator = (archived_start + i) % GS_MAX_ARCH_NUM;
        arch_ctrl = db_get_arch_ctrl(session, arch_locator, node_id);
        if (arch_ctrl->recid == 0) {
            continue;
        }

        if (arch_ctrl->asn == asn) {
            if (arch_ctrl->rst_id != rst_id) {
                GS_LOG_DEBUG_INF("[ARCH] Archived log[%u-%u] found, but restlog id not equal, %u found but %u required",
                                 arch_ctrl->rst_id, arch_ctrl->asn, arch_ctrl->rst_id, rst_id);
            }
            if (arch_ctrl->rst_id == rst_id) {
                return arch_ctrl;
            }
        }
    }

    return NULL;
}

arch_ctrl_t *arch_get_archived_log_info_for_recovery(knl_session_t *session, uint32 rst_id, uint32 asn,
                                                     uint32 dest_pos, uint64 lsn, uint32 node_id)
{
    uint32 arch_num = 0;
    arch_ctrl_t *arch_ctrl = NULL;
    uint32 arch_locator = 0;
    uint32 archived_start = arch_get_arch_start(session, node_id);

    arch_get_files_num(session, dest_pos - 1, node_id, &arch_num);
    for (uint32 i = 0; i < arch_num; i++) {
        arch_locator = (archived_start + i) % GS_MAX_ARCH_NUM;
        arch_ctrl = db_get_arch_ctrl(session, arch_locator, node_id);
        if (arch_ctrl->recid == 0) {
            continue;
        }

        if (asn == 0) {
            if (lsn >= arch_ctrl->start_lsn && lsn < arch_ctrl->end_lsn) {
                return arch_ctrl;
            }
            continue;
        }

        if (arch_ctrl->asn == asn) {
            if (arch_ctrl->rst_id != rst_id) {
                GS_LOG_DEBUG_INF("[ARCH] Archived log[%u-%u] found, but restlog id not equal, %u found but %u required",
                                 arch_ctrl->rst_id, arch_ctrl->asn, arch_ctrl->rst_id, rst_id);
            }
            return arch_ctrl;
        }
    }

    return NULL;
}

arch_ctrl_t *arch_get_last_log(knl_session_t *session)
{
    uint32 arch_locator = 0;
    dtc_node_ctrl_t *node_ctrl = dtc_my_ctrl(session);

    if (node_ctrl->archived_end == 0) {
        arch_locator = GS_MAX_ARCH_NUM - 1;
    } else {
        arch_locator = (node_ctrl->archived_end - 1) % GS_MAX_ARCH_NUM;
    }

    return db_get_arch_ctrl(session, arch_locator, session->kernel->id);
}

arch_ctrl_t *arch_dtc_get_last_log(knl_session_t *session, uint32 inst_id)
{
    uint32 arch_locator = 0;
    dtc_node_ctrl_t *node_ctrl = dtc_get_ctrl(session, inst_id);

    if (node_ctrl->archived_end == 0) {
        arch_locator = GS_MAX_ARCH_NUM - 1;
    } else {
        arch_locator = (node_ctrl->archived_end - 1) % GS_MAX_ARCH_NUM;
    }

    return db_get_arch_ctrl(session, arch_locator, inst_id);
}

bool32 arch_archive_log_recorded(knl_session_t *session, uint32 rst_id, uint32 asn, uint32 dest_pos, uint32 node_id)
{
    arch_ctrl_t *arch_ctrl = arch_get_archived_log_info(session, rst_id, asn, dest_pos, node_id);
    return (arch_ctrl != NULL);
}

bool32 arch_need_print_error(knl_session_t *session, arch_proc_context_t *proc_ctx)
{
    if (proc_ctx->fail_time == 0) {
        proc_ctx->fail_time = KNL_NOW(session);
        return GS_TRUE;
    }

    if (KNL_NOW(session) - proc_ctx->fail_time >= ARCH_FAIL_PRINT_THRESHOLD) {
        proc_ctx->fail_time = KNL_NOW(session);
        return GS_TRUE;
    }

    return GS_FALSE;
}

void arch_do_archive(knl_session_t *session, arch_proc_context_t *proc_ctx)
{
    log_file_t *logfile = session->kernel->redo_ctx.files + proc_ctx->next_file_id;
    char arch_file_name[GS_FILE_NAME_BUFFER_SIZE] = {0};

    knl_panic_log(proc_ctx->next_file_id != GS_INVALID_ID32, "next_file_id is invalid.");

    if (logfile->head.asn == GS_INVALID_ASN) {
        GS_LOG_RUN_INF("[ARCH] Empty log file[%u], no need to archive. Skip to process next.", proc_ctx->next_file_id);

        // Try to recycle logfile
        dtc_node_ctrl_t *node_ctrl = dtc_my_ctrl(session);
        log_recycle_file(session, &node_ctrl->rcy_point);

        // Update last archived log file id
        proc_ctx->last_file_id = proc_ctx->next_file_id;

        return;
    }

    arch_set_archive_log_name(session, logfile->head.rst_id, logfile->head.asn, proc_ctx->arch_id, arch_file_name,
                              GS_FILE_NAME_BUFFER_SIZE, session->kernel->id);

    if (arch_archive_file(session, proc_ctx->arch_buf, logfile, arch_file_name, &proc_ctx->cmp_ctx) == GS_SUCCESS) {
        // Update last archived log file id
        proc_ctx->last_file_id = proc_ctx->next_file_id;
        GS_LOG_RUN_INF("[ARCH] Archive log file[%u], restlog id is %u, asn is %u to %s",
            proc_ctx->next_file_id, logfile->head.rst_id, logfile->head.asn, arch_file_name);

        if (!arch_archive_log_recorded(session, logfile->head.rst_id, logfile->head.asn, ARCH_DEFAULT_DEST,
                                       session->kernel->id)) {
            // Update control file archive information
            if (arch_record_archinfo(session, proc_ctx->arch_id, arch_file_name, &logfile->head, session->kernel->id) !=
                GS_SUCCESS) {
                return;
            }
        } else {
            if (proc_ctx->last_archived_log.rst_id < logfile->head.rst_id ||
                (proc_ctx->last_archived_log.rst_id == logfile->head.rst_id &&
                 proc_ctx->last_archived_log.asn < logfile->head.asn)) {
                arch_log_id_t id;
                id.rst_id = logfile->head.rst_id;
                id.asn = logfile->head.asn;
                proc_ctx->last_archived_log = id;
                GS_LOG_DEBUG_INF("[ARCH] Already archived %s, set last_arch_log [%u-%u]", arch_file_name,
                                 proc_ctx->last_archived_log.rst_id, proc_ctx->last_archived_log.asn);
            }
        }
        logfile->ctrl->archived = GS_TRUE;
        if (db_save_log_ctrl(session, proc_ctx->next_file_id, session->kernel->id) != GS_SUCCESS) {
            CM_ABORT(0, "[ARCH] ABORT INFO: save control redo file failed when archive file");
        }

        // Try to recycle logfile
        dtc_node_ctrl_t *node_ctrl = dtc_my_ctrl(session);
        log_recycle_file(session, &node_ctrl->rcy_point);

        if (proc_ctx->alarmed) {
            GS_LOG_ALARM_RECOVER(WARN_ARCHIVE, "'file-name':'%s'}", arch_file_name);
        }
        proc_ctx->alarmed = GS_FALSE;
        proc_ctx->fail_time = 0;
    } else {
        if (arch_need_print_error(session, proc_ctx)) {
            GS_LOG_RUN_ERR("[ARCH] Failed to archive log file[%u], restlog id is %u, asn is %u to %s",
                proc_ctx->next_file_id, logfile->head.rst_id, logfile->head.asn, arch_file_name);
        }
        cm_reset_error();
        if (!proc_ctx->alarmed) {
            GS_LOG_ALARM(WARN_ARCHIVE, "'file-name':'%s'}", arch_file_name);
            proc_ctx->alarmed = GS_TRUE;
        }
    }
}

void arch_wake_force_thread(arch_proc_context_t *proc_ctx)
{
    arch_context_t *arch_ctx = &proc_ctx->session->kernel->arch_ctx;
    if (arch_ctx->force_archive_param.force_archive && proc_ctx->is_force_archive) {
        if (arch_ctx->force_archive_param.end_lsn != GS_INVALID_ID64 &&
            proc_ctx->last_archived_log_record.cur_lsn < arch_ctx->force_archive_param.end_lsn &&
            proc_ctx->redo_log_filesize > 0) {
            GS_LOG_DEBUG_INF("[ARCH] force_archive process, end_lsn %llu, cur_lsn %llu",
                arch_ctx->force_archive_param.end_lsn, proc_ctx->last_archived_log_record.cur_lsn);
            return;
        }
        if (arch_ctx->force_archive_param.end_lsn == GS_INVALID_ID64 &&
            proc_ctx->redo_log_filesize > 0) {
            GS_LOG_DEBUG_INF("[ARCH] force_archive process, remaining size of redo log %llu",
                proc_ctx->redo_log_filesize);
            return;
        }
        GS_LOG_RUN_INF("[ARCH] force_archive success, end_lsn %llu, cur_lsn %llu, redo log size %llu, clear params!",
            arch_ctx->force_archive_param.end_lsn, proc_ctx->last_archived_log_record.cur_lsn,
            proc_ctx->redo_log_filesize);
        arch_ctx->force_archive_param.end_lsn = GS_INVALID_ID64;
        proc_ctx->is_force_archive = GS_FALSE;
        arch_ctx->force_archive_param.force_archive = GS_FALSE;
    }
}

void arch_set_process_alarmed(arch_proc_context_t *proc_ctx, char *arch_file_name, status_t arch_ret)
{
    if (arch_ret == GS_SUCCESS) {
        if (proc_ctx->alarmed) {
            GS_LOG_ALARM_RECOVER(WARN_ARCHIVE, "'file-name':'%s'}", arch_file_name);
        }
        proc_ctx->alarmed = GS_FALSE;
        proc_ctx->fail_time = 0;
    } else {
        if (!proc_ctx->alarmed) {
            GS_LOG_ALARM(WARN_ARCHIVE, "'file-name':'%s'}", arch_file_name);
            proc_ctx->alarmed = GS_TRUE;
        }
    }
}

void arch_dbstor_do_archive(knl_session_t *session, arch_proc_context_t *proc_ctx)
{
    log_file_t *logfile = session->kernel->redo_ctx.files + proc_ctx->next_file_id;
    log_file_head_t head = {0};
    uint32 *cur_asn = &proc_ctx->last_archived_log_record.asn;
    char arch_file_name[GS_FILE_NAME_BUFFER_SIZE] = {0};

    knl_panic_log(proc_ctx->next_file_id != GS_INVALID_ID32, "next_file_id is invalid.");
    status_t ret = arch_dbstor_archive_file(logfile->ctrl->name, arch_file_name, logfile, &head, proc_ctx);
    if (ret == GS_SUCCESS) {
        if (!proc_ctx->need_file_archive) {
            arch_wake_force_thread(proc_ctx);
            return;
        }
        proc_ctx->need_file_archive = GS_FALSE;

        if (!arch_archive_log_recorded(session, logfile->head.rst_id, *cur_asn, ARCH_DEFAULT_DEST,
                                       proc_ctx->session->kernel->id)) {
            if (arch_record_archinfo(session, ARCH_DEFAULT_DEST, arch_file_name, &head,
                proc_ctx->session->kernel->id) != GS_SUCCESS) {
                arch_wake_force_thread(proc_ctx);
                return;
            }
            proc_ctx->last_archived_log_record.asn++;
        } else {
            GS_LOG_RUN_ERR("[ARCH] the corresponding arch ctrl for archive log file [%s] already exists, "
                "restlog id is %u, asn is %u",
                arch_file_name, logfile->head.rst_id, *cur_asn);
            CM_ABORT(0, "[ARCH] ABORT INFO: the arch ctrl has been occupied.");
        }
        arch_wake_force_thread(proc_ctx);
        logfile->ctrl->archived = GS_TRUE;
        if (db_save_log_ctrl(session, proc_ctx->next_file_id, proc_ctx->session->kernel->id) != GS_SUCCESS) {
            CM_ABORT(0, "[ARCH] ABORT INFO: save control redo file failed when archive file");
        }

        dtc_node_ctrl_t *node_ctrl = dtc_my_ctrl(session);
        log_recycle_file(session, &node_ctrl->rcy_point);
    } else {
        arch_wake_force_thread(proc_ctx);
        if (arch_need_print_error(session, proc_ctx)) {
            GS_LOG_RUN_ERR("[ARCH] Failed to archive log file[%u], restlog id is %u, asn is %u to %s",
                proc_ctx->next_file_id, logfile->head.rst_id, logfile->head.asn, arch_file_name);
        }
        cm_reset_error();
    }
    arch_set_process_alarmed(proc_ctx, arch_file_name, ret);
}

bool32 arch_get_archived_log_name(knl_session_t *session, uint32 rst_id, uint32 asn, uint32 dest_pos, char *buf,
                                  uint32 buf_size, uint32 node_id)
{
    uint32 arch_num = 0;
    arch_ctrl_t *arch_ctrl = NULL;
    uint32 arch_locator = 0;
    uint32 archived_start = arch_get_arch_start(session, node_id);
    errno_t ret;

    arch_get_files_num(session, dest_pos - 1, node_id, &arch_num);
    for (uint32 i = 0; i < arch_num; i++) {
        arch_locator = (archived_start + i) % GS_MAX_ARCH_NUM;
        arch_ctrl = db_get_arch_ctrl(session, arch_locator, node_id);
        if (arch_ctrl->recid == 0) {
            continue;
        }

        if (arch_ctrl->asn == asn) {
            size_t dest_len;
            dest_len = strlen(arch_ctrl->name);
            ret = strncpy_s(buf, buf_size, arch_ctrl->name, dest_len);
            knl_securec_check(ret);
            if (arch_ctrl->rst_id != rst_id) {
                GS_LOG_DEBUG_INF("[ARCH] Archived log[%u-%u] found, but restlog id not equal, %u found but %u required",
                                 arch_ctrl->rst_id, arch_ctrl->asn, arch_ctrl->rst_id, rst_id);
            }
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

bool32 arch_can_be_cleaned(arch_ctrl_t *arch_ctrl, log_point_t *rcy_point, log_point_t *backup_rcy,
    knl_alterdb_archivelog_t *def)
{
    log_point_t curr_rcy_point;
    curr_rcy_point.asn = arch_ctrl->asn;
    curr_rcy_point.rst_id = arch_ctrl->rst_id;
    curr_rcy_point.lsn = arch_ctrl->end_lsn;

    if (!def->all_delete) {
        if (arch_ctrl->stamp > def->until_time) {
            return GS_FALSE;
        }
    }

    if (cm_dbs_is_enable_dbs() == GS_TRUE) {
        if (!LOG_POINT_FILE_LT_CHECK(curr_rcy_point, *rcy_point)) {
            return GS_FALSE;
        }

        if (!def->force_delete) {
            if (!LOG_POINT_FILE_LT_CHECK(curr_rcy_point, *backup_rcy)) {
                return GS_FALSE;
            }
        }
    } else {
        if (!LOG_POINT_FILE_LT(curr_rcy_point, *rcy_point)) {
            return GS_FALSE;
        }

        if (!def->force_delete) {
            if (!LOG_POINT_FILE_LT(curr_rcy_point, *backup_rcy)) {
                return GS_FALSE;
            }
        }
    }

    return GS_TRUE;
}

bool32 arch_needed_by_backup(knl_session_t *session, uint32 asn)
{
    bak_context_t *backup_ctx = &session->kernel->backup_ctx;

    if (!BAK_NOT_WORK(backup_ctx) || BAK_IS_BUILDING(backup_ctx)) {
        return bak_logfile_not_backed(session, asn);
    }

    // in two stage backup, after backup datafiles(stage one), we need save archive log for stage two
    if (backup_ctx->bak.record.data_only) {
        return (asn >= backup_ctx->bak.arch_stat.start_asn);
    }
    return GS_FALSE;
}

status_t clean_arch_file(arch_ctrl_t *arch_ctrl, uint32 archived_start, uint32 archived_end,
    log_point_t *rcy_point, log_point_t *backup_rcy)
{
    if (!cm_exist_device(cm_device_type(arch_ctrl->name), arch_ctrl->name)) {
        GS_LOG_RUN_INF("archive file %s is not exist", arch_ctrl->name);
        return GS_SUCCESS;
    }

    if (cm_remove_device(cm_device_type(arch_ctrl->name), arch_ctrl->name) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("Failed to remove archive file %s", arch_ctrl->name);
        return GS_ERROR;
    }

    GS_LOG_RUN_INF("[ARCH]archive file %s is cleaned, resetlog %u asn %u start_lsn %llu end_lsn %llu start %u end %u."
        "rcy_point(rst_id: %u, lsn: %llu, asn: %u), backup_rcy(rst_id: %u, lsn: %llu, asn: %u).",
        arch_ctrl->name, arch_ctrl->rst_id, arch_ctrl->asn, arch_ctrl->start_lsn, arch_ctrl->end_lsn,
        archived_start, archived_end, rcy_point->rst_id, rcy_point->lsn, rcy_point->asn, backup_rcy->rst_id,
        backup_rcy->lsn, backup_rcy->asn);
    
    return GS_SUCCESS;
}

status_t arch_do_real_clean(knl_session_t *session, arch_proc_context_t *proc_ctx, log_point_t *rcy_point,
    log_point_t *backup_rcy, uint64 target_size, knl_alterdb_archivelog_t *def)
{
    status_t status = GS_SUCCESS;
    uint32 archived_start = arch_get_arch_start(session, session->kernel->id);
    uint32 archived_end = arch_get_arch_end(session, session->kernel->id);
    uint32 arch_num = 0;
    uint32 clean_num = 0;
    uint32 clean_locator = 0;
    bool32 clean_skip = GS_FALSE;
    arch_ctrl_t *arch_ctrl = NULL;

    cm_spin_lock(&proc_ctx->record_lock, NULL);

    arch_get_files_num(session, proc_ctx->arch_id - 1, session->kernel->id, &arch_num);

    for (uint32 i = 0; i < arch_num; i++) {
        clean_locator = (archived_start + i) % GS_MAX_ARCH_NUM;
        arch_ctrl = db_get_arch_ctrl(session, clean_locator, session->kernel->id);
        if (arch_needed_by_backup(session, arch_ctrl->asn)) {
            break;
        }

        if (arch_ctrl->recid == 0) {
            if (!clean_skip) {
                clean_num++;
            }
            continue;
        }

        if (!arch_can_be_cleaned(arch_ctrl, rcy_point, backup_rcy, def)) {
            clean_skip = GS_TRUE;
            continue;
        }

        if (clean_arch_file(arch_ctrl, archived_start, archived_end, rcy_point, backup_rcy) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        arch_ctrl->recid = 0;
        if (!clean_skip) {
            clean_num++;
        }

        proc_ctx->curr_arch_size -= ctarch_get_arch_ctrl_size(arch_ctrl);

        if (db_save_arch_ctrl(session, clean_locator, session->kernel->id) != GS_SUCCESS) {
            cm_spin_unlock(&proc_ctx->record_lock);
            return GS_ERROR;
        }

        if ((uint64)proc_ctx->curr_arch_size < target_size) {
            break;
        }
    }

    archived_start = (archived_start + clean_num) % GS_MAX_ARCH_NUM;
    arch_set_arch_start(session, archived_start, session->kernel->id);
    if (arch_save_ctrl(session, session->kernel->id) != GS_SUCCESS) {
        status = GS_ERROR;
    }

    cm_spin_unlock(&proc_ctx->record_lock);
    return status;
}

status_t arch_check_bak_proc_status(knl_session_t *session)
{
    bool32 running = GS_FALSE;
    cluster_view_t view;
    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        if (i == g_dtc->profile.inst_id) {
            continue;
        }
        rc_get_cluster_view(&view, GS_FALSE);
        if (!rc_bitmap64_exist(&view.bitmap, i)) {
            GS_LOG_RUN_INF("[ARCH] inst id (%u) is not alive, alive bitmap: %llu", i, view.bitmap);
            continue;
        }
        if (dtc_bak_running(session, i, &running) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[ARCH] fail to get backup status from node %u.", i);
            return GS_ERROR;
        }
        if (running != GS_FALSE) {
            GS_LOG_DEBUG_ERR("[ARCH] backup process is running in node %u, do not clean archived logfiles.", i);
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t arch_clean_arch_files(knl_session_t *session, arch_proc_context_t *proc_ctx,
    knl_alterdb_archivelog_t *def, arch_clean_attr_t clean_attr)
{
    log_point_t local_rcy_point = dtc_my_ctrl(session)->rcy_point;
    bool32 ignore_standby = session->kernel->attr.arch_ignore_standby;
    log_point_t backup_rcy_point = clean_attr.backup_rcy_point;
    log_point_t min_rcy_point = clean_attr.min_rcy_point;

    if (session->kernel->attr.clustered) {
        dtc_node_ctrl_t *node_ctrl = dtc_my_ctrl(session);
        local_rcy_point = node_ctrl->rcy_point;
        if (arch_check_bak_proc_status(session) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (arch_do_real_clean(session, proc_ctx, &min_rcy_point, &backup_rcy_point,
        clean_attr.opt_size, def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (ignore_standby && !LOG_POINT_FILE_EQUAL(local_rcy_point, min_rcy_point) &&
        (uint64)proc_ctx->curr_arch_size > clean_attr.hwm_size) {
        GS_LOG_DEBUG_INF("[ARCH] begin to clean archive logfile ignore standby");
        if (arch_do_real_clean(session, proc_ctx, &local_rcy_point, &backup_rcy_point,
            clean_attr.hwm_size, def) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if ((uint64)proc_ctx->curr_arch_size > clean_attr.hwm_size) {
            GS_LOG_DEBUG_ERR("failed to clean archive logfile ignore standby, local rcy_point [%u-%u/%u/%llu], "
                             "total archive size %lld, archive hwm size %llu",
                             local_rcy_point.rst_id, local_rcy_point.asn, local_rcy_point.block_id,
                             (uint64)local_rcy_point.lfn, proc_ctx->curr_arch_size, clean_attr.hwm_size);
        }
    }

    return GS_SUCCESS;
}

status_t ctarch_set_clean_factor(knl_session_t *ct_se, arch_clean_attr_t* arch_clean_attr, bool32 clean)
{
    return CT_SUCCESS;
}

void arch_auto_clean(arch_proc_context_t *proc_ctx)
{
    knl_session_t *session = proc_ctx->session;
    uint64 max_arch_size = session->kernel->attr.max_arch_files_size;
    uint64 hwm_arch_size = max_arch_size * session->kernel->attr.arch_upper_limit / 100;
    knl_alterdb_archivelog_t def;
    arch_clean_attr_t clean_attr;

    if (!DB_IS_OPEN(session) || DB_IS_MAINTENANCE(session) ||
        max_arch_size == 0 || (uint64)proc_ctx->curr_arch_size < hwm_arch_size) {
        return;
    }

    if (ctarch_set_clean_factor(session, &clean_attr, GS_TRUE) != GS_SUCCESS) {
        return;
    }

    def.all_delete = GS_FALSE;
    def.force_delete = session->kernel->attr.arch_ignore_backup;
    def.until_time = GS_INVALID_INT64;

    (void)arch_clean_arch_files(session, proc_ctx, &def, clean_attr);
}

status_t arch_force_clean(knl_session_t *session, knl_alterdb_archivelog_t *def)
{
    arch_context_t *ctx = &session->kernel->arch_ctx;
    arch_proc_context_t *proc_ctx = NULL;
    arch_clean_attr_t clean_attr;

    if (ctarch_set_clean_factor(session, &clean_attr, GS_FALSE) != GS_SUCCESS) {
        return GS_SUCCESS;
    }

    for (uint32 i = 0; i < GS_MAX_ARCH_DEST; i++) {
        proc_ctx = &ctx->arch_proc[i];

        if (proc_ctx->arch_dest[0] == '\0') {
            continue;
        }

        if (arch_clean_arch_files(session, proc_ctx, def, clean_attr) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

void arch_try_update_contflush_point(log_point_t *cont_point, uint32 rst_id, uint32 asn)
{
    if (cont_point->rst_id <= rst_id && cont_point->asn == (asn - 1)) {
        cont_point->rst_id = rst_id;
        cont_point->asn = asn;
    }
}

void arch_check_cont_archived_log(arch_proc_context_t *proc_ctx)
{
    knl_session_t *session = proc_ctx->session;
    uint32 arch_num = 0;
    arch_ctrl_t *arch_ctrl = NULL;
    uint32 arch_locator = 0;
    dtc_node_ctrl_t *node_ctrl = dtc_my_ctrl(session);
    log_point_t rcy_point = node_ctrl->rcy_point;

    if (!DB_IS_OPEN(session) || DB_IS_PRIMARY(&session->kernel->db)) {
        return;
    }

    log_point_t *contflush_point = &session->kernel->lrcv_ctx.contflush_point;
    if (LOG_POINT_FILE_LT(*contflush_point, rcy_point)) {
        contflush_point->rst_id = rcy_point.rst_id;
        contflush_point->asn = rcy_point.asn;
    }

    if (!LOG_POINT_FILE_LT(*contflush_point, proc_ctx->last_archived_log)) {
        return;
    }

    arch_get_files_num(session, proc_ctx->arch_id - 1, session->kernel->id, &arch_num);
    for (uint32 i = 0; i < arch_num; i++) {
        arch_locator = (node_ctrl->archived_start + i) % GS_MAX_ARCH_NUM;
        arch_ctrl = db_get_arch_ctrl(session, arch_locator, session->kernel->id);
        if (arch_ctrl->recid == 0) {
            continue;
        }
        arch_try_update_contflush_point(contflush_point, arch_ctrl->rst_id, arch_ctrl->asn);
    }
}

void arch_proc(thread_t *thread)
{
    arch_proc_context_t *proc_ctx = (arch_proc_context_t *)thread->argument;
    knl_session_t *session = proc_ctx->session;
    log_context_t *redo_ctx = &session->kernel->redo_ctx;

    cm_set_thread_name("arch_proc");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());
    while (!thread->closed) {
        if (DB_NOT_READY(session) || !proc_ctx->enabled) {
            cm_sleep(200);
            continue;
        }

        if (arch_need_archive(proc_ctx, redo_ctx)) {
            // Try to archive log file
            arch_do_archive(session, proc_ctx);
        } else {
            // No work to do
            cm_sleep(1000);
        }

        // Try to record the max continuous received log in standby
        arch_check_cont_archived_log(proc_ctx);
        // Try to clean archived log file
        arch_auto_clean(proc_ctx);
    }

    GS_LOG_RUN_INF("[ARCH] Thread exit.");
    KNL_SESSION_CLEAR_THREADID(session);
}

void arch_dbstor_archive(arch_proc_context_t *proc_ctx)
{
    knl_session_t *session = proc_ctx->session;
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    if (proc_ctx->is_force_archive == GS_TRUE && arch_ctx->force_archive_param.force_archive == GS_TRUE) {
        do {
            arch_dbstor_do_archive(session, proc_ctx);
        } while (proc_ctx->redo_log_filesize > 0);
    } else {
        arch_dbstor_do_archive(session, proc_ctx);
    }
}

static void arch_dbstor_proc(thread_t *thread)
{
    arch_proc_context_t *proc_ctx = (arch_proc_context_t *)thread->argument;
    knl_session_t *session = proc_ctx->session;
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    uint64 sleep_time = MIN(arch_ctx->arch_time / 2000, 1000);
    ELAPSED_BEGIN(proc_ctx->arch_record_time.start_time);
    ELAPSED_BEGIN(proc_ctx->arch_record_time.start_intf_time);

    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());
    while (!thread->closed) {
        if (DB_NOT_READY(session) || !proc_ctx->enabled) {
            cm_sleep(200);
            continue;
        }
        if (arch_need_archive_dbstor(proc_ctx, redo_ctx)) {
            ELAPSED_BEGIN(proc_ctx->arch_record_time.start_time);
            arch_dbstor_archive(proc_ctx);
        } else {
            cm_sleep(sleep_time);
        }

        // Try to clean archived log file
        arch_auto_clean(proc_ctx);
    }

    GS_LOG_RUN_INF("[ARCH] Thread exit.");
    KNL_SESSION_CLEAR_THREADID(session);
}

status_t arch_check_dest(arch_context_t *arch_ctx, char *dest, uint32 cur_pos)
{
    arch_proc_context_t *proc_ctx = NULL;
    uint32 i;
    knl_attr_t *attr = &arch_ctx->arch_proc[0].session->kernel->attr;

    if (strlen(dest) == 0) {
        return GS_SUCCESS;
    }

    if (strlen(dest) >= GS_MAX_ARCH_NAME_LEN) {
        GS_THROW_ERROR(ERR_NAME_TOO_LONG, "arch dest path", strlen(dest), GS_MAX_ARCH_NAME_LEN);
        return GS_ERROR;
    }

    if (cm_check_exist_special_char(dest, (uint32)strlen(dest))) {
        GS_THROW_ERROR(ERR_INVALID_DIR, dest);
        return GS_ERROR;
    }

    if ((attr->arch_attr[cur_pos].dest_mode == LOG_ARCH_DEST_LOCATION) &&
        !cm_exist_device_dir(cm_device_type(dest), dest)) {
        GS_THROW_ERROR(ERR_DIR_NOT_EXISTS, dest);
        return GS_ERROR;
    }

    for (i = 0; i < GS_MAX_ARCH_DEST; i++) {
        proc_ctx = &arch_ctx->arch_proc[i];
        if (i == cur_pos || strlen(proc_ctx->arch_dest) == 0) {
            continue;
        }

        if (strcmp(proc_ctx->arch_dest, dest) == 0) {
            GS_THROW_ERROR(ERR_DUPLICATE_LOG_ARCHIVE_DEST, cur_pos + 1, i + 1);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

void renew_arch_log_record_lsn(knl_session_t *session, st_arch_log_record_id_t *last_arch_log_record)
{
    uint32 cur_rstid = session->kernel->db.ctrl.core.resetlogs.rst_id;
    if (cur_rstid > last_arch_log_record->rst_id) {
        last_arch_log_record->rst_id = cur_rstid;
        last_arch_log_record->asn = 1;
        last_arch_log_record->end_lsn = session->kernel->redo_ctx.curr_point.lsn;
        last_arch_log_record->cur_lsn = last_arch_log_record->end_lsn;
        GS_LOG_RUN_INF("[ARCH]new rst_id update last archlog record rstid [%u], endlsn [%llu], curlsn [%llu], \
            asn [%u]", last_arch_log_record->rst_id, last_arch_log_record->end_lsn,
            last_arch_log_record->cur_lsn, last_arch_log_record->asn);
    }
}

void arch_init_arch_files_size(knl_session_t *session, uint32 dest_id)
{
    uint32 arch_num, arch_locator;
    arch_ctrl_t *arch_ctrl = NULL;
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    arch_log_id_t *last_arch_log = NULL;
    st_arch_log_record_id_t *last_arch_log_record = NULL;
    last_arch_log_record = &arch_ctx->arch_proc[dest_id].last_archived_log_record;
    uint32 archived_start = arch_get_arch_start(session, session->kernel->id);

    arch_get_files_num(session, dest_id, session->kernel->id, &arch_num);

    if (cm_dbs_is_enable_dbs() == GS_TRUE) {
        last_arch_log_record->start_lsn = GS_INVALID_ID64;
        last_arch_log_record->asn = 1;
    }

    for (uint32 i = 0; i < arch_num; i++) {
        arch_locator = (archived_start + i) % GS_MAX_ARCH_NUM;
        arch_ctrl = db_get_arch_ctrl(session, arch_locator, session->kernel->id);
        if (arch_ctrl->recid == 0) {
            continue;
        }

        arch_ctx->arch_proc[dest_id].curr_arch_size += ctarch_get_arch_ctrl_size(arch_ctrl);

        last_arch_log = &arch_ctx->arch_proc[dest_id].last_archived_log;
        if (arch_ctrl->rst_id > last_arch_log->rst_id ||
            (arch_ctrl->rst_id == last_arch_log->rst_id && arch_ctrl->asn > last_arch_log->asn)) {
            last_arch_log->rst_id = arch_ctrl->rst_id;
            last_arch_log->asn = arch_ctrl->asn;
        }
        if (cm_dbs_is_enable_dbs() == GS_TRUE) {
            if (arch_ctrl->rst_id > last_arch_log_record->rst_id ||
                (arch_ctrl->rst_id == last_arch_log_record->rst_id && arch_ctrl->asn >= last_arch_log_record->asn)) {
                last_arch_log_record->rst_id = arch_ctrl->rst_id;
                last_arch_log_record->asn = arch_ctrl->asn + 1;
                last_arch_log_record->end_lsn = arch_ctrl->end_lsn;
                last_arch_log_record->cur_lsn = arch_ctrl->end_lsn;
            }
        }
    }
    if (cm_dbs_is_enable_dbs() == GS_TRUE) {
        renew_arch_log_record_lsn(session, last_arch_log_record);
    }
    if (dest_id == 0) {
        GS_LOG_RUN_INF("[ARCH]update last archlog record rstid[%u], endlsn[%llu], curlsn[%llu], asn[%u], archnum[%u]",
                       last_arch_log_record->rst_id, last_arch_log_record->end_lsn,
                       last_arch_log_record->cur_lsn, last_arch_log_record->asn, arch_num);
    }
}

static status_t arch_init_single_proc_ctx(arch_context_t *arch_ctx, uint32 dest_id, knl_session_t *session)
{
    const config_t *config = session->kernel->attr.config;
    const char *state_format = "ARCHIVE_DEST_STATE_%d";
    char param_name[GS_MAX_NAME_LEN];
    errno_t ret;

    arch_proc_context_t *proc_ctx = &arch_ctx->arch_proc[dest_id];
    ret = memset_sp(proc_ctx, sizeof(arch_proc_context_t), 0, sizeof(arch_proc_context_t));
    knl_securec_check(ret);

    proc_ctx->arch_id = dest_id + 1;
    proc_ctx->session = session->kernel->sessions[SESSION_ID_ARCH];
    proc_ctx->last_file_id = GS_INVALID_ID32;
    proc_ctx->next_file_id = GS_INVALID_ID32;
    proc_ctx->first_scn = GS_INVALID_ID64;
    proc_ctx->enabled = GS_FALSE;
    proc_ctx->alarmed = GS_FALSE;

    arch_attr_t *arch_attr = &session->kernel->attr.arch_attr[dest_id];

    // Set log archive destination path
    char *value = arch_attr->local_path;
    if (arch_set_dest(arch_ctx, value, dest_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    // Set log archive destination status
    ret = sprintf_s(param_name, GS_MAX_NAME_LEN, state_format, dest_id + 1); /* state_format length < 26 + 11 = 37 */
    knl_securec_check_ss(ret);
    value = cm_get_config_value(config, param_name);
    knl_panic_log(value != NULL, "the config value is NULL.");

    if (arch_set_dest_state(session, value, dest_id, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    arch_init_arch_files_size(session, dest_id);

    if (proc_ctx->arch_dest[0] != '\0' && proc_ctx->dest_status == STATE_ENABLE) {
        if (proc_ctx->arch_id > ARCH_DEFAULT_DEST) {
            GS_LOG_RUN_ERR("[ARCH] Multiple ARCHIVE_DEST not supported. ARCHIVE_DEST_%u is set.",
                proc_ctx->arch_id);
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "Set multiple ARCHIVE_DEST",
                "the situation when ARCHIVE_DEST is set");
            return GS_ERROR;
        }
        arch_ctx->arch_dest_num++;
        proc_ctx->enabled = GS_TRUE;
    }
    return GS_SUCCESS;
}

static status_t arch_init_proc_ctx(arch_context_t *arch_ctx, knl_session_t *session)
{
    for (uint32 i = 0; i < GS_MAX_ARCH_DEST; i++) {
        if (arch_init_single_proc_ctx(arch_ctx, i, session) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    // If no LOG_ARCHIVE_DEST_n is configured, set LOG_ARCHIVE_DEST_1 with default value.
    if (arch_ctx->arch_dest_num == 0) {
        arch_proc_context_t *proc_ctx = &arch_ctx->arch_proc[0];
        char *value = session->kernel->home;
        knl_panic_log(value != NULL, "the value is NULL.");

        int32 print_num = sprintf_s(proc_ctx->arch_dest, GS_FILE_NAME_BUFFER_SIZE, "%s/archive_log", value);
        knl_securec_check_ss(print_num);
        if (strlen(proc_ctx->arch_dest) >= GS_MAX_ARCH_NAME_LEN) {
            GS_THROW_ERROR(ERR_NAME_TOO_LONG, "dest path", strlen(proc_ctx->arch_dest), GS_MAX_ARCH_NAME_LEN);
            return GS_ERROR;
        }

        if (!cm_exist_device_dir(cm_device_type(proc_ctx->arch_dest), proc_ctx->arch_dest)) {
            if (cm_create_device_dir(cm_device_type(proc_ctx->arch_dest), proc_ctx->arch_dest) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[ARCH] failed to create dir %s", proc_ctx->arch_dest);
                return GS_ERROR;
            }
        }

        arch_ctx->arch_dest_num++;
        proc_ctx->enabled = GS_TRUE;
    }

    return GS_SUCCESS;
}

status_t arch_init(knl_session_t *session)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    database_ctrl_t *ctrl = &session->kernel->db.ctrl;
    const config_t *config = session->kernel->attr.config;
    char *value = NULL;

    if (arch_ctx->initialized) {
        if (!arch_ctx->is_archive && ctrl->core.log_mode == ARCHIVE_LOG_ON) {
            arch_ctx->is_archive = GS_TRUE;
        }

        GS_LOG_RUN_INF("[ARCH] Already initialized");
        return GS_SUCCESS;
    }

    arch_ctx->is_archive = (ctrl->core.log_mode == ARCHIVE_LOG_ON);

    dtc_node_ctrl_t *node_ctrl = dtc_my_ctrl(session);
    arch_ctx->rcy_point = &node_ctrl->rcy_point;

    arch_ctx->archived_recid = 0;
    arch_ctx->inst_id = session->kernel->id;

    if (cm_dbs_is_enable_dbs() == GS_TRUE) {
        value = cm_get_config_value(config, "ARCHIVE_FORMAT_WITH_LSN");
    } else {
        // Set archived log file name format
        value = cm_get_config_value(config, "ARCHIVE_FORMAT");
        knl_panic_log(value != NULL, "the config value is NULL.");
    }

    if (arch_set_format(arch_ctx, value)) {
        return GS_ERROR;
    }

    if (server_get_param_size_uint64("ARCH_FILE_SIZE", &arch_ctx->arch_file_size) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "ARCH_FILE_SIZE");
        return GS_ERROR;
    }

    if (server_get_param_size_uint64("ARCH_SIZE", &arch_ctx->arch_size) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "ARCH_SIZE");
        return GS_ERROR;
    }

    if (server_get_param_size_uint64("ARCH_TIME", &arch_ctx->arch_time) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "ARCH_TIME");
        return GS_ERROR;
    }

    if (arch_init_proc_ctx(arch_ctx, session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    arch_ctx->initialized = GS_TRUE;
    GS_LOG_RUN_INF("[ARCH] Initialization complete");
    return GS_SUCCESS;
}

void arch_last_archived_log(knl_session_t *session, uint32 dest_pos, arch_log_id_t *arch_log_out)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    arch_proc_context_t *proc_ctx = NULL;

    if (dest_pos <= GS_MAX_ARCH_DEST && dest_pos >= ARCH_DEFAULT_DEST) {
        proc_ctx = &arch_ctx->arch_proc[dest_pos - 1];
        if (proc_ctx->arch_id == 0) {
            arch_log_out->arch_log = 0;
        } else {
            *arch_log_out = proc_ctx->last_archived_log;
        }
    } else {
        CM_ABORT(0, "[ARCH] ABORT INFO: invalid destination id %u for archive", dest_pos);
    }
}

void arch_get_last_rstid_asn(knl_session_t *session, uint32 *rst_id, uint32 *asn)
{
    arch_log_id_t last_arch_log;
    arch_last_archived_log(session, ARCH_DEFAULT_DEST, &last_arch_log);

    *rst_id = last_arch_log.rst_id;
    *asn = last_arch_log.asn;
}

static int64 inline arch_get_buffer_size(knl_session_t *session)
{
    if (cm_dbs_is_enable_dbs() == GS_TRUE) {
        // dbstor batch's max size may extend to logw_buf_size.
        return (int64)session->kernel->attr.lgwr_buf_size;
    }
    return (int64)GS_ARCHIVE_BUFFER_SIZE;
}

status_t arch_start(knl_session_t *session)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    arch_proc_context_t *proc_ctx = NULL;
    database_ctrl_t *ctrl = &session->kernel->db.ctrl;
    uint32 i;
    int64 buffer_size;

    arch_ctx->is_archive = (ctrl->core.log_mode == ARCHIVE_LOG_ON);

    if (!arch_ctx->is_archive) {
        return GS_SUCCESS;
    }

    buffer_size = arch_get_buffer_size(session);

    for (i = 0; i < GS_MAX_ARCH_DEST; i++) {
        proc_ctx = &arch_ctx->arch_proc[i];
        if (proc_ctx != NULL && proc_ctx->arch_dest[0] != '\0' && proc_ctx->enabled) {
            if (cm_aligned_malloc(buffer_size, "archive buffer", &proc_ctx->arch_buf) != GS_SUCCESS) {
                GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)GS_ARCHIVE_BUFFER_SIZE, "copying archive log file");
                return GS_ERROR;
            }

            if (knl_compress_alloc(DEFAULT_ARCH_COMPRESS_ALGO, &proc_ctx->cmp_ctx, GS_TRUE) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[ARCH] Failed to alloc compress context for ARCHIVE_DEST_%d[%s]",
                    proc_ctx->arch_id, proc_ctx->arch_dest);
                cm_aligned_free(&proc_ctx->arch_buf);
                return GS_ERROR;
            }

            if (cm_aligned_malloc(GS_COMPRESS_BUFFER_SIZE, "archive compress buffer",
                &proc_ctx->cmp_ctx.compress_buf) != GS_SUCCESS) {
                GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)GS_COMPRESS_BUFFER_SIZE, "archive compress buffer");
                cm_aligned_free(&proc_ctx->arch_buf);
                knl_compress_free(DEFAULT_ARCH_COMPRESS_ALGO, &proc_ctx->cmp_ctx, GS_TRUE);
                return GS_ERROR;
            }

            proc_ctx->cmp_ctx.compress_level = 1;

            if (knl_compress_init(DEFAULT_ARCH_COMPRESS_ALGO, &proc_ctx->cmp_ctx, GS_TRUE) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[ARCH] Failed to init compress context for ARCHIVE_DEST_%d[%s]",
                    proc_ctx->arch_id, proc_ctx->arch_dest);
                cm_aligned_free(&proc_ctx->arch_buf);
                cm_aligned_free(&proc_ctx->cmp_ctx.compress_buf);
                knl_compress_free(DEFAULT_ARCH_COMPRESS_ALGO, &proc_ctx->cmp_ctx, GS_TRUE);
                return GS_ERROR;
            }

            if (cm_dbs_is_enable_dbs() != GS_TRUE) {
                if (cm_create_thread(arch_proc, 0, proc_ctx, &proc_ctx->thread) != GS_SUCCESS) {
                    cm_aligned_free(&proc_ctx->arch_buf);
                    cm_aligned_free(&proc_ctx->cmp_ctx.compress_buf);
                    knl_compress_free(DEFAULT_ARCH_COMPRESS_ALGO, &proc_ctx->cmp_ctx, GS_TRUE);
                    return GS_ERROR;
                }
            } else {
                if (cm_create_thread(arch_dbstor_proc, 0, proc_ctx, &proc_ctx->thread) != GS_SUCCESS) {
                    cm_aligned_free(&proc_ctx->arch_buf);
                    cm_aligned_free(&proc_ctx->cmp_ctx.compress_buf);
                    knl_compress_free(DEFAULT_ARCH_COMPRESS_ALGO, &proc_ctx->cmp_ctx, GS_TRUE);
                    return GS_ERROR;
                }
            }

            GS_LOG_RUN_INF("[ARCH] Start ARCH thread for ARCHIVE_DEST_%d[%s] buf_size[%llu]",
                           proc_ctx->arch_id, proc_ctx->arch_dest, buffer_size);
        }
    }

    return GS_SUCCESS;
}

void arch_close(knl_session_t *session)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    arch_proc_context_t *proc_ctx = NULL;
    uint32 i;

    for (i = 0; i < GS_MAX_ARCH_DEST; i++) {
        proc_ctx = &arch_ctx->arch_proc[i];
        if (proc_ctx->arch_dest[0] != '\0' && proc_ctx->enabled) {
            cm_close_thread(&proc_ctx->thread);
            cm_aligned_free(&proc_ctx->arch_buf);
            cm_aligned_free(&proc_ctx->cmp_ctx.compress_buf);
            knl_compress_free(DEFAULT_ARCH_COMPRESS_ALGO, &proc_ctx->cmp_ctx, GS_TRUE);
            GS_LOG_RUN_INF("[ARCH] Close ARCH thread for ARCHIVE_DEST_%d[%s]",
                           proc_ctx->arch_id, proc_ctx->arch_dest);
        }
    }
}

status_t arch_set_dest(arch_context_t *arch_ctx, char *value, uint32 pos)
{
    knl_panic_log(pos < GS_MAX_ARCH_DEST, "the pos is abnormal, panic info: pos %u", pos);
    arch_proc_context_t *proc_ctx = &arch_ctx->arch_proc[pos];
    size_t value_len;
    errno_t ret;

    cm_spin_lock(&arch_ctx->dest_lock, NULL);
    if (arch_check_dest(arch_ctx, value, pos) != GS_SUCCESS) {
        cm_spin_unlock(&arch_ctx->dest_lock);
        return GS_ERROR;
    }

    value_len = strlen(value);
    ret = strncpy_s(proc_ctx->arch_dest, GS_FILE_NAME_BUFFER_SIZE, value, value_len);
    knl_securec_check(ret);

    cm_spin_unlock(&arch_ctx->dest_lock);
    return GS_SUCCESS;
}

status_t arch_set_dest_state(knl_session_t *session, const char *value, uint32 cur_pos, bool32 notify)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    arch_proc_context_t *proc_ctx = &arch_ctx->arch_proc[cur_pos];
    knl_attr_t *attr = &session->kernel->attr;

    cm_spin_lock(&arch_ctx->dest_lock, NULL);
    if (cm_strcmpi(value, "DEFER") == 0) {
        proc_ctx->dest_status = STATE_DEFER;
    } else if (cm_strcmpi(value, "ALTERNATE") == 0) {
        proc_ctx->dest_status = STATE_ALTERNATE;
    } else if (cm_strcmpi(value, "ENABLE") == 0) {
        proc_ctx->dest_status = STATE_ENABLE;
    } else {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "archive_dest_state_n");
        cm_spin_unlock(&arch_ctx->dest_lock);
        return GS_ERROR;
    }

    if (!notify) {
        cm_spin_unlock(&arch_ctx->dest_lock);
        return GS_SUCCESS;
    }

    bool32 enable_orig = attr->arch_attr[cur_pos].enable;
    attr->arch_attr[cur_pos].enable = (bool32)(proc_ctx->dest_status == STATE_ENABLE);
    if (arch_check_dest_service(attr, &attr->arch_attr[cur_pos], cur_pos) != GS_SUCCESS) {
        attr->arch_attr[cur_pos].enable = enable_orig;
        cm_spin_unlock(&arch_ctx->dest_lock);
        return GS_ERROR;
    }

    arch_ctx->arch_dest_state_changed = GS_TRUE;
    GS_LOG_RUN_INF("ARCHIVE_DEST_STATE_%d is changed to %s", cur_pos + 1,
                   attr->arch_attr[cur_pos].enable ? "ENABLE" : "DISABLE");

    while (arch_ctx->arch_dest_state_changed) {
        cm_sleep(1);
        if (proc_ctx->thread.closed) {
            arch_ctx->arch_dest_state_changed = GS_FALSE;
            cm_spin_unlock(&arch_ctx->dest_lock);
            return GS_ERROR;
        }
    }

    cm_spin_unlock(&arch_ctx->dest_lock);
    return GS_SUCCESS;
}

static status_t arch_check_format(char *value, char *cur_pos, bool32 *has_asn, bool32 *has_instance_id,
                                  bool32 *has_rst_id, bool32 *has_start_lsn, bool32 *has_end_lsn)
{
    switch (*cur_pos) {
        case 's':
        case 'S': {
            if (*has_asn) {
                GS_THROW_ERROR_EX(ERR_INVALID_ARCHIVE_PARAMETER,
                    "'%s' has repeated format '%c' for ARCHIVE_FORMAT", value, *cur_pos);
                return GS_ERROR;
            }

            *has_asn = GS_TRUE;
            break;
        }
        case 't':
        case 'T': {
            if (*has_instance_id) {
                GS_THROW_ERROR_EX(ERR_INVALID_ARCHIVE_PARAMETER,
                    "'%s' has repeated format '%c' for ARCHIVE_FORMAT", value, *cur_pos);
                return GS_ERROR;
            }

            *has_instance_id = GS_TRUE;
            break;
        }
        case 'r':
        case 'R': {
            if (*has_rst_id) {
                GS_THROW_ERROR_EX(ERR_INVALID_ARCHIVE_PARAMETER,
                    "'%s' has repeated format '%c' for ARCHIVE_FORMAT", value, *cur_pos);
                return GS_ERROR;
            }

            *has_rst_id = GS_TRUE;
            break;
        }
        case 'd':
        case 'D': {
            if (*has_start_lsn) {
                GS_THROW_ERROR_EX(ERR_INVALID_ARCHIVE_PARAMETER,
                    "'%s' has repeated format '%c' for ARCHIVE_FORMAT", value, *cur_pos);
                return GS_ERROR;
            }

            *has_start_lsn = GS_TRUE;
            break;
        }
        case 'e':
        case 'E': {
            if (*has_end_lsn) {
                GS_THROW_ERROR_EX(ERR_INVALID_ARCHIVE_PARAMETER,
                    "'%s' has repeated format '%c' for ARCHIVE_FORMAT", value, *cur_pos);
                return GS_ERROR;
            }

            *has_end_lsn = GS_TRUE;
            break;
        }
        default: {
            // Invalid format.
            GS_THROW_ERROR_EX(ERR_INVALID_ARCHIVE_PARAMETER,
                "'%s' has wrong format '%c' for ARCHIVE_FORMAT", value, *cur_pos);
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t arch_set_format(arch_context_t *arch_ctx, char *value)
{
    char *cur_pos = value;
    bool32 has_asn = GS_FALSE;
    bool32 has_rst_id = GS_FALSE;
    bool32 has_instance_id = GS_FALSE;
    bool32 has_start_lsn = GS_FALSE;
    bool32 has_end_lsn = GS_FALSE;
    size_t value_len;
    errno_t ret;

    cm_spin_lock(&arch_ctx->dest_lock, NULL);
    if (strlen(value) > GS_MAX_ARCH_NAME_LEN - GS_ARCH_RESERVED_FORMAT_LEN) {
        GS_THROW_ERROR(ERR_NAME_TOO_LONG, "archive format", strlen(value),
                       GS_MAX_ARCH_NAME_LEN - GS_ARCH_RESERVED_FORMAT_LEN);
        cm_spin_unlock(&arch_ctx->dest_lock);
        return GS_ERROR;
    }

    while (*cur_pos != '\0') {
        while (*cur_pos != '%' && *cur_pos != '\0') {
            // literal char, just move to next.
            cur_pos++;
        }

        if (*cur_pos == '\0') {
            break;
        }

        cur_pos++;
        // here we got a valid option, process it
        if (arch_check_format(value, cur_pos, &has_asn, &has_instance_id,
                              &has_rst_id, &has_start_lsn, &has_end_lsn) != GS_SUCCESS) {
            cm_spin_unlock(&arch_ctx->dest_lock);
            return GS_ERROR;
        }
        cur_pos++;
    }

    if (cm_dbs_is_enable_dbs() == GS_TRUE) {
        if (!has_start_lsn || !has_end_lsn) {
            GS_THROW_ERROR_EX(ERR_INVALID_ARCHIVE_PARAMETER,
                              "'%s' does not contains start_lsn[s], end_lsn[r]for ARCHIVE_FORMAT", value);
            GS_LOG_RUN_ERR("ARCHIVE_FORMAT '%s' does not contains start_lsn[s], end_lsn[r] option", value);
            cm_spin_unlock(&arch_ctx->dest_lock);
            return GS_ERROR;
        }
    }

    if (has_asn && has_rst_id) {
        value_len = strlen(value);
        ret = strncpy_s(arch_ctx->arch_format, GS_FILE_NAME_BUFFER_SIZE, value, value_len);
        knl_securec_check(ret);
        cm_spin_unlock(&arch_ctx->dest_lock);
        return GS_SUCCESS;
    } else {
        GS_THROW_ERROR_EX(ERR_INVALID_ARCHIVE_PARAMETER,
                          "'%s' does not contains asn[s], resetlog[r] or instance[t] option for ARCHIVE_FORMAT", value);
        GS_LOG_RUN_ERR("ARCHIVE_FORMAT '%s' does not contains asn[s], resetlog[r] or instance[t] option", value);
        cm_spin_unlock(&arch_ctx->dest_lock);
        return GS_ERROR;
    }
}

status_t arch_set_max_processes(knl_session_t *session, char *value)
{
    GS_THROW_ERROR(ERR_NOT_COMPATIBLE, "ARCHIVE_MAX_THREADS");
    return GS_ERROR;
}

status_t arch_set_min_succeed(arch_context_t *ctx, char *value)
{
    GS_THROW_ERROR(ERR_NOT_COMPATIBLE, "ARCHIVE_MIN_SUCCEED_DEST");
    return GS_ERROR;
}

status_t arch_set_trace(char *value, uint32 *arch_trace)
{
    GS_THROW_ERROR(ERR_NOT_COMPATIBLE, "ARCHIVE_TRACE");
    return GS_ERROR;
}

char *arch_get_dest_type(knl_session_t *session, uint32 id, arch_attr_t *attr, bool32 *is_primary)
{
    database_t *db = &session->kernel->db;
    uint16 port;
    char host[GS_HOST_NAME_BUFFER_SIZE];

    *is_primary = GS_FALSE;
    if (id == 0) {
        return "LOCAL";
    }

    if (DB_IS_PRIMARY(db)) {
        if (attr->role_valid != VALID_FOR_STANDBY_ROLE && attr->enable) {
            return "PHYSICAL STANDBY";
        }

        return "UNKNOWN";
    }

    if (attr->enable) {
        lrcv_context_t *lrcv = &session->kernel->lrcv_ctx;
        if (lrcv->status == LRCV_DISCONNECTED || lrcv->status == LRCV_NEED_REPAIR ||
            lrcv_get_primary_server(session, 0, host, GS_HOST_NAME_BUFFER_SIZE, &port) != GS_SUCCESS) {
            return "UNKNOWN";
        }

        if (!strcmp(host, attr->service.host) && port == attr->service.port) {
            if (DB_IS_PHYSICAL_STANDBY(db) && attr->role_valid != VALID_FOR_STANDBY_ROLE) {
                *is_primary = GS_TRUE;
                return "PRIMARY";
            }

            if (DB_IS_CASCADED_PHYSICAL_STANDBY(db) && attr->role_valid != VALID_FOR_PRIMARY_ROLE) {
                return "PHYSICAL STANDBY";
            }
        } else {
            if (DB_IS_PHYSICAL_STANDBY(db)) {
                if (attr->role_valid == VALID_FOR_STANDBY_ROLE) {
                    return "CASCADED PHYSICAL STANDBY";
                }
            }

            return "UNKNOWN";
        }
    }

    return "UNKNOWN";
}

void arch_get_dest_path(knl_session_t *session, uint32 id, arch_attr_t *arch_attr, char *path, uint32 path_size)
{
    arch_proc_context_t *proc_ctx = &session->kernel->arch_ctx.arch_proc[id];
    errno_t ret;
    int32 print_num;
    size_t arch_dest_len = strlen(proc_ctx->arch_dest);

    if (id == 0) {
        ret = strncpy_s(path, path_size, proc_ctx->arch_dest, arch_dest_len);
        knl_securec_check(ret);
    } else if (arch_attr->used) {
        print_num = sprintf_s(path, path_size, "[%s:%u] %s",
                              arch_attr->service.host, arch_attr->service.port, proc_ctx->arch_dest);
        knl_securec_check_ss(print_num);
    } else {
        path[0] = '\0';
    }
}

char *arch_get_sync_status(knl_session_t *session, uint32 id, arch_attr_t *arch_attr, arch_dest_sync_t *sync_type)
{
    uint32 i;
    database_t *db = &session->kernel->db;
    lsnd_context_t *lsnd_ctx = &session->kernel->lsnd_ctx;
    lsnd_t *proc = NULL;

    if (DB_IS_PRIMARY(db) || DB_IS_PHYSICAL_STANDBY(db)) {
        if (id == 0) {
            *sync_type = ARCH_DEST_SYNCHRONIZED;
            return "OK";
        }

        if (arch_attr->enable) {
            if (db->ctrl.core.protect_mode == MAXIMUM_PERFORMANCE ||
                (DB_IS_PRIMARY(db) && arch_attr->net_mode != LOG_NET_TRANS_MODE_SYNC)) {
                *sync_type = ARCH_DEST_UNKNOWN;
                return "CHECK CONFIGURATION";
            }

            for (i = 0; i < GS_MAX_PHYSICAL_STANDBY; i++) {
                proc = lsnd_ctx->lsnd[i];
                if (proc == NULL) {
                    continue;
                }

                if (!strcmp(proc->dest_info.peer_host, arch_attr->service.host)) {
                    if (proc->status >= LSND_LOG_SHIFTING) {
                        *sync_type = ARCH_DEST_SYNCHRONIZED;
                        return "OK";
                    } else if (DB_IS_PRIMARY(db)) {
                        *sync_type = ARCH_DEST_NO_SYNCHRONIZED;
                        return "CHECK NETWORK";
                    } else {
                        *sync_type = ARCH_DEST_UNKNOWN;
                        return "NOT AVAILABLE";
                    }
                }
            }
        }
    }

    *sync_type = ARCH_DEST_UNKNOWN;
    return "NOT AVAILABLE";
}

char *arch_get_dest_sync(const arch_dest_sync_t *sync_type)
{
    switch (*sync_type) {
        case ARCH_DEST_SYNCHRONIZED:
            return "YES";
        case ARCH_DEST_NO_SYNCHRONIZED:
            return "NO";
        default:
            return "UNKNOWN";
    }
}

bool32 arch_dest_state_match_role(knl_session_t *session, arch_attr_t *arch_attr)
{
    return (bool32)((DB_IS_PRIMARY(&session->kernel->db) && arch_attr->role_valid != VALID_FOR_STANDBY_ROLE) ||
        (DB_IS_PHYSICAL_STANDBY(&session->kernel->db) && arch_attr->role_valid != VALID_FOR_PRIMARY_ROLE));
}

bool32 arch_dest_state_disabled(knl_session_t *session, uint32 inx)
{
    knl_attr_t *attr = &session->kernel->attr;

    return !attr->arch_attr[inx].enable;
}

void arch_set_deststate_disabled(knl_session_t *session, uint32 inx)
{
    knl_attr_t *attr = &session->kernel->attr;

    knl_panic(attr->arch_attr[inx].enable);
    attr->arch_attr[inx].enable = GS_FALSE;
}

static inline bool32 arch_dest_both_valid(arch_attr_t *tmp_attr, arch_attr_t *arch_attr)
{
    if (tmp_attr->role_valid != arch_attr->role_valid &&
        tmp_attr->role_valid != VALID_FOR_ALL_ROLES &&
        arch_attr->role_valid != VALID_FOR_ALL_ROLES) {
        return GS_FALSE;
    }

    return (bool32)(tmp_attr->enable && arch_attr->enable);
}

status_t arch_check_dest_service(void *attr, arch_attr_t *arch_attr, uint32 slot)
{
    uint32 i;
    arch_attr_t *tmp_attr = NULL;

    for (i = 1; i < GS_MAX_ARCH_DEST; i++) {
        tmp_attr = &((knl_attr_t *)attr)->arch_attr[i];

        if (i == slot || tmp_attr->dest_mode != LOG_ARCH_DEST_SERVICE) {
            continue;
        }

        if (strcmp(tmp_attr->service.host, arch_attr->service.host) == 0 &&
            tmp_attr->service.port == arch_attr->service.port &&
            arch_dest_both_valid(tmp_attr, arch_attr)) {
            GS_THROW_ERROR(ERR_DUPLICATE_LOG_ARCHIVE_DEST, slot + 1, i + 1);
            GS_LOG_RUN_ERR("ARCHIVE_DEST_%d destination is the same as ARCHIVE_DEST_%d", slot + 1, i + 1);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

bool32 arch_has_valid_arch_dest(knl_session_t *session)
{
    uint32 i;
    knl_attr_t *attr = &session->kernel->attr;

    if (!DB_IS_PRIMARY(&session->kernel->db)) {
        return GS_TRUE;
    }

    for (i = 1; i < GS_MAX_ARCH_DEST; i++) {
        if (attr->arch_attr[i].dest_mode == LOG_ARCH_DEST_SERVICE) {
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

status_t arch_regist_archive(knl_session_t *session, const char *name)
{
    int32 handle = GS_INVALID_HANDLE;
    log_file_head_t head = {0};
    device_type_t type = cm_device_type(name);
    if (cm_open_device(name, type, O_BINARY | O_SYNC | O_RDWR, &handle) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (cm_read_device(type, handle, 0, &head, sizeof(log_file_head_t)) != GS_SUCCESS) {
        cm_close_device(type, &handle);
        return GS_ERROR;
    }
    if ((head.cmp_algorithm == COMPRESS_NONE) && ((int64)head.write_pos != cm_device_size(type, handle))) {
        cm_close_device(type, &handle);
        GS_THROW_ERROR(ERR_INVALID_ARCHIVE_LOG, name);
        return GS_ERROR;
    }
    cm_close_device(type, &handle);
    if (ctarch_do_arch_info_record(session, ARCH_DEFAULT_DEST, name, &head) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t arch_try_regist_archive(knl_session_t *session, uint32 rst_id, uint32 *asn)
{
    char file_name[GS_FILE_NAME_BUFFER_SIZE] = { 0 };
    for (;;) {
        arch_set_archive_log_name(session, rst_id, *asn, ARCH_DEFAULT_DEST,
                                  file_name, GS_FILE_NAME_BUFFER_SIZE, session->kernel->id);

        if (!cm_exist_device(cm_device_type(file_name), file_name)) {
            break;
        }

        if (arch_regist_archive(session, file_name) != GS_SUCCESS) {
            return GS_ERROR;
        }

        (*asn)++;
    }

    return GS_SUCCESS;
}

void arch_reset_archfile(knl_session_t *session, uint32 replay_asn)
{
    arch_proc_context_t *proc_ctx = &session->kernel->arch_ctx.arch_proc[0];
    arch_ctrl_t *arch_ctrl = NULL;
    uint32 archived_start = arch_get_arch_start(session, session->kernel->id);
    uint32 archived_end = arch_get_arch_end(session, session->kernel->id);

    cm_spin_lock(&proc_ctx->record_lock, NULL);

    for (uint32 i = archived_start; i != archived_end;) {
        arch_ctrl = db_get_arch_ctrl(session, i, session->kernel->id);
        if (arch_ctrl->asn > replay_asn) {
            if (cm_exist_device(cm_device_type(arch_ctrl->name), arch_ctrl->name)) {
                if (cm_remove_device(cm_device_type(arch_ctrl->name), arch_ctrl->name) != GS_SUCCESS) {
                    GS_LOG_RUN_ERR("[ARCH] failed to remove archive logfile %s", arch_ctrl->name);
                } else {
                    proc_ctx->curr_arch_size -= ctarch_get_arch_ctrl_size(arch_ctrl);
                    GS_LOG_RUN_INF("[ARCH] remove archive logfile %s", arch_ctrl->name);
                }
            }

            arch_ctrl->recid = 0;

            if (db_save_arch_ctrl(session, i, session->kernel->id) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[ARCH] failed to save archive control file");
            }
        }

        i = (i + 1) % GS_MAX_ARCH_NUM;
    }

    cm_spin_unlock(&proc_ctx->record_lock);

    if (proc_ctx->last_archived_log.asn > replay_asn) {
        proc_ctx->last_archived_log.asn = replay_asn - 1;
    }
}

bool32 arch_log_not_archived(knl_session_t *session, uint32 req_rstid, uint32 req_asn)
{
    arch_log_id_t last_arch_log;
    database_t *db = &session->kernel->db;
    log_point_t point = session->kernel->redo_ctx.curr_point;
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    log_file_t *active_file = &redo_ctx->files[redo_ctx->active_file];

    arch_last_archived_log(session, ARCH_DEFAULT_DEST, &last_arch_log);

    if (DB_IS_PRIMARY(db) && req_asn < active_file->head.asn) {
        return GS_FALSE;
    }

    if (req_rstid > last_arch_log.rst_id || (req_rstid == last_arch_log.rst_id && req_asn > last_arch_log.asn)) {
        return GS_TRUE;
    }

    if (!DB_IS_PHYSICAL_STANDBY(db)) {
        return GS_FALSE;
    }

    /*
     * The resetid and asn in last archived log is not necessarily increasing in ascending order on standby,
     * because it may receive online log and archive log concurrently, and it is unpredictable which one will
     * be recorded in archive firstly.
     *
     * So on the standby, it is need to compare the requested resetid/asn with the replay point further.
     * If the former is larger than the latter, we should consider the requested log has not been archived.
     */
    return (bool32)(req_rstid > point.rst_id || (req_rstid == point.rst_id && req_asn > point.asn));
}

void arch_get_bind_host(knl_session_t *session, const char *srv_host, char *bind_host, uint32 buf_size)
{
    knl_attr_t *attr = &session->kernel->attr;
    arch_attr_t *arch_attr = NULL;
    size_t host_len;
    errno_t err;

    for (uint32 i = 1; i < GS_MAX_ARCH_DEST; i++) {
        arch_attr = &attr->arch_attr[i];

        if (strcmp(srv_host, arch_attr->service.host) == 0 && arch_attr->local_host[0] != '\0') {
            host_len = strlen(arch_attr->local_host);
            err = strncpy_s(bind_host, buf_size, arch_attr->local_host, host_len);
            knl_securec_check(err);
            return;
        }
    }

    bind_host[0] = '\0';
}

static bool32 arch_is_same(const char *arch_name, log_file_head_t head)
{
    log_file_head_t arch_head = {0};
    int32 handle = GS_INVALID_HANDLE;
    device_type_t type = cm_device_type(arch_name);
    if (cm_open_device(arch_name, type, 0, &handle) != GS_SUCCESS) {
        GS_LOG_RUN_INF("[ARCH] failed to open %s", arch_name);
        cm_reset_error();
        return GS_FALSE;
    }

    if (cm_read_device(type, handle, 0, &arch_head, sizeof(log_file_head_t)) != GS_SUCCESS) {
        cm_close_device(type, &handle);
        GS_LOG_RUN_INF("[ARCH] failed to read %s", arch_name);
        cm_reset_error();
        return GS_FALSE;
    }

    if (arch_head.cmp_algorithm == COMPRESS_NONE && cm_file_size(handle) != arch_head.write_pos) {
        cm_close_device(type, &handle);
        GS_LOG_RUN_INF("[ARCH] archive file %s is invalid", arch_name);
        return GS_FALSE;
    }
    cm_close_device(type, &handle);

    if (arch_head.first != head.first || arch_head.write_pos < head.write_pos) {
        GS_LOG_RUN_INF("[ARCH] archive file %s is not expected, arch info [%lld-%lld], expected log info [%lld-%lld]",
            arch_name, arch_head.write_pos, arch_head.first, head.write_pos, head.first);
        return GS_FALSE;
    }

    return GS_TRUE;
}

status_t arch_process_existed_archfile(knl_session_t *session, const char *arch_name,
    log_file_head_t head, bool32 *ignore_data)
{
    arch_proc_context_t *proc_ctx = &session->kernel->arch_ctx.arch_proc[0];
    arch_ctrl_t *arch_ctrl = NULL;
    *ignore_data = arch_is_same(arch_name, head);
    if (*ignore_data) {
        return GS_SUCCESS;
    }

    if (cm_remove_file(arch_name) != GS_SUCCESS) {
        return GS_ERROR;
    }

    dtc_node_ctrl_t *node_ctrl = dtc_my_ctrl(session);
    for (uint32 i = node_ctrl->archived_start; i != node_ctrl->archived_end;) {
        arch_ctrl = db_get_arch_ctrl(session, i, session->kernel->id);
        if (arch_ctrl->asn == head.asn && arch_ctrl->rst_id == head.rst_id) {
            proc_ctx->curr_arch_size -= (int64)arch_ctrl->blocks * arch_ctrl->block_size;
            arch_ctrl->recid = 0;
            if (db_save_arch_ctrl(session, i, session->kernel->id) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[ARCH] failed to save archive control file");
            }
            break;
        }
        i = (i + 1) % GS_MAX_ARCH_NUM;
    }

    GS_LOG_RUN_INF("[ARCH] Remove archive log %s", arch_name);
    return GS_SUCCESS;
}

static status_t log_try_get_file_offset(knl_session_t *session, log_file_t *logfile, aligned_buf_t *buf)
{
    uint64 size = (uint64)logfile->ctrl->size - logfile->head.write_pos;
    size = (size > buf->buf_size) ? buf->buf_size : size;

    if (logfile->head.write_pos == logfile->ctrl->size) {
        return GS_SUCCESS;
    }
    knl_panic(logfile->head.write_pos < logfile->ctrl->size);

    if (cm_read_device(logfile->ctrl->type, logfile->handle, logfile->head.write_pos,
        buf->aligned_buf, size) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[LOG] failed to read %s ", logfile->ctrl->name);
        return GS_ERROR;
    }
    log_batch_t *batch = (log_batch_t *)(buf->aligned_buf);
    log_batch_tail_t *tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));
    if (size < batch->space_size || !rcy_validate_batch(batch, tail) ||
        batch->head.point.rst_id != logfile->head.rst_id || batch->head.point.asn != logfile->head.asn) {
        return GS_SUCCESS;
    }

    uint64 latest_lfn;
    if (log_get_file_offset(session, logfile->ctrl->name, buf, (uint64 *)&logfile->head.write_pos,
        &latest_lfn, &logfile->head.last) != GS_SUCCESS) {
        return GS_ERROR;
    }
    log_flush_head(session, logfile);

    return GS_SUCCESS;
}

status_t arch_archive_redo(knl_session_t *session, log_file_t *logfile, aligned_buf_t arch_buf,
    aligned_buf_t log_buf, bool32 *is_continue, knl_compress_t *compress_ctx)
{
    char arch_file_name[GS_FILE_NAME_BUFFER_SIZE] = { 0 };
    bool32 ignore_data = GS_FALSE;

    if (log_init_file_head(session, logfile) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (logfile->head.write_pos <= CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size)) {
        GS_LOG_RUN_INF("[ARCH] Skip archive empty log file %s", logfile->ctrl->name);
        *is_continue = GS_TRUE;
        return GS_SUCCESS;
    }

    if (log_try_get_file_offset(session, logfile, &log_buf) != GS_SUCCESS) {
        return GS_ERROR;
    }
    arch_set_archive_log_name(session, logfile->head.rst_id, logfile->head.asn, ARCH_DEFAULT_DEST, arch_file_name,
                              GS_FILE_NAME_BUFFER_SIZE, session->kernel->id);

    if (cm_file_exist(arch_file_name)) {
        if (arch_process_existed_archfile(session, arch_file_name, logfile->head, &ignore_data) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (ignore_data) {
            GS_LOG_RUN_INF("[ARCH] skip archive log file %s to %s which already exists",
                logfile->ctrl->name, arch_file_name);
            if (arch_archive_log_recorded(session, logfile->head.rst_id, logfile->head.asn, ARCH_DEFAULT_DEST,
                                          session->kernel->id)) {
                *is_continue = GS_TRUE;
                return GS_SUCCESS;
            }
            return (arch_regist_archive(session, arch_file_name));
        }
    }

    if (arch_archive_file(session, arch_buf, logfile, arch_file_name, compress_ctx) != GS_SUCCESS) {
        return GS_ERROR;
    }
    GS_LOG_RUN_INF("[ARCH] Archive log file %s to %s", logfile->ctrl->name, arch_file_name);

    if (arch_regist_archive(session, arch_file_name) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t arch_redo_alloc_resource(knl_session_t *session, aligned_buf_t *log_buf, aligned_buf_t *arch_buf,
    knl_compress_t *compress_ctx)
{
    uint32 log_buf_size = (uint32)LOG_LGWR_BUF_SIZE(session) + SIZE_K(4);
    uint32 arch_buf_size = (uint32)GS_ARCHIVE_BUFFER_SIZE + SIZE_K(4);

    if (cm_aligned_malloc((int64)log_buf_size, "log buffer", log_buf) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[PITR] failed to alloc log buffer with size %u", log_buf_size);
        return GS_ERROR;
    }

    if (cm_aligned_malloc((int64)arch_buf_size, "arch redo buffer", arch_buf) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[PITR] failed to alloc arch redo buffer with size %u", arch_buf_size);
        cm_aligned_free(log_buf);
        return GS_ERROR;
    }

    if (knl_compress_alloc(DEFAULT_ARCH_COMPRESS_ALGO, compress_ctx, GS_TRUE) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[ARCH] Failed to alloc compress context");
        cm_aligned_free(log_buf);
        cm_aligned_free(arch_buf);
        return GS_ERROR;
    }

    compress_ctx->compress_level = 1;

    if (knl_compress_init(DEFAULT_ARCH_COMPRESS_ALGO, compress_ctx, GS_TRUE) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[PITR] Failed to init compress context");
        cm_aligned_free(log_buf);
        cm_aligned_free(arch_buf);
        knl_compress_free(DEFAULT_ARCH_COMPRESS_ALGO, compress_ctx, GS_TRUE);
    }

    if (cm_aligned_malloc(GS_COMPRESS_BUFFER_SIZE, "archive compress buffer",
        &compress_ctx->compress_buf) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)GS_COMPRESS_BUFFER_SIZE, "archive compress buffer");
        cm_aligned_free(log_buf);
        cm_aligned_free(arch_buf);
        knl_compress_free(DEFAULT_ARCH_COMPRESS_ALGO, compress_ctx, GS_TRUE);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t arch_try_arch_redo(knl_session_t *session, uint32 *max_asn)
{
    log_file_t *logfile = NULL;
    aligned_buf_t log_buf;
    aligned_buf_t arch_buf;
    knl_compress_t compress_ctx;

    if (arch_redo_alloc_resource(session, &log_buf, &arch_buf, &compress_ctx) != GS_SUCCESS) {
        return GS_ERROR;
    }

    *max_asn = 0;
    for (uint32 i = 0; i < dtc_my_ctrl(session)->log_hwm; i++) {
        logfile = &MY_LOGFILE_SET(session)->items[i];
        if (LOG_IS_DROPPED(logfile->ctrl->flg)) {
            continue;
        }
        if (logfile->ctrl->status == LOG_FILE_ACTIVE || logfile->ctrl->status == LOG_FILE_CURRENT) {
            bool32 is_continue = GS_FALSE;
            if (arch_archive_redo(session, logfile, arch_buf, log_buf, &is_continue, &compress_ctx) != GS_SUCCESS) {
                cm_aligned_free(&log_buf);
                cm_aligned_free(&arch_buf);
                cm_aligned_free(&compress_ctx.compress_buf);
                knl_compress_free(DEFAULT_ARCH_COMPRESS_ALGO, &compress_ctx, GS_TRUE);
            }

            if (is_continue) {
                continue;
            }

            if (logfile->head.asn >= *max_asn) {
                *max_asn = logfile->head.asn;
            }
        }
    }
    cm_aligned_free(&log_buf);
    cm_aligned_free(&arch_buf);
    cm_aligned_free(&compress_ctx.compress_buf);
    knl_compress_free(DEFAULT_ARCH_COMPRESS_ALGO, &compress_ctx, GS_TRUE);

    return GS_SUCCESS;
}

status_t ctarch_do_arch_log(knl_session_t *ct_se, uint32 rstid, uint32 asn)
{
    return CT_SUCCESS;
}

static bool32 arch_convert_err(const char *err)
{
    if (err == NULL) {
        return GS_FALSE;
    }
 
    if (*err != '\0') {
        if (*err != '_' && *err != '.') {
            // the arch file name illegal
            return GS_TRUE;
        }
    }
    // end of filename
    return GS_FALSE;
}

static status_t arch_str2uint32_withpos(const char *str, uint32 *value, char **endpos)
{
    char *err = NULL;
    int64 val_int64 = strtoll(str, &err, CM_DEFAULT_DIGIT_RADIX);
    if (val_int64 > UINT_MAX || val_int64 < 0) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
                          "Convert uint32 failed, the number text is not in the range of uint32, text = %s", str);
        return GS_ERROR;
    }
 
    *value = (uint32)val_int64;
    *endpos = err;
    return GS_SUCCESS;
}

static status_t arch_str2uint64_withpos(const char *str, uint64 *value, char **endpos)
{
    char *err = NULL;
    *value = strtoull(str, &err, CM_HEX_DIGIT_RADIX);
    if (arch_convert_err(err)) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Convert uint64 failed, text = %s", str);
        return GS_ERROR;
    }
 
    if (*value == ULLONG_MAX) {  // if str = "18446744073709551616", *value will be ULLONG_MAX
        if (cm_compare_str(str, (const char *)UNSIGNED_LLONG_MAX) != 0) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
                "Convert int64 failed, the number text is not in the range of unsigned long long, text = %s", str);
            return GS_ERROR;
        }
    }
    *endpos = err;
    return GS_SUCCESS;
}

static inline void arch_set_file_name(char *buf, char *arch_dest, uint32 dest_len, char *file_name)
{
    int32 print_num;
    print_num = sprintf_s(buf, GS_FILE_NAME_BUFFER_SIZE, "%s/%s", arch_dest, file_name);
    knl_securec_check_ss(print_num);
    return;
}

static const char *g_arch_suffix_name = ".arc";
static const uint32 g_arch_suffix_length = 4;

static status_t arch_convert_file_name_id_rst(char *file_name, char **pos, uint32 *node_id, uint32 *rst_id)
{
    if (arch_str2uint32_withpos(file_name, node_id, pos) != GS_SUCCESS) {
        return GS_ERROR;
    }
    file_name = *pos + 1;
    if (arch_str2uint32_withpos(file_name, rst_id, pos) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t arch_convert_file_name(char *file_name, uint32 *asn, uint64 *start_lsn, uint64 *end_lsn)
{
    char *pos = file_name;
    if (arch_str2uint32_withpos(pos, asn, &pos) != GS_SUCCESS) {
        return GS_ERROR;
    }
    pos++;
    if (arch_str2uint64_withpos(pos, start_lsn, &pos) != GS_SUCCESS) {
        return GS_ERROR;
    }
    pos++;
    if (arch_str2uint64_withpos(pos, end_lsn, &pos) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t arch_find_archive_log_name(knl_session_t *session, uint32 rst_id, uint32 node_id,
                                    uint64 lsn, char *buf, uint32 buf_size, uint64* out_lsn, uint32* out_asn)
{
    DIR *arch_dir;
    struct dirent *arch_dirent;
    arch_attr_t *arch_attr = &session->kernel->attr.arch_attr[0];
    char *pos;
    char *file_name;
    uint64 start_lsn, end_lsn;
    uint32 local_rst_id, local_node_id, asn;
    char *arch_path = arch_attr->local_path;
    char tmp_buf[GS_FILE_NAME_BUFFER_SIZE] = {0};
    uint32 tmp_buf_size = GS_FILE_NAME_BUFFER_SIZE;
    uint32 arch_file_dbid = 0;
    if ((arch_dir = opendir(arch_path)) == NULL) {
        return GS_ERROR;
    }
    while ((arch_dirent = readdir(arch_dir)) != NULL) {
        file_name = arch_dirent->d_name;
        uint32 name_length = strlen(file_name);
        if (name_length <= g_arch_suffix_length ||
            strcmp(file_name + name_length - g_arch_suffix_length, g_arch_suffix_name) != 0) {
            continue;
        }
        GS_LOG_DEBUG_INF("[ARCH] arch info : [%u/%u/%llu], filename[%s]", rst_id, node_id, lsn, file_name);
        file_name = arch_dirent->d_name;
        while (*file_name != '_' && *file_name != '\0') {
            file_name++;
        }
        file_name++;
        if (arch_convert_file_name_id_rst(file_name, &pos, &local_node_id, &local_rst_id) != GS_SUCCESS) {
            break;
        }
        if (node_id != local_node_id || rst_id != local_rst_id) {
            continue;
        }
        file_name = pos + 1;
        if (arch_convert_file_name(file_name, &asn, &start_lsn, &end_lsn) != GS_SUCCESS) {
            break;
        }
        if (lsn > start_lsn && lsn <= end_lsn) {
            memset_sp(tmp_buf, tmp_buf_size, 0, tmp_buf_size);
            arch_set_file_name(tmp_buf, arch_path, strlen(arch_path), arch_dirent->d_name);
            if (get_dbid_from_arch_logfile(session, &arch_file_dbid, tmp_buf) != GS_SUCCESS) {
                closedir(arch_dir);
                return GS_ERROR;
            }
            if (arch_file_dbid == session->kernel->db.ctrl.core.bak_dbid) {
                *out_lsn = end_lsn;
                *out_asn = asn;
                memset_sp(buf, buf_size, 0, buf_size);
                arch_set_file_name(buf, arch_path, strlen(arch_path), arch_dirent->d_name);
                closedir(arch_dir);
                return GS_SUCCESS;
            } else {
                GS_LOG_RUN_WAR("[RESTORE] the dbid %u of archive logfile %s is different from the bak dbid %u",
                    arch_file_dbid, tmp_buf, session->kernel->db.ctrl.core.bak_dbid);
            }
        }
    }
    closedir(arch_dir);
    return GS_ERROR;
}

status_t arch_find_archive_asn_log_name(knl_session_t *session, uint32 rst_id, uint32 node_id,
                                        uint32 arch_asn, char *buf, uint32 buf_size)
{
    DIR *arch_dir;
    struct dirent *arch_dirent;
    arch_attr_t *arch_attr = &session->kernel->attr.arch_attr[0];
    char *pos;
    char *file_name;
    uint64 start_lsn, end_lsn;
    uint32 local_rst_id, local_node_id, asn;
    char *arch_path = arch_attr->local_path;
    char tmp_buf[GS_FILE_NAME_BUFFER_SIZE] = {0};
    uint32 tmp_buf_size = GS_FILE_NAME_BUFFER_SIZE;
    uint32 arch_file_dbid = 0;
    if ((arch_dir = opendir(arch_path)) == NULL) {
        return GS_ERROR;
    }
    while ((arch_dirent = readdir(arch_dir)) != NULL) {
        file_name = arch_dirent->d_name;
        uint32 name_length = strlen(file_name);
        if (name_length <= g_arch_suffix_length ||
            strcmp(file_name + name_length - g_arch_suffix_length, g_arch_suffix_name) != 0) {
            continue;
        }
        GS_LOG_DEBUG_INF("[ARCH] arch info : [%u/%u/%u], filename[%s]", rst_id, node_id, arch_asn, file_name);
        while (*file_name != '_' && *file_name != '\0') {
            file_name++;
        }
        file_name++;
        if (arch_convert_file_name_id_rst(file_name, &pos, &local_node_id, &local_rst_id) != GS_SUCCESS) {
            break;
        }
        if (node_id != local_node_id || rst_id != local_rst_id) {
            continue;
        }
        file_name = pos + 1;
        if (arch_convert_file_name(file_name, &asn, &start_lsn, &end_lsn) != GS_SUCCESS) {
            break;
        }
        if (asn == arch_asn) {
            memset_sp(tmp_buf, tmp_buf_size, 0, tmp_buf_size);
            arch_set_file_name(tmp_buf, arch_path, strlen(arch_path), arch_dirent->d_name);
            if (get_dbid_from_arch_logfile(session, &arch_file_dbid, tmp_buf) != GS_SUCCESS) {
                closedir(arch_dir);
                return GS_ERROR;
            }
            if (arch_file_dbid == session->kernel->db.ctrl.core.bak_dbid) {
                memset_sp(buf, buf_size, 0, buf_size);
                arch_set_file_name(buf, arch_path, strlen(arch_path), arch_dirent->d_name);
                closedir(arch_dir);
                return GS_SUCCESS;
            } else {
                GS_LOG_RUN_WAR("[RECOVER] the dbid %u of archive logfile %s is different from the bak dbid %u",
                    arch_file_dbid, tmp_buf, session->kernel->db.ctrl.core.bak_dbid);
            }
        }
    }
    closedir(arch_dir);
    return GS_ERROR;
}

status_t arch_find_first_archfile_rst(knl_session_t *session, uint32 rst_id, uint32 node_id,
                                      char *buf, uint32 buf_size, uint32 *out_asn)
{
    DIR *arch_dir;
    struct dirent *arch_dirent;
    arch_attr_t *arch_attr = &session->kernel->attr.arch_attr[0];
    char *pos;
    char *file_name;
    uint32 local_rst_id, local_node_id;
    uint32 asn = 0;
    uint32 min_asn = 0;
    char *arch_path = arch_attr->local_path;
    *out_asn = 0;
    char tmp_buf[GS_FILE_NAME_BUFFER_SIZE] = {0};
    uint32 tmp_buf_size = GS_FILE_NAME_BUFFER_SIZE;
    uint32 arch_file_dbid = 0;
    if ((arch_dir = opendir(arch_path)) == NULL) {
        return GS_ERROR;
    }
    while ((arch_dirent = readdir(arch_dir)) != NULL) {
        file_name = arch_dirent->d_name;
        uint32 name_length = strlen(file_name);
        if (name_length <= g_arch_suffix_length ||
            strcmp(file_name + name_length - g_arch_suffix_length, g_arch_suffix_name) != 0) {
            continue;
        }
        GS_LOG_DEBUG_INF("[ARCH] arch info : [%u/%u/%u], filename[%s]", rst_id, node_id, asn, file_name);
        while (*file_name != '_' && *file_name != '\0') {
            file_name++;
        }
        file_name++;
        if (arch_convert_file_name_id_rst(file_name, &pos, &local_node_id, &local_rst_id) != GS_SUCCESS) {
            break;
        }
        if (node_id != local_node_id || rst_id != local_rst_id) {
            continue;
        }
        file_name = pos + 1;
        if (arch_str2uint32_withpos(file_name, &asn, &pos) != GS_SUCCESS) {
            break;
        }
        if (min_asn == 0 || min_asn > asn) {
            memset_sp(tmp_buf, tmp_buf_size, 0, tmp_buf_size);
            arch_set_file_name(tmp_buf, arch_path, strlen(arch_path), arch_dirent->d_name);
            if (get_dbid_from_arch_logfile(session, &arch_file_dbid, tmp_buf) != GS_SUCCESS) {
                closedir(arch_dir);
                return GS_ERROR;
            }
            if (arch_file_dbid == session->kernel->db.ctrl.core.bak_dbid) {
                *out_asn = asn;
                min_asn = asn;
                memset_sp(buf, buf_size, 0, buf_size);
                arch_set_file_name(buf, arch_path, strlen(arch_path), arch_dirent->d_name);
            } else {
                GS_LOG_RUN_WAR("[RECOVER] the dbid %u of archive logfile %s is different from the bak dbid %u",
                    arch_file_dbid, tmp_buf, session->kernel->db.ctrl.core.bak_dbid);
            }
        }
    }
    closedir(arch_dir);
    if (*out_asn != 0) {
        return GS_SUCCESS;
    }
    return GS_ERROR;
}

status_t arch_get_tmp_file_last_lsn(char *buf, int32 size_read, uint64 *lsn, uint32 *data_size)
{
    int32 buffer_size = size_read;
    uint32 invalide_size = 0;
    log_batch_t *batch = NULL;
    while (buffer_size >= sizeof(log_batch_t)) {
        batch = (log_batch_t *)(buf + invalide_size);
        if (batch == NULL) {
            GS_LOG_RUN_ERR("[DTC RCY] batch is null, read_size[%d], invalide_size[%u]",
                           size_read, invalide_size);
            return GS_ERROR;
        }
        if (buffer_size < batch->size) {
            break;
        }
        if (!dtc_rcy_validate_batch(batch)) {
            GS_LOG_RUN_ERR("[DTC RCY] batch is invalidate, read_size[%d], invalide_size[%u]",
                           size_read, invalide_size);
            return GS_ERROR;
        }
        invalide_size += batch->space_size;
        buffer_size -= batch->space_size;
    }
    if (batch == NULL) {
        GS_LOG_RUN_ERR("[DTC RCY] batch is null, read_size[%d]", size_read);
        return GS_ERROR;
    }
    *lsn = batch->lsn;
    *data_size = invalide_size;
    return GS_SUCCESS;
}

status_t arch_read_file(knl_session_t *session, char *file_name, int64 head_size, uint64 *out_lsn,
                        uint32 node_id, arch_proc_context_t *proc_ctx)
{
    int32  file_handle = GS_INVALID_HANDLE;
    int64  offset = 0;
    uint32 size_read = 0;
    uint32 data_size = 0;
    aligned_buf_t read_buf = {0};
    arch_set_tmp_filename(file_name, proc_ctx, node_id);
    bool32 exist_tmp_file = cm_exist_device(cm_device_type(proc_ctx->arch_dest), file_name);
    if (!exist_tmp_file) {
        *out_lsn = 0;
        return GS_SUCCESS;
    }
    if (cm_aligned_malloc(GS_MAX_BATCH_SIZE, "log buffer", &read_buf) != GS_SUCCESS) {
        return GS_ERROR;
    }

    int64 size_need_read = read_buf.buf_size;
    char* buf = read_buf.aligned_buf;
    do {
        offset = offset == 0 ? head_size : offset + data_size;
        status_t status = dtc_rcy_read_log(session, &file_handle, file_name, offset,
                                           buf, read_buf.buf_size, size_need_read, &size_read);
        if (status != GS_SUCCESS) {
            cm_aligned_free(&read_buf);
            return status;
        }
        if (size_read == 0) {
            proc_ctx->last_archived_log_record.offset = offset;
            cm_aligned_free(&read_buf);
            return status;
        }
        status = arch_get_tmp_file_last_lsn(buf, (int32)(size_read), out_lsn, &data_size);
        if (status != GS_SUCCESS) {
            cm_aligned_free(&read_buf);
            return status;
        }
    } while (size_read > 0);
    cm_aligned_free(&read_buf);
    return GS_SUCCESS;
}

status_t arch_force_archive_file(knl_session_t *session, uint32 node_id, int32 block_size,
                                 device_type_t type, int32 handle)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    log_file_t *logfile = redo_ctx->files;
    arch_ctrl_t *arch_ctrl = NULL;
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    arch_proc_context_t *proc_ctx_force = &arch_ctx->arch_proc[ARCH_DEFAULT_DEST - 1];
    // read temp file and get start end lsn.
    char  file_name[GS_FILE_NAME_BUFFER_SIZE];
    uint64 start_lsn    = 0;
    uint64 cur_lsn      = 0;
    uint32 archived_end = 0;
    uint32 redo_log_filesize = 0;
    arch_ctx->force_archive_param.force_archive = GS_TRUE;
    arch_ctx->force_archive_param.end_lsn = GS_INVALID_ID64;
    proc_ctx_force->next_file_id = redo_ctx->curr_file;
    proc_ctx_force->session = session;

    const config_t *config = session->kernel->attr.config;
    char *format_value = NULL;
    format_value = cm_get_config_value(config, "ARCHIVE_FORMAT_WITH_LSN");
    if (arch_set_format(arch_ctx, format_value)) {
        return GS_ERROR;
    }

    char *value = cm_get_config_value(config, "ARCHIVE_DEST_1");
    strncpy_s(proc_ctx_force->arch_dest, GS_FILE_NAME_BUFFER_SIZE, &value[ARCH_DEST_PREFIX_LENGTH],
              strlen(value) - ARCH_DEST_PREFIX_LENGTH);

    if (arch_read_file(session, file_name, block_size, &cur_lsn, node_id, proc_ctx_force) != GS_SUCCESS) {
        return GS_ERROR;
    }
    archived_end = arch_get_arch_end(session, node_id);
    arch_ctrl = db_get_arch_ctrl(session, archived_end, node_id);
    if (arch_ctrl == NULL) {
        return GS_ERROR;
    }
    if (cm_aligned_malloc(arch_get_buffer_size(session), "archive buffer", &proc_ctx_force->arch_buf) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)GS_ARCHIVE_BUFFER_SIZE, "copying archive log file");
        return GS_ERROR;
    }
    proc_ctx_force->last_archived_log_record.rst_id = arch_ctrl->rst_id;
    uint32 asn = arch_ctrl->asn + 1;
    start_lsn = arch_ctrl->end_lsn;
    proc_ctx_force->last_archived_log_record.asn = asn;
    proc_ctx_force->last_archived_log_record.start_lsn = start_lsn;
    proc_ctx_force->last_archived_log_record.end_lsn = start_lsn;
    proc_ctx_force->last_archived_log_record.cur_lsn = cur_lsn == 0 ? arch_ctrl->end_lsn : cur_lsn;

    GS_LOG_RUN_INF("[ARCH] archinit rst_id [%u], start [%llu], end [%llu], asn [%u], cur [%llu]",
                   arch_ctrl->rst_id, arch_ctrl->start_lsn, arch_ctrl->end_lsn, arch_ctrl->asn, cur_lsn);
    start_lsn = proc_ctx_force->last_archived_log_record.cur_lsn + 1;
    if (cm_device_get_used_cap(type, handle, start_lsn, &redo_log_filesize) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[ARCH] failed to fetch redolog size from DBStor");
        cm_aligned_free(&proc_ctx_force->arch_buf);
        return GS_ERROR;
    }
    proc_ctx_force->redo_log_filesize = SIZE_K(redo_log_filesize);
    proc_ctx_force->session->kernel->id = node_id;
    proc_ctx_force->need_file_archive = GS_TRUE;
    logfile->head.asn = arch_ctrl->asn;
    logfile->handle = handle;
    do {
        arch_dbstor_do_archive(session, proc_ctx_force);
    } while (proc_ctx_force->redo_log_filesize > 0);
    if (proc_ctx_force->alarmed == GS_TRUE) {
        cm_aligned_free(&proc_ctx_force->arch_buf);
        return GS_ERROR;
    }
    cm_aligned_free(&proc_ctx_force->arch_buf);
    return GS_SUCCESS;
}
