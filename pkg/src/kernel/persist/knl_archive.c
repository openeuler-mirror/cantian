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
 * knl_archive.c
 *
 *
 * IDENTIFICATION
 * src/kernel/persist/knl_archive.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_archive_module.h"
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
#include "knl_lrepl_meta.h"
#define CT_MIN_FREE_LOGS 2

// LOG_ARCHIVE_FORMAT contains %s %r %t, need to reserve enough space for the integers
#define CT_ARCH_RESERVED_FORMAT_LEN (uint32)(CT_MAX_UINT32_PREC * 2 + CT_MAX_UINT64_PREC - 6)
#define ARCH_READ_BATCH_RETRY_TIMES 3
#define ARCH_FORCE_ARCHIVE_WAIT_SLEEP_TIME 1000
#define ARCH_FAIL_WAIT_SLEEP_TIME 5000
#define ARCH_WAIT_WRITE_FINISH_SLEEP_TIME 200 // 200ms
#define DTC_TIME_INTERVAL_OPEN_WARNING_US 500000 // 500ms
#define ARCH_FORCE_WAIT_PROC_TIME 100

const char *g_arch_suffix_name = ".arc";
const uint32 g_arch_suffix_length = 4;

arch_standby_ctx_t g_arch_standby_ctx = { 0 };

const arch_func_context g_arch_func[] = {
    {"ARCHIVE_FORMAT", ARCH_RW_BUF_NUM, arch_proc_init_file, arch_need_archive_file, arch_file_archive,
     arch_check_cont_archived_log_file, arch_write_proc_file, arch_log_point_file, arch_auto_clean},
    {"ARCHIVE_FORMAT_WITH_LSN", DBSTOR_ARCH_RW_BUF_NUM, arch_proc_init_dbstor, arch_need_archive_dbstor,
     arch_dbstor_archive, arch_check_cont_archived_log_dbstor, arch_write_proc_dbstor, arch_log_point_dbstor,
     arch_auto_clean},
    {"ARCHIVE_FORMAT_WITH_LSN_STANDBY", DBSTOR_ARCH_RW_BUF_NUM, arch_proc_init_dbstor, arch_need_archive_dbstor,
     arch_dbstor_archive, arch_check_cont_archived_log_dbstor, arch_write_proc_dbstor, arch_log_point_dbstor,
     arch_auto_clean_standby},
};

typedef struct st_arch_file_attr {
    const char *src_name;
    const char *arch_file_name;
    int32 src_file;
    int32 dst_file;
    log_file_head_t *log_head;
} arch_file_attr_t;

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

status_t arch_save_ctrl(knl_session_t *session, uint32 node_id)
{
    if (session->kernel->attr.clustered) {
        return dtc_save_ctrl(session, node_id);
    }

    if (db_save_core_ctrl(session) != CT_SUCCESS) {
        CM_ABORT(0, "[CKPT] ABORT INFO: save core control file failed when perform checkpoint");
    }

    return CT_SUCCESS;
}

void arch_reset_file_id(knl_session_t *session, uint32 dest_pos)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    arch_proc_context_t *proc_ctx = &arch_ctx->arch_proc[dest_pos - 1];

    proc_ctx->last_file_id = CT_INVALID_ID32;
    proc_ctx->next_file_id = CT_INVALID_ID32;
}


bool32 arch_need_wait_clean(arch_proc_context_t *proc_ctx)
{
    uint32 node_id = arch_get_proc_node_id(proc_ctx);
    uint32 archived_start = arch_get_arch_start(proc_ctx->session, node_id);
    uint32 archived_end = arch_get_arch_end(proc_ctx->session, node_id);
    uint32 end_pos = (archived_end + 1) % CT_MAX_ARCH_NUM;
    if (end_pos == archived_start) {
        CT_LOG_RUN_WAR("[ARCH] need to wait archived file clean");
        return CT_TRUE;
    }
    return CT_FALSE;
}

bool32 arch_need_archive_dbstor(arch_proc_context_t *proc_ctx, log_context_t *redo_ctx)
{
    status_t status;
    uint32 redo_log_filesize = 0;
    uint64 used_time, used_intf_time;
    bool32 need_arch = CT_FALSE;
    proc_ctx->next_file_id = redo_ctx->curr_file;
    log_file_t* logfile = arch_get_proc_logfile(proc_ctx);

    if (arch_need_wait_clean(proc_ctx) == CT_TRUE) {
        return CT_FALSE;
    }

    ELAPSED_END(proc_ctx->arch_record_time.start_time, used_time);
    ELAPSED_END(proc_ctx->arch_record_time.start_intf_time, used_intf_time);

    knl_session_t *session = proc_ctx->session;
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    uint64 arch_intervel_time = session->kernel->db.ctrl.core.lrep_mode == LOG_REPLICATION_ON ?
        ARCH_TIME_FOR_LOGICREP : arch_ctx->arch_time;
    uint64 used_cap_intf_interval = arch_intervel_time / ARCH_TRY_CAP_INTERVAL;

    bool32 force_archive = CT_FALSE;
    arch_get_force_archive_param(proc_ctx, &force_archive);
    if (force_archive) {
        proc_ctx->is_force_archive = CT_TRUE;
        need_arch = CT_TRUE;
    }

    if (used_intf_time < used_cap_intf_interval && !need_arch) {
        return CT_FALSE;
    }

    uint64 start_lsn = proc_ctx->last_archived_log_record.cur_lsn + 1;
    SYNC_POINT_GLOBAL_START(CANTIAN_ARCH_GET_LOG_CAPACITY_FAIL, &status, CT_ERROR);
    status = cm_device_get_used_cap(logfile->ctrl->type, logfile->handle, start_lsn, &redo_log_filesize);
    SYNC_POINT_GLOBAL_END;
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ARCH] failed to fetch redolog size from DBStor");
        return CT_FALSE;
    }
    // 间隔 used_intf_time 查询一次
    ELAPSED_BEGIN(proc_ctx->arch_record_time.start_intf_time);
    proc_ctx->redo_log_filesize = SIZE_K_U64(redo_log_filesize);
    CT_LOG_DEBUG_INF("[ARCH] logfile handle (%d) lsn (%llu) size(%u)", logfile->handle, start_lsn, redo_log_filesize);
    if (need_arch) {
        ELAPSED_BEGIN(proc_ctx->arch_record_time.start_time);
        return CT_TRUE;
    }

    if (redo_log_filesize == 0) {
        CT_LOG_DEBUG_INF("[ARCH] redo_log_filesize no need arch!");
        return CT_FALSE;
    }

    // the global arch_size for archive
    uint32_t arch_size = proc_ctx->session->kernel->arch_ctx.arch_size;
    CT_LOG_DEBUG_INF("[ARCH] size(%u) arch size(%u) used_time(%llu) arch_time(%llu)",
                     redo_log_filesize, arch_size, used_time, arch_intervel_time);
    if (proc_ctx->redo_log_filesize < arch_size && used_time < arch_intervel_time) {
        return CT_FALSE;
    }
    // 间隔 arch_intervel_time 执行一次
    ELAPSED_BEGIN(proc_ctx->arch_record_time.start_time);
    return CT_TRUE;
}

bool32 arch_need_archive_file(arch_proc_context_t *proc_ctx, log_context_t *redo_ctx)
{
    knl_session_t *session = proc_ctx->session;
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    if (arch_ctx->force_archive_param.force_archive == CT_TRUE) {
        proc_ctx->is_force_archive = CT_TRUE;
    }
    log_file_t *file = NULL;
    uint32 file_id = proc_ctx->last_file_id;
    uint32 ori_file_id = proc_ctx->last_file_id;

    proc_ctx->next_file_id = CT_INVALID_ID32;

    log_lock_logfile(proc_ctx->session);

    if (file_id == CT_INVALID_ID32) {
        file_id = redo_ctx->active_file;
    } else {
        log_get_next_file(proc_ctx->session, &file_id, CT_FALSE);
    }

    file = redo_ctx->files + file_id;

    /*
     * log file is current log file, no need to archive, and last_file_id = CT_INVALID_ID32 is needed.
     * Consider the scenario as follows: standby logfile is skipped and proc_ctx->last_file_id's next
     * is current file, will lead to active file can not be archived.
     *
     * 3 logfile, asn 7(file 0) is archived, asn 8~24 is skipped, asn 26(file 1) has been archived,
     * asn 27(file 2) is current file, asd asn 25(file 0) can not be archive, last_file_id is 1.
     */
    if (file_id == redo_ctx->curr_file) {
        log_unlock_logfile(proc_ctx->session);
        proc_ctx->last_file_id = DB_IS_PRIMARY(&proc_ctx->session->kernel->db) ? ori_file_id : CT_INVALID_ID32;
        return CT_FALSE;
    }

    /*
     * log file is invalid, need to check the next one.
     * On standby or cascade standby, log switch skip and this routine could run concurrently. Skipped
     * file will set CT_INVALID_ASN, and last_file_id will be push backwards slowly. This will lead to
     * some active file can not be archived immediately.
     */
    if (file->head.asn == CT_INVALID_ASN) {
        // Just skip this log file
        log_unlock_logfile(proc_ctx->session);
        proc_ctx->last_file_id = DB_IS_PRIMARY(&proc_ctx->session->kernel->db) ? file_id : CT_INVALID_ID32;
        return CT_FALSE;
    }

    // log file is valid, need to check whether it is archived
    if (file->ctrl->archived) {
        // already archived, skip it
        log_unlock_logfile(proc_ctx->session);
        proc_ctx->last_file_id = file_id;
        return CT_FALSE;
    } else {
        // need to archive this log file
        log_unlock_logfile(proc_ctx->session);
        proc_ctx->next_file_id = file_id;
        return CT_TRUE;
    }
}

void arch_process_archive_long_name(arch_file_name_info_t *file_name_info, char *cur_pos, size_t offset,
                                    int32 *print_num, char *arch_format)
{
    char *buf = file_name_info->buf;
    uint32 buf_size = file_name_info->buf_size;
    switch (*cur_pos) {
        case 's':
        case 'S': {
            *print_num = snprintf_s(buf + offset, buf_size - offset, CT_MAX_UINT32_PREC, "%u", file_name_info->asn);
            knl_securec_check_ss(*print_num);
            break;
        }
        case 't':
        case 'T': {
            *print_num = snprintf_s(buf + offset, buf_size - offset, CT_MAX_UINT32_PREC, "%u", file_name_info->node_id);
            knl_securec_check_ss(*print_num);
            break;
        }
        case 'r':
        case 'R': {
            *print_num = snprintf_s(buf + offset, buf_size - offset, CT_MAX_UINT32_PREC, "%u", file_name_info->rst_id);
            knl_securec_check_ss(*print_num);
            break;
        }
        case 'd':
        case 'D': {
            *print_num = snprintf_s(buf + offset, buf_size - offset, CT_MAX_UINT64_PREC, "%llx", file_name_info->start_lsn);
            knl_securec_check_ss(*print_num);
            break;
        }
        case 'e':
        case 'E': {
            *print_num = snprintf_s(buf + offset, buf_size - offset, CT_MAX_UINT64_PREC, "%llx", file_name_info->end_lsn);
            knl_securec_check_ss(*print_num);
            break;
        }
        default: {
            // Invalid format, just ignore.
            CM_ABORT(0, "[ARCH] ABORT INFO: ARCHIVE_FORMAT '%s' has wrong format '%c' for ARCHIVE_FORMAT",
                     arch_format, *cur_pos);
            return;
        }
    }
}

void arch_set_archive_log_name_with_lsn(knl_session_t *session, uint32 dest_pos, arch_file_name_info_t *file_name_info)
{
    char *buf = file_name_info->buf;
    uint32 buf_size = file_name_info->buf_size;
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
        arch_process_archive_long_name(file_name_info, cur_pos, offset, &print_num, arch_ctx->arch_format);

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
                print_num = snprintf_s(buf + offset, buf_size - offset, CT_MAX_UINT32_PREC, "%u", asn);
                knl_securec_check_ss(print_num);
                break;
            }
            case 't':
            case 'T': {
                print_num = snprintf_s(buf + offset, buf_size - offset, CT_MAX_UINT64_PREC, "%lu", node_id);
                knl_securec_check_ss(print_num);
                break;
            }
            case 'r':
            case 'R': {
                print_num = snprintf_s(buf + offset, buf_size - offset, CT_MAX_UINT32_PREC, "%u", rst_id);
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
    while (arch_ctx->force_archive_param.force_archive == CT_TRUE) {
        cm_sleep(100);
    }
    return;
}

// 等待所有线程归档完成，不阻塞备升主
status_t wait_archive_finished_standby()
{
    CT_LOG_RUN_INF("[ARCH_STANDBY] force archive, wait all standby node finish");
    status_t result = CT_SUCCESS;
    for (uint32 idx = 0; idx < ARCH_MAX_NODE_COUNT;) {
        cm_spin_lock(&g_arch_standby_ctx.arch_lock, NULL);
        if (g_arch_standby_ctx.enabled == CT_FALSE) {
            CT_LOG_RUN_ERR("[ARCH_STANDBY] force archive, db role is switch to primary");
            cm_spin_unlock(&g_arch_standby_ctx.arch_lock);
            return CT_ERROR;
        }
        arch_proc_context_t *arch_proc_ctx = &g_arch_standby_ctx.arch_proc_ctx[idx];
        if (arch_proc_ctx->enabled != CT_TRUE) {
            idx++;
            cm_spin_unlock(&g_arch_standby_ctx.arch_lock);
            cm_sleep(ARCH_FORCE_WAIT_PROC_TIME);
            continue;
        }
        if (arch_proc_ctx->force_archive_trigger == CT_TRUE) {
            cm_spin_unlock(&g_arch_standby_ctx.arch_lock);
            cm_sleep(ARCH_FORCE_WAIT_PROC_TIME);
            continue;
        }
        if (arch_proc_ctx->force_archive_failed == CT_TRUE) {
            CT_LOG_RUN_ERR("[ARCH_STANDBY] force archive failed, standby node %u",
                           arch_proc_ctx->arch_standby_node);
            arch_proc_ctx->force_archive_failed = CT_FALSE;
            result = CT_ERROR;
        }
        idx++;
        CT_LOG_RUN_INF("[ARCH_STANDBY] force archive succ, standby node %u end wait lsn (%llu)",
                       arch_proc_ctx->arch_standby_node, CT_INVALID_ID64);
        cm_spin_unlock(&g_arch_standby_ctx.arch_lock);
        cm_sleep(ARCH_FORCE_WAIT_PROC_TIME);
    }
    return result;
}

status_t arch_force_trigger_standby_node(arch_proc_context_t *arch_proc_ctx)
{
    cm_spin_lock(&arch_proc_ctx->record_lock, NULL);
    if (arch_proc_ctx->force_archive_trigger == CT_TRUE ||
        arch_proc_ctx->force_archive_failed == CT_TRUE) {
        cm_spin_unlock(&arch_proc_ctx->record_lock);
        return CT_ERROR;
    }
    arch_proc_ctx->force_archive_trigger = CT_TRUE;
    cm_spin_unlock(&arch_proc_ctx->record_lock);
    CT_LOG_RUN_INF("[ARCH_STANDBY] force archive for standby node %u trigger succ",
                   arch_proc_ctx->arch_standby_node);
    return CT_SUCCESS;
}

status_t arch_force_archive_trigger_standby()
{
    CT_LOG_RUN_INF("[ARCH_STANDBY] force archive for all standby node trigger");
    for (uint32 idx = 0; idx < ARCH_MAX_NODE_COUNT;) {
        cm_spin_lock(&g_arch_standby_ctx.arch_lock, NULL);
        if (g_arch_standby_ctx.enabled == CT_FALSE) {
            CT_LOG_RUN_ERR("[ARCH_STANDBY] force archive, db role is switch to primary");
            cm_spin_unlock(&g_arch_standby_ctx.arch_lock);
            return CT_ERROR;
        }
        arch_proc_context_t *arch_proc_ctx = &g_arch_standby_ctx.arch_proc_ctx[idx];
        if (arch_proc_ctx->enabled != CT_TRUE) {
            idx++;
            cm_spin_unlock(&g_arch_standby_ctx.arch_lock);
            cm_sleep(ARCH_FORCE_WAIT_PROC_TIME);
            continue;
        }
        if (arch_force_trigger_standby_node(arch_proc_ctx) != CT_SUCCESS) {
            cm_spin_unlock(&g_arch_standby_ctx.arch_lock);
            cm_sleep(ARCH_FORCE_ARCHIVE_WAIT_SLEEP_TIME);
            continue;
        }
        idx++;
        cm_spin_unlock(&g_arch_standby_ctx.arch_lock);
        cm_sleep(ARCH_FORCE_WAIT_PROC_TIME);
    }
    
    if (wait_archive_finished_standby() != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ARCH_STANDBY] force archive failed");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t arch_force_archive_trigger(knl_session_t *session, uint64 end_lsn, bool32 wait)
{
    if (DB_IS_PRIMARY(&session->kernel->db) != CT_TRUE) {
        return arch_force_archive_trigger_standby();
    }

    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    while (CT_TRUE) {
        cm_spin_lock(&arch_ctx->dest_lock, NULL);
        if (arch_ctx->force_archive_param.force_archive == CT_TRUE ||
            arch_ctx->force_archive_param.failed == CT_TRUE) {
            cm_spin_unlock(&arch_ctx->dest_lock);
            cm_sleep(ARCH_FORCE_ARCHIVE_WAIT_SLEEP_TIME);
            continue;
        }
        arch_ctx->force_archive_param.force_archive = CT_TRUE;
        arch_ctx->force_archive_param.end_lsn = end_lsn;
        arch_ctx->force_archive_param.wait = wait;
        cm_spin_unlock(&arch_ctx->dest_lock);
        break;
    }

    if (!wait) {
        CT_LOG_RUN_INF("force archive file, no need wait, end(%llu)", arch_ctx->force_archive_param.end_lsn);
        return CT_SUCCESS;
    }
    CT_LOG_RUN_INF("[ARCH] wait force archive file, node %u, end wait lsn (%llu)",
                   session->kernel->id, arch_ctx->force_archive_param.end_lsn);
    wait_archive_finished(session);
    if (arch_ctx->force_archive_param.failed == CT_TRUE) {
        CT_LOG_RUN_ERR("[ARCH] force archive file failed, node %u", session->kernel->id);
        arch_ctx->force_archive_param.failed = CT_FALSE;
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t arch_switch_archfile_trigger(knl_session_t *session, bool32 wait)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    while (CT_TRUE) {
        cm_spin_lock(&arch_ctx->dest_lock, NULL);
        if (arch_ctx->force_archive_param.force_archive == CT_TRUE ||
            arch_ctx->force_archive_param.failed == CT_TRUE) {
            cm_spin_unlock(&arch_ctx->dest_lock);
            cm_sleep(ARCH_FORCE_ARCHIVE_WAIT_SLEEP_TIME);
            continue;
        }
        arch_ctx->force_archive_param.force_archive = CT_TRUE;
        arch_ctx->force_archive_param.end_lsn = CT_INVALID_ID64;
        arch_ctx->force_archive_param.wait = wait;
        cm_spin_unlock(&arch_ctx->dest_lock);
        break;
    }
    if (!wait) {
        CT_LOG_RUN_INF("switch file,no need wait");
        return CT_SUCCESS;
    }
    CT_LOG_RUN_INF("switch file, need wait");
    wait_archive_finished(session);
    if (arch_ctx->force_archive_param.failed == CT_TRUE) {
        arch_ctx->force_archive_param.failed = CT_FALSE;
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void arch_get_files_num(knl_session_t *session, uint32 dest_id, uint32 node_id, uint32 *arch_num)
{
    uint32 archived_start = arch_get_arch_start(session, node_id);
    uint32 archived_end = arch_get_arch_end(session, node_id);

    *arch_num = (archived_end - archived_start + CT_MAX_ARCH_NUM) % CT_MAX_ARCH_NUM;
}

status_t arch_lsn_asn_convert(knl_session_t *session, uint64 lsn, uint32 *asn)
{
    uint32 node_id = session->kernel->id;
    bool32 find_arch = CT_FALSE;
    arch_ctrl_t *arch_ctrl = NULL;
    uint32 archived_start = arch_get_arch_start(session, node_id);
    uint32 archived_end = arch_get_arch_end(session, node_id);
    uint32 arch_locator;
    uint32 arch_num;
    uint32 i;
    uint32 rst_id = session->kernel->db.ctrl.core.resetlogs.rst_id;
    arch_get_files_num(session, ARCH_DEFAULT_DEST, node_id, &arch_num);
    for (i = 0; i < arch_num; i++) {
        arch_locator = (archived_start + i) % CT_MAX_ARCH_NUM;
        arch_ctrl = db_get_arch_ctrl(session, arch_locator, node_id);
        if (arch_ctrl->rst_id != rst_id) {
            continue;
        }

        CT_LOG_DEBUG_INF("arch_lsn_asn num (%u) start(%u) end(%u), locator(%u) start(%llu) end(%llu), lsn(%llu)",
            arch_num, archived_start, archived_end, arch_locator, arch_ctrl->start_lsn, arch_ctrl->end_lsn, lsn);
        if (lsn >= arch_ctrl->start_lsn && lsn <= arch_ctrl->end_lsn) {
            *asn = arch_ctrl->asn;
            find_arch = CT_TRUE;
            break;
        }
    }
    if (!find_arch && arch_num > 0) {
        arch_locator = (archived_start + arch_num - 1) % CT_MAX_ARCH_NUM;
        arch_ctrl = db_get_arch_ctrl(session, arch_locator, node_id);
        if (arch_ctrl->rst_id == rst_id) {
            *asn = arch_ctrl->asn;
            find_arch = CT_TRUE;
            CT_LOG_RUN_INF("[BACKUP] can not find arch_ctrl->end_lsn >= lsn(%llu), choose lastest one, asn(%u).",
                           lsn, *asn);
        }
    }
    if (arch_ctrl != NULL) {
        CT_LOG_DEBUG_INF("start(%llu) end(%llu) lsn(%llu) asn(%u)",
            arch_ctrl->start_lsn, arch_ctrl->end_lsn, lsn, *asn);
    }
    return find_arch ? CT_SUCCESS : CT_ERROR;
}

status_t arch_clear_tmp_file(device_type_t arch_file_type, char *file_name)
{
    bool32 exist_tmp_file = cm_exist_device(arch_file_type, file_name);
    if (exist_tmp_file) {
        CT_LOG_RUN_INF("[ARCH] exist temp archive log file %s", file_name);
        if (cm_remove_device_when_enoent(arch_file_type, file_name) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[ARCH] failed to create temp archive log file %s", file_name);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t arch_handle_fault(arch_proc_context_t *proc_ctx, log_file_t *logfile, char *file_name)
{
    device_type_t arch_file_type = cm_device_type(proc_ctx->arch_dest);
    bool32 exist_tmp_file;
    if (proc_ctx->last_archived_log_record.start_lsn == CT_INVALID_ID64) {
        CT_LOG_RUN_INF("[ARCH] clear temp archive log file %s", TMP_ARCH_FILE_NAME);
        if (arch_clear_tmp_file(arch_file_type, file_name) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[ARCH] failed to remove temp archive log file %s", TMP_ARCH_FILE_NAME);
            return CT_ERROR;
        }
        proc_ctx->last_archived_log_record.start_lsn = 0;
    } else {
        exist_tmp_file = cm_exist_device(arch_file_type, file_name);
        if (!exist_tmp_file &&
            proc_ctx->last_archived_log_record.cur_lsn != proc_ctx->last_archived_log_record.end_lsn) {
            CT_LOG_RUN_WAR("[ARCH] the lastest temp archive file may be lost, cur lsn %llu, reset cur lsn to %llu",
                proc_ctx->last_archived_log_record.cur_lsn, proc_ctx->last_archived_log_record.end_lsn);
            proc_ctx->last_archived_log_record.cur_lsn = proc_ctx->last_archived_log_record.end_lsn;
            proc_ctx->last_archived_log_record.offset = 0;
        }
    }
    if (proc_ctx->last_archived_log_record.offset == 0) {
        proc_ctx->last_archived_log_record.offset = CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size);
    }
    return CT_SUCCESS;
}

status_t arch_tmp_flush_head(device_type_t arch_file_type, const char *dst_name, arch_proc_context_t *proc_ctx,
                             log_file_t *file, int32 dst_file)
{
    knl_session_t *session = proc_ctx->session;
    int32 head_size = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
    log_file_head_t head = {0};

    head.rst_id = file->head.rst_id;
    head.asn = proc_ctx->last_archived_log_record.asn;
    head.block_size = head_size;

    log_calc_head_checksum(session, &head);
    if (cm_write_device(arch_file_type, dst_file, 0, &head, head_size) != CT_SUCCESS) {
        cm_close_device(arch_file_type, &dst_file);
        CT_LOG_RUN_ERR("[ARCH] failed to flush tmp_file head:%s, offset:%u, size:%d failed.", dst_name, 0, head_size);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[ARCH] Flush tmp_file  asn[%u] rst[%u], head[%d]", head.asn, head.rst_id, head.block_size);
    return CT_SUCCESS;
}

status_t arch_create_open_file(arch_proc_context_t *proc_ctx, const char *file_name,
                               device_type_t arch_file_type, int32 *dst_file, log_file_t *logfile)
{
    knl_session_t *session = proc_ctx->session;
    bool32 exist_tmp_file = cm_exist_device(arch_file_type, file_name);
    if (!exist_tmp_file) {
        CT_LOG_RUN_INF("[ARCH] create temp archive log file %s", file_name);
        if (cm_create_device(file_name, arch_file_type, knl_io_flag(session), dst_file) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[ARCH] failed to create temp archive log file %s", file_name);
            return CT_ERROR;
        }
        if (arch_tmp_flush_head(arch_file_type, file_name, proc_ctx, logfile, *dst_file) != CT_SUCCESS) {
            return CT_ERROR;
        }
        cm_close_device(arch_file_type, dst_file);
    }
    if (cm_open_device(file_name, arch_file_type, knl_io_flag(session), dst_file) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ARCH] failed to open archive log file %s", file_name);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void arch_set_first_scn(void *buf, knl_scn_t *scn)
{
    log_batch_t *batch = (log_batch_t *)(buf);
    if (batch == NULL) {
        CT_LOG_RUN_ERR("[DTC RCY] batch is null");
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
            CT_LOG_RUN_ERR("[ARCH] batch is null, read_size[%d], invalide_size[%u]",
                data_size, invalide_size);
            return CT_ERROR;
        }
        if (buffer_size < batch->size) {
            break;
        }
        if (!dtc_rcy_validate_batch(batch)) {
            CT_LOG_RUN_ERR("[ARCH] batch is invalidate, read_size[%d], invalide_size[%u]",
                data_size, invalide_size);
            return CT_ERROR;
        }
        invalide_size += batch->space_size;
        buffer_size -= batch->space_size;
    }
    return CT_SUCCESS;
}

status_t arch_read_batch(log_file_t *logfile, arch_proc_context_t *proc_ctx,
    arch_read_batch_attr_t read_batch_attr)
{
    int32 src_file = logfile->handle;
    char *buf = read_batch_attr.read_buf->data_addr;
    int32 *data_size = &read_batch_attr.read_buf->data_size;
    uint32 buf_size = proc_ctx->arch_rw_buf.aligned_buf.buf_size / DBSTOR_ARCH_RW_BUF_NUM;
    status_t status;
    for (uint32 i = 0; i < ARCH_READ_BATCH_RETRY_TIMES; i++) {
        SYNC_POINT_GLOBAL_START(CANTIAN_ARCH_GET_LOG_FAIL, &status, CT_ERROR);
        status = cm_device_read_batch(logfile->ctrl->type, src_file, read_batch_attr.start_lsn, CT_INVALID_ID64,
            buf, buf_size, data_size, read_batch_attr.last_lsn);
        SYNC_POINT_GLOBAL_END;
        if (status != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[ARCH] fail to read log file %s lsn %llu read size %u", read_batch_attr.src_name,
                           read_batch_attr.start_lsn, *data_size);
            cm_sleep(ARCH_FAIL_WAIT_SLEEP_TIME);
            return CT_ERROR;
        }

        if (proc_ctx->session->kernel->attr.arch_log_check &&
            arch_check_log_valid(*data_size, buf) != CT_SUCCESS) {
            if (i < (ARCH_READ_BATCH_RETRY_TIMES - 1)) {
                cm_sleep(ARCH_FAIL_WAIT_SLEEP_TIME);
                continue;
            } else if (cm_dbs_is_enable_dbs() == CT_TRUE) {
                CT_LOG_RUN_ERR("[ARCH] fail to check log file.");
                return CT_ERROR;
            }
        } else {
            break;
        }
    }
    return CT_SUCCESS;
}

void arch_end_write_file(arch_proc_context_t *proc_ctx, device_type_t arch_file_type)
{
    arch_wait_write_finish(proc_ctx, &proc_ctx->arch_rw_buf);
    proc_ctx->arch_execute = CT_FALSE;
    cm_close_device(arch_file_type, &proc_ctx->tmp_file_handle);
}

status_t arch_read_from_src(arch_read_file_src_info_t *read_file_src_info,
                            arch_proc_context_t *proc_ctx, device_type_t arch_file_type, uint64 *out_last_lsn)
{
    uint64 start_lsn = read_file_src_info->start_lsn_input;
    uint64 end_lsn = read_file_src_info->end_lsn;
    log_file_t *logfile = read_file_src_info->logfile;
    uint64 last_lsn = proc_ctx->last_archived_log_record.cur_lsn;
    int64 left_size = (int64)proc_ctx->redo_log_filesize;
    uint64 *file_offset = &proc_ctx->last_archived_log_record.offset;
    int32 data_size = 0;
    arch_read_batch_attr_t read_batch_attr = {read_file_src_info->src_name, 0, NULL, &last_lsn};
    do {
        read_batch_attr.start_lsn = start_lsn;
        if (arch_get_read_buf(&proc_ctx->arch_rw_buf, &read_batch_attr.read_buf) != CT_SUCCESS) {
            cm_sleep(1);
            continue;
        }
        if (arch_read_batch(logfile, proc_ctx, read_batch_attr) != CT_SUCCESS) {
            arch_end_write_file(proc_ctx, arch_file_type);
            return CT_ERROR;
        }
        data_size = read_batch_attr.read_buf->data_size;
        if (data_size == 0) {
            proc_ctx->redo_log_filesize = 0;
            CT_LOG_DEBUG_INF("[ARCH] reach data end, left(%lld), data(%d), last(%llu)", left_size, data_size, last_lsn);
            break;
        }
        read_batch_attr.read_buf->last_lsn = last_lsn;
        arch_set_read_done(&proc_ctx->arch_rw_buf);
        left_size -= data_size;
        proc_ctx->redo_log_filesize -= data_size;
        start_lsn  = last_lsn + 1;
        if (last_lsn >= end_lsn) {
            proc_ctx->redo_log_filesize = 0;
            CT_LOG_RUN_INF("[ARCH] read lsn end, left(%lld), last(%llu), end(%llu)", left_size, last_lsn, end_lsn);
            break;
        }
        if (*file_offset >= proc_ctx->session->kernel->arch_ctx.arch_file_size) {
            CT_LOG_RUN_INF("[ARCH] file oversize(%llu), left(%lld), last(%llu)", *file_offset, left_size, last_lsn);
            break;
        }
    } while (left_size > 0 && !proc_ctx->write_failed);
    *out_last_lsn = last_lsn;
    return CT_SUCCESS;
}

status_t arch_write_file(arch_read_file_src_info_t *read_file_src_info, arch_proc_context_t *proc_ctx,
                         const char *dst_name, device_type_t arch_file_type)
{
    uint64 *file_offset = &proc_ctx->last_archived_log_record.offset;
    uint64 last_lsn = 0;
    log_file_t *logfile = read_file_src_info->logfile;
    if (arch_create_open_file(proc_ctx, dst_name, arch_file_type, &proc_ctx->tmp_file_handle, logfile) != CT_SUCCESS) {
        return CT_ERROR;
    }
    proc_ctx->arch_execute = CT_TRUE;
    proc_ctx->write_failed = CT_FALSE;
    timeval_t start_time;
    uint64 used_time;
    ELAPSED_BEGIN(start_time);
    if (arch_read_from_src(read_file_src_info, proc_ctx, arch_file_type, &last_lsn) != CT_SUCCESS) {
        return CT_ERROR;
    }
    arch_end_write_file(proc_ctx, arch_file_type);
    ELAPSED_END(start_time, used_time);
    proc_ctx->total_used_time += used_time;
    if (proc_ctx->write_failed == CT_TRUE || proc_ctx->last_archived_log_record.cur_lsn != last_lsn) {
        CT_LOG_RUN_ERR("[ARCH] failed, lsn cur(%llu), last(%llu), lsn start(%llu), size(%llu)",
                       proc_ctx->last_archived_log_record.cur_lsn, last_lsn,
                       proc_ctx->last_archived_log_record.start_lsn, *file_offset);
        return CT_ERROR;
    }
    proc_ctx->last_archived_log_record.start_lsn = proc_ctx->last_archived_log_record.end_lsn;
    CT_LOG_DEBUG_INF("[ARCH] succ, lsn start(%llu) cur(%llu) size(%llu)", proc_ctx->last_archived_log_record.start_lsn,
                     last_lsn, *file_offset);
    return CT_SUCCESS;
}
 
status_t arch_flush_head(device_type_t arch_file_type, const char *dst_name, arch_proc_context_t *proc_ctx,
                         log_file_t *file, log_file_head_t *head)
{
    knl_session_t *session = proc_ctx->session;
    int32 head_size = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
    int32 dst_file = CT_INVALID_HANDLE;
    aligned_buf_t *arch_buf = &proc_ctx->arch_rw_buf.aligned_buf;
    knl_scn_t first_scn = CT_INVALID_ID64;
    int32 data_size = 0;

    if (cm_open_device(dst_name, arch_file_type, knl_io_flag(session), &dst_file) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ARCHIVE] failed to open archive log file %s", dst_name);
        return CT_ERROR;
    }
    status_t ret = memset_sp(arch_buf->aligned_buf, arch_buf->buf_size, 0, arch_buf->buf_size);
    knl_securec_check(ret);

    if (cm_read_device_nocheck(arch_file_type, dst_file, head_size, arch_buf->aligned_buf, arch_buf->buf_size,
                               &data_size) != CT_SUCCESS) {
        cm_close_device(arch_file_type, &dst_file);
        return CT_ERROR;
    }
 
    arch_set_first_scn(arch_buf->aligned_buf, &first_scn);
    head->first = first_scn;
    head->last = CT_INVALID_ID64;
    head->first_lsn = proc_ctx->last_archived_log_record.start_lsn;
    head->last_lsn = proc_ctx->last_archived_log_record.cur_lsn;
    head->rst_id = file->head.rst_id;
    head->asn = proc_ctx->last_archived_log_record.asn;
    head->write_pos = proc_ctx->last_archived_log_record.offset;
    head->cmp_algorithm = COMPRESS_NONE;
    head->block_size = head_size;
    head->dbid = session->kernel->db.ctrl.core.dbid;
    ret = memset_sp(head->unused, CT_LOG_HEAD_RESERVED_BYTES, 0, CT_LOG_HEAD_RESERVED_BYTES);
    knl_securec_check(ret);

    log_calc_head_checksum(session, head);
    if (cm_write_device(arch_file_type, dst_file, 0, head, head_size) != CT_SUCCESS) {
        cm_close_device(arch_file_type, &dst_file);
        CT_LOG_ALARM(WARN_FLUSHREDO, "%s", dst_name);
        CM_ABORT(0, "[LOG] ABORT INFO: flush head:%s, offset:%u, size:%d failed.", dst_name, 0, head_size);
    }
    CT_LOG_RUN_INF("Flush head start[%llu] end[%llu] asn[%u] rst[%u] fscn[%llu], write_pos[%llu] head[%d] dbid[%u]",
                   head->first_lsn, head->last_lsn, head->asn, head->rst_id, head->first, head->write_pos,
                   head->block_size, head->dbid);
    cm_close_device(arch_file_type, &dst_file);
    return CT_SUCCESS;
}

static inline void arch_dbstor_update_progress(log_file_t *logfile, arch_proc_context_t *proc_ctx)
{
    // next file offset start from log_head.
    if (proc_ctx->last_archived_log_record.rst_id < logfile->head.rst_id) {
        // pitr rst_id change, need reset asn to 1.
        proc_ctx->last_archived_log_record.rst_id = logfile->head.rst_id;
        proc_ctx->last_archived_log_record.asn = 1;
    }
}


void arch_set_tmp_filename(char *file_name, arch_proc_context_t *proc_ctx, uint32 node_id)
{
    errno_t ret;
    size_t dest_len;
    char *buf = file_name;
    dest_len = strlen(proc_ctx->arch_dest);
    ret = strncpy_s(file_name, CT_FILE_NAME_BUFFER_SIZE, proc_ctx->arch_dest, dest_len);
    knl_securec_check(ret);
    file_name[dest_len] = '/';
    ret = snprintf_s(buf + strlen(proc_ctx->arch_dest) + 1, CT_FILE_NAME_BUFFER_SIZE - strlen(proc_ctx->arch_dest) - 1,
                     CT_MAX_UINT32_PREC, "%u", node_id);
    knl_securec_check_ss(ret);
    ret = strcat_s(file_name, CT_FILE_NAME_BUFFER_SIZE, TMP_ARCH_FILE_NAME);
    knl_securec_check(ret);
}

void arch_set_force_endlsn(bool32 force_archive, arch_proc_context_t *proc_ctx, uint64 *end_lsn)
{
    CT_LOG_DEBUG_INF("[ARCH] set force archive endlsn, proc data type is %u", proc_ctx->data_type);
    if (proc_ctx->data_type == ARCH_DATA_TYPE_DBSTOR) {
        arch_context_t *arch_ctx = &proc_ctx->session->kernel->arch_ctx;
        if (force_archive && proc_ctx->is_force_archive && arch_ctx->force_archive_param.end_lsn != CT_INVALID_ID64) {
            *end_lsn = arch_ctx->force_archive_param.end_lsn;
            CT_LOG_RUN_INF("[ARCH] set end_lsn %llu for force archive!", arch_ctx->force_archive_param.end_lsn);
        }
        return;
    }
    *end_lsn = CT_INVALID_ID64;
    return;
}

status_t arch_dbstor_rename_tmp_file(const char *tmp_file_name, const char *arch_file_name,
                                     device_type_t arch_file_type)
{
    status_t status;
    SYNC_POINT_GLOBAL_START(CANTIAN_ARCH_RENAME_TMP_FILE_FAIL, &status, CT_ERROR);
    status = cm_rename_device_when_enoent(arch_file_type, tmp_file_name, arch_file_name);
    SYNC_POINT_GLOBAL_END;
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ARCH] rename tmp file %s to %s failed", tmp_file_name, arch_file_name);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void arch_set_force_archive_stat(arch_proc_context_t *proc_ctx, bool32 result)
{
    CT_LOG_RUN_INF("[ARCH] force archive failed, proc data type is %u", proc_ctx->data_type);
    if (proc_ctx->data_type == ARCH_DATA_TYPE_DBSTOR_STANDBY) {
        proc_ctx->force_archive_failed = result;
        return;
    }
    arch_context_t *arch_ctx = &proc_ctx->session->kernel->arch_ctx;
    arch_ctx->force_archive_param.failed = result;
    return;
}

status_t arch_dbstor_generate_arch_file(arch_proc_context_t *proc_ctx, log_file_t *logfile,
                                        char *tmp_file_name, char *arch_file_name, log_file_head_t *head)
{
    uint32 node_id = arch_get_proc_node_id(proc_ctx);
    uint32 *asn = &proc_ctx->last_archived_log_record.asn;
    device_type_t arch_file_type = cm_device_type(proc_ctx->arch_dest);
    if (proc_ctx->last_archived_log_record.end_lsn == proc_ctx->last_archived_log_record.cur_lsn) {
        proc_ctx->need_file_archive = CT_FALSE; // no log when force archive, need clear.
        CT_LOG_RUN_WAR("[ARCH] empty file no need to archive %s", tmp_file_name);
        return CT_ERROR;
    }
    st_arch_log_record_id_t tmp_record = proc_ctx->last_archived_log_record;
    arch_dbstor_update_progress(logfile, proc_ctx);
    if (arch_flush_head(arch_file_type, tmp_file_name, proc_ctx, logfile, head) != CT_SUCCESS) {
        proc_ctx->last_archived_log_record = tmp_record;
        arch_set_force_archive_stat(proc_ctx, CT_TRUE);
        return CT_ERROR;
    }
    proc_ctx->total_arch_size += proc_ctx->last_archived_log_record.offset;
    CT_LOG_RUN_INF("[ARCH] total_arch_size %llu(byte), total_used_time %llu(us), average speed %.2f(MB/s)",
                   proc_ctx->total_arch_size, proc_ctx->total_used_time,
                   ((float)proc_ctx->total_arch_size / SIZE_M(1)) / (proc_ctx->total_used_time / MS_PER_SEC));
    proc_ctx->last_archived_log_record.offset = CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size);
    arch_file_name_info_t file_name_info = {logfile->head.rst_id, *asn, node_id, CT_FILE_NAME_BUFFER_SIZE,
                                            proc_ctx->last_archived_log_record.start_lsn,
                                            proc_ctx->last_archived_log_record.cur_lsn, arch_file_name};
    arch_set_archive_log_name_with_lsn(proc_ctx->session, ARCH_DEFAULT_DEST, &file_name_info);
    if (arch_dbstor_rename_tmp_file(tmp_file_name, arch_file_name, arch_file_type) != CT_SUCCESS) {
        proc_ctx->last_archived_log_record = tmp_record;
        arch_set_force_archive_stat(proc_ctx, CT_TRUE);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void arch_get_force_archive_param(arch_proc_context_t *proc_ctx, bool32 *force_archive)
{
    // CT_LOG_RUN_INF("[ARCH] get force archive param, proc data type is %u", proc_ctx->data_type);
    if (proc_ctx->data_type == ARCH_DATA_TYPE_DBSTOR_STANDBY) {
        *force_archive = proc_ctx->force_archive_trigger;
        return;
    }
    arch_context_t *arch_ctx = &proc_ctx->session->kernel->arch_ctx;
    *force_archive = arch_ctx->force_archive_param.force_archive;
    return;
}


status_t arch_dbstor_archive_file(const char *src_name, char *arch_file_name, log_file_t *logfile,
                                  log_file_head_t *head, arch_proc_context_t *proc_ctx)
{
    uint64 start_lsn = proc_ctx->last_archived_log_record.cur_lsn + 1;
    uint64 end_lsn = CT_INVALID_ID64;
    arch_context_t *arch_ctx = &proc_ctx->session->kernel->arch_ctx;
    bool32 force_archive = proc_ctx->is_force_archive;
    uint64 arch_file_size = arch_ctx->arch_file_size;
    char *tmp_file_name = proc_ctx->tmp_file_name;
    device_type_t arch_file_type = cm_device_type(proc_ctx->arch_dest);
    // arch_set_tmp_filename(tmp_file_name, proc_ctx, proc_ctx->session->kernel->id);
    if (arch_handle_fault(proc_ctx, logfile, tmp_file_name) != CT_SUCCESS) {
        arch_set_force_archive_stat(proc_ctx, CT_TRUE);
        return CT_ERROR;
    }
    if (force_archive || proc_ctx->redo_log_filesize + proc_ctx->last_archived_log_record.offset >= arch_file_size) {
        CT_LOG_RUN_INF("[ARCH] force %d, left_size %llu, cur_size %llu, file_size %llu, start_lsn %llu", force_archive,
            proc_ctx->redo_log_filesize, proc_ctx->last_archived_log_record.offset, arch_file_size, start_lsn);
        proc_ctx->need_file_archive = CT_TRUE;
    }
    arch_set_force_endlsn(force_archive, proc_ctx, &end_lsn);
    arch_read_file_src_info_t read_file_src_info = {(char *)src_name, logfile, start_lsn, end_lsn};
    if (arch_write_file(&read_file_src_info, proc_ctx, tmp_file_name, arch_file_type) != CT_SUCCESS) {
        arch_set_force_archive_stat(proc_ctx, CT_TRUE);
        return CT_ERROR;
    }

    CT_LOG_DEBUG_INF("[ARCH] archive info, tmp name %s, handle %d, start lsn %llu, end lsn %llu, cur lsn %llu, offset %llu",
        proc_ctx->tmp_file_name, proc_ctx->tmp_file_handle, proc_ctx->last_archived_log_record.start_lsn,
        proc_ctx->last_archived_log_record.end_lsn, proc_ctx->last_archived_log_record.cur_lsn,
        proc_ctx->last_archived_log_record.offset);
    if (proc_ctx->need_file_archive) {
        if (arch_need_wait_clean(proc_ctx) == CT_TRUE) {
            g_arch_func[proc_ctx->data_type].arch_auto_clean_func(proc_ctx);
            if (arch_need_wait_clean(proc_ctx) == CT_TRUE) {
                arch_set_force_archive_stat(proc_ctx, CT_TRUE);
                return CT_ERROR;
            }
        }
        if (arch_dbstor_generate_arch_file(proc_ctx, logfile, tmp_file_name, arch_file_name, head) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

static void arch_archive_delay(knl_session_t *session)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    uint64 log_generated = ctx->stat.flush_bytes - arch_ctx->begin_redo_bytes;

    if (arch_ctx->prev_redo_bytes == ctx->stat.flush_bytes) {
        /* no log generate during this archive copy, max speed */
        return;
    }

    arch_ctx->prev_redo_bytes = ctx->stat.flush_bytes;

    if (log_generated > arch_ctx->total_bytes) {
        /* log generate is fast than arch, max speed */
        return;
    }

    if (log_get_free_count(session) <= CT_MIN_FREE_LOGS) {
        /* when arch proc is bottleneck, we do not delay arch proc */
        return;
    }
    CT_LOG_DEBUG_INF("[ARCH] arch_delay log_generated:%llu log_archived:%llu", log_generated, arch_ctx->total_bytes);
    cm_sleep(100); /* 100ms */
}

static status_t arch_write_arch_file_nocompress(knl_session_t *session, aligned_buf_t buf, log_file_t *logfile,
    arch_file_attr_t *arch_files)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    uint64 left_size = logfile->head.write_pos;
    int32 read_size, data_size;
    int64 file_offset = 0;
    device_type_t arch_file_type = cm_device_type(arch_files->arch_file_name);

    read_size = CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size);
    if (cm_read_file(arch_files->src_file, buf.aligned_buf, read_size, &data_size) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ARCHIVE] failed to read archive log file %s offset size %llu actual read size %u",
            arch_files->src_name, logfile->head.write_pos - left_size, read_size);
        return CT_ERROR;
    }

    log_file_head_t *arch_log_head = (log_file_head_t *)buf.aligned_buf;
    arch_log_head->dbid = session->kernel->db.ctrl.core.dbid;
    log_calc_head_checksum(session, arch_log_head);

    if (cm_write_file(arch_files->dst_file, buf.aligned_buf, data_size) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ARCHIVE] failed to write archive log file %s offset size %llu write size %u",
            arch_files->arch_file_name, logfile->head.write_pos - left_size, data_size);
        return CT_ERROR;
    }

    left_size -= (uint64)data_size;
    arch_ctx->total_bytes += data_size;
    logfile->arch_pos += data_size;
    file_offset += (uint64)data_size;
    while (left_size > 0) {
        read_size = (int32)((left_size > buf.buf_size) ? buf.buf_size : left_size);
        if (cm_read_device_nocheck(logfile->ctrl->type, arch_files->src_file, file_offset, buf.aligned_buf, read_size,
                                   &data_size) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cm_write_device(arch_file_type, arch_files->dst_file, file_offset, buf.aligned_buf, data_size) !=
            CT_SUCCESS) {
            return CT_ERROR;
        }

        left_size -= (uint64)data_size;
        file_offset += (uint64)data_size;
        arch_ctx->total_bytes += data_size;
        logfile->arch_pos += data_size;

        if (DB_TO_RECOVERY(session)) {
            arch_archive_delay(session);
        }
    }
    return CT_SUCCESS;
}

static status_t arch_compress_write(arch_file_attr_t *arch_files, knl_compress_t *compress_ctx,
    char *buf, int32 size, bool32 stream_end)
{
    compress_algo_e compress_alog;
    if (arch_files->log_head != NULL && arch_files->log_head->cmp_algorithm == COMPRESS_LZ4) {
        compress_alog = COMPRESS_LZ4;
    } else {
        compress_alog = DEFAULT_ARCH_COMPRESS_ALGO;
    }
    knl_compress_set_input(compress_alog, compress_ctx, buf, (uint32)size);
    CT_LOG_DEBUG_INF("[ARCHIVE] compress log file %s set input data_size %d, compress_alog %u.", arch_files->arch_file_name, size, compress_alog);
    for (;;) {
        if (knl_compress(compress_alog, compress_ctx, stream_end,
            compress_ctx->compress_buf.aligned_buf, (uint32)compress_ctx->compress_buf.buf_size) != CT_SUCCESS) {
            return CT_ERROR;
        }

        CT_LOG_DEBUG_INF("[ARCHIVE] compress log file %s with data_size %d to %u stream end %d",
            arch_files->arch_file_name, size, compress_ctx->write_len, stream_end);

        if (cm_write_file(arch_files->dst_file, compress_ctx->compress_buf.aligned_buf,
            compress_ctx->write_len) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (compress_ctx->finished) {
            break;
        }
    }

    return CT_SUCCESS;
}

// lz4 compress algorithm needs to write a compress head when starting a compression
status_t arch_write_lz4_compress_head(bak_t *bak, knl_compress_t *compress_ctx, arch_file_attr_t *arch_files, log_file_head_t *log_head)
{
    if (log_head->cmp_algorithm != COMPRESS_LZ4) {
        return CT_SUCCESS;
    }
    LZ4F_preferences_t ref = LZ4F_INIT_PREFERENCES;
    char *lz4_write_buf = NULL;
    size_t res;

    ref.compressionLevel = bak->compress_ctx.compress_level;
    res = LZ4F_compressBegin(compress_ctx->lz4f_cstream, compress_ctx->compress_buf.aligned_buf,
        (uint32)COMPRESS_BUFFER_SIZE(bak), &ref);
    if (LZ4F_isError(res)) {
        CT_THROW_ERROR(ERR_COMPRESS_ERROR, "lz4f", res, LZ4F_getErrorName(res));
        return CT_ERROR;
    }
    lz4_write_buf = compress_ctx->compress_buf.aligned_buf;

    if (cm_write_file(arch_files->dst_file, lz4_write_buf, res) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ARCHIVE] failed to write archive log file %s size %lu",
            arch_files->arch_file_name, res);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t arch_write_arch_file_compress(knl_session_t *session, aligned_buf_t buf, log_file_t *logfile,
    arch_file_attr_t *arch_files, knl_compress_t *compress_ctx)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    uint64 left_size = logfile->head.write_pos;
    int32 read_size, data_size;

    // Need to set compress flag first
    read_size = CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size);
    if (cm_read_file(arch_files->src_file, buf.aligned_buf, read_size, &data_size) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ARCHIVE] failed to read archive log file %s offset size %llu actual read size %u",
            arch_files->src_name, logfile->head.write_pos - left_size, read_size);
        return CT_ERROR;
    }

    // Update archived logfile head if compression needed
    log_file_head_t *arch_log_head = (log_file_head_t *)buf.aligned_buf;
    arch_log_head->dbid = session->kernel->db.ctrl.core.dbid;
    if (logfile->head.cmp_algorithm != COMPRESS_LZ4) {
        arch_log_head->cmp_algorithm = DEFAULT_ARCH_COMPRESS_ALGO; 
    }
    // Recalculate checksum for log head
    log_calc_head_checksum(session, arch_log_head);
    
    if (cm_write_file(arch_files->dst_file, buf.aligned_buf, data_size) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ARCHIVE] failed to write archive log file %s offset size %llu write size %u",
            arch_files->arch_file_name, logfile->head.write_pos - left_size, data_size);
        return CT_ERROR;
    }

    if (arch_write_lz4_compress_head(&session->kernel->backup_ctx.bak, compress_ctx, arch_files, &logfile->head) != CT_SUCCESS) {
        return CT_ERROR;
    }

    left_size -= (uint64)data_size;
    arch_ctx->total_bytes += data_size;
    logfile->arch_pos += data_size;

    arch_files->log_head = &logfile->head;
    while (left_size > 0) {
        read_size = (int32)((left_size > buf.buf_size) ? buf.buf_size : left_size);
        if (cm_read_file(arch_files->src_file, buf.aligned_buf, read_size, &data_size) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (read_size != data_size) {
            CT_LOG_RUN_ERR("[ARCH] failed to read log file %s, expect to read %d but actually read %d",
                logfile->ctrl->name, read_size, data_size);
            return CT_ERROR;
        }

        if (arch_compress_write(arch_files, compress_ctx, buf.aligned_buf, data_size, CT_FALSE) != CT_SUCCESS) {
            return CT_ERROR;
        }

        left_size -= (uint64)data_size;
        arch_ctx->total_bytes += data_size;
        logfile->arch_pos += data_size;
        if (DB_TO_RECOVERY(session)) {
            arch_archive_delay(session);
        }
    }

    return arch_compress_write(arch_files, compress_ctx, NULL, 0, CT_TRUE);
}

static status_t arch_write_arch_file(knl_session_t *session, aligned_buf_t buf, log_file_t *logfile,
    arch_file_attr_t *arch_files, knl_compress_t *compress_ctx)
{
    bool32 compress = session->kernel->attr.enable_arch_compress;
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    log_context_t *ctx = &session->kernel->redo_ctx;

    logfile->arch_pos = 0;
    arch_ctx->begin_redo_bytes = ctx->stat.flush_bytes;
    arch_ctx->prev_redo_bytes = ctx->stat.flush_bytes;
    arch_ctx->total_bytes = 0;

    if (!compress) {
        return arch_write_arch_file_nocompress(session, buf, logfile, arch_files);
    } else {
        return arch_write_arch_file_compress(session, buf, logfile, arch_files, compress_ctx);
    }
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
        cm_remove_device(arch_file_type, tmp_arch_file_name) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ARCH] failed to remove remained temp archived log file %s", tmp_arch_file_name);
        return CT_ERROR;
    }

    arch_files.src_file = -1;
    status_t status = CT_SUCCESS;
    SYNC_POINT_GLOBAL_START(CANTIAN_REFORM_ARCHIVE_READ_REDO_LOG_FAIL, &status, CT_ERROR);
    status = cm_open_device(logfile->ctrl->name, logfile->ctrl->type, knl_redo_io_flag(session), &arch_files.src_file);
    SYNC_POINT_GLOBAL_END;
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ARCH] failed to open log file %s", logfile->ctrl->name);
        return CT_ERROR;
    }

    arch_files.dst_file = -1;
    if (cm_build_device(tmp_arch_file_name, logfile->ctrl->type, session->kernel->attr.xpurpose_buf,
        CT_XPURPOSE_BUFFER_SIZE, CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size),
        knl_arch_io_flag(session, compress), CT_FALSE, &arch_files.dst_file) != CT_SUCCESS) {
        cm_close_device(logfile->ctrl->type, &arch_files.src_file);
        return CT_ERROR;
    }

    if (cm_open_device(tmp_arch_file_name, logfile->ctrl->type, knl_arch_io_flag(session, compress),
        &arch_files.dst_file) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ARCH] failed to create temp archive log file %s", tmp_arch_file_name);
        cm_close_device(logfile->ctrl->type, &arch_files.src_file);
        return CT_ERROR;
    }

    status = arch_write_arch_file(session, buf, logfile, &arch_files, compress_ctx);

    cm_close_device(logfile->ctrl->type, &arch_files.src_file);
    cm_close_device(logfile->ctrl->type, &arch_files.dst_file);
    return status;
}

status_t arch_archive_file(knl_session_t *session, aligned_buf_t buf, log_file_t *logfile,
    const char *arch_file_name, knl_compress_t *compress_ctx)
{
    const char *src_name = logfile->ctrl->name;
    char tmp_arch_file_name[CT_FILE_NAME_BUFFER_SIZE + 4] = {0}; /* 4 bytes for ".tmp" */
    uint64 left_size = logfile->head.write_pos;
    int32 ret;
    device_type_t arch_file_type = cm_device_type(arch_file_name);
    if (cm_exist_device(arch_file_type, arch_file_name)) {
        CT_LOG_RUN_INF("[ARCH] Archived log file %s already exits", arch_file_name);
        return CT_SUCCESS;
    } else {
        knl_panic(left_size > CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size));
    }

    ret = sprintf_s(tmp_arch_file_name, CT_FILE_NAME_BUFFER_SIZE + 4, "%s.tmp", arch_file_name);
    knl_securec_check_ss(ret);
    if (arch_archive_tmp_file(session, buf, tmp_arch_file_name, logfile, src_name,
        arch_file_name, compress_ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cm_rename_device(arch_file_type, tmp_arch_file_name, arch_file_name) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ARCH] failed to rename temp archive log file %s to %s", tmp_arch_file_name, arch_file_name);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void arch_init_arch_ctrl(knl_session_t *session, arch_ctrl_record_info_t *arch_ctrl_record_info)
{
    arch_ctrl_t *arch_ctrl = arch_ctrl_record_info->arch_ctrl;
    log_file_head_t *log_head = arch_ctrl_record_info->log_head;
    const char *file_name = arch_ctrl_record_info->file_name;
    size_t file_name_size = strlen(file_name) + 1;
    errno_t ret;

    arch_ctrl->recid = arch_ctrl_record_info->recid;
    arch_ctrl->dest_id = arch_ctrl_record_info->dest_id;
    arch_ctrl->stamp = session->kernel->attr.timer->now;

    ret = memcpy_sp(arch_ctrl->name, CT_FILE_NAME_BUFFER_SIZE, file_name, file_name_size);
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

int64 arch_get_ctrl_real_size(arch_ctrl_t *arch_ctrl)
{
    if (arch_ctrl->real_size == 0) {
        return (int64)arch_ctrl->blocks * arch_ctrl->block_size;
    } else {
        return arch_ctrl->real_size;
    }
}

bool32 arch_is_compressed(arch_ctrl_t *arch_ctrl)
{
    return (bool32)((int64)arch_ctrl->blocks * arch_ctrl->block_size != arch_get_ctrl_real_size(arch_ctrl));
}

status_t arch_get_real_size(const char *file_name, int64 *file_size)
{
    int handle;

    *file_size = 0;

    if (cm_open_file(file_name, O_RDONLY | O_BINARY, &handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ARCH] Failed to open file %s", file_name);
        return CT_ERROR;
    }

    *file_size = cm_file_size(handle);
    cm_close_file(handle);

    if (*file_size <= 0) {
        CT_LOG_RUN_ERR("[ARCH] Failed to get file size of %s", file_name);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t arch_flush_head_by_arch_ctrl(knl_session_t *session, arch_ctrl_t *arch_ctrl, int32 head_size, aligned_buf_t *arch_buf)
{
    int32 dst_file = CT_INVALID_HANDLE;
    int32 data_size = 0;
    char *dst_name = arch_ctrl->name;
    device_type_t arch_file_type = cm_device_type(dst_name);
 
    if (cm_open_device(dst_name, arch_file_type, knl_io_flag(session), &dst_file) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ARCHIVE] failed to open archive log file %s", dst_name);
        return CT_ERROR;
    }
    status_t ret = memset_sp(arch_buf->aligned_buf, arch_buf->buf_size, 0, arch_buf->buf_size);
    knl_securec_check(ret);
 
    if (cm_read_device_nocheck(arch_file_type, dst_file, 0, arch_buf->aligned_buf, arch_buf->buf_size,
                               &data_size) != CT_SUCCESS) {
        cm_close_device(arch_file_type, &dst_file);
        return CT_ERROR;
    }
    log_file_head_t *head = (log_file_head_t *)arch_buf->aligned_buf;
 
    head->recid = arch_ctrl->recid;
    head->dest_id = arch_ctrl->dest_id;
    head->arch_ctrl_stamp = arch_ctrl->stamp;
    head->real_size = arch_ctrl->real_size;

    ret = memset_sp(head->unused, CT_LOG_HEAD_RESERVED_BYTES, 0, CT_LOG_HEAD_RESERVED_BYTES);
    knl_securec_check(ret);
 
    log_calc_head_checksum(session, head);
    if (cm_write_device(arch_file_type, dst_file, 0, head, head_size) != CT_SUCCESS) {
        cm_close_device(arch_file_type, &dst_file);
        CT_LOG_RUN_ERR("[ARCH] failed to flush file head by arch_ctrl:%s, offset:%u, size:%d failed.", dst_name, 0, head_size);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[ARCH] Flush file head by arch_ctrl, recid[%u] dest_id[%u], arch_ctrl_stamp[%llu], real_size[%llu].", head->recid, head->dest_id, head->arch_ctrl_stamp, head->real_size);
    cm_close_device(arch_file_type, &dst_file);
    return CT_SUCCESS;
}

void arch_record_arch_ctrl(knl_session_t *session, arch_ctrl_record_info_t *arch_ctrl_record_info)
{
    arch_ctrl_t *arch_ctrl = arch_ctrl_record_info->arch_ctrl;
    const char *file_name = arch_ctrl_record_info->file_name;
    log_file_head_t *log_head = arch_ctrl_record_info->log_head;
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    arch_ctrl->recid = arch_ctx->archived_recid;
    arch_ctrl->dest_id = arch_ctrl_record_info->dest_id;
    arch_ctrl->stamp = session->kernel->attr.timer->now;
    size_t file_name_size = strlen(file_name) + 1;
    errno_t ret = memcpy_sp(arch_ctrl->name, CT_FILE_NAME_BUFFER_SIZE, file_name, file_name_size);
    knl_securec_check(ret);
    arch_ctrl->block_size = log_head->block_size;
    /* log_head->write_pos / log_head->block_size < max int32, cannont overflow */
    arch_ctrl->blocks = (int32)(log_head->write_pos / (uint32)log_head->block_size);
    arch_ctrl->first = log_head->first;
    arch_ctrl->last = log_head->last;
    arch_ctrl->rst_id = log_head->rst_id;
    arch_ctrl->asn = log_head->asn;
    arch_ctrl->real_size = arch_ctrl_record_info->real_file_size;
    if (cm_dbs_is_enable_dbs() == CT_TRUE) {
        arch_ctrl->start_lsn = log_head->first_lsn;
        arch_ctrl->end_lsn = log_head->last_lsn;
    }
}

status_t arch_save_archinfo(knl_session_t *session, arch_ctrl_record_info_t *arch_ctrl_record_info,
                            uint32 archived_start, uint32 archived_end, uint32 end_pos)
{
    log_file_head_t *log_head = arch_ctrl_record_info->log_head;
    int64 real_file_size = arch_ctrl_record_info->real_file_size;
    uint32 node_id = arch_ctrl_record_info->node_id;
    arch_proc_context_t *proc_ctx = arch_ctrl_record_info->proc_ctx;
    arch_ctrl_t *arch_ctrl = db_get_arch_ctrl(session, archived_end, node_id);
    arch_ctrl_record_info->arch_ctrl = arch_ctrl;

    arch_record_arch_ctrl(session, arch_ctrl_record_info);

    proc_ctx->curr_arch_size += real_file_size;
    arch_set_arch_end(session, end_pos, node_id);

    int32 head_size = CM_CALC_ALIGN(sizeof(log_file_head_t), arch_ctrl->block_size);
    aligned_buf_t *arch_buf = &proc_ctx->arch_rw_buf.aligned_buf;
    if (arch_flush_head_by_arch_ctrl(session, arch_ctrl, head_size, arch_buf) != CT_SUCCESS) {
        cm_spin_unlock(&proc_ctx->record_lock);
        CT_LOG_RUN_ERR("[ARCH] failed to flush file head by arch_ctrl.");
        return CT_ERROR;
    }

    if (proc_ctx->last_archived_log.rst_id < log_head->rst_id ||
        (proc_ctx->last_archived_log.rst_id == log_head->rst_id && proc_ctx->last_archived_log.asn < log_head->asn)) {
        proc_ctx->last_archived_log.rst_id = log_head->rst_id;
        proc_ctx->last_archived_log.asn = log_head->asn;
        CT_LOG_DEBUG_INF("[ARCH] Set last_arch_log [%u-%u]", proc_ctx->last_archived_log.rst_id,
                         proc_ctx->last_archived_log.asn);
    }

    // save node ctrl and arch ctrl
    if (db_save_arch_ctrl(session, archived_end, node_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    CT_LOG_RUN_INF("[ARCH] Record archive log file %s for log [%u-%u] start %u end %u size %llu real size %lld",
                   arch_ctrl->name, log_head->rst_id, log_head->asn, archived_start, end_pos, log_head->write_pos,
                   real_file_size);
    return CT_SUCCESS;
}

status_t arch_record_archinfo(knl_session_t *session, const char *file_name,
                              log_file_head_t *log_head, arch_proc_context_t *proc_ctx)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    uint32 node_id = arch_get_proc_node_id(proc_ctx);
    uint32 archived_start = arch_get_arch_start(session, node_id);
    uint32 archived_end = arch_get_arch_end(session, node_id);
    uint32 end_pos = (archived_end + 1) % CT_MAX_ARCH_NUM;
    dtc_node_ctrl_t *node_ctrl = dtc_get_ctrl(session, node_id);
    int64 real_file_size = 0;
    if (arch_get_real_size(file_name, &real_file_size) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ARCH] Failed to record archive log file %s for log [%u-%u] start %u end %u", file_name,
                       log_head->rst_id, log_head->asn, node_ctrl->archived_start, node_ctrl->archived_end);
        return CT_ERROR;
    }

    if (end_pos == archived_start) {
        CM_ABORT(0,
                 "[ARCH] ABORT INFO: Failed to record archive log file %s for log [%u-%u] start %u end %u",
                 file_name, log_head->rst_id, log_head->asn, node_ctrl->archived_start, node_ctrl->archived_end);
    }
    cm_spin_lock(&arch_ctx->record_lock, NULL);
    ++arch_ctx->archived_recid;
    cm_spin_unlock(&arch_ctx->record_lock);

    cm_spin_lock(&proc_ctx->record_lock, NULL);
    arch_ctrl_record_info_t arch_ctrl_record_info = {real_file_size, 0, node_id, 0,
                                                     NULL, file_name, log_head, proc_ctx};
    if (arch_save_archinfo(session, &arch_ctrl_record_info, archived_start, archived_end, end_pos) != CT_SUCCESS) {
        cm_spin_unlock(&proc_ctx->record_lock);
        CM_ABORT(0,
                 "[ARCH] ABORT INFO: save core control file failed when record archive log file %s for "
                 "log [%u-%u] start %u end %u",
                 file_name, log_head->rst_id, log_head->asn, node_ctrl->archived_start, node_ctrl->archived_end);
    }
    cm_spin_unlock(&proc_ctx->record_lock);
    return CT_SUCCESS;
}

status_t arch_try_record_archinfo(knl_session_t *session, uint32 dest_pos, const char *file_name,
    log_file_head_t *head)
{
    if (arch_archive_log_recorded(session, head->rst_id, head->asn, dest_pos, session->kernel->id)) {
        return CT_SUCCESS;
    }
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    arch_proc_context_t *proc_ctx = &arch_ctx->arch_proc[dest_pos - 1];
    if (arch_record_archinfo(session, file_name, head, proc_ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }
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
        arch_locator = (archived_start + i) % CT_MAX_ARCH_NUM;
        arch_ctrl = db_get_arch_ctrl(session, arch_locator, node_id);
        if (arch_ctrl->recid == 0) {
            continue;
        }

        if (arch_ctrl->asn == asn) {
            if (arch_ctrl->rst_id != rst_id) {
                CT_LOG_DEBUG_INF("[ARCH] Archived log[%u-%u] found, but restlog id not equal, %u found but %u required",
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
        arch_locator = (archived_start + i) % CT_MAX_ARCH_NUM;
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
                CT_LOG_DEBUG_INF("[ARCH] Archived log[%u-%u] found, but restlog id not equal, %u found but %u required",
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
        arch_locator = CT_MAX_ARCH_NUM - 1;
    } else {
        arch_locator = (node_ctrl->archived_end - 1) % CT_MAX_ARCH_NUM;
    }

    return db_get_arch_ctrl(session, arch_locator, session->kernel->id);
}

arch_ctrl_t *arch_dtc_get_last_log(knl_session_t *session, uint32 inst_id)
{
    uint32 arch_locator = 0;
    dtc_node_ctrl_t *node_ctrl = dtc_get_ctrl(session, inst_id);

    if (node_ctrl->archived_end == 0) {
        arch_locator = CT_MAX_ARCH_NUM - 1;
    } else {
        arch_locator = (node_ctrl->archived_end - 1) % CT_MAX_ARCH_NUM;
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
        return CT_TRUE;
    }

    if (KNL_NOW(session) - proc_ctx->fail_time >= ARCH_FAIL_PRINT_THRESHOLD) {
        proc_ctx->fail_time = KNL_NOW(session);
        return CT_TRUE;
    }

    return CT_FALSE;
}

bool32 arch_check_logfile(knl_session_t *session, arch_proc_context_t *proc_ctx, log_file_t *logfile)
{
    knl_panic_log(proc_ctx->next_file_id != CT_INVALID_ID32, "next_file_id is invalid.");
    if (logfile->head.asn == CT_INVALID_ASN) {
        CT_LOG_RUN_INF("[ARCH] Empty log file[%u], no need to archive. Skip to process next.", proc_ctx->next_file_id);
        // Try to recycle logfile
        dtc_node_ctrl_t *node_ctrl = dtc_my_ctrl(session);
        log_recycle_file(session, &node_ctrl->rcy_point);
        // Update last archived log file id
        proc_ctx->last_file_id = proc_ctx->next_file_id;
        return CT_TRUE;
    }
    return CT_FALSE;
}

void arch_file_archive(knl_session_t *session, arch_proc_context_t *proc_ctx)
{
    log_file_t *logfile = session->kernel->redo_ctx.files + proc_ctx->next_file_id;
    char arch_file_name[CT_FILE_NAME_BUFFER_SIZE] = {0};
    if (arch_check_logfile(session, proc_ctx, logfile) == CT_TRUE) {
        return;
    }

    arch_set_archive_log_name(session, logfile->head.rst_id, logfile->head.asn, proc_ctx->arch_id, arch_file_name,
                              CT_FILE_NAME_BUFFER_SIZE, session->kernel->id);

    status_t arch_ret = arch_archive_file(session, proc_ctx->arch_rw_buf.aligned_buf, logfile, arch_file_name, &proc_ctx->cmp_ctx);
    arch_set_force_archive_stat(proc_ctx, CT_FALSE);
    if (proc_ctx->is_force_archive == CT_TRUE) {
        arch_set_force_archive_stat(proc_ctx, !(arch_ret == CT_SUCCESS));
    }
    if (arch_ret == CT_SUCCESS) {
        // Update last archived log file id
        proc_ctx->last_file_id = proc_ctx->next_file_id;
        CT_LOG_RUN_INF("[ARCH] Archive log file[%u], restlog id is %u, asn is %u to %s",
            proc_ctx->next_file_id, logfile->head.rst_id, logfile->head.asn, arch_file_name);

        if (!arch_archive_log_recorded(session, logfile->head.rst_id, logfile->head.asn, ARCH_DEFAULT_DEST, session->kernel->id)) {
            // Update control file archive information
            if (arch_record_archinfo(session, arch_file_name, &logfile->head, proc_ctx) !=CT_SUCCESS) {
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
                CT_LOG_DEBUG_INF("[ARCH] Already archived %s, set last_arch_log [%u-%u]", arch_file_name,
                                 proc_ctx->last_archived_log.rst_id, proc_ctx->last_archived_log.asn);
            }
        }
        logfile->ctrl->archived = CT_TRUE;
        if (db_save_log_ctrl(session, proc_ctx->next_file_id, session->kernel->id) != CT_SUCCESS) {
            CM_ABORT(0, "[ARCH] ABORT INFO: save control redo file failed when archive file");
        }

        // Try to recycle logfile
        dtc_node_ctrl_t *node_ctrl = dtc_my_ctrl(session);
        log_recycle_file(session, &node_ctrl->rcy_point);
    } else {
        proc_ctx->write_failed = CT_TRUE;
        if (arch_need_print_error(session, proc_ctx)) {
            CT_LOG_RUN_ERR("[ARCH] Failed to archive log file[%u], restlog id is %u, asn is %u to %s",
                proc_ctx->next_file_id, logfile->head.rst_id, logfile->head.asn, arch_file_name);
        }
        cm_reset_error();
    }
    arch_set_process_alarmed(proc_ctx, arch_file_name, arch_ret);
}

void arch_wake_force_thread(arch_proc_context_t *proc_ctx)
{
    arch_context_t *arch_ctx = &proc_ctx->session->kernel->arch_ctx;
    // handle archive failure in abnormal scenarios
    if (arch_ctx->force_archive_param.failed == CT_TRUE) {
        // the trigger thread will handle itself if it is waiting
        if (arch_ctx->force_archive_param.force_archive && proc_ctx->is_force_archive) {
            arch_ctx->force_archive_param.end_lsn = CT_INVALID_ID64;
            proc_ctx->redo_log_filesize = 0;
            if (arch_ctx->force_archive_param.wait != CT_TRUE) {
                arch_ctx->force_archive_param.failed = CT_FALSE;
            }
            proc_ctx->is_force_archive = CT_FALSE;
            arch_ctx->force_archive_param.force_archive = CT_FALSE;
        } else {
            arch_ctx->force_archive_param.failed = CT_FALSE;
        }
        return;
    }

    if (arch_ctx->force_archive_param.force_archive && proc_ctx->is_force_archive) {
        if (arch_ctx->force_archive_param.end_lsn != CT_INVALID_ID64 &&
            proc_ctx->last_archived_log_record.cur_lsn < arch_ctx->force_archive_param.end_lsn &&
            proc_ctx->redo_log_filesize > 0) {
            CT_LOG_DEBUG_INF("[ARCH] force_archive process, end_lsn %llu, cur_lsn %llu",
                arch_ctx->force_archive_param.end_lsn, proc_ctx->last_archived_log_record.cur_lsn);
            return;
        }
        if (arch_ctx->force_archive_param.end_lsn == CT_INVALID_ID64 &&
            proc_ctx->redo_log_filesize > 0) {
            CT_LOG_DEBUG_INF("[ARCH] force_archive process, remaining size of redo log %llu",
                proc_ctx->redo_log_filesize);
            return;
        }
        CT_LOG_RUN_INF("[ARCH] force_archive success, end_lsn %llu, cur_lsn %llu, redo log size %llu, clear params!",
            arch_ctx->force_archive_param.end_lsn, proc_ctx->last_archived_log_record.cur_lsn,
            proc_ctx->redo_log_filesize);
        arch_ctx->force_archive_param.end_lsn = CT_INVALID_ID64;
        proc_ctx->is_force_archive = CT_FALSE;
        arch_ctx->force_archive_param.force_archive = CT_FALSE;
    }
}

void arch_wake_force_thread_standby(arch_proc_context_t *proc_ctx)
{
    // handle archive failure in abnormal scenarios
    if (proc_ctx->force_archive_failed == CT_TRUE) {
        CT_LOG_RUN_WAR("[ARCH_STANDBY] archive failed, clear force artchive params!");
        if (proc_ctx->force_archive_trigger && proc_ctx->is_force_archive) {
            proc_ctx->redo_log_filesize = 0;
            proc_ctx->is_force_archive = CT_FALSE;
            proc_ctx->force_archive_trigger = CT_FALSE;
        } else {
            proc_ctx->force_archive_failed = CT_FALSE;
        }
        return;
    }

    if (proc_ctx->force_archive_trigger && proc_ctx->is_force_archive) {
        if (proc_ctx->redo_log_filesize > 0) {
            CT_LOG_RUN_INF("[ARCH_STANDBY] force_archive process, remaining size of redo log %llu",
                           proc_ctx->redo_log_filesize);
            return;
        }
        CT_LOG_RUN_INF("[ARCH_STANDBY] force_archive success, cur_lsn %llu, clear params!",
                       proc_ctx->last_archived_log_record.cur_lsn);
        proc_ctx->is_force_archive = CT_FALSE;
        proc_ctx->force_archive_trigger = CT_FALSE;
    }
    return;
}

void arch_set_process_alarmed(arch_proc_context_t *proc_ctx, const char *arch_file_name, status_t arch_ret)
{
    if (arch_ret == CT_SUCCESS) {
        if (proc_ctx->alarmed) {
            CT_LOG_ALARM_RECOVER(WARN_ARCHIVE, "'file-name':'%s'}", arch_file_name);
        }
        proc_ctx->alarmed = CT_FALSE;
        proc_ctx->fail_time = 0;
    } else {
        if (!proc_ctx->alarmed) {
            CT_LOG_ALARM(WARN_ARCHIVE, "'file-name':'%s'}", arch_file_name);
            proc_ctx->alarmed = CT_TRUE;
        }
    }
}

void arch_dbstor_wake_force_thread(arch_proc_context_t *proc_ctx)
{
    cm_spin_lock(&proc_ctx->record_lock, NULL);
    if (proc_ctx->data_type == ARCH_DATA_TYPE_DBSTOR_STANDBY) {
        arch_wake_force_thread_standby(proc_ctx);
        cm_spin_unlock(&proc_ctx->record_lock);
        return;
    }
    arch_wake_force_thread(proc_ctx);
    cm_spin_unlock(&proc_ctx->record_lock);
    return;
}

log_file_t* arch_get_proc_logfile(arch_proc_context_t *proc_ctx)
{
    if (proc_ctx->data_type == ARCH_DATA_TYPE_DBSTOR_STANDBY) {
        return &proc_ctx->logfile;
    }
    return proc_ctx->session->kernel->redo_ctx.files + proc_ctx->next_file_id;
}

uint32 arch_get_proc_node_id(arch_proc_context_t *proc_ctx)
{
    if (proc_ctx->data_type == ARCH_DATA_TYPE_DBSTOR_STANDBY) {
        return proc_ctx->arch_standby_node;
    }
    return proc_ctx->session->kernel->id;
}

void arch_log_recycle_file(arch_proc_context_t *proc_ctx, uint32 node_id)
{
    uint64 free_size = 0;
    knl_session_t *session = proc_ctx->session;
    log_file_t *logfile = arch_get_proc_logfile(proc_ctx);
    dtc_node_ctrl_t *node_ctrl = dtc_get_ctrl(session, node_id);
    log_point_t recycle_point = { 0 };
    recycle_point.lsn = MIN(node_ctrl->rcy_point.lsn, proc_ctx->last_archived_log_record.end_lsn);
    cm_spin_lock(&session->kernel->redo_ctx.flush_lock, &session->stat->spin_stat.stat_log_flush);
    free_size = cm_dbs_ulog_recycle(logfile->handle, recycle_point.lsn);
    CT_LOG_RUN_INF("[ARCH] recycle redo logs in ulog, rcy lsn %llu, archive lsn %llu, free size %llu",
                   node_ctrl->rcy_point.lsn, proc_ctx->last_archived_log_record.end_lsn, free_size);
    cm_spin_unlock(&session->kernel->redo_ctx.flush_lock);
    return;
}

void arch_print_err_info(arch_proc_context_t *proc_ctx)
{
    uint32 node_id = arch_get_proc_node_id(proc_ctx);
    if (proc_ctx->data_type == ARCH_DATA_TYPE_DBSTOR_STANDBY) {
        CT_LOG_RUN_ERR("[ARCH_STANDBY] archive failed, need archive %u, force %u, node id %u, cur arch size %lld,"
                       " cur_lsn %llu, offset %llu, redo log size %llu",
                       proc_ctx->need_file_archive, proc_ctx->force_archive_trigger, node_id,
                       proc_ctx->curr_arch_size, proc_ctx->last_archived_log_record.cur_lsn,
                       proc_ctx->last_archived_log_record.offset, proc_ctx->redo_log_filesize);   
        return; 
    }
    arch_context_t *arch_ctx = &proc_ctx->session->kernel->arch_ctx;
    CT_LOG_RUN_ERR("[ARCH] archive failed, need archive %u, force %u, node id %u, cur arch size %lld,"
                    " cur_lsn %llu, offset %llu, redo log size %llu, wait %u, end_lsn %llu",
                    proc_ctx->need_file_archive, arch_ctx->force_archive_param.force_archive, node_id,
                    proc_ctx->curr_arch_size, proc_ctx->last_archived_log_record.cur_lsn,
                    proc_ctx->last_archived_log_record.offset, proc_ctx->redo_log_filesize,
                    arch_ctx->force_archive_param.wait, arch_ctx->force_archive_param.end_lsn);
    return;
}

void arch_dbstor_do_archive(knl_session_t *session, arch_proc_context_t *proc_ctx)
{
    log_file_t *logfile = arch_get_proc_logfile(proc_ctx);
    uint32 node_id = arch_get_proc_node_id(proc_ctx);
    log_file_head_t head = {0};
    uint32 *cur_asn = &proc_ctx->last_archived_log_record.asn;
    char arch_file_name[CT_FILE_NAME_BUFFER_SIZE] = {0};

    knl_panic_log(proc_ctx->next_file_id != CT_INVALID_ID32, "next_file_id is invalid.");
    status_t ret = arch_dbstor_archive_file(logfile->ctrl->name, arch_file_name, logfile, &head, proc_ctx);
    if (ret == CT_SUCCESS) {
        if (!proc_ctx->need_file_archive) {
            arch_dbstor_wake_force_thread(proc_ctx);
            return;
        }
        proc_ctx->need_file_archive = CT_FALSE;
        if (!arch_archive_log_recorded(session, logfile->head.rst_id, *cur_asn, ARCH_DEFAULT_DEST, node_id)) {
            if (arch_record_archinfo(session, arch_file_name, &head, proc_ctx) != CT_SUCCESS) {
                arch_dbstor_rename_tmp_file(arch_file_name, proc_ctx->tmp_file_name, cm_device_type(proc_ctx->arch_dest));
                arch_dbstor_wake_force_thread(proc_ctx);
                return;
            }
            proc_ctx->last_archived_log_record.asn++;
        } else {
            CT_LOG_RUN_ERR("[ARCH] the corresponding arch ctrl for archive log file [%s] already exists, "
                           "restlog id is %u, asn is %u", arch_file_name, logfile->head.rst_id, *cur_asn);
            CM_ABORT(0, "[ARCH] ABORT INFO: the arch ctrl has been occupied.");
        }
        arch_dbstor_wake_force_thread(proc_ctx);
        proc_ctx->last_archived_log_record.end_lsn = proc_ctx->last_archived_log_record.cur_lsn;
        arch_log_recycle_file(proc_ctx, node_id);
    } else {
        if (arch_need_print_error(session, proc_ctx)) {
            arch_print_err_info(proc_ctx);        
        }
        proc_ctx->need_file_archive = CT_FALSE;
        arch_dbstor_wake_force_thread(proc_ctx);
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
        arch_locator = (archived_start + i) % CT_MAX_ARCH_NUM;
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
                CT_LOG_DEBUG_INF("[ARCH] Archived log[%u-%u] found, but restlog id not equal, %u found but %u required",
                                 arch_ctrl->rst_id, arch_ctrl->asn, arch_ctrl->rst_id, rst_id);
            }
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

bool32 arch_log_point_file(log_point_t curr_rcy_point, log_point_t *rcy_point, log_point_t *backup_rcy,
                           bool32 force_delete)
{
    if (!LOG_POINT_FILE_LT(curr_rcy_point, *rcy_point)) {
        return CT_FALSE;
    }

    if (!force_delete) {
        if (!LOG_POINT_FILE_LT(curr_rcy_point, *backup_rcy)) {
            return CT_FALSE;
        }
    }
    return CT_TRUE;
}

bool32 arch_log_point_dbstor(log_point_t curr_rcy_point, log_point_t *rcy_point, log_point_t *backup_rcy,
                             bool32 force_delete)
{
    if (!LOG_POINT_FILE_LT_CHECK(curr_rcy_point, *rcy_point)) {
        return CT_FALSE;
    }

    if (!force_delete) {
        if (!LOG_POINT_FILE_LT_CHECK(curr_rcy_point, *backup_rcy)) {
            return CT_FALSE;
        }
    }
    return CT_TRUE;
}

bool32 arch_can_be_cleaned(arch_check_log_point check_log_point_func, arch_ctrl_t *arch_ctrl, log_point_t *rcy_point,
                           log_point_t *backup_rcy, knl_alterdb_archivelog_t *def)
{
    log_point_t curr_rcy_point;
    curr_rcy_point.asn = arch_ctrl->asn;
    curr_rcy_point.rst_id = arch_ctrl->rst_id;
    curr_rcy_point.lsn = arch_ctrl->end_lsn;

    if (!def->all_delete) {
        if (arch_ctrl->stamp > def->until_time) {
            return CT_FALSE;
        }
    }
    return check_log_point_func(curr_rcy_point, rcy_point, backup_rcy, def->force_delete);
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
    return CT_FALSE;
}

status_t clean_arch_file(arch_ctrl_t *arch_ctrl, uint32 archived_start, uint32 archived_end,
    log_point_t *rcy_point, log_point_t *backup_rcy)
{
    if (!cm_exist_device(cm_device_type(arch_ctrl->name), arch_ctrl->name)) {
        CT_LOG_RUN_INF("[ARCH] archive file %s is not exist", arch_ctrl->name);
        return CT_SUCCESS;
    }

    if (cm_remove_device(cm_device_type(arch_ctrl->name), arch_ctrl->name) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ARCH] Failed to remove archive file %s", arch_ctrl->name);
        return CT_ERROR;
    }

    CT_LOG_RUN_INF("[ARCH] archive file %s is cleaned, resetlog %u asn %u start_lsn %llu end_lsn %llu start %u end %u."
        "real_size %llu, rcy_point(rst_id: %u, lsn: %llu, asn: %u), backup_rcy(rst_id: %u, lsn: %llu, asn: %u).",
        arch_ctrl->name, arch_ctrl->rst_id, arch_ctrl->asn, arch_ctrl->start_lsn, arch_ctrl->end_lsn,
        archived_start, archived_end, arch_ctrl->real_size, rcy_point->rst_id, rcy_point->lsn, rcy_point->asn,
        backup_rcy->rst_id, backup_rcy->lsn, backup_rcy->asn);
    
    return CT_SUCCESS;
}

status_t arch_do_real_clean(knl_session_t *session, arch_proc_context_t *proc_ctx, log_point_t *rcy_point,
    log_point_t *backup_rcy, uint64 target_size, knl_alterdb_archivelog_t *def)
{
    status_t status = CT_SUCCESS;
    uint32 archived_start = arch_get_arch_start(session, session->kernel->id);
    uint32 archived_end = arch_get_arch_end(session, session->kernel->id);
    uint32 arch_num = 0;
    uint32 clean_num = 0;
    uint32 clean_locator = 0;
    bool32 clean_skip = CT_FALSE;
    arch_ctrl_t *arch_ctrl = NULL;

    cm_spin_lock(&proc_ctx->record_lock, NULL);

    arch_get_files_num(session, proc_ctx->arch_id - 1, session->kernel->id, &arch_num);
    CT_LOG_RUN_INF("[ARCH] current arch file num %u, start %u, end %u, size %lld",
                   arch_num, archived_start, archived_end, proc_ctx->curr_arch_size);
    for (uint32 i = 0; i < arch_num; i++) {
        clean_locator = (archived_start + i) % CT_MAX_ARCH_NUM;
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

        if (!arch_can_be_cleaned(g_arch_func[proc_ctx->data_type].check_log_point_func,
                                 arch_ctrl, rcy_point, backup_rcy, def)) {
            clean_skip = CT_TRUE;
            continue;
        }

        if (clean_arch_file(arch_ctrl, archived_start, archived_end, rcy_point, backup_rcy) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        arch_ctrl->recid = 0;
        if (!clean_skip) {
            clean_num++;
        }

        (void)knl_meta_delete(session, arch_ctrl->first);
        proc_ctx->curr_arch_size -= arch_get_ctrl_real_size(arch_ctrl);

        if (db_save_arch_ctrl(session, clean_locator, session->kernel->id) != CT_SUCCESS) {
            cm_spin_unlock(&proc_ctx->record_lock);
            return CT_ERROR;
        }

        if ((uint64)proc_ctx->curr_arch_size < target_size) {
            break;
        }
    }

    archived_start = (archived_start + clean_num) % CT_MAX_ARCH_NUM;
    arch_set_arch_start(session, archived_start, session->kernel->id);
    if (arch_save_ctrl(session, session->kernel->id) != CT_SUCCESS) {
        status = CT_ERROR;
    }
    CT_LOG_RUN_INF("[ARCH_STANDBY] clean archive file succ, current archived start %u, end %u, size %lld",
                   archived_start, archived_end, proc_ctx->curr_arch_size);
    cm_spin_unlock(&proc_ctx->record_lock);
    return status;
}

status_t arch_check_bak_proc_status(knl_session_t *session)
{
    bool32 running = CT_FALSE;
    cluster_view_t view;
    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        if (i == g_dtc->profile.inst_id) {
            continue;
        }
        rc_get_cluster_view(&view, CT_FALSE);
        if (!rc_bitmap64_exist(&view.bitmap, i)) {
            CT_LOG_RUN_INF("[ARCH] inst id (%u) is not alive, alive bitmap: %llu", i, view.bitmap);
            continue;
        }
        if (dtc_bak_running(session, i, &running) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[ARCH] fail to get backup status from node %u.", i);
            return CT_ERROR;
        }
        if (running != CT_FALSE) {
            CT_LOG_RUN_ERR("[ARCH] backup process is running in node %u, do not clean archived logfiles.", i);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
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
        if (arch_check_bak_proc_status(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (arch_do_real_clean(session, proc_ctx, &min_rcy_point, &backup_rcy_point,
        clean_attr.opt_size, def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (ignore_standby && !LOG_POINT_FILE_EQUAL(local_rcy_point, min_rcy_point) &&
        (uint64)proc_ctx->curr_arch_size > clean_attr.hwm_size) {
        CT_LOG_DEBUG_INF("[ARCH] begin to clean archive logfile ignore standby");
        if (arch_do_real_clean(session, proc_ctx, &local_rcy_point, &backup_rcy_point,
            clean_attr.hwm_size, def) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if ((uint64)proc_ctx->curr_arch_size > clean_attr.hwm_size) {
            CT_LOG_DEBUG_ERR("failed to clean archive logfile ignore standby, local rcy_point [%u-%u/%u/%llu], "
                             "total archive size %lld, archive hwm size %llu",
                             local_rcy_point.rst_id, local_rcy_point.asn, local_rcy_point.block_id,
                             (uint64)local_rcy_point.lfn, proc_ctx->curr_arch_size, clean_attr.hwm_size);
        }
    }

    return CT_SUCCESS;
}

status_t arch_clean_set_params(knl_session_t *session, arch_clean_attr_t* clean_attr, bool32 auto_clean)
{
    lsnd_context_t *lsnd_ctx = &session->kernel->lsnd_ctx;
    database_t *db = &session->kernel->db;

    uint64 max_arch_size = auto_clean ? session->kernel->attr.max_arch_files_size : 0;
    clean_attr->hwm_size = max_arch_size * session->kernel->attr.arch_upper_limit / 100;
    clean_attr->opt_size = max_arch_size * session->kernel->attr.arch_lower_limit / 100;

    clean_attr->min_rcy_point = dtc_my_ctrl(session)->rcy_point;
    bool32 exist_standby = (lsnd_ctx->standby_num != 0) && !DB_IS_RAFT_ENABLED(session->kernel);
    if (exist_standby && !DB_IS_CASCADED_PHYSICAL_STANDBY(db)) {
        lsnd_get_min_contflush_point(lsnd_ctx, &clean_attr->min_rcy_point);
    }

    if (bak_get_last_rcy_point(session, &clean_attr->backup_rcy_point) != CT_SUCCESS) {
        CT_LOG_RUN_INF("[ARCH] failed to get backup rcy_point when clean archive logs");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void arch_auto_clean(arch_proc_context_t *proc_ctx)
{
    knl_session_t *session = proc_ctx->session;
    uint64 max_arch_size = session->kernel->attr.max_arch_files_size;
    uint64 hwm_arch_size = max_arch_size * session->kernel->attr.arch_upper_limit / 100;
    knl_alterdb_archivelog_t def;
    arch_clean_attr_t clean_attr;

    // CT_LOG_RUN_INF("[ARCH] start to clean archive logs, max_arch_size %llu,"
    //                "cur_arch_size %lld, hwm_arch_size %llu",
    //                max_arch_size, proc_ctx->curr_arch_size, hwm_arch_size);
    if (!DB_IS_OPEN(session) || DB_IS_MAINTENANCE(session) ||
        max_arch_size == 0 || (uint64)proc_ctx->curr_arch_size < hwm_arch_size) {
        return;
    }

    if (arch_clean_set_params(session, &clean_attr, CT_TRUE) != CT_SUCCESS) {
        return;
    }

    def.all_delete = CT_FALSE;
    def.force_delete = session->kernel->attr.arch_ignore_backup;
    def.until_time = CT_INVALID_INT64;

    (void)arch_clean_arch_files(session, proc_ctx, &def, clean_attr);
}

status_t arch_clean_arch_files_standby(knl_session_t *session, arch_proc_context_t *proc_ctx,
    knl_alterdb_archivelog_t *def, arch_clean_attr_t clean_attr)
{
    uint64 target_size = clean_attr.opt_size;
    log_point_t backup_rcy = clean_attr.backup_rcy_point;
    log_point_t rcy_point = clean_attr.min_rcy_point;
    uint32 archived_start = arch_get_arch_start(session, proc_ctx->arch_standby_node);
    uint32 archived_end = arch_get_arch_end(session, proc_ctx->arch_standby_node);
    uint32 arch_num = 0;
    uint32 clean_num = 0;
    status_t status = CT_SUCCESS;

    cm_spin_lock(&proc_ctx->record_lock, NULL);
    arch_get_files_num(session, proc_ctx->arch_id - 1, proc_ctx->arch_standby_node, &arch_num);
    CT_LOG_RUN_INF("[ARCH_STANDBY] current arch file num %u, start %u, end %u", arch_num, archived_start, archived_end);
    for (uint32 i = 0; i < arch_num; i++) {
        uint32 clean_locator = (archived_start + i) % CT_MAX_ARCH_NUM;
        arch_ctrl_t *arch_ctrl = db_get_arch_ctrl(session, clean_locator, proc_ctx->arch_standby_node);
        if (arch_ctrl->recid == 0) {
            clean_num++;
            CT_LOG_RUN_WAR("[ARCH_STANDBY] invalid arch ctrl, locator: %u", clean_locator);
            continue;
        }
        if (!arch_can_be_cleaned(g_arch_func[proc_ctx->data_type].check_log_point_func,
                                 arch_ctrl, &rcy_point, &backup_rcy, def)) {
            continue;
        }
        if (clean_arch_file(arch_ctrl, archived_start, archived_end, &rcy_point, &backup_rcy) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }
        arch_ctrl->recid = 0;
        clean_num++;
        proc_ctx->curr_arch_size -= arch_get_ctrl_real_size(arch_ctrl);
        if (db_save_arch_ctrl(session, clean_locator, proc_ctx->arch_standby_node) != CT_SUCCESS) {
            CT_LOG_RUN_WAR("[ARCH_STANDBY] save arch ctrl failed, locator: %u", clean_locator);
            cm_spin_unlock(&proc_ctx->record_lock);
            return CT_ERROR;
        }
        if ((uint64)proc_ctx->curr_arch_size < target_size) {
            break;
        }
    }
    archived_start = (archived_start + clean_num) % CT_MAX_ARCH_NUM;
    arch_set_arch_start(session, archived_start, proc_ctx->arch_standby_node);
    if (arch_save_ctrl(session, proc_ctx->arch_standby_node) != CT_SUCCESS) {
        status = CT_ERROR;
    }
    CT_LOG_RUN_INF("[ARCH_STANDBY] clean archive file succ, current archived start %u, end %u, arch size %lld",
                   archived_start, archived_end, proc_ctx->curr_arch_size);
    cm_spin_unlock(&proc_ctx->record_lock);
    return status;
}

void arch_auto_clean_standby(arch_proc_context_t *proc_ctx)
{
    if (proc_ctx->is_force_archive == CT_TRUE) {
        return;
    }
    knl_session_t *session = proc_ctx->session;
    uint64 max_arch_size = session->kernel->attr.max_arch_files_size;
    uint64 hwm_arch_size = max_arch_size * session->kernel->attr.arch_upper_limit / 100;
    if (!DB_IS_OPEN(session) || DB_IS_MAINTENANCE(session) ||
        max_arch_size == 0 || (uint64)proc_ctx->curr_arch_size < hwm_arch_size) {
        return;
    }

    knl_alterdb_archivelog_t def = { 0 };
    arch_clean_attr_t clean_attr = { 0 };
    clean_attr.hwm_size = max_arch_size * session->kernel->attr.arch_upper_limit / 100;
    clean_attr.opt_size = max_arch_size * session->kernel->attr.arch_lower_limit / 100;
    clean_attr.min_rcy_point = dtc_get_ctrl(session, proc_ctx->arch_standby_node)->rcy_point;
    def.all_delete = CT_FALSE;
    def.force_delete = CT_TRUE;
    def.until_time = CT_INVALID_INT64;

    CT_LOG_RUN_INF("[ARCH_STANDBY] clean archived file, hwm_size %llu, opt_size %llu, rcy lsn %llu",
                    clean_attr.hwm_size, clean_attr.opt_size, clean_attr.min_rcy_point.lsn);
    if (arch_clean_arch_files_standby(session, proc_ctx, &def, clean_attr) != CT_SUCCESS) {
        CT_LOG_RUN_WAR("[ARCH_STANDBY] clean archived file failed!");
    }
    return;
}

static inline void arch_set_file_name(char *buf, const char *arch_dest, char *file_name)
{
    int32 print_num;
    print_num = sprintf_s(buf, CT_FILE_NAME_BUFFER_SIZE, "%s/%s", arch_dest, file_name);
    knl_securec_check_ss(print_num);
    return;
}

#define ARCH_WRINING_RESERVED_LEN 60
#define ARCH_DOTS_RESERVED_LEN 3
#define ARCH_DBID_ZERO_EXIST_WARNING "there exists arch_log with dbid = 0.\n"

status_t arch_remove_abnormal_file(char *arch_path, char **logfile_name,
                                   uint32 remove_file_num, bool32 dbid_zero_exist)
{
    char tmp_name[CT_FILE_NAME_BUFFER_SIZE];
    uint32 filename_len = CT_FILE_NAME_BUFFER_SIZE;
    uint32 dbid_zero_exist_warning_len = dbid_zero_exist ? 0 : strlen(ARCH_DBID_ZERO_EXIST_WARNING);
    const uint32 filename_contact_max_len = CT_MESSAGE_BUFFER_SIZE - strlen(arch_path) - ARCH_WRINING_RESERVED_LEN -
                                            dbid_zero_exist_warning_len;
    char filename_contact[filename_contact_max_len];
    errno_t ret = memset_sp(filename_contact, filename_contact_max_len, 0, filename_contact_max_len);
    knl_securec_check(ret);
    uint32 filename_contact_remain_len = filename_contact_max_len - ARCH_DOTS_RESERVED_LEN;
    bool32 all_listed = CT_TRUE;
    char *file_name;
    for (int i = 0; i < remove_file_num; i++) {
        file_name = logfile_name[i];
        ret = memset_sp(tmp_name, filename_len, 0, filename_len);
        knl_securec_check(ret);
        arch_set_file_name(tmp_name, arch_path, file_name);
        if (cm_remove_device(cm_device_type(tmp_name), tmp_name) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("Failed to remove archive file %s", tmp_name);
            return CT_ERROR;
        }
        CT_LOG_RUN_WAR("[ARCH] remove arch_log %s", tmp_name);
        if (!all_listed || (filename_contact_remain_len < strlen(file_name))) {
            all_listed = CT_FALSE;
            continue;
        }
        ret = strcat_s(filename_contact, filename_contact_max_len, file_name);
        knl_securec_check(ret);
        ret = strcat_s(filename_contact, filename_contact_max_len, "\n");
        knl_securec_check(ret);
        filename_contact_remain_len -= (strlen(file_name) + 1);
    }
    if (!all_listed) {
        ret = strcat_s(filename_contact, filename_contact_max_len, "...");
        knl_securec_check(ret);
    }
    if (dbid_zero_exist) {
        CT_SET_HINT("[ARCH_REMOVE] %sremove %d arch_log in %s, lists:\n%s", ARCH_DBID_ZERO_EXIST_WARNING,
                    remove_file_num, arch_path, filename_contact);
    } else {
        CT_SET_HINT("[ARCH_REMOVE] remove %d arch_log in %s, lists:\n%s", remove_file_num, arch_path, filename_contact);
    }
    
    return CT_SUCCESS;
}

bool32 arch_check_archfile_with_dbid(knl_session_t *session, const char *tmp_name, bool32 *dbid_zero_exist)
{
    uint32 arch_file_dbid = 0;
    if (get_dbid_from_arch_logfile(session, &arch_file_dbid, tmp_name) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ARCH] can not get dbid from arch_log %s ", tmp_name);
        return CT_FALSE;
    }
    // 1.0.0版本中无dbid字段，默认为0，需自行判断是否删除
    if (arch_file_dbid == 0) {
        *dbid_zero_exist = CT_TRUE;
        CT_LOG_RUN_WAR("[ARCH] arch_log %s generated by eariler version, please confirm and remove it manually!",
            tmp_name);
        return CT_FALSE;
    }
    if (arch_file_dbid != session->kernel->db.ctrl.core.dbid) {
        CT_LOG_RUN_WAR("[ARCH] arch_log %s with dbid %u different from current dbid %u",
                tmp_name, arch_file_dbid, session->kernel->db.ctrl.core.dbid);
        return CT_TRUE;
    }
    return CT_FALSE;
}

bool32 arch_check_archfile_with_archctrl(knl_session_t *session, char *arch_path, char *file_name)
{
    if (DB_IS_PRIMARY(&session->kernel->db)) {
        return CT_FALSE;
    }
    uint32 rst_id;
    uint32 node_id;
    char tmp_name[CT_FILE_NAME_BUFFER_SIZE];
    arch_set_file_name(tmp_name, arch_path, file_name);
    char *pos;
    while (*file_name != '_' && *file_name != '\0') {
        file_name++;
    }
    file_name++;
    if (arch_convert_file_name_id_rst(file_name, &pos, &node_id, &rst_id) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ARCH] arch convert file_name failed for %s.", file_name);
        return CT_FALSE;
    }
    uint32 archived_start = arch_get_arch_start(session, node_id);
    uint32 arch_num = 0;
    uint32 arch_locator;
    arch_ctrl_t *arch_ctrl = NULL;
    arch_get_files_num(session, ARCH_DEFAULT_DEST, node_id, &arch_num);
    for (uint32 i = 0; i < arch_num; i++) {
        arch_locator = (archived_start + i) % CT_MAX_ARCH_NUM;
        arch_ctrl = db_get_arch_ctrl(session, arch_locator, node_id);
        if (strcmp(tmp_name, arch_ctrl->name) == 0) {
            return CT_FALSE;
        }
    }
    CT_LOG_RUN_WAR("[ARCH] arch_log %s for node %u can not be found in arch_ctrl.", tmp_name, node_id);
    return CT_TRUE;
}

status_t arch_verify_abnormal_file(knl_session_t *session, char *arch_path, char **logfile_name,
                                   bool32 *dbid_zero_exist, uint32 *remove_file_num)
{
    DIR *arch_dir;
    struct dirent *arch_dirent;
    char *file_name;
    errno_t ret;
    char tmp_name[CT_FILE_NAME_BUFFER_SIZE];
    uint32 filename_len = CT_FILE_NAME_BUFFER_SIZE;
    if ((arch_dir = opendir(arch_path)) == NULL) {
        CT_THROW_ERROR(ERR_INVALID_DIR, arch_path);
        return CT_ERROR;
    }
    while ((arch_dirent = readdir(arch_dir)) != NULL) {
        file_name = arch_dirent->d_name;
        uint32 name_length = strlen(file_name);
        if (name_length <= g_arch_suffix_length ||
            strcmp(file_name + name_length - g_arch_suffix_length, g_arch_suffix_name) != 0) {
            continue;
        }
        CT_LOG_DEBUG_INF("[ARCH] arch info : filename[%s]", file_name);
        ret = memset_sp(tmp_name, filename_len, 0, filename_len);
        knl_securec_check(ret);
        arch_set_file_name(tmp_name, arch_path, file_name);
        if (arch_check_archfile_with_dbid(session, tmp_name, dbid_zero_exist) ||
            arch_check_archfile_with_archctrl(session, arch_path, file_name)) {
            logfile_name[*remove_file_num] = (char *)malloc(filename_len);
            if (logfile_name[*remove_file_num] == NULL) {
                CT_THROW_ERROR(ERR_ALLOC_MEMORY, filename_len, "logfile_name");
                closedir(arch_dir);
                return CT_ERROR;
            }
            ret = strcpy_sp(logfile_name[*remove_file_num], CT_FILE_NAME_BUFFER_SIZE, file_name);
            knl_securec_check(ret);
            (*remove_file_num)++;
        }
        if (*remove_file_num >= CT_MAX_LOG_FILES) {
            break;
        }
    }
    closedir(arch_dir);
    return CT_SUCCESS;
}

status_t arch_clean_abnormal_file(knl_session_t *session)
{
    arch_attr_t *arch_attr = &session->kernel->attr.arch_attr[0];
    char *arch_path = arch_attr->local_path;
    uint32 remove_file_num = 0;
    bool32 dbid_zero_exist = CT_FALSE;
    char **logfile_name = (char **)malloc(sizeof(char *) * CT_MAX_LOG_FILES);
    if (logfile_name == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)(sizeof(char *) * CT_MAX_LOG_FILES), "logfile_name");
        return CT_ERROR;
    }
    status_t status = arch_verify_abnormal_file(session, arch_path, logfile_name, &dbid_zero_exist, &remove_file_num);
    if (status != CT_SUCCESS) {
        for (int i = 0; i < remove_file_num; i++) {
            CM_FREE_PTR(logfile_name[i]);
        }
        CM_FREE_PTR(logfile_name);
        return CT_ERROR;
    }
    status = arch_remove_abnormal_file(arch_path, logfile_name, remove_file_num, dbid_zero_exist);
    for (int i = 0; i < remove_file_num; i++) {
        CM_FREE_PTR(logfile_name[i]);
    }
    CM_FREE_PTR(logfile_name);
    return status;
}

status_t arch_force_clean(knl_session_t *session, knl_alterdb_archivelog_t *def)
{
    if (def->delete_abnormal) {
        return arch_clean_abnormal_file(session);
    }
    arch_context_t *ctx = &session->kernel->arch_ctx;
    arch_proc_context_t *proc_ctx = NULL;
    arch_clean_attr_t clean_attr;

    if (arch_clean_set_params(session, &clean_attr, CT_FALSE) != CT_SUCCESS) {
        return CT_SUCCESS;
    }

    for (uint32 i = 0; i < CT_MAX_ARCH_DEST; i++) {
        proc_ctx = &ctx->arch_proc[i];

        if (proc_ctx->arch_dest[0] == '\0') {
            continue;
        }

        if (arch_clean_arch_files(session, proc_ctx, def, clean_attr) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

void arch_try_update_contflush_point(log_point_t *cont_point, uint32 rst_id, uint32 asn)
{
    if (cont_point->rst_id <= rst_id && cont_point->asn == (asn - 1)) {
        cont_point->rst_id = rst_id;
        cont_point->asn = asn;
    }
}

void arch_check_cont_archived_log_file(arch_proc_context_t *proc_ctx)
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
        arch_locator = (node_ctrl->archived_start + i) % CT_MAX_ARCH_NUM;
        arch_ctrl = db_get_arch_ctrl(session, arch_locator, session->kernel->id);
        if (arch_ctrl->recid == 0) {
            continue;
        }
        arch_try_update_contflush_point(contflush_point, arch_ctrl->rst_id, arch_ctrl->asn);
    }
}

void arch_check_cont_archived_log_dbstor(arch_proc_context_t *proc_ctx)
{
    return;
}

void arch_dbstor_archive(knl_session_t *session, arch_proc_context_t *proc_ctx)
{   
    bool32 force_archive = CT_FALSE;
    arch_get_force_archive_param(proc_ctx, &force_archive);
    if (proc_ctx->is_force_archive == CT_TRUE && force_archive == CT_TRUE) {
        do {
            arch_dbstor_do_archive(session, proc_ctx);
        } while (proc_ctx->redo_log_filesize > 0);
    } else {
        arch_dbstor_do_archive(session, proc_ctx);
    }
}

#define DTC_TIME_INTERVAL_LOG_PRINT_INTERVAL_ONE_HOUR (SECONDS_PER_HOUR * MICROSECS_PER_SECOND)
void arch_print_dtc_time_interval(timeval_t *start_time)
{
    uint64 used_time;
    ELAPSED_END(*start_time, used_time);
    if (used_time < DTC_TIME_INTERVAL_LOG_PRINT_INTERVAL_ONE_HOUR) {
        return;
    }
    uint32 timeout_ticks = 100000; // 10s
    if (!cm_spin_timed_lock(&g_cluster_time_interval_pitr->lock, timeout_ticks)) {
        return;
    }
    ELAPSED_BEGIN(*start_time);
    char date[CT_MAX_TIME_STRLEN] = { 0 };
    for (int i = 0; i < g_cluster_time_interval_pitr->number; i++) {
        if (g_cluster_time_interval_pitr->interval_record[i] >= DTC_TIME_INTERVAL_OPEN_WARNING_US) {
            (void)cm_date2str(g_cluster_time_interval_pitr->date_record[i], "yyyy-mm-dd hh24:mi:ss.ff3", date, CT_MAX_TIME_STRLEN);
            CT_LOG_RUN_WAR("[NTP_TIME_WARN] cluster exist time interval %llu us at %s.",
                           g_cluster_time_interval_pitr->interval_record[i], date);
            errno_t err = memset_sp(date, CT_MAX_TIME_STRLEN, 0, CT_MAX_TIME_STRLEN);
            if (err != EOK) {
                CT_LOG_RUN_ERR("[ARCH] memset_sp for data error!");
            }
        }
    }
    g_cluster_time_interval_pitr->number = 0;
    cm_spin_unlock(&g_cluster_time_interval_pitr->lock);
}

void arch_proc_init_dbstor(knl_session_t *session, arch_proc_context_t *proc_ctx, uint64 *sleep_time)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    *sleep_time = MIN(arch_ctx->arch_time / 2000, 1000);
    proc_ctx->total_arch_size = 0;
    proc_ctx->total_used_time = 0;
    ELAPSED_BEGIN(proc_ctx->arch_record_time.start_time);
    ELAPSED_BEGIN(proc_ctx->arch_record_time.start_intf_time);
    ELAPSED_BEGIN(proc_ctx->check_time_interval_pitr);

    uint32 node_id = proc_ctx->data_type == ARCH_DATA_TYPE_DBSTOR ?
                     proc_ctx->session->kernel->id : proc_ctx->arch_standby_node;
    arch_set_tmp_filename(proc_ctx->tmp_file_name, proc_ctx, node_id);
    CT_LOG_RUN_INF("[ARCH] data_type %u, set tmp arch file name: %s",
                   proc_ctx->data_type, proc_ctx->tmp_file_name);
}

void arch_proc_init_file(knl_session_t *session, arch_proc_context_t *proc_ctx, uint64 *sleep_time)
{
    *sleep_time = 1000;
    return;
}

static void arch_proc(thread_t *thread)
{
    arch_proc_context_t *proc_ctx = (arch_proc_context_t *)thread->argument;
    knl_session_t *session = proc_ctx->session;
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    uint64 sleep_time;
    g_arch_func[proc_ctx->data_type].proc_init_func(session, proc_ctx, &sleep_time);

    cm_set_thread_name("arch_proc");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());
    while (!thread->closed) {
        if (!DB_IS_PRIMARY(&session->kernel->db) || DB_NOT_READY(session) || !proc_ctx->enabled) {
            cm_sleep(2000);
            continue;
        }
        if (g_arch_func[proc_ctx->data_type].need_archive_func(proc_ctx, redo_ctx)) {
            g_arch_func[proc_ctx->data_type].archive_func(session, proc_ctx);
        } else {
            if (arch_ctx->force_archive_param.force_archive == CT_TRUE &&
                proc_ctx->is_force_archive == CT_TRUE) {
                cm_spin_lock(&arch_ctx->dest_lock, NULL);
                arch_ctx->force_archive_param.force_archive = CT_FALSE;
                cm_spin_unlock(&arch_ctx->dest_lock);
                proc_ctx->is_force_archive = CT_FALSE;
            // force arch trigger but not done arch
            } else if (arch_ctx->force_archive_param.force_archive == CT_TRUE &&
                       proc_ctx->is_force_archive == CT_FALSE) {
                continue;
            }
            cm_sleep(sleep_time);
        }

        // Try to record the max continuous received log in standby
        g_arch_func[proc_ctx->data_type].check_cont_archived_log_func(proc_ctx);
        // Try to clean archived log file
        g_arch_func[proc_ctx->data_type].arch_auto_clean_func(proc_ctx);
        arch_print_dtc_time_interval(&proc_ctx->check_time_interval_pitr);
    }

    CT_LOG_RUN_INF("[ARCH] arch read thread exit.");
    KNL_SESSION_CLEAR_THREADID(session);
}

void rc_arch_record_arch_ctrl(arch_ctrl_t *arch_ctrl, knl_session_t *session,
                              const char *file_name, log_file_head_t *log_head)
{
    arch_ctrl->recid = 1;
    arch_ctrl->stamp = session->kernel->attr.timer->now;
    size_t file_name_size = strlen(file_name) + 1;
    errno_t ret = memcpy_sp(arch_ctrl->name, CT_FILE_NAME_BUFFER_SIZE, file_name, file_name_size);
    knl_securec_check(ret);
    arch_ctrl->block_size = log_head->block_size;
    arch_ctrl->blocks = (int32)(log_head->write_pos / (uint32)log_head->block_size);
    arch_ctrl->first = log_head->first;
    arch_ctrl->last = log_head->last;
    arch_ctrl->rst_id = log_head->rst_id;
    arch_ctrl->asn = log_head->asn;
    arch_ctrl->start_lsn = log_head->first_lsn;
    arch_ctrl->end_lsn = log_head->last_lsn;
}

status_t rc_arch_record_archinfo(arch_proc_context_t *proc_ctx, uint32 dest_pos, const char *file_name,
                                 log_file_head_t *log_head, uint32 node_id)
{
    knl_session_t *session = proc_ctx->session;
    arch_ctrl_t *arch_ctrl = NULL;
    uint32 archived_start = arch_get_arch_start(session, node_id);
    uint32 archived_end = arch_get_arch_end(session, node_id);
    uint32 end_pos = (archived_end + 1) % CT_MAX_ARCH_NUM;
    int64 real_file_size;
    dtc_node_ctrl_t *node_ctrl = dtc_get_ctrl(session, node_id);

    if (arch_get_real_size(file_name, &real_file_size) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RC_ARCH] Failed to record archive log file %s for log [%u-%u] start %u end %u", file_name,
                       log_head->rst_id, log_head->asn, node_ctrl->archived_start, node_ctrl->archived_end);
        return CT_ERROR;
    }
    if (end_pos == archived_start) {
        arch_ctrl = db_get_arch_ctrl(session, end_pos, node_id);
        arch_ctrl->recid = 1;
        archived_end = (archived_start + 1) % CT_MAX_ARCH_NUM;
        arch_set_arch_end(session, archived_end, node_id);
        // only save node ctrl
        if (arch_save_ctrl(session, node_id) != CT_SUCCESS) {
            CM_ABORT(0, "[RC_ARCH] ABORT INFO: save core control file failed when record archive log file %s for "
                     "log [%u-%u] start %u end %u",
                     file_name, log_head->rst_id, log_head->asn, node_ctrl->archived_start, node_ctrl->archived_end);
        }
    }

    arch_ctrl = db_get_arch_ctrl(session, archived_end, node_id);
    arch_ctrl->dest_id = dest_pos - 1;
    arch_ctrl->real_size = real_file_size;
    rc_arch_record_arch_ctrl(arch_ctrl, session, file_name, log_head);
    arch_set_arch_end(session, end_pos, node_id);
    // save node ctrl and arch ctrl
    if (db_save_arch_ctrl(session, archived_end, node_id) != CT_SUCCESS) {
        CM_ABORT(0, "[RC_ARCH] ABORT INFO: save arch control file failed when record archive log file %s for "
                 "log [%u-%u] start %u end %u",
                 file_name, log_head->rst_id, log_head->asn, node_ctrl->archived_start, node_ctrl->archived_end);
    }
    log_file_t *logfile = &proc_ctx->logfile;
    int32 head_size = CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size);
    aligned_buf_t *arch_buf = &proc_ctx->arch_rw_buf.aligned_buf;
    if (arch_flush_head_by_arch_ctrl(session, arch_ctrl, head_size, arch_buf) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RC_ARCH] failed to flush file head by arch_ctrl.");
        return CT_ERROR;
    }

    CT_LOG_RUN_INF("[RC_ARCH] Record archive log file %s for log [%u-%u] start %u end %u size %llu real size %lld",
                   arch_ctrl->name, log_head->rst_id, log_head->asn, archived_start, end_pos, log_head->write_pos,
                   real_file_size);
    return CT_SUCCESS;
}

void rc_arch_recycle_file(arch_proc_context_t *proc_ctx)
{
    uint64 free_size = 0;
    knl_session_t *session = proc_ctx->session;
    log_file_t *logfile = &proc_ctx->logfile;
    dtc_node_ctrl_t *node_ctrl = dtc_get_ctrl(session, proc_ctx->arch_id);
    log_point_t recycle_point;
    recycle_point.lsn = MIN(node_ctrl->rcy_point.lsn, proc_ctx->last_archived_log_record.end_lsn);
    timeval_t tv_begin;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_NS_TRUNCATE_ULOG, &tv_begin);
    free_size = cm_dbs_ulog_recycle(logfile->handle, recycle_point.lsn);
    cantian_record_io_stat_end(IO_RECORD_EVENT_NS_TRUNCATE_ULOG, &tv_begin, IO_STAT_SUCCESS);
    CT_LOG_RUN_INF("[RC_ARCH] recycle redo logs in ulog, rcy lsn %llu, archive lsn %llu, free size %llu",
                   node_ctrl->rcy_point.lsn, proc_ctx->last_archived_log_record.end_lsn, free_size);
}

status_t rc_arch_generate_file(arch_proc_context_t *proc_ctx)
{
    log_file_head_t head = {0};
    knl_session_t *session = proc_ctx->session;
    log_file_t *logfile = &proc_ctx->logfile;
    device_type_t arch_file_type = cm_device_type(proc_ctx->arch_dest);
    char arch_file_name[CT_FILE_NAME_BUFFER_SIZE] = {0};
    CT_LOG_RUN_INF("[RC_ARCH] convert a temporary file to a new archive file with head info");
    if (arch_flush_head(arch_file_type, proc_ctx->tmp_file_name, proc_ctx, logfile, &head) != CT_SUCCESS) {
        return CT_ERROR;
    }
    arch_file_name_info_t file_name_info = {logfile->head.rst_id, proc_ctx->last_archived_log_record.asn, proc_ctx->arch_id,
                                            CT_FILE_NAME_BUFFER_SIZE,
                                            proc_ctx->last_archived_log_record.start_lsn,
                                            proc_ctx->last_archived_log_record.cur_lsn,
                                            arch_file_name};
    arch_set_archive_log_name_with_lsn(proc_ctx->session, ARCH_DEFAULT_DEST, &file_name_info);
    if (arch_dbstor_rename_tmp_file(proc_ctx->tmp_file_name, arch_file_name, arch_file_type) != CT_SUCCESS) {
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[RC_ARCH] record the arch file %s info to ctrl", arch_file_name);
    if (!arch_archive_log_recorded(session, logfile->head.rst_id, proc_ctx->last_archived_log_record.asn,
                                   ARCH_DEFAULT_DEST, proc_ctx->arch_id)) {
        if (rc_arch_record_archinfo(proc_ctx, ARCH_DEFAULT_DEST, arch_file_name, &head,
            proc_ctx->arch_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        CT_LOG_RUN_WAR("[RC_ARCH] arch ctrl already exists, arch file name %s", arch_file_name);
    }
    logfile->ctrl->archived = CT_TRUE;
    if (db_save_log_ctrl(session, 0, proc_ctx->arch_id) != CT_SUCCESS) {
        CM_ABORT(0, "[RC_ARCH] ABORT INFO: save control redo file failed when archive file");
    }
    proc_ctx->last_archived_log_record.end_lsn = proc_ctx->last_archived_log_record.cur_lsn;
    rc_arch_recycle_file(proc_ctx);
    return CT_SUCCESS;
}

void rc_arch_file_archive(knl_session_t *session, arch_proc_context_t *proc_ctx)
{
    errno_t ret;
    knl_session_t *rc_session = (knl_session_t *)(g_rc_ctx->session);
    cm_spin_lock(&rc_session->kernel->db.ctrl_lock, NULL);
    ret = memcpy_s(&session->kernel->db.ctrlfiles, sizeof(ctrlfile_set_t), &rc_session->kernel->db.ctrlfiles,
                   sizeof(ctrlfile_set_t));
    knl_securec_check(ret);
    arch_file_archive(session, proc_ctx);
    ret = memcpy_s(&rc_session->kernel->db.ctrlfiles, sizeof(ctrlfile_set_t), &session->kernel->db.ctrlfiles,
                   sizeof(ctrlfile_set_t));
    knl_securec_check(ret);
    cm_spin_unlock(&rc_session->kernel->db.ctrl_lock);
}

void rc_arch_proc(thread_t *thread)
{
    arch_proc_context_t *proc_ctx = (arch_proc_context_t *)thread->argument;
    arch_proc_context_t *rc_proc_ctx = &proc_ctx->session->kernel->arch_ctx.arch_proc[ARCH_DEFAULT_DEST - 1];
    errno_t ret = memcpy_s((char*)rc_proc_ctx, sizeof(arch_proc_context_t), (char*)proc_ctx,
                           sizeof(arch_proc_context_t));
    knl_securec_check(ret);
    knl_session_t *session = rc_proc_ctx->session;
    log_context_t *redo_ctx = &session->kernel->redo_ctx;

    cm_set_thread_name("rc_arch_proc");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());
    while (!thread->closed) {
        if (!rc_proc_ctx->arch_execute || !rc_proc_ctx->enabled) {
            cm_sleep(200);
            continue;
        }

        if (arch_need_archive_file(rc_proc_ctx, redo_ctx)) {
            // Try to archive log file
            rc_arch_file_archive(session, rc_proc_ctx);
        } else {
            rc_proc_ctx->arch_execute = CT_FALSE;
            ret = memcpy_s((char*)proc_ctx, sizeof(arch_proc_context_t), (char*)rc_proc_ctx,
                           sizeof(arch_proc_context_t));
            knl_securec_check(ret);
        }
    }

    logfile_set_t *file_set = LOGFILE_SET(proc_ctx->session, session->kernel->id);
    for (int i = 0; i < file_set->log_count; ++i) {
        cm_close_device(file_set->items[i].ctrl->type, &file_set->items[i].handle);
    }

    free(session->kernel);
    free(session);
    CT_LOG_RUN_INF("[ARCH] arch proc thread exit.");
}

void rc_arch_dbstor_read_proc(thread_t *thread)
{
    arch_proc_context_t *proc_ctx = (arch_proc_context_t *)thread->argument;
    log_file_t *logfile = &proc_ctx->logfile;
    buf_data_t *read_buf = NULL;
    uint32 buf_size = proc_ctx->arch_rw_buf.aligned_buf.buf_size / DBSTOR_ARCH_RW_BUF_NUM;
    int32 data_size = 0;
    uint64 start_lsn = proc_ctx->last_archived_log_record.cur_lsn + 1;
    uint64 last_lsn = proc_ctx->last_archived_log_record.cur_lsn;
    CT_LOG_RUN_INF("[RC_ARCH] start to read redo %s, start lsn %llu", logfile->ctrl->name, start_lsn);

    while (proc_ctx->redo_log_filesize > 0 && !proc_ctx->write_failed) {
        if (arch_get_read_buf(&proc_ctx->arch_rw_buf, &read_buf) != CT_SUCCESS) {
            cm_sleep(1);
            continue;
        }
        if (cm_device_read_batch(logfile->ctrl->type, logfile->handle, start_lsn, CT_INVALID_ID64,
                                 read_buf->data_addr, buf_size, &data_size, &last_lsn) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RC_ARCH] fail to read file %s, start lsn %llu, data size %u, buf size %u",
                           logfile->ctrl->name, start_lsn, data_size, buf_size);
            proc_ctx->read_failed = CT_TRUE;
            break;
        }
        if (data_size == 0) {
            CT_LOG_RUN_INF("[RC_ARCH] reach last lsn, left size(%lld), data size(%d), last_lsn(%llu)",
                           proc_ctx->redo_log_filesize, data_size, last_lsn);
            break;
        }
        if (arch_check_log_valid(data_size, read_buf->data_addr) != CT_SUCCESS) {
            proc_ctx->read_failed = CT_TRUE;
            break;
        }
        read_buf->data_size = data_size;
        read_buf->last_lsn = last_lsn;
        arch_set_read_done(&proc_ctx->arch_rw_buf);
        proc_ctx->redo_log_filesize -= data_size;
        start_lsn = last_lsn + 1;
    }
    arch_wait_write_finish(proc_ctx, &proc_ctx->arch_rw_buf);

    if (!proc_ctx->read_failed && !proc_ctx->write_failed && last_lsn == proc_ctx->last_archived_log_record.cur_lsn) {
        if (rc_arch_generate_file(proc_ctx) != CT_SUCCESS) {
            proc_ctx->read_failed = CT_TRUE;
        }
    }
    proc_ctx->arch_execute = CT_FALSE;
    CT_LOG_RUN_INF("[RC_ARCH] arch read thread exit, last lsn %llu, read stat: %s",
                   last_lsn, proc_ctx->read_failed == CT_SUCCESS ? "SUCCESS" : "ERROR");
}

void arch_write_proc_file(thread_t *thread)
{
    return;
}

void arch_write_proc_dbstor(thread_t *thread)
{
    arch_proc_context_t *proc_ctx = (arch_proc_context_t *)thread->argument;
    buf_data_t *write_buf = NULL;
    status_t status;
    device_type_t arch_file_type = cm_device_type(proc_ctx->arch_dest);
    uint64 *file_offset = &proc_ctx->last_archived_log_record.offset;
    uint64 *cur_lsn = &proc_ctx->last_archived_log_record.cur_lsn;
    while (!thread->closed) {
        if (!proc_ctx->arch_execute || !proc_ctx->enabled) {
            cm_sleep(200);
            continue;
        }
        if (arch_get_write_buf(&proc_ctx->arch_rw_buf, &write_buf) != CT_SUCCESS) {
            cm_sleep(1);
            continue;
        }
        SYNC_POINT_GLOBAL_START(CANTIAN_ARCH_WRITE_LOG_TO_FILE_FAIL, &status, CT_ERROR);
        status = cm_write_device(arch_file_type, proc_ctx->tmp_file_handle,
                                 *file_offset, write_buf->data_addr, write_buf->data_size);
        SYNC_POINT_GLOBAL_END;
        if (status != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[ARCH] fail to write arch %s lsn %llu write size %u", proc_ctx->tmp_file_name,
                           *file_offset, write_buf->data_size);
            proc_ctx->write_failed = CT_TRUE;
            cm_sleep(ARCH_FAIL_WAIT_SLEEP_TIME);
            continue;
        }
        CT_LOG_DEBUG_INF("[ARCH] arch write thread exit, cur lsn %llu, offset %llu, data size %d",
                         *cur_lsn, *file_offset, write_buf->data_size);
        *file_offset += (uint64)write_buf->data_size;
        *cur_lsn = write_buf->last_lsn;
        arch_set_write_done(&proc_ctx->arch_rw_buf);
    }

    CT_LOG_RUN_INF("[ARCH] arch write thread exit, cur lsn %llu, offset %llu, write stat: %s",
        *cur_lsn, *file_offset, proc_ctx->write_failed == CT_SUCCESS ? "SUCCESS" : "ERROR");
}

void arch_write_proc_all(thread_t *thread)
{
    arch_proc_context_t *proc_ctx = (arch_proc_context_t *)thread->argument;
    g_arch_func[proc_ctx->data_type].write_proc_func(thread);
}

status_t arch_check_dest(arch_context_t *arch_ctx, char *dest, uint32 cur_pos)
{
    arch_proc_context_t *proc_ctx = NULL;
    uint32 i;
    knl_attr_t *attr = &arch_ctx->arch_proc[0].session->kernel->attr;

    if (strlen(dest) == 0) {
        return CT_SUCCESS;
    }

    if (strlen(dest) >= CT_MAX_ARCH_NAME_LEN) {
        CT_THROW_ERROR(ERR_NAME_TOO_LONG, "arch dest path", strlen(dest), CT_MAX_ARCH_NAME_LEN);
        return CT_ERROR;
    }

    if (cm_check_exist_special_char(dest, (uint32)strlen(dest))) {
        CT_THROW_ERROR(ERR_INVALID_DIR, dest);
        return CT_ERROR;
    }

    if ((attr->arch_attr[cur_pos].dest_mode == LOG_ARCH_DEST_LOCATION) &&
        !cm_exist_device_dir(cm_device_type(dest), dest)) {
        CT_THROW_ERROR(ERR_DIR_NOT_EXISTS, dest);
        return CT_ERROR;
    }

    for (i = 0; i < CT_MAX_ARCH_DEST; i++) {
        proc_ctx = &arch_ctx->arch_proc[i];
        if (i == cur_pos || strlen(proc_ctx->arch_dest) == 0) {
            continue;
        }

        if (strcmp(proc_ctx->arch_dest, dest) == 0) {
            CT_THROW_ERROR(ERR_DUPLICATE_LOG_ARCHIVE_DEST, cur_pos + 1, i + 1);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

void renew_arch_log_record_lsn(knl_session_t *session, st_arch_log_record_id_t *last_arch_log_record)
{
    uint32 cur_rstid = session->kernel->db.ctrl.core.resetlogs.rst_id;
    if (cur_rstid > last_arch_log_record->rst_id) {
        last_arch_log_record->rst_id = cur_rstid;
        last_arch_log_record->asn = 1;
        CT_LOG_RUN_INF("[ARCH]new rst_id update last archlog record rstid [%u], endlsn [%llu], curlsn [%llu], \
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

    if (cm_dbs_is_enable_dbs() == CT_TRUE) {
        last_arch_log_record->start_lsn = CT_INVALID_ID64;
        last_arch_log_record->asn = 1;
    }

    for (uint32 i = 0; i < arch_num; i++) {
        arch_locator = (archived_start + i) % CT_MAX_ARCH_NUM;
        arch_ctrl = db_get_arch_ctrl(session, arch_locator, session->kernel->id);
        if (arch_ctrl->recid == 0) {
            CT_LOG_RUN_WAR("[ARCH] invalid recid %u, asn %u", arch_ctrl->recid, arch_ctrl->asn);
            continue;
        }

        arch_ctx->arch_proc[dest_id].curr_arch_size += arch_get_ctrl_real_size(arch_ctrl);

        last_arch_log = &arch_ctx->arch_proc[dest_id].last_archived_log;
        if (arch_ctrl->rst_id > last_arch_log->rst_id ||
            (arch_ctrl->rst_id == last_arch_log->rst_id && arch_ctrl->asn > last_arch_log->asn)) {
            last_arch_log->rst_id = arch_ctrl->rst_id;
            last_arch_log->asn = arch_ctrl->asn;
        }
        if (cm_dbs_is_enable_dbs() == CT_TRUE) {
            if (arch_ctrl->rst_id > last_arch_log_record->rst_id ||
                (arch_ctrl->rst_id == last_arch_log_record->rst_id && arch_ctrl->asn >= last_arch_log_record->asn)) {
                last_arch_log_record->rst_id = arch_ctrl->rst_id;
                last_arch_log_record->asn = arch_ctrl->asn + 1;
                last_arch_log_record->end_lsn = arch_ctrl->end_lsn;
                last_arch_log_record->cur_lsn = arch_ctrl->end_lsn;
            }
        }
    }
    if (cm_dbs_is_enable_dbs() == CT_TRUE) {
        renew_arch_log_record_lsn(session, last_arch_log_record);
    }
    if (dest_id == 0) {
        CT_LOG_RUN_INF("[ARCH] update last archlog record rstid[%u], endlsn[%llu], curlsn[%llu], asn[%u], archnum[%u]",
                       last_arch_log_record->rst_id, last_arch_log_record->end_lsn,
                       last_arch_log_record->cur_lsn, last_arch_log_record->asn, arch_num);
    }
}

static status_t arch_init_single_proc_ctx(arch_context_t *arch_ctx, uint32 dest_id, knl_session_t *session)
{
    const config_t *config = session->kernel->attr.config;
    const char *state_format = "ARCHIVE_DEST_STATE_%d";
    char param_name[CT_MAX_NAME_LEN];
    errno_t ret;

    arch_proc_context_t *proc_ctx = &arch_ctx->arch_proc[dest_id];
    ret = memset_sp(proc_ctx, sizeof(arch_proc_context_t), 0, sizeof(arch_proc_context_t));
    knl_securec_check(ret);

    proc_ctx->arch_id = dest_id + 1;
    proc_ctx->session = session->kernel->sessions[SESSION_ID_ARCH];
    proc_ctx->last_file_id = CT_INVALID_ID32;
    proc_ctx->next_file_id = CT_INVALID_ID32;
    proc_ctx->enabled = CT_FALSE;
    proc_ctx->alarmed = CT_FALSE;
    proc_ctx->tmp_file_handle = CT_INVALID_HANDLE;
    proc_ctx->arch_execute = CT_FALSE;

    arch_attr_t *arch_attr = &session->kernel->attr.arch_attr[dest_id];

    // Set log archive destination path
    char *value = arch_attr->local_path;
    if (arch_set_dest(arch_ctx, value, dest_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // Set log archive destination status
    ret = sprintf_s(param_name, CT_MAX_NAME_LEN, state_format, dest_id + 1); /* state_format length < 26 + 11 = 37 */
    knl_securec_check_ss(ret);
    value = cm_get_config_value(config, param_name);
    knl_panic_log(value != NULL, "the config value is NULL.");

    if (arch_set_dest_state(session, value, dest_id, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    arch_init_arch_files_size(session, dest_id);

    if (proc_ctx->arch_dest[0] != '\0' && proc_ctx->dest_status == STATE_ENABLE) {
        if (proc_ctx->arch_id > ARCH_DEFAULT_DEST) {
            CT_LOG_RUN_ERR("[ARCH] Multiple ARCHIVE_DEST not supported. ARCHIVE_DEST_%u is set.",
                proc_ctx->arch_id);
            CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "Set multiple ARCHIVE_DEST",
                "the situation when ARCHIVE_DEST is set");
            return CT_ERROR;
        }
        arch_ctx->arch_dest_num++;
        proc_ctx->enabled = CT_TRUE;
    }
    return CT_SUCCESS;
}


static status_t arch_init_proc_ctx(arch_context_t *arch_ctx, knl_session_t *session)
{
    for (uint32 i = 0; i < CT_MAX_ARCH_DEST; i++) {
        if (arch_init_single_proc_ctx(arch_ctx, i, session) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    // If no LOG_ARCHIVE_DEST_n is configured, set LOG_ARCHIVE_DEST_1 with default value.
    if (arch_ctx->arch_dest_num == 0) {
        arch_proc_context_t *proc_ctx = &arch_ctx->arch_proc[0];
        char *value = session->kernel->home;
        knl_panic_log(value != NULL, "the value is NULL.");

        int32 print_num = sprintf_s(proc_ctx->arch_dest, CT_FILE_NAME_BUFFER_SIZE, "%s/archive_log", value);
        knl_securec_check_ss(print_num);
        if (strlen(proc_ctx->arch_dest) >= CT_MAX_ARCH_NAME_LEN) {
            CT_THROW_ERROR(ERR_NAME_TOO_LONG, "dest path", strlen(proc_ctx->arch_dest), CT_MAX_ARCH_NAME_LEN);
            return CT_ERROR;
        }

        if (!cm_exist_device_dir(cm_device_type(proc_ctx->arch_dest), proc_ctx->arch_dest)) {
            if (cm_create_device_dir(cm_device_type(proc_ctx->arch_dest), proc_ctx->arch_dest) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[ARCH] failed to create dir %s", proc_ctx->arch_dest);
                return CT_ERROR;
            }
        }

        arch_ctx->arch_dest_num++;
        proc_ctx->enabled = CT_TRUE;
    }

    return CT_SUCCESS;
}

status_t arch_open_logfile_dbstor(knl_session_t *session, log_file_t *logfile, uint32 inst_id)
{
    database_t *db = &session->kernel->db;
    logfile->ctrl = (log_file_ctrl_t *)db_get_log_ctrl_item(db->ctrl.pages, 0, sizeof(log_file_ctrl_t),
                                                            db->ctrl.log_segment, inst_id);
    logfile->head.rst_id = db->ctrl.core.resetlogs.rst_id;
    status_t ret = cm_open_device(logfile->ctrl->name, logfile->ctrl->type,
                                  knl_redo_io_flag(session), &logfile->handle);
    if (ret != CT_SUCCESS || logfile->handle == -1) {
        CT_LOG_RUN_ERR("[ARCH] failed to open %s ", logfile->ctrl->name);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[ARCH] open logfile %s finish for instance %u, handle %u",
                   logfile->ctrl->name, inst_id, logfile->handle);
    return CT_SUCCESS;
}

status_t arch_init_logfile(knl_session_t *session)
{
    if (cm_dbs_is_enable_dbs() != CT_TRUE) {
        return CT_SUCCESS;
    }

    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    // init for standby node recycle log 
    for (uint32 node_id = 0; node_id < g_dtc->profile.node_count; node_id++) {
        log_file_t *logfile = &arch_ctx->logfile[node_id];
        logfile->handle = CT_INVALID_HANDLE;
        if (arch_open_logfile_dbstor(session, logfile, node_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t arch_init(knl_session_t *session)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    database_ctrl_t *ctrl = &session->kernel->db.ctrl;
    const config_t *config = session->kernel->attr.config;
    char *value = NULL;

    if (arch_ctx->initialized) {
        if (!arch_ctx->is_archive && ctrl->core.log_mode == ARCHIVE_LOG_ON) {
            arch_ctx->is_archive = CT_TRUE;
        }

        CT_LOG_RUN_INF("[ARCH] Already initialized");
        return CT_SUCCESS;
    }

    arch_ctx->is_archive = (ctrl->core.log_mode == ARCHIVE_LOG_ON);
    dtc_node_ctrl_t *node_ctrl = dtc_my_ctrl(session);
    arch_ctx->rcy_point = &node_ctrl->rcy_point;
    arch_ctx->archived_recid = 0;
    arch_ctx->inst_id = session->kernel->id;
    arch_ctx->force_archive_param.force_archive = CT_FALSE;
    arch_ctx->force_archive_param.end_lsn = CT_INVALID_ID64;
    arch_ctx->force_archive_param.failed = CT_FALSE;
    arch_ctx->data_type = cm_dbs_is_enable_dbs() == CT_TRUE ? ARCH_DATA_TYPE_DBSTOR : ARCH_DATA_TYPE_FILE;
    value = cm_get_config_value(config, g_arch_func[arch_ctx->data_type].archive_format_name);
    if (arch_set_format(arch_ctx, value)) {
        return CT_ERROR;
    }

    if (srv_get_param_size_uint64("ARCH_FILE_SIZE", &arch_ctx->arch_file_size) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "ARCH_FILE_SIZE");
        return CT_ERROR;
    }

    if (srv_get_param_size_uint64("ARCH_SIZE", &arch_ctx->arch_size) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "ARCH_SIZE");
        return CT_ERROR;
    }

    if (srv_get_param_size_uint64("ARCH_TIME", &arch_ctx->arch_time) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "ARCH_TIME");
        return CT_ERROR;
    }

    if (arch_init_proc_ctx(arch_ctx, session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (arch_init_logfile(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    arch_ctx->initialized = CT_TRUE;
    CT_LOG_RUN_INF("[ARCH] Initialization complete");
    return CT_SUCCESS;
}

void arch_last_archived_log(knl_session_t *session, uint32 dest_pos, arch_log_id_t *arch_log_out)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    arch_proc_context_t *proc_ctx = NULL;

    if (dest_pos <= CT_MAX_ARCH_DEST && dest_pos >= ARCH_DEFAULT_DEST) {
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

int64 arch_get_buffer_size(knl_session_t *session)
{
    if (cm_dbs_is_enable_dbs() == CT_TRUE) {
        // dbstor batch's max size may extend to logw_buf_size.
        return (int64)session->kernel->attr.lgwr_buf_size;
    }
    return (int64)CT_ARCHIVE_BUFFER_SIZE;
}

status_t arch_init_proc_resource(knl_session_t *session, arch_proc_context_t *proc_ctx)
{
    uint32 buffer_size = arch_get_buffer_size(session);
    if (arch_init_rw_buf(&proc_ctx->arch_rw_buf, buffer_size * g_arch_func[proc_ctx->data_type].rw_buf_num,
                         "ARCH") != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)CT_ARCHIVE_BUFFER_SIZE, "archive rw buffer");
        return CT_ERROR;
    }

    if (knl_compress_alloc(DEFAULT_ARCH_COMPRESS_ALGO, &proc_ctx->cmp_ctx, CT_TRUE) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ARCH] Failed to alloc compress context for ARCHIVE_DEST_%d[%s]",
            proc_ctx->arch_id, proc_ctx->arch_dest);
        arch_release_rw_buf(&proc_ctx->arch_rw_buf, "ARCH");
        return CT_ERROR;
    }

    if (cm_aligned_malloc(CT_COMPRESS_BUFFER_SIZE, "archive compress buffer",
        &proc_ctx->cmp_ctx.compress_buf) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)CT_COMPRESS_BUFFER_SIZE, "archive compress buffer");
        arch_release_rw_buf(&proc_ctx->arch_rw_buf, "ARCH");
        knl_compress_free(DEFAULT_ARCH_COMPRESS_ALGO, &proc_ctx->cmp_ctx, CT_TRUE);
        return CT_ERROR;
    }

    proc_ctx->cmp_ctx.compress_level = 1;

    if (knl_compress_init(DEFAULT_ARCH_COMPRESS_ALGO, &proc_ctx->cmp_ctx, CT_TRUE) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ARCH] Failed to init compress context for ARCHIVE_DEST_%d[%s]",
            proc_ctx->arch_id, proc_ctx->arch_dest);
        arch_release_rw_buf(&proc_ctx->arch_rw_buf, "ARCH");
        cm_aligned_free(&proc_ctx->cmp_ctx.compress_buf);
        knl_compress_free(DEFAULT_ARCH_COMPRESS_ALGO, &proc_ctx->cmp_ctx, CT_TRUE);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void arch_release_proc_resource(arch_proc_context_t *proc_ctx)
{
    arch_release_rw_buf(&proc_ctx->arch_rw_buf, "ARCH");
    cm_aligned_free(&proc_ctx->cmp_ctx.compress_buf);
    knl_compress_free(DEFAULT_ARCH_COMPRESS_ALGO, &proc_ctx->cmp_ctx, CT_TRUE);
}

status_t arch_create_proc(arch_proc_context_t *proc_ctx)
{
    if (cm_create_thread(arch_proc, 0, proc_ctx, &proc_ctx->read_thread) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cm_create_thread(arch_write_proc_all, 0, proc_ctx, &proc_ctx->write_thread) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t arch_start(knl_session_t *session)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    arch_proc_context_t *proc_ctx = NULL;
    database_ctrl_t *ctrl = &session->kernel->db.ctrl;
    uint32 i;
    arch_ctx->is_archive = (ctrl->core.log_mode == ARCHIVE_LOG_ON);
    if (!arch_ctx->is_archive) {
        return CT_SUCCESS;
    }

    if (!DB_IS_PRIMARY(&session->kernel->db)) {
        return CT_SUCCESS;
    }
    for (i = 0; i < CT_MAX_ARCH_DEST; i++) {
        proc_ctx = &arch_ctx->arch_proc[i];
        proc_ctx->data_type = arch_ctx->data_type;
        if (proc_ctx != NULL && proc_ctx->arch_dest[0] != '\0' && proc_ctx->enabled) {
            if (arch_init_proc_resource(session, proc_ctx) != CT_SUCCESS) {
                return CT_ERROR;
            }
            if (arch_create_proc(proc_ctx) != CT_SUCCESS) {
                arch_release_proc_resource(proc_ctx);
                return CT_ERROR;
            }
            CT_LOG_RUN_INF("[ARCH] Start ARCH thread for ARCHIVE_DEST_%d[%s]", proc_ctx->arch_id, proc_ctx->arch_dest);
        }
    }

    return CT_SUCCESS;
}

void arch_close(knl_session_t *session)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    arch_proc_context_t *proc_ctx = NULL;
    uint32 i;

    for (i = 0; i < CT_MAX_ARCH_DEST; i++) {
        proc_ctx = &arch_ctx->arch_proc[i];
        if (proc_ctx->arch_dest[0] != '\0' && proc_ctx->enabled) {
            cm_close_thread(&proc_ctx->write_thread);
            cm_close_thread(&proc_ctx->read_thread);
            cm_aligned_free(&proc_ctx->arch_rw_buf.aligned_buf);
            cm_aligned_free(&proc_ctx->cmp_ctx.compress_buf);
            knl_compress_free(DEFAULT_ARCH_COMPRESS_ALGO, &proc_ctx->cmp_ctx, CT_TRUE);
            CT_LOG_RUN_INF("[ARCH] Close ARCH thread for ARCHIVE_DEST_%d[%s]",
                           proc_ctx->arch_id, proc_ctx->arch_dest);
        }
    }
}

status_t arch_set_dest(arch_context_t *arch_ctx, char *value, uint32 pos)
{
    knl_panic_log(pos < CT_MAX_ARCH_DEST, "the pos is abnormal, panic info: pos %u", pos);
    arch_proc_context_t *proc_ctx = &arch_ctx->arch_proc[pos];
    size_t value_len;
    errno_t ret;

    cm_spin_lock(&arch_ctx->dest_lock, NULL);
    if (arch_check_dest(arch_ctx, value, pos) != CT_SUCCESS) {
        cm_spin_unlock(&arch_ctx->dest_lock);
        return CT_ERROR;
    }

    value_len = strlen(value);
    ret = strncpy_s(proc_ctx->arch_dest, CT_FILE_NAME_BUFFER_SIZE, value, value_len);
    knl_securec_check(ret);

    cm_spin_unlock(&arch_ctx->dest_lock);
    return CT_SUCCESS;
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
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "archive_dest_state_n");
        cm_spin_unlock(&arch_ctx->dest_lock);
        return CT_ERROR;
    }

    if (!notify) {
        cm_spin_unlock(&arch_ctx->dest_lock);
        return CT_SUCCESS;
    }

    bool32 enable_orig = attr->arch_attr[cur_pos].enable;
    attr->arch_attr[cur_pos].enable = (bool32)(proc_ctx->dest_status == STATE_ENABLE);
    if (arch_check_dest_service(attr, &attr->arch_attr[cur_pos], cur_pos) != CT_SUCCESS) {
        attr->arch_attr[cur_pos].enable = enable_orig;
        cm_spin_unlock(&arch_ctx->dest_lock);
        return CT_ERROR;
    }

    arch_ctx->arch_dest_state_changed = CT_TRUE;
    CT_LOG_RUN_INF("ARCHIVE_DEST_STATE_%d is changed to %s", cur_pos + 1,
                   attr->arch_attr[cur_pos].enable ? "ENABLE" : "DISABLE");

    while (arch_ctx->arch_dest_state_changed) {
        cm_sleep(1);
        if (proc_ctx->read_thread.closed) {
            arch_ctx->arch_dest_state_changed = CT_FALSE;
            cm_spin_unlock(&arch_ctx->dest_lock);
            return CT_ERROR;
        }
    }

    cm_spin_unlock(&arch_ctx->dest_lock);
    return CT_SUCCESS;
}

static status_t arch_check_format(char *value, char *cur_pos, arch_format_info_t *arch_format_info)
{
    switch (*cur_pos) {
        case 's':
        case 'S': {
            if (arch_format_info->has_asn) {
                CT_THROW_ERROR_EX(ERR_INVALID_ARCHIVE_PARAMETER,
                                  "'%s' has repeated format '%c' for ARCHIVE_FORMAT", value, *cur_pos);
                return CT_ERROR;
            }

            arch_format_info->has_asn = CT_TRUE;
            break;
        }
        case 't':
        case 'T': {
            if (arch_format_info->has_instance_id) {
                CT_THROW_ERROR_EX(ERR_INVALID_ARCHIVE_PARAMETER,
                                  "'%s' has repeated format '%c' for ARCHIVE_FORMAT", value, *cur_pos);
                return CT_ERROR;
            }

            arch_format_info->has_instance_id = CT_TRUE;
            break;
        }
        case 'r':
        case 'R': {
            if (arch_format_info->has_rst_id) {
                CT_THROW_ERROR_EX(ERR_INVALID_ARCHIVE_PARAMETER,
                                  "'%s' has repeated format '%c' for ARCHIVE_FORMAT", value, *cur_pos);
                return CT_ERROR;
            }

            arch_format_info->has_rst_id = CT_TRUE;
            break;
        }
        case 'd':
        case 'D': {
            if (arch_format_info->has_start_lsn) {
                CT_THROW_ERROR_EX(ERR_INVALID_ARCHIVE_PARAMETER,
                                  "'%s' has repeated format '%c' for ARCHIVE_FORMAT", value, *cur_pos);
                return CT_ERROR;
            }

            arch_format_info->has_start_lsn = CT_TRUE;
            break;
        }
        case 'e':
        case 'E': {
            if (arch_format_info->has_end_lsn) {
                CT_THROW_ERROR_EX(ERR_INVALID_ARCHIVE_PARAMETER,
                                  "'%s' has repeated format '%c' for ARCHIVE_FORMAT", value, *cur_pos);
                return CT_ERROR;
            }

            arch_format_info->has_end_lsn = CT_TRUE;
            break;
        }
        default: {
            // Invalid format.
            CT_THROW_ERROR_EX(ERR_INVALID_ARCHIVE_PARAMETER,
                              "'%s' has wrong format '%c' for ARCHIVE_FORMAT", value, *cur_pos);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t arch_set_format(arch_context_t *arch_ctx, char *value)
{
    if (value == NULL) {
        CT_LOG_RUN_ERR("[ARCH] value is NULL!");
        return CT_ERROR;
    }
    char *cur_pos = value;

    cm_spin_lock(&arch_ctx->dest_lock, NULL);
    if (strlen(value) > CT_MAX_ARCH_NAME_LEN - CT_ARCH_RESERVED_FORMAT_LEN) {
        CT_THROW_ERROR(ERR_NAME_TOO_LONG, "archive format", strlen(value), CT_MAX_ARCH_NAME_LEN - CT_ARCH_RESERVED_FORMAT_LEN);
        cm_spin_unlock(&arch_ctx->dest_lock);
        return CT_ERROR;
    }
    arch_format_info_t arch_format_info = {0};

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
        if (arch_check_format(value, cur_pos, &arch_format_info) != CT_SUCCESS) {
            cm_spin_unlock(&arch_ctx->dest_lock);
            return CT_ERROR;
        }
        cur_pos++;
    }

    if (cm_dbs_is_enable_dbs() == CT_TRUE) {
        if (!arch_format_info.has_start_lsn || !arch_format_info.has_end_lsn) {
            CT_THROW_ERROR_EX(ERR_INVALID_ARCHIVE_PARAMETER,
                              "'%s' does not contains start_lsn[s], end_lsn[r]for ARCHIVE_FORMAT", value);
            CT_LOG_RUN_ERR("ARCHIVE_FORMAT '%s' does not contains start_lsn[s], end_lsn[r] option", value);
            cm_spin_unlock(&arch_ctx->dest_lock);
            return CT_ERROR;
        }
    }

    if (arch_format_info.has_asn && arch_format_info.has_rst_id) {
        size_t value_len = strlen(value);
        errno_t ret = strncpy_s(arch_ctx->arch_format, CT_FILE_NAME_BUFFER_SIZE, value, value_len);
        knl_securec_check(ret);
        cm_spin_unlock(&arch_ctx->dest_lock);
        return CT_SUCCESS;
    } else {
        CT_THROW_ERROR_EX(ERR_INVALID_ARCHIVE_PARAMETER,
                          "'%s' does not contains asn[s], resetlog[r] or instance[t] option for ARCHIVE_FORMAT", value);
        CT_LOG_RUN_ERR("ARCHIVE_FORMAT '%s' does not contains asn[s], resetlog[r] or instance[t] option", value);
        cm_spin_unlock(&arch_ctx->dest_lock);
        return CT_ERROR;
    }
}

status_t arch_set_max_processes(knl_session_t *session, char *value)
{
    CT_THROW_ERROR(ERR_NOT_COMPATIBLE, "ARCHIVE_MAX_THREADS");
    return CT_ERROR;
}

status_t arch_set_min_succeed(arch_context_t *ctx, char *value)
{
    CT_THROW_ERROR(ERR_NOT_COMPATIBLE, "ARCHIVE_MIN_SUCCEED_DEST");
    return CT_ERROR;
}

status_t arch_set_trace(char *value, uint32 *arch_trace)
{
    CT_THROW_ERROR(ERR_NOT_COMPATIBLE, "ARCHIVE_TRACE");
    return CT_ERROR;
}

char *arch_get_dest_type(knl_session_t *session, uint32 id, arch_attr_t *attr, bool32 *is_primary)
{
    database_t *db = &session->kernel->db;
    uint16 port;
    char host[CT_HOST_NAME_BUFFER_SIZE];

    *is_primary = CT_FALSE;
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
            lrcv_get_primary_server(session, 0, host, CT_HOST_NAME_BUFFER_SIZE, &port) != CT_SUCCESS) {
            return "UNKNOWN";
        }

        if (!strcmp(host, attr->service.host) && port == attr->service.port) {
            if (DB_IS_PHYSICAL_STANDBY(db) && attr->role_valid != VALID_FOR_STANDBY_ROLE) {
                *is_primary = CT_TRUE;
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

            for (i = 0; i < CT_MAX_PHYSICAL_STANDBY; i++) {
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
    attr->arch_attr[inx].enable = CT_FALSE;
}

static inline bool32 arch_dest_both_valid(arch_attr_t *tmp_attr, arch_attr_t *arch_attr)
{
    if (tmp_attr->role_valid != arch_attr->role_valid &&
        tmp_attr->role_valid != VALID_FOR_ALL_ROLES &&
        arch_attr->role_valid != VALID_FOR_ALL_ROLES) {
        return CT_FALSE;
    }

    return (bool32)(tmp_attr->enable && arch_attr->enable);
}

status_t arch_check_dest_service(void *attr, arch_attr_t *arch_attr, uint32 slot)
{
    uint32 i;
    arch_attr_t *tmp_attr = NULL;

    for (i = 1; i < CT_MAX_ARCH_DEST; i++) {
        tmp_attr = &((knl_attr_t *)attr)->arch_attr[i];

        if (i == slot || tmp_attr->dest_mode != LOG_ARCH_DEST_SERVICE) {
            continue;
        }

        if (strcmp(tmp_attr->service.host, arch_attr->service.host) == 0 &&
            tmp_attr->service.port == arch_attr->service.port &&
            arch_dest_both_valid(tmp_attr, arch_attr)) {
            CT_THROW_ERROR(ERR_DUPLICATE_LOG_ARCHIVE_DEST, slot + 1, i + 1);
            CT_LOG_RUN_ERR("ARCHIVE_DEST_%d destination is the same as ARCHIVE_DEST_%d", slot + 1, i + 1);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

bool32 arch_has_valid_arch_dest(knl_session_t *session)
{
    uint32 i;
    knl_attr_t *attr = &session->kernel->attr;

    if (!DB_IS_PRIMARY(&session->kernel->db)) {
        return CT_TRUE;
    }

    for (i = 1; i < CT_MAX_ARCH_DEST; i++) {
        if (attr->arch_attr[i].dest_mode == LOG_ARCH_DEST_SERVICE) {
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

status_t arch_regist_archive(knl_session_t *session, const char *name)
{
    int32 handle = CT_INVALID_HANDLE;
    log_file_head_t head = {0};
    device_type_t type = cm_device_type(name);
    if (cm_open_device(name, type, O_BINARY | O_SYNC | O_RDWR, &handle) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cm_read_device(type, handle, 0, &head, sizeof(log_file_head_t)) != CT_SUCCESS) {
        cm_close_device(type, &handle);
        return CT_ERROR;
    }
    if ((head.cmp_algorithm == COMPRESS_NONE) && ((int64)head.write_pos != cm_device_size(type, handle))) {
        cm_close_device(type, &handle);
        CT_THROW_ERROR(ERR_INVALID_ARCHIVE_LOG, name);
        return CT_ERROR;
    }
    cm_close_device(type, &handle);
    if (arch_try_record_archinfo(session, ARCH_DEFAULT_DEST, name, &head) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t arch_validate_archive_file(knl_session_t *session, arch_file_name_info_t *file_name_info)
{
    // valid directory
    DIR *arch_dir;
    char *arch_path = session->kernel->attr.arch_attr[0].local_path;
    if ((arch_dir = opendir(arch_path)) == NULL) {
        return CT_ERROR;
    }
    
    // valid node_id, rst_id, dbid
    int ret;
    char tmp_name[CT_FILE_NAME_BUFFER_SIZE];
    uint32 filename_len = CT_FILE_NAME_BUFFER_SIZE;
    uint32 arch_file_dbid = 0;
    struct dirent *arch_dirent;
    arch_file_name_info_t local_file_name_info = {0};
    char *file_name;
    uint32 name_length;
    while ((arch_dirent = readdir(arch_dir)) != NULL) {
        file_name = arch_dirent->d_name;
        name_length = strlen(file_name);
        if (name_length <= g_arch_suffix_length ||
            strcmp(file_name + name_length - g_arch_suffix_length, g_arch_suffix_name) != 0) {
            continue;
        }
        char *pos;
        local_file_name_info.buf = file_name;
        if (arch_find_convert_file_name_id_rst(&local_file_name_info, &pos, local_file_name_info.buf) != CT_SUCCESS) {
            return CT_ERROR;
        }
        
        if (file_name_info->node_id != local_file_name_info.node_id ||
            file_name_info->asn != local_file_name_info.asn ||
            file_name_info->rst_id != local_file_name_info.rst_id) {
            continue;
        }

        // valid dbid
        CT_LOG_DEBUG_INF("[ARCH] arch info : filename[%s]", file_name);
        ret = memset_sp(tmp_name, filename_len, 0, filename_len);
        knl_securec_check(ret);
        arch_set_file_name(tmp_name, arch_path, file_name);
        if (get_dbid_from_arch_logfile(session, &arch_file_dbid, tmp_name) != CT_SUCCESS) {
            closedir(arch_dir);
            return CT_ERROR;
        }
        if (arch_file_dbid == session->kernel->db.ctrl.core.bak_dbid) {
            return CT_SUCCESS;
        }
    }
    closedir(arch_dir);
    return CT_ERROR;
}

status_t arch_try_regist_archive(knl_session_t *session, uint32 rst_id, uint32 *asn)
{
    char file_name[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    for (;;) {
        arch_set_archive_log_name(session, rst_id, *asn, ARCH_DEFAULT_DEST,
                                  file_name, CT_FILE_NAME_BUFFER_SIZE, session->kernel->id);

        if (!cm_exist_device(cm_device_type(file_name), file_name)) {
            break;
        }
        arch_file_name_info_t file_name_info = {rst_id, *asn, session->kernel->id,
                                                CT_FILE_NAME_BUFFER_SIZE, 0, 0, file_name};
        if (arch_validate_archive_file(session, &file_name_info) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[ARCH] failed to load archive file");
            break;
        }
        if (arch_regist_archive(session, file_name) != CT_SUCCESS) {
            return CT_ERROR;
        }

        (*asn)++;
    }

    return CT_SUCCESS;
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
                if (cm_remove_device(cm_device_type(arch_ctrl->name), arch_ctrl->name) != CT_SUCCESS) {
                    CT_LOG_RUN_ERR("[ARCH] failed to remove archive logfile %s", arch_ctrl->name);
                } else {
                    proc_ctx->curr_arch_size -= arch_get_ctrl_real_size(arch_ctrl);
                    CT_LOG_RUN_INF("[ARCH] remove archive logfile %s", arch_ctrl->name);
                }
            }

            arch_ctrl->recid = 0;

            if (db_save_arch_ctrl(session, i, session->kernel->id) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[ARCH] failed to save archive control file");
            }
        }

        i = (i + 1) % CT_MAX_ARCH_NUM;
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
        return CT_FALSE;
    }

    if (req_rstid > last_arch_log.rst_id || (req_rstid == last_arch_log.rst_id && req_asn > last_arch_log.asn)) {
        return CT_TRUE;
    }

    if (!DB_IS_PHYSICAL_STANDBY(db)) {
        return CT_FALSE;
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

    for (uint32 i = 1; i < CT_MAX_ARCH_DEST; i++) {
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
    int32 handle = CT_INVALID_HANDLE;
    device_type_t type = cm_device_type(arch_name);
    if (cm_open_device(arch_name, type, 0, &handle) != CT_SUCCESS) {
        CT_LOG_RUN_INF("[ARCH] failed to open %s", arch_name);
        cm_reset_error();
        return CT_FALSE;
    }

    if (cm_read_device(type, handle, 0, &arch_head, sizeof(log_file_head_t)) != CT_SUCCESS) {
        cm_close_device(type, &handle);
        CT_LOG_RUN_INF("[ARCH] failed to read %s", arch_name);
        cm_reset_error();
        return CT_FALSE;
    }

    if (arch_head.cmp_algorithm == COMPRESS_NONE && cm_file_size(handle) != arch_head.write_pos) {
        cm_close_device(type, &handle);
        CT_LOG_RUN_INF("[ARCH] archive file %s is invalid", arch_name);
        return CT_FALSE;
    }
    cm_close_device(type, &handle);

    if (arch_head.first != head.first || arch_head.write_pos < head.write_pos) {
        CT_LOG_RUN_INF("[ARCH] archive file %s is not expected, arch info [%lld-%lld], expected log info [%lld-%lld]",
            arch_name, arch_head.write_pos, arch_head.first, head.write_pos, head.first);
        return CT_FALSE;
    }

    return CT_TRUE;
}

status_t arch_process_existed_archfile(knl_session_t *session, const char *arch_name,
    log_file_head_t head, bool32 *ignore_data)
{
    arch_proc_context_t *proc_ctx = &session->kernel->arch_ctx.arch_proc[0];
    arch_ctrl_t *arch_ctrl = NULL;
    *ignore_data = arch_is_same(arch_name, head);
    if (*ignore_data) {
        return CT_SUCCESS;
    }

    if (cm_remove_file(arch_name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dtc_node_ctrl_t *node_ctrl = dtc_my_ctrl(session);
    for (uint32 i = node_ctrl->archived_start; i != node_ctrl->archived_end;) {
        arch_ctrl = db_get_arch_ctrl(session, i, session->kernel->id);
        if (arch_ctrl->asn == head.asn && arch_ctrl->rst_id == head.rst_id) {
            proc_ctx->curr_arch_size -= (int64)arch_ctrl->blocks * arch_ctrl->block_size;
            arch_ctrl->recid = 0;
            if (db_save_arch_ctrl(session, i, session->kernel->id) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[ARCH] failed to save archive control file");
            }
            break;
        }
        i = (i + 1) % CT_MAX_ARCH_NUM;
    }

    CT_LOG_RUN_INF("[ARCH] Remove archive log %s", arch_name);
    return CT_SUCCESS;
}

static status_t log_try_get_file_offset(knl_session_t *session, log_file_t *logfile, aligned_buf_t *buf)
{
    uint64 size = (uint64)logfile->ctrl->size - logfile->head.write_pos;
    size = (size > buf->buf_size) ? buf->buf_size : size;

    if (logfile->head.write_pos == logfile->ctrl->size) {
        return CT_SUCCESS;
    }
    knl_panic(logfile->head.write_pos < logfile->ctrl->size);

    if (cm_read_device(logfile->ctrl->type, logfile->handle, logfile->head.write_pos,
        buf->aligned_buf, size) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[LOG] failed to read %s ", logfile->ctrl->name);
        return CT_ERROR;
    }
    log_batch_t *batch = (log_batch_t *)(buf->aligned_buf);
    log_batch_tail_t *tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));
    if (size < batch->space_size || !rcy_validate_batch(batch, tail) ||
        batch->head.point.rst_id != logfile->head.rst_id || batch->head.point.asn != logfile->head.asn) {
        return CT_SUCCESS;
    }

    uint64 latest_lfn;
    if (log_get_file_offset(session, logfile->ctrl->name, buf, (uint64 *)&logfile->head.write_pos,
        &latest_lfn, &logfile->head.last) != CT_SUCCESS) {
        return CT_ERROR;
    }
    log_flush_head(session, logfile);

    return CT_SUCCESS;
}

status_t arch_archive_redo(knl_session_t *session, log_file_t *logfile, aligned_buf_t arch_buf,
    aligned_buf_t log_buf, bool32 *is_continue, knl_compress_t *compress_ctx)
{
    char arch_file_name[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    bool32 ignore_data = CT_FALSE;

    if (log_init_file_head(session, logfile) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (logfile->head.write_pos <= CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size)) {
        CT_LOG_RUN_INF("[ARCH] Skip archive empty log file %s", logfile->ctrl->name);
        *is_continue = CT_TRUE;
        return CT_SUCCESS;
    }

    if (log_try_get_file_offset(session, logfile, &log_buf) != CT_SUCCESS) {
        return CT_ERROR;
    }
    arch_set_archive_log_name(session, logfile->head.rst_id, logfile->head.asn, ARCH_DEFAULT_DEST, arch_file_name,
                              CT_FILE_NAME_BUFFER_SIZE, session->kernel->id);

    if (cm_file_exist(arch_file_name)) {
        if (arch_process_existed_archfile(session, arch_file_name, logfile->head, &ignore_data) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (ignore_data) {
            CT_LOG_RUN_INF("[ARCH] skip archive log file %s to %s which already exists",
                logfile->ctrl->name, arch_file_name);
            if (arch_archive_log_recorded(session, logfile->head.rst_id, logfile->head.asn, ARCH_DEFAULT_DEST,
                                          session->kernel->id)) {
                *is_continue = CT_TRUE;
                return CT_SUCCESS;
            }
            return (arch_regist_archive(session, arch_file_name));
        }
    }

    if (arch_archive_file(session, arch_buf, logfile, arch_file_name, compress_ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[ARCH] Archive log file %s to %s", logfile->ctrl->name, arch_file_name);

    if (arch_regist_archive(session, arch_file_name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t arch_redo_alloc_resource(knl_session_t *session, aligned_buf_t *log_buf, aligned_buf_t *arch_buf,
    knl_compress_t *compress_ctx)
{
    uint32 log_buf_size = (uint32)LOG_LGWR_BUF_SIZE(session) + SIZE_K(4);
    uint32 arch_buf_size = (uint32)CT_ARCHIVE_BUFFER_SIZE + SIZE_K(4);

    if (cm_aligned_malloc((int64)log_buf_size, "log buffer", log_buf) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[PITR] failed to alloc log buffer with size %u", log_buf_size);
        return CT_ERROR;
    }

    if (cm_aligned_malloc((int64)arch_buf_size, "arch redo buffer", arch_buf) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[PITR] failed to alloc arch redo buffer with size %u", arch_buf_size);
        cm_aligned_free(log_buf);
        return CT_ERROR;
    }

    if (knl_compress_alloc(DEFAULT_ARCH_COMPRESS_ALGO, compress_ctx, CT_TRUE) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ARCH] Failed to alloc compress context");
        cm_aligned_free(log_buf);
        cm_aligned_free(arch_buf);
        return CT_ERROR;
    }

    compress_ctx->compress_level = 1;

    if (knl_compress_init(DEFAULT_ARCH_COMPRESS_ALGO, compress_ctx, CT_TRUE) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[PITR] Failed to init compress context");
        cm_aligned_free(log_buf);
        cm_aligned_free(arch_buf);
        knl_compress_free(DEFAULT_ARCH_COMPRESS_ALGO, compress_ctx, CT_TRUE);
    }

    if (cm_aligned_malloc(CT_COMPRESS_BUFFER_SIZE, "archive compress buffer",
        &compress_ctx->compress_buf) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)CT_COMPRESS_BUFFER_SIZE, "archive compress buffer");
        cm_aligned_free(log_buf);
        cm_aligned_free(arch_buf);
        knl_compress_free(DEFAULT_ARCH_COMPRESS_ALGO, compress_ctx, CT_TRUE);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t arch_try_arch_redo_by_nodeid(knl_session_t *session, uint32 *max_asn, uint32 node_id)
{
    log_file_t *logfile = NULL;
    aligned_buf_t log_buf;
    aligned_buf_t arch_buf;
    knl_compress_t compress_ctx;

    if (arch_redo_alloc_resource(session, &log_buf, &arch_buf, &compress_ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }

    *max_asn = 0;
    for (uint32 i = 0; i < dtc_get_ctrl(session,node_id)->log_hwm; i++) {
        logfile = &LOGFILE_SET(session, node_id)->items[i];
        if (LOG_IS_DROPPED(logfile->ctrl->flg)) {
            continue;
        }
        if (logfile->ctrl->status == LOG_FILE_ACTIVE || logfile->ctrl->status == LOG_FILE_CURRENT) {
            bool32 is_continue = CT_FALSE;
            if (arch_archive_redo(session, logfile, arch_buf, log_buf, &is_continue, &compress_ctx) != CT_SUCCESS) {
                cm_aligned_free(&log_buf);
                cm_aligned_free(&arch_buf);
                cm_aligned_free(&compress_ctx.compress_buf);
                knl_compress_free(DEFAULT_ARCH_COMPRESS_ALGO, &compress_ctx, CT_TRUE);
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
    knl_compress_free(DEFAULT_ARCH_COMPRESS_ALGO, &compress_ctx, CT_TRUE);

    return CT_SUCCESS;
}

status_t arch_try_arch_one_redo(knl_session_t *session, uint32 rst_id, uint32 asn)
{
    log_file_t *logfile = NULL;
    aligned_buf_t log_buf;
    aligned_buf_t arch_buf;
    knl_compress_t compress_ctx;

    if (session->kernel->db.status != DB_STATUS_MOUNT) {
        CT_LOG_RUN_ERR("[ARCH] Only allowed to archive logfile under MOUNT status, current status is %s",
            db_get_status(session));
        return CT_ERROR;
    }

    for (uint32 i = 0; i < dtc_my_ctrl(session)->log_hwm; i++) {
        logfile = &MY_LOGFILE_SET(session)->items[i];
        if (LOG_IS_DROPPED(logfile->ctrl->flg)) {
            continue;
        }
        if (logfile->ctrl->status == LOG_FILE_ACTIVE || logfile->ctrl->status == LOG_FILE_CURRENT) {
            if (logfile->head.asn != asn || logfile->head.rst_id != rst_id) {
                continue;
            }
            if (arch_redo_alloc_resource(session, &log_buf, &arch_buf, &compress_ctx) != CT_SUCCESS) {
                return CT_ERROR;
            }
            bool32 is_continue = CT_FALSE;
            status_t status = arch_archive_redo(session, logfile, arch_buf, log_buf, &is_continue, &compress_ctx);
            cm_aligned_free(&log_buf);
            cm_aligned_free(&arch_buf);
            cm_aligned_free(&compress_ctx.compress_buf);
            knl_compress_free(DEFAULT_ARCH_COMPRESS_ALGO, &compress_ctx, CT_TRUE);
            return status;
        }
    }

    return CT_ERROR;
}

static bool32 arch_convert_err(const char *err)
{
    if (err == NULL) {
        return CT_FALSE;
    }
 
    if (*err != '\0') {
        if (*err != '_' && *err != '.') {
            // the arch file name illegal
            return CT_TRUE;
        }
    }
    // end of filename
    return CT_FALSE;
}

static status_t arch_str2uint32_withpos(const char *str, uint32 *value, char **endpos)
{
    char *err = NULL;
    int64 val_int64 = strtoll(str, &err, CM_DEFAULT_DIGIT_RADIX);
    if (val_int64 > UINT_MAX || val_int64 < 0) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
                          "Convert uint32 failed, the number text is not in the range of uint32, text = %s", str);
        return CT_ERROR;
    }
 
    *value = (uint32)val_int64;
    *endpos = err;
    return CT_SUCCESS;
}

static status_t arch_str2uint64_withpos(const char *str, uint64 *value, char **endpos)
{
    char *err = NULL;
    *value = strtoull(str, &err, CM_HEX_DIGIT_RADIX);
    if (arch_convert_err(err)) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Convert uint64 failed, text = %s", str);
        return CT_ERROR;
    }
 
    if (*value == ULLONG_MAX) {  // if str = "18446744073709551616", *value will be ULLONG_MAX
        if (cm_compare_str(str, (const char *)UNSIGNED_LLONG_MAX) != 0) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
                "Convert int64 failed, the number text is not in the range of unsigned long long, text = %s", str);
            return CT_ERROR;
        }
    }
    *endpos = err;
    return CT_SUCCESS;
}

status_t arch_convert_file_name_id_rst(char *file_name, char **pos, uint32 *node_id, uint32 *rst_id)
{
    if (arch_str2uint32_withpos(file_name, node_id, pos) != CT_SUCCESS) {
        return CT_ERROR;
    }
    file_name = *pos + 1;
    if (arch_str2uint32_withpos(file_name, rst_id, pos) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t arch_convert_file_name_asn(char *file_name, uint32 *asn)
{
    char *pos = file_name;
    if (arch_str2uint32_withpos(pos, asn, &pos) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t arch_convert_file_name(char *file_name, uint32 *asn, uint64 *start_lsn, uint64 *end_lsn)
{
    char *pos = file_name;
    if (arch_str2uint32_withpos(pos, asn, &pos) != CT_SUCCESS) {
        return CT_ERROR;
    }
    pos++;
    if (arch_str2uint64_withpos(pos, start_lsn, &pos) != CT_SUCCESS) {
        return CT_ERROR;
    }
    pos++;
    if (arch_str2uint64_withpos(pos, end_lsn, &pos) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t arch_find_convert_file_name_id_rst(arch_file_name_info_t *file_name_info, char **pos, char *file_name)
{
    uint32 *local_rst_id = &file_name_info->rst_id;
    uint32 *local_node_id = &file_name_info->node_id;
    while (*file_name != '_' && *file_name != '\0') {
        file_name++;
    }
    file_name++;
    if (arch_convert_file_name_id_rst(file_name, pos, local_node_id, local_rst_id) != CT_SUCCESS) {
        return CT_ERROR;
    }
    file_name = *pos + 1;
    if (arch_convert_file_name_asn(file_name, &file_name_info->asn) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t arch_find_convert_file_name_id_rst_asn_lsn(arch_file_name_info_t *file_name_info)
{
    char *pos;
    char *file_name = file_name_info->buf;
    if (arch_find_convert_file_name_id_rst(file_name_info, &pos, file_name) != CT_SUCCESS) {
        return CT_ERROR;
    }
    file_name = pos + 1;
    uint64 *start_lsn = &file_name_info->start_lsn;
    uint64 *end_lsn = &file_name_info->end_lsn;
    uint32 *asn = &file_name_info->asn;
    if (arch_convert_file_name(file_name, asn, start_lsn, end_lsn) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t arch_find_archive_log_name(knl_session_t *session, arch_file_name_info_t *file_name_info)
{
    DIR *arch_dir;
    struct dirent *arch_dirent;
    char *file_name;
    char *arch_path = session->kernel->attr.arch_attr[0].local_path;
    char tmp_buf[CT_FILE_NAME_BUFFER_SIZE] = {0};
    uint32 tmp_buf_size = CT_FILE_NAME_BUFFER_SIZE;
    uint32 arch_file_dbid = 0;
    uint32 buf_size = file_name_info->buf_size;
    arch_file_name_info_t local_file_name_info = {0};
    if ((arch_dir = opendir(arch_path)) == NULL) {
        return CT_ERROR;
    }
    while ((arch_dirent = readdir(arch_dir)) != NULL) {
        file_name = arch_dirent->d_name;
        uint32 name_length = strlen(file_name);
        if (name_length <= g_arch_suffix_length ||
            strcmp(file_name + name_length - g_arch_suffix_length, g_arch_suffix_name) != 0) {
            continue;
        }
        local_file_name_info.buf = file_name;
        if (arch_find_convert_file_name_id_rst_asn_lsn(&local_file_name_info) != CT_SUCCESS) {
            break;
        }
        if (file_name_info->node_id != local_file_name_info.node_id ||
            file_name_info->rst_id != local_file_name_info.rst_id) {
            continue;
        }
        if (file_name_info->start_lsn > local_file_name_info.start_lsn &&
            file_name_info->start_lsn <= local_file_name_info.end_lsn) {
            memset_sp(tmp_buf, tmp_buf_size, 0, tmp_buf_size);
            arch_set_file_name(tmp_buf, arch_path, arch_dirent->d_name);
            if (get_dbid_from_arch_logfile(session, &arch_file_dbid, tmp_buf) != CT_SUCCESS) {
                closedir(arch_dir);
                return CT_ERROR;
            }
            if (arch_file_dbid == session->kernel->db.ctrl.core.bak_dbid) {
                file_name_info->end_lsn = local_file_name_info.end_lsn;
                file_name_info->asn = local_file_name_info.asn;
                memset_sp(file_name_info->buf, buf_size, 0, buf_size);
                arch_set_file_name(file_name_info->buf, arch_path, arch_dirent->d_name);
                closedir(arch_dir);
                return CT_SUCCESS;
            } else {
                CT_LOG_RUN_WAR("[RESTORE] the dbid %u of archive logfile %s is different from the bak dbid %u",
                    arch_file_dbid, tmp_buf, session->kernel->db.ctrl.core.bak_dbid);
            }
        }
    }
    closedir(arch_dir);
    return CT_ERROR;
}

status_t arch_find_archive_asn_log_name(knl_session_t *session, const char *arch_path, uint32 bak_dbid, arch_file_name_info_t *file_name_info)
{
    DIR *arch_dir;
    struct dirent *arch_dirent;
    char *file_name;
    char tmp_buf[CT_FILE_NAME_BUFFER_SIZE] = {0};
    uint32 tmp_buf_size = CT_FILE_NAME_BUFFER_SIZE;
    uint32 arch_file_dbid = 0;
    uint32 buf_size = file_name_info->buf_size;
    arch_file_name_info_t local_file_name_info = {0};
    if ((arch_dir = opendir(arch_path)) == NULL) {
        return CT_ERROR;
    }
    while ((arch_dirent = readdir(arch_dir)) != NULL) {
        file_name = arch_dirent->d_name;
        uint32 name_length = strlen(file_name);
        if (name_length <= g_arch_suffix_length ||
            strcmp(file_name + name_length - g_arch_suffix_length, g_arch_suffix_name) != 0) {
            continue;
        }
        CT_LOG_DEBUG_INF("[ARCH] arch info : [%u/%u/%u], filename[%s]", file_name_info->rst_id,
                         file_name_info->node_id, file_name_info->asn, file_name);
        local_file_name_info.buf = file_name;
        if (arch_find_convert_file_name_id_rst_asn_lsn(&local_file_name_info) != CT_SUCCESS) {
            break;
        }
        if (file_name_info->node_id != local_file_name_info.node_id ||
            file_name_info->rst_id != local_file_name_info.rst_id) {
            continue;
        }
        if (local_file_name_info.asn == file_name_info->asn) {
            memset_sp(tmp_buf, tmp_buf_size, 0, tmp_buf_size);
            arch_set_file_name(tmp_buf, arch_path, arch_dirent->d_name);
            if (get_dbid_from_arch_logfile(session, &arch_file_dbid, tmp_buf) != CT_SUCCESS) {
                closedir(arch_dir);
                return CT_ERROR;
            }
            if (arch_file_dbid == bak_dbid) {
                memset_sp(file_name_info->buf, buf_size, 0, buf_size);
                arch_set_file_name(file_name_info->buf, arch_path, arch_dirent->d_name);
                closedir(arch_dir);
                return CT_SUCCESS;
            } else {
                CT_LOG_RUN_WAR("[RECOVER] the dbid %u of archive logfile %s is different from the bak dbid %u",
                    arch_file_dbid, tmp_buf, bak_dbid);
            }
        }
    }
    closedir(arch_dir);
    return CT_ERROR;
}

status_t arch_find_first_archfile_rst(knl_session_t *session, const char *arch_path, uint32 bak_dbid, arch_file_name_info_t *file_name_info)
{
    DIR *arch_dir;
    struct dirent *arch_dirent;
    char *file_name;
    uint32 min_asn = 0;
    file_name_info->asn = 0;
    char tmp_buf[CT_FILE_NAME_BUFFER_SIZE] = {0};
    uint32 tmp_buf_size = CT_FILE_NAME_BUFFER_SIZE;
    uint32 arch_file_dbid = 0;
    uint32 buf_size = file_name_info->buf_size;
    arch_file_name_info_t local_file_name_info = {0};
    if ((arch_dir = opendir(arch_path)) == NULL) {
        return CT_ERROR;
    }
    while ((arch_dirent = readdir(arch_dir)) != NULL) {
        file_name = arch_dirent->d_name;
        uint32 name_length = strlen(file_name);
        if (name_length <= g_arch_suffix_length ||
            strcmp(file_name + name_length - g_arch_suffix_length, g_arch_suffix_name) != 0) {
            continue;
        }
        CT_LOG_DEBUG_INF("[ARCH] arch info : [%u/%u/%u], filename[%s]", file_name_info->rst_id,
                         file_name_info->node_id, file_name_info->asn, file_name);
        local_file_name_info.buf = file_name;
        if (arch_find_convert_file_name_id_rst_asn_lsn(&local_file_name_info) != CT_SUCCESS) {
            break;
        }
        if (file_name_info->node_id != local_file_name_info.node_id ||
            file_name_info->rst_id != local_file_name_info.rst_id) {
            continue;
        }
        if (min_asn == 0 || min_asn > local_file_name_info.asn) {
            memset_sp(tmp_buf, tmp_buf_size, 0, tmp_buf_size);
            arch_set_file_name(tmp_buf, arch_path, arch_dirent->d_name);
            if (get_dbid_from_arch_logfile(session, &arch_file_dbid, tmp_buf) != CT_SUCCESS) {
                closedir(arch_dir);
                return CT_ERROR;
            }
            if (arch_file_dbid == bak_dbid) {
                file_name_info->asn = local_file_name_info.asn;
                min_asn = local_file_name_info.asn;
                memset_sp(file_name_info->buf, buf_size, 0, buf_size);
                arch_set_file_name(file_name_info->buf, arch_path, arch_dirent->d_name);
            } else {
                CT_LOG_RUN_WAR("[RECOVER] the dbid %u of archive logfile %s is different from the bak dbid %u",
                    arch_file_dbid, tmp_buf, bak_dbid);
            }
        }
    }
    closedir(arch_dir);
    if (file_name_info->asn != 0) {
        return CT_SUCCESS;
    }
    return CT_ERROR;
}

status_t arch_get_tmp_file_last_lsn(char *buf, int32 size_read, uint64 *lsn, uint32 *data_size)
{
    int32 buffer_size = size_read;
    uint32 invalide_size = 0;
    log_batch_t *batch = NULL;
    while (buffer_size >= sizeof(log_batch_t)) {
        batch = (log_batch_t *)(buf + invalide_size);
        if (batch == NULL) {
            CT_LOG_RUN_ERR("[DTC RCY] batch is null, read_size[%d], invalide_size[%u]",
                           size_read, invalide_size);
            return CT_ERROR;
        }
        if (buffer_size < batch->size) {
            break;
        }
        if (!dtc_rcy_validate_batch(batch)) {
            CT_LOG_RUN_ERR("[DTC RCY] batch is invalidate, read_size[%d], invalide_size[%u]",
                           size_read, invalide_size);
            return CT_ERROR;
        }
        invalide_size += batch->space_size;
        buffer_size -= batch->space_size;
    }
    if (batch == NULL) {
        CT_LOG_RUN_ERR("[DTC RCY] batch is null, read_size[%d]", size_read);
        return CT_ERROR;
    }
    *lsn = batch->lsn;
    *data_size = invalide_size;
    return CT_SUCCESS;
}

status_t arch_read_file(knl_session_t *session, char *file_name, int64 head_size, uint64 *out_lsn,
                        uint32 node_id, arch_proc_context_t *proc_ctx)
{
    int32  file_handle = CT_INVALID_HANDLE;
    int64  offset = 0;
    uint32 size_read = 0;
    uint32 data_size = 0;
    aligned_buf_t read_buf = {0};
    arch_set_tmp_filename(file_name, proc_ctx, node_id);
    bool32 exist_tmp_file = cm_exist_device(cm_device_type(proc_ctx->arch_dest), file_name);
    if (!exist_tmp_file) {
        *out_lsn = 0;
        return CT_SUCCESS;
    }
    if (cm_aligned_malloc(CT_MAX_BATCH_SIZE, "log buffer", &read_buf) != CT_SUCCESS) {
        return CT_ERROR;
    }

    int64 size_need_read = read_buf.buf_size;
    char* buf = read_buf.aligned_buf;
    do {
        offset = offset == 0 ? head_size : offset + data_size;
        status_t status = dtc_rcy_read_log(session, &file_handle, file_name, offset,
                                           buf, read_buf.buf_size, size_need_read, &size_read);
        if (status != CT_SUCCESS) {
            cm_aligned_free(&read_buf);
            return status;
        }
        if (size_read == 0) {
            proc_ctx->last_archived_log_record.offset = offset;
            cm_aligned_free(&read_buf);
            return status;
        }
        status = arch_get_tmp_file_last_lsn(buf, (int32)(size_read), out_lsn, &data_size);
        if (status != CT_SUCCESS) {
            cm_aligned_free(&read_buf);
            return status;
        }
    } while (size_read > 0);
    cm_aligned_free(&read_buf);
    return CT_SUCCESS;
}

status_t arch_force_do_archive(knl_session_t *session, uint64 cur_lsn, uint32 node_id, device_type_t type, int32 handle)
{
    arch_proc_context_t *proc_ctx_force = &session->kernel->arch_ctx.arch_proc[ARCH_DEFAULT_DEST - 1];
    log_file_t *logfile = session->kernel->redo_ctx.files;
    uint32 archived_end = arch_get_arch_end(session, node_id);
    arch_ctrl_t *arch_ctrl = db_get_arch_ctrl(session, archived_end, node_id);
    if (arch_ctrl == NULL) {
        return CT_ERROR;
    }
    uint32 redo_log_filesize = 0;
    if (arch_init_rw_buf(&proc_ctx_force->arch_rw_buf, arch_get_buffer_size(session), "ARCH") != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)CT_ARCHIVE_BUFFER_SIZE, "archive rw buffer");
        return CT_ERROR;
    }
    if (cm_create_thread(arch_write_proc_dbstor, 0, proc_ctx_force, &proc_ctx_force->write_thread) != CT_SUCCESS) {
        arch_release_rw_buf(&proc_ctx_force->arch_rw_buf, "ARCH");
        return CT_ERROR;
    }
    proc_ctx_force->last_archived_log_record.rst_id = arch_ctrl->rst_id;
    uint32 asn = arch_ctrl->asn + 1;
    uint64 start_lsn = arch_ctrl->end_lsn;
    proc_ctx_force->last_archived_log_record.asn = asn;
    proc_ctx_force->last_archived_log_record.start_lsn = start_lsn;
    proc_ctx_force->last_archived_log_record.end_lsn = start_lsn;
    proc_ctx_force->last_archived_log_record.cur_lsn = cur_lsn == 0 ? arch_ctrl->end_lsn : cur_lsn;

    CT_LOG_RUN_INF("[ARCH] archinit rst_id [%u], start [%llu], end [%llu], asn [%u], cur [%llu]",
                   arch_ctrl->rst_id, arch_ctrl->start_lsn, arch_ctrl->end_lsn, arch_ctrl->asn, cur_lsn);
    start_lsn = proc_ctx_force->last_archived_log_record.cur_lsn + 1;
    if (cm_device_get_used_cap(type, handle, start_lsn, &redo_log_filesize) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ARCH] failed to fetch redolog size from DBStor");
        arch_release_rw_buf(&proc_ctx_force->arch_rw_buf, "ARCH");
        return CT_ERROR;
    }
    proc_ctx_force->redo_log_filesize = SIZE_K(redo_log_filesize);
    proc_ctx_force->session->kernel->id = node_id;
    proc_ctx_force->need_file_archive = CT_TRUE;
    logfile->head.asn = arch_ctrl->asn;
    logfile->handle = handle;
    do {
        arch_dbstor_do_archive(session, proc_ctx_force);
    } while (proc_ctx_force->redo_log_filesize > 0);
    if (proc_ctx_force->alarmed == CT_TRUE) {
        arch_release_rw_buf(&proc_ctx_force->arch_rw_buf, "ARCH");
        return CT_ERROR;
    }
    arch_release_rw_buf(&proc_ctx_force->arch_rw_buf, "ARCH");
    return CT_SUCCESS;
}

status_t arch_force_archive_file(knl_session_t *session, uint32 node_id, int32 block_size,
                                 device_type_t type, int32 handle)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    arch_proc_context_t *proc_ctx_force = &arch_ctx->arch_proc[ARCH_DEFAULT_DEST - 1];
    // read temp file and get start end lsn.
    char file_name[CT_FILE_NAME_BUFFER_SIZE];
    uint64 cur_lsn = 0;
    arch_ctx->force_archive_param.force_archive = CT_TRUE;
    arch_ctx->force_archive_param.end_lsn = CT_INVALID_ID64;
    proc_ctx_force->next_file_id = redo_ctx->curr_file;
    proc_ctx_force->session = session;

    const config_t *config = session->kernel->attr.config;
    char *format_value = NULL;
    format_value = cm_get_config_value(config, "ARCHIVE_FORMAT_WITH_LSN");
    if (arch_set_format(arch_ctx, format_value)) {
        return CT_ERROR;
    }

    char *value = cm_get_config_value(config, "ARCHIVE_DEST_1");
    strncpy_s(proc_ctx_force->arch_dest, CT_FILE_NAME_BUFFER_SIZE, &value[ARCH_DEST_PREFIX_LENGTH],
              strlen(value) - ARCH_DEST_PREFIX_LENGTH);

    if (arch_read_file(session, file_name, block_size, &cur_lsn, node_id, proc_ctx_force) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (arch_force_do_archive(session, cur_lsn, node_id, type, handle) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t arch_init_rw_buf(arch_rw_buf_t *rw_buf, uint32 buf_size, const char *task)
{
    CT_LOG_RUN_INF("[%s] init aligned buf for read and write process paral. buf size %u, num %u", task, buf_size,
                   DBSTOR_ARCH_RW_BUF_NUM);
    error_t err = memset_sp(rw_buf, sizeof(arch_rw_buf_t), 0, sizeof(arch_rw_buf_t));
    knl_securec_check(err);
    if (cm_aligned_malloc(buf_size, "bak rw buf", &rw_buf->aligned_buf) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ARCHIVE] failed to malloc rw buf");
        return CT_ERROR;
    }
    rw_buf->buf_data[0].data_addr = rw_buf->aligned_buf.aligned_buf;
    rw_buf->buf_data[1].data_addr = rw_buf->aligned_buf.aligned_buf + buf_size / DBSTOR_ARCH_RW_BUF_NUM;
    return CT_SUCCESS;
}

void arch_release_rw_buf(arch_rw_buf_t *rw_buf, const char *task)
{
    CT_LOG_RUN_INF("[%s] release aligned buf for read and write process paral.", task);
    cm_aligned_free(&rw_buf->aligned_buf);
}

status_t arch_get_read_buf(arch_rw_buf_t *rw_buf, buf_data_t **read_buf)
{
    if (rw_buf->buf_stat[rw_buf->read_index] == CT_FALSE) {
        *read_buf = &rw_buf->buf_data[rw_buf->read_index];
        return CT_SUCCESS;
    }
    return CT_ERROR;
}

void arch_set_read_done(arch_rw_buf_t *rw_buf)
{
    rw_buf->buf_stat[rw_buf->read_index] = CT_TRUE;
    rw_buf->read_index = !rw_buf->read_index;
}

status_t arch_get_write_buf(arch_rw_buf_t *rw_buf, buf_data_t **write_buf)
{
    if (rw_buf->buf_stat[rw_buf->write_index] == CT_TRUE) {
        *write_buf = &rw_buf->buf_data[rw_buf->write_index];
        return CT_SUCCESS;
    }
    return CT_ERROR;
}

void arch_set_write_done(arch_rw_buf_t *rw_buf)
{
    rw_buf->buf_stat[rw_buf->write_index] = CT_FALSE;
    rw_buf->write_index = !rw_buf->write_index;
}

void arch_wait_write_finish(arch_proc_context_t *proc_ctx, arch_rw_buf_t *rw_buf)
{
    for (uint32 i = 0; i <= 1 && !proc_ctx->write_failed;) {
        if (rw_buf->buf_stat[i] == CT_TRUE) {
            cm_sleep(ARCH_WAIT_WRITE_FINISH_SLEEP_TIME);
            continue;
        }
        i++;
    }
    rw_buf->buf_stat[0] = CT_FALSE;
    rw_buf->buf_stat[1] = CT_FALSE;
}

void arch_dbs_ctrl_record_arch_ctrl(arch_ctrl_t *arch_ctrl, log_file_head_t *log_head, const char *name)
{
    size_t file_name_size = strlen(name) + 1;
    errno_t ret = memcpy_sp(arch_ctrl->name, CT_FILE_NAME_BUFFER_SIZE, name, file_name_size);
    knl_securec_check(ret);
    arch_ctrl->recid = log_head->recid;
    arch_ctrl->dest_id = log_head->dest_id;
    arch_ctrl->rst_id = log_head->rst_id;
    arch_ctrl->asn = log_head->asn;
    arch_ctrl->stamp = log_head->arch_ctrl_stamp;
    arch_ctrl->block_size = log_head->block_size;
    arch_ctrl->blocks = (int32)(log_head->write_pos / (uint32)log_head->block_size);
    arch_ctrl->first = log_head->first;
    arch_ctrl->last = log_head->last;
    arch_ctrl->real_size = log_head->real_size;
    if (cm_dbs_is_enable_dbs() == CT_TRUE) {
        arch_ctrl->start_lsn = log_head->first_lsn;
        arch_ctrl->end_lsn = log_head->last_lsn;
    }
}

status_t arch_dbs_ctrl_rebuild_parse_arch_ctrl(knl_session_t *session, const char *file_name, uint32 node_id)
{
    log_file_head_t log_head;
    int32 handle = CT_INVALID_HANDLE;
    device_type_t type = cm_device_type(file_name);
    if (cm_open_device(file_name, type, O_BINARY | O_SYNC | O_RDWR, &handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[arch_bk] can not open archivelog %s.", file_name);
        return CT_ERROR;
    }
    if (cm_read_device(type, handle, 0, &log_head, sizeof(log_file_head_t)) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[arch_bk] can not read archivelog %s.", file_name);
        cm_close_device(type, &handle);
        return CT_ERROR;
    }
    dtc_node_ctrl_t *node_ctrl = dtc_get_ctrl(session, node_id);
    arch_ctrl_t *arch_ctrl = NULL;
    uint32 archived_start = arch_get_arch_start(session, node_id);
    uint32 archived_end = arch_get_arch_end(session, node_id);
    uint32 end_pos = (archived_end + 1) % CT_MAX_ARCH_NUM;
    if (end_pos == archived_start) {
        arch_ctrl = db_get_arch_ctrl(session, end_pos, node_id);
        arch_ctrl->recid = 1;
        archived_end = (archived_start + 1) % CT_MAX_ARCH_NUM;
        arch_set_arch_end(session, archived_end, node_id);
        // only save node ctrl
        if (arch_save_ctrl(session, node_id) != CT_SUCCESS) {
            CM_ABORT(0, "[arch_bk] ABORT INFO: save core control file failed when record archive log file %s for "
                     "start %u end %u",
                     file_name, node_ctrl->archived_start, node_ctrl->archived_end);
        }
    }
    arch_ctrl = db_get_arch_ctrl(session, archived_end, node_id);
    arch_dbs_ctrl_record_arch_ctrl(arch_ctrl, &log_head, file_name);
    arch_set_arch_end(session, end_pos, node_id);
    // save node ctrl and arch ctrl
    if (db_save_arch_ctrl(session, archived_end, node_id) != CT_SUCCESS) {
        CM_ABORT(0, "[arch_bk] ABORT INFO: save core control file failed when record archive log file %s for "
                     "start %u end %u node_id %u.",
                     file_name, node_ctrl->archived_start, node_ctrl->archived_end, node_id);
    }
    cm_close_device(type, &handle);
    return CT_SUCCESS;
}

status_t arch_dbs_ctrl_rebuild_parse_arch_file(knl_session_t *session, uint32 node_id, const char *arch_path)
{
    status_t status;
    uint32 dbid = session->kernel->db.ctrl.core.dbid;
    uint32 rst_id = session->kernel->db.ctrl.core.resetlogs.rst_id;
    arch_file_name_info_t file_name_info = {rst_id, 1, node_id, CT_FILE_NAME_BUFFER_SIZE,
                                            0, 0, NULL};
    uint32 *archive_asn = &file_name_info.asn;
    
    while (CT_TRUE) {
        char file_name[CT_FILE_NAME_BUFFER_SIZE] = {0};
        file_name_info.buf = file_name;
        if (*archive_asn == 1) {
            status = arch_find_first_archfile_rst(session, arch_path, dbid, &file_name_info);
        } else {
            status = arch_find_archive_asn_log_name(session, arch_path, dbid, &file_name_info);
        }
        if (status != CT_SUCCESS) {
            break;
        }

        if (arch_dbs_ctrl_rebuild_parse_arch_ctrl(session, file_name, node_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
        (*archive_asn)++;
    }
    return CT_SUCCESS;
}

status_t arch_handle_tmp_file(arch_proc_context_t *proc_ctx, uint32 node_id)
{
    knl_session_t *session = proc_ctx->session;
    device_type_t arch_file_type = cm_device_type(proc_ctx->arch_dest);
    log_file_t *logfile = &proc_ctx->logfile;
    arch_set_tmp_filename(proc_ctx->tmp_file_name, proc_ctx, node_id);
    CT_LOG_RUN_INF("[ARCH] handle tmp arch file %s", proc_ctx->tmp_file_name);
    if (arch_clear_tmp_file(arch_file_type, proc_ctx->tmp_file_name) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cm_create_device_retry_when_eexist(proc_ctx->tmp_file_name, arch_file_type,
                                           knl_io_flag(session), &proc_ctx->tmp_file_handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ARCH] failed to create temp archive log file %s", proc_ctx->tmp_file_name);
        return CT_ERROR;
    }

    if (cm_dbs_is_enable_dbs() == true) {
        if (arch_tmp_flush_head(arch_file_type, proc_ctx->tmp_file_name,
                                proc_ctx, logfile, proc_ctx->tmp_file_handle) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t arch_update_arch_ctrl(uint32 node_id)
{
    CT_LOG_RUN_INF("[ARCH] update node %u arch ctrl from device", node_id);
    knl_session_t *session = (knl_session_t *)g_rc_ctx->session;
    database_t *db = &session->kernel->db;
    cm_spin_lock(&db->ctrl_lock, NULL);
    uint32 count = CTRL_MAX_BUF_SIZE / sizeof(arch_ctrl_t);
    uint32 pages_per_inst = (CT_MAX_ARCH_NUM - 1) / count + 1;
    ctrl_page_t *pages = &db->ctrl.pages[db->ctrl.arch_segment + pages_per_inst * node_id];
    bool32 loaded = CT_FALSE;
    for (int i = 0; i < db->ctrlfiles.count; i++) {
        ctrlfile_t *ctrlfile = &db->ctrlfiles.items[i];
        int64 offset = (db->ctrl.arch_segment + pages_per_inst * node_id) * ctrlfile->block_size;
        if (cm_open_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[ARCH] failed to open ctrlfile[%d], filename[%s], instid[%u]",
                           i, ctrlfile->name, node_id);
            continue;
        }
        if (cm_read_device(ctrlfile->type, ctrlfile->handle, offset,
                           pages, pages_per_inst * ctrlfile->block_size) != CT_SUCCESS) {
            cm_close_device(ctrlfile->type, &ctrlfile->handle);
            CT_LOG_RUN_ERR("[ARCH] fail to read offline node arch ctrl from ctrlfile[%d], instid[%u]", i, node_id);
            continue;
        }
        CT_LOG_RUN_INF("[ARCH] succ to get offline node arch ctrl, ctrlfile[%d], instid[%u]", i, node_id);
        loaded = CT_TRUE;
        break;
    }
    if (!loaded) {
        CT_THROW_ERROR(ERR_LOAD_CONTROL_FILE, "no usable control file");
        cm_spin_unlock(&db->ctrl_lock);
        return CT_ERROR;
    }
    cm_spin_unlock(&db->ctrl_lock);
    return CT_SUCCESS;
}

void arch_proc_standby(thread_t *thread)
{
    arch_proc_context_t *proc_ctx = (arch_proc_context_t *)thread->argument;
    knl_session_t *session = proc_ctx->session;
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    uint64 sleep_time;
    g_arch_func[proc_ctx->data_type].proc_init_func(session, proc_ctx, &sleep_time);
    CT_LOG_RUN_INF("[ARCH_STANDBY] arch proc standby node %u thread run.", proc_ctx->arch_standby_node);
    cm_set_thread_name("arch_proc_standby");
    while (!thread->closed) {
        if (DB_NOT_READY(session) || !proc_ctx->enabled) {
            cm_sleep(200);
            continue;
        }
        if (g_arch_func[proc_ctx->data_type].need_archive_func(proc_ctx, redo_ctx)) {
            g_arch_func[proc_ctx->data_type].archive_func(session, proc_ctx);
        } else {
            if (arch_ctx->force_archive_param.force_archive == CT_TRUE &&
                proc_ctx->is_force_archive == CT_TRUE) {
                cm_spin_lock(&arch_ctx->dest_lock, NULL);
                arch_ctx->force_archive_param.force_archive = CT_FALSE;
                cm_spin_unlock(&arch_ctx->dest_lock);
                proc_ctx->is_force_archive = CT_FALSE;
            } else if (arch_ctx->force_archive_param.force_archive == CT_TRUE && // force arch trigger but not done arch
                       proc_ctx->is_force_archive == CT_FALSE) {
                continue;
            }
            cm_sleep(sleep_time);
        }

        g_arch_func[proc_ctx->data_type].arch_auto_clean_func(proc_ctx);
        arch_print_dtc_time_interval(&proc_ctx->check_time_interval_pitr);
    }
    CT_LOG_RUN_INF("[ARCH_STANDBY] arch proc standby node %u thread exit.", proc_ctx->arch_standby_node);
}

status_t arch_init_proc_ctx_standby(arch_proc_context_t *proc_ctx, uint32 node_id)
{
    CT_LOG_RUN_INF("[ARCH_STANDBY] init arch proc ctx params and resource, node id %u", node_id);
    knl_session_t *session = (knl_session_t *)g_rc_ctx->session;
    dtc_node_ctrl_t *node_ctrl = dtc_get_ctrl(session, node_id);
    log_file_t *logfile = &proc_ctx->logfile;
    logfile->handle = CT_INVALID_HANDLE;
    if (arch_open_logfile_dbstor(session, logfile, node_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (strcpy_s(proc_ctx->arch_dest, CT_FILE_NAME_BUFFER_SIZE,
                 session->kernel->arch_ctx.arch_proc[ARCH_DEFAULT_DEST - 1].arch_dest) != EOK) {
        CT_LOG_RUN_ERR("[ARCH_STANDBY] strcpy_s arch_dest failed, node id %u", node_id);
        return CT_ERROR;
    }
    proc_ctx->session = session;
    proc_ctx->arch_id = node_id;
    proc_ctx->last_archived_log_record.rst_id = session->kernel->db.ctrl.core.resetlogs.rst_id;
    proc_ctx->last_archived_log_record.offset = CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size);
    proc_ctx->write_failed = CT_FALSE;
    proc_ctx->read_failed = CT_FALSE;
    proc_ctx->enabled = CT_TRUE;
    proc_ctx->tmp_file_handle = CT_INVALID_HANDLE;
    proc_ctx->data_type = ARCH_DATA_TYPE_DBSTOR_STANDBY;
    proc_ctx->arch_standby_node = node_id;
    proc_ctx->force_archive_failed = CT_FALSE;
    proc_ctx->force_archive_trigger = CT_FALSE;
    
    uint32 arch_num = (node_ctrl->archived_end - node_ctrl->archived_start + CT_MAX_ARCH_NUM) % CT_MAX_ARCH_NUM;
    if (arch_num != 0) {
        arch_ctrl_t *arch_ctrl = db_get_arch_ctrl(session, node_ctrl->archived_end - 1, node_id);
        proc_ctx->last_archived_log_record.asn = arch_ctrl->asn + 1;
        proc_ctx->last_archived_log_record.start_lsn = arch_ctrl->end_lsn;
        proc_ctx->last_archived_log_record.end_lsn = arch_ctrl->end_lsn;
        proc_ctx->last_archived_log_record.cur_lsn = arch_ctrl->end_lsn;
        for (uint32 i = 0; i < arch_num; i++) {
            uint32 arch_locator = (node_ctrl->archived_start + i) % CT_MAX_ARCH_NUM;
            arch_ctrl = db_get_arch_ctrl(session, arch_locator, node_id);
            if (arch_ctrl->recid == 0) {
                CT_LOG_RUN_WAR("[ARCH] invalid recid %u, asn %u", arch_ctrl->recid, arch_ctrl->asn);
                continue;
            }
            proc_ctx->curr_arch_size += arch_get_ctrl_real_size(arch_ctrl);
        }
    } else {
        proc_ctx->last_archived_log_record.asn = 1;
    }
    CT_LOG_RUN_INF("[ARCH_STANDBY] cur arch num %u, next asn %u, next start lsn %llu", arch_num,
                   proc_ctx->last_archived_log_record.asn, proc_ctx->last_archived_log_record.end_lsn);
    return CT_SUCCESS;
}

void arch_deinit_proc_standby()
{
    cm_spin_lock(&g_arch_standby_ctx.arch_lock, NULL);
    CT_LOG_RUN_INF("[ARCH_STANDBY] release all archive proc ctx resource");
    for (uint32 idx = 0; idx < ARCH_MAX_NODE_COUNT; idx++) {
        arch_proc_context_t *arch_proc_ctx = &g_arch_standby_ctx.arch_proc_ctx[idx];
        if (arch_proc_ctx->enabled != CT_TRUE) {
            continue;
        }
        CT_LOG_RUN_INF("[ARCH_STANDBY] release proc ctx resource for node %u", idx);
        arch_proc_ctx->enabled = CT_FALSE;
        cm_close_thread(&arch_proc_ctx->read_thread);
        cm_close_thread(&arch_proc_ctx->write_thread);

        arch_release_rw_buf(&arch_proc_ctx->arch_rw_buf, "ARCH_STANDBY");

        if (arch_proc_ctx->tmp_file_name[0] != '\0' && arch_proc_ctx->tmp_file_handle != CT_INVALID_HANDLE) {
            cm_close_device(cm_device_type(arch_proc_ctx->tmp_file_name), &arch_proc_ctx->tmp_file_handle);
        }
        if (arch_proc_ctx->logfile.ctrl != NULL && arch_proc_ctx->logfile.handle != CT_INVALID_HANDLE) {
            cm_close_device(arch_proc_ctx->logfile.ctrl->type, &arch_proc_ctx->logfile.handle);
        }
        (void)memset_sp(arch_proc_ctx, sizeof(arch_proc_context_t), 0, sizeof(arch_proc_context_t));
    }
    g_arch_standby_ctx.enabled = CT_FALSE;
    cm_spin_unlock(&g_arch_standby_ctx.arch_lock);
    CT_LOG_RUN_INF("[ARCH_STANDBY] finish to release all archive proc ctx resource");
    return;
}

status_t arch_init_proc_standby_node(arch_proc_context_t *proc_ctx, uint32 node_id)
{
    if (arch_update_arch_ctrl(node_id) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (arch_init_proc_ctx_standby(proc_ctx, node_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    uint32 buffer_size = proc_ctx->session->kernel->attr.lgwr_buf_size;
    if (arch_init_rw_buf(&proc_ctx->arch_rw_buf, buffer_size * DBSTOR_ARCH_RW_BUF_NUM, "ARCH_STANDBY")
        != CT_SUCCESS) {
        return CT_ERROR;
    }

    proc_ctx->enabled = CT_TRUE;
    if (arch_handle_tmp_file(proc_ctx, node_id) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cm_create_thread(arch_proc_standby, 0, proc_ctx, &proc_ctx->read_thread) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cm_create_thread(arch_write_proc_all, 0, proc_ctx, &proc_ctx->write_thread) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t arch_init_proc_standby()
{
    knl_session_t *session = (knl_session_t *)g_rc_ctx->session;
    bool32 is_archive = session->kernel->arch_ctx.is_archive;
    CT_LOG_RUN_INF("[ARCH_STANDBY] is primary %d, is dbstor %d, is master %d, is changed %d, is archive %d", 
        knl_db_is_primary(session), cm_dbs_is_enable_dbs(), rc_is_master(),
        g_rc_ctx->info.master_changed, is_archive);
    if (knl_db_is_primary(session) || !cm_dbs_is_enable_dbs() || !is_archive) {
        CT_LOG_RUN_INF("[ARCH_STANDBY] db is primary or not dbstor, no need to init arch proc for other nodes");
        return CT_SUCCESS;
    }
    if (!rc_is_master() || (rc_is_master() && !g_rc_ctx->info.master_changed)) {
        CT_LOG_RUN_INF("[ARCH_STANDBY] not master changed, no need to init arch proc for other nodes");
        return CT_SUCCESS;
    }

    cm_spin_lock(&g_arch_standby_ctx.arch_lock, NULL);
    knl_panic_log(g_arch_standby_ctx.enabled == CT_FALSE, "standby arch proc ctx is already inited");
    CT_LOG_RUN_INF("[ARCH_STANDBY] start to init arch proc for all nodes");
    for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
        CT_LOG_RUN_INF("[ARCH_STANDBY] start to init arch proc for node %u", i);
        if (arch_init_proc_standby_node(&g_arch_standby_ctx.arch_proc_ctx[i], i) != CT_SUCCESS) {
            cm_spin_unlock(&g_arch_standby_ctx.arch_lock);
            CT_LOG_RUN_INF("[ARCH_STANDBY] failed to init arch proc for node %u", i);
            return CT_ERROR;
        }
    }
    g_arch_standby_ctx.enabled = CT_TRUE;
    cm_spin_unlock(&g_arch_standby_ctx.arch_lock);
    return CT_SUCCESS;
}

status_t arch_start_proc_primary(knl_session_t *session)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    arch_proc_context_t *proc_ctx = NULL;
    database_ctrl_t *ctrl = &session->kernel->db.ctrl;
    uint32 node_id = session->kernel->id;
    arch_ctx->is_archive = (ctrl->core.log_mode == ARCHIVE_LOG_ON);
    if (!arch_ctx->is_archive) {
        CT_LOG_RUN_INF("[ARCH] log archive function is disabled");
        return CT_SUCCESS;
    }
    
    proc_ctx = &arch_ctx->arch_proc[ARCH_DEFAULT_DEST - 1];
    proc_ctx->data_type = ARCH_DATA_TYPE_DBSTOR;
    if (arch_update_arch_ctrl(node_id) != CT_SUCCESS) {
        return CT_ERROR;
    }
    arch_init_arch_files_size(session, proc_ctx->arch_id - 1);
    arch_set_tmp_filename(proc_ctx->tmp_file_name, proc_ctx, node_id);
    device_type_t arch_file_type = cm_device_type(proc_ctx->arch_dest);
    if (arch_clear_tmp_file(arch_file_type, proc_ctx->tmp_file_name) != CT_SUCCESS) {
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[ARCH] node %u swtich role to pirmary, init arch proc.", node_id);
    if (proc_ctx != NULL && proc_ctx->arch_dest[0] != '\0' && proc_ctx->enabled) {
        if (arch_init_proc_resource(session, proc_ctx) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (arch_create_proc(proc_ctx) != CT_SUCCESS) {
            arch_release_proc_resource(proc_ctx);
            return CT_ERROR;
        }
        CT_LOG_RUN_INF("[ARCH] Start ARCH thread for ARCHIVE_DEST_%d[%s]", proc_ctx->arch_id, proc_ctx->arch_dest);
    }

    return CT_SUCCESS;
}