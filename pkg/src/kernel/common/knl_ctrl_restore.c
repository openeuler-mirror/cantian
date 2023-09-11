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
 * knl_ctrl_restore.c
 *
 *
 * IDENTIFICATION
 * src/kernel/common/knl_ctrl_restore.c
 *
 * -------------------------------------------------------------------------
 */

#include "knl_ctrl_restore.h"
#include "knl_context.h"
#include "dtc_database.h"

static void ctrl_restore_core_ctrl(knl_session_t *session, page_head_t *page, int handle)
{
    knl_instance_t *kernel = session->kernel;
    database_t *db = &kernel->db;
    core_ctrl_t *core = &db->ctrl.core;
    int64 offset = sizeof(page_head_t) + sizeof(datafile_header_t) + sizeof(datafile_ctrl_bk_t) +
        sizeof(space_ctrl_bk_t);

    static_core_ctrl_items_t *static_core = (static_core_ctrl_items_t *)((char *)page + offset);
    errno_t ret = memcpy_sp(core->name, GS_DB_NAME_LEN, static_core, GS_DB_NAME_LEN);
    knl_securec_check(ret);
    core->init_time = static_core->init_time;

    offset += sizeof(static_core_ctrl_items_t);
    sys_table_entries_t *sys_entries = (sys_table_entries_t *)((char *)page + offset);
    ret = memcpy_sp((char *)core + OFFSET_OF(core_ctrl_t, sys_table_entry), sizeof(sys_table_entries_t), sys_entries,
        sizeof(sys_table_entries_t));
    knl_securec_check(ret);
}

static void ctrl_restore_logfile_ctrl(knl_session_t *session, log_file_ctrl_t *logfile_ctrl,
    log_file_ctrl_bk_t *logfile_ctrl_bk, bool32 need_restore_name)
{
    if (need_restore_name) {
        errno_t ret = memcpy_sp(logfile_ctrl->name, GS_FILE_NAME_BUFFER_SIZE,
            logfile_ctrl_bk->name, GS_FILE_NAME_BUFFER_SIZE);
        knl_securec_check(ret);
    }
    logfile_ctrl->size = logfile_ctrl_bk->size;
    logfile_ctrl->hwm = logfile_ctrl_bk->hwm;
    logfile_ctrl->file_id = logfile_ctrl_bk->file_id;
    logfile_ctrl->seq = logfile_ctrl_bk->seq;
    logfile_ctrl->block_size = logfile_ctrl_bk->block_size;
    logfile_ctrl->flg = logfile_ctrl_bk->flg;
    logfile_ctrl->type = logfile_ctrl_bk->type;
    logfile_ctrl->status = logfile_ctrl_bk->status;
    logfile_ctrl->forward = logfile_ctrl_bk->forward;
    logfile_ctrl->backward = logfile_ctrl_bk->backward;
}

static status_t ctrl_rebuild_parse_logfile(knl_session_t *session, knl_device_def_t *device, uint32 *file_id)
{
    int32 handle = -1;
    uint32 asn = 0;
    char file_name[GS_MAX_FILE_NAME_LEN] = { 0 };
    database_t *db = &session->kernel->db;
    core_ctrl_t *core = &db->ctrl.core;

    CM_SAVE_STACK(session->stack);
    char *page_buf = (char *)cm_push(session->stack, GS_DFLT_LOG_BLOCK_SIZE + (uint32)GS_MAX_ALIGN_SIZE_4K);
    char *page = (char *)cm_aligned_buf(page_buf);

    (void)cm_text2str(&device->name, file_name, GS_MAX_FILE_NAME_LEN);
    device_type_t type = cm_device_type(file_name);
    if (cm_open_device(file_name, type, knl_io_flag(session), &handle) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (cm_read_device(type, handle, 0, page, GS_DFLT_LOG_BLOCK_SIZE) != GS_SUCCESS) {
        cm_close_device(type, &handle);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    log_file_head_t *log_head = (log_file_head_t *)page;
    if (log_head->last != GS_INVALID_ID64 && log_head->last > (knl_scn_t)dtc_my_ctrl(session)->scn) {
        cm_close_device(type, &handle);
        CM_RESTORE_STACK(session->stack);
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ", rebuild ctrlfile: the backup information on the datafile has expired");
        return GS_ERROR;
    }

    log_file_ctrl_bk_t *logfile_ctrl_bk = (log_file_ctrl_bk_t *)(page + sizeof(log_file_head_t));
    reset_log_t *reset_logs = (reset_log_t *)(page + sizeof(log_file_head_t) + sizeof(log_file_ctrl_bk_t));

    /* the is no backup info */
    if (logfile_ctrl_bk->version < CTRL_BACKUP_VERSION_REBUILD_CTRL) {
        GS_THROW_ERROR(ERR_NO_BKINFO_REBUILD_CTRL);
        cm_close_device(type, &handle);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    log_file_t *logfile = &MY_LOGFILE_SET(session)->items[logfile_ctrl_bk->file_id];
    ctrl_restore_logfile_ctrl(session, logfile->ctrl, logfile_ctrl_bk, GS_TRUE);
    *file_id = logfile->ctrl->file_id;

    /* restore reset logs, the latest info the one whose rst_id is the biggest */
    if (core->resetlogs.rst_id < reset_logs->rst_id) {
        core->resetlogs.rst_id = reset_logs->rst_id;
        core->resetlogs.last_asn = reset_logs->last_asn;
        core->resetlogs.last_lfn = reset_logs->last_lfn;
    }

    /* if the database down abnormally in function log_switch_file, maybe two log file's status is CURRENT,
     * but the new(also the right one) current file's asn is bigger than the old one */
    if (logfile->ctrl->status == LOG_FILE_CURRENT && asn < log_head->asn) {
        dtc_my_ctrl(session)->log_last = logfile->ctrl->file_id;
    }
    
    cm_close_device(type, &handle);
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

bool32 ctrl_formalize_logfile_ctrl(log_file_t *logfile)
{
    log_file_ctrl_t *ctrl = logfile->ctrl;
    if (((ctrl->type == DEV_TYPE_FILE && ctrl->size == cm_file_size(logfile->handle)) ||
        (ctrl->size == cm_device_size(cm_device_type(logfile->ctrl->name), logfile->handle))) &&
        (ctrl->block_size == FILE_BLOCK_SIZE_512 || ctrl->block_size == FILE_BLOCK_SIZE_4096)) {
        return GS_TRUE;
    }
    return GS_FALSE;
}

status_t ctrl_init_logfile_ctrl(knl_session_t *session, log_file_t *logfile)
{
    aligned_buf_t log_buf;
    logfile->handle = GS_INVALID_HANDLE;
    device_type_t type = cm_device_type(logfile->ctrl->name);

    if (cm_aligned_malloc((int64)GS_DFLT_LOG_BLOCK_SIZE, "log buffer", &log_buf) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)GS_DFLT_LOG_BLOCK_SIZE, "init logfile ctrl");
        return GS_ERROR;
    }

    /* cm_close_device in db_alter_archive_logfile */
    if (cm_open_device(logfile->ctrl->name, type, knl_io_flag(session), &logfile->handle) != GS_SUCCESS) {
        cm_aligned_free(&log_buf);
        return GS_ERROR;
    }

    if (cm_read_device(type, logfile->handle, 0, log_buf.aligned_buf, GS_DFLT_LOG_BLOCK_SIZE) != GS_SUCCESS) {
        cm_close_device(type, &logfile->handle);
        cm_aligned_free(&log_buf);
        return GS_ERROR;
    }

    log_file_ctrl_bk_t *logfile_ctrl_bk = (log_file_ctrl_bk_t *)(log_buf.aligned_buf + sizeof(log_file_head_t));
    ctrl_restore_logfile_ctrl(session, logfile->ctrl, logfile_ctrl_bk, GS_FALSE);
    cm_aligned_free(&log_buf);

    if (!ctrl_formalize_logfile_ctrl(logfile)) {
        cm_close_device(type, &logfile->handle);
        GS_THROW_ERROR_EX(ERR_INVALID_OPERATION, ", %s is not a redolog file", logfile->ctrl->name);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t ctrl_restore_space_ctrl(knl_session_t *session, char *page, int handle)
{
    knl_instance_t *kernel = session->kernel;
    database_t *db = &kernel->db;
    core_ctrl_t *core = &db->ctrl.core;
    int64 offset = sizeof(page_head_t) + sizeof(datafile_header_t) + sizeof(datafile_ctrl_bk_t);
    space_ctrl_bk_t *space_ctrl_bk = (space_ctrl_bk_t *)(page + offset);
    space_t *space = SPACE_GET(session, space_ctrl_bk->id);

    errno_t ret = memcpy_sp(space->ctrl, sizeof(space_ctrl_t), space_ctrl_bk, sizeof(space_ctrl_bk_t));
    knl_securec_check(ret);

    if (IS_DEFAULT_SPACE(space)) {
        if (IS_SYSTEM_SPACE(space)) {
            core->system_space = space->ctrl->id;
        }
        
        if (IS_SYSAUX_SPACE(space)) {
            core->sysaux_space = space->ctrl->id;
        }
        
        if (IS_TEMP_SPACE(space) && IS_SWAP_SPACE(space)) {
            dtc_my_ctrl(session)->swap_space = space->ctrl->id;
        }
        
        if (IS_UNDO_SPACE(space) && !IS_TEMP_SPACE(space)) {
            dtc_my_ctrl(session)->undo_space = space->ctrl->id;
        }
        
        if (IS_USER_SPACE(space) && !IS_TEMP_SPACE(space)) {
            core->user_space = space->ctrl->id;
        }
        
        if (IS_USER_SPACE(space) && IS_TEMP_SPACE(space)) {
            core->temp_space = space->ctrl->id;
        }
        
        if (IS_UNDO_SPACE(space) && IS_TEMP_SPACE(space)) {
            core->temp_undo_space = space->ctrl->id;
        }
    }

    /* some core ctrl info is backuped in system tablespace, restore them */
    if (IS_SYSTEM_SPACE(space)) {
        ctrl_restore_core_ctrl(session, (page_head_t *)page, handle);
    }

    return GS_SUCCESS;
}

static void ctrl_rebuild_restore_corelog(knl_session_t *session, char *page)
{
    core_ctrl_log_info_t *core_log = NULL;

    int64 offset = sizeof(page_head_t) + sizeof(datafile_header_t);
    datafile_ctrl_bk_t *datafile_ctrl_bk = (datafile_ctrl_bk_t *)(page + offset);

    if (datafile_ctrl_bk->file_no == 0) {
        offset += sizeof(datafile_ctrl_bk_t);
        space_ctrl_bk_t *space_ctrl_bk = (space_ctrl_bk_t *)(page + offset);
        if (space_ctrl_bk->type & SPACE_TYPE_SYSTEM) {
            offset += sizeof(space_ctrl_bk_t) + sizeof(static_core_ctrl_items_t) + sizeof(sys_table_entries_t);
        } else {
            offset += sizeof(space_ctrl_bk_t);
        }
    } else {
        offset += sizeof(datafile_ctrl_bk_t);
    }

    core_log = (core_ctrl_log_info_t *)(page + offset);
    if ((uint64)session->kernel->lsn < core_log->lsn) {
        session->kernel->lsn = core_log->lsn;
    }

    if ((uint64)session->kernel->lfn < core_log->lfn) {
        session->kernel->lfn = core_log->lfn;
    }

    if (log_cmp_point(&dtc_my_ctrl(session)->lrp_point, &core_log->lrp_point) < 0) {
        dtc_my_ctrl(session)->lrp_point = core_log->lrp_point;
    }

    if (log_cmp_point(&dtc_my_ctrl(session)->rcy_point, &core_log->rcy_point) < 0) {
        dtc_my_ctrl(session)->rcy_point = core_log->rcy_point;
    }

    if ((uint64)dtc_my_ctrl(session)->scn < core_log->scn) {
        dtc_my_ctrl(session)->scn = core_log->scn;
    }
}

static status_t ctrl_rebuild_parse_datafile(knl_session_t *session, knl_device_def_t *device)
{
    int32 handle = -1;
    char file_name[GS_MAX_FILE_NAME_LEN] = { 0 };
    core_ctrl_t *core = &session->kernel->db.ctrl.core;

    CM_SAVE_STACK(session->stack);
    char *page_buf = (char *)cm_push(session->stack, DEFAULT_PAGE_SIZE(session) + (uint32)GS_MAX_ALIGN_SIZE_4K);
    page_head_t *page = (page_head_t *)cm_aligned_buf(page_buf);

    (void)cm_text2str(&device->name, file_name, GS_MAX_FILE_NAME_LEN);
    device_type_t type = cm_device_type(file_name);
    if (cm_open_device(file_name, type, knl_io_flag(session), &handle) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (cm_read_device(type, handle, 0, page, session->kernel->attr.page_size) != GS_SUCCESS) {
        cm_close_device(type, &handle);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    datafile_ctrl_bk_t *datafile_ctrl_bk = (datafile_ctrl_bk_t *)((char *)page + sizeof(page_head_t) +
        sizeof(datafile_header_t));

    /* the is no backup info */
    if (datafile_ctrl_bk->version < CTRL_BACKUP_VERSION_REBUILD_CTRL) {
        GS_THROW_ERROR(ERR_NO_BKINFO_REBUILD_CTRL);
        cm_close_device(type, &handle);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (datafile_ctrl_bk->file_no == GS_INVALID_ID32) {    // datafile has been dropped
        cm_close_device(type, &handle);
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }

    ctrl_rebuild_restore_corelog(session, (char *)page);
    if (datafile_ctrl_bk->file_no == 0) {    // the file is the first one of space, restore space ctrl info.
        if (ctrl_restore_space_ctrl(session, (char *)page, handle) != GS_SUCCESS) {
            cm_close_device(type, &handle);
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
        
        core->space_count++;
    }

    /* restore datafile ctrl backup info */
    datafile_t *datafile = DATAFILE_GET(session, datafile_ctrl_bk->id);
    datafile_ctrl_t *datafile_ctrl = datafile->ctrl;
    errno_t ret = memcpy_sp(datafile_ctrl, sizeof(datafile_ctrl_t), &datafile_ctrl_bk->id, sizeof(datafile_ctrl_t));
    knl_securec_check(ret);
    space_t *space = SPACE_GET(session, datafile_ctrl_bk->space_id);
    space->ctrl->files[datafile_ctrl_bk->file_no] = datafile_ctrl_bk->id;
    cm_close_device(type, &handle);
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static void ctrl_rebuild_set_default(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    database_t *db = &kernel->db;
    core_ctrl_t *core = &db->ctrl.core;
    dtc_node_ctrl_t *node = dtc_my_ctrl(session);

    core->page_size = kernel->attr.page_size;
    core->undo_segments = kernel->attr.undo_segments;
    core->undo_segments_extended = GS_FALSE;
    core->max_column_count = kernel->attr.max_column_count;
    core->sysdata_version = CORE_SYSDATA_VERSION;
    core->version.main = CORE_VERSION_MAIN;
    core->version.major = CORE_VERSION_MAJOR;
    core->version.revision = CORE_VERSION_REVISION;
    core->version.inner = CORE_VERSION_INNER;
    core->open_count = 1;    // cannot be set to zero, because it will rebuild systables if it equal to 0
    node->ckpt_id = 0;
    node->dw_start = DW_DISTRICT_BEGIN(session->kernel->id);
    node->dw_end = DW_DISTRICT_END(session->kernel->id);
    core->build_completed = GS_TRUE;
    errno_t ret = memset_sp(core->archived_log, sizeof(arch_log_id_t) * GS_MAX_ARCH_DEST, 0,
        sizeof(arch_log_id_t) * GS_MAX_ARCH_DEST);
    knl_securec_check(ret);
    core->db_role = REPL_ROLE_PRIMARY;
    core->protect_mode = MAXIMUM_AVAILABILITY;
    node->archived_start = 0;
    node->archived_end = 0;
    node->shutdown_consistency = GS_FALSE;
    node->open_inconsistency = GS_FALSE;
    core->dw_file_id = 0;
    core->dw_area_pages = DOUBLE_WRITE_PAGES * core->node_count;
    core->resetlogs.rst_id = 0;
    core->resetlogs.last_asn = 0;
    core->resetlogs.last_lfn = 0;
}

static void ctrl_rebuild_restore_log_first(knl_session_t *session)
{
    log_file_t *log_file = NULL;
    uint32 log_first = dtc_my_ctrl(session)->log_last == 0 ? dtc_my_ctrl(session)->log_hwm - 1
                                                           : dtc_my_ctrl(session)->log_last - 1;

    while (log_first != dtc_my_ctrl(session)->log_last) {
        log_file = &MY_LOGFILE_SET(session)->items[log_first];
        if (LOG_IS_DROPPED(log_file->ctrl->flg)) {
            log_first = log_first == 0 ? dtc_my_ctrl(session)->log_hwm - 1 : log_first - 1;
            continue;
        }

        if (log_file->ctrl->status == LOG_FILE_INACTIVE) {
            break;
        }
        log_first = log_first == 0 ? dtc_my_ctrl(session)->log_hwm - 1 : log_first - 1;
    }

    /* if we not find a inactive log file, set log_first to the first active log file */
    if (log_first == dtc_my_ctrl(session)->log_last) {
        log_first = log_first == dtc_my_ctrl(session)->log_hwm - 1 ? 0 : log_first + 1;
        log_file = &MY_LOGFILE_SET(session)->items[log_first];
        while (LOG_IS_DROPPED(log_file->ctrl->flg)) {
            log_first = log_first == dtc_my_ctrl(session)->log_hwm - 1 ? 0 : log_first + 1;
            log_file = &MY_LOGFILE_SET(session)->items[log_first];
        }

        dtc_my_ctrl(session)->log_first = log_first;
    } else {
        dtc_my_ctrl(session)->log_first = log_first == dtc_my_ctrl(session)->log_hwm - 1 ? 0 : log_first + 1;
    }
}

static void ctrl_rebuild_init_doublewrite(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(session);

    space_t *dw_space = &(db->spaces[core_ctrl->sysaux_space]);

    db->ctrl.core.dw_file_id = dw_space->ctrl->files[0];
    db->ctrl.core.dw_area_pages = DOUBLE_WRITE_PAGES * core_ctrl->node_count;

    dtc_my_ctrl(session)->dw_start = DW_DISTRICT_BEGIN(session->kernel->id);
    dtc_my_ctrl(session)->dw_end = DW_DISTRICT_BEGIN(session->kernel->id);
}

static status_t ctrl_restore_charset(knl_session_t *session, knl_rebuild_ctrlfile_def_t *def)
{
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(session);

    if (def->charset.len == 0) {
        core_ctrl->charset_id = CHARSET_UTF8; // default UTF8
        return GS_SUCCESS;
    }
    
    uint16 charset_id = cm_get_charset_id_ex(&def->charset);
    if (charset_id == GS_INVALID_ID16) {
        core_ctrl->charset_id = CHARSET_UTF8;
        return GS_SUCCESS;
    }

    core_ctrl->charset_id = (uint32)charset_id;

    return GS_SUCCESS;
}

status_t ctrl_restore_ctrl_data(knl_session_t *session, knl_rebuild_ctrlfile_def_t *def)
{
    uint32 max_logfile_id = 0;
    uint32 logfile_id;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    core_ctrl_t *core = &db->ctrl.core;
    knl_device_def_t *device = NULL;

    core->dbid = dbc_generate_dbid(session);
    core->log_mode = def->arch_mode;

    ctrl_rebuild_set_default(session);

    /* set charset for database */
    if (ctrl_restore_charset(session, def) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    core->space_count = 0;
    for (uint32 i = 0; i < def->datafiles.count; i++) {
        device = (knl_device_def_t *)cm_galist_get(&def->datafiles, i);
        if (ctrl_rebuild_parse_datafile(session, device) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    for (uint32 i = 0; i < def->logfiles.count; i++) {
        device = (knl_device_def_t *)cm_galist_get(&def->logfiles, i);
        if (ctrl_rebuild_parse_logfile(session, device, &logfile_id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (max_logfile_id < logfile_id) {
            max_logfile_id = logfile_id;
        }
    }

    dtc_my_ctrl(session)->consistent_lfn = dtc_my_ctrl(session)->rcy_point.lfn;
    dtc_my_ctrl(session)->log_hwm = max_logfile_id + 1;

    /* set the hole logfile to be dropped */
    for (uint32 i = 0; i < dtc_my_ctrl(session)->log_hwm; i++) {
        log_file_t *logfile = &MY_LOGFILE_SET(session)->items[i];
        if (logfile->ctrl->name[0] == 0) {
            LOG_SET_DROPPED(logfile->ctrl->flg);
        }
    }

    ctrl_rebuild_restore_log_first(session);
    dtc_my_ctrl(session)->log_count = def->logfiles.count;
    core->device_count = def->datafiles.count;
    ctrl_rebuild_init_doublewrite(session);

    return GS_SUCCESS;
}

static void ctrl_fetch_ctrlfile_name(text_t *file_names, text_t *filename)
{
    if (!cm_fetch_text(file_names, ',', '\0', filename)) {
        return;
    }

    cm_trim_text(filename);
    if (filename->str[0] == '\'') {
        filename->str++;
        filename->len -= CM_SINGLE_QUOTE_LEN;

        cm_trim_text(filename);
    }
}

static status_t ctrl_recreate_ctrl_files(knl_session_t *session)
{
    text_t file_names;
    text_t file_name;
    uint32 count = 0;
    ctrlfile_t *ctrlfile = NULL;
    knl_instance_t *kernel = session->kernel;
    database_t *db = &kernel->db;
    char *param = cm_get_config_value(kernel->attr.config, "CONTROL_FILES");

    cm_str2text(param, &file_names);
    if (file_names.len == 0) {
        GS_THROW_ERROR(ERR_LOAD_CONTROL_FILE, "CONTROL_FILES is not set!");
        return GS_ERROR;
    }

    cm_remove_brackets(&file_names);
    ctrl_fetch_ctrlfile_name(&file_names, &file_name);
    while (file_name.len > 0) {
        ctrlfile = &db->ctrlfiles.items[count];
        (void)cm_text2str(&file_name, ctrlfile->name, GS_FILE_NAME_BUFFER_SIZE);
        ctrlfile->type = cm_device_type(ctrlfile->name);
        ctrlfile->blocks = CTRL_MAX_PAGES(session);
        ctrlfile->block_size = GS_DFLT_CTRL_BLOCK_SIZE;
        if (cm_build_device(ctrlfile->name, ctrlfile->type, kernel->attr.xpurpose_buf,
            GS_XPURPOSE_BUFFER_SIZE, (int64)ctrlfile->blocks * ctrlfile->block_size, knl_io_flag(session),
            GS_FALSE, &ctrlfile->handle) != GS_SUCCESS) {
            return GS_ERROR;
        }
        
        count++;
        ctrl_fetch_ctrlfile_name(&file_names, &file_name);
    }

    db->ctrlfiles.count = count;
    return GS_SUCCESS;
}

static void ctrl_init_ctrl_page(knl_session_t *session)
{
    page_id_t page_id;
    page_head_t *head = NULL;
    page_tail_t *tail = NULL;
    knl_instance_t *kernel = session->kernel;
    database_t *db = &kernel->db;

    /* init page for every ctrl buf page */
    for (uint32 i = 0; i < CTRL_MAX_PAGES(session); i++) {
        page_id.file = 0;
        page_id.page = 1;

        head = (page_head_t *)(db->ctrl.pages + i);
        TO_PAGID_DATA(page_id, head->id);
        TO_PAGID_DATA(INVALID_PAGID, head->next_ext);
        head->size_units = page_size_units(GS_DFLT_CTRL_BLOCK_SIZE);
        head->type = PAGE_TYPE_CTRL;
        tail = PAGE_TAIL(head);
        tail->pcn = 0;
    }
}

status_t ctrl_rebuild_ctrl_files(knl_session_t *session, knl_rebuild_ctrlfile_def_t *def)
{
    ctrlfile_t *ctrlfile = NULL;
    knl_instance_t *kernel = session->kernel;
    database_t *db = &kernel->db;
    core_ctrl_t *core = (core_ctrl_t *)db->ctrl.pages[CORE_CTRL_PAGE_ID].buf;

    /* rebuild control files can only be done in nomount status */
    if (db->status != DB_STATUS_NOMOUNT) {
        GS_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "rebuild control files not in nomount status");
        return GS_ERROR;
    }
    
    /* create empty ctrl files */
    if (ctrl_recreate_ctrl_files(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /* restore core data in memory */
    if (ctrl_restore_ctrl_data(session, def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    ctrl_init_ctrl_page(session);
    *core = db->ctrl.core;

    /* write ctrl data into ctrl files */
    for (uint32 i = 0; i < db->ctrlfiles.count; i++) {
        ctrlfile = &db->ctrlfiles.items[i];
        if (cm_open_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (cm_write_device(ctrlfile->type, ctrlfile->handle, 0, db->ctrl.pages,
            (int32)ctrlfile->blocks * ctrlfile->block_size) != GS_SUCCESS) {
            cm_close_device(ctrlfile->type, &ctrlfile->handle);
            return GS_ERROR;
        }

        if (db_fdatasync_file(session, ctrlfile->handle) != GS_SUCCESS) {
            cm_close_device(ctrlfile->type, &ctrlfile->handle);
            return GS_ERROR;
        }

        cm_close_device(ctrlfile->type, &ctrlfile->handle);
    }

    return GS_SUCCESS;
}

status_t ctrl_backup_static_core_items(knl_session_t *session, static_core_ctrl_items_t *items)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    space_t *space = SPACE_GET(session, db->ctrl.core.system_space);
    datafile_t *datafile = &db->datafiles[space->ctrl->files[0]];
    
    if (cm_open_device(datafile->ctrl->name, datafile->ctrl->type, knl_io_flag(session),
        DATAFILE_FD(session, datafile->ctrl->id)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    char *page_buf = (char *)cm_push(session->stack, (uint32)datafile->ctrl->block_size + (uint32)GS_MAX_ALIGN_SIZE_4K);
    page_head_t *page = (page_head_t *)cm_aligned_buf(page_buf);
    
    int64 offset = 0;
    if (cm_read_device(datafile->ctrl->type, session->datafiles[datafile->ctrl->id], offset, page,
        datafile->ctrl->block_size) != GS_SUCCESS) {
        cm_close_device(datafile->ctrl->type, &session->datafiles[datafile->ctrl->id]);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    offset = sizeof(page_head_t) + sizeof(datafile_header_t) + sizeof(datafile_ctrl_bk_t) + sizeof(space_ctrl_bk_t);
    errno_t ret = memcpy_sp((char *)page + offset, sizeof(static_core_ctrl_items_t), items,
        sizeof(static_core_ctrl_items_t));
    knl_securec_check(ret);

    offset = 0;
    if (cm_write_device(datafile->ctrl->type, session->datafiles[datafile->ctrl->id], offset, page,
        datafile->ctrl->block_size) != GS_SUCCESS) {
        cm_close_device(datafile->ctrl->type, &session->datafiles[datafile->ctrl->id]);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_fdatasync_file(session, session->datafiles[datafile->ctrl->id]) != GS_SUCCESS) {
        cm_close_device(datafile->ctrl->type, &session->datafiles[datafile->ctrl->id]);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    cm_close_device(datafile->ctrl->type, &session->datafiles[datafile->ctrl->id]);
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t ctrl_backup_sys_entries(knl_session_t *session, sys_table_entries_t *entries)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    space_t *space = SPACE_GET(session, db->ctrl.core.system_space);
    datafile_t *datafile = &db->datafiles[space->ctrl->files[0]];
    
    if (cm_open_device(datafile->ctrl->name, datafile->ctrl->type, knl_io_flag(session),
        DATAFILE_FD(session, datafile->ctrl->id)) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    CM_SAVE_STACK(session->stack);
    char *page_buf = (char *)cm_push(session->stack, (uint32)datafile->ctrl->block_size + (uint32)GS_MAX_ALIGN_SIZE_4K);
    page_head_t *page = (page_head_t *)cm_aligned_buf(page_buf);
    
    int64 offset = 0;
    if (cm_read_device(datafile->ctrl->type, session->datafiles[datafile->ctrl->id], offset, page,
        datafile->ctrl->block_size) != GS_SUCCESS) {
        cm_close_device(datafile->ctrl->type, &session->datafiles[datafile->ctrl->id]);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    
    offset = sizeof(page_head_t) + sizeof(datafile_header_t) + sizeof(datafile_ctrl_bk_t) + sizeof(space_ctrl_bk_t) +
        sizeof(static_core_ctrl_items_t);
    errno_t ret = memcpy_sp((char *)page + offset, sizeof(sys_table_entries_t), entries, sizeof(sys_table_entries_t));
    knl_securec_check(ret);
    
    offset = 0;
    if (cm_write_device(datafile->ctrl->type, session->datafiles[datafile->ctrl->id], offset, page,
        datafile->ctrl->block_size) != GS_SUCCESS) {
        cm_close_device(datafile->ctrl->type, &session->datafiles[datafile->ctrl->id]);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_fdatasync_file(session, session->datafiles[datafile->ctrl->id]) != GS_SUCCESS) {
        cm_close_device(datafile->ctrl->type, &session->datafiles[datafile->ctrl->id]);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    
    cm_close_device(datafile->ctrl->type, &session->datafiles[datafile->ctrl->id]);
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static void ctrl_generate_logctrl_backup(knl_session_t *session, log_file_ctrl_t *ctrl_info,
    log_file_ctrl_bk_t *backup_info)
{
    backup_info->version = CTRL_BACKUP_VERSION_REBUILD_CTRL;
    errno_t ret = memcpy_sp(backup_info->name, GS_FILE_NAME_BUFFER_SIZE, ctrl_info->name, strlen(ctrl_info->name));
    knl_securec_check(ret);
    
    backup_info->size = ctrl_info->size;
    backup_info->hwm = ctrl_info->hwm;
    backup_info->file_id = ctrl_info->file_id;
    backup_info->seq = ctrl_info->seq;
    backup_info->block_size = ctrl_info->block_size;
    backup_info->flg = ctrl_info->flg;
    backup_info->type = ctrl_info->type;
    backup_info->status = ctrl_info->status;
    backup_info->forward = ctrl_info->forward;
    backup_info->backward = ctrl_info->backward;
}

static status_t ctrl_backup_write_datafile(knl_session_t *session, datafile_t *datafile, int64 offset, const void *buf,
    uint32 length)
{
    CM_SAVE_STACK(session->stack);
    char *page_buf = (char *)cm_push(session->stack, session->kernel->attr.page_size + (uint32)GS_MAX_ALIGN_SIZE_4K);
    page_head_t *page = (page_head_t *)cm_aligned_buf(page_buf);
    
    if (cm_open_device(datafile->ctrl->name, datafile->ctrl->type, knl_io_flag(session),
        DATAFILE_FD(session, datafile->ctrl->id)) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (cm_read_device(datafile->ctrl->type, session->datafiles[datafile->ctrl->id], 0, page,
        datafile->ctrl->block_size) != GS_SUCCESS) {
        cm_close_device(datafile->ctrl->type, &session->datafiles[datafile->ctrl->id]);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    errno_t ret = memcpy_sp((char *)page + offset, length, buf, length);
    knl_securec_check(ret);

    if (cm_write_device(datafile->ctrl->type, session->datafiles[datafile->ctrl->id], 0, page,
        datafile->ctrl->block_size) != GS_SUCCESS) {
        cm_close_device(datafile->ctrl->type, &session->datafiles[datafile->ctrl->id]);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_fdatasync_file(session, session->datafiles[datafile->ctrl->id]) != GS_SUCCESS) {
        cm_close_device(datafile->ctrl->type, &session->datafiles[datafile->ctrl->id]);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    cm_close_device(datafile->ctrl->type, &session->datafiles[datafile->ctrl->id]);
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static void ctrl_get_core_log_info(knl_session_t *session, core_ctrl_log_info_t *log_info)
{
    log_info->lrp_point = dtc_my_ctrl(session)->lrp_point;
    log_info->rcy_point = dtc_my_ctrl(session)->rcy_point;
    log_info->lfn = dtc_my_ctrl(session)->lfn;
    log_info->lsn = dtc_my_ctrl(session)->lsn;
    log_info->scn = dtc_my_ctrl(session)->scn;
}

status_t ctrl_backup_core_log_info(knl_session_t *session)
{
    int64 offset = 0;
    knl_instance_t *kernel = session->kernel;
    database_t *db = &kernel->db;
    datafile_t *datafile = NULL;
    space_t *space = NULL;
    core_ctrl_log_info_t log_info;

    if (DB_ATTR_CLUSTER(session) || CTRL_LOG_BACKUP_LEVEL(session) == CTRLLOG_BACKUP_LEVEL_NONE) {
        return GS_SUCCESS;
    }

    ctrl_get_core_log_info(session, &log_info);
    if (CTRL_LOG_BACKUP_LEVEL(session) == CTRLLOG_BACKUP_LEVEL_TYPICAL) {
        datafile = &db->datafiles[0];
        space = &db->spaces[datafile->space_id];
        knl_panic(IS_SYSTEM_SPACE(space));
        offset = sizeof(page_head_t) + sizeof(datafile_header_t) + sizeof(datafile_ctrl_bk_t) +
            sizeof(space_ctrl_bk_t) + sizeof(static_core_ctrl_items_t) + sizeof(sys_table_entries_t);
        if (ctrl_backup_write_datafile(session, datafile, offset, (const void *)&log_info,
            sizeof(log_info)) != GS_SUCCESS) {
            return GS_ERROR;
        }

        return GS_SUCCESS;
    }
    
    for (uint32 i = 0; i < GS_MAX_DATA_FILES; i++) {
        datafile = &db->datafiles[i];
    
        /* if datafile is not used or has been removed or is offline, handle next datafile */
        if (DF_FILENO_IS_INVAILD(datafile) || !datafile->ctrl->used || DATAFILE_IS_ALARMED(datafile) ||
            !DATAFILE_IS_ONLINE(datafile)) {
            continue;
        }

        space = &db->spaces[datafile->space_id];
        if (datafile->ctrl->id == space->ctrl->files[0]) {
            if (IS_SYSTEM_SPACE(space)) {
                offset = sizeof(page_head_t) + sizeof(datafile_header_t) + sizeof(datafile_ctrl_bk_t) +
                    sizeof(space_ctrl_bk_t) + sizeof(static_core_ctrl_items_t) + sizeof(sys_table_entries_t);
            } else {
                offset = sizeof(page_head_t) + sizeof(datafile_header_t) + sizeof(datafile_ctrl_bk_t) +
                    sizeof(space_ctrl_bk_t);
            }
        } else {
            offset = sizeof(page_head_t) + sizeof(datafile_header_t) + sizeof(datafile_ctrl_bk_t);
        }

        if (ctrl_backup_write_datafile(session, datafile, offset, (const void *)&log_info, sizeof(log_info)) !=
            GS_SUCCESS) {
            continue;
        }
    }

    return GS_SUCCESS;
}

status_t ctrl_backup_log_ctrl(knl_session_t *session, uint32 id)
{
    log_file_t *log_file = &MY_LOGFILE_SET(session)->items[id];

    /* if log file has been dropped, return success */
    if (LOG_IS_DROPPED(log_file->ctrl->flg)) {
        return GS_SUCCESS;
    }
    if (log_file->ctrl->type == DEV_TYPE_ULOG) {
        GS_LOG_RUN_INF("logfile(%s) need NOT backup ctrl.", log_file->ctrl->name);
        return GS_SUCCESS;
    }
    if (cm_open_device(log_file->ctrl->name, log_file->ctrl->type, knl_redo_io_flag(session),
        &log_file->handle) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    CM_SAVE_STACK(session->stack);
    char *page_buf = (char *)cm_push(session->stack, (uint32)log_file->ctrl->block_size + (uint32)GS_MAX_ALIGN_SIZE_4K);
    char *page = (char *)cm_aligned_buf(page_buf);
    
    if (cm_read_device(log_file->ctrl->type, log_file->handle, 0, page, log_file->ctrl->block_size) != GS_SUCCESS) {
        cm_close_device(log_file->ctrl->type, &log_file->handle);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    log_file_ctrl_bk_t *ctrl_bk = (log_file_ctrl_bk_t *)(page + sizeof(log_file_head_t));
    ctrl_generate_logctrl_backup(session, log_file->ctrl, ctrl_bk);

    if (cm_write_device(log_file->ctrl->type, log_file->handle, 0, page, log_file->ctrl->block_size) != GS_SUCCESS) {
        cm_close_device(log_file->ctrl->type, &log_file->handle);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_fdatasync_file(session, log_file->handle) != GS_SUCCESS) {
        cm_close_device(log_file->ctrl->type, &log_file->handle);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t ctrl_backup_reset_logs(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    database_t *db = &kernel->db;
    core_ctrl_t *core = &db->ctrl.core;
    log_context_t *log = &session->kernel->redo_ctx;
    log_file_t *log_file = &MY_LOGFILE_SET(session)->items[log->curr_file];

    if (cm_open_device(log_file->ctrl->name, log_file->ctrl->type, knl_redo_io_flag(session),
        &log_file->handle) != GS_SUCCESS) {
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    char *page_buf = (char *)cm_push(session->stack, (uint32)log_file->ctrl->block_size + (uint32)GS_MAX_ALIGN_SIZE_4K);
    char *page = (char *)cm_aligned_buf(page_buf);
    
    if (cm_read_device(log_file->ctrl->type, log_file->handle, 0, page, log_file->ctrl->block_size) != GS_SUCCESS) {
        cm_close_device(log_file->ctrl->type, &log_file->handle);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    int64 offset = sizeof(log_file_head_t) + sizeof(log_file_ctrl_bk_t);
    reset_log_t *reset_logs = (reset_log_t *)(page + offset);
    reset_logs->rst_id = core->resetlogs.rst_id;
    reset_logs->last_asn = core->resetlogs.last_asn;
    reset_logs->last_lfn = core->resetlogs.last_lfn;

    if (cm_write_device(log_file->ctrl->type, log_file->handle, 0, page, log_file->ctrl->block_size) != GS_SUCCESS) {
        cm_close_device(log_file->ctrl->type, &log_file->handle);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_fdatasync_file(session, log_file->handle) != GS_SUCCESS) {
        cm_close_device(log_file->ctrl->type, &log_file->handle);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t ctrl_backup_space_ctrl(knl_session_t *session, uint32 space_id)
{
    knl_instance_t *kernel = session->kernel;
    database_t *db = &kernel->db;

    knl_panic(!DAAC_REPLAY_NODE(session));

    /* when the primary node redo the rd_spc_create_space log entry, it's no need to backup sapce ctrl info. */
    if (db->ctrl.core.db_role == REPL_ROLE_PRIMARY && db->status == DB_STATUS_RECOVERY) {
        return GS_SUCCESS;
    }
    
    knl_panic(space_id < GS_MAX_SPACES);
    space_t *space = SPACE_GET(session, space_id);
    if (!space->ctrl->used || !SPACE_IS_ONLINE(space)) {    // if space has been dropped, return success
        return GS_SUCCESS;
    }

    if (space->ctrl->files[0] == GS_INVALID_ID32) {    // the datafile has not been created.
        return GS_SUCCESS;
    }
    
    datafile_t *datafile = &db->datafiles[space->ctrl->files[0]];
    
    /* if datafile is not used or has been removed or is offline, return success */
    if (!datafile->ctrl->used || DATAFILE_IS_ALARMED(datafile) || !DATAFILE_IS_ONLINE(datafile)) {
        return GS_SUCCESS;
    }
    
    int64 offset = sizeof(page_head_t) + sizeof(datafile_header_t) + sizeof(datafile_ctrl_bk_t);
    if (ctrl_backup_write_datafile(session, datafile, offset, (const void *)space->ctrl,
        OFFSET_OF(space_ctrl_t, files)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t ctrl_backup_datafile_ctrl(knl_session_t *session, uint32 file_id)
{
    knl_instance_t *kernel = session->kernel;
    database_t *db = &kernel->db;
    datafile_ctrl_bk_t df_ctrl_bk;

    /* when the primary node redo the rd_spc_create_datafile log entry, it's no need to backup datafile ctrl info */
    if (db->ctrl.core.db_role == REPL_ROLE_PRIMARY && db->status == DB_STATUS_RECOVERY) {
        return GS_SUCCESS;
    }

    knl_panic(file_id < GS_MAX_DATA_FILES);
    datafile_t *datafile = DATAFILE_GET(session, file_id);

    /* if datafile is not used or has been removed or is offline, return success */
    if (!datafile->ctrl->used || DATAFILE_IS_ALARMED(datafile) || !DATAFILE_IS_ONLINE(datafile)) {
        return GS_SUCCESS;
    }

    errno_t ret = memset_sp(&df_ctrl_bk, sizeof(datafile_ctrl_bk_t), 0, sizeof(datafile_ctrl_bk_t));
    knl_securec_check(ret);

    df_ctrl_bk.version = CTRL_BACKUP_VERSION_REBUILD_CTRL;
    ret = memcpy_sp(&df_ctrl_bk.id, sizeof(datafile_ctrl_t), datafile->ctrl, sizeof(datafile_ctrl_t));
    knl_securec_check(ret);
    df_ctrl_bk.file_no = datafile->file_no;
    df_ctrl_bk.space_id = datafile->space_id;
    
    int64 offset = sizeof(page_head_t) + sizeof(datafile_header_t);
    if (ctrl_backup_write_datafile(session, datafile, offset, (const void *)&df_ctrl_bk, sizeof(datafile_ctrl_bk_t)) !=
        GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t ctrl_backup_ctrl_info(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    database_t *db = &kernel->db;

    /* backup static core info */
    static_core_ctrl_items_t *core_ctrl_backup = (static_core_ctrl_items_t *)((char *)&kernel->db.ctrl.core +
        OFFSET_OF(core_ctrl_t, name));
    if (ctrl_backup_static_core_items(session, core_ctrl_backup) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /* backup system table entries of core ctrl */
    sys_table_entries_t *system_entry = (sys_table_entries_t *)((char *)&db->ctrl.core +
        OFFSET_OF(core_ctrl_t, sys_table_entry));
    if (ctrl_backup_sys_entries(session, system_entry) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /* backup log ctrl info */
    for (uint32 i = 0; i < MY_LOGFILE_SET(session)->logfile_hwm; i++) {
        log_file_t *logfile = &MY_LOGFILE_SET(session)->items[i];
        if (LOG_IS_DROPPED(logfile->ctrl->flg)) {
            continue;
        }

        if (ctrl_backup_log_ctrl(session, i) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    /* backup space ctrl info */
    for (uint32 i = 0; i < GS_MAX_SPACES; i++) {
        space_t *space = &db->spaces[i];
        if (space->ctrl->file_hwm == 0) {
            continue;
        }

        if (!SPACE_IS_ONLINE(space)) {
            continue;
        }

        if (ctrl_backup_space_ctrl(session, space->ctrl->id) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    /* backup datafile ctrl info */
    for (uint32 i = 0; i < GS_MAX_DATA_FILES; i++) {
        datafile_t *datafile = DATAFILE_GET(session, i);
        if (!datafile->ctrl->used || !DATAFILE_IS_ONLINE(datafile)) {
            continue;
        }

        if (ctrl_backup_datafile_ctrl(session, i) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}
