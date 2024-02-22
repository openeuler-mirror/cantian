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
 * knl_db_create.c
 *
 *
 * IDENTIFICATION
 * src/kernel/knl_db_create.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_common_module.h"
#include "knl_db_create.h"
#include "knl_database.h"
#include "knl_context.h"
#include "knl_user.h"
#include "knl_ctlg.h"
#include "knl_create_space.h"
#include "dtc_database.h"
#include "cm_dbs_intf.h"
#include "ct_tbox.h"
#include "cm_file_iofence.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_dbname_time {
    char name[CT_DB_NAME_LEN];
    date_t time;
} dbname_time_t;

static void dbc_init_archivelog(knl_session_t *session, knl_database_def_t *def)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;

    db->ctrl.core.log_mode = def->arch_mode;
}

static void dbc_init_dbid(knl_session_t *session, knl_database_def_t *def)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    (void)cm_text2str(&def->name, db->ctrl.core.name, CT_DB_NAME_LEN);
    db->ctrl.core.dbid = dbc_generate_dbid(session);
}

void dbc_init_scn(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    timeval_t now;

    (void)cm_gettimeofday(&now);
    db->ctrl.core.init_time = now.tv_sec;

    KNL_SET_SCN(&session->kernel->scn, 0);
}

static status_t dbc_save_sys_password(knl_session_t *session, knl_database_def_t *def)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    char *alg = kernel->attr.pwd_alg;
    char *sys_pwd = kernel->attr.sys_pwd;
    errno_t ret;

    if (strlen(def->sys_password) != 0) {
        if (user_encrypt_password(alg, kernel->attr.alg_iter, def->sys_password, (uint32)strlen(def->sys_password),
            sys_pwd, CT_PASSWORD_BUFFER_SIZE) != CT_SUCCESS) {
            ret = memset_sp(def->sys_password, CT_PASSWORD_BUFFER_SIZE, 0, CT_PASSWORD_BUFFER_SIZE);
            knl_securec_check(ret);
            return CT_ERROR;
        }

        ret = memset_sp(def->sys_password, CT_PASSWORD_BUFFER_SIZE, 0, CT_PASSWORD_BUFFER_SIZE);
        knl_securec_check(ret);
        return CT_SUCCESS;
    }

    return CT_SUCCESS;
}

static status_t dbc_save_charset(knl_session_t *session, knl_database_def_t *def)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    uint16 charset_id;

    if (def->charset.len == 0) {
        kernel->db.ctrl.core.charset_id = CHARSET_UTF8; // default UTF8
        return CT_SUCCESS;
    }
    charset_id = cm_get_charset_id_ex(&def->charset);
    if (charset_id == CT_INVALID_ID16) {
        /* not check at 'sql_parse_dbca_charset' */
        CT_LOG_RUN_WAR("[DB] invaid charaset %s, reset to UTF8.", T2S(&def->charset));
        kernel->db.ctrl.core.charset_id = CHARSET_UTF8;
        return CT_SUCCESS;
    }

    kernel->db.ctrl.core.charset_id = (uint32)charset_id;

    return CT_SUCCESS;
}

static void dbc_ctrl_page_init(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    page_tail_t *tail = NULL;
    page_id_t page_id;
    uint32 i;
    page_head_t *page = NULL;

    for (i = 0; i < CTRL_MAX_PAGES(session); i++) {
        page_id.file = 0;
        page_id.page = 1;
        page = (page_head_t *)(db->ctrl.pages + i);

        TO_PAGID_DATA(page_id, page->id);
        TO_PAGID_DATA(INVALID_PAGID, page->next_ext);
        page->size_units = page_size_units(CT_DFLT_CTRL_BLOCK_SIZE);
        page->type = PAGE_TYPE_CTRL;
        tail = PAGE_TAIL(page);
        tail->pcn = 0;
    }
}

static void dbc_ctrl_file_init(knl_session_t *session, knl_database_def_t *def)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    uint32 node_count = def->nodes.count;
    dbc_ctrl_page_init(session);
    db->ctrlfiles.count = def->ctrlfiles.count;
    db->ctrl.core.resetlogs.rst_id = 0;
    db->ctrl.core.undo_segments = kernel->attr.undo_segments;
    db->ctrl.core.undo_segments_extended = CT_FALSE;
    db->ctrl.core.page_size = kernel->attr.page_size;
    db->ctrl.core.max_column_count = kernel->attr.max_column_count;
    db->ctrl.core.clustered = kernel->attr.clustered;
    db->ctrl.core.node_count = node_count;
    db_get_cantiand_version(&(db->ctrl.core.version));
    db->ctrl.core.version.inner = CORE_VERSION_INNER;
    db->ctrl.core.sysdata_version = CORE_SYSDATA_VERSION;
}

static status_t dbc_build_ctrlfiles(knl_session_t *session, knl_database_def_t *def)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;

    dbc_ctrl_page_init(session);
    dbc_ctrl_file_init(session, def);
    db_store_core(db);

    for (uint32 i = 0; i < def->ctrlfiles.count; i++) {
        ctrlfile_t *ctrlfile = &db->ctrlfiles.items[i];
        text_t *name = (text_t *)cm_galist_get(&def->ctrlfiles, i);

        (void)cm_text2str(name, ctrlfile->name, CT_FILE_NAME_BUFFER_SIZE);
        ctrlfile->type = cm_device_type(ctrlfile->name);
        ctrlfile->blocks = kernel->attr.clustered ? CTRL_MAX_PAGES_CLUSTERED : CTRL_MAX_PAGES_NONCLUSTERED;
        ctrlfile->block_size = CT_DFLT_CTRL_BLOCK_SIZE;
        uint32 flags = (ctrlfile->type == DEV_TYPE_PGPOOL ? 0xFFFFFFFF : knl_io_flag(session));
        if (cm_build_device(ctrlfile->name, ctrlfile->type, kernel->attr.xpurpose_buf,
            CT_XPURPOSE_BUFFER_SIZE, (int64)ctrlfile->blocks * ctrlfile->block_size,
            flags, CT_FALSE, &ctrlfile->handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to build %s ", ctrlfile->name);
            return CT_ERROR;
        }
        /* ctrlfile can be opened for a long time, closed in db_close_ctrl_files */
        if (cm_open_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to open %s ", ctrlfile->name);
            return CT_ERROR;
        }

        if (cm_write_device(ctrlfile->type, ctrlfile->handle, 0, db->ctrl.pages,
            (int32)ctrlfile->blocks * ctrlfile->block_size) != CT_SUCCESS) {
            cm_close_device(ctrlfile->type, &ctrlfile->handle);
            CT_LOG_RUN_ERR("[DB] failed to write %s ", ctrlfile->name);
            return CT_ERROR;
        }

        if (db_fdatasync_file(session, ctrlfile->handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to fdatasync datafile %s", ctrlfile->name);
            cm_close_device(ctrlfile->type, &ctrlfile->handle);
            return CT_ERROR;
        }

        cm_close_device(ctrlfile->type, &ctrlfile->handle);
    }

    return CT_SUCCESS;
}

status_t dbc_build_logfiles(knl_session_t *session, galist_t *logfiles, uint8 node_id)
{
    uint32 i;
    int64 min_size;
    int64 block_num;
    knl_device_def_t *dev_def = NULL;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    int64 temp_size = 0;
    dtc_node_ctrl_t *ctrl = dtc_get_ctrl(session, node_id);

    ctrl->log_count = logfiles->count;
    ctrl->log_hwm = logfiles->count;
    ctrl->rcy_point.asn = CT_FIRST_ASN;
    ctrl->lrp_point.asn = CT_FIRST_ASN;

    min_size = (int64)LOG_MIN_SIZE(session, kernel);

    if (DB_IS_RAFT_ENABLED(kernel)) {
        for (i = 0; i < logfiles->count; i++) {
            dev_def = (knl_device_def_t *)cm_galist_get(logfiles, i);
            temp_size = (temp_size == 0) ? dev_def->size : temp_size;
            if (dev_def->size != temp_size) {
                CT_THROW_ERROR(ERR_LOG_SIZE_NOT_MATCH);
                return CT_ERROR;
            }
        }
    }

    for (i = 0; i < logfiles->count; i++) {
        dev_def = (knl_device_def_t *)cm_galist_get(logfiles, i);
        if (dev_def->size <= min_size) {
            CT_THROW_ERROR(ERR_LOG_FILE_SIZE_TOO_SMALL, min_size);
            return CT_ERROR;
        }

        log_file_t logfile;
        logfile.ctrl = (log_file_ctrl_t *)db_get_log_ctrl_item(db->ctrl.pages, i, sizeof(log_file_ctrl_t),
                                                               db->ctrl.log_segment, node_id);
        logfile.ctrl->file_id = (int32)i;
        logfile.ctrl->node_id = node_id;
        logfile.ctrl->size = dev_def->size;
        (void)cm_text2str(&dev_def->name, logfile.ctrl->name, CT_FILE_NAME_BUFFER_SIZE);
        logfile.ctrl->type = cm_device_type(logfile.ctrl->name);
        logfile.ctrl->block_size = dev_def->block_size == 0 ? CT_DFLT_LOG_BLOCK_SIZE : (uint16)dev_def->block_size;
        /* Ignore the entered size parameter, the default size of the ULOG is the same as that defined by the DBStor. */
        if (logfile.ctrl->type == DEV_TYPE_ULOG &&
            cm_device_capacity(logfile.ctrl->type, &logfile.ctrl->size) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to get device(%u, %s) capacity.", logfile.ctrl->type, logfile.ctrl->name);
            return CT_ERROR;
        }
        block_num = logfile.ctrl->size / logfile.ctrl->block_size;
        INT32_OVERFLOW_CHECK(block_num);
        logfile.ctrl->flg = 0;
        logfile.ctrl->archived = CT_FALSE;
        if (cm_exist_device(logfile.ctrl->type, logfile.ctrl->name)) {
            CT_THROW_ERROR(ERR_OBJECT_EXISTS, "redo log file", logfile.ctrl->name);
            return CT_ERROR;
        }

        if (cm_build_device(logfile.ctrl->name, logfile.ctrl->type, kernel->attr.xpurpose_buf, CT_XPURPOSE_BUFFER_SIZE,
                            logfile.ctrl->size, knl_io_flag(session), CT_FALSE, &logfile.handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to build %s ", logfile.ctrl->name);
            return CT_ERROR;
        }

        logfile.head.first = CT_INVALID_ID64;
        logfile.head.last = CT_INVALID_ID64;
        logfile.head.write_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), logfile.ctrl->block_size);
        logfile.head.block_size = (int32)logfile.ctrl->block_size;
        logfile.head.rst_id = db->ctrl.core.resetlogs.rst_id;
        logfile.head.cmp_algorithm = COMPRESS_NONE;

        if (i == 0) {
            logfile.ctrl->status = LOG_FILE_CURRENT;
            logfile.head.asn = CT_FIRST_ASN;
            ctrl->rcy_point.block_id = 1;
            ctrl->lrp_point.block_id = 1;
        } else {
            logfile.head.asn = CT_INVALID_ASN;
            logfile.ctrl->status = LOG_FILE_INACTIVE;
        }
        logfile.head.dbid = db->ctrl.core.dbid;
        status_t ret = memset_sp(logfile.head.unused, CT_LOG_HEAD_RESERVED_BYTES, 0, CT_LOG_HEAD_RESERVED_BYTES);
        knl_securec_check(ret);

        if (cm_open_device(logfile.ctrl->name, logfile.ctrl->type, knl_io_flag(session), &logfile.handle) !=
            CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to open %s ", logfile.ctrl->name);
            return CT_ERROR;
        }

        log_flush_head(session, &logfile);
        cm_close_device(logfile.ctrl->type, &logfile.handle);
        if (db_save_log_ctrl(session, logfile.ctrl->file_id, node_id) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to save ctrl when create logfile : %s ", logfile.ctrl->name);
            return CT_ERROR;
        }
        /* Only one log file is required for DBStor. */
        if (cm_dbs_is_enable_dbs() == CT_TRUE) {
            return CT_SUCCESS;
        }
    }

    return CT_SUCCESS;
}

static status_t dbc_init_space(knl_session_t *session, knl_database_def_t *def)
{
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(session);
    def->system_space.is_for_create_db = CT_FALSE;
    if (spc_create_space(session, &def->system_space, &core_ctrl->system_space) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dtc_build_node_spaces(session, def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (def->user_space.datafiles.count > 0) {
        def->user_space.is_for_create_db = CT_FALSE;
        if (spc_create_space(session, &def->user_space, &core_ctrl->user_space) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    def->temp_space.is_for_create_db = CT_FALSE;
    if (spc_create_space(session, &def->temp_space, &core_ctrl->temp_space) != CT_SUCCESS) {
        return CT_ERROR;
    }
    def->temp_undo_space.is_for_create_db = CT_FALSE;
    def->temp_undo_space.extent_size = UNDO_EXTENT_SIZE;
    if (spc_create_space(session, &def->temp_undo_space, &core_ctrl->temp_undo_space) != CT_SUCCESS) {
        return CT_ERROR;
    }
    def->sysaux_space.is_for_create_db = CT_FALSE;
    if (spc_create_space(session, &def->sysaux_space, &core_ctrl->sysaux_space) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static void dbc_init_doublewrite(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(session);
    dtc_node_ctrl_t *node = dtc_my_ctrl(session);
    uint32 node_count = core_ctrl->node_count;

    space_t *dw_space = &(db->spaces[core_ctrl->sysaux_space]);

    buf_enter_page(session, dw_space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT | ENTER_PAGE_NO_READ);
    db->ctrl.core.dw_file_id = dw_space->ctrl->files[0];
    db->ctrl.core.dw_area_pages = DOUBLE_WRITE_PAGES * node_count;

    node->dw_start = DW_DISTRICT_BEGIN(session->kernel->id);
    node->dw_end = DW_DISTRICT_BEGIN(session->kernel->id);

    dw_space->head->hwms[0] = SPACE_IS_BITMAPMANAGED(dw_space) ? DW_MAP_HWM_START : DW_SPC_HWM_START;
    dw_space->head->hwms[0] += (node_count - 1) * DOUBLE_WRITE_PAGES; /* bypass all the doublewrite area for all nodes.
                                                                       */
    CM_ASSERT(DATAFILE_GET(session, dw_space->ctrl->files[0])->ctrl->size >=
              (dw_space->head->hwms[0] + CT_MIN_SYSAUX_DATAFILE_SIZE) * DEFAULT_PAGE_SIZE(session));
    buf_leave_page(session, CT_TRUE);

    uint32 dw_start = node->dw_start;
    for (uint32 i = 1; i < node_count; i++) {
        node = dtc_get_ctrl(session, i);
        node->dw_start = dw_start + DOUBLE_WRITE_PAGES;
        node->dw_end = dw_start + DOUBLE_WRITE_PAGES;
        dw_start = node->dw_start;
    }
}

static status_t dbc_build_sys_table(knl_session_t *session, knl_cursor_t *cursor)
{
    uint32 i;
    table_t *table = NULL;

    for (i = 0; i <= CORE_SYS_TABLE_CEIL; i++) {
        table = db_sys_table(i);
        dc_set_table_accessor(table);

        if (db_write_systable(session, cursor, &table->desc) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    knl_commit(session);

    return CT_SUCCESS;
}

static status_t dbc_create_sys_segment(knl_session_t *session, uint32 table_id, page_id_t *entry)
{
    table_t *table;

    table = db_sys_table(table_id);
    if (session->kernel->attr.clustered) {
        table->desc.cr_mode = CR_PAGE;
    }

    if (heap_create_segment(session, table) != CT_SUCCESS) {
        return CT_ERROR;
    }

    buf_enter_page(session, table->heap.entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
    table->heap.segment = HEAP_SEG_HEAD(session);
    buf_leave_page(session, CT_FALSE);

    *entry = table->heap.entry;
    return CT_SUCCESS;
}

static status_t dbc_create_sys_segments(knl_session_t *session)
{
    database_t *db = &session->kernel->db;

    if (dbc_create_sys_segment(session, SYS_TABLE_ID, &db->ctrl.core.sys_table_entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dbc_create_sys_segment(session, SYS_COLUMN_ID, &db->ctrl.core.sys_column_entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dbc_create_sys_segment(session, SYS_INDEX_ID, &db->ctrl.core.sys_index_entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dbc_create_sys_segment(session, SYS_USER_ID, &db->ctrl.core.sys_user_entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t dbc_build_systables(knl_session_t *session)
{
    knl_cursor_t *cursor = NULL;

    if (dbc_create_sys_segments(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    if (dbc_build_sys_table(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (db_build_sys_column(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (db_build_sys_index(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (db_build_sys_user(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    
    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

static status_t dbc_save_data_file(knl_session_t *session)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    buf_ctrl_t *next = NULL;

    dbwr_context_t *dbwr = (dbwr_context_t *)cm_push(session->stack, sizeof(dbwr_context_t));
    for (uint32 i = 0; i < CT_MAX_DATA_FILES; i++) {
        dbwr->datafiles[i] = CT_INVALID_HANDLE;
        dbwr->flags[i] = CT_FALSE;
    }

    knl_panic(ctx->queue.count > 0);
    buf_ctrl_t *ctrl = ctx->queue.first;

    while (ctrl != NULL) {
        if (CT_SUCCESS != dbwr_save_page(session, dbwr, ctrl->page)) {
            dbwr_end(session, dbwr);
            cm_pop(session->stack);
            return CT_ERROR;
        }

        next = ctrl->ckpt_next;
        ctrl->ckpt_prev = NULL;
        ctrl->ckpt_next = NULL;
        ctrl->in_ckpt = CT_FALSE;
        ctrl->is_dirty = 0;
        ctrl = next;
    }

    if (session->kernel->attr.enable_fdatasync) {
        if (dbwr_fdatasync(session, dbwr) != CT_SUCCESS) {
            dbwr_end(session, dbwr);
            cm_pop(session->stack);
            return CT_ERROR;
        }
    }

    ctx->queue.count = 0;
    ctx->queue.first = NULL;
    ctx->queue.last = NULL;

    dbwr_end(session, dbwr);
    cm_pop(session->stack);
    return CT_SUCCESS;
}

/*
 * Description     : save database configuration
 * Input           : kernel: database kernel instance
 * Input           : def : database definition
 * Output          : NA
 * Return Value    : status
 * History         : 1.2017/4/26,  add description
 */
static status_t dbc_save_config(knl_instance_t *kernel, knl_database_def_t *def)
{
    char buf[CT_MAX_CONFIG_LINE_SIZE] = { 0 };
    text_t file_list = { .len = 0, .str = buf };
    
    if (cm_concat_string(&file_list, CT_MAX_CONFIG_LINE_SIZE, "(") != CT_SUCCESS) {
        return CT_ERROR;
    }

    for (uint32 i = 0; i < def->ctrlfiles.count; i++) {
        text_t *file_name = (text_t *)cm_galist_get(&def->ctrlfiles, i);
        cm_concat_text(&file_list, CT_MAX_CONFIG_LINE_SIZE, file_name);

        if (i != def->ctrlfiles.count - 1) {
            if (cm_concat_string(&file_list, CT_MAX_CONFIG_LINE_SIZE, ", ") != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }

    if (cm_concat_string(&file_list, CT_MAX_CONFIG_LINE_SIZE, ")\0") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cm_alter_config(kernel->attr.config, "CONTROL_FILES", buf, CONFIG_SCOPE_BOTH, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    knl_panic(kernel->id < def->nodes.count);
    dtc_node_def_t *node = (dtc_node_def_t *)cm_galist_get(&def->nodes, kernel->id);
    if (cm_alter_config(kernel->attr.config, "UNDO_TABLESPACE", node->undo_space.name.str, CONFIG_SCOPE_MEMORY,
                        CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t dbc_wait_dc_completed(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;

    while (!kernel->dc_ctx.completed) {
        if (session->canceled) {
            CT_THROW_ERROR(ERR_OPERATION_CANCELED);
            return CT_ERROR;
        }

        if (session->killed) {
            CT_THROW_ERROR(ERR_OPERATION_KILLED);
            return CT_ERROR;
        }

        cm_sleep(100);
    }

    return CT_SUCCESS;
}

static status_t db_record_install_info(knl_session_t *session)
{
    row_assist_t ra;
    char action[CT_MAX_ACTION_LEN] = "INSTALL";
    timeval_t now;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_UPGRADE_RECORD_ID, CT_INVALID_ID32);
    table_t *table = (table_t *)cursor->table;
    row_init(&ra, (char *)cursor->row, HEAP_MAX_ROW_SIZE(session),  table->desc.column_count);
    (void)cm_gettimeofday(&now);
    (void)row_put_date(&ra, cm_time2date(now.tv_sec));
    (void)row_put_str(&ra, action);
    // install info, the old version is null
    (void)row_put_null(&ra);
    (void)row_put_str(&ra, cantiand_get_dbversion());
    if (knl_internal_insert(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    CM_RESTORE_STACK(session->stack);
    knl_commit(session);

    return CT_SUCCESS;
}

status_t dbc_register_iof(knl_instance_t *kernel)
{
    if (knl_dbs_is_enable_dbs()) {
        if (cm_dbs_create_all_ns() != CT_SUCCESS) {
            CT_LOG_RUN_ERR("Failed to build dbstore namespace.");
            return CT_ERROR;
        }

        if (cm_dbs_iof_reg_all_ns(kernel->id) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("Failed to iof reg dbstore namespace, inst id %u", kernel->id);
            return CT_ERROR;
        }

        if (cm_dbs_open_all_ns() != CT_SUCCESS) {
            CT_LOG_RUN_ERR("Failed to open dbstore namespace.");
            return CT_ERROR;
        }
    } else {
        if (kernel->file_iof_thd.id == 0) {
            if (cm_file_iof_register(kernel->id, &kernel->file_iof_thd) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("Failed to iof reg file, inst id %u", kernel->id);
                return CT_ERROR;
            }
        }
    }
    return CT_SUCCESS;
}

status_t dbc_create_database(knl_handle_t session, knl_database_def_t *def, bool32 clustered)
{
    knl_session_t *knl_session = (knl_session_t *)session;
    knl_instance_t *kernel = knl_session->kernel;

    if (DB_ATTR_CLUSTER(knl_session) != clustered) {
        CT_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "parameter CLUSTER_DATABASE is not equal to that of create database");
        return CT_ERROR;
    }

    kernel->db.status = DB_STATUS_CREATING;
    DB_CORE_CTRL(knl_session)->resetlogs.rst_id = 0;
    dbc_init_scn(knl_session);
    dbc_init_archivelog(knl_session, def);
    dbc_init_dbid(knl_session, def);
    if (DB_ATTR_CLUSTER(knl_session)) {
        db_init_max_instance(session, def->max_instance);
    } else {
        knl_panic(def->nodes.count == 1);
    }

    if (dbc_save_sys_password(knl_session, def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dbc_register_iof(kernel) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cm_alter_config(kernel->attr.config, "_SYS_PASSWORD", kernel->attr.sys_pwd, CONFIG_SCOPE_DISK, CT_TRUE) !=
        CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dbc_save_charset(knl_session, def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dbc_build_ctrlfiles(knl_session, def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dtc_build_logfiles(knl_session, def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // after build ctrl files and log files, we should launch the redo log
    // and checkpoint facility to keep database init consistency.
    if (db_load_logfiles(knl_session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dbc_init_space(knl_session, def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dbc_init_doublewrite(knl_session);

    if (dtc_init_undo_spaces(knl_session, def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dbc_build_systables(knl_session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dbc_save_data_file(knl_session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (db_save_core_ctrl(knl_session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dtc_save_all_ctrls(knl_session, def->nodes.count) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dbc_save_config(kernel, def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (db_mount(knl_session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    db_open_opt_t open_options = {
        CT_TRUE, CT_FALSE, CT_FALSE, CT_FALSE, CT_TRUE, DB_OPEN_STATUS_NORMAL, CT_INVALID_LFN
    };
    if (db_open(knl_session, &open_options) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (undo_preload(knl_session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dbc_wait_dc_completed(knl_session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (db_record_install_info(knl_session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

uint32 dbc_generate_dbid(knl_session_t *session)
{
    database_t *db = &session->kernel->db;
    dbname_time_t dbname_time;

    errno_t ret = strcpy_s(dbname_time.name, CT_DB_NAME_LEN, db->ctrl.core.name);
    knl_securec_check(ret);
    dbname_time.time = cm_now();

    int32 name_len = (int32)strlen(dbname_time.name);
    int32 remain_size = CT_DB_NAME_LEN - name_len;

    /* Fill the remaining bytes of the name with random number. */
    for (int32 i = 0; i < remain_size; i++) {
        dbname_time.name[name_len + i] = cm_random(CT_MAX_UINT8);
    }

    return cm_hash_bytes((uint8 *)&dbname_time.name[0], CT_DB_NAME_LEN + sizeof(date_t), CT_MAX_INT32);
}

#ifdef __cplusplus
}
#endif
