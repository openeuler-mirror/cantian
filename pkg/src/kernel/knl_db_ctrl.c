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
 * knl_db_ctrl.c
 *
 *
 * IDENTIFICATION
 * src/kernel/knl_db_ctrl.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_common_module.h"
#include "knl_db_ctrl.h"
#include "cm_file.h"
#include "knl_context.h"
#include "knl_ctrl_restore.h"
#include "dtc_database.h"
#include "dtc_dls.h"

#ifdef __cplusplus
extern "C" {
#endif

void db_init_logfile_ctrl(knl_session_t *session, uint32 *offset)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    uint32 count = CTRL_MAX_BUF_SIZE / sizeof(log_file_ctrl_t);
    uint32 pages_per_inst = (CT_MAX_LOG_FILES - 1) / count + 1;
    uint32 i;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);

    for (i = 0; i < CT_MAX_LOG_FILES; i++) {
        logfile_set->items[i].ctrl = (log_file_ctrl_t *)db_get_log_ctrl_item(db->ctrl.pages, i, sizeof(log_file_ctrl_t),
                                                                             *offset, kernel->id);
        logfile_set->items[i].handle = CT_INVALID_HANDLE;
    }

    uint32 inst_count = kernel->attr.clustered ? CT_MAX_INSTANCES : 1;
    *offset = *offset + pages_per_inst * inst_count;
}

void db_init_space_ctrl(knl_session_t *session, uint32 *offset)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    uint32 count = CTRL_MAX_BUF_SIZE / sizeof(space_ctrl_t);
    uint32 i;
    errno_t err;

    for (i = 0; i < CT_MAX_SPACES; i++) {
        db->spaces[i].ctrl = (space_ctrl_t *)db_get_ctrl_item(db->ctrl.pages, i, sizeof(space_ctrl_t), *offset);
        db->spaces[i].ctrl->used = CT_FALSE;
        db->spaces[i].ctrl->id = i;
        err = memset_sp(db->spaces[i].ctrl->files, CT_MAX_SPACE_FILES * sizeof(uint32), 0xFF,
                        CT_MAX_SPACE_FILES * sizeof(uint32));
        knl_securec_check(err);
    }
    *offset = *offset + (CT_MAX_SPACES - 1) / count + 1;
}

void db_init_datafile_ctrl(knl_session_t *session, uint32 *offset)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    uint32 count = CTRL_MAX_BUF_SIZE / sizeof(datafile_ctrl_t);
    uint32 i;

    for (i = 0; i < CT_MAX_DATA_FILES; i++) {
        db->datafiles[i].ctrl = (datafile_ctrl_t *)db_get_ctrl_item(db->ctrl.pages, i, sizeof(datafile_ctrl_t),
                                                                    *offset);
        db->datafiles[i].ctrl->id = i;
        db->datafiles[i].ctrl->used = CT_FALSE;
        db->datafiles[i].file_no = CT_INVALID_ID32;
        db->datafiles[i].block_num = 0;
    }

    *offset = *offset + (CT_MAX_DATA_FILES - 1) / count + 1;
}

static inline void db_calc_ctrl_checksum(knl_session_t *session, ctrl_page_t *page, uint32 size)
{
    page->tail.checksum = CT_INVALID_CHECKSUM;
    if (size == 0 || DB_IS_CHECKSUM_OFF(session)) {
        return;
    }

    page_calc_checksum((page_head_t *)page, size);
}

static bool32 db_verify_ctrl_checksum(knl_session_t *session, ctrl_page_t *page, uint32 size, uint32 id)
{
    uint32 cks_level = session->kernel->attr.db_block_checksum;
    if (DB_IS_CHECKSUM_OFF(session) || page->tail.checksum == CT_INVALID_CHECKSUM) {
        return CT_TRUE;
    }

    if (size == 0 || !page_verify_checksum((page_head_t *)page, size)) {
        CT_LOG_RUN_ERR("the %d's ctrl page corrupted.size %u cks %u checksum level %s", id, size, page->tail.checksum,
                       knl_checksum_level(cks_level));
        return CT_FALSE;
    }

    return CT_TRUE;
}

static status_t db_try_sync_ctrl_files(knl_session_t *session, uint32 main_file_id)
{
    uint32 i;
    ctrlfile_t *ctrlfile = NULL;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;

    for (i = 0; i < db->ctrlfiles.count; i++) {
        ctrlfile = &db->ctrlfiles.items[i];
        if (i == main_file_id) {
            continue;
        }

        if (cm_open_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to open %s ", ctrlfile->name);
            return CT_ERROR;
        }

        if (cm_write_device(ctrlfile->type, ctrlfile->handle, 0, db->ctrl.pages,
                            (int32)ctrlfile->blocks * ctrlfile->block_size) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to write %s ", ctrlfile->name);
            cm_close_device(ctrlfile->type, &ctrlfile->handle);
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

/*
 * Description     : fetch ctrl file name from file name list
 * Input           : files: file name list seperated by \0
 * Output          : name: one ctrl file name
 * Return Value    : void
 * History         : 1.2017/4/26,  add description
 */
static void db_fetch_ctrlfile_name(text_t *files, text_t *name)
{
    if (!cm_fetch_text(files, ',', '\0', name)) {
        return;
    }

    cm_trim_text(name);
    if (name->str[0] == '\'') {
        name->str++;
        /* reduce the length of "\'XXX\'" */
        name->len -= (uint32)strlen("\'\'");

        cm_trim_text(name);
    }
}

static bool32 db_is_ctrl_size_valid(knl_session_t *session, ctrlfile_t *ctrlfile)
{
    int64 filesize, max_size;

    max_size = (int64)(ctrlfile->blocks * ctrlfile->block_size);
    filesize = cm_device_size(ctrlfile->type, ctrlfile->handle);
    if (filesize != max_size) {
        CT_LOG_RUN_ERR("[DB] the size of ctrl file %s is abnormal, the expected size is: %lld, "
            "the actual size is: %lld",
            ctrlfile->name, max_size, filesize);
        return CT_FALSE;
    }

    return CT_TRUE;
}

static bool32 db_validate_ctrl(knl_session_t *session, ctrlfile_t *ctrlfile)
{
    uint32 i;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    ctrl_page_t *pages = kernel->db.ctrl.pages;

    for (i = 0; i < CTRL_MAX_PAGES(session); i++) {
        if (pages[i].head.pcn != pages[i].tail.pcn) {
            return CT_FALSE;
        }

        if (!db_verify_ctrl_checksum(session, &pages[i], (uint32)ctrlfile->block_size, i)) {
            return CT_FALSE;
        }
    }

    return CT_TRUE;
}

static status_t db_try_load_oldctrl(ctrlfile_t *ctrlfile, knl_instance_t *kernel, bool32 *updated)
{
    int32 error_code = cm_get_error_code();
    if (error_code == ERR_READ_DEVICE_INCOMPLETE) {
        CT_LOG_RUN_ERR("[DB] failed to read %s try read old version", ctrlfile->name);
        if (cm_read_device(ctrlfile->type, ctrlfile->handle, 0, kernel->db.ctrl.pages,
                           CTRL_OLD_MAX_PAGE * ctrlfile->block_size) == CT_SUCCESS) {
            cm_reset_error();
            *updated = CT_TRUE;
            return CT_SUCCESS;
        }
    }
    return CT_ERROR;
}

static status_t db_check_undo_space(knl_instance_t *kernel, database_t *db)
{
    dtc_node_ctrl_t *ctrl = dtc_my_kernel_ctrl(kernel);
    uint32 undo_id = ctrl->undo_space;
    space_t *undo_space = &db->spaces[undo_id];
    text_t undo_name;
    char *param = cm_get_config_value(kernel->attr.config, "UNDO_TABLESPACE");
    uint32 len = (uint32)strlen(param);
    if (len == 0) {
        return cm_alter_config(kernel->attr.config, "UNDO_TABLESPACE", undo_space->ctrl->name, CONFIG_SCOPE_MEMORY,
                               CT_TRUE);
    }

    cm_str2text(param, &undo_name);
    if (!cm_text_str_equal_ins(&undo_name, undo_space->ctrl->name)) {
        CT_THROW_ERROR(ERR_UNDO_TABLESPACE_NOT_MATCH, undo_name.str, undo_space->ctrl->name);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t db_check_ctrl_attr(knl_instance_t *kernel, database_t *db)
{
    if (!db->recover_for_restore && !(db->status == DB_STATUS_CREATING || db->status == DB_STATUS_MOUNT) &&
        !db->ctrl.core.build_completed) {
        CT_THROW_ERROR(ERR_DATABASE_NOT_COMPLETED);
        knl_panic_log(0, "database is not create completed ,db status is : %d", db->status);
        return CT_ERROR;
    }

    if (kernel->attr.page_size != db->ctrl.core.page_size) {
        CT_THROW_ERROR(ERR_PARAMETER_NOT_MATCH, "PAGE_SIZE", kernel->attr.page_size, db->ctrl.core.page_size);
        return CT_ERROR;
    }

    if (kernel->attr.clustered != db->ctrl.core.clustered) {
        //        CT_THROW_ERROR(ERR_PARAMETER_NOT_MATCH, "CLUSTER_DATABASE", kernel->attr.clustered,
        //        db->ctrl.core.clustered);
        CT_LOG_RUN_WAR("CLUSTER_DATABASE not match, in cnf:%d, in ctrl:%d", kernel->attr.clustered,
                       db->ctrl.core.clustered);
    }

    if (kernel->attr.max_column_count < db->ctrl.core.max_column_count) {
        CT_THROW_ERROR(ERR_PARAMETER_NOT_MATCH, "MAX_COLUMN_COUNT", kernel->attr.max_column_count,
                       db->ctrl.core.max_column_count);
        return CT_ERROR;
    }

    if (kernel->attr.max_column_count > db->ctrl.core.max_column_count) {
        db->ctrl.core.max_column_count = kernel->attr.max_column_count;
    }

    if (kernel->attr.undo_segments != db->ctrl.core.undo_segments) {
        CT_THROW_ERROR(ERR_PARAMETER_NOT_MATCH, "UNDO_SEGMENTS", kernel->attr.undo_segments,
                       db->ctrl.core.undo_segments);
        return CT_ERROR;
    }

    if (db_check_undo_space(kernel, db) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t db_load_ctrlspace(knl_session_t *session, text_t *files)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    ctrlfile_t *ctrlfile = NULL;
    text_t file_name;
    uint32 main_file_id = CT_INVALID_ID32;
    uint32 id = 0;
    bool32 loaded = CT_FALSE;
    bool32 upgrade = CT_FALSE;

    cm_remove_brackets(files);

    db_fetch_ctrlfile_name(files, &file_name);
    while (file_name.len > 0) {
        CM_ABORT((id < CT_MAX_CTRL_FILES), "number of ctrl file exceeded the limit %d.", CT_MAX_CTRL_FILES);
        ctrlfile = &db->ctrlfiles.items[id];
        (void)cm_text2str(&file_name, ctrlfile->name, CT_FILE_NAME_BUFFER_SIZE);
        ctrlfile->type = cm_device_type(ctrlfile->name);
        ctrlfile->block_size = CT_DFLT_CTRL_BLOCK_SIZE;
        ctrlfile->blocks = CTRL_MAX_PAGES(session);

        if (cm_open_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to open %s ", ctrlfile->name);
            return CT_ERROR;
        }

        if (loaded) {
            id++;
            cm_close_device(ctrlfile->type, &ctrlfile->handle);
            db_fetch_ctrlfile_name(files, &file_name);
            continue;
        }

        if (cm_read_device(ctrlfile->type, ctrlfile->handle, 0, db->ctrl.pages,
                           (int32)ctrlfile->blocks * ctrlfile->block_size) != CT_SUCCESS) {
            /*
             * old version ctrl file size is 512*16k, new version change to 640*16k
             * need to adapte old version and read 512*16k again when read error!
             */
            if (db_try_load_oldctrl(ctrlfile, kernel, &upgrade) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[DB] failed to read %s ", ctrlfile->name);
                cm_close_device(ctrlfile->type, &ctrlfile->handle);
                return CT_ERROR;
            }
        }

        if (!db_is_ctrl_size_valid(session, ctrlfile)) {
            CT_THROW_ERROR(ERR_LOAD_CONTROL_FILE, "control file size is not correct");
            return CT_ERROR;
        }

        cm_close_device(ctrlfile->type, &ctrlfile->handle);

        if (!db_validate_ctrl(session, ctrlfile)) {
            CT_LOG_RUN_WAR("control file %s is corrupted", ctrlfile->name);
        } else {
            main_file_id = id;
            loaded = CT_TRUE;
        }

        id++;
        db_fetch_ctrlfile_name(files, &file_name);
    }

    if (!loaded) {
        CT_THROW_ERROR(ERR_LOAD_CONTROL_FILE, "no usable control file");
        return CT_ERROR;
    }

    bool is_slave = !DB_IS_PRIMARY(db);
    db_load_core(db);
    if (is_slave) {
        CT_LOG_RUN_INF("Manually set to STANDBY.");
        db->ctrl.core.db_role = REPL_ROLE_PHYSICAL_STANDBY;
    } else {
        if (db->ctrl.core.db_role == REPL_ROLE_PHYSICAL_STANDBY) {
            CT_LOG_RUN_INF("[INST] [SWITCHOVER] db role is PHYSICAL_STANDBY, need promote role");
            tx_rollback_close(session);
            lrpl_context_t *lrpl = &session->kernel->lrpl_ctx;
            status_t status = cm_create_thread(db_promote_cluster_role, 0, NULL, &lrpl->promote_thread);
            if (status != CT_SUCCESS) {
                CM_ABORT_REASONABLE(0, "[INST] [SWITCHOVER] promote cm_create_thread failed");
                return CT_ERROR;
            }
        } else {
            CT_LOG_RUN_INF("Manually set to PRIMARY.");
            db->ctrl.core.db_role = REPL_ROLE_PRIMARY;
        }
    }

    if (db_check_ctrl_attr(kernel, db) != CT_SUCCESS) {
        return CT_ERROR;
    }

    db->ctrlfiles.count = id;
    db->cluster_ready = db->ctrl.core.clustered;

    /* load core system info to kernel */
    kernel->scn = dtc_my_ctrl(session)->scn;
    kernel->lsn = dtc_my_ctrl(session)->lsn;
    kernel->lfn = dtc_my_ctrl(session)->lfn;

    g_timer()->db_init_time = db->ctrl.core.init_time;
    g_timer()->system_scn = &kernel->scn;
    CM_MFENCE;
    cm_atomic_set(&(g_timer()->sys_scn_valid), (int64)CT_TRUE);

    if (upgrade) {
        main_file_id = db->ctrlfiles.count;
    }
    return db_try_sync_ctrl_files(session, main_file_id);
}

status_t db_generate_ctrlitems(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    ctrlfile_t *ctrlfile = NULL;
    char *param;
    text_t files;
    text_t file_name;
    uint32 id = 0;

    param = cm_get_config_value(kernel->attr.config, "CONTROL_FILES");
    cm_str2text(param, &files);

    if (files.len == 0) {
        CT_THROW_ERROR(ERR_LOAD_CONTROL_FILE, "CONTROL_FILES is not set!");
        return CT_ERROR;
    }

    cm_remove_brackets(&files);
    db_fetch_ctrlfile_name(&files, &file_name);
    while (file_name.len > 0) {
        ctrlfile = &db->ctrlfiles.items[id];
        (void)cm_text2str(&file_name, ctrlfile->name, CT_FILE_NAME_BUFFER_SIZE);
        ctrlfile->type = cm_device_type(ctrlfile->name);
        ctrlfile->block_size = CT_DFLT_CTRL_BLOCK_SIZE;
        id++;
        db_fetch_ctrlfile_name(&files, &file_name);
    }

    db->ctrlfiles.count = id;
    return CT_SUCCESS;
}

static status_t db_create_ctrl_device(knl_session_t *session, ctrlfile_t *ctrlfile)
{
    knl_instance_t *kernel = session->kernel;
    bool32 is_dbstor = cm_dbs_is_enable_dbs();
    if (is_dbstor) {
        ctrlfile->blocks = kernel->attr.clustered ? CTRL_MAX_PAGES_CLUSTERED : CTRL_MAX_PAGES_NONCLUSTERED;
        ctrlfile->block_size = CT_DFLT_CTRL_BLOCK_SIZE;
        uint32 flags = (ctrlfile->type == DEV_TYPE_PGPOOL ? 0xFFFFFFFF : knl_io_flag(session));
        if (cm_build_device(ctrlfile->name, ctrlfile->type, kernel->attr.xpurpose_buf,
            CT_XPURPOSE_BUFFER_SIZE, (int64)ctrlfile->blocks * ctrlfile->block_size,
            flags, CT_FALSE, &ctrlfile->handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to build %s ", ctrlfile->name);
            return CT_ERROR;
        }
        if (cm_open_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to open %s ", ctrlfile->name);
            return CT_ERROR;
        }
    } else {
        if (cm_create_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BACKUP] failed to create %s ", ctrlfile->name);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t db_create_ctrl_file(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    ctrlfile_t *ctrlfile = NULL;
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_stat_t *stat = &ctx->bak.stat;
    uint32 id;

    for (id = 0; id < db->ctrlfiles.count; id++) {
        ctrlfile = &db->ctrlfiles.items[id];
        if (db_create_ctrl_device(session, ctrlfile) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (db_fsync_file(session, ctrlfile->handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BACKUP] failed to fsync datafile %s", ctrlfile->name);
            return CT_ERROR;
        }

        (void)cm_atomic_inc(&stat->writes);
    }

    return CT_SUCCESS;
}

status_t db_save_ctrl_page(knl_session_t *session, ctrlfile_t *ctrlfile, uint32 page_id)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    char *page_buf = (char *)cm_push(session->stack, (uint32)ctrlfile->block_size + (uint32)CT_MAX_ALIGN_SIZE_4K);
    ctrl_page_t *page = (ctrl_page_t *)cm_aligned_buf(page_buf);
    errno_t ret;

    knl_panic(page_id < CTRL_MAX_PAGES(session));
    CM_ABORT(page_id < CTRL_MAX_PAGES(session),
             "[DB] ABORT INFO: the count of control page has reached max control page %u",
             CTRL_MAX_PAGES(session));
    ret = memcpy_sp(page, ctrlfile->block_size, &db->ctrl.pages[page_id], ctrlfile->block_size);
    knl_securec_check(ret);

    page->head.pcn++;
    page->tail.pcn++;

    db_calc_ctrl_checksum(session, page, (uint32)ctrlfile->block_size);

    if (cm_write_device(ctrlfile->type, ctrlfile->handle, (int64)page_id * ctrlfile->block_size, (char *)page,
                        ctrlfile->block_size) != CT_SUCCESS) {
        cm_pop(session->stack);
        CT_LOG_RUN_ERR("[DB] failed to write %s ", ctrlfile->name);
        return CT_ERROR;
    }

    if (db_fdatasync_file(session, ctrlfile->handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DB] failed to fdatasync datafile %s", ctrlfile->name);
        cm_pop(session->stack);
        return CT_ERROR;
    }

    cm_pop(session->stack);
    return CT_SUCCESS;
}

status_t db_read_ctrl_page(knl_session_t *session, ctrlfile_t *ctrlfile, uint32 page_id)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;

    knl_panic(page_id < CTRL_MAX_PAGES(session));
    CM_ABORT(page_id < CTRL_MAX_PAGES(session),
             "[DB] ABORT INFO: the count of control page has reached max control page %u",
             CTRL_MAX_PAGES(session));

    if (cm_read_device(ctrlfile->type, ctrlfile->handle, (int64)page_id * ctrlfile->block_size,
                       &db->ctrl.pages[page_id], ctrlfile->block_size) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DB] failed to read %s offset %lld", ctrlfile->name, (int64)page_id * ctrlfile->block_size);
        return CT_ERROR;
    }

    db_calc_ctrl_checksum(session, &db->ctrl.pages[page_id], (uint32)ctrlfile->block_size);
    return CT_SUCCESS;
}

status_t db_read_log_page(knl_session_t *session, ctrlfile_t *ctrlfile, uint32 start, uint32 end)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;

    knl_panic(end < CTRL_MAX_PAGES(session));
    CM_ABORT(end < CTRL_MAX_PAGES(session),
             "[DB] ABORT INFO: the count of control page has reached max control page %u",
             CTRL_MAX_PAGES(session));

    for (uint32 i = start; i <= end; i++) {
        if (cm_read_device(ctrlfile->type, ctrlfile->handle, (int64)i * ctrlfile->block_size, &db->ctrl.pages[i],
                           ctrlfile->block_size) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to read %s offset %lld", ctrlfile->name, (int64)i * ctrlfile->block_size);
            return CT_ERROR;
        }
        db_calc_ctrl_checksum(session, &db->ctrl.pages[i], (uint32)ctrlfile->block_size);
    }

    return CT_SUCCESS;
}

status_t db_save_core_ctrl(knl_session_t *session)
{
    ctrlfile_t *ctrlfile = NULL;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    uint32 i;

    cm_spin_lock(&db->ctrl_lock, NULL);
    db_store_core(db);

    for (i = 0; i < db->ctrlfiles.count; i++) {
        ctrlfile = &db->ctrlfiles.items[i];
        knl_panic((uint32)ctrlfile->block_size == CT_DFLT_CTRL_BLOCK_SIZE);

        /* ctrlfile can be opened for a long time, closed in db_close_ctrl_files */
        if (cm_open_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to open %s ", ctrlfile->name);
            cm_spin_unlock(&db->ctrl_lock);
            return CT_ERROR;
        }

        if (db_save_ctrl_page(session, ctrlfile, CORE_CTRL_PAGE_ID) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to write %s ", ctrlfile->name);
            cm_spin_unlock(&db->ctrl_lock);
            return CT_ERROR;
        }
    }

    cm_spin_unlock(&db->ctrl_lock);
    return CT_SUCCESS;
}

status_t db_save_node_ctrl(knl_session_t *session)
{
    return dtc_save_ctrl(session, session->kernel->id);
}

status_t db_save_log_ctrl(knl_session_t *session, uint32 id, uint32 node_id)
{
    ctrlfile_t *ctrlfile = NULL;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    uint32 count = CTRL_MAX_BUF_SIZE / sizeof(log_file_ctrl_t);
    uint32 pages_per_inst = (CT_MAX_LOG_FILES - 1) / count + 1;
    uint32 i;
    uint32 page_id;

    cm_spin_lock(&db->ctrl_lock, NULL);
    db_store_core(db);

    for (i = 0; i < db->ctrlfiles.count; i++) {
        ctrlfile = &db->ctrlfiles.items[i];
        /* ctrlfile can be opened for a long time, closed in db_close_ctrl_files */
        if (cm_open_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to open %s ", ctrlfile->name);
            cm_spin_unlock(&db->ctrl_lock);
            return CT_ERROR;
        }

        page_id = db->ctrl.log_segment + pages_per_inst * node_id + id / count;
        if (db_save_ctrl_page(session, ctrlfile, page_id) != CT_SUCCESS) {
            cm_spin_unlock(&db->ctrl_lock);
            return CT_ERROR;
        }

        if (db_save_ctrl_page(session, ctrlfile, CORE_CTRL_PAGE_ID) != CT_SUCCESS) {
            cm_spin_unlock(&db->ctrl_lock);
            return CT_ERROR;
        }
    }

    if (ctrl_backup_log_ctrl(session, id) != CT_SUCCESS) {
        cm_spin_unlock(&db->ctrl_lock);
        return CT_ERROR;
    }

    cm_spin_unlock(&db->ctrl_lock);

    if (session->kernel->attr.clustered) {
        if (dtc_save_ctrl(session, session->kernel->id) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to save ctrl for instance %u", session->kernel->id);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}
status_t db_write_ctrl_page(knl_session_t *session, ctrlfile_t *ctrlfile, uint32 page_id, ctrl_page_t *page)
{
    page->head.pcn++;
    page->tail.pcn++;
    db_calc_ctrl_checksum(session, page, (uint32)ctrlfile->block_size);
    if (cm_write_device(ctrlfile->type, ctrlfile->handle, (int64)page_id * ctrlfile->block_size, (char *)page,
                        ctrlfile->block_size) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DB] failed to write %s ", ctrlfile->name);
        return CT_ERROR;
    }

    if (db_fdatasync_file(session, ctrlfile->handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DB] failed to fdatasync datafile %s", ctrlfile->name);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}
status_t db_save_ctrl_page_daac(knl_session_t *session, ctrlfile_t *ctrlfile, uint32 id)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    uint32 count = CTRL_MAX_BUF_SIZE / sizeof(datafile_ctrl_t);
    uint32 page_id = db->ctrl.datafile_segment + id / count;
    datafile_ctrl_t *df_ctrl_buf = NULL;
    datafile_ctrl_t *df_ctrl = (datafile_ctrl_t *)db_get_ctrl_item(db->ctrl.pages, id, sizeof(datafile_ctrl_t),
                                                                   db->ctrl.datafile_segment);
    char *page_buf = (char *)cm_push(session->stack, (uint32)CT_DFLT_CTRL_BLOCK_SIZE + (uint32)CT_MAX_ALIGN_SIZE_4K);
    ctrl_page_t *page = (ctrl_page_t *)cm_aligned_buf(page_buf);
    if (cm_read_device(ctrlfile->type, ctrlfile->handle, (int64)page_id * ctrlfile->block_size,
                       page, ctrlfile->block_size) != CT_SUCCESS) {
        cm_pop(session->stack);
        CT_LOG_RUN_ERR("[DB]failed to read %s offset %lld", ctrlfile->name, (int64)page_id * ctrlfile->block_size);
        return CT_ERROR;
    }

    df_ctrl_buf = (datafile_ctrl_t *)(page->buf + id % count * sizeof(datafile_ctrl_t));
    int32 ret = memcpy_sp(df_ctrl_buf, sizeof(datafile_ctrl_t), df_ctrl, sizeof(datafile_ctrl_t));
    knl_securec_check(ret);
    if (db_write_ctrl_page(session, ctrlfile, page_id, page) != CT_SUCCESS) {
        cm_pop(session->stack);
        CT_LOG_RUN_ERR("[DB]failed to write %s offset %lld", ctrlfile->name, (int64)page_id * ctrlfile->block_size);
        return CT_ERROR;
    }
    cm_pop(session->stack);
    return CT_SUCCESS;
}
status_t db_save_datafile_ctrl(knl_session_t *session, uint32 id)
{
    ctrlfile_t *ctrlfile = NULL;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    uint32 count = CTRL_MAX_BUF_SIZE / sizeof(datafile_ctrl_t);
    uint32 i;
    uint32 page_id;

    knl_panic(!DAAC_REPLAY_NODE(session));
    for (;;) {
        if (dls_spin_try_lock(session, &db->df_ctrl_lock)) {
            break;
        }
        cm_sleep(2);
    }
    db_store_core(db);
    for (i = 0; i < db->ctrlfiles.count; i++) {
        ctrlfile = &db->ctrlfiles.items[i];
        /* ctrlfile can be opened for a long time, closed in db_close_ctrl_files */
        if (cm_open_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != CT_SUCCESS) {
            dls_spin_unlock(session, &db->df_ctrl_lock);
            CT_LOG_RUN_ERR("[DB]failed to open %s ", ctrlfile->name);
            return CT_ERROR;
        }
        if (DB_IS_CLUSTER(session)) {
            if (db_save_ctrl_page_daac(session, ctrlfile, id) != CT_SUCCESS) {
                dls_spin_unlock(session, &db->df_ctrl_lock);
                return CT_ERROR;
            }
        } else {
            page_id = db->ctrl.datafile_segment + id / count;
            if (db_save_ctrl_page(session, ctrlfile, page_id) != CT_SUCCESS) {
                dls_spin_unlock(session, &db->df_ctrl_lock);
                return CT_ERROR;
            }
        }
        if (db_save_ctrl_page(session, ctrlfile, CORE_CTRL_PAGE_ID) != CT_SUCCESS) {
            dls_spin_unlock(session, &db->df_ctrl_lock);
            return CT_ERROR;
        }
    }
    if (ctrl_backup_datafile_ctrl(session, id) != CT_SUCCESS) {
        dls_spin_unlock(session, &db->df_ctrl_lock);
        return CT_ERROR;
    }
    dls_spin_unlock(session, &db->df_ctrl_lock);
    return CT_SUCCESS;
}

status_t db_save_space_ctrl(knl_session_t *session, uint32 id)
{
    ctrlfile_t *ctrlfile = NULL;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    uint32 count = CTRL_MAX_BUF_SIZE / sizeof(space_ctrl_t);
    uint32 i;
    uint32 page_id;

    knl_panic(!DAAC_REPLAY_NODE(session));
    cm_spin_lock(&db->ctrl_lock, NULL);
    db_store_core(db);

    for (i = 0; i < db->ctrlfiles.count; i++) {
        ctrlfile = &db->ctrlfiles.items[i];
        /* ctrlfile can be opened for a long time, closed in db_close_ctrl_files */
        if (cm_open_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to open %s ", ctrlfile->name);
            cm_spin_unlock(&db->ctrl_lock);
            return CT_ERROR;
        }

        page_id = db->ctrl.space_segment + id / count;
        if (db_save_ctrl_page(session, ctrlfile, page_id) != CT_SUCCESS) {
            cm_spin_unlock(&db->ctrl_lock);
            return CT_ERROR;
        }

        if (db_save_ctrl_page(session, ctrlfile, CORE_CTRL_PAGE_ID) != CT_SUCCESS) {
            cm_spin_unlock(&db->ctrl_lock);
            return CT_ERROR;
        }
    }

    if (ctrl_backup_space_ctrl(session, id) != CT_SUCCESS) {
        cm_spin_unlock(&db->ctrl_lock);
        return CT_ERROR;
    }

    cm_spin_unlock(&db->ctrl_lock);
    return CT_SUCCESS;
}

status_t db_save_arch_ctrl(knl_session_t *session, uint32 id, uint32 node_id)
{
    ctrlfile_t *ctrlfile = NULL;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    uint32 count = CTRL_MAX_BUF_SIZE / sizeof(arch_ctrl_t);
    uint32 pages_per_inst = (CT_MAX_ARCH_NUM - 1) / count + 1;
    uint32 page_id = db->ctrl.arch_segment + pages_per_inst * node_id + id / count;

    cm_spin_lock(&db->ctrl_lock, NULL);
    db_store_core(db);

    for (uint32 i = 0; i < db->ctrlfiles.count; i++) {
        ctrlfile = &db->ctrlfiles.items[i];
        /* ctrlfile can be opened for a long time, closed in db_close_ctrl_files */
        if (cm_open_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to open %s ", ctrlfile->name);
            cm_spin_unlock(&db->ctrl_lock);
            return CT_ERROR;
        }

        if (db_save_ctrl_page(session, ctrlfile, page_id) != CT_SUCCESS) {
            cm_spin_unlock(&db->ctrl_lock);
            return CT_ERROR;
        }

        if (db_save_ctrl_page(session, ctrlfile, CORE_CTRL_PAGE_ID) != CT_SUCCESS) {
            cm_spin_unlock(&db->ctrl_lock);
            return CT_ERROR;
        }
    }

    cm_spin_unlock(&db->ctrl_lock);
    if (session->kernel->attr.clustered) {
        if (dtc_save_ctrl(session, node_id) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to save ctrl for instance %u", session->kernel->id);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

arch_ctrl_t *db_get_arch_ctrl(knl_session_t *session, uint32 id, uint32 node_id)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    uint32 count = CTRL_MAX_BUF_SIZE / sizeof(arch_ctrl_t);
    uint32 pages_per_inst = (CT_MAX_ARCH_NUM - 1) / count + 1;
    uint32 page_id = db->ctrl.arch_segment + pages_per_inst * node_id + id / count;
    uint32 slot = id % count;

    knl_panic(page_id < CTRL_MAX_PAGES(session));
    CM_ABORT(page_id < CTRL_MAX_PAGES(session),
             "[DB] ABORT INFO: the count of control page has reached max control page %u",
             CTRL_MAX_PAGES(session));

    ctrl_page_t *page = &db->ctrl.pages[page_id];
    return (arch_ctrl_t *)(page->buf + slot * sizeof(arch_ctrl_t));
}

/*
 * check if ctrl file readable
 */
status_t db_check(knl_session_t *session, text_t *ctrlfiles, bool32 *is_found)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    text_t file_name;
    text_t temp_ctrlfiles;
    int32 fp = CT_INVALID_HANDLE;
    char name[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    char *param = cm_get_config_value(kernel->attr.config, "CONTROL_FILES");

    cm_str2text(param, ctrlfiles);
    cm_str2text(param, &temp_ctrlfiles);
    if (ctrlfiles->len == 0) {
        *is_found = CT_FALSE;
        return CT_SUCCESS;
    }

    cm_remove_brackets(&temp_ctrlfiles);
    db_fetch_ctrlfile_name(&temp_ctrlfiles, &file_name);
    (void)cm_text2str(&file_name, name, CT_FILE_NAME_BUFFER_SIZE);

    device_type_t type = cm_device_type(name);
    if (cm_open_device(name, type, knl_io_flag(session), &fp) != CT_SUCCESS) {
        *is_found = CT_FALSE;
        CT_LOG_RUN_ERR("[DB] failed to open %s ", name);
        return CT_ERROR;
    }
    cm_close_device(type, &fp);
    *is_found = CT_TRUE;

    return CT_SUCCESS;
}

void db_update_name_by_path(const char *path, char *name, uint32 len)
{
    text_t left;
    text_t right;
    text_t text;
    char right_str[CT_FILE_NAME_BUFFER_SIZE];
    errno_t err;

    cm_str2text(name, &text);
    (void)cm_split_rtext(&text, SLASH, '\0', &left, &right);
    (void)cm_text2str(&right, right_str, CT_FILE_NAME_BUFFER_SIZE);
    err = snprintf_s(name, len, len - 1, "%s/%s", path, right_str);
    knl_securec_check_ss(err);
}

status_t db_update_ctrl_filename(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    ctrlfile_set_t *ctrlfiles = &kernel->db.ctrlfiles;
    char *param = NULL;
    text_t local_ctrlfiles;
    text_t file_name;
    char path[CT_FILE_NAME_BUFFER_SIZE];
    char name[CT_FILE_NAME_BUFFER_SIZE];
    uint32 i;
    errno_t err;

    param = cm_get_config_value(kernel->attr.config, "CONTROL_FILES");
    cm_str2text(param, &local_ctrlfiles);
    if (local_ctrlfiles.len == 0) {
        CT_LOG_RUN_ERR("the value of CONTROL_FILES is invaild");
        return CT_ERROR;
    }
    if (cm_check_exist_special_char(param, (uint32)strlen(param))) {
        CT_THROW_ERROR(ERR_INVALID_DIR, param);
        return CT_ERROR;
    }

    err = snprintf_s(path, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1, "%s/%s", kernel->home, "data");
    knl_securec_check_ss(err);
    cm_remove_brackets(&local_ctrlfiles);
    for (i = 0; i < ctrlfiles->count; i++) {
        db_fetch_ctrlfile_name(&local_ctrlfiles, &file_name);
        if (file_name.len == 0) {
            CT_LOG_RUN_ERR("the value of CONTROL_FILES is invaild");
            return CT_ERROR;
        }
        (void)cm_text2str(&file_name, name, CT_FILE_NAME_BUFFER_SIZE);
        if (cm_device_type(name) == DEV_TYPE_FILE) {
            db_update_name_by_path(path, name, CT_FILE_NAME_BUFFER_SIZE);
        }
        err = strcpy_sp(ctrlfiles->items[i].name, CT_FILE_NAME_BUFFER_SIZE, name);
        knl_securec_check(err);
    }

    return CT_SUCCESS;
}

status_t db_update_config_ctrl_name(knl_session_t *session)
{
    config_t *config = session->kernel->attr.config;
    knl_instance_t *kernel = session->kernel;
    ctrlfile_set_t *ctrlfiles = &kernel->db.ctrlfiles;
    char value[CT_MAX_CONFIG_LINE_SIZE] = { 0 };
    uint32 i;
    errno_t err;

    err = strcpy_sp(value, CT_MAX_CONFIG_LINE_SIZE, "(");
    knl_securec_check(err);
    if (ctrlfiles->count > 1) {
        for (i = 0; i < ctrlfiles->count - 1; i++) {
            err = strcat_sp(value, CT_MAX_CONFIG_LINE_SIZE, ctrlfiles->items[i].name);
            knl_securec_check(err);
            err = strcat_sp(value, CT_MAX_CONFIG_LINE_SIZE, ", ");
            knl_securec_check(err);
        }
    }
    err = strcat_sp(value, CT_MAX_CONFIG_LINE_SIZE, ctrlfiles->items[ctrlfiles->count - 1].name);
    knl_securec_check(err);
    err = strcat_sp(value, CT_MAX_CONFIG_LINE_SIZE, ")");
    knl_securec_check(err);

    if (cm_alter_config(config, "CONTROL_FILES", value, CONFIG_SCOPE_BOTH, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t db_update_ctrl_logfile_name(knl_session_t *session)
{
    knl_attr_t *attr = &session->kernel->attr;
    log_file_ctrl_t *logfile = NULL;
    uint32 i;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);

    if (!attr->log_file_convert.is_convert) {
        return CT_SUCCESS;
    }

    for (i = 0; i < logfile_set->logfile_hwm; i++) {
        logfile = logfile_set->items[i].ctrl;
        if (LOG_IS_DROPPED(logfile->flg)) {
            continue;
        }
        if (db_change_storage_path(&attr->log_file_convert, logfile->name, CT_FILE_NAME_BUFFER_SIZE) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t db_update_ctrl_datafile_name(knl_session_t *session)
{
    knl_attr_t *attr = &session->kernel->attr;
    knl_instance_t *kernel = session->kernel;
    datafile_ctrl_t *datafile = NULL;
    uint32 i;

    if (!attr->data_file_convert.is_convert) {
        return CT_SUCCESS;
    }

    for (i = 0; i < CT_MAX_DATA_FILES; i++) {
        datafile = kernel->db.datafiles[i].ctrl;
        if (!datafile->used) {
            continue;
        }
        if (db_change_storage_path(&attr->data_file_convert, datafile->name, CT_FILE_NAME_BUFFER_SIZE) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t db_update_storage_filename(knl_session_t *session)
{
    if (db_update_ctrl_logfile_name(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (db_update_ctrl_datafile_name(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void db_update_sysdata_version(knl_session_t *session)
{
    database_t *db = &session->kernel->db;
    rd_update_sysdata_t redo;

    redo.op_type = RD_UPDATE_SYSDATA_VERSION;
    redo.sysdata_version = CORE_SYSDATA_VERSION;

    CT_LOG_RUN_INF("[UPGRADE] system data version is update from %u to %u",
        db->ctrl.core.sysdata_version, CORE_SYSDATA_VERSION);
    db->ctrl.core.sysdata_version = CORE_SYSDATA_VERSION;
    if (db_save_core_ctrl(session) != CT_SUCCESS) {
        CM_ABORT(0, "[UPGRADE] ABORT INFO: update system data version failed when perform upgrade");
    }

    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_update_sysdata_t), LOG_ENTRY_FLAG_NONE);
    knl_commit(session);
}

void rd_update_sysdata_version(knl_session_t *session, log_entry_t *log)
{
    database_t *db = &session->kernel->db;
    if (log->size != CM_ALIGN4(sizeof(rd_update_sysdata_t)) + LOG_ENTRY_SIZE) {
        CT_LOG_RUN_ERR("[UPGRADE]no need to replay update sys version, log size %u is wrong", log->size);
        return;
    }
    rd_update_sysdata_t *redo = (rd_update_sysdata_t *)log->data;

    if (redo->sysdata_version != CORE_SYSDATA_VERSION) {
        CT_LOG_RUN_ERR("[UPGRADE] update sys version failed: the system data's binary version"
                       "is different between primary and standby");
        CM_ASSERT(0);
    }
    CT_LOG_RUN_INF("[UPGRADE] system data version is update from %u to %u",
        db->ctrl.core.sysdata_version, CORE_SYSDATA_VERSION);
    db->ctrl.core.sysdata_version = CORE_SYSDATA_VERSION;
    if (db_save_core_ctrl(session) != CT_SUCCESS) {
        CM_ABORT(0, "[UPGRADE] ABORT INFO: update system data version failed when perform upgrade");
    }
}

void print_update_sysdata_version(log_entry_t *log)
{
    rd_update_sysdata_t *redo = (rd_update_sysdata_t *)log->data;
    printf("update sysdata version:%u\n", redo->sysdata_version);
}

bool32 db_sysdata_version_is_equal(knl_session_t *session, bool32 is_upgrade)
{
    database_t *db = &session->kernel->db;
    knl_attr_t *attr = &session->kernel->attr;

    if (is_upgrade || !attr->check_sysdata_version) {
        return CT_TRUE;
    }
    if (db->ctrl.core.sysdata_version != CORE_SYSDATA_VERSION) {
        CT_LOG_RUN_ERR("[CTRL] the system data's version is different between binary and ctrl file");
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ": the system data's version is different between binary and ctrl file");
        return CT_FALSE;
    }

    return CT_TRUE;
}

bool32 db_cur_ctrl_version_is_higher(knl_session_t *session, ctrl_version_t version)
{
    ctrl_version_t cur_version = DB_CORE_CTRL(session)->version;
    if (cur_version.main == version.main) {
        if (cur_version.major == version.major) {
            return (cur_version.revision == version.revision) ?
                   (cur_version.inner > version.inner) : (cur_version.revision > version.revision);
        } else {
            return (cur_version.major > version.major);
        }
    } else {
        return (cur_version.main > version.main);
    }
}

bool32 db_equal_to_cur_ctrl_version(knl_session_t *session, ctrl_version_t version)
{
    ctrl_version_t cur_version = DB_CORE_CTRL(session)->version;
    return (cur_version.main == version.main && cur_version.major == version.major &&
            cur_version.revision == version.revision && (cur_version.inner == version.inner));
}

#ifdef __cplusplus
}
#endif
