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
 * knl_alter_space.c
 *
 *
 * IDENTIFICATION
 * src/kernel/tablespace/knl_alter_space.c
 *
 * -------------------------------------------------------------------------
 */

#include "knl_alter_space.h"
#include "knl_context.h"
#include "dtc_dls.h"
#include "dtc_database.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t spc_alter_precheck_datafile_autoextend(knl_session_t *session, space_t *space,
    knl_autoextend_def_t *autoextend)
{
    if (session->kernel->db.status != DB_STATUS_OPEN) {
        GS_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "set space autoextend");
        return GS_ERROR;
    }

    if (!autoextend->enabled) {
        return GS_SUCCESS;
    }

    // max_file_size is less than 2^30 * 2^13
    int64 max_file_size = (int64)MAX_FILE_PAGES(space->ctrl->type) * DEFAULT_PAGE_SIZE(session);
    for (uint32 i = 0; i < GS_MAX_SPACE_FILES; i++) {
        if (GS_INVALID_ID32 == space->ctrl->files[i]) {
            continue;
        }

        datafile_t *df = DATAFILE_GET(session, space->ctrl->files[i]);

        if (autoextend->maxsize > max_file_size) {
            GS_THROW_ERROR(ERR_DATAFILE_SIZE_NOT_ALLOWED, "MAXSIZE", space->ctrl->name);
            return GS_ERROR;
        }

        if (autoextend->maxsize != 0 && autoextend->maxsize < df->ctrl->size) {
            GS_THROW_ERROR(ERR_DATAFILE_SIZE_NOT_ALLOWED, "MAXSIZE", space->ctrl->name);
            return GS_ERROR;
        }

        if (autoextend->nextsize > max_file_size) {
            GS_THROW_ERROR(ERR_DATAFILE_SIZE_NOT_ALLOWED, "NEXTSIZE", space->ctrl->name);
            return GS_ERROR;
        }

        if (df_alter_datafile_precheck_autoextend(session, df, autoextend)) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t spc_set_autoextend(knl_session_t *session, space_t *space, knl_autoextend_def_t *autoextend)
{
    datafile_t *df = NULL;
    rd_set_space_autoextend_daac_t daac_redo;
    rd_set_space_autoextend_t *redo = &daac_redo.rd;

    dls_spin_lock(session, &space->lock, &session->stat->spin_stat.stat_space);

    if (spc_alter_precheck_datafile_autoextend(session, space, autoextend) != GS_SUCCESS) {
        dls_spin_unlock(session, &space->lock);
        return GS_ERROR;
    }

    log_atomic_op_begin(session);

    for (uint32 i = 0; i < GS_MAX_SPACE_FILES; i++) {
        if (GS_INVALID_ID32 == space->ctrl->files[i]) {
            continue;
        }

        df = DATAFILE_GET(session, space->ctrl->files[i]);
        spc_set_datafile_autoextend(session, df, autoextend);

        if (db_save_datafile_ctrl(session, df->ctrl->id) != GS_SUCCESS) {
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when space set autoextend");
        }
    }

    daac_redo.op_type = RD_SPC_SET_AUTOEXTEND_DAAC;
    redo->space_id = (uint16)space->ctrl->id;  // space id is less than 1023
    redo->auto_extend = DATAFILE_IS_AUTO_EXTEND(df);
    redo->auto_extend_size = df->ctrl->auto_extend_size;
    redo->auto_extend_maxsize = df->ctrl->auto_extend_maxsize;

    log_put(session, RD_SPC_SET_AUTOEXTEND, redo, sizeof(rd_set_space_autoextend_t), LOG_ENTRY_FLAG_NONE);
    if (DB_IS_CLUSTER(session)) {
        log_put(session, RD_LOGIC_OPERATION, &daac_redo, sizeof(rd_set_space_autoextend_daac_t), LOG_ENTRY_FLAG_NONE);
    }

    log_atomic_op_end(session);

    dls_spin_unlock(session, &space->lock);
    return GS_SUCCESS;
}

status_t spc_set_autooffline(knl_session_t *session, space_t *space, bool32 auto_offline)
{
    rd_set_space_flag_daac_t daac_redo;
    rd_set_space_flag_t *redo = &daac_redo.rd;

    if (session->kernel->db.status != DB_STATUS_OPEN) {
        GS_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "set tablespace autooffline");
        return GS_ERROR;
    }

    dls_spin_lock(session, &space->lock, &session->stat->spin_stat.stat_space);

    if (!space->ctrl->used || !SPACE_IS_ONLINE(space)) {
        dls_spin_unlock(session, &space->lock);
        GS_THROW_ERROR(ERR_OBJECT_ID_NOT_EXIST, "tablespace", space->ctrl->id);
        return GS_ERROR;
    }

    if (SPACE_IS_DEFAULT(space)) {
        dls_spin_unlock(session, &space->lock);
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ",forbid to set system space auto offline");
        return GS_ERROR;
    }

    log_atomic_op_begin(session);

    if (!auto_offline) {
        SPACE_UNSET_AUTOOFFLINE(space);
    } else {
        SPACE_SET_AUTOOFFLINE(space);
    }

    daac_redo.op_type = RD_SPC_SET_FLAG_DAAC;
    redo->space_id = (uint16)space->ctrl->id;  // the maximum space id is 1023
    redo->flags = space->ctrl->flag;

    log_put(session, RD_SPC_SET_FLAG, redo, sizeof(rd_set_space_flag_t), LOG_ENTRY_FLAG_NONE);
    if (DB_IS_CLUSTER(session)) {
        log_put(session, RD_LOGIC_OPERATION, &daac_redo, sizeof(rd_set_space_flag_daac_t), LOG_ENTRY_FLAG_NONE);
    }

    log_atomic_op_end(session);
    dls_spin_unlock(session, &space->lock);

    if (db_save_space_ctrl(session, space->ctrl->id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when space set autooffline");
    }

    return GS_SUCCESS;
}

bool32 spc_check_space_exists(knl_session_t *session, const text_t *name, bool32 is_for_create_db)
{
    space_t *space = NULL;
    uint32 i;

    for (i = 0; i < GS_MAX_SPACES; i++) {
        space = SPACE_GET(session, i);
        if (!space->ctrl->used) {
            continue;
        }

        if (cm_text_str_equal(name, space->ctrl->name) && is_for_create_db == space->ctrl->is_for_create_db) {
            break;
        }
    }

    return (i >= GS_MAX_SPACES) ? GS_FALSE : GS_TRUE;
}

status_t spc_rename_space(knl_session_t *session, space_t *space, text_t *rename_space)
{
    char buf[GS_NAME_BUFFER_SIZE];
    rd_rename_space_daac_t daac_redo;
    rd_rename_space_t *redo = &daac_redo.rd;
    uint32 name_len = GS_NAME_BUFFER_SIZE - 1;
    errno_t ret;
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(session);
    dtc_node_ctrl_t *node_ctrl = dtc_my_ctrl(session);

    if (session->kernel->db.status != DB_STATUS_OPEN) {
        GS_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "rename space");
        return GS_ERROR;
    }

    if (space->ctrl->id == core_ctrl->temp_undo_space || space->ctrl->id == core_ctrl->sysaux_space ||
        space->ctrl->id == core_ctrl->system_space || space->ctrl->id == node_ctrl->undo_space ||
        space->ctrl->id == node_ctrl->temp_undo_space) {
        GS_THROW_ERROR_EX(ERR_INVALID_OPERATION, ", can't rename %s tablespace.", space->ctrl->name);
        return GS_ERROR;
    }

    (void)cm_text2str(rename_space, buf, GS_NAME_BUFFER_SIZE);
    if (spc_check_space_exists(session, rename_space, GS_FALSE)) {
        GS_THROW_ERROR(ERR_SPACE_ALREADY_EXIST, T2S(rename_space));
        return GS_ERROR;
    }

    log_atomic_op_begin(session);
    dls_spin_lock(session, &space->lock, &session->stat->spin_stat.stat_space);

    ret = strncpy_s(space->ctrl->name, GS_NAME_BUFFER_SIZE, buf, name_len);
    knl_securec_check(ret);
    space->ctrl->name[rename_space->len] = 0;

    daac_redo.op_type = RD_SPC_RENAME_SPACE_DAAC;
    redo->space_id = space->ctrl->id;
    ret = strcpy_sp(redo->name, GS_NAME_BUFFER_SIZE, space->ctrl->name);
    knl_securec_check(ret);

    log_put(session, RD_SPC_RENAME_SPACE, redo, sizeof(rd_rename_space_t), LOG_ENTRY_FLAG_NONE);
    if (DB_IS_CLUSTER(session)) {
        log_put(session, RD_LOGIC_OPERATION, &daac_redo, sizeof(rd_rename_space_daac_t), LOG_ENTRY_FLAG_NONE);
    }

    dls_spin_unlock(session, &space->lock);
    log_atomic_op_end(session);

    if (db_save_space_ctrl(session, space->ctrl->id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when rename space");
    }

    return GS_SUCCESS;
}

/*
 * rename a space datafile
 */
status_t spc_rename_datafile(knl_session_t *session, space_t *space, text_t *name, text_t *new_name)
{
    datafile_t *tmp_df = NULL;
    datafile_t *df = NULL;
    uint32 i;
    uint32 id = GS_INVALID_ID32;
    uint32 file_name_len = GS_MAX_FILE_NAME_LEN - 1;
    char buf[GS_MAX_FILE_NAME_LEN];
    errno_t ret;

    for (i = 0; i < GS_MAX_SPACE_FILES; i++) {
        if (GS_INVALID_ID32 == space->ctrl->files[i]) {
            continue;
        }

        df = DATAFILE_GET(session, space->ctrl->files[i]);
        if (df->ctrl->used) {
            if (cm_text_str_equal_ins(new_name, df->ctrl->name)) {
                GS_THROW_ERROR(ERR_DATAFILE_ALREADY_EXIST, T2S(new_name));
                return GS_ERROR;
            }
            if (cm_text_str_equal_ins(name, df->ctrl->name)) {
                tmp_df = df;
                id = space->ctrl->files[i];
            }
        }
    }

    if (tmp_df == NULL) {
        GS_THROW_ERROR(ERR_FILE_NOT_EXIST, "data", T2S(name));
        return GS_ERROR;
    }

    spc_close_datafile(tmp_df, DATAFILE_FD(session, id));
    (void)cm_text2str(new_name, buf, GS_MAX_FILE_NAME_LEN);

    device_type_t type = cm_device_type(tmp_df->ctrl->name);
    if (cm_exist_device(type, buf)) {
        GS_THROW_ERROR(ERR_FILE_ALREADY_EXIST, buf, "failed to rename datafile");
        return GS_ERROR;
    }

    if (cm_rename_device(type, tmp_df->ctrl->name, buf) != 0) {
        GS_THROW_ERROR(ERR_RENAME_FILE, tmp_df->ctrl->name, buf, errno);
        return GS_ERROR;
    }

    ret = strncpy_s(tmp_df->ctrl->name, GS_FILE_NAME_BUFFER_SIZE, buf, file_name_len);
    knl_securec_check(ret);

    if (db_save_datafile_ctrl(session, tmp_df->ctrl->id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save control file when space rename datafiles");
    }

    return GS_SUCCESS;
}

status_t spc_rebuild_space(knl_session_t *session, space_t *space)
{
    datafile_t *df = &session->kernel->db.datafiles[space->ctrl->files[0]];
    space_head_t *spc_head = NULL;
    page_id_t page_id;
    char *buf = NULL;
    errno_t ret;

    if (!IS_SWAP_SPACE(space)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "rebuild space which is not temp");
        return GS_ERROR;
    }

    if (spc_open_datafile(session, df, DATAFILE_FD(session, df->ctrl->id)) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[SPACE] failed to open datafile %s when rebuild space", df->ctrl->name);
        return GS_ERROR;
    }

    if (spc_init_datafile_head(session, df) != GS_SUCCESS) {
        return GS_ERROR;
    }

    buf = (char *)cm_push(session->stack, DEFAULT_PAGE_SIZE(session) + GS_MAX_ALIGN_SIZE_4K);
    char *space_buf = (char *)cm_aligned_buf(buf);
    ret = memset_sp(space_buf, DEFAULT_PAGE_SIZE(session), 0, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);

    page_id.file = df->ctrl->id;
    page_id.page = SPACE_ENTRY_PAGE;
    page_init(session, (page_head_t *)space_buf, page_id, PAGE_TYPE_SPACE_HEAD);

    spc_head = (space_head_t *)(space_buf + sizeof(page_head_t));
    space->head = spc_head;
    spc_init_swap_space(session, space);

    if (cm_write_device(df->ctrl->type, session->datafiles[df->ctrl->id], DEFAULT_PAGE_SIZE(session),
        space_buf, DEFAULT_PAGE_SIZE(session))) {
        cm_pop(session->stack);
        return GS_ERROR;
    }

    cm_pop(session->stack);
    return GS_SUCCESS;
}

status_t spc_set_autopurge(knl_session_t *session, space_t *space, bool32 auto_purge)
{
    rd_set_space_flag_daac_t daac_redo;
    rd_set_space_flag_t *redo = &daac_redo.rd;

    if (session->kernel->db.status != DB_STATUS_OPEN) {
        GS_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "set tablespace autopurge");
        return GS_ERROR;
    }

    dls_spin_lock(session, &space->lock, &session->stat->spin_stat.stat_space);

    if (!space->ctrl->used || !SPACE_IS_ONLINE(space)) {
        dls_spin_unlock(session, &space->lock);
        GS_THROW_ERROR(ERR_OBJECT_ID_NOT_EXIST, "tablespace", space->ctrl->id);
        return GS_ERROR;
    }

    log_atomic_op_begin(session);

    if (!auto_purge) {
        SPACE_UNSET_AUTOPURGE(space);
    } else {
        SPACE_SET_AUTOPURGE(space);
    }

    daac_redo.op_type = RD_SPC_SET_FLAG_DAAC;
    redo->space_id = (uint16)space->ctrl->id;  // the maximum space id is 1023
    redo->flags = space->ctrl->flag;

    log_put(session, RD_SPC_SET_FLAG, redo, sizeof(rd_set_space_flag_t), LOG_ENTRY_FLAG_NONE);
    if (DB_IS_CLUSTER(session)) {
        log_put(session, RD_LOGIC_OPERATION, &daac_redo, sizeof(rd_set_space_flag_daac_t), LOG_ENTRY_FLAG_NONE);
    }

    log_atomic_op_end(session);
    dls_spin_unlock(session, &space->lock);

    if (db_save_space_ctrl(session, space->ctrl->id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when space set autopurge");
    }

    return GS_SUCCESS;
}

status_t spc_rename_datafiles(knl_session_t *session, space_t *space, galist_t *datafiles, galist_t *new_datafiles)
{
    knl_device_def_t *file = NULL;
    knl_device_def_t *new_file = NULL;

    if (!cm_spin_try_lock(&session->kernel->lock)) {
        GS_THROW_ERROR(ERR_DB_START_IN_PROGRESS);
        return GS_ERROR;
    }

    if (session->kernel->db.status != DB_STATUS_MOUNT) {
        cm_spin_unlock(&session->kernel->lock);
        GS_THROW_ERROR(ERR_DATABASE_NOT_MOUNT, "rename datafiles");
        return GS_ERROR;
    }

    if (!SPACE_IS_ONLINE(space)) {
        cm_spin_unlock(&session->kernel->lock);
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "rename datafiles failed");
        return GS_ERROR;
    }

    if (spc_mount_space(session, space, GS_FALSE) != GS_SUCCESS) {
        cm_spin_unlock(&session->kernel->lock);
        return GS_ERROR;
    }

    for (uint32 i = 0; i < datafiles->count; i++) {
        file = (knl_device_def_t *)cm_galist_get(datafiles, i);
        new_file = (knl_device_def_t *)cm_galist_get(new_datafiles, i);
        if (cm_text_equal_ins(&file->name, &new_file->name)) {
            continue;
        }

        if (spc_rename_datafile(session, space, &file->name, &new_file->name) != GS_SUCCESS) {
            cm_spin_unlock(&session->kernel->lock);
            return GS_ERROR;
        }
    }

    spc_umount_space(session, space);

    if (db_save_space_ctrl(session, space->ctrl->id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when space rename datafiles");
    }

    cm_spin_unlock(&session->kernel->lock);

    return GS_SUCCESS;
}

void spc_init_swap_space_bitmap(knl_session_t *session, space_t *space)
{
    datafile_t *df = NULL;
    space_head_t *spc_head = space->head;
    page_init(session, (page_head_t *)CURR_PAGE(session), space->entry, PAGE_TYPE_SPACE_HEAD);
    knl_securec_check(memset_sp(space->head, sizeof(space_head_t), 0, sizeof(space_head_t)));
    // free_extents will not be used for bitmap swap space
    spc_head->free_extents.first = INVALID_PAGID;
    spc_head->free_extents.last = INVALID_PAGID;
    space->swap_bitmap = GS_TRUE;

    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        if (GS_INVALID_ID32 == space->ctrl->files[i]) {
            continue;
        }

        df = DATAFILE_GET(session, space->ctrl->files[i]);
        spc_head->datafile_count++;
        // init map group and update hwms
        df_init_swap_map_head(session, df);
        spc_head->hwms[i] = DF_MAP_GROUP_SIZE;
    }

    GS_LOG_RUN_INF("[SPACE] init swap space %u bitmap head.", space->ctrl->id);
}

void spc_init_swap_space_normal(space_t *space)
{
    space_head_t *spc_head = space->head;

    spc_head->segment_count = 0;
    spc_head->free_extents.count = 0;
    spc_head->datafile_count = 0;
    spc_head->free_extents.first = INVALID_PAGID;
    spc_head->free_extents.last = INVALID_PAGID;
    space->swap_bitmap = GS_FALSE;

    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        if (GS_INVALID_ID32 == space->ctrl->files[i]) {
            continue;
        }

        spc_head->datafile_count++;
        spc_head->hwms[i] = (i == 0) ? DF_FIRST_HWM_START : DF_HWM_START;
    }
    GS_LOG_RUN_INF("[SPACE] init swap space %u normal head.", space->ctrl->id);
}

void spc_init_swap_space(knl_session_t *session, space_t *space)
{
    buf_enter_temp_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    if (SECUREC_LIKELY(SPACE_SWAP_BITMAP(space))) {
        spc_init_swap_space_bitmap(session, space);
    } else {
        spc_init_swap_space_normal(space);
    }
    buf_leave_temp_page(session);
}

#ifdef __cplusplus
}
#endif

