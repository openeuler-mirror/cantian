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
 * knl_space_log.c
 *
 *
 * IDENTIFICATION
 * src/kernel/tablespace/knl_space_log.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_space_module.h"
#include "knl_space_log.h"
#include "cm_file.h"
#include "knl_context.h"
#include "knl_ctrl_restore.h"
#include "knl_alter_space.h"
#include "knl_create_space.h"
#include "knl_drop_space.h"
#include "knl_punch_space.h"
#include "knl_shrink_space.h"
#include "knl_abr.h"
#include "dtc_database.h"
#include "dtc_dls.h"

#ifdef __cplusplus
extern "C" {
#endif

static void spc_active_encrypt_spc(knl_session_t *session, space_t *space)
{
    if (SPACE_IS_ENCRYPT(space)) {
        if (spc_active_undo_encrypt(session, dtc_my_ctrl(session)->undo_space) != CT_SUCCESS) {
            knl_panic_log(CT_FALSE, "fail to active undo encrypt");
        }
        if (spc_active_undo_encrypt(session, DB_CORE_CTRL(session)->temp_undo_space) != CT_SUCCESS) {
            knl_panic_log(CT_FALSE, "fail to active undo encrypt");
        }
        if (spc_active_swap_encrypt(session) != CT_SUCCESS) {
            knl_panic_log(CT_FALSE, "fail to active swap encrypt");
        }
    }
}

void rd_spc_create_space_internal(knl_session_t *session, rd_create_space_t *redo)
{
    space_t *space = SPACE_GET(session, redo->space_id);
    database_t *db = &session->kernel->db;
    uint32 name_len = CT_NAME_BUFFER_SIZE - 1;
    errno_t ret;

    // only one session process the same message from the same source.
    if (!session->log_diag && !DB_IS_CLUSTER(session)) {
        cm_latch_x(&session->kernel->db.ddl_latch.latch, session->id, NULL);
    }
    cm_spin_lock(&session->kernel->db.replay_logic_lock, NULL);
    if (space->ctrl->used) {
        knl_panic(db->ctrl.core.space_count > 0);
        CT_LOG_RUN_WAR("trying to redo create tablespace %s", redo->name);
        if (DB_IS_CLUSTER(session)) {
            CT_LOG_RUN_WAR("Do not redo create space %s, as it is already used", redo->name);
            cm_spin_unlock(&session->kernel->db.replay_logic_lock);
            return;
        }
        db->ctrl.core.space_count--;
    }

    // In standby or crash recovery, set the space to online status directly.
    space->ctrl->id = redo->space_id;
    space->ctrl->flag = redo->flags;
    space->ctrl->extent_size = redo->extent_size;
    space->ctrl->block_size = redo->block_size;
    space->ctrl->org_scn = redo->org_scn;
    space->ctrl->encrypt_version = redo->encrypt_version;
    space->ctrl->cipher_reserve_size = redo->cipher_reserve_size;
    space->ctrl->is_for_create_db = redo->is_for_create_db;
    space->is_empty = CT_FALSE;
    space->allow_extend = CT_TRUE;
    ret = memset_sp(&space->lock, sizeof(space->lock), 0, sizeof(space->lock));
    knl_securec_check(ret);
    dls_init_spinlock(&space->lock, DR_TYPE_SPACE, DR_ID_SPACE_OP, space->ctrl->id);

    space->ctrl->type = redo->type;

    spc_active_encrypt_spc(session, space);

    ret = strncpy_s(space->ctrl->name, CT_NAME_BUFFER_SIZE, redo->name, name_len);
    knl_securec_check(ret);
    space->ctrl->file_hwm = 0;

    ret = memset_s(space->ctrl->files, CT_MAX_SPACE_FILES * sizeof(uint32), 0xFF, CT_MAX_SPACE_FILES * sizeof(uint32));
    knl_securec_check(ret);

    space->ctrl->used = CT_TRUE;
    db->ctrl.core.space_count++;

    SPACE_SET_ONLINE(space);

    if (!DAAC_REPLAY_NODE(session) && db_save_space_ctrl(session, space->ctrl->id) != CT_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when create tablespace");
    }
    cm_spin_unlock(&session->kernel->db.replay_logic_lock);
    if (!session->log_diag && !DB_IS_CLUSTER(session)) {
        cm_unlatch(&session->kernel->db.ddl_latch.latch, NULL);
    }
}

void rd_spc_create_space(knl_session_t *session, log_entry_t *log)
{
    rd_create_space_t *redo = (rd_create_space_t *)log->data;
    rd_spc_create_space_internal(session, redo);
}

void print_spc_create_space_internal(rd_create_space_t *redo)
{
    (void)printf("name %s, id %u, flag %u, extent_size %u, block_size %u",
        redo->name, redo->space_id, redo->flags, redo->extent_size, redo->block_size);
    (void)printf("\n");
}

void print_spc_create_space(log_entry_t *log)
{
    rd_create_space_t *redo = (rd_create_space_t *)log->data;
    print_spc_create_space_internal(redo);
}

void print_spc_remove_space_internal(rd_remove_space_t *redo)
{
    (void)printf("id %u, options %u, org_scn %llu\n,", redo->space_id, redo->options, redo->org_scn);
}

void print_spc_remove_space(log_entry_t *log)
{
    rd_remove_space_t *redo = (rd_remove_space_t *)log->data;
    print_spc_remove_space_internal(redo);
}

static bool32 rd_spc_remove_space_precheck(knl_session_t *session, rd_remove_space_t *redo, space_t *space)
{
    if (SPACE_IS_DEFAULT(space)) {
        CT_LOG_RUN_ERR("[SPACE] replay remove space %u failed, forbid to drop database system space", redo->space_id);
        return CT_FALSE;
    }
    if (DAAC_REPLAY_NODE(session) && SPACE_IS_ONLINE(space) &&
        spc_check_default_tablespace(session, space) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[SPACE] replay remove space %u failed, it's the default tablespace for user", redo->space_id);
        return CT_FALSE;
    }
    if (!space->ctrl->used) {
        CT_LOG_RUN_WAR("trying to redo remove space.");
        session->kernel->db.ctrl.core.space_count++;
    }

    if (session->kernel->db.status == DB_STATUS_OPEN) {
        if (spc_check_object_exist(session, space) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[SPACE] failed to check if object exist");
            return CT_FALSE;
        }
    }
    return CT_TRUE;
}

void rd_spc_remove_space_internal(knl_session_t *session, rd_remove_space_t *redo)
{
    uint32 space_id = redo->space_id;
    space_t *space = SPACE_GET(session, space_id);
    database_t *db = &session->kernel->db;

    // only one session process the same message from the same source.
    if (!session->log_diag && !DB_IS_CLUSTER(session)) {
        cm_latch_x(&session->kernel->db.ddl_latch.latch, session->id, NULL);
    }

    if (!rd_spc_remove_space_precheck(session, redo, space)) {
        if (!session->log_diag && !DB_IS_CLUSTER(session)) {
            cm_unlatch(&session->kernel->db.ddl_latch.latch, NULL);
        }
        return;
    }

    cm_spin_lock(&session->kernel->db.replay_logic_lock, NULL);

    if (space->ctrl->org_scn != redo->org_scn) {
        CT_LOG_RUN_INF("No need to redo remove space, space slot is already been dropped or recycled.");
        if (!space->ctrl->used) {
            session->kernel->db.ctrl.core.space_count--;
        }
        cm_spin_unlock(&session->kernel->db.replay_logic_lock);
        if (!session->log_diag && !DB_IS_CLUSTER(session)) {
            cm_unlatch(&session->kernel->db.ddl_latch.latch, NULL);
        }
        return;
    }

    knl_panic(db->ctrl.core.space_count > 0);

    if (!DB_IS_CLUSTER(session)) {
        ckpt_trigger(session, CT_TRUE, CKPT_TRIGGER_FULL);
        spc_wait_data_buffer(session, space);
        (void)spc_remove_space(session, space, redo->options, CT_TRUE);
    } else {
        if (!DB_IS_PRIMARY(&session->kernel->db) && rc_is_master()) {
            ckpt_trigger(session, CT_TRUE, CKPT_TRIGGER_FULL);
        }
        spc_wait_data_buffer(session, space);
        CT_LOG_RUN_INF("logic to remove space id is %d.", space_id);
        if (spc_remove_space(session, space, redo->options, CT_FALSE) != CT_SUCCESS && DAAC_REPLAY_NODE(session)) {
            if (!space->ctrl->used) {
                session->kernel->db.ctrl.core.space_count--;
            }
            cm_spin_unlock(&session->kernel->db.replay_logic_lock);
            return;
        }
    }

    (void)spc_try_inactive_swap_encrypt(session);

    if (!DAAC_REPLAY_NODE(session) && db_save_space_ctrl(session, space->ctrl->id) != CT_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file");
    }

    cm_spin_unlock(&session->kernel->db.replay_logic_lock);
    if (!session->log_diag && !DB_IS_CLUSTER(session)) {
        cm_unlatch(&session->kernel->db.ddl_latch.latch, NULL);
    }
}

void rd_spc_remove_space(knl_session_t *session, log_entry_t *log)
{
    rd_remove_space_t *redo = (rd_remove_space_t *)log->data;
    rd_spc_remove_space_internal(session, redo);
}

static void update_spc_ctrl(knl_session_t *session, rd_create_datafile_t *redo, space_t *space)
{
    space->ctrl->files[redo->file_no] = redo->id;
    if (redo->file_no == 0) {
        space->entry.file = redo->id;
        space->entry.page = SPACE_ENTRY_PAGE;
    }
    if (redo->file_no >= space->ctrl->file_hwm) {
        space->ctrl->file_hwm++;
    }

    if (!DAAC_REPLAY_NODE(session) && (CT_SUCCESS != db_save_space_ctrl(session, space->ctrl->id))) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file");
    }
}

void rd_spc_create_datafile_internal(knl_session_t *session, rd_create_datafile_t *redo)
{
    space_t *space = SPACE_GET(session, redo->space_id);
    datafile_t *df = DATAFILE_GET(session, redo->id);
    database_t *db = &session->kernel->db;
    knl_attr_t *attr = &session->kernel->attr;
    uint32 name_len = CT_FILE_NAME_BUFFER_SIZE - 1;
    page_id_t space_head;
    errno_t ret;
    bool32 need_rename = CT_FALSE;
    char old_name[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    redo->name[CT_FILE_NAME_BUFFER_SIZE - 1] = 0;

    /* Only replay one page when page is repairing, we need init page to zero and do not operate datafile */
    if (IS_BLOCK_RECOVER(session)) {
        abr_clear_page(session, redo->id);
        return;
    }

    if (!session->log_diag) {
        if (!DB_IS_CLUSTER(session)) {
            cm_latch_x(&session->kernel->db.ddl_latch.latch, session->id, NULL);
        }
    }

    // only one session process the same message from the same source.
    if (df->ctrl->used) {
        knl_panic(db->ctrl.core.device_count > 0);
        CT_LOG_RUN_WAR("trying to redo create datafile %s", redo->name);
        if (DB_IS_CLUSTER(session) && !IS_SWAP_SPACE(space)) {
            // do not recreate datafile after df has aleady been create, but the space ctrl may need to update
            // update space ctrl, skip the offlined df
            CT_LOG_RUN_WAR("Do not redo create datafile %s, as it is already used", redo->name);
            if (DATAFILE_IS_ONLINE(df) && space->ctrl->used && space->ctrl->files[redo->file_no] == CT_INVALID_ID32) {
                update_spc_ctrl(session, redo, space);
            }
            return;
        }
        if (DAAC_REPLAY_NODE(session)) {
            if (df->ctrl->size != redo->size) {
                CT_LOG_RUN_ERR("replay create df %s failed, df size not match ", redo->name);
                return;
            }
        }
        db->ctrl.core.device_count--;
        if (IS_SWAP_SPACE(space)) {
            space->head->datafile_count--;
        }
        /* expire space head in buffer */
        if (redo->file_no == 0) {
            space_head.file = redo->id;
            space_head.page = SPACE_ENTRY_PAGE;
            space_head.aligned = 0;
            buf_expire_page(session, space_head);
        }

        /* expire map head of datafile in bitmap space */
        if (SPACE_IS_BITMAPMANAGED(space)) {
            buf_expire_page(session, df->map_head_entry);
        }
    }

    if (!space->ctrl->used) {
        if (!session->log_diag) {
            if (!DB_IS_CLUSTER(session)) {
                cm_unlatch(&session->kernel->db.ddl_latch.latch, NULL);
            }
        }
        return;
    }

    df->space_id = redo->space_id;
    df->file_no = redo->file_no;
    df->ctrl->size = (int64)redo->size;
    df->ctrl->block_size = space->ctrl->block_size;
    knl_panic(df->ctrl->block_size != 0);

    df->ctrl->id = redo->id;

    df->ctrl->auto_extend_size = redo->auto_extend_size;
    df->ctrl->auto_extend_maxsize = redo->auto_extend_maxsize;
    df->ctrl->type = redo->type;

    if (db_change_storage_path(&attr->data_file_convert, redo->name, CT_FILE_NAME_BUFFER_SIZE) != CT_SUCCESS) {
        if (!session->log_diag) {
            if (!DB_IS_CLUSTER(session)) {
                cm_unlatch(&session->kernel->db.ddl_latch.latch, NULL);
            }
        }
        return;
    }

    if (df->ctrl->used) {
        text_t ctrl_name_text;
        text_t redo_name_text;
        cm_str2text(redo->name, &redo_name_text);
        cm_str2text(df->ctrl->name, &ctrl_name_text);
        if (!cm_text_equal(&redo_name_text, &ctrl_name_text) && cm_exist_device(df->ctrl->type, df->ctrl->name)) {
            need_rename = CT_TRUE;
            ret = strncpy_s(old_name, CT_FILE_NAME_BUFFER_SIZE, df->ctrl->name, name_len);
            knl_securec_check(ret);
        }
    }

    ret = strncpy_s(df->ctrl->name, CT_FILE_NAME_BUFFER_SIZE, redo->name, name_len);
    knl_securec_check(ret);

    if (!DAAC_REPLAY_NODE(session)) {
        if (cm_exist_device(df->ctrl->type, df->ctrl->name) || cm_exist_device(df->ctrl->type, old_name)) {
            if (need_rename) {
                knl_panic_log(!cm_exist_device(df->ctrl->type, df->ctrl->name),
                              "new file %s should not exist, old file %s already exists", df->ctrl->name, old_name);
                if (cm_rename_device(df->ctrl->type, old_name, df->ctrl->name) != CT_SUCCESS) {
                    CM_ABORT(0, "[SPACE] ABORT INFO: failed to rename datafile from %s to %s", old_name,
                             df->ctrl->name);
                }
                CT_LOG_RUN_INF("succeed to rename datafile from %s to %s", old_name, df->ctrl->name);
            }
            if (spc_open_datafile(session, df, DATAFILE_FD(session, df->ctrl->id)) != CT_SUCCESS) {
                CM_ABORT(0, "[SPACE] ABORT INFO: datafile %s break down, try to offline it in MOUNT mode",
                         df->ctrl->name);
            }

            if (cm_truncate_device(df->ctrl->type, *(DATAFILE_FD(session, df->ctrl->id)), 0) != CT_SUCCESS) {
                CM_ABORT(0, "[SPACE] ABORT INFO: failed to truncate datafile %s", df->ctrl->name);
            }

            if (cm_extend_device(df->ctrl->type, *(DATAFILE_FD(session, df->ctrl->id)),
                                 session->kernel->attr.xpurpose_buf, CT_XPURPOSE_BUFFER_SIZE, (int64)redo->size,
                                 session->kernel->attr.build_datafile_prealloc) != CT_SUCCESS) {
                CM_ABORT(0, "[SPACE] ABORT INFO: failed to rebuild datafile %s", df->ctrl->name);
            }

            if (df->ctrl->type == DEV_TYPE_FILE &&
                db_fsync_file(session, *(DATAFILE_FD(session, df->ctrl->id))) != CT_SUCCESS) {
                CM_ABORT(0, "[SPACE] ABORT INFO: failed to fsync datafile %s", df->ctrl->name);
            }
        } else {
            if (CT_SUCCESS != spc_build_datafile(session, df, DATAFILE_FD(session, df->ctrl->id))) {
                CM_ABORT(0, "[SPACE] ABORT INFO: failed to build datafile %s", df->ctrl->name);
            }
            df->ctrl->create_version++;

            if (spc_open_datafile(session, df, DATAFILE_FD(session, df->ctrl->id)) != CT_SUCCESS) {
                CM_ABORT(0, "[SPACE] ABORT INFO: datafile %s break down, try to offline it in MOUNT mode",
                         df->ctrl->name);
            }
        }
    }

    if (!DAAC_REPLAY_NODE(session) && spc_init_datafile_head(session, df) != CT_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save control file for datafile %s", df->ctrl->name);
    }

    df->ctrl->flag = redo->flags;
    df->ctrl->used = CT_TRUE;
    DATAFILE_SET_ONLINE(df);

    db->ctrl.core.device_count++;

    if (!DAAC_REPLAY_NODE(session) && (CT_SUCCESS != db_save_datafile_ctrl(session, df->ctrl->id))) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file");
    }

    update_spc_ctrl(session, redo, space);

    /* backup sapce ctrl info after datafile is created */
    if (db->ctrl.core.db_role != REPL_ROLE_PRIMARY) {
        if (!DAAC_REPLAY_NODE(session) && ctrl_backup_space_ctrl(session, space->ctrl->id) != CT_SUCCESS) {
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to backup space ctrl info");
        }
    }

    if (IS_SWAP_SPACE(space)) {
        space->head->datafile_count++;
        spc_init_swap_space(session, space);
    }

    if (!session->log_diag) {
        if (!DB_IS_CLUSTER(session)) {
            cm_unlatch(&session->kernel->db.ddl_latch.latch, NULL);
        }
    }
}

void rd_spc_create_datafile(knl_session_t *session, log_entry_t *log)
{
    rd_create_datafile_t *redo = (rd_create_datafile_t *)log->data;
    rd_spc_create_datafile_internal(session, redo);
}

void print_spc_create_datafile_internal(rd_create_datafile_t *redo)
{
    (void)printf("name %s, id %u, space_id %u, file_no %u, size %llu, auto_extend %d, "
                 "auto_extend_size %lld, max_extend_size %lld\n",
                 redo->name, redo->id, redo->space_id, redo->file_no, redo->size,
                 (redo->flags & DATAFILE_FLAG_AUTO_EXTEND), redo->auto_extend_size, redo->auto_extend_maxsize);
}

void print_spc_create_datafile(log_entry_t *log)
{
    rd_create_datafile_t *redo = (rd_create_datafile_t *)log->data;
    print_spc_create_datafile_internal(redo);
}

void rd_spc_extend_undo_segments(knl_session_t *session, log_entry_t *log)
{
    rd_extend_undo_segments_t *redo = (rd_extend_undo_segments_t *)log->data;
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(session);
    char seg_count[CT_MAX_UINT32_STRLEN] = { 0 };
    errno_t ret;
    undo_set_t *undo_set = MY_UNDO_SET(session);

    if (redo->undo_segments <= core_ctrl->undo_segments) {
        return;
    }

    if (!DB_IS_PRIMARY(&session->kernel->db)) {
        undo_init_impl(session, undo_set, redo->old_undo_segments, redo->undo_segments);
        if (tx_area_init_impl(session, undo_set, redo->old_undo_segments, redo->undo_segments, CT_TRUE) != CT_SUCCESS) {
            uint16 extend_cnt = redo->undo_segments - redo->old_undo_segments;
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to allocate memory for extend %u undo segments", extend_cnt);
        }
        tx_area_release_impl(session, redo->old_undo_segments, redo->undo_segments);
        ckpt_trigger(session, CT_TRUE, CKPT_TRIGGER_FULL);
    }

    core_ctrl->undo_segments = redo->undo_segments;
    core_ctrl->undo_segments_extended = CT_TRUE;

    if (db_save_core_ctrl(session) != CT_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file");
    }

    ret = sprintf_s(seg_count, CT_MAX_UINT32_STRLEN, "%u", redo->undo_segments);
    knl_securec_check_ss(ret);
    UNDO_SEGMENT_COUNT(session) = redo->undo_segments;
    if (cm_alter_config(session->kernel->attr.config, "_UNDO_SEGMENTS", seg_count, CONFIG_SCOPE_BOTH, CT_TRUE) != CT_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save config");
    }

    CT_LOG_RUN_INF("[SPACE LOG] replay extend undo segments from %u to %u completed", redo->old_undo_segments, redo->undo_segments);
}

void print_spc_extend_undo_segments(log_entry_t *log)
{
    rd_extend_undo_segments_t *redo = (rd_extend_undo_segments_t *)log->data;
    (void)printf("extend undo segments from %u to %u\n", redo->old_undo_segments, redo->undo_segments);
}

void rd_ckpt_trigger(knl_session_t *session, bool32 wait, ckpt_mode_t mode)
{
    page_id_t page_id = session->curr_page_ctrl->page_id;
    uint8 options = session->curr_page_ctrl->is_resident ? ENTER_PAGE_RESIDENT : ENTER_PAGE_NORMAL;

    buf_leave_page(session, CT_FALSE);

    ckpt_trigger(session, wait, mode);

    buf_enter_page(session, page_id, LATCH_MODE_X, options);
}

static void rd_spc_remove_datafile_(knl_session_t *session, datafile_t *df, space_t *space, rd_remove_datafile_t *redo)
{
    database_t *db = &session->kernel->db;
    if (!DAAC_REPLAY_NODE(session) && !DB_IS_PRIMARY(&(session->kernel->db))) {
        ckpt_trigger(session, CT_TRUE, CKPT_TRIGGER_FULL);
    }

    if (space->ctrl->files[redo->file_no] != CT_INVALID_ID32) {
        space->ctrl->files[redo->file_no] = CT_INVALID_ID32;
        db->ctrl.core.device_count--;
    }

    if (!DAAC_REPLAY_NODE(session) && db_save_space_ctrl(session, space->ctrl->id) != CT_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole space control file when rd_remove datafile");
    }

    DATAFILE_UNSET_ONLINE(df);
    df->ctrl->used = CT_FALSE;
    if (!DAAC_REPLAY_NODE(session) && db_save_datafile_ctrl(session, df->ctrl->id) != CT_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save datafile control file when offline datafile");
    }

    if (!DAAC_REPLAY_NODE(session)) {
        spc_remove_datafile_device(session, df);
    }

    df->space_id = CT_INVALID_ID32;
    df->ctrl->size = 0;
    df->ctrl->name[0] = '\0';
}

void rd_spc_remove_datafile_interanal(knl_session_t *session, rd_remove_datafile_t *redo)
{
    space_t *space = SPACE_GET(session, redo->space_id);
    space_head_t *head = SPACE_HEAD(session);
    datafile_t *df = DATAFILE_GET(session, redo->id);
    if (df->space_id != redo->space_id || space->ctrl->file_hwm == 0 || df->file_no != redo->file_no ||
        space->ctrl->files[df->file_no] != redo->id) {
        CT_LOG_RUN_ERR("replay remove datafile failed, redo spc id %u, file no %u not match df %u spc id %u file no %u",
                       redo->space_id, redo->file_no, redo->id, df->space_id, df->file_no);
        return;
    }

    if (!session->log_diag && !DAAC_REPLAY_NODE(session) && !DB_IS_PRIMARY(&(session->kernel->db))) {
        rd_ckpt_trigger(session, CT_TRUE, CKPT_TRIGGER_FULL);
    }

    // only one session process the same message from the same source.
    if (df->ctrl->used == CT_FALSE) {
        CT_LOG_RUN_INF("has remove datafile, file %u.\n", redo->id);
        return;
    }
    /* Only replay one page when page is repairing, we need init page to zero and do not operate datafile */
    if (IS_BLOCK_RECOVER(session)) {
        abr_clear_page(session, redo->id);
        return;
    }

    if (IS_SWAP_SPACE(space)) {
        if (space->ctrl->files[redo->file_no] != CT_INVALID_ID32) {
            head->datafile_count--;
            head->hwms[redo->file_no] = 0;
        }
    } else {
        if (!DAAC_REPLAY_NODE(session)) {  // todo: how does head->hwm changes? how does this resident page changes?
            head->datafile_count--;
            head->hwms[redo->file_no] = 0;
        }
    }

    if (!session->log_diag) {
        if (!DB_IS_CLUSTER(session)) {
            cm_latch_x(&session->kernel->db.ddl_latch.latch, session->id, NULL);
        }

        spc_invalidate_datafile(session, df, CT_TRUE);
        rd_spc_remove_datafile_(session, df, space, redo);
    }

    if (!session->log_diag) {
        if (!DAAC_REPLAY_NODE(session) && db_save_datafile_ctrl(session, df->ctrl->id) != CT_SUCCESS) {
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when rd_remove datafile");
        }

        if (!DB_IS_CLUSTER(session)) {  // todo: check this condition
            cm_unlatch(&session->kernel->db.ddl_latch.latch, NULL);
        }
    }
}

void rd_spc_remove_datafile(knl_session_t *session, log_entry_t *log)
{
    rd_remove_datafile_t *redo = (rd_remove_datafile_t *)log->data;
    rd_spc_remove_datafile_interanal(session, redo);
}

void print_spc_remove_datafile_internal(rd_remove_datafile_t *redo)
{
    (void)printf("id %u, space_id %u, file_no %u\n", redo->id, redo->space_id, redo->file_no);
}

void print_spc_remove_datafile(log_entry_t *log)
{
    rd_remove_datafile_t *redo = (rd_remove_datafile_t *)log->data;
    print_spc_remove_datafile_internal(redo);
}

void rd_spc_update_head(knl_session_t *session, log_entry_t *log)
{
    rd_update_head_t *redo = (rd_update_head_t *)log->data;
    space_t *space = SPACE_GET(session, redo->space_id);
    space_head_t *head = (space_head_t *)(CURR_PAGE(session) + PAGE_HEAD_SIZE);
    errno_t ret;

    if (0 == redo->file_no) {
        if (!session->log_diag) {
            session->curr_page_ctrl->is_resident = 1;
            space->head = head;
        }
        page_init(session, (page_head_t *)CURR_PAGE(session), redo->entry, PAGE_TYPE_SPACE_HEAD);
        ret = memset_sp(head, sizeof(space_head_t), 0, sizeof(space_head_t));
        knl_securec_check(ret);
        head->free_extents.first = INVALID_PAGID;
        head->free_extents.last = INVALID_PAGID;
        spc_try_init_punch_head(session, space);
    }

    head->hwms[redo->file_no] = spc_get_hwm_start(session, space,
                                                  DATAFILE_GET(session, space->ctrl->files[redo->file_no]));
    head->datafile_count++;

    if (IS_BLOCK_RECOVER(session)) {
        return; // do not modify ctrl files when repair page use ztrst tool
    }

    if (!DAAC_REPLAY_NODE(session) && !session->log_diag &&
        (CT_SUCCESS != db_save_space_ctrl(session, space->ctrl->id))) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file");
    }
}

void print_spc_update_head(log_entry_t *log)
{
    rd_update_head_t *redo = (rd_update_head_t *)log->data;
    (void)printf("head %u-%u, space_id %u, file_no %u\n",
        (uint32)redo->entry.file, (uint32)redo->entry.page, (uint32)redo->space_id, (uint32)redo->file_no);
}

void rd_spc_change_segment(knl_session_t *session, log_entry_t *log)
{
    uint32 count = *(uint32 *)log->data;
    space_head_t *head = (space_head_t *)(CURR_PAGE(session) + PAGE_HEAD_SIZE);
    head->segment_count = count;
}

void print_spc_change_segment(log_entry_t *log)
{
    uint32 count = *(uint32 *)log->data;
    (void)printf("count %u\n", count);
}

void rd_spc_update_hwm(knl_session_t *session, log_entry_t *log)
{
    rd_update_hwm_t *redo = (rd_update_hwm_t *)log->data;
    space_head_t *head = (space_head_t *)(CURR_PAGE(session) + PAGE_HEAD_SIZE);
    head->hwms[redo->file_no] = redo->file_hwm;
}

void print_spc_update_hwm(log_entry_t *log)
{
    rd_update_hwm_t *redo = (rd_update_hwm_t *)log->data;
    (void)printf("file_no %u, file_hwm %u\n", redo->file_no, redo->file_hwm);
}

void rd_spc_alloc_extent(knl_session_t *session, log_entry_t *log)
{
    page_list_t *extents = (page_list_t *)log->data;
    space_head_t *head = (space_head_t *)(CURR_PAGE(session) + PAGE_HEAD_SIZE);

    head->free_extents = *extents;
}

void print_spc_alloc_extent(log_entry_t *log)
{
    page_list_t *extents = (page_list_t *)log->data;
    (void)printf("count %u, first %u-%u, last %u-%u\n", extents->count,
        (uint32)extents->first.file, (uint32)extents->first.page,
        (uint32)extents->last.file, (uint32)extents->last.page);
}

void rd_spc_free_extent(knl_session_t *session, log_entry_t *log)
{
    page_list_t *extents = (page_list_t *)log->data;
    space_head_t *head = (space_head_t *)(CURR_PAGE(session) + PAGE_HEAD_SIZE);

    head->free_extents = *extents;
}

void print_spc_free_extent(log_entry_t *log)
{
    page_list_t *extents = (page_list_t *)log->data;
    (void)printf("count %u, first %u-%u, last %u-%u\n", extents->count,
        (uint32)extents->first.file, (uint32)extents->first.page,
        (uint32)extents->last.file, (uint32)extents->last.page);
}

void rd_spc_set_autoextend_internal(knl_session_t *session, rd_set_space_autoextend_t *redo)
{
    space_t *space = SPACE_GET(session, (uint32)redo->space_id);
    datafile_t *df = NULL;

    if (!space->ctrl->used) {
        return;
    }

    for (uint32 i = 0; i < CT_MAX_SPACE_FILES; i++) {
        if (CT_INVALID_ID32 == space->ctrl->files[i]) {
            continue;
        }

        df = DATAFILE_GET(session, space->ctrl->files[i]);
        if (redo->auto_extend) {
            DATAFILE_SET_AUTO_EXTEND(df);
        } else {
            DATAFILE_UNSET_AUTO_EXTEND(df);
        }
        df->ctrl->auto_extend_size = redo->auto_extend_size;
        df->ctrl->auto_extend_maxsize = redo->auto_extend_maxsize;

        if (!DAAC_REPLAY_NODE(session) && db_save_datafile_ctrl(session, df->ctrl->id) != CT_SUCCESS) {
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole ctrl files");
        }
    }
}

void rd_spc_set_autoextend(knl_session_t *session, log_entry_t *log)
{
    rd_set_space_autoextend_t *redo = (rd_set_space_autoextend_t *)log->data;
    rd_spc_set_autoextend_internal(session, redo);
}

void print_spc_set_autoextend_internal(rd_set_space_autoextend_t *rd)
{
    (void)printf("spc get autoextend space_id:%u,auto_extend:%u,next size:%lld,max size:%lld\n",
        rd->space_id, rd->auto_extend, rd->auto_extend_size, rd->auto_extend_maxsize);
}

void print_spc_set_autoextend(log_entry_t *log)
{
    rd_set_space_autoextend_t *rd = (rd_set_space_autoextend_t *)log->data;
    print_spc_set_autoextend_internal(rd);
}

void rd_spc_set_flag_internal(knl_session_t *session, rd_set_space_flag_t *redo)
{
    space_t *space = SPACE_GET(session, (uint32)redo->space_id);

    if (!space->ctrl->used) {
        return;
    }

    space->ctrl->flag = redo->flags;

    if (!DAAC_REPLAY_NODE(session) && db_save_space_ctrl(session, space->ctrl->id) != CT_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole ctrl files");
    }
}

void rd_spc_set_flag(knl_session_t *session, log_entry_t *log)
{
    rd_set_space_flag_t *redo = (rd_set_space_flag_t *)log->data;
    rd_spc_set_flag_internal(session, redo);
}

void print_spc_set_flag_internal(rd_set_space_flag_t *rd)
{
    (void)printf("spc set flag space_id:%u, flag %u\n", rd->space_id, (uint32)rd->flags);
}

void print_spc_set_flag(log_entry_t *log)
{
    rd_set_space_flag_t *rd = (rd_set_space_flag_t *)log->data;
    print_spc_set_flag_internal(rd);
}

void rd_spc_rename_space_internal(knl_session_t *session, rd_rename_space_t *redo)
{
    space_t *space = SPACE_GET(session, redo->space_id);
    uint32 name_len = CT_NAME_BUFFER_SIZE - 1;
    errno_t ret;

    if (!space->ctrl->used) {
        return;
    }
    redo->name[CT_NAME_BUFFER_SIZE - 1] = 0;
    text_t redo_name_text;
    cm_str2text(redo->name, &redo_name_text);
    if (spc_check_space_exists(session, &redo_name_text, CT_FALSE)) {
        CT_LOG_RUN_ERR("[DC] no need to replay rename space, spaceb name %s already exist", redo->name);
        return;
    }
    ret = strncpy_s(space->ctrl->name, CT_NAME_BUFFER_SIZE, redo->name, name_len);
    knl_securec_check(ret);

    if (!DAAC_REPLAY_NODE(session) && db_save_space_ctrl(session, space->ctrl->id) != CT_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole ctrl files");
    }
}

void rd_spc_rename_space(knl_session_t *session, log_entry_t *log)
{
    rd_rename_space_t *redo = (rd_rename_space_t *)log->data;
    rd_spc_rename_space_internal(session, redo);
}

void rd_spc_shrink_ckpt(knl_session_t *session, log_entry_t *log)
{
    if (log->size != CM_ALIGN4(sizeof(rd_shrink_space_t)) + LOG_ENTRY_SIZE) {
        CT_LOG_RUN_ERR("no need to replay shrink ckpt, log size %u is wrong", log->size);
        return;
    }
    rd_shrink_space_t *redo = (rd_shrink_space_t *)log->data;
    if (redo->space_id >= CT_MAX_SPACES) {
        CT_LOG_RUN_ERR("no need to replay shrink ckpt, invalid space id %u", redo->space_id);
        return;
    }
    space_t *space = SPACE_GET(session, redo->space_id);

    if (!space->ctrl->used) {
        return;
    }

    ckpt_trigger(session, CT_TRUE, CKPT_TRIGGER_FULL);
}

void print_spc_rename_space_internal(rd_rename_space_t *rd)
{
    (void)printf("spc rename space space_id:%u,name:%s\n", rd->space_id, rd->name);
}

void print_spc_rename_space(log_entry_t *log)
{
    rd_rename_space_t *rd = (rd_rename_space_t *)log->data;
    print_spc_rename_space_internal(rd);
}

void print_spc_shrink_ckpt(log_entry_t *log)
{
    rd_shrink_space_t *rd = (rd_shrink_space_t *)log->data;
    (void)printf("spc shrink space space_id:%u checkpoint\n", rd->space_id);
}

void rd_spc_concat_extent(knl_session_t *session, log_entry_t *log)
{
    page_id_t page_id = *(page_id_t *)log->data;
    page_head_t *page_head = (page_head_t *)CURR_PAGE(session);
    TO_PAGID_DATA(page_id, page_head->next_ext);
}

void print_spc_concat_extent(log_entry_t *log)
{
    page_id_t page_id = *(page_id_t *)log->data;
    (void)printf("next %u-%u\n", (uint32)page_id.file, (uint32)page_id.page);
}

void rd_spc_free_page(knl_session_t *session, log_entry_t *log)
{
    page_head_t *page_head = (page_head_t *)CURR_PAGE(session);
    page_free(session, page_head);
    buf_unreside(session, session->curr_page_ctrl);
}

void print_spc_free_page(log_entry_t *log)
{
    page_id_t page_id = *(page_id_t *)log->data;
    (void)printf("page %u-%u\n", (uint32)page_id.file, (uint32)page_id.page);
}

void rd_spc_extend_datafile_internal(knl_session_t *session, rd_extend_datafile_t *redo)
{
    if (redo->id >= CT_MAX_DATA_FILES) {
        CT_LOG_RUN_ERR("replay extend datafile fail, df id %u is invalid", redo->id);
        return;
    }
    datafile_t *df = DATAFILE_GET(session, redo->id);
    int32 *handle = DATAFILE_FD(session, redo->id);
    bool32 need_lock = KNL_GBP_ENABLE(session->kernel);

    if (!df->ctrl->used || !DATAFILE_IS_ONLINE(df)) {
        return;
    }

    space_t *space = SPACE_GET(session, df->space_id);
    uint64 max_file_size = (uint64)MAX_FILE_PAGES(space->ctrl->type) * DEFAULT_PAGE_SIZE(session);
    if (redo->size > df->ctrl->auto_extend_maxsize || redo->size > max_file_size) {
        CT_LOG_RUN_ERR("replay extend datafile %u fail, extend size %llu is invalid", redo->id, redo->size);
        return;
    }

    if (need_lock) { // concurrency with gbp_aly_spc_extend_datafile in gbp_aly_proc
        cm_spin_lock(&session->kernel->gbp_aly_ctx.extend_lock, NULL);
    }

    if (df->ctrl->size < redo->size) {
        if (DAAC_REPLAY_NODE(session)) {
            df->ctrl->size = redo->size;
        } else {
            if (*handle == -1) {
                if (spc_open_datafile(session, df, handle) != CT_SUCCESS) {
                    CM_ABORT(0, "[SPACE] ABORT INFO: failed to open file %s when extending datafile, error code is %d",
                             df->ctrl->name, errno);
                }
            }

            knl_attr_t *attr = &(session->kernel->attr);
            // if a node crashed after write redo log, but before sync_ddl, the reformer's df->ctrl->size may be staled,
            // thus, before extend the physical datafile, get its real size first to prevent re-extend
            int64 offset = cm_device_size(df->ctrl->type, *handle);
            if (offset == -1) {
                CT_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_END, errno);
                CM_ABORT(0, "[REDO] ABORT INFO: failed to extend datafile %s, error code is %d", df->ctrl->name, errno);
            }
            if (offset < redo->size) {
                if (cm_extend_device(df->ctrl->type, *handle, attr->xpurpose_buf, CT_XPURPOSE_BUFFER_SIZE,
                                     redo->size - df->ctrl->size, attr->build_datafile_prealloc) != CT_SUCCESS) {
                    CM_ABORT(0, "[REDO] ABORT INFO: failed to extend datafile %s, error code is %d", df->ctrl->name,
                             errno);
                }

                if (db_fsync_file(session, *handle) != CT_SUCCESS) {
                    CM_ABORT(0, "[REDO] ABORT INFO: failed to fsync datafile %s", df->ctrl->name);
                }
            }

            df->ctrl->size = redo->size;

            if (db_save_datafile_ctrl(session, df->ctrl->id) != CT_SUCCESS) {
                CM_ABORT(0, "[REDO] ABORT INFO: failed to save whole ctrl files");
            }
        }
    }

    if (need_lock) {
        cm_spin_unlock(&session->kernel->gbp_aly_ctx.extend_lock);
    }
}

void rd_spc_extend_datafile(knl_session_t *session, log_entry_t *log)
{
    rd_extend_datafile_t *redo = (rd_extend_datafile_t *)log->data;
    rd_spc_extend_datafile_internal(session, redo);
}

void gbp_aly_spc_extend_datafile(knl_session_t *session, log_entry_t *log, uint64 lsn)
{
    if (KNL_GBP_SAFE(session->kernel)) {
        rd_spc_extend_datafile(session, log);
    } else {
        gbp_aly_unsafe_entry(session, log, lsn);
    }
}

void rd_spc_truncate_datafile_internal(knl_session_t *session, rd_truncate_datafile_t *redo)
{
    if (redo->id >= CT_MAX_DATA_FILES) {
        CT_LOG_RUN_ERR("replay truncate datafile fail, df id %u is invalid", redo->id);
        return;
    }
    datafile_t *df = DATAFILE_GET(session, redo->id);
    int32 *handle = DATAFILE_FD(session, redo->id);

    if (!df->ctrl->used || !DATAFILE_IS_ONLINE(df)) {
        return;
    }

    space_t *space = NULL;
    space = SPACE_GET(session, df->space_id);
    uint64 min_file_size = spc_get_datafile_minsize_byspace(session, space);
    uint64 min_keep_size = 0;
    min_keep_size = MAX(min_file_size,
                        ((int64)SPACE_HEAD_RESIDENT(session, space)->hwms[df->file_no] * DEFAULT_PAGE_SIZE(session)));
    if (redo->size < min_keep_size) {
        CT_LOG_RUN_ERR("replay truncate datafile fail, truncate keep size %llu is invalid", redo->size);
        return;
    }

    if (df->ctrl->size > redo->size) {
        if (DAAC_REPLAY_NODE(session)) {
            df->ctrl->size = redo->size;
        } else {
            if (*handle == -1) {
                if (spc_open_datafile(session, df, handle) != CT_SUCCESS) {
                    CM_ABORT(0, "[SPACE] ABORT INFO: failed to open file %s when truncate datafile, error code is %d",
                             df->ctrl->name, errno);
                }
            }
            df->ctrl->size = redo->size;

            if (cm_truncate_device(df->ctrl->type, *handle, redo->size) != CT_SUCCESS) {
                CM_ABORT(0, "[REDO] ABORT INFO: failed to truncate datafile %s, error code is %d", df->ctrl->name,
                         errno);
            }

            if (db_fsync_file(session, *handle) != CT_SUCCESS) {
                CM_ABORT(0, "[REDO] ABORT INFO: failed to fsync datafile %s", df->ctrl->name);
            }

            if (db_save_datafile_ctrl(session, df->ctrl->id) != CT_SUCCESS) {
                CM_ABORT(0, "[REDO] ABORT INFO: failed to save whole ctrl files");
            }
        }
    }
}

void rd_spc_truncate_datafile(knl_session_t *session, log_entry_t *log)
{
    rd_truncate_datafile_t *redo = (rd_truncate_datafile_t *)log->data;
    rd_spc_truncate_datafile_internal(session, redo);
}

void rd_spc_extend_datafile_daac(knl_session_t *session, log_entry_t *log)
{
    if (!DAAC_REPLAY_NODE(session)) {
        return;
    }
    if (log->size != CM_ALIGN4(sizeof(rd_extend_datafile_daac_t)) + LOG_ENTRY_SIZE) {
        CT_LOG_RUN_ERR("no need to replay extend datafile, log size %u is wrong", log->size);
        return;
    }
    rd_extend_datafile_daac_t *redo = (rd_extend_datafile_daac_t *)log->data;
    rd_spc_extend_datafile_internal(session, &redo->datafile);
}

void rd_spc_truncate_datafile_daac(knl_session_t *session, log_entry_t *log)
{
    if (!DAAC_REPLAY_NODE(session)) {
        return;
    }
    if (log->size != CM_ALIGN4(sizeof(rd_truncate_datafile_daac_t)) + LOG_ENTRY_SIZE) {
        CT_LOG_RUN_ERR("no need to replay truncate datafile, log size %u is wrong", log->size);
        return;
    }
    rd_truncate_datafile_daac_t *redo = (rd_truncate_datafile_daac_t *)log->data;
    rd_spc_truncate_datafile_internal(session, &redo->datafile);
}

void print_spc_extend_datafile_internal(rd_extend_datafile_t *redo)
{
    printf("id %u, new_size %lld\n", redo->id, redo->size);
}

void print_spc_extend_datafile(log_entry_t *log)
{
    rd_extend_datafile_t *redo = (rd_extend_datafile_t *)log->data;
    print_spc_extend_datafile_internal(redo);
}

void print_spc_truncate_datafile_internal(rd_truncate_datafile_t *redo)
{
    printf("id %u, new_size %lld\n", redo->id, redo->size);
}

void print_spc_truncate_datafile(log_entry_t *log)
{
    rd_truncate_datafile_t *redo = (rd_truncate_datafile_t *)log->data;
    print_spc_truncate_datafile_internal(redo);
}

void print_spc_extend_datafile_daac(log_entry_t *log)
{
    rd_extend_datafile_daac_t *daac_redo = (rd_extend_datafile_daac_t *)log->data;
    print_spc_extend_datafile_internal(&daac_redo->datafile);
}

void print_spc_truncate_datafile_daac(log_entry_t *log)
{
    rd_truncate_datafile_daac_t *daac_redo = (rd_truncate_datafile_daac_t *)log->data;
    print_spc_truncate_datafile_internal(&daac_redo->datafile);
}
static status_t spc_check_datafile(knl_session_t *session, rd_set_df_autoextend_t *redo)
{
    datafile_t *df = DATAFILE_GET(session, redo->id);
    space_t *space = SPACE_GET(session, df->space_id);
    int64 max_file_size = (int64)MAX_FILE_PAGES(space->ctrl->type) * DEFAULT_PAGE_SIZE(session);
    if (redo->auto_extend_size > max_file_size || redo->auto_extend_size > redo->auto_extend_maxsize) {
        return CT_ERROR;
    }
    if (redo->auto_extend_maxsize > max_file_size ||
        (redo->auto_extend_maxsize != 0 && redo->auto_extend_maxsize < df->ctrl->size)) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void rd_spc_change_autoextend_internal(knl_session_t *session, rd_set_df_autoextend_t *redo)
{
    datafile_t *df = DATAFILE_GET(session, redo->id);

    if (redo->auto_extend) {
        DATAFILE_SET_AUTO_EXTEND(df);
    } else {
        DATAFILE_UNSET_AUTO_EXTEND(df);
    }
    df->ctrl->auto_extend_size = redo->auto_extend_size;
    df->ctrl->auto_extend_maxsize = redo->auto_extend_maxsize;

    if (!DAAC_REPLAY_NODE(session)) {
        if (db_save_datafile_ctrl(session, df->ctrl->id) != CT_SUCCESS) {
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file");
        }
    }
}

void rd_spc_change_autoextend(knl_session_t *session, log_entry_t *log)
{
    rd_set_df_autoextend_t *redo = (rd_set_df_autoextend_t *)log->data;
    rd_spc_change_autoextend_internal(session, redo);
}

void rd_spc_change_autoextend_daac(knl_session_t *session, log_entry_t *log)
{
    if (log->size != CM_ALIGN4(sizeof(rd_set_df_autoextend_daac_t)) + LOG_ENTRY_SIZE) {
        CT_LOG_RUN_ERR("[SPACE] no need to replay change auto_extend, log size %u is wrong", log->size);
        return;
    }
    rd_set_df_autoextend_daac_t *redo = (rd_set_df_autoextend_daac_t *)log->data;
    if (redo->rd.id >= CT_MAX_DATA_FILES) {
        CT_LOG_RUN_ERR("[SPACE] no need to replay change auto_extend, invalid datafile id %u", redo->rd.id);
        return;
    }
    if (spc_check_datafile(session, &redo->rd) != CT_SUCCESS) {
        CT_LOG_RUN_ERR(
            "[SPACE] datafile size is wrong, datafile id %u, auto extend %u, extend size %lld, extend maxsize %lld",
            redo->rd.id, redo->rd.auto_extend, redo->rd.auto_extend_size, redo->rd.auto_extend_maxsize);
        return;
    }
    rd_spc_change_autoextend_internal(session, &redo->rd);
}

void print_spc_change_autoextend_internal(rd_set_df_autoextend_t *redo)
{
    printf("id %u, auto_extend %u, auto_extend_size %lld, auto_extend_maxsize %lld \n", redo->id, redo->auto_extend,
           redo->auto_extend_size, redo->auto_extend_maxsize);
}

void print_spc_change_autoextend(log_entry_t *log)
{
    rd_set_df_autoextend_t *redo = (rd_set_df_autoextend_t *)log->data;
    print_spc_change_autoextend_internal(redo);
}

void print_spc_change_autoextend_daac(log_entry_t *log)
{
    rd_set_df_autoextend_daac_t *redo = (rd_set_df_autoextend_daac_t *)log->data;
    print_spc_change_autoextend_internal(&redo->rd);
}

void rd_df_init_map_head(knl_session_t *session, log_entry_t *log)
{
    page_id_t *page_id = (page_id_t *)log->data;
    datafile_t *df = DATAFILE_GET(session, page_id->file);
    space_t *space = SPACE_GET(session, df->space_id);
    df_map_head_t *bitmap_head = (df_map_head_t *)CURR_PAGE(session);

    page_init(session, (page_head_t *)CURR_PAGE(session), *page_id, PAGE_TYPE_DF_MAP_HEAD);
    bitmap_head->group_count = 0;
    bitmap_head->bit_unit = space->ctrl->extent_size;

    if (!session->log_diag) {
        session->curr_page_ctrl->is_resident = 1;
        df->map_head = bitmap_head;
        df->map_head_entry = *page_id;
    }
}

void rd_df_add_map_group(knl_session_t *session, log_entry_t *log)
{
    rd_df_add_map_group_t *redo = (rd_df_add_map_group_t *)log->data;
    df_map_head_t *bitmap_head = (df_map_head_t *)CURR_PAGE(session);
    df_map_group_t *bitmap_group;

    bitmap_group = &bitmap_head->groups[bitmap_head->group_count++];
    bitmap_group->first_map = redo->begin_page;
    bitmap_group->page_count = redo->page_count;
}

void rd_df_init_map_page(knl_session_t *session, log_entry_t *log)
{
    page_id_t *page_id = (page_id_t *)log->data;
    df_map_page_t *bitmap_page = (df_map_page_t *)CURR_PAGE(session);

    page_init(session, (page_head_t *)CURR_PAGE(session), session->curr_page_ctrl->page_id, PAGE_TYPE_DF_MAP_DATA);
    bitmap_page->free_begin = 0;
    bitmap_page->free_bits = DF_MAP_BIT_CNT(session);
    bitmap_page->first_page = *page_id;
}

void rd_df_change_map(knl_session_t *session, log_entry_t *log)
{
    df_map_page_t *bitmap_page = (df_map_page_t *)CURR_PAGE(session);
    rd_df_change_map_t *redo = (rd_df_change_map_t *)log->data;

    if (redo->is_set == CT_TRUE) {
        df_set_bitmap(bitmap_page->bitmap, redo->start, redo->size);

        bitmap_page->free_bits -= redo->size;
        if (bitmap_page->free_begin == redo->start) {
            bitmap_page->free_begin += redo->size;
        }
    } else {
        df_unset_bitmap(bitmap_page->bitmap, redo->start, redo->size);
        bitmap_page->free_bits += redo->size;
        if (redo->start < bitmap_page->free_begin) {
            bitmap_page->free_begin = redo->start;
        }
    }
}

void print_df_init_map_head(log_entry_t * log)
{
    page_id_t *page_id = (page_id_t *)log->data;
    (void)printf("page %u-%u\n", (uint32)page_id->file, (uint32)page_id->page);
}

void print_df_add_map_group(log_entry_t * log)
{
    rd_df_add_map_group_t *redo = (rd_df_add_map_group_t *)log->data;
    (void)printf("begin page %u-%u, page count %u\n", (uint32)redo->begin_page.file,
        (uint32)redo->begin_page.page, redo->page_count);
}

void print_df_init_map_page(log_entry_t * log)
{
    page_id_t *page_id = (page_id_t *)log->data;
    (void)printf("page %u-%u\n", (uint32)page_id->file, (uint32)page_id->page);
}

void print_df_change_map(log_entry_t * log)
{
    rd_df_change_map_t *redo = (rd_df_change_map_t *)log->data;
    (void)printf("start %u, size %u, is_set %u\n", redo->start, redo->size, redo->is_set);
}

void rd_spc_set_ext_size(knl_session_t *session, log_entry_t *log)
{
    page_head_t *page_head = (page_head_t *)CURR_PAGE(session);
    uint16 *extent_size = (uint16 *)log->data;

    page_head->ext_size = spc_ext_id_by_size(*extent_size);
}

void rd_spc_punch_format_page(knl_session_t *session, log_entry_t *log)
{
    rd_punch_page_t *id = (rd_punch_page_t *)log->data;
    page_head_t *page = (page_head_t *)CURR_PAGE(session);

    TO_PAGID_DATA(id->page_id, page->id);
    page->type = PAGE_TYPE_PUNCH_PAGE;
    page->size_units = page_size_units(DEFAULT_PAGE_SIZE(session));
    page->pcn = 0;
    page_tail_t *tail = PAGE_TAIL(page);
    tail->checksum = 0;
    tail->pcn = 0;

    spc_set_datafile_ctrl_punched(session, id->page_id.file);
}

void print_spc_punch_format_hole(log_entry_t *log)
{
    page_id_t *page = (page_id_t *)log->data;
    (void)printf("spc punch hole page:%u-%u, \n", page->file, page->page);
}

bool32 format_page_redo_type(uint8 type)
{
    switch (type) {
        case RD_HEAP_FORMAT_PAGE:
        case RD_HEAP_FORMAT_MAP:
        case RD_HEAP_FORMAT_ENTRY:
        case RD_BTREE_FORMAT_PAGE:
        case RD_BTREE_INIT_ENTRY:
        case RD_SPC_UPDATE_HEAD:
        case RD_SPC_INIT_MAP_HEAD:
        case RD_SPC_INIT_MAP_PAGE:
        case RD_SPC_CREATE_DATAFILE:
        case RD_UNDO_CREATE_SEGMENT:
        case RD_UNDO_FORMAT_TXN:
        case RD_UNDO_FORMAT_PAGE:
        case RD_LOB_PAGE_INIT:
        case RD_LOB_PAGE_EXT_INIT:
        case RD_LOGIC_OPERATION:
        case RD_PUNCH_FORMAT_PAGE:
        case RD_LOGIC_REP_INSERT:
        case RD_LOGIC_REP_UPDATE:
        case RD_LOGIC_REP_DELETE:
        case RD_LOGIC_REP_DDL:
        case RD_LOGIC_REP_ALL_DDL:
            return CT_TRUE;
        default:
            return CT_FALSE;
    }

    return CT_FALSE;
}

void format_page_must_rcy_log(knl_session_t *session, log_entry_t *log, bool32 *need_replay)
{
    knl_panic(format_page_redo_type(log->type));
    *need_replay = CT_TRUE;
}

/* some redo type is to format page, we need to verify format normally and punch page */
void punch_page_skip_rcy_log(knl_session_t *session, log_entry_t *log, bool32 *need_replay)
{
    database_t *db = &session->kernel->db;

    if (RD_TYPE_IS_ENTER_PAGE(log->type) || RD_TYPE_IS_LEAVE_PAGE(log->type) || session->page_stack.depth == 0) {
        *need_replay = CT_TRUE;
        return;
    }

    if (SECUREC_UNLIKELY(dtc_my_ctrl(session)->shutdown_consistency) && DB_IS_PRIMARY(db)) {
        *need_replay = CT_TRUE;
        return;
    }

    page_id_t *page_id = NULL;
    if (session->kernel->backup_ctx.block_repairing) {
        page_id = session->kernel->rcy_ctx.abr_ctrl == NULL ? NULL : &session->kernel->rcy_ctx.abr_ctrl->page_id;
    } else {
        page_id = session->curr_page_ctrl == NULL ? NULL : &session->curr_page_ctrl->page_id;
    }

    if (page_id == NULL) {
        *need_replay = CT_TRUE;
        return;
    }

    page_head_t *page = (page_head_t *)CURR_PAGE(session);
    datafile_t *df = DATAFILE_GET(session, page_id->file);
    // df has punched and page is inited, the page may be punched so we need skip entry.
    if (df->ctrl->punched && page->size_units == 0) {
        *need_replay = CT_FALSE;
        // we must set is_skip to true, because rd_leave_page will check the page size is 0 or not.
        session->page_stack.is_skip[session->page_stack.depth - 1] = CT_TRUE;
        return;
    }

    *need_replay = CT_TRUE;
}

void rd_spc_punch_extents(knl_session_t *session, log_entry_t *log)
{
    rd_punch_extents_t *rd = (rd_punch_extents_t*)log->data;
    spc_punch_head_t *punch_head = SPACE_PUNCH_HEAD(session);

    punch_head->punching_exts = rd->punching_exts;
    punch_head->punched_exts = rd->punched_exts;
}

void print_spc_punch_extents(log_entry_t *log)
{
    rd_punch_extents_t *rd = (rd_punch_extents_t *)log->data;
    page_list_t *punching = &rd->punching_exts;
    page_list_t *punched = &rd->punched_exts;
    (void)printf("punching extent: count %u, first %u-%u, last %u-%u \n."
        " punched extent: count %u, first %u-%u, last %u-%u \n.",
        punching->count, (uint32)punching->first.file, (uint32)punching->first.page,
        (uint32)punching->last.file, (uint32)punching->last.page,
        punched->count, (uint32)punched->first.file, (uint32)punched->first.page,
        (uint32)punched->last.file, (uint32)punched->last.page);
}

static bool32 rd_spc_create_space_check_type(knl_session_t *session, rd_create_space_t *redo)
{
    if ((redo->flags & SPACE_FLAG_AUTOALLOCATE) && ((redo->type & SPACE_TYPE_TEMP) || (redo->type & SPACE_TYPE_UNDO))) {
        return CT_FALSE;
    }
    if ((redo->flags & SPACE_FLAG_ENCRYPT) && ((redo->type & SPACE_TYPE_UNDO) || (redo->type & SPACE_TYPE_DEFAULT))) {
        return CT_FALSE;
    }
    if (redo->type == (SPACE_TYPE_UNDO | SPACE_TYPE_TEMP) ||
        ((redo->flags & SPACE_FLAG_AUTOOFFLINE) && (redo->type & SPACE_TYPE_DEFAULT))) {
        return CT_FALSE;
    }
    return CT_TRUE;
}

void rd_spc_create_space_daac(knl_session_t *session, log_entry_t *log)
{
    if (log->size != CM_ALIGN4(sizeof(rd_create_space_daac_t)) + LOG_ENTRY_SIZE) {
        CT_LOG_RUN_ERR("no need to replay create space, log size %u is wrong", log->size);
        return;
    }
    rd_create_space_daac_t *redo = (rd_create_space_daac_t *)log->data;
    redo->space.name[CT_NAME_BUFFER_SIZE  - 1] = 0;
    if (redo->space.space_id >= CT_MAX_SPACES || redo->space.extent_size <= 0) {
        CT_LOG_RUN_ERR("replay create spc %s fail, invalid spc id %u or extent size %u",
                       redo->space.name, redo->space.space_id, redo->space.extent_size);
        return;
    }
    if (!rd_spc_create_space_check_type(session, &redo->space)) {
        CT_LOG_RUN_ERR("replay create spc %s fail, invalid type %u or flags %u", redo->space.name, redo->space.type, redo->space.flags);
        return;
    }
    for (uint32 i = 0; i < CT_MAX_SPACES; i++) {
        if (i == redo->space.space_id) {
            continue;
        }
        space_t *space = SPACE_GET(session, i);
        if (space->ctrl->used && cm_str_equal(redo->space.name, space->ctrl->name) &&
            redo->space.is_for_create_db == space->ctrl->is_for_create_db) {
            CT_LOG_RUN_ERR("failed replay create space, spc name %s already exist", redo->space.name);
            return;
        }
    }
    rd_spc_create_space_internal(session, &redo->space);
}

void print_spc_create_space_daac(log_entry_t *log)
{
    rd_create_space_daac_t *redo = (rd_create_space_daac_t *)log->data;
    print_spc_create_space_internal(&redo->space);
}

void print_spc_remove_space_daac(log_entry_t *log)
{
    rd_remove_space_daac_t *redo = (rd_remove_space_daac_t *)log->data;
    print_spc_remove_space_internal(&redo->space);
}

void rd_spc_remove_space_daac(knl_session_t *session, log_entry_t *log)
{
    if (log->size != CM_ALIGN4(sizeof(rd_remove_space_daac_t)) + LOG_ENTRY_SIZE) {
        CT_LOG_RUN_ERR("no need to replay remove space, log size %u is wrong", log->size);
        return;
    }
    rd_remove_space_daac_t *redo = (rd_remove_space_daac_t *)log->data;
    if (redo->space.space_id >= CT_MAX_SPACES) {
        CT_LOG_RUN_ERR("replay remove space fail, space id %u is invalid", redo->space.space_id);
        return;
    }
    rd_spc_remove_space_internal(session, &redo->space);
}

void rd_spc_create_datafile_daac(knl_session_t *session, log_entry_t *log)
{
    if (log->size != CM_ALIGN4(sizeof(rd_create_datafile_daac_t)) + LOG_ENTRY_SIZE) {
        CT_LOG_RUN_ERR("no need to replay create datafile, log size %u is wrong", log->size);
        return;
    }
    rd_create_datafile_daac_t *redo = (rd_create_datafile_daac_t *)log->data;
    redo->datafile.name[CT_FILE_NAME_BUFFER_SIZE - 1] = 0;
    if (redo->datafile.space_id >= CT_MAX_SPACES || redo->datafile.id >= CT_MAX_DATA_FILES ||
        redo->datafile.type > DEV_TYPE_PGPOOL) {
        CT_LOG_RUN_ERR("replay create df %s failed, spc id %u, df id %u, or df type %u is invalid",
                       redo->datafile.name, redo->datafile.space_id, redo->datafile.id, redo->datafile.type);
        return;
    }
    for (uint32 i = 0; i < CT_MAX_DATA_FILES; i++) {
        if (i == redo->datafile.id) {
            continue;
        }
        datafile_t *df = DATAFILE_GET(session, i);
        if (cm_str_equal(redo->datafile.name, df->ctrl->name)) {
            CT_LOG_RUN_ERR("failed to replay create datafile, df name %s already exists", redo->datafile.name);
            return;
        }
    }
    space_t *space = SPACE_GET(session, redo->datafile.space_id);
    if (!SPACE_IS_ONLINE(space)) {
        CT_LOG_RUN_ERR("replay create df %s failed, spc %u is offline", redo->datafile.name, redo->datafile.space_id);
        return;
    }
    uint64 min_file_size = spc_get_datafile_minsize_byspace(session, space);
    uint64 max_file_size = (uint64)MAX_FILE_PAGES(space->ctrl->type) * DEFAULT_PAGE_SIZE(session);
    if (redo->datafile.size < min_file_size || redo->datafile.size > max_file_size) {
        CT_LOG_RUN_ERR("replay create df %s fail, datafile size %llu is invalid",
                       redo->datafile.name, redo->datafile.size);
        return;
    }
    if (redo->datafile.auto_extend_size > max_file_size || redo->datafile.auto_extend_maxsize > max_file_size ||
        redo->datafile.auto_extend_size < 0) {
        CT_LOG_RUN_ERR("replay create df %s fail, extend size %llu or max extend size %llu is invalid",
                       redo->datafile.name, redo->datafile.auto_extend_size, redo->datafile.auto_extend_maxsize);
        return;
    }

    if (DAAC_REPLAY_NODE(session) && !cm_exist_device(redo->datafile.type, redo->datafile.name)) {
        CT_LOG_RUN_ERR("replay create df %s failed, df device not exist when sync ddl", redo->datafile.name);
        return;
    }
    page_id_t entry;
    entry.file = redo->datafile.id;
    entry.page = SPACE_ENTRY_PAGE;
    if (redo->datafile.file_no == 0 && IS_INVALID_PAGID(entry)) {
        CT_LOG_RUN_ERR("replay create df %s failed, entry page %u-%u is invalid",
                       redo->datafile.name, redo->datafile.id, entry.page);
        return;
    }

    rd_spc_create_datafile_internal(session, &redo->datafile);

    if (redo->datafile.file_no == 0) {
        buf_enter_page(session, space->entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
        space->head = (space_head_t *)(session->curr_page + PAGE_HEAD_SIZE);
        buf_leave_page(session, CT_FALSE);
    }
}

void print_spc_create_datafile_daac(log_entry_t *log)
{
    rd_create_datafile_daac_t *redo = (rd_create_datafile_daac_t *)log->data;
    print_spc_create_datafile_internal(&redo->datafile);
}

void rd_spc_remove_datafile_daac(knl_session_t *session, log_entry_t *log)
{
    if (log->size != CM_ALIGN4(sizeof(rd_remove_datafile_daac_t)) + LOG_ENTRY_SIZE) {
        CT_LOG_RUN_ERR("no need to replay remove datafile, log size %u is wrong", log->size);
        return;
    }
    rd_remove_datafile_daac_t *redo = (rd_remove_datafile_daac_t *)log->data;
    if (redo->datafile.space_id >= CT_MAX_SPACES || redo->datafile.id >= CT_MAX_DATA_FILES) {
        CT_LOG_RUN_ERR("replay remove datafile %u in space %u failed, space id or df id is invalid",
                       redo->datafile.id, redo->datafile.space_id);
        return;
    }

    space_t *space = SPACE_GET(session, redo->datafile.space_id);
    if (!SPACE_IS_ONLINE(space)) {
        CT_LOG_RUN_ERR("replay remove datafile %u in space %u failed, space is offline",
                       redo->datafile.id, redo->datafile.space_id);
        return;
    }
    buf_enter_page(session, space->entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
    rd_spc_remove_datafile_interanal(session, &redo->datafile);
    buf_leave_page(session, CT_FALSE);
}

void print_spc_remove_datafile_daac(log_entry_t *log)
{
    rd_remove_datafile_daac_t *daac_redo = (rd_remove_datafile_daac_t *)log->data;
    print_spc_remove_datafile_internal(&daac_redo->datafile);
}

static status_t check_datafile_autoextend(knl_session_t *session, rd_set_space_autoextend_t *redo)
{
    space_t *space = SPACE_GET(session, (uint32)redo->space_id);
    int64 max_file_size = (int64)MAX_FILE_PAGES(space->ctrl->type) * DEFAULT_PAGE_SIZE(session);
    for (uint32 i = 0; i < CT_MAX_SPACE_FILES; i++) {
        if (CT_INVALID_ID32 == space->ctrl->files[i]) {
            continue;
        }
        datafile_t *df = DATAFILE_GET(session, space->ctrl->files[i]);
        if (redo->auto_extend_maxsize > max_file_size ||
            (redo->auto_extend_maxsize != 0 && redo->auto_extend_maxsize < df->ctrl->size)) {
            return CT_ERROR;
        }
        if (redo->auto_extend_size > max_file_size || redo->auto_extend_size > redo->auto_extend_maxsize) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

void rd_spc_set_autoextend_daac(knl_session_t *session, log_entry_t *log)
{
    if (log->size != CM_ALIGN4(sizeof(rd_set_space_autoextend_daac_t)) + LOG_ENTRY_SIZE) {
        CT_LOG_RUN_ERR("[DC] no need to replay auto extend, log size %u is wrong", log->size);
        return;
    }
    rd_set_space_autoextend_daac_t *redo = (rd_set_space_autoextend_daac_t *)log->data;
    if (redo->rd.space_id >= CT_MAX_SPACES) {
        CT_LOG_RUN_ERR("[DC] no need to replay auto extend, invalid space id %u", redo->rd.space_id);
        return;
    }
    if (check_datafile_autoextend(session, &redo->rd) != CT_SUCCESS) {
        CT_LOG_RUN_ERR(
            "[DC] auto extend size is invalid, auto extend %u, space id %u, extend size %lld, extend max size %lld",
            redo->rd.auto_extend, redo->rd.space_id, redo->rd.auto_extend_size, redo->rd.auto_extend_maxsize);
        return;
    }
    rd_spc_set_autoextend_internal(session, &redo->rd);
}

void print_spc_set_autoextend_daac(log_entry_t *log)
{
    rd_set_space_autoextend_daac_t *rd = (rd_set_space_autoextend_daac_t *)log->data;
    print_spc_set_autoextend_internal(&rd->rd);
}

void rd_spc_rename_space_daac(knl_session_t *session, log_entry_t *log)
{
    if (log->size != CM_ALIGN4(sizeof(rd_rename_space_daac_t)) + LOG_ENTRY_SIZE) {
        CT_LOG_RUN_ERR("[DC] no need to replay rename space, log size %u is wrong", log->size);
        return;
    }
    rd_rename_space_daac_t *redo = (rd_rename_space_daac_t *)log->data;
    if (redo->rd.space_id >= CT_MAX_SPACES) {
        CT_LOG_RUN_ERR("[DC] no need to replay rename space, invalid space id %u", redo->rd.space_id);
        return;
    }
    rd_spc_rename_space_internal(session, &redo->rd);
}

void print_spc_rename_space_daac(log_entry_t *log)
{
    rd_rename_space_daac_t *rd = (rd_rename_space_daac_t *)log->data;
    print_spc_rename_space_internal(&rd->rd);
}

void rd_spc_set_flag_daac(knl_session_t *session, log_entry_t *log)
{
    if (log->size != CM_ALIGN4(sizeof(rd_set_space_flag_daac_t)) + LOG_ENTRY_SIZE) {
        CT_LOG_RUN_ERR("[DC] no need to replay set flag, log size %u is wrong", log->size);
        return;
    }
    rd_set_space_flag_daac_t *redo = (rd_set_space_flag_daac_t *)log->data;
    if (redo->rd.space_id >= CT_MAX_SPACES) {
        CT_LOG_RUN_ERR("[DC] no need to replay set flag, invalid space id %u", redo->rd.space_id);
        return;
    }
    rd_spc_set_flag_internal(session, &redo->rd);
}

void print_spc_set_flag_daac(log_entry_t *log)
{
    rd_set_space_flag_daac_t *rd = (rd_set_space_flag_daac_t *)log->data;
    print_spc_set_flag_internal(&rd->rd);
}

#ifdef __cplusplus
}
#endif

