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
 * knl_space_ddl.c
 *
 *
 * IDENTIFICATION
 * src/kernel/tablespace/knl_space_ddl.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_space_module.h"
#include "knl_space_ddl.h"
#include "knl_context.h"
#include "knl_table.h"
#include "dtc_dls.h"

#ifdef __cplusplus
extern "C" {
#endif

void spc_set_datafile_autoextend(knl_session_t *session, datafile_t *df, knl_autoextend_def_t *def)
{
    if (def->enabled) {
        DATAFILE_SET_AUTO_EXTEND(df);
        // If user does not gei next size, parse ddl will set it to 0
        if (def->nextsize == 0) {
            // If df's auto_extend_size is also 0, set DEFAULD AUTOEXTEND SIZE, otherwise, do nothing
            if (df->ctrl->auto_extend_size == 0) {
                df->ctrl->auto_extend_size = DF_DEFAULD_AUTOEXTEND_SIZE;
            }
        } else {
            df->ctrl->auto_extend_size = def->nextsize;
        }
    } else {
        DATAFILE_UNSET_AUTO_EXTEND(df);
        // if set auto extend off, set size to 0
        df->ctrl->auto_extend_size = 0;
    }

    if (def->maxsize == 0) {
        // If df's auto_extend_maxsize is also 0, set MAX SIZE, otherwise, do nothing
        if (df->ctrl->auto_extend_maxsize == 0) {
            // max file size is not more than 8T
            space_t *space = SPACE_GET(session, df->space_id);
            df->ctrl->auto_extend_maxsize = (int64)MAX_FILE_PAGES(space->ctrl->type) * DEFAULT_PAGE_SIZE(session);
        }
    } else {
        df->ctrl->auto_extend_maxsize = def->maxsize;
    }
}

bool32 spc_auto_offline_space(knl_session_t *session, space_t *space, datafile_t *df)
{
    if (!SPACE_IS_AUTOOFFLINE(space)) {
        return CT_FALSE;
    }

    CT_LOG_RUN_INF("[SPACE] auto offline space %s and datafile %s", space->ctrl->name, df->ctrl->name);
    DATAFILE_UNSET_ONLINE(df);
    SPACE_UNSET_ONLINE(space);

    if (db_save_datafile_ctrl(session, df->ctrl->id) != CT_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when auto offline datafile %s",
                 df->ctrl->name);
    }

    if (db_save_space_ctrl(session, space->ctrl->id) != CT_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when auto offline space %s",
                 space->ctrl->name);
    }

    return CT_TRUE;
}

status_t spc_active_swap_encrypt(knl_session_t *session)
{
    encrypt_context_t *encrypt_ctx = &session->kernel->encrypt_ctx;
    if (encrypt_ctx->swap_encrypt_flg) {
        return CT_SUCCESS;
    }

    knl_panic(encrypt_ctx->swap_encrypt_version > NO_ENCRYPT);
    knl_panic(encrypt_ctx->swap_cipher_reserve_size > 0);

    encrypt_ctx->swap_encrypt_flg = CT_TRUE;
    return CT_SUCCESS;
}

status_t spc_active_undo_encrypt(knl_session_t *session, uint32 space_id)
{
    space_t *space = SPACE_GET(session, space_id);

    dls_spin_lock(session, &space->lock, &session->stat->spin_stat.stat_space);

    if (space->ctrl->encrypt_version == NO_ENCRYPT) {
        space->ctrl->encrypt_version = KMC_DEFAULT_ENCRYPT;
        if (page_cipher_reserve_size(session, space->ctrl->encrypt_version,
            &space->ctrl->cipher_reserve_size) != CT_SUCCESS) {
            dls_spin_unlock(session, &space->lock);
            return CT_ERROR;
        }

        dls_spin_unlock(session, &space->lock);

        if (db_save_space_ctrl(session, space->ctrl->id) != CT_SUCCESS) {
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when create tablespace");
        }
        return CT_SUCCESS;
    }

    dls_spin_unlock(session, &space->lock);
    return CT_SUCCESS;
}

void spc_umount_space(knl_session_t *session, space_t *space)
{
    datafile_t *df = NULL;
    uint32 file_id;
    uint32 i;

    for (i = 0; i < space->ctrl->file_hwm; i++) {
        file_id = space->ctrl->files[i];
        if (CT_INVALID_ID32 == file_id) {
            continue;
        }

        df = DATAFILE_GET(session, file_id);
        spc_close_datafile(df, DATAFILE_FD(session, file_id));
        df->file_no = CT_INVALID_ID32;
        df->space_id = CT_INVALID_ID32;
    }

    space->entry = INVALID_PAGID;
    space->head = NULL;
}

static void spc_update_datafile_hwm(knl_session_t *session, space_t *space, uint32 id, uint32 hwm)
{
    rd_update_hwm_t *redo = NULL;
    bool32 need_redo = SPACE_IS_LOGGING(space);

    log_atomic_op_begin(session);
    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);

    space->head->hwms[id] = hwm;

    redo = (rd_update_hwm_t *)cm_push(session->stack, sizeof(rd_update_hwm_t));
    knl_panic(redo != NULL);
    redo->file_no = id;
    redo->file_hwm = space->head->hwms[id];

    if (need_redo) {
        log_put(session, RD_SPC_UPDATE_HWM, redo, sizeof(rd_update_hwm_t), LOG_ENTRY_FLAG_NONE);
    }

    cm_pop(session->stack);

    buf_leave_page(session, CT_TRUE);
    log_atomic_op_end(session);
}

void spc_update_hwms(knl_session_t *session, space_t *space, uint32 *hwms)
{
    uint32 id;

    for (id = 0; id < space->ctrl->file_hwm; id++) {
        if (CT_INVALID_ID32 == space->ctrl->files[id]) {
            continue;
        }

        if (hwms[id] == SPACE_HEAD_RESIDENT(session, space)->hwms[id]) {
            continue;
        }

        spc_update_datafile_hwm(session, space, id, hwms[id]);
        CT_LOG_RUN_INF("update hwm of file %u from %u to %u",
                       space->ctrl->files[id], SPACE_HEAD_RESIDENT(session, space)->hwms[id], hwms[id]);
    }
}

void spc_offline_space_files(knl_session_t *session, uint32 *files, uint32 file_hwm)
{
    datafile_t *df = NULL;
    uint32 i;

    for (i = 0; i < file_hwm; i++) {
        if (files[i] == CT_INVALID_ID32) {
            continue;
        }
        df = DATAFILE_GET(session, files[i]);
        CT_LOG_RUN_INF("[SPACE] set datafile %s offline", df->ctrl->name);
        DATAFILE_UNSET_ONLINE(df);
    }
}

#ifdef __cplusplus
}
#endif

