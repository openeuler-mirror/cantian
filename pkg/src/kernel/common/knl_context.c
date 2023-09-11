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
 * knl_context.c
 *
 *
 * IDENTIFICATION
 * src/kernel/common/knl_context.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_context.h"
#include "cm_file.h"
#include "cm_dbs_intf.h"
#include "mes_config.h"
#include "cm_dbstore.h"

#ifdef __cplusplus
extern "C" {
#endif

void knl_init_attr(knl_handle_t kernel)
{
    knl_instance_t *inst = (knl_instance_t *)kernel;
    char *param = NULL;

    uint32 page_size = inst->attr.page_size;
    inst->attr.max_row_size = GS_MAX_ROW_SIZE;
    /* the max value of page_size is 32768 and GS_PLOG_PAGES is 7 */
    inst->attr.plog_buf_size = page_size * GS_PLOG_PAGES;

    /*
     * page_size * 2: is allocated for row buffer and page buffer of cursor;
     * inst->attr.max_column_count * sizeof(uint16) * 2: need to add 2 array size when calculate
     * the cursor size: cursor->offsets, cursor->lens;
     */
    inst->attr.cursor_size = sizeof(knl_cursor_t) + page_size * 2 + inst->attr.max_column_count * sizeof(uint16) * 2;
    inst->attr.commit_batch = GS_FALSE;
    inst->attr.commit_nowait = GS_FALSE;
    /* the min value of inst->attr.max_map_nodes is 8192 */
    inst->attr.max_map_nodes = (page_size - sizeof(map_page_t) - sizeof(page_tail_t)) / sizeof(map_node_t);

    param = cm_get_config_value(inst->attr.config, "COMMIT_WAIT");
    if (param != NULL) {
        inst->attr.commit_nowait = cm_str_equal(param, "NOWAIT");
    }
}

status_t knl_init_dbs_client(knl_instance_t *ctx)
{
    cm_dbs_cfg_s *cfg = cm_dbs_get_cfg();
    if (!cfg->enable) {
        GS_LOG_RUN_INF("dbstore is not enabled");
        return GS_SUCCESS;
    }
    knl_session_t *session = ctx->sessions[SESSION_ID_KERNEL];
    const char* uuid = get_config_uuid(session->kernel->id);
    uint32 lsid = get_config_lsid(session->kernel->id);
    cm_set_dbs_uuid_lsid(uuid, lsid);
    if (cm_dbs_init(ctx->home) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("DBSTOR: init failed.");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t knl_startup(knl_handle_t kernel)
{
    knl_instance_t *ctx = (knl_instance_t *)kernel;
    knl_session_t *session = ctx->sessions[SESSION_ID_KERNEL];
    int32 ret;

    // try to open database, if db is exists
    session->kernel->db.status = DB_STATUS_CLOSED;

    ret = memset_sp(&ctx->switch_ctrl, sizeof(switch_ctrl_t), 0, sizeof(switch_ctrl_t));
    knl_securec_check(ret);

    if (db_load_lib(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_init(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (DB_ATTR_CLUSTER(session)) {
        if (g_knl_callback.device_init((const char *)session->kernel->dtc_attr.gss_inst_path) != GS_SUCCESS) {
            GS_LOG_RUN_INF("RAFT: db init raw type device failed");
            return GS_ERROR;
        }
        if (knl_init_dbs_client(ctx) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("knl init dbstor failed.");
            return GS_ERROR;
        }
    }

    session->kernel->db.status = DB_STATUS_NOMOUNT;
    session->kernel->db_startup_time = cm_now();

    return GS_SUCCESS;
}

void knl_shutdown(knl_handle_t sess, knl_handle_t kernel, bool32 need_ckpt)
{
    knl_handle_t session = sess;
    knl_instance_t *ctx = (knl_instance_t *)kernel;
    
    alck_deinit_ctx(ctx);

    if (session == NULL) {
        session = ctx->sessions[SESSION_ID_KERNEL];
    }
    db_close((knl_session_t *)session, need_ckpt);
}

status_t db_fdatasync_file(knl_session_t *session, int32 file)
{
    if (!session->kernel->attr.enable_fdatasync) {
        return GS_SUCCESS;
    }

    if (cm_fdatasync_file(file) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_fsync_file(knl_session_t *session, int32 file)
{
    if (session->kernel->attr.enable_OSYNC) {
        return GS_SUCCESS;
    }

    if (cm_fsync_file(file) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t db_load_aio_lib(cm_aio_lib_t *procs)
{
    if (cm_open_dl(&procs->lib_handle, "libaio.so.1") != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_load_symbol(procs->lib_handle, "io_setup", (void **)(&procs->io_setup)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_load_symbol(procs->lib_handle, "io_destroy", (void **)(&procs->io_destroy)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_load_symbol(procs->lib_handle, "io_submit", (void **)(&procs->io_submit)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_load_symbol(procs->lib_handle, "io_cancel", (void **)(&procs->io_cancel)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_load_symbol(procs->lib_handle, "io_getevents", (void **)(&procs->io_getevents)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_load_lib(knl_session_t *session)
{
    if (session->kernel->attr.enable_asynch) {
        if (db_load_aio_lib(&session->kernel->aio_lib) == GS_SUCCESS) {
            return GS_SUCCESS;
        }
        GS_LOG_RUN_ERR("[DB] It is not support async io");
        return GS_ERROR;
    }

    session->kernel->gbp_aly_ctx.sid = GS_INVALID_ID32;
    if (KNL_GBP_ENABLE(session->kernel) && cm_str_equal_ins(session->kernel->gbp_attr.trans_type, "rdma")) {
        if (rdma_init_lib() != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DB] failed to init rdma library");
            return GS_ERROR;
        }
    }

    if (cm_dbs_is_enable_dbs() == GS_TRUE) {
        if (dbs_init_lib() != GS_SUCCESS) {
            GS_LOG_RUN_ERR("Failed to init lib.");
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

uint32 knl_io_flag(knl_session_t *session)
{
    if (session->kernel->attr.enable_asynch) {
        return O_DIRECT;
    }
    if (session->kernel->attr.enable_directIO) {
        return O_DIRECT | O_SYNC;
    }
    if (session->kernel->attr.enable_dsync) {
        return O_DSYNC;
    }
    if (session->kernel->attr.enable_fdatasync) {
        return 0;
    }
    return O_SYNC;
}

uint32 knl_redo_io_flag(knl_session_t *session)
{
    uint32 flag = 0;

    if (session->kernel->attr.enable_logdirectIO) {
        flag |= O_DIRECT;
    }

    if (session->kernel->attr.enable_OSYNC) {
        flag |= O_SYNC;
    } else {
        flag |= O_DSYNC;
    }

    return flag;
}

uint32 knl_arch_io_flag(knl_session_t *session, bool32 is_compressed)
{
    uint32 flag = 0;

    if (!is_compressed && session->kernel->attr.enable_logdirectIO) {
        flag |= O_DIRECT;
    }

    if (session->kernel->attr.enable_OSYNC) {
        flag |= O_SYNC;
    } else {
        flag |= O_DSYNC;
    }

    return flag;
}

#ifdef __cplusplus
}
#endif