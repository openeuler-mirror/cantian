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
 * srv_device_adpt.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_device_adpt.c
 *
 * -------------------------------------------------------------------------
 */

#include "srv_device_adpt.h"
#include "cm_device.h"
#include "cm_log.h"
#include "cm_utils.h"

#ifdef WIN32
#define DSSAPI "dssapi.dll"
#else
#define DSSAPISO "libdssapi.so"
#endif

static void srv_dss_write_normal_log(int log_id, int log_level, const char *code_file_name, uint32 code_line_num,
                                     const char *module_name, const char *format, ...)
{
    log_id_t db_log_id = (log_id_t)log_id;
    log_level_t db_log_level = (log_level_t)log_level;
    va_list args;
    va_start(args, format);
    char buf[CT_MAX_LOG_CONTENT_LENGTH];
    int32 errcode = vsnprintf_s(buf, CT_MAX_LOG_CONTENT_LENGTH, CT_MAX_LOG_CONTENT_LENGTH, format, args);
    if (errcode < 0) {
        va_end(args);
        return;
    }
    va_end(args);

    cm_dss_write_normal_log(db_log_id, db_log_level, code_file_name, code_line_num, DSSAPI, CT_TRUE, buf);
}

status_t srv_device_init(const char *conn_path)
{
    raw_device_op_t device_op = { 0 };
    status_t ret = cm_open_dl(&device_op.handle, DSSAPISO);
    if (ret != CT_SUCCESS) {
        return ret;
    }
    CT_RETURN_IFERR(cm_load_symbol(device_op.handle, "dss_fcreate", (void **)&device_op.raw_create));
    CT_RETURN_IFERR(cm_load_symbol(device_op.handle, "dss_fclose", (void **)&device_op.raw_close));
    CT_RETURN_IFERR(cm_load_symbol(device_op.handle, "dss_fread", (void **)&device_op.raw_read));
    CT_RETURN_IFERR(cm_load_symbol(device_op.handle, "dss_fopen", (void **)&device_op.raw_open));
    CT_RETURN_IFERR(cm_load_symbol(device_op.handle, "dss_fremove", (void **)&device_op.raw_remove));
    CT_RETURN_IFERR(cm_load_symbol(device_op.handle, "dss_fseek", (void **)&device_op.raw_seek));
    CT_RETURN_IFERR(cm_load_symbol(device_op.handle, "dss_fwrite", (void **)&device_op.raw_write));
    CT_RETURN_IFERR(cm_load_symbol(device_op.handle, "dss_dmake", (void **)&device_op.raw_create_dir));
    CT_RETURN_IFERR(cm_load_symbol(device_op.handle, "dss_frename", (void **)&device_op.raw_rename));
    CT_RETURN_IFERR(cm_load_symbol(device_op.handle, "dss_check_size", (void **)&device_op.raw_check_size));
    CT_RETURN_IFERR(cm_load_symbol(device_op.handle, "dss_align_size", (void **)&device_op.raw_align_size));
    CT_RETURN_IFERR(cm_load_symbol(device_op.handle, "dss_fsize_physical", (void **)&device_op.raw_fsize_pyhsical));
    CT_RETURN_IFERR(cm_load_symbol(device_op.handle, "dss_get_error", (void **)&device_op.raw_get_error));
    CT_RETURN_IFERR(cm_load_symbol(device_op.handle, "dss_pread", (void **)&device_op.raw_pread));
    CT_RETURN_IFERR(cm_load_symbol(device_op.handle, "dss_pwrite", (void **)&device_op.raw_pwrite));
    CT_RETURN_IFERR(cm_load_symbol(device_op.handle, "dss_ftruncate", (void **)&device_op.raw_truncate));
    CT_RETURN_IFERR(cm_load_symbol(device_op.handle, "dss_set_svr_path", (void **)&device_op.raw_set_svr_path));
    CT_RETURN_IFERR(
        cm_load_symbol(device_op.handle, "dss_register_log_callback", (void **)&device_op.raw_regist_logger));
    CT_RETURN_IFERR(cm_load_symbol(device_op.handle, "dss_aio_prep_pread", (void **)&device_op.aio_prep_pread));
    CT_RETURN_IFERR(cm_load_symbol(device_op.handle, "dss_aio_prep_pwrite", (void **)&device_op.aio_prep_pwrite));
    CT_RETURN_IFERR(cm_load_symbol(device_op.handle, "dss_get_au_size", (void **)&device_op.get_au_size));
    CT_RETURN_IFERR(cm_load_symbol(device_op.handle, "dss_stat", (void **)&device_op.raw_stat));
    CT_RETURN_IFERR(cm_load_symbol(device_op.handle, "dss_set_log_level", (void **)&device_op.set_dss_log_level));
    CT_RETURN_IFERR(cm_load_symbol(device_op.handle, "dss_aio_post_pwrite", (void **)&device_op.aio_post_pwrite));
    CT_RETURN_IFERR(cm_load_symbol(device_op.handle, "dss_set_conn_opts", (void **)&device_op.dss_set_conn_opts));
    CT_RETURN_IFERR(
        cm_load_symbol(device_op.handle, "dss_set_default_conn_timeout", (void **)&device_op.dss_set_def_conn_timeout));
    if (device_op.handle != NULL) {
        cm_raw_device_register(&device_op);
        device_op.raw_set_svr_path(conn_path);
        device_op.raw_regist_logger(srv_dss_write_normal_log, cm_log_param_instance()->log_level);
    }

    return CT_SUCCESS;
}