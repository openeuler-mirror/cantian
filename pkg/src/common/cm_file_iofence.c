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
 * cm_file_iofence.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_file_iofence.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_common_module.h"
#include "cm_file.h"
#include "cm_log.h"
#include "cm_error.h"
#include "cm_file_iofence.h"

#define IO_FENCE_FILE_NAME_BUFFER_SIZE 256

typedef struct {
    uint32 cluster_id;
    uint32 termid;
    char   file_path[IO_FENCE_FILE_NAME_BUFFER_SIZE];
} cm_file_iof_cfg_s;

cm_file_iof_cfg_s g_file_cfg;

status_t cm_set_file_iof_cfg(uint32 cluster_id, uint32 termid, const char* file_path)
{
    errno_t err;
    g_file_cfg.cluster_id = cluster_id;
    g_file_cfg.termid = termid;
    err = strncpy_s(g_file_cfg.file_path, IO_FENCE_FILE_NAME_BUFFER_SIZE, file_path, strlen(file_path));
    if (err != EOK) {
        CT_LOG_RUN_ERR("Set file iof cfg failed, strncpy err, %d:%s.", errno, strerror(errno));
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("File set iof cfg succ, file path %s, cluster id %u.", g_file_cfg.file_path,
        g_file_cfg.cluster_id);
    return CT_SUCCESS;
}

void iof_file_watcher(thread_t *thread)
{
    char* file_name = (char *)thread->argument;
    cm_set_thread_name("Iof_file_watcher");
    CT_LOG_RUN_INF("Iof file watcher, file name(%s).", file_name);
    for (;;) {
        if (cm_access_file(file_name, F_OK) != 0) {
            CT_LOG_RUN_ERR("Failed to access file(%s).", file_name);
            break;
        }
        cm_sleep(1);
    }
    CM_FREE_PTR(file_name);
    CM_ABORT_REASONABLE(0, "ABORT INFO: self abort, iofence.");
}

status_t cm_file_iof_register(uint32 inst_id, thread_t *file_iof_thd)
{
    if (strlen(g_file_cfg.file_path) == 0) {
        CT_LOG_RUN_WAR("Iof file path is empty, no need iofence.");
        return CT_SUCCESS;
    }

    errno_t err;
    int iof_fd;
    char* file_name = malloc(sizeof(char) * IO_FENCE_FILE_NAME_BUFFER_SIZE);
    if (file_name == NULL) {
        CT_LOG_RUN_ERR("Failed to malloc file name buffer(%u), %d:%s.", IO_FENCE_FILE_NAME_BUFFER_SIZE,
            errno, strerror(errno));
        return CT_ERROR;
    }
    err = snprintf_s(file_name, IO_FENCE_FILE_NAME_BUFFER_SIZE, IO_FENCE_FILE_NAME_BUFFER_SIZE - 1, "%s/%u_%u_iof",
        g_file_cfg.file_path, g_file_cfg.cluster_id, inst_id);
    if (err == -1) {
        CT_LOG_RUN_ERR("Failed to snprintf file name, %d:%s.", errno, strerror(errno));
        return CT_ERROR;
    }
    CT_RETURN_IFERR(cm_open_file(file_name, O_CREAT | O_RDWR | O_BINARY | O_CLOEXEC | O_SYNC | O_DIRECT, &iof_fd));
    cm_close_file(iof_fd);

    if (CT_SUCCESS != cm_create_thread(iof_file_watcher, 0, file_name, file_iof_thd)) {
        CT_LOG_RUN_ERR("Failed to create file(%s) watcher thread.", file_name);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("File iof register succ, file name %s, cluster id %u, inst id %u.", file_name,
        g_file_cfg.cluster_id, inst_id);
    return CT_SUCCESS;
}

status_t cm_file_iof_kick_by_inst_id(uint32 inst_id)
{
    if (strlen(g_file_cfg.file_path) == 0) {
        CT_LOG_RUN_WAR("Iof file path is empty, no need iofence.");
        return CT_SUCCESS;
    }
    errno_t err;
    char file_name[IO_FENCE_FILE_NAME_BUFFER_SIZE] = {0};
    err = snprintf_s(file_name, IO_FENCE_FILE_NAME_BUFFER_SIZE, IO_FENCE_FILE_NAME_BUFFER_SIZE - 1, "%s/%u_%u_iof",
        g_file_cfg.file_path, g_file_cfg.cluster_id, inst_id);
    if (err == -1) {
        CT_LOG_RUN_ERR("Failed to snprintf file name, %d:%s.", errno, strerror(errno));
        return CT_ERROR;
    }
    if (cm_access_file(file_name, F_OK) != 0) {
        CT_LOG_RUN_WAR("Iof file not exist, file(%s).", file_name);
        return CT_SUCCESS;
    }
    if (cm_remove_file(file_name) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to remove file(%s).", file_name);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("File iof kick succ, file name %s, cluster id %u, inst id %u.", file_name, g_file_cfg.cluster_id,
        inst_id);
    return CT_SUCCESS;
}