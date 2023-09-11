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
 * mes_config.c
 *
 *
 * IDENTIFICATION
 * src/mec/mes_config.c
 *
 * -------------------------------------------------------------------------
 */
#include <stdlib.h>
#include <string.h>
#include "mes_func.h"
#include "mes_config.h"

#define MAX_LSID_BUFFER 80
#define LSID_TYPE 2
#define MAX_NODE_COUNT 2
#define MAX_CLUSTER_ID 65535

static char g_uuid[GS_MAX_INSTANCES][37];
static uint32 g_lsid[GS_MAX_INSTANCES];

status_t mes_set_inst_lsid(uint16 cluster_id, uint16 pid, uint32 inst_id)
{
    FILE *fp = NULL;
    char get_buff[MAX_LSID_BUFFER];
    char cmd_buff[GS_MAX_CMD_LEN];
    int ret;
    if (!g_enable_dbstor) {
        ret = sprintf_s(cmd_buff, GS_MAX_CMD_LEN, "python /home/regress/CantianKernel/pkg/deploy/action/obtains_lsid.py %u %u %u %u",
            LSID_TYPE, cluster_id, pid, inst_id);
    } else {
        ret = sprintf_s(cmd_buff, GS_MAX_CMD_LEN, "python3 /opt/cantian/action/obtains_lsid.py %u %u %u %u",
            LSID_TYPE, cluster_id, pid, inst_id);
    }
    if (ret < 0) {
        GS_LOG_RUN_INF("cantian obtain lsid failed, ret=%d.", ret);
        return GS_ERROR;
    }
    GS_LOG_DEBUG_INF("generate lsid cluster id %d, pid %d, inst id %d", cluster_id, pid, inst_id);

    fp = popen(cmd_buff, "r");
    if (fp == NULL) {
        GS_LOG_RUN_ERR("execute generate lsid cmd failed");
        return GS_ERROR;
    }
    // get lsid
    if (fgets(get_buff, sizeof(get_buff), fp) != NULL) {
        g_lsid[inst_id] = strtol(get_buff, NULL, 0);
    } else {
        GS_LOG_RUN_ERR("generate lsid failed.");
        pclose(fp);
        return GS_ERROR;
    }
    // get uuid
    if (fgets(g_uuid[inst_id], sizeof(g_uuid[inst_id]), fp) == NULL) {
        GS_LOG_RUN_ERR("get uuid failed");
        pclose(fp);
        return GS_ERROR;
    }
    pclose(fp);
    return GS_SUCCESS;
}

status_t set_all_inst_lsid(uint16 cluster_id, uint16 pid)
{
    int index;
    for (index = 0; index < MAX_NODE_COUNT; index++) {
        if (mes_set_inst_lsid(cluster_id, pid, index) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("generate inst %d lsid failed.", index);
            return GS_ERROR;
        }
    }
    GS_LOG_RUN_INF("generate all lsid, uuid success.");
    return GS_SUCCESS;
}

uint32 get_config_lsid(uint32 inst_id)
{
    knl_panic_log(inst_id < MAX_NODE_COUNT, "get lsid of %d failed", inst_id);
    return g_lsid[inst_id];
}

char* get_config_uuid(uint32 inst_id)
{
    knl_panic_log(inst_id < MAX_NODE_COUNT, "get lsid of %d failed", inst_id);
    return g_uuid[inst_id];
}
