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
 * cm_dss_iofence.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_dss_iofence.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_common_module.h"
#include "cm_log.h"
#include "cm_error.h"
#include "cm_dss_iofence.h"

#define DSS_CMD_TIOMEOUT_SECOND         (float)10.0
#define DSS_SCRIPT_NAME                 "dss_contrl.sh"
#define DSS_CMD_OUT_BUFFER_SIZE         (CT_MAX_CMD_LEN + 1)
#define DSS_TIMEOUT_ERROR_NUMBER        "124"

status_t cm_exec_dss_cmd(const char* arg, uint32 node_id)
{
    errno_t ret = EOK;
    char cmd[CT_MAX_CMD_LEN] = {0};
    char cmd_out[DSS_CMD_OUT_BUFFER_SIZE] = {0};
    ret = sprintf_s(cmd, CT_MAX_CMD_LEN,
            "echo 'script begin';source ~/.bashrc;timeout %.2f ${DSS_HOME}/%s %s %u;echo $?;echo 'script end\n';",
            DSS_CMD_TIOMEOUT_SECOND, DSS_SCRIPT_NAME, arg, node_id);
    PRTS_RETURN_IFERR(ret);
    CT_LOG_RUN_INF("begin exec dss cmd, cmd=%s", cmd);
    FILE* fp = popen(cmd, "r");
    if (fp == NULL) {
        CT_LOG_RUN_ERR("popen failed, cmd=%s", cmd);
        return CT_ERROR;
    }

    size_t size = 0;
    size = fread(cmd_out, 1, DSS_CMD_OUT_BUFFER_SIZE, fp);
    (void)pclose(fp);

    if (size == 0 || size >= sizeof(cmd_out)) {
        CT_LOG_RUN_ERR("fread failed, cmd=%s, size=%lu", cmd, size);
        return CT_ERROR;
    }

    cmd_out[size] = 0;
    CT_LOG_RUN_INF("end exec dss cmd.");

    if (strstr(cmd_out, DSS_TIMEOUT_ERROR_NUMBER) != NULL) {
        CT_LOG_RUN_ERR("DSS script exec timeout, cmd=%s, cmd_out=%s", cmd, cmd_out);
        return CT_ERROR;
    }

    if (strstr(cmd_out, "RES_SUCCESS") != NULL) {
        CT_LOG_RUN_INF("DSS script exec succeed, cmd=%s", cmd);
        return CT_SUCCESS;
    }

    CT_LOG_RUN_ERR("DSS script exec failed, cmd=%s, cmd_out=%s", cmd, cmd_out);
    return CT_ERROR;
}

status_t cm_dss_iof_register()
{
    if (cm_exec_dss_cmd("-reg", 0) != CT_SUCCESS){
        CT_LOG_RUN_ERR("DSS iof register failed");
        return CT_ERROR;
    }

    CT_LOG_RUN_INF("DSS iof register succeed");
    return CT_SUCCESS;
}

status_t cm_dss_iof_kick_by_inst_id(uint32 inst_id)
{
    if (cm_exec_dss_cmd("-kick", inst_id) != CT_SUCCESS){
        CT_LOG_RUN_ERR("DSS iof kick node %u failed", inst_id);
        return CT_ERROR;
    }

    CT_LOG_RUN_INF("DSS iof unregister succeed");
    return CT_SUCCESS;
}