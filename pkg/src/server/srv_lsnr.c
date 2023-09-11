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
 * srv_lsnr.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_lsnr.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_lsnr.h"
#include "srv_agent.h"
#include "srv_instance.h"
#ifdef __cplusplus
extern "C" {
#endif

static status_t server_check_tcp_ip(cs_pipe_t *pipe)
{
    char ipstr[CM_MAX_IP_LEN];
    status_t status;
    bool32 check_res = GS_FALSE;
    (void)cm_inet_ntop((struct sockaddr *)&pipe->link.tcp.remote.addr, ipstr, CM_MAX_IP_LEN);
    status = cm_check_remote_ip(GET_WHITE_CTX, ipstr, &check_res);
    if (status == GS_ERROR || !check_res) {
        GS_THROW_ERROR(ERR_TCP_INVALID_IPADDRESS, ipstr);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t server_tcp_app_connect_action(tcp_lsnr_t *lsnr, cs_pipe_t *pipe)
{
    if (g_instance->kernel.switch_ctrl.request != SWITCH_REQ_NONE) {
        cs_tcp_disconnect(&pipe->link.tcp);
        GS_THROW_ERROR(ERR_SESSION_CLOSED, "server is doing switch request");
        return GS_ERROR;
    }

    if (server_check_tcp_ip(pipe) != GS_SUCCESS) {
        cs_tcp_disconnect(&pipe->link.tcp);
        return GS_ERROR;
    }

    if (server_create_session(pipe) != GS_SUCCESS) {
        cs_tcp_disconnect(&pipe->link.tcp);
        GS_THROW_ERROR(ERR_CREATE_AGENT, "agent");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t server_uds_connect_action(uds_lsnr_t *lsnr, cs_pipe_t *pipe)
{
    status_t status;

    {
        if (g_instance->kernel.switch_ctrl.request != SWITCH_REQ_NONE) {
            cs_uds_disconnect(&pipe->link.uds);
            GS_THROW_ERROR(ERR_SESSION_CLOSED, "server is doing switch request");
            return GS_ERROR;
        }
        status = server_create_session(pipe);
    }

    if (status != GS_SUCCESS) {
        GS_LOG_RUN_ERR("UDS connect, create %s session failed", lsnr->is_emerg ? "emerg" : "user");
        cs_uds_disconnect(&pipe->link.uds);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t server_start_replica_lsnr(void)
{
    status_t status = GS_SUCCESS;

    g_instance->lsnr.tcp_replica.type = LSNR_TYPE_REPLICA;

    return status;
}

status_t server_start_lsnr(void)
{
    status_t status;

    g_instance->lsnr.tcp_service.type = LSNR_TYPE_SERVICE;
    status = cs_start_tcp_lsnr(&g_instance->lsnr.tcp_service, server_tcp_app_connect_action, GS_FALSE);
    if (status != GS_SUCCESS) {
        GS_LOG_RUN_ERR("failed to start lsnr for LSNR_ADDR");
        return status;
    }

    status = server_start_replica_lsnr();
    if (status != GS_SUCCESS) {
        cs_stop_tcp_lsnr(&g_instance->lsnr.tcp_service);
        return status;
    }

    g_instance->lsnr.uds_service.type = LSNR_TYPE_UDS;
    status = cs_start_uds_lsnr(&g_instance->lsnr.uds_service, server_uds_connect_action);
    if (status != GS_SUCCESS) {
        cs_stop_tcp_lsnr(&g_instance->lsnr.tcp_replica);
        cs_stop_tcp_lsnr(&g_instance->lsnr.tcp_service);
        GS_LOG_RUN_ERR("failed to start lsnr for UDS");
        return status;
    }

    return GS_SUCCESS;
}

void server_pause_lsnr(lsnr_type_t type)
{
    switch (type) {
        case LSNR_TYPE_SERVICE:
            cs_pause_tcp_lsnr(&g_instance->lsnr.tcp_service);
            break;
        case LSNR_TYPE_REPLICA:
            if (g_instance->lsnr.tcp_replica.port != 0) {
                cs_pause_tcp_lsnr(&g_instance->lsnr.tcp_replica);
            }
            break;
        case LSNR_TYPE_UDS:
            cs_pause_uds_lsnr(&g_instance->lsnr.uds_service);
            break;
        default:
            cs_pause_tcp_lsnr(&g_instance->lsnr.tcp_service);
            if (g_instance->lsnr.tcp_replica.port != 0) {
                cs_pause_tcp_lsnr(&g_instance->lsnr.tcp_replica);
            }
            cs_pause_uds_lsnr(&g_instance->lsnr.uds_service);
            break;
    }

    return;
}

void server_resume_lsnr(lsnr_type_t type)
{
    switch (type) {
        case LSNR_TYPE_SERVICE:
            cs_resume_tcp_lsnr(&g_instance->lsnr.tcp_service);
            break;
        case LSNR_TYPE_REPLICA:
            if (g_instance->lsnr.tcp_replica.port != 0) {
                cs_resume_tcp_lsnr(&g_instance->lsnr.tcp_replica);
            }
            break;
        case LSNR_TYPE_UDS:
            cs_resume_uds_lsnr(&g_instance->lsnr.uds_service);
            break;
        default:
            cs_resume_tcp_lsnr(&g_instance->lsnr.tcp_service);
            if (g_instance->lsnr.tcp_replica.port != 0) {
                cs_resume_tcp_lsnr(&g_instance->lsnr.tcp_replica);
            }
            cs_resume_uds_lsnr(&g_instance->lsnr.uds_service);
            break;
    }

    return;
}

void server_stop_lsnr(lsnr_type_t type)
{
    switch (type) {
        case LSNR_TYPE_SERVICE:
            cs_stop_tcp_lsnr(&g_instance->lsnr.tcp_service);
            break;
        case LSNR_TYPE_REPLICA:
            if (g_instance->lsnr.tcp_replica.port != 0) {
                cs_stop_tcp_lsnr(&g_instance->lsnr.tcp_replica);
            }
            break;
        case LSNR_TYPE_UDS:
            cs_stop_uds_lsnr(&g_instance->lsnr.uds_service);
            break;
        default:
            cs_stop_tcp_lsnr(&g_instance->lsnr.tcp_service);
            if (g_instance->lsnr.tcp_replica.port != 0) {
                cs_stop_tcp_lsnr(&g_instance->lsnr.tcp_replica);
            }
            cs_stop_uds_lsnr(&g_instance->lsnr.uds_service);
            break;
    }

    return;
}

#ifdef __cplusplus
}
#endif
