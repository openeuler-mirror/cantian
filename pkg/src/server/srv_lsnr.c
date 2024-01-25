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
 * srv_lsnr.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_lsnr.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "srv_lsnr.h"
#include "srv_agent.h"
#include "srv_instance.h"
#include "srv_replica.h"
#include "srv_emerg.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t srv_check_tcp_ip(cs_pipe_t *pipe)
{
    char ipstr[CM_MAX_IP_LEN];
    status_t status;
    bool32 check_res = CT_FALSE;
    (void)cm_inet_ntop((struct sockaddr *)&pipe->link.tcp.remote.addr, ipstr, CM_MAX_IP_LEN);
    status = cm_check_remote_ip(GET_WHITE_CTX, ipstr, &check_res);
    if (status == CT_ERROR || !check_res) {
        CT_THROW_ERROR(ERR_TCP_INVALID_IPADDRESS, ipstr);
        sql_audit_log_ddos(ipstr);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t srv_tcp_app_connect_action(tcp_lsnr_t *lsnr, cs_pipe_t *pipe)
{
    if (g_instance->kernel.switch_ctrl.request != SWITCH_REQ_NONE) {
        cs_tcp_disconnect(&pipe->link.tcp);
        CT_THROW_ERROR(ERR_SESSION_CLOSED, "server is doing switch request");
        return CT_ERROR;
    }

    if (srv_check_tcp_ip(pipe) != CT_SUCCESS) {
        cs_tcp_disconnect(&pipe->link.tcp);
        return CT_ERROR;
    }

    if (srv_create_session(pipe) != CT_SUCCESS) {
        cs_tcp_disconnect(&pipe->link.tcp);
        CT_THROW_ERROR(ERR_CREATE_AGENT, "agent");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t srv_tcp_replica_connect_action(tcp_lsnr_t *lsnr, cs_pipe_t *pipe)
{
    if (srv_create_replica_session(pipe) != CT_SUCCESS) {
        cs_tcp_disconnect(&pipe->link.tcp);
        CT_THROW_ERROR(ERR_CREATE_AGENT, "replica agent");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t srv_uds_connect_action(uds_lsnr_t *lsnr, cs_pipe_t *pipe)
{
    status_t status;

    if (lsnr->is_emerg) {
        status = srv_create_emerg_session(pipe);
    } else {
        if (g_instance->kernel.switch_ctrl.request != SWITCH_REQ_NONE) {
            cs_uds_disconnect(&pipe->link.uds);
            CT_THROW_ERROR(ERR_SESSION_CLOSED, "server is doing switch request");
            return CT_ERROR;
        }
        status = srv_create_session(pipe);
    }

    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("UDS connect, create %s session failed", lsnr->is_emerg ? "emerg" : "user");
        cs_uds_disconnect(&pipe->link.uds);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t srv_start_replica_lsnr(void)
{
    status_t status = CT_SUCCESS;

    g_instance->lsnr.tcp_replica.type = LSNR_TYPE_REPLICA;
    if (g_instance->lsnr.tcp_replica.port != 0) {
        status = cs_start_tcp_lsnr(&g_instance->lsnr.tcp_replica, srv_tcp_replica_connect_action, CT_TRUE);
        if (status != CT_SUCCESS) {
            CT_LOG_RUN_ERR("failed to start lsnr for REPL_ADDR");
        }
    }

    return status;
}

status_t srv_start_lsnr(void)
{
    status_t status;

    g_instance->lsnr.tcp_service.type = LSNR_TYPE_SERVICE;
    status = cs_start_tcp_lsnr(&g_instance->lsnr.tcp_service, srv_tcp_app_connect_action, CT_FALSE);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("failed to start lsnr for LSNR_ADDR");
        return status;
    }

    status = srv_start_replica_lsnr();
    if (status != CT_SUCCESS) {
        cs_stop_tcp_lsnr(&g_instance->lsnr.tcp_service);
        return status;
    }

    g_instance->lsnr.uds_service.type = LSNR_TYPE_UDS;
    status = cs_start_uds_lsnr(&g_instance->lsnr.uds_service, srv_uds_connect_action);
    if (status != CT_SUCCESS) {
        cs_stop_tcp_lsnr(&g_instance->lsnr.tcp_replica);
        cs_stop_tcp_lsnr(&g_instance->lsnr.tcp_service);
        CT_LOG_RUN_ERR("failed to start lsnr for UDS");
        return status;
    }

    return CT_SUCCESS;
}

void srv_pause_lsnr(lsnr_type_t type)
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

void srv_resume_lsnr(lsnr_type_t type)
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

void srv_stop_lsnr(lsnr_type_t type)
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
