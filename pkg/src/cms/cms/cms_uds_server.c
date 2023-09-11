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
 * cms_uds_server.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_uds_server.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_signal.h"
#include "cms_msg_def.h"
#include "cms_instance.h"
#include "cms_gcc.h"
#include "cms_param.h"
#include "cms_comm.h"
#include "cms_socket.h"
#include "cms_stat.h"
#include "cms_node_fault.h"
#include "cms_mes.h"
#include "mes_func.h"
#include "cms_log.h"
#include "cms_uds_server.h"

status_t cms_uds_srv_init(void)
{
    status_t ret = GS_SUCCESS;
    errno_t err = EOK;
    char uds_server_path[GS_FILE_NAME_BUFFER_SIZE] = {0};
    err = sprintf_s(uds_server_path, sizeof(uds_server_path), "%s/" CMS_UDS_PATH "_%d", g_cms_param->cms_home,
        (int32)g_cms_param->node_id);
    if (err == -1) {
        CMS_LOG_ERR("sprintf_s failed, errno %d[%s]", cm_get_os_error(), strerror(errno));
        return GS_ERROR;
    }
    
    ret = cms_uds_create_listener(uds_server_path, &g_cms_inst->uds_server);
    if (ret != GS_SUCCESS) {
        CMS_LOG_ERR("create uds listener failed, ret %d, uds path %s", ret, uds_server_path);
        return GS_ERROR;
    }

    ret = cm_regist_signal(SIGPIPE, SIG_IGN);
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_ERR("set singal ignore SIGPIE failed, ret %d", ret);
        cms_socket_close(g_cms_inst->uds_server);
        return ret;
    }

    ret = cms_socket_setopt_close_exec(g_cms_inst->uds_server);
    if (ret != GS_SUCCESS) {
        CMS_LOG_ERR("socket setopt close exec failed, ret %d, sock %d, errno %d[%s]", ret, g_cms_inst->uds_server,
            cm_get_os_error(), strerror(errno));
        cms_socket_close(g_cms_inst->uds_server);
        return ret;
    }

    ret = cms_socket_setopt_reuse(g_cms_inst->uds_server, GS_TRUE);
    if (ret != GS_SUCCESS) {
        CMS_LOG_ERR("socket setopt reuse failed, ret %d, sock %d, errno %d[%s]", ret, g_cms_inst->uds_server,
            cm_get_os_error(), strerror(errno));
        cms_socket_close(g_cms_inst->uds_server);
        return ret;
    }
    CMS_LOG_INF("create uds listener succ, uds path %s, uds sock %d", uds_server_path, g_cms_inst->uds_server);
    return GS_SUCCESS;
}

status_t cms_uds_srv_conn(socket_t sock, cms_cli_msg_req_conn_t *req, cms_cli_msg_res_conn_t *res)
{
    status_t ret = GS_SUCCESS;
    if (req->cli_type == CMS_CLI_RES) {
        ret = cms_res_connect(sock, req, res);
        if (ret != GS_SUCCESS) {
            CMS_LOG_ERR("process resource connect req failed, sock %d, res type %s, inst id %u",
                sock, req->res_type, req->inst_id);
            return ret;
        }
    } else if (req->cli_type == CMS_CLI_TOOL) {
        ret = cms_tool_connect(sock, req, res);
        if (ret != GS_SUCCESS) {
            CMS_LOG_ERR("process tool connect req failed, sock %d, res type %s, inst id %u",
                sock, req->res_type, req->inst_id);
            return ret;
        }
    } else {
        CMS_LOG_ERR("invalid cli type, cli type %d", req->cli_type);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t cms_uds_srv_accept_conn(socket_t* sock, cms_cli_msg_req_conn_t* req, cms_cli_msg_res_conn_t* res)
{
    status_t ret = GS_SUCCESS;
    errno_t err = EOK;

    ret = cms_socket_accept(g_cms_inst->uds_server, CMS_SRV_ACCEPT_TMOUT, sock);
    if (ret != GS_SUCCESS) {
        CMS_LOG_INF("accetp failed, ret %d", ret);
        return ret;
    }
    if (req->cli_type != CMS_CLI_TOOL) {
        CMS_LOG_INF("accept uds sock succ, sock %d", *sock);
    }
    err = memset_s(req, sizeof(cms_cli_msg_req_conn_t), 0, sizeof(cms_cli_msg_req_conn_t));
    if (err != EOK) {
        CMS_LOG_ERR("memset_s faild, ret %d, errno %d[%s]", err, errno, strerror(errno));
        return GS_ERROR;
    }
    err = memset_s(res, sizeof(cms_cli_msg_res_conn_t), 0, sizeof(cms_cli_msg_res_conn_t));
    if (err != EOK) {
        CMS_LOG_ERR("memset_s faild, ret %d, errno %d[%s]", err, errno, strerror(errno));
        return GS_ERROR;
    }
    ret = cms_socket_recv(*sock, &req->head, sizeof(cms_cli_msg_req_conn_t), CMS_SRV_RECV_TMOUT, GS_FALSE);
    if (ret != GS_SUCCESS) {
        CMS_LOG_ERR("recv failed, ret %d", ret);
        return ret;
    }
    if (req->cli_type != CMS_CLI_TOOL) {
        CMS_LOG_INF("recv conn req succ, sock %d", *sock);
    }
    if (req->head.msg_type != CMS_CLI_MSG_REQ_CONNECT) {
        CMS_LOG_ERR("recv invalid mes, msg type %u", req->head.msg_type);
        return GS_ERROR;
    }

    ret = cms_uds_srv_conn(*sock, req, res);
    if (ret != GS_SUCCESS) {
        CMS_LOG_ERR("process the connection request from the client failed, sock %d, res type %s, inst id %u",
            *sock, req->res_type, req->inst_id);
        return ret;
    }

    ret = cms_socket_send(*sock, &res->head, CMS_SRV_SEND_TMOUT);
    if (ret != GS_SUCCESS) {
        CMS_LOG_ERR("send conn res failed, sock %d, res type %s, inst id %u, session id %llu",
            *sock, req->res_type, req->inst_id, res->session_id);
        return ret;
    }
    return GS_SUCCESS;
}

void cms_uds_srv_listen_entry(thread_t* thread)
{
    socket_t sock = CMS_IO_INVALID_SOCKET;
    status_t ret = GS_SUCCESS;
    cms_cli_msg_req_conn_t req;
    cms_cli_msg_res_conn_t res;

    while (!thread->closed) {
        sock = CMS_IO_INVALID_SOCKET;
        ret = cms_uds_srv_accept_conn(&sock, &req, &res);
        if (ret != GS_SUCCESS) {
            CMS_LOG_ERR("cms uds accept new conn failed, ret %d, sock %d", ret, sock);
            if (sock != CMS_IO_INVALID_SOCKET) {
                cms_socket_close(sock);
            }
            continue;
        }
        CMS_LOG_INF("accept new conn succ, sock %d, res type %s, inst id %u, session id %llu",
            sock, req.res_type, req.inst_id, res.session_id);
    }
}

status_t cms_uds_srv_disconn(socket_t sock, cms_res_session_t* res_sessions, uint32 sessions_count)
{
    status_t ret = GS_SUCCESS;

    for (uint32 i = 0; i < sessions_count; i++) {
        if (res_sessions[i].uds_sock != sock) {
            continue;
        }

        if (res_sessions[i].type == CMS_CLI_RES) {
            CMS_LOG_INF("begin process client disconnect req, session id %d, sock %d", i, sock);
            ret = cms_res_detect_offline(i, NULL);
            if (ret != GS_SUCCESS) {
                CMS_LOG_ERR("cms res detect offline failed, ret %d, res id %d, sock %d", ret, i, sock);
                return ret;
            }
            CMS_LOG_INF("process client disconnect req succ, sock %d", sock);
        } else if (res_sessions[i].type == CMS_CLI_TOOL) {
            cms_tool_detect_offline(i);
        }
        break;
    }
    return GS_SUCCESS;
}

status_t cms_uds_srv_recv_msg(socket_t sock, char* msg_buf, uint32 msg_len)
{
    status_t ret = GS_SUCCESS;
    
    ret = cms_socket_recv(sock, (cms_packet_head_t*)msg_buf, msg_len, CMS_SRV_RECV_TMOUT, GS_FALSE);
    if (ret != GS_SUCCESS) {
        CMS_LOG_ERR("cms_socket_recv failed, ret %d", ret);
        return ret;
    }

    cms_packet_head_t* head = (cms_packet_head_t*)msg_buf;
    biqueue_node_t* node = cms_que_alloc_node_ex((char*)head, head->msg_size);
    if (node == NULL) {
        CMS_LOG_ERR("cms que alloc node failed");
        return GS_ERROR;
    }
    CMS_LOG_DEBUG_INF("recv one msg, sock %d, msg type %u, msg seg %llu", sock, head->msg_type, head->msg_seq);
    if (head->msg_type == CMS_CLI_MSG_REQ_HB) {
        cms_enque_ex(&g_cms_inst->cli_recv_que, node, CMS_QUE_PRIORITY_HIGH);
    } else {
        cms_enque_ex(&g_cms_inst->cli_recv_que, node, CMS_QUE_PRIORITY_NORMAL);
    }
    
    return GS_SUCCESS;
}

void cms_uds_srv_proc_pevents(struct pollfd *pfd, uint32 count, cms_res_session_t *res_sessions,
    uint32 sessions_count)
{
    status_t ret = GS_SUCCESS;
    static char msg_buf[CMS_MAX_MSG_SIZE] = {0};

    for (uint32 i = 0; i < count; i++) {
        if (pfd[i].revents & POLLHUP) {
            ret = cms_uds_srv_disconn(pfd[i].fd, res_sessions, sessions_count);
            if (ret != GS_SUCCESS) {
                CMS_LOG_ERR("cms proc res disconn event failed, ret %d, socke %d", ret, pfd[i].fd);
                continue;
            }
        } else if (pfd[i].revents & POLLIN) {
            ret = cms_uds_srv_recv_msg(pfd[i].fd, msg_buf, CMS_MAX_MSG_SIZE);
            if (ret != GS_SUCCESS) {
                CMS_LOG_ERR("cms recv uds msg failed, ret %d", ret);
                continue;
            }
        } else {
            CMS_LOG_INF("get other poll event, revents %d", pfd[i].revents);
        }
    }
}

status_t cms_uds_srv_recv_proc(void)
{
    status_t ret = GS_SUCCESS;
    struct pollfd pfd[CMS_MAX_UDS_SESSION_COUNT];
    uint32 uds_count = 0;
    cms_res_session_t res_sessions[CMS_MAX_UDS_SESSION_COUNT];

    ret = cms_get_res_session(res_sessions, sizeof(res_sessions));
    if (ret != GS_SUCCESS) {
        CMS_LOG_ERR("get res session failed, ret %d", ret);
        return ret;
    }

    for (uint32 i = 0; i < CMS_MAX_UDS_SESSION_COUNT; i++) {
        if (res_sessions[i].uds_sock > 0) {
            pfd[uds_count].fd = res_sessions[i].uds_sock;
            pfd[uds_count].events = POLLIN;
            pfd[uds_count].revents = 0;
            uds_count++;
        }
    }

    if (uds_count == 0) {
        cm_sleep(CMS_SRV_RECV_SLEEP);
        return GS_SUCCESS;
    }

    ret = cs_tcp_poll(pfd, uds_count, CMS_SRV_POOL_TMOUT);
    if (ret < 0) {
        CMS_LOG_ERR("cs tcp poll failed, ret %d", ret);
        return GS_ERROR;
    }
    cms_uds_srv_proc_pevents(pfd, uds_count, res_sessions, CMS_MAX_UDS_SESSION_COUNT);
    return GS_SUCCESS;
}

void cms_uds_srv_recv_entry(thread_t* thread)
{
    status_t ret = GS_SUCCESS;

    CMS_LOG_INF("start uds recv entry thread");
    while (!thread->closed) {
        ret = cms_uds_srv_recv_proc();
        if (ret != GS_SUCCESS) {
            CMS_LOG_ERR("cms uds recv proc failed, ret %d", ret);
        }
    }
    CMS_LOG_INF("end uds recv entry thread");
}

status_t cms_uds_srv_send_proc(void)
{
    status_t ret = GS_SUCCESS;
    socket_t uds_sock = CMS_IO_INVALID_SOCKET;

    biqueue_node_t *node = cms_deque(&g_cms_inst->cli_send_que);
    if (node == NULL) {
        return GS_SUCCESS;
    }

    cms_packet_head_t* msg = (cms_packet_head_t*)cms_que_node_data(node);
    CMS_LOG_DEBUG_INF("get one msg to send, msg type %u, msg seq %llu, src msg seq %llu",
        msg->msg_type, msg->msg_seq, msg->src_msg_seq);
    ret = cms_stat_get_uds(msg->uds_sid, &uds_sock);
    if (ret != GS_SUCCESS || uds_sock == CMS_IO_INVALID_SOCKET) {
        CMS_LOG_ERR("get connected uds sock failed, ret %d, sock %d, msg type %u, msg seq %llu, src msg seq %llu",
            ret, uds_sock, msg->msg_type, msg->msg_seq, msg->src_msg_seq);
        cms_que_free_node(node);
        return GS_ERROR;
    }
    ret = cms_socket_send(uds_sock, msg, CMS_SRV_SEND_TMOUT);
    if (ret != GS_SUCCESS) {
        CMS_LOG_ERR("uds send failed, ret %d, sock %d, msg type %u, msg seq %llu, src msg seq %llu",
            ret, uds_sock, msg->msg_type, msg->msg_seq, msg->src_msg_seq);
        cms_que_free_node(node);
        return GS_ERROR;
    }
    CMS_LOG_DEBUG_INF("uds send msg succ, sock %d, msg type %u, msg seq %llu, src msg seq %llu",
        uds_sock, msg->msg_type, msg->msg_seq, msg->src_msg_seq);
    cms_que_free_node(node);
    return GS_SUCCESS;
}

void cms_uds_srv_send_entry(thread_t* thread)
{
    status_t ret = GS_SUCCESS;
    CMS_LOG_INF("start uds send entry thread");
    while (!thread->closed) {
        ret = cms_uds_srv_send_proc();
        if (ret != GS_SUCCESS) {
            CMS_LOG_ERR("cms uds send proc failed, ret %d", ret);
        }
    }
    CMS_LOG_INF("end uds send entry thread");
}
