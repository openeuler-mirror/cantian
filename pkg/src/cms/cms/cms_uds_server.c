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
 * cms_uds_server.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_uds_server.c
 *
 * -------------------------------------------------------------------------
 */
#include "cms_log_module.h"
#include "cm_signal.h"
#include "cm_hashmap.h"
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

typedef struct st_srv_request_info {
    cms_packet_head_t* send_msg;  // caller to release this mem
    cms_packet_head_t* recv_msg;
    pthread_condattr_t recv_cond_attr;
    pthread_cond_t recv_cond;
} srv_request_info_t;

cm_oamap_t               g_srv_req_map;
thread_lock_t            g_srv_req_map_lock;

bool32 cms_uds_srv_seq_compare(void *key1, void *key2)
{
    CM_POINTER2(key1, key2);
    uint64 *seq1 = (uint64*)key1;
    uint64 *seq2 = (uint64*)key2;

    if (*seq1 == *seq2) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

void cms_free_srv_req_info(srv_request_info_t* req_info)
{
    if (req_info == NULL) {
        return;
    }

    if (req_info->recv_msg != NULL) {
        CM_FREE_PTR(req_info->recv_msg);
    }
    (void)pthread_condattr_destroy(&req_info->recv_cond_attr);
    (void)pthread_cond_destroy(&req_info->recv_cond);
    CM_FREE_PTR(req_info);
    return;
}

srv_request_info_t* cms_new_srv_req_info(cms_packet_head_t* req)
{
    srv_request_info_t *req_info = malloc(sizeof(srv_request_info_t));
    if (req_info == NULL) {
        CT_LOG_RUN_ERR("malloc failed, size %u, errno %d[%s]", (uint32)sizeof(srv_request_info_t),
            errno, strerror(errno));
        return NULL;
    }

    int32 ret = pthread_condattr_init(&req_info->recv_cond_attr);
    if (ret != 0) {
        CT_LOG_RUN_ERR("pthread condattr init failed, ret %d", ret);
        CM_FREE_PTR(req_info);
        return NULL;
    }
    ret = pthread_condattr_setclock(&req_info->recv_cond_attr, CLOCK_MONOTONIC);
    if (ret != 0) {
        CT_LOG_RUN_ERR("pthread condattr setclock failed, ret %d", ret);
        (void)pthread_condattr_destroy(&req_info->recv_cond_attr);
        CM_FREE_PTR(req_info);
        return NULL;
    }
    ret = pthread_cond_init(&req_info->recv_cond, &req_info->recv_cond_attr);
    if (ret != 0) {
        CT_LOG_RUN_ERR("pthread cond init failed, ret %d", ret);
        (void)pthread_condattr_destroy(&req_info->recv_cond_attr);
        CM_FREE_PTR(req_info);
        return NULL;
    }
    req_info->send_msg = req;
    req_info->recv_msg = NULL;

    return req_info;
}

void cms_uds_srv_del_req(cms_packet_head_t* req)
{
    srv_request_info_t *req_info = (srv_request_info_t*)cm_oamap_lookup(&g_srv_req_map,
        cm_hash_int64((uint64)req->msg_seq), &req->msg_seq);
    if (req_info != NULL) {
        CT_LOG_DEBUG_INF("del req from hashmap, msg type %u, msg req %llu", req->msg_type,
            req->msg_seq);
        cms_free_srv_req_info(req_info);
    }
    cm_oamap_remove(&g_srv_req_map, cm_hash_int64((uint64)req->msg_seq), &req->msg_seq);
    return;
}

status_t cms_uds_srv_init(void)
{
    status_t ret = CT_SUCCESS;
    errno_t err = EOK;
    char uds_server_path[CT_FILE_NAME_BUFFER_SIZE] = {0};
    err = sprintf_s(uds_server_path, sizeof(uds_server_path), "%s/" CMS_UDS_PATH "_%d", g_cms_param->cms_home,
        (int32)g_cms_param->node_id);
    if (err == -1) {
        CMS_LOG_ERR("sprintf_s failed, errno %d[%s]", cm_get_os_error(), strerror(errno));
        return CT_ERROR;
    }
    
    ret = cms_uds_create_listener(uds_server_path, &g_cms_inst->uds_server);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("create uds listener failed, ret %d, uds path %s", ret, uds_server_path);
        return CT_ERROR;
    }

    ret = cm_regist_signal(SIGPIPE, SIG_IGN);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("set singal ignore SIGPIE failed, ret %d", ret);
        cms_socket_close(g_cms_inst->uds_server);
        return ret;
    }

    ret = cms_socket_setopt_close_exec(g_cms_inst->uds_server);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("socket setopt close exec failed, ret %d, sock %d, errno %d[%s]", ret, g_cms_inst->uds_server,
            cm_get_os_error(), strerror(errno));
        cms_socket_close(g_cms_inst->uds_server);
        return ret;
    }

    ret = cms_socket_setopt_reuse(g_cms_inst->uds_server, CT_TRUE);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("socket setopt reuse failed, ret %d, sock %d, errno %d[%s]", ret, g_cms_inst->uds_server,
            cm_get_os_error(), strerror(errno));
        cms_socket_close(g_cms_inst->uds_server);
        return ret;
    }

    // 初始化线程锁
    cm_init_thread_lock(&g_srv_req_map_lock);
    ret = cm_oamap_init(&g_srv_req_map, CMS_SRV_SEND_MSG_HASH_SIZE, cms_uds_srv_seq_compare);
    if (ret != CT_SUCCESS) {
        cm_destroy_thread_lock(&g_srv_req_map_lock);
        CMS_LOG_ERR("init srv send map failed, ret %d", ret);
        return ret;
    }

    CMS_LOG_INF("create uds listener succ, uds path %s, uds sock %d", uds_server_path, g_cms_inst->uds_server);
    return CT_SUCCESS;
}

status_t cms_uds_srv_conn(socket_t sock, cms_cli_msg_req_conn_t *req, cms_cli_msg_res_conn_t *res)
{
    status_t ret = CT_SUCCESS;
    if (req->cli_type == CMS_CLI_RES) {
        ret = cms_res_connect(sock, req, res);
        if (ret != CT_SUCCESS) {
            CMS_LOG_ERR("process resource connect req failed, sock %d, res type %s, inst id %u",
                sock, req->res_type, req->inst_id);
            return ret;
        }
    } else if (req->cli_type == CMS_CLI_TOOL) {
        ret = cms_tool_connect(sock, req, res);
        if (ret != CT_SUCCESS) {
            CMS_LOG_ERR("process tool connect req failed, sock %d, res type %s, inst id %u",
                sock, req->res_type, req->inst_id);
            return ret;
        }
    } else {
        CMS_LOG_ERR("invalid cli type, cli type %d", req->cli_type);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cms_uds_srv_accept_conn_reset_req_res(cms_cli_msg_req_conn_t* req, cms_cli_msg_res_conn_t* res)
{
    errno_t err = EOK;
    err = memset_s(req, sizeof(cms_cli_msg_req_conn_t), 0, sizeof(cms_cli_msg_req_conn_t));
    if (err != EOK) {
        CMS_LOG_ERR("memset_s faild, ret %d, errno %d[%s]", err, errno, strerror(errno));
        return CT_ERROR;
    }
    err = memset_s(res, sizeof(cms_cli_msg_res_conn_t), 0, sizeof(cms_cli_msg_res_conn_t));
    if (err != EOK) {
        CMS_LOG_ERR("memset_s faild, ret %d, errno %d[%s]", err, errno, strerror(errno));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void cms_uds_srv_thread_unlock(cms_cli_msg_req_conn_t* req, uint32 res_id)
{
    if (req->cli_type != CMS_CLI_TOOL) {
        cm_thread_unlock(&g_res_session[res_id].uds_lock);
    }
}

status_t cms_uds_srv_accept_conn(socket_t* sock, cms_cli_msg_req_conn_t* req, cms_cli_msg_res_conn_t* res)
{
    status_t ret = CT_SUCCESS;
    uint32 res_id;

    ret = cms_socket_accept(g_cms_inst->uds_server, CMS_SRV_ACCEPT_TMOUT, sock);
    if (ret != CT_SUCCESS) {
        CMS_LOG_INF("accetp failed, ret %d", ret);
        return ret;
    }

    CT_RETURN_IFERR(cms_uds_srv_accept_conn_reset_req_res(req, res));

    ret = cms_socket_recv(*sock, &req->head, sizeof(cms_cli_msg_req_conn_t), CMS_SRV_RECV_TMOUT, CT_FALSE);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("recv failed, ret %d", ret);
        return ret;
    }

    if (req->head.msg_type != CMS_CLI_MSG_REQ_CONNECT) {
        CMS_LOG_ERR("recv invalid mes, msg type %u", req->head.msg_type);
        return CT_ERROR;
    }

    if (req->cli_type != CMS_CLI_TOOL) {
        CMS_LOG_INF("recv conn req succ, sock %d", *sock);
        if (cms_get_res_id_by_type(req->res_type, &res_id) != CT_SUCCESS) {
            CMS_LOG_ERR("cms get res id failed");
            return CT_ERROR;
        }
        cm_thread_lock(&g_res_session[res_id].uds_lock);
    }

    ret = cms_uds_srv_conn(*sock, req, res);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("process the connection request from the client failed, sock %d, res type %s, inst id %u",
            *sock, req->res_type, req->inst_id);
        cms_uds_srv_thread_unlock(req, res_id);
        return ret;
    }

    ret = cms_socket_send(*sock, &res->head, CMS_SRV_SEND_TMOUT);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("send conn res failed, sock %d, res type %s, inst id %u, session id %llu",
            *sock, req->res_type, req->inst_id, res->session_id);
        cms_uds_srv_thread_unlock(req, res_id);
        return ret;
    }
    cms_uds_srv_thread_unlock(req, res_id);
    return CT_SUCCESS;
}

void cms_uds_srv_listen_entry(thread_t* thread)
{
    socket_t sock = CMS_IO_INVALID_SOCKET;
    status_t ret = CT_SUCCESS;
    cms_cli_msg_req_conn_t req;
    cms_cli_msg_res_conn_t res;

    while (!thread->closed) {
        sock = CMS_IO_INVALID_SOCKET;
        ret = cms_uds_srv_accept_conn(&sock, &req, &res);
        if (ret != CT_SUCCESS) {
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
    status_t ret = CT_SUCCESS;

    for (uint32 i = 0; i < sessions_count; i++) {
        if (res_sessions[i].uds_sock != sock) {
            continue;
        }

        if (res_sessions[i].type == CMS_CLI_RES) {
            CMS_LOG_INF("begin process client disconnect req, session id %d, sock %d", i, sock);
            ret = cms_res_detect_offline(i, NULL);
            if (ret != CT_SUCCESS) {
                CMS_LOG_ERR("cms res detect offline failed, ret %d, res id %d, sock %d", ret, i, sock);
                return ret;
            }
            CMS_LOG_INF("process client disconnect cli res req succ, sock %u, sessionId %u", sock, i);
        } else if (res_sessions[i].type == CMS_CLI_TOOL) {
            cms_tool_detect_offline(i);
            CMS_LOG_INF("process client disconnect cli tool req succ, sock %d sessionId %u", sock, i);
        }
        break;
    }
    return CT_SUCCESS;
}

status_t cms_uds_srv_recv_msg(socket_t sock, char* msg_buf, uint32 msg_len, bool32 is_retry_conn)
{
    status_t ret = CT_SUCCESS;
    
    ret = cms_socket_recv(sock, (cms_packet_head_t*)msg_buf, msg_len, CMS_SRV_RECV_TMOUT, is_retry_conn);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("cms_socket_recv failed, ret %d", ret);
        return ret;
    }

    cms_packet_head_t* head = (cms_packet_head_t*)msg_buf;
    biqueue_node_t* node = cms_que_alloc_node_ex((char*)head, head->msg_size);
    if (node == NULL) {
        CMS_LOG_ERR("cms que alloc node failed");
        return CT_ERROR;
    }
    CMS_LOG_DEBUG_INF("recv one msg, sock %d, msg type %u, msg seg %llu", sock, head->msg_type, head->msg_seq);
    if (head->msg_type == CMS_CLI_MSG_REQ_HB) {
        cms_enque_ex(&g_cms_inst->cli_recv_que, node, CMS_QUE_PRIORITY_HIGH);
    } else {
        cms_enque_ex(&g_cms_inst->cli_recv_que, node, CMS_QUE_PRIORITY_NORMAL);
    }
    
    return CT_SUCCESS;
}

void cms_handle_sockpoll_timeout(socket_t sock, cms_res_session_t *res_sessions, uint32 sessions_count)
{
    status_t ret = CT_SUCCESS;
    static char msg_buf[CMS_MAX_MSG_SIZE] = {0};

    ret = cms_uds_srv_recv_msg(sock, msg_buf, CMS_MAX_MSG_SIZE, CT_TRUE);
    if (ret == CT_ERROR_CONN_CLOSED) {
        CMS_LOG_INF("sock: %d poll timeout & connection is closed by peer, ret: %d, errno: %d",
            sock, ret, errno);
        ret = cms_uds_srv_disconn(sock, res_sessions, sessions_count);
        if (ret != CT_SUCCESS) {
            CMS_LOG_ERR("cms proc res disconn event failed, ret %d, socke %d", ret, sock);
        }
    }
}

void cms_uds_srv_proc_pevents(struct pollfd *pfd, cms_cli_type_t *type, uint32 count, cms_res_session_t *res_sessions,
    uint32 sessions_count, bool32 timeout)
{
    status_t ret = CT_SUCCESS;
    static char msg_buf[CMS_MAX_MSG_SIZE] = {0};

    for (uint32 i = 0; i < count; i++) {
        if (pfd[i].revents & POLLHUP) {
            ret = cms_uds_srv_disconn(pfd[i].fd, res_sessions, sessions_count);
            if (ret != CT_SUCCESS) {
                CMS_LOG_ERR("cms proc res disconn event failed, ret %d, socke %d", ret, pfd[i].fd);
                continue;
            }
        } else if (pfd[i].revents & POLLIN) {
            ret = cms_uds_srv_recv_msg(pfd[i].fd, msg_buf, CMS_MAX_MSG_SIZE, CT_FALSE);
            if (ret != CT_SUCCESS) {
                CMS_LOG_ERR("cms recv uds msg failed, ret %d", ret);
                continue;
            }
        } else if (pfd[i].revents == 0 && type[i] == CMS_CLI_RES && timeout == CT_TRUE) {
            cms_handle_sockpoll_timeout(pfd[i].fd, res_sessions, sessions_count);
        } else {
            CMS_LOG_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_10, "get other poll event, type %d revents %d",
                type[i], pfd[i].revents);
        }
    }
}

bool32 cms_uds_res_db_timeout(struct pollfd *pfd, cms_cli_type_t *type, uint32 count)
{
    for (uint32 i = 0; i < count; i++) {
        if (pfd[i].revents == 0 && type[i] == CMS_CLI_RES) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

status_t cms_uds_srv_recv_proc(void)
{
    status_t ret = CT_SUCCESS;
    struct pollfd pfd[CMS_MAX_UDS_SESSION_COUNT];
    cms_cli_type_t type[CMS_MAX_UDS_SESSION_COUNT];
    uint32 uds_count = 0;
    bool32 is_timeout = CT_FALSE;
    status_t poll_ret = 0;
    uint32 retry_times = 0;
    cms_res_session_t res_sessions[CMS_MAX_UDS_SESSION_COUNT];

    ret = cms_get_res_session(res_sessions, sizeof(res_sessions));
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("get res session failed, ret %d", ret);
        return ret;
    }

    for (uint32 i = 0; i < CMS_MAX_UDS_SESSION_COUNT; i++) {
        if (res_sessions[i].uds_sock > 0) {
            pfd[uds_count].fd = res_sessions[i].uds_sock;
            pfd[uds_count].events = POLLIN;
            pfd[uds_count].revents = 0;
            type[uds_count] = res_sessions[i].type;
            uds_count++;
        }
    }

    if (uds_count == 0) {
        cm_sleep(CMS_SRV_RECV_SLEEP);
        return CT_SUCCESS;
    }
    // poll_ret返回值为0，表示cs_tcp_poll超时退出；< 0，表示cs_tcp_poll反错；> 0，表示监听到有事件发生
    // 当前cs_tcp_poll超时时间为1秒，连续2秒超时在cms_uds_srv_proc_pevents中主动recv，如果发现对端socket断连，调用cms_uds_srv_disconn
    while (retry_times < CMS_SRV_POOL_TMOUT_RETRY) {
        poll_ret = cs_tcp_poll(pfd, uds_count, CMS_SRV_POOL_TMOUT);
        if (poll_ret < 0) {
            CMS_LOG_ERR("cs tcp poll failed, ret %d", ret);
            return CT_ERROR;
        } else if (poll_ret == 0 && cms_uds_res_db_timeout(pfd, type, uds_count) == CT_TRUE) {
            retry_times++;
        } else {
            break;
        }
    }
    if (poll_ret == 0) {
        CMS_LOG_WAR("cs tcp poll timeout, ret %d, timeout: %d, retry times: %u",
            poll_ret, CMS_SRV_POOL_TMOUT, retry_times);
        is_timeout = CT_TRUE;
    }
    cms_uds_srv_proc_pevents(pfd, type, uds_count, res_sessions, CMS_MAX_UDS_SESSION_COUNT, is_timeout);
    return CT_SUCCESS;
}

void cms_uds_srv_recv_entry(thread_t* thread)
{
    status_t ret = CT_SUCCESS;

    CMS_LOG_INF("start uds recv entry thread");
    while (!thread->closed) {
        ret = cms_uds_srv_recv_proc();
        if (ret != CT_SUCCESS) {
            CMS_LOG_ERR("cms uds recv proc failed, ret %d", ret);
        }
    }
    CMS_LOG_INF("end uds recv entry thread");
}

status_t cms_uds_srv_send_proc(void)
{
    status_t ret = CT_SUCCESS;
    socket_t uds_sock = CMS_IO_INVALID_SOCKET;

    biqueue_node_t *node = cms_deque(&g_cms_inst->cli_send_que);
    if (node == NULL) {
        return CT_SUCCESS;
    }

    cms_packet_head_t* msg = (cms_packet_head_t*)cms_que_node_data(node);
    CMS_LOG_DEBUG_INF("get one msg to send, msg type %u, msg seq %llu, src msg seq %llu",
        msg->msg_type, msg->msg_seq, msg->src_msg_seq);
    ret = cms_stat_get_uds(msg->uds_sid, &uds_sock);
    if (ret != CT_SUCCESS || uds_sock == CMS_IO_INVALID_SOCKET) {
        CMS_LOG_ERR("get connected uds sock failed %d, sock %d, sessionId %llu, msg type %u, msg seq %llu, "
            "src msg seq %llu", ret, uds_sock, msg->uds_sid, msg->msg_type, msg->msg_seq, msg->src_msg_seq);
        cms_que_free_node(node);
        return CT_ERROR;
    }
    ret = cms_socket_send(uds_sock, msg, CMS_SRV_SEND_TMOUT);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("uds send failed, ret %d, sock %d, msg type %u, msg seq %llu, src msg seq %llu",
            ret, uds_sock, msg->msg_type, msg->msg_seq, msg->src_msg_seq);
        cms_que_free_node(node);
        return CT_ERROR;
    }
    CMS_LOG_DEBUG_INF("uds send msg succ, sock %d, msg type %u, msg seq %llu, src msg seq %llu",
        uds_sock, msg->msg_type, msg->msg_seq, msg->src_msg_seq);
    cms_que_free_node(node);
    return CT_SUCCESS;
}

void cms_uds_srv_send_entry(thread_t* thread)
{
    status_t ret = CT_SUCCESS;
    CMS_LOG_INF("start uds send entry thread");
    while (!thread->closed) {
        ret = cms_uds_srv_send_proc();
        if (ret != CT_SUCCESS) {
            CMS_LOG_ERR("cms uds send proc failed, ret %d", ret);
        }
    }
    CMS_LOG_INF("end uds send entry thread");
}

status_t cms_uds_srv_save_req(cms_packet_head_t* req)
{
    status_t ret = CT_SUCCESS;
    srv_request_info_t *req_info = cms_new_srv_req_info(req);
    if (req_info == NULL) {
        CT_LOG_RUN_ERR("cms new req info failed");
        return CT_ERROR;
    }

    ret = cm_oamap_insert(&g_srv_req_map, cm_hash_int64((uint64)req->msg_seq), &req->msg_seq, req_info);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("save req to hashamp failed, ret %d", ret);
        cms_free_srv_req_info(req_info);
        return ret;
    }
    CT_LOG_DEBUG_INF("save req to hashmap, msg type %u, msg req %llu", req->msg_type, req->msg_seq);
    return CT_SUCCESS;
}

status_t cms_uds_srv_send(cms_packet_head_t* msg, int32 timeout_ms)
{
    status_t ret = CT_SUCCESS;
    socket_t uds_sock = CMS_IO_INVALID_SOCKET;
    CT_LOG_DEBUG_INF("get one msg to send, msg type %u, msg seq %llu, src msg seq %llu",
        msg->msg_type, msg->msg_seq, msg->src_msg_seq);

    ret = cms_stat_get_uds(msg->uds_sid, &uds_sock);
    if (ret != CT_SUCCESS || uds_sock == CMS_IO_INVALID_SOCKET) {
        CMS_LOG_ERR("get connected uds sock failed, ret %d, sock %d, msg type %u, msg seq %llu, src msg seq %llu",
            ret, uds_sock, msg->msg_type, msg->msg_seq, msg->src_msg_seq);
        return CT_ERROR;
    }

    ret = cms_socket_send(uds_sock, msg, timeout_ms);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("uds send failed, ret %d, sock %d, msg type %u, msg seq %llu, src msg seq %llu",
            ret, uds_sock, msg->msg_type, msg->msg_seq, msg->src_msg_seq);
        return CT_ERROR;
    }
    CT_LOG_DEBUG_INF("uds send msg succ, sock %d, msg type %u, msg seq %llu, src msg seq %llu",
        uds_sock, msg->msg_type, msg->msg_seq, msg->src_msg_seq);
    return CT_SUCCESS;
}

status_t cms_uds_srv_wait_res(cms_packet_head_t* req, cms_packet_head_t **res, int32 timeout_ms)
{
    CT_LOG_DEBUG_INF("begin wait recv res, msg type %u, msg seq %llu", req->msg_type, req->msg_seq);
    srv_request_info_t *req_info = (srv_request_info_t*)cm_oamap_lookup(&g_srv_req_map,
        cm_hash_int64((uint64)req->msg_seq), &req->msg_seq);
    if (!req_info) {
        CT_LOG_RUN_ERR("look up req info from map failed");
        return CT_ERROR;
    }

    struct timespec ts;
    cm_get_timespec(&ts, timeout_ms);
    int32 ret = pthread_cond_timedwait(&req_info->recv_cond, &g_srv_req_map_lock, &ts);
    if (ret != 0) {
        CT_LOG_RUN_ERR("wait recv cond failed, ret %d, msg type %u, msg req %llu", ret, req->msg_type,
            req->msg_seq);
        return CT_ERROR;
    }
    *res = req_info->recv_msg;
    CT_LOG_DEBUG_INF("wait recv res succ, req msg type %u, res msg type %u, req msg seq %llu, res msg seq %llu, "
        "res msg src req %llu", req->msg_type, (*res)->msg_type, req->msg_seq, (*res)->msg_seq, (*res)->src_msg_seq);
    return CT_SUCCESS;
}

status_t cms_uds_srv_request(cms_packet_head_t *req, cms_packet_head_t *res, uint32 res_size, int32 timeout_ms)
{
    status_t ret = CT_SUCCESS;
    cm_thread_lock(&g_srv_req_map_lock);
    CT_LOG_DEBUG_INF("begin cms srv uds request, msg type %u, msg seq %llu", req->msg_type, req->msg_seq);
    ret = cms_uds_srv_save_req(req);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("save req to map failed, ret %d, msg type %u, msg seq %llu", ret, req->msg_type, req->msg_seq);
        cm_thread_unlock(&g_srv_req_map_lock);
        return ret;
    }

    ret = cms_uds_srv_send(req, timeout_ms);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cms srv send failed, msg type %u, msg seq %llu, timeout %d", req->msg_type, req->msg_seq,
            timeout_ms);
        cms_uds_srv_del_req(req);
        cm_thread_unlock(&g_srv_req_map_lock);
        return ret;
    }
    CT_LOG_DEBUG_INF("send uds req succ, msg type %u, msg seq %llu", req->msg_type, req->msg_seq);

    cms_packet_head_t* wait_res = NULL;
    ret = cms_uds_srv_wait_res(req, &wait_res, timeout_ms);
    if (ret != CT_SUCCESS || wait_res == NULL) {
        CT_LOG_RUN_ERR("wait msg ack failed, ret %d, msg type %u, msg seq %llu", ret, req->msg_type, req->msg_seq);
        cms_uds_srv_del_req(req);
        cm_thread_unlock(&g_srv_req_map_lock);
        return ret;
    }
    CT_LOG_DEBUG_INF("cms srv wait recv res succ, res msg type %u, res msg size %u, res msg seq %llu, src msg req %llu",
        wait_res->msg_type, wait_res->msg_size, wait_res->msg_seq, wait_res->src_msg_seq);

    errno_t err = memcpy_s(res, res_size, wait_res, wait_res->msg_size);
    if (err != EOK) {
        CT_LOG_RUN_ERR("memcpy_s failed, err %d, errno %d[%s], msg type %u, msg seq %llu",
            err, errno, strerror(errno), req->msg_type, req->msg_seq);
        cms_uds_srv_del_req(req);
        cm_thread_unlock(&g_srv_req_map_lock);
        return CT_ERROR;
    }
    CT_LOG_DEBUG_INF("cms srv uds request succ, req msg type %u, req msg seq %llu, res msg type %u, res msg size %u, "
        "res msg req %llu, src msg req %llu", req->msg_type, req->msg_seq, res->msg_type, res->msg_size,
        res->msg_seq, res->src_msg_seq);
    cms_uds_srv_del_req(req);
    cm_thread_unlock(&g_srv_req_map_lock);
    return CT_SUCCESS;
}

status_t cms_uds_srv_wakeup_sender(cms_packet_head_t *res)
{
    CT_LOG_DEBUG_INF("begin wakeup req sender, msg type %u, msg seq %llu, msg src seq %llu",
        res->msg_type, res->msg_seq, res->src_msg_seq);
    cm_thread_lock(&g_srv_req_map_lock);
    srv_request_info_t *req_info = (srv_request_info_t*)cm_oamap_lookup(&g_srv_req_map,
        cm_hash_int64((uint64)res->src_msg_seq), &res->src_msg_seq);
    if (!req_info) {
        CT_LOG_RUN_ERR("can not find req sender, msg type %u, msg seq %llu, msg src seq %llu",
            res->msg_type, res->msg_seq, res->src_msg_seq);
        cm_thread_unlock(&g_srv_req_map_lock);
        return CT_ERROR;
    }
    req_info->recv_msg = res;

    int32 ret = pthread_cond_signal(&req_info->recv_cond);
    if (ret != 0) {
        CT_LOG_RUN_ERR("pthread cond signal failed, ret %d, msg type %u, msg seq %llu, msg src seq %llu",
            ret, res->msg_type, res->msg_seq, res->src_msg_seq);
        req_info->recv_msg = NULL;
        cm_thread_unlock(&g_srv_req_map_lock);
        return CT_ERROR;
    }
    CT_LOG_DEBUG_INF("end wakeup req sender, msg type %u, msg seq %llu, msg src seq %llu",
        res->msg_type, res->msg_seq, res->src_msg_seq);
    cm_thread_unlock(&g_srv_req_map_lock);
    return CT_SUCCESS;
}