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
 * cms_uds_client.c
 *
 *
 * IDENTIFICATION
 * src/cms/interface/cms_uds_client.c
 *
 * -------------------------------------------------------------------------
 */
#include "cms_log_module.h"
#include "cms_uds_client.h"
#include "cms_defs.h"
#include "cm_thread.h"
#include "cm_ip.h"
#include "cs_tcp.h"
#include "cms_client.h"
#include "cms_comm.h"
#include "cms_socket.h"
#include "cm_malloc.h"
#include "cm_file.h"
#include "cms_msgque.h"
#include "cm_hashmap.h"
#include "cm_hash.h"
#include "cm_signal.h"
#include "cm_sync.h"

typedef struct st_cli_request_info {
    cms_packet_head_t* send_msg;  // caller to release this mem
    cms_packet_head_t* recv_msg;
    pthread_condattr_t recv_cond_attr;
    pthread_cond_t recv_cond;
} cli_request_info_t;

uint64                   g_cli_session_id = CMS_CLI_INVALID_SESS_ID;
socket_t                 g_cli_sock = CMS_IO_INVALID_SOCKET;
uint16                   g_cli_node_id = CMS_CLI_INVALID_NODE_ID;
char                     g_cli_cms_home[CMS_PATH_BUFFER_SIZE] = {0};
thread_lock_t            g_cli_send_lock;
thread_lock_t            g_cli_req_map_lock;
cm_oamap_t               g_cli_req_map;
atomic_t                 g_cli_msg_seq;
bool32                   g_cli_recv_timeout = CT_FALSE;

bool32 cms_uds_cli_seq_compare(void *key1, void *key2)
{
    CM_POINTER2(key1, key2);
    uint64 *seq1 = (uint64*)key1;
    uint64 *seq2 = (uint64*)key2;

    if (*seq1 == *seq2) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

cli_request_info_t* cms_new_req_info(cms_packet_head_t* req)
{
    cli_request_info_t *req_info = malloc(sizeof(cli_request_info_t));
    if (req_info == NULL) {
        CT_LOG_RUN_ERR("malloc failed, size %u, errno %d[%s]", (uint32)sizeof(cli_request_info_t),
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

void cms_free_req_info(cli_request_info_t* req_info)
{
    if (req_info == NULL) {
        return;
    }

    if (req_info->recv_msg != NULL) {
        CM_FREE_PTR(req_info->recv_msg);
        req_info->recv_msg = NULL;
    }
    (void)pthread_condattr_destroy(&req_info->recv_cond_attr);
    (void)pthread_cond_destroy(&req_info->recv_cond);
    CM_FREE_PTR(req_info);
}

status_t cms_uds_cli_save_req(cms_packet_head_t* req)
{
    status_t ret = CT_SUCCESS;
    cli_request_info_t *req_info = cms_new_req_info(req);
    if (req_info == NULL) {
        CT_LOG_RUN_ERR("cms new req info failed");
        return CT_ERROR;
    }

    ret = cm_oamap_insert(&g_cli_req_map, cm_hash_int64((uint64)req->msg_seq), &req->msg_seq, req_info);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("save req to hashamp failed, ret %d", ret);
        cms_free_req_info(req_info);
        return ret;
    }
    CT_LOG_DEBUG_INF("save req to hashmap, msg type %u, msg req %llu", req->msg_type, req->msg_seq);
    return CT_SUCCESS;
}

void cms_uds_cli_del_req(cms_packet_head_t* req)
{
    cli_request_info_t *req_info = (cli_request_info_t*)cm_oamap_lookup(&g_cli_req_map,
        cm_hash_int64((uint64)req->msg_seq), &req->msg_seq);
    if (req_info != NULL) {
        CT_LOG_DEBUG_INF("del req from hashmap, msg type %u, msg req %llu", req->msg_type,
            req->msg_seq);
        cms_free_req_info(req_info);
    }
    cm_oamap_remove(&g_cli_req_map, cm_hash_int64((uint64)req->msg_seq), &req->msg_seq);
}

status_t cms_uds_cli_wait_res(cms_packet_head_t* req, cms_packet_head_t **res, int32 timeout_ms)
{
    CT_LOG_DEBUG_INF("begin wait recv res, msg type %u, msg seq %llu", req->msg_type, req->msg_seq);
    cli_request_info_t *req_info = (cli_request_info_t*)cm_oamap_lookup(&g_cli_req_map,
        cm_hash_int64((uint64)req->msg_seq), &req->msg_seq);
    if (!req_info) {
        CT_LOG_RUN_ERR("look up req info from map failed");
        return CT_ERROR;
    }

    struct timespec ts;
    cm_get_timespec(&ts, timeout_ms);
    int32 ret = pthread_cond_timedwait(&req_info->recv_cond, &g_cli_req_map_lock, &ts);
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

status_t cms_uds_cli_wakeup_sender(cms_packet_head_t *res)
{
    CT_LOG_DEBUG_INF("begin wakeup req sender, msg type %u, msg seq %llu, msg src seq %llu",
        res->msg_type, res->msg_seq, res->src_msg_seq);
    cm_thread_lock(&g_cli_req_map_lock);
    cli_request_info_t *req_info = (cli_request_info_t*)cm_oamap_lookup(&g_cli_req_map,
        cm_hash_int64((uint64)res->src_msg_seq), &res->src_msg_seq);
    if (!req_info) {
        CT_LOG_RUN_ERR("can not find req sender, msg type %u, msg seq %llu, msg src seq %llu",
            res->msg_type, res->msg_seq, res->src_msg_seq);
        cm_thread_unlock(&g_cli_req_map_lock);
        return CT_ERROR;
    }
    req_info->recv_msg = res;

    int32 ret = pthread_cond_signal(&req_info->recv_cond);
    if (ret != 0) {
        CT_LOG_RUN_ERR("pthread cond signal failed, ret %d, msg type %u, msg seq %llu, msg src seq %llu",
            ret, res->msg_type, res->msg_seq, res->src_msg_seq);
        req_info->recv_msg = NULL;
        cm_thread_unlock(&g_cli_req_map_lock);
        return CT_ERROR;
    }
    CT_LOG_DEBUG_INF("end wakeup req sender, msg type %u, msg seq %llu, msg src seq %llu",
        res->msg_type, res->msg_seq, res->src_msg_seq);
    cm_thread_unlock(&g_cli_req_map_lock);
    return CT_SUCCESS;
}

status_t cms_uds_cli_send(cms_packet_head_t* msg, int32 timeout_ms)
{
    status_t ret = CT_SUCCESS;
    CT_LOG_DEBUG_INF("begin cli send msg, sock %d, msg type %u, msg seq %llu",
        g_cli_sock, msg->msg_type, msg->msg_seq);
    cm_thread_lock(&g_cli_send_lock);
    CT_LOG_DEBUG_INF("begin socket send msg");
    if (g_cli_sock == CMS_IO_INVALID_SOCKET || g_cli_session_id == CMS_CLI_INVALID_SESS_ID) {
        CT_LOG_RUN_ERR("socket send failed, uds conn is closed, sock %d, session id %llu, msg type %u, msg seq %llu, "
            "timeout %d", g_cli_sock, g_cli_session_id, msg->msg_type, msg->msg_seq, timeout_ms);
        cm_thread_unlock(&g_cli_send_lock);
        return CT_ERROR;
    }
    
    msg->uds_sid = g_cli_session_id;
    ret = cms_socket_send(g_cli_sock, msg, timeout_ms);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("socket send failed, sock %d, msg type %u, msg seq %llu, timeout %d",
            g_cli_sock, msg->msg_type, msg->msg_seq, timeout_ms);
        cm_thread_unlock(&g_cli_send_lock);
        return ret;
    }
    cm_thread_unlock(&g_cli_send_lock);
    CT_LOG_DEBUG_INF("cli send msg, sock %d, msg type %u, msg seq %llu", g_cli_sock, msg->msg_type, msg->msg_seq);
    return CT_SUCCESS;
}

status_t cms_uds_cli_recv(cms_packet_head_t* msg, int32 size, int32 timeout_ms)
{
    status_t ret = CT_SUCCESS;

    CT_LOG_DEBUG_INF("begin cms uds cli recv msg, sock %d", g_cli_sock);
    ret = cms_socket_recv(g_cli_sock, msg, size, timeout_ms, g_cli_recv_timeout);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cms socket recv failed, ret %d, sock %d", ret, g_cli_sock);
        return ret;
    }
    CT_LOG_DEBUG_INF("cms uds cli recv msg succ, sock %d", g_cli_sock);
    return CT_SUCCESS;
}

status_t cms_uds_cli_request(cms_packet_head_t *req, cms_packet_head_t *res, uint32 res_size, int32 timeout_ms)
{
    status_t ret = CT_SUCCESS;
    cm_thread_lock(&g_cli_req_map_lock);
    CT_LOG_DEBUG_INF("begin cms cli uds request, msg type %u, msg seq %llu", req->msg_type, req->msg_seq);
    ret = cms_uds_cli_save_req(req);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("save req to map failed, ret %d, msg type %u, msg seq %llu", ret, req->msg_type, req->msg_seq);
        cm_thread_unlock(&g_cli_req_map_lock);
        return ret;
    }
    
    ret = cms_uds_cli_send(req, timeout_ms);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cms cli send failed, sock %d, msg type %u, msg seq %llu, timeout %d",
            g_cli_sock, req->msg_type, req->msg_seq, timeout_ms);
        cms_uds_cli_del_req(req);
        cm_thread_unlock(&g_cli_req_map_lock);
        return ret;
    }
    CT_LOG_DEBUG_INF("send uds req succ, msg type %u, msg seq %llu", req->msg_type, req->msg_seq);
    
    cms_packet_head_t* wait_res = NULL;
    ret = cms_uds_cli_wait_res(req, &wait_res, timeout_ms);
    if (ret != CT_SUCCESS || wait_res == NULL) {
        CT_LOG_RUN_ERR("wait msg ack failed, ret %d, msg type %u, msg seq %llu", ret, req->msg_type, req->msg_seq);
        cms_uds_cli_del_req(req);
        cm_thread_unlock(&g_cli_req_map_lock);
        return ret;
    }
    CT_LOG_DEBUG_INF("cms cli wait recv res succ, res msg type %u, res msg size %u, res msg seq %llu, src msg req %llu",
        wait_res->msg_type, wait_res->msg_size, wait_res->msg_seq, wait_res->src_msg_seq);

    errno_t err = memcpy_s(res, res_size, wait_res, wait_res->msg_size);
    if (err != EOK) {
        CT_LOG_RUN_ERR("memcpy_s failed, err %d, errno %d[%s], msg type %u, msg seq %llu",
            err, errno, strerror(errno), req->msg_type, req->msg_seq);
        cms_uds_cli_del_req(req);
        cm_thread_unlock(&g_cli_req_map_lock);
        return CT_ERROR;
    }
    CT_LOG_DEBUG_INF("cms cli uds request succ, req msg type %u, req msg seq %llu, res msg type %u, res msg size %u, "
        "res msg req %llu, src msg req %llu", req->msg_type, req->msg_seq, res->msg_type, res->msg_size,
        res->msg_seq, res->src_msg_seq);
    cms_uds_cli_del_req(req);
    cm_thread_unlock(&g_cli_req_map_lock);
    return CT_SUCCESS;
}

status_t cms_uds_cli_request_sync(cms_packet_head_t *req, cms_packet_head_t *res, uint32 res_size, int32 timeout_ms)
{
    status_t ret = CT_SUCCESS;
    static char msg_buf[CMS_MAX_MSG_SIZE] = {0};
    errno_t err = EOK;
    cms_packet_head_t* msg = (cms_packet_head_t*)msg_buf;
    cm_thread_lock(&g_cli_req_map_lock);
    CT_LOG_DEBUG_INF("begin cms cli uds request sync, msg type %u, msg seq %llu, session id %llu", req->msg_type,
        req->msg_seq, req->uds_sid);

    ret = cms_uds_cli_send(req, timeout_ms);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cms cli send failed, sock %d, msg type %u, msg seq %llu, session id %llu, timeout %d",
            g_cli_sock, req->msg_type, req->msg_seq, req->uds_sid, timeout_ms);
        cm_thread_unlock(&g_cli_req_map_lock);
        return ret;
    }
    
    ret = cms_uds_cli_recv((cms_packet_head_t*)msg_buf, CMS_MAX_MSG_SIZE, timeout_ms);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cms cli recv msg failed, ret %d", ret);
        cm_thread_unlock(&g_cli_req_map_lock);
        return ret;
    }
    
    err = memcpy_s(res, res_size, msg, msg->msg_size);
    if (err != EOK) {
        CT_LOG_RUN_ERR("memcpy_s failed, err %d, errno %d[%s], msg type %u, msg size %u, msg seq %llu, "
            "msg src seq %llu, session id %llu", err, errno, strerror(errno), msg->msg_type,
            msg->msg_size, msg->msg_seq, msg->src_msg_seq, msg->uds_sid);
        CM_FREE_PTR(res);
        cm_thread_unlock(&g_cli_req_map_lock);
        return CT_ERROR;
    }

    CT_LOG_DEBUG_INF("cms cli uds request sync succ, req msg type %u, req msg seq %llu, res msg type %u, "
        "res msg size %u, res msg req %llu, src msg req %llu, session id %llu", req->msg_type, req->msg_seq,
        res->msg_type, res->msg_size, res->msg_seq, res->src_msg_seq, res->uds_sid);
    cm_thread_unlock(&g_cli_req_map_lock);
    return CT_SUCCESS;
}

status_t cms_uds_cli_init(uint16 node_id, const char* cms_home)
{
    status_t ret = CT_SUCCESS;
    errno_t err = EOK;
    
    g_cli_session_id = CMS_CLI_INVALID_SESS_ID;
    g_cli_sock = CMS_IO_INVALID_SOCKET;
    g_cli_node_id = node_id;
    err = memset_s(g_cli_cms_home, sizeof(g_cli_cms_home), 0, sizeof(g_cli_cms_home));
    MEMS_RETURN_IFERR(err);
    err = strcpy_s(g_cli_cms_home, sizeof(g_cli_cms_home), cms_home);
    MEMS_RETURN_IFERR(err);
    cm_atomic_set(&g_cli_msg_seq, cm_now());
    cm_init_thread_lock(&g_cli_send_lock);
    cm_init_thread_lock(&g_cli_req_map_lock);
    ret = cm_regist_signal(SIGPIPE, SIG_IGN);
    if (ret != CT_SUCCESS) {
        cm_destroy_thread_lock(&g_cli_send_lock);
        cm_destroy_thread_lock(&g_cli_req_map_lock);
        g_cli_node_id = CMS_CLI_INVALID_NODE_ID;
        CT_LOG_RUN_ERR("set singal ignore SIGPIE failed, ret %d", ret);
        return ret;
    }

    ret = cm_oamap_init(&g_cli_req_map, CMS_CLI_SEND_MSG_HASH_SIZE, cms_uds_cli_seq_compare);
    if (ret != CT_SUCCESS) {
        cm_destroy_thread_lock(&g_cli_send_lock);
        cm_destroy_thread_lock(&g_cli_req_map_lock);
        g_cli_node_id = CMS_CLI_INVALID_NODE_ID;
        CT_LOG_RUN_ERR("init cli send map failed, ret %d", ret);
        return ret;
    }

    return CT_SUCCESS;
}

void cms_uds_cli_destory_oamap(void)
{
    // TODO: free objs in req map
}

void cms_uds_cli_destory(void)
{
    if (g_cli_node_id != CMS_CLI_INVALID_NODE_ID) {
        g_cli_node_id = CMS_CLI_INVALID_NODE_ID;
        cms_uds_cli_destory_oamap();
        cms_uds_cli_sock_close();
        cm_destroy_thread_lock(&g_cli_send_lock);
        cm_destroy_thread_lock(&g_cli_req_map_lock);
    }
}

static status_t cms_uds_cli_exec_conn_req(socket_t uds_sock, cms_cli_msg_res_conn_t *res,
    cms_uds_cli_info_t* cms_uds_cli_info)
{
    status_t ret = CT_SUCCESS;
    cms_cli_msg_req_conn_t req;
    errno_t err = EOK;

    req.head.msg_size = sizeof(cms_cli_msg_req_conn_t);
    req.head.msg_type = CMS_CLI_MSG_REQ_CONNECT;
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cms_uds_cli_get_msg_seq();
    req.head.src_msg_seq = 0;
    err = strcpy_s(req.res_type, sizeof(req.res_type), cms_uds_cli_info->res_type);
    MEMS_RETURN_IFERR(err);
    req.inst_id = cms_uds_cli_info->inst_id;
    req.is_retry_conn = cms_uds_cli_info->is_retry_conn;
    req.cli_type = cms_uds_cli_info->cli_type;

    ret = cms_socket_send(uds_sock, &req.head, CMS_CLI_UDS_SEND_TMOUT);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("send msg to cms by uds failed, ret %d", ret);
        return CT_ERROR;
    }
    if (req.cli_type != CMS_CLI_TOOL) {
        CT_LOG_RUN_INF("send conn req succ, uds sock %d, req msg type %u, req msg seq %llu, is retry %d", uds_sock,
            req.head.msg_type, req.head.msg_seq, req.is_retry_conn);
    }

    ret = cms_socket_recv(uds_sock, &res->head, sizeof(cms_cli_msg_res_conn_t), CMS_CLI_RETRY_RECV_TMOUT,
        cms_uds_cli_info->is_retry_conn);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("recv msg from cms by uds failed, ret %d uds sock %d, req msg type %u, req msg seq %llu, "
            "is retry %d",
            ret, uds_sock, req.head.msg_type, req.head.msg_seq, req.is_retry_conn);
        return CT_ERROR;
    }
    if (req.cli_type != CMS_CLI_TOOL) {
        CT_LOG_RUN_INF("recv conn res succ, uds sock %d, req msg type %u, req msg seq %llu, res msg type %u, "
            "res msg seq %llu, res msg src req %llu, is retry %d",
            uds_sock, req.head.msg_type, req.head.msg_seq, res->head.msg_type, res->head.msg_seq, res->head.src_msg_seq,
            req.is_retry_conn);
    }
    return CT_SUCCESS;
}

status_t cms_uds_cli_check_server_online(void)
{
    char uds_server_path[CT_MAX_NAME_LEN] = {0};
    cms_cli_msg_res_conn_t res = {0};
    socket_t uds_sock = CMS_IO_INVALID_SOCKET;
    status_t ret = CT_SUCCESS;
    errno_t err = EOK;
    char CMS_TOOL_RES_TYPE[CMS_MAX_RES_TYPE_LEN] = "TOOL";
    cms_uds_cli_info_t cms_uds_cli_info = { CMS_TOOL_RES_TYPE, CMS_TOOL_INST_ID, CT_FALSE, CMS_CLI_TOOL };
    CT_LOG_RUN_INF("cms uds cli check server online begain.");
    err = sprintf_s(uds_server_path, sizeof(uds_server_path), "%s/" CMS_UDS_PATH "_%d", g_cli_cms_home,
        (int32)g_cli_node_id);
    PRTS_RETURN_IFERR(err);
 
    ret = cms_uds_connect(uds_server_path, &uds_sock);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cms connect to server by uds failed, uds path:%s", uds_server_path);
        return CT_ERROR;
    }
 
    ret = cms_uds_cli_exec_conn_req(uds_sock, &res, &cms_uds_cli_info);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cms cli conn request to server failed, ret %d, uds path %s, uds sock %d",
            ret, uds_server_path, uds_sock);
        cms_socket_close(uds_sock);
        return CT_ERROR;
    }
 
    cms_socket_close(uds_sock);
    CT_LOG_RUN_INF("cms uds cli check server online success.");
    return CT_SUCCESS;
}

status_t cms_uds_cli_get_server_master_id(uint64* inst_id)
{
    char uds_server_path[CT_MAX_NAME_LEN] = {0};
    cms_cli_msg_res_conn_t res = {0};
    socket_t uds_sock = CMS_IO_INVALID_SOCKET;
    status_t ret = CT_SUCCESS;
    errno_t err = EOK;
    char CMS_TOOL_RES_TYPE[CMS_MAX_RES_TYPE_LEN] = "TOOL";
    cms_uds_cli_info_t cms_uds_cli_info = { CMS_TOOL_RES_TYPE, CMS_TOOL_INST_ID, CT_FALSE, CMS_CLI_TOOL };
    CT_LOG_RUN_INF("cms_uds_cli_get_server_master_id begain.");
    err = sprintf_s(uds_server_path, sizeof(uds_server_path), "%s/" CMS_UDS_PATH "_%d", g_cli_cms_home,
        (int32)g_cli_node_id);
    PRTS_RETURN_IFERR(err);
 
    ret = cms_uds_connect(uds_server_path, &uds_sock);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cms connect to server by uds failed, uds path:%s", uds_server_path);
        return CT_ERROR;
    }
 
    ret = cms_uds_cli_exec_conn_req(uds_sock, &res, &cms_uds_cli_info);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cms cli conn request to server failed, ret %d, uds path %s, uds sock %d",
            ret, uds_server_path, uds_sock);
        cms_socket_close(uds_sock);
        return CT_ERROR;
    }
    *inst_id = res.master_id;
    cms_socket_close(uds_sock);
    CT_LOG_RUN_INF("cms_uds_cli_get_server_master_id success, id=%lld.", *inst_id);
    return CT_SUCCESS;
}

status_t cms_uds_cli_connect(cms_uds_cli_info_t* cms_uds_cli_info, res_init_info_t *res_info)
{
    char uds_server_path[CT_FILE_NAME_BUFFER_SIZE] = {0};
    cms_cli_msg_res_conn_t res = {0};
    socket_t uds_sock = CMS_IO_INVALID_SOCKET;
    status_t ret = CT_SUCCESS;
    errno_t err = EOK;

    err = sprintf_s(uds_server_path, sizeof(uds_server_path), "%s/" CMS_UDS_PATH "_%d", g_cli_cms_home,
        (int32)g_cli_node_id);
    PRTS_RETURN_IFERR(err);
    ret = cms_uds_connect(uds_server_path, &uds_sock);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("connect cms by uds failed, uds path:%s", uds_server_path);
        return CT_ERROR;
    }
    if (cms_uds_cli_info->cli_type != CMS_CLI_TOOL) {
        CT_LOG_RUN_INF("connect cms by uds succ, uds path %s, uds sock %d", uds_server_path, uds_sock);
    }

    ret = cms_uds_cli_exec_conn_req(uds_sock, &res, cms_uds_cli_info);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cms cli exec conn request failed, ret %d, uds path %s, uds sock %d",
            ret, uds_server_path, uds_sock);
        cms_socket_close(uds_sock);
        return ret;
    }

    if (res.head.msg_type != CMS_CLI_MSG_RES_CONNECT) {
        CT_LOG_RUN_ERR("get usd connect res failed, invalid message type %d", res.head.msg_type);
        cms_socket_close(uds_sock);
        return CT_ERROR;
    }
    g_cli_sock = uds_sock;
    g_cli_session_id = res.session_id;

    if (res_info != NULL) {
        err = memcpy_s(res_info, sizeof(res_init_info_t), &res.res_init_info, sizeof(res_init_info_t));
        if (err != EOK) {
            CT_LOG_RUN_ERR("memcpy_s failed, ret %d, errno %d[%s]", err, errno, strerror(errno));
            cms_uds_cli_sock_close();
            return CT_ERROR;
        }
    }
    if (cms_uds_cli_info->cli_type != CMS_CLI_TOOL) {
        CT_LOG_RUN_INF("cms uds connect succeed, uds sock %d, session id %llu, trigger version %llu.",
            g_cli_sock, g_cli_session_id, res.res_init_info.trigger_version);
    }
    return CT_SUCCESS;
}

void cms_uds_cli_disconnect(void)
{
    cms_uds_cli_sock_close();
}

socket_t cms_uds_cli_get_sock(void)
{
    return g_cli_sock;
}

socket_t cms_uds_cli_get_sid(void)
{
    return g_cli_session_id;
}

uint64 cms_uds_cli_get_msg_seq(void)
{
    return cm_atomic_inc(&g_cli_msg_seq);
}

void cms_uds_cli_sock_close(void)
{
    if (g_cli_sock != CMS_IO_INVALID_SOCKET) {
        cms_socket_close(g_cli_sock);
        g_cli_sock = CMS_IO_INVALID_SOCKET;
    }
    g_cli_session_id = CMS_CLI_INVALID_SESS_ID;
}

void cms_set_recv_timeout(void)
{
    g_cli_recv_timeout = CT_TRUE;
}
