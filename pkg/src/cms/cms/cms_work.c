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
 * cms_work.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_work.c
 *
 * -------------------------------------------------------------------------
 */

#include <stdio.h>
#include "cms_work.h"
#include "cm_thread.h"
#include "cms_msgque.h"
#include "cms_instance.h"
#include "cms_msg_def.h"
#include "cms_gcc.h"
#include "cms_param.h"
#include "cms_uds_server.h"
#include "cms_stat.h"
#include "cm_malloc.h"
#include "cms_comm.h"
#include "cms_node_fault.h"
#include "cms_iofence.h"
#include "cms_mes.h"
#include "cms_vote.h"
#include "cms_log.h"
#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#endif

#define PRINT_LEN 128
void cms_date2str(date_t date, char* str, uint32 max_size);

void cms_proc_msg_req_hb(cms_packet_head_t* msg)
{
    status_t ret = GS_SUCCESS;
    CMS_SYNC_POINT_GLOBAL_START(CMS_SEND_HEARTBEAT_MESSAGE_FAIL, &ret, GS_ERROR);
    CMS_SYNC_POINT_GLOBAL_END;
    if (ret != GS_SUCCESS) {
        return;
    }

    cms_msg_req_hb_t* req_hb = (cms_msg_req_hb_t*)msg;
    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_msg_res_hb_t));
    cms_msg_res_hb_t* res_hb = (cms_msg_res_hb_t*)cms_que_node_data(node);
    res_hb->head.src_node = req_hb->head.dest_node;
    res_hb->head.dest_node = req_hb->head.src_node;
    res_hb->head.msg_size = sizeof(cms_msg_res_hb_t);
    res_hb->head.msg_type = CMS_MSG_RES_HB;
    res_hb->head.msg_version = CMS_MSG_VERSION;
    res_hb->head.msg_seq = cm_now();
    res_hb->head.src_msg_seq = req_hb->head.msg_seq;
    res_hb->req_send_time = req_hb->req_send_time;
    res_hb->req_receive_time = req_hb->req_receive_time;

    cms_enque(&g_cms_inst->send_que, node);
}

void cms_proc_msg_res_hb(cms_packet_head_t *msg)
{
    cms_msg_res_hb_t *res_hb = (cms_msg_res_hb_t *)msg;

    uint16 src_node = g_cms_param->node_id;
    uint16 dest_node = res_hb->head.src_node;

    date_t time_diff =
        ((res_hb->req_receive_time - res_hb->req_send_time) + (res_hb->res_send_time - res_hb->res_receive_time)) / 2;

    if (time_diff > 0) {
        g_cms_inst->time_gap = MAX(g_cms_inst->time_gap, time_diff);
    }
    if (g_cms_inst->time_gap > CMS_DETECT_CLUSTER_TIME_GAP) {
        CMS_LOG_WAR("time_difference between node %d and node %d is %lld,cluster time gap:%lld", src_node, dest_node,
            time_diff, g_cms_inst->time_gap);
    } else {
        CMS_LOG_TIMER("time_difference between node %d and node %d is %lld,cluster time gap:%lld", src_node, dest_node,
            time_diff, g_cms_inst->time_gap);
    }
}

status_t cms_start_all_res(cms_packet_head_t* src_msg, char* err_info, uint32 err_info_len)
{
    status_t ret = GS_SUCCESS;
    uint32 node_count = cms_get_gcc_node_count();
    cms_msg_req_start_res_t* req = (cms_msg_req_start_res_t*)src_msg;

    CMS_LOG_INF("begin start all db res");
    req->scope = CMS_MSG_SCOPE_NODE;
    for (uint32 i = 0; i < node_count; i++) {
        if (cms_node_is_invalid(i)) {
            CMS_LOG_INF("skip invalid node, node id %u", i);
            continue;
        }
        
        req->target_node = i;
        ret = cms_start_res_node(src_msg, err_info, err_info_len);
        if (ret != GS_SUCCESS) {
            CMS_LOG_ERR("start one res faield, node id %u, res name %s", i, req->name);
            return ret;
        }
    }

    CMS_LOG_INF("start all db res succ");
    return GS_SUCCESS;
}

status_t cms_msg_start_res_send_to_other(uint16 node_id, cms_packet_head_t* head, uint32 timeout_ms)
{
    status_t ret = GS_SUCCESS;
    errno_t err = EOK;
    cms_msg_req_start_res_t* msg = (cms_msg_req_start_res_t*)head;
    cms_msg_req_start_res_t req = {0};
    cms_msg_res_start_res_t res = {0};
    req.head.msg_type = msg->head.msg_type;
    req.head.msg_version = msg->head.msg_version;
    req.head.src_node = g_cms_param->node_id;
    req.head.dest_node = node_id;
    req.head.msg_size = sizeof(cms_msg_req_start_res_t);
    req.head.msg_seq = msg->head.msg_seq;
    req.head.src_msg_seq = msg->head.src_msg_seq;
    req.scope = msg->scope;
    req.target_node = msg->target_node;
    req.timeout = timeout_ms;
    err = strcpy_s(req.name, CMS_NAME_BUFFER_SIZE, msg->name);
    if (err != EOK) {
        CMS_LOG_ERR("strcpy_s failed, err %d, errno %d[%s]", err, errno, strerror(errno));
        return GS_ERROR;
    }

    err = memset_sp(&res, sizeof(cms_msg_res_start_res_t), 0, sizeof(cms_msg_res_start_res_t));
    if (err != EOK) {
        CMS_LOG_ERR("memset_s failed, err %d, errno %d[%s]", err, errno, strerror(errno));
        return GS_ERROR;
    }

    ret = cms_mes_request(&req.head, &res.head, timeout_ms);
    if (ret != GS_SUCCESS || res.result != 0) {
        CMS_LOG_ERR("send start msg form node %u to node %u failed", req.head.src_node, req.head.dest_node);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

void cms_reply_msg_res_start_res_to_server(cms_packet_head_t* req_msg, status_t ret, const char* info)
{
    if (strlen(info) > CMS_MAX_INFO_LEN) {
        CMS_LOG_ERR("start resource result info is too long.");
        return;
    }

    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_msg_res_start_res_t));
    cms_msg_res_start_res_t *res = (cms_msg_res_start_res_t*)cms_que_node_data(node);
    res->head.dest_node = req_msg->src_node;
    res->head.src_node = req_msg->dest_node;
    res->head.msg_size = sizeof(cms_msg_res_start_res_t);
    res->head.msg_type = CMS_MSG_RES_START_RES;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.msg_seq = cm_now();
    res->head.src_msg_seq = req_msg->msg_seq;
    if (req_msg->need_ack == GS_TRUE) {
        res->head.is_ack = GS_TRUE;
        res->head.sid = req_msg->sid;
        res->head.rsn = req_msg->rsn;
    } else {
        res->head.is_ack = GS_FALSE;
    }
    res->result = ret;
    errno_t err = strcpy_s(res->info, CMS_INFO_BUFFER_SIZE, info);
    if (err != EOK) {
        CMS_LOG_ERR("cms strcpy failed, CMS_INFO_BUFFER_SIZE %u, err %d, errno %d[%s]", CMS_INFO_BUFFER_SIZE,
            err, errno, strerror(errno));
        cms_que_free_node(node);
        return;
    }

    cms_enque(&g_cms_inst->send_que, node);
}

status_t cms_start_res_cluster(cms_packet_head_t* msg, char* err_info, uint32 err_info_len)
{
    status_t ret = GS_SUCCESS;
    bool32 is_master = GS_FALSE;
    uint16 master_node = 0;
    errno_t err = EOK;
    cms_msg_req_start_res_t* req = (cms_msg_req_start_res_t*)msg;

    CMS_RETRY_IF_ERR(cms_is_master(&is_master));
    if (is_master) {
        ret = cms_start_all_res(msg, err_info, err_info_len);
        if (ret != GS_SUCCESS) {
            return ret;
        }
    } else {
        ret = cms_get_master_node(&master_node);
        if (ret != GS_SUCCESS || master_node >= CMS_MAX_NODE_COUNT) {
            err = strcpy_s(err_info, err_info_len, "cms get master node failed");
            cms_securec_check(err);
            return GS_ERROR;
        }
        // forwarding start cluster res message to master
        ret = cms_msg_start_res_send_to_other(master_node, msg, req->timeout);
        if (ret != GS_SUCCESS) {
            err = strcpy_s(err_info, err_info_len, "message forwarding failed");
            cms_securec_check(err);
            return ret;
        }
    }
    return GS_SUCCESS;
}

status_t cms_start_res_local(uint32 res_id, uint32 timeout, char* err_info)
{
    status_t ret = GS_SUCCESS;
    errno_t err = EOK;
    ret = cms_res_start(res_id, timeout);
    if (ret != GS_SUCCESS) {
        err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "start resource failed");
        cms_securec_check(err);
        return ret;
    }
    return GS_SUCCESS;
}

status_t cms_start_res_remote(cms_packet_head_t* msg, uint32 res_id, char* err_info)
{
    status_t ret = GS_SUCCESS;
    errno_t err = EOK;
    bool32 is_master = GS_FALSE;
    uint16 master_node = 0;
    cms_msg_req_start_res_t* req = (cms_msg_req_start_res_t*)msg;

    CMS_RETRY_IF_ERR(cms_is_master(&is_master));
    if (is_master) {
        ret = cms_msg_start_res_send_to_other(req->target_node, msg, req->timeout);
        if (ret != GS_SUCCESS) {
            err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "message forwarding to target node failed");
            cms_securec_check(err);
            return ret;
        }
    } else {
        ret = cms_get_master_node(&master_node);
        if (ret != GS_SUCCESS || master_node >= CMS_MAX_NODE_COUNT) {
            err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "get master info failed");
            cms_securec_check(err);
            return GS_ERROR;
        }
        ret = cms_msg_start_res_send_to_other(master_node, msg, req->timeout);
        if (ret != GS_SUCCESS) {
            err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "message forwarding to master node failed");
            cms_securec_check(err);
            return ret;
        }
    }
    return GS_SUCCESS;
}

status_t cms_start_res_node(cms_packet_head_t* msg, char* err_info, uint32 err_info_len)
{
    status_t ret = GS_SUCCESS;
    errno_t err = EOK;
    uint32 res_id = -1;
    cms_msg_req_start_res_t* req = (cms_msg_req_start_res_t*)msg;

    ret = cms_get_res_id_by_name(req->name, &res_id);
    if (ret != GS_SUCCESS) {
        err = strcpy_s(err_info, err_info_len, "resource is not found");
        cms_securec_check(err);
        return ret;
    }
    if (req->target_node != GS_MAX_UINT16 && g_cms_param->node_id != req->target_node) {
        ret = cms_start_res_remote(msg, res_id, err_info);
        if (ret != GS_SUCCESS) {
            return ret;
        }
    } else {
        ret = cms_start_res_local(res_id, req->timeout, err_info);
        if (ret != GS_SUCCESS) {
            return ret;
        }
    }
    return GS_SUCCESS;
}

void cms_proc_msg_req_start_res(cms_packet_head_t* msg)
{
    status_t ret = GS_SUCCESS;
    char err_info[CMS_INFO_BUFFER_SIZE] = {0};
    cms_msg_req_start_res_t* req = (cms_msg_req_start_res_t*)msg;

    if (req->scope == CMS_MSG_SCOPE_CLUSTER) {
        ret = cms_start_res_cluster(msg, err_info, CMS_INFO_BUFFER_SIZE);
    } else {
        ret = cms_start_res_node(msg, err_info, CMS_INFO_BUFFER_SIZE);
    }
    CMS_SYNC_POINT_GLOBAL_START(CMS_SET_START_RES_FAILED_ABORT, NULL, 0);
    CMS_SYNC_POINT_GLOBAL_END;
    cms_reply_msg_res_start_res_to_server(msg, ret, err_info);
}

status_t cms_stop_all_res(cms_packet_head_t* msg, char* err_info, uint32 err_info_len)
{
    status_t ret = GS_SUCCESS;
    uint32 node_count = cms_get_gcc_node_count();
    cms_msg_req_stop_res_t* req = (cms_msg_req_stop_res_t*)msg;

    CMS_LOG_INF("begin stop all db res");
    req->scope = CMS_MSG_SCOPE_NODE;
    for (uint32 i = 0; i < node_count; i++) {
        if (cms_node_is_invalid(i)) {
            CMS_LOG_INF("skip invalid node, node id %u", i);
            continue;
        }
        
        req->target_node = i;
        ret = cms_stop_res_node(msg, err_info, err_info_len);
        if (ret != GS_SUCCESS) {
            CMS_LOG_ERR("stop one res faield, node id %u, res name %s", i, req->name);
            return ret;
        }
    }

    CMS_LOG_INF("stop all db res succ");
    return GS_SUCCESS;
}

status_t cms_msg_stop_res_send_to_other(uint16 node_id, cms_packet_head_t* head, uint32 timeout_ms)
{
    status_t ret = GS_SUCCESS;
    errno_t err = EOK;
    cms_msg_req_stop_res_t* msg = (cms_msg_req_stop_res_t*)head;
    cms_msg_req_stop_res_t req = {0};
    cms_msg_res_stop_res_t res = {0};
    req.head.msg_type = msg->head.msg_type;
    req.head.msg_version = msg->head.msg_version;
    req.head.src_node = g_cms_param->node_id;
    req.head.dest_node = node_id;
    req.head.msg_size = sizeof(cms_msg_req_stop_res_t);
    req.head.msg_seq = msg->head.msg_seq;
    req.head.src_msg_seq = msg->head.src_msg_seq;
    req.scope = msg->scope;
    req.target_node = msg->target_node;
    err = strcpy_s(req.name, CMS_NAME_BUFFER_SIZE, msg->name);
    if (err != EOK) {
        CMS_LOG_ERR("strcpy_s failed, err %d, errno %d[%s]", err, errno, strerror(errno));
        return GS_ERROR;
    }

    err = memset_sp(&res, sizeof(cms_msg_res_stop_res_t), 0, sizeof(cms_msg_res_stop_res_t));
    if (err != EOK) {
        CMS_LOG_ERR("memset_s failed, err %d, errno %d[%s]", err, errno, strerror(errno));
        return GS_ERROR;
    }

    ret = cms_mes_request(&req.head, &res.head, timeout_ms);
    if (ret != GS_SUCCESS || res.result != 0) {
        CMS_LOG_ERR("mes request failed, ret %d, result %u, src node %u, dest node %u", ret, res.result,
            req.head.src_node, req.head.dest_node);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

void cms_reply_msg_res_stop_res_to_server(cms_packet_head_t* req_msg, status_t ret, const char* info)
{
    if (strlen(info) > CMS_MAX_INFO_LEN) {
        CMS_LOG_ERR("stop resource result info is too long.");
        return;
    }

    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_msg_res_stop_res_t));
    cms_msg_res_stop_res_t *res = (cms_msg_res_stop_res_t*)cms_que_node_data(node);
    res->head.dest_node = req_msg->src_node;
    res->head.src_node = req_msg->dest_node;
    res->head.msg_size = sizeof(cms_msg_res_stop_res_t);
    res->head.msg_type = CMS_MSG_RES_STOP_RES;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.msg_seq = cm_now();
    res->head.src_msg_seq = req_msg->msg_seq;
    if (req_msg->need_ack == GS_TRUE) {
        res->head.is_ack = GS_TRUE;
        res->head.sid = req_msg->sid;
        res->head.rsn = req_msg->rsn;
    } else {
        res->head.is_ack = GS_FALSE;
    }
    res->result = ret;
    errno_t err = strcpy_s(res->info, CMS_INFO_BUFFER_SIZE, info);
    if (err != EOK) {
        CMS_LOG_ERR("cms strcpy failed, CMS_INFO_BUFFER_SIZE %u, err %d, errno %d[%s]", CMS_INFO_BUFFER_SIZE,
            err, errno, strerror(errno));
        cms_que_free_node(node);
        return;
    }

    cms_enque(&g_cms_inst->send_que, node);
}

status_t cms_stop_res_cluster(cms_packet_head_t* msg, char* err_info, uint32 err_info_len)
{
    status_t ret = GS_SUCCESS;
    bool32 is_master = GS_FALSE;
    uint16 master_node = 0;
    errno_t err = EOK;

    CMS_RETRY_IF_ERR(cms_is_master(&is_master));
    if (is_master) {
        ret = cms_stop_all_res(msg, err_info, err_info_len);
        if (ret != GS_SUCCESS) {
            return ret;
        }
    } else {
        ret = cms_get_master_node(&master_node);
        if (ret != GS_SUCCESS || master_node >= CMS_MAX_NODE_COUNT) {
            err = strcpy_s(err_info, err_info_len, "cms get master node failed");
            cms_securec_check(err);
            return GS_ERROR;
        }
        uint32 node_count = cms_get_gcc_node_count();
        // forwarding stop cluster res message to master
        ret = cms_msg_stop_res_send_to_other(master_node, msg, node_count * CMS_CMD_RECV_TMOUT_MS);
        if (ret != GS_SUCCESS) {
            err = strcpy_s(err_info, err_info_len, "message forwarding failed");
            cms_securec_check(err);
            return ret;
        }
    }
    return GS_SUCCESS;
}

status_t cms_stop_res_local(uint32 res_id, char* err_info)
{
    status_t ret = GS_SUCCESS;
    errno_t err = EOK;
    bool32 res_running = GS_TRUE;
    ret = cms_res_check(res_id, &res_running);
    if (ret != GS_SUCCESS) {
        err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "check resource failed");
        cms_securec_check(err);
        return GS_ERROR;
    }
    if (res_running != GS_TRUE) {
        err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "res count is 0 or greater than 1");
        cms_securec_check(err);
        return GS_ERROR;
    }
    ret = cms_res_stop(res_id, GS_TRUE);
    if (ret != GS_SUCCESS) {
        if (ret == GS_TIMEDOUT) {
            err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "stop resource timeout");
        } else {
            err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "stop resource failed");
        }
        cms_securec_check(err);
        return ret;
    }
    return GS_SUCCESS;
}

status_t cms_stop_res_remote(cms_packet_head_t* msg, uint32 res_id, char* err_info)
{
    status_t ret = GS_SUCCESS;
    bool32 is_master = GS_FALSE;
    uint16 master_node = 0;
    errno_t err = EOK;
    cms_msg_req_stop_res_t* req = (cms_msg_req_stop_res_t*)msg;

    CMS_RETRY_IF_ERR(cms_is_master(&is_master));
    if (is_master) {
        ret = cms_msg_stop_res_send_to_other(req->target_node, msg, CMS_CMD_RECV_TMOUT_MS);
        if (ret != GS_SUCCESS) {
            err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "message forwarding to target node failed");
            cms_securec_check(err);
            return ret;
        }
    } else {
        ret = cms_get_master_node(&master_node);
        if (ret != GS_SUCCESS || master_node >= CMS_MAX_NODE_COUNT) {
            err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "get master info failed");
            cms_securec_check(err);
            return GS_ERROR;
        }
        ret = cms_msg_stop_res_send_to_other(master_node, msg, CMS_CMD_RECV_TMOUT_MS);
        if (ret != GS_SUCCESS) {
            err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "message forwarding to master node failed");
            cms_securec_check(err);
            return ret;
        }
    }
    return GS_SUCCESS;
}

status_t cms_stop_res_node(cms_packet_head_t* msg, char* err_info, uint32 err_info_len)
{
    status_t ret = GS_SUCCESS;
    uint32 res_id = -1;
    errno_t err = EOK;
    cms_msg_req_stop_res_t* req = (cms_msg_req_stop_res_t*)msg;
    
    ret = cms_get_res_id_by_name(req->name, &res_id);
    if (ret != GS_SUCCESS) {
        err = strcpy_s(err_info, err_info_len, "resource is not found");
        cms_securec_check(err);
        return ret;
    }
    if (req->target_node != GS_MAX_UINT16 && g_cms_param->node_id != req->target_node) {
        ret = cms_stop_res_remote(msg, res_id, err_info);
        if (ret != GS_SUCCESS) {
            return ret;
        }
    } else {
        ret = cms_stop_res_local(res_id, err_info);
        if (ret != GS_SUCCESS) {
            return ret;
        }
    }
    return GS_SUCCESS;
}

void cms_proc_msg_req_stop_res(cms_packet_head_t* msg)
{
    status_t ret = GS_SUCCESS;
    char err_info[CMS_INFO_BUFFER_SIZE] = {0};
    cms_msg_req_stop_res_t* req = (cms_msg_req_stop_res_t*)msg;

    if (req->scope == CMS_MSG_SCOPE_CLUSTER) {
        ret = cms_stop_res_cluster(msg, err_info, CMS_INFO_BUFFER_SIZE);
    } else {
        ret = cms_stop_res_node(msg, err_info, CMS_INFO_BUFFER_SIZE);
    }
    cms_reply_msg_res_stop_res_to_server(msg, ret, err_info);
}

void cms_get_error_info(char *info)
{
    int32 err_code = 0;
    const char *err_msg = NULL;
    cm_get_error(&err_code, &err_msg, NULL);
    errno_t err = strcpy_s(info, CMS_INFO_BUFFER_SIZE, err_msg);
    MEMS_RETVOID_IFERR(err);
    cm_reset_error();
}

status_t cms_exec_add_res(cms_packet_head_t* msg, char* info, uint32 info_len)
{
    status_t ret = GS_SUCCESS;
    cms_msg_req_add_res_t* req = (cms_msg_req_add_res_t*)msg;
    char* name = req->name;
    char* type = req->type;
    char* group = req->group;
    char* attrs = req->attrs;

    ret = cms_add_res(name, type, group, attrs);
    if (ret != GS_SUCCESS) {
        cms_get_error_info(info);
        CMS_LOG_ERR("cms add res failed, ret %d, name %s, err info %s", ret, name, info);
    }
    return ret;
}

status_t cms_exec_edit_res(cms_packet_head_t *msg, char *info, uint32 info_len)
{
    cms_msg_req_edit_res_t *req = (cms_msg_req_edit_res_t *)msg;
    char *name = req->name;
    char *attrs = req->attrs;

    status_t ret = cms_edit_res(name, attrs);
    if (ret != GS_SUCCESS) {
        cms_get_error_info(info);
        CMS_LOG_ERR("cms edit res failed, ret %d, name %s, err info %s", ret, name, info);
    }

    return ret;
}

status_t cms_exec_del_res(cms_packet_head_t* msg, char* info, uint32 info_len)
{
    cms_msg_req_del_res_t* req = (cms_msg_req_del_res_t*)msg;
    char* name = req->name;

    status_t ret = cms_del_res(name);
    if (ret != GS_SUCCESS) {
        cms_get_error_info(info);
        CMS_LOG_ERR("cms del res failed, ret %d, name %s, err info %s", ret, name, info);
    }

    return ret;
}

status_t cms_exec_add_grp(cms_packet_head_t* msg, char* info, uint32 info_len)
{
    cms_msg_req_add_grp_t* req = (cms_msg_req_add_grp_t*)msg;
    char *group = req->group;
    status_t ret;

    ret = cms_add_resgrp(group);
    if (ret != GS_SUCCESS) {
        cms_get_error_info(info);
        CMS_LOG_ERR("cms add resgrp failed, ret %d, group %s, err info %s", ret, group, info);
    }

    return ret;
}

status_t cms_exec_del_grp(cms_packet_head_t* msg, char* info, uint32 info_len)
{
    cms_msg_req_del_grp_t* req = (cms_msg_req_del_grp_t*)msg;
    char *group = req->group;
    status_t ret;
    if (req->force != GS_TRUE) {
        ret = cms_del_resgrp(group);
    } else {
        ret = cms_del_resgrp_force(group);
    }
    if (ret != GS_SUCCESS) {
        cms_get_error_info(info);
        CMS_LOG_ERR("cms del resgrp failed, ret %d, group %s, err info %s", ret, group, info);
    }
    return ret;
}

status_t cms_exec_add_node(cms_packet_head_t* msg, char* info, uint32 info_len)
{
    cms_msg_req_add_node_t* req = (cms_msg_req_add_node_t*)msg;
    uint32 node_id = req->node_id;
    char *name = req->name;
    char *ip = req->ip;
    uint32 port = req->port;
    status_t ret;
    if (node_id == -1) {
        ret = cms_add_node(name, ip, port);
    } else {
        ret = cms_insert_node(node_id, name, ip, port);
    }
    if (ret != GS_SUCCESS) {
        cms_get_error_info(info);
        CMS_LOG_ERR("cms add node failed, ret %d, node id  %u, name %s, err info %s", ret, req->node_id,
            req->name, info);
    }
    return ret;
}

status_t cms_exec_del_node(cms_packet_head_t* msg, char* info, uint32 info_len)
{
    cms_msg_req_del_node_t* req = (cms_msg_req_del_node_t*)msg;

    status_t ret = cms_del_node(req->node_id);
    if (ret != GS_SUCCESS) {
        cms_get_error_info(info);
        CMS_LOG_ERR("cms del node failed, ret %d, node id  %u, err info %s", ret, req->node_id, info);
    }
    return ret;
}

void cms_broadcast_update_local_gcc(void)
{
    cms_msg_req_update_local_gcc_t req = {0};
    req.head.dest_node = -1;
    req.head.src_node = g_cms_param->node_id;
    req.head.msg_type = CMS_MSG_REQ_UPDATE_LOCAL_GCC;
    req.head.msg_size = sizeof(cms_msg_req_update_local_gcc_t);
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cm_now();
    req.head.src_msg_seq = 0;
    cms_broadcast_srv_msg((cms_packet_head_t*)&req);
    cms_load_gcc();
    cms_update_local_gcc();
}

status_t cms_init_add_node_req_to_master(cms_tool_msg_req_add_node_t* tool_req, cms_msg_req_add_node_t* req,
    char* err_info)
{
    errno_t err = EOK;
    req->head.msg_type = CMS_MSG_REQ_ADD_NODE;
    req->head.msg_size = sizeof(cms_msg_req_add_node_t);
    req->head.msg_version = CMS_MSG_VERSION;
    req->head.msg_seq = cm_now();
    req->head.src_msg_seq = 0;
    req->node_id = tool_req->node_id;
    req->port = tool_req->port;
    err = strcpy_sp(req->name, CMS_NAME_BUFFER_SIZE, tool_req->name);
    if (err != EOK) {
        CMS_LOG_ERR("strcpy_sp failed, CMS_NAME_BUFFER_SIZE %u, errno %d[%s]", CMS_NAME_BUFFER_SIZE,
            cm_get_os_error(), strerror(errno));
        err = strcpy_sp(err_info, CMS_MAX_INFO_LEN, "strcpy name failed");
        cms_securec_check(err);
        return GS_ERROR;
    }
    err = strcpy_sp(req->ip, CMS_IP_BUFFER_SIZE, tool_req->ip);
    if (err != EOK) {
        CMS_LOG_ERR("strcpy_sp failed, CMS_IP_BUFFER_SIZE %u, errno %d[%s]", CMS_IP_BUFFER_SIZE,
            cm_get_os_error(), strerror(errno));
        err = strcpy_sp(err_info, CMS_MAX_INFO_LEN, "strcpy ip failed");
        cms_securec_check(err);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t cms_add_node_on_master(cms_packet_head_t* msg, char* err_info)
{
    status_t ret = GS_SUCCESS;
    uint16 master_node = -1;
    errno_t err = EOK;
    cms_msg_req_add_node_t req = {0};
    cms_msg_res_add_node_t res = {0};
    cms_tool_msg_req_add_node_t* tool_req = (cms_tool_msg_req_add_node_t*)msg;
    
    CMS_LOG_INF("begin add node on master, msg type %u, msg req %llu, node id %u, name %s", msg->msg_type,
        msg->msg_seq, tool_req->node_id, tool_req->name);
    ret = cms_get_master_node(&master_node);
    if (ret != GS_SUCCESS || master_node >= CMS_MAX_NODE_COUNT) {
        CMS_LOG_ERR("get master node failed, ret %d, master node %u", ret, master_node);
        err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "get master info failed");
        cms_securec_check(err);
        return ret;
    }
    
    if (cms_init_add_node_req_to_master(tool_req, &req, err_info) != GS_SUCCESS) {
        CMS_LOG_ERR("cms init add node req to master failed");
        return GS_ERROR;
    }

    CMS_LOG_INF("send srv msg add node to master, srv msg type %u, srv msg req %llu", req.head.msg_type,
        req.head.msg_seq);
    ret = cms_mes_send_cmd_to_other((cms_packet_head_t*)&req, (cms_packet_head_t*)&res, master_node);
    if (ret != GS_SUCCESS) {
        CMS_LOG_ERR("send srv msg add node to master failed, ret %d, msg type %u, msg req %llu, srv msg type %u,"
            " srv msg seq %llu", ret, msg->msg_type, msg->msg_seq, req.head.msg_type, req.head.msg_seq);
        err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "send message to master failed");
        cms_securec_check(err);
        return ret;
    }
    if (ret == GS_SUCCESS && res.result != GS_SUCCESS) {
        CMS_LOG_ERR("add node on master node failed, result %d, msg type %u, msg req %llu, srv msg type %u,"
            " srv msg seq %llu, srv res msg type %u, srv res msg seq %llu", res.result, msg->msg_type, msg->msg_seq,
            req.head.msg_type, req.head.msg_seq, res.head.msg_type, res.head.msg_seq);
        err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, res.info);
        cms_securec_check(err);
        return GS_ERROR;
    }
    CMS_LOG_INF("add node on master succ, msg type %u, msg req %llu, srv msg type %u, srv msg seq %llu, "
        "srv res msg type %u, srv res msg seq %llu, node id %u, name %s", msg->msg_type, msg->msg_seq,
        req.head.msg_type, req.head.msg_seq, res.head.msg_type, res.head.msg_seq, tool_req->node_id,
        tool_req->name);
    return GS_SUCCESS;
}

status_t cms_sync_gcc_backup(char* err_info)
{
    status_t ret = cms_backup_gcc_auto();
    if (ret != GS_SUCCESS) {
        errno_t err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "cms automatically backup gcc failed");
        if (err != EOK) {
            CMS_LOG_ERR("cms strcpy failed, CMS_INFO_BUFFER_SIZE %u, errno %d[%s]", CMS_INFO_BUFFER_SIZE,
                cm_get_os_error(), strerror(errno));
        }
    }
    return ret;
}

void cms_proc_uds_msg_req_add_node(cms_packet_head_t* msg)
{
    status_t ret = GS_SUCCESS;
    bool32 is_master = GS_FALSE;
    cms_tool_msg_req_add_node_t* req = (cms_tool_msg_req_add_node_t*)msg;
    CMS_LOG_INF("begin proc uds msg add node, msg type %u, msg req %llu, node id %u, name %s", msg->msg_type,
        msg->msg_seq, req->node_id, req->name);
    CMS_RETRY_IF_ERR(cms_is_master(&is_master));
    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_tool_msg_res_add_node_t));
    cms_tool_msg_res_add_node_t* res = (cms_tool_msg_res_add_node_t*)cms_que_node_data(node);
    res->head.dest_node = msg->src_node;
    res->head.src_node = msg->dest_node;
    res->head.msg_size = sizeof(cms_tool_msg_res_add_node_t);
    res->head.msg_type = CMS_TOOL_MSG_RES_ADD_NODE;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.src_msg_seq = msg->msg_seq;
    res->head.msg_seq = cm_now();
    res->head.uds_sid = msg->uds_sid;
    if (is_master) {
        ret = cms_exec_add_node(msg, res->info, CMS_INFO_BUFFER_SIZE);
    } else {
        ret = cms_add_node_on_master(msg, res->info);
    }
    if (ret == GS_SUCCESS) {
        ret = cms_sync_gcc_backup(res->info);
    }
    res->result = ret;
    cms_enque(&g_cms_inst->cli_send_que, node);
    cms_notify_load_gcc();
    CMS_LOG_INF("end proc uds msg add node, ret %d, is master %d, msg type %u, msg req %llu, node id %u, name %s",
        ret, is_master, msg->msg_type, msg->msg_seq, req->node_id, req->name);
}

status_t cms_del_node_on_master(cms_packet_head_t* msg, char* err_info)
{
    status_t ret = GS_SUCCESS;
    errno_t err = EOK;
    uint16 master_node = -1;
    cms_msg_req_del_node_t req = {0};
    cms_msg_res_del_node_t res = {0};
    cms_tool_msg_req_del_node_t* tool_req = (cms_tool_msg_req_del_node_t*)msg;
    
    CMS_LOG_INF("begin del node on master, msg type %u, msg req %llu, node id %u", msg->msg_type, msg->msg_seq,
        tool_req->node_id);
    ret = cms_get_master_node(&master_node);
    if (ret != GS_SUCCESS || master_node >= CMS_MAX_NODE_COUNT) {
        CMS_LOG_ERR("get master node failed, ret %d, master node %u", ret, master_node);
        err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "get master info failed");
        cms_securec_check(err);
        return ret;
    }
    req.head.msg_type = CMS_MSG_REQ_DEL_NODE;
    req.head.msg_size = sizeof(cms_msg_req_del_node_t);
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cm_now();
    req.head.src_msg_seq = 0;
    req.node_id = tool_req->node_id;

    CMS_LOG_INF("send srv msg del node to master, srv msg type %u, srv msg req %llu", req.head.msg_type,
        req.head.msg_seq);
    ret = cms_mes_send_cmd_to_other((cms_packet_head_t*)&req, (cms_packet_head_t*)&res, master_node);
    if (ret != GS_SUCCESS) {
        CMS_LOG_ERR("send srv msg del node to master failed, ret %d, msg type %u, msg req %llu, srv msg type %u,"
            " srv msg seq %llu", ret, msg->msg_type, msg->msg_seq, req.head.msg_type, req.head.msg_seq);
        err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "send message to master failed");
        cms_securec_check(err);
        return ret;
    }
    if (ret == GS_SUCCESS && res.result != GS_SUCCESS) {
        CMS_LOG_ERR("del node on master node failed, result %d, msg type %u, msg req %llu, srv msg type %u,"
            " srv msg seq %llu, srv res msg type %u, srv res msg seq %llu", res.result, msg->msg_type, msg->msg_seq,
            req.head.msg_type, req.head.msg_seq, res.head.msg_type, res.head.msg_seq);
        err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, res.info);
        cms_securec_check(err);
        return GS_ERROR;
    }
    CMS_LOG_INF("del node on master succ, msg type %u, msg req %llu, srv msg type %u, srv msg seq %llu, "
        "srv res msg type %u, srv res msg seq %llu, node id %u", msg->msg_type, msg->msg_seq, req.head.msg_type,
        req.head.msg_seq, res.head.msg_type, res.head.msg_seq, tool_req->node_id);
    return GS_SUCCESS;
}

void cms_proc_uds_msg_req_del_node(cms_packet_head_t* msg)
{
    status_t ret = GS_SUCCESS;
    bool32 is_master = GS_FALSE;
    cms_tool_msg_req_del_node_t* req = (cms_tool_msg_req_del_node_t*)msg;
    CMS_LOG_INF("begin proc uds msg del node, msg type %u, msg req %llu, node id %u", msg->msg_type, msg->msg_seq,
        req->node_id);
    CMS_RETRY_IF_ERR(cms_is_master(&is_master));
    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_tool_msg_res_del_node_t));
    cms_tool_msg_res_del_node_t* res = (cms_tool_msg_res_del_node_t*)cms_que_node_data(node);
    res->head.dest_node = msg->src_node;
    res->head.src_node = msg->dest_node;
    res->head.msg_size = sizeof(cms_tool_msg_res_del_node_t);
    res->head.msg_type = CMS_TOOL_MSG_RES_DEL_NODE;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.src_msg_seq = msg->msg_seq;
    res->head.msg_seq = cm_now();
    res->head.uds_sid = msg->uds_sid;
    if (is_master) {
        ret = cms_exec_del_node(msg, res->info, CMS_INFO_BUFFER_SIZE);
    } else {
        ret = cms_del_node_on_master(msg, res->info);
    }
    if (ret == GS_SUCCESS) {
        ret = cms_sync_gcc_backup(res->info);
    }
    res->result = ret;
    cms_enque(&g_cms_inst->cli_send_que, node);
    cms_notify_load_gcc();
    CMS_LOG_INF("end proc uds msg del node, ret %d, is master %d, msg type %u, msg req %llu, node id %u", ret,
        is_master, msg->msg_type, msg->msg_seq, req->node_id);
}

status_t cms_init_add_grp_req_to_master(cms_tool_msg_req_add_grp_t* tool_req, cms_msg_req_add_grp_t* req,
    char* err_info)
{
    errno_t err = EOK;
    req->head.msg_type = CMS_MSG_REQ_ADD_GRP;
    req->head.msg_size = sizeof(cms_msg_req_add_grp_t);
    req->head.msg_version = CMS_MSG_VERSION;
    req->head.msg_seq = cm_now();
    req->head.src_msg_seq = 0;
    err = strcpy_sp(req->group, CMS_NAME_BUFFER_SIZE, tool_req->group);
    if (err != EOK) {
        CMS_LOG_ERR("strcpy_sp failed, CMS_NAME_BUFFER_SIZE %u, errno %d[%s]", CMS_NAME_BUFFER_SIZE,
            cm_get_os_error(), strerror(errno));
        err = strcpy_sp(err_info, CMS_MAX_INFO_LEN, "strcpy group failed");
        cms_securec_check(err);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t cms_add_grp_on_master(cms_packet_head_t* msg, char* err_info)
{
    status_t ret = GS_SUCCESS;
    uint16 master_node = -1;
    errno_t err = EOK;
    cms_msg_req_add_grp_t req = {0};
    cms_msg_res_add_grp_t res = {0};
    cms_tool_msg_req_add_grp_t* tool_req = (cms_tool_msg_req_add_grp_t*)msg;
    
    CMS_LOG_INF("begin add grp on master, msg type %u, msg req %llu, group %s", msg->msg_type, msg->msg_seq,
        tool_req->group);
    ret = cms_get_master_node(&master_node);
    if (ret != GS_SUCCESS || master_node >= CMS_MAX_NODE_COUNT) {
        CMS_LOG_ERR("get master node failed, ret %d, master node %u", ret, master_node);
        err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "get master info failed");
        cms_securec_check(err);
        return ret;
    }

    if (cms_init_add_grp_req_to_master(tool_req, &req, err_info) != GS_SUCCESS) {
        CMS_LOG_ERR("cms init add grp req to master failed");
        return GS_ERROR;
    }

    CMS_LOG_INF("send srv msg add grp to master, srv msg type %u, srv msg req %llu", req.head.msg_type,
        req.head.msg_seq);
    ret = cms_mes_send_cmd_to_other((cms_packet_head_t*)&req, (cms_packet_head_t*)&res, master_node);
    if (ret != GS_SUCCESS) {
        CMS_LOG_ERR("send srv msg add grp to master failed, ret %d, msg type %u, msg req %llu, srv msg type %u,"
            " srv msg seq %llu", ret, msg->msg_type, msg->msg_seq, req.head.msg_type, req.head.msg_seq);
        err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "send message to master failed");
        cms_securec_check(err);
        return ret;
    }
    if (ret == GS_SUCCESS && res.result != GS_SUCCESS) {
        CMS_LOG_ERR("add grp on master node failed, result %d, msg type %u, msg req %llu, srv msg type %u,"
            " srv msg seq %llu, srv res msg type %u, srv res msg seq %llu", res.result, msg->msg_type, msg->msg_seq,
            req.head.msg_type, req.head.msg_seq, res.head.msg_type, res.head.msg_seq);
        err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, res.info);
        cms_securec_check(err);
        return GS_ERROR;
    }
    CMS_LOG_INF("add grp on master succ, msg type %u, msg req %llu, srv msg type %u, srv msg seq %llu, "
        "srv res msg type %u, srv res msg seq %llu, group %s", msg->msg_type, msg->msg_seq, req.head.msg_type,
        req.head.msg_seq, res.head.msg_type, res.head.msg_seq, tool_req->group);
    return GS_SUCCESS;
}

void cms_proc_uds_msg_req_add_grp(cms_packet_head_t* msg)
{
    status_t ret = GS_SUCCESS;
    bool32 is_master = GS_FALSE;
    cms_tool_msg_req_add_grp_t* req = (cms_tool_msg_req_add_grp_t*)msg;
    CMS_LOG_INF("begin proc uds msg add grp, msg type %u, msg req %llu, group %s", msg->msg_type, msg->msg_seq,
        req->group);
    CMS_RETRY_IF_ERR(cms_is_master(&is_master));
    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_tool_msg_res_add_grp_t));
    cms_tool_msg_res_add_grp_t* res = (cms_tool_msg_res_add_grp_t*)cms_que_node_data(node);
    res->head.dest_node = msg->src_node;
    res->head.src_node = msg->dest_node;
    res->head.msg_size = sizeof(cms_tool_msg_res_add_grp_t);
    res->head.msg_type = CMS_TOOL_MSG_RES_ADD_GRP;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.src_msg_seq = msg->msg_seq;
    res->head.msg_seq = cm_now();
    res->head.uds_sid = msg->uds_sid;
    if (is_master) {
        ret = cms_exec_add_grp(msg, res->info, CMS_INFO_BUFFER_SIZE);
    } else {
        ret = cms_add_grp_on_master(msg, res->info);
    }
    if (ret == GS_SUCCESS) {
        ret = cms_sync_gcc_backup(res->info);
    }
    res->result = ret;
    cms_enque(&g_cms_inst->cli_send_que, node);
    cms_notify_load_gcc();
    CMS_LOG_INF("end proc uds msg add grp, ret %d, is master %d, msg type %u, msg req %llu, group %s", ret, is_master,
        msg->msg_type, msg->msg_seq, req->group);
}

status_t cms_init_del_grp_req_to_master(cms_tool_msg_req_del_grp_t* tool_req, cms_msg_req_del_grp_t* req,
    char* err_info)
{
    errno_t err = EOK;
    req->head.src_node = g_cms_param->node_id;
    req->head.msg_type = CMS_MSG_REQ_DEL_GRP;
    req->head.msg_size = sizeof(cms_msg_req_del_grp_t);
    req->head.msg_version = CMS_MSG_VERSION;
    req->head.msg_seq = cm_now();
    req->head.src_msg_seq = 0;
    req->force = tool_req->force;
    err = strcpy_sp(req->group, CMS_NAME_BUFFER_SIZE, tool_req->group);
    if (err != EOK) {
        CMS_LOG_ERR("strcpy_sp failed, CMS_NAME_BUFFER_SIZE %u, errno %d[%s]", CMS_NAME_BUFFER_SIZE,
            cm_get_os_error(), strerror(errno));
        err = strcpy_sp(err_info, CMS_MAX_INFO_LEN, "strcpy group failed");
        cms_securec_check(err);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t cms_del_grp_on_master(cms_packet_head_t* msg, char* err_info)
{
    status_t ret = GS_SUCCESS;
    uint16 master_node = -1;
    errno_t err = EOK;
    cms_msg_req_del_grp_t req = {0};
    cms_msg_res_del_grp_t res = {0};
    cms_tool_msg_req_del_grp_t* tool_req = (cms_tool_msg_req_del_grp_t*)msg;
    
    CMS_LOG_INF("begin del grp on master, msg type %u, msg req %llu, group %s, force %d", msg->msg_type, msg->msg_seq,
        tool_req->group, tool_req->force);
    ret = cms_get_master_node(&master_node);
    if (ret != GS_SUCCESS || master_node >= CMS_MAX_NODE_COUNT) {
        CMS_LOG_ERR("get master node failed, ret %d, master node %u", ret, master_node);
        err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "get master info failed");
        cms_securec_check(err);
        return ret;
    }

    if (cms_init_del_grp_req_to_master(tool_req, &req, err_info) != GS_SUCCESS) {
        CMS_LOG_ERR("cms init del grp req to master failed");
        return GS_ERROR;
    }

    CMS_LOG_INF("send srv msg del grp to master, srv msg type %u, srv msg req %llu", req.head.msg_type,
        req.head.msg_seq);
    ret = cms_mes_send_cmd_to_other((cms_packet_head_t*)&req, (cms_packet_head_t*)&res, master_node);
    if (ret != GS_SUCCESS) {
        CMS_LOG_ERR("send srv msg del grp to master failed, ret %d, msg type %u, msg req %llu, srv msg type %u,"
            " srv msg seq %llu", ret, msg->msg_type, msg->msg_seq, req.head.msg_type, req.head.msg_seq);
        err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "send message to master failed");
        cms_securec_check(err);
        return ret;
    }
    if (ret == GS_SUCCESS && res.result != GS_SUCCESS) {
        CMS_LOG_ERR("del grp on master node failed, result %d, msg type %u, msg req %llu, srv msg type %u,"
            " srv msg seq %llu, srv res msg type %u, srv res msg seq %llu", res.result, msg->msg_type, msg->msg_seq,
            req.head.msg_type, req.head.msg_seq, res.head.msg_type, res.head.msg_seq);
        err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, res.info);
        cms_securec_check(err);
        return GS_ERROR;
    }
    CMS_LOG_INF("del grp on master succ, msg type %u, msg req %llu, srv msg type %u, srv msg seq %llu, "
        "srv res msg type %u, srv res msg seq %llu, group %s, force %d", msg->msg_type, msg->msg_seq,
        req.head.msg_type, req.head.msg_seq, res.head.msg_type, res.head.msg_seq, tool_req->group, tool_req->force);
    return GS_SUCCESS;
}

void cms_proc_uds_msg_req_del_grp(cms_packet_head_t* msg)
{
    status_t ret = GS_SUCCESS;
    bool32 is_master = GS_FALSE;
    cms_tool_msg_req_del_grp_t* req = (cms_tool_msg_req_del_grp_t*)msg;
    CMS_LOG_INF("begin proc uds msg del grp, msg type %u, msg req %llu, group %s, force %d", msg->msg_type,
        msg->msg_seq, req->group, req->force);
    CMS_RETRY_IF_ERR(cms_is_master(&is_master));
    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_tool_msg_res_add_grp_t));
    cms_tool_msg_res_add_grp_t* res = (cms_tool_msg_res_add_grp_t*)cms_que_node_data(node);
    res->head.dest_node = msg->src_node;
    res->head.src_node = msg->dest_node;
    res->head.msg_size = sizeof(cms_tool_msg_res_del_grp_t);
    res->head.msg_type = CMS_TOOL_MSG_RES_DEL_GRP;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.src_msg_seq = msg->msg_seq;
    res->head.msg_seq = cm_now();
    res->head.uds_sid = msg->uds_sid;
    if (is_master) {
        ret = cms_exec_del_grp(msg, res->info, CMS_INFO_BUFFER_SIZE);
    } else {
        ret = cms_del_grp_on_master(msg, res->info);
    }
    if (ret == GS_SUCCESS) {
        ret = cms_sync_gcc_backup(res->info);
    }
    res->result = ret;
    cms_enque(&g_cms_inst->cli_send_que, node);
    cms_notify_load_gcc();
    CMS_LOG_INF("end proc uds msg del grp, ret %d, is master %d, msg type %u, msg req %llu, group %s", ret, is_master,
        msg->msg_type, msg->msg_seq, req->group);
}

status_t cms_init_add_res_req_to_master(cms_tool_msg_req_add_res_t* tool_req, cms_msg_req_add_res_t* req,
    char* err_info)
{
    errno_t err = EOK;
    req->head.msg_type = CMS_MSG_REQ_ADD_RES;
    req->head.msg_size = sizeof(cms_msg_req_add_res_t);
    req->head.msg_version = CMS_MSG_VERSION;
    req->head.msg_seq = cm_now();
    req->head.src_msg_seq = 0;
    err = strcpy_sp(req->name, CMS_NAME_BUFFER_SIZE, tool_req->name);
    if (err != EOK) {
        CMS_LOG_ERR("strcpy_sp failed, CMS_NAME_BUFFER_SIZE %u, errno %d[%s]", CMS_NAME_BUFFER_SIZE,
            cm_get_os_error(), strerror(errno));
        err = strcpy_sp(err_info, CMS_MAX_INFO_LEN, "strcpy name failed");
        cms_securec_check(err);
        return GS_ERROR;
    }
    err = strcpy_sp(req->type, CMS_NAME_BUFFER_SIZE, tool_req->type);
    if (err != EOK) {
        CMS_LOG_ERR("strcpy_sp failed, CMS_NAME_BUFFER_SIZE %u, errno %d[%s]", CMS_NAME_BUFFER_SIZE,
            cm_get_os_error(), strerror(errno));
        err = strcpy_sp(err_info, CMS_MAX_INFO_LEN, "strcpy type failed");
        cms_securec_check(err);
        return GS_ERROR;
    }
    err = strcpy_sp(req->group, CMS_NAME_BUFFER_SIZE, tool_req->group);
    if (err != EOK) {
        CMS_LOG_ERR("strcpy_sp failed, CMS_NAME_BUFFER_SIZE %u, errno %d[%s]", CMS_NAME_BUFFER_SIZE,
            cm_get_os_error(), strerror(errno));
        err = strcpy_sp(err_info, CMS_MAX_INFO_LEN, "strcpy group failed");
        cms_securec_check(err);
        return GS_ERROR;
    }
    err = strcpy_sp(req->attrs, CMS_RES_ATTRS_BUFFER_SIZE, tool_req->attrs);
    if (err != EOK) {
        CMS_LOG_ERR("strcpy_sp failed, CMS_RES_ATTRS_BUFFER_SIZE %u, errno %d[%s]", CMS_RES_ATTRS_BUFFER_SIZE,
            cm_get_os_error(), strerror(errno));
        err = strcpy_sp(err_info, CMS_MAX_INFO_LEN, "strcpy attrs failed");
        cms_securec_check(err);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t cms_add_res_on_master(cms_packet_head_t* msg, char* err_info)
{
    status_t ret = GS_SUCCESS;
    uint16 master_node = -1;
    errno_t err = EOK;
    cms_msg_req_add_res_t req = {0};
    cms_msg_res_add_res_t res = {0};
    cms_tool_msg_req_add_res_t* tool_req = (cms_tool_msg_req_add_res_t*)msg;
    
    CMS_LOG_INF("begin add res on master, msg type %u, msg req %llu, name %s", msg->msg_type, msg->msg_seq,
        tool_req->name);
    ret = cms_get_master_node(&master_node);
    if (ret != GS_SUCCESS || master_node >= CMS_MAX_NODE_COUNT) {
        CMS_LOG_ERR("get master node failed, ret %d, master node %u", ret, master_node);
        err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "get master info failed");
        cms_securec_check(err);
        return ret;
    }

    if (cms_init_add_res_req_to_master(tool_req, &req, err_info) != GS_SUCCESS) {
        CMS_LOG_ERR("cms init add res req to master failed");
        return GS_ERROR;
    }

    CMS_LOG_INF("send srv msg add res to master, srv msg type %u, srv msg req %llu", req.head.msg_type,
        req.head.msg_seq);
    ret = cms_mes_send_cmd_to_other((cms_packet_head_t*)&req, (cms_packet_head_t*)&res, master_node);
    if (ret != GS_SUCCESS) {
        CMS_LOG_ERR("send srv msg add res to master failed, ret %d, msg type %u, msg req %llu, srv msg type %u,"
            " srv msg seq %llu", ret, msg->msg_type, msg->msg_seq, req.head.msg_type, req.head.msg_seq);
        err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "send message to master failed");
        cms_securec_check(err);
        return ret;
    }
    if (ret == GS_SUCCESS && res.result != GS_SUCCESS) {
        CMS_LOG_ERR("add res on master node failed, result %d, msg type %u, msg req %llu, srv msg type %u,"
            " srv msg seq %llu, srv res msg tpye %d, srv res msg seq %llu", res.result, msg->msg_type, msg->msg_seq,
            req.head.msg_type, req.head.msg_seq, res.head.msg_type, res.head.msg_seq);
        err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, res.info);
        cms_securec_check(err);
        return GS_ERROR;
    }
    CMS_LOG_INF("add res on master succ, msg type %u, msg req %llu, srv msg type %u, srv msg seq %llu, "
        "srv res msg type %u, srv res msg seq %llu, name %s", msg->msg_type, msg->msg_seq, req.head.msg_type,
        req.head.msg_seq, res.head.msg_type, res.head.msg_seq, tool_req->name);
    return GS_SUCCESS;
}

void cms_proc_uds_msg_req_add_res(cms_packet_head_t* msg)
{
    status_t ret = GS_SUCCESS;
    bool32 is_master = GS_FALSE;
    cms_tool_msg_req_add_res_t* req = (cms_tool_msg_req_add_res_t*)msg;
    CMS_LOG_INF("begin proc uds msg add res, msg type %u, msg req %llu, name %s", msg->msg_type, msg->msg_seq,
        req->name);
    CMS_RETRY_IF_ERR(cms_is_master(&is_master));
    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_tool_msg_res_add_res_t));
    cms_tool_msg_res_add_res_t* res = (cms_tool_msg_res_add_res_t*)cms_que_node_data(node);
    res->head.dest_node = msg->src_node;
    res->head.src_node = msg->dest_node;
    res->head.msg_size = sizeof(cms_tool_msg_res_add_res_t);
    res->head.msg_type = CMS_TOOL_MSG_RES_ADD_RES;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.src_msg_seq = msg->msg_seq;
    res->head.msg_seq = cm_now();
    res->head.uds_sid = msg->uds_sid;
    if (is_master) {
        ret = cms_exec_add_res(msg, res->info, CMS_INFO_BUFFER_SIZE);
    } else {
        ret = cms_add_res_on_master(msg, res->info);
    }
    if (ret == GS_SUCCESS) {
        ret = cms_sync_gcc_backup(res->info);
    }
    res->result = ret;
    cms_enque(&g_cms_inst->cli_send_que, node);
    cms_notify_load_gcc();
    CMS_LOG_INF("end proc uds msg add res, ret %d, is master %d, msg type %u, msg req %llu, name %s", ret, is_master,
        msg->msg_type, msg->msg_seq, req->name);
}

status_t cms_init_edit_res_req_to_master(cms_tool_msg_req_edit_res_t* tool_req, cms_msg_req_edit_res_t* req,
    char* err_info)
{
    errno_t err = EOK;
    req->head.msg_type = CMS_MSG_REQ_EDIT_RES;
    req->head.msg_size = sizeof(cms_msg_req_edit_res_t);
    req->head.msg_version = CMS_MSG_VERSION;
    req->head.msg_seq = cm_now();
    req->head.src_msg_seq = 0;
    err = strcpy_sp(req->name, CMS_NAME_BUFFER_SIZE, tool_req->name);
    if (err != EOK) {
        CMS_LOG_ERR("strcpy_sp failed, CMS_NAME_BUFFER_SIZE %u, errno %d[%s]", CMS_NAME_BUFFER_SIZE,
            cm_get_os_error(), strerror(errno));
        err = strcpy_sp(err_info, CMS_MAX_INFO_LEN, "strcpy name failed");
        cms_securec_check(err);
        return GS_ERROR;
    }
    err = strcpy_sp(req->attrs, CMS_RES_ATTRS_BUFFER_SIZE, tool_req->attrs);
    if (err != EOK) {
        CMS_LOG_ERR("strcpy_sp failed, CMS_RES_ATTRS_BUFFER_SIZE %u, errno %d[%s]", CMS_RES_ATTRS_BUFFER_SIZE,
            cm_get_os_error(), strerror(errno));
        err = strcpy_sp(err_info, CMS_MAX_INFO_LEN, "strcpy attrs failed");
        cms_securec_check(err);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t cms_edit_res_on_master(cms_packet_head_t* msg, char* err_info)
{
    status_t ret = GS_SUCCESS;
    uint16 master_node = -1;
    errno_t err = EOK;
    cms_msg_req_edit_res_t req = {0};
    cms_msg_res_edit_res_t res = {0};
    cms_tool_msg_req_edit_res_t* tool_req = (cms_tool_msg_req_edit_res_t*)msg;
    
    CMS_LOG_INF("begin edit res on master, msg type %u, msg req %llu, name %s", msg->msg_type, msg->msg_seq,
        tool_req->name);
    ret = cms_get_master_node(&master_node);
    if (ret != GS_SUCCESS || master_node >= CMS_MAX_NODE_COUNT) {
        CMS_LOG_ERR("get master node failed, ret %d, master node %u", ret, master_node);
        err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "get master info failed");
        cms_securec_check(err);
        return ret;
    }

    if (cms_init_edit_res_req_to_master(tool_req, &req, err_info) != GS_SUCCESS) {
        CMS_LOG_ERR("cms init edit res req to master failed");
        return GS_ERROR;
    }
    
    CMS_LOG_INF("send srv msg edit res to master, srv msg type %u, srv msg req %llu", req.head.msg_type,
        req.head.msg_seq);
    ret = cms_mes_send_cmd_to_other((cms_packet_head_t*)&req, (cms_packet_head_t*)&res, master_node);
    if (ret != GS_SUCCESS) {
        CMS_LOG_ERR("send srv msg edit res to master failed, ret %d, msg type %u, msg req %llu, srv msg type %u,"
            " srv msg seq %llu", ret, msg->msg_type, msg->msg_seq, req.head.msg_type, req.head.msg_seq);
        err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "send message to master failed");
        cms_securec_check(err);
        return ret;
    }
    if (ret == GS_SUCCESS && res.result != GS_SUCCESS) {
        CMS_LOG_ERR("edit res on master node failed, result %d, msg type %u, msg req %llu, srv msg type %u,"
            " srv msg seq %llu, srv res msg type %u, srv res msg seq %llu", res.result, msg->msg_type, msg->msg_seq,
            req.head.msg_type, req.head.msg_seq, res.head.msg_type, res.head.msg_seq);
        err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, res.info);
        cms_securec_check(err);
        return GS_ERROR;
    }
    CMS_LOG_INF("edit res on master succ, msg type %u, msg req %llu, srv msg type %u, srv msg seq %llu, "
        "srv res msg type %u, srv res msg seq %llu, name %s", msg->msg_type, msg->msg_seq, req.head.msg_type,
        req.head.msg_seq, res.head.msg_type, res.head.msg_seq, tool_req->name);
    return GS_SUCCESS;
}

void cms_proc_uds_msg_req_edit_res(cms_packet_head_t* msg)
{
    status_t ret = GS_SUCCESS;
    bool32 is_master = GS_FALSE;
    cms_tool_msg_req_edit_res_t* req = (cms_tool_msg_req_edit_res_t*)msg;
    CMS_LOG_INF("begin proc uds msg edit res, msg type %u, msg req %llu, name %s", msg->msg_type, msg->msg_seq,
        req->name);
    CMS_RETRY_IF_ERR(cms_is_master(&is_master));
    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_tool_msg_res_edit_res_t));
    cms_tool_msg_res_edit_res_t* res = (cms_tool_msg_res_edit_res_t*)cms_que_node_data(node);
    res->head.dest_node = msg->src_node;
    res->head.src_node = msg->dest_node;
    res->head.msg_size = sizeof(cms_tool_msg_res_edit_res_t);
    res->head.msg_type = CMS_TOOL_MSG_RES_EDIT_RES;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.src_msg_seq = msg->msg_seq;
    res->head.msg_seq = cm_now();
    res->head.uds_sid = msg->uds_sid;
    if (is_master) {
        ret = cms_exec_edit_res(msg, res->info, CMS_INFO_BUFFER_SIZE);
    } else {
        ret = cms_edit_res_on_master(msg, res->info);
    }
    if (ret == GS_SUCCESS) {
        ret = cms_sync_gcc_backup(res->info);
    }
    res->result = ret;
    cms_enque(&g_cms_inst->cli_send_que, node);
    cms_notify_load_gcc();
    CMS_LOG_INF("end proc uds msg edit res, ret %d, is master %d, msg type %u, msg req %llu, name %s", ret, is_master,
        msg->msg_type, msg->msg_seq, req->name);
}

status_t cms_init_del_res_req_to_master(cms_tool_msg_req_del_res_t* tool_req, cms_msg_req_del_res_t* req,
    char* err_info)
{
    errno_t err = EOK;
    req->head.msg_type = CMS_MSG_REQ_DEL_RES;
    req->head.msg_size = sizeof(cms_msg_req_del_res_t);
    req->head.msg_version = CMS_MSG_VERSION;
    req->head.msg_seq = cm_now();
    req->head.src_msg_seq = 0;
    err = strcpy_sp(req->name, CMS_NAME_BUFFER_SIZE, tool_req->name);
    if (err != EOK) {
        CMS_LOG_ERR("strcpy_sp failed, CMS_NAME_BUFFER_SIZE %u, errno %d[%s]", CMS_NAME_BUFFER_SIZE,
            cm_get_os_error(), strerror(errno));
        err = strcpy_sp(err_info, CMS_MAX_INFO_LEN, "strcpy name failed");
        cms_securec_check(err);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t cms_del_res_on_master(cms_packet_head_t* msg, char* err_info)
{
    status_t ret = GS_SUCCESS;
    uint16 master_node = -1;
    errno_t err = EOK;
    cms_msg_req_del_res_t req = {0};
    cms_msg_res_del_res_t res = {0};
    cms_tool_msg_req_del_res_t* tool_req = (cms_tool_msg_req_del_res_t*)msg;
    
    CMS_LOG_INF("begin del res on master, msg type %u, msg req %llu, name %s", msg->msg_type, msg->msg_seq,
        tool_req->name);
    ret = cms_get_master_node(&master_node);
    if (ret != GS_SUCCESS || master_node >= CMS_MAX_NODE_COUNT) {
        CMS_LOG_ERR("get master node failed, ret %d, master node %u", ret, master_node);
        err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "get master info failed");
        cms_securec_check(err);
        return ret;
    }
   
    if (cms_init_del_res_req_to_master(tool_req, &req, err_info) != GS_SUCCESS) {
        CMS_LOG_ERR("cms init del res req to master failed");
        return GS_ERROR;
    }
    
    CMS_LOG_INF("send srv msg del res to master, srv msg type %u, srv msg req %llu", req.head.msg_type,
        req.head.msg_seq);
    ret = cms_mes_send_cmd_to_other((cms_packet_head_t*)&req, (cms_packet_head_t*)&res, master_node);
    if (ret != GS_SUCCESS) {
        CMS_LOG_ERR("send srv msg del res to master failed, ret %d, msg type %u, msg req %llu, srv msg type %u,"
            " srv msg seq %llu", ret, msg->msg_type, msg->msg_seq, req.head.msg_type, req.head.msg_seq);
        err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "send message to master failed");
        cms_securec_check(err);
        return ret;
    }
    if (ret == GS_SUCCESS && res.result != GS_SUCCESS) {
        CMS_LOG_ERR("del res on master node failed, result %d, msg type %u, msg req %llu, srv msg type %u,"
            " srv msg seq %llu, srv res msg type %u, srv res msg req %llu", res.result, msg->msg_type, msg->msg_seq,
            req.head.msg_type, req.head.msg_seq, res.head.msg_type, res.head.msg_seq);
        err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, res.info);
        cms_securec_check(err);
        return GS_ERROR;
    }
    CMS_LOG_INF("del res on master succ, msg type %u, msg req %llu, srv msg type %u, srv msg seq %llu, "
        "srv res msg type %u, srv res msg seq %llu, name %s", msg->msg_type, msg->msg_seq, req.head.msg_type,
        req.head.msg_seq, res.head.msg_type, res.head.msg_seq, tool_req->name);
    return GS_SUCCESS;
}

void cms_proc_uds_msg_req_del_res(cms_packet_head_t* msg)
{
    status_t ret = GS_SUCCESS;
    bool32 is_master = GS_FALSE;
    cms_tool_msg_req_del_res_t* req = (cms_tool_msg_req_del_res_t*)msg;
    CMS_LOG_INF("begin proc uds msg del res, msg type %u, msg req %llu, name %s", msg->msg_type, msg->msg_seq,
        req->name);
    CMS_RETRY_IF_ERR(cms_is_master(&is_master));
    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_tool_msg_res_del_res_t));
    cms_tool_msg_res_del_res_t* res = (cms_tool_msg_res_del_res_t*)cms_que_node_data(node);
    res->head.dest_node = msg->src_node;
    res->head.src_node = msg->dest_node;
    res->head.msg_size = sizeof(cms_tool_msg_res_del_res_t);
    res->head.msg_type = CMS_TOOL_MSG_RES_DEL_RES;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.src_msg_seq = msg->msg_seq;
    res->head.msg_seq = cm_now();
    res->head.uds_sid = msg->uds_sid;
    if (is_master) {
        ret = cms_exec_del_res(msg, res->info, CMS_INFO_BUFFER_SIZE);
    } else {
        ret = cms_del_res_on_master(msg, res->info);
    }
    if (ret == GS_SUCCESS) {
        ret = cms_sync_gcc_backup(res->info);
    }
    res->result = ret;
    cms_enque(&g_cms_inst->cli_send_que, node);
    cms_notify_load_gcc();
    CMS_LOG_INF("end proc uds msg del res, ret %d, is master %d, msg type %u, msg req %llu, name %s", ret, is_master,
        msg->msg_type, msg->msg_seq, req->name);
}

void cms_proc_msg_req_update_local_gcc(cms_packet_head_t* msg)
{
    if (msg->src_node != msg->dest_node) {
        cms_load_gcc();
        cms_update_local_gcc();
        // trigger gcc_auto_bak
        g_cms_inst->gcc_auto_bak.is_backuping = GS_FALSE;
    }
}

void cms_proc_msg_req_dis_conn(cms_packet_head_t *msg)
{
    status_t ret = GS_SUCCESS;
    timeval_t tv_begin;

    CMS_LOG_INF("begin proc disconnect req, msg type %u, msg req %llu", msg->msg_type, msg->msg_seq);
    cantian_record_io_stat_begin(CMS_IO_RECORD_UDS_UNREGISTER, &tv_begin);
    cms_cli_msg_req_dis_conn_t *req = (cms_cli_msg_req_dis_conn_t *)msg;
    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_cli_msg_res_dis_conn_t));
    cms_cli_msg_res_dis_conn_t* res = (cms_cli_msg_res_dis_conn_t*)cms_que_node_data(node);

    ret = cms_res_dis_conn(req->res_type, req->inst_id);
    if (ret != GS_SUCCESS) {
        cantian_record_io_stat_end(CMS_IO_RECORD_UDS_UNREGISTER, &tv_begin, IO_STAT_FAILED);
        CMS_LOG_ERR("res disconnect failed, inst id %u, msg type %u, msg req %llu", req->inst_id, msg->msg_type,
            msg->msg_seq);
    } else {
        cantian_record_io_stat_end(CMS_IO_RECORD_UDS_UNREGISTER, &tv_begin, IO_STAT_SUCCESS);
    }

    res->result = ret;
    res->head.dest_node = -1;
    res->head.src_node = g_cms_param->node_id;
    res->head.msg_size = sizeof(cms_cli_msg_res_dis_conn_t);
    res->head.msg_type = CMS_CLI_MSG_RES_DIS_CONN;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.msg_seq = cm_now();
    res->head.src_msg_seq = req->head.msg_seq;
    CMS_LOG_INF("end proc disconnect req, msg type %u, msg req %llu, result %d",
        msg->msg_type, msg->msg_seq, res->result);
    cms_enque(&g_cms_inst->cli_send_que, node);
}

void cms_proc_msg_req_set_work_stat(cms_packet_head_t *msg)
{
    CMS_LOG_INF("begin proc set work stat req, msg type %u, msg req %llu", msg->msg_type, msg->msg_seq);
    timeval_t tv_begin;
    cantian_record_io_stat_begin(CMS_IO_RECORD_UDS_SET_WORK_STAT, &tv_begin);

    cms_cli_msg_req_set_work_stat_t* req = (cms_cli_msg_req_set_work_stat_t*)msg;

    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_cli_msg_res_set_work_stat_t));
    cms_cli_msg_res_set_work_stat_t* res = (cms_cli_msg_res_set_work_stat_t*)cms_que_node_data(node);

    if (req->work_stat == RC_JOINED) {
        CMS_SYNC_POINT_GLOBAL_START(CMS_RES_REFORM_TO_JOINED_ABORT, NULL, 0);
        CMS_SYNC_POINT_GLOBAL_END;
    }
    res->result = cms_res_set_workstat(req->res_type, req->inst_id, req->work_stat);

    if (res->result != GS_SUCCESS) {
        cantian_record_io_stat_end(CMS_IO_RECORD_UDS_SET_WORK_STAT, &tv_begin, IO_STAT_FAILED);
    } else {
        cantian_record_io_stat_end(CMS_IO_RECORD_UDS_SET_WORK_STAT, &tv_begin, IO_STAT_SUCCESS);
    }
    res->head.dest_node = -1;
    res->head.src_node = g_cms_param->node_id;
    res->head.msg_size = sizeof(cms_cli_msg_res_set_work_stat_t);
    res->head.msg_type = CMS_CLI_MSG_RES_SET_WORK_STAT;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.msg_seq = cm_now();
    res->head.src_msg_seq = req->head.msg_seq;

    CMS_LOG_INF("end proc set work stat req, msg type %u, msg req %llu, set work stat(%d) result %d",
        msg->msg_type, msg->msg_seq, req->work_stat, res->result);
    cms_enque(&g_cms_inst->cli_send_que, node);
}

void cms_proc_msg_req_stat_chg(cms_packet_head_t* msg)
{
    status_t ret = GS_SUCCESS;
    cms_msg_req_stat_chg_t* req = (cms_msg_req_stat_chg_t*)msg;
    CMS_LOG_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_20,
        "begin proc stat chg req, msg type %u, msg req %llu, res id %u, version %llu",
        msg->msg_type, msg->msg_seq, req->res_id, req->version);
    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_cli_msg_res_stat_chg_t));
    cms_cli_msg_res_stat_chg_t *res = (cms_cli_msg_res_stat_chg_t*)cms_que_node_data(node);
    res->head.dest_node = -1;
    res->head.src_node = g_cms_param->node_id;
    res->head.msg_size = sizeof(cms_cli_msg_res_stat_chg_t);
    res->head.msg_type = CMS_CLI_MSG_RES_STAT_CHG;
    res->head.src_msg_seq = req->head.msg_seq;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.msg_seq = cm_now();
    res->stat.inst_count = 0;

    ret = cms_get_cluster_stat(req->res_id, req->version, &res->stat);
    if (ret != GS_SUCCESS) {
        CMS_LOG_ERR("proc stat chg req failed, msg type %u, msg req %llu, res id %u, version %llu", msg->msg_type,
            msg->msg_seq, req->res_id, req->version);
        cms_que_free_node(node);
        return;
    }
    CMS_LOG_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_20,
        "end proc stat chg req, msg type %u, msg req %llu, res id %u, version %llu", msg->msg_type,
        msg->msg_seq, req->res_id, res->stat.version);
    cms_enque(&g_cms_inst->cli_send_que, node);
}

void cms_proc_msg_req_cli_hb(cms_packet_head_t* msg)
{
    uint32 cms_res_id;
    uint64 version;
    cms_cli_msg_req_hb_t* req = (cms_cli_msg_req_hb_t*)msg;

    CMS_LOG_DEBUG_INF("begin proc hb req, msg type %u, msg req %llu", msg->msg_type, msg->msg_seq);
    if (cms_get_res_id_by_type(req->res_type, &cms_res_id) != GS_SUCCESS) {
        CMS_LOG_ERR("get res id by type faield, res type %s, mst type %d, msg seq %llu",
            req->res_type, msg->msg_type, msg->msg_seq);
        return;
    }

    cms_res_hb(cms_res_id);

    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_cli_msg_res_hb_t));
    cms_cli_msg_res_hb_t *res = (cms_cli_msg_res_hb_t*)cms_que_node_data(node);
    res->head.dest_node = -1;
    res->head.src_node = g_cms_param->node_id;
    res->head.msg_size = sizeof(cms_cli_msg_res_hb_t);
    res->head.msg_type = CMS_CLI_MSG_RES_HB;
    res->head.src_msg_seq = req->head.msg_seq;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.msg_seq = cm_now();
    if (cms_get_stat_version(&version) == GS_SUCCESS) {
        res->version = version;
    } else {
        res->version = 0;
    }

    CMS_LOG_DEBUG_INF("end proc hb req, msg type %u, msg req %llu", msg->msg_type, msg->msg_seq);
    cms_enque(&g_cms_inst->cli_send_que, node);
}

void cms_proc_msg_req_get_cluster_res_stat(cms_packet_head_t* msg)
{
    timeval_t tv_begin;
    status_t ret = GS_SUCCESS;

    CMS_LOG_DEBUG_INF("begin proc get res stat req, msg type %u, msg req %llu", msg->msg_type, msg->msg_seq);
    cantian_record_io_stat_begin(CMS_IO_RECORD_UDS_GET_STAT_LIST1, &tv_begin);
    cms_cli_msg_req_get_res_stat_t* req = (cms_cli_msg_req_get_res_stat_t*)msg;

    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_cli_msg_res_get_res_stat_t));
    cms_cli_msg_res_get_res_stat_t *res = (cms_cli_msg_res_get_res_stat_t*)cms_que_node_data(node);
    res->head.dest_node = -1;
    res->head.src_node = g_cms_param->node_id;
    res->head.msg_size = sizeof(cms_cli_msg_res_get_res_stat_t);
    res->head.msg_type = CMS_CLI_MSG_RES_GET_RES_STAT;
    res->head.src_msg_seq = req->head.msg_seq;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.msg_seq = cm_now();
    res->stat.inst_count = 0;

    CMS_SYNC_POINT_GLOBAL_START(CMS_GET_CLUSTER_STAT_FAIL, &ret, GS_ERROR);
    ret = cms_get_cluster_stat_bytype(req->res_type, 0, &res->stat);
    CMS_SYNC_POINT_GLOBAL_END;
    if (ret != GS_SUCCESS) {
        cantian_record_io_stat_end(CMS_IO_RECORD_UDS_GET_STAT_LIST1, &tv_begin, IO_STAT_FAILED);
        CMS_LOG_ERR("get all res stat failed, ret %d, res type %s, msg type %u, msg req %llu", ret, req->res_type,
            msg->msg_type, msg->msg_seq);
    } else {
        cantian_record_io_stat_end(CMS_IO_RECORD_UDS_GET_STAT_LIST1, &tv_begin, IO_STAT_SUCCESS);
    }
    res->result = ret;
    cms_enque(&g_cms_inst->cli_send_que, node);
    CMS_LOG_DEBUG_INF("end proc get res stat req, msg type %u, msg req %llu", msg->msg_type, msg->msg_seq);
}

void cms_proc_msg_req_set_res_data(cms_packet_head_t* msg)
{
    CMS_LOG_INF("begin proc set res data req, msg type %u, msg req %llu", msg->msg_type, msg->msg_seq);
    timeval_t tv_begin;
    cantian_record_io_stat_begin(CMS_IO_RECORD_UDS_SET_DATA_NEW, &tv_begin);
    cms_cli_msg_req_set_data_t* req = (cms_cli_msg_req_set_data_t*)msg;
    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_cli_msg_res_set_data_t));
    cms_cli_msg_res_set_data_t* res = (cms_cli_msg_res_set_data_t*)cms_que_node_data(node);

    res->result = cms_stat_set_res_data(req->res_type, req->slot_id, req->data, req->data_size, req->old_version);
    res->head.dest_node = -1;
    res->head.src_node = g_cms_param->node_id;
    res->head.msg_size = sizeof(cms_cli_msg_res_set_data_t);
    res->head.msg_type = CMS_CLI_MSG_RES_SET_RES_DATA;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.msg_seq = cm_now();
    res->head.src_msg_seq = req->head.msg_seq;
    CMS_LOG_INF("begin proc set res data req, msg type %u, msg req %llu", msg->msg_type, msg->msg_seq);
    if (res->result != GS_SUCCESS) {
        CMS_LOG_ERR("cms stat set res data failed");
        cantian_record_io_stat_end(CMS_IO_RECORD_UDS_SET_DATA_NEW, &tv_begin, IO_STAT_FAILED);
    } else {
        cantian_record_io_stat_end(CMS_IO_RECORD_UDS_SET_DATA_NEW, &tv_begin, IO_STAT_SUCCESS);
    }
    CMS_LOG_DEBUG_INF("end proc set res data req, msg type %u, msg req %llu", msg->msg_type, msg->msg_seq);
    cms_enque(&g_cms_inst->cli_send_que, node);
}

void cms_proc_msg_req_get_res_data(cms_packet_head_t* msg)
{
    CMS_LOG_DEBUG_INF("begin proc get res data req, msg type %u, msg req %llu", msg->msg_type, msg->msg_seq);
    timeval_t tv_begin;
    cantian_record_io_stat_begin(CMS_IO_RECORD_UDS_GET_DATA_NEW, &tv_begin);
    cms_cli_msg_req_get_data_t* req = (cms_cli_msg_req_get_data_t*)msg;
    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_cli_msg_res_get_data_t));
    cms_cli_msg_res_get_data_t* res = (cms_cli_msg_res_get_data_t*)cms_que_node_data(node);
    errno_t err = memset_s(res, sizeof(cms_cli_msg_res_get_data_t), 0, sizeof(cms_cli_msg_res_get_data_t));
    if (err != EOK) {
        CMS_LOG_ERR("memset failed, ret %d, msg type %u, msg req %llu, msg size %u", err, msg->msg_type,
            msg->msg_seq, msg->msg_size);
        cms_que_free_node(node);
        return;
    }

    res->result = cms_stat_get_res_data(req->res_type, req->slot_id, res->data, sizeof(res->data),
        &res->data_size, &res->version);
    res->head.dest_node = -1;
    res->head.src_node = g_cms_param->node_id;
    res->head.msg_size = sizeof(cms_cli_msg_res_get_data_t) - (sizeof(res->data) - res->data_size);
    res->head.msg_type = CMS_CLI_MSG_RES_GET_RES_DATA;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.msg_seq = cm_now();
    res->head.src_msg_seq = req->head.msg_seq;
    CMS_LOG_DEBUG_INF("end proc get res data req, msg type %u, msg req %llu, src msg req %llu, msg size %u, result %d, "
        "res msg req %llu, res src msg req %llu",
        msg->msg_type, msg->msg_seq, msg->src_msg_seq, msg->msg_size, res->result, res->head.msg_seq,
        res->head.src_msg_seq);

    if (res->result != GS_SUCCESS) {
        cantian_record_io_stat_end(CMS_IO_RECORD_UDS_GET_DATA_NEW, &tv_begin, IO_STAT_FAILED);
        CMS_LOG_ERR("proc get res data failed, ret %d, res type %s, msg type %u, msg req %llu", res->result,
            req->res_type, msg->msg_type, msg->msg_seq);
    } else {
        cantian_record_io_stat_end(CMS_IO_RECORD_UDS_GET_DATA_NEW, &tv_begin, IO_STAT_SUCCESS);
    }
    cms_enque(&g_cms_inst->cli_send_que, node);
}

void cms_proc_uds_msg_req_stop_srv(cms_packet_head_t* msg)
{
    CMS_LOG_INF("begin proc stop server, msg type %u, msg req %llu", msg->msg_type, msg->msg_seq);
    g_cms_inst->server_loop = GS_FALSE;
    biqueue_node_t *node = cms_que_alloc_node(sizeof(cms_tool_msg_res_stop_srv_t));
    cms_tool_msg_res_stop_srv_t *res = (cms_tool_msg_res_stop_srv_t*)cms_que_node_data(node);
    res->head.dest_node = msg->src_node;
    res->head.src_node = msg->dest_node;
    res->head.msg_size = sizeof(cms_tool_msg_res_stop_srv_t);
    res->head.msg_type = CMS_TOOL_MSG_RES_STOP_SRV;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.src_msg_seq = msg->msg_seq;
    res->head.msg_seq = cm_now();
    res->head.uds_sid = msg->uds_sid;
    res->result = GS_SUCCESS;
    cms_enque(&g_cms_inst->cli_send_que, node);
    CMS_LOG_INF("end proc stop server, msg type %u, msg req %llu", msg->msg_type, msg->msg_seq);
}

void cms_proc_msg_req_get_srv_stat(cms_packet_head_t* msg)
{
    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_msg_res_get_srv_stat_t));
    cms_msg_res_get_srv_stat_t* res = (cms_msg_res_get_srv_stat_t*)cms_que_node_data(node);
    res->cluster_gap = g_cms_inst->time_gap;
    res->send_que_count = g_cms_inst->send_que.count;
    res->recv_que_count = g_cms_inst->recv_que.count + g_cms_inst->cmd_recv_que.count;
    res->server_stat_ready = g_cms_inst->server_loop;
    res->head.dest_node = msg->src_node;
    res->head.src_node = msg->dest_node;
    if (msg->need_ack == GS_TRUE) {
        res->head.is_ack = GS_TRUE;
        res->head.sid = msg->sid;
        res->head.rsn = msg->rsn;
    } else {
        res->head.is_ack = GS_FALSE;
    }
    res->head.msg_type = CMS_MSG_RES_GET_SRV_STAT;
    res->head.msg_size = sizeof(cms_msg_res_get_srv_stat_t);
    cms_enque(&g_cms_inst->send_que, node);
}

void cms_reply_msg_res_add_res(cms_packet_head_t* msg, status_t result, char* err_info, uint32 err_info_len)
{
    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_msg_res_add_res_t));
    cms_msg_res_add_res_t* res = (cms_msg_res_add_res_t*)cms_que_node_data(node);
    res->head.dest_node = msg->src_node;
    res->head.src_node = msg->dest_node;
    res->head.msg_size = sizeof(cms_msg_res_add_res_t);
    res->head.msg_type = CMS_MSG_RES_ADD_RES;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.msg_seq = cm_now();
    res->head.src_msg_seq = msg->msg_seq;
    if (msg->need_ack == GS_TRUE) {
        res->head.is_ack = GS_TRUE;
        res->head.sid = msg->sid;
        res->head.rsn = msg->rsn;
    } else {
        res->head.is_ack = GS_FALSE;
    }
    res->result = result;
    if (result != GS_SUCCESS) {
        errno_t err = strcpy_s(res->info, CMS_INFO_BUFFER_SIZE, err_info);
        if (err != EOK) {
            CMS_LOG_ERR("cms strcpy failed, CMS_INFO_BUFFER_SIZE %u, errno %d[%s]", CMS_INFO_BUFFER_SIZE,
                cm_get_os_error(), strerror(errno));
            cms_que_free_node(node);
            return;
        }
    }
    cms_enque(&g_cms_inst->send_que, node);
}

void cms_proc_msg_req_add_res(cms_packet_head_t* msg)
{
    status_t ret = GS_SUCCESS;
    bool32 is_master = GS_FALSE;
    char err_info[CMS_INFO_BUFFER_SIZE] = {0};
    cms_msg_req_add_res_t* req = (cms_msg_req_add_res_t*)msg;
 
    CMS_LOG_INF("begin proc msg add res, msg type %u, msg req %llu, name %s", msg->msg_type, msg->msg_seq,
        req->name);
    CMS_RETRY_IF_ERR(cms_is_master(&is_master));
    if (!is_master) {
        CMS_LOG_ERR("add res failed, current node is not the master node");
        char err[] = "current node is not the master node";
        cms_reply_msg_res_add_res(msg, GS_ERROR, err, sizeof(err));
        return;
    }
    ret = cms_exec_add_res(msg, err_info, CMS_INFO_BUFFER_SIZE);
    cms_reply_msg_res_add_res(msg, ret, err_info, CMS_INFO_BUFFER_SIZE);
    if (ret == GS_SUCCESS) {
        cms_notify_load_gcc();
        cms_broadcast_update_local_gcc();
    }
    CMS_LOG_INF("end proc msg add res, ret %d, msg type %u, msg req %llu, name %s", ret, msg->msg_type,
        msg->msg_seq, req->name);
}

void cms_reply_msg_res_edit_res(cms_packet_head_t* msg, status_t result, char* err_info, uint32 err_info_len)
{
    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_msg_res_edit_res_t));
    cms_msg_res_edit_res_t* res = (cms_msg_res_edit_res_t*)cms_que_node_data(node);
    res->head.dest_node = msg->src_node;
    res->head.src_node = msg->dest_node;
    res->head.msg_size = sizeof(cms_msg_res_edit_res_t);
    res->head.msg_type = CMS_MSG_RES_EDIT_RES;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.msg_seq = cm_now();
    res->head.src_msg_seq = msg->msg_seq;
    if (msg->need_ack == GS_TRUE) {
        res->head.is_ack = GS_TRUE;
        res->head.sid = msg->sid;
        res->head.rsn = msg->rsn;
    } else {
        res->head.is_ack = GS_FALSE;
    }
    res->result = result;
    if (result != GS_SUCCESS) {
        errno_t err = strcpy_s(res->info, CMS_INFO_BUFFER_SIZE, err_info);
        if (err != EOK) {
            CMS_LOG_ERR("cms strcpy failed, CMS_INFO_BUFFER_SIZE %u, errno %d[%s]", CMS_INFO_BUFFER_SIZE,
                cm_get_os_error(), strerror(errno));
            cms_que_free_node(node);
            return;
        }
    }
    cms_enque(&g_cms_inst->send_que, node);
}

void cms_proc_msg_req_edit_res(cms_packet_head_t* msg)
{
    status_t ret = GS_SUCCESS;
    bool32 is_master = GS_FALSE;
    char err_info[CMS_INFO_BUFFER_SIZE] = {0};
    cms_msg_req_edit_res_t* req = (cms_msg_req_edit_res_t*)msg;
 
    CMS_LOG_INF("begin proc msg edit res, msg type %u, msg req %llu, name %s", msg->msg_type, msg->msg_seq,
        req->name);
    CMS_RETRY_IF_ERR(cms_is_master(&is_master));
    if (!is_master) {
        CMS_LOG_ERR("edit res failed, current node is not the master node");
        char err[] = "current node is not the master node";
        cms_reply_msg_res_edit_res(msg, GS_ERROR, err, sizeof(err));
        CMS_LOG_INF("err length is %lu", sizeof(err));
        return;
    }
    ret = cms_exec_edit_res(msg, err_info, CMS_INFO_BUFFER_SIZE);
    cms_reply_msg_res_edit_res(msg, ret, err_info, CMS_INFO_BUFFER_SIZE);
    if (ret == GS_SUCCESS) {
        cms_notify_load_gcc();
        cms_broadcast_update_local_gcc();
    }
    CMS_LOG_INF("end proc msg edit res, ret %d, msg type %u, msg req %llu, name %s", ret, msg->msg_type,
        msg->msg_seq, req->name);
}

void cms_reply_msg_res_del_res(cms_packet_head_t* msg, status_t result, char* err_info, uint32 err_len)
{
    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_msg_res_del_res_t));
    cms_msg_res_del_res_t* res = (cms_msg_res_del_res_t*)cms_que_node_data(node);
    res->head.dest_node = msg->src_node;
    res->head.src_node = msg->dest_node;
    res->head.msg_size = sizeof(cms_msg_res_del_res_t);
    res->head.msg_type = CMS_MSG_RES_DEL_RES;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.msg_seq = cm_now();
    res->head.src_msg_seq = msg->msg_seq;
    if (msg->need_ack == GS_TRUE) {
        res->head.is_ack = GS_TRUE;
        res->head.sid = msg->sid;
        res->head.rsn = msg->rsn;
    } else {
        res->head.is_ack = GS_FALSE;
    }
    res->result = result;
    if (result != GS_SUCCESS) {
        errno_t err = strcpy_s(res->info, CMS_INFO_BUFFER_SIZE, err_info);
        if (err != EOK) {
            CMS_LOG_ERR("cms strcpy failed, CMS_INFO_BUFFER_SIZE %u, errno %d[%s]", CMS_INFO_BUFFER_SIZE,
                cm_get_os_error(), strerror(errno));
            cms_que_free_node(node);
            return;
        }
    }
    cms_enque(&g_cms_inst->send_que, node);
}

void cms_proc_msg_req_del_res(cms_packet_head_t* msg)
{
    status_t ret = GS_SUCCESS;
    bool32 is_master = GS_FALSE;
    char err_info[CMS_INFO_BUFFER_SIZE] = {0};
    cms_msg_req_del_res_t* req = (cms_msg_req_del_res_t*)msg;
 
    CMS_LOG_INF("begin proc msg del res, msg type %u, msg req %llu, name %s", msg->msg_type, msg->msg_seq,
        req->name);
    CMS_RETRY_IF_ERR(cms_is_master(&is_master));
    if (!is_master) {
        CMS_LOG_ERR("del res failed, current node is not the master node");
        char err[] = "current node is not the master node";
        cms_reply_msg_res_del_res(msg, GS_ERROR, err, sizeof(err));
        return;
    }
    ret = cms_exec_del_res(msg, err_info, CMS_INFO_BUFFER_SIZE);
    cms_reply_msg_res_del_res(msg, ret, err_info, CMS_INFO_BUFFER_SIZE);
    if (ret == GS_SUCCESS) {
        cms_notify_load_gcc();
        cms_broadcast_update_local_gcc();
    }
    CMS_LOG_INF("end proc msg del res, ret %d, msg type %u, msg req %llu, name %s", ret, msg->msg_type,
        msg->msg_seq, req->name);
}

void cms_reply_msg_add_grp_res(cms_packet_head_t* msg, status_t result, char* err_info, uint32 err_len)
{
    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_msg_res_add_grp_t));
    cms_msg_res_add_grp_t* res = (cms_msg_res_add_grp_t*)cms_que_node_data(node);
    res->head.dest_node = msg->src_node;
    res->head.src_node = msg->dest_node;
    res->head.msg_size = sizeof(cms_msg_res_add_grp_t);
    res->head.msg_type = CMS_MSG_RES_ADD_GRP;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.msg_seq = cm_now();
    res->head.src_msg_seq = msg->msg_seq;
    if (msg->need_ack == GS_TRUE) {
        res->head.is_ack = GS_TRUE;
        res->head.sid = msg->sid;
        res->head.rsn = msg->rsn;
    } else {
        res->head.is_ack = GS_FALSE;
    }
    res->result = result;
    if (result != GS_SUCCESS) {
        errno_t err = strcpy_s(res->info, CMS_INFO_BUFFER_SIZE, err_info);
        if (err != EOK) {
            CMS_LOG_ERR("cms strcpy failed, CMS_INFO_BUFFER_SIZE %u, errno %d[%s]", CMS_INFO_BUFFER_SIZE,
                cm_get_os_error(), strerror(errno));
            cms_que_free_node(node);
            return;
        }
    }
    cms_enque(&g_cms_inst->send_que, node);
}

void cms_proc_msg_req_add_grp(cms_packet_head_t* msg)
{
    status_t ret = GS_SUCCESS;
    bool32 is_master = GS_FALSE;
    char err_info[CMS_INFO_BUFFER_SIZE] = {0};
    cms_msg_req_add_grp_t* req = (cms_msg_req_add_grp_t*)msg;
 
    CMS_LOG_INF("begin proc msg add grp, msg type %u, msg req %llu, group %s", msg->msg_type, msg->msg_seq,
        req->group);
    CMS_RETRY_IF_ERR(cms_is_master(&is_master));
    if (!is_master) {
        CMS_LOG_ERR("add grp failed, current node is not the master node");
        char err[] = "current node is not the master node";
        cms_reply_msg_add_grp_res(msg, GS_ERROR, err, sizeof(err));
        return;
    }
    ret = cms_exec_add_grp(msg, err_info, CMS_INFO_BUFFER_SIZE);
    cms_reply_msg_add_grp_res(msg, ret, err_info, CMS_INFO_BUFFER_SIZE);
    if (ret == GS_SUCCESS) {
        cms_notify_load_gcc();
        cms_broadcast_update_local_gcc();
    }
    CMS_LOG_INF("end proc msg add grp, ret %d, msg type %u, msg req %llu, group %s", ret, msg->msg_type,
        msg->msg_seq, req->group);
}

void cms_reply_msg_del_grp_res(cms_packet_head_t* msg, status_t result, char* err_info, uint32 err_len)
{
    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_msg_res_del_grp_t));
    cms_msg_res_del_grp_t* res = (cms_msg_res_del_grp_t*)cms_que_node_data(node);
    res->head.dest_node = msg->src_node;
    res->head.src_node = msg->dest_node;
    res->head.msg_size = sizeof(cms_msg_res_del_grp_t);
    res->head.msg_type = CMS_MSG_RES_DEL_GRP;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.msg_seq = cm_now();
    res->head.src_msg_seq = msg->msg_seq;
    if (msg->need_ack == GS_TRUE) {
        res->head.is_ack = GS_TRUE;
        res->head.sid = msg->sid;
        res->head.rsn = msg->rsn;
    } else {
        res->head.is_ack = GS_FALSE;
    }
    res->result = result;
    if (result != GS_SUCCESS) {
        errno_t err = strcpy_s(res->info, CMS_INFO_BUFFER_SIZE, err_info);
        if (err != EOK) {
            CMS_LOG_ERR("cms strcpy failed, CMS_INFO_BUFFER_SIZE %u, errno %d[%s]", CMS_INFO_BUFFER_SIZE,
                cm_get_os_error(), strerror(errno));
            cms_que_free_node(node);
            return;
        }
    }
    cms_enque(&g_cms_inst->send_que, node);
}

void cms_proc_msg_req_del_grp(cms_packet_head_t* msg)
{
    status_t ret = GS_SUCCESS;
    bool32 is_master = GS_FALSE;
    char err_info[CMS_INFO_BUFFER_SIZE] = {0};
    cms_msg_req_del_grp_t* req = (cms_msg_req_del_grp_t*)msg;
 
    CMS_LOG_INF("begin proc msg del grp, msg type %u, msg req %llu, group %s", msg->msg_type, msg->msg_seq,
        req->group);
    CMS_RETRY_IF_ERR(cms_is_master(&is_master));
    if (!is_master) {
        CMS_LOG_ERR("del grp failed, current node is not the master node");
        char err[] = "current node is not the master node";
        cms_reply_msg_del_grp_res(msg, GS_ERROR, err, sizeof(err));
        return;
    }
    ret = cms_exec_del_grp(msg, err_info, CMS_INFO_BUFFER_SIZE);
    cms_reply_msg_del_grp_res(msg, ret, err_info, CMS_INFO_BUFFER_SIZE);
    if (ret == GS_SUCCESS) {
        cms_notify_load_gcc();
        cms_broadcast_update_local_gcc();
    }
    CMS_LOG_INF("end proc msg del grp, ret %d, msg type %u, msg req %llu, group %s", ret, msg->msg_type,
        msg->msg_seq, req->group);
}

void cms_reply_msg_add_node_res(cms_packet_head_t* msg, status_t result, char* err_info, uint32 err_len)
{
    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_msg_res_add_node_t));
    cms_msg_res_add_node_t* res = (cms_msg_res_add_node_t*)cms_que_node_data(node);
    res->head.dest_node = msg->src_node;
    res->head.src_node = msg->dest_node;
    res->head.msg_size = sizeof(cms_msg_res_add_node_t);
    res->head.msg_type = CMS_MSG_RES_ADD_NODE;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.msg_seq = cm_now();
    res->head.src_msg_seq = msg->msg_seq;
    if (msg->need_ack == GS_TRUE) {
        res->head.is_ack = GS_TRUE;
        res->head.sid = msg->sid;
        res->head.rsn = msg->rsn;
    } else {
        res->head.is_ack = GS_FALSE;
    }
    res->result = result;
    if (result != GS_SUCCESS) {
        errno_t err = strcpy_s(res->info, CMS_INFO_BUFFER_SIZE, err_info);
        if (err != EOK) {
            CMS_LOG_ERR("cms strcpy failed, CMS_INFO_BUFFER_SIZE %u, errno %d[%s]", CMS_INFO_BUFFER_SIZE,
                cm_get_os_error(), strerror(errno));
            cms_que_free_node(node);
            return;
        }
    }
    cms_enque(&g_cms_inst->send_que, node);
}

void cms_proc_msg_req_add_node(cms_packet_head_t* msg)
{
    status_t ret = GS_SUCCESS;
    bool32 is_master = GS_FALSE;
    char err_info[CMS_INFO_BUFFER_SIZE] = {0};
    cms_msg_req_add_node_t* req = (cms_msg_req_add_node_t*)msg;
 
    CMS_LOG_INF("begin proc msg add node, msg type %u, msg req %llu, node id %u, name %s", msg->msg_type, msg->msg_seq,
        req->node_id, req->name);
    CMS_RETRY_IF_ERR(cms_is_master(&is_master));
    if (!is_master) {
        CMS_LOG_ERR("add node failed, current node is not the master node");
        char err[] = "current node is not the master node";
        cms_reply_msg_add_node_res(msg, GS_ERROR, err, sizeof(err));
        return;
    }
    ret = cms_exec_add_node(msg, err_info, CMS_INFO_BUFFER_SIZE);
    cms_reply_msg_add_node_res(msg, ret, err_info, CMS_INFO_BUFFER_SIZE);
    if (ret == GS_SUCCESS) {
        cms_notify_load_gcc();
        cms_broadcast_update_local_gcc();
    }
    CMS_LOG_INF("end proc msg add node, ret %d, msg type %u, msg req %llu, node id %u, name %s", ret, msg->msg_type,
        msg->msg_seq, req->node_id, req->name);
}

void cms_reply_msg_del_node_res(cms_packet_head_t* msg, status_t result, char* err_info, uint32 err_len)
{
    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_msg_res_del_node_t));
    cms_msg_res_del_node_t* res = (cms_msg_res_del_node_t*)cms_que_node_data(node);
    res->head.dest_node = msg->src_node;
    res->head.src_node = msg->dest_node;
    res->head.msg_size = sizeof(cms_msg_res_del_node_t);
    res->head.msg_type = CMS_MSG_RES_DEL_NODE;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.msg_seq = cm_now();
    res->head.src_msg_seq = msg->msg_seq;
    if (msg->need_ack == GS_TRUE) {
        res->head.is_ack = GS_TRUE;
        res->head.sid = msg->sid;
        res->head.rsn = msg->rsn;
    } else {
        res->head.is_ack = GS_FALSE;
    }
    res->result = result;
    if (result != GS_SUCCESS) {
        errno_t err = strcpy_s(res->info, CMS_INFO_BUFFER_SIZE, err_info);
        if (err != EOK) {
            CMS_LOG_ERR("cms strcpy failed, CMS_INFO_BUFFER_SIZE %u, errno %d[%s]", CMS_INFO_BUFFER_SIZE,
                cm_get_os_error(), strerror(errno));
            cms_que_free_node(node);
            return;
        }
    }
    cms_enque(&g_cms_inst->send_que, node);
}


void cms_proc_msg_req_del_node(cms_packet_head_t* msg)
{
    status_t ret = GS_SUCCESS;
    bool32 is_master = GS_FALSE;
    char err_info[CMS_INFO_BUFFER_SIZE] = {0};
    cms_msg_req_del_node_t* req = (cms_msg_req_del_node_t*)msg;
 
    CMS_LOG_INF("begin proc msg del node, msg type %u, msg req %llu, node id %u", msg->msg_type, msg->msg_seq,
        req->node_id);
    CMS_RETRY_IF_ERR(cms_is_master(&is_master));
    if (!is_master) {
        CMS_LOG_ERR("del node failed, current node is not the master node");
        char err[] = "current node is not the master node";
        cms_reply_msg_add_node_res(msg, GS_ERROR, err, sizeof(err));
        return;
    }
    ret = cms_exec_del_node(msg, err_info, CMS_INFO_BUFFER_SIZE);
    cms_reply_msg_add_node_res(msg, ret, err_info, CMS_INFO_BUFFER_SIZE);
    if (ret == GS_SUCCESS) {
        cms_notify_load_gcc();
        cms_broadcast_update_local_gcc();
    }
    CMS_LOG_INF("end proc msg del node, ret %d, msg type %u, msg req %llu, node id %u", ret, msg->msg_type,
        msg->msg_seq, req->node_id);
}

void cmd_proc_msg(cms_packet_head_t* msg)
{
    switch (msg->msg_type) {
        case CMS_MSG_REQ_ADD_RES:
            cms_proc_msg_req_add_res(msg);
            break;
        case CMS_MSG_REQ_EDIT_RES:
            cms_proc_msg_req_edit_res(msg);
            break;
        case CMS_MSG_REQ_DEL_RES:
            cms_proc_msg_req_del_res(msg);
            break;
        case CMS_MSG_REQ_ADD_GRP:
            cms_proc_msg_req_add_grp(msg);
            break;
        case CMS_MSG_REQ_DEL_GRP:
            cms_proc_msg_req_del_grp(msg);
            break;
        case CMS_MSG_REQ_ADD_NODE:
            cms_proc_msg_req_add_node(msg);
            break;
        case CMS_MSG_REQ_DEL_NODE:
            cms_proc_msg_req_del_node(msg);
            break;
        default:
            CMS_LOG_ERR("unknown msg_type:%d", msg->msg_type);
    }
}

void cms_reply_msg_iof_kick_res(cms_packet_head_t *req_msg, status_t ret, const char *info)
{
    if (strlen(info) > CMS_MAX_INFO_LEN) {
        CMS_LOG_ERR("result info is too long.\n");
        return;
    }

    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_msg_res_iof_kick_t));
    cms_msg_res_iof_kick_t* res = (cms_msg_res_iof_kick_t*)cms_que_node_data(node);
    res->head.dest_node = req_msg->src_node;
    res->head.src_node = req_msg->dest_node;
    res->head.msg_size = sizeof(cms_msg_res_iof_kick_t);
    res->head.msg_type = CMS_MSG_RES_IOF_KICK;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.msg_seq = cm_now();
    res->head.src_msg_seq = req_msg->msg_seq;
    if (req_msg->need_ack == GS_TRUE) {
        res->head.is_ack = GS_TRUE;
        res->head.sid = req_msg->sid;
        res->head.rsn = req_msg->rsn;
    } else {
        res->head.is_ack = GS_FALSE;
    }
    res->result = ret;
    errno_t err = strcpy_s(res->info, CMS_INFO_BUFFER_SIZE, info);
    if (err != EOK) {
        CMS_LOG_ERR("cms strcpy failed, CMS_INFO_BUFFER_SIZE %u, errno %d[%s]", CMS_INFO_BUFFER_SIZE, cm_get_os_error(),
            strerror(errno));
        cms_que_free_node(node);
        return;
    }

    cms_enque(&g_cms_inst->send_que, node);
}

void cms_proc_msg_req_iof_kick(cms_packet_head_t* msg)
{
    status_t ret = GS_SUCCESS;
    cms_msg_req_iof_kick_t* req = (cms_msg_req_iof_kick_t*)msg;

    ret = cms_iofence_kick(req->name, req->node_id);
    if (ret != GS_SUCCESS) {
        cms_reply_msg_iof_kick_res(msg, GS_ERROR, "iofence kick failed");
        return;
    }
    cms_reply_msg_iof_kick_res(msg, GS_SUCCESS, "iofence kick succ");
}

void cms_proc_msg_res_client_iof_kick(cms_packet_head_t* msg)
{
    timeval_t tv_begin;
    cantian_record_io_stat_begin(CMS_IO_RECORD_UDS_IOF_KICK_RES, &tv_begin);
    cms_cli_msg_res_iof_kick_t *res = (cms_cli_msg_res_iof_kick_t *)msg;
    if (res->result != GS_SUCCESS) {
        CMS_LOG_ERR("iof kick failed");
        return;
    }
    cms_finish_iof_kick();
    cantian_record_io_stat_end(CMS_IO_RECORD_UDS_IOF_KICK_RES, &tv_begin, IO_STAT_SUCCESS);
    CMS_LOG_DEBUG_INF("recv client iof kick response succ");
}

#ifdef DB_DEBUG_VERSION
void cms_reply_msg_res_enable_inject(cms_packet_head_t *req_msg, status_t ret)
{
    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_tool_msg_res_enable_inject_t));
    cms_tool_msg_res_enable_inject_t* res = (cms_tool_msg_res_enable_inject_t*)cms_que_node_data(node);
    res->head.dest_node = req_msg->src_node;
    res->head.src_node = req_msg->dest_node;
    res->head.msg_size = sizeof(cms_tool_msg_res_enable_inject_t);
    res->head.msg_type = CMS_TOOL_MSG_RES_ENABLE_REJECT;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.msg_seq = cm_now();
    res->head.src_msg_seq = req_msg->msg_seq;
    res->head.uds_sid = req_msg->uds_sid;
    res->result = ret;
    cms_enque(&g_cms_inst->cli_send_que, node);
}

void cms_proc_msg_req_enable_inject(cms_packet_head_t *msg)
{
    char *enable = "enable";
    cms_tool_msg_req_enable_inject_t *req = (cms_tool_msg_req_enable_inject_t *)msg;
    uint16 execution_num = req->raise_num;
    if (cms_sp_set_global_syncpoint(req->syncpoint_type, execution_num, enable) != GS_SUCCESS) {
        cms_reply_msg_res_enable_inject(msg, GS_ERROR);
        CMS_LOG_DEBUG_ERR("set global sync point failed.");
    } else {
        cms_reply_msg_res_enable_inject(msg, GS_SUCCESS);
        CMS_LOG_DEBUG_INF("recv enable inject succ, type is %s, execution num is %u.", enable, execution_num);
    }
}
#endif

void cms_proc_msg_req_get_iostat(cms_packet_head_t *msg)
{
    cms_tool_msg_req_iostat_t *req = (cms_tool_msg_req_iostat_t *)msg;
    biqueue_node_t *node = cms_que_alloc_node(sizeof(cms_tool_msg_res_iostat_t));
    cms_tool_msg_res_iostat_t *res = (cms_tool_msg_res_iostat_t *)cms_que_node_data(node);
    res->head.dest_node = msg->src_node;
    res->head.src_node = g_cms_param->node_id;
    res->head.msg_size = sizeof(cms_tool_msg_res_iostat_t);
    res->head.msg_type = CMS_TOOL_MSG_RES_GET_IOSTAT;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.msg_seq = cm_now();
    res->head.src_msg_seq = req->head.msg_seq;
    res->head.uds_sid = msg->uds_sid;
    for (uint8 i = 0; i < CMS_IO_COUNT; i++) {
        res->detail[i].back_bad = g_io_record_event_wait[i].detail.back_bad;
        res->detail[i].back_good = g_io_record_event_wait[i].detail.back_good;
        res->detail[i].total_good_time = g_io_record_event_wait[i].detail.total_good_time;
        res->detail[i].total_bad_time = g_io_record_event_wait[i].detail.total_bad_time;
        res->detail[i].max_time = g_io_record_event_wait[i].detail.max_time;
        res->detail[i].min_time = g_io_record_event_wait[i].detail.min_time;
        res->detail[i].total_time = g_io_record_event_wait[i].detail.total_time;
        res->detail[i].start = g_io_record_event_wait[i].detail.start;
    }
    res->result = GS_SUCCESS;
    cms_enque(&g_cms_inst->cli_send_que, node);
}

void cms_proc_msg_req_reset_iostat(cms_packet_head_t *msg)
{
    biqueue_node_t *node = cms_que_alloc_node(sizeof(cms_tool_msg_res_reset_iostat_t));
    cms_tool_msg_res_reset_iostat_t *res = (cms_tool_msg_res_reset_iostat_t *)cms_que_node_data(node);
    res->head.dest_node = msg->src_node;
    res->head.src_node = g_cms_param->node_id;
    res->head.msg_size = sizeof(cms_tool_msg_res_reset_iostat_t);
    res->head.msg_type = CMS_TOOL_MSG_RES_RESET_IOSTAT;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.msg_seq = cm_now();
    res->head.src_msg_seq = msg->msg_seq;
    res->head.uds_sid = msg->uds_sid;
    status_t ret = record_io_stat_reset();
    res->result = ret;
    cms_enque(&g_cms_inst->cli_send_que, node);
}

void cms_proc_msg_req_get_disk_iostat(cms_packet_head_t *msg)
{
    cms_tool_msg_req_disk_iostat_t *req = (cms_tool_msg_req_disk_iostat_t *)msg;
    biqueue_node_t *node = cms_que_alloc_node(sizeof(cms_tool_msg_res_disk_iostat_t));
    cms_tool_msg_res_disk_iostat_t *res = (cms_tool_msg_res_disk_iostat_t *)cms_que_node_data(node);
    res->head.dest_node = msg->src_node;
    res->head.src_node = g_cms_param->node_id;
    res->head.msg_size = sizeof(cms_tool_msg_res_disk_iostat_t);
    res->head.msg_type = CMS_TOOL_MSG_RES_GET_DISK_IOSTAT;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.msg_seq = cm_now();
    res->head.src_msg_seq = req->head.msg_seq;
    res->head.uds_sid = msg->uds_sid;
    res->detail.avg_ms = g_local_disk_stat.avg_ms;
    res->result = GS_SUCCESS;
    cms_enque(&g_cms_inst->cli_send_que, node);
}

status_t cms_exec_start_res(char* name, cms_msg_scope_t scope, uint16 targe_node, uint32 timeout,
    char* err_info)
{
    status_t ret = GS_SUCCESS;
    errno_t err = EOK;
    cms_msg_req_start_res_t req = {0};
    req.head.msg_type = CMS_MSG_REQ_START_RES;
    req.head.msg_size = sizeof(cms_msg_req_start_res_t);
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cm_now();
    req.head.src_msg_seq = 0;
    req.scope = scope;
    req.target_node = targe_node;
    req.timeout = timeout;
    err = strcpy_sp(req.name, CMS_NAME_BUFFER_SIZE, name);
    if (err != EOK) {
        err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "strcpy_sp name failed");
        cms_securec_check(err);
        return GS_ERROR;
    }
    if (scope == CMS_MSG_SCOPE_CLUSTER) {
        ret = cms_start_res_cluster(&req.head, err_info, CMS_INFO_BUFFER_SIZE);
    } else {
        ret = cms_start_res_node(&req.head, err_info, CMS_INFO_BUFFER_SIZE);
    }
    return ret;
}

status_t cms_exec_stop_res(char* name, cms_msg_scope_t scope, uint16 targe_node, char* err_info, uint32 err_info_len)
{
    status_t ret = GS_SUCCESS;
    errno_t err = EOK;
    cms_msg_req_stop_res_t req = {0};
    req.head.msg_type = CMS_MSG_REQ_STOP_RES;
    req.head.msg_size = sizeof(cms_msg_req_stop_res_t);
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cm_now();
    req.head.src_msg_seq = 0;
    req.scope = scope;
    req.target_node = targe_node;
    err = strcpy_sp(req.name, CMS_NAME_BUFFER_SIZE, name);
    if (err != EOK) {
        err = strcpy_s(err_info, CMS_INFO_BUFFER_SIZE, "strcpy_sp name failed");
        cms_securec_check(err);
        return GS_ERROR;
    }
    if (scope == CMS_MSG_SCOPE_CLUSTER) {
        ret = cms_stop_res_cluster(&req.head, err_info, err_info_len);
    } else {
        ret = cms_stop_res_node(&req.head, err_info, err_info_len);
    }
    return ret;
}

void cms_proc_uds_msg_req_start_res(cms_packet_head_t* msg)
{
    status_t ret = GS_SUCCESS;
    cms_tool_msg_req_start_res_t* req = (cms_tool_msg_req_start_res_t*)msg;
    CMS_LOG_INF("begin proc start res, msg type %u, msg req %llu, name %s, scope %d, target node %u", msg->msg_type,
        msg->msg_seq, req->name, req->scope, req->target_node);
    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_tool_msg_res_start_res_t));
    cms_tool_msg_res_start_res_t* res = (cms_tool_msg_res_start_res_t*)cms_que_node_data(node);
    ret = cms_exec_start_res(req->name, req->scope, req->target_node, req->timeout, res->info);
    res->head.msg_size = sizeof(cms_tool_msg_res_start_res_t);
    res->head.msg_type = CMS_TOOL_MSG_RES_START_RES;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.src_msg_seq = msg->msg_seq;
    res->head.msg_seq = cm_now();
    res->head.uds_sid = msg->uds_sid;
    res->result = ret;
    cms_enque(&g_cms_inst->cli_send_que, node);
    CMS_LOG_INF("end proc start res, ret %d, msg type %u, msg req %llu, name %s, scope %d, target node %u", ret,
        msg->msg_type, msg->msg_seq, req->name, req->scope, req->target_node);
}

void cms_proc_uds_msg_req_stop_res(cms_packet_head_t* msg)
{
    status_t ret = GS_SUCCESS;
    cms_tool_msg_req_stop_res_t* req = (cms_tool_msg_req_stop_res_t*)msg;
    CMS_LOG_INF("begin proc stop res, msg type %u, msg req %llu, name %s, scope %d, target node %u", msg->msg_type,
        msg->msg_seq, req->name, req->scope, req->target_node);
    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_tool_msg_res_stop_res_t));
    cms_tool_msg_res_stop_res_t* res = (cms_tool_msg_res_stop_res_t*)cms_que_node_data(node);
    ret = cms_exec_stop_res(req->name, req->scope, req->target_node, res->info, CMS_INFO_BUFFER_SIZE);
    res->head.msg_size = sizeof(cms_tool_msg_res_stop_res_t);
    res->head.msg_type = CMS_TOOL_MSG_RES_STOP_RES;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.src_msg_seq = msg->msg_seq;
    res->head.msg_seq = cm_now();
    res->head.uds_sid = msg->uds_sid;
    res->result = ret;
    cms_enque(&g_cms_inst->cli_send_que, node);
    CMS_LOG_INF("end proc stop res, ret %d, msg type %u, msg req %llu, name %s, scope %d, target node %u", ret,
        msg->msg_type, msg->msg_seq, req->name, req->scope, req->target_node);
}

status_t cms_exec_get_srv_stat(uint16 target_node, cms_tool_msg_res_get_srv_stat_t* tool_msg)
{
    status_t ret = GS_SUCCESS;
    if (g_cms_param->node_id == target_node) {
        tool_msg->cluster_gap = g_cms_inst->time_gap;
        tool_msg->send_que_count = g_cms_inst->send_que.count;
        tool_msg->recv_que_count = g_cms_inst->recv_que.count + g_cms_inst->cmd_recv_que.count;
        tool_msg->server_stat_ready = g_cms_inst->server_loop;
        return ret;
    }

    cms_msg_req_get_srv_stat_t req;
    req.head.msg_type = CMS_MSG_REQ_GET_SRV_STAT;
    req.head.msg_size = sizeof(cms_msg_req_get_srv_stat_t);
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cm_now();
    req.head.src_msg_seq = 0;
    cms_msg_res_get_srv_stat_t res;
    ret = cms_mes_send_cmd_to_other((cms_packet_head_t*)&req, (cms_packet_head_t*)&res, target_node);
    if (ret != GS_SUCCESS) {
        CMS_LOG_ERR("cms send get srv stat req msg to node %u err.", target_node);
        return GS_ERROR;
    }
    tool_msg->cluster_gap = res.cluster_gap;
    tool_msg->send_que_count = res.send_que_count;
    tool_msg->recv_que_count = res.recv_que_count;
    tool_msg->server_stat_ready = res.server_stat_ready;
    return GS_SUCCESS;
}

void cms_proc_uds_msg_req_get_srv_stat(cms_packet_head_t* msg)
{
    status_t ret = GS_SUCCESS;
    cms_tool_msg_req_get_srv_stat_t* req = (cms_tool_msg_req_get_srv_stat_t*)msg;
    biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_tool_msg_res_get_srv_stat_t));
    cms_tool_msg_res_get_srv_stat_t* res = (cms_tool_msg_res_get_srv_stat_t*)cms_que_node_data(node);
    ret = cms_exec_get_srv_stat(req->target_node, res);
    res->head.msg_size = sizeof(cms_tool_msg_res_get_srv_stat_t);
    res->head.msg_type = CMS_TOOL_MSG_RES_GET_SRV_STAT;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.src_msg_seq = msg->msg_seq;
    res->head.msg_seq = cm_now();
    res->head.uds_sid = msg->uds_sid;
    res->head.src_node = req->head.dest_node;
    res->head.dest_node = req->head.src_node;
    res->result = ret;
    cms_enque(&g_cms_inst->cli_send_que, node);
}

void cms_proc_uds_msg_req_vote_result(cms_packet_head_t *msg)
{
    status_t ret = GS_SUCCESS;
    cms_tool_msg_req_vote_result_t *req = (cms_tool_msg_req_vote_result_t *)msg;
    biqueue_node_t *node = cms_que_alloc_node(sizeof(cms_tool_msg_res_get_srv_stat_t));
    cms_tool_msg_res_vote_result_t *res = (cms_tool_msg_res_vote_result_t *)cms_que_node_data(node);
    res->head.msg_size = sizeof(cms_tool_msg_res_vote_result_t);
    res->head.msg_type = CMS_TOOL_MSG_RES_VOTE_RESULT;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.src_msg_seq = msg->msg_seq;
    res->head.msg_seq = cm_now();
    res->head.uds_sid = msg->uds_sid;
    res->head.src_node = req->head.dest_node;
    res->head.dest_node = req->head.src_node;
    vote_result_ctx_t* vote_result = get_current_vote_result();
    res->cluster_bitmap = vote_result->new_cluster_bitmap;
    res->cluster_is_voting = cms_cluster_is_voting();
    res->result = ret;
    cms_enque(&g_cms_inst->cli_send_que, node);
    CMS_LOG_DEBUG_INF("end proc req vote result, ret %d, msg type %u, msg req %llu", ret, msg->msg_type, msg->msg_seq);
}

void cms_proc_msg(cms_packet_head_t* msg)
{
    switch (msg->msg_type) {
        case CMS_MSG_REQ_HB:
            cms_proc_msg_req_hb(msg);
            break;
        case CMS_MSG_RES_HB:
            cms_proc_msg_res_hb(msg);
            break;
        case CMS_MSG_REQ_START_RES:
            cms_proc_msg_req_start_res(msg);
            break;
        case CMS_MSG_REQ_STOP_RES:
            cms_proc_msg_req_stop_res(msg);
            break;
        case CMS_MSG_REQ_STAT_CHG:
            cms_proc_msg_req_stat_chg(msg);
            break;
        case CMS_MSG_RES_START_RES:
        case CMS_MSG_RES_STOP_RES:
            CMS_LOG_INF("no operation, msg_type:%d", msg->msg_type);
            break;
        case CMS_MSG_REQ_GET_SRV_STAT:
            cms_proc_msg_req_get_srv_stat(msg);
            break;
        case CMS_MSG_REQ_UPDATE_LOCAL_GCC:
            cms_proc_msg_req_update_local_gcc(msg);
            break;
        case CMS_MSG_REQ_IOF_KICK:
            cms_proc_msg_req_iof_kick(msg);
            break;
        default:
            CMS_LOG_ERR("unknown msg_type:%d", msg->msg_type);
    }
}

void cms_worker_entry(thread_t* thread)
{
    char info[128];
    biqueue_node_t *node;
    date_t start_time;
    date_t end_time;
    errno_t ret;
    cms_packet_head_t *msg;

    while (!thread->closed) {
        if (thread->argument == CMS_HB_WORKER_FLAG) {
            node = cms_deque_ex(&g_cms_inst->recv_que, CMS_QUE_PRIORITY_HIGH);
        } else {
            node = cms_deque(&g_cms_inst->recv_que);
        }
        
        if (node == NULL) {
            continue;
        }

        msg = (cms_packet_head_t*)cms_que_node_data(node);
        start_time = cm_monotonic_now();
        cms_proc_msg(msg);
        end_time = cm_monotonic_now();
        ret = sprintf_s(info, sizeof(info), "end to process msg, elapsed time %lld.",
            (end_time - start_time) / MICROSECS_PER_MILLISEC);
        PRTS_RETVOID_IFERR(ret);

        if (CMS_IS_TIMER_MSG(msg->msg_type)) {
            CMS_LOG_MSG(CMS_LOG_TIMER, info, msg);
            if ((end_time - start_time) > MILLISECS_PER_SECOND) {
                CMS_LOG_MSG(CMS_LOG_DEBUG_INF, info, msg);
            }
        } else {
            CMS_LOG_MSG(CMS_LOG_DEBUG_INF, info, msg);
        }
        
        cms_que_free_node(node);
    }
}

void cmd_handle_entry(thread_t* thread)
{
    char info[PRINT_LEN];
    biqueue_node_t *node;
    errno_t ret;
    cms_packet_head_t *msg;
    date_t start_time;
    date_t end_time;

    while (!thread->closed) {
        node = cms_deque(&g_cms_inst->cmd_recv_que);
        if (node == NULL) {
            continue;
        }

        msg = (cms_packet_head_t*)cms_que_node_data(node);
        start_time = cm_monotonic_now();
        cmd_proc_msg(msg);
        end_time = cm_monotonic_now();
        ret = sprintf_s(info, PRINT_LEN, "end to process msg, elapsed time %lld.",
            (end_time - start_time) / MICROSECS_PER_MILLISEC);
        PRTS_RETVOID_IFERR(ret);

        CMS_LOG_MSG(CMS_LOG_DEBUG_INF, info, msg);
        cms_que_free_node(node);
    }
}

void cms_hb_timer_entry(thread_t* thread)
{
    while (!thread->closed) {
        uint32 node_count = cms_get_gcc_node_count();
        for (uint32 i = 0; i < node_count; i++) {
            if (i == g_cms_param->node_id || cms_node_is_invalid(i)) {
                continue;
            }

            biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_msg_req_hb_t));
            cms_msg_req_hb_t* msg = (cms_msg_req_hb_t*)cms_que_node_data(node);
            msg->head.msg_type = CMS_MSG_REQ_HB;
            msg->head.msg_size = sizeof(cms_msg_req_hb_t);
            msg->head.src_node = g_cms_param->node_id;
            msg->head.dest_node = i;
            msg->head.msg_version = CMS_MSG_VERSION;
            msg->head.msg_seq = cm_now();
            msg->head.src_msg_seq = 0;
            cms_enque_ex(&g_cms_inst->send_que, node, CMS_QUE_PRIORITY_HIGH);
            
            cms_hb_lost_handle(i);
        }

        cm_sleep(CMS_WORK_HB_SLEEP_TIME);
    }
}

void cms_stat_chg_restart_res(cms_res_t res, cms_res_stat_t stat, date_t now_time)
{
    char restart_str[32], now_str[32];
    cms_date2str(stat.restart_time, restart_str, sizeof(restart_str));
    cms_date2str(now_time, now_str, sizeof(now_str));
    CMS_LOG_DEBUG_INF("restart info:res_id=%u,cur_stat=%s,target_stat=%s, restart_count=%d, restart_time=%s, now=%s",
        res.res_id, cms_stat_str(stat.cur_stat), cms_stat_str(stat.target_stat), stat.restart_count,
        restart_str, now_str);

    if (res.script[0] != '\0' && res.restart_times != 0 && stat.cur_stat == CMS_RES_OFFLINE &&
        stat.target_stat == CMS_RES_ONLINE && (stat.restart_count == -1 || stat.restart_count > 0) &&
        (stat.restart_time != 0 &&
        (uint64)stat.restart_time + res.restart_interval * MICROSECS_PER_MILLISEC <= (uint64)now_time)) {
        CMS_LOG_INF("send restart msg, restart_count: %d", stat.restart_count);
        biqueue_node_t* node = cms_que_alloc_node(sizeof(cms_msg_req_start_res_t));
        cms_msg_req_start_res_t *msg = (cms_msg_req_start_res_t*)cms_que_node_data(node);
        msg->head.dest_node = g_cms_param->node_id;
        msg->head.src_node = g_cms_param->node_id;
        msg->head.msg_size = sizeof(cms_msg_req_start_res_t);
        msg->head.msg_type = CMS_MSG_REQ_START_RES;
        msg->head.msg_version = CMS_MSG_VERSION;
        msg->head.msg_seq = cm_now();
        msg->head.src_msg_seq = 0;
        errno_t ret = strcpy_s(msg->name, CMS_NAME_BUFFER_SIZE, res.name);
        if (ret != EOK) {
            CMS_LOG_ERR("cms strcpy failed, CMS_NAME_BUFFER_SIZE %u, errno %d[%s]", CMS_NAME_BUFFER_SIZE, cm_get_os_error(),
                strerror(errno));
            cms_que_free_node(node);
            return;
        }
        msg->scope = CMS_MSG_SCOPE_NODE;
        msg->target_node = g_cms_param->node_id;
        msg->timeout = CMS_RES_RESTART_INTERVAL;
        cms_enque(&g_cms_inst->recv_que, node);
        cms_stat_update_restart_attr(res.res_id);
    }
}

void cms_detect_osclock_abnormal(date_t now_time, date_t last_refresh_time)
{
    if (last_refresh_time < now_time) {
        if (now_time - last_refresh_time >= CMS_DETECT_OSCLOCK_ABNORMAL_THRESHOLD) {
            CMS_LOG_WAR("system time is changed(osclock becomes bigger), time difference from the previous round of "
                        "detection is %lld(ms)",
                (now_time - last_refresh_time) / CMS_MICROS_TRANS_MS);
        }
    } else {
        CMS_LOG_WAR("system time is changed(osclock becomes smaller), time difference from the previous round of "
                    "detection is %lld(ms)",
            (last_refresh_time - now_time) / CMS_MICROS_TRANS_MS);
    }
}

void cms_res_check_timer_entry(thread_t* thread)
{
    uint32 min_interval = 1000;
    uint32 max_interval = 500;
    date_t last_refresh_time = cm_now();
    cms_res_stat_t stat;

    while (!thread->closed) {
        date_t now_time;
        cms_res_t res;
        for (uint32 i = 0; i < CMS_MAX_RESOURCE_COUNT; i++) {
            if (cms_get_res_by_id(i, &res) != GS_SUCCESS) {
                continue;
            }
            min_interval = MIN(res.check_interval, min_interval);
            min_interval = MAX(max_interval, min_interval);

            get_cur_res_stat(i, &stat);
            now_time = cm_now(); // cluster time
            cms_detect_osclock_abnormal(now_time, last_refresh_time);
            last_refresh_time = now_time;
            char hb_time[32], last_check[32], now_str[32];
            cms_date2str(stat.hb_time, hb_time, sizeof(hb_time));
            cms_date2str(stat.last_check, last_check, sizeof(last_check));
            cms_date2str(now_time, now_str, sizeof(now_str));

            if (now_time > stat.hb_time + res.hb_timeout * MICROSECS_PER_MILLISEC &&
                stat.cur_stat == CMS_RES_ONLINE) {
                CMS_LOG_ERR("resource state offline, res_id %u, cur_stat %s, hb_time %s, last_check %s, now %s",
                    i, cms_stat_str(stat.cur_stat), hb_time, last_check, now_str);
                cms_res_detect_offline(i, &stat);
            }
            cms_stat_chg_restart_res(res, stat, now_time);
        }
        cm_sleep(min_interval);
    }
}

void cms_uds_proc_cli_msg(cms_packet_head_t* msg)
{
    switch (msg->msg_type) {
        case CMS_CLI_MSG_REQ_DIS_CONN:
            cms_proc_msg_req_dis_conn(msg);
            break;
        case CMS_CLI_MSG_RES_IOF_KICK:
            cms_proc_msg_res_client_iof_kick(msg);
            break;
        case CMS_CLI_MSG_REQ_SET_RES_DATA:
            cms_proc_msg_req_set_res_data(msg);
            break;
        case CMS_CLI_MSG_REQ_GET_RES_DATA:
            cms_proc_msg_req_get_res_data(msg);
            break;
        case CMS_CLI_MSG_REQ_GET_RES_STAT:
            cms_proc_msg_req_get_cluster_res_stat(msg);
            break;
        case CMS_CLI_MSG_REQ_SET_WORK_STAT:
            cms_proc_msg_req_set_work_stat(msg);
            break;
        default:
            CMS_LOG_ERR("unknown msg_type:%d", msg->msg_type);
    }
}

void cms_uds_proc_tool_edit_msg(cms_packet_head_t* msg)
{
    switch (msg->msg_type) {
        case CMS_TOOL_MSG_REQ_ADD_NODE:
            cms_proc_uds_msg_req_add_node(msg);
            break;
        case CMS_TOOL_MSG_REQ_DEL_NODE:
            cms_proc_uds_msg_req_del_node(msg);
            break;
        case CMS_TOOL_MSG_REQ_ADD_GRP:
            cms_proc_uds_msg_req_add_grp(msg);
            break;
        case CMS_TOOL_MSG_REQ_DEL_GRP:
            cms_proc_uds_msg_req_del_grp(msg);
            break;
        case CMS_TOOL_MSG_REQ_ADD_RES:
            cms_proc_uds_msg_req_add_res(msg);
            break;
        case CMS_TOOL_MSG_REQ_EDIT_RES:
            cms_proc_uds_msg_req_edit_res(msg);
            break;
        case CMS_TOOL_MSG_REQ_DEL_RES:
            cms_proc_uds_msg_req_del_res(msg);
            break;
        default:
            CMS_LOG_ERR("unknown msg_type:%d", msg->msg_type);
    }
}

void cms_uds_proc_tool_oper_msg(cms_packet_head_t* msg)
{
    switch (msg->msg_type) {
        case CMS_TOOL_MSG_REQ_GET_IOSTAT:
            cms_proc_msg_req_get_iostat(msg);
            break;
        case CMS_TOOL_MSG_REQ_RESET_IOSTAT:
            cms_proc_msg_req_reset_iostat(msg);
            break;
        case CMS_TOOL_MSG_REQ_START_RES:
            cms_proc_uds_msg_req_start_res(msg);
            break;
        case CMS_TOOL_MSG_REQ_STOP_RES:
            cms_proc_uds_msg_req_stop_res(msg);
            break;
        case CMS_TOOL_MSG_REQ_STOP_SRV:
            cms_proc_uds_msg_req_stop_srv(msg);
            break;
        case CMS_TOOL_MSG_REQ_GET_SRV_STAT:
            cms_proc_uds_msg_req_get_srv_stat(msg);
            break;
        case CMS_TOOL_MSG_REQ_VOTE_RESULT:
            cms_proc_uds_msg_req_vote_result(msg);
            break;
        case CMS_TOOL_MSG_REQ_GET_DISK_IOSTAT:
            cms_proc_msg_req_get_disk_iostat(msg);
            break;
        default:
            CMS_LOG_ERR("unknown msg_type:%d", msg->msg_type);
    }
}

void cms_uds_proc_msg(cms_packet_head_t* msg)
{
    if (msg->msg_type >= CMS_CLI_MSG_REQ_CONNECT && msg->msg_type <= CMS_CLI_MSG_RES_IOF_KICK) {
        cms_uds_proc_cli_msg(msg);
        return;
    } else if (msg->msg_type >= CMS_TOOL_MSG_REQ_ADD_NODE && msg->msg_type <= CMS_TOOL_MSG_RES_DEL_RES) {
        cms_uds_proc_tool_edit_msg(msg);
        return;
    } else if (msg->msg_type >= CMS_TOOL_MSG_REQ_GET_IOSTAT && msg->msg_type <= CMS_TOOL_MSG_RES_GET_DISK_IOSTAT) {
        cms_uds_proc_tool_oper_msg(msg);
        return;
    }

#ifdef DB_DEBUG_VERSION
    if (msg->msg_type == CMS_TOOL_MSG_REQ_ENABLE_REJECT) {
        cms_proc_msg_req_enable_inject(msg);
        return;
    }
#endif

    CMS_LOG_ERR("unknown msg_type:%d", msg->msg_type);
}

void cms_uds_hb_entry(thread_t* thread)
{
    biqueue_node_t *node;
    cms_packet_head_t* msg;
    date_t start;
    date_t end;

    CMS_LOG_INF("start uds hb entry thread");
    while (!thread->closed) {
        node = cms_deque_ex(&g_cms_inst->cli_recv_que, CMS_QUE_PRIORITY_HIGH);
        if (node == NULL) {
            continue;
        }

        msg = (cms_packet_head_t*)cms_que_node_data(node);
        CMS_LOG_DEBUG_INF("uds hb entry get hb msg to proc, msg type %u, msg seg %llu", msg->msg_type, msg->msg_seq);
        timeval_t tv_begin;
        cantian_record_io_stat_begin(CMS_IO_RECORD_UDS_CLI_HB, &tv_begin);
        start = cm_monotonic_now();
        cms_proc_msg_req_cli_hb(msg);
        end = cm_monotonic_now();
        cantian_record_io_stat_end(CMS_IO_RECORD_UDS_CLI_HB, &tv_begin, IO_STAT_SUCCESS);
        CMS_LOG_DEBUG_INF("uds hb entry proc hb msg succ, msg type %u, msg seg %llu, msg src seq %llu, "
            "msg exec time %lld", msg->msg_type, msg->msg_seq, msg->src_msg_seq,
            (end - start) / MICROSECS_PER_MILLISEC);
        cms_que_free_node(node);
    }
    CMS_LOG_INF("end uds hb entry thread");
}

void cms_uds_worker_entry(thread_t* thread)
{
    biqueue_node_t *node;
    cms_packet_head_t* msg;
    date_t start;
    date_t end;

    CMS_LOG_DEBUG_INF("start uds worker entry thread");
    while (!thread->closed) {
        node = cms_deque_ex(&g_cms_inst->cli_recv_que, CMS_QUE_PRIORITY_NORMAL);
        if (node == NULL) {
            continue;
        }

        msg = (cms_packet_head_t*)cms_que_node_data(node);
        CMS_LOG_DEBUG_INF("uds worker get msg to proc, msg type %u, msg seg %llu", msg->msg_type, msg->msg_seq);
        start = cm_monotonic_now();
        cms_uds_proc_msg(msg);
        end = cm_monotonic_now();
        CMS_LOG_DEBUG_INF("usd worker proc msg succ, msg type %u, msg seg %llu, msg src seq %llu, msg exec time %lld",
            msg->msg_type, msg->msg_seq, msg->src_msg_seq, (end - start) / MICROSECS_PER_MILLISEC);
        cms_que_free_node(node);
    }
    CMS_LOG_INF("end uds worker entry thread");
}