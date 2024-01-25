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
 * cms_iofence.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_iofence.c
 *
 * -------------------------------------------------------------------------
 */
#include "cms_log_module.h"
#include "cms_iofence.h"
#include "cm_dbs_iofence.h"
#include "cm_file_iofence.h"
#include "cms_gcc.h"
#include "cm_queue.h"
#include "cms_client.h"
#include "cms_stat.h"
#include "cms_msgque.h"
#include "cms_instance.h"
#include "cms_param.h"
#include "cms_cmd_imp.h"
#include "cm_dbs_intf.h"
#include "cms_vote.h"
#include "cms_mes.h"
#include "cms_detect_error.h"
#include "cms_log.h"

bool32 g_iof_start_reg;
bool32 g_iof_start_kick;
#define IOF_REQ_TMOUT       1000
#define IOF_CHECK_INTERVAL  200
#define IOF_WAIT_LOOP_TIME  1000
#define IOF_WAIT_DBSTOR_CLI_INIT_TIMEOUT 10000000
#define IOF_RETRY_NUM       3

status_t cms_iofence_wait_reg(const char* res_name, uint32 node_id)
{
    uint32 tcount = 0;
    do {
        if (tcount > IOF_REQ_TMOUT) {
            CMS_LOG_ERR("iof reg timeount, res_name %s, node id %u", res_name, node_id);
            return CT_TIMEDOUT;
        }

        CMS_LOG_DEBUG_INF("wait for the iof reg oper to complete");
        cm_sleep(IOF_CHECK_INTERVAL);
        tcount += IOF_CHECK_INTERVAL;
    } while (g_iof_start_reg);

    return CT_SUCCESS;
}

status_t cms_iofence_wait_kick(const char* res_name, uint32 node_id)
{
    do {
        CMS_LOG_DEBUG_INF("wait for the iof kick oper to complete");
        cm_sleep(IOF_CHECK_INTERVAL);
    } while (g_iof_start_kick);

    return CT_SUCCESS;
}

status_t cms_iofence_kick(const char* res_name, uint32 node_id)
{
    status_t ret = CT_SUCCESS;
    uint32 res_id;

    ret = cms_get_res_id_by_name(res_name, &res_id);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("get res id by name failed, res_name is not found");
        return ret;
    }

    biqueue_node_t *node = cms_que_alloc_node(sizeof(cms_cli_msg_req_iof_kick_t));
    if (node == NULL) {
        CMS_LOG_ERR("cms malloc msg cms_cli_msg_req_iof_kick_t failed.");
        return CT_ERROR;
    }
    cms_cli_msg_req_iof_kick_t *req = (cms_cli_msg_req_iof_kick_t*)cms_que_node_data(node);
    req->head.dest_node = -1;
    req->head.src_node = g_cms_param->node_id;
    req->head.msg_size = sizeof(cms_cli_msg_req_iof_kick_t);
    req->head.msg_type = CMS_CLI_MSG_REQ_IOF_KICK;
    req->head.msg_version = CMS_MSG_VERSION;
    req->head.msg_seq = cm_now();
    req->node_id = node_id;
    g_iof_start_kick = CT_TRUE;
    cms_enque(&g_cms_inst->cli_send_que, node);

    ret = cms_iofence_wait_kick(res_name, node_id);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("iof wait kick finish failed, res name %s, node id %u", res_name, node_id);
        return ret;
    }

    CMS_LOG_INF("iof kick oper succ");
    return CT_SUCCESS;
}

void cms_finish_iof_kick(void)
{
    g_iof_start_kick = CT_FALSE;
    CMS_LOG_INF("iof kick oper finish");
}

static bool32 res_is_available(uint32 node_id, iofence_type_t iofence_type)
{
    vote_result_ctx_t *vote_result = get_current_vote_result();
    if (cms_bitmap64_exist(vote_result, node_id)) {
        if (iofence_type == IOFENCE_BY_DETECT_OFFLINE && g_cms_param->node_id == node_id) {
            return CT_FALSE;
        }
        return CT_TRUE;
    }
    CMS_LOG_WAR("cms node %u is not in vote_result %llu", node_id, vote_result->new_cluster_bitmap);
    return CT_FALSE;
}

status_t cms_send_msg_kick_node(cms_msg_req_iof_kick_t *req, cms_msg_res_iof_kick_t *res, iofence_type_t iofence_type)
{
    uint16 master_node = 0;
    status_t ret;
    ret = cms_get_master_node(&master_node);
    if (ret != CT_SUCCESS || master_node >= CMS_MAX_NODE_COUNT) {
        CMS_LOG_ERR("cms get master node failed, master node %d", master_node);
        return CT_ERROR;
    }

    if (res_is_available(master_node, iofence_type)) {
        if (cms_mes_send_cmd_to_other((cms_packet_head_t*)req, (cms_packet_head_t*)res, master_node) == CT_SUCCESS) {
            CMS_LOG_INF("send kick node msg to master node success, kick node id %u", req->node_id);
            return CT_SUCCESS;
        }
    }

    uint32 node_count = cms_get_gcc_node_count();
    for (uint32 i = 0; i < node_count; i++) {
        if (i != master_node && res_is_available(i, iofence_type)) {
            if (cms_mes_send_cmd_to_other((cms_packet_head_t*)req, (cms_packet_head_t*)res, i) == CT_SUCCESS) {
                CMS_LOG_INF("send kick node msg to node %u success, kick node id %u", i, req->node_id);
                return CT_SUCCESS;
            }
        }
    }
    return CT_ERROR;
}

status_t cms_kick_node_by_ns(const char* name, uint32 node_id, iofence_type_t iofence_type)
{
    iof_info_t iof = {0};
    iof.nodeid = node_id;
    iof.sn = 0;
    iof.termid = 0;
    status_t ret;
    CMS_SYNC_POINT_GLOBAL_START(CMS_IOFENCE_KICK_NODE_FAIL, &ret, CT_ERROR);
    ret = cm_dbs_iof_kick_by_ns(&iof);
    CMS_SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_WAR("dbstore iof failed, node_id : %u", node_id);
    }
    return ret;
}

status_t cms_kick_node(const char* name, uint32 node_id, iofence_type_t iofence_type)
{
    status_t ret;
    cms_msg_req_iof_kick_t req;
    cms_msg_res_iof_kick_t res;
    req.head.msg_type = CMS_MSG_REQ_IOF_KICK;
    req.head.msg_size = sizeof(cms_msg_req_iof_kick_t);
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cm_now();
    req.head.src_msg_seq = 0;
    req.node_id = node_id;
    req.sn = 0;
    ret = strcpy_sp(req.name, CMS_NAME_BUFFER_SIZE, name);
    MEMS_RETURN_IFERR(ret);

    errno_t err = memset_s(&res, sizeof(cms_msg_res_iof_kick_t), 0, sizeof(cms_msg_res_iof_kick_t));
    MEMS_RETURN_IFERR(err);

    CMS_LOG_INF("begin kick node, name %s, node id %u", name, node_id);
    ret = cms_send_msg_kick_node(&req, &res, iofence_type);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("send kick node msg failed, name %s, node_id %u", name, node_id);
        return CT_ERROR;
    }

    if (res.result != CT_SUCCESS) {
        CT_LOG_RUN_ERR("kick node msg exec failed, result info %s", res.info);
        return CT_ERROR;
    }

    CMS_LOG_INF("kick node succ, name %s, node id %u", name, node_id);
    return CT_SUCCESS;
}

void try_cms_dbs_kick_node(uint32 node_id, uint32 res_id, iofence_type_t iofence_type)
{
    date_t start_time;
    date_t now_time;
    cm_dbs_cfg_s *cfg = cm_dbs_get_cfg();
    if (!cfg->enable) {
        CT_LOG_RUN_INF("dbstore is not enabled");
        return;
    }
    if (cms_online_res_count(res_id, iofence_type) == 0) {
        CMS_LOG_INF("cluster have no online res, no need iofence");
        return;
    }

    start_time = cm_now();
    while (!g_cms_inst->is_dbstor_cli_init) {
        now_time = cm_now();
        if (now_time - start_time > IOF_WAIT_DBSTOR_CLI_INIT_TIMEOUT) {
            CMS_LOG_WAR("cms wait dbstor client init spend %lld(ms)", (now_time - start_time) / IOF_WAIT_LOOP_TIME);
        }
        cm_sleep(IOF_WAIT_LOOP_TIME);
    }
    status_t ret = CT_ERROR;
    for (int i = 0; i < IOF_RETRY_NUM; i++) {
        ret = cms_kick_node_by_ns(CMS_RES_TYPE_DB, node_id, iofence_type);
        if (ret == CT_SUCCESS) {
            CMS_LOG_INF("kick node succ, namespace %s, node_id %u", (char *)cfg->ns, node_id);
            return;
        }
        cm_sleep(IOF_CHECK_INTERVAL);
        CMS_LOG_ERR("dbstore iof failed, ret %d, namespace %s, node_id %u", ret, (char *)cfg->ns, node_id);
    }
    if (cms_daemon_stop_pull() != CT_SUCCESS) {
        CMS_LOG_ERR("stop cms daemon process failed.");
    }
    CM_ABORT_REASONABLE(0, "[CMS] ABORT INFO: cms exec iof error, please check if dbstoreclient and dbstoreserver are disconnected.");
}

void try_cms_file_kick_node(uint32 node_id, uint32 res_id, iofence_type_t iofence_type)
{
    if (cms_online_res_count(res_id, iofence_type) == 0) {
        CMS_LOG_INF("cluster have no online res, no need iofence");
        return;
    }
    status_t ret = CT_ERROR;
    for (int i = 0; i < IOF_RETRY_NUM; i++) {
        ret = cm_file_iof_kick_by_inst_id(node_id);
        if (ret == CT_SUCCESS) {
            CMS_LOG_INF("kick node succ, node_id %u", node_id);
            return;
        }
        cm_sleep(IOF_CHECK_INTERVAL);
        CMS_LOG_ERR("file iof failed, ret %d, node_id %u", ret, node_id);
    }
    if (cms_daemon_stop_pull() != CT_SUCCESS) {
        CMS_LOG_ERR("stop cms daemon process failed.");
    }
    CM_ABORT_REASONABLE(0, "[CMS] ABORT INFO: cms exec iof error.");
}

void try_cms_kick_node(uint32 node_id, uint32 res_id, iofence_type_t iofence_type)
{
    if (cm_dbs_is_enable_dbs() == CT_TRUE) {
        try_cms_dbs_kick_node(node_id, res_id, iofence_type);
    } else {
        try_cms_file_kick_node(node_id, res_id, iofence_type);
    }
}