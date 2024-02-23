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
 * cms_node_fault.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_node_fault.c
 *
 * -------------------------------------------------------------------------
 */
#include "cms_log_module.h"
#include "cms_node_fault.h"
#include "cms_param.h"
#include "cms_uds_server.h"
#include "cms_gcc.h"
#include "cms_instance.h"
#include "cms_stat.h"
#include "cms_comm.h"
#include "cms_vote.h"
#include "cms_log.h"

static cms_hb_mgr_t g_cms_hb_mgr = {0};

cms_hb_mgr_t *g_cms_hb_manager = &g_cms_hb_mgr;

void cms_hb_counter_update(cms_packet_head_t *head)
{
    status_t ret = CT_SUCCESS;
    CMS_SYNC_POINT_GLOBAL_START(CMS_SEND_HEARTBEAT_MESSAGE_FAIL, &ret, CT_ERROR);
    CMS_SYNC_POINT_GLOBAL_END;
    
    if (ret != CT_SUCCESS) {
        return;
    }

    uint32 node_id = head->src_node;
    if (cms_node_is_invalid(node_id)) {
        CMS_LOG_ERR_LIMIT(LOG_PRINT_INTERVAL_SECOND_20, "invalid node id, node_id=%u", node_id);
        return;
    }

    cms_hb_stat_t* stat = &g_cms_hb_mgr.stat[node_id];
    stat->last_time = cm_now();
    cm_atomic_set(&stat->lost_cnt, 0);
    cm_atomic_inc(&stat->recv_cnt);
}

void cms_res_offline_broadcast(uint32 offline_node)
{
    cms_res_t res = {0};
    CMS_LOG_INF("cms res offline node, node id %u", offline_node);
    for (uint32 res_id = 0; res_id < CMS_MAX_RESOURCE_COUNT; res_id++) {
        if (cms_get_res_by_id(res_id, &res) != CT_SUCCESS) {
            continue;
        }
        cms_stat_chg_notify_to_cms(res_id, 0);
    }
}

status_t cms_node_all_res_offline(uint32 node_id, bool32 *stat_changed)
{
    cms_res_t res;
    for (uint32 res_id = 0; res_id < CMS_MAX_RESOURCE_COUNT; res_id++) {
        if (cms_get_res_by_id(res_id, &res) != CT_SUCCESS) {
            continue;
        }

        CMS_LOG_INF("Update res[%u:%u:%s]", node_id, res_id, res.name);
        cms_res_stat_t *stat;
        bool32 is_changed = CT_FALSE;
        CMS_SYNC_POINT_GLOBAL_START(CMS_RES_OTHER_TO_OFFLINE_ABORT, NULL, 0);
        CMS_SYNC_POINT_GLOBAL_END;
        cm_thread_lock(&g_node_lock[node_id]);
        if (cms_disk_lock(&g_cms_inst->res_stat_lock[node_id][res_id], DISK_LOCK_WAIT_TIMEOUT, DISK_LOCK_WRITE) !=
            CT_SUCCESS) {
            CMS_LOG_ERR("cms_disk_lock timeout.");
            cm_thread_unlock(&g_node_lock[node_id]);
            return CT_ERROR;
        }
        if (cms_stat_read_from_disk(node_id, res_id, &stat) != CT_SUCCESS) {
            cms_disk_unlock(&g_cms_inst->res_stat_lock[node_id][res_id], DISK_LOCK_WRITE);
            CMS_LOG_ERR("cms_stat_read_from_disk failed.");
            cm_thread_unlock(&g_node_lock[node_id]);
            return CT_ERROR;
        }
        cms_stat_set(stat, CMS_RES_OFFLINE, &is_changed);
        if (cms_stat_write_to_disk(node_id, res_id, stat) != CT_SUCCESS) {
            cms_disk_unlock(&g_cms_inst->res_stat_lock[node_id][res_id], DISK_LOCK_WRITE);
            CMS_LOG_ERR("cms_stat_write_to_disk failed.");
            cm_thread_unlock(&g_node_lock[node_id]);
            return CT_ERROR;
        }
        cms_disk_unlock(&g_cms_inst->res_stat_lock[node_id][res_id], DISK_LOCK_WRITE);
        *stat_changed |= is_changed;
        cm_thread_unlock(&g_node_lock[node_id]);
    }
    CMS_SYNC_POINT_GLOBAL_START(CMS_SET_OTHER_NODE_OFFLINE_BEFORE_INCVER_ABORT, NULL, 0);
    CMS_SYNC_POINT_GLOBAL_END;
    
    if (inc_stat_version() != CT_SUCCESS) {
        CMS_LOG_ERR("cms inc stat version fialed");
        return CT_ERROR;
    }
    
    return CT_SUCCESS;
}


bool32 is_node_in_cluster(uint32 node_id)
{
    vote_result_ctx_t *vote_result = get_current_vote_result();
    if (!cms_bitmap64_exist(vote_result, node_id)) {
        return CT_FALSE;
    }
    return CT_TRUE;
}

void cms_hb_lost_handle(uint32 node_id)
{
    cms_hb_stat_t* stat = &g_cms_hb_mgr.stat[node_id];
    atomic_t send_cnt = cm_atomic_inc(&stat->send_cnt);
    atomic_t lost_cnt = cm_atomic_inc(&stat->lost_cnt);

    if (g_cms_param->split_brain == CMS_OPEN_WITHOUT_SPLIT_BRAIN) {
        bool32 is_master = CT_FALSE;
        CMS_RETRY_IF_ERR(cms_is_master(&is_master));
        if (!is_master) {
            return;
        }
    }

    if (g_cms_param->split_brain == CMS_OPEN_WITHOUT_SPLIT_BRAIN) {
        if (lost_cnt <= g_cms_param->cms_node_fault_thr || stat->recv_cnt == stat->last_recv) {
            return;
        }
    }
    
    if (g_cms_param->split_brain == CMS_OPEN_WITH_SPLIT_BRAIN) {
        if (lost_cnt <= g_cms_param->cms_node_fault_thr || !is_node_in_cluster(node_id)) {
            return;
        }
    }
 
    stat->last_recv = stat->recv_cnt;

    CMS_LOG_ERR_LIMIT(LOG_PRINT_INTERVAL_SECOND_20,
                      "Detected node:%d lost heartbeat %lld times, send:%lld, recv:%lld, last_recv:%lld",
                      node_id, lost_cnt, send_cnt, stat->recv_cnt, stat->last_recv);

    if (g_cms_param->split_brain == CMS_OPEN_WITH_SPLIT_BRAIN) {
        CMS_LOG_DEBUG_INF("Detect lost hearbeat and trigger voting");
        cms_trigger_voting();
    } else {
        bool32 stat_changed = CT_FALSE;
        if (cms_node_all_res_offline(node_id, &stat_changed) != CT_SUCCESS) {
            CMS_LOG_ERR("Update node stat fail");
            return;
        }
        if (stat_changed) {
            cms_res_offline_broadcast(node_id);
        }
    }
}
