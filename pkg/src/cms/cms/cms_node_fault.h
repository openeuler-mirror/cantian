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
 * cms_node_fault.h
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_node_fault.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMS_NODE_FAULT_H
#define CMS_NODE_FAULT_H
#include "cm_defs.h"
#include "cms_msg_def.h"
#include "cm_date.h"
#include "cm_atomic.h"
#ifdef __cplusplus
extern "C" {
#endif
 
#define CMS_NODE_FAULT_TIMEOUT   (5000)  //ms
typedef struct {
    date_t last_time;
    atomic_t send_cnt;
    atomic_t recv_cnt;
    atomic_t last_recv;
    atomic_t lost_cnt;
} cms_hb_stat_t;

typedef struct {
    cms_hb_stat_t stat[CMS_MAX_NODE_COUNT];
} cms_hb_mgr_t;

extern cms_hb_mgr_t *g_cms_hb_manager;
void cms_hb_counter_update(cms_packet_head_t *head);
void cms_hb_lost_handle(uint32 node_id);
status_t cms_node_all_res_offline(uint32 node_id, bool32 *stat_changed);
void cms_res_offline_broadcast(uint32 offline_node);
bool32 is_node_in_cluster(uint32 node_id);
void cms_hb_lost_handle(uint32 node_id);
#ifdef __cplusplus
}
#endif
#endif

