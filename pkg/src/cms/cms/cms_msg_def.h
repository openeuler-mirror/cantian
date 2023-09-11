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
 * cms_msg_def.h
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_msg_def.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMS_MSG_DEF_H
#define CMS_MSG_DEF_H

#include "cm_types.h"
#include "cm_ip.h"
#include "cms_defs.h"
#include "cm_date.h"
#include "cms_client.h"
#include "cms_disk_lock.h"
#include "cm_defs.h"
#include "cm_io_record.h"

// Message definition of the CMS server
// server msg type
typedef enum en_cms_msg_type {
    CMS_MSG_REQ_HB = 0,
    CMS_MSG_RES_HB,
    CMS_MSG_REQ_START_RES,
    CMS_MSG_RES_START_RES,
    CMS_MSG_REQ_STOP_RES,
    CMS_MSG_RES_STOP_RES,

    CMS_MSG_REQ_ADD_RES,
    CMS_MSG_RES_ADD_RES,
    CMS_MSG_REQ_EDIT_RES,
    CMS_MSG_RES_EDIT_RES,
    CMS_MSG_REQ_DEL_RES,
    CMS_MSG_RES_DEL_RES,
    CMS_MSG_REQ_ADD_GRP,
    CMS_MSG_RES_ADD_GRP,
    CMS_MSG_REQ_DEL_GRP,
    CMS_MSG_RES_DEL_GRP,
    CMS_MSG_REQ_ADD_NODE,
    CMS_MSG_RES_ADD_NODE,
    CMS_MSG_REQ_DEL_NODE,
    CMS_MSG_RES_DEL_NODE,
    CMS_MSG_REQ_GET_SRV_STAT,
    CMS_MSG_RES_GET_SRV_STAT,
    CMS_MSG_REQ_UPDATE_LOCAL_GCC,
    CMS_MSG_REQ_IOF_KICK,
    CMS_MSG_RES_IOF_KICK,
    CMS_MSG_REQ_STAT_CHG,
}cms_msg_type_t;

#define CMS_IS_TIMER_MSG(msg_type) \
    ((msg_type) == CMS_MSG_REQ_HB                   || (msg_type) == CMS_MSG_RES_HB || \
     (msg_type) == CMS_CLI_MSG_REQ_GET_RES_STAT || (msg_type) == CMS_CLI_MSG_RES_GET_RES_STAT || \
     (msg_type) == CMS_CLI_MSG_REQ_HB            || (msg_type) == CMS_CLI_MSG_RES_HB)


typedef struct st_cms_msg_req_hb {
    cms_packet_head_t       head;
    uint32                  bsn;                //beating sequence number
    date_t                  req_send_time;
    date_t                  req_receive_time;
}cms_msg_req_hb_t;
typedef struct st_cms_msg_res_hb {
    cms_packet_head_t       head;
    uint32                  bsn;        //beating sequence number
    date_t                  req_send_time;
    date_t                  req_receive_time;
    date_t                  res_send_time;
    date_t                  res_receive_time;
}cms_msg_res_hb_t;

typedef enum en_cms_msg_scope {
    CMS_MSG_SCOPE_CLUSTER = 1,
    CMS_MSG_SCOPE_NODE = 2,
}cms_msg_scope_t;

typedef struct st_cms_msg_req_start_res {
    cms_packet_head_t       head;
    cms_msg_scope_t         scope;
    uint16                  target_node;
    char                    name[CMS_NAME_BUFFER_SIZE];
    uint32                  timeout;
}cms_msg_req_start_res_t;

typedef struct st_cms_msg_res_start_res {
    cms_packet_head_t       head;
    status_t                result;
    char                    info[CMS_INFO_BUFFER_SIZE];
}cms_msg_res_start_res_t;

typedef struct st_cms_msg_req_stop_res {
    cms_packet_head_t       head;
    cms_msg_scope_t         scope;
    uint16                  target_node;
    char                    name[CMS_NAME_BUFFER_SIZE];
}cms_msg_req_stop_res_t;

typedef struct st_cms_msg_res_stop_res {
    cms_packet_head_t       head;
    status_t                result;
    char                    info[CMS_INFO_BUFFER_SIZE];
}cms_msg_res_stop_res_t;

typedef struct st_cms_msg_req_add_res {
    cms_packet_head_t       head;
    char                    name[CMS_NAME_BUFFER_SIZE];
    char                    type[CMS_NAME_BUFFER_SIZE];
    char                    group[CMS_NAME_BUFFER_SIZE];
    char                    attrs[CMS_RES_ATTRS_BUFFER_SIZE];
}cms_msg_req_add_res_t;

typedef struct st_cms_msg_res_add_res {
    cms_packet_head_t       head;
    status_t                result;
    char                    info[CMS_INFO_BUFFER_SIZE];
}cms_msg_res_add_res_t;

typedef struct st_cms_msg_req_get_srv_stat {
    cms_packet_head_t       head;
}cms_msg_req_get_srv_stat_t;

typedef struct st_cms_msg_res_get_srv_stat {
    cms_packet_head_t       head;
    uint64                  send_que_count;
    uint64                  recv_que_count;
    date_t                  cluster_gap;
    bool32                  server_stat_ready;
}cms_msg_res_get_srv_stat_t;

typedef struct st_cms_msg_req_edit_res {
    cms_packet_head_t       head;
    char                    name[CMS_NAME_BUFFER_SIZE];
    char                    attrs[CMS_RES_ATTRS_BUFFER_SIZE];
}cms_msg_req_edit_res_t;

typedef struct st_cms_msg_res_edit_res {
    cms_packet_head_t       head;
    status_t                result;
    char                    info[CMS_INFO_BUFFER_SIZE];
}cms_msg_res_edit_res_t;

typedef struct st_cms_msg_req_del_res {
    cms_packet_head_t       head;
    char                    name[CMS_NAME_BUFFER_SIZE];
}cms_msg_req_del_res_t;

typedef struct st_cms_msg_res_del_res {
    cms_packet_head_t       head;
    status_t                result;
    char                    info[CMS_INFO_BUFFER_SIZE];
}cms_msg_res_del_res_t;

typedef struct st_cms_msg_req_add_grp {
    cms_packet_head_t       head;
    char                    group[CMS_NAME_BUFFER_SIZE];
}cms_msg_req_add_grp_t;

typedef struct st_cms_msg_res_add_grp {
    cms_packet_head_t       head;
    status_t                result;
    char                    info[CMS_INFO_BUFFER_SIZE];
}cms_msg_res_add_grp_t;

typedef struct st_cms_msg_req_del_grp {
    cms_packet_head_t       head;
    char                    group[CMS_NAME_BUFFER_SIZE];
    bool32                  force;
}cms_msg_req_del_grp_t;

typedef struct st_cms_msg_res_del_grp {
    cms_packet_head_t       head;
    status_t                result;
    char                    info[CMS_INFO_BUFFER_SIZE];
}cms_msg_res_del_grp_t;

typedef struct st_cms_msg_req_add_node {
    cms_packet_head_t       head;
    uint32                  node_id;
    char                    name[CMS_NAME_BUFFER_SIZE];
    char                    ip[CMS_IP_BUFFER_SIZE];
    uint32                  port;
}cms_msg_req_add_node_t;

typedef struct st_cms_msg_res_add_node {
    cms_packet_head_t       head;
    status_t                result;
    char                    info[CMS_INFO_BUFFER_SIZE];
}cms_msg_res_add_node_t;

typedef struct st_cms_msg_req_del_node {
    cms_packet_head_t       head;
    uint32                  node_id;
}cms_msg_req_del_node_t;

typedef struct st_cms_msg_res_del_node {
    cms_packet_head_t       head;
    status_t                result;
    char                    info[CMS_INFO_BUFFER_SIZE];
}cms_msg_res_del_node_t;

typedef struct st_cms_msg_req_update_local_gcc_t {
    cms_packet_head_t       head;
    uint8                   type; // reserved for future
}cms_msg_req_update_local_gcc_t;

typedef struct st_cms_msg_req_stat_chg {
    cms_packet_head_t       head;
    uint64                  version;
    uint32                  res_id;
}cms_msg_req_stat_chg_t;

typedef struct st_cms_msg_req_bak_gcc {
    cms_packet_head_t       head;
}cms_msg_req_bak_gcc_t;

typedef struct st_cms_msg_req_get_res_stat {
    cms_packet_head_t       head;
    uint32                  res_id;
}cms_msg_req_get_res_stat_t;

typedef struct st_cms_msg_res_get_res_stat {
    cms_packet_head_t       head;
    status_t                result;
    uint64                  session_id;
    uint64                  inst_id;
    int64                   hb_time;
    int64                   last_check;
    int64                   last_stat_change;
    cms_stat_t              pre_stat;
    cms_stat_t              cur_stat;
    cms_stat_t              target_stat;
    uint8                   work_stat;
}cms_msg_res_get_res_stat_t;

typedef struct st_cms_msg_req_iof_kick_t {
    cms_packet_head_t       head;
    uint32                  node_id;
    uint64                  sn;
    char                    name[CMS_NAME_BUFFER_SIZE];
}cms_msg_req_iof_kick_t;

typedef struct st_cms_msg_res_iof_kick_t {
    cms_packet_head_t       head;
    status_t                result;
    char                    info[CMS_INFO_BUFFER_SIZE];
}cms_msg_res_iof_kick_t;

// Message definition of the CMS tool client
// tool msg type
typedef enum en_cms_tool_msg_type {
    CMS_TOOL_MSG_REQ_ADD_NODE = 100,
    CMS_TOOL_MSG_RES_ADD_NODE,
    CMS_TOOL_MSG_REQ_DEL_NODE,
    CMS_TOOL_MSG_RES_DEL_NODE,
    CMS_TOOL_MSG_REQ_ADD_GRP,
    CMS_TOOL_MSG_RES_ADD_GRP,
    CMS_TOOL_MSG_REQ_DEL_GRP,
    CMS_TOOL_MSG_RES_DEL_GRP,
    CMS_TOOL_MSG_REQ_ADD_RES,
    CMS_TOOL_MSG_RES_ADD_RES,
    CMS_TOOL_MSG_REQ_EDIT_RES,
    CMS_TOOL_MSG_RES_EDIT_RES,
    CMS_TOOL_MSG_REQ_DEL_RES,
    CMS_TOOL_MSG_RES_DEL_RES,
    CMS_TOOL_MSG_REQ_GET_IOSTAT,
    CMS_TOOL_MSG_RES_GET_IOSTAT,
    CMS_TOOL_MSG_REQ_RESET_IOSTAT,
    CMS_TOOL_MSG_RES_RESET_IOSTAT,
    CMS_TOOL_MSG_REQ_START_RES,
    CMS_TOOL_MSG_RES_START_RES,
    CMS_TOOL_MSG_REQ_STOP_RES,
    CMS_TOOL_MSG_RES_STOP_RES,
    CMS_TOOL_MSG_REQ_STOP_SRV,
    CMS_TOOL_MSG_RES_STOP_SRV,
    CMS_TOOL_MSG_REQ_VOTE_RESULT,
    CMS_TOOL_MSG_RES_VOTE_RESULT,
    CMS_TOOL_MSG_REQ_GET_SRV_STAT,
    CMS_TOOL_MSG_RES_GET_SRV_STAT,
    CMS_TOOL_MSG_REQ_GET_DISK_IOSTAT,
    CMS_TOOL_MSG_RES_GET_DISK_IOSTAT,
#ifdef DB_DEBUG_VERSION
    CMS_TOOL_MSG_REQ_ENABLE_REJECT,
    CMS_TOOL_MSG_RES_ENABLE_REJECT,
#endif
}cms_tool_msg_type_t;

typedef struct st_cms_tool_msg_req_add_node {
    cms_packet_head_t       head;
    uint32                  node_id;
    char                    name[CMS_NAME_BUFFER_SIZE];
    char                    ip[CMS_IP_BUFFER_SIZE];
    uint32                  port;
}cms_tool_msg_req_add_node_t;

typedef struct st_cms_tool_msg_res_add_node {
    cms_packet_head_t       head;
    status_t                result;
    char                    info[CMS_INFO_BUFFER_SIZE];
}cms_tool_msg_res_add_node_t;

typedef struct st_cms_tool_msg_req_del_node {
    cms_packet_head_t       head;
    uint32                  node_id;
}cms_tool_msg_req_del_node_t;

typedef struct st_cms_tool_msg_res_del_node {
    cms_packet_head_t       head;
    status_t                result;
    char                    info[CMS_INFO_BUFFER_SIZE];
}cms_tool_msg_res_del_node_t;

typedef struct st_cms_tool_msg_req_add_grp {
    cms_packet_head_t       head;
    char                    group[CMS_NAME_BUFFER_SIZE];
}cms_tool_msg_req_add_grp_t;

typedef struct st_cms_tool_msg_res_add_grp {
    cms_packet_head_t       head;
    status_t                result;
    char                    info[CMS_INFO_BUFFER_SIZE];
}cms_tool_msg_res_add_grp_t;

typedef struct st_cms_tool_msg_req_del_grp {
    cms_packet_head_t       head;
    char                    group[CMS_NAME_BUFFER_SIZE];
    bool32                  force;
}cms_tool_msg_req_del_grp_t;

typedef struct st_cms_tool_msg_res_del_grp {
    cms_packet_head_t       head;
    status_t                result;
    char                    info[CMS_INFO_BUFFER_SIZE];
}cms_tool_msg_res_del_grp_t;

typedef struct st_cms_tool_msg_req_add_res {
    cms_packet_head_t       head;
    char                    name[CMS_NAME_BUFFER_SIZE];
    char                    type[CMS_NAME_BUFFER_SIZE];
    char                    group[CMS_NAME_BUFFER_SIZE];
    char                    attrs[CMS_RES_ATTRS_BUFFER_SIZE];
}cms_tool_msg_req_add_res_t;

typedef struct st_cms_tool_msg_res_add_res {
    cms_packet_head_t       head;
    status_t                result;
    char                    info[CMS_INFO_BUFFER_SIZE];
}cms_tool_msg_res_add_res_t;

typedef struct st_cms_tool_msg_req_edit_res {
    cms_packet_head_t       head;
    char                    name[CMS_NAME_BUFFER_SIZE];
    char                    attrs[CMS_RES_ATTRS_BUFFER_SIZE];
}cms_tool_msg_req_edit_res_t;

typedef struct st_cms_tool_msg_res_edit_res {
    cms_packet_head_t       head;
    status_t                result;
    char                    info[CMS_INFO_BUFFER_SIZE];
}cms_tool_msg_res_edit_res_t;

typedef struct st_cms_tool_msg_req_del_res {
    cms_packet_head_t       head;
    char                    name[CMS_NAME_BUFFER_SIZE];
}cms_tool_msg_req_del_res_t;

typedef struct st_cms_tool_msg_res_del_res {
    cms_packet_head_t       head;
    status_t                result;
    char                    info[CMS_INFO_BUFFER_SIZE];
}cms_tool_msg_res_del_res_t;

typedef struct st_cms_tool_msg_req_iostat_t {
    cms_packet_head_t  head;
} cms_tool_msg_req_iostat_t;

typedef struct st_cms_toll_msg_res_iostat_t {
    cms_packet_head_t  head;
    io_record_detail_t detail[CMS_IO_COUNT];
    status_t           result;
} cms_tool_msg_res_iostat_t;

typedef struct st_cms_tool_msg_req_reset_iostat_t {
    cms_packet_head_t  head;
} cms_tool_msg_req_reset_iostat_t;

typedef struct st_cms_tool_msg_res_reset_iostat_t {
    cms_packet_head_t  head;
    status_t           result;
} cms_tool_msg_res_reset_iostat_t;

typedef struct st_cms_tool_msg_req_disk_iostat_t {
    cms_packet_head_t  head;
} cms_tool_msg_req_disk_iostat_t;

typedef struct st_cms_tool_msg_res_disk_iostat_t {
    cms_packet_head_t  head;
    cms_disk_check_stat_t detail;
    status_t           result;
} cms_tool_msg_res_disk_iostat_t;

typedef struct st_cms_tool_msg_req_stop_res {
    cms_packet_head_t       head;
    cms_msg_scope_t         scope;
    uint16                  target_node;
    char                    name[CMS_NAME_BUFFER_SIZE];
}cms_tool_msg_req_stop_res_t;

typedef struct st_cms_tool_msg_res_stop_res {
    cms_packet_head_t       head;
    status_t                result;
    char                    info[CMS_INFO_BUFFER_SIZE];
}cms_tool_msg_res_stop_res_t;

typedef struct st_cms_tool_msg_req_start_res {
    cms_packet_head_t       head;
    cms_msg_scope_t         scope;
    uint16                  target_node;
    char                    name[CMS_NAME_BUFFER_SIZE];
    uint32                  timeout;
}cms_tool_msg_req_start_res_t;

typedef struct st_cms_tool_msg_res_start_res {
    cms_packet_head_t       head;
    status_t                result;
    char                    info[CMS_INFO_BUFFER_SIZE];
}cms_tool_msg_res_start_res_t;

typedef struct st_cms_tool_msg_req_stop_srv {
    cms_packet_head_t       head;
}cms_tool_msg_req_stop_srv_t;

typedef struct st_cms_tool_msg_res_stop_srv {
    cms_packet_head_t       head;
    status_t                result;
    char                    info[CMS_INFO_BUFFER_SIZE];
}cms_tool_msg_res_stop_srv_t;

typedef struct st_cms_tool_msg_req_get_srv_stat {
    cms_packet_head_t       head;
    uint16                  target_node;
}cms_tool_msg_req_get_srv_stat_t;

typedef struct st_cms_tool_msg_res_get_srv_stat {
    cms_packet_head_t       head;
    uint64                  send_que_count;
    uint64                  recv_que_count;
    date_t                  cluster_gap;
    bool32                  server_stat_ready;
    status_t                result;
}cms_tool_msg_res_get_srv_stat_t;

typedef struct st_cms_tool_msg_req_vote_result {
    cms_packet_head_t       head;
}cms_tool_msg_req_vote_result_t;

typedef struct st_cms_tool_msg_res_vote_result {
    cms_packet_head_t       head;
    uint64                  cluster_bitmap;
    bool32                  cluster_is_voting;
    status_t                result;
}cms_tool_msg_res_vote_result_t;

#ifdef DB_DEBUG_VERSION
typedef struct st_cms_tool_msg_req_enable_inject_t {
    cms_packet_head_t head;
    uint64 raise_num;
    uint32 syncpoint_type;
} cms_tool_msg_req_enable_inject_t;

typedef struct st_cms_tool_msg_res_enable_inject_t {
    cms_packet_head_t head;
    status_t result;
} cms_tool_msg_res_enable_inject_t;
#endif

#endif
