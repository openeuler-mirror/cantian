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
    CMS_MSG_REQ_VERSION_UPGRADE,
    CMS_MSG_RES_VERSION_UPGRADE,
    CMS_MSG_REQ_DEL_NODE,
    CMS_MSG_RES_DEL_NODE,
    CMS_MSG_REQ_GET_SRV_STAT,
    CMS_MSG_RES_GET_SRV_STAT,
    CMS_MSG_REQ_UPDATE_LOCAL_GCC,
    CMS_MSG_RES_UPDATE_LOCAL_GCC,
    CMS_MSG_REQ_IOF_KICK,
    CMS_MSG_RES_IOF_KICK,
    CMS_MSG_REQ_UPGRADE_LOCAL_VERSION,
    CMS_MSG_RES_UPGRADE_LOCAL_VERSION,
    CMS_MSG_REQ_STAT_CHG,
    #ifdef DB_DEBUG_VERSION
        CMS_MSG_REQ_STAT_CHG_NEW
    #endif
}cms_msg_type_t;

#define CMS_IS_TIMER_MSG(msg_type) \
    ((msg_type) == CMS_MSG_REQ_HB                   || (msg_type) == CMS_MSG_RES_HB || \
     (msg_type) == CMS_CLI_MSG_REQ_GET_RES_STAT || (msg_type) == CMS_CLI_MSG_RES_GET_RES_STAT || \
     (msg_type) == CMS_CLI_MSG_REQ_HB            || (msg_type) == CMS_CLI_MSG_RES_HB)

#define CMS_NODES_COUNT 8
#define CMS_RESOURCE_COUNT 4

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
    CMS_MSG_SCOPE_NODE_FORCE = 3,
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
    char                    ip[CT_MAX_INST_IP_LEN];
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

typedef struct st_cms_msg_req_version_update {
    cms_packet_head_t       head;
    uint16                  main_ver;
    uint16                  major_ver;
    uint16                  revision;
    uint16                  inner;
}cms_msg_req_version_update_t;

typedef struct st_cms_msg_res_version_update {
    cms_packet_head_t       head;
    status_t                result;
    char                    info[CMS_INFO_BUFFER_SIZE];
}cms_msg_res_version_update_t;

typedef struct st_cms_msg_req_stat_chg {
    cms_packet_head_t       head;
    uint64                  version;
    uint32                  res_id;
}cms_msg_req_stat_chg_t;

#ifdef DB_DEBUG_VERSION
typedef struct st_cms_msg_req_stat_chg_new {
    cms_packet_head_t       head;
    uint64                  version;
    uint32                  res_id;
    int32                   fake_flag;
}cms_msg_req_stat_chg_new_t;
#endif

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
    CMS_TOOL_MSG_REQ_UPGRADE,
    CMS_TOOL_MSG_RES_UPGRADE,
    CMS_TOOL_MSG_REQ_VERSION,
    CMS_TOOL_MSG_RES_VERSION,
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
    CMS_TOOL_MSG_REQ_NODE_CONNECTED,
    CMS_TOOL_MSG_RES_NODE_CONNECTED,
    CMS_TOOL_MSG_REQ_GET_SRV_STAT,
    CMS_TOOL_MSG_RES_GET_SRV_STAT,
    CMS_TOOL_MSG_REQ_GET_RES_STAT,
    CMS_TOOL_MSG_RES_GET_RES_STAT,
    CMS_TOOL_MSG_REQ_GET_GCC_INFO,
    CMS_TOOL_MSG_RES_GET_GCC_INFO,
    CMS_TOOL_MSG_REQ_GET_DISK_IOSTAT,
    CMS_TOOL_MSG_RES_GET_DISK_IOSTAT,
#ifdef DB_DEBUG_VERSION
    CMS_TOOL_MSG_REQ_ENABLE_REJECT,
    CMS_TOOL_MSG_RES_ENABLE_REJECT,
#endif
    CMS_TOOL_MSG_REQ_GCC_EXPORT,
    CMS_TOOL_MSG_RES_GCC_EXPORT,
    CMS_TOOL_MSG_REQ_GCC_IMPORT,
    CMS_TOOL_MSG_RES_GCC_IMPORT,
    CMS_TOOL_MSG_REQ_NODE_LIST,
    CMS_TOOL_MSG_RES_NODE_LIST,
    CMS_TOOL_MSG_REQ_RESGRP_LIST,
    CMS_TOOL_MSG_RES_RESGRP_LIST,
    CMS_TOOL_MSG_REQ_RES_LIST,
    CMS_TOOL_MSG_RES_RES_LIST,
}cms_tool_msg_type_t;

typedef struct st_cms_tool_msg_req_add_node {
    cms_packet_head_t       head;
    uint32                  node_id;
    char                    name[CMS_NAME_BUFFER_SIZE];
    char                    ip[CT_MAX_INST_IP_LEN];
    uint32                  port;
}cms_tool_msg_req_add_node_t;

typedef struct st_cms_tool_msg_res_add_node {
    cms_packet_head_t       head;
    status_t                result;
    char                    info[CMS_INFO_BUFFER_SIZE];
}cms_tool_msg_res_add_node_t;

typedef struct st_cms_tool_msg_req_upgrade {
    cms_packet_head_t       head;
    uint16                  main_ver;
    uint16                  major_ver;
    uint16                  revision;
    uint16                  inner;
}cms_tool_msg_req_upgrade_t;

typedef struct st_cms_tool_msg_res_upgrade {
    cms_packet_head_t       head;
    status_t                result;
    char                    info[CMS_INFO_BUFFER_SIZE];
}cms_tool_msg_res_upgrade_t;

typedef struct st_cms_tool_msg_req_version {
    cms_packet_head_t       head;
}cms_tool_msg_req_version_t;

typedef struct st_cms_tool_msg_res_version {
    cms_packet_head_t       head;
    status_t                result;
    uint16                  gcc_main_ver;
    uint16                  gcc_major_ver;
    uint16                  gcc_revision;
    uint16                  gcc_inner;
    uint16                  mem_main_ver;
    uint16                  mem_major_ver;
    uint16                  mem_revision;
    uint16                  mem_inner;
    char                    info[CMS_INFO_BUFFER_SIZE];
}cms_tool_msg_res_version_t;

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

typedef struct st_cms_tool_msg_req_node_connected {
    cms_packet_head_t       head;
}cms_tool_msg_req_node_connected_t;

typedef struct st_cms_node_info_t {
    uint32                  node_id;
    char                    name[CMS_NAME_BUFFER_SIZE];
    char                    ip[CT_MAX_INST_IP_LEN];
    uint32                  port;
} cms_node_info_t;

typedef struct st_cms_tool_msg_res_node_connected {
    cms_packet_head_t       head;
    uint64                  cluster_bitmap;
    bool32                  cluster_is_voting;
    cms_node_info_t         node_info[CMS_NODES_COUNT];
    uint32                  node_count;
    char                    info[CMS_INFO_BUFFER_SIZE];
    status_t                result;
}cms_tool_msg_res_node_connected_t;

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
typedef struct st_cms_msg_res_stat {
    uint64                  session_id;
    uint64                  inst_id;
    int64                   hb_time;
    int64                   last_check;
    int64                   last_stat_change;
    cms_stat_t              pre_stat;
    cms_stat_t              cur_stat;
    cms_stat_t              target_stat;
    uint8                   work_stat;
}cms_msg_res_stat_t;

typedef struct st_cms_msg_res {
    uint64          magic;
    uint32          hb_timeout;
    uint32          res_id;
    char            name[CMS_NAME_BUFFER_SIZE];
}cms_msg_res_t;

typedef struct st_cms_msg_node_def {
    uint64          magic;
    char            name[CMS_NAME_BUFFER_SIZE];
}cms_msg_node_def_t;

typedef struct st_cms_tool_res_stat_list {
    cms_msg_res_stat_t stat_list[CMS_MAX_NODE_COUNT];
    uint8 inst_count;
    uint8 master_inst_id;
} cms_tool_res_stat_list_t;

typedef struct st_cms_tool_msg_req_get_res_stat {
    cms_packet_head_t head;
    uint32 res_id;
} cms_tool_msg_req_get_res_stat_t;

typedef struct st_cms_tool_msg_res_get_res_stat {
    cms_packet_head_t head;
    cms_tool_res_stat_list_t stat;
    status_t result;
} cms_tool_msg_res_get_res_stat_t;

typedef struct st_cms_tool_msg_req_get_gcc {
    cms_packet_head_t head;
} cms_tool_msg_req_get_gcc_t;

typedef struct st_cms_tool_msg_res_get_gcc {
    cms_packet_head_t head;
    cms_msg_res_t res_list[CMS_RESOURCE_COUNT];
    cms_msg_node_def_t node_def_list[CMS_NODES_COUNT];
    uint32 node_count;
    uint32 res_count;
    uint16 master_node_id;
    status_t result;
} cms_tool_msg_res_get_gcc_t;

typedef struct st_cms_tool_msg_req_gcc_export_t {
    cms_packet_head_t   head;
    uint16              target_node;
    char                path[CMS_MAX_PATH_LEN];
} cms_tool_msg_req_gcc_export_t;

typedef struct st_cms_tool_msg_res_gcc_export_t {
    cms_packet_head_t   head;
    status_t            result;
    char                info[CMS_INFO_BUFFER_SIZE];
} cms_tool_msg_res_gcc_export_t;

typedef struct st_cms_tool_msg_req_gcc_import_t {
    cms_packet_head_t   head;
    char                path[CMS_MAX_PATH_LEN];
} cms_tool_msg_req_gcc_import_t;

typedef struct st_cms_tool_msg_res_gcc_import_t {
    cms_packet_head_t   head;
    status_t            result;
    char                info[CMS_INFO_BUFFER_SIZE];
} cms_tool_msg_res_gcc_import_t;

typedef struct st_cms_tool_msg_req_node_list_t {
    cms_packet_head_t   head;
} cms_tool_msg_req_node_list_t;
typedef struct st_cms_tool_msg_res_node_list_t {
    cms_packet_head_t   head;
    status_t            result;
    uint32              node_count;
    cms_node_info_t     node_info[CMS_NODES_COUNT];
    char                info[CMS_INFO_BUFFER_SIZE];
} cms_tool_msg_res_node_list_t;

typedef struct st_cms_tool_msg_req_resgrp_list_t {
    cms_packet_head_t   head;
} cms_tool_msg_req_resgrp_list_t;

typedef struct st_cms_tool_msg_res_resgrp_list_t {
    cms_packet_head_t   head;
    status_t            result;
    uint32              resgrp_cnt;
    char                resgrp_name[CMS_MAX_RESOURCE_GRP_COUNT][CMS_NAME_BUFFER_SIZE];
    char                info[CMS_INFO_BUFFER_SIZE];
} cms_tool_msg_res_resgrp_list_t;

typedef struct st_cms_tool_msg_req_res_list_t {
    cms_packet_head_t   head;
} cms_tool_msg_req_res_list_t;

typedef struct st_cms_res_info_t {
    uint32              start_timeout;
    uint32              stop_timeout;
    uint32              check_timeout;
    uint32              hb_timeout;
    uint32              check_interval;
    int32               restart_times;
    uint32              restart_interval;
    char                name[CMS_NAME_BUFFER_SIZE];
    char                type[CMS_NAME_BUFFER_SIZE];
    char                grp_name[CMS_NAME_BUFFER_SIZE];
    char                script[CMS_FILE_NAME_BUFFER_SIZE];
} cms_res_info_t;
typedef struct st_cms_tool_msg_res_res_list_t {
    cms_packet_head_t   head;
    cms_res_info_t      res_info[CMS_RESOURCE_COUNT];
    uint32              res_count;
    status_t            result;
    char                info[CMS_INFO_BUFFER_SIZE];
} cms_tool_msg_res_res_list_t;

#endif
