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
 * cms_client.h
 *
 *
 * IDENTIFICATION
 * src/cms/interface/cms_client.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMS_CLIENT_H
#define CMS_CLIENT_H

#include "cm_defs.h"
#include "cm_ip.h"

#define CMS_MAX_MSG_SIZE                SIZE_K(9)
#define CMS_MAX_RES_DATA_BUFFER         SIZE_K(8)
#define CMS_MAX_INFO_SIZE               64
#define CMS_UDS_PATH                    "cantian.ctd.cms.uds"
#define CMS_CLIENT_REQUEST_TIMEOUT      10000
#define CMS_CMSTOOL_REQUEST_TIMEOUT     30000
#define CMS_CLI_WORK_ENTRY_COUNT        10
#define CMS_MAX_RES_TYPE_LEN            16
#define CMS_MAX_RES_DATA_SIZE           8000
#define CMS_TOOL_INST_ID                1

// Message definition of the CMS client
// client msg type
enum cms_cli_msg_type_t {
    CMS_CLI_MSG_REQ_CONNECT = 200,  // conn: send->recv
    CMS_CLI_MSG_RES_CONNECT,
    CMS_CLI_MSG_REQ_DIS_CONN,       // dis conn: send->recv
    CMS_CLI_MSG_RES_DIS_CONN,
    CMS_CLI_MSG_RES_STAT_CHG,       // stat chg: recv
    CMS_CLI_MSG_REQ_SET_WORK_STAT,  // set work stat: send->recv
    CMS_CLI_MSG_RES_SET_WORK_STAT,
    CMS_CLI_MSG_REQ_GET_RES_STAT,   // get cluster stat: send->recv
    CMS_CLI_MSG_RES_GET_RES_STAT,
    CMS_CLI_MSG_REQ_HB,             // hb req: send
    CMS_CLI_MSG_RES_HB,             // hb res: recv
    CMS_CLI_MSG_REQ_SET_RES_DATA,   // set res stat: send->recv
    CMS_CLI_MSG_RES_SET_RES_DATA,
    CMS_CLI_MSG_REQ_GET_RES_DATA,   // get res stat: send->recv
    CMS_CLI_MSG_RES_GET_RES_DATA,
    CMS_CLI_MSG_REQ_UPGRADE,       // upgrade : send->recv
    CMS_CLI_MSG_RES_UPGRADE,
    CMS_CLI_MSG_REQ_IOF_KICK,       // iof kick: recv->send
    CMS_CLI_MSG_RES_IOF_KICK,
};

typedef enum {
    CMS_RES_UNKNOWN     = 0,
    CMS_RES_ONLINE      = 1,
    CMS_RES_OFFLINE     = 2,
    CMS_RES_STATE_COUNT = 3,
}cms_stat_t;

typedef enum {
    CMS_CLI_RES   = 0,
    CMS_CLI_TOOL  = 1,
}cms_cli_type_t;

typedef struct st_cms_uds_cli_info {
    const char* res_type;
    uint8 inst_id;
    bool32 is_retry_conn;
    cms_cli_type_t cli_type;
} cms_uds_cli_info_t;

typedef struct st_packet_head {
    uint8                       msg_type;
    uint8                       msg_version;
    uint16                      src_node;   // the resource node id of message
    uint16                      dest_node;  // the destination node id of message
    uint32                      msg_size;   // include msg header
    uint64                      msg_seq;
    uint64                      src_msg_seq;
    uint64                      uds_sid;    // uds cli msg, uds client session id
    bool32                      need_ack;   // if the req msg need ack, need_ack euqals to CT_TRUE,
                                            // or need_ack euqals to CT_FALSE
    bool32                      is_ack;     // if the msg is ack msg, is_ack euqals to CT_TRUE,
                                            // or is_ack euqals to CT_FALSE
    uint32                      sid;    // the session id of the msg
    uint32                      rsn;    // message sequence number
}cms_packet_head_t;

typedef struct st_cms_res_status_t {
    uint64 session_id;
    cms_stat_t stat;      // resource state
    uint8 inst_id;        // resource's instance id
    uint8 work_stat;      // 0: init;
    uint8 node_id;
    uint8 reserve[1];
    int64 hb_time;
    char node_ip[CM_MAX_IP_LEN];
}cms_res_status_t;

typedef struct st_cms_res_status_list_t {
    uint64 version;                    // every time members in cluster change, version increase
    cms_res_status_t inst_list[CT_MAX_INSTANCES]; // unordered list, real-inst-id can not be used as inst_list index
    uint8 inst_count;
    uint8 master_inst_id;
    uint8 reserve[2];
} cms_res_status_list_t;

typedef struct st_res_init_info {
    uint64 trigger_version;
    cms_res_status_list_t res_stat;
} res_init_info_t;

// Message definition of the CMS res client
typedef struct st_cms_cli_msg_req_conn {
    cms_packet_head_t   head;
    char                res_type[CMS_MAX_RES_TYPE_LEN];
    uint32              inst_id;
    bool32              is_retry_conn;
    cms_cli_type_t      cli_type;
}cms_cli_msg_req_conn_t;

typedef struct st_cms_cli_msg_req_set_work_stat_t {
    cms_packet_head_t   head;
    char                res_type[CMS_MAX_RES_TYPE_LEN];
    uint32              inst_id;
    uint8               work_stat;
}cms_cli_msg_req_set_work_stat_t;


typedef struct st_cms_cli_msg_res_conn {
    cms_packet_head_t       head;
    uint64                  session_id;  // uds server alloc session id for each cli
    status_t                result;
    res_init_info_t         res_init_info;
}cms_cli_msg_res_conn_t;

typedef struct st_cms_cli_msg_req_dis_conn_t {
    cms_packet_head_t       head;
    char                    res_type[CMS_MAX_RES_TYPE_LEN];
    uint32                  inst_id;
}cms_cli_msg_req_dis_conn_t;

typedef struct st_cms_cli_msg_res_dis_conn_t {
    cms_packet_head_t       head;
    status_t                result;
}cms_cli_msg_res_dis_conn_t;

typedef struct st_cms_cli_msg_res_stat_chg {
    cms_packet_head_t       head;
    cms_res_status_list_t   stat;
}cms_cli_msg_res_stat_chg_t;

typedef struct st_cms_cli_msg_req_get_res_stat_t {
    cms_packet_head_t       head;
    char                    res_type[CMS_MAX_RES_TYPE_LEN];
}cms_cli_msg_req_get_res_stat_t;

typedef struct st_cms_cli_msg_res_get_res_stat_t {
    cms_packet_head_t       head;
    cms_res_status_list_t   stat;
    status_t                result;
}cms_cli_msg_res_get_res_stat_t;

typedef struct st_cms_cli_msg_req_hb_t {
    cms_packet_head_t       head;
    char                    res_type[CMS_MAX_RES_TYPE_LEN];
}cms_cli_msg_req_hb_t;

typedef struct st_cms_cli_msg_res_hb_t {
    cms_packet_head_t       head;
    uint64                  version;
}cms_cli_msg_res_hb_t;

typedef struct st_cms_cli_msg_req_set_data_t {
    cms_packet_head_t       head;
    char                    res_type[CMS_MAX_RES_TYPE_LEN];
    uint32                  slot_id;
    uint32                  data_size;
    uint64                  old_version;
    char                    data[CMS_MAX_RES_DATA_SIZE];
}cms_cli_msg_req_set_data_t;

typedef struct st_cms_cli_msg_res_set_data_t {
    cms_packet_head_t       head;
    status_t                result;
    char                    info[CMS_MAX_INFO_SIZE];
}cms_cli_msg_res_set_data_t;

typedef struct st_cms_cli_msg_res_set_work_stat_t {
    cms_packet_head_t       head;
    status_t                result;
}cms_cli_msg_res_set_work_stat_t;

typedef struct st_cms_cli_msg_req_get_data_t {
    cms_packet_head_t       head;
    char                    res_type[CMS_MAX_RES_TYPE_LEN];
    uint32                  slot_id;
}cms_cli_msg_req_get_data_t;

typedef struct st_cms_cli_msg_res_get_data_t {
    cms_packet_head_t       head;
    status_t                result;
    uint32                  data_size;
    uint64                  version;
    char                    data[CMS_MAX_RES_DATA_SIZE];
}cms_cli_msg_res_get_data_t;

typedef struct st_cms_cli_msg_req_iof_kick_t {
    cms_packet_head_t       head;
    uint32                  node_id;
    uint64                  sn;
}cms_cli_msg_req_iof_kick_t;

typedef struct st_cms_cli_msg_res_iof_kick_t {
    cms_packet_head_t       head;
    status_t                result;
}cms_cli_msg_res_iof_kick_t;

typedef struct st_cms_cli_msg_req_upgrade_t {
    cms_packet_head_t       head;
    uint16                  main_ver;
    uint16                  major_ver;
    uint16                  revision;
    uint16                  inner;
}cms_cli_msg_req_upgrade_t;
 
typedef struct st_cms_cli_msg_res_upgrade_t {
    cms_packet_head_t       head;
    status_t                result;
}cms_cli_msg_res_upgrade_t;
#endif