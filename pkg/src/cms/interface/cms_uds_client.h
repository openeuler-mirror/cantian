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
 * cms_uds_client.h
 *
 *
 * IDENTIFICATION
 * src/cms/interface/cms_uds_client.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMS_UDS_CLIENT_H
#define CMS_UDS_CLIENT_H

#include "cm_defs.h"
#include "cms_client.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define CMS_CLI_SEND_MSG_HASH_SIZE  5000
#define CMS_CLI_INVALID_SESS_ID     (-1)
#define CMS_CLI_INVALID_NODE_ID     (-1)

typedef status_t(*cms_uds_cli_conn_req)(cms_packet_head_t* req, cms_packet_head_t* res, uint32 res_len);

status_t cms_uds_cli_init(uint16 node_id, const char* cms_home);
void cms_uds_cli_destory(void);
status_t cms_uds_cli_connect(cms_uds_cli_info_t* cms_uds_cli_info, res_init_info_t *res_info);
status_t cms_uds_cli_check_server_online(void);
status_t cms_uds_cli_get_server_master_id(uint64* inst_id);
void cms_uds_cli_disconnect(void);
status_t cms_uds_cli_recv(cms_packet_head_t* msg, int32 size, int32 timeout_ms);
status_t cms_uds_cli_send(cms_packet_head_t* msg, int32 timeout_ms);
status_t cms_uds_cli_request(cms_packet_head_t *req, cms_packet_head_t *res, uint32 res_size, int32 timeout_ms);
status_t cms_uds_cli_request_sync(cms_packet_head_t *req, cms_packet_head_t *res, uint32 res_size, int32 timeout_ms);
status_t cms_uds_cli_wakeup_sender(cms_packet_head_t *res);
socket_t cms_uds_cli_get_sid(void);
socket_t cms_uds_cli_get_sock(void);
uint64 cms_uds_cli_get_msg_seq(void);
void cms_uds_cli_sock_close(void);
void cms_set_recv_timeout(void);

bool32 cms_uds_cli_seq_compare(void *key1, void *key2);
status_t cms_uds_cli_save_req(cms_packet_head_t* req);
void cms_uds_cli_del_req(cms_packet_head_t* req);
status_t cms_uds_cli_wait_res(cms_packet_head_t* req, cms_packet_head_t **res, int32 timeout_ms);
#ifdef __cplusplus
}
#endif
#endif
