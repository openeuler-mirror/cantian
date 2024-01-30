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
 * cms_uds_server.h
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_uds_server.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMS_UDS_SERVER_H
#define CMS_UDS_SERVER_H

#include "cm_thread.h"
#include "cms_msg_def.h"
#include "cms_stat.h"
#include "cs_ipc.h"
#include "cs_tcp.h"
#include "cm_ip.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CMS_SRV_ACCEPT_TMOUT 1000
#define CMS_SRV_RECV_TMOUT 1000
#define CMS_SRV_SEND_TMOUT 1000
#define CMS_SRV_POOL_TMOUT 1000
#define CMS_SRV_POOL_TMOUT_RETRY 2
#define CMS_SRV_RECV_SLEEP 200

#define CMS_SRV_SEND_MSG_HASH_SIZE  5000

void cms_uds_srv_listen_entry(thread_t* thread);
void cms_uds_srv_recv_entry(thread_t* thread);
void cms_uds_srv_send_entry(thread_t* thread);

status_t cms_uds_srv_init(void);
status_t cms_uds_srv_accept_conn(socket_t* sock, cms_cli_msg_req_conn_t* req, cms_cli_msg_res_conn_t* res);
status_t cms_uds_srv_recv_msg(socket_t sock, char* msg_buf, uint32 msg_len, bool32 is_retry_conn);
status_t cms_uds_srv_send_proc(void);
status_t cms_uds_srv_recv_proc(void);
status_t cms_uds_srv_disconn(socket_t sock, cms_res_session_t* res_sessions, uint32 sessions_count);
void cms_uds_srv_proc_pevents(struct pollfd *pfd, cms_cli_type_t *type, uint32 count, cms_res_session_t *res_sessions,
    uint32 sessions_count, bool32 timeout);
status_t cms_uds_srv_request(cms_packet_head_t *req, cms_packet_head_t *res, uint32 res_size, int32 timeout_ms);
status_t cms_uds_srv_wakeup_sender(cms_packet_head_t *res);

bool32 cms_uds_srv_seq_compare(void *key1, void *key2);
status_t cms_uds_srv_save_req(cms_packet_head_t* req);
void cms_uds_srv_del_req(cms_packet_head_t* req);
status_t cms_uds_srv_wait_res(cms_packet_head_t* req, cms_packet_head_t **res, int32 timeout_ms);

#ifdef __cplusplus
}
#endif
#endif
