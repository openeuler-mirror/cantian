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
 * cms_work.h
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_work.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMS_WORK_H
#define CMS_WORK_H

#include "cm_thread.h"
#include "cms_client.h"
#include "cms_syncpoint_inject.h"
#include "cm_io_record.h"
#include "cms_msg_def.h"
#include "cms_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CMS_WORK_HB_SLEEP_TIME 1000
#define CMS_MICROS_TRANS_MS 1000
#define CMS_DETECT_OSCLOCK_ABNORMAL_THRESHOLD 5000000
#define CMS_DETECT_CLUSTER_TIME_GAP 10000000

void cms_worker_entry(thread_t* thread);
void cms_hb_timer_entry(thread_t* thread);
void cms_res_check_timer_entry(thread_t* thread);
void cmd_handle_entry(thread_t* thread);
void cms_uds_worker_entry(thread_t* thread);
void cms_uds_hb_entry(thread_t* thread);

EXTER_ATTACK void cms_uds_proc_msg(cms_packet_head_t* msg);
EXTER_ATTACK void cms_uds_proc_cli_msg(cms_packet_head_t* msg);
EXTER_ATTACK void cms_uds_proc_tool_edit_msg(cms_packet_head_t* msg);
EXTER_ATTACK void cms_uds_proc_tool_oper_msg(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_msg_req_set_work_stat(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_msg_req_get_cluster_res_stat(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_msg_req_get_res_data(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_msg_req_set_res_data(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_msg_res_client_iof_kick(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_msg_req_cli_hb(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_msg_req_dis_conn(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_uds_msg_req_add_node(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_uds_msg_req_del_node(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_uds_msg_req_add_grp(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_uds_msg_req_del_grp(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_uds_msg_req_add_res(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_uds_msg_req_edit_res(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_uds_msg_req_del_res(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_msg_req_get_iostat(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_msg_req_reset_iostat(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_uds_msg_req_start_res(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_uds_msg_req_stop_res(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_uds_msg_req_stop_srv(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_uds_msg_req_get_srv_stat(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_uds_msg_req_version(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_msg_res_client_upgrade(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_uds_msg_req_upgrade(cms_packet_head_t* msg);

EXTER_ATTACK void cms_proc_msg(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_msg_req_hb(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_msg_res_hb(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_msg_req_start_res(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_msg_req_stop_res(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_msg_req_stat_chg(cms_packet_head_t* msg);
#ifdef DB_DEBUG_VERSION
EXTER_ATTACK void cms_proc_msg_req_stat_chg_new(cms_packet_head_t* msg);
#endif
EXTER_ATTACK void cms_proc_uds_msg_req_stop_srv(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_msg_req_get_srv_stat(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_msg_req_update_local_gcc(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_msg_req_iof_kick(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_msg_req_upgrade_local_version(cms_packet_head_t* msg);

void cms_reply_msg_iof_kick_res(cms_packet_head_t *req_msg, status_t ret, const char *info);
void cms_get_error_info(char *info);
void cms_reply_msg_res_start_res_to_server(cms_packet_head_t* req_msg, status_t ret, const char* info);
void cms_reply_msg_res_stop_res_to_server(cms_packet_head_t* req_msg, status_t ret, const char* info);
status_t cms_msg_start_res_send_to_other(uint16 node_id, cms_packet_head_t* head, uint32 timeout_ms);
status_t cms_msg_stop_res_send_to_other(uint16 node_id, cms_packet_head_t* head, uint32 timeout_ms);
status_t cms_start_res_cluster(cms_packet_head_t* msg, char* err_info, uint32 err_info_len);
status_t cms_start_res_node(cms_packet_head_t* msg, char* err_info, uint32 err_info_len);
status_t cms_start_all_res(cms_packet_head_t* src_msg, char* err_info, uint32 err_info_len);
status_t cms_stop_all_res(cms_packet_head_t* msg, char* err_info, uint32 err_info_len);
status_t cms_stop_res_cluster(cms_packet_head_t* msg, char* err_info, uint32 err_info_len);
status_t cms_stop_res_node(cms_packet_head_t* msg, char* err_info, uint32 err_info_len);
void cms_proc_msg_req_get_iostat(cms_packet_head_t *msg);
void cms_proc_msg_req_reset_iostat(cms_packet_head_t *msg);
void cms_proc_msg_req_get_disk_iostat(cms_packet_head_t *msg);
void cms_proc_msg_req_start_res_common(cms_packet_head_t* msg, status_t (*res_action_fp)(uint32, uint32),
    uint8 res_msg_type);
void cms_proc_uds_msg_req_stop_res(cms_packet_head_t* msg);
void cms_detect_osclock_abnormal(date_t now_time, date_t last_refresh_time);
status_t cms_exec_add_node(cms_packet_head_t* msg, char* info, uint32 info_len);
status_t cms_exec_del_node(cms_packet_head_t* msg, char* info, uint32 info_len);
status_t cms_exec_add_grp(cms_packet_head_t* msg, char* info, uint32 info_len);
status_t cms_exec_del_grp(cms_packet_head_t* msg, char* info, uint32 info_len);
status_t cms_exec_add_res(cms_packet_head_t* msg, char* info, uint32 info_len);
status_t cms_exec_edit_res(cms_packet_head_t* msg, char* info, uint32 info_len);
status_t cms_exec_del_res(cms_packet_head_t* msg, char* info, uint32 info_len);

status_t cms_add_node_on_master(cms_packet_head_t* msg, char* err_info);
status_t cms_del_node_on_master(cms_packet_head_t* msg, char* err_info);
status_t cms_add_grp_on_master(cms_packet_head_t* msg, char* err_info);
status_t cms_del_grp_on_master(cms_packet_head_t* msg, char* err_info);
status_t cms_add_res_on_master(cms_packet_head_t* msg, char* err_info);
status_t cms_edit_res_on_master(cms_packet_head_t* msg, char* err_info);
status_t cms_del_res_on_master(cms_packet_head_t* msg, char* err_info);

void cms_reply_msg_res_add_res(cms_packet_head_t* msg, status_t result, char* err_info, uint32 err_info_len);
void cms_reply_msg_res_edit_res(cms_packet_head_t* msg, status_t result, char* err_info, uint32 err_info_len);
void cms_reply_msg_res_del_res(cms_packet_head_t* msg, status_t result, char* err_info, uint32 err_len);
void cms_reply_msg_add_grp_res(cms_packet_head_t* msg, status_t result, char* err_info, uint32 err_len);
void cms_reply_msg_del_grp_res(cms_packet_head_t* msg, status_t result, char* err_info, uint32 err_len);
void cms_reply_msg_add_node_res(cms_packet_head_t* msg, status_t result, char* err_info, uint32 err_len);
void cms_reply_msg_del_node_res(cms_packet_head_t* msg, status_t result, char* err_info, uint32 err_len);

status_t cms_init_add_node_req_to_master(cms_tool_msg_req_add_node_t* tool_req, cms_msg_req_add_node_t* req,
    char* err_info);
status_t cms_init_add_grp_req_to_master(cms_tool_msg_req_add_grp_t* tool_req, cms_msg_req_add_grp_t* req,
    char* err_info);
status_t cms_init_del_grp_req_to_master(cms_tool_msg_req_del_grp_t* tool_req, cms_msg_req_del_grp_t* req,
    char* err_info);
status_t cms_init_add_grp_req_to_master(cms_tool_msg_req_add_grp_t* tool_req, cms_msg_req_add_grp_t* req,
    char* err_info);
status_t cms_init_edit_res_req_to_master(cms_tool_msg_req_edit_res_t* tool_req, cms_msg_req_edit_res_t* req,
    char* err_info);
status_t cms_init_del_res_req_to_master(cms_tool_msg_req_del_res_t* tool_req, cms_msg_req_del_res_t* req,
    char* err_info);

status_t cms_exec_stop_res(char* name, cms_msg_scope_t scope, uint16 targe_node, char* err_info, uint32 err_info_len);
status_t cms_exec_start_res(char* name, cms_msg_scope_t scope, uint16 targe_node, uint32 timeout,
    char* err_info);
void cms_broadcast_update_local_gcc(void);
EXTER_ATTACK void cmd_proc_msg(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_msg_req_add_res(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_msg_req_edit_res(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_msg_req_del_node(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_msg_req_del_res(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_msg_req_add_grp(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_msg_req_del_grp(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_msg_req_add_node(cms_packet_head_t* msg);
EXTER_ATTACK void cms_proc_msg_req_version_upgrade(cms_packet_head_t* msg);

#ifdef DB_DEBUG_VERSION
void cms_proc_msg_req_enable_inject(cms_packet_head_t *msg);
void cms_reply_msg_res_enable_inject(cms_packet_head_t *req_msg, status_t ret);
#endif

bool32 cms_dbversion_cmp(const upgrade_version_t *cms_version, const cms_gcc_t* gcc_version);
status_t cms_exec_upgrade_version(cms_packet_head_t* msg, char* info, uint32 info_len);
status_t cms_exec_upgrade_version_on_master(cms_packet_head_t* msg, char* err_info);

#ifdef __cplusplus
}
#endif
#endif
