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
 * dtc_context.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_context.c
 *
 * -------------------------------------------------------------------------
 */
#include "dtc_context.h"
#include "mes_func.h"
#include "mes_config.h"
#include "dtc_drc.h"
#include "knl_context.h"
#include "dtc_dmon.h"
#include "dtc_context.h"
#include "dtc_dcs.h"
#include "dtc_dls.h"
#include "dtc_tran.h"
#include "dtc_backup.h"
#include "dtc_ckpt.h"
#include "dtc_log.h"
#include "dtc_view.h"
#include "dtc_btree.h"
#include "dtc_dc.h"
#include "dtc_reform.h"
#include "dtc_smon.h"
#include "dtc_ddl.h"
#include "tse_ddl_broadcast.h"
#include "cm_io_record.h"
#define DTC_BUFFER_POOL_NUM      (4)
#define DTC_MSG_BUFFER_QUEUE_NUM (8)
#define DTC_FIRST_BUFFER_LENGTH  (64)
#define DTC_SECOND_BUFFER_LENGTH (128)
#define DTC_THIRD_BUFFER_LENGTH  MES_MESSAGE_BUFFER_SIZE
#define DTC_FOURTH_BUFFER_LENGTH MES_128K_MESSAGE_BUFFER_SIZE
#define DTC_FIRST_BUFFER_MULTIPLE   (256)
#define DTC_SECOND_BUFFER_MULTIPLE  (128)
#define DTC_FOURTH_BUFFER_MULTIPLE  (0.125)

static dtc_instance_t g_dtc_instance;
dtc_instance_t *g_dtc = &g_dtc_instance;
dtc_processor_t g_processors[MES_CMD_CEIL] = {0};

// add function
status_t dtc_register_proc_func(mes_command_t command_type, dtc_message_proc_t proc, bool32 is_enqueue, const char *func_name)
{
    errno_t ret;

    if (command_type >= MES_CMD_CEIL) {
        GS_THROW_ERROR_EX(ERR_MES_INVALID_CMD, "register mes command type(%d) is invalid.", command_type);
        return GS_ERROR;
    }

    g_processors[command_type].proc = proc;
    g_processors[command_type].is_enqueue = is_enqueue;
    ret = strncpy_s(g_processors[command_type].name, GS_MAX_NAME_LEN, func_name, strlen(func_name));
    if (ret != EOK) {
        GS_THROW_ERROR_EX(ERR_MES_INVALID_CMD, "register func name (%s) is invalid.", func_name);
        return GS_ERROR;
    }

    //TODO info log

    return GS_SUCCESS;
}

void dtc_process_message(uint32 work_idx, mes_message_t *msg)
{
    dtc_processor_t *processor = &g_processors[msg->head->cmd];
    knl_session_t *session = g_dtc->session_pool.kernel_sessions[work_idx];

    if (processor->proc == NULL) {
        GS_LOG_RUN_ERR("The processing function of this message is NULL, cmd=%u", msg->head->cmd);
        return;
    }

    processor->proc(session, msg);

    return;
}

void dtc_proc_syncpoint_msg(void *session, mes_message_t *msg)
{
    CM_EXIT_WITH_LOG(GS_FALSE, "syncpoint match exit!");
}

status_t dtc_register_proc(void)
{
    knl_securec_check(dtc_register_proc_func(MES_CMD_CONNECT, NULL, GS_TRUE, "connect"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_MSG_ACK, mes_process_msg_ack, GS_FALSE, "msg ack"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_BROADCAST_ACK, mes_process_broadcast_ack, GS_FALSE, "broadcast ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_PAGE_ACK, mes_process_msg_ack, GS_FALSE, "page ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_INVLDT_REQ, dcs_process_invld_req, GS_TRUE, "invalidate req"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_INVLDT_ACK, mes_process_msg_ack, GS_FALSE, "invalidate ack"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_ASK_MASTER, dcs_process_ask_master_for_page, GS_TRUE, "ask master"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_TRY_ASK_MASTER, dcs_process_try_ask_master_for_page, GS_TRUE, "try ask master"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_TRY_ASK_MASTER_ACK, mes_process_msg_ack, GS_FALSE, "try ask master ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_ASK_OWNER, dcs_process_ask_owner_for_page, GS_TRUE, "ask owner"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_PAGE_READY, mes_process_msg_ack, GS_FALSE, "owner ack page ready"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_MASTER_ACK_NEED_LOAD, mes_process_msg_ack, GS_FALSE, "master ack need load"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_MASTER_ACK_ALREADY_OWNER, mes_process_msg_ack, GS_FALSE,
                                             "master ack requester already owner"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_MASTER_ACK_OWNER, mes_process_msg_ack, GS_FALSE,
                                             "master ack requester other owner"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_CLAIM_OWNER_REQ, dcs_process_claim_ownership_req, GS_TRUE,
                                             "claim ownership req"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_RECYCLE_OWNER_REQ, dcs_process_recycle_owner, GS_TRUE, "recycle owner req"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_NOTIFY_MASTER_CLEAN_EDP_REQ,
                                             dcs_process_notify_master_clean_edp_req, GS_TRUE, "notify clean edp req"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_NOTIFY_CLEAN_EDP_ACK, mes_process_msg_ack, GS_FALSE, "notify clean edp ack"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_CLEAN_EDP_REQ, dcs_process_clean_edp_req, GS_TRUE, "clean edp req"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_EDPINFO_REQ, dcs_process_edpinfo_req, GS_TRUE, "edp info req"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_EDPINFO_ACK, mes_process_msg_ack, GS_FALSE, "edp info req"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_REQUEST_LOCK, dls_process_lock_msg, GS_TRUE, "process dls lock msg"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_TRY_REQUEST_LOCK, dls_process_lock_msg, GS_TRUE, "process try dls lock msg"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_RELEASE_LOCK, dls_process_lock_msg, GS_TRUE, "process dls release lock msg"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_TRY_RELEASE_LOCK, dls_process_lock_msg, GS_TRUE,
                                             "process try dls release lock msg"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_CLAIM_LOCK, dls_process_lock_msg, GS_TRUE, "process dls claim lock msg"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_CANCLE_LOCK, dls_process_lock_msg, GS_TRUE, "process dls cancle lock msg"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_LOCK_ACK, mes_process_msg_ack, GS_FALSE, "process dls lock msg ack"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_REQUEST_LATCH_S, dls_process_lock_msg, GS_TRUE, "process dls latch_s msg"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_REQUEST_LATCH_X, dls_process_lock_msg, GS_TRUE, "process dls latch_x msg"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_WAIT_TXN, dls_process_txn_msg, GS_TRUE, "process dls txn wait msg"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_AWAKE_TXN, dls_process_txn_msg, GS_TRUE, "process dls txn awake msg"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_TXN_ACK, mes_process_msg_ack, GS_FALSE, "process dls txn ack msg"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_SCN_REQ, dtc_process_scn_req, GS_TRUE, "SCN request"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_SCN_BROADCAST, dtc_process_scn_broadcast, GS_FALSE, "SCN broadcast"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_LSN_BROADCAST, dtc_process_lsn_broadcast, GS_TRUE, "LSN broadcast"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_TXN_INFO_REQ, dtc_process_txn_info_req, GS_TRUE, "TXN info request"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_TXN_INFO_ACK, mes_process_msg_ack, GS_FALSE, "TXN info ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_TXN_SNAPSHOT_REQ, dtc_process_txn_snapshot_req, GS_TRUE,
                                             "TXN snapshot request"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_TXN_SNAPSHOT_ACK, mes_process_msg_ack, GS_FALSE, "TXN snapshot ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_TXN_WAIT, mes_process_msg_ack, GS_FALSE, "TXN wait"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_PCR_REQ_MASTER, dcs_process_pcr_req_master, GS_TRUE, "PCR request master"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_PCR_REQ_OWNER, dcs_process_pcr_req_owner, GS_TRUE, "PCR request owner"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_PCR_REQ, dcs_process_pcr_request, GS_TRUE, "PCR request"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_PCR_ACK, mes_process_msg_ack, GS_FALSE, "PCR ack"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_CHECK_VISIBLE, dcs_process_check_visible, GS_TRUE, "row check visible"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_CHECK_VISIBLE_ACK, mes_process_msg_ack, GS_FALSE, "row check visible ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_ERROR_MSG, mes_process_msg_ack, GS_FALSE, "error msg"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_GET_VIEW_INFO_REQ, dtc_view_process_get_view_info, GS_TRUE,
                                             "process dtc view msg"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_DDL_BROADCAST, dcs_process_ddl_broadcast, GS_TRUE, "ddl broadcast"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_DDL_BROADCAST_ACK, mes_process_broadcast_ack, GS_FALSE, "ddl broadcast ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_BLOCK_FILE, bak_process_block_file, GS_TRUE, "bak block file"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_UNBLOCK_FILE, bak_process_unblock_file, GS_TRUE, "bak unblock file"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_CKPT_TRIGGER, dtc_process_ckpt_trigger, GS_TRUE, "dtc ckpt trigger"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_CKPT_TRIGGER_ACK, mes_process_msg_ack, GS_FALSE, "dtc ckpt trigger ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_LOG_SWITCH, dtc_process_log_switch, GS_TRUE, "dtc log switch"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_LOG_SWITCH_SUCCESS, mes_process_msg_ack, GS_FALSE,
                                             "dtc log switch success ack"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_LOG_SWITCH_FAIL, mes_process_msg_ack, GS_FALSE, "dtc log switch fail ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_CREATE_OBJ_NAME_BROADCAST_ACK, mes_process_msg_ack, GS_FALSE,
                                             "ddl create obj name broadcast ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_GET_LOG_CURR_ASN, dtc_process_get_log_curr_asn, GS_TRUE,
                                             "dtc get log curr asn"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_GET_LOG_CURR_ASN_ACK, mes_process_msg_ack, GS_FALSE,
                                             "dtc get log curr asn ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_GET_LOG_ASN_BY_LSN, dtc_process_get_log_asn_by_lsn,
                                             GS_TRUE, "dtc get log asn"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_GET_LOG_ASN_BY_LSN_ACK, mes_process_msg_ack,
                                             GS_FALSE, "dtc get log asn ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_GET_LOG_CURR_SIZE, dtc_process_get_log_curr_size, GS_TRUE,
                                             "dtc get log curr size"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_GET_LOG_CURR_SIZE_ACK, mes_process_msg_ack, GS_FALSE,
                                             "dtc get log curr size ack"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_SET_LOG_CTRL, dtc_bak_process_set_log_ctrl, GS_TRUE, "dtc set log ctrl"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_SET_LOG_CTRL_ACK, mes_process_msg_ack, GS_FALSE, "dtc set log ctrl ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_BAK_PRECHECK, bak_process_precheck, GS_TRUE, "dtc bak precheck"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_BAK_PRECHECK_ACK, mes_process_msg_ack, GS_FALSE, "dtc bak prechecke ack"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_UNLATCH_LOGFILE, dtc_process_unlatch_logfile, GS_TRUE, "dtc unlatch logfile"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_UNLATCH_LOGFILE_ACK, mes_process_msg_ack, GS_FALSE, "dtc unlatch logfile ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_SET_LOG_LSN, dtc_process_set_lsn, GS_TRUE, "dtc set lsn"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_SET_LOG_LSN_ACK, mes_process_msg_ack, GS_FALSE, "dtc set lsn ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_BAK_GET_CTRL, dtc_process_bak_get_ctrl, GS_TRUE, "dtc get ctrl"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_BAK_GET_CTRL_ACK, mes_process_msg_ack, GS_FALSE, "dtc get ctrl ack"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_BTREE_ROOT_PAGE, dtc_btree_process_root_page, GS_TRUE, "btree root page"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_BROADCAST_DATA, dtc_process_broadcast_data, GS_TRUE, "broadcast data"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_BROADCAST_DATA_ACK, mes_process_msg_ack, GS_FALSE, "broadcast data ack"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_BROADCAST_USER, dtc_process_broadcast_data, GS_TRUE, "broadcast user"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_CLAIM_OWNER_ACK, mes_process_msg_ack, GS_FALSE, "claim ownership ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_DTC_VIEW_INFO_REQ, dtc_view_process_get_view_info, GS_TRUE,
                                             "process dtc view msg"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_DTC_VIEW_CONVERTING_PAGE_CNT_ACK, mes_process_msg_ack, GS_FALSE,
                                             "dtc_view ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_DTC_VIEW_INFO_ACK, mes_process_msg_ack, GS_FALSE, "dtc view ack"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_RELEASE_OWNER_ACK, mes_process_msg_ack, GS_FALSE, "release owner ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_DTC_VIEW_BUFFER_CTRL_REQ, dtc_view_process_get_buffer_ctrl_info,
                                             GS_FALSE, "process get buffer ctrl msg"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_DTC_VIEW_BUFFER_CTRL_ACK, mes_process_msg_ack, GS_FALSE, "buffer_ctrl msg ack"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_JOIN_CLUSTER_DONE, NULL, GS_FALSE, "notify join member reform done"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_LEAVE_CLUSTER_DONE, NULL, GS_FALSE, "notify leave member reform done"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_NOTIFY_REMASTER_STATUS, drc_process_remaster_status_notify,
                                             GS_FALSE, "drc notify remaster status"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_DRC_REMASTER_TASK, drc_accept_remaster_task, GS_TRUE,
                                             "drc accept the remaster task from master"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_ACCEPT_REMASTER_TASK_ACK, mes_process_msg_ack, GS_FALSE,
                                             "drc accept the remaster task ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_DRC_REMASTER_TASK_ACK, drc_process_remaster_task_ack, GS_FALSE,
                                             "ask master to complete one remaster task"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_MGRT_MASTER_DATA, drc_process_mgrt_data, GS_FALSE,
                                             "drc process the migrated data"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_SEND_RCY_SET, dtc_process_rcy_set, GS_TRUE,
                                             "dtc process recovery set"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_BROADCAST_TARGET_PART, drc_accept_target_part, GS_TRUE,
                                             "drc accept the target partition and switch"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_BROADCAST_REMASTER_DONE, drc_accept_remaster_done, GS_TRUE,
                                             "drc broadcast remaster done"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_MGRT_MASTER_DATA_ACK, mes_process_msg_ack, GS_FALSE, "migrate data msg ack"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_DEAD_LOCK_SID, dtc_smon_process_get_sid, GS_TRUE, "smon get remote sid"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_DEAD_LOCK_SID_ACK, mes_process_msg_ack, GS_FALSE, "smon get remote sid ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_DEAD_LOCK_TXN, dtc_smon_process_txn_dlock, GS_TRUE,
                                             "smon get remote dead lock txn"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_DEAD_LOCK_TXN_ACK, mes_process_msg_ack, GS_FALSE,
                                             "smon get remote dead lock txn ack"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_DEAD_LOCK_ROWID, dtc_smon_process_get_wrid, GS_TRUE, "smon get remote row id"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_DEAD_LOCK_ROWID_ACK, mes_process_msg_ack, GS_FALSE,
                                             "smon get remote row id ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_DEAD_LOCK_CHECK_TABLE, dtc_smon_process_check_tlock_msg, GS_TRUE,
                                             "smon check table lock"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_DEAD_LOCK_CHECK_TABLE_ACK, mes_process_msg_ack, GS_FALSE,
                                             "smon check table lock ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_DEAD_LOCK_WAIT_TABLES, dtc_smon_process_wait_tlocks_msg, GS_TRUE,
                                             "smon get table lock"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_DEAD_LOCK_WAIT_SHARED_TABLES, dtc_smon_process_wait_tlocks_msg,
                                             GS_TRUE, "smon get wait table shared locks"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_DEAD_LOCK_GET_TABLE, dtc_smon_process_wait_tlock_msg, GS_TRUE,
                                             "smon get wait table shared locks"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_DEAD_LOCK_TABLES_ACK, mes_process_msg_ack, GS_FALSE,
                                             "smon get wait table locks ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_DEAD_LOCK_WAIT_RM, dtc_smon_process_get_tlock_msg, GS_TRUE,
                                             "smon get one table lock"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_DEAD_LOCK_GET_RM, dtc_smon_process_get_tlock_msg, GS_TRUE,
                                             "smon get one table lock by itl"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_DEAD_LOCK_TABLE_ACK, mes_process_msg_ack, GS_FALSE,
                                             "smon get one table lock ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_DEAD_LOCK_WAIT_EVENT, dtc_smon_process_wait_event_msg, GS_TRUE,
                                             "smon get session wait table"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_DEAD_LOCK_WAIT_EVENT_ACK, mes_process_msg_ack, GS_FALSE,
                                             "smon get session wait table ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_DEAD_LOCK_GET_ITL, dtc_smon_process_get_ilock_msg, GS_TRUE,
                                             "smon get one itl lock"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_DEAD_LOCK_GET_ITL_ACK, mes_process_msg_ack, GS_FALSE,
                                             "smon get one itl lock ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_DEAD_LOCK_CHECK_ITL, dtc_smon_process_check_se_msg, GS_TRUE,
                                             "smon get itl session status"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_DEAD_LOCK_CHECK_ITL_ACK, mes_process_msg_ack, GS_FALSE,
                                             "smon get itl session status ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_DEAD_LOCK_SQL, dtc_smon_process_deadlock_sql, GS_TRUE,
                                             "smon get sql statement"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_DEAD_LOCK_SQL_ACK, mes_process_msg_ack, GS_FALSE, "smon get sql statement ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_CHECK_DDL_ENABLED, dtc_process_check_ddl_enabled, GS_TRUE,
                                             "ddl check ddl enabled"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_CHECK_DDL_ENABLED_ACK, mes_process_broadcast_ack, GS_FALSE,
                                             "ddl check ddl enabled ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_CKPT_EDP_BROADCAST_TO_MASTER,
                                             dcs_process_ckpt_edp_broadcast_to_master_req, GS_TRUE,
                                             "broadcast ckpt edp broadcast to master"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_CKPT_EDP_BROADCAST_TO_OWNER,
                                             dcs_process_ckpt_edp_broadcast_to_owner_req, GS_TRUE,
                                             "broadcast ckpt edp broadcast to owner"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_GDV_PREP_AND_EXEC_ACK, mes_process_msg_ack, GS_FALSE, "get stmt id for gdv"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_GDV_FETCH_ROW_ACK, mes_process_msg_ack, GS_FALSE, "gdv fetch row ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_CKPT_REQ, dcs_process_ckpt_request, GS_TRUE, "ckpt req"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_BAK_RUNNING, dtc_process_running, GS_TRUE, "check bak running"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_BAK_RUNNING_ACK, mes_process_msg_ack, GS_FALSE, "check bak running ack"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_SEND_PAGE_INFO, drc_process_send_page_info, GS_TRUE, "send page info"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_SEND_PAGE_INFO_ACK, drc_process_remaster_recovery_task_ack,
                                             GS_FALSE, "send page info ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_PREPARE_DDL_REQ, dtc_proc_msg_tse_lock_table_req, GS_TRUE,
    "MES_CMD_PREPARE_DDL_REQ")); knl_securec_check(dtc_register_proc_func(MES_CMD_PREPARE_DDL_RSP,
    tse_process_broadcast_ack_ex, GS_FALSE, "MES_CMD_PREPARE_DDL_RSP"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_EXECUTE_DDL_REQ, dtc_proc_msg_tse_execute_ddl_req, GS_TRUE,
    "MES_CMD_EXECUTE_DDL_REQ")); knl_securec_check(dtc_register_proc_func(MES_CMD_EXECUTE_DDL_RSP,
    tse_process_broadcast_ack_ex, GS_FALSE, "MES_CMD_EXECUTE_DDL_RSP"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_REWRITE_OPEN_CONN_REQ,
    dtc_proc_msg_tse_execute_rewrite_open_conn_req, GS_TRUE, "MES_CMD_REWRITE_OPEN_CONN_REQ"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_REWRITE_OPEN_CONN_RSP, tse_process_broadcast_ack_ex, GS_FALSE,
    "MES_CMD_REWRITE_OPEN_CONN_RSP"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_COMMIT_DDL_REQ, dtc_proc_msg_tse_commit_ddl_req, GS_TRUE,
    "MES_CMD_COMMIT_DDL_REQ")); knl_securec_check(dtc_register_proc_func(MES_CMD_COMMIT_DDL_RSP,
    tse_process_broadcast_ack_ex, GS_FALSE, "MES_CMD_COMMIT_DDL_RSP"));
 
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_RECOVERY_LOCK_RES, drc_process_recovery_lock_res, GS_TRUE, "send page info"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_RECOVERY_LOCK_RES_ACK, drc_process_remaster_recovery_task_ack,
                                             GS_FALSE, "send page info ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_BROADCAST_CHANGE_STATUS, rc_accept_status_change, GS_TRUE,
                                             "drc accept to change the status"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_SEND_RCY_SET_ACK, dtc_process_rcy_set_ack,
                                             GS_TRUE, "dtc process recovery set ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_SEND_RCY_SET_ERR_ACK,
        dtc_process_rcy_set_err_ack, GS_TRUE, "dtc process recovery set error ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_CLOSE_MYSQL_CONNECTION_REQ, dtc_proc_msg_tse_close_mysql_conn_req,
                                             GS_TRUE, "close mysql connection request"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_CLOSE_MYSQL_CONNECTION_RSP, tse_process_broadcast_ack_ex, GS_FALSE,
                                             "close mysql connection response"));

    knl_securec_check(dtc_register_proc_func(MES_CMD_SYNCPOINT_ABORT, dtc_proc_syncpoint_msg,
        GS_FALSE, "syncpoint abort"));

    knl_securec_check(dtc_register_proc_func(MES_CMD_RECYCLE_DLS_MASTER, drc_process_recycle_lock_master, GS_TRUE, "recycle lock master"));
    knl_securec_check(
        dtc_register_proc_func(MES_CMD_RECYCLE_DLS_MASTER_ACK, mes_process_msg_ack, GS_FALSE, "recycle lock master ack"));
    knl_securec_check(dtc_register_proc_func(MES_CMD_CLEAN_GRANTED_MAP, dls_process_lock_msg, GS_TRUE,
        "process dls clean granted_map msg"));
    for (uint32 i = 0; i < MES_CMD_CEIL; i++) {
        mes_set_msg_enqueue(i, g_processors[i].is_enqueue);
    }

    mes_register_proc_func(dtc_process_message);

    return GS_SUCCESS;
}

void dtc_set_command_group(void)
{
    // group 0
    for (uint32 i = 0; i < MES_CMD_CEIL; i++) {
        mes_set_command_task_group(i, MES_TASK_GROUP_ZERO);
    }

    // group 1
    mes_set_command_task_group(MES_CMD_CKPT_EDP_BROADCAST_TO_MASTER, MES_TASK_GROUP_ONE);
    mes_set_command_task_group(MES_CMD_CKPT_EDP_BROADCAST_TO_OWNER, MES_TASK_GROUP_ONE);

    // group 2
    mes_set_command_task_group(MES_CMD_CLEAN_EDP_REQ, MES_TASK_GROUP_TWO);
    mes_set_command_task_group(MES_CMD_NOTIFY_MASTER_CLEAN_EDP_REQ, MES_TASK_GROUP_TWO);

    // group 3
    mes_set_command_task_group(MES_CMD_TXN_INFO_REQ, MES_TASK_GROUP_THREE);
    mes_set_command_task_group(MES_CMD_CLAIM_OWNER_REQ, MES_TASK_GROUP_THREE);

    // group 4, serialized
    mes_set_command_task_group(MES_CMD_DDL_BROADCAST, MES_TASK_GROUP_FOUR);
    mes_set_command_task_group(MES_CMD_CHECK_DDL_ENABLED, MES_TASK_GROUP_FOUR);
    mes_set_command_task_group(MES_CMD_CREATE_OBJ_NAME_BROADCAST, MES_TASK_GROUP_FOUR);
    mes_set_command_task_group(MES_CMD_BROADCAST_USER, MES_TASK_GROUP_FOUR);
    return;
}

status_t dtc_set_group_task_num(void)
{
    uint32 group_task[MES_TASK_GROUP_ALL];
    uint32 task_num = g_dtc->profile.task_num;

    group_task[MES_TASK_GROUP_ONE] = (uint32)(task_num * g_dtc->profile.ckpt_notify_task_ratio);
    group_task[MES_TASK_GROUP_TWO] = (uint32)(task_num * g_dtc->profile.clean_edp_task_ratio);
    group_task[MES_TASK_GROUP_THREE] = (uint32)(task_num * g_dtc->profile.txn_info_task_ratio);
    group_task[MES_TASK_GROUP_FOUR] = 1;
    group_task[MES_TASK_GROUP_ZERO] = task_num - (group_task[MES_TASK_GROUP_ONE] + group_task[MES_TASK_GROUP_TWO] +
                                                  group_task[MES_TASK_GROUP_THREE] + group_task[MES_TASK_GROUP_FOUR]);

    for (uint32 i = 0; i < MES_TASK_GROUP_ALL; i++) {
        if (mes_set_group_task_num(i, group_task[i]) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[mes]: mes_set_group_task_num %u failed.", i);
            return GS_ERROR;
        }
    }

    dtc_set_command_group();

    return GS_SUCCESS;
}

void dtc_set_mes_buffer_pool(mes_profile_t *profile)
{
    uint32 buffer_count = g_dtc->profile.mes_pool_size;
    profile->buffer_pool_attr.pool_count = DTC_BUFFER_POOL_NUM;

    mes_buffer_attr_t buf_pool_attr[MES_MAX_BUFFER_STEP_NUM] = {
        {DTC_MSG_BUFFER_QUEUE_NUM, DTC_FIRST_BUFFER_LENGTH, buffer_count * DTC_FIRST_BUFFER_MULTIPLE}, // 64B buffer
        {DTC_MSG_BUFFER_QUEUE_NUM, DTC_SECOND_BUFFER_LENGTH, buffer_count * DTC_SECOND_BUFFER_MULTIPLE}, // 128B buffer
        {DTC_MSG_BUFFER_QUEUE_NUM, DTC_THIRD_BUFFER_LENGTH, buffer_count}, // 32K buffer
        {DTC_MSG_BUFFER_QUEUE_NUM, DTC_FOURTH_BUFFER_LENGTH, buffer_count * DTC_FOURTH_BUFFER_MULTIPLE} // 128K buffer
    };

    for (uint32 pool_idx = 0; pool_idx < profile->buffer_pool_attr.pool_count; pool_idx++) {
        profile->buffer_pool_attr.buf_attr[pool_idx].queue_count = buf_pool_attr[pool_idx].queue_count;
        profile->buffer_pool_attr.buf_attr[pool_idx].count = buf_pool_attr[pool_idx].count;
        profile->buffer_pool_attr.buf_attr[pool_idx].size = buf_pool_attr[pool_idx].size;
    }
}

status_t dtc_set_mes_profile(void)
{
    errno_t ret;
    mes_profile_t profile;

    ret = memset_sp(&profile, sizeof(mes_profile_t), 0, sizeof(mes_profile_t));
    knl_securec_check(ret);

    profile.inst_id = g_dtc->profile.inst_id;
    profile.inst_count = g_dtc->profile.node_count;
    profile.pipe_type = g_dtc->profile.pipe_type;
    profile.pool_size = g_dtc->profile.mes_pool_size;
    profile.channel_num = g_dtc->profile.channel_num;
    profile.reactor_thread_num = g_dtc->profile.reactor_thread_num;
    profile.work_thread_num = g_dtc->profile.task_num;
    profile.conn_by_profile = g_dtc->profile.conn_by_profile;
    profile.channel_version = GS_INVALID_ID64;
    dtc_set_mes_buffer_pool(&profile);

    if (profile.inst_count >= GS_MAX_INSTANCES) {
        GS_THROW_ERROR_EX(ERR_INVALID_PARAMETER, "inst_count %u is invalid.", profile.inst_count);
        return GS_ERROR;
    }

    for (int i = 0; i < profile.inst_count; i++) {
#ifdef _DBSTOR_ENABLE_
        profile.inst_lsid[i] = get_config_lsid(i);
        GS_LOG_RUN_INF("instance %d get lsid 0x%x", i, profile.inst_lsid[i]);
#endif
        ret = strncpy_s(profile.inst_arr[i].ip, CM_MAX_IP_LEN, g_dtc->profile.nodes[i], strlen(g_dtc->profile.nodes[i]));
        if (ret != EOK) {
            GS_THROW_ERROR(ERR_SYSTEM_CALL, (ret));
            return GS_ERROR;
        }
        profile.inst_arr[i].port = g_dtc->profile.ports[i];
    }

    if (mes_set_profile(&profile) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("mes_set_profile failed.");
        return GS_ERROR;
    }

    if (mes_set_uc_dpumm_config_path(g_instance->home) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("mes_set_uc_dpumm_config_path failed.");
        return GS_ERROR;
    }

    if (dtc_set_group_task_num() != GS_SUCCESS) {
        GS_LOG_RUN_ERR("mes_set_profile failed.");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t dtc_startup(void)
{
    knl_instance_t *kernel = g_dtc->kernel;

    g_dtc->profile.inst_id = kernel->dtc_attr.inst_id;
    g_dtc->profile.node_count = kernel->db.ctrl.core.node_count;

    if (drc_init() != GS_SUCCESS) {
        GS_LOG_RUN_ERR("drc_init failed.");
        return GS_ERROR;
    }

    if (dtc_register_proc() != GS_SUCCESS) {
        GS_LOG_RUN_ERR("dtc_register_proc_func failed.");
        return GS_ERROR;
    }

    if (dtc_init_proc_sessions() != GS_SUCCESS) {
        GS_LOG_RUN_ERR("dtc_init_proc_sessions failed.");
        return GS_ERROR;
    }
    
    if (dtc_set_mes_profile() != GS_SUCCESS) {
        GS_LOG_RUN_ERR("dtc_set_mes_profile failed.");
        return GS_ERROR;
    }

    if (mes_startup() != GS_SUCCESS) {
        GS_LOG_RUN_ERR("mes_startup failed.");
        return GS_ERROR;
    }

    if (dmon_startup() != GS_SUCCESS) {
        GS_LOG_RUN_ERR("dmon_startup failed.");
        return GS_ERROR;
    }

    if (record_io_stat_init() != GS_SUCCESS) {
        GS_LOG_RUN_ERR("init io stat record failed.");
        return GS_ERROR;
    }

    if (init_dtc_rc() != GS_SUCCESS) {
        GS_LOG_RUN_ERR("init_dtc_rc failed.");
        return GS_ERROR;
    }
    
    GS_LOG_RUN_INF("dtc_startup finish, memory usage=%lu", cm_print_memory_usage());
    return GS_SUCCESS;
}


void dtc_shutdown(knl_session_t *session, bool32 need_ckpt)
{
    free_dtc_rc();
    dmon_close();
    mes_clean();
#ifdef DTC_RUN_WITH_REFORM
    cms_res_inst_unregister();
#endif
}
