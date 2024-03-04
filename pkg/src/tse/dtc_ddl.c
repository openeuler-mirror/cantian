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
 * dtc_ddl.c
 *
 *
 * IDENTIFICATION
 * src/tse/dtc_ddl.c
 *
 * -------------------------------------------------------------------------
 */
#include "tse_module.h"
#include "dtc_ddl.h"
#include "rc_reform.h"
#include "tse_mysql_client.h"
#include "tse_srv_util.h"

// 下标代表发送端节点id
msg_rsp_res_pair g_tse_msg_result_arr[TSE_CLUSTER_MAX_NODES] = {
    {0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}
};

msg_rsp_res_pair *get_tse_msg_result_arr(void)
{
    return &g_tse_msg_result_arr;
}

status_t tse_send_data_retry(const void *msg_data, uint8 dst_inst)
{
    uint32 retry_time = 0;
    status_t status = CT_SUCCESS;
    SYNC_POINT_GLOBAL_START(TSE_MES_OVERVIEW_SEND_FAIL, &status, CT_ERROR);
    status = mes_send_data(msg_data);
    SYNC_POINT_GLOBAL_END;
    while (status != CT_SUCCESS) {
        retry_time++;
        cluster_view_t view;
        rc_get_cluster_view(&view, CT_FALSE);
        if (rc_bitmap64_exist(&view.bitmap, dst_inst)) {
            cm_sleep(TSE_RESEND_MSG_INTERVAL);
            status = mes_send_data(msg_data);
        } else {
            CT_LOG_RUN_WAR("[TSE_MES]:target instance %u is not alive", dst_inst);
            return CT_ERROR;
        }

        if (retry_time % TSE_RESEND_MSG_TIMES == 0) {
            CT_LOG_RUN_WAR("[TSE_MES]:send message failed times:%u", retry_time);
        }
    }
    return status;
}

static void dtc_tse_ddl_msg_struct_not_match(mes_message_head_t *req_head, mes_command_t mes_cmd, knl_session_t *session)
{
    msg_ddl_rsp_t rsp = {0};

    rsp.err_code = TSE_DDL_VERSION_NOT_MATCH;
    mes_init_ack_head(req_head, &(rsp.head), mes_cmd, sizeof(msg_ddl_rsp_t), session->id);
    if (mes_send_data(&rsp) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[TSE_MES]: mes struct not match. Please make sure cluster on same version."
            "mes_cmd=%d, src_sid=%u", mes_cmd, req_head->src_sid);
    }
    return;
}

void tse_deal_repeat_msg(mes_message_head_t *req_head, mes_command_t mes_cmd, knl_session_t *session)
{
    msg_ddl_rsp_t rsp = {0};

    rsp.err_code = cm_atomic32_get(&g_tse_msg_result_arr[req_head->src_inst].err_code);
    rsp.allow_fail = cm_atomic32_get(&g_tse_msg_result_arr[req_head->src_inst].allow_fail);
    if (rsp.err_code == TSE_DDL_PROCESSING) {
        CT_LOG_RUN_ERR("[TSE_MES]: %d from src_sid=%u still in processing.", mes_cmd, req_head->src_sid);
        return;
    }

    mes_init_ack_head(req_head, &(rsp.head), mes_cmd, sizeof(msg_ddl_rsp_t), session->id);
    if (mes_send_data(&rsp) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[TSE_MES]: Response repeat message failed, mes_cmd=%d, src_sid=%u", mes_cmd, req_head->src_sid);
    }
}

bool is_exist_repeat_msg(mes_message_head_t *req_head, knl_session_t *session,
                         mes_command_t mes_cmd, uint32_t new_msg_num)
{
    if (req_head->src_inst >= TSE_CLUSTER_MAX_NODES) {
        CT_LOG_RUN_ERR("req_head src_inst is invalid, slot %u, MAX %u", req_head->src_inst, TSE_CLUSTER_MAX_NODES);
        return true;
    }

    uint32_t old_msg_num = (uint32_t)cm_atomic32_get(&g_tse_msg_result_arr[req_head->src_inst].msg_num);
    if (old_msg_num == new_msg_num) {
        tse_deal_repeat_msg(req_head, mes_cmd, session);
        CT_LOG_RUN_WAR("[TSE_MES]: Remote node receive repeat msg. mes_cmd=%d, msg_num=%u", mes_cmd, new_msg_num);
        return true;
    }

    (void)cm_atomic_cas(&g_tse_msg_result_arr[req_head->src_inst].msg_num, old_msg_num, new_msg_num);
    cm_atomic_set(&g_tse_msg_result_arr[req_head->src_inst].err_code, TSE_DDL_PROCESSING);
    return false;
}

void dtc_proc_msg_tse_lock_table_req(void *sess, mes_message_t *msg)
{
    msg_prepare_ddl_req_t *req = (msg_prepare_ddl_req_t *)msg->buffer;
    msg_ddl_rsp_t rsp = {0};
    knl_session_t *session = (knl_session_t *)sess;

    if (sizeof(msg_prepare_ddl_req_t) != msg->head->size) {
        CT_LOG_RUN_ERR("proc msg tse lock table req msg size is invalid, msg size %u, struct size:%d",
            msg->head->size, sizeof(msg_prepare_ddl_req_t));
        dtc_tse_ddl_msg_struct_not_match(&(req->head), MES_CMD_PREPARE_DDL_RSP, session);
        mes_release_message_buf(msg->buffer);
        return;
    }

    if (is_exist_repeat_msg(&(req->head), session, MES_CMD_PREPARE_DDL_RSP, req->msg_num)) {
        CT_LOG_RUN_ERR("[TSE_LOCK_TABLE]: repeat msg, conn_id=%u, lock_info(db=%s, table=%s), tse_instance_id=%u",
                       req->tch.thd_id, req->lock_info.db_name, req->lock_info.table_name, req->tch.inst_id);
        mes_release_message_buf(msg->buffer);
        return;
    }

    mes_init_ack_head(&(req->head), &(rsp.head), MES_CMD_PREPARE_DDL_RSP, sizeof(msg_ddl_rsp_t), session->id);
    int ret = tse_ddl_execute_lock_tables(&(req->tch), req->db_name, &(req->lock_info), &(rsp.err_code));
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[TSE_LOCK_TABLE]: remote node execute lock table failed,"
                       "ret=%d, err_code=%u, conn_id=%u, lock_info(db=%s, table=%s), tse_instance_id=%u",
                       ret, rsp.err_code, req->tch.thd_id, req->lock_info.db_name,
                       req->lock_info.table_name, req->tch.inst_id);
    }
    
    SYNC_POINT_GLOBAL_START(TSE_LOCK_TABLE_REMOTE_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    cm_atomic_set(&g_tse_msg_result_arr[req->head.src_inst].err_code, rsp.err_code);
    
    if (mes_send_data(&rsp) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[TSE_LOCK_TABLE]: mes_send_data failed, table lock_info(db=%s, table=%s), "
                       "conn_id=%u, tse_instance_id=%u", req->lock_info.db_name,
                       req->lock_info.table_name, req->tch.thd_id, req->tch.inst_id);
    }

    mes_release_message_buf(msg->buffer);
}

void dtc_proc_msg_tse_execute_ddl_req(void *sess, mes_message_t *msg)
{
    msg_execute_ddl_req_t *req = (msg_execute_ddl_req_t *)msg->buffer;
    msg_ddl_rsp_t rsp = {0};
    knl_session_t *session = (knl_session_t *)sess;

    if (sizeof(msg_execute_ddl_req_t) != msg->head->size) {
        CT_LOG_RUN_ERR("proc msg tse execute ddl req msg size is invalid, msg size %u, struct size:%d",
            msg->head->size, sizeof(msg_execute_ddl_req_t));
        dtc_tse_ddl_msg_struct_not_match(&(req->head), MES_CMD_PREPARE_DDL_RSP, session);
        mes_release_message_buf(msg->buffer);
        return;
    }

    if (is_exist_repeat_msg(&(req->head), session, MES_CMD_EXECUTE_DDL_RSP, req->msg_num)) {
        CT_LOG_RUN_ERR("[TSE_DDL]: repeat msg, conn_id=%u, sql_command=%u, sql=%s",
                       req->thd_id, req->broadcast_req.sql_command,
                       sql_without_plaintext_password((req->broadcast_req.options & TSE_CURRENT_SQL_CONTAIN_PLAINTEXT_PASSWORD),
                                                      req->broadcast_req.sql_str, sizeof(req->broadcast_req.sql_str)));
        mes_release_message_buf(msg->buffer);
        return;
    }

    mes_init_ack_head(&(req->head), &(rsp.head), MES_CMD_EXECUTE_DDL_RSP, sizeof(msg_ddl_rsp_t), session->id);
    rsp.err_code = mysql_execute_ddl_sql(req->thd_id, &req->broadcast_req, &req->allow_fail);
    rsp.allow_fail = req->allow_fail;
    if (rsp.err_code != CT_SUCCESS) {
        strncpy_s(rsp.err_msg, ERROR_MESSAGE_LEN, req->broadcast_req.err_msg, strlen(req->broadcast_req.err_msg));
        CT_LOG_RUN_ERR("[TSE_DDL]: remote node execute ddl failed. ret=%u, conn_id=%u,"
                       "sql_command=%u, sql=%s.", rsp.err_code, req->thd_id, req->broadcast_req.sql_command,
                       sql_without_plaintext_password((req->broadcast_req.options & TSE_CURRENT_SQL_CONTAIN_PLAINTEXT_PASSWORD),
                                                      req->broadcast_req.sql_str, sizeof(req->broadcast_req.sql_str)));
    }

    SYNC_POINT_GLOBAL_START(TSE_EXECUTE_DDL_REMOTE_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    cm_atomic_set(&g_tse_msg_result_arr[req->head.src_inst].err_code, rsp.err_code);
    cm_atomic_set(&g_tse_msg_result_arr[req->head.src_inst].allow_fail, rsp.allow_fail);

    if (mes_send_data(&rsp) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[TSE_DDL]: mes_send_data failed, conn_id=%u, sql_command=%u, sql=%s.",
                       req->thd_id, req->broadcast_req.sql_command,
                       sql_without_plaintext_password((req->broadcast_req.options & TSE_CURRENT_SQL_CONTAIN_PLAINTEXT_PASSWORD),
                                                      req->broadcast_req.sql_str, sizeof(req->broadcast_req.sql_str)));
    }

    mes_release_message_buf(msg->buffer);
}

void dtc_proc_msg_tse_execute_rewrite_open_conn_req(void *sess, mes_message_t *msg)
{
    msg_execute_ddl_req_t *req = (msg_execute_ddl_req_t *)msg->buffer;
    msg_ddl_rsp_t rsp = {0};
    knl_session_t *session = (knl_session_t *)sess;

    if (sizeof(msg_execute_ddl_req_t) != msg->head->size) {
        CT_LOG_RUN_ERR("proc msg tse execute rewrite open conn req msg size is invalid, msg size %u, struct size:%d",
            msg->head->size, sizeof(msg_execute_ddl_req_t));
        dtc_tse_ddl_msg_struct_not_match(&(req->head), MES_CMD_REWRITE_OPEN_CONN_RSP, session);
        mes_release_message_buf(msg->buffer);
        return;
    }

    if (is_exist_repeat_msg(&(req->head), session, MES_CMD_REWRITE_OPEN_CONN_RSP, req->msg_num)) {
        CT_LOG_RUN_ERR("[TSE_REWRITE_CONN]: repeat msg, conn_id=%u, sql_command=%u, sql=%s",
                       req->thd_id, req->broadcast_req.sql_command,
                       sql_without_plaintext_password((req->broadcast_req.options & TSE_CURRENT_SQL_CONTAIN_PLAINTEXT_PASSWORD),
                                                      req->broadcast_req.sql_str, sizeof(req->broadcast_req.sql_str)));
        mes_release_message_buf(msg->buffer);
        return;
    }

    mes_init_ack_head(&(req->head), &(rsp.head), MES_CMD_REWRITE_OPEN_CONN_RSP, sizeof(msg_ddl_rsp_t), session->id);
    rsp.err_code = tse_execute_rewrite_open_conn(req->thd_id, &req->broadcast_req);
    if (rsp.err_code != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[TSE_REWRITE_CONN]: remote node execute ddl failed. ret=%u, conn_id=%u,"
                       "sql_command=%u, sql=%s.", rsp.err_code, req->thd_id, req->broadcast_req.sql_command,
                       sql_without_plaintext_password((req->broadcast_req.options & TSE_CURRENT_SQL_CONTAIN_PLAINTEXT_PASSWORD),
                                                      req->broadcast_req.sql_str, sizeof(req->broadcast_req.sql_str)));
    }

    cm_atomic_set(&g_tse_msg_result_arr[req->head.src_inst].err_code, rsp.err_code);
    cm_atomic_set(&g_tse_msg_result_arr[req->head.src_inst].allow_fail, rsp.allow_fail);

    if (mes_send_data(&rsp) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[TSE_REWRITE_CONN]: mes_send_data failed, conn_id=%u, sql_command=%u, sql=%s.",
                       req->thd_id, req->broadcast_req.sql_command,
                       sql_without_plaintext_password((req->broadcast_req.options & TSE_CURRENT_SQL_CONTAIN_PLAINTEXT_PASSWORD),
                                                      req->broadcast_req.sql_str, sizeof(req->broadcast_req.sql_str)));
    }

    mes_release_message_buf(msg->buffer);
}

void dtc_proc_msg_tse_commit_ddl_req(void *sess, mes_message_t *msg)
{
    msg_commit_ddl_req_t *req = (msg_commit_ddl_req_t *)msg->buffer;
    msg_ddl_rsp_t rsp = {0};
    knl_session_t *session = (knl_session_t *)sess;

    if (sizeof(msg_commit_ddl_req_t) != msg->head->size) {
        CT_LOG_RUN_ERR("proc msg tse commit ddl req msg size is invalid, msg size %u.", msg->head->size);
        mes_release_message_buf(msg->buffer);
        return;
    }

    if (is_exist_repeat_msg(&(req->head), session, MES_CMD_COMMIT_DDL_RSP, req->msg_num)) {
        CT_LOG_RUN_ERR("[TSE_UNLOCK_TABLE]: repeat msg, conn_id=%u, tse_instance_id=%u",
                       req->tch.thd_id, req->tch.inst_id);
        mes_release_message_buf(msg->buffer);
        return;
    }

    mes_init_ack_head(&(req->head), &(rsp.head), MES_CMD_COMMIT_DDL_RSP, sizeof(msg_ddl_rsp_t), session->id);
    rsp.err_code = tse_ddl_execute_unlock_tables(&(req->tch), req->mysql_inst_id, &(req->lock_info));
    if (rsp.err_code != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[TSE_UNLOCK_TABLE]:remote node execute unlock table failed,"
                       "ret=%u, conn_id=%u, tse_instance_id=%u", rsp.err_code, req->tch.thd_id, req->tch.inst_id);
    }

    SYNC_POINT_GLOBAL_START(TSE_UNLOCK_REMOTE_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    cm_atomic_set(&g_tse_msg_result_arr[req->head.src_inst].err_code, rsp.err_code);

    if (mes_send_data(&rsp) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[TSE_UNLOCK_TABLE]: mes_send_data failed, conn_id=%u, tse_instance_id=%u",
                       req->tch.thd_id, req->tch.inst_id);
    }

    mes_release_message_buf(msg->buffer);
}

void dtc_proc_msg_tse_close_mysql_conn_req(void *sess, mes_message_t *msg)
{
    msg_close_connection_req_t *req = (msg_close_connection_req_t *)msg->buffer;
    msg_ddl_rsp_t rsp = {0};
    knl_session_t *session = (knl_session_t *)sess;

    if (sizeof(msg_close_connection_req_t) != msg->head->size) {
        CT_LOG_RUN_ERR("proc msg tse close mysql conn req msg size is invalid, msg size %u.", msg->head->size);
        mes_release_message_buf(msg->buffer);
        return;
    }

    if (is_exist_repeat_msg(&(req->head), session, MES_CMD_CLOSE_MYSQL_CONNECTION_RSP, req->msg_num)) {
        CT_LOG_RUN_ERR("[TSE_CLOSE_SESSION]: repeat msg, src_sid=%u, conn_id=%u, tse_inst_id=%u, msg_num=%u",
                       req->head.src_sid, req->thd_id, req->mysql_inst_id, req->msg_num);
        mes_release_message_buf(msg->buffer);
        return;
    }

    mes_init_ack_head(&(req->head), &(rsp.head), MES_CMD_CLOSE_MYSQL_CONNECTION_RSP,
                      sizeof(msg_ddl_rsp_t), session->id);
    
    rsp.err_code = close_mysql_connection(req->thd_id, req->mysql_inst_id);
    if (rsp.err_code != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[TSE_CLOSE_SESSION]: close_mysql_connection failed,"
                       "ret=%u, src_sid=%u, conn_id=%u, tse_inst_id=%u, msg_num=%u",
                       rsp.err_code, req->head.src_sid, req->thd_id, req->mysql_inst_id, req->msg_num);
    }

    SYNC_POINT_GLOBAL_START(TSE_CLOSE_CONN_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    cm_atomic_set(&g_tse_msg_result_arr[req->head.src_inst].err_code, rsp.err_code);

    if (mes_send_data(&rsp) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[TSE_CLOSE_SESSION]: mes_send_data failed, src_sid=%u, conn_id=%u, tse_inst_id=%u, msg_num=%u",
                       req->head.src_sid, req->thd_id, req->mysql_inst_id, req->msg_num);
    }

    mes_release_message_buf(msg->buffer);
}

void dtc_proc_msg_tse_invalidate_all_dd_cache_req(void *sess, mes_message_t *msg)
{
    msg_invalid_all_dd_cache_req_t *req = (msg_invalid_all_dd_cache_req_t *)msg->buffer;
    msg_invalid_all_dd_cache_rsp_t rsp = {0};
    knl_session_t *session = (knl_session_t *)sess;
 
    if (sizeof(msg_invalid_all_dd_cache_req_t) != msg->head->size) {
        CT_LOG_RUN_ERR("proc msg tse invalidate all dd cache req msg size is invalid, expected size: %u, actual msg size %u.",
                        sizeof(msg_invalid_all_dd_cache_req_t), msg->head->size);
        mes_release_message_buf(msg->buffer);
        return;
    }
 
    if (is_exist_repeat_msg(&(req->head), session, MES_CMD_INVALID_DD_RSP, req->msg_num)) {
        CT_LOG_RUN_ERR("[TSE_INVALID_DD]: repeat msg");
        mes_release_message_buf(msg->buffer);
        return;
    }
    mes_init_ack_head(&(req->head), &(rsp.head), MES_CMD_INVALID_ALL_DD_RSP, sizeof(msg_invalid_all_dd_cache_rsp_t), session->id);
    CT_LOG_RUN_INF("[zzh debug] begin to tse_invalidate_all_dd_cache, msg->num:%d", req->msg_num);
    int ret = tse_invalidate_all_dd_cache();
    CT_LOG_RUN_INF("[zzh debug] AFTER tse_invalidate_all_dd_cache, ret: %d, msg->num:%d", ret, req->msg_num);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[Disaster Recovery]: remote node execute invalid dd failed.");
    }
    cm_atomic_set(&g_tse_msg_result_arr[req->head.src_inst].err_code, rsp.error_code);
    CT_LOG_RUN_INF("[zzh debug] begin to send rsp, req->msg_num:%d", req->msg_num);
    if (mes_send_data(&rsp) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[Disaster Recovery]: mes_send_data failed.");
    }
    CT_LOG_RUN_INF("[zzh debug] after sending rsp, req->msg_num:%d", req->msg_num);
 
    mes_release_message_buf(msg->buffer);
}

void dtc_proc_msg_tse_invalidate_dd_req(void *sess, mes_message_t *msg)
{
    msg_invalid_dd_req_t *req = (msg_invalid_dd_req_t *)msg->buffer;
    msg_ddl_rsp_t rsp = {0};
    knl_session_t *session = (knl_session_t *)sess;

    if (sizeof(msg_invalid_dd_req_t) != msg->head->size) {
        CT_LOG_RUN_ERR("proc msg tse invalidate  dd req msg size is invalid, msg size %u.", msg->head->size);
        mes_release_message_buf(msg->buffer);
        return;
    }

    if (is_exist_repeat_msg(&(req->head), session, MES_CMD_INVALID_DD_RSP, req->msg_num)) {
        CT_LOG_RUN_ERR("[TSE_INVALID_DD]: repeat msg, conn_id=%u, tse_instance_id=%u",
                       req->tch.thd_id, req->tch.inst_id);
        mes_release_message_buf(msg->buffer);
        return;
    }
 
    mes_init_ack_head(&(req->head), &(rsp.head), MES_CMD_INVALID_DD_RSP, sizeof(msg_ddl_rsp_t), session->id);
    int ret = tse_invalidate_mysql_dd_cache(&(req->tch), &req->broadcast_req, &(rsp.err_code));
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[TSE_INVALID_DD]: remote node execute invalid dd failed,"
                       "ret=%d, err_code=%u, conn_id=%u, tse_instance_id=%u", ret, rsp.err_code, req->tch.thd_id,
                       req->tch.inst_id);
    }

    cm_atomic_set(&g_tse_msg_result_arr[req->head.src_inst].err_code, rsp.err_code);
    
    if (mes_send_data(&rsp) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[TSE_INVALID_DD]: mes_send_data failed, conn_id=%u, tse_instance_id=%u", req->tch.thd_id, req->tch.inst_id);
    }
 
    mes_release_message_buf(msg->buffer);
}

void dtc_proc_msg_tse_update_dd_cache_req(void *sess, mes_message_t *msg)
{
    msg_update_dd_cache_req_t *req = (msg_update_dd_cache_req_t *)msg->buffer;
    msg_ddl_rsp_t rsp = {0};
    knl_session_t *session = (knl_session_t *)sess;
    
    if (sizeof(msg_update_dd_cache_req_t) != msg->head->size) {
        CT_LOG_RUN_ERR("proc msg tse update dd cache req msg size is invalid, msg size %u.", msg->head->size);
        mes_release_message_buf(msg->buffer);
        return;
    }
    
    if (is_exist_repeat_msg(&(req->head), session, MES_CMD_INVALID_DD_RSP, req->msg_num)) {
        CT_LOG_RUN_ERR("[TSE_INVALID_DD]: repeat msg, conn_id=%u, tse_instance_id=%u",
                       req->thd_id, req->inst_id);
        mes_release_message_buf(msg->buffer);
        return;
    }
 
    mes_init_ack_head(&(req->head), &(rsp.head), MES_CMD_UPDATE_DD_RSP, sizeof(msg_ddl_rsp_t), session->id);
    int ret = tse_update_mysql_dd_cache(&req->sql_str);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[Disaster Recovery]: remote node execute updata dd cache failed, sql_str: %s, ret: %d", &req->sql_str, ret);
    }
 
    if (mes_send_data(&rsp) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[Disaster Recovery]: Failed to send the rsp in dtc_proc_msg_tse_update_dd_cache_req.");
    }
 
    mes_release_message_buf(msg->buffer);
}