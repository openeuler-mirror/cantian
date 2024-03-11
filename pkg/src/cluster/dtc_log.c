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
 * dtc_log.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_log.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_cluster_module.h"
#include "knl_log.h"
#include "dtc_database.h"
#include "dtc_backup.h"
#include "dtc_log.h"

status_t dtc_log_switch(knl_session_t *session, uint64 lsn, uint32 target_id)
{
    mes_message_head_t head;
    mes_message_t  msg;

    mes_init_send_head(&head, MES_CMD_LOG_SWITCH, sizeof(mes_message_head_t) + sizeof(uint64), CT_INVALID_ID32,
                       session->kernel->dtc_attr.inst_id, target_id, session->id, CT_INVALID_ID16);

    if (mes_send_data2((void *)&head, &lsn) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] %s failed", "send log switch mes ");
        return CT_ERROR;
    }

    if (mes_recv(session->id, &msg, CT_FALSE, CT_INVALID_ID32, MES_WAIT_MAX_TIME) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] %s failed", "receive log switch mes ");
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(msg.head->cmd == MES_CMD_LOG_SWITCH_FAIL)) {
        mes_release_message_buf(msg.buffer);
        return CT_ERROR;
    }
    mes_release_message_buf(msg.buffer);

    return CT_SUCCESS;
}

void dtc_process_log_switch(void *sess, mes_message_t * receive_msg)
{
    if (sizeof(mes_message_head_t) + sizeof(uint64) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("dtc_process_log_switch msg size is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    mes_message_head_t head;
    status_t ret;
    knl_session_t *session = (knl_session_t *)sess;
    uint64 lsn = *(uint64 *)(receive_msg->buffer + sizeof(mes_message_head_t));
    if ((lsn == 0 && cm_dbs_is_enable_dbs() == CT_TRUE) ||
        (lsn != 0 && cm_dbs_is_enable_dbs() == CT_FALSE)) {
        CT_LOG_RUN_ERR("[BACKUP] the lsn value can not be 0 while dbstor is enable");
        mes_release_message_buf(receive_msg->buffer);
        return;
    }

    if (lsn != CT_INVALID_ID64) {
        SYNC_POINT_GLOBAL_START(CANTIAN_BACKUP_TRIGGER_FORCH_ARCH_WAIT_ABORT, NULL, 0);
        SYNC_POINT_GLOBAL_END;
    }

    if (lsn == 0) {
        ret = dtc_bak_force_arch_local_file(session);
    } else {
        ret = dtc_bak_force_arch_local(session, lsn);
    }
    
    if (ret == CT_SUCCESS) {
        mes_init_ack_head(receive_msg->head, &head, MES_CMD_LOG_SWITCH_SUCCESS, sizeof(mes_message_head_t), session->id);
        mes_release_message_buf(receive_msg->buffer);
        if (mes_send_data((void*)&head) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BACKUP] %s failed", "send log switch success ack mes ");
            return;
        }
    } else {
        mes_init_ack_head(receive_msg->head, &head, MES_CMD_LOG_SWITCH_FAIL, sizeof(mes_message_head_t), session->id);
        mes_release_message_buf(receive_msg->buffer);
        if (mes_send_data((void*)&head) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[BACKUP] %s failed", "send log switch fail ack mes ");
            return;
        }
    }
}

status_t dtc_get_log_curr_asn(knl_session_t *session, uint32 target_id, uint32 *curr_asn)
{
    mes_message_head_t head;
    mes_message_t  msg;

    mes_init_send_head(&head, MES_CMD_GET_LOG_CURR_ASN, sizeof(mes_message_head_t), CT_INVALID_ID32,
                       session->kernel->dtc_attr.inst_id, target_id, session->id, CT_INVALID_ID16);

    if (mes_send_data((void *)&head) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] %s failed", "send get log curr asn mes ");
        return CT_ERROR;
    }

    if (mes_recv(session->id, &msg, CT_FALSE, CT_INVALID_ID32, MES_WAIT_MAX_TIME) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] %s failed", "receive get log curr asn mes ");
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(msg.head->cmd != MES_CMD_GET_LOG_CURR_ASN_ACK)) {
        mes_release_message_buf(msg.buffer);
        return CT_ERROR;
    }

    *curr_asn = *(uint32 *)(msg.buffer + sizeof(mes_message_head_t));
    mes_release_message_buf(msg.buffer);

    return CT_SUCCESS;
}

void dtc_process_get_log_curr_asn(void *sess, mes_message_t * receive_msg)
{
    if (sizeof(mes_message_head_t) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("dtc_process_get_log_curr_asn msg size is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    mes_message_head_t head;
    uint32 curr_asn;
    knl_session_t *session = (knl_session_t *)sess;
    log_context_t *redo_ctx = &session->kernel->redo_ctx;

    curr_asn = redo_ctx->files[redo_ctx->curr_file].head.asn;

    mes_init_ack_head(receive_msg->head, &head, MES_CMD_GET_LOG_CURR_ASN_ACK, sizeof(mes_message_head_t) + sizeof(uint32), session->id);

    mes_release_message_buf(receive_msg->buffer);
    if (mes_send_data2(&head, &curr_asn) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] %s failed", "send get log curr asn ack mes ");
        return;
    }
}

status_t dtc_get_log_curr_size(knl_session_t *session, uint32 target_id, int64 *curr_size)
{
    mes_message_head_t head;
    mes_message_t  msg;

    mes_init_send_head(&head, MES_CMD_GET_LOG_CURR_SIZE, sizeof(mes_message_head_t), CT_INVALID_ID32,
                       session->kernel->dtc_attr.inst_id, target_id, session->id, CT_INVALID_ID16);

    if (mes_send_data((void *)&head) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] %s failed", "send get log curr size mes ");
        return CT_ERROR;
    }

    if (mes_recv(session->id, &msg, CT_FALSE, CT_INVALID_ID32, MES_WAIT_MAX_TIME) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] %s failed", "receive get log curr size mes ");
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(msg.head->cmd != MES_CMD_GET_LOG_CURR_SIZE_ACK)) {
        mes_release_message_buf(msg.buffer);
        return CT_ERROR;
    }

    *curr_size = *(uint32 *)(msg.buffer + sizeof(mes_message_head_t));
    mes_release_message_buf(msg.buffer);

    return CT_SUCCESS;
}

void dtc_process_get_log_curr_size(void *sess, mes_message_t * receive_msg)
{
    if (sizeof(mes_message_head_t) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("dtc_process_get_log_curr_size msg size is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    mes_message_head_t head;
    int64 curr_size;
    knl_session_t *session = (knl_session_t *)sess;
    log_context_t *redo_ctx = &session->kernel->redo_ctx;

    curr_size = redo_ctx->files[redo_ctx->curr_file].ctrl->size;

    mes_init_ack_head(receive_msg->head, &head, MES_CMD_GET_LOG_CURR_SIZE_ACK, sizeof(mes_message_head_t) + sizeof(uint32), session->id);

    mes_release_message_buf(receive_msg->buffer);
    if (mes_send_data2(&head, &curr_size) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] %s failed", "send get log curr size ack mes ");
        return;
    }
}

void dtc_log_flush_head(knl_session_t *session, log_file_t *file)
{
    errno_t ret;
    int32 size;
    char *logwr_head_buf = NULL;

    if (file->ctrl->type == DEV_TYPE_ULOG) {
        CT_LOG_RUN_INF("No need flush head for ulog %s", file->ctrl->name);
        return;
    }

    log_calc_head_checksum(session, &file->head);

    size = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
    logwr_head_buf = (char *)malloc(size);
    if (logwr_head_buf == NULL) {
        CM_ABORT(0, "[LOG] ABORT INFO: flush redo file:%s, offset:%u, size:%lu failed.", file->ctrl->name, 0,
            sizeof(log_file_head_t));
    }

    ret = memset_sp(logwr_head_buf, file->ctrl->block_size, 0, file->ctrl->block_size);
    knl_securec_check(ret);

    *(log_file_head_t *)logwr_head_buf = file->head;

    if (cm_open_device(file->ctrl->name, file->ctrl->type, knl_io_flag(session), &file->handle) != CT_SUCCESS) {
        free(logwr_head_buf);
        CM_ABORT(0, "[LOG] ABORT INFO: flush redo file:%s, offset:%u, size:%lu failed.", file->ctrl->name, 0,
            sizeof(log_file_head_t));
    }

    if (cm_write_device(file->ctrl->type, file->handle, 0, logwr_head_buf, size) != CT_SUCCESS) {
        free(logwr_head_buf);
        CT_LOG_RUN_WAR("[LOG] file handle is %u.", file->handle);
        cm_close_device(file->ctrl->type, &file->handle);
        CM_ABORT(0, "[LOG] ABORT INFO: flush redo file:%s, offset:%u, size:%lu failed.", file->ctrl->name, 0,
            sizeof(log_file_head_t));
    }
    CT_LOG_DEBUG_INF("Flush log[%u] head with asn %u status %d", file->ctrl->file_id, file->head.asn,
                     file->ctrl->status);
    free(logwr_head_buf);
    cm_close_device(file->ctrl->type, &file->handle);
}
