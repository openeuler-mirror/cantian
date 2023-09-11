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
 * dtc_log.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_log.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_log.h"
#include "dtc_database.h"
#include "dtc_backup.h"
#include "dtc_log.h"

status_t dtc_log_switch(knl_session_t *session, uint64 lsn, uint32 target_id)
{
    mes_message_head_t head;
    mes_message_t  msg;

    mes_init_send_head(&head, MES_CMD_LOG_SWITCH, sizeof(mes_message_head_t) + sizeof(uint64), GS_INVALID_ID32,
                       session->kernel->dtc_attr.inst_id, target_id, session->id, GS_INVALID_ID16);

    if (mes_send_data2((void *)&head, &lsn) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "send log switch mes ");
        return GS_ERROR;
    }

    if (mes_recv(session->id, &msg, GS_FALSE, GS_INVALID_ID32, MES_WAIT_MAX_TIME) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "receive log switch mes ");
        return GS_ERROR;
    }

    if (SECUREC_UNLIKELY(msg.head->cmd == MES_CMD_LOG_SWITCH_FAIL)) {
        mes_release_message_buf(msg.buffer);
        return GS_ERROR;
    }
    mes_release_message_buf(msg.buffer);

    return GS_SUCCESS;
}

void dtc_process_log_switch(void *sess, mes_message_t * receive_msg)
{
    mes_message_head_t head;
    status_t ret;
    knl_session_t *session = (knl_session_t *)sess;
    uint64 lsn = *(uint64 *)(receive_msg->buffer + sizeof(mes_message_head_t));
    
    if (lsn == 0 && cm_dbs_is_enable_dbs() != GS_TRUE) {
        ret = log_switch_logfile(session, GS_INVALID_FILEID, GS_INVALID_ASN, NULL);
    } else {
        ret = dtc_bak_force_arch_local(session, lsn);
    }
    
    if (ret == GS_SUCCESS) {
        mes_init_ack_head(receive_msg->head, &head, MES_CMD_LOG_SWITCH_SUCCESS, sizeof(mes_message_head_t), session->id);
        mes_release_message_buf(receive_msg->buffer);
        if (mes_send_data((void*)&head) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[BACKUP] %s failed", "send log switch success ack mes ");
            return;
        }
    } else {
        mes_init_ack_head(receive_msg->head, &head, MES_CMD_LOG_SWITCH_FAIL, sizeof(mes_message_head_t), session->id);
        mes_release_message_buf(receive_msg->buffer);
        if (mes_send_data((void*)&head) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[BACKUP] %s failed", "send log switch fail ack mes ");
            return;
        }
    }
}

status_t dtc_get_log_asn_by_lsn(knl_session_t *session, log_start_end_lsn_t *lsn,
                                uint32 target_id, log_start_end_asn_t *asn)
{
    mes_message_head_t head;
    mes_message_t  msg;
    mes_init_send_head(&head, MES_CMD_GET_LOG_ASN_BY_LSN, sizeof(mes_message_head_t) + sizeof(log_start_end_lsn_t),
                       GS_INVALID_ID32, session->kernel->dtc_attr.inst_id, target_id, session->id, GS_INVALID_ID16);
    if (mes_send_data2((void *)&head, lsn) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "send get log curr asn mes ");
        return GS_ERROR;
    }
    if (mes_recv(session->id, &msg, GS_FALSE, GS_INVALID_ID32, MES_WAIT_MAX_TIME) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "receive get log curr asn mes ");
        return GS_ERROR;
    }
    if (SECUREC_UNLIKELY(msg.head->cmd != MES_CMD_GET_LOG_ASN_BY_LSN_ACK)) {
        mes_release_message_buf(msg.buffer);
        return GS_ERROR;
    }
    *asn = *(log_start_end_asn_t *)(msg.buffer + sizeof(mes_message_head_t));
    mes_release_message_buf(msg.buffer);
    return asn->result == DTC_BAK_ERROR ? GS_ERROR : GS_SUCCESS;
}

status_t dtc_get_log_curr_asn(knl_session_t *session, uint32 target_id, uint32 *curr_asn)
{
    mes_message_head_t head;
    mes_message_t  msg;

    mes_init_send_head(&head, MES_CMD_GET_LOG_CURR_ASN, sizeof(mes_message_head_t), GS_INVALID_ID32,
                       session->kernel->dtc_attr.inst_id, target_id, session->id, GS_INVALID_ID16);

    if (mes_send_data((void *)&head) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "send get log curr asn mes ");
        return GS_ERROR;
    }

    if (mes_recv(session->id, &msg, GS_FALSE, GS_INVALID_ID32, MES_WAIT_MAX_TIME) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "receive get log curr asn mes ");
        return GS_ERROR;
    }

    if (SECUREC_UNLIKELY(msg.head->cmd != MES_CMD_GET_LOG_CURR_ASN_ACK)) {
        mes_release_message_buf(msg.buffer);
        return GS_ERROR;
    }

    *curr_asn = *(uint32 *)(msg.buffer + sizeof(mes_message_head_t));
    mes_release_message_buf(msg.buffer);

    return GS_SUCCESS;
}

void dtc_process_get_log_curr_asn(void *sess, mes_message_t * receive_msg)
{
    mes_message_head_t head;
    uint32 curr_asn;
    knl_session_t *session = (knl_session_t *)sess;
    log_context_t *redo_ctx = &session->kernel->redo_ctx;

    curr_asn = redo_ctx->files[redo_ctx->curr_file].head.asn;

    mes_init_ack_head(receive_msg->head, &head, MES_CMD_GET_LOG_CURR_ASN_ACK, sizeof(mes_message_head_t) + sizeof(uint32), session->id);

    mes_release_message_buf(receive_msg->buffer);
    if (mes_send_data2(&head, &curr_asn) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "send get log curr asn ack mes ");
        return;
    }
}

static status_t dtc_get_asn_by_lsn(knl_session_t *session, log_start_end_lsn_t *lsn, log_start_end_asn_t *asn)
{
    asn->start_asn = 0;
    status_t status = arch_lsn_asn_convert(session, lsn->start_lsn, &(asn->start_asn));
    if (status != GS_SUCCESS) {
        return status;
    }

    asn->end_asn = 0;
    status = arch_lsn_asn_convert(session, lsn->end_lsn, &(asn->end_asn));
    if (status != GS_SUCCESS) {
        return status;
    }
    return GS_SUCCESS;
}

void dtc_process_get_log_asn_by_lsn(void *sess, mes_message_t *receive_msg)
{
    mes_message_head_t head;
    knl_session_t *session = (knl_session_t *)sess;
    log_start_end_lsn_t lsn_info = *(log_start_end_lsn_t *)(receive_msg->buffer + sizeof(mes_message_head_t));
    log_start_end_asn_t asn = {0, 0, DTC_BAK_ERROR};
    // get asn by lsn
    GS_LOG_RUN_INF("[BACKUP] start lsn %llu, end lsn %llu", lsn_info.start_lsn, lsn_info.end_lsn);
    status_t status = dtc_get_asn_by_lsn(sess, &lsn_info, &asn);
    if (status == GS_SUCCESS) {
        asn.result = DTC_BAK_SUCCESS;
    } else {
        asn.result = DTC_BAK_ERROR;
    }
    mes_init_ack_head(receive_msg->head, &head, MES_CMD_GET_LOG_ASN_BY_LSN_ACK,
                      sizeof(mes_message_head_t) + sizeof(log_start_end_asn_t), session->id);
    mes_release_message_buf(receive_msg->buffer);
    if (mes_send_data2(&head, &asn) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "send get log curr asn ack mes ");
        return;
    }
}

status_t dtc_get_log_curr_size(knl_session_t *session, uint32 target_id, int64 *curr_size)
{
    mes_message_head_t head;
    mes_message_t  msg;

    mes_init_send_head(&head, MES_CMD_GET_LOG_CURR_SIZE, sizeof(mes_message_head_t), GS_INVALID_ID32,
                       session->kernel->dtc_attr.inst_id, target_id, session->id, GS_INVALID_ID16);

    if (mes_send_data((void *)&head) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "send get log curr size mes ");
        return GS_ERROR;
    }

    if (mes_recv(session->id, &msg, GS_FALSE, GS_INVALID_ID32, MES_WAIT_MAX_TIME) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "receive get log curr size mes ");
        return GS_ERROR;
    }

    if (SECUREC_UNLIKELY(msg.head->cmd != MES_CMD_GET_LOG_CURR_SIZE_ACK)) {
        mes_release_message_buf(msg.buffer);
        return GS_ERROR;
    }

    *curr_size = *(uint32 *)(msg.buffer + sizeof(mes_message_head_t));
    mes_release_message_buf(msg.buffer);

    return GS_SUCCESS;
}

void dtc_process_get_log_curr_size(void *sess, mes_message_t * receive_msg)
{
    mes_message_head_t head;
    int64 curr_size;
    knl_session_t *session = (knl_session_t *)sess;
    log_context_t *redo_ctx = &session->kernel->redo_ctx;

    curr_size = redo_ctx->files[redo_ctx->curr_file].ctrl->size;

    mes_init_ack_head(receive_msg->head, &head, MES_CMD_GET_LOG_CURR_SIZE_ACK, sizeof(mes_message_head_t) + sizeof(uint32), session->id);

    mes_release_message_buf(receive_msg->buffer);
    if (mes_send_data2(&head, &curr_size) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] %s failed", "send get log curr size ack mes ");
        return;
    }
}

void dtc_log_flush_head(knl_session_t *session, log_file_t *file)
{
    errno_t ret;
    int32 size;
    char *logwr_head_buf = NULL;

    if (file->ctrl->type == DEV_TYPE_ULOG) {
        GS_LOG_RUN_INF("No need flush head for ulog %s", file->ctrl->name);
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

    if (cm_open_device(file->ctrl->name, file->ctrl->type, knl_io_flag(session), &file->handle) != GS_SUCCESS) {
        free(logwr_head_buf);
        CM_ABORT(0, "[LOG] ABORT INFO: flush redo file:%s, offset:%u, size:%lu failed.", file->ctrl->name, 0,
            sizeof(log_file_head_t));
    }

    if (cm_write_device(file->ctrl->type, file->handle, 0, logwr_head_buf, size) != GS_SUCCESS) {
        free(logwr_head_buf);
        cm_close_device(file->ctrl->type, &file->handle);
        CM_ABORT(0, "[LOG] ABORT INFO: flush redo file:%s, offset:%u, size:%lu failed.", file->ctrl->name, 0,
            sizeof(log_file_head_t));
    }
    GS_LOG_DEBUG_INF("Flush log[%u] head with asn %u status %d", file->ctrl->file_id, file->head.asn,
                     file->ctrl->status);
    free(logwr_head_buf);
    cm_close_device(file->ctrl->type, &file->handle);
}
