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
 * dtc_log.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_log.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DTC_LOG_H__
#define __DTC_LOG_H__

#include "mes_func.h"

typedef struct log_start_end_asn {
    uint32 start_asn;
    uint32 end_asn;
    uint32 result;
} log_start_end_asn_t;
typedef struct log_start_end_lsn {
    uint64 start_lsn;
    uint64 end_lsn;
} log_start_end_lsn_t;

status_t dtc_log_switch(knl_session_t *session, uint64 lsn, uint32 target_id);
EXTER_ATTACK void dtc_process_log_switch(void *sess, mes_message_t *receive_msg);
status_t dtc_get_log_curr_asn(knl_session_t *session, uint32 target_id, uint32 *curr_asn);
status_t dtc_get_log_asn_by_lsn(knl_session_t *session, log_start_end_lsn_t *lsn,
                                uint32 target_id, log_start_end_asn_t *asn);
EXTER_ATTACK void dtc_process_get_log_curr_asn(void *sess, mes_message_t *receive_msg);
EXTER_ATTACK void dtc_process_get_log_asn_by_lsn(void *sess, mes_message_t *receive_msg);
status_t dtc_get_log_curr_size(knl_session_t *session, uint32 target_id, int64 *curr_size);
EXTER_ATTACK void dtc_process_get_log_curr_size(void *sess, mes_message_t *receive_msg);
void dtc_log_flush_head(knl_session_t *session, log_file_t *file);

#endif