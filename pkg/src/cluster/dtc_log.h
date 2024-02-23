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

#ifdef __cplusplus
extern "C" {
#endif

typedef struct log_start_end_asn {
    uint32 start_asn;
    uint32 end_asn;
    uint32 max_asn;
} log_start_end_asn_t;
typedef struct log_start_end_lsn {
    uint64 start_lsn;
    uint64 end_lsn;
    uint64 max_lsn;
} log_start_end_lsn_t;

typedef struct log_start_end_info {
    log_start_end_asn_t *result_asn;
    log_start_end_asn_t *target_asn;
    log_start_end_lsn_t *target_lsn;
    uint64 *result_end_lsn;
    uint32 *arch_num;
} log_start_end_info_t;
typedef struct arch_info {
    char *buf;
    log_start_end_lsn_t *find_lsn;
    bool32 *found_arch;
    uint32 *last_archived_asn;
    uint32 inst_id;
    uint32 rst_id;
} arch_info_t;
 
typedef struct local_arch_file_info {
    uint32 local_rst_id;
    uint32 local_node_id;
    uint64 local_start_lsn;
    uint64 local_end_lsn;
    uint32 local_asn;
} local_arch_file_info_t;

status_t dtc_log_switch(knl_session_t *session, uint64 lsn, uint32 target_id);
EXTER_ATTACK void dtc_process_log_switch(void *sess, mes_message_t *receive_msg);
status_t dtc_get_log_curr_asn(knl_session_t *session, uint32 target_id, uint32 *curr_asn);
EXTER_ATTACK void dtc_process_get_log_curr_asn(void *sess, mes_message_t *receive_msg);
status_t dtc_get_log_curr_size(knl_session_t *session, uint32 target_id, int64 *curr_size);
EXTER_ATTACK void dtc_process_get_log_curr_size(void *sess, mes_message_t *receive_msg);
void dtc_log_flush_head(knl_session_t *session, log_file_t *file);

#ifdef __cplusplus
}
#endif

#endif