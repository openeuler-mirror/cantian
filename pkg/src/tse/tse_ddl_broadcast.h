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
 * tse_ddl_broadcast.h
 *
 *
 * IDENTIFICATION
 * src/tse/tse_ddl_broadcast.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __TSE_DDL_BROADCAST_H__
#define __TSE_DDL_BROADCAST_H__

#include "dtc_ddl.h"
#include "mes_queue.h"
#include "tse_inst.h"
#include "cm_malloc.h"

int tse_broadcast_and_recv(knl_session_t *knl_session, uint64 inst_bits, const void *req_data, char *err_msg);
void tse_process_broadcast_ack_ex(void *session, mes_message_t *msg);
bool ctc_handle_recv_error(mes_message_t *recv_msg, char *err_msg);

status_t ctc_lock_table_in_slave_node(knl_handle_t session, void *buff);
status_t ctc_unlock_table_in_slave_node(knl_handle_t session, void *buff);
status_t ctc_invalid_dd_in_slave_node(knl_handle_t session, void *buff);
status_t ctc_execute_ddl_in_slave_node(knl_handle_t session, char *sql_text, uint32 sql_len);
status_t ctc_unlock_mdl_key_in_slave_node(knl_handle_t session);
#endif
