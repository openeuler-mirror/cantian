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
 * dtc_ddl.h
 *
 *
 * IDENTIFICATION
 * src/tse/dtc_ddl.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DTC_DDL_H__
#define __DTC_DDL_H__
#include <stdbool.h>
#include "cm_defs.h"
#include "knl_session.h"
#include "knl_buffer.h"
#include "tse_srv.h"
#include "mes_func.h"

#define MES_TABLE_NAME_BUFFER_SIZE      (128)
#define MES_DB_NAME_BUFFER_SIZE      (128)
#define TSE_RESEND_MSG_INTERVAL (5)  // unit: ms
#define TSE_RESEND_MSG_TIMES (4000) // resend 200 times in 1s
#define TSE_BROADCAST_WAIT_TIMEOUT (12000)  // ms
#define TSE_CLUSTER_MAX_NODES (4)
#define TSE_DDL_PROCESSING (-99)
#define TSE_DDL_VERSION_NOT_MATCH (9999)
#define TSE_DDL_WAIT_PROCESS (100000)  // 100ms/0.1s

typedef struct st_msg_rsp_res_pair_t {
    atomic_t       msg_num;
    atomic_t       err_code;
    atomic_t       allow_fail;
} msg_rsp_res_pair;

typedef struct st_msg_ddl_rsp_t {
    mes_message_head_t      head;
    int32_t                 err_code;
    bool                    allow_fail;
    char                    err_msg[ERROR_MESSAGE_LEN];
} msg_ddl_rsp_t;

typedef struct st_msg_invalid_all_dd_cache_rsp_t {
    mes_message_head_t      head;
    int32_t                 error_code;
} msg_invalid_all_dd_cache_rsp_t;

typedef struct st_msg_prepare_ddl_req_t {
    mes_message_head_t      head;
    char                    db_name[MES_DB_NAME_BUFFER_SIZE];
    tse_lock_table_info     lock_info;
    tianchi_handler_t       tch;
    uint32_t                msg_num;
} msg_prepare_ddl_req_t;

typedef struct st_msg_execute_ddl_req_t {
    mes_message_head_t        head;
    tse_ddl_broadcast_request broadcast_req;
    uint32_t                  thd_id;
    uint32_t                  msg_num;
    bool                      allow_fail;
} msg_execute_ddl_req_t;

typedef struct st_msg_commit_ddl_req_t {
    mes_message_head_t      head;
    tianchi_handler_t       tch;
    uint32_t                mysql_inst_id;
    uint32_t                msg_num;
    tse_lock_table_info     lock_info;
} msg_commit_ddl_req_t;

typedef struct st_msg_close_connection_req_t {
    mes_message_head_t        head;
    uint32_t                  thd_id;
    uint32_t                  mysql_inst_id;
    uint32_t                  msg_num;
} msg_close_connection_req_t;

typedef struct st_msg_invalid_dd_req_t {
    mes_message_head_t                  head;
    tse_invalidate_broadcast_request    broadcast_req;
    tianchi_handler_t                   tch;
    uint32_t                            msg_num;
} msg_invalid_dd_req_t;

typedef struct st_msg_invalid_all_dd_cache_req_t {
    mes_message_head_t                  head;
    uint32_t                            msg_num;
} msg_invalid_all_dd_cache_req_t;
 
typedef struct st_msg_update_dd_cache_req_t {
    mes_message_head_t                  head;
    char*                               sql_str;
    uint32_t                            inst_id;
    uint32_t                            thd_id;
    uint32_t                            msg_num;
} msg_update_dd_cache_req_t;

EXTER_ATTACK void dtc_proc_msg_tse_lock_table_req(void *sess, mes_message_t *msg);
EXTER_ATTACK void dtc_proc_msg_tse_execute_ddl_req(void *sess, mes_message_t *msg);
EXTER_ATTACK void dtc_proc_msg_tse_commit_ddl_req(void *sess, mes_message_t *msg);
EXTER_ATTACK void dtc_proc_msg_tse_close_mysql_conn_req(void *sess, mes_message_t *msg);
EXTER_ATTACK void dtc_proc_msg_tse_execute_rewrite_open_conn_req(void *sess, mes_message_t *msg);
EXTER_ATTACK void dtc_proc_msg_tse_invalidate_dd_req(void *sess, mes_message_t *msg);
EXTER_ATTACK void dtc_proc_msg_tse_invalidate_all_dd_cache_req(void *sess, mes_message_t *msg);
status_t tse_is_inst_alive(uint8 dst_inst);
status_t tse_send_data_retry(const void *msg_data, uint8 dst_inst);
msg_rsp_res_pair *get_tse_msg_result_arr(void);

#endif
