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
 * tse_mysql_proxy.c
 *
 *
 * IDENTIFICATION
 * src/tse/tse_mysql_proxy.c
 *
 * -------------------------------------------------------------------------
 */

#include "tse_srv.h"
#include "srv_mq.h"
#include "srv_mq_msg.h"
#include "knl_common.h"

int tse_execute_rewrite_open_conn(uint32_t thd_id, tse_ddl_broadcast_request *broadcast_req)
{
    void* shm_inst = get_upstream_shm_inst();
    struct execute_ddl_mysql_sql_request *req =
        (struct execute_ddl_mysql_sql_request*)alloc_share_mem(shm_inst, sizeof(struct execute_ddl_mysql_sql_request));
    if (req == NULL) {
        return ERR_GENERIC_INTERNAL_ERROR;
    }
    req->broadcast_req = *broadcast_req;
    req->thd_id = thd_id;
    req->result = 0;
    int result = ERR_GENERIC_INTERNAL_ERROR;
    int ret = tse_mq_deal_func(shm_inst, TSE_FUNC_TYPE_EXECUTE_REWRITE_OPEN_CONN, req);
    broadcast_req->err_code = req->broadcast_req.err_code;
    if (ret == GS_SUCCESS) {
        result = req->result;
    }
    free_share_mem(shm_inst, req);
    return result;
}

int tse_ddl_execute_update(uint32_t thd_id, tse_ddl_broadcast_request *broadcast_req,
    bool *allow_fail)
{
    void* shm_inst = get_upstream_shm_inst();
    struct execute_ddl_mysql_sql_request *req =
        (struct execute_ddl_mysql_sql_request*)alloc_share_mem(shm_inst, sizeof(struct execute_ddl_mysql_sql_request));
    if (req == NULL) {
        return ERR_GENERIC_INTERNAL_ERROR;
    }
    req->broadcast_req = *broadcast_req;
    req->thd_id = thd_id;
    req->result = 0;
    req->allow_fail = *allow_fail;
    int result = ERR_GENERIC_INTERNAL_ERROR;
    int ret = tse_mq_deal_func(shm_inst, TSE_FUNC_TYPE_MYSQL_EXECUTE_UPDATE, req);
    broadcast_req->err_code = req->broadcast_req.err_code;
    if (ret == GS_SUCCESS) {
        result = req->result;
        *allow_fail = req->allow_fail;
    }
    free_share_mem(shm_inst, req);
    return result;
}

int close_mysql_connection(uint32_t thd_id, uint32_t mysql_inst_id)
{
    void* shm_inst = get_upstream_shm_inst();
    struct close_mysql_connection_request *req =
        (struct close_mysql_connection_request *)alloc_share_mem(shm_inst,
        sizeof(struct close_mysql_connection_request));
    if (req == NULL) {
        return ERR_GENERIC_INTERNAL_ERROR;
    }
    req->inst_id = mysql_inst_id;
    req->thd_id = thd_id;
    int result = ERR_GENERIC_INTERNAL_ERROR;
    int ret = tse_mq_deal_func(shm_inst, TSE_FUNC_TYPE_CLOSE_MYSQL_CONNECTION, req);
    if (ret == GS_SUCCESS) {
        result = req->result;
    }
    free_share_mem(shm_inst, req);
    return result;
}

int tse_ddl_execute_lock_tables(tianchi_handler_t *tch, char *db_name, tse_lock_table_info *lock_info,
    int *err_code)
{
    void* shm_inst = get_upstream_shm_inst();
    struct tse_lock_tables_request *req =
        (struct tse_lock_tables_request *)alloc_share_mem(shm_inst, sizeof(struct tse_lock_tables_request));
    if (req == NULL) {
        return ERR_GENERIC_INTERNAL_ERROR;
    }
    req->tch = *tch;
    req->lock_info = *lock_info;
    req->err_code = 0;
    
    int strcpy_ret = 0;
    req->db_name[0] = '\0';
    if (!CM_IS_EMPTY_STR(db_name)) {
        strcpy_ret = strcpy_s(req->db_name, SMALL_RECORD_SIZE - 1, db_name);
        knl_securec_check(strcpy_ret);
    }

    int result = ERR_GENERIC_INTERNAL_ERROR;
    int ret = tse_mq_deal_func(shm_inst, TSE_FUNC_TYPE_LOCK_TABLES, req);
    *err_code = req->err_code;
    if (ret == GS_SUCCESS) {
        result = req->result;
    }
    free_share_mem(shm_inst, req);
    return result;
}

int tse_ddl_execute_unlock_tables(tianchi_handler_t *tch, uint32_t mysql_inst_id)
{
    void* shm_inst = get_upstream_shm_inst();
    struct tse_unlock_tables_request *req =
        (struct tse_unlock_tables_request *)alloc_share_mem(shm_inst, sizeof(struct tse_unlock_tables_request));
    if (req == NULL) {
        return ERR_GENERIC_INTERNAL_ERROR;
    }
    req->tch = *tch;
    req->mysql_inst_id = mysql_inst_id;
    int result = ERR_GENERIC_INTERNAL_ERROR;
    int ret = tse_mq_deal_func(shm_inst, TSE_FUNC_TYPE_UNLOCK_TABLES, req);
    if (ret == GS_SUCCESS) {
        result = req->result;
    }
    free_share_mem(shm_inst, req);
    return result;
}
