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
 * tse_mysql_proxy.c
 *
 *
 * IDENTIFICATION
 * src/tse/tse_mysql_proxy.c
 *
 * -------------------------------------------------------------------------
 */
#include "tse_module.h"
#include "tse_srv.h"
#include "srv_mq.h"
#include "srv_mq_msg.h"
#include "knl_common.h"

EXTER_ATTACK int tse_execute_rewrite_open_conn(uint32_t thd_id, tse_ddl_broadcast_request *broadcast_req)
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
    if (ret == CT_SUCCESS) {
        result = req->result;
    }
    free_share_mem(shm_inst, req);
    return result;
}

EXTER_ATTACK int tse_ddl_execute_update(uint32_t thd_id, tse_ddl_broadcast_request *broadcast_req,
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
    strncpy_s(broadcast_req->err_msg, ERROR_MESSAGE_LEN, req->broadcast_req.err_msg,
        strlen(req->broadcast_req.err_msg));
    if (ret == CT_SUCCESS) {
        result = req->result;
        *allow_fail = req->allow_fail;
    }
    free_share_mem(shm_inst, req);
    return result;
}

EXTER_ATTACK int close_mysql_connection(uint32_t thd_id, uint32_t mysql_inst_id)
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
    if (ret == CT_SUCCESS) {
        result = req->result;
    }
    free_share_mem(shm_inst, req);
    return result;
}

EXTER_ATTACK int tse_ddl_execute_lock_tables(tianchi_handler_t *tch, char *db_name, tse_lock_table_info *lock_info,
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
        if (strcpy_ret != 0) {
            CT_LOG_RUN_ERR("tse_ddl_execute_lock_tables strcpy_s fail.");
            return ERR_GENERIC_INTERNAL_ERROR;
        }
    }

    int result = ERR_GENERIC_INTERNAL_ERROR;
    int ret = tse_mq_deal_func(shm_inst, TSE_FUNC_TYPE_LOCK_TABLES, req);
    *err_code = req->err_code;
    if (ret == CT_SUCCESS) {
        result = req->result;
    }
    free_share_mem(shm_inst, req);
    return result;
}

EXTER_ATTACK int tse_ddl_execute_unlock_tables(tianchi_handler_t *tch, uint32_t mysql_inst_id, tse_lock_table_info *lock_info)
{
    void* shm_inst = get_upstream_shm_inst();
    struct tse_unlock_tables_request *req =
        (struct tse_unlock_tables_request *)alloc_share_mem(shm_inst, sizeof(struct tse_unlock_tables_request));
    if (req == NULL) {
        return ERR_GENERIC_INTERNAL_ERROR;
    }
    req->tch = *tch;
    req->mysql_inst_id = mysql_inst_id;
    req->lock_info = *lock_info;
    int result = ERR_GENERIC_INTERNAL_ERROR;
    int ret = tse_mq_deal_func(shm_inst, TSE_FUNC_TYPE_UNLOCK_TABLES, req);
    if (ret == CT_SUCCESS) {
        result = req->result;
    }
    free_share_mem(shm_inst, req);
    return result;
}

EXTER_ATTACK int tse_invalidate_mysql_dd_cache(tianchi_handler_t *tch, tse_invalidate_broadcast_request *broadcast_req, int *err_code)
{
    void* shm_inst = get_upstream_shm_inst();
    struct invalidate_mysql_dd_request *req =
        (struct invalidate_mysql_dd_request *)alloc_share_mem(shm_inst, sizeof(struct invalidate_mysql_dd_request));
    if (req == NULL) {
        return ERR_GENERIC_INTERNAL_ERROR;
    }
    req->broadcast_req = *broadcast_req;
    req->tch = *tch;
    req->result = 0;
    int result = ERR_GENERIC_INTERNAL_ERROR;
    int ret = tse_mq_deal_func(shm_inst, TSE_FUNC_TYPE_INVALIDATE_OBJECTS, req);
    *err_code = req->err_code;
    if (ret == CT_SUCCESS) {
        result = req->result;
    }
    free_share_mem(shm_inst, req);
    return result;
}

EXTER_ATTACK int tse_set_cluster_role_by_cantian(bool is_slave)
{
    void* shm_inst = get_upstream_shm_inst();
    struct set_cluster_role_by_cantian_request *req = 
        (struct set_cluster_role_by_cantian_request *)alloc_share_mem(shm_inst, sizeof(struct set_cluster_role_by_cantian_request));
    if (req == NULL) {
        return ERR_GENERIC_INTERNAL_ERROR;
    }
    req->is_slave = is_slave;
    req->result = 0;
    int result = ERR_GENERIC_INTERNAL_ERROR;
    int ret = tse_mq_deal_func(shm_inst, TSE_FUNC_SET_CLUSTER_ROLE_BY_CANTIAN, req);
    if (ret == CT_SUCCESS) {
        result = req->result;
    }
    free_share_mem(shm_inst, req);
    return result;
}
 
EXTER_ATTACK int tse_invalidate_all_dd_cache()
{
    void* shm_inst = get_upstream_shm_inst();
    struct invalidate_all_dd_cache_request *req = 
        (struct invalidate_all_dd_cache_request *)alloc_share_mem(shm_inst, sizeof(struct invalidate_all_dd_cache_request));
    if (req == NULL) {
        return ERR_GENERIC_INTERNAL_ERROR;
    }
    req->result = CT_ERROR;
    int result = ERR_GENERIC_INTERNAL_ERROR;
    CT_LOG_RUN_INF("[zzh debug] inform local mysql to invalidate_all_dd_cache");
    int ret = tse_mq_deal_func(shm_inst, TSE_FUNC_TYPE_INVALIDATE_ALL_OBJECTS, req);
    CT_LOG_RUN_INF("[zzh debug] local mysql after invalidate_all_dd_cache, ret: %d", ret);
    if (ret == CT_SUCCESS) {
        result = req->result;
    }
    free_share_mem(shm_inst, req);
    // CT_LOG_RUN_INF("[zzh debug] result: %d", result);
    return result;
}
 
 
EXTER_ATTACK int tse_update_mysql_dd_cache(char *sql_str)
{
    void* shm_inst = get_upstream_shm_inst();
    struct update_mysql_dd_cache_request *req =
        (struct update_mysql_dd_cache_request *)alloc_share_mem(shm_inst, sizeof(struct update_mysql_dd_cache_request));
    if (req == NULL) {
        return ERR_GENERIC_INTERNAL_ERROR;
    }
    req->inst_id = CT_INVALID_ID32 - 1;
    req->thd_id = CT_INVALID_ID32 - 1;
    req->result = 0;
    int sql_len = strlen(sql_str);
    memcpy_sp(req->sql_str, sql_len, sql_str, sql_len);
    int result = ERR_GENERIC_INTERNAL_ERROR;
    int ret = tse_mq_deal_func(shm_inst, TSE_FUNC_TYPE_UPDATE_DDCACHE, req);
    if (ret == CT_SUCCESS) {
        result = req->result;
    }
    free_share_mem(shm_inst, req);
    return result;
}