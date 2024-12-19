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
 * ctc_mysql_proxy.c
 *
 *
 * IDENTIFICATION
 * src/ctc/ctc_mysql_proxy.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctc_module.h"
#include "ctc_srv.h"
#include "srv_mq.h"
#include "srv_mq_msg.h"
#include "knl_common.h"
typedef int (*ctc_execute_rewrite_open_conn_t)(uint32_t thd_id, ctc_ddl_broadcast_request *broadcast_req);
typedef int (*ctc_ddl_execute_update_t)(uint32_t thd_id, ctc_ddl_broadcast_request *broadcast_req, bool *allow_fail);
typedef int (*ctc_ddl_execute_set_opt_t)(uint32_t thd_id, ctc_set_opt_request *broadcast_req, bool allow_fail);
typedef int (*close_mysql_connection_t)(uint32_t thd_id, uint32_t mysql_inst_id);
typedef int (*ctc_ddl_execute_lock_tables_t)(ctc_handler_t *tch, char *db_name, ctc_lock_table_info *lock_info, int *err_code);
typedef int (*ctc_ddl_execute_unlock_tables_t)(ctc_handler_t *tch, uint32_t mysql_inst_id, ctc_lock_table_info *lock_info);
typedef int (*ctc_invalidate_mysql_dd_cache_t)(ctc_handler_t *tch, ctc_invalidate_broadcast_request *broadcast_req, int *err_code);
typedef int (*ctc_set_cluster_role_by_cantian_t)(bool is_slave);
typedef struct mysql_interface_t {
    void* ctc_handle;
    ctc_execute_rewrite_open_conn_t ctc_execute_rewrite_open_conn;
    ctc_ddl_execute_update_t ctc_ddl_execute_update;
    ctc_ddl_execute_set_opt_t ctc_ddl_execute_set_opt;
    close_mysql_connection_t close_mysql_connection;
    ctc_ddl_execute_lock_tables_t ctc_ddl_execute_lock_tables;
    ctc_ddl_execute_unlock_tables_t ctc_ddl_execute_unlock_tables;
    ctc_invalidate_mysql_dd_cache_t ctc_invalidate_mysql_dd_cache;
    ctc_set_cluster_role_by_cantian_t ctc_set_cluster_role_by_cantian;
} mysql_interface;
static mysql_interface g_mysql_intf;

mysql_interface *mysql_global_handle(void)
{
    return &g_mysql_intf;
}

static status_t mysql_load_symbol(void *lib_handle, char *symbol, void **sym_lib_handle)
{
    const char *dlsym_err = NULL;
    *sym_lib_handle = dlsym(lib_handle, symbol);
    dlsym_err = dlerror();
    if (dlsym_err != NULL) {
        CT_LOG_RUN_ERR("mysql_load_symbol error, symbol: %s, dlsym_err: %s", symbol, dlsym_err);
        CT_THROW_ERROR(ERR_LOAD_SYMBOL, symbol, dlsym_err);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

int init_mysql_lib(void)
{
    mysql_interface *intf = &g_mysql_intf;
    CT_LOG_DEBUG_INF("Current user: %s\n", getenv("USER"));
    intf->ctc_handle = dlopen("ha_ctc.so", RTLD_LAZY);
    const char *dlopen_err = NULL;
    dlopen_err = dlerror();
    if (intf->ctc_handle == NULL) {
        CT_LOG_RUN_ERR("fail to load ha_ctc.so, maybe lib path error, errno %s", dlopen_err);
        return CT_ERROR;
    }
    CT_RETURN_IFERR(mysql_load_symbol(intf->ctc_handle, "ctc_invalidate_mysql_dd_cache", (void **)(&intf->ctc_invalidate_mysql_dd_cache)));
    CT_RETURN_IFERR(mysql_load_symbol(intf->ctc_handle, "ctc_execute_rewrite_open_conn", (void **)(&intf->ctc_execute_rewrite_open_conn)));
    CT_RETURN_IFERR(mysql_load_symbol(intf->ctc_handle, "ctc_ddl_execute_update", (void **)(&intf->ctc_ddl_execute_update)));
    CT_RETURN_IFERR(mysql_load_symbol(intf->ctc_handle, "ctc_ddl_execute_set_opt", (void **)(&intf->ctc_ddl_execute_set_opt)));
    CT_RETURN_IFERR(mysql_load_symbol(intf->ctc_handle, "close_mysql_connection", (void **)(&intf->close_mysql_connection)));
    CT_RETURN_IFERR(mysql_load_symbol(intf->ctc_handle, "ctc_ddl_execute_lock_tables", (void **)(&intf->ctc_ddl_execute_lock_tables)));
    CT_RETURN_IFERR(mysql_load_symbol(intf->ctc_handle, "ctc_ddl_execute_unlock_tables", (void **)(&intf->ctc_ddl_execute_unlock_tables)));
    CT_RETURN_IFERR(mysql_load_symbol(intf->ctc_handle, "ctc_set_cluster_role_by_cantian", (void **)(&intf->ctc_set_cluster_role_by_cantian)));

    CT_LOG_RUN_INF("init_mysql_lib go to the end");
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_execute_rewrite_open_conn(uint32_t thd_id, ctc_ddl_broadcast_request *broadcast_req) {
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
    int ret = ctc_mq_deal_func(shm_inst, CTC_FUNC_TYPE_EXECUTE_REWRITE_OPEN_CONN, req);
    broadcast_req->err_code = req->broadcast_req.err_code;
    if (ret == CT_SUCCESS) {
        result = req->result;
    }
    free_share_mem(shm_inst, req);
    return result;
}

EXTER_ATTACK int ctc_ddl_execute_set_opt(uint32_t thd_id, ctc_set_opt_request *broadcast_req, bool allow_fail) {
    void* shm_inst_req = get_upstream_shm_inst();
    void* shm_inst_info = get_upstream_shm_inst();
    struct execute_mysql_set_opt_request *req =
        (struct execute_mysql_set_opt_request*)alloc_share_mem(shm_inst_req, sizeof(struct execute_mysql_set_opt_request));
    if (req == NULL) {
        return ERR_GENERIC_INTERNAL_ERROR;
    }
    req->broadcast_req = *broadcast_req;
    req->broadcast_req.set_opt_info = (set_opt_info_t *)alloc_share_mem(shm_inst_info, broadcast_req->opt_num * sizeof(set_opt_info_t));
    if (req->broadcast_req.set_opt_info == NULL) {
      free_share_mem(shm_inst_req, req);
      return ERR_GENERIC_INTERNAL_ERROR;
    }
    errno_t err_s;
    err_s = memcpy_s(req->broadcast_req.set_opt_info, broadcast_req->opt_num * sizeof(set_opt_info_t),
                    broadcast_req->set_opt_info, broadcast_req->opt_num * sizeof(set_opt_info_t));
    knl_securec_check(err_s);
    req->result = 0;
    req->allow_fail = allow_fail;
    req->thd_id = thd_id;
    int result = ERR_GENERIC_INTERNAL_ERROR;
    int ret = ctc_mq_deal_func(shm_inst_req, CTC_FUNC_TYPE_MYSQL_EXECUTE_SET_OPT, req);
    broadcast_req->err_code = req->broadcast_req.err_code;
    err_s = strncpy_s(broadcast_req->err_msg, ERROR_MESSAGE_LEN, req->broadcast_req.err_msg,
        strlen(req->broadcast_req.err_msg));
    knl_securec_check(err_s);
    if (ret == CT_SUCCESS) {
        result = req->result;
    }
    free_share_mem(shm_inst_info, req->broadcast_req.set_opt_info);
    free_share_mem(shm_inst_req, req);
    return result;
}

EXTER_ATTACK int ctc_ddl_execute_update(uint32_t thd_id, ctc_ddl_broadcast_request *broadcast_req,
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
    int ret = ctc_mq_deal_func(shm_inst, CTC_FUNC_TYPE_MYSQL_EXECUTE_UPDATE, req);
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
    int ret = ctc_mq_deal_func(shm_inst, CTC_FUNC_TYPE_CLOSE_MYSQL_CONNECTION, req);
    if (ret == CT_SUCCESS) {
        result = req->result;
    }
    free_share_mem(shm_inst, req);
    return result;
}

EXTER_ATTACK int ctc_ddl_execute_lock_tables(ctc_handler_t *tch, char *db_name, ctc_lock_table_info *lock_info,
    int *err_code)
{
    void* shm_inst = get_upstream_shm_inst();
    struct ctc_lock_tables_request *req =
        (struct ctc_lock_tables_request *)alloc_share_mem(shm_inst, sizeof(struct ctc_lock_tables_request));
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
            CT_LOG_RUN_ERR("ctc_ddl_execute_lock_tables strcpy_s fail.");
            return ERR_GENERIC_INTERNAL_ERROR;
        }
    }

    int result = ERR_GENERIC_INTERNAL_ERROR;
    int ret = ctc_mq_deal_func(shm_inst, CTC_FUNC_TYPE_LOCK_TABLES, req);
    *err_code = req->err_code;
    if (ret == CT_SUCCESS) {
        result = req->result;
    }
    free_share_mem(shm_inst, req);
    return result;
}

EXTER_ATTACK int ctc_ddl_execute_unlock_tables(ctc_handler_t *tch, uint32_t mysql_inst_id, ctc_lock_table_info *lock_info)
{
    void* shm_inst = get_upstream_shm_inst();
    struct ctc_unlock_tables_request *req =
        (struct ctc_unlock_tables_request *)alloc_share_mem(shm_inst, sizeof(struct ctc_unlock_tables_request));
    if (req == NULL) {
        return ERR_GENERIC_INTERNAL_ERROR;
    }
    req->tch = *tch;
    req->mysql_inst_id = mysql_inst_id;
    req->lock_info = *lock_info;
    int result = ERR_GENERIC_INTERNAL_ERROR;
    int ret = ctc_mq_deal_func(shm_inst, CTC_FUNC_TYPE_UNLOCK_TABLES, req);
    if (ret == CT_SUCCESS) {
        result = req->result;
    }
    free_share_mem(shm_inst, req);
    return result;
}

EXTER_ATTACK int ctc_invalidate_mysql_dd_cache(ctc_handler_t *tch, ctc_invalidate_broadcast_request *broadcast_req, int *err_code)
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
    int ret = ctc_mq_deal_func(shm_inst, CTC_FUNC_TYPE_INVALIDATE_OBJECTS, req);
    *err_code = req->err_code;
    if (ret == CT_SUCCESS) {
        result = req->result;
    }
    free_share_mem(shm_inst, req);
    return result;
}

EXTER_ATTACK int ctc_set_cluster_role_by_cantian(bool is_slave)
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
    int ret = ctc_mq_deal_func(shm_inst, CTC_FUNC_SET_CLUSTER_ROLE_BY_CANTIAN, req);
    if (ret == CT_SUCCESS) {
        result = req->result;
    }
    free_share_mem(shm_inst, req);
    return result;
}

EXTER_ATTACK int ctc_execute_rewrite_open_conn_intf(uint32_t thd_id, ctc_ddl_broadcast_request *broadcast_req)
{
#ifndef WITH_CANTIAN
    return ctc_execute_rewrite_open_conn(thd_id, broadcast_req);
#else
    return g_mysql_intf.ctc_execute_rewrite_open_conn(thd_id, broadcast_req);
#endif
}


EXTER_ATTACK int ctc_ddl_execute_update_intf(uint32_t thd_id, ctc_ddl_broadcast_request *broadcast_req,
    bool *allow_fail)
{
#ifndef WITH_CANTIAN
    return ctc_ddl_execute_update(thd_id, broadcast_req, allow_fail);
#else
    return g_mysql_intf.ctc_ddl_execute_update(thd_id, broadcast_req, allow_fail);
#endif
}

EXTER_ATTACK int ctc_ddl_execute_set_opt_intf(uint32_t thd_id, ctc_set_opt_request *broadcast_req, bool allow_fail)
{
#ifndef WITH_CANTIAN
    return ctc_ddl_execute_set_opt(thd_id, broadcast_req, allow_fail);
#else
    return g_mysql_intf.ctc_ddl_execute_set_opt(thd_id, broadcast_req, allow_fail);
#endif
}

EXTER_ATTACK int close_mysql_connection_intf(uint32_t thd_id, uint32_t mysql_inst_id)
{
#ifndef WITH_CANTIAN
    return close_mysql_connection(thd_id, mysql_inst_id);
#else
    return g_mysql_intf.close_mysql_connection(thd_id, mysql_inst_id);
#endif
}

EXTER_ATTACK int ctc_ddl_execute_lock_tables_intf(ctc_handler_t *tch, char *db_name, ctc_lock_table_info *lock_info,
    int *err_code)
{
#ifndef WITH_CANTIAN
    return ctc_ddl_execute_lock_tables(tch, db_name, lock_info, err_code);
#else
    return g_mysql_intf.ctc_ddl_execute_lock_tables(tch, db_name, lock_info, err_code);
#endif
}

EXTER_ATTACK int ctc_ddl_execute_unlock_tables_intf(ctc_handler_t *tch, uint32_t mysql_inst_id, ctc_lock_table_info *lock_info)
{
#ifndef WITH_CANTIAN
    return ctc_ddl_execute_unlock_tables(tch, mysql_inst_id, lock_info);
#else
    return g_mysql_intf.ctc_ddl_execute_unlock_tables(tch, mysql_inst_id, lock_info);
#endif
}

EXTER_ATTACK int ctc_invalidate_mysql_dd_cache_intf(ctc_handler_t *tch, ctc_invalidate_broadcast_request *broadcast_req, int *err_code)
{
#ifndef WITH_CANTIAN 
    return ctc_invalidate_mysql_dd_cache(tch, broadcast_req, err_code);
#else
    return g_mysql_intf.ctc_invalidate_mysql_dd_cache(tch, broadcast_req, err_code);
#endif
}

EXTER_ATTACK int ctc_set_cluster_role_by_cantian_intf(bool is_slave)
{
#ifndef WITH_CANTIAN    
    return ctc_set_cluster_role_by_cantian(is_slave);
#else
    return g_mysql_intf.ctc_set_cluster_role_by_cantian(is_slave);
#endif
}