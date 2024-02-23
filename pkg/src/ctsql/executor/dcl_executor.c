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
 * dcl_executor.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/dcl_executor.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_defs.h"
#include "cm_log.h"
#include "pl_executor.h"
#include "ctsql_expr.h"
#include "ctsql_privilege.h"
#include "srv_instance.h"
#include "srv_replica.h"
#include "pl_trigger.h"
#include "pl_memory.h"

#ifdef DB_DEBUG_VERSION
#include "knl_syncpoint.h"
#endif /* DB_DEBUG_VERSION */
#include "dcl_executor.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t sql_set_param(sql_stmt_t *ctsql_stmt, knl_alter_sys_def_t *def)
{
    CM_POINTER(ctsql_stmt);
    knl_session_t *se = KNL_SESSION(ctsql_stmt);
    database_t *db = &se->kernel->db;
    config_item_t *item = NULL;
    bool32 force = CT_TRUE;
    if (db->status != DB_STATUS_MOUNT && db->status != DB_STATUS_OPEN) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "set param only work in mount or open state");
        return CT_ERROR;
    }

    item = &se->kernel->attr.config->items[def->param_id];
    if (def->param_id != item->id) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "def->param_id(%u) == item->id(%u)", def->param_id, item->id);
        return CT_ERROR;
    }

    if (def->scope != CONFIG_SCOPE_DISK) {
        if (item->notify && item->notify((knl_handle_t)se, (void *)item, def->value)) {
            return CT_ERROR;
        }
    } else {
        if (item->notify_pfile && item->notify_pfile((knl_handle_t)se, (void *)item, def->value)) {
            return CT_ERROR;
        }
    }

    if (item->attr & ATTR_READONLY) {
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
        force = CT_TRUE;
#else
        force = CT_FALSE; // can not alter parameter whose attr is readonly  for release
#endif
    }
    if (cm_alter_config(se->kernel->attr.config, def->param, def->value, def->scope, force) != CT_SUCCESS) {
        return CT_ERROR;
    }
    CT_LOG_RUN_WAR("parameter %s has been changed successfully", def->param);
    CT_LOG_ALARM(WARN_PARAMCHANGE, "parameter : %s", def->param);
    return CT_SUCCESS;
}

status_t sql_set_debug_param(knl_handle_t handle, knl_alter_sys_def_t *def)
{
    debug_config_item_t *debug_params = NULL;
    debug_config_item_t *debug_item = NULL;
    char *param = def->param;
    char *value = def->value;
    uint32 count;

    srv_get_debug_config_info(&debug_params, &count);

    for (uint32 i = 0; i < count; i++) {
        if (cm_str_equal_ins(debug_params[i].name, param)) {
            debug_item = &debug_params[i];
            break;
        }
    }

    if (debug_item == NULL) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER_NAME, param);
        return CT_ERROR;
    }

    if (debug_item->notify(handle, (void *)debug_item, value) != CT_SUCCESS) {
        return CT_ERROR;
    }

    MEMS_RETURN_IFERR(strncpy_s(debug_item->curr_value, CT_PARAM_BUFFER_SIZE, value, CT_PARAM_BUFFER_SIZE - 1));

    CT_LOG_RUN_WAR("[DB] set debug mode parameter \"%s\" to \"%s\"", param, value);
    return CT_SUCCESS;
}

status_t sql_flush_sqlpool(sql_stmt_t *ctsql_stmt)
{
    CM_POINTER(ctsql_stmt);
    knl_session_t *se = KNL_SESSION(ctsql_stmt);
    database_t *db = &se->kernel->db;

    if (db->status != DB_STATUS_MOUNT && db->status != DB_STATUS_OPEN) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "flush sqlpool only work in mount or open state");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_recycle_sharedpool(sql_stmt_t *stmt, knl_alter_sys_def_t *def)
{
    knl_session_t *se = &stmt->session->knl_session;
    memory_pool_t *sqlpool = g_instance->sql.pool->memory;
    memory_pool_t *dc_pool = &se->kernel->dc_ctx.pool;
    memory_area_t *memory_area = sqlpool->area;
    database_t *db = &se->kernel->db;

    if (db->status != DB_STATUS_MOUNT && db->status != DB_STATUS_OPEN) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "recycle sharedpool only work in mount or open state");
        return CT_ERROR;
    }
    if (def->force_recycle) {
        ctx_flush_shared_pool(sql_pool);
    }
    pl_recycle_all();
    ctx_recycle_all();
    dc_recycle_all(se);

    if (sqlpool->free_pages.count > 0) {
        cm_spin_lock(&sqlpool->lock, NULL);
        if (sqlpool->free_pages.count > 0) {
            cm_spin_lock(&memory_area->lock, NULL);
            cm_concat_page_list(memory_area->maps, &memory_area->free_pages, &sqlpool->free_pages);
            cm_spin_unlock(&memory_area->lock);
            CM_ASSERT(sqlpool->page_count >= sqlpool->free_pages.count);
            sqlpool->page_count -= sqlpool->free_pages.count;
            sqlpool->free_pages.count = 0;
        }
        cm_spin_unlock(&sqlpool->lock);
    }
    if (dc_pool->free_pages.count > 0) {
        cm_spin_lock(&dc_pool->lock, NULL);
        if (dc_pool->free_pages.count > 0) {
            cm_spin_lock(&memory_area->lock, NULL);
            cm_concat_page_list(memory_area->maps, &memory_area->free_pages, &dc_pool->free_pages);
            cm_spin_unlock(&memory_area->lock);
            CM_ASSERT(dc_pool->page_count >= dc_pool->free_pages.count);
            dc_pool->page_count -= dc_pool->free_pages.count;
            dc_pool->free_pages.count = 0;
        }
        cm_spin_unlock(&dc_pool->lock);
    }

    return CT_SUCCESS;
}

static status_t sql_add_lsnr_addr_core(const char *value, int32 *slot_id, char *param_value)
{
    tcp_lsnr_t *lsnr = &g_instance->lsnr.tcp_service;

    for (uint32 loop = 0; loop < CT_MAX_LSNR_HOST_COUNT; loop++) {
        if (lsnr->socks[loop] != CS_INVALID_SOCKET && cm_str_equal(lsnr->host[loop], value)) {
            CT_THROW_ERROR(ERR_OBJECT_EXISTS, "lsnr address", value);
            return CT_ERROR;
        }
    }

    CT_RETURN_IFERR(cs_add_lsnr_ipaddr(lsnr, value, slot_id));

    /* modify global param */
    if (cs_strcat_host(lsnr, param_value, CT_PARAM_BUFFER_SIZE) != CT_SUCCESS) {
        (void)cs_delete_lsnr_slot(lsnr, *slot_id);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_add_lsnr_addr(sql_stmt_t *ctsql_stmt, const char *value)
{
    CM_POINTER(ctsql_stmt);
    knl_session_t *se = KNL_SESSION(ctsql_stmt);
    database_t *db = &se->kernel->db;
    char *param_name = "LSNR_ADDR";
    char param_value[CT_PARAM_BUFFER_SIZE] = { 0 };
    char ip_input_str[CM_MAX_IP_LEN] = { 0 };
    tcp_lsnr_t *lsnr = &g_instance->lsnr.tcp_service;
    int32 slot_id;

    if (db->status != DB_STATUS_MOUNT && db->status != DB_STATUS_OPEN) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "add lsnr address only work in mount or open state");
        return CT_ERROR;
    }
    /* check this addr is valid and existed */
    if (lsnr->sock_count == CT_MAX_LSNR_HOST_COUNT) {
        CT_THROW_ERROR(ERR_IPADDRESS_NUM_EXCEED, (uint32)CT_MAX_LSNR_HOST_COUNT);
        return CT_ERROR;
    }
    MEMS_RETURN_IFERR(memcpy_s(ip_input_str, CM_MAX_IP_LEN, value, CM_MAX_IP_LEN));
    if (!cm_is_local_ip(ip_input_str)) {
        CT_THROW_ERROR(ERR_IPADDRESS_LOCAL_NOT_EXIST, value);
        return CT_ERROR;
    }

    if (!cm_spin_try_lock(&g_instance->kernel.db.lock)) {
        CT_THROW_ERROR(ERR_SYSTEM_BUSY);
        return CT_ERROR;
    }
    status_t status = sql_add_lsnr_addr_core(value, &slot_id, param_value);
    cm_spin_unlock(&g_instance->kernel.db.lock);
    CT_RETURN_IFERR(status);

    if (cm_alter_config(se->kernel->attr.config, param_name, param_value, CONFIG_SCOPE_BOTH, CT_TRUE) != CT_SUCCESS) {
        (void)cs_delete_lsnr_slot(lsnr, slot_id);
        return CT_ERROR;
    }

    if (cm_modify_runtimevalue(se->kernel->attr.config, param_name, param_value) != CT_SUCCESS) {
        (void)cs_delete_lsnr_slot(lsnr, slot_id);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_delete_lsnr_addr_core(const char *value, uint32 current_sid, char *param_new_value)
{
    uint32 loop;
    tcp_lsnr_t *lsnr = &g_instance->lsnr.tcp_service;

    for (loop = 0; loop < CT_MAX_LSNR_HOST_COUNT; loop++) {
        if (lsnr->socks[loop] != CS_INVALID_SOCKET && cm_str_equal(lsnr->host[loop], value)) {
            break;
        }
    }
    if (loop == CT_MAX_LSNR_HOST_COUNT) {
        CT_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "lsnr", value);
        return CT_ERROR;
    }

    if (lsnr->sock_count <= 1) {
        CT_THROW_ERROR(ERR_LSNR_IP_DELETE_ERROR);
        return CT_ERROR;
    }

    srv_pause_lsnr(LSNR_TYPE_SERVICE);
    reactor_pause_pool();
    if ((cs_delete_lsnr_slot(lsnr, loop) != CT_SUCCESS)) {
        reactor_resume_pool();
        srv_resume_lsnr(LSNR_TYPE_SERVICE);
        return CT_ERROR;
    }
    srv_kill_session_byhost(value);
    srv_wait_session_free_byhost(current_sid, value);
    reactor_resume_pool();
    srv_resume_lsnr(LSNR_TYPE_SERVICE);

    /* modify global param */
    return cs_strcat_host(lsnr, param_new_value, CT_PARAM_BUFFER_SIZE);
}

static status_t sql_delete_lsnr_addr(sql_stmt_t *ctsql_stmt, const char *value)
{
    CM_POINTER(ctsql_stmt);
    knl_session_t *se = KNL_SESSION(ctsql_stmt);
    database_t *db = &se->kernel->db;
    uint32 current_sid = se->id;
    char *param_name = "LSNR_ADDR";
    char param_value[CT_PARAM_BUFFER_SIZE] = { 0 };

    if (db->status != DB_STATUS_MOUNT && db->status != DB_STATUS_OPEN) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "delete lsnr address only work in mount or open state");
        return CT_ERROR;
    }
    /* check this addr is valid and existed */
    if (!cm_spin_try_lock(&g_instance->kernel.db.lock)) {
        CT_THROW_ERROR(ERR_SYSTEM_BUSY);
        return CT_ERROR;
    }
    status_t status = sql_delete_lsnr_addr_core(value, current_sid, param_value);
    cm_spin_unlock(&g_instance->kernel.db.lock);
    CT_RETURN_IFERR(status);

    CT_RETURN_IFERR(cm_alter_config(se->kernel->attr.config, param_name, param_value, CONFIG_SCOPE_BOTH, CT_TRUE));

    CT_RETURN_IFERR(cm_modify_runtimevalue(se->kernel->attr.config, param_name, param_value));

    return CT_SUCCESS;
}

static status_t sql_verify_single_repl_addr(const char *ip, uint32 count, uint32 len)
{
    if (count >= CT_MAX_LSNR_HOST_COUNT) {
        CT_THROW_ERROR(ERR_IPADDRESS_NUM_EXCEED, (uint32)CT_MAX_LSNR_HOST_COUNT);
        return CT_ERROR;
    }

    if (len == 1 || !cm_check_ip_valid(ip)) {
        CT_THROW_ERROR(ERR_TCP_INVALID_IPADDRESS, (len == 1) ? "" : ip);
        return CT_ERROR;
    }

    if (!cm_is_local_ip(ip)) {
        CT_THROW_ERROR(ERR_IPADDRESS_LOCAL_NOT_EXIST, ip);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_verify_replication_addr(char *repl_ip, uint32 temp_len, char ip_arr[][CM_MAX_IP_LEN])
{
    uint32 ip_len = 0;
    uint32 ip_cnt = 0;
    char *ip = repl_ip;
    char *pos = NULL;
    uint32 len = temp_len;

    for (pos = repl_ip; len > 0; len--) {
        if (*pos != ',') {
            ip_len++;
            pos++;
            continue;
        }

        *pos = '\0';
        if (sql_verify_single_repl_addr(ip, ip_cnt, len) != CT_SUCCESS) {
            return CT_ERROR;
        }

        MEMS_RETURN_IFERR(memcpy_s(ip_arr[ip_cnt], CM_MAX_IP_LEN, ip, strlen(ip)));

        *pos = ',';
        ip += (ip_len + 1);
        ip_cnt++;
        ip_len = 0;
        pos = ip;
    }

    if (ip_len > 0) {
        if (sql_verify_single_repl_addr(ip, ip_cnt, len) != CT_SUCCESS) {
            return CT_ERROR;
        }

        MEMS_RETURN_IFERR(memcpy_s(ip_arr[ip_cnt], CM_MAX_IP_LEN, ip, strlen(ip)));
    }

    return CT_SUCCESS;
}

static status_t sql_modify_replica_pre_check(char *buf, const char *value, text_t *host, text_t *port,
    uint16 *replica_port, char ip_arr[][CM_MAX_IP_LEN])
{
    text_t replica_value;

    MEMS_RETURN_IFERR(strncpy_s(buf, CT_PARAM_BUFFER_SIZE, value, strlen(value)));
    cm_str2text(buf, &replica_value);
    (void)cm_split_rtext(&replica_value, ':', '\0', host, port);
    if (port->len != 0) {
        if (cm_text2uint16(port, replica_port) != CT_SUCCESS) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "the input port is invalid");
            return CT_ERROR;
        }
    } else {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "the port must be entered");
        return CT_ERROR;
    }

    if ((*replica_port) < CT_MIN_PORT && (*replica_port) != 0) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "the input port is too small");
        return CT_ERROR;
    }

    if (host->len != 0) {
        (void)cm_text2str(host, buf, CT_PARAM_BUFFER_SIZE);
        CT_RETVALUE_IFTRUE(sql_verify_replication_addr(buf, host->len, ip_arr), CT_ERROR);
    }

    return CT_SUCCESS;
}

static status_t sql_modify_replica(sql_stmt_t *ctsql_stmt, const char *value)
{
    CM_POINTER(ctsql_stmt);
    knl_session_t *se = KNL_SESSION(ctsql_stmt);
    char *host_name = "REPL_ADDR";
    char *port_name = "REPL_PORT";
    status_t status;
    tcp_lsnr_t *replica = &g_instance->lsnr.tcp_replica;
    text_t host, port;
    uint16 replica_port = 0;
    char buf[CT_PARAM_BUFFER_SIZE] = { 0 };
    char ip_arr[CT_MAX_LSNR_HOST_COUNT][CM_MAX_IP_LEN] = { 0 };

    bool32 has_nolog = CT_FALSE;
    CT_RETURN_IFERR(knl_database_has_nolog_object(se, &has_nolog));
    if (has_nolog) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "add standby host dynamic when database has nologging insert object");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_modify_replica_pre_check(buf, value, &host, &port, &replica_port, ip_arr));

    if (g_instance->kernel.attr.enable_arch_compress) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", forbid to mosify replica if ENABLE_ARCH_COMPRESS is TRUE");
        return CT_ERROR;
    }

    cm_spin_lock(&replica->lock, NULL);
    status = srv_modify_replica(ctsql_stmt->session, &host, replica_port, ip_arr);
    knl_set_replica(se, replica->port, CT_TRUE);
    cm_spin_unlock(&replica->lock);
    CT_RETURN_IFERR(status);

    if (host.len != 0) {
        CT_RETURN_IFERR(
            cm_alter_config(se->kernel->attr.config, host_name, host.str, CONFIG_SCOPE_BOTH, CT_TRUE));
        CT_RETURN_IFERR(cm_modify_runtimevalue(se->kernel->attr.config, host_name, host.str));
    }
    CT_RETURN_IFERR(cm_alter_config(se->kernel->attr.config, port_name, port.str, CONFIG_SCOPE_BOTH, CT_TRUE));
    CT_RETURN_IFERR(cm_modify_runtimevalue(se->kernel->attr.config, port_name, port.str));
    CT_LOG_RUN_INF("succeed to start replica lsnr on %u", replica->port);

    return CT_SUCCESS;
}

static status_t sql_stop_replica(sql_stmt_t *ctsql_stmt)
{
    CM_POINTER(ctsql_stmt);
    knl_session_t *se = KNL_SESSION(ctsql_stmt);
    database_t *db = &se->kernel->db;
    char *port_name = "REPL_PORT";

    tcp_lsnr_t *repl = &g_instance->lsnr.tcp_replica;
    char *replica_port = "0";

    if (db->status != DB_STATUS_MOUNT && db->status != DB_STATUS_OPEN) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "stop repl only works in mount or open state");
        return CT_ERROR;
    }

    cm_spin_lock(&repl->lock, NULL);
    if (repl->thread.closed) {
        CT_LOG_RUN_INF("repl lsnr has already been closed");
        cm_spin_unlock(&repl->lock);
        return CT_SUCCESS;
    }
    srv_stop_replica(ctsql_stmt->session);

    repl->port = 0;
    knl_set_replica(se, repl->port, CT_FALSE);
    cm_spin_unlock(&repl->lock);

    CT_RETURN_IFERR(
        cm_alter_config(se->kernel->attr.config, port_name, replica_port, CONFIG_SCOPE_BOTH, CT_TRUE));
    CT_RETURN_IFERR(cm_modify_runtimevalue(se->kernel->attr.config, port_name, replica_port));
    CT_LOG_RUN_INF("succeed to stop repl lsnr");

    return CT_SUCCESS;
}

status_t sql_add_hba_entry(sql_stmt_t *ctsql_stmt, const char *hba_str)
{
    char file_name[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    char write_content[HBA_MAX_LINE_SIZE + 1] = { 0 };
    PRTS_RETURN_IFERR(snprintf_s(file_name, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1, "%s/cfg/%s",
        g_instance->home, cthba_FILENAME));

    PRTS_RETURN_IFERR(sprintf_s(write_content, (size_t)(HBA_MAX_LINE_SIZE + 1), "\n%s", hba_str));

    CT_RETURN_IFERR(cm_write_hba_file(file_name, write_content, (uint32)strlen(write_content), CT_FALSE));

    return cm_load_hba(GET_WHITE_CTX, file_name);
}

status_t sql_del_hba_entry(sql_stmt_t *ctsql_stmt, const char *hba_str)
{
    char file_name[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    char swap_file_name[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    char del_content[HBA_MAX_LINE_SIZE + 1] = { 0 };

    PRTS_RETURN_IFERR(snprintf_s(file_name, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1, "%s/cfg/%s",
        g_instance->home, cthba_FILENAME));

    MEMS_RETURN_IFERR(strncpy_s(del_content, (size_t)(HBA_MAX_LINE_SIZE + 1), hba_str, strlen(hba_str)));

    PRTS_RETURN_IFERR(snprintf_s(swap_file_name, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1, "%s/cfg/%s",
        g_instance->home, cthba_SWAP_FILENAME));
    CT_RETURN_IFERR(cm_modify_hba_file(file_name, swap_file_name, del_content));
    return cm_load_hba(GET_WHITE_CTX, file_name);
}

status_t sql_execute_alter_system(sql_stmt_t *ctsql_stmt)
{
    knl_alter_sys_def_t *def = (knl_alter_sys_def_t *)ctsql_stmt->context->entry;

    switch (def->action) {
        case ALTER_SYS_SWITCHLOG:
            return knl_switch_log(&ctsql_stmt->session->knl_session);
        case ALTER_SYS_SET_PARAM:
            return sql_set_param(ctsql_stmt, def);
        case ALTER_SYS_LOAD_DC:
            return knl_load_sys_dc(&ctsql_stmt->session->knl_session, def);
        case ALTER_SYS_INIT_ENTRY:
            return knl_init_entry(&ctsql_stmt->session->knl_session, def);
        case ALTER_SYS_DUMP_PAGE:
            return knl_dump_page(&ctsql_stmt->session->knl_session, def);

        case ALTER_SYS_DUMP_CTRLPAGE:
            return knl_dump_ctrl_page(&ctsql_stmt->session->knl_session, def);
        case ALTER_SYS_DUMP_DC:
            return knl_dump_dc(&ctsql_stmt->session->knl_session, def);
        case ALTER_SYS_FLUSH_BUFFER:
            return knl_flush_buffer(&ctsql_stmt->session->knl_session, def);
        case ALTER_SYS_FLUSH_SQLPOOL:
            return sql_flush_sqlpool(ctsql_stmt);
        case ALTER_SYS_RECYCLE_SHAREDPOOL:
            return sql_recycle_sharedpool(ctsql_stmt, def);

        case ALTER_SYS_KILL_SESSION:
            CT_RETURN_IFERR(srv_kill_session(ctsql_stmt->session, def));
            return CT_SUCCESS;

        case ALTER_SYS_RESET_STATISTIC:
            return srv_reset_statistic(ctsql_stmt->session);

        case ALTER_SYS_CHECKPOINT:
            return knl_checkpoint(&ctsql_stmt->session->knl_session, def->ckpt_type);

        case ALTER_SYS_RELOAD_HBA:
            return srv_load_hba(CT_FALSE);

        case ALTER_SYS_RELOAD_PBL:
            return srv_load_pbl(CT_FALSE);

        case ALTER_SYS_ADD_HBA_ENTRY:
            return sql_add_hba_entry(ctsql_stmt, def->hba_node);

        case ALTER_SYS_REFRESH_SYSDBA:
            return srv_refresh_sysdba_privilege();
        case ALTER_SYS_ADD_LSNR_ADDR:
            return sql_add_lsnr_addr(ctsql_stmt, def->value);
        case ALTER_SYS_DELETE_LSNR_ADDR:
            return sql_delete_lsnr_addr(ctsql_stmt, def->value);
        case ALTER_SYS_DEL_HBA_ENTRY:
            return sql_del_hba_entry(ctsql_stmt, def->hba_node);
        case ALTER_SYS_DEBUG_MODE:
            return sql_set_debug_param(&ctsql_stmt->session->knl_session, def);
        case ALTER_SYS_MODIFY_REPLICA:
            return sql_modify_replica(ctsql_stmt, def->value);
        case ALTER_SYS_STOP_REPLICA:
            return sql_stop_replica(ctsql_stmt);
        case ALTER_SYS_STOP_BUILD:
            return knl_stop_build(&ctsql_stmt->session->knl_session);
        case ALTER_SYS_REPAIR_CATALOG:
            return knl_repair_catalog(&ctsql_stmt->session->knl_session);
        case ALTER_SYS_ARCHIVE_SET:
            return knl_set_arch_param(&ctsql_stmt->session->knl_session, def);
        default:
            CT_THROW_ERROR(ERR_INVALID_COMMAND, "ddl");
            return CT_ERROR;
    }
}

static status_t sql_execute_alter_session_set_commit(sql_stmt_t *ctsql_stmt, altset_def_t *def)
{
    CT_RETURN_IFERR(knl_set_commit(&ctsql_stmt->session->knl_session, &def->commit));
    return CT_SUCCESS;
}

static inline void sql_execute_alter_session_set_lockwait_timeout(sql_stmt_t *ctsql_stmt, altset_def_t *def)
{
    knl_set_lockwait_timeout(&ctsql_stmt->session->knl_session, &def->lock_wait_timeout);
}

static status_t sql_execute_alter_session_set_nls_params(sql_stmt_t *ctsql_stmt, altset_def_t *def)
{
    CT_RETURN_IFERR(cm_session_nls_seter(&(ctsql_stmt->session->nls_params), def->nls_seting.id, &def->nls_seting.value));
    CT_RETURN_IFERR(my_sender(ctsql_stmt)->send_nls_feedback(ctsql_stmt, def->nls_seting.id, &def->nls_seting.value));
    return CT_SUCCESS;
}

static status_t sql_execute_alter_session_set_schema(sql_stmt_t *ctsql_stmt, altset_def_t *def)
{
    uint32 schema_id;
    if (!knl_get_user_id(&ctsql_stmt->session->knl_session, &def->curr_schema, &schema_id)) {
        CT_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&def->curr_schema));
        return CT_ERROR;
    }

    /* change schema will not take effect immediately when execute procedure */
    if (ctsql_stmt->pl_exec != NULL) {
        if (def->curr_schema.len != 0) {
            MEMS_RETURN_IFERR(
                strncpy_s(ctsql_stmt->pl_set_schema, CT_NAME_BUFFER_SIZE, def->curr_schema.str, def->curr_schema.len));
        }
    } else {
        if (def->curr_schema.len != 0) {
            MEMS_RETURN_IFERR(
                strncpy_s(ctsql_stmt->session->curr_schema, CT_NAME_BUFFER_SIZE, def->curr_schema.str, def->curr_schema.len));
        }
        ctsql_stmt->session->curr_schema_id = schema_id;
    }
    return CT_SUCCESS;
}

static status_t sql_execute_alter_session_set_timezone(sql_stmt_t *ctsql_stmt, altset_def_t *def)
{
    CT_RETURN_IFERR(cm_text2tzoffset(&def->timezone_offset_name, &(ctsql_stmt->session->nls_params.client_timezone)));
    CT_RETURN_IFERR(my_sender(ctsql_stmt)->send_session_tz_feedback(ctsql_stmt, ctsql_stmt->session->nls_params.client_timezone));
    return CT_SUCCESS;
}

static inline void sql_execute_alter_session_set_explain_predicate(sql_stmt_t *ctsql_stmt, altset_def_t *def)
{
    if (def->on_off) {
        CT_BIT_SET(ctsql_stmt->session->plan_display_format, PLAN_FORMAT_TYPICAL);
    } else {
        CT_BIT_SET(ctsql_stmt->session->plan_display_format, PLAN_FORMAT_BASIC);
        CT_BIT_RESET(ctsql_stmt->session->plan_display_format, PLAN_FORMAT_PREDICATE);
    }
}

static status_t sql_execute_alter_session_set_tenant(sql_stmt_t *ctsql_stmt, altset_def_t *def)
{
    uint32 tenant_id;
    dc_user_t *user = NULL;
    text_t username;

    cm_str2text(ctsql_stmt->session->db_user, &username);
    if (dc_open_user_direct(&ctsql_stmt->session->knl_session, &username, &user)) {
        CT_THROW_ERROR(ERR_USER_NOT_EXIST, ctsql_stmt->session->db_user);
        return CT_ERROR;
    }

    if (user->desc.tenant_id != SYS_TENANTROOT_ID) {
        CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(knl_get_tenant_id(&ctsql_stmt->session->knl_session, &def->tenant, &tenant_id));
    if (def->tenant.len != 0) {
        MEMS_RETURN_IFERR(
            strncpy_s(ctsql_stmt->session->curr_tenant, CT_TENANT_BUFFER_SIZE, def->tenant.str, def->tenant.len));
    }
    ctsql_stmt->session->curr_tenant_id = tenant_id;
    return CT_SUCCESS;
}

static status_t sql_execute_alter_session_set(sql_stmt_t *ctsql_stmt, altset_def_t *def)
{
    switch (def->set_type) {
        case SET_COMMIT:
            return sql_execute_alter_session_set_commit(ctsql_stmt, def);
        case SET_LOCKWAIT_TIMEOUT:
            sql_execute_alter_session_set_lockwait_timeout(ctsql_stmt, def);
            return CT_SUCCESS;
        case SET_NLS_PARAMS:
            return sql_execute_alter_session_set_nls_params(ctsql_stmt, def);
        case SET_SCHEMA:
            return sql_execute_alter_session_set_schema(ctsql_stmt, def);
        case SET_SESSION_TIMEZONE:
            return sql_execute_alter_session_set_timezone(ctsql_stmt, def);
        case SET_SHOW_EXPLAIN_PREDICATE:
            sql_execute_alter_session_set_explain_predicate(ctsql_stmt, def);
            return CT_SUCCESS;
        case SET_TENANT:
            return sql_execute_alter_session_set_tenant(ctsql_stmt, def);
        case SET_OUTER_JOIN_OPT:
            ctsql_stmt->session->outer_join_optimization = def->on_off ? PARAM_ON : PARAM_OFF;
            return CT_SUCCESS;
        case SET_CBO_INDEX_CACHING:
            ctsql_stmt->session->cbo_param.cbo_index_caching = def->cbo_index_caching;
            return CT_SUCCESS;
        case SET_CBO_INDEX_COST_ADJ:
            ctsql_stmt->session->cbo_param.cbo_index_cost_adj = def->cbo_index_cost_adj;
            return CT_SUCCESS;
        case SET_WITHAS_SUBQUERY:
            ctsql_stmt->session->withas_subquery = def->withas_subquery;
            return CT_SUCCESS;
        case SET_CURSOR_SHARING:
            ctsql_stmt->session->cursor_sharing = def->on_off ? PARAM_ON : PARAM_OFF;
            return CT_SUCCESS;
        case SET_PLAN_DISPLAY_FORMAT:
            ctsql_stmt->session->plan_display_format = def->plan_display_format;
            return CT_SUCCESS;
        default:
            CT_THROW_ERROR(ERR_INVALID_COMMAND, "dcl");
            return CT_ERROR;
    }
}

static status_t sql_execute_alter_session_able(sql_stmt_t *ctsql_stmt, altable_def_t *def)
{
    switch (def->able_type) {
        case ABLE_TRIGGERS:
            ctsql_stmt->session->triggers_disable = !def->enable;
            break;

        case ABLE_INAV_TO:
            ctsql_stmt->session->interactive_info.is_on = def->enable;
            break;

        case ABLE_NOLOGGING:
            ctsql_stmt->session->nologging_enable = def->enable;
            break;

        case ABLE_OPTINFO:
            ctsql_stmt->session->optinfo_enable = def->enable;
            ctsql_stmt->session->optinfo_start = (def->enable) ? cm_monotonic_now() : 0;
            break;

        default:
            CT_THROW_ERROR(ERR_INVALID_COMMAND, "dcl");
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_execute_alter_session(sql_stmt_t *ctsql_stmt)
{
    alter_session_def_t *def = (alter_session_def_t *)ctsql_stmt->context->entry;

    switch (def->action) {
        case ALTSES_SET:
            return sql_execute_alter_session_set(ctsql_stmt, &def->setting);

        case ALTSES_DISABLE:
        case ALTSES_ENABLE:
            return sql_execute_alter_session_able(ctsql_stmt, &def->setable);

        default:
            CT_THROW_ERROR(ERR_INVALID_COMMAND, "dcl");
            return CT_ERROR;
    }
}

status_t sql_execute_commit_phase1(sql_stmt_t *ctsql_stmt)
{
    xa_xid_t *xid = (xa_xid_t *)ctsql_stmt->context->entry;

    ctsql_stmt->session->sql_audit.audit_type = SQL_AUDIT_DML;

    bool32 rdonly = CT_FALSE;
    return knl_xa_prepare(KNL_SESSION(ctsql_stmt), xid, (uint64)KNL_XA_DEFAULT, CT_INVALID_ID64, &rdonly);
}

status_t sql_execute_end_phase2(sql_stmt_t *ctsql_stmt)
{
    xa_xid_t *xid = (xa_xid_t *)ctsql_stmt->context->entry;
    ctsql_stmt->session->sql_audit.audit_type = SQL_AUDIT_DML;

    if (ctsql_stmt->context->type == CTSQL_TYPE_COMMIT_PHASE2) {
        return knl_xa_commit(KNL_SESSION(ctsql_stmt), xid, (uint64)KNL_XA_DEFAULT, CT_INVALID_ID64);
    } else {
        return knl_xa_rollback(KNL_SESSION(ctsql_stmt), xid, (uint64)KNL_XA_DEFAULT);
    }
}

status_t sql_execute_commit_force(sql_stmt_t *ctsql_stmt)
{
    knl_xid_t *xid = (knl_xid_t *)ctsql_stmt->context->entry;

    ctsql_stmt->session->sql_audit.audit_type = SQL_AUDIT_DML;

    return knl_commit_force(&ctsql_stmt->session->knl_session, xid);
}

status_t sql_execute_commit(sql_stmt_t *ctsql_stmt)
{
    if (ctsql_stmt->context->entry != NULL) {
        return sql_execute_commit_force(ctsql_stmt);
    }

    ctsql_stmt->session->sql_audit.audit_type = SQL_AUDIT_DML;
    (void)do_commit(ctsql_stmt->session);

    return CT_SUCCESS;
}

status_t sql_execute_rollback(sql_stmt_t *ctsql_stmt)
{
    ctsql_stmt->session->sql_audit.audit_type = SQL_AUDIT_DML;

    do_rollback(ctsql_stmt->session, NULL);
    return CT_SUCCESS;
}

status_t sql_execute_rollback_to(sql_stmt_t *ctsql_stmt)
{
    status_t status = CT_SUCCESS;
    text_t *name = (text_t *)ctsql_stmt->context->entry;
    ctsql_stmt->session->sql_audit.audit_type = SQL_AUDIT_DML;
    if (ctsql_stmt->is_sub_stmt && ctsql_stmt->parent_stmt != NULL) {
        sql_stmt_t *parent = (sql_stmt_t *)ctsql_stmt->parent_stmt;
        if (parent->context != NULL && SQL_TYPE(parent) >= CTSQL_TYPE_CREATE_PROC &&
            SQL_TYPE(parent) < CTSQL_TYPE_PL_CEIL_END) {
            pl_executor_t *exec = (pl_executor_t *)parent->pl_exec;
            CT_RETURN_IFERR(ple_check_rollback(exec, name, NULL));
        }
    }

    CT_RETURN_IFERR(knl_rollback_savepoint(&ctsql_stmt->session->knl_session, name));

    return status;
}

status_t sql_execute_savepoint(sql_stmt_t *ctsql_stmt)
{
    status_t status = CT_SUCCESS;

    text_t *name = (text_t *)ctsql_stmt->context->entry;
    CT_RETURN_IFERR(knl_set_savepoint(&ctsql_stmt->session->knl_session, name));
    if (ctsql_stmt->is_sub_stmt && ctsql_stmt->parent_stmt != NULL) {
        sql_stmt_t *parent = (sql_stmt_t *)ctsql_stmt->parent_stmt;
        if (parent->context != NULL && SQL_TYPE(parent) >= CTSQL_TYPE_CREATE_PROC &&
            SQL_TYPE(parent) < CTSQL_TYPE_PL_CEIL_END) {
            pl_executor_t *exec = (pl_executor_t *)parent->pl_exec;
            CT_RETURN_IFERR(ple_store_savepoint(parent, exec, name));
        }
    }
    return status;
}

static status_t sql_execute_release_savepoint(sql_stmt_t *ctsql_stmt)
{
    status_t status = CT_SUCCESS;

    text_t *name = (text_t *)ctsql_stmt->context->entry;
    CT_RETURN_IFERR(knl_release_savepoint(&ctsql_stmt->session->knl_session, name));

    return status;
}

static status_t sql_execute_set_trans(sql_stmt_t *ctsql_stmt)
{
    status_t ret;

    isolation_level_t isolevel = *(isolation_level_t *)ctsql_stmt->context->entry;
    if (IS_COORDINATOR && IS_APP_CONN(ctsql_stmt->session) && isolevel != ISOLATION_READ_COMMITTED) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ",Only support READ COMMITTED level");
        return CT_ERROR;
    }

    ret = knl_set_session_trans(&ctsql_stmt->session->knl_session, isolevel);
    return ret;
}

static status_t sql_execute_backup(sql_stmt_t *ctsql_stmt)
{
    knl_backup_t *param = (knl_backup_t *)ctsql_stmt->context->entry;
    CT_RETURN_IFERR(knl_backup(&ctsql_stmt->session->knl_session, param));
    if (ctsql_stmt->session->knl_session.kernel->backup_ctx.bak.has_badblock) {
        if (sql_try_send_backup_warning(ctsql_stmt) != CT_SUCCESS) {
            return CT_ERROR;
        }
        cm_reset_error();
    }
    return CT_SUCCESS;
}

static status_t sql_execute_restore(sql_stmt_t *ctsql_stmt)
{
    knl_restore_t *param = (knl_restore_t *)ctsql_stmt->context->entry;
    CT_RETURN_IFERR(knl_restore(&ctsql_stmt->session->knl_session, param));
    if (ctsql_stmt->session->knl_session.kernel->backup_ctx.bak.has_badblock) {
        if (sql_try_send_backup_warning(ctsql_stmt) != CT_SUCCESS) {
            return CT_ERROR;
        }
        cm_reset_error();
    }
    return CT_SUCCESS;
}

static status_t sql_execute_recover(sql_stmt_t *ctsql_stmt)
{
    knl_recover_t *param = (knl_recover_t *)ctsql_stmt->context->entry;
    return knl_recover(&ctsql_stmt->session->knl_session, param);
}

static status_t sql_execute_daac_recover(sql_stmt_t *ctsql_stmt)
{
    knl_daac_recover_t *param = (knl_daac_recover_t *)ctsql_stmt->context->entry;
    return knl_daac_recover(&ctsql_stmt->session->knl_session, param);
}

static status_t sql_execute_validate(sql_stmt_t *ctsql_stmt)
{
    knl_validate_t *param = (knl_validate_t *)ctsql_stmt->context->entry;
    return knl_validate(&ctsql_stmt->session->knl_session, param);
}

static status_t sql_execute_shutdown(sql_stmt_t *ctsql_stmt)
{
    CT_LOG_RUN_INF("sql begin to execute shutdown");
    shutdown_context_t *param = (shutdown_context_t *)ctsql_stmt->context->entry;

    return srv_shutdown(ctsql_stmt->session, param->mode);
}

static status_t sql_execute_lock_table(sql_stmt_t *ctsql_stmt)
{
    lock_tables_def_t *def = (lock_tables_def_t *)ctsql_stmt->context->entry;
    return knl_lock_tables(KNL_SESSION(ctsql_stmt), def);
}

static status_t sql_execute_build(sql_stmt_t *ctsql_stmt)
{
    knl_build_def_t *param = (knl_build_def_t *)ctsql_stmt->context->entry;
    return knl_build(&ctsql_stmt->session->knl_session, param);
}

#ifdef DB_DEBUG_VERSION
static status_t sql_execute_syncpoint(sql_stmt_t *ctsql_stmt)
{
    syncpoint_def_t *def = (syncpoint_def_t *)ctsql_stmt->context->entry;
    if (def->enable.str != NULL) {
        return knl_set_global_syncpoint(def);
    }

    if (def->signal.str != NULL || def->wait_for.str != NULL) {
        return knl_add_syncpoint(&ctsql_stmt->session->knl_session, def);
    }

    return knl_reset_syncpoint(&ctsql_stmt->session->knl_session);
}
#endif /* DB_DEBUG_VERSION */

static status_t sql_check_commit_for_dcl(sql_stmt_t *ctsql_stmt)
{
    switch (ctsql_stmt->context->type) {
        case CTSQL_TYPE_COMMIT_PHASE1:
        case CTSQL_TYPE_ALTER_SYSTEM:
        case CTSQL_TYPE_ALTER_SESSION:
        case CTSQL_TYPE_COMMIT_PHASE2:
        case CTSQL_TYPE_COMMIT:
        case CTSQL_TYPE_ROLLBACK_PHASE2:
        case CTSQL_TYPE_ROLLBACK:
        case CTSQL_TYPE_ROLLBACK_TO:
        case CTSQL_TYPE_SAVEPOINT:
        case CTSQL_TYPE_RELEASE_SAVEPOINT:
        case CTSQL_TYPE_SET_TRANS:
            return pl_check_trig_and_udf(ctsql_stmt->parent_stmt);
        default:
            return CT_SUCCESS;
    }
}

status_t sql_execute_dcl(sql_stmt_t *ctsql_stmt)
{
    status_t status;
    sql_set_scn(ctsql_stmt);
    sql_set_ssn(ctsql_stmt);

    ctsql_stmt->session->sql_audit.audit_type = SQL_AUDIT_DCL;
    if (sql_check_commit_for_dcl(ctsql_stmt) != CT_SUCCESS) {
        return CT_ERROR;
    }

    switch (ctsql_stmt->context->type) {
        case CTSQL_TYPE_COMMIT_PHASE1:
            status = sql_execute_commit_phase1(ctsql_stmt);
            break;
        case CTSQL_TYPE_ALTER_SYSTEM:
            status = sql_execute_alter_system(ctsql_stmt);
            break;
        case CTSQL_TYPE_ALTER_SESSION:
            status = sql_execute_alter_session(ctsql_stmt);
            break;
        case CTSQL_TYPE_COMMIT_PHASE2:
            status = sql_execute_end_phase2(ctsql_stmt);
            break;
        case CTSQL_TYPE_COMMIT:
            status = sql_execute_commit(ctsql_stmt);
            break;
        case CTSQL_TYPE_ROLLBACK_PHASE2:
            status = sql_execute_end_phase2(ctsql_stmt);
            break;
        case CTSQL_TYPE_ROLLBACK:
            status = sql_execute_rollback(ctsql_stmt);
            break;
        case CTSQL_TYPE_ROLLBACK_TO:
            status = sql_execute_rollback_to(ctsql_stmt);
            break;
        case CTSQL_TYPE_SAVEPOINT:
            status = sql_execute_savepoint(ctsql_stmt);
            break;
        case CTSQL_TYPE_RELEASE_SAVEPOINT:
            status = sql_execute_release_savepoint(ctsql_stmt);
            break;
#ifdef DB_DEBUG_VERSION
        case CTSQL_TYPE_SYNCPOINT:
            status = sql_execute_syncpoint(ctsql_stmt);
            break;
#endif
        case CTSQL_TYPE_SET_TRANS:
            status = sql_execute_set_trans(ctsql_stmt);
            break;
        case CTSQL_TYPE_BACKUP:
            status = sql_execute_backup(ctsql_stmt);
            break;
        case CTSQL_TYPE_RESTORE:
            status = sql_execute_restore(ctsql_stmt);
            break;
        case CTSQL_TYPE_RECOVER:
            status = sql_execute_recover(ctsql_stmt);
            break;
        case CTSQL_TYPE_DAAC:
            status = sql_execute_daac_recover(ctsql_stmt);
            break;
        case CTSQL_TYPE_SHUTDOWN:
            status = sql_execute_shutdown(ctsql_stmt);
            break;
        case CTSQL_TYPE_LOCK_TABLE:
            status = sql_execute_lock_table(ctsql_stmt);
            break;
        case CTSQL_TYPE_BUILD:
            status = sql_execute_build(ctsql_stmt);
            break;
        case CTSQL_TYPE_VALIDATE:
            status = sql_execute_validate(ctsql_stmt);
            break;
        default:
            ctsql_stmt->eof = CT_TRUE;
            CT_THROW_ERROR(ERR_INVALID_COMMAND, "dcl");
            return CT_ERROR;
    }

    return status;
}

#ifdef __cplusplus
}
#endif
