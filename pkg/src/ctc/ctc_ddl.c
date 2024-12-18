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
 * ctc_ddl.c
 *
 *
 * IDENTIFICATION
 * src/ctc/ctc_ddl.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctc_module.h"
#include "srv_instance.h"
#include "ctc_srv.h"
#include "dtc_ddl.h"
#include "dtc_dcs.h"
#include "ctc_srv_util.h"
#include "knl_interface.h"
#include "ddl_parser.h"
#include "ctsql_stmt.h"
#include "ddl_executor.h"
#include "dtc_dls.h"
#include "ctc_ddl.h"
#include "srv_param.h"
#include "srv_param_common.h"
#include "ctc_ddl_broadcast.h"
#include "ctc_mysql_client.h"
#include "ctsql_parser.h"
#include "dml_parser.h"
#include "ddl_column_parser.h"
#include "ctsql_func.h"
#include "ddl_table_parser.h"
#include "knl_table.h"
#include "knl_db_alter.h"
#include "knl_alter_space.h"
#include "db_defs.h"
#include "ctc_ddl_list.h"
#include "knl_dc.h"
#include "knl_lrepl_meta.h"
#include "srv_mq.h"

#define DEFAULT_NULL_TEXT_STR "NULL"
#define DEFAULT_NULL_TEXT_LEN 4

#define FK_RESTRICT_MODE 0
#define FK_CASCADE_MODE 1
#define FK_SET_NULL_MODE 2

#define META_SEARCH_TIMES 3
#define META_SEARCH_WAITING_TIME_IN_MS 10000

#define USER_LOCK_MAX_WAIT 10000

#ifndef MEM_CLASS_NUM
#define MEM_CLASS_NUM 27
#endif

typedef struct st_mysql_cantiandba_type {
    enum_ctc_ddl_field_types mysql_type;
    ct_type_t cantian_type;
} mysql_cantiandba_type_t;

mysql_cantiandba_type_t g_mysql_to_cantian_type[] = {
    { CTC_DDL_TYPE_LONG, CT_TYPE_INTEGER },
    { CTC_DDL_TYPE_TINY, CT_TYPE_INTEGER },
    { CTC_DDL_TYPE_SHORT, CT_TYPE_INTEGER },
    { CTC_DDL_TYPE_INT24, CT_TYPE_INTEGER },
    { CTC_DDL_TYPE_LONGLONG, CT_TYPE_BIGINT },
    { CTC_DDL_TYPE_DOUBLE, CT_TYPE_REAL },
    { CTC_DDL_TYPE_FLOAT, CT_TYPE_REAL },
    { CTC_DDL_TYPE_DECIMAL, CT_TYPE_NUMBER3 },
    { CTC_DDL_TYPE_NEWDECIMAL, CT_TYPE_NUMBER3 },  // 是否也用decimal类型
    { CTC_DDL_TYPE_NULL, CT_DATATYPE_OF_NULL },
    { CTC_DDL_TYPE_TIMESTAMP, CT_TYPE_TIMESTAMP },
    { CTC_DDL_TYPE_DATE, CT_TYPE_DATE_MYSQL },
    { CTC_DDL_TYPE_TIME, CT_TYPE_TIME_MYSQL },      // 确认是否用这个timestamp
    { CTC_DDL_TYPE_DATETIME, CT_TYPE_DATETIME_MYSQL },  // 确认是否和type date用一样的
    { CTC_DDL_TYPE_YEAR, CT_TYPE_DATE },
    { CTC_DDL_TYPE_NEWDATE, CT_TYPE_NATIVE_DATE },          // native datetime, internal used
    { CTC_DDL_TYPE_DATETIME2, CT_TYPE_NATIVE_DATE },        // native datetime, internal used
    { CTC_DDL_TYPE_TIMESTAMP2, CT_TYPE_NATIVE_TIMESTAMP },  // native datetime, internal used
    { CTC_DDL_TYPE_TIME2, CT_TYPE_NATIVE_TIMESTAMP },       // native datetime, internal used
    { CTC_DDL_TYPE_STRING, CT_TYPE_STRING },
    { CTC_DDL_TYPE_JSON, CT_TYPE_CLOB },
    { CTC_DDL_TYPE_VARCHAR, CT_TYPE_VARCHAR },
    { CTC_DDL_TYPE_VAR_STRING, CT_TYPE_VARCHAR },  // 待确定
    { CTC_DDL_TYPE_TYPED_ARRAY, CT_TYPE_ARRAY },
    { CTC_DDL_TYPE_TINY_BLOB, CT_TYPE_BLOB },  // tiny和medium blob待确认
    { CTC_DDL_TYPE_MEDIUM_BLOB, CT_TYPE_BLOB },
    { CTC_DDL_TYPE_BLOB, CT_TYPE_BLOB },
    { CTC_DDL_TYPE_CLOB, CT_TYPE_CLOB },
    { CTC_DDL_TYPE_LONG_BLOB, CT_TYPE_BLOB }
};

void ctc_ddl_clear_stmt(sql_stmt_t *stmt)
{
    if (stmt == NULL) {
        return;
    }
    ctc_ddl_def_list_clear(&stmt->ddl_def_list);
    sql_release_resource(stmt, CT_TRUE);
    sql_release_context(stmt);
    cm_reset_error();
    stmt->session->sql_audit.sql.len = 0;
    cm_stack_reset(stmt->session->knl_session.stack);
    stmt->eof = CT_TRUE;
    stmt->query_scn = CT_INVALID_ID64;
    stmt->gts_scn = CT_INVALID_ID64;
    stmt->v_systimestamp = CT_INVALID_INT64;
    stmt->session->call_version = CS_VERSION_0;
    stmt->tz_offset_utc = TIMEZONE_OFFSET_DEFAULT;
    if (stmt->session->active_stmts_cnt > 0) {
        stmt->session->active_stmts_cnt--;
    }

    if (stmt->session->stmts_cnt > 0) {
        stmt->session->stmts_cnt--;
    }
}

#define CT_RETURN_IFERR_EX(ret, stmt, ddl_ctrl)                                                                 \
    do {                                                                                                        \
        char *error_msg = (ddl_ctrl)->error_msg;                                                                \
        int _status_ = (ret);                                                                                   \
        if (_status_ != CT_SUCCESS) {                                                                           \
            int32 error_code = 0;                                                                               \
            char *message = NULL;                                                                               \
            cm_get_error(&error_code, (const char **)&message, NULL);                                           \
            CT_LOG_RUN_ERR("RETURN_IF_ERROR[%s,%d]error_code:%d,message:%s", __FILE__, __LINE__, error_code,    \
                           message == NULL ? "" : message);                                                     \
            if (error_code == 0 || message == NULL || (error_msg) == NULL) {                                    \
                ctc_ddl_clear_stmt(stmt);                                                                       \
                return _status_;                                                                                \
            }                                                                                                   \
            _status_ = strncpy_s(error_msg, ERROR_MESSAGE_LEN, message, strlen(message));                       \
            knl_securec_check(_status_);                                                                        \
            ctc_ddl_clear_stmt(stmt);                                                                           \
            return error_code;                                                                                  \
        }                                                                                                       \
    } while (0)

#define CT_RETURN_IFERR_NOCLEAR(ret, ddl_ctrl)                                                                  \
    do {                                                                                                        \
        char *error_msg = (ddl_ctrl)->error_msg;                                                                \
        int _status_ = (ret);                                                                                   \
        if (_status_ != CT_SUCCESS) {                                                                           \
            int32 error_code = 0;                                                                               \
            char *message = NULL;                                                                               \
            cm_get_error(&error_code, (const char **)&message, NULL);                                           \
            CT_LOG_RUN_ERR("RETURN_IF_ERROR[%s,%d]error_code:%d,message:%s", __FILE__, __LINE__, error_code,    \
                           message == NULL ? "" : message);                                                     \
            if (error_code == 0 || message == NULL || (error_msg) == NULL) {                                    \
                return _status_;                                                                                \
            }                                                                                                   \
            _status_ = strncpy_s(error_msg, ERROR_MESSAGE_LEN, message, strlen(message));                       \
            knl_securec_check(_status_);                                                                        \
            return error_code;                                                                                  \
        }                                                                                                       \
    } while (0)

static bool ctc_is_db_mysql_owner(const char *db_name)
{
    if (!strcmp(db_name, "mysql") || !strcmp(db_name, "information_schema") ||
        !strcmp(db_name, "performance_schema") || !strcmp(db_name, "sys")) {
        return true;
    }
    return false;
}

static bool ctc_check_db_exists(knl_session_t *session, const char *db_name)
{
    if (CM_IS_EMPTY_STR(db_name)) {
        CT_LOG_DEBUG_INF("ctc_check_db_exists db_name is empty");
        return false;
    }

    if (!DB_ATTR_MYSQL_META_IN_DACC(session)) {
        if (ctc_is_db_mysql_owner(db_name)) {
            return true;
        }
    }

    char buf[CTC_IDENTIFIER_MAX_LEN + 1];
    text_t text_db_name = { .str = buf, .len = 0 };
    cm_text_copy_from_str(&text_db_name, db_name, CTC_IDENTIFIER_MAX_LEN + 1);
    
    return spc_check_space_exists(session, &text_db_name, CT_TRUE);
}

int copy_broadcast_dbname_to_req(char *dst, int dst_len, const char *src)
{
    int len = strlen(src);
    if (len >= dst_len) {
        CT_LOG_RUN_ERR("str len : %d > %d", len, dst_len);
        return CT_ERROR;
    }
    errno_t errcode = memcpy_s(dst, dst_len, src, len);
    if (errcode != EOK) {
        return CT_ERROR;
    }
    dst[len] = '\0';
    return CT_SUCCESS;
}

static status_t ctc_ddl_reentrant_lock_user(session_t *session, dc_user_t *user, uint32 max_wait_time)
{
    knl_session_t *knl_session = &(session->knl_session);
    sql_stmt_t *stmt = session->current_stmt;

    if (user == NULL) {
        CT_LOG_RUN_INF("[CTC LOCK]: user is nullptr");
        return CT_SUCCESS;
    }

    if (knl_session->user_locked_lst == NULL) {
        CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(uint32) * (KNL_MAX_USER_LOCK + 1),
                                      (pointer_t *)&(knl_session->user_locked_lst)));
    }

    uint32 *user_num = knl_session->user_locked_lst;
    uint32 *user_locked_lst = knl_session->user_locked_lst;
    for (uint32 i = 0; i < *user_num; i++) {
        if (user_locked_lst[i + 1] == user->desc.id) {
            CT_LOG_RUN_INF("[CTC LOCK]: user has been locked");
            return CT_SUCCESS;
        }
    }

    if (*user_num == KNL_MAX_USER_LOCK) {
        CT_LOG_RUN_ERR("[CTC LOCK]: user lock num has reach limit");
        return CT_ERROR;
    }

    if (max_wait_time != CT_INVALID_ID32) {
        if (!dls_latch_timed_x(knl_session, &user->user_latch, 0, 1, NULL, max_wait_time)) {
            CT_THROW_ERROR_EX(ERR_LOCK_TIMEOUT, "Getting user lock timed out");
            CT_LOG_RUN_ERR("[CTC LOCK]: user %s is locked by reentrant lock fail", user->desc.name);
            return CT_ERROR;
        }
    } else {
        dls_latch_sx(knl_session, &user->user_latch, knl_session->id, NULL);
    }

    *user_num += 1;
    user_locked_lst[*user_num] = user->desc.id;
    CT_LOG_RUN_INF("[CTC LOCK]: user %s is locked by reentrant lock", user->desc.name);
    return CT_SUCCESS;
}

status_t ctc_ddl_lock_table(session_t *session, knl_dictionary_t *dc, dc_user_t *user, bool32 is_alter_copy)
{
    status_t status = CT_SUCCESS;
    knl_session_t *knl_session = &session->knl_session;
    sql_stmt_t *stmt = session->current_stmt;
    bool32 is_lock_ddl = (!is_alter_copy) && (knl_session->user_locked_ddl != DDL_ATOMIC_TABLE_LOCKED);
    drlatch_t *ddl_latch = &(knl_session->kernel->db.ddl_latch);

    if (!DB_IS_PRIMARY(&knl_session->kernel->db)) {
        CT_LOG_RUN_ERR("[CTC_DDL_LOCK_TABLE] DDL cannot be executed at the standby point.");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(ctc_ddl_reentrant_lock_user(session, user, CT_INVALID_ID32));

    do {
        if (is_lock_ddl) {
            status = knl_ddl_enabled(knl_session, CT_TRUE);
            if (status != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[CTC_DDL_LOCK_TABLE] Cantian Cluster is not avaliable.");
                break;
            }

            status = knl_ddl_latch_s(ddl_latch, knl_session, NULL);
            if (status != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[CTC_DDL_LOCK_TABLE] latch ddl failed");
                break;
            }
            knl_session->user_locked_ddl = DDL_ATOMIC_TABLE_LOCKED;
        }
        
        // The phase of the Alter COPY is DROP, is_alter_copy is true
        if (dc != NULL && !is_alter_copy && knl_lock_table_self_parent_child_directly(knl_session, dc) != CT_SUCCESS) {
            status = CT_ERROR;
            CT_LOG_RUN_ERR("[CTC_DDL_LOCK_TABLE] lock table failed");
            if (is_lock_ddl) {
                dls_unlatch(knl_session, ddl_latch, NULL);
            }
        }
    } while (0);

    if (status != CT_SUCCESS && user != NULL) {
        knl_unlock_users4mysql(knl_session);
    }
    return status;
}

static status_t ctc_ddl_lock_table4rename_cross_db(session_t *session, dc_user_t *user, dc_user_t *new_user)
{
    status_t status = CT_SUCCESS;
    knl_session_t *knl_session = &session->knl_session;
    drlatch_t *ddl_latch = &(knl_session->kernel->db.ddl_latch);

    if (user->desc.id < new_user->desc.id) {
        CT_RETURN_IFERR(ctc_ddl_reentrant_lock_user(session, user, USER_LOCK_MAX_WAIT));
        if (ctc_ddl_reentrant_lock_user(session, new_user, USER_LOCK_MAX_WAIT) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[CTC_DDL_LOCK_TABLE] not all user was locked.");
            knl_unlock_users4mysql(knl_session);
            return CT_ERROR;
        }
    } else {
        CT_RETURN_IFERR(ctc_ddl_reentrant_lock_user(session, new_user, USER_LOCK_MAX_WAIT));
        if (ctc_ddl_reentrant_lock_user(session, user, USER_LOCK_MAX_WAIT) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[CTC_DDL_LOCK_TABLE] not all user was locked.");
            knl_unlock_users4mysql(knl_session);
            return CT_ERROR;
        }
    }

    SYNC_POINT_GLOBAL_START(CTC_RENAME_CROSS_DB_LOCK_USER_DELAY, NULL, 5000); // delay 5000ms
    SYNC_POINT_GLOBAL_END;

    if (knl_session->user_locked_ddl != DDL_ATOMIC_TABLE_LOCKED) {
        if (knl_ddl_enabled(knl_session, CT_TRUE) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[CTC_DDL_LOCK_TABLE] Cantian Cluster is not avaliable.");
            knl_unlock_users4mysql(knl_session);
            return CT_ERROR;
        }

        if (knl_ddl_latch_s(ddl_latch, knl_session, NULL) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[CTC_DDL_LOCK_TABLE] latch ddl failed");
            knl_unlock_users4mysql(knl_session);
            return CT_ERROR;
        }
        knl_session->user_locked_ddl = DDL_ATOMIC_TABLE_LOCKED;
    }
    return CT_SUCCESS;
}

void ctc_ddl_unlock_table(knl_session_t *knl_session, bool unlock_tables)
{
    drlatch_t *ddl_latch = &(knl_session->kernel->db.ddl_latch);

    if (unlock_tables) {
        unlock_tables_directly(knl_session);
    }

    if (knl_session->user_locked_ddl == DDL_ATOMIC_TABLE_LOCKED) {
        dls_unlatch(knl_session, ddl_latch, NULL);
        knl_session->user_locked_ddl = CT_FALSE;
    }

    if (knl_unlock_users4mysql(knl_session) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC UNLOCK]: fail to unlock users");
    }

    return;
}

static inline msg_prepare_ddl_req_t ctc_init_ddl_req(ctc_handler_t *tch, ctc_lock_table_info *lock_info)
{
    msg_prepare_ddl_req_t req;
    req.tch = *tch;
    req.lock_info = *lock_info;
    req.msg_num = cm_random(CT_INVALID_ID32);
    req.db_name[0] = '\0';
    return req;
}

static inline void ctc_fill_execute_ddl_req(msg_execute_ddl_req_t *req, uint32_t thd_id,
    ctc_ddl_broadcast_request *broadcast_req, bool allow_fail)
{
    req->thd_id = thd_id;
    req->broadcast_req = *broadcast_req;
    req->msg_num = cm_random(CT_INVALID_ID32);
    req->allow_fail = allow_fail;
}

static inline void ctc_fill_execute_set_opt_req(void *req, uint32_t thd_id,
                                                ctc_set_opt_request *broadcast_req,
                                                bool allow_fail)
{   
    msg_execute_set_opt_req_t *msg_req = (msg_execute_set_opt_req_t *)req;
    msg_req->thd_id = thd_id;
    msg_req->broadcast_req = *broadcast_req;
    msg_req->msg_num = cm_random(CT_INVALID_ID32);
    msg_req->allow_fail = allow_fail;
}

static inline msg_invalid_dd_req_t ctc_fill_invalid_dd_req(ctc_handler_t *tch, ctc_invalidate_broadcast_request *broadcast_req)
{
    msg_invalid_dd_req_t req;
    req.broadcast_req = *broadcast_req;
    req.tch = *tch;
    req.msg_num = cm_random(CT_INVALID_ID32);
    return req;
}

static void ctc_write_lock_info_into_rd(rd_lock_info_4mysql_ddl *rd_lock_info, ctc_lock_table_info *lock_info)
{
    rd_lock_info->sql_type = lock_info->sql_type;
    rd_lock_info->mdl_namespace = lock_info->mdl_namespace;
    status_t ret;
    if (rd_lock_info->db_name_len > 0) {
        ret = memcpy_sp(rd_lock_info->buff, rd_lock_info->db_name_len, lock_info->db_name, rd_lock_info->db_name_len);
        knl_securec_check(ret);
    }
    if (rd_lock_info->table_name_len > 0) {
        ret = memcpy_sp(rd_lock_info->buff + rd_lock_info->db_name_len, rd_lock_info->table_name_len,
                        lock_info->table_name, rd_lock_info->table_name_len);
        knl_securec_check(ret);
    }
}

int ctc_lock_table_impl(ctc_handler_t *tch, knl_handle_t knl_session, const char *db_name,
                        ctc_lock_table_info *lock_info, int *error_code)
{
    char *broadcast_db_name = ctc_check_db_exists((knl_session_t *)knl_session, db_name) ? db_name : NULL;
    // 广播 mysqld
    int ret = ctc_ddl_execute_lock_tables_intf(tch, broadcast_db_name, lock_info, error_code);
    if (ret != CT_SUCCESS && DB_IS_PRIMARY(&g_instance->kernel.db)) {
        CT_LOG_RUN_ERR("[CTC_LOCK_TABLE]:execute failed at other mysqld on current node, error_code:%d"
                       "lock_info(db:%s, table:%s), conn_id:%u, ctc_instance_id:%u", *error_code,
                       lock_info->db_name, lock_info->table_name, tch->thd_id, tch->inst_id);
        return CT_ERROR;
    }

    // 广播 其他cantian节点
    msg_prepare_ddl_req_t req = ctc_init_ddl_req(tch, lock_info);
    if (!CM_IS_EMPTY_STR(broadcast_db_name) &&
        copy_broadcast_dbname_to_req(req.db_name, MES_DB_NAME_BUFFER_SIZE, broadcast_db_name) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_LOCK_TABLE]: strcpy failed, db_name=%s", broadcast_db_name);
        return CT_ERROR;
    }

    mes_init_send_head(&req.head, MES_CMD_PREPARE_DDL_REQ, sizeof(msg_prepare_ddl_req_t), CT_INVALID_ID32,
        DCS_SELF_INSTID((knl_session_t *)knl_session), 0, ((knl_session_t *)knl_session)->id, CT_INVALID_ID16);
    knl_panic(sizeof(msg_prepare_ddl_req_t) < MES_MESSAGE_BUFFER_SIZE);

    *error_code = ctc_broadcast_and_recv((knl_session_t *)knl_session, MES_BROADCAST_ALL_INST, &req, NULL);
    if (*error_code != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_LOCK_TABLE]:execute failed on remote node, err_code:%d, db_name %s,"
                       "lock_info(db:%s, table:%s), conn_id:%u, ctc_instance_id:%u", *error_code,
                       db_name, lock_info->db_name, lock_info->table_name, tch->thd_id, tch->inst_id);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static void ctc_write_rd_lock_info_4mysql_ddl(knl_session_t *knl_session, ctc_lock_table_info *lock_info, uint32 op_type)
{
    if (knl_db_is_primary(knl_session) && DB_ATTR_MYSQL_META_IN_DACC(knl_session)) {
        uint32_t db_name_size = strlen(lock_info->db_name);
        uint32_t table_name_size = strlen(lock_info->table_name);
        uint32_t rd_size = sizeof(rd_lock_info_4mysql_ddl) + db_name_size + table_name_size;
        rd_lock_info_4mysql_ddl *redo = (rd_lock_info_4mysql_ddl *)cm_malloc(rd_size);
        status_t ret = memset_sp(redo, rd_size, 0, rd_size);
        knl_securec_check(ret);
        redo->op_type = op_type;
        redo->db_name_len = db_name_size;
        redo->table_name_len = table_name_size;
        ctc_write_lock_info_into_rd(redo, lock_info);
        CT_LOG_DEBUG_INF("[ctc_write_rd_lock_info_4mysql_ddl] redo op_type = %d, db_name = %s, db_name_len = %d, "
                         "table_name = %s, table_name_len = %d, mdl_namespace = %d, sql_type = %d",
                         op_type, lock_info->db_name, db_name_size, lock_info->table_name, table_name_size,
                         lock_info->mdl_namespace, lock_info->sql_type);
        knl_lock_info_log_put4mysql(knl_session, redo);
        cm_free(redo);
    }
}

EXTER_ATTACK int ctc_lock_table(ctc_handler_t *tch, const char *db_name, ctc_lock_table_info *lock_info,
                                int *error_code)
{
    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    CT_RETURN_IFERR(ctc_get_or_new_session(&session, tch, true, false, &is_new_session));
    knl_session_t *knl_session = &session->knl_session;
    if (knl_session->user_locked_ddl == CT_TRUE) {
        CT_LOG_RUN_ERR("[CTC_LOCK_TABLE]: Instance has been locked, disallow this operation"
                       "lock_info(db=%s, table=%s), conn_id=%u, ctc_instance_id=%u",
                       lock_info->db_name, lock_info->table_name, tch->thd_id, tch->inst_id);
        *error_code = ERR_USER_DDL_LOCKED;
        return CT_ERROR;
    }

    CT_RETURN_IFERR(ctc_lock_table_impl(tch, knl_session, db_name, lock_info, error_code));

    ctc_write_rd_lock_info_4mysql_ddl(knl_session, lock_info, RD_LOCK_TABLE_FOR_MYSQL_DDL);

    if (tch->sql_command == SQLCOM_LOCK_INSTANCE) {
        CT_LOG_RUN_INF("[CTC_LOCK_INSTANCE]:ctc_inst_id:%u, conn_id:%u, "
                       "knl_session id:%u.", tch->inst_id, tch->thd_id, session->knl_session.id);
    }
    SYNC_POINT_GLOBAL_START(CTC_LOCK_TABLE_SUCC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    return CT_SUCCESS;
}

int ctc_broadcast_mysql_dd_invalidate_impl(ctc_handler_t *tch, knl_handle_t knl_session,
                                           ctc_invalidate_broadcast_request *broadcast_req)
{
    // 本节点的其他mysqld
    int error_code;
    status_t ret = ctc_invalidate_mysql_dd_cache_intf(tch, broadcast_req, &error_code);
    //metadata DDL in slave node continue broadcast
    if (ret != CT_SUCCESS && DB_IS_PRIMARY(&g_instance->kernel.db)) {
        CT_LOG_RUN_ERR("[CTC_DD_INVALID]:execute failed at other mysqld on current node, error_code:%d"
                       "conn_id:%u, ctc_instance_id:%u", error_code, tch->thd_id, tch->inst_id);
        return CT_ERROR;
    }
 
    // 广播 其他cantian节点
    msg_invalid_dd_req_t req = ctc_fill_invalid_dd_req(tch, broadcast_req);
    mes_init_send_head(&req.head, MES_CMD_INVALID_DD_REQ, sizeof(msg_invalid_dd_req_t), CT_INVALID_ID32,
        DCS_SELF_INSTID((knl_session_t *)knl_session), 0, ((knl_session_t *)knl_session)->id, CT_INVALID_ID16);
    knl_panic(sizeof(msg_invalid_dd_req_t) < MES_512K_MESSAGE_BUFFER_SIZE);
 
    SYNC_POINT_GLOBAL_START(CTC_BEFORE_INVALID_MYSQL_CACHE_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    (void)ctc_broadcast_and_recv((knl_session_t *)knl_session, MES_BROADCAST_ALL_INST, &req, NULL);
    SYNC_POINT_GLOBAL_START(CTC_AFTER_INVALID_MYSQL_CACHE_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    return CT_SUCCESS;
}

static void ctc_write_rd_invalid_dd_4mysql_ddl(knl_session_t *knl_session, ctc_invalidate_broadcast_request *broadcast_req)
{
    if (knl_db_is_primary(knl_session) && DB_ATTR_MYSQL_META_IN_DACC(knl_session)) {
        uint32_t rd_size = sizeof(rd_invalid_dd_4mysql_ddl) + broadcast_req->buff_len;
        rd_invalid_dd_4mysql_ddl *redo = (rd_invalid_dd_4mysql_ddl *)cm_malloc(rd_size);
        status_t ret = memset_sp(redo, rd_size, 0, rd_size);
        knl_securec_check(ret);
        redo->op_type = RD_INVALID_DD_FOR_MYSQL_DDL;
        redo->buff_len = broadcast_req->buff_len;
        redo->is_dcl = broadcast_req->is_dcl;
        if (broadcast_req->buff_len > 0) {
            ret = memcpy_sp(redo->buff, broadcast_req->buff_len, broadcast_req->buff, broadcast_req->buff_len);
            knl_securec_check(ret);
        }
        CT_LOG_DEBUG_INF("[ctc_write_rd_invalid_dd_4mysql_ddl] redo op_type = %d, redo buff = %s, "
                         "buff_len = %d, is_dcl = %u",
                         redo->op_type, broadcast_req->buff, broadcast_req->buff_len, broadcast_req->is_dcl);
        knl_invalid_dd_log_put4mysql(knl_session, redo);
        cm_free(redo);
    }
}

EXTER_ATTACK int ctc_broadcast_mysql_dd_invalidate(ctc_handler_t *tch, ctc_invalidate_broadcast_request *broadcast_req)
{
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    if (session == NULL) {
        status_t status = ctc_get_new_session(&session);
        if (status != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[CTC_DD_INVALID]:alloc new session failed, thdid %u", tch->thd_id);
            return status;
        }
        session->ctc_inst_id = tch->inst_id;
        session->ctc_thd_id = tch->thd_id;
        tch->sess_addr = (uint64)session;
        CT_LOG_DEBUG_INF("[CTC_DD_INVALID]:alloc new session for thd_id = %u", tch->thd_id);
    }
    ctc_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;

    CT_RETURN_IFERR(ctc_broadcast_mysql_dd_invalidate_impl(tch, knl_session, broadcast_req));
    ctc_write_rd_invalid_dd_4mysql_ddl(knl_session, broadcast_req);

    return CT_SUCCESS;
}

// 参天需要执行的，走此接口
int ctc_put_ddl_sql_2_stmt(session_t *session, const char *db_name, const char *sql_str)
{
    sql_stmt_t *stmt = session->current_stmt;
    knl_session_t *knl_session = &session->knl_session;
    if (DB_ATTR_MYSQL_META_IN_DACC(knl_session) && DB_SQL_SERVER_INITIALIZING(knl_session)) {
        return CT_SUCCESS;
    }

    int ret;
    int len = strlen(sql_str);
    if (len == 0) {
        return CT_SUCCESS;
    }
    if (len < 0) {
        CT_LOG_RUN_ERR("[CTC_DDL]:ctc_put_ddl_sql_2_stmt length is invalid");
        return CT_ERROR;
    }
    char *my_sql_str = NULL;
    my_sql_str = (char *)malloc(len + 1);
    CTC_LOG_RET_VAL_IF_NUL(my_sql_str, CT_ERROR, "[CTC_DDL]:ctc_put_ddl_sql_2_stmt fail to malloc my_sql_str");
    ret = strcpy_s(my_sql_str, len + 1, sql_str);
    knl_securec_check(ret);
    if (my_sql_str[len - 1] == ';') {
        my_sql_str[len - 1] = '\0';  // 将最后一个;去掉，避免sql语句语法错误
    }
    text_t sql = { 0 };
    sql.len = strlen(db_name) + strlen(my_sql_str) + SMALL_RECORD_SIZE; // use XXX_DB; sql;
    sql.str = (char *)malloc(sql.len * sizeof(char));
    if (sql.str == NULL) {
        CM_FREE_PTR(my_sql_str);
        return CT_ERROR;
    }
    if (strlen(db_name) > 0) {
        // keep a semicolon after use db, for keey synatx correct in disaster recovery in slave cluster.
        ret = sprintf_s(sql.str, sql.len, "use %s\n%s", db_name, my_sql_str);
    } else {
        ret = sprintf_s(sql.str, sql.len, "%s", my_sql_str);
    }
    if (ret == -1) {
        free(my_sql_str);
        free(sql.str);
        return CT_ERROR;
    }
    sql.len = strlen(sql.str);
    stmt->lang_type = LANG_DDL;
    if (ctx_write_text(&stmt->context->ctrl, &sql) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_DDL]:ctc_put_ddl_sql_2_stmt fail to put sql to stmt");
        free(my_sql_str);
        free(sql.str);
        return CT_ERROR;
    }
    stmt->context->ctrl.hash_value = cm_hash_text(&sql, INFINITE_HASH_RANGE);
    free(my_sql_str);
    free(sql.str);
    knl_session->uid = DB_PUB_USER_ID;
    return CT_SUCCESS;
}

int ctc_put_ddl_sql_2_stmt_not_cantian_exe(session_t *session, ctc_ddl_broadcast_request *broadcast_req)
{
    knl_session_t *knl_session = &session->knl_session;
    if (DB_ATTR_MYSQL_META_IN_DACC(knl_session) && DB_SQL_SERVER_INITIALIZING(knl_session)) {
        return CT_SUCCESS;
    }

    // 参天需要执行的，不走此接口
    if (!(broadcast_req->options & CTC_NOT_NEED_CANTIAN_EXECUTE)) {
        return CT_SUCCESS;
    }
    
    if (broadcast_req->sql_command == SQLCOM_SET_OPTION || broadcast_req->sql_command == SQLCOM_LOCK_INSTANCE ||
        broadcast_req->sql_command == SQLCOM_UNLOCK_INSTANCE) {
        return CT_SUCCESS;
    }

    bool alloc_stmt = false;
    if (session->current_stmt == NULL) {
        CT_RETURN_IFERR(sql_alloc_stmt(session, &session->current_stmt));
        alloc_stmt = true;
    }

    if (session->current_stmt != NULL && session->current_stmt->context != NULL) {
        sql_release_context(session->current_stmt);
    }
    sql_alloc_context(session->current_stmt);
    sql_stmt_t *stmt = session->current_stmt;
    int ret = ctc_put_ddl_sql_2_stmt(session, broadcast_req->db_name, broadcast_req->sql_str);
    // Do not record ddl log for standby cluster.
    if (knl_db_is_primary(session)) {
        (void)knl_put_ddl_sql(knl_session, stmt);
    }

    sql_release_context(session->current_stmt);

    if (alloc_stmt) {
        sql_free_stmt(session->current_stmt);
        session->current_stmt = NULL;
    }
    return ret;
}

int ctc_ddl_execute_and_broadcast(ctc_handler_t *tch, ctc_ddl_broadcast_request *broadcast_req,
    bool allow_fail, knl_session_t *knl_session)
{
    status_t ret = mysql_execute_ddl_sql(tch->thd_id, broadcast_req, &allow_fail);

    if (!knl_db_is_primary(knl_session)) {
        // Repeatedlly try to execute on current node.
        if (ret != CT_SUCCESS) {
            CT_LOG_DEBUG_INF("[Disaster Recovery] Failed to reform ddl at mysqld on current node, "
                    "sql_str:%s, user_name:%s, sql_command:%u, err_code:%d, err_msg:%s, conn_id:%u, ctc_instance_id:%u, allow_fail:%d",
                    broadcast_req->sql_str, broadcast_req->user_name, broadcast_req->sql_command, broadcast_req->err_code,
                    broadcast_req->err_msg, tch->thd_id, tch->inst_id, allow_fail);
            cm_sleep(1000);
            CT_LOG_RUN_INF("Retrying to reform this ddl......");
            ret = mysql_execute_ddl_sql(tch->thd_id, broadcast_req, &allow_fail);
        }
    }
    CT_LOG_DEBUG_INF("[Disaster Recovery] In ctc_ddl_execute_and_broadcast, knl_is_primary: %d, ret: %d, ddl:%s", knl_db_is_primary(knl_session), (int)ret, broadcast_req->sql_str);

    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_DDL]:execute failed at other mysqld on current node, ret:%d, sql_str:%s,"
            "user_name:%s, sql_command:%u, err_code:%d, err_msg:%s, conn_id:%u, ctc_instance_id:%u, allow_fail:%d",
            ret, sql_without_plaintext_password((broadcast_req->options & CTC_CURRENT_SQL_CONTAIN_PLAINTEXT_PASSWORD),
            broadcast_req->sql_str, strlen(broadcast_req->sql_str)),
            broadcast_req->user_name, broadcast_req->sql_command, broadcast_req->err_code, broadcast_req->err_msg,
            tch->thd_id, tch->inst_id, allow_fail);
        return CT_ERROR;
    }

    msg_execute_ddl_req_t req;
    ctc_fill_execute_ddl_req(&req, tch->thd_id, broadcast_req, allow_fail);
    mes_init_send_head(&req.head, MES_CMD_EXECUTE_DDL_REQ, sizeof(msg_execute_ddl_req_t), CT_INVALID_ID32, DCS_SELF_INSTID(knl_session), 0, knl_session->id,
        CT_INVALID_ID16);
    knl_panic(sizeof(msg_execute_ddl_req_t) < MES_512K_MESSAGE_BUFFER_SIZE);

    int error_code = ctc_broadcast_and_recv(knl_session, MES_BROADCAST_ALL_INST, &req, &broadcast_req->err_msg);
    if (!knl_db_is_primary(knl_session)) {
        // Repeatedlly try to execute on current node.
        if (error_code != CT_SUCCESS) {
            CT_LOG_DEBUG_INF("[Disaster Recovery] Failed to reform ddl at mysqld on remote node, "
                    "sql_str:%s, user_name:%s, sql_command:%u, err_code:%d, err_msg:%s, conn_id:%u, ctc_instance_id:%u, allow_fail:%d",
                    broadcast_req->sql_str, broadcast_req->user_name, broadcast_req->sql_command, broadcast_req->err_code,
                    broadcast_req->err_msg, tch->thd_id, tch->inst_id, allow_fail);
            cm_sleep(1000);
            CT_LOG_RUN_INF("Retrying to reform this ddl on remote node......");
            error_code = ctc_broadcast_and_recv(knl_session, MES_BROADCAST_ALL_INST, &req, &broadcast_req->err_msg);
        }
    }
    CT_LOG_DEBUG_INF("[Disaster Recovery] In ctc_ddl_execute_and_broadcast, broadcast err_code: %d, ddl:%s",
                     error_code, broadcast_req->sql_str);
    if (error_code != CT_SUCCESS && allow_fail == true) {
        broadcast_req->err_code = error_code;
        CT_LOG_RUN_ERR("[CTC_DDL_REWRITE]:execute on other mysqld fail. error_code:%d", error_code);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

int mysql_set_opt_and_retry(ctc_handler_t *tch, ctc_set_opt_request *broadcast_req, knl_session_t *knl_session, bool allow_fail){
    status_t ret = mysql_execute_set_opt(tch->thd_id, broadcast_req, allow_fail);
    if (!knl_db_is_primary(knl_session)) {
        // Repeatedlly try to execute on current node.
        if (ret != CT_SUCCESS) {
            CT_LOG_DEBUG_INF("[Disaster Recovery] Failed to set opt at mysqld on current node, "
                    "err_code:%d, err_msg:%s, conn_id:%u, ctc_instance_id:%u, allow_fail:%d",
                    broadcast_req->err_code, broadcast_req->err_msg,
                    tch->thd_id, tch->inst_id, allow_fail);
            cm_sleep(1000);
            CT_LOG_RUN_INF("Retrying to reform this set opt......");
            ret = mysql_execute_set_opt(tch->thd_id, broadcast_req, allow_fail);
        }
    }
    CT_LOG_DEBUG_INF("[Disaster Recovery] In ctc_set_opt_and_broadcast, knl_is_primary: %d, ret: %d", knl_db_is_primary(knl_session), (int)ret);

    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_SET_OPT]:execute failed at other mysqld on current node, ret:%d, "
            "err_code:%d, err_msg:%s, conn_id:%u, ctc_instance_id:%u, allow_fail:%d",
            ret, broadcast_req->err_code, broadcast_req->err_msg,
            tch->thd_id, tch->inst_id, allow_fail);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

int set_opt_broadcast_and_retry(ctc_handler_t *tch, ctc_set_opt_request *broadcast_req,
                                knl_session_t *knl_session, void *req, bool allow_fail){
    int error_code = ctc_broadcast_and_recv(knl_session, MES_BROADCAST_ALL_INST, req, &broadcast_req->err_msg);
    if (!knl_db_is_primary(knl_session)) {
        // Repeatedlly try to execute on current node.
        if (error_code != CT_SUCCESS) {
            CT_LOG_DEBUG_INF("[Disaster Recovery] Failed to reform set opt at mysqld on remote node, "
                    "err_code:%d, err_msg:%s, conn_id:%u, ctc_instance_id:%u, allow_fail:%d",
                    broadcast_req->err_code, broadcast_req->err_msg, tch->thd_id, tch->inst_id, allow_fail);
            cm_sleep(1000);
            CT_LOG_RUN_INF("Retrying to reform this set opt on remote node......");
            error_code = ctc_broadcast_and_recv(knl_session, MES_BROADCAST_ALL_INST, &req, &broadcast_req->err_msg);
        }
    }
    CT_LOG_DEBUG_INF("[Disaster Recovery] In ctc_set_opt_and_broadcast, broadcast err_code: %d", error_code);
    if (error_code != CT_SUCCESS) {
        broadcast_req->err_code = error_code;
        CT_LOG_RUN_ERR("[SET_OPT_BROADCAST_AND_RETRY]:execute on other mysqld fail. error_code:%d", error_code);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

int ctc_set_opt_and_broadcast(ctc_handler_t *tch, ctc_set_opt_request *broadcast_req, knl_session_t *knl_session, bool allow_fail)
{
    uint32_t req_size = sizeof(msg_execute_set_opt_req_t) + (broadcast_req->opt_num * sizeof(set_opt_info_t));
    void *req = cm_push(knl_session->stack, req_size);
    if (req == NULL) {
        CT_LOG_RUN_ERR("msg failed to malloc memory");
        return CT_ERROR;
    }
    ctc_fill_execute_set_opt_req(req, tch->thd_id, broadcast_req, allow_fail);
    errno_t err_s;
    err_s = memcpy_s(req + sizeof(msg_execute_set_opt_req_t), broadcast_req->opt_num * sizeof(set_opt_info_t),
                    broadcast_req->set_opt_info, broadcast_req->opt_num * sizeof(set_opt_info_t));
    knl_securec_check(err_s);
    msg_execute_set_opt_req_t *msg_req = (msg_execute_set_opt_req_t *)req;
    mes_init_send_head(&msg_req->head, MES_CMD_EXECUTE_SET_OPT_REQ, req_size,
                       CT_INVALID_ID32, DCS_SELF_INSTID(knl_session), 0, knl_session->id, CT_INVALID_ID16);

    status_t ret = CT_SUCCESS;
    ret = set_opt_broadcast_and_retry(tch, broadcast_req, knl_session, req, allow_fail);
    cm_pop(knl_session->stack);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_SET_OPT_AND_BROADCAST]:failed to execute broadcast and retry, ret:%d", ret);
        return CT_ERROR;
    }

    ret = mysql_set_opt_and_retry(tch, broadcast_req, knl_session, allow_fail);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_SET_OPT_AND_BROADCAST]:failed to execute set opt and retry in mysql, ret:%d", ret);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t ddl_drop_table_rewrite_sql(bilist_t *def_list, char* broadcast_sql_str)
{
    char sql_str[MAX_DDL_SQL_LEN];
    MEMS_RETURN_IFERR(strcpy_s(sql_str, MAX_DDL_SQL_LEN, "drop table "));
    int offset = strlen(sql_str);
    int ret;
    int max_len;
    bilist_node_t *node = cm_bilist_head(def_list);
    for (; node != NULL; node = BINODE_NEXT(node)) {
        ctc_ddl_def_node_t *def_node = (ctc_ddl_def_node_t *)BILIST_NODE_OF(ctc_ddl_def_node_t, node, bilist_node);
        knl_panic(def_node->def_mode == DROP_DEF);
        knl_drop_def_t *drop_def = (knl_drop_def_t *)def_node->ddl_def;
        text_t table = drop_def->name;
        text_t db = drop_def->owner;
        max_len = MAX_DDL_SQL_LEN - offset;
        ret = snprintf_s(sql_str + offset, max_len, max_len - 1, "`%s`.`%s`, ", db.str, table.str);
        knl_securec_check_ss(ret);
        offset += ret;
    }
    uint32 len = strlen(sql_str);
    sql_str[len - 2] = '\0'; // get rid of char at -2, which always being ','
    MEMS_RETURN_IFERR(strcat_s(sql_str, MAX_DDL_SQL_LEN, ";"));
    CT_RETURN_IFERR(strcpy_s(broadcast_sql_str, MAX_DDL_SQL_LEN, sql_str));
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_execute_mysql_ddl_sql(ctc_handler_t *tch, ctc_ddl_broadcast_request *broadcast_req,
                                           bool allow_fail)
{
    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    CT_RETURN_IFERR(ctc_get_or_new_session(&session, tch, true, false, &is_new_session));
    knl_session_t *knl_session = &session->knl_session;
    if (DB_ATTR_MYSQL_META_IN_DACC(knl_session) && !(broadcast_req->sql_command == SQLCOM_SET_OPTION)) {
        return CT_SUCCESS;
    }
    session->query_id = tch->query_id;
    
    if (broadcast_req->sql_command != SQLCOM_SET_OPTION && !ctc_check_db_exists(knl_session, broadcast_req->db_name)) {
        broadcast_req->db_name[0] = '\0';
    }
    if (!DB_ATTR_MYSQL_META_IN_DACC(knl_session) && broadcast_req->sql_command == SQLCOM_DROP_TABLE) {
        sql_stmt_t *stmt = (sql_stmt_t *)session->current_stmt;
        CT_RETURN_IFERR(ddl_drop_table_rewrite_sql(&stmt->ddl_def_list, &broadcast_req->sql_str));
        ctc_ddl_clear_stmt(stmt);
    }
    int ret = ctc_ddl_execute_and_broadcast(tch, broadcast_req, allow_fail, knl_session);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_DDL]:ctc_ddl_execute_and_broadcast faile. sql_str:%s, user_name:%s,"
            "sql_command:%u, err_code:%d, conn_id:%u, ctc_instance_id:%u, allow_fail:%d",
            sql_without_plaintext_password((broadcast_req->options & CTC_CURRENT_SQL_CONTAIN_PLAINTEXT_PASSWORD),
            broadcast_req->sql_str, strlen(broadcast_req->sql_str)),
            broadcast_req->user_name, broadcast_req->sql_command, broadcast_req->err_code,
            tch->thd_id, tch->inst_id, allow_fail);
        return CT_ERROR;
    }

    SYNC_POINT_GLOBAL_START(CTC_DDL_SUCC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    CT_RETURN_IFERR(ctc_put_ddl_sql_2_stmt_not_cantian_exe(session, broadcast_req));
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_execute_set_opt(ctc_handler_t *tch, ctc_set_opt_request *broadcast_req, bool allow_fail)
{
    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    CT_RETURN_IFERR(ctc_get_or_new_session(&session, tch, true, false, &is_new_session));
    knl_session_t *knl_session = &session->knl_session;

    int ret = ctc_set_opt_and_broadcast(tch, broadcast_req, knl_session, allow_fail);

    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_SET_OPT]:ctc_set_opt_and_broadcast failed. "
            "err_code:%d, conn_id:%u, ctc_instance_id:%u, allow_fail:%d",
            broadcast_req->err_code, tch->thd_id, tch->inst_id, allow_fail);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

int ctc_rewrite_open_conn(ctc_handler_t *tch, ctc_ddl_broadcast_request *broadcast_req,
    knl_session_t *knl_session)
{
    // 本节点的其他mysqld
    status_t ret = ctc_execute_rewrite_open_conn_intf(tch->thd_id, broadcast_req);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_REWRITE_CONN]:execute failed at other mysqld on current node, ret:%d,"
            "sql_str:%s, user_name:%s, sql_command:%u, err_code:%d, conn_id:%u, ctc_instance_id:%u",
            ret, sql_without_plaintext_password((broadcast_req->options & CTC_CURRENT_SQL_CONTAIN_PLAINTEXT_PASSWORD),
            broadcast_req->sql_str, strlen(broadcast_req->sql_str)),
            broadcast_req->user_name, broadcast_req->sql_command, broadcast_req->err_code,
            tch->thd_id, tch->inst_id);
        return CT_ERROR;
    }

    msg_execute_ddl_req_t req;
    ctc_fill_execute_ddl_req(&req, tch->thd_id, broadcast_req, true);
    mes_init_send_head(&req.head, MES_CMD_REWRITE_OPEN_CONN_REQ, sizeof(msg_execute_ddl_req_t), CT_INVALID_ID32,
        DCS_SELF_INSTID(knl_session), 0, knl_session->id, CT_INVALID_ID16);
    knl_panic(sizeof(msg_execute_ddl_req_t) < MES_512K_MESSAGE_BUFFER_SIZE);

    int error_code = ctc_broadcast_and_recv(knl_session, MES_BROADCAST_ALL_INST, &req, NULL);
    if (error_code != CT_SUCCESS) {
        broadcast_req->err_code = error_code;
        CT_LOG_RUN_ERR("[CTC_REWRITE_CONN]:execute on other mysqld fail. error_code:%d", error_code);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_broadcast_rewrite_sql(ctc_handler_t *tch, ctc_ddl_broadcast_request *broadcast_req,
                                           bool allow_fail)
{
    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    CT_RETURN_IFERR(ctc_get_or_new_session(&session, tch, true, false, &is_new_session));
    
    knl_session_t *knl_session = &session->knl_session;
    if (!ctc_check_db_exists(knl_session, broadcast_req->db_name)) {
        broadcast_req->db_name[0] = '\0';
    }

    // 全局开连接
    int ret = ctc_rewrite_open_conn(tch, broadcast_req, knl_session);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_REWRITE_CONN]:Open connections faile for ctc_ddl_rewrite.");
        return CT_ERROR;
    }

    // 开连接后执行
    ret = ctc_ddl_execute_and_broadcast(tch, broadcast_req, allow_fail, knl_session);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_DDL_REWRITE]:ctc_ddl_execute_and_broadcast faile. sql_str:%s, user_name:%s,"
            "sql_command:%u, err_code:%d, err_msg:%s, conn_id:%u, ctc_instance_id:%u, allow_fail:%d",
            sql_without_plaintext_password((broadcast_req->options & CTC_CURRENT_SQL_CONTAIN_PLAINTEXT_PASSWORD),
            broadcast_req->sql_str, strlen(broadcast_req->sql_str)), broadcast_req->user_name,
            broadcast_req->sql_command, broadcast_req->err_code, broadcast_req->err_msg, tch->thd_id,
            tch->inst_id, allow_fail);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(ctc_put_ddl_sql_2_stmt_not_cantian_exe(session, broadcast_req));
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_record_sql_for_cantian(ctc_handler_t *tch, ctc_ddl_broadcast_request *broadcast_req,
                                            bool allow_fail)
{
    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    CT_RETURN_IFERR(ctc_get_or_new_session(&session, tch, true, false, &is_new_session));

    knl_session_t *knl_session = &session->knl_session;
    if (!ctc_check_db_exists(knl_session, broadcast_req->db_name)) {
        broadcast_req->db_name[0] = '\0';
    }

    CT_RETURN_IFERR(ctc_put_ddl_sql_2_stmt_not_cantian_exe(session, broadcast_req));
    return CT_SUCCESS;
}

int ctc_close_mysql_connection(ctc_handler_t *tch)
{
    int ret;
    // 广播 mysqld
    if (tch->is_broadcast == true) {
        ret = close_mysql_connection_intf(tch->thd_id, tch->inst_id);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[CTC_CLOSE_SESSION]:execute failed at other mysqld on current node, "
                "ret = %d, conn_id:%u, inst_id:%u.", ret, tch->thd_id, tch->inst_id);
            return ret;
        }
    }

    // TODO: 依赖MES的故障处理方案, 现在节点故障后节点间广播会失败返错,导致整个清理流程失败
    if ((uint16_t)(tch->inst_id) == (uint16_t)CANTIAN_DOWN_MASK) {
        CT_LOG_RUN_ERR("[CTC_CLOSE_SESSION]:Clean bad node resourses not broadcast to other node YET!");
        return ret;
    }

    // 广播 其他cantian节点
    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    CT_RETURN_IFERR(ctc_get_or_new_session(&session, tch, true, false, &is_new_session));
    if (is_new_session) {
        tch->sess_addr = INVALID_VALUE64; // 此处不能把这个session传出去，避免外面没释放session,导致这个地方session泄漏
    }
    knl_session_t *knl_session = &session->knl_session;
    msg_close_connection_req_t req;
    req.thd_id = tch->thd_id;
    req.mysql_inst_id = tch->inst_id;
    req.msg_num = cm_random(CT_INVALID_ID32);
    mes_init_send_head(&req.head, MES_CMD_CLOSE_MYSQL_CONNECTION_REQ, sizeof(msg_close_connection_req_t), CT_INVALID_ID32,
        DCS_SELF_INSTID(knl_session), 0, knl_session->id, CT_INVALID_ID16);
    knl_panic(sizeof(msg_close_connection_req_t) < MES_MESSAGE_BUFFER_SIZE);

    if (tch->is_broadcast == true) {
        (void)ctc_broadcast_and_recv(knl_session, MES_BROADCAST_ALL_INST, &req, NULL);
        CT_LOG_RUN_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_60,
            "[CTC_CLOSE_CONNECTION]:session total_cursor_num = %d", session->total_cursor_num);
    }
    
    ctc_free_session(session);
    session = NULL;
    SYNC_POINT_GLOBAL_START(CTC_CLOSE_CONN_SUCC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    return CT_SUCCESS;
}

int ctc_db_common_pre_check(knl_session_t *knl_session, const char *db_name, int *error_code, char *error_message)
{
    int ret = 0;
    
    if (db_name != NULL && strlen(db_name) > CTC_IDENTIFIER_MAX_LEN) {
        *error_code = ERR_SQL_SYNTAX_ERROR;
        ret = snprintf_s(error_message, ERROR_MESSAGE_LEN, ERROR_MESSAGE_LEN - 1,
                         "[CTC_DB]: The db name '%-.100s' is too long", db_name);
        knl_securec_check_ss(ret);
        return CT_ERROR;
    }

    if (knl_ddl_enabled(knl_session, CT_TRUE) != CT_SUCCESS) {
        *error_code = ERR_CLUSTER_DDL_DISABLED;
        ret = snprintf_s(error_message, ERROR_MESSAGE_LEN, ERROR_MESSAGE_LEN - 1,
                         "[CTC_DB]: Cantian Cluster it not avaliable.");
        knl_securec_check_ss(ret);
        return CT_ERROR;
    }

    text_t user_name;
    cm_str2text(db_name, &user_name);
    if (cm_text_str_equal(&user_name, "tmp") || cm_text_str_equal(&user_name, "SYS") ||
        cm_text_str_equal(&user_name, "PUBLIC") || cm_text_str_equal(&user_name, "LREP") ||
        cm_text_str_equal(&user_name, "cantian")) {
        *error_code = ERR_OPERATIONS_NOT_SUPPORT;
        ret = snprintf_s(error_message, ERROR_MESSAGE_LEN, ERROR_MESSAGE_LEN - 1,
                         "[CTC_DB]: Not allowed to operate sys users for mysql.");
        knl_securec_check_ss(ret);
        CT_LOG_RUN_ERR("[CTC_DB] user %s is sys users, not allowed to operate for mysql", db_name);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

int ctc_create_db_pre_check(session_t *session, const char *db_name, int *error_code, char *error_message)
{
    int ret = 0;

    if (ctc_db_common_pre_check(&session->knl_session, db_name, error_code, error_message)) {
        CT_LOG_RUN_ERR("[CTC_PRE_CREATE_DB]:Pre create database pre-check failed. error_code:%d, error_message:%s",
            *error_code, error_message);
        return CT_ERROR;
    }
    
    if (!DB_ATTR_MYSQL_META_IN_DACC(&session->knl_session)) {
        if (ctc_is_db_mysql_owner(db_name)) {
            *error_code = ERR_OPERATIONS_NOT_ALLOW;
            ret = snprintf_s(error_message, ERROR_MESSAGE_LEN, ERROR_MESSAGE_LEN - 1,
                             "[CTC_PRE_CREATE_DB]: do not allow to create mysql sys schema %s", db_name);
            knl_securec_check_ss(ret);
            CT_LOG_RUN_ERR(error_message);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_drop_db_pre_check(ctc_handler_t *tch, const char *db_name, int *error_code,
                                       char *error_message)
{
    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    // 删除db ctc_lock_table创建过session，这里不需要在创建session
    CT_RETURN_IFERR(ctc_get_or_new_session(&session, tch, false, true, &is_new_session));

    if (ctc_db_common_pre_check(&session->knl_session, db_name, error_code, error_message)) {
        CT_LOG_RUN_ERR("[CTC_PRE_DROP_DB]:Drop database pre-check failed. error_code:%d, error_message:%s",
            *error_code, error_message);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t ctc_generate_tablespace_path(const char *db_tablespace_name, char *db_ts_path, uint32_t path_max_len)
{
    int ret;
    char path_prefix[CT_FILE_NAME_BUFFER_SIZE];
    if (cm_dbs_is_enable_dbs() == CT_TRUE) {
        PRTS_RETURN_IFERR(snprintf_s(path_prefix, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1,
                                     "%s", srv_get_param("SHARED_PATH")));
    } else {
        PRTS_RETURN_IFERR(snprintf_s(path_prefix, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1,
                                     "%s/data/", g_instance->home));
    }
    CT_LOG_RUN_INF("[CTC_CREATE_TS] mysql path: %s", path_prefix);
    int path_prefix_len = path_prefix == NULL ? 0 : strlen(path_prefix);
    if ((path_prefix_len + strlen(db_tablespace_name)) > path_max_len) {
        CT_LOG_RUN_ERR("[CTC_CREATE_TS]: tablespace and prefix exceeds the total maximum value %d, prefix:%s,\
            tablespace:%s.", path_max_len, path_prefix, db_tablespace_name);
        return ERR_NAME_TOO_LONG;
    }
    if (path_prefix == NULL || strlen(path_prefix) == 0) {
        ret = sprintf_s(db_ts_path, path_max_len, "%s", db_tablespace_name);
    } else {
        if (cm_dbs_is_enable_dbs() == CT_TRUE) {
            // for dbstor, remove sep to ensure users can mount from nfs and get correct file desc.
            ret = sprintf_s(db_ts_path, path_max_len, "%s%s", path_prefix, db_tablespace_name);
        } else {
            ret = sprintf_s(db_ts_path, path_max_len, "%s/%s", path_prefix, db_tablespace_name);
        }
    }
    knl_securec_check_ss(ret);
    return CT_SUCCESS;
}

static void ctc_db_get_err(int *error_code, char *error_message, uint32_t msg_len)
{
    char *message = NULL;
    cm_get_error(error_code, &message, NULL);
    int ret = strncpy_s(error_message, msg_len, message, msg_len - 1);
    knl_securec_check(ret);
}

status_t ctc_fill_dbspace_info(sql_stmt_t *stmt, knl_space_def_t *space_def,
                               ctc_db_infos_t *db_infos, char *db_ts_path)
{
    status_t status = CT_SUCCESS;
    knl_device_def_t *datafile = NULL;
 
    proto_str2text(db_infos->name, &space_def->name);
    space_def->type = SPACE_TYPE_USERS;
    space_def->is_for_create_db = CT_TRUE;
 
    cm_galist_init(&space_def->datafiles, stmt->context, sql_alloc_mem);
    status = cm_galist_new(&space_def->datafiles, sizeof(knl_device_def_t), (pointer_t *)&datafile);
    CT_RETURN_IFERR(status);
    status = ctc_generate_tablespace_path(db_infos->name, db_ts_path, TABLESPACE_PATH_MAX_LEN - 1);
    CT_RETURN_IFERR(status);
    proto_str2text(db_ts_path, &datafile->name);
    datafile->size = (int64)(db_infos->datafile_size) * 1024 * 1024; // 1024 * 1024 为M转B
    datafile->autoextend.enabled = db_infos->datafile_autoextend;
    datafile->autoextend.nextsize = (int64)(db_infos->datafile_extend_size) * 1024 * 1024; // 1024 * 1024 为M转B
    return status;
}
 
status_t ctc_fill_dbuser_info(knl_user_def_t *user_def, const char *user_name)
{
    status_t status = CT_SUCCESS;
 
    knl_securec_check(strcpy_s(user_def->name, CT_NAME_BUFFER_SIZE, user_name));
    /* db创建的用户名与表空间同名 */
    knl_securec_check(strcpy_s(user_def->default_space, CT_NAME_BUFFER_SIZE, user_name));
 
    user_def->is_readonly = CT_TRUE;
    user_def->is_lock = CT_TRUE;
    user_def->is_for_create_db = CT_TRUE;
    user_def->mask |= USER_LOCK_MASK;
    user_def->mask |= USER_DATA_SPACE_MASK;
    user_def->is_encrypt = CT_TRUE;
    return status;
}

EXTER_ATTACK int ctc_pre_create_db(ctc_handler_t *tch, const char *sql_str, ctc_db_infos_t *db_infos,
                                   int *error_code, char *error_message)
{
    int status = CT_SUCCESS;
    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    sql_stmt_t *stmt = NULL;
    knl_space_def_t *space_def = NULL;
    knl_user_def_t *user_def = NULL;
    char db_ts_path[TABLESPACE_PATH_MAX_LEN] = { 0 };
    char db_name[SMALL_RECORD_SIZE] = { '\0' };
    size_t db_len = strlen(db_infos->name);

    // 创建db ctc_lock_table里面分配过session了，这里不需要在分配了
    // 元数据归一初始化场景没有ctc_lock_table, 这里需要分配
    CT_RETURN_IFERR(ctc_get_or_new_session(&session, tch, true, true, &is_new_session));

    MEMS_RETURN_IFERR(strncpy_s(db_name, SMALL_RECORD_SIZE, db_infos->name, db_len));
    CT_RETURN_IFERR(ctc_create_db_pre_check(session, db_name, error_code, error_message));
    stmt = session->current_stmt;
    CT_RETURN_IFERR(ctc_put_ddl_sql_2_stmt(session, EMPTY_DATABASE, sql_str));

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_space_def_t), (pointer_t *)&space_def));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_user_def_t), (pointer_t *)&user_def));

    CT_RETURN_IFERR(ctc_fill_dbspace_info(stmt, space_def, db_infos, db_ts_path));
 
    CT_RETURN_IFERR(ctc_fill_dbuser_info(user_def, db_infos->name));

    bool32 is_mysql_sys_db = !strcmp(db_name, "mysql");
    status = knl_create_database4mysql((knl_handle_t)session, (knl_handle_t)stmt, space_def, user_def, is_mysql_sys_db);
    if (status == CT_SUCCESS) {
        do_commit(stmt->session);
    } else {
        do_rollback(stmt->session, NULL);
        ctc_db_get_err(error_code, error_message, ERROR_MESSAGE_LEN);
        CT_LOG_RUN_ERR("[CTC_CREATE_DB]:create database error,"
                       "ret:%d, error_code:%d, error_message:%s, conn_id:%u, ctc_instance_id:%u",
                       status, *error_code, error_message, tch->thd_id, tch->inst_id);
        ctc_ddl_clear_stmt(stmt);
        return CT_ERROR;
    }
    ctc_ddl_clear_stmt(stmt);
    return CT_SUCCESS;
}

void ctc_fill_drop_dbuser(knl_drop_user_t *user_def, char *user_name)
{
    proto_str2text(user_name, &user_def->owner);
    user_def->purge = CT_TRUE;
}
 
void ctc_fill_drop_dbspace(knl_drop_space_def_t *space_def, char *space_name)
{
    proto_str2text(space_name, &space_def->obj_name);
    space_def->options |= TABALESPACE_DFS_AND;
    space_def->options |= TABALESPACE_INCLUDE;
    space_def->options |= TABALESPACE_CASCADE;
    space_def->is_for_create_db = CT_TRUE;
}

EXTER_ATTACK int ctc_drop_tablespace_and_user(ctc_handler_t *tch, const char *db_name, const char *sql_str,
                                              const char *user_name, const char *user_ip, int *error_code,
                                              char *error_message)
{
    bool is_new_session;
    session_t *session = NULL;
    knl_drop_user_t *user_def = NULL;
    knl_drop_space_def_t *space_def = NULL;
    sql_stmt_t *stmt = NULL;
    int status = CT_SUCCESS;

    // TODO：mysql没有下发正确的tch， ctc_drop_db_pre_check之前已经有session了
    CT_RETURN_IFERR(ctc_get_or_new_session(&session, tch, true, true, &is_new_session));
    stmt = session->current_stmt;

    CT_RETURN_IFERR(ctc_put_ddl_sql_2_stmt(session, EMPTY_DATABASE, sql_str));

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_drop_user_t), (pointer_t *)&user_def));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_drop_space_def_t), (pointer_t *)&space_def));
    ctc_fill_drop_dbspace(space_def, db_name);
    ctc_fill_drop_dbuser(user_def, db_name);

    cm_reset_error();
    status = knl_drop_database4mysql((knl_handle_t)session, (knl_handle_t)stmt, space_def, user_def);
    if (status == CT_SUCCESS) {
        do_commit(stmt->session);
    } else {
        do_rollback(stmt->session, NULL);
        ctc_db_get_err(error_code, error_message, ERROR_MESSAGE_LEN);
        CT_LOG_RUN_ERR("[CTC_DROP_DB]: drop database failed, error_code:%d, error_message:%s",
            *error_code, error_message);
        ctc_ddl_clear_stmt(stmt);
        return CT_ERROR;
    }
    ctc_ddl_clear_stmt(stmt);

    ctc_ddl_broadcast_request broadcast_req = {0};
    FILL_BROADCAST_REQ(broadcast_req, db_name, sql_str, user_name, user_ip, tch->inst_id, tch->sql_command);
    if (ctc_execute_mysql_ddl_sql(tch, &broadcast_req, false) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_DROP_DB]:Broadcast drop db sql_str error, error_code:%d, conn_id:%lu, ctc_instance_id:%lu",
                       broadcast_req.err_code, tch->thd_id, tch->inst_id);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

int ctc_unlock_table_impl(ctc_handler_t *tch, knl_handle_t knl_session, uint32_t mysql_inst_id,
                          ctc_lock_table_info *lock_info)

{
    // 广播 mysqld
    int ret = ctc_ddl_execute_unlock_tables_intf(tch, mysql_inst_id, lock_info);
    if (ret != CT_SUCCESS && DB_IS_PRIMARY(&g_instance->kernel.db)) {
        CT_LOG_RUN_ERR("[CTC_UNLOCK_TABLE]:execute failed at other mysqld on current node conn_id:%u", tch->thd_id);
        return CT_ERROR;
    }
    // 广播 其他cantian节点
    msg_commit_ddl_req_t req;
    req.tch = *tch;
    req.lock_info = *lock_info;

    req.msg_num = cm_random(CT_INVALID_ID32);
    req.mysql_inst_id = mysql_inst_id;
    mes_init_send_head(&req.head, MES_CMD_COMMIT_DDL_REQ, sizeof(msg_commit_ddl_req_t), CT_INVALID_ID32,
        DCS_SELF_INSTID((knl_session_t *)knl_session), 0, ((knl_session_t *)knl_session)->id, CT_INVALID_ID16);
    knl_panic(sizeof(msg_commit_ddl_req_t) < MES_MESSAGE_BUFFER_SIZE);

    (void)ctc_broadcast_and_recv((knl_session_t *)knl_session, MES_BROADCAST_ALL_INST, &req, NULL);
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_unlock_table(ctc_handler_t *tch, uint32_t mysql_inst_id, ctc_lock_table_info *lock_info)
{
    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    CT_RETURN_IFERR(ctc_get_or_new_session(&session, tch, true, false, &is_new_session));
    knl_session_t *knl_session = &session->knl_session;

    CT_RETURN_IFERR(ctc_unlock_table_impl(tch, knl_session, mysql_inst_id, lock_info));

    ctc_write_rd_lock_info_4mysql_ddl(knl_session, lock_info, RD_UNLOCK_TABLE_FOR_MYSQL_DDL);

    if (is_new_session) {
        tch->sess_addr = INVALID_VALUE64;
        (void)ctc_free_session(session);
    }

    if (tch->sql_command == SQLCOM_UNLOCK_INSTANCE) {
        CT_LOG_RUN_INF("[CTC_UNLOCK_INSTANCE]: ctc_inst_id:%u, conn_id:%u, knl_session_id:%d.",
                       tch->inst_id, tch->thd_id, session->knl_session.id);
    }
    SYNC_POINT_GLOBAL_START(CTC_MES_UNLOCK_TABLE_SUCC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    return CT_SUCCESS;
}

status_t init_ddl_session(session_t *session)
{
    session->knl_session.spid = cm_get_current_thread_id();
    knl_set_curr_sess2tls((void *)session);
    // set session id here, because need consider agent mode, for example, agent mode is AGENT_MODE_SHARED
    cm_log_set_session_id(session->knl_session.id);
    sql_audit_init(&session->sql_audit);
    cm_reset_error();
    sql_begin_exec_stat((void *)session);

    /* get stmt to prepare sql */
    if (session->current_stmt == NULL) {
        CT_RETURN_IFERR(sql_alloc_stmt(session, &session->current_stmt));
    }
    
    /* atomic DDL only needs to init_ddl_sesion once for multi ddl sql*/
    if (session->current_stmt->ddl_def_list.head != NULL) {
        return CT_SUCCESS;
    }

    sql_stmt_t *stmt = session->current_stmt;
    sql_release_lob_info(stmt);

    sql_release_resource(stmt, CT_TRUE);
    sql_release_context(stmt);

    sql_reset_plsql_resource(stmt);
    stmt->is_explain = CT_FALSE;
    stmt->is_reform_call = CT_FALSE;

    stmt->pl_failed = CT_FALSE;
    stmt->lang_type = LANG_DDL;

    stmt->session->sql_audit.audit_type = SQL_AUDIT_DDL;

    status_t status = sql_alloc_context(stmt);
    CT_RETURN_IFERR(status);
    CT_RETURN_IFERR(sql_create_list(stmt, &stmt->context->ref_objects));
    sql_set_scn(stmt);
    sql_set_ssn(stmt);
    ctc_init_ddl_def_list(stmt);
    stmt->status = STMT_STATUS_PREPARED;
    return CT_SUCCESS;
}

ct_type_t get_ct_type_from_ctc_ddl_type(enum_ctc_ddl_field_types ctc_type, uint32_t is_unsigned)
{
    ct_type_t ct_type = CT_TYPE_UNKNOWN;
    for (size_t i = 0; i < sizeof(g_mysql_to_cantian_type) / sizeof(mysql_cantiandba_type_t); i++) {
        if (ctc_type == g_mysql_to_cantian_type[i].mysql_type) {
            ct_type = g_mysql_to_cantian_type[i].cantian_type;
            if (is_unsigned == 1) {
                if (ct_type == CT_TYPE_INTEGER) {
                    ct_type = CT_TYPE_UINT32;
                } else if (ct_type == CT_TYPE_BIGINT) {
                    ct_type = CT_TYPE_UINT64;
                }
            }
            return ct_type;
        }
    }

    return ct_type;
}

bool type_is_number(ct_type_t datatype)
{
    switch (datatype) {
        case CT_TYPE_INTEGER:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_TINYINT:
        case CT_TYPE_SMALLINT:
        case CT_TYPE_REAL:
        case CT_TYPE_BIGINT:
            return true;
        default:
            return false;
    }
}

status_t fill_column_default_text(session_t *session, sql_stmt_t *stmt, knl_column_def_t *column,
                                  const TcDb__CtcDDLColumnDef *def, ddl_ctrl_t *ddl_ctrl)
{
    // if default value is not number or generated by mysql functions, treat it as string
    bool is_default_str = !type_is_number(column->datatype) &&
                          !((ctc_column_option_set_bit)def->is_option_set).is_default_func;
    int appendLen = is_default_str ? 3 : 1; // 3表示两个单引号和\0的长度
    char *format = is_default_str ? "'%s'" : "%s";
    if (sql_alloc_mem(stmt->context, strlen(def->default_text) + appendLen,
        (pointer_t *)&column->default_text.str) != CT_SUCCESS) {
        return CT_ERROR;
    }
    int ret = sprintf_s(column->default_text.str, strlen(def->default_text) + appendLen, format, def->default_text);
    column->default_text.len = strlen(column->default_text.str);
    knl_securec_check_ss(ret);
    return CT_SUCCESS;
}

status_t ctc_fill_column_info(session_t *session, sql_stmt_t *stmt, knl_column_def_t *column,
                              const TcDb__CtcDDLColumnDef *def, ddl_ctrl_t *ddl_ctrl)
{
    proto_str2text(def->name, &column->name);
    column->datatype = get_ct_type_from_ctc_ddl_type(def->datatype->datatype, def->is_unsigned);
    column->mysql_ori_datatype = def->datatype->mysql_ori_datatype;

    if (column->mysql_ori_datatype == MYSQL_TYPE_ENUM || column->mysql_ori_datatype == MYSQL_TYPE_SET ||
        column->mysql_ori_datatype == MYSQL_TYPE_BIT) {
        column->precision = def->datatype->precision;
    }

    if (column->datatype == CT_TYPE_REAL || column->datatype == CT_TYPE_DECIMAL || column->datatype == CT_TYPE_NUMBER3) {
        column->precision = def->datatype->precision;
        column->scale = def->datatype->scale;
    }

    if (column->datatype == CT_TYPE_DATETIME_MYSQL || column->datatype == CT_TYPE_TIME_MYSQL ||
        column->datatype == CT_TYPE_TIMESTAMP) {
        column->precision = def->datatype->precision;
    }

    column->size = def->datatype->size;
    column->is_option_set = def->is_option_set;
    column->is_unsigned = def->is_unsigned;
    if (column->is_default && def->default_text && !column->is_default_null) {
        int ret = fill_column_default_text(session, stmt, column, def, ddl_ctrl);
        if (ret != CT_SUCCESS) {
            return ret;
        }
    }

    if (column->is_default_null && column->is_default && column->nullable) {
        column->default_text.str = DEFAULT_NULL_TEXT_STR;
        column->default_text.len = DEFAULT_NULL_TEXT_LEN;
    }

    if (column->is_comment) {
        proto_str2text(def->comment, &column->comment);
    }

    if (column->is_collate) {
        column->typmod.collate = def->collate;
        column->collate_id = def->collate;
    }
    return CT_SUCCESS;
}

knl_refactor_t get_refactor_from_fk_def(TcDb__CtcDDLForeignKeyDef *fk_def)
{
    uint32_t delete_opt = fk_def->delete_opt;
    uint32_t update_opt = fk_def->update_opt;
    knl_refactor_t refactor = REF_DEL_NOT_ALLOWED;
    if (delete_opt == FK_CASCADE_MODE) {
        refactor |= REF_DEL_CASCADE;
    }
    if (delete_opt == FK_SET_NULL_MODE) {
        refactor |= REF_DEL_SET_NULL;
    }
    if (update_opt == FK_CASCADE_MODE) {
        refactor |= REF_UPDATE_CASCADE;
    }
    if (update_opt == FK_SET_NULL_MODE) {
        refactor |= REF_UPDATE_SET_NULL;
    }
    return refactor;
}

int fill_ctc_create_fk_info(sql_stmt_t *stmt, TcDb__CtcDDLCreateTableDef *req, knl_table_def_t *def)
{
    status_t status;
    if (req->n_fk_list == 0) {
        return 0;
    }
    for (int i = 0; i < req->n_fk_list; i++) {
        TcDb__CtcDDLForeignKeyDef *fk_def = req->fk_list[i];
        knl_constraint_def_t *cons = NULL;
        status = cm_galist_new(&def->constraints, sizeof(knl_constraint_def_t), (pointer_t *)&cons);
        CT_RETURN_IFERR(status);
        cons->cons_state.is_enable = CT_TRUE;
        cons->cons_state.is_validate = CT_TRUE;
        cons->cons_state.is_cascade = CT_TRUE;
        cons->type = CONS_TYPE_REFERENCE;

        if (sql_alloc_mem(stmt->context, CT_NAME_BUFFER_SIZE, (pointer_t *)&cons->name.str) != CT_SUCCESS) {
            return CT_ERROR;
        }

        // 建表时无法获取 tableid，索引名在 db_create_table 中修改
        proto_str2text_ex(fk_def->name, &cons->name, CT_NAME_BUFFER_SIZE - 1);
        
        knl_reference_def_t *ref = &cons->ref;
        proto_str2text(fk_def->referenced_table_schema_name, &ref->ref_user);
        proto_str2text(fk_def->referenced_table_name, &ref->ref_table);
        ref->refactor = get_refactor_from_fk_def(fk_def);
        cm_galist_init(&ref->ref_columns, stmt->context, sql_alloc_mem);
        cm_galist_init(&cons->columns, stmt->context, sql_alloc_mem);
        for (int j = 0; j < fk_def->n_elements; j++) {
            TcDb__CtcDDLForeignKeyElementDef *fk_ele = fk_def->elements[j];
            knl_index_col_def_t *src_column = NULL;
            status = cm_galist_new(&cons->columns, sizeof(knl_index_col_def_t), (void **)&src_column);
            CT_RETURN_IFERR(status);
            src_column->is_func = CT_FALSE;
            src_column->func_expr = NULL;
            src_column->func_text.len = 0;
            proto_str2text(fk_ele->src_column_name, &src_column->name);

            knl_index_col_def_t *ref_column = NULL;
            status = cm_galist_new(&ref->ref_columns, sizeof(knl_index_col_def_t), (void **)&ref_column);
            CT_RETURN_IFERR(status);
            ref_column->is_func = CT_FALSE;
            ref_column->func_expr = NULL;
            ref_column->func_text.len = 0;
            proto_str2text(fk_ele->ref_column_name, &ref_column->name);
        }
    }
    return CT_SUCCESS;
}

static status_t ctc_ddl_fill_key_column(TcDb__CtcDDLTableKeyPart *key_part, knl_index_col_def_t *key_column)
{
    proto_str2text(key_part->name, &key_column->name);
    key_column->datatype = get_ct_type_from_ctc_ddl_type(key_part->datatype, key_part->is_unsigned);
    key_column->size = key_part->length;
    key_column->is_func = key_part->is_func;
    if (key_column->is_func) {
        text_t func_name_text = {0};
        proto_str2text(key_part->func_name, &func_name_text);
        uint32 func_id = sql_get_func_id(&func_name_text);
        if (func_id == CT_INVALID_ID32) {
            CT_THROW_ERROR_EX(ERR_FUNCTION_NOT_EXIST, key_part->func_name);
            return CT_ERROR;
        }
        if (!g_func_tab[func_id].indexable) {
            CT_THROW_ERROR_EX(ERR_FUNCTION_NOT_INDEXABLE, key_part->func_name);
            return CT_ERROR;
        }
        proto_str2text(key_part->func_text, &key_column->func_text);
    }
    return CT_SUCCESS;
}

// tmp table only
static status_t fill_cons_and_index_type(knl_constraint_def_t *cons, int32_t key_type, knl_index_def_t *index)
{
    cons->cons_state.is_enable = CT_TRUE;
    cons->cons_state.is_validate = CT_TRUE;
    cons->cons_state.is_cascade = CT_TRUE;
    cons->cons_state.is_use_index = CT_TRUE;
    switch (key_type) {
        case CTC_KEYTYPE_PRIMARY:
            cons->type = CONS_TYPE_PRIMARY;
            index->primary = CT_TRUE;
            break;
        case CTC_KEYTYPE_UNIQUE:
            cons->type = CONS_TYPE_UNIQUE;
            index->unique = CT_TRUE;
            break;
        case CTC_KEYTYPE_FOREIGN:
            break;
        default:
            CT_LOG_RUN_ERR("fill_cons_and_index_type unknow key type:%d", key_type);
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t fill_index_info_and_column(sql_stmt_t *stmt, knl_table_def_t *def, TcDb__CtcDDLTableKey *ck_def,
                                           knl_index_def_t *index, knl_constraint_def_t *cons)
{
    index->parted = def->parted;
    index->is_for_create_db = CT_TRUE;
    index->initrans = knl_get_initrans();
    index->pctfree = CT_PCT_FREE;
    index->cr_mode = CR_PAGE;

    index->is_func = ck_def->is_func;
    index->is_dsc = ck_def->is_dsc;
    proto_str2text(ck_def->user, &index->user);   // 用户名
    proto_str2text(ck_def->table, &index->table); // 表名

    cm_galist_init(&index->columns, stmt->context, sql_alloc_mem);
    for (int j = 0; j < ck_def->n_columns; j++) {
        TcDb__CtcDDLTableKeyPart *ck_key_part = ck_def->columns[j];
        knl_index_col_def_t *key_column = NULL;

        if (ck_def->key_type != CTC_KEYTYPE_MULTIPLE) {
            CT_RETURN_IFERR(cm_galist_new(&cons->columns, sizeof(knl_index_col_def_t), (void **)&key_column));
        } else {
            CT_RETURN_IFERR(cm_galist_new(&index->columns, sizeof(knl_index_col_def_t), (void **)&key_column));
        }
        CT_RETURN_IFERR(ctc_ddl_fill_key_column(ck_key_part, key_column));
    }

    return CT_SUCCESS;
}

int fill_ctc_create_key_info(sql_stmt_t *stmt, TcDb__CtcDDLCreateTableDef *req, knl_table_def_t *def)
{
    status_t status;

    for (int i = 0; i < req->n_key_list; i++) {
        TcDb__CtcDDLTableKey *ck_def = req->key_list[i];
        knl_index_def_t *index = NULL;
        knl_constraint_def_t *cons = NULL;

        if (ck_def->key_type == CTC_KEYTYPE_MULTIPLE) {
            status = cm_galist_new(&def->indexs, sizeof(knl_index_def_t), (pointer_t *)&index);
            CT_RETURN_IFERR(status);

            if (sql_alloc_mem(stmt->context, CT_NAME_BUFFER_SIZE, (pointer_t *)&index->name.str) != CT_SUCCESS) {
                return CT_ERROR;
            }

            // 建表时无法获取 tableid，索引名在 db_create_table 中修改
            proto_str2text_ex(ck_def->name, &index->name, CT_NAME_BUFFER_SIZE - 1);
            index->type = INDEX_TYPE_BTREE;
        } else {
            status = cm_galist_new(&def->constraints, sizeof(knl_constraint_def_t), (pointer_t *)&cons);
            CT_RETURN_IFERR(status);

            if (sql_alloc_mem(stmt->context, CT_NAME_BUFFER_SIZE, (pointer_t *)&cons->name.str) != CT_SUCCESS) {
                return CT_ERROR;
            }

            // 建表时无法获取 tableid，约束名在 db_create_table 中修改
            proto_str2text_ex(ck_def->name, &cons->name, CT_NAME_BUFFER_SIZE - 1);
            index = &cons->index;

            CT_RETURN_IFERR(fill_cons_and_index_type(cons, ck_def->key_type, index));
            cm_galist_init(&cons->columns, stmt->context, sql_alloc_mem);
        }
        CT_RETURN_IFERR(fill_index_info_and_column(stmt, def, ck_def, index, cons));
    }
    return CT_SUCCESS;
}

part_type_t get_ctc_part_type(uint32_t part_type)
{
    part_type_t ctc_part_type = PART_TYPE_INVALID;
    switch (part_type) {
        case CTC_PART_TYPE_RANGE:
            ctc_part_type = PART_TYPE_RANGE;
            break;
        case CTC_PART_TYPE_LIST:
            ctc_part_type = PART_TYPE_LIST;
            break;
        case CTC_PART_TYPE_HASH:
            ctc_part_type = PART_TYPE_HASH;
            break;
        default:
            CT_LOG_DEBUG_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_20, "get_ctc_part_type invalid partition type : %d.", part_type);
            break;
    }
    return ctc_part_type;
}

status_t ctc_sql_parse_hash_partition(sql_stmt_t *stmt, knl_part_def_t *part_def)
{
    int64 part_name_id;
    int errcode;
    char name_arr[CT_NAME_BUFFER_SIZE] = { '\0' };
    text_t part_name;
    CT_RETURN_IFERR(sql_alloc_object_id(stmt, &part_name_id));
    errcode = snprintf_s(name_arr, CT_NAME_BUFFER_SIZE, CT_NAME_BUFFER_SIZE - 1, "SYS_P%lld", part_name_id);
    PRTS_RETURN_IFERR(errcode);
    part_name.len = (uint32)strlen(name_arr);
    part_name.str = name_arr;
    CT_RETURN_IFERR(sql_copy_object_name(stmt->context, WORD_TYPE_STRING, &part_name, &part_def->name));
    return CT_SUCCESS;
}

status_t ctc_sql_subpart_parse_partition(sql_stmt_t *stmt, knl_part_def_t *part_def, knl_part_obj_def_t *obj_def)
{
    knl_part_def_t *subpart_def = NULL;
    status_t status;
    part_def->is_parent = CT_TRUE;
    CT_RETURN_IFERR(cm_galist_new(&part_def->subparts, sizeof(knl_part_def_t), (pointer_t *)&subpart_def));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, CT_MAX_COLUMN_SIZE, (pointer_t *)&subpart_def->partkey));
 
    cm_galist_init(&subpart_def->value_list, stmt->context, sql_alloc_mem);
    cm_galist_init(&subpart_def->subparts, stmt->context, sql_alloc_mem);
    cm_galist_init(&subpart_def->group_subkeys, stmt->context, sql_alloc_mem);

    subpart_def->initrans = knl_get_initrans();
    subpart_def->pctfree = CT_PCT_FREE;

    switch (obj_def->subpart_type) {
        case PART_TYPE_HASH:
            status = ctc_sql_parse_hash_partition(stmt, subpart_def);
            break;
        default:
            status = CT_ERROR;
            break;
    }
    return status;
}
 
static status_t ctc_sql_part_parse_partition(sql_stmt_t *stmt, knl_part_obj_def_t *obj_def,
                                             TcDb__CtcDDLPartitionTableDef *part_table_def)
{
    knl_part_def_t *part_def = NULL;
    status_t status = CT_SUCCESS;

    CT_RETURN_IFERR(cm_galist_new(&obj_def->parts, sizeof(knl_part_def_t), (pointer_t *)&part_def));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, CT_MAX_COLUMN_SIZE, (pointer_t *)&part_def->partkey));

    cm_galist_init(&part_def->value_list, stmt->context, sql_alloc_mem);
    cm_galist_init(&part_def->subparts, stmt->context, sql_alloc_mem);
    cm_galist_init(&part_def->group_subkeys, stmt->context, sql_alloc_mem);
    part_def->exist_subparts = obj_def->is_composite ? CT_TRUE : CT_FALSE;

    part_def->initrans = knl_get_initrans();
    part_def->pctfree = CT_PCT_FREE;

    switch (obj_def->part_type) {
        case PART_TYPE_LIST:
        case PART_TYPE_RANGE:
            proto_str2text(part_table_def->name, &part_def->name);
            break;
        case PART_TYPE_HASH:
            status = ctc_sql_parse_hash_partition(stmt, part_def);
            break;
        default:
            return CT_ERROR;
    }

    if (obj_def->is_composite) {
        for (uint32_t i = 0; i < part_table_def->n_subpart_table_list; i++) {
            CT_RETURN_IFERR(ctc_sql_subpart_parse_partition(stmt, part_def, obj_def));
        }
    }
    return status;
}

int fill_ctc_partition_info(sql_stmt_t *stmt, TcDb__CtcDDLCreateTableDef *req, knl_table_def_t *def)
{
    if (req->partition_def == NULL) {
        return 0;
    }
    def->parted = CT_TRUE;
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_part_obj_def_t), (pointer_t *)&def->part_def));
    knl_part_obj_def_t *obj_def = def->part_def;
    obj_def->part_type = get_ctc_part_type(req->partition_def->part_type);
    obj_def->subpart_type = get_ctc_part_type(req->partition_def->subpart_type);
    obj_def->is_for_create_db = CT_TRUE;

    cm_galist_init(&obj_def->parts, stmt->context, sql_alloc_mem);
    cm_galist_init(&obj_def->part_keys, stmt->context, sql_alloc_mem);
    cm_galist_init(&obj_def->group_keys, stmt->context, sql_alloc_mem);
    cm_galist_init(&obj_def->part_store_in.space_list, stmt->context, sql_alloc_mem);
    cm_galist_init(&obj_def->subpart_store_in.space_list, stmt->context, sql_alloc_mem);
    cm_galist_init(&obj_def->subpart_keys, stmt->context, sql_alloc_mem);

    if (obj_def->subpart_type != PART_TYPE_INVALID) {
        obj_def->is_composite = CT_TRUE;
    }

    for (uint32_t i = 0; i < req->partition_def->n_part_table_list; i++) {
        CT_RETURN_IFERR(ctc_sql_part_parse_partition(stmt, obj_def, req->partition_def->part_table_list[i]));
    }
    return CT_SUCCESS;
}

int fill_ctc_alter_fk_info(sql_stmt_t *stmt, TcDb__CtcDDLAlterTableDef *req, knl_altable_def_t *def)
{
    status_t status;

    knl_constraint_def_t *cons = &def->cons_def.new_cons;
    for (int i = 0; i < req->n_add_foreign_key_list; i++) {
        TcDb__CtcDDLForeignKeyDef *fk_def = req->add_foreign_key_list[i];
        cons->cons_state.is_enable = CT_TRUE;
        cons->cons_state.is_validate = CT_TRUE;
        cons->cons_state.is_cascade = CT_TRUE;

        proto_str2text(fk_def->name, &cons->name);
        cons->type = CONS_TYPE_REFERENCE;
        knl_reference_def_t *ref = &cons->ref;
        proto_str2text(fk_def->referenced_table_schema_name, &ref->ref_user);
        proto_str2text(fk_def->referenced_table_name, &ref->ref_table);
        ref->refactor = get_refactor_from_fk_def(fk_def);
        cm_galist_init(&ref->ref_columns, stmt->context, sql_alloc_mem);
        cm_galist_init(&cons->columns, stmt->context, sql_alloc_mem);
        for (int j = 0; j < fk_def->n_elements; j++) {
            TcDb__CtcDDLForeignKeyElementDef *fk_ele = fk_def->elements[j];
            knl_index_col_def_t *src_column = NULL;
            status = cm_galist_new(&cons->columns, sizeof(knl_index_col_def_t), (void **)&src_column);
            CT_RETURN_IFERR(status);
            src_column->is_func = CT_FALSE;
            src_column->func_expr = NULL;
            src_column->func_text.len = 0;
            proto_str2text(fk_ele->src_column_name, &src_column->name);

            knl_index_col_def_t *ref_column = NULL;
            status = cm_galist_new(&ref->ref_columns, sizeof(knl_index_col_def_t), (void **)&ref_column);
            CT_RETURN_IFERR(status);
            ref_column->is_func = CT_FALSE;
            ref_column->func_expr = NULL;
            ref_column->func_text.len = 0;
            proto_str2text(fk_ele->ref_column_name, &ref_column->name);
        }
    }
    return CT_SUCCESS;
}

int ctc_truncate_table_impl(TcDb__CtcDDLTruncateTableDef *req, ddl_ctrl_t *ddl_ctrl)
{
    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    CT_RETURN_IFERR(ctc_get_or_new_session(&session, &(ddl_ctrl->tch), false, true, &is_new_session));

    knl_session_t *knl_session = &session->knl_session;
    ctc_ddl_def_node_t *def_node = NULL;
    knl_trunc_def_t *def = NULL;
    sql_stmt_t *stmt = session->current_stmt;
    ctc_init_ddl_def_list(stmt);
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_trunc_def_t), (pointer_t *)&def));
    CT_RETURN_IFERR(ctc_put_ddl_sql_2_stmt(session, req->db_name, req->sql_str));
    stmt->context->type = CTSQL_TYPE_TRUNCATE_TABLE;
    stmt->context->entry = def;

    proto_str2text(req->schema, &def->owner);
    proto_str2text(req->name, &def->name);
    def->option = TRUNC_RECYCLE_STORAGE;
    def->no_need_check_fk = req->no_check_fk;
    knl_dictionary_t dc;
    if (knl_open_dc(&session->knl_session, &(def->owner), &(def->name), &dc) != CT_SUCCESS) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not find", T2S(&(def->name)));
        return CT_ERROR;
    }
    RETURN_IF_OPERATION_UNSUPPORTED(&dc, "truncate table");

    int status = knl_truncate_table_lock_table(&session->knl_session, &dc);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_LOCK_DROP_TABLE]:drop table to lock table failed, ret:%d,"
                       "conn_id:%u, ctc_instance_id:%u", (int)status, ddl_ctrl->tch.thd_id, ddl_ctrl->tch.inst_id);
        knl_close_dc(&dc);
        CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    }
    if (sql_alloc_mem(stmt->context, sizeof(ctc_ddl_def_node_t), (void **)&def_node) != CT_SUCCESS) {
        knl_close_dc(&dc);
        return CT_ERROR;
    }
    ctc_init_ddl_def_node(def_node, TRUNC_DEF, (pointer_t *)def, &dc);
    ctc_ddl_def_list_insert(&stmt->ddl_def_list, def_node);
    
    cm_reset_error();
    status = knl_truncate_table4mysql(knl_session, stmt, def, &dc);
    knl_close_dc(&dc);
    CT_LOG_RUN_WAR("trunc_table finish, table_name:%s, session_id:%d", def->name.str, stmt->session->knl_session.id);
    CT_RETURN_IFERR_NOCLEAR(status, ddl_ctrl);

    return status;
}

EXTER_ATTACK int ctc_truncate_table(void *table_def, ddl_ctrl_t *ddl_ctrl)
{
    TcDb__CtcDDLTruncateTableDef *req = tc_db__ctc_ddltruncate_table_def__unpack(NULL, ddl_ctrl->msg_len, table_def);
    CTC_LOG_RET_VAL_IF_NUL(req, CT_ERROR, "ctc_truncate_table: null req ptr");
    int ret = ctc_truncate_table_impl(req, ddl_ctrl);
    tc_db__ctc_ddltruncate_table_def__free_unpacked(req, NULL);
    return ret;
}

/*
 * hash分区mysql会给分区取名为p0,p1,p2... 与参天命名不一致，因此需要根据part_id获取分区的分区名
 * list(columns)分区和range(columns)分区直接使用mysql传下来的分区名即可
 */
static status_t ctc_get_partition_real_name(knl_session_t *session, uint32_t idx,
    TcDb__CtcDDLTruncateTablePartitionDef *req, char *part_name, uint32_t part_name_len)
{
    knl_dictionary_t dc = {0};
    text_t user = {0};
    text_t table_name = {0};
    proto_str2text(req->user, &user);
    proto_str2text(req->table_name, &table_name);
    CT_RETURN_IFERR(knl_open_dc(session, &user, &table_name, &dc));
    table_t *table = DC_TABLE(&dc);
    if (req->is_subpart) {
        if (table->part_table->desc.subparttype != PART_TYPE_HASH) {
            dc_close(&dc);
            CT_RETURN_IFERR(strcpy_s(part_name, part_name_len, req->subpartition_name[idx]));
            return CT_SUCCESS;
        }
        table_part_t *table_part = TABLE_GET_PART(table, req->partition_id[idx]);
        table_part_t *table_subpart = PART_GET_SUBENTITY(table->part_table,
            table_part->subparts[req->subpartition_id[idx]]);
        errno_t ret = strcpy_s(part_name, part_name_len, table_subpart->desc.name);
        if (ret != EOK) {
            CT_LOG_RUN_ERR("ctc_get_subpartition_real_name: strcpy_s failed, ret = %d, len = %u, subpart_name = %s.",
                ret, part_name_len, table_subpart->desc.name);
            dc_close(&dc);
            return CT_ERROR;
        }
    } else {
        if (table->part_table->desc.parttype != PART_TYPE_HASH) {
            dc_close(&dc);
            CT_RETURN_IFERR(strcpy_s(part_name, part_name_len, req->partition_name[idx]));
            return CT_SUCCESS;
        }
        table_part_t *table_part = TABLE_GET_PART(table, req->partition_id[idx]);
        errno_t ret = strcpy_s(part_name, part_name_len, table_part->desc.name);
        if (ret != EOK) {
            CT_LOG_RUN_ERR("ctc_get_partition_real_name: strcpy_s failed, ret = %d, len = %u, part_name = %s.",
                ret, part_name_len, table_part->desc.name);
            dc_close(&dc);
            return CT_ERROR;
        }
    }
    dc_close(&dc);
    return CT_SUCCESS;
}
static void ctc_fill_common_truncate_partiton_def(knl_altable_def_t *def, TcDb__CtcDDLTruncateTablePartitionDef *req,
    char *part_name)
{
    def->action = req->is_subpart ? ALTABLE_TRUNCATE_SUBPARTITION : ALTABLE_TRUNCATE_PARTITION;
    def->part_def.option = TRUNC_RECYCLE_STORAGE;
    def->is_for_create_db = CT_TRUE;
    proto_str2text(req->user, &def->user);
    proto_str2text(req->table_name, &def->name);
    proto_str2text(part_name, &def->part_def.name);
}

static int ctc_truncate_partition_impl(TcDb__CtcDDLTruncateTablePartitionDef *req, ddl_ctrl_t *ddl_ctrl)
{
    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    int status = CT_SUCCESS;
    CT_RETURN_IFERR(ctc_get_or_new_session(&session, &(ddl_ctrl->tch), false, true, &is_new_session));
    knl_altable_def_t *def = NULL;
    sql_stmt_t *stmt = session->current_stmt;
    knl_altable_def_t *def_arrays = NULL;
    uint32_t n_defs_num = req->is_subpart ? req->n_subpartition_id : req->n_partition_id;
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_altable_def_t) * n_defs_num, (pointer_t *)&def_arrays));
    CT_RETURN_IFERR(ctc_put_ddl_sql_2_stmt(session, req->db_name, req->sql_str));
    for (int i = 0; i < n_defs_num; i++) {
        def = &(def_arrays[i]);
        char *tmp_name = NULL;
        CT_RETURN_IFERR(sql_alloc_mem(stmt->context, CT_NAME_BUFFER_SIZE, (pointer_t *)&tmp_name));
        status = ctc_get_partition_real_name(&stmt->session->knl_session, i, req, tmp_name, CT_NAME_BUFFER_SIZE);
        if (status != CT_SUCCESS) {
            CT_LOG_RUN_ERR("ctc_truncate_partition: failed to get the (sub)partition name, ret = %d.", status);
            break;
        }
        ctc_fill_common_truncate_partiton_def(def, req, tmp_name);
    }
    knl_dictionary_t dc;
    if (knl_open_dc(&session->knl_session, &(def_arrays->user), &(def_arrays->name), &dc) != CT_SUCCESS) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not find", T2S(&(def_arrays->name)));
        return CT_ERROR;
    }
    RETURN_IF_OPERATION_UNSUPPORTED(&dc, "truncate partition");

    status = ctc_ddl_lock_table(session, &dc, NULL, CT_FALSE);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_LOCK_ALTER_TABLE]:alter table to lock table failed, ret:%d,"
                       "conn_id:%u, ctc_instance_id:%u", (int)status, ddl_ctrl->tch.thd_id, ddl_ctrl->tch.inst_id);
        knl_close_dc(&dc);
        ctc_ddl_unlock_table(&session->knl_session, CT_TRUE);
        CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    }
    status = knl_alter_table4mysql(session, stmt, def_arrays, n_defs_num, &dc, true);
    uint32_t part_cnt = req->is_subpart ? DC_TABLE(&dc)->part_table->desc.subpart_cnt : DC_TABLE(&dc)->part_table->desc.partcnt;
    if (status == CT_SUCCESS && part_cnt == n_defs_num) {
        status = knl_reset_serial_value(&session->knl_session, dc.handle);
        if (status != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[TRUNCATE TABLE] Failed to check table %s", T2S_EX(&def->name));
        }
    }
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("ctc_truncate_partition: faild to truncate partitions");
        knl_alter_table_rollback(&session->knl_session, &dc, true);
        knl_close_dc(&dc);
        ctc_ddl_unlock_table(&session->knl_session, CT_TRUE);
        CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    } else {
        knl_alter_table_commit(&session->knl_session, stmt, &dc, true);
        knl_close_dc(&dc);
        ctc_ddl_unlock_table(&session->knl_session, CT_TRUE);
    }
    ctc_ddl_clear_stmt(stmt);

    ctc_ddl_broadcast_request broadcast_req = {0};
    FILL_BROADCAST_REQ(broadcast_req, req->db_name, req->sql_str, ddl_ctrl->user_name, ddl_ctrl->user_ip,
                       ddl_ctrl->mysql_inst_id, ddl_ctrl->tch.sql_command);
    int broadcat_ret = ctc_execute_mysql_ddl_sql(&ddl_ctrl->tch, &broadcast_req, false);
    return broadcat_ret;
}

EXTER_ATTACK int ctc_truncate_partition(void *table_def, ddl_ctrl_t *ddl_ctrl)
{
    TcDb__CtcDDLTruncateTablePartitionDef *req =
        tc_db__ctc_ddltruncate_table_partition_def__unpack(NULL,
                                                           ddl_ctrl->msg_len - sizeof(ddl_ctrl_t),
                                                           table_def + sizeof(ddl_ctrl_t));
    CTC_LOG_RET_VAL_IF_NUL(req, CT_ERROR, "ctc_truncate_partition: null req ptr");
    int ret = ctc_truncate_partition_impl(req, ddl_ctrl);
    tc_db__ctc_ddltruncate_table_partition_def__free_unpacked(req, NULL);
    return ret;
}

static int ctc_create_tmp_table_for_copy(session_t *session, ctc_ddl_def_node_t *def_node,
                                         char *alter_table_name, char *alter_db_name, ddl_ctrl_t *ddl_ctrl)
{
    status_t status;
    knl_dictionary_t dc;
    knl_session_t *knl_session = &session->knl_session;
    sql_stmt_t *stmt = session->current_stmt;
    knl_table_def_t *create_def = (knl_table_def_t *)def_node->ddl_def;
    text_t copy_table = { .str = NULL, .len = 0 };
    text_t copy_db = { .str = NULL, .len = 0 };
    proto_str2text(alter_table_name, &copy_table);
    proto_str2text(alter_db_name, &copy_db);
    status = knl_open_dc(knl_session, &copy_db, &copy_table, &dc);
    if (status != CT_SUCCESS) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not find", T2S(&(copy_table)));
        CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    }
    def_node->uid = dc.uid;
    def_node->oid = dc.oid;

    SYNC_POINT_GLOBAL_START(CTC_CRETAE_TABLE_STATS_ACK_TIMEOUT, NULL, 5000); // delay 5000ms
    SYNC_POINT_GLOBAL_END;
    
    cm_reset_error();
    SYNC_POINT_GLOBAL_START(CTC_CREATE_TABLE_4MYSQL_FAIL, &status, CT_ERROR);
    status = knl_create_table4mysql(knl_session, stmt, create_def);
    SYNC_POINT_GLOBAL_END;

    if (knl_lock_table_self_parent_child_directly(knl_session, &dc) != CT_SUCCESS) {
        knl_close_dc(&dc);
        CT_RETURN_IFERR_NOCLEAR(CT_ERROR, ddl_ctrl);
    }

    knl_close_dc(&dc);
    CT_RETURN_IFERR_NOCLEAR(status, ddl_ctrl);
    
    SYNC_POINT_GLOBAL_START(CTC_CREATE_TABLE_AFTER_KNL_CREATE_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    return status;
}

static int ctc_fill_def_for_create_table(sql_stmt_t *stmt, TcDb__CtcDDLCreateTableDef *req, knl_table_def_t *def,
                                         ddl_ctrl_t *ddl_ctrl)
{
    int status = CT_SUCCESS;
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, CT_NAME_BUFFER_SIZE, (pointer_t *)&def->schema.str));
    proto_str2text_ex(req->schema, &def->schema, CT_NAME_BUFFER_SIZE - 1);
    status = strncpy_s(stmt->session->curr_schema, CT_NAME_BUFFER_SIZE, def->schema.str, def->schema.len);
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, CT_NAME_BUFFER_SIZE, (pointer_t *)&def->name.str));
    proto_str2text_ex(req->name, &def->name, CT_NAME_BUFFER_SIZE - 1);
    CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    proto_str2text(req->space, &def->space);
    def->is_for_create_db = def->space.str == NULL ? CT_TRUE : CT_FALSE;

    cm_galist_init(&def->columns, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->constraints, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->indexs, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->lob_stores, stmt->context, sql_alloc_mem);
    for (int i = 0; i < req->n_columns; i++) {
        knl_column_def_t *column = NULL;
        status = cm_galist_new(&def->columns, sizeof(knl_column_def_t), (pointer_t *)&column);
        CT_RETURN_IFERR(status);
        column->table = (void *)def;
        cm_galist_init(&column->ref_columns, stmt->context, sql_alloc_mem);
        int ret = ctc_fill_column_info(stmt->session, stmt, column, req->columns[i], ddl_ctrl);
        if (ret != CT_SUCCESS) {
            return ret;
        }
        def->has_serial_column = column->is_serial == CT_TRUE ? CT_TRUE : def->has_serial_column;
        if (column->primary) {
            def->pk_inline = CT_TRUE;
        }
        def->rf_inline = def->rf_inline || (column->is_ref);
        def->uq_inline = def->uq_inline || (column->unique);
        def->chk_inline = def->chk_inline || (column->is_check);
    }
    def->create_as_select = req->is_create_as_select;
    def->is_mysql_copy = ddl_ctrl->is_alter_copy;
    
    def->serial_start = req->auto_increment_value;
    def->options = req->options;

    // add logic from sql_parse_table_attrs
    if (def->initrans == 0) {
        def->initrans = knl_get_initrans();
    }

    if (def->pctfree == 0) {
        def->pctfree = CT_PCT_FREE;
    }
    def->cr_mode = CR_PAGE;
    if (ddl_ctrl->table_flags & CTC_INTERNAL_TMP_TABLE) {
        def->is_intrinsic = CT_TRUE;
    }

    def->contains_vircol = (ddl_ctrl->table_flags & CTC_TABLE_CONTAINS_VIRCOL) ? CT_TRUE : CT_FALSE;
    return CT_SUCCESS;
}

static int ctc_verify_for_create_table(sql_stmt_t *stmt, TcDb__CtcDDLCreateTableDef *req, knl_table_def_t *def,
                                       ddl_ctrl_t *ddl_ctrl)
{
    int status = CT_SUCCESS;
    // 处理分区表逻辑
    status = fill_ctc_partition_info(stmt, req, def);
    CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    // 处理外键逻辑
    status = fill_ctc_create_fk_info(stmt, req, def);
    CT_RETURN_IFERR(status);
    // 处理创建索引逻辑
    status = fill_ctc_create_key_info(stmt, req, def);
    CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    
    // 逻辑抄自 sql_parse_create_table 用于创建索引等等
    // column type may be known after as-select parsed, so delay check partition table type
    // column type may be known after as-select parsed, so delay check default/default on update verifying
    CT_RETURN_IFERR(sql_delay_verify_default(stmt, def));

    // column type may be known after as-select parsed, so delay check constraint verifying
    CT_RETURN_IFERR(sql_verify_check_constraint(stmt, def));

    CT_RETURN_IFERR(sql_verify_cons_def(def));
    CT_RETURN_IFERR(sql_verify_auto_increment(stmt, def));
    CT_RETURN_IFERR(sql_verify_array_columns(def->type, &def->columns));
    return CT_SUCCESS;
}

static int ctc_create_table_impl(TcDb__CtcDDLCreateTableDef *req, ddl_ctrl_t *ddl_ctrl)
{
    SYNC_POINT_GLOBAL_START(CTC_CREATE_TABLE_BEFORE_KNL_CREATE_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    int status = CT_SUCCESS;
    CT_RETURN_IFERR(ctc_get_or_new_session(&session, &(ddl_ctrl->tch), true, true, &is_new_session));

    knl_session_t *knl_session = &session->knl_session;
    knl_table_def_t *def = NULL;
    dc_user_t *user = NULL;
    ctc_ddl_def_node_t *def_node = NULL;
    sql_stmt_t *stmt = session->current_stmt;
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_table_def_t), (pointer_t *)&def));
    CT_RETURN_IFERR(ctc_put_ddl_sql_2_stmt(session, req->db_name, req->sql_str));
    def->sysid = CT_INVALID_ID32;
    stmt->context->type = CTSQL_TYPE_CREATE_TABLE;
    stmt->context->entry = def;

    status = ctc_fill_def_for_create_table(stmt, req, def, ddl_ctrl);
    if (status != CT_SUCCESS) {
        return status;
    }

    status = ctc_verify_for_create_table(stmt, req, def, ddl_ctrl);
    if (status != CT_SUCCESS) {
        return status;
    }
    
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(ctc_ddl_def_node_t), (void **)&def_node));

    // 创建临时表
    if (ddl_ctrl->table_flags & CTC_TMP_TABLE) {
        bool32 is_existed = CT_FALSE;
        cm_latch_x(&stmt->session->knl_session.ltt_latch, stmt->session->knl_session.id, NULL);
        def->type = TABLE_TYPE_SESSION_TEMP;
        status = knl_create_ltt(&stmt->session->knl_session, def, &is_existed);
        cm_unlatch(&stmt->session->knl_session.ltt_latch, NULL);
        CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
        if (!(ddl_ctrl->table_flags & CTC_INTERNAL_TMP_TABLE)) {
            ctc_ddl_clear_stmt(stmt);
        }
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(dc_open_user(knl_session, &def->schema, &user));
    status = ctc_ddl_lock_table(session, NULL, user, CT_FALSE);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_LOCK_CREATE_TABLE]:create table to lock table failed, ret:%d,"
                       "conn_id:%u, ctc_instance_id:%u", (int)status, ddl_ctrl->tch.thd_id, ddl_ctrl->tch.inst_id);
    }
    CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);

    ctc_init_ddl_def_node(def_node, CREATE_DEF, (pointer_t *)def, NULL);
    ctc_ddl_def_list_insert(&stmt->ddl_def_list, def_node);

    if (ddl_ctrl->is_alter_copy) {
        return ctc_create_tmp_table_for_copy(session, def_node, req->alter_table_name, req->alter_db_name, ddl_ctrl);
    }

    SYNC_POINT_GLOBAL_START(CTC_CRETAE_TABLE_STATS_ACK_TIMEOUT, NULL, 5000); // delay 5000ms
    SYNC_POINT_GLOBAL_END;
    cm_reset_error();

    SYNC_POINT_GLOBAL_START(CTC_CREATE_TABLE_4MYSQL_FAIL, &status, CT_ERROR);
    status = knl_create_table4mysql(knl_session, stmt, def);
    SYNC_POINT_GLOBAL_END;
    def_node->uid = CT_INVALID_INT32;
    def_node->oid = CT_INVALID_INT32;

    knl_dictionary_t dc;
    if (knl_open_dc(knl_session, &(def->schema), &(def->name), &dc) != CT_SUCCESS) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not find", T2S(&(def->name)));
        CT_RETURN_IFERR_NOCLEAR(CT_ERROR, ddl_ctrl);
    }
    RETURN_IF_OPERATION_UNSUPPORTED(&dc, "create table");
    def_node->uid = dc.uid;
    def_node->oid = dc.oid;

    // knl_create_table4mysql failed, but dc_entry has been created
    if (status != CT_SUCCESS) {
        knl_close_dc(&dc);
        CT_RETURN_IFERR_NOCLEAR(status, ddl_ctrl);
    }
    if (knl_meta_record(knl_session, NULL, &dc, DB_CURR_SCN(knl_session)) != CT_SUCCESS) {
        knl_close_dc(&dc);
        CT_RETURN_IFERR_NOCLEAR(CT_ERROR, ddl_ctrl);
    }
    knl_close_dc(&dc);
    CT_RETURN_IFERR_NOCLEAR(status, ddl_ctrl);
    
    SYNC_POINT_GLOBAL_START(CTC_CREATE_TABLE_AFTER_KNL_CREATE_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    return status;
}

EXTER_ATTACK int ctc_create_table(void *table_def, ddl_ctrl_t *ddl_ctrl)
{
    INIT_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_CREATE_TABLE);
    BEGIN_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_CREATE_TABLE);
    TcDb__CtcDDLCreateTableDef *req = tc_db__ctc_ddlcreate_table_def__unpack(NULL,
        ddl_ctrl->msg_len - sizeof(ddl_ctrl_t), (uint8_t*)((char*)table_def + sizeof(ddl_ctrl_t)));
    CTC_LOG_RET_VAL_IF_NUL(req, CT_ERROR, "ctc_create_table: null req ptr");
    int ret = ctc_create_table_impl(req, ddl_ctrl);
    tc_db__ctc_ddlcreate_table_def__free_unpacked(req, NULL);
    END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_CREATE_TABLE);
    return ret;
}

void fill_common_alter_def(sql_stmt_t *stmt, TcDb__CtcDDLAlterTableDef *req, knl_altable_def_t *def)
{
    cm_galist_init(&def->column_defs, stmt->context, sql_alloc_mem);
    cm_galist_clean(&def->column_defs);
    proto_str2text(req->user, &def->user);
    proto_str2text(req->name, &def->name);
    def->index_def = NULL;
    def->alindex_def = NULL;
    def->drop_index_def = NULL;
    def->options = req->options;
    def->is_for_create_db = CT_TRUE;
}

static int ctc_fill_drop_index_only(sql_stmt_t *stmt, TcDb__CtcDDLAlterTableDef *req, int req_idx,
                                    knl_altable_def_t **alterdef_ptr)
{
    knl_altable_def_t *alter_def = *alterdef_ptr;
    int32_t key_type = req->drop_key_list[req_idx]->key_type;
    if (key_type == CTC_KEYTYPE_PRIMARY || key_type == CTC_KEYTYPE_UNIQUE) {
        // 通过drop constraint的形式才能删除，但是cantian侧的constraint name需要查询系统表
        return CT_SUCCESS; // 后面通过drop constraint处理
    }
    fill_common_alter_def(stmt, req, alter_def);
    knl_drop_def_t *def = NULL;

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_drop_def_t), (pointer_t *)&def));

    proto_str2text(req->user, &def->owner);   // 用户名
    proto_str2text(req->name, &def->ex_name); // 表名
    proto_str2text(req->drop_key_list[req_idx]->name, &(def->name));

    alter_def->drop_index_def = def;
    (*alterdef_ptr)++;

    return CT_SUCCESS;
}

static int ctc_fill_add_index(sql_stmt_t *stmt, knl_altable_def_t **altable_def_ptr, TcDb__CtcDDLAlterTableDef *req)
{
    for (int i = 0; i < req->n_add_key_list; ++i) {
        TcDb__CtcDDLTableKey *alter_key = req->add_key_list[i];
        if (alter_key->is_constraint) {
            // 约束不在此接口中创建
            continue;
        }

        knl_index_def_t *def = NULL;
        knl_altable_def_t *altable_def = *altable_def_ptr;
        fill_common_alter_def(stmt, req, altable_def);

        CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_index_def_t), (pointer_t *)&def));

        proto_str2text(alter_key->user, &def->user);   // 用户名
        proto_str2text(alter_key->table, &def->table); // 表名

        alter_key->key_type = (alter_key->key_type == CTC_KEYTYPE_FOREIGN) ? CTC_KEYTYPE_MULTIPLE : alter_key->key_type;

        proto_str2text(alter_key->name, &def->name);
        def->type = INDEX_TYPE_BTREE; // 高斯db目前只支持这一种key
        def->is_func = alter_key->is_func;
        def->is_for_create_db = CT_TRUE;
        cm_galist_init(&def->columns, stmt->context, sql_alloc_mem);
        for (int j = 0; j < alter_key->n_columns; ++j) {
            knl_index_col_def_t *key_column = NULL;
            CT_RETURN_IFERR(cm_galist_new(&def->columns, sizeof(knl_index_col_def_t), (void **)&key_column));
            CT_RETURN_IFERR(ctc_ddl_fill_key_column(alter_key->columns[j], key_column));
        }
        knl_dictionary_t dc;
        knl_handle_t knl = &stmt->session->knl_session;
        if (knl_open_dc(knl, (text_t *)&altable_def->user, (text_t *)&altable_def->name, &dc) != CT_SUCCESS) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not find", T2S(&altable_def->name));
            return CT_ERROR;
        }
        if (knl_is_part_table(dc.handle)) {
            def->parted = CT_TRUE;
            def->initrans = knl_get_initrans();
            def->pctfree = CT_PCT_FREE;
            def->cr_mode = CR_PAGE;
        }
        def->parallelism = alter_key->parallelism;
        knl_close_dc(&dc);
        altable_def->index_def = def;
        (*altable_def_ptr)++;
    }
    return CT_SUCCESS;
}

static void ctc_fill_constraint_defs(sql_stmt_t *stmt, knl_constraint_def_t *cons,
    text_t user_name, text_t table_name, ctc_key_type cons_type)
{
    cons->type = (cons_type == CTC_KEYTYPE_UNIQUE) ? CONS_TYPE_UNIQUE : CONS_TYPE_PRIMARY;
    
    knl_index_def_t *index = &cons->index;
    index->user = user_name;
    index->table = table_name;
    index->name = cons->name;
    index->type = INDEX_TYPE_BTREE;
    index->unique = (cons_type == CTC_KEYTYPE_UNIQUE) ? CT_TRUE : CT_FALSE;
    index->primary = (cons_type == CTC_KEYTYPE_PRIMARY) ? CT_TRUE : CT_FALSE;
    index->parted = CT_FALSE;
    index->is_for_create_db = CT_TRUE;
}

static int ctc_fill_add_constraint(knl_session_t *session, sql_stmt_t *stmt, knl_altable_def_t **def_ptr,
                                   TcDb__CtcDDLAlterTableDef *req)
{
    status_t status;
    knl_dictionary_t dc;
    knl_handle_t knl = &stmt->session->knl_session;
    knl_altable_def_t *def = NULL;
    bool32 is_parted_index = 0;

    for (int i = 0; i < req->n_add_key_list; ++i) {
        TcDb__CtcDDLTableKey *alter_key = req->add_key_list[i];

        if (!alter_key->is_constraint || alter_key->key_type == CTC_KEYTYPE_FOREIGN) {
            continue;
        }
        def = *def_ptr;
        fill_common_alter_def(stmt, req, def);
        if (i == 0) {
            if (knl_open_dc(knl, (text_t *)&def->user, (text_t *)&def->name, &dc) != CT_SUCCESS) {
                CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not find", T2S(&def->name));
                return CT_ERROR;
            }
            is_parted_index = knl_is_part_table(dc.handle);
            knl_close_dc(&dc);
        }
        def->action = ALTABLE_ADD_CONSTRAINT;
        knl_constraint_def_t *cons = &def->cons_def.new_cons;

        cons->cons_state.is_enable = CT_TRUE;
        cons->cons_state.is_validate = CT_TRUE;
        cons->cons_state.is_cascade = CT_TRUE;
        cons->cons_state.is_use_index = CT_TRUE;

        if (sql_alloc_mem(stmt->context, CT_NAME_BUFFER_SIZE, (pointer_t *)&def->cons_def.name.str) != CT_SUCCESS) {
            return CT_ERROR;
        }

        proto_str2text(alter_key->name, &cons->name);

        ctc_fill_constraint_defs(stmt, cons, def->user, def->name, alter_key->key_type);
        knl_index_def_t *index = &cons->index;
        index->name = cons->name;
        index->parted = is_parted_index;
        index->initrans = knl_get_initrans();
        index->pctfree = CT_PCT_FREE;
        index->cr_mode = CR_PAGE;

        cm_galist_init(&cons->columns, stmt->context, sql_alloc_mem);
        for (int j = 0; j < alter_key->n_columns; j++) {
            TcDb__CtcDDLTableKeyPart *ck_key_part = alter_key->columns[j];
            knl_index_col_def_t *key_column_cond = NULL;
            status = cm_galist_new(&cons->columns, sizeof(knl_index_col_def_t), (void **)&key_column_cond);
            CT_RETURN_IFERR(status);
            CT_RETURN_IFERR(ctc_ddl_fill_key_column(ck_key_part, key_column_cond));
        }
        (*def_ptr)++;
    }

    return CT_SUCCESS;
}

static int ctc_fill_drop_constraint(sql_stmt_t *stmt, knl_altable_def_t **def_ptr,
    TcDb__CtcDDLAlterTableDef *req, int req_idx)
{
    knl_altable_def_t *def = *def_ptr;
    fill_common_alter_def(stmt, req, def);
    TcDb__CtcDDLAlterTableDrop *alter = req->drop_list[req_idx];
    knl_constraint_def_t *cons = &def->cons_def.new_cons;

    proto_str2text(alter->name, &def->cons_def.name);

    if (alter->key_type == CTC_KEYTYPE_FOREIGN) {
        cons->type = CONS_TYPE_REFERENCE;
    }

    def->action = ALTABLE_DROP_CONSTRAINT;
    def->is_for_create_db = CT_TRUE;

    (*def_ptr)++;

    return CT_SUCCESS;
}

static int ctc_fill_drop_index_constraint(sql_stmt_t *stmt, knl_altable_def_t **def_ptr,
    TcDb__CtcDDLAlterTableDef *req, int req_idx)
{
    knl_altable_def_t *def = *def_ptr;
    fill_common_alter_def(stmt, req, def);
    TcDb__CtcDDLAlterTableDropKey *alter = req->drop_key_list[req_idx];
    knl_constraint_def_t *cons = &def->cons_def.new_cons;

    proto_str2text(alter->name, &def->cons_def.name);
    def->action = ALTABLE_DROP_CONSTRAINT;
    def->is_for_create_db = CT_TRUE;

    (*def_ptr)++;

    return CT_SUCCESS;
}

static int ctc_fill_drop_index(sql_stmt_t *stmt, knl_altable_def_t **def_ptr, TcDb__CtcDDLAlterTableDef *req)
{
    status_t status = CT_SUCCESS;
    for (int i = 0; i < req->n_drop_key_list; ++i) {
        if ((req->drop_key_list[i]->key_type == CTC_KEYTYPE_PRIMARY ||
            req->drop_key_list[i]->key_type == CTC_KEYTYPE_UNIQUE ||
            req->drop_key_list[i]->key_type == CTC_KEYTYPE_FOREIGN)) {
            status = ctc_fill_drop_index_constraint(stmt, def_ptr, req, i);
        } else {
            status = ctc_fill_drop_index_only(stmt, req, i, def_ptr);
        }
    }
    return status;
}

static int ctc_fill_drop_column(sql_stmt_t *stmt, knl_altable_def_t **def_ptr, TcDb__CtcDDLAlterTableDef *req)
{
    status_t status = CT_SUCCESS;
    for (int i = 0; i < req->n_drop_list; ++i) {
        bool alter_drop = false;
        knl_alt_column_prop_t *column_def = NULL;
        knl_altable_def_t *def = *def_ptr;
        fill_common_alter_def(stmt, req, def);
        CT_RETURN_IFERR(cm_galist_new(&def->column_defs, sizeof(knl_alt_column_prop_t), (void **)&column_def));
        switch (req->drop_list[i]->drop_type) {
            case CTC_ALTER_TABLE_DROP_COLUMN:
                def->action = ALTABLE_DROP_COLUMN;
                proto_str2text(req->drop_list[i]->name, &column_def->name);
                alter_drop = true;
                break;
            case CTC_ALTER_TABLE_DROP_ANY_CONSTRAINT:
            case CTC_ALTER_TABLE_DROP_CHECK_CONSTRAINT:
                break;
            case CTC_ALTER_TABLE_DROP_FOREIGN_KEY:
                status = ctc_fill_drop_constraint(stmt, def_ptr, req, i);
                break;
            case CTC_ALTER_TABLE_DROP_KEY:
                // 删除索引通过n_drop_key_list处理
                break;
            default:
                break;
        }
        if (!alter_drop) {
            continue;
        }
        (*def_ptr)++;
    }

    return CT_SUCCESS;
}

static int ctc_fill_rename_and_set_column_default(session_t *session, sql_stmt_t *stmt, knl_altable_def_t **def_ptr,
                                                  TcDb__CtcDDLAlterTableDef *req, bool *rename_column_flag,
                                                  ddl_ctrl_t *ddl_ctrl)
{
    int err_code;
    for (int i = 0; i < req->n_alter_list; ++i) {
        knl_altable_def_t *def = *def_ptr;
        fill_common_alter_def(stmt, req, def);
        ctc_column_option_set_bit option_set;
        option_set.is_option_set = 0;
        knl_column_def_t *column = NULL;
        knl_alt_column_prop_t *column_def = NULL;
        CT_RETURN_IFERR(cm_galist_new(&def->column_defs, sizeof(knl_alt_column_prop_t), (void **)&column_def));
        option_set.is_option_set = column_def->new_column.is_option_set;

        for (int j = 0; j < req->n_create_list; ++j) {
            if (req->create_list[j]->name != NULL &&
                strcasecmp(req->alter_list[i]->name, req->create_list[j]->name) == 0) {
                column = &column_def->new_column;
                column->table = (void *)def;
                err_code = ctc_fill_column_info(session, stmt, column, req->create_list[j], ddl_ctrl);
                break;
            }
        }
        if (err_code != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[ctc_fill_rename_and_set_column_default]:fill column info failed, err_code:%d", err_code);
            return CT_ERROR;
        }

        proto_str2text(req->alter_list[i]->name, &column_def->name);
        switch (req->alter_list[i]->type) {
            case CTC_ALTER_COLUMN_SET_DEFAULT:
                if (column == NULL) {
                    CT_LOG_RUN_ERR("[ctc_fill_rename_and_set_column_default]: column is null");
                    return CT_ERROR;
                }
                def->action = ALTABLE_MODIFY_COLUMN;
                option_set.is_default = 1;
                option_set.is_serial = column->is_serial;
                if (req->alter_list[i]->is_default_null) {
                    option_set.is_default_null = 1;
                    option_set.nullable = 1;
                }
                break;
            case CTC_ALTER_COLUMN_DROP_DEFAULT:
                def->action = ALTABLE_MODIFY_COLUMN;
                option_set.is_default = 0;
                break;
            case CTC_ALTER_COLUMN_RENAME_COLUMN:
                *rename_column_flag = true;
                def->action = ALTABLE_RENAME_COLUMN;
                proto_str2text(req->alter_list[i]->new_name, &column_def->new_name);
                break;
            case CTC_ALTER_COLUMN_SET_COLUMN_VISIBLE:
            case CTC_ALTER_COLUMN_SET_COLUMN_INVISIBLE:
                // 设置列invisible or visible, cantian不需要执行任何操作
                continue;
            default:
                break;
        }

        column_def->new_column.is_option_set = option_set.is_option_set;
        (*def_ptr)++;
    }

    return CT_SUCCESS;
}

static int ctc_fill_add_column(session_t *session, sql_stmt_t *stmt, knl_altable_def_t **def_ptr,
                               TcDb__CtcDDLAlterTableDef *req, ddl_ctrl_t *ddl_ctrl)
{
    int add_column_cnt = 0;
    knl_altable_def_t *def = *def_ptr;
    for (int i = 0; i < req->n_create_list; ++i) {
        if (req->create_list[i]->alter_mode != CTC_ALTER_COLUMN_ALTER_ADD_COLUMN) {
            continue;
        }

        add_column_cnt++;
        // 不重复初始化def && 避免赋值无效def，踩内存
        if (add_column_cnt == 1) {
            fill_common_alter_def(stmt, req, def);
            def->action = ALTABLE_ADD_COLUMN;
        }
        knl_column_def_t *column = NULL;
        knl_alt_column_prop_t *column_def = NULL;
        CT_RETURN_IFERR(cm_galist_new(&def->column_defs, sizeof(knl_alt_column_prop_t), (void **)&column_def));
        column = &column_def->new_column;
        column->table = (void *)def;
        int ret = ctc_fill_column_info(session, stmt, column, req->create_list[i], ddl_ctrl);
        if (ret != CT_SUCCESS) {
            return ret;
        }

        ctc_column_option_set_bit op_bitmap = (ctc_column_option_set_bit)req->create_list[i]->is_option_set;
        if (op_bitmap.unique || op_bitmap.primary) {
            knl_constraint_def_t *cons = NULL;
            char *ctc_cons_name = req->create_list[i]->cons_name;
            cm_galist_init(&column_def->constraints, stmt->context, sql_alloc_mem);
            CT_RETURN_IFERR(cm_galist_new(&column_def->constraints, sizeof(knl_constraint_def_t), (pointer_t *)&cons));
            
            cm_galist_init(&cons->columns, stmt->context, sql_alloc_mem);
            knl_index_col_def_t *key_column_cond = NULL;
            CT_RETURN_IFERR(cm_galist_new(&cons->columns, sizeof(knl_index_col_def_t), (void **)&key_column_cond));
            key_column_cond->name = column->name;
            key_column_cond->size = column->size;
            ctc_key_type cons_type = (op_bitmap.unique) ? CTC_KEYTYPE_UNIQUE : CTC_KEYTYPE_PRIMARY;

            if (ctc_cons_name == NULL) {
                return CT_ERROR;
            }
            proto_str2text(ctc_cons_name, &cons->name);
            ctc_fill_constraint_defs(stmt, cons, def->user, def->name, cons_type);
        }
    }

    if (add_column_cnt > 0) {
        (*def_ptr)++; // 多个add column可以只下发一次knl
    }

    return CT_SUCCESS;
}

static int ctc_fill_modify_column(session_t *session, sql_stmt_t *stmt, knl_altable_def_t **def_ptr,
                                  TcDb__CtcDDLAlterTableDef *req, bool rename_column_flag, ddl_ctrl_t *ddl_ctrl)
{
    for (int i = 0; i < req->n_create_list; ++i) {
        if (req->create_list[i]->alter_mode != CTC_ALTER_COLUMN_ALTER_MODIFY_COLUMN ||
            (rename_column_flag && strlen(req->create_list[i]->new_name))) {
            continue;
        }
        knl_altable_def_t *def = *def_ptr;
        fill_common_alter_def(stmt, req, def);
        def->action = ALTABLE_MODIFY_COLUMN;

        knl_column_def_t *column = NULL;
        knl_alt_column_prop_t *column_def = NULL;
        CT_RETURN_IFERR(cm_galist_new(&def->column_defs, sizeof(knl_alt_column_prop_t), (void **)&column_def));
        column = &column_def->new_column;
        column->table = (void *)def;
        column->is_option_set = req->create_list[i]->is_option_set;
        proto_str2text(req->create_list[i]->name, &column_def->name);
        int ret = ctc_fill_column_info(session, stmt, column, req->create_list[i], ddl_ctrl);
        if (ret != CT_SUCCESS) {
            return ret;
        }
        // 避免db_altable_add_column->db_altable_create_inline_constraints去创建索引
        column->is_check = 0;
        column->unique = 0;
        column->primary = 0;
        (*def_ptr)++;

        if (strlen(req->create_list[i]->new_name)) {
            def = *def_ptr; // 指向def下一个数组元素
            fill_common_alter_def(stmt, req, def);
            def->action = ALTABLE_RENAME_COLUMN;

            CT_RETURN_IFERR(cm_galist_new(&def->column_defs, sizeof(knl_alt_column_prop_t), (void **)&column_def));
            proto_str2text(req->create_list[i]->new_name, &column_def->new_name);
            proto_str2text(req->create_list[i]->name, &column_def->name);
            (*def_ptr)++;
        }
    }

    return CT_SUCCESS;
}

static int ctc_fill_rename_constraint(knl_handle_t *session, sql_stmt_t *stmt, knl_altable_def_t *def,
    char *cons_old_name, char *cons_new_name)
{
    knl_constraint_def_t *cons = &def->cons_def.new_cons;

    proto_str2text(cons_old_name, &def->cons_def.name);
    proto_str2text(cons_new_name, &def->cons_def.new_cons.name);

    def->action = ALTABLE_RENAME_CONSTRAINT;
    def->is_for_create_db = CT_TRUE;
    return CT_SUCCESS;
}

static int ctc_fill_alter_index(knl_handle_t *session, sql_stmt_t *stmt, knl_altable_def_t **altable_def_ptr,
                                sql_type_t type, TcDb__CtcDDLAlterTableDef *req)
{
    status_t status;
    for (int i = 0; i < req->n_alter_index_list; ++i) {
        TcDb__CtcDDLAlterIndexDef *index = req->alter_index_list[i];

        knl_alindex_def_t *def = NULL;
        knl_altable_def_t *altable_def = *altable_def_ptr;
        fill_common_alter_def(stmt, req, altable_def);

        CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_alindex_def_t), (pointer_t *)&def));
        proto_str2text(index->user, &def->user);   // 用户名
        proto_str2text(index->table, &def->table); // 表名
        proto_str2text(index->name, &def->name);
        def->is_for_create_db = CT_TRUE;

        if (strlen(index->new_name) != 0) { // rename index
            def->type = ALINDEX_TYPE_RENAME;
            proto_str2text(index->new_name, &def->idx_def.new_name);
        } else {
            def->type = ALINDEX_TYPE_REBUILD;
            def->rebuild.cr_mode = CR_PAGE;
        }

        altable_def->alindex_def = def;
        (*altable_def_ptr)++;

        if ((index->key_type == CTC_KEYTYPE_PRIMARY || index->key_type == CTC_KEYTYPE_UNIQUE) &&
            strlen(index->new_name) != 0) {
            // 因为primary key和unique key二者的constraint name和index name一致，所以需要也修改constraint name
            altable_def = *altable_def_ptr;
            fill_common_alter_def(stmt, req, altable_def);
            status = ctc_fill_rename_constraint(session, stmt, altable_def, index->name, index->new_name);
            (*altable_def_ptr)++;
            if (status != CT_SUCCESS) {
                return status;
            }
        }
    }
    return CT_SUCCESS;
}

static int ctc_fill_add_foreign_key(sql_stmt_t *stmt, knl_altable_def_t **def_ptr,
    TcDb__CtcDDLAlterTableDef *req)
{
    status_t status = CT_SUCCESS;
    if (req->n_add_foreign_key_list > 0) {
        knl_altable_def_t *def = *def_ptr;
        fill_common_alter_def(stmt, req, def);
        status = fill_ctc_alter_fk_info(stmt, req, def);
        if (status != CT_SUCCESS) {
            return status;
        }
        def->action = ALTABLE_ADD_CONSTRAINT;
        (*def_ptr)++;
    }

    return status;
}

static int ctc_fill_drop_partition(sql_stmt_t *stmt, knl_altable_def_t **def_ptr,
    TcDb__CtcDDLAlterTableDef *req)
{
    for (uint32_t i = 0; i < req->n_drop_partition_names; i++) {
        knl_altable_def_t *def = *def_ptr;
        fill_common_alter_def(stmt, req, def);
        proto_str2text(req->drop_partition_names[i], &def->part_def.name); // 删除分区 只能一个一个删除
        def->action = ALTABLE_DROP_PARTITION;

        (*def_ptr)++;
    }

    return CT_SUCCESS;
}

static int ctc_fill_coalesce_partition(sql_stmt_t *stmt, knl_altable_def_t **def_ptr,
    TcDb__CtcDDLAlterTableDef *req)
{
    if (req->hash_coalesce_count <= 0) {
        return CT_SUCCESS;
    }

    for (uint32_t i = 0; i < req->hash_coalesce_count; i++) {
        knl_altable_def_t *def = *def_ptr;
        fill_common_alter_def(stmt, req, def);
        def->action = ALTABLE_COALESCE_PARTITION;
        (*def_ptr)++;
    }

    return CT_SUCCESS;
}

static int ctc_fill_add_partition(sql_stmt_t *stmt, knl_altable_def_t **def_ptr,
    TcDb__CtcDDLAlterTableDef *req)
{
    knl_column_t *knl_column = NULL;
    knl_dictionary_t dc;
    knl_part_column_def_t *part_column = NULL;
    knl_handle_t knl = &stmt->session->knl_session;

    for (uint32_t idx = 0; idx < req->n_add_part_list; idx++) {
        knl_altable_def_t *def = *def_ptr;
        fill_common_alter_def(stmt, req, def);

        if (knl_open_dc(knl, (text_t *)&def->user, (text_t *)&def->name, &dc) != CT_SUCCESS) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not find", T2S(&def->name));
            return CT_ERROR;
        }

        if (!knl_is_part_table(dc.handle)) {
            knl_close_dc(&dc);
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not partition table", T2S(&def->name));
            return CT_ERROR;
        }

        if (sql_alloc_mem(stmt->context, sizeof(knl_part_obj_def_t),
            (pointer_t *)&def->part_def.obj_def) != CT_SUCCESS) {
            knl_close_dc(&dc);
            return CT_ERROR;
        }

        def->part_def.obj_def->part_type = knl_part_table_type(dc.handle);
        def->part_def.obj_def->subpart_type = knl_subpart_table_type(dc.handle);
        if (def->part_def.obj_def->subpart_type != PART_TYPE_INVALID) {
            def->part_def.obj_def->is_composite = CT_TRUE;
        }
        cm_galist_init(&def->part_def.obj_def->parts, stmt->context, sql_alloc_mem);
        cm_galist_init(&def->part_def.obj_def->part_keys, stmt->context, sql_alloc_mem);
        cm_galist_init(&def->part_def.obj_def->group_keys, stmt->context, sql_alloc_mem);
        cm_galist_init(&def->part_def.obj_def->part_store_in.space_list, stmt->context, sql_alloc_mem);
        cm_galist_init(&def->part_def.obj_def->subpart_store_in.space_list, stmt->context, sql_alloc_mem);
        cm_galist_init(&def->part_def.obj_def->subpart_keys, stmt->context, sql_alloc_mem);

        cm_galist_init(&def->part_def.obj_def->parts, stmt->context, sql_alloc_mem);
        if (ctc_sql_part_parse_partition(stmt, def->part_def.obj_def, req->add_part_list[idx]) != CT_SUCCESS) {
            knl_close_dc(&dc);
            return CT_ERROR;
        }

        knl_close_dc(&dc);
        def->action = ALTABLE_ADD_PARTITION;
        (*def_ptr)++;
    }

    return CT_SUCCESS;
}

// 处理分区表功能
int fill_handler_partition_table(sql_stmt_t *stmt, knl_altable_def_t **def_ptr, TcDb__CtcDDLAlterTableDef *req)
{
    status_t status;
    // 删除分区
    status = ctc_fill_drop_partition(stmt, def_ptr, req);
    CT_RETURN_IFERR(status);

    // 增加分区
    status = ctc_fill_add_partition(stmt, def_ptr, req);
    CT_RETURN_IFERR(status);

    // hash分区coalesce
    status = ctc_fill_coalesce_partition(stmt, def_ptr, req);
    CT_RETURN_IFERR(status);
    return status;
}

static void ctc_fill_modify_auto_inc_value(sql_stmt_t *stmt, knl_altable_def_t **def_ptr,
    TcDb__CtcDDLAlterTableDef *req)
{
    knl_altable_def_t *def = *def_ptr;
    fill_common_alter_def(stmt, req, def);
    def->action = ALTABLE_AUTO_INCREMENT;
    def->table_def.serial_start = req->new_auto_increment_value;

    (*def_ptr)++;
}

size_t ctc_get_add_or_modify_column_ops(TcDb__CtcDDLAlterTableDef *req)
{
    int count = 0;
    bool has_add_column = false; // just one def fills added multi column_defs in add column
    for (int i = 0; i < req->n_create_list; ++i) {
        if (req->create_list[i]->alter_mode == CTC_ALTER_COLUMN_ALTER_ADD_COLUMN) {
            has_add_column = true;
        }
        if (req->create_list[i]->alter_mode == CTC_ALTER_COLUMN_ALTER_MODIFY_COLUMN) {
            count++;
            if (strlen(req->create_list[i]->new_name)) {
                count++;
            }
        }
    }
    if (has_add_column) {
        count++;
    }
    return count;
}

size_t ctc_get_alter_index_ops(TcDb__CtcDDLAlterTableDef *req)
{
    int count = 0;
    for (int i = 0; i < req->n_alter_index_list; ++i) {
        TcDb__CtcDDLAlterIndexDef *index = req->alter_index_list[i];
        count++;
        if ((index->key_type == CTC_KEYTYPE_PRIMARY || index->key_type == CTC_KEYTYPE_UNIQUE) &&
            strlen(index->new_name) != 0) {
            count++;
        }
    }
    return count;
}

static int ctc_prepare_for_alter_table(session_t *session, sql_stmt_t *stmt, knl_altable_def_t **def_ptr,
                                       TcDb__CtcDDLAlterTableDef *req, ddl_ctrl_t *ddl_ctrl)
{
    int status = CT_SUCCESS;
    bool rename_column_flag = false;
    knl_altable_def_t *def = *def_ptr;
    sql_copy_str(stmt->context, req->user, &def->user);
    sql_copy_str(stmt->context, req->name, &def->name);
    CT_RETURN_IFERR(sql_regist_ddl_table(stmt, &def->user, &def->name));

    status = ctc_fill_drop_index(stmt, def_ptr, req);
    CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);

    status = ctc_fill_rename_and_set_column_default(session, stmt, def_ptr, req, &rename_column_flag, ddl_ctrl);
    CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);

    // 修改索引名
    status = ctc_fill_alter_index((knl_handle_t)(&session->knl_session), stmt, def_ptr,
                                  CTSQL_TYPE_ALTER_TABLE, req);
    CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);

    status = ctc_fill_modify_column(session, stmt, def_ptr, req, rename_column_flag, ddl_ctrl);
    CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);

    status = ctc_fill_add_column(session, stmt, def_ptr, req, ddl_ctrl);
    CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);

    status = ctc_fill_drop_column(stmt, def_ptr, req);
    CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);

    status = ctc_fill_add_foreign_key(stmt, def_ptr, req);
    CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);

    status = ctc_fill_add_index(stmt, def_ptr, req);
    CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);

    // 增加primary key，unique key
    status = ctc_fill_add_constraint(session, stmt, def_ptr, req);
    CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);

    if (req->new_auto_increment_value) {
        ctc_fill_modify_auto_inc_value(stmt, def_ptr, req);
    }

    status = fill_handler_partition_table(stmt, def_ptr, req);
    CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);

    return CT_SUCCESS;
}

static int ctc_alter_table_atomic_impl(TcDb__CtcDDLAlterTableDef *req, ddl_ctrl_t *ddl_ctrl)
{
    SYNC_POINT_GLOBAL_START(CTC_ALTER_TABLE_BEFORE_KNL_ALTER_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    knl_altable_def_t *def = NULL;
    sql_stmt_t *stmt = NULL;
    ctc_ddl_def_node_t *def_node = NULL;
    knl_altable_def_t *start_def = NULL;
    size_t alter_op_max_nums = 0;
    size_t add_or_modify_ops = 0;
    uint32_t user_len = (req->user == NULL ? 0 : strlen(req->user));
    int status = CT_SUCCESS;
    CT_RETURN_IFERR(ctc_get_or_new_session(&session, &(ddl_ctrl->tch), true, true, &is_new_session));

    stmt = session->current_stmt;
    stmt->session->call_version = CS_VERSION_8;
    stmt->v_systimestamp = req->systimestamp;
    stmt->tz_offset_utc = req->tz_offset_utc + TIMEZONE_OFFSET_DEFAULT;
    stmt->context->type = CTSQL_TYPE_ALTER_TABLE;

    // 提前计算增列和改列操作数，代替使用n_create_list造成列数过多，分配不出最大的def内存
    add_or_modify_ops = ctc_get_add_or_modify_column_ops(req);
    MEMS_RETURN_IFERR(strncpy_s(stmt->session->curr_schema, CT_NAME_BUFFER_SIZE, req->user, user_len));

    alter_op_max_nums = req->n_drop_list + req->n_alter_list + add_or_modify_ops + req->n_add_key_list +
                        req->n_drop_key_list + req->n_add_foreign_key_list + ctc_get_alter_index_ops(req) +
                        req->n_drop_partition_names + req->n_add_part_list + req->hash_coalesce_count +
                        (req->new_auto_increment_value ? 1 : 0);
    int alter_op_fake_nums = alter_op_max_nums == 0 ? 1 : alter_op_max_nums;
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_altable_def_t) * alter_op_fake_nums, (pointer_t *)&def));
    start_def = def;
    stmt->context->entry = start_def; // def值会变化，后面会逐个往后偏移knl_altable_def_t大小

    CT_RETURN_IFERR(ctc_put_ddl_sql_2_stmt(session, req->db_name, req->sql_str));

    status = ctc_prepare_for_alter_table(session, stmt, &def, req, ddl_ctrl);
    if (status != CT_SUCCESS) {
        return status;
    }
    start_def->contains_vircol = (ddl_ctrl->table_flags & CTC_TABLE_CONTAINS_VIRCOL) ? CT_TRUE : CT_FALSE;

    uint32 def_count = ((uint64)def - (uint64)start_def) / sizeof(knl_altable_def_t);
    ctc_context_t *ctc_context = ctc_get_ctx_by_addr(ddl_ctrl->tch.ctx_addr);
    CTC_LOG_RET_VAL_IF_NUL(ctc_context, ERR_INVALID_DC, "get_ha_context failed");

    if (ddl_ctrl->tch.read_only_in_ct) {
        CT_LOG_RUN_ERR("Operation alter table is not supported on view, func, join table, "
                       "json table, subqueries or system table");
        return CT_ERROR;
    }
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(ctc_ddl_def_node_t), (void **)&def_node));
    status = ctc_ddl_lock_table(session, ctc_context->dc, NULL, CT_FALSE);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_LOCK_ALTER_TABLE]:alter table to lock table failed, ret:%d,"
                       "conn_id:%u, ctc_instance_id:%u", (int)status, ddl_ctrl->tch.thd_id, ddl_ctrl->tch.inst_id);
    }
    CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    SYNC_POINT_GLOBAL_START(CTC_ALTER_TABLE_STATS_ACK_TIMEOUT, NULL, 5000); // delay 5000ms
    SYNC_POINT_GLOBAL_END;

    ctc_init_ddl_def_node(def_node, ALTER_DEF, (pointer_t *)start_def, ctc_context->dc);
    ctc_ddl_def_list_insert(&stmt->ddl_def_list, def_node);

    cm_reset_error();
    SYNC_POINT_GLOBAL_START(CTC_ALTER_TABLE_4MYSQL_FAIL, &status, CT_ERROR);
    status = knl_alter_table4mysql(session, stmt, start_def, def_count, ctc_context->dc, true);
    SYNC_POINT_GLOBAL_END;

    CT_RETURN_IFERR_NOCLEAR(status, ddl_ctrl);
    
    SYNC_POINT_GLOBAL_START(CTC_ALTER_TABLE_AFTER_KNL_ALTER_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_alter_table(void *alter_def, ddl_ctrl_t *ddl_ctrl)
{
    INIT_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_ALTER_TABLE);
    BEGIN_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_ALTER_TABLE);
    TcDb__CtcDDLAlterTableDef *req = tc_db__ctc_ddlalter_table_def__unpack(NULL,
        ddl_ctrl->msg_len - sizeof(ddl_ctrl_t), (uint8_t*)((char*)alter_def + sizeof(ddl_ctrl_t)));
    CTC_LOG_RET_VAL_IF_NUL(req, CT_ERROR, "ctc_alter_table: null req ptr");
    int ret = ctc_alter_table_atomic_impl(req, ddl_ctrl);
    tc_db__ctc_ddlalter_table_def__free_unpacked(req, NULL);
    END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_ALTER_TABLE);
    return ret;
}

static void ctc_fill_column_by_dc(knl_column_def_t *column, knl_column_t *dc_column, sql_stmt_t *stmt)
{
    proto_str2text(dc_column->name, &column->name);
    column->datatype = dc_column->datatype;
    column->size = dc_column->size;
    column->nullable = dc_column->nullable;
    column->precision = dc_column->precision;
    column->scale = dc_column->scale;
    column->is_collate = dc_column->is_collate;
    column->mysql_ori_datatype = dc_column->mysql_ori_datatype;
    column->is_unsigned = dc_column->mysql_unsigned;
    column->is_serial = KNL_COLUMN_IS_SERIAL(dc_column);
    column->is_update_default = KNL_COLUMN_IS_UPDATE_DEFAULT(dc_column);
    column->has_quote = KNL_COLUMN_HAS_QUOTE(dc_column);
    column->typmod.is_char = KNL_COLUMN_IS_CHARACTER(dc_column);
    column->is_default_null = KNL_COLUMN_IS_DEFAULT_NULL(dc_column);
    column->typmod.is_array = KNL_COLUMN_IS_ARRAY(dc_column);
    column->is_jsonb = KNL_COLUMN_IS_JSONB(dc_column);

    if (dc_column->default_text.len > 0) {
        column->is_default = CT_TRUE;
        if (sql_alloc_mem(stmt->context, dc_column->default_text.len,
            (pointer_t *)&column->default_text.str) != CT_SUCCESS) {
            return;
        }
        knl_securec_check(memcpy_s(column->default_text.str, dc_column->default_text.len,
                                   dc_column->default_text.str, dc_column->default_text.len));
        column->default_text.len = dc_column->default_text.len;
    }

    if (column->is_collate) {
        column->collate_id = dc_column->collate_id;
    }
}

static status_t ctc_sql_parse_partition_by_dc(knl_part_obj_def_t *obj_def, dc_entity_t *entity, sql_stmt_t *stmt)
{
    status_t status = CT_SUCCESS;
    for (int i = 0; i < obj_def->part_store_in.part_cnt; i++) {
        knl_part_def_t *part_def = NULL;
        CT_RETURN_IFERR(cm_galist_new(&obj_def->parts, sizeof(knl_part_def_t), (pointer_t *)&part_def));
        CT_RETURN_IFERR(sql_alloc_mem(stmt->context, CT_MAX_COLUMN_SIZE, (pointer_t *)&part_def->partkey));

        part_def->is_for_create_db = CT_TRUE;
        cm_galist_init(&part_def->value_list, stmt->context, sql_alloc_mem);
        cm_galist_init(&part_def->subparts, stmt->context, sql_alloc_mem);
        cm_galist_init(&part_def->group_subkeys, stmt->context, sql_alloc_mem);
        part_def->exist_subparts = obj_def->is_composite ? CT_TRUE : CT_FALSE;

        switch (obj_def->part_type) {
            case PART_TYPE_LIST:
            case PART_TYPE_RANGE:
                proto_str2text(entity->table.part_table->groups[0]->entity[i]->desc.name, &part_def->name);
                break;
            case PART_TYPE_HASH:
                status = ctc_sql_parse_hash_partition(stmt, part_def);
                break;
            default:
                status = CT_ERROR;
                break;
        }

        if (obj_def->is_composite) {
            int sub_per_part_count = entity->table.part_table->desc.subpart_cnt /
                                     entity->table.part_table->desc.partcnt;
            for (int j = 0; j < sub_per_part_count; j++) {
                CT_RETURN_IFERR(ctc_sql_subpart_parse_partition(stmt, part_def, obj_def));
            }
        }
    }
    return status;
}

static status_t ctc_fill_partition_by_dc(knl_table_def_t *def, dc_entity_t *entity, sql_stmt_t *stmt)
{
    if (!entity->table.desc.parted) {
        return CT_SUCCESS;
    }
    part_table_t *part_table = entity->table.part_table;
    def->parted = CT_TRUE;
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_part_obj_def_t), (pointer_t *)&def->part_def));
    knl_part_obj_def_t *obj_def = def->part_def;
    obj_def->part_type = entity->table.part_table->desc.parttype;
    obj_def->subpart_type = entity->table.part_table->desc.subparttype;
    obj_def->is_for_create_db = CT_TRUE;
    cm_galist_init(&obj_def->parts, stmt->context, sql_alloc_mem);
    cm_galist_init(&obj_def->part_keys, stmt->context, sql_alloc_mem);
    cm_galist_init(&obj_def->group_keys, stmt->context, sql_alloc_mem);
    cm_galist_init(&obj_def->part_store_in.space_list, stmt->context, sql_alloc_mem);
    cm_galist_init(&obj_def->subpart_store_in.space_list, stmt->context, sql_alloc_mem);
    cm_galist_init(&obj_def->subpart_keys, stmt->context, sql_alloc_mem);

    obj_def->part_store_in.part_cnt = part_table->desc.partcnt;
    if (obj_def->part_store_in.part_cnt == 0) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "invalid partition number");
        return CT_ERROR;
    }

    if (part_table->desc.subpart_cnt > 0) {
        obj_def->is_composite = CT_TRUE;
    }

    CT_RETURN_IFERR(ctc_sql_parse_partition_by_dc(obj_def, entity, stmt));
    return CT_SUCCESS;
}

static void update_default_cons_name(TcDb__CtcDDLRenameTableDef *req, char *fk_name, uint32_t buf_size,
                                     knl_constraint_def_t *cons)
{
    if (strlen(fk_name) <= 0) {
        return;
    }

    uint32 def_count = req->n_old_constraints_name;
    for (int i = 0; i < def_count; i++) {
        if (strncmp(fk_name, req->old_constraints_name[i], strlen(req->old_constraints_name[i])) == 0) {
            proto_str2text_ex(req->new_constraints_name[i], &cons->name, buf_size - 1);
            return;
        }
    }
    proto_str2text_ex(fk_name, &cons->name, buf_size - 1);
}

static status_t ctc_fill_fk_by_dc(TcDb__CtcDDLRenameTableDef *req, knl_session_t *knl_session,
                                  knl_table_def_t *def, knl_dictionary_t *dc, sql_stmt_t *stmt)
{
    knl_dictionary_t ref_dc = {0};
    dc_entity_t *entity = (dc_entity_t *)dc->handle;
    for (int i = 0; i < entity->table.cons_set.ref_count; i++) {
        knl_constraint_def_t *cons = NULL;
        CT_RETURN_IFERR(cm_galist_new(&def->constraints, sizeof(knl_constraint_def_t), (pointer_t *)&cons));
        cons->cons_state.is_enable = CT_TRUE;
        cons->cons_state.is_validate = CT_TRUE;
        cons->cons_state.is_cascade = CT_TRUE;
        cons->type = CONS_TYPE_REFERENCE;
        CT_RETURN_IFERR((sql_alloc_mem(stmt->context, CT_NAME_BUFFER_SIZE, (pointer_t *)&cons->name.str) != CT_SUCCESS));

        knl_reference_def_t *ref = &cons->ref;
        dc_user_t *user = NULL;
        uint32_t ref_uid = entity->table.cons_set.ref_cons[i]->ref_uid;
        uint32_t ref_oid = entity->table.cons_set.ref_cons[i]->ref_oid;

        char fk_name[CT_NAME_BUFFER_SIZE];
        CT_RETURN_IFERR(knl_fill_fk_name_from_sys4mysql(knl_session, fk_name, ref_uid, ref_oid, dc));
        update_default_cons_name(req, fk_name, CT_NAME_BUFFER_SIZE, cons);
        
        CT_RETURN_IFERR(dc_open_user_by_id(knl_session, ref_uid, &user));
        CT_RETURN_IFERR(dc_open_table_directly(knl_session, ref_uid, ref_oid, &ref_dc));
        dc_entity_t *ref_entity = (dc_entity_t *)ref_dc.handle;
        proto_str2text(user->desc.name, &ref->ref_user);
        proto_str2text(ref_entity->table.desc.name, &ref->ref_table);
        ref->refactor = entity->table.cons_set.ref_cons[i]->refactor;
        cm_galist_init(&ref->ref_columns, stmt->context, sql_alloc_mem);
        cm_galist_init(&cons->columns, stmt->context, sql_alloc_mem);

        index_t *ref_dc_index = ref_entity->table.index_set.items[entity->table.cons_set.ref_cons[i]->ref_ix];
        uint16 *fk_column = entity->table.cons_set.ref_cons[i]->cols;
        for (int j = 0; j < ref_dc_index->desc.column_count; j++) {
            knl_index_col_def_t *src_column = NULL;
            if (cm_galist_new(&cons->columns, sizeof(knl_index_col_def_t), (void **)&src_column) != CT_SUCCESS) {
                knl_close_dc(&ref_dc);
                return CT_ERROR;
            }
            knl_index_col_def_t *ref_column = NULL;
            if (cm_galist_new(&ref->ref_columns, sizeof(knl_index_col_def_t), (void **)&ref_column) != CT_SUCCESS) {
                knl_close_dc(&ref_dc);
                return CT_ERROR;
            }
            knl_column_t *dc_column = dc_get_column(entity, *fk_column);
            proto_str2text(dc_column->name, &src_column->name);
            knl_column_t *ref_fk_column = dc_get_column(ref_entity, ref_dc_index->desc.columns[j]);
            proto_str2text(ref_fk_column->name, &ref_column->name);
            fk_column++;
        }
    }
    knl_close_dc(&ref_dc);
    return CT_SUCCESS;
}

static void ctc_fill_index_from_dc(TcDb__CtcDDLRenameTableDef *req, knl_index_def_t *index,
                                   index_t *dc_index, sql_stmt_t *stmt)
{
    proto_str2text(req->new_user, &index->user);
    proto_str2text(req->new_table_name, &index->table);
    proto_str2text(dc_index->desc.name, &index->name);
}

static void ctc_fill_index_parted(knl_index_def_t *index, index_t *dc_index)
{
    index->parted = dc_index->desc.parted;
    index->initrans = knl_get_initrans();
    index->pctfree = CT_PCT_FREE;
    index->cr_mode = CR_PAGE;
}

static status_t ctc_ddl_fill_func_column_by_dc(dc_entity_t *entity, index_t *dc_index, knl_index_def_t *index,
                                               sql_stmt_t *stmt)
{
    knl_index_col_def_t *key_column = NULL;
    CT_RETURN_IFERR(cm_galist_new(&index->columns, sizeof(knl_index_col_def_t), (void **)&key_column));
    int arg_cols = *(dc_index->desc.columns_info->arg_cols);
    knl_column_t *dc_column = dc_get_column(entity, arg_cols);
    proto_str2text(dc_column->name, &key_column->name);
    key_column->datatype = dc_index->desc.profile.types[0];
    key_column->size = dc_column->size;
    key_column->is_func = 1;
    int vir_col = 0;

    while (CT_TRUE) {
        if (entity->virtual_columns[vir_col]->id != dc_index->desc.columns[0]) {
            vir_col += 1;
            continue;
        }
        char *default_func_str = entity->virtual_columns[vir_col]->default_text.str;
        char *default_str = NULL;
        CT_RETURN_IFERR(sql_alloc_mem(stmt->context, entity->virtual_columns[vir_col]->default_text.len + 1,
                                      (pointer_t *)&default_str));
        CT_RETURN_IFERR(cm_text2str(&entity->virtual_columns[vir_col]->default_text, default_str,
                                    entity->virtual_columns[vir_col]->default_text.len + 1));
        char *p_token = NULL;
        char *split_name = strtok_s(default_str, "(", &p_token);
        if (split_name == NULL) {
            CT_THROW_ERROR_EX(ERR_FUNCTION_NOT_EXIST, default_str);
            return CT_ERROR;
        }

        text_t func_name_text = {0};
        proto_str2text(split_name, &func_name_text);
        uint32 func_id = sql_get_func_id(&func_name_text);
        if (func_id == CT_INVALID_ID32) {
            CT_THROW_ERROR_EX(ERR_FUNCTION_NOT_EXIST, split_name);
            return CT_ERROR;
        }
        if (!g_func_tab[func_id].indexable) {
            CT_THROW_ERROR_EX(ERR_FUNCTION_NOT_INDEXABLE, dc_column->default_text.str);
            return CT_ERROR;
        }
        cm_str2text_safe(default_func_str, entity->virtual_columns[vir_col]->default_text.len, &key_column->func_text);
        break;
    }

    return CT_SUCCESS;
}

static status_t ctc_ddl_fill_key_column_by_dc(dc_entity_t *entity, index_t *dc_index, bool is_ordinary_index,
                                              knl_index_def_t *index, knl_constraint_def_t *cons)
{
    for (int i = 0; i < dc_index->desc.column_count; i++) {
        knl_index_col_def_t *key_column = NULL;
        knl_column_t *dc_column = dc_get_column(entity, dc_index->desc.columns[i]);
        if (is_ordinary_index) {
            CT_RETURN_IFERR(cm_galist_new(&index->columns, sizeof(knl_index_col_def_t), (void **)&key_column));
            proto_str2text(dc_column->name, &key_column->name);
            key_column->datatype = dc_column->datatype;
            key_column->size = dc_column->size;
            key_column->is_func = 0;
        } else {
            knl_index_col_def_t *key_column_cond = NULL;
            CT_RETURN_IFERR(cm_galist_new(&cons->columns, sizeof(knl_index_col_def_t), (void **)&key_column_cond));
            proto_str2text(dc_column->name, &key_column_cond->name);
            key_column_cond->size = dc_column->size;
        }
    }
    return CT_SUCCESS;
}

static status_t ctc_fill_index_by_dc(TcDb__CtcDDLRenameTableDef *req, dc_entity_t *entity,
                                     knl_table_def_t *def, sql_stmt_t *stmt)
{
    status_t status = CT_SUCCESS;
    for (int i = 0; i < entity->table.index_set.total_count; i++) {
        knl_index_def_t *index = NULL;
        knl_constraint_def_t *cons = NULL;
        index_t *dc_index = entity->table.index_set.items[i];
        bool is_ordinary_index = !dc_index->desc.primary && !dc_index->desc.unique;
        if (is_ordinary_index) {
            status = cm_galist_new(&def->indexs, sizeof(knl_index_def_t), (pointer_t *)&index);
            CT_RETURN_IFERR(status);
            ctc_fill_index_from_dc(req, index, dc_index, stmt);
            index->type = INDEX_TYPE_BTREE;
        } else {
            status = cm_galist_new(&def->constraints, sizeof(knl_constraint_def_t), (pointer_t *)&cons);
            CT_RETURN_IFERR(status);
            cons->cons_state.is_enable = CT_TRUE;
            cons->cons_state.is_validate = CT_TRUE;
            cons->cons_state.is_cascade = CT_TRUE;
            cons->cons_state.is_use_index = CT_TRUE;
            if (sql_alloc_mem(stmt->context, CT_NAME_BUFFER_SIZE, (pointer_t *)&cons->name.str) != CT_SUCCESS) {
                return CT_ERROR;
            }
            proto_str2text_ex(dc_index->desc.name, &cons->name, CT_NAME_BUFFER_SIZE - 1);
            index = &cons->index;
            ctc_fill_index_from_dc(req, index, dc_index, stmt);
            if (dc_index->desc.primary) {
                cons->type = CONS_TYPE_PRIMARY;
                index->primary = CT_TRUE;
            } else if (dc_index->desc.unique) {
                cons->type = CONS_TYPE_UNIQUE;
                index->unique = CT_TRUE;
            }
            cm_galist_init(&cons->columns, stmt->context, sql_alloc_mem);
        }

        ctc_fill_index_parted(index, dc_index);
        cm_galist_init(&index->columns, stmt->context, sql_alloc_mem);

        if (dc_index->desc.is_func) {
            status = ctc_ddl_fill_func_column_by_dc(entity, dc_index, index, stmt);
            CT_RETURN_IFERR(status);
        } else {
            status = ctc_ddl_fill_key_column_by_dc(entity, dc_index, is_ordinary_index, index, cons);
            CT_RETURN_IFERR(status);
        }
    }
    return status;
}

static status_t ctc_get_auto_increment(knl_table_def_t *def, dc_entity_t *entity,
                                       knl_session_t *knl_session, knl_column_t *dc_column)
{
    if (!KNL_COLUMN_IS_SERIAL(dc_column)) {
        return CT_SUCCESS;
    }
    if (entity->has_serial_col) {
        if (!entity->table.heap.segment) {
            def->serial_start = entity->table.desc.serial_start;
        } else {
            def->serial_start = HEAP_SEGMENT(knl_session, entity->table.heap.entry, entity->table.heap.segment)->serial;
        }
    }
    return CT_SUCCESS;
}

static status_t ctc_fill_def_base_from_dc(TcDb__CtcDDLRenameTableDef *req, knl_table_def_t *def,
                                          knl_dictionary_t *dc, sql_stmt_t *stmt, knl_session_t *knl_session)
{
    status_t ret = CT_SUCCESS;
    dc_entity_t *entity = (dc_entity_t *)dc->handle;
    def->sysid = CT_INVALID_ID32;
    def->cr_mode = entity->table.desc.cr_mode;
    def->pctfree = entity->table.desc.pctfree;
    def->initrans = entity->table.desc.initrans;
#ifdef Z_SHARDING
    def->slice_count = entity->table.desc.slice_count;
#endif
    def->is_for_create_db = CT_TRUE;
    def->is_mysql_copy = CT_TRUE;

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, CT_NAME_BUFFER_SIZE, (pointer_t *)&def->schema.str));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, CT_NAME_BUFFER_SIZE, (pointer_t *)&def->name.str));
    proto_str2text_ex(req->new_user, &def->schema, CT_NAME_BUFFER_SIZE - 1);
    ret = strncpy_s(stmt->session->curr_schema, CT_NAME_BUFFER_SIZE, def->schema.str, def->schema.len);
    MEMS_RETURN_IFERR(ret);
    proto_str2text_ex(req->new_table_name, &def->name, CT_NAME_BUFFER_SIZE - 1);

    cm_galist_init(&def->columns, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->constraints, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->indexs, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->lob_stores, stmt->context, sql_alloc_mem);

    for (int i = 0; i < entity->column_count; i++) {
        knl_column_def_t *column = NULL;
        if ((ret = cm_galist_new(&def->columns, sizeof(knl_column_def_t), (pointer_t *)&column))) {
            break;
        }
        column->table = (void *)def;
        knl_column_t *dc_column = dc_get_column(entity, i);
        cm_galist_init(&column->ref_columns, stmt->context, sql_alloc_mem);
        ctc_fill_column_by_dc(column, dc_column, stmt);
        for (uint32 j = 0; j < entity->table.index_set.count; j++) {
            if (entity->table.index_set.items[j]->desc.primary &&
                entity->table.index_set.items[j]->desc.columns[0] == dc_column->id) {
                def->pk_inline = CT_TRUE;
            }
        }
        def->rf_inline = def->rf_inline || (column->is_ref);
        def->uq_inline = def->uq_inline || (column->unique);
        def->chk_inline = def->chk_inline || (column->is_check);
        ret = ctc_get_auto_increment(def, entity, knl_session, dc_column);
        if (ret != CT_SUCCESS) {
            break;
        }
    }
    return ret;
}

static status_t ctc_fill_def_from_dc(TcDb__CtcDDLRenameTableDef *req, knl_table_def_t *def,
                                     knl_dictionary_t *dc, sql_stmt_t *stmt, knl_session_t *knl_session)
{
    status_t ret = CT_SUCCESS;
    dc_entity_t *entity = (dc_entity_t *)dc->handle;
    ret = ctc_fill_def_base_from_dc(req, def, dc, stmt, knl_session);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RENAME CROSS DB]: fill new table base def failed.");
        return ret;
    }

    // partition
    SYNC_POINT_GLOBAL_START(CTC_RENAME_CROSS_DB_FILL_PART_FAIL, &ret, CT_ERROR);
    ret = ctc_fill_partition_by_dc(def, entity, stmt);
    SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RENAME CROSS DB]: fill new table partition def failed.");
        return ret;
    }

    // foreign key
    SYNC_POINT_GLOBAL_START(CTC_RENAME_CROSS_DB_FILL_FK_FAIL, &ret, CT_ERROR);
    if (entity->table.cons_set.ref_count >= 1) {
        ret = ctc_fill_fk_by_dc(req, knl_session, def, dc, stmt);
    }
    SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RENAME CROSS DB]: fill new table foreign key def failed.");
        return ret;
    }

    // index
    SYNC_POINT_GLOBAL_START(CTC_RENAME_CROSS_DB_FILL_INDEX_FAIL, &ret, CT_ERROR);
    ret = ctc_fill_index_by_dc(req, entity, def, stmt);
    SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RENAME CROSS DB]: fill new table index def failed.");
        return ret;
    }
    return ret;
}

static void ctc_set_cursor_to_read(knl_cursor_t *cursor, knl_dictionary_t *old_dc)
{
    cursor->action = CURSOR_ACTION_SELECT;
    cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor->vnc_column = NULL;
    cursor->table = DC_TABLE(old_dc);
    cursor->dc_entity = old_dc->handle;
    cursor->dc_type = old_dc->type;
}

static void ctc_set_cursor_to_write(knl_cursor_t *cursor, knl_dictionary_t *new_dc)
{
    cursor->action = CURSOR_ACTION_INSERT;
    cursor->table = DC_TABLE(new_dc);
    cursor->dc_entity = new_dc->handle;
    cursor->dc_type = new_dc->type;
}

static status_t ctc_fetch_from_part(knl_cursor_t *old_cursor, knl_cursor_t *new_cursor,
                                    knl_dictionary_t *old_dc, knl_dictionary_t *new_dc, knl_session_t *knl_session)
{
    uint32_t sub_cnt = DC_TABLE(new_dc)->part_table->desc.subpart_cnt;
    uint32_t part_cnt = DC_TABLE(new_dc)->part_table->desc.partcnt;
    bool is_contain_sub_part = (sub_cnt == 0) ? CT_FALSE : CT_TRUE;
    uint32_t sub_part_num = sub_cnt / part_cnt;
    uint32_t par_no = 0;
    uint32_t sub_no = is_contain_sub_part ? 0 : INVALID_PART_ID;
    uint32_t tmp_cnt = 0;
    while (CT_TRUE) {
        if (is_contain_sub_part && (sub_no >= sub_part_num)) {
            sub_no = 0;
            par_no += 1;
            continue;
        }
        knl_part_locate_t part_loc = { .part_no = par_no, .subpart_no = sub_no };
        knl_set_table_part(old_cursor, part_loc);
        knl_set_table_part(new_cursor, part_loc);
        CT_RETURN_IFERR(knl_reopen_cursor(knl_session, old_cursor, old_dc));
        CT_RETURN_IFERR(knl_reopen_cursor(knl_session, new_cursor, new_dc));
        new_cursor->table_part = TABLE_GET_PART(DC_TABLE(new_dc), part_loc.part_no);
        if (is_contain_sub_part) {
            new_cursor->table_part = PART_GET_SUBENTITY(((table_t *)new_cursor->table)->part_table,
                                                        ((table_part_t *)new_cursor->table_part)->subparts[sub_no]);
        }
        while (!old_cursor->eof) {
            CT_RETURN_IFERR(knl_fetch(knl_session, old_cursor));
            if (!old_cursor->eof) {
                knl_copy_row(knl_session, old_cursor, new_cursor);
                CT_RETURN_IFERR(knl_insert(knl_session, new_cursor));
            }
        }

        is_contain_sub_part ? sub_no++ : par_no++;
        tmp_cnt++;
        if (par_no >= part_cnt || (is_contain_sub_part && tmp_cnt >= sub_cnt)) {
            break;
        }
    }
    return CT_SUCCESS;
}

static status_t ctc_fetch_from_normal_table(knl_session_t *knl_session,
                                            knl_cursor_t *old_cursor, knl_cursor_t *new_cursor)
{
    while (!old_cursor->eof) {
        CT_RETURN_IFERR(knl_fetch(knl_session, old_cursor));
        if (!old_cursor->eof) {
            knl_copy_row(knl_session, old_cursor, new_cursor);
            CT_RETURN_IFERR(knl_insert(knl_session, new_cursor));
        }
    }
    return CT_SUCCESS;
}

static status_t ctc_fetch_data_in_rename_table(TcDb__CtcDDLRenameTableDef *req, ddl_ctrl_t *ddl_ctrl,
                                               sql_stmt_t *stmt, knl_dictionary_t *old_dc, knl_dictionary_t *new_dc)
{
    status_t status = CT_SUCCESS;
    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    CT_RETURN_IFERR(ctc_get_or_new_session(&session, &(ddl_ctrl->tch), false, false, &is_new_session));
    knl_session_t *knl_session = &session->knl_session;
    CM_SAVE_STACK(knl_session->stack);

    // open old context and new context
    ctc_context_t *old_context = NULL;
    ctc_context_t *new_context = NULL;
    // open old cursor
    knl_cursor_t *old_cursor = ctc_push_cursor(knl_session);
    ctc_set_cursor_to_read(old_cursor, old_dc);
    // open new cursor
    knl_cursor_t *new_cursor = ctc_push_cursor(knl_session);
    ctc_set_cursor_to_write(new_cursor, new_dc);

    do {
        if (init_ctc_ctx(&old_context, req->old_table_name, req->user) != CT_SUCCESS ||
            init_ctc_ctx(&new_context, req->new_table_name, req->new_user) != CT_SUCCESS) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "[RENAME CROSS DB]: open context failed.");
            break;
        }
        
        old_context->dc = old_dc;
        new_context->dc = new_dc;
        if (ctc_open_cursor(knl_session, old_cursor, old_context, NULL, false) != CT_SUCCESS ||
            ctc_open_cursor(knl_session, new_cursor, new_context, NULL, false) != CT_SUCCESS) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "[RENAME CROSS DB]: open cursor failed.");
            break;
        }

        old_cursor->row = (row_head_t *)cm_push(knl_session->stack, CT_MAX_ROW_SIZE);
        if (old_cursor->row == NULL) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "[RENAME CROSS DB]: old cursor fetch failed.");
            break;
        }

        if (((dc_entity_t *)(old_dc->handle))->table.part_table) {
            status = ctc_fetch_from_part(old_cursor, new_cursor, old_dc, new_dc, knl_session);
        } else {
            status = ctc_fetch_from_normal_table(knl_session, old_cursor, new_cursor);
        }
    } while (0);

    CTC_POP_CURSOR(knl_session);
    ctc_close_cursor(knl_session, old_cursor);
    ctc_close_cursor(knl_session, new_cursor);
    if (status != CT_SUCCESS) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "[RENAME CROSS DB]: fetch data failed.");
    }
    return status;
}

static void ctc_fill_drop_table_def(knl_drop_def_t *drop_def, char *user_name,
                                    char* table_name, knl_dictionary_t *new_dc)
{
    proto_str2text_ex(table_name, &drop_def->name, CT_NAME_BUFFER_SIZE - 1);
    proto_str2text_ex(user_name, &drop_def->owner, CT_NAME_BUFFER_SIZE - 1);
    drop_def->purge = CT_TRUE;
    drop_def->options = DROP_NO_CHECK_FK;
    drop_def->new_parent_id = new_dc->oid;
    drop_def->new_user_id = new_dc->uid;
}

static status_t ctc_reopen_dc4rename_cross_db(TcDb__CtcDDLRenameTableDef *req, sql_stmt_t *stmt, session_t *session,
                                              knl_dictionary_t *old_dc, knl_dictionary_t *new_dc)
{
    dc_invalidate_children(&session->knl_session, (dc_entity_t *)old_dc->handle);
    dc_invalidate_parents(&session->knl_session, (dc_entity_t *)old_dc->handle);
    dc_invalidate(&session->knl_session, (dc_entity_t *)old_dc->handle);
    if (new_dc != NULL && new_dc->handle != NULL) {
        dc_invalidate(&session->knl_session, (dc_entity_t *)new_dc->handle);
        dc_invalidate_remote(session, (dc_entity_t *)new_dc->handle);
    }
    knl_close_dc(new_dc);

    // reopen new dc
    if (ctc_open_dc(req->new_user, req->new_table_name, stmt, new_dc) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RENAME CROSS DB]: reopen new dc after update fk failed.");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t ctc_create_table_in_rename(TcDb__CtcDDLRenameTableDef *req, knl_table_def_t *table_def,
                                           session_t *session, knl_dictionary_t *old_dc, ctc_ddl_def_node_t *def_node)
{
    dc_user_t *user = NULL;
    dc_user_t *new_user = NULL;
    knl_session_t *knl_session = &session->knl_session;
    sql_stmt_t *stmt = session->current_stmt;

    text_t user_text = {0};
    text_t new_user_text = {0};
    proto_str2text(req->user, &user_text);
    proto_str2text(req->new_user, &new_user_text);
    CT_RETURN_IFERR(dc_open_user(knl_session, &user_text, &user));
    CT_RETURN_IFERR(dc_open_user(knl_session, &new_user_text, &new_user));
    if (ctc_ddl_lock_table4rename_cross_db(session, user, new_user) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RENAME CROSS DB]: lock before create new table failed.");
        return CT_ERROR;
    }

    ctc_init_ddl_def_node(def_node, CREATE_DEF, (pointer_t *)table_def, NULL);
    ctc_ddl_def_list_insert(&stmt->ddl_def_list, def_node);
    if (knl_create_table4mysql(knl_session, stmt, table_def) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RENAME CROSS DB]: create new table failed.");
        return CT_ERROR;
    }

    if (knl_lock_table_self_parent_child_directly(knl_session, old_dc) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RENAME CROSS DB]: lock old table failed.");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t ctc_update_new_table_in_rename(TcDb__CtcDDLRenameTableDef *req, session_t *session,
                                               ddl_ctrl_t *ddl_ctrl, knl_dictionary_t *old_dc, knl_dictionary_t *new_dc)
{
    status_t ret = CT_SUCCESS;
    sql_stmt_t *stmt = session->current_stmt;
    knl_session_t *knl_session = &session->knl_session;
    knl_drop_def_t *old_drop_def = NULL;
    dc_entity_t *new_entity = (dc_entity_t *)new_dc->handle;
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_drop_def_t), (pointer_t *)&old_drop_def));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, CT_NAME_BUFFER_SIZE, (pointer_t *)&old_drop_def->owner.str));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, CT_NAME_BUFFER_SIZE, (pointer_t *)&old_drop_def->name.str));
    ctc_fill_drop_table_def(old_drop_def, req->user, req->old_table_name, new_dc);
    ctc_ddl_def_node_t *def_node = NULL;
    do {
        // close logic before fetch data
        new_entity->lrep_info.status = LOGICREP_STATUS_OFF;

        // data update
        ret = ctc_fetch_data_in_rename_table(req, ddl_ctrl, stmt, old_dc, new_dc);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RENAME CROSS DB]: new table update data failed.");
            break;
        }

        // reopen logic after fetch data
        new_entity->lrep_info.status = LOGICREP_STATUS_ON;

        SYNC_POINT_GLOBAL_START(CTC_RENAME_CROSS_DB_AFTER_FILL_DATA_ABORT, NULL, 0);
        SYNC_POINT_GLOBAL_END;

        // foreign key update
        ret = knl_update_ref_syscons4mysql(knl_session, old_dc, new_dc);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RENAME CROSS DB]: update foreign key failed.");
            break;
        }

        // comment update
        ret = knl_update_comment4mysql(knl_session, old_dc, new_dc);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RENAME CROSS DB]: update comment failed.");
            break;
        }

        // dictionary his update
        ret = knl_meta_record_when_copy(knl_session, old_dc, new_dc, DB_CURR_SCN(knl_session), CT_TRUE);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RENAME CROSS DB]: update his failed.");
            break;
        }

        CT_RETURN_IFERR(ctc_reopen_dc4rename_cross_db(req, stmt, session, old_dc, new_dc));

        // drop old table
        CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(ctc_ddl_def_node_t), (void **)&def_node));
        ctc_put_ddl_sql_2_stmt(session, req->current_db_name, req->sql_str);
        ctc_init_ddl_def_node(def_node, DROP_DEF, (pointer_t *)old_drop_def, old_dc);
        ctc_ddl_def_list_insert(&stmt->ddl_def_list, def_node);
        ret = knl_drop_table_no_commit4mysql(&stmt->session->knl_session, stmt, old_drop_def);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[RENAME CROSS DB]: drop old table failed.");
            break;
        }
    } while (0);

    SYNC_POINT_GLOBAL_START(CTC_RENAME_CROSS_DB_AFTER_DROP_OLD_TABLE_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    return ret;
}

static status_t ctc_open_new_dc4rename(knl_session_t *knl_session, sql_stmt_t *stmt, knl_table_def_t *table_def,
                                       knl_dictionary_t *new_dc, ctc_ddl_def_node_t *def_node)
{
    SYNC_POINT_GLOBAL_START(CTC_RENAME_CROSS_DB_AFTER_CREATE_TABLE_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    dc_user_t *new_user = NULL;
    if (ctc_open_dc(table_def->schema.str, table_def->name.str, stmt, new_dc) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RENAME CROSS DB]: open new dc after create new table failed.");
        return CT_ERROR;
    }
    def_node->uid = new_dc->uid;
    def_node->oid = new_dc->oid;

    if (dc_open_user(knl_session, &table_def->schema, &new_user) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[RENAME CROSS DB]: open new user failed.");
    }
    DC_GET_ENTRY(new_user, new_dc->oid)->entity = new_dc->handle;

    SYNC_POINT_GLOBAL_START(CTC_RENAME_CROSS_DB_DELAY, NULL, 5000); // delay 5000ms
    SYNC_POINT_GLOBAL_END;

    return CT_SUCCESS;
}

static int ctc_rename_table_cross_database_impl(TcDb__CtcDDLRenameTableDef *req, ddl_ctrl_t *ddl_ctrl)
{
    status_t ret = CT_SUCCESS;
    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    CT_RETURN_IFERR(ctc_get_or_new_session(&session, &(ddl_ctrl->tch), CT_FALSE, CT_TRUE, &is_new_session));
    sql_stmt_t *stmt = session->current_stmt;
    knl_session_t *knl_session = &session->knl_session;

    text_t alter_user = {0};
    text_t alter_name = {0};
    stmt->context->type = CTSQL_TYPE_CREATE_TABLE;
    proto_str2text(req->user, &alter_user);
    proto_str2text(req->old_table_name, &alter_name);

    knl_dictionary_t old_dc;
    knl_dictionary_t new_dc;

    bool32 is_open_new_dc = CT_FALSE;
    knl_table_def_t *table_def = NULL;
    ctc_ddl_def_node_t *def_node = NULL;
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(ctc_ddl_def_node_t), (void **)&def_node));
    CT_RETURN_IFERR(knl_open_dc((knl_handle_t)&stmt->session->knl_session, (text_t *)&alter_user,
                                (text_t *)&alter_name, &old_dc));
    RETURN_IF_OPERATION_UNSUPPORTED(&old_dc, "rename table");
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_table_def_t), (pointer_t *)&table_def));
    do {
        ret = ctc_fill_def_from_dc(req, table_def, &old_dc, stmt, knl_session);
        if (ret != CT_SUCCESS) {
            break;
        }

        stmt->context->entry = table_def;
        ret = ctc_create_table_in_rename(req, table_def, session, &old_dc, def_node);
        if (ret != CT_SUCCESS) {
            break;
        }

        ret = ctc_open_new_dc4rename(knl_session, stmt, table_def, &new_dc, def_node);
        if (ret != CT_SUCCESS || check_if_operation_unsupported(&new_dc, "rename table")) {
            break;
        }
        is_open_new_dc = CT_TRUE;

        ret = ctc_update_new_table_in_rename(req, session, ddl_ctrl, &old_dc, &new_dc);
    } while (0);

    knl_close_dc(&old_dc);
    if (is_open_new_dc) {
        knl_close_dc(&new_dc);
    }
    CT_RETURN_IFERR_NOCLEAR(ret,ddl_ctrl);
    return ret;
}

static int ctc_rename_table_impl(TcDb__CtcDDLRenameTableDef *req, ddl_ctrl_t *ddl_ctrl)
{
    SYNC_POINT_GLOBAL_START(CTC_RENAME_TABLE_BEFORE_KNL_RENAME_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    if (req->new_table_name == NULL) {
        return CT_ERROR;
    }
    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    status_t status = CT_SUCCESS;
    bool need_init = !ddl_ctrl->is_alter_copy;
    CT_RETURN_IFERR(ctc_get_or_new_session(&session, &(ddl_ctrl->tch), false, need_init, &is_new_session));

    knl_altable_def_t *def = NULL;
    knl_altable_def_t *def_arrays = NULL;
    sql_stmt_t *stmt = session->current_stmt;
    ctc_ddl_def_node_t *def_node = NULL;
    ctc_ddl_def_node_t *def_rename_node = NULL;
    uint32 def_count = req->n_old_constraints_name + 1;
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_altable_def_t) * def_count, (pointer_t *)&def_arrays));
    CT_RETURN_IFERR(ctc_put_ddl_sql_2_stmt(session, req->current_db_name, req->sql_str));
    stmt->context->type = CTSQL_TYPE_ALTER_TABLE; // todo
    stmt->context->entry = def_arrays;
    cm_galist_init(&def_arrays->column_defs, stmt->context, sql_alloc_mem);
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, CT_NAME_BUFFER_SIZE, (void **)&def_arrays->user.str));
    proto_str2text_ex(req->user, &def_arrays->user, CT_NAME_BUFFER_SIZE - 1);
    status = strncpy_s(stmt->session->curr_schema, CT_NAME_BUFFER_SIZE, def_arrays->user.str, def_arrays->user.len);
    CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, CT_NAME_BUFFER_SIZE, (void **)&def_arrays->name.str));
    proto_str2text_ex(req->old_table_name, &def_arrays->name, CT_NAME_BUFFER_SIZE - 1);
    def_arrays->action = ALTABLE_RENAME_TABLE;
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, CT_NAME_BUFFER_SIZE, (void **)&def_arrays->table_def.new_name.str));
    proto_str2text_ex(req->new_table_name, &def_arrays->table_def.new_name, CT_NAME_BUFFER_SIZE - 1);

    for (int i = 1; i < def_count; i++) {
        def = &(def_arrays[i]);
        proto_str2text(req->user, &def->user);
        proto_str2text(req->old_table_name, &def->name);
        CT_RETURN_IFERR(ctc_fill_rename_constraint(session, stmt, def, req->old_constraints_name[i - 1],
                                                   req->new_constraints_name[i - 1]));
    }

    knl_dictionary_t dc;
    status = knl_open_dc(&session->knl_session, &(def_arrays->user), &(def_arrays->name), &dc);
    if (status != CT_SUCCESS) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not find", T2S(&(def_arrays->name)));
        CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    }
    RETURN_IF_OPERATION_UNSUPPORTED(&dc, "rename table");

    if (sql_alloc_mem(stmt->context, sizeof(ctc_ddl_def_node_t), (void **)&def_rename_node) != CT_SUCCESS) {
        knl_close_dc(&dc);
        CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    }

    status = ctc_ddl_lock_table(session, &dc, NULL, ddl_ctrl->is_alter_copy);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_LOCK_ALTER_TABLE]:rename table to lock table failed, ret:%d,"
                       "conn_id:%u, ctc_instance_id:%u", (int)status, ddl_ctrl->tch.thd_id, ddl_ctrl->tch.inst_id);
        knl_close_dc(&dc);
        CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    }
    SYNC_POINT_GLOBAL_START(CTC_RENAME_TABLE_STATS_ACK_TIMEOUT, NULL, 5000); // delay 5000ms
    SYNC_POINT_GLOBAL_END;
    
    def_arrays->is_mysql_copy = ddl_ctrl->is_alter_copy;
    ctc_init_ddl_def_node(def_rename_node, RENAME_DEF, (pointer_t *)def_arrays, &dc);
    ctc_ddl_def_list_insert(&stmt->ddl_def_list, def_rename_node);

    if (req->n_old_constraints_name > 0) {
        def = &(def_arrays[1]);
        if (sql_alloc_mem(stmt->context, sizeof(ctc_ddl_def_node_t), (void **)&def_node) != CT_SUCCESS) {
            knl_close_dc(&dc);
            CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
        }
        ctc_init_ddl_def_node(def_node, ALTER_DEF, (pointer_t *)&def, &dc);
        ctc_ddl_def_list_insert(&stmt->ddl_def_list, def_node);
    }

    cm_reset_error();
    SYNC_POINT_GLOBAL_START(CTC_RENAME_TABLE_4MYSQL_FAIL, &status, CT_ERROR);
    status = knl_alter_table4mysql(session, stmt, def_arrays, def_count, &dc, true);
    SYNC_POINT_GLOBAL_END;

    knl_close_dc(&dc);
    CT_RETURN_IFERR_NOCLEAR(status, ddl_ctrl);

    SYNC_POINT_GLOBAL_START(CTC_RENAME_TABLE_AFTER_KNL_RENAME_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    return status;
}

EXTER_ATTACK int ctc_rename_table(void *alter_def, ddl_ctrl_t *ddl_ctrl)
{
    INIT_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_RENAME_TABLE);
    BEGIN_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_RENAME_TABLE);
    TcDb__CtcDDLRenameTableDef *req = tc_db__ctc_ddlrename_table_def__unpack(NULL, ddl_ctrl->msg_len, alter_def);
    CTC_LOG_RET_VAL_IF_NUL(req, CT_ERROR, "ctc_rename_table: null req ptr");
    int ret = CT_SUCCESS;
    if (strcmp(req->user, req->new_user) != 0) {
        ret = ctc_rename_table_cross_database_impl(req, ddl_ctrl);
    } else {
        ret = ctc_rename_table_impl(req, ddl_ctrl);
    }
    tc_db__ctc_ddlrename_table_def__free_unpacked(req, NULL);
    END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_RENAME_TABLE);
    return ret;
}

static int ctc_drop_table_impl(TcDb__CtcDDLDropTableDef *req, ddl_ctrl_t *ddl_ctrl)
{
    SYNC_POINT_GLOBAL_START(CTC_DROP_TABLE_BEFORE_KNL_DROP_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    bool is_new_session;
    session_t *session = NULL;
    int status = CT_SUCCESS;
    bool need_init = !ddl_ctrl->is_alter_copy;
    CT_RETURN_IFERR(ctc_get_or_new_session(&session, &(ddl_ctrl->tch), false, need_init, &is_new_session));

    knl_drop_def_t *def = NULL;
    dc_user_t *user = NULL;
    ctc_ddl_def_node_t *def_node = NULL;
    sql_stmt_t *stmt = session->current_stmt;
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_drop_def_t), (pointer_t *)&def));
    CT_RETURN_IFERR(ctc_put_ddl_sql_2_stmt(session, req->db_name, req->sql_str));
    stmt->context->type = CTSQL_TYPE_DROP_TABLE;
    stmt->context->entry = def;
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, CT_NAME_BUFFER_SIZE, (pointer_t *)&def->owner.str));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, CT_NAME_BUFFER_SIZE, (pointer_t *)&def->name.str));
    proto_str2text_ex(req->name, &def->name, CT_NAME_BUFFER_SIZE - 1);
    proto_str2text_ex(req->user, &def->owner, CT_NAME_BUFFER_SIZE - 1);
    status = strncpy_s(stmt->session->curr_schema, CT_NAME_BUFFER_SIZE, def->owner.str, def->owner.len);
    CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    def->options = req->options;
    def->purge = true;

    // 删除临时表
    if (ddl_ctrl->table_flags & CTC_TMP_TABLE) {
        status = knl_drop_ltt(&stmt->session->knl_session, def);
        ctc_ddl_clear_stmt(stmt);
        return status;
    }
    
    CT_LOG_RUN_WAR("knl_drop_table enter, table_name:%s, session_id:%d", def->name.str, stmt->session->knl_session.id);
    
    knl_dictionary_t dc;
    if (knl_open_dc(&session->knl_session, &(def->owner), &(def->name), &dc) != CT_SUCCESS) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not find", T2S(&(def->name)));
        return CT_ERROR;
    }
    RETURN_IF_OPERATION_UNSUPPORTED(&dc, "drop table");

    if (ddl_ctrl->is_alter_copy) {
        bilist_node_t *node = cm_bilist_tail(&stmt->ddl_def_list);
        ctc_ddl_def_node_t *tail_node = (ctc_ddl_def_node_t *)BILIST_NODE_OF(ctc_ddl_def_node_t, node, bilist_node);
        def->new_parent_id = tail_node->oid;
        def->new_user_id = tail_node->uid;

        knl_dictionary_t new_dc;
        if (dc_open_table_private(session, tail_node->uid, tail_node->oid, &new_dc) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (knl_meta_record_when_copy(&session->knl_session, &dc, &new_dc,
                                      DB_CURR_SCN(&session->knl_session), CT_FALSE) != CT_SUCCESS) {
            knl_close_dc(&dc);
            dc_close_table_private(&new_dc);
            return CT_ERROR;
        }
        dc_close_table_private(&new_dc);
    }

    if (!ddl_ctrl->is_alter_copy &&
        (session->knl_session.user_locked_lst == NULL || *(session->knl_session.user_locked_lst) == 0)) {
        if (dc_open_user(&session->knl_session, &def->owner, &user) != CT_SUCCESS) {
            knl_close_dc(&dc);
            return CT_ERROR;
        }
    }

    if (sql_alloc_mem(stmt->context, sizeof(ctc_ddl_def_node_t), (void **)&def_node) != CT_SUCCESS) {
        knl_close_dc(&dc);
        CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    }

    status = ctc_ddl_lock_table(session, &dc, user, ddl_ctrl->is_alter_copy);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_LOCK_DROP_TABLE]:drop table to lock table failed, ret:%d,"
                       "conn_id:%u, ctc_instance_id:%u", (int)status, ddl_ctrl->tch.thd_id, ddl_ctrl->tch.inst_id);
        knl_close_dc(&dc);
        CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    }
    SYNC_POINT_GLOBAL_START(CTC_DROP_TABLE_STATS_ACK_TIMEOUT, NULL, 5000); // delay 5000ms
    SYNC_POINT_GLOBAL_END;
    
    ctc_init_ddl_def_node(def_node, DROP_DEF, (pointer_t *)def, &dc);
    ctc_ddl_def_list_insert(&stmt->ddl_def_list, def_node);

    cm_reset_error();
    SYNC_POINT_GLOBAL_START(CTC_DROP_TABLE_4MYSQL_FAIL, &status, CT_ERROR);
    status = knl_drop_table_no_commit4mysql(&stmt->session->knl_session, stmt, def);
    SYNC_POINT_GLOBAL_END;

    knl_close_dc(&dc);
    CT_RETURN_IFERR_NOCLEAR(status, ddl_ctrl);

    SYNC_POINT_GLOBAL_START(CTC_DROP_TABLE_AFTER_KNL_DROP_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    return status;
}

EXTER_ATTACK int ctc_drop_table(void *drop_def, ddl_ctrl_t *ddl_ctrl)
{
    INIT_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_DROP_TABLE);
    BEGIN_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_DROP_TABLE);
    TcDb__CtcDDLDropTableDef *req = tc_db__ctc_ddldrop_table_def__unpack(NULL, ddl_ctrl->msg_len, drop_def);
    CTC_LOG_RET_VAL_IF_NUL(req, CT_ERROR, "ctc_drop_table: null req ptr");
    int ret = ctc_drop_table_impl(req, ddl_ctrl);
    tc_db__ctc_ddldrop_table_def__free_unpacked(req, NULL);
    END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_DROP_TABLE);
    return ret;
}

status_t fill_datafile_by_TcDb__CtcDDLDataFileDef(knl_device_def_t *datafile, const TcDb__CtcDDLDataFileDef *def,
    char *ts_path, uint32_t ts_len)
{
    status_t status = ctc_generate_tablespace_path(def->name, ts_path, ts_len);
    CT_RETURN_IFERR(status);
    proto_str2text(ts_path, &datafile->name);
    datafile->size = def->size;
    datafile->autoextend.enabled = def->autoextend->enabled;
    datafile->autoextend.nextsize = def->autoextend->nextsize == 0 ?
        DATA_FILE_DEFALUT_EXTEND_SIZE : def->autoextend->nextsize;
    return status;
}

static int ctc_create_tablespace_impl(TcDb__CtcDDLSpaceDef *req, ddl_ctrl_t *ddl_ctrl)
{
    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    char ts_path[TABLESPACE_PATH_MAX_LEN] = {0};
    // 创建tablespace不会走ctc_lock_table，所有这里必须要要创建session
    CT_RETURN_IFERR(ctc_get_or_new_session(&session, &(ddl_ctrl->tch), true, true, &is_new_session));

    knl_space_def_t *def = NULL;
    sql_stmt_t *stmt = session->current_stmt;
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_space_def_t), (pointer_t *)&def));
    CT_RETURN_IFERR(ctc_put_ddl_sql_2_stmt(session, req->db_name, req->sql_str));
    stmt->context->type = CTSQL_TYPE_CREATE_TABLESPACE;
    stmt->context->entry = def;
    proto_str2text(req->name, &def->name);

    cm_galist_init(&def->datafiles, stmt->context, sql_alloc_mem);
    def->type = SPACE_TYPE_USERS;
    knl_device_def_t *datafile = NULL;
    int status = cm_galist_new(&def->datafiles, sizeof(knl_device_def_t), (pointer_t *)&datafile);
    CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    status = fill_datafile_by_TcDb__CtcDDLDataFileDef(datafile, req->datafiles_list[0], ts_path,
        TABLESPACE_PATH_MAX_LEN - 1);
    CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    status = knl_create_space(&stmt->session->knl_session, stmt, def);
    if (status == CT_SUCCESS) {
        do_commit(stmt->session);
    } else {
        do_rollback(stmt->session, NULL);
        CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    }
    ctc_ddl_clear_stmt(stmt);

    ctc_ddl_broadcast_request broadcast_req = {0};
    FILL_BROADCAST_REQ(broadcast_req, req->db_name, req->sql_str, ddl_ctrl->user_name, ddl_ctrl->user_ip,
                       ddl_ctrl->mysql_inst_id, ddl_ctrl->tch.sql_command);
    int broadcat_ret = ctc_execute_mysql_ddl_sql(&ddl_ctrl->tch, &broadcast_req, false);
    // 如果带有忽略参天错误的标志，需要同步忽略掉广播其他节点的报错
    return broadcat_ret;
}

EXTER_ATTACK int ctc_create_tablespace(void *space_def, ddl_ctrl_t *ddl_ctrl)
{
    TcDb__CtcDDLSpaceDef *req = tc_db__ctc_ddlspace_def__unpack(NULL, ddl_ctrl->msg_len, space_def);
    CTC_LOG_RET_VAL_IF_NUL(req, CT_ERROR, "ctc_create_tablespace: null req ptr");
    int ret = ctc_create_tablespace_impl(req, ddl_ctrl);
    tc_db__ctc_ddlspace_def__free_unpacked(req, NULL);
    return ret;
}

static int ctc_alter_tablespace_impl(TcDb__CtcDDLAlterSpaceDef *req, ddl_ctrl_t *ddl_ctrl)
{
    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    int status = CT_SUCCESS;
    CT_RETURN_IFERR(ctc_get_or_new_session(&session, &(ddl_ctrl->tch), true, true, &is_new_session));

    knl_altspace_def_t *def = NULL;
    sql_stmt_t *stmt = session->current_stmt;
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_altspace_def_t), (pointer_t *)&def));
    CT_RETURN_IFERR(ctc_put_ddl_sql_2_stmt(session, req->db_name, req->sql_str));
    stmt->context->type = CTSQL_TYPE_ALTER_TABLESPACE;
    stmt->context->entry = def;
    proto_str2text(req->name, &def->name);
    proto_str2text(req->new_name, &def->rename_space);
    cm_galist_init(&def->datafiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->rename_datafiles, stmt->context, sql_alloc_mem);
    def->action = req->action;
    def->autoextend.enabled = req->auto_extend_size == 0 ? false : true;
    def->autoextend.nextsize = req->auto_extend_size;
    status = knl_alter_space(&stmt->session->knl_session, stmt, def);
    CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    if (status == CT_SUCCESS) {
        do_commit(stmt->session);
    } else {
        do_rollback(stmt->session, NULL);
        CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    }
    ctc_ddl_clear_stmt(stmt);

    ctc_ddl_broadcast_request broadcast_req = {0};
    FILL_BROADCAST_REQ(broadcast_req, req->db_name, req->sql_str, ddl_ctrl->user_name, ddl_ctrl->user_ip,
                       ddl_ctrl->mysql_inst_id, ddl_ctrl->tch.sql_command);
    int broadcat_ret = ctc_execute_mysql_ddl_sql(&ddl_ctrl->tch, &broadcast_req, false);
    // 如果带有忽略参天错误的标志，需要同步忽略掉广播其他节点的报错
    return broadcat_ret;
}

EXTER_ATTACK int ctc_alter_tablespace(void *space_alter_def, ddl_ctrl_t *ddl_ctrl)
{
    TcDb__CtcDDLAlterSpaceDef *req = tc_db__ctc_ddlalter_space_def__unpack(NULL, ddl_ctrl->msg_len, space_alter_def);
    CTC_LOG_RET_VAL_IF_NUL(req, CT_ERROR, "ctc_alter_tablespace: null req ptr");
    int ret = ctc_alter_tablespace_impl(req, ddl_ctrl);
    tc_db__ctc_ddlalter_space_def__free_unpacked(req, NULL);
    return ret;
}

static int ctc_drop_tablespace_impl(TcDb__CtcDDLDropSpaceDef *req, ddl_ctrl_t *ddl_ctrl)
{
    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    int status = CT_SUCCESS;
    CT_RETURN_IFERR(ctc_get_or_new_session(&session, &(ddl_ctrl->tch), true, true, &is_new_session));

    knl_drop_space_def_t *def = NULL;
    sql_stmt_t *stmt = session->current_stmt;
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_drop_space_def_t), (pointer_t *)&def));
    CT_RETURN_IFERR(ctc_put_ddl_sql_2_stmt(session, req->db_name, req->sql_str));
    stmt->context->type = CTSQL_TYPE_DROP_TABLESPACE;
    stmt->context->entry = def;
    proto_str2text(req->obj_name, &def->obj_name);
    def->options |= TABALESPACE_DFS_AND;
    def->options |= TABALESPACE_INCLUDE;
    def->is_for_create_db = CT_FALSE;
    status = knl_drop_space(&stmt->session->knl_session, stmt, def);
    CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    if (status == CT_SUCCESS) {
        do_commit(stmt->session);
    } else {
        do_rollback(stmt->session, NULL);
        CT_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    }
    ctc_ddl_clear_stmt(stmt);

    ctc_ddl_broadcast_request broadcast_req = {0};
    FILL_BROADCAST_REQ(broadcast_req, req->db_name, req->sql_str, ddl_ctrl->user_name, ddl_ctrl->user_ip,
                       ddl_ctrl->mysql_inst_id, ddl_ctrl->tch.sql_command);
    int broadcat_ret = ctc_execute_mysql_ddl_sql(&ddl_ctrl->tch, &broadcast_req, false);
    // 如果带有忽略参天错误的标志，需要同步忽略掉广播其他节点的报错
    return broadcat_ret;
}

EXTER_ATTACK int ctc_drop_tablespace(void *space_drop_def, ddl_ctrl_t *ddl_ctrl)
{
    TcDb__CtcDDLDropSpaceDef *req = tc_db__ctc_ddldrop_space_def__unpack(NULL, ddl_ctrl->msg_len, space_drop_def);
    CTC_LOG_RET_VAL_IF_NUL(req, CT_ERROR, "ctc_drop_tablespace: null req ptr");
    int ret = ctc_drop_tablespace_impl(req, ddl_ctrl);
    tc_db__ctc_ddldrop_space_def__free_unpacked(req, NULL);
    return ret;
}

static void lock_user_ddl(session_t *session, ctc_lock_table_mode_t lock_type)
{
    if (lock_type == CTC_LOCK_MODE_SHARE) {
        dls_latch_s(&session->knl_session, &session->knl_session.kernel->db.ddl_latch,
                session->knl_session.id, CT_FALSE, NULL);
    } else if (lock_type == CTC_LOCK_MODE_EXCLUSIVE) { // 目前只有元数据归一启动时会设置x
        dls_latch_x(&session->knl_session, &session->knl_session.kernel->db.ddl_latch,
                    session->knl_session.id, NULL);
    }
    session->knl_session.user_locked_ddl = CT_TRUE;
}

void unlock_user_ddl(session_t *session)
{
    dls_unlatch(&session->knl_session, &session->knl_session.kernel->db.ddl_latch, NULL);
    session->knl_session.user_locked_ddl = CT_FALSE;
}

EXTER_ATTACK int ctc_lock_instance(bool *is_mysqld_starting, ctc_lock_table_mode_t lock_type, ctc_handler_t *tch)
{
    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    int status = CT_SUCCESS;
    CT_RETURN_IFERR(ctc_get_or_new_session(&session, tch, true, true, &is_new_session));

    // 给cantian加全局latch
    lock_user_ddl(session, lock_type);
    CT_LOG_RUN_INF("[CTC_LOCK_INSTANCE]:lock_mode:%s, ctc_inst_id:%u, conn_id:%u,"
        "knl_session id:%u.", lock_type == CTC_LOCK_MODE_SHARE ? "S_LATCH" : "X_LATCH", tch->inst_id,
        tch->thd_id, session->knl_session.id);

    if (is_mysqld_starting && *is_mysqld_starting) {
        knl_set_sql_server_initializing_status(&session->knl_session, CT_FALSE);
        knl_set_db_status_4mysql_init(CT_FALSE);
        CT_LOG_RUN_INF("[CTC_LOCK_INSTANCE]: set readonly option close in mysqld server starting.");
    }
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_unlock_instance(bool *is_mysqld_starting, ctc_handler_t *tch)
{
    if (is_mysqld_starting && *is_mysqld_starting) {
        knl_set_db_status_4mysql_init(CT_TRUE);
        CT_LOG_RUN_INF("[CTC_UNLOCK_INSTANCE]: set readonly option open in mysqld server starting.");
    }
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    if (session == NULL) {
        return CT_ERROR;
    }
    
    ctc_set_no_use_other_sess4thd(session);
    if (session->knl_session.user_locked_ddl == CT_TRUE) {
        unlock_user_ddl(session);
        CT_LOG_RUN_INF("[CTC_UNLOCK_INSTANCE]: ctc_inst_id:%d, conn_id:%d, knl_session_id:%d.",
                       tch->inst_id, tch->thd_id, session->knl_session.id);
    }
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_check_db_table_exists(const char *db, const char *name, bool *is_exists)
{
    status_t ret = CT_SUCCESS;
    session_t *session = NULL;
    status_t status = ctc_get_new_session(&session);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_LOCK_TABLE]:alloc new session failed");
        return status;
    }
    ctc_set_no_use_other_sess4thd(session);
    char buf_db[CT_NAME_BUFFER_SIZE + 1];
    char buf_name[CT_NAME_BUFFER_SIZE + 1];
    text_t db_name = { .str = buf_db, .len = 0 };
    text_t table_name = { .str = buf_name, .len = 0 };
    bool32 is_found = CT_FALSE;
    cm_text_copy_from_str(&db_name, db, CT_NAME_BUFFER_SIZE + 1);
    cm_text_copy_from_str(&table_name, name, CT_NAME_BUFFER_SIZE + 1);
    if (table_name.len == 0) {
        ret = knl_schema_exists4mysql((knl_handle_t)session, &db_name, &is_found);
    } else {
        ret = knl_object_exists4mysql((knl_handle_t)session, &db_name, &table_name, &is_found);
    }
    if (is_found) {
        *is_exists = true;
    } else {
        knl_set_sql_server_initializing_status(&session->knl_session, CT_TRUE);
        *is_exists = false;
    }
    cm_reset_error();
    (void)ctc_free_session(session);
    return ret;
}
 
EXTER_ATTACK int ctc_query_cluster_role(bool *is_slave, bool *cantian_cluster_ready)
{
    database_t *db = &g_instance->kernel.db;
    bool32 ct_cluster_ready = CT_FALSE;
    for (int i = 0; i < META_SEARCH_TIMES; i++) {
        CT_RETURN_IFERR(knl_is_cantian_cluster_ready(&ct_cluster_ready));
        if (ct_cluster_ready) {
            *cantian_cluster_ready = true;
            CT_LOG_DEBUG_INF("[Disaster Recovery]: cantian_cluster_ready: %d.", ct_cluster_ready);
            if(DB_IS_PHYSICAL_STANDBY(db)) {
                *is_slave = true;
            } else {
                *is_slave = false;
            }
            return CT_SUCCESS;
        }
        cm_sleep(META_SEARCH_WAITING_TIME_IN_MS);
    }
    CT_LOG_RUN_ERR("[Disaster Recovery]: cantian_cluster_cluster_ready: %d.", ct_cluster_ready);
    return CT_ERROR;
}

EXTER_ATTACK int ctc_query_shm_file_num(uint32_t *shm_file_num)
{
    *shm_file_num = get_mq_queue_num();
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_search_metadata_status(bool *cantian_metadata_switch, bool *cantian_cluster_ready)
{
    bool32 ct_metadata_switch = CT_FALSE;
    CT_RETURN_IFERR(srv_get_param_bool32("MYSQL_METADATA_IN_CANTIAN", &ct_metadata_switch));
    *cantian_metadata_switch = (ct_metadata_switch == CT_TRUE);
    CT_LOG_RUN_INF("[CTC_SEARCH_METADATA_STATUS]: cantian_metadata_switch: %d.", ct_metadata_switch);
    
    bool32 ct_cluster_ready = CT_FALSE;
    for (int i = 0; i < META_SEARCH_TIMES; i++) {
        CT_RETURN_IFERR(knl_is_cantian_cluster_ready(&ct_cluster_ready));
        if (ct_cluster_ready) {
            *cantian_cluster_ready = true;
            CT_LOG_RUN_INF("[CTC_SEARCH_METADATA_STATUS]: cantian_cluster_ready: %d.", ct_cluster_ready);
            return CT_SUCCESS;
        }
        cm_sleep(META_SEARCH_WAITING_TIME_IN_MS);
    }
    CT_LOG_RUN_INF("[CTC_SEARCH_METADATA_STATUS]: cantian_cluster_ready: %d.", ct_cluster_ready);
    return CT_ERROR;
}

int ctc_unlock_mdl_key_impl(ctc_handler_t *tch, knl_handle_t knl_session, uint32_t mysql_inst_id)
{
    int ret;
    // 广播 mysqld
    ret = close_mysql_connection_intf(tch->thd_id, tch->inst_id);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_UNLOCK_MDL_KEY]:execute failed at other mysqld on current node, "
                       "ret = %d, conn_id:%u, inst_id:%u.", ret, tch->thd_id, tch->inst_id);
        return ret;
    }

    // 广播 其他cantian节点
    knl_session_t *knl_sess = (knl_session_t *)knl_session;
    msg_close_connection_req_t req;
    req.thd_id = tch->thd_id;
    req.mysql_inst_id = mysql_inst_id;
    req.msg_num = cm_random(CT_INVALID_ID32);
    mes_init_send_head(&req.head, MES_CMD_CLOSE_MYSQL_CONNECTION_REQ, sizeof(msg_close_connection_req_t), CT_INVALID_ID32,
        DCS_SELF_INSTID(knl_sess), 0, knl_sess->id, CT_INVALID_ID16);

    int error_code = ctc_broadcast_and_recv(knl_sess, MES_BROADCAST_ALL_INST, &req, NULL);
    if(error_code != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_UNLOCK_MDL]:execute failed on remote node, conn_id:%u, ctc_instance_id:%u", tch->thd_id, tch->inst_id);
    }

    SYNC_POINT_GLOBAL_START(CTC_UNLOCK_MDL_KEY_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    return CT_SUCCESS;
}

bool32 ctc_command_type_read(sql_command_filter_op_t cmd)
{
    switch (cmd) {
        case SQLCOM_SELECT:
        case SQLCOM_SHOW_DATABASES:
        case SQLCOM_SHOW_TABLES:
        case SQLCOM_SHOW_FIELDS:
        case SQLCOM_SHOW_KEYS:
        case SQLCOM_SHOW_VARIABLES:
        case SQLCOM_SHOW_STATUS:
        case SQLCOM_SHOW_ENGINE_LOGS:
        case SQLCOM_SHOW_ENGINE_STATUS:
        case SQLCOM_SHOW_ENGINE_MUTEX:
        case SQLCOM_SHOW_PROCESSLIST:
        case SQLCOM_SHOW_MASTER_STAT:
        case SQLCOM_SHOW_SLAVE_STAT:
        case SQLCOM_SHOW_GRANTS:
        case SQLCOM_SHOW_CREATE:
        case SQLCOM_SHOW_CHARSETS:
        case SQLCOM_SHOW_COLLATIONS:
        case SQLCOM_SHOW_CREATE_DB:
        case SQLCOM_SHOW_TABLE_STATUS:
        case SQLCOM_SHOW_TRIGGERS:
        case SQLCOM_SET_OPTION:
        case SQLCOM_CHECK:
        case SQLCOM_SHOW_BINLOGS:
        case SQLCOM_SHOW_OPEN_TABLES:
        case SQLCOM_SHOW_SLAVE_HOSTS:
        case SQLCOM_SHOW_BINLOG_EVENTS:
        case SQLCOM_SHOW_WARNS:
        case SQLCOM_SHOW_ERRORS:
        case SQLCOM_SHOW_STORAGE_ENGINES:
        case SQLCOM_SHOW_PRIVILEGES:
        case SQLCOM_SHOW_CREATE_PROC:
        case SQLCOM_SHOW_CREATE_FUNC:
        case SQLCOM_SHOW_STATUS_PROC:
        case SQLCOM_SHOW_STATUS_FUNC:
        case SQLCOM_SHOW_PROC_CODE:
        case SQLCOM_SHOW_FUNC_CODE:
        case SQLCOM_SHOW_PLUGINS:
        case SQLCOM_SHOW_CREATE_EVENT:
        case SQLCOM_SHOW_EVENTS:
        case SQLCOM_SHOW_CREATE_TRIGGER:
        case SQLCOM_SHOW_PROFILE:
        case SQLCOM_SHOW_PROFILES:
        case SQLCOM_SHOW_RELAYLOG_EVENTS:
        case SQLCOM_SHOW_CREATE_USER:
        case SQLCOM_END:
            return CT_TRUE;
        default:
            return CT_FALSE;
    }
}