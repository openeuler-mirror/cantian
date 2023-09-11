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
 * tse_ddl.c
 *
 *
 * IDENTIFICATION
 * src/tse/tse_ddl.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_instance.h"
#include "tse_srv.h"
#include "dtc_ddl.h"
#include "dtc_dcs.h"
#include "tse_srv_util.h"
#include "knl_interface.h"
#include "srv_query.h"
#include "dtc_dls.h"
#include "tse_ddl.h"
#include "srv_param.h"
#include "tse_ddl_broadcast.h"
#include "tse_mysql_client.h"
#include "srv_query.h"
#include "knl_table.h"
#include "knl_db_alter.h"
#include "knl_alter_space.h"
#include "db_defs.h"

#define DEFAULT_NULL_TEXT_STR "NULL"
#define DEFAULT_NULL_TEXT_LEN 4

#define FK_RESTRICT_MODE 0
#define FK_CASCADE_MODE 1
#define FK_SET_NULL_MODE 2

typedef struct st_mysql_cantiandba_type {
    enum_tse_ddl_field_types mysql_type;
    gs_type_t cantian_type;
} mysql_cantiandba_type_t;

mysql_cantiandba_type_t g_mysql_to_cantian_type[] = {
    { TSE_DDL_TYPE_LONG, GS_TYPE_INTEGER },
    { TSE_DDL_TYPE_TINY, GS_TYPE_INTEGER },
    { TSE_DDL_TYPE_SHORT, GS_TYPE_INTEGER },
    { TSE_DDL_TYPE_INT24, GS_TYPE_INTEGER },
    { TSE_DDL_TYPE_LONGLONG, GS_TYPE_BIGINT },
    { TSE_DDL_TYPE_DOUBLE, GS_TYPE_REAL },
    { TSE_DDL_TYPE_FLOAT, GS_TYPE_REAL },
    { TSE_DDL_TYPE_DECIMAL, GS_TYPE_NUMBER3 },
    { TSE_DDL_TYPE_NEWDECIMAL, GS_TYPE_NUMBER3 },  // 是否也用decimal类型
    { TSE_DDL_TYPE_NULL, GS_DATATYPE_OF_NULL },
    { TSE_DDL_TYPE_TIMESTAMP, GS_TYPE_TIMESTAMP },
    { TSE_DDL_TYPE_DATE, GS_TYPE_DATE },
    { TSE_DDL_TYPE_TIME, GS_TYPE_DATE },      // 确认是否用这个timestamp
    { TSE_DDL_TYPE_DATETIME, GS_TYPE_DATE },  // 确认是否和type date用一样的
    { TSE_DDL_TYPE_YEAR, GS_TYPE_DATE },
    { TSE_DDL_TYPE_NEWDATE, GS_TYPE_NATIVE_DATE },          // native datetime, internal used
    { TSE_DDL_TYPE_DATETIME2, GS_TYPE_NATIVE_DATE },        // native datetime, internal used
    { TSE_DDL_TYPE_TIMESTAMP2, GS_TYPE_NATIVE_TIMESTAMP },  // native datetime, internal used
    { TSE_DDL_TYPE_TIME2, GS_TYPE_NATIVE_TIMESTAMP },       // native datetime, internal used
    { TSE_DDL_TYPE_BIT, GS_TYPE_STRING },
    { TSE_DDL_TYPE_STRING, GS_TYPE_STRING },
    { TSE_DDL_TYPE_JSON, GS_TYPE_CLOB },
    { TSE_DDL_TYPE_VARCHAR, GS_TYPE_VARCHAR },
    { TSE_DDL_TYPE_VAR_STRING, GS_TYPE_VARCHAR },  // 待确定
    { TSE_DDL_TYPE_TYPED_ARRAY, GS_TYPE_ARRAY },
    { TSE_DDL_TYPE_TINY_BLOB, GS_TYPE_BLOB },  // tiny和medium blob待确认
    { TSE_DDL_TYPE_MEDIUM_BLOB, GS_TYPE_BLOB },
    { TSE_DDL_TYPE_BLOB, GS_TYPE_BLOB },
    { TSE_DDL_TYPE_CLOB, GS_TYPE_CLOB },
    { TSE_DDL_TYPE_LONG_BLOB, GS_TYPE_BLOB }
};

int get_and_init_session(session_t **session, tianchi_handler_t *tch, bool alloc_if_null);
void tse_ddl_clear_stmt(sql_stmt_t *stmt)
{
    sql_release_resource(stmt, GS_TRUE);
    sql_release_context(stmt);
    cm_reset_error();
    cm_stack_reset(stmt->session->knl_session.stack);

    stmt->eof = GS_TRUE;
    stmt->query_scn = GS_INVALID_ID64;
    stmt->gts_scn = GS_INVALID_ID64;
    stmt->v_systimestamp = GS_INVALID_INT64;
    stmt->session->call_version = CS_VERSION_0;
    stmt->tz_offset_utc = TIMEZONE_OFFSET_DEFAULT;
    if (stmt->session->active_stmts_cnt > 0) {
        stmt->session->active_stmts_cnt--;
    }

    if (stmt->session->stmts_cnt > 0) {
        stmt->session->stmts_cnt--;
    }
}

#define GS_RETURN_IFERR_EX(ret, stmt, ddl_ctrl)                                                                 \
    do {                                                                                                        \
        char *error_msg = (ddl_ctrl)->error_msg;                                                                \
        int _status_ = (ret);                                                                                   \
        if (_status_ != GS_SUCCESS) {                                                                           \
            int32 error_code = 0;                                                                               \
            char *message = NULL;                                                                               \
            cm_get_error(&error_code, (const char **)&message, NULL);                                           \
            GS_LOG_RUN_ERR("RETURN_IF_ERROR[%s,%d]error_code:%d,message:%s", __FILE__, __LINE__, error_code,    \
                           message == NULL ? "" : message);                                                     \
            if (error_code == 0 || message == NULL || (error_msg) == NULL) {                                    \
                tse_ddl_clear_stmt(stmt);                                                                       \
                return _status_;                                                                                \
            }                                                                                                   \
            _status_ = strncpy_s(error_msg, ERROR_MESSAGE_LEN, message, strlen(message));                       \
            knl_securec_check(_status_);                                                                        \
            tse_ddl_clear_stmt(stmt);                                                                           \
            return error_code;                                                                                  \
        }                                                                                                       \
    } while (0)

static bool tse_is_db_mysql_owner(const char *db_name)
{
    if (!strcmp(db_name, "mysql") || !strcmp(db_name, "information_schema") ||
        !strcmp(db_name, "performance_schema") || !strcmp(db_name, "sys")) {
        return true;
    }
    return false;
}

static bool tse_check_db_exists(knl_session_t *session, const char *db_name)
{
    if (CM_IS_EMPTY_STR(db_name)) {
        GS_LOG_DEBUG_INF("tse_check_db_exists db_name is empty");
        return false;
    }

    if (tse_is_db_mysql_owner(db_name)) {
        return true;
    }

    char buf[TSE_IDENTIFIER_MAX_LEN + 1];
    text_t text_db_name = { .str = buf, .len = 0 };
    cm_text_copy_from_str(&text_db_name, db_name, TSE_IDENTIFIER_MAX_LEN + 1);
    
    return spc_check_space_exists(session, &text_db_name, GS_TRUE);
}

int copy_broadcast_dbname_to_req(char *dst, int dst_len, const char *src)
{
    int len = strlen(src);
    if (len >= dst_len) {
        GS_LOG_RUN_ERR("str len : %d > %d", len, dst_len);
        return GS_ERROR;
    }
    errno_t errcode = memcpy_s(dst, dst_len, src, len);
    if (errcode != EOK) {
        return GS_ERROR;
    }
    dst[len] = '\0';
    return GS_SUCCESS;
}

int tse_alter_table_lock_table(knl_session_t *knl_session, knl_dictionary_t *dc)
{
    status_t status = GS_SUCCESS;
    drlatch_t *ddl_latch = &(knl_session->kernel->db.ddl_latch);

    if (knl_ddl_enabled(knl_session, GS_TRUE) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[TSE_ALTER_LOCK_TABLE] Cantian Cluster it not avaliable.");
        return GS_ERROR;
    }

    if (knl_ddl_latch_s(ddl_latch, knl_session, NULL) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[TSE_ALTER_LOCK_TABLE] latch ddl failed");
        return GS_ERROR;
    }
    knl_session->user_locked_ddl = ALTER_TABLE_DDL_LOCKED;
    return knl_alter_table_lock_table(knl_session, dc);
}

static inline msg_prepare_ddl_req_t tse_init_ddl_req(tianchi_handler_t *tch, tse_lock_table_info *lock_info)
{
    msg_prepare_ddl_req_t req;
    req.tch = *tch;
    req.lock_info = *lock_info;
    req.msg_num = cm_random(GS_INVALID_ID32);
    req.db_name[0] = '\0';
    return req;
}

static inline void tse_fill_execute_ddl_req(msg_execute_ddl_req_t *req, uint32_t thd_id,
    tse_ddl_broadcast_request *broadcast_req, bool allow_fail)
{
    req->thd_id = thd_id;
    req->broadcast_req = *broadcast_req;
    req->msg_num = cm_random(GS_INVALID_ID32);
    req->allow_fail = allow_fail;
}

int tse_lock_table(tianchi_handler_t *tch, const char *db_name, tse_lock_table_info *lock_info,
    int *error_code)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    if (session == NULL) {
        status_t status = tse_get_new_session(&session);
        if (status != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[TSE_LOCK_TABLE]:alloc new session failed, thdid:%u, tse_inst_id:%u",
                tch->thd_id, tch->inst_id);
            return status;
        }
        session->tse_inst_id = tch->inst_id;
        session->tse_thd_id = tch->thd_id;
        tch->sess_addr = (uint64)session;
        GS_LOG_DEBUG_INF("[TSE_LOCK_TABLE]:get new session for thd_id:%u, tse_inst_id:%u",
                         tch->thd_id, tch->inst_id);
    }
    tse_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    if (knl_session->user_locked_ddl == GS_TRUE) {
        GS_LOG_RUN_ERR("[CTC_LOCK_TABLE]: Instance has been locked, disallow this operation"
                       "lock_info(db=%s, table=%s), conn_id=%u, tse_instance_id=%u",
                       lock_info->db_name, lock_info->table_name, tch->thd_id, tch->inst_id);
        *error_code = ERR_USER_DDL_LOCKED;
        return GS_ERROR;
    }

    char *broadcast_db_name = tse_check_db_exists(knl_session, db_name) ? db_name : NULL;
    // 本节点的其他mysqld
    status_t ret = tse_ddl_execute_lock_tables(tch, broadcast_db_name, lock_info, error_code);
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[TSE_LOCK_TABLE]:execute failed at other mysqld on current node, error_code:%d"
                       "lock_info(db:%s, table:%s), conn_id:%u, tse_instance_id:%u", *error_code,
                       lock_info->db_name, lock_info->table_name, tch->thd_id, tch->inst_id);
        return GS_ERROR;
    }

    // 广播 其他daac节点
    msg_prepare_ddl_req_t req = tse_init_ddl_req(tch, lock_info);
    if (!CM_IS_EMPTY_STR(broadcast_db_name) &&
        copy_broadcast_dbname_to_req(req.db_name, MES_DB_NAME_BUFFER_SIZE, broadcast_db_name) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[TSE_LOCK_TABLE]: strcpy failed, db_name=%s", broadcast_db_name);
        return GS_ERROR;
    }

    mes_init_send_head(&req.head, MES_CMD_PREPARE_DDL_REQ, sizeof(msg_prepare_ddl_req_t),
        GS_INVALID_ID32, DCS_SELF_INSTID(knl_session), 0, knl_session->id, GS_INVALID_ID16);
    knl_panic(sizeof(msg_prepare_ddl_req_t) < MES_MESSAGE_BUFFER_SIZE);

    *error_code = tse_broadcast_and_recv(knl_session, MES_BROADCAST_ALL_INST, &req);
    if (*error_code != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[TSE_LOCK_TABLE]:execute failed on remote node, err_code:%d, db_name %s,"
                       "lock_info(db:%s, table:%s), conn_id:%u, tse_instance_id:%u", *error_code,
                       db_name, lock_info->db_name, lock_info->table_name, tch->thd_id, tch->inst_id);
        return GS_ERROR;
    }

    SYNC_POINT_GLOBAL_START(TSE_LOCK_TABLE_SUCC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    return GS_SUCCESS;
}

// 参天需要执行的，走此接口
int tse_put_ddl_sql_2_stmt(session_t *session, const char *db_name, const char *sql_str)
{
    int ret;
    int len = strlen(sql_str);
    if (len <= 0) {
        GS_LOG_RUN_ERR("[TSE_DDL]:tse_put_ddl_sql_2_stmt length is invalid");
        return GS_ERROR;
    }
    sql_stmt_t *stmt = session->current_stmt;
    knl_session_t *knl_session = &session->knl_session;
    char *my_sql_str = NULL;
    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, len + 1, (pointer_t *)&my_sql_str));
    ret = strcpy_s(my_sql_str, len + 1, sql_str);
    knl_securec_check(ret);
    if (my_sql_str[len - 1] == ';') {
        my_sql_str[len - 1] = '\0';  // 将最后一个;去掉，避免sql语句语法错误
    }
    text_t sql = { 0 };
    sql.len = strlen(db_name) + strlen(my_sql_str) + SMALL_RECORD_SIZE; // use XXX_DB; sql;

    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sql.len, (pointer_t *)&sql.str));
    if (strlen(db_name) > 0) {
        ret = sprintf_s(sql.str, sql.len, "use %s\n%s", db_name, my_sql_str);
    } else {
        ret = sprintf_s(sql.str, sql.len, "%s", my_sql_str);
    }
    PRTS_RETURN_IFERR(ret);
    sql.len = strlen(sql.str);
    stmt->lang_type = LANG_DDL;
    GS_RETURN_IFERR(ctx_write_text(&stmt->context->ctrl, &sql));
    stmt->context->ctrl.hash_value = cm_hash_text(&sql, INFINITE_HASH_RANGE);
    knl_session->uid = DB_PUB_USER_ID;
    return GS_SUCCESS;
}

int tse_put_ddl_sql_2_stmt_not_cantian_exe(session_t *session, tse_ddl_broadcast_request *broadcast_req)
{
    // 参天需要执行的，不走此接口
    if (!(broadcast_req->options & TSE_NOT_NEED_CANTIAN_EXECUTE)) {
        return GS_SUCCESS;
    }
    
    if (broadcast_req->sql_command == SQLCOM_SET_OPTION || broadcast_req->sql_command == SQLCOM_LOCK_INSTANCE ||
        broadcast_req->sql_command == SQLCOM_UNLOCK_INSTANCE) {
        return GS_SUCCESS;
    }

    bool alloc_stmt = false;
    if (session->current_stmt == NULL) {
        GS_RETURN_IFERR(sql_alloc_stmt(session, &session->current_stmt));
        alloc_stmt = true;
    }
    bool alloc_context = false;
    if (session->current_stmt->context == NULL) {
        sql_alloc_context(session->current_stmt);
        alloc_context = true;
    }
    sql_stmt_t *stmt = session->current_stmt;
    knl_session_t *knl_session = &session->knl_session;
    int ret = tse_put_ddl_sql_2_stmt(session, broadcast_req->db_name, broadcast_req->sql_str);
    (void)knl_put_ddl_sql(knl_session, stmt);
    if (alloc_context) {
        sql_release_context(session->current_stmt);
    }
    if (alloc_stmt) {
        sql_free_stmt(session->current_stmt);
        session->current_stmt = NULL;
    }
    return ret;
}

int tse_ddl_execute_and_broadcast(tianchi_handler_t *tch, tse_ddl_broadcast_request *broadcast_req,
    bool allow_fail, knl_session_t *knl_session)
{
    status_t ret = mysql_execute_ddl_sql(tch->thd_id, broadcast_req, &allow_fail);
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[TSE_DDL]:execute failed at other mysqld on current node, ret:%d,"
            "sql_str:%s, user_name:%s, sql_command:%u, err_code:%d, conn_id:%u, tse_instance_id:%u, allow_fail:%d",
            ret, sql_without_plaintext_password((broadcast_req->options & TSE_CURRENT_SQL_CONTAIN_PLAINTEXT_PASSWORD),
            broadcast_req->sql_str, strlen(broadcast_req->sql_str)),
            broadcast_req->user_name, broadcast_req->sql_command, broadcast_req->err_code,
            tch->thd_id, tch->inst_id, allow_fail);
        return GS_ERROR;
    }

    msg_execute_ddl_req_t req;
    tse_fill_execute_ddl_req(&req, tch->thd_id, broadcast_req, allow_fail);
    mes_init_send_head(&req.head, MES_CMD_EXECUTE_DDL_REQ, sizeof(msg_execute_ddl_req_t), GS_INVALID_ID32, DCS_SELF_INSTID(knl_session), 0, knl_session->id,
        GS_INVALID_ID16);
    knl_panic(sizeof(msg_execute_ddl_req_t) < MES_MESSAGE_BUFFER_SIZE);

    int error_code = tse_broadcast_and_recv(knl_session, MES_BROADCAST_ALL_INST, &req);
    if (error_code != GS_SUCCESS && allow_fail == true) {
        broadcast_req->err_code = error_code;
        GS_LOG_RUN_ERR("[TSE_DDL_REWRITE]:execute on other mysqld fail. error_code:%d", error_code);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

int tse_execute_mysql_ddl_sql(tianchi_handler_t *tch, tse_ddl_broadcast_request *broadcast_req, bool allow_fail)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    if (session == NULL) {
        status_t status = tse_get_new_session(&session);
        if (status != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[TSE_DDL]:alloc new session failed, thdid %u", tch->thd_id);
            return status;
        }
        session->tse_inst_id = tch->inst_id;
        session->tse_thd_id = tch->thd_id;
        tch->sess_addr = (uint64)session;
        GS_LOG_DEBUG_INF("[TSE_DDL]:alloc new session for thd_id = %u", tch->thd_id);
    }
    tse_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    if (tch->query_id == session->query_id && broadcast_req->sql_command != SQLCOM_DROP_TABLE) {
        return GS_SUCCESS;
    }
    session->query_id = tch->query_id;
    
    if (!tse_check_db_exists(knl_session, broadcast_req->db_name)) {
        broadcast_req->db_name[0] = '\0';
    }

    status_t ret = tse_ddl_execute_and_broadcast(tch, broadcast_req, allow_fail, knl_session);
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[TSE_DDL]:tse_ddl_execute_and_broadcast faile. sql_str:%s, user_name:%s,"
            "sql_command:%u, err_code:%d, conn_id:%u, tse_instance_id:%u, allow_fail:%d",
            sql_without_plaintext_password((broadcast_req->options & TSE_CURRENT_SQL_CONTAIN_PLAINTEXT_PASSWORD),
            broadcast_req->sql_str, strlen(broadcast_req->sql_str)),
            broadcast_req->user_name, broadcast_req->sql_command, broadcast_req->err_code,
            tch->thd_id, tch->inst_id, allow_fail);
        return GS_ERROR;
    }

    SYNC_POINT_GLOBAL_START(TSE_DDL_SUCC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    (void)tse_put_ddl_sql_2_stmt_not_cantian_exe(session, broadcast_req);
    return GS_SUCCESS;
}

int tse_rewrite_open_conn(tianchi_handler_t *tch, tse_ddl_broadcast_request *broadcast_req,
    knl_session_t *knl_session)
{
    // 本节点的其他mysqld
    status_t ret = tse_execute_rewrite_open_conn(tch->thd_id, broadcast_req);
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[TSE_REWRITE_CONN]:execute failed at other mysqld on current node, ret:%d,"
            "sql_str:%s, user_name:%s, sql_command:%u, err_code:%d, conn_id:%u, tse_instance_id:%u",
            ret, sql_without_plaintext_password((broadcast_req->options & TSE_CURRENT_SQL_CONTAIN_PLAINTEXT_PASSWORD),
            broadcast_req->sql_str, strlen(broadcast_req->sql_str)),
            broadcast_req->user_name, broadcast_req->sql_command, broadcast_req->err_code,
            tch->thd_id, tch->inst_id);
        return GS_ERROR;
    }

    msg_execute_ddl_req_t req;
    tse_fill_execute_ddl_req(&req, tch->thd_id, broadcast_req, true);
    mes_init_send_head(&req.head, MES_CMD_REWRITE_OPEN_CONN_REQ, sizeof(msg_execute_ddl_req_t), GS_INVALID_ID32,
        DCS_SELF_INSTID(knl_session), 0, knl_session->id, GS_INVALID_ID16);
    knl_panic(sizeof(msg_execute_ddl_req_t) < MES_MESSAGE_BUFFER_SIZE);

    int error_code = tse_broadcast_and_recv(knl_session, MES_BROADCAST_ALL_INST, &req);
    if (error_code != GS_SUCCESS) {
        broadcast_req->err_code = error_code;
        GS_LOG_RUN_ERR("[TSE_REWRITE_CONN]:execute on other mysqld fail. error_code:%d", error_code);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

int tse_broadcast_rewrite_sql(tianchi_handler_t *tch, tse_ddl_broadcast_request *broadcast_req, bool allow_fail)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    if (session == NULL) {
        status_t status = tse_get_new_session(&session);
        if (status != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[TSE_DDL_REWRITE]:alloc new session failed, thdid %u", tch->thd_id);
            return status;
        }
        session->tse_inst_id = tch->inst_id;
        session->tse_thd_id = tch->thd_id;
        tch->sess_addr = (uint64)session;
        GS_LOG_DEBUG_INF("[TSE_DDL_REWRITE]:alloc new session for thd_id = %u", tch->thd_id);
    }
    tse_set_no_use_other_sess4thd(session);
    
    knl_session_t *knl_session = &session->knl_session;
    if (!tse_check_db_exists(knl_session, broadcast_req->db_name)) {
        broadcast_req->db_name[0] = '\0';
    }

    // 全局开连接
    status_t ret = tse_rewrite_open_conn(tch, broadcast_req, knl_session);
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[TSE_REWRITE_CONN]:Open connections faile for tse_ddl_rewrite.");
        return GS_ERROR;
    }

    // 开连接后执行
    ret = tse_ddl_execute_and_broadcast(tch, broadcast_req, allow_fail, knl_session);
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[TSE_DDL_REWRITE]:tse_ddl_execute_and_broadcast faile. sql_str:%s, user_name:%s,"
            "sql_command:%u, err_code:%d, conn_id:%u, tse_instance_id:%u, allow_fail:%d",
            sql_without_plaintext_password((broadcast_req->options & TSE_CURRENT_SQL_CONTAIN_PLAINTEXT_PASSWORD),
            broadcast_req->sql_str, strlen(broadcast_req->sql_str)),
            broadcast_req->user_name, broadcast_req->sql_command, broadcast_req->err_code,
            tch->thd_id, tch->inst_id, allow_fail);
        return GS_ERROR;
    }

    (void)tse_put_ddl_sql_2_stmt_not_cantian_exe(session, broadcast_req);
    return GS_SUCCESS;
}

int tse_close_mysql_connection(tianchi_handler_t *tch)
{
    // 本节点的其他mysqld
    status_t ret = close_mysql_connection(tch->thd_id, tch->inst_id);
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[TSE_CLOSE_SESSION]:execute failed at other mysqld on current node, "
            "ret = %d, conn_id:%u, inst_id:%u.", ret, tch->thd_id, tch->inst_id);
        return ret;
    }

    // TODO: 依赖MES的故障处理方案, 现在节点故障后节点间广播会失败返错,导致整个清理流程失败
    if ((uint16_t)(tch->inst_id) == (uint16_t)CANTIAN_DOWN_MASK) {
        GS_LOG_RUN_ERR("[TSE_CLOSE_SESSION]:Clean bad node resourses not broadcast to other node YET!");
        return ret;
    }

    // 广播 其他daac节点
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    if (session == NULL) {
        status_t status = tse_get_new_session(&session);
        if (status != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[TSE_CLOSE_SESSION]:alloc new session failed, thdid = %u", tch->thd_id);
            return status;
        }
        session->tse_inst_id = tch->inst_id;
        session->tse_thd_id = tch->thd_id;
        tch->sess_addr = INVALID_VALUE64; // 此处不能把这个session传出去，避免外面没释放session,导致这个地方session泄漏
        GS_LOG_DEBUG_INF("[TSE_CLOSE_SESSION]:tse_close_mysql_connection alloc new session for inst_id:%u, thd_id = %u",
                         tch->inst_id, tch->thd_id);
    }
    knl_session_t *knl_session = &session->knl_session;
    msg_close_connection_req_t req;
    req.thd_id = tch->thd_id;
    req.mysql_inst_id = tch->inst_id;
    req.msg_num = cm_random(GS_INVALID_ID32);
    mes_init_send_head(&req.head, MES_CMD_CLOSE_MYSQL_CONNECTION_REQ, sizeof(msg_close_connection_req_t), GS_INVALID_ID32,
        DCS_SELF_INSTID(knl_session), 0, knl_session->id, GS_INVALID_ID16);
    knl_panic(sizeof(msg_close_connection_req_t) < MES_MESSAGE_BUFFER_SIZE);

    (void)tse_broadcast_and_recv(knl_session, MES_BROADCAST_ALL_INST, &req);
    tse_free_session(session);
    session = NULL;
    SYNC_POINT_GLOBAL_START(TSE_CLOSE_CONN_SUCC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    return GS_SUCCESS;
}

int tse_db_common_pre_check(knl_session_t *knl_session, const char *db_name, int *error_code, char *error_message)
{
    int ret = 0;
    
    if (db_name != NULL && strlen(db_name) > TSE_IDENTIFIER_MAX_LEN) {
        *error_code = ERR_SQL_SYNTAX_ERROR;
        ret = snprintf_s(error_message, ERROR_MESSAGE_LEN, ERROR_MESSAGE_LEN - 1,
                         "[CTC_DB]: The db name '%-.100s' is too long", db_name);
        knl_securec_check_ss(ret);
        return GS_ERROR;
    }

    if (knl_ddl_enabled(knl_session, GS_TRUE) != GS_SUCCESS) {
        *error_code = ERR_CLUSTER_DDL_DISABLED;
        ret = snprintf_s(error_message, ERROR_MESSAGE_LEN, ERROR_MESSAGE_LEN - 1,
                         "[CTC_DB]: Cantian Cluster it not avaliable.");
        knl_securec_check_ss(ret);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

int tse_create_db_pre_check(session_t *session, const char *db_name, int *error_code, char *error_message)
{
    int ret = 0;

    if (tse_db_common_pre_check(&session->knl_session, db_name, error_code, error_message)) {
        GS_LOG_RUN_ERR("[CTC_PRE_CREATE_DB]:Pre create database pre-check failed. error_code:%d, error_message:%s",
            *error_code, error_message);
        return GS_ERROR;
    }
    
    if (tse_is_db_mysql_owner(db_name)) {
        *error_code = ERR_OPERATIONS_NOT_ALLOW;
        ret = snprintf_s(error_message, ERROR_MESSAGE_LEN, ERROR_MESSAGE_LEN - 1,
                         "[CTC_PRE_CREATE_DB]: do not allow to create mysql sys schema %s", db_name);
        knl_securec_check_ss(ret);
        GS_LOG_RUN_ERR(error_message);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

int tse_drop_db_pre_check(tianchi_handler_t *tch, const char *db_name, int *error_code, char *error_message)
{
    session_t *session = NULL;
    // 删除db tse_lock_table创建过session，这里不需要在创建session
    GS_RETURN_IFERR(get_and_init_session(&session, tch, false));

    if (tse_db_common_pre_check(&session->knl_session, db_name, error_code, error_message)) {
        GS_LOG_RUN_ERR("[CTC_PRE_DROP_DB]:Drop database pre-check failed. error_code:%d, error_message:%s",
            *error_code, error_message);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t tse_generate_tablespace_path(const char *db_tablespace_name, char *db_ts_path, uint32_t path_max_len)
{
    int ret;
    char *path_prefix = server_get_param("SHARED_PATH");
    int path_prefix_len = path_prefix == NULL ? 0 : strlen(path_prefix);
    if ((path_prefix_len + strlen(db_tablespace_name)) > path_max_len) {
        GS_LOG_RUN_ERR("[CTC_CREATE_TS]: tablespace and prefix exceeds the total maximum value %d, prefix:%s,\
            tablespace:%s.", path_max_len, path_prefix, db_tablespace_name);
        return ERR_NAME_TOO_LONG;
    }
    if (path_prefix == NULL || strlen(path_prefix) == 0) {
        ret = sprintf_s(db_ts_path, path_max_len, "%s", db_tablespace_name);
    } else {
        if (cm_dbs_is_enable_dbs() == GS_TRUE) {
            // for dbstor, remove sep to ensure users can mount from nfs and get correct file desc.
            ret = sprintf_s(db_ts_path, path_max_len, "%s%s", path_prefix, db_tablespace_name);
        } else {
            ret = sprintf_s(db_ts_path, path_max_len, "%s/%s", path_prefix, db_tablespace_name);
        }
    }
    knl_securec_check_ss(ret);
    return GS_SUCCESS;
}

static void tse_db_get_err(int *error_code, char *error_message, uint32_t msg_len)
{
    char *message = NULL;
    cm_get_error(error_code, &message, NULL);
    int ret = strncpy_s(error_message, msg_len, message, msg_len - 1);
    knl_securec_check(ret);
}

static status_t tse_fill_dbspace_info(sql_stmt_t *stmt, knl_space_def_t *space_def,
                                      tse_db_infos_t *db_infos, char *db_ts_path)
{
    status_t status = GS_SUCCESS;
    knl_device_def_t *datafile = NULL;
 
    proto_str2text(db_infos->name_suffix, &space_def->name);
    space_def->type = SPACE_TYPE_USERS;
    space_def->is_for_create_db = GS_TRUE;
 
    cm_galist_init(&space_def->datafiles, stmt->context, sql_alloc_mem);
    status = cm_galist_new(&space_def->datafiles, sizeof(knl_device_def_t), (pointer_t *)&datafile);
    GS_RETURN_IFERR(status);
    status = tse_generate_tablespace_path(db_infos->name_suffix, db_ts_path, TABLESPACE_PATH_MAX_LEN - 1);
    GS_RETURN_IFERR(status);
    proto_str2text(db_ts_path, &datafile->name);
    datafile->size = (int64)(db_infos->datafile_size) * 1024 * 1024; // 1024 * 1024 为M转B
    datafile->autoextend.enabled = db_infos->datafile_autoextend;
    datafile->autoextend.nextsize = (int64)(db_infos->datafile_extend_size) * 1024 * 1024; // 1024 * 1024 为M转B
    return status;
}
 
static status_t tse_fill_dbuser_info(knl_user_def_t *user_def, const char *user_name, const char *user_password)
{
    status_t status = GS_SUCCESS;
 
    knl_securec_check(strcpy_s(user_def->name, GS_NAME_BUFFER_SIZE, user_name));
    knl_securec_check(strcpy_s(user_def->password, GS_PASSWORD_BUFFER_SIZE, user_password));
    /* db创建的用户名与表空间同名 */
    knl_securec_check(strcpy_s(user_def->default_space, GS_NAME_BUFFER_SIZE, user_name));
 
    user_def->is_readonly = GS_TRUE;
    user_def->is_lock = GS_TRUE;
    user_def->is_for_create_db = GS_TRUE;
    user_def->mask |= USER_LOCK_MASK;
    user_def->mask |= USER_DATA_SPACE_MASK;
    return status;
}

static int is_column_with_default_func(const TcDb__TseDDLColumnDef *def, ddl_ctrl_t *ddl_ctrl)
{
    bool is_default_func = ((tse_column_option_set_bit)def->is_option_set).is_default_func &&
                           !((tse_column_option_set_bit)def->is_option_set).is_curr_timestamp;
    if (is_default_func) {
        text_t default_func;
        char *func_name = def->default_func_name;
        cm_str2text(func_name, &default_func);
        uint32 func_id = sql_get_func_id(&default_func);
        if (func_id == GS_INVALID_ID32) {
            MEMS_RETURN_IFERR(strcat_s(ddl_ctrl->error_msg, MAX_DDL_ERROR_MSG_LEN, def->name));
            MEMS_RETURN_IFERR(strcat_s(ddl_ctrl->error_msg, MAX_DDL_ERROR_MSG_LEN, ","));
            MEMS_RETURN_IFERR(strcat_s(ddl_ctrl->error_msg, MAX_DDL_ERROR_MSG_LEN, func_name));
            GS_THROW_ERROR(ERR_FUNCTION_NOT_EXIST, T2S(&default_func));
             
            return ERR_FUNCTION_NOT_EXIST;
        }
    }
    return GS_SUCCESS;
}

int tse_pre_create_db(tianchi_handler_t *tch, const char *sql_str, tse_db_infos_t *db_infos,
                      int *error_code, char *error_message)
{
    status_t status = GS_SUCCESS;
    session_t *session = NULL;
    sql_stmt_t *stmt = NULL;
    knl_space_def_t *space_def = NULL;
    knl_user_def_t *user_def = NULL;
    char db_ts_path[TABLESPACE_PATH_MAX_LEN] = { 0 };
    char db_name[SMALL_RECORD_SIZE] = { '\0' };
    size_t db_len = strlen(db_infos->name_suffix);

    // 创建db tse_lock_table里面分配过session了，这里不需要在分配了
    status = get_and_init_session(&session, tch, false);
    if (status != GS_SUCCESS) {
        return GS_ERROR;
    }

    MEMS_RETURN_IFERR(strncpy_s(db_name, SMALL_RECORD_SIZE, db_infos->name_suffix, db_len));
    GS_RETURN_IFERR(tse_create_db_pre_check(session, db_name, error_code, error_message));
    stmt = session->current_stmt;
    tse_put_ddl_sql_2_stmt(session, EMPTY_DATABASE, sql_str);

    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_space_def_t), (pointer_t *)&space_def));
    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_user_def_t), (pointer_t *)&user_def));

    GS_RETURN_IFERR(tse_fill_dbspace_info(stmt, space_def, db_infos, db_ts_path));
 
    GS_RETURN_IFERR(tse_fill_dbuser_info(user_def, db_infos->name_suffix, db_infos->user_password));

    status = knl_create_database4mysql((knl_handle_t)session, (knl_handle_t)stmt, space_def, user_def);
    if (status == GS_SUCCESS) {
        do_commit(stmt->session);
    } else {
        do_rollback(stmt->session, NULL);
        tse_db_get_err(error_code, error_message, ERROR_MESSAGE_LEN);
        GS_LOG_RUN_ERR("[TSE_CREATE_DB]:create database error,"
                       "ret:%d, error_code:%d, error_message:%s, conn_id:%u, tse_instance_id:%u",
                       status, *error_code, error_message, tch->thd_id, tch->inst_id);
        tse_ddl_clear_stmt(stmt);
        return GS_ERROR;
    }
    tse_ddl_clear_stmt(stmt);
    return GS_SUCCESS;
}

void tse_fill_drop_dbuser(knl_drop_user_t *user_def, char *user_name)
{
    proto_str2text(user_name, &user_def->owner);
    user_def->purge = GS_TRUE;
}
 
void tse_fill_drop_dbspace(knl_drop_space_def_t *space_def, char *space_name)
{
    proto_str2text(space_name, &space_def->obj_name);
    space_def->options |= TABALESPACE_DFS_AND;
    space_def->options |= TABALESPACE_INCLUDE;
    space_def->options |= TABALESPACE_CASCADE;
    space_def->is_for_create_db = GS_TRUE;
}

int tse_drop_tablespace_and_user(tianchi_handler_t *tch, const char *db_name, const char *db_name_with_suffix,
                                 const char *sql_str, const char *user_name, const char *user_ip, int *error_code,
                                 char *error_message)
{
    session_t *session = NULL;
    knl_drop_user_t *user_def = NULL;
    knl_drop_space_def_t *space_def = NULL;
    sql_stmt_t *stmt = NULL;
    status_t status = GS_SUCCESS;

    // TODO：mysql没有下发正确的tch， tse_drop_db_pre_check之前已经有session了
    status = get_and_init_session(&session, tch, true);
    if (status != GS_SUCCESS) {
        return status;
    }
    stmt = session->current_stmt;

    tse_put_ddl_sql_2_stmt(session, EMPTY_DATABASE, sql_str);

    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_drop_user_t), (pointer_t *)&user_def));
    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_drop_space_def_t), (pointer_t *)&space_def));
    tse_fill_drop_dbspace(space_def, db_name_with_suffix);
    tse_fill_drop_dbuser(user_def, db_name_with_suffix);

    status = knl_drop_database4mysql((knl_handle_t)session, (knl_handle_t)stmt, space_def, user_def);
    if (status == GS_SUCCESS) {
        do_commit(stmt->session);
    } else {
        do_rollback(stmt->session, NULL);
        tse_db_get_err(error_code, error_message, ERROR_MESSAGE_LEN);
        GS_LOG_RUN_ERR("[TSE_DROP_DB]: drop database failed, error_code:%d, error_message:%s",
            *error_code, error_message);
        tse_ddl_clear_stmt(stmt);
        return GS_ERROR;
    }
    tse_ddl_clear_stmt(stmt);

    tse_ddl_broadcast_request broadcast_req = {0};
    FILL_BROADCAST_REQ(broadcast_req, db_name, sql_str, user_name, user_ip, tch->inst_id, tch->sql_command);
    if (tse_execute_mysql_ddl_sql(tch, &broadcast_req, false) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[TSE_DROP_DB]:Broadcast drop db sql_str error, error_code:%d, conn_id:%lu, tse_instance_id:%lu",
                       broadcast_req.err_code, tch->thd_id, tch->inst_id);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

void tse_alter_table_unlock(knl_session_t *knl_session)
{
    drlatch_t *ddl_latch = NULL;
    knl_alter_table_unlock_table(knl_session);
    if (knl_session->user_locked_ddl == ALTER_TABLE_DDL_LOCKED) {
        ddl_latch = &(knl_session->kernel->db.ddl_latch);
        dls_unlatch(knl_session, ddl_latch, NULL);
        knl_session->user_locked_ddl = GS_FALSE;
    }
}

int tse_unlock_table(tianchi_handler_t *tch, uint32_t mysql_inst_id)
{
    bool8 is_new_session = GS_FALSE;
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    if (session == NULL) {
        status_t status = tse_get_new_session(&session);
        if (status != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[TSE_UNLOCK_TABLE]:alloc new session failed, thd_id=%u", tch->thd_id);
            return status;
        }
        session->tse_inst_id = tch->inst_id;
        session->tse_thd_id = tch->thd_id;
        is_new_session = GS_TRUE;
    }
    tse_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;

    // 本节点的其他mysql
    status_t ret = tse_ddl_execute_unlock_tables(tch, mysql_inst_id);
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[TSE_UNLOCK_TABLE]:execute failed at other mysqld on current node conn_id:%u", tch->thd_id);
        return GS_ERROR;
    }
    // 广播 其他daac节点
    msg_commit_ddl_req_t req;
    req.tch = *tch;

    req.msg_num = cm_random(GS_INVALID_ID32);
    req.mysql_inst_id = mysql_inst_id;
    mes_init_send_head(&req.head, MES_CMD_COMMIT_DDL_REQ, sizeof(msg_commit_ddl_req_t), GS_INVALID_ID32, DCS_SELF_INSTID(knl_session), 0, knl_session->id,
        GS_INVALID_ID16);
    knl_panic(sizeof(msg_commit_ddl_req_t) < MES_MESSAGE_BUFFER_SIZE);

    (void)tse_broadcast_and_recv(knl_session, MES_BROADCAST_ALL_INST, &req);
    
    if (is_new_session) {
        (void)tse_free_session(session);
    }

    SYNC_POINT_GLOBAL_START(TSE_MES_UNLOCK_TABLE_SUCC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    return GS_SUCCESS;
}

status_t init_ddl_session(session_t *session)
{
    session->knl_session.spid = cm_get_current_thread_id();
    knl_set_curr_sess2tls((void *)session);
    // set session id here, because need consider agent mode, for example, agent mode is AGENT_MODE_SHARED
    cm_log_set_session_id(session->knl_session.id);
    cm_reset_error();
    /* get stmt to prepare sql */
    if (session->current_stmt == NULL) {
        GS_RETURN_IFERR(sql_alloc_stmt(session, &session->current_stmt));
    }
    sql_stmt_t *stmt = session->current_stmt;
    sql_release_lob_info(stmt);

    sql_release_resource(stmt, GS_TRUE);
    sql_release_context(stmt);

    stmt->is_explain = GS_FALSE;
    stmt->is_reform_call = GS_FALSE;

    stmt->pl_failed = GS_FALSE;
    stmt->lang_type = LANG_DDL;

    status_t status = sql_alloc_context(stmt);
    GS_RETURN_IFERR(status);
    GS_RETURN_IFERR(sql_create_list(stmt, &stmt->context->ref_objects));
    sql_set_scn(stmt);
    sql_set_ssn(stmt);
    stmt->status = STMT_STATUS_PREPARED;
    return GS_SUCCESS;
}

gs_type_t get_gs_type_from_tse_ddl_type(enum_tse_ddl_field_types tse_type)
{
    for (size_t i = 0; i < sizeof(g_mysql_to_cantian_type) / sizeof(mysql_cantiandba_type_t); i++) {
        if (tse_type == g_mysql_to_cantian_type[i].mysql_type) {
            return g_mysql_to_cantian_type[i].cantian_type;
        }
    }
    return GS_TYPE_UNKNOWN;
}

bool type_is_number(gs_type_t datatype)
{
    switch (datatype) {
        case GS_TYPE_INTEGER:
        case GS_TYPE_DECIMAL:
        case GS_TYPE_TINYINT:
        case GS_TYPE_SMALLINT:
        case GS_TYPE_REAL:
        case GS_TYPE_BIGINT:
            return true;
        default:
            return false;
    }
}

status_t fill_column_default_text(session_t *session, sql_stmt_t *stmt, knl_column_def_t *column,
                                  const TcDb__TseDDLColumnDef *def, ddl_ctrl_t *ddl_ctrl)
{
    // if default value is not number or generated by mysql functions, treat it as string
    bool is_default_str = !type_is_number(column->datatype) &&
                          !((tse_column_option_set_bit)def->is_option_set).is_default_func;
    int appendLen = is_default_str ? 3 : 1; // 3表示两个单引号和\0的长度
    char *format = is_default_str ? "'%s'" : "%s";
    if (sql_alloc_mem(stmt->context, strlen(def->default_text) + appendLen,
        (pointer_t *)&column->default_text.str) != GS_SUCCESS) {
        return GS_ERROR;
    }
    int ret = sprintf_s(column->default_text.str, strlen(def->default_text) + appendLen, format, def->default_text);
    column->default_text.len = strlen(column->default_text.str);
    knl_securec_check_ss(ret);
    ret = is_column_with_default_func(def, ddl_ctrl);
    if (ret != GS_SUCCESS) {
        return ret;
    }
    knl_column_t column_t = { 0 };
    char column_name[GS_NAME_BUFFER_SIZE] = { 0 };
    column_t.name = column_name;
    db_convert_column_def(&column_t, GS_INVALID_ID32, GS_INVALID_ID32, column, NULL, GS_INVALID_ID32);
    ret = g_knl_callback.verify_default_from_text(session, &column_t, column->default_text);
    if (ret != GS_SUCCESS) {
        char *message = NULL;
        cm_get_error(&(ddl_ctrl->error_code), (const char **)&message, NULL);
        GS_LOG_RUN_ERR("verify default expression failed! error_code:%d", ddl_ctrl->error_code);
        if (ddl_ctrl->error_code == 0 || message == NULL) {
            return ret;
        }
        knl_securec_check(strncpy_s(ddl_ctrl->error_msg, MAX_DDL_ERROR_MSG_LEN, message, strlen(message)));
        cm_reset_error();
        return ddl_ctrl->error_code;
    }
    
    return GS_SUCCESS;
}

status_t tse_fill_column_info(session_t *session, sql_stmt_t *stmt, knl_column_def_t *column,
                              const TcDb__TseDDLColumnDef *def, ddl_ctrl_t *ddl_ctrl)
{
    proto_str2text(def->name, &column->name);
    column->datatype = get_gs_type_from_tse_ddl_type(def->datatype->datatype);
    if (def->is_unsigned == 1) {
        if (column->datatype == GS_TYPE_INTEGER) {
            column->datatype = GS_TYPE_UINT32;
        } else if (column->datatype == GS_TYPE_BIGINT) {
            column->datatype = GS_TYPE_UINT64;
        }
    }

    if (column->datatype == GS_TYPE_REAL || column->datatype == GS_TYPE_DECIMAL || column->datatype == GS_TYPE_NUMBER3) {
        column->precision = def->datatype->precision;
        column->scale = def->datatype->scale;
    }
    column->size = def->datatype->size;
    column->is_option_set = def->is_option_set;
    if (column->is_default && def->default_text && !column->is_default_null) {
        int ret = fill_column_default_text(session, stmt, column, def, ddl_ctrl);
        if (ret != GS_SUCCESS) {
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
    }
    return GS_SUCCESS;
}

knl_refactor_t get_refactor_from_fk_def(TcDb__TseDDLForeignKeyDef *fk_def)
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

int fill_tse_create_fk_info(sql_stmt_t *stmt, TcDb__TseDDLCreateTableDef *req, knl_table_def_t *def)
{
    status_t status;
    if (req->n_fk_list == 0) {
        return 0;
    }
    for (int i = 0; i < req->n_fk_list; i++) {
        TcDb__TseDDLForeignKeyDef *fk_def = req->fk_list[i];
        knl_constraint_def_t *cons = NULL;
        status = cm_galist_new(&def->constraints, sizeof(knl_constraint_def_t), (pointer_t *)&cons);
        GS_RETURN_IFERR(status);
        cons->cons_state.is_enable = GS_TRUE;
        cons->cons_state.is_validate = GS_TRUE;
        cons->type = CONS_TYPE_REFERENCE;

        if (sql_alloc_mem(stmt->context, GS_NAME_BUFFER_SIZE, (pointer_t *)&cons->name.str) != GS_SUCCESS) {
            return GS_ERROR;
        }

        // 建表时无法获取 tableid，索引名在 db_create_table 中修改
        proto_str2text_ex(fk_def->name, &cons->name, GS_NAME_BUFFER_SIZE - 1);
        
        knl_reference_def_t *ref = &cons->ref;
        proto_str2text(fk_def->referenced_table_schema_name, &ref->ref_user);
        proto_str2text(fk_def->referenced_table_name, &ref->ref_table);
        ref->refactor = get_refactor_from_fk_def(fk_def);
        cm_galist_init(&ref->ref_columns, stmt->context, sql_alloc_mem);
        cm_galist_init(&cons->columns, stmt->context, sql_alloc_mem);
        for (int j = 0; j < fk_def->n_elements; j++) {
            TcDb__TseDDLForeignKeyElementDef *fk_ele = fk_def->elements[j];
            knl_index_col_def_t *src_column = NULL;
            status = cm_galist_new(&cons->columns, sizeof(knl_index_col_def_t), (void **)&src_column);
            GS_RETURN_IFERR(status);
            src_column->is_func = GS_FALSE;
            src_column->func_expr = NULL;
            src_column->func_text.len = 0;
            proto_str2text(fk_ele->src_column_name, &src_column->name);

            knl_index_col_def_t *ref_column = NULL;
            status = cm_galist_new(&ref->ref_columns, sizeof(knl_index_col_def_t), (void **)&ref_column);
            GS_RETURN_IFERR(status);
            ref_column->is_func = GS_FALSE;
            ref_column->func_expr = NULL;
            ref_column->func_text.len = 0;
            proto_str2text(fk_ele->ref_column_name, &ref_column->name);
        }
    }
    return GS_SUCCESS;
}

static status_t tse_ddl_fill_key_column(TcDb__TseDDLTableKeyPart *key_part, knl_index_col_def_t *key_column)
{
    proto_str2text(key_part->name, &key_column->name);
    key_column->datatype = get_gs_type_from_tse_ddl_type(key_part->datatype);
    key_column->size = key_part->length;
    key_column->is_func = key_part->is_func;
    if (key_column->is_func) {
        text_t func_name_text = {0};
        proto_str2text(key_part->func_name, &func_name_text);
        uint32 func_id = sql_get_func_id(&func_name_text);
        if (func_id == GS_INVALID_ID32) {
            GS_THROW_ERROR_EX(ERR_FUNCTION_NOT_EXIST, key_part->func_name);
            return GS_ERROR;
        }
        if (!g_func_tab[func_id].indexable) {
            GS_THROW_ERROR_EX(ERR_FUNCTION_NOT_INDEXABLE, key_part->func_name);
            return GS_ERROR;
        }
        proto_str2text(key_part->func_text, &key_column->func_text);
    }
    return GS_SUCCESS;
}

int fill_tse_create_key_info(sql_stmt_t *stmt, TcDb__TseDDLCreateTableDef *req, knl_table_def_t *def)
{
    status_t status;

    for (int i = 0; i < req->n_key_list; i++) {
        TcDb__TseDDLTableKey *ck_def = req->key_list[i];
        knl_index_def_t *index = NULL;
        knl_constraint_def_t *cons = NULL;

        if (ck_def->key_type == TSE_KEYTYPE_MULTIPLE) {
            status = cm_galist_new(&def->indexs, sizeof(knl_index_def_t), (pointer_t *)&index);
            GS_RETURN_IFERR(status);

            if (sql_alloc_mem(stmt->context, GS_NAME_BUFFER_SIZE, (pointer_t *)&index->name.str) != GS_SUCCESS) {
                return GS_ERROR;
            }

            // 建表时无法获取 tableid，索引名在 db_create_table 中修改
            proto_str2text_ex(ck_def->name, &index->name, GS_NAME_BUFFER_SIZE - 1);
            index->type = INDEX_TYPE_BTREE;
        } else {
            status = cm_galist_new(&def->constraints, sizeof(knl_constraint_def_t), (pointer_t *)&cons);
            GS_RETURN_IFERR(status);
            cons->cons_state.is_enable = GS_TRUE;
            cons->cons_state.is_validate = GS_TRUE;
            cons->cons_state.is_use_index = GS_TRUE;

            if (sql_alloc_mem(stmt->context, GS_NAME_BUFFER_SIZE, (pointer_t *)&cons->name.str) != GS_SUCCESS) {
                return GS_ERROR;
            }

            // 建表时无法获取 tableid，约束名在 db_create_table 中修改
            proto_str2text_ex(ck_def->name, &cons->name, GS_NAME_BUFFER_SIZE - 1);
            index = &cons->index;

            switch (ck_def->key_type) {
                case TSE_KEYTYPE_PRIMARY:
                    cons->type = CONS_TYPE_PRIMARY;
                    index->primary = GS_TRUE;
                    break;
                case TSE_KEYTYPE_FOREIGN:
                case TSE_KEYTYPE_UNIQUE:
                    cons->type = CONS_TYPE_UNIQUE;
                    index->unique = GS_TRUE;
                    break;
                default:
                    GS_LOG_RUN_ERR("fill_tse_create_key_info unknow key type:%d", ck_def->key_type);
                    return GS_ERROR;
            }
            cm_galist_init(&cons->columns, stmt->context, sql_alloc_mem);
        }
        index->parted = def->parted;
        index->is_for_create_db = GS_TRUE;
        if (index->parted) {
            index->initrans = GS_INI_TRANS;
            index->pctfree = GS_PCT_FREE;
            index->cr_mode = CR_PAGE;
        }
        index->is_func = ck_def->is_func;
        proto_str2text(ck_def->user, &index->user);   // 用户名
        proto_str2text(ck_def->table, &index->table); // 表名

        cm_galist_init(&index->columns, stmt->context, sql_alloc_mem);
        for (int j = 0; j < ck_def->n_columns; j++) {
            TcDb__TseDDLTableKeyPart *ck_key_part = ck_def->columns[j];
            knl_index_col_def_t *key_column = NULL;

            if (ck_def->key_type != TSE_KEYTYPE_MULTIPLE) {
                status = cm_galist_new(&cons->columns, sizeof(knl_index_col_def_t), (void **)&key_column);
                GS_RETURN_IFERR(status);
            } else {
                GS_RETURN_IFERR(cm_galist_new(&index->columns, sizeof(knl_index_col_def_t), (void **)&key_column));
            }
            GS_RETURN_IFERR(tse_ddl_fill_key_column(ck_key_part, key_column));
        }
    }
    return GS_SUCCESS;
}

part_type_t get_tse_part_type(uint32_t part_type)
{
    part_type_t tse_part_type = PART_TYPE_INVALID;
    switch (part_type) {
        case TSE_PART_TYPE_RANGE:
            tse_part_type = PART_TYPE_RANGE;
            break;
        case TSE_PART_TYPE_LIST:
            tse_part_type = PART_TYPE_LIST;
            break;
        case TSE_PART_TYPE_HASH:
            tse_part_type = PART_TYPE_HASH;
            break;
        default:
            GS_LOG_DEBUG_INF("get_tse_part_type invalid partition type : %d.", part_type);
            break;
    }
    return tse_part_type;
}

static status_t tse_partition_set_value(knl_part_column_def_t *key, char *part_value, variant_t *value)
{
    status_t ret = GS_SUCCESS;
    value->type = key->datatype;
    value->is_null = strlen(part_value) == 0;
    switch (value->type) {
        case GS_TYPE_INTEGER:
            value->v_int = atoi(part_value);
            break;
        case GS_TYPE_REAL:
            if (sscanf_s(part_value, "%lf", &value->v_real) <= 0) {
                GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "partition value %s is invalid.", part_value);
                ret = GS_ERROR;
            }
            break;
        case GS_TYPE_BIGINT:
            value->v_bigint = strtol(part_value, NULL, 10); // 10进制
            break;
        case GS_TYPE_UINT32:
            value->v_uint32 = strtoul(part_value, NULL, 10); // 10进制
            break;
        case GS_TYPE_UINT64:
            value->v_ubigint = strtoul(part_value, NULL, 10); // 10进制
            break;
        case GS_TYPE_CHAR:
        case GS_TYPE_STRING:
        case GS_TYPE_VARCHAR:
            proto_str2text(part_value, &value->v_text);
            break;
        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_TIMESTAMP_TZ_FAKE:
        case GS_TYPE_TIMESTAMP_LTZ:
        case GS_TYPE_DATE:
            value->type = GS_TYPE_CHAR;
            proto_str2text(part_value, &value->v_text);
            break;
        default:
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "datatype %d is not supported by partition.", value->type);
            ret = GS_ERROR;
            break;
    }
    return ret;
}

static status_t tse_sql_parse_list_partition(sql_stmt_t *stmt, knl_part_def_t *part_def,
    knl_part_obj_def_t *obj_def, TcDb__TseDDLPartitionTableDef *part_table_def)
{
    proto_str2text(part_table_def->name, &part_def->name);
    proto_str2text(part_table_def->hiboundval, &part_def->hiboundval);
    part_key_init(part_def->partkey, part_table_def->n_part_value_list);
    for (uint32_t i = 0; i < part_table_def->n_part_value_list; i += obj_def->part_keys.count) {
        part_key_t *curr_key = NULL;
        GS_RETURN_IFERR(sql_alloc_mem(stmt->context, GS_MAX_COLUMN_SIZE, (pointer_t *)&curr_key));
        part_key_init(curr_key, obj_def->part_keys.count);
        for (uint32 j = 0; j < obj_def->part_keys.count; j++) {
            knl_part_column_def_t *key = cm_galist_get(&obj_def->part_keys, j);
            variant_t value = {0};
            GS_RETURN_IFERR(tse_partition_set_value(key, part_table_def->part_value_list[i + j]->value, &value));
            GS_RETURN_IFERR(sql_part_put_key(stmt, &value, key->datatype, key->size, key->is_char, key->precision,
                                             key->scale, curr_key));
            GS_RETURN_IFERR(sql_part_put_key(stmt, &value, key->datatype, key->size, key->is_char, key->precision,
                                             key->scale, part_def->partkey));
        }
        GS_RETURN_IFERR(sql_list_store_define_key(curr_key, NULL, obj_def, &part_def->name));
    }
    return GS_SUCCESS;
}

static status_t tse_sql_parse_range_partition(sql_stmt_t *stmt, knl_part_def_t *part_def,
    knl_part_obj_def_t *obj_def, TcDb__TseDDLPartitionTableDef *part_table_def)
{
    proto_str2text(part_table_def->name, &part_def->name);
    proto_str2text(part_table_def->hiboundval, &part_def->hiboundval);
    variant_t value = {0};
    knl_part_column_def_t *key = NULL;

    part_key_init(part_def->partkey, obj_def->part_keys.count);

    for (uint32_t i = 0; i < obj_def->part_keys.count; i++) {
        if (part_table_def->part_value_list[i]->is_max_value) {
            part_put_max(part_def->partkey);
        } else {
            key = cm_galist_get(&obj_def->part_keys, i);
            GS_RETURN_IFERR(tse_partition_set_value(key, part_table_def->part_value_list[i]->value, &value));
            GS_RETURN_IFERR(sql_part_put_key(stmt, &value, key->datatype, key->size, key->is_char, key->precision,
                                             key->scale, part_def->partkey));
        }
    }
    
    int32 cmp_result;
    knl_part_def_t *prev_part = NULL;

    if (obj_def->parts.count >= PARTITION_MIN_CNT) {
        prev_part = cm_galist_get(&obj_def->parts, obj_def->parts.count - PARTITION_MIN_CNT);
        cmp_result = knl_compare_defined_key(&obj_def->part_keys, prev_part->partkey, part_def->partkey);
        if (cmp_result >= 0) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "partition %s boundary invalid", T2S(&part_def->name));
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t tse_sql_parse_hash_partition(sql_stmt_t *stmt, knl_part_def_t *part_def)
{
    int64 part_name_id;
    int errcode;
    char name_arr[GS_NAME_BUFFER_SIZE] = { '\0' };
    text_t part_name;
    GS_RETURN_IFERR(sql_alloc_object_id(stmt, &part_name_id));
    errcode = snprintf_s(name_arr, GS_NAME_BUFFER_SIZE, GS_NAME_BUFFER_SIZE - 1, "SYS_P%lld", part_name_id);
    PRTS_RETURN_IFERR(errcode);
    part_name.len = (uint32)strlen(name_arr);
    part_name.str = name_arr;
    GS_RETURN_IFERR(sql_copy_object_name(stmt->context, WORD_TYPE_STRING, &part_name, &part_def->name));
    return GS_SUCCESS;
}

status_t tse_sql_subpart_parse_partition(sql_stmt_t *stmt, knl_part_def_t *part_def, knl_part_obj_def_t *obj_def)
{
    knl_part_def_t *subpart_def = NULL;
    status_t status;
    part_def->is_parent = GS_TRUE;
    GS_RETURN_IFERR(cm_galist_new(&part_def->subparts, sizeof(knl_part_def_t), (pointer_t *)&subpart_def));
    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, GS_MAX_COLUMN_SIZE, (pointer_t *)&subpart_def->partkey));
 
    cm_galist_init(&subpart_def->value_list, stmt->context, sql_alloc_mem);
    cm_galist_init(&subpart_def->subparts, stmt->context, sql_alloc_mem);
    cm_galist_init(&subpart_def->group_subkeys, stmt->context, sql_alloc_mem);
 
    switch (obj_def->subpart_type) {
        case PART_TYPE_HASH:
            status = tse_sql_parse_hash_partition(stmt, subpart_def);
            break;
        default:
            status = GS_ERROR;
            break;
    }
    return status;
}
 
static status_t tse_sql_part_parse_partition(sql_stmt_t *stmt, knl_part_obj_def_t *obj_def,
                                             TcDb__TseDDLPartitionTableDef *part_table_def)
{
    knl_part_def_t *part_def = NULL;
    status_t status;

    GS_RETURN_IFERR(cm_galist_new(&obj_def->parts, sizeof(knl_part_def_t), (pointer_t *)&part_def));
    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, GS_MAX_COLUMN_SIZE, (pointer_t *)&part_def->partkey));

    cm_galist_init(&part_def->value_list, stmt->context, sql_alloc_mem);
    cm_galist_init(&part_def->subparts, stmt->context, sql_alloc_mem);
    cm_galist_init(&part_def->group_subkeys, stmt->context, sql_alloc_mem);
    part_def->exist_subparts = obj_def->is_composite ? GS_TRUE : GS_FALSE;

    switch (obj_def->part_type) {
        case PART_TYPE_LIST:
            status = tse_sql_parse_list_partition(stmt, part_def, obj_def, part_table_def);
            break;
        case PART_TYPE_RANGE:
            status = tse_sql_parse_range_partition(stmt, part_def, obj_def, part_table_def);
            break;
        case PART_TYPE_HASH:
            status = tse_sql_parse_hash_partition(stmt, part_def);
            break;
        default:
            return GS_ERROR;
    }

    if (obj_def->is_composite) {
        for (uint32_t i = 0; i < part_table_def->n_subpart_table_list; i++) {
            GS_RETURN_IFERR(tse_sql_subpart_parse_partition(stmt, part_def, obj_def));
        }
    }
    return status;
}

int fill_partition_column_info(text_t *column_name, knl_part_column_def_t *part_column, knl_table_def_t *def)
{
    status_t status;
    for (uint32 j = 0; j < def->columns.count; j++) {
        knl_column_def_t *column_def = cm_galist_get(&def->columns, j);
        if (!cm_text_equal(column_name, &column_def->name)) {
            continue;
        }

        part_column->column_id = j;
        status = sql_part_verify_key_type(&column_def->typmod);
        GS_RETURN_IFERR(status);
        part_column->datatype = column_def->typmod.datatype;

        if (column_def->typmod.size > GS_MAX_PART_COLUMN_SIZE) {
            GS_THROW_ERROR(ERR_MAX_PART_CLOUMN_SIZE, T2S(&column_def->name), GS_MAX_PART_COLUMN_SIZE);
            return GS_ERROR;
        }
        part_column->size = column_def->typmod.size;
        part_column->is_char = column_def->typmod.is_char;
        break;
    }

    if (part_column->column_id == GS_INVALID_ID32) {
        GS_LOG_RUN_ERR("fill_tse_partition_info invalid part_column_id : %u.", part_column->column_id);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

int fill_sub_partition_column_info(TcDb__TseDDLCreateTableDef *req, knl_part_obj_def_t *obj_def, knl_table_def_t *def)
{
    obj_def->is_composite = GS_TRUE;
    knl_part_column_def_t *subpart_column = NULL;
    for (uint32_t i = 0; i < req->partition_def->n_subpart_column_list; i++) {
        GS_RETURN_IFERR(cm_galist_new(&obj_def->subpart_keys, sizeof(knl_part_column_def_t),
                                      (pointer_t *)&subpart_column));
        subpart_column->column_id = GS_INVALID_ID32;
        text_t column_name;
        proto_str2text(req->partition_def->subpart_column_list[i]->name, &column_name);
        GS_RETURN_IFERR(fill_partition_column_info(&column_name, subpart_column, def));

        if (obj_def->subpart_keys.count > GS_MAX_PARTKEY_COLUMNS) {
            GS_LOG_RUN_ERR("fill_tse_partition_info invalid part_keys_count : %u.", obj_def->subpart_keys.count);
            return GS_ERROR;
        }
        for (uint32 j = 0; j < obj_def->subpart_keys.count - 1; j++) {
            knl_part_column_def_t *column_def = (knl_part_column_def_t *)cm_galist_get(&obj_def->subpart_keys, j);
            if (subpart_column->column_id == column_def->column_id) {
                GS_LOG_RUN_ERR("fill_tse_partition_info duplicate column name : %s.", column_name.str);
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

int fill_tse_partition_info(sql_stmt_t *stmt, TcDb__TseDDLCreateTableDef *req, knl_table_def_t *def)
{
    if (req->partition_def == NULL) {
        return 0;
    }
    def->parted = GS_TRUE;
    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_part_obj_def_t), (pointer_t *)&def->part_def));
    knl_part_obj_def_t *obj_def = def->part_def;
    obj_def->part_type = get_tse_part_type(req->partition_def->part_type);
    obj_def->subpart_type = get_tse_part_type(req->partition_def->subpart_type);
    obj_def->is_for_create_db = GS_TRUE;

    cm_galist_init(&obj_def->parts, stmt->context, sql_alloc_mem);
    cm_galist_init(&obj_def->part_keys, stmt->context, sql_alloc_mem);
    cm_galist_init(&obj_def->group_keys, stmt->context, sql_alloc_mem);
    cm_galist_init(&obj_def->part_store_in.space_list, stmt->context, sql_alloc_mem);
    cm_galist_init(&obj_def->subpart_store_in.space_list, stmt->context, sql_alloc_mem);
    cm_galist_init(&obj_def->subpart_keys, stmt->context, sql_alloc_mem);

    knl_part_column_def_t *part_column = NULL;
    for (uint32_t i = 0; i < req->partition_def->n_part_column_list; i++) {
        GS_RETURN_IFERR(cm_galist_new(&obj_def->part_keys, sizeof(knl_part_column_def_t), (pointer_t *)&part_column));
        part_column->column_id = GS_INVALID_ID32;
        text_t column_name;
        proto_str2text(req->partition_def->part_column_list[i]->name, &column_name);
        GS_RETURN_IFERR(fill_partition_column_info(&column_name, part_column, def));

        if (obj_def->part_keys.count > GS_MAX_PARTKEY_COLUMNS) {
            GS_LOG_RUN_ERR("fill_tse_partition_info invalid part_keys_count : %u.", obj_def->part_keys.count);
            return GS_ERROR;
        }
        for (uint32 j = 0; j < obj_def->part_keys.count - 1; j++) {
            knl_part_column_def_t *column_def = (knl_part_column_def_t *)cm_galist_get(&obj_def->part_keys, j);
            if (part_column->column_id == column_def->column_id) {
                GS_LOG_RUN_ERR("fill_tse_partition_info duplicate column name : %s.", column_name.str);
                return GS_ERROR;
            }
        }
    }

    if (obj_def->subpart_type != PART_TYPE_INVALID) {
        GS_RETURN_IFERR(fill_sub_partition_column_info(req, obj_def, def));
    }

    for (uint32_t i = 0; i < req->partition_def->n_part_table_list; i++) {
        GS_RETURN_IFERR(tse_sql_part_parse_partition(stmt, obj_def, req->partition_def->part_table_list[i]));
    }
    return GS_SUCCESS;
}

int fill_tse_alter_fk_info(sql_stmt_t *stmt, TcDb__TseDDLAlterTableDef *req, knl_altable_def_t *def)
{
    status_t status;

    knl_constraint_def_t *cons = &def->cons_def.new_cons;
    for (int i = 0; i < req->n_add_foreign_key_list; i++) {
        TcDb__TseDDLForeignKeyDef *fk_def = req->add_foreign_key_list[i];
        cons->cons_state.is_enable = GS_TRUE;
        cons->cons_state.is_validate = GS_TRUE;

        proto_str2text(fk_def->name, &cons->name);
        cons->type = CONS_TYPE_REFERENCE;
        knl_reference_def_t *ref = &cons->ref;
        proto_str2text(fk_def->referenced_table_schema_name, &ref->ref_user);
        proto_str2text(fk_def->referenced_table_name, &ref->ref_table);
        ref->refactor = get_refactor_from_fk_def(fk_def);
        cm_galist_init(&ref->ref_columns, stmt->context, sql_alloc_mem);
        cm_galist_init(&cons->columns, stmt->context, sql_alloc_mem);
        for (int j = 0; j < fk_def->n_elements; j++) {
            TcDb__TseDDLForeignKeyElementDef *fk_ele = fk_def->elements[j];
            knl_index_col_def_t *src_column = NULL;
            status = cm_galist_new(&cons->columns, sizeof(knl_index_col_def_t), (void **)&src_column);
            GS_RETURN_IFERR(status);
            src_column->is_func = GS_FALSE;
            src_column->func_expr = NULL;
            src_column->func_text.len = 0;
            proto_str2text(fk_ele->src_column_name, &src_column->name);

            knl_index_col_def_t *ref_column = NULL;
            status = cm_galist_new(&ref->ref_columns, sizeof(knl_index_col_def_t), (void **)&ref_column);
            GS_RETURN_IFERR(status);
            ref_column->is_func = GS_FALSE;
            ref_column->func_expr = NULL;
            ref_column->func_text.len = 0;
            proto_str2text(fk_ele->ref_column_name, &ref_column->name);
        }
    }
    return GS_SUCCESS;
}

static int tse_truncate_table_impl(TcDb__TseDDLTruncateTableDef *req, ddl_ctrl_t *ddl_ctrl)
{
    session_t *session = NULL;
    status_t status = get_and_init_session(&session, &(ddl_ctrl->tch), false);
    if (status != GS_SUCCESS) {
        return status;
    }

    knl_session_t *knl_session = &session->knl_session;
    knl_trunc_def_t *def = NULL;
    sql_stmt_t *stmt = session->current_stmt;
    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_trunc_def_t), (pointer_t *)&def));
    tse_put_ddl_sql_2_stmt(session, req->db_name, req->sql_str);
    stmt->context->type = SQL_TYPE_TRUNCATE_TABLE;
    stmt->context->entry = def;

    proto_str2text(req->schema, &def->owner);
    proto_str2text(req->name, &def->name);
    def->option = TRUNC_RECYCLE_STORAGE;
    def->no_need_check_fk = req->no_check_fk;
    status = knl_truncate_table(knl_session, stmt, def);
    if (status == GS_SUCCESS) {
        do_commit(stmt->session);
    } else {
        do_rollback(stmt->session, NULL);
        GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    }

    tse_ddl_clear_stmt(stmt);

    tse_ddl_broadcast_request broadcast_req = {0};
    FILL_BROADCAST_REQ(broadcast_req, req->db_name, req->sql_str, ddl_ctrl->user_name, ddl_ctrl->user_ip,
                       ddl_ctrl->mysql_inst_id, ddl_ctrl->tch.sql_command);
    int broadcat_ret = tse_execute_mysql_ddl_sql(&ddl_ctrl->tch, &broadcast_req, false);
    // 如果带有忽略参天错误的标志，需要同步忽略掉广播其他节点的报错
    return broadcat_ret;
}

int tse_truncate_table(void *table_def, ddl_ctrl_t *ddl_ctrl)
{
    TcDb__TseDDLTruncateTableDef *req = tc_db__tse_ddltruncate_table_def__unpack(NULL, ddl_ctrl->msg_len, table_def);
    int ret = tse_truncate_table_impl(req, ddl_ctrl);
    tc_db__tse_ddltruncate_table_def__free_unpacked(req, NULL);
    return ret;
}

/*
 * hash分区mysql会给分区取名为p0,p1,p2... 与参天命名不一致，因此需要根据part_id获取分区的分区名
 * list(columns)分区和range(columns)分区直接使用mysql传下来的分区名即可
 */
static status_t tse_get_partition_real_name(knl_session_t *session, uint32_t idx,
    TcDb__TseDDLTruncateTablePartitionDef *req, char *part_name, uint32_t part_name_len)
{
    knl_dictionary_t dc = {0};
    text_t user = {0};
    text_t table_name = {0};
    proto_str2text(req->user, &user);
    proto_str2text(req->table_name, &table_name);
    GS_RETURN_IFERR(dc_open(session, &user, &table_name, &dc));
    table_t *table = DC_TABLE(&dc);
    if (req->is_subpart) {
        if (table->part_table->desc.subparttype != PART_TYPE_HASH) {
            dc_close(&dc);
            GS_RETURN_IFERR(strcpy_s(part_name, part_name_len, req->subpartition_name[idx]));
            return GS_SUCCESS;
        }
        table_part_t *table_part = TABLE_GET_PART(table, req->partition_id[idx]);
        table_part_t *table_subpart = PART_GET_SUBENTITY(table->part_table,
            table_part->subparts[req->subpartition_id[idx]]);
        errno_t ret = strcpy_s(part_name, part_name_len, table_subpart->desc.name);
        if (ret != EOK) {
            GS_LOG_RUN_ERR("tse_get_subpartition_real_name: strcpy_s failed, ret = %d, len = %u, subpart_name = %s.",
                ret, part_name_len, table_subpart->desc.name);
            dc_close(&dc);
            return GS_ERROR;
        }
    } else {
        if (table->part_table->desc.parttype != PART_TYPE_HASH) {
            dc_close(&dc);
            GS_RETURN_IFERR(strcpy_s(part_name, part_name_len, req->partition_name[idx]));
            return GS_SUCCESS;
        }
        table_part_t *table_part = TABLE_GET_PART(table, req->partition_id[idx]);
        errno_t ret = strcpy_s(part_name, part_name_len, table_part->desc.name);
        if (ret != EOK) {
            GS_LOG_RUN_ERR("tse_get_partition_real_name: strcpy_s failed, ret = %d, len = %u, part_name = %s.",
                ret, part_name_len, table_part->desc.name);
            dc_close(&dc);
            return GS_ERROR;
        }
    }
    dc_close(&dc);
    return GS_SUCCESS;
}
static void tse_fill_common_truncate_partiton_def(knl_altable_def_t *def, TcDb__TseDDLTruncateTablePartitionDef *req,
    char *part_name)
{
    def->action = req->is_subpart ? ALTABLE_TRUNCATE_SUBPARTITION : ALTABLE_TRUNCATE_PARTITION;
    def->part_def.option = TRUNC_RECYCLE_STORAGE;
    def->is_for_create_db = GS_TRUE;
    proto_str2text(req->user, &def->user);
    proto_str2text(req->table_name, &def->name);
    proto_str2text(part_name, &def->part_def.name);
}

static int tse_truncate_partition_impl(TcDb__TseDDLTruncateTablePartitionDef *req, ddl_ctrl_t *ddl_ctrl)
{
    session_t *session = NULL;
    status_t status = get_and_init_session(&session, &(ddl_ctrl->tch), false);
    if (status != GS_SUCCESS) {
        return status;
    }
    knl_altable_def_t *def = NULL;
    sql_stmt_t *stmt = session->current_stmt;
    knl_altable_def_t *def_arrays = NULL;
    uint32_t n_defs_num = req->is_subpart ? req->n_subpartition_id : req->n_partition_id;
    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_altable_def_t) * n_defs_num, (pointer_t *)&def_arrays));
    tse_put_ddl_sql_2_stmt(session, req->db_name, req->sql_str);
    for (int i = 0; i < n_defs_num; i++) {
        def = &(def_arrays[i]);
        char *tmp_name = NULL;
        GS_RETURN_IFERR(sql_alloc_mem(stmt->context, GS_NAME_BUFFER_SIZE, (pointer_t *)&tmp_name));
        status = tse_get_partition_real_name(&stmt->session->knl_session, i, req, tmp_name, GS_NAME_BUFFER_SIZE);
        if (status != GS_SUCCESS) {
            GS_LOG_RUN_ERR("tse_truncate_partition: failed to get the (sub)partition name, ret = %d.", status);
            break;
        }
        tse_fill_common_truncate_partiton_def(def, req, tmp_name);
    }
    knl_dictionary_t dc;
    if (knl_open_dc(&session->knl_session, &(def_arrays->user), &(def_arrays->name), &dc) != GS_SUCCESS) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not find", T2S(&(def_arrays->name)));
        return GS_ERROR;
    }
    status = tse_alter_table_lock_table(&session->knl_session, &dc);
    if (status != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[TSE_LOCK_ALTER_TABLE]:alter table to lock table failed, ret:%d,"
                       "conn_id:%u, tse_instance_id:%u", (int)status, ddl_ctrl->tch.thd_id, ddl_ctrl->tch.inst_id);
        knl_close_dc(&dc);
        tse_alter_table_unlock(&session->knl_session);
        GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    }
    status = knl_alter_table4mysql(session, stmt, def_arrays, n_defs_num, &dc, true);
    if (status != GS_SUCCESS) {
        GS_LOG_RUN_ERR("tse_truncate_partition: faild to truncate partitions");
        knl_alter_table_rollback(&session->knl_session, &dc, true);
        knl_close_dc(&dc);
        tse_alter_table_unlock(&session->knl_session);
        GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    } else {
        knl_alter_table_commit(&session->knl_session, stmt, &dc, true);
        knl_close_dc(&dc);
        tse_alter_table_unlock(&session->knl_session);
    }
    tse_ddl_clear_stmt(stmt);

    tse_ddl_broadcast_request broadcast_req = {0};
    FILL_BROADCAST_REQ(broadcast_req, req->db_name, req->sql_str, ddl_ctrl->user_name, ddl_ctrl->user_ip,
                       ddl_ctrl->mysql_inst_id, ddl_ctrl->tch.sql_command);
    int broadcat_ret = tse_execute_mysql_ddl_sql(&ddl_ctrl->tch, &broadcast_req, false);
    return broadcat_ret;
}

int tse_truncate_partition(void *table_def, ddl_ctrl_t *ddl_ctrl)
{
    TcDb__TseDDLTruncateTablePartitionDef *req =
        tc_db__tse_ddltruncate_table_partition_def__unpack(NULL,
                                                           ddl_ctrl->msg_len - sizeof(ddl_ctrl_t),
                                                           table_def + sizeof(ddl_ctrl_t));
    int ret = tse_truncate_partition_impl(req, ddl_ctrl);
    tc_db__tse_ddltruncate_table_partition_def__free_unpacked(req, NULL);
    return ret;
}

int get_and_init_session(session_t **session, tianchi_handler_t *tch, bool alloc_if_null)
{
    status_t status;
    *session = tse_get_session_by_addr(tch->sess_addr);
    if (*session == NULL && alloc_if_null) {
        status = tse_get_new_session(session);
        if (status != GS_SUCCESS) {
            GS_LOG_RUN_ERR("alloc new session failed, thdid %u", tch->thd_id);
            return status;
        }
        (*session)->tse_inst_id = tch->inst_id;
        (*session)->tse_thd_id = tch->thd_id;
        (*session)->query_id = GS_INVALID_INT64;
        tch->sess_addr = (uint64)(*session);
        GS_LOG_DEBUG_INF("get_and_init_session alloc new session for thd_id=%u", tch->thd_id);
    }
    if (alloc_if_null == false && *session == NULL) {
        GS_LOG_RUN_ERR("get_and_init_session session is null thd_id=%u", tch->thd_id);
        CM_ASSERT(0);
        return GS_ERROR;
    }
    // 初始化knl_session stmt context逻辑
    status = init_ddl_session(*session);

    return status;
}

static status_t pre_check_drop_table_exist(TcDb__TseDDLCreateTableDef *req, session_t *session,
                                           sql_stmt_t *stmt, knl_table_def_t *def)
{
    // we might see staled table objects in cantian if previous create/alter ddl were rollback-ed.
    knl_dict_type_t obj_type;
    status_t status = GS_SUCCESS;
    if (dc_object_exists(session, &def->schema, &def->name, &obj_type)) {
        if (IS_TABLE_BY_TYPE(obj_type) && !(req->options & CREATE_IF_NOT_EXISTS)) {
            knl_drop_def_t drop_def = { { 0 } };
            drop_def.purge = GS_TRUE;
            GS_LOG_RUN_ERR("[pre_check_drop_table_exist]:The table %s is staled and will be dropped first.", req->name);
            if (cm_strcmpni(req->name, "#sql", strlen("#sql")) != 0) {
                CM_ASSERT(0);
            }
            proto_str2text(req->schema, &drop_def.owner);
            proto_str2text(req->name, &drop_def.name);
            status = knl_drop_table(&stmt->session->knl_session, stmt, &drop_def);
            if (status != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[pre_check_drop_table_exist]:drop the existing table failed.");
                return status;
            }
        }
    }
    return status;
}

static int tse_create_table_impl(TcDb__TseDDLCreateTableDef *req, ddl_ctrl_t *ddl_ctrl)
{
    session_t *session = NULL;
    status_t status = get_and_init_session(&session, &(ddl_ctrl->tch), false);
    if (status != GS_SUCCESS) {
        return status;
    }

    knl_session_t *knl_session = &session->knl_session;
    knl_table_def_t *def = NULL;
    sql_stmt_t *stmt = session->current_stmt;
    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_table_def_t), (pointer_t *)&def));
    tse_put_ddl_sql_2_stmt(session, req->db_name, req->sql_str);
    def->sysid = GS_INVALID_ID32;
    stmt->context->type = SQL_TYPE_CREATE_TABLE;
    stmt->context->entry = def;

    proto_str2text(req->schema, &def->schema);
    status = strncpy_s(stmt->session->curr_schema, GS_NAME_BUFFER_SIZE, def->schema.str, def->schema.len);
    GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    proto_str2text(req->name, &def->name);
    proto_str2text(req->space, &def->space);
    def->is_for_create_db = def->space.str == NULL ? GS_TRUE : GS_FALSE;

    // This function should be removed when table creation atomicity is implemented.
    GS_RETURN_IFERR(pre_check_drop_table_exist(req, session, stmt, def));

    cm_galist_init(&def->columns, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->constraints, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->indexs, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->lob_stores, stmt->context, sql_alloc_mem);
    for (int i = 0; i < req->n_columns; i++) {
        knl_column_def_t *column = NULL;
        status = cm_galist_new(&def->columns, sizeof(knl_column_def_t), (pointer_t *)&column);
        GS_RETURN_IFERR(status);
        column->table = (void *)def;
        cm_galist_init(&column->ref_columns, stmt->context, sql_alloc_mem);
        int ret = tse_fill_column_info(session, stmt, column, req->columns[i], ddl_ctrl);
        if (ret != GS_SUCCESS) {
            return ret;
        }

        if (column->primary) {
            def->pk_inline = GS_TRUE;
        }
        def->rf_inline = def->rf_inline || (column->is_ref);
        def->uq_inline = def->uq_inline || (column->unique);
        def->chk_inline = def->chk_inline || (column->is_check);
    }
    // 处理分区表逻辑
    cm_reset_error();
    status = fill_tse_partition_info(stmt, req, def);
    GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    // 处理外键逻辑
    status = fill_tse_create_fk_info(stmt, req, def);
    GS_RETURN_IFERR(status);
    // 处理创建索引逻辑
    cm_reset_error();
    status = fill_tse_create_key_info(stmt, req, def);
    GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    
    def->serial_start = req->auto_increment_value;
    def->options = req->options;
    // 逻辑抄自 sql_parse_create_table 用于创建索引等等
    // column type may be known after as-select parsed, so delay check partition table type
    // column type may be known after as-select parsed, so delay check default/default on update verifying
    GS_RETURN_IFERR(sql_delay_verify_default(stmt, def));

    // column type may be known after as-select parsed, so delay check constraint verifying
    GS_RETURN_IFERR(sql_verify_check_constraint(stmt, def));

    GS_RETURN_IFERR(sql_verify_cons_def(def));
    GS_RETURN_IFERR(sql_verify_auto_increment(stmt, def));
    GS_RETURN_IFERR(sql_verify_array_columns(def->type, &def->columns));
    cm_reset_error();
    // add logic from sql_parse_table_attrs
    if (def->initrans == 0) {
        def->initrans = GS_INI_TRANS;
    }

    if (def->pctfree == 0) {
        def->pctfree = GS_PCT_FREE;
    }
    def->cr_mode = CR_PAGE;

    status = knl_create_table(knl_session, stmt, def);
    GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    status = sql_try_import_rows(stmt, 0);
    if (status != GS_SUCCESS) {
        knl_rollback(&stmt->session->knl_session, NULL);
        knl_drop_def_t drop_def = {0};
        drop_def.purge = GS_TRUE;
        proto_str2text(req->schema, &drop_def.owner);
        proto_str2text(req->name, &drop_def.name);
        status = knl_drop_table(&stmt->session->knl_session, stmt, &drop_def);
    }
    if (status == GS_SUCCESS) {
        do_commit(stmt->session);
    } else {
        do_rollback(stmt->session, NULL);
        GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    }
    tse_ddl_clear_stmt(stmt);

    if (ddl_ctrl->is_alter_table) {
        return GS_SUCCESS;
    }

    tse_ddl_broadcast_request broadcast_req = {0};
    FILL_BROADCAST_REQ(broadcast_req, req->db_name, req->sql_str, ddl_ctrl->user_name, ddl_ctrl->user_ip,
                       ddl_ctrl->mysql_inst_id,
                       ddl_ctrl->tch.sql_command);  // create table不加锁，因此需要在广播结束后直接关掉mysql连接
    int broadcat_ret = tse_execute_mysql_ddl_sql(&ddl_ctrl->tch, &broadcast_req, false);
    // 如果带有忽略参天错误的标志，需要同步忽略掉广播其他节点的报错
    return broadcat_ret;
}

int tse_create_table(void *table_def, ddl_ctrl_t *ddl_ctrl)
{
    TcDb__TseDDLCreateTableDef *req = tc_db__tse_ddlcreate_table_def__unpack(NULL,
        ddl_ctrl->msg_len - sizeof(ddl_ctrl_t), (uint8_t*)((char*)table_def + sizeof(ddl_ctrl_t)));
    int ret = tse_create_table_impl(req, ddl_ctrl);
    tc_db__tse_ddlcreate_table_def__free_unpacked(req, NULL);
    return ret;
}

void fill_common_alter_def(sql_stmt_t *stmt, TcDb__TseDDLAlterTableDef *req, knl_altable_def_t *def)
{
    cm_galist_init(&def->column_defs, stmt->context, sql_alloc_mem);
    cm_galist_clean(&def->column_defs);
    proto_str2text(req->user, &def->user);
    proto_str2text(req->name, &def->name);
    def->index_def = NULL;
    def->alindex_def = NULL;
    def->drop_index_def = NULL;
    def->options = req->options;
    def->is_for_create_db = GS_TRUE;
}

static int tse_fill_drop_index_only(sql_stmt_t *stmt, TcDb__TseDDLAlterTableDef *req, int req_idx,
                                    knl_altable_def_t **alterdef_ptr)
{
    knl_altable_def_t *alter_def = *alterdef_ptr;
    int32_t key_type = req->drop_key_list[req_idx]->key_type;
    if (key_type == TSE_KEYTYPE_PRIMARY || key_type == TSE_KEYTYPE_UNIQUE) {
        // 通过drop constraint的形式才能删除，但是daac侧的constraint name需要查询系统表
        return GS_SUCCESS; // 后面通过drop constraint处理
    }
    fill_common_alter_def(stmt, req, alter_def);
    knl_drop_def_t *def = NULL;

    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_drop_def_t), (pointer_t *)&def));

    proto_str2text(req->user, &def->owner);   // 用户名
    proto_str2text(req->name, &def->ex_name); // 表名
    proto_str2text(req->drop_key_list[req_idx]->name, &(def->name));

    alter_def->drop_index_def = def;
    (*alterdef_ptr)++;

    return GS_SUCCESS;
}

static int tse_fill_add_index(sql_stmt_t *stmt, knl_altable_def_t **altable_def_ptr, TcDb__TseDDLAlterTableDef *req)
{
    for (int i = 0; i < req->n_add_key_list; ++i) {
        TcDb__TseDDLTableKey *alter_key = req->add_key_list[i];
        if (alter_key->is_constraint) {
            // 约束不在此接口中创建
            continue;
        }

        knl_index_def_t *def = NULL;
        knl_altable_def_t *altable_def = *altable_def_ptr;
        fill_common_alter_def(stmt, req, altable_def);

        GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_index_def_t), (pointer_t *)&def));

        proto_str2text(alter_key->user, &def->user);   // 用户名
        proto_str2text(alter_key->table, &def->table); // 表名

        alter_key->key_type = (alter_key->key_type == TSE_KEYTYPE_FOREIGN) ? TSE_KEYTYPE_MULTIPLE : alter_key->key_type;

        proto_str2text(alter_key->name, &def->name);
        def->type = INDEX_TYPE_BTREE; // 高斯db目前只支持这一种key
        def->is_func = alter_key->is_func;
        def->is_for_create_db = GS_TRUE;
        cm_galist_init(&def->columns, stmt->context, sql_alloc_mem);
        for (int j = 0; j < alter_key->n_columns; ++j) {
            knl_index_col_def_t *key_column = NULL;
            GS_RETURN_IFERR(cm_galist_new(&def->columns, sizeof(knl_index_col_def_t), (void **)&key_column));
            GS_RETURN_IFERR(tse_ddl_fill_key_column(alter_key->columns[j], key_column));
        }
        knl_dictionary_t dc;
        knl_handle_t knl = &stmt->session->knl_session;
        if (knl_open_dc(knl, (text_t *)&altable_def->user, (text_t *)&altable_def->name, &dc) != GS_SUCCESS) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not find", T2S(&altable_def->name));
            return GS_ERROR;
        }
        if (knl_is_part_table(dc.handle)) {
            def->parted = GS_TRUE;
            def->initrans = GS_INI_TRANS;
            def->pctfree = GS_PCT_FREE;
            def->cr_mode = CR_PAGE;
        }
        knl_close_dc(&dc);
        altable_def->index_def = def;
        (*altable_def_ptr)++;
    }
    return GS_SUCCESS;
}

static void tse_fill_constraint_defs(sql_stmt_t *stmt, knl_constraint_def_t *cons,
    text_t user_name, text_t table_name, tse_key_type cons_type)
{
    cons->type = (cons_type == TSE_KEYTYPE_UNIQUE) ? CONS_TYPE_UNIQUE : CONS_TYPE_PRIMARY;
    
    knl_index_def_t *index = &cons->index;
    index->user = user_name;
    index->table = table_name;
    index->name = cons->name;
    index->type = INDEX_TYPE_BTREE;
    index->unique = (cons_type == TSE_KEYTYPE_UNIQUE) ? GS_TRUE : GS_FALSE;
    index->primary = (cons_type == TSE_KEYTYPE_PRIMARY) ? GS_TRUE : GS_FALSE;
    index->parted = GS_FALSE;
    index->is_for_create_db = GS_TRUE;
}

static int tse_fill_add_constraint(knl_session_t *session, sql_stmt_t *stmt, knl_altable_def_t **def_ptr,
                                   TcDb__TseDDLAlterTableDef *req)
{
    status_t status;
    knl_dictionary_t dc;
    knl_handle_t knl = &stmt->session->knl_session;
    knl_altable_def_t *def = NULL;
    bool32 is_parted_index = 0;

    for (int i = 0; i < req->n_add_key_list; ++i) {
        TcDb__TseDDLTableKey *alter_key = req->add_key_list[i];

        if (!alter_key->is_constraint || alter_key->key_type == TSE_KEYTYPE_FOREIGN) {
            continue;
        }
        def = *def_ptr;
        fill_common_alter_def(stmt, req, def);
        if (i == 0) {
            if (knl_open_dc(knl, (text_t *)&def->user, (text_t *)&def->name, &dc) != GS_SUCCESS) {
                GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not find", T2S(&def->name));
                return GS_ERROR;
            }
            is_parted_index = knl_is_part_table(dc.handle);
            knl_close_dc(&dc);
        }
        def->action = ALTABLE_ADD_CONSTRAINT;
        knl_constraint_def_t *cons = &def->cons_def.new_cons;

        cons->cons_state.is_enable = GS_TRUE;
        cons->cons_state.is_validate = GS_TRUE;
        cons->cons_state.is_use_index = GS_TRUE;

        if (sql_alloc_mem(stmt->context, GS_NAME_BUFFER_SIZE, (pointer_t *)&def->cons_def.name.str) != GS_SUCCESS) {
            return GS_ERROR;
        }

        proto_str2text(alter_key->name, &cons->name);

        tse_fill_constraint_defs(stmt, cons, def->user, def->name, alter_key->key_type);
        knl_index_def_t *index = &cons->index;
        index->name = cons->name;
        index->parted = is_parted_index;
        if (index->parted) {
            index->initrans = GS_INI_TRANS;
            index->pctfree = GS_PCT_FREE;
            index->cr_mode = CR_PAGE;
            index->unique = GS_TRUE;
            index->primary = GS_FALSE;
        }
        cm_galist_init(&cons->columns, stmt->context, sql_alloc_mem);
        for (int j = 0; j < alter_key->n_columns; j++) {
            TcDb__TseDDLTableKeyPart *ck_key_part = alter_key->columns[j];
            knl_index_col_def_t *key_column_cond = NULL;
            status = cm_galist_new(&cons->columns, sizeof(knl_index_col_def_t), (void **)&key_column_cond);
            GS_RETURN_IFERR(status);
            GS_RETURN_IFERR(tse_ddl_fill_key_column(ck_key_part, key_column_cond));
        }
        (*def_ptr)++;
    }

    return GS_SUCCESS;
}

static int tse_fill_drop_constraint(sql_stmt_t *stmt, knl_altable_def_t **def_ptr,
    TcDb__TseDDLAlterTableDef *req, int req_idx)
{
    knl_altable_def_t *def = *def_ptr;
    fill_common_alter_def(stmt, req, def);
    TcDb__TseDDLAlterTableDrop *alter = req->drop_list[req_idx];
    knl_constraint_def_t *cons = &def->cons_def.new_cons;

    proto_str2text(alter->name, &def->cons_def.name);

    if (alter->key_type == TSE_KEYTYPE_FOREIGN) {
        cons->type = CONS_TYPE_REFERENCE;
    }

    def->action = ALTABLE_DROP_CONSTRAINT;
    def->is_for_create_db = GS_TRUE;

    (*def_ptr)++;

    return GS_SUCCESS;
}

static int tse_fill_drop_index_constraint(sql_stmt_t *stmt, knl_altable_def_t **def_ptr,
    TcDb__TseDDLAlterTableDef *req, int req_idx)
{
    knl_altable_def_t *def = *def_ptr;
    fill_common_alter_def(stmt, req, def);
    TcDb__TseDDLAlterTableDropKey *alter = req->drop_key_list[req_idx];
    knl_constraint_def_t *cons = &def->cons_def.new_cons;

    proto_str2text(alter->name, &def->cons_def.name);
    def->action = ALTABLE_DROP_CONSTRAINT;
    def->is_for_create_db = GS_TRUE;

    (*def_ptr)++;

    return GS_SUCCESS;
}

static int tse_fill_drop_index(sql_stmt_t *stmt, knl_altable_def_t **def_ptr, TcDb__TseDDLAlterTableDef *req)
{
    status_t status = GS_SUCCESS;
    for (int i = 0; i < req->n_drop_key_list; ++i) {
        knl_panic(req->drop_key_list[i]->drop_type == TSE_ALTER_TABLE_DROP_KEY);

        if ((req->drop_key_list[i]->key_type == TSE_KEYTYPE_PRIMARY ||
            req->drop_key_list[i]->key_type == TSE_KEYTYPE_UNIQUE ||
            req->drop_key_list[i]->key_type == TSE_KEYTYPE_FOREIGN)) {
            status = tse_fill_drop_index_constraint(stmt, def_ptr, req, i);
        } else {
            status = tse_fill_drop_index_only(stmt, req, i, def_ptr);
        }
    }
    return status;
}

static int tse_fill_drop_column(sql_stmt_t *stmt, knl_altable_def_t **def_ptr, TcDb__TseDDLAlterTableDef *req)
{
    status_t status = GS_SUCCESS;
    for (int i = 0; i < req->n_drop_list; ++i) {
        bool alter_drop = false;
        knl_alt_column_prop_t *column_def = NULL;
        knl_altable_def_t *def = *def_ptr;
        fill_common_alter_def(stmt, req, def);
        GS_RETURN_IFERR(cm_galist_new(&def->column_defs, sizeof(knl_alt_column_prop_t), (void **)&column_def));
        switch (req->drop_list[i]->drop_type) {
            case TSE_ALTER_TABLE_DROP_COLUMN:
                def->action = ALTABLE_DROP_COLUMN;
                proto_str2text(req->drop_list[i]->name, &column_def->name);
                alter_drop = true;
                break;
            case TSE_ALTER_TABLE_DROP_ANY_CONSTRAINT:
            case TSE_ALTER_TABLE_DROP_CHECK_CONSTRAINT:
                break;
            case TSE_ALTER_TABLE_DROP_FOREIGN_KEY:
                status = tse_fill_drop_constraint(stmt, def_ptr, req, i);
                break;
            case TSE_ALTER_TABLE_DROP_KEY:
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

    return GS_SUCCESS;
}

static int tse_fill_rename_and_set_column_default(session_t *session, sql_stmt_t *stmt, knl_altable_def_t **def_ptr,
                                                  TcDb__TseDDLAlterTableDef *req, bool *rename_column_flag,
                                                  ddl_ctrl_t *ddl_ctrl)
{
    int err_code;
    for (int i = 0; i < req->n_alter_list; ++i) {
        knl_altable_def_t *def = *def_ptr;
        fill_common_alter_def(stmt, req, def);
        tse_column_option_set_bit option_set;
        option_set.is_option_set = 0;
        knl_column_def_t *column = NULL;
        knl_alt_column_prop_t *column_def = NULL;
        GS_RETURN_IFERR(cm_galist_new(&def->column_defs, sizeof(knl_alt_column_prop_t), (void **)&column_def));
        option_set.is_option_set = column_def->new_column.is_option_set;

        for (int j = 0; j < req->n_create_list; ++j) {
            if (req->create_list[j]->name != NULL && strcmp(req->alter_list[i]->name, req->create_list[j]->name) == 0) {
                column = &column_def->new_column;
                column->table = (void *)def;
                err_code = tse_fill_column_info(session, stmt, column, req->create_list[j], ddl_ctrl);
                break;
            }
        }
        if (err_code != GS_SUCCESS) {
            return err_code;
        }

        proto_str2text(req->alter_list[i]->name, &column_def->name);
        switch (req->alter_list[i]->type) {
            case TSE_ALTER_COLUMN_SET_DEFAULT:
                def->action = ALTABLE_MODIFY_COLUMN;
                option_set.is_default = 1;

                if (req->alter_list[i]->is_default_null) {
                    option_set.is_default_null = 1;
                    option_set.nullable = 1;
                } else {
                    proto_str2text(req->alter_list[i]->default_text, &column_def->new_column.default_text);
                }
                break;
            case TSE_ALTER_COLUMN_DROP_DEFAULT:
                def->action = ALTABLE_MODIFY_COLUMN;
                option_set.is_default = 0;
                break;
            case TSE_ALTER_COLUMN_RENAME_COLUMN:
                *rename_column_flag = true;
                def->action = ALTABLE_RENAME_COLUMN;
                proto_str2text(req->alter_list[i]->new_name, &column_def->new_name);
                break;
            case TSE_ALTER_COLUMN_SET_COLUMN_VISIBLE:
            case TSE_ALTER_COLUMN_SET_COLUMN_INVISIBLE:
                // 设置列invisible or visible, cantian不需要执行任何操作
                continue;
            default:
                break;
        }

        column_def->new_column.is_option_set = option_set.is_option_set;
        (*def_ptr)++;
    }

    return GS_SUCCESS;
}

static int tse_fill_add_column(session_t *session, sql_stmt_t *stmt, knl_altable_def_t **def_ptr,
                               TcDb__TseDDLAlterTableDef *req, ddl_ctrl_t *ddl_ctrl)
{
    int add_column_cnt = 0;
    knl_altable_def_t *def = *def_ptr;
    for (int i = 0; i < req->n_create_list; ++i) {
        if (req->create_list[i]->alter_mode != TSE_ALTER_COLUMN_ALTER_ADD_COLUMN) {
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
        GS_RETURN_IFERR(cm_galist_new(&def->column_defs, sizeof(knl_alt_column_prop_t), (void **)&column_def));
        column = &column_def->new_column;
        column->table = (void *)def;
        int ret = tse_fill_column_info(session, stmt, column, req->create_list[i], ddl_ctrl);
        if (ret != GS_SUCCESS) {
            return ret;
        }

        tse_column_option_set_bit op_bitmap = (tse_column_option_set_bit)req->create_list[i]->is_option_set;
        if (op_bitmap.unique || op_bitmap.primary) {
            knl_constraint_def_t *cons = NULL;
            char *tse_cons_name = req->create_list[i]->cons_name;
            cm_galist_init(&column_def->constraints, stmt->context, sql_alloc_mem);
            GS_RETURN_IFERR(cm_galist_new(&column_def->constraints, sizeof(knl_constraint_def_t), (pointer_t *)&cons));
            
            cm_galist_init(&cons->columns, stmt->context, sql_alloc_mem);
            knl_index_col_def_t *key_column_cond = NULL;
            GS_RETURN_IFERR(cm_galist_new(&cons->columns, sizeof(knl_index_col_def_t), (void **)&key_column_cond));
            key_column_cond->name = column->name;
            key_column_cond->size = column->size;
            tse_key_type cons_type = (op_bitmap.unique) ? TSE_KEYTYPE_UNIQUE : TSE_KEYTYPE_PRIMARY;

            if (tse_cons_name == NULL) {
                return GS_ERROR;
            }
            proto_str2text(tse_cons_name, &cons->name);
            tse_fill_constraint_defs(stmt, cons, def->user, def->name, cons_type);
        }
    }

    if (add_column_cnt > 0) {
        (*def_ptr)++; // 多个add column可以只下发一次knl
    }

    return GS_SUCCESS;
}

static int tse_fill_modify_column(session_t *session, sql_stmt_t *stmt, knl_altable_def_t **def_ptr,
                                  TcDb__TseDDLAlterTableDef *req, bool rename_column_flag, ddl_ctrl_t *ddl_ctrl)
{
    for (int i = 0; i < req->n_create_list; ++i) {
        if (req->create_list[i]->alter_mode != TSE_ALTER_COLUMN_ALTER_MODIFY_COLUMN ||
            (rename_column_flag && strlen(req->create_list[i]->new_name))) {
            continue;
        }
        knl_altable_def_t *def = *def_ptr;
        fill_common_alter_def(stmt, req, def);
        def->action = ALTABLE_MODIFY_COLUMN;

        knl_column_def_t *column = NULL;
        knl_alt_column_prop_t *column_def = NULL;
        GS_RETURN_IFERR(cm_galist_new(&def->column_defs, sizeof(knl_alt_column_prop_t), (void **)&column_def));
        column = &column_def->new_column;
        column->table = (void *)def;
        column->is_option_set = req->create_list[i]->is_option_set;
        proto_str2text(req->create_list[i]->name, &column_def->name);
        int ret = tse_fill_column_info(session, stmt, column, req->create_list[i], ddl_ctrl);
        if (ret != GS_SUCCESS) {
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

            GS_RETURN_IFERR(cm_galist_new(&def->column_defs, sizeof(knl_alt_column_prop_t), (void **)&column_def));
            proto_str2text(req->create_list[i]->new_name, &column_def->new_name);
            proto_str2text(req->create_list[i]->name, &column_def->name);
            (*def_ptr)++;
        }
    }

    return GS_SUCCESS;
}

static int tse_fill_rename_constraint(knl_handle_t *session, sql_stmt_t *stmt, knl_altable_def_t *def,
    char *cons_old_name, char *cons_new_name)
{
    knl_constraint_def_t *cons = &def->cons_def.new_cons;

    proto_str2text(cons_old_name, &def->cons_def.name);
    proto_str2text(cons_new_name, &def->cons_def.new_cons.name);

    def->action = ALTABLE_RENAME_CONSTRAINT;
    def->is_for_create_db = GS_TRUE;
    return GS_SUCCESS;
}

static int tse_fill_alter_index(knl_handle_t *session, sql_stmt_t *stmt, knl_altable_def_t **altable_def_ptr,
                                sql_type_t type, TcDb__TseDDLAlterTableDef *req)
{
    status_t status;
    for (int i = 0; i < req->n_alter_index_list; ++i) {
        TcDb__TseDDLAlterIndexDef *index = req->alter_index_list[i];

        knl_alindex_def_t *def = NULL;
        knl_altable_def_t *altable_def = *altable_def_ptr;
        fill_common_alter_def(stmt, req, altable_def);

        GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_alindex_def_t), (pointer_t *)&def));
        proto_str2text(index->user, &def->user);   // 用户名
        proto_str2text(index->table, &def->table); // 表名
        proto_str2text(index->name, &def->name);
        def->is_for_create_db = GS_TRUE;

        if (index->new_name != NULL) { // rename index
            def->type = ALINDEX_TYPE_RENAME;
            proto_str2text(index->new_name, &def->idx_def.new_name);
        }

        altable_def->alindex_def = def;
        (*altable_def_ptr)++;

        if ((index->key_type == TSE_KEYTYPE_PRIMARY || index->key_type == TSE_KEYTYPE_UNIQUE) &&
            index->new_name != NULL) {
            // 因为primary key和unique key二者的constraint name和index name一致，所以需要也修改constraint name
            altable_def = *altable_def_ptr;
            fill_common_alter_def(stmt, req, altable_def);
            status = tse_fill_rename_constraint(session, stmt, altable_def, index->name, index->new_name);
            (*altable_def_ptr)++;
            if (status != GS_SUCCESS) {
                return status;
            }
        }
    }

    // stmt->context->type = type;
    // stmt->context->entry = altable_def;

    return GS_SUCCESS;
}

static int tse_fill_add_foreign_key(sql_stmt_t *stmt, knl_altable_def_t **def_ptr,
    TcDb__TseDDLAlterTableDef *req)
{
    status_t status = GS_SUCCESS;
    if (req->n_add_foreign_key_list > 0) {
        knl_altable_def_t *def = *def_ptr;
        fill_common_alter_def(stmt, req, def);
        status = fill_tse_alter_fk_info(stmt, req, def);
        if (status != GS_SUCCESS) {
            return status;
        }
        def->action = ALTABLE_ADD_CONSTRAINT;
        (*def_ptr)++;
    }

    return status;
}

static int tse_fill_drop_partition(sql_stmt_t *stmt, knl_altable_def_t **def_ptr,
    TcDb__TseDDLAlterTableDef *req)
{
    for (uint32_t i = 0; i < req->n_drop_partition_names; i++) {
        knl_altable_def_t *def = *def_ptr;
        fill_common_alter_def(stmt, req, def);
        proto_str2text(req->drop_partition_names[i], &def->part_def.name); // 删除分区 只能一个一个删除
        def->action = ALTABLE_DROP_PARTITION;

        (*def_ptr)++;
    }

    return GS_SUCCESS;
}

static int tse_fill_coalesce_partition(sql_stmt_t *stmt, knl_altable_def_t **def_ptr,
    TcDb__TseDDLAlterTableDef *req)
{
    if (req->hash_coalesce_count <= 0) {
        return GS_SUCCESS;
    }

    for (uint32_t i = 0; i < req->hash_coalesce_count; i++) {
        knl_altable_def_t *def = *def_ptr;
        fill_common_alter_def(stmt, req, def);
        def->action = ALTABLE_COALESCE_PARTITION;
        (*def_ptr)++;
    }

    return GS_SUCCESS;
}

int fill_alter_part_key(knl_dictionary_t dc, knl_altable_def_t *def, knl_column_t *knl_column)
{
    knl_part_column_def_t *part_column = NULL;
    for (uint16 i = 0; i < knl_part_key_count(dc.handle); i++) {
        if (cm_galist_new(&def->part_def.obj_def->part_keys, sizeof(knl_part_column_def_t),
            (pointer_t *)&part_column) != GS_SUCCESS) {
            knl_close_dc(&dc);
            return GS_ERROR;
        }
        part_column->column_id = knl_part_key_column_id(dc.handle, i);
        knl_column = knl_get_column(dc.handle, part_column->column_id);
        part_column->datatype = knl_column->datatype;
        part_column->size = knl_column->size;
    }
    return GS_SUCCESS;
}

int fill_alter_subpart_key(knl_dictionary_t dc, knl_altable_def_t *def, knl_column_t *knl_column)
{
    knl_part_column_def_t *subpart_column = NULL;
    for (uint16 i = 0; i < knl_subpart_key_count(dc.handle); i++) {
        if (cm_galist_new(&def->part_def.obj_def->subpart_keys, sizeof(knl_part_column_def_t),
            (pointer_t *)&subpart_column) != GS_SUCCESS) {
            knl_close_dc(&dc);
            return GS_ERROR;
        }
        subpart_column->column_id = knl_subpart_key_column_id(dc.handle, i);
        knl_column = knl_get_column(dc.handle, subpart_column->column_id);
        subpart_column->datatype = knl_column->datatype;
        subpart_column->size = knl_column->size;
    }
    return GS_SUCCESS;
}

static int tse_fill_add_partition(sql_stmt_t *stmt, knl_altable_def_t **def_ptr,
    TcDb__TseDDLAlterTableDef *req)
{
    knl_column_t *knl_column = NULL;
    knl_dictionary_t dc;
    knl_part_column_def_t *part_column = NULL;
    knl_handle_t knl = &stmt->session->knl_session;

    for (uint32_t idx = 0; idx < req->n_add_part_list; idx++) {
        knl_altable_def_t *def = *def_ptr;
        fill_common_alter_def(stmt, req, def);

        if (knl_open_dc(knl, (text_t *)&def->user, (text_t *)&def->name, &dc) != GS_SUCCESS) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not find", T2S(&def->name));
            return GS_ERROR;
        }

        if (!knl_is_part_table(dc.handle)) {
            knl_close_dc(&dc);
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not partition table", T2S(&def->name));
            return GS_ERROR;
        }

        if (sql_alloc_mem(stmt->context, sizeof(knl_part_obj_def_t),
            (pointer_t *)&def->part_def.obj_def) != GS_SUCCESS) {
            knl_close_dc(&dc);
            return GS_ERROR;
        }

        def->part_def.obj_def->part_type = knl_part_table_type(dc.handle);
        def->part_def.obj_def->subpart_type = knl_subpart_table_type(dc.handle);
        if (def->part_def.obj_def->subpart_type != PART_TYPE_INVALID) {
            def->part_def.obj_def->is_composite = GS_TRUE;
        }
        cm_galist_init(&def->part_def.obj_def->parts, stmt->context, sql_alloc_mem);
        cm_galist_init(&def->part_def.obj_def->part_keys, stmt->context, sql_alloc_mem);
        cm_galist_init(&def->part_def.obj_def->group_keys, stmt->context, sql_alloc_mem);
        cm_galist_init(&def->part_def.obj_def->part_store_in.space_list, stmt->context, sql_alloc_mem);
        cm_galist_init(&def->part_def.obj_def->subpart_store_in.space_list, stmt->context, sql_alloc_mem);
        cm_galist_init(&def->part_def.obj_def->subpart_keys, stmt->context, sql_alloc_mem);

        GS_RETURN_IFERR(fill_alter_part_key(dc, def, knl_column));
        if (def->part_def.obj_def->is_composite) {
            GS_RETURN_IFERR(fill_alter_subpart_key(dc, def, knl_column));
        }
        cm_galist_init(&def->part_def.obj_def->parts, stmt->context, sql_alloc_mem);
        if (tse_sql_part_parse_partition(stmt, def->part_def.obj_def, req->add_part_list[idx]) != GS_SUCCESS) {
            knl_close_dc(&dc);
            return GS_ERROR;
        }

        knl_close_dc(&dc);
        def->action = ALTABLE_ADD_PARTITION;
        (*def_ptr)++;
    }

    return GS_SUCCESS;
}

// 处理分区表功能
int fill_handler_partition_table(sql_stmt_t *stmt, knl_altable_def_t **def_ptr, TcDb__TseDDLAlterTableDef *req)
{
    status_t status;
    // 删除分区
    status = tse_fill_drop_partition(stmt, def_ptr, req);
    GS_RETURN_IFERR(status);

    // 增加分区
    status = tse_fill_add_partition(stmt, def_ptr, req);
    GS_RETURN_IFERR(status);

    // hash分区coalesce
    status = tse_fill_coalesce_partition(stmt, def_ptr, req);
    GS_RETURN_IFERR(status);
    return status;
}

static void tse_fill_modify_auto_inc_value(sql_stmt_t *stmt, knl_altable_def_t **def_ptr,
    TcDb__TseDDLAlterTableDef *req)
{
    knl_altable_def_t *def = *def_ptr;
    fill_common_alter_def(stmt, req, def);
    def->action = ALTABLE_AUTO_INCREMENT;
    def->table_def.serial_start = req->new_auto_increment_value;

    (*def_ptr)++;
}

size_t tse_get_add_or_modify_column_ops(TcDb__TseDDLAlterTableDef *req)
{
    int count = 0;
    bool has_add_column = false; // just one def fills added multi column_defs in add column
    for (int i = 0; i < req->n_create_list; ++i) {
        if (req->create_list[i]->alter_mode == TSE_ALTER_COLUMN_ALTER_ADD_COLUMN) {
            has_add_column = true;
        }
        if (req->create_list[i]->alter_mode == TSE_ALTER_COLUMN_ALTER_MODIFY_COLUMN) {
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

size_t tse_get_alter_index_ops(TcDb__TseDDLAlterTableDef *req)
{
    int count = 0;
    for (int i = 0; i < req->n_alter_index_list; ++i) {
        TcDb__TseDDLAlterIndexDef *index = req->alter_index_list[i];
        count++;
        if ((index->key_type == TSE_KEYTYPE_PRIMARY || index->key_type == TSE_KEYTYPE_UNIQUE) &&
            index->new_name != NULL) {
            count++;
        }
    }
    return count;
}

static int tse_alter_table_atomic_impl(TcDb__TseDDLAlterTableDef *req, ddl_ctrl_t *ddl_ctrl)
{
    session_t *session = NULL;
    knl_altable_def_t *def = NULL;
    sql_stmt_t *stmt = NULL;
    knl_dictionary_t *dc = NULL;
    knl_altable_def_t *start_def = NULL;
    size_t alter_op_max_nums = 0;
    size_t add_or_modify_ops = 0;
    bool rename_column_flag = false;
    uint32_t user_len = (req->user == NULL ? 0 : strlen(req->user));
    status_t status = get_and_init_session(&session, &(ddl_ctrl->tch), false);
    if (status != GS_SUCCESS) {
        return status;
    }

    stmt = session->current_stmt;
    stmt->session->call_version = CS_VERSION_8;
    stmt->v_systimestamp = req->systimestamp;
    stmt->tz_offset_utc = req->tz_offset_utc + TIMEZONE_OFFSET_DEFAULT;
    stmt->context->type = SQL_TYPE_ALTER_TABLE;

    // 提前计算增列和改列操作数，代替使用n_create_list造成列数过多，分配不出最大的def内存
    add_or_modify_ops = tse_get_add_or_modify_column_ops(req);
    MEMS_RETURN_IFERR(strncpy_s(stmt->session->curr_schema, GS_NAME_BUFFER_SIZE, req->user, user_len));

    alter_op_max_nums = req->n_drop_list + req->n_alter_list + add_or_modify_ops + req->n_add_key_list +
                        req->n_drop_key_list + req->n_add_foreign_key_list + tse_get_alter_index_ops(req) +
                        req->n_drop_partition_names + req->n_add_part_list + req->hash_coalesce_count +
                        (req->new_auto_increment_value ? 1 : 0);
    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_altable_def_t) * alter_op_max_nums, (pointer_t *)&def));
    start_def = def;
    stmt->context->entry = start_def; // def值会变化，后面会逐个往后偏移knl_altable_def_t大小

    tse_put_ddl_sql_2_stmt(session, req->db_name, req->sql_str);

    sql_copy_str(stmt->context, req->user, &def->user);
    sql_copy_str(stmt->context, req->name, &def->name);
    GS_RETURN_IFERR(sql_regist_ddl_table(stmt, &def->user, &def->name));

    status = tse_fill_rename_and_set_column_default(session, stmt, &def, req, &rename_column_flag, ddl_ctrl);
    GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);

    // 修改索引名
    status = tse_fill_alter_index((knl_handle_t)(&session->knl_session), stmt, &def,
                                  SQL_TYPE_ALTER_TABLE, req);
    GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);

    status = tse_fill_drop_index(stmt, &def, req);
    GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);

    status = tse_fill_modify_column(session, stmt, &def, req, rename_column_flag, ddl_ctrl);
    GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);

    status = tse_fill_add_column(session, stmt, &def, req, ddl_ctrl);
    GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);

    status = tse_fill_drop_column(stmt, &def, req);
    GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);

    status = tse_fill_add_foreign_key(stmt, &def, req);
    GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);

    status = tse_fill_add_index(stmt, &def, req);
    GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);

    // 增加primary key，unique key
    status = tse_fill_add_constraint(session, stmt, &def, req);
    GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);

    if (req->new_auto_increment_value) {
        tse_fill_modify_auto_inc_value(stmt, &def, req);
    }

    status = fill_handler_partition_table(stmt, &def, req);
    GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);

    uint32 def_count = ((uint64)def - (uint64)start_def) / sizeof(knl_altable_def_t);
    tse_context_t *tse_context = tse_get_ctx_by_addr(ddl_ctrl->tch.ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    status = tse_alter_table_lock_table(&(session->knl_session), tse_context->dc);
    if (status != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[TSE_LOCK_ALTER_TABLE]:alter table to lock table failed, ret:%d,"
                       "conn_id:%u, tse_instance_id:%u", (int)status, ddl_ctrl->tch.thd_id, ddl_ctrl->tch.inst_id);
    }
    GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);

    status = knl_alter_table4mysql(session, stmt, start_def, def_count, tse_context->dc, true);
    if (status != GS_SUCCESS) {
        char *message = NULL;
        cm_get_error(&(ddl_ctrl->error_code), (const char **)&message, NULL);
        GS_LOG_RUN_ERR("knl_alter_table4mysql FAILED! error_code:%d, message:%s",
                        ddl_ctrl->error_code, message == NULL ? "" : message);
        if (ddl_ctrl->error_code == 0 || message == NULL) {
            return status;
        }
        knl_securec_check(strncpy_s(ddl_ctrl->error_msg, MAX_DDL_ERROR_MSG_LEN, message, strlen(message)));
        cm_reset_error();
        return ddl_ctrl->error_code;
    }
    cm_reset_error();
    return GS_SUCCESS;
}

int tse_alter_table(void *alter_def, ddl_ctrl_t *ddl_ctrl)
{
    TcDb__TseDDLAlterTableDef *req = tc_db__tse_ddlalter_table_def__unpack(NULL,
        ddl_ctrl->msg_len - sizeof(ddl_ctrl_t), (uint8_t*)((char*)alter_def + sizeof(ddl_ctrl_t)));
    int ret = tse_alter_table_atomic_impl(req, ddl_ctrl);
    tc_db__tse_ddlalter_table_def__free_unpacked(req, NULL);
    return ret;
}

static void tse_fill_column_by_dc(knl_column_def_t *column, knl_column_t *dc_column, sql_stmt_t *stmt)
{
    proto_str2text(dc_column->name, &column->name);
    column->datatype = dc_column->datatype;
    column->size = dc_column->size;
    column->nullable = dc_column->nullable;
    column->precision = dc_column->precision;
    column->scale = dc_column->scale;
    column->nullable = dc_column->nullable;
    column->is_serial = KNL_COLUMN_IS_SERIAL(dc_column);

    if (column->is_default && dc_column->default_text.len > 0) {
        // if default value is not number or generated by mysql functions, treat it as string
        bool is_default_str = !type_is_number(dc_column->datatype);
        int append_len = is_default_str ? 3 : 1;
        char *format = is_default_str ? "'%s'" : "%s";
        if (sql_alloc_mem(stmt->context, dc_column->default_text.len + append_len,
            (pointer_t *)&column->default_text.str) != GS_SUCCESS) {
            return;
        }
        int ret = sprintf_s(column->default_text.str, dc_column->default_text.len + append_len,
                            format, dc_column->default_text);
        column->default_text.len = strlen(column->default_text.str);
        knl_securec_check_ss(ret);
    }

    if (column->is_default_null && column->is_default && column->nullable) {
        column->default_text.str = DEFAULT_NULL_TEXT_STR;
        column->default_text.len = DEFAULT_NULL_TEXT_LEN;
    }
}

static status_t tse_sql_parse_list_partition_by_dc(sql_stmt_t *stmt, knl_part_def_t *part_def,
                                                   knl_part_obj_def_t *obj_def, dc_entity_t *entity, int offset)
{
    part_table_t *part_table = entity->table.part_table;
    proto_str2text(part_table->groups[0]->entity[offset]->desc.name, &part_def->name);
    proto_str2text(part_table->groups[0]->entity[offset]->desc.hiboundval.str, &part_def->hiboundval);
    part_key_init(part_def->partkey, part_table->groups[0]->entity[offset]->desc.groupcnt);
    char *hiboundval_str = part_table->groups[0]->entity[offset]->desc.hiboundval.str;
    char my_hiboundval[PART_HIBOUND_VALUE_LENGTH + 1];
    knl_securec_check(memcpy_s(my_hiboundval, PART_HIBOUND_VALUE_LENGTH + 1,
                               hiboundval_str, PART_HIBOUND_VALUE_LENGTH + 1));
    char *p_token = NULL;
    char *split = strtok_s(my_hiboundval, ",", &p_token);
    for (uint32_t i = 0; i < part_table->groups[0]->entity[offset]->desc.groupcnt; i += obj_def->part_keys.count) {
        part_key_t *curr_key = NULL;
        GS_RETURN_IFERR(sql_alloc_mem(stmt->context, GS_MAX_COLUMN_SIZE, (pointer_t *)&curr_key));
        part_key_init(curr_key, obj_def->part_keys.count);

        knl_part_column_def_t *key = cm_galist_get(&obj_def->part_keys, 0);
        variant_t value = {0};
        
        if (split != NULL) {
            GS_RETURN_IFERR(tse_partition_set_value(key, split, &value));
        }
        GS_RETURN_IFERR(sql_part_put_key(stmt, &value, key->datatype, key->size, key->is_char, key->precision,
                                         key->scale, curr_key));
        GS_RETURN_IFERR(sql_part_put_key(stmt, &value, key->datatype, key->size, key->is_char, key->precision,
                                         key->scale, part_def->partkey));
        GS_RETURN_IFERR(sql_list_store_define_key(curr_key, NULL, obj_def, &part_def->name));

        split = strtok_s(NULL, ",", &p_token);
    }
    return GS_SUCCESS;
}

static status_t tse_sql_parse_range_partition_by_dc(sql_stmt_t *stmt, knl_part_def_t *part_def,
                                                    knl_part_obj_def_t *obj_def, dc_entity_t *entity, int offset)
{
    part_table_t *part_table = entity->table.part_table;
    proto_str2text(part_table->groups[0]->entity[offset]->desc.name, &part_def->name);
    proto_str2text(part_table->groups[0]->entity[offset]->desc.hiboundval.str, &part_def->hiboundval);
    variant_t value = {0};
    knl_part_column_def_t *key = NULL;

    part_key_init(part_def->partkey, obj_def->part_keys.count);

    key = cm_galist_get(&obj_def->part_keys, 0);
    uint32_t part_id = part_table->groups[0]->entity[offset]->desc.part_id;
    char part_value[GS_MAX_DATA_FILES] = {0};
    PRTS_RETURN_IFERR(snprintf_s(part_value, GS_MAX_DATA_FILES, GS_MAX_DATA_FILES - 1, "%u", part_id));
    GS_RETURN_IFERR(tse_partition_set_value(key, part_value, &value));
    GS_RETURN_IFERR(sql_part_put_key(stmt, &value, key->datatype, key->size, key->is_char, key->precision,
                                     key->scale, part_def->partkey));
    
    int32 cmp_result;
    knl_part_def_t *prev_part = NULL;

    if (obj_def->parts.count >= PARTITION_MIN_CNT) {
        prev_part = cm_galist_get(&obj_def->parts, obj_def->parts.count - PARTITION_MIN_CNT);
        cmp_result = knl_compare_defined_key(&obj_def->part_keys, prev_part->partkey, part_def->partkey);
        if (cmp_result >= 0) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "partition %s boundary invalid", T2S(&part_def->name));
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

static status_t tse_sql_parse_partition_by_dc(knl_part_obj_def_t *obj_def, dc_entity_t *entity, sql_stmt_t *stmt)
{
    status_t status = GS_SUCCESS;
    for (int i = 0; i < obj_def->part_store_in.part_cnt; i++) {
        knl_part_def_t *part_def = NULL;
        GS_RETURN_IFERR(cm_galist_new(&obj_def->parts, sizeof(knl_part_def_t), (pointer_t *)&part_def));
        GS_RETURN_IFERR(sql_alloc_mem(stmt->context, GS_MAX_COLUMN_SIZE, (pointer_t *)&part_def->partkey));

        part_def->is_for_create_db = GS_TRUE;
        cm_galist_init(&part_def->value_list, stmt->context, sql_alloc_mem);
        cm_galist_init(&part_def->subparts, stmt->context, sql_alloc_mem);
        cm_galist_init(&part_def->group_subkeys, stmt->context, sql_alloc_mem);
        part_def->exist_subparts = obj_def->is_composite ? GS_TRUE : GS_FALSE;

        switch (obj_def->part_type) {
            case PART_TYPE_LIST:
                status = tse_sql_parse_list_partition_by_dc(stmt, part_def, obj_def, entity, i);
                break;
            case PART_TYPE_RANGE:
                status = tse_sql_parse_range_partition_by_dc(stmt, part_def, obj_def, entity, i);
                break;
            case PART_TYPE_HASH:
                status = tse_sql_parse_hash_partition(stmt, part_def);
                break;
            default:
                status = GS_ERROR;
                break;
        }

        if (obj_def->is_composite) {
            int sub_per_part_count = entity->table.part_table->desc.subpart_cnt /
                                     entity->table.part_table->desc.partcnt;
            for (int j = 0; j < sub_per_part_count; j++) {
                GS_RETURN_IFERR(tse_sql_subpart_parse_partition(stmt, part_def, obj_def));
            }
        }
    }
    return status;
}

static status_t tse_fill_sub_partition_by_dc(knl_table_def_t *def, knl_part_obj_def_t *obj_def, dc_entity_t *entity)
{
    obj_def->is_composite = GS_TRUE;
    knl_part_column_def_t *subpart_column = NULL;
    GS_RETURN_IFERR(cm_galist_new(&obj_def->subpart_keys, sizeof(knl_part_column_def_t),
                                  (pointer_t *)&subpart_column));
    subpart_column->column_id = GS_INVALID_ID32;
    text_t column_name;
    knl_column_t *dc_column = dc_get_column(entity, entity->table.part_table->sub_keycols->column_id);
    proto_str2text(dc_column->name, &column_name);
    GS_RETURN_IFERR(fill_partition_column_info(&column_name, subpart_column, def));

    if (obj_def->subpart_keys.count > GS_MAX_PARTKEY_COLUMNS) {
        GS_LOG_RUN_ERR("fill_tse_partition_info invalid part_keys_count : %u.", obj_def->subpart_keys.count);
        return GS_ERROR;
    }
    for (uint32 i = 0; i < obj_def->subpart_keys.count - 1; i++) {
        knl_part_column_def_t *column_def = (knl_part_column_def_t *)cm_galist_get(&obj_def->subpart_keys, i);
        if (subpart_column->column_id == column_def->column_id) {
            GS_LOG_RUN_ERR("fill_tse_partition_info duplicate column name : %s.", column_name.str);
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

static status_t tse_fill_partition_by_dc(knl_table_def_t *def, dc_entity_t *entity, sql_stmt_t *stmt)
{
    if (!entity->table.desc.parted) {
        return GS_SUCCESS;
    }
    part_table_t *part_table = entity->table.part_table;
    def->parted = GS_TRUE;
    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_part_obj_def_t), (pointer_t *)&def->part_def));
    knl_part_obj_def_t *obj_def = def->part_def;
    obj_def->part_type = entity->table.part_table->desc.parttype;
    obj_def->subpart_type = entity->table.part_table->desc.subparttype;
    obj_def->is_for_create_db = GS_TRUE;
    cm_galist_init(&obj_def->parts, stmt->context, sql_alloc_mem);
    cm_galist_init(&obj_def->part_keys, stmt->context, sql_alloc_mem);
    cm_galist_init(&obj_def->group_keys, stmt->context, sql_alloc_mem);
    cm_galist_init(&obj_def->part_store_in.space_list, stmt->context, sql_alloc_mem);
    cm_galist_init(&obj_def->subpart_store_in.space_list, stmt->context, sql_alloc_mem);
    cm_galist_init(&obj_def->subpart_keys, stmt->context, sql_alloc_mem);

    knl_part_column_def_t *part_column = NULL;
    GS_RETURN_IFERR(cm_galist_new(&obj_def->part_keys, sizeof(knl_part_column_def_t), (pointer_t *)&part_column));
    part_column->column_id = GS_INVALID_ID32;
    text_t column_name;
    knl_column_t *dc_column = dc_get_column(entity, part_table->keycols->column_id);
    proto_str2text(dc_column->name, &column_name);
    GS_RETURN_IFERR(fill_partition_column_info(&column_name, part_column, def));

    if (obj_def->part_keys.count > GS_MAX_PARTKEY_COLUMNS) {
        GS_LOG_RUN_ERR("fill_tse_partition_info invalid part_keys_count : %u.", obj_def->part_keys.count);
        return GS_ERROR;
    }
    for (uint32 i = 0; i < obj_def->part_keys.count - 1; i++) {
        knl_part_column_def_t *column_def = (knl_part_column_def_t *)cm_galist_get(&obj_def->part_keys, i);
        if (part_column->column_id == column_def->column_id) {
            GS_LOG_RUN_ERR("fill_tse_partition_info duplicate column name : %s.", column_name.str);
            return GS_ERROR;
        }
    }

    obj_def->part_store_in.part_cnt = part_table->desc.partcnt;
    if (obj_def->part_store_in.part_cnt == 0) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "invalid partition number");
        return GS_ERROR;
    }

    if (part_table->desc.subpart_cnt > 0) {
        GS_RETURN_IFERR(tse_fill_sub_partition_by_dc(def, obj_def, entity));
    }

    GS_RETURN_IFERR(tse_sql_parse_partition_by_dc(obj_def, entity, stmt));
    return GS_SUCCESS;
}

static void update_default_cons_name(TcDb__TseDDLRenameTableDef *req, char *fk_name, uint32_t buf_size,
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

static status_t tse_fill_fk_by_dc(TcDb__TseDDLRenameTableDef *req, knl_session_t *knl_session,
                                  knl_table_def_t *def, knl_dictionary_t *dc, sql_stmt_t *stmt)
{
    status_t status = GS_SUCCESS;
    knl_dictionary_t ref_dc = {0};
    dc_entity_t *entity = (dc_entity_t *)dc->handle;
    if (entity->table.cons_set.ref_count < 1) {
        return GS_SUCCESS;
    }
    for (int i = 0; i < entity->table.cons_set.ref_count; i++) {
        knl_constraint_def_t *cons = NULL;
        GS_RETURN_IFERR(cm_galist_new(&def->constraints, sizeof(knl_constraint_def_t), (pointer_t *)&cons));
        cons->cons_state.is_enable = GS_TRUE;
        cons->cons_state.is_validate = GS_TRUE;
        cons->type = CONS_TYPE_REFERENCE;
        GS_RETURN_IFERR((sql_alloc_mem(stmt->context, GS_NAME_BUFFER_SIZE, (pointer_t *)&cons->name.str) != GS_SUCCESS));

        knl_reference_def_t *ref = &cons->ref;
        dc_user_t *user = NULL;
        uint32_t ref_uid = entity->table.cons_set.ref_cons[i]->ref_uid;
        uint32_t ref_oid = entity->table.cons_set.ref_cons[i]->ref_oid;

        char fk_name[GS_NAME_BUFFER_SIZE];
        GS_RETURN_IFERR(knl_fill_fk_name_from_sys4mysql(knl_session, fk_name, ref_uid, ref_oid, dc));
        update_default_cons_name(req, fk_name, GS_NAME_BUFFER_SIZE, cons);
        
        GS_RETURN_IFERR(dc_open_user_by_id(knl_session, ref_uid, &user));
        GS_RETURN_IFERR(dc_open_table_directly(knl_session, ref_uid, ref_oid, &ref_dc));
        dc_entity_t *ref_entity = (dc_entity_t *)ref_dc.handle;
        proto_str2text(user->desc.name, &ref->ref_user);
        proto_str2text(ref_entity->table.desc.name, &ref->ref_table);
        ref->refactor = entity->table.cons_set.ref_cons[i]->refactor;
        cm_galist_init(&ref->ref_columns, stmt->context, sql_alloc_mem);
        cm_galist_init(&cons->columns, stmt->context, sql_alloc_mem);

        int ref_index = entity->table.cons_set.ref_cons[i]->ref_ix;
        index_t *ref_dc_index = ref_entity->table.index_set.items[ref_index];
        uint16 *fk_column = entity->table.cons_set.ref_cons[i]->cols;
        for (int j = 0; j < ref_dc_index->desc.column_count; j++) {
            knl_index_col_def_t *src_column = NULL;
            GS_RETURN_IFERR(cm_galist_new(&cons->columns, sizeof(knl_index_col_def_t), (void **)&src_column));
            knl_index_col_def_t *ref_column = NULL;
            GS_RETURN_IFERR(cm_galist_new(&ref->ref_columns, sizeof(knl_index_col_def_t), (void **)&ref_column));
            knl_column_t *dc_column = dc_get_column(entity, *fk_column);
            proto_str2text(dc_column->name, &src_column->name);
            knl_column_t *ref_fk_column = dc_get_column(ref_entity, ref_dc_index->desc.columns[j]);
            proto_str2text(ref_fk_column->name, &ref_column->name);
            fk_column++;
        }
    }
    knl_close_dc(&ref_dc);
    return status;
}

static void tse_fill_index_from_dc(TcDb__TseDDLRenameTableDef *req, knl_index_def_t *index,
                                   index_t *dc_index, sql_stmt_t *stmt)
{
    proto_str2text(req->new_user, &index->user);
    proto_str2text(req->new_table_name, &index->table);
    proto_str2text(dc_index->desc.name, &index->name);
}

static void tse_fill_index_parted(knl_index_def_t *index, index_t *dc_index)
{
    index->parted = dc_index->desc.parted;
    if (index->parted) {
        index->initrans = GS_INI_TRANS;
        index->pctfree = GS_PCT_FREE;
        index->cr_mode = CR_PAGE;
    }
}

static status_t tse_ddl_fill_func_column_by_dc(dc_entity_t *entity, index_t *dc_index, knl_index_def_t *index,
                                               sql_stmt_t *stmt)
{
    knl_index_col_def_t *key_column = NULL;
    GS_RETURN_IFERR(cm_galist_new(&index->columns, sizeof(knl_index_col_def_t), (void **)&key_column));
    int arg_cols = *(dc_index->desc.columns_info->arg_cols);
    knl_column_t *dc_column = dc_get_column(entity, arg_cols);
    proto_str2text(dc_column->name, &key_column->name);
    key_column->datatype = dc_index->desc.profile.types[0];
    key_column->size = dc_column->size;
    key_column->is_func = 1;
    int vir_col = 0;

    while (GS_TRUE) {
        if (entity->virtual_columns[vir_col]->id != dc_index->desc.columns[0]) {
            vir_col += 1;
            continue;
        }
        char *default_func_str = entity->virtual_columns[vir_col]->default_text.str;
        char *default_str = NULL;
        GS_RETURN_IFERR(sql_alloc_mem(stmt->context, entity->virtual_columns[vir_col]->default_text.len + 1,
                                      (pointer_t *)&default_str));
        GS_RETURN_IFERR(cm_text2str(&entity->virtual_columns[vir_col]->default_text, default_str,
                                    entity->virtual_columns[vir_col]->default_text.len + 1));
        char *p_token = NULL;
        char *split_name = strtok_s(default_str, "(", &p_token);

        text_t func_name_text = {0};
        proto_str2text(split_name, &func_name_text);
        uint32 func_id = sql_get_func_id(&func_name_text);
        if (func_id == GS_INVALID_ID32) {
            GS_THROW_ERROR_EX(ERR_FUNCTION_NOT_EXIST, split_name);
            return GS_ERROR;
        }
        if (!g_func_tab[func_id].indexable) {
            GS_THROW_ERROR_EX(ERR_FUNCTION_NOT_INDEXABLE, dc_column->default_text.str);
            return GS_ERROR;
        }
        proto_str2text(default_func_str, &key_column->func_text);
        break;
    }

    return GS_SUCCESS;
}

static status_t tse_ddl_fill_key_column_by_dc(dc_entity_t *entity, index_t *dc_index, bool is_ordinary_index,
                                              knl_index_def_t *index, knl_constraint_def_t *cons)
{
    for (int i = 0; i < dc_index->desc.column_count; i++) {
        knl_index_col_def_t *key_column = NULL;
        knl_column_t *dc_column = dc_get_column(entity, dc_index->desc.columns[i]);
        if (is_ordinary_index) {
            GS_RETURN_IFERR(cm_galist_new(&index->columns, sizeof(knl_index_col_def_t), (void **)&key_column));
            proto_str2text(dc_column->name, &key_column->name);
            key_column->datatype = dc_column->datatype;
            key_column->size = dc_column->size;
            key_column->is_func = 0;
        } else {
            knl_index_col_def_t *key_column_cond = NULL;
            GS_RETURN_IFERR(cm_galist_new(&cons->columns, sizeof(knl_index_col_def_t), (void **)&key_column_cond));
            proto_str2text(dc_column->name, &key_column_cond->name);
            key_column_cond->size = dc_column->size;
        }
    }
    return GS_SUCCESS;
}

static status_t tse_fill_index_by_dc(TcDb__TseDDLRenameTableDef *req, dc_entity_t *entity,
                                     knl_table_def_t *def, sql_stmt_t *stmt)
{
    status_t status = GS_SUCCESS;
    for (int i = 0; i < entity->table.index_set.total_count; i++) {
        knl_index_def_t *index = NULL;
        knl_constraint_def_t *cons = NULL;
        index_t *dc_index = entity->table.index_set.items[i];
        bool is_ordinary_index = !dc_index->desc.primary && !dc_index->desc.unique;
        if (is_ordinary_index) {
            status = cm_galist_new(&def->indexs, sizeof(knl_index_def_t), (pointer_t *)&index);
            GS_RETURN_IFERR(status);
            tse_fill_index_from_dc(req, index, dc_index, stmt);
            index->type = INDEX_TYPE_BTREE;
        } else {
            status = cm_galist_new(&def->constraints, sizeof(knl_constraint_def_t), (pointer_t *)&cons);
            GS_RETURN_IFERR(status);
            cons->cons_state.is_enable = GS_TRUE;
            cons->cons_state.is_validate = GS_TRUE;
            cons->cons_state.is_use_index = GS_TRUE;
            if (sql_alloc_mem(stmt->context, GS_NAME_BUFFER_SIZE, (pointer_t *)&cons->name.str) != GS_SUCCESS) {
                return GS_ERROR;
            }
            proto_str2text_ex(dc_index->desc.name, &cons->name, GS_NAME_BUFFER_SIZE - 1);
            index = &cons->index;
            tse_fill_index_from_dc(req, index, dc_index, stmt);
            if (dc_index->desc.primary) {
                cons->type = CONS_TYPE_PRIMARY;
                index->primary = GS_TRUE;
            } else if (dc_index->desc.unique) {
                cons->type = CONS_TYPE_UNIQUE;
                index->unique = GS_TRUE;
            }
            cm_galist_init(&cons->columns, stmt->context, sql_alloc_mem);
        }

        tse_fill_index_parted(index, dc_index);
        cm_galist_init(&index->columns, stmt->context, sql_alloc_mem);

        if (dc_index->desc.is_func) {
            status = tse_ddl_fill_func_column_by_dc(entity, dc_index, index, stmt);
            GS_RETURN_IFERR(status);
        } else {
            status = tse_ddl_fill_key_column_by_dc(entity, dc_index, is_ordinary_index, index, cons);
            GS_RETURN_IFERR(status);
        }
    }
    return status;
}

static status_t tse_get_auto_increment(knl_table_def_t *def, dc_entity_t *entity,
                                       knl_session_t *knl_session, knl_column_t *dc_column)
{
    if (!KNL_COLUMN_IS_SERIAL(dc_column)) {
        return GS_SUCCESS;
    }
    if (entity->has_serial_col) {
        uint64 serial_col_value = 0;
        GS_RETURN_IFERR(tse_get_curr_serial_value_auto_inc(knl_session, entity, (uint64 *)(&serial_col_value), 1, 1));
        uint64 max_serial_value = tse_calc_max_serial_value(dc_column, &serial_col_value);
        def->serial_start = serial_col_value;
    }
    return GS_SUCCESS;
}

static status_t tse_fill_def_base_from_dc(TcDb__TseDDLRenameTableDef *req, knl_table_def_t *def,
                                          knl_dictionary_t *dc, sql_stmt_t *stmt, knl_session_t *knl_session)
{
    status_t ret = GS_SUCCESS;
    dc_entity_t *entity = (dc_entity_t *)dc->handle;
    def->sysid = GS_INVALID_ID32;
    def->cr_mode = entity->table.desc.cr_mode;
    def->pctfree = entity->table.desc.pctfree;
    def->initrans = entity->table.desc.initrans;
    def->is_for_create_db = GS_TRUE;

    proto_str2text(req->new_user, &def->schema);
    ret = strncpy_s(stmt->session->curr_schema, GS_NAME_BUFFER_SIZE, def->schema.str, def->schema.len);
    MEMS_RETURN_IFERR(ret);
    proto_str2text(req->new_table_name, &def->name);

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
        tse_fill_column_by_dc(column, dc_column, stmt);
        if (column->primary) {
            def->pk_inline = GS_TRUE;
        }
        def->rf_inline = def->rf_inline || (column->is_ref);
        def->uq_inline = def->uq_inline || (column->unique);
        def->chk_inline = def->chk_inline || (column->is_check);
        ret = tse_get_auto_increment(def, entity, knl_session, dc_column);
        if (ret != GS_SUCCESS) {
            break;
        }
    }
    return ret;
}

static status_t tse_fill_def_from_dc(TcDb__TseDDLRenameTableDef *req, knl_table_def_t *def,
                                     knl_dictionary_t *dc, sql_stmt_t *stmt, knl_session_t *knl_session)
{
    status_t ret = GS_SUCCESS;
    dc_entity_t *entity = (dc_entity_t *)dc->handle;
    ret = tse_fill_def_base_from_dc(req, def, dc, stmt, knl_session);
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[tse_fill_def_from_dc]: tse_fill_def_base_from_dc failed");
        knl_close_dc(dc);
        do_rollback(stmt->session, NULL);
        return ret;
    }

    // partition
    SYNC_POINT_GLOBAL_START(TSE_RENAME_CROSS_DB_FILL_PART_FAIL, &ret, GS_ERROR);
    ret = tse_fill_partition_by_dc(def, entity, stmt);
    SYNC_POINT_GLOBAL_END;
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[tse_fill_def_from_dc]: tse_fill_partition_by_dc failed");
        knl_close_dc(dc);
        do_rollback(stmt->session, NULL);
        return ret;
    }

    // foreign key
    SYNC_POINT_GLOBAL_START(TSE_RENAME_CROSS_DB_FILL_FK_FAIL, &ret, GS_ERROR);
    ret = tse_fill_fk_by_dc(req, knl_session, def, dc, stmt);
    SYNC_POINT_GLOBAL_END;
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[tse_fill_def_from_dc]: tse_fill_fk_by_dc failed");
        knl_close_dc(dc);
        do_rollback(stmt->session, NULL);
        return ret;
    }

    // index
    SYNC_POINT_GLOBAL_START(TSE_RENAME_CROSS_DB_FILL_INDEX_FAIL, &ret, GS_ERROR);
    ret = tse_fill_index_by_dc(req, entity, def, stmt);
    SYNC_POINT_GLOBAL_END;
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[tse_fill_def_from_dc]: tse_fill_index_by_dc failed");
        knl_close_dc(dc);
        do_rollback(stmt->session, NULL);
        return ret;
    }
    return ret;
}

static void tse_set_cursor_to_read(knl_cursor_t *cursor, knl_dictionary_t *old_dc)
{
    cursor->action = CURSOR_ACTION_SELECT;
    cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor->vnc_column = NULL;
    cursor->table = DC_TABLE(old_dc);
    cursor->dc_entity = old_dc->handle;
    cursor->dc_type = old_dc->type;
}

static void tse_set_cursor_to_write(knl_cursor_t *cursor, knl_dictionary_t *new_dc)
{
    cursor->action = CURSOR_ACTION_INSERT;
    cursor->table = DC_TABLE(new_dc);
    cursor->dc_entity = new_dc->handle;
    cursor->dc_type = new_dc->type;
}

static status_t tse_fetch_from_part(knl_cursor_t *old_cursor, knl_cursor_t *new_cursor,
                                    knl_dictionary_t *old_dc, knl_dictionary_t *new_dc, knl_session_t *knl_session)
{
    uint32_t sub_cnt = DC_TABLE(new_dc)->part_table->desc.subpart_cnt;
    uint32_t part_cnt = DC_TABLE(new_dc)->part_table->desc.partcnt;
    bool is_contain_sub_part = (sub_cnt == 0) ? GS_FALSE : GS_TRUE;
    uint32_t sub_part_num = sub_cnt / part_cnt;
    uint32_t par_no = 0;
    uint32_t sub_no = is_contain_sub_part ? 0 : INVALID_PART_ID;
    uint32_t tmp_cnt = 0;
    while (GS_TRUE) {
        if (is_contain_sub_part && (sub_no >= sub_part_num)) {
            sub_no = 0;
            par_no += 1;
            continue;
        }
        knl_part_locate_t part_loc = { .part_no = par_no, .subpart_no = sub_no };
        knl_set_table_part(old_cursor, part_loc);
        knl_set_table_part(new_cursor, part_loc);
        GS_RETURN_IFERR(knl_reopen_cursor(knl_session, old_cursor, old_dc));
        GS_RETURN_IFERR(knl_reopen_cursor(knl_session, new_cursor, new_dc));
        new_cursor->table_part = TABLE_GET_PART(DC_TABLE(new_dc), part_loc.part_no);
        if (is_contain_sub_part) {
            new_cursor->table_part = PART_GET_SUBENTITY(((table_t *)new_cursor->table)->part_table,
                                                        ((table_part_t *)new_cursor->table_part)->subparts[sub_no]);
        }
        while (!old_cursor->eof) {
            GS_RETURN_IFERR(knl_fetch(knl_session, old_cursor));
            if (!old_cursor->eof) {
                knl_copy_row(knl_session, old_cursor, new_cursor);
                GS_RETURN_IFERR(knl_insert(knl_session, new_cursor));
            }
        }

        is_contain_sub_part ? sub_no++ : par_no++;
        tmp_cnt++;
        if (par_no >= part_cnt || (is_contain_sub_part && tmp_cnt >= sub_cnt)) {
            break;
        }
    }
    return GS_SUCCESS;
}

static status_t tse_fetch_from_normal_table(knl_session_t *knl_session,
                                            knl_cursor_t *old_cursor, knl_cursor_t *new_cursor)
{
    while (!old_cursor->eof) {
        GS_RETURN_IFERR(knl_fetch(knl_session, old_cursor));
        if (!old_cursor->eof) {
            knl_copy_row(knl_session, old_cursor, new_cursor);
            GS_RETURN_IFERR(knl_insert(knl_session, new_cursor));
        }
    }
    return GS_SUCCESS;
}

static status_t tse_trx_commit_rollback(status_t ret, sql_stmt_t *stmt)
{
    if (ret == GS_SUCCESS) {
        do_commit(stmt->session);
    } else {
        do_rollback(stmt->session, NULL);
    }
    return ret;
}

static status_t tse_fetch_data_in_rename_table(TcDb__TseDDLRenameTableDef *req, ddl_ctrl_t *ddl_ctrl,
                                               sql_stmt_t *stmt, knl_dictionary_t *old_dc, knl_dictionary_t *new_dc)
{
    status_t status = GS_SUCCESS;
    session_t *session = NULL;
    GS_RETURN_IFERR(get_and_init_session(&session, &(ddl_ctrl->tch), false));
    knl_session_t *knl_session = &session->knl_session;
    CM_SAVE_STACK(knl_session->stack);

    // open old context and new context
    tse_context_t *old_context = NULL;
    tse_context_t *new_context = NULL;
    // open old cursor
    knl_cursor_t *old_cursor = knl_push_cursor(knl_session);
    tse_set_cursor_to_read(old_cursor, old_dc);
    // open new cursor
    knl_cursor_t *new_cursor = knl_push_cursor(knl_session);
    tse_set_cursor_to_write(new_cursor, new_dc);

    do {
        if (init_tse_ctx(&old_context, req->old_table_name, req->user) != GS_SUCCESS ||
            init_tse_ctx(&new_context, req->new_table_name, req->new_user) != GS_SUCCESS) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "[tse_fetch_data_in_rename_table]: open context failed.");
            break;
        }
        
        old_context->dc = old_dc;
        new_context->dc = new_dc;
        if (tse_open_cursor(knl_session, old_cursor, old_context, NULL) != GS_SUCCESS ||
            tse_open_cursor(knl_session, new_cursor, new_context, NULL) != GS_SUCCESS) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "[tse_fetch_data_in_rename_table]: open cursor failed.");
            break;
        }

        old_cursor->row = (row_head_t *)cm_push(knl_session->stack, GS_MAX_ROW_SIZE);
        if (old_cursor->row == NULL) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "[tse_fetch_data_in_rename_table]: old cursor fetch failed.");
            break;
        }

        if (((dc_entity_t *)(old_dc->handle))->table.part_table) {
            status = tse_fetch_from_part(old_cursor, new_cursor, old_dc, new_dc, knl_session);
        } else {
            status = tse_fetch_from_normal_table(knl_session, old_cursor, new_cursor);
        }
    } while (0);

    CM_RESTORE_STACK(knl_session->stack);
    tse_close_cursor(knl_session, old_cursor);
    tse_close_cursor(knl_session, new_cursor);
    if (status != GS_SUCCESS) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "[tse_fetch_data_in_rename_table]: fetch data failed.");
    }
    return tse_trx_commit_rollback(status, stmt);
}

static void tse_fill_drop_table_def(TcDb__TseDDLRenameTableDef *req, knl_drop_def_t *drop_def,
                                    char *user_name, char* table_name)
{
    proto_str2text(table_name, &drop_def->name);
    proto_str2text(user_name, &drop_def->owner);
    drop_def->purge = true;
    drop_def->options = DROP_NO_CHECK_FK;
}

static status_t fill_rename_broadcast_req_and_broadcast(TcDb__TseDDLRenameTableDef *req, ddl_ctrl_t *ddl_ctrl,
                                                        tse_ddl_broadcast_request *broadcast_req)
{
    FILL_BROADCAST_REQ(*broadcast_req, req->current_db_name, req->sql_str, ddl_ctrl->user_name,
                       ddl_ctrl->user_ip, ddl_ctrl->mysql_inst_id, ddl_ctrl->tch.sql_command);
    return tse_execute_mysql_ddl_sql(&ddl_ctrl->tch, broadcast_req, false);
}

static void tse_rename_table_cross_db_post_process(session_t *session, knl_dictionary_t *old_dc,
                                                   knl_dictionary_t *new_dc)
{
    tse_alter_table_unlock(&session->knl_session);
    dc_invalidate_children(&session->knl_session, (dc_entity_t *)old_dc->handle);
    dc_invalidate_parents(&session->knl_session, (dc_entity_t *)old_dc->handle);
    dc_invalidate(&session->knl_session, (dc_entity_t *)old_dc->handle);
    knl_close_dc(old_dc);
    if (new_dc != NULL && new_dc->handle != NULL) {
        dc_invalidate_children(&session->knl_session, (dc_entity_t *)new_dc->handle);
        dc_invalidate_parents(&session->knl_session, (dc_entity_t *)new_dc->handle);
        dc_invalidate(&session->knl_session, (dc_entity_t *)new_dc->handle);
    }
    knl_close_dc(new_dc);
}

static status_t tse_update_fk_msg(TcDb__TseDDLRenameTableDef *req, sql_stmt_t *stmt,
                                  knl_session_t *session, bool is_recover)
{
    knl_dictionary_t old_dc;
    knl_dictionary_t new_dc;
    CM_SAVE_STACK(session->stack);

    if (tse_open_dc(req->user, req->old_table_name, stmt, &old_dc) != GS_SUCCESS ||
        tse_open_dc(req->new_user, req->new_table_name, stmt, &new_dc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "[tse_update_fk_msg]: open dc failed.");
        do_rollback(stmt->session, NULL);
        return GS_ERROR;
    }

    int ret = GS_SUCCESS;
    if (is_recover) {
        ret = knl_update_ref_syscons4mysql(session, &new_dc, &old_dc);
        dc_invalidate_children(session, (dc_entity_t *)old_dc.handle);
        dc_invalidate_parents(session, (dc_entity_t *)old_dc.handle);
        dc_invalidate(session, (dc_entity_t *)old_dc.handle);
        dc_invalidate_children(session, (dc_entity_t *)new_dc.handle);
        dc_invalidate_parents(session, (dc_entity_t *)new_dc.handle);
        dc_invalidate(session, (dc_entity_t *)new_dc.handle);
    } else {
        ret = knl_update_ref_syscons4mysql(session, &old_dc, &new_dc);
    }

    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[tse_update_fk_msg]:update sys table failed.");
    }
    knl_close_dc(&old_dc);
    knl_close_dc(&new_dc);
    return tse_trx_commit_rollback(ret, stmt);
}

static status_t tse_creat_table_in_rename(knl_table_def_t *table_def, session_t *session,
                                          sql_stmt_t *stmt, knl_dictionary_t *old_dc, knl_dictionary_t *new_dc)
{
    knl_session_t *knl_session = &session->knl_session;
    if (knl_create_table(knl_session, stmt, table_def)) {
        GS_LOG_RUN_ERR("[tse_creat_table_in_rename]: knl_create_table failed");
        return GS_ERROR;
    }

    knl_drop_def_t new_drop_def = {0};
    proto_str2text(table_def->name.str, &(new_drop_def.name));
    proto_str2text(table_def->schema.str, &(new_drop_def.owner));
    new_drop_def.purge = true;
    new_drop_def.options = DROP_NO_CHECK_FK;

    // open new dc
    if (tse_open_dc(table_def->schema.str, table_def->name.str, stmt, new_dc)) {
        tse_rename_table_cross_db_post_process(session, old_dc, new_dc);
        GS_RETURN_IFERR(knl_drop_table(&stmt->session->knl_session, stmt, &new_drop_def));
        tse_ddl_clear_stmt(session->current_stmt);
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "[tse_creat_table_in_rename]: open dc failed");
        do_rollback(stmt->session, NULL);
        return GS_ERROR;
    }

    // lock
    if (tse_alter_table_lock_table(knl_session, old_dc) != GS_SUCCESS ||
        knl_alter_table_lock_table(knl_session, new_dc) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[tse_creat_table_in_rename]: tse_alter_table_lock_table failed");
        tse_rename_table_cross_db_post_process(session, old_dc, new_dc);
        if (knl_drop_table(&stmt->session->knl_session, stmt, &new_drop_def) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[tse_creat_table_in_rename]: drop new renamed table failed");
            do_rollback(stmt->session, NULL);
            tse_ddl_clear_stmt(session->current_stmt);
            return GS_ERROR;
        }
        do_rollback(stmt->session, NULL);
        tse_ddl_clear_stmt(session->current_stmt);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t tse_update_new_table_in_rename(TcDb__TseDDLRenameTableDef *req, session_t *session,
                                               ddl_ctrl_t *ddl_ctrl, knl_dictionary_t *old_dc, knl_dictionary_t *new_dc)
{
    status_t ret = GS_SUCCESS;
    sql_stmt_t *stmt = session->current_stmt;
    knl_session_t *knl_session = &session->knl_session;
    knl_drop_def_t old_drop_def = {0};
    knl_drop_def_t new_drop_def = {0};
    tse_fill_drop_table_def(req, &old_drop_def, req->user, req->old_table_name);
    tse_fill_drop_table_def(req, &new_drop_def, req->new_user, req->new_table_name);
    do {
        // data update
        ret = tse_fetch_data_in_rename_table(req, ddl_ctrl, stmt, old_dc, new_dc);
        if (ret != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[tse_update_new_table_in_rename]: tse_fetch_data_in_rename_table failed");
            break;
        }

        // foreign key update
        ret = tse_update_fk_msg(req, stmt, knl_session, false);
        if (ret != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[tse_update_new_table_in_rename]: tse_update_fk_msg failed");
            break;
        }

        // drop old table
        ret = knl_drop_table(&stmt->session->knl_session, stmt, &old_drop_def);
        if (ret != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[tse_update_new_table_in_rename]: knl_drop_table failed");
            break;
        }
    } while (0);
    if (ret != GS_SUCCESS) {
        // if reach here, old table exists
        if (knl_drop_table(&stmt->session->knl_session, stmt, &new_drop_def) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[tse_update_new_table_in_rename]: update new table failed and drop new table failed");
        }
    }
    tse_rename_table_cross_db_post_process(session, old_dc, new_dc);
    tse_trx_commit_rollback(ret, stmt);
    tse_ddl_clear_stmt(stmt);
    return ret;
}

static status_t tse_rename_table_cross_database_impl(TcDb__TseDDLRenameTableDef *req, ddl_ctrl_t *ddl_ctrl)
{
    session_t *session = NULL;
    GS_RETURN_IFERR(get_and_init_session(&session, &(ddl_ctrl->tch), false));
    sql_stmt_t *stmt = session->current_stmt;
    knl_session_t *knl_session = &session->knl_session;
    knl_dict_type_t obj_type;
    knl_drop_def_t old_drop_def = {0};
    knl_drop_def_t new_drop_def = {0};
    tse_fill_drop_table_def(req, &old_drop_def, req->user, req->old_table_name);
    tse_fill_drop_table_def(req, &new_drop_def, req->new_user, req->new_table_name);

    tse_ddl_broadcast_request broadcast_req = {0};
 
    if (dc_object_exists(knl_session, &(new_drop_def.owner), &(new_drop_def.name), &obj_type) &&
        !dc_object_exists(knl_session, &(old_drop_def.owner), &(old_drop_def.name), &obj_type)) {
        return fill_rename_broadcast_req_and_broadcast(req, ddl_ctrl, &broadcast_req);
    }
 
    if (dc_object_exists(knl_session, &(new_drop_def.owner), &(new_drop_def.name), &obj_type) &&
        dc_object_exists(knl_session, &(old_drop_def.owner), &(old_drop_def.name), &obj_type)) {
        if (tse_update_fk_msg(req, stmt, knl_session, true) != GS_SUCCESS) {
            GS_RETURN_IFERR(knl_drop_table(&stmt->session->knl_session, stmt, &new_drop_def));
            return GS_ERROR;
        }
        GS_RETURN_IFERR(knl_drop_table(&stmt->session->knl_session, stmt, &new_drop_def));
    }

    text_t alter_user = {0};
    text_t alter_name = {0};
    tse_put_ddl_sql_2_stmt(session, req->old_db_name, req->sql_str);
    stmt->context->type = SQL_TYPE_CREATE_TABLE;
    proto_str2text(req->user, &alter_user);
    proto_str2text(req->old_table_name, &alter_name);

    knl_dictionary_t old_dc;
    knl_dictionary_t new_dc;
    GS_RETURN_IFERR(knl_open_dc((knl_handle_t)&stmt->session->knl_session, (text_t *)&alter_user,
                                (text_t *)&alter_name, &old_dc));
    knl_table_def_t *table_def = NULL;
    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_table_def_t), (pointer_t *)&table_def));
    tse_put_ddl_sql_2_stmt(session, req->new_db_name, req->sql_str);
    GS_RETURN_IFERR_EX(tse_fill_def_from_dc(req, table_def, &old_dc, stmt, knl_session), stmt, ddl_ctrl);
    stmt->context->entry = table_def;
    GS_RETURN_IFERR_EX(tse_creat_table_in_rename(table_def, session, stmt, &old_dc, &new_dc), stmt, ddl_ctrl);

    SYNC_POINT_GLOBAL_START(TSE_RENAME_CROSS_DB_AFTER_CREATE_TABLE_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    GS_RETURN_IFERR_EX(tse_update_new_table_in_rename(req, session, ddl_ctrl, &old_dc, &new_dc), stmt, ddl_ctrl);

    SYNC_POINT_GLOBAL_START(TSE_RENAME_CROSS_DB_AFTER_FILL_DATA_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    tse_ddl_clear_stmt(stmt);
    return fill_rename_broadcast_req_and_broadcast(req, ddl_ctrl, &broadcast_req);
}

static int tse_rename_table_impl(TcDb__TseDDLRenameTableDef *req, ddl_ctrl_t *ddl_ctrl)
{
    if (req->new_table_name == NULL) {
        return GS_ERROR;
    }
    session_t *session = NULL;
    status_t status = get_and_init_session(&session, &(ddl_ctrl->tch), false);
    if (status != GS_SUCCESS) {
        return status;
    }

    knl_altable_def_t *def = NULL;
    knl_altable_def_t *def_arrays = NULL;
    sql_stmt_t *stmt = session->current_stmt;
    uint32 def_count = req->n_old_constraints_name + 1;
    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_altable_def_t) * def_count, (pointer_t *)&def_arrays));
    tse_put_ddl_sql_2_stmt(session, req->old_db_name, req->sql_str);
    stmt->context->type = SQL_TYPE_ALTER_TABLE; // todo
    stmt->context->entry = def_arrays;
    cm_galist_init(&def_arrays->column_defs, stmt->context, sql_alloc_mem);
    proto_str2text(req->user, &def_arrays->user);
    status = strncpy_s(stmt->session->curr_schema, GS_NAME_BUFFER_SIZE, def_arrays->user.str, def_arrays->user.len);
    GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);

    proto_str2text(req->old_table_name, &def_arrays->name);

    knl_dictionary_t dc;
    status = knl_open_dc(&session->knl_session, &(def_arrays->user), &(def_arrays->name), &dc);
    if (status != GS_SUCCESS) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not find", T2S(&(def_arrays->name)));
        GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    }
    def_arrays->action = ALTABLE_RENAME_TABLE;
    proto_str2text(req->new_table_name, &def_arrays->table_def.new_name);

    for (int i = 1; i < def_count; i++) {
        def = &(def_arrays[i]);
        proto_str2text(req->user, &def->user);
        proto_str2text(req->old_table_name, &def->name);
        GS_RETURN_IFERR(tse_fill_rename_constraint(session, stmt, def, req->old_constraints_name[i - 1],
                                                   req->new_constraints_name[i - 1]));
    }

    status = tse_alter_table_lock_table(&session->knl_session, &dc);
    if (status != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[TSE_LOCK_ALTER_TABLE]:alter table to lock table failed, ret:%d,"
                       "conn_id:%u, tse_instance_id:%u", (int)status, ddl_ctrl->tch.thd_id, ddl_ctrl->tch.inst_id);
        knl_close_dc(&dc);
        tse_alter_table_unlock(&session->knl_session);
        GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    }
    status = knl_alter_table4mysql(session, stmt, def_arrays, def_count, &dc, true);
    if (status != GS_SUCCESS) {
        GS_LOG_RUN_ERR("tse_rename_table: faild to rename table");
        knl_alter_table_rollback(&session->knl_session, &dc, true);
        knl_close_dc(&dc);
        tse_alter_table_unlock(&session->knl_session);
        GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    } else {
        knl_rename_table_write_logical(&session->knl_session, def_arrays, &dc);
        knl_alter_table_commit(&session->knl_session, stmt, &dc, true);
        knl_close_dc(&dc);
        tse_alter_table_unlock(&session->knl_session);
    }
    tse_ddl_clear_stmt(stmt);

    if (ddl_ctrl->is_alter_table) {
        return GS_SUCCESS;
    }

    tse_ddl_broadcast_request broadcast_req = {0};
    FILL_BROADCAST_REQ(broadcast_req, req->old_db_name, req->sql_str, ddl_ctrl->user_name, ddl_ctrl->user_ip,
                       ddl_ctrl->mysql_inst_id, ddl_ctrl->tch.sql_command);
    int broadcat_ret = tse_execute_mysql_ddl_sql(&ddl_ctrl->tch, &broadcast_req, false);
    // 如果带有忽略参天错误的标志，需要同步忽略掉广播其他节点的报错
    return broadcat_ret;
}
int tse_rename_table(void *alter_def, ddl_ctrl_t *ddl_ctrl)
{
    TcDb__TseDDLRenameTableDef *req = tc_db__tse_ddlrename_table_def__unpack(NULL, ddl_ctrl->msg_len, alter_def);
    int ret = GS_SUCCESS;
    if (strcmp(req->user, req->new_user) != 0) {
        ret = tse_rename_table_cross_database_impl(req, ddl_ctrl);
    } else {
        ret = tse_rename_table_impl(req, ddl_ctrl);
    }
    tc_db__tse_ddlrename_table_def__free_unpacked(req, NULL);
    return ret;
}

static int tse_drop_table_impl(TcDb__TseDDLDropTableDef *req, ddl_ctrl_t *ddl_ctrl)
{
    session_t *session = NULL;
    status_t status = get_and_init_session(&session, &(ddl_ctrl->tch), false);
    if (status != GS_SUCCESS) {
        return status;
    }

    knl_drop_def_t *def = NULL;
    sql_stmt_t *stmt = session->current_stmt;
    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_drop_def_t), (pointer_t *)&def));
    tse_put_ddl_sql_2_stmt(session, req->db_name, req->sql_str);
    stmt->context->type = SQL_TYPE_DROP_TABLE;
    stmt->context->entry = def;

    proto_str2text(req->name, &def->name);
    proto_str2text(req->user, &def->owner);
    status = strncpy_s(stmt->session->curr_schema, GS_NAME_BUFFER_SIZE, def->owner.str, def->owner.len);
    GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    def->options = req->options;
    def->purge = true;
    proto_str2text(req->alter_copy_table, &def->old_parent_name);
    GS_LOG_RUN_WAR("knl_drop_table enter, table_name:%s, session_id:%d", def->name.str, stmt->session->knl_session.id);

    status = knl_drop_table(&stmt->session->knl_session, stmt, def);
    GS_LOG_RUN_WAR("knl_drop_table finish, table_name:%s, session_id:%d", def->name.str, stmt->session->knl_session.id);
    GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    if (status == GS_SUCCESS) {
        do_commit(stmt->session);
    } else {
        do_rollback(stmt->session, NULL);
        GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    }
    GS_LOG_RUN_WAR("tse_drop_table commit or rollback finish.");
    tse_ddl_clear_stmt(stmt);

    tse_ddl_broadcast_request broadcast_req = {0};
    FILL_BROADCAST_REQ(broadcast_req, req->db_name, req->sql_str, ddl_ctrl->user_name, ddl_ctrl->user_ip,
                       ddl_ctrl->mysql_inst_id, ddl_ctrl->tch.sql_command);
    broadcast_req.options |= ((req->options & TSE_DROP_NO_CHECK_FK_FOR_CANTIAN_AND_BROADCAST) ? TSE_OPEN_NO_CHECK_FK_FOR_CURRENT_SQL : 0);
    int broadcat_ret = tse_execute_mysql_ddl_sql(&ddl_ctrl->tch, &broadcast_req, false);
    // 如果带有忽略参天错误的标志，需要同步忽略掉广播其他节点的报错
    return broadcat_ret;
}

int tse_drop_table(void *drop_def, ddl_ctrl_t *ddl_ctrl)
{
    TcDb__TseDDLDropTableDef *req = tc_db__tse_ddldrop_table_def__unpack(NULL, ddl_ctrl->msg_len, drop_def);
    int ret = tse_drop_table_impl(req, ddl_ctrl);
    tc_db__tse_ddldrop_table_def__free_unpacked(req, NULL);
    return ret;
}

status_t fill_datafile_by_TcDb__TseDDLDataFileDef(knl_device_def_t *datafile, const TcDb__TseDDLDataFileDef *def,
    char *ts_path, uint32_t ts_len)
{
    status_t status = tse_generate_tablespace_path(def->name, ts_path, ts_len);
    GS_RETURN_IFERR(status);
    proto_str2text(ts_path, &datafile->name);
    datafile->size = def->size;
    datafile->autoextend.enabled = def->autoextend->enabled;
    datafile->autoextend.nextsize = def->autoextend->nextsize == 0 ?
        DATA_FILE_DEFALUT_EXTEND_SIZE : def->autoextend->nextsize;
    return status;
}

static int tse_create_tablespace_impl(TcDb__TseDDLSpaceDef *req, ddl_ctrl_t *ddl_ctrl)
{
    status_t status;
    session_t *session = NULL;
    char ts_path[TABLESPACE_PATH_MAX_LEN] = {0};
    // 创建tablespace不会走tse_lock_table，所有这里必须要要创建session
    status = get_and_init_session(&session, &(ddl_ctrl->tch), true);
    if (status != GS_SUCCESS) {
        return status;
    }

    knl_space_def_t *def = NULL;
    sql_stmt_t *stmt = session->current_stmt;
    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_space_def_t), (pointer_t *)&def));
    tse_put_ddl_sql_2_stmt(session, req->db_name, req->sql_str);
    stmt->context->type = SQL_TYPE_CREATE_TABLESPACE;
    stmt->context->entry = def;
    proto_str2text(req->name, &def->name);

    cm_galist_init(&def->datafiles, stmt->context, sql_alloc_mem);
    def->type = SPACE_TYPE_USERS;
    knl_device_def_t *datafile = NULL;
    status = cm_galist_new(&def->datafiles, sizeof(knl_device_def_t), (pointer_t *)&datafile);
    GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    status = fill_datafile_by_TcDb__TseDDLDataFileDef(datafile, req->datafiles_list[0], ts_path,
        TABLESPACE_PATH_MAX_LEN - 1);
    GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    status = knl_create_space(&stmt->session->knl_session, stmt, def);
    if (status == GS_SUCCESS) {
        do_commit(stmt->session);
    } else {
        do_rollback(stmt->session, NULL);
        GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    }
    tse_ddl_clear_stmt(stmt);

    tse_ddl_broadcast_request broadcast_req = {0};
    FILL_BROADCAST_REQ(broadcast_req, req->db_name, req->sql_str, ddl_ctrl->user_name, ddl_ctrl->user_ip,
                       ddl_ctrl->mysql_inst_id, ddl_ctrl->tch.sql_command);
    int broadcat_ret = tse_execute_mysql_ddl_sql(&ddl_ctrl->tch, &broadcast_req, false);
    // 如果带有忽略参天错误的标志，需要同步忽略掉广播其他节点的报错
    return broadcat_ret;
}

int tse_create_tablespace(void *space_def, ddl_ctrl_t *ddl_ctrl)
{
    TcDb__TseDDLSpaceDef *req = tc_db__tse_ddlspace_def__unpack(NULL, ddl_ctrl->msg_len, space_def);
    int ret = tse_create_tablespace_impl(req, ddl_ctrl);
    tc_db__tse_ddlspace_def__free_unpacked(req, NULL);
    return ret;
}

static int tse_alter_tablespace_impl(TcDb__TseDDLAlterSpaceDef *req, ddl_ctrl_t *ddl_ctrl)
{
    session_t *session = NULL;
    status_t status = get_and_init_session(&session, &(ddl_ctrl->tch), true);
    if (status != GS_SUCCESS) {
        return status;
    }

    knl_altspace_def_t *def = NULL;
    sql_stmt_t *stmt = session->current_stmt;
    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_altspace_def_t), (pointer_t *)&def));
    tse_put_ddl_sql_2_stmt(session, req->db_name, req->sql_str);
    stmt->context->type = SQL_TYPE_ALTER_TABLESPACE;
    stmt->context->entry = def;
    proto_str2text(req->name, &def->name);
    proto_str2text(req->new_name, &def->rename_space);
    cm_galist_init(&def->datafiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->rename_datafiles, stmt->context, sql_alloc_mem);
    def->action = req->action;
    def->autoextend.enabled = req->auto_extend_size == 0 ? false : true;
    def->autoextend.nextsize = req->auto_extend_size;
    status = knl_alter_space(&stmt->session->knl_session, stmt, def);
    GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    if (status == GS_SUCCESS) {
        do_commit(stmt->session);
    } else {
        do_rollback(stmt->session, NULL);
        GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    }
    tse_ddl_clear_stmt(stmt);

    tse_ddl_broadcast_request broadcast_req = {0};
    FILL_BROADCAST_REQ(broadcast_req, req->db_name, req->sql_str, ddl_ctrl->user_name, ddl_ctrl->user_ip,
                       ddl_ctrl->mysql_inst_id, ddl_ctrl->tch.sql_command);
    int broadcat_ret = tse_execute_mysql_ddl_sql(&ddl_ctrl->tch, &broadcast_req, false);
    // 如果带有忽略参天错误的标志，需要同步忽略掉广播其他节点的报错
    return broadcat_ret;
}

int tse_alter_tablespace(void *space_alter_def, ddl_ctrl_t *ddl_ctrl)
{
    TcDb__TseDDLAlterSpaceDef *req = tc_db__tse_ddlalter_space_def__unpack(NULL, ddl_ctrl->msg_len, space_alter_def);
    int ret = tse_alter_tablespace_impl(req, ddl_ctrl);
    tc_db__tse_ddlalter_space_def__free_unpacked(req, NULL);
    return ret;
}

static int tse_drop_tablespace_impl(TcDb__TseDDLDropSpaceDef *req, ddl_ctrl_t *ddl_ctrl)
{
    session_t *session = NULL;
    status_t status = get_and_init_session(&session, &(ddl_ctrl->tch), true);
    if (status != GS_SUCCESS) {
        return status;
    }

    knl_drop_space_def_t *def = NULL;
    sql_stmt_t *stmt = session->current_stmt;
    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_drop_space_def_t), (pointer_t *)&def));
    tse_put_ddl_sql_2_stmt(session, req->db_name, req->sql_str);
    stmt->context->type = SQL_TYPE_DROP_TABLESPACE;
    stmt->context->entry = def;
    proto_str2text(req->obj_name, &def->obj_name);
    def->options |= TABALESPACE_DFS_AND;
    def->options |= TABALESPACE_INCLUDE;
    def->is_for_create_db = GS_FALSE;
    status = knl_drop_space(&stmt->session->knl_session, stmt, def);
    GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    if (status == GS_SUCCESS) {
        do_commit(stmt->session);
    } else {
        do_rollback(stmt->session, NULL);
        GS_RETURN_IFERR_EX(status, stmt, ddl_ctrl);
    }
    tse_ddl_clear_stmt(stmt);

    tse_ddl_broadcast_request broadcast_req = {0};
    FILL_BROADCAST_REQ(broadcast_req, req->db_name, req->sql_str, ddl_ctrl->user_name, ddl_ctrl->user_ip,
                       ddl_ctrl->mysql_inst_id, ddl_ctrl->tch.sql_command);
    int broadcat_ret = tse_execute_mysql_ddl_sql(&ddl_ctrl->tch, &broadcast_req, false);
    // 如果带有忽略参天错误的标志，需要同步忽略掉广播其他节点的报错
    return broadcat_ret;
}

int tse_drop_tablespace(void *space_drop_def, ddl_ctrl_t *ddl_ctrl)
{
    TcDb__TseDDLDropSpaceDef *req = tc_db__tse_ddldrop_space_def__unpack(NULL, ddl_ctrl->msg_len, space_drop_def);
    int ret = tse_drop_tablespace_impl(req, ddl_ctrl);
    tc_db__tse_ddldrop_space_def__free_unpacked(req, NULL);
    return ret;
}

static void lock_user_ddl(session_t *session)
{
    dls_latch_s(&session->knl_session, &session->knl_session.kernel->db.ddl_latch,
                session->knl_session.id, GS_FALSE, NULL);
    session->knl_session.user_locked_ddl = GS_TRUE;
}

void unlock_user_ddl(session_t *session)
{
    dls_unlatch(&session->knl_session, &session->knl_session.kernel->db.ddl_latch, NULL);
    session->knl_session.user_locked_ddl = GS_FALSE;
}

int tse_lock_instance(tse_lock_table_mode_t lock_type, tianchi_handler_t *tch)
{
    status_t status;
    session_t *session = NULL;
    status = get_and_init_session(&session, tch, true);
    if (status != GS_SUCCESS) {
        return status;
    }

    // 给cantian加全局latch
    if (lock_type == TSE_LOCK_MODE_SHARE) {
        lock_user_ddl(session);
    } else if (lock_type == TSE_LOCK_MODE_EXCLUSIVE) {
        dls_latch_x(&session->knl_session, &session->knl_session.kernel->db.ddl_latch,
                    session->knl_session.id, NULL);
    }

    GS_LOG_RUN_INF("[TSE_LOCK_INSTANCE]:lock_mode:%s, tse_inst_id:%u, conn_id:%u,"
        "knl_session id:%u.", lock_type == TSE_LOCK_MODE_SHARE ? "S_LATCH" : "X_LATCH", tch->inst_id,
        tch->thd_id, session->knl_session.id);
    return GS_SUCCESS;
}

int tse_unlock_instance(tianchi_handler_t *tch)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    if (session == NULL) {
        return GS_ERROR;
    }
    
    tse_set_no_use_other_sess4thd(session);
    if (session->knl_session.user_locked_ddl == GS_TRUE) {
        unlock_user_ddl(session);
        GS_LOG_RUN_INF("[TSE_UNLOCK_INSTANCE]: tse_inst_id:%d, conn_id:%d, knl_session_id:%d.",
                       tch->inst_id, tch->thd_id, session->knl_session.id);
    }
    return GS_SUCCESS;
}
