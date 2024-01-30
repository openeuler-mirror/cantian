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
 * ctsql_audit.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/ctsql_audit.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_AUDIT_H__
#define __SQL_AUDIT_H__

#include "cm_defs.h"
#include "cm_text.h"
#include "cm_log.h"
#include "cm_thread.h"
#include "cs_pipe.h"

#ifdef __cplusplus
extern "C" {
#endif

static const char * const SQL_AUDIT_ACTION_INTERACTIVE_TIMEOUT = "INTERACTIVE_TIMEOUT";
static const char * const SQL_AUDIT_ACTION_DISCONNECT = "DISCONNECT";
static const char * const SQL_AUDIT_ACTION_INVALID_ADDRESS_DISCONNECT = "INVALID ADDRESS DISCONNECT";
static const char * const SQL_AUDIT_ACTION_CONNECT = "CONNECT";
static const char * const SQL_AUDIT_ACTION_AUTH_INIT = "AUTH_INIT";
static const char * const SQL_AUDIT_ACTION_LOCKED = "LOCKED";
static const char * const SQL_AUDIT_ACTION_UNLOCK = "UNLOCK";
static const char * const SQL_AUDIT_ACTION_LOGIN = "LOGIN";
static const char * const SQL_AUDIT_ACTION_LOGOUT = "LOGOUT";
static const char * const SQL_AUDIT_ACTION_CANCEL = "CANCEL";
static const char * const SQL_AUDIT_ACTION_FREE_STMT = "FREE_STMT";
static const char * const SQL_AUDIT_ACTION_PREPARE = "PREPARE";
static const char * const SQL_AUDIT_ACTION_EXECUTE = "EXECUTE";
static const char * const SQL_AUDIT_ACTION_AUTOCOMMIT_EXECUTE = "EXECUTE[AUTOCOMMIT]";
static const char * const SQL_AUDIT_ACTION_FETCH = "FETCH";
static const char * const SQL_AUDIT_ACTION_COMMIT = "COMMIT";
static const char * const SQL_AUDIT_ACTION_ROLLBACK = "ROLLBACK";
static const char * const SQL_AUDIT_ACTION_QUERY = "QUERY";
static const char * const SQL_AUDIT_ACTION_AUTOCOMMIT_QUERY = "QUERY[AUTOCOMMIT]";
static const char * const SQL_AUDIT_ACTION_PREP_EXEC = "PREP_EXEC";
static const char * const SQL_AUDIT_ACTION_PREP_AUTOCOMMIT_EXEC = "PREP_EXEC[AUTOCOMMIT]";
static const char * const SQL_AUDIT_ACTION_LOB_WRITE = "LOB_WRITE";
static const char * const SQL_AUDIT_ACTION_LOB_READ = "LOB_READ";
static const char * const SQL_AUDIT_ACTION_LOAD_DATA = "LOAD_DATA";

static const char * const SQL_AUDIT_ACTION_XA_PREPARE = "XA_PREPARE";
static const char * const SQL_AUDIT_ACTION_XA_COMMIT = "XA_COMMIT";
static const char * const SQL_AUDIT_ACTION_XA_ROLLBACK = "XA_ROLLBACK";
static const char * const SQL_AUDIT_ACTION_XA_START = "XA_START";
static const char * const SQL_AUDIT_ACTION_XA_END = "XA_END";
static const char * const SQL_AUDIT_ACTION_XA_STATUS = "XA_STATUS";

#ifdef Z_SHARDING
static const char * const SQL_AUDIT_ACTION_GTS = "GTS";
static const char * const SQL_AUDIT_ACTION_SEQUENCE = "SEQUENCE";
#endif
static const char * const SQL_AUDIT_ACTION_SHARD_ROLLBACK = "SHARD_ROLLBACK";

typedef struct st_sql_audit {
    const char *action;
    text_t sql;
    text_t packet_sql;
    uint32 audit_type;
    bool32 need_ignore_pwd;
    bool32 need_copy_sql;
} sql_audit_t;

static inline void sql_audit_init(sql_audit_t *sql_audit)
{
    sql_audit->action = "UNKNOWN";
    sql_audit->sql.len = 0;
    sql_audit->packet_sql.len = 0;
    sql_audit->audit_type = SQL_AUDIT_ALL;
    sql_audit->need_ignore_pwd = CT_FALSE;
    sql_audit->need_copy_sql = CT_FALSE;
}

typedef struct st_audit_t {
    char *ctime;
    int32 sessionid;
    int32 stmtid;
    char *username;
    char *hostname;
    const char *action;
    int32 returncode;
} audit_t;

typedef struct st_audit_assist {
    char date[CT_MAX_TIME_STRLEN];
    char session_buf[CT_MAX_NUMBER_LEN];
    char stmt_buf[CT_MAX_NUMBER_LEN];
    char return_code_buf[CT_MAX_NUMBER_LEN];
    char os_host[CT_HOST_NAME_BUFFER_SIZE];
    char db_user[CT_NAME_BUFFER_SIZE];
    const char *action;

    text_t sql_text;
    text_t session_id;
    text_t stmt_id;
    text_t return_code;

    int32 stmtid;
    int32 sid;
    int32 code;
    int32 tz;
} audit_assist_t;

typedef struct st_lsnr_aduit {
    thread_t thread;
    cs_pipe_t pipe;
    int32 error_code;
    char ip_str[CM_MAX_IP_LEN];
} lsnr_aduit_t;

#define SQL_SET_IGNORE_PWD(sess) (sess)->sql_audit.need_ignore_pwd = CT_TRUE
#define SQL_SET_COPY_LOG(sess, value) (sess)->sql_audit.need_copy_sql = (value)
#define SQL_GET_IGNORE_PWD(sess) (sess)->sql_audit.need_ignore_pwd

typedef void (*write_audit_log_func)(const char *format, ...);

status_t sql_parse_audit_trail_mode(const char *str_trail_mode, uint8_t *mode);
status_t sql_parse_audit_syslog(char *str_audit_syslog, audit_log_param_t *audit_log_param);
void sql_auditlog_init(const audit_log_param_t *audit_log_param);
void sql_auditlog_reinit(const audit_log_param_t *old_audit_log_param, const audit_log_param_t *audit_log_param);
void sql_auditlog_deinit(const audit_log_param_t *audit_log_param);
void sql_record_audit_log(void *sess, status_t status, bool8 ignore_sql);
void sql_audit_log(void *sess, status_t status, bool8 ignore_sql, bool8 is_log_param);
void sql_ignore_passwd_log(void *session, text_t *sql_text);
void sql_audit_log_ddos(const char *ip_str);

#ifdef __cplusplus
}
#endif

#endif
