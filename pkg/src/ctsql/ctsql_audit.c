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
 * ctsql_audit.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/ctsql_audit.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_audit.h"
#include "srv_instance.h"
#include "ctsql_func.h"
#include "cm_util.h"
#include "ast.h"
#ifndef WIN32
#include <syslog.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_syslog_map {
    const char *name;
    int32_t id;
} syslog_map_t;

#ifdef WIN32
#define LOG_AUTH 0
#define LOG_AUTHPRIV 0
#define LOG_CRON 0
#define LOG_DAEMON 0
#define LOG_FTP 0
#define LOG_KERN 0
#define LOG_LOCAL0 0
#define LOG_LOCAL1 0
#define LOG_LOCAL2 0
#define LOG_LOCAL3 0
#define LOG_LOCAL4 0
#define LOG_LOCAL5 0
#define LOG_LOCAL6 0
#define LOG_LOCAL7 0
#define LOG_LPR 0
#define LOG_MAIL 0
#define LOG_NEWS 0
#define LOG_SYSLOG 0
#define LOG_USER 0
#define LOG_UUCP 0
#define LOG_EMERG 0
#define LOG_ALERT 0
#define LOG_CRIT 0
#define LOG_ERR 0
#define LOG_WARNING 0
#define LOG_NOTICE 0
#define LOG_INFO 0
#define LOG_DEBUG 0

#define OPEN_SYSLOG(ident, option, facility)
#define WRITE_SYSLOG(priority, format, ...)
#define CLOSE_SYSLOG()
#else
#define OPEN_SYSLOG(ident, option, facility) openlog(ident, option, facility)
#define WRITE_SYSLOG(priority, format, ...) syslog(priority, format, ##__VA_ARGS__)
#define CLOSE_SYSLOG() closelog()
#endif

static syslog_map_t g_syslog_facilitys[] = {
    { "AUTH", LOG_AUTH },
    { "AUTHPRIV", LOG_AUTHPRIV },
    { "CRON", LOG_CRON },
    { "DAEMON", LOG_DAEMON },
    { "FTP", LOG_FTP },
    { "KERN", LOG_KERN },
    { "LOCAL0", LOG_LOCAL0 },
    { "LOCAL1", LOG_LOCAL1 },
    { "LOCAL2", LOG_LOCAL2 },
    { "LOCAL3", LOG_LOCAL3 },
    { "LOCAL4", LOG_LOCAL4 },
    { "LOCAL5", LOG_LOCAL5 },
    { "LOCAL6", LOG_LOCAL6 },
    { "LOCAL7", LOG_LOCAL7 },
    { "LPR", LOG_LPR },
    { "MAIL", LOG_MAIL },
    { "NEWS", LOG_NEWS },
    { "SYSLOG", LOG_SYSLOG },
    { "USER", LOG_USER },
    { "UUCP", LOG_UUCP }
};

static syslog_map_t g_syslog_prioritys[] = {
    { "EMERG", LOG_EMERG },
    { "ALERT", LOG_ALERT },
    { "CRIT", LOG_CRIT },
    { "ERR", LOG_ERR },
    { "WARNING", LOG_WARNING },
    { "NOTICE", LOG_NOTICE },
    { "INFO", LOG_INFO },
    { "DEBUG", LOG_DEBUG }
};

#define SYSLOG_FACILITY_CNT (sizeof(g_syslog_facilitys) / sizeof(syslog_map_t))
#define SYSLOG_PRIORITY_CNT (sizeof(g_syslog_prioritys) / sizeof(syslog_map_t))

status_t sql_parse_audit_trail_mode(const char *str_trail_mode, uint8_t *mode)
{
    if (cm_str_equal_ins(str_trail_mode, "FILE")) {
        *mode = AUDIT_TRAIL_FILE;
    } else if (cm_str_equal_ins(str_trail_mode, "ALL")) {
        *mode = AUDIT_TRAIL_ALL;
    } else if (cm_str_equal_ins(str_trail_mode, "DB")) {
        *mode = AUDIT_TRAIL_DB;
    } else if (cm_str_equal_ins(str_trail_mode, "SYSLOG")) {
        *mode = AUDIT_TRAIL_SYSLOG;
    } else if (cm_str_equal_ins(str_trail_mode, "NONE")) {
        *mode = AUDIT_TRAIL_NONE;
    } else {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "Only ALL/FILE/DB/SYSLOG/NONE for AUDIT_TRAIL_MODE parameter");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_parse_audit_syslog(char *str_audit_syslog, audit_log_param_t *audit_log_param)
{
    text_t syslog_audit, syslog_facility, syslog_priority;
    uint32 i;

    syslog_audit.str = str_audit_syslog;
    syslog_audit.len = (uint32_t)strlen(str_audit_syslog);

    cm_split_text(&syslog_audit, '.', '\0', &syslog_facility, &syslog_priority);

    for (i = 0; i < SYSLOG_FACILITY_CNT; i++) {
        if (cm_compare_text_str_ins(&syslog_facility, g_syslog_facilitys[i].name) == 0) {
            audit_log_param->syslog_facility = g_syslog_facilitys[i].id;
            break;
        }
    }
    if (i == SYSLOG_FACILITY_CNT) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "invalid facility value for AUDIT_SYSLOG_LEVEL parameter");
        return CT_ERROR;
    }

    for (i = 0; i < SYSLOG_PRIORITY_CNT; i++) {
        if (cm_compare_text_str_ins(&syslog_priority, g_syslog_prioritys[i].name) == 0) {
            audit_log_param->syslog_level = g_syslog_prioritys[i].id;
            break;
        }
    }
    if (i == SYSLOG_PRIORITY_CNT) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "invalid priority value for AUDIT_SYSLOG_LEVEL parameter");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void sql_auditlog_init(const audit_log_param_t *audit_log_param)
{
    if (audit_log_param->audit_trail_mode & AUDIT_TRAIL_SYSLOG) {
        OPEN_SYSLOG("cantiand", LOG_CONS | LOG_PID, audit_log_param->syslog_facility);
    }
}

void sql_auditlog_deinit(const audit_log_param_t *audit_log_param)
{
    if (audit_log_param->audit_trail_mode & AUDIT_TRAIL_SYSLOG) {
        CLOSE_SYSLOG();
    }
}

void sql_auditlog_reinit(const audit_log_param_t *old_audit_log_param, const audit_log_param_t *audit_log_param)
{
    // to close
    if (!(audit_log_param->audit_trail_mode & AUDIT_TRAIL_SYSLOG)) {
        if (old_audit_log_param->audit_trail_mode & AUDIT_TRAIL_SYSLOG) {
            CLOSE_SYSLOG();
        }
        return;
    }

    // to open
    if (old_audit_log_param->audit_trail_mode & AUDIT_TRAIL_SYSLOG) {
        // no change
        if (old_audit_log_param->syslog_facility == audit_log_param->syslog_facility) {
            return;
        } else { // reopen
            CLOSE_SYSLOG();
        }
    }

    OPEN_SYSLOG("cantiand", LOG_CONS | LOG_PID, audit_log_param->syslog_facility);
    return;
}

static inline void sql_get_dml_text(session_t *session, text_t *sql, vmc_t *vmc)
{
    sql_stmt_t *stmt = session->current_stmt;
    uint32 cmd = (uint32)session->agent->recv_pack.head->cmd;

    if (cmd != CS_CMD_EXECUTE && cmd != CS_CMD_FETCH) {
        return;
    }

#if ((defined DB_DEBUG_VERSION) || (defined GS_CANTIAND_PARAM_LOG))
    if (stmt != NULL && stmt->lang_type == LANG_PL && stmt->context != NULL) {
        pl_entity_t *entity = stmt->pl_context;
        pl_line_ctrl_t *line = (pl_line_ctrl_t *)entity->anonymous->body;
        if (line->type == LINE_PROC) {
            pl_line_normal_t *proc_line = (pl_line_normal_t *)line;
            if (proc_line->proc->type == EXPR_NODE_USER_PROC) {
                sql->str = proc_line->proc->word.func.name.str;
                sql->len = proc_line->proc->word.func.name.len;
                return;
            }
        }
    }
#endif

    if (stmt == NULL || stmt->lang_type != LANG_DML ||
        stmt->context == NULL) { // if not prepare or prepare failed, stmt->context is null
        return;
    }

    if (vmc_alloc(vmc, stmt->context->ctrl.text_size + 1, (void **)&sql->str) != CT_SUCCESS) {
        sql->len = 0;
        return;
    }
    sql->len = stmt->context->ctrl.text_size + 1;
    if (ctx_read_text(sql_pool, &stmt->context->ctrl, sql, CT_FALSE) != CT_SUCCESS) {
        sql->len = 0;
        return;
    }
}

static void sql_get_text(session_t *session, text_t *sql, vmc_t *vmc)
{
    if (session->sql_audit.packet_sql.len > 0) {
        *sql = session->sql_audit.packet_sql;
    } else if (session->pipe != NULL) {
        sql_get_dml_text(session, sql, vmc);
    }
}


static void write_audit_syslog(const char *format, ...)
{
    char audit_msg[CT_T2S_LARGER_BUFFER_SIZE];

    va_list var_list;
    va_start(var_list, format);
    if (vsnprintf_s(audit_msg, CT_T2S_LARGER_BUFFER_SIZE, CT_T2S_LARGER_BUFFER_SIZE - 1, format, var_list) < 0) {
        va_end(var_list);
        return;
    }
    va_end(var_list);

    WRITE_SYSLOG(cm_log_param_instance()->audit_param.syslog_level, "%s", audit_msg);
}

static void sql_get_params(sql_stmt_t *stmt, char *buf, uint32 buf_len, write_audit_log_func audit_func)
{
    uint32 i, count;
    sql_param_t *param;
    variant_t value;
    text_buf_t buffer;
    int32 type = CT_TYPE_UNKNOWN;

    CM_INIT_TEXTBUF(&buffer, buf_len, buf);

    count = stmt->context->params->count;

    audit_func("SESSIONID=[%u], PARAMS-SIZE:[%u], PARAMS-COUNT:[%u]", stmt->session->knl_session.id,
        stmt->param_info.paramset_size, count);

    for (i = 0; i < count; i++) {
        char *data = NULL;
        uint32 length = 0;

        param = &stmt->param_info.params[i];
        var_copy(&param->value, &value);
        type = value.type;

        if (value.is_null) {
            audit_func("SESSIONID=[%u],PARAM-VALUE:id=[%u],direct=[%d],type=[%d],len=[%d],value=[NULL]",
                stmt->session->knl_session.id, i, param->direction, type, -1);
            continue;
        }

        switch (type) {
            case CT_TYPE_UINT32:
            case CT_TYPE_INTEGER:
            case CT_TYPE_BIGINT:
            case CT_TYPE_REAL:
            case CT_TYPE_NUMBER:
            case CT_TYPE_NUMBER2:
            case CT_TYPE_DECIMAL:
            case CT_TYPE_DATE:
            case CT_TYPE_TIMESTAMP:
            case CT_TYPE_BOOLEAN:
            case CT_TYPE_TIMESTAMP_TZ_FAKE:
            case CT_TYPE_TIMESTAMP_TZ:
            case CT_TYPE_TIMESTAMP_LTZ:
                if (var_as_string(SESSION_NLS(stmt), &value, &buffer) != CT_SUCCESS) {
                    continue;
                }
                data = value.v_text.str;
                length = value.v_text.len;
                break;

            case CT_TYPE_BINARY:
            case CT_TYPE_VARBINARY:
            case CT_TYPE_RAW:
                if (var_as_string(SESSION_NLS(stmt), &value, &buffer) != CT_SUCCESS) {
                    continue;
                }

                data = value.v_text.str;
                length = value.v_text.len;
                break;

            case CT_TYPE_CLOB:
            case CT_TYPE_BLOB:
            case CT_TYPE_IMAGE:
                data = "LOB";
                length = sql_get_lob_var_length(&value);
                break;

            case CT_TYPE_CHAR:
            case CT_TYPE_VARCHAR:
            case CT_TYPE_STRING:
                data = value.v_text.str;
                length = value.v_text.len;
                break;

            default:
                audit_func("SESSIONID=[%u],PARAM-VALUE:id=[%u],direct=[%d],type=[%d],len=[-2],value=[NULL]",
                    stmt->session->knl_session.id, i, param->direction, type);
                continue;
        }

        if (!CT_IS_LOB_TYPE(type) && length > 0) {
            data[length] = '\0';
        }

        audit_func("SESSIONID=[%u],PARAM-VALUE:id=[%u],direct=[%d],type=[%d],len=[%u],value=[%s]",
            stmt->session->knl_session.id, i, param->direction, type, length, (length == 0) ? "" : data);
    }

    audit_func("\n");
}

static void sql_ignore_passwd_log_core(session_t *session, text_t *sql_text)
{
    bool32 matched = CT_FALSE;
    int32 match_type;

    cm_text_try_map_key2type(&session->sql_audit.sql, &match_type, &matched);
    if (!matched) {
        return;
    }

    text_t l_text;
    text_t r_text;
    text_t sub_text;
    char *pattern_str = g_key_pattern[match_type].type_desc;
    uint32 pattern_len = (uint32)strlen(pattern_str);

    cm_str2text("begin", &sub_text);
    if (cm_text_split(&session->sql_audit.sql, &sub_text, &l_text, &r_text)) {
        sql_text->len = l_text.len + pattern_len;
        sql_text->str = (char *)cm_push(session->stack, (uint32)(sql_text->len + 1));
        if (sql_text->str == NULL) {
            return;
        }
        (void)cm_text2str(&l_text, sql_text->str, sql_text->len);
        MEMS_RETVOID_IFERR(strncpy_s(sql_text->str + l_text.len, pattern_len + 1, pattern_str, pattern_len));
    } else {
        sql_text->len = pattern_len;
        sql_text->str = (char *)cm_push(session->stack, (uint32)(sql_text->len + 1));
        if (sql_text->str == NULL) {
            return;
        }
        MEMS_RETVOID_IFERR(strncpy_s(sql_text->str, sql_text->len + 1, pattern_str, pattern_len));
    }
}

void sql_ignore_passwd_log(void *session, text_t *sql_text)
{
    session_t *sess = (session_t *)session;

    if (sess->sql_audit.need_ignore_pwd && sql_text->len != 0) {
        if (sess->sql_audit.need_copy_sql) {
            sql_ignore_passwd_log_core(sess, sql_text);
        } else {
            sql_text->str = (char *)cm_push(sess->stack, (uint32)(sql_text->len + 1));
            if (sql_text->str == NULL) {
                return;
            }
            MEMS_RETVOID_IFERR(
                strncpy_s(sql_text->str, sql_text->len + 1, sess->sql_audit.sql.str, sess->sql_audit.sql.len));
            cm_text_star_to_one(sql_text);
        }
    }
}
status_t db_write_sysaudit(knl_session_t *session, audit_t *audit_key, text_t *sql_text)
{
    uint32 max_size;
    row_assist_t row_ass;
    table_t *table = NULL;
    char *buffer = NULL;
    status_t status;
    errno_t ret;
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    uint32 buffer_len = sql_text->len + 1;
    if (sql_text->len > CT_MAX_VARCHAR_LEN) {
        buffer_len = CT_MAX_VARCHAR_LEN;
    }
    cursor->row = (row_head_t *)cursor->buf;
    buffer = (char *)cm_push(session->stack, buffer_len);
    ret = memset_sp(buffer, buffer_len, 0, buffer_len);
    if (ret != EOK) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    if (sql_text->len != 0) {
        (void)cm_text2str(sql_text, buffer, buffer_len);
    }
    max_size = session->kernel->attr.max_row_size;
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_AUDIT_ID, CT_INVALID_ID32);
    table = (table_t *)cursor->table;
    row_init(&row_ass, (char *)cursor->row, max_size, table->desc.column_count);
    (void)row_put_str(&row_ass, audit_key->ctime);
    (void)row_put_int32(&row_ass, audit_key->sessionid);
    (void)row_put_int32(&row_ass, audit_key->stmtid);
    (void)row_put_str(&row_ass, audit_key->username);
    (void)row_put_str(&row_ass, audit_key->hostname);
    (void)row_put_str(&row_ass, audit_key->action);
    (void)row_put_int32(&row_ass, audit_key->returncode);
    (void)row_put_str(&row_ass, buffer);

    status = knl_internal_insert(session, cursor);
    CM_RESTORE_STACK(session->stack);
    return status;
}


void sql_record_para_audit_log(void *session, char *log_msg, uint8 audit_trail_mode)
{
    session_t *sess = (session_t *)session;
    write_audit_log_func audit_func = NULL;

    if ((cm_log_param_instance()->audit_param.audit_level & (uint32)SQL_AUDIT_PARAM) == 0) {
        return;
    }

    audit_func = (audit_trail_mode == AUDIT_TRAIL_SYSLOG ? write_audit_syslog : cm_write_audit_log);

    // record params info
    if (sess->current_stmt != NULL && sess->pipe != NULL &&
        strcmp(sess->sql_audit.action, SQL_AUDIT_ACTION_DISCONNECT) != 0) {
        uint32 cmd = (uint32)sess->agent->recv_pack.head->cmd;
        if ((cmd == CS_CMD_EXECUTE || cmd == CS_CMD_PREP_AND_EXEC) &&
            (sess->current_stmt->context != NULL && sess->current_stmt->context->params != NULL &&
            sess->current_stmt->context->params->count != 0) &&
            (sess->current_stmt->param_info.params != NULL && sess->current_stmt->params_ready == CT_TRUE)) {
            sql_get_params(sess->current_stmt, log_msg, CT_T2S_LARGER_BUFFER_SIZE - 1, audit_func);
        }
    }
}

void sql_audit_init_assist(audit_assist_t *audit_ass, session_t *session, status_t status)
{
    int iret_snprintf, tz_hour, tz_min;
    const char *err_msg = NULL;

    audit_ass->sql_text = session->sql_audit.sql;
    sql_ignore_passwd_log(session, &audit_ass->sql_text);
    audit_ass->action = session->sql_audit.action;

    MEMS_RETVOID_IFERR(strcpy_s(audit_ass->db_user, CT_NAME_BUFFER_SIZE, session->db_user));
    MEMS_RETVOID_IFERR(strcpy_s(audit_ass->os_host, CT_HOST_NAME_BUFFER_SIZE, session->os_host));

    // DATE
    audit_ass->tz = g_timer()->tz;
    tz_hour = TIMEZONE_GET_HOUR(audit_ass->tz);
    tz_min = TIMEZONE_GET_MINUTE(audit_ass->tz);
    if (tz_hour >= 0) {
        iret_snprintf =
            snprintf_s(audit_ass->date, CT_MAX_TIME_STRLEN, CT_MAX_TIME_STRLEN - 1, "UTC+%02d:%02d ", tz_hour, tz_min);
    } else {
        iret_snprintf =
            snprintf_s(audit_ass->date, CT_MAX_TIME_STRLEN, CT_MAX_TIME_STRLEN - 1, "UTC%02d:%02d ", tz_hour, tz_min);
    }
    if (iret_snprintf == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
        return;
    }

    (void)cm_date2str(g_timer()->now, "yyyy-mm-dd hh24:mi:ss.ff3", audit_ass->date + iret_snprintf,
        CT_MAX_TIME_STRLEN - iret_snprintf);

    // SESSIONID
    audit_ass->sid = (int32)session->knl_session.id;
    audit_ass->session_id.str = audit_ass->session_buf;
    cm_int2text(audit_ass->sid, &audit_ass->session_id);
    audit_ass->session_id.str[audit_ass->session_id.len] = '\0';

    // STMTID
    audit_ass->stmt_id.len = 0;
    audit_ass->stmt_id.str = audit_ass->stmt_buf;
    if (session->current_stmt != NULL) {
        audit_ass->stmtid = (int32)session->current_stmt->id;
        cm_int2text(audit_ass->stmtid, &audit_ass->stmt_id);
    }
    audit_ass->stmt_id.str[audit_ass->stmt_id.len] = '\0';

    // RETURNCODE
    audit_ass->return_code.str = audit_ass->return_code_buf;
    audit_ass->code = 0;
    if (status != CT_SUCCESS) {
        cm_get_error(&audit_ass->code, &err_msg, NULL);
    }
    PRTS_RETVOID_IFERR(
        snprintf_s(audit_ass->return_code_buf, CT_MAX_NUMBER_LEN, CT_MAX_NUMBER_LEN - 1, "CT-%05d", audit_ass->code));
    audit_ass->return_code.len = (uint32)strlen(audit_ass->return_code_buf);
    audit_ass->return_code.str[audit_ass->return_code.len] = '\0';
}

void sql_audit_write_systab(audit_assist_t *audit_ass, knl_session_t *knl_session)
{
    audit_t audit_key;
    status_t stat;
    audit_key.action = audit_ass->action;
    audit_key.ctime = audit_ass->date;
    audit_key.hostname = audit_ass->os_host;
    audit_key.sessionid = audit_ass->sid;
    audit_key.stmtid = audit_ass->stmtid;

    audit_key.username = audit_ass->db_user;
    audit_key.returncode = audit_ass->code;
    if (knl_begin_auton_rm(knl_session) != CT_SUCCESS) {
        return;
    }
    stat = db_write_sysaudit(knl_session, &audit_key, &audit_ass->sql_text);
    if (stat == CT_ERROR) {
        // start warning
        if (g_instance->audit_log_warning == CT_FALSE) {
            CT_LOG_ALARM(WARN_AUDITLOG, "'instance-name':'%s'}", g_instance->kernel.instance_name);
            g_instance->audit_log_warning = CT_TRUE;
        }
        knl_end_auton_rm(knl_session, CT_ERROR);
        CT_LOG_RUN_WAR("write audit log table error");
        return;
    }
    // remove warning
    if (g_instance->audit_log_warning == CT_TRUE) {
        CT_LOG_ALARM_RECOVER(WARN_AUDITLOG, "'instance-name':'%s'}", g_instance->kernel.instance_name);
        g_instance->audit_log_warning = CT_FALSE;
    }
    knl_end_auton_rm(knl_session, CT_SUCCESS);
}

void sql_audit_create_message(audit_assist_t *audit_ass, char *log_msg, uint32 *log_msg_len)
{
    int iret_snprintf;

    iret_snprintf = snprintf_s(log_msg, CT_T2S_LARGER_BUFFER_SIZE, CT_T2S_LARGER_BUFFER_SIZE - 1,
        "SESSIONID:[%u] \"%s\" STMTID:[%u] \"%s\" USER:[%u] \"%s\" "
        "HOST:[%u] \"%s\" ACTION:[%u] \"%s\" RETURNCODE:[%u] \"%s\" "
        "SQLTEXT:[%u] \"",
        audit_ass->session_id.len, audit_ass->session_id.str,   // SESSIONID
        audit_ass->stmt_id.len, audit_ass->stmt_id.str,         // STMTID
        (uint32)strlen(audit_ass->db_user), audit_ass->db_user, // USER
        (uint32)strlen(audit_ass->os_host), audit_ass->os_host, // HOST
        (uint32)strlen(audit_ass->action), audit_ass->action,   // ACTION
        audit_ass->return_code.len, audit_ass->return_code.str, // RETURNCODE
        audit_ass->sql_text.len);                            // SQLTEXT
    PRTS_RETVOID_IFERR(iret_snprintf);

    if (iret_snprintf > CT_T2S_LARGER_BUFFER_SIZE - 1) {
        *log_msg_len = CT_T2S_LARGER_BUFFER_SIZE - 1;
        log_msg[CT_T2S_LARGER_BUFFER_SIZE - 1] = '\0';
        return;
    }

    *log_msg_len = (uint32)iret_snprintf + audit_ass->sql_text.len + 1;
    if (*log_msg_len > CT_T2S_LARGER_BUFFER_SIZE - 1) {
        *log_msg_len = CT_T2S_LARGER_BUFFER_SIZE - 1;
    }
    if (*log_msg_len > (uint32)iret_snprintf + 1) {
        MEMS_RETVOID_IFERR(memcpy_s(log_msg + iret_snprintf, *log_msg_len - (uint32)iret_snprintf, audit_ass->sql_text.str,
            MIN(*log_msg_len - (uint32)iret_snprintf, audit_ass->sql_text.len)));
    }
    log_msg[*log_msg_len - 1] = '\"';
    log_msg[*log_msg_len] = '\0';
}


void sql_audit_log(void *sess, status_t status, bool8 ignore_sql, bool8 is_log_param)
{
    char *log_msg = cm_get_t2s_addr();
    uint32 log_msg_len;
    audit_assist_t audit_ass;
    session_t *session = (session_t *)sess;
    vmc_t vmc;
    if (cm_log_param_instance()->audit_param.audit_trail_mode == AUDIT_TRAIL_NONE && is_log_param == CT_FALSE) {
        return;
    }

    vmc_init(&session->vmp, &vmc);
    session->sql_audit.sql.len = 0;

    if (!ignore_sql) {
        sql_get_text(session, &session->sql_audit.sql, &vmc);
    }

    sql_audit_init_assist(&audit_ass, session, status);

    if (cm_log_param_instance()->audit_param.audit_trail_mode & AUDIT_TRAIL_FILE) {
        sql_audit_create_message(&audit_ass, log_msg, &log_msg_len);
        CT_LOG_AUDIT("%s\nLENGTH: \"%u\"\n%s\n", audit_ass.date, log_msg_len, log_msg);
        sql_record_para_audit_log(sess, log_msg, AUDIT_TRAIL_FILE);
    }

    if (knl_get_db_status(&session->knl_session) == DB_STATUS_OPEN &&
        knl_get_db_open_status(&session->knl_session) == DB_OPEN_STATUS_NORMAL &&
        (cm_log_param_instance()->audit_param.audit_trail_mode & AUDIT_TRAIL_DB)) {
        sql_audit_write_systab(&audit_ass, &session->knl_session);
    }

    if (cm_log_param_instance()->audit_param.audit_trail_mode & AUDIT_TRAIL_SYSLOG) {
        sql_audit_create_message(&audit_ass, log_msg, &log_msg_len);
        WRITE_SYSLOG(cm_log_param_instance()->audit_param.syslog_level, "LENGTH: \"%u\" %s\n", log_msg_len, log_msg);
        sql_record_para_audit_log(sess, log_msg, AUDIT_TRAIL_SYSLOG);
    }

    vmc_free(&vmc);
}

void sql_record_audit_log(void *sess, status_t status, bool8 ignore_sql)
{
    if ((cm_log_param_instance()->audit_param.audit_level & ((session_t *)sess)->sql_audit.audit_type) == 0) {
        return;
    }

    sql_audit_log(sess, status, ignore_sql, CT_FALSE);
}

void sql_audit_init_assist_ddos(audit_assist_t *audit_ass, const char *ip_str)
{
    int iret_snprintf, tz_hour, tz_min;
    const char *msg = NULL;

    audit_ass->sql_text = g_null_text;
    audit_ass->action = SQL_AUDIT_ACTION_INVALID_ADDRESS_DISCONNECT;

    audit_ass->db_user[0] = '\0';
    MEMS_RETVOID_IFERR(strcpy_s(audit_ass->os_host, CT_HOST_NAME_BUFFER_SIZE, ip_str));

    // DATE
    audit_ass->tz = g_timer()->tz;
    tz_hour = TIMEZONE_GET_HOUR(audit_ass->tz);
    tz_min = TIMEZONE_GET_MINUTE(audit_ass->tz);
    if (tz_hour >= 0) {
        iret_snprintf =
            snprintf_s(audit_ass->date, CT_MAX_TIME_STRLEN, CT_MAX_TIME_STRLEN - 1, "UTC+%02d:%02d ", tz_hour, tz_min);
    } else {
        iret_snprintf =
            snprintf_s(audit_ass->date, CT_MAX_TIME_STRLEN, CT_MAX_TIME_STRLEN - 1, "UTC%02d:%02d ", tz_hour, tz_min);
    }
    if (iret_snprintf == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
        return;
    }

    (void)cm_date2str(g_timer()->now, "yyyy-mm-dd hh24:mi:ss.ff3", audit_ass->date + iret_snprintf,
        CT_MAX_TIME_STRLEN - iret_snprintf);

    // SESSIONID
    audit_ass->sid = 0;
    audit_ass->session_id = g_null_text;

    // STMTID
    audit_ass->stmtid = 0;
    audit_ass->stmt_id = g_null_text;

    // RETURNCODE
    cm_get_error(&audit_ass->code, &msg, NULL);
    audit_ass->return_code.str = audit_ass->return_code_buf;
    PRTS_RETVOID_IFERR(
        snprintf_s(audit_ass->return_code_buf, CT_MAX_NUMBER_LEN, CT_MAX_NUMBER_LEN - 1, "CT-%05d", audit_ass->code));
    audit_ass->return_code.len = (uint32)strlen(audit_ass->return_code_buf);
    audit_ass->return_code.str[audit_ass->return_code.len] = '\0';
}

void sql_audit_log_ddos(const char *ip_str)
{
    audit_assist_t audit_ass;
    char *log_msg = cm_get_t2s_addr();
    uint32 log_msg_len;

    if (cm_log_param_instance()->audit_param.audit_level == 0) {
        return;
    }
    sql_audit_init_assist_ddos(&audit_ass, ip_str);

    if (cm_log_param_instance()->audit_param.audit_trail_mode == AUDIT_TRAIL_FILE ||
        cm_log_param_instance()->audit_param.audit_trail_mode == AUDIT_TRAIL_ALL) {
        sql_audit_create_message(&audit_ass, log_msg, &log_msg_len);
        CT_LOG_AUDIT("%s\nLENGTH: \"%u\"\n%s\n", audit_ass.date, log_msg_len, log_msg);
    }
}

#ifdef __cplusplus
}
#endif
