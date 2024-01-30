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
 * gsc_client.c
 *
 *
 * IDENTIFICATION
 * src/driver/gsc/gsc_client.c
 *
 * -------------------------------------------------------------------------
 */
#include "gsc_inner.h"
#include "gsc_client.h"
#include "gsc_stmt.h"
#include "gsc_lob.h"
#include "gsc_fetch.h"

#ifdef __cplusplus
extern "C" {
#endif

enum en_array_format_type {
    ARRAY_USE_BRACE = 0,         // {val1,val2...valn}
    ARRAY_USE_SQUARE_BRACKET = 1 // array['val1','val2'...'valn']
};

#define CLT_ARRAY_MORE *(uint32 *)"..."
#define CLT_ARRAY_PRE_FOR_EXP "array["
#define CLT_ARRAY_END_FOR_EXP "]"
#define CLT_ARRAY_PRE_FOR_DISPLAY '{'
#define CLT_ARRAY_END_FOR_DISPLAY "}"
#define CLT_ARRAY_NULL_FOR_EXP "array[]"
#define CLT_ARRAY_NULL_FOR_DISPLAY "{}"
#define CLT_ARRAY_MORE_ELE_FOR_DISPLAY ", ...}"
/* 1) array element doesn't contain single quote
   2) 8K + 2(single quotes)
   3) for example: '1234567890abcdefghijklmnopqrstu' */
#define CLT_MAX_LEN_WITH_SINGLE_QUOTE_MARK (CT_MAX_COLUMN_SIZE + 2)
/* 1) array element contains single quote which is more than 0,
      and these single quote should be use another single quote as escape character
   2) 2 * 8K + 2(single quotes)
   3) for example: '''123''456''7890abcdefghijklmnopqrstu', there are three single quotes in it */
#define CLT_MAX_LEN_WITH_SINGLE_QUOTE_MARK2 (2 * CT_MAX_COLUMN_SIZE + 2)

void gsc_get_error_position(gsc_conn_t pconn, uint16 *line, uint16 *column)
{
    clt_conn_t *conn = (clt_conn_t *)pconn;

    if (SECUREC_UNLIKELY(line == NULL || column == NULL)) {
        CT_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "line or column");
        return;
    }

    if (SECUREC_UNLIKELY(conn == NULL)) {
        *line = 0;
        *column = 0;
    } else {
        *line = conn->loc.line;
        *column = conn->loc.column;
    }
}

void gsc_get_error(gsc_conn_t pconn, int32 *code, const char **message)
{
    clt_conn_t *conn = (clt_conn_t *)pconn;

    if (SECUREC_UNLIKELY(code == NULL)) {
        CT_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "error code");
        return;
    }

    if (SECUREC_UNLIKELY(message == NULL)) {
        CT_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "message");
        return;
    }

    if (SECUREC_UNLIKELY(conn == NULL)) {
        cm_get_error(code, message, NULL);
    } else {
        if (conn->error_code == ERR_ERRNO_BASE) {
            clt_copy_local_error(conn);
        }

        *code = conn->error_code;
        *message = conn->message;
    }
}

char *gsc_get_message(gsc_conn_t pconn)
{
    clt_conn_t *conn = (clt_conn_t *)pconn;

    if (SECUREC_UNLIKELY(conn == NULL)) {
        CT_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "connection");
        return NULL;
    }

    if (conn->error_code == ERR_ERRNO_BASE) {
        clt_copy_local_error(conn);
    }

    return conn->message;
}

uint32 gsc_get_sid(gsc_conn_t pconn)
{
    clt_conn_t *conn = (clt_conn_t *)pconn;
    return (conn != NULL) ? conn->sid : CT_INVALID_ID32;
}

void gsc_set_paramset_size(gsc_stmt_t pstmt, uint32 sz)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    if (SECUREC_UNLIKELY(stmt == NULL)) {
        CT_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "statement");
        return;
    }

    stmt->paramset_size = sz;
}

status_t gsc_datetime_construct(gsc_stmt_t pstmt, gsc_datetime_t datetime, int32 datatype, uint16 year, uint8 mon,
    uint8 day, uint8 hour, uint8 min, uint8 sec, uint32 fsec, char *timezone, uint32 timezone_len)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    date_detail_t date_detail = { 0 };
    text_t timezone_txt = {
        .str = timezone,
        .len = timezone_len
    };
    date_t encode_date;

    // check input is valid
    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, datetime, "datetime");

    if (!CM_IS_VALID_YEAR(year)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_VALUE, "input year", (uint32)year);
        return CT_ERROR;
    }

    if (!CM_IS_VALID_MONTH(mon)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_VALUE, "input month", (uint32)mon);
        return CT_ERROR;
    }

    if (!CM_IS_VALID_DAY(day)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_VALUE, "input day", (uint32)day);
        return CT_ERROR;
    }

    if (!CM_IS_VALID_HOUR(hour)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_VALUE, "input hour", (uint32)hour);
        return CT_ERROR;
    }

    if (!CM_IS_VALID_MINUTE(min)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_VALUE, "input minute", (uint32)min);
        return CT_ERROR;
    }

    if (!CM_IS_VALID_SECOND(sec)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_VALUE, "input second", (uint32)sec);
        return CT_ERROR;
    }

    if (!CM_IS_VALID_FRAC_SEC(fsec)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_VALUE, "input nano second", (uint32)fsec);
        return CT_ERROR;
    }

    date_detail.year = year;
    date_detail.mon = mon;
    date_detail.day = day;
    date_detail.hour = hour;
    date_detail.min = min;
    date_detail.sec = sec;
    date_detail.millisec = fsec / NANOSECS_PER_MILLISEC;
    date_detail.microsec = (fsec % NANOSECS_PER_MILLISEC) / NANOSECS_PER_MICROSEC;
    date_detail.nanosec = fsec % NANOSECS_PER_MICROSEC;

    encode_date = cm_encode_date(&date_detail);

    switch (datatype) {
        case GSC_TYPE_TIMESTAMP_TZ_FAKE:
        case GSC_TYPE_TIMESTAMP:
            *(timestamp_t *)datetime = encode_date;
            break;

        case GSC_TYPE_TIMESTAMP_LTZ:
            /* parameter type (timestamp-with-local-timezone)'s value in packet should be formatted to db timezone */
            *(timestamp_ltz_t *)datetime = cm_adjust_date_between_two_tzs((timestamp_ltz_t)encode_date,
                stmt->conn->local_sessiontz, stmt->conn->server_info.server_dbtimezone);
            break;

        case GSC_TYPE_TIMESTAMP_TZ:
            GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, timezone, "timezone");
            CT_RETURN_IFERR(cm_text2tzoffset(&timezone_txt, &date_detail.tz_offset));
            ((timestamp_tz_t *)datetime)->tstamp = encode_date;
            ((timestamp_tz_t *)datetime)->tz_offset = date_detail.tz_offset;
            break;

        default:
            CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_VALUE, "timestamp type", (uint32)datatype);
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t gsc_datetime_deconstruct(gsc_stmt_t pstmt, gsc_datetime_t datetime, int32 datatype, uint16 *year, uint8 *mon,
    uint8 *day, uint8 *hour, uint8 *min, uint8 *sec, uint32 *fsec)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    date_detail_t date_detail = { 0 };
    date_t timeinfo = 0;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, datetime, "datetime");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, year, "year");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, mon, "mon");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, day, "day");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, hour, "hour");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, min, "min");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, sec, "sec");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, fsec, "fsec");

    switch (datatype) {
        case GSC_TYPE_TIMESTAMP_TZ_FAKE:
        case GSC_TYPE_TIMESTAMP:
        case GSC_TYPE_TIMESTAMP_LTZ:
            timeinfo = *(timestamp_t *)datetime;
            break;

        case GSC_TYPE_TIMESTAMP_TZ:
            timeinfo = ((timestamp_tz_t *)datetime)->tstamp;
            break;

        default:
            CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_VALUE, "timestamp type", (uint32)datatype);
            return CT_ERROR;
    }

    cm_decode_date(timeinfo, &date_detail);
    *year = date_detail.year;
    *mon = date_detail.mon;
    *day = date_detail.day;
    *hour = date_detail.hour;
    *min = date_detail.min;
    *sec = date_detail.sec;
    *fsec = date_detail.millisec * NANOSECS_PER_MILLISEC + date_detail.microsec * NANOSECS_PER_MICROSEC +
        date_detail.nanosec;

    return CT_SUCCESS;
}

status_t gsc_datetime_get_timezone_name(gsc_stmt_t pstmt, gsc_datetime_t datetime, int32 datatype, char *buf,
    uint32 *buf_len)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    timezone_info_t timezone_info = 0;
    text_t timezone_txt = {
        .str = buf,
        .len = 0
    };

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, datetime, "datetime");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, buf, "buf");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, buf_len, "buf_len");

    switch (datatype) {
        case GSC_TYPE_TIMESTAMP_TZ:
            timezone_info = ((timestamp_tz_t *)datetime)->tz_offset;
            break;
        case GSC_TYPE_TIMESTAMP_LTZ:
            timezone_info = stmt->conn->local_sessiontz;
            break;
        default:
            CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_VALUE, "timestamp type", (uint32)datatype);
            return CT_ERROR;
    }

    if (*buf_len < TIMEZONE_OFFSET_STRLEN) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_STRING_BUF_TOO_SMALL, "time zone buffer", *buf_len);
        return CT_ERROR;
    }
    CT_RETURN_IFERR(cm_tzoffset2text(timezone_info, &timezone_txt));
    *buf_len = timezone_txt.len;

    return CT_SUCCESS;
}

status_t gsc_datetime_get_timezone_offset(gsc_stmt_t pstmt, gsc_datetime_t datetime, int32 datatype, int8 *hour,
    int8 *min)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    timezone_info_t timezone_info = 0;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, datetime, "datetime");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, hour, "hour");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, min, "min");

    switch (datatype) {
        case GSC_TYPE_TIMESTAMP_TZ:
            timezone_info = ((timestamp_tz_t *)datetime)->tz_offset;
            break;
        case GSC_TYPE_TIMESTAMP_LTZ:
            timezone_info = stmt->conn->local_sessiontz;
            break;
        default:
            CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_VALUE, "timestamp type", (uint32)datatype);
            return CT_ERROR;
    }

    *hour = (int8)TIMEZONE_GET_HOUR(timezone_info);
    *min = (int8)TIMEZONE_GET_SIGN_MINUTE(timezone_info);

    return CT_SUCCESS;
}

static inline status_t clt_per_bind_info(clt_stmt_t *stmt, int type, const void *data, int32 *size)
{
    switch (type) {
        case GSC_TYPE_INTEGER:
        case GSC_TYPE_UINT32:
        case GSC_TYPE_BOOLEAN:
            *size = sizeof(int32);
            break;

        case GSC_TYPE_BIGINT:
        case GSC_TYPE_TIMESTAMP:
        case GSC_TYPE_TIMESTAMP_TZ_FAKE:
        case GSC_TYPE_TIMESTAMP_LTZ:
        case GSC_TYPE_NATIVE_DATE:
            *size = sizeof(int64);
            break;

        case GSC_TYPE_REAL:
            *size = sizeof(double);
            break;

        case GSC_TYPE_NUMBER2:
        case GSC_TYPE_NUMBER:
        case GSC_TYPE_DECIMAL:
        case GSC_TYPE_CHAR:
        case GSC_TYPE_VARCHAR:
        case GSC_TYPE_STRING:
        case GSC_TYPE_BINARY:
        case GSC_TYPE_VARBINARY:
        case GSC_TYPE_RAW:
            /* the STRING, BINARY datatype may use 4 extra bytes to store the
               length of its content, thus these spaces should be considered.
               string value putted into send-pack,include body(align 4) and length */
            break;

        case GSC_TYPE_DATE:
            *size = CLT_DATE_BINARY_SIZE;
            break;

        case GSC_TYPE_TIMESTAMP_TZ:
            *size = sizeof(timestamp_tz_t);
            break;

        case GSC_TYPE_INTERVAL_YM:
            *size = sizeof(interval_ym_t);
            break;

        case GSC_TYPE_INTERVAL_DS:
            *size = sizeof(interval_ds_t);
            break;

        case GSC_TYPE_CLOB:
        case GSC_TYPE_BLOB:
        case GSC_TYPE_IMAGE:
        case GSC_TYPE_ARRAY:
            clt_reset_batch_lob((gsc_lob_t *)data, stmt->paramset_size);
            *size = sizeof(gsc_lob_t);
            break;

        default:
            CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_BIND, "bind type not supports");
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t clt_bind_by_pos2(clt_stmt_t *stmt, uint32 pos, int type, const void *data, int32 size, uint16 *ind,
    int32 direction)
{
    clt_param_t *param = NULL;

    if (SECUREC_UNLIKELY(stmt->status < CLI_STMT_PREPARED)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_API_SEQUENCE, "sql is not prepared");
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(pos >= stmt->param_count || pos >= stmt->params.count)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_INDEX, "parameter");
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(!GSC_IS_DATABASE_DATATYPE(type))) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_VALUE, "data type", (uint32)type);
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(direction < GSC_INPUT || direction > GSC_INOUT)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_BIND, "direction only supports GSC_INPUT/GSC_OUT/GSC_INOUT");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(clt_per_bind_info(stmt, type, data, &size));

    param = (clt_param_t *)cm_list_get(&stmt->params, pos);
    param->direction = direction;
    param->bnd_type = type;
    param->bnd_size = size;
    param->bnd_ptr = (char *)data;
    param->ind_ptr = ind;
    param->curr_ptr = NULL;
    param->is_W_CType = CT_FALSE;

    return CT_SUCCESS;
}

status_t gsc_bind_by_pos2(gsc_stmt_t pstmt, uint32 pos, int type, const void *data, int32 size, uint16 *ind,
    int32 direction)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_bind_by_pos2(stmt, pos, type, data, size, ind, direction);
    clt_unlock_conn(stmt->conn);
    return status;
}

status_t gsc_bind_by_pos(gsc_stmt_t pstmt, uint32 pos, int type, const void *data, int32 size, uint16 *ind)
{
    return gsc_bind_by_pos2(pstmt, pos, type, data, size, ind, GSC_INPUT);
}

status_t gsc_bind_value_len_by_pos(gsc_stmt_t pstmt, uint32 pos, const void *data, uint16 *ind, bool32 is_trans,
    bool32 ind_not_null)
{
    clt_param_t *param = NULL;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));

    param = (clt_param_t *)cm_list_get(&stmt->params, pos);
    if (is_trans) {
        param->bnd_ptr = (char *)data;
    }
    if (ind_not_null) {
        param->ind_ptr = ind;
    }

    clt_unlock_conn(stmt->conn);
    return CT_SUCCESS;
}

status_t gsc_sql_set_param_c_type(gsc_stmt_t pstmt, uint32 pos, bool32 ctype)
{
    clt_param_t *param = NULL;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));

    param = (clt_param_t *)cm_list_get(&stmt->params, pos);
    param->is_W_CType = ctype;
    clt_unlock_conn(stmt->conn);
    return CT_SUCCESS;
}

static bool32 clt_is_bind_name_equal_ins(const char *name1, const char *name2)
{
    char *str1 = (char *)name1;
    char *str2 = (char *)name2;

    if (str1[0] == ':') {
        str1++;
    }

    if (str2[0] == ':') {
        str2++;
    }

    return cm_str_equal_ins(str1, str2);
}

status_t gsc_get_paramid_by_name(gsc_stmt_t pstmt, const char *name, unsigned int offset1, unsigned int *pos)
{
    clt_param_t *param = NULL;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    unsigned int offset = offset1;
    GSC_CHECK_OBJECT_NULL_GS(pos, "position pointer");

    for (uint32 i = 0; i < stmt->param_count && i < stmt->params.count; i++) {
        param = (clt_param_t *)cm_list_get(&stmt->params, i);
        if (!clt_is_bind_name_equal_ins(name, param->name)) {
            continue;
        }

        if (offset > 0) {
            offset--;
            continue;
        }

        *pos = i;
        return CT_SUCCESS;
    }
    CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_ATTR, "parameter name", name);
    return CT_ERROR;
}

static status_t clt_bind_by_name2(clt_stmt_t *stmt, const char *name, int32 type, const void *data, int32 size,
    uint16 *ind, int32 direction)
{
    uint32 i;
    uint32 bnd_count = 0;
    clt_param_t *param = NULL;

    if (SECUREC_UNLIKELY(stmt->status < CLI_STMT_PREPARED)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_API_SEQUENCE, "sql is not prepared");
        return CT_ERROR;
    }

    for (i = 0; i < stmt->param_count && i < stmt->params.count; i++) {
        param = (clt_param_t *)cm_list_get(&stmt->params, i);
        if (!clt_is_bind_name_equal_ins(name, param->name)) {
            continue;
        }

        CT_RETURN_IFERR(clt_bind_by_pos2(stmt, i, type, data, size, ind, direction));
        bnd_count++;
    }

    if (bnd_count == 0) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_ATTR, "parameter name", name);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t gsc_bind_by_name2(gsc_stmt_t pstmt, const char *name, int type, const void *data, int32 size, uint16 *ind,
                           int32 direction)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, name, "name");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_bind_by_name2(stmt, name, type, data, size, ind, direction);
    clt_unlock_conn(stmt->conn);
    return status;
}

status_t gsc_bind_by_name(gsc_stmt_t pstmt, const char *name, int type, const void *data, int32 size, uint16 *ind)
{
    return gsc_bind_by_name2(pstmt, name, type, data, size, ind, GSC_INPUT);
}

status_t gsc_desc_column_by_id(gsc_stmt_t pstmt, uint32 id, gsc_column_desc_t *desc)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_desc_column_by_id(stmt, id, desc);
    clt_unlock_conn(stmt->conn);
    return status;
}

static status_t clt_desc_inner_column_by_id(clt_stmt_t *stmt, uint32 id, gsc_inner_column_desc_t *desc)
{
    clt_column_t *column = NULL;

    if (SECUREC_UNLIKELY(id >= stmt->column_count)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_INDEX, "column");
        return CT_ERROR;
    }

    if (desc != NULL) {
        column = (clt_column_t *)cm_list_get(&stmt->columns, id);
        desc->name = column->def.name;
        desc->type = column->def.datatype;
        desc->size = column->def.size;
        desc->precision = column->def.precision;
        desc->scale = column->def.scale;
        desc->nullable = column->def.nullable;
        desc->auto_increment = column->def.auto_increment;
        desc->is_character = column->def.is_character;
        desc->is_array = column->def.is_array;
        desc->is_jsonb = column->def.is_jsonb;
    }

    return CT_SUCCESS;
}

status_t gsc_desc_inner_column_by_id(gsc_stmt_t pstmt, uint32 id, gsc_inner_column_desc_t *desc)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_desc_inner_column_by_id(stmt, id, desc);
    clt_unlock_conn(stmt->conn);
    return status;
}

static status_t clt_desc_column_by_name(clt_stmt_t *stmt, const char *col_name, gsc_column_desc_t *desc)
{
    uint32 i;
    clt_column_t *column = NULL;

    for (i = 0; i < stmt->column_count && i < stmt->columns.count; i++) {
        // get the i-th column
        column = (clt_column_t *)cm_list_get(&stmt->columns, i);
        if (cm_str_equal_ins(col_name, column->def.name)) {
            if (SECUREC_LIKELY(desc != NULL)) {
                desc->name = column->def.name;
                desc->type = column->def.datatype;
                desc->size = column->def.size;
                desc->precision = column->def.precision;
                desc->scale = column->def.scale;
                desc->nullable = column->def.nullable;
                desc->is_character = column->def.is_character;
            }
            return CT_SUCCESS;
        }
    }

    CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_ATTR, "column name", col_name);
    return CT_ERROR;
}

status_t gsc_desc_column_by_name(gsc_stmt_t pstmt, const char *col_name, gsc_column_desc_t *desc)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, col_name, "column name");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_desc_column_by_name(stmt, col_name, desc);
    clt_unlock_conn(stmt->conn);
    return status;
}

static status_t clt_get_desc_attr(clt_stmt_t *stmt, uint32 id, int32 attr, void *data, uint32 *len)
{
    uint32 attr_len = 0;
    clt_column_t *column = NULL;

    if (SECUREC_UNLIKELY(id >= stmt->column_count)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_INDEX, "column");
        return CT_ERROR;
    }

    column = (clt_column_t *)cm_list_get(&stmt->columns, id);

    switch (attr) {
        case GSC_ATTR_NAME:
            attr_len = column->def.name_len;
            *(char **)data = column->def.name;
            break;

        case GSC_ATTR_DATA_SIZE:
            attr_len = sizeof(uint16);
            *(uint16 *)data = column->def.size;
            break;

        case GSC_ATTR_PRECISION:
            attr_len = sizeof(uint8);
            *(uint8 *)data = column->def.precision;
            break;

        case GSC_ATTR_SCALE:
            attr_len = sizeof(int8);
            *(int8 *)data = column->def.scale;
            break;

        case GSC_ATTR_DATA_TYPE:
            attr_len = sizeof(uint16);
            *(uint16 *)data = column->def.datatype;
            break;

        case GSC_ATTR_NULLABLE:
            attr_len = sizeof(uint8);
            *(uint8 *)data = column->def.nullable;
            break;

        case GSC_ATTR_CHAR_USED:
            attr_len = sizeof(uint8);
            *(uint8 *)data = column->def.is_character;
            break;

        case GSC_ATTR_ARRAY_USED:
            attr_len = sizeof(uint8);
            *(uint8 *)data = column->def.is_array;
            break;

        default:
            CT_THROW_ERROR(ERR_CLT_INVALID_VALUE, "describe attribute id", (uint32)attr);
            return CT_ERROR;
    }

    if (len != NULL) {
        *len = attr_len;
    }

    return CT_SUCCESS;
}

status_t gsc_get_desc_attr(gsc_stmt_t pstmt, uint32 id, int32 attr, void *data, uint32 *len)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, data, "value of statement attribute to get");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_get_desc_attr(stmt, id, attr, data, len);
    clt_unlock_conn(stmt->conn);
    return status;
}

status_t gsc_get_column_count(gsc_stmt_t pstmt, uint32 *column_count)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");

    if (SECUREC_LIKELY(column_count != NULL)) {
        *column_count = stmt->column_count;
    }

    return CT_SUCCESS;
}

status_t gsc_get_column_by_id(gsc_stmt_t pstmt, unsigned int id, void **data, unsigned int *size, bool32 *is_null)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_get_column_by_id(stmt, id, data, size, is_null);
    clt_unlock_conn(stmt->conn);
    return status;
}

static status_t clt_get_column_by_name(clt_stmt_t *stmt, const char *col_name, void **data, uint32 *size,
    uint32 *is_null)
{
    uint32 i;
    clt_column_t *column = NULL;

    if (SECUREC_UNLIKELY(stmt->status < CLI_STMT_FETCHING)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_API_SEQUENCE, "statement is not fetched");
        return CT_ERROR;
    }

    for (i = 0; i < stmt->column_count && i < stmt->columns.count; i++) {
        // get the i-th column
        column = (clt_column_t *)cm_list_get(&stmt->columns, i);
        if (cm_str_equal_ins(col_name, column->def.name)) {
            if (SECUREC_LIKELY(size != NULL)) {
                *size = column->size;
            }
            if (SECUREC_LIKELY(is_null != NULL)) {
                *is_null = (column->size == GSC_NULL);
            }
            if (SECUREC_LIKELY(data != NULL)) {
                *data = (column->size == GSC_NULL) ? NULL : ((column->bnd_ptr == NULL) ? column->ptr : column->bnd_ptr);
            }
            return CT_SUCCESS;
        }
    }

    CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_ATTR, "column name", col_name);
    return CT_ERROR;
}

status_t gsc_get_column_by_name(gsc_stmt_t pstmt, const char *col_name, void **data, uint32 *size, uint32 *is_null)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, col_name, "column name");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_get_column_by_name(stmt, col_name, data, size, is_null);
    clt_unlock_conn(stmt->conn);
    return status;
}

uint32 gsc_get_affected_rows(gsc_stmt_t pstmt)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    return (stmt != NULL) ? stmt->affected_rows : 0;
}

#define CLT_CHECK_AS_STR_SIZE(id, buf_size, need_size)                                                             \
    {                                                                                                              \
        if ((buf_size) < (need_size)) {                                                                            \
            CLT_THROW_ERROR(stmt->conn, ERR_CLT_COL_SIZE_TOO_SMALL, (uint32)(id), "as string", (uint32)(buf_size), \
                (uint32)(need_size));                                                                              \
            return CT_ERROR;                                                                                       \
        }                                                                                                          \
    }

status_t gsc_column_as_string_get_data(clt_stmt_t *stmt, const clt_column_t *column, char *str, uint32 buf_size,
    uint32 tsize, void *data)
{
    int32 int_value;
    uint32 uint_value;
    uint32 size = tsize;
    int64 bigint_value;
    double real_value;
    uint32 num_width;
    timestamp_tz_t tstz;
    uint32 read_size;
    text_t fmt_text;
    binary_t bin;
    int32 iret_snprintf;
    dec4_t dec4;
    dec2_t dec2;
    switch (column->def.datatype) {
        case GSC_TYPE_INTEGER:
            int_value =
                CS_DIFFERENT_ENDIAN(stmt->conn->pack.options) ? cs_reverse_int32(*(int32 *)data) : *(int32 *)data;
            PRTS_RETURN_IFERR(snprintf_s(str, buf_size, buf_size - 1, PRINT_FMT_INTEGER, int_value));
            break;
        case GSC_TYPE_UINT32:
            uint_value =
                CS_DIFFERENT_ENDIAN(stmt->conn->pack.options) ? cs_reverse_uint32(*(uint32 *)data) : *(uint32 *)data;
            PRTS_RETURN_IFERR(snprintf_s(str, buf_size, buf_size - 1, PRINT_FMT_UINT32, uint_value));
            break;

        case GSC_TYPE_BIGINT:
            bigint_value =
                CS_DIFFERENT_ENDIAN(stmt->conn->pack.options) ? cs_reverse_int64(*(int64 *)data) : *(int64 *)data;
            PRTS_RETURN_IFERR(snprintf_s(str, buf_size, buf_size - 1, PRINT_FMT_BIGINT, bigint_value));
            break;

        case GSC_TYPE_REAL:
            real_value =
                CS_DIFFERENT_ENDIAN(stmt->conn->pack.options) ? cs_reverse_real(*(double *)data) : *(double *)data;
            CM_SNPRINTF_REAL(iret_snprintf, str, real_value, buf_size);
            PRTS_RETURN_IFERR(iret_snprintf);
            break;
        case GSC_TYPE_NUMBER2:
            num_width = MIN(stmt->conn->num_width + 1, buf_size);
            cm_dec2_copy_ex(&dec2, (const payload_t *)data, (uint8)size);
            if (cm_dec2_to_str(&dec2, num_width, str) != CT_SUCCESS) {
                if (num_width > 1) {
                    MEMS_RETURN_IFERR(memset_s(str, num_width - 1, '#', num_width - 1));
                }
                str[num_width - 1] = '\0';
            }
            break;
        case GSC_TYPE_NUMBER:
        case GSC_TYPE_DECIMAL:
            if (CS_DIFFERENT_ENDIAN(stmt->conn->pack.options)) {
                cm_reverse_dec4(&dec4, (dec4_t *)data);
            } else {
                dec4 = *(dec4_t *)data;
            }
            num_width = MIN(stmt->conn->num_width + 1, buf_size);
            if (cm_dec4_to_str(&dec4, num_width, str) != CT_SUCCESS) {
                if (num_width > 1) {
                    MEMS_RETURN_IFERR(memset_s(str, num_width - 1, '#', num_width - 1));
                }
                str[num_width - 1] = '\0';
            }
            break;

        case GSC_TYPE_BOOLEAN:
            CLT_CHECK_AS_STR_SIZE(column->id, buf_size, GSC_BOOL_BOUND_SIZE);
            int_value =
                CS_DIFFERENT_ENDIAN(stmt->conn->pack.options) ? cs_reverse_int32(*(int32 *)data) : *(int32 *)data;
            (void)cm_bool2str((bool32)int_value, str);
            break;

        case GSC_TYPE_DATE:
            CLT_CHECK_AS_STR_SIZE(column->id, buf_size, GSC_TIME_BOUND_SIZE);
            clt_session_nlsparam_geter(stmt, NLS_DATE_FORMAT, &fmt_text);
            CLT_CHECK_AS_STR_SIZE(column->id, buf_size, fmt_text.len + 1);
            bigint_value =
                CS_DIFFERENT_ENDIAN(stmt->conn->pack.options) ? cs_reverse_int64(*(int64 *)data) : *(int64 *)data;
            return cm_date2str_ex((date_t)bigint_value, &fmt_text, str, buf_size);

        case GSC_TYPE_TIMESTAMP:
        case GSC_TYPE_TIMESTAMP_TZ_FAKE:
        case GSC_TYPE_TIMESTAMP_LTZ:
            CLT_CHECK_AS_STR_SIZE(column->id, buf_size, GSC_TIME_BOUND_SIZE);
            clt_session_nlsparam_geter(stmt, NLS_TIMESTAMP_FORMAT, &fmt_text);
            CLT_CHECK_AS_STR_SIZE(column->id, buf_size, fmt_text.len + 7);
            bigint_value =
                CS_DIFFERENT_ENDIAN(stmt->conn->pack.options) ? cs_reverse_int64(*(int64 *)data) : *(int64 *)data;
            return cm_timestamp2str_ex((timestamp_t)bigint_value, &fmt_text, column->def.precision, str, buf_size);

        case GSC_TYPE_TIMESTAMP_TZ:
            CLT_CHECK_AS_STR_SIZE(column->id, buf_size, GSC_TIME_BOUND_SIZE);
            clt_session_nlsparam_geter(stmt, NLS_TIMESTAMP_TZ_FORMAT, &fmt_text);
            CLT_CHECK_AS_STR_SIZE(column->id, buf_size, fmt_text.len + 7);

            tstz.tstamp = CS_DIFFERENT_ENDIAN(stmt->conn->pack.options) ?
                cs_reverse_int64(((timestamp_tz_t *)data)->tstamp) :
                ((timestamp_tz_t *)data)->tstamp;
            tstz.tz_offset = CS_DIFFERENT_ENDIAN(stmt->conn->pack.options) ?
                cs_reverse_int16(((timestamp_tz_t *)data)->tz_offset) :
                ((timestamp_tz_t *)data)->tz_offset;

            return cm_timestamp_tz2str_ex(&tstz, &fmt_text, column->def.precision, str, buf_size);

        case GSC_TYPE_INTERVAL_YM:
            CLT_CHECK_AS_STR_SIZE(column->id, buf_size, GSC_YM_INTERVAL_BOUND_SIZE);
            int_value =
                CS_DIFFERENT_ENDIAN(stmt->conn->pack.options) ? cs_reverse_int32(*(int32 *)data) : *(int32 *)data;
            (void)cm_yminterval2str_ex((interval_ym_t)int_value, column->def.precision, str);
            break;

        case GSC_TYPE_INTERVAL_DS:
            CLT_CHECK_AS_STR_SIZE(column->id, buf_size, GSC_DS_INTERVAL_BOUND_SIZE);
            bigint_value =
                CS_DIFFERENT_ENDIAN(stmt->conn->pack.options) ? cs_reverse_int64(*(int64 *)data) : *(int64 *)data;
            (void)cm_dsinterval2str_ex((interval_ds_t)bigint_value, column->def.precision, column->def.scale, str,
                buf_size);
            break;

        case GSC_TYPE_CHAR:
        case GSC_TYPE_VARCHAR:
        case GSC_TYPE_STRING:
        case GSC_TYPE_BINARY:
        case GSC_TYPE_VARBINARY:
            // binary display like mysql
            size = (size >= buf_size - 1) ? buf_size - 1 : size;
            if (size != 0) {
                MEMS_RETURN_IFERR(memcpy_s(str, buf_size, data, size));
            }
            str[size] = '\0';
            break;

        case GSC_TYPE_RAW:
            bin.bytes = (uint8 *)data;
            bin.size = size;
            return cm_bin2str(&bin, CT_FALSE, str, buf_size);

        case GSC_TYPE_CLOB:
            return clt_clob_as_string(stmt, data, str, buf_size, &read_size);

        case GSC_TYPE_BLOB:
            return clt_blob_as_string(stmt, data, str, buf_size, &read_size);

        case GSC_TYPE_IMAGE:
            return clt_image_as_string(stmt, data, str, buf_size, &read_size);

        default:
            PRTS_RETURN_IFERR(snprintf_s(str, buf_size, buf_size - 1, "<UNKNOWN TYPE>"));
            break;
    }

    return CT_SUCCESS;
}

static status_t clt_element_as_string(clt_stmt_t *stmt, clt_array_assist_t *aa, const char *data, uint32 data_len,
    uint32 *full, uint32 array_format)
{
    int ret;
    uint32 free;
    char *last_str = CLT_ARRAY_MORE_ELE_FOR_DISPLAY;

    free = aa->dst_len - aa->dst_offset;
    /* retain enough buffer size for the last */
    if (free <= data_len + strlen(last_str)) {
        *full = CT_TRUE;
        if (array_format == ARRAY_USE_SQUARE_BRACKET) {
            CLT_THROW_ERROR(stmt->conn, ERR_CLT_BUF_SIZE_TOO_SMALL,
                "to export Array data with \'filetype=txt\', Please use \'filetype=bin\'");
            return CT_ERROR;
        } else {
            ret = strncpy_sp(aa->dst + aa->dst_offset, free, last_str, strlen(last_str));
            if (ret != EOK) {
                CLT_THROW_ERROR(stmt->conn, ERR_SYSTEM_CALL, ret);
                return CT_ERROR;
            }
        }
        return CT_SUCCESS;
    }

    ret = strncpy_sp(aa->dst + aa->dst_offset, free, data, data_len);
    if (ret != EOK) {
        CLT_THROW_ERROR(stmt->conn, ERR_SYSTEM_CALL, ret);
        *full = CT_TRUE;
        return CT_ERROR;
    }

    aa->dst_offset += data_len;
    return CT_SUCCESS;
}

static status_t clt_gen_array_prefix(clt_stmt_t *stmt, clt_array_assist_t *aa, uint32 *full, uint32 subscript,
    uint32 array_format)
{
    if (array_format == ARRAY_USE_SQUARE_BRACKET) {
        int len = strlen(CLT_ARRAY_PRE_FOR_EXP);
        uint32 free = aa->dst_len - aa->dst_offset;
        int ret = strncpy_sp(aa->dst + aa->dst_offset, free, CLT_ARRAY_PRE_FOR_EXP, len);
        if (ret != EOK) {
            CLT_THROW_ERROR(stmt->conn, ERR_SYSTEM_CALL, ret);
            *full = CT_TRUE;
            return CT_ERROR;
        }
        aa->dst_offset += len;
    } else {
        aa->dst[aa->dst_offset++] = CLT_ARRAY_PRE_FOR_DISPLAY;
    }
    aa->expect_subscript = subscript + 1;
    return CT_SUCCESS;
}

static status_t clt_gen_null_or_empty_ele(char *col_value, uint32 offset, uint32 array_format)
{
    if (offset == ELEMENT_NULL_OFFSET) {
        /* null elements */
        if (strncpy_sp(col_value, CT_MAX_COLUMN_SIZE, "NULL", strlen("NULL")) != EOK) {
            return CT_ERROR;
        }
    } else {
        /* empty string */
        if (array_format == ARRAY_USE_SQUARE_BRACKET) {
            if (strncpy_sp(col_value, CT_MAX_COLUMN_SIZE, "'\"\"'", strlen("'\"\"'")) != EOK) {
                return CT_ERROR;
            }
        } else {
            if (strncpy_sp(col_value, CT_MAX_COLUMN_SIZE, "\"\"", strlen("\"\"")) != EOK) {
                return CT_ERROR;
            }
        }
    }
    return CT_SUCCESS;
}

static status_t clt_gen_ele_with_single_quote(clt_stmt_t *stmt, char **elem, char *local_buf)
{
    bool32 exist_flag = CT_FALSE;
    uint32 max_len = CT_MAX_COLUMN_SIZE + 1;
    uint32 len;

    /* 1) if elem has single quote as element, elem will be rewrittened into local_buf
       2) elem[0] or local_buf[0] is reversed for single quote which is used for mark border
       3) the max buf len of 'local_buf + 1' should be  CLT_MAX_LEN_WITH_SINGLE_QUOTE_MARK2 */
    CT_RETURN_IFERR(cm_replace_quotation(*elem + 1, local_buf + 1, CLT_MAX_LEN_WITH_SINGLE_QUOTE_MARK2, &exist_flag));

    if (exist_flag) {
        *elem = local_buf;
        max_len = CLT_MAX_LEN_WITH_SINGLE_QUOTE_MARK2 - 1;
    }

    (*elem)[0] = '\'';
    len = strlen(*elem);
    if (len > max_len) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_VALUE, "array element size", len);
        return CT_ERROR;
    }
    (*elem)[len] = '\'';
    (*elem)[len + 1] = '\0';

    return CT_SUCCESS;
}

static status_t clt_elements_as_string(clt_stmt_t *stmt, const clt_column_t *column, elem_dir_t *dir,
    clt_array_assist_t *aa, uint32 *full, uint32 array_format)
{
    uint32 nbytes, subscript, size, offset;
    bool32 eof = CT_FALSE;
    bool32 need_convert = CS_DIFFERENT_ENDIAN(stmt->conn->pack.options);
    char col_value[CLT_MAX_LEN_WITH_SINGLE_QUOTE_MARK + 1] = { 0 };
    char local_buf[CLT_MAX_LEN_WITH_SINGLE_QUOTE_MARK2 + 1] = { 0 };
    char *elem = col_value;

    size = need_convert ? cs_reverse_uint32(dir->size) : dir->size;
    subscript = need_convert ? cs_reverse_uint32(dir->subscript) : dir->subscript;
    offset = need_convert ? cs_reverse_uint32(dir->offset) : dir->offset;

    if (aa->expect_subscript == CT_INVALID_ID32) {
        /* the first element of the array */
        CT_RETURN_IFERR(clt_gen_array_prefix(stmt, aa, full, subscript, array_format));
    } else {
        /* 1) For display: array output format : {val1,val2,...}
           2) For export: array output format : array['val1','val2',...] */
        while (subscript > aa->expect_subscript) {
            /* fill with null */
            CT_RETURN_IFERR(clt_element_as_string(stmt, aa, ",NULL", (uint32)strlen(",NULL"), full, array_format));

            if (*full == CT_TRUE) {
                return CT_SUCCESS;
            }

            aa->expect_subscript++;
        }
        aa->dst[aa->dst_offset++] = ',';
        aa->expect_subscript++;
    }

    if (size == 0) {
        CT_RETURN_IFERR(clt_gen_null_or_empty_ele(elem, offset, array_format));
    } else {
        /* get the element's value */
        CT_RETURN_IFERR(clt_read_blob(stmt, aa->locator, offset, aa->ele_val, size, &nbytes, &eof));

        if (nbytes != size) {
            CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_VALUE, "array element size", size);
            return CT_ERROR;
        }

        if (array_format == ARRAY_USE_SQUARE_BRACKET) {
            /* elem[0] is reversed for single quote which is used to mark left border of array element */
            CT_RETURN_IFERR(
                gsc_column_as_string_get_data(stmt, column, elem + 1, CT_MAX_COLUMN_SIZE + 1, size, aa->ele_val));
            CT_RETURN_IFERR(clt_gen_ele_with_single_quote(stmt, &elem, local_buf));
        } else {
            CT_RETURN_IFERR(
                gsc_column_as_string_get_data(stmt, column, elem, CT_MAX_COLUMN_SIZE + 1, size, aa->ele_val));
        }
    }

    return clt_element_as_string(stmt, aa, elem, (uint32)strlen(elem), full, array_format);
}

static status_t clt_get_dir(clt_stmt_t *stmt, void *locator, elem_dir_t *dir, uint32 dir_size)
{
    uint32 nbytes;
    uint32 eof;
    uint32 offset = sizeof(array_head_t);
    uint32 remain = dir_size;
    while (remain > 0) {
        if (clt_read_blob(stmt, locator, offset, (char *)dir + (dir_size - remain), remain, &nbytes, &eof) !=
            CT_SUCCESS) {
            free(dir);
            CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_VALUE, "array elements' size", dir_size);
            return CT_ERROR;
        }
        remain -= nbytes;
        offset += nbytes;
    }
    return CT_SUCCESS;
}

static status_t clt_array_as_string_inner(clt_stmt_t *stmt, void *locator, const clt_column_t *column, char *str,
    uint32 buf_size, uint32 array_format)
{
    uint32 i, nbytes, dir_size;
    uint32 eof = CT_FALSE;
    uint32 full = CT_FALSE;
    char data[CT_MAX_COLUMN_SIZE + 1] = { 0 };
    char *end_array = ((array_format == ARRAY_USE_BRACE) ? CLT_ARRAY_END_FOR_DISPLAY : CLT_ARRAY_END_FOR_EXP);
    char *null_array = ((array_format == ARRAY_USE_BRACE) ? CLT_ARRAY_NULL_FOR_DISPLAY : CLT_ARRAY_NULL_FOR_EXP);
    clt_array_assist_t aa;
    elem_dir_t *dir = NULL;
    errno_t errcode;
    array_head_t head;

    /* get the array head information */
    CT_RETURN_IFERR(clt_read_blob(stmt, locator, 0, (void *)&head, sizeof(head), &nbytes, &eof));

    /* no elements in array */
    if (head.count == 0) {
        MEMS_RETURN_IFERR(memcpy_sp(str, buf_size, null_array, strlen(null_array) + 1));
        return CT_SUCCESS;
    }

    /* get elements' directory */
    dir_size = head.count * sizeof(elem_dir_t);
    dir = (elem_dir_t *)malloc(dir_size);
    if (dir == NULL) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_TOO_MANY_ELEMENTS);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(clt_get_dir(stmt, locator, dir, dir_size));

    aa.ele_val = data;
    aa.dst = str;
    aa.dst_len = buf_size;
    aa.dst_offset = 0;
    aa.expect_subscript = CT_INVALID_ID32;
    aa.locator = locator;
    for (i = 0; i < head.count; i++) {
        if (clt_elements_as_string(stmt, column, dir + i, &aa, &full, array_format) != CT_SUCCESS) {
            free(dir);
            return CT_ERROR;
        }

        CT_BREAK_IF_TRUE(full);

        if (i == head.count - 1) {
            errcode = strncpy_s(aa.dst + aa.dst_offset, (uint32)(aa.dst_len - aa.dst_offset), end_array, 1);
            if (errcode != EOK) {
                free(dir);
                CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
                return CT_ERROR;
            }
            aa.dst[++aa.dst_offset] = '\0';
        }
    }

    free(dir);
    return CT_SUCCESS;
}

static status_t clt_array_as_string(clt_stmt_t *stmt, void *locator, const clt_column_t *column, char *str,
    uint32 buf_size, uint32 array_format)
{
    char *null_array = ((array_format == ARRAY_USE_BRACE) ? CLT_ARRAY_NULL_FOR_DISPLAY : CLT_ARRAY_NULL_FOR_EXP);

    if (buf_size < strlen(null_array) + 1) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_COL_SIZE_TOO_SMALL, column->id, "as string", buf_size, strlen(null_array));
        return CT_ERROR;
    }

    if (stmt->conn->autotrace) {
        *(uint32 *)str = CLT_ARRAY_MORE;
        return CT_SUCCESS;
    }

    if (column->size == 0) {
        MEMS_RETURN_IFERR(memcpy_sp(str, buf_size, null_array, strlen(null_array) + 1));
        return CT_SUCCESS;
    }

    return clt_array_as_string_inner(stmt, locator, column, str, buf_size, array_format);
}

static status_t clt_column_as_string(clt_stmt_t *stmt, uint32 id, char *str, uint32 buf_size, uint32 array_format)
{
    void *data = NULL;
    uint32 size, is_null;
    const clt_column_t *column = NULL;

    if (SECUREC_UNLIKELY(stmt->status < CLI_STMT_FETCHING)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_API_SEQUENCE, "statement is not fetched");
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(id >= stmt->column_count || id >= stmt->columns.count)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_INDEX, "column");
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(str == NULL || buf_size <= 1)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_STRING_BUF_TOO_SMALL, "column", id);
        return CT_ERROR;
    }
    str[0] = '\0';

    column = (clt_column_t *)cm_list_get(&stmt->columns, id);
    is_null = (column->size == GSC_NULL);
    data = column->ptr;
    size = column->size;

    if (is_null) {
        if (column->def.datatype == GSC_TYPE_CURSOR) {
            PRTS_RETURN_IFERR(snprintf_s(str, buf_size, buf_size - 1, "CURSOR STATEMENT"));
        }
        return CT_SUCCESS;
    }

    if (column->def.is_array == CT_TRUE) {
        return clt_array_as_string(stmt, data, column, str, buf_size, array_format);
    }

    return gsc_column_as_string_get_data(stmt, column, str, buf_size, size, data);
}

status_t gsc_column_as_string(gsc_stmt_t pstmt, uint32 id, char *str, uint32 buf_size)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_column_as_string(stmt, id, str, buf_size, ARRAY_USE_BRACE);
    clt_unlock_conn(stmt->conn);
    return status;
}

status_t gsc_column_as_array(gsc_stmt_t pstmt, uint32 id, char *str, uint32 buf_size)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_column_as_string(stmt, id, str, buf_size, ARRAY_USE_SQUARE_BRACKET);
    clt_unlock_conn(stmt->conn);
    return status;
}

static status_t clt_bind_column(clt_stmt_t *stmt, uint32 id, uint16 bind_type, uint16 bind_size, void *bind_ptr,
    uint16 *ind_ptr)
{
    clt_column_t *column = NULL;

    if (SECUREC_UNLIKELY(stmt->status < CLI_STMT_PREPARED)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_API_SEQUENCE, "statement is not prepared");
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(id >= stmt->column_count || id >= stmt->columns.count)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_INDEX, "column");
        return CT_ERROR;
    }

    column = (clt_column_t *)cm_list_get(&stmt->columns, id);
    if (!(bind_type == column->def.datatype || GSC_IS_STRING_TYPE(bind_type) || GSC_IS_BINARY_TYPE(bind_type) ||
        (GSC_IS_DATE_TYPE(bind_type) &&
        (GSC_IS_DATE_TYPE(column->def.datatype) || GSC_IS_STRING_TYPE(column->def.datatype))) ||
        (GSC_IS_NUMBER_TYPE(bind_type) &&
        (GSC_IS_NUMBER_TYPE(column->def.datatype) || GSC_IS_STRING_TYPE(column->def.datatype))))) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_BIND, "bind type do not match with column type");
        return CT_ERROR;
    }

    column->bnd_type = (uint8)bind_type;
    column->bnd_size = bind_size;
    column->bnd_ptr = (char *)bind_ptr;
    column->ind_ptr = ind_ptr;
    return CT_SUCCESS;
}
status_t gsc_bind_column(gsc_stmt_t pstmt, uint32 id, uint16 bind_type, uint16 bind_size, void *bind_ptr,
    uint16 *ind_ptr)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_bind_column(stmt, id, bind_type, bind_size, bind_ptr, ind_ptr);
    clt_unlock_conn(stmt->conn);
    return status;
}

gsc_stmt_t gsc_get_query_stmt(gsc_conn_t pconn)
{
    clt_conn_t *conn = (clt_conn_t *)pconn;
    return (conn != NULL) ? (gsc_stmt_t)conn->query.query_stmt : NULL;
}

static status_t clt_get_implicit_resultset(clt_stmt_t *stmt, gsc_stmt_t *resultset)
{
    clt_stmt_t *sub_stmt = NULL;
    uint32 *id = NULL;
    clt_rs_stmt_t *rs_stmt = NULL;

    *resultset = NULL;

    if (stmt->resultset.pos + 1 > stmt->resultset.stmt_ids.count) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(clt_alloc_stmt(stmt->conn, &sub_stmt));
    rs_stmt = (clt_rs_stmt_t *)cm_list_get(&stmt->resultset.stmt_ids, stmt->resultset.pos);
    sub_stmt->stmt_id = rs_stmt->stmt_id;
    sub_stmt->fetch_mode = rs_stmt->fetch_mode;

    if (clt_prepare_stmt_pack(sub_stmt) != CT_SUCCESS || clt_remote_fetch(sub_stmt) != CT_SUCCESS) {
        clt_free_stmt(sub_stmt);
        return CT_ERROR;
    }
    sub_stmt->status = CLI_STMT_EXECUTED;
    sub_stmt->fetch_mode = 0;

    if (cm_list_new(&stmt->resultset.ids, (void **)&id) != CT_SUCCESS) {
        clt_free_stmt(sub_stmt);
        return CT_ERROR;
    }
    *id = (uint32)sub_stmt->id;

    *resultset = (gsc_stmt_t)sub_stmt;
    stmt->resultset.pos++;
    return CT_SUCCESS;
}
status_t gsc_get_implicit_resultset(gsc_stmt_t pstmt, gsc_stmt_t *resultset)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, resultset, "resultset");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_get_implicit_resultset(stmt, resultset);
    clt_unlock_conn(stmt->conn);
    return status;
}

static status_t clt_desc_outparam_by_id(clt_stmt_t *stmt, uint32 id, gsc_outparam_desc_t *desc)
{
    clt_outparam_t *outparam = NULL;

    if (SECUREC_UNLIKELY(stmt->status < CLI_STMT_PREPARED)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_API_SEQUENCE, "sql is not prepared");
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(id >= stmt->outparam_count || id >= stmt->outparams.count)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_INDEX, "outparam");
        return CT_ERROR;
    }

    outparam = (clt_outparam_t *)cm_list_get(&stmt->outparams, id);
    desc->name = outparam->def.name;
    desc->size = outparam->def.size;
    desc->direction = outparam->def.direction;
    desc->type = outparam->def.datatype;
    return CT_SUCCESS;
}
status_t gsc_desc_outparam_by_id(gsc_stmt_t pstmt, uint32 id, gsc_outparam_desc_t *desc)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, desc, "desc");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_desc_outparam_by_id(stmt, id, desc);
    clt_unlock_conn(stmt->conn);
    return status;
}

static status_t clt_desc_outparam_by_name(clt_stmt_t *stmt, const char *name, gsc_outparam_desc_t *desc)
{
    clt_outparam_t *outparam = NULL;
    uint32 i;

    if (SECUREC_UNLIKELY(stmt->status < CLI_STMT_PREPARED)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_API_SEQUENCE, "sql is not prepared");
        return CT_ERROR;
    }

    for (i = 0; i < stmt->outparam_count && i < stmt->outparams.count; i++) {
        // get the i-th outparam
        outparam = (clt_outparam_t *)cm_list_get(&stmt->outparams, i);
        if (cm_str_equal_ins(name, outparam->def.name)) {
            desc->name = outparam->def.name;
            desc->size = outparam->def.size;
            desc->direction = outparam->def.direction;
            desc->type = outparam->def.datatype;
            return CT_SUCCESS;
        }
    }

    CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_ATTR, "outparam name", name);
    return CT_ERROR;
}
status_t gsc_desc_outparam_by_name(gsc_stmt_t pstmt, const char *name, gsc_outparam_desc_t *desc)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, name, "name");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, desc, "desc");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_desc_outparam_by_name(stmt, name, desc);
    clt_unlock_conn(stmt->conn);
    return status;
}

status_t gsc_outparam_as_string_get_data(clt_stmt_t *stmt, uint32 id, char *str, uint32 buf_size,
    const clt_outparam_t *outparam, uint32 tsize, void *data)
{
    int32 int_value;
    int64 bigint_value;
    double real_value;
    uint32 num_width;
    timestamp_tz_t tstz;
    uint32 read_size;
    uint32 size = tsize;
    text_t fmt_text;
    binary_t bin;
    int32 iret_snprintf;
    dec2_t dec2;
    switch (outparam->def.datatype) {
        case GSC_TYPE_UINT32:
            int_value =
                CS_DIFFERENT_ENDIAN(stmt->conn->pack.options) ? cs_reverse_uint32(*(uint32 *)data) : *(uint32 *)data;
            PRTS_RETURN_IFERR(snprintf_s(str, buf_size, buf_size - 1, PRINT_FMT_UINT32, (uint32)int_value));
            break;
        case GSC_TYPE_INTEGER:
            int_value =
                CS_DIFFERENT_ENDIAN(stmt->conn->pack.options) ? cs_reverse_int32(*(int32 *)data) : *(int32 *)data;
            PRTS_RETURN_IFERR(snprintf_s(str, buf_size, buf_size - 1, PRINT_FMT_INTEGER, int_value));

            break;

        case GSC_TYPE_BIGINT:
            bigint_value =
                CS_DIFFERENT_ENDIAN(stmt->conn->pack.options) ? cs_reverse_int64(*(int64 *)data) : *(int64 *)data;
            PRTS_RETURN_IFERR(snprintf_s(str, buf_size, buf_size - 1, PRINT_FMT_BIGINT, bigint_value));
            break;

        case GSC_TYPE_REAL:
            real_value =
                CS_DIFFERENT_ENDIAN(stmt->conn->pack.options) ? cs_reverse_real(*(double *)data) : *(double *)data;
            CM_SNPRINTF_REAL(iret_snprintf, str, real_value, buf_size);
            PRTS_RETURN_IFERR(iret_snprintf);
            break;

        case GSC_TYPE_NUMBER2:
            num_width = MIN(stmt->conn->num_width + 1, buf_size);
            cm_dec2_copy_ex(&dec2, (const payload_t *)data, (uint8)size);
            if (cm_dec2_to_str(&dec2, num_width, str) != CT_SUCCESS) {
                if (num_width != 0) {
                    MEMS_RETURN_IFERR(memset_s(str, num_width, '#', num_width));
                }
                str[num_width] = '\0';
            }
            break;
        case GSC_TYPE_NUMBER:
        case GSC_TYPE_DECIMAL: {
            num_width = MIN(stmt->conn->num_width, buf_size - 1);
            if (cm_dec4_to_str((dec4_t *)data, num_width, str) != CT_SUCCESS) {
                if (num_width != 0) {
                    MEMS_RETURN_IFERR(memset_s(str, num_width, '#', num_width));
                }
                str[num_width] = '\0';
            }
            break;
        }

        case GSC_TYPE_BOOLEAN:
            CLT_CHECK_AS_STR_SIZE(id, buf_size, GSC_BOOL_BOUND_SIZE);
            int_value =
                CS_DIFFERENT_ENDIAN(stmt->conn->pack.options) ? cs_reverse_int32(*(int32 *)data) : *(int32 *)data;
            (void)cm_bool2str((bool32)int_value, str);
            break;

        case GSC_TYPE_DATE:
            CLT_CHECK_AS_STR_SIZE(id, buf_size, GSC_TIME_BOUND_SIZE);
            clt_session_nlsparam_geter(stmt, NLS_DATE_FORMAT, &fmt_text);
            CLT_CHECK_AS_STR_SIZE(id, buf_size, fmt_text.len + 1);
            bigint_value =
                CS_DIFFERENT_ENDIAN(stmt->conn->pack.options) ? cs_reverse_int64(*(int64 *)data) : *(int64 *)data;
            return cm_date2str_ex((date_t)bigint_value, &fmt_text, str, buf_size);

        case GSC_TYPE_TIMESTAMP:
        case GSC_TYPE_TIMESTAMP_TZ_FAKE:
        case GSC_TYPE_TIMESTAMP_LTZ:
            CLT_CHECK_AS_STR_SIZE(id, buf_size, GSC_TIME_BOUND_SIZE);
            clt_session_nlsparam_geter(stmt, NLS_TIMESTAMP_FORMAT, &fmt_text);
            CLT_CHECK_AS_STR_SIZE(id, buf_size, fmt_text.len + 7);
            bigint_value =
                CS_DIFFERENT_ENDIAN(stmt->conn->pack.options) ? cs_reverse_int64(*(int64 *)data) : *(int64 *)data;
            return cm_timestamp2str_ex((timestamp_t)bigint_value, &fmt_text, CT_DEFAULT_DATETIME_PRECISION, str,
                buf_size);

        case GSC_TYPE_TIMESTAMP_TZ:
            CLT_CHECK_AS_STR_SIZE(id, buf_size, GSC_TIME_BOUND_SIZE);
            clt_session_nlsparam_geter(stmt, NLS_TIMESTAMP_TZ_FORMAT, &fmt_text);
            CLT_CHECK_AS_STR_SIZE(id, buf_size, fmt_text.len + 1);

            tstz.tstamp = CS_DIFFERENT_ENDIAN(stmt->conn->pack.options) ?
                cs_reverse_int64(((timestamp_tz_t *)data)->tstamp) :
                ((timestamp_tz_t *)data)->tstamp;
            tstz.tz_offset = CS_DIFFERENT_ENDIAN(stmt->conn->pack.options) ?
                cs_reverse_int16(((timestamp_tz_t *)data)->tz_offset) :
                ((timestamp_tz_t *)data)->tz_offset;

            return cm_timestamp_tz2str_ex(&tstz, &fmt_text, CT_DEFAULT_DATETIME_PRECISION, str, buf_size);

        case GSC_TYPE_INTERVAL_YM:
            CLT_CHECK_AS_STR_SIZE(id, buf_size, GSC_YM_INTERVAL_BOUND_SIZE);
            int_value =
                CS_DIFFERENT_ENDIAN(stmt->conn->pack.options) ? cs_reverse_int32(*(int32 *)data) : *(int32 *)data;
            (void)cm_yminterval2str((interval_ym_t)int_value, str);
            break;

        case GSC_TYPE_INTERVAL_DS:
            CLT_CHECK_AS_STR_SIZE(id, buf_size, GSC_DS_INTERVAL_BOUND_SIZE);
            bigint_value =
                CS_DIFFERENT_ENDIAN(stmt->conn->pack.options) ? cs_reverse_int64(*(int64 *)data) : *(int64 *)data;
            (void)cm_dsinterval2str((interval_ds_t)bigint_value, str, buf_size);
            break;

        case GSC_TYPE_CHAR:
        case GSC_TYPE_VARCHAR:
        case GSC_TYPE_STRING:
        case GSC_TYPE_BINARY:
        case GSC_TYPE_VARBINARY:
            size = (size >= buf_size - 1) ? buf_size - 1 : size;
            if (size != 0) {
                MEMS_RETURN_IFERR(memcpy_s(str, buf_size, data, size));
            }
            str[size] = '\0';
            break;

        case GSC_TYPE_RAW:
            bin.bytes = (uint8 *)data;
            bin.size = size;
            return cm_bin2str(&bin, CT_FALSE, str, buf_size);

        case GSC_TYPE_CLOB:
            return clt_clob_as_string(stmt, data, str, buf_size, &read_size);

        case GSC_TYPE_BLOB:
            return clt_blob_as_string(stmt, data, str, buf_size, &read_size);

        case GSC_TYPE_IMAGE:
            return clt_image_as_string(stmt, data, str, buf_size, &read_size);

        case GSC_TYPE_CURSOR:
            PRTS_RETURN_IFERR(snprintf_s(str, buf_size, buf_size - 1, "SYS_REFCURSOR"));
            break;

        default:
            PRTS_RETURN_IFERR(snprintf_s(str, buf_size, buf_size - 1, "<UNKNOWN TYPE>"));
            break;
    }

    return CT_SUCCESS;
}

static status_t clt_outparam_as_string_by_id(clt_stmt_t *stmt, uint32 id, char *str, uint32 buf_size)
{
    void *data = NULL;
    uint32 size = 0;
    uint32 is_null = 0;
    const clt_outparam_t *outparam = NULL;

    if (SECUREC_UNLIKELY(str == NULL || buf_size <= 1)) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_STRING_BUF_TOO_SMALL, "outparam", id);
        return CT_ERROR;
    }
    str[0] = '\0';

    // will check correct of stmt inside
    CT_RETURN_IFERR(clt_get_outparam_by_id(stmt, id, &data, &size, &is_null));
    outparam = (clt_outparam_t *)cm_list_get(&stmt->outparams, id);

    if (is_null) {
        if (outparam->def.datatype == GSC_TYPE_CURSOR) {
            PRTS_RETURN_IFERR(snprintf_s(str, buf_size, buf_size - 1, "CURSOR STATEMENT"));
        }
        return CT_SUCCESS;
    }

    return gsc_outparam_as_string_get_data(stmt, id, str, buf_size, outparam, size, data);
}
status_t gsc_outparam_as_string_by_id(gsc_stmt_t pstmt, uint32 id, char *str, uint32 buf_size)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_outparam_as_string_by_id(stmt, id, str, buf_size);
    clt_unlock_conn(stmt->conn);
    return status;
}

static status_t clt_outparam_as_string_by_name(clt_stmt_t *stmt, const char *name, char *str, uint32 buf_size)
{
    clt_outparam_t *outparam = NULL;
    uint32 i;

    for (i = 0; i < stmt->outparam_count && i < stmt->outparams.count; i++) {
        // get the i-th outparam
        outparam = (clt_outparam_t *)cm_list_get(&stmt->outparams, i);
        if (cm_str_equal_ins(name, outparam->def.name)) {
            return clt_outparam_as_string_by_id(stmt, i, str, buf_size);
        }
    }

    CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_ATTR, "outparam name", name);
    return CT_ERROR;
}
status_t gsc_outparam_as_string_by_name(gsc_stmt_t pstmt, const char *name, char *str, uint32 buf_size)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, name, "name");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_outparam_as_string_by_name(stmt, name, str, buf_size);
    clt_unlock_conn(stmt->conn);
    return status;
}

#define MAX_DESC_SQL 1024
/* objname: [schema.]obj */
static status_t clt_desc_tbl_vw_syn(clt_stmt_t *stmt, const char *obj_name)
{
    char desc_sql[MAX_SET_NLS_SQL];
    text_t sql_text;

    if (strlen(obj_name) > CT_MAX_NAME_LEN * 2) {
        CLT_SET_ERROR(stmt->conn, ERR_INVALID_PARAMETER, "the object name is too long");
        return CT_ERROR;
    }

    PRTS_RETURN_IFERR(sprintf_s(desc_sql, MAX_SET_NLS_SQL, "select * from %s", obj_name));

    sql_text.str = desc_sql;
    sql_text.len = (uint32)strlen(desc_sql);

    CT_RETURN_IFERR(clt_prepare(stmt, &sql_text));
    stmt->status = CLI_STMT_DESCRIBLE;
    return CT_SUCCESS;
}

static status_t clt_desc_query(clt_stmt_t *stmt, char *query)
{
    static const text_t word_select = {
        .str = "SELECT",
        .len = 6
    };
    static const text_t word_with = {
        .str = "WITH",
        .len = 4
    };

    text_t sql_text;

    sql_text.str = query;
    sql_text.len = (uint32)strlen(query);

    cm_trim_text(&sql_text);

    if ((cm_strcmpni(sql_text.str, word_select.str, word_select.len) != 0) &&
        (cm_strcmpni(sql_text.str, word_with.str, word_with.len) != 0)) {
        CLT_SET_ERROR(stmt->conn, ERR_INVALID_PARAMETER, "a query is expected");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(clt_prepare(stmt, &sql_text));
    stmt->status = CLI_STMT_DESCRIBLE;
    return CT_SUCCESS;
}

static status_t clt_describle(clt_stmt_t *stmt, char *objptr, gsc_desc_type_t desc_type)
{
    gsc_desc_type_t dtype = desc_type;
    if (dtype == GSC_DESC_OBJ) { // get the right type of objptr, now, we merely support table/view/syn object
        dtype = GSC_DESC_TABLE;
    }

    switch (dtype) {
        case GSC_DESC_TABLE:
        case GSC_DESC_VIEW:
        case GSC_DESC_SYN:
            return clt_desc_tbl_vw_syn(stmt, objptr);

        case GSC_DESC_QUERY:
            return clt_desc_query(stmt, objptr);

        case GSC_DESC_PROC:
            CLT_SET_ERROR(stmt->conn, ERR_INVALID_PARAMETER, "describle procedure is unsupported");
            return CT_ERROR;

        case GSC_DESC_FUNC:
            CLT_SET_ERROR(stmt->conn, ERR_INVALID_PARAMETER, "describle function is unsupported");
            return CT_ERROR;

        case GSC_DESC_PKG:
            CLT_SET_ERROR(stmt->conn, ERR_INVALID_PARAMETER, "describle package is unsupported");
            return CT_ERROR;

        case GSC_DESC_SEQ:
            CLT_SET_ERROR(stmt->conn, ERR_INVALID_PARAMETER, "describle sequence is unsupported");
            return CT_ERROR;

        default:
            CLT_SET_ERROR(stmt->conn, ERR_INVALID_PARAMETER, "unsupported describing type");
            return CT_ERROR;
    }
}
status_t gsc_describle(gsc_stmt_t pstmt, char *objptr, gsc_desc_type_t dtype)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, objptr, "describle object");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));

    if (clt_prepare_stmt_pack(stmt) != CT_SUCCESS) {
        clt_unlock_conn(stmt->conn);
        return CT_ERROR;
    }

    status = clt_describle(stmt, objptr, dtype);

    clt_recycle_stmt_pack(stmt);
    clt_unlock_conn(stmt->conn);
    return status;
}

status_t clt_get_batch_error2(clt_stmt_t *stmt, uint32 *line, int *code, char **err_message, uint32 *rows)
{
    clt_batch_error_t *batch_error = NULL;

    if (SECUREC_UNLIKELY(line == NULL || err_message == NULL || rows == NULL)) {
        CT_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "line or err_message or rows");
        return CT_ERROR;
    }

    if (stmt->batch_errs.pos >= stmt->batch_errs.actual_count) {
        *rows = 0;
    } else {
        batch_error = (clt_batch_error_t *)cm_list_get(&stmt->batch_errs.err_list, stmt->batch_errs.pos);
        *line = batch_error->line;
        if (code != NULL) {
            *code = batch_error->err_code;
        }
        *err_message = batch_error->err_message;
        *rows = 1;
        stmt->batch_errs.pos++;
    }

    return CT_SUCCESS;
}

status_t gsc_get_batch_error(gsc_stmt_t pstmt, uint32 *line, char **err_message, uint32 *rows)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_get_batch_error2(stmt, line, NULL, err_message, rows);
    clt_unlock_conn(stmt->conn);
    return status;
}

status_t gsc_get_batch_error2(gsc_stmt_t pstmt, unsigned int *line, int *code, char **err_message, unsigned int *rows)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_get_batch_error2(stmt, line, code, err_message, rows);
    clt_unlock_conn(stmt->conn);
    return status;
}

static status_t clt_get_query_resultset(clt_conn_t *conn, clt_stmt_t **resultset)
{
    clt_query_t *query = &conn->query;
    uint32 stmt_id;

    if (query->pos >= query->ids.count) {
        *resultset = NULL;
    } else {
        stmt_id = *(uint32 *)cm_list_get(&query->ids, query->pos);
        *resultset = (clt_stmt_t *)cm_ptlist_get(&conn->stmts, stmt_id);
        query->pos++;
    }

    return CT_SUCCESS;
}
status_t gsc_get_query_resultset(gsc_conn_t pconn, gsc_stmt_t *resultset)
{
    status_t status;
    clt_conn_t *conn = (clt_conn_t *)pconn;

    GSC_CHECK_OBJECT_NULL_GS(conn, "connection");
    GSC_CHECK_OBJECT_NULL_CLT(conn, resultset, "resultset");

    CT_RETURN_IFERR(clt_lock_conn(conn));
    status = clt_get_query_resultset(conn, (clt_stmt_t **)resultset);
    clt_unlock_conn(conn);
    return status;
}

int clt_read_ori_row(clt_stmt_t *stmt, void **ori_row, unsigned int *size)
{
    if (stmt->status < CLI_STMT_FETCHING) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_API_SEQUENCE, "statement is not fetched");
        return CT_ERROR;
    }

    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, stmt->ori_row, "ori row");

    if (ori_row != NULL) {
        *ori_row = stmt->ori_row;
    }

    if (size != NULL) {
        *size = *(uint16 *)stmt->ori_row;
    }

    return CT_SUCCESS;
}

int gsc_read_ori_row(gsc_stmt_t pstmt, void **ori_row, unsigned int *size)
{
    status_t status;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    CT_RETURN_IFERR(clt_lock_conn(stmt->conn));
    status = clt_read_ori_row(stmt, ori_row, size);
    clt_unlock_conn(stmt->conn);
    return status;
}

status_t gsc_number_to_int(gsc_stmt_t pstmt, void *number, unsigned int sign_flag, unsigned int rsl_length, void *rsl)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    dec4_t *dec = (dec4_t *)number;
    int16 val16;
    int32 val32;
    int64 val64;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, number, "number");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, rsl, "rsl");

    if (sign_flag != GSC_NUMBER_SIGNED && sign_flag != GSC_NUMBER_UNSIGNED) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_VALUE, "sign_flag", sign_flag);
        return CT_ERROR;
    }
    switch (rsl_length) {
        case sizeof(int16):
            if (sign_flag == GSC_NUMBER_SIGNED) {
                CLT_SET_LOCAL_ERROR(stmt->conn, cm_dec4_to_int16(dec, &val16, ROUND_HALF_UP));
            } else {
                CLT_SET_LOCAL_ERROR(stmt->conn, cm_dec4_to_uint16(dec, (uint16 *)&val16, ROUND_HALF_UP));
            }
            *(int16 *)rsl = val16;
            break;
        case sizeof(int32):
            if (sign_flag == GSC_NUMBER_SIGNED) {
                CLT_SET_LOCAL_ERROR(stmt->conn, cm_dec4_to_int32(dec, &val32, ROUND_HALF_UP));
            } else {
                CLT_SET_LOCAL_ERROR(stmt->conn, cm_dec4_to_uint32(dec, (uint32 *)&val32, ROUND_HALF_UP));
            }
            *(int32 *)rsl = val32;
            break;
        case sizeof(int64):
            if (sign_flag == GSC_NUMBER_SIGNED) {
                CLT_SET_LOCAL_ERROR(stmt->conn, cm_dec4_to_int64(dec, &val64, ROUND_HALF_UP));
            } else if (sign_flag == GSC_NUMBER_UNSIGNED) {
                CLT_SET_LOCAL_ERROR(stmt->conn, cm_dec4_to_uint64(dec, (uint64 *)&val64, ROUND_HALF_UP));
            }
            *(int64 *)rsl = val64;
            break;
        default:
            CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_VALUE, "result length", rsl_length);
            return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t gsc_number_to_real(gsc_stmt_t pstmt, void *number, unsigned int rsl_length, void *rsl)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    dec4_t *dec = (dec4_t *)number;
    double val;

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, number, "number");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, rsl, "rsl");

    val = cm_dec4_to_real(dec);
    switch (rsl_length) {
        case sizeof(float):
            if (val != 0 && ((dec->sign == 0 && (val > FLT_MAX || val < FLT_MIN)) ||
                (dec->sign == 1 && (val < -FLT_MAX || val > -FLT_MIN)))) {
                CLT_THROW_ERROR(stmt->conn, ERR_TYPE_OVERFLOW, "FLOAT");
                return CT_ERROR;
            }
            *(float *)rsl = (float)val;
            break;
        case sizeof(double):
            *(double *)rsl = val;
            break;
        default:
            CLT_THROW_ERROR(stmt->conn, ERR_CLT_INVALID_VALUE, "result length", rsl_length);
            return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t gsc_number_to_string(gsc_stmt_t pstmt, void *number, char *buf, unsigned int buf_size)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    dec4_t *dec = (dec4_t *)number;
    int max_size = MIN(buf_size, CT_NUMBER_BUFFER_SIZE);

    GSC_CHECK_OBJECT_NULL_GS(stmt, "statement");
    GSC_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, number, "number");
    GSC_CHECK_OBJECT_NULL_CLT(stmt->conn, buf, "buf");

    /* max write size of buf is max_size-1 */
    if (cm_dec4_to_str(dec, max_size, buf) != CT_SUCCESS) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_BUF_SIZE_TOO_SMALL, "convert to string");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

#ifdef WIN32
const char *gsc_get_dbversion()
{
    return "NONE";
}
#else
extern const char *gsc_get_dbversion(void);
#endif

const char *gsc_get_version(void)
{
    return gsc_get_dbversion();
}

char *gsc_get_typename_by_id(gsc_type_t gsc_type)
{
    struct st_gsc_datatype {
        gsc_type_t typid;
        char *typname;
    } type_map[] = {
        { GSC_TYPE_UNKNOWN,       (char *)"UNKNOWN_TYPE",           },
        { GSC_TYPE_INTEGER,       (char *)"BINARY_INTEGER",         },
        { GSC_TYPE_BIGINT,        (char *)"BINARY_BIGINT",          },
        { GSC_TYPE_REAL,          (char *)"BINARY_DOUBLE",          },
        { GSC_TYPE_NUMBER,        (char *)"NUMBER",                 },
        { GSC_TYPE_NUMBER2,       (char *)"NUMBER2",                },
        { GSC_TYPE_DECIMAL,       (char *)"DECIMAL",                },
        { GSC_TYPE_DATE,          (char *)"DATE",                   },
        { GSC_TYPE_TIMESTAMP,     (char *)"TIMESTAMP",              },
        { GSC_TYPE_CHAR,          (char *)"CHAR",                   },
        { GSC_TYPE_VARCHAR,       (char *)"VARCHAR",                },
        { GSC_TYPE_STRING,        (char *)"VARCHAR",                },
        { GSC_TYPE_BINARY,        (char *)"BINARY",                 },
        { GSC_TYPE_VARBINARY,     (char *)"VARBINARY",              },
        { GSC_TYPE_CLOB,          (char *)"CLOB",                   },
        { GSC_TYPE_BLOB,          (char *)"BLOB",                   },
        { GSC_TYPE_CURSOR,        (char *)"CURSOR",                 },
        { GSC_TYPE_COLUMN,        (char *)"COLUMN",                 },
        { GSC_TYPE_BOOLEAN,       (char *)"BOOLEAN",                },
        { GSC_TYPE_TIMESTAMP_TZ_FAKE,  (char *)"TIMESTAMP",         },
        { GSC_TYPE_TIMESTAMP_LTZ, (char *)"TIMESTAMP_LTZ",          },
        { GSC_TYPE_INTERVAL,      (char *)"INTERVAL",               },
        { GSC_TYPE_INTERVAL_YM,   (char *)"INTERVAL YEAR TO MONTH", },
        { GSC_TYPE_INTERVAL_DS,   (char *)"INTERVAL DAY TO SECOND", },
        { GSC_TYPE_RAW,           (char *)"RAW",                    },
        { GSC_TYPE_IMAGE,         (char *)"IMAGE",                  },
        { GSC_TYPE_UINT32,        (char *)"BINARY_UINT32"           },
        { GSC_TYPE_TIMESTAMP_TZ,  (char *)"TIMESTAMP_TZ",           },
        { GSC_TYPE_ARRAY,         (char *)"ARRAY",                  },
        { GSC_TYPE_NATIVE_DATE,   (char *)"NATIVE_DATE",            }
    };

    uint32 type_cnt = sizeof(type_map) / sizeof(type_map[0]);
    uint32 i;

    for (i = 0; i < type_cnt; i++) {
        if (type_map[i].typid == gsc_type) {
            return type_map[i].typname;
        }
    }

    return type_map[0].typname;
}

#ifdef __cplusplus
}
#endif
