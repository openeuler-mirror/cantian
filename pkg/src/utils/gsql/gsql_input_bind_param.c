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
 * gsql_input_bind_param.c
 *
 *
 * IDENTIFICATION
 * src/utils/gsql/gsql_input_bind_param.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_base.h"
#include "gsql.h"
#include "gsql_input_bind_param.h"

static char **g_bind_param = NULL;

status_t gsql_bind_param_init(uint32 param_count)
{
    uint32 i;

    if (param_count == 0) {
        return GS_SUCCESS;
    }

    if (param_count > GS_MAX_UINT32 / sizeof(char *)) {
        gsql_printf("Bind params failed, ErrMsg: params count is too large.\n");
        return GS_ERROR;
    }

    g_bind_param = (char **)malloc(sizeof(char *) * param_count);
    if (g_bind_param == NULL) {
        gsql_printf("Bind params failed, ErrMsg:Alloc memory for params failed.\n");
        return GS_ERROR;
    }

    for (i = 0; i < param_count; i++) {
        g_bind_param[i] = NULL;
    }
    return GS_SUCCESS;
}

void gsql_bind_param_uninit(uint32 param_count)
{
    uint32 i;

    if (g_bind_param != NULL) {
        for (i = 0; i < param_count; i++) {
            if (g_bind_param[i] != NULL) {
                free(g_bind_param[i]);
                g_bind_param[i] = NULL;
            }
        }

        free(g_bind_param);
        g_bind_param = NULL;
    }
}

static uint32 gsql_sql_get_bind_direction(text_t *confirm_text)
{
    if (cm_text_str_equal_ins(confirm_text, "in")) {
        return GSC_INPUT;
    } else if (cm_text_str_equal_ins(confirm_text, "out")) {
        return GSC_OUTPUT;
    } else if (cm_text_str_equal_ins(confirm_text, "in out")) {
        return GSC_INOUT;
    }

    return 0;
}

static gsc_type_t gsql_sql_get_bind_data_type(text_t *confirm_text)
{
    uint32 i;
    uint32 size;
    struct st_gsc_datatype {
        char *name;
        gsc_type_t type;
    } type_table[] = {
        { "CHAR",             GSC_TYPE_CHAR },
        { "VARCHAR",          GSC_TYPE_VARCHAR },
        { "STRING",           GSC_TYPE_STRING },
        { "INT",              GSC_TYPE_INTEGER },
        { "INTEGER",          GSC_TYPE_INTEGER },
        { "UINT32",           GSC_TYPE_UINT32 },
        { "INTEGER UNSIGNED", GSC_TYPE_UINT32 },
        { "BIGINT",           GSC_TYPE_BIGINT },
        { "REAL",             GSC_TYPE_REAL },
        { "DOUBLE",           GSC_TYPE_REAL },
        { "DATE",             GSC_TYPE_DATE },
        { "TIMESTAMP",        GSC_TYPE_TIMESTAMP },
        { "BLOB",             GSC_TYPE_STRING },
        { "CLOB",             GSC_TYPE_STRING },
        { "DECIMAL",          GSC_TYPE_DECIMAL },
        { "NUMBER",           GSC_TYPE_NUMBER },
        { "NUMBER2",          GSC_TYPE_NUMBER2 },
        { "BOOLEAN",          GSC_TYPE_BOOLEAN },
        { "BOOL",             GSC_TYPE_BOOLEAN },
        { "BINARY",           GSC_TYPE_BINARY },
        { "VARBINARY",        GSC_TYPE_VARBINARY },
        { "TEXT",             GSC_TYPE_STRING },
        { "LONGTEXT",         GSC_TYPE_STRING },
        { "LONG",             GSC_TYPE_STRING },
        { "BYTEA",            GSC_TYPE_STRING }
    };

    size = sizeof(type_table) / sizeof(struct st_gsc_datatype);
    for (i = 0; i < size; i++) {
        if (cm_text_str_equal_ins(confirm_text, type_table[i].name)) {
            return type_table[i].type;
        }
    }

    return GSC_TYPE_UNKNOWN;
}

status_t transform_hex(const unsigned char *str, uint64 *iret, uint32 len)
{
    unsigned char *ptr = (unsigned char *)str;
    for (uint32 i = 0; i < len; i++) {
        if (*ptr >= '0' && *ptr <= '9') {
            *iret = ((*iret) << 4) + ((*ptr) - '0');
        } else if (*ptr >= 'A' && *ptr <= 'F') {
            *iret = ((*iret) << 4) + (((*ptr) - 'A') + 10);
        } else if (*ptr >= 'a' && *ptr <= 'f') {
            *iret = ((*iret) << 4) + (((*ptr) - 'a') + 10);
        } else {
            return GS_ERROR;
        }
        ++ptr;
    }
    return GS_SUCCESS;
}

status_t hex2int64(const unsigned char *str, int64 *res, uint32 len)
{
    uint64 iret = 0;
    GS_RETURN_IFERR(transform_hex(str, &iret, len));
    *res = (int64)iret;
    return GS_SUCCESS;
}

status_t hex2uint32(const unsigned char *str, uint32 *res, uint32 len)
{
    uint64 iret = 0;
    GS_RETURN_IFERR(transform_hex(str, &iret, len));
    *res = (uint32)iret;
    return GS_SUCCESS;
}

status_t hex2int32(const unsigned char *str, int32 *res, uint32 len)
{
    uint64 iret = 0;
    GS_RETURN_IFERR(transform_hex(str, &iret, len));
    *res = (int32)iret;
    return GS_SUCCESS;
}

status_t hex2double(const unsigned char *str, double *res, uint32 len)
{
    uint64 iret = 0;
    GS_RETURN_IFERR(transform_hex(str, &iret, len));
    *res = (double)iret;
    return GS_SUCCESS;
}

static status_t is_hex_string(text_t *confirm_text, bool32 *isHex)
{
    *isHex = GS_FALSE;
    if (confirm_text->len < 3) {
        return GS_SUCCESS;
    }
    uint32 len = confirm_text->len;
    if (confirm_text->str[0] == 'X' && confirm_text->str[1] == '\'' && confirm_text->str[len - 1] == '\'') {
        len = len - 1;
    }

    if ((confirm_text->str[0] == '0' && confirm_text->str[1] == 'x') ||
        (confirm_text->str[0] == 'X' && confirm_text->str[1] == '\'' && confirm_text->str[len - 1] == '\'')) {
        uint32 i = 2;
        for (; i < len; i++) {
            if (!((confirm_text->str[i] >= '0' && confirm_text->str[i] <= '9') ||
                (confirm_text->str[i] >= 'a' && confirm_text->str[i] <= 'f') ||
                (confirm_text->str[i] >= 'A' && confirm_text->str[i] <= 'F'))) {
                gsql_printf("Bind params failed, this param value format is not hexadecimal\n");
                return GS_ERROR;
            }
        }
        if (i == len) {
            *isHex = GS_TRUE;
        }
    }
    return GS_SUCCESS;
}

static void get_hex_string(text_t *confirm_text, unsigned char *res, uint32 res_len, uint32 *lenth)
{
    uint32 len = confirm_text->len;
    if ((confirm_text->str[0] == 'X' && confirm_text->str[1] == '\'' && confirm_text->str[len - 1] == '\'')) {
        len = confirm_text->len - 1;
    }

    uint32 pos = 0;
    for (uint32 i = 2; i < len && i - 2 < res_len; i++) {
        res[i - 2] = confirm_text->str[i];
        pos++;
    }
    *lenth = pos;
    return;
}

static status_t gsql_bind_hex_number_value(gsc_type_t data_type,
    text_t *confirm_text, char* bind_buffer, uint32 buff_size)
{
    unsigned char temp[GS_MAX_PARAM_LEN] = { 0 };
    uint32 len = 0;
    int64 res = 0;
    text_t text_value;

    switch (data_type) {
        case GSC_TYPE_BOOLEAN:
        case GSC_TYPE_INTEGER: {
            get_hex_string(confirm_text, temp, GS_MAX_PARAM_LEN, &len);
            return hex2int32(temp, (int32 *)bind_buffer, len);
        }
        case GSC_TYPE_UINT32: {
            get_hex_string(confirm_text, temp, GS_MAX_PARAM_LEN, &len);
            return hex2uint32(temp, (uint32 *)bind_buffer, len);
        }
        case GSC_TYPE_BIGINT: {
            get_hex_string(confirm_text, temp, GS_MAX_PARAM_LEN, &len);
            return hex2int64(temp, (int64 *)bind_buffer, len);
        }
        case GSC_TYPE_REAL: {
            get_hex_string(confirm_text, temp, GS_MAX_PARAM_LEN, &len);
            return hex2double(temp, (double *)bind_buffer, len);
        }
        case GSC_TYPE_DECIMAL:
        case GSC_TYPE_NUMBER:
        case GSC_TYPE_NUMBER2:
        default: {
            get_hex_string(confirm_text, temp, GS_MAX_PARAM_LEN, &len);
            GS_RETURN_IFERR(hex2int64(temp, &res, len));
        
            text_value.str = (char*)temp;
            text_value.len = 0;
            cm_bigint2text(res, &text_value);
            if (text_value.len <= 0) {
                return GS_ERROR;
            }
            MEMS_RETURN_IFERR(memcpy_s(bind_buffer, buff_size, text_value.str, text_value.len));
            bind_buffer[text_value.len] = '\0';
            return GS_SUCCESS;
        }
    }
}

static status_t gsql_bind_check_boolean(text_t *confirm_text, char* bind_buffer, uint32 buff_size)
{
    if (cm_text_str_equal_ins(confirm_text, "TRUE")) {
        confirm_text->len = 1;
        confirm_text->str[confirm_text->len - 1] = '1';
        confirm_text->str[confirm_text->len] = '\0';
    }
    if (cm_text_str_equal_ins(confirm_text, "FALSE")) {
        confirm_text->len = 1;
        confirm_text->str[confirm_text->len - 1] = '0';
        confirm_text->str[confirm_text->len] = '\0';
    }
    num_errno_t err_no = cm_text2int_ex(confirm_text, (int32 *)bind_buffer);
    if (err_no != NERR_SUCCESS) {
        gsql_printf("Convert text into boolean failed %s \n", cm_get_num_errinfo(err_no));
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t gsql_bind_normal_number_value(gsc_type_t data_type,
    text_t *confirm_text, char* bind_buffer, uint32 buff_size)
{
    num_errno_t err_no;

    switch (data_type) {
        case GSC_TYPE_BOOLEAN:
            return gsql_bind_check_boolean(confirm_text, bind_buffer, buff_size);
        case GSC_TYPE_INTEGER: {
            err_no = cm_text2int_ex(confirm_text, (int32 *)bind_buffer);
            if (err_no != NERR_SUCCESS) {
                gsql_printf("Convert text into int failed %s \n", cm_get_num_errinfo(err_no));
                return GS_ERROR;
            }
            return GS_SUCCESS;
        }
        case GSC_TYPE_UINT32: {
            err_no = cm_text2uint32_ex(confirm_text, (uint32 *)bind_buffer);
            if (err_no != NERR_SUCCESS) {
                gsql_printf("Convert text into uint32 failed %s \n", cm_get_num_errinfo(err_no));
                return GS_ERROR;
            }
            return GS_SUCCESS;
        }
        case GSC_TYPE_BIGINT: {
            err_no = cm_text2bigint_ex(confirm_text, (int64 *)bind_buffer);
            if (err_no != NERR_SUCCESS) {
                gsql_printf("Convert text into bigint failed %s \n", cm_get_num_errinfo(err_no));
                return GS_ERROR;
            }
            return GS_SUCCESS;
        }
        case GSC_TYPE_REAL: {
            err_no = cm_text2real_ex(confirm_text, (double *)bind_buffer);
            if (err_no != NERR_SUCCESS) {
                gsql_printf("Convert text into real failed %s \n", cm_get_num_errinfo(err_no));
                return GS_ERROR;
            }
            return GS_SUCCESS;
        }
        case GSC_TYPE_DECIMAL:
        case GSC_TYPE_NUMBER:
        case GSC_TYPE_NUMBER2:
        default: {
            if (buff_size < confirm_text->len) {
                return GS_ERROR;
            }
            MEMS_RETURN_IFERR(memcpy_s(bind_buffer, buff_size, confirm_text->str, confirm_text->len));
            bind_buffer[confirm_text->len] = '\0';
            return GS_SUCCESS;
        }
    }
}

static status_t gsql_bind_one_param_number(gsc_stmt_t stmt, uint32 i, gsc_type_t data_type, text_t *confirm_text,
    uint32 direction)
{
    bool32 isHex = GS_FALSE;
    int32 bind_size = 0;

    GS_RETURN_IFERR(is_hex_string(confirm_text, &isHex));

    switch (data_type) {
        case GSC_TYPE_BOOLEAN:
        case GSC_TYPE_INTEGER:
            bind_size = sizeof(int32);
            break;
        case GSC_TYPE_UINT32:
            bind_size = sizeof(uint32);
            break;
        case GSC_TYPE_BIGINT:
            bind_size = sizeof(int64);
            break;
        case GSC_TYPE_REAL:
            bind_size = sizeof(double);
            break;
        case GSC_TYPE_DECIMAL:
        case GSC_TYPE_NUMBER:
        case GSC_TYPE_NUMBER2:
        default:
            bind_size = isHex ? GS_MAX_PARAM_LEN : (confirm_text->len + 1);
            break;
    }

    g_bind_param[i] = (char *)malloc(bind_size);
    GS_RETVALUE_IFTRUE(g_bind_param[i] == NULL, GS_ERROR);

    MEMS_RETURN_IFERR(memset_s(g_bind_param[i], bind_size, 0, bind_size));

    if (isHex) {
        GS_RETURN_IFERR(gsql_bind_hex_number_value(data_type, confirm_text, g_bind_param[i], bind_size));
    } else {
        GS_RETURN_IFERR(gsql_bind_normal_number_value(data_type, confirm_text, g_bind_param[i], bind_size));
    }

    return gsc_bind_by_pos2(stmt, i, data_type, (void *)g_bind_param[i], bind_size, NULL, direction);
}

static status_t gsql_bind_one_param_time(gsc_stmt_t stmt, uint32 i, gsc_type_t p_data_type, text_t *confirm_text,
                                         uint32 direction)
{
    status_t ret = GS_ERROR;
    char nlsbuf[MAX_NLS_PARAM_LENGTH];
    text_t fmt;
    gsc_type_t data_type = p_data_type;

    switch (data_type) {
        case GSC_TYPE_DATE:
        case GSC_TYPE_TIMESTAMP:
            if (data_type == GSC_TYPE_DATE) {
                data_type = GSC_TYPE_NATIVE_DATE;
                ret = gsql_nlsparam_geter(nlsbuf, NLS_DATE_FORMAT, &fmt);
                GS_RETURN_IFERR(ret);
            } else if (data_type == GSC_TYPE_TIMESTAMP) {
                ret = gsql_nlsparam_geter(nlsbuf, NLS_TIMESTAMP_FORMAT, &fmt);
                GS_RETURN_IFERR(ret);
            }

            g_bind_param[i] = (char *)malloc(sizeof(date_t));
            if (g_bind_param[i] == NULL) {
                return GS_ERROR;
            }

            MEMS_RETURN_IFERR(memset_s(g_bind_param[i], sizeof(date_t), 0, sizeof(date_t)));

            if (cm_text2date(confirm_text, &fmt, (date_t *)g_bind_param[i]) != GS_SUCCESS) {
                gsql_printf("Bind params[%u] failed, ErrMsg = date format is error, format must be %s.\n", i + 1,
                            fmt.str);  // because fmt.str is a const str
                return GS_ERROR;
            }

            if (gsc_bind_by_pos2(stmt, i, data_type, (void *)g_bind_param[i], sizeof(date_t), NULL,
                                 direction) != GSC_SUCCESS) {
                gsql_print_error(CONN);
                return GS_ERROR;
            }
            return GS_SUCCESS;
        default:
            return GS_ERROR;
    }
}

static status_t gsql_bind_one_param_core(gsc_stmt_t stmt, uint32 i, text_t *confirm_text, gsc_type_t data_type,
                                         uint32 direction)
{
    status_t ret = GS_ERROR;

    switch (data_type) {
        case GSC_TYPE_CHAR:
        case GSC_TYPE_VARCHAR:
        case GSC_TYPE_BINARY:
        case GSC_TYPE_VARBINARY:
        case GSC_TYPE_STRING:  // end with '\0': paramLen=strlen(value)+1
            g_bind_param[i] = (char *)malloc(confirm_text->len + 1);
            if (g_bind_param[i] == NULL) {
                return GS_ERROR;
            }
            if (confirm_text->len != 0) {
                MEMS_RETURN_IFERR(memcpy_s(g_bind_param[i], confirm_text->len + 1, confirm_text->str, confirm_text->len));
            }
            g_bind_param[i][confirm_text->len] = '\0';
            ret = gsc_bind_by_pos2(stmt, i, data_type, (void *)g_bind_param[i], confirm_text->len + 1, NULL, direction);
            break;
        case GSC_TYPE_BLOB:
        case GSC_TYPE_CLOB:
        case GSC_TYPE_IMAGE:
            break;
        case GSC_TYPE_BOOLEAN:
        case GSC_TYPE_INTEGER:
        case GSC_TYPE_UINT32:
        case GSC_TYPE_BIGINT:
        case GSC_TYPE_REAL:
        case GSC_TYPE_DECIMAL:
        case GSC_TYPE_NUMBER:
        case GSC_TYPE_NUMBER2:
            ret = gsql_bind_one_param_number(stmt, i, data_type, confirm_text, direction);
            break;
        case GSC_TYPE_DATE:
        case GSC_TYPE_TIMESTAMP:
            ret = gsql_bind_one_param_time(stmt, i, data_type, confirm_text, direction);
            break;
        default:
            break;
    }
    
    return ret;
}

static status_t gsql_bind_one_param(gsc_stmt_t stmt, uint32 param_count)
{
    uint32 i;

    for (i = 0; i < param_count; i++) {
        char confirm[GS_MAX_PARAM_LEN + 1] = { 0 };
        text_t confirm_text;
        gsc_type_t data_type = GSC_TYPE_UNKNOWN;
        int32 direction = GSC_INPUT;

        gsql_printf("The %uth param:\n", i + 1);

        /* get parameter direction */
        gsql_printf("Direction : ");
        (void)fflush(stdout);
        if (NULL == fgets(confirm, sizeof(confirm), stdin)) {
            gsql_printf("Bind params[%u] failed, ErrMsg = %s.\n", i + 1, "Get parameter direction failed");
            return GS_ERROR;
        }

        cm_str2text_safe(confirm, (uint32)strlen(confirm), &confirm_text);
        cm_trim_text(&confirm_text);

        direction = gsql_sql_get_bind_direction(&confirm_text);
        if (direction == GSC_TYPE_UNKNOWN) {
            gsql_printf("Bind params[%u] failed, ErrMsg = %s.\n", i + 1, "Unknown parameter direction, must be in/out/in out");
            return GS_ERROR;
        }

        /* get parameter datatype */
        gsql_printf("DataType : ");
        (void)fflush(stdout);
        if (NULL == fgets(confirm, sizeof(confirm), stdin)) {
            gsql_printf("Bind params[%u] failed, ErrMsg = %s.\n", i + 1, "Get parameter DataType failed");
            return GS_ERROR;
        }

        cm_str2text_safe(confirm, (uint32)strlen(confirm), &confirm_text);
        cm_trim_text(&confirm_text);

        data_type = gsql_sql_get_bind_data_type(&confirm_text);
        if (data_type == GSC_TYPE_UNKNOWN) {
            gsql_printf("Bind params[%u] failed, ErrMsg = %s.\n", i + 1, "Don't support the input datatype");
            return GS_ERROR;
        }

        /* get parameter bind value */
        gsql_printf("BindValue: ");
        (void)fflush(stdout);
        if (NULL == fgets(confirm, sizeof(confirm), stdin)) {
            gsql_printf("Bind params[%u] failed, ErrMsg = %s.\n", i + 1, "Get parameter BindValue failed");
            return GS_ERROR;
        }

        cm_str2text_safe(confirm, (uint32)strlen(confirm), &confirm_text);
        if (confirm_text.len >= GS_MAX_PARAM_LEN) {
            gsql_printf("Bind params[%u] failed, ErrMsg = %s.\n", i + 1, "BindVaule len must less than 128");
            return GS_ERROR;
        }

        if (confirm_text.len > 0) {
            confirm_text.len = confirm_text.len > 0 ? confirm_text.len - 1 : confirm_text.len;
            confirm_text.str[confirm_text.len] = '\0';
        }
        if (confirm_text.len == 0) {
            gsql_printf("Bind params[%u] failed, ErrMsg = %s.\n", i + 1, "BindVaule len must more than 1");
            return GS_ERROR;
        }

        if (gsql_bind_one_param_core(stmt, i, &confirm_text, data_type, direction) != GS_SUCCESS) {
            gsql_printf("Bind params[%u] failed.\n", i + 1);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t gsql_bind_params(gsc_stmt_t stmt, uint32 param_count /* , uint32 *batch_count */)
{
    int32 ret;
    if (param_count == 0) {
        return GS_SUCCESS;
    }

    gsql_printf("+-------------------------------------------------+\n");
    gsql_printf("|                CTCLIENT Bind Param              |\n");
    gsql_printf("+-------------------------------------------------+\n");

    ret = gsql_bind_one_param(stmt, param_count);
    if (ret != GS_SUCCESS) {
        gsql_printf("Bind params failed.\n");
        return ret;
    }

    gsql_printf("Bind params successfully.\n");
    return ret;
}

static bool32 gsql_try_skip_comment(text_t *sql_text)
{
    char c1, c2;

    if (sql_text->len <= 2) {
        return GS_FALSE;
    }

    if (sql_text->str[0] == '-' && sql_text->str[1] == '-') {
        sql_text->str += 2;
        sql_text->len -= 2;

        while (sql_text->len > 0) {
            c1 = *sql_text->str;
            sql_text->str++;
            sql_text->len--;
            if (c1 == '\n') {
                return GS_TRUE;
            }
        }

        return GS_TRUE;
    }

    if (sql_text->str[0] == '/' && sql_text->str[1] == '*') {
        sql_text->str += 2;
        sql_text->len -= 2;

        while (sql_text->len >= 2) {
            c1 = sql_text->str[0];
            c2 = sql_text->str[1];

            if (c1 == '*' && c2 == '/') {
                sql_text->str += 2;
                sql_text->len -= 2;
                return GS_TRUE;
            }

            sql_text->str++;
            sql_text->len--;
        }

        sql_text->len = 0;
        return GS_TRUE;
    }

    return GS_FALSE;
}

static bool32 gsql_try_skip_string(text_t *sql_text)
{
    char c;

    if (sql_text->str[0] != '\'') {
        return GS_FALSE;
    }

    sql_text->str++;
    sql_text->len--;

    while (sql_text->len > 0) {
        c = sql_text->str[0];
        sql_text->str++;
        sql_text->len--;
        if (c == '\'') {
            return GS_TRUE;
        }
    }

    return GS_TRUE;
}

uint32 gsql_get_param_count(const char *sql)
{
    text_t sql_text;
    uint32 param_count = 0;

    cm_str2text((char *)sql, &sql_text);
    while (sql_text.len > 0) {
        if (gsql_try_skip_comment(&sql_text)) {
            continue;
        }

        if (gsql_try_skip_string(&sql_text)) {
            continue;
        }

        if (sql_text.str[0] != ':' && sql_text.str[0] != '?') {
            sql_text.str++;
            sql_text.len--;
            continue;
        }

        sql_text.str++;
        sql_text.len--;
        while (sql_text.len > 0) {
            if (!CM_IS_NAMING_LETER(*sql_text.str)) {
                break;
            }

            sql_text.str++;
            sql_text.len--;
        }

        ++param_count;
    }

    return param_count;
}

