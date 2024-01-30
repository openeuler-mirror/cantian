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
 * var_cast.c
 *
 *
 * IDENTIFICATION
 * src/common/variant/var_cast.c
 *
 * -------------------------------------------------------------------------
 */
#include "var_cast.h"

/* **NOTE:** The type must be arranged by id ascending order. */
static const type_desc_t g_datatype_items[CT_MAX_DATATYPE_NUM] = {
    // type_id                      type_name                                 weight
    [0] = { CT_TYPE_UNKNOWN, { (char *)"UNKNOWN_TYPE", 12 },          -10000 },
    [CT_TYPE_I(CT_TYPE_INTEGER)] = { CT_TYPE_INTEGER, { (char *)"BINARY_INTEGER", 14 }, 1 },
    [CT_TYPE_I(CT_TYPE_BIGINT)] = { CT_TYPE_BIGINT, { (char *)"BINARY_BIGINT", 13 }, 10 },
    [CT_TYPE_I(CT_TYPE_REAL)] = { CT_TYPE_REAL, { (char *)"BINARY_DOUBLE", 13 }, 100 },
    [CT_TYPE_I(CT_TYPE_NUMBER)] = { CT_TYPE_NUMBER, { (char *)"NUMBER", 6 }, 1000 },
    [CT_TYPE_I(CT_TYPE_DECIMAL)] = { CT_TYPE_DECIMAL, { (char *)"NUMBER", 6 }, 1000 },
    [CT_TYPE_I(CT_TYPE_NUMBER2)] = { CT_TYPE_NUMBER2, { (char *)"NUMBER2", 7 }, 1001 },
    [CT_TYPE_I(CT_TYPE_DATE)] = { CT_TYPE_DATE, { (char *)"DATE", 4 }, 1 },
    [CT_TYPE_I(CT_TYPE_TIMESTAMP)] = { CT_TYPE_TIMESTAMP, { (char *)"TIMESTAMP", 9 }, 10 },
    [CT_TYPE_I(CT_TYPE_CHAR)] = { CT_TYPE_CHAR, { (char *)"CHAR", 4 }, 1 },
    [CT_TYPE_I(CT_TYPE_VARCHAR)] = { CT_TYPE_VARCHAR, { (char *)"VARCHAR", 7 }, 10 },
    [CT_TYPE_I(CT_TYPE_STRING)] = { CT_TYPE_STRING, { (char *)"VARCHAR", 7 }, 10000 },
    [CT_TYPE_I(CT_TYPE_BINARY)] = { CT_TYPE_BINARY, { (char *)"BINARY", 6 }, 1 },
    [CT_TYPE_I(CT_TYPE_VARBINARY)] = { CT_TYPE_VARBINARY, { (char *)"VARBINARY", 9 }, 10 },
    [CT_TYPE_I(CT_TYPE_CLOB)] = { CT_TYPE_CLOB, { (char *)"CLOB", 4 }, 1 },
    [CT_TYPE_I(CT_TYPE_BLOB)] = { CT_TYPE_BLOB, { (char *)"BLOB", 4 }, 100 },
    [CT_TYPE_I(CT_TYPE_CURSOR)] = { CT_TYPE_CURSOR, { (char *)"CURSOR", 6 }, -10000 },
    [CT_TYPE_I(CT_TYPE_COLUMN)] = { CT_TYPE_COLUMN, { (char *)"COLUMN", 6 }, -10000 },
    [CT_TYPE_I(CT_TYPE_BOOLEAN)] = { CT_TYPE_BOOLEAN, { (char *)"BOOLEAN", 7 }, 1 },
    [CT_TYPE_I(CT_TYPE_TIMESTAMP)] = { CT_TYPE_TIMESTAMP, { (char *)"TIMESTAMP", 9 }, 10 },
    [CT_TYPE_I(CT_TYPE_TIMESTAMP_TZ_FAKE)] = { CT_TYPE_TIMESTAMP_TZ_FAKE, { (char *)"TIMESTAMP", 9 }, 10 },
    [CT_TYPE_I(CT_TYPE_TIMESTAMP_LTZ)] = { CT_TYPE_TIMESTAMP_LTZ, { (char *)"TIMESTAMP_LTZ", 13 }, 100 },
    [CT_TYPE_I(CT_TYPE_INTERVAL)] = { CT_TYPE_INTERVAL, { (char *)"INTERVAL", 8 }, 0 },
    [CT_TYPE_I(CT_TYPE_INTERVAL_YM)] = { CT_TYPE_INTERVAL_YM, { (char *)"INTERVAL YEAR TO MONTH", 22 }, 1 },
    [CT_TYPE_I(CT_TYPE_INTERVAL_DS)] = { CT_TYPE_INTERVAL_DS, { (char *)"INTERVAL DAY TO SECOND", 22 }, 1 },
    [CT_TYPE_I(CT_TYPE_RAW)] = { CT_TYPE_RAW, { (char *)"RAW", 3 }, 1000 },
    [CT_TYPE_I(CT_TYPE_IMAGE)] = { CT_TYPE_IMAGE, { (char *)"IMAGE", 5 }, 1000 },
    [CT_TYPE_I(CT_TYPE_UINT32)] = { CT_TYPE_UINT32, { (char *)"BINARY_UINT32", 13 }, 1 },
    [CT_TYPE_I(CT_TYPE_UINT64)] = { CT_TYPE_UINT64, { (char *)"BINARY_UINT64", 13 }, -10000 },
    [CT_TYPE_I(CT_TYPE_SMALLINT)] = { CT_TYPE_SMALLINT, { (char *)"SMALLINT", 8 }, -10000 },
    [CT_TYPE_I(CT_TYPE_USMALLINT)] = { CT_TYPE_USMALLINT, { (char *)"SMALLINT UNSIGNED", 17 }, -10000 },
    [CT_TYPE_I(CT_TYPE_TINYINT)] = { CT_TYPE_TINYINT, { (char *)"TINYINT", 7 }, -10000 },
    [CT_TYPE_I(CT_TYPE_UTINYINT)] = { CT_TYPE_UTINYINT, { (char *)"TINYINT UNSIGNED", 16 }, -10000 },
    [CT_TYPE_I(CT_TYPE_FLOAT)] = { CT_TYPE_FLOAT, { (char *)"FLOAT", 5 }, 10000 },
    [CT_TYPE_I(CT_TYPE_TIMESTAMP_TZ)] = { CT_TYPE_TIMESTAMP_TZ, { (char *)"TIMESTAMP_TZ", 12 }, 200 },
    [CT_TYPE_I(CT_TYPE_RECORD)] = { CT_TYPE_RECORD, { (char *)"RECORD",  6 }, -10000 },
    [CT_TYPE_I(CT_TYPE_ARRAY)] = { CT_TYPE_ARRAY, { (char *)"ARRAY", 5 }, 1 },
    [CT_TYPE_I(CT_TYPE_COLLECTION)] = { CT_TYPE_COLLECTION, { (char *)"COLLECTION", 10 }, -10000 },
    [CT_TYPE_I(CT_TYPE_OBJECT)] = { CT_TYPE_OBJECT, { (char *)"OBJECT", 6 }, -10000 },
};

#define LOWEST_WEIGHT_LEVEL         (-100000000)

static const char* g_lob_type_items[] = {
    (const char*)"CT_LOB_FROM_KERNEL(0)",
    (const char*)"CT_LOB_FROM_VMPOOL(1)",
    (const char*)"CT_LOB_FROM_NORMAL(2)",
    (const char*)"UNKNOWN_TYPE"
};
#define CT_LOB_TYPE_UNKOWN_TYPE_INDEX ((sizeof(g_lob_type_items) / sizeof(char*)) - 1)

const text_t *get_datatype_name(int32 type_input)
{
    int32 type = type_input;
    if (type < CT_TYPE_BASE || type >= CT_TYPE__DO_NOT_USE) {
        return &g_datatype_items[0].name;
    }

    type -= (int32)CT_TYPE_BASE;
    if (g_datatype_items[type].id == 0) { // not defined in g_datatype_items
        return &g_datatype_items[0].name;
    }

    return &g_datatype_items[type].name;
}

int32 get_datatype_weight(int32 type_input)
{
    int32 type = type_input;
    if (type < CT_TYPE_BASE || type >= CT_TYPE__DO_NOT_USE) {
        return LOWEST_WEIGHT_LEVEL;
    }
    
    type -= (int32)CT_TYPE_BASE;
    if (g_datatype_items[type].id == 0) { // not defined in g_datatype_items
        return LOWEST_WEIGHT_LEVEL;
    }

    return g_datatype_items[type].weight;
}

/** Get the type id by type name */
ct_type_t get_datatype_id(const char *type_str)
{
    if (type_str == NULL) {
        return CT_TYPE_UNKNOWN;
    }

    text_t typname;
    cm_str2text((char *)type_str, &typname);

    for (uint32 i = 0; i < CT_MAX_DATATYPE_NUM; i++) {
        if (cm_text_equal_ins(&typname, &(g_datatype_items[i].name))) {
            return (ct_type_t)(i + CT_TYPE_BASE);
        }
    }

    return CT_TYPE_UNKNOWN;
}

const char  *get_lob_type_name(int32 type)
{
    if (!CT_IS_VALID_LOB_TYPE(type)) {
        return g_lob_type_items[CT_LOB_TYPE_UNKOWN_TYPE_INDEX];
    }
    
    return g_lob_type_items[type];
}

static const uint64 g_dest_cast_mask[CT_MAX_DATATYPE_NUM] = {
    [CT_TYPE_I(CT_TYPE_INTEGER)] = CT_TYPE_MASK_NUMERIC | CT_TYPE_MASK_STRING | CT_TYPE_MASK(CT_TYPE_BOOLEAN) |
    CT_TYPE_MASK_BINARY,
    [CT_TYPE_I(CT_TYPE_BIGINT)] = CT_TYPE_MASK_NUMERIC | CT_TYPE_MASK_STRING | CT_TYPE_MASK(CT_TYPE_BOOLEAN) |
    CT_TYPE_MASK_BINARY,
    [CT_TYPE_I(CT_TYPE_UINT64)] = CT_TYPE_MASK_NUMERIC | CT_TYPE_MASK_STRING | CT_TYPE_MASK(CT_TYPE_BOOLEAN) |
    CT_TYPE_MASK_BINARY,
    [CT_TYPE_I(CT_TYPE_REAL)] = CT_TYPE_MASK_NUMERIC | CT_TYPE_MASK_STRING | CT_TYPE_MASK_BINARY,
    [CT_TYPE_I(CT_TYPE_NUMBER)] = CT_TYPE_MASK_NUMERIC | CT_TYPE_MASK_STRING | CT_TYPE_MASK_BINARY,
    [CT_TYPE_I(CT_TYPE_NUMBER2)] = CT_TYPE_MASK_NUMERIC | CT_TYPE_MASK_STRING | CT_TYPE_MASK_BINARY,
    [CT_TYPE_I(CT_TYPE_DECIMAL)] = CT_TYPE_MASK_NUMERIC | CT_TYPE_MASK_STRING | CT_TYPE_MASK_BINARY,
    [CT_TYPE_I(CT_TYPE_DATE)] = CT_TYPE_MASK_DATETIME | CT_TYPE_MASK_STRING,
    [CT_TYPE_I(CT_TYPE_TIMESTAMP)] = CT_TYPE_MASK_DATETIME | CT_TYPE_MASK_STRING,
    [CT_TYPE_I(CT_TYPE_CHAR)] = CT_TYPE_MASK_ALL,
    [CT_TYPE_I(CT_TYPE_VARCHAR)] = CT_TYPE_MASK_ALL,
    [CT_TYPE_I(CT_TYPE_STRING)] = CT_TYPE_MASK_ALL,
    [CT_TYPE_I(CT_TYPE_BINARY)] = CT_TYPE_MASK_ALL,  // any type => string => binary
    [CT_TYPE_I(CT_TYPE_VARBINARY)] = CT_TYPE_MASK_ALL,
    [CT_TYPE_I(CT_TYPE_RAW)] = CT_TYPE_MASK_STRING | CT_TYPE_MASK(CT_TYPE_RAW) | CT_TYPE_MASK_BINARY |
    CT_TYPE_MASK(CT_TYPE_BLOB),
    [CT_TYPE_I(CT_TYPE_CLOB)] = CT_TYPE_MASK_STRING | CT_TYPE_MASK(CT_TYPE_CLOB) |
    CT_TYPE_MASK(CT_TYPE_IMAGE) | CT_TYPE_MASK_NUMERIC,
    [CT_TYPE_I(CT_TYPE_BLOB)] = CT_TYPE_MASK_BINARY | CT_TYPE_MASK_STRING | CT_TYPE_MASK(CT_TYPE_CLOB) |
    CT_TYPE_MASK(CT_TYPE_BLOB) | CT_TYPE_MASK(CT_TYPE_RAW) | CT_TYPE_MASK(CT_TYPE_IMAGE),
    [CT_TYPE_I(CT_TYPE_IMAGE)] = CT_TYPE_MASK_ALL,
    [CT_TYPE_I(CT_TYPE_CURSOR)] = CT_TYPE_MASK_NONE,
    [CT_TYPE_I(CT_TYPE_COLUMN)] = CT_TYPE_MASK_NONE,
    [CT_TYPE_I(CT_TYPE_BOOLEAN)] = CT_TYPE_MASK_INTEGER | CT_TYPE_MASK_STRING | CT_TYPE_MASK(CT_TYPE_BOOLEAN),
    [CT_TYPE_I(CT_TYPE_TIMESTAMP_TZ)] = CT_TYPE_MASK_DATETIME | CT_TYPE_MASK_STRING,
    [CT_TYPE_I(CT_TYPE_TIMESTAMP_LTZ)] = CT_TYPE_MASK_DATETIME | CT_TYPE_MASK_STRING,
    [CT_TYPE_I(CT_TYPE_INTERVAL)] = CT_TYPE_MASK_NONE,
    [CT_TYPE_I(CT_TYPE_INTERVAL_YM)] = CT_TYPE_MASK(CT_TYPE_INTERVAL_YM) | CT_TYPE_MASK_STRING,
    [CT_TYPE_I(CT_TYPE_INTERVAL_DS)] = CT_TYPE_MASK(CT_TYPE_INTERVAL_DS) | CT_TYPE_MASK_STRING,
    [CT_TYPE_I(CT_TYPE_UINT32)] = CT_TYPE_MASK_NUMERIC | CT_TYPE_MASK_STRING |
    CT_TYPE_MASK(CT_TYPE_BOOLEAN) | CT_TYPE_MASK_BINARY,
    [CT_TYPE_I(CT_TYPE_TIMESTAMP_TZ_FAKE)] = CT_TYPE_MASK_DATETIME | CT_TYPE_MASK_STRING,
    [CT_TYPE_I(CT_TYPE_ARRAY)] = CT_TYPE_MASK_ARRAY,
    [CT_TYPE_I(CT_TYPE_COLLECTION)] = CT_TYPE_MASK_COLLECTION,
    [CT_TYPE_I(CT_TYPE_DATETIME_MYSQL)] = CT_TYPE_MASK_DATETIME | CT_TYPE_MASK_STRING,
    [CT_TYPE_I(CT_TYPE_TIME_MYSQL)] = CT_TYPE_MASK_DATETIME | CT_TYPE_MASK_STRING,
    [CT_TYPE_I(CT_TYPE_DATE_MYSQL)] = CT_TYPE_MASK_DATETIME | CT_TYPE_MASK_STRING,
    [CT_TYPE_I(CT_TYPE_NUMBER3)] = CT_TYPE_MASK_NUMERIC | CT_TYPE_MASK_STRING | CT_TYPE_MASK_BINARY,
};

/**
* To decide whether built-in datatypes can be cast into which other built-in datatype.
* This function can check the Compatibility of two datatypes before conversion. therefore
* it can speed the program.
* NOTE: this is a temporary solution
*/
bool32 var_datatype_matched(ct_type_t dest_type, ct_type_t src_type)
{
    if (CT_TYPE_UNKNOWN == dest_type || CT_TYPE_UNKNOWN == src_type) {
        return CT_TRUE;
    }
    if (!CM_IS_DATABASE_DATATYPE(src_type) || !CM_IS_DATABASE_DATATYPE(dest_type)) {
        return CT_FALSE;
    }
    return ((g_dest_cast_mask[CT_TYPE_I(dest_type)] & CT_TYPE_MASK(src_type)) != 0);
}

status_t var_text2num(const text_t *text, ct_type_t type, bool32 negative, variant_t *result)
{
    char num_str[512];
    CT_RETURN_IFERR(cm_text2str(text, num_str, 512));  // for save 0.000[307]1

    result->is_null = CT_FALSE;
    result->type = type;

    switch (type) {
        case CT_TYPE_UINT32:
            VALUE(uint32, result) = negative ? (uint32)(-atoi(num_str)) : (uint32)(atoi(num_str));
            break;
        case CT_TYPE_INTEGER:
            VALUE(int32, result) = negative ? -atoi(num_str) : atoi(num_str);
            break;
        case CT_TYPE_BIGINT:
            VALUE(int64, result) = negative ? -atoll(num_str) : atoll(num_str);
            if (result->v_bigint == (int64)(CT_MIN_INT32)) {
                result->type = CT_TYPE_INTEGER;
                result->v_int = (int32)result->v_bigint;
            }
            break;
        case CT_TYPE_UINT64:
            VALUE(uint64, result) = negative ? (uint64)(-atoi(num_str)) : (uint64)(atoi(num_str));
            if (result->v_ubigint == (uint64)(CT_MIN_UINT32)) {
                result->type = CT_TYPE_UINT32;
                result->v_int = (uint32)result->v_ubigint;
            }
            break;
        case CT_TYPE_REAL:
            VALUE(double, result) = negative ? -atof(num_str) : atof(num_str);
            break;
        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_NUMBER2:
            (void)cm_text_to_dec(text, VALUE_PTR(dec8_t, result));
            if (negative) {
                cm_dec_negate(&result->v_dec);
            }
            break;
        default:
            CM_NEVER;
            break;
    }
    return CT_SUCCESS;
}

status_t var_as_date(const nlsparams_t *nls, variant_t *var)
{
    text_t fmt_text;

    switch (var->type) {
        case CT_TYPE_STRING:
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR: {
            nls->param_geter(nls, NLS_DATE_FORMAT, &fmt_text);
            var->type = CT_TYPE_DATE;
            return cm_text2date(VALUE_PTR(text_t, var), &fmt_text, VALUE_PTR(date_t, var));
        }

        case CT_TYPE_DATE:
            var->type = CT_TYPE_DATE;
            return CT_SUCCESS;

        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_TZ:
            var->v_date = cm_timestamp2date(var->v_tstamp);
            var->type = CT_TYPE_DATE;
            return CT_SUCCESS;

        case CT_TYPE_TIMESTAMP_LTZ:
            /* adjust with dbtimezone */
            var->v_tstamp = cm_adjust_date_between_two_tzs(var->v_tstamp_ltz,
                cm_get_db_timezone(), cm_get_session_time_zone(nls));
            var->v_date = cm_timestamp2date(var->v_tstamp);
            var->type = CT_TYPE_DATE;
            return CT_SUCCESS;

        default:
            CT_SET_ERROR_MISMATCH(CT_TYPE_DATE, var->type);
            return CT_ERROR;
    }
}

status_t var_as_timestamp(const nlsparams_t *nls, variant_t *var)
{
    text_t fmt_text;

    switch (var->type) {
        case CT_TYPE_STRING:
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR: {
            nls->param_geter(nls, NLS_TIMESTAMP_FORMAT, &fmt_text);
            var->type = CT_TYPE_TIMESTAMP;
            return cm_text2date(&var->v_text, &fmt_text, VALUE_PTR(timestamp_t, var));
        }

        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_TZ:
            var->type = CT_TYPE_TIMESTAMP;
            return CT_SUCCESS;
        case CT_TYPE_TIMESTAMP_LTZ:
            /* adjust whith dbtimezone */
            var->type = CT_TYPE_TIMESTAMP;
            var->v_tstamp = cm_adjust_date_between_two_tzs(var->v_tstamp,
                cm_get_db_timezone(), cm_get_session_time_zone(nls));
            return CT_SUCCESS;

        default:
            CT_SET_ERROR_MISMATCH(CT_TYPE_TIMESTAMP, var->type);
            return CT_ERROR;
    }
}

status_t var_as_timestamp_ltz(const nlsparams_t *nls, variant_t *var)
{
    status_t status;
    text_t fmt_text;
    timezone_info_t tz_offset;

    status = CT_SUCCESS;
    switch (var->type) {
        case CT_TYPE_STRING:
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR: {
            nls->param_geter(nls, NLS_TIMESTAMP_FORMAT, &fmt_text);
            status = cm_text2date(&var->v_text, &fmt_text, VALUE_PTR(timestamp_ltz_t, var));
            var->type = CT_TYPE_TIMESTAMP_LTZ;

            /* default tz value  = cm_get_session_time_zone  */
            tz_offset = cm_get_session_time_zone(nls);
            break;
        }

        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:

            /* default tz value  = cm_get_session_time_zone  */
            tz_offset = cm_get_session_time_zone(nls);
            break;

        case CT_TYPE_TIMESTAMP_TZ:
            tz_offset = var->v_tstamp_tz.tz_offset;
            break;
        case CT_TYPE_TIMESTAMP_LTZ:
            tz_offset = cm_get_db_timezone();
            break;

        default:
            CT_SET_ERROR_MISMATCH(CT_TYPE_TIMESTAMP, var->type);
            return CT_ERROR;
    }

    /* finally, adjust whith dbtimezone */
    var->v_tstamp_ltz = cm_adjust_date_between_two_tzs(var->v_tstamp_ltz, tz_offset, cm_get_db_timezone());

    return status;
}

status_t var_as_timestamp_tz(const nlsparams_t *nls, variant_t *var)
{
    text_t fmt_text;

    switch (var->type) {
        case CT_TYPE_STRING:
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR: {
            nls->param_geter(nls, NLS_TIMESTAMP_TZ_FORMAT, &fmt_text);
            var->type = CT_TYPE_TIMESTAMP_TZ;
            return cm_text2timestamp_tz(&var->v_text, &fmt_text, cm_get_session_time_zone(nls),
                VALUE_PTR(timestamp_tz_t, var));
        }

        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:

            /* default current session time zone */
            var->type = CT_TYPE_TIMESTAMP_TZ;
            var->v_tstamp_tz.tz_offset = cm_get_session_time_zone(nls);
            return CT_SUCCESS;

        case CT_TYPE_TIMESTAMP_TZ:
            return CT_SUCCESS;
        case CT_TYPE_TIMESTAMP_LTZ:

            /* adjust whith dbtimezone */
            var->type = CT_TYPE_TIMESTAMP_TZ;
            var->v_tstamp = cm_adjust_date_between_two_tzs(var->v_tstamp,
                cm_get_db_timezone(), cm_get_session_time_zone(nls));
            var->v_tstamp_tz.tz_offset = cm_get_session_time_zone(nls);
            return CT_SUCCESS;

        default:
            CT_SET_ERROR_MISMATCH(CT_TYPE_TIMESTAMP_TZ, var->type);
            return CT_ERROR;
    }
}

status_t var_as_timestamp_flex(variant_t *var)
{
    status_t status = CT_SUCCESS;

    switch (var->type) {
        case CT_TYPE_STRING:
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR: {
            status = cm_text2date_flex(&var->v_text, VALUE_PTR(date_t, var));
            var->type = CT_TYPE_TIMESTAMP;
            break;
        }

        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
            var->type = CT_TYPE_TIMESTAMP;
            break;

        case CT_TYPE_TIMESTAMP_TZ:
            var->type = CT_TYPE_TIMESTAMP_TZ;
            break;

        default:
            CT_SET_ERROR_MISMATCH(CT_TYPE_TIMESTAMP, var->type);
            return CT_ERROR;
    }
    return status;
}

status_t var_as_bool(variant_t *var)
{
    CM_POINTER(var);

    switch (var->type) {
        case CT_TYPE_BOOLEAN:
            return CT_SUCCESS;

        case CT_TYPE_STRING:
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
            break;

        case CT_TYPE_BINARY:
            if (var->v_bin.is_hex_const) {
                CT_RETURN_IFERR(cm_xbytes2bigint(&var->v_bin, &var->v_bigint));
                var->v_bool = (var->v_bigint != 0);
                var->type = CT_TYPE_BOOLEAN;
                return CT_SUCCESS;
            }
            CT_SET_ERROR_MISMATCH(CT_TYPE_BOOLEAN, var->type);
            return CT_ERROR;

        case CT_TYPE_BIGINT:
            var->v_bool = (var->v_bigint != 0);
            var->type = CT_TYPE_BOOLEAN;
            return CT_SUCCESS;

        case CT_TYPE_UINT64:
            var->v_bool = (var->v_ubigint != 0);
            var->type = CT_TYPE_BOOLEAN;
            return CT_SUCCESS;

        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
            var->v_bool = (var->v_int != 0);
            var->type = CT_TYPE_BOOLEAN;
            return CT_SUCCESS;

        case CT_TYPE_REAL:
        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_NUMBER2:
        default:
            CT_SET_ERROR_MISMATCH(CT_TYPE_BOOLEAN, var->type);
            return CT_ERROR;
    }

    if (cm_text2bool(VALUE_PTR(text_t, var), &var->v_bool) != CT_SUCCESS) {
        return CT_ERROR;
    }

    var->type = CT_TYPE_BOOLEAN;
    return CT_SUCCESS;
}

status_t var_as_num(variant_t *var)
{
    CM_POINTER(var);

    switch (var->type) {
        case CT_TYPE_REAL:
        case CT_TYPE_BIGINT:
        case CT_TYPE_UINT64:
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_NUMBER:
        case CT_TYPE_NUMBER2:
        case CT_TYPE_DECIMAL:
            return CT_SUCCESS;

        case CT_TYPE_BOOLEAN:
            var->v_int = var->v_bool ? 1 : 0;
            var->type = CT_TYPE_INTEGER;
            return CT_SUCCESS;

        case CT_TYPE_BINARY:
            if (var->v_bin.is_hex_const) {
                CT_RETURN_IFERR(cm_xbytes2bigint(&var->v_bin, &var->v_bigint));
                var->type = CT_TYPE_BIGINT;
                return CT_SUCCESS;
            }
            break;
        case CT_TYPE_VARBINARY:
        case CT_TYPE_STRING:
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
            break;
        default:
            CT_THROW_ERROR(ERR_CONVERT_TYPE, get_datatype_name_str((int32)var->type), "NUMERIC");
            return CT_ERROR;
    }

    ct_type_t type;
    text_t text = VALUE(text_t, var);
    num_errno_t err_no = cm_is_number(&text, &type);
    if (err_no != NERR_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_NUMBER, cm_get_num_errinfo(err_no));
        return CT_ERROR;
    }

    return var_text2num(&text, type, CT_FALSE, var);
}

status_t var_as_date_mysql(variant_t *var, uint32 datatype)
{
    switch (var->type) {
        case CT_TYPE_STRING:
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR: {
            var->type = CT_TYPE_DATE;
            return cm_text2date_mysql(VALUE_PTR(text_t, var), NULL, VALUE_PTR(date_t, var), datatype);
        }

        case CT_TYPE_DATE_MYSQL:
        case CT_TYPE_TIME_MYSQL:
        case CT_TYPE_DATETIME_MYSQL:
            var->type = CT_TYPE_DATE;
            return CT_SUCCESS;
 
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_TZ:
            var->v_date = cm_timestamp2date_mysql(var->v_tstamp);
            var->type = CT_TYPE_DATE;
            return CT_SUCCESS;

        default:
            return CT_ERROR;
    }
}

#define VAR_HAS_PREFIX(text)                                                                                      \
    (((text).len >= 2) &&                                                                                              \
     (((((text).str[0] == '\\') || ((text).str[0] == '0')) && (((text).str[1] == 'x') || ((text).str[1] == 'X'))) ||   \
      (((text).str[0] == 'X') && ((text).str[1] == '\''))))

/*
* in order to use var_convert,especially if the target type being string type or binary type,
* the caller should do the following steps:
*
* 1. create a *text_buf_t* variable
* 2. allocate a buffer
* 3. call the *CM_INIT_TEXTBUF* macro to initialize the *text_buf_t* variable
*    with the allocated buffer and length of buffer
* 4. when convert variant to array, type is the element type, is_array should set to TRUE
*/
status_t var_convert(const nlsparams_t *nls, variant_t *var, ct_type_t type, text_buf_t *buf)
{
    status_t status = CT_SUCCESS;

    CT_RETVALUE_IFTRUE((var->type == type), CT_SUCCESS);
    // NULL value, set type
    if (var->is_null) {
        var->type = type;
        return CT_SUCCESS;
    }

    switch (type) {
        case CT_TYPE_UINT32:
            status = var_as_uint32(var);
            break;

        case CT_TYPE_INTEGER:
            status = var_as_integer(var);
            break;

        case CT_TYPE_BOOLEAN:
            status = var_as_bool(var);
            break;

        case CT_TYPE_NUMBER:
        case CT_TYPE_NUMBER3:
        case CT_TYPE_DECIMAL:
            status = var_as_number(var);
            break;

        case CT_TYPE_NUMBER2:
            status = var_as_number2(var);
            break;

        case CT_TYPE_BIGINT:
            status = var_as_bigint(var);
            break;

        case CT_TYPE_UINT64:
            status = var_as_ubigint(var);
            break;

        case CT_TYPE_REAL:
            status = var_as_real(var);
            break;

        case CT_TYPE_STRING:
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
            status = var_as_string(nls, var, buf);
            break;
        case CT_TYPE_DATETIME_MYSQL:
        case CT_TYPE_TIME_MYSQL:
        case CT_TYPE_DATE_MYSQL:
            status = var_as_date_mysql(var, type);
            break;

        case CT_TYPE_DATE:
            status = var_as_date(nls, var);
            break;

        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
            status = var_as_timestamp(nls, var);
            break;

        case CT_TYPE_TIMESTAMP_LTZ:
            status = var_as_timestamp_ltz(nls, var);
            break;

        case CT_TYPE_TIMESTAMP_TZ:
            status = var_as_timestamp_tz(nls, var);
            break;

        case CT_TYPE_VARBINARY:
        case CT_TYPE_BINARY:
            status = var_as_binary(nls, var, buf);
            break;

        case CT_TYPE_RAW:
            status = var_as_raw(var, buf->str, buf->max_size);
            break;

        case CT_TYPE_INTERVAL_YM:
            status = var_as_yminterval(var);
            break;

        case CT_TYPE_INTERVAL_DS:
            status = var_as_dsinterval(var);
            break;

        case CT_TYPE_CLOB:
            status = var_as_clob(nls, var, buf);
            break;

        case CT_TYPE_BLOB:
            status = var_as_blob(var, buf);
            break;

        case CT_TYPE_IMAGE:
            status = var_as_image(nls, var, buf);
            break;

        case CT_TYPE_CURSOR:
        case CT_TYPE_COLUMN:
        case CT_TYPE_ARRAY:
        case CT_TYPE_BASE:
        default:
            CT_SET_ERROR_MISMATCH(type, var->type);
            return CT_ERROR;
    }

    var->type = type;
    return status;
}

status_t var_as_binary(const nlsparams_t *nls, variant_t *var, text_buf_t *buf)
{
    if (var->is_null) {
        var->type = CT_TYPE_BINARY;
        var->v_bin.is_hex_const = CT_FALSE;
        return CT_SUCCESS;
    }

    switch (var->type) {
        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            // raw, binary can transform?
            return CT_SUCCESS;

        case CT_TYPE_STRING:
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR: {
            var->type = CT_TYPE_BINARY;
            var->v_bin.is_hex_const = CT_FALSE;
            return CT_SUCCESS;
        }

                              // any other types convert to string
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_BIGINT:
        case CT_TYPE_UINT64:
        case CT_TYPE_REAL:
        case CT_TYPE_NUMBER:
        case CT_TYPE_NUMBER2:
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_BOOLEAN:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_TZ:
        case CT_TYPE_TIMESTAMP_LTZ:
        case CT_TYPE_INTERVAL_DS:
        case CT_TYPE_INTERVAL_YM: {
            CT_RETURN_IFERR(var_as_string(nls, var, buf));
            var->type = CT_TYPE_BINARY;
            var->v_bin.is_hex_const = CT_FALSE;
            return CT_SUCCESS;
        }
        default:
            CT_SET_ERROR_MISMATCH(CT_TYPE_BINARY, var->type);
            return CT_ERROR;
    }
}

status_t var_as_raw(variant_t *var, char *buf, uint32 buf_size)
{
    bool32 has_prefix = CT_FALSE;
    binary_t bin;

    if (var->is_null) {
        var->type = CT_TYPE_RAW;
        return CT_SUCCESS;
    }

    switch (var->type) {
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING: {
            // same as oracle, we interprets each consecutive input character as a hexadecimal representation
            //  of four consecutive bits of binary data
            has_prefix = VAR_HAS_PREFIX(var->v_text);
            bin.bytes = (uint8 *)buf;
            bin.size = 0;
            if (cm_text2bin(&var->v_text, has_prefix, &bin, buf_size) != CT_SUCCESS) {
                return CT_ERROR;
            }

            var->v_bin.bytes = bin.bytes;
            var->v_bin.size = bin.size;
            var->type = CT_TYPE_RAW;
            return CT_SUCCESS;
        }

                             // jdbc type is bianry
        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
            var->type = CT_TYPE_RAW;
            return CT_SUCCESS;

        case CT_TYPE_RAW:
            return CT_SUCCESS;

        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_BIGINT:
        case CT_TYPE_UINT64:
        case CT_TYPE_REAL:
        case CT_TYPE_NUMBER:
        case CT_TYPE_NUMBER2:
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        default:
            CT_SET_ERROR_MISMATCH(CT_TYPE_RAW, var->type);
            return CT_ERROR;
    }
}

status_t var_as_yminterval(variant_t *var)
{
    if (var->is_null) {
        var->type = CT_TYPE_INTERVAL_YM;
        return CT_SUCCESS;
    }

    switch (var->type) {
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING: {
            CT_RETURN_IFERR(cm_text2yminterval(&var->v_text, &var->v_itvl_ym));
            var->type = CT_TYPE_INTERVAL_YM;
            return CT_SUCCESS;
        }

        case CT_TYPE_INTERVAL_YM:
            return CT_SUCCESS;

        case CT_TYPE_BINARY:
        case CT_TYPE_RAW:
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_BIGINT:
        case CT_TYPE_UINT64:
        case CT_TYPE_REAL:
        case CT_TYPE_NUMBER:
        case CT_TYPE_NUMBER2:
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        default:
            CT_SET_ERROR_MISMATCH(CT_TYPE_INTERVAL_YM, var->type);
            return CT_ERROR;
    }
}

status_t var_as_dsinterval(variant_t *var)
{
    if (var->is_null) {
        var->type = CT_TYPE_INTERVAL_DS;
        return CT_SUCCESS;
    }

    switch (var->type) {
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING: {
            CT_RETURN_IFERR(cm_text2dsinterval(&var->v_text, &var->v_itvl_ds));
            var->type = CT_TYPE_INTERVAL_DS;
            return CT_SUCCESS;
        }

        case CT_TYPE_INTERVAL_DS:
            return CT_SUCCESS;

        case CT_TYPE_BINARY:
        case CT_TYPE_RAW:
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_BIGINT:
        case CT_TYPE_UINT64:
        case CT_TYPE_REAL:
        case CT_TYPE_NUMBER:
        case CT_TYPE_NUMBER2:
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        default:
            CT_SET_ERROR_MISMATCH(CT_TYPE_INTERVAL_DS, var->type);
            return CT_ERROR;
    }
}

status_t var_to_int64_check_overflow(uint64 u64)
{
    if (u64 > (uint64)CT_MAX_INT64) {
        CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "BIGINT");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}


status_t var_to_round_bigint(const variant_t *var, round_mode_t rnd_mode, int64 *i64, int *overflow)
{
    status_t ret;
    CM_POINTER(var);

    if (overflow != NULL) {
        *overflow = OVERFLOW_NONE;
    }

    switch (var->type) {
        case CT_TYPE_UINT32:
            *i64 = (int64)var->v_uint32;
            return CT_SUCCESS;
        case CT_TYPE_INTEGER:
            *i64 = (int64)var->v_int;
            return CT_SUCCESS;

        case CT_TYPE_BIGINT:
            *i64 = var->v_bigint;
            return CT_SUCCESS;

        case CT_TYPE_UINT64:
            CT_RETURN_IFERR(var_to_int64_check_overflow(var->v_ubigint));
            *i64 = (int64)var->v_bigint;
            return CT_SUCCESS;

        case CT_TYPE_REAL: {
            double val = cm_round_real(var->v_real, rnd_mode);
            *i64 = (int64)val;
            if (REAL2INT64_IS_OVERFLOW(*i64, val)) {
                CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "BIGINT");
                if (overflow != NULL) {
                    *overflow = (val > 0) ? OVERFLOW_UPWARD : OVERFLOW_DOWNWARD;
                }
                return CT_ERROR;
            }
            return CT_SUCCESS;
        }
        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_NUMBER2:
            ret = cm_dec_to_int64((dec8_t *)&var->v_dec, i64, rnd_mode);
            if (ret != CT_SUCCESS && overflow != NULL) {
                *overflow = (IS_DEC8_NEG(&var->v_dec)) ? OVERFLOW_DOWNWARD : OVERFLOW_UPWARD;
            }
            return ret;

        case CT_TYPE_BOOLEAN:
            *i64 = var->v_bool ? 1 : 0;
            return CT_SUCCESS;

        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
            if (var->v_bin.is_hex_const) {
                return cm_xbytes2bigint(&var->v_bin, i64);
            }
            /* fall-through */
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING: {
            dec8_t dec;
            CT_RETURN_IFERR(cm_text_to_dec(&var->v_text, &dec));
            ret = cm_dec8_to_int64(&dec, i64, rnd_mode);
            if (ret != CT_SUCCESS && overflow != NULL) {
                *overflow = (IS_DEC8_NEG(&var->v_dec)) ? OVERFLOW_DOWNWARD : OVERFLOW_UPWARD;
            }
            return ret;
        }

        case CT_TYPE_RAW:
        default:
            CT_SET_ERROR_MISMATCH(CT_TYPE_BIGINT, var->type);
            return CT_ERROR;
    }
}

status_t var_to_round_ubigint(const variant_t *uvar, round_mode_t rnd_mode, uint64 *ui64, int *uoverflow)
{
    status_t uret;
    CM_POINTER(uvar);

    if (uoverflow != NULL) {
        *uoverflow = OVERFLOW_NONE;
    }

    switch (uvar->type) {
        case CT_TYPE_UINT32:
            *ui64 = (uint64)uvar->v_uint32;
            return CT_SUCCESS;
        case CT_TYPE_INTEGER:
            TO_UINT64_OVERFLOW_CHECK(uvar->v_int, int32);
            *ui64 = (uint64)uvar->v_int;
            return CT_SUCCESS;
        
        case CT_TYPE_BIGINT:
            TO_UINT64_OVERFLOW_CHECK(uvar->v_bigint, int64);
            *ui64 = (uint32)uvar->v_bigint;
            return CT_SUCCESS;

        case CT_TYPE_UINT64:
            *ui64 = uvar->v_ubigint;
            return CT_SUCCESS;
        
        case CT_TYPE_REAL: {
            double val = cm_round_real(uvar->v_real, rnd_mode);
            *ui64 = (uint64)val;
            if (REAL2UINT64_IS_OVERFLOW(*ui64, val)) {
                CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "UNSIGNED BIGINT");
                if (uoverflow != NULL) {
                    *uoverflow = (val > 0) ? OVERFLOW_UPWARD : OVERFLOW_DOWNWARD;
                }
                return CT_ERROR;
            }
            return CT_SUCCESS;
        }
        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_NUMBER2:
            uret = cm_dec_to_uint64((dec8_t *)&uvar->v_dec, ui64, rnd_mode);
            if (uret != CT_SUCCESS && uoverflow != NULL) {
                *uoverflow = (IS_DEC8_NEG(&uvar->v_dec)) ? OVERFLOW_DOWNWARD : OVERFLOW_UPWARD;
            }
            return uret;

        case CT_TYPE_BOOLEAN:
            *ui64 = uvar->v_bool ? 1 : 0;
            return CT_SUCCESS;

        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
            if (uvar->v_bin.is_hex_const) {
                return cm_xbytes2ubigint(&uvar->v_bin, ui64);
            }
            /* fall-through */
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING: {
            dec8_t dec;
            CT_RETURN_IFERR(cm_text_to_dec(&uvar->v_text, &dec));
            uret = cm_dec_to_uint64(&dec, ui64, rnd_mode);
            if (uret != CT_SUCCESS && uoverflow != NULL) {
                *uoverflow = (IS_DEC8_NEG(&uvar->v_dec)) ? OVERFLOW_DOWNWARD : OVERFLOW_UPWARD;
            }
            return uret;
        }

        case CT_TYPE_RAW:
        default:
            CT_SET_ERROR_MISMATCH(CT_TYPE_UINT64, uvar->type);
            return CT_ERROR;
    }
}

/**
* Get a integer32 from a variant

*/
status_t var_to_round_uint32(const variant_t *var, round_mode_t rnd_mode, uint32 *u32)
{
    CM_POINTER(var);

    switch (var->type) {
        case CT_TYPE_UINT32:
            *u32 = var->v_uint32;
            return CT_SUCCESS;

        case CT_TYPE_INTEGER:
            TO_UINT32_OVERFLOW_CHECK(var->v_int, int64);
            *u32 = (uint32)var->v_int;
            return CT_SUCCESS;

        case CT_TYPE_BIGINT: {
            TO_UINT32_OVERFLOW_CHECK(var->v_bigint, int64);
            *u32 = (uint32)var->v_bigint;
            return CT_SUCCESS;
        }

        case CT_TYPE_UINT64: {
            TO_UINT32_OVERFLOW_CHECK(var->v_ubigint, uint64);
            *u32 = (uint32)var->v_ubigint;
            return CT_SUCCESS;
        }

        case CT_TYPE_REAL: {
            TO_UINT32_OVERFLOW_CHECK(var->v_real, double);
            *u32 = (uint32)cm_round_real(var->v_real, rnd_mode);
            return CT_SUCCESS;
        }
        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_NUMBER2:
            return cm_dec_to_uint32((dec8_t *)&var->v_dec, u32, rnd_mode);

        case CT_TYPE_BOOLEAN:
            *u32 = var->v_bool ? 1 : 0;
            return CT_SUCCESS;

        case CT_TYPE_BINARY:
            if (var->v_bin.is_hex_const) {
                return cm_xbytes2uint32(&var->v_bin, u32);
            }
            /* fall-through */
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
        case CT_TYPE_VARBINARY: {
            double real;
            num_errno_t  err_no = cm_text2real_ex(&var->v_text, &real);
            CM_TRY_THROW_NUM_ERR(err_no);
            real = cm_round_real(real, rnd_mode);
            TO_UINT32_OVERFLOW_CHECK(real, double);
            *u32 = (uint32)real;
            return CT_SUCCESS;
        }

        case CT_TYPE_RAW:
        default:
            CT_SET_ERROR_MISMATCH(CT_TYPE_UINT32, var->type);
            return CT_ERROR;
    }
}

status_t var_to_int32_check_overflow(uint32 u32)
{
    if (u32 > (uint32)CT_MAX_INT32) {
        CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "INTEGER");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

/**
* Get a integer32 from a variant

*/
status_t var_to_round_int32(const variant_t *var, round_mode_t rnd_mode, int32 *i32)
{
    CM_POINTER(var);

    switch (var->type) {
        case CT_TYPE_UINT32:
            CT_RETURN_IFERR(var_to_int32_check_overflow(var->v_uint32));
            *i32 = (int32)var->v_uint32;
            return CT_SUCCESS;

        case CT_TYPE_INTEGER:
            *i32 = var->v_int;
            return CT_SUCCESS;

        case CT_TYPE_BIGINT:
            INT32_OVERFLOW_CHECK(var->v_bigint);
            *i32 = (int32)var->v_bigint;
            return CT_SUCCESS;

        case CT_TYPE_UINT64:
            INT32_OVERFLOW_CHECK(var->v_ubigint);
            *i32 = (int32)var->v_ubigint;
            return CT_SUCCESS;

        case CT_TYPE_REAL:
            INT32_OVERFLOW_CHECK(var->v_real);
            *i32 = (int32)cm_round_real(var->v_real, rnd_mode);
            return CT_SUCCESS;

        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_NUMBER2:
            return cm_dec_to_int32((dec8_t *)&var->v_dec, i32, rnd_mode);

        case CT_TYPE_BOOLEAN:
            *i32 = var->v_bool ? 1 : 0;
            return CT_SUCCESS;

        case CT_TYPE_BINARY:
            if (var->v_bin.is_hex_const) {
                return cm_xbytes2int32(&var->v_bin, i32);
            }
            /* fall-through */
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
        case CT_TYPE_VARBINARY: {
            double real;
            num_errno_t err_no = cm_text2real_ex(&var->v_text, &real);
            CM_TRY_THROW_NUM_ERR(err_no);
            real = cm_round_real(real, rnd_mode);
            INT32_OVERFLOW_CHECK(real);
            *i32 = (int32)real;
            return CT_SUCCESS;
        }
        default:
            CT_SET_ERROR_MISMATCH(CT_TYPE_INTEGER, var->type);
            return CT_ERROR;
    }
}

static status_t var_time_to_text(const nlsparams_t *nls, variant_t *var, text_t *text)
{
    text_t fmt_text;
    status_t status = CT_SUCCESS;

    switch (var->type) {
        case CT_TYPE_DATE:
            nls->param_geter(nls, NLS_DATE_FORMAT, &fmt_text);
            status = cm_date2text(VALUE(date_t, var), &fmt_text, text, text->len);
            break;
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
            nls->param_geter(nls, NLS_TIMESTAMP_FORMAT, &fmt_text);
            status = cm_timestamp2text(VALUE(timestamp_t, var), &fmt_text, text, text->len);
            break;
        case CT_TYPE_TIMESTAMP_TZ:
            nls->param_geter(nls, NLS_TIMESTAMP_TZ_FORMAT, &fmt_text);
            status = cm_timestamp_tz2text(VALUE_PTR(timestamp_tz_t, var), &fmt_text, text, text->len);
            break;
        case CT_TYPE_TIMESTAMP_LTZ:
            nls->param_geter(nls, NLS_TIMESTAMP_FORMAT, &fmt_text);

            /* convert from dbtimezone to sessiontimezone */
            var->v_tstamp_ltz = cm_adjust_date_between_two_tzs(var->v_tstamp_ltz, cm_get_db_timezone(),
                cm_get_session_time_zone(nls));
            status = cm_timestamp2text(VALUE(timestamp_ltz_t, var), &fmt_text, text, text->len);
            break;
        default:
            return CT_ERROR;
    }

    return status;
}

static status_t var_to_text(const nlsparams_t *nls, variant_t *var, text_t *text)
{
    status_t status = CT_SUCCESS;

    switch (var->type) {
        case CT_TYPE_UINT32:
            cm_uint32_to_text(VALUE(uint32, var), text);
            break;
        case CT_TYPE_INTEGER:
            cm_int2text(VALUE(int32, var), text);
            break;
        case CT_TYPE_BOOLEAN:
            cm_bool2text(VALUE(bool32, var), text);
            break;
        case CT_TYPE_BIGINT:
            cm_bigint2text(VALUE(int64, var), text);
            break;
        case CT_TYPE_UINT64:
            cm_uint64_to_text(VALUE(uint64, var), text);
            break;
        case CT_TYPE_REAL:
            cm_real2text(VALUE(double, var), text);
            break;
        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_NUMBER2:
            status = cm_dec_to_text(VALUE_PTR(dec8_t, var), CT_MAX_DEC_OUTPUT_PREC, text);
            break;
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_TZ:
        case CT_TYPE_TIMESTAMP_LTZ:
            status = var_time_to_text(nls, var, text);
            break;
        case CT_TYPE_RAW:
            status = cm_bin2text(VALUE_PTR(binary_t, var), CT_FALSE, text);
            break;
        case CT_TYPE_INTERVAL_DS:
            cm_dsinterval2text(var->v_itvl_ds, text);
            break;
        case CT_TYPE_INTERVAL_YM:
            cm_yminterval2text(var->v_itvl_ym, text);
            break;
        case CT_TYPE_ARRAY:
            status = cm_array2text(nls, &var->v_array, text);
            break;
        default:
            return CT_ERROR;
    }

    return status;
}

/*
* in order to use var_as_string,
* the caller should do the following steps:
*
* 1. create a *text_buf_t* variable
* 2. allocate a buffer
* 3. call the *CM_INIT_TEXTBUF* macro to initialize the *text_buf_t* variable
*    with the allocated buffer and length of buffer
*
*/
status_t var_as_string(const nlsparams_t *nls, variant_t *var, text_buf_t *buf)
{
    text_t text;

    if (var->is_null) {
        var->type = CT_TYPE_STRING;
        return CT_SUCCESS;
    }

    switch (var->type) {
        case CT_TYPE_STRING:
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
            var->type = CT_TYPE_STRING;
            return CT_SUCCESS;

        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_BOOLEAN:
        case CT_TYPE_BIGINT:
        case CT_TYPE_UINT64:
        case CT_TYPE_REAL:
        case CT_TYPE_NUMBER:
        case CT_TYPE_NUMBER2:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_TZ:
        case CT_TYPE_TIMESTAMP_LTZ:
        case CT_TYPE_RAW:
        case CT_TYPE_INTERVAL_DS:
        case CT_TYPE_INTERVAL_YM:
        case CT_TYPE_ARRAY:
            if (buf == NULL || buf->str == NULL) {
                CT_THROW_ERROR(ERR_COVNERT_FORMAT_ERROR, "string");
                return CT_ERROR;
            }

            text.str = buf->str;
            text.len = buf->max_size;
            if (var_to_text(nls, var, &text) != CT_SUCCESS) {
                return CT_ERROR;
            }
            var->v_text = text;
            var->type = CT_TYPE_STRING;
            break;

        default:
            CT_SET_ERROR_MISMATCH(CT_TYPE_STRING, var->type);
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t var_as_string2(const nlsparams_t *nls, variant_t *var, text_buf_t *buf, typmode_t *typmod)
{
    status_t status;
    text_t text;
    text_t fmt_text;

    if (var->is_null) {
        var->type = CT_TYPE_STRING;
        return CT_SUCCESS;
    }

    /* use the local variable "text" as the temporary argument for cm_xxxxxx() series
    so that we don't need to change the interface of the cm_xxxxxx() series */
    text.str = buf->str;
    text.len = buf->max_size;

    status = CT_SUCCESS;
    switch (var->type) {
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE: {
            nls->param_geter(nls, NLS_TIMESTAMP_FORMAT, &fmt_text);
            status = cm_timestamp2text_prec(VALUE(timestamp_t, var), &fmt_text, &text, text.len, typmod->precision);
            break;
        }

        case CT_TYPE_TIMESTAMP_TZ:
            nls->param_geter(nls, NLS_TIMESTAMP_TZ_FORMAT, &fmt_text);
            status = cm_timestamp_tz2text_prec(VALUE_PTR(timestamp_tz_t, var), &fmt_text, &text, text.len,
                typmod->precision);
            break;

        case CT_TYPE_TIMESTAMP_LTZ: {
            nls->param_geter(nls, NLS_TIMESTAMP_FORMAT, &fmt_text);

            /* convert from dbtiomezone to sessiontimezone */
            var->v_tstamp_ltz = cm_adjust_date_between_two_tzs(var->v_tstamp_ltz, cm_get_db_timezone(),
                cm_get_session_time_zone(nls));
            status = cm_timestamp2text_prec(VALUE(timestamp_ltz_t, var), &fmt_text, &text, text.len, typmod->precision);
            break;
        }

        case CT_TYPE_INTERVAL_DS:
            cm_dsinterval2text_prec(var->v_itvl_ds, typmod->day_prec, typmod->frac_prec, &text);
            break;

        case CT_TYPE_INTERVAL_YM:
            cm_yminterval2text_prec(var->v_itvl_ym, typmod->year_prec, &text);
            break;

        default:
            CT_SET_ERROR_MISMATCH(CT_TYPE_STRING, var->type);
            return CT_ERROR;
    }

    CT_RETURN_IFERR(status);

    var->v_text = text;
    var->type = CT_TYPE_STRING;
    return CT_SUCCESS;
}

status_t datetype_as_string(const nlsparams_t *nls, variant_t *var, typmode_t *typmod, text_buf_t *buf)
{
    status_t status;
    text_t text;
    text_t fmt_text;

    if (var->is_null) {
        var->type = CT_TYPE_STRING;
        return CT_SUCCESS;
    }

    /* use the local variable "text" as the temporary argument for cm_xxxxxx() series
    so that we don't need to change the interface of the cm_xxxxxx() series */
    text.str = buf->str;
    text.len = buf->max_size;

    status = CT_SUCCESS;
    switch (var->type) {
        case CT_TYPE_DATE:
            nls->param_geter(nls, NLS_DATE_FORMAT, &fmt_text);
            status = cm_date2text_ex(VALUE(date_t, var), &fmt_text, typmod->precision, &text, text.len);
            break;

        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
            nls->param_geter(nls, NLS_TIMESTAMP_FORMAT, &fmt_text);
            status = cm_timestamp2text_ex(VALUE(timestamp_t, var), &fmt_text, typmod->precision, &text, text.len);
            break;

        case CT_TYPE_TIMESTAMP_TZ:
            nls->param_geter(nls, NLS_TIMESTAMP_TZ_FORMAT, &fmt_text);
            status = cm_timestamp_tz2text_ex(VALUE_PTR(timestamp_tz_t, var), &fmt_text,
                typmod->precision, &text, text.len);
            break;

        case CT_TYPE_INTERVAL_DS:
            text.len = cm_dsinterval2str_ex(var->v_itvl_ds, typmod->day_prec, typmod->frac_prec, text.str, text.len);
            break;

        case CT_TYPE_INTERVAL_YM:
            text.len = cm_yminterval2str_ex(var->v_itvl_ym, typmod->year_prec, text.str);
            break;

        default:
            CT_SET_ERROR_MISMATCH(CT_TYPE_STRING, var->type);
            return CT_ERROR;
    }

    CT_RETURN_IFERR(status);

    var->v_text = text;
    var->type = CT_TYPE_STRING;
    return CT_SUCCESS;
}

status_t var_as_clob(const nlsparams_t *nls, variant_t *var, text_buf_t *buf)
{
    status_t status;
    text_t text;
    text_t fmt_text;

    if (var->is_null) {
        var->type = CT_TYPE_CLOB;
        return CT_SUCCESS;
    }

    /* use the local variable "text" as the temporary argument for cm_xxxxxx() series
    so that we don't need to change the interface of the cm_xxxxxx() series */
    text.str = buf->str;
    text.len = buf->max_size;

    status = CT_SUCCESS;
    switch (var->type) {
        case CT_TYPE_STRING:
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
            text = var->v_text;
            break;

        case CT_TYPE_UINT32:
            cm_uint32_to_text(VALUE(uint32, var), &text);
            break;
        case CT_TYPE_INTEGER:
            cm_int2text(VALUE(int32, var), &text);
            break;

        case CT_TYPE_BOOLEAN:
            cm_bool2text(VALUE(bool32, var), &text);
            break;

        case CT_TYPE_BIGINT:
            cm_bigint2text(VALUE(int64, var), &text);
            break;

        case CT_TYPE_UINT64:
            cm_uint64_to_text(VALUE(uint64, var), &text);
            break;

        case CT_TYPE_REAL:
            cm_real2text(VALUE(double, var), &text);
            break;

        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_NUMBER2:
            status = cm_dec_to_text(VALUE_PTR(dec8_t, var), CT_MAX_DEC_OUTPUT_PREC, &text);
            break;

        case CT_TYPE_DATE:
            nls->param_geter(nls, NLS_DATE_FORMAT, &fmt_text);
            status = cm_date2text(VALUE(date_t, var), &fmt_text, &text, text.len);
            break;

        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
            nls->param_geter(nls, NLS_TIMESTAMP_FORMAT, &fmt_text);
            status = cm_timestamp2text(VALUE(timestamp_t, var), &fmt_text, &text, text.len);
            break;

        case CT_TYPE_TIMESTAMP_TZ:
            nls->param_geter(nls, NLS_TIMESTAMP_TZ_FORMAT, &fmt_text);
            status = cm_timestamp_tz2text(VALUE_PTR(timestamp_tz_t, var), &fmt_text, &text, text.len);
            break;

        case CT_TYPE_INTERVAL_DS:
            cm_dsinterval2text(var->v_itvl_ds, &text);
            break;

        case CT_TYPE_INTERVAL_YM:
            cm_yminterval2text(var->v_itvl_ym, &text);
            break;

        case CT_TYPE_RAW:
            status = cm_bin2text(&var->v_bin, CT_FALSE, &text);
            break;

        default:
            CT_SET_ERROR_MISMATCH(CT_TYPE_CLOB, var->type);
            return CT_ERROR;
    }

    CT_RETURN_IFERR(status);

    var->v_lob.type = CT_LOB_FROM_NORMAL;
    var->v_lob.normal_lob.size = text.len;
    var->v_lob.normal_lob.type = CT_LOB_FROM_NORMAL;
    var->v_lob.normal_lob.value = text;
    var->type = CT_TYPE_CLOB;
    return CT_SUCCESS;
}

status_t var_as_blob(variant_t *var, text_buf_t *buf)
{
    bool32 has_prefix = CT_FALSE;
    binary_t bin;
    bin.bytes = (uint8 *)buf->str;
    bin.size = buf->max_size;

    if (var->is_null) {
        var->type = CT_TYPE_BLOB;
        return CT_SUCCESS;
    }

    switch (var->type) {
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
            if (var->v_text.len > bin.size * 2) {
                CT_THROW_ERROR(ERR_COVNERT_FORMAT_ERROR, "blob");
                return CT_ERROR;
            }
            has_prefix = VAR_HAS_PREFIX(var->v_text);
            bin.size = 0;
            CT_RETURN_IFERR(cm_text2bin(&var->v_text, has_prefix, &bin, buf->max_size));
            break;

        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            if (var->v_bin.size > bin.size) {
                CT_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "blob");
                return CT_ERROR;
            }
            if (var->v_bin.size != 0) {
                MEMS_RETURN_IFERR(memcpy_sp(bin.bytes, bin.size, var->v_bin.bytes, var->v_bin.size));
            }
            bin.size = var->v_bin.size;
            break;

        default:
            CT_SET_ERROR_MISMATCH(CT_TYPE_BLOB, var->type);
            return CT_ERROR;
    }

    var->v_lob.type = CT_LOB_FROM_NORMAL;
    var->v_lob.normal_lob.size = bin.size;
    var->v_lob.normal_lob.type = CT_LOB_FROM_NORMAL;
    var->v_lob.normal_lob.value.str = (char *)bin.bytes;
    var->v_lob.normal_lob.value.len = bin.size;
    var->type = CT_TYPE_BLOB;
    return CT_SUCCESS;
}

status_t var_as_image(const nlsparams_t *nls, variant_t *var, text_buf_t *buf)
{
    status_t status;
    text_t text;
    text_t fmt_text;

    if (var->is_null) {
        var->type = CT_TYPE_IMAGE;
        return CT_SUCCESS;
    }

    /* use the local variable "text" as the temporary argument for cm_xxxxxx() series
    so that we don't need to change the interface of the cm_xxxxxx() series */
    text.str = buf->str;
    text.len = buf->max_size;

    status = CT_SUCCESS;
    switch (var->type) {
        case CT_TYPE_STRING:
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
            if (var->v_text.len > text.len) {
                CT_THROW_ERROR(ERR_COVNERT_FORMAT_ERROR, "image");
                return CT_ERROR;
            }
            if (var->v_text.len != 0) {
                MEMS_RETURN_IFERR(memcpy_sp(text.str, text.len, var->v_text.str, var->v_text.len));
            }
            text.len = var->v_text.len;
            break;

        case CT_TYPE_UINT32:
            cm_uint32_to_text(VALUE(uint32, var), &text);
            break;

        case CT_TYPE_INTEGER:
            cm_int2text(VALUE(int32, var), &text);
            break;

        case CT_TYPE_BOOLEAN:
            cm_bool2text(VALUE(bool32, var), &text);
            break;

        case CT_TYPE_BIGINT:
            cm_bigint2text(VALUE(int64, var), &text);
            break;

        case CT_TYPE_UINT64:
            cm_uint64_to_text(VALUE(uint64, var), &text);
            break;

        case CT_TYPE_REAL:
            cm_real2text(VALUE(double, var), &text);
            break;

        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_NUMBER2:
            status = cm_dec_to_text(VALUE_PTR(dec8_t, var), CT_MAX_DEC_OUTPUT_PREC, &text);
            break;

        case CT_TYPE_DATE:
            nls->param_geter(nls, NLS_DATE_FORMAT, &fmt_text);
            status = cm_date2text(VALUE(date_t, var), &fmt_text, &text, text.len);
            break;

        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
            nls->param_geter(nls, NLS_TIMESTAMP_FORMAT, &fmt_text);
            status = cm_timestamp2text(VALUE(timestamp_t, var), &fmt_text, &text, text.len);
            break;

        case CT_TYPE_TIMESTAMP_TZ:
            nls->param_geter(nls, NLS_TIMESTAMP_TZ_FORMAT, &fmt_text);
            status = cm_timestamp_tz2text(VALUE_PTR(timestamp_tz_t, var), &fmt_text, &text, text.len);
            break;

        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            if (var->v_bin.size > text.len) {
                CT_THROW_ERROR(ERR_COVNERT_FORMAT_ERROR, "image");
                return CT_ERROR;
            }
            if (var->v_text.len != 0) {
                MEMS_RETURN_IFERR(memcpy_sp(text.str, text.len, var->v_bin.bytes, var->v_bin.size));
            }
            text.len = var->v_bin.size;
            break;

        case CT_TYPE_INTERVAL_DS:
            cm_dsinterval2text(var->v_itvl_ds, &text);
            break;

        case CT_TYPE_INTERVAL_YM:
            cm_yminterval2text(var->v_itvl_ym, &text);
            break;

        default:
            CT_SET_ERROR_MISMATCH(CT_TYPE_IMAGE, var->type);
            return CT_ERROR;
    }

    CT_RETURN_IFERR(status);

    var->v_lob.type = CT_LOB_FROM_NORMAL;
    var->v_lob.normal_lob.size = text.len;
    var->v_lob.normal_lob.type = CT_LOB_FROM_NORMAL;
    var->v_lob.normal_lob.value = text;
    var->type = CT_TYPE_IMAGE;
    return CT_SUCCESS;
}

static status_t var_as_decimal_core(variant_t *var)
{
    switch (var->type) {
        case CT_TYPE_BINARY:
            if (var->v_bin.is_hex_const) {
                CT_RETURN_IFERR(cm_xbytes2bigint(&var->v_bin, &var->v_bigint));
                cm_int64_to_dec(var->v_bigint, VALUE_PTR(dec8_t, var));
                return CT_SUCCESS;
            }
            /* fall-through */
        case CT_TYPE_STRING:
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_VARBINARY: {
            text_t var_text = var->v_text;
            return cm_text_to_dec(&var_text, VALUE_PTR(dec8_t, var));
        }
        case CT_TYPE_UINT32:
            cm_uint32_to_dec(var->v_uint32, VALUE_PTR(dec8_t, var));
            return CT_SUCCESS;

        case CT_TYPE_INTEGER:
            cm_int32_to_dec(var->v_int, VALUE_PTR(dec8_t, var));
            return CT_SUCCESS;

        case CT_TYPE_BIGINT:
            cm_int64_to_dec(var->v_bigint, VALUE_PTR(dec8_t, var));
            return CT_SUCCESS;

        case CT_TYPE_UINT64:
            cm_uint64_to_dec(var->v_ubigint, VALUE_PTR(dec8_t, var));
            return CT_SUCCESS;

        case CT_TYPE_REAL:
            return cm_real_to_dec(var->v_real, VALUE_PTR(dec8_t, var));

        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_NUMBER2:
        case CT_TYPE_NUMBER3:
            return CT_SUCCESS;

        case CT_TYPE_RAW:
        default:
            CT_SET_ERROR_MISMATCH(CT_TYPE_NUMBER, var->type);
            return CT_ERROR;
    }
}

status_t var_as_decimal(variant_t *var)
{
    CT_RETURN_IFERR(var_as_decimal_core(var)); // var->v_dec's range is [DEC2_EXPN_LOW, MAX_NUMERIC_EXPN]
    if (var->type == CT_TYPE_NUMBER2) { // number2, range is [DEC2_EXPN_LOW, DEC2_EXPN_UPPER]
        return CT_SUCCESS;
    }
    var->type = CT_TYPE_NUMBER; // number, range is [MIN_NUMERIC_EXPN, MAX_NUMERIC_EXPN]
    if (!var->is_null) {
        CT_RETURN_IFERR(cm_dec_check_overflow(&var->v_dec, var->type));
    }
    return CT_SUCCESS;
}

// number, range is [MIN_NUMERIC_EXPN, MAX_NUMERIC_EXPN]
status_t var_as_number(variant_t *var)
{
    CT_RETURN_IFERR(var_as_decimal_core(var));
    var->type = CT_TYPE_NUMBER;
    if (!var->is_null) {
        CT_RETURN_IFERR(cm_dec_check_overflow(&var->v_dec, var->type));
    }
    return CT_SUCCESS;
}

// number2, range is [DEC2_EXPN_LOW, DEC2_EXPN_UPPER]
status_t var_as_number2(variant_t *var)
{
    CT_RETURN_IFERR(var_as_decimal_core(var));
    var->type = CT_TYPE_NUMBER2;
    if (!var->is_null) {
        CT_RETURN_IFERR(cm_dec_check_overflow(&var->v_dec, var->type));
    }
    return CT_SUCCESS;
}

status_t var_as_real(variant_t *var)
{
    switch (var->type) {
        case CT_TYPE_UINT32:
            var->v_real = (double)VALUE(uint32, var);
            break;
        case CT_TYPE_INTEGER:
            var->v_real = (double)VALUE(int32, var);
            break;
        case CT_TYPE_BIGINT:
            VALUE(double, var) = (double)VALUE(int64, var);
            break;
        case CT_TYPE_UINT64:
            VALUE(double, var) = (double)VALUE(uint64, var);
            break;
        case CT_TYPE_REAL:
            return CT_SUCCESS;

        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_NUMBER2:
            VALUE(double, var) = (double)cm_dec_to_real(VALUE_PTR(dec8_t, var));
            break;

        case CT_TYPE_BINARY:
            if (var->v_bin.is_hex_const) {
                CT_RETURN_IFERR(cm_xbytes2bigint(&var->v_bin, &var->v_bigint));
                VALUE(double, var) = (double)var->v_bigint;
                var->type = CT_TYPE_REAL;
                return CT_SUCCESS;
            }
            /* fall-through */
        case CT_TYPE_STRING:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_CHAR:
        case CT_TYPE_VARBINARY: {
            num_errno_t nerr_no = cm_text2real_ex(&var->v_text, &var->v_real);
            CM_TRY_THROW_NUM_ERR(nerr_no);
            break;
        }

        default:
            CT_SET_ERROR_MISMATCH(CT_TYPE_REAL, var->type);
            return CT_ERROR;
    }

    var->type = CT_TYPE_REAL;
    return CT_SUCCESS;
}

status_t var_to_unix_timestamp(dec8_t *unix_ts, timestamp_t *ts_ret, int64 time_zone_offset)
{
    timestamp_t ts;

    if (CT_SUCCESS != cm_int64_mul_dec((int64)MICROSECS_PER_SECOND, unix_ts, unix_ts)) {
        cm_reset_error();
        CT_SET_ERROR_TIMESTAMP_OVERFLOW();
        return CT_ERROR;
    }

    if (CT_SUCCESS != cm_dec_to_int64(unix_ts, &ts, ROUND_TRUNC)) {
        cm_reset_error();
        CT_SET_ERROR_TIMESTAMP_OVERFLOW();
        return CT_ERROR;
    }

    *ts_ret = ts + CM_UNIX_EPOCH + time_zone_offset;
    if (!CM_IS_VALID_TIMESTAMP(*ts_ret)) {
        CT_SET_ERROR_TIMESTAMP_OVERFLOW();
        return CT_ERROR;
    }
    return CT_SUCCESS;
}