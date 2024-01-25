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
 * ctsql_func.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/node/ctsql_func.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_FUNC_H__
#define __SQL_FUNC_H__

#include "cm_defs.h"
#include "cm_text.h"
#include "var_inc.h"
#include "ctsql_expr.h"
#include "ctsql_stmt.h"
#include "ctsql_verifier.h"
#include "cm_uuid.h"
#include "srv_instance.h"
#include <math.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_sql_aggr_type {
    AGGR_TYPE_NONE = 0,
    AGGR_TYPE_AVG = 1,
    AGGR_TYPE_SUM = 2,
    AGGR_TYPE_MIN = 3,
    AGGR_TYPE_MAX = 4,
    AGGR_TYPE_COUNT = 5,
    AGGR_TYPE_AVG_COLLECT = 6, // Z-Sharding
    AGGR_TYPE_GROUP_CONCAT = 7,
    AGGR_TYPE_STDDEV = 8,
    AGGR_TYPE_STDDEV_POP = 9,
    AGGR_TYPE_STDDEV_SAMP = 10,
    AGGR_TYPE_LAG = 11,
    AGGR_TYPE_ARRAY_AGG = 12,
    AGGR_TYPE_NTILE = 13,
    // ///////////////////aggr_type count//////////////
    AGGR_TYPE_MEDIAN,
    AGGR_TYPE_CUME_DIST,
    AGGR_TYPE_VARIANCE,
    AGGR_TYPE_VAR_POP,
    AGGR_TYPE_VAR_SAMP,
    AGGR_TYPE_COVAR_POP,
    AGGR_TYPE_COVAR_SAMP,
    AGGR_TYPE_CORR,
    AGGR_TYPE_DENSE_RANK,
    AGGR_TYPE_FIRST_VALUE,
    AGGR_TYPE_LAST_VALUE,
    AGGR_TYPE_RANK,
    AGGR_TYPE_APPX_CNTDIS
} sql_aggr_type_t;

#define SQL_MIN_HEX_STR_LEN 2
#define SQL_GROUP_CONCAT_STR_LEN 1024
#define SQL_USERENV_VALUE_DEFAULT_LEN 256
#define SQL_VERSION_VALUE_DEFAULT_LEN 50
#define SQL_ASCII_COUNT 256
#define UTF8_MAX_BYTE 6

typedef enum en_bit_operation {
    BIT_OPER_AND = 1,
    BIT_OPER_OR = 2,
    BIT_OPER_XOR = 3,
} bit_operation_t;

/* **NOTE:**
 * 1. The function item id should be the same order as function name.
 * 2. The function item id is equal to function id.
 */
typedef enum en_function_item_id {
    ID_FUNC_ITEM_ABS = 0,
    ID_FUNC_ITEM_ACOS,
    ID_FUNC_ITEM_ADD_MONTHS,
    ID_FUNC_ITEM_APPX_CNTDIS,
    ID_FUNC_ITEM_ARRAY_AGG,
    ID_FUNC_ITEM_ARRAY_LENGTH,
    ID_FUNC_ITEM_ASCII,
    ID_FUNC_ITEM_ASCIISTR,
    ID_FUNC_ITEM_ASIN,
    ID_FUNC_ITEM_ATAN,
    ID_FUNC_ITEM_ATAN2,
    ID_FUNC_ITEM_AVG,
    ID_FUNC_ITEM_BIN2HEX,
    ID_FUNC_ITEM_BITAND,
    ID_FUNC_ITEM_BITOR,
    ID_FUNC_ITEM_BITXOR,
    ID_FUNC_ITEM_CAST,
    ID_FUNC_ITEM_CEIL,
    ID_FUNC_ITEM_CHAR,
    ID_FUNC_ITEM_CHAR_LENGTH,
    ID_FUNC_ITEM_CHR,
    ID_FUNC_ITEM_COALESCE,
    ID_FUNC_ITEM_CONCAT,
    ID_FUNC_ITEM_CONCAT_WS,
    ID_FUNC_ITEM_CONNECTION_ID,
    ID_FUNC_ITEM_CONVERT,
    ID_FUNC_ITEM_CORR,
    ID_FUNC_ITEM_COS,
    ID_FUNC_ITEM_COUNT,
    ID_FUNC_ITEM_COVAR_POP,
    ID_FUNC_ITEM_COVAR_SAMP,
    ID_FUNC_ITEM_CUME_DIST,
    ID_FUNC_ITEM_CURRENT_TIMESTAMP,
    ID_FUNC_ITEM_DECODE,
    ID_FUNC_ITEM_DENSE_RANK,
    ID_FUNC_ITEM_EMPTY_BLOB,
    ID_FUNC_ITEM_EMPTY_CLOB,
    ID_FUNC_ITEM_EXP,
    ID_FUNC_ITEM_EXTRACT,
    ID_FUNC_ITEM_FIND_IN_SET,
    ID_FUNC_ITEM_FLOOR,
    ID_FUNC_ITEM_FOUND_ROWS,
    ID_FUNC_ITEM_FROM_TZ,
    ID_FUNC_ITEM_FROM_UNIXTIME,
    ID_FUNC_ITEM_GETUTCDATE,
    ID_FUNC_ITEM_GET_LOCK,
    ID_FUNC_ITEM_GET_SHARED_LOCK,
    ID_FUNC_ITEM_GET_XACT_LOCK,
    ID_FUNC_ITEM_GET_XACT_SHARED_LOCK,
    ID_FUNC_ITEM_GREATEST,
    ID_FUNC_ITEM_GROUPING,
    ID_FUNC_ITEM_GROUPING_ID,
    ID_FUNC_ITEM_GROUP_CONCAT,
    ID_FUNC_ITEM_GSCN2DATE,
    ID_FUNC_ITEM_CT_HASH,
    ID_FUNC_ITEM_HASH,
    ID_FUNC_ITEM_HEX,
    ID_FUNC_ITEM_HEX2BIN,
    ID_FUNC_ITEM_HEXTORAW,
    ID_FUNC_ITEM_IF,
    ID_FUNC_ITEM_IFNULL,
    ID_FUNC_ITEM_INET_ATON,
    ID_FUNC_ITEM_INET_NTOA,
    ID_FUNC_ITEM_INSERT,
    ID_FUNC_ITEM_INSTR,
    ID_FUNC_ITEM_INSTRB,
    ID_FUNC_ITEM_ISNUMERIC,
    ID_FUNC_ITEM_JSONB_ARRAY_LENGTH,
    ID_FUNC_ITEM_JSONB_EXISTS,
    ID_FUNC_ITEM_JSONB_MERGEPATCH,
    ID_FUNC_ITEM_JSONB_QUERY,
    ID_FUNC_ITEM_JSONB_SET,
    ID_FUNC_ITEM_JSONB_VALUE,
    ID_FUNC_ITEM_JSON_ARRAY,
    ID_FUNC_ITEM_JSON_ARRAY_LENGTH,
    ID_FUNC_ITEM_JSON_EXISTS,
    ID_FUNC_ITEM_JSON_MERGEPATCH,
    ID_FUNC_ITEM_JSON_OBJECT,
    ID_FUNC_ITEM_JSON_QUERY,
    ID_FUNC_ITEM_JSON_SET,
    ID_FUNC_ITEM_JSON_VALUE,
    ID_FUNC_ITEM_LAST_DAY,
    ID_FUNC_ITEM_LAST_INSERT_ID,
    ID_FUNC_ITEM_LEAST,
    ID_FUNC_ITEM_LEFT,
    ID_FUNC_ITEM_LENGTH,
    ID_FUNC_ITEM_LENGTHB,
    ID_FUNC_ITEM_LISTAGG,
    ID_FUNC_ITEM_LN,
    ID_FUNC_ITEM_LNNVL,
    ID_FUNC_ITEM_LOCALTIMESTAMP,
    ID_FUNC_ITEM_LOCATE,
    ID_FUNC_ITEM_LOG,
    ID_FUNC_ITEM_LOWER,
    ID_FUNC_ITEM_LPAD,
    ID_FUNC_ITEM_LTRIM,
    ID_FUNC_ITEM_MAX,
    ID_FUNC_ITEM_MD5,
    ID_FUNC_ITEM_MEDIAN,
    ID_FUNC_ITEM_MIN,
    ID_FUNC_ITEM_MOD,
    ID_FUNC_ITEM_MONTHS_BETWEEN,
    ID_FUNC_ITEM_NEXT_DAY,
    ID_FUNC_ITEM_NOW,
    ID_FUNC_ITEM_NULLIF,
    ID_FUNC_ITEM_NUMTODSINTERVAL,
    ID_FUNC_ITEM_NUMTOYMINTERVAL,
    ID_FUNC_ITEM_NVL,
    ID_FUNC_ITEM_NVL2,
    ID_FUNC_ITEM_OBJECT_ID,
    ID_FUNC_ITEM_PAGE_MASTERID,
    ID_FUNC_ITEM_PI,
    ID_FUNC_ITEM_POWER,
    ID_FUNC_ITEM_RADIANS,
    ID_FUNC_ITEM_RAND,
    ID_FUNC_ITEM_RANK,
    ID_FUNC_ITEM_RAWTOHEX,
    ID_FUNC_ITEM_REGEXP_COUNT,
    ID_FUNC_ITEM_REGEXP_INSTR,
    ID_FUNC_ITEM_REGEXP_REPLACE,
    ID_FUNC_ITEM_REGEXP_SUBSTR,
    ID_FUNC_ITEM_RELEASE_LOCK,
    ID_FUNC_ITEM_RELEASE_SHARED_LOCK,
    ID_FUNC_ITEM_PEPEAT,
    ID_FUNC_ITEM_REPLACE,
    ID_FUNC_ITEM_REVERSE,
    ID_FUNC_ITEM_RIGHT,
    ID_FUNC_ITEM_ROUND,
    ID_FUNC_ITEM_RPAD,
    ID_FUNC_ITEM_RTRIM,
    ID_FUNC_ITEM_SCN2DATE,
    ID_FUNC_ITEM_SERIAL_LASTVAL,
    ID_FUNC_ITEM_SHA,
    ID_FUNC_ITEM_SHA1,
    ID_FUNC_ITEM_SIGN,
    ID_FUNC_ITEM_SIN,
    ID_FUNC_ITEM_SOUNDEX,
    ID_FUNC_ITEM_SPACE,
    ID_FUNC_ITEM_SQRT,
    ID_FUNC_ITEM_STDDEV,
    ID_FUNC_ITEM_STDDEV_POP,
    ID_FUNC_ITEM_STDDEV_SAMP,
    ID_FUNC_ITEM_SUBSTR,
    ID_FUNC_ITEM_SUBSTRB,
    ID_FUNC_ITEM_SUBSTRING,
    ID_FUNC_ITEM_SUBSTRING_INDEX,
    ID_FUNC_ITEM_SUM,
    ID_FUNC_ITEM_SYSTIMESTAMP,
    ID_FUNC_ITEM_SYS_CONNECT_BY_PATH,
    ID_FUNC_ITEM_SYS_CONTEXT,
    ID_FUNC_ITEM_SYS_EXTRACT_UTC,
    ID_FUNC_ITEM_SYS_GUID,
    ID_FUNC_ITEM_TAN,
    ID_FUNC_ITEM_TANH,
    ID_FUNC_ITEM_TIMESTAMPADD,
    ID_FUNC_ITEM_TIMESTAMPDIFF,
    ID_FUNC_ITEM_TO_BLOB,
    ID_FUNC_ITEM_TO_CHAR,
    ID_FUNC_ITEM_TO_CLOB,
    ID_FUNC_ITEM_TO_DATE,
    ID_FUNC_ITEM_TO_DSINTERVAL,
    ID_FUNC_ITEM_TO_MULTI_BYTE,
    ID_FUNC_ITEM_TO_NCHAR,
    ID_FUNC_ITEM_TO_NUMBER,
    ID_FUNC_ITEM_TO_SINGLE_BYTE,
    ID_FUNC_ITEM_TO_TIMESTAMP,
    ID_FUNC_ITEM_TO_YMINTERVAL,
    ID_FUNC_ITEM_TRANSLATE,
    ID_FUNC_ITEM_TRIM,
    ID_FUNC_ITEM_TRUNC,
    ID_FUNC_ITEM_TRY_GET_LOCK,
    ID_FUNC_ITEM_TRY_GET_SHARED_LOCK,
    ID_FUNC_ITEM_TRY_GET_XACT_LOCK,
    ID_FUNC_ITEM_TRY_GET_XACT_SHARED_LOCK,
    ID_FUNC_ITEM_TYPE_ID2NAME,
    ID_FUNC_ITEM_UNHEX,
    ID_FUNC_ITEM_UNIX_TIMESTAMP,
    ID_FUNC_ITEM_UPDATING,
    ID_FUNC_ITEM_UPPER,
    ID_FUNC_ITEM_USERENV,
    ID_FUNC_ITEM_UTCDATE,
    ID_FUNC_ITEM_UTCTIMESTAMP,
    ID_FUNC_ITEM_UUID,
    ID_FUNC_ITEM_VALUES,
    ID_FUNC_ITEM_VARIANCE,
    ID_FUNC_ITEM_VAR_POP,
    ID_FUNC_ITEM_VAR_SAMP,
    ID_FUNC_ITEM_VERSION,
    ID_FUNC_ITEM_VSIZE,
} function_item_id_t;

#define IS_BUILDIN_FUNCTION(node, id) \
    ((node)->value.v_func.pack_id == CT_INVALID_ID32 && (node)->value.v_func.func_id == (id))

typedef status_t (*sql_invoke_func_t)(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
typedef status_t (*sql_verify_func_t)(sql_verifier_t *verifier, expr_node_t *func);
typedef enum en_func_value_cnt {
    FO_USUAL = 1,
    FO_COVAR = 2,
    FO_VAL_MAX
} func_value_cnt_t;
typedef enum en_func_option {
    /* no optimal methods */
    FO_NONE = 0,
    /* Using the normal method to infer its optimal inferring method,
     * see sql_infer_func_optmz_mode */
    FO_NORMAL = 1,
    // as procedure
    FO_PROC = 2,
    /* The function has its special optimal inferring method.
     * Generally, its inferring is in its verification function */
    FO_SPECIAL = 3,
} func_option_t;

typedef struct st_sql_func {
    text_t name;
    sql_invoke_func_t invoke;
    sql_verify_func_t verify;
    sql_aggr_type_t aggr_type;
    uint32 options;         /* need to const function reduce */
    uint32 builtin_func_id; /* only use for built-in function, other is set to CT_INVALID_ID32 */
    uint32 value_cnt;
    bool32 indexable; /* true: the function can be used as index column */
} sql_func_t;

typedef struct st_fmt_dot_pos {
    bool32 fill_mode;
    uint32 start_pos;
    uint32 dot_pos;
    uint32 fmt_dot_pos;
    uint32 last_zero_pos;
    uint32 int_len;
} fmt_dot_pos_t;
#define CT_CONST_FOUR (uint32)(4)
#define SQL_SET_NULL_VAR(var) VAR_SET_NULL((var), CT_DATATYPE_OF_NULL)
#define SQL_SET_COLUMN_VAR(var)       \
    do {                              \
        (var)->type = CT_TYPE_COLUMN; \
        (var)->is_null = CT_FALSE;    \
    } while (0)

#define SQL_CHECK_COLUMN_VAR(arg, res)         \
    do {                                       \
        if (((arg)->type) == CT_TYPE_COLUMN) { \
            SQL_SET_COLUMN_VAR(res);           \
            return CT_SUCCESS;                 \
        }                                      \
    } while (0)

#define SQL_CHECK_COND_PANDING(pending, res) \
    do {                                     \
        if ((pending)) {                     \
            SQL_SET_COLUMN_VAR(res);         \
            return CT_SUCCESS;               \
        }                                    \
    } while (0)

#define SQL_EXEC_FUNC_ARG(arg_expr, arg_var, res_var, stmt)                                                           \
    do {                                                                                                              \
        if (sql_exec_expr((stmt), (arg_expr), (arg_var)) != CT_SUCCESS) {                                             \
            return CT_ERROR;                                                                                          \
        }                                                                                                             \
        SQL_CHECK_COLUMN_VAR((arg_var), (res_var));                                                                   \
        if (CT_IS_LOB_TYPE((arg_var)->type) && !(arg_var)->is_null) {                                                 \
            CT_RETURN_IFERR(sql_get_lob_value((stmt), (arg_var)));                                                    \
        }                                                                                                             \
    } while (0)

#define SQL_EXEC_FUNC_ARG_EX(arg_expr, arg_var, res_var)     \
    do {                                                     \
        SQL_EXEC_FUNC_ARG((arg_expr), (arg_var), (res_var), stmt); \
        if ((arg_var)->is_null) {                            \
            SQL_SET_NULL_VAR(res_var);                       \
            return CT_SUCCESS;                               \
        }                                                    \
    } while (0)

#define SQL_EXEC_FUNC_ARG_SUBSTR(arg_expr, arg_var, res_var, stmt)                                                    \
    do {                                                                                                              \
        if (sql_exec_expr((stmt), (arg_expr), (arg_var)) != CT_SUCCESS) {                                             \
            return CT_ERROR;                                                                                          \
        }                                                                                                             \
        SQL_CHECK_COLUMN_VAR((arg_var), (res_var));                                                                   \
        if (CT_IS_LOB_TYPE((arg_var)->type) && !(arg_var)->is_null) {                                                 \
            if (((lob_locator_t *)(arg_var)->v_lob.knl_lob.bytes)->head.size > g_instance->attr.lob_max_exec_size) {  \
                ((lob_locator_t *)(arg_var)->v_lob.knl_lob.bytes)->head.size = CT_LOB_LOCATOR_BUF_SIZE;               \
            }                                                                                                         \
            CT_RETURN_IFERR(sql_get_lob_value((stmt), (arg_var)));                                                    \
        }                                                                                                             \
    } while (0)

#define SQL_EXEC_FUNC_ARG_EX_SUBSTR(arg_expr, arg_var, res_var)                       \
    do {                                                                              \
        SQL_EXEC_FUNC_ARG_SUBSTR((arg_expr), (arg_var), (res_var), stmt);             \
        if ((arg_var)->is_null) {                                                     \
            SQL_SET_NULL_VAR(res_var);                                                \
            return CT_SUCCESS;                                                        \
        }                                                                             \
    } while (0)

#define SQL_EXEC_FUNC_ARG_EX2(arg_expr, arg_var, res_var)          \
    do {                                                           \
        SQL_EXEC_FUNC_ARG((arg_expr), (arg_var), (res_var), stmt); \
        if ((arg_var)->is_null) {                                  \
            SQL_SET_NULL_VAR(res_var);                             \
        }                                                          \
    } while (0)

#define SQL_EXEC_LENGTH_FUNC_ARG(arg_expr, arg_var, res_var, stmt)            \
    do {                                                                      \
        if (sql_exec_expr((stmt), (arg_expr), (arg_var)) != CT_SUCCESS) {     \
            return CT_ERROR;                                                  \
        }                                                                     \
        SQL_CHECK_COLUMN_VAR((arg_var), (res_var));                           \
        if ((arg_var)->is_null) {                                             \
            SQL_SET_NULL_VAR(res_var);                                        \
            return CT_SUCCESS;                                                \
        }                                                                     \
    } while (0)

#define CTSQL_INIT_TYPEMOD(typemod)         \
    do {                                  \
        (typemod).size = CT_INVALID_ID16; \
        (typemod).mode = CT_INVALID_ID16; \
        (typemod).is_array = 0;           \
        (typemod).reserve[0] = 0;         \
        (typemod).reserve[1] = 0;         \
        (typemod).reserve[2] = 0;         \
    } while (0)

/**
 * Used to static check the datatype for TO_XXXX functions, such as *to_date*,
 * *to_timestamp*, *to_yminterval* and *to_dsinterval*. These functions require the
 * source argument must be a STRING type, as well as binding argument with UNKNOWN type.

 */
static inline bool32 sql_match_string_type(ct_type_t src_type)
{
    return (bool32)(CT_IS_STRING_TYPE(src_type) || CT_IS_UNKNOWN_TYPE(src_type));
}

static inline bool32 sql_match_numeric_type(ct_type_t src_type)
{
    return (bool32)(CT_IS_WEAK_NUMERIC_TYPE(src_type) || CT_IS_UNKNOWN_TYPE(src_type));
}

static inline bool32 sql_match_num_and_str_type(ct_type_t src_type)
{
    return (bool32)(CT_IS_WEAK_NUMERIC_TYPE(src_type) || CT_IS_UNKNOWN_TYPE(src_type));
}

static inline bool32 sql_match_datetime_type(ct_type_t src_type)
{
    return (bool32)(CT_IS_WEAK_DATETIME_TYPE(src_type) || CT_IS_UNKNOWN_TYPE(src_type));
}

static inline bool32 sql_match_timestamp(ct_type_t src_type)
{
    return (bool32)(CT_IS_TIMESTAMP(src_type) || CT_IS_TIMESTAMP_TZ_TYPE(src_type) ||
        CT_IS_TIMESTAMP_LTZ_TYPE(src_type) || CT_IS_UNKNOWN_TYPE(src_type));
}


static inline bool32 sql_match_num_and_datetime_type(ct_type_t src_type)
{
    return (bool32)(sql_match_numeric_type(src_type) || sql_match_datetime_type(src_type));
}

static inline bool32 sql_match_interval_type(ct_type_t src_type)
{
    return (bool32)(src_type == CT_TYPE_INTERVAL_DS || src_type == CT_TYPE_INTERVAL_YM);
}

static inline bool32 sql_match_bool_type(ct_type_t src_type)
{
    return (bool32)(CT_IS_WEAK_BOOLEAN_TYPE(src_type) || CT_IS_UNKNOWN_TYPE(src_type));
}

static inline status_t sql_var_as_string(sql_stmt_t *stmt, variant_t *var)
{
    char *buf = NULL;
    text_buf_t buffer;

    uint32 size = cm_get_datatype_strlen(var->type, CT_STRING_BUFFER_SIZE) + 1;
    CT_RETURN_IFERR(sql_push(stmt, size, (void **)&buf));
    CM_INIT_TEXTBUF(&buffer, size, buf);
    CT_RETURN_IFERR(var_as_string(SESSION_NLS(stmt), var, &buffer));
    return CT_SUCCESS;
}

/* Set error for function: string argument is required */
#define CT_SRC_ERROR_REQUIRE_STRING(loc, got_type)        \
    CT_SRC_THROW_ERROR_EX((loc), ERR_INVALID_FUNC_PARAMS, \
        "illegal function argument: string argument expected - got %s", get_datatype_name_str((int32)(got_type)));

/* Set error for function: INTEGER argument is required */
#define CT_SRC_ERROR_REQUIRE_INTEGER(loc, got_type)       \
    CT_SRC_THROW_ERROR_EX((loc), ERR_INVALID_FUNC_PARAMS, \
        "illegal function argument: integer argument expected - got %s", get_datatype_name_str((int32)(got_type)));

/* Set error for function: NUMERIC argument is required */
#define CT_SRC_ERROR_REQUIRE_NUMERIC(loc, got_type)       \
    CT_SRC_THROW_ERROR_EX((loc), ERR_INVALID_FUNC_PARAMS, \
        "illegal function argument: NUMERIC argument expected - got %s", get_datatype_name_str((int32)(got_type)));

/* Set error for function: NUMERIC or string argument is required */
#define CT_SRC_ERROR_REQUIRE_NUM_OR_STR(loc, got_type)                             \
    CT_SRC_THROW_ERROR_EX((loc), ERR_INVALID_FUNC_PARAMS,                          \
        "illegal function argument: NUMERIC or string argument expected - got %s", \
        get_datatype_name_str((int32)(got_type)));

/* Set error for function: NUMERIC or DATETIME argument is required */
#define CT_SRC_ERROR_REQUIRE_NUM_OR_DATETIME(loc, got_type)                          \
    CT_SRC_THROW_ERROR_EX((loc), ERR_INVALID_FUNC_PARAMS,                            \
        "illegal function argument: NUMERIC or DATETIME argument expected - got %s", \
        get_datatype_name_str((int32)(got_type)));

/* Set error for function: DATETIME argument is required */
#define CT_SRC_ERROR_REQUIRE_DATETIME(loc, got_type)      \
    CT_SRC_THROW_ERROR_EX((loc), ERR_INVALID_FUNC_PARAMS, \
        "illegal function argument: DATETIME argument expected - got %s", get_datatype_name_str((int32)(got_type)));

#define CT_BLANK_CHAR_SET " \t"

typedef text_t *(*sql_func_item_t)(void *set, uint32 id);
extern sql_func_t g_func_tab[];
extern sql_func_t *sql_get_pack_func(var_func_t *v);

static inline sql_func_t *sql_get_func(var_func_t *v)
{
    if (v->pack_id == CT_INVALID_ID32) {
        return &g_func_tab[v->func_id];
    }

    return sql_get_pack_func(v);
}

status_t sql_invoke_func(sql_stmt_t *stmt, expr_node_t *node, variant_t *result);
status_t sql_verify_func_node(sql_verifier_t *verf, expr_node_t *func, uint16 min_args, uint16 max_args,
    uint32 type_arg_no);
status_t sql_exec_expr_as_string(sql_stmt_t *stmt, expr_tree_t *arg, variant_t *var, text_t **text);
status_t sql_get_utf8_clob_char_len(sql_stmt_t *stmt, variant_t *var, uint32 *len);
uint32 sql_func_binsearch(const text_t *name, sql_func_item_t get_item, void *set, uint32 count);
uint32 sql_get_func_id(const text_t *func_name);
uint32 sql_get_lob_var_length(variant_t *var);
bool32 sql_verify_lob_func_args(ct_type_t datatype);
status_t sql_func_page2masterid(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_page2masterid(sql_verifier_t *verifier, expr_node_t *func);
#ifdef __cplusplus
}
#endif

#endif
