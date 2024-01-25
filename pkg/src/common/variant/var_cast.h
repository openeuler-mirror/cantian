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
 * var_cast.h
 *
 *
 * IDENTIFICATION
 * src/common/variant/var_cast.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __VAR_CAST_H__
#define __VAR_CAST_H__

#include "var_defs.h"

typedef struct st_type_desc {
    int32  id;
    text_t name;

    /** The weight of a datatype represents the priority of the datatype. It can
    * be used to decide the priority level of two datatypes that are in the same
    * datatypes group. The datatypes group of a datatype can be decided by
    * the Marco, such as CT_IS_STRING_TYPE, CT_IS_NUMERIC_TYPE, .... (see datatype_group)
    */
    int32 weight;
} type_desc_t;

#define CT_TYPE_MASK_ALL   ((uint64)0xFFFFFFFFFFFFFFFF)
#define CT_TYPE_MASK_NONE  ((uint64)0)

#define CT_TYPE_MASK_LOB (CT_TYPE_MASK(CT_TYPE_BLOB) | CT_TYPE_MASK(CT_TYPE_CLOB) | CT_TYPE_MASK(CT_TYPE_IMAGE))
#define CT_TYPE_MASK_CLOB_BLOB (CT_TYPE_MASK(CT_TYPE_BLOB) | CT_TYPE_MASK(CT_TYPE_CLOB))
#define CT_TYPE_MASK_EXC_CLOB_BLOB ((CT_TYPE_MASK_ALL) ^ (CT_TYPE_MASK_CLOB_BLOB))

#define CT_TYPE_MASK_STRING                                        \
    (CT_TYPE_MASK(CT_TYPE_CHAR) | CT_TYPE_MASK(CT_TYPE_VARCHAR) |  \
        CT_TYPE_MASK(CT_TYPE_STRING))

#define CT_TYPE_MASK_DATETIME                                        \
    (CT_TYPE_MASK(CT_TYPE_TIMESTAMP) | CT_TYPE_MASK(CT_TYPE_DATE) |  \
     CT_TYPE_MASK(CT_TYPE_TIMESTAMP_TZ_FAKE) | CT_TYPE_MASK(CT_TYPE_TIMESTAMP_TZ) | CT_TYPE_MASK(CT_TYPE_TIMESTAMP_LTZ))

#define CT_TYPE_MASK_UNSIGNED_INTEGER                               \
    (CT_TYPE_MASK(CT_TYPE_UINT32) | CT_TYPE_MASK(CT_TYPE_UINT64) |  \
        CT_TYPE_MASK(CT_TYPE_USMALLINT) | CT_TYPE_MASK(CT_TYPE_UTINYINT))

#define CT_TYPE_MASK_SIGNED_INTEGER                                  \
    (CT_TYPE_MASK(CT_TYPE_INTEGER) | CT_TYPE_MASK(CT_TYPE_BIGINT) |  \
        CT_TYPE_MASK(CT_TYPE_SMALLINT) | CT_TYPE_MASK(CT_TYPE_TINYINT))

#define CT_TYPE_MASK_INTEGER \
    (CT_TYPE_MASK_UNSIGNED_INTEGER | CT_TYPE_MASK_SIGNED_INTEGER)

#define CT_TYPE_MASK_NUMERIC                                                            \
    (CT_TYPE_MASK_INTEGER | CT_TYPE_MASK(CT_TYPE_REAL) | CT_TYPE_MASK(CT_TYPE_NUMBER) | \
        CT_TYPE_MASK(CT_TYPE_DECIMAL) | CT_TYPE_MASK(CT_TYPE_NUMBER2) | CT_TYPE_MASK(CT_TYPE_NUMBER3))

#define CT_TYPE_MASK_DECIMAL \
    (CT_TYPE_MASK(CT_TYPE_NUMBER) | CT_TYPE_MASK(CT_TYPE_DECIMAL) | CT_TYPE_MASK(CT_TYPE_NUMBER3))

#define CT_TYPE_MASK_BINARY \
    (CT_TYPE_MASK(CT_TYPE_BINARY) | CT_TYPE_MASK(CT_TYPE_VARBINARY))

#define CT_TYPE_MASK_ARRAY \
    (CT_TYPE_MASK(CT_TYPE_ARRAY) | CT_TYPE_MASK_STRING)

#define CT_TYPE_MASK_RAW (CT_TYPE_MASK(CT_TYPE_RAW))

    /** mask of variant length datatype */
#define CT_TYPE_MASK_VARLEN \
    (CT_TYPE_MASK_BINARY | CT_TYPE_MASK_STRING | CT_TYPE_MASK_RAW)

#define CT_TYPE_MASK_BINSTR \
    (CT_TYPE_MASK_BINARY | CT_TYPE_MASK_STRING)

    /** mask of text lob (CLOB/IMAGE) */
#define CT_TYPE_MASK_TEXTUAL_LOB (CT_TYPE_CLOB | CT_TYPE_IMAGE)

    /** mask of data types that require to consume extra buffer when conversion.
    *  see function var_convert to decide which data types need buffer */
#define CT_TYPE_MASK_BUFF_CONSUMING (CT_TYPE_MASK_VARLEN | CT_TYPE_MASK_LOB)

#define CT_TYPE_MASK_COLLECTION  CT_TYPE_MASK(CT_TYPE_COLLECTION)

    /**
    * @addtogroup datatype_group
    * @brief These Macros define the datatype groups of datatypes. The datatypes in
    *       same group may have priority. These priority values can be used to determine
    *       the result datatype when two datatypes are combined, e.g. performing
    *       UNION [ALL], INTERSECT and MINUS operators, inferring the datatype of
    *       CASE..WHEN, NVL and DECODE SQL function and expression.
    * @{ */
#define CT_IS_LOB_TYPE(type)                                                                                           \
    ((type) > CT_TYPE_BASE && (type) < CT_TYPE__DO_NOT_USE && (CT_TYPE_MASK(type) & CT_TYPE_MASK_LOB) > 0)
#define CT_IS_TEXTUAL_LOB(type)                                                                                        \
    ((type) > CT_TYPE_BASE && (type) < CT_TYPE__DO_NOT_USE && (CT_TYPE_MASK(type) & CT_TYPE_MASK_TEXTUAL_LOB) > 0)
#define CT_IS_SIGNED_INTEGER_TYPE(type)                                                                                \
    ((type) > CT_TYPE_BASE && (type) < CT_TYPE__DO_NOT_USE && (CT_TYPE_MASK(type) & CT_TYPE_MASK_SIGNED_INTEGER) > 0)
#define CT_IS_UNSIGNED_INTEGER_TYPE(type)                                                                              \
    ((type) > CT_TYPE_BASE && (type) < CT_TYPE__DO_NOT_USE && (CT_TYPE_MASK(type) & CT_TYPE_MASK_UNSIGNED_INTEGER) > 0)
#define CT_IS_INTEGER_TYPE(type)                                                                                       \
    ((type) > CT_TYPE_BASE && (type) < CT_TYPE__DO_NOT_USE && (CT_TYPE_MASK(type) & CT_TYPE_MASK_INTEGER) > 0)
#define CT_IS_NUMERIC_TYPE(type)                                                                                       \
    ((type) > CT_TYPE_BASE && (type) < CT_TYPE__DO_NOT_USE && (CT_TYPE_MASK(type) & CT_TYPE_MASK_NUMERIC) > 0)
#define CT_IS_DATETIME_TYPE(type)                                                                                      \
    ((type) > CT_TYPE_BASE && (type) < CT_TYPE__DO_NOT_USE && (CT_TYPE_MASK(type) & CT_TYPE_MASK_DATETIME) > 0)
#define CT_IS_STRING_TYPE(type)                                                                                        \
    ((type) > CT_TYPE_BASE && (type) < CT_TYPE__DO_NOT_USE && (CT_TYPE_MASK(type) & CT_TYPE_MASK_STRING) > 0)
#define CT_IS_BINARY_TYPE(type)                                                                                        \
    ((type) > CT_TYPE_BASE && (type) < CT_TYPE__DO_NOT_USE && (CT_TYPE_MASK(type) & CT_TYPE_MASK_BINARY) > 0)
#define CT_IS_BOOLEAN_TYPE(type)          ((type) == CT_TYPE_BOOLEAN)
#define CT_IS_UNKNOWN_TYPE(type)          ((type) == CT_TYPE_UNKNOWN)
#define CT_IS_DSITVL_TYPE(type)           ((type) == CT_TYPE_INTERVAL_DS)
#define CT_IS_YMITVL_TYPE(type)           ((type) == CT_TYPE_INTERVAL_YM)
#define CT_IS_DECIMAL_TYPE(type)                                                                                       \
    ((type) > CT_TYPE_BASE && (type) < CT_TYPE__DO_NOT_USE && (CT_TYPE_MASK(type) & CT_TYPE_MASK_DECIMAL) > 0)
#define CT_IS_DOUBLE_TYPE(type)           ((type) == CT_TYPE_REAL)
#define CT_IS_CLOB_TYPE(type)             ((type) == CT_TYPE_CLOB)
#define CT_IS_BLOB_TYPE(type)             ((type) == CT_TYPE_BLOB)
#define CT_IS_RAW_TYPE(type)              ((type) == CT_TYPE_RAW)
#define CT_IS_IMAGE_TYPE(type)            ((type) == CT_TYPE_IMAGE)
#define CT_IS_TIMESTAMP(type)             ((type) == CT_TYPE_TIMESTAMP||(type) == CT_TYPE_TIMESTAMP_TZ_FAKE)
#define CT_IS_TIMESTAMP_TZ_TYPE(type)     ((type) == CT_TYPE_TIMESTAMP_TZ)
#define CT_IS_TIMESTAMP_LTZ_TYPE(type)    ((type) == CT_TYPE_TIMESTAMP_LTZ)
#define CT_IS_NUMBER_TYPE(type) \
    ((type) == CT_TYPE_NUMBER || (type) == CT_TYPE_DECIMAL || (type) == CT_TYPE_NUMBER2 || (type) == CT_TYPE_NUMBER3)
#define CT_IS_NUMBER2_TYPE(type) ((type) == CT_TYPE_NUMBER2)
    /* end of datatype_group */
    /* to decide whether the datatype is variant length */
#define CT_IS_VARLEN_TYPE(type)                                                                                        \
    ((type) > CT_TYPE_BASE && (type) < CT_TYPE__DO_NOT_USE && (CT_TYPE_MASK(type) & CT_TYPE_MASK_VARLEN) > 0)

#define CT_IS_BINSTR_TYPE(type)                                                                                        \
    ((type) > CT_TYPE_BASE && (type) < CT_TYPE__DO_NOT_USE && (CT_TYPE_MASK(type) & CT_TYPE_MASK_BINSTR) > 0)

#define CT_IS_ARRAY_TYPE(type)                                                                                         \
    ((type) > CT_TYPE_BASE && (type) < CT_TYPE__DO_NOT_USE && (CT_TYPE_MASK(type) & CT_TYPE_MASK_ARRAY) > 0)

    /* to decide whether the datatype is buffer consuming when conversion */
#define CT_IS_BUFF_CONSUMING_TYPE(type) ((type) > CT_TYPE_BASE && (type) < CT_TYPE__DO_NOT_USE &&  \
        (CT_TYPE_MASK(type) & CT_TYPE_MASK_BUFF_CONSUMING) > 0)

#define CT_IS_WEAK_INTEGER_TYPE(type)  (CT_IS_INTEGER_TYPE(type) || CT_IS_STRING_TYPE(type))
#define CT_IS_WEAK_NUMERIC_TYPE(type)  (CT_IS_NUMERIC_TYPE(type) || CT_IS_STRING_TYPE(type))
#define CT_IS_WEAK_BOOLEAN_TYPE(type)  (CT_IS_BOOLEAN_TYPE(type) || CT_IS_STRING_TYPE(type))
#define CT_IS_WEAK_DATETIME_TYPE(type) (CT_IS_DATETIME_TYPE(type) || CT_IS_STRING_TYPE(type))

    /* To decide whether two datatypes are in same group */
#define CT_IS_STRING_TYPE2(type1, type2)   (CT_IS_STRING_TYPE(type1) && CT_IS_STRING_TYPE(type2))
#define CT_IS_NUMERIC_TYPE2(type1, type2)  (CT_IS_NUMERIC_TYPE(type1) && CT_IS_NUMERIC_TYPE(type2))
#define CT_IS_BINARY_TYPE2(type1, type2)   (CT_IS_BINARY_TYPE(type1) && CT_IS_BINARY_TYPE(type2))
#define CT_IS_BOOLEAN_TYPE2(type1, type2)  (CT_IS_BOOLEAN_TYPE(type1) && CT_IS_BOOLEAN_TYPE(type2))
#define CT_IS_DATETIME_TYPE2(type1, type2) (CT_IS_DATETIME_TYPE(type1) && CT_IS_DATETIME_TYPE(type2))
#define CT_IS_DSITVL_TYPE2(type1, type2)   (CT_IS_DSITVL_TYPE(type1) && CT_IS_DSITVL_TYPE(type2))
#define CT_IS_YMITVL_TYPE2(type1, type2)   (CT_IS_YMITVL_TYPE(type1) && CT_IS_YMITVL_TYPE(type2))
#define CT_IS_CLOB_TYPE2(type1, type2)     (CT_IS_CLOB_TYPE(type1) && CT_IS_CLOB_TYPE(type2))
#define CT_IS_BLOB_TYPE2(type1, type2)     (CT_IS_BLOB_TYPE(type1) && CT_IS_BLOB_TYPE(type2))
#define CT_IS_RAW_TYPE2(type1, type2)      (CT_IS_RAW_TYPE(type1) && CT_IS_RAW_TYPE(type2))
#define CT_IS_IMAGE_TYPE2(type1, type2)    (CT_IS_IMAGE_TYPE(type1) && CT_IS_IMAGE_TYPE(type2))
#define CT_IS_BINSTR_TYPE2(type1, type2)   (CT_IS_BINSTR_TYPE(type1) && CT_IS_BINSTR_TYPE(type2))

const text_t  *get_datatype_name(int32 type_input);
int32          get_datatype_weight(int32 type_input);
ct_type_t      get_datatype_id(const char *type_str);
const char  *get_lob_type_name(int32 type);

static inline const char *get_datatype_name_str(int32 type)
{
    return get_datatype_name(type)->str;
}

bool32 var_datatype_matched(ct_type_t dest_type, ct_type_t src_type);

#define CT_SET_ERROR_MISMATCH(dest_type, src_type) \
    CT_THROW_ERROR(ERR_TYPE_MISMATCH,              \
        get_datatype_name_str((int32)(dest_type)),  \
        get_datatype_name_str((int32)(src_type)))

#define CT_SRC_ERROR_MISMATCH(loc, dest_type, src_type) \
    do {                                                \
        if (g_tls_plc_error.plc_flag) {                                \
            cm_set_error_loc((loc));                        \
            CT_SET_ERROR_MISMATCH((dest_type), (src_type)); \
        } else {                                            \
            CT_SET_ERROR_MISMATCH((dest_type), (src_type)); \
            cm_set_error_loc((loc));                        \
        }                                                   \
    } while (0)

#define CT_SET_ERROR_MISMATCH_EX(src_type) \
    CT_THROW_ERROR(ERR_UNSUPPORT_DATATYPE, \
        get_datatype_name_str((int32)(src_type)))

#define CT_CHECK_ERROR_MISMATCH(dest_type, src_type)                \
    do {                                                            \
        if (!var_datatype_matched((dest_type), (src_type))) {           \
            CT_SET_ERROR_MISMATCH((dest_type), (src_type));         \
            return CT_ERROR;                                        \
        }                                                           \
    } while (0)


status_t var_to_round_bigint(const variant_t *var, round_mode_t rnd_mode, int64 *i64, int *overflow);
status_t var_to_round_ubigint(const variant_t *uvar, round_mode_t rnd_mode, uint64 *ui64, int *uoverflow);
status_t var_to_round_uint32(const variant_t *var, round_mode_t rnd_mode, uint32 *u32);
status_t var_to_round_int32(const variant_t *var, round_mode_t rnd_mode, int32 *i32);

static inline status_t var_as_bigint(variant_t *var)
{
    int64 i64;
    CT_RETURN_IFERR(var_to_round_bigint(var, ROUND_HALF_UP, &i64, NULL));
    var->v_bigint = i64;
    var->type = CT_TYPE_BIGINT;
    return CT_SUCCESS;
}

static inline status_t var_as_ubigint(variant_t *var)
{
    uint64 ui64;
    CT_RETURN_IFERR(var_to_round_ubigint(var, ROUND_HALF_UP, &ui64, NULL));
    var->v_bigint = ui64;
    var->type = CT_TYPE_UINT64;
    return CT_SUCCESS;
}

static inline status_t var_as_floor_bigint(variant_t *var)
{
    int64 i64;
    CT_RETURN_IFERR(var_to_round_bigint(var, ROUND_TRUNC, &i64, NULL));
    var->v_bigint = i64;
    var->type = CT_TYPE_BIGINT;
    return CT_SUCCESS;
}

// In some case, need to know overflow type
static inline status_t var_as_bigint_ex(variant_t *var, int *overflow)
{
    int64 i64;
    CT_RETURN_IFERR(var_to_round_bigint(var, ROUND_HALF_UP, &i64, overflow));
    var->v_bigint = i64;
    var->type = CT_TYPE_BIGINT;
    return CT_SUCCESS;
}

// In some case, need to know overflow type
static inline status_t var_as_floor_bigint_ex(variant_t *var, int *overflow)
{
    int64 i64;
    CT_RETURN_IFERR(var_to_round_bigint(var, ROUND_TRUNC, &i64, overflow));
    var->v_bigint = i64;
    var->type = CT_TYPE_BIGINT;
    return CT_SUCCESS;
}

static inline status_t var_as_integer(variant_t *var)
{
    int32 i32;
    CT_RETURN_IFERR(var_to_round_int32(var, ROUND_HALF_UP, &i32));
    var->v_int = i32;
    var->type = CT_TYPE_INTEGER;
    return CT_SUCCESS;
}

static inline status_t var_as_uint32(variant_t *var)
{
    uint32 u32;
    CT_RETURN_IFERR(var_to_round_uint32(var, ROUND_HALF_UP, &u32));
    var->v_uint32 = u32;
    var->type = CT_TYPE_UINT32;
    return CT_SUCCESS;
}

static inline status_t var_as_floor_integer(variant_t *var)
{
    int32 i32;
    CT_RETURN_IFERR(var_to_round_int32(var, ROUND_TRUNC, &i32));
    var->v_int = i32;
    var->type = CT_TYPE_INTEGER;
    return CT_SUCCESS;
}

static inline status_t var_as_floor_uint32(variant_t *var)
{
    uint32 u32;
    CT_RETURN_IFERR(var_to_round_uint32(var, ROUND_TRUNC, &u32));
    var->v_uint32 = u32;
    var->type = CT_TYPE_UINT32;
    return CT_SUCCESS;
}

status_t var_as_num(variant_t *var);
status_t var_as_string(const nlsparams_t *nls, variant_t *var, text_buf_t *buf);
status_t var_as_string2(const nlsparams_t *nls, variant_t *var, text_buf_t *buf, typmode_t *typmod);
status_t datetype_as_string(const nlsparams_t *nls, variant_t *var, typmode_t *typmod, text_buf_t *buf);
status_t var_as_decimal(variant_t *var);
status_t var_as_number(variant_t *var);
status_t var_as_number2(variant_t *var);
status_t var_as_real(variant_t *var);
status_t var_as_date(const nlsparams_t *nls, variant_t *var);
status_t var_as_date_mysql(variant_t *var, uint32 datatype);
status_t var_as_timestamp(const nlsparams_t *nls, variant_t *var);
status_t var_as_timestamp_tz(const nlsparams_t *nls, variant_t *var);
status_t var_as_timestamp_ltz(const nlsparams_t *nls, variant_t *var);
status_t var_as_timestamp_flex(variant_t *var);
status_t var_as_bool(variant_t *var);
status_t var_as_binary(const nlsparams_t *nls, variant_t *var, text_buf_t *buf);
status_t var_as_raw(variant_t *var, char *buf, uint32 buf_size);
status_t var_as_yminterval(variant_t *var);
status_t var_as_dsinterval(variant_t *var);
status_t var_convert(const nlsparams_t *nls, variant_t *var, ct_type_t type, text_buf_t *buf);
status_t var_text2num(const text_t *text, ct_type_t type, bool32 negative, variant_t *result);
status_t var_to_unix_timestamp(dec8_t *unix_ts, timestamp_t *ts_ret, int64 time_zone_offset);
status_t var_to_int32_check_overflow(uint32 u32);
#endif

