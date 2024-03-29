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
 * var_typmode.c
 *
 *
 * IDENTIFICATION
 * src/common/variant/var_typmode.c
 *
 * -------------------------------------------------------------------------
 */
#include "var_typmode.h"
#include "cm_interval.h"
#include "cm_decimal.h"
#include "var_inc.h"

status_t cm_typmode2text(const typmode_t *typmod, text_t *txt, uint32 max_len)
{
    switch (typmod->datatype) {
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
            cm_concat_text(txt, max_len, get_datatype_name(typmod->datatype));
            if ((uint32)typmod->size > 0) {
                cm_concat_fmt(txt, CT_MAX_DATATYPE_STRLEN, "(%u %s)",
                    (uint32)typmod->size,
                    typmod->is_char ? "CHAR" : "BYTE");
            }
            return CT_SUCCESS;

        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            cm_concat_fmt(txt, CT_MAX_DATATYPE_STRLEN, "%s(%u)",
                get_datatype_name_str(typmod->datatype),
                (uint32)typmod->size);
            return CT_SUCCESS;

        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_BOOLEAN:
        case CT_TYPE_BIGINT:
        case CT_TYPE_REAL:
        case CT_TYPE_DATE:
        case CT_TYPE_BLOB:
        case CT_TYPE_CLOB:
        case CT_TYPE_IMAGE:
            cm_concat_text(txt, max_len, get_datatype_name(typmod->datatype));
            return CT_SUCCESS;

        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
            cm_concat_fmt(txt, CT_MAX_DATATYPE_STRLEN, "%s(%u)",
                get_datatype_name_str(typmod->datatype),
                (uint32)typmod->precision);
            return CT_SUCCESS;

        case CT_TYPE_TIMESTAMP_TZ:
            cm_concat_fmt(txt, CT_MAX_DATATYPE_STRLEN, "%s(%u) WITH TIME ZONE",
                get_datatype_name_str(CT_TYPE_TIMESTAMP),
                (uint32)typmod->precision);
            return CT_SUCCESS;

        case CT_TYPE_TIMESTAMP_LTZ:
            cm_concat_fmt(txt, CT_MAX_DATATYPE_STRLEN, "%s(%u) WITH LOCAL TIME ZONE",
                get_datatype_name_str(CT_TYPE_TIMESTAMP),
                (uint32)typmod->precision);
            return CT_SUCCESS;

        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_NUMBER2:
            cm_concat_text(txt, max_len, get_datatype_name(typmod->datatype));
            CT_RETSUC_IFTRUE((typmod->precision == CT_UNSPECIFIED_NUM_PREC));
            if (typmod->scale == 0) {
                cm_concat_fmt(txt, CT_MAX_DATATYPE_STRLEN, "(%u)", (uint32)typmod->precision);
            } else {
                cm_concat_fmt(txt, CT_MAX_DATATYPE_STRLEN, "(%u, %d)", (uint32)typmod->precision, (int32)typmod->scale);
            }
            return CT_SUCCESS;

        case CT_TYPE_INTERVAL_DS:
            cm_concat_fmt(txt, CT_MAX_DATATYPE_STRLEN, "INTERVAL DAY(%u) TO SECOND(%u)",
                (uint32)typmod->day_prec, (uint32)typmod->frac_prec);
            return CT_SUCCESS;

        case CT_TYPE_INTERVAL_YM:
            cm_concat_fmt(txt, CT_MAX_DATATYPE_STRLEN, "INTERVAL YEAR(%u) TO MONTH", (uint32)typmod->year_prec);
            return CT_SUCCESS;

        case CT_TYPE_BASE:
            cm_concat_text(txt, max_len, get_datatype_name(typmod->datatype));
            return CT_SUCCESS;

        default:
            CT_THROW_ERROR(ERR_UNSUPPORT_DATATYPE,
                get_datatype_name_str(typmod->datatype));
            return CT_ERROR;
    }
}

void cm_adjust_typmode(typmode_t *typmod)
{
    if (CT_IS_VARLEN_TYPE(typmod->datatype) && typmod->size > CT_MAX_COLUMN_SIZE) {
        typmod->size = CT_MAX_COLUMN_SIZE;
    }
}

static inline void cm_combine_charset_typmode(const typmode_t *tm_char, const typmode_t *tmx, typmode_t *tmr)
{
    if (tm_char->size * CT_CHAR_TO_BYTES_RATIO <= tmx->size) {
        tmr->is_char = CT_FALSE;
        tmr->size = tmx->size;
        return;
    }

    tmr->size = MAX(tm_char->size, tmx->size);
    tmr->is_char = CT_TRUE;
}

static inline void cm_combine_string_typmode(const typmode_t *tm1, const typmode_t *tm2, typmode_t *tmr)
{
    if (tm1->datatype == tm2->datatype) {
        tmr->datatype = tm1->datatype;
    } else {
        tmr->datatype = CT_TYPE_VARCHAR;
    }
    if (tm1->is_char == tm2->is_char) {
        tmr->size = MAX(tm1->size, tm2->size);
        tmr->is_char = tm1->is_char;
        return;
    }

    if (tm1->is_char) {
        cm_combine_charset_typmode(tm1, tm2, tmr);
    } else {
        cm_combine_charset_typmode(tm2, tm1, tmr);
    }
}

static inline void cm_combine_binary_typmode(const typmode_t *tm1, const typmode_t *tm2, typmode_t *tmr)
{
    tmr->datatype = (get_datatype_weight(tm1->datatype) > get_datatype_weight(tm2->datatype)) ? tm1->datatype :
        tm2->datatype;
    tmr->size = MAX(tm1->size, tm2->size);
}

static inline void cm_combine_numeric_typmode(const typmode_t *tm1, const typmode_t *tm2, typmode_t *tmr)
{
    *tmr = (get_datatype_weight(tm1->datatype) > get_datatype_weight(tm2->datatype)) ? *tm1 : *tm2;

    if (CT_IS_NUMBER_TYPE(tmr->datatype)) {
        if (tm1->size != tm2->size || tm1->precision != tm2->precision || tm1->scale != tm2->scale) {
            if (CT_IS_NUMBER2_TYPE(tmr->datatype)) {
                tmr->size = MAX_DEC2_BYTE_SZ;
            } else {
                tmr->size = MAX_DEC_BYTE_SZ;
            }
            tmr->precision = CT_UNSPECIFIED_NUM_PREC;
            tmr->scale = CT_UNSPECIFIED_NUM_SCALE;
        }
    } else if (CT_IS_DOUBLE_TYPE(tmr->datatype)) {
        tmr->size = sizeof(double);
        tmr->precision = CT_UNSPECIFIED_NUM_PREC;
        tmr->scale = CT_UNSPECIFIED_NUM_SCALE;
    }

    if ((tm1->datatype == CT_TYPE_UINT32 && tm2->datatype == CT_TYPE_INTEGER) ||
        (tm1->datatype == CT_TYPE_INTEGER && tm2->datatype == CT_TYPE_UINT32)) {
        tmr->datatype = CT_TYPE_BIGINT;
        tmr->size = CT_BIGINT_SIZE;
    }
}

static inline void cm_combine_datetime_typmode(const typmode_t *tm1, const typmode_t *tm2, typmode_t *tmr)
{
    tmr->datatype = (get_datatype_weight(tm1->datatype) > get_datatype_weight(tm2->datatype)) ? tm1->datatype :
        tm2->datatype;
    tmr->size = 8;
    tmr->precision = MAX(tm1->precision, tm2->precision);
}

/* for typmode of NULL from view, its datatype is CT_TYPE_VARCHAR and size is zero  */
#define CT_IS_NULL_TYPMODE(tm) ((tm).datatype == CT_TYPE_VARCHAR && (tm).size == 0)

/**
* This function can combine two typemodes, when performing UNION [ALL], INTERSECT
* and MINUS operators, and inferring the datatype of CASE..WHEN, NVL and DECODE
* SQL function and expression.

*/
status_t cm_combine_typmode(typmode_t tm1, bool32 is_null1, typmode_t tm2, bool32 is_null2, typmode_t *tmr)
{
    if (is_null1 || CT_IS_NULL_TYPMODE(tm1) || CT_IS_UNKNOWN_TYPE(tm1.datatype)) {
        *tmr = tm2;
        return CT_SUCCESS;
    }

    if (is_null2 || CT_IS_NULL_TYPMODE(tm2) || CT_IS_UNKNOWN_TYPE(tm2.datatype)) {
        *tmr = tm1;
        return CT_SUCCESS;
    }

    if (CM_TYPMODE_IS_EQUAL(&tm1, &tm2)) {
        *tmr = tm1;
        return CT_SUCCESS;
    }

    if (tm2.is_array == CT_TRUE) {
        tmr->is_array = CT_TRUE;
    }

    if (CT_IS_STRING_TYPE2(tm1.datatype, tm2.datatype)) {
        cm_combine_string_typmode(&tm1, &tm2, tmr);
        return CT_SUCCESS;
    }

    if (CT_IS_NUMERIC_TYPE2(tm1.datatype, tm2.datatype)) {
        cm_combine_numeric_typmode(&tm1, &tm2, tmr);
        return CT_SUCCESS;
    }

    if (CT_IS_BINARY_TYPE2(tm1.datatype, tm2.datatype)) {
        cm_combine_binary_typmode(&tm1, &tm2, tmr);
        return CT_SUCCESS;
    }

    if (CT_IS_RAW_TYPE2(tm1.datatype, tm2.datatype)) {
        tmr->datatype = CT_TYPE_RAW;
        tmr->size = MAX(tm1.size, tm2.size);
        return CT_SUCCESS;
    }

    if (CT_IS_DATETIME_TYPE2(tm1.datatype, tm2.datatype)) {
        cm_combine_datetime_typmode(&tm1, &tm2, tmr);
        return CT_SUCCESS;
    }

    if (CT_IS_YMITVL_TYPE2(tm1.datatype, tm2.datatype)) {
        tmr->datatype = CT_TYPE_INTERVAL_YM;
        tmr->size = sizeof(interval_ym_t);
        tmr->year_prec = MAX(tm1.year_prec, tm2.year_prec);
        return CT_SUCCESS;
    }

    if (CT_IS_DSITVL_TYPE2(tm1.datatype, tm2.datatype)) {
        tmr->datatype = CT_TYPE_INTERVAL_DS;
        tmr->size = sizeof(interval_ds_t);
        tmr->day_prec = MAX(tm1.day_prec, tm2.day_prec);
        tmr->frac_prec = MAX(tm1.frac_prec, tm2.frac_prec);
        return CT_SUCCESS;
    }

    CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "expression must have same datatype as corresponding expression");
    return CT_ERROR;
}

status_t cm_typmode2str(const typmode_t *typmod, unsigned char is_array, char *buf, uint32 max_len)
{
    const text_t part = { "[]", 2 };
    text_t text;
    text.len = 0;
    text.str = buf;

    CT_RETURN_IFERR(cm_typmode2text(typmod, &text, max_len));

    if (is_array) {
        cm_concat_text(&text, max_len, &part);
    }

    CM_NULL_TERM(&text);

    return CT_SUCCESS;
}