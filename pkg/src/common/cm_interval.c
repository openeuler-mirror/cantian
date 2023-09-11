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
 * cm_interval.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_interval.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_defs.h"
#include "cm_text.h"
#include "cm_interval.h"
#include "var_inc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Reset the interval field */
#define CM_ZERO_INTVL_DETAIL(detail)   \
    do {                               \
        (detail)->year = 0;            \
        (detail)->mon = 0;             \
        (detail)->day = 0;             \
        (detail)->hour = 0;            \
        (detail)->min = 0;             \
        (detail)->sec = 0;             \
        (detail)->fsec = 0;            \
    } while (0)

/* skipping the leading digits, and return the number of digits that are skipped */
static inline uint32 cm_skip_digits(text_t *text)
{
    uint32 len = 0;
    CM_POINTER(text);
    while (text->len > 0 && CM_IS_DIGIT(CM_TEXT_FIRST(text))) {
        ++len;
        CM_REMOVE_FIRST(text);
    }
    return len;
}

/* The error no. when parsing a interval text. It can be used not only
 * for reducing cyclic complexity, but also for maintenance. */
typedef enum en_itvl_errno {
    IERR_SUCCESS = 0, /* GS_SUCCESS */
    IERR_ERROR = 1,
    IERR_NO_DIGIT,
    IERR_FIELD_TOO_LONG,
    IERR_UNEXPECTED_DOT,
    IERR_UNEXPECTED_CHAR,
    IERR_NO_FRAC_DIGIT,
    IERR_NO_INDICATOR,
    IERR_INVALID_INDICATOR,
    IERR_DISORDERED_FIELD,
    IERR_TEXT_TOO_SHORT,
    IERR_ILLEGAL_YEAR_FIELD,
    IERR_ILLEGAL_MONTH_FIELD,
    IERR_ILLEGAL_DAY_FIELD,
    IERR_ILLEGAL_HOUR_FIELD,
    IERR_ILLEGAL_MINUTE_FIELD,
    IERR_ILLEGAL_SECOND_FIELD,
    IERR_INVALID_FORMAT,
    IEER_SHORT_TIME_FIELDS,
    IEER_UNDESIRED_CHARS, /* undesired after SECOND field */
    IERR_YMINTERVAL_OVERFLOW,
    IERR_DSINTERVAL_OVERFLOW,
    IERR__NOT_USED__ /* The maximal number of error codes */
} itvl_errno_t;

static const char *g_itvl_errinfos[IERR__NOT_USED__] = {
    [IERR_SUCCESS] = "",
    [IERR_ERROR] = "",
    [IERR_NO_DIGIT] = "-- digit(s) is expected",
    [IERR_FIELD_TOO_LONG] = "-- field text is too long (<=" GS_STR(ITVL_MAX_ISO_FIELD_LEN) ")",
    [IERR_UNEXPECTED_DOT] = "-- unexpected decimal point",
    [IERR_UNEXPECTED_CHAR] = "-- unexpected character",
    [IERR_NO_FRAC_DIGIT] = "-- no fractional digits",
    [IERR_NO_INDICATOR] = "-- no field indicator",
    [IERR_INVALID_INDICATOR] = "-- invalid field indicator",
    [IERR_DISORDERED_FIELD] = "-- trailing fields must be less significant than the previous field",
    [IERR_TEXT_TOO_SHORT] = "-- text is too short",
    [IERR_ILLEGAL_YEAR_FIELD] = "-- illegal YEAR field",
    [IERR_ILLEGAL_MONTH_FIELD] = "-- illegal MONTH field",
    [IERR_ILLEGAL_DAY_FIELD] = "-- illegal DAY field",
    [IERR_ILLEGAL_HOUR_FIELD] = "-- illegal HOUR field",
    [IERR_ILLEGAL_MINUTE_FIELD] = "-- illegal MINUTE field",
    [IERR_ILLEGAL_SECOND_FIELD] = "-- illegal SECOND field",
    [IERR_INVALID_FORMAT] = "-- format error",
    [IEER_SHORT_TIME_FIELDS] = "-- time field is too short",
    [IEER_UNDESIRED_CHARS] = "-- undesired character(s) followed the SECOND field",
    [IERR_YMINTERVAL_OVERFLOW] = "-- out of range",
    [IERR_DSINTERVAL_OVERFLOW] = "-- out of range",
};

static inline const char *cm_get_itvl_errinfo(uint32 err_no)
{
    CM_ASSERT(err_no < IERR__NOT_USED__);
    CM_ASSERT(err_no != IERR_SUCCESS);
    return (g_itvl_errinfos[err_no] != NULL) ? g_itvl_errinfos[err_no] : "";
}

/* if the condition is true, throw return the value.
* Note: this Macro used to reduce Circle Complexity */
#define GS_THROW_ITVL_ERROR(cond, err_no)         \
    if (cond) {                                   \
        GS_THROW_ERROR(ERR_INVALID_INTERVAL_TEXT, \
            cm_get_itvl_errinfo(err_no));         \
        return GS_ERROR;                          \
    }

/* To verify the validation of an interval text, the new coming unit must
* less than the current unit */
#define VERIFY_INTVL_UNIT(rank, val)                         \
    do {                                                     \
        if ((rank) <= (val)) {                               \
            GS_THROW_ERROR(ERR_INVALID_INTERVAL_TEXT,        \
                cm_get_itvl_errinfo(IERR_DISORDERED_FIELD)); \
            return GS_ERROR;                                 \
        }                                                    \
        (rank) = (val);                                      \
    } while (0)

/* To verify the range of a field */
#define VERIFY_INTVL_UNIT_VALUE(unit_val, max_val, info)                \
    if ((unit_val) > (max_val)) {                                       \
        GS_THROW_ERROR(ERR_INTERVAL_FIELD_OVERFLOW, (info), (max_val)); \
        return GS_ERROR;                                                \
    }

typedef union un_itvl_item {
    text_t value;
    struct {
        char *str;
        uint32 len;
        bool32 has_dot;
    };
} itvl_item_t;

/* [field_val_uint32[.frac]][field_indicator_char] */
static inline itvl_errno_t cm_fetch_iso8601_item(text_t *iso_text, itvl_item_t *item, bool32 in_datepart)
{
    if (CM_IS_EMPTY(iso_text)) {
        GS_THROW_ERROR(ERR_ASSERT_ERROR, "iso_text is not empty");
        return IERR_ERROR;
    }

    // record the start position
    item->str = iso_text->str;
    item->len = cm_skip_digits(iso_text);

    GS_RETVALUE_IFTRUE((item->len == 0), IERR_UNEXPECTED_CHAR);
    GS_RETVALUE_IFTRUE((iso_text->len == 0), IERR_NO_INDICATOR);

    // removing leading zeros
    cm_text_ltrim_zero((text_t *)item);
    GS_RETVALUE_IFTRUE((item->len > ITVL_MAX_ISO_FIELD_LEN), IERR_FIELD_TOO_LONG);

    // handle dot
    if (!CM_IS_DOT(CM_TEXT_FIRST(iso_text))) {
        item->has_dot = GS_FALSE;
        return IERR_SUCCESS;
    }

    // the decimal point is not allowed in date part
    GS_RETVALUE_IFTRUE(in_datepart, IERR_UNEXPECTED_DOT);

    /* if dot exists */
    CM_REMOVE_FIRST(iso_text);
    uint32 fsec_prec = cm_skip_digits(iso_text);

    // if no digits in frac
    GS_RETVALUE_IFTRUE((fsec_prec == 0), IERR_NO_FRAC_DIGIT);

    // no indicator
    GS_RETVALUE_IFTRUE((iso_text->len == 0), IERR_NO_INDICATOR);

    // the indicator must be 'S', i.e., the dot must allowed in second field
    GS_RETVALUE_IFTRUE((!IS_SECOND_INDICATOR(CM_TEXT_FIRST(iso_text))), IERR_UNEXPECTED_CHAR);

    /* SECOND is the last field, and no characters are allowed */
    GS_RETVALUE_IFTRUE((iso_text->len > 1), IEER_UNDESIRED_CHARS);

    // recompute the length
    item->len = (uint32)(iso_text->str - item->str);
    item->has_dot = GS_TRUE;
    return IERR_SUCCESS;
}

/* Convert YEAR, MONTH, DAY, HOUR and MINUTE fields into value.
 * @note The field text must be an unsigned integer, and the number of
 * significant digits is limited to ITVL_MAX_FIELD_LEN */
static inline uint32 cm_field2value(const text_t *item)
{
    uint32 value = (uint32)CM_C2D(CM_TEXT_FIRST(item));

    // the number of significant digits of a field is limit to 9
    CM_ASSERT(item->len <= ITVL_MAX_ISO_FIELD_LEN);
    for (uint32 i = 1; i < item->len; i++) {
        value *= 10;
        value += (uint32)CM_C2D(item->str[i]);
    }

    return value;
}

static inline status_t cm_parse_iso_dateitem(interval_detail_t *idetail,
                                             uint32 *mask, text_t *isotext, itvl_item_t *item)
{
    if (CM_IS_EMPTY(isotext)) {
        GS_THROW_ERROR(ERR_ASSERT_ERROR, "isotext is not empty");
        return GS_ERROR;
    }

    switch (CM_TEXT_FIRST(isotext)) {
        case 'Y': /* YEAR */
            VERIFY_INTVL_UNIT(*mask, IU_YEAR);
            idetail->year = cm_field2value((text_t *)item);
            VERIFY_INTVL_UNIT_VALUE(idetail->year, ITVL_MAX_ISO_YEAR, "YEAR");
            break;
        case 'M': /* MONTH */
            VERIFY_INTVL_UNIT(*mask, IU_MONTH);
            idetail->mon = cm_field2value((text_t *)item);
            VERIFY_INTVL_UNIT_VALUE(idetail->mon, ITVL_MAX_ISO_MONTH, "MONTH");
            break;
        case 'D': /* DAYS */
            VERIFY_INTVL_UNIT(*mask, IU_DAY);
            idetail->day = cm_field2value((text_t *)item);
            VERIFY_INTVL_UNIT_VALUE(idetail->day, ITVL_MAX_ISO_DAY, "DAY");
            break;
        default:
            GS_THROW_ERROR(ERR_INVALID_INTERVAL_TEXT, cm_get_itvl_errinfo(IERR_UNEXPECTED_CHAR));
            return GS_ERROR;
    }

    return GS_SUCCESS;
}

/* Convert SECOND fields into value.
* @note The SECOND field text must be an unsigned integer, and the number of
* significant digits is also limited to ITVL_MAX_FIELD_LEN.  */
static inline status_t cm_second_field2value(const itvl_item_t *item, uint32 *sec, uint32 *frac_sec)
{
    double val;

    if (!item->has_dot) {
        // if no dot, use cm_field2value may improve the performance
        *sec = cm_field2value((text_t *)item);
        *frac_sec = 0;
        return GS_SUCCESS;
    }

    if (cm_text2real_ex((text_t *)item, &val) != NERR_SUCCESS) {
        return GS_ERROR;
    }
    CM_ASSERT(val >= 0.0 && val <= (ITVL_MAX_ISO_SECOND + 1));
    *sec = (uint32)(int32)val;
    // compute fractional second from mantissa
    *frac_sec = (uint32)(int32)rint((val - (*sec)) * (double)(ITVL_MAX_SQL_FRAC_SEC + 1));
    return GS_SUCCESS;
}

static inline status_t cm_parse_iso_timeitem(interval_detail_t *idetail,
                                             uint32 *mask, text_t *isotext, itvl_item_t *item)
{
    if (CM_IS_EMPTY(isotext)) {
        GS_THROW_ERROR(ERR_ASSERT_ERROR, "isotext is not empty");
        return GS_ERROR;
    }

    switch (CM_TEXT_FIRST(isotext)) {
        case 'H':
            VERIFY_INTVL_UNIT(*mask, IU_HOUR);
            idetail->hour = cm_field2value((text_t *)item);
            break;
        case 'M': /* MINUTE */
            VERIFY_INTVL_UNIT(*mask, IU_MINUTE);
            idetail->min = cm_field2value((text_t *)item);
            break;
        case 'S':  // parsing second without fractional second
            VERIFY_INTVL_UNIT(*mask, IU_SECOND);
            GS_RETURN_IFERR(cm_second_field2value(item, &idetail->sec, &idetail->fsec));
            break;
        default:
            GS_THROW_ERROR(ERR_INVALID_INTERVAL_TEXT, cm_get_itvl_errinfo(IERR_UNEXPECTED_CHAR));
            return GS_ERROR;
    }

    return GS_SUCCESS;
}

/* Set the rank. The *rank* is mainly used to control the parsing order of
 * interval fields. The ISO 8601:2004 format requires that the trailing
 * fields must be less significant than the previous field. For example,
 * YEAR field is more significant than MONTH field, therefore, the YEAR
 * field can not be allowed after MONTH field, e.g., P12M00Y is illegal.
 * The significance of interval fields refer to the definition of
 * *interval_unit_t*. The macro *VERIFY_INTVL_UNIT* is used to ensure this
 * requirement.
 *
 * For GS_TYPE_INTERVAL_YM type, all fields can be allowed in the interval text.
 * However, if the DAY or TIME fields are specified in YM_INTERVAL, they will
 * be ignored. For GS_TYPE_INTERVAL_DS type, YEAR and MONTH fields are not allowed.
 * Therefore, the MASK is set by IU_DS_INTERVAL.
 * */
static inline uint32 cm_init_interval_rank(gs_type_t itype)
{
    return (itype == GS_TYPE_INTERVAL_YM) ? (uint32)IU_ALL : (uint32)IU_DS_INTERVAL;
}

/* Parse ISO 8601:2004 standard based Interval text to interval details.
 * The syntax of the standard is:
 * [-] P [years Y] [months M] [days D] [T [hours H] [minutes M] [seconds [. frac_secs] S ] ] */
static inline status_t cm_isotext2intvl_detail(text_t *iso_text,
                                               gs_type_t itype, interval_detail_t *idetail)
{
    itvl_item_t item;
    uint32 rank;
    bool32 in_datepart = GS_TRUE;
    itvl_errno_t err_no;

    CM_POINTER2(iso_text, idetail);

    // if text is too short
    GS_THROW_ITVL_ERROR((iso_text->len < 3), IERR_TEXT_TOO_SHORT);

    rank = cm_init_interval_rank(itype);

    // ignoring the Leading P
    CM_REMOVE_FIRST(iso_text);
    while (iso_text->len > 0) {
        if (IS_TIME_INDICATOR(CM_TEXT_FIRST(iso_text))) {
            VERIFY_INTVL_UNIT(rank, IU_TIME);
            in_datepart = GS_FALSE;

            /* If T is specified, then at least one of the hours, minutes,
             * or seconds values must be specified. */
            GS_THROW_ITVL_ERROR((iso_text->len < 3), IEER_SHORT_TIME_FIELDS);
            CM_REMOVE_FIRST(iso_text);  // remove indicator T
            continue;
        }

        err_no = cm_fetch_iso8601_item(iso_text, &item, in_datepart);
        if (err_no != IERR_SUCCESS) {
            GS_THROW_ERROR(ERR_INVALID_INTERVAL_TEXT, cm_get_itvl_errinfo(err_no));
            return GS_ERROR;
        }

        if (in_datepart) {
            GS_RETURN_IFERR(cm_parse_iso_dateitem(idetail, &rank, iso_text, &item));
        } else {
            GS_RETURN_IFERR(cm_parse_iso_timeitem(idetail, &rank, iso_text, &item));
        }

        // remove indicator and go into next field
        CM_REMOVE_FIRST(iso_text);
    }

    return GS_SUCCESS;
}

/** fetch field from SQL format */
static inline status_t cm_fetch_sqlfmt_item(text_t *sqltext, itvl_item_t *item)
{
    cm_trim_text(sqltext);
    GS_THROW_ITVL_ERROR(CM_IS_EMPTY(sqltext), IERR_INVALID_FORMAT);

    item->str = sqltext->str;
    item->len = cm_skip_digits(sqltext);

    // removing leading zeros
    cm_text_ltrim_zero((text_t *)item);

    if (item->len == 0) {
        GS_THROW_ITVL_ERROR((sqltext->len > 0), IERR_UNEXPECTED_CHAR);
        GS_THROW_ITVL_ERROR((sqltext->len == 0), IERR_INVALID_FORMAT);
    }
    GS_THROW_ITVL_ERROR((item->len > ITVL_MAX_ISO_FIELD_LEN), IERR_FIELD_TOO_LONG);

    return GS_SUCCESS;
}

static status_t cm_fetch_sqlfmt_field(text_t *sqltext, char split_char, uint32 *val)
{
    itvl_item_t item;
    uint32 i;
    bool32 is_found = GS_FALSE; /* record whether found the split char */

    GS_RETURN_IFERR(cm_fetch_sqlfmt_item(sqltext, &item));

    if (sqltext->len == 0) {
        // the last item may not have the separator char
        *val = cm_field2value((text_t *)(&item));
        return GS_SUCCESS;
    } else {
        // scan the split char, here invisible chars are allowed
        for (i = 0; i < sqltext->len; i++) {
            if (sqltext->str[i] == split_char) {
                is_found = GS_TRUE;
                break;
            }
            GS_THROW_ITVL_ERROR((sqltext->str[i] > ' '), IERR_UNEXPECTED_CHAR);
        }
        GS_THROW_ITVL_ERROR(!is_found, IERR_INVALID_FORMAT);

        *val = cm_field2value((text_t *)(&item));

        // remove the split char
        i++;
        sqltext->str += i;
        sqltext->len -= i;
    }
    return GS_SUCCESS;
}

/* [+|-] years - months */
static status_t cm_sqltext2ymintvl_detail(text_t *sqltext, interval_detail_t *idetail, uint32 fmt)
{
    text_t month;

    if (fmt & IU_YEAR) {
        GS_RETURN_IFERR(cm_fetch_sqlfmt_field(sqltext, '-', &idetail->year));
        VERIFY_INTVL_UNIT_VALUE(idetail->year, ITVL_MAX_SQL_YEAR, "YEAR");
    }
    if (fmt & IU_MONTH) {
        // MONTH fields can not be empty and must begin with digit
        cm_trim_text(sqltext);
        month.str = sqltext->str;
        month.len = cm_skip_digits(sqltext);

        // removing leading zeros
        cm_text_ltrim_zero(&month);

        // expect to end the parsing
        GS_THROW_ITVL_ERROR((sqltext->len != 0), IERR_UNEXPECTED_CHAR);

        GS_THROW_ITVL_ERROR((month.len == 0), IERR_INVALID_FORMAT);
        GS_THROW_ITVL_ERROR((month.len > ITVL_MAX_ISO_FIELD_LEN), IERR_ILLEGAL_MONTH_FIELD);

        idetail->mon = cm_field2value(&month);
    }
    // expected end
    cm_trim_text(sqltext);
    GS_THROW_ITVL_ERROR(!CM_IS_EMPTY(sqltext), IERR_INVALID_FORMAT);

    if (fmt & IU_YEAR) {
        VERIFY_INTVL_UNIT_VALUE(idetail->mon, ITVL_MAX_SQL_MONTH, "MONTH");
    }

    // adjust fields
    if (idetail->mon > ITVL_MAX_SQL_MONTH) {
        idetail->year += idetail->mon / 12;
        idetail->mon %= 12;
        VERIFY_INTVL_UNIT_VALUE(idetail->year, ITVL_MAX_SQL_YEAR, "YEAR");
    }
    return GS_SUCCESS;
}

static inline status_t cm_fetch_sqlfmt_second(text_t *sqltext, interval_detail_t *idetail)
{
    itvl_item_t item;

    /* fetch the second part */
    GS_RETURN_IFERR(cm_fetch_sqlfmt_item(sqltext, &item));

    if (sqltext->len == 0) {
        item.has_dot = GS_FALSE;
    } else { /* try to fetch the fractional second part */
        uint32 fsec_prec;
        // if the first char is not a dot
        GS_THROW_ITVL_ERROR((!CM_IS_DOT(CM_TEXT_FIRST(sqltext))), IERR_UNEXPECTED_CHAR);

        // handle dot
        CM_REMOVE_FIRST(sqltext);  // remove dot
        fsec_prec = cm_skip_digits(sqltext);

        // if no digits in frac
        GS_THROW_ITVL_ERROR((fsec_prec == 0), IERR_NO_FRAC_DIGIT);
        /* SECOND is the last field, and no characters are allowed */
        GS_THROW_ITVL_ERROR((sqltext->len != 0), IEER_UNDESIRED_CHARS);

        // recompute the length
        item.len = (uint32)(sqltext->str - item.str);
        item.has_dot = GS_TRUE;
    }

    GS_RETURN_IFERR(cm_second_field2value(&item, &idetail->sec, &idetail->fsec));

    return GS_SUCCESS;
}

/* The minimal text length of a DS interval, e.g., "0 0:0:0" */
/* [+|-] days hours : minutes : seconds [. frac_secs ] */
static status_t cm_sqltext2dsintvl_detail(text_t *sqltext, interval_detail_t *idetail, uint32 fmt)
{
    cm_trim_text(sqltext);
    GS_THROW_ITVL_ERROR(CM_IS_EMPTY(sqltext), IERR_INVALID_FORMAT);

    if (fmt & IU_DAY) {
        // fetch day field
        GS_RETURN_IFERR(cm_fetch_sqlfmt_field(sqltext, ' ', &idetail->day));
        VERIFY_INTVL_UNIT_VALUE(idetail->day, ITVL_MAX_SQL_DAY, "DAY");
    }
    if (fmt & IU_HOUR) {
        // fetch hour field
        GS_RETURN_IFERR(cm_fetch_sqlfmt_field(sqltext, ':', &idetail->hour));
    }
    if (fmt & IU_MINUTE) {
        // fetch minute field
        GS_RETURN_IFERR(cm_fetch_sqlfmt_field(sqltext, ':', &idetail->min));
    }
    if (fmt & IU_SECOND) {
        // fetch second field
        GS_RETURN_IFERR(cm_fetch_sqlfmt_second(sqltext, idetail));
    }
    // expected end
    cm_trim_text(sqltext);
    GS_THROW_ITVL_ERROR(!CM_IS_EMPTY(sqltext), IERR_INVALID_FORMAT);

    // verify field value
    if (fmt & IU_DAY) {
        VERIFY_INTVL_UNIT_VALUE(idetail->hour, ITVL_MAX_SQL_HOUR, "HOUR");
    }
    if (fmt & (IU_DAY | IU_HOUR)) {
        VERIFY_INTVL_UNIT_VALUE(idetail->min, ITVL_MAX_SQL_MINUTE, "MINUTE");
    }
    if (fmt & (IU_DAY | IU_HOUR | IU_MINUTE)) {
        VERIFY_INTVL_UNIT_VALUE(idetail->sec, ITVL_MAX_SQL_SECOND, "SECOND");
    }

    // adjust fields
    if (idetail->sec > ITVL_MAX_SQL_SECOND) {
        idetail->min += idetail->sec / 60;
        idetail->sec %= 60;
    }
    if (idetail->min > ITVL_MAX_SQL_MINUTE) {
        idetail->hour += idetail->min / 60;
        idetail->min %= 60;
    }
    if (idetail->hour > ITVL_MAX_SQL_HOUR) {
        idetail->day += idetail->hour / 24;
        idetail->hour %= 24;
    }
    VERIFY_INTVL_UNIT_VALUE(idetail->day, ITVL_MAX_SQL_DAY, "DAY");
    return GS_SUCCESS;
}

static inline status_t cm_sqltext2intvl_detail(text_t *sqltext, gs_type_t itype, interval_detail_t *idetail,
                                               uint32 fmt)
{
    // if no text
    GS_THROW_ITVL_ERROR((sqltext->len == 0), IERR_TEXT_TOO_SHORT);

    if (itype == GS_TYPE_INTERVAL_YM) {
        return cm_sqltext2ymintvl_detail(sqltext, idetail, fmt);
    } else {
        return cm_sqltext2dsintvl_detail(sqltext, idetail, fmt);
    }
}

status_t cm_text2intvl_detail(const text_t *text, gs_type_t itype, interval_detail_t *idetail, uint32 fmt)
{
    text_t itv_text = *text;
    cm_trim_text(&itv_text);

    // if no text
    GS_THROW_ITVL_ERROR((itv_text.len == 0), IERR_TEXT_TOO_SHORT);

    idetail->is_neg = GS_FALSE;
    if (CM_IS_SIGN_CHAR(CM_TEXT_FIRST(&itv_text))) {
        idetail->is_neg = (CM_TEXT_FIRST(&itv_text) == '-');
        CM_REMOVE_FIRST(&itv_text);
    }

    /* Reset the interval field */
    CM_ZERO_INTVL_DETAIL(idetail);

    if (IS_ISO_INDICATOR(CM_TEXT_FIRST(&itv_text))) {
        return cm_isotext2intvl_detail(&itv_text, itype, idetail);
    } else {
        return cm_sqltext2intvl_detail(&itv_text, itype, idetail, fmt);
    }
}

status_t cm_text2yminterval(const text_t *text, interval_ym_t *itvl)
{
    interval_detail_t itvl_detail;

    GS_RETURN_IFERR(cm_text2intvl_detail(text, GS_TYPE_INTERVAL_YM, &itvl_detail, IU_YM_INTERVAL));

    return cm_encode_yminterval(&itvl_detail, itvl);
}

status_t cm_text2dsinterval(const text_t *text, interval_ds_t *itvl)
{
    interval_detail_t itvl_detail;

    GS_RETURN_IFERR(cm_text2intvl_detail(text, GS_TYPE_INTERVAL_DS, &itvl_detail, IU_DS_INTERVAL));

    return cm_encode_dsinterval(&itvl_detail, itvl);
}

status_t cm_encode_yminterval(const interval_detail_t *idetail, interval_ym_t *itvl)
{
    CM_POINTER(idetail);

    *itvl = (interval_ym_t)(idetail->mon + idetail->year * ITVL_MONTHS_PER_YEAR);
    GS_THROW_ITVL_ERROR((*itvl > GS_MAX_YMINTERVAL), IERR_YMINTERVAL_OVERFLOW);

    if (idetail->is_neg) {
        *itvl = -(*itvl);
    }

    return GS_SUCCESS;
}

status_t cm_encode_dsinterval(const interval_detail_t *idetail, interval_ds_t *itvl)
{
    interval_ds_t unit;
    CM_POINTER(idetail);

    // init with day unit
    *itvl = (interval_ds_t)((uint64)idetail->day * ITVL_UNITS_PER_DAY);

    // add hour unit
    unit = (interval_ds_t)((uint64)idetail->hour * ITVL_UNITS_PER_HOUR);
    GS_RETURN_IFERR(cm_dsinterval_add(*itvl, unit, itvl));

    // add minute unit
    unit = (interval_ds_t)((uint64)idetail->min * ITVL_UNITS_PER_MINUTE);
    GS_RETURN_IFERR(cm_dsinterval_add(*itvl, unit, itvl));

    // add second unit
    unit = (interval_ds_t)((uint64)idetail->sec * ITVL_UNITS_PER_SECOND);
    GS_RETURN_IFERR(cm_dsinterval_add(*itvl, unit, itvl));

    // add frac_sec unit
    GS_RETURN_IFERR(cm_dsinterval_add(*itvl, idetail->fsec, itvl));

    if (idetail->is_neg) {
        *itvl = -(*itvl);
    }
    return GS_SUCCESS;
}

void cm_decode_yminterval(interval_ym_t ymitvl_input, interval_detail_t *idetail)
{
    int32 ymitvl = ymitvl_input;
    CM_POINTER(idetail);

    CM_ZERO_INTVL_DETAIL(idetail);

    idetail->is_neg = GS_FALSE;
    if (ymitvl < 0) {
        idetail->is_neg = GS_TRUE;
        ymitvl = -ymitvl;
    }

    idetail->year = (uint32)ymitvl / (uint32)ITVL_MONTHS_PER_YEAR;
    idetail->mon = (uint32)ymitvl - idetail->year * (uint32)ITVL_MONTHS_PER_YEAR;
}

static inline uint32 cm_decode_dsunit(uint64 ds_val, uint64 unit, interval_ds_t *ds_res)
{
    if (unit == 0) {
        GS_THROW_ERROR(ERR_ZERO_DIVIDE);
        return GS_DEFAULT_NULL_VALUE;
    }
    uint32 uval = (uint32)(ds_val / unit);
    *ds_res = (interval_ds_t)(ds_val - uval * unit);
    return uval;
}

void cm_decode_dsinterval(interval_ds_t dsitvl_input, interval_detail_t *idetail)
{
    int64 dsitvl = dsitvl_input;
    CM_POINTER(idetail);

    CM_ZERO_INTVL_DETAIL(idetail);

    idetail->is_neg = GS_FALSE;
    if (dsitvl < 0) {
        idetail->is_neg = GS_TRUE;
        dsitvl = -dsitvl;
    }

    CM_ASSERT(dsitvl <= GS_MAX_DSINTERVAL);

    idetail->day = cm_decode_dsunit((uint64)dsitvl, ITVL_UNITS_PER_DAY, &dsitvl);
    idetail->hour = cm_decode_dsunit((uint64)dsitvl, ITVL_UNITS_PER_HOUR, &dsitvl);
    idetail->min = cm_decode_dsunit((uint64)dsitvl, ITVL_UNITS_PER_MINUTE, &dsitvl);
    idetail->sec = cm_decode_dsunit((uint64)dsitvl, ITVL_UNITS_PER_SECOND, &dsitvl);
    idetail->fsec = (uint32)dsitvl;

    CM_ASSERT(idetail->day <= ITVL_MAX_SQL_DAY);
    CM_ASSERT(idetail->hour <= ITVL_MAX_SQL_HOUR);
    CM_ASSERT(idetail->min <= ITVL_MAX_SQL_MINUTE);
    CM_ASSERT(idetail->sec <= ITVL_MAX_SQL_SECOND);
    CM_ASSERT(idetail->fsec <= ITVL_MAX_SQL_FRAC_SEC);
}

static void cm_yminterval2text_ex(interval_ym_t ymitvl, uint32 year_prec, text_t *text)
{
    interval_detail_t idetail;
    int iret_sprintf;

    CM_POINTER2(text, text->str);
    cm_decode_yminterval(ymitvl, &idetail);

    CM_TEXT_CLEAR(text);
    CM_TEXT_APPEND(text, (idetail.is_neg ? '-' : '+'));

    iret_sprintf = snprintf_s(CM_GET_TAIL(text), GS_MAX_YM_INTERVAL_STRLEN, GS_MAX_YM_INTERVAL_STRLEN - 1, "%0*u-%02u",
                              year_prec, idetail.year, idetail.mon);
    PRTS_RETVOID_IFERR(iret_sprintf);
    text->len += (uint32)iret_sprintf;
}

static void cm_dsinterval2text_ex(interval_ds_t dsitvl, uint32 day_prec, uint32 frac_prec, text_t *text)
{
    interval_detail_t idetail;
    int iret_sprintf;

    CM_POINTER2(text, text->str);
    cm_decode_dsinterval(dsitvl, &idetail);

    CM_TEXT_CLEAR(text);
    CM_TEXT_APPEND(text, (idetail.is_neg ? '-' : '+'));

    if (frac_prec == 0) {
        iret_sprintf = snprintf_s(CM_GET_TAIL(text), GS_MAX_DS_INTERVAL_STRLEN, GS_MAX_DS_INTERVAL_STRLEN - 1,
                                  "%0*u %02u:%02u:%02u", day_prec, idetail.day, idetail.hour, idetail.min, idetail.sec);
        PRTS_RETVOID_IFERR(iret_sprintf);
        text->len += (uint32)iret_sprintf;
    } else {
        iret_sprintf = snprintf_s(CM_GET_TAIL(text), GS_MAX_DS_INTERVAL_STRLEN, GS_MAX_DS_INTERVAL_STRLEN - 1,
                                  "%0*u %02u:%02u:%02u.%06u", day_prec, idetail.day, idetail.hour, idetail.min,
                                  idetail.sec, idetail.fsec);
        PRTS_RETVOID_IFERR(iret_sprintf);
        text->len += (uint32)iret_sprintf;
        text->len -= (ITVL_MAX_SECOND_PREC - frac_prec);
    }
}

void cm_yminterval2text(interval_ym_t ymitvl, text_t *text)
{
    cm_yminterval2text_ex(ymitvl, ITVL_DEFAULT_YEAR_PREC, text);
}

void cm_yminterval2text_prec(interval_ym_t ymitvl, uint8 year_prec, text_t *text)
{
    cm_yminterval2text_ex(ymitvl, (uint32)year_prec, text);
}

void cm_dsinterval2text(interval_ds_t dsitvl, text_t *text)
{
    cm_dsinterval2text_ex(dsitvl, ITVL_DEFAULT_DAY_PREC, ITVL_MAX_SECOND_PREC, text);
}

void cm_dsinterval2text_prec(interval_ds_t dsitvl, uint8 day_prec, uint8 sec_prec, text_t *text)
{
    cm_dsinterval2text_ex(dsitvl, (uint32)day_prec, (uint32)sec_prec, text);
}

uint32 cm_yminterval2str_ex(interval_ym_t ymitvl, uint32 year_prec, char *str)
{
    text_t text;
    CM_POINTER(str);

    text.str = str;
    text.len = 0;

    cm_yminterval2text_ex(ymitvl, year_prec, &text);

    return text.len;
}

uint32 cm_dsinterval2str_ex(interval_ds_t dsitvl, uint32 day_prec, uint32 frac_prec, char *str, uint32 str_max_sz)
{
    text_t text;
    CM_POINTER(str);

    text.str = str;
    text.len = 0;

    cm_dsinterval2text_ex(dsitvl, day_prec, frac_prec, &text);

    if (text.len >= str_max_sz) {
        GS_THROW_ERROR(ERR_BUFFER_OVERFLOW, text.len, str_max_sz);
        return 0;
    }
    CM_NULL_TERM(&text);

    return text.len;
}

uint32 cm_yminterval2str(interval_ym_t ymitvl, char *str)
{
    return cm_yminterval2str_ex(ymitvl, ITVL_DEFAULT_YEAR_PREC, str);
}

uint32 cm_dsinterval2str(interval_ds_t dsitvl, char *str, uint32 str_max_sz)
{
    return cm_dsinterval2str_ex(dsitvl, ITVL_DEFAULT_DAY_PREC, ITVL_DEFAULT_SECOND_PREC, str, str_max_sz);
}

interval_unit_t cm_get_ymitvl_unit(const text_t *text)
{
    static const text_t ytext = { .str = "YEAR", .len = 4u };
    static const text_t mtext = { .str = "MONTH", .len = 5u };

    text_t utext;
    CM_POINTER(text);
    utext = *text;

    cm_trim_text(&utext);
    if (cm_text_equal_ins(&utext, &ytext)) {
        return IU_YEAR;
    }
    if (cm_text_equal_ins(&utext, &mtext)) {
        return IU_MONTH;
    }

    return IU_NONE;
}

interval_unit_t cm_get_dsitvl_unit(const text_t *text)
{
    static const text_t text_day = { .str = "DAY",    .len = 3u };
    static const text_t text_hour = { .str = "HOUR",   .len = 4u };
    static const text_t text_min = { .str = "MINUTE", .len = 6u };
    static const text_t text_sec = { .str = "SECOND", .len = 6u };

    text_t utext;
    CM_POINTER(text);
    utext = *text;

    cm_trim_text(&utext);
    if (cm_text_equal_ins(&utext, &text_day)) {
        return IU_DAY;
    }
    if (cm_text_equal_ins(&utext, &text_hour)) {
        return IU_HOUR;
    }
    if (cm_text_equal_ins(&utext, &text_min)) {
        return IU_MINUTE;
    }
    if (cm_text_equal_ins(&utext, &text_sec)) {
        return IU_SECOND;
    }

    return IU_NONE;
}

status_t cm_yminterval_add_date(interval_ym_t ymitvl_input, date_t date, date_t *res)
{
    date_detail_t detail;
    int32 year, month;
    int32 ymitvl = ymitvl_input;

    cm_decode_date(date, &detail);
    year = (int32)detail.year;
    month = detail.mon;

    year += (ymitvl / ITVL_MONTHS_PER_YEAR);
    ymitvl %= ITVL_MONTHS_PER_YEAR;
    month += ymitvl;

    if (month > ITVL_MONTHS_PER_YEAR) {
        year++;
        month -= ITVL_MONTHS_PER_YEAR;
    } else if (month <= 0) {
        year--;
        month += ITVL_MONTHS_PER_YEAR;
    }

    if (!CM_IS_VALID_YEAR(year)) {
        GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "DATETIME");
        return GS_ERROR;
    }

    detail.day = MIN(detail.day, CM_MONTH_DAYS(year, month));
    detail.year = (uint16)year;
    detail.mon = (uint8)month;

    *res = cm_encode_date(&detail);

    return GS_SUCCESS;
}

status_t cm_adjust_yminterval(interval_ym_t *ymitvl, uint32 year_prec)
{
    uint32 year = CM_EXTRACT_YEAR(*ymitvl);
    if (year_prec > (uint32)ITVL_MAX_YEAR_PREC) {
        GS_THROW_ERROR_EX(ERR_ASSERT_ERROR, "year_prec(%u) <= ITVL_MAX_YEAR_PREC(%u)", year_prec,
                          (uint32)ITVL_MAX_YEAR_PREC);
        return GS_ERROR;
    }

    if (year < g_1ten_powers[year_prec]) {
        return GS_SUCCESS;
    }

    GS_THROW_ERROR(ERR_INVALID_INTERVAL_FIELD, "YEAR", year_prec);
    return GS_ERROR;
}

#define CM_VERIFY_DAY_FIELD(dsitvl, day_prec)                            \
    do {                                                                 \
        if ((uint32)CM_EXTRACT_DAY(dsitvl) >= g_1ten_powers[day_prec]) { \
            GS_THROW_ERROR(ERR_INVALID_INTERVAL_FIELD, "DAY", day_prec); \
            return GS_ERROR;                                             \
        }                                                                \
    } while (GS_FALSE)

status_t cm_adjust_dsinterval(interval_ds_t *dsitvl, uint32 day_prec, uint32 fsec_prec)
{
    if (day_prec > (uint32)ITVL_MAX_DAY_PREC) {
        GS_THROW_ERROR_EX(ERR_ASSERT_ERROR, "day_prec(%u) <= ITVL_MAX_DAY_PREC(%u)",
            day_prec, (uint32)ITVL_MAX_DAY_PREC);
        return GS_ERROR;
    }
    if (fsec_prec > (uint32)ITVL_MAX_SECOND_PREC) {
        GS_THROW_ERROR_EX(ERR_ASSERT_ERROR, "fsec_prec(%u) <= ITVL_MAX_SECOND_PREC(%u)", fsec_prec,
                          (uint32)ITVL_MAX_SECOND_PREC);
        return GS_ERROR;
    }

    if (*dsitvl == 0) {
        return GS_SUCCESS;
    }

    CM_VERIFY_DAY_FIELD(*dsitvl, day_prec);

    if (fsec_prec == ITVL_MAX_SECOND_PREC) {
        return GS_SUCCESS;
    }

    *dsitvl = (interval_ds_t)cm_truncate_bigint(*dsitvl, (uint32)(ITVL_MAX_SECOND_PREC - fsec_prec));

    CM_VERIFY_DAY_FIELD(*dsitvl, day_prec);

    return GS_SUCCESS;
}

#ifdef __cplusplus
}
#endif
