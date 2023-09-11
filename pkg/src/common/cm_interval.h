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
 * cm_interval.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_interval.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CM_INTERVAL_H__
#define __CM_INTERVAL_H__

#include "cm_defs.h"
#include "cm_text.h"
#include "cm_date.h"
#include <math.h>

#ifdef WIN32
#else
#include <string.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* The interval data type YEAR TO MONTH. It stores a period of time
   in years and months. Thus, the smallest unit is month */
typedef int32 interval_ym_t;

/* The interval data type DAY TO SECOND. It stores a period of time
   in n days, hours, minutes, and seconds. The SECOND part is designed
   not only to include seconds, but also to include milliseconds and
   micro-seconds. Therefore, the smallest unit of this interval datatype
   is designed to be micro-seconds (us) */
typedef int64 interval_ds_t;

/* The interval data type with Postgre style. The DDL syntax of interval for
   Postgre is `interval [fields][(frac_prec)]`. The field option is to
   restrict the set of stored fields by writing one of the following phrases:
   `YEAR`, `MONTH`, `DAY`, `HOUR`, `MINUTE`, `SECOND`, `YEAR TO MONTH`,
   `DAY TO HOUR`, `DAY TO MINUTE`, `DAY TO SECOND`, `HOUR TO MINUTE`,
   `HOUR TO SECOND`, `MINUTE TO SECOND`; the frac_prec option is merely
   used when the field SECOND is specified.
 
   @note (1) This datatype merely used in PG-style SQL;
         (2) The PG-style SQL allows to specify `YEAR TO MONTH` and `DAY TO SECOND` to
         Interval datatype, which are exactly same as the TWO types of
         Interval in Oracle-style SQL, but they have different storages
         and operating ways.
*/
typedef int64 interval_t;

/* The unit of an interval. Its value defines its significance. The high
   significant unit can not be parsed after low significant unit. */
typedef enum en_interval_unit {
    IU_NONE = 0x00000000,
    IU_MICROSECOND = 0x00000001,
    IU_MILLISECOND = 0x00000002,
    IU_SECOND = 0x00000004,
    IU_MINUTE = 0x00000008,
    IU_HOUR = 0x00000010,
    IU_DAY = 0x00000020,
    IU_WEEK = 0x00000040,
    IU_MONTH = 0x00000080,
    IU_QUARTER = 0x00000100,
    IU_YEAR = 0x00000200,
    IU_TIME = IU_SECOND | IU_MINUTE | IU_HOUR,
    IU_DS_INTERVAL = IU_DAY | IU_TIME,
    IU_YM_INTERVAL = IU_YEAR | IU_MONTH,
    IU_ALL = IU_YM_INTERVAL | IU_DS_INTERVAL,
} interval_unit_t;

#define GS_IS_YM_UNIT(resid)       ((resid) == IU_YEAR || (resid) == IU_MONTH || (resid) == IU_QUARTER)
#define GS_IS_DAY_UNIT(resid)      ((resid) == IU_DAY || (resid) == IU_WEEK)
#define GS_IS_TIME_UNIT(resid)                                                                                         \
    ((resid) == IU_HOUR || (resid) == IU_MINUTE || (resid) == IU_SECOND || (resid) == IU_MICROSECOND)
#define GS_IS_DATETIME_UNIT(resid) (GS_IS_YM_UNIT(resid) || GS_IS_DAY_UNIT(resid) || GS_IS_TIME_UNIT(resid))

#pragma pack(4)
/* To represent all parts of a interval type */
typedef struct st_interval_detail {
    bool32 is_neg;
    uint32 year;
    uint32 mon;
    uint32 day;
    uint32 hour;
    uint32 min;
    uint32 sec;
    uint32 fsec;
} interval_detail_t;
#pragma pack()

/* Used for parsing an interval text or literal */
#define IS_ISO_INDICATOR(c)    ('P' == (c))
#define IS_TIME_INDICATOR(c)   ('T' == (c))
#define IS_YEAR_INDICATOR(c)   ('Y' == (c))
#define IS_MONTH_INDICATOR(c)  ('M' == (c))
#define IS_DAY_INDICATOR(c)    ('D' == (c))
#define IS_HOUR_INDICATOR(c)   ('H' == (c))
#define IS_MINUTE_INDICATOR(c) ('M' == (c))
#define IS_SECOND_INDICATOR(c) ('S' == (c))

/* The basic settings for INTERVAL types */
#define ITVL_MONTHS_PER_YEAR  12
#define ITVL_DAYS_PER_MONTH   30
#define ITVL_HOURS_PER_DAY    24
#define ITVL_UNITS_PER_DAY    86400000000ULL
#define ITVL_UNITS_PER_HOUR   3600000000ULL
#define ITVL_UNITS_PER_MINUTE 60000000ULL
#define ITVL_UNITS_PER_SECOND 1000000ULL

/* Extract an interval unit from a positive interval */
#define CM_EXTRACT_YEAR(ymitvl)    (((uint32)abs(ymitvl)) / (uint32)ITVL_MONTHS_PER_YEAR)
#define CM_EXTRACT_MONTH(ymitvl)   (((uint32)abs(ymitvl)) % (uint32)ITVL_MONTHS_PER_YEAR)
#define CM_EXTRACT_DAY(dsitvl)     (((uint64)llabs(dsitvl)) / ITVL_UNITS_PER_DAY)
#define CM_EXTRACT_FRACSEC(dsitvl) (((uint64)llabs(dsitvl)) % ITVL_UNITS_PER_SECOND)

/** The limitations of fields when parsing an interval text */
/* The limitations for SQL format */
#define ITVL_MAX_SQL_YEAR     (9999u)
#define ITVL_MAX_SQL_MONTH    (11u)
#define ITVL_MAX_SQL_DAY      (9999999u)
#define ITVL_MAX_SQL_HOUR     (23u)
#define ITVL_MAX_SQL_MINUTE   (59u)
#define ITVL_MAX_SQL_SECOND   (59u)
#define ITVL_MAX_SQL_FRAC_SEC (999999u)

/* The limitations for ISO8601 format */
#define ITVL_MAX_ISO_YEAR     ITVL_MAX_SQL_YEAR
#define ITVL_MAX_ISO_MONTH    (99999u)
#define ITVL_MAX_ISO_DAY      ITVL_MAX_SQL_DAY
#define ITVL_MAX_ISO_HOUR     (99999999u)
#define ITVL_MAX_ISO_MINUTE   (999999999u)
#define ITVL_MAX_ISO_SECOND   (999999999u)
#define ITVL_MAX_ISO_FRAC_SEC ITVL_MAX_SQL_FRAC_SEC

/* The maximal field length of an interval unit. The value is the maximal
   number of significant digits in a field. Different format has different
   length. For SQL format, the maximal length is 7, as the allowed maximal field
   is ITVL_MAX_SQL_DAY. It allows 7 significant digits.
   @note The leading zeros are not counted and ignored, e.g., the
   length of 00000213 is 3.
   */
#define ITVL_MAX_ISO_FIELD_LEN 9

/* The settings of minimal, maximal, and default YEAR precisions for
   YM_INTERVAL datatype */
#define ITVL_MIN_YEAR_PREC     0
#define ITVL_MAX_YEAR_PREC     4
#define ITVL_DEFAULT_YEAR_PREC 2

/* The settings of minimal, maximal, and default DAY precisions for
   DS_INTERVAL datatype */
#define ITVL_MIN_DAY_PREC     0
#define ITVL_MAX_DAY_PREC     7
#define ITVL_DEFAULT_DAY_PREC 2

/* The settings of minimal, maximal, and default SECOND precisions for
   DS_INTERVAL datatype */
#define ITVL_MIN_SECOND_PREC     0
#define ITVL_MAX_SECOND_PREC     6
#define ITVL_DEFAULT_SECOND_PREC 6

/* The maximal and minimal of interval values */
#define GS_MAX_YMINTERVAL ((interval_ym_t)(ITVL_MAX_SQL_YEAR * ITVL_MONTHS_PER_YEAR + ITVL_MAX_SQL_MONTH))
#define GS_MIN_YMINTERVAL (-(GS_MAX_YMINTERVAL))

#define GS_MAX_DSINTERVAL \
    ((interval_ds_t)(ITVL_MAX_SQL_DAY * ITVL_UNITS_PER_DAY         \
        + ITVL_MAX_SQL_HOUR * ITVL_UNITS_PER_HOUR                  \
        + ITVL_MAX_SQL_MINUTE * ITVL_UNITS_PER_MINUTE              \
        + ITVL_MAX_SQL_SECOND * ITVL_UNITS_PER_SECOND              \
        + ITVL_MAX_SQL_FRAC_SEC))

#define GS_MIN_DSINTERVAL (-(GS_MAX_DSINTERVAL))

#define CM_IS_VALID_DSINTERVAL(dsitvl) \
    (((dsitvl) >= GS_MIN_DSINTERVAL) && ((dsitvl) <= GS_MAX_DSINTERVAL))


/* addition/subtraction of two interval_ds_t, if overflow occurs, an error will be return; */
static inline status_t cm_dsinterval_add(interval_ds_t a, interval_ds_t b, interval_ds_t *res)
{
    if (a < GS_MIN_DSINTERVAL || a > GS_MAX_DSINTERVAL) {
        GS_THROW_ERROR_EX(ERR_ASSERT_ERROR, "GS_MIN_DSINTERVAL(%lld) <= a(%lld) <= GS_MAX_DSINTERVAL(%lld)",
                          GS_MIN_DSINTERVAL, a, GS_MAX_DSINTERVAL);
        return GS_ERROR;
    }
    if (b < GS_MIN_DSINTERVAL || b > GS_MAX_DSINTERVAL) {
        GS_THROW_ERROR_EX(ERR_ASSERT_ERROR, "GS_MIN_DSINTERVAL(%lld) <= b(%lld) <= GS_MAX_DSINTERVAL(%lld)",
                          GS_MIN_DSINTERVAL, b, GS_MAX_DSINTERVAL);
        return GS_ERROR;
    }

    *res = a + b;
    if (*res >= GS_MIN_DSINTERVAL && *res <= GS_MAX_DSINTERVAL) {
        return GS_SUCCESS;
    }

    GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "INTERVAL DAY TO SECOND");
    return GS_ERROR;
}

static inline status_t cm_dsinterval_sub(interval_ds_t a, interval_ds_t b, interval_ds_t *res)
{
    return cm_dsinterval_add(a, -b, res);
}

static inline status_t cm_tmstamp_add_dsinterval(timestamp_t ts, interval_ds_t dsitvl, timestamp_t *res)
{
    *res = ts + dsitvl;
    if (CM_IS_DATETIME_ADDTION_OVERFLOW(ts, dsitvl, *res)) {
        GS_SET_ERROR_TIMESTAMP_OVERFLOW();
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static inline status_t cm_date_add_dsinterval(date_t date, interval_ds_t dsitvl, date_t *res)
{
    *res = date + dsitvl;
    if (CM_IS_DATETIME_ADDTION_OVERFLOW(date, dsitvl, *res)) {
        GS_SET_ERROR_DATETIME_OVERFLOW();
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static inline status_t cm_dsinterval_add_date(interval_ds_t dsitvl, date_t date, date_t *res)
{
    return cm_date_add_dsinterval(date, dsitvl, res);
}

static inline status_t cm_date_sub_dsinterval(date_t date, interval_ds_t dsitvl, date_t *res)
{
    return cm_date_add_dsinterval(date, -dsitvl, res);
}

static inline status_t cm_dsinterval_add_tmstamp(interval_ds_t dsitvl, timestamp_t ts, timestamp_t *res)
{
    return cm_tmstamp_add_dsinterval(ts, dsitvl, res);
}

static inline status_t cm_tmstamp_sub_dsinterval(timestamp_t ts, interval_ds_t dsitvl, timestamp_t *res)
{
    return cm_tmstamp_add_dsinterval(ts, -dsitvl, res);
}

/* addition/subtraction of two interval_ym_t; */
static inline status_t cm_yminterval_add(interval_ym_t a, interval_ym_t b, interval_ym_t *res)
{
    if (a < GS_MIN_YMINTERVAL || a > GS_MAX_YMINTERVAL) {
        GS_THROW_ERROR_EX(ERR_ASSERT_ERROR, "GS_MIN_YMINTERVAL(%d) <= a(%d) <= GS_MAX_YMINTERVAL(%d)",
            GS_MIN_YMINTERVAL, a, GS_MAX_YMINTERVAL);
        return GS_ERROR;
    }
    if (b < GS_MIN_YMINTERVAL || b > GS_MAX_YMINTERVAL) {
        GS_THROW_ERROR_EX(ERR_ASSERT_ERROR, "GS_MIN_YMINTERVAL(%d) <= b(%d) <= GS_MAX_YMINTERVAL(%d)",
            GS_MIN_YMINTERVAL, b, GS_MAX_YMINTERVAL);
        return GS_ERROR;
    }

    *res = a + b;
    if (*res >= GS_MIN_YMINTERVAL && *res <= GS_MAX_YMINTERVAL) {
        return GS_SUCCESS;
    }

    GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "INTERVAL YEAR TO MONTH");
    return GS_ERROR;
}

static inline status_t cm_yminterval_sub(interval_ym_t a, interval_ym_t b, interval_ym_t *res)
{
    return cm_yminterval_add(a, -b, res);
}

status_t cm_yminterval_add_date(interval_ym_t ymitvl_input, date_t date, date_t *res);

static inline status_t cm_date_add_yminterval(date_t date, interval_ym_t ymitvl, date_t *res)
{
    return cm_yminterval_add_date(ymitvl, date, res);
}

static inline status_t cm_date_sub_yminterval(date_t date, interval_ym_t ymitvl, date_t *res)
{
    return cm_date_add_yminterval(date, -ymitvl, res);
}

static inline status_t cm_yminterval_add_tmstamp(interval_ym_t ymitvl, timestamp_t ts, timestamp_t *res)
{
    return cm_yminterval_add_date(ymitvl, *((date_t *)(&ts)), (date_t *)res);
}

static inline status_t cm_tmstamp_add_yminterval(timestamp_t ts, interval_ym_t ymitvl, timestamp_t *res)
{
    return cm_yminterval_add_tmstamp(ymitvl, ts, res);
}

static inline status_t cm_tmstamp_sub_yminterval(timestamp_t ts, interval_ym_t ymitvl, timestamp_t *res)
{
    return cm_tmstamp_add_yminterval(ts, -ymitvl, res);
}

status_t cm_text2yminterval(const text_t *text, interval_ym_t *itvl);
status_t cm_text2dsinterval(const text_t *text, interval_ds_t *itvl);
void cm_yminterval2text(interval_ym_t ymitvl, text_t *text);
void cm_yminterval2text_prec(interval_ym_t ymitvl, uint8 year_prec, text_t *text);
void cm_dsinterval2text(interval_ds_t dsitvl, text_t *text);
void cm_dsinterval2text_prec(interval_ds_t dsitvl, uint8 day_prec, uint8 sec_prec, text_t *text);
uint32 cm_yminterval2str(interval_ym_t ymitvl, char *str);
uint32 cm_dsinterval2str(interval_ds_t dsitvl, char *str, uint32 str_max_sz);
uint32 cm_yminterval2str_ex(interval_ym_t ymitvl, uint32 year_prec, char *str);
uint32 cm_dsinterval2str_ex(interval_ds_t dsitvl, uint32 day_prec, uint32 frac_prec, char *str, uint32 str_max_sz);
interval_unit_t cm_get_ymitvl_unit(const text_t *text);
interval_unit_t cm_get_dsitvl_unit(const text_t *text);
status_t cm_text2intvl_detail(const text_t *text, gs_type_t itype, interval_detail_t *idetail, uint32 fmt);
status_t cm_encode_yminterval(const interval_detail_t *idetail, interval_ym_t *itvl);
status_t cm_encode_dsinterval(const interval_detail_t *idetail, interval_ds_t *itvl);
void cm_decode_yminterval(interval_ym_t ymitvl_input, interval_detail_t *idetail);
void cm_decode_dsinterval(interval_ds_t dsitvl_input, interval_detail_t *idetail);

#define CM_CHECK_ITVL_FIELD(val, MAX_ISO_VALUE, field_name)                        \
    if (fabs((val)) >= (double)((MAX_ISO_VALUE) + 1)) {                            \
        GS_THROW_ERROR(ERR_INVALID_INTERVAL_FIELD, (field_name), (MAX_ISO_VALUE)); \
        return GS_ERROR;                                                           \
    }

static inline status_t cm_year2yminterval(double year, interval_ym_t *ymitvl)
{
    CM_POINTER(ymitvl);
    CM_CHECK_ITVL_FIELD(year, ITVL_MAX_ISO_YEAR, "YEAR");
    *ymitvl = (interval_ym_t)(round(year * ITVL_MONTHS_PER_YEAR));

    /* e.g  select numtoyminterval(-9999.99,'YEAR') from sys_dummy;
       Due to the function to support rounded now, if the unit is 'YEAR',
       the result of  numtoyminterval(-9999.99,'YEAR') will be -100000 which
       is out of range.Other unit of time do not exists such scenarios.
    */
    if ((fabs(*ymitvl) / ITVL_MONTHS_PER_YEAR) >= (ITVL_MAX_ISO_YEAR + 1)) {
        GS_THROW_ERROR(ERR_INVALID_INTERVAL_FIELD, "YEAR", (ITVL_MAX_ISO_YEAR));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static inline status_t cm_month2yminterval(double month, interval_ym_t *ymitvl)
{
    CM_POINTER(ymitvl);
    CM_CHECK_ITVL_FIELD(month, ITVL_MAX_ISO_MONTH, "MONTH");
    *ymitvl = (interval_ym_t)(round(month));
    return GS_SUCCESS;
}

static inline status_t cm_day2dsinterval(double day, interval_ds_t *dsitvl)
{
    CM_POINTER(dsitvl);
    CM_CHECK_ITVL_FIELD(day, ITVL_MAX_ISO_DAY, "DAY");
    *dsitvl = (interval_ds_t)(round(day * ITVL_UNITS_PER_DAY));
    return GS_SUCCESS;
}

static inline status_t cm_hour2dsinterval(double hour, interval_ds_t *dsitvl)
{
    CM_POINTER(dsitvl);
    CM_CHECK_ITVL_FIELD(hour, ITVL_MAX_ISO_HOUR, "HOUR");
    *dsitvl = (interval_ds_t)(round(hour * ITVL_UNITS_PER_HOUR));
    return GS_SUCCESS;
}

static inline status_t cm_minute2dsinterval(double minute, interval_ds_t *dsitvl)
{
    CM_POINTER(dsitvl);
    CM_CHECK_ITVL_FIELD(minute, ITVL_MAX_ISO_MINUTE, "MINUTE");
    *dsitvl = (interval_ds_t)(round(minute * ITVL_UNITS_PER_MINUTE));
    return GS_SUCCESS;
}

static inline status_t cm_second2dsinterval(double sec, interval_ds_t *dsitvl)
{
    CM_POINTER(dsitvl);
    CM_CHECK_ITVL_FIELD(sec, ITVL_MAX_ISO_SECOND, "SECOND");
    *dsitvl = (interval_ds_t)(round(sec * ITVL_UNITS_PER_SECOND));
    return GS_SUCCESS;
}

status_t cm_adjust_yminterval(interval_ym_t *ymitvl, uint32 year_prec);
status_t cm_adjust_dsinterval(interval_ds_t *dsitvl, uint32 day_prec, uint32 fsec_prec);

#ifdef __cplusplus
}
#endif

#endif  // end __CM_INTERVAL_H__
