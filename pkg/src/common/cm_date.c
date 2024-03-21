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
 * cm_date.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_date.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_common_module.h"
#include "cm_date.h"
#include "cm_decimal.h"
#include "cm_nls.h"
#include "cm_timer.h"

#define IS_MYSQL_NEW_TYPE(type) \
    (type == CT_TYPE_DATETIME_MYSQL || type == CT_TYPE_TIME_MYSQL || type == CT_TYPE_DATE_MYSQL)

uint16 g_month_days[2][12] = {
    { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
    { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
};

/* weekdays */
static text_t g_week_days[7] = {
    { "SUNDAY",    6 },
    { "MONDAY",    6 },
    { "TUESDAY",   7 },
    { "WEDNESDAY", 9 },
    { "THURSDAY",  8 },
    { "FRIDAY",    6 },
    { "SATURDAY",  8 }
};


/* months */
static text_t g_month_names[12] = {
    { "JANUARY",   7 },
    { "FEBRUARY",  8 },
    { "MARCH",     5 },
    { "APRIL",     5 },
    { "MAY",       3 },
    { "JUNE",      4 },
    { "JULY",      4 },
    { "AUGUST",    6 },
    { "SEPTEMBER", 9 },
    { "OCTOBER",   7 },
    { "NOVEMBER",  8 },
    { "DECEMBER",  8 }
};

static text_t g_month_roman_names[12] = {
    { "I",    1 },
    { "II",   2 },
    { "III",  3 },
    { "IV",   2 },
    { "V",    1 },
    { "VI",   2 },
    { "VII",  3 },
    { "VIII", 4 },
    { "IX",   2 },
    { "X",    1 },
    { "XI",   2 },
    { "XII",  3 }
};

const uint64 powers_of_10[20] = {1,
                               10,
                               100,
                               1000,
                               10000UL,
                               100000UL,
                               1000000UL,
                               10000000UL,
                               100000000ULL,
                               1000000000ULL,
                               10000000000ULL,
                               100000000000ULL,
                               1000000000000ULL,
                               10000000000000ULL,
                               100000000000000ULL,
                               1000000000000000ULL,
                               10000000000000000ULL,
                               100000000000000000ULL,
                               1000000000000000000ULL,
                               10000000000000000000ULL};

typedef enum g_date_time_mask {
    MASK_NONE = 0,
    MASK_YEAR = 0x0000001,
    MASK_MONTH = 0x0000002,
    MASK_DAY = 0x0000004,
    MASK_HOUR = 0x0000008,
    MASK_MINUTE = 0x0000010,
    MASK_SECOND = 0x0000020,
    MASK_USEC = 0x0000040,
    MASK_TZ_HOUR = 0x0000080,
    MASK_TZ_MINUTE = 0x0000100,
} date_time_mask_t;

static format_item_t g_formats[] = {
    {
        .name = { (char *)"%Y", 2 },
        .id = FMT_YEAR4,
        .fmask = MASK_YEAR,
        .placer = 4,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"%D", 2 },
        .id = FMT_DAY_OF_MONTH,
        .fmask = MASK_DAY,
        .placer = -1,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"%M", 2 },
        .id = FMT_MONTH_NAME,
        .fmask = MASK_MONTH,
        .placer = -1,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"%h", 2 },
        .id = FMT_HOUR_OF_DAY24,
        .fmask = MASK_HOUR,
        .placer = -1,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"%i", 2 },
        .id = FMT_MINUTE,
        .fmask = MASK_MINUTE,
        .placer = -1,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"%s", 2 },
        .id = FMT_SECOND,
        .fmask = MASK_SECOND,
        .placer = -1,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"%x", 2 },
        .id = FMT_YEAR4,
        .fmask = MASK_YEAR,
        .placer = 4,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)" ", 1 },
        .id = FMT_SPACE,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"-", 1 },
        .id = FMT_MINUS,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"\\", 1 },
        .id = FMT_SLASH,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"/", 1 },
        .id = FMT_BACK_SLASH,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)",", 1 },
        .id = FMT_COMMA,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)".", 1 },
        .id = FMT_DOT,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)";", 1 },
        .id = FMT_SEMI_COLON,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)":", 1 },
        .id = FMT_COLON,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"X", 1 },
        .id = FMT_X,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"\"", 1 },
        .id = FMT_DQ_TEXT,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"AM", 2 },
        .id = FMT_AM_INDICATOR,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CT_FALSE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"A.M.", 4 },
        .id = FMT_AM_INDICATOR,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CT_FALSE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"PM", 2 },
        .id = FMT_PM_INDICATOR,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CT_FALSE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"P.M.", 4 },
        .id = FMT_PM_INDICATOR,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CT_FALSE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"CC", 2 },
        .id = FMT_CENTURY,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CT_FALSE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"SCC", 3 },
        .id = FMT_CENTURY,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CT_FALSE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"DAY", 3 },
        .id = FMT_DAY_NAME,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CT_FALSE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"DY", 2 },
        .id = FMT_DAY_ABBR_NAME,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CT_FALSE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"DDD", 3 },
        .id = FMT_DAY_OF_YEAR,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CT_FALSE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"DD", 2 },
        .id = FMT_DAY_OF_MONTH,
        .fmask = MASK_DAY,
        .placer = -1,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"D", 1 },
        .id = FMT_DAY_OF_WEEK,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CT_FALSE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"FF1", 3 },
        .id = FMT_FRAC_SECOND1,
        .fmask = MASK_USEC,
        .placer = 1,
        .reversible = CT_TRUE,
        .dt_used = CT_FALSE,
    },
    {
        .name = { (char *)"FF2", 3 },
        .id = FMT_FRAC_SECOND2,
        .fmask = MASK_USEC,
        .placer = 2,
        .reversible = CT_TRUE,
        .dt_used = CT_FALSE,
    },
    {
        .name = { (char *)"FF3", 3 },
        .id = FMT_FRAC_SECOND3,
        .fmask = MASK_USEC,
        .placer = 3,
        .reversible = CT_TRUE,
        .dt_used = CT_FALSE,
    },
    {
        .name = { (char *)"FF4", 3 },
        .id = FMT_FRAC_SECOND4,
        .fmask = MASK_USEC,
        .placer = 4,
        .reversible = CT_TRUE,
        .dt_used = CT_FALSE,
    },
    {
        .name = { (char *)"FF5", 3 },
        .id = FMT_FRAC_SECOND5,
        .fmask = MASK_USEC,
        .placer = 5,
        .reversible = CT_TRUE,
        .dt_used = CT_FALSE,
    },
    {
        .name = { (char *)"FF6", 3 },
        .id = FMT_FRAC_SECOND6,
        .fmask = MASK_USEC,
        .placer = 6,
        .reversible = CT_TRUE,
        .dt_used = CT_FALSE,
    },
    {
        .name = { (char *)"FF", 2 },
        .id = FMT_FRAC_SEC_VAR_LEN,
        .fmask = MASK_USEC,
        .placer = 6,
        .reversible = CT_TRUE,
        .dt_used = CT_FALSE,
    }, /* FF must be after FF3, FF6, FF9 */
    {
        .name = { (char *)"HH12", 4 },
        .id = FMT_HOUR_OF_DAY12,
        .fmask = MASK_HOUR,
        .placer = -1,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"HH24", 4 },
        .id = FMT_HOUR_OF_DAY24,
        .fmask = MASK_HOUR,
        .placer = -1,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"HH", 2 },
        .id = FMT_HOUR_OF_DAY12,
        .fmask = MASK_HOUR,
        .placer = -1,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"MI", 2 },
        .id = FMT_MINUTE,
        .fmask = MASK_MINUTE,
        .placer = -1,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"MM", 2 },
        .id = FMT_MONTH,
        .fmask = MASK_MONTH,
        .placer = -1,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"RM", 2 },
        .id = FMT_MONTH_RM,
        .fmask = MASK_MONTH,
        .placer = -1,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"MONTH", 5 },
        .id = FMT_MONTH_NAME,
        .fmask = MASK_MONTH,
        .placer = -1,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"MON", 3 },
        .id = FMT_MONTH_ABBR_NAME,
        .fmask = MASK_MONTH,
        .placer = -1,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"Q", 1 },
        .id = FMT_QUARTER,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CT_FALSE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"SSSSS", 5 },
        .id = FMT_SECOND_PASS,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CT_FALSE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"SS", 2 },
        .id = FMT_SECOND,
        .fmask = MASK_SECOND,
        .placer = -1,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"WW", 2 },
        .id = FMT_WEEK_OF_YEAR,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CT_FALSE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"W", 1 },
        .id = FMT_WEEK_OF_MONTH,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CT_FALSE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"YYYY", 4 },
        .id = FMT_YEAR4,
        .fmask = MASK_YEAR,
        .placer = 4,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"YYY", 3 },
        .id = FMT_YEAR3,
        .fmask = MASK_NONE,
        .placer = 3,
        .reversible = CT_FALSE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"YY", 2 },
        .id = FMT_YEAR2,
        .fmask = MASK_NONE,
        .placer = 2,
        .reversible = CT_FALSE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"Y", 1 },
        .id = FMT_YEAR1,
        .fmask = MASK_NONE,
        .placer = 1,
        .reversible = CT_FALSE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"TZH", 3 },
        .id = FMT_TZ_HOUR,
        .fmask = MASK_TZ_HOUR,
        .placer = -1,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
    {
        .name = { (char *)"TZM", 3 },
        .id = FMT_TZ_MINUTE,
        .fmask = MASK_TZ_MINUTE,
        .placer = -1,
        .reversible = CT_TRUE,
        .dt_used = CT_TRUE,
    },
};

#define DATE_FORMAT_COUNT (sizeof(g_formats) / sizeof(format_item_t))
#define EVEN_NUM 2

#ifdef __cplusplus
extern "C" {
#endif

static void cm_text2date_init(date_detail_t *datetime)
{
    datetime->year = CM_MIN_YEAR;
    datetime->mon = 1;
    datetime->day = 1;
    datetime->hour = 0;
    datetime->min = 0;
    datetime->sec = 0;
    datetime->millisec = 0;
    datetime->microsec = 0;
    datetime->nanosec = 0;

    return ;
}

static void cm_set_all_zero_detail(date_detail_t *detail)
{
    detail->year = 0;
    detail->mon = 0;
    detail->day = 0;
    detail->hour = 0;
    detail->min = 0;
    detail->sec = 0;
    detail->millisec = 0;
    detail->microsec = 0;
    detail->nanosec = 0;

    return ;
}

static bool32 cm_is_all_zero_time(const date_detail_t *datetime)
{
    if (datetime->year == 0 && datetime->mon == 0 && datetime->day == 0 && datetime->hour == 0 && datetime->min == 0 &&
        datetime->sec == 0 &&  datetime->millisec == 0 && datetime->microsec == 0 && datetime->nanosec == 0) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

static bool32 cm_check_valid_zero_time(date_detail_t *datetime)
{
    if (cm_is_all_zero_time(datetime)) {
        return CT_TRUE;
    }
    if (datetime->day == 0 || datetime->mon == 0 || datetime->year == 0) {
        return CT_FALSE;
    }
    return CT_TRUE;
}

void cm_now_detail(date_detail_t *detail)
{
#ifdef WIN32
    SYSTEMTIME sys_time;
    GetLocalTime(&sys_time);

    CM_POINTER(detail);
    detail->year = (uint16)sys_time.wYear;
    detail->mon = (uint8)sys_time.wMonth;
    detail->day = (uint8)sys_time.wDay;
    detail->hour = (uint8)sys_time.wHour;
    detail->min = (uint8)sys_time.wMinute;
    detail->sec = (uint8)sys_time.wSecond;
    detail->millisec = (uint16)sys_time.wMilliseconds;
    detail->microsec = 0;
    detail->nanosec = 0;
#else
    time_t t_var;
    struct timeval tv;
    struct tm ut;

    CM_POINTER(detail);

    gettimeofday(&tv, NULL);
    t_var = tv.tv_sec;
    localtime_r(&t_var, &ut);

    detail->year = (uint16)ut.tm_year + 1900;
    detail->mon = (uint8)ut.tm_mon + 1;
    detail->day = (uint8)ut.tm_mday;
    detail->hour = (uint8)ut.tm_hour;
    detail->min = (uint8)ut.tm_min;
    detail->sec = (uint8)ut.tm_sec;
    detail->millisec = (uint32)((tv.tv_usec) / 1000);
    detail->microsec = (uint16)(tv.tv_usec % 1000);
    detail->nanosec = 0;
#endif
}

/* "year -> number of days before January 1st of year" */
static inline int32 days_before_year(int32 year_input)
{
    int32 year = year_input;
    --year;
    return year * 365 + year / 4 - year / 100 + year / 400;
}

static inline int32 total_days_before_date(const date_detail_t *detail)
{
    int32 i;
    int32 total_days;

    CM_POINTER(detail);

    // compute total days
    total_days = days_before_year((int32)detail->year) - CM_BASELINE_DAY;
    uint16 *day_tab = (uint16 *)g_month_days[IS_LEAP_YEAR(detail->year)];
    for (i = 0; i < (int32)(detail->mon - 1); i++) {
        total_days += (int32)day_tab[i];
    }
    total_days += detail->day;

    return total_days;
}

date_t cm_encode_date(const date_detail_t *detail)
{
    int32 total_days;
    date_t date_tmp;

    CM_POINTER(detail);  // assert

    // only support all zero datetime
    if (cm_is_all_zero_time(detail)) {
        return CM_ALL_ZERO_DATETIME;
    }

    CM_ASSERT(CM_IS_VALID_YEAR(detail->year));
    CM_ASSERT(detail->mon >= 1 && detail->mon <= 12);
    CM_ASSERT(detail->day >= 1 && detail->day <= 31);
    CM_ASSERT(detail->hour <= 23);
    CM_ASSERT(detail->min <= 59);
    CM_ASSERT(detail->sec <= 59);
    CM_ASSERT(detail->microsec <= 999);
    CM_ASSERT(detail->millisec <= 999);

    // compute total days
    total_days = total_days_before_date(detail);

    // encode the date into an integer with 1 nanosecond as the the minimum unit
    date_tmp = (int64)total_days * SECONDS_PER_DAY;
    date_tmp += (uint32)detail->hour * SECONDS_PER_HOUR;
    date_tmp += (uint32)detail->min * SECONDS_PER_MIN;
    date_tmp += detail->sec;
    date_tmp = date_tmp * MILLISECS_PER_SECOND + detail->millisec;
    date_tmp = date_tmp * MICROSECS_PER_MILLISEC + detail->microsec;

    return date_tmp;
}
bool32 cm_str2week(text_t *value, uint8 *week)
{
    uint8 day_number_of_week = (uint8)sizeof(g_week_days) / sizeof(text_t);
    for (uint8 i = 0; i < day_number_of_week; i++) {
        if (cm_text_str_contain_equal_ins(value, g_week_days[i].str, 3)) {
            *week = i;
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}
void cm_encode_timestamp_tz(const date_detail_t *detail, timestamp_tz_t *tstz)
{
    /* get timesatmp */
    tstz->tstamp = cm_encode_date(detail);

    /* get tz_offset */
    tstz->tz_offset = detail->tz_offset;

    return;
}

#define DAYS_1   365
#define DAYS_4   (DAYS_1 * 4 + 1)
#define DAYS_100 (DAYS_4 * 25 - 1)
#define DAYS_400 (DAYS_100 * 4 + 1)

static inline void cm_decode_leap(date_detail_t *detail, int32 *d)
{
    uint32 hundred_count;
    int32 days = *d;

    while (days >= DAYS_400) {
        detail->year += 400;
        days -= DAYS_400;
    }

    for (hundred_count = 1; days >= DAYS_100 && hundred_count < 4; hundred_count++) {
        detail->year += 100;
        days -= DAYS_100;
    }

    while (days >= DAYS_4) {
        detail->year += 4;
        days -= DAYS_4;
    }

    while (days > DAYS_1) {
        if (IS_LEAP_YEAR(detail->year)) {
            days--;
        }

        detail->year++;
        days -= DAYS_1;
    }

    *d = days;
}

void cm_decode_date(date_t date_input, date_detail_t *detail)
{
    int32 i;
    int32 days;
    uint16 *day_tab = NULL;
    int64 time;
    int64 date = date_input;

    CM_POINTER(detail);

    if (date == CM_ALL_ZERO_DATETIME) {
        cm_set_all_zero_detail(detail);
        return;
    }

    // decode time
    time = date;
    date /= UNITS_PER_DAY;
    time -= date * UNITS_PER_DAY;

    if (time < 0) {
        time += UNITS_PER_DAY;
        date -= 1;
    }

    detail->microsec = (uint16)(time % MICROSECS_PER_MILLISEC);
    time /= MICROSECS_PER_MILLISEC;

    detail->millisec = (uint16)(time % MILLISECS_PER_SECOND);
    time /= MILLISECS_PER_SECOND;

    detail->hour = (int16)(time / SECONDS_PER_HOUR);
    time -= (uint32)detail->hour * SECONDS_PER_HOUR;

    detail->min = (uint8)(time / SECONDS_PER_MIN);
    time -= (uint32)detail->min * SECONDS_PER_MIN;

    detail->sec = (uint8)time;

    // "days -> (year, month, day), considering 01-Jan-0001 as day 1."
    days = (int32)(date + CM_BASELINE_DAY);  // number of days since 1.1.1 to the date
    detail->year = 1;

    cm_decode_leap(detail, &days);

    if (days == 0) {
        detail->year--;
        detail->mon = 12;
        detail->day = 31;
    } else {
        day_tab = g_month_days[IS_LEAP_YEAR(detail->year)];
        detail->mon = 1;

        i = 0;
        while (days > (int32)day_tab[i]) {
            days -= (int32)day_tab[i];
            i++;
        }

        detail->mon = (uint8)(detail->mon + i);
        detail->day = (uint8)(days);
    }
}

date_t cm_now(void)
{
    date_t dt = CM_UNIX_EPOCH + CM_HOST_TIMEZONE;
    timeval_t tv;

    (void)cm_gettimeofday(&tv);
    dt += ((int64)tv.tv_sec * MICROSECS_PER_SECOND + tv.tv_usec);
    return dt;
}

date_t cm_utc_now(void)
{
    date_t dt = CM_UNIX_EPOCH;
    timeval_t tv;
    (void)cm_gettimeofday(&tv);
    dt += ((int64)tv.tv_sec * MICROSECS_PER_SECOND + tv.tv_usec);
    return dt;
}

/* Get a current date without fractional seconds */
date_t cm_date_now(void)
{
    date_t dt = CM_UNIX_EPOCH + CM_HOST_TIMEZONE;
    timeval_t tv;

    (void)cm_gettimeofday(&tv);
    dt += ((int64)tv.tv_sec * MICROSECS_PER_SECOND);
    return dt;
}

/* time INTERVAL between os start time and now */
date_t cm_monotonic_now(void)
{
#ifndef WIN32
    struct timespec signal_tv;
    date_t dt;
    (void)clock_gettime(CLOCK_MONOTONIC, &signal_tv);
    dt = ((int64)signal_tv.tv_sec * MICROSECS_PER_SECOND + signal_tv.tv_nsec / 1000);
    return dt;
#else
    return cm_now();
#endif
}

time_t cm_current_time(void)
{
    return time(NULL);
}

void cm_decode_time(time_t time, date_detail_t *detail)
{
#ifdef WIN32
    const struct tm *now_time_ptr;
    now_time_ptr = localtime(&time);
    detail->year = (uint16)now_time_ptr->tm_year + 1900;
    detail->mon = (uint8)now_time_ptr->tm_mon + 1;
    detail->day = (uint8)now_time_ptr->tm_mday;
    detail->hour = (uint8)now_time_ptr->tm_hour;
    detail->min = (uint8)now_time_ptr->tm_min;
    detail->sec = (uint8)now_time_ptr->tm_sec;

#else
    struct tm now_time;
    (void)localtime_r(&time, &now_time);
    detail->year = (uint16)now_time.tm_year + 1900;
    detail->mon = (uint8)now_time.tm_mon + 1;
    detail->day = (uint8)now_time.tm_mday;
    detail->hour = (uint8)now_time.tm_hour;
    detail->min = (uint8)now_time.tm_min;
    detail->sec = (uint8)now_time.tm_sec;

#endif

    detail->millisec = 0;
    detail->microsec = 0;
    detail->nanosec = 0;
}

time_t cm_encode_time(date_detail_t *detail)
{
    struct tm now_time;

    now_time.tm_year = (int)detail->year - 1900;
    now_time.tm_mon = (int)detail->mon - 1;
    now_time.tm_mday = (int)detail->day;
    now_time.tm_hour = (int)detail->hour;
    now_time.tm_min = (int)detail->min;
    now_time.tm_sec = (int)detail->sec;
    now_time.tm_isdst = 0;

    return mktime(&now_time);
}

void cm_decode_ora_date(date_t date, uint8 *ora_date)
{
    date_detail_t date_detail;

    cm_decode_date(date, &date_detail);

    ora_date[0] = (uint8)(date_detail.year / 100 + 100);
    ora_date[1] = date_detail.year % 100 + 100;
    ora_date[2] = date_detail.mon;
    ora_date[3] = date_detail.day;
    ora_date[4] = date_detail.hour + 1;
    ora_date[5] = date_detail.min + 1;
    ora_date[6] = date_detail.sec + 1;
}

date_t cm_encode_ora_date(uint8 *ora_date)
{
    date_detail_t date_detail;

    date_detail.year = (ora_date[0] - 100) * 100 + (ora_date[1] - 100);
    date_detail.mon = ora_date[2];
    date_detail.day = ora_date[3];
    date_detail.hour = ora_date[4] - 1;
    date_detail.min = ora_date[5] - 1;
    date_detail.sec = ora_date[6] - 1;
    date_detail.millisec = 0;
    date_detail.microsec = 0;
    date_detail.nanosec = 0;

    return cm_encode_date(&date_detail);
}

#define CT_SET_DATETIME_FMT_ERROR \
    CT_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "datetime")

/*
 * Fetch the double-quote-text item from format text, and extract the text into extra
 */
static inline status_t cm_fetch_dqtext_item(text_t *fmt, text_t *extra, bool32 do_trim)
{
    int32 pos;

    CM_REMOVE_FIRST(fmt);  // remove the first quote "
    pos = cm_text_chr(fmt, '"');
    if (pos < 0) {
        CT_SET_DATETIME_FMT_ERROR;
        return CT_ERROR;
    }

    extra->str = fmt->str;
    extra->len = (uint32)pos;
    if (do_trim) {
        cm_trim_text(extra);
    }
    CM_REMOVE_FIRST_N(fmt, pos + 1);
    return CT_SUCCESS;
}

/**
 * extra -- the extra information for the format_item
 */
static inline status_t cm_fetch_format_item(text_t *fmt, format_item_t **item, text_t *extra, bool32 do_trim)
{
    uint32 i;
    text_t cmp_text;

    CM_POINTER(fmt);

    if (do_trim) {
        cm_trim_text(fmt);
    }
    cmp_text.str = fmt->str;

    for (i = 0; i < DATE_FORMAT_COUNT; i++) {
        cmp_text.len = MIN(g_formats[i].name.len, fmt->len);

        if (cm_text_equal_ins(&g_formats[i].name, &cmp_text)) {
            *item = &g_formats[i];
            if ((*item)->id == FMT_DQ_TEXT) {
                return cm_fetch_dqtext_item(fmt, extra, do_trim);
            }

            CM_REMOVE_FIRST_N(fmt, cmp_text.len);
            return CT_SUCCESS;
        }
    }

    CT_SET_DATETIME_FMT_ERROR;
    return CT_ERROR;
}

#define CM_YEARS_PER_CMNTURY 100u
/* compute the century of a date_detail */
static inline uint32 cm_get_century(const date_detail_t *detail)
{
    return ((uint32)detail->year - 1) / CM_YEARS_PER_CMNTURY + 1;
}

#define FORMAT_ITEM_BUFFER_SIZE 16

static inline status_t cm_append_date_text(const date_detail_t *detail, const date_detail_ex_t *detail_ex,
                                           format_item_t *item, text_t *fmt_extra,
                                           uint32 prec, text_t *date_text, uint32 max_len)
{
    char item_str[FORMAT_ITEM_BUFFER_SIZE] = { 0 };
    text_t append_text = { .str = NULL, .len = 0 };
    CM_POINTER4(detail, detail_ex, item, date_text);
    uint32 frac;
    uint8 hh12_value = 0;

    int32 tz_hour, tz_minute;

    switch (item->id) {
        case FMT_AM_INDICATOR:
        case FMT_PM_INDICATOR:
            append_text.str = detail_ex->is_am ? (char *)"AM" : (char *)"PM";
            append_text.len = 2;
            break;

        case FMT_DQ_TEXT:
            append_text = *fmt_extra;
            break;

        case FMT_DOT:
        case FMT_SPACE:
        case FMT_MINUS:
        case FMT_SLASH:
        case FMT_BACK_SLASH:
        case FMT_COMMA:
        case FMT_SEMI_COLON:
        case FMT_COLON:
            append_text = item->name;
            break;

        case FMT_X:
            append_text.str = (char *)".";
            append_text.len = 1;
            break;

        case FMT_DAY_NAME:
            append_text = g_week_days[detail_ex->day_of_week];
            break;

        case FMT_DAY_ABBR_NAME:
            append_text.str = g_week_days[detail_ex->day_of_week].str;
            append_text.len = 3; /* for abbreviation, the length is 3 */
            break;

        case FMT_MONTH_ABBR_NAME:
            append_text.str = g_month_names[detail->mon - 1].str;
            append_text.len = 3;
            break;

        case FMT_MONTH_RM:
            append_text = g_month_roman_names[detail->mon - 1];
            break;

        case FMT_MONTH_NAME:
            append_text = g_month_names[detail->mon - 1];
            break;

        case FMT_YEAR1:
        case FMT_YEAR2:
        case FMT_YEAR3:
        case FMT_YEAR4:
            PRTS_RETURN_IFERR(snprintf_s(item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1,
                "%04u", detail->year));
            CM_ASSERT(item->placer > 0 && item->placer <= 4);
            append_text.len = (uint32)item->placer;
            append_text.str = item_str + (4 - item->placer);
            break;

        case FMT_CENTURY:
            PRTS_RETURN_IFERR(snprintf_s(item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1, "%02u",
                                         cm_get_century(detail)));
            break;

        case FMT_DAY_OF_WEEK:
            PRTS_RETURN_IFERR(snprintf_s(item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1, "%d",
                                         detail_ex->day_of_week + 1));
            break;

        case FMT_HOUR_OF_DAY12:
            if (detail->hour == 0) {
                hh12_value = 12;
            } else if (detail->hour > 12) {
                hh12_value = detail->hour - 12;
            } else {
                hh12_value = detail->hour;
            }
            PRTS_RETURN_IFERR(snprintf_s(item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1,
                                         "%02u", hh12_value));
            break;

        case FMT_HOUR_OF_DAY24:
            PRTS_RETURN_IFERR(snprintf_s(item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1,
                                         "%02d", detail->hour));
            break;

        case FMT_QUARTER:
            PRTS_RETURN_IFERR(snprintf_s(item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1,
                                         "%u", detail_ex->quarter));
            break;

        case FMT_SECOND:
            PRTS_RETURN_IFERR(snprintf_s(item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1,
                                         "%02u", detail->sec));
            break;

        case FMT_SECOND_PASS:
            PRTS_RETURN_IFERR(snprintf_s(item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1,
                                         "%05u", detail_ex->seconds));
            break;

        case FMT_WEEK_OF_YEAR:
            PRTS_RETURN_IFERR(snprintf_s(item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1,
                                         "%02u", detail_ex->week));
            break;

        case FMT_WEEK_OF_MONTH:
            PRTS_RETURN_IFERR(snprintf_s(item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1, "%d",
                                         (detail->day / 7) + 1));
            break;

        case FMT_DAY_OF_MONTH:
            PRTS_RETURN_IFERR(snprintf_s(item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1, "%02u",
                                         (detail->day)));
            break;

        case FMT_DAY_OF_YEAR:
            PRTS_RETURN_IFERR(snprintf_s(item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1, "%03u",
                                         detail_ex->day_of_year));
            break;

        case FMT_FRAC_SECOND1:
        case FMT_FRAC_SECOND2:
        case FMT_FRAC_SECOND3:
            PRTS_RETURN_IFERR(snprintf_s(item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1, "%03u",
                                         detail->millisec));
            CM_ASSERT(item->placer > 0 && item->placer <= 3);
            append_text.str = item_str;
            append_text.len = (uint32)item->placer;
            break;

        case FMT_FRAC_SECOND4:
        case FMT_FRAC_SECOND5:
        case FMT_FRAC_SECOND6:
            frac = (uint32)detail->millisec * MICROSECS_PER_MILLISEC + detail->microsec;
            PRTS_RETURN_IFERR(snprintf_s(item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1, "%06u",
                                         frac));
            CM_ASSERT(item->placer >= 4 && item->placer <= 6);
            append_text.str = item_str;
            append_text.len = (uint32)item->placer;
            break;

        case FMT_FRAC_SEC_VAR_LEN:
            if (prec == 0) {
                /* remove last '.' */
                if (date_text->len > 0 && date_text->str[date_text->len - 1] == '.') {
                    date_text->len--;
                }
                return CT_SUCCESS;
            }

            frac = (uint32)detail->millisec * MICROSECS_PER_MILLISEC + detail->microsec;
            PRTS_RETURN_IFERR(snprintf_s(item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1, "%06u",
                                         frac));
            CM_ASSERT(prec <= CT_MAX_DATETIME_PRECISION);
            append_text.str = item_str;
            append_text.len = prec;
            break;

        case FMT_MINUTE:
            PRTS_RETURN_IFERR(snprintf_s(item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1,
                                         "%02u", detail->min));
            break;

        case FMT_MONTH:
            PRTS_RETURN_IFERR(snprintf_s(item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1,
                                         "%02u", detail->mon));
            break;

        case FMT_TZ_HOUR:
            tz_hour = TIMEZONE_GET_HOUR(detail->tz_offset);
            PRTS_RETURN_IFERR(snprintf_s(item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1, "%+03d",
                                         tz_hour));
            break;

        case FMT_TZ_MINUTE:
            tz_minute = TIMEZONE_GET_MINUTE(detail->tz_offset);
            PRTS_RETURN_IFERR(snprintf_s(item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1, "%02d",
                                         tz_minute));
            break;

        default:
            return CT_SUCCESS;
    }

    if (append_text.str == NULL) {
        return cm_concat_string(date_text, max_len, item_str);
    }

    cm_concat_text(date_text, max_len, &append_text);
    return CT_SUCCESS;
}

static uint32 cm_get_day_of_year(const date_detail_t *detail)
{
    uint32 days;
    uint32 i;
    CM_POINTER(detail);

    if (cm_is_all_zero_time(detail)) {
        days = 0;
        return days;
    }

    uint16 *day_tab = (uint16 *)g_month_days[IS_LEAP_YEAR(detail->year)];
    days = 0;

    for (i = 0; i < (uint32)detail->mon - 1; i++) {
        days += day_tab[i];
    }

    days += (uint32)detail->day;
    return days;
}

#define CM_DAYS_PER_WEEK 7
/* week start with SATURDAY, day of 2001-01-01 is MONDAY */
static inline int32 cm_get_day_of_week(const date_detail_t *detail)
{
    int32 day_of_week = total_days_before_date(detail) + CM_BASELINE_DAY;

    day_of_week %= CM_DAYS_PER_WEEK;
    if (day_of_week < 0) {
        day_of_week += CM_DAYS_PER_WEEK;
    }

    CM_ASSERT(day_of_week >= 0 && day_of_week < CM_DAYS_PER_WEEK);
    return day_of_week;
}

void cm_get_detail_ex(const date_detail_t *detail, date_detail_ex_t *detail_ex)
{
    CM_POINTER2(detail, detail_ex);

    detail_ex->day_of_week = (uint8)cm_get_day_of_week(detail);
    detail_ex->is_am = (bool32)(detail->hour < 12);
    detail_ex->quarter = (uint8)((detail->mon - 1) / 3 + 1);
    detail_ex->day_of_year = (uint16)cm_get_day_of_year(detail);
    detail_ex->week = (uint8)((detail_ex->day_of_year - 1) / 7 + 1);
    detail_ex->seconds = (uint32)(detail->hour * 3600 + detail->min * 60 + detail->sec);
}

static status_t cm_detail2text(date_detail_t *detail, text_t *fmt, uint32 precision, text_t *text,
                               uint32 max_len)
{
    date_detail_ex_t detail_ex;
    format_item_t *item = NULL;
    text_t fmt_extra = { .str = NULL, .len = 0 };

    CM_POINTER3(detail, fmt, text);
    cm_get_detail_ex(detail, &detail_ex);

    text->len = 0;

    while (fmt->len > 0) {
        if (cm_fetch_format_item(fmt, &item, &fmt_extra, CT_FALSE) != CT_SUCCESS) {
            return CT_ERROR;
        }

        /* check fmt */
        if ((!cm_validate_timezone(detail->tz_offset)) && (item->id == FMT_TZ_HOUR || item->id == FMT_TZ_MINUTE)) {
            CT_SET_DATETIME_FMT_ERROR;
            return CT_ERROR;
        }

        if (detail->day == 0 && (item->id == FMT_DAY_NAME || item->id == FMT_DAY_ABBR_NAME)) {
            CT_SET_DATETIME_FMT_ERROR;
            return CT_ERROR;
        }

        if (detail->mon == 0 &&
            (item->id == FMT_MONTH_ABBR_NAME || item->id == FMT_MONTH_RM || item->id == FMT_MONTH_NAME)) {
            CT_SET_DATETIME_FMT_ERROR;
            return CT_ERROR;
        }

        CT_RETURN_IFERR(cm_append_date_text(detail, &detail_ex, item,
                                            &fmt_extra, precision, text, max_len));
    }

    CM_NULL_TERM(text);
    return CT_SUCCESS;
}

status_t cm_verify_date_fmt(const text_t *fmt)
{
    format_item_t *fmt_item = NULL;
    uint32 mask = 0;
    text_t fmt_extra;
    text_t fmt_text = *fmt;

    while (fmt_text.len > 0) {
        if (cm_fetch_format_item(&fmt_text, &fmt_item, &fmt_extra, CT_FALSE) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_UNRECOGNIZED_FORMAT_ERROR);
            return CT_ERROR;
        }

        if (!fmt_item->reversible || !fmt_item->dt_used) {
            CT_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "date");
            return CT_ERROR;
        }

        if ((mask & fmt_item->fmask) != 0) {
            CT_THROW_ERROR(ERR_MUTIPLE_FORMAT_ERROR);
            return CT_ERROR;
        }
        mask |= fmt_item->fmask;
    }

    return CT_SUCCESS;
}

status_t cm_verify_timestamp_fmt(const text_t *fmt)
{
    format_item_t *fmt_item = NULL;
    uint32 mask = 0;
    text_t fmt_extra;
    text_t fmt_text = *fmt;

    while (fmt_text.len > 0) {
        if (cm_fetch_format_item(&fmt_text, &fmt_item, &fmt_extra, CT_FALSE) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_UNRECOGNIZED_FORMAT_ERROR);
            return CT_ERROR;
        }

        if (!fmt_item->reversible) {
            CT_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "timestamp");
            return CT_ERROR;
        }

        if ((mask & fmt_item->fmask) != 0) {
            CT_THROW_ERROR(ERR_MUTIPLE_FORMAT_ERROR);
            return CT_ERROR;
        }
        mask |= fmt_item->fmask;
    }

    return CT_SUCCESS;
}

status_t cm_date2text_ex(date_t date, text_t *fmt, uint32 precision, text_t *text, uint32 max_len)
{
    date_detail_t detail;
    text_t format_text;

    CM_POINTER(text);
    cm_decode_date(date, &detail);

    if (fmt == NULL || fmt->str == NULL) {
        cm_default_nls_geter(NLS_DATE_FORMAT, &format_text);
    } else {
        format_text = *fmt;
    }
    return cm_detail2text(&detail, &format_text, precision, text, max_len);
}

status_t cm_timestamp2text_ex(timestamp_t ts, text_t *fmt, uint32 precision, text_t *text,
                              uint32 max_len)
{
    date_detail_t detail;
    text_t format_text;

    CM_POINTER(text);
    cm_decode_date(ts, &detail);

    if (fmt == NULL || fmt->str == NULL) {
        cm_default_nls_geter(NLS_TIMESTAMP_FORMAT, &format_text);
    } else {
        format_text = *fmt;
    }

    return cm_detail2text(&detail, &format_text, precision, text, max_len);
}

status_t cm_timestamp_tz2text_ex(timestamp_tz_t *tstz, text_t *fmt, uint32 precision, text_t *text,
                                 uint32 max_len)
{
    date_detail_t detail;
    text_t format_text;

    CM_POINTER(text);
    cm_decode_date(tstz->tstamp, &detail);

    detail.tz_offset = tstz->tz_offset;

    if (fmt == NULL || fmt->str == NULL) {
        cm_default_nls_geter(NLS_TIMESTAMP_FORMAT, &format_text);
    } else {
        format_text = *fmt;
    }

    return cm_detail2text(&detail, &format_text, precision, text, max_len);
}

status_t cm_time2text(time_t time, text_t *fmt, text_t *text, uint32 max_len)
{
    date_detail_t detail;
    text_t format_text;

    CM_POINTER2(fmt, text);
    cm_decode_time(time, &detail);

    if (fmt == NULL || fmt->str == NULL) {
        cm_default_nls_geter(NLS_DATE_FORMAT, &format_text);
    } else {
        format_text = *fmt;
    }

    return cm_detail2text(&detail, &format_text, CT_MAX_DATETIME_PRECISION, text, max_len);
}

date_t cm_time2date(time_t time)
{
    date_detail_t detail;

    cm_decode_time(time, &detail);
    return cm_encode_date(&detail);
}

time_t cm_date2time(date_t date)
{
    date_detail_t detail;

    cm_decode_date(date, &detail);
    return cm_encode_time(&detail);
}

date_t cm_timestamp2date(date_t date_input)
{
    int64 time;
    uint16 millisec, microsec;
    int64 date = date_input;

    /* according to cm_decode_date */
    time = date;
    date -= (date / UNITS_PER_DAY) * UNITS_PER_DAY;
    if (date < 0) {
        date += UNITS_PER_DAY;
    }

    microsec = (uint16)(date % MICROSECS_PER_MILLISEC);
    millisec = (uint16)((date / MICROSECS_PER_MILLISEC) % MILLISECS_PER_SECOND);

    return (time - millisec * MICROSECS_PER_MILLISEC - microsec);
}

static inline int64 cm_scn_delta(void)
{
    return CM_UNIX_EPOCH + CM_HOST_TIMEZONE;
}

void cm_date2timeval(date_t date, struct timeval *val)
{
    int64 value = date - cm_scn_delta();
    val->tv_sec = (long)(value / 1000000);
    val->tv_usec = (long)(value % 1000000);
}

date_t cm_timeval2date(struct timeval tv)
{
    date_t dt = cm_scn_delta();
    dt += ((int64)tv.tv_sec * MICROSECS_PER_SECOND + tv.tv_usec);
    return dt;
}

/* get the date without fractional seconds from timeval */
date_t cm_timeval2realdate(struct timeval tv)
{
    date_t dt = cm_scn_delta();
    dt += ((int64)tv.tv_sec * MICROSECS_PER_SECOND);
    return dt;
}

/**
 * convert time_t to str
 * @param time, format, string(out)
 */
status_t cm_time2str(time_t time, const char *fmt, char *str, uint32 str_max_size)
{
    text_t fmt_text, time_text;
    cm_str2text((char *)fmt, &fmt_text);
    time_text.str = str;
    time_text.len = 0;

    return cm_time2text(time, &fmt_text, &time_text, str_max_size);
}

static status_t cm_get_month_by_name(text_t *date_text, uint32 *mask, uint8 *mon)
{
    text_t cmp_text;
    CM_POINTER3(date_text, mask, mon);

    if ((*mask & MASK_MONTH) != 0) {
        return CT_ERROR;
    }

    if (date_text->len < 3) {  // min length of name is 3
        return CT_ERROR;
    }

    *mask |= MASK_MONTH;
    cmp_text.str = date_text->str;

    for (uint32 i = 0; i < 12; i++) {  // have 12 month
        if (date_text->len < g_month_names[i].len) {
            continue;
        }

        cmp_text.len = g_month_names[i].len;
        if (!cm_text_equal_ins(&cmp_text, &g_month_names[i])) {
            continue;
        }

        *mon = (uint8)(i + 1);
        date_text->len -= g_month_names[i].len;
        date_text->str += g_month_names[i].len;

        return CT_SUCCESS;
    }

    return CT_ERROR;
}

static status_t cm_get_month_by_abbr_name(text_t *date_text, uint32 *mask, uint8 *mon)
{
    text_t cmp_text, mon_text;

    CM_POINTER3(date_text, mask, mon);

    if ((*mask & MASK_MONTH) != 0) {
        return CT_ERROR;
    }

    *mask |= MASK_MONTH;

    if (date_text->len < 3) {  // min length of name is 3
        return CT_ERROR;
    }

    cmp_text.str = date_text->str;
    cmp_text.len = 3;  // just get abbr name
    mon_text.len = 3;

    for (uint32 i = 0; i < 12; i++) {
        mon_text.str = g_month_names[i].str;
        if (!cm_text_equal_ins(&cmp_text, &mon_text)) {
            continue;
        }

        *mon = (uint8)(i + 1);

        date_text->len -= 3;  // just get abbr name
        date_text->str += 3;

        return CT_SUCCESS;
    }

    return CT_ERROR;
}

static status_t cm_get_month_by_roman_name(text_t *date_text, uint32 *mask, uint8 *mon)
{
    text_t cmp_text;
    CM_POINTER3(date_text, mask, mon);

    if ((*mask & MASK_MONTH) != 0) {
        return CT_ERROR;
    }

    if (date_text->len == 0) {
        return CT_ERROR;
    }

    *mask |= MASK_MONTH;
    cmp_text.str = date_text->str;

    for (int32 i = 11; i >= 0; i--) {
        if (date_text->len < g_month_roman_names[i].len) {
            continue;
        }

        cmp_text.len = g_month_roman_names[i].len;
        if (!cm_text_equal_ins(&cmp_text, &g_month_roman_names[i])) {
            continue;
        }

        *mon = (uint8)(i + 1);
        date_text->len -= g_month_roman_names[i].len;
        date_text->str += g_month_roman_names[i].len;

        return CT_SUCCESS;
    }

    return CT_ERROR;
}

status_t cm_check_number(text_t *num_text,
                         uint32 size,
                         int64 start,
                         int64 end,
                         int64 *num_val)
{
    char num[8]; /* size less than 6 always */
    CM_POINTER2(num_text, num_val);

    if (size >= sizeof(num)) {
        return CT_ERROR;
    }

    if (size != 0) {
        MEMS_RETURN_IFERR(memcpy_sp(num, sizeof(num), num_text->str, (size_t)size));
    }
    num[size] = '\0';

    *num_val = (int64)atoi(num);

    if (*num_val >= start && *num_val <= end) {
        return CT_SUCCESS;
    } else {
        return CT_ERROR;
    }
}

status_t cm_check_number_with_sign(text_t *num_text,
                                   uint32 size,
                                   int32 start,
                                   int32 end,
                                   int32 *num_val)
{
    char num[8]; /* size less than 6 always */
    status_t status;
    text_t number_text_src;
    CM_POINTER2(num_text, num_val);

    if (size >= sizeof(num)) {
        return CT_ERROR;
    }

    if (size != 0) {
        MEMS_RETURN_IFERR(memcpy_sp(num, sizeof(num), num_text->str, (size_t)size));
    }
    num[size] = '\0';

    number_text_src.str = num;
    number_text_src.len = size;

    status = cm_text2int(&number_text_src, num_val);
    CT_RETURN_IFERR(status);

    if (*num_val >= start && *num_val <= end) {
        return CT_SUCCESS;
    } else {
        return CT_ERROR;
    }
}

static uint32 cm_get_num_len_in_str(const text_t *text, uint32 part_len, bool32 with_sign)
{
    uint32 i;
    CM_POINTER(text);

    for (i = 0; i < MIN(part_len, text->len); i++) {
        if (!CM_IS_DIGIT(text->str[i])) {
            /* if it is pos/neg sign,  it is also allowed */
            if (with_sign && (i == 0 && CM_IS_SIGN_CHAR(text->str[i]))) {
                continue;
            } else {
                return i;
            }
        }
    }

    return i;
}

/* !
 * \brief  Revise this function in order to enable to handle 9 digital precision
 *  (i.e., nanoseconds).
 *
 */
static inline status_t cm_verify_number(const text_t *num_text, uint32 size, uint32 start, uint32 end,
                                        uint32 *num_value, uint32 *act_len_val)
{
    uint32 i;
    char num[11] = "0000000000"; /* size less than 9 always */
    uint32 act_len;

    CM_POINTER2(num_text, num_value);

    act_len = (num_text->len) < size ? num_text->len : size;
    *act_len_val = act_len;
    for (i = 0; i < act_len; i++) {
        /* adapt for tstz type */
        if (*(num_text->str + i) == ' ') {
            act_len = i;
            *act_len_val = i;
            break;
        }
        if (!(*(num_text->str + i) >= '0' && *(num_text->str + i) <= '9')) {
            return CT_ERROR;
        }
    }
    if (act_len != 0) {
        MEMS_RETURN_IFERR(memcpy_sp(num, sizeof(num), num_text->str, (size_t)act_len));
    }
    /* If the actual length less than given size, the left are set as zeros.
     * For example, using FF3 for .12, the expected num_value should be 120 milliseconds.
     * Since num is initially set by all zeros, therefore, the end position should be specified. */
    num[size] = '\0';

    *num_value = (uint32)atoi(num);

    if (*num_value >= start && *num_value <= end) {
        return CT_SUCCESS;
    } else {
        return CT_ERROR;
    }
}

static inline status_t cm_verify_part(text_t *date_text,
                                      uint32 *mask,
                                      date_time_mask_t mask_id,
                                      uint32 part_len,
                                      uint32 start_value,
                                      uint32 end_value,
                                      uint32 *part_value)
{
    uint32 act_len;
    if ((*mask & mask_id) != 0) {
        return CT_ERROR;
    }

    cm_trim_text(date_text);

    if (cm_verify_number(date_text, part_len, start_value, end_value, part_value, &act_len) != CT_SUCCESS) {
        return CT_ERROR;
    }

    *mask |= mask_id;
    if (date_text->len < part_len) {
        date_text->str += date_text->len;
        date_text->len = 0;
    } else {
        date_text->len -= act_len;
        date_text->str += act_len;
    }

    return CT_SUCCESS;
}

static inline uint32 cm_find_point(text_t *date_text)
{
    uint32 len = date_text->len;
    uint32 i = 0;
    for (; i < len; i++) {
        if (date_text->str[i] == '.') {
            break;
        }
    }
    return i;
}

static inline status_t cm_get_date_item(text_t *date_text,
                                        const format_item_t *fmt_item,
                                        text_t *fmt_extra,
                                        date_detail_t *date,
                                        uint32 *mask)
{
    text_t part_text;
    int64 num_value = 0;
    int32 num_value_with_sign = 0;
    bool8 neg = 0;
    uint32 item_len = 0;

    CM_POINTER4(date_text, fmt_item, date, mask);

    part_text.str = date_text->str;

    switch (fmt_item->id) {
        case FMT_SPACE:
        case FMT_MINUS:
        case FMT_BACK_SLASH:
        case FMT_COMMA:
        case FMT_DOT:
        case FMT_SEMI_COLON:
        case FMT_COLON:
            cm_check_special_char(date_text);
            break;

        case FMT_SLASH:
            part_text.len = 1;
            if (!cm_text_equal_ins(&part_text, &fmt_item->name)) {
                return CT_ERROR;
            }
            CM_REMOVE_FIRST(date_text);
            break;

        case FMT_X:
            part_text.len = 1;
            if (!cm_text_equal_ins(&part_text, &fmt_item->name)) {
                if (!cm_text_str_equal(&part_text, (const char *)".")) {
                    return CT_ERROR;
                }
            }
            CM_REMOVE_FIRST(date_text);
            break;

        case FMT_DQ_TEXT:
            part_text.len = fmt_extra->len;
            if (!cm_text_equal_ins(&part_text, fmt_extra)) {
                return CT_ERROR;
            }
            CM_REMOVE_FIRST_N(date_text, fmt_extra->len);
            break;

        case FMT_MONTH_NAME:
            return cm_get_month_by_name(date_text, mask, &date->mon);

        case FMT_MONTH_RM:
            return cm_get_month_by_roman_name(date_text, mask, &date->mon);

        case FMT_MONTH_ABBR_NAME:
            return cm_get_month_by_abbr_name(date_text, mask, &date->mon);

        case FMT_DAY_OF_MONTH:
            cm_check_special_char(date_text);
            // part_len is 2, start is 1, end is 31 // support all 0 time
            cm_check_time(MASK_DAY, 2, 0, 31, date_text, mask, num_value);
            date->day = (uint8)num_value;
            break;

        case FMT_FRAC_SECOND1:
        case FMT_FRAC_SECOND2:
        case FMT_FRAC_SECOND3:
        case FMT_FRAC_SECOND4:
        case FMT_FRAC_SECOND5:
        case FMT_FRAC_SECOND6:
        case FMT_FRAC_SEC_VAR_LEN:
            cm_check_special_char(date_text);
            if (fmt_item->placer <= 0) {
                CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "fmt_item->placer(%d) > 0", fmt_item->placer);
                return CT_ERROR;
            }
            if (cm_verify_part(date_text, mask, MASK_USEC, (fmt_item->placer), 0, 999999, (uint32 *)&num_value) !=
                CT_SUCCESS) {
                return CT_ERROR;
            }
            num_value *= g_1ten_powers[6 - fmt_item->placer];
            date->microsec = num_value % MICROSECS_PER_MILLISEC;
            date->millisec = num_value / MICROSECS_PER_MILLISEC;
            break;

        case FMT_HOUR_OF_DAY12:
            cm_check_special_char(date_text);
            cm_check_time(MASK_HOUR, 2, 1, 12, date_text, mask, num_value);
            date->hour = (uint8)num_value;
            break;

        case FMT_HOUR_OF_DAY24:
            if (*((date_text)->str) == '-') {
                neg = 1;
            }
            cm_check_special_char(date_text);
            item_len = cm_find_point(date_text);
            if ((item_len % EVEN_NUM) == 0) {
                cm_check_time(MASK_HOUR, 2, 0, 23, date_text, mask, num_value);
            } else {
                cm_check_time(MASK_HOUR, 3, -838, 838, date_text, mask, num_value);
            }
            date->hour = (int32)num_value;
            date->neg = neg;
            break;

        case FMT_MINUTE:
            cm_check_special_char(date_text);
            cm_check_time(MASK_MINUTE, 2, 0, 59, date_text, mask, num_value);
            date->min = (uint8)num_value;
            break;

        case FMT_MONTH:
            cm_check_special_char(date_text);
            cm_check_time(MASK_MONTH, 2, 0, 12, date_text, mask, num_value); // support all 0 time
            date->mon = (uint8)num_value;
            break;

        case FMT_SECOND:
            cm_check_special_char(date_text);
            cm_check_time(MASK_SECOND, 2, 0, 59, date_text, mask, num_value);
            date->sec = (uint8)num_value;
            break;

        case FMT_YEAR4:
            cm_check_time(MASK_YEAR, 4, 0, CM_MAX_YEAR, date_text, mask, num_value); // support all 0 time
            date->year = (uint16)num_value;
            break;

        case FMT_TZ_HOUR:
            cm_check_time_with_sign(MASK_TZ_HOUR, 3, -12, 14, date_text, mask, num_value_with_sign);
            date->tz_offset = (timezone_info_t)(((int8)num_value_with_sign) * SECONDS_PER_MIN);
            break;

        case FMT_TZ_MINUTE:
            cm_check_time(MASK_TZ_MINUTE, 2, 0, 59, date_text, mask, num_value);
            if (date->tz_offset < 0) {
                date->tz_offset -= (uint8)num_value;
            } else {
                date->tz_offset += (uint8)num_value;
            }
            break;
        default:
            break;
    }

    return CT_SUCCESS;
}

static status_t cm_text2date_detail(const text_t *text, const text_t *fmt, date_detail_t *datetime, uint32 datetype)
{
    format_item_t *fmt_item = NULL;
    uint32 mask;
    text_t fmt_text, date_text;
    text_t fmt_extra = { .str = NULL, .len = 0 };

    CM_POINTER3(text, fmt, datetime);

    fmt_text = *fmt;
    date_text = *text;
    cm_trim_text(&fmt_text);
    cm_trim_text(&date_text);

    mask = 0;

    while (fmt_text.len > 0) {
        if (cm_fetch_format_item(&fmt_text, &fmt_item, &fmt_extra, CT_TRUE) != CT_SUCCESS) {
            return CT_ERROR;
        }

        /* format not supported in functions for converting string to date */
        if (!fmt_item->reversible) {
            return CT_ERROR;
        }

        cm_trim_text(&date_text);
        if (CM_IS_EMPTY(&date_text)) {
            break;
        }

        if (cm_get_date_item(&date_text, fmt_item, &fmt_extra, datetime, &mask) != 0) {
            return CT_ERROR;
        }
    }

    if (!IS_MYSQL_NEW_TYPE(datetype) && datetime->mon > 0 &&
        datetime->day > g_month_days[IS_LEAP_YEAR(datetime->year)][datetime->mon - 1]) {
        return CT_ERROR;
    }

    /* date text is not matched with format string */
    if (date_text.len > 0) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_adjust_timestamp(timestamp_t *ts, int32 precision)
{
    if (precision == CT_MAX_DATETIME_PRECISION || *ts == 0) {
        return CT_SUCCESS;
    }

    *ts = (timestamp_t)cm_truncate_bigint(*ts, (uint32)(CT_MAX_DATETIME_PRECISION - precision));

    // round may cause out of range, e.g. 9999-12-31 23:59:59.999999
    if (!CM_IS_VALID_TIMESTAMP(*ts)) {
        CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "DATETIME");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_adjust_timestamp_tz(timestamp_tz_t *tstz, int32 precision)
{
    return cm_adjust_timestamp(&tstz->tstamp, precision);
}

status_t cm_check_tstz_is_valid(timestamp_tz_t *tstz)
{
    if (!CM_IS_VALID_TIMESTAMP(tstz->tstamp)) {
        return CT_ERROR;
    }

    if (!cm_validate_timezone(tstz->tz_offset)) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_text2timestamp_tz(const text_t *text, const text_t *fmt, timezone_info_t default_tz, timestamp_tz_t *tstz)
{
    text_t fmt_text;
    date_detail_t detail;
    CM_POINTER(text);

    if (fmt == NULL) {
        cm_default_nls_geter(NLS_TIMESTAMP_TZ_FORMAT, &fmt_text);
    } else {
        fmt_text = *fmt;
    }

    cm_text2date_init(&detail);
    detail.tz_offset = default_tz;
    if (cm_text2date_detail(text, &fmt_text, &detail, CT_TYPE_TIMESTAMP_TZ) != CT_SUCCESS) {
        CT_SET_DATETIME_FMT_ERROR;
        return CT_ERROR;
    }

    if (!cm_check_valid_zero_time(&detail)) {
        CT_SET_DATETIME_FMT_ERROR;
        return CT_ERROR;
    }

    cm_encode_timestamp_tz(&detail, tstz);

    // check again
    if (cm_check_tstz_is_valid(tstz)) {
        CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "TIMESTAMP_TZ");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_text2date(const text_t *text, const text_t *fmt, date_t *date)
{
    text_t fmt_text;
    date_detail_t detail;
    CM_POINTER(text);

    if (fmt == NULL) {
        cm_default_nls_geter(NLS_DATE_FORMAT, &fmt_text);
    } else {
        fmt_text = *fmt;
    }

    cm_text2date_init(&detail);
    if (cm_text2date_detail(text, &fmt_text, &detail, CT_TYPE_DATE) != CT_SUCCESS) {
        CT_SET_DATETIME_FMT_ERROR;
        return CT_ERROR;
    }

    if (!cm_check_valid_zero_time(&detail)) {
        CT_SET_DATETIME_FMT_ERROR;
        return CT_ERROR;
    }

    *date = cm_encode_date(&detail);

    // check again
    if (!CM_IS_VALID_TIMESTAMP(*date)) {
        CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "DATETIME");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_str2time(char *date, const text_t *fmt, time_t *time_stamp)
{
    text_t date_text;
    date_t date_stamp;
    if (strlen(date) == 0) {
        CT_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "date");
        return CT_ERROR;
    }

    cm_str2text(date, &date_text);
    CT_RETURN_IFERR(cm_text2date(&date_text, fmt, &date_stamp));
    *time_stamp = cm_date2time(date_stamp);
    return CT_SUCCESS;
}

static void cm_text2date_fixed_init(date_detail_t *datetime)
{
    ct_timer_t *now = g_timer();
    datetime->year = now->detail.year;
    datetime->mon = now->detail.mon;
    datetime->day = 1;
    datetime->hour = 0;
    datetime->min = 0;
    datetime->sec = 0;
    datetime->millisec = 0;
    datetime->microsec = 0;
    datetime->nanosec = 0;
    datetime->tz_offset = TIMEZONE_OFFSET_ZERO;
}

status_t cm_text2date_fixed(const text_t *text, const text_t *fmt, date_t *date)
{
    date_detail_t detail;
    CM_POINTER2(text, fmt);

    cm_text2date_fixed_init(&detail);
    if (cm_text2date_detail(text, fmt, &detail, CT_TYPE_DATE) != CT_SUCCESS) {
        CT_SET_DATETIME_FMT_ERROR;
        return CT_ERROR;
    }

    if (!cm_check_valid_zero_time(&detail)) {
        CT_SET_DATETIME_FMT_ERROR;
        return CT_ERROR;
    }

    *date = cm_encode_date(&detail);

    // check again
    if (!CM_IS_VALID_TIMESTAMP(*date)) {
        CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "DATETIME");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_fetch_date_field(text_t *text, uint32 minval, uint32 maxval, char spilt_char, uint32 *field_val)
{
    uint32 num_len;

    cm_trim_text(text);
    num_len = cm_get_num_len_in_str(text, text->len, CT_FALSE);
    CT_RETVALUE_IFTRUE(num_len == 0, CT_ERROR);

    CT_RETURN_IFERR(cm_check_number(text, num_len, minval, maxval, (int64*)field_val));
    text->str += num_len;
    text->len -= num_len;

    if (spilt_char != ' ') {
        cm_ltrim_text(text);
    }
    if (spilt_char != '\0') {
        if (text->len == num_len || *text->str != spilt_char) {
            return CT_ERROR;
        }
        CM_REMOVE_FIRST(text);
        cm_ltrim_text(text);
    }
    return CT_SUCCESS;
}

status_t cm_text2date_def(const text_t *text, date_t *date)
{
    int32 ret = CT_ERROR;
    uint32 field_val, mon_days;
    text_t date_text;
    date_detail_t detail;
    cm_text2date_init(&detail);

    CM_POINTER2(text, date);
    date_text = *text;
    cm_trim_text(&date_text);

    do {
        // 1-1-1 ~ 1990-01-01
        CT_BREAK_IF_TRUE((date_text.len < 5));

        // year
        CT_BREAK_IF_ERROR(cm_fetch_date_field(&date_text, CM_MIN_YEAR, CM_MAX_YEAR, '-', &field_val));
        detail.year = (uint16)field_val;

        // month
        CT_BREAK_IF_ERROR(cm_fetch_date_field(&date_text, 1, 12, '-', &field_val));
        detail.mon = (uint8)field_val;

        // day
        mon_days = (uint32)g_month_days[IS_LEAP_YEAR(detail.year)][detail.mon - 1];
        CT_BREAK_IF_ERROR(cm_fetch_date_field(&date_text, 1, mon_days, '\0', &field_val));
        detail.day = (uint8)field_val;

        ret = (date_text.len == 0) ? CT_SUCCESS : CT_ERROR;
    } while (0);

    if (ret != CT_SUCCESS) {
        CT_SET_DATETIME_FMT_ERROR;
        return CT_ERROR;
    }

    (*date) = cm_encode_date(&detail);

    return CT_SUCCESS;
}

status_t cm_text2timestamp_def(const text_t *text, date_t *date)
{
    int32 ret = CT_ERROR;
    char buf[8];
    uint32 field_val, mon_days;
    text_t date_text;
    date_detail_t detail;
    cm_text2date_init(&detail);

    CM_POINTER2(text, date);
    date_text = *text;
    cm_trim_text(&date_text);

    do {
        // 1-1-1 1:1:1 ~ 1990-01-01 00:00:00.123456
        CT_BREAK_IF_TRUE((date_text.len < 11));

        // year
        CT_BREAK_IF_ERROR(cm_fetch_date_field(&date_text, CM_MIN_YEAR, CM_MAX_YEAR, '-', &field_val));
        detail.year = (uint16)field_val;

        // month
        CT_BREAK_IF_ERROR(cm_fetch_date_field(&date_text, 1, 12, '-', &field_val));
        detail.mon = (uint8)field_val;

        // day
        mon_days = (uint32)g_month_days[IS_LEAP_YEAR(detail.year)][detail.mon - 1];
        CT_BREAK_IF_ERROR(cm_fetch_date_field(&date_text, 1, mon_days, ' ', &field_val));
        detail.day = (uint8)field_val;

        // hour
        CT_BREAK_IF_ERROR(cm_fetch_date_field(&date_text, 0, 23, ':', &field_val));
        detail.hour = (int16)field_val;

        // minute
        CT_BREAK_IF_ERROR(cm_fetch_date_field(&date_text, 0, 59, ':', &field_val));
        detail.min = (uint8)field_val;

        // second
        CT_BREAK_IF_ERROR(cm_fetch_date_field(&date_text, 0, 59, '\0', &field_val));
        detail.sec = (uint8)field_val;

        // optional frac second
        if (date_text.len == 0) {
            ret = CT_SUCCESS;
            break;
        }
        CT_BREAK_IF_TRUE(CM_TEXT_BEGIN(&date_text) != '.');
        CM_REMOVE_FIRST(&date_text);
        cm_ltrim_text(&date_text);
        CT_BREAK_IF_TRUE((date_text.len == 0 || date_text.len > 6));  // max precision is 6
        // append '0' for frac second
        CT_RETURN_IFERR(cm_text2str(&date_text, buf, sizeof(buf)));
        date_text.str = buf;
        date_text.len = (uint32)strlen(buf);
        while (date_text.len < 6) {
            CM_TEXT_APPEND(&date_text, '0');
        }
        CT_BREAK_IF_ERROR(cm_fetch_date_field(&date_text, 0, 999999, '\0', &field_val));
        detail.millisec = (uint16)(field_val / 1000);
        detail.microsec = (uint16)(field_val % 1000);

        ret = (date_text.len == 0) ? CT_SUCCESS : CT_ERROR;
    } while (0);

    if (ret != CT_SUCCESS) {
        CT_SET_DATETIME_FMT_ERROR;
        return CT_ERROR;
    }

    (*date) = cm_encode_date(&detail);

    return CT_SUCCESS;
}

static status_t cm_numtext2date(const text_t *text, date_t *date)
{
    status_t ret;
    text_t date_fmt;
    date_detail_t detail;
    cm_text2date_init(&detail);

    if (text->len == 8) {
        // yyyymmdd
        date_fmt.str = (char *)"YYYYMMDD";
        date_fmt.len = 8;
        ret = cm_text2date_detail(text, &date_fmt, &detail, CT_TYPE_DATE);
    } else if (text->len == 14) {
        // yyyymmddhh24miss
        date_fmt.str = (char *)"YYYYMMDDHH24MISS";
        date_fmt.len = 16;
        ret = cm_text2date_detail(text, &date_fmt, &detail, CT_TYPE_DATE);
    } else if (text->len > 14 && cm_char_in_text('.', text)) {
        // yyyymmddhh24miss
        date_fmt.str = (char *)"YYYYMMDDHH24MISS.FF";
        date_fmt.len = 19;
        ret = cm_text2date_detail(text, &date_fmt, &detail, CT_TYPE_DATE);
    } else {
        ret = CT_ERROR;
    }

    if (ret != CT_SUCCESS) {
        CT_SET_DATETIME_FMT_ERROR;
        return CT_ERROR;
    }

    if (!cm_check_valid_zero_time(&detail)) {
        CT_SET_DATETIME_FMT_ERROR;
        return CT_ERROR;
    }

    (*date) = cm_encode_date(&detail);
    return CT_SUCCESS;
}

status_t cm_text2date_flex(const text_t *text, date_t *date)
{
    text_t date_text = *text;
    cm_trim_text(&date_text);

    if (cm_char_in_text('-', &date_text)) {
        if (cm_char_in_text(':', &date_text)) {
            return cm_text2timestamp_def(&date_text, date);
        }
        return cm_text2date_def(&date_text, date);
    } else {
        return cm_numtext2date(&date_text, date);
    }
}


#ifdef WIN32
int cm_gettimeofday(struct timeval *tv)
{
    if (tv == NULL) {
        return 0;
    }

    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);

    uint64 temp = ((uint64)ft.dwLowDateTime | ((uint64)ft.dwHighDateTime << 32)) / 10; /* convert into microseconds */

    /* converting file time to unix epoch */
    temp -= CT_DELTA_EPOCH_IN_MICROSECS;
    tv->tv_sec = (long)(temp / 1000000UL);
    tv->tv_usec = (long)(temp % 1000000UL);

    return 0;
}
#endif

static date_t cm_get_date_with_days(int32 total_days)
{
    date_t date_tmp;

    date_tmp = (int64)total_days * SECONDS_PER_DAY;
    date_tmp = date_tmp * MILLISECS_PER_SECOND;
    date_tmp = date_tmp * MICROSECS_PER_MILLISEC;

    return date_tmp;
}

status_t cm_round_date(date_t date, text_t *fmt, date_t *result)
{
    date_detail_t detail;
    date_detail_ex_t detail_ex;
    format_item_t *item = NULL;
    text_t fmt_extra = { .str = NULL, .len = 0 };
    int32 total_days;
    uint8 current_w_day, next_w_day;
    uint16 *day_tab = NULL;
    double double_day1, double_day2;
    bool32 need_round = CT_FALSE;

    cm_decode_date(date, &detail);
    cm_get_detail_ex(&detail, &detail_ex);
    CT_RETURN_IFERR(cm_fetch_format_item(fmt, &item, &fmt_extra, CT_FALSE));

    switch (item->id) {
        /* One greater than the first two digits of a four - digit year */
        case FMT_CENTURY:  // CC SCC
        {
            detail.year = (uint16)((detail.year / 100) * 100 + 1);
            detail.mon = 1;
            detail.day = 1;
            detail.hour = detail.min = detail.sec = 0;
            detail.millisec = detail.microsec = detail.nanosec = 0;
            *result = cm_encode_date(&detail);
            break;
        }
        /* Starting day of the week */
        case FMT_DAY_OF_WEEK:    // D
        case FMT_DAY_NAME:       // DAY
        case FMT_DAY_ABBR_NAME:  // DY
        {
            total_days = total_days_before_date(&detail);
            total_days = total_days - detail_ex.day_of_week;
            // check if one week is half over(>=3)
            if (detail_ex.day_of_week >= 3 && detail.hour >= 12) {
                total_days += 7;
            }
            *result = cm_get_date_with_days(total_days);
            break;
        }
        /* Same day of the week as the first day of the year */
        case FMT_WEEK_OF_YEAR:  // WW
        {
            total_days = total_days_before_date(&detail);
            total_days = total_days - detail_ex.day_of_week + 1;
            // check if one week is half+1 over(>=4)
            if (detail_ex.day_of_week >= 4 && detail.hour >= 12) {
                total_days += 7;
            }
            *result = cm_get_date_with_days(total_days);
            break;
        }
        /* Same day of the week as the first day of the month */
        case FMT_WEEK_OF_MONTH:  // W
        {
            current_w_day = (uint8)(((detail.day - 1) / 7) * 7 + 1);
            day_tab = (uint16 *)g_month_days[IS_LEAP_YEAR(detail.year)];
            if (current_w_day + 7 > day_tab[detail.mon - 1]) {
                next_w_day = current_w_day;
            } else {
                next_w_day = current_w_day + 7;
            }

            double_day1 = detail.day + ((detail.hour >= 12) ? 1 : 0);
            double_day2 = (double)(current_w_day + next_w_day) / 2;
            if (double_day1 > double_day2) {
                detail.day = next_w_day;
            } else {
                detail.day = current_w_day;
            }

            total_days = total_days_before_date(&detail);
            *result = cm_get_date_with_days(total_days);
            break;
        }
        /* Day */
        case FMT_DAY_OF_MONTH:  // DD
        case FMT_DAY_OF_YEAR:   // DDD
        {
            if (detail.hour >= 12) {
                total_days = total_days_before_date(&detail) + 1;
            } else {
                total_days = total_days_before_date(&detail);
            }
            *result = cm_get_date_with_days(total_days);
            break;
        }
        /* Month (rounds up on the sixteenth day) */
        case FMT_MONTH:  // MM RM
        case FMT_MONTH_RM:
        case FMT_MONTH_ABBR_NAME:  // MON
        case FMT_MONTH_NAME:       // MONTH
        {
            need_round = (detail.day >= 16);
            detail.day = 1;
            total_days = total_days_before_date(&detail);
            if (need_round) {
                day_tab = (uint16 *)g_month_days[IS_LEAP_YEAR(detail.year)];
                total_days += (int32)day_tab[detail.mon - 1];
            }
            *result = cm_get_date_with_days(total_days);
            break;
        }
        /* Quarter (rounds up on the sixteenth day of the second month of the quarter) */
        case FMT_QUARTER:  // Q
        {
            // second month is 2,5,8,11, return mon is 1,4,7,10
            if (detail.mon < 2 || (detail.mon == 2 && detail.day < 16)) {
                detail.mon = 1;
            } else if (detail.mon < 5 || (detail.mon == 5 && detail.day < 16)) {
                detail.mon = 4;
            } else if (detail.mon < 8 || (detail.mon == 8 && detail.day < 16)) {
                detail.mon = 7;
            } else if (detail.mon < 11 || (detail.mon == 11 && detail.day < 16)) {
                detail.mon = 10;
            } else {
                detail.year += 1;
                detail.mon = 1;
            }

            detail.day = 1;

            total_days = total_days_before_date(&detail);
            *result = cm_get_date_with_days(total_days);
            break;
        }
        /* Year (rounds up on July 1) */
        case FMT_YEAR1:  // Y
        case FMT_YEAR2:  // YY
        case FMT_YEAR3:  // YYY
        case FMT_YEAR4:  // YYYY
        {
            if (detail.mon >= 7) {
                detail.year += 1;
            }
            detail.mon = 1;
            detail.day = 1;

            total_days = total_days_before_date(&detail);
            *result = cm_get_date_with_days(total_days);
            break;
        }
        /* Hour */
        case FMT_HOUR_OF_DAY12:  // HH HH12
        case FMT_HOUR_OF_DAY24:  // HH24
        {
            detail.min = detail.sec = 0;
            detail.millisec = detail.microsec = detail.nanosec = 0;
            *result = cm_encode_date(&detail);
            break;
        }
        /* Minute */
        case FMT_MINUTE:  // MI
        {
            detail.sec = 0;
            detail.millisec = detail.microsec = detail.nanosec = 0;
            *result = cm_encode_date(&detail);
            break;
        }
        /* Second */
        case FMT_SECOND:  // SS
        {
            detail.millisec = detail.microsec = detail.nanosec = 0;
            *result = cm_encode_date(&detail);
            break;
        }
        default:
            CT_SET_DATETIME_FMT_ERROR;
            return CT_ERROR;
    }

    if (fmt->len > 0) {
        CT_SET_DATETIME_FMT_ERROR;
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_trunc_date(date_t date, text_t *fmt, date_t *result)
{
    date_detail_t detail;
    date_detail_ex_t detail_ex;
    format_item_t *item = NULL;
    text_t fmt_extra = { .str = NULL, .len = 0 };
    int32 total_days;

    cm_decode_date(date, &detail);
    cm_get_detail_ex(&detail, &detail_ex);
    CT_RETURN_IFERR(cm_fetch_format_item(fmt, &item, &fmt_extra, CT_FALSE));

    switch (item->id) {
        /* One greater than the first two digits of a four - digit year */
        case FMT_CENTURY:  // CC SCC
        {
            detail.year = (uint16)((detail.year / 100) * 100 + 1);
            detail.mon = 1;
            detail.day = 1;
            detail.hour = detail.min = detail.sec = 0;
            detail.millisec = detail.microsec = detail.nanosec = 0;
            *result = cm_encode_date(&detail);
            break;
        }
        /* Starting day of the week */
        case FMT_DAY_OF_WEEK:    // D
        case FMT_DAY_NAME:       // DAY
        case FMT_DAY_ABBR_NAME:  // DY
        {
            total_days = total_days_before_date(&detail);
            total_days = total_days - detail_ex.day_of_week;
            *result = cm_get_date_with_days(total_days);
            break;
        }
        /* Same day of the week as the first day of the year */
        case FMT_WEEK_OF_YEAR:  // WW
        {
            total_days = total_days_before_date(&detail);
            total_days = total_days - detail_ex.day_of_week + 1;
            *result = cm_get_date_with_days(total_days);
            break;
        }
        /* Same day of the week as the first day of the month */
        case FMT_WEEK_OF_MONTH:  // W
        {
            detail.day = (uint8)(((detail.day - 1) / 7) * 7 + 1);
            detail.hour = detail.min = detail.sec = 0;
            detail.millisec = detail.microsec = detail.nanosec = 0;
            *result = cm_encode_date(&detail);
            break;
        }
        /* Day */
        case FMT_DAY_OF_MONTH:  // DD
        case FMT_DAY_OF_YEAR:   // DDD
        {
            detail.hour = detail.min = detail.sec = 0;
            detail.millisec = detail.microsec = detail.nanosec = 0;
            *result = cm_encode_date(&detail);
            break;
        }
        /* Month (rounds up on the sixteenth day) */
        case FMT_MONTH:            // MM
        case FMT_MONTH_RM:         // RM
        case FMT_MONTH_ABBR_NAME:  // MON
        case FMT_MONTH_NAME:       // MONTH
        {
            detail.day = 1;
            detail.hour = detail.min = detail.sec = 0;
            detail.millisec = detail.microsec = detail.nanosec = 0;
            *result = cm_encode_date(&detail);
            break;
        }
        /* Quarter (rounds up on the sixteenth day of the second month of the quarter) */
        case FMT_QUARTER:  // Q
        {
            detail.mon = (uint8)((detail_ex.quarter - 1) * 3 + 1);
            detail.day = 1;
            detail.hour = detail.min = detail.sec = 0;
            detail.millisec = detail.microsec = detail.nanosec = 0;
            *result = cm_encode_date(&detail);
            break;
        }
        /* Year (rounds up on July 1) */
        case FMT_YEAR1:  // Y
        case FMT_YEAR2:  // YY
        case FMT_YEAR3:  // YYY
        case FMT_YEAR4:  // YYYY
        {
            detail.mon = 1;
            detail.day = 1;
            detail.hour = detail.min = detail.sec = 0;
            detail.millisec = detail.microsec = detail.nanosec = 0;
            *result = cm_encode_date(&detail);
            break;
        }
        /* Hour */
        case FMT_HOUR_OF_DAY12:  // HH HH12
        case FMT_HOUR_OF_DAY24:  // HH24
        {
            detail.min = detail.sec = 0;
            detail.millisec = detail.microsec = detail.nanosec = 0;
            *result = cm_encode_date(&detail);
            break;
        }
        /* Minute */
        case FMT_MINUTE:  // MI
        {
            detail.sec = 0;
            detail.millisec = detail.microsec = detail.nanosec = 0;
            *result = cm_encode_date(&detail);
            break;
        }
        /* Second */
        case FMT_SECOND:  // SS
        {
            detail.millisec = detail.microsec = detail.nanosec = 0;
            *result = cm_encode_date(&detail);
            break;
        }
        default:
            CT_SET_DATETIME_FMT_ERROR;
            return CT_ERROR;
    }

    if (fmt->len > 0) {
        CT_SET_DATETIME_FMT_ERROR;
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

int64 cm_get_unix_timestamp(timestamp_t ts, int64 time_zone_offset)
{
    return ((int64)ts - time_zone_offset - (int64)CM_UNIX_EPOCH) / MICROSECS_PER_SECOND;
}

static int64 cm_pack_time_to_int64(int64 intpart, int64 fracpart)
{
    cm_assert(abs(fracpart) <= 0xffffffLL);
    return ((uint64)(intpart) << CM_BASE_24) + fracpart;
}

static int64 cm_cnvrt_datetime_from_binary_to_int(const uchar *ptr)
{
    int64 intpart = cm_ptr5_to_uint_little_endian(ptr) - DATETIMEF_INT_OFS;
    int32 fracpart = cm_ptr3_to_sint_little_endian(ptr + CT_DATETIME_PRECISION_5);
    return cm_pack_time_to_int64(intpart, fracpart);
}

int32 cm_datetime_cmp_mysql(void *datetime1, void *datetime2)
{
    int64 datetime1_int = cm_cnvrt_datetime_from_binary_to_int((const uchar *)datetime1);
    int64 datetime2_int = cm_cnvrt_datetime_from_binary_to_int((const uchar *)datetime2);
    return (datetime1_int < datetime2_int) ? -1 : (datetime1_int > datetime2_int) ? 1 : 0;
}

static inline int64 cm_cnvrt_time_from_binary_to_int(const uchar *ptr)
{    
    return ((int64)(cm_ptr6_to_uint_little_endian(ptr))) - TIMEF_OFS;
}

int32 cm_time_cmp_mysql(void *time1, void *time2)
{
    int64 time1_int = cm_cnvrt_time_from_binary_to_int((const uchar *)time1);
    int64 time2_int = cm_cnvrt_time_from_binary_to_int((const uchar *)time2);
    return (time1_int < time2_int) ? -1 : (time1_int > time2_int) ? 1 : 0;
}

static inline uint32 cm_cnvrt_date_from_binary_to_uint(const uchar *ptr)
{
    return cm_ptr3_to_uint_big_endian(ptr);
}

int32 cm_date_cmp_mysql(void *date1, void *date2)
{
    int64 date1_int = cm_cnvrt_date_from_binary_to_uint((const uchar *)date1);
    int64 date2_int = cm_cnvrt_date_from_binary_to_uint((const uchar *)date2);
    return (date1_int < date2_int) ? -1 : (date1_int > date2_int) ? 1 : 0;
}

date_t cm_encode_datetime_mysql(const date_detail_t *detail)
{
    int64 y_m_d = ((detail->year * DT_ENCODE_13 + detail->mon) << DT_ENCODE_5) | detail->day;
    int64 h_m_s = (detail->hour << DT_ENCODE_12) | (detail->min << DT_ENCODE_6) | detail->sec;
    int64 res = cm_pack_time_to_int64(((y_m_d << DT_ENCODE_17) | h_m_s),
        (detail->millisec * MICROSECS_PER_MILLISEC) + detail->microsec);
    return res;
}

date_t cm_encode_time_mysql(const date_detail_t *detail)
{
    int64 h_m_s = (((detail->mon ? 0 : detail->day * DT_ENCODE_24) + detail->hour) << DT_ENCODE_12) |
        (detail->min << DT_ENCODE_6) | detail->sec;
    int64 res = cm_pack_time_to_int64(h_m_s, (detail->millisec * MICROSECS_PER_MILLISEC) + detail->microsec);
    return detail->neg ? -res : res;
}

date_t cm_encode_date_mysql(const date_detail_t *detail)
{
    int64 tmp = detail->day + detail->mon * DT_ENCODE_32 + detail->year * DT_ENCODE_16 * DT_ENCODE_32;
    uchar ptr[CM_BYTE_8];
    *ptr = (uchar)tmp;
    *(ptr + 1) = (uchar)(tmp >> CM_BASE_8);
    *(ptr + DT_ENCODE_2) = (uchar)(tmp >> CM_BASE_16);
    return *(date_t *)ptr;
}

status_t cm_text2date_mysql(const text_t *text, const text_t *fmt, date_t *date, uint32 datatype)
{
    text_t fmt_text;
    date_detail_t detail;
    CM_POINTER(text);

    if (fmt == NULL) {
        switch (datatype) {
            case CT_TYPE_DATETIME_MYSQL:
            case CT_TYPE_DATE_MYSQL:
            case CT_TYPE_TIME_MYSQL:
                cm_default_nls_geter(NLS_TIMESTAMP_FORMAT, &fmt_text);
                break;
            default:
                break;
        }
    } else {
        fmt_text = *fmt;
    }

    cm_text2date_init(&detail);
    if (cm_text2date_detail(text, &fmt_text, &detail, datatype) != CT_SUCCESS) {
        CT_SET_DATETIME_FMT_ERROR;
        return CT_ERROR;
    }

    switch (datatype) {
        case CT_TYPE_DATETIME_MYSQL:
            *date = cm_encode_datetime_mysql(&detail);
            break;
        case CT_TYPE_TIME_MYSQL:
            *date = cm_encode_time_mysql(&detail);
            break;
        case CT_TYPE_DATE_MYSQL:
            *date = cm_encode_date_mysql(&detail);
            break;
        default:
            break;
    }

    return CT_SUCCESS;
}

void cm_cnvrt_datetime_from_int_to_date_detail(int64 input, date_detail_t *detail)
{
    int64 y_m_d;
    int64 h_m_s;
    int64 ymd_hms;
    int64 y_m;
    int64 time = input;

    if (time < 0) {
        time = -time;
    }

    detail->microsec = time % (1LL << DT_ENCODE_24);
    ymd_hms = (uint64)time >> DT_ENCODE_24;
    y_m_d = (uint64)ymd_hms >> DT_ENCODE_17;
    y_m = (uint64)y_m_d >> DT_ENCODE_5;
    h_m_s = ymd_hms % (1 << DT_ENCODE_17);
    detail->day = (uint8)(y_m_d % (1 << DT_ENCODE_5));
    detail->mon = (uint8)(y_m % DT_ENCODE_13);
    detail->year = (uint16)(y_m / DT_ENCODE_13);

    detail->sec = (uint8)(h_m_s % (1 << DT_ENCODE_6));
    detail->min = (uint8)(((uint64)h_m_s >> DT_ENCODE_6) % (1 << DT_ENCODE_6));
    detail->hour = (uint8)((uint64)h_m_s >> DT_ENCODE_12);

    uint32 tmp = (uint32)(time % (1LL << DT_ENCODE_24));
    detail->millisec = (uint16)(tmp / MICROSECS_PER_MILLISEC);
    detail->microsec = (uint16)(tmp % MICROSECS_PER_MILLISEC);
}

void cm_cnvrt_time_from_int_to_date_detail(int64 input, date_detail_t *detail)
{
    int64 h_m_s;
    int64 time = input;
    if (time < 0) {
        time = -time;
    }
    h_m_s = (uint64)time >> DT_ENCODE_24;
    detail->year = 0;
    detail->mon = 0;
    detail->day = 0;
    detail->hour = (uint8)(((uint64)h_m_s >> DT_ENCODE_12) % (1 << DT_ENCODE_10));
    detail->min = (uint8)(((uint64)h_m_s >> DT_ENCODE_6) % (1 << DT_ENCODE_6));
    detail->sec = (uint8)(h_m_s % (1 << DT_ENCODE_6));

    uint32 tmp = (uint32)(time % (1LL << DT_ENCODE_24));
    detail->millisec = (uint16)(tmp / MICROSECS_PER_MILLISEC);
    detail->microsec = (uint16)(tmp % MICROSECS_PER_MILLISEC);
}

void cm_decode_date_mysql(date_t date, date_detail_t *detail)
{
    int64 time;
    CM_POINTER(detail);

    time = cm_cnvrt_date_from_binary_to_uint((const uchar *)(&date));
    detail->year = (uint16)(time / DT_ENCODE_16 / DT_ENCODE_32);
    detail->mon = (uint8)(time / DT_ENCODE_32 % DT_ENCODE_16);
    detail->day = (uint8)(time % DT_ENCODE_32);

    detail->hour = 0;
    detail->min = 0;
    detail->sec = 0;
    detail->millisec = 0;
    detail->microsec = 0;
}

void cm_decode_datetime_mysql(date_t date, date_detail_t *detail)
{
    int64 time;
    CM_POINTER(detail);

    time = cm_cnvrt_datetime_from_binary_to_int((const uchar *)(&date));
    cm_cnvrt_datetime_from_int_to_date_detail(time, detail);
}

void cm_decode_time_mysql(date_t date, date_detail_t *detail)
{
    int64 time;
    CM_POINTER(detail);

    time = cm_cnvrt_time_from_binary_to_int((const uchar *)(&date));
    cm_cnvrt_time_from_int_to_date_detail(time, detail);
}

status_t cm_date2text_mysql_ex(uint32 datatype, date_t date, text_t *fmt, uint32 precision, text_t *text,
    uint32 max_len)
{
    date_detail_t detail;
    text_t format_text;

    CM_POINTER(text);
    switch (datatype) {
        case CT_TYPE_DATETIME_MYSQL:
            cm_decode_datetime_mysql(date, &detail);
            break;
        case CT_TYPE_TIME_MYSQL:
            cm_decode_time_mysql(date, &detail);
            break;
        case CT_TYPE_DATE_MYSQL:
        default:
            cm_decode_date_mysql(date, &detail);
            break;
    }

    if (fmt == NULL || fmt->str == NULL) {
        cm_default_nls_geter(NLS_DATE_FORMAT, &format_text);
    } else {
        format_text = *fmt;
    }

    if (datatype == CT_TYPE_TIME_MYSQL) {
        detail.year = 1;
        detail.mon = 1;
        detail.day = 1;
    }

    if (detail.year == 0 || detail.mon == 0 || detail.day == 0) {
        CT_LOG_RUN_ERR("invalid date time, datatype:%u, year:%u, month:%u, date:%u", datatype, detail.year, detail.mon, detail.day);
        CT_SET_DATETIME_FMT_ERROR;
        cm_panic(0);
        return CT_ERROR;
    }
    return cm_detail2text(&detail, &format_text, precision, text, max_len);
}

int32 cm_tstz_cmp(timestamp_tz_t *tstz1, timestamp_tz_t *tstz2)
{
    timestamp_t ts1;

    /* adjust to the same tz to cmpare */
    ts1 = cm_adjust_date_between_two_tzs(tstz1->tstamp, tstz1->tz_offset, tstz2->tz_offset);

    return (ts1 < tstz2->tstamp) ? -1 : (ts1 > tstz2->tstamp) ? 1 : 0;
}

int64 cm_tstz_sub(timestamp_tz_t *tstz1, timestamp_tz_t *tstz2)
{
    timestamp_t ts1;

    /* adjust to the same tz to cmpare */
    ts1 = cm_adjust_date_between_two_tzs(tstz1->tstamp, tstz1->tz_offset, tstz2->tz_offset);

    return (ts1 - tstz2->tstamp);
}

void cm_datetime_int_to_binary(int64 input, uchar *ptr, int32 precision)
{
    CM_ASSERT(precision <= DATETIME_MAX_DECIMALS);
    CM_ASSERT((cm_get_time_frac_part_from_int64(input) % (int)(powers_of_10[DATETIME_MAX_DECIMALS - precision])) == 0);

    cm_int5_to_binary(ptr, cm_get_time_int_part_from_int64(input) + DATETIMEF_INT_OFS);
    switch (precision) {
        case CM_DATE_PRE_0:
            cm_3_zero_ending(ptr);
            break;
        case CM_DATE_PRE_1:
        case CM_DATE_PRE_2:
            ptr[CM_BYTE_5] = (uchar)((char)(cm_get_time_frac_part_from_int64(input) / CM_4_POWER_OF_10));
            cm_2_zero_ending(ptr);
            break;
        case CM_DATE_PRE_3:
        case CM_DATE_PRE_4:
            cm_int2_to_binary(ptr + CM_BYTE_5, cm_get_time_frac_part_from_int64(input) / CM_2_POWER_OF_10);
            cm_1_zero_ending(ptr);
            break;
        case CM_DATE_PRE_5:
        case CM_DATE_PRE_6:
            cm_int3_to_binary(ptr + CM_BYTE_5, cm_get_time_frac_part_from_int64(input));
            break;
        default:
            cm_3_zero_ending(ptr);
            break;
    }
}

void cm_time_int_to_binary(int64 input, uchar *ptr, int32 precision)
{
    CM_ASSERT(precision <= DATETIME_MAX_DECIMALS);
    /* Make sure the stored value was previously properly rounded or truncated */
    CM_ASSERT((cm_get_time_frac_part_from_int64(input) % (int)(powers_of_10[DATETIME_MAX_DECIMALS - precision])) == 0);

    switch (precision) {
        case CM_DATE_PRE_0:
            cm_int3_to_binary(ptr, TIMEF_INT_OFS + cm_get_time_int_part_from_int64(input));
            cm_5_zero_ending(ptr);
            break;
        case CM_DATE_PRE_1:
        case CM_DATE_PRE_2:
            cm_int3_to_binary(ptr, TIMEF_INT_OFS + cm_get_time_int_part_from_int64(input));
            ptr[CM_BYTE_3] = (uchar)((char)(cm_get_time_frac_part_from_int64(input) / CM_4_POWER_OF_10));
            cm_4_zero_ending(ptr);
            break;
        case CM_DATE_PRE_3:
        case CM_DATE_PRE_4:
            cm_int3_to_binary(ptr, TIMEF_INT_OFS + cm_get_time_int_part_from_int64(input));
            cm_int2_to_binary(ptr + CM_BYTE_3, cm_get_time_frac_part_from_int64(input) / CM_2_POWER_OF_10);
            cm_3_zero_ending(ptr);
            break;
        case CM_DATE_PRE_5:
        case CM_DATE_PRE_6:
            cm_int6tobinary(ptr, input + TIMEF_OFS);
            cm_2_zero_ending(ptr);
            break;
        default:
            cm_int3_to_binary(ptr, TIMEF_INT_OFS + cm_get_time_int_part_from_int64(input));
            cm_5_zero_ending(ptr);
            break;
    }
}

date_t cm_timestamp2date_mysql(date_t date_input)
{
    date_detail_t detail;
    cm_decode_date(date_input, &detail);
    return cm_encode_datetime_mysql(&detail);
}

#ifdef __cplusplus
}
#endif

