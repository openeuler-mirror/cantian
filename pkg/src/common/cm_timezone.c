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
 * cm_timezone.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_timezone.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_log.h"
#include "cm_text.h"
#include "cm_timezone.h"

#ifdef WIN32
#include <Winbase.h>
#endif

const char *g_default_tzoffset_fmt = "%c%02d:%02d";


/* db time zone, every module could get it */
static timezone_info_t g_db_timezone;

/* the buffer of the text_t should be prepared in advance and
   the length of buffer should be no less than TIMEZONE_OFFSET_STRLEN */
status_t cm_tzoffset2text(timezone_info_t tz, text_t *text)
{
    int32 hour, minute;
    uchar sign;

    CM_POINTER2(text, text->str);
    if (!cm_validate_timezone(tz)) {
        GS_THROW_ERROR(ERR_VALUE_ERROR, "an invalid timezone offset value");
        return GS_ERROR;
    }

    hour = TIMEZONE_GET_HOUR(tz);
    minute = TIMEZONE_GET_MINUTE(tz);
    sign = (hour < 0) ? '-' : '+';

    /* sprintf_s will copy the '\0' in the format string as well */
    PRTS_RETURN_IFERR(snprintf_s(text->str, TIMEZONE_OFFSET_STRLEN, TIMEZONE_OFFSET_STRLEN - 1,
                                 g_default_tzoffset_fmt, sign, abs(hour), minute));

    text->len = TIMEZONE_OFFSET_STRLEN - 1; /* '\0' should not be counted as the text length */

    return GS_SUCCESS;
}

static num_errno_t cm_text2tzoffset_core(text_t *text, timezone_info_t *tz)
{
    char c;
    bool32 is_neg = GS_FALSE;
    bool32 colon_found = GS_FALSE;
    uint32 i = 0;
    int32 hour = 0;
    int32 min = 0;
    int32 *val_ptr = &hour;

    CM_POINTER2(text, tz);

    cm_trim_text(text);

    if (text->len < 3 || text->len > 64) {
        return NERR_ERROR;
    }
    /* handle the sign */
    c = text->str[i];
    if (CM_IS_SIGN_CHAR(c)) {
        is_neg = (c == '-');
        if ((++i) >= text->len) {
            return NERR_ERROR;
        }
    }

    for (; i < text->len; i++) {
        c = text->str[i];
        if (CM_IS_COLON(c)) {
            if (!colon_found) {
                colon_found = GS_TRUE;
                /* after colon, switch to min */
                hour = *val_ptr;
                val_ptr = &min;
                continue;
            } else {
                /* duplicate colon */
                return NERR_ERROR;
            }
        }

        if (!CM_IS_DIGIT(c)) {
            return NERR_UNEXPECTED_CHAR;
        } else {
            *val_ptr = (*val_ptr) * CM_DEFAULT_DIGIT_RADIX + CM_C2D(c);
        }
    }

    if (!colon_found) {
        return NERR_ERROR;
    }

    hour = (is_neg) ? (0 - hour) : hour;
    if (!cm_validate_hour_min_fortz(hour, min)) {
        return NERR_OVERFLOW;
    }

    *((int16 *)tz) = (int16)((is_neg) ? (hour * TIMEZONE_MINUTES_PER_HOUR - min)
                                      : (hour * TIMEZONE_MINUTES_PER_HOUR + min));

    return NERR_SUCCESS;
}

/*
 * the function to convert a timezone offset string("[+|-]TZH:TZM") into a timezone_info_t
 * if the input string is not valid(wrong format, invalid TZH or TZM, etc),
 * this function would return GS_ERROR and report an error
 */
status_t cm_text2tzoffset(text_t *text, timezone_info_t *tz)
{
    num_errno_t retval;

    retval = cm_text2tzoffset_core(text, tz);
    switch (retval) {
        case NERR_SUCCESS:
            break;
        case NERR_ERROR:
            GS_THROW_ERROR(ERR_VALUE_ERROR, "string does not match the timezone offset format");
            return GS_ERROR;
        case NERR_UNEXPECTED_CHAR:
            GS_THROW_ERROR(ERR_VALUE_ERROR, "unrecognized character in the specified timezone offset");
            return GS_ERROR;
        case NERR_OVERFLOW:
            GS_THROW_ERROR(ERR_VALUE_ERROR,
                "invalid time zone offset. time zone offset must be between -12:00 and 14:00");
            return GS_ERROR;
        default:
            GS_THROW_ERROR(ERR_VALUE_ERROR, "unexpected return value");
            return GS_ERROR;
    }

    return GS_SUCCESS;
}

/*
 * get the local timezone offset in minutes on the executing system
 * this is also called ostimezone,  SYSTIMESTAMP and SYSDATE will also use this func
 *
 * if the return value is greater than zero, it means current timezone is to the EAST of GMT;
 * if the return value is less than zero, it means current timezone is to the WEST of GMT;
 */
int16 cm_get_local_tzoffset(void)
{
#ifdef WIN32
    LONG tzoffset = 0;
    TIME_ZONE_INFORMATION tmp;
    if (GetTimeZoneInformation(&tmp) == TIME_ZONE_ID_INVALID) {
        GS_LOG_RUN_WAR("error occurred during calling GetTimeZoneInformation(). errno: \"%lu\"", GetLastError());
    } else {
        tzoffset = 0 - tmp.Bias; /* field "Bias" means west of GMT,
                                           just the opposite of the definition of our timezone offset */
    }
    return (int16)tzoffset;
#else
    struct tm result;
    time_t utc_time = time(NULL);
    int retval = 0;

    tzset();
    if (localtime_r(&utc_time, &result) != NULL) {
        retval = (int16)(result.tm_gmtoff / TIMEZONE_MINUTES_PER_HOUR); /* tm_gmtoff: seconds east of GMT */
    } else {
        /* when compiled with gcc on linux, errno is thread-safe. ref: http://www.unix.org/whitepapers/reentrant.html */
        GS_LOG_RUN_WAR("error occurred during calling localtime_r(). errno: \"%d\"", errno);
    }

    return (int16)retval;
#endif
}

/*
 * this function is used to  get db time zone
 */
int16 cm_get_db_timezone(void)
{
    return g_db_timezone;
}

/*
 * this function is used to  set db time zone
 */
void cm_set_db_timezone(timezone_info_t tz)
{
    g_db_timezone = tz;
    return;
}
