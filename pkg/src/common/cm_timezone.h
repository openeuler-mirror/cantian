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
 * cm_timezone.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_timezone.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_TIMEZONE_H__
#define __CM_TIMEZONE_H__

#include "cm_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * the internal data structure for storing timezone information.
 * the purpose of it is to save space when transforming the information via network,
 * or storing the information with TIMESTAMP WITH TIMEZONE data.
 *
 * the timezone_info_t stands for the offset (in minutes) of a timezone.
 * for instance, the content of timezone_info_t for CMT(GMT+8:00) is 480
 * while EST(GMT-5:00) is -300
 */
typedef int16 timezone_info_t;

#define TIMEZONE_IS_GMT(timezone)          (bool32)((timezone) == 0)
#define TIMEZONE_IS_GMT_EAST(timezone)     (bool32)((timezone) > 0)
#define TIMEZONE_GET_HOUR(timezone)        (int32)((timezone) / 60) /* the sign included */
#define TIMEZONE_GET_MICROSECOND(timezone) (int64)((timezone)*60 * 1000000LL)
/* the value of TIMEZONE_GET_MINUTE is never less than zero */
#define TIMEZONE_GET_MINUTE(timezone)      (int32)(((timezone) >= 0) ? ((timezone) % 60) : ((0 - (timezone)) % 60))
#define TIMEZONE_GET_SIGN_MINUTE(timezone) (int32)((timezone) % 60)
#define TIMEZONE_HOUR_MINVALUE        (-12)
#define TIMEZONE_HOUR_MAXVALUE        14
#define TIMEZONE_MINUTE_MINVALUE      0
#define TIMEZONE_MINUTE_MAXVALUE      59
#define TIMEZONE_OFFSET_MINVALUE      (-720) /* -12 * 60 */
#define TIMEZONE_OFFSET_MAXVALUE      840  /* 14 * 60 */
#define TIMEZONE_OFFSET_INVALIDVALUE  0x7FFF   /* 0x7FFF */
#define TIMEZONE_OFFSET_ZERO          0   /* 0 */
#define TIMEZONE_OFFSET_DEFAULT       480 /* default value = (beijing /China time zone) */
#define TIMEZONE_MINUTES_PER_HOUR     60

extern const char *g_default_tzoffset_fmt;
#define TIMEZONE_OFFSET_STRLEN (6 + 1) /* including '\0' byte because CM_SPRINT_S() will also copy the '\0' */

static inline bool32 cm_validate_hour_min_fortz(int32 hour, int32 minute)
{
    if ((hour < TIMEZONE_HOUR_MINVALUE) || (hour > TIMEZONE_HOUR_MAXVALUE)) {
        return GS_FALSE;
    } else if (hour > TIMEZONE_HOUR_MINVALUE && hour < TIMEZONE_HOUR_MAXVALUE) {
        if (minute > TIMEZONE_MINUTE_MAXVALUE || minute < TIMEZONE_MINUTE_MINVALUE) {
            return GS_FALSE;
        }
    } else {
        if (minute != TIMEZONE_MINUTE_MINVALUE) {
            return GS_FALSE;
        }
    }

    return GS_TRUE;
}

static inline bool32 cm_validate_timezone(timezone_info_t timezone_to_validate)
{
    return (bool32)((timezone_to_validate >= TIMEZONE_OFFSET_MINVALUE) &&
        (timezone_to_validate <= TIMEZONE_OFFSET_MAXVALUE));
}

/* external functions declarations */
status_t cm_tzoffset2text(timezone_info_t tz, text_t *text);
status_t cm_text2tzoffset(text_t *text, timezone_info_t *tz);
int16 cm_get_local_tzoffset(void);

int16 cm_get_db_timezone(void);
void cm_set_db_timezone(timezone_info_t tz);

#ifdef __cplusplus
}
#endif

#endif
