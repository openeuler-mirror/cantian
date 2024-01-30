/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2020. All rights reserved.
 * Description: Time processing function interface, which is not open to external systems.

 * Create: 2014-07-11

 */

#ifndef KMC_SRC_COMMON_WSECV2_DATETIME_H
#define KMC_SRC_COMMON_WSECV2_DATETIME_H

#include "wsecv2_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KMC_TIME_SUNDAY 7
/* Date and time processing function */
/* Add nAdd time units (days) to the specified date and time (baseTime). */
WsecBool WsecDateTimeAddDay(const WsecSysTime *baseTime, WsecUint32 day, WsecSysTime *newTime);

/* Number of extra days between endTime and startTime. The unit is day. */
WsecBool WsecDateTimeDiffDay(const WsecSysTime *startTime, const WsecSysTime *endTime, int *day);

/* Copy the DateTime structure. */
WsecBool WsecDateTimeCopy(const WsecSysTime *srcTime, WsecSysTime *destTime);

/* Obtaining the Current Universal Time Coordinated (UTC) Date and Time */
WsecBool WsecGetUtcDateTime(WsecHandle kmcCtx, WsecSysTime *nowUtc);

/*
 * Checks whether the specified parameter is valid.
 * The system only checks whether the values of year, month, day, hour, minute, and second are valid.
 * The system cannot determine whether the week value matches the year, month, and day.
 */
WsecBool WsecIsDateTime(const WsecSysTime *timeValue);

/* Convert the time structure. */
WsecVoid WsecCvtByteOrderForDateTime(WsecSysTime *dateTime, WsecUint32 direction);

#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif /* KMC_SRC_COMMON_WSECV2_DATETIME_H */
