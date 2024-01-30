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
 * cantian_fdsa_interface.h
 *
 *
 * IDENTIFICATION
 * src/fdsa/cantian_fdsa_interface.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CANTIAN_FDSA_INTERFACE_H
#define CANTIAN_FDSA_INTERFACE_H

#include "dpax_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

// if need more functions, check from heal.h, fdsa_inner.h, iod.h.

/*fdsa_inner.h begin*/
#define HEAL_NAME_LEN               (32)    /*任务名称字符串长度*/
#define HEAL_CAUSE_STRLEN           (128)   /*故障原因描述字符串长度*/
#define HEAL_COLLECT_INFO_STRLEN    (10240) /*信息采集字符串长度*/
#define FDSA_QUERY_ATTR_MAX_COUNT   (5)
#define FDSA_BUFFER_SIZE_8          (8)
#define FDSA_BUFFER_SIZE_16         (16)
#define FDSA_BUFFER_SIZE_32         (32)
#define FDSA_BUFFER_SIZE_64         (64)
#define FDSA_BUFFER_SIZE_128        (128)
#define FDSA_BUFFER_SIZE_256        (256)
#define FDSA_BUFFER_SIZE_512        (512)
#define FDSA_BUFFER_SIZE_1K         (1024)
#define FDSA_BUFFER_SIZE_2K         (2048)
#define FDSA_BUFFER_SIZE_10K        (10240)

typedef enum tagHEAL_RECOVER_LEVEL
{
    HEAL_RECOVER_NONE = 0,                  /* 不处理 */
    HEAL_RECOVER_TRY_YOUR_BEST = 1,         /* 尽量复位 */
    HEAL_RECOVER_IMMEDIATELY = 2,           /* 立即复位 */
    HEAL_RECOVER_ALARM = 3,                 /* 上报告警 */
    HEAL_RECOVER_IMMEDIATELY_NOCOLLECT = 4, /* 立即复位，不收集信息 */

    HEAL_RECOVER_PROCESS_TRY_YOUR_BEST = 5, /* 进程尽量复位 */
    HEAL_RECOVER_PROCESS_IMMEDIATELY = 6,   /* 进程立即复位 */
    HEAL_RECOVER_TOTAL
} HEAL_RECOVER_LEVEL_E;

typedef struct tagHEAL_COLLECT_INFO
{
    char    szCollectInfo[FDSA_BUFFER_SIZE_10K]; /* 采集信息长度 */
} HEAL_COLLECT_INFO_S;


typedef struct tagHEAL_CBRETURN
{
    char     szName[FDSA_BUFFER_SIZE_32];       /* 任务名称 */
    OSP_BOOL bResult;                           /* 是否执行成功 */
    uint32_t uiNodeId;                          /* 故障节点id */
    char     szCause[FDSA_BUFFER_SIZE_128];     /* 故障原因描述字符串 */
    uint64_t ullReserved;                       /* 预留字段 */
    uint32_t uiRecoveryCheck;                   /* 自愈前的附加判断，默认值为0。参考FDSA_RECOVERY_CHECK_*系列宏定义。 */
} HEAL_CBRETURN_S;

typedef struct tagHEAL_REGPARAM
{
    char    szName[FDSA_BUFFER_SIZE_32];            /* 任务名称，区分大小写 */
    void (*pCheckCB)(HEAL_CBRETURN_S *, void *);    /* 检测函数，不允许为空*/
    void (*pCollectCB)(HEAL_CBRETURN_S *, void *, HEAL_COLLECT_INFO_S *); /* 信息采集函数，可为空*/
    void (*pHealCB)(HEAL_CBRETURN_S *, void *);     /* 自愈函数，可为空 */
    uint32_t     uiCheckFailTimes;                  /* 连续检测失败指定次数后进行自愈，正整数 */
    uint32_t     uiCheckPeriod;                     /* 检查周期，单位秒 ，正整数*/
    HEAL_RECOVER_LEVEL_E eRecoverLever;             /* 上报恢复级别 */
    void *  pUserParam;                             /* 任务处理过程需要的用户参数,返填给回调函数 */
} HEAL_REGPARAM_S;
/*fdsa_inner.h end*/

typedef void (*HEALCALLBACK)(HEAL_CBRETURN_S *, void *);
typedef OSP_S32 (*HEAL_InitCommon_T)(void);
typedef int32_t (*HEAL_RegisterTask_T)(HEAL_REGPARAM_S *, uint16_t,
    const char *, const int32_t);
typedef int32_t (*HEAL_EnableTask_T)(char *, uint16_t,
    const char *, const int32_t);
typedef int32_t (*HEAL_DisableTask_T)(char *, uint16_t,
    const char *, const int32_t);
typedef int32_t (*HEAL_UnregisterTask_T)(char *, HEALCALLBACK,
    void *, uint16_t, const char *, const int32_t);

typedef struct st_fdsa_interface {
    void *fdsa_handle;

    HEAL_InitCommon_T     HEAL_InitCommon;
    HEAL_RegisterTask_T   HEAL_RegisterTask;
    HEAL_EnableTask_T     HEAL_EnableTask;
    HEAL_DisableTask_T    HEAL_DisableTask;
    HEAL_UnregisterTask_T HEAL_UnregisterTask;

} fdsa_interface_t;

#ifdef __cplusplus
}
#endif
#endif