/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: MultiInstance cbb interface definition

 * Create: 2021-08-28
 * History: None
 */

#ifndef KMC_INCLUDE_WSECV2_MULTITF_H
#define KMC_INCLUDE_WSECV2_MULTITF_H

#include "wsecv2_multitype.h"
#include "wsecv2_type.h"
#include "wsecv2_itf.h"

#ifdef __cplusplus
extern "C" {
#endif

unsigned long WsecCreateInstanceMul(WsecHandle *kmcCtx, WsecVoid *userData, const WsecCallbacksMulti *allCallbacks);

WsecVoid WsecReleaseMul(WsecHandle *kmcCtx);

unsigned long WsecInitializeKmcMul(WsecHandle kmcCtx, const KmcInitParam *initParam);

unsigned long WsecFinalizeMul(WsecHandle kmcCtx);

unsigned long WsecResetMul(WsecHandle kmcCtx, const WsecVoid *hardwareParam, WsecUint32 hardwareParamLen);

unsigned long WsecSetRoleMul(WsecHandle kmcCtx, WsecUint32 roleType);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* KMC_INCLUDE_WSECV2_MULTITF_H */
