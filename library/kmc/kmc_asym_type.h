/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: KMC asym type interface

 * Create: 2022-9-17
 * Notes: New Create
 */

#ifndef KMC_INCLUDE_KMC_ASYM_TYPE_H
#define KMC_INCLUDE_KMC_ASYM_TYPE_H

#include "wsecv2_config.h"
#if WSEC_COMPILE_ENABLE_ASYM

#include "wsecv2_type.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#pragma pack(1)
typedef struct KmcGenAsymParamTag {
    WsecUint32      domainId;
    WsecUint16      keySpec; /* value in WsecKeySpec */
    unsigned char   resv[18];
} KmcGenAsymParam;
#pragma pack()

#pragma pack(1)
typedef struct KmcGenAsymParamListTag {
    WsecUint32      count;
    KmcGenAsymParam *keyParamList;  /* Array or continuous memory with the size of count * sizeof(KmcGenAsymParam) */
    WsecUint32      extLen;
    unsigned char   ext[];
} KmcGenAsymParamList;
#pragma pack()

#pragma pack(1)
typedef struct KmcAsymKeyInfoTag {
    WsecUint32      domainId;
    WsecUint32      keyId;
    unsigned char   priIndex[8]; /* index of priKey */
    unsigned char   pubIndex[8]; /* index of pubKey */
    WsecUint16      keySpec;     /* value in WsecKeySpec */
    WsecUint16      keyType;     /* value in KmcKeyType */
    WsecUint32      pubKeyLen;
    unsigned char   *pubKey;
    unsigned char   resv[24];
} KmcAsymKeyInfo;
#pragma pack()

#pragma pack(1)
typedef struct KmcAsymKeyInfoListTag {
    WsecUint32      count;
    KmcAsymKeyInfo  *keyInfoList; /* Array or continuous memory with the size of count * sizeof(KmcAsymKeyInfo) */
    WsecUint32      extLen;
    unsigned char   ext[];
} KmcAsymKeyInfoList;
#pragma pack()

#pragma pack(1)
typedef struct KmcAsymKeyIdxTag {
    WsecUint32      domainId;
    unsigned char   keyIndex[8];  /* index of priKey */
    unsigned char   resv[12];
} KmcAsymIdx;
#pragma pack()

#pragma pack(1)
typedef struct KmcAsymIdxListTag {
    WsecUint32      count;
    KmcAsymIdx      *keyList;
    WsecUint32      extLen;
    unsigned char   ext[];
} KmcAsymIdxList;
#pragma pack()

#pragma pack(1)
typedef struct KmcPubKeyIdxTag {
    WsecUint32      domainId;
    unsigned char   pubIndex[8];
    WsecUint32      extLen;
    unsigned char   ext[];
} KmcPubKeyIdx;
#pragma pack()

#pragma pack(1)
typedef struct KmcPubKeyInfoTag {
    WsecUint32      domainId;
    WsecUint16      keySpec;  /* value in WsecKeySpec */
    WsecUint16      keyType;  /* value in KmcKeyType */
    WsecUint32      pubKeyLen;
    unsigned char   *pubKey;
    WsecUint32      extLen;
    unsigned char   ext[];
} KmcPubKeyInfo;
#pragma pack()

#pragma pack(1)
typedef struct KmcAsymActiveInfoTag {
    unsigned char   pubIndex[8];
    unsigned char   priIndex[8];
    WsecUint16      keySpec;     /* value in WsecKeySpec */
    WsecUint32      extLen;
    unsigned char   ext[];
} KmcAsymActiveInfo;
#pragma pack()

#pragma pack(1)
typedef struct KmcRmvAsymParamTag {
    WsecUint32      domainId;
    WsecUint32      rmvCount;
    WsecUint32      actualRmvCount;
    unsigned char   resv[12];
} KmcRmvAsymParam;
#pragma pack()

#pragma pack(1)
typedef struct KmcRmvAsymDomainListTag {
    WsecUint32      count;
    KmcRmvAsymParam *rmvParm;
    WsecUint32      extLen;
    unsigned char   ext[];
} KmcRmvAsymDomainList;
#pragma pack()

#pragma pack(1)
typedef struct KmcAsymKeyPairTag {
    WsecUint32      domainId;
    unsigned char   priIndex[8];
    WsecUint32      pubKeyLen;
    unsigned char   *pubKey;
    WsecUint32      extLen;
    unsigned char   ext[];
} KmcAsymKeyPair;
#pragma pack()

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // WSEC_COMPILE_ENABLE_ASYM

#endif // KMC_INCLUDE_KMC_ASYM_TYPE_H
