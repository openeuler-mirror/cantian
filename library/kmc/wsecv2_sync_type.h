/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: KMC - Key Management Component - Sync MK

 * Create: 2022-08-27
 */

#ifndef KMC_INCLUDE_WSECV2_SYNC_TYPE_H
#define KMC_INCLUDE_WSECV2_SYNC_TYPE_H

#include "wsecv2_type.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct KmcRecvDomainInfoTag {
    WsecUint32 domainId;
    WsecBool isActiveChanged;
    WsecUint32 domainType;
    unsigned char reserve[12]; // 12 bytes reserve
} KmcRecvDomainInfo;

typedef struct KmcRecvSyncInfoTag {
    WsecUint16 version;
    WsecUint32 count;
    WsecUint32 actCount;
    KmcRecvDomainInfo *domainInfo;
    unsigned char extParam[];
} KmcRecvSyncInfo;

#pragma pack(1)
typedef struct KmcSyncCtrlParamTag {
    WsecUint32 dhAlg[KMC_SYNC_DH_ALG_LEN];   // 16 bytes 指定DH协商算法，不指定设置默认全0， 将以x25519算法进行协商
    WsecBool hasSafeChannel;
    WsecBool allowAsymByUnsafeChannel;
    unsigned char resv[16];	                 // 16 bytes 保留字段
} KmcSyncCtrlParam;
#pragma pack()

typedef struct TagKmcSyncDomainInfoTag {
    WsecUint32 domainId; 	 // 待发送密钥域ID
    WsecUint32 keyType;	     // 见下面解释
    unsigned char resv[8];
} KmcSyncDomainInfo;

typedef struct KmcSyncParamTag {
    WsecUint32 domainCount;	   // 待发送domain个数
    KmcSyncDomainInfo *domainInfo;
    unsigned char resv[20];	   // 20 bytes, 保留字段
} KmcSyncParam;


#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif // KMC_INCLUDE_WSECV2_SYNC_TYPE_H
