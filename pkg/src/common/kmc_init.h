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
 * kmc_init.h
 *
 *
 * IDENTIFICATION
 * src/utils/ctbackup/kmc_init.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef KMC_INIT
#define KMC_INIT

#include <stdint.h>
#include "wsecv2_type.h"

#if defined(__LINUX__) || defined(__linux__)
#include <linux/limits.h>
#define SEC_PATH_MAX PATH_MAX
#elif (defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER))
/* win10 1607 remove MAX_PATH define so we defined here for short path */
#define SEC_PATH_MAX 248
#else
#error "NOT SUPPORT OTHER PLATFROM"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TagKeCallBackParam {
    void *notifyCbCtx;
    void *loggerCtx;
    void *hwCtx;
} KeCallBackParam;

typedef struct TagKmcConfig {
    char primaryKeyStoreFile[SEC_PATH_MAX];
    char standbyKeyStoreFile[SEC_PATH_MAX];
    int32_t domainCount;
    int32_t role;
    int32_t procLockPerm;
    int32_t sdpAlgId;
    int32_t hmacAlgId;
    int32_t semKey;
    int32_t innerSymmAlgId;
    int32_t innerHashAlgId;
    int32_t innerHmacAlgId;
    int32_t innerKdfAlgId;
    int32_t workKeyIter;
    int32_t rootKeyIter;
    uint16_t version; // 0 is write read ksf file， 1 is memory ksf
} KmcConfig;

typedef struct TagKmcHardWareParm {
    int32_t len;
    char *hardParam;
} KmcHardWareParm;

typedef struct TagKmcConfigEx {
    int32_t enableHw;
    KmcHardWareParm kmcHardWareParm;
    KeCallBackParam *keCbParam;
    KmcConfig kmcConfig;
} KmcConfigEx;

typedef int32_t (*KeDecryptByDomainEx_t)(const void *ctx, uint32_t domainID,
    const char *cipherText, int32_t cipherTextLen, char **plainText, int32_t *plainTextLen);
typedef int32_t (*KeInitializeEx_t)(KmcConfigEx *kmcConfig, void **ctx);
typedef int32_t (*KeFinalizeEx_t)(void **ctx);
typedef int (*KmcGetMkCount_t)(void);
typedef unsigned long (*KmcAddDomainEx_t)(const KmcCfgDomainInfo *domainInfo);
typedef unsigned long (*KmcAddDomainKeyTypeEx_t)(WsecUint32 domainId, const KmcCfgKeyType *keyTypeCfg);
typedef unsigned long (*WsecFinalizeEx_t)(void);
typedef unsigned long (*KmcGetMaxMkId_t)(WsecUint32 domainId, WsecUint32 *maxKeyId);
typedef unsigned long (*KmcCreateMkEx_t)(WsecUint32 domainId, WsecUint32 *keyId);
typedef unsigned long (*KmcActivateMk_t)(WsecUint32 domainId, WsecUint32 keyId);
typedef unsigned long (*KmcGetMkDetail_t)(WsecUint32 domainId, WsecUint32 keyId,
                                          KmcMkInfo *mkInfo, unsigned char *keyPlaintextBuff, WsecUint32 *keyBuffLen);
typedef unsigned long (*KmcGetMkDetailByHash_t)(const unsigned char *hashData, WsecUint32 hashLen,
                                                KmcMkInfo *mkInfo, unsigned char *keyPlaintextBuff,
                                                WsecUint32 *keyBuffLen);
typedef unsigned long (*WsecInitializeEx_t)(WsecUint32 roleType, const KmcKsfName *filePathName,
                                            WsecBool useImportKey, WsecVoid *exParam);
typedef unsigned long (*KmcGetActiveMk_t)(WsecUint32 domainId, KmcMkInfo *mkInfo,
                                          unsigned char *keyPlaintextBuff, WsecUint32 *keyBuffLen);
typedef unsigned long (*WsecResetEx_t)(void);
typedef unsigned long (*KmcGenerateKsfAll_t)(const char *keystoreFile);
typedef unsigned long (*KmcGetMkHash_t)(WsecUint32 domainId, WsecUint32 keyId, unsigned char *hashData, WsecUint32 *hashLen);
typedef unsigned long (*SdpGetCipherDataLenEx_t)(WsecUint32 plaintextLen, WsecUint32 *ciphertextLenOut);
typedef unsigned long (*SdpEncryptEx_t)(WsecUint32 domain, WsecUint32 algId,
                                        const unsigned char *plainText, WsecUint32 plaintextLen,
                                        unsigned char *ciphertext, WsecUint32 *ciphertextLen);
typedef unsigned long (*SdpDecryptEx_t)(WsecUint32 domain,
                                        const unsigned char *ciphertext, WsecUint32 ciphertextLen,
                                        unsigned char *plainText, WsecUint32 *plaintextLen);
typedef unsigned long (*WsecRegFuncEx_t)(const WsecCallbacks *allCallbacks);
typedef struct st_kmc_interface {
    void *kmc_handle;
    void *sdp_handle;

    KeDecryptByDomainEx_t KeDecryptByDomainEx;
    KeInitializeEx_t KeInitializeEx;
    KeFinalizeEx_t KeFinalizeEx;
    KmcGetMkCount_t KmcGetMkCount;
    KmcAddDomainEx_t KmcAddDomainEx;
    KmcAddDomainKeyTypeEx_t KmcAddDomainKeyTypeEx;
    WsecFinalizeEx_t WsecFinalizeEx;
    KmcCreateMkEx_t KmcCreateMkEx;
    KmcActivateMk_t KmcActivateMk;
    KmcGetMkDetail_t KmcGetMkDetail;
    KmcGetMkDetailByHash_t KmcGetMkDetailByHash;
    WsecInitializeEx_t WsecInitializeEx;
    KmcGetActiveMk_t KmcGetActiveMk;
    WsecResetEx_t WsecResetEx;
    KmcGetMkHash_t KmcGetMkHash;
    KmcGetMaxMkId_t KmcGetMaxMkId;
    SdpGetCipherDataLenEx_t SdpGetCipherDataLenEx;
    SdpEncryptEx_t SdpEncryptEx;
    SdpDecryptEx_t SdpDecryptEx;
    KmcGenerateKsfAll_t KmcGenerateKsfAll;
    WsecRegFuncEx_t WsecRegFuncEx;
} kmc_interface_t;

int32_t init_KMC(void);
int32_t KMC_decrypt(uint32_t domianId, char *cipherText, int32_t length, char **plainText, int32_t *plainTextLength);
int32_t KMC_finalize(void);

status_t kmc_init_lib(void);
status_t sdp_init_lib(void);
void kmc_close_lib(void);
kmc_interface_t *kmc_global_handle(void);

#ifdef __cplusplus
}
#endif

#endif