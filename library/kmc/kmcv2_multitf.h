/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: MultiInstance kmc interface definition

 * Create: 2021-08-28
 * History: None
 */

#ifndef KMC_INCLUDE_KMCV2_MULTITF_H
#define KMC_INCLUDE_KMCV2_MULTITF_H

#include "wsecv2_type.h"
#include "wsecv2_itf.h"
#include "wsecv2_sync_type.h"
#include "kmcv2_itf.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This API is used Batch remove mks in a specified instance.
 * A key can be deleted only when it is not in the Active state.
 */
unsigned long KmcRmvMkMulEx(WsecHandle kmcCtx, WsecUint32 rmvDomainCount, KmcRmvMkParam *rmvMkParam);
/*
 * This API is used remove a specified mk in a specified instance.
 * A key can be deleted only when it is not in the Active state.
 */
unsigned long KmcRmvMkMul(WsecHandle kmcCtx, WsecUint32 domainId, WsecUint32 keyId);
/* This API is used Batch create mk in a specified instance. */
unsigned long KmcCreateMkMul(WsecHandle kmcCtx, const KmcOpMkParam *opMkParam);

/* This API is used Regist mk in a specified instance. */
unsigned long KmcRegisterMkMul(WsecHandle kmcCtx, WsecUint32 domainId, WsecUint32 keyId,
    const unsigned char *plaintextKey, WsecUint32 keyLen);

/*
 * This API is used activates batch key of different domain in a specified instance.
 * That is, the specified key is valid and all other keys in the same domain are invalid.
 */
unsigned long KmcActivateMkMul(WsecHandle kmcCtx, KmcOpMkParam *opMkParam);
/* Set the Maximum Number of MK for a specified instance., The value cannot be greater than 4096. */
unsigned long KmcSetMkMaxCountMul(WsecHandle kmcCtx, int count);
/*
 * This API is used to change the status of a specified key in a specified instance. For a single key, you can change
 * the status to any specified status, Use this function with caution. If it is used improperly,
 * multiple valid keys may exist in the same domain. will be written into the keystore file.
 */
unsigned long KmcSetMkStatusMul(WsecHandle kmcCtx, WsecUint32 domainId, WsecUint32 keyId, unsigned char status);
/* This API is used to get the active mk in the domain in a specified instance.  */
unsigned long KmcGetActiveMkMul(WsecHandle kmcCtx, WsecUint32 domainId, KmcMkInfo *mkInfo,
    unsigned char *keyPlaintextBuff, WsecUint32 *keyBuffLen);

/* This API is used to get the Status of MK */
unsigned long KmcGetMkStatusMul(WsecHandle kmcCtx, WsecUint32 domainId, WsecUint32 keyId, unsigned char *status);
/* This API is used to get the Number of MK in the domain */
int KmcGetMkCountByDomainMul(WsecHandle kmcCtx, WsecUint32 domainId);

/*
 * Obtains the number of keys in a specified instance.
 * This API can be used together with KmcGetMkMul to traverse key status.
 */
int KmcGetMkCountMul(WsecHandle kmcCtx);

/* Obtains the maximum and minimum key IDs of a specified domain in a specified instance. */
unsigned long KmcGetMaxMinMkIdMul(WsecHandle kmcCtx, WsecUint32 domainId, WsecUint32 *maxKeyId, WsecUint32 *minKeyId);
/*
 * Obtain the key information in the specified instance.
 * The index starts from 0 and the upper limit is KmcGetDomainCountMul-1.
 * If the key is modified or deleted during the obtaining process, the key may fail to be obtained.
 * If this function is used to traverse key information, ensure that other threads do not update or reload
 * keys during the traversal, In addition, do not change the status of any key or delete or add any key.
 * This function is used to obtain the mk based on the list of all keys and cannot be used together with
 * KmcGetMkCountByDomainMul.
 */
unsigned long KmcGetMkMul(WsecHandle kmcCtx, int idx, KmcMkInfo *memMk);

/*
 * Obtains the hash value of the key based on the specified domain and key ID in the specified instance.
 * The hash value is the first eight bytes of the SHA256 calculation result of the plaintext key.
 */
unsigned long KmcGetMkHashMul(WsecHandle kmcCtx, WsecUint32 domainId, WsecUint32 keyId, unsigned char *hashData,
    WsecUint32 *hashLen);

/*
 * This API is used to obtain the key information of a specified domain ID and key ID in the specified instance,
 * including the original key and basic mapping information.
 * and key status information. The creation and expiration time
 * in the information is obtained based on the local time function,
 * The caller can determine whether the validity period is 180 days by default.
 */
unsigned long KmcGetMkDetailMul(WsecHandle kmcCtx, WsecUint32 domainId, WsecUint32 keyId, KmcMkInfo *mkInfo,
    unsigned char *keyPlaintextBuff, WsecUint32 *keyBuffLen);

/*
 * This interface is used to obtain a key and its status information based on the specified hash value in the specified
 * instance.
 */
unsigned long KmcGetMkDetailByHashMul(WsecHandle kmcCtx, const unsigned char *hashData, WsecUint32 hashLen,
    KmcMkInfo *mkInfo, unsigned char *keyPlaintextBuff, WsecUint32 *keyBuffLen);

/* This interface is used to obtain the status information about a specified key in the specified instance. */
unsigned long KmcGetMkInfoByContentMul(WsecHandle kmcCtx, const unsigned char *keyPlaintextBuff, WsecUint32 keyLen,
    KmcMkInfo *mkInfo);

/*
 * Erase all keys, including the key information in the keystore file and memory of the specified instance,
 * for board recycling. Exercise caution when performing this operation.
 */
unsigned long KmcSecureEraseKeystoreMul(WsecHandle kmcCtx);
/*
 * This operation can be performed only on the Master node.
 * Check the integrity of the keystore file in the specified instance.
 * Check whether the keystore file is complete.
 * Check whether the rewriting is successful.
 */
unsigned long KmcCheckKeyStoreMul(WsecHandle kmcCtx, WsecBool rewriteOnCheckFail, unsigned long *rewriteErrorCode);
/* Obtains the number of iterations for updating the shared key in the current memory in the specified instance. */
unsigned long KmcGetSharedMkUpdateNumFromMemMul(WsecHandle kmcCtx, WsecUint32 *updateCounter);
/* Obtains the number of iterations for updating the shared key of a specified ksf file. */
unsigned long KmcGetSharedMkUpdateNumFromFileMul(WsecHandle kmcCtx, const char *keystoreFile, WsecUint32 *updateCount);
/* Obtains the number of iterations for updating the keystore in the current memory in the specified instance. */
unsigned long KmcGetUpdateNumFromMemMul(WsecHandle kmcCtx, WsecUint32 *updateCounter);
/* Obtains the number of iterations for updating the shared key in the current memory in the specified instance. */
unsigned long KmcGetUpdateNumFromFileMul(WsecHandle kmcCtx, const char *keystoreFile, WsecUint32 *updateCounter);


// /* sync */
/* Configure msg send interface in the specified instance. */
unsigned long KmcMasterSendCnfMul(WsecHandle kmcCtx, WsecVoid *param, const CallbackSendSyncData sendSyncData,
    const CallbackRecvSyncData recvSyncData);

/* Configure msg recv interface in the specified instance. */
unsigned long KmcAgentRecvCnfMul(WsecHandle kmcCtx, WsecHandle *ctx, WsecVoid *param,
    const CallbackSendSyncData sendSyncData, const CallbackRecvSyncData recvSyncData);

/* Free ctx create by KmcAgentRecvCnf in the specified instance. */
void KmcAgentRecvCnfFinalMul(WsecHandle kmcCtx, const WsecHandle *ctx);

/* Agent MK recv interface, sync msg stream：header + mks + hash in the specified instance. */
unsigned long KmcAgentRecvMkMul(WsecHandle kmcCtx, WsecHandle ctx, KmcRecvSyncInfo *syncInfo,
    KmcDomainOpMode recvMode, WsecVoid *param, const CallbackRecvSyncData recvSyncData);

/* Master send special shared MK to Agent by domain list */
unsigned long KmcMasterBatchSendMkMul(WsecHandle kmcCtx, const KmcDomainArray *domainArray, WsecVoid *param,
    CallbackSendSyncData sendSyncData);

/* Agent Recv special shared MK from master by domain list */
unsigned long KmcAgentBatchRecvMkMul(WsecHandle kmcCtx, KmcRecvSyncInfo *syncInfo, WsecVoid *param,
    CallbackRecvSyncData recvSyncData);


/* Add Domain Configuration in the specified instance. */
unsigned long KmcAddDomainMul(WsecHandle kmcCtx, const KmcCfgDomainInfo *domainInfo);
/* Delete the domain configuration in the specified instance. */
unsigned long KmcRmvDomainMul(WsecHandle kmcCtx, WsecUint32 domainId);

/*
 * This command is used to add the configuration of a specified domain key type in the specified instance.
 * Only the KMC_KEY_TYPE_ENCRPT_INTEGRITY key type can be added.
 */
unsigned long KmcAddDomainKeyTypeMul(WsecHandle kmcCtx, WsecUint32 domainId, const KmcCfgKeyType *keyTypeCfg);

/* Delete the key type configuration of a specified domain in the specified instance. */
unsigned long KmcRmvDomainKeyTypeMul(WsecHandle kmcCtx, WsecUint32 domainId, WsecUint16 keyType);
/*
 * Obtains the number of current domains in the specified instance.
 * If an error occurs, a negative number will be returned.
 */
int KmcGetDomainCountMul(WsecHandle kmcCtx);
/*
 * Obtains the domain configuration information based on idx in the specified instance.
 * This parameter is used together with KmcGetDomainCountMul. The value range of idx is [0, KmcGetDomainCountMul - 1].
 */
unsigned long KmcGetDomainMul(WsecHandle kmcCtx, int idx, KmcCfgDomainInfo *domainInfo);

/* Checking and Updating the Root Key in the specified instance. */
unsigned long KmcAutoUpdateRkMul(WsecHandle kmcCtx, int updateDaysBefore);
/* Updating the Root Key in the specified instance. */
unsigned long KmcUpdateRootKeyMul(WsecHandle kmcCtx, const unsigned char *keyEntropy, WsecUint32 size);
/* Set the default Root Key in the specified instance. */
unsigned long KmcSetDefaultRootKeyCfgMul(WsecHandle kmcCtx, const KmcCfgRootKey *rkCfg);
/* Set the Root Key in the specified instance. The setting takes effect only after the rootkey is updated.  */
unsigned long KmcSetRootKeyCfgMul(WsecHandle kmcCtx, const KmcCfgRootKey *rkCfg);
/* Get the Root Key in the specified instance. */
unsigned long KmcGetRootKeyCfgMul(WsecHandle kmcCtx, KmcCfgRootKey *rkCfg);
/* Get the Root Key info in the specified instance. */
unsigned long KmcGetRootKeyInfoMul(WsecHandle kmcCtx, KmcRkAttributes *rkAttr);

/*
 * Import all MKs in the specified instance. using the password.
 * The imported MKs overwrite the original keystore files in the memory.
 */
unsigned long KmcImportMkFileMul(WsecHandle kmcCtx, const char *fromFile, const unsigned char *password,
    WsecUint32 passwordLen);
/*
 * Export all the current MKs in the specified instance to a file encrypted
 * using the key derived from the password for remote backup.
 */
unsigned long KmcExportMkFileMul(WsecHandle kmcCtx, WsecUint16 mkfVersion, const char *destFile,
    const unsigned char *password, WsecUint32 passwordLen, WsecUint32 iter);
/* Specify the keystore file, import it to the memory MK, and synchronize it to the active and standby KSFs. */
unsigned long KmcImportKsfMul(WsecHandle kmcCtx, const char *keystoreFile, KmcImportKsfCfg *importKsfCfg);
/* Exports a memory key in the specified instance to a specified KSF file. */
unsigned long KmcExportKsfMul(WsecHandle kmcCtx, const char *keystoreFile, KmcExportKsfCfg *exportKsfCfg);
/* Exports special MKs filter by multiple domainIds to keystore file. */
unsigned long KmcBatchExportKsfMul(WsecHandle kmcCtx, const char *keystoreFile, const KmcExportKsfParam *exportParam);

/* Exports special MKs filter by domainIds and keyIds to keystore file. */
unsigned long KmcExportKsfByKeysMul(WsecHandle kmcCtx, const char *keystoreFile,
    const KmcExportKsfByKeysCfg *exportKsfCfg);

/* Stores the KSF of the specified instance to a specified version (V1 or V2). */
unsigned long KmcGenerateKsfAsMul(WsecHandle kmcCtx, WsecUint16 ksfVersion, const char *ksfName);
/*
 * Regenerates a KSF of the specified instance. This function does not change any root key or master key,
 * but only rewrites the memory key to two KSF files.
 */
unsigned long KmcReGenerateKsfMul(WsecHandle kmcCtx);


/* Refresh the MK mask in the memory. The MK is protected by the mask in the memory. */
unsigned long KmcRefreshMkMaskMul(WsecHandle kmcCtx);
/* Automatically check whether each MK in the specified domain expires in the specified instance. */
unsigned long KmcAutoCheckDomainLatestMkMul(WsecHandle kmcCtx, WsecUint32 domainId, int advanceDay,
    WsecBool *hasMkToBeUpdated, KmcMkInfo *mkInfo, int *expireRemainDay);

WsecUint32 KmcGetFaultCodeMul(WsecHandle kmcCtx, WsecUint32 faultType);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* KMC_INCLUDE_KMCV2_MULTITF_H */
