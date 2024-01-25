/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2020. All rights reserved.
 * Description: KMC interface header file

 * Create: 2014-06-16

 */

#ifndef KMC_INCLUDE_KMCV2_ITF_H
#define KMC_INCLUDE_KMCV2_ITF_H

#include "wsecv2_type.h"
#include "wsecv2_itf.h"
#include "wsecv2_sync_type.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

/*
 * For KmcExportKsf interface
 */
typedef struct TagKmcExportKsfCfg {
    WsecUint32    domainId;     /* Key Application Scope */
    /* Extended in V3. The domain type can be local domain or shared domain. For details, see KmcDomainType. */
    unsigned char domainType;
    WsecBool      withHw;       /* Whether the MK is protected by hardware */
} KmcExportKsfCfg; /* Parameters for the KMC to export MK interface data */

/* Domain key pair */
typedef struct TagKmcDomainKeyPair {
    WsecUint32  domainId;
    WsecUint32  keyId;
    unsigned char *hashData;
    WsecUint32 hashLen;
} KmcDomainKeyPair;

typedef struct TagKmcExportKsfByKeysCfg {
    KmcDomainKeyPair *pair;
    int  pairCount;
    WsecBool    withHw;       /* Whether the MK is protected by hardware */
} KmcExportKsfByKeysCfg; /* Parameters for the KMC to export MK interface data */

typedef enum {
    KMC_FAULT_CODE_TEE    = 1, /* kmc tee fault code */
} KmcFaultCodeType;

/**
 * For KmcImportKsf interface
 *
 * Interface parameters for importing a specified keystore file to the KMC
 **/
typedef struct TagKmcImportKsfCfg {
    /* Key Application Scope */
    WsecUint32         domainId;
    /* Specifies the keystore file version. For details, see KmcKsfVersion. */
    WsecUint16         ksfVersion;
    /* Extended in V3. The domain type can be local domain or shared domain. For details, see KmcDomainType. */
    unsigned char      domainType;
    /* Indicates whether to overwrite the original action. The options are replace and add. */
    /* For details, see ImportMkActionType. */
    unsigned char      importMkActionType;
} KmcImportKsfCfg;

typedef struct KmcOpMkParamTag {
    int count;
    KmcDomainKeyPair *mkInfos;
} KmcOpMkParam;

typedef struct KmcRmvMkParamTag {
    WsecUint32 domainId;
    int rmvCount;
    int actualRmvCount;
} KmcRmvMkParam;

/* API Function Prototype Description */
/* (1) Key management API */
/* This API is used to delete a key. A key can be deleted only when it is not in the Active state. */
unsigned long KmcRmvMk(WsecUint32 domainId, WsecUint32 keyId);

/**
 * @brief      Update the root key. If this parameter is left blank, the root key will be written into the keystore
 *      file. If this parameter is specified, the root key provided by the upper layer will be used.
 * @param[in]  keyEntropy The entropy value is used as a part of the input to update the root key.
 * @param[in]  size The entropy value of size.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread, file operations and TEE operations (only TEE mode).
 */
unsigned long KmcUpdateRootKey(const unsigned char *keyEntropy, WsecUint32 size);

/**
 * @brief      Obtains the number of keys in the current keystore. This API can be used together with KmcGetMk to
 *      traverse key status.
 * @return     mk count
 * @note
 *  - Memory operation: No.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread.
 */
int KmcGetMkCount(void);

/**
 * @brief      Obtain the key information in the current keystore. The index starts from 0 and the upper limit is
 *  KmcGetDomainCount-1. If the key is modified or deleted during the obtaining process, the key may fail to be
 *  obtained. If this function is used to traverse key information, ensure that other threads do not update or reload
 *  keys during the traversal, In addition, do not change the status of any key or delete or add any key. This function
 *  is used to obtain the mk based on the list of all keys and cannot be used together with KmcGetMkCountByDomain.
 * @param[in]  idx The index starts from 0 and the upper limit is KmcGetDomainCount-1.
 * @param[out] memMk Obtained mk information
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread.
 */
unsigned long KmcGetMk(int idx, KmcMkInfo *memMk);

/**
 * @brief     Obtains the number of keys in the specified domain in the current keystore.
 *          This API cannot be used together with KmcGetMk.
 * @param[in]  domainId the specified domain
 * @return     the number of keys in the specified domain
 * @note
 *  - Memory operation: No.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread.
 */
int KmcGetMkCountByDomain(WsecUint32 domainId);

/**
 * @brief      Delete specific number of oldest inactive mk.
 * @param[in]  domainId the specified domain.
 * @param[in]  rmvCount Number of keys to be deleted.
 * @param[out] actualRmvedCount Number of deleted keys.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: No.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread lock and file write operations.
 */
unsigned long KmcRmvMkByCount(WsecUint32 domainId, int rmvCount, int *actualRmvedCount);

/**
 * @brief      Batch delete specific number of oldest inactive mk in different domains.
 * @param[in]  rmvDomainCount Number of domains to be deleted
 * @param[outin] rmvMkParam The input parameter indicates the ID of the domain and the number of keys to be deleted.
 *      The output parameter actualRmvCount indicates the number of keys to be deleted.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: No.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread lock and file write operations.
 */
unsigned long KmcBatchRmvMkByCount(WsecUint32 rmvDomainCount, KmcRmvMkParam *rmvMkParam);

/**
 * @brief      This interface is used to obtain the maximum key ID of a specified domain.
 * @param[in]  domainId the specified domain.
 * @param[out] maxKeyId the maximum key ID of the domain.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: No.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread.
 */
unsigned long KmcGetMaxMkId(WsecUint32 domainId, WsecUint32 *maxKeyId);

/**
 * @brief      Obtains the minimum key ID of the current specified domain.
 * @param[in]  domainId the specified domain.
 * @param[out] maxKeyId the minimum key ID of the domain.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: No.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread.
 */
unsigned long KmcGetMinMkId(WsecUint32 domainId, WsecUint32 *minKeyId);

/**
 * @brief      This API is used to change the status of a specified key. For a single key, you can change
 *      the status to any specified status, Use this function with caution. If it is used improperly,
 *      multiple valid keys may exist in the same domain. will be written into the keystore file.
 * @param[in]  domainId the specified domain.
 * @param[in]  keyId the specified keyId.
 * @param[in]  status the specified status (must be a value in KmcKeyStatus).
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: No.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread lock and file write operations.
 */
unsigned long KmcSetMkStatus(WsecUint32 domainId, WsecUint32 keyId, unsigned char status);

/*
 * This API is used to obtain the key information of a specified domain ID and key ID,
 * including the original key and basic mapping information.
 * and key status information. The creation and expiration time
 * in the information is obtained based on the local time function,
 * The caller can determine whether the validity period is 180 days by default.
 */
unsigned long KmcGetMkDetail(WsecUint32 domainId, WsecUint32 keyId,
    KmcMkInfo *mkInfo, unsigned char *keyPlaintextBuff, WsecUint32 *keyBuffLen);

/*
 * This interface is used to obtain a valid key in a specified domain. If multiple keys
 * in a domain are valid, any of them can be obtained.
 * This function also returns the status information of the key. The creation time
 * and expiration time in the information is obtained based on the local time function,
 * The invoker can determine whether the certificate is trusted based on the site
 * requirements. The default expiration time is 180 days. If there are multiple certificates in the keystore,
 * This function is used to obtain a random key from the keys
 * with the same domain but different IDs but in valid state.
 */
unsigned long KmcGetActiveMk(WsecUint32 domainId,
    KmcMkInfo *mkInfo, unsigned char *keyPlaintextBuff, WsecUint32 *keyBuffLen);

/* Obtains the hash value of the key based on the specified domain and key ID.
 * The hash value is the first eight bytes of the SHA256 calculation result of the plaintext key.
 */
unsigned long KmcGetMkHash(WsecUint32 domainId, WsecUint32 keyId, unsigned char *hashData, WsecUint32 *hashLen);

/*
 * This interface is used to obtain a key and its status information based on the specified hash value.
 * The creation time and expiration time in the information is based on the following rules.
 * The local time is obtained by the function. The caller can determine whether
 * the default expiration time is 180 days.
 * If multiple keys with different IDs but the same key content exist in the keystore,
 * this function obtains random keys from these keys.
 * A key
 */
unsigned long KmcGetMkDetailByHash(const unsigned char *hashData, WsecUint32 hashLen,
    KmcMkInfo *mkInfo, unsigned char *keyPlaintextBuff, WsecUint32 *keyBuffLen);

/*
 * This interface is used to obtain the status information about a specified key.
 * The creation time and expiration time in the information is obtained based on the local time function.
 * The caller can determine whether the validity period is 180 days by default based on the site requirements.
 * Keys with different IDs but the same key content. This function obtains a random key from these keys.
 */
unsigned long KmcGetMkInfoByContent(const unsigned char *keyPlaintextBuff, WsecUint32 keyLen, KmcMkInfo *mkInfo);

/*
 * This API is used to create a key in a specified internal automatic generation domain
 * and return the corresponding keyId information. The caller does not need to specify the key content.
 * , the created key is in the KMC_KEY_STATUS_TOBEACTIVE state (the key is about to take effect).
 *  If you want to activate it,
 * To activate the key, call KmcActivateMk. After the key is added, the keystore file is written.
 */
unsigned long KmcCreateMkEx(WsecUint32 domainId, WsecUint32 *keyId);

/**
 * @brief      This API is used to batch create keys in corresponding specified internal automatic generation domains
 * and return the corresponding keyId information. The caller does not need to specify the key content.
 * the created keys is in the KMC_KEY_STATUS_TOBEACTIVE state (the key is about to take effect).
 * If you want to activate it,
 * To activate the key, call KmcActivateMk or KmcBatchActivateMk. After the key is added, the keystore file is written.
 * @param[outin]  opMkParam The input parameter count specifies the number of keys to be created.
 * The domain ID specifies the domain to be created. The keyId and hash parameters are output parameters.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread, file operations and TEE operations (only TEE mode).
 */
unsigned long KmcBatchCreateMkEx(const KmcOpMkParam *opMkParam);

/*
 * This API is used to register a key in a specified external import domain. The caller needs to
 * input the content of the registered key. The status of the created key is
 * KMC_KEY_STATUS_TOBEACTIVE (key that is about to take effect). To activate this key, call KmcActivateMk,
 * This function writes the keystore file after a key is added.
 * Note: When registering a key, ensure the randomness of the key. Do not register a key with poor randomness.
 * Otherwise, the key may be
 * Crack: Use functions such as SdpEncryptEx and SdpEncryptWithHmacEx to carry the hash of the registration key
 * in the ciphertext header.
 * Value used to uniquely identify a key. If the registered key is too simple,
 * the original MK may be reversely obtained from the rainbow table. Inside the KMC
 * The number of iteration times for working keys derived from the master key is 1.
 * The interface must use plaintext key data (such as security key) that meets Huawei specifications.
 * (number of devices)
 */
unsigned long KmcRegisterMkEx(WsecUint32 domainId, WsecUint32 keyId,
    const unsigned char *plaintextKey, WsecUint32 keyLen);

unsigned long KmcRegisterCipherMk(WsecUint32 domainId, WsecUint32 keyId, WsecBuffConst *hmac, WsecBuffConst *cipherMk);

/* Activates a specified key. That is, the specified key is valid and all other keys in the same domain are invalid. */
unsigned long KmcActivateMk(WsecUint32 domainId, WsecUint32 keyId);

/**
 * @brief      Batch activate specified keys, Active specified Mk in array.
 * @param[in]  opMkParam count specifies the number of keys to be activated. Domain ID and Key ID specify the
 *  keys to be activated.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread lock and file write operations.
 */
unsigned long KmcBatchActivateMk(KmcOpMkParam *opMkParam);

/* Maximum number of mks. The value cannot be greater than 4096. */
unsigned long KmcSetMkMaxCount(int count);

/*
 * Generate a keystore file based on the specified domain.
 *  The keystore file contains the current master key in the domain. The file name is specified by the product.
 * Note: Do not use the keystore specified when the process initializes the KMC as the file name.
 */
unsigned long KmcGenerateKsfByDomain(WsecUint32 domainId, const char *keystoreFile);

/*
 * Generate a new keystore file that contains all the current master keys of all domains.
 *  The file name is specified by the product.
 * Note: Do not use the keystore specified when the process initializes the KMC as the file name.
 */
unsigned long KmcGenerateKsfAll(const char *keystoreFile);

/*
 * Regenerates a KSF. This function does not change any root key or master key,
 * but only rewrites the memory key to two KSF files.
 * For example, the TPM can invoke this function to write the KMC data protected by
 * the new authorization value to the KSF file after the data authorization value is changed.
 */
unsigned long KmcReGenerateKsf(void);

/*
 * Stores the KSF to a specified version (V1 or V2).
 * Note
 * 1. This interface is used only when KSF V3 needs to be downgraded to KSF V2 or KSF V1 after the upgrade.
 * 2. After the interface is successfully invoked, do not perform any key management operation until
 * the downgrade is complete. Otherwise, the MK will be lost after the downgrade.
 * You are advised to call KmcSecureEraseKeystore to delete the KSF V3 file immediately after
 * the interface is successfully called to avoid information leakage.
 * 3. If the interface fails to be executed, the downgrade cannot be performed. Otherwise,
 * the KMC cannot decrypt data (MK is lost) after the downgrade.
 * 4. KMC 3.0 is upgraded and the hardware root key feature is used.
 * The KSF version is V3, KSF V2 (KMC V2), or KSF V1.
 * (KMC V1) is incompatible. In this scenario, this function must be called to save the KSF file as the source version,
 * Otherwise, KMC 3.0 KSF V3 cannot be parsed after the downgrade.
 * 5. If the source version is KMC V2 and the deployment mode is multi-node or multi-process master/client,
 * After the upgrade,
 * The local domain key cannot be planned because the local domain is available only in KMC 3.0. After the downgrade,
 * the local domain keys of the master and agent are different,
 * Synchronizing the KSF will overwrite the local domain key of the Agent. As a result,
 * the service data cannot be decrypted.
 */
unsigned long KmcGenerateKsfAs(WsecUint16 ksfVersion, const char *ksfName);

/**
 * @brief      Exports a memory key to a specified KSF file.
 * @param[in]  keystoreFile Specifies the path of the file to be exported.
 * @param[in]  exportKsfCfg Specifies the information about the exported ksf file.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread, file operations and TEE operations (only TEE mode).
 */
unsigned long KmcExportKsf(const char *keystoreFile, KmcExportKsfCfg *exportKsfCfg);

/**
 * @brief      Exports special MKs filter by domainIds and keyIds to keystore file.
 * @param[in]  keystoreFile Specifies the path of the file to be exported.
 * @param[in]  exportKsfCfg Specifies the number of keys to be exported and specific key information.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread, file operations and TEE operations (only TEE mode).
 * 1. It will be return fail directly if one of MK exported failure.
 * 2. The MK with status TOBEACTIVE is not allowed to export, Since TOBEACTIVE MK is not used for encryption.
 * 3. If the elements of input param pair in exportKsfCfg is duplicate, duplicate elements will be deduplicated.
 * 4. DO NOT USE THIS INTERFACE IN V1 AND STREAM DATA ENCRYPTION, SINCE THE CIPHER HEADER DOES NOT CONTAIN MK HASH
 */
unsigned long KmcExportKsfByKeys(const char *keystoreFile, const KmcExportKsfByKeysCfg *exportKsfCfg);

/**
 * @brief      Exports special MKs filter by multiple domainIds to keystore file.
 * @param[in]  keystoreFile Specifies the path of the file to be exported.
 * @param[in]  exportParam Specifies the domainIds and ksf version to be exported.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread, file operations and TEE operations (only TEE mode).
 * 1. To export all keys, it only set doaminId to KMC_ALL_DOMAIN and count to 1.
 * 2. If the domainIds of input in exportParam is duplicate, it will return failure.
 */
unsigned long KmcBatchExportKsf(const char *keystoreFile, const KmcExportKsfParam *exportParam);

/**
 * @brief      Specify the keystore file, import it to the memory MK, and synchronize it to the active and standby KSFs.
 * @param[in]  keystoreFile Specifies the path of the file to be imported.
 * @param[in]  importKsfCfg Specifies the information about the imported ksf file.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread, file operations and TEE operations (only TEE mode).
 * 1. Currently, KMC support two import types, IMPORT_MK_ACTION_REPLACE and IMPORT_MK_ACTION_ADD,
 * The type IMPORT_MK_ACTION_REPLACE will fully replace memory MKs with Mks in keystoreFile, and IMPORT_MK_ACTION_ADD
 * will incrementally add MKs in keystoreFile to memory without overwrite the origin memory MKs.
 * 2. You can import special domain or all domain in keystoreFile. For all domain import, you can set domainid equals
 * KMC_ALL_DOMAIN.
 * 3. You can also import MKs filter by domainType,domainType can value in KMC_DOMAIN_TYPE_SHARE,KMC_DOMAIN_TYPE_LOCAL,
 * KMC_DOMAIN_TYPE_IGNORE. Both share and local domain will be import if the type set to KMC_DOMAIN_TYPE_IGNORE.
 * It will treat as shared domain MKs if the domain of the MKs is not create in KMC. So the MKs whose domain is not
 * create will not import to memory keystore if domain type set to LOCAL, but the Mks will import to memory if domain
 * type set to SHARE or IGNORE.
 */
unsigned long KmcImportKsf(const char *keystoreFile, KmcImportKsfCfg *importKsfCfg);

/*
 * Check the integrity of the keystore file. This operation can be performed only on the Master node.
 * Check whether the keystore file is complete. If the file is damaged,
 * You can use the rewriteErrorCode parameter to determine whether to rewrite the keystore.
 * Check whether the rewriting is successful.
 * Note: Rewriting will cause the original key data in the rewritten keystore to be lost,
 * historical data cannot be decrypted, and the keystore cannot be used.
 * The cause of file integrity damage cannot be located. If the application specifies rewriting,
 * the rewriting logic is as follows,
 * (1) If a keystore file is valid, overwrite it with a valid one.
 * (2) If the two files are invalid, rewrite the two files using the memory MK.
 */
unsigned long KmcCheckKeyStore(WsecBool rewriteOnCheckFail, unsigned long *rewriteErrorCode);

/**
 * @brief      Obtains the status of the key with a specified domain ID and key ID.
 * @param[in]  domainId Specifies the domain ID to be obtained.
 * @param[in]  keyId Specifies the key ID to be obtained.
 * @param[out] status Obtained key status (value in KmcKeyStatus).
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread lock.
 */
unsigned long KmcGetMkStatus(WsecUint32 domainId, WsecUint32 keyId, unsigned char *status);

/*
 * Erase all keys, including the key information in the keystore file and memory,
 * for board recycling. Exercise caution when performing this operation.
 */
unsigned long KmcSecureEraseKeystore(void);

/*
 * Refresh the MK mask in the memory. The MK is protected by the mask in the memory.
 * The mask needs to be refreshed periodically. You are advised to enable the cyclic function.
 * Timer. After initialization, this function is called periodically.
 * It is recommended that this function be called once an hour.
 */
/**
 * @brief   Refresh the MK mask in the memory.
 * @return  WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: no allocate memory.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    no OS difference.
 *  - Time consuming:   Yes, related to thread.
 */
unsigned long KmcRefreshMkMaskEx(void);

/* (2) Configure the API. */
/*
 * The default configuration of the root key in the KMC is as follows
 * The validity period is 3650 days, and the number of iterations is 10000.
 * This function can be used to modify the default rootkey configuration.
 * The modification takes effect after the function is called and takes effect when the current process exits.
 * The configuration of also becomes invalid. This function can be called before WsecInitializeEx
 * to set the default rootkey configuration.
 * After this function is set, it is valid for the root key generated during subsequent initialization.
 * If the application calls this function, it does not call this function any more.
 * If the configuration of KmcSetRootKeyCfg is modified, the invocation of this function is also valid
 * for updating the root key. If after initialization,
 * KmcSetRootKeyCfg needs to be called to modify the rootkey configuration in state.
 * When the WsecResetEx function is called, this function is used to set
 * The default configuration of still takes effect. However, the configurations generated
 * by other configuration functions are invalid and need to be reconfigured.
 * Note: The greater the number of iterations, the more difficult the brute force cracking is theoretically.
 * This function does not verify the upper limit of rkCfg iterations,
 * However, if the number of iterations is too large, the key derivation time is long.
 * Therefore, you must limit the maximum number of iterations based on the site requirements.
 * Otherwise, DoS attacks may occur.
 */

/**
* @brief      set default configuration of the root key in the KMC.
* @param[in]  rkCfg The default configuration of the root key in the KMC, see detail in KmcCfgRootKey.
* @return     WSEC_SUCCESS on success, other error code on failure.
* @note
*  - Memory operation: no allocate memory.
*  - Thread safe:      Non-Thread-safe function, will modifiy global variables.
*  - OS difference:    No OS difference.
*  - Time consuming:   no consuming operation.
*/
unsigned long KmcSetDefaultRootKeyCfg(const KmcCfgRootKey *rkCfg);

/* Sets the rootkey. The setting takes effect only after the rootkey is updated. */
unsigned long KmcSetRootKeyCfg(const KmcCfgRootKey *rkCfg);

/* Obtains the current settings. */
unsigned long KmcGetRootKeyCfg(KmcCfgRootKey *rkCfg);

/* Obtaining the Attributes of the Current Root Key */
unsigned long KmcGetRootKeyInfo(KmcRkAttributes *rkAttr);

/* Add Domain Configuration */
/**
* @brief     Add Domain Configuration.
* @param[in] domainInfo to be added domain configuration.
* @return    WSEC_SUCCESS on success, other error code on failure.
* @note
*  - Memory operation: no allocate memory.
*  - Thread safe:      Thread-safe function.
*  - OS difference:    no OS difference.
*  - Time consuming:   Yes, related to thread.
*/
unsigned long KmcAddDomainEx(const KmcCfgDomainInfo *domainInfo);

/* Delete the domain configuration. */
/**
* @brief     Delete the domain configuration.
* @param[in] domainId the ID of the domain to be deleted.
* @return    WSEC_SUCCESS on success, other error code on failure.
* @note
*  - Memory operation: no allocate memory.
*  - Thread safe:      Thread-safe function.
*  - OS difference:    no OS difference.
*  - Time consuming:   Yes, related to thread.
*/
unsigned long KmcRmvDomainEx(WsecUint32 domainId);

/*
 * This command is used to add the configuration of a specified domain key type.
 * the KMC_KEY_TYPE_ENCRPT_INTEGRITY、KMC_KEY_TYPE_ASYM_ENCRYPT_DECRYPT、KMC_KEY_TYPE_ASYM_SIGN_VERIFY key type can
 * be added.
 */
/**
* @brief     add the configuration of a specified domain key type.
* @param[in] domainId the ID of the domain.
* @param[in] keyTypeCfg domain key type configuration, the KMC_KEY_TYPE_ENCRPT_INTEGRITY、
*            KMC_KEY_TYPE_ASYM_ENCRYPT_DECRYPT、KMC_KEY_TYPE_ASYM_SIGN_VERIFY key type can be added.
* @return    WSEC_SUCCESS on success, other error code on failure.
* @note
*  - Memory operation: no allocate memory.
*  - Thread safe:      Thread-safe function.
*  - OS difference:    no OS difference.
*  - Time consuming:   Yes, related to thread.
*/
unsigned long KmcAddDomainKeyTypeEx(WsecUint32 domainId, const KmcCfgKeyType *keyTypeCfg);

/* Delete the key type configuration of a specified domain. */
/**
* @brief     Delete the key type configuration of a specified domain.
* @param[in] domainId the ID of the domain.
* @param[in] keyType the kye type configuration to be deleted.
* @return    WSEC_SUCCESS on success, other error code on failure.
* @note
*  - Memory operation: no allocate memory.
*  - Thread safe:      Thread-safe function.
*  - OS difference:    no OS difference.
*  - Time consuming:   Yes, related to thread.
*/
unsigned long KmcRmvDomainKeyTypeEx(WsecUint32 domainId, WsecUint16 keyType);

/* Obtains the number of current domains. If an error occurs, a negative number is returned. */
int KmcGetDomainCount(void);

/*
 * Obtains the domain configuration information based on idx.
 * This parameter is used together with KmcGetDomainCount. The value range of idx is [0, KmcGetDomainCount - 1].
 * Note: If this function is used to traverse the domain information, ensure that
 * other threads do not update or reload the domain during the traversal,
 * Do not change the status of any domain, or delete or add a domain.
 */
unsigned long KmcGetDomain(int idx, KmcCfgDomainInfo *domainInfo);

/*
 * Export all the current MKs to a file encrypted using the key derived from the password for remote backup.
 * Note: The greater the number of iterations, the more difficult the brute force cracking is theoretically.
 * This function does not verify the upper limit of the number of iterations, but
 * If the generation times are too large, the key derivation time will be long.
 * Therefore, you must limit the maximum generation times based on the site requirements,
 * Otherwise, DoS attacks may occur.
 */
unsigned long KmcExportMkFileEx(WsecUint16 mkfVersion,
    const char *destFile,
    const unsigned char *password, WsecUint32 passwordLen,
    WsecUint32 iter);

/*
 * Import all MKs using the password. The imported MKs overwrite the original keystore files in the memory.
 * The keystore files are used for remote backup encryption.
 * Restore the local keystore file. Exercise caution when performing this operation.
 */
unsigned long KmcImportMkFileEx(const char *fromFile, const unsigned char *password, WsecUint32 passwordLen);

/* Obtains the number of iterations for updating the keystore in the current memory. */
unsigned long KmcGetUpdateNumFromMem(WsecUint32 *updateCounter);

/* Obtains the number of update iterations of a specified ksf file. */
unsigned long KmcGetUpdateNumFromFile(const char *keystoreFile, WsecUint32 *updateCounter);

/* Obtains the number of iterations for updating the shared key in the current memory. */
unsigned long KmcGetSharedMkUpdateNumFromMem(WsecUint32 *updateCounter);

/* Obtains the number of iterations for updating the shared key of a specified ksf file. */
unsigned long KmcGetSharedMkUpdateNumFromFile(const char *keystoreFile, WsecUint32 *updateCounter);

/**
 * Configure msg send interface.
 * NOTE: The communitation channel must be bidirectional. Must be called by master
 * [in] param: communitation channel handle，such as socket fd.
 * [in] sendSyncData, recvSyncData: send and recv function
 */
unsigned long KmcMasterSendCnf(WsecVoid *param,
    const CallbackSendSyncData sendSyncData, const CallbackRecvSyncData recvSyncData);

/**
 * Configure msg recv interface.
 * NOTE: The communitation channel must be bidirectional. Must be called by agent
 * [out] ctx: store recved configure information，must be call KmcAgentRecvCnfFinal to free ctx
 * [in] param: communitation channel handle，such as socket fd.
 * [in] sendSyncData, recvSyncData: send and recv function
 */
unsigned long KmcAgentRecvCnf(WsecHandle *ctx,
    WsecVoid *param, const CallbackSendSyncData sendSyncData, const CallbackRecvSyncData recvSyncData);

/**
 * Free ctx create by KmcAgentRecvCnf
 */
void KmcAgentRecvCnfFinal(const WsecHandle *ctx);

/**
 * Agent MK recv interface, sync msg stream：header + mks + hash.
 * NOTE: The communitation channel can be unidirectional (master to agent)
 * [in] ctx: recved configure context, create by KmcAgentRecvCnf，must be call KmcAgentRecvCnfFinal to free ctx
 * [out] syncInfo: recvd domainId info
 * [in] recvMode: agent recv domain mode
 *                if recvMode is KMC_ALL_DOMAIN, must used with KmcMasterSendAllMk, domainArray can be NULL.
 *                if recvMode is KMC_BATCH_DOMAIN, must used with KmcMasterSendMkByDomain, domainArray.count
 *                  must specified by caller and cannot exceed 1024.
 *                if recvMode is KMC_SINGLE_DOMAIN, must used with KmcMasterSendMkByDomain, domainArray.count must be 1.
 * [in] param: communitation channel handle，such as socket fd.
 * [in] sendSyncData, recvSyncData: send and recv function
 */
unsigned long KmcAgentRecvMkEx(WsecHandle ctx, KmcRecvSyncInfo *syncInfo, KmcDomainOpMode recvMode,
    WsecVoid *param, const CallbackRecvSyncData recvSyncData);

/* MASTER: indicates that the AGENT sends all shared master keys. */
unsigned long KmcMasterSendAllMk(WsecVoid *param, CallbackSendSyncData sendSyncData);

/* The AGENT receives all shared master keys from the master. */
unsigned long KmcAgentRecvAllMk(WsecVoid *param, CallbackRecvSyncData recvSyncData);

/* Master send special shared MK to Agent by domain */
unsigned long KmcMasterSendMkByDomain(WsecUint32 domainId, WsecVoid *param, CallbackSendSyncData sendSyncData);

/* Agent Recv special shared MK from master by domain */
unsigned long KmcAgentRecvMkByDomain(WsecUint32 *domainId, WsecVoid *param, CallbackRecvSyncData recvSyncData);

/* Master send special shared MK to Agent by domain list */
unsigned long KmcMasterBatchSendMk(const KmcDomainArray *domainArray,
    WsecVoid *param, CallbackSendSyncData sendSyncData);

/* Agent Recv special shared MK from master by domain list */
unsigned long KmcAgentBatchRecvMk(KmcRecvSyncInfo *syncInfo, WsecVoid *param, CallbackRecvSyncData recvSyncData);

/**
 * @brief      create sync configure information.
 * @param[out] syncCtx sync ctx, must be call KmcFinalSyncCtx to free ctx.
 * @param[in]  sendParam communitation channel handle，such as socket fd.
 * @param[in]  syncSend send function.
 * @param[in]  recvParam communitation channel handle，such as socket fd.
 * @param[in]  syncRecv recv function.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate memory by itself, must be call KmcFinalSyncCtx to free memory.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    no OS difference.
 *  - Time consuming:   no consuming operation.
 */
unsigned long KmcCreateSyncCtx(WsecHandle *syncCtx, WsecVoid *sendParam, CallbackSendSyncData syncSend,
    WsecVoid *recvParam, CallbackRecvSyncData syncRecv);

/**
 * @brief      set whether the peer has the negotiation capability.
 * @param[in]  syncCtx sync ctx, create in KmcCreateSyncCtx.
 * @param[in]  isNego WSEC_TRUE or WSEC_FALSE, set whether the peer has the negotiation capability.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: no allocate memory.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    no OS difference.
 *  - Time consuming:   no consuming operation.
 */
unsigned long KmcSetNegoCapability(WsecHandle syncCtx, WsecBool isNego);

/**
 * @brief     Check whether the current version has the negotiation capability.
 * @return    WSEC_TRUE or WSEC_FALSE, whether the current version has the negotiation capability.
 * @note
 *  - Memory operation: no allocate memory.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    no OS difference.
 *  - Time consuming:   no consuming operation.
 */
WsecBool KmcHasNegoCapability(void);

/**
 * @brief      Sets the negotiation capability set. By default, the negotiation capability sets is available.
 * If no negotiation capability set is available, the product needs to invoke this interface to set the negotiation
 * capability set.
 * @param[in]  syncCtx sync ctx, create in KmcCreateSyncCtx.
 * @param[in]  ctrlParam infos of dh algs and whether has safe channel to decide whether send Asymmetric key.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: no allocate memory.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    no OS difference.
 *  - Time consuming:   Yes, related to TEE operations (only TEE mode).
 */
unsigned long KmcSetSyncCtrlParam(WsecHandle syncCtx, const KmcSyncCtrlParam *ctrlParam);

/**
 * @brief      key send interface.
 * @param[in]  syncCtx sync ctx, create in KmcCreateSyncCtx.
 * @param[in]  syncParam infos of send key.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    no OS difference.
 *  - Time consuming:   Yes, related to thread and TEE operations (only TEE mode).
 */
unsigned long KmcSyncSendKey(WsecHandle syncCtx, KmcSyncParam *syncParam);

/**
 * @brief      key recv interface.
 * @param[in]  syncCtx sync ctx, create in KmcCreateSyncCtx.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    no OS difference.
 *  - Time consuming:   Yes, related to thread, file operations and TEE operations (only TEE mode).
 */
unsigned long KmcSyncRecvKey(WsecHandle syncCtx);

/**
 * @brief      get key recv info interface.
 * @param[in]  syncCtx sync ctx, create in KmcCreateSyncCtx.
 * @param[out] syncInfo key infos of recv.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: no allocate memory.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    no OS difference.
 *  - Time consuming:   no consuming operation.
 */
unsigned long KmcGetRecvResult(WsecHandle syncCtx, KmcRecvSyncInfo *syncInfo);

/**
 * @brief     free ctx, allocate in KmcCreateSyncCtx.
 * @param[in] syncCtx sync ctx, create in KmcCreateSyncCtx.
 * @return    WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: no allocate memory.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    no OS difference.
 *  - Time consuming:   no consuming operation.
 */
unsigned long KmcFinalSyncCtx(WsecHandle syncCtx);

/* Obtains the current system UTC. */
WsecBool KmcGetUtcDateTime(WsecSysTime *nowUtc);

/* Obtains the number of days between two time points. */
WsecBool KmcDateTimeDiffDay(const WsecSysTime *startTime, const WsecSysTime *endTime, int *day);

/* Checking and Updating the Root Key */
/**
* @brief     Checking and Updating the Root Key.
* @param[in] updateDaysBefore Update a few days before expiration.
* @return    WSEC_SUCCESS on success, other error code on failure.
* @note
*  - Memory operation: no allocate memory.
*  - Thread safe:      Thread-safe function.
*  - OS difference:    no OS difference.
*  - Time consuming:   Yes, related to thread, file operations and TEE operations (only TEE mode).
*/
unsigned long KmcAutoUpdateRk(int updateDaysBefore);

/* Automatically check whether each MK in the specified domain expires. */
unsigned long KmcAutoCheckDomainLatestMk(WsecUint32 domainId, int advanceDay, WsecBool *hasMkToBeUpdated,
    KmcMkInfo *mkInfo, int *expireRemainDay);

/* Get single instance ctx */
void *KmcGetSingleKmcCtx(void);

/**
* @brief      Check whether the memory configuration is same with the keystore configuration.
* @param[out] isSame whether the memory configuration is same with the keystore configuration.
* @return     WSEC_SUCCESS on success, other error code on failure.
* @note
*  - Memory operation: no allocate memory.
*  - Thread safe:      Thread-safe function.
*  - OS difference:    no OS difference.
*  - Time consuming:   Yes, related to thread, file operations and TEE operations (only TEE mode).
*/
unsigned long KmcIsMemAndKsfCnfSame(WsecBool *isSame);

/**
 * @brief      Obtains the version number of a specified kestore file.
 * @param[in]  filePathName  Specifies the kestore file path. The master cannot be null. The backup and keyStoreBackup
               can be null. If backup is null, keyStoreBackup is not checked.
 * @param[out] ksfVersion Indicates the obtained ksf version(a value in KmcKsfVersion).
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Non-thread-safe function, if kmc already init and ksfPath is same.
 *  - OS difference:    No.
 *  - Time consuming:   No.
 */
unsigned long KmcGetKsfVersion(const KmcKsfName *filePathName, WsecUint16 *ksfVersion);

WsecUint32 KmcGetFaultCode(WsecUint32 faultType);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* KMC_INCLUDE_KMCV2_ITF_H */
