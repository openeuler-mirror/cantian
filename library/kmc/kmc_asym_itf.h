/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: KMC asym interface

 * Create: 2022-8-25
 * Notes: New Create
 */

#ifndef KMC_INCLUDE_KMC_ASYM_ITF_H
#define KMC_INCLUDE_KMC_ASYM_ITF_H

#include "wsecv2_config.h"
#if WSEC_COMPILE_ENABLE_ASYM

#include "kmc_asym_type.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @brief      Create asym key on specific domainId and key spec (must be a value in WsecKeySpec)
 * @param[in]  keyParams configuration of key to create, need allocate memory by caller.
 * @param[out] keyInfos  infos of created keys when success, need allocate memory (involving pub key buff) by caller.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread, file operations and TEE operations (only TEE mode).
 */
unsigned long KmcGenerateAsymKey(const KmcGenAsymParamList *keyParams, KmcAsymKeyInfoList *keyInfos);

/**
 * @brief      Activate asym key by key index
 * @param[in]  keyParamList configure of key to activate, need allocate memory by caller.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread lock and file write operations.
 */
unsigned long KmcActivateAsymKey(const KmcAsymIdxList *keyParamList);

/**
 * @brief      Get Public key by key index
 * @param[in]  keyParam indexes of public key to get, need allocate memory by caller.
 * @param[out] keyInfos infos of public key, need allocate memory by caller.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread lock.
 */
unsigned long KmcGetPublicKey(KmcPubKeyIdx *keyParam, KmcPubKeyInfo *pubKeyInfo);

/**
 * @brief      Get asym key's status (KmcKeyStatus)
 * @param[in]  domainId  domain ID of key.
 * @param[in]  keyId     key ID of key.
 * @param[out] keyStatus status of key, its type must be a value in KmcKeyStatus, need allocate memory by caller.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread lock.
 */
unsigned long KmcGetAsymKeyStatus(WsecUint32 domainId, WsecUint32 keyId, WsecUint32 *keyStatus);

/**
 * @brief      Get asym key info by key ID
 * @param[in]  domainId  domain ID of key.
 * @param[in]  keyId     key ID of key.
 * @param[out] key       infos of key, need allocate memory by caller.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread lock.
 */
unsigned long KmcGetAsymKeyInfo(WsecUint32 domainId, WsecUint32 keyId, KmcAsymKeyInfo *key);

/**
 * @brief      Get active asym key by domain ID
 * @param[in]  domainId   domain ID of key.
 * @param[out] activeInfo info of active key, need allocate memory by caller.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread lock.
 */
unsigned long KmcGetActiveKeyInfo(WsecUint32 domainId, KmcAsymActiveInfo *activeInfo);

/**
 * @brief      Remove non-active asym key by key index
 * @param[in]  keyIdxList  info of keys to remove.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread lock and file write operations.
 */
unsigned long KmcRmvAsymKeyByIdx(const KmcAsymIdxList *keyIdxList);

/**
 * @brief      Remove non-active asym key by count
 * @param[in]  domainList  domain info of keys to remove.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread lock and file write operations.
 */
unsigned long KmcRmvAsymKeyByCount(const KmcRmvAsymDomainList *domainList);

/**
 * @brief      Get Public key len by key spec
 * @param[in]  keySpec   spec of public key, must be a value in WsecKeySpec.
 * @param[out] pubKeyLen length of public key with specific key spec, need allocate memory by caller.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   No.
 */
unsigned long KmcGetPubKeyLen(WsecUint16 keySpec, WsecUint32 *pubKeyLen);

/**
 * @brief      Update asym key's protect key
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread, file operations and TEE operations (only TEE mode).
 */
unsigned long KmcUpdateAsymProtectKey(void);

/**
 * @brief      Change the status of a specified key to any specified status within range of KmcKeyStatus
 * @param[in]  keyIdx index of key, need allocate memory by caller.
 * @param[out] status status to change, its type must be a value in KmcKeyStatus.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread lock and file write operations.
 */
unsigned long KmcSetAsymStatus(const KmcAsymIdx *keyIdx, unsigned char status);

/**
 * @brief      Check whether the public and private keys match.
 * @param[in]  keyPair index of key pair, need allocate memory by caller.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread lock.
 */
unsigned long KmcCheckKeyPair(const KmcAsymKeyPair *keyPair);

/**
 * @brief      Get asym key count by specific domain
 * @param[in]  domainId domain ID
 * @param[out] keyCount count of asym key, need allocate memory by caller.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread lock.
 */
unsigned long KmcGetAsymKeyCountByDomain(WsecUint32 domainId, int *keyCount);

#ifdef __cplusplus
}
#endif // __cplusplus


#endif // WSEC_COMPILE_ENABLE_ASYM

#endif // KMC_INCLUDE_KMC_ASYM_ITF_H
