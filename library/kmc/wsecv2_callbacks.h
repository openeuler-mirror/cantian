/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: KMC internal interfaces are not open to external systems.
 * Create: 2018-11-08
 */

#ifndef KMC_SRC_COMMON_WSECV2_CALLBACKS_H
#define KMC_SRC_COMMON_WSECV2_CALLBACKS_H

#include "wsecv2_type.h"
#include "wsecv2_ctx.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Macro */
/* Notification to the app */
#define WSEC_NOTIFY(ctx, notifyCode, data, size) WsecNotify(ctx, (WsecUint32)(notifyCode), data, (size_t)(size))

/* Hand over the execution rights of the CPU. */
#define WSEC_DO_EVENTS(ctx) WsecDoEvents(ctx)

/* Provide Random Number Interface */
WsecBool WsecIsRngSupplied(const KmcCbbCtx *kmcCtx);

/* Sets callback functions. */
/* (Optional) Setting the Memory Operation Callback Function */
unsigned long WsecSetMemCallbacks(KmcCbbCtx *kmcCtx, const WsecMemCallbacks *memCallbacks);

/* (Mandatory) Set the file operation callback function. */
unsigned long WsecSetFileCallbacks(KmcCbbCtx *kmcCtx, const WsecFileCallbacks *fileCallbacks);

/* (Mandatory) Set the thread lock callback function. */
unsigned long WsecSetThreadLockCallbacks(KmcCbbCtx *kmcCtx, const WsecLockCallbacks *lockCallbacks);

/* (Mandatory) Set the process lock callback function. */
unsigned long WsecSetProcLockCallbacks(KmcCbbCtx *kmcCtx, const WsecProcLockCallbacks *procLockCallbacks);

/* (Mandatory) Set the callback function for logs, notifications, and processing time. */
unsigned long WsecSetBasicRelyCallbacks(KmcCbbCtx *kmcCtx, const WsecBasicRelyCallbacks *basicRelyCallbacks);

/*
 * Set the callback function for random number generation
 * and entropy obtaining (either random number obtaining or entropy obtaining)
 */
unsigned long WsecSetRngCallbacks(KmcCbbCtx *kmcCtx, const WsecRngCallbacks *rngCallbacks);

/* (Mandatory) Set the callback function for obtaining the UTC time. */
unsigned long WsecSetTimeCallbacks(KmcCbbCtx *kmcCtx, const WsecTimeCallbacks *timeCallbacks);

/* (Optional) Setting Hardware Access Callback */
unsigned long WsecSetHardwareCallbacks(KmcCbbCtx *kmcCtx, const WsecHardwareCallbacks *hardwareCallbacks);

/* Encapsulate various callbacks. */
/* Memory */
WsecVoid *WsecMalloc(const KmcCbbCtx *kmcCtx, size_t size);

WsecVoid WsecFree(const KmcCbbCtx *kmcCtx, WsecVoid *memBuff);

int WsecMemCmp(const KmcCbbCtx *kmcCtx, const WsecVoid *buffA, const WsecVoid *buffB, size_t count);

/* File */
WsecHandle WsecFopen(const KmcCbbCtx *kmcCtx, const char *filePathName, const KmcFileOpenMode mode);

int WsecFclose(const KmcCbbCtx *kmcCtx, WsecHandle stream);

WsecBool WsecFread(const KmcCbbCtx *kmcCtx, WsecVoid *buffer, size_t count, WsecHandle stream);

WsecBool WsecFwrite(const KmcCbbCtx *kmcCtx, const WsecVoid *buffer, size_t count, WsecHandle stream);

int WsecFflush(const KmcCbbCtx *kmcCtx, WsecHandle stream);

int WsecFremove(const KmcCbbCtx *kmcCtx, const char *path);

long WsecFtell(const KmcCbbCtx *kmcCtx, WsecHandle stream);

long WsecFseek(const KmcCbbCtx *kmcCtx, WsecHandle stream, long offset, KmcFileSeekPos origin);

int WsecFeof(const KmcCbbCtx *kmcCtx, WsecHandle stream, WsecBool *endOfFile);

int WsecFerrno(const KmcCbbCtx *kmcCtx, WsecHandle stream);

unsigned long WsecFileCheck(const KmcCbbCtx *kmcCtx, const char *filePathName, WsecBool *fileExist);

/* Thread lock class. */
unsigned long WsecCreateThreadLock(const KmcCbbCtx *kmcCtx, WsecHandle *mutexObject);

WsecVoid WsecDestroyThreadLock(const KmcCbbCtx *kmcCtx, WsecHandle *mutexObject);

WsecVoid WsecThreadLock(const KmcCbbCtx *kmcCtx, WsecHandle mutexObject);

WsecVoid WsecThreadUnlock(const KmcCbbCtx *kmcCtx, WsecHandle mutexObject);

/* Process lock class. */
unsigned long WsecCreateProcLock(KmcCbbCtx *kmcCtx, WsecHandle *mutexObject);

WsecVoid WsecDestroyProcLock(const KmcCbbCtx *kmcCtx, WsecHandle *mutexObject);

WsecVoid WsecProcLock(const KmcCbbCtx *kmcCtx, WsecHandle mutexObject);

WsecVoid WsecProcUnlock(const KmcCbbCtx *kmcCtx, WsecHandle mutexObject);

/* Encapsulates basic dependency class callback. */
WsecVoid WsecWriteLog(KmcCbbCtx *kmcCtx, int level,
    const char *moduleName,
    const char *filePathName,
    int lineNum,
    const char *logString);

WsecVoid WsecDoEvents(KmcCbbCtx *kmcCtx);

WsecVoid WsecNotify(KmcCbbCtx *kmcCtx, WsecUint32 notifyCode, const WsecVoid *data, size_t dataSize);

/* Random number type 1: A random number generator is invoked to generate random numbers. */
WsecBool WsecGetRandomNumber(const KmcCbbCtx *kmcCtx, unsigned char *buff, size_t buffLen);

/*
 * Random number type 2: calling the external entropy value callback function
 * to obtain the entropy value and destroying the entropy value buffer
 */
WsecBool WsecGetEntropy(const KmcCbbCtx *kmcCtx, unsigned char **entropyBuff, size_t buffLen);

WsecVoid WsecCleanupEntropy(const KmcCbbCtx *kmcCtx, unsigned char *entropyBuff, size_t buffLen);

/* Time class (The gmtime cannot be reentered and can be reentered through callback, for example, linux gmtime_r.) */
WsecBool WsecGmTime(const KmcCbbCtx *kmcCtx, const time_t *curTime, struct tm *curTm);

/* Obtaining Additional Encryption Parameters */
unsigned long WsecHwGetEncExtraData(KmcCbbCtx *kmcCtx, const unsigned char **extraData, unsigned int *extraLen);

/* Obtaining Additional Decryption Parameters */
unsigned long WsecHwGetDecExtraData(KmcCbbCtx *kmcCtx, const unsigned char **extraData, unsigned int *extraLen);

/* Obtains the length of persistent data. */
unsigned long WsecHwGetPersistentDataLen(KmcCbbCtx *kmcCtx, unsigned int *len);

/* Initializing the Hardware Key Manager */
unsigned long WsecHwInitKeyMgr(KmcCbbCtx *kmcCtx, const void *passthroughData, unsigned int passthroughDataLen);

/* Create a new key on the hardware. */
unsigned long WsecHwNewRootKey(KmcCbbCtx *kmcCtx, unsigned char *persistentData, unsigned int *persistentDataLen,
    WsecHandle *handle);

/* Loading Hardware Keys */
unsigned long WsecHwLoadRootkey(KmcCbbCtx *kmcCtx, const unsigned char *persistentData, unsigned int persistentDataLen,
    WsecHandle *handle);

/* Obtains the ciphertext length. */
unsigned long WsecHwGetCipherLen(KmcCbbCtx *kmcCtx, unsigned int plaintextLen, unsigned int *ciphertextLen);

/* Encryption (software-layer root key or master key) */
unsigned long WsecHwEncData(KmcCbbCtx *kmcCtx, WsecHandle handle, const unsigned char *extraData, unsigned int extraLen,
    const WsecPlainCipherBuffs *buffs);

/* Decryption (software-layer root key or master key) */
unsigned long WsecHwDecData(KmcCbbCtx *kmcCtx, WsecHandle handle, const unsigned char *extraData, unsigned int extraLen,
    const WsecPlainCipherBuffs *buffs);

/* Unload hardware root key */
unsigned long WsecHwUnloadKey(KmcCbbCtx *kmcCtx, WsecHandle handle);

/* Removing the Hardware Root Key */
unsigned long WsecHwRemoveKey(KmcCbbCtx *kmcCtx, WsecHandle handle);

/* Deinitializes the hardware key manager. */
unsigned long WsecHwUninitKeyMgr(KmcCbbCtx *kmcCtx);

unsigned long WsecSetAdvanceCallbacks(KmcCbbCtx *kmcCtx, const WsecAdvanceCallbacks *extCallbacks);

unsigned long WsecGenCipher(KmcCbbCtx *kmcCtx, WsecBuff *cipher, const WsecSrkPrimitive *primitives);

unsigned long WsecParseCipher(KmcCbbCtx *kmcCtx, WsecBuffConst *cipher, WsecSrkPrimitive *primitives);

unsigned long WsecsetCipherConf(KmcCbbCtx *kmcCtx, WsecCipherConf *encConf);

unsigned long WsecGetSrkCipherLen(KmcCbbCtx *kmcCtx, unsigned int plaintextLen, unsigned int *ciphertextLen);

WsecUint64 WsecGetTimeTick(KmcCbbCtx *kmcCtx);
#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif /* KMC_SRC_COMMON_WSECV2_CALLBACKS_H */
