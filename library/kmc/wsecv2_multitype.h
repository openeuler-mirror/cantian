/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: MultiInstance type definition
 * Create: 2021-08-16
 * History: None
 */

#ifndef KMC_INCLUDE_WSECV2_MULTITYPE_H
#define KMC_INCLUDE_WSECV2_MULTITYPE_H

#include "wsecv2_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Macro Definition */
/* File macro redefinition */
#ifndef WSEC_DEBUG
#define WSEC_KMC_FILE ""
#else
#define WSEC_KMC_FILE __FILE__
#endif

/* WsecBasicRelyCallbacks */
typedef WsecVoid (*CallbackWriteLogMulti)(void *userData, int level, const char *moduleName, const char *filePathName,
    int lineNum, const char *logString);
typedef WsecVoid (*CallbackNotifyMulti)(WsecVoid *userData, WsecUint32 notifyCode, const WsecVoid *data,
    size_t dataSize);
typedef WsecVoid (*CallbackDoEventsMulti)(WsecVoid *userData);

/* WsecProcLockCallbacks */
typedef WsecBool (*CallbackCreateProcLockMulti)(WsecVoid *userData, WsecHandle *mutexObject);

/*
 * Implementation of the callback function for obtaining additional data. This function is used by the KMC
 * to obtain additional data for encryption and decryption. Generally, this function is provided or changed by KMC users
 */
typedef unsigned long (*CallbackHwGetEncExtraDataMulti)(void *userData, const unsigned char **extraData,
    unsigned int *extraLen);
typedef unsigned long (*CallbackHwGetDecExtraDataMulti)(void *userData, const unsigned char **extraData,
    unsigned int *extraLen);

/*
 * Hardware adaptation layer: secure hardware key management interface,
 * which is used by the KMC to call secure hardware to encrypt KMC data.
 */
typedef unsigned long (*CallbackHwGetPersistentDataLenMulti)(void *userData, unsigned int *len);
typedef unsigned long (*CallbackHwInitKeyMgrMulti)(void *userData, const void *passthroughData,
    unsigned int passthroughDataLen);
typedef unsigned long (*CallbackHwNewRootKeyMulti)(void *userData, unsigned char *persistentData,
    unsigned int *persistentDataLen, WsecHandle *handle);
typedef unsigned long (*CallbackHwLoadRootkeyMulti)(void *userData, const unsigned char *persistentData,
    unsigned int persistentDataLen, WsecHandle *handle);
typedef unsigned long (*CallbackHwGetCipherLenMulti)(void *userData, unsigned int plaintextLen,
    unsigned int *ciphertextLen);
typedef unsigned long (*CallbackHwEncDataMulti)(void *userData, WsecHandle handle, const unsigned char *extraData,
    unsigned int extraLen, const WsecPlainCipherBuffs *buffs);
typedef unsigned long (*CallbackHwDecDataMulti)(void *userData, WsecHandle handle, const unsigned char *extraData,
    unsigned int extraLen, const WsecPlainCipherBuffs *buffs);
typedef unsigned long (*CallbackHwUnloadKeyMulti)(void *userData, WsecHandle handle);
typedef unsigned long (*CallbackHwRemoveKeyMulti)(void *userData, WsecHandle handle);
typedef unsigned long (*CallbackHwUninitKeyMgrMulti)(void *userData);

/* Structure of the basic system callback function */
typedef struct TagWsecBasicRelyCallbacksMulti {
    CallbackWriteLogMulti writeLog;
    CallbackNotifyMulti notify;
    CallbackDoEventsMulti doEvents;
} WsecBasicRelyCallbacksMulti;

/* Structure of the System Process Lock Callback Function */
typedef struct TagWsecProcLockCallbacksMulti {
    CallbackCreateProcLockMulti createProcLock;
    CallbackDestroyProcLock destroyProcLock;
    CallbackProcLock procLock;
    CallbackProcUnlock procUnlock;
} WsecProcLockCallbacksMulti;

/* Hardware root key access callback function */
typedef struct TagWsecHardwareCallbacksMulti {
    CallbackHwGetEncExtraDataMulti hwGetEncExtraData;
    CallbackHwGetDecExtraDataMulti hwGetDecExtraData;
    CallbackHwGetPersistentDataLenMulti hwGetPersistentDataLen;
    CallbackHwInitKeyMgrMulti hwInitKeyMgr;
    CallbackHwNewRootKeyMulti hwNewRootKey;
    CallbackHwLoadRootkeyMulti hwLoadRootkey;
    CallbackHwGetCipherLenMulti hwGetCipherLen;
    CallbackHwEncDataMulti hwEncData;
    CallbackHwDecDataMulti hwDecData;
    CallbackHwUnloadKeyMulti hwUnloadKey;
    CallbackHwRemoveKeyMulti hwRemoveKey;
    CallbackHwUninitKeyMgrMulti hwUninitKeyMgr;
} WsecHardwareCallbacksMulti;

/* All callback functions */
typedef struct TagWsecCallbacksMulti {
    WsecMemCallbacks memCallbacks;
    WsecFileCallbacks fileCallbacks;
    WsecLockCallbacks lockCallbacks;
    WsecProcLockCallbacksMulti procLockCallbacks;
    WsecBasicRelyCallbacksMulti basicRelyCallbacks;
    WsecRngCallbacks rngCallbacks;
    WsecTimeCallbacks timeCallbacks;
    WsecHardwareCallbacksMulti hardwareCallbacks;
} WsecCallbacksMulti;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* KMC_INCLUDE_WSECV2_MULTITYPE_H */
