/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2020. All rights reserved.
 * Description: external interface

 * Create: 2014-06-16

 */

#ifndef KMC_INCLUDE_WSECV2_ITF_H
#define KMC_INCLUDE_WSECV2_ITF_H

#include "wsecv2_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WSEC_FILEPATH_MAX_LEN 260 /* Maximum length of a file path. */
#define KMC_VERSION "KMC 23.0.0"

#pragma pack(1)
typedef struct KmcInitHardWareParamTag {
    WsecBool hasSoftLevelRk;
    const WsecVoid *hardwareParam;
    WsecUint32 hardwareParamLen;
    unsigned char reserve[12];
} KmcInitHardWareParam;
#pragma pack()

#pragma pack(1)
typedef struct KmcRecoverParamTag {
    /* enableThirdBackup is set to WSEC_TRUE KmcKsfName.keyStoreBackupFile
     * must provided */
    WsecBool enableThirdBackup;
    /* deleted KSF when init failed : if custom backup ksf exists
     * do not set this flag KMC will keep ksf for manual recover */
    WsecBool deleteKsfOnInitFailed;
    unsigned char reserve[8];
} KmcRecoverParam;
#pragma pack()

/**
 * For WsecInitializeEx/WsecInitializeHw exParam
 * can be NULL
 **/
typedef struct TagWsecExtendInitParam {
    /* enableThirdBackup is set to WSEC_TRUE KmcKsfName.keyStoreBackupFile
     * must provided */
    WsecBool enableThirdBackup;
    /* deleted KSF when init failed : if custom backup ksf exists
     * do not set this flag KMC will keep ksf for manual recover */
    WsecBool deleteKsfOnInitFailed;
} WsecExtendInitParam;

#pragma pack(1)
typedef struct TagKmcAlgCnfParam {
    WsecUint32 symmAlg;
    WsecUint32 kdfAlg;
    WsecUint32 hmacAlg;
    WsecUint32 hashAlg;
    WsecUint32 workKeyIter;
    WsecUint32 saltLen;
    unsigned char reserve[16];
} KmcAlgCnfParam;
#pragma pack()

#pragma pack(1)
typedef struct KmcInitParamTag {
    WsecUint32 roleType;
    const KmcKsfName *filePathName;
    WsecBool enableHw;
    KmcInitHardWareParam *hwParam;
    KmcRecoverParam *recoverParam;
    KmcAlgCnfParam *algCnfParam;
    unsigned char type; /* type of TEE */
    unsigned char keyStoreMode;
    WsecUint32 version;
    unsigned char reserve[14];
    WsecUint32 extLen;
    unsigned char extParam[];
} KmcInitParam;
#pragma pack()

#pragma pack(1)
typedef struct TagKmcTeeInitParam {
    WsecUint32 timeLow;
    WsecUint16 timeMid;
    WsecUint16 timeHiAndVersion;
    WsecUint8 clockSeqAndNode[8];
    unsigned char *taPath;
} KmcTeeInitParam;
#pragma pack()

#pragma pack(1)
typedef struct TagKmcInitExtParamV1 {
    KmcTeeInitParam teeInitParam;
    WsecUint32 teeRootFrom; // 0:KMC default key, 1: userDefineKey
    const KmcKsfName *asymFileName;
} KmcInitExtParamV1;
#pragma pack()

#pragma pack(1)
typedef struct TagWsecScheduleTime {
    /* Hour (0-23) */
    unsigned char kmcHour;
    /* Minute (0 to 59) */
    unsigned char kmcMinute;
    /* Day of a week. The value ranges from 1 to 7,
     * indicating Monday to Sunday. 1-7: every day
     */
    unsigned char kmcWeek;
    unsigned char kmcPadding;
    unsigned char reserve[4]; /* 4 bytes are reserved. */
} WsecScheduleTime;
#pragma pack()

#pragma pack(1)
typedef struct TagKmcCfgKeyManagement {
    /* Number of days in advance users are notified that a key is about to expire */
    WsecUint32       warningBeforeKeyExpiredDays;
    /* Grace period for using an expired key.
     * If the grace period expires, the app is notified.
     * */
    int              graceDaysForUseExpiredKey;
    /* Indicates whether to automatically update the key when the key expires. */
    /* This parameter is valid for the root key and the MK whose KeyFrom is 0. */
    WsecBool         keyAutoUpdate;
    /* Automatic key update time */
    WsecScheduleTime autoUpdateKeyTime;
    /* Reserved 8 bytes */
    unsigned char    reserve[8];
} KmcCfgKeyManagement; /* Key management parameters */
#pragma pack()
#pragma pack(1)
typedef struct TagWsecCipherConf {
    WsecUint32 version;
    WsecUint32 pbkdfAlgId;
    WsecUint32 deriverKeyLen;
    WsecUint32 iter;
    WsecUint32 materialLen;
    WsecUint32 saltLen;
    WsecUint32 encAlgId;
    WsecUint32 ivLen;
} WsecCipherConf;
#pragma pack()

#pragma pack(1)
typedef struct TagWsecPerConf {
    WsecUint32 syncTimeLimit;
    WsecUint32 ioTimeLimit;
    WsecUint32 hwTimeLimit;
    WsecUint32 teeTimeLimit;
    unsigned char resv[36];
} WsecPerConf;
#pragma pack()

typedef unsigned long(*CallbackGenCipher)(const WsecSrkPrimitive *primitives, WsecBuff *cpiher);
typedef unsigned long(*CallbackParseCipher)(WsecBuffConst *cpiher, WsecSrkPrimitive *primitives);
typedef unsigned long(*CallbackGetCipherConf)(WsecCipherConf *encConf);
typedef unsigned long(*CallbackGetCipherLen)(unsigned int plaintextLen, unsigned int *ciphertextLen);
typedef WsecUint64 (*CallbackGetTimeTick)(void);

typedef struct TagWsecAdvanceCallbacks {
    CallbackGenCipher genCipher;
    CallbackParseCipher parseCipher;
    CallbackGetCipherConf getCipherConf;
    CallbackGetCipherLen getCipherLen;
    CallbackGetTimeTick getTimeTick;
    unsigned char* resv[23];
} WsecAdvanceCallbacks;

/*
 * API Function Prototype Description
 * When the system is started or shut down, the application needs to call the following functions.
 */
/* Callback function registration */
unsigned long WsecRegFuncEx(const WsecCallbacks *allCallbacks);

/*
 * When no security hardware is available,
 * the initialization function is used to specify the master or agent.
 * The paths of the active and standby files of the keystore must be specified.
 * The variant parameter is reserved.
  */
unsigned long WsecInitializeEx(WsecUint32 roleType,
    const KmcKsfName *filePathName,
    WsecBool useImportKey,
    WsecVoid *exParam);

/*
 * When security hardware is used, the initialization function is used to specify the master or agent.
 * The paths of the active and standby files of the keystore must be specified. The variant parameter is reserved.
 * hasSoftLevelRk: indicates whether to use the software-layer root key for acceleration.
 * The software-layer root key is encrypted by the hardware root key and stored in the keystore file in ciphertext.
 * Once this parameter is specified, it cannot be changed.
 * This parameter has low security risks due to performance considerations.
 */
unsigned long WsecInitializeHw(WsecUint32 roleType,
    const KmcKsfName *filePathName,
    WsecBool hasSoftLevelRk,
    const WsecVoid *hardwareParam, WsecUint32 hardwareParamLen,
    WsecVoid *exParam);


/**
 * @brief      This is a new version API for kmc initial, which you can used for both hardware procted root key and
               software protected. param is compatible with WsecInitializeEx and WsecInitializeHw
 * @param[in]  initParam is the input parameter structure of the initialization parameter.
 *             roleType: type of kmc role, you can set KMC_ROLE_MASTER or KMC_ROLE_AGENT
 *             filePathName: The keystore file name;
 *             enableHw: Whther enable hareware to protect root key. WSEC_TRUE means use hardware protect root key, also
 *             use software protect root key.
 *             hwParam:  It's only works when enableHw equal to WSEC_TRUE; Its member hasSoftLevelRk determine
 *             whther use one soft level root key.
 *             recoverParam: used set third backup and recover ksf. optional Param, set NULL if not used, Ref.
 *             WsecExtendInitParam algCnfParam: used to set crypto algorithm. optional parameter, set NULL if not used.
 *             algCnfParam->symmAlg.algId values in (WSEC_ALGID_AES128_CBC, WSEC_ALGID_AES256_CBC, WSEC_ALGID_AES128_GCM
 *             WSEC_ALGID_AES256_GCM, WSEC_ALGID_SM4_CBC, WSEC_ALGID_SM4_CTR)
 *             algCnfParam->hashAlg values in (WSEC_ALGID_SHA256, WSEC_ALGID_SM3)
 *             algCnfParam->hmacAlg values in (WSEC_ALGID_HMAC_SHA256, WSEC_ALGID_HMAC_SM3)
 *             algCnfParam->kdfAlg values in (WSEC_ALGID_PBKDF2_HMAC_SHA256, WSEC_ALGID_PBKDF2_HMAC_SM3)
 *             we strongly recommend you memset all KmcInitParam's member to 0 before assign value.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate memory, The caller needs to call the WsecFinalizeEx interface to release the memory.
 *  - Thread safe:      Non-Thread-safe function, will modifiy global variables.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread, file operations and TEE operations (only TEE mode).
 */
unsigned long WsecInitializeKmc(const KmcInitParam *initParam);

/*
 * Function for reloading the keystore file.
 * This function is used to reload the keystore file from the keystore file in the process.
 * Note: After this function is called, the configuration is restored
 * to the default configuration. If the default configuration is not used,
 * the app needs to reconfigure the configuration.
 */
unsigned long WsecResetEx(void);

unsigned long WsecResetHw(const WsecVoid *hardwareParam, WsecUint32 hardwareParamLen);

/* Specified master or agent */
unsigned long WsecSetRole(WsecUint32 roleType);

/* Deinitializes a function. */
unsigned long WsecFinalizeEx(void);

/* Obtains the current version number. */
const char *WsecGetVersion(void);

unsigned long WsecRegFuncAdvance(const WsecAdvanceCallbacks *extCallbacks);

unsigned long WsecSetPerConf(const WsecPerConf *perConf);
#ifdef WSEC_DEBUG
/* Size of the callback Wsec data structure */
WsecVoid WsecShowStructSize(CallbackShowStructSize showStructures);
#endif

#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif /* KMC_INCLUDE_WSECV2_ITF_H */
