/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2020. All rights reserved.
 * Description: type definition

 * Create: 2014-06-16

 */

#ifndef KMC_INCLUDE_WSECV2_TYPE_H
#define KMC_INCLUDE_WSECV2_TYPE_H

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WSEC_DEBUG
#include <assert.h>
#endif

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

#ifndef NULL
#define NULL ((void *)0)
#endif

/*
 * For variables or parameters that are not used temporarily,
 * use this macro to avoid the not referenced compilation alarm.
 */
#define WSEC_UNREFER(v) ((void)(v))

#define WSEC_FALSE         0
#define WSEC_TRUE          1
#define WSEC_FALSE_FOREVER (!(__LINE__)) /* Constant leave, which is used to
                                            determine conditions to avoid
                                            compilation alarms.
                                          */

/* Definition of Range Judgment */
#define WSEC_IN_SCOPE(x, min, max) (((min) <= (x)) && ((x) <= (max)))
#define WSEC_OUT_OF_SCOPE(x, min, max) (((x) < (min)) || ((max) < (x)))
#define WSEC_IS2(x, v1, v2) ((x) == (v1) || (x) == (v2))
#define WSEC_IS3(x, v1, v2, v3) ((x) == (v1) || (x) == (v2) || (x) == (v3))
#define WSEC_IS4(x, v1, v2, v3, v4) ((x) == (v1) || (x) == (v2) || (x) == (v3) || (x) == (v4))
/* Whether the character string is empty */
#define WSEC_IS_EMPTY_STRING(str) (((str) == NULL) || ((str)[0] == '\0'))
/* Calculates the number of elements in an array. */
#define WSEC_NUM_OF(arr) (sizeof(arr) / sizeof((arr)[0]))

#ifdef WSEC_DEBUG
#define WSEC_ASSERT(exp) assert(exp)
#else
#define WSEC_ASSERT(exp)
#endif
/* max key length, iv, tag, block, algId */
#define WSEC_MKTEE_LEN_MAX      164
#define WSEC_MK_LEN_MAX         128
#define WSEC_MK_PLAIN_LEN_MAX   112    /* Maximum length of the ciphertext of the MK (bytes) */
#define WSEC_MK_HASH_REC_LEN    8      /* Length of the MK hash result record */
#define WSEC_PWD_PLAIN_LEN_MAX (100 * 1024 * 1024)   /* Maximum length of the plain (bytes) */

/* type of TEE */
#define WSEC_KMC_TEE_TYPE_NONE 0x00 /* disable any TEE */
#define WSEC_KMC_TEE_TYPE_TZ   0x01 /* enable trustZone TEE */

/* Maximum hardware ciphertext length. The value of KMC_MAX_MK_RECORD_LEN must be less than or equal to 65535. */
#define WSEC_MAX_HARD_CIPHERTEXT_LEN (32 * 1024)

/* type of KeyStoreMode */
#define WSEC_HASKEYSTORE 0x00
#define WSEC_NOKEYSTORE  0X01

#define KMC_SYNC_DH_ALG_LEN 16

/* Type Definition */
typedef void            WsecVoid;
typedef unsigned short  WsecUint16;
typedef unsigned char   WsecUint8;
typedef unsigned int    WsecUint32;
typedef int             WsecBool;
typedef unsigned long long  WsecUint64;

typedef void           *WsecHandle;

/* Notification word of the notification app (used to identify the type of the notification) */
typedef enum {
    /* The root key (RK) key material is about to expire. V2 does not have this notification. */
    WSEC_KMC_NTF_RK_EXPIRE          = 1,
    /* The master key (MK) is about to expire. V2 does not have this notification. */
    WSEC_KMC_NTF_MK_EXPIRE          = 2,
    /* MK change */
    WSEC_KMC_NTF_MK_CHANGED         = 3,
    /* This notification is not sent in V2 when the MK expires. */
    WSEC_KMC_NTF_USING_EXPIRED_MK   = 4,
    /* The Keystore is damaged. */
    WSEC_KMC_NTF_KEY_STORE_CORRUPT  = 5,
    /* The KMC configuration file is damaged. V2 does not have this notification. */
    WSEC_KMC_NTF_CFG_FILE_CORRUPT   = 6,
    /* Failed to save the Keystore, */
    WSEC_KMC_NTF_WRI_KEY_STORE_FAIL = 7,
    /* Failed to save the KMC configuration file. V2 does not have this notification. */
    WSEC_KMC_NTF_WRI_CFG_FILE_FAIL  = 8,
    /* The number of MKs is about to exceed the upper limit. */
    WSEC_KMC_NTF_MK_NUM_OVERFLOW    = 9,
    /* KeyStore file update completion notification */
    WSEC_KMC_NTF_KEY_STORE_UPDATE   = 10,
    /* KMC configuration file update completion notification, which is not provided in V2. */
    WSEC_KMC_NTF_CFG_FILE_UPDATE    = 11,
    /* A keystore file of the KMC is damaged and fails to be restored. */
    WSEC_KMC_NTF_ONE_KSF_CORRUPT    = 12,
    /* Two Files Cannot Be Opened When the Keystore Is Loaded */
    WSEC_KMC_NTF_KSF_INITOPENFAIL   = 13,
    /* The third backup KSF update  success notify */
    WSEC_KMC_NTF_THIRD_KSF_UPDATE   = 14,
    /* Asym key do not need to sync */
    WSEC_KMC_NTF_NOT_SYNC_ASYM_KEY   = 15,
    /* ASYM change */
    WSEC_KMC_NTF_ASYM_CHANGED        = 16,
    /* ASYM is expires. */
    WSEC_KMC_NTF_USING_EXPIRED_ASYM  = 17,
} WsecNotifyCode;

/* Algorithm ID */
#define WSEC_ALGID_NUM_PER_TYPE     1024
#define WSEC_ALGID_SYM_BEGIN        1
#define WSEC_ALGID_DIGEST_BEGIN     (1 + WSEC_ALGID_NUM_PER_TYPE * 1)
#define WSEC_ALGID_HMAC_BEGIN       (1 + WSEC_ALGID_NUM_PER_TYPE * 2)
#define WSEC_ALGID_PBKDF_BEGIN      (1 + WSEC_ALGID_NUM_PER_TYPE * 3)
#define WSEC_ALGID_ASYM_ENC_BEGIN   (1 + WSEC_ALGID_NUM_PER_TYPE * 4)
#define WSEC_ALGID_ASYM_SIGN_BEGIN  (1 + WSEC_ALGID_NUM_PER_TYPE * 5)
#define WSEC_ALGID_ECDH_BEGIN       (1 + WSEC_ALGID_NUM_PER_TYPE * 6)

#define WSEC_ALGID_DEFAULT          0

typedef enum {
    /* Unknown algorithm */
    WSEC_ALGID_UNKNOWN,

    /* Symmetric encryption algorithm */
    /* AES-128-CBC with CMS-Padding */
    /* WSEC_ALGID_AES128_CBC:5 (The value must remain unchanged.) */
    WSEC_ALGID_AES128_CBC = (WSEC_ALGID_SYM_BEGIN + 4),
    /* AES-256-CBC with CMS-Padding */
    /* WSEC_ALGID_AES256_CBC:7 (The value must remain unchanged.) */
    WSEC_ALGID_AES256_CBC = (WSEC_ALGID_SYM_BEGIN + 6),
    /* AES-128-GCM with CMS-Padding */
    WSEC_ALGID_AES128_GCM,
    /* AES-256-GCM */
    WSEC_ALGID_AES256_GCM,
    /* SM4-CBC with CMS-Padding */
    WSEC_ALGID_SM4_CBC,
    /* SM4-CTR */
    WSEC_ALGID_SM4_CTR,
    /* AES-128-CBC with ISO-Padding */
    WSEC_ALGID_AES128_CBC_ISO_PADDING,
    /* AES-256-CBC with ISO-Padding */
    WSEC_ALGID_AES256_CBC_ISO_PADDING,
    /* SM4-CBC with ISO-Padding */
    WSEC_ALGID_SM4_CBC_ISO_PADDING,

    /* Hash algorithm ID */
    /* SHA256 */
    /* WSEC_ALGID_SHA256: 3 (The value must remain unchanged.) */
    WSEC_ALGID_SHA256 = (WSEC_ALGID_DIGEST_BEGIN + 3),
    /* SHA384 */
    WSEC_ALGID_SHA384,
    /* SHA512 */
    WSEC_ALGID_SHA512,
    /* SM3 */
    WSEC_ALGID_SM3,
    /* HMAC algorithm */
    /* HMAC SHA256 */
    /* WSEC_ALGID_HMAC_SHA256:3 (value must remain unchanged.) */
    WSEC_ALGID_HMAC_SHA256 = (WSEC_ALGID_HMAC_BEGIN + 3),
    /* HMAC SHA384 */
    WSEC_ALGID_HMAC_SHA384,
    /* HMAC SHA512 */
    WSEC_ALGID_HMAC_SHA512,
    /* HMAC SM3 */
    WSEC_ALGID_HMAC_SM3,

    /* PBKDF Algorithm */
    /* PBKDF2-HMAC-SHA256 */
    /* WSEC_ALGID_PBKDF2_HMAC_SHA256: 3 (The value must remain unchanged.) */
    WSEC_ALGID_PBKDF2_HMAC_SHA256 = (WSEC_ALGID_PBKDF_BEGIN + 3),
    /* PBKDF2-HMAC-SHA384 */
    WSEC_ALGID_PBKDF2_HMAC_SHA384,
    /* PBKDF2-HMAC-SHA512 */
    WSEC_ALGID_PBKDF2_HMAC_SHA512,
    /* PBKDF2-HMAC-SM3 */
    WSEC_ALGID_PBKDF2_HMAC_SM3,

    /* Enc */
    WSEC_ALGID_RSA_OAEP_SHA256 = WSEC_ALGID_ASYM_ENC_BEGIN,
    WSEC_ALGID_RSA_OAEP_SHA384,
    WSEC_ALGID_RSA_OAEP_SHA512,
    WSEC_ALGID_SM2_PKE_CRYPT,

    /* Sign */
    WSEC_ALGID_RSA_PSS_SHA256 = WSEC_ALGID_ASYM_SIGN_BEGIN,
    WSEC_ALGID_RSA_PSS_SHA384,
    WSEC_ALGID_RSA_PSS_SHA512,
    WSEC_ALGID_RSA_PKCS15_SHA256,
    WSEC_ALGID_RSA_PKCS15_SHA384,
    WSEC_ALGID_RSA_PKCS15_SHA512,
    WSEC_ALGID_ECC_SHA256,
    WSEC_ALGID_ECC_SHA384,
    WSEC_ALGID_ECC_SHA512,
    WSEC_ALGID_ED25519,
    WSEC_ALGID_SM2_SM3,

    /* elliptic curve */
    WSEC_ALGID_DH_25519 = WSEC_ALGID_ECDH_BEGIN + 1,
    WSEC_ALGID_DH_ECC_P256,
    WSEC_ALGID_DH_ECC_P384,
    WSEC_ALGID_DH_ECC_P521,
    WSEC_ALGID_DH_SM2,
} WsecAlgId;

typedef enum {
    WSEC_KEY_RSA_2048,
    WSEC_KEY_RSA_3072,
    WSEC_KEY_RSA_4096,
    WSEC_KEY_EC_P256,
    WSEC_KEY_EC_P384,
    WSEC_KEY_EC_P521,
    WSEC_KEY_ED_25519,
    WSEC_KEY_SM2,
} WsecKeySpec;

/* Keys are classified by function and defined by bit. */
typedef enum {
    KMC_KEY_TYPE_MIN = 0,
    KMC_KEY_TYPE_ENCRPT = 1,           /* Symmetric encryption */
    KMC_KEY_TYPE_INTEGRITY = 2,        /* Integrity protection */
    KMC_KEY_TYPE_ENCRPT_INTEGRITY = 3, /* Encryption and Integrity */

    KMC_KEY_TYPE_ASYM_ENCRYPT_DECRYPT = 4,
    KMC_KEY_TYPE_ASYM_SIGN_VERIFY = 6,
    KMC_KEY_TYPE_MAX = 8
} KmcKeyType;


/* Role */
typedef enum {
    KMC_ROLE_AGENT = 0,
    KMC_ROLE_MASTER
} KmcRoleType;

/* Key Status */
typedef enum {
    /* Inactive keys are no longer used to encrypt confidential data,
     * but can be used to decrypt historical ciphertext
     */
    KMC_KEY_STATUS_INACTIVE = 0,
    /* In use */
    KMC_KEY_STATUS_ACTIVE,
    /*
     * Intermediate status,
     * which does not take effect and is used for intermediate status
     * management during synchronization
     */
    KMC_KEY_STATUS_TOBEACTIVE
} KmcKeyStatus;

/* Key Change Type */
typedef enum {
    KMC_KEY_ACTIVATED = 0,              /* Key activation */
    KMC_KEY_INACTIVATED,                /* Key deactivation (expired) */
    KMC_KEY_REMOVED,                    /* The key is deleted. */
    KMC_KEY_TOBEACTIVATED               /* To-Be-Effective State */
} KmcKeyChangeType;

/* Root Key Material Generation Mode */
typedef enum {
    KMC_RK_GEN_BY_INNER,                /* Automatically generated by the system */
    KMC_RK_GEN_BY_IMPORT                /* External import */
} KmcRkGenerateFrom;

/* Master Key Generation Mode */
typedef enum {
    KMC_MK_GEN_BY_INNER,                /* Automatically generated by the system */
    KMC_MK_GEN_BY_IMPORT                /* External import */
} KmcMkGenerateFrom;

/* CBB-dedicated domain */
#define KMC_PRI_DOMAIN_ID_MIN 1024
#define KMC_PRI_DOMAIN_ID_MAX 1056
#define KMC_INVALID_DOMAIN (WsecUint32)(-1)

typedef enum {
    KMC_ALL_DOMAIN    = (KMC_PRI_DOMAIN_ID_MAX + 1000),
    KMC_SINGLE_DOMAIN = (KMC_PRI_DOMAIN_ID_MAX + 1001),
    KMC_BATCH_DOMAIN  = (KMC_PRI_DOMAIN_ID_MAX + 1002)
} KmcDomainOpMode;

/* Domain type. In V3 and later versions,
 * local domains and shared domains are distinguished.
 */
typedef enum {
    KMC_DOMAIN_TYPE_SHARE = 0,          /* Shared Domain Type */
    KMC_DOMAIN_TYPE_LOCAL = 1,          /* Local Domain Type */
    KMC_DOMAIN_TYPE_IGNORE = 2          /* Ignore Domain Type */
} KmcDomainType;

/* Notification from CBB to APP */
typedef WsecVoid (*CallbackNotify)(WsecUint32 notifyCode, const WsecVoid *data, size_t dataSize);
/* Callback function for sending and receiving master key synchronization data */
typedef WsecBool(*CallbackSendSyncData)(WsecVoid *param, const unsigned char *data, WsecUint32 len);
typedef WsecBool(*CallbackRecvSyncData)(WsecVoid *param, unsigned char *data, WsecUint32 len);

/* Structure Definition */
#pragma pack(1)
typedef struct TagWsecSysTime {
    WsecUint16    kmcYear;   /* Year */
    unsigned char kmcMonth;  /* Month (1-12) */
    unsigned char kmcDate;   /* Date (1-31. The upper limit is determined by the year and month.) */
    unsigned char kmcHour;   /* Hour (0-23) */
    unsigned char kmcMinute; /* Minute (0 to 59) */
    unsigned char kmcSecond; /* Second (0-59) */
    unsigned char kmcWeek;   /* Weekday (1-7 indicate Monday to Sunday respectively) */
} WsecSysTime;
#pragma pack()

#ifdef WSEC_DEBUG
/* Outputs the CBB structure length to the APP for commissioning. */
typedef WsecVoid(*CallbackShowStructSize)(const char *structName, size_t size);
#endif

/*
 * File Version History
 * 1. KSF version of the Keystore file:
 * KMC_KSF_VER = 1 Released the first version on December 31, 2014.
 * KMC_KSF_VER_V2 = 2 2016.1.30 v2 version setting
 * 2. MK file MKF version:
 * First release of KMC_MKF_VER = 1 2014-12-31
 * KMC_MKF_VER_V2 = 2 2016.1.30 v2 version setting
 */
typedef enum {
    KMC_KSF_VER    = 1, /* Keystore file version */
    KMC_KSF_VER_V2 = 2, /* Keystore v2 file version */
    KMC_KSF_VER_V3 = 3, /* keystore v3 file version */
} KmcKsfVersion;

typedef enum {
    WSEC_KMC_DEFAULT_SRK        = 0,
    WSEC_KMC_USER_DEFINE_SRK    = 1,
} KmcTeeRkType;

typedef enum {
    KMC_MKF_VER    = 1, /* MK file version */
    KMC_MKF_VER_V2 = 2, /* V2 version number of the mk file */
} KmcMkfVersion;

typedef enum {
    KMC_FILE_READ_BINARY = 0,
    KMC_FILE_WRITE_BINARY,
    KMC_FILE_READWRITE_BINARY
} KmcFileOpenMode;

typedef enum {
    KMC_FILE_SEEK_SET = 0,
    KMC_FILE_SEEK_CUR,
    KMC_FILE_SEEK_END
} KmcFileSeekPos;

/* Function pointer definition */
/* Log */
typedef WsecVoid(*CallbackWriteLog)(int level, const char *moduleName, const char *filePathName, int lineNum,
    const char *logString);


/* Memory operation */
typedef WsecVoid *(*CallbackMemAlloc)(size_t size);
typedef WsecVoid(*CallbackMemFree)(WsecVoid *memBuff);
typedef int(*CallbackMemCmp)(const WsecVoid *buffA, const WsecVoid *buffB, size_t count);

/* Thread lock */
typedef WsecBool(*CallbackCreateLock)(WsecHandle *mutexObject);
typedef WsecVoid(*CallbackDestroyLock)(WsecHandle mutexObject);
typedef WsecVoid(*CallbackLock)(WsecHandle mutexObject);
typedef WsecVoid(*CallbackUnlock)(WsecHandle mutexObject);

/* Process lock */
typedef WsecBool(*CallbackCreateProcLock)(WsecHandle *mutexObject);
typedef WsecVoid(*CallbackDestroyProcLock)(WsecHandle mutexObject);
typedef WsecVoid(*CallbackProcLock)(WsecHandle mutexObject);
typedef WsecVoid(*CallbackProcUnlock)(WsecHandle mutexObject);

typedef WsecVoid(*CallbackDoEvents)(void);
/* File operation */
typedef WsecHandle(*CallbackFopen)(const char *filePathName, const KmcFileOpenMode mode);
typedef int(*CallbackFclose)(WsecHandle stream);
typedef WsecBool(*CallbackFread)(WsecVoid *buffer, size_t count, WsecHandle stream);
typedef WsecBool(*CallbackFwrite)(const WsecVoid *buffer, size_t count, WsecHandle stream);
typedef int(*CallbackFflush)(WsecHandle stream);
typedef int(*CallbackFremove)(const char *path);
typedef long(*CallbackFtell)(WsecHandle stream);
typedef long(*CallbackFseek)(WsecHandle stream, long offset, KmcFileSeekPos origin);
typedef int(*CallbackFeof)(WsecHandle stream, WsecBool *endOfFile);
typedef int(*CallbackFerrno)(WsecHandle stream);
typedef WsecBool(*CallbackFexist)(const char *filePathName);

/* Random number generation + entropy value obtaining */
typedef WsecBool(*CallbackGetRandomNumber)(unsigned char *buff, size_t buffLen);
typedef WsecBool(*CallbackGetEntropy)(unsigned char **entropyBuff, size_t buffLen);
typedef WsecVoid(*CallbackCleanupEntropy)(unsigned char *entropyBuff, size_t buffLen);

/* Callback function for obtaining time */
struct tm;
typedef WsecBool(*CallbackGmTimeSafe)(const time_t *curTime, struct tm *curTm);

/* Hardware Interface Callback */
typedef struct TagWsecPlainCipherBuffs {
    const unsigned char *in;
    unsigned int inLen;
    unsigned char *out;
    unsigned int *outLen;
} WsecPlainCipherBuffs;

/*
 * Implementation of the callback function for obtaining additional data. This function is used by the KMC
 * to obtain additional data for encryption and decryption. Generally, this function is provided or changed by KMC users
 */
typedef unsigned long(*CallbackHwGetEncExtraData)(const unsigned char **extraData, unsigned int *extraLen);
typedef unsigned long(*CallbackHwGetDecExtraData)(const unsigned char **extraData, unsigned int *extraLen);

/*
 * Hardware adaptation layer: secure hardware key management interface,
 * which is used by the KMC to call secure hardware to encrypt KMC data.
 */
typedef unsigned int(*CallbackHwGetPersistentDataLen)(void);
typedef unsigned long(*CallbackHwInitKeyMgr)(const void *passthroughData, unsigned int passthroughDataLen);
typedef unsigned long(*CallbackHwNewRootKey)(unsigned char *persistentData, unsigned int *persistentDataLen,
    WsecHandle *handle);
typedef unsigned long(*CallbackHwLoadRootkey)(const unsigned char *persistentData, unsigned int persistentDataLen,
    WsecHandle *handle);
typedef unsigned long(*CallbackHwGetCipherLen)(unsigned int plaintextLen, unsigned int *ciphertextLen);
typedef unsigned long(*CallbackHwEncData)(WsecHandle handle, const unsigned char *extraData, unsigned int extraLen,
    const WsecPlainCipherBuffs *buffs);
typedef unsigned long(*CallbackHwDecData)(WsecHandle handle, const unsigned char *extraData, unsigned int extraLen,
    const WsecPlainCipherBuffs *buffs);
typedef unsigned long(*CallbackHwUnloadKey)(WsecHandle handle);
typedef unsigned long(*CallbackHwRemoveKey)(WsecHandle handle);
typedef unsigned long(*CallbackHwUninitKeyMgr)(void);

/* Structure */
/* Structure of the memory operation callback function */
typedef struct TagWsecMemCallbacks {
    CallbackMemAlloc memAlloc;
    CallbackMemFree  memFree;
    CallbackMemCmp   memCmp;
} WsecMemCallbacks;

/* Structure of the system file operation callback function */
typedef struct TagWsecFileCallbacks {
    CallbackFopen   fileOpen;
    CallbackFclose  fileClose;
    CallbackFread   fileRead;
    CallbackFwrite  fileWrite;
    CallbackFflush  fileFlush;
    CallbackFremove fileRemove;
    CallbackFtell   fileTell;
    CallbackFseek   fileSeek;
    CallbackFeof    fileEof;
    CallbackFerrno  fileErrno;
    CallbackFexist  fileExist;
} WsecFileCallbacks;

/* Structure of the system thread lock callback function */
typedef struct TagWsecLockCallbacks {
    CallbackCreateLock  createLock;
    CallbackDestroyLock destroyLock;
    CallbackLock        lock;
    CallbackUnlock      unlock;
} WsecLockCallbacks;

/* Structure of the basic system callback function */
typedef struct TagWsecBasicRelyCallbacks {
    CallbackWriteLog writeLog;
    CallbackNotify   notify;
    CallbackDoEvents doEvents;
} WsecBasicRelyCallbacks;

/* Structure of the System Process Lock Callback Function */
typedef struct TagWsecProcLockCallbacks {
    CallbackCreateProcLock  createProcLock;
    CallbackDestroyProcLock destroyProcLock;
    CallbackProcLock        procLock;
    CallbackProcUnlock      procUnlock;
} WsecProcLockCallbacks;

/* Callback function for obtaining random numbers or seeds */
typedef struct TagWsecRngCallbacks {
    CallbackGetRandomNumber getRandomNum;
    CallbackGetEntropy      getEntropy;
    CallbackCleanupEntropy  cleanupEntropy;
} WsecRngCallbacks;

/* Reentrant gmtime (gmtime_r/gmtime_s) callback function */
typedef struct TagWsecTimeCallbacks {
    CallbackGmTimeSafe gmTimeSafe;
} WsecTimeCallbacks;

/* Hardware root key access callback function */
typedef struct TagWsecHardwareCallbacks {
    CallbackHwGetEncExtraData      hwGetEncExtraData;
    CallbackHwGetDecExtraData      hwGetDecExtraData;
    CallbackHwGetPersistentDataLen hwGetPersistentDataLen;
    CallbackHwInitKeyMgr           hwInitKeyMgr;
    CallbackHwNewRootKey           hwNewRootKey;
    CallbackHwLoadRootkey          hwLoadRootkey;
    CallbackHwGetCipherLen         hwGetCipherLen;
    CallbackHwEncData              hwEncData;
    CallbackHwDecData              hwDecData;
    CallbackHwUnloadKey            hwUnloadKey;
    CallbackHwRemoveKey            hwRemoveKey;
    CallbackHwUninitKeyMgr         hwUninitKeyMgr;
} WsecHardwareCallbacks;

/* All callback functions */
typedef struct TagWsecCallbacks {
    WsecMemCallbacks       memCallbacks;
    WsecFileCallbacks      fileCallbacks;
    WsecLockCallbacks      lockCallbacks;
    WsecProcLockCallbacks  procLockCallbacks;
    WsecBasicRelyCallbacks basicRelyCallbacks;
    WsecRngCallbacks       rngCallbacks;
    WsecTimeCallbacks      timeCallbacks;
    WsecHardwareCallbacks  hardwareCallbacks;
} WsecCallbacks;

/* 1. Structure body Root Key (RK) information */
typedef struct TagKmcRkAttributes {
    WsecUint16  version;           /* Version */
    WsecUint16  rkMaterialFrom;    /* Source of the root key material. For details, see KmcRkGenerateFrom. */
    WsecSysTime rkCreateTimeUtc;   /* Root key creation time (UTC) */
    WsecSysTime rkExpiredTimeUtc;  /* Root key expiration time (UTC). */
    WsecUint32  rmkIter;           /* Derived RMK Iteration Times */
} KmcRkAttributes;

/* 2. Master Key (MK) information */
/*
 * The MK has two types of keywords:
 * (1) domainId + keyId are unique keywords used to identify the MK.
 * (2) domainId + keyType + status is a keyword that can be repeated.
 * Obtain the MK whose current status is Available based on keyType.
 */
#pragma pack(1)
typedef struct TagKmcMkInfo {
    WsecUint32    domainId;         /* Key Application Scope */
    WsecUint32    keyId;            /* Key ID, which is unique in a domain. */
    WsecUint16    keyType;          /* Keys are classified by usage. For details, see KmcKeyType. */
    unsigned char status;           /* Key status. For details, see KmcKeyStatus. */
    unsigned char generateType;     /* Key generation mode. For details, see KmcMkGenerateFrom. */
    WsecSysTime   mkCreateTimeUtc;  /* MK creation time (UTC). */
    WsecSysTime   mkExpiredTimeUtc; /* MK expiration time (UTC). */
} KmcMkInfo; /* MK header information */
#pragma pack()

#pragma pack(1)
typedef struct TagKmcNovaKeyInfo {
    WsecUint32      domainId;         /* Key Application Scope */
    WsecUint32      keyId;            /* Key ID, which is unique in a domain. */
    WsecUint16      keySpec;          /* keySpec */
    WsecUint16      keyType;          /* Keys are classified by usage. For details, see KmcKeyType. */
    unsigned char   status;           /* Key status. For details, see KmcKeyStatus. */
    unsigned char   generateType;     /* Key generation mode. For details, see KmcMkGenerateFrom. */
    WsecSysTime     createTimeUtc;    /* creation time (UTC). */
    WsecSysTime     expiredTimeUtc;   /* expiration time (UTC). */
} KmcNovaKeyInfo;
#pragma pack()


/* 3. Key management configuration */
/* 1) Global key configuration information */
#pragma pack(1)
typedef struct TagKmcCfgRootKey {
    WsecUint32    validity;   /* Rootkey validity period (days) */
    WsecUint32    rmkIter;    /* Number of iterations of derived root master keys */
    unsigned char reserve[8]; /* Reserved 8 bytes */
} KmcCfgRootKey; /* RK Management Parameters */
#pragma pack()


/* 3) Domain key type configuration */
#pragma pack(1)
typedef struct TagKmcCfgKeyType {
    WsecUint16    keyType;     /* Keys are classified by usage. For details, see KmcKeyType. */
    WsecUint32    keyLen;      /* Key length */
    WsecUint32    keyLifeDays; /* Validity Period (Days) */
    unsigned char reserve[8];  /* Reserved 8 bytes */
} KmcCfgKeyType;
#pragma pack()

/* 4) Domain configuration */
#pragma pack(1)
typedef struct TagKmcCfgDomainInfo {
    WsecUint32    domainId;      /* Key Application Scope */
    unsigned char domainKeyFrom; /* For details about the key generation source, see KmcMkGenerateFrom. */
    char          desc[128];     /* Key description, which contains a maximum of 128 bytes. */
    /* Extended in V3. The domain type can be local domain or shared domain. For details, see KmcDomainType. */
    unsigned char domainType;
    unsigned char reserve[7];    /* Reserved 7 bytes */
} KmcCfgDomainInfo;
#pragma pack()

/* 4. File name required by the KMC */
typedef struct TagKmcKsfName {
    /* Keystore file name ( 2 copies are backed up for reliability purposes) */
    char *keyStoreFile[2];
    /* The third backuppath */
    char *keyStoreBackupFile;
} KmcKsfName;

/* 5. Notify the app. */
/* (1) Notification of RK expiration */
typedef struct TagKmcRkExpireNotify {
    /* Information about the root key that is about to expire */
    KmcRkAttributes rkAttr;
    /* Number of days before the expiration date */
    int             remainDays;
} KmcRkExpireNotify;

/* 2) Notification of MK expiration */
typedef struct TagKmcMkExpireNotify {
    KmcMkInfo mkInfo;     /* MK information that is about to expire */
    int       remainDays; /* Number of days before the expiration date */
} KmcMkExpireNotify;

/* 3) MK change notification */
typedef struct TagKmcMkChangeNotify {
    KmcMkInfo  mkInfo;   /* Changed MK information */
    WsecUint32 type;     /* Change Type */
} KmcMkChangeNotify;

/* 4) Notification of using expired MKs beyond the grace period */
typedef struct TagKmcUseExpiredMkNotify {
    KmcMkInfo expiredMkInfo; /* Expired MK information */
    int       expiredDays;   /* Expiration days */
} KmcUseExpiredMkNotify;

/* 5) Notification of failing to write the Keystore file */
typedef struct TagKmcWriteKsfFailNotify {
    unsigned long errorCode; /* Failure Cause */
} KmcWriteKsfFailNotify;

/* 6) Notification of successful Keystore file writing */
typedef struct TagKmcKsfUpdateNotify {
    /* Which of the following files is the upper layer notified of the Keystore update? (2 files in total) */
    char *keyStoreFile[2];
} KmcKsfUpdateNotify;

/* 7) Notify that the keystore file is successfully synchronized when it is damaged and not damaged. */
typedef struct TagKmcKsfOneksfCorruptNotify {
    char *keyStoreFile; /* Damaged keystore */
} KmcKsfOneksfCorruptNotify;

/* 8) NOTIFY: The  third backup KSF updated success */
typedef struct TagKmcThirdKsfUpdateNotify {
    char *keyStoreBackupFile; /* Notify to the upper layer that the  third backup KSF updated ; */
} KmcThirdKsfUpdateNotify;

/* 16) asym change notification */
typedef struct TagKmcAsymChangeNotify {
    KmcNovaKeyInfo  keyInfo;   /* Changed Asym information */
    WsecUint32      type;     /* Change Type */
} KmcAsymChangeNotify;

/* 17) asym change notification */
typedef struct TagKmcUseExpiredAsymNotify {
    KmcNovaKeyInfo  expiredAsymInfo; /* Expired asym information */
    int             expiredDays;     /* Expiration days */
} KmcUseExpiredAsymNotify;

typedef struct TagWsecBuff {
    WsecVoid *buff;
    WsecUint32 len;
} WsecBuff;

typedef struct TagWsecBuffConst {
    const WsecVoid *buff;
    WsecUint32 len;
} WsecBuffConst;

typedef struct TagWsecBuffExt {
    unsigned char *buff;
    WsecUint32 *len;
} WsecBuffExt;

/*
 * For KmcImportKsf interface
 */
typedef enum {
    IMPORT_MK_ACTION_REPLACE  = 1,     /* Overwrite */
    IMPORT_MK_ACTION_ADD      = 2      /* Append */
} ImportMkActionType; /* Import MK Behavior Type */

/* ta call ta interface */
#pragma pack(1)
typedef struct TagTaMkCipherInfo {
    WsecUint32 encAlgId; /* encrypt alg id */
    WsecUint32 hmacAlgId; /* hmac alg id */
    WsecUint32 mkLen; /* mk plainText len */
    unsigned char reserve[20];
} TaMkCipherInfo;
#pragma pack()

#pragma pack(1)
typedef struct TagWsecSrkPrimitive {
    WsecUint32 version;
    WsecAlgId pbkdfAlgId;
    WsecUint32 iter;
    WsecUint32 deriverKeyLen;
    unsigned char material[256];
    WsecUint32 materialLen;  /* [0, 256] */
    unsigned char salt[128];
    WsecUint32 saltLen;  /* [0, 128] */
    WsecAlgId encAlgId;  /* symm alg + padding mode, AES256_CBC_ISO_Padding  */
    unsigned char iv[128];
    WsecUint32 ivLen;  /* [0, 128] */
    unsigned char tag[128];
    WsecUint32 tagLen;  /* [0, 128] */
    unsigned char cipher[256];
    WsecUint32 cipherLen;  /* [0, 2048] */
    unsigned char reserve[16];
} WsecSrkPrimitive;
#pragma pack()

/**
 * For batch operations
 **/
typedef struct TagKmcDomainArray {
    int count;
    WsecUint32 *domainIds;
} KmcDomainArray;

#pragma pack(1)
typedef struct KmcExportKsfParamTag {
    KmcDomainArray *domainArray;
    WsecBool       withHw;
    unsigned char  reserve[16];
    WsecUint32     extLen;
    unsigned char  ext[];
} KmcExportKsfParam;
#pragma pack()

#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif /* KMC_INCLUDE_WSECV2_TYPE_H */
