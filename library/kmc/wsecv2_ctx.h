/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: KMC MultiInstance context header file define the members of context.
 * Create: 2021-08-06
 * History: None
 */

#ifndef KMC_SRC_COMMON_WSECV2_CTX_H
#define KMC_SRC_COMMON_WSECV2_CTX_H

#include "wsecv2_type.h"
#include "wsecv2_itf.h"
#include "wsecv2_multitype.h"
#include "wsecv2_array.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

typedef enum {
    KMC_SINGEL_INSTANCE = 0,
    KMC_MULTI_INSTANCE
} KmcMultiInstanceFlag;

/* lock */
typedef enum {
    WSEC_FUNC_UNREG = 0,
    WSEC_FUNC_REG
} WsecFuncRegState;

typedef enum {
    LOCK4KEYSTORE = 0, /* Keystore data and corresponding files in the memory */
    LOCK4KMC_CFG  = 1, /* KMC Memory Configuration */
    LOCK4KMC_RAND = 2, /* Random number generation lock */
    LOCK4KEYSTORE_READ = 3, /* Read keystore data and corresponding files in the memory */
    WSEC_LOCK_NUM = 4,
} WsecThreadLockFor;

typedef enum {
    PROCLOCK4KEYSTORE  = 0,
    WSEC_PROC_LOCK_NUM = 1
} WsecProclockFor;

/* 4. Other data types and structures */
typedef struct TagWsecLockRegStatus {
    WsecUint32 state;
} WsecLockRegStatus;

/* mip */
#define KMC_MASKCODE_LENGTH 128
/*
 * 2: Only the first part is used, and the last part is used for verification.
 */
#define KMC_MASKCODE_KEY_LENGTH (2 * KMC_MASKCODE_LENGTH)

typedef struct TagWsecFuncRegStatus {
    WsecUint32 state;
} WsecFuncRegStatus;

#define WSEC_TIME_TICK_NUM 4

typedef enum {
    WSEC_TIME_TICK_IO      = 0,
    WSEC_TIME_TICK_SYNC    = 1,
    WSEC_TIME_TICK_HW      = 2,
    WSEC_TIME_TICK_TEE     = 3,
} WsecTimeTickIndex;

/* ksm */
#define WSEC_HASH_LEN_MAX   64 /* Maximum HMAC result length */
#define KMC_KSF_NUM 2
#define KMC_EXT_KSF_NUM 2
#define KMC_MATERIAL_SIZE 32
#define KMC_MASKED_KEY_LEN 128
#define DEFAULT_ENCLAVE_ROOT_KEY 32

/* Root Key (RK) data structure */
#pragma pack(1)
    typedef struct TagKmcRkParameters {
    unsigned char rkMaterialA[KMC_MATERIAL_SIZE]; /* Root key material 1, which is fixed to 32 bytes. */
    unsigned char rkMaterialB[KMC_MATERIAL_SIZE]; /* Root key material 2. The value is fixed to 32 bytes. */
    unsigned char reserve[32]; /* 32 bytes are reserved. */
    unsigned char rmkSalt[32]; /* Derived RMK salt value, which is fixed at 32 bytes. */
} KmcRkParameters; /* Basic parameters for exporting the root key */
#pragma pack()

#pragma pack(1)
typedef struct TagKmcKsfRk {
    KmcRkAttributes rkAttributes;  /* RK basic attributes */
    KmcRkParameters rkParameters;  /* RootKey construction parameters */
    WsecUint32      mkNum;         /* Total number of master keys */
    WsecUint32      updateCounter;
    WsecUint32      mkRecordLen; /* Maximum length of each MK ciphertext. This parameter is extended in KSFV3. */
    /*
     * Number of MK updates in the shared domain,
     * which is used to determine the host identity (new master) during startup.
     */
    WsecUint32      sharedMkUpdateCounter;
    unsigned char   hashAlg;
    unsigned char   hmacAlg;
    unsigned char   kdfAlg;
    unsigned char   paddingMode;
    unsigned char   hasKsfExt;     /* hasKsfExt */
    unsigned char   headerExt;     /* hasKsfHeaderExt */
    unsigned char   footerExt;     /* hasKsfFooterExt */
    unsigned char   envType;       /* 1 is default Tee */
    unsigned char   reserve[16];   /* Reserved 16 bytes */
    unsigned char   aboveHash[32]; /* SHA256 result, 32 bytes */
} KmcKsfRk; /* RootKey information in Keystore */
#pragma pack()

typedef struct TagKmcKsfHardRk {
    WsecBool hasHardRk;
    WsecBuff hrkInfo;    /* Hardware root key access information */
    WsecBuff srkInfo;    /* Masked key encryption result by the hardware root key */
} KmcKsfHardRk;

typedef union TagKmcMaskedKey {
    /*
     * Plaintext key at the software layer, encrypted and decrypted by the hardware key,
     * and masked plaintext stored in the memory
     */
    unsigned char maskedKey[KMC_MASKED_KEY_LEN];
    struct {
        /* 32-byte software layer root key. This parameter is valid when HASSOFTLEVELRK is set to TRUE. */
        unsigned char softLevelRk[32];
        unsigned char ksfHmacKey[32];  /* KSF integrity verification key (32 bytes) */
        unsigned char reserve[64];     /* Reserved 64 bytes are used to fill in random numbers. */
    } maskedKeyInfo;
} KmcMaskedKey;

typedef struct TagKmcHardRkMem {
    WsecHandle   hwRkHandle; /* Hardware root key handle */
    KmcKsfHardRk hardRk;
    WsecUint32   refCount;
    KmcMaskedKey key;
} KmcHardRkMem;

#pragma pack(1)
typedef struct TagKmcExtMem {
    unsigned char extKsfHash[WSEC_HASH_LEN_MAX];
    WsecArray     novaKsfMem;
} KmcExtMem;
#pragma pack()

typedef struct TagKmcKsfMem {
    char         *fromFile;      /* Keystore file from which the data comes */
    /*
     * MK array. Its elements store addresses of the KmcMemMk type.
     * Domain IDs and key types can be sorted in ascending order.
     * The domain ID and key ID must be unique.
     */
    WsecArray     mkArray;
    WsecUint32    updateCounter; /* Number of keystore file update rounds. */
    /*
     * Number of times that the master key in the shared domain is updated, which is used to determine
     * the host identity (the new one is the master one) during startup.
     */
    WsecUint32    sharedMkUpdateCounter;

    /* The following fields are extended in V3: */
    unsigned char ksfHash[WSEC_HASH_LEN_MAX];
    KmcKsfRk      rk;         /* KmcKsfRk */
    KmcKsfHardRk  hardRk;     /* Read HRKINFO and SRKINFO from KSF and load them to the hardware key handle. */
    KmcExtMem     extMem;
    WsecArray     headerSubs;
    WsecArray     footerSubs;
    WsecSrkPrimitive *srkPrimitive;
    WsecBool isUpdateRk;
} KmcKsfMem; /* KSF file in the memory */

#pragma pack(1)
typedef struct TagKmcCfgDataProtect {
    WsecUint32    algId;         /* Algorithm ID */
    WsecUint16    keyType;       /* Keys are classified by usage. For details, see KmcKeyType. */
    WsecBool      appendMac;     /* Add Integrity Check Value */
    WsecUint32    keyIterations; /* Number of key iterations */
    unsigned char reserve[8];    /* Reserved 8 bytes */
} KmcCfgDataProtect;
#pragma pack()

typedef struct TagKmcCfg {
    /* RK configuration information (valid only when the RK is generated in the CBB) */
    KmcCfgRootKey       rkCfg;
    KmcCfgKeyManagement keyManagementCfg;  /* Key management parameters */
    KmcCfgDataProtect   dataProtectCfg[3]; /* Data protection configuration, including 3 types */
    WsecArray           domainCfgArray;    /* Domain array. The type of the element is KmcDomainCfg. */
} KmcCfg;

typedef struct TagKmcSys {
    char        *keystoreFile[KMC_KSF_NUM];             /* Keystore file name, which is backed up in two copies. */
    WsecUint32  role;                        /* Identity information */
    WsecUint32  state;                       /* KMC Status */
    /* The following fields are extended in V3: */
    WsecBool    isHardware;                  /* Hardware-Protected Root Key */
    WsecBool    hasSoftLevelRk;              /* Include Software-Layer Root Key */
    WsecBool    enableThirdBackup;           /* enable the third backup path, default false; */
    WsecBool    deleteKsfOnInitFailed;       /* delete ksf when init failed */
    WsecBool    enableEnclave;
    char        *keystoreBackupFile;
    const KmcTeeInitParam *initParam;
    WsecBool    haveHw;
    unsigned char keyStoreMode;
    unsigned char userDefineSrk;
    char        *extKsf[KMC_EXT_KSF_NUM];
} KmcSys;

typedef struct TagKmcShareKey {
    WsecUint8  *shareKeyByEnc;
    WsecUint32  skLen;
} KmcShareKey;

/* All callback functions */
typedef struct TagWsecCallbacksInternal {
    WsecMemCallbacks            memCallbacks;
    WsecFileCallbacks           fileCallbacks;
    WsecLockCallbacks           lockCallbacks;
    WsecProcLockCallbacks       procLockCallbacks;
    WsecBasicRelyCallbacks      basicRelyCallbacks;
    WsecRngCallbacks            rngCallbacks;
    WsecTimeCallbacks           timeCallbacks;
    WsecHardwareCallbacks       hardwareCallbacks;
    WsecAdvanceCallbacks        advanceCallbacks;

    WsecProcLockCallbacksMulti  procLockCallbacksMulti;
    WsecBasicRelyCallbacksMulti basicRelyCallbacksMulti;
    WsecHardwareCallbacksMulti  hardwareCallbacksMulti;
} WsecCallbacksInternal;

typedef struct TagKmcCbbCtx {
    WsecCallbacksInternal regCallbacks; // 回调函数
    /* g_cbbFuncRegState */
    WsecFuncRegStatus cbbFuncRegState;  // 回调函数注册标志
    /* g_keyStore */
    KmcKsfMem *keystore;                // ksf文件信息：mk信息+硬件根密钥信息
    /* g_kmcCfg */
    KmcCfg *kmcCfg;                     // kmc配置信息 domain信息 rootkey配置信息（有效时间等）
    /* g_kmcDefaultRkCfg */
    KmcCfgRootKey kmcDefaultRkCfg;      // rootkey的默认配制项
    /* g_kmcAlgCfg */
    KmcAlgCnfParam algCnfParam;         // 内部算法配置信息
    /* g_maskCode */
    unsigned char maskCode[KMC_MASKCODE_KEY_LENGTH];
    /* g_xorCheck */
    unsigned char xorCheck[KMC_MASKCODE_LENGTH];
    /* g_keyName */
    char keyName[48]; /* The value is a string of up to 48 digits. */   // keyring
    /* g_hasName */
    WsecBool hasName;
    /* g_hardRkMem */
    WsecArray hardRkMem;                // 存储所有加载或创建的硬件根密钥内存数据
    /* g_kmcSys */
    KmcSys kmcSys;                      // kmc系统信息 对应ksf文件+角色+状态+是否硬件等
    /* g_maxMkCount */
    int maxMkCount;                     // mk最大个数
    /* g_lockEx */
    WsecHandle lockEx[WSEC_LOCK_NUM];
    /* g_kmcProcLock */
    WsecHandle kmcProcLock[WSEC_PROC_LOCK_NUM];
    /* g_cbbSysEx */
    WsecLockRegStatus cbbSysEx;   /* Check whether the lock function is registered. */

    void *userData;                     // 对接KMS需要透传的用户数据
    WsecUint32 multiFlag;               // 是否为多实例

    WsecHandle gpContext;
    WsecBool teeInitSuccess;
    WsecUint32 faultCode; // tee errcode
    WsecUint32 perfConf[WSEC_TIME_TICK_NUM];
} KmcCbbCtx;

KmcCbbCtx *GetKmcCtx(void);

typedef struct {
    void* evp_pkey_ctx_new_id_fun;
    void* evp_pkey_keygen_fun;
    void* evp_pkey_keygen_init_fun;
    void* bn_bn2bin_fun;
    void* evp_pkey_new_fun;
    void* evp_pkey_free_fun;
    void* evp_pkey_ctx_free_fun;
    void* evp_pkey_get_raw_private_key_fun;
    void* evp_pkey_get_raw_public_key_fun;
    void* evp_pkey_paramgen_init_fun;
    void* evp_pkey_ctx_ctrl_fun;
    void* evp_pkey_get0_ec_key_fun;
    void* ec_point_get_affine_coordinates_fun;
    void* ec_key_get0_group_fun;
    void* ec_key_get0_public_key_fun;
    void* ec_key_get0_private_key_fun;
    void* bn_free_fun;
    void* evp_pkey_new_raw_private_key_fun;
    void* ec_key_new_by_curve_name_fun;
    void* ec_key_set_private_key_fun;
    void* evp_pkey_set1_ec_key_fun;
    void* evp_pkey_new_raw_public_key_fun;
    void* ecdsa_sig_new_fun;
    void* ecdsa_sig_set0_fun;
    void* i2d_ecdsa_sig_fun;
    void* ecdsa_sig_free_fun;
    void* evp_sha256_fun;
    void* evp_sha384_fun;
    void* evp_sha512_fun;
    void* evp_sm3_fun;
    void* evp_pkey_ctx_new_fun;
    void* bn_bin2bn_fun;
    void* ec_key_free_fun;

    void* rsa_pkey_ctx_ctrl_fun;
    void* evp_pkey_get0_rsa_fun;
    void* bn_num_bits_fun;
    void* rsa_get0_n_fun;
    void* rsa_get0_e_fun;
    void* rsa_get0_d_fun;
    void* evp_pkey_paramgen_fun;
    void* bn_new_fun;
    void* bn_bn2binpad_fun;
    void* evp_md_ctx_new_fun;
    void* evp_md_ctx_reset_fun;
    void* evp_digestsigninit_fun;
    void* evp_digestsign_fun;
    void* evp_md_ctx_free_fun;
    void* rsa_new_fun;
    void* rsa_set0_key_fun;
    void* rsa_free_fun;
    void* evp_pkey_assign_fun;
    void* evp_digestinit_ex_fun;
    void* evp_digestupdate_fun;
    void* evp_digestfinal_ex_fun;
    void* evp_pkey_sign_init_fun;
    void* evp_md_meth_dup_fun;
    void* evp_md_meth_free_fun;
    void* evp_pkey_sign_fun;
    void* evp_pkey_set_alias_type_fun;
    void* evp_digestverifyinit_fun;
    void* evp_digestverify_fun;
    void* evp_pkey_verify_init_fun;
    void* evp_pkey_verify_fun;
    void* ec_key_set_public_key_affine_coordinates_fun;
    void* evp_pkey_encrypt_init_fun;
    void* evp_pkey_encrypt_fun;
    void* evp_pkey_decrypt_init_fun;
    void* evp_pkey_decrypt_fun;
    void* evp_verifyfinal_fun;
    void* evp_signfinal_fun;
    void* crypto_free_fun;
    void* asn1_get_object_fun;
    void* asn1_item_d2i_fun;
    void* asn1_item_free_fun;
    void* i2d_publickey_fun;
    void* d2i_publickey_fun;
    void* evp_pkey_ctx_set_ec_paramgen_curve_nid_fun;
    void* evp_pkey_get_bn_param_fun;
    void* evp_pkey_ctx_set_signature_md_fun;
    void* evp_pkey_ctx_new_from_name_fun;
    void* evp_pkey_fromdata_init_fun;
    void* ossl_param_bld_new_fun;
    void* ossl_param_bld_push_utf8_string_fun;
    void* ossl_param_bld_push_BN_fun;
    void* ossl_param_bld_to_param_fun;
    void* evp_pkey_fromdata_fun;
    void* ossl_param_free_fun;
    void* ossl_param_bld_free_fun;
    void* ossl_param_bld_push_octet_string_fun;
    void* evp_pkey_ctx_set_rsa_oaep_md_fun;
    void* evp_pkey_ctx_set_rsa_mgf1_md_fun;
} KmcAsymFuns;

unsigned long KmcCheckKmcCtx(WsecHandle kmcCtx);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* KMC_SRC_COMMON_WSECV2_CTX_H */
