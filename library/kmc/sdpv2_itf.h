/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2021. All rights reserved.
 * Description: header file of SDP V2 external interfaces

 * Create: 2014-06-16

 */

#ifndef KMC_SRC_SDP_SDPV2_ITF_H
#define KMC_SRC_SDP_SDPV2_ITF_H

#include "wsecv2_type.h"
#include "wsecv2_itf.h"
#include "sdpv3_type.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

/* Key derivation length */
#define SDP_HMAC_DERIVE_KEY_LEN 16u
#define SDP_HMAC_HEAD_LEN_V2    70 // SDP_HMAC_HEAD_LEN_V2 is sizeof(SdpHmacExHeaderEx) + 8 bytes(reserve)
#define SDP_CIPHER_HEAD_LEN_V2  72 // SDP_CIPHER_HEAD_LEN_V2 is sizeof(SdpCipherHeaderEx) + 8 bytes(reserve)
#define SDP_PWD_HEAD_LEN_EX     60 // SDP_PWD_HEAD_LEN_EX is sizeof(SdpPwdHeaderEx) + 8 bytes(reserve)
/* Structure */
/* Ciphertext Header Definition */
#pragma pack(1)


typedef struct TagSdpCipherHeaderEx {
    WsecUint32    cipherVersion;
    WsecUint32    hmacFlag;    /* Determine whether to add HMAC */
    WsecUint32    domainId;
    WsecUint32    keyId;
    WsecUint32    cipherAlgId;
    unsigned char mkHashId[WSEC_MK_HASH_REC_LEN]; /* The first eight bytes of the MK SHA256. */
    unsigned char salt[SDP_SALT_LEN_V2];     /* The salt value is 8 bytes. */
    unsigned char iv[16];      /* IV: 16 bytes */
    unsigned char kdfAlgId;    /* Used to get work key */
    unsigned char iter[3];     /* The iteration rounds to get work key */
    WsecUint32    extLen;
    WsecUint32    ciphertextLen;
} SdpCipherHeaderEx;

typedef struct TagSdpHmacHeaderEx {
    WsecUint32    hmacAlgId;  /* HMAC algorithm */
    unsigned char salt[8];    /* The salt value of the generated key is 8 bytes. */
    WsecUint32    extLen; /* 4 bytes are reserved. */
    WsecUint32    hmacLen;    /* Indicates the length of an HMAC. */
} SdpHmacHeaderEx;
#pragma pack()

#pragma pack(1)
typedef struct TagSdpHmacExHeaderEx {
    WsecUint32      version;            /* Data protection module version */
    WsecUint32      domain;             /* Field corresponding to the key ID */
    WsecUint32      algId;              /* Algorithm ID */
    WsecUint32      keyId;              /* Key ID used to calculate the HMAC */
    WsecUint32      kdfIter;
    WsecUint32      kdfAlgId;
    unsigned char   salt[SDP_SALT_LEN];
    unsigned char   mkHash[WSEC_MK_HASH_REC_LEN];
    WsecUint32      extLen;
    unsigned char   reserve[12];
} SdpHmacExHeaderEx;
#pragma pack()

#pragma pack(1)
typedef struct TagSdpHmacAlgAttributesEx {
    union {
        unsigned char buff[SDP_HMAC_HEAD_LEN_V2];
        SdpHmacExHeaderEx hmacHeader;
    };
} SdpHmacAlgAttributesEx;
#pragma pack()

#pragma pack(1)
typedef struct TagSdpCipherHeaderBuffEx {
    union {
        unsigned char   buff[SDP_CIPHER_HEAD_LEN_V2];
        SdpCipherHeaderEx cipherHeader;
    };
} SdpCipherHeaderBuffEx;
#pragma pack()

#pragma pack(1)
typedef struct TagSdpBodCipherHeaderEx {
    SdpCipherHeaderBuffEx  cipherBuff;
    SdpHmacAlgAttributesEx hmacBuff;
    WsecUint32 extLen;
    unsigned char reserve[12];
} SdpBodCipherHeaderEx;
#pragma pack()

#pragma pack(1)
typedef struct TagSdpPwdHeaderEx {
    WsecUint32    version;            /* Data protection module version */
    WsecUint32    algId;              /* Algorithm ID */
    /* Iteration round, which is configured by the application for the key management module to derive working keys. */
    WsecUint32    iter;
    unsigned char salt[SDP_SALT_LEN]; /* Salt generated by the data protection module. */
    WsecUint32    cipherLen;          /* Length of the encrypted password */
    WsecUint32    extLen;
    unsigned char reserve[16];
} SdpPwdHeaderEx;
#pragma pack()

typedef struct TagSdpBodCipherInfoSt {
    WsecUint32 cipherAlgId;
    WsecUint32 hasHmac;
    WsecUint32 hmacAlgId;
    unsigned char reserve[20];
} SdpBodCipherInfo;

typedef struct TagSdpCipherCnfParam {
    WsecUint32    domain;
    WsecUint32    cipherAlgId;
    WsecUint32    hmacAlgId;
} SdpCipherCnfParam;


/**
 * @brief      Specify the domain and encryption algorithm ID, encrypt the specified plaintext,
               and obtain the ciphertext.
 * @param[in]  domain Domain ID of the key used for encrypt.
 * @param[in]  algId AlgId used for calculating the encrypt.
 * @param[in]  plainText plain buffer.
 * @param[in]  plaintextLen plain buffer Len.
 * @param[out] ciphertext cipher buffer.
 * @param[out] ciphertextLen cipher buffer len.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread, cryptographic computation operation and TEE operations (only TEE mode).
 */
unsigned long SdpEncryptEx(WsecUint32 domain, WsecUint32 algId,
    const unsigned char *plainText, WsecUint32 plaintextLen,
    unsigned char *ciphertext, WsecUint32 *ciphertextLen);


/**
 * @brief      Decrypts the specified ciphertext data. The data with or without the HMAC can be decrypted.
 * @param[in]  domain Domain ID of the key used for encrypt.
 * @param[in]  ciphertext cipher buffer.
 * @param[in]  ciphertextLen cipher buffer len.
 * @param[out] plainText plain buffer.
 * @param[out] plaintextLen plain buffer Len.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread, cryptographic computation operation and TEE operations (only TEE mode).
 */
unsigned long SdpDecryptEx(WsecUint32 domain,
    const unsigned char *ciphertext, WsecUint32 ciphertextLen,
    unsigned char *plainText, WsecUint32 *plaintextLen);

/*
 * Specify the domain and encryption/MAC algorithm ID, encrypt the specified plaintext,
 * calculate the MAC, and obtain the ciphertext.
 */
unsigned long SdpEncryptWithHmacEx(WsecUint32 domain,
    WsecUint32 cipherAlgId, WsecUint32 hmacAlgId,
    const unsigned char *plainText, WsecUint32 plaintextLen,
    unsigned char *ciphertext, WsecUint32 *ciphertextLen);

/*
 * Specify the domain and encryption/MAC algorithm ID, encrypt the specified plaintext,
 * calculate the MAC, and obtain the ciphertext.
 * Note
 * This interface is used to resolve the problem that the HMAC key length of the SdpEncryptWithHmacEx
 * interface is insufficient, but the interface is incompatible.
 * The application scenarios of the SDP_DecryptEx interface in the old version are as follows,
 * 1. In the scenario where the KMC is deployed on multiple nodes (only V2 supports the deployment on multiple nodes),
 * this interface is used for newly deployed nodes.
 * In the scenario where SdpEncryptWithHmacV3 is used for encryption and the old node uses SDP_DecryptEx
 * in the old version for decryption,
 * SdpEncryptWithHmacV3 is incompatible with SDP_DecryptEx in earlier versions.
 * SDP_DecryptEx cannot decrypt data encrypted by SdpEncryptWithHmacV3.
 * SdpEncryptWithHmacV3
 * 2. In the version rollback scenario, after the data encrypted using SdpEncryptWithHmacV3 is rolled
 * back to the source version,
 * SDP_DecryptEx Failed to Decrypt the Newly Encrypted SdpEncryptWithHmacV3 Data
 * Therefore, for a single-node system, SdpEncryptWithHmacV3 is upgraded for multiple nodes,
 * or only old nodes are encrypted.
 * In the scenarios where new nodes are deployed for decryption, the SdpEncryptWithHmacV3 encryption
 * algorithm that cannot be decrypted after the rollback is considered.
 * The new SdpEncryptWithHmacV3 interface should be used after the risk of the output data is eliminated.
 */
/**
 * @brief      Specify the domain and encryption/MAC algorithm ID, encrypt the specified plaintext,
 *             calculate the MAC, and obtain the ciphertext.
 * @param[in]  domain Domain ID of the key used for encrypt.
 * @param[in]  algId AlgId used for calculating the encrypt.
 * @param[in]  hmacAlgId AlgId used for calculating the HMAC.
 * @param[in]  plainText plain buffer.
 * @param[in]  plaintextLen plain buffer Len.
 * @param[out] ciphertext cipher buffer.
 * @param[out] ciphertextLen cipher buffer len.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread, cryptographic computation operation and TEE operations (only TEE mode).
 */
unsigned long SdpEncryptWithHmacV3(WsecUint32 domain,
    WsecUint32 cipherAlgId, WsecUint32 hmacAlgId,
    const unsigned char *plainText, WsecUint32 plaintextLen,
    unsigned char *ciphertext, WsecUint32 *ciphertextLen);

/**
 * @brief      Get the length of the ciphertext data corresponding to the plaintext data when HMAC is not calculated.
 * @param[in]  plaintextLen plaintext length.
 * @param[out] ciphertextLenOut Ciphertext length calculated based on the plaintext length.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      NON-Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   No.
 */
unsigned long SdpGetCipherDataLenEx(WsecUint32 plaintextLen, WsecUint32 *ciphertextLenOut);

/**
 * @brief      Obtains the length of the ciphertext data, algCnf MUST be same as the configuration of WsecInitializeKmc.
 * @param[in]  algCnf Encryption Parameter Structure.
 * @param[in]  plaintextLen plaintext length.
 * @param[out] ciphertextLen Ciphertext length calculated based on the plaintext length and algCnf.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   No.
 */
unsigned long SdpGetCipherDataLenExByAlgCnf(const KmcAlgCnfParam *algCnf, WsecUint32 plaintextLen,
    WsecUint32 *ciphertextLen);

/**
 * @brief      Obtains the length of the ciphertext data corresponding to the plaintext data when HMAC is calculated.
 * @param[in]  plaintextLen plaintext length.
 * @param[out] ciphertextLenOut Ciphertext length calculated based on the plaintext length.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   No.
 */
unsigned long SdpGetCipherDataLenWithHmacEx(WsecUint32 plaintextLen, WsecUint32 *ciphertextLenOut);


/**
 * @brief      Obtains the header structure of the input ciphertext.
 * @param[in]  ciphertext Ciphertext buffer.
 * @param[in]  ciphertextLen Ciphertext length.
 * @param[out] cipherHeader the header structure of the input ciphertext.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   No.
 */
unsigned long SdpGetCipherHeaderEx(const unsigned char *ciphertext, WsecUint32 ciphertextLen,
    SdpCipherHeaderEx *cipherHeader);

/**
 * @brief      Obtain MKInfo based on the obtained ciphertext information.
 * @param[in]  cipherData Ciphertext buffer.
 * @param[in]  cipherDataLen Ciphertext length.
 * @param[out] mkInfo MKInfo based on the obtained ciphertext.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread and TEE operations (only TEE mode).
 */
unsigned long SdpGetMkDetailByCipher(const unsigned char *cipherData, WsecUint32 cipherDataLen, KmcMkInfo *mkInfo);

/* according to passwordHashLen get pwdCipherLen  */
size_t SdpGetPwdCipherLenEx(size_t passwordHashLen);

/* according to passwordHashLen get pwdCipherLen */
unsigned long  SdpGetPwdCipherLenV3(WsecUint32 passwordHashLen, WsecUint32 *pwdCipherLen);

/* Protection password */
unsigned long SdpProtectPwdEx(WsecUint32 algId, WsecUint32 iter, const unsigned char *plain, WsecUint32 plainLen,
    unsigned char *cipher, WsecUint32 cipherLen);

/* Plaintext password authentication */
unsigned long SdpVerifyPwdEx(const unsigned char *plainText, WsecUint32 plainLen,
    const unsigned char *cipherText, WsecUint32 cipherLen);

/* Obtains MKInfo based on hmacData. */
unsigned long SdpGetMkDetailByHmacDataEx(WsecVoid *hmacData, WsecUint32 hmacLen, KmcMkInfo *mkInfo);

/* Get mac len by symAlgId and hmacAlgId */
unsigned long SdpGetMacLenForEncryptEx(WsecUint32 cipherAlgId, WsecUint32 hmacAlgId, WsecUint32 *macLen);

/**
 * @brief        Calculates the HMAC of the specified data using the key in the specified domain and the specified
                 algorithm ID.
 * @param[in]    domain Configuration the domain.
 * @param[in]    algId Algorithm to calculate Hmac(must be a value in WsecAlgId and use HMAC).
 * @param[in]    plainText Value to be calculated Hmac.
 * @param[in]    plaintextLen Length of the value to be calculated Hmac.
 * @param[out]   hmacData Hmac result, need allocate memory by caller.
 * @param[outin] hmacLen The input parameter is the length of the hmacData value buff. The output parameter is
    the actual length of the plainText value.
 * @return       WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread, cryptographic computation operation and TEE operations (only TEE mode).
 */
unsigned long SdpHmacEx(WsecUint32 domain, WsecUint32 algId, const unsigned char *plainText, WsecUint32 plaintextLen,
    unsigned char *hmacData, WsecUint32 *hmacLen);

/**
 * @brief     Check whether the HMAC result is correct.
 * @param[in] domain Configuration the domain.
 * @param[in] plainText Value to be calculated Hmac.
 * @param[in] plaintextLen Length of the value to be calculated Hmac.
 * @param[in] hmacData Value to be checked Hmac.
 * @param[in] hmacLen Length of the value to be checked Hmac.
 * @return    WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread, cryptographic computation operation and TEE operations (only TEE mode).
 */
unsigned long SdpVerifyHmacEx(WsecUint32 domain, const unsigned char *plainText, WsecUint32 plaintextLen,
    const unsigned char *hmacData, WsecUint32 hmacLen);

/**
 * @brief      Obtains the maximum possible HMAC length.
 * @param[out] hmacLen Return maximum possible HMAC len when success.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Non-Thread-safe function, cannot be invoked concurrently with the WsecInitializeKmc,
 *                      WsecInitializeEx, WsecInitializeKmcm, WsecResetEx, WsecResetHw, WsecFinalizeEx.
 *  - OS difference:    No.
 *  - Time consuming:   No.
 */
unsigned long SdpGetHmacLenEx(WsecUint32 *hmacLen);

/* Get hmac header len by version or header before decrypt, header only support sdp v2 */
unsigned long SdpDecGetHmacHeaderLen(const unsigned char *verBuff, WsecUint32 verLen, WsecUint32 *outLen);

/* Get BodcipherHeaderLen by version before decrypt */
unsigned long SdpDecGetBodHeaderLen(const unsigned char *verBuff, WsecUint32 verBuffLen, WsecUint32 *outLen);

/* Get HmacHeaderLen by version before encrypt */
WsecUint32 SdpEncGetHamcHeaderLen(void);

/**
 * @brief      Obtains the HMAC header length with tlvLen.
 * @param[out] outLen Return the HMAC header length with tlvLen.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Non-Thread-safe function, cannot be invoked concurrently with the WsecInitializeKmc,
 *                      WsecInitializeEx, WsecInitializeKmcm, WsecResetEx, WsecResetHw, WsecFinalizeEx.
 *  - OS difference:    No.
 *  - Time consuming:   No.
 */
unsigned long SdpEncGetHmacHeaderLenV3(WsecUint32 *outLen);

/* Get BodcipherHeaderLen by version before encrypt */
WsecUint32 SdpEncGetBodHeaderLen(void);

/* Get BodcipherHeaderLen by version before encrypt */
unsigned long SdpEncGetBodHeaderLenV3(WsecUint32 cipherAlgId, WsecUint32 hmacAlgId, WsecUint32 *outLen);

unsigned long SdpHmacInitEx(WsecUint32 domain, const void *hmacAlgAttributes, WsecUint32 attrLen, WsecHandle *ctx);

unsigned long SdpHmacUpdateEx(WsecHandle *ctx, const unsigned char *plainText, WsecUint32 plaintextLen);

unsigned long SdpHmacFinalEx(WsecHandle *ctx, unsigned char *hmacData, WsecUint32 *hmacLen);

unsigned long SdpFileHmacEx(WsecUint32 domain, const char *file, const SdpHmacAlgAttributesEx *hmacAlgAttributes,
    WsecVoid *hmacData, WsecUint32 *hmacLen);

/**
 * @brief        Calculates the HMAC of the file data using the key in the specified domain and the specified
                 algorithm ID.
 * @param[in]    domain Configuration the domain.
 * @param[in]    file Path of the file to be calculated hmac.
 * @param[in]    hmacAlgAttributes Hmac header value and length, need to invoke SdpGetHmacAlgAttrV3 to obtain.
 * @param[out]   hmacData Hmac result, need allocate memory by caller.
 * @param[outin] hmacLen The input parameter is the length of the hmacData value buff. The output parameter is
    the actual length of the plainText value.
 * @return       WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread, cryptographic computation operation and TEE operations (only TEE mode).
 */
unsigned long SdpFileHmacV3(WsecUint32 domain, const char *file, WsecBuffConst *hmacAlgAttributes,
    WsecVoid *hmacData, WsecUint32 *hmacLen);

unsigned long SdpVerifyFileHmacEx(WsecUint32 domain, const char *file, const void *hmacAlgAttributes,
    WsecUint32 attrLen, const WsecVoid *hmacData, WsecUint32 hmacLen);

unsigned long SdpGetHmacAlgAttrEx(WsecUint32 domain, WsecUint32 algId, SdpHmacAlgAttributesEx *hmacAlgAttributes);

/**
 * @brief        Obtains the HMAC header value and length with tlvLen.
 * @param[in]    domain Configuration the domain.
 * @param[in]    algId Algorithm to calculate Hmac(must be a value in WsecAlgId and use HMAC).
 * @param[out]   hmacAlgAttributes Hmac header value, need allocate memory by caller.
 * @param[outin] attrLen The input parameter is the length of the hmacAlgAttributes value buff. The output parameter is
    the actual length of the Hamc header value.
 * @return       WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread.
 */
unsigned long SdpGetHmacAlgAttrV3(WsecUint32 domain, WsecUint32 algId, WsecVoid *hmacAlgAttributes,
    WsecUint32 *attrLen);

unsigned long SdpEncryptInitEx(WsecUint32 domain, WsecUint32 cipherAlgId, WsecUint32 hmacAlgId, WsecHandle *ctx,
    SdpBodCipherHeaderEx *bodCipherHeader);

/**
 * @brief      Prepar to initialize configuration of stream encrypt.
 * @param[in]  cipherCnf Configuration the domain, encrypt algorithm and Hmac algorithm.
 * @param[out] ctx Encryption handle.
 * @param[out] bodCipherHeader Encrypt header value and length, need allocate memory by caller.
 * @return     WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate ctx memory need release by SdpEncryptFinalEx.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread, cryptographic computation operation and TEE operations (only TEE mode).
 */
unsigned long SdpEncryptInitV3(SdpCipherCnfParam *cipherCnf, WsecHandle *ctx, WsecBuff *bodCipherHeader);

/**
 * @brief        Calculating the cipher of stream encrypt.
 * @param[in]    ctx Encryption handle, created by SdpEncryptInitEx or SdpEncryptInitV3.
 * @param[in]    plainText Value to be encypted.
 * @param[in]    plainLen Length of the value to be encypted.
 * @param[out]   cipherText Cipher result, need allocate memory by caller.
 * @param[outin] cipherLen The input parameter is the length of the cipherText value buff. The output parameter is
    the actual length of the cipher.
 * @return       WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread, cryptographic computation operation.
 */
unsigned long SdpEncryptUpdateEx(WsecHandle *ctx, const unsigned char *plainText, WsecUint32 plainLen,
    unsigned char *cipherText, WsecUint32 *cipherLen);

/**
 * @brief        Releasing handle and calculating Hmac value of stream encrypt.
 * @param[in]    ctx Encryption handle, created by SdpEncryptInitEx or SdpEncryptInitV3.
 * @param[out]   cipherText Cipher result, need allocate memory by caller.
 * @param[outin] cipherLen The input parameter is the length of the cipherText value buff. The output parameter is
    the actual length of the cipher.
 * @param[out]   hmacText Hmac result, need allocate memory by caller.
 * @param[outin] hmacLen The input parameter is the length of the hmacText value buff. The output parameter is
    the actual length of the Hmac value.
 * @return       WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread, cryptographic computation operation.
 */
unsigned long SdpEncryptFinalEx(WsecHandle *ctx, unsigned char *cipherText, WsecUint32 *cipherLen,
    unsigned char *hmacText, WsecUint32 *hmacLen);

/**
 * @brief      Prepar to initialize configuration of stream decrypt.
 * @param[in]  domain Configuration the domain.
 * @param[in]  ctx Decryption handle, created by SdpEncryptInitEx or SdpEncryptInitV3.
 * @param[out] bodCipherHeader Decrypt header value, created by SdpEncryptInitEx or SdpEncryptInitV3.
 * @param[in]  bodHeaderLen The length of decrypt header value.
 * @note
 *  - Memory operation: Allocate ctx memory need release by SdpEncryptFinalEx.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread, cryptographic computation operation and TEE operations (only TEE mode).
 */
unsigned long SdpDecryptInitEx(WsecUint32 domain, WsecHandle *ctx, const WsecVoid *bodCipherHeader,
    WsecUint32 bodHeaderLen);

/**
 * @brief        Calculating the plain of stream decrypt.
 * @param[in]    ctx Decryption handle, created by SdpEncryptInitEx or SdpEncryptInitV3.
 * @param[in]    cipherText Value to be decypted.
 * @param[in]    cipherLen Length of the value to be decypted.
 * @param[out]   plainText Plain result, need allocate memory by caller.
 * @param[outin] plainLen The input parameter is the length of the plainText value buff. The output parameter is
    the actual length of the plain.
 * @return       WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread, cryptographic computation operation.
 */
unsigned long SdpDecryptUpdateEx(WsecHandle *ctx, const unsigned char *cipherText, WsecUint32 cipherLen,
    unsigned char *plainText, WsecUint32 *plainLen);

/**
 * @brief        Releasing handle and checking Hmac value of stream decrypt.
 * @param[in]    ctx Decryption handle, created by SdpEncryptInitEx or SdpEncryptInitV3.
 * @param[in]    hmacText Value to be checked Hmac.
 * @param[in]    hmacLen Length of the value to be checked Hmac value.
 * @param[out]   plainText Plain result, need allocate memory by caller.
 * @param[outin] plainLen The input parameter is the length of the plainText value buff. The output parameter is
    the actual length of the plain value.
 * @return       WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread, cryptographic computation operation.
 */
unsigned long SdpDecryptFinalEx(WsecHandle *ctx, const unsigned char *hmacText, WsecUint32 hmacLen,
    unsigned char *plainText, WsecUint32 *plainLen);


unsigned long SdpFileEncryptEx(WsecUint32 domain, WsecUint32 cipherAlgId, WsecUint32 hmacAlgId,
    const char *plainFile, const char *cipherFile, const CallbackGetFileDateTime getFileDateTime);

unsigned long SdpFileDecryptEx(WsecUint32 domain, const char *cipherFile, const char *plainFile,
    const CallbackSetFileDateTime setFileDateTime);

/* Obtain the encryption infomation of the ciphertext file. */
unsigned long SdpGetCipherInfoFromBodHeader(const unsigned char *bodCipherHeader, WsecUint32 bodCipherHeaderLen,
    SdpBodCipherInfo* cipherInfo);

/**
 * @brief        Obtains the mk infomation from cipher header.
 * @param[in]    bodCipherHeader Stream encypt cipher header.
 * @param[in]    bodCipherLen The length of stream encypt cipher header.
 * @param[out]   mkInfo Mk infomation result, need allocate memory by caller.
 * @return       WSEC_SUCCESS on success, other error code on failure.
 * @note
 *  - Memory operation: Allocate and release memory by itself, doesn't need invoker release.
 *  - Thread safe:      Thread-safe function.
 *  - OS difference:    No.
 *  - Time consuming:   Yes, related to thread.
 */
unsigned long SdpGetMkDetailByBodCipherHeaderEx(WsecVoid *bodCipherHeader, WsecUint32 bodCipherLen, KmcMkInfo *mkInfo);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* KMC_SRC_SDP_SDPV2_ITF_H */
